// Package cli parses CLI arguments and runs agbox modes.
//
// Security properties:
//   - Rejects root execution by default unless --allow-root or AGBOX_ALLOW_ROOT=1 is set.
//   - Fails closed across setup, create-base, edit-base, update, auth, skills, rules, profile,
//     share, run, and resume whenever a prerequisite, FUSE filter, network rule, or secret transfer fails.
//   - Enforces MaskStrict FUSE VCS filtering and default-deny public-only egress
//     by default on every run.
//   - Binds --serve web interfaces strictly to host loopback (127.0.0.1).
//   - Streams host API keys and saved sandbox login credentials over stdin into the microVM.
//   - Mounts cached agent updates, global skills, and global rules read-only and isolates --profile disks with flock.
package cli

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"agbox/internal/config"
	"agbox/internal/mounttab"
	"agbox/internal/msb"
	"agbox/internal/pathsec"
	"agbox/internal/persist"
	"agbox/internal/vcsfuse"
)

// ErrHelp indicates that `-h` or `--help` was requested.
var ErrHelp = errors.New("help requested")

type passthroughExitError struct {
	code int
	err  error
}

func (e passthroughExitError) Error() string {
	return e.err.Error()
}

func (e passthroughExitError) Unwrap() error {
	return e.err
}

func wrapPassthroughExit(res msb.CommandResult, err error) error {
	if err == nil {
		return nil
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) && exitErr.ExitCode() > 0 {
		return passthroughExitError{code: exitErr.ExitCode(), err: err}
	}
	if res.ExitCode > 0 {
		return passthroughExitError{code: res.ExitCode, err: err}
	}
	return err
}

func formatMSBError(prefix string, res msb.CommandResult, err error) error {
	detail := strings.TrimSpace(res.Stderr)
	if detail == "" {
		detail = strings.TrimSpace(res.Stdout)
	}
	if detail != "" {
		return fmt.Errorf("%s: %w (%s)", prefix, err, tailLines(detail, 10))
	}
	return fmt.Errorf("%s: %w", prefix, err)
}

// GlobalOpts holds top-level CLI flags that precede the mode name.
type GlobalOpts struct {
	AllowRoot bool
	Mode      string
	Rest      []string
}

// ParseGlobalArgs parses global flags and separates the mode name from mode arguments.
func ParseGlobalArgs(args []string) (GlobalOpts, error) {
	var opts GlobalOpts
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--allow-root":
			opts.AllowRoot = true
		case "-h", "--help", "help":
			return opts, ErrHelp
		default:
			if strings.HasPrefix(args[i], "-") {
				return GlobalOpts{}, fmt.Errorf("unknown option %q (run 'agbox --help')", args[i])
			}
			opts.Mode = args[i]
			opts.Rest = args[i+1:]
			return opts, nil
		}
	}
	return opts, ErrHelp
}

// CheckRootExecution checks whether agbox may run with effective user ID euid.
// It returns the active override name ("--allow-root" or "AGBOX_ALLOW_ROOT=1") for root runs.
func CheckRootExecution(euid int, envAllowRoot, flagAllowRoot bool) (string, error) {
	if euid != 0 {
		return "", nil
	}
	if flagAllowRoot {
		return "--allow-root", nil
	}
	if envAllowRoot {
		return "AGBOX_ALLOW_ROOT=1", nil
	}
	return "", errors.New("do not run as root. Pass --allow-root or set AGBOX_ALLOW_ROOT=1 to override")
}

// SetupOpts holds parsed arguments for `agbox setup`.
type SetupOpts struct {
	AllowRoot bool
}

// ParseSetupArgs parses CLI arguments for `setup`.
func ParseSetupArgs(args []string) (SetupOpts, error) {
	var opts SetupOpts
	for _, a := range args {
		switch a {
		case "-h", "--help":
			return SetupOpts{}, ErrHelp
		case "--allow-root":
			opts.AllowRoot = true
		default:
			return SetupOpts{}, fmt.Errorf("unknown setup option: %s (expected --allow-root)", a)
		}
	}
	return opts, nil
}

// StatusOpts holds parsed arguments for `agbox status`.
type StatusOpts struct {
	AllowRoot bool
}

// ParseStatusArgs parses CLI arguments for `status`.
func ParseStatusArgs(args []string) (StatusOpts, error) {
	var opts StatusOpts
	for _, a := range args {
		switch a {
		case "-h", "--help":
			return StatusOpts{}, ErrHelp
		case "--allow-root":
			opts.AllowRoot = true
		default:
			return StatusOpts{}, fmt.Errorf("unknown status option: %s (expected --allow-root)", a)
		}
	}
	return opts, nil
}

// CreateBaseOpts holds parsed arguments for `agbox create-base`.
type CreateBaseOpts struct {
	Agent      string
	Force      bool
	AllowRoot  bool
	Categories []msb.Category
}

// ParseCreateBaseArgs parses CLI arguments for `create-base`.
func ParseCreateBaseArgs(args []string) (CreateBaseOpts, error) {
	var opts CreateBaseOpts
	var pos []string
	var catSpecs []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch a {
		case "-h", "--help":
			return CreateBaseOpts{}, ErrHelp
		case "--force":
			opts.Force = true
		case "--allow-root":
			opts.AllowRoot = true
		case "--add", "--categories":
			if i+1 >= len(args) || args[i+1] == "" {
				return CreateBaseOpts{}, fmt.Errorf("%s requires at least one category name (%s, or all)", a, msb.CategoryNamesList())
			}
			catSpecs = append(catSpecs, args[i+1])
			i++
		default:
			if strings.HasPrefix(a, "-") {
				return CreateBaseOpts{}, fmt.Errorf("unknown create-base option: %s", a)
			}
			pos = append(pos, a)
		}
	}
	if len(pos) != 1 {
		return CreateBaseOpts{}, errors.New("Usage: agbox create-base [--force] [--allow-root] [--add <categories>] <opencode|antigravity|both>")
	}
	switch pos[0] {
	case "opencode", "antigravity", "both":
		opts.Agent = pos[0]
	default:
		return CreateBaseOpts{}, errors.New("Usage: agbox create-base [--force] [--allow-root] [--add <categories>] <opencode|antigravity|both>")
	}
	if len(catSpecs) > 0 {
		cats, err := msb.ResolveCategories(catSpecs)
		if err != nil {
			return CreateBaseOpts{}, err
		}
		opts.Categories = cats
	}
	return opts, nil
}

// EditBaseOpts holds parsed arguments for `agbox edit-base`.
type EditBaseOpts struct {
	Cmd        string
	NoSnap     bool
	Shell      bool
	ListOnly   bool
	AllowRoot  bool
	Categories []msb.Category
}

// ParseEditBaseArgs parses CLI arguments for `edit-base`.
// Users may select categories with `--add <cat1,cat2,...>` or as positional
// arguments (`agbox edit-base core go rust esphome`).
func ParseEditBaseArgs(args []string) (EditBaseOpts, error) {
	opts := EditBaseOpts{}
	var catSpecs []string
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-h", "--help":
			return EditBaseOpts{}, ErrHelp
		case "--allow-root":
			opts.AllowRoot = true
		case "--list", "--list-categories":
			opts.ListOnly = true
		case "--shell":
			opts.Shell = true
		case "--add", "--categories":
			if i+1 >= len(args) || args[i+1] == "" {
				return EditBaseOpts{}, fmt.Errorf("%s requires at least one category (%s, or all)", args[i], msb.CategoryNamesList())
			}
			catSpecs = append(catSpecs, args[i+1])
			i++
		case "--cmd":
			if i+1 >= len(args) || args[i+1] == "" {
				return EditBaseOpts{}, errors.New("--cmd requires a non-empty shell command")
			}
			opts.Cmd = args[i+1]
			i++
		case "--no-snap":
			opts.NoSnap = true
		default:
			if strings.HasPrefix(args[i], "-") {
				return EditBaseOpts{}, fmt.Errorf("unknown edit-base option: %s (use: --allow-root | --add <cats> | --list | --shell | --cmd \"shell\" | --no-snap)", args[i])
			}
			catSpecs = append(catSpecs, args[i])
		}
	}
	if len(catSpecs) > 0 {
		cats, err := msb.ResolveCategories(catSpecs)
		if err != nil {
			return EditBaseOpts{}, err
		}
		opts.Categories = cats
	}
	return opts, nil
}

// SandboxPrefix precedes every agbox sandbox name.
const SandboxPrefix = "agbox-"

// ValidateRunName checks a user-supplied `--name` value for `agbox run`.
func ValidateRunName(raw string) (string, error) {
	if raw == "" {
		return "", errors.New("--name requires a non-empty sandbox name")
	}
	if len(raw) > 63 {
		return "", errors.New("--name must be 63 characters or fewer")
	}
	if raw == "base" {
		return "", errors.New("name \"base\" is reserved for agbox-base")
	}
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		isAlphaNum := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
		if i == 0 {
			if !isAlphaNum {
				return "", fmt.Errorf("invalid --name %q: must start with an ASCII letter or digit", raw)
			}
			continue
		}
		if !isAlphaNum && c != '-' && c != '_' {
			return "", fmt.Errorf("invalid --name %q: use only ASCII letters, digits, '-' or '_'", raw)
		}
	}
	return raw, nil
}

// FormatRunSandboxName returns `agbox-<name>` when name is set, or `agbox-run-<pid>`.
func FormatRunSandboxName(name string, pid int) string {
	if name != "" {
		return SandboxPrefix + name
	}
	return fmt.Sprintf("%s-%d", config.RunPrefix, pid)
}

// IsRunSandboxName reports whether sandbox is a valid `agbox-<name>` or `agbox-run-<pid>` name.
func IsRunSandboxName(sandbox string) bool {
	if sandbox == config.BaseSandbox || !strings.HasPrefix(sandbox, SandboxPrefix) {
		return false
	}
	suffix := strings.TrimPrefix(sandbox, SandboxPrefix)
	_, err := ValidateRunName(suffix)
	return err == nil
}

// RunDirIDFromSandbox maps a run sandbox name to its collision-free directory name under `$DATA_DIR/run`.
func RunDirIDFromSandbox(sandbox string) (string, error) {
	if !IsRunSandboxName(sandbox) {
		return "", fmt.Errorf("invalid agbox run sandbox %q", sandbox)
	}
	runPIDPrefix := config.RunPrefix + "-"
	if strings.HasPrefix(sandbox, runPIDPrefix) {
		pidStr := strings.TrimPrefix(sandbox, runPIDPrefix)
		if isDigits(pidStr) {
			return pidStr, nil
		}
	}
	suffix := strings.TrimPrefix(sandbox, SandboxPrefix)
	if isDigits(suffix) {
		return "_" + suffix, nil
	}
	return suffix, nil
}

// SandboxFromRunDirID maps a directory name under `$DATA_DIR/run` back to its sandbox name.
func SandboxFromRunDirID(dirID string) (string, bool) {
	if dirID == "" {
		return "", false
	}
	if isDigits(dirID) {
		return config.RunPrefix + "-" + dirID, true
	}
	if strings.HasPrefix(dirID, "_") && isDigits(dirID[1:]) {
		return SandboxPrefix + dirID[1:], true
	}
	if strings.HasPrefix(dirID, "run-") && isDigits(strings.TrimPrefix(dirID, "run-")) {
		return "", false
	}
	if _, err := ValidateRunName(dirID); err != nil {
		return "", false
	}
	return SandboxPrefix + dirID, true
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// RunOpts holds parsed arguments for `agbox run`.
type RunOpts struct {
	Name            string
	Agent           string
	Paths           []string
	ShareSpecs      []string
	ShareHub        bool
	AllowRoot       bool
	ReadOnly        bool
	LockAccess      bool
	DefaultVCS      config.VCSPolicy
	LockVCS         bool
	Detach          bool
	Serve           bool
	Probe           bool
	Port            int
	RemoteControl   bool
	Cmd             string
	NoNet           bool
	NetSpecs        []string
	CPUs            string
	Memory          string
	MaskMode        config.MaskMode
	Persist         bool
	Profile         string
	Continue        bool
	ContinueSession string
	NoAuth          bool
	NoSkills        bool
	NoRules         bool
	NoAgentCache    bool
}

// ParseRunArgs parses CLI arguments for `run`.
// Options must appear before shared paths. Pass `--` before paths that start with `-`.
func ParseRunArgs(args []string, defaultMask config.MaskMode, pathExists func(string) bool) (RunOpts, error) {
	if defaultMask == "" {
		defaultMask = config.MaskStrict
	}
	if pathExists == nil {
		pathExists = func(p string) bool {
			_, err := os.Stat(p)
			return err == nil
		}
	}

	opts := RunOpts{
		MaskMode:   defaultMask,
		DefaultVCS: config.VCSMask,
	}
	sawRO := false
	sawRW := false
	sawMaskVCS := false
	sawNoMask := false
	sawVCS := false
	sawVCSHooks := false

	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "-h" || arg == "--help" {
			return RunOpts{}, ErrHelp
		}
		if arg == "--" {
			opts.Paths = append(opts.Paths, args[i+1:]...)
			break
		}
		if len(opts.Paths) > 0 && strings.HasPrefix(arg, "-") {
			return RunOpts{}, fmt.Errorf("options must come before paths (found %s after path %q)", arg, opts.Paths[len(opts.Paths)-1])
		}

		if strings.HasPrefix(arg, "--name=") {
			validName, nErr := ValidateRunName(strings.TrimPrefix(arg, "--name="))
			if nErr != nil {
				return RunOpts{}, nErr
			}
			opts.Name = validName
			continue
		}
		if strings.HasPrefix(arg, "--share=") {
			rawShare := strings.TrimPrefix(arg, "--share=")
			if _, sErr := pathsec.ParseShareSpec(rawShare); sErr != nil {
				return RunOpts{}, sErr
			}
			opts.ShareSpecs = append(opts.ShareSpecs, rawShare)
			continue
		}
		if strings.HasPrefix(arg, "--profile=") {
			profName, pErr := persist.ValidateProfileName(strings.TrimPrefix(arg, "--profile="))
			if pErr != nil {
				return RunOpts{}, pErr
			}
			opts.Profile = profName
			continue
		}
		if strings.HasPrefix(arg, "--session=") {
			sid, sErr := persist.ValidateSessionID(strings.TrimPrefix(arg, "--session="))
			if sErr != nil {
				return RunOpts{}, sErr
			}
			opts.ContinueSession = sid
			continue
		}
		if strings.HasPrefix(arg, "--conversation=") {
			sid, sErr := persist.ValidateSessionID(strings.TrimPrefix(arg, "--conversation="))
			if sErr != nil {
				return RunOpts{}, sErr
			}
			opts.ContinueSession = sid
			continue
		}

		switch arg {
		case "opencode", "antigravity":
			if opts.Agent == "" && (len(opts.Paths) == 0 || !pathExists(arg)) {
				opts.Agent = arg
			} else {
				opts.Paths = append(opts.Paths, arg)
			}
		case "--name":
			if i+1 >= len(args) {
				return RunOpts{}, errors.New("--name requires a non-empty sandbox name")
			}
			validName, nErr := ValidateRunName(args[i+1])
			if nErr != nil {
				return RunOpts{}, nErr
			}
			opts.Name = validName
			i++
		case "--share":
			if i+1 >= len(args) || args[i+1] == "" {
				return RunOpts{}, errors.New("--share requires a path[:opts] argument")
			}
			if _, sErr := pathsec.ParseShareSpec(args[i+1]); sErr != nil {
				return RunOpts{}, sErr
			}
			opts.ShareSpecs = append(opts.ShareSpecs, args[i+1])
			i++
		case "--share-hub":
			opts.ShareHub = true
		case "--allow-root":
			opts.AllowRoot = true
		case "--ro":
			sawRO = true
			opts.ReadOnly = true
		case "--rw":
			sawRW = true
			opts.ReadOnly = false
		case "-d", "--detach":
			opts.Detach = true
		case "--serve":
			opts.Serve = true
		case "--remote-control":
			opts.RemoteControl = true
		case "--probe":
			opts.Probe = true
			opts.Serve = true
		case "--port":
			if i+1 >= len(args) {
				return RunOpts{}, errors.New("--port requires a port number")
			}
			p, err := strconv.Atoi(args[i+1])
			if err != nil || p < 1 || p > 65535 {
				return RunOpts{}, errors.New("--port must be an integer between 1 and 65535")
			}
			opts.Port = p
			opts.Serve = true
			i++
		case "--cmd":
			if i+1 >= len(args) || args[i+1] == "" {
				return RunOpts{}, errors.New("--cmd requires a shell command string")
			}
			opts.Cmd = args[i+1]
			i++
		case "--no-net":
			opts.NoNet = true
		case "--net", "--net-rule":
			if i+1 >= len(args) || args[i+1] == "" {
				return RunOpts{}, fmt.Errorf("%s requires a value", arg)
			}
			opts.NetSpecs = append(opts.NetSpecs, args[i+1])
			i++
		case "--cpus":
			if i+1 >= len(args) {
				return RunOpts{}, errors.New("--cpus requires a positive integer")
			}
			n, err := strconv.Atoi(args[i+1])
			if err != nil || n < 1 {
				return RunOpts{}, errors.New("--cpus must be a positive integer")
			}
			opts.CPUs = args[i+1]
			i++
		case "--memory":
			if i+1 >= len(args) || args[i+1] == "" {
				return RunOpts{}, errors.New("--memory requires a size value (for example, 2G or 2048M)")
			}
			if !isValidMemorySpec(args[i+1]) {
				return RunOpts{}, fmt.Errorf("invalid --memory %q: expected a positive size in M or G (for example, 2G or 2048M)", args[i+1])
			}
			opts.Memory = strings.ToUpper(strings.TrimSpace(args[i+1]))
			i++
		case "--mask-vcs":
			sawMaskVCS = true
			opts.MaskMode = config.MaskStrict
			opts.DefaultVCS = config.VCSMask
		case "--no-mask":
			sawNoMask = true
			opts.MaskMode = config.MaskOff
		case "--vcs":
			sawVCS = true
			opts.MaskMode = config.MaskStrict
			opts.DefaultVCS = config.VCSAllow
		case "--vcs-hooks":
			sawVCSHooks = true
			opts.MaskMode = config.MaskStrict
			opts.DefaultVCS = config.VCSAllowHooks
		case "--persist":
			opts.Persist = true
		case "--profile":
			if i+1 >= len(args) {
				return RunOpts{}, errors.New("--profile requires a profile name")
			}
			profName, pErr := persist.ValidateProfileName(args[i+1])
			if pErr != nil {
				return RunOpts{}, pErr
			}
			opts.Profile = profName
			i++
		case "-c", "--continue":
			opts.Continue = true
		case "-s", "--session", "--conversation":
			if i+1 >= len(args) {
				return RunOpts{}, fmt.Errorf("%s requires a session or conversation ID", arg)
			}
			sid, sErr := persist.ValidateSessionID(args[i+1])
			if sErr != nil {
				return RunOpts{}, sErr
			}
			opts.ContinueSession = sid
			i++
		case "--no-auth":
			opts.NoAuth = true
		case "--no-skills":
			opts.NoSkills = true
		case "--no-rules":
			opts.NoRules = true
		case "--no-agent-cache", "--no-agent-override":
			opts.NoAgentCache = true
		default:
			if strings.HasPrefix(arg, "-") {
				return RunOpts{}, fmt.Errorf("unknown run option: %s ('agbox run --help')", arg)
			}
			opts.Paths = append(opts.Paths, arg)
		}
	}

	if sawRO && sawRW {
		return RunOpts{}, errors.New("conflicting options: cannot combine --ro and --rw")
	}
	vcsModeFlags := 0
	for _, b := range []bool{sawMaskVCS, sawNoMask, sawVCS, sawVCSHooks} {
		if b {
			vcsModeFlags++
		}
	}
	if vcsModeFlags > 1 {
		return RunOpts{}, errors.New("conflicting VCS options: specify at most one of --mask-vcs, --no-mask, --vcs, or --vcs-hooks")
	}
	if sawRO && sawVCSHooks {
		return RunOpts{}, errors.New("conflicting options: cannot combine --ro and --vcs-hooks")
	}
	if opts.MaskMode == config.MaskOff && opts.ShareHub {
		return RunOpts{}, errors.New("conflicting options: cannot combine --no-mask and --share-hub")
	}
	opts.LockAccess = sawRO || sawRW
	opts.LockVCS = sawMaskVCS || sawVCS || sawVCSHooks

	allRawShares := make([]string, 0, len(opts.ShareSpecs)+len(opts.Paths))
	allRawShares = append(allRawShares, opts.ShareSpecs...)
	allRawShares = append(allRawShares, opts.Paths...)
	for _, raw := range allRawShares {
		if raw == "" {
			continue
		}
		spec, sErr := pathsec.ParseShareSpec(raw)
		if sErr != nil {
			return RunOpts{}, sErr
		}
		if opts.MaskMode == config.MaskOff && spec.HasVCSOpt {
			return RunOpts{}, fmt.Errorf("conflicting options for %q: per-share VCS modifier requires FUSE filtering (cannot combine with --no-mask)", raw)
		}
		effRO := opts.ReadOnly
		if spec.HasAccessOpt {
			if opts.LockAccess && spec.ReadOnly != opts.ReadOnly {
				return RunOpts{}, fmt.Errorf("conflicting access options for %q: flag and modifier disagree on ro/rw", raw)
			}
			effRO = spec.ReadOnly
		}
		effVCS := opts.DefaultVCS
		if spec.HasVCSOpt {
			if opts.LockVCS && spec.VCSPolicy != opts.DefaultVCS {
				return RunOpts{}, fmt.Errorf("conflicting VCS options for %q: flag (%s) and modifier (%s) disagree", raw, opts.DefaultVCS, spec.VCSPolicy)
			}
			effVCS = spec.VCSPolicy
		}
		if effRO && effVCS == config.VCSAllowHooks {
			return RunOpts{}, fmt.Errorf("conflicting options for %q: read-only share cannot enable vcs-hooks", raw)
		}
	}

	if opts.Serve && opts.Cmd != "" {
		return RunOpts{}, errors.New("--serve and --cmd are mutually exclusive")
	}
	if opts.RemoteControl && opts.Serve {
		return RunOpts{}, errors.New("--remote-control and --serve are mutually exclusive")
	}
	if opts.RemoteControl && opts.Cmd != "" {
		return RunOpts{}, errors.New("--remote-control and --cmd are mutually exclusive")
	}
	if opts.Detach && !opts.Serve && !opts.RemoteControl {
		return RunOpts{}, errors.New("--detach (-d) requires --remote-control or --serve")
	}
	if opts.Persist && opts.Name == "" {
		return RunOpts{}, errors.New("--persist requires --name <NAME>")
	}
	if opts.Persist && opts.Profile != "" {
		return RunOpts{}, errors.New("--persist and --profile are mutually exclusive")
	}
	if opts.Persist && opts.Probe {
		return RunOpts{}, errors.New("--persist and --probe are mutually exclusive")
	}
	if opts.Continue && opts.ContinueSession != "" {
		return RunOpts{}, errors.New("--continue (-c) and --session/--conversation are mutually exclusive")
	}
	if opts.Continue || opts.ContinueSession != "" {
		if opts.Serve || opts.Cmd != "" {
			return RunOpts{}, errors.New("--continue and --session cannot be combined with --serve or --cmd")
		}
		if opts.RemoteControl && opts.Detach {
			return RunOpts{}, errors.New("--continue and --session cannot be combined with detached --remote-control")
		}
	}

	return opts, nil
}

// SelectEffectiveAgent resolves which agent binary to run from the base agent and run flags.
func SelectEffectiveAgent(baseAgent string, opts RunOpts) (string, error) {
	if baseAgent == "" {
		baseAgent = "both"
	}
	if opts.Agent != "" && baseAgent != "both" && opts.Agent != baseAgent {
		return "", fmt.Errorf("base was built for agent=%s. You requested %s. Run 'agbox create-base %s' or 'both' first", baseAgent, opts.Agent, opts.Agent)
	}
	if opts.Serve && baseAgent != "opencode" && baseAgent != "both" {
		return "", fmt.Errorf("--serve requires the OpenCode agent. This base (%s) does not include it", baseAgent)
	}
	if opts.RemoteControl && baseAgent != "antigravity" && baseAgent != "both" {
		return "", fmt.Errorf("--remote-control requires the Antigravity (agy) agent. This base (%s) does not include it", baseAgent)
	}
	if opts.RemoteControl && opts.Agent == "opencode" {
		return "", errors.New("--remote-control is only supported with the antigravity (agy) agent")
	}
	if opts.Cmd != "" {
		return opts.Agent, nil
	}
	agent := opts.Agent
	if agent == "" {
		agent = baseAgent
	}
	if agent == "both" {
		if opts.Serve {
			return "opencode", nil
		}
		if opts.RemoteControl {
			return "antigravity", nil
		}
		return "", errors.New("base includes both agents. Specify one: 'agbox run opencode ...' or 'agbox run antigravity ...'")
	}
	return agent, nil
}

// SuspendOpts holds parsed arguments for `agbox suspend`.
type SuspendOpts struct {
	Sandbox   string
	AllowRoot bool
}

// ParseSuspendArgs validates CLI arguments for `agbox suspend`.
func ParseSuspendArgs(args []string) (SuspendOpts, error) {
	var opts SuspendOpts
	var pos []string
	for _, a := range args {
		switch a {
		case "-h", "--help":
			return SuspendOpts{}, ErrHelp
		case "--allow-root":
			opts.AllowRoot = true
		default:
			if strings.HasPrefix(a, "-") {
				return SuspendOpts{}, fmt.Errorf("unknown suspend option: %s (expected --allow-root)", a)
			}
			pos = append(pos, a)
		}
	}
	if len(pos) != 1 {
		return SuspendOpts{}, errors.New("Usage: agbox suspend [--allow-root] <sandbox>")
	}
	name, err := validateTargetRunSandbox(pos[0], "suspend")
	if err != nil {
		return SuspendOpts{}, err
	}
	opts.Sandbox = name
	return opts, nil
}

// ResumeOpts holds parsed arguments for `agbox resume`.
type ResumeOpts struct {
	Sandbox         string
	AllowRoot       bool
	Detach          bool
	Continue        bool
	ContinueSession string
	NoAuth          bool
	NoSkills        bool
	NoRules         bool
	NoAgentCache    bool
}

// ParseResumeArgs validates CLI arguments for `agbox resume`.
func ParseResumeArgs(args []string) (ResumeOpts, error) {
	var opts ResumeOpts
	var pos []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if strings.HasPrefix(a, "--session=") {
			sid, err := persist.ValidateSessionID(strings.TrimPrefix(a, "--session="))
			if err != nil {
				return ResumeOpts{}, err
			}
			opts.ContinueSession = sid
			continue
		}
		if strings.HasPrefix(a, "--conversation=") {
			sid, err := persist.ValidateSessionID(strings.TrimPrefix(a, "--conversation="))
			if err != nil {
				return ResumeOpts{}, err
			}
			opts.ContinueSession = sid
			continue
		}
		switch a {
		case "-h", "--help":
			return ResumeOpts{}, ErrHelp
		case "--allow-root":
			opts.AllowRoot = true
		case "-d", "--detach":
			opts.Detach = true
		case "-c", "--continue":
			opts.Continue = true
		case "-s", "--session", "--conversation":
			if i+1 >= len(args) {
				return ResumeOpts{}, fmt.Errorf("%s requires a session or conversation ID", a)
			}
			sid, err := persist.ValidateSessionID(args[i+1])
			if err != nil {
				return ResumeOpts{}, err
			}
			opts.ContinueSession = sid
			i++
		case "--no-auth":
			opts.NoAuth = true
		case "--no-skills":
			opts.NoSkills = true
		case "--no-rules":
			opts.NoRules = true
		case "--no-agent-cache", "--no-agent-override":
			opts.NoAgentCache = true
		default:
			if strings.HasPrefix(a, "-") {
				return ResumeOpts{}, fmt.Errorf("unknown resume option: %s (expected --allow-root, --detach, --continue, --session, --no-auth, --no-skills, --no-rules, or --no-agent-cache)", a)
			}
			pos = append(pos, a)
		}
	}
	if opts.Continue && opts.ContinueSession != "" {
		return ResumeOpts{}, errors.New("--continue (-c) and --session/--conversation are mutually exclusive")
	}
	if len(pos) != 1 {
		return ResumeOpts{}, errors.New("Usage: agbox resume [--allow-root] [-d|--detach] [-c|--continue] [--session ID] <sandbox>")
	}
	name, err := validateTargetRunSandbox(pos[0], "resume")
	if err != nil {
		return ResumeOpts{}, err
	}
	opts.Sandbox = name
	return opts, nil
}

// ParseStopArgs validates the sandbox name argument for `agbox stop`.
func ParseStopArgs(args []string) (string, error) {
	name, _, err := parseStopOpts(args)
	return name, err
}

func parseStopOpts(args []string) (name string, allowRoot bool, err error) {
	var pos []string
	for _, a := range args {
		switch a {
		case "-h", "--help":
			return "", false, ErrHelp
		case "--allow-root":
			allowRoot = true
		default:
			if strings.HasPrefix(a, "-") {
				return "", false, fmt.Errorf("unknown stop option: %s (expected --allow-root)", a)
			}
			pos = append(pos, a)
		}
	}
	if len(pos) != 1 {
		return "", false, errors.New("Usage: agbox stop [--allow-root] <sandbox>")
	}
	validName, vErr := validateTargetRunSandbox(pos[0], "stop")
	if vErr != nil {
		return "", false, vErr
	}
	return validName, allowRoot, nil
}

func validateTargetRunSandbox(name, verb string) (string, error) {
	if name == config.BaseSandbox {
		return "", fmt.Errorf("refusing to %s %q: it is the base sandbox", verb, name)
	}
	if !IsRunSandboxName(name) {
		return "", fmt.Errorf("refusing to %s %q: not an agbox run sandbox (agbox-<name>)", verb, name)
	}
	return name, nil
}

// ParseRemoveArgs parses CLI arguments for `agbox remove`.
func ParseRemoveArgs(args []string) (yes bool, err error) {
	yes, _, err = parseRemoveOpts(args)
	return yes, err
}

func parseRemoveOpts(args []string) (yes bool, allowRoot bool, err error) {
	for _, a := range args {
		switch a {
		case "-y", "--yes":
			yes = true
		case "--allow-root":
			allowRoot = true
		case "-h", "--help":
			return false, false, ErrHelp
		default:
			return false, false, fmt.Errorf("unknown remove option: %s (expected --yes, -y, or --allow-root)", a)
		}
	}
	return yes, allowRoot, nil
}

// DataDirSupportsFilter reports whether dataDir is safe to use as a FUSE
// mountpoint parent (no whitespace, backslashes, or control characters).
func DataDirSupportsFilter(dataDir string) bool {
	if dataDir == "" || strings.ContainsAny(dataDir, " \t\n\r\\") {
		return false
	}
	for _, r := range dataDir {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

func isValidMemorySpec(spec string) bool {
	s := strings.ToUpper(strings.TrimSpace(spec))
	if len(s) < 2 {
		return false
	}
	unit := s[len(s)-1]
	if unit != 'M' && unit != 'G' {
		return false
	}
	num := s[:len(s)-1]
	if num[0] == '0' {
		return false
	}
	return isDigits(num)
}

// PickFreeLoopbackPort binds 127.0.0.1:0 momentarily to obtain an unused
// high loopback TCP port from the kernel.
func PickFreeLoopbackPort() (int, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, fmt.Errorf("find free loopback port: %w", err)
	}
	defer ln.Close()
	addr, ok := ln.Addr().(*net.TCPAddr)
	if !ok || addr.Port <= 0 {
		return 0, errors.New("could not determine bound TCP port")
	}
	return addr.Port, nil
}

// App holds runtime dependencies for executing CLI modes.
type App struct {
	Env         config.Env
	ExePath     string
	MSB         msb.Runner
	MountCtl    mounttab.Controller
	Stdin       io.Reader
	Stdout      io.Writer
	Stderr      io.Writer
	Getenv      func(string) string
	IsTTY       func() bool
	GetEUID     func() int
	CheckKVM    func() error
	CheckFUSE   func() error
	PID         int
	StartFilter func(srcDir, mntDir, pidFile string, dieWithParent bool) (int, error)
	StartHub    func(mntDir, sockPath, pidFile string, initial []vcsfuse.HubShareConfig, dieWithParent bool) (int, error)
	WaitServeUI func(ctx context.Context, port int, sandbox string) bool
}

// NewApp constructs a production App wired to the current OS process.
func NewApp() (*App, error) {
	env, err := config.LoadEnv()
	if err != nil {
		return nil, err
	}
	exePath, err := os.Executable()
	if err != nil {
		exePath = os.Args[0]
	}
	if resolved, rErr := filepath.EvalSymlinks(exePath); rErr == nil {
		exePath = resolved
	}
	runner, _ := msb.NewExecRunner("")

	app := &App{
		Env:      env,
		ExePath:  exePath,
		MSB:      runner,
		MountCtl: mounttab.OSController{},
		Stdin:    os.Stdin,
		Stdout:   os.Stdout,
		Stderr:   os.Stderr,
		Getenv:   os.Getenv,
		IsTTY: func() bool {
			return isFileTerminal(os.Stdin) && isFileTerminal(os.Stdout)
		},
		GetEUID:  os.Geteuid,
		CheckKVM: checkKVMAccess,
		PID:      os.Getpid(),
	}
	app.CheckFUSE = func() error {
		return vcsfuse.CheckHostSupport(app.Env.DataDir)
	}
	app.StartFilter = func(srcDir, mntDir, pidFile string, dieWithParent bool) (int, error) {
		return vcsfuse.StartSubprocess(app.ExePath, srcDir, mntDir, pidFile, dieWithParent)
	}
	app.StartHub = func(mntDir, sockPath, pidFile string, initial []vcsfuse.HubShareConfig, dieWithParent bool) (int, error) {
		return vcsfuse.StartHubSubprocess(app.ExePath, mntDir, sockPath, pidFile, initial, app.Env.DataDir, dieWithParent)
	}
	app.WaitServeUI = app.defaultWaitServeUI
	return app, nil
}

func isFileTerminal(f *os.File) bool {
	if f == nil {
		return false
	}
	_, err := unix.IoctlGetTermios(int(f.Fd()), unix.TCGETS)
	return err == nil
}

func (a *App) cmdNeedsNoStdin() bool {
	if a.Stdin == nil {
		return true
	}
	if f, ok := a.Stdin.(*os.File); ok {
		if isFileTerminal(f) {
			return true
		}
		st, err := f.Stat()
		if err != nil {
			return true
		}
		if (st.Mode() & os.ModeCharDevice) != 0 {
			return true
		}
		if st.Mode().IsRegular() && st.Size() == 0 {
			return true
		}
		return false
	}
	if sized, ok := a.Stdin.(interface{ Len() int }); ok {
		return sized.Len() == 0
	}
	return false
}

func (a *App) logf(format string, args ...any) {
	fmt.Fprintf(a.Stdout, "[agbox] "+format+"\n", args...)
}

func (a *App) warnf(format string, args ...any) {
	fmt.Fprintf(a.Stderr, "[agbox] WARN: "+format+"\n", args...)
}

func (a *App) ensureMSB() error {
	if a.MSB != nil {
		return nil
	}
	r, err := msb.NewExecRunner("")
	if err != nil {
		return fmt.Errorf("missing command 'msb' (run 'agbox setup' first): %w", err)
	}
	a.MSB = r
	return nil
}

func (a *App) isRoot() bool {
	return a.GetEUID != nil && a.GetEUID() == 0
}

func (a *App) verifyUser(allowRootFlag bool) error {
	euid := 1000
	if a.GetEUID != nil {
		euid = a.GetEUID()
	}
	warnSrc, err := CheckRootExecution(euid, a.Env.AllowRoot, allowRootFlag)
	if err != nil {
		return err
	}
	if warnSrc != "" {
		a.warnf("Root mode is active (%s).", warnSrc)
	}
	return nil
}

func (a *App) requireSetup(allowRootFlag bool) error {
	if err := a.verifyUser(allowRootFlag); err != nil {
		return err
	}
	if err := a.ensureMSB(); err != nil {
		return err
	}
	kvmCheck := a.CheckKVM
	if kvmCheck == nil {
		kvmCheck = checkKVMAccess
	}
	if err := kvmCheck(); err != nil {
		return err
	}
	return nil
}

func checkKVMAccess() error {
	f, err := os.OpenFile("/dev/kvm", os.O_RDWR, 0)
	if err != nil {
		return fmt.Errorf("/dev/kvm is not accessible (%v). Run 'agbox setup'", err)
	}
	_ = f.Close()
	return nil
}

func (a *App) requireBase(ctx context.Context) (config.State, error) {
	st, err := config.LoadFile(a.Env.ConfigFile)
	if err != nil || st.Snapshot == "" {
		return config.State{}, errors.New("no base configured. Run 'agbox create-base <opencode|antigravity|both>' first")
	}
	exists, err := msb.SnapshotExists(ctx, a.MSB, st.Snapshot)
	if err != nil || !exists {
		return config.State{}, fmt.Errorf("base snapshot %q was not found in msb. Rebuild it with 'agbox create-base --force %s'", st.Snapshot, defaultStr(st.Agent, "both"))
	}
	return st, nil
}

func defaultStr(v, fallback string) string {
	if v == "" {
		return fallback
	}
	return v
}

// ReapOrphanRuns deletes run microVMs whose host owner PID is no longer active.
// It skips running detached sandboxes and stopped or running suspended sandboxes.
func (a *App) ReapOrphanRuns(ctx context.Context) {
	if a.MSB == nil {
		return
	}
	res, err := a.MSB.Run(ctx, msb.CommandRequest{Args: []string{"ls"}})
	if err != nil {
		return
	}
	runPIDPrefix := config.RunPrefix + "-"
	for _, sb := range msb.ParseSandboxList(res.Stdout) {
		if !IsRunSandboxName(sb.Name) {
			continue
		}
		dirID, dErr := RunDirIDFromSandbox(sb.Name)
		if dErr != nil {
			continue
		}
		dir := filepath.Join(a.Env.DataDir, "run", dirID)
		if hasMarker(filepath.Join(dir, "suspended")) {
			continue
		}
		if hasMarker(filepath.Join(dir, "detached")) && sb.Running {
			continue
		}
		ownerPID := 0
		if meta, mErr := config.LoadRunMeta(filepath.Join(dir, "run.meta")); mErr == nil && meta.OwnerPID > 0 {
			ownerPID = meta.OwnerPID
		} else if strings.HasPrefix(sb.Name, runPIDPrefix) {
			if pid, pErr := strconv.Atoi(strings.TrimPrefix(sb.Name, runPIDPrefix)); pErr == nil && pid > 0 {
				ownerPID = pid
			}
		}
		if ownerPID <= 0 || ownerPID == a.PID || isPIDAlive(ownerPID) {
			continue
		}
		_, _ = a.MSB.Run(ctx, msb.CommandRequest{Args: []string{"rm", "-f", sb.Name}})
	}
}

// ReapStaleFilterDirs unmounts and deletes stale `$DATA_DIR/run/<id>` directories.
// It skips active owners, running detached sandboxes, and suspended sandboxes.
func (a *App) ReapStaleFilterDirs(ctx context.Context) {
	runRoot := filepath.Join(a.Env.DataDir, "run")
	entries, err := os.ReadDir(runRoot)
	if err != nil {
		return
	}
	var sandboxes []msb.SandboxInfo
	listedSandboxes := false
	if a.MSB != nil {
		if res, lErr := a.MSB.Run(ctx, msb.CommandRequest{Args: []string{"ls"}}); lErr == nil {
			sandboxes = msb.ParseSandboxList(res.Stdout)
			listedSandboxes = true
		}
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		dirID := entry.Name()
		dir := filepath.Join(runRoot, dirID)

		suspendedFile := filepath.Join(dir, "suspended")
		if hasMarker(suspendedFile) {
			if !listedSandboxes {
				continue
			}
			sbxName := ""
			if meta, mErr := config.LoadRunMeta(suspendedFile); mErr == nil {
				sbxName = meta.Sandbox
			} else if inferred, ok := SandboxFromRunDirID(dirID); ok {
				sbxName = inferred
			}
			if sbxName != "" {
				if _, ok := msb.FindSandbox(sandboxes, sbxName); ok {
					continue
				}
			}
		}

		detachedFile := filepath.Join(dir, "detached")
		if raw, err := os.ReadFile(detachedFile); err == nil {
			if !listedSandboxes {
				continue
			}
			sbxName := strings.TrimSpace(string(raw))
			if sb, ok := msb.FindSandbox(sandboxes, sbxName); ok && sb.Running {
				continue
			}
		}

		ownerPID := 0
		if meta, mErr := config.LoadRunMeta(filepath.Join(dir, "run.meta")); mErr == nil && meta.OwnerPID > 0 {
			ownerPID = meta.OwnerPID
		} else if pid, pErr := strconv.Atoi(dirID); pErr == nil && pid > 0 {
			ownerPID = pid
		}
		if ownerPID > 0 {
			if ownerPID == a.PID || isPIDAlive(ownerPID) {
				continue
			}
		} else if listedSandboxes {
			if inferred, ok := SandboxFromRunDirID(dirID); ok {
				if sb, found := msb.FindSandbox(sandboxes, inferred); found && sb.Running {
					continue
				}
			}
		}
		_ = mounttab.TeardownFilterDir(dir, a.MountCtl)
	}
}

func hasMarker(path string) bool {
	st, err := os.Stat(path)
	return err == nil && !st.IsDir()
}

func writeMarkerAtomic(path, content string) error {
	dir := filepath.Dir(path)
	if err := config.EnsurePrivateDir(dir); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".marker.*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpName)
		}
	}()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.WriteString(content); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	cleanup = false
	return nil
}

func isPIDAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	err := syscall.Kill(pid, 0)
	return err == nil || errors.Is(err, syscall.EPERM)
}

// Setup checks host prerequisites (user, DATA_DIR, FUSE, msb, /dev/kvm,
// msb doctor, and an offline microVM smoke test).
func (a *App) Setup(ctx context.Context, args []string) error {
	opts, err := ParseSetupArgs(args)
	if err != nil {
		return err
	}
	a.logf("Checking host...")
	if err := a.verifyUser(opts.AllowRoot); err != nil {
		return err
	}
	if !DataDirSupportsFilter(a.Env.DataDir) {
		return fmt.Errorf("DATA_DIR (%s) cannot contain whitespace, backslashes, or control characters", a.Env.DataDir)
	}
	if err := config.EnsurePrivateDir(a.Env.DataDir); err != nil {
		return fmt.Errorf("prepare data dir %s: %w", a.Env.DataDir, err)
	}

	if err := a.ensureMSB(); err != nil {
		return fmt.Errorf("%w (run ./install.sh or 'curl --proto \"=https\" --tlsv1.2 -fsSL https://install.microsandbox.dev | sh')", err)
	}
	if verRes, err := a.MSB.Run(ctx, msb.CommandRequest{Args: []string{"--version"}}); err == nil {
		firstLine, _, _ := strings.Cut(strings.TrimSpace(verRes.Stdout), "\n")
		a.logf("msb %s", firstLine)
	}

	kvmCheck := a.CheckKVM
	if kvmCheck == nil {
		kvmCheck = checkKVMAccess
	}
	if err := kvmCheck(); err != nil {
		if a.isRoot() {
			return fmt.Errorf("%w\nEnsure /dev/kvm exists and load the KVM kernel module (kvm_intel or kvm_amd)", err)
		}
		return fmt.Errorf("%w\nGrant access with: sudo usermod -aG kvm $(id -un) (then re-login) or sudo setfacl -m u:$(id -un):rw /dev/kvm", err)
	}
	a.logf("/dev/kvm accessible: OK")

	fuseCheck := a.CheckFUSE
	if fuseCheck == nil {
		fuseCheck = func() error {
			return vcsfuse.CheckHostSupport(a.Env.DataDir)
		}
	}
	if err := fuseCheck(); err != nil {
		return fmt.Errorf("FUSE VCS filter check failed: %w", err)
	}
	a.logf("FUSE VCS filter accessible: OK")

	a.logf("Running msb doctor...")
	if _, err := a.MSB.Run(ctx, msb.CommandRequest{Args: []string{"doctor"}, Interactive: true}); err != nil {
		return fmt.Errorf("msb doctor reported problems: %w", err)
	}

	a.logf("Smoke test: booting an offline alpine microVM...")
	smoke := fmt.Sprintf("%s-%d", config.RunPrefix, a.PID)
	smokeRemoved := false
	defer func() {
		if !smokeRemoved {
			_, _ = a.MSB.Run(context.Background(), msb.CommandRequest{Args: []string{"rm", "-f", smoke}})
		}
	}()
	if createRes, err := a.MSB.Run(ctx, msb.CommandRequest{
		Args: []string{"create", "alpine", "--name", smoke, "--cpus", "1", "--memory", "256M", "--no-net"},
	}); err != nil {
		return formatMSBError("could not boot smoke-test sandbox", createRes, err)
	}
	execRes, err := a.MSB.Run(ctx, msb.CommandRequest{
		Args: []string{"exec", smoke, "--", "sh", "-c", "echo SMOKE-OK; id -u"},
	})
	if err != nil || !strings.Contains(execRes.Stdout, "SMOKE-OK") {
		return errors.New("smoke test failed: cannot run commands in a sandbox")
	}
	if rmRes, err := a.MSB.Run(ctx, msb.CommandRequest{Args: []string{"rm", "-f", smoke}}); err != nil {
		return formatMSBError("delete smoke-test sandbox "+smoke, rmRes, err)
	}
	smokeRemoved = true
	a.logf("Smoke test: OK (guest boots, exec works, teardown clean)")

	a.logf("Embedded FUSE VCS filter ready (single binary: %s).", a.ExePath)
	if a.isRoot() {
		a.logf("Setup complete. Next: agbox create-base --allow-root <opencode|antigravity|both>")
	} else {
		a.logf("Setup complete. Next: agbox create-base <opencode|antigravity|both>")
	}
	return nil
}

// CreateBase builds the persistent `agbox-base` microVM, provisions the
// non-root `agent` user and requested agent CLI(s), and snapshots `agbox:vN`.
func (a *App) CreateBase(ctx context.Context, args []string) error {
	opts, err := ParseCreateBaseArgs(args)
	if err != nil {
		return err
	}
	if err := a.requireSetup(opts.AllowRoot); err != nil {
		return err
	}
	if err := config.EnsurePrivateDir(a.Env.DataDir); err != nil {
		return fmt.Errorf("prepare data dir %s: %w", a.Env.DataDir, err)
	}

	lsRes, err := a.MSB.Run(ctx, msb.CommandRequest{Args: []string{"ls"}})
	if err == nil {
		if _, exists := msb.FindSandbox(msb.ParseSandboxList(lsRes.Stdout), config.BaseSandbox); exists {
			_, confErr := os.Stat(a.Env.ConfigFile)
			if opts.Force || os.IsNotExist(confErr) {
				a.logf("Replacing existing base sandbox %q...", config.BaseSandbox)
				if rmRes, rmErr := a.MSB.Run(ctx, msb.CommandRequest{Args: []string{"rm", "-f", config.BaseSandbox}}); rmErr != nil {
					return formatMSBError(fmt.Sprintf("delete existing base sandbox %q", config.BaseSandbox), rmRes, rmErr)
				}
			} else {
				return fmt.Errorf("base sandbox %q already exists. Edit it with 'agbox edit-base' or rebuild with 'agbox create-base --force %s'", config.BaseSandbox, opts.Agent)
			}
		}
	}

	image := "debian:bookworm-slim"
	if opts.Agent == "opencode" || opts.Agent == "both" {
		image = "node:24-bookworm-slim"
	}

	a.logf("Creating base sandbox %q from %s (%s vCPU, %s, %s disk)...",
		config.BaseSandbox, image, a.Env.CPUs, a.Env.Memory, a.Env.RootDisk)

	createArgs, err := msb.BuildCreateArgs(msb.CreateOpts{
		Image:    image,
		Name:     config.BaseSandbox,
		CPUs:     a.Env.CPUs,
		Memory:   a.Env.Memory,
		RootDisk: a.Env.RootDisk,
		Workdir:  msb.GuestWorkspace,
		NetSpecs: []string{"public"},
	})
	if err != nil {
		return err
	}
	if _, err := a.MSB.Run(ctx, msb.CommandRequest{
		Args:   createArgs,
		Stdout: a.Stdout,
		Stderr: a.Stderr,
	}); err != nil {
		return fmt.Errorf("base sandbox creation failed: %w", err)
	}

	succeeded := false
	defer func() {
		if !succeeded {
			_, _ = a.MSB.Run(context.Background(), msb.CommandRequest{Args: []string{"rm", "-f", config.BaseSandbox}})
		}
	}()

	a.logf("Provisioning guest (apt baseline, shellcheck, mdformat, and non-root %q user with passwordless sudo)...", config.GuestUser)
	aptCmd := "apt-get update -qq && apt-get install -y -qq --no-install-recommends ca-certificates curl git ripgrep less procps sudo shellcheck python3 python3-venv pipx >/dev/null"
	if _, err := a.MSB.Run(ctx, msb.CommandRequest{
		Args:   []string{"exec", "--stream", "--no-stdin", "-u", "root", config.BaseSandbox, "--", "sh", "-c", aptCmd},
		Stdout: a.Stdout,
		Stderr: a.Stderr,
	}); err != nil {
		return fmt.Errorf("apt provisioning failed: %w", err)
	}

	if err := a.provisionGuestUser(ctx, config.BaseSandbox); err != nil {
		return fmt.Errorf("guest user provisioning failed: %w", err)
	}

	baseToolsScript := fmt.Sprintf(`set -euo pipefail
su - %s -c 'export PATH="/home/agent/.local/bin:$PATH" && pipx install --force mdformat && rm -rf /home/agent/.cache/pip'
if [ -x /home/agent/.local/bin/mdformat ]; then
  ln -sf /home/agent/.local/bin/mdformat /usr/local/bin/mdformat
fi
su - %s -c 'export PATH="/home/agent/.local/bin:$PATH" && shellcheck --version >/dev/null && mdformat --version >/dev/null'
apt-get clean
rm -rf /var/lib/apt/lists/*`, config.GuestUser, config.GuestUser)
	if res, err := a.MSB.Run(ctx, msb.CommandRequest{
		Args:   []string{"exec", "--stream", "--no-stdin", "-u", "root", config.BaseSandbox, "--", "bash", "-c", baseToolsScript},
		Stdout: a.Stdout,
		Stderr: a.Stderr,
	}); err != nil {
		return formatMSBError("install baseline tools (shellcheck and mdformat)", res, err)
	}

	if opts.Agent == "opencode" || opts.Agent == "both" {
		a.logf("Installing OpenCode (npm opencode-ai@%s)...", a.Env.OpenCodeVersion)
		ocScript := fmt.Sprintf(`set -euo pipefail
npm install -g --no-fund --no-audit "opencode-ai@$1"
su - %q -c "opencode --version"`, config.GuestUser)
		if _, err := a.MSB.Run(ctx, msb.CommandRequest{
			Args:   []string{"exec", "--stream", "--no-stdin", "-u", "root", config.BaseSandbox, "--", "bash", "-c", ocScript, "--", a.Env.OpenCodeVersion},
			Stdout: a.Stdout,
			Stderr: a.Stderr,
		}); err != nil {
			return fmt.Errorf("OpenCode install failed: %w", err)
		}
	}

	if opts.Agent == "antigravity" || opts.Agent == "both" {
		a.logf("Installing Google Antigravity CLI (agy) from %s...", a.Env.AgyInstallerURL)
		innerCmd := fmt.Sprintf("curl --proto '=https' --tlsv1.2 -fsSL -- %s | bash", msb.ShellQuote(a.Env.AgyInstallerURL))
		agyScript := fmt.Sprintf(`set -euo pipefail
su - %s -c %s
if [ -x /home/agent/.local/bin/agy ]; then
  ln -sf /home/agent/.local/bin/agy /usr/local/bin/agy
fi
su - %s -c "agy --version"`, config.GuestUser, msb.ShellQuote(innerCmd), config.GuestUser)
		if _, err := a.MSB.Run(ctx, msb.CommandRequest{
			Args:   []string{"exec", "--stream", "--no-stdin", "-u", "root", config.BaseSandbox, "--", "bash", "-c", agyScript},
			Stdout: a.Stdout,
			Stderr: a.Stderr,
		}); err != nil {
			return fmt.Errorf("agy install failed: %w", err)
		}
	}

	if len(opts.Categories) > 0 {
		if err := a.installCategories(ctx, config.BaseSandbox, opts.Categories); err != nil {
			return err
		}
	}

	prevState, _ := config.LoadFile(a.Env.ConfigFile)
	snapListRes, _ := a.MSB.Run(ctx, msb.CommandRequest{Args: []string{"snap", "ls"}})
	count, snapSelector := config.NextSnapshotMember(
		prevState.SnapCount,
		msb.ParseSnapshotList(snapListRes.Stdout),
		config.SnapGroup,
	)
	member := fmt.Sprintf("v%d", count)

	a.logf("Stopping base and snapshotting %s...", snapSelector)
	if stopRes, err := a.MSB.Run(ctx, msb.CommandRequest{Args: []string{"stop", config.BaseSandbox}}); err != nil {
		return formatMSBError("stop base sandbox", stopRes, err)
	}
	if _, err := a.MSB.Run(ctx, msb.CommandRequest{
		Args:   []string{"snap", "create", member, "--sandbox", config.BaseSandbox, "--group", config.SnapGroup},
		Stdout: a.Stdout,
		Stderr: a.Stderr,
	}); err != nil {
		return fmt.Errorf("snapshot failed: %w", err)
	}

	newState := config.State{
		Agent:      opts.Agent,
		Image:      image,
		Snapshot:   snapSelector,
		SnapCount:  count,
		CPUs:       a.Env.CPUs,
		Memory:     a.Env.Memory,
		RootDisk:   a.Env.RootDisk,
		Categories: msb.MergeCategoryNames("", opts.Categories),
	}
	if err := config.SaveFile(a.Env.ConfigFile, newState); err != nil {
		return fmt.Errorf("save config: %w", err)
	}

	succeeded = true
	a.logf("Base ready: %s (agent=%s, image=%s, guest_user=%s).", snapSelector, opts.Agent, image, config.GuestUser)
	a.logf("Next: agbox run [options] [agent] [paths...]")
	return nil
}

func (a *App) provisionGuestUser(ctx context.Context, sandbox string) error {
	if res, err := a.MSB.Run(ctx, msb.CommandRequest{
		Args: []string{"exec", "-u", "root", sandbox, "--", "bash", "-c", msb.ProvisionGuestUserScript()},
	}); err != nil {
		return formatMSBError("provision guest user in "+sandbox, res, err)
	}
	return nil
}

func (a *App) installCategories(ctx context.Context, sandbox string, cats []msb.Category) error {
	names := make([]string, len(cats))
	for i, c := range cats {
		names[i] = c.Name
	}
	a.logf("Installing categories (%s) in %s...", strings.Join(names, ", "), sandbox)
	script := msb.BuildCategoriesScript(cats)
	if res, err := a.MSB.Run(ctx, msb.CommandRequest{
		Args:   []string{"exec", "--stream", "--no-stdin", "-u", "root", sandbox, "--", "bash", "-c", script},
		Stdout: a.Stdout,
		Stderr: a.Stderr,
	}); err != nil {
		return fmt.Errorf("category installation failed (exit %d): %w", res.ExitCode, err)
	}
	return nil
}

// EditBase starts `agbox-base`, installs selected categories, runs `--cmd`, or
// opens an interactive root shell. It then re-verifies the `agent` user, stops
// the microVM, and saves a new snapshot `agbox:v<N+1>` (unless `--no-snap`).
func (a *App) EditBase(ctx context.Context, args []string) error {
	opts, err := ParseEditBaseArgs(args)
	if err != nil {
		return err
	}
	if opts.ListOnly {
		fmt.Fprint(a.Stdout, msb.FormatCategoriesTable())
		return nil
	}
	if err := a.requireSetup(opts.AllowRoot); err != nil {
		return err
	}
	st, err := a.requireBase(ctx)
	if err != nil {
		return err
	}

	lsRes, err := a.MSB.Run(ctx, msb.CommandRequest{Args: []string{"ls"}})
	if err != nil {
		return formatMSBError("msb ls", lsRes, err)
	}
	baseInfo, exists := msb.FindSandbox(msb.ParseSandboxList(lsRes.Stdout), config.BaseSandbox)
	if !exists {
		return fmt.Errorf("no base sandbox %q. Run 'agbox create-base <agent>' first", config.BaseSandbox)
	}

	// If no categories, --cmd, or --shell were specified on the CLI, prompt on TTY.
	if len(opts.Categories) == 0 && opts.Cmd == "" && !opts.Shell {
		if a.IsTTY == nil || !a.IsTTY() {
			return errors.New("not a TTY and no --add or --cmd given. Use: agbox edit-base --add core,go,rust,esphome or --cmd \"...\"")
		}
		fmt.Fprint(a.Stdout, msb.FormatCategoriesTable())
		if st.Categories != "" {
			fmt.Fprintf(a.Stdout, "Currently installed categories: %s\n", st.Categories)
		}
		fmt.Fprintln(a.Stdout, "\nEnter categories to install (numbers or names, 'all', or press Enter for an interactive shell):")
		sc := bufio.NewScanner(a.Stdin)
		if sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" || strings.EqualFold(line, "s") || strings.EqualFold(line, "shell") {
				opts.Shell = true
			} else {
				cats, cErr := msb.ResolveCategories([]string{line})
				if cErr != nil {
					return cErr
				}
				opts.Categories = cats
			}
		} else {
			opts.Shell = true
		}
	}

	if err := a.ensureSparseRootDiskSize(ctx, baseInfo.Running); err != nil {
		a.warnf("Could not expand base root disk: %v", err)
	}

	if !baseInfo.Running {
		a.logf("Starting base sandbox...")
		if startRes, err := a.MSB.Run(ctx, msb.CommandRequest{Args: []string{"start", config.BaseSandbox}}); err != nil {
			return formatMSBError("start base sandbox", startRes, err)
		}
	}

	if len(opts.Categories) > 0 {
		if err := a.installCategories(ctx, config.BaseSandbox, opts.Categories); err != nil {
			_, _ = a.MSB.Run(context.Background(), msb.CommandRequest{Args: []string{"stop", config.BaseSandbox}})
			return err
		}
		st.Categories = msb.MergeCategoryNames(st.Categories, opts.Categories)
	}

	if opts.Cmd != "" {
		a.logf("Running provisioning command in the base...")
		if res, err := a.MSB.Run(ctx, msb.CommandRequest{
			Args:   []string{"exec", "--stream", "--no-stdin", "-u", "root", config.BaseSandbox, "--", "sh", "-c", opts.Cmd},
			Stdout: a.Stdout,
			Stderr: a.Stderr,
		}); err != nil {
			_, _ = a.MSB.Run(context.Background(), msb.CommandRequest{Args: []string{"stop", config.BaseSandbox}})
			return fmt.Errorf("provisioning command failed (exit %d): %w", res.ExitCode, err)
		}
	}

	if opts.Shell {
		fmt.Fprintln(a.Stdout, "Interactive shell in the base sandbox.")
		fmt.Fprintf(a.Stdout, "Changes persist in %q AND (after the snapshot below) in future run microVMs.\n", config.BaseSandbox)
		if res, err := a.MSB.Run(ctx, msb.CommandRequest{
			Args:        []string{"exec", "-t", "-u", "root", config.BaseSandbox, "--", "sh", "-c", "cd /workspace 2>/dev/null || cd /; bash; exit 0"},
			Interactive: true,
		}); err != nil {
			_, _ = a.MSB.Run(context.Background(), msb.CommandRequest{Args: []string{"stop", config.BaseSandbox}})
			return fmt.Errorf("interactive shell failed (exit %d): %w", res.ExitCode, err)
		}
	}

	if err := a.provisionGuestUser(ctx, config.BaseSandbox); err != nil {
		_, _ = a.MSB.Run(context.Background(), msb.CommandRequest{Args: []string{"stop", config.BaseSandbox}})
		return fmt.Errorf("guest user check failed: %w", err)
	}

	a.logf("Stopping base...")
	if stopRes, err := a.MSB.Run(ctx, msb.CommandRequest{Args: []string{"stop", config.BaseSandbox}}); err != nil {
		return formatMSBError("stop base sandbox", stopRes, err)
	}

	if opts.NoSnap {
		if err := config.SaveFile(a.Env.ConfigFile, st); err != nil {
			return fmt.Errorf("save config: %w", err)
		}
		a.logf("Edits live in %q but were NOT snapshotted (--no-snap).", config.BaseSandbox)
		return nil
	}

	snapListRes, _ := a.MSB.Run(ctx, msb.CommandRequest{Args: []string{"snap", "ls"}})
	count, snapSelector := config.NextSnapshotMember(
		st.SnapCount,
		msb.ParseSnapshotList(snapListRes.Stdout),
		config.SnapGroup,
	)
	member := fmt.Sprintf("v%d", count)
	a.logf("Snapshotting new base -> %s", snapSelector)
	if _, err := a.MSB.Run(ctx, msb.CommandRequest{
		Args:   []string{"snap", "create", member, "--sandbox", config.BaseSandbox, "--group", config.SnapGroup},
		Stdout: a.Stdout,
		Stderr: a.Stderr,
	}); err != nil {
		return fmt.Errorf("re-snapshot failed (base edits remain in %q): %w", config.BaseSandbox, err)
	}

	st.Snapshot = snapSelector
	st.SnapCount = count
	st.RootDisk = a.Env.RootDisk
	if err := config.SaveFile(a.Env.ConfigFile, st); err != nil {
		return fmt.Errorf("save config: %w", err)
	}
	a.logf("New runs use %s. Previous snapshots remain intact.", member)
	return nil
}

// ensureSparseRootDiskSize expands the thin-provisioned (sparse) upper.ext4
// image of `agbox-base` if it is currently smaller than a.Env.RootDisk.
func (a *App) ensureSparseRootDiskSize(ctx context.Context, isRunning bool) error {
	targetBytes, ok := parseSizeBytes(a.Env.RootDisk)
	if !ok || targetBytes <= 0 {
		return nil
	}
	upperPath := filepath.Join(a.Env.MSBHome, "sandboxes", config.BaseSandbox, "upper.ext4")
	info, err := os.Stat(upperPath)
	if err != nil || info.Size() >= targetBytes {
		return nil
	}

	a.logf("Expanding thin-provisioned base disk (%s) to %s...", upperPath, a.Env.RootDisk)
	if isRunning {
		_, _ = a.MSB.Run(ctx, msb.CommandRequest{Args: []string{"stop", config.BaseSandbox}})
	}
	if err := os.Truncate(upperPath, targetBytes); err != nil {
		return fmt.Errorf("truncate %s: %w", upperPath, err)
	}
	// Resize the ext4 filesystem inside the sparse image on the host if resize2fs is available.
	for _, dir := range []string{"/sbin", "/usr/sbin", "/bin", "/usr/bin"} {
		r2fs := filepath.Join(dir, "resize2fs")
		if _, sErr := os.Stat(r2fs); sErr == nil {
			e2fsck := filepath.Join(dir, "e2fsck")
			_ = exec.CommandContext(ctx, e2fsck, "-fp", upperPath).Run()
			_ = exec.CommandContext(ctx, r2fs, upperPath).Run()
			break
		}
	}
	if isRunning {
		_, _ = a.MSB.Run(ctx, msb.CommandRequest{Args: []string{"start", config.BaseSandbox}})
	}
	return nil
}

func parseSizeBytes(spec string) (int64, bool) {
	s := strings.ToUpper(strings.TrimSpace(spec))
	if s == "" {
		return 0, false
	}
	mult := int64(1)
	switch {
	case strings.HasSuffix(s, "G"):
		mult = 1024 * 1024 * 1024
		s = strings.TrimSuffix(s, "G")
	case strings.HasSuffix(s, "M"):
		mult = 1024 * 1024
		s = strings.TrimSuffix(s, "M")
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n <= 0 {
		return 0, false
	}
	return n * mult, true
}

func supportsUserXattr(path string, isDir bool) bool {
	checkPath := path
	if !isDir {
		checkPath = filepath.Dir(path)
	}
	_, err := unix.Getxattr(checkPath, "user.agbox.probe", nil)
	return err == nil || errors.Is(err, unix.ENODATA) || errors.Is(err, syscall.ERANGE)
}

// Run restores an ephemeral or persistent microVM from the base snapshot.
// It validates and mounts host paths, streams saved login and API keys over stdin, and starts the agent.
// On exit, Run deletes the microVM and unmounts FUSE shares unless persistent, suspended, or detached.
func (a *App) Run(ctx context.Context, args []string) error {
	opts, err := ParseRunArgs(args, a.Env.MaskVCS, nil)
	if err != nil {
		return err
	}
	if err := a.requireSetup(opts.AllowRoot); err != nil {
		return err
	}
	if err := config.EnsurePrivateDir(a.Env.DataDir); err != nil {
		return fmt.Errorf("prepare data dir: %w", err)
	}
	baseState, err := a.requireBase(ctx)
	if err != nil {
		return err
	}

	effectiveAgent, err := SelectEffectiveAgent(baseState.Agent, opts)
	if err != nil {
		return err
	}

	useMask := false
	maskStrict := false
	switch opts.MaskMode {
	case config.MaskOff:
		useMask = false
	case config.MaskStrict:
		useMask = true
		maskStrict = true
	case config.MaskAuto:
		useMask = DataDirSupportsFilter(a.Env.DataDir)
	default:
		return fmt.Errorf("invalid mask mode %q", opts.MaskMode)
	}
	if maskStrict && !DataDirSupportsFilter(a.Env.DataDir) {
		return fmt.Errorf("DATA_DIR (%s) cannot contain whitespace or backslashes when VCS masking is active", a.Env.DataDir)
	}

	a.ReapOrphanRuns(ctx)
	a.ReapStaleFilterDirs(ctx)

	runSandbox := FormatRunSandboxName(opts.Name, a.PID)
	dirID, err := RunDirIDFromSandbox(runSandbox)
	if err != nil {
		return err
	}

	lsRes, err := a.MSB.Run(ctx, msb.CommandRequest{Args: []string{"ls"}})
	if err != nil {
		return formatMSBError("list sandboxes", lsRes, err)
	}
	sandboxes := msb.ParseSandboxList(lsRes.Stdout)
	if existing, exists := msb.FindSandbox(sandboxes, runSandbox); exists {
		if hasMarker(filepath.Join(a.Env.DataDir, "run", dirID, "suspended")) {
			if opts.Persist && !existing.Running {
				return a.resumeFromRunPersist(ctx, runSandbox, dirID, baseState, opts, useMask)
			}
			return fmt.Errorf("sandbox %q is suspended. Run 'agbox resume %s' or 'agbox stop %s'", runSandbox, runSandbox, runSandbox)
		}
		if existing.Running {
			return fmt.Errorf("sandbox %q is already running. Stop it with 'agbox stop %s'", runSandbox, runSandbox)
		}
		return fmt.Errorf("sandbox %q already exists. Delete it with 'agbox stop %s'", runSandbox, runSandbox)
	}

	skillsDir := filepath.Join(a.Env.DataDir, "skills")
	var skillNames []string
	skillsMounted := false
	if !opts.NoSkills {
		var sErr error
		skillNames, sErr = persist.InspectSkillsDir(skillsDir)
		if sErr != nil {
			return sErr
		}
		if len(skillNames) > 0 {
			skillsMounted = true
		}
	}

	rulesDir := filepath.Join(a.Env.DataDir, "rules")
	var ruleNames []string
	rulesMounted := false
	if !opts.NoRules {
		var rErr error
		ruleNames, rErr = persist.InspectRulesDir(rulesDir)
		if rErr != nil {
			return rErr
		}
		if len(ruleNames) > 0 {
			rulesMounted = true
		}
	}

	agentsDir := filepath.Join(a.Env.DataDir, "agents")
	var cachedAgents []persist.CachedAgentInfo
	agentsMounted := false
	if !opts.NoAgentCache {
		var agErr error
		cachedAgents, agErr = persist.InspectAgentsDir(agentsDir)
		if agErr != nil {
			return agErr
		}
		if len(cachedAgents) > 0 || opts.Persist {
			if err := persist.EnsureAgentsDir(agentsDir); err != nil {
				return err
			}
			agentsMounted = true
		}
	}

	var profLock *persist.ProfileLock
	var diskMounts []msb.DiskMountSpec
	if opts.Profile != "" {
		var lErr error
		profLock, lErr = persist.LockProfile(a.Env.DataDir, opts.Profile)
		if lErr != nil {
			return lErr
		}
		defer func() { _ = profLock.Unlock() }()

		if err := a.checkProfileNotActive(opts.Profile, runSandbox, sandboxes); err != nil {
			return err
		}
		volName, vErr := a.ensureProfileVolume(ctx, opts.Profile, a.Env.ProfileDisk)
		if vErr != nil {
			return vErr
		}
		diskPath, dErr := msb.ResolveVolumeDiskPath(ctx, a.MSB, a.Env.MSBHome, volName)
		if dErr != nil {
			return dErr
		}
		diskMounts = append(diskMounts, msb.DiskMountSpec{
			HostPath:  diskPath,
			GuestPath: msb.GuestProfileMount,
			ReadOnly:  false,
			Format:    "raw",
			FSType:    "ext4",
		})
	}

	validated, err := a.resolveRunShareTargets(opts)
	if err != nil {
		return err
	}
	if opts.ShareHub && !useMask {
		return fmt.Errorf("DATA_DIR (%s) does not support FUSE mounts required by --share-hub", a.Env.DataDir)
	}

	var port int
	var portArgs []string
	if opts.Serve {
		port = opts.Port
		if port == 0 {
			var pErr error
			port, pErr = PickFreeLoopbackPort()
			if pErr != nil {
				return pErr
			}
		}
		portArgs = []string{fmt.Sprintf("127.0.0.1:%d:%d", port, config.GuestPort)}
	}

	isDetachedServe := opts.Serve && !opts.Probe && (opts.Detach || a.IsTTY == nil || !a.IsTTY())
	isDetachedRC := opts.RemoteControl && (opts.Detach || a.IsTTY == nil || !a.IsTTY())
	if !opts.Serve && !isDetachedRC && opts.Cmd == "" {
		if a.IsTTY == nil || !a.IsTTY() {
			return fmt.Errorf("the %s TUI requires a TTY (or pass --serve, --remote-control -d, or --cmd)", effectiveAgent)
		}
	}

	var runMode config.RunMode
	switch {
	case opts.Cmd != "":
		runMode = config.RunModeCmd
	case opts.Serve:
		runMode = config.RunModeServe
	case isDetachedRC:
		runMode = config.RunModeRemoteControl
	default:
		runMode = config.RunModeTUI
	}

	isDetached := isDetachedServe || isDetachedRC
	dieWithParent := !isDetached

	runRootDir := filepath.Join(a.Env.DataDir, "run")
	runFilterDir := filepath.Join(runRootDir, dirID)
	if err := config.EnsurePrivateDir(runRootDir); err != nil {
		return fmt.Errorf("prepare run root dir: %w", err)
	}
	if err := config.EnsurePrivateDir(runFilterDir); err != nil {
		return fmt.Errorf("prepare run dir: %w", err)
	}

	runCtx, cancelRun := context.WithCancel(ctx)
	defer cancelRun()

	var meta config.RunMeta
	suspendedPath := filepath.Join(runFilterDir, "suspended")
	sandboxCreated := false
	persistReady := false
	detached := false
	var cleanupOnce sync.Once
	cleanup := func() {
		cleanupOnce.Do(func() {
			if detached {
				return
			}
			if hasMarker(suspendedPath) {
				_ = mounttab.UnmountFilterDir(runFilterDir, a.MountCtl)
				return
			}
			if persistReady && sandboxCreated {
				a.suspendSandboxOnExit(runSandbox, runFilterDir, meta)
				return
			}
			if sandboxCreated {
				_, _ = a.MSB.Run(context.Background(), msb.CommandRequest{Args: []string{"rm", "-f", runSandbox}})
			}
			_ = mounttab.TeardownFilterDir(runFilterDir, a.MountCtl)
		})
	}
	defer cleanup()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	defer signal.Stop(sigCh)
	go func() {
		select {
		case <-sigCh:
			cancelRun()
			cleanup()
			if profLock != nil {
				_ = profLock.Unlock()
			}
		case <-runCtx.Done():
		}
	}()

	var volumes []msb.VolumeSpec
	var shareRecords []config.ShareRecord
	maskedCount := 0
	directCount := 0
	workspaceHubActive := false

	if useMask && (opts.ShareHub || len(validated) > 0) {
		if a.StartHub == nil {
			if maskStrict || opts.ShareHub {
				return errors.New("FUSE workspace hub starter is not configured")
			}
		} else {
			hubInitial := make([]vcsfuse.HubShareConfig, 0, len(validated))
			for _, target := range validated {
				hubInitial = append(hubInitial, vcsfuse.HubShareConfig{
					GuestName: target.GuestName,
					HostPath:  target.HostPath,
					ReadOnly:  target.ReadOnly,
					VCSPolicy: target.VCSPolicy,
				})
			}
			wsDir := filepath.Join(runFilterDir, "ws")
			sockPath := filepath.Join(runFilterDir, "ws.sock")
			pidFile := filepath.Join(runFilterDir, "ws.pid")
			if _, fErr := a.StartHub(wsDir, sockPath, pidFile, hubInitial, dieWithParent); fErr == nil {
				workspaceHubActive = true
				volumes = append(volumes, msb.VolumeSpec{
					HostPath:  wsDir,
					GuestPath: msb.GuestWorkspace,
					ReadOnly:  false,
					StatVirt:  "off",
				})
				for i, target := range validated {
					masked := target.IsDir && target.VCSPolicy == config.VCSMask
					if masked {
						maskedCount++
					}
					accessMode := "rw"
					if target.ReadOnly {
						accessMode = "ro"
					}
					shareRecords = append(shareRecords, config.ShareRecord{
						Index:      i,
						HostPath:   target.HostPath,
						GuestName:  target.GuestName,
						IsDir:      target.IsDir,
						Masked:     masked,
						AccessMode: accessMode,
						ReadOnly:   target.ReadOnly,
						VCSPolicy:  target.VCSPolicy,
					})
				}
			} else if maskStrict || opts.ShareHub {
				return fmt.Errorf("mount FUSE workspace hub: %w", fErr)
			} else {
				a.warnf("FUSE workspace hub failed (%v). Sharing paths directly without VCS filter.", fErr)
			}
		}
	}

	if !workspaceHubActive {
		for i, target := range validated {
			guestPath := msb.GuestWorkspace + "/" + target.GuestName
			statVirt := "relaxed"
			hostPerms := ""
			if !target.ReadOnly {
				euid := os.Geteuid()
				if a.GetEUID != nil {
					euid = a.GetEUID()
				}
				if (euid == config.GuestUID && os.Getegid() == config.GuestGID) || !supportsUserXattr(target.HostPath, target.IsDir) {
					statVirt = "off"
				} else {
					hostPerms = "mirror"
				}
			}
			volumes = append(volumes, msb.VolumeSpec{
				HostPath:  target.HostPath,
				GuestPath: guestPath,
				ReadOnly:  target.ReadOnly,
				StatVirt:  statVirt,
				HostPerms: hostPerms,
			})
			if target.IsDir {
				directCount++
			}
			accessMode := "rw"
			if target.ReadOnly {
				accessMode = "ro"
			}
			vcsPol := config.VCSMask
			if target.IsDir {
				vcsPol = config.VCSAllowHooks
			}
			shareRecords = append(shareRecords, config.ShareRecord{
				Index:      i,
				HostPath:   target.HostPath,
				GuestName:  target.GuestName,
				IsDir:      target.IsDir,
				Masked:     false,
				AccessMode: accessMode,
				ReadOnly:   target.ReadOnly,
				VCSPolicy:  vcsPol,
			})
		}
	}

	if skillsMounted {
		volumes = append(volumes, msb.VolumeSpec{
			HostPath:  skillsDir,
			GuestPath: msb.GuestSkillsMount,
			ReadOnly:  true,
			StatVirt:  "relaxed",
		})
	}
	if rulesMounted {
		volumes = append(volumes, msb.VolumeSpec{
			HostPath:  rulesDir,
			GuestPath: msb.GuestRulesMount,
			ReadOnly:  true,
			StatVirt:  "relaxed",
		})
	}
	if agentsMounted {
		volumes = append(volumes, msb.VolumeSpec{
			HostPath:  agentsDir,
			GuestPath: msb.GuestAgentsMount,
			ReadOnly:  true,
			StatVirt:  "relaxed",
		})
	}

	if maskedCount > 0 {
		extra := ""
		if directCount > 0 {
			extra = fmt.Sprintf(" (%d direct)", directCount)
		}
		a.logf("VCS filter: %d share(s) masked%s.", maskedCount, extra)
	}

	meta = config.RunMeta{
		Sandbox:         runSandbox,
		OwnerPID:        a.PID,
		Agent:           effectiveAgent,
		Mode:            runMode,
		Detached:        isDetached,
		RemoteControl:   opts.RemoteControl,
		Port:            port,
		Cmd:             opts.Cmd,
		ReadOnly:        opts.ReadOnly,
		MaskMode:        opts.MaskMode,
		WorkspaceHub:    workspaceHubActive,
		Shares:          shareRecords,
		Persist:         opts.Persist,
		Profile:         opts.Profile,
		Continue:        opts.Continue,
		ContinueSession: opts.ContinueSession,
		NoAuth:          opts.NoAuth,
		NoSkills:        opts.NoSkills,
		NoRules:         opts.NoRules,
		NoAgentCache:    opts.NoAgentCache,
		SkillsMounted:   skillsMounted,
		RulesMounted:    rulesMounted,
		AgentsMounted:   agentsMounted,
	}
	if err := config.SaveRunMeta(filepath.Join(runFilterDir, "run.meta"), meta); err != nil {
		return fmt.Errorf("save run metadata: %w", err)
	}

	restoreArgs, err := msb.BuildRestoreArgs(msb.RestoreOpts{
		Snapshot:   baseState.Snapshot,
		Name:       runSandbox,
		User:       config.GuestUser,
		CPUs:       defaultStr(opts.CPUs, a.Env.CPUs),
		Memory:     defaultStr(opts.Memory, a.Env.Memory),
		Volumes:    volumes,
		DiskMounts: diskMounts,
		Ports:      portArgs,
		NoNet:      opts.NoNet,
		NetSpecs:   opts.NetSpecs,
	})
	if err != nil {
		return err
	}

	if opts.Persist {
		a.logf("Booting persistent microVM %s from %s (changes do not persist to the base)...", runSandbox, baseState.Snapshot)
	} else {
		a.logf("Booting ephemeral microVM %s from %s (changes do not persist to the base)...", runSandbox, baseState.Snapshot)
	}
	sandboxCreated = true
	if res, err := a.MSB.Run(runCtx, msb.CommandRequest{Args: restoreArgs}); err != nil {
		return formatMSBError("snapshot restore failed", res, err)
	}

	if err := a.ensureGuestUser(runCtx, runSandbox); err != nil {
		return err
	}
	if agentsMounted && len(cachedAgents) > 0 {
		if err := a.setupGuestAgents(runCtx, runSandbox); err != nil {
			return err
		}
		a.logf("Cached agents: %d updated binary(ies) mounted read-only.", len(cachedAgents))
	}
	if skillsMounted {
		if err := a.setupGuestSkills(runCtx, runSandbox); err != nil {
			return err
		}
		a.logf("Global skills: %d skill(s) mounted read-only.", len(skillNames))
	}
	if rulesMounted {
		if err := a.setupGuestRules(runCtx, runSandbox); err != nil {
			return err
		}
		a.logf("Global rules: %d rule(s) mounted read-only.", len(ruleNames))
	}
	if opts.Profile != "" {
		if err := a.setupGuestProfile(runCtx, runSandbox); err != nil {
			return err
		}
		a.logf("Conversation profile %q mounted.", opts.Profile)
	}
	if !opts.NoAuth {
		if err := a.pushAuth(runCtx, runSandbox, effectiveAgent); err != nil {
			return err
		}
	}
	if err := a.pushKeys(runCtx, runSandbox); err != nil {
		return err
	}

	persistReady = opts.Persist
	return a.execSession(runCtx, meta, runFilterDir, opts.Probe, &detached)
}

// Suspend halts a run microVM, saves its metadata, and unmounts host FUSE shares.
func (a *App) Suspend(ctx context.Context, args []string) error {
	opts, err := ParseSuspendArgs(args)
	if err != nil {
		return err
	}
	if err := a.requireSetup(opts.AllowRoot); err != nil {
		return err
	}
	dirID, err := RunDirIDFromSandbox(opts.Sandbox)
	if err != nil {
		return err
	}
	runRootDir := filepath.Join(a.Env.DataDir, "run")
	runFilterDir := filepath.Join(runRootDir, dirID)
	if err := config.EnsurePrivateDir(a.Env.DataDir); err != nil {
		return fmt.Errorf("prepare data dir: %w", err)
	}
	if err := config.EnsurePrivateDir(runRootDir); err != nil {
		return fmt.Errorf("prepare run root dir: %w", err)
	}

	lsRes, err := a.MSB.Run(ctx, msb.CommandRequest{Args: []string{"ls"}})
	if err != nil {
		return formatMSBError("list sandboxes", lsRes, err)
	}
	sb, exists := msb.FindSandbox(msb.ParseSandboxList(lsRes.Stdout), opts.Sandbox)
	if !exists {
		return fmt.Errorf("sandbox %q does not exist", opts.Sandbox)
	}

	suspendedPath := filepath.Join(runFilterDir, "suspended")
	wasSuspended := hasMarker(suspendedPath)
	meta, err := config.LoadRunMeta(filepath.Join(runFilterDir, "run.meta"))
	if err != nil {
		meta, err = config.LoadRunMeta(suspendedPath)
	}
	if err != nil {
		return fmt.Errorf("load run metadata for %q: %w", opts.Sandbox, err)
	}

	// Write the suspended marker before calling `msb stop` so a concurrent foreground
	// session observes the marker during exit cleanup and skips `msb rm -f`.
	if err := config.SaveRunMeta(suspendedPath, meta); err != nil {
		return fmt.Errorf("save suspended metadata: %w", err)
	}

	if sb.Running {
		a.logf("Stopping microVM %s...", opts.Sandbox)
		if stopRes, err := a.MSB.Run(ctx, msb.CommandRequest{Args: []string{"stop", opts.Sandbox}}); err != nil {
			if !wasSuspended {
				_ = os.Remove(suspendedPath)
			}
			return formatMSBError("stop sandbox "+opts.Sandbox, stopRes, err)
		}
	}

	if rErr := os.Remove(filepath.Join(runFilterDir, "detached")); rErr != nil && !os.IsNotExist(rErr) {
		return fmt.Errorf("remove detached marker: %w", rErr)
	}

	if err := mounttab.UnmountFilterDir(runFilterDir, a.MountCtl); err != nil {
		return fmt.Errorf("unmount FUSE shares for %s: %w", opts.Sandbox, err)
	}

	a.logf("Suspended %s. Resume with: agbox resume %s", opts.Sandbox, opts.Sandbox)
	return nil
}

// Resume validates recorded shares, remounts FUSE filters, boots a suspended microVM, and restarts its agent.
func (a *App) Resume(ctx context.Context, args []string) error {
	opts, err := ParseResumeArgs(args)
	if err != nil {
		return err
	}
	return a.resumeSandbox(ctx, opts)
}

func (a *App) resumeSandbox(ctx context.Context, opts ResumeOpts) error {
	if err := a.requireSetup(opts.AllowRoot); err != nil {
		return err
	}
	dirID, err := RunDirIDFromSandbox(opts.Sandbox)
	if err != nil {
		return err
	}
	runRootDir := filepath.Join(a.Env.DataDir, "run")
	runFilterDir := filepath.Join(runRootDir, dirID)
	if err := config.EnsurePrivateDir(a.Env.DataDir); err != nil {
		return fmt.Errorf("prepare data dir: %w", err)
	}
	if err := config.EnsurePrivateDir(runRootDir); err != nil {
		return fmt.Errorf("prepare run root dir: %w", err)
	}
	if err := config.EnsurePrivateDir(runFilterDir); err != nil {
		return fmt.Errorf("prepare run dir: %w", err)
	}
	suspendedPath := filepath.Join(runFilterDir, "suspended")

	meta, err := config.LoadRunMeta(suspendedPath)
	if err != nil {
		return fmt.Errorf("sandbox %q is not suspended: %w", opts.Sandbox, err)
	}
	if meta.Sandbox != "" && meta.Sandbox != opts.Sandbox {
		return fmt.Errorf("suspended metadata sandbox mismatch: got %q, want %q", meta.Sandbox, opts.Sandbox)
	}
	if meta.Profile != "" {
		if _, pErr := persist.ValidateProfileName(meta.Profile); pErr != nil {
			return fmt.Errorf("invalid profile in suspended metadata: %w", pErr)
		}
	}
	if meta.ContinueSession != "" {
		if _, sErr := persist.ValidateSessionID(meta.ContinueSession); sErr != nil {
			return fmt.Errorf("invalid session ID in suspended metadata: %w", sErr)
		}
	}
	maskMode := meta.MaskMode
	if maskMode == "" {
		maskMode = config.MaskStrict
	}
	switch maskMode {
	case config.MaskStrict, config.MaskAuto, config.MaskOff:
	default:
		return fmt.Errorf("invalid recorded mask mode %q", maskMode)
	}
	meta.MaskMode = maskMode

	lsRes, err := a.MSB.Run(ctx, msb.CommandRequest{Args: []string{"ls"}})
	if err != nil {
		return formatMSBError("list sandboxes", lsRes, err)
	}
	sandboxes := msb.ParseSandboxList(lsRes.Stdout)
	sb, exists := msb.FindSandbox(sandboxes, opts.Sandbox)
	if !exists {
		return fmt.Errorf("suspended sandbox %q does not exist in msb", opts.Sandbox)
	}
	if sb.Running {
		return fmt.Errorf("sandbox %q is already running", opts.Sandbox)
	}

	effectiveMode := meta.Mode
	var isDetached bool
	if opts.Detach {
		if effectiveMode == config.RunModeTUI && meta.RemoteControl {
			effectiveMode = config.RunModeRemoteControl
		}
		if effectiveMode != config.RunModeServe && effectiveMode != config.RunModeRemoteControl {
			return errors.New("--detach (-d) requires a --serve or --remote-control sandbox")
		}
		isDetached = true
	} else {
		switch effectiveMode {
		case config.RunModeServe:
			isDetached = meta.Detached || a.IsTTY == nil || !a.IsTTY()
		case config.RunModeRemoteControl:
			isDetached = true
		case config.RunModeTUI:
			isDetached = false
			if a.IsTTY == nil || !a.IsTTY() {
				return fmt.Errorf("the %s TUI requires a TTY", meta.Agent)
			}
		case config.RunModeCmd:
			isDetached = false
		default:
			return fmt.Errorf("unsupported run mode %q", effectiveMode)
		}
	}

	wantContinue := meta.Continue || opts.Continue
	wantSession := meta.ContinueSession
	if opts.ContinueSession != "" {
		wantContinue = false
		wantSession = opts.ContinueSession
	} else if opts.Continue {
		wantSession = ""
	}
	if (wantContinue || wantSession != "") && effectiveMode != config.RunModeTUI {
		return errors.New("--continue and --session require an interactive TUI sandbox")
	}

	skillsDir := filepath.Join(a.Env.DataDir, "skills")
	skipSkills := meta.NoSkills || opts.NoSkills
	var skillNames []string
	if meta.SkillsMounted {
		var sErr error
		skillNames, sErr = persist.InspectSkillsDir(skillsDir)
		if sErr != nil {
			return sErr
		}
		if err := config.EnsurePrivateDir(skillsDir); err != nil {
			return fmt.Errorf("prepare skills dir: %w", err)
		}
	} else if !skipSkills {
		var sErr error
		skillNames, sErr = persist.InspectSkillsDir(skillsDir)
		if sErr != nil {
			return sErr
		}
		if len(skillNames) > 0 {
			a.logf("Note: %s was created before global skills existed. Recreate it with 'agbox stop %s' to mount global skills.", opts.Sandbox, opts.Sandbox)
		}
	}

	rulesDir := filepath.Join(a.Env.DataDir, "rules")
	skipRules := meta.NoRules || opts.NoRules
	var ruleNames []string
	if meta.RulesMounted {
		var rErr error
		ruleNames, rErr = persist.InspectRulesDir(rulesDir)
		if rErr != nil {
			return rErr
		}
		if err := config.EnsurePrivateDir(rulesDir); err != nil {
			return fmt.Errorf("prepare rules dir: %w", err)
		}
	} else if !skipRules {
		var rErr error
		ruleNames, rErr = persist.InspectRulesDir(rulesDir)
		if rErr != nil {
			return rErr
		}
		if len(ruleNames) > 0 {
			a.logf("Note: %s was created before global rules existed. Recreate it with 'agbox stop %s' to mount global rules.", opts.Sandbox, opts.Sandbox)
		}
	}

	agentsDir := filepath.Join(a.Env.DataDir, "agents")
	skipAgents := meta.NoAgentCache || opts.NoAgentCache
	var cachedAgents []persist.CachedAgentInfo
	if meta.AgentsMounted {
		var agErr error
		cachedAgents, agErr = persist.InspectAgentsDir(agentsDir)
		if agErr != nil {
			return agErr
		}
		if err := persist.EnsureAgentsDir(agentsDir); err != nil {
			return err
		}
	} else if !skipAgents {
		var agErr error
		cachedAgents, agErr = persist.InspectAgentsDir(agentsDir)
		if agErr != nil {
			return agErr
		}
		if len(cachedAgents) > 0 {
			a.logf("Note: %s was created without $DATA_DIR/agents mounted. Recreate it with 'agbox stop %s' to use cached agent updates.", opts.Sandbox, opts.Sandbox)
		}
	}

	var profLock *persist.ProfileLock
	if meta.Profile != "" {
		var lErr error
		profLock, lErr = persist.LockProfile(a.Env.DataDir, meta.Profile)
		if lErr != nil {
			return lErr
		}
		defer func() { _ = profLock.Unlock() }()

		if err := a.checkProfileNotActive(meta.Profile, opts.Sandbox, sandboxes); err != nil {
			return err
		}
		volName := persist.FormatProfileVolumeName(meta.Profile)
		volExists, vErr := msb.VolumeExists(ctx, a.MSB, volName)
		if vErr != nil {
			return vErr
		}
		if !volExists {
			return fmt.Errorf("profile disk volume %q does not exist", volName)
		}
	}

	needsMask := false
	seenIndex := make(map[int]bool, len(meta.Shares))
	seenGuest := make(map[string]bool, len(meta.Shares))
	disjointTargets := make([]pathsec.ShareTarget, 0, len(meta.Shares))
	hubConfigs := make([]vcsfuse.HubShareConfig, 0, len(meta.Shares))
	for _, sh := range meta.Shares {
		if seenIndex[sh.Index] {
			return fmt.Errorf("duplicate share index %d in suspended metadata", sh.Index)
		}
		seenIndex[sh.Index] = true
		if !isSafeGuestShareName(sh.GuestName) {
			return fmt.Errorf("invalid guest share name %q in suspended metadata", sh.GuestName)
		}
		if _, gErr := pathsec.ValidateGuestAlias(sh.GuestName); gErr != nil {
			return fmt.Errorf("invalid guest share name %q in suspended metadata: %w", sh.GuestName, gErr)
		}
		if seenGuest[sh.GuestName] {
			return fmt.Errorf("duplicate guest share name %q in suspended metadata", sh.GuestName)
		}
		seenGuest[sh.GuestName] = true

		shRO := sh.EffectiveReadOnly(meta.ReadOnly)
		if sh.VCSPolicy != "" {
			if _, pErr := config.ParseVCSPolicy(string(sh.VCSPolicy)); pErr != nil {
				return fmt.Errorf("invalid VCS policy in suspended metadata: %w", pErr)
			}
		}
		shVCS := sh.EffectiveVCSPolicy()
		if shRO && shVCS == config.VCSAllowHooks {
			return fmt.Errorf("conflicting options in suspended metadata for %s: read-only share cannot enable vcs-hooks", sh.HostPath)
		}

		target, vErr := pathsec.ValidateShare(sh.HostPath, a.sharePolicy(shRO))
		if vErr != nil {
			return fmt.Errorf("validate share %s: %w", sh.HostPath, vErr)
		}
		if target.IsDir != sh.IsDir {
			return fmt.Errorf("share type changed for %s", sh.HostPath)
		}
		if !sh.IsDir && (sh.Masked || shVCS != config.VCSMask) {
			return fmt.Errorf("file share %s cannot enable directory VCS filtering or VCS policy", sh.HostPath)
		}

		if meta.WorkspaceHub {
			if maskMode == config.MaskStrict && sh.IsDir && !sh.Masked && sh.VCSPolicy == "" {
				return fmt.Errorf("directory share %s must use the FUSE VCS filter in strict mode", sh.HostPath)
			}
		} else {
			if maskMode == config.MaskStrict && sh.IsDir && !sh.Masked {
				return fmt.Errorf("directory share %s must use the FUSE VCS filter in strict mode", sh.HostPath)
			}
			if sh.Masked {
				needsMask = true
			}
		}

		disjointTargets = append(disjointTargets, pathsec.ShareTarget{
			HostPath:  target.HostPath,
			GuestName: sh.GuestName,
			IsDir:     sh.IsDir,
		})
		hubConfigs = append(hubConfigs, vcsfuse.HubShareConfig{
			GuestName: sh.GuestName,
			HostPath:  target.HostPath,
			ReadOnly:  shRO,
			VCSPolicy: shVCS,
		})
	}
	if err := pathsec.CheckDisjointHostPaths(disjointTargets); err != nil {
		return fmt.Errorf("suspended share metadata invalid: %w", err)
	}

	dieWithParent := !isDetached
	if meta.WorkspaceHub {
		if !DataDirSupportsFilter(a.Env.DataDir) {
			return fmt.Errorf("DATA_DIR (%s) cannot contain whitespace or backslashes when FUSE workspace hub is active", a.Env.DataDir)
		}
		if a.StartHub == nil {
			return errors.New("FUSE workspace hub starter is not configured")
		}
		wsDir := filepath.Join(runFilterDir, "ws")
		sockPath := filepath.Join(runFilterDir, "ws.sock")
		pidFile := filepath.Join(runFilterDir, "ws.pid")
		if _, fErr := a.StartHub(wsDir, sockPath, pidFile, hubConfigs, dieWithParent); fErr != nil {
			_ = mounttab.UnmountFilterDir(runFilterDir, a.MountCtl)
			return fmt.Errorf("mount FUSE workspace hub: %w", fErr)
		}
	} else {
		if needsMask {
			if !DataDirSupportsFilter(a.Env.DataDir) {
				return fmt.Errorf("DATA_DIR (%s) cannot contain whitespace or backslashes when VCS masking is active", a.Env.DataDir)
			}
			if a.StartFilter == nil {
				return errors.New("FUSE filter starter is not configured")
			}
		}
		for _, sh := range meta.Shares {
			if !sh.Masked {
				continue
			}
			mntDir := filepath.Join(runFilterDir, fmt.Sprintf("m%d", sh.Index))
			pidFile := mntDir + ".pid"
			if _, fErr := a.StartFilter(sh.HostPath, mntDir, pidFile, dieWithParent); fErr != nil {
				_ = mounttab.UnmountFilterDir(runFilterDir, a.MountCtl)
				return fmt.Errorf("mount FUSE filter for %s: %w", sh.HostPath, fErr)
			}
		}
	}

	a.logf("Starting suspended microVM %s...", opts.Sandbox)
	if startRes, err := a.MSB.Run(ctx, msb.CommandRequest{Args: []string{"start", opts.Sandbox}}); err != nil {
		_ = mounttab.UnmountFilterDir(runFilterDir, a.MountCtl)
		return formatMSBError("start sandbox "+opts.Sandbox, startRes, err)
	}

	meta.Sandbox = opts.Sandbox
	meta.OwnerPID = a.PID
	meta.Mode = effectiveMode
	meta.Detached = isDetached
	meta.Continue = false
	meta.ContinueSession = ""
	if err := config.SaveRunMeta(filepath.Join(runFilterDir, "run.meta"), meta); err != nil {
		_, _ = a.MSB.Run(context.Background(), msb.CommandRequest{Args: []string{"stop", opts.Sandbox}})
		_ = mounttab.UnmountFilterDir(runFilterDir, a.MountCtl)
		return fmt.Errorf("save run metadata: %w", err)
	}
	if err := os.Remove(suspendedPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove suspended marker: %w", err)
	}

	runCtx, cancelRun := context.WithCancel(ctx)
	defer cancelRun()

	sessionStarted := false
	detached := false
	var cleanupOnce sync.Once
	cleanup := func() {
		cleanupOnce.Do(func() {
			if detached {
				return
			}
			if hasMarker(suspendedPath) {
				_ = mounttab.UnmountFilterDir(runFilterDir, a.MountCtl)
				return
			}
			if meta.Persist || !sessionStarted {
				a.suspendSandboxOnExit(opts.Sandbox, runFilterDir, meta)
				return
			}
			_, _ = a.MSB.Run(context.Background(), msb.CommandRequest{Args: []string{"rm", "-f", opts.Sandbox}})
			_ = mounttab.TeardownFilterDir(runFilterDir, a.MountCtl)
		})
	}
	defer cleanup()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	defer signal.Stop(sigCh)
	go func() {
		select {
		case <-sigCh:
			cancelRun()
			cleanup()
			if profLock != nil {
				_ = profLock.Unlock()
			}
		case <-runCtx.Done():
		}
	}()

	if err := a.ensureGuestUser(runCtx, opts.Sandbox); err != nil {
		return err
	}
	if meta.AgentsMounted && !skipAgents && len(cachedAgents) > 0 {
		if err := a.setupGuestAgents(runCtx, opts.Sandbox); err != nil {
			return err
		}
	}
	if meta.SkillsMounted && !skipSkills && len(skillNames) > 0 {
		if err := a.setupGuestSkills(runCtx, opts.Sandbox); err != nil {
			return err
		}
	}
	if meta.RulesMounted && !skipRules && len(ruleNames) > 0 {
		if err := a.setupGuestRules(runCtx, opts.Sandbox); err != nil {
			return err
		}
	}
	if meta.Profile != "" {
		if err := a.setupGuestProfile(runCtx, opts.Sandbox); err != nil {
			return err
		}
	}
	if !meta.NoAuth && !opts.NoAuth {
		if err := a.pushAuth(runCtx, opts.Sandbox, meta.Agent); err != nil {
			return err
		}
	}
	if err := a.pushKeys(runCtx, opts.Sandbox); err != nil {
		return err
	}

	execMeta := meta
	execMeta.Continue = wantContinue
	execMeta.ContinueSession = wantSession
	sessionStarted = true
	return a.execSession(runCtx, execMeta, runFilterDir, false, &detached)
}

func (a *App) resolveRunShareTargets(opts RunOpts) ([]pathsec.ShareTarget, error) {
	var specs []pathsec.ShareSpec
	for _, raw := range opts.ShareSpecs {
		if raw == "" {
			continue
		}
		spec, err := pathsec.ParseShareSpec(raw)
		if err != nil {
			return nil, err
		}
		specs = append(specs, spec)
	}
	for _, raw := range opts.Paths {
		if raw == "" {
			continue
		}
		spec, err := pathsec.ParseShareSpec(raw)
		if err != nil {
			return nil, err
		}
		specs = append(specs, spec)
	}
	if len(specs) == 0 {
		return nil, nil
	}
	defaultVCS := opts.DefaultVCS
	if defaultVCS == "" {
		defaultVCS = config.VCSMask
	}
	return pathsec.ResolveShareSpecs(specs, pathsec.ResolveOpts{
		Policy:     a.sharePolicy(opts.ReadOnly),
		DefaultRO:  opts.ReadOnly,
		LockRO:     opts.LockAccess,
		DefaultVCS: defaultVCS,
		LockVCS:    opts.LockVCS,
	})
}

func (a *App) sharePolicy(readOnly bool) pathsec.Policy {
	return pathsec.Policy{
		HomeReal:         a.Env.HomeReal,
		AllowOutsideHome: a.Env.AllowOutsideHome,
		ReadOnly:         readOnly,
		Blocklist:        pathsec.DefaultBlocklist(a.Env.HomeReal, a.Env.DataDir, a.Env.MSBHome),
		VCSNames:         pathsec.DefaultVCSNames(),
	}
}

func isSafeGuestShareName(name string) bool {
	if name == "" || name == "." || name == ".." || strings.ContainsAny(name, "/:,\\") {
		return false
	}
	for _, r := range name {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

func (a *App) ensureGuestUser(ctx context.Context, sandbox string) error {
	if _, err := a.MSB.Run(ctx, msb.CommandRequest{
		Args: []string{"exec", "-u", config.GuestUser, sandbox, "--", "true"},
	}); err != nil {
		if pErr := a.provisionGuestUser(ctx, sandbox); pErr != nil {
			return fmt.Errorf("initialize guest user %q: %w", config.GuestUser, pErr)
		}
	}
	return nil
}

func (a *App) execSession(ctx context.Context, meta config.RunMeta, runFilterDir string, probe bool, detached *bool) error {
	runSandbox := meta.Sandbox
	suspendedPath := filepath.Join(runFilterDir, "suspended")
	guestEnv := msb.GuestEnvFlags()
	guestWorkDir := sessionWorkDir(meta.Shares)
	quotedWorkDir := msb.ShellQuote(guestWorkDir)

	switch meta.Mode {
	case config.RunModeCmd:
		a.logf("Running command in %s as %s (passwordless sudo available)...", runSandbox, config.GuestUser)
		noStdin := a.cmdNeedsNoStdin()
		var cmdStdin io.Reader = a.Stdin
		if noStdin {
			cmdStdin = bytes.NewReader(nil)
		}
		execArgs := msb.BuildExecArgs(msb.ExecCmdOpts{
			Sandbox: runSandbox,
			Stream:  true,
			NoStdin: noStdin,
			User:    config.GuestUser,
			Env:     guestEnv,
			Command: []string{
				"sh", "-c",
				fmt.Sprintf("%s cd %s && exec sh -c \"$1\"", msb.KeyLoaderPrefix, quotedWorkDir),
				"--", meta.Cmd,
			},
		})
		res, err := a.MSB.Run(ctx, msb.CommandRequest{
			Args:        execArgs,
			Stdin:       cmdStdin,
			Stdout:      a.Stdout,
			Stderr:      a.Stderr,
			Interactive: true,
		})
		if err != nil && hasMarker(suspendedPath) {
			a.logf("Session %s suspended.", runSandbox)
			return nil
		}
		return wrapPassthroughExit(res, err)

	case config.RunModeServe:
		a.logf("Starting 'opencode serve' on guest:%d as %s...", config.GuestPort, config.GuestUser)
		serveCmd := fmt.Sprintf("%s cd %s && exec opencode serve --hostname 0.0.0.0 --port %d",
			msb.KeyLoaderPrefix, quotedWorkDir, config.GuestPort)
		serveArgs := msb.BuildExecArgs(msb.ExecCmdOpts{
			Sandbox:  runSandbox,
			Detached: true,
			NoStdin:  true,
			User:     config.GuestUser,
			Env:      guestEnv,
			Command:  []string{"sh", "-c", serveCmd},
		})
		if serveRes, err := a.MSB.Run(ctx, msb.CommandRequest{Args: serveArgs}); err != nil {
			return formatMSBError("start opencode serve", serveRes, err)
		}

		up := false
		if a.WaitServeUI != nil {
			up = a.WaitServeUI(ctx, meta.Port, runSandbox)
		}
		if !up {
			a.warnf("OpenCode UI did not answer on 127.0.0.1:%d within 90s. Guest log tail:", meta.Port)
			if logRes, lErr := a.MSB.Run(ctx, msb.CommandRequest{Args: []string{"logs", runSandbox}}); lErr == nil {
				fmt.Fprintln(a.Stderr, tailLines(logRes.Stdout, 20))
			}
			return fmt.Errorf("opencode serve did not become ready on 127.0.0.1:%d", meta.Port)
		}

		a.logf("OpenCode web UI: http://127.0.0.1:%d", meta.Port)
		a.warnf("Loopback TCP (127.0.0.1:%d) is reachable by local host processes. Set OPENCODE_SERVER_PASSWORD for HTTP basic auth. Provider keys stay inside the disposable microVM.", meta.Port)

		if probe {
			a.logf("--probe: UI verified. Stopping now.")
			return nil
		}

		if meta.Detached {
			if err := writeMarkerAtomic(filepath.Join(runFilterDir, "detached"), runSandbox+"\n"); err != nil {
				return fmt.Errorf("write detached marker: %w", err)
			}
			*detached = true
			if meta.Persist {
				a.logf("Detached persistent session %s is running. Suspend it with 'agbox suspend %s' or delete it with 'agbox stop %s'.", runSandbox, runSandbox, runSandbox)
			} else {
				a.logf("Detached session %s is running. Stop it with: agbox stop %s", runSandbox, runSandbox)
			}
			return nil
		}

		if meta.Persist {
			fmt.Fprintln(a.Stdout, "Press Ctrl-C to stop the microVM and save guest changes.")
		} else {
			fmt.Fprintln(a.Stdout, "Press Ctrl-C to stop the microVM and delete all guest changes.")
		}
		for {
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(2 * time.Second):
				if hasMarker(suspendedPath) {
					a.logf("Session %s suspended.", runSandbox)
					return nil
				}
				if _, pErr := a.MSB.Run(ctx, msb.CommandRequest{Args: []string{"ping", runSandbox}}); pErr != nil {
					if hasMarker(suspendedPath) {
						a.logf("Session %s suspended.", runSandbox)
					}
					return nil
				}
			}
		}

	case config.RunModeRemoteControl:
		startDaemonCmd := fmt.Sprintf("%s cd %s && agy remote-control start --name %s",
			msb.KeyLoaderPrefix, quotedWorkDir, msb.ShellQuote(runSandbox))
		startArgs := msb.BuildExecArgs(msb.ExecCmdOpts{
			Sandbox: runSandbox,
			User:    config.GuestUser,
			Env:     guestEnv,
			Command: []string{"sh", "-c", startDaemonCmd},
		})
		res, startErr := a.MSB.Run(ctx, msb.CommandRequest{Args: startArgs})
		if startErr != nil && a.IsTTY != nil && a.IsTTY() {
			a.logf("Authenticating agy in %s. Open the printed URL, paste the verification code, and run /exit to detach.", runSandbox)
			authArgs := msb.BuildExecArgs(msb.ExecCmdOpts{
				Sandbox: runSandbox,
				TTY:     true,
				User:    config.GuestUser,
				Env:     guestEnv,
				Command: []string{"sh", "-c", fmt.Sprintf("%s cd %s && exec agy", msb.KeyLoaderPrefix, quotedWorkDir)},
			})
			_, _ = a.MSB.Run(ctx, msb.CommandRequest{
				Args:        authArgs,
				Interactive: true,
			})
			res, startErr = a.MSB.Run(ctx, msb.CommandRequest{Args: startArgs})
		}
		if startErr != nil {
			msg := strings.TrimSpace(res.Stderr + "\n" + res.Stdout)
			if msg != "" {
				return fmt.Errorf("agy remote-control start failed: %w (%s)", startErr, msg)
			}
			return fmt.Errorf("agy remote-control start failed: %w", startErr)
		}

		statusArgs := msb.BuildExecArgs(msb.ExecCmdOpts{
			Sandbox: runSandbox,
			User:    config.GuestUser,
			Env:     guestEnv,
			Command: []string{"sh", "-c", "agy remote-control status"},
		})
		if stRes, stErr := a.MSB.Run(ctx, msb.CommandRequest{Args: statusArgs}); stErr == nil && strings.TrimSpace(stRes.Stdout) != "" {
			fmt.Fprintln(a.Stdout, strings.TrimSpace(stRes.Stdout))
		}

		if err := writeMarkerAtomic(filepath.Join(runFilterDir, "detached"), runSandbox+"\n"); err != nil {
			return fmt.Errorf("write detached marker: %w", err)
		}
		*detached = true
		a.logf("Detached Remote Control microVM: %s (instance: %s)", runSandbox, runSandbox)
		a.logf("Open https://antigravity.google.com and select %q in the instance switcher.", runSandbox)
		if meta.Persist {
			a.logf("Suspend it with 'agbox suspend %s' or delete it with 'agbox stop %s'.", runSandbox, runSandbox)
		} else {
			a.logf("Stop and delete it with: agbox stop %s", runSandbox)
		}
		return nil

	default:
		inv := buildTUIInvokeCommand(meta)
		modeStr := summarizeShareModes(meta)
		a.logf("Starting %s (%s) in %s as %s (passwordless sudo available).",
			meta.Agent, inv, runSandbox, config.GuestUser)
		a.logf("Shared: %d path(s) under /workspace (%s).", len(meta.Shares), modeStr)

		tuiArgs := msb.BuildExecArgs(msb.ExecCmdOpts{
			Sandbox: runSandbox,
			TTY:     true,
			User:    config.GuestUser,
			Env:     guestEnv,
			Command: []string{"sh", "-c", fmt.Sprintf("%s cd %s && exec %s", msb.KeyLoaderPrefix, quotedWorkDir, inv)},
		})
		res, err := a.MSB.Run(ctx, msb.CommandRequest{
			Args:        tuiArgs,
			Interactive: true,
		})
		if err != nil && hasMarker(suspendedPath) {
			a.logf("Session %s suspended.", runSandbox)
			return nil
		}
		return wrapPassthroughExit(res, err)
	}
}

func summarizeShareModes(meta config.RunMeta) string {
	if len(meta.Shares) == 0 {
		if meta.ReadOnly {
			return "ro"
		}
		return "none"
	}
	hasRO := false
	hasRW := false
	for _, sh := range meta.Shares {
		if sh.EffectiveReadOnly(meta.ReadOnly) {
			hasRO = true
		} else {
			hasRW = true
		}
	}
	if hasRO && hasRW {
		return "mixed ro/rw"
	}
	if hasRO {
		return "ro"
	}
	return "rw"
}

func (a *App) pushKeys(ctx context.Context, sandbox string) error {
	if a.Getenv == nil {
		return nil
	}
	script, count := msb.FormatEnvExports(a.Getenv, msb.DefaultPassthroughEnvVars)
	if count == 0 {
		return nil
	}
	keyRes, err := a.MSB.Run(ctx, msb.CommandRequest{
		Args:  []string{"exec", "-u", config.GuestUser, sandbox, "--", "sh", "-c", "umask 077; cat > " + config.GuestKeysFile},
		Stdin: strings.NewReader(script),
	})
	if err != nil {
		return formatMSBError("stream environment secrets into "+sandbox, keyRes, err)
	}
	a.logf("Streamed %d environment secret(s) from host env into the disposable guest.", count)
	return nil
}

func (a *App) defaultWaitServeUI(ctx context.Context, port int, sandbox string) bool {
	client := &http.Client{Timeout: 3 * time.Second}
	url := fmt.Sprintf("http://127.0.0.1:%d/doc", port)
	pass := ""
	user := "opencode"
	if a.Getenv != nil {
		pass = a.Getenv("OPENCODE_SERVER_PASSWORD")
		if u := a.Getenv("OPENCODE_SERVER_USERNAME"); u != "" {
			user = u
		}
	}

	for range 90 {
		select {
		case <-ctx.Done():
			return false
		case <-time.After(time.Second):
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err == nil {
			if pass != "" {
				req.SetBasicAuth(user, pass)
			}
			resp, rErr := client.Do(req)
			if rErr == nil {
				_, _ = io.Copy(io.Discard, resp.Body)
				_ = resp.Body.Close()
				if resp.StatusCode >= 200 && resp.StatusCode < 300 {
					return true
				}
			}
		}
		if _, pErr := a.MSB.Run(ctx, msb.CommandRequest{Args: []string{"ping", sandbox}}); pErr != nil {
			return false
		}
	}
	return false
}

func tailLines(s string, n int) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(lines) <= n {
		return strings.Join(lines, "\n")
	}
	return strings.Join(lines[len(lines)-n:], "\n")
}

// Stop deletes a running or suspended run sandbox and unmounts its FUSE shares.
func (a *App) Stop(ctx context.Context, args []string) error {
	name, allowRoot, err := parseStopOpts(args)
	if err != nil {
		return err
	}
	if err := a.verifyUser(allowRoot); err != nil {
		return err
	}
	if err := a.ensureMSB(); err != nil {
		return err
	}
	rmRes, rmErr := a.MSB.Run(ctx, msb.CommandRequest{Args: []string{"rm", "-f", name}})
	var tdErr error
	if dirID, dErr := RunDirIDFromSandbox(name); dErr == nil {
		filterDir := filepath.Join(a.Env.DataDir, "run", dirID)
		if _, sErr := os.Stat(filterDir); sErr == nil {
			tdErr = mounttab.TeardownFilterDir(filterDir, a.MountCtl)
		}
	}
	if rmErr != nil {
		return formatMSBError("delete sandbox "+name, rmRes, rmErr)
	}
	if tdErr != nil {
		return tdErr
	}
	a.logf("Deleted %s.", name)
	return nil
}

// Remove deletes all agbox sandboxes, snapshots, profile volumes, FUSE mounts, and `$DATA_DIR`.
func (a *App) Remove(ctx context.Context, args []string) error {
	yes, allowRoot, err := parseRemoveOpts(args)
	if err != nil {
		return err
	}
	if err := a.verifyUser(allowRoot); err != nil {
		return err
	}
	if !yes {
		fmt.Fprintf(a.Stdout, "This deletes: agbox sandboxes (%s, agbox-*), snapshots (%s), profile volumes (agbox-profile-*), unused cached images, and %s.\n",
			config.BaseSandbox, config.SnapGroup, a.Env.DataDir)
		fmt.Fprintln(a.Stdout, "It does NOT modify the msb binary, your other sandboxes, or any shared host files.")
		fmt.Fprintln(a.Stdout, "Type 'y' to confirm:")
		sc := bufio.NewScanner(a.Stdin)
		if !sc.Scan() || strings.TrimSpace(sc.Text()) != "y" {
			return errors.New("aborted")
		}
	}

	if err := a.ensureMSB(); err == nil && a.MSB != nil {
		if lsRes, lErr := a.MSB.Run(ctx, msb.CommandRequest{Args: []string{"ls"}}); lErr == nil {
			for _, sb := range msb.ParseSandboxList(lsRes.Stdout) {
				if isAgboxSandboxName(sb.Name) {
					_, _ = a.MSB.Run(ctx, msb.CommandRequest{Args: []string{"rm", "-f", sb.Name}})
				}
			}
		}

		if volRes, vErr := a.MSB.Run(ctx, msb.CommandRequest{Args: []string{"volume", "ls"}}); vErr == nil {
			for _, v := range msb.ParseVolumeList(volRes.Stdout) {
				if persist.IsProfileVolumeName(v) {
					_, _ = a.MSB.Run(ctx, msb.CommandRequest{Args: []string{"volume", "rm", v}})
				}
			}
		}

		st, _ := config.LoadFile(a.Env.ConfigFile)
		if snapRes, sErr := a.MSB.Run(ctx, msb.CommandRequest{Args: []string{"snap", "ls"}}); sErr == nil {
			existing := msb.ParseSnapshotList(snapRes.Stdout)
			removed := make(map[string]bool)
			for m := st.SnapCount; m >= 1; m-- {
				target := fmt.Sprintf("%s:v%d", config.SnapGroup, m)
				if containsStr(existing, target) {
					if res, rErr := a.MSB.Run(ctx, msb.CommandRequest{Args: []string{"snap", "rm", "--force", target}}); rErr != nil {
						a.warnf("could not remove %s: %s", target, strings.TrimSpace(res.Stderr))
					}
					removed[target] = true
				}
			}
			for _, name := range existing {
				if removed[name] {
					continue
				}
				if isAgboxSnapshotName(name) {
					if res, rErr := a.MSB.Run(ctx, msb.CommandRequest{Args: []string{"snap", "rm", "--force", name}}); rErr != nil {
						a.warnf("could not remove snapshot %s: %s", name, strings.TrimSpace(res.Stderr))
					}
				}
			}
		}

		for _, grp := range []string{config.SnapGroup, config.BaseSandbox} {
			if qRes, qErr := a.MSB.Run(ctx, msb.CommandRequest{Args: []string{"snap", "ls", "--group", grp, "-q"}}); qErr == nil {
				for _, line := range strings.Split(qRes.Stdout, "\n") {
					digest := strings.TrimSpace(line)
					if digest != "" {
						_, _ = a.MSB.Run(ctx, msb.CommandRequest{Args: []string{"snap", "rm", "--force", digest}})
					}
				}
			}
			if a.Env.MSBHome != "" {
				_ = os.RemoveAll(filepath.Join(a.Env.MSBHome, "snapshots", grp))
			}
		}
		_, _ = a.MSB.Run(ctx, msb.CommandRequest{Args: []string{"snap", "reindex"}})
		_, _ = a.MSB.Run(ctx, msb.CommandRequest{Args: []string{"image", "prune", "-y"}})
		_, _ = a.MSB.Run(ctx, msb.CommandRequest{Args: []string{"prune", "-y"}})
	}

	runRoot := filepath.Join(a.Env.DataDir, "run")
	if entries, rErr := os.ReadDir(runRoot); rErr == nil {
		for _, entry := range entries {
			if entry.IsDir() {
				_ = mounttab.TeardownFilterDir(filepath.Join(runRoot, entry.Name()), a.MountCtl)
			}
		}
	}

	if err := mounttab.TeardownFilterDir(a.Env.DataDir, a.MountCtl); err != nil {
		return err
	}

	a.logf("Deleted all agbox state.")
	return nil
}

func isAgboxSandboxName(name string) bool {
	return name == config.BaseSandbox || IsRunSandboxName(name)
}

func isAgboxSnapshotName(name string) bool {
	for _, grp := range []string{config.SnapGroup, config.BaseSandbox} {
		if name == grp || strings.HasPrefix(name, grp+":") {
			return true
		}
	}
	return false
}

func containsStr(list []string, target string) bool {
	for _, s := range list {
		if s == target {
			return true
		}
	}
	return false
}

// Status prints the current base configuration, persistence state, sandboxes, snapshots, and disk usage.
func (a *App) Status(ctx context.Context, args []string) error {
	opts, err := ParseStatusArgs(args)
	if err != nil {
		return err
	}
	if err := a.requireSetup(opts.AllowRoot); err != nil {
		return err
	}
	fmt.Fprintln(a.Stdout, "== agbox base config ==")
	if raw, err := os.ReadFile(a.Env.ConfigFile); err == nil {
		fmt.Fprint(a.Stdout, string(raw))
	} else {
		fmt.Fprintln(a.Stdout, "(none - run create-base)")
	}

	a.printPersistenceStatus(ctx)

	fmt.Fprintln(a.Stdout, "\n== sandboxes ==")
	if res, err := a.MSB.Run(ctx, msb.CommandRequest{Args: []string{"ls"}}); err == nil {
		fmt.Fprint(a.Stdout, res.Stdout)
	}

	fmt.Fprintln(a.Stdout, "\n== snapshots ==")
	if res, err := a.MSB.Run(ctx, msb.CommandRequest{Args: []string{"snap", "ls"}}); err == nil {
		fmt.Fprint(a.Stdout, res.Stdout)
	}

	fmt.Fprintln(a.Stdout, "\n== storage ==")
	if res, err := a.MSB.Run(ctx, msb.CommandRequest{Args: []string{"df"}}); err == nil {
		fmt.Fprint(a.Stdout, res.Stdout)
	}
	return nil
}

// UsageText returns the top-level CLI help message.
func UsageText() string {
	return `agbox — Run OpenCode or Google Antigravity CLI inside an isolated microVM.

Global options:
  --allow-root
      Allow agbox to run as the root user (or set AGBOX_ALLOW_ROOT=1).

Modes:
  agbox setup [--allow-root]
      Check host prerequisites (msb, /dev/kvm, FUSE, and microVM smoke test).

  agbox create-base [--force] [--allow-root] [--add <categories>] <opencode|antigravity|both>
      Create the base microVM and save snapshot agbox:vN.

  agbox edit-base [--allow-root] [--add <categories>] [--list] [--shell] [--cmd "shell"] [--no-snap]
      Start the base microVM and install categories or run custom updates.
      Save snapshot agbox:v<N+1> unless you pass --no-snap.

  agbox update [--allow-root] [antigravity|opencode|both|status|clear]
      Update agent binaries inside a disposable zero-share microVM and cache
      verified ELF binaries in $DATA_DIR/agents without rebuilding the base snapshot.

  agbox auth [--allow-root] [antigravity|opencode|status|logout]
      Sign in inside a disposable microVM and save credentials in $DATA_DIR/auth.

  agbox skills [--allow-root] [list|add [--force] <path>|rm <name>]
      Manage global skills mounted read-only into sandboxes from $DATA_DIR/skills.

  agbox rules [--allow-root] [list|add [--force] [--name NAME] <file.md>|show [<name>]|rm <name|--all>]
      Manage global rules mounted read-only into sandboxes from $DATA_DIR/rules.

  agbox profile [--allow-root] [list|create [--size SIZE] <name>|rm [--force] <name>]
      Manage ext4 disk profiles for conversation history across ephemeral runs.

  agbox share [--allow-root] <list|add|set|rm> <sandbox> [...]
      List, attach, update permissions on, or detach /workspace shares on a running
      or suspended sandbox (agbox share add defaults to ro,mask).

  agbox run [options] [opencode|antigravity] [path[:opts]...]
      Restore a microVM and mask VCS files and directories.
      Block local, private, multicast, and cloud-config IPs by default.
      Delete the microVM on exit unless you pass --persist or suspend it.
      Options (must precede paths):
        --name NAME          Name the sandbox agbox-NAME instead of agbox-run-PID
        --persist            Keep the named microVM on exit and resume it on repeat runs
        --profile NAME       Mount ext4 profile volume agbox-profile-NAME for conversations
        -c, --continue       Continue the most recent conversation in TUI mode
        -s, --session ID     Continue conversation ID in TUI mode (alias: --conversation)
        --no-auth            Skip saved login credentials from $DATA_DIR/auth
        --no-skills          Skip global skills from $DATA_DIR/skills
        --no-rules           Skip global rules from $DATA_DIR/rules
        --no-agent-cache     Skip cached agent binary updates from $DATA_DIR/agents
        --allow-root         Allow agbox to run as the root user
        --share PATH[:OPTS]  Share a host path with modifiers (ro,rw,mask,vcs,vcs-hooks,as=NAME)
        --share-hub          Mount an empty /workspace FUSE hub so shares can be added live
        --ro / --rw          Set default share access mode (conflicts with opposite modifier)
        --mask-vcs           Mask VCS metadata inside directory shares (default)
        --vcs                Allow VCS metadata inside shares while write-protecting hooks
        --vcs-hooks          Allow VCS metadata and writable hooks inside writable shares
        --no-mask            Disable the FUSE VCS filter (.git is visible to guest)
        --serve              Run 'opencode serve' and bind the web UI on 127.0.0.1
        --port N             Use fixed loopback TCP port N for --serve
        --probe              With --serve: wait for the web UI, then exit
        --remote-control     Run 'agy' with Remote Control for https://antigravity.google.com
        -d, --detach         Keep --remote-control or --serve running in the background
        --cmd "shell"        Run one command in the microVM and exit
        --no-net             Disable guest network access
        --net SPEC           Set network profile (public|none|private|host|all) or rule
        --cpus N             Override vCPU count for this run
        --memory SIZE        Override RAM size for this run (for example, 4G)

  agbox suspend [--allow-root] <sandbox>
      Stop a run microVM, keep its root disk, and unmount host FUSE shares.

  agbox resume [--allow-root] [-d|--detach] [-c|--continue] [--session ID] <sandbox>
      Validate shares, mount FUSE filters, start a suspended microVM, and restart its agent.

  agbox stop [--allow-root] <sandbox>
      Delete a running or suspended run microVM and unmount its FUSE shares.

  agbox remove [--allow-root] [--yes]
      Delete all agbox microVMs, snapshots, profile volumes, FUSE mounts, and $DATA_DIR.

  agbox status [--allow-root]
      Show base configuration, persistence state, microVMs, snapshots, and disk usage.
`
}

// RunUsageText returns the help message for `agbox run --help`.
func RunUsageText() string {
	return `Usage: agbox run [options] [agent] [path[:opts]...]

  --name NAME          name the sandbox agbox-NAME instead of agbox-run-PID
  --persist            keep the named microVM on exit and resume it on repeat runs
  --profile NAME       mount ext4 profile volume agbox-profile-NAME for conversations
  -c, --continue       continue the most recent conversation in TUI mode
  -s, --session ID     continue conversation ID in TUI mode (alias: --conversation)
  --no-auth            skip saved login credentials from $DATA_DIR/auth
  --no-skills          skip global skills from $DATA_DIR/skills
  --no-rules           skip global rules from $DATA_DIR/rules
  --no-agent-cache     skip cached agent binary updates from $DATA_DIR/agents
  --allow-root         allow agbox to run as the root user
  --share PATH[:OPTS]  share a host path (modifiers: ro,rw,mask,vcs,vcs-hooks,as=NAME)
  --share-hub          mount an empty /workspace FUSE hub for live 'agbox share add'
  --ro / --rw          set default share access mode (errors on conflicting modifiers)
  --mask-vcs           mask VCS metadata in directory shares (default)
  --vcs                allow VCS metadata in shares while write-protecting hooks
  --vcs-hooks          allow VCS metadata and writable hooks in writable shares
  --no-mask            disable the FUSE VCS filter (.git is visible to guest)
  --serve              run 'opencode serve' and bind the web UI on 127.0.0.1
  --port N             use fixed loopback port N for --serve (default: random)
  --probe              with --serve: wait for the web UI, then exit
  --remote-control     run 'agy' with Remote Control for https://antigravity.google.com
  -d, --detach         keep --remote-control or --serve running in the background
  --cmd 'shell'        run one command in the microVM and exit
  --no-net             disable guest network access
  --net SPEC           set network profile (public|none|private|host|all) or msb rule
  --cpus N / --memory S   override vCPU count or RAM size for this run
  agent                opencode | antigravity (default: the base's agent)
  path[:opts]...       host dirs/files mounted at /workspace/<name>
`
}

// Dispatch executes the requested top-level subcommand on App.
func (a *App) Dispatch(ctx context.Context, args []string) int {
	globalOpts, gErr := ParseGlobalArgs(args)
	if gErr != nil {
		if errors.Is(gErr, ErrHelp) {
			fmt.Fprint(a.Stdout, UsageText())
			return 0
		}
		fmt.Fprintf(a.Stderr, "[agbox] ERROR: %v\n", gErr)
		return 1
	}

	mode := globalOpts.Mode
	rest := globalOpts.Rest
	if globalOpts.AllowRoot {
		rest = append([]string{"--allow-root"}, rest...)
	}

	var err error
	switch mode {
	case "setup":
		err = a.Setup(ctx, rest)
	case "create-base":
		err = a.CreateBase(ctx, rest)
	case "edit-base":
		err = a.EditBase(ctx, rest)
	case "update":
		err = a.Update(ctx, rest)
		if errors.Is(err, ErrHelp) {
			fmt.Fprint(a.Stdout, UpdateUsageText())
			return 0
		}
	case "auth":
		err = a.Auth(ctx, rest)
		if errors.Is(err, ErrHelp) {
			fmt.Fprint(a.Stdout, AuthUsageText())
			return 0
		}
	case "skills":
		err = a.Skills(ctx, rest)
		if errors.Is(err, ErrHelp) {
			fmt.Fprint(a.Stdout, SkillsUsageText())
			return 0
		}
	case "rules":
		err = a.Rules(ctx, rest)
		if errors.Is(err, ErrHelp) {
			fmt.Fprint(a.Stdout, RulesUsageText())
			return 0
		}
	case "profile":
		err = a.Profile(ctx, rest)
		if errors.Is(err, ErrHelp) {
			fmt.Fprint(a.Stdout, ProfileUsageText())
			return 0
		}
	case "share":
		err = a.Share(ctx, rest)
		if errors.Is(err, ErrHelp) {
			fmt.Fprint(a.Stdout, ShareUsageText())
			return 0
		}
	case "run":
		err = a.Run(ctx, rest)
		if errors.Is(err, ErrHelp) {
			fmt.Fprint(a.Stdout, RunUsageText())
			return 0
		}
	case "suspend":
		err = a.Suspend(ctx, rest)
	case "resume":
		err = a.Resume(ctx, rest)
	case "stop":
		err = a.Stop(ctx, rest)
	case "remove":
		err = a.Remove(ctx, rest)
	case "status":
		err = a.Status(ctx, rest)
	default:
		fmt.Fprintf(a.Stderr, "[agbox] ERROR: unknown mode %q (try: setup create-base edit-base update auth skills rules profile share run suspend resume stop remove status)\n", mode)
		return 1
	}

	if err != nil {
		if errors.Is(err, ErrHelp) {
			fmt.Fprint(a.Stdout, UsageText())
			return 0
		}
		var passErr passthroughExitError
		if errors.As(err, &passErr) {
			return passErr.code
		}
		fmt.Fprintf(a.Stderr, "[agbox] ERROR: %v\n", err)
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) && exitErr.ExitCode() > 0 {
			return exitErr.ExitCode()
		}
		return 1
	}
	return 0
}

// Main initializes a production App and dispatches os.Args[1:].
func Main(args []string) int {
	if _, err := ParseGlobalArgs(args); err != nil {
		if errors.Is(err, ErrHelp) {
			fmt.Print(UsageText())
			return 0
		}
		fmt.Fprintf(os.Stderr, "[agbox] ERROR: %v\n", err)
		return 1
	}
	app, err := NewApp()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[agbox] ERROR: %v\n", err)
		return 1
	}
	return app.Dispatch(context.Background(), args)
}
