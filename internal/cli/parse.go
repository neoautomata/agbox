package cli

import (
	"errors"
	"fmt"
	"math"
	"os"
	"strconv"
	"strings"

	"agbox/internal/config"
	"agbox/internal/msb"
	"agbox/internal/pathsec"
	"agbox/internal/persist"
)

const sandboxPrefix = "agbox-"

func consumeFlagValue(args []string, idx *int, names ...string) (string, bool, error) {
	cur := args[*idx]
	for _, name := range names {
		if strings.HasPrefix(name, "--") && strings.HasPrefix(cur, name+"=") {
			return strings.TrimPrefix(cur, name+"="), true, nil
		}
		if cur == name {
			if *idx+1 >= len(args) {
				return "", true, fmt.Errorf("%s requires a value", name)
			}
			*idx++
			return args[*idx], true, nil
		}
	}
	return "", false, nil
}

type globalOpts struct {
	AllowRoot bool
	Mode      string
	Rest      []string
}

func parseGlobalArgs(args []string) (globalOpts, error) {
	var opts globalOpts
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--allow-root":
			opts.AllowRoot = true
		case "-h", "--help", "help":
			return opts, errHelp
		case "--version", "version":
			opts.Mode = "version"
			opts.Rest = args[i+1:]
			return opts, nil
		default:
			if strings.HasPrefix(args[i], "-") {
				return globalOpts{}, fmt.Errorf("unknown option %q (run 'agbox --help')", args[i])
			}
			opts.Mode = args[i]
			opts.Rest = args[i+1:]
			return opts, nil
		}
	}
	return opts, errHelp
}

func checkRootExecution(euid int, envAllowRoot, flagAllowRoot bool) (string, error) {
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

type setupOpts struct {
	AllowRoot bool
}

func parseSetupArgs(args []string) (setupOpts, error) {
	var opts setupOpts
	for _, a := range args {
		switch a {
		case "-h", "--help":
			return setupOpts{}, errHelp
		case "--allow-root":
			opts.AllowRoot = true
		default:
			return setupOpts{}, fmt.Errorf("unknown setup option: %s (expected --allow-root)", a)
		}
	}
	return opts, nil
}

type statusOpts struct {
	AllowRoot bool
}

func parseStatusArgs(args []string) (statusOpts, error) {
	var opts statusOpts
	for _, a := range args {
		switch a {
		case "-h", "--help":
			return statusOpts{}, errHelp
		case "--allow-root":
			opts.AllowRoot = true
		default:
			return statusOpts{}, fmt.Errorf("unknown status option: %s (expected --allow-root)", a)
		}
	}
	return opts, nil
}

type createBaseOpts struct {
	Agent      string
	Force      bool
	AllowRoot  bool
	Categories []msb.Category
}

func parseCreateBaseArgs(args []string) (createBaseOpts, error) {
	var opts createBaseOpts
	var pos []string
	var catSpecs []string
	for i := 0; i < len(args); i++ {
		if val, ok, err := consumeFlagValue(args, &i, "--add", "--categories"); ok {
			if err != nil || val == "" {
				return createBaseOpts{}, fmt.Errorf("--add requires at least one category name (%s, or all)", msb.CategoryNamesList())
			}
			catSpecs = append(catSpecs, val)
			continue
		}
		a := args[i]
		switch a {
		case "-h", "--help":
			return createBaseOpts{}, errHelp
		case "--force":
			opts.Force = true
		case "--allow-root":
			opts.AllowRoot = true
		default:
			if strings.HasPrefix(a, "-") {
				return createBaseOpts{}, fmt.Errorf("unknown create-base option: %s", a)
			}
			pos = append(pos, a)
		}
	}
	if len(pos) != 1 {
		return createBaseOpts{}, errors.New("usage: agbox create-base [--force] [--allow-root] [--add <categories>] <opencode|antigravity|both>")
	}
	switch pos[0] {
	case "opencode", "antigravity", "both":
		opts.Agent = pos[0]
	default:
		return createBaseOpts{}, errors.New("usage: agbox create-base [--force] [--allow-root] [--add <categories>] <opencode|antigravity|both>")
	}
	if len(catSpecs) > 0 {
		cats, err := msb.ResolveCategories(catSpecs)
		if err != nil {
			return createBaseOpts{}, err
		}
		opts.Categories = cats
	}
	return opts, nil
}

type editBaseOpts struct {
	Cmd        string
	NoSnap     bool
	Shell      bool
	ListOnly   bool
	AllowRoot  bool
	Categories []msb.Category
}

func parseEditBaseArgs(args []string) (editBaseOpts, error) {
	var opts editBaseOpts
	var catSpecs []string
	for i := 0; i < len(args); i++ {
		if val, ok, err := consumeFlagValue(args, &i, "--add", "--categories"); ok {
			if err != nil || val == "" {
				return editBaseOpts{}, fmt.Errorf("--add requires at least one category (%s, or all)", msb.CategoryNamesList())
			}
			catSpecs = append(catSpecs, val)
			continue
		}
		if val, ok, err := consumeFlagValue(args, &i, "--cmd"); ok {
			if err != nil || val == "" {
				return editBaseOpts{}, errors.New("--cmd requires a non-empty shell command")
			}
			opts.Cmd = val
			continue
		}
		switch args[i] {
		case "-h", "--help":
			return editBaseOpts{}, errHelp
		case "--allow-root":
			opts.AllowRoot = true
		case "--list", "--list-categories":
			opts.ListOnly = true
		case "--shell":
			opts.Shell = true
		case "--no-snap":
			opts.NoSnap = true
		default:
			if strings.HasPrefix(args[i], "-") {
				return editBaseOpts{}, fmt.Errorf("unknown edit-base option: %s (use: --allow-root | --add <cats> | --list | --shell | --cmd \"shell\" | --no-snap)", args[i])
			}
			catSpecs = append(catSpecs, args[i])
		}
	}
	if len(catSpecs) > 0 {
		cats, err := msb.ResolveCategories(catSpecs)
		if err != nil {
			return editBaseOpts{}, err
		}
		opts.Categories = cats
	}
	return opts, nil
}

func validateRunName(raw string) (string, error) {
	if raw == "" {
		return "", errors.New("--name requires a non-empty sandbox name")
	}
	if len(raw) > 63 {
		return "", errors.New("--name must be 63 characters or fewer")
	}
	if raw == "base" {
		return "", errors.New("name \"base\" is reserved for agbox-base")
	}
	if strings.HasPrefix(raw, "run-") && isDigits(strings.TrimPrefix(raw, "run-")) {
		return "", fmt.Errorf("invalid --name %q: names matching run-<digits> are reserved for PID runs", raw)
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

func formatRunSandboxName(name string, pid int) string {
	if name != "" {
		return sandboxPrefix + name
	}
	return fmt.Sprintf("%s-%d", config.RunPrefix, pid)
}

func isRunSandboxName(sandbox string) bool {
	if sandbox == config.BaseSandbox || !strings.HasPrefix(sandbox, sandboxPrefix) {
		return false
	}
	runPIDPrefix := config.RunPrefix + "-"
	if strings.HasPrefix(sandbox, runPIDPrefix) && isDigits(strings.TrimPrefix(sandbox, runPIDPrefix)) {
		return true
	}
	suffix := strings.TrimPrefix(sandbox, sandboxPrefix)
	_, err := validateRunName(suffix)
	return err == nil
}

func runDirIDFromSandbox(sandbox string) (string, error) {
	if !isRunSandboxName(sandbox) {
		return "", fmt.Errorf("invalid agbox run sandbox %q", sandbox)
	}
	runPIDPrefix := config.RunPrefix + "-"
	if strings.HasPrefix(sandbox, runPIDPrefix) {
		pidStr := strings.TrimPrefix(sandbox, runPIDPrefix)
		if isDigits(pidStr) {
			return pidStr, nil
		}
	}
	suffix := strings.TrimPrefix(sandbox, sandboxPrefix)
	if isDigits(suffix) {
		return "_" + suffix, nil
	}
	return suffix, nil
}

func sandboxFromRunDirID(dirID string) (string, bool) {
	if dirID == "" {
		return "", false
	}
	if isDigits(dirID) {
		return config.RunPrefix + "-" + dirID, true
	}
	if strings.HasPrefix(dirID, "_") && isDigits(dirID[1:]) {
		return sandboxPrefix + dirID[1:], true
	}
	if strings.HasPrefix(dirID, "run-") && isDigits(strings.TrimPrefix(dirID, "run-")) {
		return "", false
	}
	if _, err := validateRunName(dirID); err != nil {
		return "", false
	}
	return sandboxPrefix + dirID, true
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

type runOpts struct {
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

func parseRunArgs(args []string, defaultMask config.MaskMode, pathExists func(string) bool) (runOpts, error) {
	if defaultMask == "" {
		defaultMask = config.MaskStrict
	}
	if pathExists == nil {
		pathExists = func(p string) bool {
			_, err := os.Stat(p)
			return err == nil
		}
	}

	opts := runOpts{
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
			return runOpts{}, errHelp
		}
		if arg == "--" {
			opts.Paths = append(opts.Paths, args[i+1:]...)
			break
		}
		if len(opts.Paths) > 0 && strings.HasPrefix(arg, "-") {
			return runOpts{}, fmt.Errorf("options must come before paths (found %s after path %q)", arg, opts.Paths[len(opts.Paths)-1])
		}

		if val, ok, err := consumeFlagValue(args, &i, "--name"); ok {
			if err != nil {
				return runOpts{}, errors.New("--name requires a non-empty sandbox name")
			}
			validName, nErr := validateRunName(val)
			if nErr != nil {
				return runOpts{}, nErr
			}
			opts.Name = validName
			continue
		}
		if val, ok, err := consumeFlagValue(args, &i, "--share"); ok {
			if err != nil || val == "" {
				return runOpts{}, errors.New("--share requires a path[:opts] argument")
			}
			if _, sErr := pathsec.ParseShareSpec(val); sErr != nil {
				return runOpts{}, sErr
			}
			opts.ShareSpecs = append(opts.ShareSpecs, val)
			continue
		}
		if val, ok, err := consumeFlagValue(args, &i, "--profile"); ok {
			if err != nil {
				return runOpts{}, errors.New("--profile requires a profile name")
			}
			profName, pErr := persist.ValidateProfileName(val)
			if pErr != nil {
				return runOpts{}, pErr
			}
			opts.Profile = profName
			continue
		}
		if val, ok, err := consumeFlagValue(args, &i, "--session", "--conversation", "-s"); ok {
			if err != nil {
				return runOpts{}, fmt.Errorf("%s requires a session or conversation ID", arg)
			}
			sid, sErr := persist.ValidateSessionID(val)
			if sErr != nil {
				return runOpts{}, sErr
			}
			opts.ContinueSession = sid
			continue
		}
		if val, ok, err := consumeFlagValue(args, &i, "--port"); ok {
			if err != nil {
				return runOpts{}, errors.New("--port requires a port number")
			}
			p, pErr := strconv.Atoi(val)
			if pErr != nil || !isDigits(val) || p < 1 || p > 65535 {
				return runOpts{}, errors.New("--port must be an integer between 1 and 65535")
			}
			opts.Port = p
			opts.Serve = true
			continue
		}
		if val, ok, err := consumeFlagValue(args, &i, "--cmd"); ok {
			if err != nil || val == "" {
				return runOpts{}, errors.New("--cmd requires a shell command string")
			}
			opts.Cmd = val
			continue
		}
		if val, ok, err := consumeFlagValue(args, &i, "--net", "--net-rule"); ok {
			if err != nil || val == "" {
				return runOpts{}, fmt.Errorf("%s requires a value", arg)
			}
			opts.NetSpecs = append(opts.NetSpecs, val)
			continue
		}
		if val, ok, err := consumeFlagValue(args, &i, "--cpus"); ok {
			if err != nil {
				return runOpts{}, errors.New("--cpus requires a positive integer")
			}
			n, cErr := strconv.Atoi(val)
			if cErr != nil || !isDigits(val) || n < 1 {
				return runOpts{}, errors.New("--cpus must be a positive integer")
			}
			opts.CPUs = strconv.Itoa(n)
			continue
		}
		if val, ok, err := consumeFlagValue(args, &i, "--memory"); ok {
			if err != nil || val == "" {
				return runOpts{}, errors.New("--memory requires a size value (for example, 2G or 2048M)")
			}
			if !isValidMemorySpec(val) {
				return runOpts{}, fmt.Errorf("invalid --memory %q: expected a positive size in M or G (for example, 2G or 2048M)", val)
			}
			opts.Memory = strings.ToUpper(strings.TrimSpace(val))
			continue
		}

		switch arg {
		case "opencode", "antigravity":
			if opts.Agent == "" && (len(opts.Paths) == 0 || !pathExists(arg)) {
				opts.Agent = arg
			} else {
				opts.Paths = append(opts.Paths, arg)
			}
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
		case "--no-net":
			opts.NoNet = true
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
		case "-c", "--continue":
			opts.Continue = true
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
				return runOpts{}, fmt.Errorf("unknown run option: %s ('agbox run --help')", arg)
			}
			opts.Paths = append(opts.Paths, arg)
		}
	}

	if sawRO && sawRW {
		return runOpts{}, errors.New("conflicting options: cannot combine --ro and --rw")
	}
	vcsModeFlags := 0
	for _, b := range []bool{sawMaskVCS, sawNoMask, sawVCS, sawVCSHooks} {
		if b {
			vcsModeFlags++
		}
	}
	if vcsModeFlags > 1 {
		return runOpts{}, errors.New("conflicting VCS options: specify at most one of --mask-vcs, --no-mask, --vcs, or --vcs-hooks")
	}
	if sawRO && sawVCSHooks {
		return runOpts{}, errors.New("conflicting options: cannot combine --ro and --vcs-hooks")
	}
	if opts.MaskMode == config.MaskOff && opts.ShareHub {
		return runOpts{}, errors.New("conflicting options: cannot combine --no-mask and --share-hub")
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
			return runOpts{}, sErr
		}
		if opts.MaskMode == config.MaskOff && spec.HasVCSOpt {
			return runOpts{}, fmt.Errorf("conflicting options for %q: per-share VCS modifier requires FUSE filtering (cannot combine with --no-mask)", raw)
		}
		effRO := opts.ReadOnly
		if spec.HasAccessOpt {
			if opts.LockAccess && spec.ReadOnly != opts.ReadOnly {
				return runOpts{}, fmt.Errorf("conflicting access options for %q: flag and modifier disagree on ro/rw", raw)
			}
			effRO = spec.ReadOnly
		}
		effVCS := opts.DefaultVCS
		if spec.HasVCSOpt {
			if opts.LockVCS && spec.VCSPolicy != opts.DefaultVCS {
				return runOpts{}, fmt.Errorf("conflicting VCS options for %q: flag (%s) and modifier (%s) disagree", raw, opts.DefaultVCS, spec.VCSPolicy)
			}
			effVCS = spec.VCSPolicy
		}
		if effRO && effVCS == config.VCSAllowHooks {
			return runOpts{}, fmt.Errorf("conflicting options for %q: read-only share cannot enable vcs-hooks", raw)
		}
	}

	if opts.Serve && opts.Cmd != "" {
		return runOpts{}, errors.New("--serve and --cmd are mutually exclusive")
	}
	if opts.RemoteControl && opts.Serve {
		return runOpts{}, errors.New("--remote-control and --serve are mutually exclusive")
	}
	if opts.RemoteControl && opts.Cmd != "" {
		return runOpts{}, errors.New("--remote-control and --cmd are mutually exclusive")
	}
	if opts.Serve && opts.Agent == "antigravity" {
		return runOpts{}, errors.New("--serve supports only the opencode agent")
	}
	if opts.RemoteControl && opts.Agent == "opencode" {
		return runOpts{}, errors.New("--remote-control supports only the antigravity agent")
	}
	if opts.Detach && !opts.Serve && !opts.RemoteControl {
		return runOpts{}, errors.New("--detach (-d) requires --remote-control or --serve")
	}
	if opts.Persist && opts.Name == "" {
		return runOpts{}, errors.New("--persist requires --name <NAME>")
	}
	if opts.Persist && opts.Profile != "" {
		return runOpts{}, errors.New("--persist and --profile are mutually exclusive")
	}
	if opts.Persist && opts.Probe {
		return runOpts{}, errors.New("--persist and --probe are mutually exclusive")
	}
	if opts.Continue && opts.ContinueSession != "" {
		return runOpts{}, errors.New("--continue (-c) and --session/--conversation are mutually exclusive")
	}
	if opts.Continue || opts.ContinueSession != "" {
		if opts.Serve || opts.Cmd != "" {
			return runOpts{}, errors.New("cannot combine --continue or --session with --serve or --cmd")
		}
		if opts.RemoteControl && opts.Detach {
			return runOpts{}, errors.New("cannot combine --continue or --session with detached --remote-control")
		}
	}

	return opts, nil
}

func selectEffectiveAgent(baseAgent string, opts runOpts) (string, error) {
	if baseAgent == "" {
		baseAgent = "both"
	}
	if opts.Agent != "" && baseAgent != "both" && opts.Agent != baseAgent {
		return "", fmt.Errorf("the base snapshot contains only agent=%s. Run 'agbox create-base %s' or 'agbox create-base both'", baseAgent, opts.Agent)
	}
	if opts.Serve {
		if opts.Agent == "antigravity" || (baseAgent != "opencode" && baseAgent != "both") {
			return "", errors.New("--serve supports only the opencode agent")
		}
	}
	if opts.RemoteControl {
		if opts.Agent == "opencode" || (baseAgent != "antigravity" && baseAgent != "both") {
			return "", errors.New("--remote-control supports only the antigravity agent")
		}
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

type suspendOpts struct {
	Sandbox   string
	AllowRoot bool
}

func parseSuspendArgs(args []string) (suspendOpts, error) {
	var opts suspendOpts
	var pos []string
	for _, a := range args {
		switch a {
		case "-h", "--help":
			return suspendOpts{}, errHelp
		case "--allow-root":
			opts.AllowRoot = true
		default:
			if strings.HasPrefix(a, "-") {
				return suspendOpts{}, fmt.Errorf("unknown suspend option: %s (expected --allow-root)", a)
			}
			pos = append(pos, a)
		}
	}
	if len(pos) != 1 {
		return suspendOpts{}, errors.New("usage: agbox suspend [--allow-root] <sandbox>")
	}
	name, err := validateTargetRunSandbox(pos[0], "suspend")
	if err != nil {
		return suspendOpts{}, err
	}
	opts.Sandbox = name
	return opts, nil
}

type resumeOpts struct {
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

func parseResumeArgs(args []string) (resumeOpts, error) {
	var opts resumeOpts
	var pos []string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if val, ok, err := consumeFlagValue(args, &i, "--session", "--conversation", "-s"); ok {
			if err != nil {
				return resumeOpts{}, fmt.Errorf("%s requires a session or conversation ID", arg)
			}
			sid, sErr := persist.ValidateSessionID(val)
			if sErr != nil {
				return resumeOpts{}, sErr
			}
			opts.ContinueSession = sid
			continue
		}
		switch arg {
		case "-h", "--help":
			return resumeOpts{}, errHelp
		case "--allow-root":
			opts.AllowRoot = true
		case "-d", "--detach":
			opts.Detach = true
		case "-c", "--continue":
			opts.Continue = true
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
				return resumeOpts{}, fmt.Errorf("unknown resume option: %s (expected --allow-root, --detach, --continue, --session, --no-auth, --no-skills, --no-rules, or --no-agent-cache)", arg)
			}
			pos = append(pos, arg)
		}
	}
	if opts.Continue && opts.ContinueSession != "" {
		return resumeOpts{}, errors.New("--continue (-c) and --session/--conversation are mutually exclusive")
	}
	if len(pos) != 1 {
		return resumeOpts{}, errors.New("usage: agbox resume [--allow-root] [-d|--detach] [-c|--continue] [--session ID] [--no-auth] [--no-skills] [--no-rules] [--no-agent-cache] <sandbox>")
	}
	name, err := validateTargetRunSandbox(pos[0], "resume")
	if err != nil {
		return resumeOpts{}, err
	}
	opts.Sandbox = name
	return opts, nil
}

func parseStopOpts(args []string) (name string, allowRoot bool, err error) {
	var pos []string
	for _, a := range args {
		switch a {
		case "-h", "--help":
			return "", false, errHelp
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
		return "", false, errors.New("usage: agbox stop [--allow-root] <sandbox>")
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
	if !isRunSandboxName(name) {
		return "", fmt.Errorf("refusing to %s %q: not an agbox run sandbox (agbox-<name>)", verb, name)
	}
	return name, nil
}

func parseRemoveOpts(args []string) (yes bool, allowRoot bool, err error) {
	for _, a := range args {
		switch a {
		case "-y", "--yes":
			yes = true
		case "--allow-root":
			allowRoot = true
		case "-h", "--help":
			return false, false, errHelp
		default:
			return false, false, fmt.Errorf("unknown remove option: %s (expected --yes, -y, or --allow-root)", a)
		}
	}
	return yes, allowRoot, nil
}

type authOpts struct {
	Action    string
	Target    string
	AllowRoot bool
}

func parseAuthArgs(args []string) (authOpts, error) {
	opts := authOpts{Action: "login"}
	var pos []string
	for _, a := range args {
		switch a {
		case "-h", "--help":
			return authOpts{}, errHelp
		case "--allow-root":
			opts.AllowRoot = true
		default:
			if strings.HasPrefix(a, "-") {
				return authOpts{}, fmt.Errorf("unknown auth option: %s (run 'agbox auth --help')", a)
			}
			pos = append(pos, a)
		}
	}

	if len(pos) == 0 {
		return opts, nil
	}

	switch pos[0] {
	case "status":
		if len(pos) > 1 {
			return authOpts{}, errors.New("usage: agbox auth [--allow-root] status")
		}
		opts.Action = "status"
		return opts, nil
	case "logout":
		if len(pos) > 2 {
			return authOpts{}, errors.New("usage: agbox auth [--allow-root] logout [antigravity|opencode|all]")
		}
		opts.Action = "logout"
		opts.Target = "all"
		if len(pos) == 2 {
			switch pos[1] {
			case "antigravity", "opencode", "all":
				opts.Target = pos[1]
			default:
				return authOpts{}, fmt.Errorf("unknown auth logout target %q (expected antigravity, opencode, or all)", pos[1])
			}
		}
		return opts, nil
	case "login":
		if len(pos) > 2 {
			return authOpts{}, errors.New("usage: agbox auth [--allow-root] [login] <antigravity|opencode>")
		}
		if len(pos) == 2 {
			switch pos[1] {
			case "antigravity", "opencode":
				opts.Target = pos[1]
			default:
				return authOpts{}, fmt.Errorf("unknown auth agent %q (expected antigravity or opencode)", pos[1])
			}
		}
		return opts, nil
	case "antigravity", "opencode":
		if len(pos) > 1 {
			return authOpts{}, errors.New("usage: agbox auth [--allow-root] <antigravity|opencode>")
		}
		opts.Target = pos[0]
		return opts, nil
	default:
		return authOpts{}, fmt.Errorf("unknown auth argument %q (expected antigravity, opencode, status, or logout)", pos[0])
	}
}

type skillsOpts struct {
	Action    string
	Target    string
	Force     bool
	AllowRoot bool
}

func parseSkillsArgs(args []string) (skillsOpts, error) {
	opts := skillsOpts{Action: "list"}
	var pos []string
	for _, a := range args {
		switch a {
		case "-h", "--help":
			return skillsOpts{}, errHelp
		case "--allow-root":
			opts.AllowRoot = true
		case "--force", "-f":
			opts.Force = true
		default:
			if strings.HasPrefix(a, "-") {
				return skillsOpts{}, fmt.Errorf("unknown skills option: %s (run 'agbox skills --help')", a)
			}
			pos = append(pos, a)
		}
	}
	if len(pos) == 0 {
		if opts.Force {
			return skillsOpts{}, errors.New("agbox skills list does not accept --force")
		}
		return opts, nil
	}
	switch pos[0] {
	case "list", "ls":
		if len(pos) != 1 {
			return skillsOpts{}, errors.New("usage: agbox skills [--allow-root] [list]")
		}
		if opts.Force {
			return skillsOpts{}, errors.New("agbox skills list does not accept --force")
		}
		opts.Action = "list"
		return opts, nil
	case "add":
		if len(pos) != 2 {
			return skillsOpts{}, errors.New("usage: agbox skills [--allow-root] add [--force] <skill-dir-or-SKILL.md>")
		}
		opts.Action = "add"
		opts.Target = pos[1]
		return opts, nil
	case "rm", "remove":
		if len(pos) != 2 {
			return skillsOpts{}, errors.New("usage: agbox skills [--allow-root] rm <skill-name>")
		}
		if opts.Force {
			return skillsOpts{}, errors.New("agbox skills rm does not accept --force")
		}
		opts.Action = "rm"
		opts.Target = pos[1]
		return opts, nil
	default:
		return skillsOpts{}, fmt.Errorf("unknown skills subcommand %q (expected list, add, or rm)", pos[0])
	}
}

type rulesOpts struct {
	Action    string
	Target    string
	Name      string
	Force     bool
	All       bool
	AllowRoot bool
}

func parseRulesArgs(args []string) (rulesOpts, error) {
	opts := rulesOpts{Action: "list"}
	var pos []string
	sawName := false
	for i := 0; i < len(args); i++ {
		if val, ok, err := consumeFlagValue(args, &i, "--name"); ok {
			if err != nil || val == "" {
				return rulesOpts{}, errors.New("--name requires a rule name")
			}
			if sawName {
				return rulesOpts{}, errors.New("duplicate --name flag")
			}
			name, vErr := persist.ValidateRuleName(val)
			if vErr != nil {
				return rulesOpts{}, vErr
			}
			sawName = true
			opts.Name = name
			continue
		}
		a := args[i]
		switch a {
		case "-h", "--help":
			return rulesOpts{}, errHelp
		case "--allow-root":
			opts.AllowRoot = true
		case "--force", "-f":
			opts.Force = true
		case "--all":
			opts.All = true
		default:
			if strings.HasPrefix(a, "-") {
				return rulesOpts{}, fmt.Errorf("unknown rules option: %s (run 'agbox rules --help')", a)
			}
			pos = append(pos, a)
		}
	}
	if len(pos) == 0 {
		if opts.Name != "" || opts.Force || opts.All {
			return rulesOpts{}, errors.New("agbox rules list does not accept --name, --force, or --all")
		}
		return opts, nil
	}
	switch pos[0] {
	case "list", "ls":
		if len(pos) != 1 {
			return rulesOpts{}, errors.New("usage: agbox rules [--allow-root] [list]")
		}
		if opts.Name != "" || opts.Force || opts.All {
			return rulesOpts{}, errors.New("agbox rules list does not accept --name, --force, or --all")
		}
		opts.Action = "list"
		return opts, nil
	case "add":
		if len(pos) != 2 {
			return rulesOpts{}, errors.New("usage: agbox rules [--allow-root] add [--force] [--name NAME] <file.md>")
		}
		if opts.All {
			return rulesOpts{}, errors.New("agbox rules add does not accept --all")
		}
		opts.Action = "add"
		opts.Target = pos[1]
		return opts, nil
	case "show", "cat":
		if len(pos) > 2 {
			return rulesOpts{}, errors.New("usage: agbox rules [--allow-root] show [<name>]")
		}
		if opts.Name != "" || opts.Force || opts.All {
			return rulesOpts{}, errors.New("agbox rules show does not accept --name, --force, or --all")
		}
		opts.Action = "show"
		if len(pos) == 2 {
			opts.Target = pos[1]
		}
		return opts, nil
	case "rm", "remove":
		if opts.Name != "" || opts.Force {
			return rulesOpts{}, errors.New("agbox rules rm does not accept --name or --force")
		}
		if opts.All {
			if len(pos) != 1 {
				return rulesOpts{}, errors.New("usage: agbox rules [--allow-root] rm --all")
			}
		} else if len(pos) != 2 {
			return rulesOpts{}, errors.New("usage: agbox rules [--allow-root] rm <name|--all>")
		} else {
			opts.Target = pos[1]
		}
		opts.Action = "rm"
		return opts, nil
	default:
		return rulesOpts{}, fmt.Errorf("unknown rules subcommand %q (expected list, add, show, or rm)", pos[0])
	}
}

type profileOpts struct {
	Action    string
	Name      string
	Size      string
	Force     bool
	AllowRoot bool
}

func parseProfileArgs(args []string) (profileOpts, error) {
	opts := profileOpts{Action: "list"}
	var pos []string
	sawSize := false
	for i := 0; i < len(args); i++ {
		if val, ok, err := consumeFlagValue(args, &i, "--size"); ok {
			if err != nil || val == "" {
				return profileOpts{}, errors.New("--size requires a disk size such as 10G or 2048M")
			}
			if sawSize {
				return profileOpts{}, errors.New("duplicate --size flag")
			}
			if !config.IsValidSizeSpec(val) {
				return profileOpts{}, fmt.Errorf("invalid --size %q: expected a positive size in M or G (for example, 10G)", val)
			}
			sawSize = true
			opts.Size = strings.ToUpper(strings.TrimSpace(val))
			continue
		}
		a := args[i]
		switch a {
		case "-h", "--help":
			return profileOpts{}, errHelp
		case "--allow-root":
			opts.AllowRoot = true
		case "--force", "-f":
			opts.Force = true
		default:
			if strings.HasPrefix(a, "-") {
				return profileOpts{}, fmt.Errorf("unknown profile option: %s (run 'agbox profile --help')", a)
			}
			pos = append(pos, a)
		}
	}
	if len(pos) == 0 {
		if opts.Size != "" || opts.Force {
			return profileOpts{}, errors.New("agbox profile list does not accept --size or --force")
		}
		return opts, nil
	}
	switch pos[0] {
	case "list", "ls":
		if len(pos) != 1 {
			return profileOpts{}, errors.New("usage: agbox profile [--allow-root] [list]")
		}
		if opts.Size != "" || opts.Force {
			return profileOpts{}, errors.New("agbox profile list does not accept --size or --force")
		}
		opts.Action = "list"
		return opts, nil
	case "create":
		if len(pos) != 2 {
			return profileOpts{}, errors.New("usage: agbox profile [--allow-root] create [--size SIZE] <name>")
		}
		if opts.Force {
			return profileOpts{}, errors.New("agbox profile create does not accept --force")
		}
		name, err := persist.ValidateProfileName(pos[1])
		if err != nil {
			return profileOpts{}, err
		}
		opts.Action = "create"
		opts.Name = name
		return opts, nil
	case "rm", "remove":
		if len(pos) != 2 {
			return profileOpts{}, errors.New("usage: agbox profile [--allow-root] rm [--force] <name>")
		}
		if opts.Size != "" {
			return profileOpts{}, errors.New("agbox profile rm does not accept --size")
		}
		name, err := persist.ValidateProfileName(pos[1])
		if err != nil {
			return profileOpts{}, err
		}
		opts.Action = "rm"
		opts.Name = name
		return opts, nil
	default:
		return profileOpts{}, fmt.Errorf("unknown profile subcommand %q (expected list, create, or rm)", pos[0])
	}
}

type shareOpts struct {
	Action    string
	Sandbox   string
	Target    string
	Alias     string
	ReadOnly  bool
	HasAccess bool
	VCSPolicy config.VCSPolicy
	HasVCS    bool
	Force     bool
	AllowRoot bool
}

func parseShareArgs(args []string) (shareOpts, error) {
	var opts shareOpts
	var pos []string
	sawRO := false
	sawRW := false
	sawAs := false
	vcsFlagCount := 0

	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			pos = append(pos, args[i+1:]...)
			break
		}
		if val, ok, err := consumeFlagValue(args, &i, "--as"); ok {
			if err != nil {
				return shareOpts{}, errors.New("--as requires a guest share name")
			}
			if sawAs {
				return shareOpts{}, errors.New("duplicate --as flag")
			}
			alias, vErr := pathsec.ValidateGuestAlias(val)
			if vErr != nil {
				return shareOpts{}, vErr
			}
			sawAs = true
			opts.Alias = alias
			continue
		}
		switch a {
		case "-h", "--help":
			return shareOpts{}, errHelp
		case "--allow-root":
			opts.AllowRoot = true
		case "--ro":
			sawRO = true
			opts.ReadOnly = true
			opts.HasAccess = true
		case "--rw":
			sawRW = true
			opts.ReadOnly = false
			opts.HasAccess = true
		case "--mask", "--mask-vcs":
			vcsFlagCount++
			opts.VCSPolicy = config.VCSMask
			opts.HasVCS = true
		case "--vcs":
			vcsFlagCount++
			opts.VCSPolicy = config.VCSAllow
			opts.HasVCS = true
		case "--vcs-hooks":
			vcsFlagCount++
			opts.VCSPolicy = config.VCSAllowHooks
			opts.HasVCS = true
		case "--force", "-f":
			opts.Force = true
		default:
			if strings.HasPrefix(a, "-") {
				return shareOpts{}, fmt.Errorf("unknown share option: %s (run 'agbox share --help')", a)
			}
			pos = append(pos, a)
		}
	}

	if sawRO && sawRW {
		return shareOpts{}, errors.New("conflicting share options: cannot combine --ro and --rw")
	}
	if vcsFlagCount > 1 {
		return shareOpts{}, errors.New("conflicting share options: specify at most one of --mask-vcs, --vcs, or --vcs-hooks")
	}
	if sawRO && opts.HasVCS && opts.VCSPolicy == config.VCSAllowHooks {
		return shareOpts{}, errors.New("conflicting share options: cannot combine --ro and --vcs-hooks")
	}

	if len(pos) == 0 {
		return shareOpts{}, errors.New("usage: agbox share <list|add|set|rm> <sandbox> [...]")
	}

	opts.Action = pos[0]
	switch opts.Action {
	case "list", "ls":
		opts.Action = "list"
		if len(pos) != 2 {
			return shareOpts{}, errors.New("usage: agbox share [--allow-root] list <sandbox>")
		}
		if opts.HasAccess || opts.HasVCS || opts.Alias != "" || opts.Force {
			return shareOpts{}, errors.New("agbox share list does not accept --ro, --rw, --vcs, --as, or --force")
		}
		sbx, err := validateTargetRunSandbox(pos[1], "inspect shares on")
		if err != nil {
			return shareOpts{}, err
		}
		opts.Sandbox = sbx
		return opts, nil

	case "add":
		if len(pos) != 3 {
			return shareOpts{}, errors.New("usage: agbox share [--allow-root] add [--ro|--rw] [--mask-vcs|--vcs|--vcs-hooks] [--as NAME] <sandbox> <path[:opts]>")
		}
		if opts.Force {
			return shareOpts{}, errors.New("agbox share add does not accept --force")
		}
		sbx, err := validateTargetRunSandbox(pos[1], "modify shares on")
		if err != nil {
			return shareOpts{}, err
		}
		opts.Sandbox = sbx
		opts.Target = pos[2]
		return opts, nil

	case "set":
		if len(pos) != 3 {
			return shareOpts{}, errors.New("usage: agbox share [--allow-root] set [--ro|--rw] [--mask-vcs|--vcs|--vcs-hooks] [--force] <sandbox> <guest-name-or-path>")
		}
		if opts.Alias != "" {
			return shareOpts{}, errors.New("agbox share set does not accept --as")
		}
		if !opts.HasAccess && !opts.HasVCS {
			return shareOpts{}, errors.New("agbox share set requires at least one permission flag (--ro, --rw, --mask-vcs, --vcs, or --vcs-hooks)")
		}
		sbx, err := validateTargetRunSandbox(pos[1], "modify shares on")
		if err != nil {
			return shareOpts{}, err
		}
		opts.Sandbox = sbx
		opts.Target = pos[2]
		return opts, nil

	case "rm", "remove":
		opts.Action = "rm"
		if len(pos) != 3 {
			return shareOpts{}, errors.New("usage: agbox share [--allow-root] rm [--force] <sandbox> <guest-name-or-path>")
		}
		if opts.HasAccess || opts.HasVCS || opts.Alias != "" {
			return shareOpts{}, errors.New("agbox share rm does not accept --ro, --rw, --vcs, or --as")
		}
		sbx, err := validateTargetRunSandbox(pos[1], "modify shares on")
		if err != nil {
			return shareOpts{}, err
		}
		opts.Sandbox = sbx
		opts.Target = pos[2]
		return opts, nil

	default:
		return shareOpts{}, fmt.Errorf("unknown share subcommand %q (expected list, add, set, or rm)", opts.Action)
	}
}

type updateOpts struct {
	Action    string
	Target    string
	AllowRoot bool
}

func parseUpdateArgs(args []string) (updateOpts, error) {
	opts := updateOpts{Action: "update"}
	var pos []string
	for _, a := range args {
		switch a {
		case "-h", "--help":
			return updateOpts{}, errHelp
		case "--allow-root":
			opts.AllowRoot = true
		default:
			if strings.HasPrefix(a, "-") {
				return updateOpts{}, fmt.Errorf("unknown update option: %s (run 'agbox update --help')", a)
			}
			pos = append(pos, a)
		}
	}

	if len(pos) == 0 {
		return opts, nil
	}

	switch pos[0] {
	case "status", "list":
		if len(pos) > 1 {
			return updateOpts{}, errors.New("usage: agbox update [--allow-root] status")
		}
		opts.Action = "status"
		return opts, nil

	case "clear", "rm":
		if len(pos) > 2 {
			return updateOpts{}, errors.New("usage: agbox update [--allow-root] clear [antigravity|opencode|all]")
		}
		opts.Action = "clear"
		opts.Target = "all"
		if len(pos) == 2 {
			switch pos[1] {
			case "antigravity", "opencode", "all":
				opts.Target = pos[1]
			case "both":
				opts.Target = "all"
			default:
				return updateOpts{}, fmt.Errorf("unknown update clear target %q (expected antigravity, opencode, or all)", pos[1])
			}
		}
		return opts, nil

	case "antigravity", "opencode", "both":
		if len(pos) > 1 {
			return updateOpts{}, errors.New("usage: agbox update [--allow-root] [antigravity|opencode|both]")
		}
		opts.Target = pos[0]
		return opts, nil

	default:
		return updateOpts{}, fmt.Errorf("unknown update argument %q (expected antigravity, opencode, both, status, or clear)", pos[0])
	}
}

func dataDirSupportsFilter(dataDir string) bool {
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
	if !isDigits(s) {
		return 0, false
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n <= 0 || n > math.MaxInt64/mult {
		return 0, false
	}
	return n * mult, true
}
