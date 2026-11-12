// Package cli implements argument parsing and mode orchestration for agbox.
// Pure parsing and validation functions are separated from side-effecting VM
// and filesystem operations, which run through injected dependencies on App.
package cli

import (
	"bufio"
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

	"agbox/internal/config"
	"agbox/internal/mounttab"
	"agbox/internal/msb"
	"agbox/internal/pathsec"
	"agbox/internal/vcsfuse"
)

// ErrHelp indicates that `-h` or `--help` was requested.
var ErrHelp = errors.New("help requested")

// CreateBaseOpts holds parsed arguments for `agbox create-base`.
type CreateBaseOpts struct {
	Agent      string
	Force      bool
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
		return CreateBaseOpts{}, errors.New("Usage: agbox create-base [--force] [--add <categories>] <opencode|antigravity|both>")
	}
	switch pos[0] {
	case "opencode", "antigravity", "both":
		opts.Agent = pos[0]
	default:
		return CreateBaseOpts{}, errors.New("Usage: agbox create-base [--force] [--add <categories>] <opencode|antigravity|both>")
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
				return EditBaseOpts{}, fmt.Errorf("unknown edit-base option: %s (use: --add <cats> | --list | --shell | --cmd \"shell\" | --no-snap)", args[i])
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

// RunOpts holds parsed arguments for `agbox run`.
type RunOpts struct {
	Agent         string
	Paths         []string
	ReadOnly      bool
	Serve         bool
	Probe         bool
	Port          int
	RemoteControl bool
	Cmd           string
	NoNet         bool
	NetSpecs      []string
	CPUs          string
	Memory        string
	MaskMode      config.MaskMode
}

// ParseRunArgs parses CLI arguments for `run`.
// Options must appear before shared paths. Use `--` to pass a path that begins
// with `-`.
func ParseRunArgs(args []string, defaultMask config.MaskMode, pathExists func(string) bool) (RunOpts, error) {
	if defaultMask == "" {
		defaultMask = config.MaskAuto
	}
	if pathExists == nil {
		pathExists = func(p string) bool {
			_, err := os.Stat(p)
			return err == nil
		}
	}

	opts := RunOpts{
		MaskMode: defaultMask,
	}

	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "-h" || arg == "--help" {
			return RunOpts{}, ErrHelp
		}
		if arg == "--" {
			opts.Paths = append(opts.Paths, args[i+1:]...)
			break
		}
		// Enforce that all option flags appear before any shared paths.
		if len(opts.Paths) > 0 && strings.HasPrefix(arg, "-") {
			return RunOpts{}, fmt.Errorf("options must come before paths (found %s after path %q)", arg, opts.Paths[len(opts.Paths)-1])
		}

		switch arg {
		case "opencode", "antigravity":
			if opts.Agent == "" && (len(opts.Paths) == 0 || !pathExists(arg)) {
				opts.Agent = arg
			} else {
				opts.Paths = append(opts.Paths, arg)
			}
		case "--ro":
			opts.ReadOnly = true
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
			opts.Memory = args[i+1]
			i++
		case "--mask-vcs":
			opts.MaskMode = config.MaskStrict
		case "--no-mask":
			opts.MaskMode = config.MaskOff
		default:
			if strings.HasPrefix(arg, "-") {
				return RunOpts{}, fmt.Errorf("unknown run option: %s ('agbox run --help')", arg)
			}
			opts.Paths = append(opts.Paths, arg)
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

	return opts, nil
}

// SelectEffectiveAgent checks and resolves which agent binary to run.
// It compares the base image's configured agent ("opencode", "antigravity", or "both")
// with the per-run options.
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

// ParseStopArgs validates the sandbox name argument for `agbox stop`.
func ParseStopArgs(args []string) (string, error) {
	if len(args) == 0 {
		return "", errors.New("Usage: agbox stop <sandbox>")
	}
	if args[0] == "-h" || args[0] == "--help" {
		return "", ErrHelp
	}
	name := args[0]
	if name == config.BaseSandbox {
		return "", fmt.Errorf("refusing to discard %q: it is the persistent base sandbox (use 'msb stop %s' or 'agbox remove')", name, name)
	}
	prefix := config.RunPrefix + "-"
	if !strings.HasPrefix(name, prefix) {
		return "", fmt.Errorf("refusing to stop %q: not an agbox run sandbox (%s<pid>)", name, prefix)
	}
	return name, nil
}

// ParseRemoveArgs parses CLI arguments for `agbox remove`.
func ParseRemoveArgs(args []string) (yes bool, err error) {
	for _, a := range args {
		switch a {
		case "-y", "--yes":
			yes = true
		case "-h", "--help":
			return false, ErrHelp
		default:
			return false, fmt.Errorf("unknown remove option: %s (expected --yes or -y)", a)
		}
	}
	return yes, nil
}

// DataDirSupportsFilter reports whether dataDir is safe to use as a FUSE
// mountpoint parent (no whitespace or backslashes).
func DataDirSupportsFilter(dataDir string) bool {
	return dataDir != "" && !strings.ContainsAny(dataDir, " \t\n\r\\")
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
	PID         int
	StartFilter func(srcDir, mntDir, pidFile string, dieWithParent bool) (int, error)
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
	app.StartFilter = func(srcDir, mntDir, pidFile string, dieWithParent bool) (int, error) {
		return vcsfuse.StartSubprocess(app.ExePath, srcDir, mntDir, pidFile, dieWithParent)
	}
	app.WaitServeUI = app.defaultWaitServeUI
	return app, nil
}

func isFileTerminal(f *os.File) bool {
	if f == nil {
		return false
	}
	st, err := f.Stat()
	if err != nil {
		return false
	}
	return (st.Mode() & os.ModeCharDevice) != 0
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

func (a *App) requireSetup() error {
	if a.GetEUID != nil && a.GetEUID() == 0 {
		return errors.New("do not run as root. agbox uses your normal user and /dev/kvm")
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

// ReapOrphanRuns deletes any `agbox-run-<pid>` microVMs whose host PID is no
// longer active. It skips detached runs recorded in `$DATA_DIR/run/<pid>/detached`.
func (a *App) ReapOrphanRuns(ctx context.Context) {
	if a.MSB == nil {
		return
	}
	res, err := a.MSB.Run(ctx, msb.CommandRequest{Args: []string{"ls"}})
	if err != nil {
		return
	}
	prefix := config.RunPrefix + "-"
	for _, sb := range msb.ParseSandboxList(res.Stdout) {
		if !strings.HasPrefix(sb.Name, prefix) {
			continue
		}
		pidStr := strings.TrimPrefix(sb.Name, prefix)
		pid, err := strconv.Atoi(pidStr)
		if err != nil || pid <= 0 || pid == a.PID {
			continue
		}
		if isPIDAlive(pid) {
			continue
		}
		detachedFile := filepath.Join(a.Env.DataDir, "run", pidStr, "detached")
		if _, err := os.Stat(detachedFile); err == nil && sb.Running {
			continue
		}
		_, _ = a.MSB.Run(ctx, msb.CommandRequest{Args: []string{"rm", "-f", sb.Name}})
	}
}

// ReapStaleFilterDirs unmounts and deletes any `$DATA_DIR/run/<pid>` directory
// whose host PID is no longer active. It skips directories that belong to an
// active detached `--serve` microVM.
func (a *App) ReapStaleFilterDirs(ctx context.Context) {
	runRoot := filepath.Join(a.Env.DataDir, "run")
	entries, err := os.ReadDir(runRoot)
	if err != nil {
		return
	}
	var sandboxes []msb.SandboxInfo
	if a.MSB != nil {
		if res, lErr := a.MSB.Run(ctx, msb.CommandRequest{Args: []string{"ls"}}); lErr == nil {
			sandboxes = msb.ParseSandboxList(res.Stdout)
		}
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pidStr := entry.Name()
		pid, err := strconv.Atoi(pidStr)
		if err != nil || pid == a.PID || isPIDAlive(pid) {
			continue
		}
		dir := filepath.Join(runRoot, pidStr)
		detachedFile := filepath.Join(dir, "detached")
		if raw, err := os.ReadFile(detachedFile); err == nil {
			sbxName := strings.TrimSpace(string(raw))
			if sb, ok := msb.FindSandbox(sandboxes, sbxName); ok && sb.Running {
				continue
			}
		}
		_ = mounttab.TeardownFilterDir(dir, a.MountCtl)
	}
}

func isPIDAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	err := syscall.Kill(pid, 0)
	return err == nil || errors.Is(err, syscall.EPERM)
}

// Setup verifies host prerequisites (non-root user, glibc, msb, /dev/kvm,
// msb doctor, and a microVM smoke test) and initializes DATA_DIR.
func (a *App) Setup(ctx context.Context) error {
	a.logf("Checking host...")
	if a.GetEUID != nil && a.GetEUID() == 0 {
		return errors.New("run this as your normal user, not as root")
	}

	if err := a.ensureMSB(); err != nil {
		return fmt.Errorf("%w (run ./install.sh or 'curl -fsSL https://install.microsandbox.dev | sh')", err)
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
		return fmt.Errorf("%w\nGrant access with: sudo usermod -aG kvm $(id -un) (then re-login) or sudo setfacl -m u:$(id -un):rw /dev/kvm", err)
	}
	a.logf("/dev/kvm accessible: OK")

	a.logf("Running msb doctor...")
	if _, err := a.MSB.Run(ctx, msb.CommandRequest{Args: []string{"doctor"}, Interactive: true}); err != nil {
		return fmt.Errorf("msb doctor reported problems: %w", err)
	}

	a.logf("Smoke test: booting an alpine microVM...")
	smoke := fmt.Sprintf("%s-%d", config.RunPrefix, a.PID)
	defer func() {
		_, _ = a.MSB.Run(context.Background(), msb.CommandRequest{Args: []string{"rm", "-f", smoke}})
	}()
	if _, err := a.MSB.Run(ctx, msb.CommandRequest{
		Args: []string{"create", "alpine", "--name", smoke, "--cpus", "1", "--memory", "256M"},
	}); err != nil {
		return fmt.Errorf("could not boot smoke-test sandbox: %w", err)
	}
	execRes, err := a.MSB.Run(ctx, msb.CommandRequest{
		Args: []string{"exec", smoke, "--", "sh", "-c", "echo SMOKE-OK; id -u"},
	})
	if err != nil || !strings.Contains(execRes.Stdout, "SMOKE-OK") {
		return errors.New("smoke test failed: cannot run commands in a sandbox")
	}
	_, _ = a.MSB.Run(ctx, msb.CommandRequest{Args: []string{"rm", "-f", smoke}})
	a.logf("Smoke test: OK (guest boots, exec works, teardown clean)")

	if err := os.MkdirAll(a.Env.DataDir, 0o700); err != nil {
		return fmt.Errorf("create data dir %s: %w", a.Env.DataDir, err)
	}
	_ = os.Chmod(a.Env.DataDir, 0o700)
	a.logf("Embedded FUSE VCS filter ready (single binary: %s).", a.ExePath)
	a.logf("Setup complete. Next: agbox create-base <opencode|antigravity|both>")
	return nil
}

// CreateBase builds the persistent `agbox-base` microVM, provisions the
// non-root `agent` user and requested agent CLI(s), and snapshots `agbox:vN`.
func (a *App) CreateBase(ctx context.Context, args []string) error {
	opts, err := ParseCreateBaseArgs(args)
	if err != nil {
		return err
	}
	if err := a.requireSetup(); err != nil {
		return err
	}

	lsRes, err := a.MSB.Run(ctx, msb.CommandRequest{Args: []string{"ls"}})
	if err == nil {
		if _, exists := msb.FindSandbox(msb.ParseSandboxList(lsRes.Stdout), config.BaseSandbox); exists {
			_, confErr := os.Stat(a.Env.ConfigFile)
			if opts.Force || os.IsNotExist(confErr) {
				a.logf("Replacing existing base sandbox %q...", config.BaseSandbox)
				_, _ = a.MSB.Run(ctx, msb.CommandRequest{Args: []string{"rm", "-f", config.BaseSandbox}})
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

	a.logf("Provisioning guest (apt baseline + non-root %q user with passwordless sudo)...", config.GuestUser)
	aptCmd := "apt-get update -qq && apt-get install -y -qq --no-install-recommends ca-certificates curl git ripgrep less procps sudo >/dev/null"
	if _, err := a.MSB.Run(ctx, msb.CommandRequest{
		Args:   []string{"exec", "--stream", "--no-stdin", config.BaseSandbox, "--", "sh", "-c", aptCmd},
		Stdout: a.Stdout,
		Stderr: a.Stderr,
	}); err != nil {
		return fmt.Errorf("apt provisioning failed: %w", err)
	}

	if err := a.provisionGuestUser(ctx, config.BaseSandbox); err != nil {
		return fmt.Errorf("guest user provisioning failed: %w", err)
	}

	if opts.Agent == "opencode" || opts.Agent == "both" {
		a.logf("Installing OpenCode (npm opencode-ai@%s)...", a.Env.OpenCodeVersion)
		ocScript := fmt.Sprintf(`set -euo pipefail
npm install -g --no-fund --no-audit "opencode-ai@$1"
su - %q -c "opencode --version"`, config.GuestUser)
		if _, err := a.MSB.Run(ctx, msb.CommandRequest{
			Args:   []string{"exec", "--stream", "--no-stdin", config.BaseSandbox, "--", "bash", "-c", ocScript, "--", a.Env.OpenCodeVersion},
			Stdout: a.Stdout,
			Stderr: a.Stderr,
		}); err != nil {
			return fmt.Errorf("OpenCode install failed: %w", err)
		}
	}

	if opts.Agent == "antigravity" || opts.Agent == "both" {
		a.logf("Installing Google Antigravity CLI (agy) from %s...", a.Env.AgyInstallerURL)
		innerCmd := fmt.Sprintf("curl -fsSL %s | bash", msb.ShellQuote(a.Env.AgyInstallerURL))
		agyScript := fmt.Sprintf(`set -euo pipefail
su - %s -c %s
if [ -x /home/agent/.local/bin/agy ]; then
  ln -sf /home/agent/.local/bin/agy /usr/local/bin/agy
fi
su - %s -c "agy --version"`, config.GuestUser, msb.ShellQuote(innerCmd), config.GuestUser)
		if _, err := a.MSB.Run(ctx, msb.CommandRequest{
			Args:   []string{"exec", "--stream", "--no-stdin", config.BaseSandbox, "--", "bash", "-c", agyScript},
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
	if _, err := a.MSB.Run(ctx, msb.CommandRequest{Args: []string{"stop", config.BaseSandbox}}); err != nil {
		return fmt.Errorf("stop base sandbox: %w", err)
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
	_, err := a.MSB.Run(ctx, msb.CommandRequest{
		Args: []string{"exec", sandbox, "--", "bash", "-c", msb.ProvisionGuestUserScript()},
	})
	return err
}

func (a *App) installCategories(ctx context.Context, sandbox string, cats []msb.Category) error {
	names := make([]string, len(cats))
	for i, c := range cats {
		names[i] = c.Name
	}
	a.logf("Installing categories (%s) in %s...", strings.Join(names, ", "), sandbox)
	script := msb.BuildCategoriesScript(cats)
	if res, err := a.MSB.Run(ctx, msb.CommandRequest{
		Args:   []string{"exec", "--stream", "--no-stdin", sandbox, "--", "bash", "-c", script},
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
	if err := a.requireSetup(); err != nil {
		return err
	}
	st, err := a.requireBase(ctx)
	if err != nil {
		return err
	}

	lsRes, err := a.MSB.Run(ctx, msb.CommandRequest{Args: []string{"ls"}})
	if err != nil {
		return fmt.Errorf("msb ls: %w", err)
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
		if _, err := a.MSB.Run(ctx, msb.CommandRequest{Args: []string{"start", config.BaseSandbox}}); err != nil {
			return fmt.Errorf("start base sandbox: %w", err)
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
			Args:   []string{"exec", "--stream", "--no-stdin", config.BaseSandbox, "--", "sh", "-c", opts.Cmd},
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
			Args:        []string{"exec", "-t", config.BaseSandbox, "--", "sh", "-c", "cd /workspace 2>/dev/null || cd /; bash; exit 0"},
			Interactive: true,
		}); err != nil {
			_, _ = a.MSB.Run(context.Background(), msb.CommandRequest{Args: []string{"stop", config.BaseSandbox}})
			return fmt.Errorf("interactive shell failed (exit %d): %w", res.ExitCode, err)
		}
	}

	_ = a.provisionGuestUser(ctx, config.BaseSandbox)

	a.logf("Stopping base...")
	_, _ = a.MSB.Run(ctx, msb.CommandRequest{Args: []string{"stop", config.BaseSandbox}})

	if opts.NoSnap {
		_ = config.SaveFile(a.Env.ConfigFile, st)
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

// Run restores an ephemeral `agbox-run-<pid>` microVM from the base snapshot.
// It mounts validated host paths (with FUSE VCS filtering for directories),
// streams API keys over stdin into `/home/agent/.agbox-keys.sh`, and runs the
// requested agent or command as `agent` (1000:1000). On exit, Run deletes the
// microVM and unmounts all FUSE shares.
func (a *App) Run(ctx context.Context, args []string) error {
	opts, err := ParseRunArgs(args, a.Env.MaskVCS, nil)
	if err != nil {
		return err
	}
	if err := a.requireSetup(); err != nil {
		return err
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
		return fmt.Errorf("--mask-vcs requested but DATA_DIR (%s) contains whitespace or backslashes", a.Env.DataDir)
	}

	a.ReapOrphanRuns(ctx)
	a.ReapStaleFilterDirs(ctx)

	pol := pathsec.Policy{
		HomeReal:         a.Env.HomeReal,
		AllowOutsideHome: a.Env.AllowOutsideHome,
		ReadOnly:         opts.ReadOnly,
		Blocklist:        pathsec.DefaultBlocklist(a.Env.HomeReal, a.Env.DataDir, a.Env.MSBHome),
		VCSNames:         pathsec.DefaultVCSNames(),
	}

	var validated []pathsec.ShareTarget
	for _, rawPath := range opts.Paths {
		if rawPath == "" {
			continue
		}
		target, vErr := pathsec.ValidateShare(rawPath, pol)
		if vErr != nil {
			return vErr
		}
		validated = append(validated, target)
	}
	validated = pathsec.AssignGuestNames(validated)

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

	if !opts.Serve && opts.Cmd == "" {
		if a.IsTTY == nil || !a.IsTTY() {
			return fmt.Errorf("the %s TUI requires a TTY (or use --serve / --cmd)", effectiveAgent)
		}
	}

	isDetachedServe := opts.Serve && !opts.Probe && (a.IsTTY == nil || !a.IsTTY())
	dieWithParent := !isDetachedServe

	runCtx, cancelRun := context.WithCancel(ctx)
	defer cancelRun()

	runSandbox := fmt.Sprintf("%s-%d", config.RunPrefix, a.PID)
	runFilterDir := ""
	detached := false
	var cleanupOnce sync.Once
	cleanup := func() {
		cleanupOnce.Do(func() {
			if !detached {
				_, _ = a.MSB.Run(context.Background(), msb.CommandRequest{Args: []string{"rm", "-f", runSandbox}})
				if runFilterDir != "" {
					_ = mounttab.TeardownFilterDir(runFilterDir, a.MountCtl)
				}
			}
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
		case <-runCtx.Done():
		}
	}()

	var volumes []msb.VolumeSpec
	maskedCount := 0
	directCount := 0
	for i, target := range validated {
		guestPath := msb.GuestWorkspace + "/" + target.GuestName
		if target.IsDir && useMask && a.StartFilter != nil {
			if runFilterDir == "" {
				runFilterDir = filepath.Join(a.Env.DataDir, "run", strconv.Itoa(a.PID))
				if err := os.MkdirAll(runFilterDir, 0o700); err != nil {
					return fmt.Errorf("create filter dir: %w", err)
				}
				_ = os.Chmod(runFilterDir, 0o700)
			}
			mntDir := filepath.Join(runFilterDir, fmt.Sprintf("m%d", i))
			pidFile := mntDir + ".pid"
			if _, fErr := a.StartFilter(target.HostPath, mntDir, pidFile, dieWithParent); fErr == nil {
				volumes = append(volumes, msb.VolumeSpec{
					HostPath:  mntDir,
					GuestPath: guestPath,
					ReadOnly:  opts.ReadOnly,
				})
				maskedCount++
				continue
			} else if maskStrict {
				return fmt.Errorf("FUSE filter failed to mount for %s: %w", target.HostPath, fErr)
			} else {
				a.warnf("FUSE filter failed for %s (%v). Sharing directly (VCS directory is visible to the guest).", target.HostPath, fErr)
			}
		}
		volumes = append(volumes, msb.VolumeSpec{
			HostPath:  target.HostPath,
			GuestPath: guestPath,
			ReadOnly:  opts.ReadOnly,
		})
		if target.IsDir {
			directCount++
		}
	}

	if maskedCount > 0 {
		extra := ""
		if directCount > 0 {
			extra = fmt.Sprintf(" (%d direct)", directCount)
		}
		a.logf("VCS filter: %d share(s) masked%s.", maskedCount, extra)
	}

	restoreArgs, err := msb.BuildRestoreArgs(msb.RestoreOpts{
		Snapshot: baseState.Snapshot,
		Name:     runSandbox,
		User:     config.GuestUser,
		CPUs:     defaultStr(opts.CPUs, a.Env.CPUs),
		Memory:   defaultStr(opts.Memory, a.Env.Memory),
		Volumes:  volumes,
		Ports:    portArgs,
		NoNet:    opts.NoNet,
		NetSpecs: opts.NetSpecs,
	})
	if err != nil {
		return err
	}

	a.logf("Booting ephemeral VM %s from %s (nothing here persists to the base)...", runSandbox, baseState.Snapshot)
	if _, err := a.MSB.Run(ctx, msb.CommandRequest{Args: restoreArgs}); err != nil {
		return fmt.Errorf("snapshot restore failed: %w", err)
	}

	// Verify the non-root guest user exists inside the restored VM.
	if _, err := a.MSB.Run(ctx, msb.CommandRequest{
		Args: []string{"exec", "-u", config.GuestUser, runSandbox, "--", "true"},
	}); err != nil {
		if pErr := a.provisionGuestUser(ctx, runSandbox); pErr != nil {
			return fmt.Errorf("could not initialize guest user %q: %w", config.GuestUser, pErr)
		}
	}

	a.pushKeys(ctx, runSandbox)

	guestEnv := msb.GuestEnvFlags()

	if opts.Cmd != "" {
		a.logf("Running one-shot command in %s as %s (passwordless sudo available)...", runSandbox, config.GuestUser)
		execArgs := msb.BuildExecArgs(msb.ExecCmdOpts{
			Sandbox: runSandbox,
			Stream:  true,
			User:    config.GuestUser,
			Env:     guestEnv,
			Command: []string{
				"sh", "-c",
				msb.KeyLoaderPrefix + " cd /workspace && exec sh -c \"$1\"",
				"--", opts.Cmd,
			},
		})
		_, err := a.MSB.Run(ctx, msb.CommandRequest{
			Args:        execArgs,
			Interactive: true,
		})
		return err
	}

	if opts.Serve {
		a.logf("Starting 'opencode serve' on guest:%d as %s...", config.GuestPort, config.GuestUser)
		serveCmd := fmt.Sprintf("%s cd /workspace && exec opencode serve --hostname 0.0.0.0 --port %d",
			msb.KeyLoaderPrefix, config.GuestPort)
		serveArgs := msb.BuildExecArgs(msb.ExecCmdOpts{
			Sandbox:  runSandbox,
			Detached: true,
			User:     config.GuestUser,
			Env:      guestEnv,
			Command:  []string{"sh", "-c", serveCmd},
		})
		if _, err := a.MSB.Run(ctx, msb.CommandRequest{Args: serveArgs}); err != nil {
			return fmt.Errorf("could not start opencode serve: %w", err)
		}

		up := false
		if a.WaitServeUI != nil {
			up = a.WaitServeUI(ctx, port, runSandbox)
		}
		if !up {
			a.warnf("OpenCode UI did not answer on 127.0.0.1:%d within 90s. Guest log tail:", port)
			if logRes, lErr := a.MSB.Run(ctx, msb.CommandRequest{Args: []string{"logs", runSandbox}}); lErr == nil {
				fmt.Fprintln(a.Stderr, tailLines(logRes.Stdout, 20))
			}
			return fmt.Errorf("opencode serve did not become ready on 127.0.0.1:%d", port)
		}

		a.logf("OpenCode web UI: http://127.0.0.1:%d", port)
		a.warnf("Loopback TCP (127.0.0.1:%d) is reachable by local host processes. Set OPENCODE_SERVER_PASSWORD for HTTP basic auth. Provider keys stay inside the disposable microVM.", port)

		if opts.Probe {
			a.logf("--probe: UI verified. Stopping now.")
			return nil
		}

		if isDetachedServe {
			if runFilterDir == "" {
				runFilterDir = filepath.Join(a.Env.DataDir, "run", strconv.Itoa(a.PID))
				_ = os.MkdirAll(runFilterDir, 0o700)
			}
			_ = os.WriteFile(filepath.Join(runFilterDir, "detached"), []byte(runSandbox+"\n"), 0o600)
			detached = true
			a.logf("Non-interactive: keeping %s and its share filters running. Stop later with: agbox stop %s", runSandbox, runSandbox)
			return nil
		}

		fmt.Fprintln(a.Stdout, "Press Ctrl-C to stop the microVM and discard all guest changes.")
		for {
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(2 * time.Second):
				if _, pErr := a.MSB.Run(ctx, msb.CommandRequest{Args: []string{"ping", runSandbox}}); pErr != nil {
					return nil
				}
			}
		}
	}

	bin := effectiveAgent
	switch effectiveAgent {
	case "opencode":
		bin = "opencode"
	case "antigravity":
		bin = "agy"
		if opts.RemoteControl {
			bin = "agy --remote-control"
		}
	}
	modeStr := "rw"
	if opts.ReadOnly {
		modeStr = "ro"
	}
	a.logf("Launching %s (%s) in %s as %s (passwordless sudo available). All VM changes are discarded on exit.",
		effectiveAgent, bin, runSandbox, config.GuestUser)
	a.logf("Shared: %d path(s) under /workspace (%s). Egress: public internet only.", len(validated), modeStr)

	tuiArgs := msb.BuildExecArgs(msb.ExecCmdOpts{
		Sandbox: runSandbox,
		TTY:     true,
		User:    config.GuestUser,
		Env:     guestEnv,
		Command: []string{"sh", "-c", fmt.Sprintf("%s cd /workspace && exec %s", msb.KeyLoaderPrefix, bin)},
	})
	_, err = a.MSB.Run(ctx, msb.CommandRequest{
		Args:        tuiArgs,
		Interactive: true,
	})
	return err
}

func (a *App) pushKeys(ctx context.Context, sandbox string) {
	if a.Getenv == nil {
		return
	}
	script, count := msb.FormatEnvExports(a.Getenv, msb.DefaultPassthroughEnvVars)
	if count == 0 {
		return
	}
	_, err := a.MSB.Run(ctx, msb.CommandRequest{
		Args:  []string{"exec", "-u", config.GuestUser, sandbox, "--", "sh", "-c", "umask 077; cat > " + config.GuestKeysFile},
		Stdin: strings.NewReader(script),
	})
	if err != nil {
		a.warnf("Could not push provider keys into the guest (agent will prompt for auth itself).")
		return
	}
	a.logf("Streamed %d environment secret(s) from host env into the disposable guest.", count)
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

// Stop destroys a running `agbox-run-<pid>` sandbox and tears down its FUSE
// filter directory.
func (a *App) Stop(ctx context.Context, args []string) error {
	name, err := ParseStopArgs(args)
	if err != nil {
		return err
	}
	if err := a.ensureMSB(); err != nil {
		return err
	}
	_, _ = a.MSB.Run(ctx, msb.CommandRequest{Args: []string{"rm", "-f", name}})
	pidStr := strings.TrimPrefix(name, config.RunPrefix+"-")
	if _, pErr := strconv.Atoi(pidStr); pErr == nil {
		filterDir := filepath.Join(a.Env.DataDir, "run", pidStr)
		if _, sErr := os.Stat(filterDir); sErr == nil {
			_ = mounttab.TeardownFilterDir(filterDir, a.MountCtl)
		}
	}
	a.logf("Discarded %s.", name)
	return nil
}

// Remove deletes all agbox sandboxes (`agbox-base`, `agbox-run-*`), snapshots
// (`agbox:v*`), unused cached OCI images, FUSE filter daemons/mounts, and
// `$DATA_DIR`.
func (a *App) Remove(ctx context.Context, args []string) error {
	yes, err := ParseRemoveArgs(args)
	if err != nil {
		return err
	}
	if !yes {
		fmt.Fprintf(a.Stdout, "This removes: agbox sandboxes (%s, %s-*), snapshots (%s), unused cached images, and %s.\n",
			config.BaseSandbox, config.RunPrefix, config.SnapGroup, a.Env.DataDir)
		fmt.Fprintln(a.Stdout, "It does NOT touch the msb install, your other sandboxes/volumes, or any host files you shared.")
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

	a.logf("Removed all agbox state.")
	return nil
}

func isAgboxSandboxName(name string) bool {
	return name == config.BaseSandbox ||
		strings.HasPrefix(name, config.RunPrefix+"-")
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

// Status prints the current base configuration, sandboxes, snapshots, and disk usage.
func (a *App) Status(ctx context.Context) error {
	if err := a.requireSetup(); err != nil {
		return err
	}
	fmt.Fprintln(a.Stdout, "== agbox base config ==")
	if raw, err := os.ReadFile(a.Env.ConfigFile); err == nil {
		fmt.Fprint(a.Stdout, string(raw))
	} else {
		fmt.Fprintln(a.Stdout, "(none - run create-base)")
	}

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

Modes:
  agbox setup
      Check host prerequisites (glibc, msb, /dev/kvm, smoke test).

  agbox create-base [--force] [--add <categories>] <opencode|antigravity|both>
      Create the base microVM and save snapshot agbox:vN.

  agbox edit-base [--add <categories>] [--list] [--shell] [--cmd "shell"] [--no-snap]
      Start the base microVM, install developer categories (core, go, rust,
      esphome, embedded-rust, chrome, hugo, caddy, or all) or run custom
      updates, and save snapshot agbox:v<N+1>.

  agbox run [options] [opencode|antigravity] [paths...]
      Restore an ephemeral microVM from the base snapshot and mount paths.
      Delete the microVM and unmount FUSE shares on exit.
      Options (must precede paths):
        --ro                 Mount shared paths read-only
        --mask-vcs           Require the FUSE filter for directory shares
        --no-mask            Disable the FUSE filter (.git is visible to guest)
        --serve              Run 'opencode serve' and bind the web UI on 127.0.0.1
        --port N             Use fixed loopback TCP port N for --serve
        --probe              With --serve: wait for the web UI, then exit
        --remote-control     Run 'agy --remote-control' for https://antigravity.google.com
        --cmd "shell"        Run one command in the ephemeral microVM and exit
        --no-net             Disable guest network access
        --net SPEC           Set network profile (public|none|private|host|all) or rule
        --cpus N             Override vCPU count for this run
        --memory SIZE        Override RAM size for this run (for example, 4G)

  agbox stop <agbox-run-pid>
      Stop a detached --serve microVM and unmount its FUSE shares.

  agbox remove [--yes]
      Delete all agbox microVMs, snapshots, FUSE mounts, and ~/.local/share/agbox.

  agbox status
      Show base configuration, microVMs, snapshots, and disk usage.
`
}

// RunUsageText returns the help message for `agbox run --help`.
func RunUsageText() string {
	return `Usage: agbox run [options] [agent] [path...]

  --ro             mount shared paths read-only
  --mask-vcs       require the FUSE filter for directory shares
  --no-mask        disable the FUSE filter (.git is visible to guest)
  --serve          run 'opencode serve' and bind the web UI on 127.0.0.1
  --port N         use fixed loopback port N for --serve (default: random)
  --probe          with --serve: wait for the web UI, then exit
  --remote-control run 'agy --remote-control' for https://antigravity.google.com
  --cmd 'shell'    run one command in the ephemeral microVM and exit
  --no-net         disable guest network access
  --net SPEC       set network profile (public|none|private|host|all) or msb rule
  --cpus N / --memory S   override vCPU count or RAM size for this run
  agent            opencode | antigravity (default: the base's agent)
  path...          host dirs/files mounted at /workspace/<name>
`
}

// Dispatch executes the requested top-level subcommand on App.
func (a *App) Dispatch(ctx context.Context, args []string) int {
	if len(args) == 0 {
		fmt.Fprint(a.Stdout, UsageText())
		return 0
	}
	mode := args[0]
	rest := args[1:]

	var err error
	switch mode {
	case "-h", "--help", "help":
		fmt.Fprint(a.Stdout, UsageText())
		return 0
	case "setup":
		err = a.Setup(ctx)
	case "create-base":
		err = a.CreateBase(ctx, rest)
	case "edit-base":
		err = a.EditBase(ctx, rest)
	case "run":
		err = a.Run(ctx, rest)
		if errors.Is(err, ErrHelp) {
			fmt.Fprint(a.Stdout, RunUsageText())
			return 0
		}
	case "stop":
		err = a.Stop(ctx, rest)
	case "remove":
		err = a.Remove(ctx, rest)
	case "status":
		err = a.Status(ctx)
	default:
		fmt.Fprintf(a.Stderr, "[agbox] ERROR: unknown mode %q (try: setup create-base edit-base run stop remove status)\n", mode)
		return 1
	}

	if err != nil {
		if errors.Is(err, ErrHelp) {
			fmt.Fprint(a.Stdout, UsageText())
			return 0
		}
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return exitErr.ExitCode()
		}
		fmt.Fprintf(a.Stderr, "[agbox] ERROR: %v\n", err)
		return 1
	}
	return 0
}

// Main initializes a production App and dispatches os.Args[1:].
func Main(args []string) int {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		fmt.Print(UsageText())
		return 0
	}
	app, err := NewApp()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[agbox] ERROR: %v\n", err)
		return 1
	}
	return app.Dispatch(context.Background(), args)
}
