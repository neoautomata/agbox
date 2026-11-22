// Package cli parses CLI arguments and runs agbox modes.
//
// Security properties:
//   - CheckRootExecution rejects root execution unless --allow-root or AGBOX_ALLOW_ROOT=1 is active.
//   - Every mode fails closed if any check, FUSE mount, network rule, or secret transfer fails.
//   - Default runs enforce MaskStrict VCS masking and default-deny public egress.
//   - Published --serve ports bind only to 127.0.0.1.
//   - Secret helpers stream host API keys and saved credentials over stdin into mode 0600 guest files.
//   - Guest setup mounts cached binaries, skills, and rules read-only and locks --profile disks with flock.
package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"agbox/internal/complete"
	"agbox/internal/config"
	"agbox/internal/mounttab"
	"agbox/internal/msb"
	"agbox/internal/service"
	"agbox/internal/vcsfuse"
)

const version = "0.1.0"

var errHelp = errors.New("help requested")

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
	if errors.As(err, &exitErr) {
		if ws, ok := exitErr.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
			return passthroughExitError{code: 128 + int(ws.Signal()), err: err}
		}
		if exitErr.ExitCode() > 0 {
			return passthroughExitError{code: exitErr.ExitCode(), err: err}
		}
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

func formatMSBStderrOnlyError(prefix string, stderr string, err error) error {
	detail := strings.TrimSpace(stderr)
	if detail != "" {
		return fmt.Errorf("%s: %w (%s)", prefix, err, tailLines(detail, 10))
	}
	return fmt.Errorf("%s: %w", prefix, err)
}

func shortSHA256(digest string) string {
	if len(digest) > 12 {
		return digest[:12]
	}
	return digest
}

func tailLines(s string, n int) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(lines) <= n {
		return strings.Join(lines, "\n")
	}
	return strings.Join(lines[len(lines)-n:], "\n")
}

func defaultStr(v, fallback string) string {
	if v == "" {
		return fallback
	}
	return v
}

type appRuntime struct {
	Env                 config.Env
	ExePath             string
	MSB                 msb.Runner
	MountCtl            mounttab.Controller
	ServiceCtl          service.Controller
	ServicePollInterval time.Duration
	CurrentUser         func() (string, error)
	Stdin               io.Reader
	Stdout              io.Writer
	Stderr              io.Writer
	Getenv              func(string) string
	IsTTY               func() bool
	GetEUID             func() int
	GetEGID             func() int
	SupportsXattr       func(path string, isDir bool) bool
	TruncateFile        func(path string, size int64) error
	RunHostCmd          func(ctx context.Context, name string, args ...string) ([]byte, error)
	Now                 func() time.Time
	CheckKVM            func() error
	CheckFUSE           func() error
	PID                 int
	StartFilter         func(srcDir, mntDir, pidFile string, dieWithParent bool) (int, error)
	StartHub            func(mntDir, sockPath, pidFile string, initial []vcsfuse.HubShareConfig, dieWithParent bool) (int, error)
	WaitServeUI         func(ctx context.Context, port int, sandbox string) bool
}

func newApp() (*appRuntime, error) {
	env, err := config.LoadEnv()
	if err != nil {
		return nil, err
	}
	exePath, err := os.Executable()
	if err != nil && len(os.Args) > 0 {
		exePath = os.Args[0]
	}
	if resolved, rErr := filepath.EvalSymlinks(exePath); rErr == nil {
		exePath = resolved
	}
	var runner msb.Runner
	if r, rErr := msb.NewExecRunner(""); rErr == nil {
		runner = r
	}

	app := &appRuntime{
		Env:                 env,
		ExePath:             exePath,
		MSB:                 runner,
		MountCtl:            mounttab.OSController{},
		ServiceCtl:          service.OSController{},
		ServicePollInterval: 15 * time.Second,
		CurrentUser: func() (string, error) {
			u, uErr := user.Current()
			if uErr != nil {
				return "", uErr
			}
			return u.Username, nil
		},
		Stdin:  os.Stdin,
		Stdout: os.Stdout,
		Stderr: os.Stderr,
		Getenv: os.Getenv,
		IsTTY: func() bool {
			return isFileTerminal(os.Stdin) && isFileTerminal(os.Stdout)
		},
		GetEUID:       os.Geteuid,
		GetEGID:       os.Getegid,
		SupportsXattr: supportsUserXattr,
		TruncateFile:  os.Truncate,
		RunHostCmd: func(ctx context.Context, name string, args ...string) ([]byte, error) {
			return exec.CommandContext(ctx, name, args...).CombinedOutput()
		},
		Now:      time.Now,
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
		return vcsfuse.StartHubSubprocessWithOptions(app.ExePath, mntDir, sockPath, pidFile, initial, vcsfuse.HubOptions{
			HomeReal:         app.Env.HomeReal,
			DataDir:          app.Env.DataDir,
			MSBHome:          app.Env.MSBHome,
			AllowOutsideHome: app.Env.AllowOutsideHome,
			MapGuestIDs:      true,
			GuestUID:         config.GuestUID,
			GuestGID:         config.GuestGID,
		}, dieWithParent)
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

func (a *appRuntime) cmdNeedsNoStdin() bool {
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

func (a *appRuntime) now() time.Time {
	if a.Now != nil {
		return a.Now()
	}
	return time.Now()
}

func (a *appRuntime) euid() int {
	if a.GetEUID != nil {
		return a.GetEUID()
	}
	return config.GuestUID
}

func (a *appRuntime) egid() int {
	if a.GetEGID != nil {
		return a.GetEGID()
	}
	return config.GuestGID
}

func (a *appRuntime) logf(format string, args ...any) {
	fmt.Fprintf(a.Stdout, "[agbox] "+format+"\n", args...)
}

func (a *appRuntime) warnf(format string, args ...any) {
	fmt.Fprintf(a.Stderr, "[agbox] WARN: "+format+"\n", args...)
}

func (a *appRuntime) ensureMSB() error {
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

func (a *appRuntime) isRoot() bool {
	return a.GetEUID != nil && a.GetEUID() == 0
}

func (a *appRuntime) verifyUser(allowRootFlag bool) error {
	warnSrc, err := checkRootExecution(a.euid(), a.Env.AllowRoot, allowRootFlag)
	if err != nil {
		return err
	}
	if warnSrc != "" {
		a.warnf("Root mode is active (%s).", warnSrc)
	}
	return nil
}

func (a *appRuntime) requireSetup(allowRootFlag bool) error {
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
	return kvmCheck()
}

func checkKVMAccess() error {
	f, err := os.OpenFile("/dev/kvm", os.O_RDWR, 0)
	if err != nil {
		return fmt.Errorf("/dev/kvm is not accessible (%w). Run 'agbox setup'", err)
	}
	_ = f.Close()
	return nil
}

func (a *appRuntime) requireBase(ctx context.Context) (config.State, error) {
	st, err := config.LoadFile(a.Env.ConfigFile)
	if err != nil {
		if os.IsNotExist(err) {
			return config.State{}, errors.New("no base configured. Run 'agbox create-base <opencode|antigravity|both>' first")
		}
		return config.State{}, fmt.Errorf("load base config %s: %w", a.Env.ConfigFile, err)
	}
	if st.Snapshot == "" {
		return config.State{}, errors.New("no base configured. Run 'agbox create-base <opencode|antigravity|both>' first")
	}
	exists, err := msb.SnapshotExists(ctx, a.MSB, st.Snapshot)
	if err != nil {
		return config.State{}, fmt.Errorf("check base snapshot %q: %w", st.Snapshot, err)
	}
	if !exists {
		return config.State{}, fmt.Errorf("msb has no base snapshot %q. Run 'agbox create-base --force %s'", st.Snapshot, defaultStr(st.Agent, "both"))
	}
	return st, nil
}

func (a *appRuntime) runGuestRootScript(ctx context.Context, sandbox, label, shell, script string) (msb.CommandResult, error) {
	args := msb.BuildExecArgs(msb.ExecCmdOpts{
		Sandbox: sandbox,
		User:    "root",
		Stream:  true,
		NoStdin: true,
		Command: []string{shell, "-c", script},
	})
	res, err := a.MSB.Run(ctx, msb.CommandRequest{Args: args})
	if err != nil {
		return res, formatMSBError(label, res, err)
	}
	return res, nil
}

func stopSandboxArgs(sandbox string, withTimeout bool) []string {
	if withTimeout {
		return []string{"stop", "-t", "10", sandbox}
	}
	return []string{"stop", sandbox}
}

func isMSBSandboxNotFound(res msb.CommandResult) bool {
	combined := strings.ToLower(res.Stderr + "\n" + res.Stdout)
	return strings.Contains(combined, "sandbox not found")
}

// destroySandbox stops sandboxes with mounted ext4 profile disks before removal.
// Stopping first lets the guest kernel flush dirty ext4 pages and journals.
func (a *appRuntime) destroySandbox(ctx context.Context, sandbox string, flushProfile bool, allowConcurrentGone bool) (msb.CommandResult, error) {
	detached := context.WithoutCancel(ctx)
	stoppedOK := false
	if flushProfile {
		stopCtx, cancel := context.WithTimeout(detached, 15*time.Second)
		_, stopErr := a.MSB.Run(stopCtx, msb.CommandRequest{Args: stopSandboxArgs(sandbox, true)})
		cancel()
		stoppedOK = stopErr == nil
	}
	rmCtx, cancel := context.WithTimeout(detached, 15*time.Second)
	defer cancel()
	rmRes, rmErr := a.MSB.Run(rmCtx, msb.CommandRequest{Args: []string{"rm", "-f", sandbox}})
	if rmErr != nil && (stoppedOK || allowConcurrentGone) && isMSBSandboxNotFound(rmRes) {
		return msb.CommandResult{}, nil
	}
	return rmRes, rmErr
}

func (a *appRuntime) startDisposableVM(ctx context.Context, prefix, snapshot, metaAgent string, mode config.RunMode, bootLogFmt string) (context.Context, string, func(), error) {
	a.reapOrphanRuns(ctx)
	a.reapStaleFilterDirs(ctx)

	dispName := fmt.Sprintf("%s-%d", prefix, a.PID)
	dispSandbox := formatRunSandboxName(dispName, a.PID)
	runRootDir := filepath.Join(a.Env.DataDir, "run")
	dispRunDir := filepath.Join(runRootDir, dispName)
	if err := config.EnsurePrivateDir(runRootDir); err != nil {
		return nil, "", nil, err
	}
	if err := config.EnsurePrivateDir(dispRunDir); err != nil {
		return nil, "", nil, err
	}

	dispCtx, cancelDisp := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	sandboxCreated := false
	var cleanupOnce sync.Once
	cleanup := func() {
		cleanupOnce.Do(func() {
			cancelDisp()
			if sandboxCreated {
				teardownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				rmRes, rmErr := a.MSB.Run(teardownCtx, msb.CommandRequest{Args: []string{"rm", "-f", dispSandbox}})
				cancel()
				if rmErr != nil && !isMSBSandboxNotFound(rmRes) {
					a.warnf("Could not delete disposable sandbox %s: %v", dispSandbox, formatMSBError("msb rm", rmRes, rmErr))
				}
			}
			if tdErr := mounttab.TeardownFilterDir(dispRunDir, a.MountCtl); tdErr != nil {
				a.warnf("Could not delete run directory %s: %v", dispRunDir, tdErr)
			}
		})
	}

	meta := config.RunMeta{
		Sandbox:  dispSandbox,
		OwnerPID: a.PID,
		Agent:    metaAgent,
		Mode:     mode,
		MaskMode: config.MaskStrict,
	}
	if err := config.SaveRunMeta(filepath.Join(dispRunDir, "run.meta"), meta); err != nil {
		cleanup()
		return nil, "", nil, err
	}

	restoreArgs, err := msb.BuildRestoreArgs(msb.RestoreOpts{
		Snapshot: snapshot,
		Name:     dispSandbox,
		User:     config.GuestUser,
		CPUs:     a.Env.CPUs,
		Memory:   a.Env.Memory,
		NetSpecs: []string{"public"},
	})
	if err != nil {
		cleanup()
		return nil, "", nil, err
	}

	a.logf(bootLogFmt, dispSandbox)
	sandboxCreated = true
	if res, err := a.MSB.Run(dispCtx, msb.CommandRequest{Args: restoreArgs}); err != nil {
		cleanup()
		return nil, "", nil, formatMSBError("restore snapshot", res, err)
	}
	if err := a.ensureGuestUser(dispCtx, dispSandbox); err != nil {
		cleanup()
		return nil, "", nil, err
	}
	return dispCtx, dispSandbox, cleanup, nil
}

type runMetaLock struct {
	file *os.File
}

func (l *runMetaLock) unlock() {
	if l == nil || l.file == nil {
		return
	}
	_ = syscall.Flock(int(l.file.Fd()), syscall.LOCK_UN)
	_ = l.file.Close()
	l.file = nil
}

func lockRunMeta(runFilterDir string) (*runMetaLock, error) {
	info, err := os.Lstat(runFilterDir)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return nil, fmt.Errorf("refusing non-directory run path %q", runFilterDir)
	}
	lockPath := filepath.Join(runFilterDir, "meta.lock")
	if lInfo, lErr := os.Lstat(lockPath); lErr == nil {
		if lInfo.Mode()&os.ModeSymlink != 0 || !lInfo.Mode().IsRegular() {
			return nil, fmt.Errorf("refusing non-regular run lock %q", lockPath)
		}
	}
	fd, err := syscall.Open(lockPath, syscall.O_CREAT|syscall.O_RDWR|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0o600)
	if err != nil {
		if errors.Is(err, syscall.ELOOP) {
			return nil, fmt.Errorf("refusing symlinked run lock %q", lockPath)
		}
		return nil, fmt.Errorf("open run lock %s: %w", lockPath, err)
	}
	f := os.NewFile(uintptr(fd), lockPath)
	if err := syscall.Flock(fd, syscall.LOCK_EX); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("lock run metadata %s: %w", lockPath, err)
	}
	return &runMetaLock{file: f}, nil
}

func (a *appRuntime) dispatch(ctx context.Context, args []string) int {
	globalOpts, gErr := parseGlobalArgs(args)
	if gErr != nil {
		if errors.Is(gErr, errHelp) {
			fmt.Fprint(a.Stdout, usageText())
			return 0
		}
		fmt.Fprintf(a.Stderr, "[agbox] ERROR: %v\n", gErr)
		return 1
	}
	return a.dispatchParsed(ctx, globalOpts)
}

func (a *appRuntime) dispatchParsed(ctx context.Context, globalOpts globalOpts) int {
	mode := globalOpts.Mode
	rest := globalOpts.Rest
	if globalOpts.AllowRoot {
		rest = append([]string{"--allow-root"}, rest...)
	}

	var err error
	switch mode {
	case "version":
		fmt.Fprintf(a.Stdout, "agbox %s\n", version)
		return 0
	case "completion":
		err = a.completion(rest)
		if errors.Is(err, errHelp) {
			fmt.Fprint(a.Stdout, completionUsageText())
			return 0
		}
	case complete.SubcommandName:
		return a.runHiddenComplete(globalOpts.Rest)
	case "setup":
		err = a.setup(ctx, rest)
	case "create-base":
		err = a.createBase(ctx, rest)
	case "edit-base":
		err = a.editBase(ctx, rest)
	case "update":
		err = a.update(ctx, rest)
		if errors.Is(err, errHelp) {
			fmt.Fprint(a.Stdout, updateUsageText())
			return 0
		}
	case "auth":
		err = a.auth(ctx, rest)
		if errors.Is(err, errHelp) {
			fmt.Fprint(a.Stdout, authUsageText())
			return 0
		}
	case "skills":
		err = a.skills(ctx, rest)
		if errors.Is(err, errHelp) {
			fmt.Fprint(a.Stdout, skillsUsageText())
			return 0
		}
	case "rules":
		err = a.rules(ctx, rest)
		if errors.Is(err, errHelp) {
			fmt.Fprint(a.Stdout, rulesUsageText())
			return 0
		}
	case "profile":
		err = a.profile(ctx, rest)
		if errors.Is(err, errHelp) {
			fmt.Fprint(a.Stdout, profileUsageText())
			return 0
		}
	case "share":
		err = a.share(ctx, rest)
		if errors.Is(err, errHelp) {
			fmt.Fprint(a.Stdout, shareUsageText())
			return 0
		}
	case "service":
		err = a.serviceMode(ctx, rest)
		if errors.Is(err, errHelp) {
			fmt.Fprint(a.Stdout, serviceUsageText())
			return 0
		}
	case service.SubcommandName:
		err = a.serviceRun(ctx, rest)
	case "run":
		err = a.run(ctx, rest)
		if errors.Is(err, errHelp) {
			fmt.Fprint(a.Stdout, runUsageText())
			return 0
		}
	case "suspend":
		err = a.suspend(ctx, rest)
	case "resume":
		err = a.resume(ctx, rest)
	case "stop":
		err = a.stop(ctx, rest)
	case "remove":
		err = a.remove(ctx, rest)
	case "status":
		err = a.status(ctx, rest)
	default:
		fmt.Fprintf(a.Stderr, "[agbox] ERROR: unknown mode %q (try: setup version completion create-base edit-base update auth skills rules profile share service run suspend resume stop remove status)\n", mode)
		return 1
	}

	if err != nil {
		if errors.Is(err, errHelp) {
			fmt.Fprint(a.Stdout, usageText())
			return 0
		}
		var passErr passthroughExitError
		if errors.As(err, &passErr) {
			return passErr.code
		}
		fmt.Fprintf(a.Stderr, "[agbox] ERROR: %v\n", err)
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			if ws, ok := exitErr.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
				return 128 + int(ws.Signal())
			}
			if exitErr.ExitCode() > 0 {
				return exitErr.ExitCode()
			}
		}
		return 1
	}
	return 0
}

// Main initializes a production appRuntime and dispatches args.
func Main(args []string) int {
	if len(args) > 0 && args[0] == complete.SubcommandName {
		env, _ := config.LoadEnv()
		app := &appRuntime{
			Env:    env,
			Stdout: os.Stdout,
			Stderr: os.Stderr,
		}
		return app.runHiddenComplete(args[1:])
	}
	globalOpts, err := parseGlobalArgs(args)
	if err != nil {
		if errors.Is(err, errHelp) {
			fmt.Print(usageText())
			return 0
		}
		fmt.Fprintf(os.Stderr, "[agbox] ERROR: %v\n", err)
		return 1
	}
	app, err := newApp()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[agbox] ERROR: %v\n", err)
		return 1
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	defer cancel()
	return app.dispatchParsed(ctx, globalOpts)
}
