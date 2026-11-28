// Package remotedaemon runs the remote command broker target daemon (agbox remote serve).
//
// Security properties:
//   - Commands execute via execve directly (no shell) with Setsid (/dev/tty detached).
//   - Child processes inherit PR_SET_NO_NEW_PRIVS via a dedicated single-use locked OS thread.
//   - Startup sweeps /proc/self/fd to set FD_CLOEXEC on any unexpected inherited FDs > 2.
//   - PATH is sanitized against relative, writable, or foreign-owned dirs and looked up via
//     lookPathIn instead of Go exec.LookPath against host os.Getenv("PATH").
//   - cwd is canonicalized, pinned with openat2(RESOLVE_NO_SYMLINKS), verified against both
//     daemon --allow-cwd and broker allow/deny scopes, and passed via /proc/self/fd/<dirfd>.
//   - Output is clamped to max 2 MiB combined, with a 16 MiB runaway drain SIGKILL ceiling.
package remotedaemon

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"agbox/internal/remotepolicy"
	"agbox/internal/remoteproto"

	"golang.org/x/sys/unix"
)

var defaultTrustedPATHDirs = []string{
	"/usr/local/sbin",
	"/usr/local/bin",
	"/usr/sbin",
	"/usr/bin",
	"/sbin",
	"/bin",
}

var forbiddenPassEnvExact = map[string]bool{
	"PATH":                  true,
	"PWD":                   true,
	"IFS":                   true,
	"CDPATH":                true,
	"BASH_ENV":              true,
	"ENV":                   true,
	"PROMPT_COMMAND":        true,
	"ZDOTDIR":               true,
	"GIT_SSH_COMMAND":       true,
	"GIT_CONFIG_PARAMETERS": true,
	"GIT_EXEC_PATH":         true,
	"PYTHONPATH":            true,
	"PYTHONSTARTUP":         true,
	"NODE_OPTIONS":          true,
	"PERL5OPT":              true,
	"PERL5LIB":              true,
	"RUBYOPT":               true,
	"RUBYLIB":               true,
}

// ValidatePassEnv rejects dangerous loader, shell, and runtime environment variables.
func ValidatePassEnv(name string) error {
	if name == "" {
		return errors.New("environment variable name must not be empty")
	}
	if strings.ContainsRune(name, '=') {
		return fmt.Errorf("invalid --pass-env %q: pass only the variable name without '='", name)
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		ok := (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_'
		if !ok || (i == 0 && c >= '0' && c <= '9') {
			return fmt.Errorf("invalid --pass-env %q: must be a valid environment variable name", name)
		}
	}
	upper := strings.ToUpper(name)
	if strings.HasPrefix(upper, "LD_") || forbiddenPassEnvExact[upper] {
		return fmt.Errorf("refusing dangerous --pass-env variable %q", name)
	}
	return nil
}

// SweepUnexpectedFDs sets FD_CLOEXEC on any open file descriptors above stderr (> 2).
func SweepUnexpectedFDs() {
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return
	}
	for _, e := range entries {
		fd, err := strconv.Atoi(e.Name())
		if err != nil || fd <= 2 {
			continue
		}
		_, _ = unix.FcntlInt(uintptr(fd), unix.F_SETFD, unix.FD_CLOEXEC)
	}
}

// SanitizePATH filters rawPath to clean absolute directories owned by root or euid
// with no group or world write permissions.
func SanitizePATH(rawPath string, strictOnly bool, euid int) string {
	seen := make(map[string]bool)
	var out []string
	addIfSafe := func(dir string) {
		clean := filepath.Clean(strings.TrimSpace(dir))
		if clean == "" || !strings.HasPrefix(clean, "/") || seen[clean] {
			return
		}
		info, err := os.Stat(clean)
		if err != nil || !info.IsDir() {
			return
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			return
		}
		if st.Uid != 0 && int(st.Uid) != euid {
			return
		}
		if st.Mode&0o022 != 0 {
			return
		}
		seen[clean] = true
		out = append(out, clean)
	}

	if strictOnly {
		for _, d := range defaultTrustedPATHDirs {
			addIfSafe(d)
		}
	} else {
		for _, part := range strings.Split(rawPath, ":") {
			if part == "" || part == "." || !strings.HasPrefix(part, "/") {
				continue
			}
			addIfSafe(part)
		}
		for _, d := range defaultTrustedPATHDirs {
			addIfSafe(d)
		}
	}
	if len(out) == 0 {
		return ""
	}
	return strings.Join(out, ":")
}

// LookPathIn resolves exe exclusively against sanitizedPATH (never os.Getenv("PATH")).
func LookPathIn(sanitizedPATH, exe string) (string, error) {
	if err := remotepolicy.ValidateExecutable(exe); err != nil {
		return "", err
	}
	if strings.HasPrefix(exe, "/") {
		if err := checkExecutableFile(exe); err != nil {
			return "", err
		}
		return exe, nil
	}
	for _, dir := range strings.Split(sanitizedPATH, ":") {
		if dir == "" || !strings.HasPrefix(dir, "/") {
			continue
		}
		cand := filepath.Join(dir, exe)
		if err := checkExecutableFile(cand); err == nil {
			return cand, nil
		}
	}
	return "", fmt.Errorf("executable %q not found in sanitized PATH", exe)
}

func checkExecutableFile(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if info.IsDir() || !info.Mode().IsRegular() {
		return fmt.Errorf("%q is not a regular executable file", path)
	}
	if info.Mode().Perm()&0o111 == 0 {
		return fmt.Errorf("%q is not executable", path)
	}
	if err := unix.Access(path, unix.X_OK); err != nil {
		return fmt.Errorf("%q is not executable", path)
	}
	return nil
}

// CanonicalizeDir resolves symlinks on dir and requires an existing directory.
func CanonicalizeDir(dir string) (string, error) {
	if dir == "" {
		return "", errors.New("directory path must not be empty")
	}
	if !strings.HasPrefix(dir, "/") {
		return "", fmt.Errorf("directory %q must be an absolute path", dir)
	}
	resolved, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return "", fmt.Errorf("resolve directory %q: %w", dir, err)
	}
	clean := filepath.Clean(resolved)
	info, err := os.Stat(clean)
	if err != nil {
		return "", fmt.Errorf("stat directory %q: %w", clean, err)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("%q is not a directory", clean)
	}
	return clean, nil
}

// PinCWD canonicalizes reqCWD (or defaultCWD), pins it via openat2(RESOLVE_NO_SYMLINKS),
// rejects unlinked directories, and enforces both daemon and broker CWD scopes.
func PinCWD(reqCWD, defaultCWD string, allowCWD []string, allowScope *remoteproto.CWDScope, denyScopes []remoteproto.CWDScope) (int, string, error) {
	if err := remotepolicy.ValidateCWD(reqCWD); err != nil {
		return -1, "", err
	}
	target := reqCWD
	if target == "" {
		target = defaultCWD
	}
	if target == "" {
		return -1, "", errors.New("no working directory available")
	}
	rawClean := filepath.Clean(target)
	resolved, err := filepath.EvalSymlinks(rawClean)
	if err != nil {
		return -1, "", fmt.Errorf("resolve cwd %q: %w", target, err)
	}
	resolved = filepath.Clean(resolved)

	fd, err := openDirNoSymlinks(resolved)
	if err != nil {
		return -1, "", fmt.Errorf("pin cwd %q: %w", resolved, err)
	}
	closeOnErr := true
	defer func() {
		if closeOnErr {
			_ = unix.Close(fd)
		}
	}()

	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return -1, "", fmt.Errorf("fstat pinned cwd: %w", err)
	}
	if (st.Mode & unix.S_IFMT) != unix.S_IFDIR {
		return -1, "", errors.New("pinned cwd is not a directory")
	}
	if st.Nlink == 0 {
		return -1, "", errors.New("refusing unlinked working directory")
	}
	canonical, err := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", fd))
	if err != nil {
		return -1, "", fmt.Errorf("readlink pinned cwd: %w", err)
	}
	if strings.HasSuffix(canonical, " (deleted)") {
		return -1, "", errors.New("refusing deleted working directory")
	}
	canonical = filepath.Clean(canonical)

	if len(allowCWD) > 0 {
		ok := false
		for _, root := range allowCWD {
			if remotepolicy.IsPathWithin(canonical, root) {
				ok = true
				break
			}
		}
		if !ok {
			return -1, "", fmt.Errorf("cwd %q is outside allowed daemon directories", canonical)
		}
	}

	if allowScope != nil {
		canonAllow := canonicalizeScope(*allowScope)
		if !cwdMatchesScope(canonical, canonAllow) {
			return -1, "", fmt.Errorf("cwd %q is outside policy allow_cwd_scope", canonical)
		}
	}

	for _, ds := range denyScopes {
		canonDS := canonicalizeScope(ds)
		if cwdMatchesScope(canonical, canonDS) || cwdMatchesScope(canonical, ds) || cwdMatchesScope(rawClean, ds) {
			return -1, "", fmt.Errorf("cwd %q matched policy deny_cwd_scopes", canonical)
		}
	}

	closeOnErr = false
	return fd, canonical, nil
}

func canonicalizeScope(scope remoteproto.CWDScope) remoteproto.CWDScope {
	resolveList := func(roots []string) []string {
		if len(roots) == 0 {
			return nil
		}
		out := make([]string, 0, len(roots))
		for _, root := range roots {
			clean := filepath.Clean(root)
			if resolved, err := filepath.EvalSymlinks(clean); err == nil {
				out = append(out, filepath.Clean(resolved))
			} else {
				out = append(out, clean)
			}
		}
		return out
	}
	return remoteproto.CWDScope{
		In:    resolveList(scope.In),
		NotIn: resolveList(scope.NotIn),
	}
}

func cwdMatchesScope(cwd string, scope remoteproto.CWDScope) bool {
	if len(scope.In) > 0 {
		matched := false
		for _, root := range scope.In {
			if remotepolicy.IsPathWithin(cwd, root) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	for _, excluded := range scope.NotIn {
		if remotepolicy.IsPathWithin(cwd, excluded) {
			return false
		}
	}
	return true
}

func openDirNoSymlinks(absClean string) (int, error) {
	how := &unix.OpenHow{
		Flags:   unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_NO_SYMLINKS,
	}
	fd, err := unix.Openat2(unix.AT_FDCWD, absClean, how)
	if err == nil {
		return fd, nil
	}
	if !errors.Is(err, unix.ENOSYS) && !errors.Is(err, unix.EPERM) {
		return -1, err
	}
	// Component-wise fallback for kernels older than 5.6.
	curFD, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	trimmed := strings.TrimPrefix(absClean, "/")
	if trimmed == "" {
		return curFD, nil
	}
	for _, seg := range strings.Split(trimmed, "/") {
		if seg == "" || seg == "." {
			continue
		}
		nextFD, oErr := unix.Openat(curFD, seg, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		_ = unix.Close(curFD)
		if oErr != nil {
			return -1, oErr
		}
		curFD = nextFD
	}
	return curFD, nil
}

// ExecConfig holds immutable execution limits and environment policy for the remote daemon.
type ExecConfig struct {
	SanitizedPATH  string
	DefaultCWD     string
	AllowCWD       []string
	PassEnv        []string
	MaxOutputBytes int
	MaxStdinBytes  int
	ExecTimeout    time.Duration
	AllowNewPrivs  bool
	Getenv         func(string) string
}

// BuildCleanEnv constructs the clean child process environment with PWD set to canonicalCWD.
func BuildCleanEnv(cfg ExecConfig, canonicalCWD string) []string {
	getenv := cfg.Getenv
	if getenv == nil {
		getenv = os.Getenv
	}
	home := getenv("HOME")
	usr := getenv("USER")
	if u, err := user.Current(); err == nil {
		if home == "" {
			home = u.HomeDir
		}
		if usr == "" {
			usr = u.Username
		}
	}
	lang := getenv("LANG")
	if lang == "" {
		lang = "C.UTF-8"
	}
	env := []string{
		"PATH=" + cfg.SanitizedPATH,
		"HOME=" + home,
		"USER=" + usr,
		"LOGNAME=" + usr,
		"LANG=" + lang,
		"TERM=dumb",
		"PWD=" + canonicalCWD,
	}
	baseKeys := map[string]int{
		"PATH":    0,
		"HOME":    1,
		"USER":    2,
		"LOGNAME": 3,
		"LANG":    4,
		"TERM":    5,
		"PWD":     6,
	}
	seen := make(map[string]bool, len(cfg.PassEnv))
	for _, k := range cfg.PassEnv {
		if seen[k] {
			continue
		}
		seen[k] = true
		val := getenv(k)
		if val == "" {
			continue
		}
		if idx, exists := baseKeys[k]; exists {
			if k == "PATH" || k == "PWD" {
				continue
			}
			env[idx] = k + "=" + val
			continue
		}
		env = append(env, k+"="+val)
	}
	return env
}

// ExecuteCommand executes one approved ExecRequest inside an isolated session and process group.
func ExecuteCommand(ctx context.Context, cfg ExecConfig, req remoteproto.ExecRequest) remoteproto.ExecResponse {
	start := time.Now()
	maxOut := cfg.MaxOutputBytes
	if maxOut <= 0 || maxOut > remoteproto.MaxOutputBytes {
		maxOut = remoteproto.DefaultOutputBytes
	}
	if req.MaxOutputBytes > 0 && req.MaxOutputBytes < maxOut {
		maxOut = req.MaxOutputBytes
	}
	maxStdin := cfg.MaxStdinBytes
	if maxStdin <= 0 || maxStdin > remoteproto.MaxStdinBytes {
		maxStdin = remoteproto.MaxStdinBytes
	}
	execTimeout := cfg.ExecTimeout
	if execTimeout <= 0 {
		execTimeout = time.Duration(remoteproto.DefaultExecTimeoutSec) * time.Second
	}
	if req.ExecTimeoutSec > 0 {
		reqDur := time.Duration(req.ExecTimeoutSec) * time.Second
		if reqDur < execTimeout {
			execTimeout = reqDur
		}
	}

	var stdinBytes []byte
	if req.StdinB64 != "" {
		decoded, err := base64.StdEncoding.DecodeString(req.StdinB64)
		if err != nil || len(decoded) > maxStdin {
			return remoteproto.DeniedResponse(req.ReqID, "")
		}
		stdinBytes = decoded
	}

	resolvedExe, err := LookPathIn(cfg.SanitizedPATH, req.Executable)
	if err != nil {
		return remoteproto.ExecResponse{
			ReqID:      req.ReqID,
			Status:     remoteproto.StatusCompleted,
			ExitCode:   127,
			StderrB64:  base64.StdEncoding.EncodeToString([]byte(err.Error() + "\n")),
			DurationMS: time.Since(start).Milliseconds(),
		}
	}

	dirFD, canonicalCWD, err := PinCWD(req.CWD, cfg.DefaultCWD, cfg.AllowCWD, req.AllowCWDScope, req.DenyCWDScopes)
	if err != nil {
		return remoteproto.DeniedResponse(req.ReqID, "")
	}
	dirFDClosed := false
	closeDirFD := func() {
		if !dirFDClosed {
			_ = unix.Close(dirFD)
			dirFDClosed = true
		}
	}
	defer closeDirFD()

	runCtx, cancel := context.WithTimeout(ctx, execTimeout)
	defer cancel()

	cmd := exec.CommandContext(runCtx, resolvedExe, req.Args...)
	cmd.Path = resolvedExe
	cmd.Args = append([]string{req.Executable}, req.Args...)
	cmd.Dir = fmt.Sprintf("/proc/self/fd/%d", dirFD)
	cmd.Env = BuildCleanEnv(cfg, canonicalCWD)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	cmd.WaitDelay = 2 * time.Second

	if len(stdinBytes) > 0 {
		cmd.Stdin = bytes.NewReader(stdinBytes)
	} else {
		devNull, err := os.Open(os.DevNull)
		if err == nil {
			cmd.Stdin = devNull
			defer devNull.Close()
		}
	}

	budget := &sharedOutputBudget{
		maxStore: maxOut,
		maxDrain: remoteproto.MaxDrainBytes,
	}
	cmd.Cancel = func() error {
		if pid := budget.getPID(); pid > 0 {
			return syscall.Kill(-pid, syscall.SIGKILL)
		}
		if cmd.Process != nil {
			return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		}
		return nil
	}

	stdoutCap := &boundedStreamWriter{budget: budget}
	stderrCap := &boundedStreamWriter{budget: budget}
	cmd.Stdout = stdoutCap
	cmd.Stderr = stderrCap

	if err := startWithNoNewPrivs(cmd, !cfg.AllowNewPrivs); err != nil {
		closeDirFD()
		return remoteproto.ExecResponse{
			ReqID:      req.ReqID,
			Status:     remoteproto.StatusCompleted,
			ExitCode:   126,
			StderrB64:  base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("start command: %v\n", err))),
			DurationMS: time.Since(start).Milliseconds(),
		}
	}
	if cmd.Process != nil {
		budget.setPID(cmd.Process.Pid)
	}
	closeDirFD()

	waitErr := cmd.Wait()
	durMS := time.Since(start).Milliseconds()

	outBytes, outTrunc := stdoutCap.snapshot()
	errBytes, errTrunc := stderrCap.snapshot()

	if errors.Is(runCtx.Err(), context.DeadlineExceeded) {
		return remoteproto.ExecResponse{
			ReqID:           req.ReqID,
			Status:          remoteproto.StatusTimeout,
			ExitCode:        remoteproto.TimeoutExitCode,
			StdoutB64:       encodeOptionalB64(outBytes),
			StderrB64:       encodeOptionalB64(errBytes),
			StdoutTruncated: outTrunc,
			StderrTruncated: errTrunc,
			DurationMS:      durMS,
			TimeoutSec:      int(execTimeout / time.Second),
		}
	}
	if errors.Is(ctx.Err(), context.Canceled) {
		return remoteproto.DeniedResponse(req.ReqID, "")
	}

	exitCode := 0
	if waitErr != nil {
		var exitErr *exec.ExitError
		if errors.As(waitErr, &exitErr) {
			if ws, ok := exitErr.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
				exitCode = 128 + int(ws.Signal())
			} else {
				exitCode = exitErr.ExitCode()
			}
		} else {
			exitCode = 1
		}
	}
	return remoteproto.ExecResponse{
		ReqID:           req.ReqID,
		Status:          remoteproto.StatusCompleted,
		ExitCode:        exitCode,
		StdoutB64:       encodeOptionalB64(outBytes),
		StderrB64:       encodeOptionalB64(errBytes),
		StdoutTruncated: outTrunc,
		StderrTruncated: errTrunc,
		DurationMS:      durMS,
	}
}

// startWithNoNewPrivs starts cmd on a dedicated single-use locked OS thread when enableNoNewPrivs is true.
// The goroutine intentionally exits without UnlockOSThread so the Go runtime terminates that thread.
func startWithNoNewPrivs(cmd *exec.Cmd, enableNoNewPrivs bool) error {
	if !enableNoNewPrivs {
		return cmd.Start()
	}
	errCh := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
			errCh <- fmt.Errorf("prctl PR_SET_NO_NEW_PRIVS: %w", err)
			return
		}
		errCh <- cmd.Start()
		// Return while locked so Go destroys this OS thread instead of returning it to the M pool.
	}()
	return <-errCh
}

type sharedOutputBudget struct {
	mu       sync.Mutex
	maxStore int
	stored   int
	maxDrain int
	drained  int
	killed   bool
	procPID  int
}

func (b *sharedOutputBudget) setPID(pid int) {
	b.mu.Lock()
	b.procPID = pid
	alreadyKilled := b.killed
	b.mu.Unlock()
	if alreadyKilled && pid > 0 {
		_ = syscall.Kill(-pid, syscall.SIGKILL)
	}
}

func (b *sharedOutputBudget) getPID() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.procPID
}

type boundedStreamWriter struct {
	budget    *sharedOutputBudget
	mu        sync.Mutex
	buf       bytes.Buffer
	truncated bool
}

func (w *boundedStreamWriter) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	w.budget.mu.Lock()
	avail := w.budget.maxStore - w.budget.stored
	storeN := 0
	if avail > 0 {
		storeN = len(p)
		if storeN > avail {
			storeN = avail
		}
		w.budget.stored += storeN
	}
	overflow := len(p) - storeN
	killNow := false
	killPID := 0
	if overflow > 0 {
		w.budget.drained += overflow
		if w.budget.drained > w.budget.maxDrain && !w.budget.killed {
			w.budget.killed = true
			killNow = true
			killPID = w.budget.procPID
		}
	}
	w.budget.mu.Unlock()

	w.mu.Lock()
	if storeN > 0 {
		_, _ = w.buf.Write(p[:storeN])
	}
	if overflow > 0 {
		w.truncated = true
	}
	w.mu.Unlock()

	if killNow {
		if killPID > 0 {
			_ = syscall.Kill(-killPID, syscall.SIGKILL)
		}
		return 0, io.ErrClosedPipe
	}
	return len(p), nil
}

func (w *boundedStreamWriter) snapshot() ([]byte, bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]byte(nil), w.buf.Bytes()...), w.truncated
}

func encodeOptionalB64(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	return base64.StdEncoding.EncodeToString(b)
}
