// Package mounttab parses /proc/self/mountinfo and unmounts FUSE filter directories.
//
// Security properties:
//   - ReadCurrent reads /proc/self/mountinfo instead of os.Stat because a
//     crashed FUSE daemon returns ENOTCONN while its mount stays active.
//   - OSController checks /proc/<pid>/cmdline for argv[1] == "__filter" and a
//     matching -mnt prefix before sending SIGTERM or SIGKILL.
//   - TeardownFilterDir rejects symlinked directories and verifies zero active
//     mounts under both raw and canonical paths before deletion.
package mounttab

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	maxMountinfoLineBytes = 1024 * 1024
	unmountCmdTimeout     = 5 * time.Second
	maxSymlinkHops        = 40
)

// Entry describes one mounted filesystem from /proc/self/mountinfo.
type Entry struct {
	MountPoint string
	FSType     string
	Source     string
}

// UnescapeOctal decodes 3-digit octal escape sequences (\040, \011, \012, \134).
// The Linux kernel writes these sequences for whitespace and backslashes in
// /proc/self/mountinfo.
func UnescapeOctal(s string) string {
	if !strings.ContainsRune(s, '\\') {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) && s[i+1] >= '0' && s[i+1] <= '3' && isOctal(s[i+2]) && isOctal(s[i+3]) {
			v := (s[i+1]-'0')*64 + (s[i+2]-'0')*8 + (s[i+3] - '0')
			b.WriteByte(v)
			i += 3
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func isOctal(c byte) bool {
	return c >= '0' && c <= '7'
}

// ParseMountinfo parses lines from /proc/self/mountinfo.
// Example proc(5) line:
// 36 35 98:0 /mnt1 /mnt2 rw,noatime master:1 - ext3 /dev/root rw,errors=continue
func ParseMountinfo(r io.Reader) ([]Entry, error) {
	var entries []Entry
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), maxMountinfoLineBytes)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		beforeHyphen, afterHyphen, ok := strings.Cut(line, " - ")
		if !ok {
			continue
		}
		preFields := strings.Fields(beforeHyphen)
		postFields := strings.Fields(afterHyphen)
		if len(preFields) < 5 || len(postFields) < 2 {
			continue
		}
		entries = append(entries, Entry{
			MountPoint: filepath.Clean(UnescapeOctal(preFields[4])),
			FSType:     UnescapeOctal(postFields[0]),
			Source:     UnescapeOctal(postFields[1]),
		})
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return entries, nil
}

func resolvePathWithAncestor(absPath string) string {
	p := filepath.Clean(absPath)
	if !filepath.IsAbs(p) {
		return p
	}
	for hop := 0; hop < maxSymlinkHops; hop++ {
		if resolved, err := filepath.EvalSymlinks(p); err == nil {
			return filepath.Clean(resolved)
		}
		advanced := false
		cur := p
		for cur != "/" && cur != "." {
			if resolved, err := filepath.EvalSymlinks(cur); err == nil {
				rel, rErr := filepath.Rel(cur, p)
				if rErr == nil {
					return filepath.Clean(filepath.Join(resolved, rel))
				}
				return p
			}
			if info, lErr := os.Lstat(cur); lErr == nil && info.Mode()&os.ModeSymlink != 0 {
				target, rErr := os.Readlink(cur)
				if rErr != nil {
					return p
				}
				if !filepath.IsAbs(target) {
					target = filepath.Join(filepath.Dir(cur), target)
				}
				rel, relErr := filepath.Rel(cur, p)
				if relErr != nil {
					return p
				}
				if rel == "." {
					p = filepath.Clean(target)
				} else {
					p = filepath.Clean(filepath.Join(target, rel))
				}
				advanced = true
				break
			}
			parent := filepath.Dir(cur)
			if parent == cur {
				break
			}
			cur = parent
		}
		if !advanced {
			return p
		}
	}
	return p
}

func isPathWithin(candidate, root string) bool {
	if candidate == "" || root == "" {
		return false
	}
	c := filepath.Clean(candidate)
	r := filepath.Clean(root)
	if r == "/" {
		return strings.HasPrefix(c, "/")
	}
	return c == r || strings.HasPrefix(c, r+"/")
}

// IsMounted reports whether target or its canonical path matches an Entry in entries.
func IsMounted(entries []Entry, target string) bool {
	if target == "" {
		return false
	}
	clean := filepath.Clean(target)
	resolved := resolvePathWithAncestor(clean)
	for _, e := range entries {
		if e.MountPoint == clean || (resolved != "" && e.MountPoint == resolved) {
			return true
		}
	}
	return false
}

// MountsUnder returns all mountpoints in entries at or inside dir (or its canonical path).
func MountsUnder(entries []Entry, dir string) []string {
	if dir == "" {
		return nil
	}
	clean := filepath.Clean(dir)
	resolved := resolvePathWithAncestor(clean)
	var out []string
	for _, e := range entries {
		matchClean := isPathWithin(e.MountPoint, clean)
		matchResolved := resolved != "" && resolved != clean && isPathWithin(e.MountPoint, resolved)
		if matchClean || matchResolved {
			out = append(out, e.MountPoint)
		}
	}
	return out
}

// ReadCurrent reads and parses /proc/self/mountinfo from the host kernel.
func ReadCurrent() ([]Entry, error) {
	return readMountinfoFile("/proc/self/mountinfo")
}

func readMountinfoFile(path string) ([]Entry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return ParseMountinfo(f)
}

// IsPathMounted checks whether target is an active mountpoint in /proc/self/mountinfo.
// It rejects symlinked mountpoint paths.
func IsPathMounted(target string) (bool, error) {
	if target == "" {
		return false, nil
	}
	clean := filepath.Clean(target)
	if info, err := os.Lstat(clean); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return false, fmt.Errorf("refusing symlinked mountpoint %q", target)
	}
	entries, err := ReadCurrent()
	if err != nil {
		return false, err
	}
	return IsMounted(entries, clean), nil
}

// Controller abstracts mount-table reads, process signals, and unmount calls.
type Controller interface {
	ListMounts() ([]Entry, error)
	SignalPID(pid int, sig syscall.Signal) error
	Unmount(mountpoint string, lazy bool) error
	Sleep(d time.Duration)
}

type dirScopedSignaler interface {
	signalPIDForDir(pid int, cleanDir, resolvedDir string, sig syscall.Signal) error
}

// IsFilterCmdline reports whether raw /proc/<pid>/cmdline bytes belong to an
// `agbox __filter` daemon process.
func IsFilterCmdline(cmdline []byte) bool {
	return isFilterCmdline(cmdline, false)
}

func isFilterCmdline(cmdline []byte, allowTestBin bool) bool {
	parts, ok := parseFilterCmdlineParts(cmdline, allowTestBin)
	return ok && len(parts) >= 2
}

func parseFilterCmdlineParts(cmdline []byte, allowTestBin bool) ([]string, bool) {
	if len(cmdline) == 0 {
		return nil, false
	}
	rawParts := bytes.Split(cmdline, []byte{0})
	if len(rawParts) < 2 || len(rawParts[0]) == 0 || string(rawParts[1]) != "__filter" {
		return nil, false
	}
	argv0 := string(rawParts[0])
	for _, r := range argv0 {
		if r <= 0x20 || r == 0x7f {
			return nil, false
		}
	}
	base := filepath.Base(argv0)
	if base != "agbox" && !(allowTestBin && strings.HasSuffix(base, ".test")) {
		return nil, false
	}
	parts := make([]string, 0, len(rawParts))
	for _, p := range rawParts {
		parts = append(parts, string(p))
	}
	return parts, true
}

func isFilterCmdlineForDir(cmdline []byte, cleanDir, resolvedDir string, allowTestBin bool) bool {
	parts, ok := parseFilterCmdlineParts(cmdline, allowTestBin)
	if !ok {
		return false
	}
	if cleanDir == "" && resolvedDir == "" {
		return true
	}
	mntArg := extractFilterMountArg(parts[2:])
	if mntArg == "" {
		return false
	}
	mntClean := filepath.Clean(mntArg)
	mntResolved := resolvePathWithAncestor(mntClean)
	if cleanDir != "" && (isPathWithin(mntClean, cleanDir) || isPathWithin(mntResolved, cleanDir)) {
		return true
	}
	if resolvedDir != "" && (isPathWithin(mntClean, resolvedDir) || isPathWithin(mntResolved, resolvedDir)) {
		return true
	}
	return false
}

func extractFilterMountArg(args []string) string {
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "" {
			continue
		}
		if (arg == "-mnt" || arg == "--mnt") && i+1 < len(args) {
			return args[i+1]
		}
		if strings.HasPrefix(arg, "-mnt=") {
			return strings.TrimPrefix(arg, "-mnt=")
		}
		if strings.HasPrefix(arg, "--mnt=") {
			return strings.TrimPrefix(arg, "--mnt=")
		}
	}
	return ""
}

// OSController implements Controller with /proc/self/mountinfo, kill(2), and fusermount3.
type OSController struct {
	RunCommand      func(ctx context.Context, name string, args ...string) ([]byte, error)
	ReadCmdline     func(pid int) ([]byte, error)
	KillPID         func(pid int, sig syscall.Signal) error
	UnmountSyscall  func(target string, flags int) error
	AllowTestBinary bool
}

func (OSController) ListMounts() ([]Entry, error) {
	return ReadCurrent()
}

func (c OSController) SignalPID(pid int, sig syscall.Signal) error {
	return c.signalPIDForDir(pid, "", "", sig)
}

func (c OSController) signalPIDForDir(pid int, cleanDir, resolvedDir string, sig syscall.Signal) error {
	if pid <= 0 {
		return nil
	}
	readCmd := c.ReadCmdline
	if readCmd == nil {
		readCmd = func(p int) ([]byte, error) {
			return os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", p))
		}
	}
	cmdline, err := readCmd(pid)
	if err != nil {
		if os.IsNotExist(err) || errors.Is(err, syscall.ESRCH) {
			return nil
		}
		return err
	}
	if !isFilterCmdlineForDir(cmdline, cleanDir, resolvedDir, c.AllowTestBinary) {
		return nil
	}
	killFn := c.KillPID
	if killFn == nil {
		killFn = syscall.Kill
	}
	err = killFn(pid, sig)
	if errors.Is(err, syscall.ESRCH) {
		return nil
	}
	return err
}

func (c OSController) Unmount(mountpoint string, lazy bool) error {
	runCmd := c.RunCommand
	if runCmd == nil {
		runCmd = func(ctx context.Context, name string, args ...string) ([]byte, error) {
			return exec.CommandContext(ctx, name, args...).CombinedOutput()
		}
	}
	unmountSys := c.UnmountSyscall
	if unmountSys == nil {
		unmountSys = syscall.Unmount
	}

	var args []string
	var sysFlags int
	if lazy {
		args = []string{"-u", "-z", "--", mountpoint}
		sysFlags = syscall.MNT_DETACH
	} else {
		args = []string{"-u", "--", mountpoint}
		sysFlags = 0
	}

	var lastDetail string
	for _, bin := range []string{"fusermount3", "fusermount"} {
		ctx, cancel := context.WithTimeout(context.Background(), unmountCmdTimeout)
		out, err := runCmd(ctx, bin, args...)
		cancel()
		if err == nil {
			return nil
		}
		if trimmed := strings.TrimSpace(string(out)); trimmed != "" {
			lastDetail = trimmed
		}
	}

	if err := unmountSys(mountpoint, sysFlags); err != nil {
		if lastDetail != "" {
			return fmt.Errorf("unmount %s: %w (%s)", mountpoint, err, lastDetail)
		}
		return err
	}
	return nil
}

func (OSController) Sleep(d time.Duration) {
	time.Sleep(d)
}

func validateFilterDirTarget(dir, op string) (string, string, error) {
	cleanDir := filepath.Clean(dir)
	if dir == "" || !filepath.IsAbs(cleanDir) || cleanDir == "/" {
		return "", "", fmt.Errorf("refusing to %s unsafe directory %q", op, dir)
	}
	if info, err := os.Lstat(cleanDir); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return "", "", fmt.Errorf("refusing to %s symlinked directory %q", op, dir)
	}
	resolvedDir := resolvePathWithAncestor(cleanDir)
	if resolvedDir == "/" {
		return "", "", fmt.Errorf("refusing to %s unsafe directory %q", op, dir)
	}
	if resolvedDir != cleanDir {
		if info, err := os.Lstat(resolvedDir); err == nil && info.Mode()&os.ModeSymlink != 0 {
			return "", "", fmt.Errorf("refusing to %s symlinked directory %q", op, dir)
		}
	}
	return cleanDir, resolvedDir, nil
}

func mountsMatchingDir(entries []Entry, cleanDir, resolvedDir string) []string {
	seen := make(map[string]bool)
	var out []string
	for _, d := range []string{cleanDir, resolvedDir} {
		if d == "" {
			continue
		}
		for _, mp := range MountsUnder(entries, d) {
			if !seen[mp] {
				seen[mp] = true
				out = append(out, mp)
			}
		}
	}
	return out
}

// UnmountFilterDir stops FUSE filter daemons recorded in dir/*.pid and unmounts
// all mountpoints under dir while keeping dir and its metadata files.
func UnmountFilterDir(dir string, ctl Controller) error {
	cleanDir, resolvedDir, err := validateFilterDirTarget(dir, "unmount")
	if err != nil {
		return err
	}
	if ctl == nil {
		ctl = OSController{}
	}

	signalRecordedPIDs(cleanDir, resolvedDir, syscall.SIGTERM, ctl)

	entries, err := ctl.ListMounts()
	if err != nil {
		return fmt.Errorf("read mount table: %w", err)
	}
	mps := mountsMatchingDir(entries, cleanDir, resolvedDir)
	for i := len(mps) - 1; i >= 0; i-- {
		_ = ctl.Unmount(mps[i], false)
	}

	// Poll the mount table up to 20 times at 100 ms intervals.
	unmounted := false
	for i := 0; i < 20; i++ {
		cur, err := ctl.ListMounts()
		if err == nil && len(mountsMatchingDir(cur, cleanDir, resolvedDir)) == 0 {
			unmounted = true
			break
		}
		ctl.Sleep(100 * time.Millisecond)
	}

	// Send SIGKILL and run a lazy unmount if mounts remain active.
	if !unmounted {
		signalRecordedPIDs(cleanDir, resolvedDir, syscall.SIGKILL, ctl)
		if cur, err := ctl.ListMounts(); err == nil {
			curMps := mountsMatchingDir(cur, cleanDir, resolvedDir)
			for i := len(curMps) - 1; i >= 0; i-- {
				_ = ctl.Unmount(curMps[i], true)
			}
		}
		for i := 0; i < 20; i++ {
			cur, err := ctl.ListMounts()
			if err == nil && len(mountsMatchingDir(cur, cleanDir, resolvedDir)) == 0 {
				unmounted = true
				break
			}
			ctl.Sleep(100 * time.Millisecond)
		}
	}

	finalEntries, err := ctl.ListMounts()
	if err != nil {
		return fmt.Errorf("verify mount table after unmount: %w", err)
	}
	if remaining := mountsMatchingDir(finalEntries, cleanDir, resolvedDir); len(remaining) > 0 {
		return fmt.Errorf("%d mounts remain active under %s (%s)", len(remaining), cleanDir, strings.Join(remaining, ", "))
	}

	removePIDFiles(resolvedDir)
	sockPath := filepath.Join(resolvedDir, "ws.sock")
	if info, lErr := os.Lstat(sockPath); lErr == nil && info.Mode()&os.ModeSocket != 0 {
		_ = os.Remove(sockPath)
	}
	return nil
}

// TeardownFilterDir stops FUSE filter daemons in dir/*.pid and unmounts all
// mountpoints under dir. It deletes dir only when zero mounts remain active.
func TeardownFilterDir(dir string, ctl Controller) error {
	cleanDir, resolvedDir, err := validateFilterDirTarget(dir, "remove")
	if err != nil {
		return err
	}
	if ctl == nil {
		ctl = OSController{}
	}
	if err := UnmountFilterDir(cleanDir, ctl); err != nil {
		return fmt.Errorf("refusing to remove %s: %w", cleanDir, err)
	}
	if info, lErr := os.Lstat(cleanDir); lErr == nil && info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("refusing to remove symlinked directory %q", dir)
	}
	finalEntries, err := ctl.ListMounts()
	if err != nil {
		return fmt.Errorf("refusing to remove %s: verify mount table: %w", cleanDir, err)
	}
	if remaining := mountsMatchingDir(finalEntries, cleanDir, resolvedDir); len(remaining) > 0 {
		return fmt.Errorf("refusing to remove %s: %d mounts remain active", cleanDir, len(remaining))
	}
	if err := os.RemoveAll(resolvedDir); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove filter dir %s: %w", cleanDir, err)
	}
	return nil
}

func removePIDFiles(dir string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".pid") {
			continue
		}
		_ = os.Remove(filepath.Join(dir, entry.Name()))
	}
}

func signalRecordedPIDs(cleanDir, resolvedDir string, sig syscall.Signal, ctl Controller) {
	entries, err := os.ReadDir(resolvedDir)
	if err != nil {
		return
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".pid") {
			continue
		}
		pid, ok := readPIDFileNoFollow(filepath.Join(resolvedDir, entry.Name()))
		if !ok {
			continue
		}
		if scoped, ok := ctl.(dirScopedSignaler); ok {
			_ = scoped.signalPIDForDir(pid, cleanDir, resolvedDir, sig)
		} else {
			_ = ctl.SignalPID(pid, sig)
		}
	}
}

func readPIDFileNoFollow(path string) (int, bool) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC|syscall.O_NONBLOCK, 0)
	if err != nil {
		return 0, false
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()

	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return 0, false
	}
	raw, err := io.ReadAll(io.LimitReader(f, 64))
	if err != nil {
		return 0, false
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(raw)))
	if err != nil || pid <= 0 {
		return 0, false
	}
	return pid, true
}
