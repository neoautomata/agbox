// Package mounttab parses /proc/self/mountinfo and unmounts FUSE filter directories.
//
// Security properties:
//   - ReadCurrent inspects /proc/self/mountinfo instead of os.Stat because a
//     crashed FUSE daemon returns ENOTCONN while its mount remains active.
//   - OSController.SignalPID checks /proc/<pid>/cmdline for argv[1] == "__filter"
//     before sending SIGTERM or SIGKILL, preventing PID-reuse kills on the host.
//   - TeardownFilterDir refuses to run os.RemoveAll if any mount remains active.
package mounttab

import (
	"bufio"
	"bytes"
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

// Entry represents a mounted filesystem from /proc/self/mountinfo.
type Entry struct {
	MountPoint string
	FSType     string
	Source     string
}

// UnescapeOctal decodes 3-digit octal escape sequences (\040, \011, \012, \134).
// The Linux kernel uses these sequences for whitespace and backslashes in
// /proc/self/mountinfo.
func UnescapeOctal(s string) string {
	if !strings.ContainsRune(s, '\\') {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) && isOctal(s[i+1]) && isOctal(s[i+2]) && isOctal(s[i+3]) {
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

// ParseMountinfo parses the contents of /proc/self/mountinfo.
// Format per proc(5):
// 36 35 98:0 /mnt1 /mnt2 rw,noatime master:1 - ext3 /dev/root rw,errors=continue
func ParseMountinfo(r io.Reader) ([]Entry, error) {
	var entries []Entry
	sc := bufio.NewScanner(r)
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

// IsMounted reports whether target matches a MountPoint in entries.
func IsMounted(entries []Entry, target string) bool {
	if target == "" {
		return false
	}
	clean := filepath.Clean(target)
	for _, e := range entries {
		if e.MountPoint == clean {
			return true
		}
	}
	return false
}

// MountsUnder returns all mountpoints in entries that are equal to dir or
// located inside dir.
func MountsUnder(entries []Entry, dir string) []string {
	if dir == "" {
		return nil
	}
	clean := filepath.Clean(dir)
	prefix := clean + "/"
	if clean == "/" {
		prefix = "/"
	}
	var out []string
	for _, e := range entries {
		if e.MountPoint == clean || strings.HasPrefix(e.MountPoint, prefix) {
			out = append(out, e.MountPoint)
		}
	}
	return out
}

// ReadCurrent reads and parses /proc/self/mountinfo from the host kernel.
func ReadCurrent() ([]Entry, error) {
	f, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return ParseMountinfo(f)
}

// IsPathMounted checks whether target is currently a mountpoint in /proc/self/mountinfo.
func IsPathMounted(target string) (bool, error) {
	entries, err := ReadCurrent()
	if err != nil {
		return false, err
	}
	return IsMounted(entries, target), nil
}

// HasMountsUnder reports whether any mount in /proc/self/mountinfo is at or under dir.
func HasMountsUnder(dir string) (bool, error) {
	entries, err := ReadCurrent()
	if err != nil {
		return false, err
	}
	return len(MountsUnder(entries, dir)) > 0, nil
}

// Controller abstracts mount-table reads, process signals, and unmount calls.
// This interface allows deterministic unit tests for TeardownFilterDir.
type Controller interface {
	ListMounts() ([]Entry, error)
	SignalPID(pid int, sig syscall.Signal) error
	Unmount(mountpoint string, lazy bool) error
	Sleep(d time.Duration)
}

// IsFilterCmdline reports whether raw /proc/<pid>/cmdline bytes belong to an
// `agbox __filter` daemon process (argv[1] == "__filter").
func IsFilterCmdline(cmdline []byte) bool {
	if len(cmdline) == 0 {
		return false
	}
	parts := bytes.Split(cmdline, []byte{0})
	return len(parts) >= 2 && len(parts[0]) > 0 && string(parts[1]) == "__filter"
}

// OSController is the production Controller backed by /proc/self/mountinfo,
// kill(2), and fusermount3/fusermount/umount.
type OSController struct{}

func (OSController) ListMounts() ([]Entry, error) {
	return ReadCurrent()
}

func (OSController) SignalPID(pid int, sig syscall.Signal) error {
	if pid <= 0 {
		return nil
	}
	cmdline, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil {
		if os.IsNotExist(err) || errors.Is(err, syscall.ESRCH) {
			return nil
		}
		return err
	}
	if !IsFilterCmdline(cmdline) {
		return nil
	}
	err = syscall.Kill(pid, sig)
	if errors.Is(err, syscall.ESRCH) {
		return nil
	}
	return err
}

func (OSController) Unmount(mountpoint string, lazy bool) error {
	if !lazy {
		if err := exec.Command("fusermount3", "-u", mountpoint).Run(); err == nil {
			return nil
		}
		if err := exec.Command("fusermount", "-u", mountpoint).Run(); err == nil {
			return nil
		}
		return syscall.Unmount(mountpoint, 0)
	}
	if err := exec.Command("fusermount3", "-u", "-z", mountpoint).Run(); err == nil {
		return nil
	}
	if err := exec.Command("fusermount", "-u", "-z", mountpoint).Run(); err == nil {
		return nil
	}
	return syscall.Unmount(mountpoint, syscall.MNT_DETACH)
}

func (OSController) Sleep(d time.Duration) {
	time.Sleep(d)
}

// UnmountFilterDir stops FUSE filter daemons recorded in dir/m*.pid and
// unmounts all mountpoints under dir while keeping dir and its metadata files.
func UnmountFilterDir(dir string, ctl Controller) error {
	cleanDir := filepath.Clean(dir)
	if cleanDir == "" || cleanDir == "/" || cleanDir == "." {
		return fmt.Errorf("refusing to unmount unsafe directory %q", dir)
	}
	if ctl == nil {
		ctl = OSController{}
	}

	signalRecordedPIDs(cleanDir, syscall.SIGTERM, ctl)

	entries, err := ctl.ListMounts()
	if err != nil {
		return fmt.Errorf("read mount table: %w", err)
	}
	for _, mp := range MountsUnder(entries, cleanDir) {
		_ = ctl.Unmount(mp, false)
	}

	// Wait up to 20 ticks for polite unmount.
	unmounted := false
	for i := 0; i < 20; i++ {
		cur, err := ctl.ListMounts()
		if err == nil && len(MountsUnder(cur, cleanDir)) == 0 {
			unmounted = true
			break
		}
		ctl.Sleep(100 * time.Millisecond)
	}

	// Escalate to SIGKILL + lazy unmount if still mounted.
	if !unmounted {
		signalRecordedPIDs(cleanDir, syscall.SIGKILL, ctl)
		if cur, err := ctl.ListMounts(); err == nil {
			for _, mp := range MountsUnder(cur, cleanDir) {
				_ = ctl.Unmount(mp, true)
			}
		}
		for i := 0; i < 20; i++ {
			cur, err := ctl.ListMounts()
			if err == nil && len(MountsUnder(cur, cleanDir)) == 0 {
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
	if remaining := MountsUnder(finalEntries, cleanDir); len(remaining) > 0 {
		return fmt.Errorf("%d mount(s) still active under %s (%s)", len(remaining), cleanDir, strings.Join(remaining, ", "))
	}

	removePIDFiles(cleanDir)
	return nil
}

// TeardownFilterDir stops FUSE filter daemons recorded in dir/m*.pid and
// unmounts all mountpoints under dir. It deletes dir only after it verifies
// that zero mounts remain under dir in /proc/self/mountinfo.
func TeardownFilterDir(dir string, ctl Controller) error {
	cleanDir := filepath.Clean(dir)
	if cleanDir == "" || cleanDir == "/" || cleanDir == "." {
		return fmt.Errorf("refusing to remove unsafe directory %q", dir)
	}
	if err := UnmountFilterDir(cleanDir, ctl); err != nil {
		return fmt.Errorf("refusing to remove %s: %w", cleanDir, err)
	}
	if err := os.RemoveAll(cleanDir); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove filter dir %s: %w", cleanDir, err)
	}
	return nil
}

func removePIDFiles(dir string) {
	matches, err := filepath.Glob(filepath.Join(dir, "m*.pid"))
	if err != nil {
		return
	}
	for _, pf := range matches {
		_ = os.Remove(pf)
	}
}

func signalRecordedPIDs(dir string, sig syscall.Signal, ctl Controller) {
	matches, err := filepath.Glob(filepath.Join(dir, "m*.pid"))
	if err != nil {
		return
	}
	for _, pf := range matches {
		raw, err := os.ReadFile(pf)
		if err != nil {
			continue
		}
		if pid, err := strconv.Atoi(strings.TrimSpace(string(raw))); err == nil && pid > 0 {
			_ = ctl.SignalPID(pid, sig)
		}
	}
}
