package mounttab

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestUnescapeOctal(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"/normal/path", "/normal/path"},
		{"/path/with\\040space/and\\011tab", "/path/with space/and\ttab"},
		{"/path/with\\134backslash/and\\012nl", "/path/with\\backslash/and\nnl"},
		{"/incomplete\\04", "/incomplete\\04"},
		{"/non_octal\\089", "/non_octal\\089"},
		{"/overflow\\400", "/overflow\\400"},
		{"/overflow\\777", "/overflow\\777"},
		{"/max_valid\\377", "/max_valid\xff"},
		{"/null_byte\\000", "/null_byte\x00"},
	}
	for _, tc := range cases {
		if got := UnescapeOctal(tc.in); got != tc.want {
			t.Errorf("UnescapeOctal(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestParseMountinfoAndQueries(t *testing.T) {
	longOpt := strings.Repeat("x", 100*1024)
	sample := `
22 1 8:1 / / rw,relatime shared:1 - ext4 /dev/sda1 rw
89 22 0:45 / /home/alice/.local/share/agbox/run/100/m0 rw,nosuid,nodev - fuse.agboxfilter agboxfilter rw,user_id=1000,group_id=1000
90 22 0:46 / /home/alice/dir\040with\040space/m1 rw,nosuid - fuse.agboxfilter agboxfilter rw
91 22 0:47 / /home/alice/.local/share/agbox/run/1000/m0 rw - fuse.agboxfilter agboxfilter rw,` + longOpt + `
malformed line without separator
1 2 3 /only_four - ext4 /dev/sda1
22 1 8:1 / /mnt rw - only_one_post_field
22 1 8:1 / /mnt rw - 
`
	entries, err := ParseMountinfo(strings.NewReader(sample))
	if err != nil {
		t.Fatalf("ParseMountinfo failed: %v", err)
	}
	if len(entries) != 4 {
		t.Fatalf("len(entries) = %d, want 4", len(entries))
	}
	if !IsMounted(entries, "/home/alice/.local/share/agbox/run/100/m0") {
		t.Errorf("expected m0 to be mounted")
	}
	if !IsMounted(entries, "/home/alice/dir with space/m1") {
		t.Errorf("expected octal-escaped mountpoint with spaces to be found")
	}
	if IsMounted(entries, "/nonexistent") || IsMounted(entries, "") {
		t.Errorf("unexpected mount match")
	}

	under100 := MountsUnder(entries, "/home/alice/.local/share/agbox/run/100")
	if len(under100) != 1 || under100[0] != "/home/alice/.local/share/agbox/run/100/m0" {
		t.Errorf("MountsUnder(/run/100) = %v", under100)
	}

	if _, err := readMountinfoFile(filepath.Join(t.TempDir(), "missing-mountinfo")); err == nil {
		t.Error("expected error reading missing mountinfo file")
	}
}

type fakeController struct {
	mounts        []Entry
	signals       []syscall.Signal
	signaledPIDs  []int
	unmountCalls  []bool
	unmountedMPs  []string
	keepStubborn  bool
	failPolite    bool
	listErr       error
	listErrOnCall int
	listCalls     int
}

func (f *fakeController) ListMounts() ([]Entry, error) {
	f.listCalls++
	if f.listErr != nil && (f.listErrOnCall == 0 || f.listCalls >= f.listErrOnCall) {
		return nil, f.listErr
	}
	return append([]Entry(nil), f.mounts...), nil
}

func (f *fakeController) SignalPID(pid int, sig syscall.Signal) error {
	f.signaledPIDs = append(f.signaledPIDs, pid)
	f.signals = append(f.signals, sig)
	return nil
}

func (f *fakeController) Unmount(mp string, lazy bool) error {
	f.unmountCalls = append(f.unmountCalls, lazy)
	f.unmountedMPs = append(f.unmountedMPs, mp)
	if f.keepStubborn {
		return nil
	}
	if f.failPolite && !lazy {
		return nil
	}
	var next []Entry
	for _, e := range f.mounts {
		if e.MountPoint != mp {
			next = append(next, e)
		}
	}
	f.mounts = next
	return nil
}

func (f *fakeController) Sleep(time.Duration) {}

func TestTeardownFilterDirPoliteAndLazy(t *testing.T) {
	// Include '[' and ']' in directory path to guard against filepath.Glob pattern bugs.
	runDir := filepath.Join(t.TempDir(), "run-[1]", "1234")
	mp := filepath.Join(runDir, "m0")
	if err := os.MkdirAll(mp, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(runDir, "m0.pid"), []byte("4321\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Subdirectory ending in .pid, invalid .pid, negative .pid, and symlinked .pid are ignored safely.
	if err := os.MkdirAll(filepath.Join(runDir, "sub.pid"), 0o700); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(runDir, "bad.pid"), []byte("not-a-pid\n"), 0o600)
	_ = os.WriteFile(filepath.Join(runDir, "neg.pid"), []byte("-9\n"), 0o600)
	_ = os.WriteFile(filepath.Join(runDir, "other.txt"), []byte("keep"), 0o600)
	outsidePID := filepath.Join(t.TempDir(), "outside.pid")
	_ = os.WriteFile(outsidePID, []byte("9999\n"), 0o600)
	_ = os.Symlink(outsidePID, filepath.Join(runDir, "sym.pid"))

	ctl := &fakeController{
		mounts:     []Entry{{MountPoint: mp, FSType: "fuse.agboxfilter"}},
		failPolite: true,
	}
	if err := TeardownFilterDir(runDir, ctl); err != nil {
		t.Fatalf("TeardownFilterDir failed: %v", err)
	}
	if _, err := os.Stat(runDir); !os.IsNotExist(err) {
		t.Errorf("expected runDir to be removed after unmount, err = %v", err)
	}
	if len(ctl.signals) < 2 || ctl.signals[0] != syscall.SIGTERM || ctl.signals[1] != syscall.SIGKILL {
		t.Errorf("expected SIGTERM then SIGKILL escalation, got %v", ctl.signals)
	}
	if slices.Contains(ctl.signaledPIDs, 9999) {
		t.Error("expected symlinked .pid file not to be signaled")
	}

	// TeardownFilterDir on nonexistent directory succeeds cleanly as a no-op.
	missingDir := filepath.Join(t.TempDir(), "nonexistent-run")
	if err := TeardownFilterDir(missingDir, &fakeController{}); err != nil {
		t.Errorf("expected TeardownFilterDir on nonexistent dir to succeed, got %v", err)
	}
}

func TestTeardownFilterDirRefusesRemoveWhenStillMountedAndSymlinkAncestors(t *testing.T) {
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	realRoot := filepath.Join(base, "real")
	symRoot := filepath.Join(base, "sym")
	if err := os.MkdirAll(realRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(realRoot, symRoot); err != nil {
		t.Fatal(err)
	}

	// Create run directory under realRoot, while caller passes path via symRoot ([H3]).
	realRunDir := filepath.Join(realRoot, "run", "5678")
	realMP := filepath.Join(realRunDir, "m0")
	if err := os.MkdirAll(realMP, 0o700); err != nil {
		t.Fatal(err)
	}
	canary := filepath.Join(realMP, "precious_host_file.txt")
	if err := os.WriteFile(canary, []byte("do-not-delete"), 0o600); err != nil {
		t.Fatal(err)
	}

	symRunDir := filepath.Join(symRoot, "run", "5678")
	// Kernel mountinfo records the canonical path realMP, while TeardownFilterDir receives symRunDir.
	ctl := &fakeController{
		mounts:       []Entry{{MountPoint: realMP, FSType: "fuse.agboxfilter"}},
		keepStubborn: true,
	}
	err = TeardownFilterDir(symRunDir, ctl)
	if err == nil || !strings.Contains(err.Error(), "refusing to remove") {
		t.Fatalf("expected refusal error when canonical mount stays active, got %v", err)
	}
	if _, err := os.Stat(canary); err != nil {
		t.Fatalf("canary file inside stubborn canonical mount was deleted: %v", err)
	}

	// Direct symlink target for UnmountFilterDir, TeardownFilterDir, and IsPathMounted is rejected.
	directSym := filepath.Join(base, "direct-sym")
	if err := os.Symlink(realRunDir, directSym); err != nil {
		t.Fatal(err)
	}
	if err := UnmountFilterDir(directSym, &fakeController{}); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Errorf("expected UnmountFilterDir to reject direct symlink, got %v", err)
	}
	if err := TeardownFilterDir(directSym, &fakeController{}); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Errorf("expected TeardownFilterDir to reject direct symlink, got %v", err)
	}
	if _, err := IsPathMounted(directSym); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Errorf("expected IsPathMounted to reject direct symlink, got %v", err)
	}
}

func TestUnmountFilterDirPreservesMetadataAndHandlesListMountErrors(t *testing.T) {
	sockBase, sErr := os.MkdirTemp("", "mtsock-")
	if sErr != nil {
		t.Fatal(sErr)
	}
	defer os.RemoveAll(sockBase)
	sockBase, _ = filepath.EvalSymlinks(sockBase)
	runDir := filepath.Join(sockBase, "f1")
	mp := filepath.Join(runDir, "m0")
	if err := os.MkdirAll(mp, 0o700); err != nil {
		t.Fatal(err)
	}
	pidPath := filepath.Join(runDir, "m0.pid")
	suspendedPath := filepath.Join(runDir, "suspended")
	if err := os.WriteFile(pidPath, []byte("4321\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(suspendedPath, []byte("{\"sandbox\":\"agbox-feat1\"}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	sockPath := filepath.Join(runDir, "ws.sock")
	ln, lErr := net.Listen("unix", sockPath)
	if lErr == nil {
		_ = ln.Close()
	}

	ctl := &fakeController{
		mounts: []Entry{{MountPoint: mp, FSType: "fuse.agboxfilter"}},
	}
	if err := UnmountFilterDir(runDir, ctl); err != nil {
		t.Fatalf("UnmountFilterDir failed: %v", err)
	}
	if _, err := os.Stat(pidPath); !os.IsNotExist(err) {
		t.Errorf("expected m0.pid to be deleted, err = %v", err)
	}
	if _, err := os.Stat(suspendedPath); err != nil {
		t.Errorf("expected suspended metadata to remain intact, err = %v", err)
	}

	// ListMounts initial error and final verification error propagate cleanly.
	errCtlInitial := &fakeController{listErr: errors.New("mountinfo read failed")}
	if err := UnmountFilterDir(runDir, errCtlInitial); err == nil {
		t.Error("expected UnmountFilterDir to fail when initial ListMounts fails")
	}
	errCtlFinal := &fakeController{
		mounts:        []Entry{{MountPoint: mp, FSType: "fuse.agboxfilter"}},
		listErr:       errors.New("final mountinfo read failed"),
		listErrOnCall: 3,
	}
	if err := UnmountFilterDir(runDir, errCtlFinal); err == nil {
		t.Error("expected UnmountFilterDir to fail when final ListMounts fails")
	}
}

func TestReverseOrderNestedUnmount(t *testing.T) {
	parent := "/run/test1/m0"
	child := "/run/test1/m0/nested"
	ctl := &fakeController{
		mounts: []Entry{
			{MountPoint: parent, FSType: "fuse.agboxfilter"},
			{MountPoint: child, FSType: "fuse.agboxfilter"},
		},
	}
	if err := UnmountFilterDir("/run/test1", ctl); err != nil {
		t.Fatalf("UnmountFilterDir failed: %v", err)
	}
	if len(ctl.unmountedMPs) != 2 {
		t.Fatalf("expected 2 unmount calls, got %d", len(ctl.unmountedMPs))
	}
	if ctl.unmountedMPs[0] != child || ctl.unmountedMPs[1] != parent {
		t.Errorf("expected reverse unmount order [%s, %s], got %v", child, parent, ctl.unmountedMPs)
	}
}

func TestMountsUnderRootAndEmpty(t *testing.T) {
	entries := []Entry{
		{MountPoint: "/", FSType: "rootfs"},
		{MountPoint: "/home", FSType: "ext4"},
		{MountPoint: "/home/user", FSType: "ext4"},
	}
	all := MountsUnder(entries, "/")
	if len(all) != 3 {
		t.Errorf("MountsUnder(entries, \"/\") = %v, want 3 entries", all)
	}
	none := MountsUnder(entries, "")
	if len(none) != 0 {
		t.Errorf("MountsUnder(entries, \"\") = %v, want empty", none)
	}
}

func TestIsFilterCmdlineAndOSControllerDI(t *testing.T) {
	validProdCases := [][]byte{
		[]byte("/usr/local/bin/agbox\x00__filter\x00-src\x00/a\x00-mnt\x00/b\x00"),
		[]byte("/home/alice/.local/bin/agbox\x00__filter"),
		[]byte("agbox\x00__filter"),
	}
	for _, raw := range validProdCases {
		if !IsFilterCmdline(raw) {
			t.Errorf("expected %q to match production __filter cmdline", string(raw))
		}
	}

	// Production IsFilterCmdline rejects *.test binaries, whereas allowTestBin=true accepts them.
	for _, testBinRaw := range [][]byte{
		[]byte("/tmp/mounttab.test\x00__filter\x00-mnt\x00/run/sbx1/ws"),
		[]byte("cli.test\x00__filter\x00"),
	} {
		if IsFilterCmdline(testBinRaw) {
			t.Errorf("expected production IsFilterCmdline to reject test binary %q", string(testBinRaw))
		}
		if !isFilterCmdline(testBinRaw, true) {
			t.Errorf("expected allowTestBin=true to accept %q", string(testBinRaw))
		}
	}

	invalidCases := [][]byte{
		nil,
		[]byte(""),
		[]byte("\x00"),
		[]byte("agbox"),
		[]byte("agbox\x00"),
		[]byte("agbox\x00run"),
		[]byte("agbox\x00__filter_extra"),
		[]byte("\x00__filter"),
		[]byte("/bin/bash\x00__filter"),
		[]byte("/usr/bin/python3\x00__filter"),
		[]byte("agbox \x00__filter"),
		[]byte("agbox\t\x00__filter"),
		[]byte("bad\x01cmd\x00__filter"),
		[]byte("/usr/bin/bash\x00-l\x00"),
		[]byte("/usr/local/bin/agbox\x00run\x00__filter\x00"),
	}
	for _, nonFilter := range invalidCases {
		if IsFilterCmdline(nonFilter) {
			t.Errorf("expected %q not to match __filter cmdline", string(nonFilter))
		}
	}

	// Verify [M8]: SignalPID / signalRecordedPIDs checks -mnt directory prefix in cmdline.
	runDir1 := filepath.Join(t.TempDir(), "run", "sbx1")
	if err := os.MkdirAll(runDir1, 0o700); err != nil {
		t.Fatal(err)
	}
	runDir1Real, _ := filepath.EvalSymlinks(runDir1)
	_ = os.WriteFile(filepath.Join(runDir1Real, "ws.pid"), []byte("101\n"), 0o600)
	_ = os.WriteFile(filepath.Join(runDir1Real, "other.pid"), []byte("202\n"), 0o600)

	var killed []int
	diCtl := OSController{
		AllowTestBinary: true,
		ReadCmdline: func(pid int) ([]byte, error) {
			switch pid {
			case 101:
				return []byte("/tmp/agbox.test\x00__filter\x00-hub\x00-mnt=" + filepath.Join(runDir1Real, "ws") + "\x00"), nil
			case 202:
				// PID reused by another sandbox's FUSE daemon!
				return []byte("/usr/local/bin/agbox\x00__filter\x00-hub\x00--mnt\x00/other/run/sbx2/ws\x00"), nil
			case 303:
				return nil, syscall.ESRCH
			default:
				return nil, os.ErrNotExist
			}
		},
		KillPID: func(pid int, _ syscall.Signal) error {
			killed = append(killed, pid)
			return nil
		},
	}
	if err := UnmountFilterDir(runDir1Real, diCtl); err != nil {
		t.Fatalf("UnmountFilterDir with DI OSController failed: %v", err)
	}
	if !slices.Equal(killed, []int{101}) {
		t.Errorf("killed PIDs = %v, want only [101] (PID 202 belongs to sbx2)", killed)
	}

	// Direct SignalPID edge cases: pid <= 0, ESRCH from ReadCmdline, ESRCH from KillPID, non-filter process.
	if err := diCtl.SignalPID(0, syscall.SIGTERM); err != nil {
		t.Errorf("SignalPID(0) = %v", err)
	}
	if err := diCtl.SignalPID(303, syscall.SIGTERM); err != nil {
		t.Errorf("SignalPID(ESRCH) = %v", err)
	}
	var osCtl OSController
	if err := osCtl.SignalPID(os.Getpid(), syscall.SIGTERM); err != nil {
		t.Fatalf("OSController.SignalPID on non-filter process returned error: %v", err)
	}
	osCtl.Sleep(1 * time.Millisecond)

	// Verify OSController.Unmount passes "--" before mountpoint, retries fusermount, falls back to syscall, and wraps stderr.
	var cmdInvocations [][]string
	unmountCtl := OSController{
		RunCommand: func(_ context.Context, name string, args ...string) ([]byte, error) {
			cmdInvocations = append(cmdInvocations, append([]string{name}, args...))
			if name == "fusermount" {
				return nil, nil
			}
			return []byte("fusermount3: busy"), errors.New("exit 1")
		},
	}
	if err := unmountCtl.Unmount("/run/sbx/-weird", false); err != nil {
		t.Fatalf("unmountCtl.Unmount failed: %v", err)
	}
	if len(cmdInvocations) != 2 || !slices.Equal(cmdInvocations[0], []string{"fusermount3", "-u", "--", "/run/sbx/-weird"}) {
		t.Errorf("unexpected unmount invocations: %v", cmdInvocations)
	}

	failAllCtl := OSController{
		RunCommand: func(_ context.Context, _ string, _ ...string) ([]byte, error) {
			return []byte("device or resource busy"), errors.New("exit 1")
		},
		UnmountSyscall: func(_ string, flags int) error {
			if flags != syscall.MNT_DETACH {
				t.Errorf("expected MNT_DETACH on lazy unmount, got %d", flags)
			}
			return syscall.EPERM
		},
	}
	if err := failAllCtl.Unmount("/run/sbx/m0", true); err == nil || !errors.Is(err, syscall.EPERM) || !strings.Contains(err.Error(), "device or resource busy") {
		t.Errorf("expected wrapped EPERM with fusermount detail, got %v", err)
	}

	// Unsafe relative, root, and empty paths must be rejected by both UnmountFilterDir and TeardownFilterDir.
	unsafeDirs := []string{"", ".", "..", "../..", "run/m0", "relative/path", "/"}
	for _, unsafeDir := range unsafeDirs {
		if err := UnmountFilterDir(unsafeDir, &fakeController{}); err == nil {
			t.Errorf("expected UnmountFilterDir(%q) to fail", unsafeDir)
		}
		if err := TeardownFilterDir(unsafeDir, &fakeController{}); err == nil {
			t.Errorf("expected TeardownFilterDir(%q) to fail", unsafeDir)
		}
	}
}

func TestReadCurrentAndHostMounts(t *testing.T) {
	var ctl OSController
	entries, err := ctl.ListMounts()
	if err != nil {
		t.Fatalf("ListMounts failed: %v", err)
	}
	if len(entries) == 0 {
		t.Fatal("expected ListMounts to return at least one mount entry")
	}

	mounted, err := IsPathMounted("/")
	if err != nil {
		t.Fatalf("IsPathMounted(\"/\") failed: %v", err)
	}
	if !mounted {
		t.Error("expected IsPathMounted(\"/\") to return true")
	}
	if mountedEmpty, err := IsPathMounted(""); err != nil || mountedEmpty {
		t.Errorf("IsPathMounted(\"\") = (%v, %v), want (false, nil)", mountedEmpty, err)
	}
}

func TestReadPIDFileNoFollowDoesNotBlockOnFIFO(t *testing.T) {
	base := t.TempDir()
	filterDir := filepath.Join(base, "run-fifo")
	if err := os.MkdirAll(filterDir, 0o700); err != nil {
		t.Fatal(err)
	}
	fifoPID := filepath.Join(filterDir, "ws.pid")
	if err := syscall.Mkfifo(fifoPID, 0o600); err != nil {
		t.Fatalf("Mkfifo: %v", err)
	}

	done := make(chan error, 1)
	go func() {
		done <- TeardownFilterDir(filterDir, &fakeController{})
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("TeardownFilterDir with FIFO pidfile failed: %v", err)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("TeardownFilterDir blocked on FIFO pidfile")
	}
	if _, err := os.Stat(filterDir); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("expected filterDir removed, stat err = %v", err)
	}
}
