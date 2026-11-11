package mounttab

import (
	"os"
	"path/filepath"
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
	}
	for _, tc := range cases {
		if got := UnescapeOctal(tc.in); got != tc.want {
			t.Errorf("UnescapeOctal(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestParseMountinfoAndQueries(t *testing.T) {
	sample := `
22 1 8:1 / / rw,relatime shared:1 - ext4 /dev/sda1 rw
89 22 0:45 / /home/alice/.local/share/agbox/run/100/m0 rw,nosuid,nodev - fuse.agboxfilter agboxfilter rw,user_id=1000,group_id=1000
90 22 0:46 / /home/alice/dir\040with\040space/m1 rw,nosuid - fuse.agboxfilter agboxfilter rw
91 22 0:47 / /home/alice/.local/share/agbox/run/1000/m0 rw - fuse.agboxfilter agboxfilter rw
malformed line without separator
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

	// Verify MountsUnder does not confuse /run/100 with /run/1000.
	under100 := MountsUnder(entries, "/home/alice/.local/share/agbox/run/100")
	if len(under100) != 1 || under100[0] != "/home/alice/.local/share/agbox/run/100/m0" {
		t.Errorf("MountsUnder(/run/100) = %v", under100)
	}
}

type fakeController struct {
	mounts       []Entry
	signals      []syscall.Signal
	unmountCalls []bool // lazy flag per call
	keepStubborn bool
	failPolite   bool
}

func (f *fakeController) ListMounts() ([]Entry, error) {
	return append([]Entry(nil), f.mounts...), nil
}

func (f *fakeController) SignalPID(_ int, sig syscall.Signal) error {
	f.signals = append(f.signals, sig)
	return nil
}

func (f *fakeController) Unmount(mp string, lazy bool) error {
	f.unmountCalls = append(f.unmountCalls, lazy)
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
	runDir := filepath.Join(t.TempDir(), "run", "1234")
	mp := filepath.Join(runDir, "m0")
	if err := os.MkdirAll(mp, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(runDir, "m0.pid"), []byte("4321\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	ctl := &fakeController{
		mounts:     []Entry{{MountPoint: mp, FSType: "fuse.agboxfilter"}},
		failPolite: true, // force escalation to SIGKILL + lazy unmount
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
}

func TestTeardownFilterDirRefusesRemoveWhenStillMounted(t *testing.T) {
	runDir := filepath.Join(t.TempDir(), "run", "5678")
	mp := filepath.Join(runDir, "m0")
	if err := os.MkdirAll(mp, 0o700); err != nil {
		t.Fatal(err)
	}
	canary := filepath.Join(mp, "precious_host_file.txt")
	if err := os.WriteFile(canary, []byte("do-not-delete"), 0o600); err != nil {
		t.Fatal(err)
	}

	ctl := &fakeController{
		mounts:       []Entry{{MountPoint: mp, FSType: "fuse.agboxfilter"}},
		keepStubborn: true, // mount never clears
	}
	err := TeardownFilterDir(runDir, ctl)
	if err == nil || !strings.Contains(err.Error(), "refusing to remove") {
		t.Fatalf("expected refusal error when mount stays active, got %v", err)
	}
	// Canary file inside the mount must still exist!
	if _, err := os.Stat(canary); err != nil {
		t.Fatalf("CRITICAL: canary file inside stubborn mount was deleted: %v", err)
	}
}
