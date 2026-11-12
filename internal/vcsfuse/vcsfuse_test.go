package vcsfuse

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"syscall"
	"testing"
)

func TestIsProtectedXattr(t *testing.T) {
	tests := []struct {
		attr string
		want bool
	}{
		{"security.capability", true},
		{"security.selinux", true},
		{"system.posix_acl_access", true},
		{"system.posix_acl_default", true},
		{"user.comment", false},
		{"trusted.overlay.opaque", false},
		{"", false},
	}

	for _, tc := range tests {
		if got := IsProtectedXattr(tc.attr); got != tc.want {
			t.Errorf("IsProtectedXattr(%q) = %v, want %v", tc.attr, got, tc.want)
		}
	}
}

func TestMountValidationErrors(t *testing.T) {
	if _, err := Mount("", "/tmp/mnt", nil); err == nil {
		t.Fatal("expected error for empty srcDir")
	}
	if _, err := Mount("/tmp/src", "", nil); err == nil {
		t.Fatal("expected error for empty mntDir")
	}
	if _, err := Mount("/nonexistent-agbox-src-dir", t.TempDir(), nil); err == nil {
		t.Fatal("expected error for nonexistent srcDir")
	}
}

func mountTestFS(t *testing.T) (srcDir, mntDir string) {
	t.Helper()
	if _, err := os.Stat("/dev/fuse"); err != nil {
		t.Skipf("/dev/fuse unavailable: %v", err)
	}

	base := t.TempDir()
	srcDir = filepath.Join(base, "src")
	mntDir = filepath.Join(base, "mnt")

	if err := os.MkdirAll(srcDir, 0o755); err != nil {
		t.Fatalf("mkdir src: %v", err)
	}
	if err := os.MkdirAll(mntDir, 0o755); err != nil {
		t.Fatalf("mkdir mnt: %v", err)
	}

	server, err := Mount(srcDir, mntDir, DefaultHiddenEntries)
	if err != nil {
		t.Skipf("FUSE mount not permitted in test environment: %v", err)
	}
	t.Cleanup(func() {
		_ = server.Unmount()
		server.Wait()
	})

	return srcDir, mntDir
}

func TestVCSHidingAndWriteProtection(t *testing.T) {
	srcDir, mntDir := mountTestFS(t)

	// Populate source directory with VCS metadata and regular files.
	for _, vcs := range DefaultHiddenEntries {
		vcsPath := filepath.Join(srcDir, vcs)
		if err := os.MkdirAll(vcsPath, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", vcs, err)
		}
		if err := os.WriteFile(filepath.Join(vcsPath, "config"), []byte("secret"), 0o600); err != nil {
			t.Fatalf("write %s/config: %v", vcs, err)
		}
	}
	if err := os.WriteFile(filepath.Join(srcDir, "main.go"), []byte("package main\n"), 0o644); err != nil {
		t.Fatalf("write main.go: %v", err)
	}
	subDir := filepath.Join(srcDir, "pkg")
	if err := os.MkdirAll(subDir, 0o755); err != nil {
		t.Fatalf("mkdir pkg: %v", err)
	}
	if err := os.WriteFile(filepath.Join(subDir, "lib.go"), []byte("package pkg\n"), 0o644); err != nil {
		t.Fatalf("write pkg/lib.go: %v", err)
	}

	// 1. ReadDir at root must only show visible entries ("main.go", "pkg").
	entries, err := os.ReadDir(mntDir)
	if err != nil {
		t.Fatalf("ReadDir(mntDir): %v", err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	slices.Sort(names)
	wantNames := []string{"main.go", "pkg"}
	if !slices.Equal(names, wantNames) {
		t.Fatalf("ReadDir names = %v, want %v", names, wantNames)
	}

	// 2. Direct lookup/stat of hidden entries at root must fail with ENOENT.
	for _, vcs := range DefaultHiddenEntries {
		_, err := os.Stat(filepath.Join(mntDir, vcs))
		if !errors.Is(err, syscall.ENOENT) {
			t.Errorf("Stat(%s) = %v, want ENOENT", vcs, err)
		}
		_, err = os.Stat(filepath.Join(mntDir, vcs, "config"))
		if !errors.Is(err, syscall.ENOENT) {
			t.Errorf("Stat(%s/config) = %v, want ENOENT", vcs, err)
		}
	}

	// 3. Creating, linking, symlinking, removing, or renaming onto a hidden VCS name must fail with EPERM/ENOENT.
	if err := os.Mkdir(filepath.Join(mntDir, ".git"), 0o755); !errors.Is(err, syscall.EPERM) {
		t.Errorf("Mkdir(.git) = %v, want EPERM", err)
	}
	if err := os.WriteFile(filepath.Join(mntDir, ".jj"), []byte("x"), 0o644); !errors.Is(err, syscall.EPERM) {
		t.Errorf("WriteFile(.jj) = %v, want EPERM", err)
	}
	if err := syscall.Mknod(filepath.Join(mntDir, ".bzr"), syscall.S_IFIFO|0o600, 0); !errors.Is(err, syscall.EPERM) {
		t.Errorf("Mknod(.bzr) = %v, want EPERM", err)
	}
	if err := os.Symlink("main.go", filepath.Join(mntDir, ".svn")); !errors.Is(err, syscall.EPERM) {
		t.Errorf("Symlink(.svn) = %v, want EPERM", err)
	}
	if err := os.Link(filepath.Join(mntDir, "main.go"), filepath.Join(mntDir, ".hg")); !errors.Is(err, syscall.EPERM) {
		t.Errorf("Link(.hg) = %v, want EPERM", err)
	}
	if err := syscall.Rmdir(filepath.Join(mntDir, ".git")); !errors.Is(err, syscall.ENOENT) && !errors.Is(err, syscall.EPERM) {
		t.Errorf("Rmdir(.git) = %v, want ENOENT or EPERM", err)
	}
	if err := syscall.Unlink(filepath.Join(mntDir, ".git")); !errors.Is(err, syscall.ENOENT) && !errors.Is(err, syscall.EPERM) {
		t.Errorf("Unlink(.git) = %v, want ENOENT or EPERM", err)
	}
	// Rename from root onto .git
	if err := os.Rename(filepath.Join(mntDir, "main.go"), filepath.Join(mntDir, ".git")); !errors.Is(err, syscall.EPERM) {
		t.Errorf("Rename(main.go -> .git) = %v, want EPERM", err)
	}
	// Rename from subdirectory onto root .git
	if err := os.Rename(filepath.Join(mntDir, "pkg", "lib.go"), filepath.Join(mntDir, ".git")); !errors.Is(err, syscall.EPERM) {
		t.Errorf("Rename(pkg/lib.go -> .git) = %v, want EPERM", err)
	}
	// Nested .git inside a subdirectory must also be blocked.
	if err := os.Mkdir(filepath.Join(mntDir, "pkg", ".git"), 0o755); !errors.Is(err, syscall.EPERM) {
		t.Errorf("Mkdir(pkg/.git) = %v, want EPERM", err)
	}

	// 4. Normal file creation and modification in root and subdirectories must succeed.
	newFile := filepath.Join(mntDir, "added.txt")
	if err := os.WriteFile(newFile, []byte("hello"), 0o644); err != nil {
		t.Fatalf("WriteFile(added.txt): %v", err)
	}
	raw, err := os.ReadFile(filepath.Join(srcDir, "added.txt"))
	if err != nil || string(raw) != "hello" {
		t.Fatalf("host file added.txt content = %q (err=%v), want %q", string(raw), err, "hello")
	}

	// Host .git/config must remain completely intact.
	gitCfg, err := os.ReadFile(filepath.Join(srcDir, ".git", "config"))
	if err != nil || string(gitCfg) != "secret" {
		t.Fatalf("host .git/config = %q (err=%v), want %q", string(gitCfg), err, "secret")
	}
}

func TestDirectoryFDLifecycleAndSeekdir(t *testing.T) {
	srcDir, mntDir := mountTestFS(t)

	if err := os.WriteFile(filepath.Join(srcDir, "a.txt"), []byte("a"), 0o644); err != nil {
		t.Fatalf("write a.txt: %v", err)
	}
	if err := os.WriteFile(filepath.Join(srcDir, "b.txt"), []byte("b"), 0o644); err != nil {
		t.Fatalf("write b.txt: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(srcDir, ".git"), 0o755); err != nil {
		t.Fatalf("mkdir .git: %v", err)
	}

	countOpenFDs := func() int {
		fds, err := os.ReadDir("/proc/self/fd")
		if err != nil {
			t.Fatalf("ReadDir(/proc/self/fd): %v", err)
		}
		return len(fds)
	}

	// Warm up a single ReadDir, then measure FD count across 60 iterations to
	// verify Releasedir is properly forwarded and no host directory FDs leak.
	if _, err := os.ReadDir(mntDir); err != nil {
		t.Fatalf("warmup ReadDir: %v", err)
	}
	beforeFDs := countOpenFDs()
	for range 60 {
		list, err := os.ReadDir(mntDir)
		if err != nil {
			t.Fatalf("ReadDir iteration: %v", err)
		}
		if len(list) != 2 {
			t.Fatalf("ReadDir count = %d, want 2", len(list))
		}
	}
	afterFDs := countOpenFDs()
	// Allow a small variance of +/- 2 FDs for runtime background activity,
	// whereas a leak of 60 FDs would increase afterFDs by ~60.
	if afterFDs > beforeFDs+3 {
		t.Fatalf("detected FD leak: open FDs grew from %d to %d after 60 ReadDir calls", beforeFDs, afterFDs)
	}

	// Verify Seekdir (rewinddir via Seek(0, io.SeekStart)) on an open directory handle.
	dirFile, err := os.Open(mntDir)
	if err != nil {
		t.Fatalf("Open(mntDir): %v", err)
	}
	defer dirFile.Close()

	firstPass, err := dirFile.Readdirnames(-1)
	if err != nil {
		t.Fatalf("first Readdirnames: %v", err)
	}
	if len(firstPass) != 2 {
		t.Fatalf("firstPass = %v, want 2 entries", firstPass)
	}

	if _, err := dirFile.Seek(0, io.SeekStart); err != nil {
		t.Fatalf("Seek(0, SeekStart) on directory failed: %v", err)
	}

	secondPass, err := dirFile.Readdirnames(-1)
	if err != nil {
		t.Fatalf("second Readdirnames after Seek(0): %v", err)
	}
	slices.Sort(firstPass)
	slices.Sort(secondPass)
	if !slices.Equal(firstPass, secondPass) {
		t.Fatalf("secondPass after rewind = %v, want %v", secondPass, firstPass)
	}
}

func TestXattrBlockingOnRootAndSubdirs(t *testing.T) {
	srcDir, mntDir := mountTestFS(t)

	if err := os.MkdirAll(filepath.Join(srcDir, "sub"), 0o755); err != nil {
		t.Fatalf("mkdir sub: %v", err)
	}
	subFile := filepath.Join(mntDir, "sub", "file.txt")
	if err := os.WriteFile(subFile, []byte("data"), 0o644); err != nil {
		t.Fatalf("write sub/file.txt: %v", err)
	}

	// Verify direct FilteredNode handler enforcement for all protected prefixes.
	fn := &FilteredNode{}
	for _, attr := range []string{"security.capability", "security.selinux", "system.posix_acl_access", "system.posix_acl_default"} {
		if errno := fn.Setxattr(context.Background(), attr, []byte("val"), 0); errno != syscall.EPERM {
			t.Errorf("FilteredNode.Setxattr(%q) = %v, want EPERM", attr, errno)
		}
		if errno := fn.Removexattr(context.Background(), attr); errno != syscall.EPERM {
			t.Errorf("FilteredNode.Removexattr(%q) = %v, want EPERM", attr, errno)
		}
	}

	// Verify end-to-end through the mounted FUSE filesystem.
	// The Linux VFS pre-validates binary structs for security.capability and
	// system.posix_acl_* on setxattr, whereas security.custom and removexattr
	// reach our FUSE handler directly and must return EPERM.
	if err := syscall.Setxattr(subFile, "security.custom", []byte("val"), 0); !errors.Is(err, syscall.EPERM) {
		t.Errorf("Setxattr(security.custom) on child file = %v, want EPERM", err)
	}
	if err := syscall.Setxattr(mntDir, "security.custom", []byte("val"), 0); !errors.Is(err, syscall.EPERM) {
		t.Errorf("Setxattr(security.custom) on root dir = %v, want EPERM", err)
	}
	for _, attr := range []string{"security.capability", "security.custom", "system.posix_acl_access"} {
		if err := syscall.Removexattr(subFile, attr); !errors.Is(err, syscall.EPERM) {
			t.Errorf("Removexattr(%q) on child file = %v, want EPERM", attr, err)
		}
		if err := syscall.Removexattr(mntDir, attr); !errors.Is(err, syscall.EPERM) {
			t.Errorf("Removexattr(%q) on root dir = %v, want EPERM", attr, err)
		}
	}
}

func TestUnmountAndClean(t *testing.T) {
	if _, err := os.Stat("/dev/fuse"); err != nil {
		t.Skipf("/dev/fuse unavailable: %v", err)
	}

	base := t.TempDir()
	srcDir := filepath.Join(base, "src")
	filterRoot := filepath.Join(base, "filters")
	mntDir := filepath.Join(filterRoot, "0")

	if err := os.MkdirAll(srcDir, 0o755); err != nil {
		t.Fatalf("mkdir src: %v", err)
	}
	if err := os.MkdirAll(mntDir, 0o755); err != nil {
		t.Fatalf("mkdir mnt: %v", err)
	}

	server, err := Mount(srcDir, mntDir, DefaultHiddenEntries)
	if err != nil {
		t.Skipf("FUSE mount not permitted: %v", err)
	}
	defer func() {
		_ = server.Unmount()
	}()

	if err := UnmountAndClean(filterRoot); err != nil {
		t.Fatalf("UnmountAndClean(%q): %v", filterRoot, err)
	}
	server.Wait()

	if _, err := os.Stat(filterRoot); !os.IsNotExist(err) {
		t.Fatalf("expected filterRoot %q to be removed, stat err = %v", filterRoot, err)
	}
}

func TestRunMainValidationAndStartSubprocess(t *testing.T) {
	if rc := RunMain([]string{"-invalid-flag"}); rc != 2 {
		t.Errorf("RunMain(-invalid-flag) = %d, want 2", rc)
	}
	if rc := RunMain(nil); rc != 2 {
		t.Errorf("RunMain(nil) = %d, want 2", rc)
	}
	if rc := RunMain([]string{"-src", "/nonexistent-agbox-src", "-mnt", t.TempDir()}); rc != 1 {
		t.Errorf("RunMain(nonexistent) = %d, want 1", rc)
	}

	// Test StartSubprocess failure when binary exits immediately.
	base := t.TempDir()
	pidFile := filepath.Join(base, "m0.pid")
	if _, err := StartSubprocess("/bin/false", base, filepath.Join(base, "m0"), pidFile, true); err == nil {
		t.Error("expected error when filter subprocess exits before mounting")
	}
}
