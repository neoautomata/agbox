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

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"
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
		{"trusted.overlay.opaque", true},
		{"user.", true},
		{"", true},
		{"user.comment", false},
		{"user.agbox.tag", false},
	}

	for _, tc := range tests {
		if got := IsProtectedXattr(tc.attr); got != tc.want {
			t.Errorf("IsProtectedXattr(%q) = %v, want %v", tc.attr, got, tc.want)
		}
	}
}

func TestValidateSymlinkTarget(t *testing.T) {
	hidden := buildHiddenSet(DefaultHiddenEntries)
	cases := []struct {
		parent string
		name   string
		target string
		want   syscall.Errno
	}{
		{"", "link.go", "main.go", 0},
		{"", "link_sub", "pkg/lib.go", 0},
		{"pkg", "up_ok", "../main.go", 0},
		{"pkg/deep", "up2_ok", "../../main.go", 0},
		{"", "github_ok", ".github/workflows/ci.yml", 0},
		{"", "abs_bad", "/etc/passwd", syscall.EPERM},
		{"", "escape_root", "../secret.txt", syscall.EPERM},
		{"pkg", "escape_sub", "../../secret.txt", syscall.EPERM},
		{"", "git_target", ".git/config", syscall.EPERM},
		{"pkg", "jj_upper", "../.JJ/repo", syscall.EPERM},
		{"", "gitignore_target", ".gitignore", syscall.EPERM},
		{"", ".git", "main.go", syscall.EPERM},
		{"", ".GITIGNORE", "main.go", syscall.EPERM},
		{"", "empty_target", "", syscall.EINVAL},
		{"", "nul_target", "a\x00b", syscall.EINVAL},
		{"", "../badname", "main.go", syscall.EINVAL},
	}
	for _, tc := range cases {
		if got := ValidateSymlinkTarget(tc.parent, tc.name, tc.target, hidden); got != tc.want {
			t.Errorf("ValidateSymlinkTarget(%q, %q, %q) = %v, want %v", tc.parent, tc.name, tc.target, got, tc.want)
		}
	}
}

func newTestFilteredRoot(t *testing.T) (srcDir string, root *FilteredNode) {
	t.Helper()
	srcDir = filepath.Join(t.TempDir(), "share")
	if err := os.MkdirAll(srcDir, 0o755); err != nil {
		t.Fatal(err)
	}
	pr, st, err := newPinnedRoot(srcDir)
	if err != nil {
		t.Fatalf("newPinnedRoot: %v", err)
	}
	t.Cleanup(pr.Close)

	hidden := buildHiddenSet(DefaultHiddenEntries)
	rootData := &fs.LoopbackRoot{
		Path: srcDir,
		Dev:  uint64(st.Dev),
	}
	root = &FilteredNode{
		LoopbackNode: &fs.LoopbackNode{RootData: rootData},
		root:         pr,
		hidden:       hidden,
		isRoot:       true,
	}
	rootData.RootNode = root
	_ = fs.NewNodeFS(root, &fs.Options{})
	return srcDir, root
}

func TestFilteredNodeKernelSyscallsAndSecurityBoundaries(t *testing.T) {
	ctx := context.Background()
	outsideDir := t.TempDir()
	outsideFile := filepath.Join(outsideDir, "host-secret.txt")
	if err := os.WriteFile(outsideFile, []byte("DO-NOT-TOUCH"), 0o600); err != nil {
		t.Fatal(err)
	}

	srcDir, root := newTestFilteredRoot(t)

	// Seed VCS directories/files (including uppercase .GIT), .github, regular files, and host symlinks.
	for _, dir := range []string{".git", ".GIT", ".jj", ".github", "pkg"} {
		if err := os.MkdirAll(filepath.Join(srcDir, dir), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(srcDir, ".git", "config"), []byte("git-secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(srcDir, ".gitignore"), []byte("*.key\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(srcDir, ".gitmodules"), []byte("[submodule]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(srcDir, "main.go"), []byte("package main\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outsideFile, filepath.Join(srcDir, "escape_link")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(".git/config", filepath.Join(srcDir, "vcs_link")); err != nil {
		t.Fatal(err)
	}

	// 1. Readdir hides .git, .GIT, .jj, .gitignore, .gitmodules while keeping .github, main.go, pkg, and symlinks.
	stream, errno := root.Readdir(ctx)
	if errno != 0 {
		t.Fatalf("Readdir: %v", errno)
	}
	var gotNames []string
	for stream.HasNext() {
		de, dErrno := stream.Next()
		if dErrno != 0 {
			t.Fatalf("stream.Next: %v", dErrno)
		}
		if de.Name == "." || de.Name == ".." {
			continue
		}
		gotNames = append(gotNames, de.Name)
	}
	stream.Close()
	slices.Sort(gotNames)
	wantNames := []string{".github", "escape_link", "main.go", "pkg", "vcs_link"}
	if !slices.Equal(gotNames, wantNames) {
		t.Fatalf("Readdir names = %v, want %v", gotNames, wantNames)
	}

	// 2. Lookup blocks all VCS entries case-insensitively with ENOENT, while allowing .github.
	for _, hiddenName := range []string{".git", ".GIT", ".jj", ".JJ", ".gitignore", ".GITIGNORE", ".gitmodules"} {
		var out fuse.EntryOut
		if _, lErrno := root.Lookup(ctx, hiddenName, &out); lErrno != syscall.ENOENT {
			t.Errorf("Lookup(%q) = %v, want ENOENT", hiddenName, lErrno)
		}
	}
	var ghOut fuse.EntryOut
	if _, lErrno := root.Lookup(ctx, ".github", &ghOut); lErrno != 0 {
		t.Fatalf("Lookup(.github) failed: %v", lErrno)
	}

	// 3. Write operations onto VCS names fail with EPERM.
	var entryOut fuse.EntryOut
	if _, _, _, cErrno := root.Create(ctx, ".gitignore", syscall.O_CREAT|syscall.O_WRONLY, 0o644, &entryOut); cErrno != syscall.EPERM {
		t.Errorf("Create(.gitignore) = %v, want EPERM", cErrno)
	}
	if _, mErrno := root.Mkdir(ctx, ".GIT", 0o755, &entryOut); mErrno != syscall.EPERM {
		t.Errorf("Mkdir(.GIT) = %v, want EPERM", mErrno)
	}
	if rErrno := root.Unlink(ctx, ".gitignore"); rErrno != syscall.EPERM {
		t.Errorf("Unlink(.gitignore) = %v, want EPERM", rErrno)
	}
	if rErrno := root.Rmdir(ctx, ".git"); rErrno != syscall.EPERM {
		t.Errorf("Rmdir(.git) = %v, want EPERM", rErrno)
	}

	// 4. Pre-existing unsafe host symlinks cannot be read, overwritten via Create, or chmod/truncated via Setattr.
	escapeIno, lErrno := root.Lookup(ctx, "escape_link", &entryOut)
	if lErrno != 0 {
		t.Fatalf("Lookup(escape_link): %v", lErrno)
	}
	// Verify an unattached/unlinked child node fails closed with ENOENT before attachment.
	if _, rlErrno := escapeIno.Operations().(*FilteredNode).Readlink(ctx); rlErrno != syscall.ENOENT {
		t.Errorf("unattached child Readlink = %v, want ENOENT", rlErrno)
	}
	root.AddChild("escape_link", escapeIno, true)
	escapeNode := escapeIno.Operations().(*FilteredNode)
	if _, rlErrno := escapeNode.Readlink(ctx); rlErrno != syscall.EPERM {
		t.Errorf("Readlink(escape_link) = %v, want EPERM", rlErrno)
	}
	vcsLinkIno, lErrno := root.Lookup(ctx, "vcs_link", &entryOut)
	if lErrno != 0 {
		t.Fatalf("Lookup(vcs_link): %v", lErrno)
	}
	root.AddChild("vcs_link", vcsLinkIno, true)
	if _, rlErrno := vcsLinkIno.Operations().(*FilteredNode).Readlink(ctx); rlErrno != syscall.EPERM {
		t.Errorf("Readlink(vcs_link) = %v, want EPERM", rlErrno)
	}
	if _, _, _, cErrno := root.Create(ctx, "escape_link", syscall.O_WRONLY|syscall.O_TRUNC, 0o644, &entryOut); cErrno == 0 {
		t.Fatal("Create(escape_link) unexpectedly succeeded and followed symlink")
	}
	var attrOut fuse.AttrOut
	setIn := fuse.SetAttrIn{}
	setIn.Valid = fuse.FATTR_MODE | fuse.FATTR_SIZE
	setIn.Mode = 0o777
	setIn.Size = 0
	if sErrno := escapeNode.Setattr(ctx, nil, &setIn, &attrOut); sErrno == 0 {
		t.Fatal("Setattr on symlink unexpectedly succeeded")
	}
	// Verify outsideFile content and mode were untouched.
	outsideBytes, err := os.ReadFile(outsideFile)
	if err != nil || string(outsideBytes) != "DO-NOT-TOUCH" {
		t.Fatalf("outside host file modified: %q (%v)", string(outsideBytes), err)
	}

	// 5. Symlink allows safe relative intra-share links and rejects unsafe targets.
	safeIno, sErrno := root.Symlink(ctx, "main.go", "safe_link", &entryOut)
	if sErrno != 0 {
		t.Fatalf("Symlink(safe_link -> main.go) failed: %v", sErrno)
	}
	root.AddChild("safe_link", safeIno, true)
	if target, rlErrno := safeIno.Operations().(*FilteredNode).Readlink(ctx); rlErrno != 0 || string(target) != "main.go" {
		t.Errorf("Readlink(safe_link) = (%q, %v), want (main.go, 0)", string(target), rlErrno)
	}
	for _, badTarget := range []string{"/etc/passwd", "../outside", ".git/config", ".gitignore"} {
		if _, bErrno := root.Symlink(ctx, badTarget, "bad_sym", &entryOut); bErrno != syscall.EPERM {
			t.Errorf("Symlink(target=%q) = %v, want EPERM", badTarget, bErrno)
		}
	}

	// 6. Mknod blocks FIFOs and device nodes with EPERM, and allows regular files while stripping setuid/setgid.
	for _, badMode := range []uint32{
		syscall.S_IFIFO | 0o600,
		syscall.S_IFSOCK | 0o600,
		syscall.S_IFCHR | 0o600,
		syscall.S_IFBLK | 0o600,
	} {
		if _, mkErrno := root.Mknod(ctx, "special", badMode, 0, &entryOut); mkErrno != syscall.EPERM {
			t.Errorf("Mknod(mode=%#o) = %v, want EPERM", badMode, mkErrno)
		}
	}
	if _, mkErrno := root.Mknod(ctx, "mknod_reg.txt", syscall.S_IFREG|syscall.S_ISUID|syscall.S_ISGID|0o644, 0, &entryOut); mkErrno != 0 {
		t.Fatalf("Mknod(S_IFREG) failed: %v", mkErrno)
	}
	stReg, err := os.Lstat(filepath.Join(srcDir, "mknod_reg.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if stReg.Mode()&(os.ModeSetuid|os.ModeSetgid) != 0 {
		t.Errorf("expected setuid/setgid bits to be stripped on Mknod, got mode %v", stReg.Mode())
	}

	// 7. Create strips setuid/setgid, wraps handle in safeFile (no PassthroughFd or Ioctl),
	// rejects setuid/chown in Setattr, and supports chmod on mode 0000 regular files.
	createdIno, fh, _, cErrno := root.Create(ctx, "created.txt", syscall.O_CREAT|syscall.O_RDWR, syscall.S_ISUID|syscall.S_ISGID|0o600, &entryOut)
	if cErrno != 0 {
		t.Fatalf("Create(created.txt): %v", cErrno)
	}
	if _, ok := fh.(fs.FilePassthroughFder); ok {
		t.Error("safeFile must not expose FilePassthroughFder")
	}
	if _, ok := fh.(fs.FileIoctler); ok {
		t.Error("safeFile must not expose FileIoctler")
	}
	if relCaller, ok := fh.(fs.FileReleaser); ok {
		_ = relCaller.Release(ctx)
	}
	root.AddChild("created.txt", createdIno, true)
	createdNode := createdIno.Operations().(*FilteredNode)

	// Setattr with setuid must fail with EPERM.
	suidIn := fuse.SetAttrIn{}
	suidIn.Valid = fuse.FATTR_MODE
	suidIn.Mode = syscall.S_ISUID | 0o755
	if errNo := createdNode.Setattr(ctx, nil, &suidIn, &attrOut); errNo != syscall.EPERM {
		t.Errorf("Setattr(S_ISUID) = %v, want EPERM", errNo)
	}
	// Setattr with cross-UID chown must fail with EPERM.
	chownIn := fuse.SetAttrIn{}
	chownIn.Valid = fuse.FATTR_UID
	chownIn.Uid = uint32(os.Geteuid() + 1)
	if errNo := createdNode.Setattr(ctx, nil, &chownIn, &attrOut); errNo != syscall.EPERM {
		t.Errorf("Setattr(cross-UID) = %v, want EPERM", errNo)
	}
	// Chmod to 0000 and back to 0644 on a regular file must succeed via /proc/self/fd/<fd>.
	zeroIn := fuse.SetAttrIn{}
	zeroIn.Valid = fuse.FATTR_MODE
	zeroIn.Mode = 0
	if errNo := createdNode.Setattr(ctx, nil, &zeroIn, &attrOut); errNo != 0 {
		t.Fatalf("Setattr(0000) failed: %v", errNo)
	}
	restoreIn := fuse.SetAttrIn{}
	restoreIn.Valid = fuse.FATTR_MODE
	restoreIn.Mode = 0o644
	if errNo := createdNode.Setattr(ctx, nil, &restoreIn, &attrOut); errNo != 0 {
		t.Fatalf("Setattr(0644 on 0000 file) failed: %v", errNo)
	}

	// 8. Non-user xattrs fail with EPERM on Setxattr, Getxattr, and Removexattr.
	for _, blockedAttr := range []string{"security.capability", "system.posix_acl_access", "trusted.overlay.opaque", "user."} {
		if xErrno := createdNode.Setxattr(ctx, blockedAttr, []byte("v"), 0); xErrno != syscall.EPERM {
			t.Errorf("Setxattr(%q) = %v, want EPERM", blockedAttr, xErrno)
		}
		if xErrno := createdNode.Removexattr(ctx, blockedAttr); xErrno != syscall.EPERM {
			t.Errorf("Removexattr(%q) = %v, want EPERM", blockedAttr, xErrno)
		}
		if _, xErrno := createdNode.Getxattr(ctx, blockedAttr, make([]byte, 16)); xErrno != syscall.ENODATA {
			t.Errorf("Getxattr(%q) = %v, want ENODATA", blockedAttr, xErrno)
		}
	}

	// 9. Exhaustive check across all 22 DefaultHiddenEntries, OpendirHandle, Open/Link/Rename escapes, FIFOs, and safeFile.Setattr.
	pkgIno, lErrno := root.Lookup(ctx, "pkg", &entryOut)
	if lErrno != 0 {
		t.Fatalf("Lookup(pkg): %v", lErrno)
	}
	root.AddChild("pkg", pkgIno, true)
	pkgNode := pkgIno.Operations().(*FilteredNode)

	mainIno, lErrno := root.Lookup(ctx, "main.go", &entryOut)
	if lErrno != 0 {
		t.Fatalf("Lookup(main.go): %v", lErrno)
	}
	root.AddChild("main.go", mainIno, true)
	mainNode := mainIno.Operations().(*FilteredNode)

	for _, vcsName := range DefaultHiddenEntries {
		for _, cand := range []string{vcsName, filepath.Base(vcsName)} {
			if _, errNo := root.Lookup(ctx, cand, &entryOut); errNo != syscall.ENOENT {
				t.Errorf("Lookup(%q) = %v, want ENOENT", cand, errNo)
			}
			if _, _, _, errNo := pkgNode.Create(ctx, cand, syscall.O_CREAT|syscall.O_WRONLY, 0o644, &entryOut); errNo != syscall.EPERM {
				t.Errorf("nested Create(%q) = %v, want EPERM", cand, errNo)
			}
			if _, errNo := pkgNode.Mkdir(ctx, cand, 0o755, &entryOut); errNo != syscall.EPERM {
				t.Errorf("nested Mkdir(%q) = %v, want EPERM", cand, errNo)
			}
			if _, errNo := pkgNode.Link(ctx, mainNode, cand, &entryOut); errNo != syscall.EPERM {
				t.Errorf("nested Link(%q) = %v, want EPERM", cand, errNo)
			}
			if errNo := root.Rename(ctx, "main.go", pkgNode, cand, 0); errNo != syscall.EPERM {
				t.Errorf("Rename(main.go -> pkg/%s) = %v, want EPERM", cand, errNo)
			}
			if errNo := root.Rename(ctx, cand, pkgNode, "stolen", 0); errNo != syscall.EPERM {
				t.Errorf("Rename(%s -> pkg/stolen) = %v, want EPERM", cand, errNo)
			}
		}
	}

	// OpendirHandle must omit hidden entries and hide FilePassthroughFder and FileIoctler.
	dirFH, _, odErrno := root.OpendirHandle(ctx, 0)
	if odErrno != 0 {
		t.Fatalf("OpendirHandle: %v", odErrno)
	}
	if _, ok := dirFH.(fs.FilePassthroughFder); ok {
		t.Error("filteredDir must not expose FilePassthroughFder")
	}
	if _, ok := dirFH.(fs.FileIoctler); ok {
		t.Error("filteredDir must not expose FileIoctler")
	}
	if rde, ok := dirFH.(fs.FileReaddirenter); ok {
		for {
			de, rErrno := rde.Readdirent(ctx)
			if rErrno != 0 {
				t.Fatalf("Readdirent: %v", rErrno)
			}
			if de == nil {
				break
			}
			if isHiddenEntry(de.Name, root.hidden) {
				t.Errorf("OpendirHandle leaked hidden VCS entry %q", de.Name)
			}
		}
	}
	if relDir, ok := dirFH.(fs.FileReleasedirer); ok {
		relDir.Releasedir(ctx, 0)
	}

	// Open on pre-existing host symlink and pre-existing host FIFO must fail.
	if _, _, oErrno := escapeNode.Open(ctx, syscall.O_RDONLY); oErrno == 0 {
		t.Error("Open(escape_link) unexpectedly succeeded")
	}
	if err := os.Symlink(outsideDir, filepath.Join(srcDir, "escape_dir")); err != nil {
		t.Fatal(err)
	}
	escDirIno, lErrno := root.Lookup(ctx, "escape_dir", &entryOut)
	if lErrno != 0 {
		t.Fatalf("Lookup(escape_dir): %v", lErrno)
	}
	root.AddChild("escape_dir", escDirIno, true)
	if _, travErrno := escDirIno.Operations().(*FilteredNode).Lookup(ctx, "host-secret.txt", &entryOut); travErrno == 0 {
		t.Fatal("Lookup through symlinked host directory unexpectedly succeeded")
	}

	// Link on a symlink must fail with EPERM, and cross-root Link/Rename must fail with EXDEV.
	if _, lkErrno := root.Link(ctx, escapeNode, "hardlinked_sym", &entryOut); lkErrno != syscall.EPERM {
		t.Errorf("Link(escape_link) = %v, want EPERM", lkErrno)
	}
	_, otherRoot := newTestFilteredRoot(t)
	if _, lkErrno := otherRoot.Link(ctx, mainNode, "cross_link", &entryOut); lkErrno != syscall.EXDEV {
		t.Errorf("cross-root Link = %v, want EXDEV", lkErrno)
	}
	if rnErrno := root.Rename(ctx, "main.go", otherRoot, "cross_rename", 0); rnErrno != syscall.EXDEV {
		t.Errorf("cross-root Rename = %v, want EXDEV", rnErrno)
	}

	// Pre-existing host FIFO cannot be opened through FilteredNode.Open.
	hostFIFO := filepath.Join(srcDir, "host.fifo")
	if err := syscall.Mkfifo(hostFIFO, 0o600); err == nil {
		fifoIno, fErrno := root.Lookup(ctx, "host.fifo", &entryOut)
		if fErrno != 0 {
			t.Fatalf("Lookup(host.fifo): %v", fErrno)
		}
		root.AddChild("host.fifo", fifoIno, true)
		if _, _, openErr := fifoIno.Operations().(*FilteredNode).Open(ctx, syscall.O_RDONLY|syscall.O_NONBLOCK); openErr != syscall.EPERM {
			t.Errorf("Open(host.fifo) = %v, want EPERM", openErr)
		}
	}

	// Mkdir strips S_ISUID and S_ISGID, and open-handle safeFile.Setattr blocks S_ISUID and cross-UID chown.
	if _, mkErrno := root.Mkdir(ctx, "suid_dir", syscall.S_ISUID|syscall.S_ISGID|0o755, &entryOut); mkErrno != 0 {
		t.Fatalf("Mkdir(suid_dir): %v", mkErrno)
	}
	stDir, err := os.Lstat(filepath.Join(srcDir, "suid_dir"))
	if err != nil {
		t.Fatal(err)
	}
	if stDir.Mode()&(os.ModeSetuid|os.ModeSetgid) != 0 {
		t.Errorf("expected Mkdir to strip setuid/setgid, got %v", stDir.Mode())
	}

	openFH, _, oErrno := createdNode.Open(ctx, syscall.O_RDWR)
	if oErrno != 0 {
		t.Fatalf("Open(created.txt): %v", oErrno)
	}
	sfAttr := openFH.(fs.FileSetattrer)
	if errNo := sfAttr.Setattr(ctx, &suidIn, &attrOut); errNo != syscall.EPERM {
		t.Errorf("safeFile.Setattr(S_ISUID) = %v, want EPERM", errNo)
	}
	if errNo := sfAttr.Setattr(ctx, &chownIn, &attrOut); errNo != syscall.EPERM {
		t.Errorf("safeFile.Setattr(cross-UID) = %v, want EPERM", errNo)
	}
	if relCaller, ok := openFH.(fs.FileReleaser); ok {
		_ = relCaller.Release(ctx)
	}

	// Symlink nodes reject xattr operations and return 0 bytes for Listxattr.
	safeNode := safeIno.Operations().(*FilteredNode)
	if xErr := safeNode.Setxattr(ctx, "user.tag", []byte("1"), 0); xErr != syscall.EPERM {
		t.Errorf("Setxattr on symlink = %v, want EPERM", xErr)
	}
	if sz, xErr := safeNode.Listxattr(ctx, nil); xErr != 0 || sz != 0 {
		t.Errorf("Listxattr on symlink = (%d, %v), want (0, 0)", sz, xErr)
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

	// Test StartSubprocess failure when binary exits immediately or mountpoint is a symlink.
	base := t.TempDir()
	pidFile := filepath.Join(base, "m0.pid")
	if _, err := StartSubprocess("/bin/false", base, filepath.Join(base, "m0"), pidFile, true); err == nil {
		t.Error("expected error when filter subprocess exits before mounting")
	}
	symMnt := filepath.Join(base, "sym-mnt")
	if err := os.Symlink(base, symMnt); err != nil {
		t.Fatal(err)
	}
	if _, err := StartSubprocess("/bin/false", base, symMnt, pidFile, true); err == nil {
		t.Error("expected StartSubprocess to reject symlinked mountpoint")
	}
}

func TestProjectSkillsAndRulesPassThroughFUSEWhileVCSRemainsMasked(t *testing.T) {
	ctx := context.Background()
	srcDir, root := newTestFilteredRoot(t)

	for _, dir := range []string{
		".git",
		".jj",
		".agents/skills/review",
		".opencode/skills/lint",
	} {
		if err := os.MkdirAll(filepath.Join(srcDir, dir), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for rel, body := range map[string]string{
		".git/config":                    "[core]\n",
		".agents/skills/review/SKILL.md": "---\nname: review\ndescription: Code review\n---\n",
		".opencode/skills/lint/SKILL.md": "---\nname: lint\ndescription: Lint helper\n---\n",
		"GEMINI.md":                      "# Project rules\n",
		"AGENTS.md":                      "# Agent instructions\n",
	} {
		if err := os.WriteFile(filepath.Join(srcDir, rel), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	// Verify FilteredNode Lookup exposes .agents, .opencode, GEMINI.md, and AGENTS.md while hiding .git and .jj.
	for _, allowed := range []string{".agents", ".opencode", "GEMINI.md", "AGENTS.md"} {
		var out fuse.EntryOut
		if _, errno := root.Lookup(ctx, allowed, &out); errno != 0 {
			t.Errorf("Lookup(%q) = %v, want 0", allowed, errno)
		}
	}
	for _, masked := range []string{".git", ".jj"} {
		var out fuse.EntryOut
		if _, errno := root.Lookup(ctx, masked, &out); errno != syscall.ENOENT {
			t.Errorf("Lookup(%q) = %v, want ENOENT", masked, errno)
		}
	}

	// If kernel FUSE mounting is available, verify full path read/write through the live mount.
	if _, err := os.Stat("/dev/fuse"); err != nil {
		return
	}
	mntDir := filepath.Join(t.TempDir(), "mnt")
	if err := os.MkdirAll(mntDir, 0o755); err != nil {
		t.Fatal(err)
	}
	server, err := Mount(srcDir, mntDir, DefaultHiddenEntries)
	if err != nil {
		return
	}
	defer func() {
		_ = server.Unmount()
		server.Wait()
	}()

	for _, rel := range []string{
		".agents/skills/review/SKILL.md",
		".opencode/skills/lint/SKILL.md",
		"GEMINI.md",
		"AGENTS.md",
	} {
		raw, rErr := os.ReadFile(filepath.Join(mntDir, rel))
		if rErr != nil || len(raw) == 0 {
			t.Errorf("ReadFile(%s) through FUSE = (%q, %v)", rel, string(raw), rErr)
		}
	}
	if _, gErr := os.Stat(filepath.Join(mntDir, ".git")); !os.IsNotExist(gErr) {
		t.Errorf("expected .git to be hidden through FUSE mount, got err=%v", gErr)
	}
	newSkillDir := filepath.Join(mntDir, ".agents", "skills", "created-in-guest")
	if err := os.MkdirAll(newSkillDir, 0o755); err != nil {
		t.Fatalf("MkdirAll(%s) through FUSE: %v", newSkillDir, err)
	}
	if err := os.WriteFile(filepath.Join(newSkillDir, "SKILL.md"), []byte("# Guest skill\n"), 0o644); err != nil {
		t.Fatalf("WriteFile SKILL.md through FUSE: %v", err)
	}
	if _, sErr := os.Stat(filepath.Join(srcDir, ".agents", "skills", "created-in-guest", "SKILL.md")); sErr != nil {
		t.Errorf("expected guest-created skill to persist in host share: %v", sErr)
	}
}
