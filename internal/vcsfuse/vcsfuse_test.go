package vcsfuse

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"agbox/internal/config"
	"agbox/internal/mounttab"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"
	"golang.org/x/sys/unix"
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
		if got := isProtectedXattr(tc.attr); got != tc.want {
			t.Errorf("isProtectedXattr(%q) = %v, want %v", tc.attr, got, tc.want)
		}
	}
}

func TestValidateSymlinkTarget(t *testing.T) {
	hidden := buildHiddenSet(defaultHiddenEntries())
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
		if got := validateSymlinkTarget(tc.parent, tc.name, tc.target, hidden); got != tc.want {
			t.Errorf("validateSymlinkTarget(%q, %q, %q) = %v, want %v", tc.parent, tc.name, tc.target, got, tc.want)
		}
	}
}

func validateSymlinkTarget(parentRelPath, linkName, target string, hidden map[string]struct{}) syscall.Errno {
	return validateSymlinkTargetForPolicy(parentRelPath, linkName, target, hidden, config.VCSMask)
}

func newShareSlot(slotID uint64, guestName, hostPath string, isFile bool, fileName string, pr *pinnedRoot, hidden map[string]struct{}, readOnly bool, policy config.VCSPolicy) *shareSlot {
	return newShareSlotWithIDMap(slotID, guestName, hostPath, isFile, fileName, pr, hidden, readOnly, policy, guestIDMap{})
}

func mountWorkspaceHub(mntDir, sockPath string, initial []HubShareConfig, dataDir string) (*WorkspaceHub, *fuse.Server, io.Closer, error) {
	return mountWorkspaceHubWithOptions(mntDir, sockPath, initial, HubOptions{
		DataDir:          dataDir,
		AllowOutsideHome: true,
	})
}

func newTestFilteredRoot(t *testing.T) (srcDir string, root *filteredNode) {
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

	hidden := buildHiddenSet(defaultHiddenEntries())
	rootData := &fs.LoopbackRoot{
		Path: srcDir,
		Dev:  uint64(st.Dev),
	}
	root = &filteredNode{
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
	if _, rlErrno := escapeIno.Operations().(*filteredNode).Readlink(ctx); rlErrno != syscall.ENOENT {
		t.Errorf("unattached child Readlink = %v, want ENOENT", rlErrno)
	}
	root.AddChild("escape_link", escapeIno, true)
	escapeNode := escapeIno.Operations().(*filteredNode)
	if _, rlErrno := escapeNode.Readlink(ctx); rlErrno != syscall.EPERM {
		t.Errorf("Readlink(escape_link) = %v, want EPERM", rlErrno)
	}
	vcsLinkIno, lErrno := root.Lookup(ctx, "vcs_link", &entryOut)
	if lErrno != 0 {
		t.Fatalf("Lookup(vcs_link): %v", lErrno)
	}
	root.AddChild("vcs_link", vcsLinkIno, true)
	if _, rlErrno := vcsLinkIno.Operations().(*filteredNode).Readlink(ctx); rlErrno != syscall.EPERM {
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
	if target, rlErrno := safeIno.Operations().(*filteredNode).Readlink(ctx); rlErrno != 0 || string(target) != "main.go" {
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
	createdNode := createdIno.Operations().(*filteredNode)

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

	// 9. Exhaustive check across all 22 defaultHiddenEntries(), OpendirHandle, Open/Link/Rename escapes, FIFOs, and safeFile.Setattr.
	pkgIno, lErrno := root.Lookup(ctx, "pkg", &entryOut)
	if lErrno != 0 {
		t.Fatalf("Lookup(pkg): %v", lErrno)
	}
	root.AddChild("pkg", pkgIno, true)
	pkgNode := pkgIno.Operations().(*filteredNode)

	mainIno, lErrno := root.Lookup(ctx, "main.go", &entryOut)
	if lErrno != 0 {
		t.Fatalf("Lookup(main.go): %v", lErrno)
	}
	root.AddChild("main.go", mainIno, true)
	mainNode := mainIno.Operations().(*filteredNode)

	for _, vcsName := range defaultHiddenEntries() {
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
	if _, travErrno := escDirIno.Operations().(*filteredNode).Lookup(ctx, "host-secret.txt", &entryOut); travErrno == 0 {
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
		if _, _, openErr := fifoIno.Operations().(*filteredNode).Open(ctx, syscall.O_RDONLY|syscall.O_NONBLOCK); openErr != syscall.EPERM {
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
	safeNode := safeIno.Operations().(*filteredNode)
	if xErr := safeNode.Setxattr(ctx, "user.tag", []byte("1"), 0); xErr != syscall.EPERM {
		t.Errorf("Setxattr on symlink = %v, want EPERM", xErr)
	}
	if sz, xErr := safeNode.Listxattr(ctx, nil); xErr != 0 || sz != 0 {
		t.Errorf("Listxattr on symlink = (%d, %v), want (0, 0)", sz, xErr)
	}
}

func TestMountValidationErrors(t *testing.T) {
	if _, err := mount("", "/tmp/mnt", nil); err == nil {
		t.Fatal("expected error for empty srcDir")
	}
	if _, err := mount("/tmp/src", "", nil); err == nil {
		t.Fatal("expected error for empty mntDir")
	}
	if _, err := mount("/nonexistent-agbox-src-dir", t.TempDir(), nil); err == nil {
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

	server, err := mount(srcDir, mntDir, defaultHiddenEntries())
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
	for _, vcs := range defaultHiddenEntries() {
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
	for _, vcs := range defaultHiddenEntries() {
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
	_, fn := newTestFilteredRoot(t)
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

	server, err := mount(srcDir, mntDir, defaultHiddenEntries())
	if err != nil {
		t.Skipf("FUSE mount not permitted: %v", err)
	}
	defer func() {
		_ = server.Unmount()
	}()

	if err := mounttab.TeardownFilterDir(filterRoot, nil); err != nil {
		t.Fatalf("TeardownFilterDir(%q): %v", filterRoot, err)
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
	server, err := mount(srcDir, mntDir, defaultHiddenEntries())
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

func TestVCSHookProtectionAndPolicySymlinks(t *testing.T) {
	hidden := buildHiddenSet(defaultHiddenEntries())

	// Hook and executable config path detection across Git, Jujutsu, SVN, Darcs, Pijul, Mercurial, Sapling, and Bazaar.
	for _, protected := range []string{
		".git/hooks",
		".git/hooks/pre-commit",
		".GIT/HOOKS/post-checkout",
		"sub/.git/hooks/pre-push",
		".git/modules/sub/hooks/commit-msg",
		".git/worktrees/wt1/hooks/pre-commit",
		".git/config",
		".GIT/CONFIG",
		".git/commondir",
		".git/gitdir",
		".git/modules/sub/config",
		".git/worktrees/wt1/config",
		".jj/repo/store/git/hooks/pre-commit",
		".jj/repo/store/git/config",
		".jj/repo/config.toml",
		".jj/config.toml",
		".svn/hooks/pre-commit",
		"_darcs/prefs/defaults",
		".pijul/hooks/record",
		".hg/hgrc",
		".hg/hgrc.d/ext.rc",
		".hg/hgrc-not-shared",
		".sl/config",
		".sl/hgrc",
		".bzr/branch/branch.conf",
		".bzr/branch/locations.conf",
	} {
		if !isProtectedVCSHookRelPath(protected) {
			t.Errorf("expected %q to be protected under VCSAllow", protected)
		}
	}
	for _, allowed := range []string{
		".",
		"src/hooks/useAuth.ts",
		"src/config/config.toml",
		".git/index.lock",
		".git/HEAD",
		".git/refs/heads/config",
		".git/logs/refs/heads/config",
		".git/objects/pack",
		".jj/repo/op_heads",
		".hg/store/00changelog.i",
	} {
		if isProtectedVCSHookRelPath(allowed) {
			t.Errorf("expected %q to be writable under VCSAllow", allowed)
		}
	}

	// Symlink validation under VCSAllow allows intra-repo .git/refs links while blocking .git/hooks targets and host escapes.
	if errNo := validateSymlinkTargetForPolicy("", "ref-link", ".git/HEAD", hidden, config.VCSAllow); errNo != 0 {
		t.Errorf("expected intra-share .git/HEAD symlink under VCSAllow to succeed, got %v", errNo)
	}
	if errNo := validateSymlinkTargetForPolicy("src", "evil-hook", "../.git/hooks/pre-commit", hidden, config.VCSAllow); errNo != syscall.EPERM {
		t.Errorf("expected symlink targeting .git/hooks under VCSAllow to fail with EPERM, got %v", errNo)
	}
	if errNo := validateSymlinkTargetForPolicy(".git/hooks", "pre-commit", "../../script.sh", hidden, config.VCSAllow); errNo != syscall.EPERM {
		t.Errorf("expected symlink inside .git/hooks under VCSAllow to fail with EPERM, got %v", errNo)
	}
	if errNo := validateSymlinkTargetForPolicy(".git/hooks", "pre-commit", "../../script.sh", hidden, config.VCSAllowHooks); errNo != 0 {
		t.Errorf("expected intra-share symlink inside .git/hooks under VCSAllowHooks to succeed, got %v", errNo)
	}
	if errNo := validateSymlinkTargetForPolicy(".git/hooks", "escape", "../../../etc/passwd", hidden, config.VCSAllowHooks); errNo != syscall.EPERM {
		t.Errorf("expected escaping symlink under VCSAllowHooks to fail with EPERM, got %v", errNo)
	}
}

func TestWorkspaceHubControlSocketPermissionsAndRevocation(t *testing.T) {
	ctx := context.Background()
	base := t.TempDir()
	dataDir := filepath.Join(base, "agbox-data")
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}

	roDir := filepath.Join(base, "docs-ro")
	vcsDir := filepath.Join(base, "repo-vcs")
	hooksDir := filepath.Join(base, "repo-hooks")
	hotDir := filepath.Join(base, "hot-added")
	cfgFile := filepath.Join(base, "app.yaml")
	hardFile := filepath.Join(base, "hard.txt")
	hardPeer := filepath.Join(base, "hard-peer.txt")

	for _, d := range []string{
		roDir,
		filepath.Join(roDir, ".git"),
		filepath.Join(vcsDir, ".git", "hooks"),
		filepath.Join(hooksDir, ".git", "hooks"),
		filepath.Join(hotDir, ".git"),
	} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	_ = os.WriteFile(filepath.Join(roDir, "readme.md"), []byte("read-only doc\n"), 0o644)
	_ = os.WriteFile(filepath.Join(roDir, ".git", "HEAD"), []byte("ref: refs/heads/main\n"), 0o644)
	_ = os.WriteFile(filepath.Join(vcsDir, "main.go"), []byte("package main\n"), 0o644)
	_ = os.WriteFile(filepath.Join(vcsDir, ".git", "HEAD"), []byte("ref: refs/heads/main\n"), 0o644)
	_ = os.WriteFile(filepath.Join(vcsDir, ".git", "hooks", "pre-commit"), []byte("#!/bin/sh\nexit 0\n"), 0o755)
	_ = os.WriteFile(filepath.Join(hooksDir, ".git", "hooks", "pre-commit"), []byte("#!/bin/sh\nexit 0\n"), 0o755)
	_ = os.WriteFile(filepath.Join(hotDir, "hello.txt"), []byte("hot\n"), 0o644)
	_ = os.WriteFile(filepath.Join(hotDir, ".git", "HEAD"), []byte("ref: refs/heads/main\n"), 0o644)
	_ = os.WriteFile(cfgFile, []byte("port: 8080\n"), 0o600)
	_ = os.WriteFile(hardFile, []byte("linked\n"), 0o600)
	if err := os.Link(hardFile, hardPeer); err != nil {
		t.Fatal(err)
	}

	initial := []HubShareConfig{
		{GuestName: "docs", HostPath: roDir, ReadOnly: true, VCSPolicy: config.VCSMask},
		{GuestName: "repo", HostPath: vcsDir, ReadOnly: false, VCSPolicy: config.VCSAllow},
		{GuestName: "hooksrepo", HostPath: hooksDir, ReadOnly: false, VCSPolicy: config.VCSAllowHooks},
		{GuestName: "app.yaml", HostPath: cfgFile, ReadOnly: false, VCSPolicy: config.VCSMask},
		{GuestName: "hard.txt", HostPath: hardFile, ReadOnly: true, VCSPolicy: config.VCSMask},
	}

	hub, err := NewWorkspaceHubWithOptions(initial, HubOptions{HomeReal: base, DataDir: dataDir})
	if err != nil {
		t.Fatalf("NewWorkspaceHubWithOptions: %v", err)
	}
	defer hub.CloseAll()

	sockDir := filepath.Join(base, "filter")
	sockPath := filepath.Join(sockDir, "ws.sock")
	ln, err := listenVerifiedUnixSocket(sockPath, hub)
	if err != nil {
		t.Fatalf("listenVerifiedUnixSocket: %v", err)
	}
	defer ln.Close()

	if err := pingHub(sockPath); err != nil {
		t.Fatalf("PingHub: %v", err)
	}
	listed, err := ListHubShares(sockPath)
	if err != nil || len(listed) != 5 {
		t.Fatalf("ListHubShares = (%+v, %v), want 5 shares", listed, err)
	}

	// Synthetic /workspace root rejects direct mutations with EROFS.
	var eOut fuse.EntryOut
	if _, _, _, errNo := hub.Create(ctx, "evil.txt", syscall.O_RDWR, 0o644, &eOut); errNo != syscall.EROFS {
		t.Errorf("hub.Create = %v, want EROFS", errNo)
	}
	if _, errNo := hub.Mkdir(ctx, "evil", 0o755, &eOut); errNo != syscall.EROFS {
		t.Errorf("hub.Mkdir = %v, want EROFS", errNo)
	}
	if errNo := hub.Rmdir(ctx, "docs"); errNo != syscall.EROFS {
		t.Errorf("hub.Rmdir = %v, want EROFS", errNo)
	}

	// Security rejections over ws.sock: duplicate name, nested path, dataDir path, ro+vcs-hooks, single-file vcs, hardlinked ro->rw.
	if _, err := AddHubShare(sockPath, HubShareConfig{GuestName: "docs", HostPath: hotDir, ReadOnly: true, VCSPolicy: config.VCSMask}); err == nil {
		t.Error("expected duplicate guest name on AddHubShare to fail")
	}
	if _, err := AddHubShare(sockPath, HubShareConfig{GuestName: "nested", HostPath: filepath.Join(vcsDir, ".git"), ReadOnly: true, VCSPolicy: config.VCSMask}); err == nil {
		t.Error("expected nested/VCS host path on AddHubShare to fail")
	}
	if _, err := AddHubShare(sockPath, HubShareConfig{GuestName: "datadir", HostPath: dataDir, ReadOnly: true, VCSPolicy: config.VCSMask}); err == nil {
		t.Error("expected dataDir overlap on AddHubShare to fail")
	}
	if _, err := AddHubShare(sockPath, HubShareConfig{GuestName: "conflict", HostPath: hotDir, ReadOnly: true, VCSPolicy: config.VCSAllowHooks}); err == nil {
		t.Error("expected ReadOnly + VCSAllowHooks on AddHubShare to fail")
	}
	roFalse := false
	if _, err := SetHubShare(sockPath, "hard.txt", &roFalse, nil, false); err == nil {
		t.Error("expected upgrading hardlinked single-file share from ro to rw to fail")
	}
	vcsAllow := config.VCSAllow
	if _, err := SetHubShare(sockPath, "app.yaml", nil, &vcsAllow, false); err == nil {
		t.Error("expected setting VCS policy on single-file share to fail")
	}

	// Verify in-process slot enforcement for docs (ro,mask) and repo (rw,vcs).
	docsSlot := hub.slots["docs"]
	docsSt, _ := os.Stat(roDir)
	var sySt syscall.Stat_t
	_ = syscall.Stat(roDir, &sySt)
	docsRoot := buildRootFilteredNode(roDir, docsSlot.root, sySt, docsSlot)
	fs.NewNodeFS(docsRoot, &fs.Options{})
	if _, errNo := docsRoot.Lookup(ctx, ".git", &eOut); errNo != syscall.ENOENT {
		t.Errorf("docs(ro,mask) Lookup(.git) = %v, want ENOENT", errNo)
	}
	if _, errNo := docsRoot.Mkdir(ctx, "newdir", 0o755, &eOut); errNo != syscall.EROFS {
		t.Errorf("docs(ro,mask) Mkdir = %v, want EROFS", errNo)
	}

	repoSlot := hub.slots["repo"]
	_ = syscall.Stat(vcsDir, &sySt)
	repoRoot := buildRootFilteredNode(vcsDir, repoSlot.root, sySt, repoSlot)
	fs.NewNodeFS(repoRoot, &fs.Options{})
	gitIno, errNo := repoRoot.Lookup(ctx, ".git", &eOut)
	if errNo != 0 {
		t.Fatalf("repo(rw,vcs) Lookup(.git) = %v, want 0", errNo)
	}
	repoRoot.AddChild(".git", gitIno, true)
	gitNode := gitIno.Operations().(*filteredNode)
	// Writing .git/index.lock is allowed under VCSAllow, whereas .git/hooks/* is blocked with EPERM!
	_, idxFH, _, errNo := gitNode.Create(ctx, "index.lock", syscall.O_RDWR, 0o600, &eOut)
	if errNo != 0 {
		t.Fatalf("repo(rw,vcs) Create(.git/index.lock) = %v, want 0", errNo)
	}
	_ = idxFH.(fs.FileReleaser).Release(ctx)

	hooksIno, errNo := gitNode.Lookup(ctx, "hooks", &eOut)
	if errNo != 0 {
		t.Fatalf("repo(rw,vcs) Lookup(.git/hooks) = %v, want 0", errNo)
	}
	gitNode.AddChild("hooks", hooksIno, true)
	if eOut.Attr.Mode&0o222 != 0 {
		t.Errorf("expected .git/hooks mode bits to have write bits masked under VCSAllow, got %o", eOut.Attr.Mode)
	}
	hooksNode := hooksIno.Operations().(*filteredNode)
	if _, _, _, cErr := hooksNode.Create(ctx, "post-commit", syscall.O_RDWR, 0o755, &eOut); cErr != syscall.EPERM {
		t.Errorf("repo(rw,vcs) Create(.git/hooks/post-commit) = %v, want EPERM", cErr)
	}
	if uErr := hooksNode.Unlink(ctx, "pre-commit"); uErr != syscall.EPERM {
		t.Errorf("repo(rw,vcs) Unlink(.git/hooks/pre-commit) = %v, want EPERM", uErr)
	}
	// Removing or renaming top-level .git under VCSAllow is also blocked with EPERM.
	if rErr := repoRoot.Rename(ctx, ".git", repoRoot, ".git-bak", 0); rErr != syscall.EPERM {
		t.Errorf("repo(rw,vcs) Rename(.git) = %v, want EPERM", rErr)
	}

	// Open writable handle tracking + non-forced rejection + forced revocation!
	hotStatus, err := AddHubShare(sockPath, HubShareConfig{
		GuestName: "hot",
		HostPath:  hotDir,
		ReadOnly:  false,
		VCSPolicy: config.VCSMask,
	})
	if err != nil || hotStatus.GuestName != "hot" {
		t.Fatalf("AddHubShare(hot) = (%+v, %v)", hotStatus, err)
	}
	_ = docsSt
	hotSlot := hub.slots["hot"]
	_ = syscall.Stat(hotDir, &sySt)
	hotRoot := buildRootFilteredNode(hotDir, hotSlot.root, sySt, hotSlot)
	fs.NewNodeFS(hotRoot, &fs.Options{})
	_, openHotFH, _, errNo := hotRoot.Create(ctx, "active.txt", syscall.O_RDWR, 0o644, &eOut)
	if errNo != 0 {
		t.Fatalf("hot Create(active.txt): %v", errNo)
	}
	sfHot := openHotFH.(*safeFile)
	if nW, wErr := sfHot.Write(ctx, []byte("before"), 0); wErr != 0 || nW != 6 {
		t.Fatalf("sfHot.Write = (%d, %v)", nW, wErr)
	}

	// Downgrading rw -> ro without --force fails closed while sfHot is open.
	roTrue := true
	if _, err := SetHubShare(sockPath, "hot", &roTrue, nil, false); err == nil || !strings.Contains(err.Error(), "open writable") {
		t.Fatalf("expected non-forced SetHubShare(--ro) to fail on open writable FD, got %v", err)
	}
	// Removing share without --force fails closed while sfHot is open.
	if err := RemoveHubShare(sockPath, "hot", false); err == nil || !strings.Contains(err.Error(), "open writable") {
		t.Fatalf("expected non-forced RemoveHubShare to fail on open writable FD, got %v", err)
	}

	// Forced SetHubShare(--ro) revokes sfHot with EROFS!
	if _, err := SetHubShare(sockPath, "hot", &roTrue, nil, true); err != nil {
		t.Fatalf("SetHubShare(--ro, force=true): %v", err)
	}
	if _, wErr := sfHot.Write(ctx, []byte("after"), 0); wErr != syscall.EROFS {
		t.Errorf("sfHot.Write after forced ro downgrade = %v, want EROFS", wErr)
	}
	_ = sfHot.Release(ctx)

	// Open a read handle and call RemoveHubShare. Subsequent Read calls return ESTALE.
	helloIno, errNo := hotRoot.Lookup(ctx, "hello.txt", &eOut)
	if errNo != 0 {
		t.Fatalf("hot Lookup(hello.txt): %v", errNo)
	}
	hotRoot.AddChild("hello.txt", helloIno, true)
	helloFH, _, errNo := helloIno.Operations().(*filteredNode).Open(ctx, syscall.O_RDONLY)
	if errNo != 0 {
		t.Fatalf("hot Open(hello.txt): %v", errNo)
	}
	if err := RemoveHubShare(sockPath, "hot", false); err != nil {
		t.Fatalf("RemoveHubShare(hot): %v", err)
	}
	buf := make([]byte, 16)
	if _, rErr := helloFH.(*safeFile).Read(ctx, buf, 0); rErr != syscall.ESTALE {
		t.Errorf("Read after RemoveHubShare = %v, want ESTALE", rErr)
	}
	_ = helloFH.(*safeFile).Release(ctx)

	// Optional end-to-end kernel FUSE mount test when /dev/fuse is available.
	if _, err := os.Stat("/dev/fuse"); err != nil {
		return
	}
	mntDir := filepath.Join(base, "hub-mnt")
	sockPath2 := filepath.Join(base, "filter2", "ws.sock")
	if err := os.MkdirAll(mntDir, 0o755); err != nil {
		t.Fatal(err)
	}
	hub2, server2, ln2, mErr := mountWorkspaceHub(mntDir, sockPath2, initial[:4], dataDir)
	if mErr != nil {
		t.Logf("skipping live kernel MountWorkspaceHub check: %v", mErr)
		return
	}
	defer func() {
		if ln2 != nil {
			_ = ln2.Close()
		}
		_ = server2.Unmount()
		server2.Wait()
		hub2.CloseAll()
	}()

	// Real git commit inside mntDir/repo (:rw,vcs) must succeed while writing .git/hooks fails with EPERM!
	if _, gErr := exec.LookPath("git"); gErr == nil {
		gitInitRepo := filepath.Join(base, "real-git")
		if err := exec.Command("git", "init", gitInitRepo).Run(); err == nil {
			if _, aErr := AddHubShare(sockPath2, HubShareConfig{
				GuestName: "realgit",
				HostPath:  gitInitRepo,
				ReadOnly:  false,
				VCSPolicy: config.VCSAllow,
			}); aErr != nil {
				t.Fatalf("AddHubShare(realgit): %v", aErr)
			}
			mountedGit := filepath.Join(mntDir, "realgit")
			if err := os.WriteFile(filepath.Join(mountedGit, "hello.go"), []byte("package main\n"), 0o644); err != nil {
				t.Fatalf("write hello.go through hub FUSE: %v", err)
			}
			if out, err := exec.Command("git", "-C", mountedGit, "add", "hello.go").CombinedOutput(); err != nil {
				t.Fatalf("git add through hub FUSE failed: %v (%s)", err, string(out))
			}
			if out, err := exec.Command("git", "-C", mountedGit, "-c", "user.name=Test", "-c", "user.email=t@e.st", "commit", "-m", "test commit").CombinedOutput(); err != nil {
				t.Fatalf("git commit through hub FUSE failed: %v (%s)", err, string(out))
			}
			hookFile := filepath.Join(mountedGit, ".git", "hooks", "post-commit")
			if err := os.WriteFile(hookFile, []byte("#!/bin/sh\nid\n"), 0o755); !errors.Is(err, syscall.EPERM) {
				t.Errorf("WriteFile(.git/hooks/post-commit) on :vcs = %v, want EPERM", err)
			}
		}
	}

	// Single-file share read/write through live FUSE mount.
	rawCfg, err := os.ReadFile(filepath.Join(mntDir, "app.yaml"))
	if err != nil || string(rawCfg) != "port: 8080\n" {
		t.Errorf("ReadFile(mnt/app.yaml) = (%q, %v)", string(rawCfg), err)
	}
	if err := os.WriteFile(filepath.Join(mntDir, "app.yaml"), []byte("port: 9090\n"), 0o600); err != nil {
		t.Errorf("WriteFile(mnt/app.yaml): %v", err)
	}
	// Cross-share rename returns EXDEV.
	if err := os.Rename(filepath.Join(mntDir, "repo", "main.go"), filepath.Join(mntDir, "hooksrepo", "main.go")); !errors.Is(err, syscall.EXDEV) {
		t.Errorf("cross-share Rename = %v, want EXDEV", err)
	}
}

func TestWorkspaceHubXattrAndGuestIDMapping(t *testing.T) {
	ctx := context.Background()
	base := t.TempDir()
	dataDir := filepath.Join(base, "data")
	projDir := filepath.Join(base, "proj")
	dynDir := filepath.Join(base, "dyn")
	cfgFile := filepath.Join(base, "config.yml")
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(projDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(dynDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(projDir, "main.go"), []byte("package main\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dynDir, "extra.txt"), []byte("extra\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfgFile, []byte("ok: true\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	const mappedUID = uint32(2000)
	const mappedGID = uint32(2000)

	initial := []HubShareConfig{
		{GuestName: "proj", HostPath: projDir, ReadOnly: false, VCSPolicy: config.VCSMask},
		{GuestName: "config.yml", HostPath: cfgFile, ReadOnly: false, VCSPolicy: config.VCSMask},
	}
	hub, err := NewWorkspaceHubWithOptions(initial, HubOptions{
		HomeReal:    base,
		DataDir:     dataDir,
		MapGuestIDs: true,
		GuestUID:    mappedUID,
		GuestGID:    mappedGID,
	})
	if err != nil {
		t.Fatalf("NewWorkspaceHubWithIDMap: %v", err)
	}
	defer hub.CloseAll()
	_ = fs.NewNodeFS(hub, &fs.Options{})

	// Hub root reports mapped IDs, ENODATA on Getxattr, 0 on Listxattr, and EROFS on Setxattr.
	var hubAttr fuse.AttrOut
	if errno := hub.Getattr(ctx, nil, &hubAttr); errno != 0 {
		t.Fatalf("hub.Getattr = %v", errno)
	}
	if hubAttr.Uid != mappedUID || hubAttr.Gid != mappedGID {
		t.Errorf("hub.Getattr uid:gid = %d:%d, want %d:%d", hubAttr.Uid, hubAttr.Gid, mappedUID, mappedGID)
	}
	if _, errno := hub.Getxattr(ctx, "user.msb.test", nil); errno != unix.ENODATA {
		t.Errorf("hub.Getxattr = %v, want ENODATA", errno)
	}
	if sz, errno := hub.Listxattr(ctx, nil); errno != 0 || sz != 0 {
		t.Errorf("hub.Listxattr = (%d, %v), want (0, 0)", sz, errno)
	}
	if errno := hub.Setxattr(ctx, "user.msb._probe", []byte("1"), 0); errno != syscall.EROFS {
		t.Errorf("hub.Setxattr = %v, want EROFS", errno)
	}

	var eOut fuse.EntryOut
	projIno, errno := hub.Lookup(ctx, "proj", &eOut)
	if errno != 0 {
		t.Fatalf("hub.Lookup(proj) = %v", errno)
	}
	if eOut.Attr.Uid != mappedUID || eOut.Attr.Gid != mappedGID {
		t.Errorf("hub.Lookup(proj) uid:gid = %d:%d, want %d:%d", eOut.Attr.Uid, eOut.Attr.Gid, mappedUID, mappedGID)
	}
	cfgIno, errno := hub.Lookup(ctx, "config.yml", &eOut)
	if errno != 0 {
		t.Fatalf("hub.Lookup(config.yml) = %v", errno)
	}
	if eOut.Attr.Uid != mappedUID || eOut.Attr.Gid != mappedGID {
		t.Errorf("hub.Lookup(config.yml) uid:gid = %d:%d, want %d:%d", eOut.Attr.Uid, eOut.Attr.Gid, mappedUID, mappedGID)
	}

	// fileShareNode Lookup/Getattr/Statx/Setattr all report mapped IDs and accept mapped UID/GID in Setattr.
	cfgNode := cfgIno.Operations().(*fileShareNode)
	var aOut fuse.AttrOut
	if errno := cfgNode.Getattr(ctx, nil, &aOut); errno != 0 {
		t.Fatalf("fileShareNode.Getattr = %v", errno)
	}
	if aOut.Uid != mappedUID || aOut.Gid != mappedGID {
		t.Errorf("fileShareNode.Getattr uid:gid = %d:%d, want %d:%d", aOut.Uid, aOut.Gid, mappedUID, mappedGID)
	}
	var sxOut fuse.StatxOut
	if errno := cfgNode.Statx(ctx, nil, 0, unix.STATX_BASIC_STATS, &sxOut); errno != 0 {
		t.Fatalf("fileShareNode.Statx = %v", errno)
	}
	if sxOut.Statx.Uid != mappedUID || sxOut.Statx.Gid != mappedGID {
		t.Errorf("fileShareNode.Statx uid:gid = %d:%d, want %d:%d", sxOut.Statx.Uid, sxOut.Statx.Gid, mappedUID, mappedGID)
	}
	chownMappedIn := &fuse.SetAttrIn{}
	chownMappedIn.Valid = fuse.FATTR_UID | fuse.FATTR_GID | fuse.FATTR_MODE
	chownMappedIn.Uid = mappedUID
	chownMappedIn.Gid = mappedGID
	chownMappedIn.Mode = 0o600
	if errno := cfgNode.Setattr(ctx, nil, chownMappedIn, &aOut); errno != 0 {
		t.Fatalf("fileShareNode.Setattr(mapped) = %v", errno)
	}
	if aOut.Uid != mappedUID || aOut.Gid != mappedGID {
		t.Errorf("fileShareNode.Setattr uid:gid = %d:%d, want %d:%d", aOut.Uid, aOut.Gid, mappedUID, mappedGID)
	}
	chownBadIn := &fuse.SetAttrIn{}
	chownBadIn.Valid = fuse.FATTR_UID
	chownBadIn.Uid = 9999
	if errno := cfgNode.Setattr(ctx, nil, chownBadIn, &aOut); errno != syscall.EPERM {
		t.Errorf("fileShareNode.Setattr(9999) = %v, want EPERM", errno)
	}

	// Directory FilteredNode and safeFile operations report mapped IDs across Lookup, Create, Mkdir, Symlink, Statx, Setattr.
	projRoot := projIno.Operations().(*filteredNode)

	if _, errno := projRoot.Lookup(ctx, "main.go", &eOut); errno != 0 {
		t.Fatalf("projRoot.Lookup(main.go) = %v", errno)
	}
	if eOut.Attr.Uid != mappedUID || eOut.Attr.Gid != mappedGID {
		t.Errorf("projRoot.Lookup uid:gid = %d:%d, want %d:%d", eOut.Attr.Uid, eOut.Attr.Gid, mappedUID, mappedGID)
	}
	if _, errno := projRoot.Mkdir(ctx, "sub", 0o755, &eOut); errno != 0 {
		t.Fatalf("projRoot.Mkdir = %v", errno)
	}
	if eOut.Attr.Uid != mappedUID || eOut.Attr.Gid != mappedGID {
		t.Errorf("projRoot.Mkdir uid:gid = %d:%d, want %d:%d", eOut.Attr.Uid, eOut.Attr.Gid, mappedUID, mappedGID)
	}
	if _, errno := projRoot.Symlink(ctx, "main.go", "main-link.go", &eOut); errno != 0 {
		t.Fatalf("projRoot.Symlink = %v", errno)
	}
	if eOut.Attr.Uid != mappedUID || eOut.Attr.Gid != mappedGID {
		t.Errorf("projRoot.Symlink uid:gid = %d:%d, want %d:%d", eOut.Attr.Uid, eOut.Attr.Gid, mappedUID, mappedGID)
	}
	_, createdFH, _, errno := projRoot.Create(ctx, "created.txt", syscall.O_RDWR, 0o644, &eOut)
	if errno != 0 {
		t.Fatalf("projRoot.Create = %v", errno)
	}
	if eOut.Attr.Uid != mappedUID || eOut.Attr.Gid != mappedGID {
		t.Errorf("projRoot.Create uid:gid = %d:%d, want %d:%d", eOut.Attr.Uid, eOut.Attr.Gid, mappedUID, mappedGID)
	}
	sf := createdFH.(*safeFile)
	if errno := sf.Getattr(ctx, &aOut); errno != 0 {
		t.Fatalf("safeFile.Getattr = %v", errno)
	}
	if aOut.Uid != mappedUID || aOut.Gid != mappedGID {
		t.Errorf("safeFile.Getattr uid:gid = %d:%d, want %d:%d", aOut.Uid, aOut.Gid, mappedUID, mappedGID)
	}
	if errno := sf.Setattr(ctx, chownMappedIn, &aOut); errno != 0 {
		t.Fatalf("safeFile.Setattr(mapped) = %v", errno)
	}
	if aOut.Uid != mappedUID || aOut.Gid != mappedGID {
		t.Errorf("safeFile.Setattr uid:gid = %d:%d, want %d:%d", aOut.Uid, aOut.Gid, mappedUID, mappedGID)
	}
	if errno := sf.Setattr(ctx, chownBadIn, &aOut); errno != syscall.EPERM {
		t.Errorf("safeFile.Setattr(9999) = %v, want EPERM", errno)
	}
	_ = sf.Release(ctx)

	if errno := projRoot.Statx(ctx, nil, 0, unix.STATX_BASIC_STATS, &sxOut); errno != 0 {
		t.Fatalf("projRoot.Statx = %v", errno)
	}
	if sxOut.Statx.Uid != mappedUID || sxOut.Statx.Gid != mappedGID {
		t.Errorf("projRoot.Statx uid:gid = %d:%d, want %d:%d", sxOut.Statx.Uid, sxOut.Statx.Gid, mappedUID, mappedGID)
	}

	// Dynamically added share inherits mapped IDs.
	sockPath := filepath.Join(base, "filter", "ws.sock")
	ln, err := ServeControlSocket(sockPath, hub)
	if err != nil {
		t.Fatalf("ServeControlSocket: %v", err)
	}
	defer ln.Close()
	if _, err := AddHubShare(sockPath, HubShareConfig{
		GuestName: "dyn",
		HostPath:  dynDir,
		ReadOnly:  true,
		VCSPolicy: config.VCSMask,
	}); err != nil {
		t.Fatalf("AddHubShare(dyn): %v", err)
	}
	if _, errno := hub.Lookup(ctx, "dyn", &eOut); errno != 0 {
		t.Fatalf("hub.Lookup(dyn) = %v", errno)
	}
	if eOut.Attr.Uid != mappedUID || eOut.Attr.Gid != mappedGID {
		t.Errorf("hub.Lookup(dyn) uid:gid = %d:%d, want %d:%d", eOut.Attr.Uid, eOut.Attr.Gid, mappedUID, mappedGID)
	}
}

func TestDetachedSubprocessPipeHelper(t *testing.T) {
	if os.Getenv("AGBOX_TEST_DETACHED_HELPER") != "1" {
		return
	}
	hangScript := os.Getenv("AGBOX_TEST_HANG_SCRIPT")
	baseDir := os.Getenv("AGBOX_TEST_BASE_DIR")
	mode := os.Getenv("AGBOX_TEST_MODE")
	if mode == "hub" {
		_, err := StartHubSubprocessWithOptions(
			hangScript,
			filepath.Join(baseDir, "ws"),
			filepath.Join(baseDir, "ws.sock"),
			filepath.Join(baseDir, "ws.pid"),
			nil,
			HubOptions{HomeReal: baseDir, DataDir: filepath.Join(baseDir, "data")},
			false,
		)
		if err == nil {
			t.Fatal("expected StartHubSubprocessWithOptions timeout error from hang script")
		}
		return
	}
	_, err := StartSubprocess(
		hangScript,
		baseDir,
		filepath.Join(baseDir, "m0"),
		filepath.Join(baseDir, "m0.pid"),
		false,
	)
	if err == nil {
		t.Fatal("expected StartSubprocess timeout error from hang script")
	}
}

func TestStartHubAndFilterSubprocessDoNotLeakCallerStderrPipe(t *testing.T) {
	base := t.TempDir()
	srcDir := filepath.Join(base, "src")
	dataDir := filepath.Join(base, "data")
	if err := os.MkdirAll(srcDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}

	// 1. Failing daemon stderr is captured in a 0600 .err file and returned in the error.
	failScript := filepath.Join(base, "fail-daemon.sh")
	if err := os.WriteFile(failScript, []byte("#!/bin/sh\necho \"daemon boot failure detail\" >&2\nexit 1\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	m0Pid := filepath.Join(base, "m0.pid")
	if _, err := StartSubprocess(failScript, srcDir, filepath.Join(base, "m0"), m0Pid, true); err == nil || !strings.Contains(err.Error(), "daemon boot failure detail") {
		t.Fatalf("StartSubprocess error = %v, want daemon boot failure detail", err)
	}
	if info, err := os.Stat(filepath.Join(base, "m0.err")); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("m0.err stat = %+v, %v, want mode 0600", info, err)
	}

	wsPid := filepath.Join(base, "ws.pid")
	if _, err := StartHubSubprocessWithOptions(failScript, filepath.Join(base, "ws"), filepath.Join(base, "ws.sock"), wsPid, nil, HubOptions{HomeReal: base, DataDir: dataDir}, false); err == nil || !strings.Contains(err.Error(), "daemon boot failure detail") {
		t.Fatalf("StartHubSubprocessWithOptions error = %v, want daemon boot failure detail", err)
	}
	if info, err := os.Stat(filepath.Join(base, "ws.err")); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("ws.err stat = %+v, %v, want mode 0600", info, err)
	}

	// 2. Symlinked .err path is rejected fail-closed before launching the subprocess.
	symPid := filepath.Join(base, "sym.pid")
	symErr := filepath.Join(base, "sym.err")
	if err := os.Symlink(filepath.Join(base, "outside"), symErr); err != nil {
		t.Fatal(err)
	}
	if _, err := StartSubprocess(failScript, srcDir, filepath.Join(base, "msym"), symPid, true); err == nil || !strings.Contains(err.Error(), "refusing non-regular daemon stderr log path") {
		t.Fatalf("StartSubprocess symlink .err = %v, want symlink rejection", err)
	}
	if _, err := StartHubSubprocessWithOptions(failScript, filepath.Join(base, "wssym"), filepath.Join(base, "wssym.sock"), symPid, nil, HubOptions{HomeReal: base, DataDir: dataDir}, false); err == nil || !strings.Contains(err.Error(), "refusing non-regular daemon stderr log path") {
		t.Fatalf("StartHubSubprocessWithOptions symlink .err = %v, want symlink rejection", err)
	}

	// 3. Detached daemons that stay alive do not hold the parent's stdout/stderr pipes open.
	hangScript := filepath.Join(base, "hang-daemon.sh")
	if err := os.WriteFile(hangScript, []byte("#!/bin/sh\ntrap '' TERM\nexec sleep 60\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}

	for _, mode := range []string{"hub", "filter"} {
		subBase := filepath.Join(base, "pipe-"+mode)
		if err := os.MkdirAll(subBase, 0o700); err != nil {
			t.Fatal(err)
		}
		pidFile := filepath.Join(subBase, "m0.pid")
		if mode == "hub" {
			pidFile = filepath.Join(subBase, "ws.pid")
		}
		t.Cleanup(func() {
			raw, rErr := os.ReadFile(pidFile)
			if rErr != nil {
				return
			}
			pid, pErr := strconv.Atoi(strings.TrimSpace(string(raw)))
			if pErr != nil || pid <= 0 {
				return
			}
			_ = syscall.Kill(-pid, syscall.SIGKILL)
			_ = syscall.Kill(pid, syscall.SIGKILL)
			deadline := time.Now().Add(500 * time.Millisecond)
			for time.Now().Before(deadline) {
				if syscall.Kill(pid, 0) != nil {
					break
				}
				time.Sleep(10 * time.Millisecond)
			}
		})

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		cmd := exec.CommandContext(ctx, exe, "-test.run=^TestDetachedSubprocessPipeHelper$")
		cmd.Env = append(os.Environ(),
			"AGBOX_TEST_DETACHED_HELPER=1",
			"AGBOX_TEST_HANG_SCRIPT="+hangScript,
			"AGBOX_TEST_BASE_DIR="+subBase,
			"AGBOX_TEST_MODE="+mode,
		)
		out, runErr := cmd.CombinedOutput()
		cancel()
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			t.Fatalf("%s CombinedOutput hung because detached child inherited stdout/stderr pipe", mode)
		}
		if runErr != nil {
			t.Fatalf("%s helper failed: %v\n%s", mode, runErr, string(out))
		}
		if !strings.Contains(string(out), "PASS") {
			t.Fatalf("%s helper unexpected output:\n%s", mode, string(out))
		}
	}
}

// TestVCSPolicyDowngrade verifies scoped writable handle blocking and revocation during VCS policy downgrades.
func TestVCSPolicyDowngrade(t *testing.T) {
	ctx := context.Background()
	base := t.TempDir()
	dataDir := filepath.Join(base, "data")
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}

	repoDir := filepath.Join(base, "repo")
	if err := os.MkdirAll(filepath.Join(repoDir, ".git", "hooks"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repoDir, "main.go"), []byte("package main\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repoDir, ".git", "config"), []byte("repo_config\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repoDir, ".git", "HEAD"), []byte("ref: refs/heads/main\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repoDir, ".git", "hooks", "pre-commit"), []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	initial := []HubShareConfig{
		{GuestName: "repo", HostPath: repoDir, ReadOnly: false, VCSPolicy: config.VCSAllowHooks},
	}
	hub, err := NewWorkspaceHubWithOptions(initial, HubOptions{HomeReal: base, DataDir: dataDir})
	if err != nil {
		t.Fatalf("NewWorkspaceHubWithOptions: %v", err)
	}
	defer hub.CloseAll()
	_ = fs.NewNodeFS(hub, &fs.Options{})

	sockPath := filepath.Join(base, "ws.sock")
	ln, err := listenVerifiedUnixSocket(sockPath, hub)
	if err != nil {
		t.Fatalf("listenVerifiedUnixSocket: %v", err)
	}
	defer ln.Close()

	slot := hub.slots["repo"]
	var sySt syscall.Stat_t
	_ = syscall.Stat(repoDir, &sySt)
	repoRoot := buildRootFilteredNode(repoDir, slot.root, sySt, slot)
	fs.NewNodeFS(repoRoot, &fs.Options{})

	var eOut fuse.EntryOut
	mainIno, errNo := repoRoot.Lookup(ctx, "main.go", &eOut)
	if errNo != 0 {
		t.Fatalf("repoRoot.Lookup(main.go): %v", errNo)
	}
	repoRoot.AddChild("main.go", mainIno, true)
	mainNode := mainIno.Operations().(*filteredNode)

	mainFH, _, errNo := mainNode.Open(ctx, syscall.O_RDWR)
	if errNo != 0 {
		t.Fatalf("mainNode.Open(O_RDWR): %v", errNo)
	}
	mainSF := mainFH.(*safeFile)
	defer mainSF.Release(ctx)

	if _, wErr := mainSF.Write(ctx, []byte("// initial edit\n"), 0); wErr != 0 {
		t.Fatalf("mainSF.Write initial failed: %v", wErr)
	}

	vcsAllow := config.VCSAllow
	vcsHooks := config.VCSAllowHooks
	vcsMask := config.VCSMask

	// Verify (b): open writable handle on normal non-VCS file does not block downgrade without force.
	if _, err := SetHubShare(sockPath, "repo", nil, &vcsAllow, false); err != nil {
		t.Fatalf("expected SetHubShare to succeed when only non-VCS writable file is open, got: %v", err)
	}
	if _, wErr := mainSF.Write(ctx, []byte("// edit after vcsAllow downgrade\n"), 0); wErr != 0 {
		t.Fatalf("mainSF.Write after downgrade failed: %v", wErr)
	}

	// Reset policy to VCSAllowHooks to test hook handle blocking and revocation.
	if _, err := SetHubShare(sockPath, "repo", nil, &vcsHooks, true); err != nil {
		t.Fatalf("SetHubShare back to VCSAllowHooks failed: %v", err)
	}

	gitIno, errNo := repoRoot.Lookup(ctx, ".git", &eOut)
	if errNo != 0 {
		t.Fatalf("repoRoot.Lookup(.git): %v", errNo)
	}
	repoRoot.AddChild(".git", gitIno, true)
	gitNode := gitIno.Operations().(*filteredNode)

	hooksIno, errNo := gitNode.Lookup(ctx, "hooks", &eOut)
	if errNo != 0 {
		t.Fatalf("gitNode.Lookup(hooks): %v", errNo)
	}
	gitNode.AddChild("hooks", hooksIno, true)
	hooksNode := hooksIno.Operations().(*filteredNode)

	preCommitIno, errNo := hooksNode.Lookup(ctx, "pre-commit", &eOut)
	if errNo != 0 {
		t.Fatalf("hooksNode.Lookup(pre-commit): %v", errNo)
	}
	hooksNode.AddChild("pre-commit", preCommitIno, true)
	preCommitNode := preCommitIno.Operations().(*filteredNode)

	hookFH, _, errNo := preCommitNode.Open(ctx, syscall.O_RDWR)
	if errNo != 0 {
		t.Fatalf("preCommitNode.Open(O_RDWR): %v", errNo)
	}
	hookSF := hookFH.(*safeFile)

	// Verify (a): open writable hook handle blocks downgrade VCSAllowHooks -> VCSAllow without force.
	if _, err := SetHubShare(sockPath, "repo", nil, &vcsAllow, false); err == nil || !strings.Contains(err.Error(), "open writable") {
		t.Fatalf("expected SetHubShare to fail on open writable hook handle, got: %v", err)
	}

	// Verify (a): downgrade with force succeeds and revokes hook handle with EROFS.
	if _, err := SetHubShare(sockPath, "repo", nil, &vcsAllow, true); err != nil {
		t.Fatalf("SetHubShare with force failed: %v", err)
	}
	if _, wErr := hookSF.Write(ctx, []byte("hook update"), 0); wErr != syscall.EROFS {
		t.Errorf("hookSF.Write after downgrade = %v, want EROFS", wErr)
	}
	_ = hookSF.Release(ctx)

	// Verify (b): main.go stays open and writable across VCSAllowHooks -> VCSAllow downgrade.
	if _, wErr := mainSF.Write(ctx, []byte("// edit after hook revocation\n"), 0); wErr != 0 {
		t.Fatalf("mainSF.Write after hook revocation failed: %v", wErr)
	}

	// Policy is now VCSAllow. .git/config is write-protected, whereas .git/HEAD is writable VCS metadata.
	gitIno, errNo = repoRoot.Lookup(ctx, ".git", &eOut)
	if errNo != 0 {
		t.Fatalf("repoRoot.Lookup(.git): %v", errNo)
	}
	repoRoot.AddChild(".git", gitIno, true)
	gitNode = gitIno.Operations().(*filteredNode)

	cfgIno, errNo := gitNode.Lookup(ctx, "config", &eOut)
	if errNo != 0 {
		t.Fatalf("gitNode.Lookup(config): %v", errNo)
	}
	gitNode.AddChild("config", cfgIno, true)
	cfgNode := cfgIno.Operations().(*filteredNode)

	if _, _, cfgWErr := cfgNode.Open(ctx, syscall.O_RDWR); cfgWErr != syscall.EPERM {
		t.Fatalf("cfgNode.Open(O_RDWR) under VCSAllow = %v, want EPERM", cfgWErr)
	}

	headIno, errNo := gitNode.Lookup(ctx, "HEAD", &eOut)
	if errNo != 0 {
		t.Fatalf("gitNode.Lookup(HEAD): %v", errNo)
	}
	gitNode.AddChild("HEAD", headIno, true)
	headNode := headIno.Operations().(*filteredNode)

	headW_FH, _, errNo := headNode.Open(ctx, syscall.O_RDWR)
	if errNo != 0 {
		t.Fatalf("headNode.Open(O_RDWR): %v", errNo)
	}
	headW_SF := headW_FH.(*safeFile)

	roFH, _, errNo := cfgNode.Open(ctx, syscall.O_RDONLY)
	if errNo != 0 {
		t.Fatalf("cfgNode.Open(O_RDONLY): %v", errNo)
	}
	roSF := roFH.(*safeFile)
	readBuf := make([]byte, 64)
	res, rErr := roSF.Read(ctx, readBuf, 0)
	if rErr != 0 || res.Size() == 0 {
		t.Fatalf("roSF.Read before downgrade failed: %v", rErr)
	}

	dirFH, _, odErrno := gitNode.OpendirHandle(ctx, 0)
	if odErrno != 0 {
		t.Fatalf("gitNode.OpendirHandle: %v", odErrno)
	}
	gitDir := dirFH.(*filteredDir)
	de, dErr := gitDir.Readdirent(ctx)
	if dErr != 0 || de == nil {
		t.Fatalf("gitDir.Readdirent before downgrade failed: %v", dErr)
	}

	// Verify (a): open writable handle on .git/HEAD blocks downgrade VCSAllow -> VCSMask without force.
	if _, err := SetHubShare(sockPath, "repo", nil, &vcsMask, false); err == nil || !strings.Contains(err.Error(), "open writable") {
		t.Fatalf("expected SetHubShare to fail on open writable VCS handle, got: %v", err)
	}

	// Verify (a): downgrade with force succeeds and revokes VCS handles with ESTALE.
	if _, err := SetHubShare(sockPath, "repo", nil, &vcsMask, true); err != nil {
		t.Fatalf("SetHubShare to VCSMask with force failed: %v", err)
	}
	if _, wErr := headW_SF.Write(ctx, []byte("blocked"), 0); wErr != syscall.ESTALE {
		t.Errorf("headW_SF.Write after downgrade = %v, want ESTALE", wErr)
	}
	_ = headW_SF.Release(ctx)

	if _, rErrAfter := roSF.Read(ctx, readBuf, 0); rErrAfter != syscall.ESTALE {
		t.Errorf("roSF.Read after downgrade = %v, want ESTALE", rErrAfter)
	}
	_ = roSF.Release(ctx)

	if _, dErrAfter := gitDir.Readdirent(ctx); dErrAfter != syscall.ESTALE {
		t.Errorf("gitDir.Readdirent after downgrade = %v, want ESTALE", dErrAfter)
	}
	if sErrAfter := gitDir.Seekdir(ctx, 0); sErrAfter != syscall.ESTALE {
		t.Errorf("gitDir.Seekdir after downgrade = %v, want ESTALE", sErrAfter)
	}
	gitDir.Releasedir(ctx, 0)

	// Verify (b): main.go stays open and writable across VCSAllow -> VCSMask downgrade.
	if _, wErr := mainSF.Write(ctx, []byte("// edit after vcsMask downgrade\n"), 0); wErr != 0 {
		t.Fatalf("mainSF.Write after vcsMask downgrade failed: %v", wErr)
	}

}

// TestTopLevelVCSAdminDirProtectionBzrAndSl verifies that Bazaar and Sapling admin dirs cannot be removed.
func TestTopLevelVCSAdminDirProtectionBzrAndSl(t *testing.T) {
	ctx := context.Background()
	base := t.TempDir()
	dataDir := filepath.Join(base, "data")
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}

	repoDir := filepath.Join(base, "repo")
	if err := os.MkdirAll(filepath.Join(repoDir, ".bzr"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(repoDir, ".sl"), 0o755); err != nil {
		t.Fatal(err)
	}

	initial := []HubShareConfig{
		{GuestName: "repo", HostPath: repoDir, ReadOnly: false, VCSPolicy: config.VCSAllow},
	}
	hub, err := NewWorkspaceHubWithOptions(initial, HubOptions{HomeReal: base, DataDir: dataDir})
	if err != nil {
		t.Fatalf("NewWorkspaceHubWithOptions: %v", err)
	}
	defer hub.CloseAll()

	slot := hub.slots["repo"]
	var sySt syscall.Stat_t
	_ = syscall.Stat(repoDir, &sySt)
	repoRoot := buildRootFilteredNode(repoDir, slot.root, sySt, slot)
	fs.NewNodeFS(repoRoot, &fs.Options{})

	var eOut fuse.EntryOut
	for _, adminDir := range []string{".bzr", ".sl"} {
		if _, errNo := repoRoot.Lookup(ctx, adminDir, &eOut); errNo != 0 {
			t.Fatalf("Lookup(%q) = %v, want 0", adminDir, errNo)
		}
		if errNo := repoRoot.Unlink(ctx, adminDir); errNo != syscall.EPERM {
			t.Errorf("Unlink(%q) = %v, want EPERM", adminDir, errNo)
		}
		if errNo := repoRoot.Rmdir(ctx, adminDir); errNo != syscall.EPERM {
			t.Errorf("Rmdir(%q) = %v, want EPERM", adminDir, errNo)
		}
		if errNo := repoRoot.Rename(ctx, adminDir, repoRoot, adminDir+"-bak", 0); errNo != syscall.EPERM {
			t.Errorf("Rename(%q) = %v, want EPERM", adminDir, errNo)
		}
	}
}

// TestFileShareNodeOperations verifies single file share operations and access controls.
func TestFileShareNodeOperations(t *testing.T) {
	ctx := context.Background()
	base := t.TempDir()
	dataDir := filepath.Join(base, "data")
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}

	filePath := filepath.Join(base, "doc.txt")
	if err := os.WriteFile(filePath, []byte("content\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	initial := []HubShareConfig{
		{GuestName: "doc.txt", HostPath: filePath, ReadOnly: true, VCSPolicy: config.VCSMask},
	}
	hub, err := NewWorkspaceHubWithOptions(initial, HubOptions{HomeReal: base, DataDir: dataDir})
	if err != nil {
		t.Fatalf("NewWorkspaceHubWithOptions: %v", err)
	}
	defer hub.CloseAll()
	_ = fs.NewNodeFS(hub, &fs.Options{})

	slot := hub.slots["doc.txt"]
	node := &fileShareNode{slot: slot}

	var sOut fuse.StatfsOut
	if errNo := node.Statfs(ctx, &sOut); errNo != 0 {
		t.Errorf("node.Statfs = %v, want 0", errNo)
	}

	fh, _, errNo := node.Open(ctx, syscall.O_RDONLY)
	if errNo != 0 {
		t.Fatalf("node.Open(O_RDONLY) = %v, want 0", errNo)
	}
	_ = fh.(fs.FileReleaser).Release(ctx)

	if _, _, errNo := node.Open(ctx, syscall.O_RDWR); errNo != syscall.EROFS {
		t.Errorf("node.Open(O_RDWR) on read-only share = %v, want EROFS", errNo)
	}

	var aOut fuse.AttrOut
	if errNo := node.Getattr(ctx, nil, &aOut); errNo != 0 {
		t.Errorf("node.Getattr = %v, want 0", errNo)
	}
	if aOut.Size != 8 {
		t.Errorf("node.Getattr size = %d, want 8", aOut.Size)
	}

	var sxOut fuse.StatxOut
	if errNo := node.Statx(ctx, nil, 0, unix.STATX_ALL, &sxOut); errNo != 0 {
		t.Errorf("node.Statx = %v, want 0", errNo)
	}
	if sxOut.Statx.Size != 8 {
		t.Errorf("node.Statx size = %d, want 8", sxOut.Statx.Size)
	}

	var setIn fuse.SetAttrIn
	setIn.Valid = fuse.FATTR_SIZE
	setIn.Size = 4
	var setOut fuse.AttrOut
	if errNo := node.Setattr(ctx, nil, &setIn, &setOut); errNo != syscall.EROFS {
		t.Errorf("node.Setattr on read-only = %v, want EROFS", errNo)
	}

	if _, errNo := node.Getxattr(ctx, "security.selinux", nil); errNo != unix.ENODATA {
		t.Errorf("node.Getxattr(security) = %v, want ENODATA", errNo)
	}
	if errNo := node.Setxattr(ctx, "user.test", []byte("val"), 0); errNo != syscall.EROFS {
		t.Errorf("node.Setxattr on read-only = %v, want EROFS", errNo)
	}
	if errNo := node.Removexattr(ctx, "user.test"); errNo != syscall.EROFS {
		t.Errorf("node.Removexattr on read-only = %v, want EROFS", errNo)
	}

	var dest [256]byte
	_, _ = node.Listxattr(ctx, dest[:])

	slot.setReadOnly(false)
	if errNo := node.Setattr(ctx, nil, &setIn, &setOut); errNo != 0 {
		t.Errorf("node.Setattr on writable = %v, want 0", errNo)
	}
	if errNo := node.Setxattr(ctx, "security.selinux", []byte("1"), 0); errNo != syscall.EPERM {
		t.Errorf("node.Setxattr(security) = %v, want EPERM", errNo)
	}
	if errNo := node.Removexattr(ctx, "security.selinux"); errNo != syscall.EPERM {
		t.Errorf("node.Removexattr(security) = %v, want EPERM", errNo)
	}

	userAttr := "user.comment"
	userVal := []byte("test value")
	setxErr := node.Setxattr(ctx, userAttr, userVal, 0)
	if setxErr == 0 {
		var xDest [64]byte
		nRead, gErr := node.Getxattr(ctx, userAttr, xDest[:])
		if gErr != 0 || string(xDest[:nRead]) != string(userVal) {
			t.Errorf("node.Getxattr = %v, got %q, want %q", gErr, string(xDest[:nRead]), userVal)
		}
		var lDest [256]byte
		lSz, lErr := node.Listxattr(ctx, lDest[:])
		if lErr != 0 || !strings.Contains(string(lDest[:lSz]), userAttr) {
			t.Errorf("node.Listxattr = %v, got %q", lErr, string(lDest[:lSz]))
		}
		if rmErr := node.Removexattr(ctx, userAttr); rmErr != 0 {
			t.Errorf("node.Removexattr = %v, want 0", rmErr)
		}
	} else if setxErr != syscall.EOPNOTSUPP && setxErr != unix.ENOTSUP {
		t.Errorf("node.Setxattr user attribute failed: %v", setxErr)
	}
	slot.setReadOnly(true)

	sockPath := filepath.Join(base, "ws.sock")
	ln, err := listenVerifiedUnixSocket(sockPath, hub)
	if err != nil {
		t.Fatalf("listenVerifiedUnixSocket: %v", err)
	}
	defer ln.Close()

	_ = os.Remove(filePath)
	if err := os.Mkdir(filePath, 0o755); err != nil {
		t.Fatal(err)
	}

	roFalse := false
	if _, err := SetHubShare(sockPath, "doc.txt", &roFalse, nil, false); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Errorf("expected SetHubShare to reject non-regular file, got %v", err)
	}

	// Verify ESTALE on revoked file share node operations.
	slot.revokeAll(syscall.ESTALE)
	if errNo := node.Getattr(ctx, nil, &aOut); errNo != syscall.ESTALE {
		t.Errorf("node.Getattr after revoke = %v, want ESTALE", errNo)
	}
	if errNo := node.Statx(ctx, nil, 0, unix.STATX_ALL, &sxOut); errNo != syscall.ESTALE {
		t.Errorf("node.Statx after revoke = %v, want ESTALE", errNo)
	}
	if errNo := node.Setattr(ctx, nil, &setIn, &setOut); errNo != syscall.ESTALE {
		t.Errorf("node.Setattr after revoke = %v, want ESTALE", errNo)
	}
	if _, _, errNo := node.Open(ctx, syscall.O_RDONLY); errNo != syscall.ESTALE {
		t.Errorf("node.Open after revoke = %v, want ESTALE", errNo)
	}
	if errNo := node.Statfs(ctx, &sOut); errNo != syscall.ESTALE {
		t.Errorf("node.Statfs after revoke = %v, want ESTALE", errNo)
	}
	if _, errNo := node.Getxattr(ctx, "user.test", nil); errNo != syscall.ESTALE {
		t.Errorf("node.Getxattr after revoke = %v, want ESTALE", errNo)
	}
	if _, errNo := node.Listxattr(ctx, dest[:]); errNo != syscall.ESTALE {
		t.Errorf("node.Listxattr after revoke = %v, want ESTALE", errNo)
	}
	if errNo := node.Setxattr(ctx, "user.test", []byte("val"), 0); errNo != syscall.ESTALE {
		t.Errorf("node.Setxattr after revoke = %v, want ESTALE", errNo)
	}
	if errNo := node.Removexattr(ctx, "user.test"); errNo != syscall.ESTALE {
		t.Errorf("node.Removexattr after revoke = %v, want ESTALE", errNo)
	}
}

// TestFilteredNodeTmpfileCopyFileRangeStatfs verifies Tmpfile, CopyFileRange, and Statfs on FilteredNode.
func TestFilteredNodeTmpfileCopyFileRangeStatfs(t *testing.T) {
	ctx := context.Background()
	srcDir, root := newTestFilteredRoot(t)

	hidden := buildHiddenSet(defaultHiddenEntries())
	slot := newShareSlot(1, "test", srcDir, false, "", root.root, hidden, false, config.VCSMask)
	root.slot = slot

	var sOut fuse.StatfsOut
	if errNo := root.Statfs(ctx, &sOut); errNo != 0 {
		t.Errorf("root.Statfs = %v, want 0", errNo)
	}

	root.slot.setReadOnly(true)
	var eOut fuse.EntryOut
	if _, _, _, errNo := root.Tmpfile(ctx, syscall.O_RDWR, 0o600, &eOut); errNo != syscall.EROFS {
		t.Errorf("root.Tmpfile on read-only = %v, want EROFS", errNo)
	}
	root.slot.setReadOnly(false)

	_, tmpFH, _, tmpErr := root.Tmpfile(ctx, syscall.O_RDWR, 0o600, &eOut)
	if tmpErr == 0 && tmpFH != nil {
		_ = tmpFH.(fs.FileReleaser).Release(ctx)
	}

	file1 := filepath.Join(srcDir, "source.txt")
	file2 := filepath.Join(srcDir, "dest.txt")
	_ = os.WriteFile(file1, []byte("copy-data-here\n"), 0o644)
	_ = os.WriteFile(file2, []byte("old-data-overwritten\n"), 0o644)

	srcIno, errNo := root.Lookup(ctx, "source.txt", &eOut)
	if errNo != 0 {
		t.Fatalf("Lookup source.txt: %v", errNo)
	}
	root.AddChild("source.txt", srcIno, true)

	dstIno, errNo := root.Lookup(ctx, "dest.txt", &eOut)
	if errNo != 0 {
		t.Fatalf("Lookup dest.txt: %v", errNo)
	}
	root.AddChild("dest.txt", dstIno, true)

	srcNode := srcIno.Operations().(*filteredNode)
	dstNode := dstIno.Operations().(*filteredNode)
	srcNode.slot = slot
	dstNode.slot = slot

	srcFH, _, errNo := srcNode.Open(ctx, syscall.O_RDONLY)
	if errNo != 0 {
		t.Fatalf("Open source.txt: %v", errNo)
	}
	defer srcFH.(fs.FileReleaser).Release(ctx)

	dstFH, _, errNo := dstNode.Open(ctx, syscall.O_RDWR)
	if errNo != 0 {
		t.Fatalf("Open dest.txt: %v", errNo)
	}
	defer dstFH.(fs.FileReleaser).Release(ctx)

	dstNode.slot.setReadOnly(true)
	if _, cErr := root.CopyFileRange(ctx, srcFH, 0, dstIno, dstFH, 0, 8, 0); cErr != syscall.EROFS {
		t.Errorf("CopyFileRange to read-only target = %v, want EROFS", cErr)
	}
	dstNode.slot.setReadOnly(false)

	sfDst := dstFH.(*safeFile)
	sfDst.revoke(syscall.EROFS)
	if _, cErr := root.CopyFileRange(ctx, srcFH, 0, dstIno, dstFH, 0, 8, 0); cErr != syscall.EROFS {
		t.Errorf("CopyFileRange with revoked target = %v, want EROFS", cErr)
	}
}

// TestWorkspaceHubRootMutationsAndReaddir verifies that the hub root rejects mutations and Readdir returns valid inodes.
func TestWorkspaceHubRootMutationsAndReaddir(t *testing.T) {
	ctx := context.Background()
	base := t.TempDir()
	dataDir := filepath.Join(base, "data")
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}

	dir1 := filepath.Join(base, "share1")
	dir2 := filepath.Join(base, "share2")
	_ = os.MkdirAll(dir1, 0o755)
	_ = os.MkdirAll(dir2, 0o755)

	initial := []HubShareConfig{
		{GuestName: "share1", HostPath: dir1, ReadOnly: true, VCSPolicy: config.VCSMask},
		{GuestName: "share2", HostPath: dir2, ReadOnly: false, VCSPolicy: config.VCSAllow},
	}
	hub, err := NewWorkspaceHubWithOptions(initial, HubOptions{HomeReal: base, DataDir: dataDir})
	if err != nil {
		t.Fatalf("NewWorkspaceHubWithOptions: %v", err)
	}
	defer hub.CloseAll()

	var eOut fuse.EntryOut
	var aOut fuse.AttrOut

	if _, errNo := hub.Mknod(ctx, "dev", syscall.S_IFCHR|0o600, 0, &eOut); errNo != syscall.EROFS {
		t.Errorf("hub.Mknod = %v, want EROFS", errNo)
	}
	if _, errNo := hub.Symlink(ctx, "target", "link", &eOut); errNo != syscall.EROFS {
		t.Errorf("hub.Symlink = %v, want EROFS", errNo)
	}
	if _, errNo := hub.Link(ctx, hub, "link2", &eOut); errNo != syscall.EROFS {
		t.Errorf("hub.Link = %v, want EROFS", errNo)
	}
	if errNo := hub.Unlink(ctx, "share1"); errNo != syscall.EROFS {
		t.Errorf("hub.Unlink = %v, want EROFS", errNo)
	}
	if errNo := hub.Rename(ctx, "share1", hub, "share1-new", 0); errNo != syscall.EROFS {
		t.Errorf("hub.Rename = %v, want EROFS", errNo)
	}
	if errNo := hub.Setattr(ctx, nil, &fuse.SetAttrIn{}, &aOut); errNo != syscall.EROFS {
		t.Errorf("hub.Setattr = %v, want EROFS", errNo)
	}
	if errNo := hub.Removexattr(ctx, "user.test"); errNo != syscall.EROFS {
		t.Errorf("hub.Removexattr = %v, want EROFS", errNo)
	}

	stream, errNo := hub.Readdir(ctx)
	if errNo != 0 {
		t.Fatalf("hub.Readdir = %v, want 0", errNo)
	}
	var count int
	for stream.HasNext() {
		entry, err := stream.Next()
		if err != 0 {
			t.Fatalf("stream.Next = %v", err)
		}
		count++
		if entry.Ino <= 1 {
			t.Errorf("entry %q has invalid Ino = %d, want > 1", entry.Name, entry.Ino)
		}
	}
	if count != 2 {
		t.Errorf("Readdir entries count = %d, want 2", count)
	}
}

// TestSafeFileOperations verifies safeFile operations including read-only Allocate rejection.
func TestSafeFileOperations(t *testing.T) {
	ctx := context.Background()
	srcDir, root := newTestFilteredRoot(t)

	hidden := buildHiddenSet(defaultHiddenEntries())
	slot := newShareSlot(1, "test", srcDir, false, "", root.root, hidden, false, config.VCSMask)
	root.slot = slot

	file := filepath.Join(srcDir, "testfile.txt")
	_ = os.WriteFile(file, []byte("hello world data here\n"), 0o644)

	var eOut fuse.EntryOut
	ino, errNo := root.Lookup(ctx, "testfile.txt", &eOut)
	if errNo != 0 {
		t.Fatalf("Lookup testfile.txt: %v", errNo)
	}
	root.AddChild("testfile.txt", ino, true)
	node := ino.Operations().(*filteredNode)
	node.slot = slot

	roFH, _, errNo := node.Open(ctx, syscall.O_RDONLY)
	if errNo != 0 {
		t.Fatalf("Open O_RDONLY: %v", errNo)
	}
	sfRO := roFH.(*safeFile)

	if allocErr := sfRO.Allocate(ctx, 0, 1024, 0); allocErr != syscall.EBADF {
		t.Errorf("sfRO.Allocate = %v, want EBADF", allocErr)
	}

	if err := sfRO.Flush(ctx); err != 0 {
		t.Errorf("sfRO.Flush = %v, want 0", err)
	}
	if err := sfRO.Fsync(ctx, 0); err != 0 {
		t.Errorf("sfRO.Fsync = %v, want 0", err)
	}
	if n, err := sfRO.Lseek(ctx, 5, 0); err != 0 || n != 5 {
		t.Errorf("sfRO.Lseek = (%d, %v), want (5, 0)", n, err)
	}

	var lkIn fuse.FileLock
	var lkOut fuse.FileLock
	_ = sfRO.Getlk(ctx, 1, &lkIn, 0, &lkOut)
	_ = sfRO.Setlk(ctx, 1, &lkIn, 0)
	_ = sfRO.Setlkw(ctx, 1, &lkIn, 0)

	_ = sfRO.Release(ctx)

	_, rwFH, _, errNo := root.Create(ctx, "alloc.txt", syscall.O_RDWR, 0o644, &eOut)
	if errNo != 0 {
		t.Fatalf("Create alloc.txt: %v", errNo)
	}
	sfRW := rwFH.(*safeFile)
	sfRW.revoke(syscall.EROFS)
	if allocErr := sfRW.Allocate(ctx, 0, 1024, 0); allocErr != syscall.EROFS {
		t.Errorf("sfRW.Allocate revoked = %v, want EROFS", allocErr)
	}
	_ = sfRW.Release(ctx)
}

// TestComputeStableInoZeroSlotID verifies that computeStableIno never returns 0 or 1.
func TestComputeStableInoZeroSlotID(t *testing.T) {
	for slotID := uint64(0); slotID <= 2; slotID++ {
		for dev := uint64(0); dev <= 3; dev++ {
			for rootDev := uint64(0); rootDev <= 3; rootDev++ {
				for ino := uint64(0); ino <= 5; ino++ {
					result := computeStableIno(slotID, rootDev, dev, ino)
					if result <= 1 {
						t.Errorf("computeStableIno(%d, %d, %d, %d) = %d, want > 1", slotID, rootDev, dev, ino, result)
					}
				}
			}
		}
	}
}

// TestHubControlSocketSecurityAndProtocols verifies oversized payload rejection, JSON validation, and peer UID verification.
func TestHubControlSocketSecurityAndProtocols(t *testing.T) {
	base := t.TempDir()
	dataDir := filepath.Join(base, "data")
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}

	hub, err := NewWorkspaceHubWithOptions(nil, HubOptions{HomeReal: base, DataDir: dataDir})
	if err != nil {
		t.Fatalf("NewWorkspaceHubWithOptions: %v", err)
	}
	defer hub.CloseAll()

	sockPath := filepath.Join(base, "ws.sock")
	ln, err := listenVerifiedUnixSocket(sockPath, hub)
	if err != nil {
		t.Fatalf("listenVerifiedUnixSocket: %v", err)
	}
	defer ln.Close()

	addr := &net.UnixAddr{Name: sockPath, Net: "unix"}
	conn, err := net.DialUnix("unix", nil, addr)
	if err != nil {
		t.Fatalf("Dial ws.sock: %v", err)
	}
	bigBuf := make([]byte, maxHubControlBytes+100)
	for i := range bigBuf {
		bigBuf[i] = 'a'
	}
	_, _ = conn.Write(bigBuf)
	_ = conn.CloseWrite()
	var resp hubControlResponse
	_ = json.NewDecoder(conn).Decode(&resp)
	conn.Close()
	if resp.OK {
		t.Error("expected oversized payload to be rejected")
	}

	conn2, err := net.DialUnix("unix", nil, addr)
	if err != nil {
		t.Fatalf("Dial ws.sock: %v", err)
	}
	_, _ = conn2.Write([]byte("{invalid json\n"))
	_ = conn2.CloseWrite()
	var resp2 hubControlResponse
	_ = json.NewDecoder(conn2).Decode(&resp2)
	conn2.Close()
	if resp2.OK || !strings.Contains(resp2.Error, "invalid JSON") {
		t.Errorf("expected invalid JSON rejection, got %+v", resp2)
	}

	conn3, err := net.DialUnix("unix", nil, addr)
	if err != nil {
		t.Fatalf("Dial ws.sock: %v", err)
	}
	_, _ = conn3.Write([]byte(`{"op":"unknown_test_op"}` + "\n"))
	_ = conn3.CloseWrite()
	var resp3 hubControlResponse
	_ = json.NewDecoder(conn3).Decode(&resp3)
	conn3.Close()
	if resp3.OK || !strings.Contains(resp3.Error, "unknown hub operation") {
		t.Errorf("expected unknown operation rejection, got %+v", resp3)
	}

	uConn, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: sockPath, Net: "unix"})
	if err != nil {
		t.Fatalf("DialUnix: %v", err)
	}
	defer uConn.Close()

	if err := verifyPeerUID(uConn, uint32(os.Geteuid())); err != nil {
		t.Errorf("verifyPeerUID matching UID failed: %v", err)
	}
	if err := verifyPeerUID(uConn, uint32(os.Geteuid())+9999); err == nil {
		t.Error("verifyPeerUID mismatched UID want error, got nil")
	}
}

// TestWorkspaceHubConcurrentSharesAndIO runs concurrent share modifications and file operations under race detector.
func TestWorkspaceHubConcurrentSharesAndIO(t *testing.T) {
	ctx := context.Background()
	base := t.TempDir()
	dataDir := filepath.Join(base, "data")
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}

	projDir := filepath.Join(base, "proj")
	if err := os.MkdirAll(projDir, 0o755); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(projDir, "main.go"), []byte("package main\n"), 0o644)

	initial := []HubShareConfig{
		{GuestName: "proj", HostPath: projDir, ReadOnly: false, VCSPolicy: config.VCSMask},
	}
	hub, err := NewWorkspaceHubWithOptions(initial, HubOptions{HomeReal: base, DataDir: dataDir})
	if err != nil {
		t.Fatalf("NewWorkspaceHubWithOptions: %v", err)
	}
	defer hub.CloseAll()
	_ = fs.NewNodeFS(hub, &fs.Options{})

	sockPath := filepath.Join(base, "ws.sock")
	ln, err := listenVerifiedUnixSocket(sockPath, hub)
	if err != nil {
		t.Fatalf("listenVerifiedUnixSocket: %v", err)
	}
	defer ln.Close()

	var wg sync.WaitGroup
	stop := make(chan struct{})

	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			shareName := fmt.Sprintf("dyn%d", id)
			dir := filepath.Join(base, shareName)
			_ = os.MkdirAll(dir, 0o755)
			_ = os.WriteFile(filepath.Join(dir, "data.txt"), []byte("hello\n"), 0o644)

			ro := true
			rw := false
			vcsAllow := config.VCSAllow
			vcsMask := config.VCSMask

			for {
				select {
				case <-stop:
					return
				default:
				}
				_, _ = AddHubShare(sockPath, HubShareConfig{
					GuestName: shareName,
					HostPath:  dir,
					ReadOnly:  false,
					VCSPolicy: config.VCSMask,
				})
				_, _ = SetHubShare(sockPath, shareName, &ro, nil, true)
				_, _ = SetHubShare(sockPath, shareName, &rw, &vcsAllow, true)
				_, _ = SetHubShare(sockPath, shareName, nil, &vcsMask, true)
				_ = RemoveHubShare(sockPath, shareName, true)
				time.Sleep(2 * time.Millisecond)
			}
		}(i)
	}

	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var eOut fuse.EntryOut
			for {
				select {
				case <-stop:
					return
				default:
				}
				_ = hub.listShares()
				stream, errNo := hub.Readdir(ctx)
				if errNo == 0 && stream != nil {
					for stream.HasNext() {
						_, _ = stream.Next()
					}
				}
				_, _ = hub.Lookup(ctx, "proj", &eOut)
				time.Sleep(2 * time.Millisecond)
			}
		}()
	}

	time.Sleep(300 * time.Millisecond)
	close(stop)
	wg.Wait()
}

// TestCheckHostSupport verifies FUSE host support checks including error paths.
func TestCheckHostSupport(t *testing.T) {
	base := t.TempDir()

	t.Run("empty directory path", func(t *testing.T) {
		err := CheckHostSupport("")
		if err == nil {
			t.Fatal("expected error for empty parent directory")
		}
	})

	t.Run("missing directory path", func(t *testing.T) {
		err := CheckHostSupport(filepath.Join(base, "missing-dir"))
		if err == nil {
			t.Fatal("expected error for missing parent directory")
		}
	})

	t.Run("non-directory parent path", func(t *testing.T) {
		filePath := filepath.Join(base, "file-not-dir")
		if err := os.WriteFile(filePath, []byte("probe"), 0o600); err != nil {
			t.Fatal(err)
		}
		err := CheckHostSupport(filePath)
		if err == nil {
			t.Fatal("expected error for non-directory parent path")
		}
	})

	t.Run("invalid mount point", func(t *testing.T) {
		if _, err := mount("", "", nil); err == nil {
			t.Fatal("expected error for empty mount paths")
		}
		if _, err := mount(base, filepath.Join(base, "non-existent-mnt"), nil); err == nil {
			t.Fatal("expected error for non-existent mountpoint")
		}
	})

	t.Run("live mount check", func(t *testing.T) {
		validDir := filepath.Join(base, "probe-parent")
		if err := os.MkdirAll(validDir, 0o700); err != nil {
			t.Fatal(err)
		}
		err := CheckHostSupport(validDir)
		if err != nil {
			t.Skipf("skipping live mount check: %v", err)
		}
	})
}

// TestFilteredNodeGetattrSetattrFsyncdir verifies Getattr, Setattr timestamp handling, and Fsyncdir.
func TestFilteredNodeGetattrSetattrFsyncdir(t *testing.T) {
	ctx := context.Background()
	srcDir, root := newTestFilteredRoot(t)

	// Test FilteredNode.Getattr directly on root directory.
	var rootAttr fuse.AttrOut
	if errno := root.Getattr(ctx, nil, &rootAttr); errno != 0 {
		t.Fatalf("root.Getattr failed: %v", errno)
	}
	if (rootAttr.Mode & syscall.S_IFDIR) == 0 {
		t.Errorf("expected directory mode on root, got %o", rootAttr.Mode)
	}

	// Create test file in share.
	testFile := filepath.Join(srcDir, "attr-test.txt")
	if err := os.WriteFile(testFile, []byte("hello world\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	var eOut fuse.EntryOut
	ino, errno := root.Lookup(ctx, "attr-test.txt", &eOut)
	if errno != 0 {
		t.Fatalf("root.Lookup(attr-test.txt): %v", errno)
	}
	root.AddChild("attr-test.txt", ino, true)
	fileNode := ino.Operations().(*filteredNode)

	// Test FilteredNode.Getattr directly on regular file.
	var fileAttr fuse.AttrOut
	if errno := fileNode.Getattr(ctx, nil, &fileAttr); errno != 0 {
		t.Fatalf("fileNode.Getattr failed: %v", errno)
	}
	if fileAttr.Size != 12 {
		t.Errorf("fileNode.Getattr size = %d, want 12", fileAttr.Size)
	}

	// Test FilteredNode.Setattr with FATTR_ATIME and FATTR_MTIME to exercise buildTimespecs.
	targetTime := time.Now().Add(-2 * time.Hour).Truncate(time.Second)
	var setIn fuse.SetAttrIn
	setIn.Valid = fuse.FATTR_ATIME | fuse.FATTR_MTIME
	setIn.Atime = uint64(targetTime.Unix())
	setIn.Atimensec = uint32(targetTime.Nanosecond())
	setIn.Mtime = uint64(targetTime.Unix())
	setIn.Mtimensec = uint32(targetTime.Nanosecond())

	var setOut fuse.AttrOut
	if errno := fileNode.Setattr(ctx, nil, &setIn, &setOut); errno != 0 {
		t.Fatalf("fileNode.Setattr with atime/mtime failed: %v", errno)
	}
	if setOut.Mtime != uint64(targetTime.Unix()) {
		t.Errorf("setOut.Mtime = %d, want %d", setOut.Mtime, targetTime.Unix())
	}

	// Test filteredDir.Fsyncdir.
	dirFH, _, odErrno := root.OpendirHandle(ctx, 0)
	if odErrno != 0 {
		t.Fatalf("root.OpendirHandle failed: %v", odErrno)
	}
	fDir := dirFH.(*filteredDir)

	// Call Fsyncdir on active directory handle.
	_ = fDir.Fsyncdir(ctx, 0)

	// Revoke directory handle and verify Fsyncdir returns revocation error.
	fDir.revoke(syscall.ESTALE)
	if errno := fDir.Fsyncdir(ctx, 0); errno != syscall.ESTALE {
		t.Errorf("fDir.Fsyncdir when revoked = %v, want ESTALE", errno)
	}
	fDir.Releasedir(ctx, 0)
}

func TestCopyUnixStatAndStatxFallback(t *testing.T) {
	u := unix.Stat_t{
		Dev:     42,
		Ino:     12345,
		Nlink:   2,
		Mode:    syscall.S_IFREG | 0o640,
		Uid:     1000,
		Gid:     1000,
		Rdev:    7,
		Size:    8192,
		Blksize: 4096,
		Blocks:  16,
		Atim:    unix.Timespec{Sec: 100, Nsec: 200},
		Mtim:    unix.Timespec{Sec: 300, Nsec: 400},
		Ctim:    unix.Timespec{Sec: 500, Nsec: 600},
	}
	var st syscall.Stat_t
	copyUnixStat(&u, &st)
	if st.Dev != 42 || st.Ino != 12345 || st.Nlink != 2 || st.Mode != u.Mode || st.Size != 8192 || st.Mtim.Sec != 300 || st.Mtim.Nsec != 400 {
		t.Fatalf("copyUnixStat mismatch: got %+v", st)
	}
}

func TestH1VCSAllowConfigPointerSubtreeAndWhiteoutProtection(t *testing.T) {
	ctx := context.Background()
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	dataDir := filepath.Join(base, "data")
	repoDir := filepath.Join(base, "repo")

	for _, d := range []string{
		dataDir,
		filepath.Join(repoDir, ".git", "hooks"),
		filepath.Join(repoDir, ".git", "modules", "sub"),
		filepath.Join(repoDir, ".git", "worktrees", "wt1"),
		filepath.Join(repoDir, ".jj", "repo"),
		filepath.Join(repoDir, ".sl"),
		filepath.Join(repoDir, ".bzr", "branch"),
		filepath.Join(repoDir, ".hg", "hgrc.d"),
		filepath.Join(repoDir, "sub"),
		filepath.Join(repoDir, "stage", "hooks"),
	} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for rel, content := range map[string]string{
		"main.go":                   "package main\n",
		".git/config":               "[core]\n",
		".git/commondir":            "../..\n",
		".git/modules/sub/config":   "[core]\n",
		".git/worktrees/wt1/config": "[core]\n",
		".git/hooks/pre-commit":     "#!/bin/sh\nexit 0\n",
		".jj/repo/config.toml":      "[user]\n",
		".sl/config":                "[ui]\n",
		".bzr/branch/branch.conf":   "parent_location = .\n",
		".hg/hgrc.d/custom.rc":      "[hooks]\n",
		"stage/hooks/pre-commit":    "#!/bin/sh\nid\n",
		"stage/config":              "[core]\n\thooksPath = /tmp\n",
		".deleted-note.txt":         "visible-note\n",
	} {
		if err := os.WriteFile(filepath.Join(repoDir, rel), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	hub, err := NewWorkspaceHubWithOptions([]HubShareConfig{
		{GuestName: "repo", HostPath: repoDir, ReadOnly: false, VCSPolicy: config.VCSAllow},
	}, HubOptions{
		HomeReal: base,
		DataDir:  dataDir,
	})
	if err != nil {
		t.Fatalf("NewWorkspaceHubWithOptions: %v", err)
	}
	defer hub.CloseAll()

	slot := hub.slots["repo"]
	var sySt syscall.Stat_t
	_ = syscall.Stat(repoDir, &sySt)
	repoRoot := buildRootFilteredNode(repoDir, slot.root, sySt, slot)
	_ = fs.NewNodeFS(repoRoot, &fs.Options{})

	lookupAttach := func(parent *filteredNode, parts ...string) *filteredNode {
		t.Helper()
		cur := parent
		var eOut fuse.EntryOut
		for _, p := range parts {
			ino, lErr := cur.Lookup(ctx, p, &eOut)
			if lErr != 0 {
				t.Fatalf("Lookup(%q): %v", p, lErr)
			}
			cur.AddChild(p, ino, true)
			cur = ino.Operations().(*filteredNode)
		}
		return cur
	}

	// Verify .deleted-note.txt is NOT spuriously hidden by stale .deleted prefix checks.
	delNode := lookupAttach(repoRoot, ".deleted-note.txt")
	delFH, _, dOpenErr := delNode.Open(ctx, syscall.O_RDONLY)
	if dOpenErr != 0 {
		t.Fatalf("Open(.deleted-note.txt) = %v, want 0", dOpenErr)
	}
	_ = delFH.(fs.FileReleaser).Release(ctx)

	// 1. Executable VCS config files are write-protected under VCSAllow, and safeFile.Getattr masks 0o222 ([L1]).
	for _, cfgParts := range [][]string{
		{".git", "config"},
		{".git", "commondir"},
		{".git", "modules", "sub", "config"},
		{".git", "worktrees", "wt1", "config"},
		{".jj", "repo", "config.toml"},
		{".sl", "config"},
		{".bzr", "branch", "branch.conf"},
		{".hg", "hgrc.d", "custom.rc"},
		{".git", "hooks", "pre-commit"},
	} {
		parentNode := lookupAttach(repoRoot, cfgParts[:len(cfgParts)-1]...)
		leaf := cfgParts[len(cfgParts)-1]
		leafNode := lookupAttach(parentNode, leaf)

		if _, _, oErr := leafNode.Open(ctx, syscall.O_RDWR); oErr != syscall.EPERM {
			t.Errorf("Open(%v, O_RDWR) = %v, want EPERM", cfgParts, oErr)
		}
		if uErr := parentNode.Unlink(ctx, leaf); uErr != syscall.EPERM {
			t.Errorf("Unlink(%v) = %v, want EPERM", cfgParts, uErr)
		}
		var sOut fuse.AttrOut
		setIn := fuse.SetAttrIn{}
		setIn.Valid = fuse.FATTR_SIZE
		setIn.Size = 0
		if sErr := leafNode.Setattr(ctx, nil, &setIn, &sOut); sErr != syscall.EPERM {
			t.Errorf("Setattr(%v) = %v, want EPERM", cfgParts, sErr)
		}

		roFH, _, oErr := leafNode.Open(ctx, syscall.O_RDONLY)
		if oErr != 0 {
			t.Fatalf("Open(%v, O_RDONLY) = %v, want 0", cfgParts, oErr)
		}
		sf := roFH.(*safeFile)
		if gErr := sf.Getattr(ctx, &sOut); gErr != 0 {
			t.Fatalf("safeFile.Getattr(%v) = %v", cfgParts, gErr)
		}
		if sOut.Mode&0o222 != 0 {
			t.Errorf("safeFile.Getattr(%v) mode = %o, want write bits masked", cfgParts, sOut.Mode)
		}
		_ = sf.Release(ctx)
	}

	// 2. Create, Mknod, Link, and Symlink of nested .git pointer files fail with EPERM under VCSAllow.
	subNode := lookupAttach(repoRoot, "sub")
	mainNode := lookupAttach(repoRoot, "main.go")
	var eOut fuse.EntryOut
	if _, _, _, cErr := subNode.Create(ctx, ".git", syscall.O_RDWR, 0o644, &eOut); cErr != syscall.EPERM {
		t.Errorf("subNode.Create(.git) = %v, want EPERM", cErr)
	}
	if _, mErr := subNode.Mknod(ctx, ".git", syscall.S_IFREG|0o644, 0, &eOut); mErr != syscall.EPERM {
		t.Errorf("subNode.Mknod(.git) = %v, want EPERM", mErr)
	}
	if _, lErr := subNode.Link(ctx, mainNode, ".git", &eOut); lErr != syscall.EPERM {
		t.Errorf("subNode.Link(.git) = %v, want EPERM", lErr)
	}
	if _, sErr := subNode.Symlink(ctx, "../main.go", ".git", &eOut); sErr != syscall.EPERM {
		t.Errorf("subNode.Symlink(.git) = %v, want EPERM", sErr)
	}

	// 3. RENAME_WHITEOUT fails with EPERM, and conflicting/unknown rename flags fail with EINVAL.
	if wErr := repoRoot.Rename(ctx, "main.go", repoRoot, "main2.go", unix.RENAME_WHITEOUT); wErr != syscall.EPERM {
		t.Errorf("Rename(RENAME_WHITEOUT) = %v, want EPERM", wErr)
	}
	if iErr := repoRoot.Rename(ctx, "main.go", repoRoot, "main2.go", unix.RENAME_NOREPLACE|unix.RENAME_EXCHANGE); iErr != syscall.EINVAL {
		t.Errorf("Rename(NOREPLACE|EXCHANGE) = %v, want EINVAL", iErr)
	}
	if iErr := repoRoot.Rename(ctx, "main.go", repoRoot, "main2.go", 1<<15); iErr != syscall.EINVAL {
		t.Errorf("Rename(unknown flag) = %v, want EINVAL", iErr)
	}

	// 4. Subtree Rename of staged directory containing hooks/config into .git/modules fails with EPERM.
	gitModulesNode := lookupAttach(repoRoot, ".git", "modules")
	if rErr := repoRoot.Rename(ctx, "stage", gitModulesNode, "planted", 0); rErr != syscall.EPERM {
		t.Errorf("Rename(stage -> .git/modules/planted) = %v, want EPERM", rErr)
	}
	// Moving .git/modules/sub (which contains protected config) to another name inside .git/modules also fails with EPERM.
	if rErr := gitModulesNode.Rename(ctx, "sub", gitModulesNode, "sub-moved", 0); rErr != syscall.EPERM {
		t.Errorf("Rename(.git/modules/sub -> sub-moved) = %v, want EPERM", rErr)
	}
}

func TestH2SymlinkDepthReductionAndExchangeRename(t *testing.T) {
	ctx := context.Background()
	srcDir, root := newTestFilteredRoot(t)

	for _, d := range []string{
		filepath.Join(srcDir, "a", "b", "c", "dir"),
	} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(srcDir, "main.go"), []byte("package main\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(srcDir, "peer.go"), []byte("package peer\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	lookupAttach := func(parent *filteredNode, parts ...string) *filteredNode {
		t.Helper()
		cur := parent
		var eOut fuse.EntryOut
		for _, p := range parts {
			ino, lErr := cur.Lookup(ctx, p, &eOut)
			if lErr != 0 {
				t.Fatalf("Lookup(%q): %v", p, lErr)
			}
			cur.AddChild(p, ino, true)
			cur = ino.Operations().(*filteredNode)
		}
		return cur
	}

	nodeA := lookupAttach(root, "a")
	nodeB := lookupAttach(nodeA, "b")
	nodeC := lookupAttach(nodeB, "c")
	nodeDir := lookupAttach(nodeC, "dir")

	var eOut fuse.EntryOut
	// Valid relative symlink at depth 3: ../../../main.go
	symIno, sErr := nodeC.Symlink(ctx, "../../../main.go", "escape", &eOut)
	if sErr != 0 {
		t.Fatalf("nodeC.Symlink(escape -> ../../../main.go): %v", sErr)
	}
	nodeC.AddChild("escape", symIno, true)

	// Moving escape to depth 0, 1, or 2 must fail with EPERM because ../../../ escapes above share root!
	if rErr := nodeC.Rename(ctx, "escape", root, "escape", 0); rErr != syscall.EPERM {
		t.Errorf("Rename(a/b/c/escape -> escape) = %v, want EPERM", rErr)
	}
	if rErr := nodeC.Rename(ctx, "escape", nodeA, "escape", 0); rErr != syscall.EPERM {
		t.Errorf("Rename(a/b/c/escape -> a/escape) = %v, want EPERM", rErr)
	}
	if rErr := nodeC.Rename(ctx, "escape", nodeB, "escape", 0); rErr != syscall.EPERM {
		t.Errorf("Rename(a/b/c/escape -> a/b/escape) = %v, want EPERM", rErr)
	}
	// RENAME_EXCHANGE with root file must also fail with EPERM!
	if rErr := nodeC.Rename(ctx, "escape", root, "peer.go", unix.RENAME_EXCHANGE); rErr != syscall.EPERM {
		t.Errorf("Rename(RENAME_EXCHANGE a/b/c/escape <-> peer.go) = %v, want EPERM", rErr)
	}
	// Moving escape at the same depth (depth 3) succeeds!
	if rErr := nodeC.Rename(ctx, "escape", nodeC, "same_depth_ok", 0); rErr != 0 {
		t.Fatalf("Rename(a/b/c/escape -> a/b/c/same_depth_ok) = %v, want 0", rErr)
	}

	// Subtree symlink at depth 4: ../../../../main.go inside a/b/c/dir/link
	subSymIno, sErr := nodeDir.Symlink(ctx, "../../../../main.go", "link", &eOut)
	if sErr != 0 {
		t.Fatalf("nodeDir.Symlink(link): %v", sErr)
	}
	nodeDir.AddChild("link", subSymIno, true)
	if rErr := nodeC.Rename(ctx, "dir", root, "moved_dir", 0); rErr != syscall.EPERM {
		t.Errorf("Rename(a/b/c/dir -> moved_dir) = %v, want EPERM", rErr)
	}

	// Valid RENAME_EXCHANGE between two regular files at root succeeds.
	if rErr := root.Rename(ctx, "main.go", root, "peer.go", unix.RENAME_EXCHANGE); rErr != 0 {
		t.Errorf("Rename(RENAME_EXCHANGE main.go <-> peer.go) = %v, want 0", rErr)
	}
}

func TestH4RegisterRaceAndOpenFDRenameRevocation(t *testing.T) {
	ctx := context.Background()
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	dataDir := filepath.Join(base, "data")
	repoDir := filepath.Join(base, "repo")
	if err := os.MkdirAll(filepath.Join(repoDir, ".git", "hooks"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repoDir, "normal.txt"), []byte("hello\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	hub, err := NewWorkspaceHubWithOptions([]HubShareConfig{
		{GuestName: "repo", HostPath: repoDir, ReadOnly: false, VCSPolicy: config.VCSAllow},
	}, HubOptions{HomeReal: base, DataDir: dataDir})
	if err != nil {
		t.Fatal(err)
	}
	defer hub.CloseAll()

	sockPath := filepath.Join(base, "ws.sock")
	ln, err := listenVerifiedUnixSocket(sockPath, hub)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	slot := hub.slots["repo"]

	// 1. Direct registerFile and registerDir policy checks ([H4] part 1).
	slot.setVCSPolicy(config.VCSMask)
	vcsSF := &safeFile{writable: false}
	vcsSF.isVCS.Store(true)
	if regErr := slot.registerFile(vcsSF); regErr != syscall.ESTALE {
		t.Errorf("registerFile(isVCS under VCSMask) = %v, want ESTALE", regErr)
	}
	vcsDir := &filteredDir{}
	vcsDir.isVCS.Store(true)
	if regErr := slot.registerDir(vcsDir); regErr != syscall.ESTALE {
		t.Errorf("registerDir(isVCS under VCSMask) = %v, want ESTALE", regErr)
	}

	slot.setVCSPolicy(config.VCSAllow)
	hookSF := &safeFile{writable: true}
	hookSF.isHook.Store(true)
	if regErr := slot.registerFile(hookSF); regErr != syscall.EROFS {
		t.Errorf("registerFile(writable isHook under VCSAllow) = %v, want EROFS", regErr)
	}

	// 2. Open normal.txt writable (isVCS=false), rename to .git/HEAD, then downgrade to VCSMask ([H4] part 2).
	var sySt syscall.Stat_t
	_ = syscall.Stat(repoDir, &sySt)
	repoRoot := buildRootFilteredNode(repoDir, slot.root, sySt, slot)
	_ = fs.NewNodeFS(repoRoot, &fs.Options{})

	var eOut fuse.EntryOut
	normIno, errNo := repoRoot.Lookup(ctx, "normal.txt", &eOut)
	if errNo != 0 {
		t.Fatalf("Lookup(normal.txt): %v", errNo)
	}
	repoRoot.AddChild("normal.txt", normIno, true)
	normNode := normIno.Operations().(*filteredNode)

	gitIno, errNo := repoRoot.Lookup(ctx, ".git", &eOut)
	if errNo != 0 {
		t.Fatalf("Lookup(.git): %v", errNo)
	}
	repoRoot.AddChild(".git", gitIno, true)
	gitNode := gitIno.Operations().(*filteredNode)

	fh, _, errNo := normNode.Open(ctx, syscall.O_RDWR)
	if errNo != 0 {
		t.Fatalf("Open(normal.txt): %v", errNo)
	}
	sf := fh.(*safeFile)
	defer sf.Release(ctx)

	if slot.openWritableVCSCount() != 0 {
		t.Fatalf("expected 0 writable VCS handles before rename, got %d", slot.openWritableVCSCount())
	}
	if rErr := repoRoot.Rename(ctx, "normal.txt", gitNode, "HEAD", 0); rErr != 0 {
		t.Fatalf("Rename(normal.txt -> .git/HEAD): %v", rErr)
	}
	if slot.openWritableVCSCount() != 1 {
		t.Fatalf("expected 1 writable VCS handle after rename into .git/HEAD, got %d", slot.openWritableVCSCount())
	}

	vcsMask := config.VCSMask
	if _, err := SetHubShare(sockPath, "repo", nil, &vcsMask, false); err == nil || !strings.Contains(err.Error(), "open writable") {
		t.Fatalf("expected non-forced downgrade to VCSMask to fail on renamed handle, got %v", err)
	}
	if _, err := SetHubShare(sockPath, "repo", nil, &vcsMask, true); err != nil {
		t.Fatalf("forced SetHubShare(VCSMask) failed: %v", err)
	}
	if _, wErr := sf.Write(ctx, []byte("after"), 0); wErr != syscall.ESTALE {
		t.Errorf("sf.Write after forced VCSMask downgrade = %v, want ESTALE", wErr)
	}

	// 3. Under VCSAllowHooks, open .git/config.lock writable, rename to .git/config, downgrade to VCSAllow -> EROFS.
	vcsHooks := config.VCSAllowHooks
	vcsAllow := config.VCSAllow
	if _, err := SetHubShare(sockPath, "repo", nil, &vcsHooks, true); err != nil {
		t.Fatal(err)
	}
	gitIno2, errNo := repoRoot.Lookup(ctx, ".git", &eOut)
	if errNo != 0 {
		t.Fatalf("Lookup(.git) under VCSAllowHooks: %v", errNo)
	}
	repoRoot.AddChild(".git", gitIno2, true)
	gitNode2 := gitIno2.Operations().(*filteredNode)

	_, lockFH, _, cErr := gitNode2.Create(ctx, "config.lock", syscall.O_RDWR, 0o600, &eOut)
	if cErr != 0 {
		t.Fatalf("Create(.git/config.lock): %v", cErr)
	}
	lockSF := lockFH.(*safeFile)
	defer lockSF.Release(ctx)

	if slot.openWritableHookCount() != 0 {
		t.Fatalf("expected 0 writable hook handles before rename, got %d", slot.openWritableHookCount())
	}
	if rErr := gitNode2.Rename(ctx, "config.lock", gitNode2, "config", 0); rErr != 0 {
		t.Fatalf("Rename(.git/config.lock -> .git/config): %v", rErr)
	}
	if slot.openWritableHookCount() != 1 {
		t.Fatalf("expected 1 writable hook handle after rename to .git/config, got %d", slot.openWritableHookCount())
	}
	if _, err := SetHubShare(sockPath, "repo", nil, &vcsAllow, false); err == nil || !strings.Contains(err.Error(), "open writable") {
		t.Fatalf("expected non-forced downgrade to VCSAllow to fail, got %v", err)
	}
	if _, err := SetHubShare(sockPath, "repo", nil, &vcsAllow, true); err != nil {
		t.Fatalf("forced SetHubShare(VCSAllow) failed: %v", err)
	}
	if _, wErr := lockSF.Write(ctx, []byte("evil"), 0); wErr != syscall.EROFS {
		t.Errorf("lockSF.Write after forced VCSAllow downgrade = %v, want EROFS", wErr)
	}
}

func TestH7NonBlockingFIFOSetattrAndXattrOnSpecialNodes(t *testing.T) {
	ctx := context.Background()
	srcDir, root := newTestFilteredRoot(t)

	fifoPath := filepath.Join(srcDir, "blocking.fifo")
	if err := syscall.Mkfifo(fifoPath, 0o600); err != nil {
		t.Skipf("Mkfifo unsupported: %v", err)
	}

	var eOut fuse.EntryOut
	fifoIno, lErr := root.Lookup(ctx, "blocking.fifo", &eOut)
	if lErr != 0 {
		t.Fatalf("Lookup(blocking.fifo): %v", lErr)
	}
	root.AddChild("blocking.fifo", fifoIno, true)
	fifoNode := fifoIno.Operations().(*filteredNode)

	// Open WITHOUT O_NONBLOCK and Create onto existing FIFO must return EPERM without blocking!
	done := make(chan struct{})
	go func() {
		defer close(done)
		if _, _, errNo := fifoNode.Open(ctx, syscall.O_RDONLY); errNo != syscall.EPERM {
			t.Errorf("fifoNode.Open(O_RDONLY without O_NONBLOCK) = %v, want EPERM", errNo)
		}
		if _, _, errNo := fifoNode.Open(ctx, syscall.O_WRONLY); errNo != syscall.EPERM {
			t.Errorf("fifoNode.Open(O_WRONLY without O_NONBLOCK) = %v, want EPERM", errNo)
		}
		if _, _, _, errNo := root.Create(ctx, "blocking.fifo", syscall.O_WRONLY|syscall.O_TRUNC, 0o644, &eOut); errNo != syscall.EPERM {
			t.Errorf("root.Create(existing FIFO without O_EXCL) = %v, want EPERM", errNo)
		}
		pr, _, pErr := newPinnedRoot(srcDir)
		if pErr == nil {
			defer pr.Close()
			fSlot := newShareSlot(9, "blocking.fifo", fifoPath, true, "blocking.fifo", pr, root.hidden, false, config.VCSMask)
			fNode := &fileShareNode{slot: fSlot}
			if _, _, errNo := fNode.Open(ctx, syscall.O_RDONLY); errNo != syscall.EPERM {
				t.Errorf("fileShareNode.Open(FIFO) = %v, want EPERM", errNo)
			}
		}
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("FIFO Open/Create blocked host FUSE thread instead of failing closed via O_PATH")
	}

	// Setattr and all xattr operations on FIFO reject non-regular/non-dir node with EPERM.
	var aOut fuse.AttrOut
	setIn := fuse.SetAttrIn{}
	setIn.Valid = fuse.FATTR_MODE
	setIn.Mode = 0o644
	if errNo := fifoNode.Setattr(ctx, nil, &setIn, &aOut); errNo != syscall.EPERM {
		t.Errorf("fifoNode.Setattr = %v, want EPERM", errNo)
	}
	if _, errNo := fifoNode.Getxattr(ctx, "user.tag", make([]byte, 8)); errNo != syscall.EPERM {
		t.Errorf("fifoNode.Getxattr = %v, want EPERM", errNo)
	}
	if _, errNo := fifoNode.Listxattr(ctx, nil); errNo != syscall.EPERM {
		t.Errorf("fifoNode.Listxattr = %v, want EPERM", errNo)
	}
	if errNo := fifoNode.Setxattr(ctx, "user.tag", []byte("1"), 0); errNo != syscall.EPERM {
		t.Errorf("fifoNode.Setxattr = %v, want EPERM", errNo)
	}
	if errNo := fifoNode.Removexattr(ctx, "user.tag"); errNo != syscall.EPERM {
		t.Errorf("fifoNode.Removexattr = %v, want EPERM", errNo)
	}
}

func TestH8AndM4ConcurrentRevokeReaddirentAndCopyFileRange(t *testing.T) {
	ctx := context.Background()
	srcDir, root := newTestFilteredRoot(t)
	slot := newShareSlot(1, "race", srcDir, false, "", root.root, root.hidden, false, config.VCSMask)
	root.slot = slot

	for i := 0; i < 20; i++ {
		if err := os.WriteFile(filepath.Join(srcDir, fmt.Sprintf("f%02d.txt", i)), []byte("0123456789abcdef"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	// 1. [H8] Concurrent Readdirent / Seekdir / Fsyncdir vs revoke under -race.
	for round := 0; round < 10; round++ {
		fh, _, odErr := root.OpendirHandle(ctx, 0)
		if odErr != 0 {
			t.Fatalf("OpendirHandle: %v", odErr)
		}
		d := fh.(*filteredDir)
		var wg sync.WaitGroup
		for g := 0; g < 4; g++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for k := 0; k < 10; k++ {
					_, _ = d.Readdirent(ctx)
					_ = d.Seekdir(ctx, 0)
					_ = d.Fsyncdir(ctx, 0)
				}
			}()
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			d.revoke(syscall.ESTALE)
		}()
		wg.Wait()
		d.Releasedir(ctx, 0)
	}

	// 2. [M4] Concurrent opposite-direction CopyFileRange (A->B and B->A) + revoke without AB-BA deadlock.
	var eOut fuse.EntryOut
	inoA, errNo := root.Lookup(ctx, "f00.txt", &eOut)
	if errNo != 0 {
		t.Fatal(errNo)
	}
	root.AddChild("f00.txt", inoA, true)
	nodeA := inoA.Operations().(*filteredNode)
	nodeA.slot = slot

	inoB, errNo := root.Lookup(ctx, "f01.txt", &eOut)
	if errNo != 0 {
		t.Fatal(errNo)
	}
	root.AddChild("f01.txt", inoB, true)
	nodeB := inoB.Operations().(*filteredNode)
	nodeB.slot = slot

	fhA, _, errNo := nodeA.Open(ctx, syscall.O_RDWR)
	if errNo != 0 {
		t.Fatal(errNo)
	}
	fhB, _, errNo := nodeB.Open(ctx, syscall.O_RDWR)
	if errNo != 0 {
		t.Fatal(errNo)
	}
	sfA := fhA.(*safeFile)
	sfB := fhB.(*safeFile)

	done := make(chan struct{})
	go func() {
		var wg sync.WaitGroup
		wg.Add(3)
		go func() {
			defer wg.Done()
			for i := 0; i < 30; i++ {
				_, _ = root.CopyFileRange(ctx, sfA, 0, inoB, sfB, 0, 4, 0)
			}
		}()
		go func() {
			defer wg.Done()
			for i := 0; i < 30; i++ {
				_, _ = root.CopyFileRange(ctx, sfB, 0, inoA, sfA, 0, 4, 0)
			}
		}()
		go func() {
			defer wg.Done()
			time.Sleep(2 * time.Millisecond)
			sfA.revoke(syscall.ESTALE)
			sfB.revoke(syscall.ESTALE)
		}()
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("CopyFileRange deadlocked under concurrent opposite-direction copies and revoke")
	}
	_ = sfA.Release(ctx)
	_ = sfB.Release(ctx)
}

func TestM1M2HubContainmentDecodeSpecAndNodeOperations(t *testing.T) {
	ctx := context.Background()
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	outsideBase, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	homeDir := filepath.Join(base, "home")
	dataDir := filepath.Join(homeDir, ".local", "share", "agbox")
	msbHome := filepath.Join(base, "custom-msb")
	repoDir := filepath.Join(homeDir, "repo")
	repoDir2 := filepath.Join(homeDir, "repo2")
	outsideProj := filepath.Join(outsideBase, "outside-proj")
	msbSub := filepath.Join(msbHome, "sandboxes")
	hardA := filepath.Join(homeDir, "hardA.txt")
	hardB := filepath.Join(homeDir, "hardB.txt")

	for _, d := range []string{
		dataDir,
		msbSub,
		filepath.Join(repoDir, ".GIT"),
		filepath.Join(repoDir, "sub", ".git"),
		repoDir2,
		outsideProj,
	} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	_ = os.WriteFile(filepath.Join(repoDir, ".GIT", "HEAD"), []byte("ref: main\n"), 0o644)
	_ = os.WriteFile(filepath.Join(repoDir, "sub", ".git", "HEAD"), []byte("ref: sub\n"), 0o644)
	_ = os.WriteFile(filepath.Join(repoDir, "sub", ".gitignore"), []byte("*.tmp\n"), 0o644)
	_ = os.WriteFile(filepath.Join(repoDir, "file.txt"), []byte("hello world\n"), 0o644)
	_ = os.WriteFile(filepath.Join(repoDir2, "second.txt"), []byte("v2\n"), 0o644)
	_ = os.WriteFile(hardA, []byte("hard\n"), 0o600)
	if err := os.Link(hardA, hardB); err != nil {
		t.Fatal(err)
	}

	// 1. [M2] NewWorkspaceHubWithOptions enforces AllowOutsideHome=false, MSBHome blocklist, and writable single-file Nlink==1.
	hub, err := NewWorkspaceHubWithOptions([]HubShareConfig{
		{GuestName: "repo", HostPath: repoDir, ReadOnly: false, VCSPolicy: config.VCSAllow},
	}, HubOptions{
		HomeReal:         homeDir,
		DataDir:          dataDir,
		MSBHome:          msbHome,
		AllowOutsideHome: false,
		MapGuestIDs:      true,
		GuestUID:         config.GuestUID,
		GuestGID:         config.GuestGID,
	})
	if err != nil {
		t.Fatalf("NewWorkspaceHubWithOptions: %v", err)
	}
	defer hub.CloseAll()
	_ = fs.NewNodeFS(hub, &fs.Options{})

	sockPath := filepath.Join(base, "sockdir", "ws.sock")
	ln, err := listenVerifiedUnixSocket(sockPath, hub)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	// Reject non-socket path and already-active socket in listenVerifiedUnixSocket (#8 §1).
	nonSock := filepath.Join(base, "not-a-sock")
	_ = os.WriteFile(nonSock, []byte("x"), 0o600)
	if _, err := listenVerifiedUnixSocket(nonSock, hub); err == nil {
		t.Error("expected listenVerifiedUnixSocket to reject regular file")
	}
	if _, err := listenVerifiedUnixSocket(sockPath, hub); err == nil || !strings.Contains(err.Error(), "already active") {
		t.Errorf("expected listenVerifiedUnixSocket to reject active hub socket, got %v", err)
	}

	if _, err := AddHubShare(sockPath, HubShareConfig{GuestName: "out", HostPath: outsideProj, ReadOnly: true, VCSPolicy: config.VCSMask}); err == nil || !strings.Contains(err.Error(), "outside $HOME") {
		t.Errorf("expected outside $HOME rejection on ws.sock add, got %v", err)
	}
	if _, err := AddHubShare(sockPath, HubShareConfig{GuestName: "msb", HostPath: msbSub, ReadOnly: true, VCSPolicy: config.VCSMask}); err == nil {
		t.Error("expected custom MSBHome subpath rejection on ws.sock add")
	}
	if _, err := AddHubShare(sockPath, HubShareConfig{GuestName: "hard", HostPath: hardA, ReadOnly: false, VCSPolicy: config.VCSMask}); err == nil || !strings.Contains(err.Error(), "multiple hard links") {
		t.Errorf("expected writable multi-hardlink single-file rejection, got %v", err)
	}

	// 2. Readdir fallback Ino matches Lookup Ino (#8 §1), and RemoveShare + AddShare under same alias replaces child inode cleanly (#13 §2G).
	rdStream, rdErrno := hub.Readdir(ctx)
	if rdErrno != 0 {
		t.Fatalf("hub.Readdir: %v", rdErrno)
	}
	var readdirIno uint64
	for rdStream.HasNext() {
		de, _ := rdStream.Next()
		if de.Name == "repo" {
			readdirIno = de.Ino
		}
	}
	var eOut fuse.EntryOut
	repoIno, lErrno := hub.Lookup(ctx, "repo", &eOut)
	if lErrno != 0 {
		t.Fatalf("hub.Lookup(repo): %v", lErrno)
	}
	if readdirIno != repoIno.StableAttr().Ino {
		t.Errorf("Readdir fallback Ino (%d) != Lookup Ino (%d)", readdirIno, repoIno.StableAttr().Ino)
	}

	// 3. [M1] Populate uppercase .GIT and nested sub/.git + sub/.gitignore in child inode tree, then downgrade to VCSMask.
	hub.mounted.Store(true)
	repoRoot := repoIno.Operations().(*filteredNode)
	upperGitIno, lErrno := repoRoot.Lookup(ctx, ".GIT", &eOut)
	if lErrno != 0 {
		t.Fatalf("Lookup(.GIT): %v", lErrno)
	}
	repoRoot.AddChild(".GIT", upperGitIno, true)
	subIno, lErrno := repoRoot.Lookup(ctx, "sub", &eOut)
	if lErrno != 0 {
		t.Fatalf("Lookup(sub): %v", lErrno)
	}
	repoRoot.AddChild("sub", subIno, true)
	subNode := subIno.Operations().(*filteredNode)
	nestedGitIno, lErrno := subNode.Lookup(ctx, ".git", &eOut)
	if lErrno != 0 {
		t.Fatalf("Lookup(sub/.git): %v", lErrno)
	}
	subNode.AddChild(".git", nestedGitIno, true)
	nestedIgnoreIno, lErrno := subNode.Lookup(ctx, ".gitignore", &eOut)
	if lErrno != 0 {
		t.Fatalf("Lookup(sub/.gitignore): %v", lErrno)
	}
	subNode.AddChild(".gitignore", nestedIgnoreIno, true)

	vcsMask := config.VCSMask
	if _, err := SetHubShare(sockPath, "repo", nil, &vcsMask, true); err != nil {
		t.Fatalf("SetHubShare(VCSMask): %v", err)
	}
	if repoIno.GetChild(".GIT") != nil {
		t.Error("expected invalidateSlotKernelCache to remove uppercase .GIT child inode")
	}
	if subIno.GetChild(".git") != nil || subIno.GetChild(".gitignore") != nil {
		t.Error("expected invalidateSlotKernelCache to remove nested sub/.git and sub/.gitignore child inodes")
	}

	// 4. FilteredNode Link, Unlink, Rmdir, Setattr truncate, xattr round-trip, and revoked safeFile methods (#13 §2G).
	fileIno, lErrno := repoRoot.Lookup(ctx, "file.txt", &eOut)
	if lErrno != 0 {
		t.Fatalf("Lookup(file.txt): %v", lErrno)
	}
	repoRoot.AddChild("file.txt", fileIno, true)
	fileNode := fileIno.Operations().(*filteredNode)

	linkedIno, lkErrno := repoRoot.Link(ctx, fileNode, "linked.txt", &eOut)
	if lkErrno != 0 || linkedIno == nil {
		t.Fatalf("repoRoot.Link(linked.txt) = %v", lkErrno)
	}
	repoRoot.AddChild("linked.txt", linkedIno, true)
	if uErrno := repoRoot.Unlink(ctx, "linked.txt"); uErrno != 0 {
		t.Errorf("repoRoot.Unlink(linked.txt) = %v, want 0", uErrno)
	}
	if _, mkErrno := repoRoot.Mkdir(ctx, "emptydir", 0o755, &eOut); mkErrno != 0 {
		t.Fatalf("repoRoot.Mkdir(emptydir) = %v", mkErrno)
	}
	if rmErrno := repoRoot.Rmdir(ctx, "emptydir"); rmErrno != 0 {
		t.Errorf("repoRoot.Rmdir(emptydir) = %v, want 0", rmErrno)
	}

	// Path-based Setattr truncate on file, EISDIR on directory truncate, and guest 1000:1000 Chown no-op.
	var aOut fuse.AttrOut
	truncIn := fuse.SetAttrIn{}
	truncIn.Valid = fuse.FATTR_SIZE | fuse.FATTR_UID | fuse.FATTR_GID
	truncIn.Size = 5
	truncIn.Uid = config.GuestUID
	truncIn.Gid = config.GuestGID
	if sErrno := fileNode.Setattr(ctx, nil, &truncIn, &aOut); sErrno != 0 || aOut.Size != 5 {
		t.Errorf("fileNode.Setattr(truncate=5) = (%v, size=%d), want (0, 5)", sErrno, aOut.Size)
	}
	if sErrno := repoRoot.Setattr(ctx, nil, &truncIn, &aOut); sErrno != syscall.EISDIR {
		t.Errorf("repoRoot.Setattr(FATTR_SIZE on dir) = %v, want EISDIR", sErrno)
	}

	// Allowed user.custom xattr round-trip (Setxattr -> Getxattr -> Listxattr size/ERANGE/copy -> Removexattr).
	xErr := fileNode.Setxattr(ctx, "user.custom", []byte("hello"), 0)
	if xErr == 0 {
		gotBuf := make([]byte, 16)
		nX, gErr := fileNode.Getxattr(ctx, "user.custom", gotBuf)
		if gErr != 0 || string(gotBuf[:nX]) != "hello" {
			t.Errorf("fileNode.Getxattr(user.custom) = (%q, %v)", string(gotBuf[:nX]), gErr)
		}
		sz, lErr := fileNode.Listxattr(ctx, nil)
		if lErr != 0 || sz == 0 {
			t.Errorf("fileNode.Listxattr(nil) = (%d, %v)", sz, lErr)
		}
		if _, rErr := fileNode.Listxattr(ctx, make([]byte, 2)); rErr != syscall.ERANGE {
			t.Errorf("fileNode.Listxattr(small buf) = %v, want ERANGE", rErr)
		}
		fullBuf := make([]byte, sz)
		if _, lErr := fileNode.Listxattr(ctx, fullBuf); lErr != 0 || !strings.Contains(string(fullBuf), "user.custom") {
			t.Errorf("fileNode.Listxattr(fullBuf) = (%q, %v)", string(fullBuf), lErr)
		}
		if rmX := fileNode.Removexattr(ctx, "user.custom"); rmX != 0 {
			t.Errorf("fileNode.Removexattr(user.custom) = %v", rmX)
		}
	} else if xErr != syscall.EOPNOTSUPP && xErr != unix.ENOTSUP {
		t.Errorf("fileNode.Setxattr(user.custom) = %v", xErr)
	}

	// Revoked safeFile returns 0 on Flush and ESTALE on Fsync, Lseek, Getlk, Setlk, Setlkw, Getattr, Setattr, Allocate.
	rwFH, _, oErr := fileNode.Open(ctx, syscall.O_RDWR)
	if oErr != 0 {
		t.Fatalf("fileNode.Open(O_RDWR): %v", oErr)
	}
	sf := rwFH.(*safeFile)
	sf.revoke(syscall.ESTALE)
	if errNo := sf.Flush(ctx); errNo != 0 {
		t.Errorf("revoked sf.Flush = %v, want 0", errNo)
	}
	if errNo := sf.Fsync(ctx, 0); errNo != syscall.ESTALE {
		t.Errorf("revoked sf.Fsync = %v, want ESTALE", errNo)
	}
	if _, errNo := sf.Lseek(ctx, 0, 0); errNo != syscall.ESTALE {
		t.Errorf("revoked sf.Lseek = %v, want ESTALE", errNo)
	}
	var lk fuse.FileLock
	if errNo := sf.Getlk(ctx, 1, &lk, 0, &lk); errNo != syscall.ESTALE {
		t.Errorf("revoked sf.Getlk = %v, want ESTALE", errNo)
	}
	if errNo := sf.Setlk(ctx, 1, &lk, 0); errNo != syscall.ESTALE {
		t.Errorf("revoked sf.Setlk = %v, want ESTALE", errNo)
	}
	if errNo := sf.Setlkw(ctx, 1, &lk, 0); errNo != syscall.ESTALE {
		t.Errorf("revoked sf.Setlkw = %v, want ESTALE", errNo)
	}
	if errNo := sf.Getattr(ctx, &aOut); errNo != syscall.ESTALE {
		t.Errorf("revoked sf.Getattr = %v, want ESTALE", errNo)
	}
	if errNo := sf.Setattr(ctx, &truncIn, &aOut); errNo != syscall.ESTALE {
		t.Errorf("revoked sf.Setattr = %v, want ESTALE", errNo)
	}
	if errNo := sf.Allocate(ctx, 0, 16, 0); errNo != syscall.ESTALE {
		t.Errorf("revoked sf.Allocate = %v, want ESTALE", errNo)
	}
	_ = sf.Release(ctx)

	// Read-only share rejects Rename, Unlink, Rmdir, and Link with EROFS.
	roTrue := true
	if _, err := SetHubShare(sockPath, "repo", &roTrue, nil, true); err != nil {
		t.Fatal(err)
	}
	if errNo := repoRoot.Rename(ctx, "file.txt", repoRoot, "file2.txt", 0); errNo != syscall.EROFS {
		t.Errorf("RO Rename = %v, want EROFS", errNo)
	}
	if errNo := repoRoot.Unlink(ctx, "file.txt"); errNo != syscall.EROFS {
		t.Errorf("RO Unlink = %v, want EROFS", errNo)
	}
	if errNo := repoRoot.Rmdir(ctx, "sub"); errNo != syscall.EROFS {
		t.Errorf("RO Rmdir = %v, want EROFS", errNo)
	}

	// RemoveShare + AddShare under the same alias "repo" attaches a fresh generation inode.
	if err := RemoveHubShare(sockPath, "repo", true); err != nil {
		t.Fatalf("RemoveHubShare(repo): %v", err)
	}
	if _, err := AddHubShare(sockPath, HubShareConfig{GuestName: "repo", HostPath: repoDir2, ReadOnly: true, VCSPolicy: config.VCSMask}); err != nil {
		t.Fatalf("AddHubShare(repo -> repoDir2): %v", err)
	}
	newRepoIno, lErrno := hub.Lookup(ctx, "repo", &eOut)
	if lErrno != 0 || newRepoIno == repoIno {
		t.Errorf("expected new generation inode after Remove+Add under same alias, err=%v same=%v", lErrno, newRepoIno == repoIno)
	}

	// 5. decodeHubBootstrapSpec, writePIDFileNoFollow, and RunMain flag validation (#13 §2G, [M2], [M6]).
	specPath := filepath.Join(base, "spec.json")
	validSpecJSON := `{"home_real":"/home/u","data_dir":"/home/u/d","msb_home":"/home/u/m","allow_outside_home":false,"map_guest_ids":true,"guest_uid":0,"guest_gid":0,"shares":[]}`
	if err := os.WriteFile(specPath, []byte(validSpecJSON), 0o600); err != nil {
		t.Fatal(err)
	}
	decoded, err := decodeHubBootstrapSpec("/mnt/ws", "/mnt/ws.sock", -1, specPath)
	if err != nil {
		t.Fatalf("decodeHubBootstrapSpec(file): %v", err)
	}
	if decoded.GuestUID != 0 || decoded.GuestGID != 0 || decoded.AllowOutsideHome || decoded.MSBHome != "/home/u/m" {
		t.Errorf("unexpected decoded spec (GuestUID=0 must not be clobbered): %+v", decoded)
	}

	prPipe, pwPipe, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	_, _ = pwPipe.Write([]byte(validSpecJSON))
	_ = pwPipe.Close()
	dupSpecFD, err := unix.Dup(int(prPipe.Fd()))
	if err != nil {
		_ = prPipe.Close()
		t.Fatal(err)
	}
	_ = prPipe.Close()
	if _, err := decodeHubBootstrapSpec("/mnt/ws", "/mnt/ws.sock", dupSpecFD, ""); err != nil {
		t.Errorf("decodeHubBootstrapSpec(pipe fd) failed: %v", err)
	}

	symSpec := filepath.Join(base, "sym-spec.json")
	_ = os.Symlink(specPath, symSpec)
	bigSpec := filepath.Join(base, "big-spec.json")
	_ = os.WriteFile(bigSpec, bytes.Repeat([]byte(" "), maxHubControlBytes+10), 0o600)
	badJSONSpec := filepath.Join(base, "bad.json")
	_ = os.WriteFile(badJSONSpec, []byte("{bad"), 0o600)

	for _, badCase := range []struct {
		mnt  string
		sock string
		fd   int
		file string
	}{
		{"", "/mnt/s", -1, ""},
		{"/mnt/w", "", -1, ""},
		{"/mnt/w", "/mnt/s", 3, specPath},
		{"/mnt/w", "/mnt/s", 0, ""},
		{"/mnt/w", "/mnt/s", 2, ""},
		{"/mnt/w", "/mnt/s", -1, symSpec},
		{"/mnt/w", "/mnt/s", -1, base},
		{"/mnt/w", "/mnt/s", -1, bigSpec},
		{"/mnt/w", "/mnt/s", -1, badJSONSpec},
	} {
		if _, err := decodeHubBootstrapSpec(badCase.mnt, badCase.sock, badCase.fd, badCase.file); err == nil {
			t.Errorf("expected decodeHubBootstrapSpec(%+v) to fail", badCase)
		}
	}

	if rc := RunMain([]string{"-hub", "-mnt", base}); rc != 2 {
		t.Errorf("RunMain(-hub missing -sock) = %d, want 2", rc)
	}
	if rc := RunMain([]string{"-hub", "-mnt", base, "-sock", filepath.Join(base, "x.sock"), "unexpected-arg"}); rc != 2 {
		t.Errorf("RunMain(positional arg) = %d, want 2", rc)
	}
	if rc := RunMain([]string{"-hub", "-mnt", base, "-sock", filepath.Join(base, "x.sock"), "-spec", symSpec}); rc != 1 {
		t.Errorf("RunMain(symlink -spec) = %d, want 1", rc)
	}

	symPID := filepath.Join(base, "sym.pid")
	_ = os.Symlink(filepath.Join(base, "target.pid"), symPID)
	if err := writePIDFileNoFollow(symPID, 1234); err == nil {
		t.Error("expected writePIDFileNoFollow to reject symlinked pidfile")
	}
}

func TestLiveKernelFUSESecurityFixesAndOnAddFailClosed(t *testing.T) {
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	dataDir := filepath.Join(base, "data")
	badFile := filepath.Join(base, "vanishing.txt")
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(badFile, []byte("init\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	// 1. OnAdd fails closed when a single-file share was replaced on disk before mount (#8 §1).
	hubOnAdd, err := NewWorkspaceHubWithOptions([]HubShareConfig{
		{GuestName: "vanishing.txt", HostPath: badFile, ReadOnly: false, VCSPolicy: config.VCSMask},
	}, HubOptions{HomeReal: base, DataDir: dataDir})
	if err != nil {
		t.Fatal(err)
	}
	defer hubOnAdd.CloseAll()
	_ = os.Remove(badFile)
	_ = os.MkdirAll(badFile, 0o700)
	_ = fs.NewNodeFS(hubOnAdd, &fs.Options{})
	if len(hubOnAdd.listShares()) != 0 {
		t.Errorf("expected OnAdd to revoke and remove corrupted file share, got %+v", hubOnAdd.listShares())
	}

	// 2. Live kernel FUSE integration test for [H1], [H2], and [H7] when /dev/fuse is available.
	if _, err := os.Stat("/dev/fuse"); err != nil {
		t.Skipf("/dev/fuse unavailable: %v", err)
	}
	repoDir := filepath.Join(base, "live-repo")
	mntDir := filepath.Join(base, "live-mnt")
	sockPath := filepath.Join(base, "live-sock", "ws.sock")
	for _, d := range []string{
		filepath.Join(repoDir, ".git", "hooks"),
		filepath.Join(repoDir, ".git", "modules"),
		filepath.Join(repoDir, "a", "b", "c"),
		filepath.Join(repoDir, "stage", "hooks"),
		mntDir,
	} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	_ = os.WriteFile(filepath.Join(repoDir, "main.go"), []byte("package main\n"), 0o644)
	_ = os.WriteFile(filepath.Join(repoDir, ".git", "config"), []byte("[core]\n"), 0o644)
	_ = os.WriteFile(filepath.Join(repoDir, ".git", "HEAD"), []byte("ref: refs/heads/main\n"), 0o644)
	_ = os.WriteFile(filepath.Join(repoDir, "stage", "hooks", "pre-commit"), []byte("#!/bin/sh\nid\n"), 0o755)
	_ = syscall.Mkfifo(filepath.Join(repoDir, "live.fifo"), 0o600)

	hub, server, ln, mErr := mountWorkspaceHubWithOptions(mntDir, sockPath, []HubShareConfig{
		{GuestName: "repo", HostPath: repoDir, ReadOnly: false, VCSPolicy: config.VCSAllow},
	}, HubOptions{HomeReal: base, DataDir: dataDir})
	if mErr != nil {
		t.Skipf("live FUSE mount unavailable: %v", mErr)
	}
	defer func() {
		if ln != nil {
			_ = ln.Close()
		}
		_ = server.Unmount()
		server.Wait()
		hub.CloseAll()
	}()

	mountedRepo := filepath.Join(mntDir, "repo")

	// [H1] Writing .git/config fails with EPERM under :vcs, while writing .git/HEAD succeeds.
	if err := os.WriteFile(filepath.Join(mountedRepo, ".git", "config"), []byte("evil\n"), 0o644); !errors.Is(err, syscall.EPERM) {
		t.Errorf("live WriteFile(.git/config) = %v, want EPERM", err)
	}
	if err := os.WriteFile(filepath.Join(mountedRepo, ".git", "HEAD"), []byte("ref: refs/heads/dev\n"), 0o644); err != nil {
		t.Errorf("live WriteFile(.git/HEAD) = %v, want nil", err)
	}
	if err := os.Rename(filepath.Join(mountedRepo, "stage"), filepath.Join(mountedRepo, ".git", "modules", "planted")); !errors.Is(err, syscall.EPERM) {
		t.Errorf("live subtree Rename(stage -> .git/modules/planted) = %v, want EPERM", err)
	}

	// [H2] Symlink valid at depth 3 cannot be renamed to depth 0 through live FUSE.
	deepSym := filepath.Join(mountedRepo, "a", "b", "c", "esc")
	if err := os.Symlink("../../../main.go", deepSym); err != nil {
		t.Fatalf("live Symlink(deepSym): %v", err)
	}
	if err := os.Rename(deepSym, filepath.Join(mountedRepo, "esc")); !errors.Is(err, syscall.EPERM) {
		t.Errorf("live Rename(a/b/c/esc -> esc) = %v, want EPERM", err)
	}

	// [H7] Setattr and Setxattr on FIFO fail with EPERM, and a regular->FIFO swap on Open fails without blocking.
	if err := os.Chmod(filepath.Join(mountedRepo, "live.fifo"), 0o644); !errors.Is(err, syscall.EPERM) {
		t.Errorf("live Chmod(live.fifo) = %v, want EPERM", err)
	}
	if err := unix.Setxattr(filepath.Join(mountedRepo, "live.fifo"), "user.tag", []byte("1"), 0); !errors.Is(err, syscall.EPERM) {
		t.Errorf("live Setxattr(live.fifo) = %v, want EPERM", err)
	}

	raceHost := filepath.Join(repoDir, "race.txt")
	raceMnt := filepath.Join(mountedRepo, "race.txt")
	if err := os.WriteFile(raceHost, []byte("reg\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(raceMnt); err != nil {
		t.Fatalf("live Stat(race.txt): %v", err)
	}
	_ = os.Remove(raceHost)
	if err := syscall.Mkfifo(raceHost, 0o600); err != nil {
		t.Fatal(err)
	}
	fifoDone := make(chan error, 1)
	go func() {
		f, oErr := os.Open(raceMnt)
		if f != nil {
			_ = f.Close()
		}
		fifoDone <- oErr
	}()
	select {
	case oErr := <-fifoDone:
		if !errors.Is(oErr, syscall.EPERM) {
			t.Errorf("live Open(swapped FIFO) = %v, want EPERM", oErr)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("live Open(swapped FIFO) hung FUSE worker")
	}

	// [R-M1] .git/config.worktree and .git/modules/objects/config fail with EPERM through live FUSE.
	if err := os.WriteFile(filepath.Join(mountedRepo, ".git", "config.worktree"), []byte("evil\n"), 0o644); !errors.Is(err, syscall.EPERM) {
		t.Errorf("live WriteFile(.git/config.worktree) = %v, want EPERM", err)
	}
	if err := os.MkdirAll(filepath.Join(repoDir, ".git", "modules", "objects"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(mountedRepo, ".git", "modules", "objects", "config"), []byte("evil\n"), 0o644); !errors.Is(err, syscall.EPERM) {
		t.Errorf("live WriteFile(.git/modules/objects/config) = %v, want EPERM", err)
	}
	// Mkdir of top-level VCS admin directory fails with EPERM under :vcs.
	if err := os.Mkdir(filepath.Join(mountedRepo, ".jj"), 0o755); !errors.Is(err, syscall.EPERM) {
		t.Errorf("live Mkdir(.jj) under :vcs = %v, want EPERM", err)
	}

	// [R2-H1] & [R-H1] Live FUSE rejects cross-boundary hardlinks and multi-link renames,
	// allows same-boundary hardlinks, and promotes open descriptors on single-link directory Rename.
	vcsHooks := config.VCSAllowHooks
	vcsAllow := config.VCSAllow
	vcsMask := config.VCSMask
	if _, err := SetHubShare(sockPath, "repo", nil, &vcsHooks, true); err != nil {
		t.Fatalf("live SetHubShare(vcs-hooks): %v", err)
	}
	linkSrcMnt := filepath.Join(mountedRepo, "linksrc.txt")
	linkAliasMnt := filepath.Join(mountedRepo, "linkalias.txt")
	linkHookMnt := filepath.Join(mountedRepo, ".git", "hooks", "post-commit")
	if err := os.WriteFile(linkSrcMnt, []byte("v1\n"), 0o755); err != nil {
		t.Fatalf("live WriteFile(linksrc.txt): %v", err)
	}
	if err := os.Link(linkSrcMnt, linkHookMnt); !errors.Is(err, syscall.EPERM) {
		t.Errorf("live Link(linksrc.txt -> .git/hooks/post-commit) = %v, want EPERM", err)
	}
	if err := os.Link(filepath.Join(mountedRepo, ".git", "HEAD"), filepath.Join(mountedRepo, "head_outside.txt")); !errors.Is(err, syscall.EPERM) {
		t.Errorf("live Link(.git/HEAD -> head_outside.txt) = %v, want EPERM", err)
	}
	if err := os.Link(linkSrcMnt, linkAliasMnt); err != nil {
		t.Fatalf("live same-boundary Link(linksrc.txt -> linkalias.txt): %v", err)
	}
	if err := os.Rename(linkAliasMnt, linkHookMnt); !errors.Is(err, syscall.EPERM) {
		t.Errorf("live Rename(multi-link linkalias.txt -> .git/hooks/post-commit) = %v, want EPERM", err)
	}
	if _, err := SetHubShare(sockPath, "repo", nil, &vcsAllow, false); err != nil {
		t.Fatalf("live SetHubShare(vcs): %v", err)
	}

	moveStageMnt := filepath.Join(mountedRepo, "movestage")
	if err := os.MkdirAll(moveStageMnt, 0o755); err != nil {
		t.Fatal(err)
	}
	stageRefF, err := os.OpenFile(filepath.Join(moveStageMnt, "custom_ref"), os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		t.Fatalf("live OpenFile(movestage/custom_ref): %v", err)
	}
	if err := os.Rename(moveStageMnt, filepath.Join(mountedRepo, ".git", "moved_refs")); err != nil {
		_ = stageRefF.Close()
		t.Fatalf("live Rename(movestage -> .git/moved_refs): %v", err)
	}
	if _, err := SetHubShare(sockPath, "repo", nil, &vcsMask, false); err == nil {
		t.Error("live SetHubShare(mask) without force succeeded despite moved open VCS handle")
	}
	if _, err := SetHubShare(sockPath, "repo", nil, &vcsMask, true); err != nil {
		t.Fatalf("live SetHubShare(mask, force): %v", err)
	}
	if _, wErr := stageRefF.Write([]byte("after-mask\n")); !errors.Is(wErr, syscall.ESTALE) {
		t.Errorf("live Write on moved VCS handle after mask downgrade = %v, want ESTALE", wErr)
	}
	_ = stageRefF.Close()
}

// TestRH1LinkAndDirectoryRenameHandlePromotion verifies [R2-H1] cross-boundary hardlink and multi-link
// rename rejection alongside [R-H1] open-FD and filteredDir promotion across subtree renames and RENAME_EXCHANGE.
func TestRH1LinkAndDirectoryRenameHandlePromotion(t *testing.T) {
	ctx := context.Background()
	base := t.TempDir()
	dataDir := filepath.Join(base, "data")
	repoDir := filepath.Join(base, "repo")
	for _, d := range []string{
		dataDir,
		filepath.Join(repoDir, ".git", "hooks"),
		filepath.Join(repoDir, "staging", "sub"),
		filepath.Join(repoDir, "multidir"),
		filepath.Join(repoDir, "exch_plain"),
		filepath.Join(repoDir, ".git", "exch_vcs"),
	} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	_ = os.WriteFile(filepath.Join(repoDir, "normal.txt"), []byte("v1\n"), 0o755)
	_ = os.WriteFile(filepath.Join(repoDir, ".git", "HEAD"), []byte("ref: refs/heads/main\n"), 0o644)
	_ = os.WriteFile(filepath.Join(repoDir, ".git", "hooks", "h1"), []byte("#!/bin/sh\n"), 0o755)
	_ = os.WriteFile(filepath.Join(repoDir, "staging", "sub", "pre-commit"), []byte("#!/bin/sh\n"), 0o755)
	_ = os.WriteFile(filepath.Join(repoDir, "multidir", "linked.txt"), []byte("shared\n"), 0o644)
	_ = os.WriteFile(filepath.Join(repoDir, "exch_plain", "item.txt"), []byte("plain\n"), 0o644)
	_ = os.WriteFile(filepath.Join(repoDir, ".git", "exch_vcs", "meta.txt"), []byte("meta\n"), 0o644)

	hub, err := NewWorkspaceHubWithOptions([]HubShareConfig{
		{GuestName: "repo", HostPath: repoDir, ReadOnly: false, VCSPolicy: config.VCSAllowHooks},
	}, HubOptions{HomeReal: base, DataDir: dataDir})
	if err != nil {
		t.Fatalf("NewWorkspaceHubWithOptions: %v", err)
	}
	defer hub.CloseAll()
	_ = fs.NewNodeFS(hub, &fs.Options{})

	sockPath := filepath.Join(base, "ws.sock")
	ln, err := listenVerifiedUnixSocket(sockPath, hub)
	if err != nil {
		t.Fatalf("listenVerifiedUnixSocket: %v", err)
	}
	defer ln.Close()

	slot := hub.slots["repo"]
	var sySt syscall.Stat_t
	_ = syscall.Stat(repoDir, &sySt)
	repoRoot := buildRootFilteredNode(repoDir, slot.root, sySt, slot)
	fs.NewNodeFS(repoRoot, &fs.Options{})

	lookupAttach := func(parent *filteredNode, parts ...string) *filteredNode {
		cur := parent
		for _, p := range parts {
			var eOut fuse.EntryOut
			ino, errNo := cur.Lookup(ctx, p, &eOut)
			if errNo != 0 {
				t.Fatalf("Lookup(%q): %v", p, errNo)
			}
			cur.AddChild(p, ino, true)
			cur = ino.Operations().(*filteredNode)
		}
		return cur
	}

	// 1. [R2-H1] Cross-boundary hardlinks fail with EPERM, same-boundary hardlinks succeed,
	// and cross-boundary Rename (direct, subtree, and RENAME_EXCHANGE) of multi-link files fails with EPERM.
	normalNode := lookupAttach(repoRoot, "normal.txt")
	gitNode := lookupAttach(repoRoot, ".git")
	headNode := lookupAttach(gitNode, "HEAD")
	hooksNode := lookupAttach(gitNode, "hooks")
	hookH1Node := lookupAttach(hooksNode, "h1")
	multiChildNode := lookupAttach(repoRoot, "multidir", "linked.txt")

	var eOut fuse.EntryOut
	if _, lErr := hooksNode.Link(ctx, normalNode, "pre-commit", &eOut); lErr != syscall.EPERM {
		t.Errorf("Link(normal.txt -> .git/hooks/pre-commit) = %v, want EPERM", lErr)
	}
	if _, lErr := gitNode.Link(ctx, normalNode, "HEAD_link", &eOut); lErr != syscall.EPERM {
		t.Errorf("Link(normal.txt -> .git/HEAD_link) = %v, want EPERM", lErr)
	}
	if _, lErr := repoRoot.Link(ctx, headNode, "head_outside.txt", &eOut); lErr != syscall.EPERM {
		t.Errorf("Link(.git/HEAD -> head_outside.txt) = %v, want EPERM", lErr)
	}
	if _, lErr := repoRoot.Link(ctx, hookH1Node, "hook_outside.txt", &eOut); lErr != syscall.EPERM {
		t.Errorf("Link(.git/hooks/h1 -> hook_outside.txt) = %v, want EPERM", lErr)
	}
	if _, lErr := hooksNode.Link(ctx, headNode, "from_head", &eOut); lErr != syscall.EPERM {
		t.Errorf("Link(.git/HEAD -> .git/hooks/from_head) = %v, want EPERM", lErr)
	}
	if _, lErr := gitNode.Link(ctx, hookH1Node, "from_hook", &eOut); lErr != syscall.EPERM {
		t.Errorf("Link(.git/hooks/h1 -> .git/from_hook) = %v, want EPERM", lErr)
	}

	// Same-boundary hardlinks succeed within workspace, within .git, and within .git/hooks.
	if _, lErr := repoRoot.Link(ctx, normalNode, "normal_alias.txt", &eOut); lErr != 0 {
		t.Fatalf("same-boundary Link(normal.txt -> normal_alias.txt): %v", lErr)
	}
	if _, lErr := gitNode.Link(ctx, headNode, "ORIG_HEAD", &eOut); lErr != 0 {
		t.Fatalf("same-boundary Link(.git/HEAD -> .git/ORIG_HEAD): %v", lErr)
	}
	hookFH, _, oErr := hookH1Node.Open(ctx, syscall.O_RDWR)
	if oErr != 0 {
		t.Fatalf("hookH1Node.Open(O_RDWR): %v", oErr)
	}
	hookSF := hookFH.(*safeFile)
	if _, lErr := hooksNode.Link(ctx, hookH1Node, "h2", &eOut); lErr != 0 {
		t.Fatalf("same-boundary Link(.git/hooks/h1 -> .git/hooks/h2): %v", lErr)
	}

	// Multi-link files cannot cross VCS or hook boundaries via Rename, subtree Rename, or RENAME_EXCHANGE.
	if rErr := repoRoot.Rename(ctx, "normal_alias.txt", hooksNode, "pre-commit", 0); rErr != syscall.EPERM {
		t.Errorf("Rename(multi-link normal_alias.txt -> .git/hooks/pre-commit) = %v, want EPERM", rErr)
	}
	if rErr := repoRoot.Rename(ctx, "normal_alias.txt", gitNode, "HEAD_alias", 0); rErr != syscall.EPERM {
		t.Errorf("Rename(multi-link normal_alias.txt -> .git/HEAD_alias) = %v, want EPERM", rErr)
	}
	if rErr := gitNode.Rename(ctx, "ORIG_HEAD", repoRoot, "escaped_head.txt", 0); rErr != syscall.EPERM {
		t.Errorf("Rename(multi-link .git/ORIG_HEAD -> escaped_head.txt) = %v, want EPERM", rErr)
	}
	if rErr := repoRoot.Rename(ctx, "normal_alias.txt", gitNode, "HEAD", unix.RENAME_EXCHANGE); rErr != syscall.EPERM {
		t.Errorf("Rename(RENAME_EXCHANGE multi-link src -> .git/HEAD) = %v, want EPERM", rErr)
	}
	_ = os.WriteFile(filepath.Join(repoDir, "single_out.txt"), []byte("s\n"), 0o644)
	if rErr := repoRoot.Rename(ctx, "single_out.txt", gitNode, "ORIG_HEAD", unix.RENAME_EXCHANGE); rErr != syscall.EPERM {
		t.Errorf("Rename(RENAME_EXCHANGE single src <-> multi-link .git/ORIG_HEAD) = %v, want EPERM", rErr)
	}
	if _, lErr := repoRoot.Link(ctx, multiChildNode, "outside_keep.txt", &eOut); lErr != 0 {
		t.Fatalf("Link(multidir/linked.txt -> outside_keep.txt): %v", lErr)
	}
	if rErr := repoRoot.Rename(ctx, "multidir", hooksNode, "planted_multi", 0); rErr != syscall.EPERM {
		t.Errorf("subtree Rename(multidir with Nlink=2 -> .git/hooks/planted_multi) = %v, want EPERM", rErr)
	}

	vcsAllow := config.VCSAllow
	vcsHooks := config.VCSAllowHooks
	vcsMask := config.VCSMask

	// Same-boundary linked hook handle still blocks downgrade without force and revokes with force.
	if _, err := SetHubShare(sockPath, "repo", nil, &vcsAllow, false); err == nil || !strings.Contains(err.Error(), "open writable") {
		t.Fatalf("expected downgrade without force to fail on open hook handle, got %v", err)
	}
	if _, err := SetHubShare(sockPath, "repo", nil, &vcsAllow, true); err != nil {
		t.Fatalf("SetHubShare(vcs, force): %v", err)
	}
	if _, wErr := hookSF.Write(ctx, []byte("blocked"), 0); wErr != syscall.EROFS {
		t.Errorf("hookSF.Write after hook downgrade = %v, want EROFS", wErr)
	}
	_ = hookSF.Release(ctx)

	// 2. Subtree Rename staging -> .git/hooks/staged promotes descendant safeFile and filteredDir handles.
	if _, err := SetHubShare(sockPath, "repo", nil, &vcsHooks, true); err != nil {
		t.Fatal(err)
	}
	gitNode = lookupAttach(repoRoot, ".git")
	hooksNode = lookupAttach(gitNode, "hooks")
	stagingNode := lookupAttach(repoRoot, "staging")
	subFileNode := lookupAttach(stagingNode, "sub", "pre-commit")

	subFH, _, oErr := subFileNode.Open(ctx, syscall.O_RDWR)
	if oErr != 0 {
		t.Fatalf("subFileNode.Open(O_RDWR): %v", oErr)
	}
	subSF := subFH.(*safeFile)

	dirFH, _, dErr := stagingNode.OpendirHandle(ctx, 0)
	if dErr != 0 {
		t.Fatalf("stagingNode.OpendirHandle: %v", dErr)
	}
	stagingDir := dirFH.(*filteredDir)

	if rErr := repoRoot.Rename(ctx, "staging", hooksNode, "staged", 0); rErr != 0 {
		t.Fatalf("Rename(staging -> .git/hooks/staged): %v", rErr)
	}
	if _, err := SetHubShare(sockPath, "repo", nil, &vcsAllow, false); err == nil || !strings.Contains(err.Error(), "open writable") {
		t.Fatalf("expected downgrade without force to fail on moved descendant hook handle, got %v", err)
	}
	if _, err := SetHubShare(sockPath, "repo", nil, &vcsAllow, true); err != nil {
		t.Fatalf("SetHubShare(vcs, force): %v", err)
	}
	if _, wErr := subSF.Write(ctx, []byte("blocked"), 0); wErr != syscall.EROFS {
		t.Errorf("subSF.Write after hook downgrade = %v, want EROFS", wErr)
	}
	_ = subSF.Release(ctx)

	// Downgrade to VCSMask revokes the promoted directory handle on stagingDir.
	if _, err := SetHubShare(sockPath, "repo", nil, &vcsMask, true); err != nil {
		t.Fatalf("SetHubShare(mask, force): %v", err)
	}
	if _, rdErr := stagingDir.Readdirent(ctx); rdErr != syscall.ESTALE {
		t.Errorf("stagingDir.Readdirent after mask downgrade = %v, want ESTALE", rdErr)
	}
	stagingDir.Releasedir(ctx, 0)

	// 3. RENAME_EXCHANGE promotes incoming directory descendants entering .git.
	if _, err := SetHubShare(sockPath, "repo", nil, &vcsAllow, true); err != nil {
		t.Fatal(err)
	}
	gitNode = lookupAttach(repoRoot, ".git")
	exchPlainItem := lookupAttach(repoRoot, "exch_plain", "item.txt")
	exchFH, _, oErr := exchPlainItem.Open(ctx, syscall.O_RDWR)
	if oErr != 0 {
		t.Fatalf("exchPlainItem.Open(O_RDWR): %v", oErr)
	}
	exchSF := exchFH.(*safeFile)

	exErr := repoRoot.Rename(ctx, "exch_plain", gitNode, "exch_vcs", unix.RENAME_EXCHANGE)
	if exErr == syscall.EINVAL || exErr == syscall.ENOSYS {
		_ = exchSF.Release(ctx)
		t.Skipf("RENAME_EXCHANGE unsupported on filesystem: %v", exErr)
	}
	if exErr != 0 {
		_ = exchSF.Release(ctx)
		t.Fatalf("Rename(RENAME_EXCHANGE): %v", exErr)
	}
	if _, err := SetHubShare(sockPath, "repo", nil, &vcsMask, false); err == nil {
		t.Error("expected VCSMask downgrade without force to fail after RENAME_EXCHANGE into .git")
	}
	if _, err := SetHubShare(sockPath, "repo", nil, &vcsMask, true); err != nil {
		t.Fatalf("SetHubShare(mask, force): %v", err)
	}
	if _, wErr := exchSF.Write(ctx, []byte("blocked"), 0); wErr != syscall.ESTALE {
		t.Errorf("exchSF.Write after mask downgrade = %v, want ESTALE", wErr)
	}
	_ = exchSF.Release(ctx)

	// 4. Concurrent Open/Create and directory Rename under -race.
	if _, err := SetHubShare(sockPath, "repo", nil, &vcsHooks, true); err != nil {
		t.Fatal(err)
	}
	raceDir := filepath.Join(repoDir, "racedir")
	if err := os.MkdirAll(raceDir, 0o755); err != nil {
		t.Fatal(err)
	}
	raceNode := lookupAttach(repoRoot, "racedir")
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 15; i++ {
			var ce fuse.EntryOut
			_, fh, _, cErr := raceNode.Create(ctx, fmt.Sprintf("f%d.txt", i), syscall.O_RDWR, 0o644, &ce)
			if cErr == 0 && fh != nil {
				_ = fh.(*safeFile).Release(ctx)
			}
		}
	}()
	go func() {
		defer wg.Done()
		_ = repoRoot.Rename(ctx, "racedir", gitNode, "racedir_in_git", 0)
	}()
	wg.Wait()
}

// TestRM1WorktreeConfigAndSubmoduleNamesAndMkdirVCSAllow verifies [R-M1], Mkdir under VCSAllow,
// [R-L1] single-file Setattr nlink check, and non-blocking FIFO opens in vcsfuse/hub helpers.
func TestRM1WorktreeConfigAndSubmoduleNamesAndMkdirVCSAllow(t *testing.T) {
	// 1. [R-M1] Table-driven verification of .git/config.worktree and modules/worktrees named refs/logs/objects.
	cases := []struct {
		rel  string
		want bool
	}{
		{".git/config.worktree", true},
		{".git/worktrees/wt1/config.worktree", true},
		{".git/worktrees/refs/config", true},
		{".git/worktrees/refs/config.worktree", true},
		{".git/worktrees/logs/config", true},
		{".git/worktrees/objects/config", true},
		{".git/modules/objects/config", true},
		{".git/modules/refs/config", true},
		{".git/modules/logs/config", true},
		{".git/modules/objects/commondir", true},
		{".git/modules/objects/refs/heads/config", false},
		{".git/refs/heads/config.worktree", false},
		{".git/logs/refs/heads/config.worktree", false},
	}
	for _, tc := range cases {
		if got := isProtectedVCSHookRelPath(tc.rel); got != tc.want {
			t.Errorf("isProtectedVCSHookRelPath(%q) = %v, want %v", tc.rel, got, tc.want)
		}
	}

	// 2. Mkdir of top-level VCS admin directories fails with EPERM under VCSAllow.
	ctx := context.Background()
	base := t.TempDir()
	dataDir := filepath.Join(base, "data")
	repoDir := filepath.Join(base, "repo")
	singleFile := filepath.Join(base, "single.txt")
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(repoDir, ".git", "refs", "heads"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(repoDir, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(singleFile, []byte("hello\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	hub, err := NewWorkspaceHubWithOptions([]HubShareConfig{
		{GuestName: "repo", HostPath: repoDir, ReadOnly: false, VCSPolicy: config.VCSAllow},
		{GuestName: "single.txt", HostPath: singleFile, ReadOnly: false, VCSPolicy: config.VCSMask},
	}, HubOptions{HomeReal: base, DataDir: dataDir})
	if err != nil {
		t.Fatalf("NewWorkspaceHubWithOptions: %v", err)
	}
	defer hub.CloseAll()
	_ = fs.NewNodeFS(hub, &fs.Options{})

	slot := hub.slots["repo"]
	var sySt syscall.Stat_t
	_ = syscall.Stat(repoDir, &sySt)
	repoRoot := buildRootFilteredNode(repoDir, slot.root, sySt, slot)
	fs.NewNodeFS(repoRoot, &fs.Options{})

	var eOut fuse.EntryOut
	subIno, errNo := repoRoot.Lookup(ctx, "sub", &eOut)
	if errNo != 0 {
		t.Fatalf("Lookup(sub): %v", errNo)
	}
	repoRoot.AddChild("sub", subIno, true)
	subNode := subIno.Operations().(*filteredNode)

	for _, adminName := range []string{".git", ".jj", ".hg", ".svn", "_darcs", ".pijul", ".fossil-settings", "_fossil_", ".bzr", ".sl"} {
		if _, mErr := repoRoot.Mkdir(ctx, adminName, 0o755, &eOut); mErr != syscall.EPERM {
			t.Errorf("repoRoot.Mkdir(%q) under VCSAllow = %v, want EPERM", adminName, mErr)
		}
		if _, mErr := subNode.Mkdir(ctx, adminName, 0o755, &eOut); mErr != syscall.EPERM {
			t.Errorf("subNode.Mkdir(%q) under VCSAllow = %v, want EPERM", adminName, mErr)
		}
	}
	if _, mErr := subNode.Mkdir(ctx, "allowed_dir", 0o755, &eOut); mErr != 0 {
		t.Errorf("subNode.Mkdir(allowed_dir) = %v, want 0", mErr)
	}

	// 3. [R-L1] fileShareNode.Setattr rejects path-based mutation when host file gains a second hard link.
	fileSlot := hub.slots["single.txt"]
	fNode := &fileShareNode{slot: fileSlot}
	hardPeer := filepath.Join(base, "single-hard.txt")
	if err := os.Link(singleFile, hardPeer); err != nil {
		t.Fatalf("os.Link: %v", err)
	}
	var setIn fuse.SetAttrIn
	setIn.Valid = fuse.FATTR_SIZE
	setIn.Size = 0
	var aOut fuse.AttrOut
	if sErr := fNode.Setattr(ctx, nil, &setIn, &aOut); sErr != syscall.EPERM {
		t.Errorf("fileShareNode.Setattr with Nlink=2 = %v, want EPERM", sErr)
	}
	_ = os.Remove(hardPeer)
	if sErr := fNode.Setattr(ctx, nil, &setIn, &aOut); sErr != 0 {
		t.Errorf("fileShareNode.Setattr with Nlink=1 = %v, want 0", sErr)
	}

	// 4. [R-L1] FIFO paths do not block decodeHubBootstrapSpec or appendDaemonStderr.
	fifoPath := filepath.Join(base, "spec.fifo")
	if err := syscall.Mkfifo(fifoPath, 0o600); err != nil {
		t.Fatalf("Mkfifo: %v", err)
	}
	done := make(chan error, 2)
	go func() {
		_, dErr := decodeHubBootstrapSpec(filepath.Join(base, "mnt"), filepath.Join(base, "ws.sock"), -1, fifoPath)
		done <- dErr
	}()
	select {
	case dErr := <-done:
		if dErr == nil || !strings.Contains(dErr.Error(), "refusing non-regular hub spec file") {
			t.Errorf("decodeHubBootstrapSpec(FIFO) = %v, want non-regular error", dErr)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("decodeHubBootstrapSpec blocked on FIFO")
	}

	go func() {
		done <- appendDaemonStderr(errors.New("boot failed"), fifoPath)
	}()
	select {
	case aErr := <-done:
		if aErr == nil || aErr.Error() != "boot failed" {
			t.Errorf("appendDaemonStderr(FIFO) = %v, want 'boot failed'", aErr)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("appendDaemonStderr blocked on FIFO")
	}
}
