// Package vcsfuse implements a loopback FUSE filesystem.
// It hides version-control directories (.git, .jj, .svn, .hg, .bzr) and blocks
// privileged extended attribute changes across a shared directory tree.
package vcsfuse

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"agbox/internal/mounttab"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"
)

// DefaultHiddenEntries is the canonical list of VCS metadata names hidden at
// the root of a filtered share.
var DefaultHiddenEntries = []string{
	".git",
	".jj",
	".svn",
	".hg",
	".bzr",
}

// SubcommandName is the internal argv[1] token used when agbox re-executes
// itself as a background FUSE filter daemon.
const SubcommandName = "__filter"

// IsProtectedXattr reports whether an extended attribute name could alter host
// POSIX ACLs or security capabilities/labels if set or removed by the guest.
func IsProtectedXattr(attr string) bool {
	return strings.HasPrefix(attr, "system.posix_acl_") ||
		strings.HasPrefix(attr, "security.")
}

// buildHiddenSet converts a list of entry names into an immutable lookup map.
func buildHiddenSet(entries []string) map[string]struct{} {
	if len(entries) == 0 {
		entries = DefaultHiddenEntries
	}
	set := make(map[string]struct{}, len(entries))
	for _, e := range entries {
		if e != "" {
			set[e] = struct{}{}
		}
	}
	return set
}

// FilteredNode wraps fs.LoopbackNode to enforce two security rules on every node:
//  1. It hides VCS entries (.git, .jj, .svn, .hg, .bzr) with ENOENT on Lookup
//     and denies creation, deletion, link, or rename of those names with EPERM.
//  2. It denies Setxattr and Removexattr on security.* and system.posix_acl_*
//     attributes with EPERM.
type FilteredNode struct {
	*fs.LoopbackNode
	hidden map[string]struct{}
}

// isHidden reports whether name is a masked VCS entry.
func (n *FilteredNode) isHidden(name string) bool {
	_, blocked := n.hidden[name]
	return blocked
}

func (n *FilteredNode) Lookup(ctx context.Context, name string, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	if n.isHidden(name) {
		return nil, syscall.ENOENT
	}
	return n.LoopbackNode.Lookup(ctx, name, out)
}

func (n *FilteredNode) Mkdir(ctx context.Context, name string, mode uint32, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	if n.isHidden(name) {
		return nil, syscall.EPERM
	}
	return n.LoopbackNode.Mkdir(ctx, name, mode, out)
}

func (n *FilteredNode) Create(ctx context.Context, name string, flags uint32, mode uint32, out *fuse.EntryOut) (*fs.Inode, fs.FileHandle, uint32, syscall.Errno) {
	if n.isHidden(name) {
		return nil, nil, 0, syscall.EPERM
	}
	return n.LoopbackNode.Create(ctx, name, flags, mode, out)
}

func (n *FilteredNode) Mknod(ctx context.Context, name string, mode uint32, dev uint32, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	if n.isHidden(name) {
		return nil, syscall.EPERM
	}
	return n.LoopbackNode.Mknod(ctx, name, mode, dev, out)
}

func (n *FilteredNode) Symlink(ctx context.Context, target, name string, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	if n.isHidden(name) {
		return nil, syscall.EPERM
	}
	return n.LoopbackNode.Symlink(ctx, target, name, out)
}

func (n *FilteredNode) Link(ctx context.Context, target fs.InodeEmbedder, name string, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	if n.isHidden(name) {
		return nil, syscall.EPERM
	}
	return n.LoopbackNode.Link(ctx, target, name, out)
}

func (n *FilteredNode) Rmdir(ctx context.Context, name string) syscall.Errno {
	if n.isHidden(name) {
		return syscall.EPERM
	}
	return n.LoopbackNode.Rmdir(ctx, name)
}

func (n *FilteredNode) Unlink(ctx context.Context, name string) syscall.Errno {
	if n.isHidden(name) {
		return syscall.EPERM
	}
	return n.LoopbackNode.Unlink(ctx, name)
}

func (n *FilteredNode) Rename(ctx context.Context, name string, newParent fs.InodeEmbedder, newName string, flags uint32) syscall.Errno {
	if n.isHidden(name) || n.isHidden(newName) {
		return syscall.EPERM
	}
	if dst, ok := newParent.(*FilteredNode); ok && dst.isHidden(newName) {
		return syscall.EPERM
	}
	return n.LoopbackNode.Rename(ctx, name, newParent, newName, flags)
}

func (n *FilteredNode) Setxattr(ctx context.Context, attr string, data []byte, flags uint32) syscall.Errno {
	if IsProtectedXattr(attr) {
		return syscall.EPERM
	}
	return n.LoopbackNode.Setxattr(ctx, attr, data, flags)
}

func (n *FilteredNode) Removexattr(ctx context.Context, attr string) syscall.Errno {
	if IsProtectedXattr(attr) {
		return syscall.EPERM
	}
	return n.LoopbackNode.Removexattr(ctx, attr)
}

func (n *FilteredNode) Readdir(ctx context.Context) (fs.DirStream, syscall.Errno) {
	ds, errno := n.LoopbackNode.Readdir(ctx)
	if errno != 0 {
		return ds, errno
	}
	return &filteredStream{inner: ds, hidden: n.hidden}, 0
}

// OpendirHandle intercepts directory opens on all nodes in the filtered tree.
//
// Why this method is required in addition to Readdir:
// fs.LoopbackNode implements fs.NodeOpendirHandler. Therefore, go-fuse calls
// OpendirHandle instead of Readdir when it serves getdents requests.
// Because fs.FileHandle has type `any`, wrapping the handle in a struct hides
// its optional methods. filteredDir must explicitly forward Releasedir, Seekdir,
// and Fsyncdir. Without Releasedir, each opendir call leaks one host directory FD.
func (n *FilteredNode) OpendirHandle(ctx context.Context, flags uint32) (fs.FileHandle, uint32, syscall.Errno) {
	fh, fuseFlags, errno := n.LoopbackNode.OpendirHandle(ctx, flags)
	if errno != 0 {
		return fh, fuseFlags, errno
	}
	if rd, ok := fh.(fs.FileReaddirenter); ok {
		return &filteredDir{inner: rd, raw: fh, hidden: n.hidden}, fuseFlags, 0
	}
	return fh, fuseFlags, 0
}

type filteredDir struct {
	inner  fs.FileReaddirenter
	raw    fs.FileHandle
	hidden map[string]struct{}
}

func (d *filteredDir) Readdirent(ctx context.Context) (*fuse.DirEntry, syscall.Errno) {
	for {
		de, errno := d.inner.Readdirent(ctx)
		if errno != 0 || de == nil {
			return de, errno
		}
		if _, skip := d.hidden[de.Name]; skip {
			continue
		}
		return de, 0
	}
}

func (d *filteredDir) Releasedir(ctx context.Context, releaseFlags uint32) {
	if r, ok := d.raw.(fs.FileReleasedirer); ok {
		r.Releasedir(ctx, releaseFlags)
	}
}

func (d *filteredDir) Seekdir(ctx context.Context, off uint64) syscall.Errno {
	if s, ok := d.raw.(fs.FileSeekdirer); ok {
		return s.Seekdir(ctx, off)
	}
	return syscall.ENOTSUP
}

func (d *filteredDir) Fsyncdir(ctx context.Context, flags uint32) syscall.Errno {
	if f, ok := d.raw.(fs.FileFsyncdirer); ok {
		return f.Fsyncdir(ctx, flags)
	}
	return syscall.ENOTSUP
}

type filteredStream struct {
	inner  fs.DirStream
	hidden map[string]struct{}
	peeked *fuse.DirEntry
	peekEr syscall.Errno
	hasPk  bool
}

func (f *filteredStream) advance() {
	for f.inner.HasNext() {
		de, errno := f.inner.Next()
		if errno != 0 {
			f.peekEr = errno
			f.hasPk = true
			return
		}
		if _, skip := f.hidden[de.Name]; skip {
			continue
		}
		f.peeked = &de
		f.peekEr = 0
		f.hasPk = true
		return
	}
	f.hasPk = false
}

func (f *filteredStream) HasNext() bool {
	if !f.hasPk {
		f.advance()
	}
	return f.hasPk
}

func (f *filteredStream) Next() (fuse.DirEntry, syscall.Errno) {
	if !f.hasPk {
		f.advance()
	}
	f.hasPk = false
	if f.peekEr != 0 || f.peeked == nil {
		return fuse.DirEntry{}, f.peekEr
	}
	return *f.peeked, 0
}

func (f *filteredStream) Close() {
	f.inner.Close()
}

// Mount mounts a VCS-filtered loopback view of srcDir onto mntDir and returns
// the running FUSE server. Call server.Unmount() and server.Wait() to stop it.
func Mount(srcDir, mntDir string, hiddenEntries []string) (*fuse.Server, error) {
	if srcDir == "" || mntDir == "" {
		return nil, errors.New("both source and mount directories are required")
	}
	hidden := buildHiddenSet(hiddenEntries)

	var st syscall.Stat_t
	if err := syscall.Stat(srcDir, &st); err != nil {
		return nil, fmt.Errorf("stat source directory %q: %w", srcDir, err)
	}

	rootData := &fs.LoopbackRoot{
		Path: srcDir,
		Dev:  uint64(st.Dev),
	}
	// Wrap every child node in FilteredNode so VCS masking and xattr protection
	// apply recursively across the entire tree.
	rootData.NewNode = func(rd *fs.LoopbackRoot, parent *fs.Inode, name string, st *syscall.Stat_t) fs.InodeEmbedder {
		return &FilteredNode{
			LoopbackNode: &fs.LoopbackNode{RootData: rd},
			hidden:       hidden,
		}
	}

	root := &FilteredNode{
		LoopbackNode: &fs.LoopbackNode{RootData: rootData},
		hidden:       hidden,
	}
	rootData.RootNode = root

	sec := time.Second
	opts := &fs.Options{
		AttrTimeout:  &sec,
		EntryTimeout: &sec,
		MountOptions: fuse.MountOptions{
			FsName: srcDir,
			Name:   "agboxfilter",
		},
	}

	server, err := fs.Mount(mntDir, root, opts)
	if err != nil {
		return nil, fmt.Errorf("FUSE mount %q -> %q: %w", srcDir, mntDir, err)
	}
	return server, nil
}

// RunDaemon mounts srcDir onto mntDir and blocks until the filesystem is
// unmounted or a termination signal (SIGINT, SIGTERM, SIGHUP) arrives.
func RunDaemon(srcDir, mntDir string, hiddenEntries []string) error {
	server, err := Mount(srcDir, mntDir, hiddenEntries)
	if err != nil {
		return err
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	go func() {
		<-sigCh
		_ = server.Unmount()
	}()

	server.Wait()
	return nil
}

// RunMain parses CLI arguments for the internal `__filter` subcommand and runs
// the FUSE daemon until unmounted.
func RunMain(args []string) int {
	fsFlags := flag.NewFlagSet(SubcommandName, flag.ContinueOnError)
	src := fsFlags.String("src", "", "Source directory to expose")
	mnt := fsFlags.String("mnt", "", "Mountpoint directory")
	if err := fsFlags.Parse(args); err != nil {
		fmt.Fprintf(os.Stderr, "agbox %s: %v\n", SubcommandName, err)
		return 2
	}
	if *src == "" || *mnt == "" {
		fmt.Fprintf(os.Stderr, "Usage: agbox %s -src <dir> -mnt <dir>\n", SubcommandName)
		return 2
	}
	if err := RunDaemon(*src, *mnt, DefaultHiddenEntries); err != nil {
		fmt.Fprintf(os.Stderr, "agbox %s: %v\n", SubcommandName, err)
		return 1
	}
	return 0
}

// StartSubprocess starts `exePath __filter -src <srcDir> -mnt <mntDir>` as a
// background child process. It writes the child PID to pidFile and waits until
// mntDir appears in /proc/self/mountinfo.
//
// When dieWithParent is true, the kernel sends SIGTERM to the child if the
// parent process exits. When dieWithParent is false (for detached `--serve`
// runs), the child starts in a new session so it continues after the CLI exits.
func StartSubprocess(exePath, srcDir, mntDir, pidFile string, dieWithParent bool) (int, error) {
	if err := os.MkdirAll(mntDir, 0o700); err != nil {
		return 0, fmt.Errorf("create mountpoint %q: %w", mntDir, err)
	}
	if err := os.MkdirAll(filepath.Dir(pidFile), 0o700); err != nil {
		return 0, fmt.Errorf("create pidfile directory: %w", err)
	}

	cmd := exec.Command(exePath, SubcommandName, "-src", srcDir, "-mnt", mntDir)
	cmd.Stdout = nil
	cmd.Stderr = os.Stderr
	if dieWithParent {
		cmd.SysProcAttr = &syscall.SysProcAttr{
			Pdeathsig: syscall.SIGTERM,
		}
	} else {
		cmd.SysProcAttr = &syscall.SysProcAttr{
			Setsid: true,
		}
	}

	if err := cmd.Start(); err != nil {
		return 0, fmt.Errorf("start FUSE filter subprocess: %w", err)
	}
	pid := cmd.Process.Pid
	_ = os.WriteFile(pidFile, []byte(strconv.Itoa(pid)+"\n"), 0o600)

	// Wait for the child process in a goroutine so it does not become a zombie.
	exited := make(chan error, 1)
	go func() {
		exited <- cmd.Wait()
	}()

	// Poll /proc/self/mountinfo for up to 3 seconds (60 * 50ms) until the mount is active.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		mounted, err := mounttab.IsPathMounted(mntDir)
		if err == nil && mounted {
			return pid, nil
		}
		select {
		case waitErr := <-exited:
			return 0, fmt.Errorf("FUSE filter exited before mounting %q: %w", mntDir, waitErr)
		case <-time.After(50 * time.Millisecond):
		}
	}

	// Stop the child process if the mount timed out.
	_ = cmd.Process.Signal(syscall.SIGTERM)
	return 0, fmt.Errorf("timed out waiting for FUSE mount at %q", mntDir)
}

// UnmountAndClean unmounts all active FUSE mountpoints under filterRoot and
// stops recorded filter daemons. It deletes filterRoot only after it verifies
// in /proc/self/mountinfo that no mounts remain.
func UnmountAndClean(filterRoot string) error {
	if filterRoot == "" {
		return nil
	}
	if _, err := os.Stat(filterRoot); os.IsNotExist(err) {
		return nil
	}
	return mounttab.TeardownFilterDir(filterRoot, nil)
}
