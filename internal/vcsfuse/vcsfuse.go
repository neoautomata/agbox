// Package vcsfuse implements a hardened loopback FUSE filesystem for host shares.
//
// Security properties:
//   - Masks all DefaultHiddenEntries case-insensitively at every depth (Lookup
//     returns ENOENT and directory streams omit them) and blocks all writes to
//     those names with EPERM.
//   - Pins the share root directory descriptor and resolves every path with Linux
//     openat2 (RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS) so host symlinks cannot
//     escape the share or redirect writes.
//   - Rejects unattached or deleted child inodes with ENOENT so they never
//     resolve to the share root.
//   - Validates symlink targets on both Symlink and Readlink to allow only
//     relative intra-share targets that reference no hidden VCS names.
//   - Mounts with nosuid,nodev and restricts Open and Mknod to regular files
//     (blocking FIFOs, sockets, and device nodes with EPERM).
//   - Strips setuid and setgid bits on creation and blocks setuid/setgid modes
//     and cross-UID/GID ownership changes in Setattr with EPERM.
//   - Wraps open handles in safeFile and filteredDir to block raw FD passthrough
//     and host filesystem ioctl calls.
//   - Permits only user.<name> extended attributes, blocking security.*,
//     system.*, and trusted.* attributes.
package vcsfuse

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"agbox/internal/mounttab"
	"agbox/internal/pathsec"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"
	"golang.org/x/sys/unix"
)

// DefaultHiddenEntries lists all VCS directories and control files masked in
// every directory share.
var DefaultHiddenEntries = pathsec.DefaultVCSNames()

// SubcommandName is the internal argv[1] token used when agbox starts a
// background FUSE filter daemon.
const SubcommandName = "__filter"

// IsProtectedXattr reports whether setting or removing attr is forbidden.
// Only user.* extended attributes are allowed. This blocks security.*,
// system.*, and trusted.* attributes.
func IsProtectedXattr(attr string) bool {
	if !strings.HasPrefix(attr, "user.") {
		return true
	}
	return len(attr) <= len("user.")
}

// buildHiddenSet converts entry names into a lowercase lookup map.
func buildHiddenSet(entries []string) map[string]struct{} {
	if len(entries) == 0 {
		entries = DefaultHiddenEntries
	}
	set := make(map[string]struct{}, len(entries))
	for _, e := range entries {
		clean := strings.ToLower(strings.TrimSpace(e))
		if clean != "" {
			set[clean] = struct{}{}
		}
	}
	return set
}

func isHiddenEntry(name string, hidden map[string]struct{}) bool {
	if name == "" {
		return false
	}
	_, blocked := hidden[strings.ToLower(name)]
	return blocked
}

func isInvalidComponent(name string) bool {
	return name == "" || name == "." || name == ".." ||
		strings.ContainsRune(name, '/') || strings.ContainsRune(name, 0)
}

// ValidateSymlinkTarget checks whether creating or reading a symlink named
// linkName inside parentRelPath with value target is safe.
// It rejects empty targets, absolute targets, hidden VCS components, and
// relative targets that escape above the share root.
func ValidateSymlinkTarget(parentRelPath, linkName, target string, hidden map[string]struct{}) syscall.Errno {
	if isInvalidComponent(linkName) {
		return syscall.EINVAL
	}
	if isHiddenEntry(linkName, hidden) {
		return syscall.EPERM
	}
	if target == "" || strings.ContainsRune(target, 0) {
		return syscall.EINVAL
	}
	if strings.HasPrefix(target, "/") {
		return syscall.EPERM
	}

	depth := 0
	if parentRelPath != "" && parentRelPath != "." {
		for _, part := range strings.Split(parentRelPath, "/") {
			if part == "" || part == "." {
				continue
			}
			if part == ".." || isHiddenEntry(part, hidden) {
				return syscall.EPERM
			}
			depth++
		}
	}

	for _, seg := range strings.Split(target, "/") {
		if seg == "" || seg == "." {
			continue
		}
		if isHiddenEntry(seg, hidden) {
			return syscall.EPERM
		}
		if seg == ".." {
			depth--
			if depth < 0 {
				return syscall.EPERM
			}
			continue
		}
		depth++
	}
	return 0
}

// pinnedRoot holds an open directory file descriptor for the share root.
// All path resolutions run relative to this descriptor with RESOLVE_BENEATH
// and RESOLVE_NO_SYMLINKS so host symlinks cannot escape the share.
type pinnedRoot struct {
	mu   sync.RWMutex
	fd   int
	dev  uint64
	euid int
	egid int
}

func newPinnedRoot(srcDir string) (*pinnedRoot, syscall.Stat_t, error) {
	fd, err := unix.Open(srcDir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, syscall.Stat_t{}, err
	}
	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil {
		_ = unix.Close(fd)
		return nil, syscall.Stat_t{}, err
	}
	pr := &pinnedRoot{
		fd:   fd,
		dev:  uint64(st.Dev),
		euid: os.Geteuid(),
		egid: os.Getegid(),
	}
	runtime.SetFinalizer(pr, (*pinnedRoot).Close)
	return pr, st, nil
}

func (p *pinnedRoot) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.fd >= 0 {
		_ = unix.Close(p.fd)
		p.fd = -1
	}
}

func (p *pinnedRoot) openat2(relPath string, flags int, mode uint32) (int, error) {
	if relPath == "" {
		relPath = "."
	}
	if strings.HasPrefix(relPath, "/") {
		return -1, syscall.EINVAL
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.fd < 0 {
		return -1, syscall.EBADF
	}
	how := unix.OpenHow{
		Flags:   uint64(flags) | unix.O_CLOEXEC,
		Mode:    uint64(mode),
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS,
	}
	return unix.Openat2(p.fd, relPath, &how)
}

func openat2FromDir(dirFD int, name string, flags int, mode uint32) (int, error) {
	if isInvalidComponent(name) {
		return -1, syscall.EINVAL
	}
	how := unix.OpenHow{
		Flags:   uint64(flags) | unix.O_CLOEXEC,
		Mode:    uint64(mode),
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS,
	}
	return unix.Openat2(dirFD, name, &how)
}

// FilteredNode wraps fs.LoopbackNode to enforce VCS masking and host boundary
// rules on every directory and file operation.
type FilteredNode struct {
	*fs.LoopbackNode
	root   *pinnedRoot
	hidden map[string]struct{}
	isRoot bool
}

func (n *FilteredNode) OnForget() {
	if n.isRoot && n.root != nil {
		n.root.Close()
	}
}

func (n *FilteredNode) isHidden(name string) bool {
	return isHiddenEntry(name, n.hidden)
}

func (n *FilteredNode) checkWritableName(name string) syscall.Errno {
	if isInvalidComponent(name) {
		return syscall.EINVAL
	}
	if n.isHidden(name) {
		return syscall.EPERM
	}
	return 0
}

func (n *FilteredNode) relPath() string {
	var rootInode *fs.Inode
	if n.RootData != nil && n.RootData.RootNode != nil {
		rootInode = n.RootData.RootNode.EmbeddedInode()
	} else {
		rootInode = n.Root()
	}
	return n.Path(rootInode)
}

func (n *FilteredNode) validatedRelPath() (string, syscall.Errno) {
	if n.root == nil {
		return "", syscall.EIO
	}
	rel := n.relPath()
	if rel == "" || rel == "." {
		if n.isRoot {
			return ".", 0
		}
		return "", syscall.ENOENT
	}
	if strings.HasPrefix(rel, ".deleted") {
		return "", syscall.ENOENT
	}
	for _, part := range strings.Split(rel, "/") {
		if part == "" {
			continue
		}
		if part == "." || part == ".." {
			return "", syscall.EPERM
		}
		if n.isHidden(part) {
			return "", syscall.ENOENT
		}
	}
	return rel, 0
}

func (n *FilteredNode) openDirFD() (int, syscall.Errno) {
	rel, errno := n.validatedRelPath()
	if errno != 0 {
		return -1, errno
	}
	fd, err := n.root.openat2(rel, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return -1, fs.ToErrno(err)
	}
	return fd, 0
}

func (n *FilteredNode) openNodeOPath() (int, syscall.Errno) {
	rel, errno := n.validatedRelPath()
	if errno != 0 {
		return -1, errno
	}
	fd, err := n.root.openat2(rel, unix.O_PATH|unix.O_NOFOLLOW, 0)
	if err != nil {
		return -1, fs.ToErrno(err)
	}
	return fd, 0
}

func (n *FilteredNode) openParentAndName() (int, string, string, syscall.Errno) {
	rel, errno := n.validatedRelPath()
	if errno != 0 {
		return -1, "", "", errno
	}
	if rel == "." || rel == "" {
		return -1, "", "", syscall.EINVAL
	}
	parentRel := filepath.Dir(rel)
	baseName := filepath.Base(rel)
	if isInvalidComponent(baseName) {
		return -1, "", "", syscall.EINVAL
	}
	if n.isHidden(baseName) {
		return -1, "", "", syscall.ENOENT
	}
	fd, err := n.root.openat2(parentRel, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return -1, "", "", fs.ToErrno(err)
	}
	return fd, parentRel, baseName, 0
}

func (n *FilteredNode) stableAttr(st *syscall.Stat_t, btime *syscall.Timespec) fs.StableAttr {
	gen := uint64(1)
	if btime != nil && (btime.Sec != 0 || btime.Nsec != 0) {
		gen = uint64(btime.Sec)*1e9 + uint64(btime.Nsec)
	}
	dev := uint64(st.Dev)
	swapped := (dev << 32) | (dev >> 32)
	swappedRoot := (n.root.dev << 32) | (n.root.dev >> 32)
	return fs.StableAttr{
		Mode: uint32(st.Mode),
		Gen:  gen,
		Ino:  (swapped ^ swappedRoot) ^ st.Ino,
	}
}

func (n *FilteredNode) newChildInode(ctx context.Context, name string, st *syscall.Stat_t, btime *syscall.Timespec) *fs.Inode {
	child := &FilteredNode{
		LoopbackNode: &fs.LoopbackNode{RootData: n.RootData},
		root:         n.root,
		hidden:       n.hidden,
	}
	_ = name
	return n.NewInode(ctx, child, n.stableAttr(st, btime))
}

func statAtNoFollow(dirFD int, name string, st *syscall.Stat_t, btime *syscall.Timespec) error {
	*btime = syscall.Timespec{}
	flags := unix.AT_SYMLINK_NOFOLLOW
	if name == "" {
		flags |= unix.AT_EMPTY_PATH
	}
	var sx unix.Statx_t
	err := unix.Statx(dirFD, name, flags, unix.STATX_BASIC_STATS|unix.STATX_BTIME, &sx)
	if err == nil {
		fillStatFromStatx(&sx, st)
		if sx.Mask&unix.STATX_BTIME != 0 {
			*btime = syscall.Timespec(unix.NsecToTimespec(sx.Btime.Sec*1e9 + int64(sx.Btime.Nsec)))
		}
		return nil
	}
	if !errors.Is(err, unix.ENOSYS) {
		return err
	}
	if name == "" {
		return syscall.Fstat(dirFD, st)
	}
	var uSt unix.Stat_t
	if uErr := unix.Fstatat(dirFD, name, &uSt, unix.AT_SYMLINK_NOFOLLOW); uErr != nil {
		return uErr
	}
	copyUnixStat(&uSt, st)
	return nil
}

func fillStatFromStatx(sx *unix.Statx_t, st *syscall.Stat_t) {
	st.Dev = uint64(unix.Mkdev(sx.Dev_major, sx.Dev_minor))
	st.Ino = sx.Ino
	st.Nlink = uint64(sx.Nlink)
	st.Mode = uint32(sx.Mode)
	st.Uid = sx.Uid
	st.Gid = sx.Gid
	st.Rdev = uint64(unix.Mkdev(sx.Rdev_major, sx.Rdev_minor))
	st.Size = int64(sx.Size)
	st.Blksize = int64(sx.Blksize)
	st.Blocks = int64(sx.Blocks)
	st.Atim = syscall.Timespec(unix.NsecToTimespec(sx.Atime.Sec*1e9 + int64(sx.Atime.Nsec)))
	st.Mtim = syscall.Timespec(unix.NsecToTimespec(sx.Mtime.Sec*1e9 + int64(sx.Mtime.Nsec)))
	st.Ctim = syscall.Timespec(unix.NsecToTimespec(sx.Ctime.Sec*1e9 + int64(sx.Ctime.Nsec)))
}

func copyUnixStat(u *unix.Stat_t, st *syscall.Stat_t) {
	st.Dev = uint64(u.Dev)
	st.Ino = u.Ino
	st.Nlink = uint64(u.Nlink)
	st.Mode = u.Mode
	st.Uid = u.Uid
	st.Gid = u.Gid
	st.Rdev = uint64(u.Rdev)
	st.Size = u.Size
	st.Blksize = int64(u.Blksize)
	st.Blocks = u.Blocks
	st.Atim = syscall.Timespec{Sec: u.Atim.Sec, Nsec: u.Atim.Nsec}
	st.Mtim = syscall.Timespec{Sec: u.Mtim.Sec, Nsec: u.Mtim.Nsec}
	st.Ctim = syscall.Timespec{Sec: u.Ctim.Sec, Nsec: u.Ctim.Nsec}
}

func sanitizeCreateMode(mode uint32) uint32 {
	return (mode & 0o7777) &^ uint32(syscall.S_ISUID|syscall.S_ISGID)
}

func validateSetAttrIn(in *fuse.SetAttrIn, euid, egid int) syscall.Errno {
	if m, ok := in.GetMode(); ok {
		if m&uint32(syscall.S_ISUID|syscall.S_ISGID) != 0 {
			return syscall.EPERM
		}
	}
	if uid, ok := in.GetUID(); ok && int(uid) != euid {
		return syscall.EPERM
	}
	if gid, ok := in.GetGID(); ok && int(gid) != egid {
		return syscall.EPERM
	}
	return 0
}

// safeFile wraps fs.LoopbackFile while hiding raw fd passthrough and ioctl.
// It also blocks setuid/setgid mode bits and cross-user chown on open handles.
type safeFile struct {
	raw  *fs.LoopbackFile
	euid int
	egid int
}

func newSafeFile(fd int, euid, egid int) *safeFile {
	lf := fs.NewLoopbackFileFromOS(os.NewFile(uintptr(fd), ""))
	return &safeFile{raw: lf, euid: euid, egid: egid}
}

func (f *safeFile) Read(ctx context.Context, dest []byte, off int64) (fuse.ReadResult, syscall.Errno) {
	return f.raw.Read(ctx, dest, off)
}

func (f *safeFile) Write(ctx context.Context, data []byte, off int64) (uint32, syscall.Errno) {
	return f.raw.Write(ctx, data, off)
}

func (f *safeFile) Release(ctx context.Context) syscall.Errno {
	return f.raw.Release(ctx)
}

func (f *safeFile) Flush(ctx context.Context) syscall.Errno {
	return f.raw.Flush(ctx)
}

func (f *safeFile) Fsync(ctx context.Context, flags uint32) syscall.Errno {
	return f.raw.Fsync(ctx, flags)
}

func (f *safeFile) Getlk(ctx context.Context, owner uint64, lk *fuse.FileLock, flags uint32, out *fuse.FileLock) syscall.Errno {
	return f.raw.Getlk(ctx, owner, lk, flags, out)
}

func (f *safeFile) Setlk(ctx context.Context, owner uint64, lk *fuse.FileLock, flags uint32) syscall.Errno {
	return f.raw.Setlk(ctx, owner, lk, flags)
}

func (f *safeFile) Setlkw(ctx context.Context, owner uint64, lk *fuse.FileLock, flags uint32) syscall.Errno {
	return f.raw.Setlkw(ctx, owner, lk, flags)
}

func (f *safeFile) Getattr(ctx context.Context, out *fuse.AttrOut) syscall.Errno {
	return f.raw.Getattr(ctx, out)
}

func (f *safeFile) Lseek(ctx context.Context, off uint64, whence uint32) (uint64, syscall.Errno) {
	return f.raw.Lseek(ctx, off, whence)
}

func (f *safeFile) Allocate(ctx context.Context, off uint64, sz uint64, mode uint32) syscall.Errno {
	return f.raw.Allocate(ctx, off, sz, mode)
}

func (f *safeFile) Setattr(ctx context.Context, in *fuse.SetAttrIn, out *fuse.AttrOut) syscall.Errno {
	if errno := validateSetAttrIn(in, f.euid, f.egid); errno != 0 {
		return errno
	}
	cleanIn := *in
	cleanIn.Valid &^= fuse.FATTR_UID | fuse.FATTR_GID
	return f.raw.Setattr(ctx, &cleanIn, out)
}

func (n *FilteredNode) Statfs(ctx context.Context, out *fuse.StatfsOut) syscall.Errno {
	fd, errno := n.openNodeOPath()
	if errno != 0 {
		return errno
	}
	defer unix.Close(fd)
	var s syscall.Statfs_t
	if err := syscall.Fstatfs(fd, &s); err != nil {
		return fs.ToErrno(err)
	}
	out.FromStatfsT(&s)
	return 0
}

func (n *FilteredNode) Lookup(ctx context.Context, name string, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	if isInvalidComponent(name) {
		return nil, syscall.EINVAL
	}
	if n.isHidden(name) {
		return nil, syscall.ENOENT
	}
	dirFD, errno := n.openDirFD()
	if errno != 0 {
		return nil, errno
	}
	defer unix.Close(dirFD)

	var st syscall.Stat_t
	var btime syscall.Timespec
	if err := statAtNoFollow(dirFD, name, &st, &btime); err != nil {
		return nil, fs.ToErrno(err)
	}
	out.Attr.FromStat(&st)
	return n.newChildInode(ctx, name, &st, &btime), 0
}

func (n *FilteredNode) Open(ctx context.Context, flags uint32) (fs.FileHandle, uint32, syscall.Errno) {
	rel, errno := n.validatedRelPath()
	if errno != 0 {
		return nil, 0, errno
	}
	openFlags := int(flags&^(syscall.O_APPEND|fuse.FMODE_EXEC)) | unix.O_NOFOLLOW
	fd, err := n.root.openat2(rel, openFlags, 0)
	if err != nil {
		return nil, 0, fs.ToErrno(err)
	}
	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil {
		_ = unix.Close(fd)
		return nil, 0, fs.ToErrno(err)
	}
	if (st.Mode & syscall.S_IFMT) != syscall.S_IFREG {
		_ = unix.Close(fd)
		return nil, 0, syscall.EPERM
	}
	return newSafeFile(fd, n.root.euid, n.root.egid), 0, 0
}

func (n *FilteredNode) Create(ctx context.Context, name string, flags uint32, mode uint32, out *fuse.EntryOut) (*fs.Inode, fs.FileHandle, uint32, syscall.Errno) {
	if errno := n.checkWritableName(name); errno != 0 {
		return nil, nil, 0, errno
	}
	dirFD, errno := n.openDirFD()
	if errno != 0 {
		return nil, nil, 0, errno
	}
	defer unix.Close(dirFD)

	openFlags := int(flags&^syscall.O_APPEND) | os.O_CREATE | unix.O_NOFOLLOW
	cleanMode := sanitizeCreateMode(mode)
	fd, err := openat2FromDir(dirFD, name, openFlags, cleanMode)
	if err != nil {
		return nil, nil, 0, fs.ToErrno(err)
	}
	var st syscall.Stat_t
	var btime syscall.Timespec
	if err := statAtNoFollow(fd, "", &st, &btime); err != nil {
		_ = unix.Close(fd)
		return nil, nil, 0, fs.ToErrno(err)
	}
	if (st.Mode & syscall.S_IFMT) != syscall.S_IFREG {
		_ = unix.Close(fd)
		return nil, nil, 0, syscall.EPERM
	}
	out.FromStat(&st)
	ch := n.newChildInode(ctx, name, &st, &btime)
	return ch, newSafeFile(fd, n.root.euid, n.root.egid), 0, 0
}

func (n *FilteredNode) Tmpfile(ctx context.Context, flags uint32, mode uint32, out *fuse.EntryOut) (*fs.Inode, fs.FileHandle, uint32, syscall.Errno) {
	dirFD, errno := n.openDirFD()
	if errno != 0 {
		return nil, nil, 0, errno
	}
	defer unix.Close(dirFD)

	cleanMode := sanitizeCreateMode(mode)
	openFlags := int(flags&^syscall.O_APPEND) | unix.O_TMPFILE | unix.O_CLOEXEC
	fd, err := unix.Openat(dirFD, ".", openFlags, cleanMode)
	if err != nil {
		return nil, nil, 0, fs.ToErrno(err)
	}
	var st syscall.Stat_t
	var btime syscall.Timespec
	if err := statAtNoFollow(fd, "", &st, &btime); err != nil {
		_ = unix.Close(fd)
		return nil, nil, 0, fs.ToErrno(err)
	}
	out.FromStat(&st)
	ch := n.newChildInode(ctx, "", &st, &btime)
	return ch, newSafeFile(fd, n.root.euid, n.root.egid), 0, 0
}

func (n *FilteredNode) Mkdir(ctx context.Context, name string, mode uint32, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	if errno := n.checkWritableName(name); errno != 0 {
		return nil, errno
	}
	dirFD, errno := n.openDirFD()
	if errno != 0 {
		return nil, errno
	}
	defer unix.Close(dirFD)

	if err := unix.Mkdirat(dirFD, name, sanitizeCreateMode(mode)); err != nil {
		return nil, fs.ToErrno(err)
	}
	var st syscall.Stat_t
	var btime syscall.Timespec
	if err := statAtNoFollow(dirFD, name, &st, &btime); err != nil {
		_ = unix.Unlinkat(dirFD, name, unix.AT_REMOVEDIR)
		return nil, fs.ToErrno(err)
	}
	out.Attr.FromStat(&st)
	return n.newChildInode(ctx, name, &st, &btime), 0
}

func (n *FilteredNode) Mknod(ctx context.Context, name string, mode uint32, _ uint32, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	if errno := n.checkWritableName(name); errno != 0 {
		return nil, errno
	}
	if (mode & syscall.S_IFMT) != syscall.S_IFREG {
		return nil, syscall.EPERM
	}
	dirFD, errno := n.openDirFD()
	if errno != 0 {
		return nil, errno
	}
	defer unix.Close(dirFD)

	cleanMode := uint32(syscall.S_IFREG) | sanitizeCreateMode(mode)
	if err := unix.Mknodat(dirFD, name, cleanMode, 0); err != nil {
		return nil, fs.ToErrno(err)
	}
	var st syscall.Stat_t
	var btime syscall.Timespec
	if err := statAtNoFollow(dirFD, name, &st, &btime); err != nil {
		_ = unix.Unlinkat(dirFD, name, 0)
		return nil, fs.ToErrno(err)
	}
	out.Attr.FromStat(&st)
	return n.newChildInode(ctx, name, &st, &btime), 0
}

func (n *FilteredNode) Symlink(ctx context.Context, target, name string, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	if errno := n.checkWritableName(name); errno != 0 {
		return nil, errno
	}
	rel, errno := n.validatedRelPath()
	if errno != 0 {
		return nil, errno
	}
	if errno := ValidateSymlinkTarget(rel, name, target, n.hidden); errno != 0 {
		return nil, errno
	}
	dirFD, errno := n.openDirFD()
	if errno != 0 {
		return nil, errno
	}
	defer unix.Close(dirFD)

	if err := unix.Symlinkat(target, dirFD, name); err != nil {
		return nil, fs.ToErrno(err)
	}
	var st syscall.Stat_t
	var btime syscall.Timespec
	if err := statAtNoFollow(dirFD, name, &st, &btime); err != nil {
		_ = unix.Unlinkat(dirFD, name, 0)
		return nil, fs.ToErrno(err)
	}
	out.Attr.FromStat(&st)
	return n.newChildInode(ctx, name, &st, &btime), 0
}

func (n *FilteredNode) Link(ctx context.Context, target fs.InodeEmbedder, name string, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	if errno := n.checkWritableName(name); errno != 0 {
		return nil, errno
	}
	src, ok := target.(*FilteredNode)
	if !ok || src.root == nil || src.root != n.root {
		return nil, syscall.EXDEV
	}
	srcParentFD, _, srcBase, errno := src.openParentAndName()
	if errno != 0 {
		return nil, errno
	}
	defer unix.Close(srcParentFD)

	var srcSt syscall.Stat_t
	var srcBtime syscall.Timespec
	if err := statAtNoFollow(srcParentFD, srcBase, &srcSt, &srcBtime); err != nil {
		return nil, fs.ToErrno(err)
	}
	if (srcSt.Mode & syscall.S_IFMT) != syscall.S_IFREG {
		return nil, syscall.EPERM
	}

	dstDirFD, errno := n.openDirFD()
	if errno != 0 {
		return nil, errno
	}
	defer unix.Close(dstDirFD)

	if err := unix.Linkat(srcParentFD, srcBase, dstDirFD, name, 0); err != nil {
		return nil, fs.ToErrno(err)
	}
	var st syscall.Stat_t
	var btime syscall.Timespec
	if err := statAtNoFollow(dstDirFD, name, &st, &btime); err != nil {
		_ = unix.Unlinkat(dstDirFD, name, 0)
		return nil, fs.ToErrno(err)
	}
	out.Attr.FromStat(&st)
	return n.newChildInode(ctx, name, &st, &btime), 0
}

func (n *FilteredNode) Readlink(ctx context.Context) ([]byte, syscall.Errno) {
	parentFD, parentRel, baseName, errno := n.openParentAndName()
	if errno != 0 {
		return nil, errno
	}
	defer unix.Close(parentFD)

	for size := 256; ; size *= 2 {
		buf := make([]byte, size)
		sz, err := unix.Readlinkat(parentFD, baseName, buf)
		if err != nil {
			return nil, fs.ToErrno(err)
		}
		if sz < len(buf) {
			target := string(buf[:sz])
			if vErr := ValidateSymlinkTarget(parentRel, baseName, target, n.hidden); vErr != 0 {
				return nil, syscall.EPERM
			}
			return buf[:sz], 0
		}
	}
}

func (n *FilteredNode) Rmdir(ctx context.Context, name string) syscall.Errno {
	if errno := n.checkWritableName(name); errno != 0 {
		return errno
	}
	dirFD, errno := n.openDirFD()
	if errno != 0 {
		return errno
	}
	defer unix.Close(dirFD)
	return fs.ToErrno(unix.Unlinkat(dirFD, name, unix.AT_REMOVEDIR))
}

func (n *FilteredNode) Unlink(ctx context.Context, name string) syscall.Errno {
	if errno := n.checkWritableName(name); errno != 0 {
		return errno
	}
	dirFD, errno := n.openDirFD()
	if errno != 0 {
		return errno
	}
	defer unix.Close(dirFD)
	return fs.ToErrno(unix.Unlinkat(dirFD, name, 0))
}

func (n *FilteredNode) Rename(ctx context.Context, name string, newParent fs.InodeEmbedder, newName string, flags uint32) syscall.Errno {
	if errno := n.checkWritableName(name); errno != 0 {
		return errno
	}
	if errno := n.checkWritableName(newName); errno != 0 {
		return errno
	}
	dst, ok := newParent.(*FilteredNode)
	if !ok || dst.root == nil || dst.root != n.root {
		return syscall.EXDEV
	}
	if errno := dst.checkWritableName(newName); errno != 0 {
		return errno
	}

	fd1, errno := n.openDirFD()
	if errno != 0 {
		return errno
	}
	defer unix.Close(fd1)

	fd2, errno := dst.openDirFD()
	if errno != 0 {
		return errno
	}
	defer unix.Close(fd2)

	var st syscall.Stat_t
	if err := syscall.Fstat(fd1, &st); err != nil {
		return fs.ToErrno(err)
	}
	if !n.isRoot && n.Inode.StableAttr().Ino != n.stableAttr(&st, nil).Ino {
		return syscall.EBUSY
	}
	if err := syscall.Fstat(fd2, &st); err != nil {
		return fs.ToErrno(err)
	}
	if !dst.isRoot && dst.Inode.StableAttr().Ino != dst.stableAttr(&st, nil).Ino {
		return syscall.EBUSY
	}
	return fs.ToErrno(unix.Renameat2(fd1, name, fd2, newName, uint(flags)))
}

func (n *FilteredNode) Getattr(ctx context.Context, f fs.FileHandle, out *fuse.AttrOut) syscall.Errno {
	if f != nil {
		if fga, ok := f.(fs.FileGetattrer); ok {
			return fga.Getattr(ctx, out)
		}
	}
	fd, errno := n.openNodeOPath()
	if errno != 0 {
		return errno
	}
	defer unix.Close(fd)
	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil {
		return fs.ToErrno(err)
	}
	out.FromStat(&st)
	return 0
}

func (n *FilteredNode) Statx(ctx context.Context, f fs.FileHandle, flags uint32, mask uint32, out *fuse.StatxOut) syscall.Errno {
	if f != nil {
		if fga, ok := f.(fs.FileStatxer); ok {
			return fga.Statx(ctx, flags, mask, out)
		}
	}
	fd, errno := n.openNodeOPath()
	if errno != 0 {
		return errno
	}
	defer unix.Close(fd)
	var sx unix.Statx_t
	statxFlags := int(flags) | unix.AT_EMPTY_PATH | unix.AT_SYMLINK_NOFOLLOW
	if err := unix.Statx(fd, "", statxFlags, int(mask), &sx); err != nil {
		return fs.ToErrno(err)
	}
	out.FromStatx(&sx)
	return 0
}

func (n *FilteredNode) Setattr(ctx context.Context, f fs.FileHandle, in *fuse.SetAttrIn, out *fuse.AttrOut) syscall.Errno {
	if n.root == nil {
		return syscall.EIO
	}
	if errno := validateSetAttrIn(in, n.root.euid, n.root.egid); errno != 0 {
		return errno
	}
	if f != nil {
		if fsa, ok := f.(fs.FileSetattrer); ok {
			return fsa.Setattr(ctx, in, out)
		}
	}

	fd, errno := n.openNodeOPath()
	if errno != 0 {
		return errno
	}
	defer unix.Close(fd)

	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil {
		return fs.ToErrno(err)
	}

	if (st.Mode & syscall.S_IFMT) == syscall.S_IFLNK {
		if _, ok := in.GetMode(); ok {
			return syscall.EOPNOTSUPP
		}
		if _, ok := in.GetSize(); ok {
			return syscall.EINVAL
		}
		mtime, mok := in.GetMTime()
		atime, aok := in.GetATime()
		if mok || aok {
			parentFD, _, baseName, pErr := n.openParentAndName()
			if pErr != 0 {
				return pErr
			}
			defer unix.Close(parentFD)
			ts, tErr := buildTimespecs(atime, aok, mtime, mok)
			if tErr != 0 {
				return tErr
			}
			if err := unix.UtimesNanoAt(parentFD, baseName, ts, unix.AT_SYMLINK_NOFOLLOW); err != nil {
				return fs.ToErrno(err)
			}
			if err := syscall.Fstat(fd, &st); err != nil {
				return fs.ToErrno(err)
			}
		}
		out.FromStat(&st)
		return 0
	}

	// Operate on the pinned O_PATH descriptor through /proc/self/fd/<fd>.
	// This avoids path re-traversal races and works on mode 0000 regular files.
	procPath := fmt.Sprintf("/proc/self/fd/%d", fd)
	if m, ok := in.GetMode(); ok {
		if err := syscall.Chmod(procPath, sanitizeCreateMode(m)); err != nil {
			return fs.ToErrno(err)
		}
	}
	if sz, ok := in.GetSize(); ok {
		if err := syscall.Truncate(procPath, int64(sz)); err != nil {
			return fs.ToErrno(err)
		}
	}
	mtime, mok := in.GetMTime()
	atime, aok := in.GetATime()
	if mok || aok {
		ts, tErr := buildTimespecs(atime, aok, mtime, mok)
		if tErr != 0 {
			return tErr
		}
		if err := unix.UtimesNanoAt(unix.AT_FDCWD, procPath, ts, 0); err != nil {
			return fs.ToErrno(err)
		}
	}
	if err := syscall.Fstat(fd, &st); err != nil {
		return fs.ToErrno(err)
	}
	out.FromStat(&st)
	return 0
}

func buildTimespecs(atime time.Time, aok bool, mtime time.Time, mok bool) ([]unix.Timespec, syscall.Errno) {
	ta := unix.Timespec{Nsec: unix.UTIME_OMIT}
	tm := unix.Timespec{Nsec: unix.UTIME_OMIT}
	var err error
	if aok {
		ta, err = unix.TimeToTimespec(atime)
		if err != nil {
			return nil, fs.ToErrno(err)
		}
	}
	if mok {
		tm, err = unix.TimeToTimespec(mtime)
		if err != nil {
			return nil, fs.ToErrno(err)
		}
	}
	return []unix.Timespec{ta, tm}, 0
}

func (n *FilteredNode) Getxattr(ctx context.Context, attr string, dest []byte) (uint32, syscall.Errno) {
	if IsProtectedXattr(attr) {
		return 0, unix.ENODATA
	}
	fd, errno := n.openNodeOPath()
	if errno != 0 {
		return 0, errno
	}
	defer unix.Close(fd)

	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil {
		return 0, fs.ToErrno(err)
	}
	if (st.Mode & syscall.S_IFMT) == syscall.S_IFLNK {
		return 0, unix.ENODATA
	}
	sz, err := unix.Getxattr(fmt.Sprintf("/proc/self/fd/%d", fd), attr, dest)
	return uint32(sz), fs.ToErrno(err)
}

func (n *FilteredNode) Listxattr(ctx context.Context, dest []byte) (uint32, syscall.Errno) {
	fd, errno := n.openNodeOPath()
	if errno != 0 {
		return 0, errno
	}
	defer unix.Close(fd)

	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil {
		return 0, fs.ToErrno(err)
	}
	if (st.Mode & syscall.S_IFMT) == syscall.S_IFLNK {
		return 0, 0
	}
	// Operate on the pinned O_PATH descriptor through /proc/self/fd/<fd>.
	// This avoids path re-traversal races and works on mode 0000 regular files.
	procPath := fmt.Sprintf("/proc/self/fd/%d", fd)
	sz, err := unix.Listxattr(procPath, nil)
	if err != nil {
		return 0, fs.ToErrno(err)
	}
	if sz <= 0 {
		return 0, 0
	}
	raw := make([]byte, sz)
	nRead, err := unix.Listxattr(procPath, raw)
	if err != nil {
		return 0, fs.ToErrno(err)
	}
	var filtered []byte
	for _, entry := range bytes.Split(raw[:nRead], []byte{0}) {
		if len(entry) == 0 {
			continue
		}
		if !IsProtectedXattr(string(entry)) {
			filtered = append(filtered, entry...)
			filtered = append(filtered, 0)
		}
	}
	if len(dest) == 0 {
		return uint32(len(filtered)), 0
	}
	if len(dest) < len(filtered) {
		return uint32(len(filtered)), syscall.ERANGE
	}
	copy(dest, filtered)
	return uint32(len(filtered)), 0
}

func (n *FilteredNode) Setxattr(ctx context.Context, attr string, data []byte, flags uint32) syscall.Errno {
	if IsProtectedXattr(attr) {
		return syscall.EPERM
	}
	fd, errno := n.openNodeOPath()
	if errno != 0 {
		return errno
	}
	defer unix.Close(fd)

	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil {
		return fs.ToErrno(err)
	}
	if (st.Mode & syscall.S_IFMT) == syscall.S_IFLNK {
		return syscall.EPERM
	}
	err := unix.Setxattr(fmt.Sprintf("/proc/self/fd/%d", fd), attr, data, int(flags))
	return fs.ToErrno(err)
}

func (n *FilteredNode) Removexattr(ctx context.Context, attr string) syscall.Errno {
	if IsProtectedXattr(attr) {
		return syscall.EPERM
	}
	fd, errno := n.openNodeOPath()
	if errno != 0 {
		return errno
	}
	defer unix.Close(fd)

	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil {
		return fs.ToErrno(err)
	}
	if (st.Mode & syscall.S_IFMT) == syscall.S_IFLNK {
		return syscall.EPERM
	}
	err := unix.Removexattr(fmt.Sprintf("/proc/self/fd/%d", fd), attr)
	return fs.ToErrno(err)
}

func (n *FilteredNode) CopyFileRange(ctx context.Context, fhIn fs.FileHandle, offIn uint64, out *fs.Inode, fhOut fs.FileHandle, offOut uint64, length uint64, flags uint64) (uint32, syscall.Errno) {
	sfIn, ok := fhIn.(*safeFile)
	if !ok {
		return 0, unix.ENOTSUP
	}
	sfOut, ok := fhOut.(*safeFile)
	if !ok {
		return 0, unix.ENOTSUP
	}
	return n.LoopbackNode.CopyFileRange(ctx, sfIn.raw, offIn, out, sfOut.raw, offOut, length, flags)
}

func (n *FilteredNode) Readdir(ctx context.Context) (fs.DirStream, syscall.Errno) {
	dirFD, errno := n.openDirFD()
	if errno != 0 {
		return nil, errno
	}
	ds, errno := fs.NewLoopbackDirStreamFd(dirFD)
	if errno != 0 {
		_ = unix.Close(dirFD)
		return nil, errno
	}
	return &filteredStream{inner: ds, hidden: n.hidden}, 0
}

// OpendirHandle intercepts directory opens on all nodes in the filtered tree.
// It opens the directory with openat2 and forwards Releasedir, Seekdir, and
// Fsyncdir while omitting raw ioctl forwarding.
func (n *FilteredNode) OpendirHandle(ctx context.Context, _ uint32) (fs.FileHandle, uint32, syscall.Errno) {
	dirFD, errno := n.openDirFD()
	if errno != 0 {
		return nil, 0, errno
	}
	ds, errno := fs.NewLoopbackDirStreamFd(dirFD)
	if errno != 0 {
		_ = unix.Close(dirFD)
		return nil, 0, errno
	}
	if rd, ok := ds.(fs.FileReaddirenter); ok {
		return &filteredDir{inner: rd, raw: ds, hidden: n.hidden}, 0, 0
	}
	return ds, 0, 0
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
		if isHiddenEntry(de.Name, d.hidden) {
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
		if isHiddenEntry(de.Name, f.hidden) {
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
	resolvedSrc, err := filepath.EvalSymlinks(srcDir)
	if err != nil {
		return nil, fmt.Errorf("resolve source directory %q: %w", srcDir, err)
	}
	pr, st, err := newPinnedRoot(resolvedSrc)
	if err != nil {
		return nil, fmt.Errorf("open source directory %q: %w", resolvedSrc, err)
	}
	hidden := buildHiddenSet(hiddenEntries)

	rootData := &fs.LoopbackRoot{
		Path: resolvedSrc,
		Dev:  uint64(st.Dev),
	}
	rootData.NewNode = func(rd *fs.LoopbackRoot, _ *fs.Inode, _ string, _ *syscall.Stat_t) fs.InodeEmbedder {
		return &FilteredNode{
			LoopbackNode: &fs.LoopbackNode{RootData: rd},
			root:         pr,
			hidden:       hidden,
		}
	}

	root := &FilteredNode{
		LoopbackNode: &fs.LoopbackNode{RootData: rootData},
		root:         pr,
		hidden:       hidden,
		isRoot:       true,
	}
	rootData.RootNode = root

	sec := time.Second
	opts := &fs.Options{
		AttrTimeout:  &sec,
		EntryTimeout: &sec,
		MountOptions: fuse.MountOptions{
			FsName:  resolvedSrc,
			Name:    "agboxfilter",
			Options: []string{"nosuid", "nodev"},
		},
	}

	server, err := fs.Mount(mntDir, root, opts)
	if err != nil {
		pr.Close()
		return nil, fmt.Errorf("FUSE mount %q -> %q: %w", resolvedSrc, mntDir, err)
	}
	return server, nil
}

// CheckHostSupport verifies that /dev/fuse, fusermount3 or fusermount, and an
// end-to-end VCS filter mount succeed under parentDir.
func CheckHostSupport(parentDir string) error {
	f, err := os.OpenFile("/dev/fuse", os.O_RDWR, 0)
	if err != nil {
		return fmt.Errorf("/dev/fuse is not accessible: %w", err)
	}
	_ = f.Close()

	if os.Geteuid() != 0 {
		if _, err3 := exec.LookPath("fusermount3"); err3 != nil {
			if _, err2 := exec.LookPath("fusermount"); err2 != nil {
				return errors.New("fusermount3 is missing (install fuse3: sudo apt-get install -y fuse3)")
			}
		}
	}

	probeRoot, err := os.MkdirTemp(parentDir, ".fuse-probe-*")
	if err != nil {
		return fmt.Errorf("create FUSE probe dir: %w", err)
	}
	defer func() {
		_ = os.RemoveAll(probeRoot)
	}()

	srcDir := filepath.Join(probeRoot, "src")
	mntDir := filepath.Join(probeRoot, "mnt")
	if err := os.MkdirAll(srcDir, 0o700); err != nil {
		return fmt.Errorf("create FUSE probe source: %w", err)
	}
	if err := os.MkdirAll(mntDir, 0o700); err != nil {
		return fmt.Errorf("create FUSE probe mountpoint: %w", err)
	}

	server, err := Mount(srcDir, mntDir, DefaultHiddenEntries)
	if err != nil {
		return fmt.Errorf("FUSE smoke test failed: %w", err)
	}
	unmountErr := server.Unmount()
	server.Wait()
	if unmountErr != nil {
		return fmt.Errorf("FUSE probe unmount failed: %w", unmountErr)
	}
	return nil
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
// parent process exits. When dieWithParent is false, the child starts in a new
// session so it continues after the CLI exits.
func StartSubprocess(exePath, srcDir, mntDir, pidFile string, dieWithParent bool) (int, error) {
	if err := ensureSafeMountDir(mntDir); err != nil {
		return 0, fmt.Errorf("prepare mountpoint %q: %w", mntDir, err)
	}
	if err := ensureSafeMountDir(filepath.Dir(pidFile)); err != nil {
		return 0, fmt.Errorf("prepare pidfile directory: %w", err)
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

	// Wait for the child process in a goroutine so it does not become a zombie.
	exited := make(chan error, 1)
	go func() {
		exited <- cmd.Wait()
	}()

	if err := os.WriteFile(pidFile, []byte(strconv.Itoa(pid)+"\n"), 0o600); err != nil {
		_ = cmd.Process.Signal(syscall.SIGTERM)
		return 0, fmt.Errorf("write FUSE pidfile %q: %w", pidFile, err)
	}

	// Poll /proc/self/mountinfo for up to 3 seconds (60 * 50ms) until the mount is active.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		mounted, err := mounttab.IsPathMounted(mntDir)
		if err == nil && mounted {
			return pid, nil
		}
		select {
		case waitErr := <-exited:
			_ = os.Remove(pidFile)
			return 0, fmt.Errorf("FUSE filter exited before mounting %q: %w", mntDir, waitErr)
		case <-time.After(50 * time.Millisecond):
		}
	}

	// Stop the child process if the mount timed out.
	_ = cmd.Process.Signal(syscall.SIGTERM)
	return 0, fmt.Errorf("timed out waiting for FUSE mount at %q", mntDir)
}

func ensureSafeMountDir(dir string) error {
	if info, err := os.Lstat(dir); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("refusing symlinked path %q", dir)
		}
		if !info.IsDir() {
			return fmt.Errorf("path %q is not a directory", dir)
		}
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("refusing non-directory %q", dir)
	}
	return os.Chmod(dir, 0o700)
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
