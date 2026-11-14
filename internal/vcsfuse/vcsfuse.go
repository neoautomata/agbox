// Package vcsfuse implements a hardened loopback FUSE filesystem and a
// multiplexed Workspace Hub for host shares.
//
// Security properties:
//   - Masks all DefaultHiddenEntries case-insensitively at every depth when
//     VCSPolicy is VCSMask (Lookup returns ENOENT and directory streams omit
//     them) and blocks all writes to those names with EPERM.
//   - Protects VCS hook directories (.git/**/hooks, .jj/**/hooks, .svn/**/hooks,
//     _darcs/**/prefs, .pijul/**/hooks, and .hg/hgrc) with EPERM when VCSPolicy
//     is VCSAllow, unless VCSAllowHooks is explicitly configured.
//   - Enforces per-share read-only mode (EROFS on all mutating FUSE operations
//     and stripped write mode bits) even against root inside the guest VM.
//   - Pins each share root directory descriptor and resolves every path with
//     Linux openat2 (RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS) so host symlinks
//     cannot escape the share or redirect writes.
//   - Rejects unattached or deleted child inodes with ENOENT so they never
//     resolve to the share root.
//   - Validates symlink targets on both Symlink and Readlink to allow only
//     relative intra-share targets permitted by the active VCS policy.
//   - Mounts with nosuid,nodev and restricts Open and Mknod to regular files
//     (blocking FIFOs, sockets, and device nodes with EPERM).
//   - Strips setuid and setgid bits on creation and blocks setuid/setgid modes
//     and cross-UID/GID ownership changes in Setattr with EPERM.
//   - Wraps open handles in safeFile and filteredDir to block raw FD passthrough,
//     block host filesystem ioctl calls, and allow immediate host FD revocation
//     when a share is removed or downgraded to read-only.
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
	"sync/atomic"
	"syscall"
	"time"

	"agbox/internal/config"
	"agbox/internal/mounttab"
	"agbox/internal/pathsec"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"
	"golang.org/x/sys/unix"
)

// DefaultHiddenEntries lists all VCS directories and control files masked in
// directory shares that use VCSMask.
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

// isTopLevelVCSAdminDir reports whether name is a VCS metadata directory whose
// removal or rename could displace a protected hooks directory under VCSAllow.
func isTopLevelVCSAdminDir(name string) bool {
	switch strings.ToLower(name) {
	case ".git", ".jj", ".hg", ".svn", "_darcs", ".pijul", ".fossil-settings", "_fossil_":
		return true
	default:
		return false
	}
}

// isProtectedVCSHookRelPath reports whether relPath is at or inside a VCS hook
// location (.git/**/hooks, .jj/**/hooks, .svn/**/hooks, _darcs/**/prefs,
// .pijul/**/hooks, or .hg/hgrc).
func isProtectedVCSHookRelPath(relPath string) bool {
	if relPath == "" || relPath == "." {
		return false
	}
	var segs []string
	for _, raw := range strings.Split(relPath, "/") {
		if raw == "" || raw == "." {
			continue
		}
		segs = append(segs, strings.ToLower(raw))
	}
	seenGitOrJJOrSvnOrPijul := false
	seenDarcs := false
	for i, seg := range segs {
		if seenGitOrJJOrSvnOrPijul && seg == "hooks" {
			return true
		}
		if seenDarcs && seg == "prefs" {
			return true
		}
		if seg == ".hg" && i+1 < len(segs) && segs[i+1] == "hgrc" {
			return true
		}
		switch seg {
		case ".git", ".jj", ".svn", ".pijul":
			seenGitOrJJOrSvnOrPijul = true
		case "_darcs":
			seenDarcs = true
		}
	}
	return false
}

func joinRelPath(parentRel, name string) string {
	if parentRel == "" || parentRel == "." {
		return name
	}
	return parentRel + "/" + name
}

// ValidateSymlinkTarget checks whether creating or reading a symlink named
// linkName inside parentRelPath with value target is safe under VCSMask.
// It rejects empty targets, absolute targets, hidden VCS components, and
// relative targets that escape above the share root.
func ValidateSymlinkTarget(parentRelPath, linkName, target string, hidden map[string]struct{}) syscall.Errno {
	return ValidateSymlinkTargetForPolicy(parentRelPath, linkName, target, hidden, config.VCSMask)
}

// ValidateSymlinkTargetForPolicy validates a symlink target within a share
// according to policy while always enforcing relative intra-share confinement.
func ValidateSymlinkTargetForPolicy(parentRelPath, linkName, target string, hidden map[string]struct{}, policy config.VCSPolicy) syscall.Errno {
	if isInvalidComponent(linkName) {
		return syscall.EINVAL
	}
	if policy == "" {
		policy = config.VCSMask
	}
	if policy == config.VCSMask && isHiddenEntry(linkName, hidden) {
		return syscall.EPERM
	}
	if target == "" || strings.ContainsRune(target, 0) {
		return syscall.EINVAL
	}
	if strings.HasPrefix(target, "/") {
		return syscall.EPERM
	}

	var stack []string
	if parentRelPath != "" && parentRelPath != "." {
		for _, part := range strings.Split(parentRelPath, "/") {
			if part == "" || part == "." {
				continue
			}
			if part == ".." {
				return syscall.EPERM
			}
			if policy == config.VCSMask && isHiddenEntry(part, hidden) {
				return syscall.EPERM
			}
			stack = append(stack, part)
		}
	}

	linkRel := joinRelPath(strings.Join(stack, "/"), linkName)
	if policy == config.VCSAllow && isProtectedVCSHookRelPath(linkRel) {
		return syscall.EPERM
	}

	for _, seg := range strings.Split(target, "/") {
		if seg == "" || seg == "." {
			continue
		}
		if policy == config.VCSMask && isHiddenEntry(seg, hidden) {
			return syscall.EPERM
		}
		if seg == ".." {
			if len(stack) == 0 {
				return syscall.EPERM
			}
			stack = stack[:len(stack)-1]
			continue
		}
		stack = append(stack, seg)
		if policy == config.VCSAllow && isProtectedVCSHookRelPath(strings.Join(stack, "/")) {
			return syscall.EPERM
		}
	}
	return 0
}

// pinnedRoot holds an open directory file descriptor for a share root (or the
// parent directory of a single-file share). All path resolutions run relative
// to this descriptor with RESOLVE_BENEATH and RESOLVE_NO_SYMLINKS so host
// symlinks cannot escape the share.
type pinnedRoot struct {
	mu         sync.RWMutex
	fd         int
	revokedErr syscall.Errno
	dev        uint64
	euid       int
	egid       int
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
		fd:         fd,
		revokedErr: syscall.EBADF,
		dev:        uint64(st.Dev),
		euid:       os.Geteuid(),
		egid:       os.Getegid(),
	}
	runtime.SetFinalizer(pr, (*pinnedRoot).Close)
	return pr, st, nil
}

func (p *pinnedRoot) Close() {
	p.Revoke(syscall.EBADF)
}

func (p *pinnedRoot) Revoke(errno syscall.Errno) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if errno == 0 {
		errno = syscall.ESTALE
	}
	p.revokedErr = errno
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
		return -1, p.revokedErr
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

const (
	vcsPolicyMaskUint32 uint32 = iota
	vcsPolicyAllowUint32
	vcsPolicyAllowHooksUint32
)

func vcsPolicyToUint32(p config.VCSPolicy) uint32 {
	switch p {
	case config.VCSAllow:
		return vcsPolicyAllowUint32
	case config.VCSAllowHooks:
		return vcsPolicyAllowHooksUint32
	default:
		return vcsPolicyMaskUint32
	}
}

func uint32ToVCSPolicy(v uint32) config.VCSPolicy {
	switch v {
	case vcsPolicyAllowUint32:
		return config.VCSAllow
	case vcsPolicyAllowHooksUint32:
		return config.VCSAllowHooks
	default:
		return config.VCSMask
	}
}

type guestIDMap struct {
	enabled bool
	uid     uint32
	gid     uint32
}

func newGuestIDMap(enabled bool, uid, gid uint32) guestIDMap {
	if !enabled {
		return guestIDMap{}
	}
	return guestIDMap{
		enabled: true,
		uid:     uid,
		gid:     gid,
	}
}

func (m guestIDMap) applyAttr(a *fuse.Attr) {
	if m.enabled && a != nil {
		a.Uid = m.uid
		a.Gid = m.gid
	}
}

func (m guestIDMap) applyStatx(out *fuse.StatxOut) {
	if m.enabled && out != nil {
		out.Statx.Uid = m.uid
		out.Statx.Gid = m.gid
	}
}

// shareSlot holds dynamic permission state, open file handles, and the pinned
// host directory descriptor for one mounted share.
type shareSlot struct {
	slotID    uint64
	guestName string
	hostPath  string
	isFile    bool
	fileName  string
	root      *pinnedRoot
	hidden    map[string]struct{}
	idMap     guestIDMap

	readOnly  atomic.Bool
	vcsPolicy atomic.Uint32
	revoked   atomic.Bool

	filesMu sync.Mutex
	files   map[*safeFile]struct{}

	inodeMu sync.RWMutex
	inode   *fs.Inode
}

func newShareSlot(slotID uint64, guestName, hostPath string, isFile bool, fileName string, pr *pinnedRoot, hidden map[string]struct{}, readOnly bool, policy config.VCSPolicy) *shareSlot {
	return newShareSlotWithIDMap(slotID, guestName, hostPath, isFile, fileName, pr, hidden, readOnly, policy, guestIDMap{})
}

func newShareSlotWithIDMap(slotID uint64, guestName, hostPath string, isFile bool, fileName string, pr *pinnedRoot, hidden map[string]struct{}, readOnly bool, policy config.VCSPolicy, idMap guestIDMap) *shareSlot {
	s := &shareSlot{
		slotID:    slotID,
		guestName: guestName,
		hostPath:  hostPath,
		isFile:    isFile,
		fileName:  fileName,
		root:      pr,
		hidden:    hidden,
		idMap:     idMap,
		files:     make(map[*safeFile]struct{}),
	}
	s.readOnly.Store(readOnly)
	s.vcsPolicy.Store(vcsPolicyToUint32(policy))
	return s
}

func (s *shareSlot) isReadOnly() bool {
	if s == nil {
		return false
	}
	return s.readOnly.Load()
}

func (s *shareSlot) setReadOnly(ro bool) {
	if s != nil {
		s.readOnly.Store(ro)
	}
}

func (s *shareSlot) getVCSPolicy() config.VCSPolicy {
	if s == nil {
		return config.VCSMask
	}
	return uint32ToVCSPolicy(s.vcsPolicy.Load())
}

func (s *shareSlot) setVCSPolicy(p config.VCSPolicy) {
	if s != nil {
		s.vcsPolicy.Store(vcsPolicyToUint32(p))
	}
}

func (s *shareSlot) isRevoked() bool {
	return s != nil && s.revoked.Load()
}

func (s *shareSlot) registerFile(sf *safeFile) syscall.Errno {
	if s == nil {
		return 0
	}
	s.filesMu.Lock()
	defer s.filesMu.Unlock()
	if s.revoked.Load() {
		return syscall.ESTALE
	}
	if sf.writable && s.readOnly.Load() {
		return syscall.EROFS
	}
	s.files[sf] = struct{}{}
	return 0
}

func (s *shareSlot) unregisterFile(sf *safeFile) {
	if s == nil {
		return
	}
	s.filesMu.Lock()
	delete(s.files, sf)
	s.filesMu.Unlock()
}

func (s *shareSlot) openWritableCount() int {
	if s == nil {
		return 0
	}
	s.filesMu.Lock()
	defer s.filesMu.Unlock()
	n := 0
	for sf := range s.files {
		if sf.writable && !sf.isRevoked() {
			n++
		}
	}
	return n
}

func (s *shareSlot) revokeWritableFiles(errno syscall.Errno) {
	if s == nil {
		return
	}
	s.filesMu.Lock()
	var targets []*safeFile
	for sf := range s.files {
		if sf.writable {
			targets = append(targets, sf)
			delete(s.files, sf)
		}
	}
	s.filesMu.Unlock()
	for _, sf := range targets {
		sf.revoke(errno)
	}
}

func (s *shareSlot) revokeAll(errno syscall.Errno) {
	if s == nil {
		return
	}
	s.revoked.Store(true)
	s.filesMu.Lock()
	targets := make([]*safeFile, 0, len(s.files))
	for sf := range s.files {
		targets = append(targets, sf)
	}
	s.files = make(map[*safeFile]struct{})
	s.filesMu.Unlock()

	for _, sf := range targets {
		sf.revoke(errno)
	}
	if s.root != nil {
		s.root.Revoke(errno)
	}
}

func (s *shareSlot) maskMode(mode uint32, hookProtected bool) uint32 {
	if (mode & syscall.S_IFMT) == syscall.S_IFLNK {
		return mode
	}
	if s.isReadOnly() || hookProtected {
		return mode &^ 0o222
	}
	return mode
}

func splitmix64(x uint64) uint64 {
	x += 0x9e3779b97f4a7c15
	x = (x ^ (x >> 30)) * 0xbf58476d1ce4e5b9
	x = (x ^ (x >> 27)) * 0x94d049bb133111eb
	return x ^ (x >> 31)
}

func computeStableIno(slotID, rootDev, dev, ino uint64) uint64 {
	swapped := (dev << 32) | (dev >> 32)
	swappedRoot := (rootDev << 32) | (rootDev >> 32)
	mixed := (swapped ^ swappedRoot) ^ ino
	if slotID > 0 {
		mixed ^= splitmix64(slotID)
		if mixed <= 1 {
			mixed += 2
		}
	}
	return mixed
}

func isWriteOpenFlags(flags uint32) bool {
	return flags&uint32(syscall.O_WRONLY|syscall.O_RDWR|syscall.O_APPEND|syscall.O_TRUNC|os.O_CREATE) != 0
}

// FilteredNode wraps fs.LoopbackNode to enforce VCS policy, read-only status,
// and host boundary rules on every directory and file operation.
type FilteredNode struct {
	*fs.LoopbackNode
	root   *pinnedRoot
	slot   *shareSlot
	hidden map[string]struct{}
	idMap  guestIDMap
	isRoot bool
}

func (n *FilteredNode) activeIDMap() guestIDMap {
	if n.slot != nil {
		return n.slot.idMap
	}
	return n.idMap
}

func (n *FilteredNode) OnForget() {
	if n.isRoot && n.root != nil && (n.slot == nil || n.slot.slotID == 0) {
		n.root.Close()
	}
}

func (n *FilteredNode) vcsPolicy() config.VCSPolicy {
	if n.slot != nil {
		return n.slot.getVCSPolicy()
	}
	return config.VCSMask
}

func (n *FilteredNode) isReadOnly() bool {
	return n.slot != nil && n.slot.isReadOnly()
}

func (n *FilteredNode) isHidden(name string) bool {
	if n.vcsPolicy() != config.VCSMask {
		return false
	}
	return isHiddenEntry(name, n.hidden)
}

func (n *FilteredNode) isHookProtectedRel(rel string) bool {
	return n.vcsPolicy() == config.VCSAllow && isProtectedVCSHookRelPath(rel)
}

func (n *FilteredNode) checkMutationOnSelf() (string, syscall.Errno) {
	if n.slot != nil && n.slot.isRevoked() {
		return "", syscall.ESTALE
	}
	if n.isReadOnly() {
		return "", syscall.EROFS
	}
	rel, errno := n.validatedRelPath()
	if errno != 0 {
		return "", errno
	}
	if n.isHookProtectedRel(rel) {
		return "", syscall.EPERM
	}
	return rel, 0
}

func (n *FilteredNode) checkWritableChild(name string, disallowTopVCSAdmin bool) (string, syscall.Errno) {
	if isInvalidComponent(name) {
		return "", syscall.EINVAL
	}
	if n.slot != nil && n.slot.isRevoked() {
		return "", syscall.ESTALE
	}
	if n.isReadOnly() {
		return "", syscall.EROFS
	}
	if n.isHidden(name) {
		return "", syscall.EPERM
	}
	parentRel, errno := n.validatedRelPath()
	if errno != 0 {
		return "", errno
	}
	childRel := joinRelPath(parentRel, name)
	if n.vcsPolicy() == config.VCSAllow {
		if isProtectedVCSHookRelPath(childRel) {
			return "", syscall.EPERM
		}
		if disallowTopVCSAdmin && isTopLevelVCSAdminDir(name) {
			return "", syscall.EPERM
		}
	}
	return parentRel, 0
}

func (n *FilteredNode) relPath() string {
	var rootInode *fs.Inode
	if n.slot != nil {
		n.slot.inodeMu.RLock()
		rootInode = n.slot.inode
		n.slot.inodeMu.RUnlock()
	}
	if rootInode == nil {
		if n.RootData != nil && n.RootData.RootNode != nil {
			rootInode = n.RootData.RootNode.EmbeddedInode()
		} else {
			rootInode = n.Root()
		}
	}
	return n.Path(rootInode)
}

func (n *FilteredNode) validatedRelPath() (string, syscall.Errno) {
	if n.slot != nil && n.slot.isRevoked() {
		return "", syscall.ESTALE
	}
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
	if strings.HasPrefix(rel, ".deleted") || strings.HasPrefix(rel, ".go-fuse.") {
		return "", syscall.ENOENT
	}
	hideVCS := n.vcsPolicy() == config.VCSMask
	for _, part := range strings.Split(rel, "/") {
		if part == "" {
			continue
		}
		if part == "." || part == ".." {
			return "", syscall.EPERM
		}
		if strings.HasPrefix(part, ".go-fuse.") {
			return "", syscall.ENOENT
		}
		if hideVCS && isHiddenEntry(part, n.hidden) {
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

func (n *FilteredNode) openNodeOPath() (int, string, syscall.Errno) {
	rel, errno := n.validatedRelPath()
	if errno != 0 {
		return -1, "", errno
	}
	fd, err := n.root.openat2(rel, unix.O_PATH|unix.O_NOFOLLOW, 0)
	if err != nil {
		return -1, "", fs.ToErrno(err)
	}
	return fd, rel, 0
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
	var slotID uint64
	if n.slot != nil {
		slotID = n.slot.slotID
	}
	return fs.StableAttr{
		Mode: uint32(st.Mode),
		Gen:  gen,
		Ino:  computeStableIno(slotID, n.root.dev, uint64(st.Dev), st.Ino),
	}
}

func (n *FilteredNode) applyAttrMask(attr *fuse.Attr, rel string) {
	if n.slot != nil {
		attr.Mode = n.slot.maskMode(attr.Mode, n.isHookProtectedRel(rel))
	}
	n.activeIDMap().applyAttr(attr)
}

func (n *FilteredNode) newChildInode(ctx context.Context, name string, st *syscall.Stat_t, btime *syscall.Timespec) *fs.Inode {
	child := &FilteredNode{
		LoopbackNode: &fs.LoopbackNode{RootData: n.RootData},
		root:         n.root,
		slot:         n.slot,
		hidden:       n.hidden,
		idMap:        n.activeIDMap(),
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
	return validateSetAttrInWithIDMap(in, euid, egid, guestIDMap{})
}

func validateSetAttrInWithIDMap(in *fuse.SetAttrIn, euid, egid int, idMap guestIDMap) syscall.Errno {
	if m, ok := in.GetMode(); ok {
		if m&uint32(syscall.S_ISUID|syscall.S_ISGID) != 0 {
			return syscall.EPERM
		}
	}
	if uid, ok := in.GetUID(); ok {
		uidMatchesHost := euid >= 0 && uid == uint32(euid)
		uidMatchesGuest := idMap.enabled && uid == idMap.uid
		if !uidMatchesHost && !uidMatchesGuest {
			return syscall.EPERM
		}
	}
	if gid, ok := in.GetGID(); ok {
		gidMatchesHost := egid >= 0 && gid == uint32(egid)
		gidMatchesGuest := idMap.enabled && gid == idMap.gid
		if !gidMatchesHost && !gidMatchesGuest {
			return syscall.EPERM
		}
	}
	return 0
}

// safeFile wraps an open host regular file descriptor while hiding raw fd
// passthrough and ioctl. It guards every syscall with an RWMutex so removing
// or downgrading a share can immediately close the underlying host descriptor
// without racing in-flight operations.
type safeFile struct {
	mu         sync.RWMutex
	osFile     *os.File
	raw        *fs.LoopbackFile
	slot       *shareSlot
	idMap      guestIDMap
	writable   bool
	revokedErr syscall.Errno
	euid       int
	egid       int
}

func (f *safeFile) activeIDMap() guestIDMap {
	if f.slot != nil {
		return f.slot.idMap
	}
	return f.idMap
}

func newRegisteredSafeFile(fd int, slot *shareSlot, writable bool, euid, egid int) (*safeFile, syscall.Errno) {
	osf := os.NewFile(uintptr(fd), "")
	var idMap guestIDMap
	if slot != nil {
		idMap = slot.idMap
	}
	sf := &safeFile{
		osFile:   osf,
		raw:      fs.NewLoopbackFileFromOS(osf),
		slot:     slot,
		idMap:    idMap,
		writable: writable,
		euid:     euid,
		egid:     egid,
	}
	if errno := slot.registerFile(sf); errno != 0 {
		_ = osf.Close()
		sf.osFile = nil
		sf.raw = nil
		sf.revokedErr = errno
		return nil, errno
	}
	return sf, 0
}

func (f *safeFile) isRevoked() bool {
	f.mu.RLock()
	rev := f.osFile == nil || f.revokedErr != 0
	f.mu.RUnlock()
	return rev
}

func (f *safeFile) revoke(errno syscall.Errno) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if errno == 0 {
		errno = syscall.ESTALE
	}
	if f.revokedErr == 0 {
		f.revokedErr = errno
	}
	if f.osFile != nil {
		_ = f.osFile.Close()
		f.osFile = nil
		f.raw = nil
	}
}

func (f *safeFile) withFDRead(fn func(fd int) syscall.Errno) syscall.Errno {
	f.mu.RLock()
	defer f.mu.RUnlock()
	if f.revokedErr != 0 {
		return f.revokedErr
	}
	if f.osFile == nil {
		return syscall.EBADF
	}
	sc, err := f.osFile.SyscallConn()
	if err != nil {
		return syscall.EBADF
	}
	errno := syscall.EBADF
	_ = sc.Control(func(fd uintptr) {
		errno = fn(int(fd))
	})
	return errno
}

func (f *safeFile) Read(ctx context.Context, dest []byte, off int64) (fuse.ReadResult, syscall.Errno) {
	_ = ctx
	var n int
	errno := f.withFDRead(func(fd int) syscall.Errno {
		var err error
		n, err = syscall.Pread(fd, dest, off)
		return fs.ToErrno(err)
	})
	if errno != 0 {
		return nil, errno
	}
	return fuse.ReadResultData(dest[:n]), 0
}

func (f *safeFile) Write(ctx context.Context, data []byte, off int64) (uint32, syscall.Errno) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	if f.revokedErr != 0 {
		return 0, f.revokedErr
	}
	if f.slot != nil && f.slot.isReadOnly() {
		return 0, syscall.EROFS
	}
	if f.raw == nil {
		return 0, syscall.EBADF
	}
	return f.raw.Write(ctx, data, off)
}

func (f *safeFile) Release(ctx context.Context) syscall.Errno {
	if f.slot != nil {
		f.slot.unregisterFile(f)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.raw == nil {
		return 0
	}
	raw := f.raw
	f.raw = nil
	f.osFile = nil
	return raw.Release(ctx)
}

func (f *safeFile) Flush(ctx context.Context) syscall.Errno {
	f.mu.RLock()
	defer f.mu.RUnlock()
	if f.revokedErr != 0 {
		return 0
	}
	if f.raw == nil {
		return 0
	}
	return f.raw.Flush(ctx)
}

func (f *safeFile) Fsync(ctx context.Context, flags uint32) syscall.Errno {
	f.mu.RLock()
	defer f.mu.RUnlock()
	if f.revokedErr != 0 {
		return f.revokedErr
	}
	if f.raw == nil {
		return syscall.EBADF
	}
	return f.raw.Fsync(ctx, flags)
}

func (f *safeFile) Getlk(ctx context.Context, owner uint64, lk *fuse.FileLock, flags uint32, out *fuse.FileLock) syscall.Errno {
	f.mu.RLock()
	defer f.mu.RUnlock()
	if f.revokedErr != 0 {
		return f.revokedErr
	}
	if f.raw == nil {
		return syscall.EBADF
	}
	return f.raw.Getlk(ctx, owner, lk, flags, out)
}

func (f *safeFile) Setlk(ctx context.Context, owner uint64, lk *fuse.FileLock, flags uint32) syscall.Errno {
	f.mu.RLock()
	defer f.mu.RUnlock()
	if f.revokedErr != 0 {
		return f.revokedErr
	}
	if f.raw == nil {
		return syscall.EBADF
	}
	return f.raw.Setlk(ctx, owner, lk, flags)
}

func (f *safeFile) Setlkw(ctx context.Context, owner uint64, lk *fuse.FileLock, flags uint32) syscall.Errno {
	f.mu.RLock()
	defer f.mu.RUnlock()
	if f.revokedErr != 0 {
		return f.revokedErr
	}
	if f.raw == nil {
		return syscall.EBADF
	}
	return f.raw.Setlkw(ctx, owner, lk, flags)
}

func (f *safeFile) Getattr(ctx context.Context, out *fuse.AttrOut) syscall.Errno {
	f.mu.RLock()
	defer f.mu.RUnlock()
	if f.revokedErr != 0 {
		return f.revokedErr
	}
	if f.raw == nil {
		return syscall.EBADF
	}
	errno := f.raw.Getattr(ctx, out)
	if errno == 0 {
		if f.slot != nil && f.slot.isReadOnly() {
			out.Mode = f.slot.maskMode(out.Mode, false)
		}
		f.activeIDMap().applyAttr(&out.Attr)
	}
	return errno
}

func (f *safeFile) Lseek(ctx context.Context, off uint64, whence uint32) (uint64, syscall.Errno) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	if f.revokedErr != 0 {
		return 0, f.revokedErr
	}
	if f.raw == nil {
		return 0, syscall.EBADF
	}
	return f.raw.Lseek(ctx, off, whence)
}

func (f *safeFile) Allocate(ctx context.Context, off uint64, sz uint64, mode uint32) syscall.Errno {
	f.mu.RLock()
	defer f.mu.RUnlock()
	if f.revokedErr != 0 {
		return f.revokedErr
	}
	if f.slot != nil && f.slot.isReadOnly() {
		return syscall.EROFS
	}
	if f.raw == nil {
		return syscall.EBADF
	}
	return f.raw.Allocate(ctx, off, sz, mode)
}

func (f *safeFile) Setattr(ctx context.Context, in *fuse.SetAttrIn, out *fuse.AttrOut) syscall.Errno {
	f.mu.RLock()
	defer f.mu.RUnlock()
	if f.revokedErr != 0 {
		return f.revokedErr
	}
	if f.slot != nil && f.slot.isReadOnly() {
		return syscall.EROFS
	}
	if f.raw == nil {
		return syscall.EBADF
	}
	if errno := validateSetAttrInWithIDMap(in, f.euid, f.egid, f.activeIDMap()); errno != 0 {
		return errno
	}
	cleanIn := *in
	cleanIn.Valid &^= fuse.FATTR_UID | fuse.FATTR_GID
	errno := f.raw.Setattr(ctx, &cleanIn, out)
	if errno == 0 {
		f.activeIDMap().applyAttr(&out.Attr)
	}
	return errno
}

func (n *FilteredNode) Statfs(ctx context.Context, out *fuse.StatfsOut) syscall.Errno {
	_ = ctx
	fd, _, errno := n.openNodeOPath()
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
	parentRel, errno := n.validatedRelPath()
	if errno != 0 {
		return nil, errno
	}
	dirFD, err := n.root.openat2(parentRel, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fs.ToErrno(err)
	}
	defer unix.Close(dirFD)

	var st syscall.Stat_t
	var btime syscall.Timespec
	if err := statAtNoFollow(dirFD, name, &st, &btime); err != nil {
		return nil, fs.ToErrno(err)
	}
	out.Attr.FromStat(&st)
	n.applyAttrMask(&out.Attr, joinRelPath(parentRel, name))
	return n.newChildInode(ctx, name, &st, &btime), 0
}

func (n *FilteredNode) Open(ctx context.Context, flags uint32) (fs.FileHandle, uint32, syscall.Errno) {
	_ = ctx
	rel, errno := n.validatedRelPath()
	if errno != 0 {
		return nil, 0, errno
	}
	writable := isWriteOpenFlags(flags)
	if writable {
		if n.isReadOnly() {
			return nil, 0, syscall.EROFS
		}
		if n.isHookProtectedRel(rel) {
			return nil, 0, syscall.EPERM
		}
	}
	openFlags := int(flags&^(syscall.O_APPEND|fuse.FMODE_EXEC)) | unix.O_NOFOLLOW
	if n.isReadOnly() {
		openFlags = (openFlags &^ (syscall.O_WRONLY | syscall.O_RDWR | syscall.O_APPEND | syscall.O_TRUNC | os.O_CREATE)) | syscall.O_RDONLY
	}
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
	sf, regErrno := newRegisteredSafeFile(fd, n.slot, writable, n.root.euid, n.root.egid)
	if regErrno != 0 {
		return nil, 0, regErrno
	}
	return sf, 0, 0
}

func (n *FilteredNode) Create(ctx context.Context, name string, flags uint32, mode uint32, out *fuse.EntryOut) (*fs.Inode, fs.FileHandle, uint32, syscall.Errno) {
	parentRel, errno := n.checkWritableChild(name, false)
	if errno != 0 {
		return nil, nil, 0, errno
	}
	dirFD, err := n.root.openat2(parentRel, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, nil, 0, fs.ToErrno(err)
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
	sf, regErrno := newRegisteredSafeFile(fd, n.slot, true, n.root.euid, n.root.egid)
	if regErrno != 0 {
		return nil, nil, 0, regErrno
	}
	out.FromStat(&st)
	n.applyAttrMask(&out.Attr, joinRelPath(parentRel, name))
	ch := n.newChildInode(ctx, name, &st, &btime)
	return ch, sf, 0, 0
}

func (n *FilteredNode) Tmpfile(ctx context.Context, flags uint32, mode uint32, out *fuse.EntryOut) (*fs.Inode, fs.FileHandle, uint32, syscall.Errno) {
	rel, errno := n.checkMutationOnSelf()
	if errno != 0 {
		return nil, nil, 0, errno
	}
	dirFD, err := n.root.openat2(rel, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, nil, 0, fs.ToErrno(err)
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
	sf, regErrno := newRegisteredSafeFile(fd, n.slot, true, n.root.euid, n.root.egid)
	if regErrno != 0 {
		return nil, nil, 0, regErrno
	}
	out.FromStat(&st)
	n.applyAttrMask(&out.Attr, rel)
	ch := n.newChildInode(ctx, "", &st, &btime)
	return ch, sf, 0, 0
}

func (n *FilteredNode) Mkdir(ctx context.Context, name string, mode uint32, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	parentRel, errno := n.checkWritableChild(name, false)
	if errno != 0 {
		return nil, errno
	}
	dirFD, err := n.root.openat2(parentRel, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fs.ToErrno(err)
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
	n.applyAttrMask(&out.Attr, joinRelPath(parentRel, name))
	return n.newChildInode(ctx, name, &st, &btime), 0
}

func (n *FilteredNode) Mknod(ctx context.Context, name string, mode uint32, _ uint32, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	parentRel, errno := n.checkWritableChild(name, false)
	if errno != 0 {
		return nil, errno
	}
	if (mode & syscall.S_IFMT) != syscall.S_IFREG {
		return nil, syscall.EPERM
	}
	dirFD, err := n.root.openat2(parentRel, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fs.ToErrno(err)
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
	n.applyAttrMask(&out.Attr, joinRelPath(parentRel, name))
	return n.newChildInode(ctx, name, &st, &btime), 0
}

func (n *FilteredNode) Symlink(ctx context.Context, target, name string, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	parentRel, errno := n.checkWritableChild(name, false)
	if errno != 0 {
		return nil, errno
	}
	if errno := ValidateSymlinkTargetForPolicy(parentRel, name, target, n.hidden, n.vcsPolicy()); errno != 0 {
		return nil, errno
	}
	dirFD, err := n.root.openat2(parentRel, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fs.ToErrno(err)
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
	n.activeIDMap().applyAttr(&out.Attr)
	return n.newChildInode(ctx, name, &st, &btime), 0
}

func (n *FilteredNode) Link(ctx context.Context, target fs.InodeEmbedder, name string, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	parentRel, errno := n.checkWritableChild(name, false)
	if errno != 0 {
		return nil, errno
	}
	src, ok := target.(*FilteredNode)
	if !ok || src.root == nil || src.root != n.root || src.slot != n.slot {
		return nil, syscall.EXDEV
	}
	if _, srcMutErr := src.checkMutationOnSelf(); srcMutErr != 0 {
		return nil, srcMutErr
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

	dstDirFD, err := n.root.openat2(parentRel, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fs.ToErrno(err)
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
	n.applyAttrMask(&out.Attr, joinRelPath(parentRel, name))
	return n.newChildInode(ctx, name, &st, &btime), 0
}

func (n *FilteredNode) Readlink(ctx context.Context) ([]byte, syscall.Errno) {
	_ = ctx
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
			if vErr := ValidateSymlinkTargetForPolicy(parentRel, baseName, target, n.hidden, n.vcsPolicy()); vErr != 0 {
				return nil, syscall.EPERM
			}
			return buf[:sz], 0
		}
	}
}

func (n *FilteredNode) Rmdir(ctx context.Context, name string) syscall.Errno {
	_ = ctx
	parentRel, errno := n.checkWritableChild(name, true)
	if errno != 0 {
		return errno
	}
	dirFD, err := n.root.openat2(parentRel, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return fs.ToErrno(err)
	}
	defer unix.Close(dirFD)
	return fs.ToErrno(unix.Unlinkat(dirFD, name, unix.AT_REMOVEDIR))
}

func (n *FilteredNode) Unlink(ctx context.Context, name string) syscall.Errno {
	_ = ctx
	parentRel, errno := n.checkWritableChild(name, true)
	if errno != 0 {
		return errno
	}
	dirFD, err := n.root.openat2(parentRel, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return fs.ToErrno(err)
	}
	defer unix.Close(dirFD)
	return fs.ToErrno(unix.Unlinkat(dirFD, name, 0))
}

func (n *FilteredNode) Rename(ctx context.Context, name string, newParent fs.InodeEmbedder, newName string, flags uint32) syscall.Errno {
	_ = ctx
	if _, errno := n.checkWritableChild(name, true); errno != 0 {
		return errno
	}
	dst, ok := newParent.(*FilteredNode)
	if !ok || dst.root == nil || dst.root != n.root || dst.slot != n.slot {
		return syscall.EXDEV
	}
	if _, errno := dst.checkWritableChild(newName, true); errno != 0 {
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
	fd, rel, errno := n.openNodeOPath()
	if errno != 0 {
		return errno
	}
	defer unix.Close(fd)
	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil {
		return fs.ToErrno(err)
	}
	out.FromStat(&st)
	n.applyAttrMask(&out.Attr, rel)
	return 0
}

func (n *FilteredNode) Statx(ctx context.Context, f fs.FileHandle, flags uint32, mask uint32, out *fuse.StatxOut) syscall.Errno {
	if f != nil {
		if fga, ok := f.(fs.FileStatxer); ok {
			errno := fga.Statx(ctx, flags, mask, out)
			if errno == 0 {
				if n.slot != nil {
					out.Statx.Mode = uint16(n.slot.maskMode(uint32(out.Statx.Mode), n.isHookProtectedRel(n.relPath())))
				}
				n.activeIDMap().applyStatx(out)
			}
			return errno
		}
	}
	fd, rel, errno := n.openNodeOPath()
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
	if n.slot != nil {
		out.Statx.Mode = uint16(n.slot.maskMode(uint32(out.Statx.Mode), n.isHookProtectedRel(rel)))
	}
	n.activeIDMap().applyStatx(out)
	return 0
}

func (n *FilteredNode) Setattr(ctx context.Context, f fs.FileHandle, in *fuse.SetAttrIn, out *fuse.AttrOut) syscall.Errno {
	if n.root == nil {
		return syscall.EIO
	}
	rel, mutErr := n.checkMutationOnSelf()
	if mutErr != 0 {
		return mutErr
	}
	if errno := validateSetAttrInWithIDMap(in, n.root.euid, n.root.egid, n.activeIDMap()); errno != 0 {
		return errno
	}
	if f != nil {
		if fsa, ok := f.(fs.FileSetattrer); ok {
			return fsa.Setattr(ctx, in, out)
		}
	}

	fd, _, errno := n.openNodeOPath()
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
		n.activeIDMap().applyAttr(&out.Attr)
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
	n.applyAttrMask(&out.Attr, rel)
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
	_ = ctx
	if IsProtectedXattr(attr) {
		return 0, unix.ENODATA
	}
	fd, _, errno := n.openNodeOPath()
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
	_ = ctx
	fd, _, errno := n.openNodeOPath()
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
	_ = ctx
	if _, mutErr := n.checkMutationOnSelf(); mutErr != 0 {
		return mutErr
	}
	if IsProtectedXattr(attr) {
		return syscall.EPERM
	}
	fd, _, errno := n.openNodeOPath()
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
	_ = ctx
	if _, mutErr := n.checkMutationOnSelf(); mutErr != 0 {
		return mutErr
	}
	if IsProtectedXattr(attr) {
		return syscall.EPERM
	}
	fd, _, errno := n.openNodeOPath()
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
	if dstNode, ok := out.Operations().(*FilteredNode); ok {
		if _, mutErr := dstNode.checkMutationOnSelf(); mutErr != 0 {
			return 0, mutErr
		}
	}
	sfIn.mu.RLock()
	defer sfIn.mu.RUnlock()
	if sfIn.revokedErr != 0 {
		return 0, sfIn.revokedErr
	}
	if sfIn.raw == nil {
		return 0, syscall.EBADF
	}
	if sfOut != sfIn {
		sfOut.mu.RLock()
		defer sfOut.mu.RUnlock()
	}
	if sfOut.revokedErr != 0 {
		return 0, sfOut.revokedErr
	}
	if sfOut.slot != nil && sfOut.slot.isReadOnly() {
		return 0, syscall.EROFS
	}
	if sfOut.raw == nil {
		return 0, syscall.EBADF
	}
	return n.LoopbackNode.CopyFileRange(ctx, sfIn.raw, offIn, out, sfOut.raw, offOut, length, flags)
}

func (n *FilteredNode) activeHiddenMap() map[string]struct{} {
	if n.vcsPolicy() != config.VCSMask {
		return nil
	}
	return n.hidden
}

func (n *FilteredNode) Readdir(ctx context.Context) (fs.DirStream, syscall.Errno) {
	_ = ctx
	dirFD, errno := n.openDirFD()
	if errno != 0 {
		return nil, errno
	}
	ds, errno := fs.NewLoopbackDirStreamFd(dirFD)
	if errno != 0 {
		_ = unix.Close(dirFD)
		return nil, errno
	}
	return &filteredStream{inner: ds, hidden: n.activeHiddenMap()}, 0
}

// OpendirHandle intercepts directory opens on all nodes in the filtered tree.
// It opens the directory with openat2 and forwards Releasedir, Seekdir, and
// Fsyncdir while omitting raw ioctl forwarding.
func (n *FilteredNode) OpendirHandle(ctx context.Context, _ uint32) (fs.FileHandle, uint32, syscall.Errno) {
	_ = ctx
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
		return &filteredDir{inner: rd, raw: ds, hidden: n.activeHiddenMap()}, 0, 0
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
		if d.hidden != nil && isHiddenEntry(de.Name, d.hidden) {
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
		if f.hidden != nil && isHiddenEntry(de.Name, f.hidden) {
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

func buildRootFilteredNode(resolvedSrc string, pr *pinnedRoot, st syscall.Stat_t, slot *shareSlot) *FilteredNode {
	var idMap guestIDMap
	if slot != nil {
		idMap = slot.idMap
	}
	rootData := &fs.LoopbackRoot{
		Path: resolvedSrc,
		Dev:  uint64(st.Dev),
	}
	rootData.NewNode = func(rd *fs.LoopbackRoot, _ *fs.Inode, _ string, _ *syscall.Stat_t) fs.InodeEmbedder {
		return &FilteredNode{
			LoopbackNode: &fs.LoopbackNode{RootData: rd},
			root:         pr,
			slot:         slot,
			hidden:       slot.hidden,
			idMap:        idMap,
		}
	}
	root := &FilteredNode{
		LoopbackNode: &fs.LoopbackNode{RootData: rootData},
		root:         pr,
		slot:         slot,
		hidden:       slot.hidden,
		idMap:        idMap,
		isRoot:       true,
	}
	rootData.RootNode = root
	return root
}

// Mount mounts a VCS-filtered loopback view of srcDir onto mntDir and returns
// the running FUSE server. Call server.Unmount() and server.Wait() to stop it.
func Mount(srcDir, mntDir string, hiddenEntries []string) (*fuse.Server, error) {
	return MountWithIDMap(srcDir, mntDir, hiddenEntries, false, 0, 0)
}

// MountWithIDMap mounts a VCS-filtered loopback view of srcDir onto mntDir
// while optionally presenting mapped guest UID and GID ownership values.
func MountWithIDMap(srcDir, mntDir string, hiddenEntries []string, mapGuestIDs bool, guestUID, guestGID uint32) (*fuse.Server, error) {
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
	slot := newShareSlotWithIDMap(0, "", resolvedSrc, false, "", pr, hidden, false, config.VCSMask, newGuestIDMap(mapGuestIDs, guestUID, guestGID))
	root := buildRootFilteredNode(resolvedSrc, pr, st, slot)

	sec := time.Second
	opts := &fs.Options{
		AttrTimeout:  &sec,
		EntryTimeout: &sec,
		MountOptions: fuse.MountOptions{
			FsName:      resolvedSrc,
			Name:        "agboxfilter",
			Options:     []string{"nosuid", "nodev"},
			DirectMount: os.Geteuid() == 0,
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
	return RunDaemonWithIDMap(srcDir, mntDir, hiddenEntries, false, 0, 0)
}

// RunDaemonWithIDMap mounts srcDir onto mntDir with optional guest UID/GID
// presentation mapping and blocks until unmount or termination signal.
func RunDaemonWithIDMap(srcDir, mntDir string, hiddenEntries []string, mapGuestIDs bool, guestUID, guestGID uint32) error {
	server, err := MountWithIDMap(srcDir, mntDir, hiddenEntries, mapGuestIDs, guestUID, guestGID)
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
// either the single-share FUSE daemon or the multiplexed Workspace Hub daemon.
func RunMain(args []string) int {
	fsFlags := flag.NewFlagSet(SubcommandName, flag.ContinueOnError)
	hubMode := fsFlags.Bool("hub", false, "Run multiplexed Workspace Hub daemon")
	src := fsFlags.String("src", "", "Source directory to expose")
	mnt := fsFlags.String("mnt", "", "Mountpoint directory")
	sock := fsFlags.String("sock", "", "Control socket path for Workspace Hub")
	specFD := fsFlags.Int("spec-fd", -1, "Open file descriptor containing initial Hub JSON spec")
	specFile := fsFlags.String("spec", "", "Path to JSON file containing initial Hub spec")
	mapGuestIDs := fsFlags.Bool("map-guest-ids", false, "Present mapped guest UID/GID ownership")
	guestUID := fsFlags.Uint("guest-uid", 1000, "Mapped guest UID when -map-guest-ids is set")
	guestGID := fsFlags.Uint("guest-gid", 1000, "Mapped guest GID when -map-guest-ids is set")
	if err := fsFlags.Parse(args); err != nil {
		fmt.Fprintf(os.Stderr, "agbox %s: %v\n", SubcommandName, err)
		return 2
	}
	if *hubMode {
		if *mnt == "" || *sock == "" {
			fmt.Fprintf(os.Stderr, "Usage: agbox %s -hub -mnt <dir> -sock <sock> [-spec-fd <fd>|-spec <file>]\n", SubcommandName)
			return 2
		}
		if err := runHubDaemonFromFlags(*mnt, *sock, *specFD, *specFile); err != nil {
			fmt.Fprintf(os.Stderr, "agbox %s: %v\n", SubcommandName, err)
			return 1
		}
		return 0
	}
	if *src == "" || *mnt == "" {
		fmt.Fprintf(os.Stderr, "Usage: agbox %s -src <dir> -mnt <dir>\n", SubcommandName)
		return 2
	}
	if err := RunDaemonWithIDMap(*src, *mnt, DefaultHiddenEntries, *mapGuestIDs, uint32(*guestUID), uint32(*guestGID)); err != nil {
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

	cmd := exec.Command(exePath, SubcommandName, "-src", srcDir, "-mnt", mntDir, "-map-guest-ids", "-guest-uid", "1000", "-guest-gid", "1000")
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
