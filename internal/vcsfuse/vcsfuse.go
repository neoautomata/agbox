// Package vcsfuse implements a loopback FUSE filesystem and a
// Workspace Hub for host shares.
//
// Security properties:
//   - The filesystem masks VCS entries case-insensitively when VCSPolicy is
//     VCSMask. Lookup returns ENOENT, directory streams omit entries, and writes
//     return EPERM.
//   - The filesystem write-protects VCS hooks and executable VCS config files
//     with EPERM when VCSPolicy is VCSAllow.
//   - The filesystem enforces read-only mode on designated shares. Mutating
//     operations return EROFS, and attributes omit write permission bits.
//   - The filesystem pins each share root directory descriptor. It resolves
//     paths with Linux openat2 to block symlink traversal outside the share.
//   - The filesystem rejects unattached or deleted child inodes with ENOENT.
//     Child inodes never fall back to the share root.
//   - The filesystem checks symlink targets on Symlink, Readlink, and Rename.
//     It allows only relative intra-share paths permitted by the VCS policy.
//   - The filesystem mounts with nosuid and nodev flags. It opens entries with
//     O_PATH first to block FIFOs and device nodes with EPERM before open.
//   - The filesystem strips setuid and setgid bits on creation. Setattr blocks
//     privilege escalation, non-regular targets, and cross-UID ownership changes.
//   - The filesystem wraps handles in safeFile and filteredDir. Handles block
//     ioctl calls and revoke host descriptors during share deletion or downgrade.
//   - The filesystem allows only user extended attributes. It blocks security,
//     system, and trusted attributes with EPERM.
package vcsfuse

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
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

const (
	// SubcommandName is the internal argv[1] token for background FUSE daemons.
	SubcommandName = "__filter"

	maxSymlinkTargetBytes = 64 * 1024
	maxRenameWalkDepth    = 128
	maxRenameWalkEntries  = 100000
	daemonStartupTimeout  = 3 * time.Second
)

var nextSafeFileID atomic.Uint64

// defaultHiddenEntries returns all VCS directories and control files masked in
// directory shares that use VCSMask.
func defaultHiddenEntries() []string {
	return pathsec.DefaultVCSNames()
}

// isProtectedXattr reports whether the filter blocks setting or removing attr.
// The filter allows only user.<name> extended attributes.
func isProtectedXattr(attr string) bool {
	if !strings.HasPrefix(attr, "user.") {
		return true
	}
	return len(attr) <= len("user.")
}

// buildHiddenSet converts entry names into a lowercase lookup map.
func buildHiddenSet(entries []string) map[string]struct{} {
	if len(entries) == 0 {
		entries = defaultHiddenEntries()
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

// isTopLevelVCSAdminDir reports whether name is a VCS metadata directory or
// pointer file name protected against creation, deletion, or rename under VCSAllow.
func isTopLevelVCSAdminDir(name string) bool {
	switch strings.ToLower(name) {
	case ".git", ".jj", ".hg", ".svn", "_darcs", ".pijul", ".fossil-settings", "_fossil_", ".bzr", ".sl":
		return true
	default:
		return false
	}
}

// isProtectedVCSHookRelPath reports whether relPath targets a VCS hook or
// executable VCS config file protected under VCSAllow.
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

	inGit := false
	gitRootIdx := -1
	inGitSafeData := false
	inJJ := false
	inJJSafeData := false
	inSvnOrPijul := false
	inDarcs := false
	inHg := false
	inSl := false
	inBzr := false

	for i, seg := range segs {
		if (inGit || inJJ || inSvnOrPijul) && seg == "hooks" {
			return true
		}
		if inGit && !inGitSafeData && (seg == "config" || seg == "config.worktree" || seg == "commondir" || seg == "gitdir") {
			return true
		}
		if inJJ && !inJJSafeData && (seg == "config.toml" || (!inGit && seg == "config")) {
			return true
		}
		if inDarcs && seg == "prefs" {
			return true
		}
		if inHg && i > 0 && segs[i-1] == ".hg" && strings.HasPrefix(seg, "hgrc") {
			return true
		}
		if inSl && (seg == "config" || strings.HasPrefix(seg, "hgrc")) {
			return true
		}
		if inBzr && (seg == "branch.conf" || seg == "locations.conf") {
			return true
		}

		if inGit && gitRootIdx >= 0 && i > gitRootIdx+1 && segs[i-1] == "refs" {
			refsIdx := i - 1
			isDirectRefs := refsIdx == gitRootIdx+1 || (refsIdx == gitRootIdx+2 && segs[gitRootIdx+1] == "logs")
			if isDirectRefs && (seg == "heads" || seg == "tags" || seg == "remotes" || seg == "notes" || seg == "replace" || seg == "bisect") {
				inGitSafeData = true
			}
		}
		if inJJ && (seg == "op_heads" || seg == "op_store" || seg == "working_copy") {
			inJJSafeData = true
		}
		if inJJ && !inJJSafeData && !inGit && seg == "git" {
			inGit = true
			gitRootIdx = i
			inGitSafeData = false
		}

		switch seg {
		case ".git":
			if !inGit {
				inGit = true
				gitRootIdx = i
			}
			inGitSafeData = false
		case ".jj":
			inJJ = true
			inJJSafeData = false
			inGit = false
			gitRootIdx = -1
			inGitSafeData = false
		case ".svn", ".pijul":
			inSvnOrPijul = true
		case "_darcs":
			inDarcs = true
		case ".hg":
			inHg = true
		case ".sl":
			inSl = true
		case ".bzr":
			inBzr = true
		}
	}
	return false
}

// isVCSAdminPath reports whether relPath is at or inside a VCS directory or control file.
func isVCSAdminPath(relPath string, hidden map[string]struct{}) bool {
	if relPath == "" || relPath == "." {
		return false
	}
	if len(hidden) == 0 {
		hidden = buildHiddenSet(nil)
	}
	for _, part := range strings.Split(relPath, "/") {
		if part == "" || part == "." {
			continue
		}
		if isHiddenEntry(part, hidden) {
			return true
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

// validateSymlinkTargetForPolicy checks a symlink target within a share under policy.
// It rejects empty targets, absolute paths, escaping '..' segments, and policy-blocked paths.
func validateSymlinkTargetForPolicy(parentRelPath, linkName, target string, hidden map[string]struct{}, policy config.VCSPolicy) syscall.Errno {
	if isInvalidComponent(linkName) {
		return syscall.EINVAL
	}
	if policy == "" {
		policy = config.VCSMask
	}
	if policy == config.VCSMask && isHiddenEntry(linkName, hidden) {
		return syscall.EPERM
	}
	if policy == config.VCSAllow && isTopLevelVCSAdminDir(linkName) {
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

// pinnedRoot holds an open directory descriptor for a share root or parent directory.
// Path lookups run relative to this descriptor with RESOLVE_BENEATH and RESOLVE_NO_SYMLINKS.
type pinnedRoot struct {
	mu         sync.RWMutex
	fd         int
	revokedErr syscall.Errno
	dev        uint64
	euid       int
	egid       int
}

func newPinnedRoot(srcDir string) (*pinnedRoot, syscall.Stat_t, error) {
	return newPinnedRootWithIDs(srcDir, os.Geteuid, os.Getegid)
}

func newPinnedRootWithIDs(srcDir string, geteuid, getegid func() int) (*pinnedRoot, syscall.Stat_t, error) {
	if geteuid == nil {
		geteuid = os.Geteuid
	}
	if getegid == nil {
		getegid = os.Getegid
	}
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
		euid:       geteuid(),
		egid:       getegid(),
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

func (p *pinnedRoot) statRoot(st *syscall.Stat_t, btime *syscall.Timespec) error {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.fd < 0 {
		return p.revokedErr
	}
	return statAtNoFollow(p.fd, "", st, btime)
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

// isVCSPolicyMoreRestrictive reports whether next restricts VCS access more than prev.
func isVCSPolicyMoreRestrictive(prev, next config.VCSPolicy) bool {
	return vcsPolicyRank(next) < vcsPolicyRank(prev)
}

func vcsPolicyRank(p config.VCSPolicy) int {
	switch p {
	case config.VCSAllowHooks:
		return 2
	case config.VCSAllow:
		return 1
	default:
		return 0
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

// shareSlot holds dynamic permission state, open handles, and the pinned
// host directory descriptor for one mounted share.
type shareSlot struct {
	slotID    uint64
	guestName string
	hostPath  string
	isFile    bool
	fileName  string
	root      *pinnedRoot
	initDev   uint64
	initIno   uint64
	hidden    map[string]struct{}
	idMap     guestIDMap

	readOnly  atomic.Bool
	vcsPolicy atomic.Uint32
	revoked   atomic.Bool

	renameMu sync.RWMutex

	filesMu sync.Mutex
	files   map[*safeFile]struct{}
	dirs    map[*filteredDir]struct{}

	inodeMu sync.RWMutex
	inode   *fs.Inode
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
		dirs:      make(map[*filteredDir]struct{}),
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

func (s *shareSlot) rlockRename() {
	if s != nil {
		s.renameMu.RLock()
	}
}

func (s *shareSlot) runlockRename() {
	if s != nil {
		s.renameMu.RUnlock()
	}
}

func (s *shareSlot) lockRename() {
	if s != nil {
		s.renameMu.Lock()
	}
}

func (s *shareSlot) unlockRename() {
	if s != nil {
		s.renameMu.Unlock()
	}
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
	pol := s.getVCSPolicy()
	if sf.isVCS.Load() && pol == config.VCSMask {
		return syscall.ESTALE
	}
	if sf.writable && sf.isHook.Load() && pol == config.VCSAllow {
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

// registerDir records an open directory handle in the slot after checking policy.
func (s *shareSlot) registerDir(d *filteredDir) syscall.Errno {
	if s == nil {
		return 0
	}
	s.filesMu.Lock()
	defer s.filesMu.Unlock()
	if s.revoked.Load() {
		return syscall.ESTALE
	}
	if d.isVCS.Load() && s.getVCSPolicy() == config.VCSMask {
		return syscall.ESTALE
	}
	if s.dirs == nil {
		s.dirs = make(map[*filteredDir]struct{})
	}
	s.dirs[d] = struct{}{}
	return 0
}

// unregisterDir deletes an open directory handle from the slot.
func (s *shareSlot) unregisterDir(d *filteredDir) {
	if s == nil {
		return
	}
	s.filesMu.Lock()
	delete(s.dirs, d)
	s.filesMu.Unlock()
}

type movedHandleTarget struct {
	dev    uint64
	ino    uint64
	dstRel string
}

const (
	movedFlagVCS uint8 = 1 << iota
	movedFlagHook
)

type fileRevocation struct {
	file  *safeFile
	errno syscall.Errno
}

type dirRevocation struct {
	dir   *filteredDir
	errno syscall.Errno
}

type rootRevocation struct {
	root  *pinnedRoot
	errno syscall.Errno
}

// revocationBatch holds handles detached under slot locks so callers close
// host descriptors after releasing hub and slot locks.
type revocationBatch struct {
	files []fileRevocation
	dirs  []dirRevocation
	roots []rootRevocation
}

func (b *revocationBatch) merge(other revocationBatch) {
	b.files = append(b.files, other.files...)
	b.dirs = append(b.dirs, other.dirs...)
	b.roots = append(b.roots, other.roots...)
}

func (b *revocationBatch) apply() {
	for _, item := range b.files {
		item.file.revoke(item.errno)
	}
	for _, item := range b.dirs {
		item.dir.revoke(item.errno)
	}
	for _, item := range b.roots {
		item.root.Revoke(item.errno)
	}
}

// detachPromotedOpenHandles updates VCS and hook flags on open handles matching
// targets and returns handles that require revocation under the active policy.
func (s *shareSlot) detachPromotedOpenHandles(targets []movedHandleTarget) revocationBatch {
	if s == nil || len(targets) == 0 {
		return revocationBatch{}
	}
	var flagsByID map[[2]uint64]uint8
	for _, t := range targets {
		if t.ino == 0 {
			continue
		}
		var mask uint8
		if isVCSAdminPath(t.dstRel, s.hidden) {
			mask |= movedFlagVCS
		}
		if isProtectedVCSHookRelPath(t.dstRel) {
			mask |= movedFlagHook
		}
		if mask == 0 {
			continue
		}
		if flagsByID == nil {
			flagsByID = make(map[[2]uint64]uint8, len(targets))
		}
		flagsByID[[2]uint64{t.dev, t.ino}] |= mask
	}
	if len(flagsByID) == 0 {
		return revocationBatch{}
	}

	var batch revocationBatch
	s.filesMu.Lock()
	pol := s.getVCSPolicy()
	for sf := range s.files {
		mask := flagsByID[[2]uint64{sf.dev, sf.ino}]
		if mask == 0 {
			continue
		}
		dstVCS := mask&movedFlagVCS != 0
		dstHook := mask&movedFlagHook != 0
		if dstVCS {
			sf.isVCS.Store(true)
		}
		if dstHook {
			sf.isHook.Store(true)
		}
		if dstVCS && pol == config.VCSMask {
			batch.files = append(batch.files, fileRevocation{file: sf, errno: syscall.ESTALE})
			delete(s.files, sf)
		} else if sf.writable && dstHook && pol == config.VCSAllow {
			batch.files = append(batch.files, fileRevocation{file: sf, errno: syscall.EROFS})
			delete(s.files, sf)
		}
	}
	for d := range s.dirs {
		mask := flagsByID[[2]uint64{d.dev, d.ino}]
		if mask&movedFlagVCS == 0 {
			continue
		}
		d.isVCS.Store(true)
		if pol == config.VCSMask {
			batch.dirs = append(batch.dirs, dirRevocation{dir: d, errno: syscall.ESTALE})
			delete(s.dirs, d)
		}
	}
	s.filesMu.Unlock()
	return batch
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

// openWritableVCSCount returns the number of active writable VCS file descriptors.
func (s *shareSlot) openWritableVCSCount() int {
	if s == nil {
		return 0
	}
	s.filesMu.Lock()
	defer s.filesMu.Unlock()
	n := 0
	for sf := range s.files {
		if sf.writable && sf.isVCS.Load() && !sf.isRevoked() {
			n++
		}
	}
	return n
}

// openWritableHookCount returns the number of active writable VCS hook or config descriptors.
func (s *shareSlot) openWritableHookCount() int {
	if s == nil {
		return 0
	}
	s.filesMu.Lock()
	defer s.filesMu.Unlock()
	n := 0
	for sf := range s.files {
		if sf.writable && sf.isHook.Load() && !sf.isRevoked() {
			n++
		}
	}
	return n
}

func (s *shareSlot) detachWritableFiles(errno syscall.Errno) revocationBatch {
	if s == nil {
		return revocationBatch{}
	}
	s.filesMu.Lock()
	var batch revocationBatch
	for sf := range s.files {
		if sf.writable {
			batch.files = append(batch.files, fileRevocation{file: sf, errno: errno})
			delete(s.files, sf)
		}
	}
	s.filesMu.Unlock()
	return batch
}

// detachVCSDescriptors removes all open file and directory handles on VCS paths
// from the slot and returns them for revocation outside slot locks.
func (s *shareSlot) detachVCSDescriptors(errno syscall.Errno) revocationBatch {
	if s == nil {
		return revocationBatch{}
	}
	s.filesMu.Lock()
	var batch revocationBatch
	for sf := range s.files {
		if sf.isVCS.Load() {
			batch.files = append(batch.files, fileRevocation{file: sf, errno: errno})
			delete(s.files, sf)
		}
	}
	for d := range s.dirs {
		if d.isVCS.Load() {
			batch.dirs = append(batch.dirs, dirRevocation{dir: d, errno: errno})
			delete(s.dirs, d)
		}
	}
	s.filesMu.Unlock()
	return batch
}

// detachWritableHookFiles removes all open writable handles on protected VCS paths
// from the slot and returns them for revocation outside slot locks.
func (s *shareSlot) detachWritableHookFiles(errno syscall.Errno) revocationBatch {
	if s == nil {
		return revocationBatch{}
	}
	s.filesMu.Lock()
	var batch revocationBatch
	for sf := range s.files {
		if sf.writable && sf.isHook.Load() {
			batch.files = append(batch.files, fileRevocation{file: sf, errno: errno})
			delete(s.files, sf)
		}
	}
	s.filesMu.Unlock()
	return batch
}

func (s *shareSlot) detachAll(errno syscall.Errno) revocationBatch {
	if s == nil {
		return revocationBatch{}
	}
	s.revoked.Store(true)
	s.filesMu.Lock()
	batch := revocationBatch{
		files: make([]fileRevocation, 0, len(s.files)),
		dirs:  make([]dirRevocation, 0, len(s.dirs)),
	}
	for sf := range s.files {
		batch.files = append(batch.files, fileRevocation{file: sf, errno: errno})
	}
	s.files = make(map[*safeFile]struct{})

	for d := range s.dirs {
		batch.dirs = append(batch.dirs, dirRevocation{dir: d, errno: errno})
	}
	s.dirs = make(map[*filteredDir]struct{})
	s.filesMu.Unlock()

	if s.root != nil {
		batch.roots = append(batch.roots, rootRevocation{root: s.root, errno: errno})
	}
	return batch
}

func (s *shareSlot) revokeAll(errno syscall.Errno) {
	batch := s.detachAll(errno)
	batch.apply()
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
	}
	if mixed <= 1 {
		mixed += 2
	}
	return mixed
}

func isWriteOpenFlags(flags uint32) bool {
	return flags&uint32(syscall.O_WRONLY|syscall.O_RDWR|syscall.O_APPEND|syscall.O_TRUNC|os.O_CREATE) != 0
}

func sanitizeOpenFlags(flags uint32, readOnly bool) int {
	stripped := uint32(syscall.O_APPEND | fuse.FMODE_EXEC | os.O_CREATE | syscall.O_EXCL | syscall.O_NOCTTY)
	openFlags := int(flags &^ stripped)
	if readOnly {
		openFlags = (openFlags &^ (syscall.O_WRONLY | syscall.O_RDWR | syscall.O_APPEND | syscall.O_TRUNC | os.O_CREATE)) | syscall.O_RDONLY
	}
	return openFlags
}

// openRegularViaOPath opens rel with O_PATH|O_NOFOLLOW, verifies S_IFREG, and
// reopens the pinned inode via /proc/self/fd/<fd> so FIFOs and devices never open.
func openRegularViaOPath(root *pinnedRoot, rel string, flags uint32, readOnly bool, requireSingleLink bool) (int, syscall.Stat_t, syscall.Errno) {
	if root == nil {
		return -1, syscall.Stat_t{}, syscall.EIO
	}
	pathFD, err := root.openat2(rel, unix.O_PATH|unix.O_NOFOLLOW, 0)
	if err != nil {
		return -1, syscall.Stat_t{}, fs.ToErrno(err)
	}
	var st syscall.Stat_t
	if err := syscall.Fstat(pathFD, &st); err != nil {
		_ = unix.Close(pathFD)
		return -1, syscall.Stat_t{}, fs.ToErrno(err)
	}
	fileType := st.Mode & syscall.S_IFMT
	if fileType == syscall.S_IFDIR {
		_ = unix.Close(pathFD)
		return -1, syscall.Stat_t{}, syscall.EISDIR
	}
	if fileType != syscall.S_IFREG {
		_ = unix.Close(pathFD)
		return -1, syscall.Stat_t{}, syscall.EPERM
	}
	if flags&uint32(syscall.O_DIRECTORY) != 0 {
		_ = unix.Close(pathFD)
		return -1, syscall.Stat_t{}, syscall.ENOTDIR
	}
	if requireSingleLink && st.Nlink != 1 {
		_ = unix.Close(pathFD)
		return -1, syscall.Stat_t{}, syscall.EPERM
	}

	openFlags := sanitizeOpenFlags(flags, readOnly) | unix.O_CLOEXEC
	procPath := fmt.Sprintf("/proc/self/fd/%d", pathFD)
	fd, err := unix.Open(procPath, openFlags, 0)
	_ = unix.Close(pathFD)
	if err != nil {
		return -1, syscall.Stat_t{}, fs.ToErrno(err)
	}

	var st2 syscall.Stat_t
	if err := syscall.Fstat(fd, &st2); err != nil {
		_ = unix.Close(fd)
		return -1, syscall.Stat_t{}, fs.ToErrno(err)
	}
	if (st2.Mode&syscall.S_IFMT) != syscall.S_IFREG || st2.Dev != st.Dev || st2.Ino != st.Ino {
		_ = unix.Close(fd)
		return -1, syscall.Stat_t{}, syscall.EPERM
	}
	return fd, st2, 0
}

// applyProcFDSetattr applies chmod, truncate, and utimensat via /proc/self/fd/<fd>.
func applyProcFDSetattr(fd int, in *fuse.SetAttrIn, isDir bool) syscall.Errno {
	if isDir {
		if _, ok := in.GetSize(); ok {
			return syscall.EISDIR
		}
	}
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
	return 0
}

// listFilteredXattrs lists extended attributes on /proc/self/fd/<fd> and keeps only user.<name>.
func listFilteredXattrs(fd int, dest []byte) (uint32, syscall.Errno) {
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
		if !isProtectedXattr(string(entry)) {
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

func readlinkAtBounded(dirFD int, name string) ([]byte, syscall.Errno) {
	for size := 256; size <= maxSymlinkTargetBytes; size *= 2 {
		buf := make([]byte, size)
		sz, err := unix.Readlinkat(dirFD, name, buf)
		if err != nil {
			return nil, fs.ToErrno(err)
		}
		if sz < len(buf) {
			return buf[:sz], 0
		}
	}
	return nil, syscall.ENAMETOOLONG
}

// filteredNode wraps fs.LoopbackNode to enforce VCS policy, read-only status,
// and host confinement rules on every directory and file operation.
type filteredNode struct {
	*fs.LoopbackNode
	root   *pinnedRoot
	slot   *shareSlot
	hidden map[string]struct{}
	idMap  guestIDMap
	isRoot bool
}

func (n *filteredNode) activeIDMap() guestIDMap {
	if n.slot != nil {
		return n.slot.idMap
	}
	return n.idMap
}

func (n *filteredNode) OnForget() {
	if n.isRoot && n.root != nil && (n.slot == nil || n.slot.slotID == 0) {
		n.root.Close()
	}
}

func (n *filteredNode) vcsPolicy() config.VCSPolicy {
	if n.slot != nil {
		return n.slot.getVCSPolicy()
	}
	return config.VCSMask
}

func (n *filteredNode) isReadOnly() bool {
	return n.slot != nil && n.slot.isReadOnly()
}

func (n *filteredNode) isHidden(name string) bool {
	if n.vcsPolicy() != config.VCSMask {
		return false
	}
	return isHiddenEntry(name, n.hidden)
}

func (n *filteredNode) isHookProtectedRel(rel string) bool {
	return n.vcsPolicy() == config.VCSAllow && isProtectedVCSHookRelPath(rel)
}

func (n *filteredNode) isRevoked() bool {
	return n.slot != nil && n.slot.isRevoked()
}

func (n *filteredNode) checkMutationOnSelf() (string, syscall.Errno) {
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

func (n *filteredNode) checkWritableChild(name string, disallowTopVCSAdmin bool) (string, syscall.Errno) {
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

func (n *filteredNode) relPath() string {
	var rootInode *fs.Inode
	if n.slot != nil {
		n.slot.inodeMu.RLock()
		rootInode = n.slot.inode
		n.slot.inodeMu.RUnlock()
	}
	if rootInode == nil || rootInode.Root() != n.Root() {
		if n.RootData != nil && n.RootData.RootNode != nil {
			rootInode = n.RootData.RootNode.EmbeddedInode()
		} else {
			rootInode = n.Root()
		}
	}
	return n.Path(rootInode)
}

func (n *filteredNode) validatedRelPath() (string, syscall.Errno) {
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
	if strings.HasPrefix(rel, ".go-fuse.") {
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

func (n *filteredNode) openDirFD() (int, syscall.Errno) {
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

func (n *filteredNode) openNodeOPath() (int, string, syscall.Errno) {
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

func (n *filteredNode) openParentAndName() (int, string, string, syscall.Errno) {
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

func (n *filteredNode) stableAttr(st *syscall.Stat_t, btime *syscall.Timespec) fs.StableAttr {
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

func (n *filteredNode) applyAttrMask(attr *fuse.Attr, rel string) {
	if n.slot != nil {
		attr.Mode = n.slot.maskMode(attr.Mode, n.isHookProtectedRel(rel))
	}
	n.activeIDMap().applyAttr(attr)
}

func (n *filteredNode) newChildInode(ctx context.Context, st *syscall.Stat_t, btime *syscall.Timespec) *fs.Inode {
	child := &filteredNode{
		LoopbackNode: &fs.LoopbackNode{RootData: n.RootData},
		root:         n.root,
		slot:         n.slot,
		hidden:       n.hidden,
		idMap:        n.activeIDMap(),
	}
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
			*btime = syscall.Timespec{Sec: int64(sx.Btime.Sec), Nsec: int64(sx.Btime.Nsec)}
		}
		return nil
	}
	if !errors.Is(err, unix.ENOSYS) && !errors.Is(err, unix.EINVAL) {
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
	st.Atim = syscall.Timespec{Sec: int64(sx.Atime.Sec), Nsec: int64(sx.Atime.Nsec)}
	st.Mtim = syscall.Timespec{Sec: int64(sx.Mtime.Sec), Nsec: int64(sx.Mtime.Nsec)}
	st.Ctim = syscall.Timespec{Sec: int64(sx.Ctime.Sec), Nsec: int64(sx.Ctime.Nsec)}
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

// safeFile wraps an open host regular file descriptor and blocks raw fd
// passthrough and ioctl. An RWMutex guards syscalls so revoke closes the
// host descriptor without racing active operations.
type safeFile struct {
	id         uint64
	mu         sync.RWMutex
	osFile     *os.File
	raw        *fs.LoopbackFile
	slot       *shareSlot
	dev        uint64
	ino        uint64
	active     atomic.Bool
	isVCS      atomic.Bool
	isHook     atomic.Bool
	idMap      guestIDMap
	writable   bool
	revokedErr syscall.Errno
	done       chan struct{}
	doneClosed bool
	euid       int
	egid       int
}

var _ fs.FileStatxer = (*safeFile)(nil)

func (f *safeFile) activeIDMap() guestIDMap {
	if f.slot != nil {
		return f.slot.idMap
	}
	return f.idMap
}

func newRegisteredSafeFile(fd int, st *syscall.Stat_t, slot *shareSlot, relPath string, writable bool, euid, egid int) (*safeFile, syscall.Errno) {
	osf := os.NewFile(uintptr(fd), "")
	var idMap guestIDMap
	var hidden map[string]struct{}
	if slot != nil {
		idMap = slot.idMap
		hidden = slot.hidden
	}
	var dev, ino uint64
	if st != nil {
		dev = uint64(st.Dev)
		ino = st.Ino
	}
	sf := &safeFile{
		id:       nextSafeFileID.Add(1),
		osFile:   osf,
		raw:      fs.NewLoopbackFileFromOS(osf),
		slot:     slot,
		dev:      dev,
		ino:      ino,
		idMap:    idMap,
		writable: writable,
		done:     make(chan struct{}),
		euid:     euid,
		egid:     egid,
	}
	sf.active.Store(osf != nil)
	sf.isVCS.Store(isVCSAdminPath(relPath, hidden))
	sf.isHook.Store(isProtectedVCSHookRelPath(relPath))
	if errno := slot.registerFile(sf); errno != 0 {
		sf.active.Store(false)
		sf.closeDoneLocked()
		_ = osf.Close()
		sf.osFile = nil
		sf.raw = nil
		sf.revokedErr = errno
		return nil, errno
	}
	return sf, 0
}

func (f *safeFile) closeDoneLocked() {
	if f.done != nil && !f.doneClosed {
		close(f.done)
		f.doneClosed = true
	}
}

func (f *safeFile) isRevoked() bool {
	return !f.active.Load()
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
	f.active.Store(false)
	f.closeDoneLocked()
	if f.osFile != nil {
		_ = f.osFile.Close()
		f.osFile = nil
		f.raw = nil
	}
}

// checkAccessLocked checks revocation and live slot policies under f.mu.
func (f *safeFile) checkAccessLocked(writeOp bool) syscall.Errno {
	if f.revokedErr != 0 {
		return f.revokedErr
	}
	if f.slot != nil {
		if f.slot.isRevoked() {
			return syscall.ESTALE
		}
		pol := f.slot.getVCSPolicy()
		if f.isVCS.Load() && pol == config.VCSMask {
			return syscall.ESTALE
		}
		if writeOp {
			if f.slot.isReadOnly() {
				return syscall.EROFS
			}
			if f.isHook.Load() && pol == config.VCSAllow {
				return syscall.EROFS
			}
		}
	}
	if f.osFile == nil || f.raw == nil {
		return syscall.EBADF
	}
	return 0
}

func (f *safeFile) withFDRead(fn func(fd int) syscall.Errno) syscall.Errno {
	f.mu.RLock()
	defer f.mu.RUnlock()
	if errno := f.checkAccessLocked(false); errno != 0 {
		return errno
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
	if errno := f.checkAccessLocked(true); errno != 0 {
		return 0, errno
	}
	return f.raw.Write(ctx, data, off)
}

func (f *safeFile) Release(ctx context.Context) syscall.Errno {
	if f.slot != nil {
		f.slot.unregisterFile(f)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.active.Store(false)
	f.closeDoneLocked()
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
	if f.revokedErr != 0 || f.raw == nil {
		return 0
	}
	return f.raw.Flush(ctx)
}

func (f *safeFile) Fsync(ctx context.Context, flags uint32) syscall.Errno {
	f.mu.RLock()
	defer f.mu.RUnlock()
	if errno := f.checkAccessLocked(false); errno != 0 {
		return errno
	}
	return f.raw.Fsync(ctx, flags)
}

func (f *safeFile) Getlk(ctx context.Context, owner uint64, lk *fuse.FileLock, flags uint32, out *fuse.FileLock) syscall.Errno {
	f.mu.RLock()
	defer f.mu.RUnlock()
	if errno := f.checkAccessLocked(false); errno != 0 {
		return errno
	}
	return f.raw.Getlk(ctx, owner, lk, flags, out)
}

func (f *safeFile) Setlk(ctx context.Context, owner uint64, lk *fuse.FileLock, flags uint32) syscall.Errno {
	f.mu.RLock()
	defer f.mu.RUnlock()
	if errno := f.checkAccessLocked(false); errno != 0 {
		return errno
	}
	return f.raw.Setlk(ctx, owner, lk, flags)
}

// Setlkw retries non-blocking Setlk calls so f.mu.RLock never blocks revoke or Release.
func (f *safeFile) Setlkw(ctx context.Context, owner uint64, lk *fuse.FileLock, flags uint32) syscall.Errno {
	backoff := 2 * time.Millisecond
	const maxBackoff = 50 * time.Millisecond
	for {
		f.mu.RLock()
		errno := f.checkAccessLocked(false)
		if errno == 0 {
			errno = f.raw.Setlk(ctx, owner, lk, flags)
		}
		doneCh := f.done
		f.mu.RUnlock()

		if errno != syscall.EAGAIN && errno != syscall.EWOULDBLOCK && errno != syscall.EACCES {
			return errno
		}

		timer := time.NewTimer(backoff)
		select {
		case <-ctx.Done():
			timer.Stop()
			return syscall.EINTR
		case <-doneCh:
			timer.Stop()
			f.mu.RLock()
			revErr := f.checkAccessLocked(false)
			f.mu.RUnlock()
			if revErr != 0 {
				return revErr
			}
			return syscall.EBADF
		case <-timer.C:
		}
		if backoff < maxBackoff {
			backoff *= 2
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
		}
	}
}

func (f *safeFile) Getattr(ctx context.Context, out *fuse.AttrOut) syscall.Errno {
	f.mu.RLock()
	defer f.mu.RUnlock()
	if errno := f.checkAccessLocked(false); errno != 0 {
		return errno
	}
	errno := f.raw.Getattr(ctx, out)
	if errno == 0 {
		if f.slot != nil {
			hookProt := f.isHook.Load() && f.slot.getVCSPolicy() == config.VCSAllow
			out.Mode = f.slot.maskMode(out.Mode, hookProt)
		}
		f.activeIDMap().applyAttr(&out.Attr)
	}
	return errno
}

func (f *safeFile) Statx(ctx context.Context, flags uint32, mask uint32, out *fuse.StatxOut) syscall.Errno {
	_ = ctx
	var sx unix.Statx_t
	statxFlags := int(flags) | unix.AT_EMPTY_PATH | unix.AT_SYMLINK_NOFOLLOW
	errno := f.withFDRead(func(fd int) syscall.Errno {
		return fs.ToErrno(unix.Statx(fd, "", statxFlags, int(mask), &sx))
	})
	if errno != 0 {
		return errno
	}
	out.FromStatx(&sx)
	if f.slot != nil {
		hookProt := f.isHook.Load() && f.slot.getVCSPolicy() == config.VCSAllow
		out.Statx.Mode = uint16(f.slot.maskMode(uint32(out.Statx.Mode), hookProt))
	}
	f.activeIDMap().applyStatx(out)
	return 0
}

func (f *safeFile) Lseek(ctx context.Context, off uint64, whence uint32) (uint64, syscall.Errno) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	if errno := f.checkAccessLocked(false); errno != 0 {
		return 0, errno
	}
	return f.raw.Lseek(ctx, off, whence)
}

func (f *safeFile) Allocate(ctx context.Context, off uint64, sz uint64, mode uint32) syscall.Errno {
	if !f.writable {
		return syscall.EBADF
	}
	f.mu.RLock()
	defer f.mu.RUnlock()
	if errno := f.checkAccessLocked(true); errno != 0 {
		return errno
	}
	return f.raw.Allocate(ctx, off, sz, mode)
}

func (f *safeFile) Setattr(ctx context.Context, in *fuse.SetAttrIn, out *fuse.AttrOut) syscall.Errno {
	f.mu.RLock()
	defer f.mu.RUnlock()
	if errno := f.checkAccessLocked(true); errno != 0 {
		return errno
	}
	if errno := validateSetAttrInWithIDMap(in, f.euid, f.egid, f.activeIDMap()); errno != 0 {
		return errno
	}
	if f.slot != nil && f.slot.isFile {
		sc, err := f.osFile.SyscallConn()
		if err != nil {
			return syscall.EBADF
		}
		var st syscall.Stat_t
		var statErr syscall.Errno
		if cErr := sc.Control(func(fd uintptr) {
			statErr = fs.ToErrno(syscall.Fstat(int(fd), &st))
		}); cErr != nil {
			return syscall.EBADF
		}
		if statErr != 0 {
			return statErr
		}
		if (st.Mode&syscall.S_IFMT) != syscall.S_IFREG || st.Nlink != 1 {
			return syscall.EPERM
		}
	}
	cleanIn := *in
	cleanIn.Valid &^= fuse.FATTR_UID | fuse.FATTR_GID
	errno := f.raw.Setattr(ctx, &cleanIn, out)
	if errno == 0 {
		if f.slot != nil {
			hookProt := f.isHook.Load() && f.slot.getVCSPolicy() == config.VCSAllow
			out.Mode = f.slot.maskMode(out.Mode, hookProt)
		}
		f.activeIDMap().applyAttr(&out.Attr)
	}
	return errno
}

func (n *filteredNode) Statfs(ctx context.Context, out *fuse.StatfsOut) syscall.Errno {
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

func (n *filteredNode) Lookup(ctx context.Context, name string, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
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
	return n.newChildInode(ctx, &st, &btime), 0
}

func (n *filteredNode) Open(ctx context.Context, flags uint32) (fs.FileHandle, uint32, syscall.Errno) {
	_ = ctx
	n.slot.rlockRename()
	defer n.slot.runlockRename()

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
	fd, st, openErr := openRegularViaOPath(n.root, rel, flags, n.isReadOnly(), false)
	if openErr != 0 {
		return nil, 0, openErr
	}
	sf, regErrno := newRegisteredSafeFile(fd, &st, n.slot, rel, writable, n.root.euid, n.root.egid)
	if regErrno != 0 {
		return nil, 0, regErrno
	}
	return sf, 0, 0
}

func (n *filteredNode) Create(ctx context.Context, name string, flags uint32, mode uint32, out *fuse.EntryOut) (*fs.Inode, fs.FileHandle, uint32, syscall.Errno) {
	n.slot.rlockRename()
	defer n.slot.runlockRename()

	parentRel, errno := n.checkWritableChild(name, true)
	if errno != 0 {
		return nil, nil, 0, errno
	}
	dirFD, err := n.root.openat2(parentRel, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, nil, 0, fs.ToErrno(err)
	}
	defer unix.Close(dirFD)

	cleanMode := sanitizeCreateMode(mode)
	baseFlags := sanitizeOpenFlags(flags, false)
	writable := baseFlags&(syscall.O_WRONLY|syscall.O_RDWR) != 0

	fd := -1
	var st syscall.Stat_t
	var btime syscall.Timespec
	createdNew := false

	for attempt := 0; attempt < 2; attempt++ {
		exclFlags := baseFlags | os.O_CREATE | syscall.O_EXCL | unix.O_NOFOLLOW
		newFD, cErr := openat2FromDir(dirFD, name, exclFlags, cleanMode)
		if cErr == nil {
			fd = newFD
			createdNew = true
			if sErr := statAtNoFollow(fd, "", &st, &btime); sErr != nil {
				_ = unix.Close(fd)
				_ = unix.Unlinkat(dirFD, name, 0)
				return nil, nil, 0, fs.ToErrno(sErr)
			}
			break
		}
		if !errors.Is(cErr, syscall.EEXIST) || flags&uint32(syscall.O_EXCL) != 0 {
			return nil, nil, 0, fs.ToErrno(cErr)
		}

		// Target exists and caller omitted O_EXCL. Inspect via O_PATH|O_NOFOLLOW first
		// so pre-existing FIFOs and device nodes never open or block.
		pathFD, pErr := openat2FromDir(dirFD, name, unix.O_PATH|unix.O_NOFOLLOW, 0)
		if pErr != nil {
			if errors.Is(pErr, syscall.ENOENT) && attempt == 0 {
				continue
			}
			return nil, nil, 0, fs.ToErrno(pErr)
		}
		var existSt syscall.Stat_t
		if sErr := statAtNoFollow(pathFD, "", &existSt, &btime); sErr != nil {
			_ = unix.Close(pathFD)
			return nil, nil, 0, fs.ToErrno(sErr)
		}
		fileType := existSt.Mode & syscall.S_IFMT
		if fileType == syscall.S_IFDIR {
			_ = unix.Close(pathFD)
			return nil, nil, 0, syscall.EISDIR
		}
		if fileType != syscall.S_IFREG {
			_ = unix.Close(pathFD)
			return nil, nil, 0, syscall.EPERM
		}
		reopenFD, rErr := unix.Open(fmt.Sprintf("/proc/self/fd/%d", pathFD), baseFlags|unix.O_CLOEXEC, 0)
		_ = unix.Close(pathFD)
		if rErr != nil {
			return nil, nil, 0, fs.ToErrno(rErr)
		}
		if sErr := statAtNoFollow(reopenFD, "", &st, &btime); sErr != nil {
			_ = unix.Close(reopenFD)
			return nil, nil, 0, fs.ToErrno(sErr)
		}
		if (st.Mode&syscall.S_IFMT) != syscall.S_IFREG || st.Dev != existSt.Dev || st.Ino != existSt.Ino {
			_ = unix.Close(reopenFD)
			return nil, nil, 0, syscall.EPERM
		}
		fd = reopenFD
		break
	}
	if fd < 0 {
		return nil, nil, 0, syscall.EEXIST
	}

	childRel := joinRelPath(parentRel, name)
	sf, regErrno := newRegisteredSafeFile(fd, &st, n.slot, childRel, writable, n.root.euid, n.root.egid)
	if regErrno != 0 {
		if createdNew {
			_ = unix.Unlinkat(dirFD, name, 0)
		}
		return nil, nil, 0, regErrno
	}
	out.FromStat(&st)
	n.applyAttrMask(&out.Attr, childRel)
	ch := n.newChildInode(ctx, &st, &btime)
	return ch, sf, 0, 0
}

func (n *filteredNode) Tmpfile(ctx context.Context, flags uint32, mode uint32, out *fuse.EntryOut) (*fs.Inode, fs.FileHandle, uint32, syscall.Errno) {
	n.slot.rlockRename()
	defer n.slot.runlockRename()

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
	openFlags := sanitizeOpenFlags(flags, false) | unix.O_TMPFILE | unix.O_CLOEXEC
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
	sf, regErrno := newRegisteredSafeFile(fd, &st, n.slot, rel, true, n.root.euid, n.root.egid)
	if regErrno != 0 {
		return nil, nil, 0, regErrno
	}
	out.FromStat(&st)
	n.applyAttrMask(&out.Attr, rel)
	ch := n.newChildInode(ctx, &st, &btime)
	return ch, sf, 0, 0
}

func (n *filteredNode) Mkdir(ctx context.Context, name string, mode uint32, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	n.slot.rlockRename()
	defer n.slot.runlockRename()

	parentRel, errno := n.checkWritableChild(name, true)
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
	return n.newChildInode(ctx, &st, &btime), 0
}

func (n *filteredNode) Mknod(ctx context.Context, name string, mode uint32, _ uint32, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	n.slot.rlockRename()
	defer n.slot.runlockRename()

	parentRel, errno := n.checkWritableChild(name, true)
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
	return n.newChildInode(ctx, &st, &btime), 0
}

func (n *filteredNode) Symlink(ctx context.Context, target, name string, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	n.slot.rlockRename()
	defer n.slot.runlockRename()

	parentRel, errno := n.checkWritableChild(name, true)
	if errno != 0 {
		return nil, errno
	}
	if errno := validateSymlinkTargetForPolicy(parentRel, name, target, n.hidden, n.vcsPolicy()); errno != 0 {
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
	return n.newChildInode(ctx, &st, &btime), 0
}

func crossesVCSOrHookBoundary(fromRel, toRel string, hidden map[string]struct{}) bool {
	return isVCSAdminPath(fromRel, hidden) != isVCSAdminPath(toRel, hidden) ||
		isProtectedVCSHookRelPath(fromRel) != isProtectedVCSHookRelPath(toRel)
}

func (n *filteredNode) Link(ctx context.Context, target fs.InodeEmbedder, name string, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	src, ok := target.(*filteredNode)
	if !ok || src.root == nil || src.root != n.root || src.slot != n.slot {
		return nil, syscall.EXDEV
	}

	var revocations revocationBatch
	defer func() {
		revocations.apply()
	}()
	n.slot.lockRename()
	defer n.slot.unlockRename()

	parentRel, errno := n.checkWritableChild(name, true)
	if errno != 0 {
		return nil, errno
	}
	srcRel, srcMutErr := src.checkMutationOnSelf()
	if srcMutErr != 0 {
		return nil, srcMutErr
	}
	dstRel := joinRelPath(parentRel, name)
	if crossesVCSOrHookBoundary(srcRel, dstRel, n.hidden) {
		return nil, syscall.EPERM
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
	if n.slot != nil {
		revocations.merge(n.slot.detachPromotedOpenHandles([]movedHandleTarget{{
			dev:    uint64(srcSt.Dev),
			ino:    srcSt.Ino,
			dstRel: dstRel,
		}}))
	}
	var st syscall.Stat_t
	var btime syscall.Timespec
	if err := statAtNoFollow(dstDirFD, name, &st, &btime); err != nil {
		_ = unix.Unlinkat(dstDirFD, name, 0)
		return nil, fs.ToErrno(err)
	}
	out.Attr.FromStat(&st)
	n.applyAttrMask(&out.Attr, dstRel)
	return n.newChildInode(ctx, &st, &btime), 0
}

func (n *filteredNode) Readlink(ctx context.Context) ([]byte, syscall.Errno) {
	_ = ctx
	parentFD, parentRel, baseName, errno := n.openParentAndName()
	if errno != 0 {
		return nil, errno
	}
	defer unix.Close(parentFD)

	raw, rlErrno := readlinkAtBounded(parentFD, baseName)
	if rlErrno != 0 {
		return nil, rlErrno
	}
	if vErr := validateSymlinkTargetForPolicy(parentRel, baseName, string(raw), n.hidden, n.vcsPolicy()); vErr != 0 {
		return nil, syscall.EPERM
	}
	return raw, 0
}

func (n *filteredNode) Rmdir(ctx context.Context, name string) syscall.Errno {
	_ = ctx
	n.slot.rlockRename()
	defer n.slot.runlockRename()

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

func (n *filteredNode) Unlink(ctx context.Context, name string) syscall.Errno {
	_ = ctx
	n.slot.rlockRename()
	defer n.slot.runlockRename()

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

func validateMovedEntryOrSubtree(parentFD int, entryName, fromParentRel, fromName, toParentRel, toName string, st *syscall.Stat_t, hidden map[string]struct{}, policy config.VCSPolicy) ([]movedHandleTarget, syscall.Errno) {
	fromRel := joinRelPath(fromParentRel, fromName)
	toRel := joinRelPath(toParentRel, toName)
	modeType := st.Mode & syscall.S_IFMT

	if modeType == syscall.S_IFLNK {
		raw, rlErr := readlinkAtBounded(parentFD, entryName)
		if rlErr != 0 {
			return nil, syscall.EPERM
		}
		if vErr := validateSymlinkTargetForPolicy(toParentRel, toName, string(raw), hidden, policy); vErr != 0 {
			return nil, syscall.EPERM
		}
		return nil, 0
	}

	if modeType == syscall.S_IFREG && st.Nlink != 1 && crossesVCSOrHookBoundary(fromRel, toRel, hidden) {
		return nil, syscall.EPERM
	}

	targets := []movedHandleTarget{{
		dev:    uint64(st.Dev),
		ino:    st.Ino,
		dstRel: toRel,
	}}
	if modeType != syscall.S_IFDIR {
		return targets, 0
	}

	subFD, err := openat2FromDir(parentFD, entryName, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fs.ToErrno(err)
	}
	defer unix.Close(subFD)

	visited := 0
	if wErr := walkMovedDir(subFD, fromRel, toRel, 1, &visited, hidden, policy, &targets); wErr != 0 {
		return nil, wErr
	}
	return targets, 0
}

func walkMovedDir(dirFD int, curFromRel, curToRel string, depth int, visited *int, hidden map[string]struct{}, policy config.VCSPolicy, targets *[]movedHandleTarget) syscall.Errno {
	if depth > maxRenameWalkDepth {
		return syscall.EPERM
	}
	dupFD, err := unix.Dup(dirFD)
	if err != nil {
		return fs.ToErrno(err)
	}
	unix.CloseOnExec(dupFD)
	dirFile := os.NewFile(uintptr(dupFD), "")
	names, rErr := dirFile.Readdirnames(-1)
	_ = dirFile.Close()
	if rErr != nil {
		return fs.ToErrno(rErr)
	}

	for _, childName := range names {
		if childName == "" || childName == "." || childName == ".." {
			continue
		}
		*visited++
		if *visited > maxRenameWalkEntries {
			return syscall.EPERM
		}
		if policy == config.VCSMask && isHiddenEntry(childName, hidden) {
			continue
		}

		childFromRel := joinRelPath(curFromRel, childName)
		childToRel := joinRelPath(curToRel, childName)
		if policy == config.VCSAllow {
			if isTopLevelVCSAdminDir(childName) {
				return syscall.EPERM
			}
			if isProtectedVCSHookRelPath(childFromRel) || isProtectedVCSHookRelPath(childToRel) {
				return syscall.EPERM
			}
		}

		var childSt syscall.Stat_t
		var childBtime syscall.Timespec
		if err := statAtNoFollow(dirFD, childName, &childSt, &childBtime); err != nil {
			return fs.ToErrno(err)
		}
		childType := childSt.Mode & syscall.S_IFMT
		if childType == syscall.S_IFLNK {
			raw, rlErr := readlinkAtBounded(dirFD, childName)
			if rlErr != 0 {
				return syscall.EPERM
			}
			if vErr := validateSymlinkTargetForPolicy(curToRel, childName, string(raw), hidden, policy); vErr != 0 {
				return syscall.EPERM
			}
			continue
		}
		if childType == syscall.S_IFREG && childSt.Nlink != 1 && crossesVCSOrHookBoundary(childFromRel, childToRel, hidden) {
			return syscall.EPERM
		}
		*targets = append(*targets, movedHandleTarget{
			dev:    uint64(childSt.Dev),
			ino:    childSt.Ino,
			dstRel: childToRel,
		})
		if childType == syscall.S_IFDIR {
			childDirFD, oErr := openat2FromDir(dirFD, childName, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
			if oErr != nil {
				return fs.ToErrno(oErr)
			}
			wErrno := walkMovedDir(childDirFD, childFromRel, childToRel, depth+1, visited, hidden, policy, targets)
			_ = unix.Close(childDirFD)
			if wErrno != 0 {
				return wErrno
			}
		}
	}
	return 0
}

func (n *filteredNode) Rename(ctx context.Context, name string, newParent fs.InodeEmbedder, newName string, flags uint32) syscall.Errno {
	_ = ctx
	if flags&unix.RENAME_WHITEOUT != 0 {
		return syscall.EPERM
	}
	allowedFlags := uint32(unix.RENAME_NOREPLACE | unix.RENAME_EXCHANGE)
	if flags&^allowedFlags != 0 {
		return syscall.EINVAL
	}
	if flags&unix.RENAME_NOREPLACE != 0 && flags&unix.RENAME_EXCHANGE != 0 {
		return syscall.EINVAL
	}

	dst, ok := newParent.(*filteredNode)
	if !ok || dst.root == nil || dst.root != n.root || dst.slot != n.slot {
		return syscall.EXDEV
	}

	var revocations revocationBatch
	defer func() {
		revocations.apply()
	}()
	n.slot.lockRename()
	defer n.slot.unlockRename()

	srcParentRel, errno := n.checkWritableChild(name, true)
	if errno != 0 {
		return errno
	}
	dstParentRel, errno := dst.checkWritableChild(newName, true)
	if errno != 0 {
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

	policy := n.vcsPolicy()
	var srcSt syscall.Stat_t
	var srcBtime syscall.Timespec
	if err := statAtNoFollow(fd1, name, &srcSt, &srcBtime); err != nil {
		return fs.ToErrno(err)
	}
	srcTargets, vErr := validateMovedEntryOrSubtree(fd1, name, srcParentRel, name, dstParentRel, newName, &srcSt, n.hidden, policy)
	if vErr != 0 {
		return vErr
	}

	var dstSt syscall.Stat_t
	var dstBtime syscall.Timespec
	hasDst := false
	if err := statAtNoFollow(fd2, newName, &dstSt, &dstBtime); err == nil {
		hasDst = true
	} else if flags&unix.RENAME_EXCHANGE != 0 || !errors.Is(err, syscall.ENOENT) {
		return fs.ToErrno(err)
	}

	var dstTargets []movedHandleTarget
	if flags&unix.RENAME_EXCHANGE != 0 {
		var exErr syscall.Errno
		dstTargets, exErr = validateMovedEntryOrSubtree(fd2, newName, dstParentRel, newName, srcParentRel, name, &dstSt, dst.hidden, policy)
		if exErr != 0 {
			return exErr
		}
	}

	if err := unix.Renameat2(fd1, name, fd2, newName, uint(flags)); err != nil {
		return fs.ToErrno(err)
	}

	if n.slot != nil {
		revocations.merge(n.slot.detachPromotedOpenHandles(srcTargets))
		if flags&unix.RENAME_EXCHANGE != 0 && hasDst {
			revocations.merge(n.slot.detachPromotedOpenHandles(dstTargets))
		}
	}
	return 0
}

func (n *filteredNode) Getattr(ctx context.Context, f fs.FileHandle, out *fuse.AttrOut) syscall.Errno {
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

func (n *filteredNode) Statx(ctx context.Context, f fs.FileHandle, flags uint32, mask uint32, out *fuse.StatxOut) syscall.Errno {
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

func (n *filteredNode) Setattr(ctx context.Context, f fs.FileHandle, in *fuse.SetAttrIn, out *fuse.AttrOut) syscall.Errno {
	if n.root == nil {
		return syscall.EIO
	}
	n.slot.rlockRename()
	defer n.slot.runlockRename()

	if f != nil {
		if fsa, ok := f.(fs.FileSetattrer); ok {
			return fsa.Setattr(ctx, in, out)
		}
	}
	rel, mutErr := n.checkMutationOnSelf()
	if mutErr != 0 {
		return mutErr
	}
	if errno := validateSetAttrInWithIDMap(in, n.root.euid, n.root.egid, n.activeIDMap()); errno != 0 {
		return errno
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
	fileType := st.Mode & syscall.S_IFMT
	if fileType != syscall.S_IFREG && fileType != syscall.S_IFDIR {
		return syscall.EPERM
	}

	if errno := applyProcFDSetattr(fd, in, fileType == syscall.S_IFDIR); errno != 0 {
		return errno
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

func (n *filteredNode) Getxattr(ctx context.Context, attr string, dest []byte) (uint32, syscall.Errno) {
	_ = ctx
	if isProtectedXattr(attr) {
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
	fileType := st.Mode & syscall.S_IFMT
	if fileType == syscall.S_IFLNK {
		return 0, unix.ENODATA
	}
	if fileType != syscall.S_IFREG && fileType != syscall.S_IFDIR {
		return 0, syscall.EPERM
	}
	sz, err := unix.Getxattr(fmt.Sprintf("/proc/self/fd/%d", fd), attr, dest)
	if err != nil {
		return 0, fs.ToErrno(err)
	}
	return uint32(sz), 0
}

func (n *filteredNode) Listxattr(ctx context.Context, dest []byte) (uint32, syscall.Errno) {
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
	fileType := st.Mode & syscall.S_IFMT
	if fileType == syscall.S_IFLNK {
		return 0, 0
	}
	if fileType != syscall.S_IFREG && fileType != syscall.S_IFDIR {
		return 0, syscall.EPERM
	}
	return listFilteredXattrs(fd, dest)
}

func (n *filteredNode) Setxattr(ctx context.Context, attr string, data []byte, flags uint32) syscall.Errno {
	_ = ctx
	n.slot.rlockRename()
	defer n.slot.runlockRename()

	if _, mutErr := n.checkMutationOnSelf(); mutErr != 0 {
		return mutErr
	}
	if isProtectedXattr(attr) {
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
	fileType := st.Mode & syscall.S_IFMT
	if fileType != syscall.S_IFREG && fileType != syscall.S_IFDIR {
		return syscall.EPERM
	}
	err := unix.Setxattr(fmt.Sprintf("/proc/self/fd/%d", fd), attr, data, int(flags))
	return fs.ToErrno(err)
}

func (n *filteredNode) Removexattr(ctx context.Context, attr string) syscall.Errno {
	_ = ctx
	n.slot.rlockRename()
	defer n.slot.runlockRename()

	if _, mutErr := n.checkMutationOnSelf(); mutErr != 0 {
		return mutErr
	}
	if isProtectedXattr(attr) {
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
	fileType := st.Mode & syscall.S_IFMT
	if fileType != syscall.S_IFREG && fileType != syscall.S_IFDIR {
		return syscall.EPERM
	}
	err := unix.Removexattr(fmt.Sprintf("/proc/self/fd/%d", fd), attr)
	return fs.ToErrno(err)
}

func (n *filteredNode) CopyFileRange(ctx context.Context, fhIn fs.FileHandle, offIn uint64, out *fs.Inode, fhOut fs.FileHandle, offOut uint64, length uint64, flags uint64) (uint32, syscall.Errno) {
	sfIn, ok := fhIn.(*safeFile)
	if !ok {
		return 0, unix.ENOTSUP
	}
	sfOut, ok := fhOut.(*safeFile)
	if !ok {
		return 0, unix.ENOTSUP
	}
	if dstNode, ok := out.Operations().(*filteredNode); ok {
		if _, mutErr := dstNode.checkMutationOnSelf(); mutErr != 0 {
			return 0, mutErr
		}
	}

	// Lock safeFile instances in ascending monotonic ID order to avoid AB-BA deadlocks.
	if sfIn == sfOut {
		sfIn.mu.RLock()
		defer sfIn.mu.RUnlock()
	} else if sfIn.id < sfOut.id {
		sfIn.mu.RLock()
		defer sfIn.mu.RUnlock()
		sfOut.mu.RLock()
		defer sfOut.mu.RUnlock()
	} else {
		sfOut.mu.RLock()
		defer sfOut.mu.RUnlock()
		sfIn.mu.RLock()
		defer sfIn.mu.RUnlock()
	}

	if errno := sfIn.checkAccessLocked(false); errno != 0 {
		return 0, errno
	}
	if errno := sfOut.checkAccessLocked(true); errno != 0 {
		return 0, errno
	}
	return n.LoopbackNode.CopyFileRange(ctx, sfIn.raw, offIn, out, sfOut.raw, offOut, length, flags)
}

func (n *filteredNode) activeHiddenMap() map[string]struct{} {
	if n.vcsPolicy() != config.VCSMask {
		return nil
	}
	return n.hidden
}

func (n *filteredNode) Readdir(ctx context.Context) (fs.DirStream, syscall.Errno) {
	fh, _, errno := n.OpendirHandle(ctx, 0)
	if errno != 0 {
		return nil, errno
	}
	return &registeredDirStream{ctx: ctx, dir: fh.(*filteredDir)}, 0
}

// OpendirHandle intercepts directory opens across the filtered tree.
// It opens directories with openat2, registers handles for revocation, and omits ioctl.
func (n *filteredNode) OpendirHandle(ctx context.Context, _ uint32) (fs.FileHandle, uint32, syscall.Errno) {
	n.slot.rlockRename()
	defer n.slot.runlockRename()

	if n.isRevoked() {
		return nil, 0, syscall.ESTALE
	}
	rel, errno := n.validatedRelPath()
	if errno != 0 {
		return nil, 0, errno
	}
	dirFD, errno := n.openDirFD()
	if errno != 0 {
		return nil, 0, errno
	}
	var dirSt syscall.Stat_t
	if err := syscall.Fstat(dirFD, &dirSt); err != nil {
		_ = unix.Close(dirFD)
		return nil, 0, fs.ToErrno(err)
	}
	ds, errno := fs.NewLoopbackDirStreamFd(dirFD)
	if errno != 0 {
		_ = unix.Close(dirFD)
		return nil, 0, errno
	}
	rd, _ := ds.(fs.FileReaddirenter)
	var hidden map[string]struct{}
	if n.slot != nil {
		hidden = n.slot.hidden
	} else {
		hidden = n.hidden
	}
	isVCS := isVCSAdminPath(rel, hidden)
	fd, regErrno := newRegisteredFilteredDir(ds, rd, n.slot, uint64(dirSt.Dev), dirSt.Ino, isVCS, n.activeHiddenMap())
	if regErrno != 0 {
		if r, ok := ds.(fs.FileReleasedirer); ok {
			r.Releasedir(ctx, 0)
		}
		return nil, 0, regErrno
	}
	return fd, 0, 0
}

type filteredDir struct {
	mu         sync.Mutex
	slot       *shareSlot
	dev        uint64
	ino        uint64
	isVCS      atomic.Bool
	inner      fs.FileReaddirenter
	raw        fs.FileHandle
	hidden     map[string]struct{}
	revokedErr syscall.Errno
}

func newRegisteredFilteredDir(raw fs.FileHandle, inner fs.FileReaddirenter, slot *shareSlot, dev, ino uint64, isVCS bool, hidden map[string]struct{}) (*filteredDir, syscall.Errno) {
	fd := &filteredDir{
		slot:   slot,
		dev:    dev,
		ino:    ino,
		inner:  inner,
		raw:    raw,
		hidden: hidden,
	}
	fd.isVCS.Store(isVCS)
	if slot != nil {
		if errno := slot.registerDir(fd); errno != 0 {
			fd.revokedErr = errno
			return nil, errno
		}
	}
	return fd, 0
}

func (d *filteredDir) revoke(errno syscall.Errno) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if errno == 0 {
		errno = syscall.ESTALE
	}
	if d.revokedErr == 0 {
		d.revokedErr = errno
	}
	raw := d.raw
	d.raw = nil
	d.inner = nil
	if r, ok := raw.(fs.FileReleasedirer); ok {
		r.Releasedir(context.Background(), 0)
	}
}

func (d *filteredDir) isEntryHidden(name string) bool {
	if d.slot != nil {
		if d.slot.getVCSPolicy() != config.VCSMask {
			return false
		}
		if d.slot.hidden != nil {
			return isHiddenEntry(name, d.slot.hidden)
		}
	}
	if d.hidden != nil {
		return isHiddenEntry(name, d.hidden)
	}
	return false
}

func (d *filteredDir) Readdirent(ctx context.Context) (*fuse.DirEntry, syscall.Errno) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.revokedErr != 0 {
		return nil, d.revokedErr
	}
	if d.slot != nil {
		if d.slot.isRevoked() || (d.isVCS.Load() && d.slot.getVCSPolicy() == config.VCSMask) {
			return nil, syscall.ESTALE
		}
	}
	if d.inner == nil && d.raw == nil {
		return nil, syscall.EBADF
	}

	for {
		var de *fuse.DirEntry
		var errno syscall.Errno
		if d.inner != nil {
			de, errno = d.inner.Readdirent(ctx)
		} else if s, ok := d.raw.(fs.DirStream); ok {
			if !s.HasNext() {
				return nil, 0
			}
			entry, sErr := s.Next()
			if sErr != 0 {
				return nil, sErr
			}
			de = &entry
		} else {
			return nil, syscall.EBADF
		}
		if errno != 0 || de == nil {
			return de, errno
		}
		if d.isEntryHidden(de.Name) {
			continue
		}
		return de, 0
	}
}

func (d *filteredDir) Releasedir(ctx context.Context, releaseFlags uint32) {
	if d.slot != nil {
		d.slot.unregisterDir(d)
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	raw := d.raw
	d.raw = nil
	d.inner = nil
	if r, ok := raw.(fs.FileReleasedirer); ok {
		r.Releasedir(ctx, releaseFlags)
	}
}

func (d *filteredDir) Seekdir(ctx context.Context, off uint64) syscall.Errno {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.revokedErr != 0 {
		return d.revokedErr
	}
	if d.slot != nil && (d.slot.isRevoked() || (d.isVCS.Load() && d.slot.getVCSPolicy() == config.VCSMask)) {
		return syscall.ESTALE
	}
	if s, ok := d.raw.(fs.FileSeekdirer); ok {
		return s.Seekdir(ctx, off)
	}
	return syscall.ENOTSUP
}

func (d *filteredDir) Fsyncdir(ctx context.Context, flags uint32) syscall.Errno {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.revokedErr != 0 {
		return d.revokedErr
	}
	if d.slot != nil && (d.slot.isRevoked() || (d.isVCS.Load() && d.slot.getVCSPolicy() == config.VCSMask)) {
		return syscall.ESTALE
	}
	if f, ok := d.raw.(fs.FileFsyncdirer); ok {
		return f.Fsyncdir(ctx, flags)
	}
	return syscall.ENOTSUP
}

type registeredDirStream struct {
	ctx    context.Context
	dir    *filteredDir
	peeked *fuse.DirEntry
	peekEr syscall.Errno
	hasPk  bool
}

func (s *registeredDirStream) advance() {
	de, errno := s.dir.Readdirent(s.ctx)
	if errno != 0 {
		s.peeked = nil
		s.peekEr = errno
		s.hasPk = true
		return
	}
	if de == nil {
		s.hasPk = false
		return
	}
	s.peeked = de
	s.peekEr = 0
	s.hasPk = true
}

func (s *registeredDirStream) HasNext() bool {
	if !s.hasPk {
		s.advance()
	}
	return s.hasPk
}

func (s *registeredDirStream) Next() (fuse.DirEntry, syscall.Errno) {
	if !s.hasPk {
		s.advance()
	}
	s.hasPk = false
	if s.peekEr != 0 || s.peeked == nil {
		return fuse.DirEntry{}, s.peekEr
	}
	return *s.peeked, 0
}

func (s *registeredDirStream) Close() {
	if s.dir != nil {
		s.dir.Releasedir(s.ctx, 0)
	}
}

func buildRootFilteredNode(resolvedSrc string, pr *pinnedRoot, st syscall.Stat_t, slot *shareSlot) *filteredNode {
	var idMap guestIDMap
	var hidden map[string]struct{}
	if slot != nil {
		idMap = slot.idMap
		hidden = slot.hidden
	}
	rootData := &fs.LoopbackRoot{
		Path: resolvedSrc,
		Dev:  uint64(st.Dev),
	}
	rootData.NewNode = func(rd *fs.LoopbackRoot, _ *fs.Inode, _ string, _ *syscall.Stat_t) fs.InodeEmbedder {
		return &filteredNode{
			LoopbackNode: &fs.LoopbackNode{RootData: rd},
			root:         pr,
			slot:         slot,
			hidden:       hidden,
			idMap:        idMap,
		}
	}
	root := &filteredNode{
		LoopbackNode: &fs.LoopbackNode{RootData: rootData},
		root:         pr,
		slot:         slot,
		hidden:       hidden,
		idMap:        idMap,
		isRoot:       true,
	}
	rootData.RootNode = root
	return root
}

// mount mounts a VCS-filtered loopback view of srcDir onto mntDir.
func mount(srcDir, mntDir string, hiddenEntries []string) (*fuse.Server, error) {
	return mountWithIDMap(srcDir, mntDir, hiddenEntries, false, 0, 0)
}

// mountWithIDMap mounts a VCS-filtered loopback view of srcDir onto mntDir
// with optional guest UID and GID mapping.
func mountWithIDMap(srcDir, mntDir string, hiddenEntries []string, mapGuestIDs bool, guestUID, guestGID uint32) (*fuse.Server, error) {
	if srcDir == "" || mntDir == "" {
		return nil, errors.New("source and mount directories must not be empty")
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
	slot.initDev = uint64(st.Dev)
	slot.initIno = st.Ino
	root := buildRootFilteredNode(resolvedSrc, pr, st, slot)

	sec := time.Second
	opts := &fs.Options{
		AttrTimeout:  &sec,
		EntryTimeout: &sec,
		MountOptions: fuse.MountOptions{
			FsName:      resolvedSrc,
			Name:        "agboxfilter",
			Options:     []string{"nosuid", "nodev"},
			DirectMount: pr.euid == 0,
		},
	}

	server, err := fs.Mount(mntDir, root, opts)
	if err != nil {
		pr.Close()
		return nil, fmt.Errorf("FUSE mount %q -> %q: %w", resolvedSrc, mntDir, err)
	}
	return server, nil
}

// CheckHostSupport checks /dev/fuse, fusermount3 or fusermount, and a live
// VCS filter mount under parentDir.
func CheckHostSupport(parentDir string) error {
	return checkHostSupportWith(parentDir, os.Geteuid, exec.LookPath)
}

func checkHostSupportWith(parentDir string, geteuid func() int, lookPath func(string) (string, error)) error {
	if parentDir == "" {
		return errors.New("parent directory must not be empty")
	}
	info, err := os.Lstat(parentDir)
	if err != nil {
		return fmt.Errorf("probe parent dir: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("refusing symlinked probe parent dir %q", parentDir)
	}
	if !info.IsDir() {
		return fmt.Errorf("probe parent dir %q is not a directory", parentDir)
	}

	f, err := os.OpenFile("/dev/fuse", os.O_RDWR, 0)
	if err != nil {
		return fmt.Errorf("cannot open /dev/fuse: %w", err)
	}
	_ = f.Close()

	if geteuid() != 0 {
		if _, err3 := lookPath("fusermount3"); err3 != nil {
			if _, err2 := lookPath("fusermount"); err2 != nil {
				return errors.New("fusermount3 is missing. Run: sudo apt-get install -y fuse3")
			}
		}
	}

	probeRoot, err := os.MkdirTemp(parentDir, ".fuse-probe-*")
	if err != nil {
		return fmt.Errorf("create FUSE probe dir: %w", err)
	}
	keepProbeRoot := false
	defer func() {
		if !keepProbeRoot {
			_ = os.RemoveAll(probeRoot)
		}
	}()

	srcDir := filepath.Join(probeRoot, "src")
	mntDir := filepath.Join(probeRoot, "mnt")
	if err := os.MkdirAll(srcDir, 0o700); err != nil {
		return fmt.Errorf("create FUSE probe source: %w", err)
	}
	if err := os.MkdirAll(mntDir, 0o700); err != nil {
		return fmt.Errorf("create FUSE probe mountpoint: %w", err)
	}

	server, err := mount(srcDir, mntDir, defaultHiddenEntries())
	if err != nil {
		return fmt.Errorf("FUSE smoke test failed: %w", err)
	}
	if unmountErr := server.Unmount(); unmountErr != nil {
		if tdErr := mounttab.TeardownFilterDir(probeRoot, nil); tdErr != nil {
			keepProbeRoot = true
			return fmt.Errorf("FUSE probe unmount failed: %w", unmountErr)
		}
		server.Wait()
		return fmt.Errorf("FUSE probe unmount failed: %w", unmountErr)
	}
	server.Wait()
	return nil
}

// runDaemonWithIDMap mounts srcDir onto mntDir and blocks until unmount or signal.
func runDaemonWithIDMap(srcDir, mntDir string, hiddenEntries []string, mapGuestIDs bool, guestUID, guestGID uint32) error {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	defer signal.Stop(sigCh)

	server, err := mountWithIDMap(srcDir, mntDir, hiddenEntries, mapGuestIDs, guestUID, guestGID)
	if err != nil {
		return err
	}

	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-sigCh:
			_ = server.Unmount()
		case <-done:
		}
	}()

	server.Wait()
	return nil
}

// RunMain parses CLI arguments for the internal `__filter` subcommand and runs
// either the single-share FUSE daemon or the Workspace Hub daemon.
func RunMain(args []string) int {
	fsFlags := flag.NewFlagSet(SubcommandName, flag.ContinueOnError)
	fsFlags.SetOutput(io.Discard)
	hubMode := fsFlags.Bool("hub", false, "Run the Workspace Hub daemon")
	src := fsFlags.String("src", "", "Source directory to expose")
	mnt := fsFlags.String("mnt", "", "Mountpoint directory")
	sock := fsFlags.String("sock", "", "Control socket path for Workspace Hub")
	specFD := fsFlags.Int("spec-fd", -1, "File descriptor that holds the initial hub spec in JSON")
	specFile := fsFlags.String("spec", "", "Path to JSON file that holds the initial hub spec")
	mapGuestIDs := fsFlags.Bool("map-guest-ids", false, "Map guest UID and GID ownership")
	guestUID := fsFlags.Uint("guest-uid", config.GuestUID, "Mapped guest UID when -map-guest-ids is set")
	guestGID := fsFlags.Uint("guest-gid", config.GuestGID, "Mapped guest GID when -map-guest-ids is set")
	if err := fsFlags.Parse(args); err != nil {
		fmt.Fprintf(os.Stderr, "agbox %s: %v\n", SubcommandName, err)
		return 2
	}
	if fsFlags.NArg() > 0 {
		fmt.Fprintf(os.Stderr, "agbox %s: unexpected positional arguments\n", SubcommandName)
		return 2
	}
	if *guestUID > math.MaxUint32 || *guestGID > math.MaxUint32 {
		fmt.Fprintf(os.Stderr, "agbox %s: guest UID and GID must fit in uint32\n", SubcommandName)
		return 2
	}
	if *hubMode {
		if *mnt == "" || *sock == "" || (*specFD >= 0 && *specFile != "") {
			fmt.Fprintf(os.Stderr, "usage: agbox %s -hub -mnt <dir> -sock <sock> [-spec-fd <fd>|-spec <file>]\n", SubcommandName)
			return 2
		}
		if err := runHubDaemonFromFlags(*mnt, *sock, *specFD, *specFile); err != nil {
			fmt.Fprintf(os.Stderr, "agbox %s: %v\n", SubcommandName, err)
			return 1
		}
		return 0
	}
	if *src == "" || *mnt == "" {
		fmt.Fprintf(os.Stderr, "usage: agbox %s -src <dir> -mnt <dir>\n", SubcommandName)
		return 2
	}
	if err := runDaemonWithIDMap(*src, *mnt, defaultHiddenEntries(), *mapGuestIDs, uint32(*guestUID), uint32(*guestGID)); err != nil {
		fmt.Fprintf(os.Stderr, "agbox %s: %v\n", SubcommandName, err)
		return 1
	}
	return 0
}

// StartSubprocess starts `exePath __filter -src <srcDir> -mnt <mntDir>` as a
// background child process, writes its PID to pidFile, and waits for the mount.
func StartSubprocess(exePath, srcDir, mntDir, pidFile string, dieWithParent bool) (int, error) {
	if err := config.EnsurePrivateDir(mntDir); err != nil {
		return 0, fmt.Errorf("prepare mountpoint %q: %w", mntDir, err)
	}
	if err := config.EnsurePrivateDir(filepath.Dir(pidFile)); err != nil {
		return 0, fmt.Errorf("prepare pidfile directory: %w", err)
	}
	args := []string{
		SubcommandName,
		"-src", srcDir,
		"-mnt", mntDir,
		"-map-guest-ids",
		"-guest-uid", strconv.Itoa(config.GuestUID),
		"-guest-gid", strconv.Itoa(config.GuestGID),
	}
	return launchFilterDaemon(daemonLaunchConfig{
		exePath:       exePath,
		args:          args,
		mntDir:        mntDir,
		pidFile:       pidFile,
		dieWithParent: dieWithParent,
		label:         "FUSE filter",
		readyCheck: func() bool {
			mounted, err := mounttab.IsPathMounted(mntDir)
			return err == nil && mounted
		},
	})
}

type daemonLaunchConfig struct {
	exePath        string
	args           []string
	mntDir         string
	pidFile        string
	pipePayload    []byte
	dieWithParent  bool
	label          string
	startupTimeout time.Duration
	readyCheck     func() bool
}

func launchFilterDaemon(cfg daemonLaunchConfig) (int, error) {
	timeout := cfg.startupTimeout
	if timeout <= 0 {
		timeout = daemonStartupTimeout
	}

	errPath := daemonStderrPath(cfg.pidFile)
	errFile, err := openDaemonStderrFile(errPath)
	if err != nil {
		return 0, err
	}

	var pipeR, pipeW *os.File
	if cfg.pipePayload != nil {
		pipeR, pipeW, err = os.Pipe()
		if err != nil {
			_ = errFile.Close()
			return 0, fmt.Errorf("create %s pipe: %w", cfg.label, err)
		}
	}

	cmd := exec.Command(cfg.exePath, cfg.args...)
	cmd.Stdin = nil
	cmd.Stdout = nil
	cmd.Stderr = errFile
	if pipeR != nil {
		cmd.ExtraFiles = []*os.File{pipeR}
	}
	if cfg.dieWithParent {
		cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGTERM}
	} else {
		cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	}

	startErr := cmd.Start()
	if pipeR != nil {
		_ = pipeR.Close()
	}
	_ = errFile.Close()
	if startErr != nil {
		if pipeW != nil {
			_ = pipeW.Close()
		}
		return 0, fmt.Errorf("start %s subprocess: %w", cfg.label, startErr)
	}
	pid := cmd.Process.Pid

	exited := make(chan error, 1)
	go func() {
		exited <- cmd.Wait()
	}()

	stopFailedChild := func(removePID bool) {
		if removePID {
			_ = os.Remove(cfg.pidFile)
		}
		_ = cmd.Process.Signal(syscall.SIGTERM)
		select {
		case <-exited:
		case <-time.After(300 * time.Millisecond):
			_ = cmd.Process.Kill()
			select {
			case <-exited:
			case <-time.After(200 * time.Millisecond):
			}
		}
		if mounted, mErr := mounttab.IsPathMounted(cfg.mntDir); mErr == nil && mounted {
			var ctl mounttab.OSController
			_ = ctl.Unmount(cfg.mntDir, true)
		}
	}

	if pipeW != nil {
		_ = pipeW.SetWriteDeadline(time.Now().Add(timeout))
		writeDone := make(chan error, 1)
		go func() {
			_, wErr := pipeW.Write(cfg.pipePayload)
			cErr := pipeW.Close()
			if wErr != nil {
				writeDone <- wErr
				return
			}
			writeDone <- cErr
		}()
		select {
		case writeErr := <-writeDone:
			if writeErr != nil {
				stopFailedChild(false)
				return 0, appendDaemonStderr(fmt.Errorf("write %s bootstrap pipe: %w", cfg.label, writeErr), errPath)
			}
		case <-time.After(timeout + 100*time.Millisecond):
			stopFailedChild(false)
			_ = pipeW.Close()
			<-writeDone
			return 0, appendDaemonStderr(fmt.Errorf("timed out writing %s bootstrap pipe", cfg.label), errPath)
		}
	}

	if err := writePIDFileNoFollow(cfg.pidFile, pid); err != nil {
		stopFailedChild(false)
		return 0, fmt.Errorf("write %s pidfile %q: %w", cfg.label, cfg.pidFile, err)
	}

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cfg.readyCheck() {
			return pid, nil
		}
		select {
		case waitErr := <-exited:
			_ = os.Remove(cfg.pidFile)
			if mounted, mErr := mounttab.IsPathMounted(cfg.mntDir); mErr == nil && mounted {
				var ctl mounttab.OSController
				_ = ctl.Unmount(cfg.mntDir, true)
			}
			if waitErr == nil {
				return 0, appendDaemonStderr(fmt.Errorf("%s exited before mounting %q: exit status 0", cfg.label, cfg.mntDir), errPath)
			}
			return 0, appendDaemonStderr(fmt.Errorf("%s exited before mounting %q: %w", cfg.label, cfg.mntDir, waitErr), errPath)
		case <-time.After(50 * time.Millisecond):
		}
	}

	stopFailedChild(true)
	return 0, appendDaemonStderr(fmt.Errorf("timed out waiting for %s mount at %q", cfg.label, cfg.mntDir), errPath)
}

func writePIDFileNoFollow(pidFile string, pid int) error {
	if info, err := os.Lstat(pidFile); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return fmt.Errorf("refusing non-regular pidfile path %q", pidFile)
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	fd, err := unix.Open(pidFile, unix.O_WRONLY|unix.O_CREAT|unix.O_TRUNC|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0o600)
	if err != nil {
		return err
	}
	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil {
		_ = unix.Close(fd)
		return err
	}
	if (st.Mode & syscall.S_IFMT) != syscall.S_IFREG {
		_ = unix.Close(fd)
		return fmt.Errorf("refusing non-regular pidfile path %q", pidFile)
	}
	if err := unix.Fchmod(fd, 0o600); err != nil {
		_ = unix.Close(fd)
		return err
	}
	f := os.NewFile(uintptr(fd), pidFile)
	payload := []byte(strconv.Itoa(pid) + "\n")
	_, wErr := f.Write(payload)
	cErr := f.Close()
	if wErr != nil {
		_ = os.Remove(pidFile)
		return wErr
	}
	if cErr != nil {
		_ = os.Remove(pidFile)
		return cErr
	}
	return nil
}

func daemonStderrPath(pidFile string) string {
	if strings.HasSuffix(pidFile, ".pid") {
		return strings.TrimSuffix(pidFile, ".pid") + ".err"
	}
	return pidFile + ".err"
}

func openDaemonStderrFile(errPath string) (*os.File, error) {
	if err := config.EnsurePrivateDir(filepath.Dir(errPath)); err != nil {
		return nil, fmt.Errorf("prepare daemon log directory: %w", err)
	}
	if info, err := os.Lstat(errPath); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return nil, fmt.Errorf("refusing non-regular daemon stderr log path %q", errPath)
		}
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("inspect daemon stderr log path %q: %w", errPath, err)
	}
	fd, err := unix.Open(errPath, unix.O_WRONLY|unix.O_CREAT|unix.O_TRUNC|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open daemon stderr log %q: %w", errPath, err)
	}
	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("stat daemon stderr log %q: %w", errPath, err)
	}
	if (st.Mode & syscall.S_IFMT) != syscall.S_IFREG {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("refusing non-regular daemon stderr log path %q", errPath)
	}
	if err := unix.Fchmod(fd, 0o600); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("chmod daemon stderr log %q: %w", errPath, err)
	}
	return os.NewFile(uintptr(fd), errPath), nil
}

func appendDaemonStderr(prefixErr error, errPath string) error {
	fd, err := unix.Open(errPath, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return prefixErr
	}
	f := os.NewFile(uintptr(fd), errPath)
	defer f.Close()
	if info, sErr := f.Stat(); sErr != nil || !info.Mode().IsRegular() {
		return prefixErr
	}
	buf := make([]byte, 4096)
	n, _ := f.Read(buf)
	detail := strings.TrimSpace(string(buf[:n]))
	if detail == "" {
		return prefixErr
	}
	return fmt.Errorf("%w (%s)", prefixErr, detail)
}
