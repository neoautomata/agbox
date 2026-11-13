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
	"os/signal"
	"path/filepath"
	"slices"
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
	// MaxHubControlBytes caps JSON RPC payloads over ws.sock at 64 KiB.
	MaxHubControlBytes = 64 * 1024

	hubEntryTimeout = 100 * time.Millisecond
)

// HubShareConfig describes one directory or single-file share managed by WorkspaceHub.
type HubShareConfig struct {
	GuestName string           `json:"guest_name"`
	HostPath  string           `json:"host_path"`
	IsFile    bool             `json:"is_file"`
	ReadOnly  bool             `json:"read_only"`
	VCSPolicy config.VCSPolicy `json:"vcs_policy"`
}

// HubShareStatus reports the live state of one share in WorkspaceHub.
type HubShareStatus struct {
	GuestName       string           `json:"guest_name"`
	HostPath        string           `json:"host_path"`
	IsFile          bool             `json:"is_file"`
	ReadOnly        bool             `json:"read_only"`
	VCSPolicy       config.VCSPolicy `json:"vcs_policy"`
	OpenWritableFDs int              `json:"open_writable_fds"`
}

type hubControlRequest struct {
	Op        string            `json:"op"`
	Add       *HubShareConfig   `json:"add,omitempty"`
	Name      string            `json:"name,omitempty"`
	ReadOnly  *bool             `json:"read_only,omitempty"`
	VCSPolicy *config.VCSPolicy `json:"vcs_policy,omitempty"`
	Force     bool              `json:"force,omitempty"`
}

type hubControlResponse struct {
	OK     bool             `json:"ok"`
	Error  string           `json:"error,omitempty"`
	Shares []HubShareStatus `json:"shares,omitempty"`
	Share  *HubShareStatus  `json:"share,omitempty"`
}

// FileShareNode exposes a single host regular file at /workspace/<name> while
// pinning its parent directory descriptor and blocking symlinks and special files.
type FileShareNode struct {
	fs.Inode
	slot *shareSlot
}

func (n *FileShareNode) openFileOPath() (int, syscall.Errno) {
	if n.slot == nil || n.slot.root == nil {
		return -1, syscall.EIO
	}
	if n.slot.isRevoked() {
		return -1, syscall.ESTALE
	}
	fd, err := n.slot.root.openat2(n.slot.fileName, unix.O_PATH|unix.O_NOFOLLOW, 0)
	if err != nil {
		return -1, fs.ToErrno(err)
	}
	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil {
		_ = unix.Close(fd)
		return -1, fs.ToErrno(err)
	}
	if (st.Mode & syscall.S_IFMT) != syscall.S_IFREG {
		_ = unix.Close(fd)
		return -1, syscall.EPERM
	}
	return fd, 0
}

func (n *FileShareNode) Statfs(ctx context.Context, out *fuse.StatfsOut) syscall.Errno {
	_ = ctx
	fd, errno := n.openFileOPath()
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

func (n *FileShareNode) Getattr(ctx context.Context, f fs.FileHandle, out *fuse.AttrOut) syscall.Errno {
	if f != nil {
		if fga, ok := f.(fs.FileGetattrer); ok {
			return fga.Getattr(ctx, out)
		}
	}
	fd, errno := n.openFileOPath()
	if errno != 0 {
		return errno
	}
	defer unix.Close(fd)
	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil {
		return fs.ToErrno(err)
	}
	out.FromStat(&st)
	out.Attr.Mode = n.slot.maskMode(out.Attr.Mode, false)
	return 0
}

func (n *FileShareNode) Statx(ctx context.Context, f fs.FileHandle, flags uint32, mask uint32, out *fuse.StatxOut) syscall.Errno {
	if f != nil {
		if fga, ok := f.(fs.FileStatxer); ok {
			return fga.Statx(ctx, flags, mask, out)
		}
	}
	fd, errno := n.openFileOPath()
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
	out.Statx.Mode = uint16(n.slot.maskMode(uint32(out.Statx.Mode), false))
	return 0
}

func (n *FileShareNode) Open(ctx context.Context, flags uint32) (fs.FileHandle, uint32, syscall.Errno) {
	_ = ctx
	if n.slot == nil || n.slot.root == nil {
		return nil, 0, syscall.EIO
	}
	if n.slot.isRevoked() {
		return nil, 0, syscall.ESTALE
	}
	writable := isWriteOpenFlags(flags)
	if writable && n.slot.isReadOnly() {
		return nil, 0, syscall.EROFS
	}
	openFlags := int(flags&^(syscall.O_APPEND|fuse.FMODE_EXEC)) | unix.O_NOFOLLOW
	if n.slot.isReadOnly() {
		openFlags = (openFlags &^ (syscall.O_WRONLY | syscall.O_RDWR | syscall.O_APPEND | syscall.O_TRUNC | os.O_CREATE)) | syscall.O_RDONLY
	}
	fd, err := n.slot.root.openat2(n.slot.fileName, openFlags, 0)
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
	sf, regErrno := newRegisteredSafeFile(fd, n.slot, writable, n.slot.root.euid, n.slot.root.egid)
	if regErrno != 0 {
		return nil, 0, regErrno
	}
	return sf, 0, 0
}

func (n *FileShareNode) Setattr(ctx context.Context, f fs.FileHandle, in *fuse.SetAttrIn, out *fuse.AttrOut) syscall.Errno {
	if n.slot == nil || n.slot.root == nil {
		return syscall.EIO
	}
	if n.slot.isRevoked() {
		return syscall.ESTALE
	}
	if n.slot.isReadOnly() {
		return syscall.EROFS
	}
	if errno := validateSetAttrIn(in, n.slot.root.euid, n.slot.root.egid); errno != 0 {
		return errno
	}
	if f != nil {
		if fsa, ok := f.(fs.FileSetattrer); ok {
			return fsa.Setattr(ctx, in, out)
		}
	}
	fd, errno := n.openFileOPath()
	if errno != 0 {
		return errno
	}
	defer unix.Close(fd)

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
	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil {
		return fs.ToErrno(err)
	}
	out.FromStat(&st)
	out.Attr.Mode = n.slot.maskMode(out.Attr.Mode, false)
	return 0
}

func (n *FileShareNode) Getxattr(ctx context.Context, attr string, dest []byte) (uint32, syscall.Errno) {
	_ = ctx
	if IsProtectedXattr(attr) {
		return 0, unix.ENODATA
	}
	fd, errno := n.openFileOPath()
	if errno != 0 {
		return 0, errno
	}
	defer unix.Close(fd)
	sz, err := unix.Getxattr(fmt.Sprintf("/proc/self/fd/%d", fd), attr, dest)
	return uint32(sz), fs.ToErrno(err)
}

func (n *FileShareNode) Listxattr(ctx context.Context, dest []byte) (uint32, syscall.Errno) {
	_ = ctx
	fd, errno := n.openFileOPath()
	if errno != 0 {
		return 0, errno
	}
	defer unix.Close(fd)
	procPath := fmt.Sprintf("/proc/self/fd/%d", fd)
	sz, err := unix.Listxattr(procPath, nil)
	if err != nil || sz <= 0 {
		return 0, fs.ToErrno(err)
	}
	raw := make([]byte, sz)
	nRead, err := unix.Listxattr(procPath, raw)
	if err != nil {
		return 0, fs.ToErrno(err)
	}
	var filtered []byte
	for _, entry := range bytes.Split(raw[:nRead], []byte{0}) {
		if len(entry) > 0 && !IsProtectedXattr(string(entry)) {
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

func (n *FileShareNode) Setxattr(ctx context.Context, attr string, data []byte, flags uint32) syscall.Errno {
	_ = ctx
	if n.slot.isRevoked() {
		return syscall.ESTALE
	}
	if n.slot.isReadOnly() {
		return syscall.EROFS
	}
	if IsProtectedXattr(attr) {
		return syscall.EPERM
	}
	fd, errno := n.openFileOPath()
	if errno != 0 {
		return errno
	}
	defer unix.Close(fd)
	return fs.ToErrno(unix.Setxattr(fmt.Sprintf("/proc/self/fd/%d", fd), attr, data, int(flags)))
}

func (n *FileShareNode) Removexattr(ctx context.Context, attr string) syscall.Errno {
	_ = ctx
	if n.slot.isRevoked() {
		return syscall.ESTALE
	}
	if n.slot.isReadOnly() {
		return syscall.EROFS
	}
	if IsProtectedXattr(attr) {
		return syscall.EPERM
	}
	fd, errno := n.openFileOPath()
	if errno != 0 {
		return errno
	}
	defer unix.Close(fd)
	return fs.ToErrno(unix.Removexattr(fmt.Sprintf("/proc/self/fd/%d", fd), attr))
}

// WorkspaceHub multiplexes multiple host shares beneath a synthetic read-only
// /workspace root directory and supports live add, set, and rm updates.
type WorkspaceHub struct {
	fs.Inode

	mu       sync.RWMutex
	slots    map[string]*shareSlot
	nextSlot atomic.Uint64
	mounted  atomic.Bool
	hidden   map[string]struct{}
	homeReal string
	dataDir  string
	euid     uint32
	egid     uint32
	bootTime time.Time
}

// NewWorkspaceHub creates a WorkspaceHub preloaded with initial shares.
func NewWorkspaceHub(initial []HubShareConfig, dataDir string) (*WorkspaceHub, error) {
	homeReal := ""
	if hDir, err := os.UserHomeDir(); err == nil && hDir != "" {
		if eval, eErr := filepath.EvalSymlinks(hDir); eErr == nil {
			homeReal = eval
		} else {
			homeReal = filepath.Clean(hDir)
		}
	}
	h := &WorkspaceHub{
		slots:    make(map[string]*shareSlot),
		hidden:   buildHiddenSet(DefaultHiddenEntries),
		homeReal: homeReal,
		dataDir:  dataDir,
		euid:     uint32(os.Geteuid()),
		egid:     uint32(os.Getegid()),
		bootTime: time.Now(),
	}
	for _, cfg := range initial {
		if _, err := h.addSlotLocked(cfg, false); err != nil {
			h.CloseAll()
			return nil, err
		}
	}
	return h, nil
}

// CloseAll revokes and closes all active share descriptors held by the Hub.
func (h *WorkspaceHub) CloseAll() {
	h.mu.Lock()
	slots := make([]*shareSlot, 0, len(h.slots))
	for _, s := range h.slots {
		slots = append(slots, s)
	}
	h.slots = make(map[string]*shareSlot)
	h.mu.Unlock()

	for _, s := range slots {
		s.revokeAll(syscall.EBADF)
	}
}

func (h *WorkspaceHub) validateAndPrepareSlot(cfg HubShareConfig) (*shareSlot, fs.InodeEmbedder, syscall.Stat_t, syscall.Timespec, error) {
	guestName, err := pathsec.ValidateGuestAlias(cfg.GuestName)
	if err != nil {
		return nil, nil, syscall.Stat_t{}, syscall.Timespec{}, err
	}
	if _, exists := h.slots[guestName]; exists {
		return nil, nil, syscall.Stat_t{}, syscall.Timespec{}, fmt.Errorf("share %q already exists in /workspace", guestName)
	}

	policy, err := config.ParseVCSPolicy(string(cfg.VCSPolicy))
	if err != nil {
		return nil, nil, syscall.Stat_t{}, syscall.Timespec{}, err
	}
	if cfg.ReadOnly && policy == config.VCSAllowHooks {
		return nil, nil, syscall.Stat_t{}, syscall.Timespec{}, errors.New("conflicting share options: read-only share cannot enable vcs-hooks")
	}

	target, err := pathsec.ValidateShare(cfg.HostPath, pathsec.Policy{
		HomeReal:         h.homeReal,
		AllowOutsideHome: true,
		ReadOnly:         cfg.ReadOnly,
		Blocklist:        pathsec.DefaultBlocklist(h.homeReal, h.dataDir, ""),
		VCSNames:         DefaultHiddenEntries,
	})
	if err != nil {
		return nil, nil, syscall.Stat_t{}, syscall.Timespec{}, err
	}
	resolvedHost := target.HostPath
	isFile := !target.IsDir
	if isFile && policy != config.VCSMask {
		return nil, nil, syscall.Stat_t{}, syscall.Timespec{}, fmt.Errorf("VCS policy %q cannot be applied to single-file share %q", policy, guestName)
	}

	existingTargets := make([]pathsec.ShareTarget, 0, len(h.slots)+1)
	for _, existing := range h.slots {
		existingTargets = append(existingTargets, pathsec.ShareTarget{HostPath: existing.hostPath})
	}
	existingTargets = append(existingTargets, pathsec.ShareTarget{HostPath: resolvedHost})
	if err := pathsec.CheckDisjointHostPaths(existingTargets); err != nil {
		return nil, nil, syscall.Stat_t{}, syscall.Timespec{}, err
	}

	slotID := h.nextSlot.Add(1)
	var btime syscall.Timespec

	if isFile {
		parentDir := filepath.Dir(resolvedHost)
		fileName := filepath.Base(resolvedHost)
		pr, _, err := newPinnedRoot(parentDir)
		if err != nil {
			return nil, nil, syscall.Stat_t{}, syscall.Timespec{}, fmt.Errorf("open parent directory of %q: %w", resolvedHost, err)
		}
		fd, err := pr.openat2(fileName, unix.O_PATH|unix.O_NOFOLLOW, 0)
		if err != nil {
			pr.Close()
			return nil, nil, syscall.Stat_t{}, syscall.Timespec{}, fmt.Errorf("open file share %q: %w", resolvedHost, err)
		}
		var st syscall.Stat_t
		statErr := statAtNoFollow(fd, "", &st, &btime)
		_ = unix.Close(fd)
		if statErr != nil {
			pr.Close()
			return nil, nil, syscall.Stat_t{}, syscall.Timespec{}, fmt.Errorf("stat file share %q: %w", resolvedHost, statErr)
		}
		if (st.Mode & syscall.S_IFMT) != syscall.S_IFREG {
			pr.Close()
			return nil, nil, syscall.Stat_t{}, syscall.Timespec{}, fmt.Errorf("share %q is not a regular file", resolvedHost)
		}
		slot := newShareSlot(slotID, guestName, resolvedHost, true, fileName, pr, h.hidden, cfg.ReadOnly, config.VCSMask)
		node := &FileShareNode{slot: slot}
		return slot, node, st, btime, nil
	}

	pr, st, err := newPinnedRoot(resolvedHost)
	if err != nil {
		return nil, nil, syscall.Stat_t{}, syscall.Timespec{}, fmt.Errorf("open directory share %q: %w", resolvedHost, err)
	}
	slot := newShareSlot(slotID, guestName, resolvedHost, false, "", pr, h.hidden, cfg.ReadOnly, policy)
	node := buildRootFilteredNode(resolvedHost, pr, st, slot)
	return slot, node, st, btime, nil
}

func (h *WorkspaceHub) attachSlotInode(ctx context.Context, slot *shareSlot, ops fs.InodeEmbedder, st *syscall.Stat_t, btime *syscall.Timespec) *fs.Inode {
	gen := uint64(1)
	if btime != nil && (btime.Sec != 0 || btime.Nsec != 0) {
		gen = uint64(btime.Sec)*1e9 + uint64(btime.Nsec)
	}
	mode := uint32(syscall.S_IFDIR)
	if slot.isFile {
		mode = uint32(syscall.S_IFREG)
	}
	stable := fs.StableAttr{
		Mode: mode,
		Gen:  gen,
		Ino:  computeStableIno(slot.slotID, slot.root.dev, uint64(st.Dev), st.Ino),
	}
	ch := h.NewPersistentInode(ctx, ops, stable)
	slot.inodeMu.Lock()
	slot.inode = ch
	slot.inodeMu.Unlock()
	h.AddChild(slot.guestName, ch, true)
	return ch
}

func slotToStatus(s *shareSlot) HubShareStatus {
	return HubShareStatus{
		GuestName:       s.guestName,
		HostPath:        s.hostPath,
		IsFile:          s.isFile,
		ReadOnly:        s.isReadOnly(),
		VCSPolicy:       s.getVCSPolicy(),
		OpenWritableFDs: s.openWritableCount(),
	}
}

func (h *WorkspaceHub) addSlotLocked(cfg HubShareConfig, mounted bool) (HubShareStatus, error) {
	slot, ops, st, btime, err := h.validateAndPrepareSlot(cfg)
	if err != nil {
		return HubShareStatus{}, err
	}
	h.slots[slot.guestName] = slot
	if mounted && h.mounted.Load() {
		h.attachSlotInode(context.Background(), slot, ops, &st, &btime)
		_ = h.NotifyEntry(slot.guestName)
	}
	return slotToStatus(slot), nil
}

func (h *WorkspaceHub) OnAdd(ctx context.Context) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.mounted.Store(true)
	for _, slot := range h.slots {
		slot.inodeMu.RLock()
		already := slot.inode != nil
		slot.inodeMu.RUnlock()
		if already {
			continue
		}
		var st syscall.Stat_t
		var btime syscall.Timespec
		var ops fs.InodeEmbedder
		if slot.isFile {
			fd, err := slot.root.openat2(slot.fileName, unix.O_PATH|unix.O_NOFOLLOW, 0)
			if err != nil {
				continue
			}
			_ = statAtNoFollow(fd, "", &st, &btime)
			_ = unix.Close(fd)
			ops = &FileShareNode{slot: slot}
		} else {
			fd, err := slot.root.openat2(".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
			if err != nil {
				continue
			}
			_ = statAtNoFollow(fd, "", &st, &btime)
			_ = unix.Close(fd)
			ops = buildRootFilteredNode(slot.hostPath, slot.root, st, slot)
		}
		h.attachSlotInode(ctx, slot, ops, &st, &btime)
	}
}

// ListShares returns all active shares in sorted order by guest name.
func (h *WorkspaceHub) ListShares() []HubShareStatus {
	h.mu.RLock()
	out := make([]HubShareStatus, 0, len(h.slots))
	for _, slot := range h.slots {
		out = append(out, slotToStatus(slot))
	}
	h.mu.RUnlock()
	slices.SortFunc(out, func(a, b HubShareStatus) int {
		return strings.Compare(a.GuestName, b.GuestName)
	})
	return out
}

// AddShare validates and attaches a new share under /workspace/<guest_name>.
func (h *WorkspaceHub) AddShare(cfg HubShareConfig) (HubShareStatus, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.addSlotLocked(cfg, true)
}

// SetShare updates ReadOnly and/or VCSPolicy on an active share.
// Downgrading from read-write to read-only fails closed if open writable handles
// exist unless force is true.
func (h *WorkspaceHub) SetShare(name string, readOnly *bool, vcsPolicy *config.VCSPolicy, force bool) (HubShareStatus, error) {
	if readOnly == nil && vcsPolicy == nil {
		return HubShareStatus{}, errors.New("nothing to update: specify read-only or VCS policy")
	}
	h.mu.Lock()
	slot, ok := h.slots[name]
	if !ok || slot.isRevoked() {
		h.mu.Unlock()
		return HubShareStatus{}, fmt.Errorf("share %q is not mounted in /workspace", name)
	}

	nextRO := slot.isReadOnly()
	if readOnly != nil {
		nextRO = *readOnly
	}
	nextPolicy := slot.getVCSPolicy()
	if vcsPolicy != nil {
		parsed, err := config.ParseVCSPolicy(string(*vcsPolicy))
		if err != nil {
			h.mu.Unlock()
			return HubShareStatus{}, err
		}
		nextPolicy = parsed
	}
	if slot.isFile && nextPolicy != config.VCSMask {
		h.mu.Unlock()
		return HubShareStatus{}, fmt.Errorf("VCS policy %q cannot be applied to single-file share %q", nextPolicy, name)
	}
	if nextRO && nextPolicy == config.VCSAllowHooks {
		h.mu.Unlock()
		return HubShareStatus{}, errors.New("conflicting share options: read-only share cannot enable vcs-hooks")
	}

	if slot.isFile && slot.isReadOnly() && !nextRO {
		fd, oErr := slot.root.openat2(slot.fileName, unix.O_PATH|unix.O_NOFOLLOW, 0)
		if oErr != nil {
			h.mu.Unlock()
			return HubShareStatus{}, fmt.Errorf("open single-file share %q: %w", name, oErr)
		}
		var st syscall.Stat_t
		sErr := syscall.Fstat(fd, &st)
		_ = unix.Close(fd)
		if sErr != nil {
			h.mu.Unlock()
			return HubShareStatus{}, fmt.Errorf("stat single-file share %q: %w", name, sErr)
		}
		if st.Nlink != 1 {
			h.mu.Unlock()
			return HubShareStatus{}, fmt.Errorf("refusing writable single-file share with multiple hard links (nlink=%d): %s", st.Nlink, slot.hostPath)
		}
	}

	downgradingToRO := !slot.isReadOnly() && nextRO
	if downgradingToRO {
		if openW := slot.openWritableCount(); openW > 0 && !force {
			h.mu.Unlock()
			return HubShareStatus{}, fmt.Errorf("share %q has %d open writable file handle(s) (close them inside the sandbox or pass --force)", name, openW)
		}
	}

	prevPolicy := slot.getVCSPolicy()
	slot.setReadOnly(nextRO)
	slot.setVCSPolicy(nextPolicy)
	if downgradingToRO {
		slot.revokeWritableFiles(syscall.EROFS)
	}

	slot.inodeMu.RLock()
	ch := slot.inode
	slot.inodeMu.RUnlock()
	status := slotToStatus(slot)
	h.mu.Unlock()

	if h.mounted.Load() {
		_ = h.NotifyEntry(name)
		if ch != nil {
			_ = ch.NotifyContent(0, 0)
			if prevPolicy != nextPolicy {
				for _, vcsName := range DefaultHiddenEntries {
					if nextPolicy == config.VCSMask {
						ch.RmChild(vcsName)
					}
					_ = ch.NotifyEntry(vcsName)
				}
			}
		}
	}
	return status, nil
}

// RemoveShare detaches /workspace/<name> and revokes all host descriptors.
// It fails closed if open writable handles exist unless force is true.
func (h *WorkspaceHub) RemoveShare(name string, force bool) error {
	h.mu.Lock()
	slot, ok := h.slots[name]
	if !ok || slot.isRevoked() {
		h.mu.Unlock()
		return fmt.Errorf("share %q is not mounted in /workspace", name)
	}
	if openW := slot.openWritableCount(); openW > 0 && !force {
		h.mu.Unlock()
		return fmt.Errorf("share %q has %d open writable file handle(s) (close them inside the sandbox or pass --force)", name, openW)
	}
	delete(h.slots, name)
	slot.inodeMu.RLock()
	ch := slot.inode
	slot.inodeMu.RUnlock()
	h.mu.Unlock()

	slot.revokeAll(syscall.ESTALE)

	if h.mounted.Load() {
		h.RmChild(name)
		if ch != nil {
			ch.RmAllChildren()
			_ = h.NotifyDelete(name, ch)
		}
		_ = h.NotifyEntry(name)
	}
	return nil
}

func (h *WorkspaceHub) fillHubAttr(attr *fuse.Attr) {
	attr.Ino = 1
	attr.Mode = uint32(syscall.S_IFDIR) | 0o555
	attr.Nlink = 2
	attr.Uid = h.euid
	attr.Gid = h.egid
	sec := uint64(h.bootTime.Unix())
	nsec := uint32(h.bootTime.Nanosecond())
	attr.Atime = sec
	attr.Mtime = sec
	attr.Ctime = sec
	attr.Atimensec = nsec
	attr.Mtimensec = nsec
	attr.Ctimensec = nsec
}

func (h *WorkspaceHub) Getattr(ctx context.Context, _ fs.FileHandle, out *fuse.AttrOut) syscall.Errno {
	_ = ctx
	h.fillHubAttr(&out.Attr)
	out.SetTimeout(hubEntryTimeout)
	return 0
}

func (h *WorkspaceHub) Lookup(ctx context.Context, name string, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	if isInvalidComponent(name) {
		return nil, syscall.EINVAL
	}
	h.mu.RLock()
	slot, ok := h.slots[name]
	h.mu.RUnlock()
	if !ok || slot == nil || slot.isRevoked() {
		out.SetEntryTimeout(0)
		out.SetAttrTimeout(0)
		return nil, syscall.ENOENT
	}

	var st syscall.Stat_t
	var btime syscall.Timespec
	if slot.isFile {
		fd, err := slot.root.openat2(slot.fileName, unix.O_PATH|unix.O_NOFOLLOW, 0)
		if err != nil {
			out.SetEntryTimeout(0)
			return nil, fs.ToErrno(err)
		}
		err = statAtNoFollow(fd, "", &st, &btime)
		_ = unix.Close(fd)
		if err != nil {
			out.SetEntryTimeout(0)
			return nil, fs.ToErrno(err)
		}
		if (st.Mode & syscall.S_IFMT) != syscall.S_IFREG {
			out.SetEntryTimeout(0)
			return nil, syscall.EPERM
		}
	} else {
		fd, err := slot.root.openat2(".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
		if err != nil {
			out.SetEntryTimeout(0)
			return nil, fs.ToErrno(err)
		}
		err = statAtNoFollow(fd, "", &st, &btime)
		_ = unix.Close(fd)
		if err != nil {
			out.SetEntryTimeout(0)
			return nil, fs.ToErrno(err)
		}
	}

	out.Attr.FromStat(&st)
	out.Attr.Mode = slot.maskMode(out.Attr.Mode, false)
	out.SetEntryTimeout(hubEntryTimeout)
	out.SetAttrTimeout(hubEntryTimeout)

	slot.inodeMu.RLock()
	ch := slot.inode
	slot.inodeMu.RUnlock()
	if ch != nil {
		return ch, 0
	}

	h.mu.Lock()
	defer h.mu.Unlock()
	cur, stillOK := h.slots[name]
	if !stillOK || cur != slot || slot.isRevoked() {
		out.SetEntryTimeout(0)
		return nil, syscall.ENOENT
	}
	slot.inodeMu.RLock()
	ch = slot.inode
	slot.inodeMu.RUnlock()
	if ch != nil {
		return ch, 0
	}
	var ops fs.InodeEmbedder
	if slot.isFile {
		ops = &FileShareNode{slot: slot}
	} else {
		ops = buildRootFilteredNode(slot.hostPath, slot.root, st, slot)
	}
	return h.attachSlotInode(ctx, slot, ops, &st, &btime), 0
}

func (h *WorkspaceHub) Readdir(ctx context.Context) (fs.DirStream, syscall.Errno) {
	_ = ctx
	h.mu.RLock()
	names := make([]string, 0, len(h.slots))
	slotsByName := make(map[string]*shareSlot, len(h.slots))
	for name, slot := range h.slots {
		if !slot.isRevoked() {
			names = append(names, name)
			slotsByName[name] = slot
		}
	}
	h.mu.RUnlock()
	slices.Sort(names)

	entries := make([]fuse.DirEntry, 0, len(names))
	for _, name := range names {
		slot := slotsByName[name]
		mode := uint32(syscall.S_IFDIR)
		if slot.isFile {
			mode = uint32(syscall.S_IFREG)
		}
		var ino uint64
		slot.inodeMu.RLock()
		if slot.inode != nil {
			ino = slot.inode.StableAttr().Ino
		}
		slot.inodeMu.RUnlock()
		entries = append(entries, fuse.DirEntry{
			Name: name,
			Mode: mode,
			Ino:  ino,
		})
	}
	return fs.NewListDirStream(entries), 0
}

func (h *WorkspaceHub) Create(ctx context.Context, name string, flags uint32, mode uint32, out *fuse.EntryOut) (*fs.Inode, fs.FileHandle, uint32, syscall.Errno) {
	_, _, _, _, _ = ctx, name, flags, mode, out
	return nil, nil, 0, syscall.EROFS
}

func (h *WorkspaceHub) Mkdir(ctx context.Context, name string, mode uint32, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	_, _, _, _ = ctx, name, mode, out
	return nil, syscall.EROFS
}

func (h *WorkspaceHub) Mknod(ctx context.Context, name string, mode uint32, rdev uint32, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	_, _, _, _, _ = ctx, name, mode, rdev, out
	return nil, syscall.EROFS
}

func (h *WorkspaceHub) Symlink(ctx context.Context, target, name string, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	_, _, _, _ = ctx, target, name, out
	return nil, syscall.EROFS
}

func (h *WorkspaceHub) Link(ctx context.Context, target fs.InodeEmbedder, name string, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	_, _, _, _ = ctx, target, name, out
	return nil, syscall.EROFS
}

func (h *WorkspaceHub) Unlink(ctx context.Context, name string) syscall.Errno {
	_, _ = ctx, name
	return syscall.EROFS
}

func (h *WorkspaceHub) Rmdir(ctx context.Context, name string) syscall.Errno {
	_, _ = ctx, name
	return syscall.EROFS
}

func (h *WorkspaceHub) Rename(ctx context.Context, name string, newParent fs.InodeEmbedder, newName string, flags uint32) syscall.Errno {
	_, _, _, _, _ = ctx, name, newParent, newName, flags
	return syscall.EROFS
}

func (h *WorkspaceHub) Setattr(ctx context.Context, f fs.FileHandle, in *fuse.SetAttrIn, out *fuse.AttrOut) syscall.Errno {
	_, _, _, _ = ctx, f, in, out
	return syscall.EROFS
}

func (h *WorkspaceHub) Setxattr(ctx context.Context, attr string, data []byte, flags uint32) syscall.Errno {
	_, _, _, _ = ctx, attr, data, flags
	return syscall.EROFS
}

func (h *WorkspaceHub) Removexattr(ctx context.Context, attr string) syscall.Errno {
	_, _ = ctx, attr
	return syscall.EROFS
}

// MountWorkspaceHub mounts a multiplexed WorkspaceHub onto mntDir and starts its
// peer-authenticated control socket at sockPath when sockPath is non-empty.
func MountWorkspaceHub(mntDir, sockPath string, initial []HubShareConfig, dataDir string) (*WorkspaceHub, *fuse.Server, io.Closer, error) {
	if mntDir == "" {
		return nil, nil, nil, errors.New("workspace hub mount directory is required")
	}
	hub, err := NewWorkspaceHub(initial, dataDir)
	if err != nil {
		return nil, nil, nil, err
	}

	var ln net.Listener
	if sockPath != "" {
		var lErr error
		ln, lErr = listenVerifiedUnixSocket(sockPath, hub)
		if lErr != nil {
			hub.CloseAll()
			return nil, nil, nil, lErr
		}
	}

	ttl := hubEntryTimeout
	opts := &fs.Options{
		AttrTimeout:  &ttl,
		EntryTimeout: &ttl,
		MountOptions: fuse.MountOptions{
			FsName:  "agbox-workspace-hub",
			Name:    "agboxhub",
			Options: []string{"nosuid", "nodev"},
		},
	}

	server, err := fs.Mount(mntDir, hub, opts)
	if err != nil {
		if ln != nil {
			_ = ln.Close()
		}
		hub.CloseAll()
		return nil, nil, nil, fmt.Errorf("FUSE hub mount -> %q: %w", mntDir, err)
	}
	return hub, server, ln, nil
}

// ServeControlSocket binds the authenticated 0600 Unix domain control socket at sockPath
// for hub without mounting a kernel FUSE filesystem.
func ServeControlSocket(sockPath string, hub *WorkspaceHub) (net.Listener, error) {
	return listenVerifiedUnixSocket(sockPath, hub)
}

func listenVerifiedUnixSocket(sockPath string, hub *WorkspaceHub) (net.Listener, error) {
	if err := ensureSafeMountDir(filepath.Dir(sockPath)); err != nil {
		return nil, fmt.Errorf("prepare hub socket dir: %w", err)
	}
	_ = os.Remove(sockPath)
	addr, err := net.ResolveUnixAddr("unix", sockPath)
	if err != nil {
		return nil, err
	}
	ul, err := net.ListenUnix("unix", addr)
	if err != nil {
		return nil, fmt.Errorf("listen on hub socket %q: %w", sockPath, err)
	}
	if err := os.Chmod(sockPath, 0o600); err != nil {
		_ = ul.Close()
		return nil, fmt.Errorf("chmod hub socket %q: %w", sockPath, err)
	}
	ul.SetUnlinkOnClose(true)

	expectedUID := uint32(os.Geteuid())
	go serveHubControlSocket(ul, hub, expectedUID)
	return ul, nil
}

func verifyPeerUID(conn *net.UnixConn, expectedUID uint32) error {
	sc, err := conn.SyscallConn()
	if err != nil {
		return err
	}
	var cred *unix.Ucred
	var credErr error
	if cErr := sc.Control(func(fd uintptr) {
		cred, credErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); cErr != nil {
		return cErr
	}
	if credErr != nil {
		return credErr
	}
	if cred == nil || cred.Uid != expectedUID {
		return errors.New("unauthorized peer UID on workspace hub socket")
	}
	return nil
}

func serveHubControlSocket(ul *net.UnixListener, hub *WorkspaceHub, expectedUID uint32) {
	for {
		conn, err := ul.AcceptUnix()
		if err != nil {
			return
		}
		go handleHubControlConn(conn, hub, expectedUID)
	}
}

func handleHubControlConn(conn *net.UnixConn, hub *WorkspaceHub, expectedUID uint32) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	if err := verifyPeerUID(conn, expectedUID); err != nil {
		return
	}
	raw, err := io.ReadAll(io.LimitReader(conn, MaxHubControlBytes+1))
	if err != nil || len(raw) > MaxHubControlBytes {
		_ = json.NewEncoder(conn).Encode(hubControlResponse{OK: false, Error: "invalid or oversized hub request"})
		return
	}
	var req hubControlRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		_ = json.NewEncoder(conn).Encode(hubControlResponse{OK: false, Error: "invalid JSON request"})
		return
	}

	var resp hubControlResponse
	switch req.Op {
	case "ping":
		resp = hubControlResponse{OK: true}
	case "list":
		resp = hubControlResponse{OK: true, Shares: hub.ListShares()}
	case "add":
		if req.Add == nil {
			resp = hubControlResponse{OK: false, Error: "missing share configuration"}
			break
		}
		st, aErr := hub.AddShare(*req.Add)
		if aErr != nil {
			resp = hubControlResponse{OK: false, Error: aErr.Error()}
			break
		}
		resp = hubControlResponse{OK: true, Share: &st}
	case "set":
		st, sErr := hub.SetShare(req.Name, req.ReadOnly, req.VCSPolicy, req.Force)
		if sErr != nil {
			resp = hubControlResponse{OK: false, Error: sErr.Error()}
			break
		}
		resp = hubControlResponse{OK: true, Share: &st}
	case "rm":
		if rErr := hub.RemoveShare(req.Name, req.Force); rErr != nil {
			resp = hubControlResponse{OK: false, Error: rErr.Error()}
			break
		}
		resp = hubControlResponse{OK: true}
	default:
		resp = hubControlResponse{OK: false, Error: fmt.Sprintf("unknown hub operation %q", req.Op)}
	}
	_ = json.NewEncoder(conn).Encode(resp)
}

type hubBootstrapSpec struct {
	DataDir string           `json:"data_dir,omitempty"`
	Shares  []HubShareConfig `json:"shares"`
}

func runHubDaemonFromFlags(mntDir, sockPath string, specFD int, specFile string) error {
	var spec hubBootstrapSpec
	if specFD >= 0 {
		f := os.NewFile(uintptr(specFD), "hub-spec-fd")
		if f == nil {
			return fmt.Errorf("invalid -spec-fd %d", specFD)
		}
		raw, err := io.ReadAll(io.LimitReader(f, MaxHubControlBytes+1))
		_ = f.Close()
		if err != nil || len(raw) > MaxHubControlBytes {
			return errors.New("read hub bootstrap spec pipe failed")
		}
		if len(bytes.TrimSpace(raw)) > 0 {
			if err := json.Unmarshal(raw, &spec); err != nil {
				return fmt.Errorf("parse hub bootstrap spec: %w", err)
			}
		}
	} else if specFile != "" {
		raw, err := os.ReadFile(specFile)
		if err != nil {
			return fmt.Errorf("read hub spec file: %w", err)
		}
		if len(bytes.TrimSpace(raw)) > 0 {
			if err := json.Unmarshal(raw, &spec); err != nil {
				return fmt.Errorf("parse hub spec file: %w", err)
			}
		}
	}

	hub, server, ln, err := MountWorkspaceHub(mntDir, sockPath, spec.Shares, spec.DataDir)
	if err != nil {
		return err
	}
	defer func() {
		if ln != nil {
			_ = ln.Close()
		}
		hub.CloseAll()
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	go func() {
		<-sigCh
		if ln != nil {
			_ = ln.Close()
		}
		_ = server.Unmount()
	}()

	server.Wait()
	return nil
}

// StartHubSubprocess starts `exePath __filter -hub -mnt <mntDir> -sock <sockPath> -spec-fd 3`
// as a background child process, writes its PID to pidFile, and waits until both
// the FUSE mountpoint and the control socket respond.
func StartHubSubprocess(exePath, mntDir, sockPath, pidFile string, initial []HubShareConfig, dataDir string, dieWithParent bool) (int, error) {
	if err := ensureSafeMountDir(mntDir); err != nil {
		return 0, fmt.Errorf("prepare hub mountpoint %q: %w", mntDir, err)
	}
	if err := ensureSafeMountDir(filepath.Dir(sockPath)); err != nil {
		return 0, fmt.Errorf("prepare hub socket directory: %w", err)
	}
	if err := ensureSafeMountDir(filepath.Dir(pidFile)); err != nil {
		return 0, fmt.Errorf("prepare hub pidfile directory: %w", err)
	}

	specBytes, err := json.Marshal(hubBootstrapSpec{
		DataDir: dataDir,
		Shares:  initial,
	})
	if err != nil {
		return 0, fmt.Errorf("marshal hub bootstrap spec: %w", err)
	}
	if len(specBytes) > MaxHubControlBytes {
		return 0, errors.New("initial share list exceeds maximum hub bootstrap size")
	}

	pr, pw, err := os.Pipe()
	if err != nil {
		return 0, fmt.Errorf("create hub bootstrap pipe: %w", err)
	}
	if _, err := pw.Write(specBytes); err != nil {
		_ = pr.Close()
		_ = pw.Close()
		return 0, fmt.Errorf("write hub bootstrap pipe: %w", err)
	}
	_ = pw.Close()

	cmd := exec.Command(exePath, SubcommandName, "-hub", "-mnt", mntDir, "-sock", sockPath, "-spec-fd", "3")
	cmd.Stdout = nil
	cmd.Stderr = os.Stderr
	cmd.ExtraFiles = []*os.File{pr}
	if dieWithParent {
		cmd.SysProcAttr = &syscall.SysProcAttr{
			Pdeathsig: syscall.SIGTERM,
		}
	} else {
		cmd.SysProcAttr = &syscall.SysProcAttr{
			Setsid: true,
		}
	}

	startErr := cmd.Start()
	_ = pr.Close()
	if startErr != nil {
		return 0, fmt.Errorf("start FUSE hub subprocess: %w", startErr)
	}
	pid := cmd.Process.Pid

	exited := make(chan error, 1)
	go func() {
		exited <- cmd.Wait()
	}()

	if err := os.WriteFile(pidFile, []byte(strconv.Itoa(pid)+"\n"), 0o600); err != nil {
		_ = cmd.Process.Signal(syscall.SIGTERM)
		return 0, fmt.Errorf("write FUSE hub pidfile %q: %w", pidFile, err)
	}

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		mounted, mErr := mounttab.IsPathMounted(mntDir)
		if mErr == nil && mounted && PingHub(sockPath) == nil {
			return pid, nil
		}
		select {
		case waitErr := <-exited:
			_ = os.Remove(pidFile)
			return 0, fmt.Errorf("FUSE hub exited before mounting %q: %w", mntDir, waitErr)
		case <-time.After(50 * time.Millisecond):
		}
	}

	_ = cmd.Process.Signal(syscall.SIGTERM)
	return 0, fmt.Errorf("timed out waiting for FUSE hub mount at %q", mntDir)
}

func callHubSocket(sockPath string, req hubControlRequest) (hubControlResponse, error) {
	info, err := os.Lstat(sockPath)
	if err != nil {
		return hubControlResponse{}, fmt.Errorf("stat workspace hub socket %q: %w", sockPath, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return hubControlResponse{}, fmt.Errorf("refusing symlinked workspace hub socket %q", sockPath)
	}
	if info.Mode()&os.ModeSocket == 0 {
		return hubControlResponse{}, fmt.Errorf("path %q is not a Unix domain socket", sockPath)
	}

	addr, err := net.ResolveUnixAddr("unix", sockPath)
	if err != nil {
		return hubControlResponse{}, err
	}
	conn, err := net.DialUnix("unix", nil, addr)
	if err != nil {
		return hubControlResponse{}, fmt.Errorf("connect to workspace hub socket %q: %w", sockPath, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	if err := verifyPeerUID(conn, uint32(os.Geteuid())); err != nil {
		return hubControlResponse{}, err
	}
	payload, err := json.Marshal(req)
	if err != nil {
		return hubControlResponse{}, err
	}
	if _, err := conn.Write(payload); err != nil {
		return hubControlResponse{}, err
	}
	_ = conn.CloseWrite()

	raw, err := io.ReadAll(io.LimitReader(conn, MaxHubControlBytes+1))
	if err != nil {
		return hubControlResponse{}, err
	}
	var resp hubControlResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		return hubControlResponse{}, fmt.Errorf("invalid response from workspace hub: %w", err)
	}
	if !resp.OK {
		if resp.Error != "" {
			return resp, errors.New(resp.Error)
		}
		return resp, errors.New("workspace hub rejected request")
	}
	return resp, nil
}

// PingHub checks whether the Workspace Hub control socket at sockPath is live.
func PingHub(sockPath string) error {
	_, err := callHubSocket(sockPath, hubControlRequest{Op: "ping"})
	return err
}

// ListHubShares queries all active shares from a running Workspace Hub.
func ListHubShares(sockPath string) ([]HubShareStatus, error) {
	resp, err := callHubSocket(sockPath, hubControlRequest{Op: "list"})
	if err != nil {
		return nil, err
	}
	return resp.Shares, nil
}

// AddHubShare attaches a new share on a running Workspace Hub.
func AddHubShare(sockPath string, cfg HubShareConfig) (HubShareStatus, error) {
	resp, err := callHubSocket(sockPath, hubControlRequest{Op: "add", Add: &cfg})
	if err != nil {
		return HubShareStatus{}, err
	}
	if resp.Share == nil {
		return HubShareStatus{}, errors.New("workspace hub returned empty share status")
	}
	return *resp.Share, nil
}

// SetHubShare updates permissions on an active share in a running Workspace Hub.
func SetHubShare(sockPath, name string, readOnly *bool, vcsPolicy *config.VCSPolicy, force bool) (HubShareStatus, error) {
	resp, err := callHubSocket(sockPath, hubControlRequest{
		Op:        "set",
		Name:      name,
		ReadOnly:  readOnly,
		VCSPolicy: vcsPolicy,
		Force:     force,
	})
	if err != nil {
		return HubShareStatus{}, err
	}
	if resp.Share == nil {
		return HubShareStatus{}, errors.New("workspace hub returned empty share status")
	}
	return *resp.Share, nil
}

// RemoveHubShare detaches an active share from a running Workspace Hub.
func RemoveHubShare(sockPath, name string, force bool) error {
	_, err := callHubSocket(sockPath, hubControlRequest{
		Op:    "rm",
		Name:  name,
		Force: force,
	})
	return err
}
