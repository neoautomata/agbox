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
	"os/signal"
	"path/filepath"
	"slices"
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
	// maxHubControlBytes caps JSON control payloads over ws.sock at 64 KiB.
	maxHubControlBytes = 64 * 1024

	hubEntryTimeout = 100 * time.Millisecond
)

// HubShareConfig describes one directory or single-file share in WorkspaceHub.
type HubShareConfig struct {
	GuestName string           `json:"guest_name"`
	HostPath  string           `json:"host_path"`
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

// HubOptions configures containment, blocklists, and ID mapping for WorkspaceHub.
type HubOptions struct {
	HomeReal         string
	DataDir          string
	MSBHome          string
	AllowOutsideHome bool
	MapGuestIDs      bool
	GuestUID         uint32
	GuestGID         uint32
	GetEUID          func() int
	GetEGID          func() int
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

func openWritableHandlesError(name string, count int) error {
	return fmt.Errorf("share %q has %d open writable file handles. Close them in the sandbox or use --force.", name, count)
}

// fileShareNode exposes a single host regular file at /workspace/<name>.
// It pins the parent directory descriptor and blocks symlinks and special files.
type fileShareNode struct {
	fs.Inode
	slot *shareSlot
}

func (n *fileShareNode) openFileOPath() (int, syscall.Errno) {
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

func (n *fileShareNode) Statfs(ctx context.Context, out *fuse.StatfsOut) syscall.Errno {
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

func (n *fileShareNode) Getattr(ctx context.Context, f fs.FileHandle, out *fuse.AttrOut) syscall.Errno {
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
	n.slot.idMap.applyAttr(&out.Attr)
	return 0
}

func (n *fileShareNode) Statx(ctx context.Context, f fs.FileHandle, flags uint32, mask uint32, out *fuse.StatxOut) syscall.Errno {
	if f != nil {
		if fga, ok := f.(fs.FileStatxer); ok {
			errno := fga.Statx(ctx, flags, mask, out)
			if errno == 0 {
				out.Statx.Mode = uint16(n.slot.maskMode(uint32(out.Statx.Mode), false))
				n.slot.idMap.applyStatx(out)
			}
			return errno
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
	n.slot.idMap.applyStatx(out)
	return 0
}

func (n *fileShareNode) Open(ctx context.Context, flags uint32) (fs.FileHandle, uint32, syscall.Errno) {
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
	fd, st, openErr := openRegularViaOPath(n.slot.root, n.slot.fileName, flags, n.slot.isReadOnly(), writable)
	if openErr != 0 {
		return nil, 0, openErr
	}
	sf, regErrno := newRegisteredSafeFile(fd, &st, n.slot, n.slot.fileName, writable, n.slot.root.euid, n.slot.root.egid)
	if regErrno != 0 {
		return nil, 0, regErrno
	}
	return sf, 0, 0
}

func (n *fileShareNode) Setattr(ctx context.Context, f fs.FileHandle, in *fuse.SetAttrIn, out *fuse.AttrOut) syscall.Errno {
	if n.slot == nil || n.slot.root == nil {
		return syscall.EIO
	}
	if n.slot.isRevoked() {
		return syscall.ESTALE
	}
	if n.slot.isReadOnly() {
		return syscall.EROFS
	}
	if errno := validateSetAttrInWithIDMap(in, n.slot.root.euid, n.slot.root.egid, n.slot.idMap); errno != 0 {
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

	var preSt syscall.Stat_t
	if err := syscall.Fstat(fd, &preSt); err != nil {
		return fs.ToErrno(err)
	}
	if !n.slot.isReadOnly() && preSt.Nlink != 1 {
		return syscall.EPERM
	}

	if errno := applyProcFDSetattr(fd, in, false); errno != 0 {
		return errno
	}
	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil {
		return fs.ToErrno(err)
	}
	out.FromStat(&st)
	out.Attr.Mode = n.slot.maskMode(out.Attr.Mode, false)
	n.slot.idMap.applyAttr(&out.Attr)
	return 0
}

func (n *fileShareNode) Getxattr(ctx context.Context, attr string, dest []byte) (uint32, syscall.Errno) {
	_ = ctx
	if isProtectedXattr(attr) {
		return 0, unix.ENODATA
	}
	fd, errno := n.openFileOPath()
	if errno != 0 {
		return 0, errno
	}
	defer unix.Close(fd)
	sz, err := unix.Getxattr(fmt.Sprintf("/proc/self/fd/%d", fd), attr, dest)
	if err != nil {
		return 0, fs.ToErrno(err)
	}
	return uint32(sz), 0
}

func (n *fileShareNode) Listxattr(ctx context.Context, dest []byte) (uint32, syscall.Errno) {
	_ = ctx
	fd, errno := n.openFileOPath()
	if errno != 0 {
		return 0, errno
	}
	defer unix.Close(fd)
	return listFilteredXattrs(fd, dest)
}

func (n *fileShareNode) Setxattr(ctx context.Context, attr string, data []byte, flags uint32) syscall.Errno {
	_ = ctx
	if n.slot.isRevoked() {
		return syscall.ESTALE
	}
	if n.slot.isReadOnly() {
		return syscall.EROFS
	}
	if isProtectedXattr(attr) {
		return syscall.EPERM
	}
	fd, errno := n.openFileOPath()
	if errno != 0 {
		return errno
	}
	defer unix.Close(fd)
	return fs.ToErrno(unix.Setxattr(fmt.Sprintf("/proc/self/fd/%d", fd), attr, data, int(flags)))
}

func (n *fileShareNode) Removexattr(ctx context.Context, attr string) syscall.Errno {
	_ = ctx
	if n.slot.isRevoked() {
		return syscall.ESTALE
	}
	if n.slot.isReadOnly() {
		return syscall.EROFS
	}
	if isProtectedXattr(attr) {
		return syscall.EPERM
	}
	fd, errno := n.openFileOPath()
	if errno != 0 {
		return errno
	}
	defer unix.Close(fd)
	return fs.ToErrno(unix.Removexattr(fmt.Sprintf("/proc/self/fd/%d", fd), attr))
}

// WorkspaceHub multiplexes host shares beneath a read-only /workspace root
// and supports live add, set, and rm updates.
type WorkspaceHub struct {
	fs.Inode

	mu               sync.RWMutex
	slots            map[string]*shareSlot
	nextSlot         atomic.Uint64
	mounted          atomic.Bool
	hidden           map[string]struct{}
	homeReal         string
	dataDir          string
	msbHome          string
	allowOutsideHome bool
	geteuid          func() int
	getegid          func() int
	euid             uint32
	egid             uint32
	idMap            guestIDMap
	bootTime         time.Time
}

var (
	_ fs.NodeGetxattrer  = (*WorkspaceHub)(nil)
	_ fs.NodeListxattrer = (*WorkspaceHub)(nil)
)

// NewWorkspaceHubWithOptions creates a WorkspaceHub preloaded with initial shares.
func NewWorkspaceHubWithOptions(initial []HubShareConfig, opts HubOptions) (*WorkspaceHub, error) {
	geteuid := opts.GetEUID
	if geteuid == nil {
		geteuid = os.Geteuid
	}
	getegid := opts.GetEGID
	if getegid == nil {
		getegid = os.Getegid
	}

	homeReal := strings.TrimSpace(opts.HomeReal)
	if homeReal != "" {
		if eval, eErr := filepath.EvalSymlinks(homeReal); eErr == nil {
			homeReal = eval
		} else {
			homeReal = filepath.Clean(homeReal)
		}
	} else if hDir, err := os.UserHomeDir(); err == nil && hDir != "" {
		if eval, eErr := filepath.EvalSymlinks(hDir); eErr == nil {
			homeReal = eval
		} else {
			homeReal = filepath.Clean(hDir)
		}
	}

	msbHome := strings.TrimSpace(opts.MSBHome)
	if msbHome == "" {
		if envMSB := strings.TrimSpace(os.Getenv("MSB_HOME")); envMSB != "" && filepath.IsAbs(envMSB) {
			msbHome = filepath.Clean(envMSB)
		} else if homeReal != "" {
			msbHome = filepath.Join(homeReal, ".microsandbox")
		}
	} else {
		msbHome = filepath.Clean(msbHome)
	}

	dataDir := strings.TrimSpace(opts.DataDir)
	if dataDir != "" {
		dataDir = filepath.Clean(dataDir)
	}

	h := &WorkspaceHub{
		slots:            make(map[string]*shareSlot),
		hidden:           buildHiddenSet(defaultHiddenEntries()),
		homeReal:         homeReal,
		dataDir:          dataDir,
		msbHome:          msbHome,
		allowOutsideHome: opts.AllowOutsideHome,
		geteuid:          geteuid,
		getegid:          getegid,
		euid:             uint32(geteuid()),
		egid:             uint32(getegid()),
		idMap:            newGuestIDMap(opts.MapGuestIDs, opts.GuestUID, opts.GuestGID),
		bootTime:         time.Now(),
	}
	for _, cfg := range initial {
		if _, _, err := h.addSlotLocked(cfg, false); err != nil {
			h.CloseAll()
			return nil, err
		}
	}
	return h, nil
}

// CloseAll revokes and closes all active share descriptors in the hub.
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
		AllowOutsideHome: h.allowOutsideHome,
		ReadOnly:         cfg.ReadOnly,
		Blocklist:        pathsec.DefaultBlocklist(h.homeReal, h.dataDir, h.msbHome),
		VCSNames:         defaultHiddenEntries(),
	})
	if err != nil {
		return nil, nil, syscall.Stat_t{}, syscall.Timespec{}, err
	}
	resolvedHost := target.HostPath
	isFile := !target.IsDir
	if isFile && policy != config.VCSMask {
		return nil, nil, syscall.Stat_t{}, syscall.Timespec{}, fmt.Errorf("single-file share %q accepts only the mask VCS policy, not %q", guestName, policy)
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
		pr, _, err := newPinnedRootWithIDs(parentDir, h.geteuid, h.getegid)
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
		if !cfg.ReadOnly && st.Nlink != 1 {
			pr.Close()
			return nil, nil, syscall.Stat_t{}, syscall.Timespec{}, fmt.Errorf("refusing writable single-file share with multiple hard links (nlink=%d): %s", st.Nlink, resolvedHost)
		}
		slot := newShareSlotWithIDMap(slotID, guestName, resolvedHost, true, fileName, pr, h.hidden, cfg.ReadOnly, config.VCSMask, h.idMap)
		slot.initDev = uint64(st.Dev)
		slot.initIno = st.Ino
		node := &fileShareNode{slot: slot}
		return slot, node, st, btime, nil
	}

	pr, st, err := newPinnedRootWithIDs(resolvedHost, h.geteuid, h.getegid)
	if err != nil {
		return nil, nil, syscall.Stat_t{}, syscall.Timespec{}, fmt.Errorf("open directory share %q: %w", resolvedHost, err)
	}
	slot := newShareSlotWithIDMap(slotID, guestName, resolvedHost, false, "", pr, h.hidden, cfg.ReadOnly, policy, h.idMap)
	slot.initDev = uint64(st.Dev)
	slot.initIno = st.Ino
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

func (h *WorkspaceHub) addSlotLocked(cfg HubShareConfig, mounted bool) (HubShareStatus, bool, error) {
	slot, ops, st, btime, err := h.validateAndPrepareSlot(cfg)
	if err != nil {
		return HubShareStatus{}, false, err
	}
	h.slots[slot.guestName] = slot
	notify := false
	if mounted && h.mounted.Load() {
		h.attachSlotInode(context.Background(), slot, ops, &st, &btime)
		notify = true
	}
	return slotToStatus(slot), notify, nil
}

func (h *WorkspaceHub) OnAdd(ctx context.Context) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.mounted.Store(true)
	for name, slot := range h.slots {
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
				delete(h.slots, name)
				slot.revokeAll(syscall.ESTALE)
				fmt.Fprintf(os.Stderr, "[vcsfuse] ERROR: open file share %q on mount: %v\n", name, err)
				continue
			}
			sErr := statAtNoFollow(fd, "", &st, &btime)
			_ = unix.Close(fd)
			if sErr != nil || (st.Mode&syscall.S_IFMT) != syscall.S_IFREG || (!slot.isReadOnly() && st.Nlink != 1) {
				delete(h.slots, name)
				slot.revokeAll(syscall.ESTALE)
				fmt.Fprintf(os.Stderr, "[vcsfuse] ERROR: invalid file share %q on mount\n", name)
				continue
			}
			ops = &fileShareNode{slot: slot}
		} else {
			fd, err := slot.root.openat2(".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
			if err != nil {
				delete(h.slots, name)
				slot.revokeAll(syscall.ESTALE)
				fmt.Fprintf(os.Stderr, "[vcsfuse] ERROR: open directory share %q on mount: %v\n", name, err)
				continue
			}
			sErr := statAtNoFollow(fd, "", &st, &btime)
			_ = unix.Close(fd)
			if sErr != nil || (st.Mode&syscall.S_IFMT) != syscall.S_IFDIR {
				delete(h.slots, name)
				slot.revokeAll(syscall.ESTALE)
				fmt.Fprintf(os.Stderr, "[vcsfuse] ERROR: invalid directory share %q on mount\n", name)
				continue
			}
			ops = buildRootFilteredNode(slot.hostPath, slot.root, st, slot)
		}
		h.attachSlotInode(ctx, slot, ops, &st, &btime)
	}
}

func (h *WorkspaceHub) listShares() []HubShareStatus {
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

func (h *WorkspaceHub) addShare(cfg HubShareConfig) (HubShareStatus, error) {
	h.mu.Lock()
	status, notify, err := h.addSlotLocked(cfg, true)
	h.mu.Unlock()
	if err != nil {
		return HubShareStatus{}, err
	}
	if notify {
		_ = h.NotifyEntry(status.GuestName)
	}
	return status, nil
}

func (h *WorkspaceHub) setShare(name string, readOnly *bool, vcsPolicy *config.VCSPolicy, force bool) (HubShareStatus, error) {
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
		return HubShareStatus{}, fmt.Errorf("single-file share %q accepts only the mask VCS policy, not %q", name, nextPolicy)
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
		if (st.Mode & syscall.S_IFMT) != syscall.S_IFREG {
			h.mu.Unlock()
			return HubShareStatus{}, fmt.Errorf("share %q is not a regular file", slot.hostPath)
		}
		if st.Nlink != 1 {
			h.mu.Unlock()
			return HubShareStatus{}, fmt.Errorf("refusing writable single-file share with multiple hard links (nlink=%d): %s", st.Nlink, slot.hostPath)
		}
	}

	prevPolicy := slot.getVCSPolicy()
	downgradingToRO := !slot.isReadOnly() && nextRO
	downgradingPolicy := !slot.isFile && isVCSPolicyMoreRestrictive(prevPolicy, nextPolicy)
	if downgradingToRO {
		if openW := slot.openWritableCount(); openW > 0 && !force {
			h.mu.Unlock()
			return HubShareStatus{}, openWritableHandlesError(name, openW)
		}
	} else if downgradingPolicy {
		if nextPolicy == config.VCSMask {
			if openW := slot.openWritableVCSCount(); openW > 0 && !force {
				h.mu.Unlock()
				return HubShareStatus{}, openWritableHandlesError(name, openW)
			}
		} else if nextPolicy == config.VCSAllow {
			if openW := slot.openWritableHookCount(); openW > 0 && !force {
				h.mu.Unlock()
				return HubShareStatus{}, openWritableHandlesError(name, openW)
			}
		}
	}

	slot.setReadOnly(nextRO)
	slot.setVCSPolicy(nextPolicy)
	if downgradingPolicy {
		if nextPolicy == config.VCSMask {
			slot.revokeVCSDescriptors(syscall.ESTALE)
		} else if nextPolicy == config.VCSAllow {
			slot.revokeWritableHookFiles(syscall.EROFS)
		}
	}
	if downgradingToRO {
		slot.revokeWritableFiles(syscall.EROFS)
	}

	status := slotToStatus(slot)
	h.mu.Unlock()

	if h.mounted.Load() {
		h.invalidateSlotKernelCache(slot)
	}
	return status, nil
}

func (h *WorkspaceHub) invalidateSlotKernelCache(slot *shareSlot) {
	if slot == nil {
		return
	}
	if h.mounted.Load() {
		_ = h.NotifyEntry(slot.guestName)
	}
	slot.inodeMu.RLock()
	ch := slot.inode
	slot.inodeMu.RUnlock()
	if ch == nil {
		return
	}
	_ = ch.NotifyContent(0, 0)
	maskNow := slot.getVCSPolicy() == config.VCSMask
	for _, vcsName := range defaultHiddenEntries() {
		if maskNow {
			ch.RmChild(vcsName)
		}
		_ = ch.NotifyEntry(vcsName)
	}
	invalidateInodeSubtree(ch, slot.hidden, maskNow)
}

func invalidateInodeSubtree(parent *fs.Inode, hidden map[string]struct{}, maskVCS bool) {
	if parent == nil {
		return
	}
	for childName, childIno := range parent.Children() {
		if maskVCS && isHiddenEntry(childName, hidden) {
			if childIno != nil {
				childIno.RmAllChildren()
				parent.RmChild(childName)
				_ = parent.NotifyDelete(childName, childIno)
			}
			_ = parent.NotifyEntry(childName)
			continue
		}
		_ = parent.NotifyEntry(childName)
		if childIno != nil {
			_ = childIno.NotifyContent(0, 0)
			if childIno.IsDir() {
				invalidateInodeSubtree(childIno, hidden, maskVCS)
			}
		}
	}
}

func (h *WorkspaceHub) removeShare(name string, force bool) error {
	h.mu.Lock()
	slot, ok := h.slots[name]
	if !ok || slot.isRevoked() {
		h.mu.Unlock()
		return fmt.Errorf("share %q is not mounted in /workspace", name)
	}
	if openW := slot.openWritableCount(); openW > 0 && !force {
		h.mu.Unlock()
		return openWritableHandlesError(name, openW)
	}
	delete(h.slots, name)
	slot.inodeMu.RLock()
	ch := slot.inode
	slot.inodeMu.RUnlock()
	mounted := h.mounted.Load()
	if mounted && ch != nil && h.GetChild(name) == ch {
		h.RmChild(name)
	}
	h.mu.Unlock()

	slot.revokeAll(syscall.ESTALE)

	if mounted {
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
	h.idMap.applyAttr(attr)
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
	slot.idMap.applyAttr(&out.Attr)
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
		ops = &fileShareNode{slot: slot}
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
		if ino == 0 {
			rootDev := uint64(0)
			if slot.root != nil {
				rootDev = slot.root.dev
			}
			ino = computeStableIno(slot.slotID, rootDev, slot.initDev, slot.initIno)
		}
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

func (h *WorkspaceHub) Getxattr(ctx context.Context, attr string, dest []byte) (uint32, syscall.Errno) {
	_, _, _ = ctx, attr, dest
	return 0, unix.ENODATA
}

func (h *WorkspaceHub) Listxattr(ctx context.Context, dest []byte) (uint32, syscall.Errno) {
	_, _ = ctx, dest
	return 0, 0
}

func (h *WorkspaceHub) Setxattr(ctx context.Context, attr string, data []byte, flags uint32) syscall.Errno {
	_, _, _, _ = ctx, attr, data, flags
	return syscall.EROFS
}

func (h *WorkspaceHub) Removexattr(ctx context.Context, attr string) syscall.Errno {
	_, _ = ctx, attr
	return syscall.EROFS
}

func mountWorkspaceHubWithOptions(mntDir, sockPath string, initial []HubShareConfig, opts HubOptions) (*WorkspaceHub, *fuse.Server, io.Closer, error) {
	if mntDir == "" {
		return nil, nil, nil, errors.New("workspace hub mount directory must not be empty")
	}
	hub, err := NewWorkspaceHubWithOptions(initial, opts)
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
	fuseOpts := &fs.Options{
		AttrTimeout:  &ttl,
		EntryTimeout: &ttl,
		MountOptions: fuse.MountOptions{
			FsName:      "agbox-workspace-hub",
			Name:        "agboxhub",
			Options:     []string{"nosuid", "nodev"},
			DirectMount: hub.euid == 0,
		},
	}

	server, err := fs.Mount(mntDir, hub, fuseOpts)
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
	if sockPath == "" {
		return nil, errors.New("hub socket path must not be empty")
	}
	if err := config.EnsurePrivateDir(filepath.Dir(sockPath)); err != nil {
		return nil, fmt.Errorf("prepare hub socket dir: %w", err)
	}
	if info, err := os.Lstat(sockPath); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("refusing to remove non-socket path %q", sockPath)
		}
		if pingHub(sockPath) == nil {
			return nil, fmt.Errorf("hub socket %q is already active", sockPath)
		}
		if rErr := os.Remove(sockPath); rErr != nil && !os.IsNotExist(rErr) {
			return nil, fmt.Errorf("remove stale hub socket %q: %w", sockPath, rErr)
		}
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("stat hub socket %q: %w", sockPath, err)
	}

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
	if hub != nil {
		expectedUID = hub.euid
	}
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
	raw, err := io.ReadAll(io.LimitReader(conn, maxHubControlBytes+1))
	if err != nil || len(raw) > maxHubControlBytes {
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
		resp = hubControlResponse{OK: true, Shares: hub.listShares()}
	case "add":
		if req.Add == nil {
			resp = hubControlResponse{OK: false, Error: "missing share configuration"}
			break
		}
		st, aErr := hub.addShare(*req.Add)
		if aErr != nil {
			resp = hubControlResponse{OK: false, Error: aErr.Error()}
			break
		}
		resp = hubControlResponse{OK: true, Share: &st}
	case "set":
		st, sErr := hub.setShare(req.Name, req.ReadOnly, req.VCSPolicy, req.Force)
		if sErr != nil {
			resp = hubControlResponse{OK: false, Error: sErr.Error()}
			break
		}
		resp = hubControlResponse{OK: true, Share: &st}
	case "rm":
		if rErr := hub.removeShare(req.Name, req.Force); rErr != nil {
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
	HomeReal         string           `json:"home_real,omitempty"`
	DataDir          string           `json:"data_dir,omitempty"`
	MSBHome          string           `json:"msb_home,omitempty"`
	AllowOutsideHome bool             `json:"allow_outside_home,omitempty"`
	MapGuestIDs      bool             `json:"map_guest_ids,omitempty"`
	GuestUID         uint32           `json:"guest_uid"`
	GuestGID         uint32           `json:"guest_gid"`
	Shares           []HubShareConfig `json:"shares"`
}

func readBoundedRegularFileNoFollow(path string, maxBytes int64) ([]byte, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("refusing non-regular hub spec file %q", path)
	}
	raw, err := io.ReadAll(io.LimitReader(f, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > maxBytes {
		return nil, fmt.Errorf("hub spec file %q exceeds %d bytes", path, maxBytes)
	}
	return raw, nil
}

func decodeHubBootstrapSpec(mntDir, sockPath string, specFD int, specFile string) (hubBootstrapSpec, error) {
	if mntDir == "" || sockPath == "" {
		return hubBootstrapSpec{}, errors.New("mountpoint and socket path must not be empty")
	}
	if specFD >= 0 && specFile != "" {
		return hubBootstrapSpec{}, errors.New("specify at most one of -spec-fd or -spec")
	}

	spec := hubBootstrapSpec{
		GuestUID: config.GuestUID,
		GuestGID: config.GuestGID,
	}
	if specFD >= 0 {
		if specFD <= 2 {
			return hubBootstrapSpec{}, fmt.Errorf("invalid -spec-fd %d: must be greater than 2", specFD)
		}
		f := os.NewFile(uintptr(specFD), "hub-spec-fd")
		raw, err := io.ReadAll(io.LimitReader(f, maxHubControlBytes+1))
		_ = f.Close()
		if err != nil {
			return hubBootstrapSpec{}, fmt.Errorf("read hub spec from fd %d: %w", specFD, err)
		}
		if len(raw) > maxHubControlBytes {
			return hubBootstrapSpec{}, fmt.Errorf("hub spec on fd %d exceeds %d bytes", specFD, maxHubControlBytes)
		}
		if len(bytes.TrimSpace(raw)) > 0 {
			if err := json.Unmarshal(raw, &spec); err != nil {
				return hubBootstrapSpec{}, fmt.Errorf("parse hub bootstrap spec: %w", err)
			}
		}
	} else if specFile != "" {
		raw, err := readBoundedRegularFileNoFollow(specFile, maxHubControlBytes)
		if err != nil {
			return hubBootstrapSpec{}, fmt.Errorf("read hub spec file: %w", err)
		}
		if len(bytes.TrimSpace(raw)) > 0 {
			if err := json.Unmarshal(raw, &spec); err != nil {
				return hubBootstrapSpec{}, fmt.Errorf("parse hub spec file: %w", err)
			}
		}
	}
	return spec, nil
}

func runHubDaemonFromFlags(mntDir, sockPath string, specFD int, specFile string) error {
	spec, err := decodeHubBootstrapSpec(mntDir, sockPath, specFD, specFile)
	if err != nil {
		return err
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	defer signal.Stop(sigCh)

	hub, server, ln, err := mountWorkspaceHubWithOptions(mntDir, sockPath, spec.Shares, HubOptions{
		HomeReal:         spec.HomeReal,
		DataDir:          spec.DataDir,
		MSBHome:          spec.MSBHome,
		AllowOutsideHome: spec.AllowOutsideHome,
		MapGuestIDs:      spec.MapGuestIDs,
		GuestUID:         spec.GuestUID,
		GuestGID:         spec.GuestGID,
	})
	if err != nil {
		return err
	}
	defer func() {
		if ln != nil {
			_ = ln.Close()
		}
		hub.CloseAll()
	}()

	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-sigCh:
			if ln != nil {
				_ = ln.Close()
			}
			_ = server.Unmount()
		case <-done:
		}
	}()

	server.Wait()
	return nil
}

// StartHubSubprocessWithOptions starts `exePath __filter -hub -mnt <mntDir> -sock <sockPath> -spec-fd 3`
// as a background child process, writes its PID to pidFile, and waits until ready.
func StartHubSubprocessWithOptions(exePath, mntDir, sockPath, pidFile string, initial []HubShareConfig, opts HubOptions, dieWithParent bool) (int, error) {
	if err := config.EnsurePrivateDir(mntDir); err != nil {
		return 0, fmt.Errorf("prepare hub mountpoint %q: %w", mntDir, err)
	}
	if err := config.EnsurePrivateDir(filepath.Dir(sockPath)); err != nil {
		return 0, fmt.Errorf("prepare hub socket directory: %w", err)
	}
	if err := config.EnsurePrivateDir(filepath.Dir(pidFile)); err != nil {
		return 0, fmt.Errorf("prepare hub pidfile directory: %w", err)
	}

	guestUID := opts.GuestUID
	guestGID := opts.GuestGID
	if !opts.MapGuestIDs && guestUID == 0 && guestGID == 0 {
		guestUID = config.GuestUID
		guestGID = config.GuestGID
	}
	specBytes, err := json.Marshal(hubBootstrapSpec{
		HomeReal:         opts.HomeReal,
		DataDir:          opts.DataDir,
		MSBHome:          opts.MSBHome,
		AllowOutsideHome: opts.AllowOutsideHome,
		MapGuestIDs:      opts.MapGuestIDs,
		GuestUID:         guestUID,
		GuestGID:         guestGID,
		Shares:           initial,
	})
	if err != nil {
		return 0, fmt.Errorf("marshal hub bootstrap spec: %w", err)
	}
	if len(specBytes) > maxHubControlBytes {
		return 0, fmt.Errorf("initial share list exceeds the %d-byte hub spec limit", maxHubControlBytes)
	}

	args := []string{SubcommandName, "-hub", "-mnt", mntDir, "-sock", sockPath, "-spec-fd", "3"}
	return launchFilterDaemon(daemonLaunchConfig{
		exePath:       exePath,
		args:          args,
		mntDir:        mntDir,
		pidFile:       pidFile,
		pipePayload:   specBytes,
		dieWithParent: dieWithParent,
		label:         "FUSE hub",
		readyCheck: func() bool {
			mounted, mErr := mounttab.IsPathMounted(mntDir)
			return mErr == nil && mounted && pingHub(sockPath) == nil
		},
	})
}

const defaultHubControlTimeout = 10 * time.Second

func callHubSocket(sockPath string, req hubControlRequest) (hubControlResponse, error) {
	return callHubSocketWithUIDAndTimeout(sockPath, req, uint32(os.Geteuid()), defaultHubControlTimeout)
}

func callHubSocketWithUID(sockPath string, req hubControlRequest, expectedUID uint32) (hubControlResponse, error) {
	return callHubSocketWithUIDAndTimeout(sockPath, req, expectedUID, defaultHubControlTimeout)
}

func callHubSocketWithUIDAndTimeout(sockPath string, req hubControlRequest, expectedUID uint32, timeout time.Duration) (hubControlResponse, error) {
	if timeout <= 0 {
		timeout = defaultHubControlTimeout
	}
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

	rawConn, err := net.DialTimeout("unix", sockPath, timeout)
	if err != nil {
		return hubControlResponse{}, fmt.Errorf("connect to workspace hub socket %q: %w", sockPath, err)
	}
	conn, ok := rawConn.(*net.UnixConn)
	if !ok {
		_ = rawConn.Close()
		return hubControlResponse{}, fmt.Errorf("unexpected connection type for workspace hub socket %q", sockPath)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	if err := verifyPeerUID(conn, expectedUID); err != nil {
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

	raw, err := io.ReadAll(io.LimitReader(conn, maxHubControlBytes+1))
	if err != nil {
		return hubControlResponse{}, err
	}
	if len(raw) > maxHubControlBytes {
		return hubControlResponse{}, errors.New("workspace hub response exceeds size limit")
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

// pingHub checks whether the Workspace Hub control socket at sockPath responds.
func pingHub(sockPath string) error {
	_, err := callHubSocket(sockPath, hubControlRequest{Op: "ping"})
	return err
}

// ListHubShares queries all active shares from a running Workspace Hub.
func ListHubShares(sockPath string) ([]HubShareStatus, error) {
	return ListHubSharesWithTimeout(sockPath, defaultHubControlTimeout)
}

// ListHubSharesWithTimeout queries all active shares from a running Workspace Hub
// with a bounded connection and read timeout.
func ListHubSharesWithTimeout(sockPath string, timeout time.Duration) ([]HubShareStatus, error) {
	resp, err := callHubSocketWithUIDAndTimeout(sockPath, hubControlRequest{Op: "list"}, uint32(os.Geteuid()), timeout)
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
