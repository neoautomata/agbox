// Package remotebridge serves the per-sandbox in-memory FUSE virtual bridge
// and host Unix control socket for agbox remote command execution.
//
// Security properties:
//   - The virtual filesystem stays entirely in memory with zero host disk writes.
//   - Create enforces max 4 total slots across all states, a 16 MiB memory ceiling,
//     and a per-bridge submission rate limit.
//   - Write enforces sequential bounds up to 512 KiB and blocks symlinks, mkdir,
//     mknod, link, rename, xattrs, and ioctl with EPERM.
//   - Unlink and TTL eviction revoke open file handles at once and release memory
//     so subsequent reads or writes return ESTALE.
//   - bin/agbox-remote is served from a pinned /proc/self/exe FD verified as a static ELF.
//   - remote.sock enforces mode 0600 inside a 0700 directory and mutual SO_PEERCRED UID checks.
package remotebridge

import (
	"bytes"
	"context"
	"crypto/rand"
	"debug/elf"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"agbox/internal/config"
	"agbox/internal/remoteproto"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"
	"golang.org/x/sys/unix"
)

const (
	// GuestMountPath is the guest mountpoint for the remote command bridge.
	GuestMountPath = "/home/agent/.agbox-remote"

	// GuestBinPath is the read-only guest binary path inside the bridge mount.
	GuestBinPath = "/home/agent/.agbox-remote/bin/agbox-remote"

	// GuestInstructionsPath is the read-only guest instructions path inside the bridge mount.
	GuestInstructionsPath = "/home/agent/.agbox-remote/INSTRUCTIONS.md"

	// GuestClientName is the argv[0] basename installed at /usr/local/bin/agbox-remote.
	GuestClientName = "agbox-remote"

	// GuestSubcommandName is the hidden CLI subcommand that invokes the guest client.
	GuestSubcommandName = "__guest-remote"

	// MaxSlots bounds concurrent slots across draft, pending, and completed states.
	MaxSlots = 4

	// MaxTotalBytes bounds total heap bytes held across all active bridge slots.
	MaxTotalBytes = 16 * 1024 * 1024

	// DefaultDraftTTL evicts unclosed draft requests after 30 seconds.
	DefaultDraftTTL = 30 * time.Second

	// DefaultDoneTTL evicts unread completed responses after 60 seconds.
	DefaultDoneTTL = 60 * time.Second

	defaultRatePerSec = 5.0
	defaultRateBurst  = 10.0

	defaultJitterMin = 10 * time.Millisecond
	defaultJitterMax = 50 * time.Millisecond

	brokerSendQueueCap  = 32
	brokerWriteDeadline = 5 * time.Second
)

// InstructionsMarkdown is exposed read-only inside the guest at INSTRUCTIONS.md
// and merged into AGENTS.md when remote execution is enabled.
const InstructionsMarkdown = `# Remote Command Execution (agbox-remote)

Use ` + "`agbox-remote`" + ` to run a command on a pre-connected remote machine.

## Rules

- Pass the executable and arguments directly. Do not use shell pipes, redirects, or shell expansion.
- Syntax: ` + "`agbox-remote [--cwd <ABS_DIR>] [--exec-timeout <DUR>] [--reason \"<TEXT>\"] [--stdin | --stdin-file <PATH>] [--] <EXECUTABLE> [ARG...]`" + `.
- Pass an absolute remote path to ` + "`--cwd <ABS_DIR>`" + `.
- Use ` + "`--stdin-file <PATH>`" + ` instead of ` + "`--stdin`" + ` when you send input.
- Never pass ` + "`--stdin`" + ` without a pipe, heredoc, or input redirect.
- Keep stdin at 256 KiB or less. ` + "`agbox-remote`" + ` exits with code 2 when stdin exceeds 256 KiB.
- ` + "`agbox-remote`" + ` can wait for human review on the host. Set your command timeout to at least 300 seconds.
- Exit code 126 (` + "`agbox-remote: command denied`" + `) means the host denied the request or no broker attached.
- Exit code 126 can also include an operator note on stderr. Read that note and ask the user instead of retrying.
- Exit code 124 means an approved command exceeded its timeout on the remote machine.
- Exit code 2 means a local ` + "`agbox-remote`" + ` flag or input error.
`

// Options configures a Bridge instance.
type Options struct {
	MountDir         string
	SockPath         string
	GuestUID         uint32
	GuestGID         uint32
	ClientExePath    string
	ClientReader     io.ReaderAt
	ClientSize       int64
	RequireStaticELF bool
	DenyJitterMin    time.Duration
	DenyJitterMax    time.Duration
	DraftTTL         time.Duration
	DoneTTL          time.Duration
	RatePerSec       float64
	RateBurst        float64
	Now              func() time.Time
}

type slotState int

const (
	slotDraft slotState = iota
	slotPending
	slotDone
)

type reqSlot struct {
	id        string
	ino       uint64
	doneIno   uint64
	respIno   uint64
	state     slotState
	createdAt time.Time
	doneAt    time.Time
	reqBuf    []byte
	respBuf   []byte
	revoked   bool

	reqHandles  map[*reqFileHandle]struct{}
	respHandles map[*respFileHandle]struct{}
}

type brokerSession struct {
	conn     *net.UnixConn
	peer     string
	remoteID string
	policy   string
	sendCh   chan remoteproto.BridgeMessage
	closed   chan struct{}
	closeOne sync.Once
}

func (s *brokerSession) close() {
	s.closeOne.Do(func() {
		close(s.closed)
		_ = s.conn.Close()
	})
}

func (s *brokerSession) enqueue(msg remoteproto.BridgeMessage) bool {
	select {
	case <-s.closed:
		return false
	default:
	}
	select {
	case s.sendCh <- msg:
		return true
	default:
		return false
	}
}

// Bridge manages the in-memory FUSE state machine and host remote.sock listener.
type Bridge struct {
	opts       Options
	clientFile *os.File
	clientRdr  io.ReaderAt
	clientSize int64
	instrBytes []byte

	mu         sync.Mutex
	slots      map[string]*reqSlot
	totalBytes int64
	doneMtime  time.Time
	respMtime  time.Time
	tokens     float64
	lastRefill time.Time
	broker     *brokerSession

	nextIno atomic.Uint64
	stopCh  chan struct{}
	stopOne sync.Once
	wg      sync.WaitGroup

	fuseSrv  *fuse.Server
	listener *net.UnixListener
}

// CheckStaticELF verifies that r is a valid static Linux ELF binary (PT_INTERP absent).
func CheckStaticELF(r io.ReaderAt) error {
	f, err := elf.NewFile(r)
	if err != nil {
		return fmt.Errorf("invalid ELF binary for remote bridge: %w", err)
	}
	defer f.Close()
	for _, p := range f.Progs {
		if p.Type == elf.PT_INTERP {
			return errors.New("remote bridge requires a static agbox binary. Rebuild with 'CGO_ENABLED=0 go build ./cmd/agbox' or pass --no-remote")
		}
	}
	return nil
}

// New initializes a Bridge, pinning the client binary FD and verifying static ELF when required.
func New(opts Options) (*Bridge, error) {
	if opts.GuestUID == 0 {
		opts.GuestUID = config.GuestUID
	}
	if opts.GuestGID == 0 {
		opts.GuestGID = config.GuestGID
	}
	if opts.DraftTTL <= 0 {
		opts.DraftTTL = DefaultDraftTTL
	}
	if opts.DoneTTL <= 0 {
		opts.DoneTTL = DefaultDoneTTL
	}
	if opts.RatePerSec <= 0 {
		opts.RatePerSec = defaultRatePerSec
	}
	if opts.RateBurst <= 0 {
		opts.RateBurst = defaultRateBurst
	}
	if opts.DenyJitterMin == 0 && opts.DenyJitterMax == 0 {
		opts.DenyJitterMin = defaultJitterMin
		opts.DenyJitterMax = defaultJitterMax
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}

	var (
		clientFile *os.File
		clientRdr  io.ReaderAt
		clientSize int64
	)
	if opts.ClientReader != nil {
		clientRdr = opts.ClientReader
		clientSize = opts.ClientSize
		if opts.RequireStaticELF {
			if err := CheckStaticELF(clientRdr); err != nil {
				return nil, err
			}
		}
	} else {
		exePath := opts.ClientExePath
		if exePath == "" {
			exePath = "/proc/self/exe"
		}
		f, err := os.Open(exePath)
		if err != nil {
			return nil, fmt.Errorf("open bridge client binary %s: %w", exePath, err)
		}
		st, err := f.Stat()
		if err != nil {
			_ = f.Close()
			return nil, fmt.Errorf("stat bridge client binary %s: %w", exePath, err)
		}
		if !st.Mode().IsRegular() || st.Size() <= 0 {
			_ = f.Close()
			return nil, fmt.Errorf("bridge client binary %s is not a non-empty regular file", exePath)
		}
		if opts.RequireStaticELF {
			if err := CheckStaticELF(f); err != nil {
				_ = f.Close()
				return nil, err
			}
		}
		clientFile = f
		clientRdr = f
		clientSize = st.Size()
	}

	now := opts.Now()
	b := &Bridge{
		opts:       opts,
		clientFile: clientFile,
		clientRdr:  clientRdr,
		clientSize: clientSize,
		instrBytes: []byte(InstructionsMarkdown),
		slots:      make(map[string]*reqSlot),
		doneMtime:  now,
		respMtime:  now,
		tokens:     opts.RateBurst,
		lastRefill: now,
		stopCh:     make(chan struct{}),
	}
	b.nextIno.Store(100)
	return b, nil
}

// Mount mounts the FUSE virtual bridge at opts.MountDir and binds opts.SockPath.
func (b *Bridge) Mount() error {
	if b.opts.MountDir == "" {
		return errors.New("bridge mount directory must not be empty")
	}
	if b.opts.SockPath == "" {
		return errors.New("bridge control socket path must not be empty")
	}

	if err := b.startControlSocket(); err != nil {
		return err
	}

	root := &bridgeRootNode{b: b}
	zeroTimeout := time.Duration(0)
	sec := &fs.Options{
		MountOptions: fuse.MountOptions{
			Name:          "agbox-remote",
			FsName:        "agbox-remote",
			DisableXAttrs: true,
			Options:       []string{"nosuid", "nodev"},
			DirectMount:   os.Geteuid() == 0,
		},
		EntryTimeout:    &zeroTimeout,
		AttrTimeout:     &zeroTimeout,
		NegativeTimeout: &zeroTimeout,
		UID:             b.opts.GuestUID,
		GID:             b.opts.GuestGID,
	}

	srv, err := fs.Mount(b.opts.MountDir, root, sec)
	if err != nil {
		b.closeControlSocket()
		return fmt.Errorf("mount remote FUSE bridge at %s: %w", b.opts.MountDir, err)
	}
	b.fuseSrv = srv

	b.wg.Add(1)
	go b.reaperLoop()
	return nil
}

// Close unmounts the FUSE bridge, closes remote.sock, stops background goroutines, and closes the pinned FD.
func (b *Bridge) Close() error {
	var firstErr error
	b.stopOne.Do(func() {
		close(b.stopCh)
		b.closeControlSocket()
		if b.fuseSrv != nil {
			if err := b.fuseSrv.Unmount(); err != nil {
				firstErr = err
			}
		}
		b.wg.Wait()
		if b.clientFile != nil {
			_ = b.clientFile.Close()
			b.clientFile = nil
		}
	})
	return firstErr
}

// Wait blocks until the FUSE server exits.
func (b *Bridge) Wait() {
	if b.fuseSrv != nil {
		b.fuseSrv.Wait()
	}
}

func (b *Bridge) reaperLoop() {
	defer b.wg.Done()
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-b.stopCh:
			return
		case <-ticker.C:
			b.ReapExpired(b.opts.Now())
		}
	}
}

// ReapExpired revokes and removes stale draft and unread completed slots.
func (b *Bridge) ReapExpired(now time.Time) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for id, sl := range b.slots {
		switch sl.state {
		case slotDraft:
			if now.Sub(sl.createdAt) >= b.opts.DraftTTL {
				b.deleteSlotLocked(id, sl)
			}
		case slotDone:
			if now.Sub(sl.doneAt) >= b.opts.DoneTTL {
				b.deleteSlotLocked(id, sl)
			}
		}
	}
}

func (b *Bridge) bumpDirMtimesLocked() {
	now := b.opts.Now()
	if !now.After(b.doneMtime) {
		now = b.doneMtime.Add(time.Nanosecond)
	}
	b.doneMtime = now
	b.respMtime = now
}

func (b *Bridge) takeRateTokenLocked(now time.Time) bool {
	if now.After(b.lastRefill) {
		elapsed := now.Sub(b.lastRefill).Seconds()
		b.tokens += elapsed * b.opts.RatePerSec
		if b.tokens > b.opts.RateBurst {
			b.tokens = b.opts.RateBurst
		}
		b.lastRefill = now
	}
	if b.tokens < 1.0 {
		return false
	}
	b.tokens -= 1.0
	return true
}

func isValidSlotID(id string) bool {
	if len(id) != 32 {
		return false
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

func (b *Bridge) createSlot(id string) (*reqSlot, *reqFileHandle, syscall.Errno) {
	if !isValidSlotID(id) {
		return nil, nil, syscall.EINVAL
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	now := b.opts.Now()
	if _, exists := b.slots[id]; exists {
		return nil, nil, syscall.EEXIST
	}
	if len(b.slots) >= MaxSlots {
		return nil, nil, syscall.EAGAIN
	}
	if b.totalBytes >= MaxTotalBytes {
		return nil, nil, syscall.ENOSPC
	}
	if !b.takeRateTokenLocked(now) {
		return nil, nil, syscall.EAGAIN
	}
	sl := &reqSlot{
		id:          id,
		ino:         b.nextIno.Add(1),
		doneIno:     b.nextIno.Add(1),
		respIno:     b.nextIno.Add(1),
		state:       slotDraft,
		createdAt:   now,
		reqHandles:  make(map[*reqFileHandle]struct{}),
		respHandles: make(map[*respFileHandle]struct{}),
	}
	fh := &reqFileHandle{b: b, slot: sl}
	sl.reqHandles[fh] = struct{}{}
	b.slots[id] = sl
	return sl, fh, 0
}

func (b *Bridge) writeSlot(h *reqFileHandle, data []byte, off int64) (uint32, syscall.Errno) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if h.revoked || h.slot == nil || h.slot.revoked {
		return 0, syscall.ESTALE
	}
	sl := h.slot
	if sl.state != slotDraft {
		return 0, syscall.EROFS
	}
	if off < 0 || off != int64(len(sl.reqBuf)) {
		return 0, syscall.EINVAL
	}
	if int64(len(sl.reqBuf))+int64(len(data)) > remoteproto.MaxBridgeReqBytes {
		return 0, syscall.EFBIG
	}
	if b.totalBytes+int64(len(data)) > MaxTotalBytes {
		return 0, syscall.ENOSPC
	}
	sl.reqBuf = append(sl.reqBuf, data...)
	b.totalBytes += int64(len(data))
	return uint32(len(data)), 0
}

func decodeGuestRequest(rawReq []byte) (remoteproto.GuestRequest, bool) {
	var greq remoteproto.GuestRequest
	if err := remoteproto.DecodeStrict(rawReq, &greq); err != nil || greq.Executable == "" {
		return remoteproto.GuestRequest{}, false
	}
	if greq.StdinB64 != "" {
		decoded, err := base64.StdEncoding.DecodeString(greq.StdinB64)
		if err != nil || len(decoded) > remoteproto.MaxStdinBytes {
			return remoteproto.GuestRequest{}, false
		}
	}
	return greq, true
}

func (b *Bridge) flushSlot(h *reqFileHandle) syscall.Errno {
	b.mu.Lock()
	if h.revoked || h.slot == nil || h.slot.revoked {
		b.mu.Unlock()
		return syscall.ESTALE
	}
	sl := h.slot
	// Subsequent Flush calls from dup()ed FDs are idempotent no-ops.
	if sl.state != slotDraft {
		b.mu.Unlock()
		return 0
	}
	rawReq := sl.reqBuf
	// Release request buffer memory immediately once copied for dispatch.
	b.totalBytes -= int64(len(sl.reqBuf))
	sl.reqBuf = nil
	sl.state = slotPending
	slotID := sl.id

	greq, valid := decodeGuestRequest(rawReq)
	if !valid || b.broker == nil {
		b.mu.Unlock()
		b.scheduleJitteredDeny(slotID)
		return 0
	}
	msg := remoteproto.BridgeMessage{
		Op:      "req",
		SlotID:  slotID,
		Request: &greq,
	}
	// Enqueue while holding b.mu so req always precedes any subsequent cancel frame.
	if !b.broker.enqueue(msg) {
		stalled := b.broker
		b.broker = nil
		b.denyAllPendingLocked()
		b.mu.Unlock()
		stalled.close()
		return 0
	}
	b.mu.Unlock()
	return 0
}

func (b *Bridge) scheduleJitteredDeny(slotID string) {
	delay := b.randomJitter()
	b.wg.Add(1)
	go func() {
		defer b.wg.Done()
		if delay > 0 {
			timer := time.NewTimer(delay)
			defer timer.Stop()
			select {
			case <-b.stopCh:
				return
			case <-timer.C:
			}
		}
		b.CompleteSlot(slotID, remoteproto.DeniedResponse(slotID, ""))
	}()
}

func (b *Bridge) randomJitter() time.Duration {
	if b.opts.DenyJitterMax <= b.opts.DenyJitterMin {
		return b.opts.DenyJitterMin
	}
	span := uint64(b.opts.DenyJitterMax - b.opts.DenyJitterMin)
	var rb [8]byte
	if _, err := rand.Read(rb[:]); err != nil {
		return b.opts.DenyJitterMin
	}
	return b.opts.DenyJitterMin + time.Duration(binary.BigEndian.Uint64(rb[:])%span)
}

// CompleteSlot transitions a pending slot into the write-once completed state.
func (b *Bridge) CompleteSlot(slotID string, resp remoteproto.ExecResponse) {
	raw, err := json.Marshal(resp)
	if err != nil {
		raw, _ = json.Marshal(remoteproto.DeniedResponse(slotID, ""))
	}

	b.mu.Lock()
	defer b.mu.Unlock()
	sl, ok := b.slots[slotID]
	if !ok || sl.revoked || sl.state != slotPending {
		return
	}
	if b.totalBytes+int64(len(raw)) > MaxTotalBytes {
		raw, _ = json.Marshal(remoteproto.DeniedResponse(slotID, ""))
	}
	sl.respBuf = raw
	b.totalBytes += int64(len(raw))
	sl.state = slotDone
	sl.doneAt = b.opts.Now()
	b.bumpDirMtimesLocked()
}

func (b *Bridge) unlinkSlot(id string) syscall.Errno {
	if !isValidSlotID(id) {
		return syscall.ENOENT
	}
	b.mu.Lock()
	sl, ok := b.slots[id]
	if !ok {
		b.mu.Unlock()
		return syscall.ENOENT
	}
	wasPending := sl.state == slotPending
	b.deleteSlotLocked(id, sl)
	var stalled *brokerSession
	if wasPending && b.broker != nil {
		// Enqueue cancel while holding b.mu to preserve strict req-before-cancel ordering.
		if !b.broker.enqueue(remoteproto.BridgeMessage{
			Op:     "cancel",
			SlotID: id,
		}) {
			stalled = b.broker
			b.broker = nil
			b.denyAllPendingLocked()
		}
	}
	b.mu.Unlock()
	if stalled != nil {
		stalled.close()
	}
	return 0
}

func (b *Bridge) deleteSlotLocked(id string, sl *reqSlot) {
	sl.revoked = true
	for h := range sl.reqHandles {
		h.revoked = true
		h.slot = nil
	}
	sl.reqHandles = nil
	for h := range sl.respHandles {
		h.revoked = true
		h.data = nil
		h.slot = nil
	}
	sl.respHandles = nil
	b.totalBytes -= int64(len(sl.reqBuf))
	b.totalBytes -= int64(len(sl.respBuf))
	if b.totalBytes < 0 {
		b.totalBytes = 0
	}
	sl.reqBuf = nil
	sl.respBuf = nil
	delete(b.slots, id)
	b.bumpDirMtimesLocked()
}

func (b *Bridge) denyAllPendingLocked() {
	for id, sl := range b.slots {
		if sl.state == slotPending && !sl.revoked {
			raw, _ := json.Marshal(remoteproto.DeniedResponse(id, ""))
			sl.respBuf = raw
			b.totalBytes += int64(len(raw))
			sl.state = slotDone
			sl.doneAt = b.opts.Now()
			b.bumpDirMtimesLocked()
		}
	}
}

// --- FUSE Node Implementations ---

type bridgeRootNode struct {
	fs.Inode
	b *Bridge
}

var _ = (fs.NodeGetattrer)((*bridgeRootNode)(nil))
var _ = (fs.NodeLookuper)((*bridgeRootNode)(nil))
var _ = (fs.NodeReaddirer)((*bridgeRootNode)(nil))

func (n *bridgeRootNode) Getattr(_ context.Context, _ fs.FileHandle, out *fuse.AttrOut) syscall.Errno {
	out.Mode = fuse.S_IFDIR | 0o555
	out.Uid = n.b.opts.GuestUID
	out.Gid = n.b.opts.GuestGID
	out.Nlink = 5
	out.SetTimeout(0)
	return 0
}

func (n *bridgeRootNode) Readdir(_ context.Context) (fs.DirStream, syscall.Errno) {
	return fs.NewListDirStream([]fuse.DirEntry{
		{Name: "bin", Mode: fuse.S_IFDIR, Ino: 2},
		{Name: "INSTRUCTIONS.md", Mode: fuse.S_IFREG, Ino: 3},
		{Name: "req", Mode: fuse.S_IFDIR, Ino: 4},
		{Name: "done", Mode: fuse.S_IFDIR, Ino: 5},
		{Name: "resp", Mode: fuse.S_IFDIR, Ino: 6},
	}), 0
}

func (n *bridgeRootNode) Lookup(ctx context.Context, name string, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	switch name {
	case "bin":
		child := &binDirNode{b: n.b}
		out.Attr.Mode = fuse.S_IFDIR | 0o555
		out.Attr.Uid = n.b.opts.GuestUID
		out.Attr.Gid = n.b.opts.GuestGID
		out.SetEntryTimeout(time.Hour)
		out.SetAttrTimeout(time.Hour)
		return n.NewInode(ctx, child, fs.StableAttr{Mode: fuse.S_IFDIR, Ino: 2}), 0
	case "INSTRUCTIONS.md":
		child := &staticFileNode{b: n.b, rdr: bytes.NewReader(n.b.instrBytes), size: int64(len(n.b.instrBytes)), mode: 0o444}
		out.Attr.Mode = fuse.S_IFREG | 0o444
		out.Attr.Size = uint64(len(n.b.instrBytes))
		out.Attr.Uid = n.b.opts.GuestUID
		out.Attr.Gid = n.b.opts.GuestGID
		out.SetEntryTimeout(time.Hour)
		out.SetAttrTimeout(time.Hour)
		return n.NewInode(ctx, child, fs.StableAttr{Mode: fuse.S_IFREG, Ino: 3}), 0
	case "req":
		child := &reqDirNode{b: n.b}
		out.Attr.Mode = fuse.S_IFDIR | 0o700
		out.Attr.Uid = n.b.opts.GuestUID
		out.Attr.Gid = n.b.opts.GuestGID
		out.SetEntryTimeout(0)
		out.SetAttrTimeout(0)
		return n.NewInode(ctx, child, fs.StableAttr{Mode: fuse.S_IFDIR, Ino: 4}), 0
	case "done":
		child := &doneDirNode{b: n.b}
		n.b.mu.Lock()
		mt := n.b.doneMtime
		n.b.mu.Unlock()
		out.Attr.Mode = fuse.S_IFDIR | 0o500
		out.Attr.Uid = n.b.opts.GuestUID
		out.Attr.Gid = n.b.opts.GuestGID
		out.Attr.SetTimes(nil, &mt, &mt)
		out.SetEntryTimeout(0)
		out.SetAttrTimeout(0)
		return n.NewInode(ctx, child, fs.StableAttr{Mode: fuse.S_IFDIR, Ino: 5}), 0
	case "resp":
		child := &respDirNode{b: n.b}
		n.b.mu.Lock()
		mt := n.b.respMtime
		n.b.mu.Unlock()
		out.Attr.Mode = fuse.S_IFDIR | 0o500
		out.Attr.Uid = n.b.opts.GuestUID
		out.Attr.Gid = n.b.opts.GuestGID
		out.Attr.SetTimes(nil, &mt, &mt)
		out.SetEntryTimeout(0)
		out.SetAttrTimeout(0)
		return n.NewInode(ctx, child, fs.StableAttr{Mode: fuse.S_IFDIR, Ino: 6}), 0
	default:
		out.SetEntryTimeout(0)
		return nil, syscall.ENOENT
	}
}

type binDirNode struct {
	fs.Inode
	b *Bridge
}

func (n *binDirNode) Getattr(_ context.Context, _ fs.FileHandle, out *fuse.AttrOut) syscall.Errno {
	out.Mode = fuse.S_IFDIR | 0o555
	out.Uid = n.b.opts.GuestUID
	out.Gid = n.b.opts.GuestGID
	out.Nlink = 2
	out.SetTimeout(time.Hour)
	return 0
}

func (n *binDirNode) Readdir(_ context.Context) (fs.DirStream, syscall.Errno) {
	return fs.NewListDirStream([]fuse.DirEntry{
		{Name: GuestClientName, Mode: fuse.S_IFREG, Ino: 7},
	}), 0
}

func (n *binDirNode) Lookup(ctx context.Context, name string, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	if name != GuestClientName {
		out.SetEntryTimeout(0)
		return nil, syscall.ENOENT
	}
	child := &staticFileNode{b: n.b, rdr: n.b.clientRdr, size: n.b.clientSize, mode: 0o555}
	out.Attr.Mode = fuse.S_IFREG | 0o555
	out.Attr.Size = uint64(n.b.clientSize)
	out.Attr.Uid = n.b.opts.GuestUID
	out.Attr.Gid = n.b.opts.GuestGID
	out.SetEntryTimeout(time.Hour)
	out.SetAttrTimeout(time.Hour)
	return n.NewInode(ctx, child, fs.StableAttr{Mode: fuse.S_IFREG, Ino: 7}), 0
}

type staticFileNode struct {
	fs.Inode
	b    *Bridge
	rdr  io.ReaderAt
	size int64
	mode uint32
}

func (n *staticFileNode) Getattr(_ context.Context, _ fs.FileHandle, out *fuse.AttrOut) syscall.Errno {
	out.Mode = fuse.S_IFREG | n.mode
	out.Size = uint64(n.size)
	out.Uid = n.b.opts.GuestUID
	out.Gid = n.b.opts.GuestGID
	out.Nlink = 1
	out.SetTimeout(time.Hour)
	return 0
}

func (n *staticFileNode) Open(_ context.Context, flags uint32) (fs.FileHandle, uint32, syscall.Errno) {
	if (flags & syscall.O_ACCMODE) != syscall.O_RDONLY {
		return nil, 0, syscall.EROFS
	}
	// FOPEN_KEEP_CACHE lets Linux execve() file-backed mmap work cleanly through virtiofs.
	return &staticFileHandle{rdr: n.rdr, size: n.size}, fuse.FOPEN_KEEP_CACHE, 0
}

type staticFileHandle struct {
	rdr  io.ReaderAt
	size int64
}

func (h *staticFileHandle) Read(_ context.Context, dest []byte, off int64) (fuse.ReadResult, syscall.Errno) {
	if off < 0 || off >= h.size {
		return fuse.ReadResultData(nil), 0
	}
	n, err := h.rdr.ReadAt(dest, off)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, syscall.EIO
	}
	return fuse.ReadResultData(dest[:n]), 0
}

// reqDirNode serves /home/agent/.agbox-remote/req/.
type reqDirNode struct {
	fs.Inode
	b *Bridge
}

func (n *reqDirNode) Getattr(_ context.Context, _ fs.FileHandle, out *fuse.AttrOut) syscall.Errno {
	out.Mode = fuse.S_IFDIR | 0o700
	out.Uid = n.b.opts.GuestUID
	out.Gid = n.b.opts.GuestGID
	out.Nlink = 2
	out.SetTimeout(0)
	return 0
}

func (n *reqDirNode) Readdir(_ context.Context) (fs.DirStream, syscall.Errno) {
	n.b.mu.Lock()
	entries := make([]fuse.DirEntry, 0, len(n.b.slots))
	for id, sl := range n.b.slots {
		entries = append(entries, fuse.DirEntry{Name: id, Mode: fuse.S_IFREG, Ino: sl.ino})
	}
	n.b.mu.Unlock()
	return fs.NewListDirStream(entries), 0
}

func (n *reqDirNode) Lookup(ctx context.Context, name string, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	out.SetEntryTimeout(0)
	out.SetAttrTimeout(0)
	n.b.mu.Lock()
	sl, ok := n.b.slots[name]
	var ino uint64
	if ok {
		ino = sl.ino
	}
	n.b.mu.Unlock()
	if !ok {
		return nil, syscall.ENOENT
	}
	child := &reqFileNode{b: n.b, id: name}
	out.Attr.Mode = fuse.S_IFREG | 0o200
	out.Attr.Uid = n.b.opts.GuestUID
	out.Attr.Gid = n.b.opts.GuestGID
	return n.NewInode(ctx, child, fs.StableAttr{Mode: fuse.S_IFREG, Ino: ino}), 0
}

func (n *reqDirNode) Create(ctx context.Context, name string, flags uint32, _ uint32, out *fuse.EntryOut) (*fs.Inode, fs.FileHandle, uint32, syscall.Errno) {
	out.SetEntryTimeout(0)
	out.SetAttrTimeout(0)
	accMode := flags & syscall.O_ACCMODE
	if accMode != syscall.O_WRONLY || (flags&syscall.O_APPEND) != 0 {
		return nil, nil, 0, syscall.EPERM
	}
	sl, fh, errno := n.b.createSlot(name)
	if errno != 0 {
		return nil, nil, 0, errno
	}

	child := &reqFileNode{b: n.b, id: name}
	out.Attr.Mode = fuse.S_IFREG | 0o200
	out.Attr.Uid = n.b.opts.GuestUID
	out.Attr.Gid = n.b.opts.GuestGID
	inode := n.NewInode(ctx, child, fs.StableAttr{Mode: fuse.S_IFREG, Ino: sl.ino})
	return inode, fh, fuse.FOPEN_DIRECT_IO, 0
}

func (n *reqDirNode) Unlink(_ context.Context, name string) syscall.Errno {
	return n.b.unlinkSlot(name)
}

func (n *reqDirNode) Mkdir(_ context.Context, _ string, _ uint32, _ *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	return nil, syscall.EPERM
}

func (n *reqDirNode) Symlink(_ context.Context, _, _ string, _ *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	return nil, syscall.EPERM
}

func (n *reqDirNode) Mknod(_ context.Context, _ string, _ uint32, _ uint32, _ *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	return nil, syscall.EPERM
}

func (n *reqDirNode) Link(_ context.Context, _ fs.InodeEmbedder, _ string, _ *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	return nil, syscall.EPERM
}

func (n *reqDirNode) Rename(_ context.Context, _ string, _ fs.InodeEmbedder, _ string, _ uint32) syscall.Errno {
	return syscall.EPERM
}

type reqFileNode struct {
	fs.Inode
	b  *Bridge
	id string
}

func (n *reqFileNode) Getattr(_ context.Context, _ fs.FileHandle, out *fuse.AttrOut) syscall.Errno {
	out.Mode = fuse.S_IFREG | 0o200
	out.Uid = n.b.opts.GuestUID
	out.Gid = n.b.opts.GuestGID
	out.SetTimeout(0)
	return 0
}

func (n *reqFileNode) Open(_ context.Context, _ uint32) (fs.FileHandle, uint32, syscall.Errno) {
	// Reject re-opening an existing req/<id> file.
	return nil, 0, syscall.EPERM
}

type reqFileHandle struct {
	b       *Bridge
	slot    *reqSlot
	revoked bool
}

func (h *reqFileHandle) Write(_ context.Context, data []byte, off int64) (uint32, syscall.Errno) {
	return h.b.writeSlot(h, data, off)
}

func (h *reqFileHandle) Flush(_ context.Context) syscall.Errno {
	return h.b.flushSlot(h)
}

func (h *reqFileHandle) Release(_ context.Context) syscall.Errno {
	h.b.mu.Lock()
	if h.slot != nil && h.slot.reqHandles != nil {
		delete(h.slot.reqHandles, h)
	}
	h.slot = nil
	h.b.mu.Unlock()
	return 0
}

// doneDirNode serves /home/agent/.agbox-remote/done/.
type doneDirNode struct {
	fs.Inode
	b *Bridge
}

func (n *doneDirNode) Getattr(_ context.Context, _ fs.FileHandle, out *fuse.AttrOut) syscall.Errno {
	n.b.mu.Lock()
	mt := n.b.doneMtime
	n.b.mu.Unlock()
	out.Mode = fuse.S_IFDIR | 0o500
	out.Uid = n.b.opts.GuestUID
	out.Gid = n.b.opts.GuestGID
	out.Nlink = 2
	out.SetTimes(nil, &mt, &mt)
	out.SetTimeout(0)
	return 0
}

func (n *doneDirNode) Readdir(_ context.Context) (fs.DirStream, syscall.Errno) {
	n.b.mu.Lock()
	entries := make([]fuse.DirEntry, 0, len(n.b.slots))
	for id, sl := range n.b.slots {
		if sl.state == slotDone && !sl.revoked {
			entries = append(entries, fuse.DirEntry{Name: id, Mode: fuse.S_IFREG, Ino: sl.doneIno})
		}
	}
	n.b.mu.Unlock()
	return fs.NewListDirStream(entries), 0
}

func (n *doneDirNode) Lookup(ctx context.Context, name string, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	out.SetEntryTimeout(0)
	out.SetAttrTimeout(0)
	n.b.mu.Lock()
	sl, ok := n.b.slots[name]
	ready := ok && sl.state == slotDone && !sl.revoked
	var ino uint64
	if ready {
		ino = sl.doneIno
	}
	n.b.mu.Unlock()
	if !ready {
		return nil, syscall.ENOENT
	}
	child := &doneFileNode{b: n.b, id: name}
	out.Attr.Mode = fuse.S_IFREG | 0o400
	out.Attr.Size = 0
	out.Attr.Uid = n.b.opts.GuestUID
	out.Attr.Gid = n.b.opts.GuestGID
	return n.NewInode(ctx, child, fs.StableAttr{Mode: fuse.S_IFREG, Ino: ino}), 0
}

type doneFileNode struct {
	fs.Inode
	b  *Bridge
	id string
}

func (n *doneFileNode) Getattr(_ context.Context, _ fs.FileHandle, out *fuse.AttrOut) syscall.Errno {
	n.b.mu.Lock()
	sl, ok := n.b.slots[n.id]
	ready := ok && sl.state == slotDone && !sl.revoked
	n.b.mu.Unlock()
	if !ready {
		return syscall.ESTALE
	}
	out.Mode = fuse.S_IFREG | 0o400
	out.Size = 0
	out.Uid = n.b.opts.GuestUID
	out.Gid = n.b.opts.GuestGID
	out.Nlink = 1
	out.SetTimeout(0)
	return 0
}

func (n *doneFileNode) Open(_ context.Context, flags uint32) (fs.FileHandle, uint32, syscall.Errno) {
	if (flags & syscall.O_ACCMODE) != syscall.O_RDONLY {
		return nil, 0, syscall.EROFS
	}
	return &staticFileHandle{rdr: bytes.NewReader(nil), size: 0}, fuse.FOPEN_DIRECT_IO, 0
}

// respDirNode serves /home/agent/.agbox-remote/resp/.
type respDirNode struct {
	fs.Inode
	b *Bridge
}

func (n *respDirNode) Getattr(_ context.Context, _ fs.FileHandle, out *fuse.AttrOut) syscall.Errno {
	n.b.mu.Lock()
	mt := n.b.respMtime
	n.b.mu.Unlock()
	out.Mode = fuse.S_IFDIR | 0o500
	out.Uid = n.b.opts.GuestUID
	out.Gid = n.b.opts.GuestGID
	out.Nlink = 2
	out.SetTimes(nil, &mt, &mt)
	out.SetTimeout(0)
	return 0
}

func (n *respDirNode) Readdir(_ context.Context) (fs.DirStream, syscall.Errno) {
	n.b.mu.Lock()
	entries := make([]fuse.DirEntry, 0, len(n.b.slots))
	for id, sl := range n.b.slots {
		if sl.state == slotDone && !sl.revoked {
			entries = append(entries, fuse.DirEntry{Name: id, Mode: fuse.S_IFREG, Ino: sl.respIno})
		}
	}
	n.b.mu.Unlock()
	return fs.NewListDirStream(entries), 0
}

func (n *respDirNode) Lookup(ctx context.Context, name string, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	out.SetEntryTimeout(0)
	out.SetAttrTimeout(0)
	n.b.mu.Lock()
	sl, ok := n.b.slots[name]
	ready := ok && sl.state == slotDone && !sl.revoked
	var (
		size uint64
		ino  uint64
	)
	if ready {
		size = uint64(len(sl.respBuf))
		ino = sl.respIno
	}
	n.b.mu.Unlock()
	if !ready {
		return nil, syscall.ENOENT
	}
	child := &respFileNode{b: n.b, id: name, size: size}
	out.Attr.Mode = fuse.S_IFREG | 0o400
	out.Attr.Size = size
	out.Attr.Uid = n.b.opts.GuestUID
	out.Attr.Gid = n.b.opts.GuestGID
	return n.NewInode(ctx, child, fs.StableAttr{Mode: fuse.S_IFREG, Ino: ino}), 0
}

type respFileNode struct {
	fs.Inode
	b    *Bridge
	id   string
	size uint64
}

func (n *respFileNode) Getattr(_ context.Context, _ fs.FileHandle, out *fuse.AttrOut) syscall.Errno {
	n.b.mu.Lock()
	sl, ok := n.b.slots[n.id]
	if !ok || sl.revoked || sl.state != slotDone {
		n.b.mu.Unlock()
		return syscall.ESTALE
	}
	sz := uint64(len(sl.respBuf))
	n.b.mu.Unlock()
	out.Mode = fuse.S_IFREG | 0o400
	out.Size = sz
	out.Uid = n.b.opts.GuestUID
	out.Gid = n.b.opts.GuestGID
	out.Nlink = 1
	out.SetTimeout(0)
	return 0
}

func (n *respFileNode) Open(_ context.Context, flags uint32) (fs.FileHandle, uint32, syscall.Errno) {
	if (flags & syscall.O_ACCMODE) != syscall.O_RDONLY {
		return nil, 0, syscall.EROFS
	}
	n.b.mu.Lock()
	defer n.b.mu.Unlock()
	sl, ok := n.b.slots[n.id]
	if !ok || sl.revoked || sl.state != slotDone {
		return nil, 0, syscall.ESTALE
	}
	fh := &respFileHandle{b: n.b, slot: sl, data: sl.respBuf}
	sl.respHandles[fh] = struct{}{}
	return fh, fuse.FOPEN_DIRECT_IO, 0
}

type respFileHandle struct {
	b       *Bridge
	slot    *reqSlot
	data    []byte
	revoked bool
}

func (h *respFileHandle) Read(_ context.Context, dest []byte, off int64) (fuse.ReadResult, syscall.Errno) {
	h.b.mu.Lock()
	if h.revoked || h.slot == nil || h.slot.revoked {
		h.b.mu.Unlock()
		return nil, syscall.ESTALE
	}
	data := h.data
	h.b.mu.Unlock()
	if off < 0 || off >= int64(len(data)) {
		return fuse.ReadResultData(nil), 0
	}
	end := off + int64(len(dest))
	if end > int64(len(data)) {
		end = int64(len(data))
	}
	return fuse.ReadResultData(data[off:end]), 0
}

func (h *respFileHandle) Release(_ context.Context) syscall.Errno {
	h.b.mu.Lock()
	if h.slot != nil && h.slot.respHandles != nil {
		delete(h.slot.respHandles, h)
	}
	h.data = nil
	h.slot = nil
	h.b.mu.Unlock()
	return 0
}

// VerifyUnixSocketOwner checks Lstat (non-symlink socket in 0700 dir) and SO_PEERCRED UID.
func VerifyUnixSocketOwner(sockPath string, conn *net.UnixConn, wantUID int) error {
	if sockPath != "" {
		dir := filepath.Dir(sockPath)
		dInfo, err := os.Lstat(dir)
		if err != nil {
			return fmt.Errorf("stat socket dir %s: %w", dir, err)
		}
		if dInfo.Mode()&os.ModeSymlink != 0 || !dInfo.IsDir() {
			return fmt.Errorf("refusing non-directory socket parent %s", dir)
		}
		if dInfo.Mode().Perm()&0o077 != 0 {
			return fmt.Errorf("refusing insecure socket dir permissions %04o on %s", dInfo.Mode().Perm(), dir)
		}
		sInfo, err := os.Lstat(sockPath)
		if err != nil {
			return fmt.Errorf("stat socket %s: %w", sockPath, err)
		}
		if sInfo.Mode()&os.ModeSymlink != 0 || sInfo.Mode()&os.ModeSocket == 0 {
			return fmt.Errorf("refusing non-socket path %s", sockPath)
		}
	}
	if conn != nil {
		rawConn, err := conn.SyscallConn()
		if err != nil {
			return fmt.Errorf("inspect socket credentials: %w", err)
		}
		var ucred *unix.Ucred
		var credErr error
		if err := rawConn.Control(func(fd uintptr) {
			ucred, credErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
		}); err != nil {
			return fmt.Errorf("read socket credentials: %w", err)
		}
		if credErr != nil {
			return fmt.Errorf("getsockopt SO_PEERCRED: %w", credErr)
		}
		if int(ucred.Uid) != wantUID {
			return fmt.Errorf("peer UID %d does not match host UID %d", ucred.Uid, wantUID)
		}
	}
	return nil
}

// BuildGuestSetupScript returns a root guest shell script that links /usr/local/bin/agbox-remote.
func BuildGuestSetupScript() string {
	return `set -eu
if [ -L /usr/local/bin ]; then
  echo "agbox rejects symlinked /usr/local/bin" >&2
  exit 1
fi
mkdir -p /usr/local/bin
if [ -e /usr/local/bin/agbox-remote ] && [ ! -L /usr/local/bin/agbox-remote ]; then
  rm -rf /usr/local/bin/agbox-remote
fi
ln -sfn /home/agent/.agbox-remote/bin/agbox-remote /usr/local/bin/agbox-remote
`
}
