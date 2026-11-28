package remotebridge

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"agbox/internal/remoteproto"

	"github.com/hanwen/go-fuse/v2/fuse"
)

// makeMinimalStaticELF builds a minimal valid 64-bit little-endian static ELF header (no PT_INTERP).
func makeMinimalStaticELF(withInterp bool) []byte {
	buf := make([]byte, 256)
	copy(buf[0:4], []byte{0x7f, 'E', 'L', 'F'})
	buf[4] = 2                                    // ELFCLASS64
	buf[5] = 1                                    // ELFDATA2LSB
	buf[6] = 1                                    // EV_CURRENT
	binary.LittleEndian.PutUint16(buf[16:18], 2)  // ET_EXEC
	binary.LittleEndian.PutUint16(buf[18:20], 62) // EM_X86_64
	binary.LittleEndian.PutUint32(buf[20:24], 1)  // EV_CURRENT
	binary.LittleEndian.PutUint64(buf[32:40], 64) // e_phoff
	binary.LittleEndian.PutUint16(buf[52:54], 64) // e_ehsize
	binary.LittleEndian.PutUint16(buf[54:56], 56) // e_phentsize
	binary.LittleEndian.PutUint16(buf[56:58], 1)  // e_phnum
	pType := uint32(1)                            // PT_LOAD
	if withInterp {
		pType = 3 // PT_INTERP
	}
	binary.LittleEndian.PutUint32(buf[64:68], pType)
	return buf
}

func TestCheckStaticELF(t *testing.T) {
	staticELF := makeMinimalStaticELF(false)
	if err := CheckStaticELF(bytes.NewReader(staticELF)); err != nil {
		t.Fatalf("expected static ELF to pass: %v", err)
	}
	dynELF := makeMinimalStaticELF(true)
	if err := CheckStaticELF(bytes.NewReader(dynELF)); err == nil || !strings.Contains(err.Error(), "static agbox binary") {
		t.Fatalf("expected dynamic ELF rejection, got %v", err)
	}
	if err := CheckStaticELF(bytes.NewReader([]byte("not an elf"))); err == nil {
		t.Fatal("expected non-ELF rejection")
	}
}

func TestBridgeSlotCapsHandleRevocationAndTTL(t *testing.T) {
	staticELF := makeMinimalStaticELF(false)
	now := time.Date(2026, 11, 28, 10, 0, 0, 0, time.UTC)
	b, err := New(Options{
		ClientReader:     bytes.NewReader(staticELF),
		ClientSize:       int64(len(staticELF)),
		RequireStaticELF: true,
		DenyJitterMin:    time.Millisecond,
		DenyJitterMax:    2 * time.Millisecond,
		DraftTTL:         30 * time.Second,
		DoneTTL:          60 * time.Second,
		RatePerSec:       100,
		RateBurst:        100,
		Now:              func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("New bridge failed: %v", err)
	}
	defer b.Close()

	// Invalid slot ID rejected.
	if _, _, errno := b.createSlot("not-hex"); errno != syscall.EINVAL {
		t.Fatalf("expected EINVAL for bad slot ID, got %v", errno)
	}

	// Enforce 4-slot cap across ALL states at Create().
	ids := []string{
		"00000000000000000000000000000001",
		"00000000000000000000000000000002",
		"00000000000000000000000000000003",
		"00000000000000000000000000000004",
	}
	var handles []*reqFileHandle
	for _, id := range ids {
		sl, h, errno := b.createSlot(id)
		if errno != 0 {
			t.Fatalf("createSlot(%s) failed: %v", id, errno)
		}
		if sl.doneIno == 0 || sl.doneIno == sl.respIno || sl.doneIno == sl.ino {
			t.Fatalf("expected distinct dedicated doneIno, got ino=%d doneIno=%d respIno=%d", sl.ino, sl.doneIno, sl.respIno)
		}
		handles = append(handles, h)
	}
	// Duplicate ID rejected with EEXIST.
	if _, _, errno := b.createSlot(ids[0]); errno != syscall.EEXIST {
		t.Fatalf("expected EEXIST for duplicate slot ID, got %v", errno)
	}
	if _, _, errno := b.createSlot("00000000000000000000000000000005"); errno != syscall.EAGAIN {
		t.Fatalf("expected EAGAIN on 5th slot, got %v", errno)
	}

	// Sparse/non-sequential write rejected.
	if _, errno := b.writeSlot(handles[0], []byte("abc"), 10); errno != syscall.EINVAL {
		t.Fatalf("expected EINVAL for sparse offset write, got %v", errno)
	}

	// Oversize write rejected with EFBIG.
	huge := make([]byte, remoteproto.MaxBridgeReqBytes+1)
	if _, errno := b.writeSlot(handles[0], huge, 0); errno != syscall.EFBIG {
		t.Fatalf("expected EFBIG for oversized request, got %v", errno)
	}

	// Valid write + atomic single-Flush commit.
	reqBytes, _ := json.Marshal(remoteproto.GuestRequest{Version: 1, Executable: "uname", Args: []string{"-a"}})
	if _, errno := b.writeSlot(handles[0], reqBytes, 0); errno != 0 {
		t.Fatalf("writeSlot failed: %v", errno)
	}
	if errno := b.flushSlot(handles[0]); errno != 0 {
		t.Fatalf("first flushSlot failed: %v", errno)
	}
	// Second Flush is a no-op. Subsequent Write returns EROFS.
	if errno := b.flushSlot(handles[0]); errno != 0 {
		t.Fatalf("second flushSlot should be idempotent, got %v", errno)
	}
	if _, errno := b.writeSlot(handles[0], []byte("x"), 0); errno != syscall.EROFS {
		t.Fatalf("expected EROFS on write after flush, got %v", errno)
	}

	// Wait for jittered no-broker denial to populate respBuf and assert StatusDenied.
	var gotResp []byte
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		b.mu.Lock()
		if sl := b.slots[ids[0]]; sl != nil && sl.state == slotDone {
			gotResp = append([]byte(nil), sl.respBuf...)
		}
		b.mu.Unlock()
		if len(gotResp) > 0 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if len(gotResp) == 0 {
		t.Fatal("timed out waiting for jittered no-broker denial response")
	}
	var decoded remoteproto.ExecResponse
	if err := json.Unmarshal(gotResp, &decoded); err != nil || decoded.Status != remoteproto.StatusDenied || decoded.ExitCode != remoteproto.DenyExitCode {
		t.Fatalf("expected StatusDenied response, got %+v err=%v", decoded, err)
	}

	// Open resp handle via real respFileNode.Open, then unlink and verify ESTALE revocation.
	rNode := &respFileNode{b: b, id: ids[0]}
	rawFH, _, errno := rNode.Open(context.Background(), syscall.O_RDONLY)
	if errno != 0 {
		t.Fatalf("respFileNode.Open failed: %v", errno)
	}
	rh := rawFH.(*respFileHandle)

	if errno := b.unlinkSlot(ids[0]); errno != 0 {
		t.Fatalf("unlinkSlot failed: %v", errno)
	}
	buf := make([]byte, 64)
	if _, errno := rh.Read(context.Background(), buf, 0); errno != syscall.ESTALE {
		t.Fatalf("expected ESTALE after Unlink handle revocation, got %v", errno)
	}
	if rh.data != nil {
		t.Fatal("expected revoked resp handle buffer pointer to be nil for GC")
	}
	var doneAttr fuse.AttrOut
	if errno := (&doneFileNode{b: b, id: ids[0]}).Getattr(context.Background(), nil, &doneAttr); errno != syscall.ESTALE {
		t.Fatalf("expected ESTALE for revoked doneFileNode, got %v", errno)
	}

	// TTL reaper evicts unclosed drafts after DraftTTL.
	now = now.Add(31 * time.Second)
	b.ReapExpired(now)
	b.mu.Lock()
	remaining := len(b.slots)
	totalBytes := b.totalBytes
	b.mu.Unlock()
	if remaining != 0 || totalBytes != 0 {
		t.Fatalf("expected 0 remaining slots and 0 bytes after TTL reap, got slots=%d bytes=%d", remaining, totalBytes)
	}
}

func TestBridgeLiveFUSEAndBrokerAttach(t *testing.T) {
	if _, err := os.Stat("/dev/fuse"); err != nil {
		t.Skip("/dev/fuse unavailable")
	}
	tmpDir := t.TempDir()
	if err := os.Chmod(tmpDir, 0o700); err != nil {
		t.Fatal(err)
	}
	mntDir := filepath.Join(tmpDir, "remote")
	if err := os.Mkdir(mntDir, 0o700); err != nil {
		t.Fatal(err)
	}
	sockPath := filepath.Join(tmpDir, "remote.sock")
	staticELF := makeMinimalStaticELF(false)

	b, err := New(Options{
		MountDir:         mntDir,
		SockPath:         sockPath,
		GuestUID:         uint32(os.Geteuid()),
		GuestGID:         uint32(os.Getegid()),
		ClientReader:     bytes.NewReader(staticELF),
		ClientSize:       int64(len(staticELF)),
		RequireStaticELF: true,
		DenyJitterMin:    time.Millisecond,
		DenyJitterMax:    2 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	if err := b.Mount(); err != nil {
		t.Skipf("FUSE mount unavailable in this environment: %v", err)
	}
	defer b.Close()

	// Verify bin/agbox-remote and INSTRUCTIONS.md are readable.
	gotBin, err := os.ReadFile(filepath.Join(mntDir, "bin", GuestClientName))
	if err != nil || !bytes.Equal(gotBin, staticELF) {
		t.Fatalf("read bin/agbox-remote failed: err=%v len=%d", err, len(gotBin))
	}
	gotInstr, err := os.ReadFile(filepath.Join(mntDir, "INSTRUCTIONS.md"))
	if err != nil || !strings.Contains(string(gotInstr), "agbox-remote") {
		t.Fatalf("read INSTRUCTIONS.md failed: err=%v", err)
	}

	// Verify symlink/mkdir rejected in req/.
	if err := os.Symlink("/etc/passwd", filepath.Join(mntDir, "req", "00000000000000000000000000000099")); err == nil {
		t.Fatal("expected symlink in req/ to fail")
	}

	// Verify status before broker attach.
	st, err := QueryStatus(sockPath)
	if err != nil {
		t.Fatalf("QueryStatus failed: %v", err)
	}
	if st.Attached {
		t.Fatalf("expected Attached=false before broker connects, got %+v", st)
	}

	// Attach a mock broker and reject a second broker.
	conn, err := DialAttach(sockPath, "127.0.0.1:9999", "ops@remote", "/tmp/pol.json")
	if err != nil {
		t.Fatalf("DialAttach failed: %v", err)
	}
	defer conn.Close()

	if _, err := DialAttach(sockPath, "127.0.0.1:8888", "ops@remote", ""); err == nil {
		t.Fatal("expected second concurrent broker attach to fail")
	}

	st, err = QueryStatus(sockPath)
	if err != nil || !st.Attached || st.Peer != "127.0.0.1:9999" {
		t.Fatalf("unexpected attached status: %+v, err=%v", st, err)
	}

	// Handle one request over the live FUSE mount + remote.sock.
	go func() {
		typ, payload, _, err := remoteproto.ReadFrame(conn, remoteproto.PostAuthMaxFrameBytes)
		if err != nil || typ != "bridge" {
			return
		}
		var msg remoteproto.BridgeMessage
		if err := remoteproto.DecodeStrict(payload, &msg); err != nil || msg.Op != "req" {
			return
		}
		resp := remoteproto.ExecResponse{
			ReqID:     msg.SlotID,
			Status:    remoteproto.StatusCompleted,
			ExitCode:  0,
			StdoutB64: base64.StdEncoding.EncodeToString([]byte("hello-remote\n")),
		}
		_, _ = remoteproto.WriteFrame(conn, "bridge", remoteproto.BridgeMessage{
			Op:       "resp",
			SlotID:   msg.SlotID,
			Response: &resp,
		}, remoteproto.PostAuthMaxFrameBytes)
	}()

	slotID := "abcdef0123456789abcdef0123456789"
	reqPath := filepath.Join(mntDir, "req", slotID)
	rawReq, _ := json.Marshal(remoteproto.GuestRequest{Version: 1, Executable: "echo", Args: []string{"hi"}})
	f, err := os.OpenFile(reqPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o200)
	if err != nil {
		t.Fatalf("create req file failed: %v", err)
	}
	if _, err := f.Write(rawReq); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	// Wait for slotID in done/.
	found := false
	for deadline := time.Now().Add(2 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		entries, err := os.ReadDir(filepath.Join(mntDir, "done"))
		if err != nil {
			t.Fatalf("readdir done failed: %v", err)
		}
		for _, e := range entries {
			if e.Name() == slotID {
				found = true
				break
			}
		}
		if found {
			break
		}
	}
	if !found {
		t.Fatal("slot did not appear in done/")
	}

	rawResp, err := os.ReadFile(filepath.Join(mntDir, "resp", slotID))
	if err != nil {
		t.Fatalf("read resp failed: %v", err)
	}
	var got remoteproto.ExecResponse
	if err := json.Unmarshal(rawResp, &got); err != nil || got.Status != remoteproto.StatusCompleted {
		t.Fatalf("unexpected resp: %+v, err=%v", got, err)
	}
	if err := os.Remove(reqPath); err != nil {
		t.Fatalf("unlink req failed: %v", err)
	}
}

func TestBridgeRateLimitMemoryCapDoneTTLAndMonotonicMtime(t *testing.T) {
	staticELF := makeMinimalStaticELF(false)
	now := time.Date(2026, 11, 28, 12, 0, 0, 0, time.UTC)
	b, err := New(Options{
		ClientReader:     bytes.NewReader(staticELF),
		ClientSize:       int64(len(staticELF)),
		RequireStaticELF: true,
		DenyJitterMin:    time.Millisecond,
		DenyJitterMax:    2 * time.Millisecond,
		DraftTTL:         30 * time.Second,
		DoneTTL:          60 * time.Second,
		RatePerSec:       1,
		RateBurst:        2,
		Now:              func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()

	// Rate limiter allows burst of 2, rejects 3rd with EAGAIN, then refills after advancing Now.
	id1 := "10000000000000000000000000000001"
	id2 := "10000000000000000000000000000002"
	id3 := "10000000000000000000000000000003"
	if _, _, errno := b.createSlot(id1); errno != 0 {
		t.Fatalf("slot 1 failed: %v", errno)
	}
	if _, _, errno := b.createSlot(id2); errno != 0 {
		t.Fatalf("slot 2 failed: %v", errno)
	}
	if _, _, errno := b.createSlot(id3); errno != syscall.EAGAIN {
		t.Fatalf("expected rate-limit EAGAIN on slot 3, got %v", errno)
	}
	now = now.Add(2 * time.Second)
	_, fh3, errno := b.createSlot(id3)
	if errno != 0 {
		t.Fatalf("expected refilled rate token for slot 3, got %v", errno)
	}

	// Enforce 16 MiB MaxTotalBytes cap on writeSlot and CompleteSlot fallback.
	b.mu.Lock()
	b.totalBytes = MaxTotalBytes - 4
	b.mu.Unlock()
	if _, errno := b.writeSlot(fh3, []byte("12345"), 0); errno != syscall.ENOSPC {
		t.Fatalf("expected ENOSPC when exceeding MaxTotalBytes, got %v", errno)
	}
	b.mu.Lock()
	b.totalBytes = 0
	b.mu.Unlock()

	// Bad JSON and oversized base64 stdin in flushSlot both resolve to StatusDenied.
	_, fhBad, errno := b.createSlot("10000000000000000000000000000004")
	if errno != 0 {
		t.Fatal(errno)
	}
	if _, errno := b.writeSlot(fhBad, []byte("{bad-json"), 0); errno != 0 {
		t.Fatal(errno)
	}
	if errno := b.flushSlot(fhBad); errno != 0 {
		t.Fatal(errno)
	}
	waitSlotDone := func(id string) remoteproto.ExecResponse {
		t.Helper()
		deadline := time.Now().Add(2 * time.Second)
		for time.Now().Before(deadline) {
			b.mu.Lock()
			sl := b.slots[id]
			var raw []byte
			if sl != nil && sl.state == slotDone {
				raw = append([]byte(nil), sl.respBuf...)
			}
			b.mu.Unlock()
			if len(raw) > 0 {
				var r remoteproto.ExecResponse
				if err := json.Unmarshal(raw, &r); err != nil {
					t.Fatalf("unmarshal slot %s resp: %v", id, err)
				}
				return r
			}
			time.Sleep(5 * time.Millisecond)
		}
		t.Fatalf("timed out waiting for slot %s completion", id)
		return remoteproto.ExecResponse{}
	}
	if r := waitSlotDone("10000000000000000000000000000004"); r.Status != remoteproto.StatusDenied {
		t.Fatalf("expected StatusDenied for bad JSON request, got %+v", r)
	}
	_ = b.unlinkSlot("10000000000000000000000000000004")

	// Oversized base64 stdin (> MaxStdinBytes) resolves to StatusDenied.
	now = now.Add(2 * time.Second)
	oversizeStdin := base64.StdEncoding.EncodeToString(make([]byte, remoteproto.MaxStdinBytes+1))
	overReq, _ := json.Marshal(remoteproto.GuestRequest{Version: 1, Executable: "cat", StdinB64: oversizeStdin})
	if _, errno := b.writeSlot(fh3, overReq, 0); errno != 0 {
		t.Fatalf("writeSlot oversized stdin json failed: %v", errno)
	}
	if errno := b.flushSlot(fh3); errno != 0 {
		t.Fatal(errno)
	}
	if r := waitSlotDone(id3); r.Status != remoteproto.StatusDenied {
		t.Fatalf("expected StatusDenied for oversized stdin, got %+v", r)
	}

	// CompleteSlot falls back to DeniedResponse when resp would exceed MaxTotalBytes,
	// and bumps doneMtime/respMtime monotonically even when Now does not advance.
	_ = b.unlinkSlot(id1)
	_ = b.unlinkSlot(id2)
	b.mu.Lock()
	mtBefore := b.doneMtime
	sl3 := b.slots[id3]
	sl3.state = slotPending
	b.totalBytes = MaxTotalBytes - 10
	b.mu.Unlock()
	b.CompleteSlot(id3, remoteproto.ExecResponse{
		ReqID:     id3,
		Status:    remoteproto.StatusCompleted,
		StdoutB64: base64.StdEncoding.EncodeToString(make([]byte, 512)),
	})
	b.mu.Lock()
	mtAfter := b.doneMtime
	rawFallback := append([]byte(nil), b.slots[id3].respBuf...)
	b.totalBytes = int64(len(rawFallback))
	b.mu.Unlock()
	if !mtAfter.After(mtBefore) {
		t.Fatalf("expected monotonic mtime bump without clock advance: before=%v after=%v", mtBefore, mtAfter)
	}
	var fbResp remoteproto.ExecResponse
	if err := json.Unmarshal(rawFallback, &fbResp); err != nil || fbResp.Status != remoteproto.StatusDenied {
		t.Fatalf("expected CompleteSlot memory cap fallback to StatusDenied, got %+v err=%v", fbResp, err)
	}

	// DoneTTL eviction revokes open respFileHandle with ESTALE and releases buffer memory.
	rNode := &respFileNode{b: b, id: id3}
	rawFH, _, errno := rNode.Open(context.Background(), syscall.O_RDONLY)
	if errno != 0 {
		t.Fatalf("respFileNode.Open failed: %v", errno)
	}
	rh := rawFH.(*respFileHandle)
	now = now.Add(61 * time.Second)
	b.ReapExpired(now)
	if _, errno := rh.Read(context.Background(), make([]byte, 16), 0); errno != syscall.ESTALE {
		t.Fatalf("expected ESTALE after DoneTTL eviction, got %v", errno)
	}
	if rh.data != nil {
		t.Fatal("expected DoneTTL eviction to nil respFileHandle.data")
	}
}

func TestBridgeControlSocketNoFUSEAndDirectNodeErrors(t *testing.T) {
	staticELF := makeMinimalStaticELF(false)
	tmpDir := t.TempDir()
	if err := os.Chmod(tmpDir, 0o700); err != nil {
		t.Fatal(err)
	}
	sockPath := filepath.Join(tmpDir, "remote.sock")

	b, err := New(Options{
		SockPath:         sockPath,
		ClientReader:     bytes.NewReader(staticELF),
		ClientSize:       int64(len(staticELF)),
		RequireStaticELF: true,
		DenyJitterMin:    time.Millisecond,
		DenyJitterMax:    2 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := b.startControlSocket(); err != nil {
		t.Fatalf("startControlSocket failed: %v", err)
	}
	defer b.Close()

	// Verify QueryStatus before attach.
	st, err := QueryStatus(sockPath)
	if err != nil || st.Attached || st.Pending != 0 {
		t.Fatalf("unexpected initial QueryStatus: %+v err=%v", st, err)
	}

	// Attach broker 1 and reject broker 2.
	conn, err := DialAttach(sockPath, "127.0.0.1:4444", "ops@host", "/tmp/pol.json")
	if err != nil {
		t.Fatalf("DialAttach failed: %v", err)
	}
	if _, err := DialAttach(sockPath, "127.0.0.1:5555", "ops@host", ""); err == nil {
		t.Fatal("expected second broker attach rejection")
	}

	// Verify strict req-before-cancel ordering on flush followed immediately by unlink.
	slotA := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	_, fhA, errno := b.createSlot(slotA)
	if errno != 0 {
		t.Fatal(errno)
	}
	rawReq, _ := json.Marshal(remoteproto.GuestRequest{Version: 1, Executable: "sleep", Args: []string{"10"}})
	if _, errno := b.writeSlot(fhA, rawReq, 0); errno != 0 {
		t.Fatal(errno)
	}
	if errno := b.flushSlot(fhA); errno != 0 {
		t.Fatal(errno)
	}
	if errno := b.unlinkSlot(slotA); errno != 0 {
		t.Fatal(errno)
	}

	readBrokerMsg := func() remoteproto.BridgeMessage {
		t.Helper()
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		typ, payload, _, err := remoteproto.ReadFrame(conn, remoteproto.PostAuthMaxFrameBytes)
		if err != nil || typ != "bridge" {
			t.Fatalf("ReadFrame failed: typ=%q err=%v", typ, err)
		}
		var m remoteproto.BridgeMessage
		if err := remoteproto.DecodeStrict(payload, &m); err != nil {
			t.Fatalf("DecodeStrict failed: %v", err)
		}
		return m
	}
	msg1 := readBrokerMsg()
	msg2 := readBrokerMsg()
	if msg1.Op != "req" || msg1.SlotID != slotA || msg2.Op != "cancel" || msg2.SlotID != slotA {
		t.Fatalf("expected strict req then cancel order, got msg1=%+v msg2=%+v", msg1, msg2)
	}

	// Disconnecting the broker immediately denies pending slots via denyAllPendingLocked.
	slotB := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	_, fhB, errno := b.createSlot(slotB)
	if errno != 0 {
		t.Fatal(errno)
	}
	if _, errno := b.writeSlot(fhB, rawReq, 0); errno != 0 {
		t.Fatal(errno)
	}
	if errno := b.flushSlot(fhB); errno != 0 {
		t.Fatal(errno)
	}
	msg3 := readBrokerMsg()
	if msg3.Op != "req" || msg3.SlotID != slotB {
		t.Fatalf("expected req for slotB, got %+v", msg3)
	}
	_ = conn.Close()

	deadline := time.Now().Add(2 * time.Second)
	var deniedOnDrop bool
	for time.Now().Before(deadline) {
		b.mu.Lock()
		if sl := b.slots[slotB]; sl != nil && sl.state == slotDone {
			var r remoteproto.ExecResponse
			if json.Unmarshal(sl.respBuf, &r) == nil && r.Status == remoteproto.StatusDenied {
				deniedOnDrop = true
			}
		}
		b.mu.Unlock()
		if deniedOnDrop {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if !deniedOnDrop {
		t.Fatal("expected pending slot to resolve to StatusDenied when broker disconnects")
	}

	// VerifyUnixSocketOwner rejection paths.
	if err := VerifyUnixSocketOwner(filepath.Join(tmpDir, "missing.sock"), nil, os.Geteuid()); err == nil {
		t.Fatal("expected error for missing socket path")
	}
	regFile := filepath.Join(tmpDir, "regular")
	if err := os.WriteFile(regFile, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := VerifyUnixSocketOwner(regFile, nil, os.Geteuid()); err == nil {
		t.Fatal("expected error for regular non-socket path")
	}
	symSock := filepath.Join(tmpDir, "sym.sock")
	if err := os.Symlink(sockPath, symSock); err != nil {
		t.Fatal(err)
	}
	if err := VerifyUnixSocketOwner(symSock, nil, os.Geteuid()); err == nil {
		t.Fatal("expected error for symlinked socket")
	}
	wideDir := filepath.Join(tmpDir, "wide")
	if err := os.Mkdir(wideDir, 0o755); err != nil {
		t.Fatal(err)
	}
	_ = os.Chmod(wideDir, 0o755)
	if err := VerifyUnixSocketOwner(filepath.Join(wideDir, "x.sock"), nil, os.Geteuid()); err == nil {
		t.Fatal("expected error for insecure 0755 socket parent dir")
	}
	conn2, err := DialAttach(sockPath, "127.0.0.1:6666", "ops@host", "")
	if err != nil {
		t.Fatal(err)
	}
	defer conn2.Close()
	if err := VerifyUnixSocketOwner("", conn2, os.Geteuid()+1); err == nil {
		t.Fatal("expected SO_PEERCRED UID mismatch rejection")
	}

	// Direct node EPERM and EROFS checks.
	reqDir := &reqDirNode{b: b}
	var eOut fuse.EntryOut
	if _, _, _, errno := reqDir.Create(context.Background(), slotA, syscall.O_RDWR, 0o200, &eOut); errno != syscall.EPERM {
		t.Fatalf("expected EPERM for O_RDWR Create, got %v", errno)
	}
	if _, _, _, errno := reqDir.Create(context.Background(), slotA, syscall.O_WRONLY|syscall.O_APPEND, 0o200, &eOut); errno != syscall.EPERM {
		t.Fatalf("expected EPERM for O_APPEND Create, got %v", errno)
	}
	if _, errno := reqDir.Mkdir(context.Background(), "x", 0o700, &eOut); errno != syscall.EPERM {
		t.Fatalf("expected EPERM for Mkdir, got %v", errno)
	}
	if _, errno := reqDir.Symlink(context.Background(), "a", "b", &eOut); errno != syscall.EPERM {
		t.Fatalf("expected EPERM for Symlink, got %v", errno)
	}
	if _, errno := reqDir.Mknod(context.Background(), "x", 0o600, 0, &eOut); errno != syscall.EPERM {
		t.Fatalf("expected EPERM for Mknod, got %v", errno)
	}
	if _, errno := reqDir.Link(context.Background(), reqDir, "x", &eOut); errno != syscall.EPERM {
		t.Fatalf("expected EPERM for Link, got %v", errno)
	}
	if errno := reqDir.Rename(context.Background(), "a", reqDir, "b", 0); errno != syscall.EPERM {
		t.Fatalf("expected EPERM for Rename, got %v", errno)
	}
	if _, _, errno := (&reqFileNode{b: b, id: slotB}).Open(context.Background(), syscall.O_RDONLY); errno != syscall.EPERM {
		t.Fatalf("expected EPERM for reqFileNode.Open, got %v", errno)
	}
	if _, _, errno := (&staticFileNode{b: b, rdr: bytes.NewReader(nil), mode: 0o444}).Open(context.Background(), syscall.O_WRONLY); errno != syscall.EROFS {
		t.Fatalf("expected EROFS for writable staticFileNode.Open, got %v", errno)
	}
	if _, _, errno := (&respFileNode{b: b, id: slotB}).Open(context.Background(), syscall.O_WRONLY); errno != syscall.EROFS {
		t.Fatalf("expected EROFS for writable respFileNode.Open, got %v", errno)
	}
	if _, _, errno := (&doneFileNode{b: b, id: slotB}).Open(context.Background(), syscall.O_WRONLY); errno != syscall.EROFS {
		t.Fatalf("expected EROFS for writable doneFileNode.Open, got %v", errno)
	}
}
