package remotebroker

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"agbox/internal/config"
	"agbox/internal/remotebridge"
	"agbox/internal/remoteclient"
	"agbox/internal/remotedaemon"
	"agbox/internal/remotepolicy"
	"agbox/internal/remoteproto"
)

// syncBuffer is a goroutine-safe bytes.Buffer with write notifications for deterministic prompt waiting.
type syncBuffer struct {
	mu     sync.Mutex
	buf    bytes.Buffer
	notify chan struct{}
}

func newSyncBuffer() *syncBuffer {
	return &syncBuffer{notify: make(chan struct{}, 1)}
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	n, err := b.buf.Write(p)
	b.mu.Unlock()
	select {
	case b.notify <- struct{}{}:
	default:
	}
	return n, err
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func (b *syncBuffer) Len() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Len()
}

func (b *syncBuffer) waitFor(t *testing.T, from int, substr string, timeout time.Duration) int {
	t.Helper()
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	for {
		s := b.String()
		if from <= len(s) {
			if idx := strings.Index(s[from:], substr); idx >= 0 {
				return from + idx + len(substr)
			}
		}
		select {
		case <-b.notify:
		case <-deadline.C:
			t.Fatalf("timed out waiting for %q after offset %d in buffer:\n%s", substr, from, s)
		}
	}
}

// fakeBridgeSock implements the real Unix remote.sock control protocol without FUSE.
type fakeBridgeSock struct {
	sockPath string
	ln       *net.UnixListener

	mu          sync.Mutex
	conn        *net.UnixConn
	writeMu     sync.Mutex
	attachedCh  chan remoteproto.BridgeStatus
	lastStatus  remoteproto.BridgeStatus
	respWaiters map[string]chan remoteproto.ExecResponse
	closed      bool
}

func newFakeBridgeSock(t *testing.T, dir string) *fakeBridgeSock {
	t.Helper()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	sockPath := filepath.Join(dir, "remote.sock")
	addr, err := net.ResolveUnixAddr("unix", sockPath)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.ListenUnix("unix", addr)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(sockPath, 0o600); err != nil {
		_ = ln.Close()
		t.Fatal(err)
	}
	fb := &fakeBridgeSock{
		sockPath:    sockPath,
		ln:          ln,
		attachedCh:  make(chan remoteproto.BridgeStatus, 8),
		respWaiters: make(map[string]chan remoteproto.ExecResponse),
	}
	go fb.acceptLoop()
	t.Cleanup(fb.Close)
	return fb
}

func (fb *fakeBridgeSock) acceptLoop() {
	for {
		conn, err := fb.ln.AcceptUnix()
		if err != nil {
			return
		}
		go fb.handleConn(conn)
	}
}

func (fb *fakeBridgeSock) handleConn(conn *net.UnixConn) {
	defer conn.Close()
	typ, payload, _, err := remoteproto.ReadFrame(conn, 4096)
	if err != nil || typ != "bridge" {
		return
	}
	var msg remoteproto.BridgeMessage
	if err := remoteproto.DecodeStrict(payload, &msg); err != nil {
		return
	}
	switch msg.Op {
	case "status":
		fb.mu.Lock()
		st := fb.lastStatus
		st.Attached = fb.conn != nil
		fb.mu.Unlock()
		_, _ = remoteproto.WriteFrame(conn, "status", st, 4096)
	case "attach":
		fb.mu.Lock()
		if fb.closed || fb.conn != nil {
			fb.mu.Unlock()
			_, _ = remoteproto.WriteFrame(conn, "bridge", remoteproto.BridgeMessage{
				Op:    "attach_err",
				Error: "already attached",
			}, 4096)
			return
		}
		fb.conn = conn
		st := remoteproto.BridgeStatus{
			Attached: true,
			Peer:     msg.Peer,
			RemoteID: msg.RemoteID,
			Policy:   msg.Policy,
		}
		fb.lastStatus = st
		fb.mu.Unlock()

		if _, err := remoteproto.WriteFrame(conn, "bridge", remoteproto.BridgeMessage{Op: "attach_ok"}, 4096); err != nil {
			fb.detach(conn)
			return
		}
		select {
		case fb.attachedCh <- st:
		default:
		}
		fb.readBrokerLoop(conn)
		fb.detach(conn)
	}
}

func (fb *fakeBridgeSock) readBrokerLoop(conn *net.UnixConn) {
	for {
		typ, payload, _, err := remoteproto.ReadFrame(conn, remoteproto.PostAuthMaxFrameBytes)
		if err != nil || typ != "bridge" {
			return
		}
		var msg remoteproto.BridgeMessage
		if err := remoteproto.DecodeStrict(payload, &msg); err != nil {
			return
		}
		if msg.Op == "resp" && msg.SlotID != "" && msg.Response != nil {
			fb.mu.Lock()
			ch, ok := fb.respWaiters[msg.SlotID]
			if ok {
				delete(fb.respWaiters, msg.SlotID)
			}
			fb.mu.Unlock()
			if ok {
				ch <- *msg.Response
			}
		}
	}
}

func (fb *fakeBridgeSock) detach(conn *net.UnixConn) {
	fb.mu.Lock()
	if fb.conn == conn {
		fb.conn = nil
		for id, ch := range fb.respWaiters {
			delete(fb.respWaiters, id)
			close(ch)
		}
	}
	fb.mu.Unlock()
}

func (fb *fakeBridgeSock) waitAttached(t *testing.T, timeout time.Duration) remoteproto.BridgeStatus {
	t.Helper()
	select {
	case st := <-fb.attachedCh:
		return st
	case <-time.After(timeout):
		t.Fatalf("timed out waiting for broker to attach to %s", fb.sockPath)
		return remoteproto.BridgeStatus{}
	}
}

func (fb *fakeBridgeSock) submit(t *testing.T, slotID string, req remoteproto.GuestRequest) <-chan remoteproto.ExecResponse {
	t.Helper()
	ch := make(chan remoteproto.ExecResponse, 1)
	fb.mu.Lock()
	conn := fb.conn
	if conn != nil {
		fb.respWaiters[slotID] = ch
	}
	fb.mu.Unlock()
	if conn == nil {
		t.Fatalf("fakeBridgeSock %s is not attached", fb.sockPath)
	}
	req.Version = 1
	fb.writeMu.Lock()
	_, err := remoteproto.WriteFrame(conn, "bridge", remoteproto.BridgeMessage{
		Op:      "req",
		SlotID:  slotID,
		Request: &req,
	}, remoteproto.PostAuthMaxFrameBytes)
	fb.writeMu.Unlock()
	if err != nil {
		t.Fatalf("write bridge req: %v", err)
	}
	return ch
}

func (fb *fakeBridgeSock) cancel(t *testing.T, slotID string) {
	t.Helper()
	fb.mu.Lock()
	conn := fb.conn
	fb.mu.Unlock()
	if conn == nil {
		t.Fatalf("fakeBridgeSock %s is not attached", fb.sockPath)
	}
	fb.writeMu.Lock()
	_, err := remoteproto.WriteFrame(conn, "bridge", remoteproto.BridgeMessage{
		Op:     "cancel",
		SlotID: slotID,
	}, remoteproto.PostAuthMaxFrameBytes)
	fb.writeMu.Unlock()
	if err != nil {
		t.Fatalf("write bridge cancel: %v", err)
	}
}

func (fb *fakeBridgeSock) dropBrokerConn() {
	fb.mu.Lock()
	conn := fb.conn
	fb.mu.Unlock()
	if conn != nil {
		_ = conn.Close()
	}
}

func (fb *fakeBridgeSock) Close() {
	fb.mu.Lock()
	fb.closed = true
	conn := fb.conn
	fb.conn = nil
	fb.mu.Unlock()
	_ = fb.ln.Close()
	if conn != nil {
		_ = conn.Close()
	}
	_ = os.Remove(fb.sockPath)
}

// tcpDropProxy forwards TCP traffic to a real remotedaemon and lets tests sever the live link.
type tcpDropProxy struct {
	ln     net.Listener
	target string

	mu     sync.Mutex
	active []net.Conn
}

func newTCPDropProxy(t *testing.T, target string) *tcpDropProxy {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := &tcpDropProxy{ln: ln, target: target}
	go p.serve()
	t.Cleanup(p.Close)
	return p
}

func (p *tcpDropProxy) Addr() string { return p.ln.Addr().String() }

func (p *tcpDropProxy) serve() {
	for {
		client, err := p.ln.Accept()
		if err != nil {
			return
		}
		server, err := net.Dial("tcp", p.target)
		if err != nil {
			_ = client.Close()
			continue
		}
		p.mu.Lock()
		p.active = append(p.active, client, server)
		p.mu.Unlock()
		go func() {
			_, _ = io.Copy(server, client)
			_ = server.Close()
			_ = client.Close()
		}()
		go func() {
			_, _ = io.Copy(client, server)
			_ = client.Close()
			_ = server.Close()
		}()
	}
}

func (p *tcpDropProxy) DropActive() {
	p.mu.Lock()
	conns := p.active
	p.active = nil
	p.mu.Unlock()
	for _, c := range conns {
		_ = c.Close()
	}
}

func (p *tcpDropProxy) Close() {
	_ = p.ln.Close()
	p.DropActive()
}

type harnessOpts struct {
	policyJSON          []byte
	noPolicy            bool
	outputReview        bool
	extraRedactPatterns []string
	maxOutputBytes      int
	askTimeout          time.Duration
	useTCPProxy         bool
	editBytes           func(ctx context.Context, prefix string, content []byte) ([]byte, error)
	viewText            func(ctx context.Context, text string)
	daemonMaxOutput     int
	daemonExecTimeout   time.Duration
}

type brokerHarness struct {
	t          *testing.T
	tmpDir     string
	polPath    string
	auditPath  string
	ctx        context.Context
	cancel     context.CancelFunc
	daemon     *remotedaemon.Daemon
	proxy      *tcpDropProxy
	bridge     *fakeBridgeSock
	broker     *Broker
	inR        *os.File
	inW        *os.File
	stdout     *syncBuffer
	stderr     *syncBuffer
	brokerDone chan error
	slotSeq    atomic.Uint64
}

func startBrokerHarness(t *testing.T, opts harnessOpts) *brokerHarness {
	t.Helper()
	tmpDir := t.TempDir()
	if err := os.Chmod(tmpDir, 0o700); err != nil {
		t.Fatal(err)
	}
	polPath := ""
	if !opts.noPolicy {
		polPath = filepath.Join(tmpDir, "policy.json")
		raw := opts.policyJSON
		if len(raw) == 0 {
			raw = remotepolicy.StarterPolicyJSON()
		}
		if err := os.WriteFile(polPath, raw, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	auditPath := filepath.Join(tmpDir, "audit.jsonl")

	bridgeDir := filepath.Join(tmpDir, "sb1")
	if err := os.Mkdir(bridgeDir, 0o700); err != nil {
		t.Fatal(err)
	}
	bridge := newFakeBridgeSock(t, bridgeDir)

	ctx, cancel := context.WithCancel(context.Background())
	dOut := newSyncBuffer()
	dErr := newSyncBuffer()
	sasRemoteCh := make(chan string, 1)
	daemon, err := remotedaemon.New(remotedaemon.Config{
		ListenAddr:     "127.0.0.1:0",
		AllowFrom:      []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")},
		AllowCWD:       []string{tmpDir},
		MaxOutputBytes: opts.daemonMaxOutput,
		ExecTimeout:    opts.daemonExecTimeout,
		Stdout:         dOut,
		Stderr:         dErr,
		PromptConfirm: func(_ context.Context, _ string, sas string) (bool, error) {
			sasRemoteCh <- sas
			return true, nil
		},
	})
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	addr, err := daemon.Listen()
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	go func() {
		_ = daemon.Serve(ctx)
	}()

	remoteAddr := addr.String()
	var proxy *tcpDropProxy
	if opts.useTCPProxy {
		proxy = newTCPDropProxy(t, remoteAddr)
		remoteAddr = proxy.Addr()
	}

	inR, inW, err := os.Pipe()
	if err != nil {
		cancel()
		daemon.Close()
		t.Fatal(err)
	}

	bOut := newSyncBuffer()
	bErr := newSyncBuffer()
	sasHostCh := make(chan string, 1)
	broker, err := New(Config{
		RemoteAddr:          remoteAddr,
		SandboxName:         "agbox-sb1",
		DataDir:             tmpDir,
		PolicyPath:          polPath,
		NoPolicy:            opts.noPolicy,
		OutputReview:        opts.outputReview,
		ExtraRedactPatterns: opts.extraRedactPatterns,
		MaxOutputBytes:      opts.maxOutputBytes,
		AskTimeout:          opts.askTimeout,
		AuditLogPath:        auditPath,
		Stdin:               inR,
		Stdout:              bOut,
		Stderr:              bErr,
		EditBytes:           opts.editBytes,
		ViewText:            opts.viewText,
		ListSandboxes: func() ([]SandboxCandidate, error) {
			return []SandboxCandidate{{
				Name:      "agbox-sb1",
				SockPath:  bridge.sockPath,
				HasBridge: true,
				IsRunning: true,
			}}, nil
		},
		PromptConfirmPairing: func(_ context.Context, _ string, _ remoteproto.HelloPayload, sas string) (bool, error) {
			sasHostCh <- sas
			return true, nil
		},
	})
	if err != nil {
		cancel()
		daemon.Close()
		_ = inR.Close()
		_ = inW.Close()
		t.Fatal(err)
	}

	brokerDone := make(chan error, 1)
	go func() {
		brokerDone <- broker.Run(ctx)
	}()

	select {
	case sasH := <-sasHostCh:
		select {
		case sasR := <-sasRemoteCh:
			if sasH != sasR || len(sasH) != 14 {
				t.Fatalf("SAS mismatch: host=%q remote=%q", sasH, sasR)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("timed out waiting for remote SAS")
		}
	case err := <-brokerDone:
		t.Fatalf("broker exited before pairing: %v\nstdout:\n%s\nstderr:\n%s", err, bOut.String(), bErr.String())
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for host SAS")
	}

	bridge.waitAttached(t, 5*time.Second)
	bOut.waitFor(t, 0, "Idle (sandbox=agbox-sb1", 5*time.Second)

	h := &brokerHarness{
		t:          t,
		tmpDir:     tmpDir,
		polPath:    polPath,
		auditPath:  auditPath,
		ctx:        ctx,
		cancel:     cancel,
		daemon:     daemon,
		proxy:      proxy,
		bridge:     bridge,
		broker:     broker,
		inR:        inR,
		inW:        inW,
		stdout:     bOut,
		stderr:     bErr,
		brokerDone: brokerDone,
	}
	t.Cleanup(func() {
		cancel()
		_ = inW.Close()
		select {
		case <-brokerDone:
		case <-time.After(3 * time.Second):
		}
		_ = inR.Close()
		daemon.Close()
	})
	return h
}

func (h *brokerHarness) nextSlotID() string {
	return fmt.Sprintf("%032x", h.slotSeq.Add(1))
}

func (h *brokerHarness) submitAsync(req remoteproto.GuestRequest) (string, <-chan remoteproto.ExecResponse) {
	h.t.Helper()
	slotID := h.nextSlotID()
	return slotID, h.bridge.submit(h.t, slotID, req)
}

func (h *brokerHarness) waitResp(ch <-chan remoteproto.ExecResponse) remoteproto.ExecResponse {
	h.t.Helper()
	select {
	case resp, ok := <-ch:
		if !ok {
			h.t.Fatal("response channel closed unexpectedly")
		}
		return resp
	case <-time.After(8 * time.Second):
		h.t.Fatalf("timed out waiting for response\nstdout:\n%s\nstderr:\n%s", h.stdout.String(), h.stderr.String())
		return remoteproto.ExecResponse{}
	}
}

func (h *brokerHarness) writeIn(s string) {
	h.t.Helper()
	if _, err := h.inW.WriteString(s); err != nil {
		h.t.Fatalf("write stdin %q: %v", s, err)
	}
}

func (h *brokerHarness) quit() {
	h.t.Helper()
	h.writeIn("q\n")
	select {
	case err := <-h.brokerDone:
		if err != nil {
			h.t.Fatalf("broker exited with error: %v", err)
		}
	case <-time.After(5 * time.Second):
		h.cancel()
		h.t.Fatalf("broker did not exit cleanly on [q]\nstdout:\n%s\nstderr:\n%s", h.stdout.String(), h.stderr.String())
	}
}

func decodeB64(t *testing.T, s string) string {
	t.Helper()
	if s == "" {
		return ""
	}
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("decode base64 %q: %v", s, err)
	}
	return string(raw)
}

func readAuditEntries(t *testing.T, path string) []AuditEntry {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read audit log: %v", err)
	}
	var out []AuditEntry
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var e AuditEntry
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatalf("unmarshal audit entry %q: %v", line, err)
		}
		out = append(out, e)
	}
	return out
}

func TestSplitEditorAndResolveEditor(t *testing.T) {
	t.Parallel()
	parts, err := SplitEditorCommand(`"my editor" --wait 'arg two'`)
	if err != nil {
		t.Fatalf("SplitEditorCommand failed: %v", err)
	}
	if len(parts) != 3 || parts[0] != "my editor" || parts[1] != "--wait" || parts[2] != "arg two" {
		t.Fatalf("unexpected split: %#v", parts)
	}
	for _, bad := range []string{`vim; id`, `vim $(id)`, `vim "unclosed`, `vim | cat`} {
		if _, err := SplitEditorCommand(bad); err == nil {
			t.Errorf("expected SplitEditorCommand(%q) to fail", bad)
		}
	}

	fakeLook := func(name string) (string, error) { return "/usr/bin/" + name, nil }
	argv, warn, err := ResolveEditor(func(k string) string {
		if k == "EDITOR" {
			return "nvim"
		}
		return ""
	}, fakeLook)
	if err != nil || warn != "" {
		t.Fatalf("ResolveEditor(nvim) = (%v, %q, %v)", argv, warn, err)
	}
	joined := strings.Join(argv, " ")
	if !strings.Contains(joined, "shada=") || strings.Contains(joined, "viminfo=") {
		t.Fatalf("expected nvim shada= flag without viminfo=, got %v", argv)
	}

	for _, vimName := range []string{"vim", "vim.basic", "vim.nox", "vim.tiny"} {
		argvV, warnV, errV := ResolveEditor(func(k string) string {
			if k == "EDITOR" {
				return vimName
			}
			return ""
		}, fakeLook)
		if errV != nil || warnV != "" {
			t.Fatalf("ResolveEditor(%s) = (%v, %q, %v)", vimName, argvV, warnV, errV)
		}
		joinedV := strings.Join(argvV, " ")
		if !strings.Contains(joinedV, "viminfo=") || strings.Contains(joinedV, "shada=") {
			t.Fatalf("expected %s viminfo= flag without shada=, got %v", vimName, argvV)
		}
	}

	// Verify vi pointing to Neovim receives shada= instead of viminfo=.
	viDir := t.TempDir()
	viNvim := filepath.Join(viDir, "vi")
	if err := os.WriteFile(viNvim, []byte("#!/bin/sh\necho 'NVIM v0.10.0 Neovim'\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	argvViNvim, warnViNvim, err := ResolveEditor(func(k string) string {
		if k == "EDITOR" {
			return "vi"
		}
		return ""
	}, func(string) (string, error) { return viNvim, nil })
	if err != nil || warnViNvim != "" {
		t.Fatalf("ResolveEditor(vi->nvim) = (%v, %q, %v)", argvViNvim, warnViNvim, err)
	}
	if !strings.Contains(strings.Join(argvViNvim, " "), "shada=") || strings.Contains(strings.Join(argvViNvim, " "), "viminfo=") {
		t.Fatalf("expected vi->nvim to use shada=, got %v", argvViNvim)
	}

	// Verify vi pointing to Vim receives viminfo=.
	viVim := filepath.Join(t.TempDir(), "vi")
	if err := os.WriteFile(viVim, []byte("#!/bin/sh\necho 'VIM - Vi IMproved 9.1'\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	argvViVim, warnViVim, err := ResolveEditor(func(k string) string {
		if k == "EDITOR" {
			return "vi"
		}
		return ""
	}, func(string) (string, error) { return viVim, nil })
	if err != nil || warnViVim != "" {
		t.Fatalf("ResolveEditor(vi->vim) = (%v, %q, %v)", argvViVim, warnViVim, err)
	}
	if !strings.Contains(strings.Join(argvViVim, " "), "viminfo=") {
		t.Fatalf("expected vi->vim to use viminfo=, got %v", argvViVim)
	}

	argv3, _, err := ResolveEditor(func(k string) string {
		if k == "EDITOR" {
			return "nano"
		}
		return ""
	}, fakeLook)
	if err != nil || !strings.Contains(strings.Join(argv3, " "), "-I") {
		t.Fatalf("expected nano -I, got %v, %v", argv3, err)
	}

	_, warnCode, err := ResolveEditor(func(k string) string {
		if k == "VISUAL" {
			return "code"
		}
		return ""
	}, fakeLook)
	if err != nil || warnCode == "" {
		t.Fatalf("expected warning for GUI editor 'code', got warn=%q err=%v", warnCode, err)
	}
}

func TestSecureTempDirEditBytesAndPagerEnv(t *testing.T) {
	t.Parallel()
	dataDir := t.TempDir()
	tmpDir, _, err := SecureTempDir(dataDir, os.Getenv)
	if err != nil {
		t.Fatalf("SecureTempDir failed: %v", err)
	}
	st, err := os.Lstat(tmpDir)
	if err != nil || !st.IsDir() || st.Mode().Perm() != 0o700 {
		t.Fatalf("expected 0700 dir from SecureTempDir, got st=%v err=%v", st, err)
	}

	// Test EditBytesInEditor with a script editor: happy path, oversize error, and non-zero exit.
	scriptDir := t.TempDir()
	okEditor := filepath.Join(scriptDir, "ed-ok.sh")
	if err := os.WriteFile(okEditor, []byte("#!/bin/sh\nshift\nprintf 'edited-value' > \"$1\"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	failEditor := filepath.Join(scriptDir, "ed-fail.sh")
	if err := os.WriteFile(failEditor, []byte("#!/bin/sh\nexit 1\n"), 0o700); err != nil {
		t.Fatal(err)
	}

	var stderr bytes.Buffer
	got, err := EditBytesInEditor(context.Background(), dataDir, "test", []byte("orig"), 64, func(k string) string {
		if k == "EDITOR" {
			return okEditor
		}
		return ""
	}, bytes.NewReader(nil), io.Discard, &stderr, nil)
	if err != nil || string(got) != "edited-value" {
		t.Fatalf("EditBytesInEditor happy path = (%q, %v)", string(got), err)
	}

	if _, err := EditBytesInEditor(context.Background(), dataDir, "test", []byte("orig"), 4, func(k string) string {
		if k == "EDITOR" {
			return okEditor
		}
		return ""
	}, bytes.NewReader(nil), io.Discard, &stderr, nil); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("expected oversize error from EditBytesInEditor, got %v", err)
	}

	if _, err := EditBytesInEditor(context.Background(), dataDir, "test", []byte("orig"), 64, func(k string) string {
		if k == "EDITOR" {
			return failEditor
		}
		return ""
	}, bytes.NewReader(nil), io.Discard, &stderr, nil); err == nil {
		t.Fatal("expected error from non-zero editor exit")
	}

	// Test ViewInPager sets LESSSECURE=1 and LESSHISTFILE=-.
	pagerScript := filepath.Join(scriptDir, "pager.sh")
	if err := os.WriteFile(pagerScript, []byte("#!/bin/sh\nprintf 'LESSSECURE=%s LESSHISTFILE=%s\n' \"$LESSSECURE\" \"$LESSHISTFILE\"\ncat\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	var pagerOut bytes.Buffer
	ViewInPager(context.Background(), "hello pager", func(k string) string {
		if k == "PAGER" {
			return pagerScript
		}
		return ""
	}, bytes.NewReader(nil), &pagerOut, &stderr, nil)
	if !strings.Contains(pagerOut.String(), "LESSSECURE=1 LESSHISTFILE=-") || !strings.Contains(pagerOut.String(), "hello pager") {
		t.Fatalf("unexpected pager output: %q", pagerOut.String())
	}
}

func TestAuditLoggerExternalDirSymlinkRotationAndCoalescing(t *testing.T) {
	t.Parallel()
	// Pre-existing external parent directory with mode 0755 must not be chmodded to 0700.
	extDir := t.TempDir()
	if err := os.Chmod(extDir, 0o755); err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(extDir, "audit.jsonl")
	logger, err := NewAuditLogger(logPath, nil)
	if err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(extDir)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o755 {
		t.Fatalf("NewAuditLogger modified external parent dir mode to %04o (want 0755)", st.Mode().Perm())
	}

	// Reject symlinked audit log.
	symTarget := filepath.Join(extDir, "target.jsonl")
	symPath := filepath.Join(extDir, "sym.jsonl")
	if err := os.Symlink(symTarget, symPath); err != nil {
		t.Fatal(err)
	}
	if _, err := NewAuditLogger(symPath, nil); err == nil {
		t.Fatal("expected NewAuditLogger to reject symlinked log path")
	}

	// Reject FIFO audit log without blocking.
	fifoPath := filepath.Join(extDir, "fifo.jsonl")
	if err := syscall.Mkfifo(fifoPath, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewAuditLogger(fifoPath, nil); err == nil {
		t.Fatal("expected NewAuditLogger to reject FIFO log path")
	}

	// Verify redaction and 25-count coalescing: 25 identical denials emit entry 1 and entry 25.
	for i := 0; i < 25; i++ {
		if err := logger.Log(AuditEntry{
			Sandbox:       "agbox-test",
			RemotePeer:    "127.0.0.1:1234",
			ReqID:         "req-1",
			Executable:    "curl",
			Args:          []string{"-H", "Authorization: Bearer supersecret999"},
			PolicyAction:  "deny",
			PolicyRuleID:  "deny-curl",
			OperatorEvent: "policy_deny",
			Status:        remoteproto.StatusDenied,
			ExitCode:      remoteproto.DenyExitCode,
		}); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "supersecret999") {
		t.Fatalf("secret leaked into audit log: %s", string(raw))
	}
	entries := readAuditEntries(t, logPath)
	if len(entries) != 2 || entries[0].Coalesced != 0 || entries[1].Coalesced != 25 {
		t.Fatalf("expected 2 entries with second coalesced=25, got %#v", entries)
	}

	// Verify .1 rotation when file exceeds maxAuditLogBytes.
	if err := os.Truncate(logPath, maxAuditLogBytes); err != nil {
		t.Fatal(err)
	}
	if err := logger.Log(AuditEntry{
		Sandbox:       "agbox-test",
		RemotePeer:    "127.0.0.1:1234",
		ReqID:         "req-rot",
		Executable:    "uname",
		PolicyAction:  "allow",
		OperatorEvent: "policy_allow",
		Status:        remoteproto.StatusCompleted,
		ExitCode:      0,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(logPath + ".1"); err != nil {
		t.Fatalf("expected rotated audit log %s.1: %v", logPath, err)
	}
	rotEntries := readAuditEntries(t, logPath)
	if len(rotEntries) != 1 || rotEntries[0].ReqID != "req-rot" {
		t.Fatalf("expected fresh rotated log with req-rot, got %#v", rotEntries)
	}
}

func TestPollReadLineEOFNoSpin(t *testing.T) {
	t.Parallel()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	_ = w.Close()

	b := &Broker{wakeR: -1, wakeW: -1}
	if err := b.initWakePipe(); err != nil {
		t.Fatal(err)
	}
	defer b.closeWakePipe()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, _, err = b.pollReadLine(ctx, int(r.Fd()), true, nil)
	if !errors.Is(err, io.EOF) {
		t.Fatalf("expected io.EOF on closed pipe, got %v", err)
	}
}

func TestDiscoverSandboxesDetachedNoRemoteFailFast(t *testing.T) {
	t.Parallel()
	dataDir := t.TempDir()
	runDir := filepath.Join(dataDir, "run", "det1")
	if err := os.MkdirAll(runDir, 0o700); err != nil {
		t.Fatal(err)
	}
	// OwnerPID is dead (0), RemoteBridge is false, detached marker exists -> still running.
	if err := config.SaveRunMeta(filepath.Join(runDir, "run.meta"), config.RunMeta{
		Sandbox:      "agbox-det",
		OwnerPID:     0,
		Detached:     true,
		NoRemote:     true,
		RemoteBridge: false,
	}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(runDir, "detached"), []byte("1\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	cands, err := DiscoverSandboxes(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(cands) != 1 || cands[0].Name != "agbox-det" || !cands[0].IsRunning || !cands[0].NoRemote {
		t.Fatalf("unexpected candidates: %#v", cands)
	}

	// Broker.New must fail fast before pairing when targeting a detached --no-remote sandbox.
	_, err = New(Config{
		RemoteAddr:  "127.0.0.1:1",
		SandboxName: "det",
		DataDir:     dataDir,
		NoPolicy:    true,
	})
	if err == nil || !strings.Contains(err.Error(), "--no-remote") {
		t.Fatalf("expected pre-pairing --no-remote failure, got %v", err)
	}
}

func TestPhase1GateAndSessionGrants(t *testing.T) {
	t.Parallel()
	var viewedText atomic.Value
	var editCalls atomic.Int32
	var slowEditDone atomic.Bool

	h := startBrokerHarness(t, harnessOpts{
		askTimeout: 300 * time.Millisecond,
		viewText: func(_ context.Context, text string) {
			viewedText.Store(text)
			// Sleep longer than AskTimeout to verify pager pauses the ask-timeout.
			time.Sleep(380 * time.Millisecond)
		},
		editBytes: func(_ context.Context, prefix string, content []byte) ([]byte, error) {
			switch prefix {
			case "req":
				n := editCalls.Add(1)
				if n == 1 {
					return []byte(`{bad json`), nil
				}
				if n == 2 {
					// NUL byte inside args must trigger validation retry.
					var p editRequestPayload
					_ = json.Unmarshal(content, &p)
					p.Args = []string{"bad\x00arg"}
					return json.Marshal(p)
				}
				if n == 3 {
					// Policy deny rule ("rm") must trigger validation retry.
					var p editRequestPayload
					_ = json.Unmarshal(content, &p)
					p.Executable = "rm"
					p.Args = []string{"-rf", "/"}
					return json.Marshal(p)
				}
				if n == 4 {
					// Valid edit with lower max_output_bytes and changed args.
					time.Sleep(380 * time.Millisecond)
					slowEditDone.Store(true)
					var p editRequestPayload
					_ = json.Unmarshal(content, &p)
					p.Executable = "echo"
					p.Args = []string{"edited-ok"}
					p.MaxOutputBytes = 4096
					return json.Marshal(p)
				}
				return content, nil
			case "stdin":
				if len(content) > 0 && string(content) == "oversize-trigger" {
					return bytes.Repeat([]byte("A"), remoteproto.MaxStdinBytes+1), nil
				}
				return []byte("edited-stdin\n"), nil
			default:
				return content, nil
			}
		},
	})

	// 1. [d] deny and Enter default deny both return uniform exit 126 with matching slotID.
	off := h.stdout.Len()
	slot1, ch1 := h.submitAsync(remoteproto.GuestRequest{Executable: "echo", Args: []string{"deny-me"}})
	off = h.stdout.waitFor(t, off, "Choice (", 5*time.Second)
	h.writeIn("d\n")
	resp1 := h.waitResp(ch1)
	if resp1.Status != remoteproto.StatusDenied || resp1.ExitCode != remoteproto.DenyExitCode || resp1.ReqID != slot1 || resp1.OperatorNote != "" {
		t.Fatalf("expected uniform [d] deny with slotID, got %#v", resp1)
	}

	slot2, ch2 := h.submitAsync(remoteproto.GuestRequest{Executable: "echo", Args: []string{"enter-deny"}})
	off = h.stdout.waitFor(t, off, "Choice (", 5*time.Second)
	h.writeIn("\n")
	resp2 := h.waitResp(ch2)
	if resp2.Status != remoteproto.StatusDenied || resp2.ReqID != slot2 || resp2.OperatorNote != "" {
		t.Fatalf("expected uniform Enter deny, got %#v", resp2)
	}

	// 2. Ask-timeout returns uniform deny without input.
	slot3, ch3 := h.submitAsync(remoteproto.GuestRequest{Executable: "echo", Args: []string{"timeout-me"}})
	off = h.stdout.waitFor(t, off, "Choice (", 5*time.Second)
	resp3 := h.waitResp(ch3)
	if resp3.Status != remoteproto.StatusDenied || resp3.ReqID != slot3 || resp3.OperatorNote != "" {
		t.Fatalf("expected uniform timeout deny, got %#v", resp3)
	}

	// 3. [m] deny with note.
	slot4, ch4 := h.submitAsync(remoteproto.GuestRequest{Executable: "echo", Args: []string{"note-me"}})
	off = h.stdout.waitFor(t, off, "Choice (", 5*time.Second)
	h.writeIn("m\n")
	off = h.stdout.waitFor(t, off, "Operator note", 5*time.Second)
	h.writeIn("use uname instead\n")
	resp4 := h.waitResp(ch4)
	if resp4.Status != remoteproto.StatusDenied || resp4.ReqID != slot4 || resp4.OperatorNote != "use uname instead" {
		t.Fatalf("expected [m] deny with note, got %#v", resp4)
	}

	// 4. [o] single-run output review enters Phase 2 even when global output-review is OFF.
	slot5, ch5 := h.submitAsync(remoteproto.GuestRequest{Executable: "echo", Args: []string{"one-shot-review"}})
	off = h.stdout.waitFor(t, off, "[o]utput-review+approve", 5*time.Second)
	h.writeIn("o\n")
	off = h.stdout.waitFor(t, off, "PHASE 2: OUTPUT REVIEW", 5*time.Second)
	off = h.stdout.waitFor(t, off, "Choice (", 5*time.Second)
	h.writeIn("a\n")
	resp5 := h.waitResp(ch5)
	if resp5.Status != remoteproto.StatusCompleted || resp5.ReqID != slot5 || strings.TrimSpace(decodeB64(t, resp5.StdoutB64)) != "one-shot-review" {
		t.Fatalf("expected [o] + Phase 2 [a] success, got %#v", resp5)
	}

	// 5. [e] edit loop (invalid JSON -> retry, NUL arg -> retry, deny rule -> retry, valid slow edit -> diff + [EDITED]) + [s] session grant with lower max_output_bytes.
	slot6, ch6 := h.submitAsync(remoteproto.GuestRequest{Executable: "echo", Args: []string{"orig-arg"}})
	off = h.stdout.waitFor(t, off, "Choice (", 5*time.Second)
	h.writeIn("e\n")
	// Retry 1: invalid JSON.
	off = h.stdout.waitFor(t, off, "[e] re-edit draft", 5*time.Second)
	h.writeIn("e\n")
	// Retry 2: NUL arg.
	off = h.stdout.waitFor(t, off, "[e] re-edit draft", 5*time.Second)
	h.writeIn("e\n")
	// Retry 3: deny rule violation.
	off = h.stdout.waitFor(t, off, "[e] re-edit draft", 5*time.Second)
	h.writeIn("e\n")
	// Attempt 4 succeeds after >AskTimeout sleep and shows Diff + [EDITED].
	off = h.stdout.waitFor(t, off, "[EDITED]", 5*time.Second)
	off = h.stdout.waitFor(t, off, "Choice (", 5*time.Second)
	if !slowEditDone.Load() {
		t.Fatal("expected slow edit to complete without timing out")
	}
	h.writeIn("s\n")
	resp6 := h.waitResp(ch6)
	if resp6.Status != remoteproto.StatusCompleted || resp6.ReqID != slot6 || strings.TrimSpace(decodeB64(t, resp6.StdoutB64)) != "edited-ok" {
		t.Fatalf("expected edited command approved with [s] to succeed, got %#v", resp6)
	}

	// 6. Subsequent identical request matches the exact session grant (even with operator-edited max_output_bytes=4096) without prompting!
	slot7, ch7 := h.submitAsync(remoteproto.GuestRequest{Executable: "echo", Args: []string{"edited-ok"}})
	resp7 := h.waitResp(ch7)
	if resp7.Status != remoteproto.StatusCompleted || resp7.ReqID != slot7 || strings.TrimSpace(decodeB64(t, resp7.StdoutB64)) != "edited-ok" {
		t.Fatalf("expected session grant auto-allow, got %#v", resp7)
	}

	// Modified argument does NOT match session grant and prompts Phase 1.
	_, ch8 := h.submitAsync(remoteproto.GuestRequest{Executable: "echo", Args: []string{"different-arg"}})
	off = h.stdout.waitFor(t, off, "Choice (", 5*time.Second)
	h.writeIn("d\n")
	if r := h.waitResp(ch8); r.Status != remoteproto.StatusDenied {
		t.Fatalf("expected modified arg to require Phase 1, got %#v", r)
	}

	// Non-empty stdin does NOT match session grant and hides [s]. Also test [v] pager pause + [i] stdin edit + 256 KiB cap.
	_, ch9 := h.submitAsync(remoteproto.GuestRequest{
		Executable: "cat",
		StdinB64:   base64.StdEncoding.EncodeToString([]byte("oversize-trigger")),
	})
	off = h.stdout.waitFor(t, off, "oversize-trigger", 5*time.Second)
	off = h.stdout.waitFor(t, off, "[v]iew-stdin", 5*time.Second)
	promptSlice := h.stdout.String()[off-120:]
	if strings.Contains(promptSlice, "[s]ession-exact") {
		t.Fatalf("expected [s] hidden when stdin is non-empty, got %q", promptSlice)
	}
	// [v] pauses timeout (>AskTimeout).
	h.writeIn("v\n")
	off = h.stdout.waitFor(t, off, "Choice (", 5*time.Second)
	if gotV, _ := viewedText.Load().(string); !strings.Contains(gotV, "oversize-trigger") {
		t.Fatalf("expected pager to receive stdin, got %q", gotV)
	}
	// [i] returning >256 KiB rejects edit and preserves previous stdin.
	h.writeIn("i\n")
	off = h.stdout.waitFor(t, off, "Choice (", 5*time.Second)
	if !strings.Contains(h.stderr.String(), "exceeds") {
		t.Fatalf("expected oversize stdin warning in stderr, got %q", h.stderr.String())
	}
	h.writeIn("d\n")
	_ = h.waitResp(ch9)

	// Valid [i] UTF-8 stdin edit succeeds and sends edited stdin to cat.
	_, ch10 := h.submitAsync(remoteproto.GuestRequest{
		Executable: "cat",
		StdinB64:   base64.StdEncoding.EncodeToString([]byte("orig-stdin\n")),
	})
	off = h.stdout.waitFor(t, off, "orig-stdin", 5*time.Second)
	off = h.stdout.waitFor(t, off, "[i]edit-stdin", 5*time.Second)
	h.writeIn("i\n")
	off = h.stdout.waitFor(t, off, "[EDITED]", 5*time.Second)
	off = h.stdout.waitFor(t, off, "Choice (", 5*time.Second)
	h.writeIn("a\n")
	resp10 := h.waitResp(ch10)
	if resp10.Status != remoteproto.StatusCompleted || decodeB64(t, resp10.StdoutB64) != "edited-stdin\n" {
		t.Fatalf("expected edited stdin to reach cat, got %#v", resp10)
	}

	// Interpreter hides [s] session grant option.
	_, ch11 := h.submitAsync(remoteproto.GuestRequest{Executable: "python3", Args: []string{"-V"}})
	off = h.stdout.waitFor(t, off, "python3", 5*time.Second)
	off = h.stdout.waitFor(t, off, "Choice (", 5*time.Second)
	lineStart := strings.LastIndex(h.stdout.String()[:off], "Choice (")
	fullChoice := h.stdout.String()[lineStart:]
	if strings.Contains(fullChoice, "[s]ession-exact") {
		t.Fatalf("expected [s] hidden for interpreter python3, got %q", fullChoice)
	}
	h.writeIn("d\n")
	_ = h.waitResp(ch11)

	// Verify pre-editor wait time is NOT refunded (M7):
	// AskTimeout is 300ms. Wait 180ms, press [v] (which runs without deducting time),
	// then wait at the returned prompt -> remaining budget is ~120ms, NOT refunded to 300ms.
	_, ch12 := h.submitAsync(remoteproto.GuestRequest{
		Executable: "cat",
		StdinB64:   base64.StdEncoding.EncodeToString([]byte("budget-check")),
	})
	off = h.stdout.waitFor(t, off, "budget-check", 5*time.Second)
	off = h.stdout.waitFor(t, off, "Choice (", 5*time.Second)
	time.Sleep(180 * time.Millisecond)
	h.writeIn("v\n")
	off = h.stdout.waitFor(t, off, "Choice (", 5*time.Second)
	startWait := time.Now()
	resp12 := h.waitResp(ch12)
	waited := time.Since(startWait)
	if resp12.Status != remoteproto.StatusDenied {
		t.Fatalf("expected timeout deny after non-refunded pre-pager wait, got %#v", resp12)
	}
	if waited > 260*time.Millisecond {
		t.Fatalf("pre-pager wait appears to have been refunded (waited %v after pager)", waited)
	}

	// Verify reloaded deny rule overrides existing session grant for `echo edited-ok`.
	denyEchoPol := `{
	  "version": 1,
	  "default_action": "ask",
	  "rules": [{"id": "deny-echo", "action": "deny", "executables": ["echo"]}]
	}`
	if err := os.WriteFile(h.polPath, []byte(denyEchoPol), 0o600); err != nil {
		t.Fatal(err)
	}
	_, ch13 := h.submitAsync(remoteproto.GuestRequest{Executable: "echo", Args: []string{"edited-ok"}})
	if r := h.waitResp(ch13); r.Status != remoteproto.StatusDenied {
		t.Fatalf("expected reloaded deny rule to override session grant, got %#v", r)
	}

	h.quit()
}

func TestPhase2OutputReviewModes(t *testing.T) {
	t.Parallel()
	var viewed atomic.Value
	h := startBrokerHarness(t, harnessOpts{
		outputReview: true,
		askTimeout:   300 * time.Millisecond,
		viewText: func(_ context.Context, text string) {
			viewed.Store(text)
		},
		editBytes: func(_ context.Context, prefix string, content []byte) ([]byte, error) {
			return []byte("redacted-" + prefix + "\n"), nil
		},
	})

	// 1. [a] approve redacted output + [r] single-stream stdout edit + [v] pager.
	off := h.stdout.Len()
	slot1, ch1 := h.submitAsync(remoteproto.GuestRequest{Executable: "echo", Args: []string{"hello-stdout"}})
	off = h.stdout.waitFor(t, off, "Choice (", 5*time.Second)
	h.writeIn("a\n")
	off = h.stdout.waitFor(t, off, "[r]edact-stdout", 5*time.Second)
	h.writeIn("v\n")
	off = h.stdout.waitFor(t, off, "Choice (", 5*time.Second)
	if got, _ := viewed.Load().(string); !strings.Contains(got, "hello-stdout") {
		t.Fatalf("expected pager to show stdout, got %q", got)
	}
	h.writeIn("r\n")
	off = h.stdout.waitFor(t, off, "redacted-stdout", 5*time.Second)
	off = h.stdout.waitFor(t, off, "Choice (", 5*time.Second)
	h.writeIn("a\n")
	resp1 := h.waitResp(ch1)
	if resp1.Status != remoteproto.StatusCompleted || resp1.ReqID != slot1 || decodeB64(t, resp1.StdoutB64) != "redacted-stdout\n" {
		t.Fatalf("expected [r] redacted stdout, got %#v", resp1)
	}

	// 2. [r1] and [r2] when both stdout and stderr are non-empty UTF-8 (use python3 writing both streams).
	_, ch2 := h.submitAsync(remoteproto.GuestRequest{
		Executable: "python3",
		Args:       []string{"-c", "import sys; sys.stdout.write('out1\\n'); sys.stderr.write('err1\\n')"},
	})
	off = h.stdout.waitFor(t, off, "Choice (", 5*time.Second)
	h.writeIn("a\n")
	off = h.stdout.waitFor(t, off, "[r1]redact-stdout", 5*time.Second)
	h.writeIn("r1\n")
	off = h.stdout.waitFor(t, off, "Choice (", 5*time.Second)
	h.writeIn("r2\n")
	off = h.stdout.waitFor(t, off, "Choice (", 5*time.Second)
	h.writeIn("a\n")
	resp2 := h.waitResp(ch2)
	if decodeB64(t, resp2.StdoutB64) != "redacted-stdout\n" || decodeB64(t, resp2.StderrB64) != "redacted-stderr\n" {
		t.Fatalf("expected r1/r2 edited streams, got out=%q err=%q", decodeB64(t, resp2.StdoutB64), decodeB64(t, resp2.StderrB64))
	}

	// 3. [x] drop output preserves non-zero exit code with empty streams and DroppedOutput=true.
	_, ch3 := h.submitAsync(remoteproto.GuestRequest{
		Executable: "python3",
		Args:       []string{"-c", "import sys; print('secret'); sys.exit(7)"},
	})
	off = h.stdout.waitFor(t, off, "Choice (", 5*time.Second)
	h.writeIn("a\n")
	off = h.stdout.waitFor(t, off, "[x]drop-output", 5*time.Second)
	h.writeIn("x\n")
	resp3 := h.waitResp(ch3)
	if resp3.Status != remoteproto.StatusCompleted || resp3.ExitCode != 7 || !resp3.DroppedOutput || resp3.StdoutB64 != "" || resp3.StderrB64 != "" {
		t.Fatalf("expected [x] drop output preserving exit 7, got %#v", resp3)
	}

	// 4. Binary output hides [r] while allowing [v] (receiving escaped binary!) and [a].
	viewed.Store("")
	_, ch4 := h.submitAsync(remoteproto.GuestRequest{
		Executable: "python3",
		Args:       []string{"-c", "import sys; sys.stdout.buffer.write(b'bin\\x00\\xffdata')"},
	})
	off = h.stdout.waitFor(t, off, "Choice (", 5*time.Second)
	h.writeIn("a\n")
	off = h.stdout.waitFor(t, off, "PHASE 2: OUTPUT REVIEW", 5*time.Second)
	off = h.stdout.waitFor(t, off, "Choice (", 5*time.Second)
	choiceLine := h.stdout.String()[strings.LastIndex(h.stdout.String()[:off], "Choice ("):]
	if strings.Contains(choiceLine, "[r]") || strings.Contains(choiceLine, "[r1]") {
		t.Fatalf("expected binary output to hide [r] edit actions, got %q", choiceLine)
	}
	h.writeIn("v\n")
	off = h.stdout.waitFor(t, off, "Choice (", 5*time.Second)
	gotBinView, _ := viewed.Load().(string)
	if !strings.Contains(gotBinView, `\x00`) || !strings.Contains(gotBinView, "bin") {
		t.Fatalf("expected [v] on binary output to pass sanitized binary to pager, got %q", gotBinView)
	}
	h.writeIn("a\n")
	resp4 := h.waitResp(ch4)
	if resp4.Status != remoteproto.StatusCompleted || decodeB64(t, resp4.StdoutB64) != "bin\x00\xffdata" {
		t.Fatalf("expected binary output approved cleanly, got %#v", resp4)
	}

	// 5. Phase 2 [m] deny with note, [d] uniform deny, and timeout uniform deny.
	_, ch5 := h.submitAsync(remoteproto.GuestRequest{Executable: "echo", Args: []string{"p2-note"}})
	off = h.stdout.waitFor(t, off, "Choice (", 5*time.Second)
	h.writeIn("a\n")
	off = h.stdout.waitFor(t, off, "PHASE 2: OUTPUT REVIEW", 5*time.Second)
	off = h.stdout.waitFor(t, off, "Choice (", 5*time.Second)
	h.writeIn("m\n")
	off = h.stdout.waitFor(t, off, "Operator note", 5*time.Second)
	h.writeIn("contained secret\n")
	resp5 := h.waitResp(ch5)
	if resp5.Status != remoteproto.StatusDenied || resp5.OperatorNote != "contained secret" {
		t.Fatalf("expected Phase 2 [m] deny with note, got %#v", resp5)
	}

	_, ch6 := h.submitAsync(remoteproto.GuestRequest{Executable: "echo", Args: []string{"p2-deny"}})
	off = h.stdout.waitFor(t, off, "Choice (", 5*time.Second)
	h.writeIn("a\n")
	off = h.stdout.waitFor(t, off, "PHASE 2: OUTPUT REVIEW", 5*time.Second)
	off = h.stdout.waitFor(t, off, "Choice (", 5*time.Second)
	h.writeIn("d\n")
	resp6 := h.waitResp(ch6)
	if resp6.Status != remoteproto.StatusDenied || resp6.OperatorNote != "" {
		t.Fatalf("expected Phase 2 [d] uniform deny, got %#v", resp6)
	}

	_, ch7 := h.submitAsync(remoteproto.GuestRequest{Executable: "echo", Args: []string{"p2-timeout"}})
	off = h.stdout.waitFor(t, off, "Choice (", 5*time.Second)
	h.writeIn("a\n")
	off = h.stdout.waitFor(t, off, "PHASE 2: OUTPUT REVIEW", 5*time.Second)
	off = h.stdout.waitFor(t, off, "Choice (", 5*time.Second)
	resp7 := h.waitResp(ch7)
	if resp7.Status != remoteproto.StatusDenied || resp7.OperatorNote != "" {
		t.Fatalf("expected Phase 2 timeout uniform deny, got %#v", resp7)
	}

	h.quit()
}

func TestPhase1PolicyHotReloadTOCTOU(t *testing.T) {
	t.Parallel()
	h := startBrokerHarness(t, harnessOpts{})

	// Open Phase 1 prompt, then corrupt the policy file while Phase 1 is open.
	off := h.stdout.Len()
	_, ch1 := h.submitAsync(remoteproto.GuestRequest{Executable: "echo", Args: []string{"toctou-corrupt"}})
	off = h.stdout.waitFor(t, off, "Choice (", 5*time.Second)
	if err := os.WriteFile(h.polPath, []byte(`{corrupt json`), 0o600); err != nil {
		t.Fatal(err)
	}
	h.writeIn("a\n")
	resp1 := h.waitResp(ch1)
	if resp1.Status != remoteproto.StatusDenied {
		t.Fatalf("expected Phase 1 [a] to fail closed after corrupt policy reload, got %#v", resp1)
	}

	// Restore valid policy, open Phase 1, then add a deny rule for echo before pressing [a].
	if err := os.WriteFile(h.polPath, remotepolicy.StarterPolicyJSON(), 0o600); err != nil {
		t.Fatal(err)
	}
	_, ch2 := h.submitAsync(remoteproto.GuestRequest{Executable: "echo", Args: []string{"toctou-deny"}})
	off = h.stdout.waitFor(t, off, "Choice (", 5*time.Second)
	denyPol := `{"version":1,"default_action":"ask","rules":[{"id":"deny-echo","action":"deny","executables":["echo"]}]}`
	if err := os.WriteFile(h.polPath, []byte(denyPol), 0o600); err != nil {
		t.Fatal(err)
	}
	h.writeIn("a\n")
	resp2 := h.waitResp(ch2)
	if resp2.Status != remoteproto.StatusDenied {
		t.Fatalf("expected Phase 1 [a] to fail closed when deny rule added during prompt, got %#v", resp2)
	}

	h.quit()
}

func TestCLIRedactPatternIndependentOfPolicy(t *testing.T) {
	t.Parallel()
	// Policy disables auto_redact and has 60 extra patterns. CLI adds 60 patterns (120 combined > 100).
	polExtra := make([]string, 60)
	cliExtra := make([]string, 60)
	for i := 0; i < 60; i++ {
		polExtra[i] = fmt.Sprintf("POL_PAT_%02d", i)
		cliExtra[i] = fmt.Sprintf("CLI_PAT_%02d", i)
	}
	cliExtra[0] = `CUSTOM_SECRET_[0-9]+`
	enabledFalse := false
	pol := remotepolicy.Policy{
		Version:       1,
		DefaultAction: remotepolicy.ActionAsk,
		AutoRedact: remotepolicy.AutoRedactConfig{
			Enabled:       &enabledFalse,
			ExtraPatterns: polExtra,
		},
		Rules: []remotepolicy.Rule{{
			ID:          "allow-echo",
			Action:      remotepolicy.ActionAllow,
			Executables: []string{"echo"},
			Args:        remotepolicy.ArgsMatcher{AllowAnyArgs: true},
		}},
	}
	polBytes, err := json.Marshal(pol)
	if err != nil {
		t.Fatal(err)
	}

	h := startBrokerHarness(t, harnessOpts{
		policyJSON:          polBytes,
		extraRedactPatterns: cliExtra,
	})

	// Even with policy auto_redact.enabled=false, CLI --redact-pattern still redacts!
	_, ch := h.submitAsync(remoteproto.GuestRequest{
		Executable: "echo",
		Args:       []string{"val=CUSTOM_SECRET_4242"},
	})
	resp := h.waitResp(ch)
	out := decodeB64(t, resp.StdoutB64)
	if resp.Status != remoteproto.StatusCompleted || strings.Contains(out, "CUSTOM_SECRET_4242") || !strings.Contains(out, "[REDACTED:CUSTOM]") || resp.RedactedCount < 1 {
		t.Fatalf("expected CLI --redact-pattern to apply when policy auto_redact.enabled=false, got resp=%#v out=%q", resp, out)
	}

	// Re-enable policy auto_redact with 60 policy + 60 CLI = 120 patterns (>100): both must apply without dropping patterns!
	enabledTrue := true
	pol.AutoRedact.Enabled = &enabledTrue
	polBytes, _ = json.Marshal(pol)
	if err := os.WriteFile(h.polPath, polBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	_, ch2 := h.submitAsync(remoteproto.GuestRequest{
		Executable: "echo",
		Args:       []string{"POL_PAT_59", "CUSTOM_SECRET_9999"},
	})
	resp2 := h.waitResp(ch2)
	out2 := decodeB64(t, resp2.StdoutB64)
	if strings.Contains(out2, "POL_PAT_59") || strings.Contains(out2, "CUSTOM_SECRET_9999") || resp2.RedactedCount < 2 {
		t.Fatalf("expected both policy and CLI patterns to apply when combined > 100, got resp=%#v out=%q", resp2, out2)
	}

	h.quit()
}

func TestMidFlightTCPDropResumeAndAuditAbort(t *testing.T) {
	t.Parallel()
	polJSON := `{"version":1,"default_action":"ask","rules":[
	  {"id":"allow-sleep","action":"allow","executables":["sleep"],"args":{"allow_any_args":true}},
	  {"id":"allow-echo","action":"allow","executables":["echo"],"args":{"allow_any_args":true}}
	]}`
	h := startBrokerHarness(t, harnessOpts{
		policyJSON:  []byte(polJSON),
		useTCPProxy: true,
	})

	off := h.stdout.Len()
	slot1, ch1 := h.submitAsync(remoteproto.GuestRequest{Executable: "sleep", Args: []string{"30"}})
	off = h.stdout.waitFor(t, off, "Running [", 5*time.Second)

	// Sever live TCP link mid-flight.
	h.proxy.DropActive()

	resp1 := h.waitResp(ch1)
	if resp1.Status != remoteproto.StatusDenied || resp1.ReqID != slot1 {
		t.Fatalf("expected denied response on mid-flight TCP drop, got %#v", resp1)
	}

	// Wait for automatic RESUME reconnect without re-pairing.
	off = h.stdout.waitFor(t, off, "Reconnected to remote daemon cleanly.", 5*time.Second)

	// Verify subsequent command succeeds over resumed connection (connSeq=2).
	slot2, ch2 := h.submitAsync(remoteproto.GuestRequest{Executable: "echo", Args: []string{"after-resume"}})
	resp2 := h.waitResp(ch2)
	if resp2.Status != remoteproto.StatusCompleted || resp2.ReqID != slot2 || strings.TrimSpace(decodeB64(t, resp2.StdoutB64)) != "after-resume" {
		t.Fatalf("expected command after RESUME to succeed, got %#v", resp2)
	}

	// Verify aborted execution logged an AuditEntry with *_aborted.
	entries := readAuditEntries(t, h.auditPath)
	foundAborted := false
	for _, e := range entries {
		if e.Executable == "sleep" && e.OperatorEvent == "policy_allow_aborted" && e.Status == remoteproto.StatusDenied {
			foundAborted = true
			break
		}
	}
	if !foundAborted {
		t.Fatalf("expected policy_allow_aborted audit entry for dropped sleep, got %#v", entries)
	}

	h.quit()
}

func TestCancelQueuedActivePhase1ActiveExecAndSandboxDisconnect(t *testing.T) {
	t.Parallel()
	polJSON := `{"version":1,"default_action":"ask","rules":[
	  {"id":"allow-sleep","action":"allow","executables":["sleep"],"args":{"allow_any_args":true}}
	]}`
	h := startBrokerHarness(t, harnessOpts{policyJSON: []byte(polJSON)})

	// 1. Active Phase 1 + queued cancel, then cancel active Phase 1 during [m] note prompt.
	off := h.stdout.Len()
	slotA, chA := h.submitAsync(remoteproto.GuestRequest{Executable: "echo", Args: []string{"first-active"}})
	off = h.stdout.waitFor(t, off, "Choice (", 5*time.Second)

	slotB, _ := h.submitAsync(remoteproto.GuestRequest{Executable: "echo", Args: []string{"second-queued"}})
	// Cancel queued request B while A is active.
	h.bridge.cancel(t, slotB)

	// Enter [m] note prompt on A, then cancel A from guest -> must abort [m] prompt promptly.
	h.writeIn("m\n")
	off = h.stdout.waitFor(t, off, "Operator note", 5*time.Second)
	h.bridge.cancel(t, slotA)
	respA := h.waitResp(chA)
	if respA.Status != remoteproto.StatusDenied || respA.ReqID != slotA {
		t.Fatalf("expected cancelled active Phase 1 [m] request to deny, got %#v", respA)
	}
	// Broker returns directly to Idle (queued B was purged!).
	off = h.stdout.waitFor(t, off, "Idle (sandbox=agbox-sb1", 5*time.Second)

	// 2. Active remote exec cancelled by guest unlink -> returns denied + logs aborted audit.
	slotC, chC := h.submitAsync(remoteproto.GuestRequest{Executable: "sleep", Args: []string{"30"}})
	off = h.stdout.waitFor(t, off, "Running [", 5*time.Second)
	h.bridge.cancel(t, slotC)
	respC := h.waitResp(chC)
	if respC.Status != remoteproto.StatusDenied || respC.ReqID != slotC {
		t.Fatalf("expected cancelled remote exec to deny, got %#v", respC)
	}

	// 3. Active remote exec cancelled by operator (cancelActiveRemoteExec, same path as single Ctrl-C) without dropping TLS.
	slotD, chD := h.submitAsync(remoteproto.GuestRequest{Executable: "sleep", Args: []string{"30"}})
	off = h.stdout.waitFor(t, off, "Running [", 5*time.Second)
	if !h.broker.cancelActiveRemoteExec() {
		t.Fatal("expected cancelActiveRemoteExec to cancel running sleep")
	}
	respD := h.waitResp(chD)
	if respD.Status != remoteproto.StatusDenied || respD.ReqID != slotD {
		t.Fatalf("expected operator-cancelled exec to deny, got %#v", respD)
	}

	// 4. Sandbox disconnect cancels active Phase 1 request AND purges queued requests.
	_, _ = h.submitAsync(remoteproto.GuestRequest{Executable: "echo", Args: []string{"active-on-disconnect"}})
	off = h.stdout.waitFor(t, off, "Choice (", 5*time.Second)
	_, _ = h.submitAsync(remoteproto.GuestRequest{Executable: "echo", Args: []string{"queued-on-disconnect"}})
	h.bridge.dropBrokerConn()
	// Broker logs disconnect, cancels active Phase 1, re-attaches, and returns to Idle cleanly without prompting for queued item.
	h.bridge.waitAttached(t, 5*time.Second)
	off = h.stdout.waitFor(t, off, "Idle (sandbox=agbox-sb1", 5*time.Second)
	if strings.Contains(h.stdout.String()[off-200:], "queued-on-disconnect") {
		t.Fatalf("expected queued request to be purged on sandbox disconnect")
	}

	h.quit()
}

func TestIdleMenuSwitchSandboxesAndDynamicAttach(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	if err := os.Chmod(tmpDir, 0o700); err != nil {
		t.Fatal(err)
	}
	dir1 := filepath.Join(tmpDir, "sb1")
	dir2 := filepath.Join(tmpDir, "sb2")
	if err := os.Mkdir(dir1, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(dir2, 0o700); err != nil {
		t.Fatal(err)
	}
	fb1 := newFakeBridgeSock(t, dir1)
	fb2 := newFakeBridgeSock(t, dir2)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	daemon, err := remotedaemon.New(remotedaemon.Config{
		ListenAddr: "127.0.0.1:0",
		AllowFrom:  []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")},
		AllowCWD:   []string{tmpDir},
		Stdout:     io.Discard,
		Stderr:     io.Discard,
		PromptConfirm: func(_ context.Context, _ string, _ string) (bool, error) {
			return true, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	addr, err := daemon.Listen()
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = daemon.Serve(ctx) }()
	defer daemon.Close()

	// Start with 0 sandboxes, then reveal 2 sandboxes (one ephemeral) to test dynamic wait + auto-select prompt + [w] switching!
	var candMu sync.Mutex
	var cands []SandboxCandidate

	inR, inW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}

	bOut := newSyncBuffer()
	bErr := newSyncBuffer()
	broker, err := New(Config{
		RemoteAddr: addr.String(),
		DataDir:    tmpDir,
		NoPolicy:   true,
		Stdin:      inR,
		Stdout:     bOut,
		Stderr:     bErr,
		ListSandboxes: func() ([]SandboxCandidate, error) {
			candMu.Lock()
			defer candMu.Unlock()
			return append([]SandboxCandidate(nil), cands...), nil
		},
		PromptConfirmPairing: func(_ context.Context, _ string, _ remoteproto.HelloPayload, _ string) (bool, error) {
			return true, nil
		},
	})
	if err != nil {
		_ = inR.Close()
		_ = inW.Close()
		t.Fatal(err)
	}
	brokerDone := make(chan error, 1)
	go func() { brokerDone <- broker.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		_ = inW.Close()
		select {
		case <-brokerDone:
		case <-time.After(3 * time.Second):
		}
		_ = inR.Close()
	})

	// Wait for 0-sandbox wait message.
	off := bOut.waitFor(t, 0, "Waiting for a sandbox with remote bridge", 5*time.Second)

	// Reveal 2 sandboxes -> broker must automatically display `Select sandbox [1..2] or [q]uit:`.
	candMu.Lock()
	cands = []SandboxCandidate{
		{Name: "agbox-alpha", SockPath: fb1.sockPath, HasBridge: true, IsRunning: true},
		{Name: "agbox-run-99999", SockPath: fb2.sockPath, Ephemeral: true, HasBridge: true, IsRunning: true},
	}
	candMu.Unlock()

	off = bOut.waitFor(t, off, "Select sandbox [1..2] or [q]uit:", 5*time.Second)
	_, _ = inW.WriteString("1\n")
	fb1.waitAttached(t, 5*time.Second)
	off = bOut.waitFor(t, off, "Idle (sandbox=agbox-alpha", 5*time.Second)

	// Idle [t] toggles output review ON and back OFF.
	_, _ = inW.WriteString("t\n")
	off = bOut.waitFor(t, off, "output-review=ON", 5*time.Second)
	_, _ = inW.WriteString("t\n")
	off = bOut.waitFor(t, off, "output-review=OFF", 5*time.Second)

	// Record one exact session grant on agbox-alpha, then inspect and clear it with [c].
	slot1 := fmt.Sprintf("%032x", 1)
	ch1 := fb1.submit(t, slot1, remoteproto.GuestRequest{Executable: "echo", Args: []string{"grant-me"}})
	off = bOut.waitFor(t, off, "Choice (", 5*time.Second)
	_, _ = inW.WriteString("s\n")
	select {
	case <-ch1:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for echo grant-me")
	}
	off = bOut.waitFor(t, off, "session-grants=1", 5*time.Second)

	_, _ = inW.WriteString("c\n")
	off = bOut.waitFor(t, off, "Clear all session approvals? [y/N]:", 5*time.Second)
	_, _ = inW.WriteString("y\n")
	off = bOut.waitFor(t, off, "session-grants=0", 5*time.Second)

	// Switch [w] from agbox-alpha -> agbox-run-99999 -> agbox-alpha -> agbox-run-99999
	// to confirm no leaked readBridgeLoop watcher steals switch events (H7).
	_, _ = inW.WriteString("w\n")
	off = bOut.waitFor(t, off, "Select sandbox [1..N]", 5*time.Second)
	_, _ = inW.WriteString("2\n")
	fb2.waitAttached(t, 5*time.Second)
	off = bOut.waitFor(t, off, "Idle (sandbox=agbox-run-99999", 5*time.Second)

	_, _ = inW.WriteString("w\n")
	off = bOut.waitFor(t, off, "Select sandbox [1..N]", 5*time.Second)
	_, _ = inW.WriteString("1\n")
	fb1.waitAttached(t, 5*time.Second)
	off = bOut.waitFor(t, off, "Idle (sandbox=agbox-alpha", 5*time.Second)

	_, _ = inW.WriteString("w\n")
	off = bOut.waitFor(t, off, "Select sandbox [1..N]", 5*time.Second)
	_, _ = inW.WriteString("2\n")
	fb2.waitAttached(t, 5*time.Second)
	off = bOut.waitFor(t, off, "Idle (sandbox=agbox-run-99999", 5*time.Second)

	// Now ephemeral sandbox agbox-run-99999 exits! Remove it from candidate list and drop its conn.
	// Broker must clear targetSB (CLI-M6) and auto-attach to remaining agbox-alpha!
	candMu.Lock()
	cands = []SandboxCandidate{
		{Name: "agbox-alpha", SockPath: fb1.sockPath, HasBridge: true, IsRunning: true},
	}
	candMu.Unlock()
	fb2.dropBrokerConn()

	fb1.waitAttached(t, 5*time.Second)
	off = bOut.waitFor(t, off, "Idle (sandbox=agbox-alpha", 5*time.Second)

	_, _ = inW.WriteString("q\n")
	select {
	case err := <-brokerDone:
		if err != nil {
			t.Fatalf("broker exited with error: %v", err)
		}
	case <-time.After(5 * time.Second):
		cancel()
		t.Fatal("broker did not quit cleanly")
	}
}

func TestRemotePairRejectAbortsImmediatelyAndHelloSanitizeAndFrameBye(t *testing.T) {
	t.Parallel()
	// Part 1 (M2): Remote sends PAIR_REJECT while local confirmPairing is blocked -> aborts at once.
	t.Run("peer_pair_reject_aborts_prompt", func(t *testing.T) {
		srvID, err := remoteproto.GenerateEphemeralIdentity("test-remote")
		if err != nil {
			t.Fatal(err)
		}
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()

		go func() {
			raw, err := ln.Accept()
			if err != nil {
				return
			}
			defer raw.Close()
			tc := tls.Server(raw, remoteproto.ServerTLSConfig(srvID, func() ([32]byte, bool) { return [32]byte{}, false }))
			if err := tc.Handshake(); err != nil {
				return
			}
			_, _ = remoteproto.WriteFrame(tc, remoteproto.FrameHello, remoteproto.HelloPayload{
				ProtoVer:   remoteproto.ProtocolVersion,
				Role:       "remote",
				User:       "u",
				Host:       "h",
				DefaultCWD: "/tmp",
			}, remoteproto.PreAuthMaxFrameBytes)
			_, _, _, _ = remoteproto.ReadFrame(tc, remoteproto.PreAuthMaxFrameBytes) // Hello_H
			_, _, _, _ = remoteproto.ReadFrame(tc, remoteproto.PreAuthMaxFrameBytes) // Commit_H
			nonceR, _ := remoteproto.RandomBytes32()
			_, _ = remoteproto.WriteFrame(tc, remoteproto.FrameNonce, remoteproto.NoncePayload{
				NonceHex: hex.EncodeToString(nonceR[:]),
			}, remoteproto.PreAuthMaxFrameBytes)
			_, _, _, _ = remoteproto.ReadFrame(tc, remoteproto.PreAuthMaxFrameBytes) // Reveal_H
			// Reject immediately while broker prompt is waiting!
			_, _ = remoteproto.WriteFrame(tc, remoteproto.FramePairReject, remoteproto.PairDecisionPayload{Reason: "operator rejected"}, remoteproto.PreAuthMaxFrameBytes)
		}()

		inR, inW, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		defer inR.Close()
		defer inW.Close()

		b, err := New(Config{
			RemoteAddr: ln.Addr().String(),
			DataDir:    t.TempDir(),
			NoPolicy:   true,
			Stdin:      inR,
			Stdout:     io.Discard,
			Stderr:     io.Discard,
		})
		if err != nil {
			t.Fatal(err)
		}
		start := time.Now()
		err = b.Run(context.Background())
		elapsed := time.Since(start)
		if err == nil {
			t.Fatal("expected pairing error when remote rejects")
		}
		if elapsed > 2*time.Second {
			t.Fatalf("expected prompt to abort immediately on remote PAIR_REJECT, took %v", elapsed)
		}
	})

	// Part 2 (CLI-H1 + L5): Hello_R ANSI escape sanitization in DialAttach + FrameBye triggers clean exit.
	t.Run("hello_sanitize_and_frame_bye_clean_exit", func(t *testing.T) {
		tmpDir := t.TempDir()
		fb := newFakeBridgeSock(t, tmpDir)
		srvID, err := remoteproto.GenerateEphemeralIdentity("test-remote")
		if err != nil {
			t.Fatal(err)
		}
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()

		sendByeCh := make(chan struct{})
		go func() {
			raw, err := ln.Accept()
			if err != nil {
				return
			}
			defer raw.Close()
			tc := tls.Server(raw, remoteproto.ServerTLSConfig(srvID, func() ([32]byte, bool) { return [32]byte{}, false }))
			if err := tc.Handshake(); err != nil {
				return
			}
			_, _ = remoteproto.WriteFrame(tc, remoteproto.FrameHello, remoteproto.HelloPayload{
				ProtoVer:   remoteproto.ProtocolVersion,
				Role:       "remote",
				User:       "evil\x1b[31muser",
				Host:       "bad\x07host\u202e",
				DefaultCWD: "/tmp",
			}, remoteproto.PreAuthMaxFrameBytes)
			_, _, _, _ = remoteproto.ReadFrame(tc, remoteproto.PreAuthMaxFrameBytes) // Hello_H
			_, _, _, _ = remoteproto.ReadFrame(tc, remoteproto.PreAuthMaxFrameBytes) // Commit_H
			nonceR, _ := remoteproto.RandomBytes32()
			_, _ = remoteproto.WriteFrame(tc, remoteproto.FrameNonce, remoteproto.NoncePayload{
				NonceHex: hex.EncodeToString(nonceR[:]),
			}, remoteproto.PreAuthMaxFrameBytes)
			_, _, _, _ = remoteproto.ReadFrame(tc, remoteproto.PreAuthMaxFrameBytes) // Reveal_H
			_, _ = remoteproto.WriteFrame(tc, remoteproto.FramePairAck, remoteproto.PairDecisionPayload{}, remoteproto.PreAuthMaxFrameBytes)
			_, _, _, _ = remoteproto.ReadFrame(tc, remoteproto.PreAuthMaxFrameBytes) // PairAck_H

			<-sendByeCh
			_, _ = remoteproto.WriteFrame(tc, remoteproto.FrameBye, nil, remoteproto.PostAuthMaxFrameBytes)
		}()

		inR, inW, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		defer inR.Close()
		defer inW.Close()

		bOut := newSyncBuffer()
		b, err := New(Config{
			RemoteAddr:  ln.Addr().String(),
			SandboxName: "agbox-san",
			DataDir:     tmpDir,
			NoPolicy:    true,
			Stdin:       inR,
			Stdout:      bOut,
			Stderr:      io.Discard,
			ListSandboxes: func() ([]SandboxCandidate, error) {
				return []SandboxCandidate{{
					Name:      "agbox-san",
					SockPath:  fb.sockPath,
					HasBridge: true,
					IsRunning: true,
				}}, nil
			},
			PromptConfirmPairing: func(_ context.Context, _ string, _ remoteproto.HelloPayload, _ string) (bool, error) {
				return true, nil
			},
		})
		if err != nil {
			t.Fatal(err)
		}

		done := make(chan error, 1)
		go func() { done <- b.Run(context.Background()) }()

		st := fb.waitAttached(t, 5*time.Second)
		if strings.ContainsAny(st.RemoteID, "\x1b\x07") || strings.ContainsRune(st.RemoteID, '\u202e') {
			t.Fatalf("unsanitized control/BiDi characters leaked into DialAttach RemoteID: %q", st.RemoteID)
		}
		if !strings.Contains(st.RemoteID, `\x1b`) || !strings.Contains(st.RemoteID, `\u202e`) {
			t.Fatalf("expected sanitized RemoteID escapes, got %q", st.RemoteID)
		}

		// Send FrameBye from remote -> broker must exit cleanly without reconnecting!
		close(sendByeCh)
		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("expected clean nil exit on remote FrameBye, got %v", err)
			}
		case <-time.After(3 * time.Second):
			t.Fatalf("broker did not exit cleanly after remote FrameBye\nstdout:\n%s", bOut.String())
		}
		if strings.Contains(bOut.String(), "Attempting reconnect") {
			t.Fatalf("broker attempted reconnect after clean remote FrameBye:\n%s", bOut.String())
		}
	})
}

func TestEndToEndLoopbackWithFUSEBridge(t *testing.T) {
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
	polPath := filepath.Join(tmpDir, "policy.json")
	if err := os.WriteFile(polPath, remotepolicy.StarterPolicyJSON(), 0o600); err != nil {
		t.Fatal(err)
	}

	// Start FUSE bridge with dummy client payload (ELF check disabled for CGO -race tests).
	bridge, err := remotebridge.New(remotebridge.Options{
		MountDir:         mntDir,
		SockPath:         sockPath,
		GuestUID:         uint32(os.Geteuid()),
		GuestGID:         uint32(os.Getegid()),
		ClientReader:     bytes.NewReader([]byte("dummy")),
		ClientSize:       5,
		RequireStaticELF: false,
		DenyJitterMin:    time.Millisecond,
		DenyJitterMax:    2 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := bridge.Mount(); err != nil {
		t.Skipf("FUSE mount unavailable: %v", err)
	}
	defer bridge.Close()

	// 1. Before broker attaches, agbox-remote returns uniform exit 126.
	var cOut, cErr bytes.Buffer
	rc := remoteclient.Run(context.Background(), []string{"uname", "-a"}, remoteclient.RunOptions{
		BridgeDir: mntDir,
		Stdout:    &cOut,
		Stderr:    &cErr,
	})
	if rc != remoteproto.DenyExitCode || strings.TrimSpace(cErr.String()) != remoteproto.DenyErrorMessage {
		t.Fatalf("expected uniform deny before broker attach, got rc=%d stderr=%q", rc, cErr.String())
	}

	// 2. Start remote daemon on 127.0.0.1:0.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var dOut, dErr bytes.Buffer
	sasRemoteCh := make(chan string, 1)
	daemon, err := remotedaemon.New(remotedaemon.Config{
		ListenAddr: "127.0.0.1:0",
		AllowFrom:  []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")},
		AllowCWD:   []string{tmpDir},
		Stdout:     &dOut,
		Stderr:     &dErr,
		PromptConfirm: func(_ context.Context, _ string, sas string) (bool, error) {
			sasRemoteCh <- sas
			return true, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	addr, err := daemon.Listen()
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		_ = daemon.Serve(ctx)
	}()
	defer daemon.Close()

	// 3. Start host broker connected to daemon + FUSE bridge.
	brokerInR, brokerInW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer brokerInR.Close()
	defer brokerInW.Close()

	bOut := newSyncBuffer()
	bErr := newSyncBuffer()
	sasHostCh := make(chan string, 1)
	broker, err := New(Config{
		RemoteAddr:   addr.String(),
		SandboxName:  "agbox-loopback",
		DataDir:      tmpDir,
		PolicyPath:   polPath,
		OutputReview: false,
		Stdin:        brokerInR,
		Stdout:       bOut,
		Stderr:       bErr,
		ListSandboxes: func() ([]SandboxCandidate, error) {
			return []SandboxCandidate{{
				Name:      "agbox-loopback",
				SockPath:  sockPath,
				HasBridge: true,
				IsRunning: true,
			}}, nil
		},
		PromptConfirmPairing: func(_ context.Context, _ string, _ remoteproto.HelloPayload, sas string) (bool, error) {
			sasHostCh <- sas
			return true, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	brokerDone := make(chan error, 1)
	go func() {
		brokerDone <- broker.Run(ctx)
	}()

	// Verify SAS matches identically on both sides.
	sasH := <-sasHostCh
	sasR := <-sasRemoteCh
	if sasH != sasR || len(sasH) != 14 {
		t.Fatalf("SAS mismatch: host=%q remote=%q", sasH, sasR)
	}

	// Wait for bridge attachment with explicit failure on timeout.
	attached := false
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		if st, err := remotebridge.QueryStatus(sockPath); err == nil && st.Attached {
			attached = true
			break
		}
	}
	if !attached {
		t.Fatalf("timed out waiting for FUSE bridge attachment\nstdout:\n%s\nstderr:\n%s", bOut.String(), bErr.String())
	}

	// 4. Auto-approved command (`uname -a`) executes cleanly without prompting.
	cOut.Reset()
	cErr.Reset()
	rc = remoteclient.Run(ctx, []string{"uname", "-a"}, remoteclient.RunOptions{
		BridgeDir: mntDir,
		Stdout:    &cOut,
		Stderr:    &cErr,
	})
	if rc != 0 || !strings.Contains(cOut.String(), "Linux") {
		t.Fatalf("expected uname -a auto-allow success, got rc=%d out=%q err=%q", rc, cOut.String(), cErr.String())
	}

	// 5. Auto-denied command (`rm -rf /`) returns uniform exit 126.
	cOut.Reset()
	cErr.Reset()
	rc = remoteclient.Run(ctx, []string{"rm", "-rf", "/"}, remoteclient.RunOptions{
		BridgeDir: mntDir,
		Stdout:    &cOut,
		Stderr:    &cErr,
	})
	if rc != remoteproto.DenyExitCode || strings.TrimSpace(cErr.String()) != remoteproto.DenyErrorMessage {
		t.Fatalf("expected uniform auto-deny for rm, got rc=%d err=%q", rc, cErr.String())
	}

	// 6. Ask command (`echo AKIAIOSFODNN7EXAMPLE`) approved deterministically returns redacted output.
	off := bOut.Len()
	go func() {
		bOut.waitFor(t, off, "Choice (", 5*time.Second)
		_, _ = brokerInW.WriteString("a\n")
	}()
	cOut.Reset()
	cErr.Reset()
	rc = remoteclient.Run(ctx, []string{"echo", "AKIAIOSFODNN7EXAMPLE"}, remoteclient.RunOptions{
		BridgeDir: mntDir,
		Stdout:    &cOut,
		Stderr:    &cErr,
	})
	if rc != 0 || !strings.Contains(cOut.String(), "[REDACTED:AWS_KEY]") || strings.Contains(cOut.String(), "AKIAIOSFODNN7EXAMPLE") {
		t.Fatalf("expected baseline secret redaction on approved echo, got rc=%d out=%q err=%q", rc, cOut.String(), cErr.String())
	}

	// 7. Corrupt policy hot-reloads into fail-closed DENY-ALL (even uname -a is denied).
	if err := os.WriteFile(polPath, []byte(`{corrupt json`), 0o600); err != nil {
		t.Fatal(err)
	}
	cOut.Reset()
	cErr.Reset()
	rc = remoteclient.Run(ctx, []string{"uname", "-a"}, remoteclient.RunOptions{
		BridgeDir: mntDir,
		Stdout:    &cOut,
		Stderr:    &cErr,
	})
	if rc != remoteproto.DenyExitCode {
		t.Fatalf("expected DENY-ALL after corrupt policy reload, got rc=%d out=%q err=%q", rc, cOut.String(), cErr.String())
	}

	// Clean quit with [q].
	_, _ = brokerInW.WriteString("q\n")
	select {
	case err := <-brokerDone:
		if err != nil {
			t.Fatalf("broker exited with error: %v", err)
		}
	case <-time.After(3 * time.Second):
		cancel()
		t.Fatal("broker did not exit cleanly on [q]")
	}
}
