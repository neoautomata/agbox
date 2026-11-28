package remotedaemon

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/user"
	"runtime"
	"strings"
	"sync"
	"time"

	"agbox/internal/remoteproto"

	"golang.org/x/sys/unix"
)

const (
	maxConcurrentPreAuth = 4
	defaultIdleTimeout   = 4 * time.Hour
	defaultReconnGrace   = 5 * time.Minute
)

// Config configures the remote target daemon (agbox remote serve).
type Config struct {
	ListenAddr     string
	AllowFrom      []netip.Prefix
	AllowCWD       []string
	PathOverride   string
	StrictPath     bool
	PassEnv        []string
	MaxOutputBytes int
	MaxStdinBytes  int
	ExecTimeout    time.Duration
	IdleTimeout    time.Duration
	ReconnectGrace time.Duration
	AllowNewPrivs  bool
	AllowRoot      bool

	Stdin         io.Reader
	Stdout        io.Writer
	Stderr        io.Writer
	IsTTY         func() bool
	PromptConfirm func(ctx context.Context, peerAddr, sas string) (bool, error)
}

type ipBackoff struct {
	failures int
	until    time.Time
}

// Daemon serves the TLS 1.3 mTLS remote command execution target.
type Daemon struct {
	cfg     Config
	execCfg ExecConfig
	id      remoteproto.EphemeralIdentity
	userStr string
	uid     int
	hostStr string

	ln net.Listener

	preAuthSem chan struct{}
	promptMu   sync.Mutex
	promptBusy bool

	rateMu    sync.Mutex
	rateState map[netip.Addr]*ipBackoff

	logMu sync.Mutex

	idleMu    sync.Mutex
	idleTimer *time.Timer

	sessMu           sync.Mutex
	paired           bool
	pinnedFP         [32]byte
	sessionID        [32]byte
	activeSeq        uint64
	activeConn       *tls.Conn
	activeConnCancel context.CancelFunc
	activeWriteMu    sync.Mutex
	cmdMu            sync.Mutex
	activeCmdID      string
	activeCancel     context.CancelFunc
	activeCmdDone    chan struct{}
	graceTimer       *time.Timer
	doneCh           chan struct{}
	doneOnce         sync.Once
}

func (d *Daemon) logOut(format string, args ...any) {
	d.logMu.Lock()
	_, _ = fmt.Fprintf(d.cfg.Stdout, format, args...)
	d.logMu.Unlock()
}

func (d *Daemon) logErr(format string, args ...any) {
	d.logMu.Lock()
	_, _ = fmt.Fprintf(d.cfg.Stderr, format, args...)
	d.logMu.Unlock()
}

func (d *Daemon) resetIdleTimer() {
	d.idleMu.Lock()
	if d.idleTimer != nil {
		d.idleTimer.Reset(d.cfg.IdleTimeout)
	}
	d.idleMu.Unlock()
}

// New validates Config, sweeps unexpected FDs, sanitizes PATH, canonicalizes CWD,
// and prepares a Daemon ready to Listen and Serve.
func New(cfg Config) (*Daemon, error) {
	SweepUnexpectedFDs()

	if cfg.ListenAddr == "" {
		cfg.ListenAddr = ":0"
	}
	if cfg.MaxOutputBytes <= 0 {
		cfg.MaxOutputBytes = remoteproto.DefaultOutputBytes
	}
	if cfg.MaxOutputBytes > remoteproto.MaxOutputBytes {
		return nil, fmt.Errorf("--max-output %d exceeds hard limit %d bytes", cfg.MaxOutputBytes, remoteproto.MaxOutputBytes)
	}
	if cfg.MaxStdinBytes <= 0 {
		cfg.MaxStdinBytes = remoteproto.MaxStdinBytes
	}
	if cfg.MaxStdinBytes > remoteproto.MaxStdinBytes {
		return nil, fmt.Errorf("--max-stdin %d exceeds hard limit %d bytes", cfg.MaxStdinBytes, remoteproto.MaxStdinBytes)
	}
	if cfg.ExecTimeout <= 0 {
		cfg.ExecTimeout = time.Duration(remoteproto.DefaultExecTimeoutSec) * time.Second
	}
	if cfg.IdleTimeout <= 0 {
		cfg.IdleTimeout = defaultIdleTimeout
	}
	if cfg.ReconnectGrace <= 0 {
		cfg.ReconnectGrace = defaultReconnGrace
	}
	if cfg.Stdin == nil {
		cfg.Stdin = os.Stdin
	}
	if cfg.Stdout == nil {
		cfg.Stdout = os.Stdout
	}
	if cfg.Stderr == nil {
		cfg.Stderr = os.Stderr
	}

	for _, envVar := range cfg.PassEnv {
		if err := ValidatePassEnv(envVar); err != nil {
			return nil, err
		}
	}

	// Normalize all --allow-from prefixes via Addr().Unmap() for dual-stack IPv4-mapped IPv6 parity.
	normAllow := make([]netip.Prefix, 0, len(cfg.AllowFrom))
	for _, pfx := range cfg.AllowFrom {
		u := pfx.Addr().Unmap()
		bits := pfx.Bits()
		if pfx.Addr().Is4In6() && bits >= 96 {
			bits -= 96
		}
		normAllow = append(normAllow, netip.PrefixFrom(u, bits).Masked())
	}
	cfg.AllowFrom = normAllow

	canonAllowCWD := make([]string, 0, len(cfg.AllowCWD))
	for _, dir := range cfg.AllowCWD {
		c, err := CanonicalizeDir(dir)
		if err != nil {
			return nil, fmt.Errorf("invalid --allow-cwd %q: %w", dir, err)
		}
		canonAllowCWD = append(canonAllowCWD, c)
	}

	defaultCWD := ""
	if len(canonAllowCWD) > 0 {
		defaultCWD = canonAllowCWD[0]
	} else {
		wd, err := os.Getwd()
		if err != nil {
			return nil, fmt.Errorf("determine working directory: %w", err)
		}
		c, err := CanonicalizeDir(wd)
		if err != nil {
			return nil, fmt.Errorf("canonicalize working directory: %w", err)
		}
		defaultCWD = c
	}

	euid := os.Geteuid()
	rawPath := os.Getenv("PATH")
	if cfg.PathOverride != "" {
		rawPath = cfg.PathOverride
	}
	sanitizedPATH := SanitizePATH(rawPath, cfg.StrictPath, euid)

	id, err := remoteproto.GenerateEphemeralIdentity("agbox-remote-daemon")
	if err != nil {
		return nil, err
	}
	uName := fmt.Sprintf("uid-%d", euid)
	if u, err := user.Current(); err == nil && u.Username != "" {
		uName = u.Username
	}
	hName, _ := os.Hostname()
	if hName == "" {
		hName = "remote"
	}

	return &Daemon{
		cfg: cfg,
		execCfg: ExecConfig{
			SanitizedPATH:  sanitizedPATH,
			DefaultCWD:     defaultCWD,
			AllowCWD:       canonAllowCWD,
			PassEnv:        append([]string(nil), cfg.PassEnv...),
			MaxOutputBytes: cfg.MaxOutputBytes,
			MaxStdinBytes:  cfg.MaxStdinBytes,
			ExecTimeout:    cfg.ExecTimeout,
			AllowNewPrivs:  cfg.AllowNewPrivs,
		},
		id:         id,
		userStr:    uName,
		uid:        euid,
		hostStr:    hName,
		preAuthSem: make(chan struct{}, maxConcurrentPreAuth),
		rateState:  make(map[netip.Addr]*ipBackoff),
		doneCh:     make(chan struct{}),
	}, nil
}

// Listen binds the TCP listener and returns the bound address.
func (d *Daemon) Listen() (net.Addr, error) {
	ln, err := net.Listen("tcp", d.cfg.ListenAddr)
	if err != nil {
		return nil, fmt.Errorf("listen on %s: %w", d.cfg.ListenAddr, err)
	}
	d.ln = ln
	return ln.Addr(), nil
}

// PrintBanner prints reachable endpoints, security warnings, and active execution settings.
func (d *Daemon) PrintBanner() {
	if d.ln == nil {
		return
	}
	tcpAddr, ok := d.ln.Addr().(*net.TCPAddr)
	if !ok {
		d.logOut("[agbox-remote-serve] Listening on %s\n", d.ln.Addr().String())
		return
	}
	port := tcpAddr.Port
	bindIP := tcpAddr.IP
	isAll := bindIP == nil || bindIP.IsUnspecified()

	d.logOut("[agbox-remote-serve] Identity: %s@%s (uid=%d, %s/%s)\n", d.userStr, d.hostStr, d.uid, runtime.GOOS, runtime.GOARCH)
	d.logOut("[agbox-remote-serve] Default cwd: %s\n", d.execCfg.DefaultCWD)
	d.logOut("[agbox-remote-serve] Sanitized PATH: %s\n", d.execCfg.SanitizedPATH)
	if isAll {
		addrs := discoverReachableIPs()
		if len(addrs) > 0 {
			d.logOut("[agbox-remote-serve] Listening on port %d. Connect from host:\n", port)
			d.logOut("  agbox remote connect %s\n", net.JoinHostPort(addrs[0], fmt.Sprintf("%d", port)))
			if len(addrs) > 1 {
				d.logOut("[agbox-remote-serve] Other reachable addresses:\n")
				for _, ip := range addrs[1:] {
					d.logOut("  %s\n", net.JoinHostPort(ip, fmt.Sprintf("%d", port)))
				}
			}
		} else {
			d.logOut("[agbox-remote-serve] Listening on 0.0.0.0:%d\n", port)
		}
		if len(d.cfg.AllowFrom) == 0 {
			d.logErr("[agbox-remote-serve] WARN: listening on all interfaces without --allow-from. Restrict access with --allow-from or a host firewall.\n")
		}
	} else {
		hostPort := net.JoinHostPort(bindIP.String(), fmt.Sprintf("%d", port))
		d.logOut("[agbox-remote-serve] Listening on %s. Connect from host:\n", hostPort)
		d.logOut("  agbox remote connect %s\n", hostPort)
	}
	d.logOut("[agbox-remote-serve] Waiting for host broker connection...\n")
}

// Serve accepts connections until ctx is canceled, BYE arrives, idle timeout fires, or reconnect grace expires.
func (d *Daemon) Serve(ctx context.Context) error {
	if d.ln == nil {
		if _, err := d.Listen(); err != nil {
			return err
		}
	}
	defer d.Close()

	serveCtx, cancelServe := context.WithCancel(ctx)
	defer cancelServe()

	idleTimer := time.NewTimer(d.cfg.IdleTimeout)
	d.idleMu.Lock()
	d.idleTimer = idleTimer
	d.idleMu.Unlock()
	defer func() {
		d.idleMu.Lock()
		if d.idleTimer == idleTimer {
			d.idleTimer = nil
		}
		d.idleMu.Unlock()
		idleTimer.Stop()
	}()

	go func() {
		select {
		case <-serveCtx.Done():
		case <-d.doneCh:
			cancelServe()
		case <-idleTimer.C:
			d.logErr("[agbox-remote-serve] Idle timeout reached. Exiting.\n")
			cancelServe()
		}
		_ = d.ln.Close()
	}()

	for {
		rawConn, err := d.ln.Accept()
		if err != nil {
			if serveCtx.Err() != nil {
				return nil
			}
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			continue
		}
		go d.handleConn(serveCtx, rawConn)
	}
}

// Close stops the listener, active connection, and any running command.
func (d *Daemon) Close() {
	d.doneOnce.Do(func() {
		close(d.doneCh)
	})
	if d.ln != nil {
		_ = d.ln.Close()
	}
	d.cancelActiveCommand()
	d.sessMu.Lock()
	if d.graceTimer != nil {
		d.graceTimer.Stop()
		d.graceTimer = nil
	}
	oldCancel := d.activeConnCancel
	d.activeConnCancel = nil
	if d.activeConn != nil {
		_ = d.activeConn.Close()
		d.activeConn = nil
	}
	d.sessMu.Unlock()
	if oldCancel != nil {
		oldCancel()
	}
}

func (d *Daemon) allowPeerIP(addr net.Addr) (netip.Addr, bool) {
	tcpAddr, ok := addr.(*net.TCPAddr)
	if !ok {
		return netip.Addr{}, false
	}
	ip, ok := netip.AddrFromSlice(tcpAddr.IP)
	if !ok {
		return netip.Addr{}, false
	}
	ip = ip.Unmap()
	if len(d.cfg.AllowFrom) == 0 {
		return ip, true
	}
	for _, pfx := range d.cfg.AllowFrom {
		if pfx.Contains(ip) {
			return ip, true
		}
	}
	return ip, false
}

func (d *Daemon) checkRateLimit(ip netip.Addr) bool {
	d.rateMu.Lock()
	defer d.rateMu.Unlock()
	st, ok := d.rateState[ip]
	if !ok {
		return true
	}
	return !time.Now().Before(st.until)
}

func (d *Daemon) recordFailure(ip netip.Addr) {
	d.rateMu.Lock()
	defer d.rateMu.Unlock()
	st, ok := d.rateState[ip]
	if !ok {
		if len(d.rateState) > 1024 {
			clear(d.rateState)
		}
		st = &ipBackoff{}
		d.rateState[ip] = st
	}
	st.failures++
	shift := st.failures - 1
	if shift > 5 {
		shift = 5
	}
	backoff := time.Second << shift
	st.until = time.Now().Add(backoff)
}

func (d *Daemon) getPinnedClientFP() ([32]byte, bool) {
	d.sessMu.Lock()
	defer d.sessMu.Unlock()
	return d.pinnedFP, d.paired
}

func (d *Daemon) handleConn(ctx context.Context, rawConn net.Conn) {
	defer rawConn.Close()

	peerIP, allowed := d.allowPeerIP(rawConn.RemoteAddr())
	if !allowed {
		return
	}
	if !d.checkRateLimit(peerIP) {
		return
	}

	preAuthHeld := false
	releasePreAuth := func() {
		if preAuthHeld {
			preAuthHeld = false
			<-d.preAuthSem
		}
	}
	select {
	case d.preAuthSem <- struct{}{}:
		preAuthHeld = true
		defer releasePreAuth()
	default:
		return
	}

	tlsCfg := remoteproto.ServerTLSConfig(d.id, d.getPinnedClientFP)
	tlsConn := tls.Server(rawConn, tlsCfg)
	_ = tlsConn.SetDeadline(time.Now().Add(remoteproto.HandshakeTimeout))
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		d.recordFailure(peerIP)
		return
	}
	st := tlsConn.ConnectionState()
	if len(st.PeerCertificates) != 1 {
		d.recordFailure(peerIP)
		return
	}
	clientDER := st.PeerCertificates[0].Raw
	clientFP, _, err := remoteproto.VerifyPeerEd25519Cert([][]byte{clientDER}, nil)
	if err != nil {
		d.recordFailure(peerIP)
		return
	}

	// Check whether we are already paired (reconnect flow) vs initial pairing.
	d.sessMu.Lock()
	alreadyPaired := d.paired
	pinned := d.pinnedFP
	sid := d.sessionID
	d.sessMu.Unlock()

	if alreadyPaired {
		if !remoteproto.ConstantTimeEqual32(clientFP, pinned) {
			d.recordFailure(peerIP)
			return
		}
		d.handleResume(ctx, tlsConn, peerIP, sid, releasePreAuth)
		return
	}

	d.handleInitialPairing(ctx, tlsConn, peerIP, rawConn.RemoteAddr().String(), clientDER, clientFP, releasePreAuth)
}

func (d *Daemon) handleInitialPairing(ctx context.Context, tlsConn *tls.Conn, peerIP netip.Addr, peerAddr string, clientDER []byte, clientFP [32]byte, releasePreAuth func()) {
	ekm, err := remoteproto.ExportPairingEKM(tlsConn)
	if err != nil {
		d.recordFailure(peerIP)
		return
	}

	_ = tlsConn.SetDeadline(time.Now().Add(remoteproto.CommitRevealTimeout))
	helloR := remoteproto.HelloPayload{
		ProtoVer:          remoteproto.ProtocolVersion,
		Role:              "remote",
		User:              d.userStr,
		UID:               d.uid,
		Host:              d.hostStr,
		OSArch:            runtime.GOOS + "/" + runtime.GOARCH,
		DefaultCWD:        d.execCfg.DefaultCWD,
		AllowCWD:          d.execCfg.AllowCWD,
		MaxOutputBytes:    d.execCfg.MaxOutputBytes,
		MaxStdinBytes:     d.execCfg.MaxStdinBytes,
		MaxExecTimeoutSec: int(d.execCfg.ExecTimeout / time.Second),
	}
	rawHelloR, err := remoteproto.WriteFrame(tlsConn, remoteproto.FrameHello, helloR, remoteproto.PreAuthMaxFrameBytes)
	if err != nil {
		return
	}
	typ, payloadH, rawHelloH, err := remoteproto.ReadFrame(tlsConn, remoteproto.PreAuthMaxFrameBytes)
	if err != nil || typ != remoteproto.FrameHello {
		d.recordFailure(peerIP)
		return
	}
	var helloH remoteproto.HelloPayload
	if err := remoteproto.DecodeStrict(payloadH, &helloH); err != nil || helloH.ProtoVer != remoteproto.ProtocolVersion || helloH.Role != "host" {
		d.recordFailure(peerIP)
		return
	}

	transcript := remoteproto.ComputeTranscript(ekm, clientDER, d.id.DER, rawHelloR, rawHelloH)

	// Vaudenay Move 1: receive Commit_H from host.
	typ, commitBytes, _, err := remoteproto.ReadFrame(tlsConn, remoteproto.PreAuthMaxFrameBytes)
	if err != nil || typ != remoteproto.FrameCommit {
		d.recordFailure(peerIP)
		return
	}
	var commitMsg remoteproto.CommitPayload
	if err := remoteproto.DecodeStrict(commitBytes, &commitMsg); err != nil {
		d.recordFailure(peerIP)
		return
	}
	wantCommit, err := remoteproto.DecodeHex32(commitMsg.CommitHex)
	if err != nil {
		d.recordFailure(peerIP)
		return
	}

	// Vaudenay Move 2: send random N_R to host.
	nonceR, err := remoteproto.RandomBytes32()
	if err != nil {
		return
	}
	if _, err := remoteproto.WriteFrame(tlsConn, remoteproto.FrameNonce, remoteproto.NoncePayload{
		NonceHex: hex.EncodeToString(nonceR[:]),
	}, remoteproto.PreAuthMaxFrameBytes); err != nil {
		return
	}

	// Vaudenay Move 3: receive N_H from host and verify Commit_H.
	typ, revealBytes, _, err := remoteproto.ReadFrame(tlsConn, remoteproto.PreAuthMaxFrameBytes)
	if err != nil || typ != remoteproto.FrameReveal {
		d.recordFailure(peerIP)
		return
	}
	var revealMsg remoteproto.NoncePayload
	if err := remoteproto.DecodeStrict(revealBytes, &revealMsg); err != nil {
		d.recordFailure(peerIP)
		return
	}
	nonceH, err := remoteproto.DecodeHex32(revealMsg.NonceHex)
	if err != nil {
		d.recordFailure(peerIP)
		return
	}
	gotCommit := remoteproto.ComputeCommit(nonceH, transcript)
	if !remoteproto.ConstantTimeEqual32(gotCommit, wantCommit) {
		d.recordFailure(peerIP)
		return
	}

	sas, sessionID := remoteproto.DeriveSASAndSession(transcript, nonceH, nonceR)

	// Single-owner pairing prompt serializer (at most 1 active SAS prompt on remote TTY).
	d.promptMu.Lock()
	if d.promptBusy {
		d.promptMu.Unlock()
		d.recordFailure(peerIP)
		_, _ = remoteproto.WriteFrame(tlsConn, remoteproto.FramePairReject, remoteproto.PairDecisionPayload{Reason: "pairing busy"}, remoteproto.PreAuthMaxFrameBytes)
		return
	}
	d.sessMu.Lock()
	if d.paired {
		d.sessMu.Unlock()
		d.promptMu.Unlock()
		return
	}
	d.sessMu.Unlock()
	d.promptBusy = true
	d.promptMu.Unlock()

	defer func() {
		d.promptMu.Lock()
		d.promptBusy = false
		d.promptMu.Unlock()
	}()

	promptCtx, cancelPrompt := context.WithTimeout(ctx, remoteproto.PairingPromptTimeout)
	defer cancelPrompt()

	_ = tlsConn.SetDeadline(time.Now().Add(remoteproto.PairingPromptTimeout + 5*time.Second))

	type peerPairRes struct {
		typ string
		err error
	}
	peerCh := make(chan peerPairRes, 1)
	go func() {
		pTyp, _, _, pErr := remoteproto.ReadFrame(tlsConn, remoteproto.PreAuthMaxFrameBytes)
		peerCh <- peerPairRes{typ: pTyp, err: pErr}
		if pErr != nil || pTyp != remoteproto.FramePairAck {
			// Abort the local pairing prompt at once when the peer rejects or disconnects.
			cancelPrompt()
		}
	}()

	confirmed, err := d.confirmPairing(promptCtx, peerAddr, sas)
	if err != nil || !confirmed {
		d.recordFailure(peerIP)
		_, _ = remoteproto.WriteFrame(tlsConn, remoteproto.FramePairReject, remoteproto.PairDecisionPayload{Reason: "rejected"}, remoteproto.PreAuthMaxFrameBytes)
		_ = tlsConn.SetReadDeadline(time.Now())
		<-peerCh
		d.logOut("[agbox-remote-serve] Pairing rejected.\n")
		return
	}

	if _, err := remoteproto.WriteFrame(tlsConn, remoteproto.FramePairAck, remoteproto.PairDecisionPayload{}, remoteproto.PreAuthMaxFrameBytes); err != nil {
		_ = tlsConn.SetReadDeadline(time.Now())
		<-peerCh
		return
	}
	var peerRes peerPairRes
	select {
	case peerRes = <-peerCh:
	case <-promptCtx.Done():
		d.recordFailure(peerIP)
		reason := "canceled"
		if errors.Is(promptCtx.Err(), context.DeadlineExceeded) {
			reason = "timeout"
		}
		_, _ = remoteproto.WriteFrame(tlsConn, remoteproto.FramePairReject, remoteproto.PairDecisionPayload{Reason: reason}, remoteproto.PreAuthMaxFrameBytes)
		_ = tlsConn.SetReadDeadline(time.Now())
		<-peerCh
		d.logOut("[agbox-remote-serve] Pairing canceled before peer confirmation.\n")
		return
	}
	if peerRes.err != nil || peerRes.typ != remoteproto.FramePairAck {
		d.recordFailure(peerIP)
		d.logOut("[agbox-remote-serve] Peer did not confirm pairing.\n")
		return
	}

	connCtx, connCancel := context.WithCancel(ctx)
	d.sessMu.Lock()
	if d.paired {
		d.sessMu.Unlock()
		connCancel()
		return
	}
	d.paired = true
	d.pinnedFP = clientFP
	d.sessionID = sessionID
	d.activeSeq = 1
	d.activeConn = tlsConn
	d.activeConnCancel = connCancel
	mySeq := d.activeSeq
	d.sessMu.Unlock()

	releasePreAuth()
	d.resetIdleTimer()
	d.logOut("[agbox-remote-serve] Paired with %s. Ready for approved commands.\n", remoteproto.SanitizeLine(peerAddr))
	d.servePairedLoop(connCtx, connCancel, tlsConn, mySeq)
}

func (d *Daemon) handleResume(ctx context.Context, tlsConn *tls.Conn, peerIP netip.Addr, wantSID [32]byte, releasePreAuth func()) {
	_ = tlsConn.SetDeadline(time.Now().Add(remoteproto.CommitRevealTimeout))
	typ, payload, _, err := remoteproto.ReadFrame(tlsConn, remoteproto.PreAuthMaxFrameBytes)
	if err != nil || typ != remoteproto.FrameResume {
		d.recordFailure(peerIP)
		return
	}
	var res remoteproto.ResumePayload
	if err := remoteproto.DecodeStrict(payload, &res); err != nil {
		d.recordFailure(peerIP)
		return
	}
	gotSID, err := remoteproto.DecodeHex32(res.SessionIDHex)
	if err != nil || !remoteproto.ConstantTimeEqual32(gotSID, wantSID) {
		d.recordFailure(peerIP)
		return
	}

	connCtx, connCancel := context.WithCancel(ctx)
	// Atomically supersede any stale half-open connection when conn_seq > activeSeq.
	d.sessMu.Lock()
	if res.ConnSeq <= d.activeSeq {
		d.sessMu.Unlock()
		connCancel()
		d.recordFailure(peerIP)
		return
	}
	oldConn := d.activeConn
	oldConnCancel := d.activeConnCancel
	oldCmdCancel, oldCmdDone := d.snapshotActiveCommandLocked()
	if d.graceTimer != nil {
		d.graceTimer.Stop()
		d.graceTimer = nil
	}
	d.activeSeq = res.ConnSeq
	d.activeConn = tlsConn
	d.activeConnCancel = connCancel
	mySeq := d.activeSeq
	d.sessMu.Unlock()

	if oldConnCancel != nil {
		oldConnCancel()
	}
	if oldConn != nil {
		_ = oldConn.Close()
	}
	if oldCmdCancel != nil {
		oldCmdCancel()
	}
	// Wait for any canceled command goroutine to release the active slot before sending RESUME_OK.
	if oldCmdDone != nil {
		waitTimer := time.NewTimer(3 * time.Second)
		select {
		case <-oldCmdDone:
		case <-connCtx.Done():
			waitTimer.Stop()
			connCancel()
			return
		case <-ctx.Done():
			waitTimer.Stop()
			connCancel()
			return
		case <-waitTimer.C:
		}
		waitTimer.Stop()
	}

	if _, err := remoteproto.WriteFrame(tlsConn, remoteproto.FrameResumeOK, remoteproto.ResumeOKPayload{ConnSeq: mySeq}, remoteproto.PreAuthMaxFrameBytes); err != nil {
		connCancel()
		d.sessMu.Lock()
		if d.activeSeq == mySeq && d.activeConn == tlsConn {
			d.activeConn = nil
			d.activeConnCancel = nil
			d.armGraceTimerLocked(mySeq)
		}
		d.sessMu.Unlock()
		return
	}
	releasePreAuth()
	d.resetIdleTimer()
	d.logOut("[agbox-remote-serve] Broker reconnected (seq=%d).\n", mySeq)
	d.servePairedLoop(connCtx, connCancel, tlsConn, mySeq)
}

func (d *Daemon) armGraceTimerLocked(mySeq uint64) {
	if d.graceTimer != nil {
		d.graceTimer.Stop()
	}
	d.graceTimer = time.AfterFunc(d.cfg.ReconnectGrace, func() {
		d.sessMu.Lock()
		expired := d.activeSeq == mySeq && d.activeConn == nil
		if expired {
			d.graceTimer = nil
		}
		d.sessMu.Unlock()
		if !expired {
			return
		}
		d.logErr("[agbox-remote-serve] Reconnect grace window expired. Exiting.\n")
		d.doneOnce.Do(func() { close(d.doneCh) })
	})
}

func (d *Daemon) servePairedLoop(connCtx context.Context, connCancel context.CancelFunc, tlsConn *tls.Conn, mySeq uint64) {
	cleanBye := false
	defer func() {
		connCancel()
		d.sessMu.Lock()
		// Guard all disconnect cleanup with activeSeq == mySeq so a superseded socket never kills a newer session.
		if d.activeSeq == mySeq {
			d.activeConn = nil
			d.activeConnCancel = nil
			oldCmdCancel, _ := d.snapshotActiveCommandLocked()
			if cleanBye {
				d.sessMu.Unlock()
				if oldCmdCancel != nil {
					oldCmdCancel()
				}
				d.doneOnce.Do(func() { close(d.doneCh) })
				return
			}
			d.armGraceTimerLocked(mySeq)
			d.sessMu.Unlock()
			if oldCmdCancel != nil {
				oldCmdCancel()
			}
			d.logErr("[agbox-remote-serve] Connection lost. Waiting up to %s for broker reconnect...\n", d.cfg.ReconnectGrace)
			return
		}
		d.sessMu.Unlock()
	}()

	stopPing := make(chan struct{})
	defer close(stopPing)
	go func() {
		ticker := time.NewTicker(remoteproto.HeartbeatInterval)
		defer ticker.Stop()
		for {
			select {
			case <-stopPing:
				return
			case <-connCtx.Done():
				return
			case <-ticker.C:
				if err := d.writeActiveFrame(tlsConn, mySeq, remoteproto.FramePing, nil); err != nil {
					return
				}
			}
		}
	}()

	for {
		_ = tlsConn.SetReadDeadline(time.Now().Add(remoteproto.ReadDeadTimeout))
		typ, payload, _, err := remoteproto.ReadFrame(tlsConn, remoteproto.PostAuthMaxFrameBytes)
		if err != nil {
			return
		}
		switch typ {
		case remoteproto.FramePing:
			_ = d.writeActiveFrame(tlsConn, mySeq, remoteproto.FramePong, nil)
		case remoteproto.FramePong:
		case remoteproto.FrameBye:
			cleanBye = true
			d.logOut("[agbox-remote-serve] Broker disconnected cleanly. Exiting.\n")
			return
		case remoteproto.FrameCancel:
			var cp remoteproto.CancelPayload
			if err := remoteproto.DecodeStrict(payload, &cp); err == nil {
				d.cancelCommandByID(cp.ReqID)
			}
		case remoteproto.FrameExecReq:
			var req remoteproto.ExecRequest
			if err := remoteproto.DecodeStrict(payload, &req); err != nil {
				continue
			}
			d.resetIdleTimer()
			d.dispatchExec(connCtx, tlsConn, mySeq, req)
		default:
			return
		}
	}
}

func (d *Daemon) writeActiveFrame(tlsConn *tls.Conn, mySeq uint64, frameType string, payload any) error {
	d.sessMu.Lock()
	if d.activeSeq != mySeq || d.activeConn != tlsConn {
		d.sessMu.Unlock()
		return net.ErrClosed
	}
	d.sessMu.Unlock()

	d.activeWriteMu.Lock()
	defer d.activeWriteMu.Unlock()
	_ = tlsConn.SetWriteDeadline(time.Now().Add(15 * time.Second))
	_, err := remoteproto.WriteFrame(tlsConn, frameType, payload, remoteproto.PostAuthMaxFrameBytes)
	return err
}

func (d *Daemon) dispatchExec(connCtx context.Context, tlsConn *tls.Conn, mySeq uint64, req remoteproto.ExecRequest) {
	// Keep consistent sessMu -> cmdMu lock order so a superseded connection cannot claim the command slot.
	d.sessMu.Lock()
	if d.activeSeq != mySeq || d.activeConn != tlsConn {
		d.sessMu.Unlock()
		return
	}
	d.cmdMu.Lock()
	if d.activeCancel != nil {
		d.cmdMu.Unlock()
		d.sessMu.Unlock()
		_ = d.writeActiveFrame(tlsConn, mySeq, remoteproto.FrameExecResp, remoteproto.DeniedResponse(req.ReqID, ""))
		return
	}
	cmdCtx, cancel := context.WithCancel(connCtx)
	cmdDone := make(chan struct{})
	d.activeCmdID = req.ReqID
	d.activeCancel = cancel
	d.activeCmdDone = cmdDone
	d.cmdMu.Unlock()
	d.sessMu.Unlock()

	go func() {
		defer func() {
			cancel()
			d.cmdMu.Lock()
			if d.activeCmdDone == cmdDone {
				d.activeCmdID = ""
				d.activeCancel = nil
				d.activeCmdDone = nil
			}
			d.cmdMu.Unlock()
			close(cmdDone)
		}()
		d.logOut("[agbox-remote-serve] Executing [%s]: %s\n",
			remoteproto.SanitizeLine(req.ReqID),
			remoteproto.FormatShellPreview(req.Executable, req.Args))
		resp := ExecuteCommand(cmdCtx, d.execCfg, req)
		_ = d.writeActiveFrame(tlsConn, mySeq, remoteproto.FrameExecResp, resp)
		d.resetIdleTimer()
	}()
}

// snapshotActiveCommandLocked captures the active command cancel handle and done channel.
// Callers must hold d.sessMu to keep the sessMu -> cmdMu lock order.
func (d *Daemon) snapshotActiveCommandLocked() (context.CancelFunc, <-chan struct{}) {
	d.cmdMu.Lock()
	cancel := d.activeCancel
	done := d.activeCmdDone
	d.cmdMu.Unlock()
	return cancel, done
}

func (d *Daemon) cancelActiveCommand() <-chan struct{} {
	d.cmdMu.Lock()
	cancel := d.activeCancel
	done := d.activeCmdDone
	d.cmdMu.Unlock()
	if cancel != nil {
		cancel()
	}
	return done
}

func (d *Daemon) cancelCommandByID(reqID string) {
	d.cmdMu.Lock()
	var cancel context.CancelFunc
	if d.activeCmdID == reqID {
		cancel = d.activeCancel
	}
	d.cmdMu.Unlock()
	if cancel != nil {
		cancel()
	}
}

func (d *Daemon) confirmPairing(ctx context.Context, peerAddr, sas string) (bool, error) {
	if d.cfg.PromptConfirm != nil {
		return d.cfg.PromptConfirm(ctx, peerAddr, sas)
	}
	d.logMu.Lock()
	fmt.Fprintf(d.cfg.Stdout, "\n[agbox-remote-serve] Incoming pairing from %s\n", remoteproto.SanitizeLine(peerAddr))
	fmt.Fprintf(d.cfg.Stdout, "[agbox-remote-serve] Target: %s@%s (uid=%d)\n", remoteproto.SanitizeLine(d.userStr), remoteproto.SanitizeLine(d.hostStr), d.uid)
	if d.uid == 0 {
		fmt.Fprintln(d.cfg.Stdout, "[WARNING: REMOTE DAEMON IS RUNNING AS ROOT]")
	}
	fmt.Fprintf(d.cfg.Stdout, "[agbox-remote-serve] Default cwd: %s\n", remoteproto.SanitizeLine(d.execCfg.DefaultCWD))
	fmt.Fprintf(d.cfg.Stdout, "[agbox-remote-serve] Pairing code: %s\n", sas)
	fmt.Fprint(d.cfg.Stdout, "[agbox-remote-serve] Confirm match [y/N]: ")
	d.logMu.Unlock()

	line, err := readLineWithContext(ctx, d.cfg.Stdin)
	if err != nil {
		d.logOut("\n")
		return false, err
	}
	ans := strings.ToLower(strings.TrimSpace(line))
	return ans == "y" || ans == "yes", nil
}

func readLineWithContext(ctx context.Context, r io.Reader) (string, error) {
	if f, ok := r.(*os.File); ok {
		return readLineFilePoll(ctx, int(f.Fd()))
	}
	type res struct {
		line string
		err  error
	}
	ch := make(chan res, 1)
	go func() {
		br := bufio.NewReader(r)
		s, err := br.ReadString('\n')
		ch <- res{line: s, err: err}
	}()
	select {
	case <-ctx.Done():
		return "", ctx.Err()
	case out := <-ch:
		return out.line, out.err
	}
}

func readLineFilePoll(ctx context.Context, fd int) (string, error) {
	var buf []byte
	one := make([]byte, 1)
	for {
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		pfds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
		n, err := unix.Poll(pfds, 100)
		if err != nil {
			if errors.Is(err, unix.EINTR) {
				continue
			}
			return "", err
		}
		if n == 0 {
			continue
		}
		if pfds[0].Revents&(unix.POLLERR|unix.POLLNVAL) != 0 {
			return "", io.EOF
		}
		rn, rErr := unix.Read(fd, one)
		if rn > 0 {
			if one[0] == '\n' {
				return string(buf), nil
			}
			buf = append(buf, one[0])
			if len(buf) > 4096 {
				return string(buf), nil
			}
		}
		if rErr != nil {
			if errors.Is(rErr, unix.EINTR) {
				continue
			}
			return string(buf), rErr
		}
		if rn == 0 {
			return string(buf), io.EOF
		}
	}
}

func discoverReachableIPs() []string {
	var primary string
	if conn, err := net.DialTimeout("udp", "1.1.1.1:80", 200*time.Millisecond); err == nil {
		if ua, ok := conn.LocalAddr().(*net.UDPAddr); ok && ua.IP != nil && !ua.IP.IsLoopback() {
			primary = ua.IP.String()
		}
		_ = conn.Close()
	}

	ifaces, err := net.Interfaces()
	if err != nil {
		if primary != "" {
			return []string{primary}
		}
		return nil
	}
	var out []string
	seen := make(map[string]bool)
	if primary != "" {
		out = append(out, primary)
		seen[primary] = true
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		name := iface.Name
		if strings.HasPrefix(name, "docker") || strings.HasPrefix(name, "br-") ||
			strings.HasPrefix(name, "veth") || strings.HasPrefix(name, "virbr") {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			var ip net.IP
			switch v := a.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() {
				continue
			}
			s := ip.String()
			if !seen[s] {
				seen[s] = true
				out = append(out, s)
			}
		}
	}
	return out
}
