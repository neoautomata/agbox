package remotebroker

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"agbox/internal/config"
	"agbox/internal/remotebridge"
	"agbox/internal/remotepolicy"
	"agbox/internal/remoteproto"

	"golang.org/x/sys/unix"
)

// SandboxCandidate describes one running sandbox with a remote.sock bridge.
type SandboxCandidate struct {
	Name      string
	SockPath  string
	Ephemeral bool
	NoRemote  bool
	HasBridge bool
	IsRunning bool
}

// Config configures the host interactive broker (agbox remote connect).
type Config struct {
	RemoteAddr          string
	SandboxName         string
	DataDir             string
	PolicyPath          string
	NoPolicy            bool
	OutputReview        bool
	ExtraRedactPatterns []string
	MaxOutputBytes      int
	AskTimeout          time.Duration
	AuditLogPath        string
	AllowRoot           bool

	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer
	Getenv func(string) string
	IsTTY  func() bool

	// Test hooks.
	ListSandboxes        func() ([]SandboxCandidate, error)
	PromptConfirmPairing func(ctx context.Context, peerAddr string, hello remoteproto.HelloPayload, sas string) (bool, error)
	EditBytes            func(ctx context.Context, prefix string, content []byte) ([]byte, error)
	ViewText             func(ctx context.Context, text string)
}

type queuedRequest struct {
	slotID    string
	sandbox   string
	req       remoteproto.GuestRequest
	cancelled atomic.Bool
}

type editRequestPayload struct {
	Executable     string   `json:"executable"`
	Args           []string `json:"args"`
	CWD            string   `json:"cwd"`
	ExecTimeoutSec int      `json:"exec_timeout_sec"`
	MaxOutputBytes int      `json:"max_output_bytes"`
	OutputReview   bool     `json:"output_review"`
}

// Broker pairs with a remote daemon, attaches to a sandbox remote.sock, evaluates policy,
// and mediates Phase 1 and Phase 2 interactive review through a single-owner TTY actor.
type Broker struct {
	cfg            Config
	id             remoteproto.EphemeralIdentity
	reloader       *remotepolicy.Reloader
	audit          *AuditLogger
	cliRedactRules []*regexp.Regexp

	// Remote TLS link state.
	remoteMu     sync.Mutex
	remoteConn   *tls.Conn
	remoteHello  remoteproto.HelloPayload
	pinnedSrvFP  [32]byte
	sessionID    [32]byte
	connSeq      uint64
	paired       bool
	remoteWrite  sync.Mutex
	respMu       sync.Mutex
	respWaiters  map[string]chan remoteproto.ExecResponse
	reqCounter   atomic.Uint64
	remoteClosed chan struct{}

	// Sandbox bridge attachment state.
	sbMu         sync.Mutex
	activeSB     string
	activeSBEph  bool
	bridgeConn   *net.UnixConn
	bridgeWrite  sync.Mutex
	targetSB     string
	pinnedTarget bool
	needSBSelect bool
	switchReqCh  chan string

	// Single-owner TTY actor state.
	queueMu       sync.Mutex
	queue         []*queuedRequest
	activeItem    *queuedRequest
	activeExecID  string
	activeExecCnl context.CancelFunc
	sessionGrants []remotepolicy.SessionGrant
	outputReview  bool

	wakeR     int
	wakeW     int
	wakeMu    sync.Mutex
	sigCh     chan os.Signal
	sigPaused atomic.Bool
	logMu     sync.Mutex
	logBuf    []string
}

// New validates policy and flags before dialing the remote daemon.
func New(cfg Config) (*Broker, error) {
	if strings.TrimSpace(cfg.RemoteAddr) == "" {
		return nil, errors.New("remote address <HOST:PORT> must not be empty")
	}
	if _, _, err := net.SplitHostPort(cfg.RemoteAddr); err != nil {
		return nil, fmt.Errorf("invalid remote address %q (expected HOST:PORT): %w", cfg.RemoteAddr, err)
	}
	if cfg.MaxOutputBytes > remoteproto.MaxOutputBytes {
		return nil, fmt.Errorf("--max-output %d exceeds hard limit %d bytes", cfg.MaxOutputBytes, remoteproto.MaxOutputBytes)
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
	if cfg.Getenv == nil {
		cfg.Getenv = os.Getenv
	}
	baseRedactor, err := remoteproto.NewRedactor(true, cfg.ExtraRedactPatterns)
	if err != nil {
		return nil, fmt.Errorf("invalid --redact-pattern: %w", err)
	}
	cliRedactRules := make([]*regexp.Regexp, 0, len(cfg.ExtraRedactPatterns))
	for _, pat := range cfg.ExtraRedactPatterns {
		re, cErr := regexp.Compile(pat)
		if cErr != nil {
			return nil, fmt.Errorf("invalid --redact-pattern: %w", cErr)
		}
		cliRedactRules = append(cliRedactRules, re)
	}

	// Resolve default policy path ($DATA_DIR/remote-policy.json) when neither --policy nor --no-policy is set.
	policyPath := cfg.PolicyPath
	if policyPath == "" && !cfg.NoPolicy && cfg.DataDir != "" {
		defPath := filepath.Join(cfg.DataDir, "remote-policy.json")
		if _, err := os.Lstat(defPath); err == nil {
			policyPath = defPath
		}
	}
	reloader, warnings, err := remotepolicy.NewReloader(policyPath, cfg.AllowRoot)
	if err != nil {
		return nil, fmt.Errorf("load policy: %w", err)
	}
	for _, w := range warnings {
		fmt.Fprintf(cfg.Stderr, "[agbox-remote] WARN: %s\n", w)
	}

	auditPath := cfg.AuditLogPath
	if auditPath == "" && cfg.DataDir != "" {
		if err := config.EnsurePrivateDir(cfg.DataDir); err != nil {
			return nil, fmt.Errorf("prepare data dir: %w", err)
		}
		auditPath = filepath.Join(cfg.DataDir, "remote-audit.jsonl")
	}
	audit, err := NewAuditLogger(auditPath, baseRedactor)
	if err != nil {
		return nil, err
	}

	id, err := remoteproto.GenerateEphemeralIdentity("agbox-remote-broker")
	if err != nil {
		return nil, err
	}

	targetSB := normalizeSandboxTarget(cfg.SandboxName)
	b := &Broker{
		cfg:            cfg,
		id:             id,
		reloader:       reloader,
		audit:          audit,
		cliRedactRules: cliRedactRules,
		respWaiters:    make(map[string]chan remoteproto.ExecResponse),
		switchReqCh:    make(chan string, 1),
		outputReview:   cfg.OutputReview,
		targetSB:       targetSB,
		pinnedTarget:   targetSB != "",
		wakeR:          -1,
		wakeW:          -1,
	}

	// Pre-pairing fail-fast check: if --sandbox is running with --no-remote, fail before pairing.
	if b.targetSB != "" {
		cands, err := b.listSandboxes()
		if err == nil {
			for _, c := range cands {
				if c.Name == b.targetSB && c.IsRunning && c.NoRemote {
					return nil, fmt.Errorf("sandbox %s was started with --no-remote. Restart it without --no-remote", c.Name)
				}
			}
		}
	}

	return b, nil
}

func normalizeSandboxTarget(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" {
		return ""
	}
	if strings.HasPrefix(s, "agbox-") {
		return s
	}
	return "agbox-" + s
}

func (b *Broker) listSandboxes() ([]SandboxCandidate, error) {
	if b.cfg.ListSandboxes != nil {
		return b.cfg.ListSandboxes()
	}
	return DiscoverSandboxes(b.cfg.DataDir)
}

// DiscoverSandboxes scans $DATA_DIR/run/*/run.meta and probes remote.sock availability.
func DiscoverSandboxes(dataDir string) ([]SandboxCandidate, error) {
	if dataDir == "" {
		return nil, nil
	}
	runRoot := filepath.Join(dataDir, "run")
	entries, err := os.ReadDir(runRoot)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []SandboxCandidate
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		dirPath := filepath.Join(runRoot, entry.Name())
		if _, err := os.Lstat(filepath.Join(dirPath, "suspended")); err == nil {
			continue
		}
		if _, err := os.Lstat(filepath.Join(dirPath, "deleting")); err == nil {
			continue
		}
		meta, err := config.LoadRunMeta(filepath.Join(dirPath, "run.meta"))
		if err != nil || meta.Sandbox == "" {
			continue
		}
		sockPath := filepath.Join(dirPath, "remote.sock")
		hasBridge := false
		if meta.RemoteBridge {
			if _, sErr := remotebridge.QueryStatus(sockPath); sErr == nil {
				hasBridge = true
			}
		}
		isDetached := isRegularNoFollow(filepath.Join(dirPath, "detached"))
		out = append(out, SandboxCandidate{
			Name:      meta.Sandbox,
			SockPath:  sockPath,
			Ephemeral: strings.HasPrefix(meta.Sandbox, config.RunPrefix+"-"),
			NoRemote:  !meta.RemoteBridge,
			HasBridge: hasBridge,
			IsRunning: hasBridge || isPIDAlive(meta.OwnerPID) || isDetached,
		})
	}
	slices.SortFunc(out, func(a, b SandboxCandidate) int {
		return strings.Compare(a.Name, b.Name)
	})
	return out, nil
}

func isRegularNoFollow(path string) bool {
	info, err := os.Lstat(path)
	return err == nil && info.Mode()&os.ModeSymlink == 0 && info.Mode().IsRegular()
}

func isPIDAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	err := syscall.Kill(pid, 0)
	return err == nil || errors.Is(err, syscall.EPERM)
}

func (b *Broker) initWakePipe() error {
	var fds [2]int
	if err := unix.Pipe2(fds[:], unix.O_CLOEXEC|unix.O_NONBLOCK); err != nil {
		return fmt.Errorf("create wake pipe: %w", err)
	}
	b.wakeR = fds[0]
	b.wakeW = fds[1]
	return nil
}

func (b *Broker) closeWakePipe() {
	b.wakeMu.Lock()
	defer b.wakeMu.Unlock()
	if b.wakeR >= 0 {
		_ = unix.Close(b.wakeR)
		b.wakeR = -1
	}
	if b.wakeW >= 0 {
		_ = unix.Close(b.wakeW)
		b.wakeW = -1
	}
}

func (b *Broker) signalWake() {
	b.wakeMu.Lock()
	fd := b.wakeW
	b.wakeMu.Unlock()
	if fd >= 0 {
		_, _ = unix.Write(fd, []byte{1})
	}
}

func (b *Broker) drainWake() {
	b.wakeMu.Lock()
	fd := b.wakeR
	b.wakeMu.Unlock()
	if fd < 0 {
		return
	}
	var junk [64]byte
	for {
		n, err := unix.Read(fd, junk[:])
		if n <= 0 || err != nil {
			break
		}
	}
}

// Run pairs with the remote daemon, attaches to a sandbox, and runs the single-owner TTY actor.
func (b *Broker) Run(ctx context.Context) error {
	if err := b.initWakePipe(); err != nil {
		return err
	}
	defer b.closeWakePipe()

	polPath := b.reloader.Path()
	pol, _, _ := b.reloader.Current()
	if polPath != "" {
		fmt.Fprintf(b.cfg.Stdout, "[agbox-remote] Policy: %s (%d rule(s), default=%s)\n", polPath, len(pol.Rules), pol.DefaultAction)
	} else {
		fmt.Fprintln(b.cfg.Stdout, "[agbox-remote] Policy: built-in default (default=ask)")
	}
	if b.audit.Path() != "" {
		fmt.Fprintf(b.cfg.Stdout, "[agbox-remote] Audit log: %s\n", b.audit.Path())
	}

	pairCtx, stopPairSig := signal.NotifyContext(ctx, syscall.SIGINT)
	err := b.pairRemote(pairCtx)
	stopPairSig()
	if err != nil {
		return err
	}
	defer b.sendByeAndClose()

	runCtx, cancelRun := context.WithCancel(ctx)
	defer cancelRun()

	// Broker manages SIGINT directly so single Ctrl-C cancels only the active remote command.
	b.sigCh = make(chan os.Signal, 4)
	signal.Notify(b.sigCh, syscall.SIGINT)
	defer signal.Stop(b.sigCh)

	go func() {
		for {
			select {
			case <-runCtx.Done():
				return
			case <-b.sigCh:
				if b.sigPaused.Load() {
					continue
				}
				if b.cancelActiveRemoteExec() {
					b.queueLog("[agbox-remote] Sent CANCEL for active remote command.")
					b.signalWake()
					continue
				}
				b.queueLog("[agbox-remote] Exiting cleanly...")
				cancelRun()
				b.signalWake()
				return
			}
		}
	}()

	// Background 1 s policy hot-reloader.
	go b.policyWatchLoop(runCtx)

	// Background remote reader + automatic reconnect loop.
	go b.remoteSupervisorLoop(runCtx, cancelRun)

	// Background sandbox bridge attach/re-attach supervisor.
	go b.sandboxAttachLoop(runCtx)

	return b.ttyActorLoop(runCtx, cancelRun)
}

func (b *Broker) pairRemote(ctx context.Context) error {
	fmt.Fprintf(b.cfg.Stdout, "[agbox-remote] Connecting to %s...\n", b.cfg.RemoteAddr)
	dialer := &net.Dialer{Timeout: remoteproto.HandshakeTimeout}
	rawConn, err := dialer.DialContext(ctx, "tcp", b.cfg.RemoteAddr)
	if err != nil {
		return fmt.Errorf("connect to %s: %w", b.cfg.RemoteAddr, err)
	}
	tlsConn := tls.Client(rawConn, remoteproto.ClientTLSConfig(b.id, nil))
	_ = tlsConn.SetDeadline(time.Now().Add(remoteproto.HandshakeTimeout))
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		_ = tlsConn.Close()
		return fmt.Errorf("TLS 1.3 handshake with %s: %w", b.cfg.RemoteAddr, err)
	}
	st := tlsConn.ConnectionState()
	if len(st.PeerCertificates) != 1 {
		_ = tlsConn.Close()
		return errors.New("remote peer sent invalid certificate chain")
	}
	remoteDER := st.PeerCertificates[0].Raw
	remoteFP, _, err := remoteproto.VerifyPeerEd25519Cert([][]byte{remoteDER}, nil)
	if err != nil {
		_ = tlsConn.Close()
		return err
	}
	ekm, err := remoteproto.ExportPairingEKM(tlsConn)
	if err != nil {
		_ = tlsConn.Close()
		return err
	}

	_ = tlsConn.SetDeadline(time.Now().Add(remoteproto.CommitRevealTimeout))
	typ, payloadR, rawHelloR, err := remoteproto.ReadFrame(tlsConn, remoteproto.PreAuthMaxFrameBytes)
	if err != nil || typ != remoteproto.FrameHello {
		_ = tlsConn.Close()
		return fmt.Errorf("read remote HELLO: %v", err)
	}
	var helloR remoteproto.HelloPayload
	if err := remoteproto.DecodeStrict(payloadR, &helloR); err != nil || helloR.ProtoVer != remoteproto.ProtocolVersion || helloR.Role != "remote" {
		_ = tlsConn.Close()
		return errors.New("invalid remote HELLO payload")
	}

	helloH := remoteproto.HelloPayload{
		ProtoVer: remoteproto.ProtocolVersion,
		Role:     "host",
	}
	rawHelloH, err := remoteproto.WriteFrame(tlsConn, remoteproto.FrameHello, helloH, remoteproto.PreAuthMaxFrameBytes)
	if err != nil {
		_ = tlsConn.Close()
		return err
	}

	transcript := remoteproto.ComputeTranscript(ekm, b.id.DER, remoteDER, rawHelloR, rawHelloH)

	// Vaudenay Move 1: send Commit_H.
	nonceH, err := remoteproto.RandomBytes32()
	if err != nil {
		_ = tlsConn.Close()
		return err
	}
	commitH := remoteproto.ComputeCommit(nonceH, transcript)
	if _, err := remoteproto.WriteFrame(tlsConn, remoteproto.FrameCommit, remoteproto.CommitPayload{
		CommitHex: hex.EncodeToString(commitH[:]),
	}, remoteproto.PreAuthMaxFrameBytes); err != nil {
		_ = tlsConn.Close()
		return err
	}

	// Vaudenay Move 2: receive N_R.
	typ, nonceRBytes, _, err := remoteproto.ReadFrame(tlsConn, remoteproto.PreAuthMaxFrameBytes)
	if err != nil || typ != remoteproto.FrameNonce {
		_ = tlsConn.Close()
		return fmt.Errorf("read remote pairing nonce: %v", err)
	}
	var nonceRMsg remoteproto.NoncePayload
	if err := remoteproto.DecodeStrict(nonceRBytes, &nonceRMsg); err != nil {
		_ = tlsConn.Close()
		return err
	}
	nonceR, err := remoteproto.DecodeHex32(nonceRMsg.NonceHex)
	if err != nil {
		_ = tlsConn.Close()
		return err
	}

	// Vaudenay Move 3: reveal N_H.
	if _, err := remoteproto.WriteFrame(tlsConn, remoteproto.FrameReveal, remoteproto.NoncePayload{
		NonceHex: hex.EncodeToString(nonceH[:]),
	}, remoteproto.PreAuthMaxFrameBytes); err != nil {
		_ = tlsConn.Close()
		return err
	}

	sas, sessionID := remoteproto.DeriveSASAndSession(transcript, nonceH, nonceR)

	promptCtx, cancelPrompt := context.WithTimeout(ctx, remoteproto.PairingPromptTimeout)
	defer cancelPrompt()
	stopWake := context.AfterFunc(promptCtx, b.signalWake)
	defer stopWake()
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
			cancelPrompt()
		}
	}()

	confirmed, err := b.confirmPairing(promptCtx, b.cfg.RemoteAddr, helloR, sas)
	if err != nil || !confirmed {
		_, _ = remoteproto.WriteFrame(tlsConn, remoteproto.FramePairReject, remoteproto.PairDecisionPayload{Reason: "rejected"}, remoteproto.PreAuthMaxFrameBytes)
		_ = tlsConn.Close()
		<-peerCh
		return errors.New("pairing rejected or timed out")
	}

	if _, err := remoteproto.WriteFrame(tlsConn, remoteproto.FramePairAck, remoteproto.PairDecisionPayload{}, remoteproto.PreAuthMaxFrameBytes); err != nil {
		_ = tlsConn.Close()
		<-peerCh
		return err
	}
	var pRes peerPairRes
	select {
	case pRes = <-peerCh:
	case <-promptCtx.Done():
		_, _ = remoteproto.WriteFrame(tlsConn, remoteproto.FramePairReject, remoteproto.PairDecisionPayload{Reason: "timeout"}, remoteproto.PreAuthMaxFrameBytes)
		_ = tlsConn.Close()
		<-peerCh
		return errors.New("pairing timed out waiting for remote confirmation")
	}
	if pRes.err != nil || pRes.typ != remoteproto.FramePairAck {
		_ = tlsConn.Close()
		return errors.New("remote peer rejected pairing")
	}

	_ = tlsConn.SetDeadline(time.Time{})
	b.remoteMu.Lock()
	b.remoteConn = tlsConn
	b.remoteHello = helloR
	b.pinnedSrvFP = remoteFP
	b.sessionID = sessionID
	b.connSeq = 1
	b.paired = true
	b.remoteMu.Unlock()

	fmt.Fprintf(b.cfg.Stdout, "[agbox-remote] Paired with %s@%s (uid=%d, %s, default_cwd=%s).\n",
		remoteproto.SanitizeLine(helloR.User),
		remoteproto.SanitizeLine(helloR.Host),
		helloR.UID,
		remoteproto.SanitizeLine(b.cfg.RemoteAddr),
		remoteproto.SanitizeLine(helloR.DefaultCWD))
	return nil
}

func (b *Broker) confirmPairing(ctx context.Context, peerAddr string, hello remoteproto.HelloPayload, sas string) (bool, error) {
	if b.cfg.PromptConfirmPairing != nil {
		return b.cfg.PromptConfirmPairing(ctx, peerAddr, hello, sas)
	}
	fmt.Fprintf(b.cfg.Stdout, "\n[agbox-remote] Remote peer: %s (%s@%s, uid=%d, %s)\n",
		remoteproto.SanitizeLine(peerAddr),
		remoteproto.SanitizeLine(hello.User),
		remoteproto.SanitizeLine(hello.Host),
		hello.UID,
		remoteproto.SanitizeLine(hello.OSArch))
	if hello.UID == 0 {
		fmt.Fprintln(b.cfg.Stderr, "[agbox-remote] [WARNING: REMOTE DAEMON IS RUNNING AS ROOT (uid=0)]")
	}
	fmt.Fprintf(b.cfg.Stdout, "[agbox-remote] Remote default cwd: %s\n", remoteproto.SanitizeLine(hello.DefaultCWD))
	fmt.Fprintf(b.cfg.Stdout, "[agbox-remote] Pairing code: %s\n", sas)
	fmt.Fprint(b.cfg.Stdout, "[agbox-remote] Confirm match [y/N]: ")

	line, err := b.readLinePoll(ctx)
	if err != nil {
		fmt.Fprintln(b.cfg.Stdout)
		return false, err
	}
	ans := strings.ToLower(strings.TrimSpace(line))
	return ans == "y" || ans == "yes", nil
}

func (b *Broker) sendByeAndClose() {
	b.remoteMu.Lock()
	conn := b.remoteConn
	b.remoteConn = nil
	b.remoteMu.Unlock()
	if conn != nil {
		b.remoteWrite.Lock()
		_ = conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
		_, _ = remoteproto.WriteFrame(conn, remoteproto.FrameBye, nil, remoteproto.PreAuthMaxFrameBytes)
		b.remoteWrite.Unlock()
		_ = conn.Close()
	}
	b.sbMu.Lock()
	bc := b.bridgeConn
	b.bridgeConn = nil
	b.sbMu.Unlock()
	if bc != nil {
		_ = bc.Close()
	}
}

func (b *Broker) writeRemoteFrame(frameType string, payload any) error {
	b.remoteMu.Lock()
	conn := b.remoteConn
	b.remoteMu.Unlock()
	if conn == nil {
		return net.ErrClosed
	}
	b.remoteWrite.Lock()
	defer b.remoteWrite.Unlock()
	_ = conn.SetWriteDeadline(time.Now().Add(15 * time.Second))
	_, err := remoteproto.WriteFrame(conn, frameType, payload, remoteproto.PostAuthMaxFrameBytes)
	return err
}

func (b *Broker) remoteSupervisorLoop(ctx context.Context, cancelRun context.CancelFunc) {
	for {
		b.remoteMu.Lock()
		conn := b.remoteConn
		b.remoteMu.Unlock()

		remoteBye := false
		if conn != nil {
			remoteBye = b.readRemoteUntilDrop(ctx, conn)
		}
		if remoteBye {
			b.failAllRespWaiters()
			b.queueLog("[agbox-remote] Remote daemon closed the session cleanly.")
			cancelRun()
			b.signalWake()
			return
		}
		if ctx.Err() != nil {
			return
		}

		// Fail any in-flight exec waiter on unexpected TCP drop.
		b.failAllRespWaiters()
		b.queueLog("[agbox-remote] Remote TCP connection lost. Attempting reconnect with pinned certificate...")
		b.signalWake()

		// Exponential reconnect backoff using pinned Cert_R + RESUME(session_id, conn_seq).
		backoff := 500 * time.Millisecond
		for ctx.Err() == nil {
			if err := b.reconnectOnce(ctx); err == nil {
				b.queueLog("[agbox-remote] Reconnected to remote daemon cleanly.")
				b.signalWake()
				break
			}
			timer := time.NewTimer(backoff)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
			backoff *= 2
			if backoff > 5*time.Second {
				backoff = 5 * time.Second
			}
		}
	}
}

func (b *Broker) readRemoteUntilDrop(ctx context.Context, conn *tls.Conn) bool {
	stopPing := make(chan struct{})
	defer close(stopPing)
	go func() {
		ticker := time.NewTicker(remoteproto.HeartbeatInterval)
		defer ticker.Stop()
		for {
			select {
			case <-stopPing:
				return
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := b.writeRemoteFrame(remoteproto.FramePing, nil); err != nil {
					return
				}
			}
		}
	}()

	for {
		_ = conn.SetReadDeadline(time.Now().Add(remoteproto.ReadDeadTimeout))
		typ, payload, _, err := remoteproto.ReadFrame(conn, remoteproto.PostAuthMaxFrameBytes)
		if err != nil {
			b.remoteMu.Lock()
			if b.remoteConn == conn {
				b.remoteConn = nil
			}
			b.remoteMu.Unlock()
			_ = conn.Close()
			return false
		}
		switch typ {
		case remoteproto.FramePing:
			_ = b.writeRemoteFrame(remoteproto.FramePong, nil)
		case remoteproto.FramePong:
		case remoteproto.FrameExecResp:
			var resp remoteproto.ExecResponse
			if err := remoteproto.DecodeStrict(payload, &resp); err == nil {
				b.deliverResp(resp)
			}
		case remoteproto.FrameBye:
			b.remoteMu.Lock()
			if b.remoteConn == conn {
				b.remoteConn = nil
			}
			b.remoteMu.Unlock()
			_ = conn.Close()
			return true
		}
	}
}

func (b *Broker) reconnectOnce(ctx context.Context) error {
	b.remoteMu.Lock()
	pinned := b.pinnedSrvFP
	sid := b.sessionID
	nextSeq := b.connSeq + 1
	b.remoteMu.Unlock()

	dialer := &net.Dialer{Timeout: remoteproto.HandshakeTimeout}
	rawConn, err := dialer.DialContext(ctx, "tcp", b.cfg.RemoteAddr)
	if err != nil {
		return err
	}
	tlsConn := tls.Client(rawConn, remoteproto.ClientTLSConfig(b.id, &pinned))
	_ = tlsConn.SetDeadline(time.Now().Add(remoteproto.HandshakeTimeout))
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		_ = tlsConn.Close()
		return err
	}
	_ = tlsConn.SetDeadline(time.Now().Add(remoteproto.CommitRevealTimeout))
	if _, err := remoteproto.WriteFrame(tlsConn, remoteproto.FrameResume, remoteproto.ResumePayload{
		SessionIDHex: hex.EncodeToString(sid[:]),
		ConnSeq:      nextSeq,
	}, remoteproto.PreAuthMaxFrameBytes); err != nil {
		_ = tlsConn.Close()
		return err
	}
	typ, payload, _, err := remoteproto.ReadFrame(tlsConn, remoteproto.PreAuthMaxFrameBytes)
	if err != nil || typ != remoteproto.FrameResumeOK {
		_ = tlsConn.Close()
		return errors.New("resume rejected by remote daemon")
	}
	var okMsg remoteproto.ResumeOKPayload
	if err := remoteproto.DecodeStrict(payload, &okMsg); err != nil || okMsg.ConnSeq != nextSeq {
		_ = tlsConn.Close()
		return errors.New("invalid resume_ok sequence")
	}
	_ = tlsConn.SetDeadline(time.Time{})

	b.remoteMu.Lock()
	b.remoteConn = tlsConn
	b.connSeq = nextSeq
	b.remoteMu.Unlock()
	return nil
}

func (b *Broker) deliverResp(resp remoteproto.ExecResponse) {
	b.respMu.Lock()
	ch, ok := b.respWaiters[resp.ReqID]
	if ok {
		delete(b.respWaiters, resp.ReqID)
	}
	b.respMu.Unlock()
	if ok {
		select {
		case ch <- resp:
		default:
		}
	}
}

func (b *Broker) failAllRespWaiters() {
	b.respMu.Lock()
	waiters := b.respWaiters
	b.respWaiters = make(map[string]chan remoteproto.ExecResponse)
	b.respMu.Unlock()
	for _, ch := range waiters {
		close(ch)
	}
}

func (b *Broker) policyWatchLoop(ctx context.Context) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			res := b.reloader.CheckReload()
			if res.Changed {
				if res.DenyAll {
					b.queueLog(fmt.Sprintf("[agbox-remote] ERROR: policy reload failed (%v). Failing closed: DENY-ALL until fixed.", res.Err))
				} else {
					b.queueLog(fmt.Sprintf("[agbox-remote] Policy reloaded (%s, %d rule(s), hash=%s).", b.reloader.Path(), res.RuleCount, res.HashHex))
					for _, w := range res.Warnings {
						b.queueLog("[agbox-remote] WARN: " + w)
					}
				}
				b.signalWake()
			}
		}
	}
}

func (b *Broker) sandboxAttachLoop(ctx context.Context) {
	waitState := ""
	for ctx.Err() == nil {
		b.sbMu.Lock()
		target := b.targetSB
		b.sbMu.Unlock()

		cands, err := b.listSandboxes()
		if err != nil {
			timer := time.NewTimer(500 * time.Millisecond)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
			continue
		}

		var ready []SandboxCandidate
		for _, c := range cands {
			if c.HasBridge {
				ready = append(ready, c)
			}
		}

		var chosen *SandboxCandidate
		if target != "" {
			for i := range ready {
				if ready[i].Name == target {
					chosen = &ready[i]
					break
				}
			}
			if chosen == nil {
				wantState := "target:" + target
				if waitState != wantState {
					b.queueLog(fmt.Sprintf("[agbox-remote] Waiting for sandbox %s...", target))
					b.signalWake()
					waitState = wantState
				}
				select {
				case <-ctx.Done():
					return
				case newT := <-b.switchReqCh:
					b.sbMu.Lock()
					b.targetSB = newT
					b.pinnedTarget = false
					b.needSBSelect = false
					b.sbMu.Unlock()
					waitState = ""
				case <-time.After(500 * time.Millisecond):
				}
				continue
			}
		} else {
			switch len(ready) {
			case 0:
				if waitState != "zero" {
					b.queueLog("[agbox-remote] Waiting for a sandbox with remote bridge. Start 'agbox run ...' in another terminal.")
					b.signalWake()
					waitState = "zero"
				}
				select {
				case <-ctx.Done():
					return
				case newT := <-b.switchReqCh:
					b.sbMu.Lock()
					b.targetSB = newT
					b.pinnedTarget = false
					b.needSBSelect = false
					b.sbMu.Unlock()
					waitState = ""
				case <-time.After(500 * time.Millisecond):
				}
				continue
			case 1:
				chosen = &ready[0]
			default:
				if waitState != "multi" {
					b.sbMu.Lock()
					b.needSBSelect = true
					b.sbMu.Unlock()
					b.signalWake()
					waitState = "multi"
				}
				select {
				case <-ctx.Done():
					return
				case newT := <-b.switchReqCh:
					b.sbMu.Lock()
					b.targetSB = newT
					b.pinnedTarget = false
					b.needSBSelect = false
					b.sbMu.Unlock()
					waitState = ""
				case <-time.After(500 * time.Millisecond):
				}
				continue
			}
		}

		waitState = ""
		b.remoteMu.Lock()
		remoteID := fmt.Sprintf("%s@%s",
			remoteproto.SanitizeLine(b.remoteHello.User),
			remoteproto.SanitizeLine(b.remoteHello.Host))
		b.remoteMu.Unlock()

		conn, err := remotebridge.DialAttach(chosen.SockPath, b.cfg.RemoteAddr, remoteID, b.reloader.Path())
		if err != nil {
			b.queueLog(fmt.Sprintf("[agbox-remote] Could not attach to %s (%v). Retrying...", chosen.Name, err))
			b.signalWake()
			timer := time.NewTimer(time.Second)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case newT := <-b.switchReqCh:
				timer.Stop()
				b.sbMu.Lock()
				b.targetSB = newT
				b.pinnedTarget = false
				b.needSBSelect = false
				b.sbMu.Unlock()
			case <-timer.C:
			}
			continue
		}

		b.sbMu.Lock()
		b.activeSB = chosen.Name
		b.activeSBEph = chosen.Ephemeral
		b.bridgeConn = conn
		b.needSBSelect = false
		b.sbMu.Unlock()

		b.queueLog(fmt.Sprintf("[agbox-remote] Attached to sandbox %s.", chosen.Name))
		b.signalWake()

		b.readBridgeLoop(ctx, conn, chosen.Name)

		// Cancel any active or queued requests belonging to the disconnected sandbox.
		b.cancelSandboxRequests(chosen.Name)

		b.sbMu.Lock()
		if b.bridgeConn == conn {
			b.bridgeConn = nil
			b.activeSB = ""
			// Clear an interactively selected ephemeral PID target when it disconnects.
			if !b.pinnedTarget && b.activeSBEph && b.targetSB == chosen.Name {
				b.targetSB = ""
			}
			b.activeSBEph = false
		}
		b.sbMu.Unlock()
		_ = conn.Close()

		if ctx.Err() == nil {
			b.queueLog(fmt.Sprintf("[agbox-remote] Sandbox %s disconnected. Keeping remote link alive.", chosen.Name))
			b.signalWake()
		}
	}
}

func (b *Broker) readBridgeLoop(ctx context.Context, conn *net.UnixConn, sandboxName string) {
	loopDone := make(chan struct{})
	defer close(loopDone)
	go func() {
		select {
		case <-loopDone:
			return
		case <-ctx.Done():
			_ = conn.Close()
		case newT := <-b.switchReqCh:
			b.sbMu.Lock()
			b.targetSB = newT
			b.pinnedTarget = false
			b.needSBSelect = false
			b.sbMu.Unlock()
			_ = conn.Close()
		}
	}()

	for {
		typ, payload, _, err := remoteproto.ReadFrame(conn, remoteproto.PostAuthMaxFrameBytes)
		if err != nil || typ != "bridge" {
			return
		}
		var msg remoteproto.BridgeMessage
		if err := remoteproto.DecodeStrict(payload, &msg); err != nil {
			return
		}
		switch msg.Op {
		case "req":
			if msg.SlotID != "" && msg.Request != nil {
				b.enqueueGuestRequest(sandboxName, msg.SlotID, *msg.Request)
			}
		case "cancel":
			if msg.SlotID != "" {
				b.cancelGuestSlot(sandboxName, msg.SlotID)
			}
		}
	}
}

func (b *Broker) sendBridgeResp(sandbox, slotID string, resp remoteproto.ExecResponse) {
	if resp.Status == remoteproto.StatusDenied && resp.OperatorNote == "" {
		resp = remoteproto.DeniedResponse(slotID, "")
	} else {
		resp.ReqID = slotID
	}
	b.sbMu.Lock()
	conn := b.bridgeConn
	activeSB := b.activeSB
	b.sbMu.Unlock()
	if conn == nil || activeSB != sandbox {
		return
	}
	b.bridgeWrite.Lock()
	defer b.bridgeWrite.Unlock()
	_, _ = remoteproto.WriteFrame(conn, "bridge", remoteproto.BridgeMessage{
		Op:       "resp",
		SlotID:   slotID,
		Response: &resp,
	}, remoteproto.PostAuthMaxFrameBytes)
}

func (b *Broker) enqueueGuestRequest(sandbox, slotID string, req remoteproto.GuestRequest) {
	item := &queuedRequest{
		slotID:  slotID,
		sandbox: sandbox,
		req:     req,
	}
	b.queueMu.Lock()
	b.queue = append(b.queue, item)
	b.queueMu.Unlock()
	b.signalWake()
}

func (b *Broker) cancelGuestSlot(sandbox, slotID string) {
	b.queueMu.Lock()
	if b.activeItem != nil && b.activeItem.sandbox == sandbox && b.activeItem.slotID == slotID {
		b.activeItem.cancelled.Store(true)
		cancel := b.activeExecCnl
		reqID := b.activeExecID
		b.queueMu.Unlock()
		if cancel != nil {
			cancel()
		}
		if reqID != "" {
			_ = b.writeRemoteFrame(remoteproto.FrameCancel, remoteproto.CancelPayload{ReqID: reqID})
		}
		b.signalWake()
		return
	}
	for i, item := range b.queue {
		if item.sandbox == sandbox && item.slotID == slotID {
			item.cancelled.Store(true)
			b.queue = append(b.queue[:i], b.queue[i+1:]...)
			break
		}
	}
	b.queueMu.Unlock()
	b.signalWake()
}

func (b *Broker) cancelSandboxRequests(sandbox string) {
	b.queueMu.Lock()
	var cancel context.CancelFunc
	var reqID string
	if b.activeItem != nil && b.activeItem.sandbox == sandbox {
		b.activeItem.cancelled.Store(true)
		cancel = b.activeExecCnl
		reqID = b.activeExecID
	}
	if len(b.queue) > 0 {
		kept := b.queue[:0]
		for _, item := range b.queue {
			if item.sandbox == sandbox {
				item.cancelled.Store(true)
				continue
			}
			kept = append(kept, item)
		}
		b.queue = kept
	}
	b.queueMu.Unlock()
	if cancel != nil {
		cancel()
	}
	if reqID != "" {
		_ = b.writeRemoteFrame(remoteproto.FrameCancel, remoteproto.CancelPayload{ReqID: reqID})
	}
	b.signalWake()
}

func (b *Broker) requestSwitchSandbox(name string) {
	b.sbMu.Lock()
	b.targetSB = name
	b.pinnedTarget = false
	b.needSBSelect = false
	b.sbMu.Unlock()
	select {
	case <-b.switchReqCh:
	default:
	}
	select {
	case b.switchReqCh <- name:
	default:
	}
}

func (b *Broker) consumeNeedSBSelect() bool {
	b.sbMu.Lock()
	defer b.sbMu.Unlock()
	if !b.needSBSelect {
		return false
	}
	b.needSBSelect = false
	return b.activeSB == "" && b.targetSB == ""
}

func (b *Broker) cancelActiveRemoteExec() bool {
	b.queueMu.Lock()
	cancel := b.activeExecCnl
	reqID := b.activeExecID
	b.queueMu.Unlock()
	if cancel == nil {
		return false
	}
	cancel()
	if reqID != "" {
		_ = b.writeRemoteFrame(remoteproto.FrameCancel, remoteproto.CancelPayload{ReqID: reqID})
	}
	return true
}

func (b *Broker) queueLog(line string) {
	b.logMu.Lock()
	b.logBuf = append(b.logBuf, line)
	b.logMu.Unlock()
}

func (b *Broker) flushLogs(leadingNewline bool) bool {
	b.logMu.Lock()
	lines := b.logBuf
	b.logBuf = nil
	b.logMu.Unlock()
	if len(lines) == 0 {
		return false
	}
	if leadingNewline {
		fmt.Fprintln(b.cfg.Stdout)
	}
	for _, line := range lines {
		fmt.Fprintln(b.cfg.Stdout, line)
	}
	return true
}

func (b *Broker) popNextRequest() (*queuedRequest, int) {
	b.queueMu.Lock()
	defer b.queueMu.Unlock()
	for len(b.queue) > 0 {
		item := b.queue[0]
		b.queue = b.queue[1:]
		if item.cancelled.Load() {
			continue
		}
		b.activeItem = item
		return item, len(b.queue)
	}
	b.activeItem = nil
	return nil, 0
}

func (b *Broker) ttyActorLoop(ctx context.Context, cancelRun context.CancelFunc) error {
	printedIdle := false
	for ctx.Err() == nil {
		if b.flushLogs(printedIdle) {
			printedIdle = false
		}

		item, queuedRest := b.popNextRequest()
		if item != nil {
			printedIdle = false
			b.processOneRequest(ctx, item, queuedRest)
			b.queueMu.Lock()
			b.activeItem = nil
			b.queueMu.Unlock()
			continue
		}

		if b.consumeNeedSBSelect() {
			printedIdle = false
			if quit := b.handleAutoSelectSandboxPrompt(ctx); quit {
				cancelRun()
				return nil
			}
			continue
		}

		if !printedIdle {
			b.printIdlePrompt()
			printedIdle = true
		}

		line, woke, err := b.readIdleOrWake(ctx)
		if err != nil {
			b.flushLogs(printedIdle)
			return nil
		}
		if woke {
			continue
		}
		printedIdle = false
		cmd := strings.ToLower(strings.TrimSpace(line))
		switch cmd {
		case "":
		case "w":
			b.handleSwitchSandboxPrompt(ctx)
		case "t":
			b.outputReview = !b.outputReview
			state := "OFF"
			if b.outputReview {
				state = "ON"
			}
			fmt.Fprintf(b.cfg.Stdout, "[agbox-remote] Per-run output review is now %s.\n", state)
		case "c":
			b.handleSessionGrantsPrompt(ctx)
		case "q":
			cancelRun()
			return nil
		default:
			fmt.Fprintln(b.cfg.Stdout, "[agbox-remote] Idle keys: [w] switch sandbox, [t] toggle output review, [c] session approvals, [q] quit")
		}
	}
	b.flushLogs(printedIdle)
	return nil
}

func (b *Broker) handleAutoSelectSandboxPrompt(ctx context.Context) bool {
	cands, err := b.listSandboxes()
	if err != nil {
		fmt.Fprintf(b.cfg.Stderr, "[agbox-remote] List sandboxes failed: %v\n", err)
		return false
	}
	var ready []SandboxCandidate
	for _, c := range cands {
		if c.HasBridge {
			ready = append(ready, c)
		}
	}
	if len(ready) <= 1 {
		return false
	}
	fmt.Fprintln(b.cfg.Stdout, "\nAvailable sandboxes:")
	for i, c := range ready {
		fmt.Fprintf(b.cfg.Stdout, "  [%d] %s\n", i+1, c.Name)
	}
	fmt.Fprintf(b.cfg.Stdout, "Select sandbox [1..%d] or [q]uit: ", len(ready))
	line, err := b.readLinePoll(ctx)
	if err != nil {
		return ctx.Err() != nil
	}
	ans := strings.ToLower(strings.TrimSpace(line))
	if ans == "q" || ans == "quit" {
		return true
	}
	idx, err := strconv.Atoi(ans)
	if err != nil || idx < 1 || idx > len(ready) {
		fmt.Fprintln(b.cfg.Stdout, "[agbox-remote] Press [w] at the idle prompt to select a sandbox.")
		return false
	}
	chosen := ready[idx-1].Name
	b.requestSwitchSandbox(chosen)
	fmt.Fprintf(b.cfg.Stdout, "[agbox-remote] Selecting %s...\n", chosen)
	return false
}

func (b *Broker) printIdlePrompt() {
	b.sbMu.Lock()
	sb := b.activeSB
	b.sbMu.Unlock()
	if sb == "" {
		sb = "none"
	}
	rev := "OFF"
	if b.outputReview {
		rev = "ON"
	}
	fmt.Fprintf(b.cfg.Stdout, "\n[agbox-remote] Idle (sandbox=%s, output-review=%s, session-grants=%d) | [w] switch  [t] review  [c] grants  [q] quit: ",
		sb, rev, len(b.sessionGrants))
}

func (b *Broker) handleSwitchSandboxPrompt(ctx context.Context) {
	cands, err := b.listSandboxes()
	if err != nil {
		fmt.Fprintf(b.cfg.Stderr, "[agbox-remote] List sandboxes failed: %v\n", err)
		return
	}
	var ready []SandboxCandidate
	for _, c := range cands {
		if c.HasBridge {
			ready = append(ready, c)
		}
	}
	if len(ready) == 0 {
		fmt.Fprintln(b.cfg.Stdout, "[agbox-remote] No running sandboxes with remote bridge found.")
		return
	}
	fmt.Fprintln(b.cfg.Stdout, "Available sandboxes:")
	for i, c := range ready {
		fmt.Fprintf(b.cfg.Stdout, "  [%d] %s\n", i+1, c.Name)
	}
	fmt.Fprint(b.cfg.Stdout, "Select sandbox [1..N] or Enter to cancel: ")
	line, err := b.readLinePoll(ctx)
	if err != nil {
		return
	}
	idx, err := strconv.Atoi(strings.TrimSpace(line))
	if err != nil || idx < 1 || idx > len(ready) {
		return
	}
	chosen := ready[idx-1].Name
	b.requestSwitchSandbox(chosen)
	fmt.Fprintf(b.cfg.Stdout, "[agbox-remote] Switching to %s...\n", chosen)
}

func (b *Broker) handleSessionGrantsPrompt(ctx context.Context) {
	if len(b.sessionGrants) == 0 {
		fmt.Fprintln(b.cfg.Stdout, "[agbox-remote] No active exact-match session approvals.")
		return
	}
	fmt.Fprintln(b.cfg.Stdout, "Active exact-match session approvals:")
	for i, g := range b.sessionGrants {
		fmt.Fprintf(b.cfg.Stdout, "  [%d] %s (cwd=%s, review=%v)\n",
			i+1, remoteproto.FormatShellPreview(g.Executable, g.Args), remoteproto.SanitizeLine(g.CWD), g.OutputReview)
	}
	fmt.Fprint(b.cfg.Stdout, "Clear all session approvals? [y/N]: ")
	line, err := b.readLinePoll(ctx)
	if err != nil {
		return
	}
	if strings.ToLower(strings.TrimSpace(line)) == "y" {
		b.sessionGrants = nil
		fmt.Fprintln(b.cfg.Stdout, "[agbox-remote] Cleared all session approvals.")
	}
}

func (b *Broker) processOneRequest(ctx context.Context, item *queuedRequest, queuedRest int) {
	// Always check for policy updates before evaluating every incoming request.
	relRes := b.reloader.CheckReload()
	if relRes.Changed {
		if relRes.DenyAll {
			fmt.Fprintf(b.cfg.Stderr, "\n[agbox-remote] ERROR: policy reload failed (%v). Failing closed: DENY-ALL.\n", relRes.Err)
		} else {
			fmt.Fprintf(b.cfg.Stdout, "\n[agbox-remote] Policy reloaded (%d rule(s), hash=%s).\n", relRes.RuleCount, relRes.HashHex)
		}
	}

	pol, denyAll, denyErr := b.reloader.Current()
	b.remoteMu.Lock()
	helloR := b.remoteHello
	b.remoteMu.Unlock()
	remoteID := fmt.Sprintf("%s@%s",
		remoteproto.SanitizeLine(helloR.User),
		remoteproto.SanitizeLine(helloR.Host))

	var stdinBytes []byte
	var stdinSHA string
	if item.req.StdinB64 != "" {
		dec, err := base64.StdEncoding.DecodeString(item.req.StdinB64)
		if err != nil || len(dec) > remoteproto.MaxStdinBytes {
			b.sendBridgeResp(item.sandbox, item.slotID, remoteproto.DeniedResponse(item.slotID, ""))
			return
		}
		stdinBytes = dec
		sum := sha256.Sum256(stdinBytes)
		stdinSHA = hex.EncodeToString(sum[:])
	}

	if denyAll {
		fmt.Fprintf(b.cfg.Stderr, "[agbox-remote] DENIED [%s] (policy in DENY-ALL: %v)\n", item.sandbox, denyErr)
		b.sendBridgeResp(item.sandbox, item.slotID, remoteproto.DeniedResponse(item.slotID, ""))
		_ = b.audit.Log(AuditEntry{
			Sandbox: item.sandbox, RemotePeer: b.cfg.RemoteAddr, RemoteID: remoteID,
			ReqID: item.slotID, Executable: item.req.Executable, Args: item.req.Args,
			CWD: item.req.CWD, StdinSize: len(stdinBytes), StdinSHA256: stdinSHA,
			PolicyAction: "deny", OperatorEvent: "policy_deny_all", Status: remoteproto.StatusDenied, ExitCode: remoteproto.DenyExitCode,
		})
		return
	}

	effMaxOut := pol.Limits.MaxOutputBytes
	if b.cfg.MaxOutputBytes > 0 && b.cfg.MaxOutputBytes < effMaxOut {
		effMaxOut = b.cfg.MaxOutputBytes
	}
	if helloR.MaxOutputBytes > 0 && helloR.MaxOutputBytes < effMaxOut {
		effMaxOut = helloR.MaxOutputBytes
	}

	evalIn := remotepolicy.EvalInput{
		Executable:     item.req.Executable,
		Args:           item.req.Args,
		CWD:            item.req.CWD,
		DefaultCWD:     helloR.DefaultCWD,
		StdinSize:      len(stdinBytes),
		ExecTimeoutSec: item.req.ExecTimeoutSec,
		MaxOutputBytes: 0,
	}
	dec := remotepolicy.Evaluate(pol, evalIn, b.sessionGrants)

	if dec.Action == remotepolicy.ActionDeny {
		fmt.Fprintf(b.cfg.Stdout, "[agbox-remote] AUTO-DENY [%s]: %s (%s)\n",
			item.sandbox, remoteproto.FormatShellPreview(item.req.Executable, item.req.Args), dec.Reason)
		b.sendBridgeResp(item.sandbox, item.slotID, remoteproto.DeniedResponse(item.slotID, ""))
		_ = b.audit.Log(AuditEntry{
			Sandbox: item.sandbox, RemotePeer: b.cfg.RemoteAddr, RemoteID: remoteID,
			ReqID: item.slotID, Executable: item.req.Executable, Args: item.req.Args,
			CWD: item.req.CWD, StdinSize: len(stdinBytes), StdinSHA256: stdinSHA,
			PolicyAction: string(dec.Action), PolicyRuleID: dec.RuleID,
			OperatorEvent: "policy_deny", Status: remoteproto.StatusDenied, ExitCode: remoteproto.DenyExitCode,
		})
		return
	}

	stagedMaxOut := dec.MaxOutputBytes
	if effMaxOut > 0 && (stagedMaxOut <= 0 || effMaxOut < stagedMaxOut) {
		stagedMaxOut = effMaxOut
	}
	stagedTimeout := dec.MaxExecTimeoutSec
	if helloR.MaxExecTimeoutSec > 0 && (stagedTimeout <= 0 || helloR.MaxExecTimeoutSec < stagedTimeout) {
		stagedTimeout = helloR.MaxExecTimeoutSec
	}

	// Stage executable request (may be modified in Phase 1 [e]/[i]).
	staged := remoteproto.ExecRequest{
		ReqID:          fmt.Sprintf("req-%04d", b.reqCounter.Add(1)),
		Executable:     item.req.Executable,
		Args:           append([]string(nil), item.req.Args...),
		CWD:            item.req.CWD,
		StdinB64:       item.req.StdinB64,
		StdinSize:      len(stdinBytes),
		StdinSHA256:    stdinSHA,
		ExecTimeoutSec: stagedTimeout,
		MaxOutputBytes: stagedMaxOut,
		Reason:         item.req.Reason,
		AllowCWDScope:  dec.AllowCWDScope,
		DenyCWDScopes:  dec.DenyCWDScopes,
	}
	needOutputReview := b.outputReview || dec.OutputReview
	opEvent := "policy_allow"
	edited := false

	if dec.Action == remotepolicy.ActionAsk {
		approved, reviewOut, note, wasEdited, addSession := b.runPhase1Prompt(ctx, item, queuedRest, helloR, dec, &staged, &stdinBytes, needOutputReview, pol)
		edited = wasEdited
		if !approved {
			b.sendBridgeResp(item.sandbox, item.slotID, remoteproto.DeniedResponse(item.slotID, note))
			_ = b.audit.Log(AuditEntry{
				Sandbox: item.sandbox, RemotePeer: b.cfg.RemoteAddr, RemoteID: remoteID,
				ReqID: staged.ReqID, Executable: staged.Executable, Args: staged.Args,
				CWD: staged.CWD, StdinSize: staged.StdinSize, StdinSHA256: staged.StdinSHA256,
				PolicyAction: string(dec.Action), PolicyRuleID: dec.RuleID,
				OperatorEvent: "phase1_deny", Edited: edited, Status: remoteproto.StatusDenied, ExitCode: remoteproto.DenyExitCode,
			})
			return
		}

		// Re-check policy after Phase 1 interactive wait to block TOCTOU bypasses.
		relAfter := b.reloader.CheckReload()
		if relAfter.Changed {
			if relAfter.DenyAll {
				fmt.Fprintf(b.cfg.Stderr, "\n[agbox-remote] ERROR: policy reload failed (%v). Failing closed: DENY-ALL.\n", relAfter.Err)
			} else {
				fmt.Fprintf(b.cfg.Stdout, "\n[agbox-remote] Policy reloaded (%d rule(s), hash=%s).\n", relAfter.RuleCount, relAfter.HashHex)
			}
		}
		polAfter, denyAllAfter, denyErrAfter := b.reloader.Current()
		if denyAllAfter {
			fmt.Fprintf(b.cfg.Stderr, "[agbox-remote] DENIED [%s] (policy in DENY-ALL after Phase 1: %v)\n", item.sandbox, denyErrAfter)
			b.sendBridgeResp(item.sandbox, item.slotID, remoteproto.DeniedResponse(item.slotID, ""))
			_ = b.audit.Log(AuditEntry{
				Sandbox: item.sandbox, RemotePeer: b.cfg.RemoteAddr, RemoteID: remoteID,
				ReqID: staged.ReqID, Executable: staged.Executable, Args: staged.Args,
				CWD: staged.CWD, StdinSize: staged.StdinSize, StdinSHA256: staged.StdinSHA256,
				PolicyAction: "deny", OperatorEvent: "policy_deny_all", Edited: edited,
				Status: remoteproto.StatusDenied, ExitCode: remoteproto.DenyExitCode,
			})
			return
		}
		reEval := remotepolicy.Evaluate(polAfter, remotepolicy.EvalInput{
			Executable:     staged.Executable,
			Args:           staged.Args,
			CWD:            staged.CWD,
			DefaultCWD:     helloR.DefaultCWD,
			StdinSize:      staged.StdinSize,
			ExecTimeoutSec: staged.ExecTimeoutSec,
			MaxOutputBytes: staged.MaxOutputBytes,
		}, nil)
		if reEval.Action == remotepolicy.ActionDeny {
			fmt.Fprintf(b.cfg.Stdout, "[agbox-remote] DENIED [%s] after policy reload: %s (%s)\n",
				item.sandbox, remoteproto.FormatShellPreview(staged.Executable, staged.Args), reEval.Reason)
			b.sendBridgeResp(item.sandbox, item.slotID, remoteproto.DeniedResponse(item.slotID, ""))
			_ = b.audit.Log(AuditEntry{
				Sandbox: item.sandbox, RemotePeer: b.cfg.RemoteAddr, RemoteID: remoteID,
				ReqID: staged.ReqID, Executable: staged.Executable, Args: staged.Args,
				CWD: staged.CWD, StdinSize: staged.StdinSize, StdinSHA256: staged.StdinSHA256,
				PolicyAction: string(reEval.Action), PolicyRuleID: reEval.RuleID,
				OperatorEvent: "policy_deny", Edited: edited,
				Status: remoteproto.StatusDenied, ExitCode: remoteproto.DenyExitCode,
			})
			return
		}
		staged.DenyCWDScopes = reEval.DenyCWDScopes
		if reEval.MaxOutputBytes > 0 && (staged.MaxOutputBytes <= 0 || reEval.MaxOutputBytes < staged.MaxOutputBytes) {
			staged.MaxOutputBytes = reEval.MaxOutputBytes
		}
		if b.cfg.MaxOutputBytes > 0 && b.cfg.MaxOutputBytes < staged.MaxOutputBytes {
			staged.MaxOutputBytes = b.cfg.MaxOutputBytes
		}
		if helloR.MaxOutputBytes > 0 && helloR.MaxOutputBytes < staged.MaxOutputBytes {
			staged.MaxOutputBytes = helloR.MaxOutputBytes
		}
		if reEval.MaxExecTimeoutSec > 0 && (staged.ExecTimeoutSec <= 0 || reEval.MaxExecTimeoutSec < staged.ExecTimeoutSec) {
			staged.ExecTimeoutSec = reEval.MaxExecTimeoutSec
		}
		if helloR.MaxExecTimeoutSec > 0 && helloR.MaxExecTimeoutSec < staged.ExecTimeoutSec {
			staged.ExecTimeoutSec = helloR.MaxExecTimeoutSec
		}
		if reEval.OutputReview {
			reviewOut = true
		}
		pol = polAfter

		needOutputReview = reviewOut
		opEvent = "phase1_approve"
		if addSession {
			effCWD := staged.CWD
			if effCWD == "" {
				effCWD = helloR.DefaultCWD
			}
			b.sessionGrants = append(b.sessionGrants, remotepolicy.SessionGrant{
				Executable:        staged.Executable,
				Args:              append([]string(nil), staged.Args...),
				CWD:               effCWD,
				MaxExecTimeoutSec: staged.ExecTimeoutSec,
				MaxOutputBytes:    staged.MaxOutputBytes,
				OutputReview:      needOutputReview,
			})
		}
	} else {
		fmt.Fprintf(b.cfg.Stdout, "[agbox-remote] AUTO-ALLOW [%s]: %s (%s)\n",
			item.sandbox, remoteproto.FormatShellPreview(staged.Executable, staged.Args), dec.Reason)
	}

	// Execute on remote daemon with live status and single Ctrl-C cancellation.
	resp, ok := b.executeOnRemote(ctx, item, staged)
	if !ok {
		b.sendBridgeResp(item.sandbox, item.slotID, remoteproto.DeniedResponse(item.slotID, ""))
		_ = b.audit.Log(AuditEntry{
			Sandbox: item.sandbox, RemotePeer: b.cfg.RemoteAddr, RemoteID: remoteID,
			ReqID: staged.ReqID, Executable: staged.Executable, Args: staged.Args,
			CWD: staged.CWD, StdinSize: staged.StdinSize, StdinSHA256: staged.StdinSHA256,
			PolicyAction: string(dec.Action), PolicyRuleID: dec.RuleID,
			OperatorEvent: opEvent + "_aborted", Edited: edited,
			Status: remoteproto.StatusDenied, ExitCode: remoteproto.DenyExitCode,
		})
		return
	}

	// Apply policy automatic secret redaction and always-on CLI --redact-pattern rules.
	polNow, _, _ := b.reloader.Current()
	if polNow == nil {
		polNow = pol
	}
	polRedactor, rErr := remoteproto.NewRedactor(polNow.AutoRedact.AutoRedactEnabled(), polNow.AutoRedact.ExtraPatterns)
	if rErr != nil {
		polRedactor, _ = remoteproto.NewRedactor(true, nil)
	}

	stdoutBytes, _ := base64.StdEncoding.DecodeString(resp.StdoutB64)
	stderrBytes, _ := base64.StdEncoding.DecodeString(resp.StderrB64)
	stdoutBytes, rcOut := polRedactor.RedactBytes(stdoutBytes)
	stderrBytes, rcErr := polRedactor.RedactBytes(stderrBytes)
	stdoutBytes, cliOut := b.applyCLIRedact(stdoutBytes)
	stderrBytes, cliErr := b.applyCLIRedact(stderrBytes)
	resp.RedactedCount = rcOut + rcErr + cliOut + cliErr
	resp.StdoutB64 = base64.StdEncoding.EncodeToString(stdoutBytes)
	resp.StderrB64 = base64.StdEncoding.EncodeToString(stderrBytes)

	if needOutputReview && resp.Status != remoteproto.StatusDenied {
		finalOut, finalErr, dropped, approved, note := b.runPhase2Prompt(ctx, item, staged, resp, stdoutBytes, stderrBytes, polNow)
		if !approved {
			b.sendBridgeResp(item.sandbox, item.slotID, remoteproto.DeniedResponse(item.slotID, note))
			_ = b.audit.Log(AuditEntry{
				Sandbox: item.sandbox, RemotePeer: b.cfg.RemoteAddr, RemoteID: remoteID,
				ReqID: staged.ReqID, Executable: staged.Executable, Args: staged.Args,
				CWD: staged.CWD, StdinSize: staged.StdinSize, StdinSHA256: staged.StdinSHA256,
				PolicyAction: string(dec.Action), PolicyRuleID: dec.RuleID,
				OperatorEvent: "phase2_deny", Edited: edited, Status: remoteproto.StatusDenied, ExitCode: remoteproto.DenyExitCode,
				DurationMS: resp.DurationMS, RedactedCount: resp.RedactedCount,
			})
			return
		}
		if dropped {
			resp.StdoutB64 = ""
			resp.StderrB64 = ""
			resp.DroppedOutput = true
		} else {
			resp.StdoutB64 = base64.StdEncoding.EncodeToString(finalOut)
			resp.StderrB64 = base64.StdEncoding.EncodeToString(finalErr)
		}
		opEvent = "phase2_approve"
	}

	if resp.Status == remoteproto.StatusDenied && resp.OperatorNote == "" {
		resp = remoteproto.DeniedResponse(item.slotID, "")
	} else {
		resp.ReqID = item.slotID
	}
	b.sendBridgeResp(item.sandbox, item.slotID, resp)
	_ = b.audit.Log(AuditEntry{
		Sandbox: item.sandbox, RemotePeer: b.cfg.RemoteAddr, RemoteID: remoteID,
		ReqID: staged.ReqID, Executable: staged.Executable, Args: staged.Args,
		CWD: staged.CWD, StdinSize: staged.StdinSize, StdinSHA256: staged.StdinSHA256,
		PolicyAction: string(dec.Action), PolicyRuleID: dec.RuleID,
		OperatorEvent: opEvent, Edited: edited, Status: resp.Status, ExitCode: resp.ExitCode,
		DurationMS: resp.DurationMS, RedactedCount: resp.RedactedCount,
	})
}

func (b *Broker) applyCLIRedact(data []byte) ([]byte, int) {
	if len(b.cliRedactRules) == 0 || len(data) == 0 || bytes.IndexByte(data, 0) >= 0 {
		return data, 0
	}
	cur := string(data)
	total := 0
	for _, re := range b.cliRedactRules {
		matches := re.FindAllStringIndex(cur, -1)
		if len(matches) == 0 {
			continue
		}
		total += len(matches)
		cur = re.ReplaceAllString(cur, "[REDACTED:CUSTOM]")
	}
	if total == 0 {
		return data, 0
	}
	return []byte(cur), total
}

func (b *Broker) executeOnRemote(ctx context.Context, item *queuedRequest, req remoteproto.ExecRequest) (remoteproto.ExecResponse, bool) {
	if item.cancelled.Load() {
		return remoteproto.ExecResponse{}, false
	}
	respCh := make(chan remoteproto.ExecResponse, 1)
	b.respMu.Lock()
	b.respWaiters[req.ReqID] = respCh
	b.respMu.Unlock()

	execCtx, cancelExec := context.WithCancel(ctx)
	b.queueMu.Lock()
	b.activeExecID = req.ReqID
	b.activeExecCnl = cancelExec
	b.queueMu.Unlock()
	defer func() {
		cancelExec()
		b.queueMu.Lock()
		b.activeExecID = ""
		b.activeExecCnl = nil
		b.queueMu.Unlock()
		b.respMu.Lock()
		delete(b.respWaiters, req.ReqID)
		b.respMu.Unlock()
	}()

	if err := b.writeRemoteFrame(remoteproto.FrameExecReq, req); err != nil {
		fmt.Fprintf(b.cfg.Stderr, "[agbox-remote] Failed to send request %s: %v\n", req.ReqID, err)
		return remoteproto.ExecResponse{}, false
	}

	start := time.Now()
	preview := remoteproto.FormatShellPreview(req.Executable, req.Args)
	if len(preview) > 60 {
		preview = preview[:57] + "..."
	}
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	fmt.Fprintf(b.cfg.Stdout, "[agbox-remote] Running [%s] %s (Ctrl-C to cancel command)\n", req.ReqID, preview)
	for {
		select {
		case resp, open := <-respCh:
			if !open || item.cancelled.Load() {
				return remoteproto.ExecResponse{}, false
			}
			return resp, true
		case <-execCtx.Done():
			return remoteproto.ExecResponse{}, false
		case <-ticker.C:
			if item.cancelled.Load() {
				return remoteproto.ExecResponse{}, false
			}
			elapsed := int(time.Since(start).Seconds())
			if elapsed > 0 && elapsed%10 == 0 {
				fmt.Fprintf(b.cfg.Stdout, "[agbox-remote] Running [%s] %s (%ds elapsed, Ctrl-C to cancel)\n", req.ReqID, preview, elapsed)
			}
		}
	}
}

func (b *Broker) askTimeoutDuration(pol *remotepolicy.Policy) time.Duration {
	if b.cfg.AskTimeout > 0 {
		return b.cfg.AskTimeout
	}
	if pol != nil && pol.Limits.AskTimeoutSec > 0 {
		return time.Duration(pol.Limits.AskTimeoutSec) * time.Second
	}
	return time.Duration(remoteproto.DefaultAskTimeoutSec) * time.Second
}

func (b *Broker) runPhase1Prompt(
	ctx context.Context,
	item *queuedRequest,
	queuedRest int,
	helloR remoteproto.HelloPayload,
	dec remotepolicy.Decision,
	staged *remoteproto.ExecRequest,
	stdinBytes *[]byte,
	needOutputReview bool,
	pol *remotepolicy.Policy,
) (approved bool, reviewOut bool, denyNote string, edited bool, addSession bool) {
	// Flush unread terminal input before presenting Phase 1 so stray idle input never approves.
	b.flushStdinTTY()

	reviewOut = needOutputReview
	remaining := b.askTimeoutDuration(pol)

	for {
		if item.cancelled.Load() {
			fmt.Fprintln(b.cfg.Stdout, "[agbox-remote] Request cancelled by guest.")
			return false, false, "", edited, false
		}
		b.printPhase1Card(item, queuedRest, helloR, dec, *staged, *stdinBytes, reviewOut, edited)

		hasStdin := len(*stdinBytes) > 0
		stdinUTF8 := hasStdin && !remoteproto.IsBinary(*stdinBytes)
		canSession := !hasStdin && !remotepolicy.IsInterpreterOrWrapper(staged.Executable)

		var actions []string
		actions = append(actions, "[a]pprove")
		if !reviewOut {
			actions = append(actions, "[o]utput-review+approve")
		}
		if canSession {
			actions = append(actions, "[s]ession-exact")
		}
		actions = append(actions, "[e]dit")
		if stdinUTF8 {
			actions = append(actions, "[i]edit-stdin")
		}
		if hasStdin {
			actions = append(actions, "[v]iew-stdin")
		}
		actions = append(actions, "[m]deny-with-note", "[d]eny (default)")
		fmt.Fprintf(b.cfg.Stdout, "Choice (%s): ", strings.Join(actions, "  "))

		promptStart := time.Now()
		pCtx, pCancel := context.WithTimeout(ctx, remaining)
		line, err := b.readLinePollCancel(pCtx, &item.cancelled)
		pCancel()
		elapsed := time.Since(promptStart)
		remaining -= elapsed

		if item.cancelled.Load() {
			fmt.Fprintln(b.cfg.Stdout, "\n[agbox-remote] Request cancelled by guest.")
			return false, false, "", edited, false
		}
		if err != nil {
			fmt.Fprintln(b.cfg.Stdout, "\n[agbox-remote] Approval timed out or aborted. Denying.")
			return false, false, "", edited, false
		}

		choice := strings.ToLower(strings.TrimSpace(line))
		switch choice {
		case "", "d", "deny":
			return false, false, "", edited, false
		case "a", "approve":
			return true, reviewOut, "", edited, false
		case "o":
			if !reviewOut {
				return true, true, "", edited, false
			}
		case "s":
			if canSession {
				return true, reviewOut, "", edited, true
			}
		case "m":
			fmt.Fprint(b.cfg.Stdout, "Operator note for agent (1 line, Enter to omit): ")
			nCtx, nCancel := context.WithTimeout(ctx, 30*time.Second)
			noteLine, nErr := b.readLinePollCancel(nCtx, &item.cancelled)
			nCancel()
			if item.cancelled.Load() || nErr != nil {
				return false, false, "", edited, false
			}
			return false, false, remoteproto.SanitizeLine(strings.TrimSpace(noteLine)), edited, false
		case "v":
			if hasStdin {
				// Ask-timeout stays paused while pager is open.
				b.viewText(ctx, remoteproto.SanitizeMultiline(string(*stdinBytes), "  ", 0, 0))
			}
		case "e":
			// Ask-timeout stays paused while editor is open.
			if ok := b.editPhase1Request(ctx, item, staged, &reviewOut, helloR); ok {
				edited = true
			}
		case "i":
			if stdinUTF8 {
				if ok := b.editPhase1Stdin(ctx, staged, stdinBytes); ok {
					edited = true
				}
			}
		default:
			fmt.Fprintf(b.cfg.Stdout, "[agbox-remote] Unknown choice %q.\n", remoteproto.SanitizeLine(choice))
		}
		if remaining <= 0 {
			fmt.Fprintln(b.cfg.Stdout, "[agbox-remote] Approval timed out. Denying.")
			return false, false, "", edited, false
		}
	}
}

func (b *Broker) printPhase1Card(
	item *queuedRequest,
	queuedRest int,
	helloR remoteproto.HelloPayload,
	dec remotepolicy.Decision,
	req remoteproto.ExecRequest,
	stdinBytes []byte,
	reviewOut bool,
	edited bool,
) {
	tag := ""
	if edited {
		tag = " [EDITED]"
	}
	qStr := ""
	if queuedRest > 0 {
		qStr = fmt.Sprintf(" [queued: %d]", queuedRest)
	}
	revStr := "OFF"
	if reviewOut {
		revStr = "ON"
	}
	fmt.Fprintf(b.cfg.Stdout, "\n================ PHASE 1: REMOTE COMMAND REVIEW%s%s ================\n", tag, qStr)
	fmt.Fprintf(b.cfg.Stdout, "Sandbox:       %s\n", remoteproto.SanitizeLine(item.sandbox))
	fmt.Fprintf(b.cfg.Stdout, "Target:        %s@%s (uid=%d) [%s]\n",
		remoteproto.SanitizeLine(helloR.User), remoteproto.SanitizeLine(helloR.Host), helloR.UID, remoteproto.SanitizeLine(b.cfg.RemoteAddr))
	if helloR.UID == 0 {
		fmt.Fprintln(b.cfg.Stdout, "WARNING:       REMOTE DAEMON IS RUNNING AS ROOT (uid=0)")
	}
	fmt.Fprintf(b.cfg.Stdout, "Policy:        %s (%s) | output-review=%s | timeout=%ds | max-output=%d\n",
		dec.Action, remoteproto.SanitizeLine(dec.Reason), revStr, req.ExecTimeoutSec, req.MaxOutputBytes)
	fmt.Fprintf(b.cfg.Stdout, "Command:       %s\n", remoteproto.FormatShellPreview(req.Executable, req.Args))
	fmt.Fprintf(b.cfg.Stdout, "  argv[0]:     %q\n", remoteproto.SanitizeLine(req.Executable))
	for i, a := range req.Args {
		fmt.Fprintf(b.cfg.Stdout, "  argv[%d]:     %q\n", i+1, remoteproto.SanitizeLine(a))
	}
	cwdShown := req.CWD
	if cwdShown == "" {
		cwdShown = helloR.DefaultCWD + " (default)"
	}
	fmt.Fprintf(b.cfg.Stdout, "CWD:           %s\n", remoteproto.SanitizeLine(cwdShown))
	if req.Reason != "" {
		fmt.Fprintf(b.cfg.Stdout, "Reason:        %s\n", remoteproto.SanitizeLine(req.Reason))
	}
	if len(stdinBytes) > 0 {
		kind := "utf-8"
		if remoteproto.IsBinary(stdinBytes) {
			kind = "binary"
		}
		fmt.Fprintf(b.cfg.Stdout, "Stdin:         %d bytes (%s, sha256=%s)\n", len(stdinBytes), kind, req.StdinSHA256[:16])
		if kind == "utf-8" {
			fmt.Fprintln(b.cfg.Stdout, remoteproto.SanitizeMultiline(string(stdinBytes), "  | ", 8, 1024))
		}
	} else {
		fmt.Fprintln(b.cfg.Stdout, "Stdin:         (empty)")
	}
	fmt.Fprintln(b.cfg.Stdout, "=====================================================================")
}

func (b *Broker) editPhase1Request(ctx context.Context, item *queuedRequest, staged *remoteproto.ExecRequest, reviewOut *bool, helloR remoteproto.HelloPayload) bool {
	draft := editRequestPayload{
		Executable:     staged.Executable,
		Args:           append([]string(nil), staged.Args...),
		CWD:            staged.CWD,
		ExecTimeoutSec: staged.ExecTimeoutSec,
		MaxOutputBytes: staged.MaxOutputBytes,
		OutputReview:   *reviewOut,
	}
	raw, _ := json.MarshalIndent(draft, "", "  ")
	raw = remoteproto.EscapeJSONControls(append(raw, '\n'))

	for {
		if item.cancelled.Load() {
			return false
		}
		editedRaw, err := b.editBytes(ctx, "req", raw)
		if err != nil {
			fmt.Fprintf(b.cfg.Stderr, "[agbox-remote] Edit aborted: %v\n", err)
			return false
		}
		var next editRequestPayload
		if err := remoteproto.DecodeStrict(editedRaw, &next); err != nil {
			if !b.askRetryEdit(ctx, &item.cancelled, fmt.Sprintf("invalid JSON (%v)", err)) {
				return false
			}
			raw = editedRaw
			continue
		}
		if err := remotepolicy.ValidateExecutable(next.Executable); err != nil {
			if !b.askRetryEdit(ctx, &item.cancelled, err.Error()) {
				return false
			}
			raw = editedRaw
			continue
		}
		var nulErr string
		for i, a := range next.Args {
			if strings.IndexByte(a, 0) >= 0 {
				nulErr = fmt.Sprintf("args[%d] contains NUL byte", i)
				break
			}
		}
		if nulErr != "" {
			if !b.askRetryEdit(ctx, &item.cancelled, nulErr) {
				return false
			}
			raw = editedRaw
			continue
		}
		if err := remotepolicy.ValidateCWD(next.CWD); err != nil {
			if !b.askRetryEdit(ctx, &item.cancelled, err.Error()) {
				return false
			}
			raw = editedRaw
			continue
		}

		// Re-reload policy and check DENY-ALL + hard caps + deny rules before accepting edit.
		b.reloader.CheckReload()
		pol, denyAll, dErr := b.reloader.Current()
		if denyAll {
			fmt.Fprintf(b.cfg.Stderr, "[agbox-remote] Policy is in DENY-ALL (%v). Edit rejected.\n", dErr)
			return false
		}
		capOut := pol.Limits.MaxOutputBytes
		if b.cfg.MaxOutputBytes > 0 && b.cfg.MaxOutputBytes < capOut {
			capOut = b.cfg.MaxOutputBytes
		}
		if helloR.MaxOutputBytes > 0 && helloR.MaxOutputBytes < capOut {
			capOut = helloR.MaxOutputBytes
		}
		if capOut > remoteproto.MaxOutputBytes {
			capOut = remoteproto.MaxOutputBytes
		}
		if next.MaxOutputBytes <= 0 || next.MaxOutputBytes > capOut {
			next.MaxOutputBytes = capOut
		}
		capTimeout := pol.Limits.MaxExecTimeoutSec
		if helloR.MaxExecTimeoutSec > 0 && helloR.MaxExecTimeoutSec < capTimeout {
			capTimeout = helloR.MaxExecTimeoutSec
		}
		if next.ExecTimeoutSec <= 0 || next.ExecTimeoutSec > capTimeout {
			next.ExecTimeoutSec = capTimeout
		}
		checkDec := remotepolicy.Evaluate(pol, remotepolicy.EvalInput{
			Executable:     next.Executable,
			Args:           next.Args,
			CWD:            next.CWD,
			DefaultCWD:     helloR.DefaultCWD,
			StdinSize:      staged.StdinSize,
			ExecTimeoutSec: next.ExecTimeoutSec,
			MaxOutputBytes: next.MaxOutputBytes,
		}, nil)
		if checkDec.Action == remotepolicy.ActionDeny {
			fmt.Fprintf(b.cfg.Stderr, "[agbox-remote] WARN: edited command matches policy DENY (%s).\n", checkDec.Reason)
			if !b.askRetryEdit(ctx, &item.cancelled, "edited command violates a deny rule") {
				return false
			}
			raw = editedRaw
			continue
		}

		fmt.Fprintf(b.cfg.Stdout, "[agbox-remote] Diff: %s  ->  %s\n",
			remoteproto.FormatShellPreview(staged.Executable, staged.Args),
			remoteproto.FormatShellPreview(next.Executable, next.Args))
		staged.Executable = next.Executable
		staged.Args = next.Args
		staged.CWD = next.CWD
		staged.ExecTimeoutSec = next.ExecTimeoutSec
		staged.MaxOutputBytes = next.MaxOutputBytes
		staged.DenyCWDScopes = checkDec.DenyCWDScopes
		*reviewOut = next.OutputReview
		return true
	}
}

func (b *Broker) editPhase1Stdin(ctx context.Context, staged *remoteproto.ExecRequest, stdinBytes *[]byte) bool {
	editedRaw, err := b.editBytes(ctx, "stdin", *stdinBytes)
	if err != nil {
		fmt.Fprintf(b.cfg.Stderr, "[agbox-remote] Stdin edit aborted: %v\n", err)
		return false
	}
	if len(editedRaw) > remoteproto.MaxStdinBytes {
		fmt.Fprintf(b.cfg.Stderr, "[agbox-remote] Edited stdin exceeds %d bytes. Keeping previous stdin.\n", remoteproto.MaxStdinBytes)
		return false
	}
	*stdinBytes = editedRaw
	staged.StdinSize = len(editedRaw)
	if len(editedRaw) == 0 {
		staged.StdinB64 = ""
		staged.StdinSHA256 = ""
	} else {
		staged.StdinB64 = base64.StdEncoding.EncodeToString(editedRaw)
		sum := sha256.Sum256(editedRaw)
		staged.StdinSHA256 = hex.EncodeToString(sum[:])
	}
	return true
}

func (b *Broker) runPhase2Prompt(
	ctx context.Context,
	item *queuedRequest,
	req remoteproto.ExecRequest,
	resp remoteproto.ExecResponse,
	stdoutBytes, stderrBytes []byte,
	pol *remotepolicy.Policy,
) (finalOut, finalErr []byte, dropped, approved bool, denyNote string) {
	// Flush unread terminal input before presenting Phase 2 so stray execution-time keystrokes never approve.
	b.flushStdinTTY()

	curOut := append([]byte(nil), stdoutBytes...)
	curErr := append([]byte(nil), stderrBytes...)
	remaining := b.askTimeoutDuration(pol)

	for {
		if item.cancelled.Load() {
			return nil, nil, false, false, ""
		}
		outBin := remoteproto.IsBinary(curOut)
		errBin := remoteproto.IsBinary(curErr)
		hasOut := len(curOut) > 0
		hasErr := len(curErr) > 0

		fmt.Fprintf(b.cfg.Stdout, "\n================ PHASE 2: OUTPUT REVIEW [%s] ================\n", req.ReqID)
		fmt.Fprintf(b.cfg.Stdout, "Command:  %s\n", remoteproto.FormatShellPreview(req.Executable, req.Args))
		fmt.Fprintf(b.cfg.Stdout, "Result:   status=%s exit=%d duration=%dms auto-redacted=%d\n",
			resp.Status, resp.ExitCode, resp.DurationMS, resp.RedactedCount)
		fmt.Fprintf(b.cfg.Stdout, "Stdout:   %d bytes (truncated=%v, binary=%v)\n", len(curOut), resp.StdoutTruncated, outBin)
		if hasOut && !outBin {
			fmt.Fprintln(b.cfg.Stdout, remoteproto.SanitizeMultiline(string(curOut), "  out| ", 12, 2048))
		}
		fmt.Fprintf(b.cfg.Stdout, "Stderr:   %d bytes (truncated=%v, binary=%v)\n", len(curErr), resp.StderrTruncated, errBin)
		if hasErr && !errBin {
			fmt.Fprintln(b.cfg.Stdout, remoteproto.SanitizeMultiline(string(curErr), "  err| ", 8, 1024))
		}
		fmt.Fprintln(b.cfg.Stdout, "==============================================================")

		var actions []string
		actions = append(actions, "[a]pprove")
		if hasOut || hasErr {
			actions = append(actions, "[v]iew-full")
		}
		canEditOut := hasOut && !outBin
		canEditErr := hasErr && !errBin
		switch {
		case canEditOut && canEditErr:
			actions = append(actions, "[r1]redact-stdout", "[r2]redact-stderr")
		case canEditOut:
			actions = append(actions, "[r]edact-stdout")
		case canEditErr:
			actions = append(actions, "[r]edact-stderr")
		}
		if hasOut || hasErr {
			actions = append(actions, "[x]drop-output")
		}
		actions = append(actions, "[m]deny-with-note", "[d]eny (default)")
		fmt.Fprintf(b.cfg.Stdout, "Choice (%s): ", strings.Join(actions, "  "))

		promptStart := time.Now()
		pCtx, pCancel := context.WithTimeout(ctx, remaining)
		line, err := b.readLinePollCancel(pCtx, &item.cancelled)
		pCancel()
		elapsed := time.Since(promptStart)
		remaining -= elapsed

		if item.cancelled.Load() || err != nil {
			fmt.Fprintln(b.cfg.Stdout, "\n[agbox-remote] Output review timed out or aborted. Denying.")
			return nil, nil, false, false, ""
		}

		choice := strings.ToLower(strings.TrimSpace(line))
		switch choice {
		case "", "d", "deny":
			return nil, nil, false, false, ""
		case "a", "approve":
			return curOut, curErr, false, true, ""
		case "x":
			if hasOut || hasErr {
				return nil, nil, true, true, ""
			}
		case "m":
			fmt.Fprint(b.cfg.Stdout, "Operator note for agent (1 line, Enter to omit): ")
			nCtx, nCancel := context.WithTimeout(ctx, 30*time.Second)
			noteLine, nErr := b.readLinePollCancel(nCtx, &item.cancelled)
			nCancel()
			if item.cancelled.Load() || nErr != nil {
				return nil, nil, false, false, ""
			}
			return nil, nil, false, false, remoteproto.SanitizeLine(strings.TrimSpace(noteLine))
		case "v":
			if hasOut || hasErr {
				var full strings.Builder
				if hasOut {
					full.WriteString("=== STDOUT ===\n")
					full.WriteString(remoteproto.SanitizeMultiline(string(curOut), "", 0, 0))
					full.WriteByte('\n')
				}
				if hasErr {
					full.WriteString("=== STDERR ===\n")
					full.WriteString(remoteproto.SanitizeMultiline(string(curErr), "", 0, 0))
					full.WriteByte('\n')
				}
				b.viewText(ctx, full.String())
			}
		case "r":
			if canEditOut && !canEditErr {
				if ed, eErr := b.editBytes(ctx, "stdout", curOut); eErr == nil {
					curOut = ed
				}
			} else if canEditErr && !canEditOut {
				if ed, eErr := b.editBytes(ctx, "stderr", curErr); eErr == nil {
					curErr = ed
				}
			}
		case "r1":
			if canEditOut {
				if ed, eErr := b.editBytes(ctx, "stdout", curOut); eErr == nil {
					curOut = ed
				}
			}
		case "r2":
			if canEditErr {
				if ed, eErr := b.editBytes(ctx, "stderr", curErr); eErr == nil {
					curErr = ed
				}
			}
		default:
			fmt.Fprintf(b.cfg.Stdout, "[agbox-remote] Unknown choice %q.\n", remoteproto.SanitizeLine(choice))
		}
		if remaining <= 0 {
			fmt.Fprintln(b.cfg.Stdout, "[agbox-remote] Output review timed out. Denying.")
			return nil, nil, false, false, ""
		}
	}
}

func (b *Broker) askRetryEdit(ctx context.Context, cancelled *atomic.Bool, errMsg string) bool {
	if cancelled != nil && cancelled.Load() {
		return false
	}
	fmt.Fprintf(b.cfg.Stderr, "[agbox-remote] Edit validation error: %s\n", errMsg)
	fmt.Fprint(b.cfg.Stdout, "Choice ([e] re-edit draft  [d] cancel edit): ")
	line, err := b.readLinePollCancel(ctx, cancelled)
	if err != nil || (cancelled != nil && cancelled.Load()) {
		return false
	}
	return strings.ToLower(strings.TrimSpace(line)) == "e"
}

func (b *Broker) suspendSignals() func() {
	b.sigPaused.Store(true)
	return func() {
		b.sigPaused.Store(false)
	}
}

func (b *Broker) editBytes(ctx context.Context, prefix string, content []byte) ([]byte, error) {
	if b.cfg.EditBytes != nil {
		return b.cfg.EditBytes(ctx, prefix, content)
	}
	return EditBytesInEditor(ctx, b.cfg.DataDir, prefix, content, remoteproto.MaxOutputBytes, b.cfg.Getenv, b.cfg.Stdin, b.cfg.Stdout, b.cfg.Stderr, b.suspendSignals)
}

func (b *Broker) viewText(ctx context.Context, text string) {
	if b.cfg.ViewText != nil {
		b.cfg.ViewText(ctx, text)
		return
	}
	ViewInPager(ctx, text, b.cfg.Getenv, b.cfg.Stdin, b.cfg.Stdout, b.cfg.Stderr, b.suspendSignals)
}

func (b *Broker) flushStdinTTY() {
	if f, ok := b.cfg.Stdin.(*os.File); ok && f != nil {
		FlushTTYInput(int(f.Fd()))
	}
}

func (b *Broker) readIdleOrWake(ctx context.Context) (string, bool, error) {
	if f, ok := b.cfg.Stdin.(*os.File); ok && f != nil && b.wakeR >= 0 {
		return b.pollReadLine(ctx, int(f.Fd()), true, nil)
	}
	// Non-file io.Reader fallback for unit tests.
	type res struct {
		line string
		err  error
	}
	ch := make(chan res, 1)
	go func() {
		s, err := readLineFromReader(b.cfg.Stdin)
		ch <- res{line: s, err: err}
	}()
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return "", false, ctx.Err()
		case r := <-ch:
			return r.line, false, r.err
		case <-ticker.C:
			b.queueMu.Lock()
			hasQ := len(b.queue) > 0
			b.queueMu.Unlock()
			b.logMu.Lock()
			hasL := len(b.logBuf) > 0
			b.logMu.Unlock()
			if hasQ || hasL {
				return "", true, nil
			}
		}
	}
}

func (b *Broker) readLinePoll(ctx context.Context) (string, error) {
	return b.readLinePollCancel(ctx, nil)
}

func (b *Broker) readLinePollCancel(ctx context.Context, cancelled *atomic.Bool) (string, error) {
	if f, ok := b.cfg.Stdin.(*os.File); ok && f != nil && b.wakeR >= 0 {
		line, _, err := b.pollReadLine(ctx, int(f.Fd()), false, cancelled)
		return line, err
	}
	type res struct {
		line string
		err  error
	}
	ch := make(chan res, 1)
	go func() {
		s, err := readLineFromReader(b.cfg.Stdin)
		ch <- res{line: s, err: err}
	}()
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case r := <-ch:
			return r.line, r.err
		case <-ticker.C:
			if cancelled != nil && cancelled.Load() {
				return "", context.Canceled
			}
		}
	}
}

func (b *Broker) pollReadLine(ctx context.Context, ttyFD int, wakeOnPipe bool, cancelled *atomic.Bool) (string, bool, error) {
	var buf []byte
	one := make([]byte, 1)
	for {
		if ctx.Err() != nil {
			return "", false, ctx.Err()
		}
		if cancelled != nil && cancelled.Load() {
			return "", false, context.Canceled
		}
		pfds := []unix.PollFd{
			{Fd: int32(ttyFD), Events: unix.POLLIN},
			{Fd: int32(b.wakeR), Events: unix.POLLIN},
		}
		n, err := unix.Poll(pfds, 100)
		if err != nil {
			if errors.Is(err, unix.EINTR) {
				continue
			}
			return "", false, err
		}
		if n == 0 {
			continue
		}
		if pfds[1].Revents&unix.POLLIN != 0 {
			b.drainWake()
			if wakeOnPipe && len(buf) == 0 {
				return "", true, nil
			}
			if cancelled != nil && cancelled.Load() {
				return "", false, context.Canceled
			}
		}
		if pfds[0].Revents&(unix.POLLERR|unix.POLLNVAL) != 0 {
			return string(buf), false, io.EOF
		}
		if pfds[0].Revents&(unix.POLLIN|unix.POLLHUP) != 0 {
			rn, rErr := unix.Read(ttyFD, one)
			if rn > 0 {
				if one[0] == '\n' {
					return string(buf), false, nil
				}
				buf = append(buf, one[0])
				if len(buf) > 4096 {
					return string(buf), false, nil
				}
				continue
			}
			if rErr != nil {
				if errors.Is(rErr, unix.EINTR) {
					continue
				}
				if len(buf) > 0 && errors.Is(rErr, unix.EIO) {
					return string(buf), false, nil
				}
				return string(buf), false, rErr
			}
			if rn == 0 {
				if len(buf) > 0 {
					return string(buf), false, nil
				}
				return "", false, io.EOF
			}
		}
	}
}

func readLineFromReader(r io.Reader) (string, error) {
	var buf []byte
	one := make([]byte, 1)
	for {
		n, err := r.Read(one)
		if n > 0 {
			if one[0] == '\n' {
				return string(buf), nil
			}
			buf = append(buf, one[0])
		}
		if err != nil {
			if len(buf) > 0 && errors.Is(err, io.EOF) {
				return string(buf), nil
			}
			return string(buf), err
		}
	}
}

// EvaluateAndFormatPolicyTest runs offline policy evaluation for `agbox remote policy test`.
func EvaluateAndFormatPolicyTest(pol *remotepolicy.Policy, req remotepolicy.EvalInput) (remotepolicy.Decision, string) {
	dec := remotepolicy.Evaluate(pol, req, nil)
	var b strings.Builder
	fmt.Fprintf(&b, "action:        %s\n", dec.Action)
	if dec.RuleID != "" {
		fmt.Fprintf(&b, "rule_id:       %s\n", dec.RuleID)
	}
	if dec.RuleDescription != "" {
		fmt.Fprintf(&b, "description:   %s\n", dec.RuleDescription)
	}
	fmt.Fprintf(&b, "reason:        %s\n", dec.Reason)
	fmt.Fprintf(&b, "output_review: %v\n", dec.OutputReview)
	fmt.Fprintf(&b, "max_output:    %d\n", dec.MaxOutputBytes)
	fmt.Fprintf(&b, "max_timeout:   %ds\n", dec.MaxExecTimeoutSec)
	return dec, b.String()
}
