package remotedaemon

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"agbox/internal/remoteproto"

	"golang.org/x/sys/unix"
)

func TestValidatePassEnvAndSanitizePATH(t *testing.T) {
	for _, bad := range []string{"LD_PRELOAD", "LD_AUDIT", "PATH", "PWD", "IFS", "BASH_ENV", "PYTHONPATH", "NODE_OPTIONS", "GIT_SSH_COMMAND", "FOO=bar", "1BAD", ""} {
		if err := ValidatePassEnv(bad); err == nil {
			t.Errorf("expected ValidatePassEnv(%q) to fail", bad)
		}
	}
	for _, ok := range []string{"KUBECONFIG", "AWS_REGION", "MY_APP_ENV"} {
		if err := ValidatePassEnv(ok); err != nil {
			t.Errorf("expected ValidatePassEnv(%q) to pass, got %v", ok, err)
		}
	}

	// SanitizePATH strips relative, '.', and world-writable directories.
	tmp := t.TempDir()
	wwDir := filepath.Join(tmp, "world-writable")
	if err := os.Mkdir(wwDir, 0o777); err != nil {
		t.Fatal(err)
	}
	_ = os.Chmod(wwDir, 0o777)

	safeDir := filepath.Join(tmp, "safe-bin")
	if err := os.Mkdir(safeDir, 0o700); err != nil {
		t.Fatal(err)
	}

	got := SanitizePATH(".:relative:"+wwDir+":"+safeDir, false, os.Geteuid())
	if strings.Contains(got, wwDir) || strings.Contains(got, "relative") {
		t.Fatalf("SanitizePATH retained unsafe entry: %q", got)
	}
	if !strings.Contains(got, safeDir) {
		t.Fatalf("SanitizePATH dropped safe user dir: %q", got)
	}

	strict := SanitizePATH(safeDir, true, os.Geteuid())
	if strings.Contains(strict, safeDir) {
		t.Fatalf("strict SanitizePATH should not include custom dir: %q", strict)
	}
}

func TestLookPathInIgnoresHostPATH(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "mytool")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\necho ok\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	// Present in dir -> found when dir is in sanitizedPATH, NOT found when omitted even if in host PATH.
	t.Setenv("PATH", dir)
	if got, err := LookPathIn(dir, "mytool"); err != nil || got != bin {
		t.Fatalf("LookPathIn(%q, mytool) = (%q, %v)", dir, got, err)
	}
	if _, err := LookPathIn("/usr/bin:/bin", "mytool"); err == nil {
		t.Fatal("LookPathIn must ignore os.Getenv(PATH)")
	}
}

func TestPinCWDAndSymlinkEscape(t *testing.T) {
	base := t.TempDir()
	allowed := filepath.Join(base, "allowed")
	secret := filepath.Join(base, "secret")
	if err := os.MkdirAll(allowed, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(secret, 0o700); err != nil {
		t.Fatal(err)
	}
	escapeLink := filepath.Join(allowed, "link-to-secret")
	if err := os.Symlink(secret, escapeLink); err != nil {
		t.Fatal(err)
	}

	// Symlink inside allowed pointing to secret must fail allowCWD check.
	if fd, _, err := PinCWD(escapeLink, allowed, []string{allowed}, nil, nil); err == nil {
		_ = os.NewFile(uintptr(fd), "").Close()
		t.Fatal("expected symlink escape outside allowCWD to be rejected")
	}

	// Valid dir inside allowed passes and matches canonical path.
	fd, canon, err := PinCWD(allowed, allowed, []string{allowed}, nil, nil)
	if err != nil {
		t.Fatalf("PinCWD(allowed) failed: %v", err)
	}
	_ = os.NewFile(uintptr(fd), "").Close()
	if canon == "" {
		t.Fatal("expected non-empty canonical cwd")
	}

	// Separate deny_cwd_scopes rejects secret even if allowCWD is empty.
	deny := []remoteproto.CWDScope{{In: []string{secret}}}
	if fd, _, err := PinCWD(escapeLink, allowed, nil, nil, deny); err == nil {
		_ = os.NewFile(uintptr(fd), "").Close()
		t.Fatal("expected symlink target in deny_cwd_scopes to be rejected")
	}
}

func TestExecuteCommandIsolationNoNewPrivsAndSetsid(t *testing.T) {
	wd := t.TempDir()
	cfg := ExecConfig{
		SanitizedPATH:  SanitizePATH("", true, os.Geteuid()),
		DefaultCWD:     wd,
		AllowCWD:       []string{wd},
		MaxOutputBytes: 4096,
		MaxStdinBytes:  1024,
		ExecTimeout:    10 * time.Second,
		AllowNewPrivs:  false,
	}

	// Verify PR_SET_NO_NEW_PRIVS (NoNewPrivs: 1) in /proc/self/status and /dev/tty detachment.
	resp := ExecuteCommand(context.Background(), cfg, remoteproto.ExecRequest{
		ReqID:      "req-1",
		Executable: "/bin/sh",
		Args:       []string{"-c", "grep '^NoNewPrivs:' /proc/self/status; if (exec </dev/tty) 2>/dev/null; then echo HAS_TTY; else echo NO_TTY; fi; pwd"},
		CWD:        wd,
	})
	if resp.Status != remoteproto.StatusCompleted || resp.ExitCode != 0 {
		t.Fatalf("unexpected resp: %+v", resp)
	}
	outBytes, _ := base64.StdEncoding.DecodeString(resp.StdoutB64)
	out := string(outBytes)
	if !strings.Contains(out, "NoNewPrivs:\t1") {
		t.Errorf("expected NoNewPrivs: 1 in child /proc/self/status, got %q", out)
	}
	if !strings.Contains(out, "NO_TTY") {
		t.Errorf("expected /dev/tty detached via Setsid, got %q", out)
	}

	// Verify stdin delivery and timeout enforcement.
	resp2 := ExecuteCommand(context.Background(), cfg, remoteproto.ExecRequest{
		ReqID:      "req-2",
		Executable: "cat",
		StdinB64:   base64.StdEncoding.EncodeToString([]byte("hello-stdin\n")),
	})
	out2, _ := base64.StdEncoding.DecodeString(resp2.StdoutB64)
	if resp2.Status != remoteproto.StatusCompleted || string(out2) != "hello-stdin\n" {
		t.Fatalf("unexpected cat stdin resp: %+v out=%q", resp2, string(out2))
	}

	resp3 := ExecuteCommand(context.Background(), cfg, remoteproto.ExecRequest{
		ReqID:          "req-3",
		Executable:     "sleep",
		Args:           []string{"5"},
		ExecTimeoutSec: 1,
	})
	if resp3.Status != remoteproto.StatusTimeout || resp3.ExitCode != remoteproto.TimeoutExitCode {
		t.Fatalf("expected timeout status, got %+v", resp3)
	}
}

func TestAllowFromIPv4MappedIPv6Unmap(t *testing.T) {
	d, err := New(Config{
		ListenAddr: "127.0.0.1:0",
		AllowFrom:  []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")},
	})
	if err != nil {
		t.Fatal(err)
	}
	mapped := &net.TCPAddr{IP: net.ParseIP("::ffff:127.0.0.1"), Port: 54321}
	if _, ok := d.allowPeerIP(mapped); !ok {
		t.Fatal("expected ::ffff:127.0.0.1 to match 127.0.0.1/32 after Unmap()")
	}
	other := &net.TCPAddr{IP: net.ParseIP("::ffff:10.0.0.5"), Port: 54321}
	if _, ok := d.allowPeerIP(other); ok {
		t.Fatal("expected ::ffff:10.0.0.5 to be rejected by 127.0.0.1/32")
	}
}

func TestPinCWDCanonicalizedScopesAndUnlinkedDir(t *testing.T) {
	base := t.TempDir()
	realRoot := filepath.Join(base, "real-home")
	appDir := filepath.Join(realRoot, "app")
	secretDir := filepath.Join(realRoot, "secret")
	if err := os.MkdirAll(appDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(secretDir, 0o700); err != nil {
		t.Fatal(err)
	}
	symRoot := filepath.Join(base, "home")
	if err := os.Symlink(realRoot, symRoot); err != nil {
		t.Fatal(err)
	}

	// H4: allowScope with symlink parent matches canonical appDir.
	allowScope := &remoteproto.CWDScope{In: []string{filepath.Join(symRoot, "app")}}
	fd, canon, err := PinCWD(appDir, appDir, nil, allowScope, nil)
	if err != nil {
		t.Fatalf("expected symlinked allowScope root to canonicalize and match: %v", err)
	}
	_ = unix.Close(fd)
	if canon != appDir {
		t.Fatalf("canon = %q, want %q", canon, appDir)
	}

	// H4: denyScopes with symlink parent denies canonical secretDir even when passed directly.
	denyScopes := []remoteproto.CWDScope{{In: []string{filepath.Join(symRoot, "secret")}}}
	if fd, _, err := PinCWD(secretDir, appDir, nil, nil, denyScopes); err == nil {
		_ = unix.Close(fd)
		t.Fatal("expected symlinked denyScopes root to canonicalize and reject secretDir")
	}

	// Unlinked directory is rejected.
	goneDir := filepath.Join(realRoot, "gone")
	if err := os.Mkdir(goneDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(goneDir); err != nil {
		t.Fatal(err)
	}
	if fd, _, err := PinCWD(goneDir, appDir, nil, nil, nil); err == nil {
		_ = unix.Close(fd)
		t.Fatal("expected unlinked directory to be rejected")
	}
}

func TestBuildCleanEnvSweepFDsAndExecBoundaries(t *testing.T) {
	// BuildCleanEnv excludes host secrets, blocks PWD/PATH override, and deduplicates base keys.
	fakeEnv := map[string]string{
		"HOME":        "/home/tester",
		"USER":        "tester",
		"LANG":        "en_US.UTF-8",
		"TERM":        "xterm-256color",
		"PWD":         "/evil",
		"PATH":        "/evil/bin",
		"AWS_SECRET":  "do-not-leak",
		"CUSTOM_PASS": "ok-val",
		"LOGNAME":     "tester",
	}
	env := BuildCleanEnv(ExecConfig{
		SanitizedPATH: "/usr/bin:/bin",
		PassEnv:       []string{"HOME", "USER", "LOGNAME", "LANG", "TERM", "PWD", "PATH", "CUSTOM_PASS", "CUSTOM_PASS"},
		Getenv:        func(k string) string { return fakeEnv[k] },
	}, "/srv/work")
	counts := make(map[string]int)
	vals := make(map[string]string)
	for _, kv := range env {
		k, v, _ := strings.Cut(kv, "=")
		counts[k]++
		vals[k] = v
	}
	for _, k := range []string{"HOME", "USER", "LOGNAME", "LANG", "TERM", "PWD", "PATH", "CUSTOM_PASS"} {
		if counts[k] != 1 {
			t.Errorf("expected exactly 1 entry for %s, got %d (%v)", k, counts[k], env)
		}
	}
	if vals["PWD"] != "/srv/work" || vals["PATH"] != "/usr/bin:/bin" || vals["CUSTOM_PASS"] != "ok-val" {
		t.Fatalf("unexpected clean env values: %+v", vals)
	}
	if _, leaked := vals["AWS_SECRET"]; leaked {
		t.Fatal("host secret leaked into clean child env")
	}

	// SweepUnexpectedFDs sets FD_CLOEXEC on an open FD > 2.
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer pr.Close()
	defer pw.Close()
	if _, err := unix.FcntlInt(pr.Fd(), unix.F_SETFD, 0); err != nil {
		t.Fatal(err)
	}
	SweepUnexpectedFDs()
	flags, err := unix.FcntlInt(pr.Fd(), unix.F_GETFD, 0)
	if err != nil {
		t.Fatal(err)
	}
	if flags&unix.FD_CLOEXEC == 0 {
		t.Fatalf("expected SweepUnexpectedFDs to set FD_CLOEXEC, got flags=0x%x", flags)
	}

	// checkExecutableFile rejects non-executable files.
	nonExec := filepath.Join(t.TempDir(), "not-exec")
	if err := os.WriteFile(nonExec, []byte("hi"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := checkExecutableFile(nonExec); err == nil {
		t.Fatal("expected checkExecutableFile to reject mode 0600 file")
	}

	wd := t.TempDir()
	otherDir := t.TempDir()
	cfg := ExecConfig{
		SanitizedPATH:  SanitizePATH("", true, os.Geteuid()),
		DefaultCWD:     wd,
		AllowCWD:       []string{wd},
		MaxOutputBytes: 128,
		MaxStdinBytes:  1024,
		ExecTimeout:    10 * time.Second,
		AllowNewPrivs:  false,
	}

	// Disallowed CWD scope returns StatusDenied.
	respDenied := ExecuteCommand(context.Background(), cfg, remoteproto.ExecRequest{
		ReqID:      "cwd-deny",
		Executable: "/bin/sh",
		Args:       []string{"-c", "echo hi"},
		CWD:        otherDir,
	})
	if respDenied.Status != remoteproto.StatusDenied {
		t.Fatalf("expected StatusDenied for disallowed CWD, got %+v", respDenied)
	}

	// Combined stdout + stderr truncation respects MaxOutputBytes.
	respTrunc := ExecuteCommand(context.Background(), cfg, remoteproto.ExecRequest{
		ReqID:      "trunc-1",
		Executable: "/bin/sh",
		Args:       []string{"-c", "head -c 100 /dev/zero | tr '\\0' 'A'; head -c 100 /dev/zero | tr '\\0' 'B' >&2"},
		CWD:        wd,
	})
	outB, _ := base64.StdEncoding.DecodeString(respTrunc.StdoutB64)
	errB, _ := base64.StdEncoding.DecodeString(respTrunc.StderrB64)
	if respTrunc.Status != remoteproto.StatusCompleted || len(outB)+len(errB) > 128 || (!respTrunc.StdoutTruncated && !respTrunc.StderrTruncated) {
		t.Fatalf("expected combined output <= 128 and truncated flag, got len=%d+%d resp=%+v", len(outB), len(errB), respTrunc)
	}

	// Runaway >16 MiB drain kills the child quickly via SIGKILL.
	startDrain := time.Now()
	respDrain := ExecuteCommand(context.Background(), cfg, remoteproto.ExecRequest{
		ReqID:          "drain-kill",
		Executable:     "/bin/sh",
		Args:           []string{"-c", "dd if=/dev/zero bs=65536 count=512 2>/dev/null"},
		CWD:            wd,
		ExecTimeoutSec: 10,
	})
	if respDrain.Status != remoteproto.StatusCompleted || respDrain.ExitCode == 0 {
		t.Fatalf("expected runaway drain child to be killed with non-zero exit, got %+v", respDrain)
	}
	if time.Since(startDrain) > 5*time.Second {
		t.Fatalf("runaway drain kill took too long: %v", time.Since(startDrain))
	}

	// Grandchild holding stdout pipe open is reaped on timeout via -pid SIGKILL and WaitDelay.
	startGC := time.Now()
	respGC := ExecuteCommand(context.Background(), cfg, remoteproto.ExecRequest{
		ReqID:          "grandchild-timeout",
		Executable:     "/bin/sh",
		Args:           []string{"-c", "(sleep 30) & sleep 30"},
		CWD:            wd,
		ExecTimeoutSec: 1,
	})
	if respGC.Status != remoteproto.StatusTimeout || respGC.ExitCode != remoteproto.TimeoutExitCode {
		t.Fatalf("expected timeout status for grandchild test, got %+v", respGC)
	}
	if time.Since(startGC) > 5*time.Second {
		t.Fatalf("grandchild timeout took too long to reap: %v", time.Since(startGC))
	}
}

type testClientSession struct {
	id        remoteproto.EphemeralIdentity
	conn      *tls.Conn
	serverFP  [32]byte
	sessionID [32]byte
	sas       string
	helloR    remoteproto.HelloPayload
}

func pairTestClient(t *testing.T, addr string, cliID remoteproto.EphemeralIdentity, accept bool) (*testClientSession, error) {
	t.Helper()
	raw, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		return nil, err
	}
	tlsConn := tls.Client(raw, remoteproto.ClientTLSConfig(cliID, nil))
	_ = tlsConn.SetDeadline(time.Now().Add(5 * time.Second))
	if err := tlsConn.Handshake(); err != nil {
		_ = tlsConn.Close()
		return nil, err
	}
	srvDER := tlsConn.ConnectionState().PeerCertificates[0].Raw
	srvFP, _, err := remoteproto.VerifyPeerEd25519Cert([][]byte{srvDER}, nil)
	if err != nil {
		_ = tlsConn.Close()
		return nil, err
	}
	ekm, err := remoteproto.ExportPairingEKM(tlsConn)
	if err != nil {
		_ = tlsConn.Close()
		return nil, err
	}
	typ, payloadR, rawHelloR, err := remoteproto.ReadFrame(tlsConn, remoteproto.PreAuthMaxFrameBytes)
	if err != nil || typ != remoteproto.FrameHello {
		_ = tlsConn.Close()
		return nil, io.ErrUnexpectedEOF
	}
	var helloR remoteproto.HelloPayload
	if err := remoteproto.DecodeStrict(payloadR, &helloR); err != nil {
		_ = tlsConn.Close()
		return nil, err
	}
	rawHelloH, err := remoteproto.WriteFrame(tlsConn, remoteproto.FrameHello, remoteproto.HelloPayload{
		ProtoVer: remoteproto.ProtocolVersion,
		Role:     "host",
	}, remoteproto.PreAuthMaxFrameBytes)
	if err != nil {
		_ = tlsConn.Close()
		return nil, err
	}
	tr := remoteproto.ComputeTranscript(ekm, cliID.DER, srvDER, rawHelloR, rawHelloH)
	nH, err := remoteproto.RandomBytes32()
	if err != nil {
		_ = tlsConn.Close()
		return nil, err
	}
	commit := remoteproto.ComputeCommit(nH, tr)
	if _, err := remoteproto.WriteFrame(tlsConn, remoteproto.FrameCommit, remoteproto.CommitPayload{
		CommitHex: hex.EncodeToString(commit[:]),
	}, remoteproto.PreAuthMaxFrameBytes); err != nil {
		_ = tlsConn.Close()
		return nil, err
	}
	typ, nonceRBytes, _, err := remoteproto.ReadFrame(tlsConn, remoteproto.PreAuthMaxFrameBytes)
	if err != nil || typ != remoteproto.FrameNonce {
		_ = tlsConn.Close()
		return nil, io.ErrUnexpectedEOF
	}
	var nonceRMsg remoteproto.NoncePayload
	if err := remoteproto.DecodeStrict(nonceRBytes, &nonceRMsg); err != nil {
		_ = tlsConn.Close()
		return nil, err
	}
	nR, err := remoteproto.DecodeHex32(nonceRMsg.NonceHex)
	if err != nil {
		_ = tlsConn.Close()
		return nil, err
	}
	if _, err := remoteproto.WriteFrame(tlsConn, remoteproto.FrameReveal, remoteproto.NoncePayload{
		NonceHex: hex.EncodeToString(nH[:]),
	}, remoteproto.PreAuthMaxFrameBytes); err != nil {
		_ = tlsConn.Close()
		return nil, err
	}
	sas, sid := remoteproto.DeriveSASAndSession(tr, nH, nR)
	if !accept {
		_, _ = remoteproto.WriteFrame(tlsConn, remoteproto.FramePairReject, remoteproto.PairDecisionPayload{Reason: "mismatch"}, remoteproto.PreAuthMaxFrameBytes)
		_ = tlsConn.Close()
		return nil, nil
	}
	if _, err := remoteproto.WriteFrame(tlsConn, remoteproto.FramePairAck, remoteproto.PairDecisionPayload{}, remoteproto.PreAuthMaxFrameBytes); err != nil {
		_ = tlsConn.Close()
		return nil, err
	}
	typ, _, _, err = remoteproto.ReadFrame(tlsConn, remoteproto.PreAuthMaxFrameBytes)
	if err != nil || typ != remoteproto.FramePairAck {
		_ = tlsConn.Close()
		return nil, io.ErrUnexpectedEOF
	}
	_ = tlsConn.SetDeadline(time.Time{})
	return &testClientSession{
		id:        cliID,
		conn:      tlsConn,
		serverFP:  srvFP,
		sessionID: sid,
		sas:       sas,
		helloR:    helloR,
	}, nil
}

func TestDaemonPairingResumeConcurrencyAndGrace(t *testing.T) {
	wd := t.TempDir()
	var outBuf, errBuf bytes.Buffer
	d, err := New(Config{
		ListenAddr:     "127.0.0.1:0",
		AllowCWD:       []string{wd},
		ReconnectGrace: 200 * time.Millisecond,
		IdleTimeout:    30 * time.Second,
		Stdout:         &outBuf,
		Stderr:         &errBuf,
		PromptConfirm: func(_ context.Context, _, _ string) (bool, error) {
			return true, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	addr, err := d.Listen()
	if err != nil {
		t.Fatal(err)
	}
	serveDone := make(chan error, 1)
	serveCtx, cancelServe := context.WithCancel(context.Background())
	defer cancelServe()
	go func() { serveDone <- d.Serve(serveCtx) }()
	defer d.Close()

	cliID, err := remoteproto.GenerateEphemeralIdentity("test-broker")
	if err != nil {
		t.Fatal(err)
	}
	sess1, err := pairTestClient(t, addr.String(), cliID, true)
	if err != nil {
		t.Fatalf("initial pairing failed: %v", err)
	}

	// Single-command concurrency rejection: start slow sleep, send second EXEC_REQ concurrently -> denied.
	if _, err := remoteproto.WriteFrame(sess1.conn, remoteproto.FrameExecReq, remoteproto.ExecRequest{
		ReqID:          "slow-1",
		Executable:     "sleep",
		Args:           []string{"2"},
		CWD:            wd,
		ExecTimeoutSec: 5,
	}, remoteproto.PostAuthMaxFrameBytes); err != nil {
		t.Fatal(err)
	}
	// Give slow-1 a moment to claim activeCancel.
	time.Sleep(80 * time.Millisecond)
	if _, err := remoteproto.WriteFrame(sess1.conn, remoteproto.FrameExecReq, remoteproto.ExecRequest{
		ReqID:      "concurrent-2",
		Executable: "echo",
		Args:       []string{"hi"},
		CWD:        wd,
	}, remoteproto.PostAuthMaxFrameBytes); err != nil {
		t.Fatal(err)
	}

	// Read response for concurrent-2 (must be StatusDenied).
	_ = sess1.conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	typ, payload, _, err := remoteproto.ReadFrame(sess1.conn, remoteproto.PostAuthMaxFrameBytes)
	if err != nil || typ != remoteproto.FrameExecResp {
		t.Fatalf("expected exec_resp for concurrent-2, got typ=%q err=%v", typ, err)
	}
	var resp2 remoteproto.ExecResponse
	if err := remoteproto.DecodeStrict(payload, &resp2); err != nil || resp2.ReqID != "concurrent-2" || resp2.Status != remoteproto.StatusDenied {
		t.Fatalf("expected concurrent-2 StatusDenied, got %+v err=%v", resp2, err)
	}

	// RESUME with wrong session_id and stale seq=1 must fail.
	dialResume := func(sidHex string, seq uint64) (*tls.Conn, error) {
		raw, err := net.DialTimeout("tcp", addr.String(), 2*time.Second)
		if err != nil {
			return nil, err
		}
		tc := tls.Client(raw, remoteproto.ClientTLSConfig(cliID, &sess1.serverFP))
		_ = tc.SetDeadline(time.Now().Add(2 * time.Second))
		if err := tc.Handshake(); err != nil {
			_ = tc.Close()
			return nil, err
		}
		if _, err := remoteproto.WriteFrame(tc, remoteproto.FrameResume, remoteproto.ResumePayload{
			SessionIDHex: sidHex,
			ConnSeq:      seq,
		}, remoteproto.PreAuthMaxFrameBytes); err != nil {
			_ = tc.Close()
			return nil, err
		}
		rTyp, rPay, _, err := remoteproto.ReadFrame(tc, remoteproto.PreAuthMaxFrameBytes)
		if err != nil || rTyp != remoteproto.FrameResumeOK {
			_ = tc.Close()
			return nil, io.ErrUnexpectedEOF
		}
		var okMsg remoteproto.ResumeOKPayload
		if err := remoteproto.DecodeStrict(rPay, &okMsg); err != nil || okMsg.ConnSeq != seq {
			_ = tc.Close()
			return nil, io.ErrUnexpectedEOF
		}
		_ = tc.SetDeadline(time.Time{})
		return tc, nil
	}

	// Note: reset IP rate limiter between deliberate failure probes in this unit test.
	if cBad, err := dialResume(strings.Repeat("0", 64), 2); err == nil {
		_ = cBad.Close()
		t.Fatal("expected RESUME with wrong session_id to fail")
	}
	d.rateMu.Lock()
	clear(d.rateState)
	d.rateMu.Unlock()

	if cStale, err := dialResume(hex.EncodeToString(sess1.sessionID[:]), 1); err == nil {
		_ = cStale.Close()
		t.Fatal("expected RESUME with stale seq=1 to fail")
	}
	d.rateMu.Lock()
	clear(d.rateState)
	d.rateMu.Unlock()

	// Valid RESUME(sid, seq=2) atomically supersedes sess1 without killing seq=2 when sess1 closes.
	conn2, err := dialResume(hex.EncodeToString(sess1.sessionID[:]), 2)
	if err != nil {
		t.Fatalf("valid RESUME(seq=2) failed: %v", err)
	}
	_ = sess1.conn.Close()

	// Wait longer than ReconnectGrace to prove closing stale seq=1 did NOT trigger grace expiry on seq=2.
	time.Sleep(300 * time.Millisecond)

	if _, err := remoteproto.WriteFrame(conn2, remoteproto.FrameExecReq, remoteproto.ExecRequest{
		ReqID:      "after-resume",
		Executable: "echo",
		Args:       []string{"resumed-ok"},
		CWD:        wd,
	}, remoteproto.PostAuthMaxFrameBytes); err != nil {
		t.Fatalf("write EXEC_REQ on seq=2 failed: %v", err)
	}
	_ = conn2.SetReadDeadline(time.Now().Add(2 * time.Second))
	typ, payload, _, err = remoteproto.ReadFrame(conn2, remoteproto.PostAuthMaxFrameBytes)
	if err != nil || typ != remoteproto.FrameExecResp {
		t.Fatalf("expected EXEC_RESP on seq=2, got typ=%q err=%v", typ, err)
	}
	var respAfter remoteproto.ExecResponse
	if err := remoteproto.DecodeStrict(payload, &respAfter); err != nil || respAfter.Status != remoteproto.StatusCompleted {
		t.Fatalf("unexpected resp after resume: %+v err=%v", respAfter, err)
	}

	// Dropping conn2 without BYE starts ReconnectGrace and cleanly exits Serve after 200 ms.
	_ = conn2.Close()
	select {
	case err := <-serveDone:
		if err != nil {
			t.Fatalf("Serve returned error after grace expiry: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("expected daemon Serve to exit after ReconnectGrace expiry")
	}
}

func TestDaemonPairRejectAbortsPromptAndPromptBusySerializer(t *testing.T) {
	wd := t.TempDir()
	promptStarted := make(chan struct{}, 2)
	promptAborted := make(chan error, 2)
	var outBuf, errBuf bytes.Buffer

	d, err := New(Config{
		ListenAddr:  "127.0.0.1:0",
		AllowCWD:    []string{wd},
		IdleTimeout: 30 * time.Second,
		Stdout:      &outBuf,
		Stderr:      &errBuf,
		PromptConfirm: func(ctx context.Context, _, _ string) (bool, error) {
			promptStarted <- struct{}{}
			<-ctx.Done()
			promptAborted <- ctx.Err()
			return false, ctx.Err()
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	addr, err := d.Listen()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = d.Serve(ctx) }()
	defer d.Close()

	// Start client 1 through commit-reveal so daemon enters PromptConfirm and sets promptBusy=true.
	id1, _ := remoteproto.GenerateEphemeralIdentity("c1")
	id2, _ := remoteproto.GenerateEphemeralIdentity("c2")

	startHandshakeOnly := func(cliID remoteproto.EphemeralIdentity) *tls.Conn {
		raw, err := net.DialTimeout("tcp", addr.String(), 2*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		tc := tls.Client(raw, remoteproto.ClientTLSConfig(cliID, nil))
		_ = tc.SetDeadline(time.Now().Add(5 * time.Second))
		if err := tc.Handshake(); err != nil {
			t.Fatal(err)
		}
		srvDER := tc.ConnectionState().PeerCertificates[0].Raw
		ekm, err := remoteproto.ExportPairingEKM(tc)
		if err != nil {
			t.Fatal(err)
		}
		_, _, rawHelloR, err := remoteproto.ReadFrame(tc, remoteproto.PreAuthMaxFrameBytes)
		if err != nil {
			t.Fatal(err)
		}
		rawHelloH, err := remoteproto.WriteFrame(tc, remoteproto.FrameHello, remoteproto.HelloPayload{
			ProtoVer: remoteproto.ProtocolVersion,
			Role:     "host",
		}, remoteproto.PreAuthMaxFrameBytes)
		if err != nil {
			t.Fatal(err)
		}
		tr := remoteproto.ComputeTranscript(ekm, cliID.DER, srvDER, rawHelloR, rawHelloH)
		nH, _ := remoteproto.RandomBytes32()
		commit := remoteproto.ComputeCommit(nH, tr)
		_, _ = remoteproto.WriteFrame(tc, remoteproto.FrameCommit, remoteproto.CommitPayload{CommitHex: hex.EncodeToString(commit[:])}, remoteproto.PreAuthMaxFrameBytes)
		_, _, _, _ = remoteproto.ReadFrame(tc, remoteproto.PreAuthMaxFrameBytes)
		_, _ = remoteproto.WriteFrame(tc, remoteproto.FrameReveal, remoteproto.NoncePayload{NonceHex: hex.EncodeToString(nH[:])}, remoteproto.PreAuthMaxFrameBytes)
		return tc
	}

	c1 := startHandshakeOnly(id1)
	defer c1.Close()

	select {
	case <-promptStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for client 1 to reach PromptConfirm")
	}

	// Second concurrent entrant receives FramePairReject ("pairing busy") immediately.
	c2 := startHandshakeOnly(id2)
	defer c2.Close()
	typ, payload, _, err := remoteproto.ReadFrame(c2, remoteproto.PreAuthMaxFrameBytes)
	if err != nil || typ != remoteproto.FramePairReject {
		t.Fatalf("expected FramePairReject for busy prompt entrant, got typ=%q err=%v", typ, err)
	}
	var rej remoteproto.PairDecisionPayload
	if err := remoteproto.DecodeStrict(payload, &rej); err != nil || !strings.Contains(rej.Reason, "busy") {
		t.Fatalf("expected busy rejection payload, got %+v err=%v", rej, err)
	}

	// Client 1 sends PAIR_REJECT and aborts daemon's PromptConfirm immediately.
	startRej := time.Now()
	if _, err := remoteproto.WriteFrame(c1, remoteproto.FramePairReject, remoteproto.PairDecisionPayload{Reason: "nope"}, remoteproto.PreAuthMaxFrameBytes); err != nil {
		t.Fatal(err)
	}
	select {
	case pErr := <-promptAborted:
		if pErr == nil {
			t.Fatal("expected prompt context cancellation on peer PAIR_REJECT")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("PAIR_REJECT did not abort local pairing prompt immediately")
	}
	if time.Since(startRej) > time.Second {
		t.Fatalf("PAIR_REJECT abort took too long: %v", time.Since(startRej))
	}

	// Verify confirmPairing prompt text includes user@host (uid=N), default_cwd, and root warning when uid == 0.
	var pOut bytes.Buffer
	dPrompt := &Daemon{
		cfg:     Config{Stdin: strings.NewReader("n\n"), Stdout: &pOut, Stderr: io.Discard},
		execCfg: ExecConfig{DefaultCWD: "/srv/app"},
		userStr: "root",
		hostStr: "prod-box",
		uid:     0,
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, _ = dPrompt.confirmPairing(context.Background(), "127.0.0.1:50000", "ABCD-EFGH-JKMN")
	}()
	wg.Wait()
	promptText := pOut.String()
	for _, want := range []string{"root@prod-box (uid=0)", "[WARNING: REMOTE DAEMON IS RUNNING AS ROOT]", "/srv/app", "ABCD-EFGH-JKMN"} {
		if !strings.Contains(promptText, want) {
			t.Errorf("confirmPairing prompt missing %q: %s", want, promptText)
		}
	}
}
