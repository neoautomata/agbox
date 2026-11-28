package remoteclient

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"agbox/internal/remoteproto"
)

func TestParseArgsAndStdinGuards(t *testing.T) {
	// Stops parsing at first positional arg so flags after executable pass through.
	p, err := parseArgs([]string{"--cwd", "/srv/app", "--timeout", "45s", "ls", "-la", "--color=never"})
	if err != nil {
		t.Fatalf("parseArgs failed: %v", err)
	}
	if p.CWD != "/srv/app" || p.ExecTimeoutSec != 45 || p.Executable != "ls" || len(p.Args) != 2 {
		t.Fatalf("unexpected parsed args: %+v", p)
	}

	// Conflicting --stdin and --stdin-file rejected.
	if _, err := parseArgs([]string{"--stdin", "--stdin-file", "/tmp/x", "cat"}); err == nil {
		t.Fatal("expected conflict error for --stdin + --stdin-file")
	}

	// --stdin on TTY rejected with exit 2.
	var stdout, stderr bytes.Buffer
	rc := Run(context.Background(), []string{"--stdin", "cat"}, RunOptions{
		BridgeDir: t.TempDir(),
		Stdin:     strings.NewReader("data"),
		Stdout:    &stdout,
		Stderr:    &stderr,
		IsTTY:     func() bool { return true },
	})
	if rc != remoteproto.LocalErrorExitCode {
		t.Fatalf("expected exit %d for --stdin on TTY, got %d (stderr=%s)", remoteproto.LocalErrorExitCode, rc, stderr.String())
	}

	// Stdin overflow fails closed with exit 2 (never truncates).
	stderr.Reset()
	rc = Run(context.Background(), []string{"--stdin", "cat"}, RunOptions{
		BridgeDir: t.TempDir(),
		Stdin:     bytes.NewReader(make([]byte, remoteproto.MaxStdinBytes+1)),
		Stdout:    &stdout,
		Stderr:    &stderr,
		IsTTY:     func() bool { return false },
	})
	if rc != remoteproto.LocalErrorExitCode || !strings.Contains(stderr.String(), "exceeds") {
		t.Fatalf("expected exit 2 overflow error, got rc=%d stderr=%q", rc, stderr.String())
	}

	// --help exits 0 and prints usage text including signal exit codes.
	stdout.Reset()
	stderr.Reset()
	rc = Run(context.Background(), []string{"--help"}, RunOptions{
		Stdin:  blockingReader{},
		Stdout: &stdout,
		Stderr: &stderr,
	})
	if rc != 0 || !strings.Contains(stdout.String(), "Usage: agbox-remote") || !strings.Contains(stdout.String(), "130") || !strings.Contains(stdout.String(), "143") {
		t.Fatalf("expected help exit 0 with signal codes, got rc=%d out=%q", rc, stdout.String())
	}

	// NUL bytes in executable, args, and cwd fail locally with exit 2.
	for _, badArgs := range [][]string{
		{"ls\x00x"},
		{"ls", "a\x00b"},
		{"--cwd", "/srv\x00x", "ls"},
	} {
		stderr.Reset()
		rc = Run(context.Background(), badArgs, RunOptions{
			BridgeDir: t.TempDir(),
			Stdin:     blockingReader{},
			Stdout:    &stdout,
			Stderr:    &stderr,
		})
		if rc != remoteproto.LocalErrorExitCode {
			t.Errorf("expected exit 2 for NUL byte args %q, got %d", badArgs, rc)
		}
	}

	// '--' passes an executable starting with '-'.
	pDash, err := parseArgs([]string{"--", "-dash-exe", "--flag"})
	if err != nil || pDash.Executable != "-dash-exe" || len(pDash.Args) != 1 || pDash.Args[0] != "--flag" {
		t.Fatalf("expected '--' to accept -dash-exe, got p=%+v err=%v", pDash, err)
	}

	// --stdin-file rejects missing path, directory, and >256 KiB files with exit 2.
	tmp := t.TempDir()
	bigFile := filepath.Join(tmp, "big.bin")
	if err := os.WriteFile(bigFile, make([]byte, remoteproto.MaxStdinBytes+1), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{filepath.Join(tmp, "missing"), tmp, bigFile} {
		stderr.Reset()
		rc = Run(context.Background(), []string{"--stdin-file", path, "cat"}, RunOptions{
			BridgeDir: tmp,
			Stdin:     blockingReader{},
			Stdout:    &stdout,
			Stderr:    &stderr,
		})
		if rc != remoteproto.LocalErrorExitCode {
			t.Errorf("expected exit 2 for --stdin-file %q, got rc=%d stderr=%q", path, rc, stderr.String())
		}
	}

	// Serialized request > 512 KiB rejected locally with exit 2.
	stderr.Reset()
	hugeArg := strings.Repeat("a", remoteproto.MaxBridgeReqBytes)
	rc = Run(context.Background(), []string{"echo", hugeArg}, RunOptions{
		BridgeDir: tmp,
		Stdin:     blockingReader{},
		Stdout:    &stdout,
		Stderr:    &stderr,
	})
	if rc != remoteproto.LocalErrorExitCode || !strings.Contains(stderr.String(), "serialized request exceeds") {
		t.Fatalf("expected exit 2 for >512 KiB request, got rc=%d stderr=%q", rc, stderr.String())
	}

	// Unwritable or missing bridge directory returns uniform exit 126.
	stderr.Reset()
	rc = Run(context.Background(), []string{"uname"}, RunOptions{
		BridgeDir: filepath.Join(tmp, "no-such-bridge"),
		Stdin:     blockingReader{},
		Stdout:    &stdout,
		Stderr:    &stderr,
	})
	if rc != remoteproto.DenyExitCode || !strings.Contains(stderr.String(), remoteproto.DenyErrorMessage) {
		t.Fatalf("expected uniform deny exit 126 for missing bridge dir, got rc=%d stderr=%q", rc, stderr.String())
	}
}

type blockingReader struct{}

func (blockingReader) Read([]byte) (int, error) {
	panic("stdin must not be read when --stdin is omitted")
}

func TestRunAgainstFakeBridgeDir(t *testing.T) {
	bridgeDir := t.TempDir()
	for _, sub := range []string{"req", "done", "resp"} {
		if err := os.Mkdir(filepath.Join(bridgeDir, sub), 0o700); err != nil {
			t.Fatal(err)
		}
	}

	// Responder goroutine watches req/ and populates resp/ + done/.
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		for {
			select {
			case <-stop:
				return
			default:
			}
			entries, _ := os.ReadDir(filepath.Join(bridgeDir, "req"))
			for _, e := range entries {
				id := e.Name()
				donePath := filepath.Join(bridgeDir, "done", id)
				if _, err := os.Stat(donePath); err == nil {
					continue
				}
				rawReq, err := os.ReadFile(filepath.Join(bridgeDir, "req", id))
				if err != nil || len(rawReq) == 0 {
					continue
				}
				var greq remoteproto.GuestRequest
				if err := json.Unmarshal(rawReq, &greq); err != nil {
					continue
				}
				var resp remoteproto.ExecResponse
				switch greq.Executable {
				case "okcmd":
					resp = remoteproto.ExecResponse{
						ReqID:         id,
						Status:        remoteproto.StatusCompleted,
						ExitCode:      0,
						StdoutB64:     base64.StdEncoding.EncodeToString([]byte("out-ok\n")),
						RedactedCount: 1,
					}
				case "echostdin":
					resp = remoteproto.ExecResponse{
						ReqID:     id,
						Status:    remoteproto.StatusCompleted,
						ExitCode:  0,
						StdoutB64: greq.StdinB64,
					}
				case "trailercmd":
					resp = remoteproto.ExecResponse{
						ReqID:           id,
						Status:          remoteproto.StatusCompleted,
						ExitCode:        42,
						StderrB64:       base64.StdEncoding.EncodeToString([]byte("err-body\n")),
						StdoutTruncated: true,
						StderrTruncated: true,
						DroppedOutput:   true,
					}
				case "timeoutcmd":
					resp = remoteproto.ExecResponse{
						ReqID:      id,
						Status:     remoteproto.StatusTimeout,
						ExitCode:   remoteproto.TimeoutExitCode,
						TimeoutSec: 5,
					}
				default:
					resp = remoteproto.DeniedResponse(id, "use staging")
				}
				rawResp, _ := json.Marshal(resp)
				_ = os.WriteFile(filepath.Join(bridgeDir, "resp", id), rawResp, 0o400)
				_ = os.WriteFile(donePath, nil, 0o400)
			}
			time.Sleep(10 * time.Millisecond)
		}
	}()

	var stdout, stderr bytes.Buffer
	rc := Run(context.Background(), []string{"okcmd", "--flag"}, RunOptions{
		BridgeDir: bridgeDir,
		Stdin:     blockingReader{},
		Stdout:    &stdout,
		Stderr:    &stderr,
	})
	if rc != 0 || stdout.String() != "out-ok\n" || !strings.Contains(stderr.String(), "1 secret pattern(s) redacted") {
		t.Fatalf("unexpected okcmd result: rc=%d stdout=%q stderr=%q", rc, stdout.String(), stderr.String())
	}

	stdout.Reset()
	stderr.Reset()
	rc = Run(context.Background(), []string{"timeoutcmd"}, RunOptions{
		BridgeDir: bridgeDir,
		Stdin:     blockingReader{},
		Stdout:    &stdout,
		Stderr:    &stderr,
	})
	if rc != remoteproto.TimeoutExitCode || !strings.Contains(stderr.String(), "timed out after 5s") {
		t.Fatalf("unexpected timeoutcmd result: rc=%d stderr=%q", rc, stderr.String())
	}

	stdout.Reset()
	stderr.Reset()
	rc = Run(context.Background(), []string{"badcmd"}, RunOptions{
		BridgeDir: bridgeDir,
		Stdin:     blockingReader{},
		Stdout:    &stdout,
		Stderr:    &stderr,
	})
	if rc != remoteproto.DenyExitCode || !strings.Contains(stderr.String(), "operator note: use staging") {
		t.Fatalf("unexpected denied result: rc=%d stderr=%q", rc, stderr.String())
	}

	// Verify req/<id> is unlinked after Run completes.
	leftover, err := os.ReadDir(filepath.Join(bridgeDir, "req"))
	if err != nil || len(leftover) != 0 {
		t.Fatalf("expected 0 leftover req entries after Run, got %d err=%v", len(leftover), err)
	}

	// Valid piped --stdin and valid --stdin-file deliver exact payload.
	stdout.Reset()
	stderr.Reset()
	rc = Run(context.Background(), []string{"--stdin", "echostdin"}, RunOptions{
		BridgeDir: bridgeDir,
		Stdin:     strings.NewReader("piped-payload"),
		Stdout:    &stdout,
		Stderr:    &stderr,
		IsTTY:     func() bool { return false },
	})
	if rc != 0 || stdout.String() != "piped-payload" {
		t.Fatalf("expected piped stdin round-trip, got rc=%d stdout=%q stderr=%q", rc, stdout.String(), stderr.String())
	}

	inFile := filepath.Join(t.TempDir(), "input.txt")
	if err := os.WriteFile(inFile, []byte("file-payload"), 0o600); err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	stderr.Reset()
	rc = Run(context.Background(), []string{"--stdin-file", inFile, "echostdin"}, RunOptions{
		BridgeDir: bridgeDir,
		Stdin:     blockingReader{},
		Stdout:    &stdout,
		Stderr:    &stderr,
	})
	if rc != 0 || stdout.String() != "file-payload" {
		t.Fatalf("expected --stdin-file round-trip, got rc=%d stdout=%q stderr=%q", rc, stdout.String(), stderr.String())
	}

	// Non-zero exit code, stderr forwarding, active-voice truncation notes, and dropped output trailer.
	stdout.Reset()
	stderr.Reset()
	rc = Run(context.Background(), []string{"trailercmd"}, RunOptions{
		BridgeDir: bridgeDir,
		Stdin:     blockingReader{},
		Stdout:    &stdout,
		Stderr:    &stderr,
	})
	errText := stderr.String()
	if rc != 42 || !strings.Contains(errText, "err-body\n") ||
		!strings.Contains(errText, "the remote daemon truncated stdout") ||
		!strings.Contains(errText, "the remote daemon truncated stderr") ||
		!strings.Contains(errText, "output dropped by operator") {
		t.Fatalf("unexpected trailercmd result: rc=%d stderr=%q", rc, errText)
	}
}

func TestSignalExitCodesAndInterruptDuringWaitAndStdin(t *testing.T) {
	bridgeDir := t.TempDir()
	for _, sub := range []string{"req", "done", "resp"} {
		if err := os.Mkdir(filepath.Join(bridgeDir, sub), 0o700); err != nil {
			t.Fatal(err)
		}
	}

	// Test SIGINT (130) and SIGTERM (143) while waiting on done/ unlink req/<id>.
	for _, tc := range []struct {
		name     string
		sig      syscall.Signal
		wantCode int
	}{
		{"sigint", syscall.SIGINT, 130},
		{"sigterm", syscall.SIGTERM, 143},
	} {
		t.Run(tc.name+"_wait", func(t *testing.T) {
			ctx, cancelSig := WithSignalCancel(context.Background(), tc.sig)
			go func() {
				deadline := time.Now().Add(2 * time.Second)
				for time.Now().Before(deadline) {
					entries, _ := os.ReadDir(filepath.Join(bridgeDir, "req"))
					if len(entries) > 0 {
						cancelSig()
						return
					}
					time.Sleep(5 * time.Millisecond)
				}
				cancelSig()
			}()
			var stdout, stderr bytes.Buffer
			rc := Run(ctx, []string{"slowcmd"}, RunOptions{
				BridgeDir: bridgeDir,
				Stdin:     blockingReader{},
				Stdout:    &stdout,
				Stderr:    &stderr,
			})
			if rc != tc.wantCode {
				t.Fatalf("expected exit %d on %s, got %d", tc.wantCode, tc.name, rc)
			}
			entries, _ := os.ReadDir(filepath.Join(bridgeDir, "req"))
			if len(entries) != 0 {
				t.Fatalf("expected req/<id> unlinked on %s cancel, got %d remaining", tc.name, len(entries))
			}
		})
	}

	// Signal interrupts blocked --stdin read on an open os.Pipe immediately.
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer pr.Close()
	defer pw.Close()

	ctx, cancelSig := WithSignalCancel(context.Background(), syscall.SIGINT)
	go func() {
		time.Sleep(60 * time.Millisecond)
		cancelSig()
	}()
	var stdout, stderr bytes.Buffer
	start := time.Now()
	rc := Run(ctx, []string{"--stdin", "cat"}, RunOptions{
		BridgeDir: bridgeDir,
		Stdin:     pr,
		Stdout:    &stdout,
		Stderr:    &stderr,
		IsTTY:     func() bool { return false },
	})
	if rc != 130 {
		t.Fatalf("expected exit 130 when SIGINT interrupts open --stdin pipe, got %d", rc)
	}
	if time.Since(start) > 2*time.Second {
		t.Fatalf("stdin interrupt took too long: %v", time.Since(start))
	}
}
