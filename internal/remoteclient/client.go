// Package remoteclient implements the in-VM agbox-remote CLI client.
//
// Security properties:
//   - Stdin is strictly opt-in (--stdin or --stdin-file) so open agent tool pipes never hang.
//   - Stdin is hard-capped at 256 KiB and fails closed with exit code 2 instead of truncating.
//   - Readiness polls done/ via readdir and opens resp/<id> only once immutable and terminal.
//   - resp/<id> is closed before unlinking req/<id> so bridge handles and memory release cleanly.
//   - SIGINT and SIGTERM unlink req/<id> to cancel in-flight host and remote work at once.
package remoteclient

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"agbox/internal/remotebridge"
	"agbox/internal/remoteproto"

	"golang.org/x/sys/unix"
)

// RunOptions allows injecting I/O streams and bridge path for testing.
type RunOptions struct {
	BridgeDir string
	Stdin     io.Reader
	Stdout    io.Writer
	Stderr    io.Writer
	IsTTY     func() bool
}

type parsedArgs struct {
	CWD            string
	ExecTimeoutSec int
	Reason         string
	UseStdin       bool
	StdinFile      string
	Executable     string
	Args           []string
	ShowHelp       bool
}

func usageText() string {
	return `Usage: agbox-remote [options] [--] <EXECUTABLE> [ARG...]

Request a structured command on a pre-connected remote machine.

Options (must come before <EXECUTABLE>):
  --cwd <DIR>             Remote working directory (absolute path)
  --exec-timeout <DUR>    Remote execution timeout (seconds or Go duration, alias: --timeout)
  --reason "<TEXT>"       Short note shown to the host operator during review
  --stdin                 Read stdin from a pipe, heredoc, or file redirect (max 256 KiB)
  --stdin-file <PATH>     Read stdin from a regular file inside the sandbox (max 256 KiB)
  -h, --help              Show this help text and exit

Exit codes:
  0..255  Remote command exit code on completed runs
  124     Approved command timed out on the remote machine
  126     Command denied (or no host broker attached)
  130     Interrupted by SIGINT
  143     Terminated by SIGTERM
  2       Local agbox-remote usage or input error
`
}

func parseArgs(args []string) (parsedArgs, error) {
	var opts parsedArgs
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			rest := args[i+1:]
			if len(rest) == 0 {
				return parsedArgs{}, errors.New("missing <EXECUTABLE> after '--'")
			}
			opts.Executable = rest[0]
			opts.Args = rest[1:]
			return validateParsed(opts)
		}
		if !strings.HasPrefix(a, "-") || a == "-" {
			opts.Executable = a
			opts.Args = args[i+1:]
			return validateParsed(opts)
		}
		if a == "-h" || a == "--help" {
			return parsedArgs{ShowHelp: true}, nil
		}
		if val, ok, err := takeFlag(args, &i, "--cwd"); ok {
			if err != nil {
				return parsedArgs{}, err
			}
			opts.CWD = val
			continue
		}
		if val, ok, err := takeFlag(args, &i, "--exec-timeout", "--timeout"); ok {
			if err != nil {
				return parsedArgs{}, err
			}
			d, pErr := remoteproto.ParseDurationOrSeconds(val)
			if pErr != nil {
				return parsedArgs{}, pErr
			}
			secs := int(d / time.Second)
			if secs < 1 {
				secs = 1
			}
			opts.ExecTimeoutSec = secs
			continue
		}
		if val, ok, err := takeFlag(args, &i, "--reason"); ok {
			if err != nil {
				return parsedArgs{}, err
			}
			opts.Reason = val
			continue
		}
		if val, ok, err := takeFlag(args, &i, "--stdin-file"); ok {
			if err != nil {
				return parsedArgs{}, err
			}
			opts.StdinFile = val
			continue
		}
		if a == "--stdin" {
			opts.UseStdin = true
			continue
		}
		return parsedArgs{}, fmt.Errorf("unknown option %q (pass '--' before an executable starting with '-')", a)
	}
	return parsedArgs{}, errors.New("missing <EXECUTABLE> (run 'agbox-remote --help')")
}

func takeFlag(args []string, idx *int, names ...string) (string, bool, error) {
	cur := args[*idx]
	for _, name := range names {
		if strings.HasPrefix(cur, name+"=") {
			return strings.TrimPrefix(cur, name+"="), true, nil
		}
		if cur == name {
			if *idx+1 >= len(args) {
				return "", true, fmt.Errorf("%s requires a value", name)
			}
			*idx++
			return args[*idx], true, nil
		}
	}
	return "", false, nil
}

func validateParsed(opts parsedArgs) (parsedArgs, error) {
	if opts.UseStdin && opts.StdinFile != "" {
		return parsedArgs{}, errors.New("cannot combine --stdin and --stdin-file")
	}
	if opts.Executable == "" {
		return parsedArgs{}, errors.New("executable must not be empty")
	}
	if strings.ContainsRune(opts.Executable, 0) {
		return parsedArgs{}, errors.New("executable contains NUL byte")
	}
	for _, a := range opts.Args {
		if strings.ContainsRune(a, 0) {
			return parsedArgs{}, errors.New("argument contains NUL byte")
		}
	}
	if strings.ContainsRune(opts.CWD, 0) {
		return parsedArgs{}, errors.New("cwd contains NUL byte")
	}
	return opts, nil
}

func isStdinTerminal(r io.Reader) bool {
	f, ok := r.(*os.File)
	if !ok || f == nil {
		return false
	}
	_, err := unix.IoctlGetTermios(int(f.Fd()), unix.TCGETS)
	return err == nil
}

type signalError struct {
	sig syscall.Signal
}

func (e signalError) Error() string {
	return fmt.Sprintf("interrupted by signal %d", int(e.sig))
}

func (e signalError) Unwrap() error {
	return context.Canceled
}

// WithSignalCancel returns a context whose cancellation carries exit code 128+sig.
func WithSignalCancel(parent context.Context, sig syscall.Signal) (context.Context, func()) {
	ctx, cancel := context.WithCancelCause(parent)
	return ctx, func() { cancel(signalError{sig: sig}) }
}

func cancelExitCode(ctx context.Context) int {
	var se signalError
	if errors.As(context.Cause(ctx), &se) {
		switch se.sig {
		case syscall.SIGTERM:
			return 143
		case syscall.SIGINT:
			return 130
		default:
			return 128 + int(se.sig)
		}
	}
	return 130
}

func readBoundedWithContext(ctx context.Context, r io.Reader, limit int64) ([]byte, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if f, ok := r.(*os.File); ok {
		return readFileBoundedWithContext(ctx, int(f.Fd()), limit)
	}
	type readResult struct {
		data []byte
		err  error
	}
	ch := make(chan readResult, 1)
	go func() {
		raw, err := io.ReadAll(io.LimitReader(r, limit))
		ch <- readResult{data: raw, err: err}
	}()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case res := <-ch:
		return res.data, res.err
	}
}

func readFileBoundedWithContext(ctx context.Context, fd int, limit int64) ([]byte, error) {
	var out []byte
	chunk := make([]byte, 8192)
	for int64(len(out)) < limit {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		pfds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
		n, err := unix.Poll(pfds, 50)
		if err != nil {
			if errors.Is(err, unix.EINTR) {
				continue
			}
			return nil, err
		}
		if n == 0 {
			continue
		}
		if pfds[0].Revents&(unix.POLLNVAL) != 0 {
			return out, nil
		}
		rem := limit - int64(len(out))
		buf := chunk
		if int64(len(buf)) > rem {
			buf = buf[:rem]
		}
		rn, rErr := unix.Read(fd, buf)
		if rn > 0 {
			out = append(out, buf[:rn]...)
		}
		if rErr != nil {
			if errors.Is(rErr, unix.EINTR) {
				continue
			}
			return nil, rErr
		}
		if rn == 0 {
			return out, nil
		}
	}
	return out, nil
}

func readBoundedStdin(ctx context.Context, opts parsedArgs, ro RunOptions) ([]byte, error) {
	if !opts.UseStdin && opts.StdinFile == "" {
		return nil, nil
	}
	if opts.StdinFile != "" {
		f, err := os.Open(opts.StdinFile)
		if err != nil {
			return nil, fmt.Errorf("open --stdin-file %s: %w", opts.StdinFile, err)
		}
		defer f.Close()
		info, err := f.Stat()
		if err != nil {
			return nil, fmt.Errorf("stat --stdin-file %s: %w", opts.StdinFile, err)
		}
		if info.IsDir() {
			return nil, fmt.Errorf("--stdin-file %s is a directory", opts.StdinFile)
		}
		raw, err := readBoundedWithContext(ctx, f, remoteproto.MaxStdinBytes+1)
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			return nil, fmt.Errorf("read --stdin-file %s: %w", opts.StdinFile, err)
		}
		if len(raw) > remoteproto.MaxStdinBytes {
			return nil, fmt.Errorf("stdin exceeds %d bytes", remoteproto.MaxStdinBytes)
		}
		return raw, nil
	}

	isTTY := ro.IsTTY
	if isTTY == nil {
		isTTY = func() bool { return isStdinTerminal(ro.Stdin) }
	}
	if isTTY() {
		return nil, errors.New("--stdin requires piped or redirected input (not an interactive TTY)")
	}
	if ro.Stdin == nil {
		return nil, nil
	}
	raw, err := readBoundedWithContext(ctx, ro.Stdin, remoteproto.MaxStdinBytes+1)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("read stdin: %w", err)
	}
	if len(raw) > remoteproto.MaxStdinBytes {
		return nil, fmt.Errorf("stdin exceeds %d bytes", remoteproto.MaxStdinBytes)
	}
	return raw, nil
}

// Run executes the agbox-remote client workflow and returns the process exit code.
func Run(ctx context.Context, args []string, ro RunOptions) int {
	if ro.BridgeDir == "" {
		ro.BridgeDir = remotebridge.GuestMountPath
	}
	if ro.Stdout == nil {
		ro.Stdout = os.Stdout
	}
	if ro.Stderr == nil {
		ro.Stderr = os.Stderr
	}
	if ro.Stdin == nil {
		ro.Stdin = os.Stdin
	}

	parsed, err := parseArgs(args)
	if err != nil {
		fmt.Fprintf(ro.Stderr, "agbox-remote: %v\n", err)
		return remoteproto.LocalErrorExitCode
	}
	if parsed.ShowHelp {
		fmt.Fprint(ro.Stdout, usageText())
		return 0
	}

	stdinData, err := readBoundedStdin(ctx, parsed, ro)
	if err != nil {
		if ctx.Err() != nil {
			return cancelExitCode(ctx)
		}
		fmt.Fprintf(ro.Stderr, "agbox-remote: %v\n", err)
		return remoteproto.LocalErrorExitCode
	}
	if ctx.Err() != nil {
		return cancelExitCode(ctx)
	}

	greq := remoteproto.GuestRequest{
		Version:        remoteproto.ProtocolVersion,
		Executable:     parsed.Executable,
		Args:           parsed.Args,
		CWD:            parsed.CWD,
		ExecTimeoutSec: parsed.ExecTimeoutSec,
		Reason:         parsed.Reason,
	}
	if len(stdinData) > 0 {
		greq.StdinB64 = base64.StdEncoding.EncodeToString(stdinData)
	}
	rawReq, err := json.Marshal(greq)
	if err != nil {
		fmt.Fprintf(ro.Stderr, "agbox-remote: encode request: %v\n", err)
		return remoteproto.LocalErrorExitCode
	}
	if len(rawReq) > remoteproto.MaxBridgeReqBytes {
		fmt.Fprintf(ro.Stderr, "agbox-remote: serialized request exceeds %d bytes\n", remoteproto.MaxBridgeReqBytes)
		return remoteproto.LocalErrorExitCode
	}

	slotID, err := remoteproto.RandomHex16()
	if err != nil {
		fmt.Fprintln(ro.Stderr, remoteproto.DenyErrorMessage)
		return remoteproto.DenyExitCode
	}

	reqPath := filepath.Join(ro.BridgeDir, "req", slotID)
	doneDir := filepath.Join(ro.BridgeDir, "done")
	respPath := filepath.Join(ro.BridgeDir, "resp", slotID)

	f, err := os.OpenFile(reqPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		fmt.Fprintln(ro.Stderr, remoteproto.DenyErrorMessage)
		return remoteproto.DenyExitCode
	}
	if _, wErr := f.Write(rawReq); wErr != nil {
		_ = f.Close()
		_ = os.Remove(reqPath)
		fmt.Fprintln(ro.Stderr, remoteproto.DenyErrorMessage)
		return remoteproto.DenyExitCode
	}
	if cErr := f.Close(); cErr != nil {
		_ = os.Remove(reqPath)
		fmt.Fprintln(ro.Stderr, remoteproto.DenyErrorMessage)
		return remoteproto.DenyExitCode
	}

	if err := waitUntilDone(ctx, doneDir, slotID); err != nil {
		_ = os.Remove(reqPath)
		if errors.Is(err, context.Canceled) || ctx.Err() != nil {
			return cancelExitCode(ctx)
		}
		fmt.Fprintln(ro.Stderr, remoteproto.DenyErrorMessage)
		return remoteproto.DenyExitCode
	}

	respBytes, err := readRespAndClose(respPath)
	_ = os.Remove(reqPath)
	if err != nil {
		fmt.Fprintln(ro.Stderr, remoteproto.DenyErrorMessage)
		return remoteproto.DenyExitCode
	}

	var resp remoteproto.ExecResponse
	if err := json.Unmarshal(respBytes, &resp); err != nil {
		fmt.Fprintln(ro.Stderr, remoteproto.DenyErrorMessage)
		return remoteproto.DenyExitCode
	}

	return emitResponse(resp, ro.Stdout, ro.Stderr)
}

func waitUntilDone(ctx context.Context, doneDir, slotID string) error {
	start := time.Now()
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		entries, err := os.ReadDir(doneDir)
		if err != nil {
			return err
		}
		for _, e := range entries {
			if e.Name() == slotID {
				return nil
			}
		}
		elapsed := time.Since(start)
		var sleep time.Duration
		switch {
		case elapsed < time.Second:
			sleep = 20 * time.Millisecond
		case elapsed < 10*time.Second:
			sleep = 100 * time.Millisecond
		default:
			sleep = 250 * time.Millisecond
		}
		timer := time.NewTimer(sleep)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func readRespAndClose(respPath string) ([]byte, error) {
	f, err := os.Open(respPath)
	if err != nil {
		return nil, err
	}
	raw, readErr := io.ReadAll(io.LimitReader(f, remoteproto.PostAuthMaxFrameBytes))
	closeErr := f.Close()
	if readErr != nil {
		return nil, readErr
	}
	if closeErr != nil {
		return nil, closeErr
	}
	return raw, nil
}

func emitResponse(resp remoteproto.ExecResponse, stdout, stderr io.Writer) int {
	switch resp.Status {
	case remoteproto.StatusDenied:
		if resp.OperatorNote != "" {
			fmt.Fprintf(stderr, "%s (operator note: %s)\n", remoteproto.DenyErrorMessage, resp.OperatorNote)
		} else {
			fmt.Fprintln(stderr, remoteproto.DenyErrorMessage)
		}
		return remoteproto.DenyExitCode

	case remoteproto.StatusTimeout:
		writeDecodedStream(resp.StdoutB64, stdout)
		writeDecodedStream(resp.StderrB64, stderr)
		if resp.TimeoutSec > 0 {
			fmt.Fprintf(stderr, "agbox-remote: remote command timed out after %ds\n", resp.TimeoutSec)
		} else {
			fmt.Fprintln(stderr, "agbox-remote: remote command timed out")
		}
		return remoteproto.TimeoutExitCode

	case remoteproto.StatusCompleted:
		writeDecodedStream(resp.StdoutB64, stdout)
		writeDecodedStream(resp.StderrB64, stderr)
		if resp.StdoutTruncated {
			fmt.Fprintln(stderr, "[agbox-remote] NOTE: the remote daemon truncated stdout at the configured output limit.")
		}
		if resp.StderrTruncated {
			fmt.Fprintln(stderr, "[agbox-remote] NOTE: the remote daemon truncated stderr at the configured output limit.")
		}
		if resp.RedactedCount > 0 {
			fmt.Fprintf(stderr, "[agbox-remote] NOTE: %d secret pattern(s) redacted.\n", resp.RedactedCount)
		}
		if resp.DroppedOutput {
			fmt.Fprintln(stderr, "[agbox-remote] NOTE: output dropped by operator.")
		}
		return resp.ExitCode

	default:
		fmt.Fprintln(stderr, remoteproto.DenyErrorMessage)
		return remoteproto.DenyExitCode
	}
}

func writeDecodedStream(b64 string, w io.Writer) {
	if b64 == "" {
		return
	}
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil || len(raw) == 0 {
		return
	}
	_, _ = w.Write(raw)
}

// RunMain is the production entrypoint for /usr/local/bin/agbox-remote and agbox __guest-remote.
func RunMain(args []string) int {
	ctx, cancel := context.WithCancelCause(context.Background())
	defer cancel(nil)
	sigCh := make(chan os.Signal, 2)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sigCh)
	go func() {
		select {
		case sig := <-sigCh:
			if s, ok := sig.(syscall.Signal); ok {
				cancel(signalError{sig: s})
			} else {
				cancel(context.Canceled)
			}
		case <-ctx.Done():
		}
	}()
	bridgeDir := strings.TrimSpace(os.Getenv("AGBOX_REMOTE_DIR"))
	if bridgeDir == "" {
		bridgeDir = remotebridge.GuestMountPath
	}
	return Run(ctx, args, RunOptions{
		BridgeDir: bridgeDir,
		Stdin:     os.Stdin,
		Stdout:    os.Stdout,
		Stderr:    os.Stderr,
	})
}
