// Package remotebroker implements the host interactive controller (agbox remote connect),
// single-owner TTY actor, hardened editor/pager helpers, policy hot-reloader, and audit logger.
//
// Security properties:
//   - All prompts and logs serialize through one TTY actor using unix.Poll on blocking fd 0.
//   - Idle menu keys ([w], [t], [c], [q]) are disjoint from Phase 1 and Phase 2 approval keys.
//   - Unread terminal input is flushed (TCIFLUSH) before Phase 1 and Phase 2 prompts.
//   - Editor temp files are created at mode 0600 on verified tmpfs (0700 dir) and zeroized on delete.
//   - $VISUAL and $EDITOR are parsed without a shell and receive per-editor no-swap/no-history flags.
//   - Baseline secret redaction runs on every response and on audit log arguments and edits.
package remotebroker

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"agbox/internal/config"

	"golang.org/x/sys/unix"
)

const tmpfsMagic = 0x01021994

// SplitEditorCommand parses an editor command string into argv without invoking a shell.
// It supports single and double quotes and rejects unclosed quotes or shell metacharacters.
func SplitEditorCommand(raw string) ([]string, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return nil, errors.New("editor command is empty")
	}
	var args []string
	var cur strings.Builder
	inSingle := false
	inDouble := false
	hasToken := false

	for i := 0; i < len(s); i++ {
		c := s[i]
		if inSingle {
			if c == '\'' {
				inSingle = false
			} else {
				cur.WriteByte(c)
			}
			continue
		}
		if inDouble {
			if c == '"' {
				inDouble = false
				continue
			}
			if c == '\\' && i+1 < len(s) && (s[i+1] == '"' || s[i+1] == '\\') {
				i++
				cur.WriteByte(s[i])
				continue
			}
			if c == '$' || c == '`' {
				return nil, fmt.Errorf("editor command %q contains unsupported shell expansion character %q", raw, c)
			}
			cur.WriteByte(c)
			continue
		}

		switch c {
		case ' ', '\t':
			if hasToken {
				args = append(args, cur.String())
				cur.Reset()
				hasToken = false
			}
		case '\'':
			inSingle = true
			hasToken = true
		case '"':
			inDouble = true
			hasToken = true
		case ';', '|', '&', '`', '$', '<', '>', '\n', '\r':
			return nil, fmt.Errorf("editor command %q contains shell metacharacter %q", raw, c)
		default:
			if c < 0x20 || c == 0x7F {
				return nil, fmt.Errorf("editor command %q contains control character", raw)
			}
			cur.WriteByte(c)
			hasToken = true
		}
	}
	if inSingle || inDouble {
		return nil, fmt.Errorf("editor command %q has unclosed quote", raw)
	}
	if hasToken {
		args = append(args, cur.String())
	}
	if len(args) == 0 {
		return nil, errors.New("editor command is empty")
	}
	return args, nil
}

// ResolveEditor picks the interactive editor binary and injects per-editor no-swap/no-history flags.
func ResolveEditor(getenv func(string) string, lookPath func(string) (string, error)) ([]string, string, error) {
	if getenv == nil {
		getenv = os.Getenv
	}
	if lookPath == nil {
		lookPath = exec.LookPath
	}

	raw := strings.TrimSpace(getenv("VISUAL"))
	if raw == "" {
		raw = strings.TrimSpace(getenv("EDITOR"))
	}
	var argv []string
	if raw != "" {
		parsed, err := SplitEditorCommand(raw)
		if err != nil {
			return nil, "", err
		}
		bin, err := lookPath(parsed[0])
		if err != nil {
			return nil, "", fmt.Errorf("editor %q not found: %w", parsed[0], err)
		}
		argv = append([]string{bin}, parsed[1:]...)
	} else {
		for _, cand := range []string{"nano", "vi", "ed"} {
			if bin, err := lookPath(cand); err == nil {
				argv = []string{bin}
				break
			}
		}
		if len(argv) == 0 {
			return nil, "", errors.New("no interactive editor found (set $VISUAL or $EDITOR)")
		}
	}

	base := strings.ToLower(filepath.Base(argv[0]))
	var warning string
	switch {
	case base == "nvim":
		argv = append(argv, "-n", "-i", "NONE", "--cmd", "set nobackup nowritebackup noswapfile noundofile shada=")
	case base == "vim" || strings.HasPrefix(base, "vim."):
		argv = append(argv, "-n", "-i", "NONE", "--cmd", "set nobackup nowritebackup noswapfile noundofile viminfo=")
	case base == "vi":
		switch detectViFlavor(argv[0]) {
		case "nvim":
			argv = append(argv, "-n", "-i", "NONE", "--cmd", "set nobackup nowritebackup noswapfile noundofile shada=")
		case "vim":
			argv = append(argv, "-n", "-i", "NONE", "--cmd", "set nobackup nowritebackup noswapfile noundofile viminfo=")
		default:
			warning = "Editor 'vi' is not Vim or Neovim. Verify it does not write swap or backup files."
		}
	case base == "nano":
		argv = append(argv, "-I")
	case base == "emacs" || base == "emacs-nox":
		argv = append(argv, "-Q", "--eval", "(setq make-backup-files nil auto-save-default nil auto-save-list-file-prefix nil create-lockfiles nil)")
	case base == "ed":
	default:
		warning = fmt.Sprintf("Unrecognized or GUI editor %q may persist swap, undo, or backup copies of sensitive data.", base)
	}
	return argv, warning, nil
}

func detectViFlavor(binPath string) string {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, binPath, "--version").CombinedOutput()
	if err != nil {
		return ""
	}
	low := strings.ToLower(string(out))
	if strings.Contains(low, "neovim") || strings.Contains(low, "nvim") {
		return "nvim"
	}
	if strings.Contains(low, "vim") {
		return "vim"
	}
	return ""
}

// SecureTempDir picks a private 0700 directory on tmpfs ($XDG_RUNTIME_DIR then /dev/shm),
// falling back to $DATA_DIR/tmp with onTmpfs=false only when no tmpfs is available.
func SecureTempDir(dataDir string, getenv func(string) string) (string, bool, error) {
	if getenv == nil {
		getenv = os.Getenv
	}
	euid := os.Geteuid()
	candidates := []string{}
	if xdg := strings.TrimSpace(getenv("XDG_RUNTIME_DIR")); xdg != "" && filepath.IsAbs(xdg) {
		candidates = append(candidates, xdg)
	}
	candidates = append(candidates, "/dev/shm")

	for _, base := range candidates {
		if !isVerifiedTmpfs(base) {
			continue
		}
		dir := filepath.Join(base, fmt.Sprintf("agbox-remote-%d", euid))
		if err := ensureOwnedPrivateDir(dir, euid); err == nil {
			return dir, true, nil
		}
	}

	if dataDir == "" {
		return "", false, errors.New("no tmpfs directory available and dataDir is empty")
	}
	fallback := filepath.Join(dataDir, "tmp")
	if err := config.EnsurePrivateDir(fallback); err != nil {
		return "", false, err
	}
	return fallback, false, nil
}

func isVerifiedTmpfs(dir string) bool {
	var stfs unix.Statfs_t
	if err := unix.Statfs(dir, &stfs); err != nil {
		return false
	}
	return uint64(stfs.Type) == tmpfsMagic
}

func ensureOwnedPrivateDir(dir string, wantUID int) error {
	if err := config.EnsurePrivateDir(dir); err != nil {
		return err
	}
	var st syscall.Stat_t
	if err := syscall.Lstat(dir, &st); err != nil {
		return err
	}
	if (st.Mode & syscall.S_IFMT) != syscall.S_IFDIR {
		return fmt.Errorf("%s is not a directory", dir)
	}
	if int(st.Uid) != wantUID {
		return fmt.Errorf("%s owner UID %d does not match %d", dir, st.Uid, wantUID)
	}
	if st.Mode&0o077 != 0 {
		return fmt.Errorf("%s permissions %04o are too broad", dir, st.Mode&0o7777)
	}
	return nil
}

func zeroizeAndRemove(path string) {
	fd, err := syscall.Open(path, syscall.O_WRONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC|syscall.O_NONBLOCK, 0)
	if err == nil {
		f := os.NewFile(uintptr(fd), path)
		if st, sErr := f.Stat(); sErr == nil && st.Mode().IsRegular() && st.Size() > 0 && st.Size() <= 8*1024*1024 {
			zeros := make([]byte, st.Size())
			_, _ = f.WriteAt(zeros, 0)
			_ = f.Sync()
		}
		_ = f.Close()
	}
	_ = os.Remove(path)
}

// EditBytesInEditor edits content in a verified mode-0600 tmpfs file and returns the edited bytes.
func EditBytesInEditor(
	ctx context.Context,
	dataDir, prefix string,
	content []byte,
	maxBytes int,
	getenv func(string) string,
	stdin io.Reader,
	stdout, stderr io.Writer,
	suspendSignals func() func(),
) ([]byte, error) {
	argv, warn, err := ResolveEditor(getenv, exec.LookPath)
	if err != nil {
		return nil, err
	}
	if warn != "" && stderr != nil {
		fmt.Fprintf(stderr, "[agbox-remote] WARN: %s\n", warn)
	}
	tmpDir, onTmpfs, err := SecureTempDir(dataDir, getenv)
	if err != nil {
		return nil, err
	}
	if !onTmpfs && stderr != nil {
		fmt.Fprintf(stderr, "[agbox-remote] WARN: no tmpfs available. Using disk directory %s for temporary edit file.\n", tmpDir)
	}

	tmp, err := os.CreateTemp(tmpDir, prefix+"-*")
	if err != nil {
		return nil, fmt.Errorf("create temp edit file: %w", err)
	}
	tmpPath := tmp.Name()
	defer zeroizeAndRemove(tmpPath)

	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return nil, err
	}
	if _, err := tmp.Write(content); err != nil {
		_ = tmp.Close()
		return nil, err
	}
	if err := tmp.Close(); err != nil {
		return nil, err
	}

	cmdArgs := append(append([]string(nil), argv[1:]...), "--", tmpPath)
	cmd := exec.CommandContext(ctx, argv[0], cmdArgs...)
	cmd.Stdin = stdin
	cmd.Stdout = stdout
	cmd.Stderr = stderr

	var resume func()
	if suspendSignals != nil {
		resume = suspendSignals()
	}
	runErr := cmd.Run()
	if resume != nil {
		resume()
	}
	if runErr != nil {
		return nil, fmt.Errorf("editor exited with error: %w", runErr)
	}

	fd, err := syscall.Open(tmpPath, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, fmt.Errorf("re-open edited file: %w", err)
	}
	f := os.NewFile(uintptr(fd), tmpPath)
	defer f.Close()

	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() {
		return nil, errors.New("edited temp file is no longer a regular file")
	}
	if maxBytes <= 0 {
		maxBytes = 4 * 1024 * 1024
	}
	edited, err := io.ReadAll(io.LimitReader(f, int64(maxBytes)+1))
	if err != nil {
		return nil, fmt.Errorf("read edited file: %w", err)
	}
	if len(edited) > maxBytes {
		return nil, fmt.Errorf("edited content exceeds %d bytes", maxBytes)
	}
	return edited, nil
}

// ViewInPager displays sanitized text in $PAGER or `less -R` (falling back to stdout).
func ViewInPager(
	ctx context.Context,
	content string,
	getenv func(string) string,
	stdin io.Reader,
	stdout, stderr io.Writer,
	suspendSignals func() func(),
) {
	if getenv == nil {
		getenv = os.Getenv
	}
	var argv []string
	if raw := strings.TrimSpace(getenv("PAGER")); raw != "" {
		if parsed, err := SplitEditorCommand(raw); err == nil {
			if bin, lErr := exec.LookPath(parsed[0]); lErr == nil {
				argv = append([]string{bin}, parsed[1:]...)
			}
		}
	}
	if len(argv) == 0 {
		if bin, err := exec.LookPath("less"); err == nil {
			argv = []string{bin, "-R"}
		}
	}
	if len(argv) == 0 {
		fmt.Fprintln(stdout, content)
		return
	}
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.Env = pagerEnv(os.Environ())
	cmd.Stdin = bytes.NewBufferString(content)
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	_ = stdin

	var resume func()
	if suspendSignals != nil {
		resume = suspendSignals()
	}
	_ = cmd.Run()
	if resume != nil {
		resume()
	}
}

func pagerEnv(base []string) []string {
	out := make([]string, 0, len(base)+2)
	for _, kv := range base {
		if strings.HasPrefix(kv, "LESSSECURE=") || strings.HasPrefix(kv, "LESSHISTFILE=") {
			continue
		}
		out = append(out, kv)
	}
	return append(out, "LESSSECURE=1", "LESSHISTFILE=-")
}

// FlushTTYInput discards any unread terminal input bytes on fd (TCIFLUSH).
func FlushTTYInput(fd int) {
	if fd < 0 {
		return
	}
	_ = unix.IoctlSetInt(fd, unix.TCFLSH, unix.TCIFLUSH)
}
