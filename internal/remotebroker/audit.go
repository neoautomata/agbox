package remotebroker

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"agbox/internal/remoteproto"
)

const maxAuditLogBytes = 10 * 1024 * 1024

// AuditEntry records one structured remote command review event.
type AuditEntry struct {
	Timestamp     string   `json:"ts"`
	Sandbox       string   `json:"sandbox"`
	RemotePeer    string   `json:"remote_peer"`
	RemoteID      string   `json:"remote_id,omitempty"`
	ReqID         string   `json:"req_id"`
	Executable    string   `json:"executable"`
	Args          []string `json:"args,omitempty"`
	CWD           string   `json:"cwd,omitempty"`
	StdinSize     int      `json:"stdin_size,omitempty"`
	StdinSHA256   string   `json:"stdin_sha256,omitempty"`
	PolicyAction  string   `json:"policy_action"`
	PolicyRuleID  string   `json:"policy_rule_id,omitempty"`
	OperatorEvent string   `json:"operator_event"`
	Edited        bool     `json:"edited,omitempty"`
	Status        string   `json:"status"`
	ExitCode      int      `json:"exit_code"`
	DurationMS    int64    `json:"duration_ms,omitempty"`
	RedactedCount int      `json:"redacted_count,omitempty"`
	Coalesced     int      `json:"coalesced,omitempty"`
}

// AuditLogger writes redacted JSONL records at mode 0600 with 10 MiB rotation and denial coalescing.
type AuditLogger struct {
	mu       sync.Mutex
	path     string
	redactor *remoteproto.Redactor
	now      func() time.Time

	lastDenyKey   string
	lastDenyCount int
}

// NewAuditLogger initializes an AuditLogger for path (if empty, logging is disabled).
func NewAuditLogger(path string, redactor *remoteproto.Redactor) (*AuditLogger, error) {
	if path != "" {
		dir := filepath.Dir(path)
		if dir != "" && dir != "." {
			info, err := os.Stat(dir)
			if os.IsNotExist(err) {
				if err := os.MkdirAll(dir, 0o700); err != nil {
					return nil, fmt.Errorf("prepare audit log dir: %w", err)
				}
			} else if err != nil {
				return nil, fmt.Errorf("stat audit log dir: %w", err)
			} else if !info.IsDir() {
				return nil, fmt.Errorf("audit log parent %q is not a directory", dir)
			}
		}
		if info, err := os.Lstat(path); err == nil {
			if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
				return nil, fmt.Errorf("refusing non-regular or symlinked audit log %q", path)
			}
		} else if !os.IsNotExist(err) {
			return nil, fmt.Errorf("stat audit log %q: %w", path, err)
		}
	}
	if redactor == nil {
		r, _ := remoteproto.NewRedactor(true, nil)
		redactor = r
	}
	return &AuditLogger{
		path:     path,
		redactor: redactor,
		now:      time.Now,
	}, nil
}

// Path returns the active audit log path.
func (l *AuditLogger) Path() string {
	if l == nil {
		return ""
	}
	return l.path
}

// Log writes one sanitized AuditEntry, coalescing repeated identical denials.
func (l *AuditLogger) Log(entry AuditEntry) error {
	if l == nil || l.path == "" {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	if entry.Timestamp == "" {
		entry.Timestamp = l.now().UTC().Format(time.RFC3339)
	}
	// Apply baseline secret redaction to logged args and executable.
	if l.redactor != nil {
		entry.Executable, _ = l.redactor.RedactString(entry.Executable)
		if len(entry.Args) > 0 {
			redArgs := make([]string, len(entry.Args))
			for i, a := range entry.Args {
				redArgs[i], _ = l.redactor.RedactString(a)
			}
			entry.Args = redArgs
		}
	}

	if entry.Status == remoteproto.StatusDenied && entry.OperatorEvent == "policy_deny" {
		key := denialKey(entry)
		if key == l.lastDenyKey {
			l.lastDenyCount++
			if l.lastDenyCount > 1 && l.lastDenyCount%25 != 0 {
				return nil
			}
			entry.Coalesced = l.lastDenyCount
		} else {
			l.lastDenyKey = key
			l.lastDenyCount = 1
		}
	} else {
		l.lastDenyKey = ""
		l.lastDenyCount = 0
	}

	raw, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	return l.appendLocked(raw)
}

func denialKey(e AuditEntry) string {
	h := sha256.New()
	_, _ = h.Write([]byte(e.Sandbox + "\x00" + e.Executable + "\x00" + e.CWD + "\x00" + e.PolicyRuleID))
	for _, a := range e.Args {
		_, _ = h.Write([]byte("\x00" + a))
	}
	return hex.EncodeToString(h.Sum(nil))
}

func (l *AuditLogger) appendLocked(line []byte) error {
	if info, err := os.Lstat(l.path); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return fmt.Errorf("refusing non-regular audit log %q", l.path)
		}
		if info.Size()+int64(len(line)) > maxAuditLogBytes {
			rotated := l.path + ".1"
			_ = os.Remove(rotated)
			_ = os.Rename(l.path, rotated)
		}
	}
	fd, err := syscall.Open(l.path, syscall.O_CREAT|syscall.O_WRONLY|syscall.O_APPEND|syscall.O_NOFOLLOW|syscall.O_CLOEXEC|syscall.O_NONBLOCK, 0o600)
	if err != nil {
		return fmt.Errorf("open audit log %q: %w", l.path, err)
	}
	f := os.NewFile(uintptr(fd), l.path)
	defer f.Close()
	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil {
		return fmt.Errorf("stat audit log %q: %w", l.path, err)
	}
	if (st.Mode & syscall.S_IFMT) != syscall.S_IFREG {
		return fmt.Errorf("refusing non-regular audit log %q", l.path)
	}
	if err := f.Chmod(0o600); err != nil {
		return err
	}
	_, err = f.Write(line)
	return err
}
