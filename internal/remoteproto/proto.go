// Package remoteproto defines wire framing, TLS 1.3 SAS pairing,
// display sanitization, and baseline secret redaction for agbox remote.
//
// Security properties:
//   - ReadFrame checks frame lengths against explicit caps before allocating memory.
//   - Pairing binds TLS 1.3 ExportKeyingMaterial, both certificates, and raw HELLO bytes
//     inside a Vaudenay 3-move commit-reveal protocol to prevent offline certificate grinding.
//   - SanitizeLine uses an ASCII allowlist to block C0, DEL, C1, and Unicode BiDi spoofing.
//   - Redactor masks common secret formats and truncated PEM blocks as defense-in-depth.
package remoteproto

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"strconv"
	"strings"
	"time"
)

const (
	// ProtocolVersion is the wire protocol version shared by broker and remote daemon.
	ProtocolVersion = 1

	// PreAuthMaxFrameBytes bounds any wire frame received before pairing completes.
	PreAuthMaxFrameBytes = 4 * 1024

	// PostAuthMaxFrameBytes bounds any wire frame received after pairing completes.
	PostAuthMaxFrameBytes = 5 * 1024 * 1024

	// MaxStdinBytes is the hard upper limit for guest stdin payloads.
	MaxStdinBytes = 256 * 1024

	// DefaultOutputBytes is the default combined stdout and stderr capture limit.
	DefaultOutputBytes = 256 * 1024

	// MaxOutputBytes is the hard combined stdout and stderr capture limit.
	// Base64 encoding keeps payloads under 2.7 MiB, below PostAuthMaxFrameBytes.
	MaxOutputBytes = 2 * 1024 * 1024

	// MaxDrainBytes is the runaway output drain ceiling before SIGKILL on remote.
	MaxDrainBytes = 16 * 1024 * 1024

	// MaxBridgeReqBytes bounds one serialized guest request written to the FUSE bridge.
	MaxBridgeReqBytes = 512 * 1024

	// DefaultExecTimeoutSec is the default remote execution timeout in seconds.
	DefaultExecTimeoutSec = 300

	// DefaultAskTimeoutSec is the default host interactive approval timeout in seconds.
	DefaultAskTimeoutSec = 120

	// HandshakeTimeout limits the TLS 1.3 handshake duration.
	HandshakeTimeout = 5 * time.Second

	// CommitRevealTimeout limits the post-handshake commit-reveal exchange.
	CommitRevealTimeout = 10 * time.Second

	// PairingPromptTimeout limits how long each side waits for human pairing input.
	PairingPromptTimeout = 60 * time.Second

	// HeartbeatInterval is the interval between application PING frames.
	HeartbeatInterval = 15 * time.Second

	// ReadDeadTimeout drops a connection when no traffic arrives within three heartbeats.
	ReadDeadTimeout = 45 * time.Second

	// DenyExitCode is the uniform exit code returned by agbox-remote on denial.
	DenyExitCode = 126

	// TimeoutExitCode is the exit code returned when an approved remote command times out.
	TimeoutExitCode = 124

	// LocalErrorExitCode is the exit code returned for local agbox-remote CLI errors.
	LocalErrorExitCode = 2

	// DenyErrorMessage is the uniform error message printed on denial.
	DenyErrorMessage = "agbox-remote: command denied"
)

// Wire frame type constants.
const (
	FrameHello      = "hello"
	FrameCommit     = "commit"
	FrameNonce      = "nonce"
	FrameReveal     = "reveal"
	FramePairAck    = "pair_ack"
	FramePairReject = "pair_reject"
	FrameResume     = "resume"
	FrameResumeOK   = "resume_ok"
	FramePing       = "ping"
	FramePong       = "pong"
	FrameExecReq    = "exec_req"
	FrameExecResp   = "exec_resp"
	FrameCancel     = "cancel"
	FrameBye        = "bye"
)

// Response status values shared across wire and bridge layers.
const (
	StatusCompleted = "completed"
	StatusTimeout   = "timeout"
	StatusDenied    = "denied"
)

// Envelope wraps one typed JSON wire frame.
type Envelope struct {
	Type    string          `json:"type"`
	Payload json.RawMessage `json:"payload,omitempty"`
}

// HelloPayload carries peer capabilities and identity before commit-reveal.
type HelloPayload struct {
	ProtoVer          int      `json:"proto_ver"`
	Role              string   `json:"role"`
	User              string   `json:"user,omitempty"`
	UID               int      `json:"uid,omitempty"`
	Host              string   `json:"host,omitempty"`
	OSArch            string   `json:"os_arch,omitempty"`
	DefaultCWD        string   `json:"default_cwd,omitempty"`
	AllowCWD          []string `json:"allow_cwd,omitempty"`
	MaxOutputBytes    int      `json:"max_output_bytes,omitempty"`
	MaxStdinBytes     int      `json:"max_stdin_bytes,omitempty"`
	MaxExecTimeoutSec int      `json:"max_exec_timeout_sec,omitempty"`
}

// CommitPayload carries the host 32-byte SHA-256 commitment in Move 1.
type CommitPayload struct {
	CommitHex string `json:"commit_hex"`
}

// NoncePayload carries a 32-byte random nonce in Move 2 or Move 3.
type NoncePayload struct {
	NonceHex string `json:"nonce_hex"`
}

// PairDecisionPayload carries pairing acceptance or rejection metadata.
type PairDecisionPayload struct {
	Reason string `json:"reason,omitempty"`
}

// ResumePayload reconnects an authenticated broker with a monotonic sequence number.
type ResumePayload struct {
	SessionIDHex string `json:"session_id_hex"`
	ConnSeq      uint64 `json:"conn_seq"`
}

// ResumeOKPayload confirms atomic takeover of the session on ConnSeq.
type ResumeOKPayload struct {
	ConnSeq uint64 `json:"conn_seq"`
}

// CWDScope constrains canonical working directories on the remote daemon.
type CWDScope struct {
	In    []string `json:"in,omitempty"`
	NotIn []string `json:"not_in,omitempty"`
}

// ExecRequest is one approved command sent from host broker to remote daemon.
type ExecRequest struct {
	ReqID          string     `json:"req_id"`
	Executable     string     `json:"executable"`
	Args           []string   `json:"args,omitempty"`
	CWD            string     `json:"cwd,omitempty"`
	StdinB64       string     `json:"stdin_b64,omitempty"`
	StdinSize      int        `json:"stdin_size,omitempty"`
	StdinSHA256    string     `json:"stdin_sha256,omitempty"`
	ExecTimeoutSec int        `json:"exec_timeout_sec,omitempty"`
	MaxOutputBytes int        `json:"max_output_bytes,omitempty"`
	Reason         string     `json:"reason,omitempty"`
	AllowCWDScope  *CWDScope  `json:"allow_cwd_scope,omitempty"`
	DenyCWDScopes  []CWDScope `json:"deny_cwd_scopes,omitempty"`
}

// ExecResponse is one command execution result returned from remote daemon or host broker.
type ExecResponse struct {
	ReqID           string `json:"req_id"`
	Status          string `json:"status"`
	ExitCode        int    `json:"exit_code"`
	StdoutB64       string `json:"stdout_b64,omitempty"`
	StderrB64       string `json:"stderr_b64,omitempty"`
	StdoutTruncated bool   `json:"stdout_truncated,omitempty"`
	StderrTruncated bool   `json:"stderr_truncated,omitempty"`
	DurationMS      int64  `json:"duration_ms,omitempty"`
	RedactedCount   int    `json:"redacted_count,omitempty"`
	DroppedOutput   bool   `json:"dropped_output,omitempty"`
	OperatorNote    string `json:"operator_note,omitempty"`
	TimeoutSec      int    `json:"timeout_sec,omitempty"`
}

// CancelPayload asks the remote daemon to stop a running command by ReqID.
type CancelPayload struct {
	ReqID string `json:"req_id"`
}

// GuestRequest is the JSON payload written by agbox-remote into the FUSE bridge.
type GuestRequest struct {
	Version        int      `json:"version"`
	Executable     string   `json:"executable"`
	Args           []string `json:"args,omitempty"`
	CWD            string   `json:"cwd,omitempty"`
	StdinB64       string   `json:"stdin_b64,omitempty"`
	ExecTimeoutSec int      `json:"exec_timeout_sec,omitempty"`
	Reason         string   `json:"reason,omitempty"`
}

// BridgeMessage is exchanged between the FUSE bridge and host broker over remote.sock.
type BridgeMessage struct {
	Op       string        `json:"op"`
	SlotID   string        `json:"slot_id,omitempty"`
	Request  *GuestRequest `json:"request,omitempty"`
	Response *ExecResponse `json:"response,omitempty"`
	Peer     string        `json:"peer,omitempty"`
	RemoteID string        `json:"remote_id,omitempty"`
	Policy   string        `json:"policy,omitempty"`
	Error    string        `json:"error,omitempty"`
}

// BridgeStatus describes the live state of one sandbox's remote command bridge.
type BridgeStatus struct {
	Attached bool   `json:"attached"`
	Peer     string `json:"peer,omitempty"`
	RemoteID string `json:"remote_id,omitempty"`
	Policy   string `json:"policy,omitempty"`
	Pending  int    `json:"pending"`
}

// DeniedResponse builds the uniform denial response returned to the guest.
func DeniedResponse(reqID, operatorNote string) ExecResponse {
	return ExecResponse{
		ReqID:        reqID,
		Status:       StatusDenied,
		ExitCode:     DenyExitCode,
		OperatorNote: operatorNote,
	}
}

// WriteFrame writes one 4-byte big-endian length-prefixed JSON frame to w.
// It returns the raw encoded frame bytes so callers can hash exact wire payloads.
func WriteFrame(w io.Writer, frameType string, payload any, maxBytes int) ([]byte, error) {
	if frameType == "" {
		return nil, errors.New("frame type must not be empty")
	}
	var rawPayload json.RawMessage
	if payload != nil {
		b, err := json.Marshal(payload)
		if err != nil {
			return nil, fmt.Errorf("encode frame payload %q: %w", frameType, err)
		}
		rawPayload = b
	}
	env := Envelope{
		Type:    frameType,
		Payload: rawPayload,
	}
	frameBytes, err := json.Marshal(env)
	if err != nil {
		return nil, fmt.Errorf("encode frame %q: %w", frameType, err)
	}
	if maxBytes > 0 && len(frameBytes) > maxBytes {
		return nil, fmt.Errorf("frame %q size %d exceeds limit %d", frameType, len(frameBytes), maxBytes)
	}
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(frameBytes)))
	buf := make([]byte, 4+len(frameBytes))
	copy(buf[:4], hdr[:])
	copy(buf[4:], frameBytes)
	if _, err := w.Write(buf); err != nil {
		return nil, err
	}
	return frameBytes, nil
}

// ReadFrame reads one length-prefixed JSON frame from r while enforcing maxBytes before allocation.
// It returns the frame type, payload bytes, and full raw frame bytes.
func ReadFrame(r io.Reader, maxBytes int) (frameType string, payload []byte, rawFrame []byte, err error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return "", nil, nil, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n == 0 {
		return "", nil, nil, errors.New("empty wire frame")
	}
	if maxBytes > 0 && uint64(n) > uint64(maxBytes) {
		return "", nil, nil, fmt.Errorf("wire frame size %d exceeds limit %d", n, maxBytes)
	}
	rawFrame = make([]byte, int(n))
	if _, err := io.ReadFull(r, rawFrame); err != nil {
		return "", nil, nil, err
	}
	var env Envelope
	dec := json.NewDecoder(bytes.NewReader(rawFrame))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&env); err != nil {
		return "", nil, nil, fmt.Errorf("decode wire frame: %w", err)
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return "", nil, nil, errors.New("wire frame contains trailing JSON data")
	}
	if env.Type == "" {
		return "", nil, nil, errors.New("wire frame missing type")
	}
	return env.Type, env.Payload, rawFrame, nil
}

// DecodeStrict unmarshals JSON bytes into dst while rejecting unknown fields and trailing data.
func DecodeStrict(raw []byte, dst any) error {
	if len(raw) == 0 {
		return errors.New("empty JSON payload")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return errors.New("unexpected trailing JSON data")
	}
	return nil
}

// ParseDurationOrSeconds parses either a positive integer (seconds) or a positive Go duration.
func ParseDurationOrSeconds(raw string) (time.Duration, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return 0, errors.New("duration must not be empty")
	}
	if isAllDigits(s) {
		secs, err := strconv.ParseInt(s, 10, 64)
		if err != nil || secs <= 0 || secs > math.MaxInt64/int64(time.Second) {
			return 0, fmt.Errorf("invalid duration %q: must be a positive number of seconds within range", raw)
		}
		return time.Duration(secs) * time.Second, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil || d <= 0 {
		return 0, fmt.Errorf("invalid duration %q: expected positive seconds (for example, 60) or Go duration (for example, 2m)", raw)
	}
	return d, nil
}

// ParseByteSize parses a positive byte count with optional K, M, KiB, or MiB suffix.
func ParseByteSize(raw string) (int, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return 0, errors.New("byte size must not be empty")
	}
	upper := strings.ToUpper(s)
	mult := 1
	numPart := upper
	switch {
	case strings.HasSuffix(upper, "MIB"):
		mult = 1024 * 1024
		numPart = strings.TrimSuffix(upper, "MIB")
	case strings.HasSuffix(upper, "MB"):
		mult = 1024 * 1024
		numPart = strings.TrimSuffix(upper, "MB")
	case strings.HasSuffix(upper, "M"):
		mult = 1024 * 1024
		numPart = strings.TrimSuffix(upper, "M")
	case strings.HasSuffix(upper, "KIB"):
		mult = 1024
		numPart = strings.TrimSuffix(upper, "KIB")
	case strings.HasSuffix(upper, "KB"):
		mult = 1024
		numPart = strings.TrimSuffix(upper, "KB")
	case strings.HasSuffix(upper, "K"):
		mult = 1024
		numPart = strings.TrimSuffix(upper, "K")
	case strings.HasSuffix(upper, "B"):
		numPart = strings.TrimSuffix(upper, "B")
	}
	if !isAllDigits(numPart) {
		return 0, fmt.Errorf("invalid byte size %q (for example, 262144, 256K, or 2M)", raw)
	}
	n, err := strconv.Atoi(numPart)
	if err != nil || n <= 0 {
		return 0, fmt.Errorf("invalid byte size %q: must be positive", raw)
	}
	if n > (1<<30)/mult {
		return 0, fmt.Errorf("byte size %q exceeds supported range", raw)
	}
	return n * mult, nil
}

func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}
