// Package remotepolicy parses, validates, hot-reloads, and evaluates
// structured remote command policies.
//
// Security properties:
//   - Evaluation follows strict deny > ask > allow > session_allow > default_action precedence.
//   - default_action only permits "ask" or "deny" and never "allow".
//   - Positive arg_patterns are auto-anchored with \A(?:...)\z to prevent suffix smuggling.
//   - Built-in interpreter and wrapper guardrails block accidental allow rules on shells and wrappers.
//   - Reloader opens policy files with O_NOFOLLOW, checks ownership and permissions, and fails
//     closed to DENY-ALL on any I/O, permission, symlink, or parse error.
package remotepolicy

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"agbox/internal/remoteproto"
)

const (
	// PolicyVersion is the supported remote policy JSON schema version.
	PolicyVersion = 1

	// MaxPolicyFileBytes caps the policy JSON file size read from disk.
	MaxPolicyFileBytes = 512 * 1024

	// MaxPolicyRules caps total rules in one policy file.
	MaxPolicyRules = 500

	// MaxRulePatterns caps regex patterns per rule field.
	MaxRulePatterns = 64

	// MaxPatternBytes caps each regex pattern length to bound compile memory.
	MaxPatternBytes = 1024
)

// Action names the policy decision for a command request.
type Action string

const (
	ActionDeny  Action = "deny"
	ActionAsk   Action = "ask"
	ActionAllow Action = "allow"
)

// OutputReviewMode controls when Phase 2 output review triggers.
type OutputReviewMode string

const (
	OutputReviewOff     OutputReviewMode = "off"
	OutputReviewAskOnly OutputReviewMode = "ask_only"
	OutputReviewAlways  OutputReviewMode = "always"
)

// Policy is the validated JSON policy document.
type Policy struct {
	Version            int              `json:"version"`
	Description        string           `json:"description,omitempty"`
	Comment            string           `json:"comment,omitempty"`
	DefaultAction      Action           `json:"default_action,omitempty"`
	PerRunOutputReview OutputReviewMode `json:"per_run_output_review,omitempty"`
	Limits             Limits           `json:"limits,omitempty"`
	AutoRedact         AutoRedactConfig `json:"auto_redact,omitempty"`
	Rules              []Rule           `json:"rules,omitempty"`
}

// Limits configures per-policy request and output bounds.
type Limits struct {
	MaxStdinBytes     int `json:"max_stdin_bytes,omitempty"`
	MaxOutputBytes    int `json:"max_output_bytes,omitempty"`
	MaxExecTimeoutSec int `json:"max_exec_timeout_sec,omitempty"`
	AskTimeoutSec     int `json:"ask_timeout_sec,omitempty"`
}

// AutoRedactConfig configures baseline and extra secret redaction patterns.
type AutoRedactConfig struct {
	Enabled       *bool    `json:"enabled,omitempty"`
	ExtraPatterns []string `json:"extra_patterns,omitempty"`
}

// AutoRedactEnabled reports whether baseline automatic redaction is enabled.
func (c AutoRedactConfig) AutoRedactEnabled() bool {
	if c.Enabled == nil {
		return true
	}
	return *c.Enabled
}

// ArgsMatcher matches structured command arguments.
type ArgsMatcher struct {
	Exact             []string `json:"exact,omitempty"`
	Prefix            []string `json:"prefix,omitempty"`
	ArgPatterns       []string `json:"arg_patterns,omitempty"`
	MaxArgs           *int     `json:"max_args,omitempty"`
	ForbidArgPatterns []string `json:"forbid_arg_patterns,omitempty"`
	AllowAnyArgs      bool     `json:"allow_any_args,omitempty"`

	compiledArgPatterns []*regexp.Regexp
	compiledForbid      []*regexp.Regexp
}

// Rule describes one structured command policy rule.
type Rule struct {
	ID               string      `json:"id"`
	Description      string      `json:"description,omitempty"`
	Comment          string      `json:"comment,omitempty"`
	Action           Action      `json:"action"`
	OutputReview     bool        `json:"output_review,omitempty"`
	Executables      []string    `json:"executables"`
	Args             ArgsMatcher `json:"args,omitempty"`
	CWDAllow         []string    `json:"cwd_allow,omitempty"`
	CWDDeny          []string    `json:"cwd_deny,omitempty"`
	AllowStdin       bool        `json:"allow_stdin,omitempty"`
	AllowInterpreter bool        `json:"allow_interpreter,omitempty"`
}

// SessionGrant stores one exact-match in-memory session approval.
type SessionGrant struct {
	Executable        string
	Args              []string
	CWD               string
	MaxExecTimeoutSec int
	MaxOutputBytes    int
	OutputReview      bool
}

// EvalInput holds the structured request fields evaluated by Evaluate.
type EvalInput struct {
	Executable     string
	Args           []string
	CWD            string
	DefaultCWD     string
	StdinSize      int
	ExecTimeoutSec int
	MaxOutputBytes int
}

// Decision holds the outcome of evaluating a request against a Policy.
type Decision struct {
	Action            Action
	RuleID            string
	RuleDescription   string
	Reason            string
	OutputReview      bool
	AllowCWDScope     *remoteproto.CWDScope
	DenyCWDScopes     []remoteproto.CWDScope
	MaxOutputBytes    int
	MaxExecTimeoutSec int
	SessionMatched    bool
}

var exactInterpreters = map[string]bool{
	"sh": true, "dash": true, "ash": true, "zsh": true, "ksh": true,
	"mksh": true, "csh": true, "tcsh": true, "fish": true, "rbash": true,
	"pwsh": true, "deno": true, "bun": true, "npx": true, "uv": true,
	"busybox": true, "env": true, "xargs": true, "awk": true, "gawk": true,
	"mawk": true, "nawk": true, "sed": true, "expect": true, "gdb": true,
	"strace": true, "ltrace": true, "valgrind": true, "script": true,
	"nohup": true, "timeout": true, "stdbuf": true, "nice": true,
	"ionice": true, "chrt": true, "taskset": true, "setsid": true,
	"flock": true, "unshare": true, "nsenter": true, "chroot": true,
	"bwrap": true, "time": true, "watch": true, "parallel": true,
	"sudo": true, "su": true, "doas": true, "pkexec": true,
	"runuser": true, "sg": true,
}

var versionedInterpreterPrefixes = []string{
	"bash", "python", "perl", "ruby", "php", "node", "lua",
}

var gtfoBins = map[string]bool{
	"git": true, "tar": true, "find": true, "kubectl": true,
	"curl": true, "rsync": true, "ssh": true,
}

var interpreterVariantSuffixes = []string{
	"-static", "-dbg", "-debug", "-minimal", "-cli", "-cgi", "-fpm",
}

func stripInterpreterVariant(s string) (string, bool) {
	for _, suf := range interpreterVariantSuffixes {
		if strings.HasSuffix(s, suf) {
			return strings.TrimSuffix(s, suf), true
		}
	}
	return s, false
}

func interpreterFamily(base string) string {
	low := strings.ToLower(base)
	if low == "" || low == "." || low == "/" {
		return ""
	}
	if exactInterpreters[low] {
		return low
	}
	if stripped, ok := stripInterpreterVariant(low); ok && exactInterpreters[stripped] {
		return stripped
	}
	for _, pfx := range versionedInterpreterPrefixes {
		if low == pfx {
			return pfx
		}
		if pfx == "node" && low == "nodejs" {
			return pfx
		}
		if strings.HasPrefix(low, pfx) && isVersionSuffix(low[len(pfx):]) {
			return pfx
		}
	}
	return ""
}

// IsInterpreterOrWrapper reports whether exe names a shell, script interpreter, or exec wrapper.
func IsInterpreterOrWrapper(exe string) bool {
	base := filepath.Base(strings.TrimSpace(exe))
	return interpreterFamily(base) != ""
}

func isVersionSuffix(s string) bool {
	if s == "" {
		return false
	}
	if stripped, ok := stripInterpreterVariant(s); ok {
		if stripped == "" {
			return true
		}
		s = stripped
	}
	// Strip optional trailing single-letter Python/Linux ABI flags (for example, 3m, 3.13t, 3.12d).
	end := len(s)
	for end > 0 {
		c := s[end-1]
		if c == 'm' || c == 't' || c == 'd' || c == 'u' {
			end--
			continue
		}
		break
	}
	core := s[:end]
	if core == "" {
		return false
	}
	sawDigit := false
	for i := 0; i < len(core); i++ {
		c := core[i]
		if c >= '0' && c <= '9' {
			sawDigit = true
			continue
		}
		if c == '.' || c == '-' {
			continue
		}
		return false
	}
	return sawDigit
}

// ValidateExecutable checks that exe is a clean bare name or clean canonical absolute path.
func ValidateExecutable(exe string) error {
	if exe == "" {
		return errors.New("executable must not be empty")
	}
	for i := 0; i < len(exe); i++ {
		c := exe[i]
		if c <= 0x20 || c == 0x7F {
			return fmt.Errorf("invalid executable %q: omit whitespace and control characters", exe)
		}
	}
	if strings.Contains(exe, "..") {
		return fmt.Errorf("invalid executable %q: omit '..' segments", exe)
	}
	if strings.HasPrefix(exe, "/") {
		if filepath.Clean(exe) != exe || exe == "/" {
			return fmt.Errorf("invalid executable %q: use a clean absolute path", exe)
		}
		return nil
	}
	if strings.ContainsAny(exe, "/\\") {
		return fmt.Errorf("invalid executable %q: omit relative paths", exe)
	}
	for i := 0; i < len(exe); i++ {
		c := exe[i]
		ok := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
			c == '.' || c == '_' || c == '+' || c == '-'
		if !ok {
			return fmt.Errorf("invalid executable %q: unsupported character %q", exe, c)
		}
	}
	return nil
}

// ValidateCWD checks that cwd (when non-empty) is a clean absolute path without control chars or '..'.
func ValidateCWD(cwd string) error {
	if cwd == "" {
		return nil
	}
	for i := 0; i < len(cwd); i++ {
		if cwd[i] < 0x20 || cwd[i] == 0x7F {
			return fmt.Errorf("invalid cwd %q: omit control characters", cwd)
		}
	}
	if !strings.HasPrefix(cwd, "/") {
		return fmt.Errorf("invalid cwd %q: must be an absolute path", cwd)
	}
	for _, seg := range strings.Split(cwd, "/") {
		if seg == ".." {
			return fmt.Errorf("invalid cwd %q: omit '..' segments", cwd)
		}
	}
	return nil
}

// IsPathWithin checks exact path-boundary containment of candidate inside root.
func IsPathWithin(candidate, root string) bool {
	if candidate == "" || root == "" {
		return false
	}
	cleanCand := filepath.Clean(candidate)
	cleanRoot := filepath.Clean(root)
	if !strings.HasPrefix(cleanCand, "/") || !strings.HasPrefix(cleanRoot, "/") {
		return false
	}
	if cleanRoot == "/" {
		return true
	}
	return cleanCand == cleanRoot || strings.HasPrefix(cleanCand, cleanRoot+"/")
}

// DefaultPolicy returns the built-in fail-closed default policy used when no policy file exists.
func DefaultPolicy() *Policy {
	enabled := true
	return &Policy{
		Version:            PolicyVersion,
		DefaultAction:      ActionAsk,
		PerRunOutputReview: OutputReviewOff,
		Limits: Limits{
			MaxStdinBytes:     remoteproto.MaxStdinBytes,
			MaxOutputBytes:    remoteproto.DefaultOutputBytes,
			MaxExecTimeoutSec: remoteproto.DefaultExecTimeoutSec,
			AskTimeoutSec:     remoteproto.DefaultAskTimeoutSec,
		},
		AutoRedact: AutoRedactConfig{
			Enabled: &enabled,
		},
	}
}

// Parse decodes and validates a strict JSON policy file.
// It returns the compiled Policy, non-fatal operator warnings, and any validation error.
func Parse(raw []byte) (*Policy, []string, error) {
	if len(raw) == 0 {
		return nil, nil, errors.New("policy file is empty")
	}
	if len(raw) > MaxPolicyFileBytes {
		return nil, nil, fmt.Errorf("policy file exceeds %d bytes", MaxPolicyFileBytes)
	}
	var p Policy
	if err := remoteproto.DecodeStrict(raw, &p); err != nil {
		return nil, nil, fmt.Errorf("parse policy JSON: %w", err)
	}
	if p.Version != PolicyVersion {
		return nil, nil, fmt.Errorf("unsupported policy version %d (expected %d)", p.Version, PolicyVersion)
	}
	switch p.DefaultAction {
	case "":
		p.DefaultAction = ActionAsk
	case ActionAsk, ActionDeny:
	case ActionAllow:
		return nil, nil, errors.New("policy default_action cannot be 'allow' (use 'ask' or 'deny')")
	default:
		return nil, nil, fmt.Errorf("invalid default_action %q (expected 'ask' or 'deny')", p.DefaultAction)
	}
	switch p.PerRunOutputReview {
	case "":
		p.PerRunOutputReview = OutputReviewOff
	case OutputReviewOff, OutputReviewAskOnly, OutputReviewAlways:
	default:
		return nil, nil, fmt.Errorf("invalid per_run_output_review %q (expected 'off', 'ask_only', or 'always')", p.PerRunOutputReview)
	}

	if err := validateLimits(&p.Limits); err != nil {
		return nil, nil, err
	}
	if _, err := remoteproto.NewRedactor(p.AutoRedact.AutoRedactEnabled(), p.AutoRedact.ExtraPatterns); err != nil {
		return nil, nil, fmt.Errorf("invalid auto_redact: %w", err)
	}
	if len(p.Rules) > MaxPolicyRules {
		return nil, nil, fmt.Errorf("policy has %d rules (limit %d)", len(p.Rules), MaxPolicyRules)
	}

	var warnings []string
	seenIDs := make(map[string]bool, len(p.Rules))
	for i := range p.Rules {
		r := &p.Rules[i]
		w, err := validateAndCompileRule(r, i, seenIDs)
		if err != nil {
			return nil, nil, err
		}
		warnings = append(warnings, w...)
	}
	return &p, warnings, nil
}

func validateLimits(l *Limits) error {
	if l.MaxStdinBytes == 0 {
		l.MaxStdinBytes = remoteproto.MaxStdinBytes
	} else if l.MaxStdinBytes < 0 || l.MaxStdinBytes > remoteproto.MaxStdinBytes {
		return fmt.Errorf("limits.max_stdin_bytes %d must be between 1 and %d", l.MaxStdinBytes, remoteproto.MaxStdinBytes)
	}
	if l.MaxOutputBytes == 0 {
		l.MaxOutputBytes = remoteproto.DefaultOutputBytes
	} else if l.MaxOutputBytes < 1024 || l.MaxOutputBytes > remoteproto.MaxOutputBytes {
		return fmt.Errorf("limits.max_output_bytes %d must be between 1024 and %d", l.MaxOutputBytes, remoteproto.MaxOutputBytes)
	}
	if l.MaxExecTimeoutSec == 0 {
		l.MaxExecTimeoutSec = remoteproto.DefaultExecTimeoutSec
	} else if l.MaxExecTimeoutSec < 1 || l.MaxExecTimeoutSec > 3600 {
		return fmt.Errorf("limits.max_exec_timeout_sec %d must be between 1 and 3600", l.MaxExecTimeoutSec)
	}
	if l.AskTimeoutSec == 0 {
		l.AskTimeoutSec = remoteproto.DefaultAskTimeoutSec
	} else if l.AskTimeoutSec < 5 || l.AskTimeoutSec > 3600 {
		return fmt.Errorf("limits.ask_timeout_sec %d must be between 5 and 3600", l.AskTimeoutSec)
	}
	return nil
}

func validateAndCompileRule(r *Rule, idx int, seenIDs map[string]bool) ([]string, error) {
	label := fmt.Sprintf("rule #%d", idx+1)
	if r.ID == "" {
		return nil, fmt.Errorf("%s: missing required field 'id'", label)
	}
	if err := remoteproto.ValidateSafeToken(r.ID); err != nil {
		return nil, fmt.Errorf("%s: invalid id %q: %w", label, r.ID, err)
	}
	if seenIDs[r.ID] {
		return nil, fmt.Errorf("duplicate rule id %q", r.ID)
	}
	seenIDs[r.ID] = true
	label = fmt.Sprintf("rule %q", r.ID)

	switch r.Action {
	case ActionDeny, ActionAsk, ActionAllow:
	default:
		return nil, fmt.Errorf("%s: invalid action %q (expected 'deny', 'ask', or 'allow')", label, r.Action)
	}
	if len(r.Executables) == 0 {
		return nil, fmt.Errorf("%s: executables must contain at least one entry", label)
	}

	var warnings []string
	for _, exe := range r.Executables {
		if exe == "*" {
			if r.Action == ActionAllow {
				return nil, fmt.Errorf("%s: allow rule cannot use wildcard executable '*'", label)
			}
			continue
		}
		if err := ValidateExecutable(exe); err != nil {
			return nil, fmt.Errorf("%s: %w", label, err)
		}
		if r.Action == ActionAllow && IsInterpreterOrWrapper(exe) {
			if !r.AllowInterpreter {
				return nil, fmt.Errorf("%s: allow rule targets interpreter or wrapper %q (set allow_interpreter=true to override)", label, exe)
			}
			warnings = append(warnings, fmt.Sprintf("%s allows interpreter or wrapper %q", label, exe))
		}
		base := strings.ToLower(filepath.Base(exe))
		if r.Action == ActionAllow && gtfoBins[base] && (len(r.Args.Prefix) > 0 || r.Args.AllowAnyArgs) {
			warnings = append(warnings, fmt.Sprintf("%s uses broad argument matching on %q. Add forbid_arg_patterns and max_args to block dangerous flags.", label, exe))
		}
	}

	for _, c := range r.CWDAllow {
		if c == "" || ValidateCWD(c) != nil {
			return nil, fmt.Errorf("%s: invalid cwd_allow entry %q", label, c)
		}
	}
	for _, c := range r.CWDDeny {
		if c == "" || ValidateCWD(c) != nil {
			return nil, fmt.Errorf("%s: invalid cwd_deny entry %q", label, c)
		}
	}

	if r.Args.MaxArgs != nil && *r.Args.MaxArgs < 0 {
		return nil, fmt.Errorf("%s: args.max_args must be >= 0", label)
	}
	if r.Args.Exact != nil && (len(r.Args.Prefix) > 0 || len(r.Args.ArgPatterns) > 0 || r.Args.AllowAnyArgs) {
		return nil, fmt.Errorf("%s: args.exact cannot be combined with prefix, arg_patterns, or allow_any_args", label)
	}
	if len(r.Args.ArgPatterns) > MaxRulePatterns {
		return nil, fmt.Errorf("%s: args.arg_patterns exceeds limit %d", label, MaxRulePatterns)
	}
	if len(r.Args.ForbidArgPatterns) > MaxRulePatterns {
		return nil, fmt.Errorf("%s: args.forbid_arg_patterns exceeds limit %d", label, MaxRulePatterns)
	}

	if r.Action == ActionAllow {
		hasConstraint := r.Args.Exact != nil || len(r.Args.Prefix) > 0 || len(r.Args.ArgPatterns) > 0 || r.Args.MaxArgs != nil
		if !hasConstraint && !r.Args.AllowAnyArgs {
			return nil, fmt.Errorf("%s: allow rule must constrain args or set args.allow_any_args=true", label)
		}
	}

	for i, pat := range r.Args.ArgPatterns {
		if pat == "" || len(pat) > MaxPatternBytes {
			return nil, fmt.Errorf("%s: args.arg_patterns[%d] has invalid length", label, i)
		}
		re, err := regexp.Compile(`\A(?:` + pat + `)\z`)
		if err != nil {
			return nil, fmt.Errorf("%s: compile args.arg_patterns[%d]: %w", label, i, err)
		}
		r.Args.compiledArgPatterns = append(r.Args.compiledArgPatterns, re)
	}
	for i, pat := range r.Args.ForbidArgPatterns {
		if pat == "" || len(pat) > MaxPatternBytes {
			return nil, fmt.Errorf("%s: args.forbid_arg_patterns[%d] has invalid length", label, i)
		}
		re, err := regexp.Compile(pat)
		if err != nil {
			return nil, fmt.Errorf("%s: compile args.forbid_arg_patterns[%d]: %w", label, i, err)
		}
		r.Args.compiledForbid = append(r.Args.compiledForbid, re)
	}
	return warnings, nil
}

// Evaluate computes the policy decision for req using deny > ask > allow > session > default.
func Evaluate(p *Policy, req EvalInput, sessionAllows []SessionGrant) Decision {
	if p == nil {
		p = DefaultPolicy()
	}
	maxOut := p.Limits.MaxOutputBytes
	if maxOut <= 0 {
		maxOut = remoteproto.DefaultOutputBytes
	}
	if req.MaxOutputBytes > 0 && req.MaxOutputBytes < maxOut {
		maxOut = req.MaxOutputBytes
	}
	maxTimeout := p.Limits.MaxExecTimeoutSec
	if maxTimeout <= 0 {
		maxTimeout = remoteproto.DefaultExecTimeoutSec
	}
	if req.ExecTimeoutSec > 0 && req.ExecTimeoutSec < maxTimeout {
		maxTimeout = req.ExecTimeoutSec
	}

	if err := ValidateExecutable(req.Executable); err != nil {
		return Decision{
			Action:            ActionDeny,
			Reason:            err.Error(),
			MaxOutputBytes:    maxOut,
			MaxExecTimeoutSec: maxTimeout,
		}
	}
	if err := ValidateCWD(req.CWD); err != nil {
		return Decision{
			Action:            ActionDeny,
			Reason:            err.Error(),
			MaxOutputBytes:    maxOut,
			MaxExecTimeoutSec: maxTimeout,
		}
	}
	if req.StdinSize > p.Limits.MaxStdinBytes {
		return Decision{
			Action:            ActionDeny,
			Reason:            fmt.Sprintf("stdin size %d exceeds policy limit %d", req.StdinSize, p.Limits.MaxStdinBytes),
			MaxOutputBytes:    maxOut,
			MaxExecTimeoutSec: maxTimeout,
		}
	}

	effectiveCWD := req.CWD
	if effectiveCWD == "" {
		effectiveCWD = req.DefaultCWD
	}

	// Collect cwd scopes from executable+args-matching deny rules for remote canonical verification.
	var denyCWDScopes []remoteproto.CWDScope
	for i := range p.Rules {
		r := &p.Rules[i]
		if r.Action != ActionDeny {
			continue
		}
		if !ruleMatchesExecutable(r, req.Executable) || !ruleMatchesArgs(r, req.Args) {
			continue
		}
		if len(r.CWDAllow) > 0 || len(r.CWDDeny) > 0 {
			denyCWDScopes = append(denyCWDScopes, remoteproto.CWDScope{
				In:    append([]string(nil), r.CWDAllow...),
				NotIn: append([]string(nil), r.CWDDeny...),
			})
		}
		if ruleMatchesCWD(r, req.CWD, effectiveCWD, false) {
			return Decision{
				Action:            ActionDeny,
				RuleID:            r.ID,
				RuleDescription:   r.Description,
				Reason:            "matched deny rule " + r.ID,
				MaxOutputBytes:    maxOut,
				MaxExecTimeoutSec: maxTimeout,
				DenyCWDScopes:     denyCWDScopes,
			}
		}
	}

	// Check ask rules next.
	for i := range p.Rules {
		r := &p.Rules[i]
		if r.Action != ActionAsk {
			continue
		}
		if !ruleMatchesExecutable(r, req.Executable) || !ruleMatchesArgs(r, req.Args) {
			continue
		}
		if !ruleMatchesCWD(r, req.CWD, effectiveCWD, false) {
			continue
		}
		return Decision{
			Action:            ActionAsk,
			RuleID:            r.ID,
			RuleDescription:   r.Description,
			Reason:            "matched ask rule " + r.ID,
			OutputReview:      r.OutputReview || p.PerRunOutputReview == OutputReviewAlways || p.PerRunOutputReview == OutputReviewAskOnly,
			DenyCWDScopes:     denyCWDScopes,
			MaxOutputBytes:    maxOut,
			MaxExecTimeoutSec: maxTimeout,
		}
	}

	// Check allow rules next.
	for i := range p.Rules {
		r := &p.Rules[i]
		if r.Action != ActionAllow {
			continue
		}
		if req.StdinSize > 0 && !r.AllowStdin {
			continue
		}
		if !ruleMatchesExecutable(r, req.Executable) || !ruleMatchesArgs(r, req.Args) {
			continue
		}
		if !ruleMatchesCWD(r, req.CWD, effectiveCWD, true) {
			continue
		}
		var allowScope *remoteproto.CWDScope
		if len(r.CWDAllow) > 0 || len(r.CWDDeny) > 0 {
			allowScope = &remoteproto.CWDScope{
				In:    append([]string(nil), r.CWDAllow...),
				NotIn: append([]string(nil), r.CWDDeny...),
			}
		}
		return Decision{
			Action:            ActionAllow,
			RuleID:            r.ID,
			RuleDescription:   r.Description,
			Reason:            "matched allow rule " + r.ID,
			OutputReview:      r.OutputReview || p.PerRunOutputReview == OutputReviewAlways,
			AllowCWDScope:     allowScope,
			DenyCWDScopes:     denyCWDScopes,
			MaxOutputBytes:    maxOut,
			MaxExecTimeoutSec: maxTimeout,
		}
	}

	// Check exact-match session grants (never override deny or ask rules).
	if req.StdinSize == 0 && !IsInterpreterOrWrapper(req.Executable) {
		for _, g := range sessionAllows {
			if sessionGrantMatches(g, req, effectiveCWD) {
				outCap := maxOut
				if g.MaxOutputBytes > 0 && g.MaxOutputBytes < outCap {
					outCap = g.MaxOutputBytes
				}
				timeCap := maxTimeout
				if g.MaxExecTimeoutSec > 0 && g.MaxExecTimeoutSec < timeCap {
					timeCap = g.MaxExecTimeoutSec
				}
				return Decision{
					Action:            ActionAllow,
					Reason:            "matched exact session approval",
					OutputReview:      g.OutputReview || p.PerRunOutputReview == OutputReviewAlways,
					DenyCWDScopes:     denyCWDScopes,
					MaxOutputBytes:    outCap,
					MaxExecTimeoutSec: timeCap,
					SessionMatched:    true,
				}
			}
		}
	}

	// Default action (ask or deny).
	act := p.DefaultAction
	if act == "" {
		act = ActionAsk
	}
	outReview := p.PerRunOutputReview == OutputReviewAlways
	if act == ActionAsk && p.PerRunOutputReview == OutputReviewAskOnly {
		outReview = true
	}
	return Decision{
		Action:            act,
		Reason:            "default_action=" + string(act),
		OutputReview:      outReview,
		DenyCWDScopes:     denyCWDScopes,
		MaxOutputBytes:    maxOut,
		MaxExecTimeoutSec: maxTimeout,
	}
}

func sessionGrantMatches(g SessionGrant, req EvalInput, effectiveCWD string) bool {
	if g.Executable != req.Executable {
		return false
	}
	if g.CWD != effectiveCWD {
		return false
	}
	if len(g.Args) != len(req.Args) {
		return false
	}
	for i := range g.Args {
		if g.Args[i] != req.Args[i] {
			return false
		}
	}
	if g.MaxExecTimeoutSec > 0 && req.ExecTimeoutSec > 0 && req.ExecTimeoutSec > g.MaxExecTimeoutSec {
		return false
	}
	if g.MaxOutputBytes > 0 && req.MaxOutputBytes > 0 && req.MaxOutputBytes > g.MaxOutputBytes {
		return false
	}
	return true
}

func ruleMatchesExecutable(r *Rule, reqExe string) bool {
	reqBase := filepath.Base(reqExe)
	for _, pat := range r.Executables {
		if pat == "*" {
			return true
		}
		if pat == reqExe {
			return true
		}
		if r.Action == ActionDeny || r.Action == ActionAsk {
			// Match deny and ask rules against both full path and basename.
			if filepath.Base(pat) == reqBase {
				return true
			}
			// Match versioned interpreter families in deny and ask rules (for example, python3 -> python3.12).
			if isSameInterpreterFamily(pat, reqBase) {
				return true
			}
		}
	}
	return false
}

func isSameInterpreterFamily(pat, reqBase string) bool {
	pFam := interpreterFamily(filepath.Base(pat))
	if pFam == "" {
		return false
	}
	return pFam == interpreterFamily(reqBase)
}

func ruleMatchesArgs(r *Rule, args []string) bool {
	m := &r.Args
	if m.MaxArgs != nil && len(args) > *m.MaxArgs {
		return false
	}
	for _, re := range m.compiledForbid {
		for _, a := range args {
			if re.MatchString(a) {
				return false
			}
		}
	}
	if m.Exact != nil {
		if len(args) != len(m.Exact) {
			return false
		}
		for i := range m.Exact {
			if args[i] != m.Exact[i] {
				return false
			}
		}
		return true
	}
	if len(m.Prefix) > 0 {
		if len(args) < len(m.Prefix) {
			return false
		}
		for i := range m.Prefix {
			if args[i] != m.Prefix[i] {
				return false
			}
		}
		if len(m.compiledArgPatterns) > 0 {
			rest := args[len(m.Prefix):]
			for _, a := range rest {
				matched := false
				for _, re := range m.compiledArgPatterns {
					if re.MatchString(a) {
						matched = true
						break
					}
				}
				if !matched {
					return false
				}
			}
		}
		return true
	}
	if len(m.compiledArgPatterns) > 0 {
		for _, a := range args {
			matched := false
			for _, re := range m.compiledArgPatterns {
				if re.MatchString(a) {
					matched = true
					break
				}
			}
			if !matched {
				return false
			}
		}
		return true
	}
	return true
}

func ruleMatchesCWD(r *Rule, reqCWD, effectiveCWD string, strictAllowEmpty bool) bool {
	if len(r.CWDAllow) > 0 {
		if strictAllowEmpty && reqCWD == "" {
			return false
		}
		if effectiveCWD == "" {
			return false
		}
		ok := false
		for _, root := range r.CWDAllow {
			if IsPathWithin(effectiveCWD, root) {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	if len(r.CWDDeny) > 0 {
		if effectiveCWD == "" {
			return false
		}
		for _, denied := range r.CWDDeny {
			if IsPathWithin(effectiveCWD, denied) {
				return false
			}
		}
	}
	return true
}

// StarterPolicyJSON returns a commented-via-description starter JSON policy template.
func StarterPolicyJSON() []byte {
	enabled := true
	maxZero := 0
	maxSix := 6
	p := Policy{
		Version:            PolicyVersion,
		Description:        "Starter remote command policy for agbox remote connect",
		DefaultAction:      ActionAsk,
		PerRunOutputReview: OutputReviewOff,
		Limits: Limits{
			MaxStdinBytes:     remoteproto.MaxStdinBytes,
			MaxOutputBytes:    remoteproto.DefaultOutputBytes,
			MaxExecTimeoutSec: remoteproto.DefaultExecTimeoutSec,
			AskTimeoutSec:     remoteproto.DefaultAskTimeoutSec,
		},
		AutoRedact: AutoRedactConfig{
			Enabled: &enabled,
		},
		Rules: []Rule{
			{
				ID:          "deny-destructive-rm",
				Description: "Always deny rm commands automatically",
				Action:      ActionDeny,
				Executables: []string{"rm", "shred", "dd", "mkfs"},
			},
			{
				ID:          "deny-shells",
				Description: "Always deny direct shell invocations",
				Action:      ActionDeny,
				Executables: []string{"sh", "bash", "dash", "zsh"},
			},
			{
				ID:          "allow-uname-read",
				Description: "Auto-approve read-only uname checks",
				Action:      ActionAllow,
				Executables: []string{"uname"},
				Args: ArgsMatcher{
					Exact: []string{"-a"},
				},
			},
			{
				ID:          "allow-uptime",
				Description: "Auto-approve uptime with zero arguments",
				Action:      ActionAllow,
				Executables: []string{"uptime"},
				Args: ArgsMatcher{
					MaxArgs: &maxZero,
				},
			},
			{
				ID:          "allow-git-status",
				Description: "Auto-approve git status without config overrides",
				Action:      ActionAllow,
				Executables: []string{"git"},
				Args: ArgsMatcher{
					Prefix:            []string{"status"},
					ArgPatterns:       []string{`--short`, `--branch`, `-s`, `-b`, `--porcelain`},
					MaxArgs:           &maxSix,
					ForbidArgPatterns: []string{`^-c$`, `^--config`, `^--git-dir`, `^--work-tree`},
				},
			},
		},
	}
	raw, _ := json.MarshalIndent(p, "", "  ")
	return append(raw, '\n')
}

// Reloader tracks a policy file on disk, hot-reloads changes, and fails closed to DENY-ALL on error.
type Reloader struct {
	mu        sync.Mutex
	path      string
	allowRoot bool
	euid      int
	sleepFn   func(time.Duration)

	policy   *Policy
	hash     [32]byte
	hasHash  bool
	denyAll  bool
	lastErr  error
	warnings []string
}

// NewReloader loads path (when non-empty) or uses DefaultPolicy when path is empty.
func NewReloader(path string, allowRoot bool) (*Reloader, []string, error) {
	return newReloaderWith(path, allowRoot, os.Geteuid(), time.Sleep)
}

func newReloaderWith(path string, allowRoot bool, euid int, sleepFn func(time.Duration)) (*Reloader, []string, error) {
	if sleepFn == nil {
		sleepFn = time.Sleep
	}
	r := &Reloader{
		path:      path,
		allowRoot: allowRoot,
		euid:      euid,
		sleepFn:   sleepFn,
	}
	if path == "" {
		r.policy = DefaultPolicy()
		return r, nil, nil
	}
	p, warnings, hash, err := r.loadOnce()
	if err != nil {
		return nil, nil, err
	}
	r.policy = p
	r.hash = hash
	r.hasHash = true
	r.warnings = warnings
	return r, warnings, nil
}

// ReloadResult describes the outcome of checking the policy file for updates.
type ReloadResult struct {
	Changed   bool
	DenyAll   bool
	RuleCount int
	HashHex   string
	Warnings  []string
	Err       error
}

// CheckReload checks whether the policy file changed and reloads it atomically.
// Any I/O, permission, symlink, or parse error switches the reloader to DENY-ALL.
func (r *Reloader) CheckReload() ReloadResult {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.path == "" {
		return ReloadResult{RuleCount: len(r.policy.Rules)}
	}
	raw, err := readCheckedPolicyFile(r.path, r.allowRoot, r.euid)
	if err != nil {
		return r.enterDenyAllLocked(err)
	}
	h := sha256.Sum256(raw)
	if r.hasHash && !r.denyAll && bytes.Equal(h[:], r.hash[:]) {
		return ReloadResult{
			RuleCount: len(r.policy.Rules),
			HashHex:   fmt.Sprintf("%x", h[:6]),
		}
	}
	p, warnings, err := Parse(raw)
	if err != nil {
		// Retry once after 50 ms to smooth over non-atomic editor truncate-and-write saves.
		r.sleepFn(50 * time.Millisecond)
		raw2, rErr := readCheckedPolicyFile(r.path, r.allowRoot, r.euid)
		if rErr != nil {
			return r.enterDenyAllLocked(rErr)
		}
		h = sha256.Sum256(raw2)
		p, warnings, err = Parse(raw2)
		if err != nil {
			return r.enterDenyAllLocked(err)
		}
	}
	wasDenyAll := r.denyAll
	changed := wasDenyAll || !r.hasHash || !bytes.Equal(h[:], r.hash[:])
	r.policy = p
	r.hash = h
	r.hasHash = true
	r.denyAll = false
	r.lastErr = nil
	r.warnings = warnings
	return ReloadResult{
		Changed:   changed,
		DenyAll:   false,
		RuleCount: len(p.Rules),
		HashHex:   fmt.Sprintf("%x", h[:6]),
		Warnings:  warnings,
	}
}

func (r *Reloader) enterDenyAllLocked(err error) ReloadResult {
	changed := !r.denyAll || (r.lastErr == nil) || (r.lastErr.Error() != err.Error())
	r.denyAll = true
	r.lastErr = err
	return ReloadResult{
		Changed: changed,
		DenyAll: true,
		Err:     err,
	}
}

// Current returns the active policy or (nil, err) when in fail-closed DENY-ALL state.
func (r *Reloader) Current() (*Policy, bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.denyAll {
		return nil, true, r.lastErr
	}
	return r.policy, false, nil
}

// Path returns the configured policy file path (empty when using built-in defaults).
func (r *Reloader) Path() string {
	return r.path
}

func (r *Reloader) loadOnce() (*Policy, []string, [32]byte, error) {
	raw, err := readCheckedPolicyFile(r.path, r.allowRoot, r.euid)
	if err != nil {
		return nil, nil, [32]byte{}, err
	}
	p, warnings, err := Parse(raw)
	if err != nil {
		return nil, nil, [32]byte{}, err
	}
	return p, warnings, sha256.Sum256(raw), nil
}

// LoadCheckedFile reads, checks ownership/permissions/symlinks, and parses a policy file.
func LoadCheckedFile(path string, allowRoot bool) (*Policy, []string, error) {
	raw, err := readCheckedPolicyFile(path, allowRoot, os.Geteuid())
	if err != nil {
		return nil, nil, err
	}
	return Parse(raw)
}

func readCheckedPolicyFile(path string, allowRoot bool, euid int) ([]byte, error) {
	if path == "" {
		return nil, errors.New("policy file path must not be empty")
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC|syscall.O_NONBLOCK, 0)
	if err != nil {
		if errors.Is(err, syscall.ELOOP) {
			return nil, fmt.Errorf("refusing symlinked policy file %q", path)
		}
		return nil, fmt.Errorf("open policy file %q: %w", path, err)
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()

	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil {
		return nil, fmt.Errorf("stat policy file %q: %w", path, err)
	}
	if (st.Mode & syscall.S_IFMT) != syscall.S_IFREG {
		return nil, fmt.Errorf("refusing non-regular policy file %q", path)
	}
	if !(allowRoot && euid == 0 && st.Uid == 0) && int(st.Uid) != euid {
		return nil, fmt.Errorf("policy file %q owner UID %d does not match current UID %d", path, st.Uid, euid)
	}
	if st.Mode&0o022 != 0 {
		return nil, fmt.Errorf("policy file %q has insecure permissions %04o (remove group and world write bits)", path, st.Mode&0o7777)
	}
	if st.Size > MaxPolicyFileBytes {
		return nil, fmt.Errorf("policy file %q exceeds %d bytes", path, MaxPolicyFileBytes)
	}
	raw, err := io.ReadAll(io.LimitReader(f, MaxPolicyFileBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read policy file %q: %w", path, err)
	}
	if len(raw) > MaxPolicyFileBytes {
		return nil, fmt.Errorf("policy file %q exceeds %d bytes", path, MaxPolicyFileBytes)
	}
	return raw, nil
}
