package remoteproto

import (
	"bytes"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	// MaxExtraRedactPatterns limits custom regex redaction patterns in policy or CLI.
	MaxExtraRedactPatterns = 100

	// MaxRedactPatternBytes bounds each custom regex length to avoid compile-time OOM.
	MaxRedactPatternBytes = 1024
)

// SanitizeLine renders untrusted text safely for an operator terminal.
// It permits only printable ASCII (0x20-0x7E) and escapes all C0, DEL, C1,
// BiDi/format runes, invalid UTF-8 bytes, and non-ASCII characters.
func SanitizeLine(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); {
		c := s[i]
		if c >= 0x20 && c <= 0x7E {
			b.WriteByte(c)
			i++
			continue
		}
		if c < 0x20 || c == 0x7F {
			switch c {
			case '\n':
				b.WriteString(`\n`)
			case '\r':
				b.WriteString(`\r`)
			case '\t':
				b.WriteString(`\t`)
			default:
				fmt.Fprintf(&b, `\x%02x`, c)
			}
			i++
			continue
		}
		r, size := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && size == 1 {
			fmt.Fprintf(&b, `\x%02x`, s[i])
			i++
			continue
		}
		if r <= 0xFFFF {
			fmt.Fprintf(&b, `\u%04x`, r)
		} else {
			fmt.Fprintf(&b, `\U%08x`, r)
		}
		i += size
	}
	return b.String()
}

// SanitizeMultiline renders untrusted multiline text with a fixed line prefix and caps.
func SanitizeMultiline(s, linePrefix string, maxLines, maxBytes int) string {
	if maxBytes > 0 && len(s) > maxBytes {
		s = s[:maxBytes]
	}
	rawLines := strings.Split(s, "\n")
	truncatedLines := 0
	if maxLines > 0 && len(rawLines) > maxLines {
		truncatedLines = len(rawLines) - maxLines
		rawLines = rawLines[:maxLines]
	}
	var b strings.Builder
	for idx, line := range rawLines {
		if idx > 0 {
			b.WriteByte('\n')
		}
		b.WriteString(linePrefix)
		b.WriteString(SanitizeLine(line))
	}
	if truncatedLines > 0 {
		fmt.Fprintf(&b, "\n%s... (%d more line(s))", linePrefix, truncatedLines)
	}
	return b.String()
}

// EscapeJSONControls escapes DEL, C1 controls, and invisible/BiDi Unicode runes
// as \uXXXX inside UTF-8 JSON bytes so text editors cannot render spoofing sequences.
func EscapeJSONControls(raw []byte) []byte {
	var b bytes.Buffer
	b.Grow(len(raw))
	for i := 0; i < len(raw); {
		if raw[i] < 0x80 {
			if raw[i] == 0x7F {
				b.WriteString(`\u007f`)
			} else {
				b.WriteByte(raw[i])
			}
			i++
			continue
		}
		r, size := utf8.DecodeRune(raw[i:])
		if r == utf8.RuneError && size == 1 {
			fmt.Fprintf(&b, `\u%04x`, raw[i])
			i++
			continue
		}
		if (r >= 0x80 && r <= 0x9F) || unicode.Is(unicode.Cc, r) || unicode.Is(unicode.Cf, r) || unicode.Is(unicode.Cs, r) || unicode.Is(unicode.Co, r) {
			if r <= 0xFFFF {
				fmt.Fprintf(&b, `\u%04x`, r)
			} else {
				// JSON uses UTF-16 surrogate pairs for runes above U+FFFF.
				rPrime := r - 0x10000
				hi := 0xD800 + (rPrime >> 10)
				lo := 0xDC00 + (rPrime & 0x3FF)
				fmt.Fprintf(&b, `\u%04x\u%04x`, hi, lo)
			}
		} else {
			b.Write(raw[i : i+size])
		}
		i += size
	}
	return b.Bytes()
}

// IsBinary reports whether data contains NUL bytes or invalid UTF-8 sequences.
func IsBinary(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	if bytes.IndexByte(data, 0) >= 0 {
		return true
	}
	return !utf8.Valid(data)
}

// FormatShellPreview builds a single-line sanitized preview of executable and args.
func FormatShellPreview(exe string, args []string) string {
	parts := make([]string, 0, 1+len(args))
	parts = append(parts, quotePreviewToken(SanitizeLine(exe)))
	for _, a := range args {
		parts = append(parts, quotePreviewToken(SanitizeLine(a)))
	}
	return strings.Join(parts, " ")
}

func quotePreviewToken(s string) string {
	if s == "" {
		return "''"
	}
	needsQuote := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		safe := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
			c == '/' || c == '.' || c == '_' || c == '-' || c == ':' || c == '=' || c == '+' || c == ',' || c == '@'
		if !safe {
			needsQuote = true
			break
		}
	}
	if !needsQuote {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

type redactRule struct {
	re          *regexp.Regexp
	replacement []byte
}

var builtinRedactSpecs = []struct {
	pattern     string
	replacement string
}{
	// Complete or truncated PEM private key blocks.
	{`(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?(?:-----END [A-Z0-9 ]*PRIVATE KEY-----|\z)`, `[REDACTED:PRIVATE_KEY]`},
	// AWS access and temporary session keys.
	{`\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`, `[REDACTED:AWS_KEY]`},
	// GitHub, GitLab, Slack, OpenAI, Anthropic, and Google tokens.
	{`\b(?:ghp_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{20,}|glpat-[A-Za-z0-9_-]{20,}|xox[baprs]-[A-Za-z0-9-]{10,}|sk-ant-[A-Za-z0-9_-]{20,}|sk-[A-Za-z0-9_-]{20,}|AIza[0-9A-Za-z_-]{35})\b`, `[REDACTED:TOKEN]`},
	// JWT tokens (three base64url segments starting with eyJ).
	{`\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b`, `[REDACTED:JWT]`},
	// Authorization headers (Bearer or Basic).
	{`(?i)(Authorization\s*:\s*(?:Bearer|Basic)\s+)[^\s"']+`, `${1}[REDACTED:AUTH]`},
	// Cookie and Set-Cookie headers.
	{`(?i)((?:Set-)?Cookie\s*:\s*)[^\r\n]+`, `${1}[REDACTED:COOKIE]`},
	// URL credentials (scheme://user:pass@host).
	{`([A-Za-z][A-Za-z0-9+.-]*://[^/\s:@]+:)[^/\s@]+(@)`, `${1}[REDACTED:PASS]${2}`},
	// JSON, YAML, or KEY=VALUE secret assignments.
	{`(?i)((?:["']?(?:password|passwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token|private[_-]?key|client[_-]?secret)["']?\s*[:=]\s*["']?))([^\s"',}\[\]]{4,})`, `${1}[REDACTED:SECRET]`},
}

// Redactor applies baseline and custom regular-expression secret masking.
type Redactor struct {
	enabled bool
	rules   []redactRule
}

// NewRedactor compiles built-in secret patterns and optional extra regex patterns.
func NewRedactor(enabled bool, extraPatterns []string) (*Redactor, error) {
	if !enabled {
		return &Redactor{enabled: false}, nil
	}
	if len(extraPatterns) > MaxExtraRedactPatterns {
		return nil, fmt.Errorf("too many redaction patterns: %d exceeds limit %d", len(extraPatterns), MaxExtraRedactPatterns)
	}
	rules := make([]redactRule, 0, len(builtinRedactSpecs)+len(extraPatterns))
	for _, sp := range builtinRedactSpecs {
		re, err := regexp.Compile(sp.pattern)
		if err != nil {
			return nil, fmt.Errorf("compile built-in redaction pattern: %w", err)
		}
		rules = append(rules, redactRule{re: re, replacement: []byte(sp.replacement)})
	}
	for i, pat := range extraPatterns {
		if pat == "" {
			return nil, fmt.Errorf("redaction pattern #%d must not be empty", i+1)
		}
		if len(pat) > MaxRedactPatternBytes {
			return nil, fmt.Errorf("redaction pattern #%d exceeds %d bytes", i+1, MaxRedactPatternBytes)
		}
		re, err := regexp.Compile(pat)
		if err != nil {
			return nil, fmt.Errorf("compile redaction pattern #%d %q: %w", i+1, pat, err)
		}
		rules = append(rules, redactRule{re: re, replacement: []byte(`[REDACTED:CUSTOM]`)})
	}
	return &Redactor{enabled: true, rules: rules}, nil
}

// RedactBytes masks secret patterns in data and returns the redacted bytes and match count.
func (r *Redactor) RedactBytes(data []byte) ([]byte, int) {
	if r == nil || !r.enabled || len(data) == 0 {
		return data, 0
	}
	cur := data
	total := 0
	for _, rule := range r.rules {
		matches := rule.re.FindAllIndex(cur, -1)
		if len(matches) == 0 {
			continue
		}
		total += len(matches)
		cur = rule.re.ReplaceAll(cur, rule.replacement)
	}
	if total == 0 {
		return data, 0
	}
	return cur, total
}

// RedactString masks secret patterns in s and returns the redacted string and match count.
func (r *Redactor) RedactString(s string) (string, int) {
	if r == nil || !r.enabled || s == "" {
		return s, 0
	}
	out, count := r.RedactBytes([]byte(s))
	return string(out), count
}

// ValidateSafeToken checks that a control identifier is non-empty printable ASCII without whitespace.
func ValidateSafeToken(s string) error {
	if s == "" {
		return errors.New("token must not be empty")
	}
	for i := 0; i < len(s); i++ {
		if s[i] <= 0x20 || s[i] >= 0x7F {
			return fmt.Errorf("token %q contains whitespace, control, or non-ASCII characters", s)
		}
	}
	return nil
}
