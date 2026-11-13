// Package msb provides argument builders, output parsers, and a Runner interface
// for the microsandbox (msb) CLI.
//
// Security properties:
//   - BuildNetArgs defaults to default-deny egress (--net-default deny). It places
//     deny rules for host, loopback, private, link-local, multicast, and cloud-config
//     endpoints before any allow rule under msb first-match-wins evaluation.
//   - validateNetRuleToken rejects whitespace, control characters, and malformed rules.
//   - FormatEnvExports and ShellQuote build POSIX-quoted secret scripts for stdin
//     delivery so secrets never appear in CLI arguments or host files.
package msb

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// GuestUser is the non-root username inside the microVM.
const GuestUser = "agent"

// GuestUIDGid is the numeric UID:GID of GuestUser inside the microVM.
const GuestUIDGid = "1000:1000"

// GuestHome is the home directory of GuestUser inside the microVM.
const GuestHome = "/home/agent"

// GuestKeysFile is the path inside the microVM where host API keys are written.
const GuestKeysFile = "/home/agent/.agbox-keys.sh"

// GuestSkillsMount is the read-only virtiofs mountpoint for host global skills.
const GuestSkillsMount = "/home/agent/.agbox-skills"

// GuestRulesMount is the read-only virtiofs mountpoint for host global rules.
const GuestRulesMount = "/home/agent/.agbox-rules"

// GuestAgentsMount is the read-only virtiofs mountpoint for cached agent binaries.
const GuestAgentsMount = "/home/agent/.agbox-agents"

// GuestProfileMount is the ext4 disk volume mountpoint for conversation profiles.
const GuestProfileMount = "/home/agent/.agbox-profile"

// GuestWorkspace is the directory inside the microVM where host shares are mounted.
const GuestWorkspace = "/workspace"

// DefaultPassthroughEnvVars lists the host environment variables forwarded into
// the microVM when non-empty on the host.
var DefaultPassthroughEnvVars = []string{
	"ANTHROPIC_API_KEY",
	"OPENAI_API_KEY",
	"GEMINI_API_KEY",
	"GOOGLE_API_KEY",
	"GOOGLE_GENERATIVE_AI_API_KEY",
	"GROQ_API_KEY",
	"OPENROUTER_API_KEY",
	"MISTRAL_API_KEY",
	"DEEPSEEK_API_KEY",
	"COHERE_API_KEY",
	"PERPLEXITY_API_KEY",
	"TOGETHER_API_KEY",
	"FIREWORKS_API_KEY",
	"CEREBRAS_API_KEY",
	"XAI_API_KEY",
	"GITHUB_TOKEN",
	"GH_TOKEN",
	"AWS_ACCESS_KEY_ID",
	"AWS_SECRET_ACCESS_KEY",
	"AWS_SESSION_TOKEN",
	"AWS_REGION",
	"AWS_PROFILE",
	"VERTEX_LOCATION",
	"GOOGLE_CLOUD_PROJECT",
	"GOOGLE_CLOUD_LOCATION",
	"AZURE_OPENAI_API_KEY",
	"AZURE_OPENAI_ENDPOINT",
	"OLLAMA_HOST",
	"OPENCODE_SERVER_PASSWORD",
	"OPENCODE_SERVER_USERNAME",
	"COLORTERM",
}

// DefaultBlockedCIDRRules lists local, broadcast, link-local, and cloud-config
// CIDR rules evaluated before any allow rule:
//   - 0.0.0.0/8: "this host" local network (RFC 1122).
//   - 100.100.100.200/32: Alibaba Cloud IMDS (resides inside CGNAT 100.64.0.0/10).
//   - 168.63.129.16/32: Microsoft Azure WireServer/IMDS (resides in public IPv4).
//   - 169.254.0.0/16: IPv4 link-local and AWS/GCP/Azure/OpenStack IMDS (169.254.169.254).
//   - 240.0.0.0/4: IPv4 reserved space and limited broadcast (255.255.255.255).
//   - [fe80::/10]: IPv6 link-local range.
//   - [fd00:ec2::254/128]: AWS IPv6 IMDS (resides inside IPv6 ULA fc00::/7).
var DefaultBlockedCIDRRules = []string{
	"deny@0.0.0.0/8",
	"deny@100.100.100.200/32",
	"deny@168.63.129.16/32",
	"deny@169.254.0.0/16",
	"deny@240.0.0.0/4",
	"deny@[fe80::/10]",
	"deny@[fd00:ec2::254/128]",
}

var nonDNSBlockHostRules = []string{
	"deny@host:tcp:0-52",
	"deny@host:tcp:54-65535",
	"deny@host:udp:0-52",
	"deny@host:udp:54-65535",
	"deny@host:icmpv4",
	"deny@host:icmpv6",
}

// TranslateNetSpec converts one network profile name or msb rule into CLI flags.
//
// The default "public" profile enforces default-deny egress. It blocks host,
// loopback, private, link-local, multicast, and cloud-config endpoints before
// allowing public internet destinations.
func TranslateNetSpec(spec string) ([]string, error) {
	return BuildNetArgs(false, []string{spec})
}

// BuildNetArgs compiles network flags from noNet and one or more --net specs.
// Because microsandbox evaluates --net-rule flags with first-match-wins,
// BuildNetArgs places deny rules before allow rules while permitting DNS queries
// appropriately for the selected profile or narrow allowlist.
func BuildNetArgs(noNet bool, specs []string) ([]string, error) {
	if noNet {
		return []string{"--no-net"}, nil
	}
	if len(specs) == 0 {
		specs = []string{"public"}
	}

	allowAll := false
	hasRestrictiveProfile := false
	hasGroupAllow := false
	allowHost := false
	hostAllowToken := "allow@host"
	allowLoopback := false
	allowPrivate := false
	allowLinkLocal := false
	allowMulticast := false
	allowMetadata := false
	denyDNS := false
	hasExplicitAllowDNS := false

	var userDenies []string
	var hostScopedAllows []string
	var userAllows []string

	for _, rawSpec := range specs {
		s := strings.TrimSpace(rawSpec)
		switch s {
		case "", "public", "public-only":
			hasRestrictiveProfile = true
			hasGroupAllow = true
			userAllows = appendUnique(userAllows, "allow@public")
		case "none", "deny":
			return []string{"--no-net"}, nil
		case "private":
			hasRestrictiveProfile = true
			hasGroupAllow = true
			allowPrivate = true
			userAllows = appendUnique(userAllows, "allow@public")
			userAllows = appendUnique(userAllows, "allow@private")
		case "host":
			hasRestrictiveProfile = true
			hasGroupAllow = true
			allowHost = true
			userAllows = appendUnique(userAllows, "allow@public")
		case "all", "allow":
			allowAll = true
		default:
			if !strings.Contains(s, "@") {
				return nil, fmt.Errorf("unsupported --net value %q (use: public, none, private, host, all, or an msb rule like 'allow@example.com:tcp:443')", rawSpec)
			}
			for _, tok := range strings.Split(s, ",") {
				trimmed := strings.TrimSpace(tok)
				rule, action, dir, right, err := parseAndNormalizeNetRule(trimmed)
				if err != nil {
					return nil, err
				}
				if action == "deny" {
					userDenies = appendUnique(userDenies, rule)
					if (dir == "egress" || dir == "any") && isFullDNSRight(right) {
						denyDNS = true
					}
					continue
				}
				hasRestrictiveProfile = true
				if dir == "ingress" {
					userAllows = appendUnique(userAllows, rule)
					continue
				}
				switch {
				case right == "any" || right == "public":
					hasGroupAllow = true
					userAllows = appendUnique(userAllows, rule)
				case right == "private":
					allowPrivate = true
					hasGroupAllow = true
					userAllows = appendUnique(userAllows, rule)
				case right == "host":
					allowHost = true
					if dir == "any" {
						hostAllowToken = "allow:any@host"
					}
				case right == "loopback":
					allowLoopback = true
					userAllows = appendUnique(userAllows, rule)
				case right == "link-local":
					allowLinkLocal = true
					userAllows = appendUnique(userAllows, rule)
				case right == "multicast":
					allowMulticast = true
					userAllows = appendUnique(userAllows, rule)
				case right == "meta":
					allowMetadata = true
					userAllows = appendUnique(userAllows, rule)
				case right == "dns" || strings.HasPrefix(right, "dns:"):
					hasExplicitAllowDNS = true
					hostScopedAllows = appendUnique(hostScopedAllows, rule)
				case strings.HasPrefix(right, "host:"):
					hostScopedAllows = appendUnique(hostScopedAllows, rule)
				default:
					userAllows = appendUnique(userAllows, rule)
				}
			}
		}
	}

	if allowAll && !hasRestrictiveProfile {
		args := []string{"--net-default", "allow"}
		for _, d := range userDenies {
			args = append(args, "--net-rule", d)
		}
		return args, nil
	}

	args := []string{"--net-default", "deny"}
	for _, d := range userDenies {
		args = append(args, "--net-rule", d)
	}

	trailingDenyHost := false
	switch {
	case allowHost:
		args = append(args, "--net-rule", hostAllowToken)
		for _, r := range hostScopedAllows {
			args = append(args, "--net-rule", r)
		}
	case hasGroupAllow || hasExplicitAllowDNS:
		for _, r := range hostScopedAllows {
			args = append(args, "--net-rule", r)
		}
		if hasGroupAllow && !denyDNS && !hasExplicitAllowDNS {
			args = append(args, "--net-rule", "allow@dns")
		}
		args = append(args, "--net-rule", "deny@host")
	default:
		for _, r := range hostScopedAllows {
			args = append(args, "--net-rule", r)
		}
		if denyDNS {
			args = append(args, "--net-rule", "deny@host")
		} else {
			// Block non-53 host traffic before user allows so narrow domain rules can resolve DNS
			// without opening arbitrary DNS lookups on port 53.
			for _, r := range nonDNSBlockHostRules {
				args = append(args, "--net-rule", r)
			}
			trailingDenyHost = true
		}
	}

	var denies []string
	if !allowLoopback {
		denies = appendUnique(denies, "deny@loopback")
	}
	if !allowPrivate {
		denies = appendUnique(denies, "deny@private")
	}
	if !allowLinkLocal {
		denies = appendUnique(denies, "deny@link-local")
	}
	if !allowMulticast {
		denies = appendUnique(denies, "deny@multicast")
	}
	if !allowMetadata {
		denies = appendUnique(denies, "deny@meta")
	}
	if !allowLoopback {
		denies = appendUnique(denies, "deny@0.0.0.0/8")
	}
	if !allowMetadata {
		denies = appendUnique(denies, "deny@100.100.100.200/32")
		denies = appendUnique(denies, "deny@168.63.129.16/32")
		if !allowLinkLocal {
			denies = appendUnique(denies, "deny@169.254.0.0/16")
		}
	}
	if !allowMulticast {
		denies = appendUnique(denies, "deny@240.0.0.0/4")
	}
	if !allowLinkLocal {
		denies = appendUnique(denies, "deny@[fe80::/10]")
	}
	if !allowMetadata {
		denies = appendUnique(denies, "deny@[fd00:ec2::254/128]")
	}

	for _, d := range denies {
		args = append(args, "--net-rule", d)
	}
	for _, a := range userAllows {
		args = append(args, "--net-rule", a)
	}
	if trailingDenyHost {
		args = append(args, "--net-rule", "deny@host")
	}
	return args, nil
}

func isFullDNSRight(right string) bool {
	if right == "dns" {
		return true
	}
	if !strings.HasPrefix(right, "dns:") {
		return false
	}
	parts := strings.Split(right, ":")
	if len(parts) > 3 {
		return false
	}
	if len(parts) >= 2 && parts[1] != "" && parts[1] != "any" {
		return false
	}
	if len(parts) == 3 && parts[2] != "" && parts[2] != "any" && parts[2] != "53" {
		return false
	}
	return true
}

func validateNetRuleToken(rule string) error {
	_, _, _, _, err := parseAndNormalizeNetRule(rule)
	return err
}

func parseAndNormalizeNetRule(raw string) (normalized, action, direction, right string, err error) {
	if raw == "" {
		return "", "", "", "", errors.New("empty --net-rule token")
	}
	for _, r := range raw {
		if r <= 0x20 || r == 0x7f {
			return "", "", "", "", fmt.Errorf("invalid --net-rule %q: whitespace and control characters are forbidden", raw)
		}
	}
	leftRaw, rightRaw, ok := strings.Cut(raw, "@")
	if !ok {
		return "", "", "", "", fmt.Errorf("invalid --net-rule %q: rule must use <action>[:<direction>]@<target> syntax", raw)
	}
	left := strings.ToLower(leftRaw)
	right = strings.ToLower(rightRaw)
	if right == "" {
		return "", "", "", "", fmt.Errorf("invalid --net-rule %q: missing target after '@'", raw)
	}

	action, dir, err := parseActionAndDirection(left, raw)
	if err != nil {
		return "", "", "", "", err
	}

	// Map the legacy "metadata" target name to the msb "meta" group keyword while leaving
	// hostnames such as metadata.google.internal and domain=metadata untouched.
	if right == "metadata" {
		right = "meta"
	} else if strings.HasPrefix(right, "metadata:") {
		right = "meta:" + strings.TrimPrefix(right, "metadata:")
	}

	if right == "dns" || strings.HasPrefix(right, "dns:") {
		if err := validateDNSRuleRight(right, dir, raw); err != nil {
			return "", "", "", "", err
		}
		return left + "@" + right, action, dir, right, nil
	}

	var protoRaw, portsRaw string
	if strings.HasPrefix(right, "[") {
		protoRaw, portsRaw, err = parseBracketedNetTarget(right, raw)
		if err != nil {
			return "", "", "", "", err
		}
	} else {
		protoRaw, portsRaw, err = parseUnbracketedNetTarget(right, raw)
		if err != nil {
			return "", "", "", "", err
		}
	}

	if protoRaw != "" {
		if err := validateNetProto(protoRaw, dir, raw); err != nil {
			return "", "", "", "", err
		}
	}
	if portsRaw != "" {
		if err := validateNetPorts(portsRaw, raw); err != nil {
			return "", "", "", "", err
		}
	}

	return left + "@" + right, action, dir, right, nil
}

func parseActionAndDirection(left, fullToken string) (string, string, error) {
	act := left
	dir := "egress"
	hasDir := false
	if a, d, ok := strings.Cut(left, ":"); ok {
		act = a
		dir = d
		hasDir = true
	}
	if act != "allow" && act != "deny" {
		return "", "", fmt.Errorf("invalid --net-rule %q: action must be allow or deny", fullToken)
	}
	if hasDir && dir != "egress" && dir != "ingress" && dir != "any" {
		return "", "", fmt.Errorf("invalid --net-rule %q: direction must be egress, ingress, or any", fullToken)
	}
	return act, dir, nil
}

func validateDNSRuleRight(right, dir, fullToken string) error {
	if dir != "egress" {
		return fmt.Errorf("invalid --net-rule %q: the dns target only supports egress rules", fullToken)
	}
	parts := strings.Split(right, ":")
	if len(parts) > 3 {
		return fmt.Errorf("invalid --net-rule %q: trailing fields after port", fullToken)
	}
	if len(parts) >= 2 {
		switch parts[1] {
		case "", "any", "udp", "tcp":
		default:
			return fmt.Errorf("invalid --net-rule %q: dns protocol %q must be any, udp, or tcp", fullToken, parts[1])
		}
	}
	if len(parts) == 3 {
		switch parts[2] {
		case "", "any", "53":
		default:
			return fmt.Errorf("invalid --net-rule %q: dns port %q must be 53 or any", fullToken, parts[2])
		}
	}
	return nil
}

func parseBracketedNetTarget(right, fullToken string) (protoRaw, portsRaw string, err error) {
	afterOpen := right[1:]
	closeIdx := strings.IndexByte(afterOpen, ']')
	if closeIdx < 0 {
		return "", "", fmt.Errorf("invalid --net-rule %q: unclosed '[' in IPv6 target", fullToken)
	}
	inner := afterOpen[:closeIdx]
	afterClose := afterOpen[closeIdx+1:]

	if strings.Contains(inner, "/") {
		pfx, pfxErr := netip.ParsePrefix(inner)
		if pfxErr != nil {
			return "", "", fmt.Errorf("invalid --net-rule %q: invalid CIDR %q", fullToken, inner)
		}
		if !pfx.Addr().Is6() {
			return "", "", fmt.Errorf("invalid --net-rule %q: bracketed target %q must be IPv6", fullToken, inner)
		}
	} else {
		addr, addrErr := netip.ParseAddr(inner)
		if addrErr != nil {
			return "", "", fmt.Errorf("invalid --net-rule %q: invalid IPv6 address %q", fullToken, inner)
		}
		if !addr.Is6() || addr.Zone() != "" {
			return "", "", fmt.Errorf("invalid --net-rule %q: bracketed target %q must be an IPv6 address without zone", fullToken, inner)
		}
	}

	if afterClose == "" {
		return "", "", nil
	}
	if !strings.HasPrefix(afterClose, ":") {
		return "", "", fmt.Errorf("invalid --net-rule %q: unexpected characters after ']'", fullToken)
	}
	suffixParts := strings.Split(afterClose[1:], ":")
	if len(suffixParts) > 2 {
		return "", "", fmt.Errorf("invalid --net-rule %q: trailing fields after port", fullToken)
	}
	if suffixParts[0] == "" {
		return "", "", fmt.Errorf("invalid --net-rule %q: protocol cannot be empty after ':'", fullToken)
	}
	protoRaw = suffixParts[0]
	if len(suffixParts) == 2 {
		if suffixParts[1] == "" {
			return "", "", fmt.Errorf("invalid --net-rule %q: port cannot be empty after ':'", fullToken)
		}
		portsRaw = suffixParts[1]
	}
	return protoRaw, portsRaw, nil
}

func parseUnbracketedNetTarget(right, fullToken string) (protoRaw, portsRaw string, err error) {
	if strings.Contains(right, "::") {
		return "", "", fmt.Errorf("invalid --net-rule %q: IPv6 targets must be enclosed in brackets (for example, deny@[fe80::/10])", fullToken)
	}
	parts := strings.SplitN(right, ":", 4)
	if len(parts) == 4 {
		return "", "", fmt.Errorf("invalid --net-rule %q: trailing fields or unbracketed IPv6 address (wrap IPv6 in [...])", fullToken)
	}
	target := parts[0]
	if len(parts) >= 2 {
		protoRaw = parts[1]
		if looksLikePortSpec(protoRaw) {
			return "", "", fmt.Errorf("invalid --net-rule %q: port %q is in protocol position, use <target>:<proto>:<ports>", fullToken, protoRaw)
		}
		if protoRaw == "" {
			return "", "", fmt.Errorf("invalid --net-rule %q: protocol cannot be empty after ':'", fullToken)
		}
	}
	if len(parts) == 3 {
		portsRaw = parts[2]
		if portsRaw == "" {
			return "", "", fmt.Errorf("invalid --net-rule %q: port cannot be empty after ':'", fullToken)
		}
	}
	if err := validateUnbracketedTarget(target, fullToken); err != nil {
		return "", "", err
	}
	return protoRaw, portsRaw, nil
}

func validateUnbracketedTarget(target, fullToken string) error {
	if target == "" {
		return fmt.Errorf("invalid --net-rule %q: empty target", fullToken)
	}
	switch target {
	case "any", "public", "private", "loopback", "link-local", "meta", "multicast", "host":
		return nil
	}
	if rest, ok := strings.CutPrefix(target, "*."); ok {
		if !isValidNetDomain(rest, true) {
			return fmt.Errorf("invalid --net-rule %q: invalid wildcard domain suffix %q", fullToken, target)
		}
		return nil
	}
	if rest, ok := strings.CutPrefix(target, "suffix="); ok {
		if !isValidNetDomain(rest, true) {
			return fmt.Errorf("invalid --net-rule %q: invalid domain suffix %q", fullToken, rest)
		}
		return nil
	}
	if rest, ok := strings.CutPrefix(target, "domain="); ok {
		if !isValidNetDomain(rest, false) {
			return fmt.Errorf("invalid --net-rule %q: invalid domain name %q", fullToken, rest)
		}
		return nil
	}
	if strings.Contains(target, "/") {
		pfx, err := netip.ParsePrefix(target)
		if err != nil {
			return fmt.Errorf("invalid --net-rule %q: invalid CIDR %q", fullToken, target)
		}
		if pfx.Addr().Is6() {
			return fmt.Errorf("invalid --net-rule %q: IPv6 CIDRs must be enclosed in brackets (for example, deny@[%s])", fullToken, target)
		}
		return nil
	}
	if addr, err := netip.ParseAddr(target); err == nil {
		if addr.Is6() || addr.Zone() != "" {
			return fmt.Errorf("invalid --net-rule %q: IPv6 addresses must be enclosed in brackets (for example, allow@[%s])", fullToken, target)
		}
		return nil
	}
	if strings.Contains(target, ".") {
		if !isValidNetDomain(target, true) {
			return fmt.Errorf("invalid --net-rule %q: invalid domain name %q", fullToken, target)
		}
		return nil
	}
	return fmt.Errorf("invalid --net-rule %q: %q is ambiguous (use domain=%s or a group keyword such as public, private, loopback, link-local, meta, multicast, or host)", fullToken, target, target)
}

func isValidNetDomain(s string, requireMultiLabel bool) bool {
	s = strings.TrimSuffix(s, ".")
	if s == "" || len(s) > 253 {
		return false
	}
	labels := strings.Split(s, ".")
	if requireMultiLabel && len(labels) < 2 {
		return false
	}
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 {
			return false
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-') {
				return false
			}
		}
	}
	return true
}

func looksLikePortSpec(s string) bool {
	if s == "" {
		return false
	}
	if lo, hi, ok := strings.Cut(s, "-"); ok {
		return isValidUint16Digits(lo) && isValidUint16Digits(hi)
	}
	return isValidUint16Digits(s)
}

func isValidUint16Digits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	_, err := strconv.ParseUint(s, 10, 16)
	return err == nil
}

func validateNetProto(proto, dir, fullToken string) error {
	switch proto {
	case "any", "tcp", "udp":
		return nil
	case "icmpv4", "icmpv6":
		if dir == "ingress" || dir == "any" {
			return fmt.Errorf("invalid --net-rule %q: %s is only supported on egress rules", fullToken, proto)
		}
		return nil
	default:
		return fmt.Errorf("invalid --net-rule %q: unsupported protocol %q (use any, tcp, udp, icmpv4, or icmpv6)", fullToken, proto)
	}
}

func validateNetPorts(ports, fullToken string) error {
	if ports == "any" {
		return nil
	}
	if loStr, hiStr, ok := strings.Cut(ports, "-"); ok {
		if !isValidUint16Digits(loStr) || !isValidUint16Digits(hiStr) {
			return fmt.Errorf("invalid --net-rule %q: invalid port range %q", fullToken, ports)
		}
		lo, _ := strconv.ParseUint(loStr, 10, 16)
		hi, _ := strconv.ParseUint(hiStr, 10, 16)
		if lo > hi {
			return fmt.Errorf("invalid --net-rule %q: port range start %d exceeds end %d", fullToken, lo, hi)
		}
		return nil
	}
	if !isValidUint16Digits(ports) {
		return fmt.Errorf("invalid --net-rule %q: invalid port %q", fullToken, ports)
	}
	return nil
}

func appendUnique(list []string, item string) []string {
	if slices.Contains(list, item) {
		return list
	}
	return append(list, item)
}

// ShellQuote wraps s in POSIX single quotes, escaping any embedded single quote
// as `'\”`. The resulting token is safe against all shell expansion (`$`, “ ` “,
// `\`, globbing, and newlines).
func ShellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// FormatEnvExports builds the shell script for GuestKeysFile from non-empty
// environment variables in keys. It uses lookup to read host values and returns
// the script text and the number of exported variables.
func FormatEnvExports(lookup func(string) string, keys []string) (string, int) {
	var b strings.Builder
	b.WriteString("# Auto-generated by agbox. Exists only inside this disposable microVM.\n")
	count := 0
	for _, k := range keys {
		if k == "" {
			continue
		}
		val := lookup(k)
		if val == "" {
			continue
		}
		b.WriteString("export ")
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(ShellQuote(val))
		b.WriteByte('\n')
		count++
	}
	return b.String(), count
}

// VolumeSpec describes a single host-to-guest virtiofs mount.
type VolumeSpec struct {
	HostPath  string
	GuestPath string
	ReadOnly  bool
}

// FormatFlag renders the `-v` value with `uid=1000,gid=1000` so the non-root
// guest user can read and write shared files regardless of host file modes.
func (v VolumeSpec) FormatFlag() string {
	mode := "rw"
	if v.ReadOnly {
		mode = "ro"
	}
	return fmt.Sprintf("%s:%s:%s,uid=1000,gid=1000", v.HostPath, v.GuestPath, mode)
}

// CreateOpts holds parameters for `msb create`.
type CreateOpts struct {
	Image    string
	Name     string
	CPUs     string
	Memory   string
	RootDisk string
	Workdir  string
	NoNet    bool
	NetSpecs []string
}

// BuildCreateArgs constructs the CLI argument list for `msb create`.
func BuildCreateArgs(opts CreateOpts) ([]string, error) {
	if opts.Image == "" {
		return nil, errors.New("image is required")
	}
	if opts.Name == "" {
		return nil, errors.New("sandbox name is required")
	}
	cpus := opts.CPUs
	if cpus == "" {
		cpus = "4"
	}
	mem := opts.Memory
	if mem == "" {
		mem = "8G"
	}
	args := []string{
		"create", opts.Image,
		"--name", opts.Name,
		"--cpus", cpus,
		"--memory", mem,
	}
	if opts.RootDisk != "" {
		args = append(args, "--root-disk", opts.RootDisk)
	}
	if opts.Workdir != "" {
		args = append(args, "--workdir", opts.Workdir, "--mkdir", opts.Workdir)
	}
	if opts.NoNet || len(opts.NetSpecs) > 0 {
		netArgs, err := BuildNetArgs(opts.NoNet, opts.NetSpecs)
		if err != nil {
			return nil, err
		}
		args = append(args, netArgs...)
	}
	return args, nil
}

// NamedVolumeSpec describes an msb named volume (such as a disk-backed profile volume).
// Disk-backed ext4 volumes use block-device semantics and omit virtiofs uid/gid flags.
type NamedVolumeSpec struct {
	VolumeName string
	GuestPath  string
}

// FormatFlag renders the `-v` value (`<volume>:<guest_path>`) for a named volume.
func (v NamedVolumeSpec) FormatFlag() string {
	return fmt.Sprintf("%s:%s", v.VolumeName, v.GuestPath)
}

// RestoreOpts holds parameters for `msb snap restore`.
type RestoreOpts struct {
	Snapshot     string
	Name         string
	User         string
	CPUs         string
	Memory       string
	NamedVolumes []NamedVolumeSpec
	Volumes      []VolumeSpec
	Ports        []string // e.g. "127.0.0.1:4096:3000"
	NoNet        bool
	NetSpecs     []string
}

// BuildRestoreArgs constructs the CLI argument list for `msb snap restore`.
func BuildRestoreArgs(opts RestoreOpts) ([]string, error) {
	if opts.Snapshot == "" {
		return nil, errors.New("snapshot reference is required")
	}
	if opts.Name == "" {
		return nil, errors.New("sandbox name is required")
	}
	user := opts.User
	if user == "" {
		user = GuestUser
	}
	args := []string{
		"snap", "restore", opts.Snapshot,
		"--name", opts.Name,
		"-u", user,
	}
	if opts.CPUs != "" {
		args = append(args, "--cpus", opts.CPUs)
	}
	if opts.Memory != "" {
		args = append(args, "--memory", opts.Memory)
	}
	for _, nv := range opts.NamedVolumes {
		args = append(args, "-v", nv.FormatFlag())
	}
	for _, v := range opts.Volumes {
		args = append(args, "-v", v.FormatFlag())
	}
	for _, p := range opts.Ports {
		args = append(args, "-p", p)
	}
	netArgs, err := BuildNetArgs(opts.NoNet, opts.NetSpecs)
	if err != nil {
		return nil, err
	}
	args = append(args, netArgs...)
	if len(opts.Ports) > 0 && !(len(netArgs) >= 2 && netArgs[0] == "--net-default" && netArgs[1] == "allow") {
		for _, p := range opts.Ports {
			rule, err := ingressRuleForPublishedPort(p)
			if err != nil {
				return nil, err
			}
			if !hasNetRule(args, rule) {
				args = append(args, "--net-rule", rule)
			}
		}
	}
	return args, nil
}

func hasNetRule(args []string, rule string) bool {
	for i := 0; i+1 < len(args); i++ {
		if args[i] == "--net-rule" && args[i+1] == rule {
			return true
		}
	}
	return false
}

func ingressRuleForPublishedPort(spec string) (string, error) {
	trimmed := strings.TrimSpace(spec)
	if trimmed == "" {
		return "", errors.New("empty published port spec")
	}
	for _, r := range trimmed {
		if r <= 0x20 || r == 0x7f {
			return "", fmt.Errorf("invalid published port spec %q: whitespace and control characters are forbidden", spec)
		}
	}
	base, protoRaw, hasProto := strings.Cut(trimmed, "/")
	proto := "tcp"
	if hasProto {
		proto = strings.ToLower(protoRaw)
		if proto != "tcp" && proto != "udp" {
			return "", fmt.Errorf("invalid published port spec %q: protocol %q must be tcp or udp", spec, protoRaw)
		}
	}

	var hostStr, guestStr string
	if strings.HasPrefix(base, "[") {
		closeIdx := strings.IndexByte(base, ']')
		if closeIdx < 0 {
			return "", fmt.Errorf("invalid published port spec %q: unclosed '[' in bind address", spec)
		}
		bindIP := base[1:closeIdx]
		if addr, err := netip.ParseAddr(bindIP); err != nil || addr.Zone() != "" {
			return "", fmt.Errorf("invalid published port spec %q: invalid bind IP %q", spec, bindIP)
		}
		after := base[closeIdx+1:]
		if !strings.HasPrefix(after, ":") {
			return "", fmt.Errorf("invalid published port spec %q: expected :hostPort:guestPort after ']'", spec)
		}
		parts := strings.Split(after[1:], ":")
		if len(parts) != 2 {
			return "", fmt.Errorf("invalid published port spec %q: expected [bindIP]:hostPort:guestPort", spec)
		}
		hostStr, guestStr = parts[0], parts[1]
	} else {
		parts := strings.Split(base, ":")
		switch len(parts) {
		case 2:
			hostStr, guestStr = parts[0], parts[1]
		case 3:
			if addr, err := netip.ParseAddr(parts[0]); err != nil || addr.Zone() != "" {
				return "", fmt.Errorf("invalid published port spec %q: invalid bind IP %q", spec, parts[0])
			}
			hostStr, guestStr = parts[1], parts[2]
		default:
			return "", fmt.Errorf("invalid published port spec %q: expected [bindIP:]hostPort:guestPort[/proto]", spec)
		}
	}

	if !isValidPort1To65535(hostStr) || !isValidPort1To65535(guestStr) {
		return "", fmt.Errorf("invalid published port spec %q: host and guest ports must be integers in 1..65535", spec)
	}
	return fmt.Sprintf("allow:ingress@loopback:%s:%s", proto, guestStr), nil
}

func isValidPort1To65535(s string) bool {
	if !isValidUint16Digits(s) {
		return false
	}
	v, err := strconv.ParseUint(s, 10, 16)
	return err == nil && v >= 1
}

// ExecCmdOpts holds parameters for `msb exec`.
type ExecCmdOpts struct {
	Sandbox  string
	Workdir  string
	User     string
	Detached bool
	TTY      bool
	NoTTY    bool
	Stream   bool
	Env      []string // KEY=VAL pairs
	Command  []string
}

// BuildExecArgs constructs the CLI argument list for `msb exec`.
func BuildExecArgs(opts ExecCmdOpts) []string {
	args := []string{"exec"}
	if opts.Detached {
		args = append(args, "-d")
	}
	if opts.TTY {
		args = append(args, "-t")
	} else if opts.Stream {
		args = append(args, "--stream")
	} else if opts.NoTTY {
		args = append(args, "--no-tty")
	}
	if opts.Workdir != "" {
		args = append(args, "-w", opts.Workdir)
	}
	if opts.User != "" {
		args = append(args, "-u", opts.User)
	}
	for _, kv := range opts.Env {
		args = append(args, "-e", kv)
	}
	args = append(args, opts.Sandbox, "--")
	args = append(args, opts.Command...)
	return args
}

// GuestEnvFlags returns the standard environment key=value pairs passed to
// guest `msb exec` invocations for the non-root `agent` user. Setting
// SSH_CONNECTION=1 instructs `agy` to use its remote SSH OAuth flow (printing
// a browser URL and prompting for the verification code) inside the microVM.
func GuestEnvFlags() []string {
	return []string{
		"HOME=" + GuestHome,
		"USER=" + GuestUser,
		"LOGNAME=" + GuestUser,
		"PATH=" + GuestDefaultPath,
		"SSH_CONNECTION=1",
	}
}

// KeyLoaderPrefix is the POSIX sh command that sources GuestKeysFile if it exists.
// In POSIX sh (dash), a failed '.' command aborts a non-interactive shell.
// Guarding with 'test -f' prevents shell termination when no keys file exists.
const KeyLoaderPrefix = "test -f " + GuestKeysFile + " && . " + GuestKeysFile + ";"

// ProvisionGuestUserScript returns an idempotent bash script that creates the
// non-root user 'agent' (1000:1000) with passwordless sudo. It handles both
// node:24-bookworm-slim (where UID 1000 is 'node') and debian:bookworm-slim
// (where UID 1000 does not exist).
func ProvisionGuestUserScript() string {
	return `set -euo pipefail
if ! command -v sudo >/dev/null 2>&1; then
  apt-get update -qq && apt-get install -y -qq --no-install-recommends sudo >/dev/null
fi
if id -u 1000 >/dev/null 2>&1; then
  cur_user="$(id -un 1000)"
  if [[ "${cur_user}" != "agent" ]]; then
    usermod -l "agent" -d "/home/agent" -m "${cur_user}"
  fi
else
  if ! getent group 1000 >/dev/null 2>&1; then
    groupadd -g 1000 "agent"
  fi
  useradd -m -u 1000 -g 1000 -s /bin/bash "agent"
fi
cur_grp="$(id -gn 1000 2>/dev/null || true)"
if [[ -n "${cur_grp}" && "${cur_grp}" != "agent" ]] && ! getent group "agent" >/dev/null 2>&1; then
  groupmod -n "agent" "${cur_grp}" || true
fi
usermod -s /bin/bash -d "/home/agent" -aG sudo "agent"
mkdir -p /etc/sudoers.d "/home/agent" "/home/agent/.local/bin" "/home/agent/.agbox-skills" "/home/agent/.agbox-rules" "/home/agent/.agbox-agents" "/home/agent/.agbox-profile" "/home/agent/.gemini/antigravity-cli" "/home/agent/.config/opencode" /workspace
chmod 0700 "/home/agent/.agbox-skills" "/home/agent/.agbox-rules" "/home/agent/.agbox-agents" "/home/agent/.agbox-profile" "/home/agent/.gemini" "/home/agent/.gemini/antigravity-cli" "/home/agent/.config" "/home/agent/.config/opencode"
if [[ ! -e /home/agent/.gemini/antigravity-cli/settings.json ]]; then
  cat <<'EOF' > /home/agent/.gemini/antigravity-cli/settings.json
{
  "allowNonWorkspaceAccess": true,
  "queuedMessages": "send-immediately",
  "toolPermission": "always-proceed",
  "trustedWorkspaces": [
    "/workspace"
  ]
}
EOF
  chmod 0600 /home/agent/.gemini/antigravity-cli/settings.json
fi
if [[ ! -e /home/agent/.config/opencode/opencode.json ]]; then
  cat <<'EOF' > /home/agent/.config/opencode/opencode.json
{
  "$schema": "https://opencode.ai/config.json",
  "permission": "allow"
}
EOF
  chmod 0600 /home/agent/.config/opencode/opencode.json
fi
printf "%s ALL=(ALL:ALL) NOPASSWD: ALL\n" "agent" > /etc/sudoers.d/agent
chmod 0440 /etc/sudoers.d/agent
if [[ -f /root/.local/bin/agy ]]; then
  install -m 0755 -o 1000 -g 1000 /root/.local/bin/agy /home/agent/.local/bin/agy
  ln -sf /home/agent/.local/bin/agy /usr/local/bin/agy
  rm -f /root/.local/bin/agy
fi
chown -R 1000:1000 "/home/agent" /workspace
su - "agent" -c "sudo -n true"
`
}

// SandboxInfo represents a single row from `msb ls`.
type SandboxInfo struct {
	Name    string
	Running bool
	RawLine string
}

// ParseSandboxList parses the tabular output of `msb ls`.
func ParseSandboxList(out string) []SandboxInfo {
	var result []SandboxInfo
	for _, raw := range strings.Split(out, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "NAME") || strings.HasPrefix(line, "-") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		lower := strings.ToLower(line)
		running := strings.Contains(lower, "running")
		result = append(result, SandboxInfo{
			Name:    fields[0],
			Running: running,
			RawLine: line,
		})
	}
	return result
}

// FindSandbox looks up a sandbox by name in a parsed list.
func FindSandbox(list []SandboxInfo, name string) (SandboxInfo, bool) {
	for _, sb := range list {
		if sb.Name == name {
			return sb, true
		}
	}
	return SandboxInfo{}, false
}

// ParseSnapshotList extracts snapshot identifiers (`<group>:<tag>`) from `msb snap ls`.
func ParseSnapshotList(out string) []string {
	var snaps []string
	for _, raw := range strings.Split(out, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "NAME") || strings.HasPrefix(line, "SNAPSHOT") || strings.HasPrefix(line, "-") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) > 0 && strings.Contains(fields[0], ":") {
			snaps = append(snaps, fields[0])
		}
	}
	return snaps
}

var versionSuffixRe = regexp.MustCompile(`^v(\d+)$`)

// NextSnapshotVersion inspects existing snapshot identifiers (e.g. `agbox:v1`,
// `agbox:v2`) and returns the next integer version number for group.
func NextSnapshotVersion(snaps []string, group string) int {
	prefix := group + ":"
	maxVer := 0
	for _, s := range snaps {
		if !strings.HasPrefix(s, prefix) {
			continue
		}
		tag := strings.TrimPrefix(s, prefix)
		m := versionSuffixRe.FindStringSubmatch(tag)
		if len(m) == 2 {
			if n, err := strconv.Atoi(m[1]); err == nil && n > maxVer {
				maxVer = n
			}
		}
	}
	return maxVer + 1
}

// CommandRequest describes a single invocation of the `msb` binary.
type CommandRequest struct {
	Args        []string
	Stdin       io.Reader
	Stdout      io.Writer
	Stderr      io.Writer
	Interactive bool // When true, connect nil Stdin/Stdout/Stderr directly to os.Stdin/os.Stdout/os.Stderr
}

// CommandResult captures the outcome of a non-interactive `msb` command.
type CommandResult struct {
	Stdout   string
	Stderr   string
	ExitCode int
}

// Runner abstracts execution of the `msb` binary so callers can be unit-tested
// without launching real Firecracker/libkrun microVMs.
type Runner interface {
	Run(ctx context.Context, req CommandRequest) (CommandResult, error)
}

// ExecRunner implements Runner using os/exec against the host `msb` binary.
type ExecRunner struct {
	BinaryPath string
}

// ResolveBinary locates the msb executable from explicit, PATH, ~/.local/bin, or /usr/local/bin.
func ResolveBinary(explicit string) (string, error) {
	home, _ := os.UserHomeDir()
	return resolveBinaryWith(explicit, exec.LookPath, home, []string{"/usr/local/bin/msb"})
}

func resolveBinaryWith(explicit string, lookPath func(string) (string, error), home string, extraPaths []string) (string, error) {
	if explicit != "" {
		if st, err := os.Stat(explicit); err == nil && !st.IsDir() {
			return explicit, nil
		}
		return "", fmt.Errorf("msb binary not found at %q", explicit)
	}
	if lookPath != nil {
		if p, err := lookPath("msb"); err == nil {
			return p, nil
		}
	}
	if home != "" {
		fallback := filepath.Join(home, ".local", "bin", "msb")
		if st, err := os.Stat(fallback); err == nil && !st.IsDir() {
			return fallback, nil
		}
	}
	for _, candidate := range extraPaths {
		if candidate != "" {
			if st, err := os.Stat(candidate); err == nil && !st.IsDir() {
				return candidate, nil
			}
		}
	}
	return "", errors.New("msb binary not found on PATH or ~/.local/bin/msb (run install.sh or install microsandbox)")
}

// NewExecRunner locates the `msb` binary and returns an ExecRunner.
func NewExecRunner(explicit string) (*ExecRunner, error) {
	bin, err := ResolveBinary(explicit)
	if err != nil {
		return nil, err
	}
	return &ExecRunner{BinaryPath: bin}, nil
}

// Run executes `msb` with the given arguments and I/O streams.
func (r *ExecRunner) Run(ctx context.Context, req CommandRequest) (CommandResult, error) {
	cmd := exec.CommandContext(ctx, r.BinaryPath, req.Args...)

	var outBuf, errBuf bytes.Buffer
	if req.Interactive {
		if req.Stdin != nil {
			cmd.Stdin = req.Stdin
		} else {
			cmd.Stdin = os.Stdin
		}
		if req.Stdout != nil {
			cmd.Stdout = req.Stdout
		} else {
			cmd.Stdout = os.Stdout
		}
		if req.Stderr != nil {
			cmd.Stderr = req.Stderr
		} else {
			cmd.Stderr = os.Stderr
		}
	} else {
		cmd.Stdin = req.Stdin
		if req.Stdout != nil {
			cmd.Stdout = req.Stdout
		} else {
			cmd.Stdout = &outBuf
		}
		if req.Stderr != nil {
			cmd.Stderr = req.Stderr
		} else {
			cmd.Stderr = &errBuf
		}
	}

	err := cmd.Run()
	res := CommandResult{
		Stdout:   outBuf.String(),
		Stderr:   errBuf.String(),
		ExitCode: 0,
	}
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			res.ExitCode = exitErr.ExitCode()
		} else {
			res.ExitCode = 1
		}
		return res, err
	}
	return res, nil
}

// SnapshotExists reports whether target (`<group>:<tag>`) is present in `msb snap ls`.
func SnapshotExists(ctx context.Context, runner Runner, target string) (bool, error) {
	res, err := runner.Run(ctx, CommandRequest{Args: []string{"snap", "ls"}})
	if err != nil {
		return false, fmt.Errorf("msb snap ls: %w (%s)", err, strings.TrimSpace(res.Stderr))
	}
	snaps := ParseSnapshotList(res.Stdout)
	return slices.Contains(snaps, target), nil
}

// BuildVolumeCreateDiskArgs constructs the CLI argument list for creating an ext4 disk volume.
func BuildVolumeCreateDiskArgs(name, size string) ([]string, error) {
	if name == "" {
		return nil, errors.New("volume name is required")
	}
	if size == "" {
		return nil, errors.New("volume size is required")
	}
	return []string{"volume", "create", name, "--kind", "disk", "--size", size}, nil
}

// ParseVolumeList extracts named volume identifiers from `msb volume ls`.
func ParseVolumeList(out string) []string {
	var vols []string
	for _, raw := range strings.Split(out, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "NAME") || strings.HasPrefix(line, "VOLUME") || strings.HasPrefix(line, "-") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) > 0 {
			vols = appendUnique(vols, fields[0])
		}
	}
	return vols
}

// VolumeExists reports whether target is present in `msb volume ls`.
func VolumeExists(ctx context.Context, runner Runner, target string) (bool, error) {
	res, err := runner.Run(ctx, CommandRequest{Args: []string{"volume", "ls"}})
	if err != nil {
		return false, fmt.Errorf("msb volume ls: %w (%s)", err, strings.TrimSpace(res.Stderr))
	}
	return slices.Contains(ParseVolumeList(res.Stdout), target), nil
}
