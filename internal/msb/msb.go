// Package msb builds CLI arguments, parses output, and runs commands for microsandbox (msb).
//
// Security properties:
//   - buildNetArgs defaults to default-deny egress (--net-default deny).
//   - buildNetArgs places host, loopback, private, link-local, multicast, and metadata
//     denies before allow rules under msb first-match-wins evaluation.
//   - validateNetRuleToken rejects whitespace, control characters, and malformed rules.
//   - FormatEnvExports and ShellQuote quote secrets for stdin delivery.
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

	"agbox/internal/config"
)

// GuestSkillsMount is the read-only virtiofs mountpoint for host global skills.
const GuestSkillsMount = "/home/agent/.agbox-skills"

// GuestRulesMount is the read-only virtiofs mountpoint for host global rules.
const GuestRulesMount = "/home/agent/.agbox-rules"

// GuestAgentsMount is the read-only virtiofs mountpoint for cached agent binaries.
const GuestAgentsMount = "/home/agent/.agbox-agents"

// GuestProfileMount is the ext4 disk mountpoint for conversation profiles.
const GuestProfileMount = "/home/agent/.agbox-profile"

// GuestWorkspace is the guest directory where agbox mounts host shares.
const GuestWorkspace = "/workspace"

// DefaultPassthroughEnvVars lists host environment variables forwarded when non-empty.
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

var nonDNSBlockHostRules = []string{
	"deny@host:tcp:0-52",
	"deny@host:tcp:54-65535",
	"deny@host:udp:0-52",
	"deny@host:udp:54-65535",
	"deny@host:icmpv4",
	"deny@host:icmpv6",
}

func buildNetArgs(noNet bool, specs []string) ([]string, error) {
	if noNet {
		for _, raw := range specs {
			if strings.TrimSpace(raw) != "" {
				return nil, errors.New("conflicting network options: cannot combine --no-net with --net rules")
			}
		}
		return []string{"--no-net"}, nil
	}
	if len(specs) == 0 {
		specs = []string{"public"}
	}

	sawNone := false
	sawNonNone := false
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
	var groupScopedAllows []string
	var userAllows []string

	for _, rawSpec := range specs {
		s := strings.TrimSpace(rawSpec)
		switch s {
		case "", "public", "public-only":
			sawNonNone = true
			hasRestrictiveProfile = true
			hasGroupAllow = true
			userAllows = appendUnique(userAllows, "allow@public")
		case "none", "deny":
			sawNone = true
		case "private":
			sawNonNone = true
			hasRestrictiveProfile = true
			hasGroupAllow = true
			allowPrivate = true
			userAllows = appendUnique(userAllows, "allow@public")
			userAllows = appendUnique(userAllows, "allow@private")
		case "host":
			sawNonNone = true
			hasRestrictiveProfile = true
			hasGroupAllow = true
			allowHost = true
			userAllows = appendUnique(userAllows, "allow@public")
		case "all", "allow":
			sawNonNone = true
			allowAll = true
		default:
			sawNonNone = true
			if !strings.Contains(s, "@") {
				return nil, fmt.Errorf("unsupported --net value %q (use: public, none, private, host, all, or a rule like 'allow@example.com:tcp:443')", rawSpec)
			}
			for _, tok := range strings.Split(s, ",") {
				trimmed := strings.TrimSpace(tok)
				rule, action, dir, right, err := parseAndNormalizeNetRule(trimmed)
				if err != nil {
					return nil, err
				}
				if action == "deny" {
					userDenies = appendUnique(userDenies, rule)
					if dir == "egress" && isFullDNSRight(right) {
						denyDNS = true
					}
					continue
				}
				hasRestrictiveProfile = true
				if dir == "ingress" {
					userAllows = appendUnique(userAllows, rule)
					continue
				}
				targetGroup, _, hasPortScope := strings.Cut(right, ":")
				switch {
				case right == "any" || right == "public":
					hasGroupAllow = true
					userAllows = appendUnique(userAllows, rule)
				case hasPortScope && (targetGroup == "any" || targetGroup == "public"):
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
				case targetGroup == "host" && hasPortScope:
					hostScopedAllows = appendUnique(hostScopedAllows, rule)
				case hasPortScope && (targetGroup == "private" || targetGroup == "loopback" || targetGroup == "link-local" || targetGroup == "multicast" || targetGroup == "meta"):
					groupScopedAllows = appendUnique(groupScopedAllows, rule)
				default:
					userAllows = appendUnique(userAllows, rule)
				}
			}
		}
	}

	if sawNone {
		if sawNonNone {
			return nil, errors.New("conflicting network options: cannot combine --net none with other network rules")
		}
		return []string{"--no-net"}, nil
	}
	if allowAll {
		if hasRestrictiveProfile {
			return nil, errors.New("conflicting network options: cannot combine --net all with restrictive profiles or allow rules")
		}
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
			// Block non-53 host ports before domain allows so DNS resolves without opening arbitrary ports.
			for _, r := range nonDNSBlockHostRules {
				args = append(args, "--net-rule", r)
			}
			trailingDenyHost = true
		}
	}

	for _, r := range groupScopedAllows {
		args = append(args, "--net-rule", r)
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
	if !allowPrivate {
		denies = appendUnique(denies, "deny@100.64.0.0/10")
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
	denies = appendUnique(denies, "deny@[::/128]")
	denies = appendUnique(denies, "deny@[::ffff:0:0/96]")
	denies = appendUnique(denies, "deny@[64:ff9b::/96]")
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
			return "", "", "", "", fmt.Errorf("invalid --net-rule %q: omit whitespace and control characters", raw)
		}
	}
	leftRaw, rightRaw, ok := strings.Cut(raw, "@")
	if !ok {
		return "", "", "", "", fmt.Errorf("invalid --net-rule %q: use <action>[:<direction>]@<target> syntax", raw)
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

	// Map the target name "metadata" to the msb group keyword "meta".
	// Keep hostnames such as metadata.google.internal and domain=metadata unchanged.
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
		if protoRaw == "icmpv4" || protoRaw == "icmpv6" {
			return "", "", "", "", fmt.Errorf("invalid --net-rule %q: %s does not accept ports", raw, protoRaw)
		}
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
		return fmt.Errorf("invalid --net-rule %q: dns target supports only egress rules", fullToken)
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
	if inner == "" {
		return "", "", fmt.Errorf("invalid --net-rule %q: empty IPv6 target in brackets", fullToken)
	}
	afterClose := afterOpen[closeIdx+1:]

	if strings.Contains(inner, "/") {
		pfx, pfxErr := netip.ParsePrefix(inner)
		if pfxErr != nil {
			return "", "", fmt.Errorf("invalid --net-rule %q: invalid CIDR %q", fullToken, inner)
		}
		if !pfx.Addr().Is6() {
			return "", "", fmt.Errorf("invalid --net-rule %q: bracketed target %q must be IPv6", fullToken, inner)
		}
		if pfx.Masked() != pfx {
			return "", "", fmt.Errorf("invalid --net-rule %q: non-canonical IPv6 CIDR %q", fullToken, inner)
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
		return "", "", fmt.Errorf("invalid --net-rule %q: empty protocol after ':'", fullToken)
	}
	protoRaw = suffixParts[0]
	if len(suffixParts) == 2 {
		if suffixParts[1] == "" {
			return "", "", fmt.Errorf("invalid --net-rule %q: empty port after ':'", fullToken)
		}
		portsRaw = suffixParts[1]
	}
	return protoRaw, portsRaw, nil
}

func parseUnbracketedNetTarget(right, fullToken string) (protoRaw, portsRaw string, err error) {
	if strings.Contains(right, "::") {
		return "", "", fmt.Errorf("invalid --net-rule %q: wrap IPv6 targets in square brackets", fullToken)
	}
	parts := strings.SplitN(right, ":", 4)
	if len(parts) == 4 {
		return "", "", fmt.Errorf("invalid --net-rule %q: trailing fields or unbracketed IPv6 address", fullToken)
	}
	target := parts[0]
	if len(parts) >= 2 {
		protoRaw = parts[1]
		if looksLikePortSpec(protoRaw) {
			return "", "", fmt.Errorf("invalid --net-rule %q: port %q is in protocol position, use <target>:<proto>:<ports>", fullToken, protoRaw)
		}
		if protoRaw == "" {
			return "", "", fmt.Errorf("invalid --net-rule %q: empty protocol after ':'", fullToken)
		}
	}
	if len(parts) == 3 {
		portsRaw = parts[2]
		if portsRaw == "" {
			return "", "", fmt.Errorf("invalid --net-rule %q: empty port after ':'", fullToken)
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
			return fmt.Errorf("invalid --net-rule %q: wrap IPv6 CIDR %s in square brackets", fullToken, target)
		}
		return nil
	}
	if addr, err := netip.ParseAddr(target); err == nil {
		if addr.Is6() || addr.Zone() != "" {
			return fmt.Errorf("invalid --net-rule %q: wrap IPv6 address %s in square brackets", fullToken, target)
		}
		return nil
	}
	if strings.Contains(target, ".") {
		if !isValidNetDomain(target, true) {
			return fmt.Errorf("invalid --net-rule %q: invalid domain or IPv4 address %q", fullToken, target)
		}
		return nil
	}
	return fmt.Errorf("invalid --net-rule %q: %q is ambiguous (use domain=%s or a group keyword)", fullToken, target, target)
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
	if len(labels) >= 2 && isAllDigits(labels[len(labels)-1]) {
		return false
	}
	return true
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
	if !isAllDigits(s) {
		return false
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
			return fmt.Errorf("invalid --net-rule %q: %s supports only egress rules", fullToken, proto)
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

// ShellQuote wraps s in POSIX single quotes and escapes embedded single quotes
// as the 4-character sequence close-quote, backslash, quote, open-quote.
// The quoted token prevents shell expansion, globbing, and word splitting.
func ShellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// FormatEnvExports builds the shell script for GuestKeysFile from non-empty keys.
// It uses lookup to read host values and returns the script and export count.
func FormatEnvExports(lookup func(string) string, keys []string) (string, int) {
	var b strings.Builder
	b.WriteString("# Generated by agbox inside the guest sandbox.\n")
	count := 0
	for _, k := range keys {
		if k == "" || lookup == nil {
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

// VolumeSpec describes one host-to-guest virtiofs mount.
type VolumeSpec struct {
	HostPath  string
	GuestPath string
	ReadOnly  bool
	StatVirt  string
	HostPerms string
}

func (v VolumeSpec) validate() error {
	if hasInvalidMountPath(v.HostPath) {
		return fmt.Errorf("invalid volume host path %q: use an absolute path without colons, commas, or control characters", v.HostPath)
	}
	if hasInvalidMountPath(v.GuestPath) {
		return fmt.Errorf("invalid volume guest path %q: use an absolute path without colons, commas, or control characters", v.GuestPath)
	}
	return nil
}

func (v VolumeSpec) formatFlag() string {
	mode := "rw"
	if v.ReadOnly {
		mode = "ro"
	}
	statVirt := v.StatVirt
	if statVirt == "" {
		if v.ReadOnly {
			statVirt = "relaxed"
		} else {
			statVirt = "off"
		}
	}
	opts := []string{mode, "stat-virt=" + statVirt}
	if v.HostPerms != "" && statVirt != "off" {
		opts = append(opts, "host-perms="+v.HostPerms)
	}
	if statVirt != "off" {
		opts = append(opts, fmt.Sprintf("uid=%d", config.GuestUID), fmt.Sprintf("gid=%d", config.GuestGID))
	}
	return fmt.Sprintf("%s:%s:%s", v.HostPath, v.GuestPath, strings.Join(opts, ","))
}

// CreateOpts holds parameters for msb create.
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

// BuildCreateArgs builds the CLI argument list for msb create.
func BuildCreateArgs(opts CreateOpts) ([]string, error) {
	if opts.Image == "" {
		return nil, errors.New("specify an image")
	}
	if opts.Name == "" {
		return nil, errors.New("specify a sandbox name")
	}
	cpus := opts.CPUs
	if cpus == "" {
		cpus = config.DefaultCPUs
	}
	mem := opts.Memory
	if mem == "" {
		mem = config.DefaultMemory
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
	netArgs, err := buildNetArgs(opts.NoNet, opts.NetSpecs)
	if err != nil {
		return nil, err
	}
	args = append(args, netArgs...)
	return args, nil
}

// DiskMountSpec describes a raw or qcow2 disk image attached via msb --mount-disk.
type DiskMountSpec struct {
	HostPath  string
	GuestPath string
	ReadOnly  bool
	Format    string
	FSType    string
}

func hasInvalidMountPath(p string) bool {
	if p == "" || !strings.HasPrefix(p, "/") {
		return true
	}
	if strings.ContainsAny(p, ":,") {
		return true
	}
	return hasControlChars(p)
}

func hasControlChars(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] == 0x7f {
			return true
		}
	}
	return false
}

func (d DiskMountSpec) formatFlag() (string, error) {
	if hasInvalidMountPath(d.HostPath) {
		return "", fmt.Errorf("invalid disk mount host path %q: use an absolute path without colons, commas, or control characters", d.HostPath)
	}
	if hasInvalidMountPath(d.GuestPath) {
		return "", fmt.Errorf("invalid disk mount guest path %q: use an absolute path without colons, commas, or control characters", d.GuestPath)
	}
	switch d.Format {
	case "", "raw", "qcow2":
	default:
		return "", fmt.Errorf("invalid disk mount format %q: expected raw or qcow2", d.Format)
	}
	switch d.FSType {
	case "", "ext4", "xfs":
	default:
		return "", fmt.Errorf("invalid disk mount filesystem type %q: expected ext4 or xfs", d.FSType)
	}
	mode := "rw"
	if d.ReadOnly {
		mode = "ro"
	}
	format := d.Format
	if format == "" {
		format = "raw"
	}
	fsType := d.FSType
	if fsType == "" {
		fsType = "ext4"
	}
	return fmt.Sprintf("%s:%s:%s,format=%s,fstype=%s", d.HostPath, d.GuestPath, mode, format, fsType), nil
}

// RestoreOpts holds parameters for msb snap restore.
type RestoreOpts struct {
	Snapshot   string
	Name       string
	User       string
	CPUs       string
	Memory     string
	DiskMounts []DiskMountSpec
	Volumes    []VolumeSpec
	Ports      []string
	NoNet      bool
	NetSpecs   []string
}

// BuildRestoreArgs builds the CLI argument list for msb snap restore.
func BuildRestoreArgs(opts RestoreOpts) ([]string, error) {
	if opts.Snapshot == "" {
		return nil, errors.New("specify a snapshot reference")
	}
	if opts.Name == "" {
		return nil, errors.New("specify a sandbox name")
	}
	user := opts.User
	if user == "" {
		user = config.GuestUser
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
	for _, v := range opts.Volumes {
		if err := v.validate(); err != nil {
			return nil, err
		}
		args = append(args, "-v", v.formatFlag())
	}
	for _, dm := range opts.DiskMounts {
		flagVal, err := dm.formatFlag()
		if err != nil {
			return nil, err
		}
		args = append(args, "--mount-disk", flagVal)
	}
	ingressRules := make([]string, 0, len(opts.Ports))
	for _, p := range opts.Ports {
		rule, err := ingressRuleForPublishedPort(p)
		if err != nil {
			return nil, err
		}
		args = append(args, "-p", p)
		ingressRules = append(ingressRules, rule)
	}
	netArgs, err := buildNetArgs(opts.NoNet, opts.NetSpecs)
	if err != nil {
		return nil, err
	}
	args = append(args, netArgs...)
	if len(netArgs) >= 2 && netArgs[0] == "--net-default" && netArgs[1] == "deny" {
		for _, rule := range ingressRules {
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
			return "", fmt.Errorf("invalid published port spec %q: omit whitespace and control characters", spec)
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
		addr, err := netip.ParseAddr(bindIP)
		if err != nil || addr.Zone() != "" {
			return "", fmt.Errorf("invalid published port spec %q: invalid bind IP %q", spec, bindIP)
		}
		if addr != netip.IPv6Loopback() {
			return "", fmt.Errorf("invalid published port spec %q: bind IP %q must be 127.0.0.1 or [::1]", spec, bindIP)
		}
		after := base[closeIdx+1:]
		if !strings.HasPrefix(after, ":") {
			return "", fmt.Errorf("invalid published port spec %q: expected :hostPort:guestPort after ']'", spec)
		}
		parts := strings.Split(after[1:], ":")
		if len(parts) != 2 {
			return "", fmt.Errorf("invalid published port spec %q: expected [::1]:hostPort:guestPort", spec)
		}
		hostStr, guestStr = parts[0], parts[1]
	} else {
		parts := strings.Split(base, ":")
		if len(parts) != 3 {
			return "", fmt.Errorf("invalid published port spec %q: expected 127.0.0.1:hostPort:guestPort[/proto]", spec)
		}
		if parts[0] != "127.0.0.1" {
			return "", fmt.Errorf("invalid published port spec %q: bind IP %q must be 127.0.0.1 or [::1]", spec, parts[0])
		}
		hostStr, guestStr = parts[1], parts[2]
	}

	if !isValidPort1To65535(hostStr) || !isValidPort1To65535(guestStr) {
		return "", fmt.Errorf("invalid published port spec %q: host and guest ports must be in 1..65535", spec)
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

// ExecCmdOpts holds parameters for msb exec.
type ExecCmdOpts struct {
	Sandbox  string
	Workdir  string
	User     string
	Detached bool
	TTY      bool
	NoTTY    bool
	Stream   bool
	NoStdin  bool
	Env      []string
	Command  []string
}

// BuildExecArgs builds the CLI argument list for msb exec.
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
	if !opts.TTY && opts.NoStdin {
		args = append(args, "--no-stdin")
	}
	if opts.Workdir != "" {
		args = append(args, "-w", opts.Workdir)
	}
	user := opts.User
	if user == "" {
		user = config.GuestUser
	}
	args = append(args, "-u", user)
	for _, kv := range opts.Env {
		args = append(args, "-e", kv)
	}
	args = append(args, opts.Sandbox, "--")
	args = append(args, opts.Command...)
	return args
}

// GuestEnvFlags returns environment variables for guest msb exec calls as user agent.
// SSH_CONNECTION=1 tells agy to print its remote OAuth URL and prompt for a code.
func GuestEnvFlags() []string {
	return []string{
		"HOME=" + config.GuestHome,
		"USER=" + config.GuestUser,
		"LOGNAME=" + config.GuestUser,
		"PATH=" + guestDefaultPath,
		"SSH_CONNECTION=1",
		"PYTHONDONTWRITEBYTECODE=1",
	}
}

// KeyLoaderPrefix sources the guest profile script and GuestKeysFile in POSIX sh when present.
// Checking test -f prevents dash from aborting a non-interactive shell when a file is absent.
const KeyLoaderPrefix = "test -f /etc/profile.d/agbox-path.sh && . /etc/profile.d/agbox-path.sh; test -f " + config.GuestKeysFile + " && . " + config.GuestKeysFile + ";"

// ProvisionGuestUserScript returns a bash script that prepares user agent (1000:1000) with sudo.
// It handles node:24-bookworm-slim (UID 1000 is node) and debian:bookworm-slim.
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
if [[ -x /home/agent/.local/bin/mdformat ]]; then
  ln -sf /home/agent/.local/bin/mdformat /usr/local/bin/mdformat
fi
` + ensureGuestPathProfileSnippet() + `chown -R 1000:1000 "/home/agent" /workspace
su - "agent" -c "sudo -n true"
`
}

// ProvisionAgyRetryHookScript installs the Antigravity high-traffic Stop retry hook.
// It creates the script and hooks.json only when absent so user files stay intact.
func ProvisionAgyRetryHookScript() string {
	return `set -euo pipefail
mkdir -p /home/agent/.gemini/config/scripts
chmod 0700 /home/agent/.gemini /home/agent/.gemini/config
chmod 0755 /home/agent/.gemini/config/scripts
if [[ ! -e /home/agent/.gemini/config/scripts/retry-high-traffic.py ]]; then
  cat <<'EOF' > /home/agent/.gemini/config/scripts/retry-high-traffic.py
#!/usr/bin/env python3
import json
import sys
import time

MAX_RETRIES = 5
SLEEP_SECONDS = 60

payload = json.load(sys.stdin)
reason = payload.get("terminationReason", "")
error = (payload.get("error") or "").lower()
execution_num = int(payload.get("executionNum", 0))

is_high_traffic = any(
    token in error
    for token in ("high traffic", "503", "unavailable", "capacity")
)

if reason == "ERROR" and is_high_traffic and execution_num < MAX_RETRIES:
    time.sleep(SLEEP_SECONDS)
    print(json.dumps({
        "decision": "continue",
        "reason": "The server returned a temporary high-traffic error. Continue where you left off."
    }))
else:
    print(json.dumps({"decision": "stop"}))
EOF
  chmod 0755 /home/agent/.gemini/config/scripts/retry-high-traffic.py
fi
if [[ ! -e /home/agent/.gemini/config/hooks.json ]]; then
  cat <<'EOF' > /home/agent/.gemini/config/hooks.json
{
  "retry-high-traffic": {
    "Stop": [
      {
        "type": "command",
        "command": "/home/agent/.gemini/config/scripts/retry-high-traffic.py",
        "timeout": 120
      }
    ]
  }
}
EOF
  chmod 0600 /home/agent/.gemini/config/hooks.json
fi
chown -R 1000:1000 /home/agent/.gemini/config/scripts /home/agent/.gemini/config/hooks.json
`
}

// SandboxInfo represents one row from msb ls.
type SandboxInfo struct {
	Name    string
	Running bool
	RawLine string
}

// ParseSandboxList parses the tabular output of msb ls.
func ParseSandboxList(out string) []SandboxInfo {
	clean := ansiCSIPattern.ReplaceAllString(out, "")
	var result []SandboxInfo
	statusCol := -1
	for _, raw := range strings.Split(clean, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "-") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if strings.EqualFold(fields[0], "NAME") {
			statusCol = -1
			for i, h := range fields {
				if strings.EqualFold(h, "STATUS") || strings.EqualFold(h, "STATE") {
					statusCol = i
					break
				}
			}
			continue
		}
		var running bool
		if statusCol > 0 {
			running = len(fields) > statusCol && strings.EqualFold(fields[statusCol], "running")
		} else {
			for i := 1; i < len(fields); i++ {
				if strings.EqualFold(fields[i], "running") {
					running = true
					break
				}
			}
		}
		result = append(result, SandboxInfo{
			Name:    fields[0],
			Running: running,
			RawLine: line,
		})
	}
	return result
}

// FindSandbox finds a sandbox by name in list.
func FindSandbox(list []SandboxInfo, name string) (SandboxInfo, bool) {
	for _, sb := range list {
		if sb.Name == name {
			return sb, true
		}
	}
	return SandboxInfo{}, false
}

// ParseSnapshotList extracts snapshot references (<group>:<tag>) from msb snap ls.
func ParseSnapshotList(out string) []string {
	clean := ansiCSIPattern.ReplaceAllString(out, "")
	var snaps []string
	for _, raw := range strings.Split(clean, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "-") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if strings.EqualFold(fields[0], "NAME") || strings.EqualFold(fields[0], "SNAPSHOT") {
			continue
		}
		if strings.Contains(fields[0], ":") {
			snaps = append(snaps, fields[0])
		}
	}
	return snaps
}

// CommandRequest describes one invocation of the msb binary.
type CommandRequest struct {
	Args        []string
	Stdin       io.Reader
	Stdout      io.Writer
	Stderr      io.Writer
	Interactive bool
}

// CommandResult captures the output and exit code of an msb command.
type CommandResult struct {
	Stdout   string
	Stderr   string
	ExitCode int
}

// Runner executes the msb binary so unit tests run without libkrun microVMs.
type Runner interface {
	Run(ctx context.Context, req CommandRequest) (CommandResult, error)
}

// ExecRunner implements Runner with os/exec against the host msb binary.
type ExecRunner struct {
	BinaryPath string
}

func resolveBinary(explicit string) (string, error) {
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
	return "", errors.New("cannot find msb on PATH, ~/.local/bin/msb, or /usr/local/bin/msb (run install.sh)")
}

// NewExecRunner locates the msb binary and returns an ExecRunner.
func NewExecRunner(explicit string) (*ExecRunner, error) {
	bin, err := resolveBinary(explicit)
	if err != nil {
		return nil, err
	}
	return &ExecRunner{BinaryPath: bin}, nil
}

// Run executes msb with req.Args and streams or captures I/O.
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

// SnapshotExists reports whether target (<group>:<tag>) appears in msb snap ls.
func SnapshotExists(ctx context.Context, runner Runner, target string) (bool, error) {
	res, err := runner.Run(ctx, CommandRequest{Args: []string{"snap", "ls"}})
	if err != nil {
		return false, fmt.Errorf("msb snap ls: %w (%s)", err, strings.TrimSpace(res.Stderr))
	}
	snaps := ParseSnapshotList(res.Stdout)
	return slices.Contains(snaps, target), nil
}

// BuildVolumeCreateDiskArgs builds the CLI argument list to create an ext4 disk volume.
func BuildVolumeCreateDiskArgs(name, size string) ([]string, error) {
	if name == "" {
		return nil, errors.New("specify a volume name")
	}
	if size == "" {
		return nil, errors.New("specify a volume size")
	}
	return []string{"volume", "create", name, "--kind", "disk", "--size", size}, nil
}

// ParseVolumeList extracts named volume identifiers from msb volume ls.
func ParseVolumeList(out string) []string {
	clean := ansiCSIPattern.ReplaceAllString(out, "")
	var vols []string
	for _, raw := range strings.Split(clean, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "-") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if strings.EqualFold(fields[0], "NAME") || strings.EqualFold(fields[0], "VOLUME") {
			continue
		}
		vols = appendUnique(vols, fields[0])
	}
	return vols
}

// VolumeExists reports whether target appears in msb volume ls.
func VolumeExists(ctx context.Context, runner Runner, target string) (bool, error) {
	res, err := runner.Run(ctx, CommandRequest{Args: []string{"volume", "ls"}})
	if err != nil {
		return false, fmt.Errorf("msb volume ls: %w (%s)", err, strings.TrimSpace(res.Stderr))
	}
	return slices.Contains(ParseVolumeList(res.Stdout), target), nil
}

var ansiCSIPattern = regexp.MustCompile(`\x1b\[[0-9;?]*[ -/]*[@-~]`)

func parseVolumeInspectPath(out string) string {
	clean := ansiCSIPattern.ReplaceAllString(out, "")
	for _, rawLine := range strings.Split(clean, "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" {
			continue
		}
		var rest string
		switch {
		case strings.HasPrefix(line, "Path:"):
			rest = strings.TrimSpace(strings.TrimPrefix(line, "Path:"))
		case strings.HasPrefix(line, "Path") && len(line) > len("Path") && (line[len("Path")] == ' ' || line[len("Path")] == '\t'):
			rest = strings.TrimSpace(line[len("Path"):])
		default:
			continue
		}
		if strings.HasPrefix(rest, "/") {
			return rest
		}
	}
	return ""
}

// ResolveVolumeDiskPath finds the disk.raw path for volName via msb volume inspect or msbHome.
func ResolveVolumeDiskPath(ctx context.Context, runner Runner, msbHome, volName string) (string, error) {
	if strings.TrimSpace(volName) == "" {
		return "", errors.New("specify a volume name")
	}
	if volName == "." || volName == ".." || filepath.Base(volName) != volName || strings.ContainsAny(volName, "/\\") || hasControlChars(volName) {
		return "", fmt.Errorf("invalid volume name %q: omit path traversal characters", volName)
	}
	var diskPath string
	if runner != nil {
		res, err := runner.Run(ctx, CommandRequest{Args: []string{"volume", "inspect", volName}})
		if err == nil {
			diskPath = parseVolumeInspectPath(res.Stdout)
		}
	}
	if diskPath == "" && msbHome != "" {
		diskPath = filepath.Join(msbHome, "volumes", volName, "disk.raw")
	}
	if hasInvalidMountPath(diskPath) {
		return "", fmt.Errorf("resolved disk path %q for volume %q is invalid or empty", diskPath, volName)
	}
	return diskPath, nil
}
