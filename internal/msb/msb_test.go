package msb

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"agbox/internal/config"
)

func TestTranslateNetSpecAndBuildNetArgs(t *testing.T) {
	publicWant := []string{
		"--net-default", "deny",
		"--net-rule", "allow@dns",
		"--net-rule", "deny@host",
		"--net-rule", "deny@loopback",
		"--net-rule", "deny@private",
		"--net-rule", "deny@link-local",
		"--net-rule", "deny@multicast",
		"--net-rule", "deny@meta",
		"--net-rule", "deny@0.0.0.0/8",
		"--net-rule", "deny@100.64.0.0/10",
		"--net-rule", "deny@100.100.100.200/32",
		"--net-rule", "deny@168.63.129.16/32",
		"--net-rule", "deny@169.254.0.0/16",
		"--net-rule", "deny@240.0.0.0/4",
		"--net-rule", "deny@[::/128]",
		"--net-rule", "deny@[::ffff:0:0/96]",
		"--net-rule", "deny@[64:ff9b::/96]",
		"--net-rule", "deny@[fe80::/10]",
		"--net-rule", "deny@[fd00:ec2::254/128]",
		"--net-rule", "allow@public",
	}
	for _, spec := range []string{"", "public", "public-only", "  public "} {
		got, err := buildNetArgs(false, []string{spec})
		if err != nil {
			t.Fatalf("buildNetArgs(false, []string{%q}) unexpected error: %v", spec, err)
		}
		if !slices.Equal(got, publicWant) {
			t.Errorf("buildNetArgs(false, []string{%q}) = %v, want %v", spec, got, publicWant)
		}
		assertAllNetRuleTokensValid(t, got)
	}

	// Private profile allows RFC1918, CGNAT, and ULA while blocking host, loopback, link-local, multicast, and metadata CIDRs.
	gotPrivate, err := buildNetArgs(false, []string{"private"})
	if err != nil {
		t.Fatalf("buildNetArgs(false, []string{private}): %v", err)
	}
	assertAllNetRuleTokensValid(t, gotPrivate)
	privJoined := strings.Join(gotPrivate, " ")
	for _, mustContain := range []string{
		"--net-default deny",
		"--net-rule allow@dns",
		"--net-rule deny@host",
		"--net-rule deny@loopback",
		"--net-rule deny@link-local",
		"--net-rule deny@multicast",
		"--net-rule deny@meta",
		"--net-rule deny@100.100.100.200/32",
		"--net-rule deny@168.63.129.16/32",
		"--net-rule deny@[::/128]",
		"--net-rule deny@[::ffff:0:0/96]",
		"--net-rule deny@[64:ff9b::/96]",
		"--net-rule deny@[fd00:ec2::254/128]",
		"--net-rule allow@public",
		"--net-rule allow@private",
	} {
		if !strings.Contains(privJoined, mustContain) {
			t.Errorf("buildNetArgs(false, []string{private}) = %q, missing %q", privJoined, mustContain)
		}
	}
	if strings.Index(privJoined, "allow@dns") > strings.Index(privJoined, "deny@host") {
		t.Errorf("expected allow@dns before deny@host in %q", privJoined)
	}
	for _, mustOmit := range []string{"deny@private", "deny@100.64.0.0/10"} {
		if strings.Contains(privJoined, mustOmit) {
			t.Errorf("buildNetArgs(false, []string{private}) should not contain %s: %q", mustOmit, privJoined)
		}
	}

	// Host profile places allow@host before deny@private while blocking loopback, multicast, and meta.
	gotHost, err := buildNetArgs(false, []string{"host"})
	if err != nil {
		t.Fatalf("buildNetArgs(false, []string{host}): %v", err)
	}
	assertAllNetRuleTokensValid(t, gotHost)
	hostJoined := strings.Join(gotHost, " ")
	allowHostIdx := strings.Index(hostJoined, "allow@host")
	denyPrivIdx := strings.Index(hostJoined, "deny@private")
	if allowHostIdx < 0 || denyPrivIdx < 0 || allowHostIdx > denyPrivIdx {
		t.Errorf("expected allow@host before deny@private in %q", hostJoined)
	}

	for _, spec := range []string{"all", "allow"} {
		if got, err := buildNetArgs(false, []string{spec}); err != nil || !slices.Equal(got, []string{"--net-default", "allow"}) {
			t.Errorf("buildNetArgs(false, []string{%q}) = %v, %v", spec, got, err)
		}
	}
	allWithDeny, err := buildNetArgs(false, []string{"all", "deny@evil.com", "deny@evil.com"})
	if err != nil || !slices.Equal(allWithDeny, []string{"--net-default", "allow", "--net-rule", "deny@evil.com"}) {
		t.Errorf("buildNetArgs(all+deny) = %v, %v", allWithDeny, err)
	}

	for _, spec := range []string{"none", "deny"} {
		if got, err := buildNetArgs(false, []string{spec}); err != nil || !slices.Equal(got, []string{"--no-net"}) {
			t.Errorf("buildNetArgs(false, []string{%q}) = %v, %v", spec, got, err)
		}
	}

	// Conflicting network profiles and flags must fail closed.
	if _, err := buildNetArgs(true, []string{"public"}); err == nil {
		t.Error("expected error when combining --no-net with --net public")
	}
	for _, conflictSpecs := range [][]string{
		{"none", "public"},
		{"public", "none"},
		{"deny", "allow@example.com:tcp:443"},
		{"all", "public"},
		{"all", "allow@example.com:tcp:443"},
		{"allow", "allow:ingress@loopback:tcp:3000"},
	} {
		if _, err := buildNetArgs(false, conflictSpecs); err == nil {
			t.Errorf("expected conflict error for specs %v", conflictSpecs)
		}
	}

	// Port-scoped group allows must precede the group deny block under first-match-wins evaluation.
	scopedPriv, err := buildNetArgs(false, []string{"public", "allow@private:tcp:5432", "allow@meta:tcp:80", "allow@loopback:tcp:8080", "allow@link-local:udp:5353", "allow@multicast:udp:1900"})
	if err != nil {
		t.Fatalf("buildNetArgs(scoped group allows): %v", err)
	}
	assertAllNetRuleTokensValid(t, scopedPriv)
	scopedJoined := strings.Join(scopedPriv, " ")
	for _, pair := range [][2]string{
		{"deny@host", "allow@private:tcp:5432"},
		{"allow@private:tcp:5432", "deny@private"},
		{"allow@meta:tcp:80", "deny@meta"},
		{"allow@loopback:tcp:8080", "deny@loopback"},
		{"allow@link-local:udp:5353", "deny@link-local"},
		{"allow@multicast:udp:1900", "deny@multicast"},
	} {
		idxA := strings.Index(scopedJoined, pair[0])
		idxB := strings.Index(scopedJoined, pair[1])
		if idxA < 0 || idxB < 0 || idxA > idxB {
			t.Errorf("expected %q before %q in %q", pair[0], pair[1], scopedJoined)
		}
	}

	// Port-scoped public/any allows keep private and metadata denies ahead of the allow rule and enable DNS.
	scopedPub, err := buildNetArgs(false, []string{"allow@public:tcp:443"})
	if err != nil {
		t.Fatalf("buildNetArgs(false, []string{allow@public:tcp:443}): %v", err)
	}
	scopedPubJoined := strings.Join(scopedPub, " ")
	if !strings.Contains(scopedPubJoined, "allow@dns") || strings.Index(scopedPubJoined, "deny@private") > strings.Index(scopedPubJoined, "allow@public:tcp:443") {
		t.Errorf("unexpected scoped public rule order: %q", scopedPubJoined)
	}

	// Custom DNS rules and host rules suppress default broad allow@dns.
	customDNS, err := buildNetArgs(false, []string{"public", "allow@dns:udp:53"})
	if err != nil {
		t.Fatalf("buildNetArgs(custom allow dns): %v", err)
	}
	if slices.Contains(customDNS, "allow@dns") || !slices.Contains(customDNS, "allow@dns:udp:53") {
		t.Errorf("expected custom dns rule to replace default allow@dns: %v", customDNS)
	}
	denyDNSArgs, err := buildNetArgs(false, []string{"deny@dns", "allow@93.184.216.34/32:tcp:443"})
	if err != nil {
		t.Fatalf("buildNetArgs(deny@dns): %v", err)
	}
	if slices.Contains(denyDNSArgs, "allow@dns") || slices.Contains(denyDNSArgs, "deny@host:tcp:0-52") || !slices.Contains(denyDNSArgs, "deny@host") {
		t.Errorf("unexpected deny@dns output: %v", denyDNSArgs)
	}

	// Explicit bare group allows (loopback, link-local, multicast, any@host, host:tcp:8080).
	explicitGroups, err := buildNetArgs(false, []string{
		"allow:any@host",
		"allow@host:tcp:8080",
		"allow@loopback",
		"allow@link-local",
		"allow@multicast",
		"allow@loopback", // duplicate deduplicated by appendUnique
	})
	if err != nil {
		t.Fatalf("buildNetArgs(explicitGroups): %v", err)
	}
	assertAllNetRuleTokensValid(t, explicitGroups)
	if !slices.Contains(explicitGroups, "allow:any@host") || !slices.Contains(explicitGroups, "allow@host:tcp:8080") {
		t.Errorf("missing host rules in %v", explicitGroups)
	}
	for _, omitted := range []string{"deny@loopback", "deny@link-local", "deny@multicast"} {
		if slices.Contains(explicitGroups, omitted) {
			t.Errorf("expected %s omitted when explicitly allowed: %v", omitted, explicitGroups)
		}
	}

	// Multi-spec buildNetArgs emits --net-default deny once and places user denies before allow@dns and allow@public.
	multiGot, err := buildNetArgs(false, []string{"public", "deny@evil.com", "deny@93.184.216.34/32", "allow@example.com:tcp:443"})
	if err != nil {
		t.Fatalf("buildNetArgs multi-spec: %v", err)
	}
	assertAllNetRuleTokensValid(t, multiGot)
	multiJoined := strings.Join(multiGot, " ")
	if strings.Count(multiJoined, "--net-default") != 1 {
		t.Errorf("expected single --net-default in %q", multiJoined)
	}
	denyEvilIdx := strings.Index(multiJoined, "deny@evil.com")
	allowDNSIdx := strings.Index(multiJoined, "allow@dns")
	denyCustomIdx := strings.Index(multiJoined, "deny@93.184.216.34/32")
	allowPubIdx := strings.Index(multiJoined, "allow@public")
	if denyEvilIdx < 0 || allowDNSIdx < 0 || denyEvilIdx > allowDNSIdx {
		t.Errorf("expected deny@evil.com before allow@dns in %q", multiJoined)
	}
	if denyCustomIdx < 0 || allowPubIdx < 0 || denyCustomIdx > allowPubIdx {
		t.Errorf("expected custom deny@ rule before allow@public in %q", multiJoined)
	}

	// Narrow custom domain rules omit allow@dns, block non-53 host traffic before user allows, and end with deny@host.
	narrowGot, err := buildNetArgs(false, []string{"allow@api.anthropic.com:tcp:443"})
	if err != nil {
		t.Fatalf("buildNetArgs(false, []string{narrow}): %v", err)
	}
	assertAllNetRuleTokensValid(t, narrowGot)
	narrowJoined := strings.Join(narrowGot, " ")
	if strings.Contains(narrowJoined, "allow@dns") {
		t.Errorf("narrow domain rule should not emit broad allow@dns: %q", narrowJoined)
	}
	for _, must := range []string{
		"--net-rule deny@host:tcp:0-52",
		"--net-rule deny@host:tcp:54-65535",
		"--net-rule deny@host:udp:0-52",
		"--net-rule deny@host:udp:54-65535",
		"--net-rule deny@host:icmpv4",
		"--net-rule deny@host:icmpv6",
		"--net-rule deny@meta",
		"--net-rule allow@api.anthropic.com:tcp:443",
	} {
		if !strings.Contains(narrowJoined, must) {
			t.Errorf("narrow rule args %q missing %q", narrowJoined, must)
		}
	}
	if narrowGot[len(narrowGot)-2] != "--net-rule" || narrowGot[len(narrowGot)-1] != "deny@host" {
		t.Errorf("narrow rule args should end with --net-rule deny@host, got %v", narrowGot)
	}

	// allow@metadata and deny@metadata normalize to meta, while metadata.example.com stays a domain.
	metaAliasGot, err := buildNetArgs(false, []string{"deny@metadata", "deny@metadata:tcp:80", "allow@metadata.example.com:tcp:443", "allow@domain=intranet:tcp:8080", "allow@*.github.com:tcp:443", "allow@suffix=openai.com:tcp:443"})
	if err != nil {
		t.Fatalf("buildNetArgs metadata alias: %v", err)
	}
	assertAllNetRuleTokensValid(t, metaAliasGot)
	if !slices.Contains(metaAliasGot, "deny@meta") || !slices.Contains(metaAliasGot, "deny@meta:tcp:80") || slices.Contains(metaAliasGot, "deny@metadata") {
		t.Errorf("expected metadata rules to normalize to meta in %v", metaAliasGot)
	}
	if !slices.Contains(metaAliasGot, "allow@metadata.example.com:tcp:443") {
		t.Errorf("expected metadata.example.com domain to be preserved in %v", metaAliasGot)
	}
	allowMetaGot, err := buildNetArgs(false, []string{"allow@metadata"})
	if err != nil {
		t.Fatalf("buildNetArgs(false, []string{allow@metadata}): %v", err)
	}
	assertAllNetRuleTokensValid(t, allowMetaGot)
	if !slices.Contains(allowMetaGot, "allow@meta") || slices.Contains(allowMetaGot, "deny@meta") {
		t.Errorf("expected allow@metadata to permit allow@meta without deny@meta: %v", allowMetaGot)
	}

	// allow:ingress@loopback:tcp:8080 preserves egress deny@loopback.
	ingressGot, err := buildNetArgs(false, []string{"allow:ingress@loopback:tcp:8080"})
	if err != nil {
		t.Fatalf("buildNetArgs(false, []string{ingress}): %v", err)
	}
	assertAllNetRuleTokensValid(t, ingressGot)
	if !slices.Contains(ingressGot, "deny@loopback") || !slices.Contains(ingressGot, "allow:ingress@loopback:tcp:8080") {
		t.Errorf("expected ingress loopback rule to preserve egress deny@loopback: %v", ingressGot)
	}

	v6Args, err := buildNetArgs(false, []string{"allow@[2001:db8::1]:tcp:443", "allow@[2001:db8::/32]:udp:1000-2000", "allow@public:tcp:any"})
	if err != nil {
		t.Fatalf("buildNetArgs(ipv6 host+port): %v", err)
	}
	assertAllNetRuleTokensValid(t, v6Args)
	if !slices.Contains(v6Args, "allow@[2001:db8::1]:tcp:443") {
		t.Errorf("expected bracketed ipv6 rule in %v", v6Args)
	}

	for _, tc := range []struct {
		right string
		want  bool
	}{
		{"dns", true},
		{"dns:any", true},
		{"dns::", true},
		{"dns::53", true},
		{"dns:any:53", true},
		{"dns:any:any", true},
		{"dns:tcp:53", false},
		{"dns:udp:53", false},
		{"dns:udp:54", false},
		{"dns:tcp:53:extra", false},
		{"host", false},
	} {
		if got := isFullDNSRight(tc.right); got != tc.want {
			t.Errorf("isFullDNSRight(%q) = %v, want %v", tc.right, got, tc.want)
		}
	}
}

func TestNetRuleParserBoundaryRejections(t *testing.T) {
	longLabel := strings.Repeat("a", 64) + ".com"
	longDomain := strings.Repeat("abcde.", 43) + "com" // > 253 chars
	badSpecs := []string{
		"invalid-profile",
		"foo@bar",
		"allow:bogusdir@public",
		"allow@",
		"deny@",
		"allow@example.com --privileged",
		"allow@example.com\x7f",
		"allow@example.com,",
		"allow@example.com,deny@",
		"deny@fe80::/10",
		"deny@fe80:0:0:0:0:0:0:0/10",
		"allow@2001:db8::1",
		"allow@2001:db8:0:0:0:0:0:1",
		"allow@1:2:3:4",
		"allow@[192.0.2.1]",
		"allow@[192.0.2.0/24]",
		"allow@[",
		"allow@[]",
		"allow@[not-ipv6]",
		"allow@[fe80::1%eth0]",
		"allow@[2001:db8::1/64]",
		"allow@[2001:db8::/200]",
		"allow@[::1]abc",
		"allow@[::1]:",
		"allow@[::1]:tcp:",
		"allow@[::1]:tcp:80:extra",
		"allow@:tcp:80",
		"allow@public:",
		"allow@public:tcp:",
		"allow@public:sctp:80",
		"allow@public:tcp:65536",
		"allow@public:tcp:abc",
		"allow@public:tcp:80-65536",
		"allow@public:tcp:443-80",
		"allow@public:icmpv4:80",
		"allow@public:icmpv6:80",
		"allow@myhost",
		"deny@*.com",
		"deny@suffix=local",
		"deny@domain=",
		"deny@a..b",
		"deny@a.-b.com",
		"deny@a.b-.com",
		"deny@a.b_c.com",
		"deny@foo.123",
		"deny@010.0.0.1",
		"deny@10.0.0.1/99",
		"deny@" + longLabel,
		"deny@" + longDomain,
		"allow@example.com:443",
		"allow:ingress@dns",
		"allow:ingress@public:icmpv4",
		"allow:any@public:icmpv6",
		"allow@public:tcp:443:extra",
	}
	for _, badSpec := range badSpecs {
		t.Run(badSpec, func(t *testing.T) {
			if _, err := buildNetArgs(false, []string{badSpec}); err == nil {
				t.Errorf("expected error for invalid --net spec %q", badSpec)
			}
		})
	}
	if err := validateNetRuleToken(""); err == nil {
		t.Error("expected error for empty rule token")
	}
}

func assertAllNetRuleTokensValid(t *testing.T, args []string) {
	t.Helper()
	for i := 0; i < len(args); i++ {
		if args[i] == "--net-rule" {
			if i+1 >= len(args) {
				t.Fatalf("dangling --net-rule at end of %v", args)
			}
			if err := validateNetRuleToken(args[i+1]); err != nil {
				t.Fatalf("emitted invalid --net-rule %q in %v: %v", args[i+1], args, err)
			}
			i++
		}
	}
}

func TestValidateDNSRuleRightErrors(t *testing.T) {
	cases := []struct {
		right string
		dir   string
		token string
	}{
		{right: "dns", dir: "ingress", token: "allow:ingress@dns"},
		{right: "dns", dir: "any", token: "allow:any@dns"},
		{right: "dns:any:53:extra", dir: "egress", token: "allow@dns:any:53:extra"},
		{right: "dns:sctp", dir: "egress", token: "allow@dns:sctp"},
		{right: "dns:udp:80", dir: "egress", token: "allow@dns:udp:80"},
	}
	for _, tc := range cases {
		t.Run(tc.token, func(t *testing.T) {
			if err := validateDNSRuleRight(tc.right, tc.dir, tc.token); err == nil {
				t.Errorf("expected error for validateDNSRuleRight(%q, %q, %q)", tc.right, tc.dir, tc.token)
			}
		})
	}
}

func TestIngressRuleForPublishedPort(t *testing.T) {
	validCases := []struct {
		spec string
		want string
	}{
		{"127.0.0.1:4096:3000", "allow:ingress@loopback:tcp:3000"},
		{"127.0.0.1:4096:3000/tcp", "allow:ingress@loopback:tcp:3000"},
		{"127.0.0.1:4096:3000/UDP", "allow:ingress@loopback:udp:3000"},
		{"[::1]:4096:3000", "allow:ingress@loopback:tcp:3000"},
		{"[::1]:4096:3000/udp", "allow:ingress@loopback:udp:3000"},
	}
	for _, tc := range validCases {
		got, err := ingressRuleForPublishedPort(tc.spec)
		if err != nil || got != tc.want {
			t.Errorf("ingressRuleForPublishedPort(%q) = (%q, %v), want (%q, nil)", tc.spec, got, err, tc.want)
		}
	}

	badCases := []string{
		"",
		"   ",
		"127.0.0.1:8080:3000\x7f",
		"127.0.0.1:8080: 3000",
		"[::1",
		"[::1]80",
		"[::1]:8080",
		"[::1]:8080:3000:extra",
		"[not-ip]:8080:3000",
		"[fe80::1%eth0]:8080:3000",
		"[::]:8080:3000",
		"[2001:db8::1]:8080:3000",
		"8080:3000",
		"0.0.0.0:8080:3000",
		"192.168.1.10:8080:3000",
		"127.0.0.2:8080:3000",
		"127.0.0.1:8080:8080:extra",
		"127.0.0.1:0:3000",
		"127.0.0.1:8080:0",
		"127.0.0.1:65536:3000",
		"127.0.0.1:8080:65536",
		"127.0.0.1:80:80/sctp",
	}
	for _, spec := range badCases {
		t.Run(spec, func(t *testing.T) {
			if _, err := ingressRuleForPublishedPort(spec); err == nil {
				t.Errorf("expected error for ingressRuleForPublishedPort(%q)", spec)
			}
		})
	}
}

func TestShellQuoteAndFormatEnvExports(t *testing.T) {
	if got := ShellQuote(`abc'def"$(id)`); got != `'abc'\''def"$(id)'` {
		t.Errorf("ShellQuote = %q", got)
	}

	envMap := map[string]string{
		"ANTHROPIC_API_KEY": "sk-ant-123",
		"GEMINI_API_KEY":    "val'with'quote",
		"EMPTY_KEY":         "",
	}
	script, count := FormatEnvExports(func(k string) string { return envMap[k] }, []string{
		"",
		"ANTHROPIC_API_KEY",
		"EMPTY_KEY",
		"GEMINI_API_KEY",
		"MISSING_KEY",
	})
	if count != 2 {
		t.Fatalf("count = %d, want 2", count)
	}
	if !strings.Contains(script, "export ANTHROPIC_API_KEY='sk-ant-123'\n") {
		t.Errorf("missing ANTHROPIC_API_KEY export in %q", script)
	}
	if !strings.Contains(script, `export GEMINI_API_KEY='val'\''with'\''quote'`) {
		t.Errorf("missing escaped GEMINI_API_KEY export in %q", script)
	}
	if strings.Contains(script, "EMPTY_KEY") || strings.Contains(script, "MISSING_KEY") {
		t.Errorf("unexpected empty/missing key in %q", script)
	}

	nilScript, nilCount := FormatEnvExports(nil, []string{"ANTHROPIC_API_KEY"})
	if nilCount != 0 || strings.Contains(nilScript, "export ") {
		t.Errorf("FormatEnvExports(nil) = (%q, %d)", nilScript, nilCount)
	}
}

func TestBuildCreateAndRestoreAndExecArgs(t *testing.T) {
	if _, err := BuildCreateArgs(CreateOpts{Name: "agbox-base"}); err == nil {
		t.Fatal("expected error when Image is empty")
	}
	if _, err := BuildCreateArgs(CreateOpts{Image: "debian:bookworm-slim"}); err == nil {
		t.Fatal("expected error when Name is empty")
	}
	if _, err := BuildCreateArgs(CreateOpts{Image: "debian:bookworm-slim", Name: "agbox-base", NetSpecs: []string{"bad-spec"}}); err == nil {
		t.Fatal("expected BuildCreateArgs to propagate invalid NetSpecs error")
	}

	createArgs, err := BuildCreateArgs(CreateOpts{
		Image:    "node:24-bookworm-slim",
		Name:     "agbox-base",
		RootDisk: "8G",
		Workdir:  "/workspace",
	})
	if err != nil {
		t.Fatalf("BuildCreateArgs: %v", err)
	}
	assertAllNetRuleTokensValid(t, createArgs)
	createJoined := strings.Join(createArgs, " ")
	for _, want := range []string{
		"create node:24-bookworm-slim --name agbox-base --cpus 4 --memory 8G --root-disk 8G --workdir /workspace --mkdir /workspace",
		"--net-default deny",
		"--net-rule allow@dns",
		"--net-rule deny@meta",
		"--net-rule allow@public",
	} {
		if !strings.Contains(createJoined, want) {
			t.Errorf("createArgs %q missing %q", createJoined, want)
		}
	}

	if _, err := BuildRestoreArgs(RestoreOpts{Name: "agbox-run-1"}); err == nil {
		t.Fatal("expected error when Snapshot is empty")
	}
	if _, err := BuildRestoreArgs(RestoreOpts{Snapshot: "agbox:v1"}); err == nil {
		t.Fatal("expected error when Name is empty")
	}

	restoreArgs, err := BuildRestoreArgs(RestoreOpts{
		Snapshot: "agbox:v2",
		Name:     "agbox-run-99",
		CPUs:     "4",
		Memory:   "4G",
		DiskMounts: []DiskMountSpec{
			{HostPath: "/home/u/.microsandbox/volumes/agbox-profile-work/disk.raw", GuestPath: GuestProfileMount},
		},
		Volumes: []VolumeSpec{
			{HostPath: "/tmp/ws", GuestPath: "/workspace", ReadOnly: false},
			{HostPath: "/tmp/mnt0", GuestPath: "/workspace/proj", ReadOnly: false, StatVirt: "relaxed", HostPerms: "mirror"},
			{HostPath: "/tmp/file.txt", GuestPath: "/workspace/file.txt", ReadOnly: true},
		},
		Ports:    []string{"127.0.0.1:4096:3000"},
		NoNet:    false,
		NetSpecs: []string{"public", "allow@example.com:tcp:443", "allow:ingress@loopback:tcp:3000"},
	})
	if err != nil {
		t.Fatalf("BuildRestoreArgs: %v", err)
	}
	assertAllNetRuleTokensValid(t, restoreArgs)
	joined := strings.Join(restoreArgs, " ")
	for _, substr := range []string{
		"snap restore agbox:v2",
		"--name agbox-run-99 -u agent",
		"--cpus 4 --memory 4G",
		"--mount-disk /home/u/.microsandbox/volumes/agbox-profile-work/disk.raw:/home/agent/.agbox-profile:rw,format=raw,fstype=ext4",
		"-v /tmp/ws:/workspace:rw,stat-virt=off",
		"-v /tmp/mnt0:/workspace/proj:rw,stat-virt=relaxed,host-perms=mirror,uid=1000,gid=1000",
		"-v /tmp/file.txt:/workspace/file.txt:ro,stat-virt=relaxed,uid=1000,gid=1000",
		"-p 127.0.0.1:4096:3000",
		"--net-default deny --net-rule allow@dns --net-rule deny@host --net-rule deny@loopback --net-rule deny@private --net-rule deny@link-local --net-rule deny@multicast --net-rule deny@meta",
		"--net-rule deny@100.64.0.0/10",
		"--net-rule deny@168.63.129.16/32",
		"--net-rule deny@100.100.100.200/32",
		"--net-rule deny@[::/128]",
		"--net-rule deny@[::ffff:0:0/96]",
		"--net-rule deny@[64:ff9b::/96]",
		"--net-rule deny@[fd00:ec2::254/128]",
		"--net-rule allow@public",
		"--net-rule allow@example.com:tcp:443",
		"--net-rule allow:ingress@loopback:tcp:3000",
	} {
		if !strings.Contains(joined, substr) {
			t.Errorf("restoreArgs %q missing %q", joined, substr)
		}
	}
	if strings.Count(joined, "allow:ingress@loopback:tcp:3000") != 1 {
		t.Errorf("expected deduplicated ingress rule in %q", joined)
	}
	if strings.Contains(joined, "stat-virt=off,uid=") {
		t.Errorf("restoreArgs unexpectedly combined stat-virt=off with uid=: %q", joined)
	}

	noNetServeArgs, err := BuildRestoreArgs(RestoreOpts{
		Snapshot: "agbox:v1",
		Name:     "agbox-run-serve-nonet",
		Ports:    []string{"127.0.0.1:4096:3000"},
		NoNet:    true,
	})
	if err != nil {
		t.Fatalf("BuildRestoreArgs no-net serve: %v", err)
	}
	if !slices.Contains(noNetServeArgs, "--no-net") || slices.Contains(noNetServeArgs, "--net-rule") {
		t.Errorf("expected --no-net without --net-rule in %v", noNetServeArgs)
	}

	allNetServeArgs, err := BuildRestoreArgs(RestoreOpts{
		Snapshot: "agbox:v1",
		Name:     "agbox-run-serve-all",
		Ports:    []string{"[::1]:4096:3000/udp"},
		NetSpecs: []string{"all"},
	})
	if err != nil {
		t.Fatalf("BuildRestoreArgs all serve: %v", err)
	}
	if strings.Contains(strings.Join(allNetServeArgs, " "), "allow:ingress@loopback") {
		t.Errorf("expected no extra ingress rule under --net-default allow, got %v", allNetServeArgs)
	}

	// Non-loopback published port must fail even under --net all or --no-net.
	for _, badPort := range []string{"bad", "3000", "8080:3000", "0.0.0.0:4096:3000", "127.0.0.1:0:3000", "127.0.0.1:4096:99999", "127.0.0.1:4096:3000/icmp", "badip:4096:3000"} {
		if _, err := BuildRestoreArgs(RestoreOpts{
			Snapshot: "agbox:v1",
			Name:     "agbox-run-badport",
			Ports:    []string{badPort},
			NetSpecs: []string{"all"},
		}); err == nil {
			t.Errorf("expected error for malformed or non-loopback port spec %q", badPort)
		}
	}
	if _, err := BuildRestoreArgs(RestoreOpts{
		Snapshot:   "agbox:v1",
		Name:       "agbox-bad-disk",
		DiskMounts: []DiskMountSpec{{HostPath: "relative", GuestPath: GuestProfileMount}},
	}); err == nil {
		t.Error("expected BuildRestoreArgs to reject invalid DiskMountSpec")
	}
	if _, err := BuildRestoreArgs(RestoreOpts{
		Snapshot: "agbox:v1",
		Name:     "agbox-bad-net",
		NetSpecs: []string{"bad-spec"},
	}); err == nil {
		t.Error("expected BuildRestoreArgs to reject invalid NetSpecs")
	}

	execArgs := BuildExecArgs(ExecCmdOpts{
		Sandbox: "agbox-run-99",
		Workdir: "/workspace/proj",
		User:    config.GuestUser,
		TTY:     true,
		Env:     GuestEnvFlags(),
		Command: []string{"bash", "-c", "id"},
	})
	wantExec := []string{
		"exec",
		"-t",
		"-w", "/workspace/proj",
		"-u", "agent",
		"-e", "HOME=/home/agent",
		"-e", "USER=agent",
		"-e", "LOGNAME=agent",
		"-e", "PATH=" + guestDefaultPath,
		"-e", "SSH_CONNECTION=1",
		"agbox-run-99",
		"--",
		"bash", "-c", "id",
	}
	if !slices.Equal(execArgs, wantExec) {
		t.Errorf("BuildExecArgs = %v, want %v", execArgs, wantExec)
	}

	detachedNoTTYArgs := BuildExecArgs(ExecCmdOpts{
		Sandbox:  "agbox-run-99",
		Detached: true,
		NoTTY:    true,
		NoStdin:  true,
		Command:  []string{"id"},
	})
	wantDetachedNoTTY := []string{"exec", "-d", "--no-tty", "--no-stdin", "-u", "agent", "agbox-run-99", "--", "id"}
	if !slices.Equal(detachedNoTTYArgs, wantDetachedNoTTY) {
		t.Errorf("BuildExecArgs(Detached+NoTTY) = %v, want %v", detachedNoTTYArgs, wantDetachedNoTTY)
	}

	ttyNoStdinArgs := BuildExecArgs(ExecCmdOpts{
		Sandbox: "agbox-run-99",
		TTY:     true,
		NoStdin: true,
		Command: []string{"bash"},
	})
	if slices.Contains(ttyNoStdinArgs, "--no-stdin") || slices.Contains(ttyNoStdinArgs, "-w") {
		t.Errorf("expected --no-stdin and -w omitted when TTY=true and Workdir empty in %v", ttyNoStdinArgs)
	}
}

func TestCategoriesAndResolution(t *testing.T) {
	cats, err := ResolveCategories([]string{"core,,golang", "", "4", "embedded-rust", "chrome", "hugo", "caddy"})
	if err != nil {
		t.Fatalf("ResolveCategories: %v", err)
	}
	var gotNames []string
	for _, c := range cats {
		gotNames = append(gotNames, c.Name)
	}
	// Category embedded-rust adds rust, and index 4 selects esphome.
	wantNames := []string{"core", "go", "rust", "esphome", "embedded-rust", "chrome", "hugo", "caddy"}
	if !slices.Equal(gotNames, wantNames) {
		t.Fatalf("ResolveCategories names = %v, want %v", gotNames, wantNames)
	}

	caddyOnly, err := ResolveCategories([]string{"caddy"})
	if err != nil || len(caddyOnly) != 2 || caddyOnly[0].Name != "go" || caddyOnly[1].Name != "caddy" {
		t.Fatalf("ResolveCategories(caddy) = %+v, %v", caddyOnly, err)
	}

	allCats, err := ResolveCategories([]string{"all"})
	if err != nil || len(allCats) != len(categories()) {
		t.Fatalf("ResolveCategories(all) = %d cats, err=%v", len(allCats), err)
	}

	if _, err := ResolveCategories([]string{"nonexistent-cat"}); err == nil {
		t.Fatal("expected error for unknown category")
	}
	if BuildCategoriesScript(nil) != "" {
		t.Error("expected empty script for empty categories slice")
	}

	merged := MergeCategoryNames("core,go", cats)
	if merged != "core,go,rust,esphome,embedded-rust,chrome,hugo,caddy" {
		t.Errorf("MergeCategoryNames = %q", merged)
	}

	table := FormatCategoriesTable()
	for _, kw := range []string{"core", "go", "rust", "esphome", "embedded-rust", "chrome", "hugo", "caddy", "shellcheck", "golangci-lint", "clippy", "xcaddy"} {
		if !strings.Contains(table, kw) {
			t.Errorf("FormatCategoriesTable missing %q", kw)
		}
	}

	script := BuildCategoriesScript(cats)
	for _, kw := range []string{
		"shellcheck",
		"pipx install --force mdformat",
		"github.com/go-delve/delve/cmd/dlv@latest",
		"golang.org/x/tools/gopls@latest",
		"github.com/golangci/golangci-lint/cmd/golangci-lint@latest",
		"https://sh.rustup.rs",
		"rustup component add clippy rustfmt",
		"pipx install --force esphome",
		"cargo install espflash",
		"chromium chromium-driver xvfb",
		"hugo_extended_",
		"github.com/caddyserver/xcaddy/cmd/xcaddy@latest",
		"github.com/caddy-dns/cloudflare",
		"github.com/greenpau/caddy-security",
		"github.com/mholt/caddy-l4",
	} {
		if !strings.Contains(script, kw) {
			t.Errorf("BuildCategoriesScript missing %q", kw)
		}
	}
	cmd := exec.Command("bash", "-n")
	cmd.Stdin = strings.NewReader(script)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("BuildCategoriesScript bash -n failed: %v (%s)", err, string(out))
	}
}

func TestParseSandboxAndSnapshotLists(t *testing.T) {
	if got := ParseSandboxList("NAME   STATE\n\n"); len(got) != 0 {
		t.Errorf("ParseSandboxList(header-only) = %v, want empty", got)
	}
	if got := ParseSandboxList("NAME          IMAGE                    STATUS     CREATED\n"); len(got) != 0 {
		t.Errorf("ParseSandboxList(real header-only) = %v, want empty", got)
	}

	realLS := `
NAME          IMAGE                     STATUS     CREATED
agbox-blip    node:24-bookworm-slim     running    2026-11-14 14:59:39
agbox-base    node:24-bookworm-slim     stopped    2026-11-14 14:49:18
agbox-running my-running-image:latest   stopped    2026-11-14 14:50:00
`
	realSBs := ParseSandboxList(realLS)
	if len(realSBs) != 3 {
		t.Fatalf("len(realSBs) = %d, want 3", len(realSBs))
	}
	if sb, ok := FindSandbox(realSBs, "agbox-blip"); !ok || !sb.Running {
		t.Errorf("agbox-blip in real msb ls = %+v, ok=%v", sb, ok)
	}
	if sb, ok := FindSandbox(realSBs, "agbox-base"); !ok || sb.Running {
		t.Errorf("agbox-base in real msb ls = %+v, ok=%v", sb, ok)
	}
	if sb, ok := FindSandbox(realSBs, "agbox-running"); !ok || sb.Running {
		t.Errorf("stopped sandbox named agbox-running marked running: %+v, ok=%v", sb, ok)
	}

	// Keep the legacy STATE header layout and the agbox-running-named stopped check.
	lsOut := `
NAME                   STATE     CPUS   MEMORY
----                   -----     ----   ------
agbox-base             stopped   2      2048 MiB
agbox-running-named    stopped   2      2048 MiB
agbox-run-1234         running   2      2048 MiB
`
	sbs := ParseSandboxList(lsOut)
	if len(sbs) != 3 {
		t.Fatalf("len(sbs) = %d, want 3", len(sbs))
	}
	if sb, ok := FindSandbox(sbs, "agbox-base"); !ok || sb.Running {
		t.Errorf("agbox-base = %+v, ok=%v", sb, ok)
	}
	if sb, ok := FindSandbox(sbs, "agbox-running-named"); !ok || sb.Running {
		t.Errorf("stopped sandbox with running in name marked running: %+v, ok=%v", sb, ok)
	}
	if sb, ok := FindSandbox(sbs, "agbox-run-1234"); !ok || !sb.Running {
		t.Errorf("agbox-run-1234 = %+v, ok=%v", sb, ok)
	}
	if _, ok := FindSandbox(sbs, "missing"); ok {
		t.Error("expected missing sandbox not to be found")
	}

	// Check ANSI escape stripping and fallback when no STATUS or STATE header exists.
	fallbackLS := "NAME IMAGE INFO\nagbox-running node:24-bookworm-slim stopped\nagbox-ansi node:24-bookworm-slim \x1b[32mrunning\x1b[0m\n"
	fallbackSBs := ParseSandboxList(fallbackLS)
	if sb, ok := FindSandbox(fallbackSBs, "agbox-running"); !ok || sb.Running {
		t.Errorf("fallback agbox-running = %+v, ok=%v", sb, ok)
	}
	if sb, ok := FindSandbox(fallbackSBs, "agbox-ansi"); !ok || !sb.Running {
		t.Errorf("fallback agbox-ansi = %+v, ok=%v", sb, ok)
	}

	realSnapOut := `
NAME        SCOPE   MIGRATION   IMAGE                    SIZE       CREATED               DIGEST
agbox:v1    local   offline     node:24-bookworm-slim    1.12 GiB   2026-11-14 14:52:01   sha256:abcd1234
agbox:v2    local   offline     node:24-bookworm-slim    1.15 GiB   2026-11-14 15:01:10   sha256:ef567890
`
	if gotRealSnaps := ParseSnapshotList(realSnapOut); !slices.Equal(gotRealSnaps, []string{"agbox:v1", "agbox:v2"}) {
		t.Errorf("ParseSnapshotList(real layout) = %v", gotRealSnaps)
	}

	snapOut := `
NAME        CREATED        SIZE
agbox:v1    2 hours ago    512 MiB
agbox:v3    1 hour ago     520 MiB
other:v9    10 mins ago    100 MiB
`
	snaps := ParseSnapshotList(snapOut)
	if !slices.Equal(snaps, []string{"agbox:v1", "agbox:v3", "other:v9"}) {
		t.Errorf("ParseSnapshotList = %v", snaps)
	}
	if next, sel := config.NextSnapshotMember(0, snaps, "agbox"); next != 4 || sel != "agbox:v4" {
		t.Errorf("NextSnapshotMember = %d, %q, want 4, agbox:v4", next, sel)
	}

	volOut := `
NAME                 KIND   SIZE     CREATED
----                 ----   ----     -------
agbox-profile-work   disk   10 GiB   2026-11-14 15:10:00
other-vol            dir    -        2026-11-14 15:11:00
`
	vols := ParseVolumeList(volOut)
	if !slices.Equal(vols, []string{"agbox-profile-work", "other-vol"}) {
		t.Errorf("ParseVolumeList = %v", vols)
	}
	vArgs, err := BuildVolumeCreateDiskArgs("agbox-profile-work", "10G")
	if err != nil || !slices.Equal(vArgs, []string{"volume", "create", "agbox-profile-work", "--kind", "disk", "--size", "10G"}) {
		t.Errorf("BuildVolumeCreateDiskArgs = %v, %v", vArgs, err)
	}
	if _, err := BuildVolumeCreateDiskArgs("", "10G"); err == nil {
		t.Error("expected error for empty volume name")
	}
	if _, err := BuildVolumeCreateDiskArgs("agbox-profile-work", ""); err == nil {
		t.Error("expected error for empty volume size")
	}
}

func TestProvisionScriptAndExecRunner(t *testing.T) {
	pScript := ProvisionGuestUserScript()
	if !strings.Contains(pScript, "NOPASSWD: ALL") || !strings.Contains(pScript, "/usr/local/bin/agy") {
		t.Errorf("unexpected provision script: %s", pScript)
	}

	tmp := t.TempDir()
	fakeMSB := filepath.Join(tmp, "msb")
	script := "#!/bin/sh\nif [ \"$1\" = \"snap\" ] && [ \"$2\" = \"ls\" ]; then\n  echo \"agbox:v1 1m 100M\"\n  exit 0\nfi\nif [ \"$1\" = \"volume\" ] && [ \"$2\" = \"ls\" ]; then\n  echo \"agbox-profile-work disk 10G\"\n  exit 0\nfi\necho \"out-msg\"\necho \"err-msg\" >&2\nexit 3\n"
	if err := os.WriteFile(fakeMSB, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}

	runner, err := NewExecRunner(fakeMSB)
	if err != nil {
		t.Fatalf("NewExecRunner: %v", err)
	}
	if _, err := NewExecRunner(filepath.Join(tmp, "missing-msb")); err == nil {
		t.Error("expected NewExecRunner error for missing explicit binary")
	}

	exists, err := SnapshotExists(context.Background(), runner, "agbox:v1")
	if err != nil || !exists {
		t.Fatalf("SnapshotExists(agbox:v1) = %v, %v", exists, err)
	}
	exists, err = SnapshotExists(context.Background(), runner, "agbox:v2")
	if err != nil || exists {
		t.Fatalf("SnapshotExists(agbox:v2) = %v, %v", exists, err)
	}
	vExists, err := VolumeExists(context.Background(), runner, "agbox-profile-work")
	if err != nil || !vExists {
		t.Fatalf("VolumeExists(agbox-profile-work) = %v, %v", vExists, err)
	}
	vExists, err = VolumeExists(context.Background(), runner, "agbox-profile-missing")
	if err != nil || vExists {
		t.Fatalf("VolumeExists(missing) = %v, %v", vExists, err)
	}

	res, err := runner.Run(context.Background(), CommandRequest{Args: []string{"fail"}})
	if err == nil || res.ExitCode != 3 || !strings.Contains(res.Stdout, "out-msg") || !strings.Contains(res.Stderr, "err-msg") {
		t.Fatalf("expected captured stdout/stderr and exit code 3, got res=%+v, err=%v", res, err)
	}

	var customOut, customErr bytes.Buffer
	_, _ = runner.Run(context.Background(), CommandRequest{
		Args:   []string{"fail"},
		Stdout: &customOut,
		Stderr: &customErr,
	})
	if !strings.Contains(customOut.String(), "out-msg") || !strings.Contains(customErr.String(), "err-msg") {
		t.Errorf("expected custom non-interactive writers populated, got out=%q err=%q", customOut.String(), customErr.String())
	}

	// Non-ExitError failure (missing executable) sets ExitCode to 1.
	badRunner := &ExecRunner{BinaryPath: filepath.Join(tmp, "does-not-exist")}
	badRes, badErr := badRunner.Run(context.Background(), CommandRequest{Args: []string{"ls"}})
	if badErr == nil || badRes.ExitCode != 1 {
		t.Errorf("expected ExitCode=1 on missing binary, got res=%+v err=%v", badRes, badErr)
	}

	failRunner := &stubErrorRunner{err: errors.New("simulated msb failure")}
	if _, err := SnapshotExists(context.Background(), failRunner, "agbox:v1"); err == nil {
		t.Error("expected SnapshotExists to propagate runner error")
	}
	if _, err := VolumeExists(context.Background(), failRunner, "agbox-profile-work"); err == nil {
		t.Error("expected VolumeExists to propagate runner error")
	}

	// Binary resolution paths: lookPath hit, ~/.local/bin/msb hit, directory candidate skipped, and /usr/local/bin/msb error text.
	if got, err := resolveBinaryWith("", func(string) (string, error) { return "/bin/msb", nil }, "", nil); err != nil || got != "/bin/msb" {
		t.Errorf("resolveBinaryWith lookPath = (%q, %v)", got, err)
	}
	fakeHome := filepath.Join(tmp, "home")
	localMSB := filepath.Join(fakeHome, ".local", "bin", "msb")
	if err := os.MkdirAll(filepath.Dir(localMSB), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(localMSB, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	noLook := func(string) (string, error) { return "", os.ErrNotExist }
	if got, err := resolveBinaryWith("", noLook, fakeHome, nil); err != nil || got != localMSB {
		t.Errorf("resolveBinaryWith home fallback = (%q, %v)", got, err)
	}
	dirCandidate := filepath.Join(tmp, "dir-msb")
	if err := os.MkdirAll(dirCandidate, 0o755); err != nil {
		t.Fatal(err)
	}
	extraBin := filepath.Join(tmp, "usr-local-msb")
	if err := os.WriteFile(extraBin, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	resolved, err := resolveBinaryWith("", noLook, filepath.Join(tmp, "nohome"), []string{dirCandidate, extraBin})
	if err != nil || resolved != extraBin {
		t.Errorf("resolveBinaryWith extra fallback = %q, %v", resolved, err)
	}
	if _, err := resolveBinaryWith("", noLook, filepath.Join(tmp, "nohome"), []string{dirCandidate}); err == nil || !strings.Contains(err.Error(), "/usr/local/bin/msb") {
		t.Errorf("expected /usr/local/bin/msb in missing binary error, got %v", err)
	}
}

func TestSecretShellInjectionResistanceAndCategoryTLS(t *testing.T) {
	canary := filepath.Join(t.TempDir(), "pwned")
	secretMap := map[string]string{
		"ANTHROPIC_API_KEY": "sk-ant-'$(touch " + canary + ")'\"`touch " + canary + "`\"",
		"OPENAI_API_KEY":    "line1\nexport INJECTED=1\n$HOME\necho pwn > " + canary,
		"GEMINI_API_KEY":    `backslash\and$VAR'single'"double"`,
	}
	script, count := FormatEnvExports(func(k string) string { return secretMap[k] }, []string{
		"ANTHROPIC_API_KEY",
		"OPENAI_API_KEY",
		"GEMINI_API_KEY",
	})
	if count != 3 {
		t.Fatalf("count = %d, want 3", count)
	}

	// Evaluate the export script in /bin/sh and verify literal values with zero command execution.
	keysFile := filepath.Join(t.TempDir(), ".agbox-keys.sh")
	if err := os.WriteFile(keysFile, []byte(script), 0o600); err != nil {
		t.Fatal(err)
	}
	checkCmd := `. "$1"
test -z "${INJECTED:-}" || exit 11
printf '%s\0%s\0%s' "$ANTHROPIC_API_KEY" "$OPENAI_API_KEY" "$GEMINI_API_KEY"`
	runner := &ExecRunner{BinaryPath: "/bin/sh"}
	res, err := runner.Run(context.Background(), CommandRequest{
		Args: []string{"-c", checkCmd, "--", keysFile},
	})
	if err != nil {
		t.Fatalf("shell evaluation of FormatEnvExports failed: %v (stderr=%s)", err, res.Stderr)
	}
	if _, statErr := os.Stat(canary); !os.IsNotExist(statErr) {
		t.Fatalf("CRITICAL: command injection executed and created %s", canary)
	}
	parts := strings.Split(res.Stdout, "\x00")
	if len(parts) != 3 ||
		parts[0] != secretMap["ANTHROPIC_API_KEY"] ||
		parts[1] != secretMap["OPENAI_API_KEY"] ||
		parts[2] != secretMap["GEMINI_API_KEY"] {
		t.Fatalf("round-tripped secrets mismatch: got %q", parts)
	}

	// Verify every curl command in all category install scripts enforces HTTPS, HTTPS redirects, and TLS 1.2+.
	allCats, err := ResolveCategories([]string{"all"})
	if err != nil {
		t.Fatal(err)
	}
	catScript := BuildCategoriesScript(allCats)
	for _, line := range strings.Split(catScript, "\n") {
		trimmed := strings.TrimSpace(line)
		isCurlCmd := strings.HasPrefix(trimmed, "curl ") ||
			strings.Contains(trimmed, "$(curl ") ||
			strings.Contains(trimmed, "! curl ") ||
			strings.Contains(trimmed, "&& curl ")
		if isCurlCmd {
			for _, reqFlag := range []string{"--proto", "--proto-redir", "=https", "--tlsv1.2"} {
				if !strings.Contains(trimmed, reqFlag) {
					t.Errorf("category curl command missing %s: %s", reqFlag, trimmed)
				}
			}
			if strings.Contains(trimmed, "http://") {
				t.Errorf("category curl command uses plaintext http://: %s", trimmed)
			}
		}
	}
	for _, guard := range []string{`^go[0-9]+\.[0-9]+`, `^[0-9]+\.[0-9]+\.[0-9]+`} {
		if !strings.Contains(catScript, guard) {
			t.Errorf("category script missing version regex guard %s", guard)
		}
	}
}

func TestProvisionGuestUserScriptAgentDefaults(t *testing.T) {
	script := ProvisionGuestUserScript()
	for _, want := range []string{
		"/etc/profile.d/agbox-path.sh",
		"/usr/local/bin/mdformat",
		"/home/agent/.agbox-agents",
		"/home/agent/.gemini/antigravity-cli/settings.json",
		`"toolPermission": "always-proceed"`,
		`"queuedMessages": "send-immediately"`,
		`"allowNonWorkspaceAccess": true`,
		`"trustedWorkspaces"`,
		"/home/agent/.config/opencode/opencode.json",
		`"permission": "allow"`,
	} {
		if !strings.Contains(script, want) {
			t.Errorf("ProvisionGuestUserScript missing %q", want)
		}
	}
}

func TestExecRunnerInteractiveStreaming(t *testing.T) {
	tmp := t.TempDir()
	fakeMSB := filepath.Join(tmp, "msb")
	script := `#!/bin/sh
echo "streamed-stdout-ok"
echo "streamed-stderr-ok" >&2
`
	if err := os.WriteFile(fakeMSB, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}

	runner, err := NewExecRunner(fakeMSB)
	if err != nil {
		t.Fatalf("NewExecRunner: %v", err)
	}

	var outBuf, errBuf bytes.Buffer
	res, err := runner.Run(context.Background(), CommandRequest{
		Args:        []string{"exec", "--stream", "--no-stdin", "agbox-run-1", "--", "id"},
		Stdin:       bytes.NewReader(nil),
		Stdout:      &outBuf,
		Stderr:      &errBuf,
		Interactive: true,
	})
	if err != nil {
		t.Fatalf("ExecRunner.Run unexpected error: %v", err)
	}
	if res.ExitCode != 0 {
		t.Fatalf("ExitCode = %d, want 0", res.ExitCode)
	}
	if !strings.Contains(outBuf.String(), "streamed-stdout-ok") {
		t.Errorf("expected streamed stdout in writer, got %q", outBuf.String())
	}
	if !strings.Contains(errBuf.String(), "streamed-stderr-ok") {
		t.Errorf("expected streamed stderr in writer, got %q", errBuf.String())
	}

	// Interactive mode with nil Stdin/Stdout/Stderr connects to os.Stdin/os.Stdout/os.Stderr.
	quietMSB := filepath.Join(tmp, "msb-quiet")
	if err := os.WriteFile(quietMSB, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	qRunner, err := NewExecRunner(quietMSB)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := qRunner.Run(context.Background(), CommandRequest{Interactive: true}); err != nil {
		t.Errorf("interactive default streams run failed: %v", err)
	}
}

func TestDiskMountAndVolumeInspectPathResolution(t *testing.T) {
	validFlag, err := (DiskMountSpec{
		HostPath:  "/var/lib/msb/volumes/work/disk.raw",
		GuestPath: GuestProfileMount,
	}).formatFlag()
	if err != nil || validFlag != "/var/lib/msb/volumes/work/disk.raw:/home/agent/.agbox-profile:rw,format=raw,fstype=ext4" {
		t.Fatalf("DiskMountSpec.formatFlag() = (%q, %v)", validFlag, err)
	}

	roFlag, err := (DiskMountSpec{
		HostPath:  "/var/lib/msb/volumes/work/disk.raw",
		GuestPath: GuestProfileMount,
		ReadOnly:  true,
		Format:    "qcow2",
		FSType:    "xfs",
	}).formatFlag()
	if err != nil || roFlag != "/var/lib/msb/volumes/work/disk.raw:/home/agent/.agbox-profile:ro,format=qcow2,fstype=xfs" {
		t.Fatalf("DiskMountSpec.formatFlag(ro) = (%q, %v)", roFlag, err)
	}

	for _, bad := range []DiskMountSpec{
		{HostPath: "", GuestPath: GuestProfileMount},
		{HostPath: "relative/disk.raw", GuestPath: GuestProfileMount},
		{HostPath: "/tmp/a:b/disk.raw", GuestPath: GuestProfileMount},
		{HostPath: "/tmp/a,b/disk.raw", GuestPath: GuestProfileMount},
		{HostPath: "/tmp/a\nb/disk.raw", GuestPath: GuestProfileMount},
		{HostPath: "/tmp/disk.raw", GuestPath: "relative"},
	} {
		if _, err := bad.formatFlag(); err == nil {
			t.Errorf("expected DiskMountSpec.formatFlag error for %+v", bad)
		}
	}

	plainInspect := "Volume agbox-profile-work\n  Kind   disk\n  Size   10 GiB\n  Path   /home/alice/.microsandbox/volumes/agbox-profile-work/disk.raw\n"
	if got := parseVolumeInspectPath(plainInspect); got != "/home/alice/.microsandbox/volumes/agbox-profile-work/disk.raw" {
		t.Errorf("parseVolumeInspectPath(plain) = %q", got)
	}
	colonInspect := "Path: /var/lib/msb/disk.raw\n"
	if got := parseVolumeInspectPath(colonInspect); got != "/var/lib/msb/disk.raw" {
		t.Errorf("parseVolumeInspectPath(colon) = %q", got)
	}
	ansiInspect := "\x1b[1mVolume\x1b[0m agbox-profile-work\n  \x1b[36mPath\x1b[0m   \x1b[32m/custom/vol/disk.raw\x1b[0m\n"
	if got := parseVolumeInspectPath(ansiInspect); got != "/custom/vol/disk.raw" {
		t.Errorf("parseVolumeInspectPath(ansi) = %q", got)
	}
	if got := parseVolumeInspectPath("Path: relative/disk.raw\n"); got != "" {
		t.Errorf("expected relative Path to be rejected, got %q", got)
	}
	if got := parseVolumeInspectPath("Volume work\n  Kind disk\n"); got != "" {
		t.Errorf("expected empty string when Path line is absent, got %q", got)
	}

	tmp := t.TempDir()
	fakeMSB := filepath.Join(tmp, "msb")
	script := `#!/bin/sh
if [ "$1" = "volume" ] && [ "$2" = "inspect" ]; then
  if [ "$3" = "from-inspect" ]; then
    echo "  Path   /inspected/path/disk.raw"
    exit 0
  fi
  exit 1
fi
exit 0
`
	if err := os.WriteFile(fakeMSB, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	runner, err := NewExecRunner(fakeMSB)
	if err != nil {
		t.Fatal(err)
	}

	inspected, err := ResolveVolumeDiskPath(context.Background(), runner, "/fallback/msb", "from-inspect")
	if err != nil || inspected != "/inspected/path/disk.raw" {
		t.Errorf("ResolveVolumeDiskPath(from-inspect) = (%q, %v)", inspected, err)
	}

	fallback, err := ResolveVolumeDiskPath(context.Background(), runner, "/fallback/msb", "agbox-profile-fb")
	if err != nil || fallback != "/fallback/msb/volumes/agbox-profile-fb/disk.raw" {
		t.Errorf("ResolveVolumeDiskPath(fallback) = (%q, %v)", fallback, err)
	}

	if _, err := ResolveVolumeDiskPath(context.Background(), runner, "/bad:msb", "agbox-profile-fb"); err == nil {
		t.Error("expected error for msbHome containing colon")
	}
	if _, err := ResolveVolumeDiskPath(context.Background(), runner, "/fallback/msb", ""); err == nil {
		t.Error("expected error for empty volume name")
	}

	for _, badVol := range []string{".", "..", "a/b", "a\\b", "../escape", "/root", "bad\nvol", "bad\x00vol"} {
		if _, err := ResolveVolumeDiskPath(context.Background(), runner, "/fallback/msb", badVol); err == nil {
			t.Errorf("expected error for bad volume name %q", badVol)
		}
	}

	for _, bad := range []DiskMountSpec{
		{HostPath: "/tmp/disk.raw", GuestPath: GuestProfileMount, Format: "vmdk"},
		{HostPath: "/tmp/disk.raw", GuestPath: GuestProfileMount, FSType: "btrfs"},
	} {
		if _, err := bad.formatFlag(); err == nil {
			t.Errorf("expected DiskMountSpec.formatFlag error for %+v", bad)
		}
	}

	for _, bad := range []VolumeSpec{
		{HostPath: "", GuestPath: "/workspace"},
		{HostPath: "relative", GuestPath: "/workspace"},
		{HostPath: "/tmp/host:bad", GuestPath: "/workspace"},
		{HostPath: "/tmp/host,bad", GuestPath: "/workspace"},
		{HostPath: "/tmp/host\nbad", GuestPath: "/workspace"},
		{HostPath: "/tmp/host", GuestPath: ""},
		{HostPath: "/tmp/host", GuestPath: "relative"},
		{HostPath: "/tmp/host", GuestPath: "/tmp:bad"},
		{HostPath: "/tmp/host", GuestPath: "/tmp,bad"},
		{HostPath: "/tmp/host", GuestPath: "/tmp\x00bad"},
	} {
		if err := bad.validate(); err == nil {
			t.Errorf("expected VolumeSpec.validate error for %+v", bad)
		}
	}
	validVol := VolumeSpec{HostPath: "/tmp/host", GuestPath: "/workspace"}
	if err := validVol.validate(); err != nil {
		t.Errorf("valid VolumeSpec.validate error: %v", err)
	}
	if got := validVol.formatFlag(); got != "/tmp/host:/workspace:rw,stat-virt=off" {
		t.Errorf("rw VolumeSpec with empty StatVirt = %q, want rw,stat-virt=off", got)
	}
	if _, err := BuildRestoreArgs(RestoreOpts{Snapshot: "base", Name: "test", Volumes: []VolumeSpec{{HostPath: "relative", GuestPath: "/workspace"}}}); err == nil {
		t.Error("expected BuildRestoreArgs to reject invalid VolumeSpec")
	}
}

type stubErrorRunner struct {
	err error
}

func (s *stubErrorRunner) Run(ctx context.Context, req CommandRequest) (CommandResult, error) {
	return CommandResult{Stderr: "simulated failure", ExitCode: 1}, s.err
}
