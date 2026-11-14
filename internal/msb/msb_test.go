package msb

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
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
		"--net-rule", "deny@100.100.100.200/32",
		"--net-rule", "deny@168.63.129.16/32",
		"--net-rule", "deny@169.254.0.0/16",
		"--net-rule", "deny@240.0.0.0/4",
		"--net-rule", "deny@[fe80::/10]",
		"--net-rule", "deny@[fd00:ec2::254/128]",
		"--net-rule", "allow@public",
	}
	for _, spec := range []string{"", "public", "public-only", "  public "} {
		got, err := TranslateNetSpec(spec)
		if err != nil {
			t.Fatalf("TranslateNetSpec(%q) unexpected error: %v", spec, err)
		}
		if !slices.Equal(got, publicWant) {
			t.Errorf("TranslateNetSpec(%q) = %v, want %v", spec, got, publicWant)
		}
		assertAllNetRuleTokensValid(t, got)
	}

	// private allows RFC1918/CGNAT/ULA after allowing DNS and blocking host, loopback, link-local, multicast, and cloud-config IMDS CIDRs.
	gotPrivate, err := TranslateNetSpec("private")
	if err != nil {
		t.Fatalf("TranslateNetSpec(private): %v", err)
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
		"--net-rule deny@[fd00:ec2::254/128]",
		"--net-rule allow@public",
		"--net-rule allow@private",
	} {
		if !strings.Contains(privJoined, mustContain) {
			t.Errorf("TranslateNetSpec(private) = %q, missing %q", privJoined, mustContain)
		}
	}
	if strings.Index(privJoined, "allow@dns") > strings.Index(privJoined, "deny@host") {
		t.Errorf("expected allow@dns before deny@host in %q", privJoined)
	}
	if strings.Contains(privJoined, "deny@private") {
		t.Errorf("TranslateNetSpec(private) should not contain deny@private: %q", privJoined)
	}

	// host places allow@host before deny@private while still blocking loopback, multicast, and meta.
	gotHost, err := TranslateNetSpec("host")
	if err != nil {
		t.Fatalf("TranslateNetSpec(host): %v", err)
	}
	assertAllNetRuleTokensValid(t, gotHost)
	hostJoined := strings.Join(gotHost, " ")
	allowHostIdx := strings.Index(hostJoined, "allow@host")
	denyPrivIdx := strings.Index(hostJoined, "deny@private")
	if allowHostIdx < 0 || denyPrivIdx < 0 || allowHostIdx > denyPrivIdx {
		t.Errorf("expected allow@host before deny@private in %q", hostJoined)
	}

	for _, spec := range []string{"all", "allow"} {
		if got, err := TranslateNetSpec(spec); err != nil || !slices.Equal(got, []string{"--net-default", "allow"}) {
			t.Errorf("TranslateNetSpec(%q) = %v, %v", spec, got, err)
		}
	}
	for _, spec := range []string{"none", "deny"} {
		if got, err := TranslateNetSpec(spec); err != nil || !slices.Equal(got, []string{"--no-net"}) {
			t.Errorf("TranslateNetSpec(%q) = %v, %v", spec, got, err)
		}
	}

	// Multi-spec BuildNetArgs must emit --net-default deny once and place user deny@ rules before allow@dns and allow@public.
	multiGot, err := BuildNetArgs(false, []string{"public", "deny@evil.com", "deny@93.184.216.34/32", "allow@example.com:tcp:443"})
	if err != nil {
		t.Fatalf("BuildNetArgs multi-spec: %v", err)
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
	narrowGot, err := TranslateNetSpec("allow@api.anthropic.com:tcp:443")
	if err != nil {
		t.Fatalf("TranslateNetSpec(narrow): %v", err)
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
	metaAliasGot, err := BuildNetArgs(false, []string{"deny@metadata", "allow@metadata.example.com:tcp:443"})
	if err != nil {
		t.Fatalf("BuildNetArgs metadata alias: %v", err)
	}
	assertAllNetRuleTokensValid(t, metaAliasGot)
	if !slices.Contains(metaAliasGot, "deny@meta") || slices.Contains(metaAliasGot, "deny@metadata") {
		t.Errorf("expected deny@metadata to normalize to deny@meta in %v", metaAliasGot)
	}
	if !slices.Contains(metaAliasGot, "allow@metadata.example.com:tcp:443") {
		t.Errorf("expected metadata.example.com domain to be preserved in %v", metaAliasGot)
	}
	allowMetaGot, err := TranslateNetSpec("allow@metadata")
	if err != nil {
		t.Fatalf("TranslateNetSpec(allow@metadata): %v", err)
	}
	assertAllNetRuleTokensValid(t, allowMetaGot)
	if !slices.Contains(allowMetaGot, "allow@meta") || slices.Contains(allowMetaGot, "deny@meta") {
		t.Errorf("expected allow@metadata to permit allow@meta without deny@meta: %v", allowMetaGot)
	}

	// allow:ingress@loopback:tcp:8080 preserves egress deny@loopback.
	ingressGot, err := TranslateNetSpec("allow:ingress@loopback:tcp:8080")
	if err != nil {
		t.Fatalf("TranslateNetSpec(ingress): %v", err)
	}
	assertAllNetRuleTokensValid(t, ingressGot)
	if !slices.Contains(ingressGot, "deny@loopback") || !slices.Contains(ingressGot, "allow:ingress@loopback:tcp:8080") {
		t.Errorf("expected ingress loopback rule to preserve egress deny@loopback: %v", ingressGot)
	}

	for _, badSpec := range []string{
		"invalid-profile",
		"foo@bar",
		"allow@",
		"deny@",
		"allow@example.com --privileged",
		"allow@example.com,deny@",
		"deny@fe80::/10",
		"allow@2001:db8::1",
		"allow@[192.0.2.1]",
		"allow@myhost",
		"deny@*.com",
		"deny@suffix=local",
		"allow@example.com:443",
		"allow@public:tcp:443-80",
		"allow:ingress@dns",
		"allow:ingress@public:icmpv4",
		"allow:any@public:icmpv6",
		"allow@public:tcp:443:extra",
	} {
		if _, err := TranslateNetSpec(badSpec); err == nil {
			t.Errorf("expected error for invalid --net spec %q", badSpec)
		}
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
}

func TestBuildCreateAndRestoreAndExecArgs(t *testing.T) {
	if _, err := BuildCreateArgs(CreateOpts{Name: "agbox-base"}); err == nil {
		t.Fatal("expected error when Image is empty")
	}
	if _, err := BuildCreateArgs(CreateOpts{Image: "debian:bookworm-slim"}); err == nil {
		t.Fatal("expected error when Name is empty")
	}

	createArgs, err := BuildCreateArgs(CreateOpts{
		Image:    "node:24-bookworm-slim",
		Name:     "agbox-base",
		CPUs:     "2",
		Memory:   "2G",
		RootDisk: "8G",
		Workdir:  "/workspace",
	})
	if err != nil {
		t.Fatalf("BuildCreateArgs: %v", err)
	}
	wantCreate := []string{
		"create", "node:24-bookworm-slim",
		"--name", "agbox-base",
		"--cpus", "2",
		"--memory", "2G",
		"--root-disk", "8G",
		"--workdir", "/workspace",
		"--mkdir", "/workspace",
	}
	if !slices.Equal(createArgs, wantCreate) {
		t.Errorf("createArgs = %v, want %v", createArgs, wantCreate)
	}

	createNetArgs, err := BuildCreateArgs(CreateOpts{
		Image:    "debian:bookworm-slim",
		Name:     "agbox-base",
		NetSpecs: []string{"public"},
	})
	if err != nil || !slices.Contains(createNetArgs, "deny@meta") || !slices.Contains(createNetArgs, "deny@168.63.129.16/32") || !slices.Contains(createNetArgs, "allow@dns") {
		t.Errorf("expected BuildCreateArgs with NetSpecs=[public] to include meta/cloud-config denies and allow@dns: %v, %v", createNetArgs, err)
	}
	assertAllNetRuleTokensValid(t, createNetArgs)

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
		NamedVolumes: []NamedVolumeSpec{
			{VolumeName: "agbox-profile-work", GuestPath: GuestProfileMount},
		},
		Volumes: []VolumeSpec{
			{HostPath: "/tmp/mnt0", GuestPath: "/workspace/proj", ReadOnly: false},
			{HostPath: "/tmp/file.txt", GuestPath: "/workspace/file.txt", ReadOnly: true},
		},
		Ports:    []string{"127.0.0.1:4096:3000"},
		NoNet:    false,
		NetSpecs: []string{"public", "allow@example.com:tcp:443"},
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
		"-v agbox-profile-work:/home/agent/.agbox-profile",
		"-v /tmp/mnt0:/workspace/proj:rw,uid=1000,gid=1000",
		"-v /tmp/file.txt:/workspace/file.txt:ro,uid=1000,gid=1000",
		"-p 127.0.0.1:4096:3000",
		"--net-default deny --net-rule allow@dns --net-rule deny@host --net-rule deny@loopback --net-rule deny@private --net-rule deny@link-local --net-rule deny@multicast --net-rule deny@meta",
		"--net-rule deny@168.63.129.16/32",
		"--net-rule deny@100.100.100.200/32",
		"--net-rule deny@[fd00:ec2::254/128]",
		"--net-rule allow@public",
		"--net-rule allow@example.com:tcp:443",
		"--net-rule allow:ingress@loopback:tcp:3000",
	} {
		if !strings.Contains(joined, substr) {
			t.Errorf("restoreArgs %q missing %q", joined, substr)
		}
	}

	defaultNetArgs, err := BuildRestoreArgs(RestoreOpts{
		Snapshot: "agbox:v1",
		Name:     "agbox-run-default",
	})
	if err != nil {
		t.Fatalf("BuildRestoreArgs default net: %v", err)
	}
	assertAllNetRuleTokensValid(t, defaultNetArgs)
	defaultNetJoined := strings.Join(defaultNetArgs, " ")
	for _, must := range []string{
		"--net-default deny",
		"--net-rule allow@dns",
		"--net-rule deny@host",
		"--net-rule deny@loopback",
		"--net-rule deny@private",
		"--net-rule deny@link-local",
		"--net-rule deny@multicast",
		"--net-rule deny@meta",
		"--net-rule deny@168.63.129.16/32",
		"--net-rule deny@[fd00:ec2::254/128]",
		"--net-rule allow@public",
	} {
		if !strings.Contains(defaultNetJoined, must) {
			t.Errorf("expected %q in default net policy %q", must, defaultNetJoined)
		}
	}

	noNetArgs, err := BuildRestoreArgs(RestoreOpts{
		Snapshot: "agbox:v1",
		Name:     "agbox-run-2",
		NoNet:    true,
	})
	if err != nil || !slices.Contains(noNetArgs, "--no-net") {
		t.Errorf("expected --no-net in %v (err=%v)", noNetArgs, err)
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
	assertAllNetRuleTokensValid(t, noNetServeArgs)
	if !slices.Contains(noNetServeArgs, "--no-net") || !slices.Contains(noNetServeArgs, "allow:ingress@loopback:tcp:3000") {
		t.Errorf("expected --no-net and loopback ingress rule in %v", noNetServeArgs)
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

	for _, badPort := range []string{"bad", "3000", "127.0.0.1:0:3000", "127.0.0.1:4096:99999", "127.0.0.1:4096:3000/icmp", "badip:4096:3000"} {
		if _, err := BuildRestoreArgs(RestoreOpts{
			Snapshot: "agbox:v1",
			Name:     "agbox-run-badport",
			Ports:    []string{badPort},
		}); err == nil {
			t.Errorf("expected error for malformed port spec %q", badPort)
		}
	}

	execArgs := BuildExecArgs(ExecCmdOpts{
		Sandbox: "agbox-run-99",
		Workdir: "/workspace/proj",
		User:    GuestUser,
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
		"-e", "PATH=" + GuestDefaultPath,
		"-e", "SSH_CONNECTION=1",
		"agbox-run-99",
		"--",
		"bash", "-c", "id",
	}
	if !slices.Equal(execArgs, wantExec) {
		t.Errorf("BuildExecArgs = %v, want %v", execArgs, wantExec)
	}

	streamArgs := BuildExecArgs(ExecCmdOpts{
		Sandbox: "agbox-run-99",
		Stream:  true,
		Command: []string{"id"},
	})
	if !slices.Contains(streamArgs, "--stream") {
		t.Errorf("expected --stream in %v", streamArgs)
	}
}

func TestCategoriesAndResolution(t *testing.T) {
	cats, err := ResolveCategories([]string{"core,golang", "4", "embedded-rust", "chrome", "hugo", "caddy"})
	if err != nil {
		t.Fatalf("ResolveCategories: %v", err)
	}
	var gotNames []string
	for _, c := range cats {
		gotNames = append(gotNames, c.Name)
	}
	// embedded-rust automatically includes rust. Index 4 is esphome.
	wantNames := []string{"core", "go", "rust", "esphome", "embedded-rust", "chrome", "hugo", "caddy"}
	if !slices.Equal(gotNames, wantNames) {
		t.Fatalf("ResolveCategories names = %v, want %v", gotNames, wantNames)
	}

	// Selecting caddy alone must automatically pull in go.
	caddyOnly, err := ResolveCategories([]string{"caddy"})
	if err != nil || len(caddyOnly) != 2 || caddyOnly[0].Name != "go" || caddyOnly[1].Name != "caddy" {
		t.Fatalf("ResolveCategories(caddy) = %+v, %v", caddyOnly, err)
	}

	allCats, err := ResolveCategories([]string{"all"})
	if err != nil || len(allCats) != len(Categories()) {
		t.Fatalf("ResolveCategories(all) = %d cats, err=%v", len(allCats), err)
	}

	if _, err := ResolveCategories([]string{"nonexistent-cat"}); err == nil {
		t.Fatal("expected error for unknown category")
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
}

func TestParseSandboxAndSnapshotLists(t *testing.T) {
	lsOut := `
NAME             STATE     CPUS   MEMORY
----             -----     ----   ------
agbox-base       stopped   2      2048 MiB
agbox-run-1234   running   2      2048 MiB
`
	sbs := ParseSandboxList(lsOut)
	if len(sbs) != 2 {
		t.Fatalf("len(sbs) = %d, want 2", len(sbs))
	}
	if sb, ok := FindSandbox(sbs, "agbox-base"); !ok || sb.Running {
		t.Errorf("agbox-base = %+v, ok=%v", sb, ok)
	}
	if sb, ok := FindSandbox(sbs, "agbox-run-1234"); !ok || !sb.Running {
		t.Errorf("agbox-run-1234 = %+v, ok=%v", sb, ok)
	}
	if _, ok := FindSandbox(sbs, "missing"); ok {
		t.Error("expected missing sandbox not to be found")
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
	if next := NextSnapshotVersion(snaps, "agbox"); next != 4 {
		t.Errorf("NextSnapshotVersion = %d, want 4", next)
	}
	if next := NextSnapshotVersion(nil, "agbox"); next != 1 {
		t.Errorf("NextSnapshotVersion(nil) = %d, want 1", next)
	}

	volOut := `
NAME                 KIND   SIZE
----                 ----   ----
agbox-profile-work   disk   10 GiB
other-vol            dir    -
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
	script := "#!/bin/sh\nif [ \"$1\" = \"snap\" ] && [ \"$2\" = \"ls\" ]; then\n  echo \"agbox:v1 1m 100M\"\n  exit 0\nfi\nif [ \"$1\" = \"volume\" ] && [ \"$2\" = \"ls\" ]; then\n  echo \"agbox-profile-work disk 10G\"\n  exit 0\nfi\necho \"err\" >&2\nexit 3\n"
	if err := os.WriteFile(fakeMSB, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}

	runner, err := NewExecRunner(fakeMSB)
	if err != nil {
		t.Fatalf("NewExecRunner: %v", err)
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
	if err == nil || res.ExitCode != 3 {
		t.Fatalf("expected exit code 3 on failure, got res=%+v, err=%v", res, err)
	}

	extraBin := filepath.Join(tmp, "usr-local-msb")
	if err := os.WriteFile(extraBin, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	noLook := func(string) (string, error) { return "", os.ErrNotExist }
	resolved, err := resolveBinaryWith("", noLook, filepath.Join(tmp, "nohome"), []string{extraBin})
	if err != nil || resolved != extraBin {
		t.Errorf("resolveBinaryWith extra fallback = %q, %v", resolved, err)
	}
	if _, err := resolveBinaryWith("", noLook, filepath.Join(tmp, "nohome"), nil); err == nil {
		t.Error("expected error when msb is missing from all locations")
	}
}

func TestSecretShellInjectionResistanceAndCategoryTLS(t *testing.T) {
	canary := filepath.Join(t.TempDir(), "pwned")
	secretMap := map[string]string{
		"ANTHROPIC_API_KEY": "sk-ant-'$(touch " + canary + ")'\"`touch " + canary + "`\"",
		"OPENAI_API_KEY":    "line1\nexport INJECTED=1\n$HOME; echo pwn > " + canary,
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

	// Execute the generated export script in real /bin/sh and verify literal values and zero command execution.
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

	// Verify every curl command in all category install scripts enforces HTTPS and TLS 1.2+.
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
			if !strings.Contains(trimmed, "--proto") || !strings.Contains(trimmed, "=https") || !strings.Contains(trimmed, "--tlsv1.2") {
				t.Errorf("category curl command missing --proto '=https' --tlsv1.2: %s", trimmed)
			}
			if strings.Contains(trimmed, "http://") {
				t.Errorf("category curl command uses plaintext http://: %s", trimmed)
			}
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
