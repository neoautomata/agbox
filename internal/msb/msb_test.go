package msb

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestTranslateNetSpec(t *testing.T) {
	publicWant := []string{"--net-default", "deny", "--net-rule", "allow@public"}
	for _, spec := range []string{"", "public", "public-only", "  public "} {
		got, err := TranslateNetSpec(spec)
		if err != nil {
			t.Fatalf("TranslateNetSpec(%q) unexpected error: %v", spec, err)
		}
		if !slices.Equal(got, publicWant) {
			t.Errorf("TranslateNetSpec(%q) = %v, want %v", spec, got, publicWant)
		}
	}

	if got, err := TranslateNetSpec("private"); err != nil || !slices.Equal(got, []string{"--net-default", "deny", "--net-rule", "allow@public,allow@private"}) {
		t.Errorf("TranslateNetSpec(private) = %v, %v", got, err)
	}
	if got, err := TranslateNetSpec("host"); err != nil || !slices.Equal(got, []string{"--net-default", "deny", "--net-rule", "allow@public,allow@host"}) {
		t.Errorf("TranslateNetSpec(host) = %v, %v", got, err)
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
	if got, err := TranslateNetSpec("allow@example.com:tcp:443"); err != nil || !slices.Equal(got, []string{"--net-default", "deny", "--net-rule", "allow@example.com:tcp:443"}) {
		t.Errorf("TranslateNetSpec(custom rule) = %v, %v", got, err)
	}
	if _, err := TranslateNetSpec("invalid-profile"); err == nil {
		t.Fatal("expected error for unsupported network profile")
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
	joined := strings.Join(restoreArgs, " ")
	for _, substr := range []string{
		"snap restore agbox:v2",
		"--name agbox-run-99 -u agent",
		"--cpus 4 --memory 4G",
		"-v /tmp/mnt0:/workspace/proj:rw,uid=1000,gid=1000",
		"-v /tmp/file.txt:/workspace/file.txt:ro,uid=1000,gid=1000",
		"-p 127.0.0.1:4096:3000",
		"--net-default deny --net-rule allow@public",
		"--net-rule allow@example.com:tcp:443",
	} {
		if !strings.Contains(joined, substr) {
			t.Errorf("restoreArgs %q missing %q", joined, substr)
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
		"agbox-run-99",
		"--",
		"bash", "-c", "id",
	}
	if !slices.Equal(execArgs, wantExec) {
		t.Errorf("BuildExecArgs = %v, want %v", execArgs, wantExec)
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
}

func TestProvisionScriptAndExecRunner(t *testing.T) {
	pScript := ProvisionGuestUserScript()
	if !strings.Contains(pScript, "NOPASSWD: ALL") || !strings.Contains(pScript, "/usr/local/bin/agy") {
		t.Errorf("unexpected provision script: %s", pScript)
	}

	tmp := t.TempDir()
	fakeMSB := filepath.Join(tmp, "msb")
	script := "#!/bin/sh\nif [ \"$1\" = \"snap\" ] && [ \"$2\" = \"ls\" ]; then\n  echo \"agbox:v1 1m 100M\"\n  exit 0\nfi\necho \"err\" >&2\nexit 3\n"
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

	res, err := runner.Run(context.Background(), CommandRequest{Args: []string{"fail"}})
	if err == nil || res.ExitCode != 3 {
		t.Fatalf("expected exit code 3 on failure, got res=%+v, err=%v", res, err)
	}
}
