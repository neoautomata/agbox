package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"agbox/internal/complete"
	"agbox/internal/config"
	"agbox/internal/service"
)

func TestCompletionCommand(t *testing.T) {
	var stdout, stderr bytes.Buffer
	app := &appRuntime{
		Env:    config.Env{DataDir: t.TempDir()},
		Stdout: &stdout,
		Stderr: &stderr,
	}

	if rc := app.dispatch(context.Background(), []string{"completion", "bash"}); rc != 0 {
		t.Fatalf("completion bash exited %d, stderr=%q", rc, stderr.String())
	}
	if !strings.Contains(stdout.String(), "complete -F _agbox_completions agbox") {
		t.Fatalf("unexpected completion bash stdout: %q", stdout.String())
	}

	stdout.Reset()
	stderr.Reset()
	if rc := app.dispatch(context.Background(), []string{"completion", "--allow-root", "bash"}); rc != 0 {
		t.Fatalf("completion --allow-root bash exited %d, stderr=%q", rc, stderr.String())
	}
	if !strings.Contains(stdout.String(), "_agbox_completions") {
		t.Fatalf("unexpected completion --allow-root bash stdout: %q", stdout.String())
	}

	stdout.Reset()
	stderr.Reset()
	if rc := app.dispatch(context.Background(), []string{"completion", "--help"}); rc != 0 {
		t.Fatalf("completion --help exited %d, stderr=%q", rc, stderr.String())
	}
	if !strings.Contains(stdout.String(), "agbox completion") {
		t.Fatalf("unexpected completion --help stdout: %q", stdout.String())
	}

	for _, bad := range [][]string{
		{"completion"},
		{"completion", "zsh"},
		{"completion", "--bogus", "bash"},
	} {
		stdout.Reset()
		stderr.Reset()
		if rc := app.dispatch(context.Background(), bad); rc == 0 {
			t.Errorf("expected non-zero exit for %v", bad)
		}
		if !strings.Contains(stderr.String(), "[agbox] ERROR:") {
			t.Errorf("expected error message for %v, got %q", bad, stderr.String())
		}
	}
}

func TestHiddenCompleteDynamicProviders(t *testing.T) {
	dataDir := t.TempDir()

	// Seed a skill, a rule, a profile, a running sandbox, a suspended sandbox, and a deleting sandbox.
	skillDir := filepath.Join(dataDir, "skills", "code-review")
	if err := os.MkdirAll(skillDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(skillDir, "SKILL.md"), []byte("# skill\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	rulesDir := filepath.Join(dataDir, "rules")
	if err := os.MkdirAll(rulesDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(rulesDir, "style.md"), []byte("# style\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	profDir := filepath.Join(dataDir, "profiles", "work")
	if err := os.MkdirAll(profDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(profDir, "profile.json"), []byte(`{"name":"work","volume":"agbox-profile-work","size":"10G"}`), 0o600); err != nil {
		t.Fatal(err)
	}

	runningDir := filepath.Join(dataDir, "run", "live")
	if err := os.MkdirAll(runningDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := config.SaveRunMeta(filepath.Join(runningDir, "run.meta"), config.RunMeta{
		Sandbox:      "agbox-live",
		WorkspaceHub: true,
		Shares: []config.ShareRecord{
			{GuestName: "repo-a", HostPath: "/tmp/a"},
			{GuestName: "repo-b", HostPath: "/tmp/b"},
		},
	}); err != nil {
		t.Fatal(err)
	}

	suspDir := filepath.Join(dataDir, "run", "paused")
	if err := os.MkdirAll(suspDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := config.SaveRunMeta(filepath.Join(suspDir, "suspended"), config.RunMeta{
		Sandbox: "agbox-paused",
	}); err != nil {
		t.Fatal(err)
	}

	delDir := filepath.Join(dataDir, "run", "dying")
	if err := os.MkdirAll(delDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := config.SaveRunMeta(filepath.Join(delDir, "run.meta"), config.RunMeta{Sandbox: "agbox-dying"}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(delDir, "deleting"), []byte("1\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	runComplete := func(args ...string) string {
		var stdout, stderr bytes.Buffer
		app := &appRuntime{
			Env:    config.Env{DataDir: dataDir},
			Stdout: &stdout,
			Stderr: &stderr,
		}
		fullArgs := append([]string{complete.SubcommandName, "--"}, args...)
		if rc := app.dispatch(context.Background(), fullArgs); rc != 0 {
			t.Fatalf("__complete %v exited %d, stderr=%q", args, rc, stderr.String())
		}
		if stderr.Len() != 0 {
			t.Fatalf("__complete %v wrote unexpected stderr: %q", args, stderr.String())
		}
		return stdout.String()
	}

	if got := runComplete("skills", "rm", ""); got != "code-review\n:nofiles\n" {
		t.Errorf("skills rm = %q", got)
	}
	if got := runComplete("rules", "show", ""); got != "style\n:nofiles\n" {
		t.Errorf("rules show = %q", got)
	}
	if got := runComplete("run", "--profile", ""); got != "work\n:nofiles\n" {
		t.Errorf("run --profile = %q", got)
	}
	if got := runComplete("suspend", ""); got != "agbox-live\n:nofiles\n" {
		t.Errorf("suspend = %q", got)
	}
	if got := runComplete("resume", ""); got != "agbox-paused\n:nofiles\n" {
		t.Errorf("resume = %q", got)
	}
	if got := runComplete("stop", ""); got != "agbox-live\nagbox-paused\n:nofiles\n" {
		t.Errorf("stop = %q", got)
	}
	if got := runComplete("share", "rm", "agbox-live", ""); got != "repo-a\nrepo-b\n:nofiles\n" {
		t.Errorf("share rm = %q", got)
	}
}

func TestHiddenCompleteLiveHubSocketAndTimeoutFallback(t *testing.T) {
	dataDir := t.TempDir()
	runDir := filepath.Join(dataDir, "run", "hubtest")
	if err := os.MkdirAll(runDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := config.SaveRunMeta(filepath.Join(runDir, "run.meta"), config.RunMeta{
		Sandbox:      "agbox-hubtest",
		WorkspaceHub: true,
		Shares:       []config.ShareRecord{{GuestName: "fallback-share", HostPath: "/tmp/fallback"}},
	}); err != nil {
		t.Fatal(err)
	}

	sockPath := filepath.Join(runDir, "ws.sock")
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("listen unix: %v", err)
	}
	defer ln.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, acceptErr := ln.Accept()
		if acceptErr != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 1024)
		_, _ = conn.Read(buf)
		resp, _ := json.Marshal(map[string]any{
			"ok": true,
			"shares": []map[string]any{
				{"guest_name": "live-zeta"},
				{"guest_name": "live-alpha"},
			},
		})
		_, _ = conn.Write(resp)
	}()

	gotLive := listCompletionShares(dataDir, "agbox-hubtest", 500*time.Millisecond)
	<-done
	if strings.Join(gotLive, ",") != "live-alpha,live-zeta" {
		t.Fatalf("listCompletionShares live = %v, want [live-alpha live-zeta]", gotLive)
	}

	// Simulate a stalled hub socket and verify fast timeout fallback to run.meta.
	stalled := make(chan struct{})
	go func() {
		conn, acceptErr := ln.Accept()
		if acceptErr != nil {
			return
		}
		<-stalled
		_ = conn.Close()
	}()
	defer close(stalled)

	start := time.Now()
	gotFallback := listCompletionShares(dataDir, "agbox-hubtest", 50*time.Millisecond)
	elapsed := time.Since(start)
	if strings.Join(gotFallback, ",") != "fallback-share" {
		t.Fatalf("listCompletionShares timeout fallback = %v, want [fallback-share]", gotFallback)
	}
	if elapsed > 2*time.Second {
		t.Fatalf("timeout fallback took too long: %v", elapsed)
	}
}

func TestHiddenCompleteMissingDataDirDoesNotCreate(t *testing.T) {
	missingDir := filepath.Join(t.TempDir(), "does-not-exist")
	var stdout, stderr bytes.Buffer
	app := &appRuntime{
		Env:    config.Env{DataDir: missingDir},
		Stdout: &stdout,
		Stderr: &stderr,
	}

	if rc := app.dispatch(context.Background(), []string{complete.SubcommandName, "--", "profile", "rm", ""}); rc != 0 {
		t.Fatalf("expected exit 0, got %d", rc)
	}
	if stdout.String() != ":nofiles\n" {
		t.Fatalf("unexpected stdout: %q", stdout.String())
	}
	if _, err := os.Stat(missingDir); !os.IsNotExist(err) {
		t.Fatalf("expected %s to remain absent, stat err=%v", missingDir, err)
	}
}

func TestCompletionRootGuardSuspendedPrecedenceServicesAndSymlinkRunDir(t *testing.T) {
	// 1. Root guard on `agbox completion bash` without --allow-root.
	var stdout, stderr bytes.Buffer
	rootApp := &appRuntime{
		Env:     config.Env{DataDir: t.TempDir()},
		Stdout:  &stdout,
		Stderr:  &stderr,
		GetEUID: func() int { return 0 },
	}
	if rc := rootApp.dispatch(context.Background(), []string{"completion", "bash"}); rc == 0 {
		t.Fatal("expected completion bash as root without --allow-root to fail")
	}
	if !strings.Contains(stderr.String(), "do not run as root") {
		t.Fatalf("expected root guard error, got %q", stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	if rc := rootApp.dispatch(context.Background(), []string{"completion", "--allow-root", "bash"}); rc != 0 {
		t.Fatalf("expected completion --allow-root bash to succeed, rc=%d stderr=%q", rc, stderr.String())
	}
	if !strings.Contains(stdout.String(), "_agbox_completions") {
		t.Fatalf("unexpected completion output: %q", stdout.String())
	}

	// 2. Suspended sandbox with both run.meta and suspended: hide from running and read shares from suspended.
	dataDir := t.TempDir()
	bothDir := filepath.Join(dataDir, "run", "dual")
	if err := os.MkdirAll(bothDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := config.SaveRunMeta(filepath.Join(bothDir, "run.meta"), config.RunMeta{
		Sandbox:      "agbox-dual",
		WorkspaceHub: true,
		Shares:       []config.ShareRecord{{GuestName: "stale-share", HostPath: "/tmp/stale"}},
	}); err != nil {
		t.Fatal(err)
	}
	if err := config.SaveRunMeta(filepath.Join(bothDir, "suspended"), config.RunMeta{
		Sandbox:      "agbox-dual",
		WorkspaceHub: true,
		Shares:       []config.ShareRecord{{GuestName: "fresh-share", HostPath: "/tmp/fresh"}},
	}); err != nil {
		t.Fatal(err)
	}

	if got := listCompletionSandboxes(dataDir, complete.SandboxRunning); len(got) != 0 {
		t.Errorf("SandboxRunning returned suspended sandbox with run.meta: %v", got)
	}
	if got := listCompletionSandboxes(dataDir, complete.SandboxSuspended); strings.Join(got, ",") != "agbox-dual" {
		t.Errorf("SandboxSuspended = %v, want [agbox-dual]", got)
	}
	if got := listCompletionSandboxes(dataDir, complete.SandboxAll); strings.Join(got, ",") != "agbox-dual" {
		t.Errorf("SandboxAll = %v, want [agbox-dual]", got)
	}
	if got := listCompletionShares(dataDir, "agbox-dual", 50*time.Millisecond); strings.Join(got, ",") != "fresh-share" {
		t.Errorf("listCompletionShares = %v, want [fresh-share] from suspended", got)
	}

	// 3. listCompletionServices returns sorted service names via __complete.
	for _, svcName := range []string{"zeta", "alpha"} {
		if err := service.SaveSpec(dataDir, service.Spec{
			Name:  svcName,
			Agent: "antigravity",
			Mode:  config.RunModeRemoteControl,
		}); err != nil {
			t.Fatal(err)
		}
	}
	stdout.Reset()
	stderr.Reset()
	svcApp := &appRuntime{
		Env:    config.Env{DataDir: dataDir},
		Stdout: &stdout,
		Stderr: &stderr,
	}
	if rc := svcApp.dispatch(context.Background(), []string{complete.SubcommandName, "--", "service", "start", ""}); rc != 0 {
		t.Fatalf("__complete service start exited %d, stderr=%q", rc, stderr.String())
	}
	if stdout.String() != "alpha\nzeta\n:nofiles\n" {
		t.Errorf("__complete service start = %q, want alpha/zeta", stdout.String())
	}

	// 4. Symlinked run/ directory is ignored safely.
	symData := t.TempDir()
	realRun := filepath.Join(t.TempDir(), "real-run")
	if err := os.MkdirAll(filepath.Join(realRun, "leak"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := config.SaveRunMeta(filepath.Join(realRun, "leak", "run.meta"), config.RunMeta{Sandbox: "agbox-leak"}); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(realRun, filepath.Join(symData, "run")); err != nil {
		t.Fatal(err)
	}
	if got := listCompletionSandboxes(symData, complete.SandboxAll); len(got) != 0 {
		t.Errorf("listCompletionSandboxes followed symlinked run/ dir: %v", got)
	}
}
