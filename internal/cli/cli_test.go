package cli

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"agbox/internal/config"
	"agbox/internal/mounttab"
	"agbox/internal/msb"
	"agbox/internal/persist"
)

func TestParseCreateBaseArgs(t *testing.T) {
	opts, err := ParseCreateBaseArgs([]string{"--force", "--add", "core,go,rust,esphome", "opencode"})
	if err != nil || opts.Agent != "opencode" || !opts.Force || len(opts.Categories) != 4 {
		t.Fatalf("ParseCreateBaseArgs(--force --add ... opencode) = %+v, %v", opts, err)
	}
	for _, agent := range []string{"antigravity", "both"} {
		opts, err := ParseCreateBaseArgs([]string{agent})
		if err != nil || opts.Agent != agent || opts.Force {
			t.Fatalf("ParseCreateBaseArgs(%s) = %+v, %v", agent, opts, err)
		}
	}
	if _, err := ParseCreateBaseArgs([]string{"--help"}); !errors.Is(err, ErrHelp) {
		t.Errorf("expected ErrHelp, got %v", err)
	}
	for _, bad := range [][]string{
		{},
		{"unknown"},
		{"--unknown", "opencode"},
		{"--add", "", "opencode"},
		{"--add", "badcat", "opencode"},
		{"opencode", "extra"},
	} {
		if _, err := ParseCreateBaseArgs(bad); err == nil {
			t.Errorf("expected error for %v", bad)
		}
	}
}

func TestParseEditBaseArgs(t *testing.T) {
	opts, err := ParseEditBaseArgs([]string{"--add", "core,go", "rust", "esphome", "--cmd", "apt-get install -y jq", "--no-snap"})
	if err != nil || opts.Cmd != "apt-get install -y jq" || !opts.NoSnap || len(opts.Categories) != 4 {
		t.Fatalf("ParseEditBaseArgs = %+v, %v", opts, err)
	}
	listOpts, err := ParseEditBaseArgs([]string{"--list"})
	if err != nil || !listOpts.ListOnly {
		t.Fatalf("ParseEditBaseArgs(--list) = %+v, %v", listOpts, err)
	}
	if _, err := ParseEditBaseArgs([]string{"-h"}); !errors.Is(err, ErrHelp) {
		t.Errorf("expected ErrHelp, got %v", err)
	}
	for _, bad := range [][]string{
		{"--cmd"},
		{"--cmd", ""},
		{"--add"},
		{"--add", "unknown-category"},
		{"--unknown"},
	} {
		if _, err := ParseEditBaseArgs(bad); err == nil {
			t.Errorf("expected error for %v", bad)
		}
	}
}

func TestParseRunArgsAndSelectEffectiveAgent(t *testing.T) {
	exists := func(p string) bool { return p == "opencode" }

	// Options appear before paths.
	opts, err := ParseRunArgs([]string{
		"--ro", "--mask-vcs",
		"--cpus", "4", "--memory", "4G",
		"--net", "public", "--net-rule", "allow@example.com:tcp:443",
		"antigravity", "./proj",
		"--", "-weird-file",
	}, config.MaskAuto, exists)
	if err != nil {
		t.Fatalf("ParseRunArgs: %v", err)
	}
	if opts.Agent != "antigravity" || !opts.ReadOnly || opts.MaskMode != config.MaskStrict || opts.CPUs != "4" || opts.Memory != "4G" {
		t.Errorf("unexpected opts: %+v", opts)
	}
	if !slices.Equal(opts.Paths, []string{"./proj", "-weird-file"}) {
		t.Errorf("unexpected paths: %v", opts.Paths)
	}

	// Second "opencode" token after a path when "opencode" exists on disk should be treated as a path.
	opts2, err := ParseRunArgs([]string{"./proj", "opencode"}, config.MaskAuto, exists)
	if err != nil || opts2.Agent != "" || !slices.Equal(opts2.Paths, []string{"./proj", "opencode"}) {
		t.Errorf("expected 'opencode' after path to be treated as path when it exists on disk: %+v, %v", opts2, err)
	}

	// Passing an option after a path must fail.
	if _, err := ParseRunArgs([]string{"./proj", "--ro"}, config.MaskAuto, nil); err == nil || !strings.Contains(err.Error(), "options must come before paths") {
		t.Errorf("expected error when option follows path, got %v", err)
	}

	// --port and --probe imply --serve.
	optsServe, err := ParseRunArgs([]string{"--port", "8080", "--probe", "--no-mask", "--no-net"}, config.MaskAuto, nil)
	if err != nil || !optsServe.Serve || !optsServe.Probe || optsServe.Port != 8080 || optsServe.MaskMode != config.MaskOff || !optsServe.NoNet {
		t.Errorf("unexpected serve opts: %+v, %v", optsServe, err)
	}

	if _, err := ParseRunArgs([]string{"--help"}, config.MaskAuto, nil); !errors.Is(err, ErrHelp) {
		t.Errorf("expected ErrHelp, got %v", err)
	}

	for _, bad := range [][]string{
		{"--serve", "--cmd", "id"},
		{"--remote-control", "--serve"},
		{"--remote-control", "--cmd", "id"},
		{"-d"},
		{"--detach", "antigravity"},
		{"--port"},
		{"--port", "0"},
		{"--port", "70000"},
		{"--cpus", "0"},
		{"--cpus", "abc"},
		{"--memory"},
		{"--memory", "0G"},
		{"--memory", "bad"},
		{"--net"},
		{"--cmd"},
		{"--unknown-flag"},
	} {
		if _, err := ParseRunArgs(bad, config.MaskAuto, nil); err == nil {
			t.Errorf("expected error for %v", bad)
		}
	}

	optsRC, err := ParseRunArgs([]string{"-d", "--remote-control", "./proj"}, config.MaskAuto, nil)
	if err != nil || !optsRC.RemoteControl || !optsRC.Detach {
		t.Errorf("unexpected remote-control opts: %+v, %v", optsRC, err)
	}

	// SelectEffectiveAgent tests.
	if ag, err := SelectEffectiveAgent("both", RunOpts{Serve: true}); err != nil || ag != "opencode" {
		t.Errorf("SelectEffectiveAgent(both, Serve) = %q, %v", ag, err)
	}
	if ag, err := SelectEffectiveAgent("both", RunOpts{RemoteControl: true}); err != nil || ag != "antigravity" {
		t.Errorf("SelectEffectiveAgent(both, RemoteControl) = %q, %v", ag, err)
	}
	if _, err := SelectEffectiveAgent("opencode", RunOpts{RemoteControl: true}); err == nil {
		t.Error("expected error when --remote-control used with opencode-only base")
	}
	if _, err := SelectEffectiveAgent("both", RunOpts{Agent: "opencode", RemoteControl: true}); err == nil {
		t.Error("expected error when --remote-control used with opencode agent")
	}
	if _, err := SelectEffectiveAgent("both", RunOpts{}); err == nil {
		t.Error("expected error when base=both and no agent specified for TUI")
	}
	if _, err := SelectEffectiveAgent("antigravity", RunOpts{Serve: true}); err == nil {
		t.Error("expected error when --serve used with antigravity-only base")
	}
	if _, err := SelectEffectiveAgent("opencode", RunOpts{Agent: "antigravity"}); err == nil {
		t.Error("expected error when requesting antigravity on opencode-only base")
	}
	if ag, err := SelectEffectiveAgent("antigravity", RunOpts{}); err != nil || ag != "antigravity" {
		t.Errorf("SelectEffectiveAgent(antigravity) = %q, %v", ag, err)
	}
}

func TestParseStopAndRemoveArgsAndHelpers(t *testing.T) {
	if name, err := ParseStopArgs([]string{"agbox-run-1234"}); err != nil || name != "agbox-run-1234" {
		t.Errorf("ParseStopArgs = %q, %v", name, err)
	}
	if _, err := ParseStopArgs([]string{"-h"}); !errors.Is(err, ErrHelp) {
		t.Errorf("expected ErrHelp, got %v", err)
	}
	for _, bad := range [][]string{
		{},
		{"agbox-base"},
		{"other-sandbox"},
	} {
		if _, err := ParseStopArgs(bad); err == nil {
			t.Errorf("expected error for %v", bad)
		}
	}

	if yes, err := ParseRemoveArgs([]string{"--yes"}); err != nil || !yes {
		t.Errorf("ParseRemoveArgs(--yes) = %v, %v", yes, err)
	}
	if yes, err := ParseRemoveArgs(nil); err != nil || yes {
		t.Errorf("ParseRemoveArgs(nil) = %v, %v", yes, err)
	}
	if _, err := ParseRemoveArgs([]string{"--bad"}); err == nil {
		t.Error("expected error for --bad")
	}

	if !DataDirSupportsFilter("/home/user/.local/share/agbox") {
		t.Error("expected standard path to support filter")
	}
	if DataDirSupportsFilter("/home/user/with space/agbox") || DataDirSupportsFilter(`C:\agbox`) || DataDirSupportsFilter("") {
		t.Error("expected path with space/backslash/empty to fail DataDirSupportsFilter")
	}

	port, err := PickFreeLoopbackPort()
	if err != nil || port < 1 || port > 65535 {
		t.Fatalf("PickFreeLoopbackPort = %d, %v", port, err)
	}

	if sz, ok := parseSizeBytes("50G"); !ok || sz != 50*1024*1024*1024 {
		t.Errorf("parseSizeBytes(50G) = %d, %v", sz, ok)
	}
	if sz, ok := parseSizeBytes("512M"); !ok || sz != 512*1024*1024 {
		t.Errorf("parseSizeBytes(512M) = %d, %v", sz, ok)
	}
	if _, ok := parseSizeBytes("invalid"); ok {
		t.Error("expected parseSizeBytes(invalid) to fail")
	}
}

type recordedCall struct {
	Args  []string
	Stdin string
}

type fakeMSBRunner struct {
	calls     []recordedCall
	sandboxes string
	snapshots string
	handler   func(req msb.CommandRequest) (msb.CommandResult, error)
}

func (f *fakeMSBRunner) Run(_ context.Context, req msb.CommandRequest) (msb.CommandResult, error) {
	var stdinStr string
	if req.Stdin != nil {
		raw, _ := io.ReadAll(req.Stdin)
		stdinStr = string(raw)
	}
	f.calls = append(f.calls, recordedCall{Args: slices.Clone(req.Args), Stdin: stdinStr})

	if f.handler != nil {
		return f.handler(req)
	}
	if len(req.Args) >= 1 && req.Args[0] == "--version" {
		return msb.CommandResult{Stdout: "msb 0.7.14\n"}, nil
	}
	if len(req.Args) >= 1 && req.Args[0] == "ls" {
		return msb.CommandResult{Stdout: f.sandboxes}, nil
	}
	if len(req.Args) >= 2 && req.Args[0] == "snap" && req.Args[1] == "ls" {
		return msb.CommandResult{Stdout: f.snapshots}, nil
	}
	if len(req.Args) >= 1 && req.Args[0] == "exec" && slices.Contains(req.Args, "echo SMOKE-OK; id -u") {
		return msb.CommandResult{Stdout: "SMOKE-OK\n0\n"}, nil
	}
	if len(req.Args) >= 1 && req.Args[0] == "df" {
		return msb.CommandResult{Stdout: "STORAGE OK\n"}, nil
	}
	return msb.CommandResult{}, nil
}

type noopMountCtl struct{}

func (noopMountCtl) ListMounts() ([]mounttab.Entry, error)   { return nil, nil }
func (noopMountCtl) SignalPID(_ int, _ syscall.Signal) error { return nil }
func (noopMountCtl) Unmount(_ string, _ bool) error          { return nil }
func (noopMountCtl) Sleep(_ time.Duration)                   {}

func newTestApp(t *testing.T) (*App, *fakeMSBRunner, *bytes.Buffer, *bytes.Buffer) {
	t.Helper()
	root := t.TempDir()
	home, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}
	dataDir := filepath.Join(home, ".local", "share", "agbox")
	msbHome := filepath.Join(home, ".microsandbox")
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}

	runner := &fakeMSBRunner{
		sandboxes: "NAME STATE\nagbox-base stopped\n",
		snapshots: "NAME CREATED\nagbox:v1 1m\n",
	}
	var stdout, stderr bytes.Buffer

	app := &App{
		Env: config.Env{
			HomeReal:         home,
			DataDir:          dataDir,
			ConfigFile:       filepath.Join(dataDir, "config"),
			MSBHome:          msbHome,
			CPUs:             "2",
			Memory:           "2G",
			RootDisk:         "8G",
			OpenCodeVersion:  "latest",
			AgyInstallerURL:  "https://antigravity.google/cli/install.sh",
			MaskVCS:          config.MaskStrict,
			AllowOutsideHome: false,
		},
		ExePath:  "/usr/local/bin/agbox",
		MSB:      runner,
		MountCtl: noopMountCtl{},
		Stdin:    strings.NewReader(""),
		Stdout:   &stdout,
		Stderr:   &stderr,
		Getenv: func(k string) string {
			if k == "ANTHROPIC_API_KEY" {
				return "sk-ant-test"
			}
			return ""
		},
		IsTTY:     func() bool { return true },
		GetEUID:   func() int { return 1000 },
		CheckKVM:  func() error { return nil },
		CheckFUSE: func() error { return nil },
		PID:       4242,
		StartFilter: func(_, mntDir, pidFile string, _ bool) (int, error) {
			_ = os.MkdirAll(mntDir, 0o700)
			_ = os.WriteFile(pidFile, []byte("9999\n"), 0o600)
			return 9999, nil
		},
		WaitServeUI: func(_ context.Context, _ int, _ string) bool {
			return true
		},
	}
	return app, runner, &stdout, &stderr
}

func TestAppLifecycleModes(t *testing.T) {
	app, runner, stdout, _ := newTestApp(t)
	ctx := context.Background()

	// 1. Setup
	if rc := app.Dispatch(ctx, []string{"setup"}); rc != 0 {
		t.Fatalf("Setup failed with rc=%d, stdout=%s", rc, stdout.String())
	}

	// 2. CreateBase (both)
	runner.snapshots = "NAME CREATED\n"
	if rc := app.Dispatch(ctx, []string{"create-base", "--force", "both"}); rc != 0 {
		t.Fatalf("CreateBase failed with rc=%d", rc)
	}
	st, err := config.LoadFile(app.Env.ConfigFile)
	if err != nil || st.Snapshot != "agbox:v1" || st.Agent != "both" {
		t.Fatalf("saved state after CreateBase = %+v, %v", st, err)
	}

	// 3. EditBase (--add core,go,rust,esphome and --list)
	if rc := app.Dispatch(ctx, []string{"edit-base", "--list"}); rc != 0 {
		t.Fatalf("EditBase --list failed with rc=%d", rc)
	}
	runner.snapshots = "NAME CREATED\nagbox:v1 1m\n"
	if rc := app.Dispatch(ctx, []string{"edit-base", "--add", "core,go,rust,esphome"}); rc != 0 {
		t.Fatalf("EditBase --add failed with rc=%d", rc)
	}
	st, err = config.LoadFile(app.Env.ConfigFile)
	if err != nil || st.Snapshot != "agbox:v2" || st.SnapCount != 2 || st.Categories != "core,go,rust,esphome" {
		t.Fatalf("saved state after EditBase = %+v, %v", st, err)
	}
	runner.snapshots = "NAME CREATED\nagbox:v1 1m\nagbox:v2 1m\n"

	// 4. Run (--cmd with shared project directory)
	projDir := filepath.Join(app.Env.HomeReal, "repo")
	if err := os.MkdirAll(projDir, 0o700); err != nil {
		t.Fatal(err)
	}
	runner.calls = nil
	if rc := app.Dispatch(ctx, []string{"run", "--cmd", "id -u", projDir}); rc != 0 {
		t.Fatalf("Run --cmd failed with rc=%d", rc)
	}

	// Verify API key was streamed over stdin (never in CLI args) and VM was cleaned up on exit.
	foundKeyStdin := false
	foundCleanup := false
	for _, c := range runner.calls {
		if strings.Contains(c.Stdin, "ANTHROPIC_API_KEY='sk-ant-test'") {
			foundKeyStdin = true
		}
		for _, arg := range c.Args {
			if strings.Contains(arg, "sk-ant-test") {
				t.Fatalf("secret leaked in CLI args: %v", c.Args)
			}
		}
		if slices.Equal(c.Args, []string{"rm", "-f", "agbox-run-4242"}) {
			foundCleanup = true
		}
	}
	if !foundKeyStdin {
		t.Error("expected ANTHROPIC_API_KEY to be streamed over stdin")
	}
	if !foundCleanup {
		t.Error("expected ephemeral sandbox agbox-run-4242 to be removed on exit")
	}

	// 5. Run (--serve detached when IsTTY=false)
	app.IsTTY = func() bool { return false }
	runner.calls = nil
	if rc := app.Dispatch(ctx, []string{"run", "--serve", "--port", "4096", projDir}); rc != 0 {
		t.Fatalf("Run detached --serve failed with rc=%d", rc)
	}
	detachedMarker := filepath.Join(app.Env.DataDir, "run", "4242", "detached")
	if _, err := os.Stat(detachedMarker); err != nil {
		t.Fatalf("expected detached marker at %s: %v", detachedMarker, err)
	}

	// 6. Stop the detached sandbox
	if rc := app.Dispatch(ctx, []string{"stop", "agbox-run-4242"}); rc != 0 {
		t.Fatalf("Stop failed with rc=%d", rc)
	}
	if _, err := os.Stat(filepath.Join(app.Env.DataDir, "run", "4242")); !os.IsNotExist(err) {
		t.Errorf("expected filter dir for 4242 to be removed on Stop, stat err=%v", err)
	}

	// 6b. Run (-d --remote-control detached with TTY=true)
	app.IsTTY = func() bool { return true }
	if rc := app.Dispatch(ctx, []string{"run", "-d", "--remote-control", projDir}); rc != 0 {
		t.Fatalf("Run -d --remote-control failed with rc=%d", rc)
	}
	if _, err := os.Stat(detachedMarker); err != nil {
		t.Fatalf("expected detached marker for remote-control at %s: %v", detachedMarker, err)
	}
	if rc := app.Dispatch(ctx, []string{"stop", "agbox-run-4242"}); rc != 0 {
		t.Fatalf("Stop failed with rc=%d", rc)
	}

	// 7. Status
	if rc := app.Dispatch(ctx, []string{"status"}); rc != 0 {
		t.Fatalf("Status failed with rc=%d", rc)
	}

	// 8. Remove (--yes)
	if rc := app.Dispatch(ctx, []string{"remove", "--yes"}); rc != 0 {
		t.Fatalf("Remove failed with rc=%d", rc)
	}
	if _, err := os.Stat(app.Env.DataDir); !os.IsNotExist(err) {
		t.Errorf("expected DataDir to be removed after Remove, stat err=%v", err)
	}
}

func TestReapOrphanRunsAndTUIAndServeProbe(t *testing.T) {
	app, runner, _, _ := newTestApp(t)
	ctx := context.Background()

	if err := config.SaveFile(app.Env.ConfigFile, config.State{
		Agent:     "opencode",
		Image:     "node:24-bookworm-slim",
		Snapshot:  "agbox:v1",
		SnapCount: 1,
	}); err != nil {
		t.Fatal(err)
	}

	// Set up two dead-PID filter dirs: one normal (999991) and one detached (999992).
	deadDir := filepath.Join(app.Env.DataDir, "run", "999991")
	detachedDir := filepath.Join(app.Env.DataDir, "run", "999992")
	_ = os.MkdirAll(deadDir, 0o700)
	_ = os.MkdirAll(detachedDir, 0o700)
	_ = os.WriteFile(filepath.Join(detachedDir, "detached"), []byte("agbox-run-999992\n"), 0o600)

	runner.sandboxes = "NAME STATE\nagbox-base stopped\nagbox-run-999991 running\nagbox-run-999992 running\n"

	app.ReapOrphanRuns(ctx)
	app.ReapStaleFilterDirs(ctx)

	// Dead non-detached run (999991) must be deleted. Live detached run (999992) must remain.
	if _, err := os.Stat(deadDir); !os.IsNotExist(err) {
		t.Errorf("expected dead filter dir 999991 to be reaped, err=%v", err)
	}
	if _, err := os.Stat(detachedDir); err != nil {
		t.Errorf("expected live detached filter dir 999992 to be preserved, err=%v", err)
	}

	// Test interactive TUI run mode.
	app.IsTTY = func() bool { return true }
	if rc := app.Dispatch(ctx, []string{"run", "opencode"}); rc != 0 {
		t.Fatalf("TUI run failed with rc=%d", rc)
	}

	// Test defaultWaitServeUI with an httptest server on 127.0.0.1.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/doc" {
			user, pass, ok := r.BasicAuth()
			if !ok || user != "opencode" || pass != "secret123" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("ok"))
		}
	}))
	defer srv.Close()
	_, portStr, _ := net.SplitHostPort(srv.Listener.Addr().String())
	srvPort, _ := strconv.Atoi(portStr)

	app.Getenv = func(k string) string {
		if k == "OPENCODE_SERVER_PASSWORD" {
			return "secret123"
		}
		return ""
	}
	app.WaitServeUI = app.defaultWaitServeUI
	if rc := app.Dispatch(ctx, []string{"run", "--serve", "--probe", "--port", strconv.Itoa(srvPort)}); rc != 0 {
		t.Fatalf("Run --serve --probe failed with rc=%d", rc)
	}

	// Test EditBase interactive category selection (choosing '1,2' on Stdin) + --no-snap.
	app.Stdin = strings.NewReader("1,2\n")
	if rc := app.Dispatch(ctx, []string{"edit-base", "--no-snap"}); rc != 0 {
		t.Fatalf("EditBase interactive selection --no-snap failed with rc=%d", rc)
	}

	// Test Remove interactive abort when user types 'n'.
	app.Stdin = strings.NewReader("n\n")
	if rc := app.Dispatch(ctx, []string{"remove"}); rc == 0 {
		t.Error("expected Remove to abort when user enters 'n'")
	}

	// Help and unknown mode dispatch.
	if rc := app.Dispatch(ctx, nil); rc != 0 {
		t.Errorf("Dispatch(nil) = %d, want 0", rc)
	}
	if rc := app.Dispatch(ctx, []string{"--help"}); rc != 0 {
		t.Errorf("Dispatch(--help) = %d, want 0", rc)
	}
	if rc := app.Dispatch(ctx, []string{"run", "--help"}); rc != 0 {
		t.Errorf("Dispatch(run --help) = %d, want 0", rc)
	}
	if rc := app.Dispatch(ctx, []string{"nonexistent-mode"}); rc == 0 {
		t.Error("expected non-zero exit code for unknown mode")
	}
}

func TestSandboxNamingAndGlobalAndRootParsing(t *testing.T) {
	gOpts, err := ParseGlobalArgs([]string{"--allow-root", "run", "--name", "feat1"})
	if err != nil || !gOpts.AllowRoot || gOpts.Mode != "run" || !slices.Equal(gOpts.Rest, []string{"--name", "feat1"}) {
		t.Fatalf("ParseGlobalArgs = %+v, %v", gOpts, err)
	}
	if _, err := ParseGlobalArgs([]string{"--unknown", "run"}); err == nil {
		t.Error("expected error for unknown global option")
	}

	if src, err := CheckRootExecution(1000, false, false); err != nil || src != "" {
		t.Errorf("CheckRootExecution(1000) = %q, %v", src, err)
	}
	if _, err := CheckRootExecution(0, false, false); err == nil {
		t.Error("expected error for root without override")
	}
	if src, err := CheckRootExecution(0, false, true); err != nil || src != "--allow-root" {
		t.Errorf("CheckRootExecution(flag) = %q, %v", src, err)
	}
	if src, err := CheckRootExecution(0, true, false); err != nil || src != "AGBOX_ALLOW_ROOT=1" {
		t.Errorf("CheckRootExecution(env) = %q, %v", src, err)
	}

	validNames := []struct {
		name    string
		pid     int
		sandbox string
		dirID   string
	}{
		{"", 4242, "agbox-run-4242", "4242"},
		{"feat1", 4242, "agbox-feat1", "feat1"},
		{"my_app-2", 4242, "agbox-my_app-2", "my_app-2"},
		{"4242", 1111, "agbox-4242", "_4242"},
		{"run-feat", 1111, "agbox-run-feat", "run-feat"},
	}
	for _, tc := range validNames {
		if tc.name != "" {
			gotName, err := ValidateRunName(tc.name)
			if err != nil || gotName != tc.name {
				t.Fatalf("ValidateRunName(%q) = %q, %v", tc.name, gotName, err)
			}
		}
		sbx := FormatRunSandboxName(tc.name, tc.pid)
		if sbx != tc.sandbox {
			t.Fatalf("FormatRunSandboxName(%q, %d) = %q, want %q", tc.name, tc.pid, sbx, tc.sandbox)
		}
		if !IsRunSandboxName(sbx) {
			t.Fatalf("expected IsRunSandboxName(%q) to be true", sbx)
		}
		dirID, err := RunDirIDFromSandbox(sbx)
		if err != nil || dirID != tc.dirID {
			t.Fatalf("RunDirIDFromSandbox(%q) = %q, %v (want %q)", sbx, dirID, err, tc.dirID)
		}
		roundTrip, ok := SandboxFromRunDirID(dirID)
		if !ok || roundTrip != sbx {
			t.Fatalf("SandboxFromRunDirID(%q) = %q, %v (want %q)", dirID, roundTrip, ok, sbx)
		}
	}

	for _, bad := range []string{
		"",
		"base",
		"-bad",
		"_bad",
		"bad/slash",
		"bad.dot",
		"bad space",
		strings.Repeat("a", 64),
	} {
		if _, err := ValidateRunName(bad); err == nil {
			t.Errorf("expected ValidateRunName(%q) to fail", bad)
		}
	}
	if IsRunSandboxName("agbox-base") || IsRunSandboxName("other-sandbox") || IsRunSandboxName("agbox-") {
		t.Error("expected invalid sandbox names to fail IsRunSandboxName")
	}

	defOpts, err := ParseRunArgs([]string{"--name", "feat1", "--allow-root", "opencode"}, "", nil)
	if err != nil || defOpts.MaskMode != config.MaskStrict || defOpts.Name != "feat1" || !defOpts.AllowRoot {
		t.Fatalf("ParseRunArgs defaults = %+v, %v", defOpts, err)
	}
	eqOpts, err := ParseRunArgs([]string{"--name=feat2", "opencode"}, "", nil)
	if err != nil || eqOpts.Name != "feat2" {
		t.Fatalf("ParseRunArgs(--name=feat2) = %+v, %v", eqOpts, err)
	}
	for _, badRun := range [][]string{
		{"--name"},
		{"--name", ""},
		{"--name", "base"},
		{"--name=-bad"},
	} {
		if _, err := ParseRunArgs(badRun, "", nil); err == nil {
			t.Errorf("expected ParseRunArgs(%v) to fail", badRun)
		}
	}

	if sOpts, err := ParseSuspendArgs([]string{"--allow-root", "agbox-feat1"}); err != nil || sOpts.Sandbox != "agbox-feat1" || !sOpts.AllowRoot {
		t.Fatalf("ParseSuspendArgs = %+v, %v", sOpts, err)
	}
	if rOpts, err := ParseResumeArgs([]string{"--allow-root", "-d", "agbox-feat1"}); err != nil || rOpts.Sandbox != "agbox-feat1" || !rOpts.AllowRoot || !rOpts.Detach {
		t.Fatalf("ParseResumeArgs = %+v, %v", rOpts, err)
	}
	if name, err := ParseStopArgs([]string{"agbox-feat1"}); err != nil || name != "agbox-feat1" {
		t.Fatalf("ParseStopArgs(agbox-feat1) = %q, %v", name, err)
	}
	for _, bad := range [][]string{
		{},
		{"agbox-base"},
		{"other-sandbox"},
		{"--bad", "agbox-feat1"},
	} {
		if _, err := ParseSuspendArgs(bad); err == nil {
			t.Errorf("expected ParseSuspendArgs(%v) to fail", bad)
		}
		if _, err := ParseResumeArgs(bad); err == nil {
			t.Errorf("expected ParseResumeArgs(%v) to fail", bad)
		}
	}
}

func TestRootExecutionOverrideAcrossModes(t *testing.T) {
	app, _, _, stderr := newTestApp(t)
	ctx := context.Background()
	app.GetEUID = func() int { return 0 }

	if err := config.SaveFile(app.Env.ConfigFile, config.State{
		Agent:     "opencode",
		Image:     "node:24-bookworm-slim",
		Snapshot:  "agbox:v1",
		SnapCount: 1,
	}); err != nil {
		t.Fatal(err)
	}

	for _, cmd := range [][]string{
		{"setup"},
		{"create-base", "--force", "opencode"},
		{"edit-base", "--cmd", "true"},
		{"run", "--cmd", "id"},
		{"suspend", "agbox-feat1"},
		{"resume", "agbox-feat1"},
		{"stop", "agbox-feat1"},
		{"remove", "--yes"},
		{"status"},
	} {
		if rc := app.Dispatch(ctx, cmd); rc == 0 {
			t.Errorf("expected mode %v to fail as root without --allow-root", cmd)
		}
	}

	stderr.Reset()
	if rc := app.Dispatch(ctx, []string{"--allow-root", "setup"}); rc != 0 {
		t.Fatalf("expected global --allow-root setup to succeed, stderr=%s", stderr.String())
	}
	if !strings.Contains(stderr.String(), "Root mode is active") {
		t.Errorf("expected root warning in stderr, got %q", stderr.String())
	}

	stderr.Reset()
	app.Env.AllowRoot = true
	if rc := app.Dispatch(ctx, []string{"status"}); rc != 0 {
		t.Fatalf("expected AGBOX_ALLOW_ROOT=1 status to succeed, stderr=%s", stderr.String())
	}
}

func TestSecureByDefaultAndFailClosedRun(t *testing.T) {
	app, runner, _, stderr := newTestApp(t)
	ctx := context.Background()

	if err := config.SaveFile(app.Env.ConfigFile, config.State{
		Agent:     "opencode",
		Image:     "node:24-bookworm-slim",
		Snapshot:  "agbox:v1",
		SnapCount: 1,
	}); err != nil {
		t.Fatal(err)
	}

	projDir := filepath.Join(app.Env.HomeReal, "proj")
	if err := os.MkdirAll(projDir, 0o700); err != nil {
		t.Fatal(err)
	}

	// 1. Default run uses --name, mounts via FUSE, and enforces local/private/multicast/cloud-config deny rules.
	runner.calls = nil
	if rc := app.Dispatch(ctx, []string{"run", "--name", "sec1", "--cmd", "id", projDir}); rc != 0 {
		t.Fatalf("Run --name sec1 failed: %s", stderr.String())
	}
	foundRestore := false
	for _, c := range runner.calls {
		joined := strings.Join(c.Args, " ")
		if strings.HasPrefix(joined, "snap restore ") {
			foundRestore = true
			for _, want := range []string{
				"--name agbox-sec1",
				"/run/sec1/m0:/workspace/proj:rw",
				"--net-default deny --net-rule deny@host --net-rule deny@loopback --net-rule deny@private --net-rule deny@link-local --net-rule deny@multicast --net-rule deny@metadata",
				"--net-rule deny@168.63.129.16/32",
				"--net-rule deny@100.100.100.200/32",
				"--net-rule allow@public",
			} {
				if !strings.Contains(joined, want) {
					t.Errorf("restore call %q missing %q", joined, want)
				}
			}
		}
	}
	if !foundRestore {
		t.Fatal("expected snap restore call")
	}

	// 2. FUSE failure under default MaskStrict must abort before restoring snapshot.
	origFilter := app.StartFilter
	app.StartFilter = func(_, _, _ string, _ bool) (int, error) {
		return 0, errors.New("fuse unavailable")
	}
	runner.calls = nil
	if rc := app.Dispatch(ctx, []string{"run", "--name", "sec2", "--cmd", "id", projDir}); rc == 0 {
		t.Fatal("expected Run to fail closed when FUSE filter fails")
	}
	for _, c := range runner.calls {
		if len(c.Args) >= 2 && c.Args[0] == "snap" && c.Args[1] == "restore" {
			t.Fatal("Run restored snapshot despite FUSE filter failure")
		}
	}
	app.StartFilter = origFilter

	// 3. Key streaming failure must fail closed and remove the restored sandbox.
	runner.handler = func(req msb.CommandRequest) (msb.CommandResult, error) {
		if len(req.Args) >= 1 && req.Args[0] == "ls" {
			return msb.CommandResult{Stdout: runner.sandboxes}, nil
		}
		if len(req.Args) >= 2 && req.Args[0] == "snap" && req.Args[1] == "ls" {
			return msb.CommandResult{Stdout: runner.snapshots}, nil
		}
		for _, a := range req.Args {
			if strings.Contains(a, config.GuestKeysFile) {
				return msb.CommandResult{ExitCode: 1}, errors.New("key write failed")
			}
		}
		return msb.CommandResult{}, nil
	}
	runner.calls = nil
	if rc := app.Dispatch(ctx, []string{"run", "--name", "keyfail", "--cmd", "id"}); rc == 0 {
		t.Fatal("expected Run to fail closed when pushKeys fails")
	}
	runner.handler = nil

	// 4. Duplicate --name must fail closed without removing the existing sandbox.
	runner.sandboxes = "NAME STATE\nagbox-base stopped\nagbox-existing running\n"
	runner.calls = nil
	if rc := app.Dispatch(ctx, []string{"run", "--name", "existing", "--cmd", "id"}); rc == 0 {
		t.Fatal("expected duplicate --name to fail")
	}
	for _, c := range runner.calls {
		if slices.Equal(c.Args, []string{"rm", "-f", "agbox-existing"}) {
			t.Fatal("duplicate --name run deleted the pre-existing agbox-existing sandbox")
		}
	}

	// 5. Setup fails closed on CheckFUSE error or invalid DataDir, and passes --no-net to smoke test.
	runner.sandboxes = "NAME STATE\n"
	runner.calls = nil
	if rc := app.Dispatch(ctx, []string{"setup"}); rc != 0 {
		t.Fatalf("expected Setup to succeed, stderr=%s", stderr.String())
	}
	foundOfflineSmoke := false
	for _, c := range runner.calls {
		if len(c.Args) >= 2 && c.Args[0] == "create" && c.Args[1] == "alpine" && slices.Contains(c.Args, "--no-net") {
			foundOfflineSmoke = true
		}
	}
	if !foundOfflineSmoke {
		t.Error("expected Setup smoke test to pass --no-net")
	}

	app.CheckFUSE = func() error { return errors.New("fuse broken") }
	if rc := app.Dispatch(ctx, []string{"setup"}); rc == 0 {
		t.Fatal("expected Setup to fail closed when CheckFUSE fails")
	}
	app.CheckFUSE = func() error { return nil }

	badApp := *app
	badApp.Env.DataDir = filepath.Join(app.Env.HomeReal, "dir with space")
	if rc := badApp.Dispatch(ctx, []string{"setup"}); rc == 0 {
		t.Fatal("expected Setup to fail closed when DataDir contains whitespace")
	}

	// 6. EditBase fails closed when guest user provisioning fails or msb stop fails.
	runner.sandboxes = "NAME STATE\nagbox-base stopped\n"
	runner.handler = func(req msb.CommandRequest) (msb.CommandResult, error) {
		if len(req.Args) >= 1 && req.Args[0] == "ls" {
			return msb.CommandResult{Stdout: runner.sandboxes}, nil
		}
		if len(req.Args) >= 2 && req.Args[0] == "snap" && req.Args[1] == "ls" {
			return msb.CommandResult{Stdout: runner.snapshots}, nil
		}
		if len(req.Args) >= 2 && req.Args[0] == "stop" && req.Args[1] == config.BaseSandbox {
			return msb.CommandResult{ExitCode: 1}, errors.New("stop failed")
		}
		return msb.CommandResult{}, nil
	}
	if rc := app.Dispatch(ctx, []string{"edit-base", "--cmd", "true"}); rc == 0 {
		t.Fatal("expected EditBase to fail closed when stopping agbox-base fails")
	}
	runner.handler = nil
}

func TestSuspendResumeStopAndReaper(t *testing.T) {
	app, runner, _, stderr := newTestApp(t)
	ctx := context.Background()

	if err := config.SaveFile(app.Env.ConfigFile, config.State{
		Agent:     "both",
		Image:     "node:24-bookworm-slim",
		Snapshot:  "agbox:v1",
		SnapCount: 1,
	}); err != nil {
		t.Fatal(err)
	}

	projDir := filepath.Join(app.Env.HomeReal, "work")
	if err := os.MkdirAll(projDir, 0o700); err != nil {
		t.Fatal(err)
	}

	// 1. Start a named detached Remote Control sandbox.
	runner.sandboxes = "NAME STATE\nagbox-base stopped\n"
	if rc := app.Dispatch(ctx, []string{"run", "--name", "work1", "-d", "--remote-control", projDir}); rc != 0 {
		t.Fatalf("Run -d --remote-control failed: %s", stderr.String())
	}
	workDir := filepath.Join(app.Env.DataDir, "run", "work1")
	if _, err := os.Stat(filepath.Join(workDir, "m0.pid")); err != nil {
		t.Fatalf("expected m0.pid before suspend: %v", err)
	}

	// 2. Suspend agbox-work1.
	runner.sandboxes = "NAME STATE\nagbox-base stopped\nagbox-work1 running\n"
	runner.calls = nil
	if rc := app.Dispatch(ctx, []string{"suspend", "agbox-work1"}); rc != 0 {
		t.Fatalf("Suspend failed: %s", stderr.String())
	}
	if _, err := os.Stat(filepath.Join(workDir, "suspended")); err != nil {
		t.Fatalf("expected suspended metadata at %s: %v", workDir, err)
	}
	if _, err := os.Stat(filepath.Join(workDir, "m0.pid")); !os.IsNotExist(err) {
		t.Errorf("expected m0.pid to be removed on suspend, err=%v", err)
	}
	foundStop := false
	for _, c := range runner.calls {
		if slices.Equal(c.Args, []string{"stop", "agbox-work1"}) {
			foundStop = true
		}
	}
	if !foundStop {
		t.Error("expected 'msb stop agbox-work1' during suspend")
	}

	// 3. Orphan reaper must preserve stopped sandboxes that have a suspended marker.
	runner.sandboxes = "NAME STATE\nagbox-base stopped\nagbox-work1 stopped\n"
	otherApp := *app
	otherApp.PID = 8888
	// Rewrite OwnerPID in run.meta to a dead PID to verify suspended marker protects it.
	meta, err := config.LoadRunMeta(filepath.Join(workDir, "run.meta"))
	if err != nil {
		t.Fatal(err)
	}
	meta.OwnerPID = 999993
	_ = config.SaveRunMeta(filepath.Join(workDir, "run.meta"), meta)
	_ = config.SaveRunMeta(filepath.Join(workDir, "suspended"), meta)

	runner.calls = nil
	otherApp.ReapOrphanRuns(ctx)
	otherApp.ReapStaleFilterDirs(ctx)
	for _, c := range runner.calls {
		if slices.Equal(c.Args, []string{"rm", "-f", "agbox-work1"}) {
			t.Fatal("ReapOrphanRuns deleted suspended sandbox agbox-work1")
		}
	}
	if _, err := os.Stat(filepath.Join(workDir, "suspended")); err != nil {
		t.Fatalf("ReapStaleFilterDirs deleted suspended dir: %v", err)
	}

	// 4. Resume must fail closed and preserve suspended state if share validation fails.
	renamedDir := filepath.Join(app.Env.HomeReal, "work-moved")
	if err := os.Rename(projDir, renamedDir); err != nil {
		t.Fatal(err)
	}
	if rc := app.Dispatch(ctx, []string{"resume", "agbox-work1"}); rc == 0 {
		t.Fatal("expected Resume to fail when shared path is missing")
	}
	if _, err := os.Stat(filepath.Join(workDir, "suspended")); err != nil {
		t.Fatalf("expected suspended marker to remain after failed Resume: %v", err)
	}
	if err := os.Rename(renamedDir, projDir); err != nil {
		t.Fatal(err)
	}

	// 4b. Resume must fail closed if suspended metadata disables FUSE masking on a directory in strict mode.
	tampered := meta
	tampered.Shares = []config.ShareRecord{{
		Index:     0,
		HostPath:  projDir,
		GuestName: "work",
		IsDir:     true,
		Masked:    false,
	}}
	if err := config.SaveRunMeta(filepath.Join(workDir, "suspended"), tampered); err != nil {
		t.Fatal(err)
	}
	if rc := app.Dispatch(ctx, []string{"resume", "agbox-work1"}); rc == 0 {
		t.Fatal("expected Resume to fail closed when directory share is unmasked in strict mode")
	}
	if err := config.SaveRunMeta(filepath.Join(workDir, "suspended"), meta); err != nil {
		t.Fatal(err)
	}

	// 5. Resume with updated API key remounts m0, starts VM, streams new key, and restarts daemon.
	app.Getenv = func(k string) string {
		if k == "ANTHROPIC_API_KEY" {
			return "sk-ant-rotated"
		}
		return ""
	}
	runner.calls = nil
	if rc := app.Dispatch(ctx, []string{"resume", "agbox-work1"}); rc != 0 {
		t.Fatalf("Resume failed: %s", stderr.String())
	}
	if _, err := os.Stat(filepath.Join(workDir, "suspended")); !os.IsNotExist(err) {
		t.Errorf("expected suspended marker to be removed after Resume, err=%v", err)
	}
	if _, err := os.Stat(filepath.Join(workDir, "m0.pid")); err != nil {
		t.Errorf("expected m0.pid to be remounted at same path after Resume: %v", err)
	}
	foundStart := false
	foundRotatedKey := false
	for _, c := range runner.calls {
		if slices.Equal(c.Args, []string{"start", "agbox-work1"}) {
			foundStart = true
		}
		if strings.Contains(c.Stdin, "ANTHROPIC_API_KEY='sk-ant-rotated'") {
			foundRotatedKey = true
		}
	}
	if !foundStart || !foundRotatedKey {
		t.Errorf("Resume missing start (%v) or rotated key (%v)", foundStart, foundRotatedKey)
	}

	// 6. Stop deletes agbox-work1 and removes $DATA_DIR/run/work1.
	if rc := app.Dispatch(ctx, []string{"stop", "agbox-work1"}); rc != 0 {
		t.Fatalf("Stop agbox-work1 failed: %s", stderr.String())
	}
	if _, err := os.Stat(workDir); !os.IsNotExist(err) {
		t.Errorf("expected %s to be deleted by Stop, err=%v", workDir, err)
	}

	// 7. Foreground TUI session suspended from another terminal skips msb rm -f in cleanup.
	runner.sandboxes = "NAME STATE\nagbox-base stopped\n"
	suspendedDuringTUI := false
	runner.handler = func(req msb.CommandRequest) (msb.CommandResult, error) {
		if len(req.Args) >= 1 && req.Args[0] == "ls" {
			return msb.CommandResult{Stdout: runner.sandboxes}, nil
		}
		if len(req.Args) >= 2 && req.Args[0] == "snap" && req.Args[1] == "ls" {
			return msb.CommandResult{Stdout: runner.snapshots}, nil
		}
		if len(req.Args) >= 2 && req.Args[0] == "snap" && req.Args[1] == "restore" {
			runner.sandboxes = "NAME STATE\nagbox-base stopped\nagbox-tui1 running\n"
			return msb.CommandResult{}, nil
		}
		if len(req.Args) >= 2 && req.Args[0] == "stop" && req.Args[1] == "agbox-tui1" {
			runner.sandboxes = "NAME STATE\nagbox-base stopped\nagbox-tui1 stopped\n"
			return msb.CommandResult{}, nil
		}
		if len(req.Args) >= 2 && req.Args[0] == "exec" && slices.Contains(req.Args, "-t") && !suspendedDuringTUI {
			suspendedDuringTUI = true
			peerApp := *app
			var peerOut, peerErr bytes.Buffer
			peerApp.Stdout = &peerOut
			peerApp.Stderr = &peerErr
			if sRC := peerApp.Dispatch(ctx, []string{"suspend", "agbox-tui1"}); sRC != 0 {
				t.Errorf("peer suspend failed: %s", peerErr.String())
			}
			return msb.CommandResult{ExitCode: 137}, errors.New("vm halted")
		}
		return msb.CommandResult{}, nil
	}

	runner.calls = nil
	if rc := app.Dispatch(ctx, []string{"run", "--name", "tui1", "opencode", projDir}); rc != 0 {
		t.Fatalf("foreground TUI run interrupted by suspend returned rc=%d, stderr=%s", rc, stderr.String())
	}
	for _, c := range runner.calls {
		if slices.Equal(c.Args, []string{"rm", "-f", "agbox-tui1"}) {
			t.Fatal("cleanup deleted agbox-tui1 despite suspended marker")
		}
	}
	tuiDir := filepath.Join(app.Env.DataDir, "run", "tui1")
	if _, err := os.Stat(filepath.Join(tuiDir, "suspended")); err != nil {
		t.Fatalf("expected tui1 suspended marker to persist: %v", err)
	}

	// Stop the suspended tui1 sandbox.
	runner.handler = nil
	if rc := app.Dispatch(ctx, []string{"stop", "agbox-tui1"}); rc != 0 {
		t.Fatalf("Stop suspended agbox-tui1 failed: %s", stderr.String())
	}
	if _, err := os.Stat(tuiDir); !os.IsNotExist(err) {
		t.Errorf("expected %s to be deleted by Stop, err=%v", tuiDir, err)
	}
}

func TestInstallScriptRootOverride(t *testing.T) {
	scriptPath, err := filepath.Abs("../../install.sh")
	if err != nil {
		t.Fatal(err)
	}

	// 1. --help succeeds.
	helpOut, err := exec.Command("bash", scriptPath, "--help").CombinedOutput()
	if err != nil || !strings.Contains(string(helpOut), "--allow-root") {
		t.Fatalf("install.sh --help = %v, out=%s", err, string(helpOut))
	}

	// 2. Unknown option fails.
	if err := exec.Command("bash", scriptPath, "--bad-flag").Run(); err == nil {
		t.Fatal("expected install.sh --bad-flag to fail")
	}

	// Prepare a mock bin directory simulating root (id -u -> 0) and stubbed go/msb.
	tmp := t.TempDir()
	mockBin := filepath.Join(tmp, "mockbin")
	installDir := filepath.Join(tmp, "install")
	homeDir := filepath.Join(tmp, "roothome")
	setupLog := filepath.Join(tmp, "setup.args")
	for _, d := range []string{mockBin, installDir, homeDir} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}

	writeExec := func(name, body string) {
		p := filepath.Join(mockBin, name)
		if err := os.WriteFile(p, []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	writeExec("id", "#!/bin/sh\nif [ \"$1\" = \"-u\" ]; then echo 0; exit 0; fi\nexec /usr/bin/id \"$@\"\n")
	writeExec("msb", "#!/bin/sh\necho \"msb 0.7.14\"\n")
	writeExec("fusermount3", "#!/bin/sh\nexit 0\n")
	writeExec("go", "#!/bin/sh\nif [ \"$1\" = \"version\" ]; then echo \"go version go1.24 linux/amd64\"; exit 0; fi\nif [ \"$1\" = \"build\" ] && [ \"$2\" = \"-o\" ]; then\n  printf '#!/bin/sh\\nprintf \"%%s\\\\n\" \"$*\" > %s\\n' \"$3\" > /dev/null\n  cat <<'EOS' > \"$3\"\n#!/bin/sh\nprintf '%s\\n' \"$*\" > \""+setupLog+"\"\nEOS\n  chmod 0755 \"$3\"\n  exit 0\nfi\nexit 1\n")

	baseEnv := append(os.Environ(),
		"HOME="+homeDir,
		"AGBOX_INSTALL_DIR="+installDir,
		"AGBOX_ALLOW_ROOT=0",
		"PATH="+mockBin+":"+os.Getenv("PATH"),
	)

	// 3. Running as root without --allow-root fails closed.
	cmdDeny := exec.Command("bash", scriptPath)
	cmdDeny.Env = baseEnv
	denyOut, err := cmdDeny.CombinedOutput()
	if err == nil || !strings.Contains(string(denyOut), "--allow-root") {
		t.Fatalf("expected root install without --allow-root to fail, err=%v, out=%s", err, string(denyOut))
	}

	// 4. Running as root with --allow-root succeeds and passes setup --allow-root.
	cmdAllow := exec.Command("bash", scriptPath, "--allow-root")
	cmdAllow.Env = baseEnv
	allowOut, err := cmdAllow.CombinedOutput()
	if err != nil {
		t.Fatalf("expected root install with --allow-root to succeed: %v\nout=%s", err, string(allowOut))
	}
	gotSetupArgs, err := os.ReadFile(setupLog)
	if err != nil {
		t.Fatalf("read setup log: %v", err)
	}
	if strings.TrimSpace(string(gotSetupArgs)) != "setup --allow-root" {
		t.Errorf("installed agbox invoked with %q, want %q", strings.TrimSpace(string(gotSetupArgs)), "setup --allow-root")
	}

	// 5. Missing fusermount3 and fusermount fails closed.
	if err := os.Remove(filepath.Join(mockBin, "fusermount3")); err != nil {
		t.Fatal(err)
	}
	writeExec("awk", "#!/bin/sh\nexec /usr/bin/awk \"$@\"\n")
	writeExec("getconf", "#!/bin/sh\nexec /usr/bin/getconf \"$@\"\n")
	writeExec("sort", "#!/bin/sh\nexec /usr/bin/sort \"$@\"\n")
	writeExec("head", "#!/bin/sh\nexec /usr/bin/head \"$@\"\n")
	writeExec("cut", "#!/bin/sh\nexec /usr/bin/cut \"$@\"\n")
	writeExec("dirname", "#!/bin/sh\nexec /usr/bin/dirname \"$@\"\n")
	cmdNoFuse := exec.Command("/bin/bash", scriptPath, "--allow-root")
	cmdNoFuse.Env = []string{
		"HOME=" + homeDir,
		"AGBOX_INSTALL_DIR=" + installDir,
		"PATH=" + mockBin,
	}
	noFuseOut, err := cmdNoFuse.CombinedOutput()
	if err == nil || !strings.Contains(string(noFuseOut), "fusermount3 is missing") {
		t.Fatalf("expected install.sh to fail closed when fusermount3 is missing, err=%v, out=%s", err, string(noFuseOut))
	}
}

func TestSecurityPropertiesAcrossModes(t *testing.T) {
	app, runner, _, stderr := newTestApp(t)
	ctx := context.Background()

	// 1. CreateBase applies public-only network rules, enforces HTTPS+TLS1.2 for agy,
	// and deletes partial agbox-base on provisioning failure.
	runner.sandboxes = "NAME STATE\n"
	runner.snapshots = "NAME CREATED\n"
	runner.calls = nil
	if rc := app.Dispatch(ctx, []string{"create-base", "antigravity"}); rc != 0 {
		t.Fatalf("CreateBase(antigravity) failed: %s", stderr.String())
	}
	foundCreateNet := false
	foundAgyTLS := false
	for _, c := range runner.calls {
		joined := strings.Join(c.Args, " ")
		if strings.HasPrefix(joined, "create ") {
			foundCreateNet = true
			for _, must := range []string{
				"--net-default deny",
				"--net-rule deny@host",
				"--net-rule deny@loopback",
				"--net-rule deny@private",
				"--net-rule deny@link-local",
				"--net-rule deny@multicast",
				"--net-rule deny@metadata",
				"--net-rule deny@168.63.129.16/32",
				"--net-rule allow@public",
			} {
				if !strings.Contains(joined, must) {
					t.Errorf("CreateBase msb create %q missing %q", joined, must)
				}
			}
		}
		if strings.Contains(joined, "antigravity.google") {
			foundAgyTLS = strings.Contains(joined, "=https") && strings.Contains(joined, "--tlsv1.2 -fsSL --")
		}
	}
	if !foundCreateNet || !foundAgyTLS {
		t.Errorf("CreateBase missing network isolation (%v) or TLS curl flags (%v)", foundCreateNet, foundAgyTLS)
	}

	// Provisioning failure in CreateBase must clean up partial agbox-base.
	runner.handler = func(req msb.CommandRequest) (msb.CommandResult, error) {
		if len(req.Args) >= 1 && req.Args[0] == "ls" {
			return msb.CommandResult{Stdout: "NAME STATE\n"}, nil
		}
		if len(req.Args) >= 1 && req.Args[0] == "exec" {
			return msb.CommandResult{ExitCode: 1}, errors.New("apt failed")
		}
		return msb.CommandResult{}, nil
	}
	runner.calls = nil
	if rc := app.Dispatch(ctx, []string{"create-base", "--force", "opencode"}); rc == 0 {
		t.Fatal("expected CreateBase to fail when provisioning fails")
	}
	cleanedBase := false
	for _, c := range runner.calls {
		if slices.Equal(c.Args, []string{"rm", "-f", config.BaseSandbox}) {
			cleanedBase = true
		}
	}
	if !cleanedBase {
		t.Error("expected CreateBase failure to delete partial agbox-base")
	}
	runner.handler = nil

	// 2. EditBase fails closed and stops agbox-base if guest user verification fails.
	if err := config.SaveFile(app.Env.ConfigFile, config.State{
		Agent:     "opencode",
		Image:     "node:24-bookworm-slim",
		Snapshot:  "agbox:v1",
		SnapCount: 1,
	}); err != nil {
		t.Fatal(err)
	}
	runner.sandboxes = "NAME STATE\nagbox-base stopped\n"
	runner.snapshots = "NAME CREATED\nagbox:v1 1m\n"
	runner.handler = func(req msb.CommandRequest) (msb.CommandResult, error) {
		if len(req.Args) >= 1 && req.Args[0] == "ls" {
			return msb.CommandResult{Stdout: runner.sandboxes}, nil
		}
		if len(req.Args) >= 2 && req.Args[0] == "snap" && req.Args[1] == "ls" {
			return msb.CommandResult{Stdout: runner.snapshots}, nil
		}
		if len(req.Args) >= 1 && req.Args[0] == "exec" && strings.Contains(strings.Join(req.Args, " "), "NOPASSWD") {
			return msb.CommandResult{ExitCode: 1}, errors.New("sudoers check failed")
		}
		return msb.CommandResult{}, nil
	}
	if rc := app.Dispatch(ctx, []string{"edit-base", "--cmd", "true"}); rc == 0 {
		t.Fatal("expected EditBase to fail closed when provisionGuestUser fails")
	}
	runner.handler = nil

	// 3. Run mounts zero host shares when no paths are passed, and --serve binds only 127.0.0.1.
	runner.calls = nil
	if rc := app.Dispatch(ctx, []string{"run", "--name", "noshare", "--serve", "--probe", "--port", "4321"}); rc != 0 {
		t.Fatalf("Run --serve --probe with zero shares failed: %s", stderr.String())
	}
	for _, c := range runner.calls {
		if len(c.Args) >= 2 && c.Args[0] == "snap" && c.Args[1] == "restore" {
			if slices.Contains(c.Args, "-v") {
				t.Errorf("expected zero -v volume flags when no paths are given, got %v", c.Args)
			}
			if !slices.Contains(c.Args, "127.0.0.1:4321:3000") {
				t.Errorf("expected loopback-only port binding 127.0.0.1:4321:3000 in %v", c.Args)
			}
		}
	}

	// 4. Symlinked DataDir is rejected across Setup, CreateBase, Run, Suspend, and Resume.
	symParent := t.TempDir()
	symData := filepath.Join(symParent, "sym-data")
	if err := os.Symlink(app.Env.DataDir, symData); err != nil {
		t.Fatal(err)
	}
	symApp := *app
	symApp.Env.DataDir = symData
	runner.sandboxes = "NAME STATE\nagbox-base stopped\nagbox-sym1 running\n"
	for _, modeArgs := range [][]string{
		{"setup"},
		{"create-base", "--force", "opencode"},
		{"run", "--cmd", "id"},
		{"suspend", "agbox-sym1"},
		{"resume", "agbox-sym1"},
	} {
		if rc := symApp.Dispatch(ctx, modeArgs); rc == 0 {
			t.Errorf("expected %v to reject symlinked DataDir", modeArgs)
		}
	}

	// 5. Resume rejects tampered metadata (sandbox mismatch, duplicate index, unsafe guest name, file marked masked).
	projDir := filepath.Join(app.Env.HomeReal, "tamper-proj")
	if err := os.MkdirAll(projDir, 0o700); err != nil {
		t.Fatal(err)
	}
	regFile := filepath.Join(projDir, "note.txt")
	if err := os.WriteFile(regFile, []byte("hi"), 0o600); err != nil {
		t.Fatal(err)
	}
	tamperRunDir := filepath.Join(app.Env.DataDir, "run", "tamp1")
	runner.sandboxes = "NAME STATE\nagbox-base stopped\nagbox-tamp1 stopped\n"
	tamperedCases := []config.RunMeta{
		{
			Sandbox:  "agbox-other",
			Agent:    "opencode",
			Mode:     config.RunModeCmd,
			Cmd:      "id",
			MaskMode: config.MaskStrict,
		},
		{
			Sandbox:  "agbox-tamp1",
			Agent:    "opencode",
			Mode:     config.RunModeCmd,
			Cmd:      "id",
			MaskMode: config.MaskStrict,
			Shares: []config.ShareRecord{
				{Index: 0, HostPath: projDir, GuestName: "a", IsDir: true, Masked: true},
				{Index: 0, HostPath: projDir, GuestName: "b", IsDir: true, Masked: true},
			},
		},
		{
			Sandbox:  "agbox-tamp1",
			Agent:    "opencode",
			Mode:     config.RunModeCmd,
			Cmd:      "id",
			MaskMode: config.MaskStrict,
			Shares: []config.ShareRecord{
				{Index: 0, HostPath: projDir, GuestName: "../escape", IsDir: true, Masked: true},
			},
		},
		{
			Sandbox:  "agbox-tamp1",
			Agent:    "opencode",
			Mode:     config.RunModeCmd,
			Cmd:      "id",
			MaskMode: config.MaskStrict,
			Shares: []config.ShareRecord{
				{Index: 0, HostPath: regFile, GuestName: "note.txt", IsDir: false, Masked: true},
			},
		},
	}
	for idx, badMeta := range tamperedCases {
		if err := config.SaveRunMeta(filepath.Join(tamperRunDir, "suspended"), badMeta); err != nil {
			t.Fatal(err)
		}
		if rc := app.Dispatch(ctx, []string{"resume", "agbox-tamp1"}); rc == 0 {
			t.Errorf("tampered Resume case %d unexpectedly succeeded: %+v", idx, badMeta)
		}
	}
}

func TestParsePersistenceModeAndFlagArgs(t *testing.T) {
	// 1. ParseAuthArgs
	if aOpts, err := ParseAuthArgs(nil); err != nil || aOpts.Action != "login" || aOpts.Target != "" {
		t.Fatalf("ParseAuthArgs(nil) = %+v, %v", aOpts, err)
	}
	if aOpts, err := ParseAuthArgs([]string{"--allow-root", "antigravity"}); err != nil || aOpts.Action != "login" || aOpts.Target != "antigravity" || !aOpts.AllowRoot {
		t.Fatalf("ParseAuthArgs(antigravity) = %+v, %v", aOpts, err)
	}
	if aOpts, err := ParseAuthArgs([]string{"login", "opencode"}); err != nil || aOpts.Action != "login" || aOpts.Target != "opencode" {
		t.Fatalf("ParseAuthArgs(login opencode) = %+v, %v", aOpts, err)
	}
	if aOpts, err := ParseAuthArgs([]string{"status"}); err != nil || aOpts.Action != "status" {
		t.Fatalf("ParseAuthArgs(status) = %+v, %v", aOpts, err)
	}
	if aOpts, err := ParseAuthArgs([]string{"logout"}); err != nil || aOpts.Action != "logout" || aOpts.Target != "all" {
		t.Fatalf("ParseAuthArgs(logout) = %+v, %v", aOpts, err)
	}
	if aOpts, err := ParseAuthArgs([]string{"logout", "opencode"}); err != nil || aOpts.Action != "logout" || aOpts.Target != "opencode" {
		t.Fatalf("ParseAuthArgs(logout opencode) = %+v, %v", aOpts, err)
	}
	if _, err := ParseAuthArgs([]string{"--help"}); !errors.Is(err, ErrHelp) {
		t.Errorf("expected ErrHelp, got %v", err)
	}
	for _, bad := range [][]string{
		{"--bad"},
		{"status", "extra"},
		{"logout", "bad-agent"},
		{"logout", "opencode", "extra"},
		{"login", "bad-agent"},
		{"antigravity", "extra"},
		{"unknown"},
	} {
		if _, err := ParseAuthArgs(bad); err == nil {
			t.Errorf("expected ParseAuthArgs(%v) to fail", bad)
		}
	}

	// 2. ParseSkillsArgs
	if sOpts, err := ParseSkillsArgs(nil); err != nil || sOpts.Action != "list" {
		t.Fatalf("ParseSkillsArgs(nil) = %+v, %v", sOpts, err)
	}
	if sOpts, err := ParseSkillsArgs([]string{"--allow-root", "add", "--force", "./my-skill"}); err != nil || sOpts.Action != "add" || !sOpts.Force || !sOpts.AllowRoot || sOpts.Target != "./my-skill" {
		t.Fatalf("ParseSkillsArgs(add) = %+v, %v", sOpts, err)
	}
	if sOpts, err := ParseSkillsArgs([]string{"rm", "my-skill"}); err != nil || sOpts.Action != "rm" || sOpts.Target != "my-skill" {
		t.Fatalf("ParseSkillsArgs(rm) = %+v, %v", sOpts, err)
	}
	if _, err := ParseSkillsArgs([]string{"-h"}); !errors.Is(err, ErrHelp) {
		t.Errorf("expected ErrHelp, got %v", err)
	}
	for _, bad := range [][]string{
		{"--bad"},
		{"list", "extra"},
		{"add"},
		{"rm"},
		{"unknown"},
	} {
		if _, err := ParseSkillsArgs(bad); err == nil {
			t.Errorf("expected ParseSkillsArgs(%v) to fail", bad)
		}
	}

	// 3. ParseProfileArgs
	if pOpts, err := ParseProfileArgs(nil); err != nil || pOpts.Action != "list" {
		t.Fatalf("ParseProfileArgs(nil) = %+v, %v", pOpts, err)
	}
	if pOpts, err := ParseProfileArgs([]string{"--allow-root", "create", "--size", "16g", "work1"}); err != nil || pOpts.Action != "create" || pOpts.Name != "work1" || pOpts.Size != "16G" || !pOpts.AllowRoot {
		t.Fatalf("ParseProfileArgs(create) = %+v, %v", pOpts, err)
	}
	if pOpts, err := ParseProfileArgs([]string{"rm", "--force", "work1"}); err != nil || pOpts.Action != "rm" || pOpts.Name != "work1" || !pOpts.Force {
		t.Fatalf("ParseProfileArgs(rm) = %+v, %v", pOpts, err)
	}
	if _, err := ParseProfileArgs([]string{"--help"}); !errors.Is(err, ErrHelp) {
		t.Errorf("expected ErrHelp, got %v", err)
	}
	for _, bad := range [][]string{
		{"--bad"},
		{"create"},
		{"create", "-bad"},
		{"create", "--size"},
		{"create", "--size", "0G", "work1"},
		{"rm"},
		{"rm", "../escape"},
		{"list", "extra"},
		{"unknown"},
	} {
		if _, err := ParseProfileArgs(bad); err == nil {
			t.Errorf("expected ParseProfileArgs(%v) to fail", bad)
		}
	}

	// 4. ParseRunArgs persistence flags and mutual exclusions
	rPersist, err := ParseRunArgs([]string{"--name", "dev1", "--persist", "-c", "--no-auth", "--no-skills", "opencode"}, "", nil)
	if err != nil || !rPersist.Persist || !rPersist.Continue || !rPersist.NoAuth || !rPersist.NoSkills {
		t.Fatalf("ParseRunArgs(--persist) = %+v, %v", rPersist, err)
	}
	rProf, err := ParseRunArgs([]string{"--profile=team_1", "--conversation=conv-123", "antigravity"}, "", nil)
	if err != nil || rProf.Profile != "team_1" || rProf.ContinueSession != "conv-123" {
		t.Fatalf("ParseRunArgs(--profile=) = %+v, %v", rProf, err)
	}
	for _, bad := range [][]string{
		{"--persist", "opencode"},
		{"--persist", "--name", "dev1", "--profile", "p1", "opencode"},
		{"--persist", "--name", "dev1", "--probe"},
		{"--profile"},
		{"--profile", "../bad"},
		{"-c", "--session", "s1", "opencode"},
		{"--session"},
		{"--session", "bad;id"},
		{"-c", "--cmd", "id"},
		{"-c", "--serve"},
		{"-c", "-d", "--remote-control"},
	} {
		if _, err := ParseRunArgs(bad, "", nil); err == nil {
			t.Errorf("expected ParseRunArgs(%v) to fail", bad)
		}
	}

	// 5. ParseResumeArgs continuation flags
	resOpts, err := ParseResumeArgs([]string{"--conversation=conv-42", "--no-auth", "--no-skills", "agbox-dev1"})
	if err != nil || resOpts.ContinueSession != "conv-42" || !resOpts.NoAuth || !resOpts.NoSkills {
		t.Fatalf("ParseResumeArgs = %+v, %v", resOpts, err)
	}
	for _, bad := range [][]string{
		{"-c", "--session", "s1", "agbox-dev1"},
		{"--session", "bad;id", "agbox-dev1"},
		{"--session"},
	} {
		if _, err := ParseResumeArgs(bad); err == nil {
			t.Errorf("expected ParseResumeArgs(%v) to fail", bad)
		}
	}
}

func TestPersistentAuthLifecycleAndStdinStreaming(t *testing.T) {
	app, runner, stdout, stderr := newTestApp(t)
	ctx := context.Background()

	if err := config.SaveFile(app.Env.ConfigFile, config.State{
		Agent:     "both",
		Image:     "node:24-bookworm-slim",
		Snapshot:  "agbox:v1",
		SnapCount: 1,
	}); err != nil {
		t.Fatal(err)
	}

	// Help dispatch for auth, skills, profile.
	for _, mode := range []string{"auth", "skills", "profile"} {
		stdout.Reset()
		if rc := app.Dispatch(ctx, []string{mode, "--help"}); rc != 0 || !strings.Contains(stdout.String(), "Usage:") {
			t.Fatalf("Dispatch(%s --help) = %d, out=%q", mode, rc, stdout.String())
		}
	}

	// 1. Initial auth status is unconfigured.
	stdout.Reset()
	if rc := app.Dispatch(ctx, []string{"auth", "status"}); rc != 0 {
		t.Fatalf("auth status failed: %s", stderr.String())
	}
	if !strings.Contains(stdout.String(), "antigravity: not configured") || !strings.Contains(stdout.String(), "opencode: not configured") {
		t.Fatalf("unexpected initial auth status: %q", stdout.String())
	}

	// 2. Non-TTY or missing agent when base=both fails closed.
	if rc := app.Dispatch(ctx, []string{"auth"}); rc == 0 {
		t.Fatal("expected auth without agent to fail when base=both")
	}
	app.IsTTY = func() bool { return false }
	if rc := app.Dispatch(ctx, []string{"auth", "antigravity"}); rc == 0 {
		t.Fatal("expected auth to fail closed without TTY")
	}
	app.IsTTY = func() bool { return true }

	// 3. Incomplete sign-in fails closed and deletes disposable agbox-auth-<pid> VM.
	fakeGuestHome := t.TempDir()
	runner.handler = func(req msb.CommandRequest) (msb.CommandResult, error) {
		if len(req.Args) >= 1 && req.Args[0] == "ls" {
			return msb.CommandResult{Stdout: runner.sandboxes}, nil
		}
		if len(req.Args) >= 2 && req.Args[0] == "snap" && req.Args[1] == "ls" {
			return msb.CommandResult{Stdout: runner.snapshots}, nil
		}
		if len(req.Args) >= 6 && req.Args[0] == "exec" && strings.Contains(req.Args[len(req.Args)-1], "printf 'FILE ") {
			script := strings.ReplaceAll(req.Args[len(req.Args)-1], config.GuestHome, fakeGuestHome)
			cmd := exec.Command("/bin/sh", "-c", script)
			cmd.Env = []string{"HOME=" + fakeGuestHome, "PATH=/usr/bin:/bin"}
			out, cErr := cmd.Output()
			return msb.CommandResult{Stdout: string(out)}, cErr
		}
		return msb.CommandResult{}, nil
	}
	runner.calls = nil
	if rc := app.Dispatch(ctx, []string{"auth", "antigravity"}); rc == 0 {
		t.Fatal("expected auth to fail closed when guest credentials are missing")
	}
	cleanedAuthVM := false
	for _, c := range runner.calls {
		if slices.Equal(c.Args, []string{"rm", "-f", "agbox-auth-4242"}) {
			cleanedAuthVM = true
		}
	}
	if !cleanedAuthVM {
		t.Error("expected disposable agbox-auth-4242 VM to be removed after failed login")
	}

	// 4. Populate guest credentials for antigravity and opencode and verify capture with zero host shares.
	if err := os.MkdirAll(filepath.Join(fakeGuestHome, ".gemini", "antigravity-cli"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fakeGuestHome, ".gemini", "antigravity-cli", "antigravity-oauth-token"), []byte("super-secret-agy-oauth"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fakeGuestHome, ".gemini", "antigravity-cli", "installation_id"), []byte("inst-777\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(fakeGuestHome, ".local", "share", "opencode"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fakeGuestHome, ".local", "share", "opencode", "auth.json"), []byte(`{"anthropic":{"type":"oauth","access":"super-secret-oc-token"}}`), 0o600); err != nil {
		t.Fatal(err)
	}

	runner.calls = nil
	if rc := app.Dispatch(ctx, []string{"auth", "antigravity"}); rc != 0 {
		t.Fatalf("auth antigravity failed: %s", stderr.String())
	}
	for _, c := range runner.calls {
		if len(c.Args) >= 2 && c.Args[0] == "snap" && c.Args[1] == "restore" && slices.Contains(c.Args, "-v") {
			t.Fatalf("auth VM must boot with zero host shares, got %v", c.Args)
		}
	}
	if rc := app.Dispatch(ctx, []string{"auth", "opencode"}); rc != 0 {
		t.Fatalf("auth opencode failed: %s", stderr.String())
	}
	runner.handler = nil

	// Verify 0600 permissions on saved host credential files.
	stToken, err := os.Stat(filepath.Join(app.Env.DataDir, "auth", "antigravity", "antigravity-oauth-token"))
	if err != nil || stToken.Mode().Perm() != 0o600 {
		t.Fatalf("saved oauth token stat = (%v, %v), want mode 0600", stToken, err)
	}

	stdout.Reset()
	if rc := app.Dispatch(ctx, []string{"auth", "status"}); rc != 0 {
		t.Fatalf("auth status failed: %s", stderr.String())
	}
	if !strings.Contains(stdout.String(), "antigravity: configured") || !strings.Contains(stdout.String(), "opencode: configured") {
		t.Fatalf("expected both agents configured, got %q", stdout.String())
	}

	// 5. Run streams saved auth over stdin (never in CLI args), and --no-auth skips it.
	runner.calls = nil
	if rc := app.Dispatch(ctx, []string{"run", "antigravity"}); rc != 0 {
		t.Fatalf("run antigravity failed: %s", stderr.String())
	}
	streamedAuth := false
	for _, c := range runner.calls {
		for _, a := range c.Args {
			if strings.Contains(a, "super-secret-agy-oauth") || strings.Contains(a, "super-secret-oc-token") {
				t.Fatalf("credential leaked in CLI args: %v", c.Args)
			}
		}
		if strings.Contains(c.Stdin, "antigravity-oauth-token") {
			streamedAuth = true
		}
	}
	if !streamedAuth {
		t.Error("expected saved antigravity credentials to be streamed over stdin during Run")
	}

	runner.calls = nil
	if rc := app.Dispatch(ctx, []string{"run", "--no-auth", "antigravity"}); rc != 0 {
		t.Fatalf("run --no-auth failed: %s", stderr.String())
	}
	for _, c := range runner.calls {
		if strings.Contains(c.Stdin, "antigravity-oauth-token") {
			t.Fatal("expected --no-auth to skip streaming saved credentials")
		}
	}

	// 6. Logout removes credentials.
	if rc := app.Dispatch(ctx, []string{"auth", "logout", "all"}); rc != 0 {
		t.Fatalf("auth logout all failed: %s", stderr.String())
	}
	stdout.Reset()
	_ = app.Dispatch(ctx, []string{"auth", "status"})
	if !strings.Contains(stdout.String(), "antigravity: not configured") {
		t.Errorf("expected antigravity unconfigured after logout, got %q", stdout.String())
	}
}

func TestPersistentSkillsAndProjectWorkingDirectory(t *testing.T) {
	app, runner, stdout, stderr := newTestApp(t)
	ctx := context.Background()

	if err := config.SaveFile(app.Env.ConfigFile, config.State{
		Agent:     "both",
		Image:     "node:24-bookworm-slim",
		Snapshot:  "agbox:v1",
		SnapCount: 1,
	}); err != nil {
		t.Fatal(err)
	}

	// 1. Empty skills list, then add, overwrite with --force, and list.
	stdout.Reset()
	if rc := app.Dispatch(ctx, []string{"skills"}); rc != 0 || !strings.Contains(stdout.String(), "No global skills") {
		t.Fatalf("skills list empty = %d, %q", rc, stdout.String())
	}

	skillSrc := filepath.Join(t.TempDir(), "code-audit")
	if err := os.MkdirAll(skillSrc, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(skillSrc, "SKILL.md"), []byte("---\nname: code-audit\n---\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if rc := app.Dispatch(ctx, []string{"skills", "add", skillSrc}); rc != 0 {
		t.Fatalf("skills add failed: %s", stderr.String())
	}
	if rc := app.Dispatch(ctx, []string{"skills", "add", skillSrc}); rc == 0 {
		t.Fatal("expected duplicate skills add without --force to fail")
	}
	if rc := app.Dispatch(ctx, []string{"skills", "add", "--force", skillSrc}); rc != 0 {
		t.Fatalf("skills add --force failed: %s", stderr.String())
	}
	stdout.Reset()
	if rc := app.Dispatch(ctx, []string{"skills", "list"}); rc != 0 || strings.TrimSpace(stdout.String()) != "code-audit" {
		t.Fatalf("skills list = %d, %q", rc, stdout.String())
	}

	// 2. Single directory share mounts global skills read-only, bind-mounts guest skill dirs, and cd's into /workspace/proj1.
	proj1 := filepath.Join(app.Env.HomeReal, "proj1")
	proj2 := filepath.Join(app.Env.HomeReal, "proj2")
	for _, p := range []string{proj1, proj2} {
		if err := os.MkdirAll(p, 0o700); err != nil {
			t.Fatal(err)
		}
	}

	runner.calls = nil
	if rc := app.Dispatch(ctx, []string{"run", "antigravity", proj1}); rc != 0 {
		t.Fatalf("run antigravity proj1 failed: %s", stderr.String())
	}
	wantSkillsVol := filepath.Join(app.Env.DataDir, "skills") + ":" + msb.GuestSkillsMount + ":ro,uid=1000,gid=1000"
	foundSkillsVol := false
	foundSkillsBind := false
	foundProjCWD := false
	for _, c := range runner.calls {
		joined := strings.Join(c.Args, " ")
		if strings.HasPrefix(joined, "snap restore ") && slices.Contains(c.Args, wantSkillsVol) {
			foundSkillsVol = true
		}
		if strings.Contains(joined, "remount,ro,bind") && strings.Contains(joined, ".gemini/config/skills") {
			foundSkillsBind = true
		}
		if strings.Contains(joined, "cd '/workspace/proj1' && exec agy") {
			foundProjCWD = true
		}
	}
	if !foundSkillsVol || !foundSkillsBind || !foundProjCWD {
		t.Fatalf("missing skills volume (%v), bind script (%v), or single-share CWD (%v)", foundSkillsVol, foundSkillsBind, foundProjCWD)
	}

	// 3. Multiple directory shares use /workspace CWD and pass --add-dir to agy, while --no-skills omits the skills volume.
	runner.calls = nil
	if rc := app.Dispatch(ctx, []string{"run", "--no-skills", "antigravity", proj1, proj2}); rc != 0 {
		t.Fatalf("run --no-skills multi-share failed: %s", stderr.String())
	}
	foundAddDir := false
	for _, c := range runner.calls {
		joined := strings.Join(c.Args, " ")
		if slices.Contains(c.Args, wantSkillsVol) {
			t.Fatalf("--no-skills unexpectedly mounted global skills volume: %v", c.Args)
		}
		if strings.Contains(joined, "cd '/workspace' && exec agy --add-dir '/workspace/proj1' --add-dir '/workspace/proj2'") {
			foundAddDir = true
		}
	}
	if !foundAddDir {
		t.Error("expected multi-share antigravity run to pass --add-dir for each directory share")
	}

	// 4. Symlink planted inside $DATA_DIR/skills fails closed before restoring snapshot.
	badSym := filepath.Join(app.Env.DataDir, "skills", "code-audit", "leak.md")
	if err := os.Symlink("/etc/passwd", badSym); err != nil {
		t.Fatal(err)
	}
	runner.calls = nil
	if rc := app.Dispatch(ctx, []string{"run", "antigravity", proj1}); rc == 0 {
		t.Fatal("expected Run to fail closed when $DATA_DIR/skills contains a symlink")
	}
	for _, c := range runner.calls {
		if len(c.Args) >= 2 && c.Args[0] == "snap" && c.Args[1] == "restore" {
			t.Fatal("Run restored snapshot despite symlink inside $DATA_DIR/skills")
		}
	}
	_ = os.Remove(badSym)

	// 5. Remove skill cleanly.
	if rc := app.Dispatch(ctx, []string{"skills", "rm", "code-audit"}); rc != 0 {
		t.Fatalf("skills rm failed: %s", stderr.String())
	}
}

func TestPersistModeAutoSuspendAndRepeatResume(t *testing.T) {
	app, runner, _, stderr := newTestApp(t)
	ctx := context.Background()

	if err := config.SaveFile(app.Env.ConfigFile, config.State{
		Agent:     "opencode",
		Image:     "node:24-bookworm-slim",
		Snapshot:  "agbox:v1",
		SnapCount: 1,
	}); err != nil {
		t.Fatal(err)
	}

	projA := filepath.Join(app.Env.HomeReal, "projA")
	projB := filepath.Join(app.Env.HomeReal, "projB")
	for _, p := range []string{projA, projB} {
		if err := os.MkdirAll(p, 0o700); err != nil {
			t.Fatal(err)
		}
	}

	// 1. Setup failure before execSession on a --persist run must delete the broken VM (not persist it).
	runner.handler = func(req msb.CommandRequest) (msb.CommandResult, error) {
		if len(req.Args) >= 1 && req.Args[0] == "ls" {
			return msb.CommandResult{Stdout: runner.sandboxes}, nil
		}
		if len(req.Args) >= 2 && req.Args[0] == "snap" && req.Args[1] == "ls" {
			return msb.CommandResult{Stdout: runner.snapshots}, nil
		}
		for _, a := range req.Args {
			if strings.Contains(a, config.GuestKeysFile) {
				return msb.CommandResult{ExitCode: 1}, errors.New("pushKeys failed")
			}
		}
		return msb.CommandResult{}, nil
	}
	runner.calls = nil
	if rc := app.Dispatch(ctx, []string{"run", "--persist", "--name", "broken1", "opencode", projA}); rc == 0 {
		t.Fatal("expected --persist run to fail closed when pushKeys fails")
	}
	foundBrokenRM := false
	for _, c := range runner.calls {
		if slices.Equal(c.Args, []string{"rm", "-f", "agbox-broken1"}) {
			foundBrokenRM = true
		}
	}
	if !foundBrokenRM {
		t.Error("expected failed setup before execSession to delete agbox-broken1 with msb rm -f")
	}
	runner.handler = nil

	// 2. First successful --persist run auto-suspends on exit instead of calling msb rm -f.
	runner.calls = nil
	stderr.Reset()
	if rc := app.Dispatch(ctx, []string{"run", "--persist", "--name", "dev1", "opencode", projA}); rc != 0 {
		t.Fatalf("first --persist run failed: %s", stderr.String())
	}
	dev1Dir := filepath.Join(app.Env.DataDir, "run", "dev1")
	if _, err := os.Stat(filepath.Join(dev1Dir, "suspended")); err != nil {
		t.Fatalf("expected suspended marker after --persist exit: %v", err)
	}
	foundStop := false
	for _, c := range runner.calls {
		if slices.Equal(c.Args, []string{"rm", "-f", "agbox-dev1"}) {
			t.Fatal("--persist run deleted agbox-dev1 on exit instead of suspending")
		}
		if slices.Equal(c.Args, []string{"stop", "agbox-dev1"}) {
			foundStop = true
		}
	}
	if !foundStop {
		t.Error("expected msb stop agbox-dev1 on --persist exit")
	}

	// 3. Repeat --persist run with different share path fails closed and keeps suspended marker.
	runner.sandboxes = "NAME STATE\nagbox-base stopped\nagbox-dev1 stopped\n"
	if rc := app.Dispatch(ctx, []string{"run", "--persist", "--name", "dev1", "opencode", projB}); rc == 0 {
		t.Fatal("expected repeat --persist run with mismatched share path to fail")
	}
	if _, err := os.Stat(filepath.Join(dev1Dir, "suspended")); err != nil {
		t.Fatalf("expected suspended marker to remain after share mismatch: %v", err)
	}

	// 4. Repeat --persist run with matching share and -c resumes agbox-dev1 with `opencode -c` and re-suspends on exit.
	runner.calls = nil
	stderr.Reset()
	if rc := app.Dispatch(ctx, []string{"run", "--persist", "--name", "dev1", "-c", "opencode", projA}); rc != 0 {
		t.Fatalf("repeat --persist -c run failed: %s", stderr.String())
	}
	foundStart := false
	foundContinue := false
	for _, c := range runner.calls {
		if slices.Equal(c.Args, []string{"start", "agbox-dev1"}) {
			foundStart = true
		}
		if strings.Contains(strings.Join(c.Args, " "), "exec opencode -c") {
			foundContinue = true
		}
		if slices.Equal(c.Args, []string{"rm", "-f", "agbox-dev1"}) {
			t.Fatal("repeat --persist run deleted agbox-dev1 on exit")
		}
	}
	if !foundStart || !foundContinue {
		t.Fatalf("repeat --persist missing msb start (%v) or opencode -c (%v)", foundStart, foundContinue)
	}
	if _, err := os.Stat(filepath.Join(dev1Dir, "suspended")); err != nil {
		t.Fatalf("expected suspended marker after repeat --persist exit: %v", err)
	}

	// 5. Explicit `agbox resume --session ses_42 agbox-dev1` also re-suspends on exit until `agbox stop`.
	runner.calls = nil
	if rc := app.Dispatch(ctx, []string{"resume", "--session", "ses_42", "agbox-dev1"}); rc != 0 {
		t.Fatalf("resume --session failed: %s", stderr.String())
	}
	foundSessionFlag := false
	for _, c := range runner.calls {
		if strings.Contains(strings.Join(c.Args, " "), "exec opencode -s 'ses_42'") {
			foundSessionFlag = true
		}
	}
	if !foundSessionFlag {
		t.Error("expected `opencode -s 'ses_42'` during resume")
	}
	if _, err := os.Stat(filepath.Join(dev1Dir, "suspended")); err != nil {
		t.Fatalf("expected persistent sandbox to re-suspend after `agbox resume`: %v", err)
	}

	if rc := app.Dispatch(ctx, []string{"stop", "agbox-dev1"}); rc != 0 {
		t.Fatalf("stop agbox-dev1 failed: %s", stderr.String())
	}
	if _, err := os.Stat(dev1Dir); !os.IsNotExist(err) {
		t.Errorf("expected %s to be deleted by stop, err=%v", dev1Dir, err)
	}
}

func TestProfileModeDiskVolumeLockingAndCleanup(t *testing.T) {
	app, runner, stdout, stderr := newTestApp(t)
	ctx := context.Background()

	if err := config.SaveFile(app.Env.ConfigFile, config.State{
		Agent:     "antigravity",
		Image:     "node:24-bookworm-slim",
		Snapshot:  "agbox:v1",
		SnapCount: 1,
	}); err != nil {
		t.Fatal(err)
	}

	proj := filepath.Join(app.Env.HomeReal, "proj")
	if err := os.MkdirAll(proj, 0o700); err != nil {
		t.Fatal(err)
	}

	volumesOut := "NAME KIND SIZE\n"
	runner.handler = func(req msb.CommandRequest) (msb.CommandResult, error) {
		if len(req.Args) >= 1 && req.Args[0] == "ls" {
			return msb.CommandResult{Stdout: runner.sandboxes}, nil
		}
		if len(req.Args) >= 2 && req.Args[0] == "snap" && req.Args[1] == "ls" {
			return msb.CommandResult{Stdout: runner.snapshots}, nil
		}
		if len(req.Args) >= 2 && req.Args[0] == "volume" && req.Args[1] == "ls" {
			return msb.CommandResult{Stdout: volumesOut}, nil
		}
		if len(req.Args) >= 3 && req.Args[0] == "volume" && req.Args[1] == "create" {
			volumesOut += req.Args[2] + " disk 12G\n"
			return msb.CommandResult{}, nil
		}
		if len(req.Args) >= 3 && req.Args[0] == "volume" && req.Args[1] == "rm" {
			target := req.Args[2]
			var kept []string
			for _, line := range strings.Split(volumesOut, "\n") {
				if !strings.HasPrefix(line, target+" ") {
					kept = append(kept, line)
				}
			}
			volumesOut = strings.Join(kept, "\n")
			return msb.CommandResult{}, nil
		}
		return msb.CommandResult{}, nil
	}
	defer func() { runner.handler = nil }()

	// 1. Create and list profile, and verify `agbox status` reports persistence state.
	if rc := app.Dispatch(ctx, []string{"profile", "create", "--size", "12G", "workprof"}); rc != 0 {
		t.Fatalf("profile create failed: %s", stderr.String())
	}
	stdout.Reset()
	if rc := app.Dispatch(ctx, []string{"profile", "list"}); rc != 0 || !strings.Contains(stdout.String(), "agbox-profile-workprof") {
		t.Fatalf("profile list = %d, out=%q", rc, stdout.String())
	}
	stdout.Reset()
	if rc := app.Dispatch(ctx, []string{"status"}); rc != 0 || !strings.Contains(stdout.String(), "profiles: workprof") {
		t.Fatalf("status missing profile info: rc=%d, out=%q", rc, stdout.String())
	}

	// 2. Run with --profile mounts raw ext4 disk volume, bind-mounts conversation dirs, passes --conversation, and deletes ephemeral VM on exit.
	runner.calls = nil
	if rc := app.Dispatch(ctx, []string{"run", "--name", "ephem1", "--profile", "workprof", "--conversation", "1c2a8c1e", "antigravity", proj}); rc != 0 {
		t.Fatalf("run --profile failed: %s", stderr.String())
	}
	foundNamedVol := false
	foundProfileBind := false
	foundConv := false
	foundEphemeralRM := false
	for _, c := range runner.calls {
		joined := strings.Join(c.Args, " ")
		if strings.HasPrefix(joined, "snap restore ") && slices.Contains(c.Args, "agbox-profile-workprof:"+msb.GuestProfileMount) {
			foundNamedVol = true
		}
		if strings.Contains(joined, ".agbox-profile/agy-cli") {
			foundProfileBind = true
		}
		if strings.Contains(joined, "exec agy --conversation '1c2a8c1e'") {
			foundConv = true
		}
		if slices.Equal(c.Args, []string{"rm", "-f", "agbox-ephem1"}) {
			foundEphemeralRM = true
		}
	}
	if !foundNamedVol || !foundProfileBind || !foundConv || !foundEphemeralRM {
		t.Fatalf("profile run checks: vol=%v bind=%v conv=%v rm=%v", foundNamedVol, foundProfileBind, foundConv, foundEphemeralRM)
	}

	// 3. Concurrent host flock blocks overlapping --profile runs before restoring snapshot.
	heldLock, err := persist.LockProfile(app.Env.DataDir, "workprof")
	if err != nil {
		t.Fatal(err)
	}
	runner.calls = nil
	if rc := app.Dispatch(ctx, []string{"run", "--profile", "workprof", "antigravity", proj}); rc == 0 {
		_ = heldLock.Unlock()
		t.Fatal("expected concurrent --profile run to fail while flock is held")
	}
	_ = heldLock.Unlock()
	for _, c := range runner.calls {
		if len(c.Args) >= 2 && c.Args[0] == "snap" && c.Args[1] == "restore" {
			t.Fatal("concurrent --profile run restored snapshot despite active flock")
		}
	}

	// 4. Suspended sandbox referencing workprof blocks `profile rm` unless --force is passed,
	// and resuming after `--force` removal fails closed because the disk volume is gone.
	suspDir := filepath.Join(app.Env.DataDir, "run", "psusp")
	suspMeta := config.RunMeta{
		Sandbox:  "agbox-psusp",
		Agent:    "antigravity",
		Mode:     config.RunModeTUI,
		MaskMode: config.MaskStrict,
		Profile:  "workprof",
	}
	if err := config.SaveRunMeta(filepath.Join(suspDir, "suspended"), suspMeta); err != nil {
		t.Fatal(err)
	}
	runner.sandboxes = "NAME STATE\nagbox-base stopped\nagbox-psusp stopped\n"
	if rc := app.Dispatch(ctx, []string{"profile", "rm", "workprof"}); rc == 0 {
		t.Fatal("expected profile rm without --force to fail when referenced by suspended sandbox")
	}
	if rc := app.Dispatch(ctx, []string{"profile", "rm", "--force", "workprof"}); rc != 0 {
		t.Fatalf("profile rm --force failed: %s", stderr.String())
	}
	if rc := app.Dispatch(ctx, []string{"resume", "agbox-psusp"}); rc == 0 {
		t.Fatal("expected Resume to fail closed when profile disk volume was deleted")
	}

	// 5. `agbox remove --yes` deletes remaining agbox-profile-* volumes alongside sandboxes and DataDir.
	if rc := app.Dispatch(ctx, []string{"profile", "create", "cleanupme"}); rc != 0 {
		t.Fatalf("profile create cleanupme failed: %s", stderr.String())
	}
	runner.calls = nil
	if rc := app.Dispatch(ctx, []string{"remove", "--yes"}); rc != 0 {
		t.Fatalf("remove --yes failed: %s", stderr.String())
	}
	deletedProfVol := false
	for _, c := range runner.calls {
		if slices.Equal(c.Args, []string{"volume", "rm", "agbox-profile-cleanupme"}) {
			deletedProfVol = true
		}
	}
	if !deletedProfVol {
		t.Error("expected `agbox remove --yes` to delete agbox-profile-cleanupme volume")
	}
}

func TestPersistenceSecurityChecksRootSymlinkAndTamperedMetadata(t *testing.T) {
	app, runner, _, _ := newTestApp(t)
	ctx := context.Background()

	// 1. Root check enforced on auth, skills, rules, and profile without --allow-root.
	app.GetEUID = func() int { return 0 }
	for _, cmd := range [][]string{
		{"auth", "status"},
		{"skills", "list"},
		{"rules", "list"},
		{"profile", "list"},
	} {
		if rc := app.Dispatch(ctx, cmd); rc == 0 {
			t.Errorf("expected %v to fail closed as root without --allow-root", cmd)
		}
	}
	app.GetEUID = func() int { return 1000 }

	// 2. Symlinked DataDir rejected on auth, skills, rules, and profile.
	symData := filepath.Join(t.TempDir(), "sym-data")
	if err := os.Symlink(app.Env.DataDir, symData); err != nil {
		t.Fatal(err)
	}
	symApp := *app
	symApp.Env.DataDir = symData
	for _, cmd := range [][]string{
		{"auth", "status"},
		{"skills", "list"},
		{"rules", "list"},
		{"profile", "list"},
	} {
		if rc := symApp.Dispatch(ctx, cmd); rc == 0 {
			t.Errorf("expected %v to reject symlinked DataDir", cmd)
		}
	}

	// 3. Tampered suspended metadata with invalid Profile or ContinueSession rejected on Resume.
	runner.sandboxes = "NAME STATE\nagbox-base stopped\nagbox-tamp2 stopped\n"
	tampDir := filepath.Join(app.Env.DataDir, "run", "tamp2")
	for _, badMeta := range []config.RunMeta{
		{
			Sandbox:  "agbox-tamp2",
			Agent:    "opencode",
			Mode:     config.RunModeTUI,
			MaskMode: config.MaskStrict,
			Profile:  "../escape",
		},
		{
			Sandbox:         "agbox-tamp2",
			Agent:           "opencode",
			Mode:            config.RunModeTUI,
			MaskMode:        config.MaskStrict,
			ContinueSession: "bad;rm -rf /",
		},
	} {
		if err := config.SaveRunMeta(filepath.Join(tampDir, "suspended"), badMeta); err != nil {
			t.Fatal(err)
		}
		if rc := app.Dispatch(ctx, []string{"resume", "agbox-tamp2"}); rc == 0 {
			t.Errorf("expected tampered Resume metadata %+v to fail closed", badMeta)
		}
	}
}

func TestParseRulesArgsAndNoRulesFlags(t *testing.T) {
	if _, err := ParseRulesArgs([]string{"--help"}); !errors.Is(err, ErrHelp) {
		t.Fatalf("ParseRulesArgs(--help) = %v, want ErrHelp", err)
	}
	opts, err := ParseRulesArgs(nil)
	if err != nil || opts.Action != "list" {
		t.Fatalf("ParseRulesArgs(nil) = %+v, %v", opts, err)
	}
	opts, err = ParseRulesArgs([]string{"add", "--force", "--name", "eng-standards", "/tmp/rules.md"})
	if err != nil || opts.Action != "add" || !opts.Force || opts.Name != "eng-standards" || opts.Target != "/tmp/rules.md" {
		t.Fatalf("ParseRulesArgs(add) = %+v, %v", opts, err)
	}
	opts, err = ParseRulesArgs([]string{"add", "--name=AGENTS.md", "/tmp/rules.md"})
	if err != nil || opts.Name != "AGENTS" {
		t.Fatalf("ParseRulesArgs(add --name=) = %+v, %v", opts, err)
	}
	opts, err = ParseRulesArgs([]string{"show", "eng-standards"})
	if err != nil || opts.Action != "show" || opts.Target != "eng-standards" {
		t.Fatalf("ParseRulesArgs(show) = %+v, %v", opts, err)
	}
	opts, err = ParseRulesArgs([]string{"rm", "--all"})
	if err != nil || opts.Action != "rm" || !opts.All {
		t.Fatalf("ParseRulesArgs(rm --all) = %+v, %v", opts, err)
	}

	for _, bad := range [][]string{
		{"--unknown"},
		{"--name"},
		{"--name", "../escape", "add", "a.md"},
		{"--all"},
		{"list", "--name", "foo"},
		{"add", "--all", "a.md"},
		{"show", "--force", "foo"},
		{"rm"},
		{"rm", "--all", "extra"},
		{"bogus"},
	} {
		if _, err := ParseRulesArgs(bad); err == nil {
			t.Errorf("ParseRulesArgs(%v) succeeded, want error", bad)
		}
	}

	runOpts, err := ParseRunArgs([]string{"--no-rules", "opencode"}, config.MaskStrict, func(string) bool { return false })
	if err != nil || !runOpts.NoRules {
		t.Fatalf("ParseRunArgs(--no-rules) = %+v, %v", runOpts, err)
	}
	resOpts, err := ParseResumeArgs([]string{"--no-rules", "agbox-dev"})
	if err != nil || !resOpts.NoRules || resOpts.Sandbox != "agbox-dev" {
		t.Fatalf("ParseResumeArgs(--no-rules) = %+v, %v", resOpts, err)
	}
}

func TestRulesLifecycleRunResumeAndSecurity(t *testing.T) {
	app, runner, stdout, stderr := newTestApp(t)
	ctx := context.Background()

	if err := config.SaveFile(app.Env.ConfigFile, config.State{
		Agent:     "both",
		Image:     "node:24-bookworm-slim",
		Snapshot:  "agbox:v1",
		SnapCount: 1,
	}); err != nil {
		t.Fatal(err)
	}

	// 1. Empty rules list and status check.
	stdout.Reset()
	if rc := app.Dispatch(ctx, []string{"rules"}); rc != 0 || !strings.Contains(stdout.String(), "No global rules") {
		t.Fatalf("rules empty = %d, %q", rc, stdout.String())
	}
	stdout.Reset()
	if rc := app.Dispatch(ctx, []string{"status"}); rc != 0 || !strings.Contains(stdout.String(), "global_rules: none") {
		t.Fatalf("status empty global_rules = %d, %q", rc, stdout.String())
	}

	// 2. Add rule with custom name, verify duplicate guard, overwrite with --force, >24KB warning, and show/status output.
	tmpSrc := t.TempDir()
	stdFile := filepath.Join(tmpSrc, "standards.md")
	if err := os.WriteFile(stdFile, []byte("# Engineering Standards\nRun gofmt and tests.\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if rc := app.Dispatch(ctx, []string{"rules", "add", "--name", "standards", stdFile}); rc != 0 {
		t.Fatalf("rules add standards failed: %s", stderr.String())
	}
	if rc := app.Dispatch(ctx, []string{"rules", "add", "--name", "standards", stdFile}); rc == 0 {
		t.Fatal("expected duplicate rules add without --force to fail")
	}
	if rc := app.Dispatch(ctx, []string{"rules", "add", "--force", "--name", "standards", stdFile}); rc != 0 {
		t.Fatalf("rules add --force failed: %s", stderr.String())
	}

	largeFile := filepath.Join(tmpSrc, "large-guide.md")
	largeBody := "# Large Guide\n" + strings.Repeat("Always validate inputs.\n", 1100) // > 24,000 bytes, < 64 KiB
	if err := os.WriteFile(largeFile, []byte(largeBody), 0o644); err != nil {
		t.Fatal(err)
	}
	stderr.Reset()
	if rc := app.Dispatch(ctx, []string{"rules", "add", largeFile}); rc != 0 {
		t.Fatalf("rules add large-guide failed: %s", stderr.String())
	}
	if !strings.Contains(stderr.String(), "WARN:") || !strings.Contains(stderr.String(), "24000") {
		t.Errorf("expected >24KB Antigravity truncation warning on stderr, got %q", stderr.String())
	}

	stdout.Reset()
	if rc := app.Dispatch(ctx, []string{"rules", "show", "standards"}); rc != 0 || !strings.Contains(stdout.String(), "Run gofmt and tests.") {
		t.Fatalf("rules show standards = %d, %q", rc, stdout.String())
	}
	stdout.Reset()
	if rc := app.Dispatch(ctx, []string{"rules", "show"}); rc != 0 || !strings.Contains(stdout.String(), "== standards.md ==") || !strings.Contains(stdout.String(), "== large-guide.md ==") {
		t.Fatalf("rules show all = %d, %q", rc, stdout.String())
	}
	stdout.Reset()
	if rc := app.Dispatch(ctx, []string{"status"}); rc != 0 || !strings.Contains(stdout.String(), "global_rules: large-guide, standards") {
		t.Fatalf("status global_rules = %d, %q", rc, stdout.String())
	}

	// 3. Persistent run mounts $DATA_DIR/rules read-only and stages/bind-mounts guest global rules.
	proj := filepath.Join(app.Env.HomeReal, "proj-rules")
	if err := os.MkdirAll(proj, 0o700); err != nil {
		t.Fatal(err)
	}
	wantRulesVol := filepath.Join(app.Env.DataDir, "rules") + ":" + msb.GuestRulesMount + ":ro,uid=1000,gid=1000"

	runner.calls = nil
	if rc := app.Dispatch(ctx, []string{"run", "--persist", "--name", "rulesvm", "antigravity", proj}); rc != 0 {
		t.Fatalf("run with global rules failed: %s", stderr.String())
	}
	foundRulesVol := false
	foundRulesBind := false
	for _, c := range runner.calls {
		joined := strings.Join(c.Args, " ")
		if strings.HasPrefix(joined, "snap restore ") && slices.Contains(c.Args, wantRulesVol) {
			foundRulesVol = true
		}
		if strings.Contains(joined, "/etc/agbox-global-rules/AGENTS.md") && strings.Contains(joined, ".gemini/config/AGENTS.md") && strings.Contains(joined, ".config/opencode/AGENTS.md") {
			foundRulesBind = true
		}
	}
	if !foundRulesVol || !foundRulesBind {
		t.Fatalf("missing global rules volume (%v) or guest bind-mount script (%v)", foundRulesVol, foundRulesBind)
	}

	// 4. Resume re-runs setupGuestRules so host rule edits take effect, while `resume --no-rules` skips it.
	runner.sandboxes = "NAME STATE\nagbox-base stopped\nagbox-rulesvm stopped\n"
	runner.calls = nil
	if rc := app.Dispatch(ctx, []string{"resume", "agbox-rulesvm"}); rc != 0 {
		t.Fatalf("resume agbox-rulesvm failed: %s", stderr.String())
	}
	resumedBind := false
	for _, c := range runner.calls {
		if strings.Contains(strings.Join(c.Args, " "), "/etc/agbox-global-rules/AGENTS.md") {
			resumedBind = true
		}
	}
	if !resumedBind {
		t.Error("expected `agbox resume` to restage and bind-mount global rules")
	}

	runner.calls = nil
	if rc := app.Dispatch(ctx, []string{"resume", "--no-rules", "agbox-rulesvm"}); rc != 0 {
		t.Fatalf("resume --no-rules agbox-rulesvm failed: %s", stderr.String())
	}
	for _, c := range runner.calls {
		if strings.Contains(strings.Join(c.Args, " "), "/etc/agbox-global-rules/AGENTS.md") {
			t.Fatal("expected `agbox resume --no-rules` to skip setupGuestRules")
		}
	}

	// 5. `--no-rules` on `agbox run` omits the global rules volume and skips setupGuestRules.
	runner.calls = nil
	if rc := app.Dispatch(ctx, []string{"run", "--no-rules", "opencode", proj}); rc != 0 {
		t.Fatalf("run --no-rules failed: %s", stderr.String())
	}
	for _, c := range runner.calls {
		if slices.Contains(c.Args, wantRulesVol) {
			t.Fatalf("--no-rules unexpectedly mounted global rules volume: %v", c.Args)
		}
		if strings.Contains(strings.Join(c.Args, " "), "/etc/agbox-global-rules/AGENTS.md") {
			t.Fatal("--no-rules unexpectedly ran setupGuestRules")
		}
	}

	// 6. Symlink planted inside $DATA_DIR/rules fails closed before `snap restore` on run and before `start` on resume.
	badSym := filepath.Join(app.Env.DataDir, "rules", "leak.md")
	if err := os.Symlink("/etc/passwd", badSym); err != nil {
		t.Fatal(err)
	}
	runner.calls = nil
	if rc := app.Dispatch(ctx, []string{"run", "opencode", proj}); rc == 0 {
		t.Fatal("expected Run to fail closed when $DATA_DIR/rules contains a symlink")
	}
	for _, c := range runner.calls {
		if len(c.Args) >= 2 && c.Args[0] == "snap" && c.Args[1] == "restore" {
			t.Fatal("Run restored snapshot despite symlink inside $DATA_DIR/rules")
		}
	}
	runner.calls = nil
	if rc := app.Dispatch(ctx, []string{"resume", "agbox-rulesvm"}); rc == 0 {
		t.Fatal("expected Resume to fail closed when $DATA_DIR/rules contains a symlink")
	}
	for _, c := range runner.calls {
		if len(c.Args) >= 1 && c.Args[0] == "start" {
			t.Fatal("Resume started microVM despite symlink inside $DATA_DIR/rules")
		}
	}
	_ = os.Remove(badSym)

	// 7. Remove single rule and remove --all.
	if rc := app.Dispatch(ctx, []string{"rules", "rm", "large-guide"}); rc != 0 {
		t.Fatalf("rules rm large-guide failed: %s", stderr.String())
	}
	if rc := app.Dispatch(ctx, []string{"rules", "rm", "--all"}); rc != 0 {
		t.Fatalf("rules rm --all failed: %s", stderr.String())
	}
	stdout.Reset()
	if rc := app.Dispatch(ctx, []string{"rules", "list"}); rc != 0 || !strings.Contains(stdout.String(), "No global rules") {
		t.Fatalf("rules list after rm --all = %d, %q", rc, stdout.String())
	}
}
