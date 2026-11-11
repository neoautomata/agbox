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
		{"--port"},
		{"--port", "0"},
		{"--port", "70000"},
		{"--cpus", "0"},
		{"--cpus", "abc"},
		{"--memory"},
		{"--net"},
		{"--cmd"},
		{"--unknown-flag"},
	} {
		if _, err := ParseRunArgs(bad, config.MaskAuto, nil); err == nil {
			t.Errorf("expected error for %v", bad)
		}
	}

	// SelectEffectiveAgent tests.
	if ag, err := SelectEffectiveAgent("both", RunOpts{Serve: true}); err != nil || ag != "opencode" {
		t.Errorf("SelectEffectiveAgent(both, Serve) = %q, %v", ag, err)
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

func (noopMountCtl) ListMounts() ([]mounttab.Entry, error)        { return nil, nil }
func (noopMountCtl) SignalPID(_ int, _ syscall.Signal) error      { return nil }
func (noopMountCtl) Unmount(_ string, _ bool) error               { return nil }
func (noopMountCtl) Sleep(_ time.Duration)                        {}

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
			MaskVCS:          config.MaskAuto,
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
		IsTTY:    func() bool { return true },
		GetEUID:  func() int { return 1000 },
		CheckKVM: func() error { return nil },
		PID:      4242,
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

