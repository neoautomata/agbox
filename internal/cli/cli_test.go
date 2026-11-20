package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
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
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"agbox/internal/config"
	"agbox/internal/mounttab"
	"agbox/internal/msb"
	"agbox/internal/persist"
	"agbox/internal/vcsfuse"
)

func TestParseCreateBaseArgs(t *testing.T) {
	opts, err := parseCreateBaseArgs([]string{"--force", "--add", "core,go,rust,esphome", "opencode"})
	if err != nil || opts.Agent != "opencode" || !opts.Force || len(opts.Categories) != 4 {
		t.Fatalf("ParseCreateBaseArgs(--force --add ... opencode) = %+v, %v", opts, err)
	}
	for _, agent := range []string{"antigravity", "both"} {
		opts, err := parseCreateBaseArgs([]string{agent})
		if err != nil || opts.Agent != agent || opts.Force {
			t.Fatalf("ParseCreateBaseArgs(%s) = %+v, %v", agent, opts, err)
		}
	}
	if _, err := parseCreateBaseArgs([]string{"--help"}); !errors.Is(err, errHelp) {
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
		if _, err := parseCreateBaseArgs(bad); err == nil {
			t.Errorf("expected error for %v", bad)
		}
	}
}

func TestParseEditBaseArgs(t *testing.T) {
	opts, err := parseEditBaseArgs([]string{"--add", "core,go", "rust", "esphome", "--cmd", "apt-get install -y jq", "--no-snap"})
	if err != nil || opts.Cmd != "apt-get install -y jq" || !opts.NoSnap || len(opts.Categories) != 4 {
		t.Fatalf("ParseEditBaseArgs = %+v, %v", opts, err)
	}
	listOpts, err := parseEditBaseArgs([]string{"--list"})
	if err != nil || !listOpts.ListOnly {
		t.Fatalf("ParseEditBaseArgs(--list) = %+v, %v", listOpts, err)
	}
	if _, err := parseEditBaseArgs([]string{"-h"}); !errors.Is(err, errHelp) {
		t.Errorf("expected ErrHelp, got %v", err)
	}
	for _, bad := range [][]string{
		{"--cmd"},
		{"--cmd", ""},
		{"--add"},
		{"--add", "unknown-category"},
		{"--unknown"},
	} {
		if _, err := parseEditBaseArgs(bad); err == nil {
			t.Errorf("expected error for %v", bad)
		}
	}
}

func TestParseRunArgsAndSelectEffectiveAgent(t *testing.T) {
	exists := func(p string) bool { return p == "opencode" }

	// Options appear before paths.
	opts, err := parseRunArgs([]string{
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
	opts2, err := parseRunArgs([]string{"./proj", "opencode"}, config.MaskAuto, exists)
	if err != nil || opts2.Agent != "" || !slices.Equal(opts2.Paths, []string{"./proj", "opencode"}) {
		t.Errorf("expected 'opencode' after path to be treated as path when it exists on disk: %+v, %v", opts2, err)
	}

	// Passing an option after a path must fail.
	if _, err := parseRunArgs([]string{"./proj", "--ro"}, config.MaskAuto, nil); err == nil || !strings.Contains(err.Error(), "options must come before paths") {
		t.Errorf("expected error when option follows path, got %v", err)
	}

	// --port and --probe imply --serve.
	optsServe, err := parseRunArgs([]string{"--port", "8080", "--probe", "--no-mask", "--no-net"}, config.MaskAuto, nil)
	if err != nil || !optsServe.Serve || !optsServe.Probe || optsServe.Port != 8080 || optsServe.MaskMode != config.MaskOff || !optsServe.NoNet {
		t.Errorf("unexpected serve opts: %+v, %v", optsServe, err)
	}

	if _, err := parseRunArgs([]string{"--help"}, config.MaskAuto, nil); !errors.Is(err, errHelp) {
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
		if _, err := parseRunArgs(bad, config.MaskAuto, nil); err == nil {
			t.Errorf("expected error for %v", bad)
		}
	}

	optsRC, err := parseRunArgs([]string{"-d", "--remote-control", "./proj"}, config.MaskAuto, nil)
	if err != nil || !optsRC.RemoteControl || !optsRC.Detach {
		t.Errorf("unexpected remote-control opts: %+v, %v", optsRC, err)
	}

	// SelectEffectiveAgent tests.
	if ag, err := selectEffectiveAgent("both", runOpts{Serve: true}); err != nil || ag != "opencode" {
		t.Errorf("SelectEffectiveAgent(both, Serve) = %q, %v", ag, err)
	}
	if ag, err := selectEffectiveAgent("both", runOpts{RemoteControl: true}); err != nil || ag != "antigravity" {
		t.Errorf("SelectEffectiveAgent(both, RemoteControl) = %q, %v", ag, err)
	}
	if _, err := selectEffectiveAgent("opencode", runOpts{RemoteControl: true}); err == nil {
		t.Error("expected error when --remote-control used with opencode-only base")
	}
	if _, err := selectEffectiveAgent("both", runOpts{Agent: "opencode", RemoteControl: true}); err == nil {
		t.Error("expected error when --remote-control used with opencode agent")
	}
	if _, err := selectEffectiveAgent("both", runOpts{}); err == nil {
		t.Error("expected error when base=both and no agent specified for TUI")
	}
	if _, err := selectEffectiveAgent("both", runOpts{Agent: "antigravity", Serve: true}); err == nil {
		t.Error("expected error when --serve used with antigravity agent on both base")
	}
	if _, err := selectEffectiveAgent("antigravity", runOpts{Agent: "antigravity", Serve: true}); err == nil {
		t.Error("expected error when --serve used with antigravity agent on antigravity base")
	}
	if _, err := selectEffectiveAgent("antigravity", runOpts{Serve: true}); err == nil {
		t.Error("expected error when --serve used with antigravity-only base")
	}
	if _, err := selectEffectiveAgent("opencode", runOpts{Agent: "antigravity"}); err == nil {
		t.Error("expected error when requesting antigravity on opencode-only base")
	}
	if ag, err := selectEffectiveAgent("antigravity", runOpts{}); err != nil || ag != "antigravity" {
		t.Errorf("SelectEffectiveAgent(antigravity) = %q, %v", ag, err)
	}
}

func TestParseStopAndRemoveArgsAndHelpers(t *testing.T) {
	if name, allowRoot, err := parseStopOpts([]string{"agbox-run-1234"}); err != nil || name != "agbox-run-1234" || allowRoot {
		t.Errorf("parseStopOpts = %q, %v, %v", name, allowRoot, err)
	}
	if _, _, err := parseStopOpts([]string{"-h"}); !errors.Is(err, errHelp) {
		t.Errorf("expected ErrHelp, got %v", err)
	}
	for _, bad := range [][]string{
		{},
		{"agbox-base"},
		{"other-sandbox"},
	} {
		if _, _, err := parseStopOpts(bad); err == nil {
			t.Errorf("expected error for %v", bad)
		}
	}

	if yes, allowRoot, err := parseRemoveOpts([]string{"--yes"}); err != nil || !yes || allowRoot {
		t.Errorf("parseRemoveOpts(--yes) = %v, %v, %v", yes, allowRoot, err)
	}
	if yes, _, err := parseRemoveOpts(nil); err != nil || yes {
		t.Errorf("parseRemoveOpts(nil) = %v, %v", yes, err)
	}
	if _, _, err := parseRemoveOpts([]string{"--bad"}); err == nil {
		t.Error("expected error for --bad")
	}

	if !dataDirSupportsFilter("/home/user/.local/share/agbox") {
		t.Error("expected standard path to support filter")
	}
	if dataDirSupportsFilter("/home/user/with space/agbox") || dataDirSupportsFilter(`C:\agbox`) || dataDirSupportsFilter("") {
		t.Error("expected path with space/backslash/empty to fail dataDirSupportsFilter")
	}

	port, err := pickFreeLoopbackPort()
	if err != nil || port < 1 || port > 65535 {
		t.Fatalf("pickFreeLoopbackPort = %d, %v", port, err)
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
	Args   []string
	Stdin  string
	Ctx    context.Context
	CtxErr error
}

type fakeMSBRunner struct {
	calls        []recordedCall
	sandboxes    string
	snapshots    string
	defaultUsers map[string]string
	handler      func(req msb.CommandRequest) (msb.CommandResult, error)
	ctxHandler   func(ctx context.Context, req msb.CommandRequest) (msb.CommandResult, error)
}

func parseFakeExecCall(args []string) (sandbox, explicitUser, cmdStr string) {
	cmdStart := len(args)
	for i := 1; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			cmdStart = i + 1
			break
		}
		if strings.HasPrefix(a, "--user=") {
			explicitUser = strings.TrimPrefix(a, "--user=")
			continue
		}
		if strings.HasPrefix(a, "-u=") {
			explicitUser = strings.TrimPrefix(a, "-u=")
			continue
		}
		switch a {
		case "-d", "--detach", "-t", "--tty", "--stream", "--no-tty", "--no-stdin":
		case "-w", "--workdir", "-e", "--env":
			i++
		case "-u", "--user":
			if i+1 < len(args) {
				explicitUser = args[i+1]
				i++
			}
		default:
			if !strings.HasPrefix(a, "-") && sandbox == "" {
				sandbox = a
			}
		}
	}
	if cmdStart < len(args) {
		cmdStr = strings.Join(args[cmdStart:], " ")
	}
	return sandbox, explicitUser, cmdStr
}

func execCommandRequiresRoot(cmdStr string) bool {
	for _, tok := range []string{
		"mount --bind",
		"remount,ro,bind",
		"/etc/agbox-global-rules",
		"/etc/sudoers.d/",
		"drop_caches",
		"npm install -g",
		"ln -sfn /home/agent/.local/bin/agy /usr/local/bin/agy",
	} {
		if strings.Contains(cmdStr, tok) {
			return true
		}
	}
	return false
}

func (f *fakeMSBRunner) trackDefaultUsers(args []string) {
	if len(args) == 0 {
		return
	}
	if f.defaultUsers == nil {
		f.defaultUsers = make(map[string]string)
	}
	isCreate := args[0] == "create"
	isRestore := len(args) >= 2 && args[0] == "snap" && args[1] == "restore"
	if isCreate || isRestore {
		var name string
		user := "root"
		for i := 0; i < len(args); i++ {
			switch args[i] {
			case "--name":
				if i+1 < len(args) {
					name = args[i+1]
					i++
				}
			case "-u", "--user":
				if i+1 < len(args) {
					user = args[i+1]
					i++
				}
			}
		}
		if name != "" {
			f.defaultUsers[name] = user
		}
		return
	}
	if len(args) >= 2 && args[0] == "rm" {
		for _, a := range args[1:] {
			if !strings.HasPrefix(a, "-") {
				delete(f.defaultUsers, a)
			}
		}
	}
}

func (f *fakeMSBRunner) Run(ctx context.Context, req msb.CommandRequest) (msb.CommandResult, error) {
	var stdinStr string
	if req.Stdin != nil {
		raw, _ := io.ReadAll(req.Stdin)
		stdinStr = string(raw)
	}
	f.calls = append(f.calls, recordedCall{
		Args:   slices.Clone(req.Args),
		Stdin:  stdinStr,
		Ctx:    ctx,
		CtxErr: ctx.Err(),
	})
	f.trackDefaultUsers(req.Args)

	if len(req.Args) >= 1 && req.Args[0] == "exec" {
		sandbox, explicitUser, cmdStr := parseFakeExecCall(req.Args)
		effectiveUser := explicitUser
		if effectiveUser == "" {
			if u, ok := f.defaultUsers[sandbox]; ok {
				effectiveUser = u
			} else if isRunSandboxName(sandbox) {
				effectiveUser = config.GuestUser
			} else {
				effectiveUser = "root"
			}
		}
		if execCommandRequiresRoot(cmdStr) && effectiveUser != "root" {
			return msb.CommandResult{
				Stderr:   "mount: must be superuser",
				ExitCode: 1,
			}, fmt.Errorf("guest command requires root (got user=%s)", effectiveUser)
		}
	}

	if f.ctxHandler != nil {
		return f.ctxHandler(ctx, req)
	}
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

func newTestApp(t *testing.T) (*appRuntime, *fakeMSBRunner, *bytes.Buffer, *bytes.Buffer) {
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

	app := &appRuntime{
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
		IsTTY:      func() bool { return true },
		GetEUID:    func() int { return 1000 },
		GetEGID:    func() int { return 1000 },
		RunHostCmd: func(context.Context, string, ...string) ([]byte, error) { return nil, nil },
		CheckKVM:   func() error { return nil },
		CheckFUSE:  func() error { return nil },
		PID:        4242,
		StartFilter: func(_, mntDir, pidFile string, _ bool) (int, error) {
			_ = os.MkdirAll(mntDir, 0o700)
			_ = os.WriteFile(pidFile, []byte("9999\n"), 0o600)
			return 9999, nil
		},
		StartHub: func(mntDir, _, pidFile string, _ []vcsfuse.HubShareConfig, _ bool) (int, error) {
			_ = os.MkdirAll(mntDir, 0o700)
			_ = os.WriteFile(pidFile, []byte("9998\n"), 0o600)
			return 9998, nil
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
	if rc := app.dispatch(ctx, []string{"setup"}); rc != 0 {
		t.Fatalf("Setup failed with rc=%d, stdout=%s", rc, stdout.String())
	}

	// 2. CreateBase (both)
	runner.snapshots = "NAME CREATED\n"
	if rc := app.dispatch(ctx, []string{"create-base", "--force", "both"}); rc != 0 {
		t.Fatalf("CreateBase failed with rc=%d", rc)
	}
	st, err := config.LoadFile(app.Env.ConfigFile)
	if err != nil || st.Snapshot != "agbox:v1" || st.Agent != "both" {
		t.Fatalf("saved state after CreateBase = %+v, %v", st, err)
	}

	// 3. EditBase (--add core,go,rust,esphome and --list)
	if rc := app.dispatch(ctx, []string{"edit-base", "--list"}); rc != 0 {
		t.Fatalf("EditBase --list failed with rc=%d", rc)
	}
	runner.snapshots = "NAME CREATED\nagbox:v1 1m\n"
	if rc := app.dispatch(ctx, []string{"edit-base", "--add", "core,go,rust,esphome"}); rc != 0 {
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
	if rc := app.dispatch(ctx, []string{"run", "--cmd", "id -u", projDir}); rc != 0 {
		t.Fatalf("Run --cmd failed with rc=%d", rc)
	}

	// Verify the system streamed the API key over stdin and deleted the microVM on exit.
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
	if rc := app.dispatch(ctx, []string{"run", "--serve", "--port", "4096", projDir}); rc != 0 {
		t.Fatalf("Run detached --serve failed with rc=%d", rc)
	}
	detachedMarker := filepath.Join(app.Env.DataDir, "run", "4242", "detached")
	if _, err := os.Stat(detachedMarker); err != nil {
		t.Fatalf("expected detached marker at %s: %v", detachedMarker, err)
	}

	// 6. Stop the detached sandbox
	if rc := app.dispatch(ctx, []string{"stop", "agbox-run-4242"}); rc != 0 {
		t.Fatalf("Stop failed with rc=%d", rc)
	}
	if _, err := os.Stat(filepath.Join(app.Env.DataDir, "run", "4242")); !os.IsNotExist(err) {
		t.Errorf("expected filter dir for 4242 to be removed on Stop, stat err=%v", err)
	}

	// 6b. Run (-d --remote-control detached with TTY=true)
	app.IsTTY = func() bool { return true }
	if rc := app.dispatch(ctx, []string{"run", "-d", "--remote-control", projDir}); rc != 0 {
		t.Fatalf("Run -d --remote-control failed with rc=%d", rc)
	}
	if _, err := os.Stat(detachedMarker); err != nil {
		t.Fatalf("expected detached marker for remote-control at %s: %v", detachedMarker, err)
	}
	if rc := app.dispatch(ctx, []string{"stop", "agbox-run-4242"}); rc != 0 {
		t.Fatalf("Stop failed with rc=%d", rc)
	}

	// 7. Status
	if rc := app.dispatch(ctx, []string{"status"}); rc != 0 {
		t.Fatalf("Status failed with rc=%d", rc)
	}

	// 8. Remove (--yes)
	if rc := app.dispatch(ctx, []string{"remove", "--yes"}); rc != 0 {
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

	// Configure two dead-PID filter dirs: one normal (999991) and one detached (999992).
	deadDir := filepath.Join(app.Env.DataDir, "run", "999991")
	detachedDir := filepath.Join(app.Env.DataDir, "run", "999992")
	_ = os.MkdirAll(deadDir, 0o700)
	_ = os.MkdirAll(detachedDir, 0o700)
	_ = os.WriteFile(filepath.Join(detachedDir, "detached"), []byte("agbox-run-999992\n"), 0o600)

	runner.sandboxes = "NAME STATE\nagbox-base stopped\nagbox-run-999991 running\nagbox-run-999992 running\n"

	app.reapOrphanRuns(ctx)
	app.reapStaleFilterDirs(ctx)

	// Dead non-detached run (999991) must be deleted. Live detached run (999992) must remain.
	if _, err := os.Stat(deadDir); !os.IsNotExist(err) {
		t.Errorf("expected dead filter dir 999991 to be reaped, err=%v", err)
	}
	if _, err := os.Stat(detachedDir); err != nil {
		t.Errorf("expected live detached filter dir 999992 to be preserved, err=%v", err)
	}

	// Test interactive TUI run mode.
	app.IsTTY = func() bool { return true }
	if rc := app.dispatch(ctx, []string{"run", "opencode"}); rc != 0 {
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
	if rc := app.dispatch(ctx, []string{"run", "--serve", "--probe", "--port", strconv.Itoa(srvPort)}); rc != 0 {
		t.Fatalf("Run --serve --probe failed with rc=%d", rc)
	}

	// Test EditBase interactive category selection (choosing '1,2' on Stdin) + --no-snap.
	app.Stdin = strings.NewReader("1,2\n")
	if rc := app.dispatch(ctx, []string{"edit-base", "--no-snap"}); rc != 0 {
		t.Fatalf("EditBase interactive selection --no-snap failed with rc=%d", rc)
	}

	// Test Remove interactive abort when user types 'n'.
	app.Stdin = strings.NewReader("n\n")
	if rc := app.dispatch(ctx, []string{"remove"}); rc == 0 {
		t.Error("expected Remove to abort when user enters 'n'")
	}

	// Help and unknown mode dispatch.
	if rc := app.dispatch(ctx, nil); rc != 0 {
		t.Errorf("Dispatch(nil) = %d, want 0", rc)
	}
	if rc := app.dispatch(ctx, []string{"--help"}); rc != 0 {
		t.Errorf("Dispatch(--help) = %d, want 0", rc)
	}
	if rc := app.dispatch(ctx, []string{"run", "--help"}); rc != 0 {
		t.Errorf("Dispatch(run --help) = %d, want 0", rc)
	}
	if rc := app.dispatch(ctx, []string{"nonexistent-mode"}); rc == 0 {
		t.Error("expected non-zero exit code for unknown mode")
	}
}

func TestSandboxNamingAndGlobalAndRootParsing(t *testing.T) {
	gOpts, err := parseGlobalArgs([]string{"--allow-root", "run", "--name", "feat1"})
	if err != nil || !gOpts.AllowRoot || gOpts.Mode != "run" || !slices.Equal(gOpts.Rest, []string{"--name", "feat1"}) {
		t.Fatalf("ParseGlobalArgs = %+v, %v", gOpts, err)
	}
	if _, err := parseGlobalArgs([]string{"--unknown", "run"}); err == nil {
		t.Error("expected error for unknown global option")
	}

	if src, err := checkRootExecution(1000, false, false); err != nil || src != "" {
		t.Errorf("CheckRootExecution(1000) = %q, %v", src, err)
	}
	if _, err := checkRootExecution(0, false, false); err == nil {
		t.Error("expected error for root without override")
	}
	if src, err := checkRootExecution(0, false, true); err != nil || src != "--allow-root" {
		t.Errorf("CheckRootExecution(flag) = %q, %v", src, err)
	}
	if src, err := checkRootExecution(0, true, false); err != nil || src != "AGBOX_ALLOW_ROOT=1" {
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
			gotName, err := validateRunName(tc.name)
			if err != nil || gotName != tc.name {
				t.Fatalf("ValidateRunName(%q) = %q, %v", tc.name, gotName, err)
			}
		}
		sbx := formatRunSandboxName(tc.name, tc.pid)
		if sbx != tc.sandbox {
			t.Fatalf("FormatRunSandboxName(%q, %d) = %q, want %q", tc.name, tc.pid, sbx, tc.sandbox)
		}
		if !isRunSandboxName(sbx) {
			t.Fatalf("expected IsRunSandboxName(%q) to be true", sbx)
		}
		dirID, err := runDirIDFromSandbox(sbx)
		if err != nil || dirID != tc.dirID {
			t.Fatalf("RunDirIDFromSandbox(%q) = %q, %v (want %q)", sbx, dirID, err, tc.dirID)
		}
		roundTrip, ok := sandboxFromRunDirID(dirID)
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
		if _, err := validateRunName(bad); err == nil {
			t.Errorf("expected ValidateRunName(%q) to fail", bad)
		}
	}
	if isRunSandboxName("agbox-base") || isRunSandboxName("other-sandbox") || isRunSandboxName("agbox-") {
		t.Error("expected invalid sandbox names to fail IsRunSandboxName")
	}

	defOpts, err := parseRunArgs([]string{"--name", "feat1", "--allow-root", "opencode"}, "", nil)
	if err != nil || defOpts.MaskMode != config.MaskStrict || defOpts.Name != "feat1" || !defOpts.AllowRoot {
		t.Fatalf("ParseRunArgs defaults = %+v, %v", defOpts, err)
	}
	eqOpts, err := parseRunArgs([]string{"--name=feat2", "opencode"}, "", nil)
	if err != nil || eqOpts.Name != "feat2" {
		t.Fatalf("ParseRunArgs(--name=feat2) = %+v, %v", eqOpts, err)
	}
	for _, badRun := range [][]string{
		{"--name"},
		{"--name", ""},
		{"--name", "base"},
		{"--name=-bad"},
	} {
		if _, err := parseRunArgs(badRun, "", nil); err == nil {
			t.Errorf("expected ParseRunArgs(%v) to fail", badRun)
		}
	}

	if sOpts, err := parseSuspendArgs([]string{"--allow-root", "agbox-feat1"}); err != nil || sOpts.Sandbox != "agbox-feat1" || !sOpts.AllowRoot {
		t.Fatalf("ParseSuspendArgs = %+v, %v", sOpts, err)
	}
	if rOpts, err := parseResumeArgs([]string{"--allow-root", "-d", "agbox-feat1"}); err != nil || rOpts.Sandbox != "agbox-feat1" || !rOpts.AllowRoot || !rOpts.Detach {
		t.Fatalf("ParseResumeArgs = %+v, %v", rOpts, err)
	}
	if name, _, err := parseStopOpts([]string{"agbox-feat1"}); err != nil || name != "agbox-feat1" {
		t.Fatalf("parseStopOpts(agbox-feat1) = %q, %v", name, err)
	}
	for _, bad := range [][]string{
		{},
		{"agbox-base"},
		{"other-sandbox"},
		{"--bad", "agbox-feat1"},
	} {
		if _, err := parseSuspendArgs(bad); err == nil {
			t.Errorf("expected ParseSuspendArgs(%v) to fail", bad)
		}
		if _, err := parseResumeArgs(bad); err == nil {
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
		if rc := app.dispatch(ctx, cmd); rc == 0 {
			t.Errorf("expected mode %v to fail as root without --allow-root", cmd)
		}
	}

	stderr.Reset()
	if rc := app.dispatch(ctx, []string{"--allow-root", "setup"}); rc != 0 {
		t.Fatalf("expected global --allow-root setup to succeed, stderr=%s", stderr.String())
	}
	if !strings.Contains(stderr.String(), "Root mode is active") {
		t.Errorf("expected root warning in stderr, got %q", stderr.String())
	}

	stderr.Reset()
	app.Env.AllowRoot = true
	if rc := app.dispatch(ctx, []string{"status"}); rc != 0 {
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
	if rc := app.dispatch(ctx, []string{"run", "--name", "sec1", "--cmd", "id", projDir}); rc != 0 {
		t.Fatalf("Run --name sec1 failed: %s", stderr.String())
	}
	foundRestore := false
	for _, c := range runner.calls {
		joined := strings.Join(c.Args, " ")
		if strings.HasPrefix(joined, "snap restore ") {
			foundRestore = true
			for _, want := range []string{
				"--name agbox-sec1",
				"/run/sec1/ws:/workspace:rw,stat-virt=off",
				"--net-default deny --net-rule allow@dns --net-rule deny@host --net-rule deny@loopback --net-rule deny@private --net-rule deny@link-local --net-rule deny@multicast --net-rule deny@meta",
				"--net-rule deny@168.63.129.16/32",
				"--net-rule deny@100.100.100.200/32",
				"--net-rule deny@[fd00:ec2::254/128]",
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
	origHub := app.StartHub
	app.StartHub = func(_, _, _ string, _ []vcsfuse.HubShareConfig, _ bool) (int, error) {
		return 0, errors.New("fuse unavailable")
	}
	runner.calls = nil
	if rc := app.dispatch(ctx, []string{"run", "--name", "sec2", "--cmd", "id", projDir}); rc == 0 {
		t.Fatal("expected Run to fail closed when FUSE filter fails")
	}
	for _, c := range runner.calls {
		if len(c.Args) >= 2 && c.Args[0] == "snap" && c.Args[1] == "restore" {
			t.Fatal("Run restored snapshot despite FUSE filter failure")
		}
	}
	app.StartHub = origHub

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
	if rc := app.dispatch(ctx, []string{"run", "--name", "keyfail", "--cmd", "id"}); rc == 0 {
		t.Fatal("expected Run to fail closed when pushKeys fails")
	}
	runner.handler = nil

	// 4. Duplicate --name must fail closed without removing the existing sandbox.
	runner.sandboxes = "NAME STATE\nagbox-base stopped\nagbox-existing running\n"
	runner.calls = nil
	if rc := app.dispatch(ctx, []string{"run", "--name", "existing", "--cmd", "id"}); rc == 0 {
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
	if rc := app.dispatch(ctx, []string{"setup"}); rc != 0 {
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
	if rc := app.dispatch(ctx, []string{"setup"}); rc == 0 {
		t.Fatal("expected Setup to fail closed when CheckFUSE fails")
	}
	app.CheckFUSE = func() error { return nil }

	badApp := *app
	badApp.Env.DataDir = filepath.Join(app.Env.HomeReal, "dir with space")
	if rc := badApp.dispatch(ctx, []string{"setup"}); rc == 0 {
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
	if rc := app.dispatch(ctx, []string{"edit-base", "--cmd", "true"}); rc == 0 {
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
	if rc := app.dispatch(ctx, []string{"run", "--name", "work1", "-d", "--remote-control", projDir}); rc != 0 {
		t.Fatalf("Run -d --remote-control failed: %s", stderr.String())
	}
	workDir := filepath.Join(app.Env.DataDir, "run", "work1")
	if _, err := os.Stat(filepath.Join(workDir, "ws.pid")); err != nil {
		t.Fatalf("expected ws.pid before suspend: %v", err)
	}

	// 2. Suspend agbox-work1.
	runner.sandboxes = "NAME STATE\nagbox-base stopped\nagbox-work1 running\n"
	runner.calls = nil
	if rc := app.dispatch(ctx, []string{"suspend", "agbox-work1"}); rc != 0 {
		t.Fatalf("Suspend failed: %s", stderr.String())
	}
	if _, err := os.Stat(filepath.Join(workDir, "suspended")); err != nil {
		t.Fatalf("expected suspended metadata at %s: %v", workDir, err)
	}
	if _, err := os.Stat(filepath.Join(workDir, "ws.pid")); !os.IsNotExist(err) {
		t.Errorf("expected ws.pid to be removed on suspend, err=%v", err)
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
	otherApp.reapOrphanRuns(ctx)
	otherApp.reapStaleFilterDirs(ctx)
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
	if rc := app.dispatch(ctx, []string{"resume", "agbox-work1"}); rc == 0 {
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
	if rc := app.dispatch(ctx, []string{"resume", "agbox-work1"}); rc == 0 {
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
	if rc := app.dispatch(ctx, []string{"resume", "agbox-work1"}); rc != 0 {
		t.Fatalf("Resume failed: %s", stderr.String())
	}
	if _, err := os.Stat(filepath.Join(workDir, "suspended")); !os.IsNotExist(err) {
		t.Errorf("expected suspended marker to be removed after Resume, err=%v", err)
	}
	if _, err := os.Stat(filepath.Join(workDir, "ws.pid")); err != nil {
		t.Errorf("expected ws.pid to be remounted at same path after Resume: %v", err)
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
	if rc := app.dispatch(ctx, []string{"stop", "agbox-work1"}); rc != 0 {
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
			if sRC := peerApp.dispatch(ctx, []string{"suspend", "agbox-tui1"}); sRC != 0 {
				t.Errorf("peer suspend failed: %s", peerErr.String())
			}
			return msb.CommandResult{ExitCode: 137}, errors.New("vm halted")
		}
		return msb.CommandResult{}, nil
	}

	runner.calls = nil
	if rc := app.dispatch(ctx, []string{"run", "--name", "tui1", "opencode", projDir}); rc != 0 {
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
	if rc := app.dispatch(ctx, []string{"stop", "agbox-tui1"}); rc != 0 {
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
	if rc := app.dispatch(ctx, []string{"create-base", "antigravity"}); rc != 0 {
		t.Fatalf("CreateBase(antigravity) failed: %s", stderr.String())
	}
	foundCreateNet := false
	foundAgyTLS := false
	foundBaseApt := false
	foundBaseTools := false
	for _, c := range runner.calls {
		joined := strings.Join(c.Args, " ")
		if strings.HasPrefix(joined, "create ") {
			foundCreateNet = true
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
				if !strings.Contains(joined, must) {
					t.Errorf("CreateBase msb create %q missing %q", joined, must)
				}
			}
		}
		if strings.Contains(joined, "apt-get install") && strings.Contains(joined, "shellcheck") && strings.Contains(joined, "pipx") {
			foundBaseApt = true
		}
		if strings.Contains(joined, "pipx install --force mdformat") && strings.Contains(joined, "shellcheck --version") {
			foundBaseTools = true
		}
		if strings.Contains(joined, "antigravity.google") {
			foundAgyTLS = strings.Contains(joined, "=https") && strings.Contains(joined, "--tlsv1.2 -fsSL --")
		}
	}
	if !foundCreateNet || !foundAgyTLS || !foundBaseApt || !foundBaseTools {
		t.Errorf("CreateBase missing network isolation (%v), TLS curl flags (%v), base apt (%v), or base tools (%v)", foundCreateNet, foundAgyTLS, foundBaseApt, foundBaseTools)
	}

	// Provisioning failure in CreateBase must delete partial agbox-base.
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
	if rc := app.dispatch(ctx, []string{"create-base", "--force", "opencode"}); rc == 0 {
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
	if rc := app.dispatch(ctx, []string{"edit-base", "--cmd", "true"}); rc == 0 {
		t.Fatal("expected EditBase to fail closed when provisionGuestUser fails")
	}
	runner.handler = nil

	// 3. Run mounts zero host shares when no paths are passed, and --serve binds only 127.0.0.1.
	runner.calls = nil
	if rc := app.dispatch(ctx, []string{"run", "--name", "noshare", "--serve", "--probe", "--port", "4321"}); rc != 0 {
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
			if !slices.Contains(c.Args, "allow:ingress@loopback:tcp:3000") {
				t.Errorf("expected loopback ingress rule allow:ingress@loopback:tcp:3000 in %v", c.Args)
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
		if rc := symApp.dispatch(ctx, modeArgs); rc == 0 {
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
		if rc := app.dispatch(ctx, []string{"resume", "agbox-tamp1"}); rc == 0 {
			t.Errorf("tampered Resume case %d unexpectedly succeeded: %+v", idx, badMeta)
		}
	}
}

func TestParsePersistenceModeAndFlagArgs(t *testing.T) {
	// 1. ParseAuthArgs
	if aOpts, err := parseAuthArgs(nil); err != nil || aOpts.Action != "login" || aOpts.Target != "" {
		t.Fatalf("ParseAuthArgs(nil) = %+v, %v", aOpts, err)
	}
	if aOpts, err := parseAuthArgs([]string{"--allow-root", "antigravity"}); err != nil || aOpts.Action != "login" || aOpts.Target != "antigravity" || !aOpts.AllowRoot {
		t.Fatalf("ParseAuthArgs(antigravity) = %+v, %v", aOpts, err)
	}
	if aOpts, err := parseAuthArgs([]string{"login", "opencode"}); err != nil || aOpts.Action != "login" || aOpts.Target != "opencode" {
		t.Fatalf("ParseAuthArgs(login opencode) = %+v, %v", aOpts, err)
	}
	if aOpts, err := parseAuthArgs([]string{"status"}); err != nil || aOpts.Action != "status" {
		t.Fatalf("ParseAuthArgs(status) = %+v, %v", aOpts, err)
	}
	if aOpts, err := parseAuthArgs([]string{"logout"}); err != nil || aOpts.Action != "logout" || aOpts.Target != "all" {
		t.Fatalf("ParseAuthArgs(logout) = %+v, %v", aOpts, err)
	}
	if aOpts, err := parseAuthArgs([]string{"logout", "opencode"}); err != nil || aOpts.Action != "logout" || aOpts.Target != "opencode" {
		t.Fatalf("ParseAuthArgs(logout opencode) = %+v, %v", aOpts, err)
	}
	if _, err := parseAuthArgs([]string{"--help"}); !errors.Is(err, errHelp) {
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
		if _, err := parseAuthArgs(bad); err == nil {
			t.Errorf("expected ParseAuthArgs(%v) to fail", bad)
		}
	}

	// 2. ParseSkillsArgs
	if sOpts, err := parseSkillsArgs(nil); err != nil || sOpts.Action != "list" {
		t.Fatalf("ParseSkillsArgs(nil) = %+v, %v", sOpts, err)
	}
	if sOpts, err := parseSkillsArgs([]string{"--allow-root", "add", "--force", "./my-skill"}); err != nil || sOpts.Action != "add" || !sOpts.Force || !sOpts.AllowRoot || sOpts.Target != "./my-skill" {
		t.Fatalf("ParseSkillsArgs(add) = %+v, %v", sOpts, err)
	}
	if sOpts, err := parseSkillsArgs([]string{"rm", "my-skill"}); err != nil || sOpts.Action != "rm" || sOpts.Target != "my-skill" {
		t.Fatalf("ParseSkillsArgs(rm) = %+v, %v", sOpts, err)
	}
	if _, err := parseSkillsArgs([]string{"-h"}); !errors.Is(err, errHelp) {
		t.Errorf("expected ErrHelp, got %v", err)
	}
	for _, bad := range [][]string{
		{"--bad"},
		{"list", "extra"},
		{"add"},
		{"rm"},
		{"unknown"},
	} {
		if _, err := parseSkillsArgs(bad); err == nil {
			t.Errorf("expected ParseSkillsArgs(%v) to fail", bad)
		}
	}

	// 3. ParseProfileArgs
	if pOpts, err := parseProfileArgs(nil); err != nil || pOpts.Action != "list" {
		t.Fatalf("ParseProfileArgs(nil) = %+v, %v", pOpts, err)
	}
	if pOpts, err := parseProfileArgs([]string{"--allow-root", "create", "--size", "16g", "work1"}); err != nil || pOpts.Action != "create" || pOpts.Name != "work1" || pOpts.Size != "16G" || !pOpts.AllowRoot {
		t.Fatalf("ParseProfileArgs(create) = %+v, %v", pOpts, err)
	}
	if pOpts, err := parseProfileArgs([]string{"rm", "--force", "work1"}); err != nil || pOpts.Action != "rm" || pOpts.Name != "work1" || !pOpts.Force {
		t.Fatalf("ParseProfileArgs(rm) = %+v, %v", pOpts, err)
	}
	if _, err := parseProfileArgs([]string{"--help"}); !errors.Is(err, errHelp) {
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
		if _, err := parseProfileArgs(bad); err == nil {
			t.Errorf("expected ParseProfileArgs(%v) to fail", bad)
		}
	}

	// 4. ParseRunArgs persistence flags and mutual exclusions
	rPersist, err := parseRunArgs([]string{"--name", "dev1", "--persist", "-c", "--no-auth", "--no-skills", "opencode"}, "", nil)
	if err != nil || !rPersist.Persist || !rPersist.Continue || !rPersist.NoAuth || !rPersist.NoSkills {
		t.Fatalf("ParseRunArgs(--persist) = %+v, %v", rPersist, err)
	}
	rProf, err := parseRunArgs([]string{"--profile=team_1", "--conversation=conv-123", "antigravity"}, "", nil)
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
		if _, err := parseRunArgs(bad, "", nil); err == nil {
			t.Errorf("expected ParseRunArgs(%v) to fail", bad)
		}
	}
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"-c", "--cmd", "id"}, "cannot combine --continue or --session with --serve or --cmd"},
		{[]string{"-c", "--serve"}, "cannot combine --continue or --session with --serve or --cmd"},
		{[]string{"-c", "-d", "--remote-control"}, "cannot combine --continue or --session with detached --remote-control"},
	} {
		if _, err := parseRunArgs(tc.args, "", nil); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("ParseRunArgs(%v) error = %v, want substring %q", tc.args, err, tc.want)
		}
	}

	// 5. ParseResumeArgs continuation flags
	resOpts, err := parseResumeArgs([]string{"--conversation=conv-42", "--no-auth", "--no-skills", "agbox-dev1"})
	if err != nil || resOpts.ContinueSession != "conv-42" || !resOpts.NoAuth || !resOpts.NoSkills {
		t.Fatalf("ParseResumeArgs = %+v, %v", resOpts, err)
	}
	for _, bad := range [][]string{
		{"-c", "--session", "s1", "agbox-dev1"},
		{"--session", "bad;id", "agbox-dev1"},
		{"--session"},
	} {
		if _, err := parseResumeArgs(bad); err == nil {
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
		if rc := app.dispatch(ctx, []string{mode, "--help"}); rc != 0 || !strings.Contains(stdout.String(), "Usage:") {
			t.Fatalf("Dispatch(%s --help) = %d, out=%q", mode, rc, stdout.String())
		}
	}

	// 1. Initial auth status is unconfigured.
	stdout.Reset()
	if rc := app.dispatch(ctx, []string{"auth", "status"}); rc != 0 {
		t.Fatalf("auth status failed: %s", stderr.String())
	}
	if !strings.Contains(stdout.String(), "antigravity: not configured") || !strings.Contains(stdout.String(), "opencode: not configured") {
		t.Fatalf("unexpected initial auth status: %q", stdout.String())
	}

	// 2. Non-TTY or missing agent when base=both fails closed.
	if rc := app.dispatch(ctx, []string{"auth"}); rc == 0 {
		t.Fatal("expected auth without agent to fail when base=both")
	}
	app.IsTTY = func() bool { return false }
	if rc := app.dispatch(ctx, []string{"auth", "antigravity"}); rc == 0 {
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
	if rc := app.dispatch(ctx, []string{"auth", "antigravity"}); rc == 0 {
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
	if rc := app.dispatch(ctx, []string{"auth", "antigravity"}); rc != 0 {
		t.Fatalf("auth antigravity failed: %s", stderr.String())
	}
	for _, c := range runner.calls {
		if len(c.Args) >= 2 && c.Args[0] == "snap" && c.Args[1] == "restore" && slices.Contains(c.Args, "-v") {
			t.Fatalf("auth VM must boot with zero host shares, got %v", c.Args)
		}
		if len(c.Args) >= 1 && c.Args[0] == "exec" && strings.Contains(strings.Join(c.Args, " "), "printf 'FILE ") {
			if !slices.Contains(c.Args, "--stream") || !slices.Contains(c.Args, "--no-stdin") {
				t.Fatalf("auth capScript must pass --stream and --no-stdin, got %v", c.Args)
			}
		}
	}
	if rc := app.dispatch(ctx, []string{"auth", "opencode"}); rc != 0 {
		t.Fatalf("auth opencode failed: %s", stderr.String())
	}
	runner.handler = nil

	// Verify 0600 permissions on saved host credential files.
	stToken, err := os.Stat(filepath.Join(app.Env.DataDir, "auth", "antigravity", "antigravity-oauth-token"))
	if err != nil || stToken.Mode().Perm() != 0o600 {
		t.Fatalf("saved oauth token stat = (%v, %v), want mode 0600", stToken, err)
	}

	stdout.Reset()
	if rc := app.dispatch(ctx, []string{"auth", "status"}); rc != 0 {
		t.Fatalf("auth status failed: %s", stderr.String())
	}
	if !strings.Contains(stdout.String(), "antigravity: configured") || !strings.Contains(stdout.String(), "opencode: configured") {
		t.Fatalf("expected both agents configured, got %q", stdout.String())
	}

	// 5. Run streams saved auth over stdin (never in CLI args), and --no-auth skips it.
	runner.calls = nil
	if rc := app.dispatch(ctx, []string{"run", "antigravity"}); rc != 0 {
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
	if rc := app.dispatch(ctx, []string{"run", "--no-auth", "antigravity"}); rc != 0 {
		t.Fatalf("run --no-auth failed: %s", stderr.String())
	}
	for _, c := range runner.calls {
		if strings.Contains(c.Stdin, "antigravity-oauth-token") {
			t.Fatal("expected --no-auth to skip streaming saved credentials")
		}
	}

	// 6. Logout removes credentials.
	if rc := app.dispatch(ctx, []string{"auth", "logout", "all"}); rc != 0 {
		t.Fatalf("auth logout all failed: %s", stderr.String())
	}
	stdout.Reset()
	_ = app.dispatch(ctx, []string{"auth", "status"})
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
	if rc := app.dispatch(ctx, []string{"skills"}); rc != 0 || !strings.Contains(stdout.String(), "No global skills") {
		t.Fatalf("skills list empty = %d, %q", rc, stdout.String())
	}

	skillSrc := filepath.Join(t.TempDir(), "code-audit")
	if err := os.MkdirAll(skillSrc, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(skillSrc, "SKILL.md"), []byte("---\nname: code-audit\n---\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if rc := app.dispatch(ctx, []string{"skills", "add", skillSrc}); rc != 0 {
		t.Fatalf("skills add failed: %s", stderr.String())
	}
	if rc := app.dispatch(ctx, []string{"skills", "add", skillSrc}); rc == 0 {
		t.Fatal("expected duplicate skills add without --force to fail")
	}
	if rc := app.dispatch(ctx, []string{"skills", "add", "--force", skillSrc}); rc != 0 {
		t.Fatalf("skills add --force failed: %s", stderr.String())
	}
	stdout.Reset()
	if rc := app.dispatch(ctx, []string{"skills", "list"}); rc != 0 || strings.TrimSpace(stdout.String()) != "code-audit" {
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
	if rc := app.dispatch(ctx, []string{"run", "antigravity", proj1}); rc != 0 {
		t.Fatalf("run antigravity proj1 failed: %s", stderr.String())
	}
	wantSkillsVol := filepath.Join(app.Env.DataDir, "skills") + ":" + msb.GuestSkillsMount + ":ro,stat-virt=relaxed,uid=1000,gid=1000"
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
	if rc := app.dispatch(ctx, []string{"run", "--no-skills", "antigravity", proj1, proj2}); rc != 0 {
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
	if rc := app.dispatch(ctx, []string{"run", "antigravity", proj1}); rc == 0 {
		t.Fatal("expected Run to fail closed when $DATA_DIR/skills contains a symlink")
	}
	for _, c := range runner.calls {
		if len(c.Args) >= 2 && c.Args[0] == "snap" && c.Args[1] == "restore" {
			t.Fatal("Run restored snapshot despite symlink inside $DATA_DIR/skills")
		}
	}
	_ = os.Remove(badSym)

	// 5. Remove skill cleanly.
	if rc := app.dispatch(ctx, []string{"skills", "rm", "code-audit"}); rc != 0 {
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
	if rc := app.dispatch(ctx, []string{"run", "--persist", "--name", "broken1", "opencode", projA}); rc == 0 {
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
	if rc := app.dispatch(ctx, []string{"run", "--persist", "--name", "dev1", "opencode", projA}); rc != 0 {
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
	if rc := app.dispatch(ctx, []string{"run", "--persist", "--name", "dev1", "opencode", projB}); rc == 0 {
		t.Fatal("expected repeat --persist run with mismatched share path to fail")
	}
	if _, err := os.Stat(filepath.Join(dev1Dir, "suspended")); err != nil {
		t.Fatalf("expected suspended marker to remain after share mismatch: %v", err)
	}

	// 4. Repeat --persist run with matching share and -c resumes agbox-dev1 with `opencode -c` and re-suspends on exit.
	runner.calls = nil
	stderr.Reset()
	if rc := app.dispatch(ctx, []string{"run", "--persist", "--name", "dev1", "-c", "opencode", projA}); rc != 0 {
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
	if rc := app.dispatch(ctx, []string{"resume", "--session", "ses_42", "agbox-dev1"}); rc != 0 {
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

	if rc := app.dispatch(ctx, []string{"stop", "agbox-dev1"}); rc != 0 {
		t.Fatalf("stop agbox-dev1 failed: %s", stderr.String())
	}
	if _, err := os.Stat(dev1Dir); !os.IsNotExist(err) {
		t.Errorf("expected %s to be deleted by stop, err=%v", dev1Dir, err)
	}

	// 6. Startup failure inside execSession for --persist --remote-control or --persist --serve
	// must delete the failed sandbox instead of suspending it.
	if err := config.SaveFile(app.Env.ConfigFile, config.State{
		Agent:     "both",
		Image:     "node:24-bookworm-slim",
		Snapshot:  "agbox:v1",
		SnapCount: 1,
	}); err != nil {
		t.Fatal(err)
	}
	runner.handler = func(req msb.CommandRequest) (msb.CommandResult, error) {
		if len(req.Args) >= 1 && req.Args[0] == "ls" {
			return msb.CommandResult{Stdout: runner.sandboxes}, nil
		}
		if len(req.Args) >= 2 && req.Args[0] == "snap" && req.Args[1] == "ls" {
			return msb.CommandResult{Stdout: runner.snapshots}, nil
		}
		for _, a := range req.Args {
			if strings.Contains(a, "agy remote-control start") {
				return msb.CommandResult{ExitCode: 1, Stderr: "missing saved antigravity oauth token"}, errors.New("exit 1")
			}
		}
		return msb.CommandResult{}, nil
	}
	runner.calls = nil
	stderr.Reset()
	if rc := app.dispatch(ctx, []string{"run", "--no-auth", "--persist", "--name", "rcfail", "-d", "--remote-control", "antigravity", projA}); rc == 0 {
		t.Fatal("expected --persist -d --remote-control startup failure to fail")
	}
	rcFailDir := filepath.Join(app.Env.DataDir, "run", "rcfail")
	if _, err := os.Stat(rcFailDir); !os.IsNotExist(err) {
		t.Errorf("expected failed rc run dir %s to be deleted, err=%v", rcFailDir, err)
	}
	foundRCRM := false
	for _, c := range runner.calls {
		if slices.Equal(c.Args, []string{"stop", "agbox-rcfail"}) {
			t.Fatal("failed --persist -d --remote-control called msb stop instead of deleting resources")
		}
		if slices.Equal(c.Args, []string{"rm", "-f", "agbox-rcfail"}) {
			foundRCRM = true
		}
	}
	if !foundRCRM {
		t.Error("expected failed --persist -d --remote-control startup to delete agbox-rcfail with msb rm -f")
	}

	origWaitServe := app.WaitServeUI
	app.WaitServeUI = func(context.Context, int, string) bool { return false }
	runner.handler = nil
	runner.calls = nil
	stderr.Reset()
	if rc := app.dispatch(ctx, []string{"run", "--persist", "--name", "srvfail", "-d", "--serve", "opencode", projA}); rc == 0 {
		app.WaitServeUI = origWaitServe
		t.Fatal("expected --persist -d --serve readiness failure to fail")
	}
	app.WaitServeUI = origWaitServe
	srvFailDir := filepath.Join(app.Env.DataDir, "run", "srvfail")
	if _, err := os.Stat(srvFailDir); !os.IsNotExist(err) {
		t.Errorf("expected failed serve run dir %s to be deleted, err=%v", srvFailDir, err)
	}
	foundSrvRM := false
	for _, c := range runner.calls {
		if slices.Equal(c.Args, []string{"stop", "agbox-srvfail"}) {
			t.Fatal("failed --persist -d --serve called msb stop instead of deleting resources")
		}
		if slices.Equal(c.Args, []string{"rm", "-f", "agbox-srvfail"}) {
			foundSrvRM = true
		}
	}
	if !foundSrvRM {
		t.Error("expected failed --persist -d --serve startup to delete agbox-srvfail with msb rm -f")
	}

	// 7. Concurrent `agbox stop` writes a `deleting` marker so foreground `--persist` exit
	// skips suspendSandboxOnExit and duplicate `msb rm -f`.
	stopRaceDir := filepath.Join(app.Env.DataDir, "run", "stoprace")
	runner.handler = func(req msb.CommandRequest) (msb.CommandResult, error) {
		if len(req.Args) >= 1 && req.Args[0] == "ls" {
			return msb.CommandResult{Stdout: runner.sandboxes}, nil
		}
		if len(req.Args) >= 2 && req.Args[0] == "snap" && req.Args[1] == "ls" {
			return msb.CommandResult{Stdout: runner.snapshots}, nil
		}
		if len(req.Args) >= 1 && req.Args[0] == "exec" && strings.Contains(strings.Join(req.Args, " "), "exec sh -c") {
			if err := os.WriteFile(filepath.Join(stopRaceDir, "deleting"), []byte("agbox-stoprace\n"), 0o600); err != nil {
				return msb.CommandResult{}, err
			}
		}
		return msb.CommandResult{}, nil
	}
	runner.calls = nil
	stderr.Reset()
	if rc := app.dispatch(ctx, []string{"run", "--persist", "--name", "stoprace", "--cmd", "sleep 300", "opencode", projA}); rc != 0 {
		t.Fatalf("foreground --persist run during deleting race failed: %s", stderr.String())
	}
	if _, err := os.Stat(filepath.Join(stopRaceDir, "suspended")); !os.IsNotExist(err) {
		t.Errorf("expected foreground --persist run with deleting marker not to write suspended marker, err=%v", err)
	}
	for _, c := range runner.calls {
		if len(c.Args) >= 2 && c.Args[0] == "stop" && c.Args[len(c.Args)-1] == "agbox-stoprace" {
			t.Fatalf("foreground --persist run with deleting marker unexpectedly called msb stop: %v", c.Args)
		}
		if slices.Equal(c.Args, []string{"rm", "-f", "agbox-stoprace"}) {
			t.Fatalf("foreground --persist run with deleting marker unexpectedly called msb rm -f: %v", c.Args)
		}
	}
	runner.handler = nil
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
	if rc := app.dispatch(ctx, []string{"profile", "create", "--size", "12G", "workprof"}); rc != 0 {
		t.Fatalf("profile create failed: %s", stderr.String())
	}
	stdout.Reset()
	if rc := app.dispatch(ctx, []string{"profile", "list"}); rc != 0 || !strings.Contains(stdout.String(), "agbox-profile-workprof") {
		t.Fatalf("profile list = %d, out=%q", rc, stdout.String())
	}
	stdout.Reset()
	if rc := app.dispatch(ctx, []string{"status"}); rc != 0 || !strings.Contains(stdout.String(), "profiles: workprof") {
		t.Fatalf("status missing profile info: rc=%d, out=%q", rc, stdout.String())
	}

	// 2. Run with --profile mounts raw ext4 disk volume, bind-mounts conversation dirs, passes --conversation, and deletes ephemeral VM on exit.
	runner.calls = nil
	if rc := app.dispatch(ctx, []string{"run", "--name", "ephem1", "--profile", "workprof", "--conversation", "1c2a8c1e", "antigravity", proj}); rc != 0 {
		t.Fatalf("run --profile failed: %s", stderr.String())
	}
	wantDiskFlag := filepath.Join(app.Env.MSBHome, "volumes", "agbox-profile-workprof", "disk.raw") + ":" + msb.GuestProfileMount + ":rw,format=raw,fstype=ext4"
	foundDiskMount := false
	foundProfileBind := false
	foundConv := false
	stopIdx := -1
	rmIdx := -1
	for i, c := range runner.calls {
		joined := strings.Join(c.Args, " ")
		if strings.HasPrefix(joined, "snap restore ") && strings.Contains(joined, "--mount-disk "+wantDiskFlag) {
			foundDiskMount = true
		}
		if strings.Contains(joined, ".agbox-profile/agy-cli") {
			foundProfileBind = true
		}
		if strings.Contains(joined, "exec agy --conversation '1c2a8c1e'") {
			foundConv = true
		}
		if slices.Equal(c.Args, []string{"stop", "-t", "10", "agbox-ephem1"}) {
			stopIdx = i
		}
		if slices.Equal(c.Args, []string{"rm", "-f", "agbox-ephem1"}) {
			rmIdx = i
		}
	}
	if !foundDiskMount || !foundProfileBind || !foundConv || stopIdx < 0 || rmIdx <= stopIdx {
		t.Fatalf("profile run checks: disk=%v bind=%v conv=%v stopIdx=%d rmIdx=%d", foundDiskMount, foundProfileBind, foundConv, stopIdx, rmIdx)
	}

	// Verify `agbox stop` flushes a running profile sandbox before deleting it.
	stopRunDir := filepath.Join(app.Env.DataDir, "run", "ephem-stop")
	if err := config.SaveRunMeta(filepath.Join(stopRunDir, "run.meta"), config.RunMeta{
		Sandbox: "agbox-ephem-stop",
		Profile: "workprof",
	}); err != nil {
		t.Fatal(err)
	}
	runner.calls = nil
	if rc := app.dispatch(ctx, []string{"stop", "agbox-ephem-stop"}); rc != 0 {
		t.Fatalf("agbox stop profile sandbox failed: %s", stderr.String())
	}
	manualStopIdx := -1
	manualRMIdx := -1
	for i, c := range runner.calls {
		if slices.Equal(c.Args, []string{"stop", "-t", "10", "agbox-ephem-stop"}) {
			manualStopIdx = i
		}
		if slices.Equal(c.Args, []string{"rm", "-f", "agbox-ephem-stop"}) {
			manualRMIdx = i
		}
	}
	if manualStopIdx < 0 || manualRMIdx <= manualStopIdx {
		t.Fatalf("expected agbox stop on profile sandbox to run stop -t 10 before rm -f (stopIdx=%d rmIdx=%d)", manualStopIdx, manualRMIdx)
	}

	// Simulate check_32 concurrent deletion race: `agbox stop` writes `deleting`, stops the
	// profile sandbox, and tolerates `sandbox not found` if foreground cleanup already ran `msb rm -f`.
	raceRunDir := filepath.Join(app.Env.DataDir, "run", "ephem-race")
	if err := config.SaveRunMeta(filepath.Join(raceRunDir, "run.meta"), config.RunMeta{
		Sandbox: "agbox-ephem-race",
		Profile: "workprof",
	}); err != nil {
		t.Fatal(err)
	}
	prevRaceHandler := runner.handler
	sawDeletingBeforeStop := false
	runner.handler = func(req msb.CommandRequest) (msb.CommandResult, error) {
		if len(req.Args) >= 3 && req.Args[0] == "stop" && req.Args[len(req.Args)-1] == "agbox-ephem-race" {
			if _, sErr := os.Stat(filepath.Join(raceRunDir, "deleting")); sErr == nil {
				sawDeletingBeforeStop = true
			}
			return msb.CommandResult{}, nil
		}
		if slices.Equal(req.Args, []string{"rm", "-f", "agbox-ephem-race"}) {
			return msb.CommandResult{ExitCode: 1, Stderr: "error: sandbox not found: agbox-ephem-race\n"}, errors.New("exit status 1")
		}
		return prevRaceHandler(req)
	}
	runner.calls = nil
	stderr.Reset()
	if rc := app.dispatch(ctx, []string{"stop", "agbox-ephem-race"}); rc != 0 {
		t.Fatalf("agbox stop with concurrent rm -f race failed: %s", stderr.String())
	}
	if !sawDeletingBeforeStop {
		t.Error("expected agbox stop to write deleting marker before msb stop")
	}
	if _, err := os.Stat(raceRunDir); !os.IsNotExist(err) {
		t.Errorf("expected %s to be deleted after stop race, err=%v", raceRunDir, err)
	}

	// Stopping an unknown sandbox without a run directory must still surface `sandbox not found`.
	runner.handler = func(req msb.CommandRequest) (msb.CommandResult, error) {
		if slices.Equal(req.Args, []string{"rm", "-f", "agbox-nonexistent"}) {
			return msb.CommandResult{ExitCode: 1, Stderr: "error: sandbox not found: agbox-nonexistent\n"}, errors.New("exit status 1")
		}
		return prevRaceHandler(req)
	}
	stderr.Reset()
	if rc := app.dispatch(ctx, []string{"stop", "agbox-nonexistent"}); rc == 0 {
		t.Fatal("expected agbox stop on nonexistent sandbox to fail")
	}
	if _, err := os.Stat(filepath.Join(app.Env.DataDir, "run", "nonexistent")); !os.IsNotExist(err) {
		t.Errorf("expected agbox stop on nonexistent sandbox not to create run dir, err=%v", err)
	}
	runner.handler = prevRaceHandler

	// Verify `msb volume inspect` path overrides the MSB_HOME fallback when present.
	prevHandler := runner.handler
	runner.handler = func(req msb.CommandRequest) (msb.CommandResult, error) {
		if len(req.Args) >= 3 && req.Args[0] == "volume" && req.Args[1] == "inspect" {
			return msb.CommandResult{Stdout: "  Kind   disk\n  Path   /custom/msb/volumes/" + req.Args[2] + "/disk.raw\n"}, nil
		}
		return prevHandler(req)
	}
	runner.calls = nil
	if rc := app.dispatch(ctx, []string{"run", "--name", "ephem-insp", "--profile", "workprof", "antigravity", proj}); rc != 0 {
		t.Fatalf("run --profile with volume inspect failed: %s", stderr.String())
	}
	wantInspectedDisk := "--mount-disk /custom/msb/volumes/agbox-profile-workprof/disk.raw:" + msb.GuestProfileMount + ":rw,format=raw,fstype=ext4"
	foundInspectedDisk := false
	for _, c := range runner.calls {
		joined := strings.Join(c.Args, " ")
		if strings.HasPrefix(joined, "snap restore ") && strings.Contains(joined, wantInspectedDisk) {
			foundInspectedDisk = true
		}
	}
	if !foundInspectedDisk {
		t.Fatalf("expected snap restore to use inspected disk path %q", wantInspectedDisk)
	}
	runner.handler = prevHandler

	// 3. Concurrent host flock blocks overlapping --profile runs before restoring snapshot.
	heldLock, err := persist.LockProfile(app.Env.DataDir, "workprof")
	if err != nil {
		t.Fatal(err)
	}
	runner.calls = nil
	if rc := app.dispatch(ctx, []string{"run", "--profile", "workprof", "antigravity", proj}); rc == 0 {
		_ = heldLock.Unlock()
		t.Fatal("expected concurrent --profile run to fail while flock is held")
	}
	_ = heldLock.Unlock()
	for _, c := range runner.calls {
		if len(c.Args) >= 2 && c.Args[0] == "snap" && c.Args[1] == "restore" {
			t.Fatal("concurrent --profile run restored snapshot despite active flock")
		}
	}

	// 4. Suspended sandbox referencing workprof blocks `profile rm` unless you pass --force,
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
	stderr.Reset()
	if rc := app.dispatch(ctx, []string{"profile", "rm", "workprof"}); rc == 0 {
		t.Fatal("expected profile rm without --force to fail when suspended sandbox references profile")
	}
	if !strings.Contains(stderr.String(), `suspended sandbox agbox-psusp references profile "workprof"`) {
		t.Fatalf("expected profile rm error to report suspended sandbox reference, got: %s", stderr.String())
	}
	if rc := app.dispatch(ctx, []string{"profile", "rm", "--force", "workprof"}); rc != 0 {
		t.Fatalf("profile rm --force failed: %s", stderr.String())
	}
	if rc := app.dispatch(ctx, []string{"resume", "agbox-psusp"}); rc == 0 {
		t.Fatal("expected Resume to fail closed when profile disk volume was deleted")
	}

	// 5. `agbox remove --yes` deletes remaining agbox-profile-* volumes alongside sandboxes and DataDir.
	if rc := app.dispatch(ctx, []string{"profile", "create", "cleanupme"}); rc != 0 {
		t.Fatalf("profile create cleanupme failed: %s", stderr.String())
	}
	runner.calls = nil
	if rc := app.dispatch(ctx, []string{"remove", "--yes"}); rc != 0 {
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
		if rc := app.dispatch(ctx, cmd); rc == 0 {
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
		if rc := symApp.dispatch(ctx, cmd); rc == 0 {
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
		if rc := app.dispatch(ctx, []string{"resume", "agbox-tamp2"}); rc == 0 {
			t.Errorf("expected tampered Resume metadata %+v to fail closed", badMeta)
		}
	}
}

func TestParseRulesArgsAndNoRulesFlags(t *testing.T) {
	if _, err := parseRulesArgs([]string{"--help"}); !errors.Is(err, errHelp) {
		t.Fatalf("ParseRulesArgs(--help) = %v, want ErrHelp", err)
	}
	opts, err := parseRulesArgs(nil)
	if err != nil || opts.Action != "list" {
		t.Fatalf("ParseRulesArgs(nil) = %+v, %v", opts, err)
	}
	opts, err = parseRulesArgs([]string{"add", "--force", "--name", "eng-standards", "/tmp/rules.md"})
	if err != nil || opts.Action != "add" || !opts.Force || opts.Name != "eng-standards" || opts.Target != "/tmp/rules.md" {
		t.Fatalf("ParseRulesArgs(add) = %+v, %v", opts, err)
	}
	opts, err = parseRulesArgs([]string{"add", "--name=AGENTS.md", "/tmp/rules.md"})
	if err != nil || opts.Name != "AGENTS" {
		t.Fatalf("ParseRulesArgs(add --name=) = %+v, %v", opts, err)
	}
	opts, err = parseRulesArgs([]string{"show", "eng-standards"})
	if err != nil || opts.Action != "show" || opts.Target != "eng-standards" {
		t.Fatalf("ParseRulesArgs(show) = %+v, %v", opts, err)
	}
	opts, err = parseRulesArgs([]string{"rm", "--all"})
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
		if _, err := parseRulesArgs(bad); err == nil {
			t.Errorf("ParseRulesArgs(%v) succeeded, want error", bad)
		}
	}

	runOpts, err := parseRunArgs([]string{"--no-rules", "opencode"}, config.MaskStrict, func(string) bool { return false })
	if err != nil || !runOpts.NoRules {
		t.Fatalf("ParseRunArgs(--no-rules) = %+v, %v", runOpts, err)
	}
	resOpts, err := parseResumeArgs([]string{"--no-rules", "agbox-dev"})
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
	if rc := app.dispatch(ctx, []string{"rules"}); rc != 0 || !strings.Contains(stdout.String(), "No global rules") {
		t.Fatalf("rules empty = %d, %q", rc, stdout.String())
	}
	stdout.Reset()
	if rc := app.dispatch(ctx, []string{"status"}); rc != 0 || !strings.Contains(stdout.String(), "global_rules: none") {
		t.Fatalf("status empty global_rules = %d, %q", rc, stdout.String())
	}

	// 2. Add rule with custom name, verify duplicate guard, overwrite with --force, >24KB warning, and show/status output.
	tmpSrc := t.TempDir()
	stdFile := filepath.Join(tmpSrc, "standards.md")
	if err := os.WriteFile(stdFile, []byte("# Engineering Standards\nRun gofmt and tests.\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if rc := app.dispatch(ctx, []string{"rules", "add", "--name", "standards", stdFile}); rc != 0 {
		t.Fatalf("rules add standards failed: %s", stderr.String())
	}
	if rc := app.dispatch(ctx, []string{"rules", "add", "--name", "standards", stdFile}); rc == 0 {
		t.Fatal("expected duplicate rules add without --force to fail")
	}
	if rc := app.dispatch(ctx, []string{"rules", "add", "--force", "--name", "standards", stdFile}); rc != 0 {
		t.Fatalf("rules add --force failed: %s", stderr.String())
	}

	largeFile := filepath.Join(tmpSrc, "large-guide.md")
	largeBody := "# Large Guide\n" + strings.Repeat("Always validate inputs.\n", 1100) // > 24,000 bytes, < 64 KiB
	if err := os.WriteFile(largeFile, []byte(largeBody), 0o644); err != nil {
		t.Fatal(err)
	}
	stderr.Reset()
	if rc := app.dispatch(ctx, []string{"rules", "add", largeFile}); rc != 0 {
		t.Fatalf("rules add large-guide failed: %s", stderr.String())
	}
	if !strings.Contains(stderr.String(), "WARN:") || !strings.Contains(stderr.String(), "24000") {
		t.Errorf("expected >24KB Antigravity truncation warning on stderr, got %q", stderr.String())
	}

	stdout.Reset()
	if rc := app.dispatch(ctx, []string{"rules", "show", "standards"}); rc != 0 || !strings.Contains(stdout.String(), "Run gofmt and tests.") {
		t.Fatalf("rules show standards = %d, %q", rc, stdout.String())
	}
	stdout.Reset()
	if rc := app.dispatch(ctx, []string{"rules", "show"}); rc != 0 || !strings.Contains(stdout.String(), "== standards.md ==") || !strings.Contains(stdout.String(), "== large-guide.md ==") {
		t.Fatalf("rules show all = %d, %q", rc, stdout.String())
	}
	stdout.Reset()
	if rc := app.dispatch(ctx, []string{"status"}); rc != 0 || !strings.Contains(stdout.String(), "global_rules: large-guide, standards") {
		t.Fatalf("status global_rules = %d, %q", rc, stdout.String())
	}

	// 3. Persistent run mounts $DATA_DIR/rules read-only and stages/bind-mounts guest global rules.
	proj := filepath.Join(app.Env.HomeReal, "proj-rules")
	if err := os.MkdirAll(proj, 0o700); err != nil {
		t.Fatal(err)
	}
	wantRulesVol := filepath.Join(app.Env.DataDir, "rules") + ":" + msb.GuestRulesMount + ":ro,stat-virt=relaxed,uid=1000,gid=1000"

	runner.calls = nil
	if rc := app.dispatch(ctx, []string{"run", "--persist", "--name", "rulesvm", "antigravity", proj}); rc != 0 {
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
	if rc := app.dispatch(ctx, []string{"resume", "agbox-rulesvm"}); rc != 0 {
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
	if rc := app.dispatch(ctx, []string{"resume", "--no-rules", "agbox-rulesvm"}); rc != 0 {
		t.Fatalf("resume --no-rules agbox-rulesvm failed: %s", stderr.String())
	}
	for _, c := range runner.calls {
		if strings.Contains(strings.Join(c.Args, " "), "/etc/agbox-global-rules/AGENTS.md") {
			t.Fatal("expected `agbox resume --no-rules` to skip setupGuestRules")
		}
	}

	// 5. `--no-rules` on `agbox run` omits the global rules volume and skips setupGuestRules.
	runner.calls = nil
	if rc := app.dispatch(ctx, []string{"run", "--no-rules", "opencode", proj}); rc != 0 {
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
	if rc := app.dispatch(ctx, []string{"run", "opencode", proj}); rc == 0 {
		t.Fatal("expected Run to fail closed when $DATA_DIR/rules contains a symlink")
	}
	for _, c := range runner.calls {
		if len(c.Args) >= 2 && c.Args[0] == "snap" && c.Args[1] == "restore" {
			t.Fatal("Run restored snapshot despite symlink inside $DATA_DIR/rules")
		}
	}
	runner.calls = nil
	if rc := app.dispatch(ctx, []string{"resume", "agbox-rulesvm"}); rc == 0 {
		t.Fatal("expected Resume to fail closed when $DATA_DIR/rules contains a symlink")
	}
	for _, c := range runner.calls {
		if len(c.Args) >= 1 && c.Args[0] == "start" {
			t.Fatal("Resume started microVM despite symlink inside $DATA_DIR/rules")
		}
	}
	_ = os.Remove(badSym)

	// 7. Remove single rule and remove --all.
	if rc := app.dispatch(ctx, []string{"rules", "rm", "large-guide"}); rc != 0 {
		t.Fatalf("rules rm large-guide failed: %s", stderr.String())
	}
	if rc := app.dispatch(ctx, []string{"rules", "rm", "--all"}); rc != 0 {
		t.Fatalf("rules rm --all failed: %s", stderr.String())
	}
	stdout.Reset()
	if rc := app.dispatch(ctx, []string{"rules", "list"}); rc != 0 || !strings.Contains(stdout.String(), "No global rules") {
		t.Fatalf("rules list after rm --all = %d, %q", rc, stdout.String())
	}
}

func TestParseUpdateAndShareArgsAndRunConflicts(t *testing.T) {
	// 1. ParseUpdateArgs
	if u, err := parseUpdateArgs(nil); err != nil || u.Action != "update" || u.Target != "" {
		t.Fatalf("ParseUpdateArgs(nil) = %+v, %v", u, err)
	}
	for _, ag := range []string{"antigravity", "opencode", "both"} {
		if u, err := parseUpdateArgs([]string{"--allow-root", ag}); err != nil || u.Action != "update" || u.Target != ag || !u.AllowRoot {
			t.Fatalf("ParseUpdateArgs(%s) = %+v, %v", ag, u, err)
		}
	}
	if u, err := parseUpdateArgs([]string{"status"}); err != nil || u.Action != "status" {
		t.Fatalf("ParseUpdateArgs(status) = %+v, %v", u, err)
	}
	if u, err := parseUpdateArgs([]string{"clear"}); err != nil || u.Action != "clear" || u.Target != "all" {
		t.Fatalf("ParseUpdateArgs(clear) = %+v, %v", u, err)
	}
	if u, err := parseUpdateArgs([]string{"clear", "opencode"}); err != nil || u.Action != "clear" || u.Target != "opencode" {
		t.Fatalf("ParseUpdateArgs(clear opencode) = %+v, %v", u, err)
	}
	if _, err := parseUpdateArgs([]string{"--help"}); !errors.Is(err, errHelp) {
		t.Errorf("expected ErrHelp, got %v", err)
	}
	for _, bad := range [][]string{
		{"--unknown"},
		{"status", "extra"},
		{"clear", "bogus"},
		{"clear", "opencode", "extra"},
		{"antigravity", "extra"},
		{"bogus"},
	} {
		if _, err := parseUpdateArgs(bad); err == nil {
			t.Errorf("expected ParseUpdateArgs(%v) to fail", bad)
		}
	}

	// 2. ParseShareArgs
	if s, err := parseShareArgs([]string{"list", "agbox-dev"}); err != nil || s.Action != "list" || s.Sandbox != "agbox-dev" {
		t.Fatalf("ParseShareArgs(list) = %+v, %v", s, err)
	}
	if s, err := parseShareArgs([]string{"add", "agbox-dev", "./proj"}); err != nil || s.Action != "add" || s.HasAccess || s.HasVCS {
		t.Fatalf("ParseShareArgs(add default) = %+v, %v", s, err)
	}
	if s, err := parseShareArgs([]string{"add", "--rw", "--vcs", "--as", "api", "agbox-dev", "./proj"}); err != nil || !s.HasAccess || s.ReadOnly || !s.HasVCS || s.VCSPolicy != config.VCSAllow || s.Alias != "api" {
		t.Fatalf("ParseShareArgs(add --rw --vcs --as api) = %+v, %v", s, err)
	}
	if s, err := parseShareArgs([]string{"set", "--ro", "--force", "agbox-dev", "api"}); err != nil || s.Action != "set" || !s.ReadOnly || !s.Force {
		t.Fatalf("ParseShareArgs(set --ro --force) = %+v, %v", s, err)
	}
	if s, err := parseShareArgs([]string{"rm", "--force", "agbox-dev", "api"}); err != nil || s.Action != "rm" || !s.Force {
		t.Fatalf("ParseShareArgs(rm --force) = %+v, %v", s, err)
	}
	if _, err := parseShareArgs([]string{"--help"}); !errors.Is(err, errHelp) {
		t.Errorf("expected ErrHelp, got %v", err)
	}
	for _, bad := range [][]string{
		{},
		{"list"},
		{"list", "--rw", "agbox-dev"},
		{"add", "--ro", "--rw", "agbox-dev", "./p"},
		{"add", "--vcs", "--mask-vcs", "agbox-dev", "./p"},
		{"add", "--vcs", "--vcs-hooks", "agbox-dev", "./p"},
		{"add", "--ro", "--vcs-hooks", "agbox-dev", "./p"},
		{"add", "--force", "agbox-dev", "./p"},
		{"add", "--as", ".git", "agbox-dev", "./p"},
		{"set", "agbox-dev", "proj"},
		{"set", "--ro", "--rw", "agbox-dev", "proj"},
		{"set", "--ro", "--vcs-hooks", "agbox-dev", "proj"},
		{"set", "--as", "x", "--ro", "agbox-dev", "proj"},
		{"rm", "--rw", "agbox-dev", "proj"},
		{"list", "agbox-base"},
		{"list", "not-agbox"},
	} {
		if _, err := parseShareArgs(bad); err == nil {
			t.Errorf("expected ParseShareArgs(%v) to fail on invalid or conflicting options", bad)
		}
	}

	// 3. ParseRunArgs per-share syntax and conflicting option errors
	rOpts, err := parseRunArgs([]string{
		"--share-hub",
		"--no-agent-cache",
		"--share", "./docs:ro",
		"--share=./repo:rw,vcs,as=backend",
		"antigravity",
		"./app:rw,vcs-hooks",
	}, config.MaskStrict, func(string) bool { return false })
	if err != nil {
		t.Fatalf("ParseRunArgs valid shares failed: %v", err)
	}
	if !rOpts.ShareHub || !rOpts.NoAgentCache || len(rOpts.ShareSpecs) != 2 || len(rOpts.Paths) != 1 {
		t.Fatalf("unexpected RunOpts: %+v", rOpts)
	}

	for _, badRun := range [][]string{
		{"--ro", "--rw", "./proj"},
		{"--mask-vcs", "--no-mask", "./proj"},
		{"--mask-vcs", "--vcs", "./proj"},
		{"--vcs", "--vcs-hooks", "./proj"},
		{"--no-mask", "--vcs", "./proj"},
		{"--no-mask", "--share-hub"},
		{"--no-mask", "./proj:vcs"},
		{"--ro", "--vcs-hooks", "./proj"},
		{"--ro", "./proj:rw"},
		{"--rw", "./proj:ro"},
		{"--ro", "--share", "./proj:rw"},
		{"--vcs", "./proj:mask"},
		{"--mask-vcs", "./proj:vcs"},
		{"--ro", "./proj:vcs-hooks"},
		{"--vcs-hooks", "./proj:ro"},
		{"./proj:ro,rw"},
		{"./proj:ro,vcs-hooks"},
		{"./proj:vcs,mask"},
	} {
		if _, err := parseRunArgs(badRun, config.MaskStrict, func(string) bool { return false }); err == nil {
			t.Errorf("expected ParseRunArgs(%v) to fail on conflicting options", badRun)
		}
	}
}

func TestUpdateModeCacheAndRunIntegration(t *testing.T) {
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

	// 1. Empty status check.
	stdout.Reset()
	if rc := app.dispatch(ctx, []string{"update", "status"}); rc != 0 || !strings.Contains(stdout.String(), "No cached agent updates") {
		t.Fatalf("update status empty = %d, %q", rc, stdout.String())
	}
	stdout.Reset()
	if rc := app.dispatch(ctx, []string{"status"}); rc != 0 || !strings.Contains(stdout.String(), "cached_agents: none") {
		t.Fatalf("status cached_agents empty = %d, %q", rc, stdout.String())
	}

	// 2. Non-ELF stream fails closed without writing manifest or binary.
	runner.handler = func(req msb.CommandRequest) (msb.CommandResult, error) {
		if len(req.Args) >= 1 && req.Args[0] == "ls" {
			return msb.CommandResult{Stdout: runner.sandboxes}, nil
		}
		if len(req.Args) >= 2 && req.Args[0] == "snap" && req.Args[1] == "ls" {
			return msb.CommandResult{Stdout: runner.snapshots}, nil
		}
		joined := strings.Join(req.Args, " ")
		if strings.Contains(joined, "agbox-agy-version.txt") {
			return msb.CommandResult{Stdout: "2.5.0\n"}, nil
		}
		if strings.Contains(joined, "cat /home/agent/.local/bin/agy") {
			return msb.CommandResult{Stdout: strings.Repeat("NOT-AN-ELF-BINARY!", 8)}, nil
		}
		return msb.CommandResult{}, nil
	}
	if rc := app.dispatch(ctx, []string{"update", "antigravity"}); rc == 0 {
		t.Fatal("expected update with non-ELF stream to fail closed")
	}
	if cached, err := persist.InspectAgentsDir(filepath.Join(app.Env.DataDir, "agents")); err != nil || len(cached) != 0 {
		t.Fatalf("expected empty clean agents dir after failed update, got %+v, %v", cached, err)
	}

	// 3. Valid `agbox update both` runs inside a zero-share, zero-secret disposable VM and caches both ELF binaries.
	fakeAgyELF := append([]byte{0x7f, 'E', 'L', 'F'}, bytes.Repeat([]byte("A"), 128)...)
	fakeOpenCodeELF := append([]byte{0x7f, 'E', 'L', 'F'}, bytes.Repeat([]byte("O"), 140)...)
	runner.handler = func(req msb.CommandRequest) (msb.CommandResult, error) {
		if len(req.Args) >= 1 && req.Args[0] == "ls" {
			return msb.CommandResult{Stdout: runner.sandboxes}, nil
		}
		if len(req.Args) >= 2 && req.Args[0] == "snap" && req.Args[1] == "ls" {
			return msb.CommandResult{Stdout: runner.snapshots}, nil
		}
		joined := strings.Join(req.Args, " ")
		if strings.Contains(joined, "cat /tmp/agbox-agy-version.txt") {
			return msb.CommandResult{Stdout: "agy 2.5.1\n"}, nil
		}
		if strings.Contains(joined, "cat /tmp/agbox-opencode-version.txt") {
			return msb.CommandResult{Stdout: "1.4.9\n"}, nil
		}
		if strings.Contains(joined, "cat /home/agent/.local/bin/agy") && req.Stdout != nil {
			_, _ = req.Stdout.Write(fakeAgyELF)
			return msb.CommandResult{}, nil
		}
		if strings.Contains(joined, "agbox-opencode-binpath.txt") && req.Stdout != nil {
			_, _ = req.Stdout.Write(fakeOpenCodeELF)
			return msb.CommandResult{}, nil
		}
		return msb.CommandResult{}, nil
	}
	runner.calls = nil
	stderr.Reset()
	if rc := app.dispatch(ctx, []string{"update", "both"}); rc != 0 {
		t.Fatalf("update both failed: %s", stderr.String())
	}

	foundDisposableRestore := false
	foundDisposableRM := false
	for _, c := range runner.calls {
		if c.Stdin != "" {
			t.Fatalf("disposable update VM unexpectedly streamed host secrets over stdin: %q", c.Stdin)
		}
		joined := strings.Join(c.Args, " ")
		if strings.HasPrefix(joined, "snap restore ") && strings.Contains(joined, "--name agbox-update-4242") {
			foundDisposableRestore = true
			if slices.Contains(c.Args, "-v") {
				t.Fatalf("disposable update VM must mount zero host volumes, got %v", c.Args)
			}
			if !strings.Contains(joined, "--net-default deny") {
				t.Fatalf("disposable update VM must enforce default-deny egress, got %q", joined)
			}
		}
		if slices.Equal(c.Args, []string{"rm", "-f", "agbox-update-4242"}) {
			foundDisposableRM = true
		}
	}
	if !foundDisposableRestore || !foundDisposableRM {
		t.Fatalf("update VM lifecycle checks: restore=%v rm=%v", foundDisposableRestore, foundDisposableRM)
	}
	runner.handler = nil

	stdout.Reset()
	if rc := app.dispatch(ctx, []string{"update", "status"}); rc != 0 || !strings.Contains(stdout.String(), "antigravity: version=agy 2.5.1") || !strings.Contains(stdout.String(), "opencode: version=1.4.9") {
		t.Fatalf("update status = %d, %q", rc, stdout.String())
	}
	stdout.Reset()
	if rc := app.dispatch(ctx, []string{"status"}); rc != 0 || !strings.Contains(stdout.String(), "cached_agents: antigravity (agy 2.5.1), opencode (1.4.9)") {
		t.Fatalf("status cached_agents = %d, %q", rc, stdout.String())
	}

	// 4. Subsequent `agbox run` mounts $DATA_DIR/agents read-only and bind-mounts binaries. `--no-agent-cache` skips it.
	proj := filepath.Join(app.Env.HomeReal, "proj-upd")
	if err := os.MkdirAll(proj, 0o700); err != nil {
		t.Fatal(err)
	}
	wantAgentsVol := filepath.Join(app.Env.DataDir, "agents") + ":" + msb.GuestAgentsMount + ":ro,stat-virt=relaxed,uid=1000,gid=1000"

	runner.calls = nil
	if rc := app.dispatch(ctx, []string{"run", "--cmd", "agy --version", "antigravity", proj}); rc != 0 {
		t.Fatalf("run with cached agents failed: %s", stderr.String())
	}
	foundAgentsVol := false
	foundAgentsBind := false
	for _, c := range runner.calls {
		joined := strings.Join(c.Args, " ")
		if strings.HasPrefix(joined, "snap restore ") && slices.Contains(c.Args, wantAgentsVol) {
			foundAgentsVol = true
		}
		if strings.Contains(joined, "/home/agent/.local/bin/agy") && strings.Contains(joined, "remount,ro,bind") {
			foundAgentsBind = true
		}
	}
	if !foundAgentsVol || !foundAgentsBind {
		t.Fatalf("cached agents mount checks: vol=%v bind=%v", foundAgentsVol, foundAgentsBind)
	}

	runner.calls = nil
	if rc := app.dispatch(ctx, []string{"run", "--no-agent-cache", "--cmd", "agy --version", "antigravity", proj}); rc != 0 {
		t.Fatalf("run --no-agent-cache failed: %s", stderr.String())
	}
	for _, c := range runner.calls {
		if slices.Contains(c.Args, wantAgentsVol) {
			t.Fatalf("--no-agent-cache unexpectedly mounted agents volume: %v", c.Args)
		}
	}

	// 5. Symlink planted in $DATA_DIR/agents fails closed before snap restore.
	plantedSym := filepath.Join(app.Env.DataDir, "agents", "evil")
	if err := os.Symlink("/etc/passwd", plantedSym); err != nil {
		t.Fatal(err)
	}
	runner.calls = nil
	if rc := app.dispatch(ctx, []string{"run", "--cmd", "id", "antigravity", proj}); rc == 0 {
		t.Fatal("expected Run to fail closed when $DATA_DIR/agents contains a symlink")
	}
	for _, c := range runner.calls {
		if len(c.Args) >= 2 && c.Args[0] == "snap" && c.Args[1] == "restore" {
			t.Fatal("Run restored snapshot despite symlink in $DATA_DIR/agents")
		}
	}
	_ = os.Remove(plantedSym)

	// 6. Clear single agent and clear all.
	if rc := app.dispatch(ctx, []string{"update", "clear", "opencode"}); rc != 0 {
		t.Fatalf("update clear opencode failed: %s", stderr.String())
	}
	if rc := app.dispatch(ctx, []string{"update", "clear"}); rc != 0 {
		t.Fatalf("update clear all failed: %s", stderr.String())
	}
	stdout.Reset()
	if rc := app.dispatch(ctx, []string{"update", "status"}); rc != 0 || !strings.Contains(stdout.String(), "No cached agent updates") {
		t.Fatalf("update status after clear = %d, %q", rc, stdout.String())
	}
}

func TestShareLiveAndSuspended(t *testing.T) {
	shortHome, err := os.MkdirTemp("", "agb-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(shortHome) })
	shortHome, err = filepath.EvalSymlinks(shortHome)
	if err != nil {
		t.Fatal(err)
	}

	app, runner, stdout, stderr := newTestApp(t)
	app.Env.HomeReal = shortHome
	app.Env.DataDir = filepath.Join(shortHome, "d")
	app.Env.ConfigFile = filepath.Join(app.Env.DataDir, "config")
	app.Env.MSBHome = filepath.Join(shortHome, "m")
	if err := os.MkdirAll(app.Env.DataDir, 0o700); err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	if err := config.SaveFile(app.Env.ConfigFile, config.State{
		Agent:     "both",
		Image:     "node:24-bookworm-slim",
		Snapshot:  "agbox:v1",
		SnapCount: 1,
	}); err != nil {
		t.Fatal(err)
	}

	projA := filepath.Join(shortHome, "projA")
	docsDir := filepath.Join(shortHome, "docs")
	repoDir := filepath.Join(shortHome, "repo")
	hotDir := filepath.Join(shortHome, "hot")
	for _, p := range []string{projA, docsDir, repoDir, hotDir} {
		if err := os.MkdirAll(p, 0o700); err != nil {
			t.Fatal(err)
		}
	}

	var activeHub *vcsfuse.WorkspaceHub
	var activeLn net.Listener
	t.Cleanup(func() {
		if activeLn != nil {
			_ = activeLn.Close()
		}
		if activeHub != nil {
			activeHub.CloseAll()
		}
	})

	app.StartHub = func(mntDir, sockPath, pidFile string, initial []vcsfuse.HubShareConfig, _ bool) (int, error) {
		if activeLn != nil {
			_ = activeLn.Close()
			activeLn = nil
		}
		if activeHub != nil {
			activeHub.CloseAll()
			activeHub = nil
		}
		if err := os.MkdirAll(mntDir, 0o700); err != nil {
			return 0, err
		}
		h, err := vcsfuse.NewWorkspaceHubWithOptions(initial, vcsfuse.HubOptions{
			HomeReal:         app.Env.HomeReal,
			DataDir:          app.Env.DataDir,
			MSBHome:          app.Env.MSBHome,
			AllowOutsideHome: app.Env.AllowOutsideHome,
			MapGuestIDs:      true,
			GuestUID:         config.GuestUID,
			GuestGID:         config.GuestGID,
		})
		if err != nil {
			return 0, err
		}
		ln, err := vcsfuse.ServeControlSocket(sockPath, h)
		if err != nil {
			h.CloseAll()
			return 0, err
		}
		activeHub = h
		activeLn = ln
		if err := os.WriteFile(pidFile, []byte("9998\n"), 0o600); err != nil {
			return 0, err
		}
		return 9998, nil
	}

	// 1. Start a detached running sandbox with mixed per-share permissions.
	if rc := app.dispatch(ctx, []string{
		"run", "--name", "s1", "-d", "--remote-control",
		"--share", docsDir + ":ro",
		projA + ":rw",
		repoDir + ":rw,vcs,as=gitrepo",
	}); rc != 0 {
		t.Fatalf("run detached mixed shares failed: %s", stderr.String())
	}
	runner.sandboxes = "NAME STATE\nagbox-base stopped\nagbox-s1 running\n"

	// 2. `agbox share list` queries the live control socket and reports per-share permissions.
	stdout.Reset()
	if rc := app.dispatch(ctx, []string{"share", "list", "agbox-s1"}); rc != 0 {
		t.Fatalf("share list failed: %s", stderr.String())
	}
	listOut := stdout.String()
	for _, want := range []string{
		"/workspace/docs\tmode=ro\tvcs=mask",
		"/workspace/projA\tmode=rw\tvcs=mask",
		"/workspace/gitrepo\tmode=rw\tvcs=vcs",
	} {
		if !strings.Contains(listOut, want) {
			t.Errorf("share list output %q missing %q", listOut, want)
		}
	}

	// 3. `agbox share add` defaults to ro,mask (most restrictive) on a running VM and drops guest caches.
	stderr.Reset()
	if rc := app.dispatch(ctx, []string{"share", "add", "agbox-s1", hotDir}); rc != 0 {
		t.Fatalf("share add default failed: %s", stderr.String())
	}
	stdout.Reset()
	if rc := app.dispatch(ctx, []string{"share", "list", "agbox-s1"}); rc != 0 || !strings.Contains(stdout.String(), "/workspace/hot\tmode=ro\tvcs=mask") {
		t.Fatalf("expected hot-added share to default to mode=ro vcs=mask, got %q", stdout.String())
	}

	// Overlapping or duplicate share path must fail closed.
	if rc := app.dispatch(ctx, []string{"share", "add", "agbox-s1", hotDir}); rc == 0 {
		t.Fatal("expected duplicate share add to fail closed")
	}

	// 4. `agbox share set` updates hot -> rw,vcs and then downgrades -> ro,mask. `agbox share rm` detaches it.
	if rc := app.dispatch(ctx, []string{"share", "set", "--rw", "--vcs", "agbox-s1", "hot"}); rc != 0 {
		t.Fatalf("share set --rw --vcs failed: %s", stderr.String())
	}
	stdout.Reset()
	if rc := app.dispatch(ctx, []string{"share", "list", "agbox-s1"}); rc != 0 || !strings.Contains(stdout.String(), "/workspace/hot\tmode=rw\tvcs=vcs") {
		t.Fatalf("expected mode=rw vcs=vcs after set, got %q", stdout.String())
	}
	// Downgrading to --ro while vcs=vcs-hooks is active must fail as conflicting.
	if rc := app.dispatch(ctx, []string{"share", "set", "--vcs-hooks", "agbox-s1", "hot"}); rc != 0 {
		t.Fatalf("share set --vcs-hooks failed: %s", stderr.String())
	}
	if rc := app.dispatch(ctx, []string{"share", "set", "--ro", "agbox-s1", "hot"}); rc == 0 {
		t.Fatal("expected set --ro on a vcs-hooks share without --mask-vcs/--vcs to fail closed")
	}
	if rc := app.dispatch(ctx, []string{"share", "set", "--ro", "--mask-vcs", "agbox-s1", "hot"}); rc != 0 {
		t.Fatalf("share set --ro --mask-vcs failed: %s", stderr.String())
	}
	if rc := app.dispatch(ctx, []string{"share", "rm", "agbox-s1", "hot"}); rc != 0 {
		t.Fatalf("share rm hot failed: %s", stderr.String())
	}

	// 5. Suspend agbox-s1, modify shares while suspended (add hot as rw, remove docs), and resume.
	if activeLn != nil {
		_ = activeLn.Close()
		activeLn = nil
	}
	if rc := app.dispatch(ctx, []string{"suspend", "agbox-s1"}); rc != 0 {
		t.Fatalf("suspend agbox-s1 failed: %s", stderr.String())
	}
	runner.sandboxes = "NAME STATE\nagbox-base stopped\nagbox-s1 stopped\n"

	if rc := app.dispatch(ctx, []string{"share", "add", "--rw", "agbox-s1", hotDir}); rc != 0 {
		t.Fatalf("suspended share add failed: %s", stderr.String())
	}
	if rc := app.dispatch(ctx, []string{"share", "rm", "agbox-s1", "docs"}); rc != 0 {
		t.Fatalf("suspended share rm failed: %s", stderr.String())
	}
	if rc := app.dispatch(ctx, []string{"resume", "-d", "agbox-s1"}); rc != 0 {
		t.Fatalf("resume agbox-s1 after suspended share edits failed: %s", stderr.String())
	}
	runner.sandboxes = "NAME STATE\nagbox-base stopped\nagbox-s1 running\n"
	stdout.Reset()
	if rc := app.dispatch(ctx, []string{"share", "list", "agbox-s1"}); rc != 0 {
		t.Fatalf("share list after resume failed: %s", stderr.String())
	}
	afterResume := stdout.String()
	if strings.Contains(afterResume, "/workspace/docs\t") || !strings.Contains(afterResume, "/workspace/hot\tmode=rw\tvcs=mask") {
		t.Fatalf("unexpected shares after resume: %q", afterResume)
	}

	// 6. Suspended sandbox with WorkspaceHub == false resumes cleanly via StartFilter (m0.pid).
	filterRunDir := filepath.Join(app.Env.DataDir, "run", "perfilter1")
	filterMeta := config.RunMeta{
		Sandbox:      "agbox-perfilter1",
		Agent:        "opencode",
		Mode:         config.RunModeCmd,
		Cmd:          "true",
		MaskMode:     config.MaskStrict,
		WorkspaceHub: false,
		Shares: []config.ShareRecord{
			{Index: 0, HostPath: projA, GuestName: "projA", IsDir: true, Masked: true},
		},
	}
	if err := config.SaveRunMeta(filepath.Join(filterRunDir, "suspended"), filterMeta); err != nil {
		t.Fatal(err)
	}
	runner.sandboxes = "NAME STATE\nagbox-base stopped\nagbox-perfilter1 stopped\n"
	usedShareFilter := false
	app.StartFilter = func(_, mntDir, pidFile string, _ bool) (int, error) {
		usedShareFilter = true
		_ = os.MkdirAll(mntDir, 0o700)
		_ = os.WriteFile(pidFile, []byte("7777\n"), 0o600)
		return 7777, nil
	}
	if rc := app.dispatch(ctx, []string{"resume", "agbox-perfilter1"}); rc != 0 {
		t.Fatalf("WorkspaceHub=false resume failed: %s", stderr.String())
	}
	if !usedShareFilter {
		t.Fatal("expected WorkspaceHub=false sandbox to resume using StartFilter")
	}
}

func TestPersistRemoteControlWithAuthSkillsRulesAndErrorReporting(t *testing.T) {
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

	// 1. Seed saved antigravity auth, one global skill, and one global rule.
	if err := persist.SaveAuthBundle(app.Env.DataDir, persist.AuthBundle{
		Files: []persist.AuthFile{
			{
				Agent: "antigravity",
				Name:  "antigravity-oauth-token",
				Data:  []byte("oauth-token-blip-test"),
			},
		},
	}); err != nil {
		t.Fatalf("SaveAuthBundle: %v", err)
	}

	skillSrc := filepath.Join(t.TempDir(), "blip-skill")
	if err := os.MkdirAll(skillSrc, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(skillSrc, "SKILL.md"), []byte("---\nname: blip-skill\ndescription: Test skill.\n---\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if rc := app.dispatch(ctx, []string{"skills", "add", skillSrc}); rc != 0 {
		t.Fatalf("skills add failed: %s", stderr.String())
	}

	ruleSrc := filepath.Join(t.TempDir(), "blip-rule.md")
	if err := os.WriteFile(ruleSrc, []byte("# Blip Rule\nAlways run tests.\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if rc := app.dispatch(ctx, []string{"rules", "add", ruleSrc}); rc != 0 {
		t.Fatalf("rules add failed: %s", stderr.String())
	}

	repoDir := filepath.Join(app.Env.HomeReal, "agbox")
	if err := os.MkdirAll(repoDir, 0o700); err != nil {
		t.Fatal(err)
	}

	// 2. Run the persistent detached remote-control command with auth, skill, and rule present.
	runner.calls = nil
	stdout.Reset()
	stderr.Reset()
	if rc := app.dispatch(ctx, []string{"run", "--persist", "--name", "blip", "-d", "--remote-control", repoDir}); rc != 0 {
		t.Fatalf("run --persist --name blip -d --remote-control failed (rc=%d): %s", rc, stderr.String())
	}

	detachedPath := filepath.Join(app.Env.DataDir, "run", "blip", "detached")
	if _, err := os.Stat(detachedPath); err != nil {
		t.Fatalf("expected detached marker at %s: %v", detachedPath, err)
	}

	foundRootSkills := false
	foundRootRules := false
	foundAgentAuth := false
	foundRCStart := false
	for _, c := range runner.calls {
		if slices.Equal(c.Args, []string{"rm", "-f", "agbox-blip"}) {
			t.Fatal("successful --persist detached run deleted agbox-blip")
		}
		sbx, explicitUser, cmdStr := parseFakeExecCall(c.Args)
		if len(c.Args) >= 1 && c.Args[0] == "exec" && sbx == "agbox-blip" {
			if strings.Contains(cmdStr, "/home/agent/.gemini/config/skills") {
				if explicitUser != "root" {
					t.Fatalf("setupGuestSkills must pass -u root, got args %v", c.Args)
				}
				foundRootSkills = true
			}
			if strings.Contains(cmdStr, "/etc/agbox-global-rules") {
				if explicitUser != "root" {
					t.Fatalf("setupGuestRules must pass -u root, got args %v", c.Args)
				}
				foundRootRules = true
			}
			if strings.Contains(c.Stdin, "oauth-token-blip-test") || strings.Contains(c.Stdin, "antigravity-oauth-token") {
				if explicitUser != config.GuestUser {
					t.Fatalf("pushAuth must pass -u %s, got args %v", config.GuestUser, c.Args)
				}
				foundAgentAuth = true
			}
			if strings.Contains(cmdStr, "agy remote-control start --name 'agbox-blip'") {
				if explicitUser != config.GuestUser {
					t.Fatalf("remote-control start must pass -u %s, got args %v", config.GuestUser, c.Args)
				}
				if !slices.Contains(c.Args, "--stream") || !slices.Contains(c.Args, "--no-stdin") {
					t.Fatalf("remote-control start must pass --stream and --no-stdin, got args %v", c.Args)
				}
				foundRCStart = true
			}
		}
	}
	if !foundRootSkills || !foundRootRules || !foundAgentAuth || !foundRCStart {
		t.Fatalf("run checks failed: skills=%v rules=%v auth=%v rcStart=%v",
			foundRootSkills, foundRootRules, foundAgentAuth, foundRCStart)
	}

	// 3. Suspend and resume agbox-blip and verify root exec flags repeat cleanly on resume.
	runner.sandboxes = "NAME STATE\nagbox-base stopped\nagbox-blip running\n"
	if rc := app.dispatch(ctx, []string{"suspend", "agbox-blip"}); rc != 0 {
		t.Fatalf("suspend agbox-blip failed: %s", stderr.String())
	}
	runner.sandboxes = "NAME STATE\nagbox-base stopped\nagbox-blip stopped\n"
	runner.calls = nil
	if rc := app.dispatch(ctx, []string{"resume", "agbox-blip"}); rc != 0 {
		t.Fatalf("resume agbox-blip failed: %s", stderr.String())
	}
	resumedSkills := false
	resumedRules := false
	for _, c := range runner.calls {
		sbx, explicitUser, cmdStr := parseFakeExecCall(c.Args)
		if len(c.Args) >= 1 && c.Args[0] == "exec" && sbx == "agbox-blip" {
			if strings.Contains(cmdStr, "/home/agent/.gemini/config/skills") && explicitUser == "root" {
				resumedSkills = true
			}
			if strings.Contains(cmdStr, "/etc/agbox-global-rules") && explicitUser == "root" {
				resumedRules = true
			}
		}
	}
	if !resumedSkills || !resumedRules {
		t.Fatalf("resume missing -u root skills (%v) or rules (%v)", resumedSkills, resumedRules)
	}
	if rc := app.dispatch(ctx, []string{"stop", "agbox-blip"}); rc != 0 {
		t.Fatalf("stop agbox-blip failed: %s", stderr.String())
	}
	runner.sandboxes = "NAME STATE\nagbox-base stopped\n"

	// 4. Real *exec.ExitError on snap restore and guest setup prints [agbox] ERROR and captured stderr.
	exit7Err := exec.Command("sh", "-c", "exit 7").Run()
	if exit7Err == nil {
		t.Fatal("expected sh exit 7 to produce an error")
	}

	runner.handler = func(req msb.CommandRequest) (msb.CommandResult, error) {
		if len(req.Args) >= 1 && req.Args[0] == "ls" {
			return msb.CommandResult{Stdout: runner.sandboxes}, nil
		}
		if len(req.Args) >= 2 && req.Args[0] == "snap" && req.Args[1] == "ls" {
			return msb.CommandResult{Stdout: runner.snapshots}, nil
		}
		if len(req.Args) >= 2 && req.Args[0] == "snap" && req.Args[1] == "restore" {
			return msb.CommandResult{
				Stderr:   "restore volume missing\n",
				ExitCode: 7,
			}, exit7Err
		}
		return msb.CommandResult{}, nil
	}
	runner.calls = nil
	stderr.Reset()
	if rc := app.dispatch(ctx, []string{"run", "--persist", "--name", "failrestore", "-d", "--remote-control", repoDir}); rc != 7 {
		t.Fatalf("expected rc=7 on snap restore ExitError, got rc=%d, stderr=%q", rc, stderr.String())
	}
	if !strings.Contains(stderr.String(), "[agbox] ERROR:") || !strings.Contains(stderr.String(), "restore volume missing") {
		t.Fatalf("expected snap restore error and msb stderr in output, got %q", stderr.String())
	}
	foundRM := false
	for _, c := range runner.calls {
		if slices.Equal(c.Args, []string{"rm", "-f", "agbox-failrestore"}) {
			foundRM = true
		}
	}
	if !foundRM {
		t.Error("expected partial agbox-failrestore VM to be deleted after snap restore failure")
	}

	runner.handler = func(req msb.CommandRequest) (msb.CommandResult, error) {
		if len(req.Args) >= 1 && req.Args[0] == "ls" {
			return msb.CommandResult{Stdout: runner.sandboxes}, nil
		}
		if len(req.Args) >= 2 && req.Args[0] == "snap" && req.Args[1] == "ls" {
			return msb.CommandResult{Stdout: runner.snapshots}, nil
		}
		if len(req.Args) >= 1 && req.Args[0] == "exec" && strings.Contains(strings.Join(req.Args, " "), "/home/agent/.gemini/config/skills") {
			return msb.CommandResult{
				Stderr:   "mount permission denied\n",
				ExitCode: 7,
			}, exit7Err
		}
		return msb.CommandResult{}, nil
	}
	runner.calls = nil
	stderr.Reset()
	if rc := app.dispatch(ctx, []string{"run", "--persist", "--name", "failskills", "-d", "--remote-control", repoDir}); rc != 7 {
		t.Fatalf("expected rc=7 on setupGuestSkills ExitError, got rc=%d, stderr=%q", rc, stderr.String())
	}
	if !strings.Contains(stderr.String(), "[agbox] ERROR:") || !strings.Contains(stderr.String(), "mount permission denied") {
		t.Fatalf("expected setupGuestSkills error and msb stderr in output, got %q", stderr.String())
	}
	foundRM = false
	for _, c := range runner.calls {
		if slices.Equal(c.Args, []string{"rm", "-f", "agbox-failskills"}) {
			foundRM = true
		}
	}
	if !foundRM {
		t.Error("expected partial agbox-failskills VM to be deleted after setupGuestSkills failure")
	}

	// 5. Real *exec.ExitError on interactive --cmd session exits cleanly without extra [agbox] ERROR line.
	exit23Err := exec.Command("sh", "-c", "exit 23").Run()
	if exit23Err == nil {
		t.Fatal("expected sh exit 23 to produce an error")
	}
	runner.handler = func(req msb.CommandRequest) (msb.CommandResult, error) {
		if len(req.Args) >= 1 && req.Args[0] == "ls" {
			return msb.CommandResult{Stdout: runner.sandboxes}, nil
		}
		if len(req.Args) >= 2 && req.Args[0] == "snap" && req.Args[1] == "ls" {
			return msb.CommandResult{Stdout: runner.snapshots}, nil
		}
		if len(req.Args) >= 1 && req.Args[0] == "exec" && req.Interactive {
			return msb.CommandResult{ExitCode: 23}, exit23Err
		}
		return msb.CommandResult{}, nil
	}
	stderr.Reset()
	if rc := app.dispatch(ctx, []string{"run", "--cmd", "false", repoDir}); rc != 23 {
		t.Fatalf("expected --cmd ExitError passthrough rc=23, got rc=%d, stderr=%q", rc, stderr.String())
	}
	if strings.Contains(stderr.String(), "[agbox] ERROR:") {
		t.Fatalf("did not expect [agbox] ERROR wrapper on interactive --cmd exit, got %q", stderr.String())
	}
	runner.handler = nil
}

func TestRunCmdStreamsOutputAndHandlesStdinModes(t *testing.T) {
	ctx := context.Background()

	// 1. isFileTerminal rejects /dev/null and pipes.
	devNull, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer devNull.Close()
	if isFileTerminal(devNull) {
		t.Fatal("expected /dev/null NOT to be detected as a terminal")
	}
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer pr.Close()
	defer pw.Close()
	if isFileTerminal(pr) || isFileTerminal(pw) {
		t.Fatal("expected pipe ends NOT to be detected as terminals")
	}

	// 2. Real msb.ExecRunner backed by a script simulating upstream msb exec behavior:
	// rejects --stream when --no-stdin is missing and no piped data was supplied.
	app, _, stdout, stderr := newTestApp(t)
	if err := config.SaveFile(app.Env.ConfigFile, config.State{
		Agent:    "both",
		Snapshot: "agbox:v1",
	}); err != nil {
		t.Fatal(err)
	}
	app.StartHub = nil
	app.IsTTY = func() bool { return false }

	fakeMSB := filepath.Join(t.TempDir(), "fake-msb")
	fakeMSBScript := `#!/bin/sh
cmd="$1"
shift
case "$cmd" in
  ls)
    if [ -n "${FAKE_MSB_RUNNING:-}" ]; then
      echo "NAME STATE"
      echo "$FAKE_MSB_RUNNING running"
    fi
    exit 0
    ;;
  snap)
    echo "agbox:v1 1m 100M"
    exit 0
    ;;
  exec)
    has_stream=0
    has_no_stdin=0
    user=""
    while [ "$#" -gt 0 ]; do
      case "$1" in
        --stream) has_stream=1; shift ;;
        --no-stdin) has_no_stdin=1; shift ;;
        -u) user="$2"; shift 2 ;;
        -e|-w) shift 2 ;;
        -t|--no-tty|-d) shift ;;
        --) shift; break ;;
        *) shift ;;
      esac
    done
    # Simulated root setup helpers (ensureGuestUser, pushKeys, etc.)
    if [ "$user" = "root" ]; then
      exit 0
    fi
    # Check whether this is pushKeys (sh -c "umask 077 ...")
    if [ "${1:-}" = "sh" ] && [ "${2:-}" = "-c" ] && printf '%s' "${3:-}" | grep -q "umask 077"; then
      cat >/dev/null
      exit 0
    fi
    if [ "$has_stream" -ne 1 ]; then
      echo "expected --stream flag for --cmd" >&2
      exit 1
    fi
    if [ "$has_stream" -eq 1 ] && [ "$has_no_stdin" -eq 0 ]; then
      stdin_data="$(cat)"
      if [ -z "$stdin_data" ]; then
        echo "Error: '--stream' requires piped stdin or '--no-stdin'" >&2
        exit 1
      fi
      printf 'CMD_OUT_PIPED:%s\n' "$stdin_data"
      printf 'CMD_ERR_PIPED\n' >&2
      exit 0
    fi
    echo "CMD_OUT_STREAM"
    echo "CMD_ERR_STREAM" >&2
    exit 0
    ;;
  *)
    exit 0
    ;;
esac
`
	if err := os.WriteFile(fakeMSB, []byte(fakeMSBScript), 0o755); err != nil {
		t.Fatal(err)
	}
	execRunner, err := msb.NewExecRunner(fakeMSB)
	if err != nil {
		t.Fatal(err)
	}
	app.MSB = execRunner

	// 2a. With /dev/null stdin, --cmd must pass --no-stdin and stream stdout/stderr to App writers.
	app.Stdin = devNull
	stdout.Reset()
	stderr.Reset()
	if rc := app.dispatch(ctx, []string{"run", "--cmd", "echo hello"}); rc != 0 {
		t.Fatalf("run --cmd with /dev/null stdin failed rc=%d, stdout=%q, stderr=%q", rc, stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), "CMD_OUT_STREAM") {
		t.Errorf("expected guest stdout in App.Stdout, got %q", stdout.String())
	}
	if !strings.Contains(stderr.String(), "CMD_ERR_STREAM") {
		t.Errorf("expected guest stderr in App.Stderr, got %q", stderr.String())
	}

	// 2b. With piped stdin containing data, --cmd omits --no-stdin and forwards stdin bytes.
	pipeR, pipeW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(pipeW, "piped-payload"); err != nil {
		t.Fatal(err)
	}
	_ = pipeW.Close()
	app.Stdin = pipeR
	stdout.Reset()
	stderr.Reset()
	if rc := app.dispatch(ctx, []string{"run", "--cmd", "cat"}); rc != 0 {
		_ = pipeR.Close()
		t.Fatalf("run --cmd with piped stdin failed rc=%d, stdout=%q, stderr=%q", rc, stdout.String(), stderr.String())
	}
	_ = pipeR.Close()
	if !strings.Contains(stdout.String(), "CMD_OUT_PIPED:piped-payload") {
		t.Errorf("expected piped payload echoed to App.Stdout, got %q", stdout.String())
	}
	if !strings.Contains(stderr.String(), "CMD_ERR_PIPED") {
		t.Errorf("expected stderr from piped --cmd in App.Stderr, got %q", stderr.String())
	}

	// 2c. With a real PTY slave stdin (simulating command substitution $(agbox run --cmd ...) in a terminal),
	// isFileTerminal must return true and --cmd must pass --no-stdin so msb exec streams output.
	if ptmx, pErr := os.OpenFile("/dev/ptmx", os.O_RDWR, 0); pErr == nil {
		defer ptmx.Close()
		if lockErr := unix.IoctlSetInt(int(ptmx.Fd()), unix.TIOCSPTLCK, 0); lockErr == nil {
			if ptyNum, nErr := unix.IoctlGetInt(int(ptmx.Fd()), unix.TIOCGPTN); nErr == nil {
				slavePath := fmt.Sprintf("/dev/pts/%d", ptyNum)
				if slave, sErr := os.OpenFile(slavePath, os.O_RDWR, 0); sErr == nil {
					defer slave.Close()
					if !isFileTerminal(slave) {
						t.Fatalf("expected PTY slave %s to be detected as a terminal", slavePath)
					}
					app.Stdin = slave
					stdout.Reset()
					stderr.Reset()
					if rc := app.dispatch(ctx, []string{"run", "--cmd", "echo tty-cmd"}); rc != 0 {
						t.Fatalf("run --cmd with TTY stdin failed rc=%d, stdout=%q, stderr=%q", rc, stdout.String(), stderr.String())
					}
					if !strings.Contains(stdout.String(), "CMD_OUT_STREAM") || !strings.Contains(stderr.String(), "CMD_ERR_STREAM") {
						t.Errorf("expected streamed output with TTY stdin, got stdout=%q stderr=%q", stdout.String(), stderr.String())
					}
				}
			}
		}
	}

	// 3. Resuming a persistent sandbox with --persist --name ... --cmd ... also passes --stream --no-stdin and writes to App writers.
	app2, recRunner, stdout2, stderr2 := newTestApp(t)
	if err := config.SaveFile(app2.Env.ConfigFile, config.State{
		Agent:    "both",
		Snapshot: "agbox:v1",
	}); err != nil {
		t.Fatal(err)
	}
	app2.StartHub = nil
	app2.Stdin = devNull
	runDir := filepath.Join(app2.Env.DataDir, "run", "cmdp")
	if err := config.EnsurePrivateDir(runDir); err != nil {
		t.Fatal(err)
	}
	if err := config.SaveRunMeta(filepath.Join(runDir, "suspended"), config.RunMeta{
		Sandbox:  "agbox-cmdp",
		OwnerPID: 999999,
		Agent:    "opencode",
		Mode:     config.RunModeTUI,
		Persist:  true,
		MaskMode: config.MaskStrict,
	}); err != nil {
		t.Fatal(err)
	}
	recRunner.sandboxes = "NAME STATE\nagbox-base stopped\nagbox-cmdp stopped\n"
	recRunner.handler = func(req msb.CommandRequest) (msb.CommandResult, error) {
		if len(req.Args) >= 1 && req.Args[0] == "ls" {
			return msb.CommandResult{Stdout: recRunner.sandboxes}, nil
		}
		if len(req.Args) >= 2 && req.Args[0] == "snap" && req.Args[1] == "ls" {
			return msb.CommandResult{Stdout: recRunner.snapshots}, nil
		}
		if len(req.Args) >= 1 && req.Args[0] == "exec" && req.Interactive {
			if !slices.Contains(req.Args, "--stream") || !slices.Contains(req.Args, "--no-stdin") {
				return msb.CommandResult{ExitCode: 1}, fmt.Errorf("missing --stream/--no-stdin in %v", req.Args)
			}
			if req.Stdout != nil {
				_, _ = io.WriteString(req.Stdout, "PERSIST_CMD_STDOUT\n")
			}
			if req.Stderr != nil {
				_, _ = io.WriteString(req.Stderr, "PERSIST_CMD_STDERR\n")
			}
			return msb.CommandResult{}, nil
		}
		return msb.CommandResult{}, nil
	}
	if rc := app2.dispatch(ctx, []string{"run", "--persist", "--name", "cmdp", "--cmd", "echo ok"}); rc != 0 {
		t.Fatalf("persistent --cmd resume failed rc=%d, stderr=%q", rc, stderr2.String())
	}
	if !strings.Contains(stdout2.String(), "PERSIST_CMD_STDOUT") || !strings.Contains(stderr2.String(), "PERSIST_CMD_STDERR") {
		t.Errorf("expected persistent --cmd stdout/stderr, got stdout=%q stderr=%q", stdout2.String(), stderr2.String())
	}
}

func TestServeAntigravityRejection(t *testing.T) {
	app, _, _, stderr := newTestApp(t)
	if err := config.SaveFile(app.Env.ConfigFile, config.State{
		Snapshot:  "agbox:v1",
		Agent:     "both",
		SnapCount: 1,
	}); err != nil {
		t.Fatal(err)
	}
	projDir := filepath.Join(app.Env.HomeReal, "proj-serve-err")
	if err := os.MkdirAll(projDir, 0o700); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	rc := app.dispatch(ctx, []string{"run", "--serve", "antigravity", projDir})
	if rc == 0 {
		t.Fatal("expected run --serve antigravity to fail")
	}
	if !strings.Contains(stderr.String(), "--serve supports only the opencode agent") {
		t.Errorf("expected error to mention '--serve supports only the opencode agent', got %q", stderr.String())
	}
}

func TestUpdateExecStreamingFlags(t *testing.T) {
	app, runner, stdout, stderr := newTestApp(t)
	if err := config.SaveFile(app.Env.ConfigFile, config.State{
		Snapshot:  "agbox:v1",
		Agent:     "both",
		SnapCount: 1,
	}); err != nil {
		t.Fatal(err)
	}
	runner.sandboxes = "NAME STATE\nagbox-base stopped\n"
	runner.snapshots = "agbox:v1 1m 100M\n"

	var execCalls []msb.CommandRequest
	runner.handler = func(req msb.CommandRequest) (msb.CommandResult, error) {
		if len(req.Args) >= 1 && req.Args[0] == "ls" {
			return msb.CommandResult{Stdout: runner.sandboxes}, nil
		}
		if len(req.Args) >= 2 && req.Args[0] == "snap" && req.Args[1] == "ls" {
			return msb.CommandResult{Stdout: runner.snapshots}, nil
		}
		if len(req.Args) >= 1 && req.Args[0] == "exec" {
			execCalls = append(execCalls, req)
			var isBash, isSh bool
			for i, arg := range req.Args {
				if arg == "bash" && i+1 < len(req.Args) && req.Args[i+1] == "-c" {
					isBash = true
				}
				if arg == "sh" && i+1 < len(req.Args) && req.Args[i+1] == "-c" {
					isSh = true
				}
			}
			lastArg := req.Args[len(req.Args)-1]
			if isSh && strings.Contains(lastArg, "version.txt") {
				return msb.CommandResult{Stdout: "1.0.0\n"}, nil
			}
			if isSh && strings.Contains(lastArg, "binpath.txt") {
				elf := []byte("\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00" + strings.Repeat("\x00", 100))
				if req.Stdout != nil {
					_, _ = req.Stdout.Write(elf)
				}
				return msb.CommandResult{Stdout: string(elf)}, nil
			}
			if isBash {
				return msb.CommandResult{}, nil
			}
			return msb.CommandResult{}, nil
		}
		return msb.CommandResult{}, nil
	}

	ctx := context.Background()
	rc := app.dispatch(ctx, []string{"update", "opencode"})
	if rc != 0 {
		t.Fatalf("update failed rc=%d, stdout=%s, stderr=%s", rc, stdout.String(), stderr.String())
	}
	foundUpd := false
	foundVer := false
	foundStream := false
	for _, call := range execCalls {
		var isBash, isSh bool
		for i, arg := range call.Args {
			if arg == "bash" && i+1 < len(call.Args) && call.Args[i+1] == "-c" {
				isBash = true
			}
			if arg == "sh" && i+1 < len(call.Args) && call.Args[i+1] == "-c" {
				isSh = true
			}
		}
		lastArg := call.Args[len(call.Args)-1]
		if isBash {
			foundUpd = true
			if !slices.Contains(call.Args, "--stream") || !slices.Contains(call.Args, "--no-stdin") {
				t.Errorf("updScript missing --stream or --no-stdin: %v", call.Args)
			}
		}
		if isSh && strings.Contains(lastArg, "version.txt") {
			foundVer = true
			if !slices.Contains(call.Args, "--stream") || !slices.Contains(call.Args, "--no-stdin") {
				t.Errorf("verCmd missing --stream or --no-stdin: %v", call.Args)
			}
		}
		if isSh && strings.Contains(lastArg, "binpath.txt") {
			foundStream = true
			if !slices.Contains(call.Args, "--stream") || !slices.Contains(call.Args, "--no-stdin") {
				t.Errorf("streamCmd missing --stream or --no-stdin: %v", call.Args)
			}
		}
	}
	if !foundUpd || !foundVer || !foundStream {
		t.Errorf("expected updScript (%v), verCmd (%v), and streamCmd (%v) calls", foundUpd, foundVer, foundStream)
	}
}

type raceTeardownRunner struct {
	base               *fakeMSBRunner
	cancel             context.CancelFunc
	canceledDuringExec bool
	stoppedWithProfile bool
	removedWithForce   bool
	stopBeforeRm       bool
	stopCtxNonCanceled bool
	rmCtxNonCanceled   bool
}

func (r *raceTeardownRunner) Run(callCtx context.Context, req msb.CommandRequest) (msb.CommandResult, error) {
	if len(req.Args) >= 1 && req.Args[0] == "ls" {
		return msb.CommandResult{Stdout: r.base.sandboxes}, nil
	}
	if len(req.Args) >= 2 && req.Args[0] == "snap" && req.Args[1] == "ls" {
		return msb.CommandResult{Stdout: r.base.snapshots}, nil
	}
	if len(req.Args) >= 1 && req.Args[0] == "exec" {
		cmdStr := strings.Join(req.Args, " ")
		if strings.Contains(cmdStr, "sleep 10") {
			r.canceledDuringExec = true
			r.cancel()
			return msb.CommandResult{ExitCode: 130}, callCtx.Err()
		}
	}
	if len(req.Args) >= 3 && req.Args[0] == "stop" && req.Args[1] == "-t" && req.Args[2] == "10" {
		r.stoppedWithProfile = true
		if callCtx.Err() == nil {
			r.stopCtxNonCanceled = true
		}
		return msb.CommandResult{}, nil
	}
	if len(req.Args) >= 2 && req.Args[0] == "rm" && req.Args[1] == "-f" {
		r.removedWithForce = true
		if r.stoppedWithProfile {
			r.stopBeforeRm = true
		}
		if callCtx.Err() == nil {
			r.rmCtxNonCanceled = true
		}
		return msb.CommandResult{}, nil
	}
	return r.base.Run(callCtx, req)
}

func TestSignalCancellationSynchronousTeardownUnderRace(t *testing.T) {
	app, runner, _, stderr := newTestApp(t)
	if err := config.SaveFile(app.Env.ConfigFile, config.State{
		Snapshot:  "agbox:v1",
		Agent:     "both",
		SnapCount: 1,
	}); err != nil {
		t.Fatal(err)
	}
	runner.sandboxes = "NAME STATE\nagbox-base stopped\n"
	runner.snapshots = "agbox:v1 1m 100M\n"

	if err := os.MkdirAll(filepath.Join(app.Env.MSBHome, "volumes", "agbox-profile-raceprof"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(app.Env.MSBHome, "volumes", "agbox-profile-raceprof", "disk.raw"), []byte("DISK"), 0o600); err != nil {
		t.Fatal(err)
	}

	projDir := filepath.Join(app.Env.HomeReal, "proj-race")
	if err := os.MkdirAll(projDir, 0o700); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	raceRunner := &raceTeardownRunner{
		base:   runner,
		cancel: cancel,
	}
	app.MSB = raceRunner

	rc := app.dispatch(ctx, []string{"run", "opencode", "--name", "racesbx", "--profile", "raceprof", "--cmd", "sleep 10", projDir})
	if rc == 0 {
		t.Fatal("expected canceled run to exit with non-zero")
	}

	destroyedCleanly := raceRunner.canceledDuringExec &&
		raceRunner.stoppedWithProfile &&
		raceRunner.removedWithForce &&
		raceRunner.stopBeforeRm &&
		raceRunner.stopCtxNonCanceled &&
		raceRunner.rmCtxNonCanceled

	if !destroyedCleanly {
		t.Errorf("expected clean destroySandbox execution on cancellation: %s", stderr.String())
	}

	lock, err := persist.LockProfile(app.Env.DataDir, "raceprof")
	if err != nil {
		t.Fatalf("expected profile lock to be released after cancellation, got err: %v", err)
	}
	_ = lock.Unlock()
}

func TestReapOrphanRunsFlushesProfileDisk(t *testing.T) {
	app, runner, _, _ := newTestApp(t)

	dirID := "orphan1"
	sbName := "agbox-orphan1"
	runDir := filepath.Join(app.Env.DataDir, "run", dirID)
	if err := os.MkdirAll(runDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := config.SaveRunMeta(filepath.Join(runDir, "run.meta"), config.RunMeta{
		Sandbox:  sbName,
		OwnerPID: 999999,
		Profile:  "orphanprof",
	}); err != nil {
		t.Fatal(err)
	}

	runner.sandboxes = fmt.Sprintf("NAME STATE\nagbox-base stopped\n%s running\n", sbName)
	runner.calls = nil

	app.reapOrphanRuns(context.Background())

	stopIdx := -1
	rmIdx := -1
	for i, c := range runner.calls {
		if slices.Equal(c.Args, []string{"stop", "-t", "10", sbName}) {
			stopIdx = i
		}
		if slices.Equal(c.Args, []string{"rm", "-f", sbName}) {
			rmIdx = i
		}
	}
	if stopIdx == -1 {
		t.Errorf("expected stop -t 10 call for running profile orphan sandbox, calls: %v", runner.calls)
	}
	if rmIdx == -1 {
		t.Errorf("expected rm -f call for orphan sandbox, calls: %v", runner.calls)
	}
	if stopIdx != -1 && rmIdx != -1 && stopIdx >= rmIdx {
		t.Errorf("expected stop -t 10 (idx %d) before rm -f (idx %d)", stopIdx, rmIdx)
	}
}

func TestSuspendFlushesProfileDisk(t *testing.T) {
	app, runner, _, stderr := newTestApp(t)

	sbName := "agbox-suspprof"
	dirID := "suspprof"
	runDir := filepath.Join(app.Env.DataDir, "run", dirID)
	if err := os.MkdirAll(runDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := config.SaveRunMeta(filepath.Join(runDir, "run.meta"), config.RunMeta{
		Sandbox:  sbName,
		OwnerPID: app.PID,
		Profile:  "myprofile",
	}); err != nil {
		t.Fatal(err)
	}

	runner.sandboxes = fmt.Sprintf("NAME STATE\nagbox-base stopped\n%s running\n", sbName)
	runner.calls = nil

	ctx := context.Background()
	if rc := app.dispatch(ctx, []string{"suspend", sbName}); rc != 0 {
		t.Fatalf("suspend failed (rc=%d): %s", rc, stderr.String())
	}

	foundStopFlush := false
	for _, c := range runner.calls {
		if slices.Equal(c.Args, []string{"stop", "-t", "10", sbName}) {
			foundStopFlush = true
			break
		}
	}
	if !foundStopFlush {
		t.Errorf("expected msb stop -t 10 %s on profile sandbox suspend, calls: %v", sbName, runner.calls)
	}
}

func TestStopFailureBoundaryPreservesState(t *testing.T) {
	app, runner, _, _ := newTestApp(t)

	sbName := "agbox-failstop"
	dirID := "failstop"
	runDir := filepath.Join(app.Env.DataDir, "run", dirID)
	if err := os.MkdirAll(runDir, 0o700); err != nil {
		t.Fatal(err)
	}
	metaPath := filepath.Join(runDir, "run.meta")
	if err := config.SaveRunMeta(metaPath, config.RunMeta{
		Sandbox:  sbName,
		OwnerPID: app.PID,
	}); err != nil {
		t.Fatal(err)
	}

	runner.sandboxes = fmt.Sprintf("NAME STATE\nagbox-base stopped\n%s running\n", sbName)
	runner.handler = func(req msb.CommandRequest) (msb.CommandResult, error) {
		if len(req.Args) >= 2 && req.Args[0] == "rm" && req.Args[1] == "-f" {
			return msb.CommandResult{ExitCode: 1, Stderr: "simulated backend destroy failure"}, errors.New("backend failure")
		}
		return msb.CommandResult{}, nil
	}

	ctx := context.Background()
	rc := app.dispatch(ctx, []string{"stop", sbName})
	if rc == 0 {
		t.Fatal("expected stop to fail when destroySandbox fails")
	}

	if _, err := os.Stat(runDir); err != nil {
		t.Errorf("expected runDir %s to be preserved, got error: %v", runDir, err)
	}
	if _, err := os.Stat(metaPath); err != nil {
		t.Errorf("expected run.meta %s to be preserved, got error: %v", metaPath, err)
	}
	deletingMarker := filepath.Join(runDir, "deleting")
	if _, err := os.Stat(deletingMarker); !os.IsNotExist(err) {
		t.Errorf("expected deleting marker to be removed after failure, found: %v", err)
	}
}

func TestShareMutationsRollbackOnSaveMetaError(t *testing.T) {
	app, _, _, _ := newTestApp(t)
	ctx := context.Background()

	sbName := "agbox-shroll"
	dirID := "shroll"
	runDir := filepath.Join(app.Env.DataDir, "run", dirID)
	if err := os.MkdirAll(runDir, 0o700); err != nil {
		t.Fatal(err)
	}
	sockPath := filepath.Join(runDir, "ws.sock")

	var hubCommands []string
	hubLn, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatal(err)
	}
	defer hubLn.Close()

	go func() {
		for {
			conn, lErr := hubLn.Accept()
			if lErr != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 1024)
				n, _ := c.Read(buf)
				hubCommands = append(hubCommands, strings.TrimSpace(string(buf[:n])))
				_, _ = c.Write([]byte("{\"ok\":true,\"share\":{\"guest_name\":\"sh\"}}\n"))
			}(conn)
		}
	}()

	shareDir := filepath.Join(app.Env.HomeReal, "hot-shroll")
	if err := os.MkdirAll(shareDir, 0o700); err != nil {
		t.Fatal(err)
	}

	initialMeta := config.RunMeta{
		Sandbox:  sbName,
		OwnerPID: app.PID,
		Shares: []config.ShareRecord{
			{Index: 0, GuestName: "hot", HostPath: shareDir, AccessMode: "rw", ReadOnly: false, VCSPolicy: config.VCSAllow},
		},
	}
	blockerFile := filepath.Join(runDir, "not-a-dir")
	if err := os.WriteFile(blockerFile, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	badMetaPath := filepath.Join(blockerFile, "run.meta")

	addOpts := shareOpts{Target: shareDir, Alias: "hot2"}
	errAdd := app.addSandboxShare(ctx, addOpts, true, runDir, badMetaPath, initialMeta)
	if errAdd == nil {
		t.Error("expected addSandboxShare to fail when SaveRunMeta fails")
	}

	setOpts := shareOpts{Target: "hot", HasAccess: true, ReadOnly: true}
	errSet := app.setSandboxShare(ctx, setOpts, true, runDir, badMetaPath, initialMeta)
	if errSet == nil {
		t.Error("expected setSandboxShare to fail when SaveRunMeta fails")
	}

	rmOpts := shareOpts{Target: "hot"}
	errRm := app.removeSandboxShare(ctx, rmOpts, true, runDir, badMetaPath, initialMeta)
	if errRm == nil {
		t.Error("expected removeSandboxShare to fail when SaveRunMeta fails")
	}
}

func TestEnsureProfileVolumeRollbackOnSaveMetaError(t *testing.T) {
	app, runner, _, _ := newTestApp(t)

	runner.handler = func(req msb.CommandRequest) (msb.CommandResult, error) {
		if len(req.Args) >= 2 && req.Args[0] == "volume" && req.Args[1] == "ls" {
			return msb.CommandResult{Stdout: ""}, nil
		}
		return msb.CommandResult{}, nil
	}

	origDir := app.Env.DataDir
	app.Env.DataDir = "/dev/null/impossible"
	defer func() { app.Env.DataDir = origDir }()

	ctx := context.Background()
	_, err := app.ensureProfileVolume(ctx, "myvol", "1G")
	if err == nil {
		t.Fatal("expected ensureProfileVolume to fail when SaveProfileMeta fails")
	}

	foundVolRm := false
	for _, c := range runner.calls {
		if len(c.Args) >= 3 && c.Args[0] == "volume" && c.Args[1] == "rm" && c.Args[2] == "agbox-profile-myvol" {
			foundVolRm = true
			break
		}
	}
	if !foundVolRm {
		t.Errorf("expected volume rm rollback call, calls: %v", runner.calls)
	}
}

func TestVersionCommandAndFlag(t *testing.T) {
	app, _, stdout, _ := newTestApp(t)
	ctx := context.Background()

	stdout.Reset()
	if rc := app.dispatch(ctx, []string{"--version"}); rc != 0 {
		t.Fatalf("expected --version rc=0, got %d", rc)
	}
	if stdout.String() != fmt.Sprintf("agbox %s\n", version) {
		t.Errorf("expected %q, got %q", fmt.Sprintf("agbox %s\n", version), stdout.String())
	}

	stdout.Reset()
	if rc := app.dispatch(ctx, []string{"version"}); rc != 0 {
		t.Fatalf("expected version rc=0, got %d", rc)
	}
	if stdout.String() != fmt.Sprintf("agbox %s\n", version) {
		t.Errorf("expected %q, got %q", fmt.Sprintf("agbox %s\n", version), stdout.String())
	}

	opts, err := parseGlobalArgs([]string{"--version"})
	if err != nil || opts.Mode != "version" {
		t.Errorf("ParseGlobalArgs(--version) = %+v, %v", opts, err)
	}
	opts, err = parseGlobalArgs([]string{"version"})
	if err != nil || opts.Mode != "version" {
		t.Errorf("ParseGlobalArgs(version) = %+v, %v", opts, err)
	}

	if rc := Main([]string{"--version"}); rc != 0 {
		t.Errorf("Main(--version) = %d, want 0", rc)
	}
	if rc := Main([]string{"version"}); rc != 0 {
		t.Errorf("Main(version) = %d, want 0", rc)
	}
}

func TestSignaledChildExitCode(t *testing.T) {
	cmd := exec.Command("sh", "-c", "kill -TERM $$")
	err := cmd.Run()
	if err != nil {
		wrapped := wrapPassthroughExit(msb.CommandResult{}, err)
		var passErr passthroughExitError
		if errors.As(wrapped, &passErr) {
			if passErr.code != 128+int(syscall.SIGTERM) {
				t.Errorf("expected code %d for SIGTERM, got %d", 128+int(syscall.SIGTERM), passErr.code)
			}
		} else {
			t.Errorf("expected passthroughExitError for signaled child, got %v", wrapped)
		}
	}
}

func TestCliHelperFunctionsAndEdgeCases(t *testing.T) {
	if !isAgboxSnapshotName("agbox:v1") || !isAgboxSnapshotName("agbox:v99") {
		t.Error("expected valid agbox:vN to match")
	}
	if isAgboxSnapshotName("custom:v1") || isAgboxSnapshotName("ubuntu:latest") {
		t.Error("expected invalid snapshot names not to match")
	}

	td := t.TempDir()
	_ = supportsUserXattr(td, true)
	_ = checkKVMAccess()

	app, _, stdout, _ := newTestApp(t)
	ctx := context.Background()
	for _, sub := range []string{"rules", "share", "update", "profile", "auth", "skills"} {
		stdout.Reset()
		rc := app.dispatch(ctx, []string{sub, "--help"})
		if rc != 0 {
			t.Errorf("expected %s --help rc=0, got %d", sub, rc)
		}
		if sub == "share" {
			if !strings.Contains(stdout.String(), "unless you pass --rw or :rw.") {
				t.Errorf("share --help missing active-voice text: %s", stdout.String())
			}
			if !strings.Contains(stdout.String(), "unless you pass --force.") {
				t.Errorf("share --help missing active-voice text: %s", stdout.String())
			}
		}
	}

	docsDir := filepath.Join(td, "docs")
	codeDir := filepath.Join(td, "code")
	_ = os.MkdirAll(docsDir, 0o700)
	_ = os.MkdirAll(codeDir, 0o700)
	symlinkPath := filepath.Join(td, "docs-link")
	_ = os.Symlink(docsDir, symlinkPath)

	shares := []config.ShareRecord{
		{Index: 0, GuestName: "docs", HostPath: filepath.Clean(docsDir)},
		{Index: 1, GuestName: "code", HostPath: filepath.Clean(codeDir)},
	}
	if idx, err := findShareRecordIndex(shares, "/workspace/docs"); err != nil || idx != 0 {
		t.Errorf("findShareRecordIndex(/workspace/docs) = %d, %v", idx, err)
	}
	if idx, err := findShareRecordIndex(shares, "code"); err != nil || idx != 1 {
		t.Errorf("findShareRecordIndex(code) = %d, %v", idx, err)
	}
	if idx, err := findShareRecordIndex(shares, docsDir); err != nil || idx != 0 {
		t.Errorf("findShareRecordIndex(hostPath) = %d, %v", idx, err)
	}
	if idx, err := findShareRecordIndex(shares, symlinkPath); err != nil || idx != 0 {
		t.Errorf("findShareRecordIndex(symlink) = %d, %v", idx, err)
	}
	if _, err := findShareRecordIndex(shares, "nonexistent"); err == nil {
		t.Error("expected error for nonexistent share")
	}

	if _, err := parseStatusArgs([]string{"--help"}); !errors.Is(err, errHelp) {
		t.Errorf("ParseStatusArgs(--help) expected ErrHelp, got %v", err)
	}
	if _, err := parseStatusArgs([]string{"-h"}); !errors.Is(err, errHelp) {
		t.Errorf("ParseStatusArgs(-h) expected ErrHelp, got %v", err)
	}
	if _, err := parseStatusArgs([]string{"--bogus"}); err == nil {
		t.Error("ParseStatusArgs(--bogus) expected error")
	}
	if _, err := parseSetupArgs([]string{"-h"}); !errors.Is(err, errHelp) {
		t.Errorf("ParseSetupArgs(-h) expected ErrHelp, got %v", err)
	}
	if _, err := parseSetupArgs([]string{"--bogus"}); err == nil {
		t.Error("ParseSetupArgs(--bogus) expected error")
	}

	if aOpts, err := parseAuthArgs([]string{"logout", "antigravity"}); err != nil || aOpts.Action != "logout" || aOpts.Target != "antigravity" {
		t.Errorf("ParseAuthArgs(logout antigravity) = %+v, %v", aOpts, err)
	}
	if aOpts, err := parseAuthArgs([]string{"logout", "all"}); err != nil || aOpts.Action != "logout" || aOpts.Target != "all" {
		t.Errorf("ParseAuthArgs(logout all) = %+v, %v", aOpts, err)
	}
	if _, err := parseAuthArgs([]string{"logout", "invalid"}); err == nil {
		t.Error("ParseAuthArgs(logout invalid) expected error")
	}

	app.Env.RootDisk = "0"
	if err := app.ensureSparseRootDiskSize(ctx, false); err != nil {
		t.Errorf("ensureSparseRootDiskSize with 0 expected nil, got %v", err)
	}
	app.Env.RootDisk = "invalid"
	if err := app.ensureSparseRootDiskSize(ctx, false); err != nil {
		t.Errorf("ensureSparseRootDiskSize with invalid expected nil, got %v", err)
	}

	runDir := filepath.Join(app.Env.DataDir, "run", "susp1")
	if err := os.MkdirAll(runDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := config.SaveRunMeta(filepath.Join(runDir, "suspended"), config.RunMeta{
		Sandbox: "agbox-susp1",
		Shares:  shares,
	}); err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	if err := app.listSandboxShares("agbox-susp1", false, runDir, config.RunMeta{Shares: shares}); err != nil {
		t.Errorf("listSandboxShares on suspended sandbox returned error: %v", err)
	}
	if !strings.Contains(stdout.String(), "/workspace/docs") {
		t.Errorf("expected docs share in output, got: %s", stdout.String())
	}

	prodApp, _ := newApp()
	if prodApp != nil {
		_ = prodApp.isRoot()
	}
}

func TestNoMaskStatVirtModes(t *testing.T) {
	app, runner, _, _ := newTestApp(t)
	if err := config.SaveFile(app.Env.ConfigFile, config.State{
		Snapshot:  "agbox:v1",
		Agent:     "both",
		SnapCount: 1,
	}); err != nil {
		t.Fatal(err)
	}
	app.Env.MaskVCS = config.MaskOff

	projDir := filepath.Join(app.Env.HomeReal, "nomask-proj")
	if err := os.MkdirAll(projDir, 0o700); err != nil {
		t.Fatal(err)
	}

	var restoreArgs []string
	runner.handler = func(req msb.CommandRequest) (msb.CommandResult, error) {
		if len(req.Args) >= 1 && req.Args[0] == "ls" {
			return msb.CommandResult{Stdout: runner.sandboxes}, nil
		}
		if len(req.Args) >= 2 && req.Args[0] == "snap" && req.Args[1] == "ls" {
			return msb.CommandResult{Stdout: runner.snapshots}, nil
		}
		if len(req.Args) >= 2 && req.Args[0] == "snap" && req.Args[1] == "restore" {
			restoreArgs = slices.Clone(req.Args)
		}
		return msb.CommandResult{}, nil
	}

	ctx := context.Background()
	_ = app.dispatch(ctx, []string{"run", "--no-mask", "--ro", "--cmd", "id", projDir})
	foundRO := false
	for _, a := range restoreArgs {
		if strings.Contains(a, "ro,stat-virt=relaxed,uid=1000,gid=1000") {
			foundRO = true
			break
		}
	}
	if !foundRO {
		t.Errorf("expected ro,stat-virt=relaxed for read-only direct share, got: %v", restoreArgs)
	}
}

func TestSignalExitCode128PlusSignal(t *testing.T) {
	cmd := exec.Command("sh", "-c", "kill -TERM $$")
	realErr := cmd.Run()
	var exitErr *exec.ExitError
	if !errors.As(realErr, &exitErr) {
		t.Skip("real *exec.ExitError unavailable on this platform")
	}
	ws, ok := exitErr.Sys().(syscall.WaitStatus)
	if !ok || !ws.Signaled() || ws.Signal() != syscall.SIGTERM {
		t.Skip("subprocess was not terminated by SIGTERM")
	}
	wantCode := 128 + int(syscall.SIGTERM)
	if wantCode != 143 {
		t.Fatalf("expected wantCode 143, got %d", wantCode)
	}

	// 1. Direct wrapPassthroughExit verification.
	wrapped := wrapPassthroughExit(msb.CommandResult{}, realErr)
	var passErr passthroughExitError
	if !errors.As(wrapped, &passErr) {
		t.Fatalf("wrapPassthroughExit returned %T (%v), want passthroughExitError", wrapped, wrapped)
	}
	if passErr.code != wantCode {
		t.Fatalf("wrapPassthroughExit code = %d, want %d", passErr.code, wantCode)
	}

	// 2. Dispatch verification with runner returning the signaled exit error.
	app, runner, _, _ := newTestApp(t)
	if err := config.SaveFile(app.Env.ConfigFile, config.State{
		Snapshot:  "agbox:v1",
		Agent:     "opencode",
		SnapCount: 1,
	}); err != nil {
		t.Fatal(err)
	}
	runner.sandboxes = "NAME STATE\nagbox-base stopped\n"
	runner.snapshots = "agbox:v1 1m 100M\n"
	runner.handler = func(req msb.CommandRequest) (msb.CommandResult, error) {
		if len(req.Args) >= 1 && req.Args[0] == "ls" {
			return msb.CommandResult{Stdout: runner.sandboxes}, nil
		}
		if len(req.Args) >= 2 && req.Args[0] == "snap" && req.Args[1] == "ls" {
			return msb.CommandResult{Stdout: runner.snapshots}, nil
		}
		if len(req.Args) >= 1 && req.Args[0] == "exec" {
			return msb.CommandResult{ExitCode: wantCode}, realErr
		}
		return msb.CommandResult{}, nil
	}
	projDir := filepath.Join(app.Env.HomeReal, "proj-term")
	if err := os.MkdirAll(projDir, 0o700); err != nil {
		t.Fatal(err)
	}
	rc := app.dispatch(context.Background(), []string{"run", "opencode", "--name", "test-term", "--cmd", "exit", projDir})
	if rc != wantCode {
		t.Fatalf("Dispatch exit code = %d, want %d", rc, wantCode)
	}
}

func TestAuthAndRemoteControlExecStreamFlags(t *testing.T) {
	// 1. App.Auth capScript must pass --stream and --no-stdin.
	t.Run("AuthCapScriptStreamFlags", func(t *testing.T) {
		app, runner, _, _ := newTestApp(t)
		if err := config.SaveFile(app.Env.ConfigFile, config.State{
			Snapshot:  "agbox:v1",
			Agent:     "opencode",
			SnapCount: 1,
		}); err != nil {
			t.Fatal(err)
		}
		fakeGuestHome := t.TempDir()
		if err := os.MkdirAll(filepath.Join(fakeGuestHome, ".local", "share", "opencode"), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(fakeGuestHome, ".local", "share", "opencode", "auth.json"), []byte(`{"anthropic":{"type":"oauth","access":"secret"}}`), 0o600); err != nil {
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
			if len(req.Args) >= 6 && req.Args[0] == "exec" && strings.Contains(req.Args[len(req.Args)-1], "printf 'FILE ") {
				script := strings.ReplaceAll(req.Args[len(req.Args)-1], config.GuestHome, fakeGuestHome)
				cmd := exec.Command("/bin/sh", "-c", script)
				cmd.Env = []string{"HOME=" + fakeGuestHome, "PATH=/usr/bin:/bin"}
				out, cErr := cmd.Output()
				return msb.CommandResult{Stdout: string(out)}, cErr
			}
			return msb.CommandResult{}, nil
		}

		err := app.auth(context.Background(), []string{"opencode"})
		if err != nil {
			t.Fatalf("Auth failed: %v", err)
		}

		var foundCap bool
		for _, c := range runner.calls {
			if len(c.Args) >= 1 && c.Args[0] == "exec" && strings.Contains(strings.Join(c.Args, " "), "printf 'FILE ") {
				foundCap = true
				if !slices.Contains(c.Args, "--stream") {
					t.Errorf("expected --stream in auth capScript exec args: %v", c.Args)
				}
				if !slices.Contains(c.Args, "--no-stdin") {
					t.Errorf("expected --no-stdin in auth capScript exec args: %v", c.Args)
				}
			}
		}
		if !foundCap {
			t.Fatal("auth capScript exec was not called")
		}
	})

	// 2. RunModeRemoteControl start and status must pass --stream and --no-stdin.
	t.Run("RemoteControlStartAndStatusStreamFlags", func(t *testing.T) {
		app, runner, _, _ := newTestApp(t)
		if err := config.SaveFile(app.Env.ConfigFile, config.State{
			Snapshot:  "agbox:v1",
			Agent:     "both",
			SnapCount: 1,
		}); err != nil {
			t.Fatal(err)
		}
		runner.sandboxes = "NAME STATE\nagbox-base stopped\n"
		runner.snapshots = "NAME CREATED\nagbox:v1 1m\n"

		projDir := filepath.Join(app.Env.HomeReal, "proj-rc-stream")
		if err := os.MkdirAll(projDir, 0o700); err != nil {
			t.Fatal(err)
		}

		rc := app.dispatch(context.Background(), []string{"run", "--name", "rcstream", "-d", "--remote-control", projDir})
		if rc != 0 {
			t.Fatalf("Dispatch run -d --remote-control failed with rc=%d", rc)
		}

		var foundStart, foundStatus bool
		for _, c := range runner.calls {
			cmdStr := strings.Join(c.Args, " ")
			if strings.Contains(cmdStr, "agy remote-control start") {
				foundStart = true
				if !slices.Contains(c.Args, "--stream") {
					t.Errorf("expected --stream in remote-control start args: %v", c.Args)
				}
				if !slices.Contains(c.Args, "--no-stdin") {
					t.Errorf("expected --no-stdin in remote-control start args: %v", c.Args)
				}
			}
			if strings.Contains(cmdStr, "agy remote-control status") {
				foundStatus = true
				if !slices.Contains(c.Args, "--stream") {
					t.Errorf("expected --stream in remote-control status args: %v", c.Args)
				}
				if !slices.Contains(c.Args, "--no-stdin") {
					t.Errorf("expected --no-stdin in remote-control status args: %v", c.Args)
				}
			}
		}
		if !foundStart {
			t.Fatal("agy remote-control start was not called")
		}
		if !foundStatus {
			t.Fatal("agy remote-control status was not called")
		}
	})
}

func TestCreateBaseAndEditBaseTeardownUnderCanceledContext(t *testing.T) {
	// 1. CreateBase deferred rollback under canceled context.
	t.Run("CreateBaseRollback", func(t *testing.T) {
		app, runner, _, _ := newTestApp(t)
		parentCtx, cancelParent := context.WithCancel(context.Background())
		defer cancelParent()

		var rollbackCalled bool
		var rollbackCtxErr error

		runner.ctxHandler = func(callCtx context.Context, req msb.CommandRequest) (msb.CommandResult, error) {
			if len(req.Args) >= 1 && req.Args[0] == "ls" {
				return msb.CommandResult{Stdout: "NAME STATE\n"}, nil
			}
			if len(req.Args) >= 1 && req.Args[0] == "create" {
				return msb.CommandResult{}, nil
			}
			if len(req.Args) >= 1 && req.Args[0] == "exec" {
				cancelParent()
				return msb.CommandResult{ExitCode: 1}, errors.New("simulated provisioning failure")
			}
			if slices.Equal(req.Args, []string{"rm", "-f", config.BaseSandbox}) {
				rollbackCalled = true
				rollbackCtxErr = callCtx.Err()
				return msb.CommandResult{}, nil
			}
			return msb.CommandResult{}, nil
		}

		err := app.createBase(parentCtx, []string{"--force", "opencode"})
		if err == nil {
			t.Fatal("expected CreateBase to fail when canceled during provisioning")
		}
		if parentCtx.Err() == nil {
			t.Fatal("expected parent context to be canceled")
		}
		if !rollbackCalled {
			t.Fatal("expected deferred rollback 'rm -f agbox-base' to be called")
		}
		if rollbackCtxErr != nil {
			t.Fatalf("expected callCtx.Err() == nil during rollback, got %v", rollbackCtxErr)
		}
		for _, c := range runner.calls {
			if slices.Equal(c.Args, []string{"rm", "-f", config.BaseSandbox}) {
				if c.CtxErr != nil {
					t.Fatalf("expected c.CtxErr == nil at call time, got %v", c.CtxErr)
				}
			}
		}
	})

	// 2. EditBase deferred stop under canceled context.
	t.Run("EditBaseStop", func(t *testing.T) {
		app, runner, _, _ := newTestApp(t)
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

		parentCtx, cancelParent := context.WithCancel(context.Background())
		defer cancelParent()

		var stopCalled bool
		var stopCtxErr error

		runner.ctxHandler = func(callCtx context.Context, req msb.CommandRequest) (msb.CommandResult, error) {
			if len(req.Args) >= 1 && req.Args[0] == "ls" {
				return msb.CommandResult{Stdout: runner.sandboxes}, nil
			}
			if len(req.Args) >= 2 && req.Args[0] == "snap" && req.Args[1] == "ls" {
				return msb.CommandResult{Stdout: runner.snapshots}, nil
			}
			if len(req.Args) >= 1 && req.Args[0] == "start" {
				return msb.CommandResult{}, nil
			}
			if len(req.Args) >= 1 && req.Args[0] == "exec" {
				cancelParent()
				return msb.CommandResult{ExitCode: 1}, errors.New("simulated edit failure")
			}
			if slices.Equal(req.Args, []string{"stop", config.BaseSandbox}) {
				stopCalled = true
				stopCtxErr = callCtx.Err()
				return msb.CommandResult{}, nil
			}
			return msb.CommandResult{}, nil
		}

		err := app.editBase(parentCtx, []string{"--cmd", "true"})
		if err == nil {
			t.Fatal("expected EditBase to fail when canceled during provisioning command")
		}
		if parentCtx.Err() == nil {
			t.Fatal("expected parent context to be canceled")
		}
		if !stopCalled {
			t.Fatal("expected deferred stop 'stop agbox-base' to be called")
		}
		if stopCtxErr != nil {
			t.Fatalf("expected callCtx.Err() == nil during stop, got %v", stopCtxErr)
		}
		for _, c := range runner.calls {
			if slices.Equal(c.Args, []string{"stop", config.BaseSandbox}) {
				if c.CtxErr != nil {
					t.Fatalf("expected c.CtxErr == nil at call time, got %v", c.CtxErr)
				}
			}
		}
	})
}

func TestEnsureSparseRootDiskSizeExpansion(t *testing.T) {
	app, runner, _, _ := newTestApp(t)
	baseDir := filepath.Join(app.Env.MSBHome, "sandboxes", config.BaseSandbox)
	if err := os.MkdirAll(baseDir, 0o700); err != nil {
		t.Fatal(err)
	}
	upperPath := filepath.Join(baseDir, "upper.ext4")
	initialBytes := int64(1024 * 1024)
	if err := os.WriteFile(upperPath, make([]byte, initialBytes), 0o600); err != nil {
		t.Fatal(err)
	}

	app.Env.RootDisk = "10M"
	targetBytes := int64(10 * 1024 * 1024)
	if err := app.ensureSparseRootDiskSize(context.Background(), false); err != nil {
		t.Fatalf("ensureSparseRootDiskSize failed: %v", err)
	}
	st, err := os.Stat(upperPath)
	if err != nil {
		t.Fatal(err)
	}
	if st.Size() != targetBytes {
		t.Errorf("expected size %d, got %d", targetBytes, st.Size())
	}

	// Expand running sandbox and verify msb stop and start calls.
	app.Env.RootDisk = "20M"
	targetBytes2 := int64(20 * 1024 * 1024)
	runner.calls = nil
	if err := app.ensureSparseRootDiskSize(context.Background(), true); err != nil {
		t.Fatalf("ensureSparseRootDiskSize running failed: %v", err)
	}
	st2, err := os.Stat(upperPath)
	if err != nil {
		t.Fatal(err)
	}
	if st2.Size() != targetBytes2 {
		t.Errorf("expected size %d, got %d", targetBytes2, st2.Size())
	}
	var foundStop, foundStart bool
	for _, c := range runner.calls {
		if slices.Equal(c.Args, []string{"stop", config.BaseSandbox}) {
			foundStop = true
		}
		if slices.Equal(c.Args, []string{"start", config.BaseSandbox}) {
			foundStart = true
		}
	}
	if !foundStop || !foundStart {
		t.Errorf("expected stop and start calls when isRunning is true, got %v", runner.calls)
	}
}

func TestStopUnderCanceledContextFlushesProfile(t *testing.T) {
	app, runner, _, _ := newTestApp(t)
	sbName := "agbox-run-7777"
	runDir := filepath.Join(app.Env.DataDir, "run", "7777")
	if err := os.MkdirAll(runDir, 0o700); err != nil {
		t.Fatal(err)
	}
	meta := config.RunMeta{
		Sandbox:  sbName,
		OwnerPID: app.PID,
		Mode:     config.RunModeTUI,
		Profile:  "prof-stop",
	}
	if err := config.SaveRunMeta(filepath.Join(runDir, "run.meta"), meta); err != nil {
		t.Fatal(err)
	}
	runner.sandboxes = "NAME STATE\n" + sbName + " running\n"

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if err := app.stop(ctx, []string{"--allow-root", sbName}); err != nil {
		t.Fatalf("Stop failed: %v", err)
	}

	var foundStop, foundRm bool
	for _, c := range runner.calls {
		if slices.Equal(c.Args, []string{"stop", "-t", "10", sbName}) {
			foundStop = true
			if c.CtxErr != nil {
				t.Errorf("expected non-canceled context on stop, got error %v", c.CtxErr)
			}
		}
		if slices.Equal(c.Args, []string{"rm", "-f", sbName}) {
			foundRm = true
			if c.CtxErr != nil {
				t.Errorf("expected non-canceled context on rm, got error %v", c.CtxErr)
			}
		}
	}
	if !foundStop {
		t.Error("expected stop -t 10 call before removal")
	}
	if !foundRm {
		t.Error("expected rm -f call during Stop")
	}
}

func TestRemoveFlushesRunningSandboxes(t *testing.T) {
	app, runner, _, _ := newTestApp(t)
	runner.sandboxes = "NAME STATE\nagbox-base running\nagbox-run-100 running\nagbox-run-200 stopped\n"

	if err := app.remove(context.Background(), []string{"--yes", "--allow-root"}); err != nil {
		t.Fatalf("Remove failed: %v", err)
	}

	var stopBase, rmBase, stop100, rm100, stop200, rm200 bool
	for _, c := range runner.calls {
		if slices.Equal(c.Args, []string{"stop", "-t", "10", config.BaseSandbox}) {
			stopBase = true
		}
		if slices.Equal(c.Args, []string{"rm", "-f", config.BaseSandbox}) {
			rmBase = true
		}
		if slices.Equal(c.Args, []string{"stop", "-t", "10", "agbox-run-100"}) {
			stop100 = true
		}
		if slices.Equal(c.Args, []string{"rm", "-f", "agbox-run-100"}) {
			rm100 = true
		}
		if slices.Equal(c.Args, []string{"stop", "-t", "10", "agbox-run-200"}) {
			stop200 = true
		}
		if slices.Equal(c.Args, []string{"rm", "-f", "agbox-run-200"}) {
			rm200 = true
		}
	}

	if !stopBase || !rmBase {
		t.Error("expected stop -t 10 and rm -f for running agbox-base")
	}
	if !stop100 || !rm100 {
		t.Error("expected stop -t 10 and rm -f for running agbox-run-100")
	}
	if stop200 {
		t.Error("expected no stop -t 10 call for stopped agbox-run-200")
	}
	if !rm200 {
		t.Error("expected rm -f for stopped agbox-run-200")
	}
}

func TestResumeRollbackFlushesProfileDisk(t *testing.T) {
	app, runner, _, _ := newTestApp(t)
	sbName := "agbox-run-8888"
	runDir := filepath.Join(app.Env.DataDir, "run", "8888")
	if err := os.MkdirAll(runDir, 0o700); err != nil {
		t.Fatal(err)
	}
	meta := config.RunMeta{
		Sandbox:      sbName,
		OwnerPID:     app.PID,
		Mode:         config.RunModeCmd,
		Cmd:          "echo ok",
		Agent:        "opencode",
		Profile:      "prof-resume",
		WorkspaceHub: false,
		NoSkills:     true,
		NoRules:      true,
		NoAgentCache: true,
	}
	suspendedPath := filepath.Join(runDir, "suspended")
	if err := config.SaveRunMeta(suspendedPath, meta); err != nil {
		t.Fatal(err)
	}

	parentCtx, cancelParent := context.WithCancel(context.Background())
	defer cancelParent()

	metaPath := filepath.Join(runDir, "run.meta")
	volName := persist.FormatProfileVolumeName(meta.Profile)
	runner.sandboxes = "NAME STATE\n" + sbName + " stopped\n"
	runner.handler = func(req msb.CommandRequest) (msb.CommandResult, error) {
		if len(req.Args) >= 1 && req.Args[0] == "ls" {
			return msb.CommandResult{Stdout: runner.sandboxes}, nil
		}
		if len(req.Args) >= 2 && req.Args[0] == "volume" && req.Args[1] == "ls" {
			return msb.CommandResult{Stdout: "NAME\n" + volName + "\n"}, nil
		}
		if len(req.Args) >= 2 && req.Args[0] == "start" && req.Args[1] == sbName {
			cancelParent()
			_ = os.Remove(metaPath)
			_ = os.MkdirAll(filepath.Join(metaPath, "keep"), 0o700)
			return msb.CommandResult{}, nil
		}
		return msb.CommandResult{}, nil
	}
	defer func() {
		_ = os.RemoveAll(metaPath)
	}()

	err := app.resume(parentCtx, []string{"--allow-root", sbName})
	if err == nil {
		t.Fatal("expected Resume to fail when SaveRunMeta fails")
	}

	var foundStopProfile bool
	for _, c := range runner.calls {
		if slices.Equal(c.Args, []string{"stop", "-t", "10", sbName}) {
			foundStopProfile = true
			if c.CtxErr != nil {
				t.Errorf("expected non-canceled context during rollback stop, got error %v", c.CtxErr)
			}
		}
	}
	if !foundStopProfile {
		t.Errorf("expected stop -t 10 call during SaveRunMeta rollback, got calls %v", runner.calls)
	}
}

func TestExecStreamFlagsAndSmokeTest(t *testing.T) {
	app, runner, _, _ := newTestApp(t)
	app.CheckKVM = func() error { return nil }
	app.CheckFUSE = func() error { return nil }
	runner.handler = func(req msb.CommandRequest) (msb.CommandResult, error) {
		if len(req.Args) >= 1 && req.Args[0] == "exec" {
			return msb.CommandResult{Stdout: "SMOKE-OK\n0\n"}, nil
		}
		return msb.CommandResult{}, nil
	}

	if err := app.setup(context.Background(), []string{"--allow-root"}); err != nil {
		t.Fatalf("Setup failed: %v", err)
	}

	var foundSmokeExec bool
	for _, c := range runner.calls {
		if len(c.Args) >= 1 && c.Args[0] == "exec" && strings.Contains(strings.Join(c.Args, " "), "SMOKE-OK") {
			foundSmokeExec = true
			if !slices.Contains(c.Args, "--stream") {
				t.Errorf("expected --stream in smoke test exec: %v", c.Args)
			}
			if !slices.Contains(c.Args, "--no-stdin") {
				t.Errorf("expected --no-stdin in smoke test exec: %v", c.Args)
			}
			idx := slices.Index(c.Args, "-u")
			if idx == -1 || idx+1 >= len(c.Args) || c.Args[idx+1] != "root" {
				t.Errorf("expected -u root in smoke test exec: %v", c.Args)
			}
		}
	}
	if !foundSmokeExec {
		t.Fatal("smoke test exec was not called")
	}

	// Verify the 6 helper functions pass --stream and --no-stdin with -u root.
	helperCalls := []struct {
		name string
		fn   func() error
	}{
		{"provisionGuestUser", func() error { return app.provisionGuestUser(context.Background(), "sb-test") }},
		{"setupGuestSkills", func() error { return app.setupGuestSkills(context.Background(), "sb-test") }},
		{"setupGuestRules", func() error { return app.setupGuestRules(context.Background(), "sb-test") }},
		{"setupGuestProfile", func() error { return app.setupGuestProfile(context.Background(), "sb-test") }},
		{"setupGuestAgents", func() error { return app.setupGuestAgents(context.Background(), "sb-test") }},
		{"dropGuestVFSCaches", func() error { app.dropGuestVFSCaches(context.Background(), "sb-test"); return nil }},
	}

	for _, hc := range helperCalls {
		t.Run(hc.name, func(t *testing.T) {
			runner.calls = nil
			if err := hc.fn(); err != nil {
				t.Fatalf("%s failed: %v", hc.name, err)
			}
			if len(runner.calls) == 0 {
				t.Fatalf("expected at least one call from %s", hc.name)
			}
			last := runner.calls[len(runner.calls)-1]
			if !slices.Contains(last.Args, "--stream") {
				t.Errorf("%s missing --stream: %v", hc.name, last.Args)
			}
			if !slices.Contains(last.Args, "--no-stdin") {
				t.Errorf("%s missing --no-stdin: %v", hc.name, last.Args)
			}
			idx := slices.Index(last.Args, "-u")
			if idx == -1 || idx+1 >= len(last.Args) || last.Args[idx+1] != "root" {
				t.Errorf("%s missing -u root: %v", hc.name, last.Args)
			}
		})
	}
}

func TestSetupInstallsDefaultEnvRuleAndPreservesRemoval(t *testing.T) {
	ctx := context.Background()
	app, runner, stdout, stderr := newTestApp(t)
	app.CheckKVM = func() error { return nil }
	app.CheckFUSE = func() error { return nil }

	// 1. Setup installs default environment rule file.
	if err := app.setup(ctx, []string{"--allow-root"}); err != nil {
		t.Fatalf("setup failed: %v", err)
	}
	rulePath := filepath.Join(app.Env.DataDir, "rules", persist.DefaultEnvRuleName+".md")
	if info, err := os.Lstat(rulePath); err != nil || info.Mode().Perm() != 0o644 {
		t.Fatalf("expected rule file at %s with mode 0644, err=%v", rulePath, err)
	}

	// 2. Rules list displays installed default rule.
	stdout.Reset()
	if rc := app.dispatch(ctx, []string{"rules", "list"}); rc != 0 || !strings.Contains(stdout.String(), persist.DefaultEnvRuleName) {
		t.Fatalf("rules list expected %s, rc=%d stdout=%s", persist.DefaultEnvRuleName, rc, stdout.String())
	}

	// 3. User removes default rule with rules rm.
	if rc := app.dispatch(ctx, []string{"rules", "rm", persist.DefaultEnvRuleName}); rc != 0 {
		t.Fatalf("rules rm failed with rc=%d: %s", rc, stderr.String())
	}
	if _, err := os.Lstat(rulePath); !os.IsNotExist(err) {
		t.Fatalf("expected rule file deleted, got stat err=%v", err)
	}

	// 4. Subsequent run does not re-create deleted default rule.
	runner.snapshots = "NAME CREATED\nagbox:v1 1m\n"
	if err := config.SaveFile(app.Env.ConfigFile, config.State{
		Agent:     "opencode",
		Image:     "node:24-bookworm-slim",
		Snapshot:  "agbox:v1",
		SnapCount: 1,
	}); err != nil {
		t.Fatal(err)
	}
	projDir := filepath.Join(app.Env.HomeReal, "repo-norules")
	if err := os.MkdirAll(projDir, 0o700); err != nil {
		t.Fatal(err)
	}
	runner.calls = nil
	stderr.Reset()
	if rc := app.dispatch(ctx, []string{"run", "--cmd", "id -u", projDir}); rc != 0 {
		t.Fatalf("run failed with rc=%d: %s", rc, stderr.String())
	}
	if _, err := os.Lstat(rulePath); !os.IsNotExist(err) {
		t.Fatalf("expected rule to stay deleted after run, got stat err=%v", err)
	}

	// 5. Setup fails closed when rules dir is a symlink.
	symApp, _, _, _ := newTestApp(t)
	symApp.CheckKVM = func() error { return nil }
	symApp.CheckFUSE = func() error { return nil }
	outsideRules := filepath.Join(t.TempDir(), "outside-rules")
	if err := os.MkdirAll(outsideRules, 0o700); err != nil {
		t.Fatal(err)
	}
	rulesSymlink := filepath.Join(symApp.Env.DataDir, "rules")
	if err := os.Symlink(outsideRules, rulesSymlink); err != nil {
		t.Fatal(err)
	}
	if err := symApp.setup(ctx, []string{"--allow-root"}); err == nil {
		t.Fatal("expected setup to fail closed when rules dir is a symlink")
	}
}

func TestPassthroughExitErrorAndRuntimeHelpers(t *testing.T) {
	inner := errors.New("exit 17")
	pe := passthroughExitError{code: 17, err: inner}
	if pe.Error() != "exit 17" {
		t.Fatalf("passthroughExitError.Error() = %q, want %q", pe.Error(), "exit 17")
	}
	if !errors.Is(pe, inner) {
		t.Fatalf("expected Unwrap to match inner error")
	}

	errWithStderr := formatMSBStderrOnlyError("capture auth", "line1\nline2\n", inner)
	if !strings.Contains(errWithStderr.Error(), "line2") {
		t.Errorf("expected stderr detail in %q", errWithStderr.Error())
	}
	errNoStderr := formatMSBStderrOnlyError("capture auth", "   ", inner)
	if errNoStderr.Error() != "capture auth: exit 17" {
		t.Errorf("unexpected empty-stderr format: %q", errNoStderr.Error())
	}

	if got := shortSHA256("abcdef"); got != "abcdef" {
		t.Errorf("shortSHA256 short = %q", got)
	}
	if got := shortSHA256("0123456789abcdef0000"); got != "0123456789ab" {
		t.Errorf("shortSHA256 long = %q", got)
	}
	if got := tailLines("a\nb\nc\nd\n", 2); got != "c\nd" {
		t.Errorf("tailLines(2) = %q", got)
	}

	// Verify nil-default vs injected runtime helpers.
	var bare appRuntime
	if bare.euid() != config.GuestUID || bare.egid() != config.GuestGID {
		t.Errorf("bare euid/egid = %d/%d", bare.euid(), bare.egid())
	}
	if bare.now().IsZero() {
		t.Error("expected non-zero default time")
	}
	fixedNow := time.Date(2026, 11, 19, 12, 0, 0, 0, time.UTC)
	bare.Now = func() time.Time { return fixedNow }
	bare.GetEGID = func() int { return 2222 }
	if !bare.now().Equal(fixedNow) || bare.egid() != 2222 {
		t.Errorf("injected now/egid mismatch")
	}
	if isFileTerminal(nil) {
		t.Error("expected isFileTerminal(nil) == false")
	}

	// cmdNeedsNoStdin edge cases.
	bare.Stdin = nil
	if !bare.cmdNeedsNoStdin() {
		t.Error("nil Stdin should report needsNoStdin=true")
	}
	bare.Stdin = strings.NewReader("")
	if !bare.cmdNeedsNoStdin() {
		t.Error("empty Reader should report needsNoStdin=true")
	}
	bare.Stdin = strings.NewReader("abc")
	if bare.cmdNeedsNoStdin() {
		t.Error("non-empty Reader should report needsNoStdin=false")
	}
	bare.Stdin = io.NopCloser(strings.NewReader("stream"))
	if bare.cmdNeedsNoStdin() {
		t.Error("unsized Reader should report needsNoStdin=false")
	}
	td := t.TempDir()
	emptyReg := filepath.Join(td, "empty.txt")
	nonEmptyReg := filepath.Join(td, "data.txt")
	_ = os.WriteFile(emptyReg, nil, 0o600)
	_ = os.WriteFile(nonEmptyReg, []byte("x"), 0o600)
	fEmpty, err := os.Open(emptyReg)
	if err != nil {
		t.Fatal(err)
	}
	defer fEmpty.Close()
	bare.Stdin = fEmpty
	if !bare.cmdNeedsNoStdin() {
		t.Error("empty regular file should report needsNoStdin=true")
	}
	fData, err := os.Open(nonEmptyReg)
	if err != nil {
		t.Fatal(err)
	}
	defer fData.Close()
	bare.Stdin = fData
	if bare.cmdNeedsNoStdin() {
		t.Error("non-empty regular file should report needsNoStdin=false")
	}

	// Verify newApp leaves MSB untyped nil (not typed-nil *msb.ExecRunner) when msb is absent.
	t.Setenv("PATH", td)
	t.Setenv("HOME", td)
	app, err := newApp()
	if err != nil {
		t.Fatalf("newApp without msb in PATH failed: %v", err)
	}
	if app.MSB != nil {
		t.Fatalf("expected app.MSB == nil when msb is missing, got non-nil interface %T", app.MSB)
	}
	if err := app.ensureMSB(); err == nil {
		t.Fatal("expected ensureMSB to fail when msb is absent from PATH")
	}
	fakeBin := filepath.Join(td, "msb")
	if err := os.WriteFile(fakeBin, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := app.ensureMSB(); err != nil || app.MSB == nil {
		t.Fatalf("expected ensureMSB to resolve fake msb from PATH, got %v", err)
	}

	// Main entry error and help paths.
	if rc := Main([]string{"--help"}); rc != 0 {
		t.Errorf("Main(--help) = %d, want 0", rc)
	}
	if rc := Main([]string{"--unknown-global"}); rc != 1 {
		t.Errorf("Main(--unknown-global) = %d, want 1", rc)
	}
	t.Setenv("AGBOX_CPUS", "0")
	if rc := Main([]string{"status"}); rc != 1 {
		t.Errorf("Main(status) with invalid AGBOX_CPUS = %d, want 1", rc)
	}
}

func TestParserEdgeCasesAndRunNameReservation(t *testing.T) {
	// run-<digits> must be rejected for --name while agbox-run-<digits> remains a valid PID run sandbox.
	if _, err := validateRunName("run-1234"); err == nil {
		t.Error("expected validateRunName(run-1234) to fail")
	}
	if !isRunSandboxName("agbox-run-1234") {
		t.Error("expected isRunSandboxName(agbox-run-1234) == true")
	}
	if !isRunSandboxName("agbox-1234") {
		t.Error("expected isRunSandboxName(agbox-1234) == true")
	}
	if dirID, err := runDirIDFromSandbox("agbox-1234"); err != nil || dirID != "_1234" {
		t.Errorf("runDirIDFromSandbox(agbox-1234) = %q, %v", dirID, err)
	}
	if _, err := runDirIDFromSandbox("not-agbox"); err == nil {
		t.Error("expected runDirIDFromSandbox(not-agbox) error")
	}

	sbxTests := []struct {
		dirID  string
		want   string
		wantOK bool
	}{
		{"", "", false},
		{"4242", "agbox-run-4242", true},
		{"_4242", "agbox-4242", true},
		{"run-4242", "", false},
		{"work1", "agbox-work1", true},
		{"-bad", "", false},
	}
	for _, tc := range sbxTests {
		got, ok := sandboxFromRunDirID(tc.dirID)
		if got != tc.want || ok != tc.wantOK {
			t.Errorf("sandboxFromRunDirID(%q) = (%q, %v), want (%q, %v)", tc.dirID, got, ok, tc.want, tc.wantOK)
		}
	}

	// parseRunArgs rejects --serve + antigravity at parse time without /dev/kvm.
	if _, err := parseRunArgs([]string{"--serve", "antigravity"}, config.MaskStrict, nil); err == nil || !strings.Contains(err.Error(), "--serve supports only the opencode agent") {
		t.Fatalf("expected parseRunArgs(--serve antigravity) error, got %v", err)
	}

	if _, err := parseStatusArgs([]string{"extra"}); err == nil {
		t.Error("expected parseStatusArgs positional arg error")
	}
	if _, err := parseResumeArgs([]string{"--help"}); !errors.Is(err, errHelp) {
		t.Errorf("parseResumeArgs(--help) = %v", err)
	}
	for _, bad := range [][]string{
		{},
		{"agbox-a", "agbox-b"},
		{"--bogus", "agbox-a"},
		{"-c", "--session", "s1", "agbox-a"},
		{"--session"},
	} {
		if _, err := parseResumeArgs(bad); err == nil {
			t.Errorf("expected parseResumeArgs(%v) to fail", bad)
		}
	}
	rOpts, err := parseResumeArgs([]string{"--no-auth", "--no-skills", "--no-rules", "--no-agent-cache", "-d", "agbox-a"})
	if err != nil || !rOpts.NoAuth || !rOpts.NoSkills || !rOpts.NoRules || !rOpts.NoAgentCache || !rOpts.Detach {
		t.Fatalf("parseResumeArgs valid flags = %+v, %v", rOpts, err)
	}

	if _, _, err := parseStopOpts([]string{"-h"}); !errors.Is(err, errHelp) {
		t.Errorf("parseStopOpts(-h) = %v", err)
	}
	if _, _, err := parseRemoveOpts([]string{"-h"}); !errors.Is(err, errHelp) {
		t.Errorf("parseRemoveOpts(-h) = %v", err)
	}
	if _, _, err := parseRemoveOpts([]string{"--bogus"}); err == nil {
		t.Error("expected parseRemoveOpts(--bogus) error")
	}

	// Per-subcommand flag rejections for skills, rules, profile, and share.
	for _, bad := range [][]string{
		{"--force"},
		{"list", "--force"},
		{"rm", "--force", "sk"},
		{"list", "extra"},
	} {
		if _, err := parseSkillsArgs(bad); err == nil {
			t.Errorf("expected parseSkillsArgs(%v) error", bad)
		}
	}
	for _, bad := range [][]string{
		{"--force"},
		{"list", "--force"},
		{"add", "--name", "a", "--name", "b", "f.md"},
		{"add", "--all", "f.md"},
		{"show", "--force", "a"},
		{"rm", "--force", "a"},
		{"rm", "--name", "a", "a"},
	} {
		if _, err := parseRulesArgs(bad); err == nil {
			t.Errorf("expected parseRulesArgs(%v) error", bad)
		}
	}
	for _, bad := range [][]string{
		{"--force"},
		{"list", "--size", "10G"},
		{"create", "--size", "10G", "--size", "20G", "p1"},
		{"create", "--force", "p1"},
		{"rm", "--size", "10G", "p1"},
	} {
		if _, err := parseProfileArgs(bad); err == nil {
			t.Errorf("expected parseProfileArgs(%v) error", bad)
		}
	}
	for _, bad := range [][]string{
		{},
		{"--as"},
		{"add", "--as", "a", "--as", "b", "agbox-s1", "/tmp/x"},
		{"list", "--ro", "agbox-s1"},
		{"add", "--force", "agbox-s1", "/tmp/x"},
		{"set", "--as", "alias", "--ro", "agbox-s1", "x"},
		{"rm", "--ro", "agbox-s1", "x"},
		{"add", "--ro", "--vcs-hooks", "agbox-s1", "/tmp/x"},
		{"add", "--vcs", "--vcs-hooks", "agbox-s1", "/tmp/x"},
		{"unknown", "agbox-s1"},
	} {
		if _, err := parseShareArgs(bad); err == nil {
			t.Errorf("expected parseShareArgs(%v) error", bad)
		}
	}
	shHooks, err := parseShareArgs([]string{"add", "--vcs-hooks", "agbox-s1", "/tmp/x:rw"})
	if err != nil || !shHooks.HasVCS || shHooks.VCSPolicy != config.VCSAllowHooks {
		t.Fatalf("expected share add --vcs-hooks path:rw to parse, got %+v, %v", shHooks, err)
	}

	// parseSizeBytes overflow check.
	if _, ok := parseSizeBytes("99999999999G"); ok {
		t.Error("expected parseSizeBytes int64 overflow to return ok=false")
	}
	if b, ok := parseSizeBytes("2G"); !ok || b != 2*1024*1024*1024 {
		t.Errorf("parseSizeBytes(2G) = %d, %v", b, ok)
	}
}

func TestWaitServeUIRedirectRejectionAndPingFailure(t *testing.T) {
	var canaryHits atomic.Int32
	canary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		canaryHits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer canary.Close()

	redirectSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, canary.URL+"/ssrf", http.StatusFound)
	}))
	defer redirectSrv.Close()

	_, portStr, _ := net.SplitHostPort(redirectSrv.Listener.Addr().String())
	port, _ := strconv.Atoi(portStr)

	app, runner, _, _ := newTestApp(t)
	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()

	if app.defaultWaitServeUI(ctx, port, "agbox-srv") {
		t.Fatal("expected HTTP 302 redirect response not to count as ready UI")
	}
	if canaryHits.Load() != 0 {
		t.Fatalf("expected CheckRedirect to block redirect target, got %d hits", canaryHits.Load())
	}

	// Verify msb ping failure aborts waiting immediately.
	runner.handler = func(req msb.CommandRequest) (msb.CommandResult, error) {
		if len(req.Args) >= 2 && req.Args[0] == "ping" {
			return msb.CommandResult{ExitCode: 1}, errors.New("sandbox dead")
		}
		return msb.CommandResult{}, nil
	}
	if app.defaultWaitServeUI(context.Background(), port, "agbox-srv") {
		t.Fatal("expected ping failure to abort defaultWaitServeUI")
	}
}

func TestSecurityFixesAuthSecretsAndPushKeysZeroClear(t *testing.T) {
	app, runner, stdout, stderr := newTestApp(t)
	ctx := context.Background()

	if err := config.SaveFile(app.Env.ConfigFile, config.State{
		Agent:     "opencode",
		Image:     "node:24-bookworm-slim",
		Snapshot:  "agbox:v1",
		SnapCount: 1,
	}); err != nil {
		t.Fatal(err)
	}

	// [H6] Auth capture failure must NEVER include capRes.Stdout token material in returned error.
	secretToken := "SECRET_STDOUT_OAUTH_BEARER_999"
	runner.handler = func(req msb.CommandRequest) (msb.CommandResult, error) {
		if len(req.Args) >= 1 && req.Args[0] == "ls" {
			return msb.CommandResult{Stdout: runner.sandboxes}, nil
		}
		if len(req.Args) >= 2 && req.Args[0] == "snap" && req.Args[1] == "ls" {
			return msb.CommandResult{Stdout: runner.snapshots}, nil
		}
		joined := strings.Join(req.Args, " ")
		if strings.Contains(joined, "FILE opencode") {
			return msb.CommandResult{
				Stdout:   "FILE opencode auth.json " + secretToken + "\n",
				Stderr:   "capture failed cleanly\n",
				ExitCode: 1,
			}, errors.New("exit status 1")
		}
		return msb.CommandResult{}, nil
	}
	err := app.auth(ctx, []string{"opencode"})
	if err == nil {
		t.Fatal("expected auth capture error")
	}
	if strings.Contains(err.Error(), secretToken) {
		t.Fatalf("auth capture error leaked stdout secret: %v", err)
	}
	if !strings.Contains(err.Error(), "capture failed cleanly") {
		t.Errorf("expected stderr diagnostic in auth error, got %v", err)
	}

	// Auth returns early when context is canceled during interactive login without running capture.
	authCancelCtx, cancelAuth := context.WithCancel(ctx)
	captureCalled := false
	runner.handler = func(req msb.CommandRequest) (msb.CommandResult, error) {
		if len(req.Args) >= 1 && req.Args[0] == "ls" {
			return msb.CommandResult{Stdout: runner.sandboxes}, nil
		}
		if len(req.Args) >= 2 && req.Args[0] == "snap" && req.Args[1] == "ls" {
			return msb.CommandResult{Stdout: runner.snapshots}, nil
		}
		joined := strings.Join(req.Args, " ")
		if strings.Contains(joined, "opencode auth login") {
			cancelAuth()
			return msb.CommandResult{ExitCode: 130}, context.Canceled
		}
		if strings.Contains(joined, "FILE opencode") {
			captureCalled = true
		}
		return msb.CommandResult{}, nil
	}
	if err := app.auth(authCancelCtx, []string{"opencode"}); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled on aborted auth, got %v", err)
	}
	if captureCalled {
		t.Fatal("expected auth not to run credential capture after context cancellation")
	}
	runner.handler = nil

	// [H6] pushKeys with 0 secrets still overwrites/clears /home/agent/.agbox-keys.sh and checks [ ! -L /home/agent ].
	app.Getenv = func(string) string { return "" }
	runner.calls = nil
	stdout.Reset()
	stderr.Reset()
	if err := app.pushKeys(ctx, "agbox-zero"); err != nil {
		t.Fatalf("pushKeys with 0 secrets failed: %v", err)
	}
	if strings.Contains(stdout.String(), "Streamed ") {
		t.Errorf("did not expect Streamed log when 0 secrets exist, got %q", stdout.String())
	}
	foundWrite := false
	for _, c := range runner.calls {
		joined := strings.Join(c.Args, " ")
		if strings.Contains(joined, "[ ! -L /home/agent ]") &&
			strings.Contains(joined, "rm -f "+config.GuestKeysFile) &&
			strings.Contains(joined, "chmod 0600 "+config.GuestKeysFile) {
			foundWrite = true
			if strings.Contains(c.Stdin, "export ") {
				t.Errorf("expected header-only script on 0 keys, got %q", c.Stdin)
			}
		}
	}
	if !foundWrite {
		t.Fatalf("expected pushKeys to overwrite %s even with 0 keys, calls=%v", config.GuestKeysFile, runner.calls)
	}
}

func TestSecurityFixesProfileLockRefreshAndInitialRunMeta(t *testing.T) {
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

	// [H9] Run refreshes msb ls AFTER LockProfile so a sandbox that started before lock acquisition is detected.
	otherDir := filepath.Join(app.Env.DataDir, "run", "other1")
	if err := config.SaveRunMeta(filepath.Join(otherDir, "run.meta"), config.RunMeta{
		Sandbox:  "agbox-other1",
		OwnerPID: app.PID,
		Profile:  "sharedprof",
	}); err != nil {
		t.Fatal(err)
	}
	lsCount := 0
	runner.handler = func(req msb.CommandRequest) (msb.CommandResult, error) {
		if len(req.Args) >= 1 && req.Args[0] == "ls" {
			lsCount++
			if lsCount == 1 {
				return msb.CommandResult{Stdout: "NAME STATE\nagbox-base stopped\n"}, nil
			}
			return msb.CommandResult{Stdout: "NAME STATE\nagbox-base stopped\nagbox-other1 running\n"}, nil
		}
		if len(req.Args) >= 2 && req.Args[0] == "snap" && req.Args[1] == "ls" {
			return msb.CommandResult{Stdout: runner.snapshots}, nil
		}
		return msb.CommandResult{}, nil
	}
	if rc := app.dispatch(ctx, []string{"run", "--name", "contend1", "--profile", "sharedprof", "--cmd", "true"}); rc == 0 {
		t.Fatal("expected run to detect active profile sandbox on post-lock msb ls refresh")
	}
	if !strings.Contains(stderr.String(), "active in running sandbox agbox-other1") {
		t.Errorf("unexpected stderr: %s", stderr.String())
	}
	_ = os.RemoveAll(otherDir)
	runner.handler = nil

	// [M3] Run writes initial run.meta BEFORE StartHub so concurrent reapStaleFilterDirs preserves runFilterDir.
	app.PID = os.Getpid()
	projDir := filepath.Join(app.Env.HomeReal, "m3-proj")
	if err := os.MkdirAll(projDir, 0o700); err != nil {
		t.Fatal(err)
	}
	sawLiveMetaDuringHub := false
	origHub := app.StartHub
	app.StartHub = func(mntDir, sockPath, pidFile string, initial []vcsfuse.HubShareConfig, dieWithParent bool) (int, error) {
		runDir := filepath.Dir(mntDir)
		if m, err := config.LoadRunMeta(filepath.Join(runDir, "run.meta")); err == nil && m.OwnerPID == app.PID {
			sawLiveMetaDuringHub = true
		}
		peer := *app
		peer.PID = app.PID + 100
		peer.reapStaleFilterDirs(ctx)
		if _, err := os.Stat(runDir); err != nil {
			return 0, fmt.Errorf("reapStaleFilterDirs deleted active starting runDir: %w", err)
		}
		return origHub(mntDir, sockPath, pidFile, initial, dieWithParent)
	}
	stderr.Reset()
	if rc := app.dispatch(ctx, []string{"run", "--name", "m3run", "--cmd", "true", projDir}); rc != 0 {
		t.Fatalf("run with concurrent reapStaleFilterDirs failed: %s", stderr.String())
	}
	app.StartHub = origHub
	if !sawLiveMetaDuringHub {
		t.Fatal("expected initial run.meta with live OwnerPID before StartHub")
	}
}

func TestHardenedRootDiskResizeResumeRollbackAndRemoveSymlink(t *testing.T) {
	app, runner, _, stderr := newTestApp(t)
	ctx := context.Background()

	baseDir := filepath.Join(app.Env.MSBHome, "sandboxes", config.BaseSandbox)
	if err := os.MkdirAll(baseDir, 0o700); err != nil {
		t.Fatal(err)
	}
	upperPath := filepath.Join(baseDir, "upper.ext4")

	// [M6] Reject symlinked upper.ext4.
	realTarget := filepath.Join(t.TempDir(), "real.ext4")
	_ = os.WriteFile(realTarget, make([]byte, 1024), 0o600)
	_ = os.Symlink(realTarget, upperPath)
	app.Env.RootDisk = "10M"
	if err := app.ensureSparseRootDiskSize(ctx, false); err == nil || !strings.Contains(err.Error(), "refusing non-regular") {
		t.Fatalf("expected symlinked upper.ext4 rejection, got %v", err)
	}
	_ = os.Remove(upperPath)
	if err := os.WriteFile(upperPath, make([]byte, 1024), 0o600); err != nil {
		t.Fatal(err)
	}

	// [M6] Abort before truncating if msb stop fails.
	truncated := false
	app.TruncateFile = func(string, int64) error {
		truncated = true
		return nil
	}
	runner.handler = func(req msb.CommandRequest) (msb.CommandResult, error) {
		if slices.Equal(req.Args, []string{"stop", config.BaseSandbox}) {
			return msb.CommandResult{Stderr: "stop busy", ExitCode: 1}, errors.New("stop failed")
		}
		return msb.CommandResult{}, nil
	}
	if err := app.ensureSparseRootDiskSize(ctx, true); err == nil {
		t.Fatal("expected ensureSparseRootDiskSize to fail when msb stop fails")
	}
	if truncated {
		t.Fatal("ensureSparseRootDiskSize truncated upper.ext4 despite msb stop failure")
	}
	app.TruncateFile = os.Truncate

	// [M6] e2fsck fatal exit code fails closed and still restarts agbox-base via defer.
	runner.calls = nil
	runner.handler = nil
	app.RunHostCmd = func(_ context.Context, name string, _ ...string) ([]byte, error) {
		if strings.HasSuffix(name, "e2fsck") {
			exit8 := exec.Command("sh", "-c", "exit 8").Run()
			return []byte("corrupt superblock"), exit8
		}
		return nil, nil
	}
	if err := app.ensureSparseRootDiskSize(ctx, true); err == nil {
		// Only skip if neither /sbin/resize2fs nor /usr/sbin/resize2fs exists on host.
		if _, sErr := os.Stat("/sbin/resize2fs"); sErr == nil {
			t.Fatal("expected e2fsck exit 8 to fail ensureSparseRootDiskSize")
		}
	}
	app.RunHostCmd = func(context.Context, string, ...string) ([]byte, error) { return nil, nil }

	// [M6] Remove skips symlinked snapshot group dir and never runs global 'msb prune -y'.
	snapParent := filepath.Join(app.Env.MSBHome, "snapshots")
	_ = os.MkdirAll(snapParent, 0o700)
	outsideSnap := t.TempDir()
	keepFile := filepath.Join(outsideSnap, "keep.txt")
	_ = os.WriteFile(keepFile, []byte("safe"), 0o600)
	_ = os.Symlink(outsideSnap, filepath.Join(snapParent, config.SnapGroup))

	runner.calls = nil
	stderr.Reset()
	if err := app.remove(ctx, []string{"--yes", "--allow-root"}); err != nil {
		t.Fatalf("remove failed: %v", err)
	}
	if _, err := os.Stat(keepFile); err != nil {
		t.Fatalf("remove followed symlinked snapshot dir and deleted %s", keepFile)
	}
	for _, c := range runner.calls {
		if slices.Equal(c.Args, []string{"prune", "-y"}) {
			t.Fatalf("remove unexpectedly invoked global 'msb prune -y': %v", runner.calls)
		}
	}
}

func TestShareUpgradeOnlyRollbackAndErrorWrapping(t *testing.T) {
	app, runner, _, _ := newTestApp(t)
	ctx := context.Background()

	sbName := "agbox-shsec"
	runDir := filepath.Join(app.Env.DataDir, "run", "shsec")
	if err := os.MkdirAll(runDir, 0o700); err != nil {
		t.Fatal(err)
	}
	sockPath := filepath.Join(runDir, "ws.sock")
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	var mu sync.Mutex
	var hubCmds []string
	go func() {
		for {
			conn, cErr := ln.Accept()
			if cErr != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 1024)
				n, _ := c.Read(buf)
				mu.Lock()
				hubCmds = append(hubCmds, strings.TrimSpace(string(buf[:n])))
				mu.Unlock()
				_, _ = c.Write([]byte("{\"ok\":true,\"share\":{\"guest_name\":\"sh\"}}\n"))
			}(conn)
		}
	}()

	shareDir := filepath.Join(app.Env.HomeReal, "shsec-dir")
	if err := os.MkdirAll(shareDir, 0o700); err != nil {
		t.Fatal(err)
	}
	blocker := filepath.Join(runDir, "blocker-file")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	badMetaPath := filepath.Join(blocker, "run.meta")

	// 1. Downgrade (rw -> ro) must NOT roll back to rw when SaveRunMeta fails.
	rwMeta := config.RunMeta{
		Sandbox:  sbName,
		OwnerPID: app.PID,
		Shares: []config.ShareRecord{
			{Index: 0, GuestName: "sh", HostPath: shareDir, IsDir: true, AccessMode: "rw", ReadOnly: false, VCSPolicy: config.VCSAllow},
		},
	}
	_ = app.setSandboxShare(ctx, shareOpts{Target: "sh", HasAccess: true, ReadOnly: true}, true, runDir, badMetaPath, rwMeta)
	mu.Lock()
	downgradeCalls := len(hubCmds)
	mu.Unlock()
	if downgradeCalls != 1 {
		t.Fatalf("expected exactly 1 hub call (no rollback) on rw->ro downgrade, got %d: %v", downgradeCalls, hubCmds)
	}

	// 2. Upgrade (ro -> rw and mask -> vcs) MUST roll back to ro+mask when SaveRunMeta fails.
	mu.Lock()
	hubCmds = nil
	mu.Unlock()
	roMeta := config.RunMeta{
		Sandbox:  sbName,
		OwnerPID: app.PID,
		Shares: []config.ShareRecord{
			{Index: 0, GuestName: "sh", HostPath: shareDir, IsDir: true, AccessMode: "ro", ReadOnly: true, VCSPolicy: config.VCSMask},
		},
	}
	_ = app.setSandboxShare(ctx, shareOpts{Target: "sh", HasAccess: true, ReadOnly: false, HasVCS: true, VCSPolicy: config.VCSAllowHooks}, true, runDir, badMetaPath, roMeta)
	mu.Lock()
	upgradeCalls := len(hubCmds)
	mu.Unlock()
	if upgradeCalls != 2 {
		t.Fatalf("expected 2 hub calls (apply + rollback) on ro->rw upgrade, got %d: %v", upgradeCalls, hubCmds)
	}

	// 3. Stopped sandbox with corrupt suspended file wraps parse error instead of claiming 'not suspended'.
	corruptDir := filepath.Join(app.Env.DataDir, "run", "corrupt1")
	_ = os.MkdirAll(corruptDir, 0o700)
	_ = os.WriteFile(filepath.Join(corruptDir, "suspended"), []byte("{not-json"), 0o600)
	runner.sandboxes = "NAME STATE\nagbox-base stopped\nagbox-corrupt1 stopped\n"
	sErr := app.share(ctx, []string{"list", "agbox-corrupt1"})
	if sErr == nil || strings.Contains(sErr.Error(), "not suspended") {
		t.Fatalf("expected wrapped suspended parse error, got %v", sErr)
	}
}

func TestProfileSizePreservationSuspendStopFailureAndMaskAutoWarn(t *testing.T) {
	app, runner, stdout, stderr := newTestApp(t)
	ctx := context.Background()

	// 1. Existing profile with 50G keeps 50G when ensureProfileVolume runs with default 10G.
	runner.handler = func(req msb.CommandRequest) (msb.CommandResult, error) {
		if len(req.Args) >= 2 && req.Args[0] == "volume" && req.Args[1] == "ls" {
			return msb.CommandResult{Stdout: "NAME\nagbox-profile-keep50\n"}, nil
		}
		if len(req.Args) >= 1 && req.Args[0] == "ls" {
			return msb.CommandResult{Stdout: runner.sandboxes}, nil
		}
		if len(req.Args) >= 2 && req.Args[0] == "snap" && req.Args[1] == "ls" {
			return msb.CommandResult{Stdout: runner.snapshots}, nil
		}
		return msb.CommandResult{}, nil
	}
	if err := persist.SaveProfileMeta(app.Env.DataDir, persist.ProfileMeta{
		Name:   "keep50",
		Volume: "agbox-profile-keep50",
		Size:   "50G",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := app.ensureProfileVolume(ctx, "keep50", "10G"); err != nil {
		t.Fatalf("ensureProfileVolume(keep50) failed: %v", err)
	}
	profs, err := persist.ListProfiles(app.Env.DataDir)
	if err != nil || len(profs) != 1 || profs[0].Size != "50G" {
		t.Fatalf("expected ProfileMeta.Size to remain 50G, got %+v, %v", profs, err)
	}

	// 2. suspendSandboxOnExit must NOT write suspended marker when msb stop fails.
	failStopDir := filepath.Join(app.Env.DataDir, "run", "failpers")
	_ = os.MkdirAll(failStopDir, 0o700)
	runner.handler = func(req msb.CommandRequest) (msb.CommandResult, error) {
		if len(req.Args) >= 1 && req.Args[0] == "stop" {
			return msb.CommandResult{Stderr: "cannot stop", ExitCode: 1}, errors.New("stop err")
		}
		return msb.CommandResult{}, nil
	}
	stdout.Reset()
	stderr.Reset()
	app.suspendSandboxOnExit("agbox-failpers", failStopDir, config.RunMeta{Sandbox: "agbox-failpers", Persist: true})
	if hasMarker(filepath.Join(failStopDir, "suspended")) {
		t.Fatal("suspendSandboxOnExit wrote suspended marker despite msb stop failure")
	}
	if strings.Contains(stdout.String(), "Persisted ") {
		t.Errorf("unexpected success log on failed stop: %s", stdout.String())
	}
	runner.handler = nil

	// 3. reapStaleFilterDirs fails closed when msb ls fails or MSB is nil.
	staleDir := filepath.Join(app.Env.DataDir, "run", "999995")
	_ = os.MkdirAll(staleDir, 0o700)
	origMSB := app.MSB
	app.MSB = nil
	app.reapStaleFilterDirs(ctx)
	if _, err := os.Stat(staleDir); err != nil {
		t.Fatalf("reapStaleFilterDirs tore down dir when MSB == nil: %v", err)
	}
	app.MSB = origMSB
	runner.handler = func(req msb.CommandRequest) (msb.CommandResult, error) {
		if len(req.Args) >= 1 && req.Args[0] == "ls" {
			return msb.CommandResult{ExitCode: 1}, errors.New("ls failed")
		}
		return msb.CommandResult{}, nil
	}
	app.reapStaleFilterDirs(ctx)
	if _, err := os.Stat(staleDir); err != nil {
		t.Fatalf("reapStaleFilterDirs tore down dir when msb ls failed: %v", err)
	}
	runner.handler = nil
	_ = os.RemoveAll(staleDir)

	// 4. MaskAuto emits explicit WARN on fallback while MaskStrict never falls back.
	if err := config.SaveFile(app.Env.ConfigFile, config.State{
		Agent:     "opencode",
		Image:     "node:24-bookworm-slim",
		Snapshot:  "agbox:v1",
		SnapCount: 1,
	}); err != nil {
		t.Fatal(err)
	}
	projDir := filepath.Join(app.Env.HomeReal, "auto-proj")
	_ = os.MkdirAll(projDir, 0o700)
	app.Env.MaskVCS = config.MaskAuto
	origHub := app.StartHub
	app.StartHub = func(_, _, _ string, _ []vcsfuse.HubShareConfig, _ bool) (int, error) {
		return 0, errors.New("fuse unavailable")
	}
	stderr.Reset()
	if rc := app.dispatch(ctx, []string{"run", "--cmd", "true", projDir}); rc != 0 {
		t.Fatalf("expected MaskAuto fallback run to succeed, stderr=%s", stderr.String())
	}
	if !strings.Contains(stderr.String(), "[agbox] WARN:") || !strings.Contains(stderr.String(), "without VCS masking") {
		t.Errorf("expected explicit WARN on MaskAuto fallback, got %q", stderr.String())
	}
	app.StartHub = origHub
	app.Env.MaskVCS = config.MaskStrict

	// 5. OPENCODE_SERVER_PASSWORD suppresses loopback multi-user warning when set.
	app.IsTTY = func() bool { return false }
	app.Getenv = func(k string) string {
		if k == "OPENCODE_SERVER_PASSWORD" {
			return "strong-pass"
		}
		return ""
	}
	stderr.Reset()
	if rc := app.dispatch(ctx, []string{"run", "--name", "pwdsrv", "--serve", "--port", "4099"}); rc != 0 {
		t.Fatalf("detached serve with password failed: %s", stderr.String())
	}
	if strings.Contains(stderr.String(), "Set OPENCODE_SERVER_PASSWORD") {
		t.Errorf("unexpected OPENCODE_SERVER_PASSWORD warning when password is already set: %s", stderr.String())
	}
	_ = app.dispatch(ctx, []string{"stop", "agbox-pwdsrv"})
}

func TestEditBaseNoSnapCategoriesRequireBaseAndResumeM6H9(t *testing.T) {
	app, runner, _, stderr := newTestApp(t)
	ctx := context.Background()

	// 1. requireBase distinguishes missing config vs corrupt config vs snap ls failure.
	if _, err := app.requireBase(ctx); err == nil || !strings.Contains(err.Error(), "no base configured") {
		t.Fatalf("expected missing-base error, got %v", err)
	}
	if err := os.WriteFile(app.Env.ConfigFile, []byte("BAD\x00CONFIG"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Make ConfigFile a directory so LoadFile fails with non-ENOENT error.
	_ = os.Remove(app.Env.ConfigFile)
	if err := os.MkdirAll(app.Env.ConfigFile, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := app.requireBase(ctx); err == nil || strings.Contains(err.Error(), "no base configured") {
		t.Fatalf("expected LoadFile error (not missing-base), got %v", err)
	}
	_ = os.RemoveAll(app.Env.ConfigFile)

	if err := config.SaveFile(app.Env.ConfigFile, config.State{
		Agent:      "opencode",
		Image:      "node:24-bookworm-slim",
		Snapshot:   "agbox:v1",
		SnapCount:  1,
		Categories: "core",
	}); err != nil {
		t.Fatal(err)
	}
	runner.handler = func(req msb.CommandRequest) (msb.CommandResult, error) {
		if len(req.Args) >= 2 && req.Args[0] == "snap" && req.Args[1] == "ls" {
			return msb.CommandResult{Stderr: "snap backend down", ExitCode: 1}, errors.New("snap ls err")
		}
		return msb.CommandResult{}, nil
	}
	if _, err := app.requireBase(ctx); err == nil || !strings.Contains(err.Error(), "check base snapshot") {
		t.Fatalf("expected wrapped snap ls error, got %v", err)
	}
	runner.handler = nil

	// 2. editBase --no-snap does NOT persist un-snapshotted Categories into config.
	if rc := app.dispatch(ctx, []string{"edit-base", "--add", "go", "--no-snap"}); rc != 0 {
		t.Fatalf("edit-base --add go --no-snap failed: %s", stderr.String())
	}
	stAfter, err := config.LoadFile(app.Env.ConfigFile)
	if err != nil {
		t.Fatal(err)
	}
	if stAfter.Categories != "core" {
		t.Fatalf("expected Categories to stay 'core' under --no-snap, got %q", stAfter.Categories)
	}

	// 3. [H9] resumeSandbox refreshes msb ls AFTER LockProfile and detects newly active profile sandbox.
	resDir := filepath.Join(app.Env.DataDir, "run", "resprof1")
	_ = os.MkdirAll(resDir, 0o700)
	_ = config.SaveRunMeta(filepath.Join(resDir, "suspended"), config.RunMeta{
		Sandbox:      "agbox-resprof1",
		OwnerPID:     app.PID,
		Agent:        "opencode",
		Mode:         config.RunModeCmd,
		Cmd:          "true",
		Profile:      "p-race",
		MaskMode:     config.MaskStrict,
		NoSkills:     true,
		NoRules:      true,
		NoAgentCache: true,
	})
	otherDir := filepath.Join(app.Env.DataDir, "run", "otherp")
	_ = config.SaveRunMeta(filepath.Join(otherDir, "run.meta"), config.RunMeta{
		Sandbox:  "agbox-otherp",
		OwnerPID: app.PID,
		Profile:  "p-race",
	})
	lsCalls := 0
	runner.handler = func(req msb.CommandRequest) (msb.CommandResult, error) {
		if len(req.Args) >= 1 && req.Args[0] == "ls" {
			lsCalls++
			if lsCalls == 1 {
				return msb.CommandResult{Stdout: "NAME STATE\nagbox-base stopped\nagbox-resprof1 stopped\n"}, nil
			}
			return msb.CommandResult{Stdout: "NAME STATE\nagbox-base stopped\nagbox-resprof1 stopped\nagbox-otherp running\n"}, nil
		}
		return msb.CommandResult{}, nil
	}
	if rc := app.dispatch(ctx, []string{"resume", "agbox-resprof1"}); rc == 0 {
		t.Fatal("expected resumeSandbox to reject profile activated before LockProfile")
	}
	_ = os.RemoveAll(otherDir)

	// 4. [M6] resumeSandbox stops VM and unmounts FUSE if removing suspended marker fails after msb start.
	remFailDir := filepath.Join(app.Env.DataDir, "run", "remfail")
	_ = os.MkdirAll(remFailDir, 0o700)
	suspPath := filepath.Join(remFailDir, "suspended")
	_ = config.SaveRunMeta(suspPath, config.RunMeta{
		Sandbox:      "agbox-remfail",
		OwnerPID:     app.PID,
		Agent:        "opencode",
		Mode:         config.RunModeCmd,
		Cmd:          "true",
		MaskMode:     config.MaskStrict,
		NoSkills:     true,
		NoRules:      true,
		NoAgentCache: true,
	})
	runner.sandboxes = "NAME STATE\nagbox-base stopped\nagbox-remfail stopped\n"
	runner.calls = nil
	runner.handler = func(req msb.CommandRequest) (msb.CommandResult, error) {
		if len(req.Args) >= 1 && req.Args[0] == "ls" {
			return msb.CommandResult{Stdout: runner.sandboxes}, nil
		}
		if slices.Equal(req.Args, []string{"start", "agbox-remfail"}) {
			// Replace suspended file with a non-empty directory so os.Remove(suspendedPath) fails.
			_ = os.Remove(suspPath)
			_ = os.MkdirAll(filepath.Join(suspPath, "blocker"), 0o700)
			return msb.CommandResult{}, nil
		}
		return msb.CommandResult{}, nil
	}
	defer func() { _ = os.RemoveAll(suspPath) }()

	if rc := app.dispatch(ctx, []string{"resume", "agbox-remfail"}); rc == 0 {
		t.Fatal("expected resume to fail when os.Remove(suspendedPath) fails")
	}
	stoppedAfterStart := false
	for _, c := range runner.calls {
		if slices.Equal(c.Args, []string{"stop", "agbox-remfail"}) {
			stoppedAfterStart = true
		}
	}
	if !stoppedAfterStart {
		t.Fatalf("expected resume cleanup to stop agbox-remfail on suspended-marker removal failure: %v", runner.calls)
	}
}

func TestPersistAndResumeSuspendOnCtrlCOrNonZeroExit(t *testing.T) {
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

	projDir := filepath.Join(app.Env.HomeReal, "ctrlc-proj")
	if err := os.MkdirAll(projDir, 0o700); err != nil {
		t.Fatal(err)
	}

	// 1. Foreground `run --persist` with non-zero --cmd exit (or Ctrl-C) suspends instead of deleting the sandbox.
	exit130Err := exec.Command("sh", "-c", "exit 130").Run()
	if exit130Err == nil {
		t.Fatal("expected exit 130 error")
	}
	runCtx, cancelRun := context.WithCancel(ctx)
	defer cancelRun()

	runner.sandboxes = "NAME STATE\nagbox-base stopped\n"
	runner.handler = func(req msb.CommandRequest) (msb.CommandResult, error) {
		if len(req.Args) >= 1 && req.Args[0] == "ls" {
			return msb.CommandResult{Stdout: runner.sandboxes}, nil
		}
		if len(req.Args) >= 2 && req.Args[0] == "snap" && req.Args[1] == "ls" {
			return msb.CommandResult{Stdout: runner.snapshots}, nil
		}
		if len(req.Args) >= 2 && req.Args[0] == "snap" && req.Args[1] == "restore" {
			runner.sandboxes = "NAME STATE\nagbox-base stopped\nagbox-pctrl running\n"
			return msb.CommandResult{}, nil
		}
		if slices.Equal(req.Args, []string{"stop", "agbox-pctrl"}) {
			runner.sandboxes = "NAME STATE\nagbox-base stopped\nagbox-pctrl stopped\n"
			return msb.CommandResult{}, nil
		}
		if len(req.Args) >= 1 && req.Args[0] == "exec" && req.Interactive {
			cancelRun()
			return msb.CommandResult{ExitCode: 130}, exit130Err
		}
		return msb.CommandResult{}, nil
	}

	runner.calls = nil
	rc := app.dispatch(runCtx, []string{"run", "--persist", "--name", "pctrl", "--serve", projDir})
	if rc != 130 {
		t.Fatalf("expected foreground --persist --serve Ctrl-C rc=130, got %d (stderr=%s)", rc, stderr.String())
	}
	pctrlDir := filepath.Join(app.Env.DataDir, "run", "pctrl")
	if !hasMarker(filepath.Join(pctrlDir, "suspended")) {
		t.Fatal("expected foreground --persist --serve Ctrl-C to save suspended marker")
	}
	for _, c := range runner.calls {
		if slices.Equal(c.Args, []string{"rm", "-f", "agbox-pctrl"}) {
			t.Fatalf("foreground --persist Ctrl-C deleted agbox-pctrl instead of suspending: %v", runner.calls)
		}
	}

	// 2. Foreground `agbox resume` with non-zero agent exit re-saves `suspended` instead of stranding the sandbox.
	exit9Err := exec.Command("sh", "-c", "exit 9").Run()
	if exit9Err == nil {
		t.Fatal("expected exit 9 error")
	}
	app.IsTTY = func() bool { return true }
	suspMeta, err := config.LoadRunMeta(filepath.Join(pctrlDir, "suspended"))
	if err != nil {
		t.Fatal(err)
	}
	suspMeta.Mode = config.RunModeTUI
	if err := config.SaveRunMeta(filepath.Join(pctrlDir, "suspended"), suspMeta); err != nil {
		t.Fatal(err)
	}

	runner.handler = func(req msb.CommandRequest) (msb.CommandResult, error) {
		if len(req.Args) >= 1 && req.Args[0] == "ls" {
			return msb.CommandResult{Stdout: runner.sandboxes}, nil
		}
		if slices.Equal(req.Args, []string{"start", "agbox-pctrl"}) {
			runner.sandboxes = "NAME STATE\nagbox-base stopped\nagbox-pctrl running\n"
			return msb.CommandResult{}, nil
		}
		if slices.Equal(req.Args, []string{"stop", "agbox-pctrl"}) {
			runner.sandboxes = "NAME STATE\nagbox-base stopped\nagbox-pctrl stopped\n"
			return msb.CommandResult{}, nil
		}
		if len(req.Args) >= 1 && req.Args[0] == "exec" && req.Interactive {
			return msb.CommandResult{ExitCode: 9}, exit9Err
		}
		return msb.CommandResult{}, nil
	}

	rc2 := app.dispatch(ctx, []string{"resume", "agbox-pctrl"})
	if rc2 != 9 {
		t.Fatalf("expected foreground resume non-zero exit rc=9, got %d (stderr=%s)", rc2, stderr.String())
	}
	if !hasMarker(filepath.Join(pctrlDir, "suspended")) {
		t.Fatal("expected foreground resume failure to re-save suspended marker instead of stranding sandbox")
	}

	// 3. Subsequent `agbox resume` succeeds cleanly because suspended state remained valid.
	runner.handler = func(req msb.CommandRequest) (msb.CommandResult, error) {
		if len(req.Args) >= 1 && req.Args[0] == "ls" {
			return msb.CommandResult{Stdout: runner.sandboxes}, nil
		}
		if slices.Equal(req.Args, []string{"start", "agbox-pctrl"}) {
			runner.sandboxes = "NAME STATE\nagbox-base stopped\nagbox-pctrl running\n"
			return msb.CommandResult{}, nil
		}
		if slices.Equal(req.Args, []string{"stop", "agbox-pctrl"}) {
			runner.sandboxes = "NAME STATE\nagbox-base stopped\nagbox-pctrl stopped\n"
			return msb.CommandResult{}, nil
		}
		return msb.CommandResult{}, nil
	}
	if rc3 := app.dispatch(ctx, []string{"resume", "agbox-pctrl"}); rc3 != 0 {
		t.Fatalf("expected subsequent resume to succeed, got rc=%d (stderr=%s)", rc3, stderr.String())
	}
}

func TestDirectMountReadOnlySingleFileMaskAutoAndResume(t *testing.T) {
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

	roDir := filepath.Join(app.Env.HomeReal, "direct-ro-dir")
	if err := os.MkdirAll(roDir, 0o700); err != nil {
		t.Fatal(err)
	}
	singleFile := filepath.Join(app.Env.HomeReal, "direct-note.txt")
	if err := os.WriteFile(singleFile, []byte("hello\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	runner.handler = func(req msb.CommandRequest) (msb.CommandResult, error) {
		if len(req.Args) >= 1 && req.Args[0] == "ls" {
			return msb.CommandResult{Stdout: runner.sandboxes}, nil
		}
		if len(req.Args) >= 2 && req.Args[0] == "snap" && req.Args[1] == "ls" {
			return msb.CommandResult{Stdout: runner.snapshots}, nil
		}
		if len(req.Args) >= 2 && req.Args[0] == "snap" && req.Args[1] == "restore" {
			for i := 0; i+1 < len(req.Args); i++ {
				if req.Args[i] == "--name" {
					runner.sandboxes = "NAME STATE\nagbox-base stopped\n" + req.Args[i+1] + " running\n"
				}
			}
			return msb.CommandResult{}, nil
		}
		if len(req.Args) >= 2 && req.Args[0] == "stop" {
			sbx := req.Args[len(req.Args)-1]
			runner.sandboxes = "NAME STATE\nagbox-base stopped\n" + sbx + " stopped\n"
			return msb.CommandResult{}, nil
		}
		if len(req.Args) >= 2 && req.Args[0] == "start" {
			runner.sandboxes = "NAME STATE\nagbox-base stopped\n" + req.Args[1] + " running\n"
			return msb.CommandResult{}, nil
		}
		return msb.CommandResult{}, nil
	}

	// 1. `--no-mask --ro` with directory + single-file shares records VCSAllow on ro dir and VCSMask on file, and resumes cleanly.
	stderr.Reset()
	if rc := app.dispatch(ctx, []string{"run", "--persist", "--name", "nomaskro", "--no-mask", "--ro", "--cmd", "true", roDir, singleFile}); rc != 0 {
		t.Fatalf("run --persist --no-mask --ro failed: %s", stderr.String())
	}
	suspMeta, err := config.LoadRunMeta(filepath.Join(app.Env.DataDir, "run", "nomaskro", "suspended"))
	if err != nil {
		t.Fatal(err)
	}
	if len(suspMeta.Shares) != 2 {
		t.Fatalf("expected 2 share records, got %+v", suspMeta.Shares)
	}
	if suspMeta.Shares[0].VCSPolicy != config.VCSAllow {
		t.Errorf("expected VCSAllow on direct ro directory share, got %q", suspMeta.Shares[0].VCSPolicy)
	}
	if suspMeta.Shares[1].VCSPolicy != config.VCSMask {
		t.Errorf("expected VCSMask on direct single-file share, got %q", suspMeta.Shares[1].VCSPolicy)
	}
	if rc := app.dispatch(ctx, []string{"resume", "agbox-nomaskro"}); rc != 0 {
		t.Fatalf("resume of --no-mask --ro sandbox failed: %s", stderr.String())
	}
	if rc := app.dispatch(ctx, []string{"run", "--persist", "--name", "nomaskro", "--no-mask", "--ro", "--cmd", "true", roDir, singleFile}); rc != 0 {
		t.Fatalf("repeat run --persist on --no-mask --ro sandbox failed: %s", stderr.String())
	}

	// 2. `AGBOX_MASK_VCS=auto` fallback on `--ro` succeeds SaveRunMeta and resumes cleanly.
	runner.sandboxes = "NAME STATE\nagbox-base stopped\n"
	app.Env.MaskVCS = config.MaskAuto
	origHub := app.StartHub
	app.StartHub = func(_, _, _ string, _ []vcsfuse.HubShareConfig, _ bool) (int, error) {
		return 0, errors.New("fuse unavailable")
	}
	stderr.Reset()
	if rc := app.dispatch(ctx, []string{"run", "--persist", "--name", "autoro", "--ro", "--cmd", "true", roDir}); rc != 0 {
		t.Fatalf("MaskAuto fallback on --ro failed: %s", stderr.String())
	}
	if rc := app.dispatch(ctx, []string{"run", "--persist", "--name", "autoro", "--ro", "--cmd", "true", roDir}); rc != 0 {
		t.Fatalf("repeat MaskAuto fallback run --persist --ro failed: %s", stderr.String())
	}
	app.StartHub = origHub
	app.Env.MaskVCS = config.MaskStrict
}

func TestSingleRootWarningAcrossAuthUpdateAndPersistResume(t *testing.T) {
	app, runner, _, stderr := newTestApp(t)
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

	// 1. `auth --allow-root` emits exactly one root-mode warning.
	b64Cred := "eyJ0b2tlbiI6Im9rIn0="
	runner.handler = func(req msb.CommandRequest) (msb.CommandResult, error) {
		if len(req.Args) >= 1 && req.Args[0] == "ls" {
			return msb.CommandResult{Stdout: runner.sandboxes}, nil
		}
		if len(req.Args) >= 2 && req.Args[0] == "snap" && req.Args[1] == "ls" {
			return msb.CommandResult{Stdout: runner.snapshots}, nil
		}
		if strings.Contains(strings.Join(req.Args, " "), "FILE opencode") {
			return msb.CommandResult{Stdout: "FILE opencode auth.json " + b64Cred + "\n"}, nil
		}
		return msb.CommandResult{}, nil
	}
	stderr.Reset()
	if rc := app.dispatch(ctx, []string{"--allow-root", "auth", "opencode"}); rc != 0 {
		t.Fatalf("auth --allow-root failed: %s", stderr.String())
	}
	if got := strings.Count(stderr.String(), "Root mode is active"); got != 1 {
		t.Errorf("auth --allow-root emitted %d root warnings, want 1: %s", got, stderr.String())
	}

	// 2. `update --allow-root` emits exactly one root-mode warning.
	fakeELF := append([]byte{0x7f, 'E', 'L', 'F'}, bytes.Repeat([]byte{0x11}, 128)...)
	runner.handler = func(req msb.CommandRequest) (msb.CommandResult, error) {
		if len(req.Args) >= 1 && req.Args[0] == "ls" {
			return msb.CommandResult{Stdout: runner.sandboxes}, nil
		}
		if len(req.Args) >= 2 && req.Args[0] == "snap" && req.Args[1] == "ls" {
			return msb.CommandResult{Stdout: runner.snapshots}, nil
		}
		joined := strings.Join(req.Args, " ")
		if strings.Contains(joined, "opencode-version.txt") && !strings.Contains(joined, "npm install") {
			return msb.CommandResult{Stdout: "1.9.9\n"}, nil
		}
		if strings.Contains(joined, "opencode-binpath.txt") && req.Stdout != nil {
			_, _ = req.Stdout.Write(fakeELF)
			return msb.CommandResult{}, nil
		}
		return msb.CommandResult{}, nil
	}
	stderr.Reset()
	if rc := app.dispatch(ctx, []string{"--allow-root", "update", "opencode"}); rc != 0 {
		t.Fatalf("update --allow-root failed: %s", stderr.String())
	}
	if got := strings.Count(stderr.String(), "Root mode is active"); got != 1 {
		t.Errorf("update --allow-root emitted %d root warnings, want 1: %s", got, stderr.String())
	}

	// 3. `run --allow-root --persist` resuming an existing suspended sandbox emits exactly one root-mode warning.
	runner.handler = func(req msb.CommandRequest) (msb.CommandResult, error) {
		if len(req.Args) >= 1 && req.Args[0] == "ls" {
			return msb.CommandResult{Stdout: runner.sandboxes}, nil
		}
		if len(req.Args) >= 2 && req.Args[0] == "snap" && req.Args[1] == "ls" {
			return msb.CommandResult{Stdout: runner.snapshots}, nil
		}
		if len(req.Args) >= 2 && req.Args[0] == "snap" && req.Args[1] == "restore" {
			runner.sandboxes = "NAME STATE\nagbox-base stopped\nagbox-rootp running\n"
			return msb.CommandResult{}, nil
		}
		if slices.Equal(req.Args, []string{"stop", "agbox-rootp"}) {
			runner.sandboxes = "NAME STATE\nagbox-base stopped\nagbox-rootp stopped\n"
			return msb.CommandResult{}, nil
		}
		if slices.Equal(req.Args, []string{"start", "agbox-rootp"}) {
			runner.sandboxes = "NAME STATE\nagbox-base stopped\nagbox-rootp running\n"
			return msb.CommandResult{}, nil
		}
		return msb.CommandResult{}, nil
	}
	if rc := app.dispatch(ctx, []string{"--allow-root", "run", "--persist", "--name", "rootp", "--cmd", "true"}); rc != 0 {
		t.Fatalf("initial run --allow-root --persist failed: %s", stderr.String())
	}
	stderr.Reset()
	if rc := app.dispatch(ctx, []string{"--allow-root", "run", "--persist", "--name", "rootp", "--cmd", "true"}); rc != 0 {
		t.Fatalf("resume via run --allow-root --persist failed: %s", stderr.String())
	}
	if got := strings.Count(stderr.String(), "Root mode is active"); got != 1 {
		t.Errorf("run --allow-root --persist resume emitted %d root warnings, want 1: %s", got, stderr.String())
	}
}
