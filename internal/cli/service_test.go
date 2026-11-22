package cli

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"agbox/internal/config"
	"agbox/internal/msb"
	"agbox/internal/service"
	"agbox/internal/vcsfuse"
)

type serviceFakeRunner struct {
	fn func(ctx context.Context, req msb.CommandRequest) (msb.CommandResult, error)
}

func (r *serviceFakeRunner) Run(ctx context.Context, req msb.CommandRequest) (msb.CommandResult, error) {
	if r.fn != nil {
		return r.fn(ctx, req)
	}
	return msb.CommandResult{}, nil
}

type fakeServiceCtl struct {
	mu            sync.Mutex
	calls         []string
	lingerEnabled bool
	lingerErr     error
	states        map[string]service.UnitState
	logsOutput    string
}

func (f *fakeServiceCtl) record(call string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, call)
}

func (f *fakeServiceCtl) DaemonReload(_ context.Context) error {
	f.record("daemon-reload")
	return nil
}

func (f *fakeServiceCtl) Enable(_ context.Context, unit string, now bool) error {
	if now {
		f.record("enable --now " + unit)
	} else {
		f.record("enable " + unit)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.states == nil {
		f.states = make(map[string]service.UnitState)
	}
	st := f.states[unit]
	st.UnitFile = "enabled"
	if now {
		st.ActiveState = "active"
		st.SubState = "running"
	}
	f.states[unit] = st
	return nil
}

func (f *fakeServiceCtl) Disable(_ context.Context, unit string, now bool) error {
	if now {
		f.record("disable --now " + unit)
	} else {
		f.record("disable " + unit)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.states == nil {
		f.states = make(map[string]service.UnitState)
	}
	st := f.states[unit]
	st.UnitFile = "disabled"
	if now {
		st.ActiveState = "inactive"
		st.SubState = "dead"
	}
	f.states[unit] = st
	return nil
}

func (f *fakeServiceCtl) Start(_ context.Context, unit string) error {
	f.record("start " + unit)
	return nil
}

func (f *fakeServiceCtl) Stop(_ context.Context, unit string) error {
	f.record("stop " + unit)
	return nil
}

func (f *fakeServiceCtl) Restart(_ context.Context, unit string) error {
	f.record("restart " + unit)
	return nil
}

func (f *fakeServiceCtl) Status(_ context.Context, unit string) (service.UnitState, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if st, ok := f.states[unit]; ok {
		return st, nil
	}
	return service.UnitState{ActiveState: "inactive", SubState: "dead", UnitFile: "disabled"}, nil
}

func (f *fakeServiceCtl) Logs(_ context.Context, unit string, follow bool, lines int, stdout, _ io.Writer) error {
	f.record("logs " + unit)
	_, _ = io.WriteString(stdout, f.logsOutput)
	return nil
}

func (f *fakeServiceCtl) LingerEnabled(_ context.Context, _ string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.lingerEnabled, nil
}

func (f *fakeServiceCtl) EnableLinger(_ context.Context, user string) error {
	f.record("enable-linger " + user)
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.lingerErr != nil {
		return f.lingerErr
	}
	f.lingerEnabled = true
	return nil
}

func newServiceTestApp(t *testing.T, svcCtl *fakeServiceCtl, fakeMSB msb.Runner) (*appRuntime, *bytes.Buffer, *bytes.Buffer, string) {
	t.Helper()
	home := t.TempDir()
	dataDir := filepath.Join(home, ".local", "share", "agbox")
	msbHome := filepath.Join(home, ".microsandbox")
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := config.SaveFile(filepath.Join(dataDir, "config"), config.State{
		Agent:    "both",
		Image:    "debian:bookworm",
		Snapshot: "agbox:v1",
	}); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	app := &appRuntime{
		Env: config.Env{
			HomeReal:   home,
			DataDir:    dataDir,
			ConfigFile: filepath.Join(dataDir, "config"),
			MSBHome:    msbHome,
			CPUs:       "2",
			Memory:     "4G",
			MaskVCS:    config.MaskStrict,
		},
		ExePath:             filepath.Join(home, ".local", "bin", "agbox"),
		MSB:                 fakeMSB,
		MountCtl:            noopMountCtl{},
		ServiceCtl:          svcCtl,
		ServicePollInterval: 10 * time.Millisecond,
		CurrentUser:         func() (string, error) { return "alice", nil },
		Stdin:               strings.NewReader(""),
		Stdout:              &stdout,
		Stderr:              &stderr,
		Getenv:              func(string) string { return "" },
		IsTTY:               func() bool { return false },
		GetEUID:             func() int { return 1000 },
		GetEGID:             func() int { return 1000 },
		CheckKVM:            func() error { return nil },
		CheckFUSE:           func() error { return nil },
		PID:                 4242,
		StartHub: func(mntDir, sockPath, pidFile string, initial []vcsfuse.HubShareConfig, dieWithParent bool) (int, error) {
			return 9999, nil
		},
	}
	return app, &stdout, &stderr, home
}

func TestServiceLifecycleAndLinger(t *testing.T) {
	t.Parallel()

	svcCtl := &fakeServiceCtl{}
	app, stdout, stderr, home := newServiceTestApp(t, svcCtl, &serviceFakeRunner{})

	projDir := filepath.Join(home, "proj")
	if err := os.MkdirAll(projDir, 0o755); err != nil {
		t.Fatal(err)
	}
	envFile := filepath.Join(home, "svc.env")
	if err := os.WriteFile(envFile, []byte("OPENCODE_SERVER_PASSWORD=secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Add a persistent --serve service with --enable --now.
	code := app.dispatch(context.Background(), []string{
		"service", "add", "--enable", "--now", "--env-file", envFile,
		"web", "--persist", "--serve", "--port", "4096", projDir,
	})
	if code != 0 {
		t.Fatalf("service add failed (code=%d): stderr=%s", code, stderr.String())
	}

	unitPath, err := service.TemplateUnitPath(home, "")
	if err != nil {
		t.Fatal(err)
	}
	unitBytes, err := os.ReadFile(unitPath)
	if err != nil {
		t.Fatalf("expected template unit at %s: %v", unitPath, err)
	}
	unitText := string(unitBytes)
	if strings.Contains(unitText, "secret") || strings.Contains(unitText, "OPENCODE_SERVER_PASSWORD") {
		t.Fatalf("template unit must never contain secrets:\n%s", unitText)
	}
	if !strings.Contains(unitText, "KillMode=mixed") || !strings.Contains(unitText, "WantedBy=default.target") || !strings.Contains(unitText, "Type=notify") || !strings.Contains(unitText, "WatchdogSec=90s") {
		t.Fatalf("unexpected template unit content:\n%s", unitText)
	}
	if !svcCtl.lingerEnabled {
		t.Fatal("expected linger to be enabled automatically on service enable")
	}

	// Duplicate add without --force must fail.
	stderr.Reset()
	code = app.dispatch(context.Background(), []string{
		"service", "add", "web", "--remote-control",
	})
	if code == 0 || !strings.Contains(stderr.String(), "already exists") {
		t.Fatalf("duplicate add = (code=%d, stderr=%q), want already exists error", code, stderr.String())
	}

	// List shows linger enabled and service status.
	stdout.Reset()
	code = app.dispatch(context.Background(), []string{"service", "list"})
	if code != 0 {
		t.Fatalf("service list failed: %s", stderr.String())
	}
	if !strings.Contains(stdout.String(), "linger: enabled (alice)") || !strings.Contains(stdout.String(), "web") || !strings.Contains(stdout.String(), "serve 127.0.0.1:4096") {
		t.Fatalf("unexpected list output:\n%s", stdout.String())
	}

	// Control commands: start, stop, restart, logs, disable.
	svcCtl.logsOutput = "hello from journal\n"
	for _, args := range [][]string{
		{"service", "start", "web"},
		{"service", "restart", "web"},
		{"service", "stop", "web"},
		{"service", "logs", "-n", "20", "web"},
		{"service", "disable", "--now", "web"},
		{"service", "linger", "status"},
	} {
		stdout.Reset()
		stderr.Reset()
		if c := app.dispatch(context.Background(), args); c != 0 {
			t.Fatalf("%v failed (code=%d): %s", args, c, stderr.String())
		}
	}

	// Remove deletes spec and removes template unit when last service is removed.
	if c := app.dispatch(context.Background(), []string{"service", "rm", "web"}); c != 0 {
		t.Fatalf("service rm failed: %s", stderr.String())
	}
	if _, err := os.Lstat(unitPath); !os.IsNotExist(err) {
		t.Fatalf("expected template unit to be removed when zero services remain: %v", err)
	}
}

func TestServiceAddValidationErrors(t *testing.T) {
	t.Parallel()

	svcCtl := &fakeServiceCtl{}
	app, _, stderr, home := newServiceTestApp(t, svcCtl, &serviceFakeRunner{})

	badEnv := filepath.Join(home, "bad.env")
	if err := os.WriteFile(badEnv, []byte("FOO=bar\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(badEnv, 0o644); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name    string
		args    []string
		wantErr string
	}{
		{
			name:    "tui mode rejected",
			args:    []string{"service", "add", "mybox", "opencode"},
			wantErr: "headless mode",
		},
		{
			name:    "serve without fixed port rejected",
			args:    []string{"service", "add", "mybox", "--serve"},
			wantErr: "fixed --port",
		},
		{
			name:    "detach rejected",
			args:    []string{"service", "add", "mybox", "-d", "--remote-control"},
			wantErr: "do not pass --detach",
		},
		{
			name:    "name flag rejected",
			args:    []string{"service", "add", "mybox", "--name", "other", "--remote-control"},
			wantErr: "do not pass --name",
		},
		{
			name:    "insecure env file rejected",
			args:    []string{"service", "add", "--env-file", badEnv, "mybox", "--remote-control"},
			wantErr: "insecure permissions",
		},
	}

	for _, tc := range cases {
		stderr.Reset()
		code := app.dispatch(context.Background(), tc.args)
		if code == 0 || !strings.Contains(stderr.String(), tc.wantErr) {
			t.Errorf("%s: code=%d stderr=%q, want substring %q", tc.name, code, stderr.String(), tc.wantErr)
		}
	}
}

func TestServiceRunSupervisedRemoteControlAndShutdown(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var mu sync.Mutex
	var calls [][]string
	var streamedKeys string
	pingCount := 0

	fakeMSB := &serviceFakeRunner{
		fn: func(runCtx context.Context, req msb.CommandRequest) (msb.CommandResult, error) {
			mu.Lock()
			calls = append(calls, append([]string(nil), req.Args...))
			mu.Unlock()

			if len(req.Args) == 0 {
				return msb.CommandResult{}, nil
			}
			switch req.Args[0] {
			case "snap":
				return msb.CommandResult{Stdout: "agbox:v1\n"}, nil
			case "ls":
				return msb.CommandResult{Stdout: "NAME STATUS\n"}, nil
			case "exec":
				if req.Stdin != nil && strings.Contains(strings.Join(req.Args, " "), ".agbox-keys.sh") {
					b, _ := io.ReadAll(req.Stdin)
					mu.Lock()
					streamedKeys = string(b)
					mu.Unlock()
				}
				return msb.CommandResult{}, nil
			case "ping":
				mu.Lock()
				pingCount++
				n := pingCount
				mu.Unlock()
				if n >= 2 {
					// Simulate systemd SIGTERM after two healthy polls.
					cancel()
				}
				return msb.CommandResult{}, nil
			default:
				return msb.CommandResult{}, nil
			}
		},
	}

	svcCtl := &fakeServiceCtl{}
	app, _, stderr, home := newServiceTestApp(t, svcCtl, fakeMSB)

	envFile := filepath.Join(home, "keys.env")
	if err := os.WriteFile(envFile, []byte("GEMINI_API_KEY=test-secret-key\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := service.SaveSpec(app.Env.DataDir, service.Spec{
		Name:    "rcwork",
		Agent:   "antigravity",
		Mode:    config.RunModeRemoteControl,
		Persist: true,
		EnvFile: envFile,
	}); err != nil {
		t.Fatal(err)
	}

	code := app.dispatch(ctx, []string{service.SubcommandName, "rcwork"})
	if code != 0 {
		t.Fatalf("__service-run exited %d: %s", code, stderr.String())
	}

	if !strings.Contains(streamedKeys, "GEMINI_API_KEY") || !strings.Contains(streamedKeys, "test-secret-key") {
		t.Fatalf("expected env file secret to be streamed to pushKeys, got: %q", streamedKeys)
	}

	// Persistent service should suspend cleanly on SIGTERM.
	suspPath := filepath.Join(app.Env.DataDir, "run", "rcwork", "suspended")
	if !hasMarker(suspPath) {
		t.Fatalf("expected suspended marker at %s after clean SIGTERM", suspPath)
	}
}

func TestServiceRunDetectsRemoteControlCrash(t *testing.T) {
	t.Parallel()

	fakeMSB := &serviceFakeRunner{
		fn: func(_ context.Context, req msb.CommandRequest) (msb.CommandResult, error) {
			if len(req.Args) == 0 {
				return msb.CommandResult{}, nil
			}
			switch req.Args[0] {
			case "snap":
				return msb.CommandResult{Stdout: "agbox:v1\n"}, nil
			case "ls":
				return msb.CommandResult{Stdout: "NAME STATUS\n"}, nil
			case "ping":
				return msb.CommandResult{Stderr: "sandbox not running"}, errors.New("exit status 1")
			default:
				return msb.CommandResult{}, nil
			}
		},
	}

	app, _, stderr, _ := newServiceTestApp(t, &fakeServiceCtl{}, fakeMSB)
	if err := service.SaveSpec(app.Env.DataDir, service.Spec{
		Name:  "ephemeralrc",
		Agent: "antigravity",
		Mode:  config.RunModeRemoteControl,
	}); err != nil {
		t.Fatal(err)
	}

	code := app.dispatch(context.Background(), []string{service.SubcommandName, "ephemeralrc"})
	if code == 0 {
		t.Fatal("expected non-zero exit when sandbox ping fails so systemd restarts the service")
	}
	if !strings.Contains(stderr.String(), "health check failed") {
		t.Fatalf("unexpected stderr: %s", stderr.String())
	}
}

func TestServiceRunRecoversStalePersistSandboxAfterReboot(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var startedSandbox bool
	fakeMSB := &serviceFakeRunner{
		fn: func(_ context.Context, req msb.CommandRequest) (msb.CommandResult, error) {
			if len(req.Args) == 0 {
				return msb.CommandResult{}, nil
			}
			switch req.Args[0] {
			case "snap":
				return msb.CommandResult{Stdout: "agbox:v1\n"}, nil
			case "ls":
				return msb.CommandResult{Stdout: "NAME STATUS\nagbox-rebooted stopped\n"}, nil
			case "start":
				startedSandbox = true
				return msb.CommandResult{}, nil
			case "ping":
				cancel()
				return msb.CommandResult{}, nil
			default:
				return msb.CommandResult{}, nil
			}
		},
	}

	app, _, stderr, _ := newServiceTestApp(t, &fakeServiceCtl{}, fakeMSB)
	if err := service.SaveSpec(app.Env.DataDir, service.Spec{
		Name:    "rebooted",
		Agent:   "antigravity",
		Mode:    config.RunModeRemoteControl,
		Persist: true,
	}); err != nil {
		t.Fatal(err)
	}

	// Simulate dirty host reboot: run.meta + detached marker exist, no suspended marker.
	runDir := filepath.Join(app.Env.DataDir, "run", "rebooted")
	if err := os.MkdirAll(runDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := config.SaveRunMeta(filepath.Join(runDir, "run.meta"), config.RunMeta{
		Sandbox:       "agbox-rebooted",
		Agent:         "antigravity",
		Mode:          config.RunModeRemoteControl,
		MaskMode:      config.MaskStrict,
		Persist:       true,
		RemoteControl: true,
	}); err != nil {
		t.Fatal(err)
	}
	if err := writeMarkerAtomic(filepath.Join(runDir, "detached"), "1234\n"); err != nil {
		t.Fatal(err)
	}

	code := app.dispatch(ctx, []string{service.SubcommandName, "rebooted"})
	if code != 0 {
		t.Fatalf("__service-run recovery failed (code=%d): %s", code, stderr.String())
	}
	if !startedSandbox {
		t.Fatal("expected recovered persistent sandbox to be resumed via 'msb start'")
	}
}

func TestRemoveCleansUpManagedServices(t *testing.T) {
	t.Parallel()

	svcCtl := &fakeServiceCtl{}
	app, _, stderr, home := newServiceTestApp(t, svcCtl, &serviceFakeRunner{})

	if err := service.SaveSpec(app.Env.DataDir, service.Spec{
		Name:  "bg",
		Agent: "antigravity",
		Mode:  config.RunModeRemoteControl,
	}); err != nil {
		t.Fatal(err)
	}
	unitPath, err := app.ensureTemplateUnitInstalled(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	code := app.dispatch(context.Background(), []string{"remove", "--yes"})
	if code != 0 {
		t.Fatalf("remove --yes failed: %s", stderr.String())
	}
	if _, err := os.Lstat(unitPath); !os.IsNotExist(err) {
		t.Fatalf("expected agbox@.service to be removed by 'agbox remove --yes': %v", err)
	}
	_ = home
}

func TestServiceRunRemoteControlStatusUnhealthyTriggersRestart(t *testing.T) {
	t.Parallel()

	var mu sync.Mutex
	var notifyEvents []string
	statusCalls := 0

	fakeMSB := &serviceFakeRunner{
		fn: func(_ context.Context, req msb.CommandRequest) (msb.CommandResult, error) {
			if len(req.Args) == 0 {
				return msb.CommandResult{}, nil
			}
			switch req.Args[0] {
			case "snap":
				return msb.CommandResult{Stdout: "agbox:v1\n"}, nil
			case "ls":
				return msb.CommandResult{Stdout: "NAME STATUS\n"}, nil
			case "ping":
				// VM itself is still alive, but agy remote-control inside dies.
				return msb.CommandResult{}, nil
			case "exec":
				joined := strings.Join(req.Args, " ")
				if strings.Contains(joined, "agy remote-control status") {
					mu.Lock()
					statusCalls++
					n := statusCalls
					mu.Unlock()
					if n == 1 {
						return msb.CommandResult{Stdout: "Remote Control running\n"}, nil
					}
					return msb.CommandResult{Stdout: "Remote Control is not running\n"}, nil
				}
				return msb.CommandResult{}, nil
			default:
				return msb.CommandResult{}, nil
			}
		},
	}

	app, _, stderr, _ := newServiceTestApp(t, &fakeServiceCtl{}, fakeMSB)
	app.ServiceFailThreshold = 2
	app.NotifySystemd = func(state string) {
		mu.Lock()
		notifyEvents = append(notifyEvents, state)
		mu.Unlock()
	}

	if err := service.SaveSpec(app.Env.DataDir, service.Spec{
		Name:  "rcunhealthy",
		Agent: "antigravity",
		Mode:  config.RunModeRemoteControl,
	}); err != nil {
		t.Fatal(err)
	}

	code := app.dispatch(context.Background(), []string{service.SubcommandName, "rcunhealthy"})
	if code == 0 {
		t.Fatal("expected non-zero exit when agy remote-control status reports not running")
	}
	if !strings.Contains(stderr.String(), "2 consecutive times") {
		t.Fatalf("unexpected stderr: %s", stderr.String())
	}

	mu.Lock()
	events := append([]string(nil), notifyEvents...)
	mu.Unlock()
	joinedEvents := strings.Join(events, ",")
	if !strings.Contains(joinedEvents, "READY=1") || !strings.Contains(joinedEvents, "WATCHDOG=1") || !strings.Contains(joinedEvents, "STOPPING=1") {
		t.Fatalf("expected READY=1, WATCHDOG=1, STOPPING=1 notifications, got: %v", events)
	}
}

func TestServiceRunServeHungHealthCheckTriggersRestart(t *testing.T) {
	t.Parallel()

	var mu sync.Mutex
	var notifyEvents []string
	probeCalls := 0

	fakeMSB := &serviceFakeRunner{
		fn: func(runCtx context.Context, req msb.CommandRequest) (msb.CommandResult, error) {
			if len(req.Args) == 0 {
				return msb.CommandResult{}, nil
			}
			switch req.Args[0] {
			case "snap":
				return msb.CommandResult{Stdout: "agbox:v1\n"}, nil
			case "ls":
				return msb.CommandResult{Stdout: "NAME STATUS\n"}, nil
			case "exec":
				joined := strings.Join(req.Args, " ")
				if strings.Contains(joined, "opencode serve") {
					// Simulate a hung opencode serve process that only exits when cancelled.
					<-runCtx.Done()
					return msb.CommandResult{}, runCtx.Err()
				}
				return msb.CommandResult{}, nil
			default:
				return msb.CommandResult{}, nil
			}
		},
	}

	app, _, stderr, _ := newServiceTestApp(t, &fakeServiceCtl{}, fakeMSB)
	app.ServiceFailThreshold = 2
	app.WaitServeUI = func(_ context.Context, _ int, _ string) bool {
		return true
	}
	app.ProbeServeUI = func(_ context.Context, _ int) bool {
		mu.Lock()
		probeCalls++
		n := probeCalls
		mu.Unlock()
		// Healthy on first poll, then hangs on subsequent polls.
		return n == 1
	}
	app.NotifySystemd = func(state string) {
		mu.Lock()
		notifyEvents = append(notifyEvents, state)
		mu.Unlock()
	}

	if err := service.SaveSpec(app.Env.DataDir, service.Spec{
		Name:  "hungweb",
		Agent: "opencode",
		Mode:  config.RunModeServe,
		Port:  4096,
	}); err != nil {
		t.Fatal(err)
	}

	code := app.dispatch(context.Background(), []string{service.SubcommandName, "hungweb"})
	if code == 0 {
		t.Fatal("expected non-zero exit when opencode serve fails consecutive HTTP health checks")
	}
	if !strings.Contains(stderr.String(), "opencode serve health check failed 2 consecutive times") {
		t.Fatalf("unexpected stderr: %s", stderr.String())
	}

	mu.Lock()
	events := append([]string(nil), notifyEvents...)
	mu.Unlock()
	joinedEvents := strings.Join(events, ",")
	if !strings.Contains(joinedEvents, "READY=1") || !strings.Contains(joinedEvents, "WATCHDOG=1") || !strings.Contains(joinedEvents, "STOPPING=1") {
		t.Fatalf("expected READY=1, WATCHDOG=1, STOPPING=1 notifications, got: %v", events)
	}
}
