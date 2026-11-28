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
	disableErr    error
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
	if f.disableErr != nil {
		return f.disableErr
	}
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
			HomeReal:      home,
			DataDir:       dataDir,
			ConfigFile:    filepath.Join(dataDir, "config"),
			MSBHome:       msbHome,
			CPUs:          "2",
			Memory:        "4G",
			MaskVCS:       config.MaskStrict,
			RemoteDefault: true,
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
		StartRemoteBridge: func(mntDir, sockPath, pidFile string, dieWithParent bool) (int, error) {
			_ = os.MkdirAll(mntDir, 0o700)
			_ = os.WriteFile(pidFile, []byte("9997\n"), 0o600)
			return 9997, nil
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

func TestServiceAddVCSAndSingleFileAndNoMaskRoundTrip(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var mu sync.Mutex
	var hubInitial []vcsfuse.HubShareConfig
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
				cancel()
				return msb.CommandResult{}, nil
			default:
				return msb.CommandResult{}, nil
			}
		},
	}

	app, _, stderr, home := newServiceTestApp(t, &fakeServiceCtl{}, fakeMSB)
	app.StartHub = func(_, _, _ string, initial []vcsfuse.HubShareConfig, _ bool) (int, error) {
		mu.Lock()
		hubInitial = append([]vcsfuse.HubShareConfig(nil), initial...)
		mu.Unlock()
		return 9999, nil
	}

	dirPath := filepath.Join(home, "repo")
	if err := os.MkdirAll(dirPath, 0o755); err != nil {
		t.Fatal(err)
	}
	filePath := filepath.Join(home, "notes.txt")
	if err := os.WriteFile(filePath, []byte("hello\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// 1. --vcs with both a directory and a single file must save LockAccess=false, LockVCS=false,
	// omit VCS modifier on the file, and round-trip through __service-run without conflict.
	if code := app.dispatch(context.Background(), []string{
		"service", "add", "vcsfile", "--vcs", "--remote-control", dirPath, filePath,
	}); code != 0 {
		t.Fatalf("service add --vcs dir+file failed (code=%d): %s", code, stderr.String())
	}
	spec, err := service.LoadSpec(app.Env.DataDir, "vcsfile")
	if err != nil {
		t.Fatalf("LoadSpec(vcsfile): %v", err)
	}
	if spec.LockAccess || spec.LockVCS {
		t.Fatalf("expected LockAccess=false and LockVCS=false, got LockAccess=%v LockVCS=%v", spec.LockAccess, spec.LockVCS)
	}
	if len(spec.Shares) != 2 {
		t.Fatalf("expected 2 canonical shares, got %v", spec.Shares)
	}
	if !strings.Contains(spec.Shares[0], ":rw,vcs,as=repo") {
		t.Fatalf("expected dir share with vcs modifier, got %q", spec.Shares[0])
	}
	if !strings.HasSuffix(spec.Shares[1], ":rw,as=notes.txt") {
		t.Fatalf("expected file share without vcs modifier, got %q", spec.Shares[1])
	}

	stderr.Reset()
	if code := app.dispatch(ctx, []string{service.SubcommandName, "vcsfile"}); code != 0 {
		t.Fatalf("__service-run vcsfile failed (code=%d): %s", code, stderr.String())
	}
	mu.Lock()
	gotHub := append([]vcsfuse.HubShareConfig(nil), hubInitial...)
	mu.Unlock()
	if len(gotHub) != 2 || gotHub[0].VCSPolicy != config.VCSAllow || gotHub[1].VCSPolicy != config.VCSMask {
		t.Fatalf("unexpected hub initial configs after round-trip: %+v", gotHub)
	}

	// 2. --no-mask omits VCS modifiers in canonicalShares and round-trips cleanly.
	ctx2, cancel2 := context.WithCancel(context.Background())
	defer cancel2()
	app2, _, stderr2, home2 := newServiceTestApp(t, &fakeServiceCtl{}, &serviceFakeRunner{
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
				cancel2()
				return msb.CommandResult{}, nil
			default:
				return msb.CommandResult{}, nil
			}
		},
	})
	dir2 := filepath.Join(home2, "plain")
	if err := os.MkdirAll(dir2, 0o755); err != nil {
		t.Fatal(err)
	}
	if code := app2.dispatch(context.Background(), []string{
		"service", "add", "nomasksvc", "--no-mask", "--remote-control", dir2,
	}); code != 0 {
		t.Fatalf("service add --no-mask failed: %s", stderr2.String())
	}
	spec2, err := service.LoadSpec(app2.Env.DataDir, "nomasksvc")
	if err != nil {
		t.Fatal(err)
	}
	if len(spec2.Shares) != 1 || !strings.HasSuffix(spec2.Shares[0], ":rw,as=plain") {
		t.Fatalf("expected --no-mask share without vcs modifier, got %v", spec2.Shares)
	}
	if code := app2.dispatch(ctx2, []string{service.SubcommandName, "nomasksvc"}); code != 0 {
		t.Fatalf("__service-run nomasksvc failed: %s", stderr2.String())
	}
}

func TestServiceAddNetValidationUnitOrderAndFlagParsing(t *testing.T) {
	t.Parallel()

	// 1. Early network validation rejects conflicts and invalid rules before saving any spec.
	app, _, stderr, _ := newServiceTestApp(t, &fakeServiceCtl{}, &serviceFakeRunner{})
	for _, tc := range []struct {
		name string
		args []string
	}{
		{"no-net with public", []string{"service", "add", "badnet1", "--no-net", "--net", "public", "--remote-control"}},
		{"invalid CIDR", []string{"service", "add", "badnet2", "--net", "allow@10.0.0.1/24", "--remote-control"}},
	} {
		stderr.Reset()
		if code := app.dispatch(context.Background(), tc.args); code == 0 {
			t.Fatalf("%s: expected non-zero exit", tc.name)
		}
		if _, err := os.Lstat(service.SpecPath(app.Env.DataDir, tc.args[2])); !os.IsNotExist(err) {
			t.Fatalf("%s: expected zero spec created on validation failure", tc.name)
		}
	}

	// 2. Unit installation failure leaves zero orphaned spec on disk.
	appBadUnit, _, stderrBad, _ := newServiceTestApp(t, &fakeServiceCtl{}, &serviceFakeRunner{})
	appBadUnit.ExePath = "relative/agbox"
	if code := appBadUnit.dispatch(context.Background(), []string{"service", "add", "orphancheck", "--remote-control"}); code == 0 {
		t.Fatal("expected service add to fail when template unit render fails")
	}
	if !strings.Contains(stderrBad.String(), "must be absolute") {
		t.Fatalf("unexpected error: %s", stderrBad.String())
	}
	if _, err := os.Lstat(service.SpecPath(appBadUnit.Env.DataDir, "orphancheck")); !os.IsNotExist(err) {
		t.Fatalf("expected no orphaned spec after failed template unit install: %v", err)
	}

	// 3. parseServiceAddArgs must not strip service flags inside value-taking run flags or after paths.
	opts, err := parseServiceArgs([]string{"add", "cmdbox", "--cmd", "--force"})
	if err != nil {
		t.Fatalf("parseServiceArgs(--cmd --force): %v", err)
	}
	if opts.Force {
		t.Fatal("parseServiceAddArgs stripped --force from --cmd value")
	}
	if strings.Join(opts.RunArgs, " ") != "--cmd --force" {
		t.Fatalf("RunArgs = %v, want [--cmd --force]", opts.RunArgs)
	}

	opts, err = parseServiceArgs([]string{"add", "pathbox", "--remote-control", "/tmp/proj", "--force"})
	if err != nil {
		t.Fatalf("parseServiceArgs(after path): %v", err)
	}
	if opts.Force {
		t.Fatal("parseServiceAddArgs stripped --force after positional path")
	}
	if strings.Join(opts.RunArgs, " ") != "--remote-control /tmp/proj --force" {
		t.Fatalf("RunArgs after path = %v", opts.RunArgs)
	}

	// 4. Duplicate --env-file and duplicate --lines are rejected.
	if _, err := parseServiceArgs([]string{"add", "--env-file", "/a", "dupbox", "--env-file", "/b", "--remote-control"}); err == nil || !strings.Contains(err.Error(), "duplicate --env-file") {
		t.Fatalf("expected duplicate --env-file error, got %v", err)
	}
	if _, err := parseServiceArgs([]string{"logs", "-n", "10", "--lines", "20", "dupbox"}); err == nil || !strings.Contains(err.Error(), "duplicate --lines") {
		t.Fatalf("expected duplicate --lines error, got %v", err)
	}

	// 5. parseServiceArgs edge cases and service --help (serviceUsageText).
	for _, bad := range [][]string{
		{"bogus"},
		{"list", "--bogus"},
		{"enable"},
		{"enable", "--bogus", "web"},
		{"disable"},
		{"disable", "--bogus", "web"},
		{"start"},
		{"start", "--bogus", "web"},
		{"logs"},
		{"logs", "-n", "0", "web"},
		{"logs", "--bogus", "web"},
		{"rm"},
		{"rm", "--bogus", "web"},
		{"linger", "bogus"},
		{"linger", "--bogus"},
		{"add"},
		{"add", "--bogus", "web"},
	} {
		if _, err := parseServiceArgs(bad); err == nil {
			t.Errorf("parseServiceArgs(%v) succeeded, want error", bad)
		}
	}
	var stdout bytes.Buffer
	app.Stdout = &stdout
	if code := app.dispatch(context.Background(), []string{"service", "--help"}); code != 0 {
		t.Fatalf("service --help exited %d", code)
	}
	if !strings.Contains(stdout.String(), "agbox service") || !strings.Contains(stdout.String(), "user linger in systemd-logind") {
		t.Fatalf("unexpected service --help output:\n%s", stdout.String())
	}
}

func TestServiceRemoveDisableErrorKeepTemplateLingerAndRootPropagation(t *testing.T) {
	t.Parallel()

	svcCtl := &fakeServiceCtl{}
	app, stdout, stderr, home := newServiceTestApp(t, svcCtl, &serviceFakeRunner{})

	for _, name := range []string{"web1", "web2"} {
		if code := app.dispatch(context.Background(), []string{"service", "add", name, "--remote-control"}); code != 0 {
			t.Fatalf("service add %s failed: %s", name, stderr.String())
		}
	}
	unitPath, err := service.TemplateUnitPath(home, "")
	if err != nil {
		t.Fatal(err)
	}

	// 1. Disable failure without --force fails closed and keeps spec.
	svcCtl.disableErr = errors.New("dbus connection refused")
	stderr.Reset()
	if code := app.dispatch(context.Background(), []string{"service", "rm", "web1"}); code == 0 {
		t.Fatal("expected service rm without --force to fail when disable fails")
	}
	if !strings.Contains(stderr.String(), "disable or stop agbox@web1.service") {
		t.Fatalf("unexpected stderr: %s", stderr.String())
	}
	if _, err := service.LoadSpec(app.Env.DataDir, "web1"); err != nil {
		t.Fatalf("spec web1 was deleted despite disable failure without --force: %v", err)
	}

	// 2. Disable failure with --force warns, deletes web1, and keeps agbox@.service because web2 remains.
	stderr.Reset()
	if code := app.dispatch(context.Background(), []string{"service", "rm", "--force", "web1"}); code != 0 {
		t.Fatalf("service rm --force web1 failed: %s", stderr.String())
	}
	if _, err := os.Lstat(unitPath); err != nil {
		t.Fatalf("expected agbox@.service to remain while web2 exists: %v", err)
	}

	// 3. Unit-not-found from Disable is tolerated without --force and removes template unit when last spec is deleted.
	svcCtl.disableErr = errors.New("Unit agbox@web2.service not found")
	stderr.Reset()
	if code := app.dispatch(context.Background(), []string{"service", "rm", "web2"}); code != 0 {
		t.Fatalf("service rm web2 with not-found disable failed: %s", stderr.String())
	}
	if _, err := os.Lstat(unitPath); !os.IsNotExist(err) {
		t.Fatalf("expected agbox@.service to be deleted when last service is removed: %v", err)
	}

	// 4. service linger enable success and error paths.
	svcCtl.disableErr = nil
	stdout.Reset()
	stderr.Reset()
	if code := app.dispatch(context.Background(), []string{"service", "linger", "enable"}); code != 0 {
		t.Fatalf("service linger enable failed: %s", stderr.String())
	}
	svcCtl.lingerErr = errors.New("permission denied")
	stderr.Reset()
	if code := app.dispatch(context.Background(), []string{"service", "linger", "enable"}); code == 0 {
		t.Fatal("expected service linger enable to fail when EnableLinger errors")
	}
	if !strings.Contains(stderr.String(), "sudo loginctl enable-linger alice") {
		t.Fatalf("unexpected linger error: %s", stderr.String())
	}

	// 5. Root guard rejection and AllowRoot propagation into template unit + __service-run.
	rootApp, _, rootErr, rootHome := newServiceTestApp(t, &fakeServiceCtl{}, &serviceFakeRunner{
		fn: func(_ context.Context, req msb.CommandRequest) (msb.CommandResult, error) {
			if len(req.Args) > 0 && req.Args[0] == "snap" {
				return msb.CommandResult{Stdout: "agbox:v1\n"}, nil
			}
			if len(req.Args) > 0 && req.Args[0] == "ls" {
				return msb.CommandResult{Stdout: "NAME STATUS\n"}, nil
			}
			return msb.CommandResult{}, nil
		},
	})
	rootApp.GetEUID = func() int { return 0 }

	if code := rootApp.dispatch(context.Background(), []string{"service", "list"}); code == 0 || !strings.Contains(rootErr.String(), "do not run as root") {
		t.Fatalf("expected root rejection on service list, code=%d stderr=%q", code, rootErr.String())
	}
	rootErr.Reset()
	if code := rootApp.dispatch(context.Background(), []string{"service", "add", "--allow-root", "rootbox", "--cmd", "true"}); code != 0 {
		t.Fatalf("service add --allow-root failed: %s", rootErr.String())
	}
	rootUnitPath, err := service.TemplateUnitPath(rootHome, "")
	if err != nil {
		t.Fatal(err)
	}
	rawUnit, err := os.ReadFile(rootUnitPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(rawUnit), `Environment="AGBOX_ALLOW_ROOT=1"`) {
		t.Fatalf("expected AGBOX_ALLOW_ROOT=1 in template unit:\n%s", string(rawUnit))
	}

	rootErr.Reset()
	if code := rootApp.dispatch(context.Background(), []string{service.SubcommandName, "rootbox"}); code == 0 || !strings.Contains(rootErr.String(), "do not run as root") {
		t.Fatalf("expected __service-run as root without Env.AllowRoot to fail, code=%d stderr=%q", code, rootErr.String())
	}
	rootApp.Env.AllowRoot = true
	rootErr.Reset()
	if code := rootApp.dispatch(context.Background(), []string{service.SubcommandName, "rootbox"}); code != 0 {
		t.Fatalf("expected __service-run with Env.AllowRoot=true to succeed, code=%d stderr=%q", code, rootErr.String())
	}
}

func TestServiceSuperviseCmdServeExitZeroPersistStartupFailureAndStaleNonPersist(t *testing.T) {
	t.Parallel()

	// 1. superviseCmd sends READY=1, WATCHDOG=1, STOPPING=1 and recovers stale non-persistent sandbox.
	var mu sync.Mutex
	var notifyEvents []string
	var rmStaleCalled bool
	ctx1, cancel1 := context.WithCancel(context.Background())
	defer cancel1()

	fakeMSB1 := &serviceFakeRunner{
		fn: func(runCtx context.Context, req msb.CommandRequest) (msb.CommandResult, error) {
			if len(req.Args) == 0 {
				return msb.CommandResult{}, nil
			}
			switch req.Args[0] {
			case "snap":
				return msb.CommandResult{Stdout: "agbox:v1\n"}, nil
			case "ls":
				mu.Lock()
				rm := rmStaleCalled
				mu.Unlock()
				if !rm {
					return msb.CommandResult{Stdout: "NAME STATUS\nagbox-cmdsvc stopped\n"}, nil
				}
				return msb.CommandResult{Stdout: "NAME STATUS\n"}, nil
			case "rm":
				if len(req.Args) >= 3 && req.Args[2] == "agbox-cmdsvc" {
					mu.Lock()
					rmStaleCalled = true
					mu.Unlock()
				}
				return msb.CommandResult{}, nil
			case "ping":
				cancel1()
				return msb.CommandResult{}, nil
			case "exec":
				if strings.Contains(strings.Join(req.Args, " "), "sleep 60") {
					<-runCtx.Done()
					return msb.CommandResult{}, runCtx.Err()
				}
				return msb.CommandResult{}, nil
			default:
				return msb.CommandResult{}, nil
			}
		},
	}

	app1, _, stderr1, _ := newServiceTestApp(t, &fakeServiceCtl{}, fakeMSB1)
	app1.NotifySystemd = func(state string) {
		mu.Lock()
		notifyEvents = append(notifyEvents, state)
		mu.Unlock()
	}
	staleDir := filepath.Join(app1.Env.DataDir, "run", "cmdsvc")
	if err := os.MkdirAll(staleDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := service.SaveSpec(app1.Env.DataDir, service.Spec{
		Name: "cmdsvc",
		Mode: config.RunModeCmd,
		Cmd:  "sleep 60",
	}); err != nil {
		t.Fatal(err)
	}
	if code := app1.dispatch(ctx1, []string{service.SubcommandName, "cmdsvc"}); code != 0 {
		t.Fatalf("__service-run cmdsvc failed (code=%d): %s", code, stderr1.String())
	}
	if !rmStaleCalled {
		t.Fatal("expected non-persistent stale sandbox to be removed before fresh start")
	}
	joined := strings.Join(notifyEvents, ",")
	if !strings.Contains(joined, "READY=1") || !strings.Contains(joined, "WATCHDOG=1") || !strings.Contains(joined, "STOPPING=1") {
		t.Fatalf("expected READY/WATCHDOG/STOPPING from superviseCmd, got %v", notifyEvents)
	}

	// 2. superviseServe unexpected exit 0 returns non-zero error so systemd restarts it.
	app2, _, stderr2, _ := newServiceTestApp(t, &fakeServiceCtl{}, &serviceFakeRunner{
		fn: func(_ context.Context, req msb.CommandRequest) (msb.CommandResult, error) {
			if len(req.Args) > 0 && req.Args[0] == "snap" {
				return msb.CommandResult{Stdout: "agbox:v1\n"}, nil
			}
			if len(req.Args) > 0 && req.Args[0] == "ls" {
				return msb.CommandResult{Stdout: "NAME STATUS\n"}, nil
			}
			return msb.CommandResult{}, nil
		},
	})
	app2.WaitServeUI = func(_ context.Context, _ int, _ string) bool { return true }
	if err := service.SaveSpec(app2.Env.DataDir, service.Spec{
		Name:  "exit0web",
		Agent: "opencode",
		Mode:  config.RunModeServe,
		Port:  4096,
	}); err != nil {
		t.Fatal(err)
	}
	if code := app2.dispatch(context.Background(), []string{service.SubcommandName, "exit0web"}); code == 0 {
		t.Fatal("expected non-zero exit when opencode serve exits unexpectedly with status 0")
	}
	if !strings.Contains(stderr2.String(), "exited unexpectedly with status 0") {
		t.Fatalf("unexpected stderr for exit-0 serve: %s", stderr2.String())
	}

	// 3. H8: Supervised --persist serve failing readiness deletes the broken VM instead of persisting it.
	var removedBroken bool
	app3, _, stderr3, _ := newServiceTestApp(t, &fakeServiceCtl{}, &serviceFakeRunner{
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
				if strings.Contains(strings.Join(req.Args, " "), "opencode serve") {
					<-runCtx.Done()
					return msb.CommandResult{}, runCtx.Err()
				}
				return msb.CommandResult{}, nil
			case "rm":
				if len(req.Args) >= 3 && req.Args[2] == "agbox-brokenpersist" {
					removedBroken = true
				}
				return msb.CommandResult{}, nil
			default:
				return msb.CommandResult{}, nil
			}
		},
	})
	app3.WaitServeUI = func(_ context.Context, _ int, _ string) bool { return false }
	if err := service.SaveSpec(app3.Env.DataDir, service.Spec{
		Name:    "brokenpersist",
		Agent:   "opencode",
		Mode:    config.RunModeServe,
		Port:    4097,
		Persist: true,
	}); err != nil {
		t.Fatal(err)
	}
	if code := app3.dispatch(context.Background(), []string{service.SubcommandName, "brokenpersist"}); code == 0 {
		t.Fatal("expected non-zero exit on serve readiness failure")
	}
	if !strings.Contains(stderr3.String(), "did not become ready") {
		t.Fatalf("unexpected stderr: %s", stderr3.String())
	}
	if !removedBroken {
		t.Fatal("expected broken persistent VM to be deleted (msb rm -f) on initial startup failure")
	}
	if hasMarker(filepath.Join(app3.Env.DataDir, "run", "brokenpersist", "suspended")) {
		t.Fatal("expected no suspended marker after supervised startup failure")
	}
}

func TestServiceRunPersistentRestartPreservesFlagsAndDynamicShares(t *testing.T) {
	t.Parallel()

	var mu sync.Mutex
	sandboxExists := false
	sandboxRunning := false
	startCount := 0
	restoreCount := 0
	var lastRestoreArgs []string
	var streamedKeys []string
	var hubRuns [][]vcsfuse.HubShareConfig
	var notifyRuns [][]string
	var curCancel context.CancelFunc
	var curNotify *[]string

	fakeMSB := &serviceFakeRunner{
		fn: func(_ context.Context, req msb.CommandRequest) (msb.CommandResult, error) {
			if len(req.Args) == 0 {
				return msb.CommandResult{}, nil
			}
			switch req.Args[0] {
			case "snap":
				if len(req.Args) >= 2 && req.Args[1] == "restore" {
					mu.Lock()
					restoreCount++
					lastRestoreArgs = append([]string(nil), req.Args...)
					sandboxExists = true
					sandboxRunning = true
					mu.Unlock()
					return msb.CommandResult{}, nil
				}
				return msb.CommandResult{Stdout: "agbox:v1\n"}, nil
			case "ls":
				mu.Lock()
				exists := sandboxExists
				running := sandboxRunning
				mu.Unlock()
				if !exists {
					return msb.CommandResult{Stdout: "NAME STATUS\n"}, nil
				}
				state := "stopped"
				if running {
					state = "running"
				}
				return msb.CommandResult{Stdout: "NAME STATUS\nagbox-persvc " + state + "\n"}, nil
			case "start":
				mu.Lock()
				startCount++
				sandboxRunning = true
				mu.Unlock()
				return msb.CommandResult{}, nil
			case "stop":
				mu.Lock()
				sandboxRunning = false
				mu.Unlock()
				return msb.CommandResult{}, nil
			case "exec":
				if req.Stdin != nil && strings.Contains(strings.Join(req.Args, " "), ".agbox-keys.sh") {
					b, _ := io.ReadAll(req.Stdin)
					mu.Lock()
					streamedKeys = append(streamedKeys, string(b))
					mu.Unlock()
				}
				return msb.CommandResult{}, nil
			case "ping":
				mu.Lock()
				cancelFn := curCancel
				mu.Unlock()
				if cancelFn != nil {
					cancelFn()
				}
				return msb.CommandResult{}, nil
			default:
				return msb.CommandResult{}, nil
			}
		},
	}

	app, _, stderr, home := newServiceTestApp(t, &fakeServiceCtl{}, fakeMSB)
	app.StartHub = func(_, _, _ string, initial []vcsfuse.HubShareConfig, _ bool) (int, error) {
		mu.Lock()
		hubRuns = append(hubRuns, append([]vcsfuse.HubShareConfig(nil), initial...))
		mu.Unlock()
		return 9999, nil
	}
	app.NotifySystemd = func(state string) {
		mu.Lock()
		if curNotify != nil {
			*curNotify = append(*curNotify, state)
		}
		mu.Unlock()
	}

	proj1 := filepath.Join(home, "proj1")
	proj2 := filepath.Join(home, "proj2")
	if err := os.MkdirAll(proj1, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(proj2, 0o755); err != nil {
		t.Fatal(err)
	}
	envFile := filepath.Join(home, "persvc.env")
	if err := os.WriteFile(envFile, []byte("GEMINI_API_KEY=persist-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Register a persistent service with --no-net, --cpus, --memory, --share-hub, and an initial share.
	if code := app.dispatch(context.Background(), []string{
		"service", "add", "--env-file", envFile, "persvc",
		"--persist", "--no-net", "--cpus", "2", "--memory", "2G", "--share-hub",
		"--remote-control", proj1,
	}); code != 0 {
		t.Fatalf("service add persvc failed (code=%d): %s", code, stderr.String())
	}

	// First __service-run creates the sandbox, sends READY/WATCHDOG, and suspends on SIGTERM.
	ctx1, cancel1 := context.WithCancel(context.Background())
	var events1 []string
	mu.Lock()
	curCancel = cancel1
	curNotify = &events1
	mu.Unlock()
	stderr.Reset()
	if code := app.dispatch(ctx1, []string{service.SubcommandName, "persvc"}); code != 0 {
		t.Fatalf("first __service-run persvc failed (code=%d): %s", code, stderr.String())
	}
	notifyRuns = append(notifyRuns, events1)

	if restoreCount != 1 || startCount != 0 {
		t.Fatalf("after first run: restoreCount=%d startCount=%d, want 1 and 0", restoreCount, startCount)
	}
	restoreJoined := strings.Join(lastRestoreArgs, " ")
	for _, want := range []string{"--no-net", "--cpus 2", "--memory 2G"} {
		if !strings.Contains(restoreJoined, want) {
			t.Fatalf("first restore args missing %q: %s", want, restoreJoined)
		}
	}
	suspPath := filepath.Join(app.Env.DataDir, "run", "persvc", "suspended")
	if !hasMarker(suspPath) {
		t.Fatalf("expected suspended marker at %s after first stop", suspPath)
	}

	// Simulate dynamic share edit (`agbox share add` + `agbox share rm`) while suspended.
	meta, err := config.LoadRunMeta(suspPath)
	if err != nil {
		t.Fatalf("LoadRunMeta(suspended): %v", err)
	}
	meta.Shares = []config.ShareRecord{
		{
			Index:      1,
			HostPath:   proj2,
			GuestName:  "extra",
			IsDir:      true,
			Masked:     true,
			AccessMode: "ro",
			ReadOnly:   true,
			VCSPolicy:  config.VCSMask,
		},
	}
	if err := config.SaveRunMeta(suspPath, meta); err != nil {
		t.Fatalf("SaveRunMeta(suspended): %v", err)
	}

	// Second __service-run must resume cleanly without rejecting --no-net/--cpus/--memory/--share-hub or dynamic share edits.
	ctx2, cancel2 := context.WithCancel(context.Background())
	var events2 []string
	mu.Lock()
	curCancel = cancel2
	curNotify = &events2
	mu.Unlock()
	stderr.Reset()
	if code := app.dispatch(ctx2, []string{service.SubcommandName, "persvc"}); code != 0 {
		t.Fatalf("second __service-run persvc failed (code=%d): %s", code, stderr.String())
	}
	notifyRuns = append(notifyRuns, events2)

	if restoreCount != 1 || startCount != 1 {
		t.Fatalf("after second run: restoreCount=%d startCount=%d, want 1 and 1", restoreCount, startCount)
	}
	if len(hubRuns) != 2 {
		t.Fatalf("expected 2 StartHub calls, got %d", len(hubRuns))
	}
	if len(hubRuns[1]) != 1 || hubRuns[1][0].HostPath != proj2 || hubRuns[1][0].GuestName != "extra" || !hubRuns[1][0].ReadOnly {
		t.Fatalf("expected resumed hub to preserve dynamic share edits, got %+v", hubRuns[1])
	}
	if len(streamedKeys) != 2 || !strings.Contains(streamedKeys[1], "persist-secret") {
		t.Fatalf("expected env file secret streamed on both runs, got %v", streamedKeys)
	}
	for i, evs := range notifyRuns {
		joined := strings.Join(evs, ",")
		if !strings.Contains(joined, "READY=1") || !strings.Contains(joined, "WATCHDOG=1") || !strings.Contains(joined, "STOPPING=1") {
			t.Errorf("run %d missing READY/WATCHDOG/STOPPING notifications: %v", i+1, evs)
		}
	}
	if !hasMarker(suspPath) {
		t.Fatalf("expected suspended marker at %s after second stop", suspPath)
	}
}

func TestServiceSuperviseCmdConsecutivePingFailureThreshold(t *testing.T) {
	t.Parallel()

	var mu sync.Mutex
	var notifyEvents []string
	pingCalls := 0

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
			case "ping":
				mu.Lock()
				pingCalls++
				n := pingCalls
				mu.Unlock()
				// Fail once, then succeed (resetting failures to 0), then fail 2 consecutive times.
				if n == 2 {
					return msb.CommandResult{}, nil
				}
				return msb.CommandResult{Stderr: "vm hung"}, errors.New("exit status 1")
			case "exec":
				if strings.Contains(strings.Join(req.Args, " "), "sleep 60") {
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
	app.NotifySystemd = func(state string) {
		mu.Lock()
		notifyEvents = append(notifyEvents, state)
		mu.Unlock()
	}

	if err := service.SaveSpec(app.Env.DataDir, service.Spec{
		Name: "cmdhung",
		Mode: config.RunModeCmd,
		Cmd:  "sleep 60",
	}); err != nil {
		t.Fatal(err)
	}

	code := app.dispatch(context.Background(), []string{service.SubcommandName, "cmdhung"})
	if code == 0 {
		t.Fatal("expected non-zero exit when superviseCmd hits consecutive ping failure threshold")
	}
	if !strings.Contains(stderr.String(), "health check failed 2 consecutive times") {
		t.Fatalf("unexpected stderr: %s", stderr.String())
	}

	mu.Lock()
	pings := pingCalls
	events := append([]string(nil), notifyEvents...)
	mu.Unlock()
	if pings != 4 {
		t.Fatalf("expected 4 ping polls (fail, ok-reset, fail, fail), got %d", pings)
	}
	joined := strings.Join(events, ",")
	if !strings.Contains(joined, "READY=1") || !strings.Contains(joined, "WATCHDOG=1") || !strings.Contains(joined, "STOPPING=1") {
		t.Fatalf("expected READY=1, WATCHDOG=1, STOPPING=1 notifications, got %v", events)
	}
}

func TestServiceRemoteFlagsAndPersistConflict(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	// 1. AGBOX_REMOTE=0 (RemoteDefault=false) persists NoRemote=true in the saved spec.
	app, _, stderr, _ := newServiceTestApp(t, &fakeServiceCtl{}, &serviceFakeRunner{})
	app.Env.RemoteDefault = false
	if code := app.dispatch(ctx, []string{"service", "add", "remoff", "--cmd", "true"}); code != 0 {
		t.Fatalf("service add with RemoteDefault=false failed: code=%d stderr=%s", code, stderr.String())
	}
	spec, err := service.LoadSpec(app.Env.DataDir, "remoff")
	if err != nil {
		t.Fatalf("LoadSpec(remoff): %v", err)
	}
	if !spec.NoRemote || spec.Remote {
		t.Fatalf("expected NoRemote=true and Remote=false, got Remote=%v NoRemote=%v", spec.Remote, spec.NoRemote)
	}

	// Explicit --remote overrides AGBOX_REMOTE=0.
	if code := app.dispatch(ctx, []string{"service", "add", "remon", "--remote", "--cmd", "true"}); code != 0 {
		t.Fatalf("service add --remote failed: code=%d stderr=%s", code, stderr.String())
	}
	specOn, err := service.LoadSpec(app.Env.DataDir, "remon")
	if err != nil {
		t.Fatalf("LoadSpec(remon): %v", err)
	}
	if !specOn.Remote || specOn.NoRemote {
		t.Fatalf("expected Remote=true and NoRemote=false, got Remote=%v NoRemote=%v", specOn.Remote, specOn.NoRemote)
	}

	// 2. service add --remote --no-remote fails closed.
	stderr.Reset()
	if code := app.dispatch(ctx, []string{"service", "add", "conflict", "--remote", "--no-remote", "--cmd", "true"}); code == 0 {
		t.Fatal("expected service add --remote --no-remote to fail")
	}

	// 3. Persistent service restart rejects conflicting --no-remote spec change.
	fakeMSB := &serviceFakeRunner{
		fn: func(_ context.Context, req msb.CommandRequest) (msb.CommandResult, error) {
			if len(req.Args) == 0 {
				return msb.CommandResult{}, nil
			}
			switch req.Args[0] {
			case "snap":
				return msb.CommandResult{Stdout: "agbox:v1\n"}, nil
			case "ls":
				return msb.CommandResult{Stdout: "NAME STATUS\nagbox-perrem stopped\n"}, nil
			default:
				return msb.CommandResult{}, nil
			}
		},
	}
	app2, _, stderr2, _ := newServiceTestApp(t, &fakeServiceCtl{}, fakeMSB)
	runDir := filepath.Join(app2.Env.DataDir, "run", "perrem")
	if err := os.MkdirAll(runDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := config.SaveRunMeta(filepath.Join(runDir, "suspended"), config.RunMeta{
		Sandbox:      "agbox-perrem",
		Agent:        "opencode",
		Mode:         config.RunModeCmd,
		Cmd:          "true",
		MaskMode:     config.MaskStrict,
		Persist:      true,
		RemoteBridge: true,
	}); err != nil {
		t.Fatal(err)
	}
	if err := service.SaveSpec(app2.Env.DataDir, service.Spec{
		Name:     "perrem",
		Agent:    "opencode",
		Mode:     config.RunModeCmd,
		Cmd:      "true",
		Persist:  true,
		NoRemote: true,
	}); err != nil {
		t.Fatal(err)
	}
	stderr2.Reset()
	if code := app2.dispatch(ctx, []string{service.SubcommandName, "perrem"}); code == 0 || !strings.Contains(stderr2.String(), "cannot change --remote or --no-remote") {
		t.Fatalf("expected persistent service restart with conflicting NoRemote to fail, code=%d stderr=%q", code, stderr2.String())
	}
}
