package cli

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"agbox/internal/config"
	"agbox/internal/remotebridge"
	"agbox/internal/remoteproto"
)

func TestRemoteFlagParsingAndPolicyCLI(t *testing.T) {
	opts, err := parseRunArgs([]string{"--remote", "--cmd", "true"}, config.MaskStrict, nil)
	if err != nil || !opts.Remote || opts.NoRemote {
		t.Fatalf("unexpected --remote opts: %+v err=%v", opts, err)
	}
	opts2, err := parseRunArgs([]string{"--no-remote", "--cmd", "true"}, config.MaskStrict, nil)
	if err != nil || opts2.Remote || !opts2.NoRemote {
		t.Fatalf("unexpected --no-remote opts: %+v err=%v", opts2, err)
	}
	if _, err := parseRunArgs([]string{"--remote", "--no-remote", "--cmd", "true"}, config.MaskStrict, nil); err == nil {
		t.Fatal("expected --remote and --no-remote conflict to fail")
	}

	// Valid --sandbox normalizes bare names to agbox-<name>.
	connOpts, err := parseRemoteConnectArgs([]string{"--sandbox", "devbox", "127.0.0.1:9000"})
	if err != nil || connOpts.SandboxName != "agbox-devbox" {
		t.Fatalf("parseRemoteConnectArgs(--sandbox devbox) = (%+v, %v), want SandboxName=agbox-devbox", connOpts, err)
	}

	app, _, stdout, stderr := newTestApp(t)
	ctx := context.Background()

	// Help text exits 0 for remote and subcommands.
	for _, args := range [][]string{
		{"remote", "--help"},
		{"remote", "serve", "--help"},
		{"remote", "connect", "--help"},
		{"remote", "policy", "--help"},
	} {
		stdout.Reset()
		stderr.Reset()
		if rc := app.dispatch(ctx, args); rc != 0 {
			t.Fatalf("%v returned rc=%d stderr=%q", args, rc, stderr.String())
		}
		if !strings.Contains(stdout.String(), "agbox remote") {
			t.Errorf("%v help output missing header: %q", args, stdout.String())
		}
	}

	// Conflicting flags, empty --allow-from entries, and invalid --sandbox names fail closed before pairing.
	for _, bad := range [][]string{
		{"remote", "serve", "--listen", "127.0.0.1:8080", "--port", "9090"},
		{"remote", "serve", "--path", "/usr/bin", "--strict-path"},
		{"remote", "serve", "--allow-from", "not-a-cidr"},
		{"remote", "serve", "--allow-from", ","},
		{"remote", "serve", "--allow-from", "127.0.0.1,"},
		{"remote", "connect", "--policy", "/tmp/a.json", "--no-policy", "127.0.0.1:9000"},
		{"remote", "connect", "--sandbox", "agbox-base", "127.0.0.1:9000"},
		{"remote", "connect", "--sandbox", "base", "127.0.0.1:9000"},
		{"remote", "connect", "--sandbox", "../evil", "127.0.0.1:9000"},
		{"remote", "connect"},
		{"remote", "policy", "check", "--policy", "a.json", "b.json"},
	} {
		stderr.Reset()
		if rc := app.dispatch(ctx, bad); rc == 0 {
			t.Errorf("expected %v to fail", bad)
		}
	}

	// Explicit --policy pointing to a missing default path must fail closed.
	polPath := filepath.Join(app.Env.DataDir, "remote-policy.json")
	stderr.Reset()
	if rc := app.dispatch(ctx, []string{"remote", "policy", "test", "--policy", polPath, "--", "uname", "-a"}); rc == 0 {
		t.Fatal("expected remote policy test --policy <missingDefaultPath> to fail closed")
	}

	// Omitting --policy when the default file is absent falls back to DefaultPolicy.
	stdout.Reset()
	stderr.Reset()
	if rc := app.dispatch(ctx, []string{"remote", "policy", "test", "--", "uname", "-a"}); rc != 0 {
		t.Fatalf("remote policy test without default file failed: rc=%d stderr=%s", rc, stderr.String())
	}
	if !strings.Contains(stdout.String(), "ask\n") {
		t.Errorf("expected default ask verdict when default policy file is absent, got %q", stdout.String())
	}

	// Policy init, check, and test subcommands.
	stdout.Reset()
	stderr.Reset()
	if rc := app.dispatch(ctx, []string{"remote", "policy", "init"}); rc != 0 {
		t.Fatalf("remote policy init failed: rc=%d stderr=%s", rc, stderr.String())
	}
	if _, err := os.Stat(polPath); err != nil {
		t.Fatalf("expected starter policy at %s: %v", polPath, err)
	}

	stdout.Reset()
	stderr.Reset()
	if rc := app.dispatch(ctx, []string{"remote", "policy", "check"}); rc != 0 {
		t.Fatalf("remote policy check failed: rc=%d stderr=%s", rc, stderr.String())
	}

	stdout.Reset()
	stderr.Reset()
	if rc := app.dispatch(ctx, []string{"remote", "policy", "test", "--", "uname", "-a"}); rc != 0 {
		t.Fatalf("remote policy test (uname -a) failed: rc=%d stderr=%s", rc, stderr.String())
	}
	if !strings.Contains(stdout.String(), "allow-uname-read") || !strings.Contains(stdout.String(), "allow\n") {
		t.Errorf("expected allow verdict for uname -a, got %q", stdout.String())
	}

	stdout.Reset()
	stderr.Reset()
	if rc := app.dispatch(ctx, []string{"remote", "policy", "test", "--", "rm", "-rf", "/"}); rc != 0 {
		t.Fatalf("remote policy test (rm -rf /) failed: rc=%d stderr=%s", rc, stderr.String())
	}
	if !strings.Contains(stdout.String(), "deny-destructive-rm") || !strings.Contains(stdout.String(), "deny\n") {
		t.Errorf("expected deny verdict for rm -rf /, got %q", stdout.String())
	}
}

func TestRemotePolicyInitExternalDirPermissionsAndAtomicForce(t *testing.T) {
	app, _, _, stderr := newTestApp(t)
	ctx := context.Background()

	extDir := filepath.Join(t.TempDir(), "shared-parent")
	if err := os.MkdirAll(extDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(extDir, 0o755); err != nil {
		t.Fatal(err)
	}

	// Writing to an external directory must not tighten pre-existing parent permissions.
	outPath := filepath.Join(extDir, "pol.json")
	if rc := app.dispatch(ctx, []string{"remote", "policy", "init", "--output", outPath}); rc != 0 {
		t.Fatalf("remote policy init --output failed: rc=%d stderr=%s", rc, stderr.String())
	}
	dirInfo, err := os.Stat(extDir)
	if err != nil {
		t.Fatal(err)
	}
	if dirInfo.Mode().Perm() != 0o755 {
		t.Fatalf("external parent dir mode changed to %04o, want 0755", dirInfo.Mode().Perm())
	}
	fileInfo, err := os.Lstat(outPath)
	if err != nil {
		t.Fatal(err)
	}
	if fileInfo.Mode().Perm() != 0o600 {
		t.Fatalf("policy file mode = %04o, want 0600", fileInfo.Mode().Perm())
	}

	// Refuses overwrite without --force.
	stderr.Reset()
	if rc := app.dispatch(ctx, []string{"remote", "policy", "init", "--output", outPath}); rc == 0 {
		t.Fatal("expected policy init without --force to fail on existing file")
	}

	// --force atomically replaces a 0644 file with a fresh 0600 file.
	if err := os.Chmod(outPath, 0o644); err != nil {
		t.Fatal(err)
	}
	stderr.Reset()
	if rc := app.dispatch(ctx, []string{"remote", "policy", "init", "--output", outPath, "--force"}); rc != 0 {
		t.Fatalf("remote policy init --force failed: rc=%d stderr=%s", rc, stderr.String())
	}
	forcedInfo, err := os.Lstat(outPath)
	if err != nil {
		t.Fatal(err)
	}
	if forcedInfo.Mode().Perm() != 0o600 {
		t.Fatalf("forced policy file mode = %04o, want 0600", forcedInfo.Mode().Perm())
	}

	// Rejects symlink target even with --force.
	symTarget := filepath.Join(extDir, "sym.json")
	if err := os.Symlink(outPath, symTarget); err != nil {
		t.Fatal(err)
	}
	stderr.Reset()
	if rc := app.dispatch(ctx, []string{"remote", "policy", "init", "--output", symTarget, "--force"}); rc == 0 {
		t.Fatal("expected policy init --force to reject symlink target")
	}
}

func TestRemoteBridgeRunResumeAndServiceLifecycle(t *testing.T) {
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

	// 1. Default run mounts remote bridge, links agbox-remote, and merges INSTRUCTIONS.md into AGENTS.md.
	bridgeStarts := 0
	app.StartRemoteBridge = func(mntDir, _, pidFile string, _ bool) (int, error) {
		bridgeStarts++
		_ = os.MkdirAll(mntDir, 0o700)
		_ = os.WriteFile(pidFile, []byte("9997\n"), 0o600)
		return 9997, nil
	}
	runner.calls = nil
	if rc := app.dispatch(ctx, []string{"run", "--name", "rem1", "--persist", "--cmd", "true"}); rc != 0 {
		t.Fatalf("run --persist failed: rc=%d stderr=%s", rc, stderr.String())
	}
	if bridgeStarts != 1 {
		t.Fatalf("expected 1 bridge start, got %d", bridgeStarts)
	}
	sawRemoteVol := false
	sawGuestLink := false
	sawRulesInstr := false
	for _, c := range runner.calls {
		joined := strings.Join(c.Args, " ")
		if len(c.Args) >= 2 && c.Args[0] == "snap" && c.Args[1] == "restore" {
			if strings.Contains(joined, ":"+remotebridge.GuestMountPath+":rw,stat-virt=off") {
				sawRemoteVol = true
			}
		}
		if strings.Contains(joined, "/usr/local/bin/agbox-remote") {
			sawGuestLink = true
		}
		if strings.Contains(joined, "/home/agent/.agbox-remote/INSTRUCTIONS.md") {
			sawRulesInstr = true
		}
	}
	if !sawRemoteVol || !sawGuestLink || !sawRulesInstr {
		t.Fatalf("expected remote mount (%v), guest symlink (%v), and INSTRUCTIONS.md merge (%v)", sawRemoteVol, sawGuestLink, sawRulesInstr)
	}

	// 2. Resuming suspended rem1 with --persist --no-remote is rejected.
	runner.sandboxes = fakeMSBLS("agbox-base stopped", "agbox-rem1 stopped")
	stderr.Reset()
	if rc := app.dispatch(ctx, []string{"run", "--name", "rem1", "--persist", "--no-remote", "--cmd", "true"}); rc == 0 {
		t.Fatal("expected changing --no-remote on persistent resume to fail")
	}

	// 3. Resuming suspended rem1 remounts remote bridge and re-runs guest setup and INSTRUCTIONS.md merge.
	runner.calls = nil
	if rc := app.dispatch(ctx, []string{"resume", "agbox-rem1"}); rc != 0 {
		t.Fatalf("resume agbox-rem1 failed: rc=%d stderr=%s", rc, stderr.String())
	}
	if bridgeStarts != 2 {
		t.Fatalf("expected bridge remount on resume (total 2), got %d", bridgeStarts)
	}
	sawResumeInstr := false
	for _, c := range runner.calls {
		if strings.Contains(strings.Join(c.Args, " "), "/home/agent/.agbox-remote/INSTRUCTIONS.md") {
			sawResumeInstr = true
		}
	}
	if !sawResumeInstr {
		t.Fatal("expected resume to re-merge INSTRUCTIONS.md into AGENTS.md")
	}

	// 4. Pre-upgrade suspended sandbox (RemoteBridge=false) does NOT start the remote bridge on resume.
	legacyDir := filepath.Join(app.Env.DataDir, "run", "legacy")
	if err := os.MkdirAll(legacyDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := config.SaveRunMeta(filepath.Join(legacyDir, "suspended"), config.RunMeta{
		Sandbox:      "agbox-legacy",
		Agent:        "opencode",
		Mode:         config.RunModeCmd,
		Cmd:          "true",
		MaskMode:     config.MaskStrict,
		RemoteBridge: false,
	}); err != nil {
		t.Fatal(err)
	}
	runner.sandboxes = fakeMSBLS("agbox-base stopped", "agbox-legacy stopped")
	beforeLegacy := bridgeStarts
	if rc := app.dispatch(ctx, []string{"resume", "agbox-legacy"}); rc != 0 {
		t.Fatalf("resume legacy failed: rc=%d stderr=%s", rc, stderr.String())
	}
	if bridgeStarts != beforeLegacy {
		t.Fatalf("expected legacy suspended sandbox with RemoteBridge=false not to start bridge, starts=%d", bridgeStarts)
	}

	// 5. AGBOX_REMOTE=0 disables remote bridge on run, and --remote overrides it.
	app.Env.RemoteDefault = false
	runner.sandboxes = fakeMSBLS("agbox-base stopped")
	beforeEnvOff := bridgeStarts
	if rc := app.dispatch(ctx, []string{"run", "--name", "envoff", "--cmd", "true"}); rc != 0 {
		t.Fatalf("run with RemoteDefault=false failed: rc=%d stderr=%s", rc, stderr.String())
	}
	if bridgeStarts != beforeEnvOff {
		t.Fatalf("expected RemoteDefault=false to skip bridge start, got %d -> %d", beforeEnvOff, bridgeStarts)
	}
	if rc := app.dispatch(ctx, []string{"run", "--name", "envoverride", "--remote", "--cmd", "true"}); rc != 0 {
		t.Fatalf("run --remote with RemoteDefault=false failed: rc=%d stderr=%s", rc, stderr.String())
	}
	if bridgeStarts != beforeEnvOff+1 {
		t.Fatalf("expected --remote to override RemoteDefault=false, got %d -> %d", beforeEnvOff, bridgeStarts)
	}
	app.Env.RemoteDefault = true

	// 6. run --no-rules skips AGENTS.md merge while still mounting remote bridge.
	runner.calls = nil
	beforeNoRules := bridgeStarts
	if rc := app.dispatch(ctx, []string{"run", "--name", "norules", "--no-rules", "--cmd", "true"}); rc != 0 {
		t.Fatalf("run --no-rules failed: rc=%d stderr=%s", rc, stderr.String())
	}
	if bridgeStarts != beforeNoRules+1 {
		t.Fatalf("expected --no-rules to still start remote bridge, got %d -> %d", beforeNoRules, bridgeStarts)
	}
	for _, c := range runner.calls {
		if strings.Contains(strings.Join(c.Args, " "), "/home/agent/.agbox-remote/INSTRUCTIONS.md") {
			t.Fatal("expected --no-rules to skip INSTRUCTIONS.md merge into AGENTS.md")
		}
	}

	// 7. --no-mask gracefully disables remote bridge if FUSE fails, unless --remote is explicit.
	app.StartRemoteBridge = func(_, _, _ string, _ bool) (int, error) {
		return 0, os.ErrPermission
	}
	runner.sandboxes = fakeMSBLS("agbox-base stopped")
	stderr.Reset()
	if rc := app.dispatch(ctx, []string{"run", "--name", "nomaskok", "--no-mask", "--cmd", "true"}); rc != 0 {
		t.Fatalf("expected --no-mask to warn and disable remote bridge on FUSE error, rc=%d stderr=%s", rc, stderr.String())
	}
	if !strings.Contains(stderr.String(), "Disabling remote bridge") {
		t.Errorf("expected warning about disabling remote bridge, got %q", stderr.String())
	}
	stderr.Reset()
	if rc := app.dispatch(ctx, []string{"run", "--name", "nomaskfail", "--no-mask", "--remote", "--cmd", "true"}); rc == 0 {
		t.Fatal("expected --no-mask --remote to fail closed when remote bridge fails")
	}

	// 8. DATA_DIR containing ':' fails in strict mode and warns/disables under --no-mask.
	colonDataDir := filepath.Join(t.TempDir(), "bad:data")
	if err := os.MkdirAll(colonDataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	colonCfg := filepath.Join(colonDataDir, "config")
	if err := config.SaveFile(colonCfg, config.State{
		Agent:     "opencode",
		Image:     "node:24-bookworm-slim",
		Snapshot:  "agbox:v1",
		SnapCount: 1,
	}); err != nil {
		t.Fatal(err)
	}
	origDataDir, origCfg := app.Env.DataDir, app.Env.ConfigFile
	app.Env.DataDir = colonDataDir
	app.Env.ConfigFile = colonCfg
	stderr.Reset()
	if rc := app.dispatch(ctx, []string{"run", "--name", "colonstrict", "--no-skills", "--no-rules", "--no-agent-cache", "--cmd", "true"}); rc == 0 || !strings.Contains(stderr.String(), "remote FUSE bridge") {
		t.Fatalf("expected DATA_DIR with ':' to fail on remote FUSE bridge in strict mode, rc=%d stderr=%q", rc, stderr.String())
	}
	stderr.Reset()
	if rc := app.dispatch(ctx, []string{"run", "--name", "colonnomask", "--no-mask", "--no-skills", "--no-rules", "--no-agent-cache", "--cmd", "true"}); rc != 0 {
		t.Fatalf("expected DATA_DIR with ':' to warn and disable bridge under --no-mask, rc=%d stderr=%s", rc, stderr.String())
	}
	if !strings.Contains(stderr.String(), "Disabling remote bridge") {
		t.Errorf("expected warning disabling remote bridge for bad DATA_DIR, got %q", stderr.String())
	}
	app.Env.DataDir, app.Env.ConfigFile = origDataDir, origCfg

	// 9. startDisposableVM mounts zero volumes (no remote bridge).
	runner.calls = nil
	_, _, cleanupDisp, err := app.startDisposableVM(ctx, "auth", "agbox:v1", "opencode", config.RunModeTUI, "Booting %s")
	if err != nil {
		t.Fatalf("startDisposableVM failed: %v", err)
	}
	cleanupDisp()
	for _, c := range runner.calls {
		if len(c.Args) >= 2 && c.Args[0] == "snap" && c.Args[1] == "restore" && slices.Contains(c.Args, "-v") {
			t.Errorf("expected disposable VM to mount zero volumes, got %v", c.Args)
		}
	}

	// 10. agbox status prints == remote == section.
	stdout.Reset()
	if rc := app.dispatch(ctx, []string{"status"}); rc != 0 {
		t.Fatalf("status failed: rc=%d", rc)
	}
	if !strings.Contains(stdout.String(), "== remote ==") {
		t.Errorf("expected == remote == in status output:\n%s", stdout.String())
	}
}

func TestRemoteStatusSanitizesANSIAndReportsCrashedBridge(t *testing.T) {
	app, _, stdout, stderr := newTestApp(t)
	ctx := context.Background()

	// Use a short directory under /tmp so the Unix socket path stays within sun_path limits.
	shortBase, err := os.MkdirTemp("", "agbox-st-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(shortBase)
	if err := os.Chmod(shortBase, 0o700); err != nil {
		t.Fatal(err)
	}
	app.Env.DataDir = shortBase
	app.Env.ConfigFile = filepath.Join(shortBase, "config")

	// Live sandbox with a running remote.sock that returns ANSI escape sequences in status fields.
	liveDir := filepath.Join(shortBase, "run", "live")
	if err := os.MkdirAll(liveDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := config.SaveRunMeta(filepath.Join(liveDir, "run.meta"), config.RunMeta{
		Sandbox:      "agbox-live",
		OwnerPID:     os.Getpid(),
		Agent:        "opencode",
		Mode:         config.RunModeCmd,
		MaskMode:     config.MaskStrict,
		RemoteBridge: true,
	}); err != nil {
		t.Fatal(err)
	}
	sockPath := filepath.Join(liveDir, "remote.sock")
	addr, err := net.ResolveUnixAddr("unix", sockPath)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.ListenUnix("unix", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	if err := os.Chmod(sockPath, 0o600); err != nil {
		t.Fatal(err)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, aErr := ln.AcceptUnix()
			if aErr != nil {
				return
			}
			go func(c *net.UnixConn) {
				defer c.Close()
				typ, _, _, rErr := remoteproto.ReadFrame(c, 4096)
				if rErr != nil || typ != "bridge" {
					return
				}
				_, _ = remoteproto.WriteFrame(c, "status", remoteproto.BridgeStatus{
					Attached: true,
					Peer:     "127.0.0.1:9000\x1b[31m",
					RemoteID: "alice@host\x1b]0;pwn\x07",
					Policy:   "/tmp/pol\x1b[2J.json",
				}, 4096)
			}(conn)
		}
	}()

	// Running sandbox whose remote bridge crashed (no remote.sock present).
	crashedDir := filepath.Join(shortBase, "run", "crashed")
	if err := os.MkdirAll(crashedDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := config.SaveRunMeta(filepath.Join(crashedDir, "run.meta"), config.RunMeta{
		Sandbox:      "agbox-crashed",
		OwnerPID:     os.Getpid(),
		Agent:        "opencode",
		Mode:         config.RunModeCmd,
		MaskMode:     config.MaskStrict,
		RemoteBridge: true,
	}); err != nil {
		t.Fatal(err)
	}

	stdout.Reset()
	stderr.Reset()
	if rc := app.dispatch(ctx, []string{"status"}); rc != 0 {
		t.Fatalf("status failed: rc=%d stderr=%s", rc, stderr.String())
	}
	_ = ln.Close()
	<-done

	out := stdout.String()
	if strings.Contains(out, "\x1b") || strings.Contains(out, "\x07") {
		t.Fatalf("status output leaked raw ANSI or control bytes:\n%q", out)
	}
	if !strings.Contains(out, "agbox-live: connected (") {
		t.Errorf("expected agbox-live connected line in status output:\n%s", out)
	}
	if !strings.Contains(out, "agbox-crashed: error (") {
		t.Errorf("expected crashed bridge error line in status output:\n%s", out)
	}
}
