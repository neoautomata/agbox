package cli

import (
	"bufio"
	"cmp"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"agbox/internal/config"
	"agbox/internal/mounttab"
	"agbox/internal/msb"
	"agbox/internal/pathsec"
	"agbox/internal/persist"
	"agbox/internal/vcsfuse"
)

func (a *appRuntime) reapOrphanRuns(ctx context.Context) {
	if a.MSB == nil {
		return
	}
	lsRes, err := a.MSB.Run(ctx, msb.CommandRequest{Args: []string{"ls"}})
	if err != nil {
		return
	}
	for _, sb := range msb.ParseSandboxList(lsRes.Stdout) {
		if !isRunSandboxName(sb.Name) {
			continue
		}
		dirID, dErr := runDirIDFromSandbox(sb.Name)
		if dErr != nil {
			continue
		}
		runDir := filepath.Join(a.Env.DataDir, "run", dirID)
		if hasMarker(filepath.Join(runDir, "detached")) ||
			hasMarker(filepath.Join(runDir, "suspended")) ||
			hasMarker(filepath.Join(runDir, "deleting")) {
			continue
		}
		meta, mErr := config.LoadRunMeta(filepath.Join(runDir, "run.meta"))
		ownerPID := meta.OwnerPID
		if (mErr != nil || ownerPID <= 0) && isDigits(dirID) {
			ownerPID, _ = strconv.Atoi(dirID)
		}
		if ownerPID <= 0 || ownerPID == a.PID || isPIDAlive(ownerPID) {
			continue
		}
		flushProfile := mErr == nil && meta.Profile != "" && sb.Running
		if rmRes, rmErr := a.destroySandbox(ctx, sb.Name, flushProfile, true); rmErr != nil {
			a.warnf("Could not reap orphan sandbox %s: %v", sb.Name, formatMSBError("msb rm", rmRes, rmErr))
		}
		if _, sErr := os.Lstat(runDir); sErr == nil {
			if tdErr := mounttab.TeardownFilterDir(runDir, a.MountCtl); tdErr != nil {
				a.warnf("Could not delete orphan run directory %s: %v", runDir, tdErr)
			}
		}
	}
}

func (a *appRuntime) reapStaleFilterDirs(ctx context.Context) {
	runRoot := filepath.Join(a.Env.DataDir, "run")
	entries, err := os.ReadDir(runRoot)
	if err != nil {
		return
	}
	if a.MSB == nil {
		return
	}
	lsRes, lErr := a.MSB.Run(ctx, msb.CommandRequest{Args: []string{"ls"}})
	if lErr != nil {
		return
	}
	activeSandboxes := make(map[string]bool)
	for _, sb := range msb.ParseSandboxList(lsRes.Stdout) {
		activeSandboxes[sb.Name] = true
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		dirID := entry.Name()
		dirPath := filepath.Join(runRoot, dirID)
		if hasMarker(filepath.Join(dirPath, "detached")) ||
			hasMarker(filepath.Join(dirPath, "suspended")) ||
			hasMarker(filepath.Join(dirPath, "deleting")) {
			continue
		}
		meta, mErr := config.LoadRunMeta(filepath.Join(dirPath, "run.meta"))
		sbx := meta.Sandbox
		if sbx == "" {
			sbx, _ = sandboxFromRunDirID(dirID)
		}
		if sbx != "" && activeSandboxes[sbx] {
			continue
		}
		ownerPID := meta.OwnerPID
		if (mErr != nil || ownerPID <= 0) && isDigits(dirID) {
			ownerPID, _ = strconv.Atoi(dirID)
		}
		if ownerPID > 0 && (ownerPID == a.PID || isPIDAlive(ownerPID)) {
			continue
		}
		if tdErr := mounttab.TeardownFilterDir(dirPath, a.MountCtl); tdErr != nil {
			a.warnf("Could not delete stale run directory %s: %v", dirPath, tdErr)
		}
	}
}

func hasMarker(path string) bool {
	info, err := os.Lstat(path)
	return err == nil && info.Mode().IsRegular()
}

func writeMarkerAtomic(path, content string) error {
	dir := filepath.Dir(path)
	if err := config.EnsurePrivateDir(dir); err != nil {
		return err
	}
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return fmt.Errorf("refusing non-regular marker %q", path)
		}
	}
	tmp, err := os.CreateTemp(dir, ".marker-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpPath)
		}
	}()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := io.WriteString(tmp, content); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return err
	}
	cleanup = false
	return nil
}

func isPIDAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	err := syscall.Kill(pid, 0)
	return err == nil || errors.Is(err, syscall.EPERM)
}

func (a *appRuntime) suspend(ctx context.Context, args []string) error {
	opts, err := parseSuspendArgs(args)
	if err != nil {
		return err
	}
	if err := a.requireSetup(opts.AllowRoot); err != nil {
		return err
	}
	if err := config.EnsurePrivateDir(a.Env.DataDir); err != nil {
		return fmt.Errorf("prepare data dir: %w", err)
	}

	dirID, err := runDirIDFromSandbox(opts.Sandbox)
	if err != nil {
		return err
	}
	runFilterDir := filepath.Join(a.Env.DataDir, "run", dirID)

	lsRes, err := a.MSB.Run(ctx, msb.CommandRequest{Args: []string{"ls"}})
	if err != nil {
		return formatMSBError("list sandboxes", lsRes, err)
	}
	sb, exists := msb.FindSandbox(msb.ParseSandboxList(lsRes.Stdout), opts.Sandbox)
	if !exists {
		return fmt.Errorf("sandbox %q does not exist", opts.Sandbox)
	}

	suspendedPath := filepath.Join(runFilterDir, "suspended")
	if !sb.Running {
		if hasMarker(suspendedPath) {
			a.logf("Sandbox %s is already suspended. Run 'agbox resume %s' to restart it.", opts.Sandbox, opts.Sandbox)
			return nil
		}
		return fmt.Errorf("sandbox %q is already stopped and has no suspended state", opts.Sandbox)
	}

	if err := config.EnsurePrivateDir(runFilterDir); err != nil {
		return err
	}
	metaLock, err := lockRunMeta(runFilterDir)
	if err != nil {
		return err
	}
	defer metaLock.unlock()

	meta, err := config.LoadRunMeta(filepath.Join(runFilterDir, "run.meta"))
	if err != nil {
		return fmt.Errorf("load run metadata for %q: %w", opts.Sandbox, err)
	}
	if meta.Sandbox != opts.Sandbox {
		return fmt.Errorf("metadata sandbox mismatch in %s: got %q, want %q", runFilterDir, meta.Sandbox, opts.Sandbox)
	}

	a.logf("Suspending %s...", opts.Sandbox)
	stopRes, err := a.MSB.Run(ctx, msb.CommandRequest{Args: stopSandboxArgs(opts.Sandbox, meta.Profile != "")})
	if err != nil {
		return formatMSBError("stop sandbox "+opts.Sandbox, stopRes, err)
	}

	meta.Continue = false
	meta.ContinueSession = ""
	if err := config.SaveRunMeta(suspendedPath, meta); err != nil {
		return fmt.Errorf("save suspended metadata: %w", err)
	}
	_ = os.Remove(filepath.Join(runFilterDir, "detached"))
	if err := mounttab.UnmountFilterDir(runFilterDir, a.MountCtl); err != nil {
		return err
	}

	a.logf("Suspended %s (root disk preserved, FUSE shares unmounted). Resume with 'agbox resume %s'.", opts.Sandbox, opts.Sandbox)
	return nil
}

func (a *appRuntime) resume(ctx context.Context, args []string) error {
	opts, err := parseResumeArgs(args)
	if err != nil {
		return err
	}
	if err := a.requireSetup(opts.AllowRoot); err != nil {
		return err
	}
	return a.resumeSandbox(ctx, opts)
}

func (a *appRuntime) resumeSandbox(ctx context.Context, opts resumeOpts) error {
	if err := config.EnsurePrivateDir(a.Env.DataDir); err != nil {
		return fmt.Errorf("prepare data dir: %w", err)
	}

	dirID, err := runDirIDFromSandbox(opts.Sandbox)
	if err != nil {
		return err
	}
	runFilterDir := filepath.Join(a.Env.DataDir, "run", dirID)
	if info, sErr := os.Lstat(runFilterDir); sErr == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return fmt.Errorf("refusing non-directory run path %q", runFilterDir)
		}
	}

	lsRes, err := a.MSB.Run(ctx, msb.CommandRequest{Args: []string{"ls"}})
	if err != nil {
		return formatMSBError("list sandboxes", lsRes, err)
	}
	sandboxes := msb.ParseSandboxList(lsRes.Stdout)
	sb, exists := msb.FindSandbox(sandboxes, opts.Sandbox)
	if !exists {
		return fmt.Errorf("sandbox %q does not exist", opts.Sandbox)
	}
	if sb.Running {
		return fmt.Errorf("sandbox %q is already running", opts.Sandbox)
	}

	suspendedPath := filepath.Join(runFilterDir, "suspended")
	meta, err := config.LoadRunMeta(suspendedPath)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("sandbox %q has no suspended state to resume", opts.Sandbox)
		}
		return fmt.Errorf("load suspended metadata: %w", err)
	}
	if meta.Sandbox != opts.Sandbox {
		return fmt.Errorf("suspended metadata sandbox mismatch: got %q, want %q", meta.Sandbox, opts.Sandbox)
	}
	if meta.Profile != "" {
		if _, pErr := persist.ValidateProfileName(meta.Profile); pErr != nil {
			return pErr
		}
	}
	if meta.ContinueSession != "" {
		if _, sErr := persist.ValidateSessionID(meta.ContinueSession); sErr != nil {
			return sErr
		}
	}
	if opts.Continue || opts.ContinueSession != "" {
		if meta.Mode == config.RunModeServe || meta.Mode == config.RunModeCmd {
			return errors.New("cannot combine --continue or --session with --serve or --cmd")
		}
		if (meta.RemoteControl || meta.Mode == config.RunModeRemoteControl) && (opts.Detach || a.IsTTY == nil || !a.IsTTY()) {
			return errors.New("cannot combine --continue or --session with detached --remote-control")
		}
	}

	if meta.RemoteControl && (meta.Mode == "" || meta.Mode == config.RunModeTUI) && (opts.Detach || a.IsTTY == nil || !a.IsTTY()) {
		meta.Mode = config.RunModeRemoteControl
	}
	if meta.Mode == config.RunModeTUI && (a.IsTTY == nil || !a.IsTTY()) {
		return errors.New("not a TTY. Pass -d to resume a detached session, or run from an interactive terminal")
	}

	seenIdx := make(map[int]bool, len(meta.Shares))
	seenGuest := make(map[string]bool, len(meta.Shares))
	checkTargets := make([]pathsec.ShareTarget, 0, len(meta.Shares))
	for _, sh := range meta.Shares {
		if sh.Index < 0 || seenIdx[sh.Index] {
			return fmt.Errorf("invalid or duplicate share index %d in suspended metadata", sh.Index)
		}
		seenIdx[sh.Index] = true
		if seenGuest[sh.GuestName] {
			return fmt.Errorf("duplicate guest share name %q in suspended metadata", sh.GuestName)
		}
		seenGuest[sh.GuestName] = true
		if meta.WorkspaceHub {
			if _, aErr := pathsec.ValidateGuestAlias(sh.GuestName); aErr != nil {
				return aErr
			}
		} else if !isSafeGuestShareName(sh.GuestName) {
			return fmt.Errorf("invalid guest share name %q in suspended metadata", sh.GuestName)
		}
		if !sh.IsDir && sh.Masked {
			return fmt.Errorf("tampered share metadata: regular file %q cannot be VCS-masked", sh.GuestName)
		}
		if meta.MaskMode == config.MaskStrict && sh.IsDir && !sh.Masked && sh.VCSPolicy != config.VCSAllow && sh.VCSPolicy != config.VCSAllowHooks {
			return fmt.Errorf("tampered share metadata: directory share %q disables VCS masking in strict mode", sh.GuestName)
		}
		if !meta.WorkspaceHub && meta.MaskMode == config.MaskStrict && sh.IsDir && !sh.Masked {
			return fmt.Errorf("tampered share metadata: directory share %q is unmasked in strict mode", sh.GuestName)
		}
		effRO := sh.EffectiveReadOnly(meta.ReadOnly)
		effVCS := sh.EffectiveVCSPolicy()
		if effRO && effVCS == config.VCSAllowHooks {
			return fmt.Errorf("conflicting share metadata for %q: read-only share cannot enable vcs-hooks", sh.GuestName)
		}
		target, vErr := pathsec.ValidateShare(sh.HostPath, a.sharePolicy(effRO))
		if vErr != nil {
			return vErr
		}
		if target.IsDir != sh.IsDir {
			return fmt.Errorf("share type changed on host for %s", sh.HostPath)
		}
		checkTargets = append(checkTargets, target)
	}
	if err := pathsec.CheckDisjointHostPaths(checkTargets); err != nil {
		return err
	}

	effNoSkills := meta.NoSkills || opts.NoSkills
	effNoRules := meta.NoRules || opts.NoRules
	effNoAgentCache := meta.NoAgentCache || opts.NoAgentCache
	hasSkills, hasRules, hasAgents, _, _, _, err := a.inspectGuestReadOnlyMounts(effNoSkills, effNoRules, effNoAgentCache)
	if err != nil {
		return err
	}
	if hasSkills && !meta.SkillsMounted && !effNoSkills {
		a.logf("Note: agbox created %s before global skills existed. Run 'agbox stop %s' and start it again to mount them.", opts.Sandbox, opts.Sandbox)
	}
	if hasRules && !meta.RulesMounted && !effNoRules {
		a.logf("Note: agbox created %s before global rules existed. Run 'agbox stop %s' and start it again to mount them.", opts.Sandbox, opts.Sandbox)
	}
	if hasAgents && !meta.AgentsMounted && !effNoAgentCache {
		a.logf("Note: agbox created %s before cached agent binaries existed. Run 'agbox stop %s' and start it again to mount them.", opts.Sandbox, opts.Sandbox)
	}

	var profLock *persist.ProfileLock
	defer func() {
		if profLock != nil {
			_ = profLock.Unlock()
		}
	}()
	if meta.Profile != "" {
		var lErr error
		profLock, lErr = persist.LockProfile(a.Env.DataDir, meta.Profile)
		if lErr != nil {
			return lErr
		}
		lsRes, err = a.MSB.Run(ctx, msb.CommandRequest{Args: []string{"ls"}})
		if err != nil {
			return formatMSBError("list sandboxes", lsRes, err)
		}
		sandboxes = msb.ParseSandboxList(lsRes.Stdout)
		sb, exists = msb.FindSandbox(sandboxes, opts.Sandbox)
		if !exists {
			return fmt.Errorf("sandbox %q does not exist", opts.Sandbox)
		}
		if sb.Running {
			return fmt.Errorf("sandbox %q is already running", opts.Sandbox)
		}
		if err := a.checkProfileNotActive(meta.Profile, opts.Sandbox, sandboxes); err != nil {
			return err
		}
		volName := persist.FormatProfileVolumeName(meta.Profile)
		volExists, vErr := msb.VolumeExists(ctx, a.MSB, volName)
		if vErr != nil {
			return vErr
		}
		if !volExists {
			return fmt.Errorf("profile volume %q for %s no longer exists", volName, opts.Sandbox)
		}
	}

	if err := config.EnsurePrivateDir(runFilterDir); err != nil {
		return err
	}

	willDetach := !opts.Supervised && ((meta.Mode == config.RunModeServe && (opts.Detach || a.IsTTY == nil || !a.IsTTY())) ||
		meta.Mode == config.RunModeRemoteControl)

	runCtx, cancelRun := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	keepAlive := false
	suspendAfter := false
	mountsActive := false
	sandboxStarted := false
	var cleanupOnce sync.Once
	cleanup := func() {
		cleanupOnce.Do(func() {
			if keepAlive || hasMarker(filepath.Join(runFilterDir, "deleting")) {
				cancelRun()
				return
			}
			if suspendAfter {
				cancelRun()
				a.suspendSandboxOnExit(opts.Sandbox, runFilterDir, meta)
				return
			}
			cancelRun()
			if sandboxStarted {
				stopCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
				stopRes, stopErr := a.MSB.Run(stopCtx, msb.CommandRequest{Args: stopSandboxArgs(opts.Sandbox, meta.Profile != "")})
				cancel()
				if stopErr != nil {
					a.warnf("Could not stop sandbox %s after failed resume: %v", opts.Sandbox, formatMSBError("msb stop", stopRes, stopErr))
				}
			}
			if mountsActive {
				if uErr := mounttab.UnmountFilterDir(runFilterDir, a.MountCtl); uErr != nil {
					a.warnf("Could not unmount shares in %s: %v", runFilterDir, uErr)
				}
			}
		})
	}
	defer cleanup()

	if meta.WorkspaceHub {
		if !dataDirSupportsFilter(a.Env.DataDir) {
			return fmt.Errorf("DATA_DIR (%s) contains unsupported characters for FUSE mounts", a.Env.DataDir)
		}
		if a.StartHub == nil {
			return errors.New("FUSE Workspace Hub starter is not configured")
		}
		wsDir := filepath.Join(runFilterDir, "ws")
		wsSock := filepath.Join(runFilterDir, "ws.sock")
		wsPIDFile := filepath.Join(runFilterDir, "ws.pid")
		if err := config.EnsurePrivateDir(wsDir); err != nil {
			return err
		}
		initialHub := make([]vcsfuse.HubShareConfig, len(meta.Shares))
		for idx, sh := range meta.Shares {
			initialHub[idx] = vcsfuse.HubShareConfig{
				GuestName: sh.GuestName,
				HostPath:  sh.HostPath,
				ReadOnly:  sh.EffectiveReadOnly(meta.ReadOnly),
				VCSPolicy: sh.EffectiveVCSPolicy(),
			}
		}
		if _, fErr := a.StartHub(wsDir, wsSock, wsPIDFile, initialHub, !willDetach); fErr != nil {
			return fmt.Errorf("remount FUSE Workspace Hub for %s: %w", opts.Sandbox, fErr)
		}
		mountsActive = true
	} else {
		for _, sh := range meta.Shares {
			if !sh.Masked {
				continue
			}
			if !dataDirSupportsFilter(a.Env.DataDir) {
				return fmt.Errorf("DATA_DIR (%s) contains unsupported characters for FUSE mounts", a.Env.DataDir)
			}
			if a.StartFilter == nil {
				return errors.New("FUSE filter starter is not configured")
			}
			mntDir := filepath.Join(runFilterDir, fmt.Sprintf("m%d", sh.Index))
			pidFile := filepath.Join(runFilterDir, fmt.Sprintf("m%d.pid", sh.Index))
			if err := config.EnsurePrivateDir(mntDir); err != nil {
				return err
			}
			if _, fErr := a.StartFilter(sh.HostPath, mntDir, pidFile, !willDetach); fErr != nil {
				return fmt.Errorf("remount FUSE filter for %s: %w", sh.HostPath, fErr)
			}
			mountsActive = true
		}
	}

	a.logf("Resuming %s (%d share(s))...", opts.Sandbox, len(meta.Shares))
	startRes, err := a.MSB.Run(runCtx, msb.CommandRequest{Args: []string{"start", opts.Sandbox}})
	if err != nil {
		return formatMSBError("start sandbox "+opts.Sandbox, startRes, err)
	}
	sandboxStarted = true

	meta.OwnerPID = a.PID
	meta.Continue = opts.Continue
	meta.ContinueSession = opts.ContinueSession
	if err := config.SaveRunMeta(filepath.Join(runFilterDir, "run.meta"), meta); err != nil {
		return fmt.Errorf("write run metadata: %w", err)
	}
	if err := os.Remove(suspendedPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("clear suspended marker: %w", err)
	}
	suspendAfter = true

	if err := a.ensureGuestUser(runCtx, opts.Sandbox); err != nil {
		return err
	}
	if meta.AgentsMounted && !effNoAgentCache && hasAgents {
		if err := a.setupGuestAgents(runCtx, opts.Sandbox); err != nil {
			return err
		}
	}
	if meta.SkillsMounted && !effNoSkills && hasSkills {
		if err := a.setupGuestSkills(runCtx, opts.Sandbox); err != nil {
			return err
		}
	}
	if meta.RulesMounted && !effNoRules && hasRules {
		if err := a.setupGuestRules(runCtx, opts.Sandbox); err != nil {
			return err
		}
	}
	if meta.Profile != "" {
		if err := a.setupGuestProfile(runCtx, opts.Sandbox); err != nil {
			return err
		}
	}
	if !meta.NoAuth && !opts.NoAuth {
		if err := a.pushAuth(runCtx, opts.Sandbox, meta.Agent); err != nil {
			return err
		}
	}
	if err := a.pushKeys(runCtx, opts.Sandbox); err != nil {
		return err
	}

	detachedMarker := filepath.Join(runFilterDir, "detached")
	execErr := a.execSession(runCtx, opts.Sandbox, meta, willDetach, false, opts.Supervised)
	if hasMarker(suspendedPath) || hasMarker(filepath.Join(runFilterDir, "deleting")) {
		keepAlive = true
		return nil
	}
	if execErr != nil {
		if opts.Supervised && runCtx.Err() != nil {
			suspendAfter = true
			return nil
		}
		return execErr
	}
	if willDetach {
		if err := writeMarkerAtomic(detachedMarker, fmt.Sprintf("%d\n", a.PID)); err != nil {
			return fmt.Errorf("mark detached session: %w", err)
		}
		keepAlive = true
		return nil
	}
	suspendAfter = true
	return nil
}

func (a *appRuntime) stop(ctx context.Context, args []string) error {
	name, allowRoot, err := parseStopOpts(args)
	if err != nil {
		return err
	}
	if err := a.verifyUser(allowRoot); err != nil {
		return err
	}
	if err := a.ensureMSB(); err != nil {
		return err
	}

	dirID, err := runDirIDFromSandbox(name)
	if err != nil {
		return err
	}
	runFilterDir := filepath.Join(a.Env.DataDir, "run", dirID)

	info, lstatErr := os.Lstat(runFilterDir)
	hadRunDir := lstatErr == nil && info.IsDir() && (info.Mode()&os.ModeSymlink) == 0

	hasProfile := false
	isSuspended := false
	deletingPath := filepath.Join(runFilterDir, "deleting")
	if hadRunDir {
		suspPath := filepath.Join(runFilterDir, "suspended")
		isSuspended = hasMarker(suspPath)
		if meta, mErr := config.LoadRunMeta(filepath.Join(runFilterDir, "run.meta")); mErr == nil && meta.Profile != "" {
			hasProfile = true
		} else if meta, mErr := config.LoadRunMeta(suspPath); mErr == nil && meta.Profile != "" {
			hasProfile = true
		}
		if mErr := writeMarkerAtomic(deletingPath, name+"\n"); mErr != nil {
			a.warnf("Could not write deleting marker for %s: %v", name, mErr)
		}
	}

	rmRes, rmErr := a.destroySandbox(ctx, name, hasProfile && !isSuspended, hadRunDir)
	if rmErr != nil {
		if hadRunDir {
			_ = os.Remove(deletingPath)
		}
		return formatMSBError("stop sandbox "+name, rmRes, rmErr)
	}
	if hadRunDir {
		if tdErr := mounttab.TeardownFilterDir(runFilterDir, a.MountCtl); tdErr != nil {
			return tdErr
		}
	}
	a.logf("Deleted %s.", name)
	return nil
}

func (a *appRuntime) remove(ctx context.Context, args []string) error {
	yes, allowRoot, err := parseRemoveOpts(args)
	if err != nil {
		return err
	}
	if err := a.verifyUser(allowRoot); err != nil {
		return err
	}

	if !yes {
		if a.IsTTY == nil || !a.IsTTY() {
			return errors.New("refusing to delete without --yes in non-interactive mode")
		}
		fmt.Fprintf(a.Stdout, "This deletes all agbox sandboxes (%s, %s*), snapshots (%s:*), profile volumes (%s*), active FUSE mounts, and %s.\n",
			config.BaseSandbox, config.RunPrefix, config.SnapGroup, persist.ProfileVolumePrefix, a.Env.DataDir)
		fmt.Fprintln(a.Stdout, "It does NOT modify the msb binary, your other sandboxes, or cached base images (beyond pruning unused cached images).")
		fmt.Fprint(a.Stdout, "Proceed? [y/N] ")
		sc := bufio.NewScanner(a.Stdin)
		if !sc.Scan() {
			return errors.New("aborted")
		}
		ans := strings.TrimSpace(strings.ToLower(sc.Text()))
		if ans != "y" && ans != "yes" {
			return errors.New("aborted")
		}
	}

	a.cleanupManagedServices(ctx)

	runRoot := filepath.Join(a.Env.DataDir, "run")
	if entries, rErr := os.ReadDir(runRoot); rErr == nil {
		for _, entry := range entries {
			if !entry.IsDir() {
				continue
			}
			dirPath := filepath.Join(runRoot, entry.Name())
			if uErr := mounttab.UnmountFilterDir(dirPath, a.MountCtl); uErr != nil {
				a.warnf("Could not unmount shares in %s: %v", dirPath, uErr)
			}
		}
	}

	if mErr := a.ensureMSB(); mErr != nil {
		a.warnf("Skipping msb resource deletion because msb is unavailable: %v", mErr)
	} else {
		if lsRes, lErr := a.MSB.Run(ctx, msb.CommandRequest{Args: []string{"ls"}}); lErr != nil {
			a.warnf("Could not list sandboxes during remove: %v", formatMSBError("msb ls", lsRes, lErr))
		} else {
			for _, sb := range msb.ParseSandboxList(lsRes.Stdout) {
				if !isAgboxSandboxName(sb.Name) {
					continue
				}
				if rmRes, rmErr := a.destroySandbox(ctx, sb.Name, sb.Running, true); rmErr != nil {
					a.warnf("Could not delete sandbox %s: %v", sb.Name, formatMSBError("msb rm", rmRes, rmErr))
				}
			}
		}

		if volRes, vErr := a.MSB.Run(ctx, msb.CommandRequest{Args: []string{"volume", "ls"}}); vErr != nil {
			a.warnf("Could not list volumes during remove: %v", formatMSBError("msb volume ls", volRes, vErr))
		} else {
			for _, vol := range msb.ParseVolumeList(volRes.Stdout) {
				if !persist.IsProfileVolumeName(vol) {
					continue
				}
				if rmRes, rmErr := a.MSB.Run(ctx, msb.CommandRequest{Args: []string{"volume", "rm", vol}}); rmErr != nil {
					a.warnf("Could not delete profile volume %s: %v", vol, formatMSBError("msb volume rm", rmRes, rmErr))
				}
			}
		}

		if snapRes, sErr := a.MSB.Run(ctx, msb.CommandRequest{Args: []string{"snap", "ls"}}); sErr != nil {
			a.warnf("Could not list snapshots during remove: %v", formatMSBError("msb snap ls", snapRes, sErr))
		} else {
			agboxSnaps, otherGroupSnaps := partitionGroupSnapshots(msb.ParseSnapshotList(snapRes.Stdout))
			remaining := make([]string, 0, len(otherGroupSnaps)+len(agboxSnaps))
			remaining = append(remaining, otherGroupSnaps...)
			remaining = append(remaining, agboxSnaps...)

			// msb rejects deleting the group head while another member exists in the group.
			// Switch the head once to a surviving member or the oldest target, then retry.
			removedSnaps := false
			snapRMFailed := false
			for _, snap := range agboxSnaps {
				rmRes, rmErr := a.MSB.Run(ctx, msb.CommandRequest{Args: []string{"snap", "rm", "--force", snap}})
				if rmErr != nil && isMSBCurrentHeadError(rmRes) {
					nextHead := pickNextSnapshotHead(snap, otherGroupSnaps, remaining)
					if nextHead != "" {
						headRes, headErr := a.MSB.Run(ctx, msb.CommandRequest{Args: []string{"snap", "head", nextHead}})
						if headErr != nil {
							a.warnf("Could not switch snapshot head to %s before deleting %s: %v", nextHead, snap, formatMSBError("msb snap head", headRes, headErr))
							snapRMFailed = true
							continue
						}
						rmRes, rmErr = a.MSB.Run(ctx, msb.CommandRequest{Args: []string{"snap", "rm", "--force", snap}})
					}
				}
				if rmErr != nil {
					a.warnf("Could not delete snapshot %s: %v", snap, formatMSBError("msb snap rm", rmRes, rmErr))
					snapRMFailed = true
					continue
				}
				removedSnaps = true
				remaining = slices.DeleteFunc(remaining, func(s string) bool { return s == snap })
			}
			// msb snap reindex does not prune missing SQLite rows.
			// Delete the group directory only when every agbox snapshot removal succeeded and no user member remains.
			if a.Env.MSBHome != "" && !snapRMFailed && len(otherGroupSnaps) == 0 {
				snapGroupDir := filepath.Join(a.Env.MSBHome, "snapshots", config.SnapGroup)
				if info, stErr := os.Lstat(snapGroupDir); stErr == nil {
					if info.Mode()&os.ModeSymlink != 0 {
						a.warnf("Skipping symlinked snapshot directory %s.", snapGroupDir)
					} else if rErr := os.RemoveAll(snapGroupDir); rErr != nil {
						a.warnf("Could not delete snapshot directory %s: %v", snapGroupDir, rErr)
					} else {
						removedSnaps = true
					}
				} else if !os.IsNotExist(stErr) {
					a.warnf("Could not stat snapshot directory %s: %v", snapGroupDir, stErr)
				}
			}
			if removedSnaps {
				if riRes, riErr := a.MSB.Run(ctx, msb.CommandRequest{Args: []string{"snap", "reindex"}}); riErr != nil {
					a.warnf("Could not reindex snapshots: %v", formatMSBError("msb snap reindex", riRes, riErr))
				}
			}
		}

		if prRes, prErr := a.MSB.Run(ctx, msb.CommandRequest{Args: []string{"image", "prune", "-y"}}); prErr != nil {
			a.warnf("Could not prune unused cached images: %v", formatMSBError("msb image prune", prRes, prErr))
		}
	}

	if entries, rErr := os.ReadDir(runRoot); rErr == nil {
		for _, entry := range entries {
			if !entry.IsDir() {
				continue
			}
			dirPath := filepath.Join(runRoot, entry.Name())
			if tdErr := mounttab.TeardownFilterDir(dirPath, a.MountCtl); tdErr != nil {
				return tdErr
			}
		}
	}

	if info, stErr := os.Lstat(a.Env.DataDir); stErr == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("refusing to delete symlinked data dir %q", a.Env.DataDir)
		}
		if err := mounttab.TeardownFilterDir(a.Env.DataDir, a.MountCtl); err != nil {
			return err
		}
	} else if !os.IsNotExist(stErr) {
		return stErr
	}

	a.logf("Removed agbox state (%s).", a.Env.DataDir)
	return nil
}

func (a *appRuntime) status(ctx context.Context, args []string) error {
	opts, err := parseStatusArgs(args)
	if err != nil {
		return err
	}
	if err := a.verifyUser(opts.AllowRoot); err != nil {
		return err
	}

	fmt.Fprintln(a.Stdout, "== agbox config ==")
	fmt.Fprintf(a.Stdout, "data_dir: %s\n", a.Env.DataDir)
	fmt.Fprintf(a.Stdout, "mask_vcs_default: %s\n", a.Env.MaskVCS)
	if st, err := config.LoadFile(a.Env.ConfigFile); err == nil && st.Snapshot != "" {
		fmt.Fprintf(a.Stdout, "base_snapshot: %s\n", st.Snapshot)
		fmt.Fprintf(a.Stdout, "base_agent: %s\n", defaultStr(st.Agent, "both"))
		fmt.Fprintf(a.Stdout, "base_image: %s\n", st.Image)
		if st.Categories != "" {
			fmt.Fprintf(a.Stdout, "categories: %s\n", st.Categories)
		}
	} else if err != nil && !os.IsNotExist(err) {
		fmt.Fprintf(a.Stdout, "base_snapshot: error (%v)\n", err)
	} else {
		fmt.Fprintln(a.Stdout, "base_snapshot: not configured")
	}

	_ = a.ensureMSB()
	a.printPersistenceStatus(ctx)
	a.printServiceStatus(ctx)

	if a.MSB != nil {
		if lsRes, lErr := a.MSB.Run(ctx, msb.CommandRequest{Args: []string{"ls"}}); lErr == nil {
			fmt.Fprintln(a.Stdout, "\n== sandboxes ==")
			_, _ = a.Stdout.Write([]byte(lsRes.Stdout))
		}
		if snapRes, sErr := a.MSB.Run(ctx, msb.CommandRequest{Args: []string{"snap", "ls"}}); sErr == nil {
			fmt.Fprintln(a.Stdout, "\n== snapshots ==")
			_, _ = a.Stdout.Write([]byte(snapRes.Stdout))
		}
		if dfRes, dErr := a.MSB.Run(ctx, msb.CommandRequest{Args: []string{"df"}}); dErr == nil {
			fmt.Fprintln(a.Stdout, "\n== storage ==")
			_, _ = a.Stdout.Write([]byte(dfRes.Stdout))
		}
	}
	return nil
}

func isAgboxSandboxName(name string) bool {
	return name == config.BaseSandbox || isRunSandboxName(name)
}

func isAgboxSnapshotName(snap string) bool {
	if !strings.HasPrefix(snap, config.SnapGroup+":v") {
		return false
	}
	return isDigits(strings.TrimPrefix(snap, config.SnapGroup+":v"))
}

func agboxSnapshotVersion(snap string) (int, bool) {
	if !isAgboxSnapshotName(snap) {
		return 0, false
	}
	ver, err := strconv.Atoi(strings.TrimPrefix(snap, config.SnapGroup+":v"))
	if err != nil {
		return 0, false
	}
	return ver, true
}

func sortAgboxSnapshotsDesc(snaps []string) {
	slices.SortFunc(snaps, func(a, b string) int {
		va, oka := agboxSnapshotVersion(a)
		vb, okb := agboxSnapshotVersion(b)
		if oka && okb && va != vb {
			return cmp.Compare(vb, va)
		}
		if oka != okb {
			if oka {
				return -1
			}
			return 1
		}
		return cmp.Compare(b, a)
	})
}

func partitionGroupSnapshots(snaps []string) (agboxSnaps, otherGroupSnaps []string) {
	seen := make(map[string]bool, len(snaps))
	groupPrefix := config.SnapGroup + ":"
	for _, raw := range snaps {
		snap := strings.TrimSpace(raw)
		if snap == "" || seen[snap] {
			continue
		}
		seen[snap] = true
		if !strings.HasPrefix(snap, groupPrefix) {
			continue
		}
		if strings.TrimPrefix(snap, groupPrefix) == "" {
			continue
		}
		if isAgboxSnapshotName(snap) {
			agboxSnaps = append(agboxSnaps, snap)
		} else {
			otherGroupSnaps = append(otherGroupSnaps, snap)
		}
	}
	sortAgboxSnapshotsDesc(agboxSnaps)
	return agboxSnaps, otherGroupSnaps
}

func isMSBCurrentHeadError(res msb.CommandResult) bool {
	combined := strings.ToLower(res.Stderr + "\n" + res.Stdout)
	return strings.Contains(combined, "cannot remove current head")
}

func pickNextSnapshotHead(snap string, otherGroupSnaps, remaining []string) string {
	for _, candidate := range otherGroupSnaps {
		if candidate != "" && candidate != snap {
			return candidate
		}
	}
	for i := len(remaining) - 1; i >= 0; i-- {
		if remaining[i] != "" && remaining[i] != snap {
			return remaining[i]
		}
	}
	return ""
}
