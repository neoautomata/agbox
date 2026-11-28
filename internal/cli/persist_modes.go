package cli

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"agbox/internal/config"
	"agbox/internal/mounttab"
	"agbox/internal/msb"
	"agbox/internal/pathsec"
	"agbox/internal/persist"
)

func (a *appRuntime) auth(ctx context.Context, args []string) error {
	opts, err := parseAuthArgs(args)
	if err != nil {
		return err
	}
	switch opts.Action {
	case "status":
		if err := a.verifyUser(opts.AllowRoot); err != nil {
			return err
		}
		if err := config.EnsurePrivateDir(a.Env.DataDir); err != nil {
			return fmt.Errorf("prepare data dir: %w", err)
		}
		st, err := persist.AuthStatus(a.Env.DataDir)
		if err != nil {
			return err
		}
		for _, ag := range []string{"antigravity", "opencode"} {
			stateStr := "not configured"
			if st[ag] {
				stateStr = "configured"
			}
			fmt.Fprintf(a.Stdout, "%s: %s\n", ag, stateStr)
		}
		return nil

	case "logout":
		if err := a.verifyUser(opts.AllowRoot); err != nil {
			return err
		}
		if err := config.EnsurePrivateDir(a.Env.DataDir); err != nil {
			return fmt.Errorf("prepare data dir: %w", err)
		}
		if err := persist.RemoveAuth(a.Env.DataDir, opts.Target); err != nil {
			return err
		}
		a.logf("Deleted saved %s credentials from %s.", opts.Target, filepath.Join(a.Env.DataDir, "auth"))
		return nil
	}

	if err := a.requireSetup(opts.AllowRoot); err != nil {
		return err
	}
	if err := config.EnsurePrivateDir(a.Env.DataDir); err != nil {
		return fmt.Errorf("prepare data dir: %w", err)
	}
	baseState, err := a.requireBase(ctx)
	if err != nil {
		return err
	}

	agent := opts.Target
	if agent == "" {
		if baseState.Agent == "antigravity" || baseState.Agent == "opencode" {
			agent = baseState.Agent
		} else {
			return errors.New("base includes both agents. Specify 'agbox auth antigravity' or 'agbox auth opencode'")
		}
	}
	if baseState.Agent != "" && baseState.Agent != "both" && baseState.Agent != agent {
		return fmt.Errorf("the base snapshot contains only agent=%s. Run 'agbox create-base --force %s' or 'agbox create-base --force both'", baseState.Agent, agent)
	}
	if a.IsTTY == nil || !a.IsTTY() {
		return errors.New("agbox auth requires an interactive TTY")
	}

	authCtx, authSandbox, cleanup, err := a.startDisposableVM(
		ctx,
		"auth",
		baseState.Snapshot,
		agent,
		config.RunModeTUI,
		"Booting disposable login microVM %s (zero host shares)...",
	)
	if err != nil {
		return err
	}
	defer cleanup()

	// Seed saved credentials for this agent so multi-provider logins keep prior entries.
	if err := a.pushAuth(authCtx, authSandbox, agent); err != nil {
		return err
	}
	if err := a.pushKeys(authCtx, authSandbox); err != nil {
		return err
	}

	var loginCmd string
	if agent == "opencode" {
		a.logf("Complete provider login in OpenCode.")
		loginCmd = msb.KeyLoaderPrefix + " cd /workspace && opencode auth login"
	} else {
		a.logf("Open the printed URL. Paste the verification code. Run /exit to save credentials.")
		loginCmd = msb.KeyLoaderPrefix + " cd /workspace && agy"
	}

	execArgs := msb.BuildExecArgs(msb.ExecCmdOpts{
		Sandbox: authSandbox,
		TTY:     true,
		User:    config.GuestUser,
		Env:     msb.GuestEnvFlags(),
		Command: []string{"sh", "-c", loginCmd},
	})
	_, _ = a.MSB.Run(authCtx, msb.CommandRequest{
		Args:        execArgs,
		Interactive: true,
	})
	if authCtx.Err() != nil {
		return authCtx.Err()
	}

	capScript, err := persist.BuildAuthCaptureScript(agent)
	if err != nil {
		return err
	}
	capArgs := msb.BuildExecArgs(msb.ExecCmdOpts{
		Sandbox: authSandbox,
		User:    config.GuestUser,
		Stream:  true,
		NoStdin: true,
		Command: []string{"sh", "-c", capScript},
	})
	capRes, err := a.MSB.Run(authCtx, msb.CommandRequest{Args: capArgs})
	if err != nil {
		return formatMSBStderrOnlyError(fmt.Sprintf("capture %s credentials", agent), capRes.Stderr, err)
	}
	bundle, err := persist.ParseAuthCapture(agent, capRes.Stdout)
	if err != nil {
		return err
	}
	if err := persist.SaveAuthBundle(a.Env.DataDir, bundle); err != nil {
		return fmt.Errorf("save %s credentials: %w", agent, err)
	}
	a.logf("Saved %s login credentials in %s.", agent, filepath.Join(a.Env.DataDir, "auth", agent))
	return nil
}

func (a *appRuntime) skills(ctx context.Context, args []string) error {
	_ = ctx
	opts, err := parseSkillsArgs(args)
	if err != nil {
		return err
	}
	if err := a.verifyUser(opts.AllowRoot); err != nil {
		return err
	}
	if err := config.EnsurePrivateDir(a.Env.DataDir); err != nil {
		return fmt.Errorf("prepare data dir: %w", err)
	}
	skillsDir := filepath.Join(a.Env.DataDir, "skills")

	switch opts.Action {
	case "list":
		names, err := persist.InspectSkillsDir(skillsDir)
		if err != nil {
			return err
		}
		if len(names) == 0 {
			fmt.Fprintf(a.Stdout, "No global skills installed in %s.\n", skillsDir)
			return nil
		}
		for _, n := range names {
			fmt.Fprintln(a.Stdout, n)
		}
		return nil

	case "add":
		name, err := persist.InstallSkill(skillsDir, opts.Target, opts.Force)
		if err != nil {
			return err
		}
		a.logf("Installed global skill %q in %s.", name, filepath.Join(skillsDir, name))
		return nil

	case "rm":
		if err := persist.RemoveSkill(skillsDir, opts.Target); err != nil {
			return err
		}
		a.logf("Deleted global skill %q.", opts.Target)
		return nil
	}
	return nil
}

func (a *appRuntime) rules(ctx context.Context, args []string) error {
	_ = ctx
	opts, err := parseRulesArgs(args)
	if err != nil {
		return err
	}
	if err := a.verifyUser(opts.AllowRoot); err != nil {
		return err
	}
	if err := config.EnsurePrivateDir(a.Env.DataDir); err != nil {
		return fmt.Errorf("prepare data dir: %w", err)
	}
	rulesDir := filepath.Join(a.Env.DataDir, "rules")

	switch opts.Action {
	case "list":
		names, err := persist.InspectRulesDir(rulesDir)
		if err != nil {
			return err
		}
		if len(names) == 0 {
			fmt.Fprintf(a.Stdout, "No global rules installed in %s.\n", rulesDir)
			return nil
		}
		for _, n := range names {
			fmt.Fprintln(a.Stdout, n)
		}
		return nil

	case "add":
		name, size, err := persist.InstallRule(rulesDir, opts.Target, opts.Name, opts.Force)
		if err != nil {
			return err
		}
		if size > persist.AgyRuleWarnBytes {
			a.warnf("Rule %q is %d bytes. Antigravity truncates single rule files above %d bytes.", name, size, persist.AgyRuleWarnBytes)
		}
		a.logf("Installed global rule %q in %s.", name, filepath.Join(rulesDir, name+".md"))
		return nil

	case "show":
		if opts.Target != "" {
			raw, err := persist.ReadRule(rulesDir, opts.Target)
			if err != nil {
				return err
			}
			_, _ = a.Stdout.Write(raw)
			if len(raw) > 0 && raw[len(raw)-1] != '\n' {
				fmt.Fprintln(a.Stdout)
			}
			return nil
		}
		names, err := persist.InspectRulesDir(rulesDir)
		if err != nil {
			return err
		}
		if len(names) == 0 {
			fmt.Fprintf(a.Stdout, "No global rules installed in %s.\n", rulesDir)
			return nil
		}
		for idx, n := range names {
			raw, rErr := persist.ReadRule(rulesDir, n)
			if rErr != nil {
				return rErr
			}
			if idx > 0 {
				fmt.Fprintln(a.Stdout)
			}
			fmt.Fprintf(a.Stdout, "== %s.md ==\n", n)
			_, _ = a.Stdout.Write(raw)
			if len(raw) > 0 && raw[len(raw)-1] != '\n' {
				fmt.Fprintln(a.Stdout)
			}
		}
		return nil

	case "rm":
		if opts.All {
			if err := persist.RemoveAllRules(rulesDir); err != nil {
				return err
			}
			a.logf("Deleted all global rules from %s.", rulesDir)
			return nil
		}
		if err := persist.RemoveRule(rulesDir, opts.Target); err != nil {
			return err
		}
		a.logf("Deleted global rule %q.", opts.Target)
		return nil
	}
	return nil
}

func (a *appRuntime) profile(ctx context.Context, args []string) error {
	opts, err := parseProfileArgs(args)
	if err != nil {
		return err
	}
	if err := a.verifyUser(opts.AllowRoot); err != nil {
		return err
	}
	if err := config.EnsurePrivateDir(a.Env.DataDir); err != nil {
		return fmt.Errorf("prepare data dir: %w", err)
	}
	if err := a.ensureMSB(); err != nil {
		return err
	}

	switch opts.Action {
	case "list":
		profiles, err := persist.ListProfiles(a.Env.DataDir)
		if err != nil {
			return err
		}
		volRes, vErr := a.MSB.Run(ctx, msb.CommandRequest{Args: []string{"volume", "ls"}})
		if vErr != nil {
			a.warnf("Could not list msb volumes: %v", formatMSBError("msb volume ls", volRes, vErr))
		}
		vols := msb.ParseVolumeList(volRes.Stdout)
		seen := make(map[string]bool, len(profiles))
		for _, pm := range profiles {
			seen[pm.Volume] = true
			fmt.Fprintf(a.Stdout, "%s\tvolume=%s\tsize=%s\n", pm.Name, pm.Volume, pm.Size)
		}
		hasExtra := false
		for _, v := range vols {
			if persist.IsProfileVolumeName(v) && !seen[v] {
				hasExtra = true
				name := strings.TrimPrefix(v, persist.ProfileVolumePrefix)
				fmt.Fprintf(a.Stdout, "%s\tvolume=%s\tsize=unknown\n", name, v)
			}
		}
		if len(profiles) == 0 && !hasExtra {
			fmt.Fprintln(a.Stdout, "No conversation profiles configured.")
		}
		return nil

	case "create":
		lock, err := persist.LockProfile(a.Env.DataDir, opts.Name)
		if err != nil {
			return err
		}
		defer func() { _ = lock.Unlock() }()

		if opts.Size != "" {
			if existing, lErr := persist.ListProfiles(a.Env.DataDir); lErr == nil {
				for _, pm := range existing {
					if pm.Name == opts.Name && pm.Size != "" && !strings.EqualFold(pm.Size, opts.Size) {
						return fmt.Errorf("profile %q already exists with size %s. agbox cannot resize existing profile disks in place", opts.Name, pm.Size)
					}
				}
			}
		}

		size := defaultStr(opts.Size, defaultStr(a.Env.ProfileDisk, config.DefaultProfileDisk))
		volName, err := a.ensureProfileVolume(ctx, opts.Name, size)
		if err != nil {
			return err
		}
		effectiveSize := size
		if existing, lErr := persist.ListProfiles(a.Env.DataDir); lErr == nil {
			for _, pm := range existing {
				if pm.Name == opts.Name && pm.Size != "" {
					effectiveSize = pm.Size
					break
				}
			}
		}
		a.logf("Profile %q is ready (volume=%s, size=%s).", opts.Name, volName, effectiveSize)
		return nil

	case "rm":
		volName := persist.FormatProfileVolumeName(opts.Name)
		profDir := filepath.Join(a.Env.DataDir, "profiles", opts.Name)
		dirExists := false
		if _, stErr := os.Lstat(profDir); stErr == nil {
			dirExists = true
		} else if !os.IsNotExist(stErr) {
			return fmt.Errorf("stat profile directory %s: %w", profDir, stErr)
		}
		volExists, err := msb.VolumeExists(ctx, a.MSB, volName)
		if err != nil {
			return err
		}
		if !dirExists && !volExists {
			return fmt.Errorf("profile %q does not exist", opts.Name)
		}

		lock, err := persist.LockProfile(a.Env.DataDir, opts.Name)
		if err != nil {
			return err
		}
		defer func() { _ = lock.Unlock() }()

		dirExists = false
		if _, stErr := os.Lstat(profDir); stErr == nil {
			dirExists = true
		} else if !os.IsNotExist(stErr) {
			return fmt.Errorf("stat profile directory %s: %w", profDir, stErr)
		}
		volExists, err = msb.VolumeExists(ctx, a.MSB, volName)
		if err != nil {
			return err
		}
		if !dirExists && !volExists {
			return fmt.Errorf("profile %q does not exist", opts.Name)
		}

		lsRes, err := a.MSB.Run(ctx, msb.CommandRequest{Args: []string{"ls"}})
		if err != nil {
			return formatMSBError("list sandboxes", lsRes, err)
		}
		sandboxes := msb.ParseSandboxList(lsRes.Stdout)
		if err := a.checkProfileRemovable(opts.Name, opts.Force, sandboxes); err != nil {
			return err
		}

		if volExists {
			if rmRes, err := a.MSB.Run(ctx, msb.CommandRequest{Args: []string{"volume", "rm", volName}}); err != nil {
				return formatMSBError("delete volume "+volName, rmRes, err)
			}
		}
		if err := persist.RemoveProfileDir(a.Env.DataDir, opts.Name); err != nil {
			return err
		}
		a.logf("Deleted profile %q (%s).", opts.Name, volName)
		return nil
	}
	return nil
}

func (a *appRuntime) ensureProfileVolume(ctx context.Context, profileName, size string) (string, error) {
	volName := persist.FormatProfileVolumeName(profileName)
	exists, err := msb.VolumeExists(ctx, a.MSB, volName)
	if err != nil {
		return "", err
	}
	if exists {
		if existing, lErr := persist.ListProfiles(a.Env.DataDir); lErr == nil {
			for _, pm := range existing {
				if pm.Name == profileName {
					return volName, nil
				}
			}
		}
	}
	if size == "" {
		size = defaultStr(a.Env.ProfileDisk, config.DefaultProfileDisk)
	}
	if !exists {
		createArgs, err := msb.BuildVolumeCreateDiskArgs(volName, size)
		if err != nil {
			return "", err
		}
		a.logf("Creating ext4 profile disk volume %s (%s)...", volName, size)
		if crRes, err := a.MSB.Run(ctx, msb.CommandRequest{Args: createArgs}); err != nil {
			return "", formatMSBError("create profile disk volume "+volName, crRes, err)
		}
	}
	if err := persist.SaveProfileMeta(a.Env.DataDir, persist.ProfileMeta{
		Name:      profileName,
		Volume:    volName,
		Size:      size,
		CreatedAt: a.now().UTC().Format(time.RFC3339),
	}); err != nil {
		if !exists {
			teardownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			rmRes, rmErr := a.MSB.Run(teardownCtx, msb.CommandRequest{Args: []string{"volume", "rm", volName}})
			cancel()
			if rmErr != nil {
				a.warnf("Could not delete profile volume %s: %v", volName, formatMSBError("msb volume rm", rmRes, rmErr))
			}
		}
		return "", fmt.Errorf("save profile metadata: %w", err)
	}
	return volName, nil
}

func scanRunEntries(dataDir string) ([]os.DirEntry, string, error) {
	runRoot := filepath.Join(dataDir, "run")
	entries, err := os.ReadDir(runRoot)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, runRoot, nil
		}
		return nil, runRoot, fmt.Errorf("read run directory %s: %w", runRoot, err)
	}
	return entries, runRoot, nil
}

func (a *appRuntime) checkProfileNotActive(profileName, currentSandbox string, sandboxes []msb.SandboxInfo) error {
	entries, runRoot, err := scanRunEntries(a.Env.DataDir)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		meta, mErr := config.LoadRunMeta(filepath.Join(runRoot, entry.Name(), "run.meta"))
		if mErr != nil || meta.Profile != profileName || meta.Sandbox == currentSandbox {
			continue
		}
		if sb, ok := msb.FindSandbox(sandboxes, meta.Sandbox); ok && sb.Running {
			return fmt.Errorf("profile %q is active in running sandbox %s. Stop or suspend %s first", profileName, meta.Sandbox, meta.Sandbox)
		}
	}
	return nil
}

func (a *appRuntime) checkProfileRemovable(profileName string, force bool, sandboxes []msb.SandboxInfo) error {
	if err := a.checkProfileNotActive(profileName, "", sandboxes); err != nil {
		return err
	}
	if force {
		return nil
	}
	entries, runRoot, err := scanRunEntries(a.Env.DataDir)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		suspPath := filepath.Join(runRoot, entry.Name(), "suspended")
		meta, mErr := config.LoadRunMeta(suspPath)
		if mErr != nil || meta.Profile != profileName {
			continue
		}
		if _, ok := msb.FindSandbox(sandboxes, meta.Sandbox); ok {
			return fmt.Errorf("suspended sandbox %s references profile %q. Run 'agbox stop %s' first or pass --force", meta.Sandbox, profileName, meta.Sandbox)
		}
	}
	return nil
}

func (a *appRuntime) pushAuth(ctx context.Context, sandbox, effectiveAgent string) error {
	var agents []string
	switch effectiveAgent {
	case "antigravity", "opencode":
		agents = []string{effectiveAgent}
	default:
		agents = []string{"antigravity", "opencode"}
	}
	bundle, err := persist.LoadAuthBundle(a.Env.DataDir, agents)
	if err != nil {
		return fmt.Errorf("load saved login credentials: %w", err)
	}
	if bundle.IsEmpty() {
		return nil
	}
	script, err := persist.FormatAuthRestoreScript(bundle)
	if err != nil {
		return fmt.Errorf("format login restore script: %w", err)
	}
	execArgs := msb.BuildExecArgs(msb.ExecCmdOpts{
		Sandbox: sandbox,
		User:    config.GuestUser,
		Command: []string{"sh"},
	})
	if res, err := a.MSB.Run(ctx, msb.CommandRequest{
		Args:  execArgs,
		Stdin: strings.NewReader(script),
	}); err != nil {
		return formatMSBError("stream saved login credentials into "+sandbox, res, err)
	}
	a.logf("Streamed saved login credentials into %s.", sandbox)
	return nil
}

func (a *appRuntime) setupGuestSkills(ctx context.Context, sandbox string) error {
	_, err := a.runGuestRootScript(ctx, sandbox, "bind-mount global skills in "+sandbox, "sh", persist.BuildGuestSkillsMountScript())
	return err
}

func (a *appRuntime) setupGuestRules(ctx context.Context, sandbox string) error {
	_, err := a.runGuestRootScript(ctx, sandbox, "bind-mount global rules in "+sandbox, "sh", persist.BuildGuestRulesMountScript())
	return err
}

func (a *appRuntime) setupGuestProfile(ctx context.Context, sandbox string) error {
	_, err := a.runGuestRootScript(ctx, sandbox, "bind-mount conversation profile in "+sandbox, "sh", persist.BuildGuestProfileMountScript())
	return err
}

func (a *appRuntime) suspendSandboxOnExit(sandbox, runFilterDir string, meta config.RunMeta) {
	if hasMarker(filepath.Join(runFilterDir, "deleting")) {
		return
	}
	metaLock, lockErr := lockRunMeta(runFilterDir)
	if lockErr == nil {
		defer metaLock.unlock()
	}

	savedMeta := meta
	if latest, lErr := config.LoadRunMeta(filepath.Join(runFilterDir, "run.meta")); lErr == nil {
		savedMeta = latest
	}
	savedMeta.Continue = false
	savedMeta.ContinueSession = ""

	teardownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	stopRes, stopErr := a.MSB.Run(teardownCtx, msb.CommandRequest{Args: stopSandboxArgs(sandbox, savedMeta.Profile != "")})
	if stopErr != nil {
		a.warnf("Could not stop persistent sandbox %s: %v", sandbox, formatMSBError("msb stop", stopRes, stopErr))
		return
	}

	suspendedPath := filepath.Join(runFilterDir, "suspended")
	saveErr := config.SaveRunMeta(suspendedPath, savedMeta)
	if saveErr != nil {
		a.warnf("Could not save suspended metadata for %s: %v", sandbox, saveErr)
	} else {
		_ = os.Remove(filepath.Join(runFilterDir, "detached"))
	}
	if uErr := mounttab.UnmountFilterDir(runFilterDir, a.MountCtl); uErr != nil {
		a.warnf("Could not unmount shares in %s: %v", runFilterDir, uErr)
	}
	if saveErr != nil {
		return
	}
	a.logf("Persisted %s (stopped). Resume with 'agbox resume %s' or delete with 'agbox stop %s'.", sandbox, sandbox, sandbox)
}

type shareCompareTuple struct {
	hostPath  string
	guestName string
	isDir     bool
	masked    bool
	readOnly  bool
	vcsPolicy config.VCSPolicy
}

func compareShareTuples(a, b shareCompareTuple) int {
	if c := cmp.Compare(a.hostPath, b.hostPath); c != 0 {
		return c
	}
	if c := cmp.Compare(a.guestName, b.guestName); c != 0 {
		return c
	}
	return cmp.Compare(string(a.vcsPolicy), string(b.vcsPolicy))
}

func sharesMatchRecorded(validated []pathsec.ShareTarget, recorded []config.ShareRecord, useMask bool, metaReadOnly bool) bool {
	if len(validated) != len(recorded) {
		return false
	}
	want := make([]shareCompareTuple, len(validated))
	for i, v := range validated {
		var vcs config.VCSPolicy
		if useMask {
			vcs = v.VCSPolicy
		}
		want[i] = shareCompareTuple{
			hostPath:  v.HostPath,
			guestName: v.GuestName,
			isDir:     v.IsDir,
			masked:    v.IsDir && useMask && v.VCSPolicy == config.VCSMask,
			readOnly:  v.ReadOnly,
			vcsPolicy: vcs,
		}
	}
	got := make([]shareCompareTuple, len(recorded))
	for i, rec := range recorded {
		var vcs config.VCSPolicy
		if useMask {
			vcs = rec.EffectiveVCSPolicy()
		}
		got[i] = shareCompareTuple{
			hostPath:  rec.HostPath,
			guestName: rec.GuestName,
			isDir:     rec.IsDir,
			masked:    rec.Masked,
			readOnly:  rec.EffectiveReadOnly(metaReadOnly),
			vcsPolicy: vcs,
		}
	}
	slices.SortFunc(want, compareShareTuples)
	slices.SortFunc(got, compareShareTuples)
	return slices.Equal(want, got)
}

func (a *appRuntime) resumeFromRunPersist(ctx context.Context, runSandbox, dirID string, baseState config.State, opts runOpts, useMask bool) error {
	runFilterDir := filepath.Join(a.Env.DataDir, "run", dirID)
	suspendedPath := filepath.Join(runFilterDir, "suspended")

	metaLock, err := lockRunMeta(runFilterDir)
	if err != nil {
		return err
	}
	meta, err := config.LoadRunMeta(suspendedPath)
	if err != nil {
		metaLock.unlock()
		return fmt.Errorf("load suspended metadata for %q: %w", runSandbox, err)
	}
	if meta.Sandbox != runSandbox {
		metaLock.unlock()
		return fmt.Errorf("suspended metadata sandbox mismatch: got %q, want %q", meta.Sandbox, runSandbox)
	}
	if meta.Profile != "" {
		metaLock.unlock()
		return fmt.Errorf("suspended sandbox %q uses profile %q and cannot resume with --persist. Run 'agbox resume %s' instead", runSandbox, meta.Profile, runSandbox)
	}
	if !opts.Supervised {
		if opts.NoNet || len(opts.NetSpecs) > 0 {
			metaLock.unlock()
			return fmt.Errorf("cannot change network options when resuming persistent sandbox %q. Run 'agbox stop %s' to recreate it", runSandbox, runSandbox)
		}
		if opts.CPUs != "" || opts.Memory != "" {
			metaLock.unlock()
			return fmt.Errorf("cannot change --cpus or --memory when resuming persistent sandbox %q. Run 'agbox stop %s' to recreate it", runSandbox, runSandbox)
		}
		if opts.ShareHub {
			metaLock.unlock()
			return fmt.Errorf("cannot change --share-hub when resuming persistent sandbox %q. Run 'agbox stop %s' to recreate it", runSandbox, runSandbox)
		}
	}
	if opts.Port != 0 && opts.Port != meta.Port {
		metaLock.unlock()
		return fmt.Errorf("persistent sandbox %q uses port %d, not %d. Run 'agbox stop %s' to recreate it", runSandbox, meta.Port, opts.Port, runSandbox)
	}
	if !opts.Supervised {
		if opts.LockAccess {
			accessConflict := opts.ReadOnly != meta.ReadOnly
			if !accessConflict {
				for _, sh := range meta.Shares {
					if sh.EffectiveReadOnly(meta.ReadOnly) != opts.ReadOnly {
						accessConflict = true
						break
					}
				}
			}
			if accessConflict {
				metaLock.unlock()
				return fmt.Errorf("persistent sandbox %q has different shared paths or mount flags. Use 'agbox share' to modify shares, or 'agbox stop %s' to recreate it", runSandbox, runSandbox)
			}
		}
		if opts.ExplicitMask {
			maskConflict := opts.MaskMode != meta.MaskMode || (opts.MaskMode == config.MaskOff && meta.WorkspaceHub)
			if !maskConflict && opts.LockVCS {
				for _, sh := range meta.Shares {
					if sh.IsDir && sh.EffectiveVCSPolicy() != opts.DefaultVCS {
						maskConflict = true
						break
					}
				}
			}
			if maskConflict {
				metaLock.unlock()
				return fmt.Errorf("persistent sandbox %q has different shared paths or mount flags. Use 'agbox share' to modify shares, or 'agbox stop %s' to recreate it", runSandbox, runSandbox)
			}
		}

		if len(opts.Paths) > 0 || len(opts.ShareSpecs) > 0 {
			validated, vErr := a.resolveRunShareTargets(opts)
			if vErr != nil {
				metaLock.unlock()
				return vErr
			}
			if opts.ReadOnly != meta.ReadOnly || opts.MaskMode != meta.MaskMode || !sharesMatchRecorded(validated, meta.Shares, meta.WorkspaceHub && useMask, meta.ReadOnly) {
				metaLock.unlock()
				return fmt.Errorf("persistent sandbox %q has different shared paths or mount flags. Use 'agbox share' to modify shares, or 'agbox stop %s' to recreate it", runSandbox, runSandbox)
			}
		}
	}

	origMeta := meta
	origMode := meta.Mode
	origCmd := meta.Cmd
	origRC := meta.RemoteControl
	origAgent := meta.Agent

	if opts.Agent != "" || opts.Serve || opts.RemoteControl {
		effAgent, aErr := selectEffectiveAgent(baseState.Agent, opts)
		if aErr != nil {
			metaLock.unlock()
			return aErr
		}
		meta.Agent = effAgent
	}
	if opts.Serve && meta.Port == 0 {
		metaLock.unlock()
		return fmt.Errorf("persistent sandbox %q has no --serve port. Run 'agbox stop %s', then start it with --serve", runSandbox, runSandbox)
	}
	switch {
	case opts.Cmd != "":
		meta.Mode = config.RunModeCmd
		meta.Cmd = opts.Cmd
		meta.RemoteControl = false
	case opts.Serve:
		meta.Mode = config.RunModeServe
		meta.RemoteControl = false
	case opts.RemoteControl:
		meta.RemoteControl = true
		if opts.Supervised || opts.Detach || a.IsTTY == nil || !a.IsTTY() {
			meta.Mode = config.RunModeRemoteControl
		} else {
			meta.Mode = config.RunModeTUI
		}
	default:
		if opts.Agent == "opencode" && (meta.RemoteControl || meta.Mode == config.RunModeRemoteControl) {
			meta.RemoteControl = false
			meta.Mode = config.RunModeTUI
		} else if opts.Agent == "antigravity" && meta.Mode == config.RunModeServe {
			meta.Mode = config.RunModeTUI
		}
	}

	meta.Persist = true
	if err := config.SaveRunMeta(suspendedPath, meta); err != nil {
		metaLock.unlock()
		return fmt.Errorf("update persistent metadata: %w", err)
	}
	metaLock.unlock()

	resumed, runErr := a.resumeSandboxTracked(ctx, resumeOpts{
		Sandbox:         runSandbox,
		AllowRoot:       opts.AllowRoot,
		Detach:          opts.Detach,
		Continue:        opts.Continue,
		ContinueSession: opts.ContinueSession,
		NoAuth:          opts.NoAuth,
		NoSkills:        opts.NoSkills,
		NoRules:         opts.NoRules,
		NoAgentCache:    opts.NoAgentCache,
		Supervised:      opts.Supervised,
	})

	if runErr != nil && !resumed && hasMarker(suspendedPath) {
		restoreLock, lockErr := lockRunMeta(runFilterDir)
		if lockErr == nil {
			defer restoreLock.unlock()
		}
		if sErr := config.SaveRunMeta(suspendedPath, origMeta); sErr != nil {
			a.warnf("Could not restore suspended metadata for %s: %v", runSandbox, sErr)
		}
		return runErr
	}

	if opts.Cmd != "" && origMode != config.RunModeCmd && hasMarker(suspendedPath) {
		restoreLock, lockErr := lockRunMeta(runFilterDir)
		if lockErr == nil {
			defer restoreLock.unlock()
		}
		if latest, lErr := config.LoadRunMeta(suspendedPath); lErr == nil {
			latest.Mode = origMode
			latest.Cmd = origCmd
			latest.RemoteControl = origRC
			latest.Agent = origAgent
			if sErr := config.SaveRunMeta(suspendedPath, latest); sErr != nil {
				a.warnf("Could not restore persistent run mode for %s: %v", runSandbox, sErr)
			}
			runMetaPath := filepath.Join(runFilterDir, "run.meta")
			if hasMarker(runMetaPath) {
				if mErr := config.SaveRunMeta(runMetaPath, latest); mErr != nil {
					a.warnf("Could not restore run metadata for %s: %v", runSandbox, mErr)
				}
			}
		}
	}
	return runErr
}

func sessionWorkDir(shares []config.ShareRecord) string {
	if len(shares) == 1 && shares[0].IsDir {
		return msb.GuestWorkspace + "/" + shares[0].GuestName
	}
	return msb.GuestWorkspace
}

func buildTUIInvokeCommand(meta config.RunMeta) string {
	var parts []string
	switch meta.Agent {
	case "opencode":
		parts = append(parts, "opencode")
		if meta.Continue {
			parts = append(parts, "-c")
		} else if meta.ContinueSession != "" {
			parts = append(parts, "-s", msb.ShellQuote(meta.ContinueSession))
		}
	case "antigravity":
		parts = append(parts, "agy")
		if meta.RemoteControl {
			parts = append(parts, "--remote-control")
		}
		if meta.Continue {
			parts = append(parts, "-c")
		} else if meta.ContinueSession != "" {
			parts = append(parts, "--conversation", msb.ShellQuote(meta.ContinueSession))
		}
		if len(meta.Shares) == 1 && meta.Shares[0].IsDir && meta.WorkspaceHub {
			parts = append(parts, "--add-dir", msb.ShellQuote(msb.GuestWorkspace))
		} else if len(meta.Shares) > 1 {
			for _, sh := range meta.Shares {
				if sh.IsDir {
					parts = append(parts, "--add-dir", msb.ShellQuote(msb.GuestWorkspace+"/"+sh.GuestName))
				}
			}
		}
	default:
		parts = append(parts, msb.ShellQuote(meta.Agent))
	}
	return strings.Join(parts, " ")
}

func (a *appRuntime) printPersistenceStatus(ctx context.Context) {
	fmt.Fprintln(a.Stdout, "\n== persistence ==")
	if authSt, err := persist.AuthStatus(a.Env.DataDir); err == nil {
		var configured []string
		for _, ag := range []string{"antigravity", "opencode"} {
			if authSt[ag] {
				configured = append(configured, ag)
			}
		}
		if len(configured) == 0 {
			fmt.Fprintln(a.Stdout, "auth: none")
		} else {
			fmt.Fprintf(a.Stdout, "auth: %s\n", strings.Join(configured, ", "))
		}
	} else {
		fmt.Fprintf(a.Stdout, "auth: error (%v)\n", err)
	}
	agentsDir := filepath.Join(a.Env.DataDir, "agents")
	if cached, err := persist.InspectAgentsDir(agentsDir); err == nil {
		if len(cached) == 0 {
			fmt.Fprintln(a.Stdout, "cached_agents: none")
		} else {
			var entries []string
			for _, info := range cached {
				entries = append(entries, fmt.Sprintf("%s (%s)", info.Agent, info.Version))
			}
			fmt.Fprintf(a.Stdout, "cached_agents: %s\n", strings.Join(entries, ", "))
		}
	} else {
		fmt.Fprintf(a.Stdout, "cached_agents: error (%v)\n", err)
	}
	skillsDir := filepath.Join(a.Env.DataDir, "skills")
	if skills, err := persist.InspectSkillsDir(skillsDir); err == nil {
		if len(skills) == 0 {
			fmt.Fprintln(a.Stdout, "global_skills: none")
		} else {
			fmt.Fprintf(a.Stdout, "global_skills: %s\n", strings.Join(skills, ", "))
		}
	} else {
		fmt.Fprintf(a.Stdout, "global_skills: error (%v)\n", err)
	}
	rulesDir := filepath.Join(a.Env.DataDir, "rules")
	if rules, err := persist.InspectRulesDir(rulesDir); err == nil {
		if len(rules) == 0 {
			fmt.Fprintln(a.Stdout, "global_rules: none")
		} else {
			fmt.Fprintf(a.Stdout, "global_rules: %s\n", strings.Join(rules, ", "))
		}
	} else {
		fmt.Fprintf(a.Stdout, "global_rules: error (%v)\n", err)
	}
	var profNames []string
	profs, profErr := persist.ListProfiles(a.Env.DataDir)
	if profErr == nil {
		for _, p := range profs {
			profNames = append(profNames, p.Name)
		}
	}
	if a.MSB != nil {
		if volRes, vErr := a.MSB.Run(ctx, msb.CommandRequest{Args: []string{"volume", "ls"}}); vErr == nil {
			for _, v := range msb.ParseVolumeList(volRes.Stdout) {
				if persist.IsProfileVolumeName(v) {
					name := strings.TrimPrefix(v, persist.ProfileVolumePrefix)
					if !slices.Contains(profNames, name) {
						profNames = append(profNames, name)
					}
				}
			}
		} else {
			a.warnf("Could not list msb volumes: %v", formatMSBError("msb volume ls", volRes, vErr))
		}
	}
	if profErr != nil && len(profNames) == 0 {
		fmt.Fprintf(a.Stdout, "profiles: error (%v)\n", profErr)
		return
	}
	if profErr != nil {
		a.warnf("Could not list profile metadata: %v", profErr)
	}
	slices.Sort(profNames)
	if len(profNames) == 0 {
		fmt.Fprintln(a.Stdout, "profiles: none")
	} else {
		fmt.Fprintf(a.Stdout, "profiles: %s\n", strings.Join(profNames, ", "))
	}
}
