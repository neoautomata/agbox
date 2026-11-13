package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"

	"agbox/internal/config"
	"agbox/internal/mounttab"
	"agbox/internal/msb"
	"agbox/internal/pathsec"
	"agbox/internal/persist"
)

// AuthOpts holds parsed arguments for `agbox auth`.
type AuthOpts struct {
	Action    string // "login", "status", "logout"
	Target    string // "antigravity", "opencode", "all", or ""
	AllowRoot bool
}

// ParseAuthArgs parses CLI arguments for `agbox auth`.
func ParseAuthArgs(args []string) (AuthOpts, error) {
	opts := AuthOpts{Action: "login"}
	var pos []string
	for _, a := range args {
		switch a {
		case "-h", "--help":
			return AuthOpts{}, ErrHelp
		case "--allow-root":
			opts.AllowRoot = true
		default:
			if strings.HasPrefix(a, "-") {
				return AuthOpts{}, fmt.Errorf("unknown auth option: %s (run 'agbox auth --help')", a)
			}
			pos = append(pos, a)
		}
	}

	if len(pos) == 0 {
		return opts, nil
	}

	switch pos[0] {
	case "status":
		if len(pos) > 1 {
			return AuthOpts{}, errors.New("Usage: agbox auth [--allow-root] status")
		}
		opts.Action = "status"
		return opts, nil
	case "logout":
		if len(pos) > 2 {
			return AuthOpts{}, errors.New("Usage: agbox auth [--allow-root] logout [antigravity|opencode|all]")
		}
		opts.Action = "logout"
		opts.Target = "all"
		if len(pos) == 2 {
			switch pos[1] {
			case "antigravity", "opencode", "all":
				opts.Target = pos[1]
			default:
				return AuthOpts{}, fmt.Errorf("unknown auth logout target %q (expected antigravity, opencode, or all)", pos[1])
			}
		}
		return opts, nil
	case "login":
		if len(pos) > 2 {
			return AuthOpts{}, errors.New("Usage: agbox auth [--allow-root] [login] <antigravity|opencode>")
		}
		if len(pos) == 2 {
			switch pos[1] {
			case "antigravity", "opencode":
				opts.Target = pos[1]
			default:
				return AuthOpts{}, fmt.Errorf("unknown auth agent %q (expected antigravity or opencode)", pos[1])
			}
		}
		return opts, nil
	case "antigravity", "opencode":
		if len(pos) > 1 {
			return AuthOpts{}, errors.New("Usage: agbox auth [--allow-root] <antigravity|opencode>")
		}
		opts.Target = pos[0]
		return opts, nil
	default:
		return AuthOpts{}, fmt.Errorf("unknown auth argument %q (expected antigravity, opencode, status, or logout)", pos[0])
	}
}

// AuthUsageText returns the help message for `agbox auth --help`.
func AuthUsageText() string {
	return `Usage:
  agbox auth [--allow-root] [antigravity|opencode]
      Sign in inside a disposable microVM and save credentials in $DATA_DIR/auth.
  agbox auth [--allow-root] status
      Show saved login status for antigravity and opencode.
  agbox auth [--allow-root] logout [antigravity|opencode|all]
      Delete saved login credentials from $DATA_DIR/auth.
`
}

// Auth manages persistent sandbox login credentials stored in $DATA_DIR/auth.
func (a *App) Auth(ctx context.Context, args []string) error {
	opts, err := ParseAuthArgs(args)
	if err != nil {
		return err
	}
	if err := a.verifyUser(opts.AllowRoot); err != nil {
		return err
	}
	if err := config.EnsurePrivateDir(a.Env.DataDir); err != nil {
		return fmt.Errorf("prepare data dir: %w", err)
	}

	switch opts.Action {
	case "status":
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
		if err := persist.RemoveAuth(a.Env.DataDir, opts.Target); err != nil {
			return err
		}
		a.logf("Removed saved %s credentials from %s.", opts.Target, filepath.Join(a.Env.DataDir, "auth"))
		return nil
	}

	if err := a.requireSetup(opts.AllowRoot); err != nil {
		return err
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
		return fmt.Errorf("base was built for agent=%s. Rebuild with 'agbox create-base %s' or 'both'", baseState.Agent, agent)
	}
	if a.IsTTY == nil || !a.IsTTY() {
		return errors.New("agbox auth requires an interactive TTY")
	}

	a.ReapOrphanRuns(ctx)
	a.ReapStaleFilterDirs(ctx)

	authName := fmt.Sprintf("auth-%d", a.PID)
	authSandbox := FormatRunSandboxName(authName, a.PID)
	runRootDir := filepath.Join(a.Env.DataDir, "run")
	authRunDir := filepath.Join(runRootDir, authName)
	if err := config.EnsurePrivateDir(runRootDir); err != nil {
		return err
	}
	if err := config.EnsurePrivateDir(authRunDir); err != nil {
		return err
	}
	meta := config.RunMeta{
		Sandbox:  authSandbox,
		OwnerPID: a.PID,
		Agent:    agent,
		Mode:     config.RunModeTUI,
		MaskMode: config.MaskStrict,
	}
	if err := config.SaveRunMeta(filepath.Join(authRunDir, "run.meta"), meta); err != nil {
		return err
	}

	authCtx, cancelAuth := context.WithCancel(ctx)
	defer cancelAuth()

	sandboxCreated := false
	var cleanupOnce sync.Once
	cleanup := func() {
		cleanupOnce.Do(func() {
			if sandboxCreated {
				_, _ = a.MSB.Run(context.Background(), msb.CommandRequest{Args: []string{"rm", "-f", authSandbox}})
			}
			_ = mounttab.TeardownFilterDir(authRunDir, a.MountCtl)
		})
	}
	defer cleanup()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	defer signal.Stop(sigCh)
	go func() {
		select {
		case <-sigCh:
			cancelAuth()
			cleanup()
		case <-authCtx.Done():
		}
	}()

	restoreArgs, err := msb.BuildRestoreArgs(msb.RestoreOpts{
		Snapshot: baseState.Snapshot,
		Name:     authSandbox,
		User:     config.GuestUser,
		CPUs:     a.Env.CPUs,
		Memory:   a.Env.Memory,
	})
	if err != nil {
		return err
	}

	a.logf("Booting disposable login microVM %s (zero host shares)...", authSandbox)
	sandboxCreated = true
	if _, err := a.MSB.Run(authCtx, msb.CommandRequest{Args: restoreArgs}); err != nil {
		return fmt.Errorf("snapshot restore failed: %w", err)
	}
	if err := a.ensureGuestUser(authCtx, authSandbox); err != nil {
		return err
	}
	// Seed existing saved auth for this agent so multi-provider logins keep prior entries.
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
		a.logf("Open the printed URL, paste the verification code, and run /exit to save credentials.")
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

	capScript, err := persist.BuildAuthCaptureScript(agent)
	if err != nil {
		return err
	}
	capRes, err := a.MSB.Run(authCtx, msb.CommandRequest{
		Args: []string{"exec", "-u", config.GuestUser, authSandbox, "--", "sh", "-c", capScript},
	})
	if err != nil {
		return fmt.Errorf("capture %s credentials: %w", agent, err)
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

// SkillsOpts holds parsed arguments for `agbox skills`.
type SkillsOpts struct {
	Action    string // "list", "add", "rm"
	Target    string
	Force     bool
	AllowRoot bool
}

// ParseSkillsArgs parses CLI arguments for `agbox skills`.
func ParseSkillsArgs(args []string) (SkillsOpts, error) {
	opts := SkillsOpts{Action: "list"}
	var pos []string
	for _, a := range args {
		switch a {
		case "-h", "--help":
			return SkillsOpts{}, ErrHelp
		case "--allow-root":
			opts.AllowRoot = true
		case "--force":
			opts.Force = true
		default:
			if strings.HasPrefix(a, "-") {
				return SkillsOpts{}, fmt.Errorf("unknown skills option: %s (run 'agbox skills --help')", a)
			}
			pos = append(pos, a)
		}
	}
	if len(pos) == 0 {
		return opts, nil
	}
	switch pos[0] {
	case "list", "ls":
		if len(pos) != 1 {
			return SkillsOpts{}, errors.New("Usage: agbox skills [--allow-root] [list]")
		}
		opts.Action = "list"
		return opts, nil
	case "add":
		if len(pos) != 2 {
			return SkillsOpts{}, errors.New("Usage: agbox skills [--allow-root] add [--force] <skill-dir-or-SKILL.md>")
		}
		opts.Action = "add"
		opts.Target = pos[1]
		return opts, nil
	case "rm", "remove":
		if len(pos) != 2 {
			return SkillsOpts{}, errors.New("Usage: agbox skills [--allow-root] rm <skill-name>")
		}
		opts.Action = "rm"
		opts.Target = pos[1]
		return opts, nil
	default:
		return SkillsOpts{}, fmt.Errorf("unknown skills subcommand %q (expected list, add, or rm)", pos[0])
	}
}

// SkillsUsageText returns the help message for `agbox skills --help`.
func SkillsUsageText() string {
	return `Usage:
  agbox skills [--allow-root] [list]
      List global skills stored in $DATA_DIR/skills.
  agbox skills [--allow-root] add [--force] <path>
      Validate and copy a skill directory (or SKILL.md) into $DATA_DIR/skills/<name>.
  agbox skills [--allow-root] rm <name>
      Delete a global skill from $DATA_DIR/skills/<name>.
`
}

// Skills manages host-stored global skills mounted read-only into sandboxes.
func (a *App) Skills(ctx context.Context, args []string) error {
	_ = ctx
	opts, err := ParseSkillsArgs(args)
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
		a.logf("Removed global skill %q.", opts.Target)
		return nil
	}
	return nil
}

// ProfileOpts holds parsed arguments for `agbox profile`.
type ProfileOpts struct {
	Action    string // "list", "create", "rm"
	Name      string
	Size      string
	Force     bool
	AllowRoot bool
}

// ParseProfileArgs parses CLI arguments for `agbox profile`.
func ParseProfileArgs(args []string) (ProfileOpts, error) {
	opts := ProfileOpts{Action: "list"}
	var pos []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch a {
		case "-h", "--help":
			return ProfileOpts{}, ErrHelp
		case "--allow-root":
			opts.AllowRoot = true
		case "--force", "-f":
			opts.Force = true
		case "--size":
			if i+1 >= len(args) || args[i+1] == "" {
				return ProfileOpts{}, errors.New("--size requires a disk size such as 10G or 2048M")
			}
			if !config.IsValidSizeSpec(args[i+1]) {
				return ProfileOpts{}, fmt.Errorf("invalid --size %q: expected a positive size in M or G (for example, 10G)", args[i+1])
			}
			opts.Size = strings.ToUpper(strings.TrimSpace(args[i+1]))
			i++
		default:
			if strings.HasPrefix(a, "-") {
				return ProfileOpts{}, fmt.Errorf("unknown profile option: %s (run 'agbox profile --help')", a)
			}
			pos = append(pos, a)
		}
	}
	if len(pos) == 0 {
		return opts, nil
	}
	switch pos[0] {
	case "list", "ls":
		if len(pos) != 1 {
			return ProfileOpts{}, errors.New("Usage: agbox profile [--allow-root] [list]")
		}
		opts.Action = "list"
		return opts, nil
	case "create":
		if len(pos) != 2 {
			return ProfileOpts{}, errors.New("Usage: agbox profile [--allow-root] create [--size SIZE] <name>")
		}
		name, err := persist.ValidateProfileName(pos[1])
		if err != nil {
			return ProfileOpts{}, err
		}
		opts.Action = "create"
		opts.Name = name
		return opts, nil
	case "rm", "remove":
		if len(pos) != 2 {
			return ProfileOpts{}, errors.New("Usage: agbox profile [--allow-root] rm [--force] <name>")
		}
		name, err := persist.ValidateProfileName(pos[1])
		if err != nil {
			return ProfileOpts{}, err
		}
		opts.Action = "rm"
		opts.Name = name
		return opts, nil
	default:
		return ProfileOpts{}, fmt.Errorf("unknown profile subcommand %q (expected list, create, or rm)", pos[0])
	}
}

// ProfileUsageText returns the help message for `agbox profile --help`.
func ProfileUsageText() string {
	return `Usage:
  agbox profile [--allow-root] [list]
      List persistent conversation profiles and disk volumes.
  agbox profile [--allow-root] create [--size SIZE] <name>
      Create an ext4 disk volume (agbox-profile-<name>) for --profile runs.
  agbox profile [--allow-root] rm [--force] <name>
      Delete profile disk volume agbox-profile-<name> and its metadata.
`
}

// Profile manages persistent ext4 disk profiles for cross-run conversation history.
func (a *App) Profile(ctx context.Context, args []string) error {
	opts, err := ParseProfileArgs(args)
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
		volRes, _ := a.MSB.Run(ctx, msb.CommandRequest{Args: []string{"volume", "ls"}})
		vols := msb.ParseVolumeList(volRes.Stdout)
		seen := make(map[string]bool)
		for _, pm := range profiles {
			seen[pm.Volume] = true
			fmt.Fprintf(a.Stdout, "%s\tvolume=%s\tsize=%s\n", pm.Name, pm.Volume, pm.Size)
		}
		for _, v := range vols {
			if persist.IsProfileVolumeName(v) && !seen[v] {
				name := strings.TrimPrefix(v, persist.ProfileVolumePrefix)
				fmt.Fprintf(a.Stdout, "%s\tvolume=%s\tsize=unknown\n", name, v)
			}
		}
		if len(profiles) == 0 && len(seen) == 0 {
			hasExtra := false
			for _, v := range vols {
				if persist.IsProfileVolumeName(v) {
					hasExtra = true
					break
				}
			}
			if !hasExtra {
				fmt.Fprintln(a.Stdout, "No conversation profiles configured.")
			}
		}
		return nil

	case "create":
		lock, err := persist.LockProfile(a.Env.DataDir, opts.Name)
		if err != nil {
			return err
		}
		defer func() { _ = lock.Unlock() }()

		size := defaultStr(opts.Size, defaultStr(a.Env.ProfileDisk, config.DefaultProfileDisk))
		volName, err := a.ensureProfileVolume(ctx, opts.Name, size)
		if err != nil {
			return err
		}
		a.logf("Profile %q is ready (volume=%s, size=%s).", opts.Name, volName, size)
		return nil

	case "rm":
		lock, err := persist.LockProfile(a.Env.DataDir, opts.Name)
		if err != nil {
			return err
		}
		defer func() { _ = lock.Unlock() }()

		lsRes, err := a.MSB.Run(ctx, msb.CommandRequest{Args: []string{"ls"}})
		if err != nil {
			return fmt.Errorf("list sandboxes: %w", err)
		}
		sandboxes := msb.ParseSandboxList(lsRes.Stdout)
		if err := a.checkProfileRemovable(opts.Name, opts.Force, sandboxes); err != nil {
			return err
		}

		volName := persist.FormatProfileVolumeName(opts.Name)
		exists, err := msb.VolumeExists(ctx, a.MSB, volName)
		if err != nil {
			return err
		}
		if exists {
			if _, err := a.MSB.Run(ctx, msb.CommandRequest{Args: []string{"volume", "rm", volName}}); err != nil {
				return fmt.Errorf("delete volume %s: %w", volName, err)
			}
		}
		_ = lock.Unlock()
		if err := persist.RemoveProfileDir(a.Env.DataDir, opts.Name); err != nil {
			return err
		}
		a.logf("Deleted profile %q (%s).", opts.Name, volName)
		return nil
	}
	return nil
}

func (a *App) ensureProfileVolume(ctx context.Context, profileName, size string) (string, error) {
	volName := persist.FormatProfileVolumeName(profileName)
	exists, err := msb.VolumeExists(ctx, a.MSB, volName)
	if err != nil {
		return "", err
	}
	if !exists {
		if size == "" {
			size = config.DefaultProfileDisk
		}
		createArgs, err := msb.BuildVolumeCreateDiskArgs(volName, size)
		if err != nil {
			return "", err
		}
		a.logf("Creating ext4 profile disk volume %s (%s)...", volName, size)
		if _, err := a.MSB.Run(ctx, msb.CommandRequest{Args: createArgs}); err != nil {
			return "", fmt.Errorf("create profile disk volume %s: %w", volName, err)
		}
	}
	if err := persist.SaveProfileMeta(a.Env.DataDir, persist.ProfileMeta{
		Name:   profileName,
		Volume: volName,
		Size:   defaultStr(size, config.DefaultProfileDisk),
	}); err != nil {
		return "", fmt.Errorf("save profile metadata: %w", err)
	}
	return volName, nil
}

func (a *App) checkProfileNotActive(profileName, currentSandbox string, sandboxes []msb.SandboxInfo) error {
	runRoot := filepath.Join(a.Env.DataDir, "run")
	entries, err := os.ReadDir(runRoot)
	if err != nil {
		return nil
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

func (a *App) checkProfileRemovable(profileName string, force bool, sandboxes []msb.SandboxInfo) error {
	if err := a.checkProfileNotActive(profileName, "", sandboxes); err != nil {
		return err
	}
	if force {
		return nil
	}
	runRoot := filepath.Join(a.Env.DataDir, "run")
	entries, err := os.ReadDir(runRoot)
	if err != nil {
		return nil
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
			return fmt.Errorf("profile %q is referenced by suspended sandbox %s. Run 'agbox stop %s' first or pass --force", profileName, meta.Sandbox, meta.Sandbox)
		}
	}
	return nil
}

func (a *App) pushAuth(ctx context.Context, sandbox, effectiveAgent string) error {
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
	if _, err := a.MSB.Run(ctx, msb.CommandRequest{
		Args:  []string{"exec", "-u", config.GuestUser, sandbox, "--", "sh"},
		Stdin: strings.NewReader(script),
	}); err != nil {
		return fmt.Errorf("stream saved login credentials into %s: %w", sandbox, err)
	}
	a.logf("Streamed saved login credentials into %s.", sandbox)
	return nil
}

func (a *App) setupGuestSkills(ctx context.Context, sandbox string) error {
	script := persist.BuildGuestSkillsMountScript()
	if _, err := a.MSB.Run(ctx, msb.CommandRequest{
		Args: []string{"exec", sandbox, "--", "sh", "-c", script},
	}); err != nil {
		return fmt.Errorf("bind-mount global skills in %s: %w", sandbox, err)
	}
	return nil
}

func (a *App) setupGuestProfile(ctx context.Context, sandbox string) error {
	script := persist.BuildGuestProfileMountScript()
	if _, err := a.MSB.Run(ctx, msb.CommandRequest{
		Args: []string{"exec", sandbox, "--", "sh", "-c", script},
	}); err != nil {
		return fmt.Errorf("bind-mount conversation profile in %s: %w", sandbox, err)
	}
	return nil
}

func (a *App) suspendSandboxOnExit(sandbox, runFilterDir string, meta config.RunMeta) {
	savedMeta := meta
	savedMeta.Continue = false
	savedMeta.ContinueSession = ""
	suspendedPath := filepath.Join(runFilterDir, "suspended")
	if err := config.SaveRunMeta(suspendedPath, savedMeta); err != nil {
		a.warnf("Could not save suspended metadata for %s: %v", sandbox, err)
	}
	if _, err := a.MSB.Run(context.Background(), msb.CommandRequest{Args: []string{"stop", sandbox}}); err != nil {
		a.warnf("Could not stop persistent sandbox %s: %v", sandbox, err)
	}
	_ = os.Remove(filepath.Join(runFilterDir, "detached"))
	_ = mounttab.UnmountFilterDir(runFilterDir, a.MountCtl)
	a.logf("Persisted %s (stopped). Resume with 'agbox resume %s' or delete with 'agbox stop %s'.", sandbox, sandbox, sandbox)
}

func sharesMatchRecorded(validated []pathsec.ShareTarget, recorded []config.ShareRecord, useMask bool) bool {
	if len(validated) != len(recorded) {
		return false
	}
	for i, v := range validated {
		rec := recorded[i]
		wantMasked := v.IsDir && useMask
		if rec.Index != i || rec.HostPath != v.HostPath || rec.GuestName != v.GuestName || rec.IsDir != v.IsDir || rec.Masked != wantMasked {
			return false
		}
	}
	return true
}

func (a *App) resumeFromRunPersist(ctx context.Context, runSandbox, dirID string, baseState config.State, opts RunOpts, useMask bool) error {
	suspendedPath := filepath.Join(a.Env.DataDir, "run", dirID, "suspended")
	meta, err := config.LoadRunMeta(suspendedPath)
	if err != nil {
		return fmt.Errorf("load suspended metadata for %q: %w", runSandbox, err)
	}

	if len(opts.Paths) > 0 {
		pol := a.sharePolicy(opts.ReadOnly)
		var validated []pathsec.ShareTarget
		for _, rawPath := range opts.Paths {
			if rawPath == "" {
				continue
			}
			target, vErr := pathsec.ValidateShare(rawPath, pol)
			if vErr != nil {
				return vErr
			}
			validated = append(validated, target)
		}
		validated = pathsec.AssignGuestNames(validated)
		if opts.ReadOnly != meta.ReadOnly || opts.MaskMode != meta.MaskMode || !sharesMatchRecorded(validated, meta.Shares, useMask) {
			return fmt.Errorf("persistent sandbox %q has different shared paths or mount flags. Run 'agbox stop %s' to recreate it", runSandbox, runSandbox)
		}
	}

	origMode := meta.Mode
	origCmd := meta.Cmd

	if opts.Agent != "" {
		effAgent, aErr := SelectEffectiveAgent(baseState.Agent, opts)
		if aErr != nil {
			return aErr
		}
		meta.Agent = effAgent
	}
	if opts.Serve && meta.Port == 0 {
		return fmt.Errorf("persistent sandbox %q was not created with --serve. Run 'agbox stop %s' to recreate it", runSandbox, runSandbox)
	}
	switch {
	case opts.Cmd != "":
		meta.Mode = config.RunModeCmd
		meta.Cmd = opts.Cmd
	case opts.Serve:
		meta.Mode = config.RunModeServe
	case opts.RemoteControl:
		meta.RemoteControl = true
		if opts.Detach || a.IsTTY == nil || !a.IsTTY() {
			meta.Mode = config.RunModeRemoteControl
		} else {
			meta.Mode = config.RunModeTUI
		}
	}

	meta.Persist = true
	if err := config.SaveRunMeta(suspendedPath, meta); err != nil {
		return fmt.Errorf("update persistent metadata: %w", err)
	}

	runErr := a.resumeSandbox(ctx, ResumeOpts{
		Sandbox:         runSandbox,
		AllowRoot:       opts.AllowRoot,
		Detach:          opts.Detach,
		Continue:        opts.Continue,
		ContinueSession: opts.ContinueSession,
		NoAuth:          opts.NoAuth,
		NoSkills:        opts.NoSkills,
	})

	if opts.Cmd != "" && origMode != config.RunModeCmd && hasMarker(suspendedPath) {
		if latest, lErr := config.LoadRunMeta(suspendedPath); lErr == nil {
			latest.Mode = origMode
			latest.Cmd = origCmd
			_ = config.SaveRunMeta(suspendedPath, latest)
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
		if len(meta.Shares) > 1 {
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

func (a *App) printPersistenceStatus(ctx context.Context) {
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
	}
	skillsDir := filepath.Join(a.Env.DataDir, "skills")
	if skills, err := persist.InspectSkillsDir(skillsDir); err == nil {
		if len(skills) == 0 {
			fmt.Fprintln(a.Stdout, "global_skills: none")
		} else {
			fmt.Fprintf(a.Stdout, "global_skills: %s\n", strings.Join(skills, ", "))
		}
	}
	var profNames []string
	if profs, err := persist.ListProfiles(a.Env.DataDir); err == nil {
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
		}
	}
	slices.Sort(profNames)
	if len(profNames) == 0 {
		fmt.Fprintln(a.Stdout, "profiles: none")
	} else {
		fmt.Fprintf(a.Stdout, "profiles: %s\n", strings.Join(profNames, ", "))
	}
}
