package cli

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"agbox/internal/config"
	"agbox/internal/msb"
	"agbox/internal/pathsec"
	"agbox/internal/vcsfuse"
)

// ShareOpts holds parsed CLI arguments for `agbox share`.
type ShareOpts struct {
	Action    string // "list", "add", "set", "rm"
	Sandbox   string
	Target    string
	Alias     string
	ReadOnly  bool
	HasAccess bool
	VCSPolicy config.VCSPolicy
	HasVCS    bool
	Force     bool
	AllowRoot bool
}

// ParseShareArgs parses CLI arguments for `agbox share` and rejects conflicting flags.
func ParseShareArgs(args []string) (ShareOpts, error) {
	var opts ShareOpts
	var pos []string
	sawRO := false
	sawRW := false
	vcsFlagCount := 0

	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			pos = append(pos, args[i+1:]...)
			break
		}
		if strings.HasPrefix(a, "--as=") {
			if opts.Alias != "" {
				return ShareOpts{}, errors.New("duplicate --as flag")
			}
			alias, err := pathsec.ValidateGuestAlias(strings.TrimPrefix(a, "--as="))
			if err != nil {
				return ShareOpts{}, err
			}
			opts.Alias = alias
			continue
		}
		switch a {
		case "-h", "--help":
			return ShareOpts{}, ErrHelp
		case "--allow-root":
			opts.AllowRoot = true
		case "--ro":
			sawRO = true
			opts.ReadOnly = true
			opts.HasAccess = true
		case "--rw":
			sawRW = true
			opts.ReadOnly = false
			opts.HasAccess = true
		case "--mask", "--mask-vcs":
			vcsFlagCount++
			opts.VCSPolicy = config.VCSMask
			opts.HasVCS = true
		case "--vcs":
			vcsFlagCount++
			opts.VCSPolicy = config.VCSAllow
			opts.HasVCS = true
		case "--vcs-hooks":
			vcsFlagCount++
			opts.VCSPolicy = config.VCSAllowHooks
			opts.HasVCS = true
		case "--as":
			if i+1 >= len(args) {
				return ShareOpts{}, errors.New("--as requires a guest share name")
			}
			if opts.Alias != "" {
				return ShareOpts{}, errors.New("duplicate --as flag")
			}
			alias, err := pathsec.ValidateGuestAlias(args[i+1])
			if err != nil {
				return ShareOpts{}, err
			}
			opts.Alias = alias
			i++
		case "--force", "-f":
			opts.Force = true
		default:
			if strings.HasPrefix(a, "-") {
				return ShareOpts{}, fmt.Errorf("unknown share option: %s (run 'agbox share --help')", a)
			}
			pos = append(pos, a)
		}
	}

	if sawRO && sawRW {
		return ShareOpts{}, errors.New("conflicting share options: cannot combine --ro and --rw")
	}
	if vcsFlagCount > 1 {
		return ShareOpts{}, errors.New("conflicting share options: specify at most one of --mask-vcs, --vcs, or --vcs-hooks")
	}
	if sawRO && opts.HasVCS && opts.VCSPolicy == config.VCSAllowHooks {
		return ShareOpts{}, errors.New("conflicting share options: cannot combine --ro and --vcs-hooks")
	}

	if len(pos) == 0 {
		return ShareOpts{}, errors.New("Usage: agbox share <list|add|set|rm> <sandbox> [...]")
	}

	opts.Action = pos[0]
	switch opts.Action {
	case "list", "ls":
		opts.Action = "list"
		if len(pos) != 2 {
			return ShareOpts{}, errors.New("Usage: agbox share [--allow-root] list <sandbox>")
		}
		if opts.HasAccess || opts.HasVCS || opts.Alias != "" || opts.Force {
			return ShareOpts{}, errors.New("agbox share list does not accept --ro, --rw, --vcs, --as, or --force")
		}
		sbx, err := validateTargetRunSandbox(pos[1], "inspect shares on")
		if err != nil {
			return ShareOpts{}, err
		}
		opts.Sandbox = sbx
		return opts, nil

	case "add":
		if len(pos) != 3 {
			return ShareOpts{}, errors.New("Usage: agbox share [--allow-root] add [--ro|--rw] [--mask-vcs|--vcs|--vcs-hooks] [--as NAME] <sandbox> <path[:opts]>")
		}
		if opts.Force {
			return ShareOpts{}, errors.New("agbox share add does not accept --force")
		}
		sbx, err := validateTargetRunSandbox(pos[1], "modify shares on")
		if err != nil {
			return ShareOpts{}, err
		}
		opts.Sandbox = sbx
		opts.Target = pos[2]
		return opts, nil

	case "set":
		if len(pos) != 3 {
			return ShareOpts{}, errors.New("Usage: agbox share [--allow-root] set [--ro|--rw] [--mask-vcs|--vcs|--vcs-hooks] [--force] <sandbox> <guest-name-or-path>")
		}
		if opts.Alias != "" {
			return ShareOpts{}, errors.New("agbox share set does not accept --as")
		}
		if !opts.HasAccess && !opts.HasVCS {
			return ShareOpts{}, errors.New("agbox share set requires at least one permission flag (--ro, --rw, --mask-vcs, --vcs, or --vcs-hooks)")
		}
		sbx, err := validateTargetRunSandbox(pos[1], "modify shares on")
		if err != nil {
			return ShareOpts{}, err
		}
		opts.Sandbox = sbx
		opts.Target = pos[2]
		return opts, nil

	case "rm", "remove":
		opts.Action = "rm"
		if len(pos) != 3 {
			return ShareOpts{}, errors.New("Usage: agbox share [--allow-root] rm [--force] <sandbox> <guest-name-or-path>")
		}
		if opts.HasAccess || opts.HasVCS || opts.Alias != "" {
			return ShareOpts{}, errors.New("agbox share rm does not accept --ro, --rw, --vcs, or --as")
		}
		sbx, err := validateTargetRunSandbox(pos[1], "modify shares on")
		if err != nil {
			return ShareOpts{}, err
		}
		opts.Sandbox = sbx
		opts.Target = pos[2]
		return opts, nil

	default:
		return ShareOpts{}, fmt.Errorf("unknown share subcommand %q (expected list, add, set, or rm)", opts.Action)
	}
}

// ShareUsageText returns the help message for `agbox share --help`.
func ShareUsageText() string {
	return `Usage:
  agbox share [--allow-root] list <sandbox>
      List shared directories and files on a running or suspended sandbox.

  agbox share [--allow-root] add [--ro|--rw] [--mask-vcs|--vcs|--vcs-hooks] [--as NAME] <sandbox> <path[:opts]>
      Attach a host directory or file at /workspace/<name> on a running or suspended sandbox.
      Safe default: read-only with VCS metadata masked (ro,mask) unless --rw or :rw is passed.

  agbox share [--allow-root] set [--ro|--rw] [--mask-vcs|--vcs|--vcs-hooks] [--force] <sandbox> <guest-name-or-path>
      Update read-only, read-write, or VCS policy on an existing share.
      Downgrading rw -> ro fails closed if guest processes hold open writable handles unless --force is passed.

  agbox share [--allow-root] rm [--force] <sandbox> <guest-name-or-path>
      Detach a share and revoke open host file descriptors immediately.
      Fails closed if guest processes hold open writable handles unless --force is passed.
`
}

// Share lists, adds, modifies, or removes shared paths on a running or suspended sandbox.
func (a *App) Share(ctx context.Context, args []string) error {
	opts, err := ParseShareArgs(args)
	if err != nil {
		return err
	}
	if err := a.requireSetup(opts.AllowRoot); err != nil {
		return err
	}
	if err := config.EnsurePrivateDir(a.Env.DataDir); err != nil {
		return fmt.Errorf("prepare data dir: %w", err)
	}

	dirID, err := RunDirIDFromSandbox(opts.Sandbox)
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

	runMetaPath := filepath.Join(runFilterDir, "run.meta")
	suspMetaPath := filepath.Join(runFilterDir, "suspended")

	var meta config.RunMeta
	var metaPath string
	if sb.Running {
		meta, err = config.LoadRunMeta(runMetaPath)
		if err != nil {
			return fmt.Errorf("load run metadata for %q: %w", opts.Sandbox, err)
		}
		metaPath = runMetaPath
	} else {
		meta, err = config.LoadRunMeta(suspMetaPath)
		if err != nil {
			return fmt.Errorf("sandbox %q is stopped and not suspended", opts.Sandbox)
		}
		metaPath = suspMetaPath
	}

	if opts.Action == "list" {
		return a.listSandboxShares(opts.Sandbox, sb.Running, runFilterDir, meta)
	}

	if !meta.WorkspaceHub {
		return fmt.Errorf("sandbox %q does not use the FUSE Workspace Hub (start with shared paths or --share-hub, without --no-mask)", opts.Sandbox)
	}

	switch opts.Action {
	case "add":
		return a.addSandboxShare(ctx, opts, sb.Running, runFilterDir, metaPath, meta)
	case "set":
		return a.setSandboxShare(ctx, opts, sb.Running, runFilterDir, metaPath, meta)
	case "rm":
		return a.removeSandboxShare(ctx, opts, sb.Running, runFilterDir, metaPath, meta)
	default:
		return fmt.Errorf("unsupported share action %q", opts.Action)
	}
}

func (a *App) listSandboxShares(sandbox string, running bool, runFilterDir string, meta config.RunMeta) error {
	if running && meta.WorkspaceHub {
		sockPath := filepath.Join(runFilterDir, "ws.sock")
		live, err := vcsfuse.ListHubShares(sockPath)
		if err != nil {
			return fmt.Errorf("query workspace hub for %s: %w", sandbox, err)
		}
		if len(live) == 0 {
			fmt.Fprintf(a.Stdout, "No shares mounted in %s (/workspace hub is empty).\n", sandbox)
			return nil
		}
		for _, sh := range live {
			mode := "rw"
			if sh.ReadOnly {
				mode = "ro"
			}
			kind := "dir"
			if sh.IsFile {
				kind = "file"
			}
			vcsPol := sh.VCSPolicy
			if vcsPol == "" {
				vcsPol = config.VCSMask
			}
			fmt.Fprintf(a.Stdout, "/workspace/%s\tmode=%s\tvcs=%s\ttype=%s\topen_writable=%d\thost=%s\n",
				sh.GuestName, mode, vcsPol, kind, sh.OpenWritableFDs, sh.HostPath)
		}
		return nil
	}

	if len(meta.Shares) == 0 {
		fmt.Fprintf(a.Stdout, "No shares configured on %s.\n", sandbox)
		return nil
	}
	for _, sh := range meta.Shares {
		mode := "rw"
		if sh.EffectiveReadOnly(meta.ReadOnly) {
			mode = "ro"
		}
		kind := "dir"
		if !sh.IsDir {
			kind = "file"
		}
		vcsPol := sh.EffectiveVCSPolicy()
		fmt.Fprintf(a.Stdout, "/workspace/%s\tmode=%s\tvcs=%s\ttype=%s\thost=%s\n",
			sh.GuestName, mode, vcsPol, kind, sh.HostPath)
	}
	return nil
}

func (a *App) addSandboxShare(ctx context.Context, opts ShareOpts, running bool, runFilterDir, metaPath string, meta config.RunMeta) error {
	spec, err := pathsec.ParseShareSpec(opts.Target)
	if err != nil {
		return err
	}
	if opts.Alias != "" {
		if spec.GuestAlias != "" {
			return errors.New("conflicting guest alias options: cannot combine --as with inline as=<name>")
		}
		spec.GuestAlias = opts.Alias
	}

	// Safe default for `agbox share add`: read-only + VCS-masked unless explicitly overridden.
	defaultRO := true
	if opts.HasAccess {
		defaultRO = opts.ReadOnly
	}
	defaultVCS := config.VCSMask
	if opts.HasVCS {
		defaultVCS = opts.VCSPolicy
	}

	resolvedList, err := pathsec.ResolveShareSpecs([]pathsec.ShareSpec{spec}, pathsec.ResolveOpts{
		Policy:     a.sharePolicy(defaultRO),
		DefaultRO:  defaultRO,
		LockRO:     opts.HasAccess,
		DefaultVCS: defaultVCS,
		LockVCS:    opts.HasVCS,
	})
	if err != nil {
		return err
	}
	newTarget := resolvedList[0]

	combinedTargets := make([]pathsec.ShareTarget, 0, len(meta.Shares)+1)
	existingNames := make(map[string]bool, len(meta.Shares))
	maxIndex := -1
	for _, sh := range meta.Shares {
		combinedTargets = append(combinedTargets, pathsec.ShareTarget{
			HostPath:  sh.HostPath,
			GuestName: sh.GuestName,
			IsDir:     sh.IsDir,
		})
		existingNames[sh.GuestName] = true
		if sh.Index > maxIndex {
			maxIndex = sh.Index
		}
	}
	combinedTargets = append(combinedTargets, newTarget)
	if err := pathsec.CheckDisjointHostPaths(combinedTargets); err != nil {
		return err
	}

	if existingNames[newTarget.GuestName] {
		if newTarget.ExplicitAlias {
			return fmt.Errorf("guest share name %q is already mounted in /workspace", newTarget.GuestName)
		}
		parent := filepath.Base(filepath.Dir(newTarget.HostPath))
		candidate := parent + "-" + newTarget.BaseName
		if parent == "" || parent == "." || parent == "/" || existingNames[candidate] {
			return fmt.Errorf("guest share name %q collides with an existing share (pass --as <name>)", newTarget.GuestName)
		}
		if _, vErr := pathsec.ValidateGuestAlias(candidate); vErr != nil {
			return fmt.Errorf("guest share name %q collides with an existing share (pass --as <name>)", newTarget.GuestName)
		}
		newTarget.GuestName = candidate
	}

	if running {
		sockPath := filepath.Join(runFilterDir, "ws.sock")
		st, hErr := vcsfuse.AddHubShare(sockPath, vcsfuse.HubShareConfig{
			GuestName: newTarget.GuestName,
			HostPath:  newTarget.HostPath,
			ReadOnly:  newTarget.ReadOnly,
			VCSPolicy: newTarget.VCSPolicy,
		})
		if hErr != nil {
			return hErr
		}
		newTarget.GuestName = st.GuestName
	}

	accessMode := "rw"
	if newTarget.ReadOnly {
		accessMode = "ro"
	}
	meta.Shares = append(meta.Shares, config.ShareRecord{
		Index:      maxIndex + 1,
		HostPath:   newTarget.HostPath,
		GuestName:  newTarget.GuestName,
		IsDir:      newTarget.IsDir,
		Masked:     newTarget.IsDir && newTarget.VCSPolicy == config.VCSMask,
		AccessMode: accessMode,
		ReadOnly:   newTarget.ReadOnly,
		VCSPolicy:  newTarget.VCSPolicy,
	})
	if err := config.SaveRunMeta(metaPath, meta); err != nil {
		return fmt.Errorf("save share metadata: %w", err)
	}
	if running {
		a.dropGuestVFSCaches(ctx, opts.Sandbox)
	}
	a.logf("Added share /workspace/%s (%s, vcs=%s) -> %s on %s.",
		newTarget.GuestName, accessMode, newTarget.VCSPolicy, newTarget.HostPath, opts.Sandbox)
	return nil
}

func (a *App) setSandboxShare(ctx context.Context, opts ShareOpts, running bool, runFilterDir, metaPath string, meta config.RunMeta) error {
	idx, err := findShareRecordIndex(meta.Shares, opts.Target)
	if err != nil {
		return err
	}
	rec := meta.Shares[idx]

	curRO := rec.EffectiveReadOnly(meta.ReadOnly)
	curVCS := rec.EffectiveVCSPolicy()
	nextRO := curRO
	if opts.HasAccess {
		nextRO = opts.ReadOnly
	}
	nextVCS := curVCS
	if opts.HasVCS {
		nextVCS = opts.VCSPolicy
	}

	if !rec.IsDir && nextVCS != config.VCSMask {
		return fmt.Errorf("VCS policy %q applies only to directory shares (%s is a file)", nextVCS, rec.GuestName)
	}
	if nextRO && nextVCS == config.VCSAllowHooks {
		return errors.New("conflicting share options: read-only share cannot enable vcs-hooks")
	}

	// Re-validate against host path security policy (especially rw upgrades on single files or blocked paths).
	targetCheck, err := pathsec.ValidateShare(rec.HostPath, a.sharePolicy(nextRO))
	if err != nil {
		return err
	}
	if targetCheck.IsDir != rec.IsDir {
		return fmt.Errorf("share type changed on host for %s", rec.HostPath)
	}

	if running {
		sockPath := filepath.Join(runFilterDir, "ws.sock")
		var roPtr *bool
		if opts.HasAccess {
			v := nextRO
			roPtr = &v
		}
		var vcsPtr *config.VCSPolicy
		if opts.HasVCS {
			v := nextVCS
			vcsPtr = &v
		}
		if _, hErr := vcsfuse.SetHubShare(sockPath, rec.GuestName, roPtr, vcsPtr, opts.Force); hErr != nil {
			return hErr
		}
	}

	accessMode := "rw"
	if nextRO {
		accessMode = "ro"
	}
	rec.AccessMode = accessMode
	rec.ReadOnly = nextRO
	rec.VCSPolicy = nextVCS
	rec.Masked = rec.IsDir && nextVCS == config.VCSMask
	meta.Shares[idx] = rec
	if err := config.SaveRunMeta(metaPath, meta); err != nil {
		return fmt.Errorf("save share metadata: %w", err)
	}
	if running {
		a.dropGuestVFSCaches(ctx, opts.Sandbox)
	}
	a.logf("Updated share /workspace/%s (%s, vcs=%s) on %s.", rec.GuestName, accessMode, nextVCS, opts.Sandbox)
	return nil
}

func (a *App) removeSandboxShare(ctx context.Context, opts ShareOpts, running bool, runFilterDir, metaPath string, meta config.RunMeta) error {
	idx, err := findShareRecordIndex(meta.Shares, opts.Target)
	if err != nil {
		return err
	}
	rec := meta.Shares[idx]

	if running {
		sockPath := filepath.Join(runFilterDir, "ws.sock")
		if hErr := vcsfuse.RemoveHubShare(sockPath, rec.GuestName, opts.Force); hErr != nil {
			return hErr
		}
	}

	meta.Shares = append(meta.Shares[:idx], meta.Shares[idx+1:]...)
	if err := config.SaveRunMeta(metaPath, meta); err != nil {
		return fmt.Errorf("save share metadata: %w", err)
	}
	if running {
		a.dropGuestVFSCaches(ctx, opts.Sandbox)
	}
	a.logf("Removed share /workspace/%s (%s) from %s.", rec.GuestName, rec.HostPath, opts.Sandbox)
	return nil
}

func findShareRecordIndex(shares []config.ShareRecord, query string) (int, error) {
	trimmed := strings.TrimSpace(query)
	if strings.HasPrefix(trimmed, msb.GuestWorkspace+"/") {
		rel := strings.TrimPrefix(trimmed, msb.GuestWorkspace+"/")
		if !strings.Contains(rel, "/") && rel != "" {
			for i, sh := range shares {
				if sh.GuestName == rel {
					return i, nil
				}
			}
		}
	}
	for i, sh := range shares {
		if sh.GuestName == trimmed {
			return i, nil
		}
	}
	if resolved, err := filepath.EvalSymlinks(trimmed); err == nil {
		clean := filepath.Clean(resolved)
		for i, sh := range shares {
			if sh.HostPath == clean {
				return i, nil
			}
		}
	}
	if abs, err := filepath.Abs(trimmed); err == nil {
		clean := filepath.Clean(abs)
		for i, sh := range shares {
			if sh.HostPath == clean {
				return i, nil
			}
		}
	}
	return -1, fmt.Errorf("share %q is not configured on this sandbox", query)
}

func (a *App) dropGuestVFSCaches(ctx context.Context, sandbox string) {
	_, _ = a.MSB.Run(ctx, msb.CommandRequest{
		Args: []string{"exec", "-u", "root", sandbox, "--", "sh", "-c", "sync; echo 3 > /proc/sys/vm/drop_caches 2>/dev/null || true"},
	})
}
