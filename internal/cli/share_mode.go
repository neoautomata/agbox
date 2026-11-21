package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"agbox/internal/config"
	"agbox/internal/msb"
	"agbox/internal/pathsec"
	"agbox/internal/vcsfuse"
)

func vcsPolicyRank(p config.VCSPolicy) int {
	switch p {
	case config.VCSAllow:
		return 1
	case config.VCSAllowHooks:
		return 2
	default:
		return 0
	}
}

func (a *appRuntime) share(ctx context.Context, args []string) error {
	opts, err := parseShareArgs(args)
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

	if opts.Action != "list" {
		if _, sErr := os.Lstat(runFilterDir); sErr == nil {
			metaLock, lErr := lockRunMeta(runFilterDir)
			if lErr != nil {
				return lErr
			}
			defer metaLock.unlock()
		}
	}

	runMetaPath := filepath.Join(runFilterDir, "run.meta")
	suspMetaPath := filepath.Join(runFilterDir, "suspended")

	var meta config.RunMeta
	var metaPath string
	if sb.Running {
		meta, err = config.LoadRunMeta(runMetaPath)
		if err != nil {
			if os.IsNotExist(err) {
				return fmt.Errorf("sandbox %q has no agbox run metadata. Stop it and start it again with 'agbox run'", opts.Sandbox)
			}
			return fmt.Errorf("load run metadata for %q: %w", opts.Sandbox, err)
		}
		metaPath = runMetaPath
	} else {
		meta, err = config.LoadRunMeta(suspMetaPath)
		if err != nil {
			if os.IsNotExist(err) {
				return fmt.Errorf("sandbox %q is stopped and not suspended", opts.Sandbox)
			}
			return fmt.Errorf("load suspended metadata for %q: %w", opts.Sandbox, err)
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

func (a *appRuntime) listSandboxShares(sandbox string, running bool, runFilterDir string, meta config.RunMeta) error {
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
			mode := shareAccessMode(sh.ReadOnly)
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
		mode := shareAccessMode(sh.EffectiveReadOnly(meta.ReadOnly))
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

func (a *appRuntime) addSandboxShare(ctx context.Context, opts shareOpts, running bool, runFilterDir, metaPath string, meta config.RunMeta) error {
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

	// Default agbox share add to read-only with VCS masked unless flags or modifiers override it.
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

	accessMode := shareAccessMode(newTarget.ReadOnly)
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
		if running {
			sockPath := filepath.Join(runFilterDir, "ws.sock")
			if rbErr := vcsfuse.RemoveHubShare(sockPath, newTarget.GuestName, true); rbErr != nil {
				a.warnf("Could not roll back added share /workspace/%s: %v", newTarget.GuestName, rbErr)
			}
		}
		return fmt.Errorf("save share metadata: %w", err)
	}
	if running {
		a.dropGuestVFSCaches(ctx, opts.Sandbox)
	}
	a.logf("Added share /workspace/%s (%s, vcs=%s) -> %s on %s.",
		newTarget.GuestName, accessMode, newTarget.VCSPolicy, newTarget.HostPath, opts.Sandbox)
	return nil
}

func (a *appRuntime) setSandboxShare(ctx context.Context, opts shareOpts, running bool, runFilterDir, metaPath string, meta config.RunMeta) error {
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

	// Re-check host path security policy before applying permission changes.
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

	accessMode := shareAccessMode(nextRO)
	rec.AccessMode = accessMode
	rec.ReadOnly = nextRO
	rec.VCSPolicy = nextVCS
	rec.Masked = rec.IsDir && nextVCS == config.VCSMask
	meta.Shares[idx] = rec
	if err := config.SaveRunMeta(metaPath, meta); err != nil {
		if running {
			// Roll back privilege upgrades only. Never revert a downgrade to weaker isolation.
			var origROPtr *bool
			if curRO && !nextRO {
				origRO := true
				origROPtr = &origRO
			}
			var origVCSPtr *config.VCSPolicy
			if vcsPolicyRank(nextVCS) > vcsPolicyRank(curVCS) {
				origVCS := curVCS
				origVCSPtr = &origVCS
			}
			if origROPtr != nil || origVCSPtr != nil {
				sockPath := filepath.Join(runFilterDir, "ws.sock")
				if _, rbErr := vcsfuse.SetHubShare(sockPath, rec.GuestName, origROPtr, origVCSPtr, true); rbErr != nil {
					a.warnf("Could not roll back share upgrade on /workspace/%s: %v", rec.GuestName, rbErr)
				}
			}
		}
		return fmt.Errorf("save share metadata: %w", err)
	}
	if running {
		a.dropGuestVFSCaches(ctx, opts.Sandbox)
	}
	a.logf("Updated share /workspace/%s (%s, vcs=%s) on %s.", rec.GuestName, accessMode, nextVCS, opts.Sandbox)
	return nil
}

func (a *appRuntime) removeSandboxShare(ctx context.Context, opts shareOpts, running bool, runFilterDir, metaPath string, meta config.RunMeta) error {
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
		// Keep the share detached on metadata save failure so we never re-expose revoked access.
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

func (a *appRuntime) dropGuestVFSCaches(ctx context.Context, sandbox string) {
	if _, err := a.runGuestRootScript(ctx, sandbox, "flush guest VFS caches in "+sandbox, "sh", "sync; echo 3 > /proc/sys/vm/drop_caches 2>/dev/null || true"); err != nil {
		a.warnf("Could not flush guest VFS caches in %s: %v", sandbox, err)
	}
}
