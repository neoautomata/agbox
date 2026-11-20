package cli

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"agbox/internal/config"
	"agbox/internal/mounttab"
	"agbox/internal/msb"
	"agbox/internal/pathsec"
	"agbox/internal/persist"
	"agbox/internal/vcsfuse"
)

func shareAccessMode(readOnly bool) string {
	if readOnly {
		return "ro"
	}
	return "rw"
}

func directShareVCSPolicy(isDir, readOnly bool) config.VCSPolicy {
	if !isDir {
		return config.VCSMask
	}
	if readOnly {
		return config.VCSAllow
	}
	return config.VCSAllowHooks
}

func (a *appRuntime) inspectGuestReadOnlyMounts(noSkills, noRules, noAgentCache bool) (mountSkills, mountRules, mountAgents bool, skillsDir, rulesDir, agentsDir string, err error) {
	skillsDir = filepath.Join(a.Env.DataDir, "skills")
	if !noSkills {
		skillNames, sErr := persist.InspectSkillsDir(skillsDir)
		if sErr != nil {
			return false, false, false, "", "", "", sErr
		}
		mountSkills = len(skillNames) > 0
	}

	rulesDir = filepath.Join(a.Env.DataDir, "rules")
	if !noRules {
		ruleNames, rErr := persist.InspectRulesDir(rulesDir)
		if rErr != nil {
			return false, false, false, "", "", "", rErr
		}
		mountRules = len(ruleNames) > 0
	}

	agentsDir = filepath.Join(a.Env.DataDir, "agents")
	if !noAgentCache {
		cachedAgents, aErr := persist.InspectAgentsDir(agentsDir)
		if aErr != nil {
			return false, false, false, "", "", "", aErr
		}
		mountAgents = len(cachedAgents) > 0
	}

	return mountSkills, mountRules, mountAgents, skillsDir, rulesDir, agentsDir, nil
}

func (a *appRuntime) run(ctx context.Context, args []string) error {
	opts, err := parseRunArgs(args, a.Env.MaskVCS, nil)
	if err != nil {
		return err
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

	a.reapOrphanRuns(ctx)
	a.reapStaleFilterDirs(ctx)

	runSandbox := formatRunSandboxName(opts.Name, a.PID)
	dirID, err := runDirIDFromSandbox(runSandbox)
	if err != nil {
		return err
	}

	lsRes, err := a.MSB.Run(ctx, msb.CommandRequest{Args: []string{"ls"}})
	if err != nil {
		return formatMSBError("list sandboxes", lsRes, err)
	}
	sandboxes := msb.ParseSandboxList(lsRes.Stdout)
	useMask := opts.MaskMode != config.MaskOff

	if sb, exists := msb.FindSandbox(sandboxes, runSandbox); exists {
		suspMarker := filepath.Join(a.Env.DataDir, "run", dirID, "suspended")
		if opts.Persist && opts.Name != "" && !sb.Running && hasMarker(suspMarker) {
			return a.resumeFromRunPersist(ctx, runSandbox, dirID, baseState, opts, useMask)
		}
		if opts.Name != "" {
			if !sb.Running && hasMarker(suspMarker) {
				return fmt.Errorf("sandbox %q is suspended. Run 'agbox resume %s' to restart it or 'agbox stop %s' to delete it", runSandbox, runSandbox, runSandbox)
			}
			return fmt.Errorf("sandbox %q already exists. Choose a different --name or stop it with 'agbox stop %s'", runSandbox, runSandbox)
		}
		if rmRes, rmErr := a.destroySandbox(ctx, runSandbox, false, true); rmErr != nil {
			return formatMSBError(fmt.Sprintf("delete existing run sandbox %q", runSandbox), rmRes, rmErr)
		}
	}

	effectiveAgent, err := selectEffectiveAgent(baseState.Agent, opts)
	if err != nil {
		return err
	}

	mountSkills, mountRules, mountAgents, skillsDir, rulesDir, agentsDir, err := a.inspectGuestReadOnlyMounts(opts.NoSkills, opts.NoRules, opts.NoAgentCache)
	if err != nil {
		return err
	}

	var profLock *persist.ProfileLock
	defer func() {
		if profLock != nil {
			_ = profLock.Unlock()
		}
	}()
	var profileDiskSpecs []msb.DiskMountSpec
	if opts.Profile != "" {
		var lErr error
		profLock, lErr = persist.LockProfile(a.Env.DataDir, opts.Profile)
		if lErr != nil {
			return lErr
		}
		lsRes, err = a.MSB.Run(ctx, msb.CommandRequest{Args: []string{"ls"}})
		if err != nil {
			return formatMSBError("list sandboxes", lsRes, err)
		}
		sandboxes = msb.ParseSandboxList(lsRes.Stdout)
		if err := a.checkProfileNotActive(opts.Profile, runSandbox, sandboxes); err != nil {
			return err
		}
		volSize := defaultStr(a.Env.ProfileDisk, config.DefaultProfileDisk)
		volName, vErr := a.ensureProfileVolume(ctx, opts.Profile, volSize)
		if vErr != nil {
			return vErr
		}
		diskPath, dErr := msb.ResolveVolumeDiskPath(ctx, a.MSB, a.Env.MSBHome, volName)
		if dErr != nil {
			return dErr
		}
		profileDiskSpecs = []msb.DiskMountSpec{{
			HostPath:  diskPath,
			GuestPath: msb.GuestProfileMount,
		}}
	}

	validated, err := a.resolveRunShareTargets(opts)
	if err != nil {
		return err
	}

	var runMode config.RunMode
	switch {
	case opts.Cmd != "":
		runMode = config.RunModeCmd
	case opts.Serve:
		runMode = config.RunModeServe
	case opts.RemoteControl && (opts.Detach || a.IsTTY == nil || !a.IsTTY()):
		runMode = config.RunModeRemoteControl
	default:
		runMode = config.RunModeTUI
	}
	if runMode == config.RunModeTUI && (a.IsTTY == nil || !a.IsTTY()) {
		return errors.New("not a TTY. Use --cmd \"...\", --serve, or -d --remote-control")
	}

	port := 0
	if opts.Serve {
		port = opts.Port
		if port == 0 {
			port, err = pickFreeLoopbackPort()
			if err != nil {
				return fmt.Errorf("choose free loopback port: %w", err)
			}
		}
	}

	runRootDir := filepath.Join(a.Env.DataDir, "run")
	runFilterDir := filepath.Join(runRootDir, dirID)
	if err := config.EnsurePrivateDir(runRootDir); err != nil {
		return err
	}
	if err := config.EnsurePrivateDir(runFilterDir); err != nil {
		return err
	}

	runCtx, cancelRun := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	keepAlive := false
	suspendAfter := false
	sandboxCreated := false
	mountsActive := false
	var meta config.RunMeta
	var cleanupOnce sync.Once
	cleanup := func() {
		cleanupOnce.Do(func() {
			if keepAlive || hasMarker(filepath.Join(runFilterDir, "deleting")) || hasMarker(filepath.Join(runFilterDir, "suspended")) {
				cancelRun()
				return
			}
			if suspendAfter {
				cancelRun()
				a.suspendSandboxOnExit(runSandbox, runFilterDir, meta)
				return
			}
			cancelRun()
			if mountsActive {
				if uErr := mounttab.UnmountFilterDir(runFilterDir, a.MountCtl); uErr != nil {
					a.warnf("Could not unmount shares in %s: %v", runFilterDir, uErr)
				}
			}
			if sandboxCreated {
				if rmRes, rmErr := a.destroySandbox(context.Background(), runSandbox, opts.Profile != "", true); rmErr != nil {
					a.warnf("Could not delete sandbox %s: %v", runSandbox, formatMSBError("msb rm", rmRes, rmErr))
				}
			}
			if tdErr := mounttab.TeardownFilterDir(runFilterDir, a.MountCtl); tdErr != nil {
				a.warnf("Could not delete run directory %s: %v", runFilterDir, tdErr)
			}
		})
	}
	defer cleanup()

	// Write initial run.meta before starting FUSE so concurrent stale-directory reapers see our live OwnerPID.
	meta = config.RunMeta{
		Sandbox:         runSandbox,
		OwnerPID:        a.PID,
		Agent:           effectiveAgent,
		Mode:            runMode,
		Port:            port,
		Cmd:             opts.Cmd,
		ReadOnly:        opts.ReadOnly,
		MaskMode:        opts.MaskMode,
		Persist:         opts.Persist,
		Profile:         opts.Profile,
		RemoteControl:   opts.RemoteControl,
		Continue:        opts.Continue,
		ContinueSession: opts.ContinueSession,
		NoAuth:          opts.NoAuth,
		NoSkills:        opts.NoSkills,
		NoRules:         opts.NoRules,
		NoAgentCache:    opts.NoAgentCache,
		SkillsMounted:   mountSkills,
		RulesMounted:    mountRules,
		AgentsMounted:   mountAgents,
	}
	metaPath := filepath.Join(runFilterDir, "run.meta")
	if err := config.SaveRunMeta(metaPath, meta); err != nil {
		return fmt.Errorf("write initial run metadata: %w", err)
	}

	willDetach := (runMode == config.RunModeServe && !opts.Probe && (opts.Detach || a.IsTTY == nil || !a.IsTTY())) ||
		runMode == config.RunModeRemoteControl

	var volumes []msb.VolumeSpec
	var shareRecords []config.ShareRecord
	workspaceHub := false

	wantHub := useMask && (len(validated) > 0 || opts.ShareHub)
	if wantHub {
		if !dataDirSupportsFilter(a.Env.DataDir) {
			if opts.MaskMode == config.MaskStrict || opts.ShareHub {
				return fmt.Errorf("DATA_DIR (%s) contains unsupported characters for FUSE mounts", a.Env.DataDir)
			}
			a.warnf("DATA_DIR (%s) contains characters unsupported by FUSE. Mounting shares directly without VCS masking (AGBOX_MASK_VCS=auto).", a.Env.DataDir)
			useMask = false
		} else if a.StartHub == nil {
			if opts.MaskMode == config.MaskStrict || opts.ShareHub {
				return errors.New("FUSE Workspace Hub starter is not configured")
			}
			a.warnf("FUSE Workspace Hub starter is nil. Mounting shares directly without VCS masking (AGBOX_MASK_VCS=auto).")
			useMask = false
		} else {
			wsDir := filepath.Join(runFilterDir, "ws")
			wsSock := filepath.Join(runFilterDir, "ws.sock")
			wsPIDFile := filepath.Join(runFilterDir, "ws.pid")
			if err := config.EnsurePrivateDir(wsDir); err != nil {
				return err
			}
			initialHub := make([]vcsfuse.HubShareConfig, len(validated))
			for idx, sh := range validated {
				initialHub[idx] = vcsfuse.HubShareConfig{
					GuestName: sh.GuestName,
					HostPath:  sh.HostPath,
					ReadOnly:  sh.ReadOnly,
					VCSPolicy: sh.VCSPolicy,
				}
			}
			if _, fErr := a.StartHub(wsDir, wsSock, wsPIDFile, initialHub, !willDetach); fErr != nil {
				if opts.MaskMode == config.MaskStrict || opts.ShareHub {
					return fmt.Errorf("FUSE Workspace Hub failed for /workspace (%w). Fix FUSE or pass --no-mask", fErr)
				}
				a.warnf("FUSE Workspace Hub failed (%v). Mounting shares directly without VCS masking (AGBOX_MASK_VCS=auto).", fErr)
				useMask = false
			} else {
				workspaceHub = true
				mountsActive = true
				volumes = append(volumes, msb.VolumeSpec{
					HostPath:  wsDir,
					GuestPath: msb.GuestWorkspace,
					ReadOnly:  false,
					StatVirt:  "off",
				})
				for idx, sh := range validated {
					shareRecords = append(shareRecords, config.ShareRecord{
						Index:      idx,
						HostPath:   sh.HostPath,
						GuestName:  sh.GuestName,
						IsDir:      sh.IsDir,
						Masked:     sh.IsDir && sh.VCSPolicy == config.VCSMask,
						AccessMode: shareAccessMode(sh.ReadOnly),
						ReadOnly:   sh.ReadOnly,
						VCSPolicy:  sh.VCSPolicy,
					})
				}
			}
		}
	}

	if !workspaceHub {
		xattrFn := a.SupportsXattr
		if xattrFn == nil {
			xattrFn = supportsUserXattr
		}
		for idx, sh := range validated {
			if !isSafeGuestShareName(sh.GuestName) {
				return fmt.Errorf("share name %q contains characters unsupported by msb -v. Rename or copy without colons or commas", sh.GuestName)
			}
			var statVirt, hostPerms string
			if sh.ReadOnly {
				statVirt = "relaxed"
			} else if (a.euid() == config.GuestUID && a.egid() == config.GuestGID) || !xattrFn(sh.HostPath, sh.IsDir) {
				statVirt = "off"
			} else {
				statVirt = "relaxed"
				hostPerms = "mirror"
			}
			volumes = append(volumes, msb.VolumeSpec{
				HostPath:  sh.HostPath,
				GuestPath: msb.GuestWorkspace + "/" + sh.GuestName,
				ReadOnly:  sh.ReadOnly,
				StatVirt:  statVirt,
				HostPerms: hostPerms,
			})
			shareRecords = append(shareRecords, config.ShareRecord{
				Index:      idx,
				HostPath:   sh.HostPath,
				GuestName:  sh.GuestName,
				IsDir:      sh.IsDir,
				Masked:     false,
				AccessMode: shareAccessMode(sh.ReadOnly),
				ReadOnly:   sh.ReadOnly,
				VCSPolicy:  directShareVCSPolicy(sh.IsDir, sh.ReadOnly),
			})
		}
	}

	if mountSkills {
		volumes = append(volumes, msb.VolumeSpec{
			HostPath:  skillsDir,
			GuestPath: msb.GuestSkillsMount,
			ReadOnly:  true,
			StatVirt:  "relaxed",
		})
	}
	if mountRules {
		volumes = append(volumes, msb.VolumeSpec{
			HostPath:  rulesDir,
			GuestPath: msb.GuestRulesMount,
			ReadOnly:  true,
			StatVirt:  "relaxed",
		})
	}
	if mountAgents {
		volumes = append(volumes, msb.VolumeSpec{
			HostPath:  agentsDir,
			GuestPath: msb.GuestAgentsMount,
			ReadOnly:  true,
			StatVirt:  "relaxed",
		})
	}

	meta.WorkspaceHub = workspaceHub
	meta.Shares = shareRecords
	if err := config.SaveRunMeta(metaPath, meta); err != nil {
		return fmt.Errorf("write run metadata: %w", err)
	}

	cpus := defaultStr(opts.CPUs, a.Env.CPUs)
	memory := defaultStr(opts.Memory, a.Env.Memory)
	var ports []string
	if runMode == config.RunModeServe {
		ports = []string{fmt.Sprintf("127.0.0.1:%d:%d", port, config.GuestPort)}
	}
	restoreArgs, err := msb.BuildRestoreArgs(msb.RestoreOpts{
		Snapshot:   baseState.Snapshot,
		Name:       runSandbox,
		User:       config.GuestUser,
		CPUs:       cpus,
		Memory:     memory,
		NoNet:      opts.NoNet,
		NetSpecs:   opts.NetSpecs,
		Volumes:    volumes,
		DiskMounts: profileDiskSpecs,
		Ports:      ports,
	})
	if err != nil {
		return err
	}

	shareSummary := summarizeShareModes(shareRecords)
	a.logf("Restoring %s -> %s (%d share(s), %s, %s vCPU, %s)...",
		baseState.Snapshot, runSandbox, len(shareRecords), shareSummary, cpus, memory)

	sandboxCreated = true
	if res, err := a.MSB.Run(runCtx, msb.CommandRequest{Args: restoreArgs}); err != nil {
		return formatMSBError("restore snapshot", res, err)
	}

	if err := a.ensureGuestUser(runCtx, runSandbox); err != nil {
		return err
	}
	if mountAgents {
		if err := a.setupGuestAgents(runCtx, runSandbox); err != nil {
			return err
		}
	}
	if mountSkills {
		if err := a.setupGuestSkills(runCtx, runSandbox); err != nil {
			return err
		}
	}
	if mountRules {
		if err := a.setupGuestRules(runCtx, runSandbox); err != nil {
			return err
		}
	}
	if opts.Profile != "" {
		if err := a.setupGuestProfile(runCtx, runSandbox); err != nil {
			return err
		}
	}
	if !opts.NoAuth {
		if err := a.pushAuth(runCtx, runSandbox, effectiveAgent); err != nil {
			return err
		}
	}
	if err := a.pushKeys(runCtx, runSandbox); err != nil {
		return err
	}

	detachedMarker := filepath.Join(runFilterDir, "detached")
	execErr := a.execSession(runCtx, runSandbox, meta, willDetach, opts.Probe)
	if hasMarker(filepath.Join(runFilterDir, "suspended")) || hasMarker(filepath.Join(runFilterDir, "deleting")) {
		return nil
	}
	if execErr != nil {
		if opts.Persist && !willDetach {
			suspendAfter = true
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
	if opts.Persist {
		suspendAfter = true
	}
	return nil
}

func (a *appRuntime) ensureGuestUser(ctx context.Context, sandbox string) error {
	checkArgs := msb.BuildExecArgs(msb.ExecCmdOpts{
		Sandbox: sandbox,
		User:    config.GuestUser,
		Command: []string{"true"},
	})
	if _, err := a.MSB.Run(ctx, msb.CommandRequest{Args: checkArgs}); err == nil {
		return nil
	}
	return a.provisionGuestUser(ctx, sandbox)
}

func (a *appRuntime) pushKeys(ctx context.Context, sandbox string) error {
	script, count := msb.FormatEnvExports(a.Getenv, msb.DefaultPassthroughEnvVars)
	writeCmd := fmt.Sprintf(
		"[ ! -L /home/agent ] || { echo 'agbox rejects symlinked /home/agent' >&2; exit 1; }; rm -f %s && umask 077 && cat > %s && chmod 0600 %s",
		config.GuestKeysFile, config.GuestKeysFile, config.GuestKeysFile,
	)
	execArgs := msb.BuildExecArgs(msb.ExecCmdOpts{
		Sandbox: sandbox,
		User:    config.GuestUser,
		Command: []string{"sh", "-c", writeCmd},
	})
	res, err := a.MSB.Run(ctx, msb.CommandRequest{
		Args:  execArgs,
		Stdin: strings.NewReader(script),
	})
	if err != nil {
		return formatMSBError("stream environment secrets into "+sandbox, res, err)
	}
	if count > 0 {
		a.logf("Streamed %d environment secret(s) into %s.", count, config.GuestKeysFile)
	}
	return nil
}

func (a *appRuntime) execSession(ctx context.Context, sandbox string, meta config.RunMeta, willDetach bool, probe bool) error {
	workDir := sessionWorkDir(meta.Shares)
	envFlags := msb.GuestEnvFlags()

	switch meta.Mode {
	case config.RunModeCmd:
		inner := fmt.Sprintf("%s cd %s && exec sh -c %s", msb.KeyLoaderPrefix, msb.ShellQuote(workDir), msb.ShellQuote(meta.Cmd))
		noStdin := a.cmdNeedsNoStdin()
		execArgs := msb.BuildExecArgs(msb.ExecCmdOpts{
			Sandbox: sandbox,
			User:    config.GuestUser,
			Stream:  true,
			NoStdin: noStdin,
			Env:     envFlags,
			Command: []string{"sh", "-c", inner},
		})
		res, err := a.MSB.Run(ctx, msb.CommandRequest{
			Args:        execArgs,
			Stdin:       a.Stdin,
			Stdout:      a.Stdout,
			Stderr:      a.Stderr,
			Interactive: true,
		})
		return wrapPassthroughExit(res, err)

	case config.RunModeRemoteControl:
		startInner := fmt.Sprintf(
			"%s cd %s && agy remote-control start --name %s",
			msb.KeyLoaderPrefix, msb.ShellQuote(workDir), msb.ShellQuote(sandbox),
		)
		startArgs := msb.BuildExecArgs(msb.ExecCmdOpts{
			Sandbox: sandbox,
			User:    config.GuestUser,
			Stream:  true,
			NoStdin: true,
			Env:     envFlags,
			Command: []string{"sh", "-c", startInner},
		})
		startRes, err := a.MSB.Run(ctx, msb.CommandRequest{
			Args:   startArgs,
			Stdout: a.Stdout,
			Stderr: a.Stderr,
		})
		if err != nil {
			return formatMSBError("start Antigravity Remote Control", startRes, err)
		}
		statusInner := fmt.Sprintf("%s cd %s && agy remote-control status", msb.KeyLoaderPrefix, msb.ShellQuote(workDir))
		statusArgs := msb.BuildExecArgs(msb.ExecCmdOpts{
			Sandbox: sandbox,
			User:    config.GuestUser,
			Stream:  true,
			NoStdin: true,
			Env:     envFlags,
			Command: []string{"sh", "-c", statusInner},
		})
		_, _ = a.MSB.Run(ctx, msb.CommandRequest{
			Args:   statusArgs,
			Stdout: a.Stdout,
			Stderr: a.Stderr,
		})
		fmt.Fprintln(a.Stdout, "[agbox] Antigravity Remote Control active: https://antigravity.google.com")
		fmt.Fprintf(a.Stdout, "[agbox] Suspend: agbox suspend %s | Stop: agbox stop %s\n", sandbox, sandbox)
		return nil

	case config.RunModeServe:
		serveCmd := fmt.Sprintf(
			"%s cd %s && exec opencode serve --hostname 0.0.0.0 --port %d",
			msb.KeyLoaderPrefix, msb.ShellQuote(workDir), config.GuestPort,
		)
		if willDetach || probe {
			bgCmd := fmt.Sprintf(
				"%s cd %s && nohup opencode serve --hostname 0.0.0.0 --port %d </dev/null >/tmp/agbox-serve.log 2>&1 & pid=$!; sleep 1; kill -0 \"$pid\"",
				msb.KeyLoaderPrefix, msb.ShellQuote(workDir), config.GuestPort,
			)
			execArgs := msb.BuildExecArgs(msb.ExecCmdOpts{
				Sandbox: sandbox,
				User:    config.GuestUser,
				Stream:  true,
				NoStdin: true,
				Env:     envFlags,
				Command: []string{"sh", "-c", bgCmd},
			})
			res, err := a.MSB.Run(ctx, msb.CommandRequest{Args: execArgs})
			if err != nil {
				return formatMSBError("start opencode serve", res, err)
			}
			waitFn := a.WaitServeUI
			if waitFn == nil {
				waitFn = a.defaultWaitServeUI
			}
			if !waitFn(ctx, meta.Port, sandbox) {
				logRes, _ := a.runGuestRootScript(ctx, sandbox, "read serve log", "sh", "tail -n 30 /tmp/agbox-serve.log 2>/dev/null || true")
				detail := strings.TrimSpace(logRes.Stdout)
				if detail != "" {
					return fmt.Errorf("opencode serve did not answer on http://127.0.0.1:%d (%s)", meta.Port, detail)
				}
				return fmt.Errorf("opencode serve did not answer on http://127.0.0.1:%d", meta.Port)
			}
			if probe {
				fmt.Fprintf(a.Stdout, "[agbox] OpenCode web UI: http://127.0.0.1:%d\n", meta.Port)
				fmt.Fprintf(a.Stdout, "[agbox] --probe: UI verified at http://127.0.0.1:%d.\n", meta.Port)
				return nil
			}
			if a.Getenv == nil || a.Getenv("OPENCODE_SERVER_PASSWORD") == "" {
				a.warnf("Loopback TCP (127.0.0.1:%d) accepts connections from any local user on this host. Set OPENCODE_SERVER_PASSWORD before 'agbox run --serve' on multi-user systems.", meta.Port)
			}
			fmt.Fprintf(a.Stdout, "[agbox] OpenCode web UI: http://127.0.0.1:%d\n", meta.Port)
			fmt.Fprintf(a.Stdout, "[agbox] Suspend: agbox suspend %s | Stop: agbox stop %s\n", sandbox, sandbox)
			return nil
		}

		if a.Getenv == nil || a.Getenv("OPENCODE_SERVER_PASSWORD") == "" {
			a.warnf("Loopback TCP (127.0.0.1:%d) accepts connections from any local user on this host. Set OPENCODE_SERVER_PASSWORD before 'agbox run --serve' on multi-user systems.", meta.Port)
		}
		fmt.Fprintf(a.Stdout, "[agbox] OpenCode web UI: http://127.0.0.1:%d\n", meta.Port)
		if meta.Persist {
			fmt.Fprintf(a.Stdout, "[agbox] Press Ctrl-C to stop and persist %s.\n", sandbox)
		} else {
			fmt.Fprintln(a.Stdout, "[agbox] Press Ctrl-C to stop and delete this microVM.")
		}
		execArgs := msb.BuildExecArgs(msb.ExecCmdOpts{
			Sandbox: sandbox,
			TTY:     true,
			User:    config.GuestUser,
			Env:     envFlags,
			Command: []string{"sh", "-c", serveCmd},
		})
		res, err := a.MSB.Run(ctx, msb.CommandRequest{
			Args:        execArgs,
			Interactive: true,
		})
		return wrapPassthroughExit(res, err)

	default:
		inner := fmt.Sprintf("%s cd %s && exec %s", msb.KeyLoaderPrefix, msb.ShellQuote(workDir), buildTUIInvokeCommand(meta))
		execArgs := msb.BuildExecArgs(msb.ExecCmdOpts{
			Sandbox: sandbox,
			TTY:     true,
			User:    config.GuestUser,
			Env:     envFlags,
			Command: []string{"sh", "-c", inner},
		})
		res, err := a.MSB.Run(ctx, msb.CommandRequest{
			Args:        execArgs,
			Interactive: true,
		})
		return wrapPassthroughExit(res, err)
	}
}

func (a *appRuntime) defaultWaitServeUI(ctx context.Context, port int, sandbox string) bool {
	waitCtx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()

	client := &http.Client{
		Timeout: 3 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	url := fmt.Sprintf("http://127.0.0.1:%d/doc", port)
	user := "opencode"
	pass := ""
	if a.Getenv != nil {
		user = defaultStr(a.Getenv("OPENCODE_SERVER_USERNAME"), "opencode")
		pass = a.Getenv("OPENCODE_SERVER_PASSWORD")
	}

	for waitCtx.Err() == nil {
		req, err := http.NewRequestWithContext(waitCtx, http.MethodGet, url, nil)
		if err != nil {
			return false
		}
		if pass != "" {
			req.SetBasicAuth(user, pass)
		}
		resp, err := client.Do(req)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				return true
			}
		}
		if a.MSB != nil {
			if _, pErr := a.MSB.Run(waitCtx, msb.CommandRequest{Args: []string{"ping", sandbox}}); pErr != nil {
				return false
			}
		}
		timer := time.NewTimer(time.Second)
		select {
		case <-waitCtx.Done():
			timer.Stop()
			return false
		case <-timer.C:
		}
	}
	return false
}

func (a *appRuntime) sharePolicy(readOnly bool) pathsec.Policy {
	return pathsec.Policy{
		HomeReal:         a.Env.HomeReal,
		AllowOutsideHome: a.Env.AllowOutsideHome,
		ReadOnly:         readOnly,
		Blocklist:        pathsec.DefaultBlocklist(a.Env.HomeReal, a.Env.DataDir, a.Env.MSBHome),
		VCSNames:         pathsec.DefaultVCSNames(),
	}
}

func (a *appRuntime) resolveRunShareTargets(opts runOpts) ([]pathsec.ShareTarget, error) {
	allRaw := make([]string, 0, len(opts.ShareSpecs)+len(opts.Paths))
	allRaw = append(allRaw, opts.ShareSpecs...)
	allRaw = append(allRaw, opts.Paths...)
	if len(allRaw) == 0 {
		return nil, nil
	}
	specs := make([]pathsec.ShareSpec, 0, len(allRaw))
	for _, raw := range allRaw {
		if raw == "" {
			continue
		}
		sp, err := pathsec.ParseShareSpec(raw)
		if err != nil {
			return nil, err
		}
		specs = append(specs, sp)
	}
	if len(specs) == 0 {
		return nil, nil
	}
	return pathsec.ResolveShareSpecs(specs, pathsec.ResolveOpts{
		Policy:     a.sharePolicy(opts.ReadOnly),
		DefaultRO:  opts.ReadOnly,
		LockRO:     opts.LockAccess,
		DefaultVCS: opts.DefaultVCS,
		LockVCS:    opts.LockVCS,
	})
}

func isSafeGuestShareName(name string) bool {
	if name == "" || name == "." || name == ".." {
		return false
	}
	return !strings.ContainsAny(name, "/:,")
}

func summarizeShareModes(shares []config.ShareRecord) string {
	if len(shares) == 0 {
		return "no host shares"
	}
	roCount := 0
	rwCount := 0
	maskCount := 0
	vcsCount := 0
	hooksCount := 0
	for _, sh := range shares {
		if sh.ReadOnly {
			roCount++
		} else {
			rwCount++
		}
		switch sh.EffectiveVCSPolicy() {
		case config.VCSAllow:
			vcsCount++
		case config.VCSAllowHooks:
			hooksCount++
		default:
			maskCount++
		}
	}
	var parts []string
	switch {
	case roCount > 0 && rwCount == 0:
		parts = append(parts, "ro")
	case rwCount > 0 && roCount == 0:
		parts = append(parts, "rw")
	default:
		parts = append(parts, fmt.Sprintf("%d rw/%d ro", rwCount, roCount))
	}
	switch {
	case vcsCount == 0 && hooksCount == 0:
		parts = append(parts, "VCS masked")
	case maskCount == 0 && hooksCount == 0:
		parts = append(parts, "VCS allowed (hooks ro)")
	case maskCount == 0 && vcsCount == 0:
		parts = append(parts, "VCS + hooks")
	default:
		parts = append(parts, fmt.Sprintf("vcs:%d mask/%d ro-hooks/%d rw-hooks", maskCount, vcsCount, hooksCount))
	}
	return strings.Join(parts, ", ")
}

func pickFreeLoopbackPort() (int, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer ln.Close()
	addr, ok := ln.Addr().(*net.TCPAddr)
	if !ok || addr.Port <= 0 {
		return 0, errors.New("unexpected listener address")
	}
	return addr.Port, nil
}

func supportsUserXattr(path string, _ bool) bool {
	var buf [1]byte
	_, err := unix.Getxattr(path, "user.agbox.probe", buf[:])
	return !errors.Is(err, unix.ENOTSUP) && !errors.Is(err, unix.EOPNOTSUPP)
}
