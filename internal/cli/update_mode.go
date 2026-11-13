package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"

	"agbox/internal/config"
	"agbox/internal/mounttab"
	"agbox/internal/msb"
	"agbox/internal/persist"
)

// UpdateOpts holds parsed CLI arguments for `agbox update`.
type UpdateOpts struct {
	Action    string // "update", "status", "clear"
	Target    string // "", "antigravity", "opencode", "both", "all"
	AllowRoot bool
}

// ParseUpdateArgs parses CLI arguments for `agbox update`.
func ParseUpdateArgs(args []string) (UpdateOpts, error) {
	opts := UpdateOpts{Action: "update"}
	var pos []string
	for _, a := range args {
		switch a {
		case "-h", "--help":
			return UpdateOpts{}, ErrHelp
		case "--allow-root":
			opts.AllowRoot = true
		default:
			if strings.HasPrefix(a, "-") {
				return UpdateOpts{}, fmt.Errorf("unknown update option: %s (run 'agbox update --help')", a)
			}
			pos = append(pos, a)
		}
	}

	if len(pos) == 0 {
		return opts, nil
	}

	switch pos[0] {
	case "status", "list":
		if len(pos) > 1 {
			return UpdateOpts{}, errors.New("Usage: agbox update [--allow-root] status")
		}
		opts.Action = "status"
		return opts, nil

	case "clear", "rm":
		if len(pos) > 2 {
			return UpdateOpts{}, errors.New("Usage: agbox update [--allow-root] clear [antigravity|opencode|all]")
		}
		opts.Action = "clear"
		opts.Target = "all"
		if len(pos) == 2 {
			switch pos[1] {
			case "antigravity", "opencode", "all":
				opts.Target = pos[1]
			case "both":
				opts.Target = "all"
			default:
				return UpdateOpts{}, fmt.Errorf("unknown update clear target %q (expected antigravity, opencode, or all)", pos[1])
			}
		}
		return opts, nil

	case "antigravity", "opencode", "both":
		if len(pos) > 1 {
			return UpdateOpts{}, errors.New("Usage: agbox update [--allow-root] [antigravity|opencode|both]")
		}
		opts.Target = pos[0]
		return opts, nil

	default:
		return UpdateOpts{}, fmt.Errorf("unknown update argument %q (expected antigravity, opencode, both, status, or clear)", pos[0])
	}
}

// UpdateUsageText returns the help message for `agbox update --help`.
func UpdateUsageText() string {
	return `Usage:
  agbox update [--allow-root] [antigravity|opencode|both]
      Update agent binaries inside a disposable zero-share microVM and cache
      verified ELF binaries in $DATA_DIR/agents for read-only sandbox mounts.
  agbox update [--allow-root] status
      Show cached agent versions and SHA-256 digests in $DATA_DIR/agents.
  agbox update [--allow-root] clear [antigravity|opencode|all]
      Delete cached agent updates and revert new runs to the base snapshot binaries.
`
}

// Update downloads updated agent binaries inside a disposable microVM and stores
// verified ELF executables in $DATA_DIR/agents.
func (a *App) Update(ctx context.Context, args []string) error {
	opts, err := ParseUpdateArgs(args)
	if err != nil {
		return err
	}
	if err := a.verifyUser(opts.AllowRoot); err != nil {
		return err
	}
	if err := config.EnsurePrivateDir(a.Env.DataDir); err != nil {
		return fmt.Errorf("prepare data dir: %w", err)
	}

	agentsDir := filepath.Join(a.Env.DataDir, "agents")

	switch opts.Action {
	case "status":
		cached, err := persist.InspectAgentsDir(agentsDir)
		if err != nil {
			return err
		}
		if len(cached) == 0 {
			fmt.Fprintln(a.Stdout, "No cached agent updates.")
			return nil
		}
		for _, info := range cached {
			shortHash := info.SHA256
			if len(shortHash) > 12 {
				shortHash = shortHash[:12]
			}
			fmt.Fprintf(a.Stdout, "%s: version=%s sha256=%s updated_at=%s\n",
				info.Agent, info.Version, shortHash, info.UpdatedAt)
		}
		return nil

	case "clear":
		if err := persist.RemoveCachedAgent(agentsDir, opts.Target); err != nil {
			return err
		}
		a.logf("Removed cached %s agent update(s) from %s.", opts.Target, agentsDir)
		return nil
	}

	if err := a.requireSetup(opts.AllowRoot); err != nil {
		return err
	}
	baseState, err := a.requireBase(ctx)
	if err != nil {
		return err
	}

	target := opts.Target
	if target == "" {
		target = defaultStr(baseState.Agent, "both")
	}
	if baseState.Agent != "" && baseState.Agent != "both" && target != baseState.Agent {
		return fmt.Errorf("base was built for agent=%s. Rebuild with 'agbox create-base %s' or 'both' first", baseState.Agent, target)
	}

	var targets []string
	switch target {
	case "both":
		targets = []string{"antigravity", "opencode"}
	case "antigravity", "opencode":
		targets = []string{target}
	default:
		return fmt.Errorf("unsupported update target %q", target)
	}

	if err := persist.EnsureAgentsDir(agentsDir); err != nil {
		return err
	}
	if _, err := persist.InspectAgentsDir(agentsDir); err != nil {
		return err
	}

	a.ReapOrphanRuns(ctx)
	a.ReapStaleFilterDirs(ctx)

	updName := fmt.Sprintf("update-%d", a.PID)
	updSandbox := FormatRunSandboxName(updName, a.PID)
	runRootDir := filepath.Join(a.Env.DataDir, "run")
	updRunDir := filepath.Join(runRootDir, updName)
	if err := config.EnsurePrivateDir(runRootDir); err != nil {
		return err
	}
	if err := config.EnsurePrivateDir(updRunDir); err != nil {
		return err
	}
	meta := config.RunMeta{
		Sandbox:  updSandbox,
		OwnerPID: a.PID,
		Agent:    target,
		Mode:     config.RunModeCmd,
		MaskMode: config.MaskStrict,
	}
	if err := config.SaveRunMeta(filepath.Join(updRunDir, "run.meta"), meta); err != nil {
		return err
	}

	updCtx, cancelUpd := context.WithCancel(ctx)
	defer cancelUpd()

	sandboxCreated := false
	var cleanupOnce sync.Once
	cleanup := func() {
		cleanupOnce.Do(func() {
			if sandboxCreated {
				_, _ = a.MSB.Run(context.Background(), msb.CommandRequest{Args: []string{"rm", "-f", updSandbox}})
			}
			_ = mounttab.TeardownFilterDir(updRunDir, a.MountCtl)
		})
	}
	defer cleanup()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	defer signal.Stop(sigCh)
	go func() {
		select {
		case <-sigCh:
			cancelUpd()
			cleanup()
		case <-updCtx.Done():
		}
	}()

	restoreArgs, err := msb.BuildRestoreArgs(msb.RestoreOpts{
		Snapshot: baseState.Snapshot,
		Name:     updSandbox,
		User:     config.GuestUser,
		CPUs:     a.Env.CPUs,
		Memory:   a.Env.Memory,
		NetSpecs: []string{"public"},
	})
	if err != nil {
		return err
	}

	a.logf("Booting disposable update microVM %s (zero host shares, zero host secrets)...", updSandbox)
	sandboxCreated = true
	if _, err := a.MSB.Run(updCtx, msb.CommandRequest{Args: restoreArgs}); err != nil {
		return fmt.Errorf("snapshot restore failed: %w", err)
	}
	if err := a.ensureGuestUser(updCtx, updSandbox); err != nil {
		return err
	}

	for _, ag := range targets {
		updScript, streamCmd, verCmd, err := persist.BuildAgentUpdateScript(ag, a.Env.OpenCodeVersion, a.Env.AgyInstallerURL)
		if err != nil {
			return err
		}
		a.logf("Updating %s inside %s...", ag, updSandbox)
		updRes, err := a.MSB.Run(updCtx, msb.CommandRequest{
			Args: []string{"exec", updSandbox, "--", "bash", "-c", updScript},
		})
		if err != nil {
			detail := strings.TrimSpace(updRes.Stderr + "\n" + updRes.Stdout)
			if detail != "" {
				return fmt.Errorf("update %s failed: %w (%s)", ag, err, tailLines(detail, 10))
			}
			return fmt.Errorf("update %s failed: %w", ag, err)
		}

		verRes, err := a.MSB.Run(updCtx, msb.CommandRequest{
			Args: []string{"exec", updSandbox, "--", "sh", "-c", verCmd},
		})
		if err != nil {
			return fmt.Errorf("read updated %s version: %w", ag, err)
		}

		cw, err := persist.NewAgentBinaryCaptureWriter(agentsDir, ag)
		if err != nil {
			return err
		}
		streamArgs := msb.BuildExecArgs(msb.ExecCmdOpts{
			Sandbox: updSandbox,
			NoTTY:   true,
			Command: []string{"sh", "-c", streamCmd},
		})
		streamRes, streamErr := a.MSB.Run(updCtx, msb.CommandRequest{
			Args:   streamArgs,
			Stdout: cw,
		})
		if streamErr != nil {
			cw.Abort()
			return fmt.Errorf("stream %s binary from %s: %w", ag, updSandbox, streamErr)
		}
		if cw.Written() == 0 && len(streamRes.Stdout) > 0 {
			if _, wErr := io.WriteString(cw, streamRes.Stdout); wErr != nil {
				cw.Abort()
				return wErr
			}
		}
		info, err := cw.Commit(verRes.Stdout)
		if err != nil {
			return fmt.Errorf("verify and cache %s binary: %w", ag, err)
		}
		shortHash := info.SHA256
		if len(shortHash) > 12 {
			shortHash = shortHash[:12]
		}
		a.logf("Cached %s (%s, sha256:%s) in %s.", ag, info.Version, shortHash, agentsDir)
	}

	return nil
}

func (a *App) setupGuestAgents(ctx context.Context, sandbox string) error {
	script := persist.BuildGuestAgentsMountScript()
	if _, err := a.MSB.Run(ctx, msb.CommandRequest{
		Args: []string{"exec", sandbox, "--", "sh", "-c", script},
	}); err != nil {
		return fmt.Errorf("bind-mount cached agent binaries in %s: %w", sandbox, err)
	}
	return nil
}
