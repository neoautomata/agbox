package cli

import (
	"context"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"agbox/internal/config"
	"agbox/internal/msb"
	"agbox/internal/persist"
)

func (a *appRuntime) update(ctx context.Context, args []string) error {
	opts, err := parseUpdateArgs(args)
	if err != nil {
		return err
	}
	agentsDir := filepath.Join(a.Env.DataDir, "agents")

	switch opts.Action {
	case "status":
		if err := a.verifyUser(opts.AllowRoot); err != nil {
			return err
		}
		if err := config.EnsurePrivateDir(a.Env.DataDir); err != nil {
			return fmt.Errorf("prepare data dir: %w", err)
		}
		cached, err := persist.InspectAgentsDir(agentsDir)
		if err != nil {
			return err
		}
		if len(cached) == 0 {
			fmt.Fprintln(a.Stdout, "No cached agent updates.")
			return nil
		}
		for _, info := range cached {
			fmt.Fprintf(a.Stdout, "%s: version=%s sha256=%s updated_at=%s\n",
				info.Agent, info.Version, shortSHA256(info.SHA256), info.UpdatedAt)
		}
		return nil

	case "clear":
		if err := a.verifyUser(opts.AllowRoot); err != nil {
			return err
		}
		if err := config.EnsurePrivateDir(a.Env.DataDir); err != nil {
			return fmt.Errorf("prepare data dir: %w", err)
		}
		if err := persist.RemoveCachedAgent(agentsDir, opts.Target); err != nil {
			return err
		}
		a.logf("Removed cached %s agent update(s) from %s.", opts.Target, agentsDir)
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

	target := opts.Target
	if target == "" {
		target = defaultStr(baseState.Agent, "both")
	}
	if baseState.Agent != "" && baseState.Agent != "both" && target != baseState.Agent {
		return fmt.Errorf("the base snapshot contains only agent=%s. Run 'agbox create-base %s' or 'agbox create-base both'", baseState.Agent, target)
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

	updCtx, updSandbox, cleanup, err := a.startDisposableVM(
		ctx,
		"update",
		baseState.Snapshot,
		target,
		config.RunModeCmd,
		"Booting disposable update microVM %s (zero host shares, zero host secrets)...",
	)
	if err != nil {
		return err
	}
	defer cleanup()

	for _, ag := range targets {
		updScript, streamCmd, verCmd, err := persist.BuildAgentUpdateScript(ag, a.Env.OpenCodeVersion, a.Env.AgyInstallerURL)
		if err != nil {
			return err
		}
		a.logf("Updating %s inside %s...", ag, updSandbox)
		updArgs := msb.BuildExecArgs(msb.ExecCmdOpts{
			Sandbox: updSandbox,
			User:    "root",
			Stream:  true,
			NoStdin: true,
			Command: []string{"bash", "-c", updScript},
		})
		updRes, err := a.MSB.Run(updCtx, msb.CommandRequest{Args: updArgs})
		if err != nil {
			detail := strings.TrimSpace(updRes.Stderr + "\n" + updRes.Stdout)
			if detail != "" {
				return fmt.Errorf("update %s failed: %w (%s)", ag, err, tailLines(detail, 10))
			}
			return fmt.Errorf("update %s failed: %w", ag, err)
		}

		verRes, err := a.runGuestRootScript(updCtx, updSandbox, "read updated "+ag+" version", "sh", verCmd)
		if err != nil {
			return err
		}

		cw, err := persist.NewAgentBinaryCaptureWriter(agentsDir, ag)
		if err != nil {
			return err
		}
		cw.Now = a.Now
		streamArgs := msb.BuildExecArgs(msb.ExecCmdOpts{
			Sandbox: updSandbox,
			User:    "root",
			Stream:  true,
			NoStdin: true,
			Command: []string{"sh", "-c", streamCmd},
		})
		streamRes, streamErr := a.MSB.Run(updCtx, msb.CommandRequest{
			Args:   streamArgs,
			Stdout: cw,
		})
		if streamErr != nil {
			cw.Abort()
			return formatMSBError("stream "+ag+" binary from "+updSandbox, streamRes, streamErr)
		}
		if cw.Written() == 0 && len(streamRes.Stdout) > 0 {
			if _, wErr := io.WriteString(cw, streamRes.Stdout); wErr != nil {
				cw.Abort()
				return wErr
			}
		}
		info, err := cw.Commit(verRes.Stdout)
		if err != nil {
			return fmt.Errorf("check and cache %s binary: %w", ag, err)
		}
		a.logf("Cached %s (%s, sha256:%s) in %s.", ag, info.Version, shortSHA256(info.SHA256), agentsDir)
	}

	return nil
}

func (a *appRuntime) setupGuestAgents(ctx context.Context, sandbox string) error {
	_, err := a.runGuestRootScript(ctx, sandbox, "bind-mount cached agent binaries in "+sandbox, "sh", persist.BuildGuestAgentsMountScript())
	return err
}
