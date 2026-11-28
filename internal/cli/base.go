package cli

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"agbox/internal/config"
	"agbox/internal/msb"
	"agbox/internal/persist"
	"agbox/internal/vcsfuse"
)

func (a *appRuntime) setup(ctx context.Context, args []string) error {
	opts, err := parseSetupArgs(args)
	if err != nil {
		return err
	}
	a.logf("Checking host...")
	if err := a.verifyUser(opts.AllowRoot); err != nil {
		return err
	}
	if !dataDirSupportsFilter(a.Env.DataDir) {
		return fmt.Errorf("DATA_DIR (%s) cannot contain whitespace, backslashes, or control characters", a.Env.DataDir)
	}
	if err := config.EnsurePrivateDir(a.Env.DataDir); err != nil {
		return fmt.Errorf("prepare data dir %s: %w", a.Env.DataDir, err)
	}

	if err := a.ensureMSB(); err != nil {
		return fmt.Errorf("%w (run ./install.sh or 'curl --proto \"=https\" --proto-redir \"=https\" --tlsv1.2 -fsSL https://install.microsandbox.dev | sh')", err)
	}
	if verRes, err := a.MSB.Run(ctx, msb.CommandRequest{Args: []string{"--version"}}); err == nil {
		firstLine, _, _ := strings.Cut(strings.TrimSpace(verRes.Stdout), "\n")
		a.logf("msb %s", firstLine)
	}

	kvmCheck := a.CheckKVM
	if kvmCheck == nil {
		kvmCheck = checkKVMAccess
	}
	if err := kvmCheck(); err != nil {
		if a.isRoot() {
			return fmt.Errorf("%w\nEnsure /dev/kvm exists and load the KVM kernel module (kvm_intel or kvm_amd)", err)
		}
		return fmt.Errorf("%w\nGrant access: sudo usermod -aG kvm $(id -un) or sudo setfacl -m u:$(id -un):rw /dev/kvm", err)
	}
	a.logf("/dev/kvm accessible: OK")

	fuseCheck := a.CheckFUSE
	if fuseCheck == nil {
		fuseCheck = func() error {
			return vcsfuse.CheckHostSupport(a.Env.DataDir)
		}
	}
	if err := fuseCheck(); err != nil {
		return fmt.Errorf("FUSE VCS filter check failed: %w", err)
	}
	a.logf("FUSE VCS filter accessible: OK")

	a.logf("Running msb doctor...")
	if _, err := a.MSB.Run(ctx, msb.CommandRequest{Args: []string{"doctor"}, Interactive: true}); err != nil {
		return fmt.Errorf("msb doctor reported problems: %w", err)
	}

	a.logf("Smoke test: booting an offline alpine microVM...")
	smoke := fmt.Sprintf("%s-%d", config.RunPrefix, a.PID)
	smokeRemoved := false
	defer func() {
		if !smokeRemoved {
			teardownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			rmRes, rmErr := a.MSB.Run(teardownCtx, msb.CommandRequest{Args: []string{"rm", "-f", smoke}})
			cancel()
			if rmErr != nil && !isMSBSandboxNotFound(rmRes) {
				a.warnf("Could not delete smoke-test sandbox %s: %v", smoke, formatMSBError("msb rm", rmRes, rmErr))
			}
		}
	}()
	if createRes, err := a.MSB.Run(ctx, msb.CommandRequest{
		Args: []string{"create", "alpine", "--name", smoke, "--cpus", "1", "--memory", "256M", "--no-net"},
	}); err != nil {
		return formatMSBError("boot smoke-test sandbox", createRes, err)
	}
	execRes, err := a.runGuestRootScript(ctx, smoke, "run smoke-test command", "sh", "echo SMOKE-OK; id -u")
	if err != nil {
		return err
	}
	if !strings.Contains(execRes.Stdout, "SMOKE-OK") {
		return errors.New("smoke test failed: unexpected output from guest command")
	}
	if rmRes, err := a.MSB.Run(ctx, msb.CommandRequest{Args: []string{"rm", "-f", smoke}}); err != nil {
		return formatMSBError("delete smoke-test sandbox "+smoke, rmRes, err)
	}
	smokeRemoved = true
	a.logf("Smoke test: OK (guest boots, exec works, deletion clean)")

	rulesDir := filepath.Join(a.Env.DataDir, "rules")
	if created, err := persist.EnsureDefaultEnvRule(rulesDir); err != nil {
		return fmt.Errorf("install default sandbox rules: %w", err)
	} else if created {
		a.logf("Installed default global rule %q in %s.", persist.DefaultEnvRuleName, filepath.Join(rulesDir, persist.DefaultEnvRuleName+".md"))
	}

	a.logf("Embedded FUSE VCS filter ready (single binary: %s).", a.ExePath)
	if a.isRoot() {
		a.logf("Setup complete. Next: agbox create-base --allow-root <opencode|antigravity|both>")
	} else {
		a.logf("Setup complete. Next: agbox create-base <opencode|antigravity|both>")
	}
	return nil
}

func (a *appRuntime) createBase(ctx context.Context, args []string) error {
	opts, err := parseCreateBaseArgs(args)
	if err != nil {
		return err
	}
	if err := a.requireSetup(opts.AllowRoot); err != nil {
		return err
	}
	if err := config.EnsurePrivateDir(a.Env.DataDir); err != nil {
		return fmt.Errorf("prepare data dir %s: %w", a.Env.DataDir, err)
	}

	lsRes, err := a.MSB.Run(ctx, msb.CommandRequest{Args: []string{"ls"}})
	if err != nil {
		return formatMSBError("list sandboxes", lsRes, err)
	}
	if _, exists := msb.FindSandbox(msb.ParseSandboxList(lsRes.Stdout), config.BaseSandbox); exists {
		_, confErr := os.Lstat(a.Env.ConfigFile)
		if opts.Force || os.IsNotExist(confErr) {
			a.logf("Replacing existing base sandbox %q...", config.BaseSandbox)
			if rmRes, rmErr := a.MSB.Run(ctx, msb.CommandRequest{Args: []string{"rm", "-f", config.BaseSandbox}}); rmErr != nil {
				return formatMSBError(fmt.Sprintf("delete existing base sandbox %q", config.BaseSandbox), rmRes, rmErr)
			}
		} else if confErr != nil {
			return fmt.Errorf("stat base config %s: %w", a.Env.ConfigFile, confErr)
		} else {
			return fmt.Errorf("base sandbox %q already exists. Edit it with 'agbox edit-base' or rebuild with 'agbox create-base --force %s'", config.BaseSandbox, opts.Agent)
		}
	}

	image := "debian:bookworm-slim"
	if opts.Agent == "opencode" || opts.Agent == "both" {
		image = "node:24-bookworm-slim"
	}

	a.logf("Creating base sandbox %q from %s (%s vCPU, %s, %s disk)...",
		config.BaseSandbox, image, a.Env.CPUs, a.Env.Memory, a.Env.RootDisk)

	createArgs, err := msb.BuildCreateArgs(msb.CreateOpts{
		Image:    image,
		Name:     config.BaseSandbox,
		CPUs:     a.Env.CPUs,
		Memory:   a.Env.Memory,
		RootDisk: a.Env.RootDisk,
		Workdir:  msb.GuestWorkspace,
		NetSpecs: []string{"public"},
	})
	if err != nil {
		return err
	}
	succeeded := false
	defer func() {
		if !succeeded {
			teardownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			rmRes, rmErr := a.MSB.Run(teardownCtx, msb.CommandRequest{Args: []string{"rm", "-f", config.BaseSandbox}})
			cancel()
			if rmErr != nil && !isMSBSandboxNotFound(rmRes) {
				a.warnf("Could not delete incomplete base sandbox %s: %v", config.BaseSandbox, formatMSBError("msb rm", rmRes, rmErr))
			}
		}
	}()
	if _, err := a.MSB.Run(ctx, msb.CommandRequest{
		Args:   createArgs,
		Stdout: a.Stdout,
		Stderr: a.Stderr,
	}); err != nil {
		return fmt.Errorf("create base sandbox: %w", err)
	}

	a.logf("Provisioning guest (apt baseline, shellcheck, mdformat, and non-root %q user with passwordless sudo)...", config.GuestUser)
	aptCmd := "apt-get update -qq && apt-get install -y -qq --no-install-recommends ca-certificates curl git ripgrep less procps sudo shellcheck python3 python3-venv pipx >/dev/null"
	aptArgs := msb.BuildExecArgs(msb.ExecCmdOpts{
		Sandbox: config.BaseSandbox,
		User:    "root",
		Stream:  true,
		NoStdin: true,
		Command: []string{"sh", "-c", aptCmd},
	})
	if _, err := a.MSB.Run(ctx, msb.CommandRequest{
		Args:   aptArgs,
		Stdout: a.Stdout,
		Stderr: a.Stderr,
	}); err != nil {
		return fmt.Errorf("install apt packages: %w", err)
	}

	if err := a.provisionGuestUser(ctx, config.BaseSandbox); err != nil {
		return fmt.Errorf("provision guest user: %w", err)
	}

	baseToolsScript := fmt.Sprintf(`set -euo pipefail
su - %s -c 'export PATH="/home/agent/.local/bin:$PATH" && pipx install --force mdformat && pipx inject mdformat mdformat-gfm && rm -rf /home/agent/.cache/pip'
if [ -x /home/agent/.local/bin/mdformat ]; then
  ln -sf /home/agent/.local/bin/mdformat /usr/local/bin/mdformat
fi
su - %s -c 'export PATH="/home/agent/.local/bin:$PATH" && shellcheck --version >/dev/null && mdformat --version >/dev/null'
apt-get clean
rm -rf /var/lib/apt/lists/*`, config.GuestUser, config.GuestUser)
	toolsArgs := msb.BuildExecArgs(msb.ExecCmdOpts{
		Sandbox: config.BaseSandbox,
		User:    "root",
		Stream:  true,
		NoStdin: true,
		Command: []string{"bash", "-c", baseToolsScript},
	})
	if res, err := a.MSB.Run(ctx, msb.CommandRequest{
		Args:   toolsArgs,
		Stdout: a.Stdout,
		Stderr: a.Stderr,
	}); err != nil {
		return formatMSBError("install baseline tools (shellcheck and mdformat)", res, err)
	}

	if opts.Agent == "opencode" || opts.Agent == "both" {
		a.logf("Installing OpenCode (npm opencode-ai@%s)...", a.Env.OpenCodeVersion)
		ocScript := fmt.Sprintf(`set -euo pipefail
npm install -g --no-fund --no-audit "opencode-ai@$1"
su - %q -c "opencode --version"`, config.GuestUser)
		ocArgs := msb.BuildExecArgs(msb.ExecCmdOpts{
			Sandbox: config.BaseSandbox,
			User:    "root",
			Stream:  true,
			NoStdin: true,
			Command: []string{"bash", "-c", ocScript, "--", a.Env.OpenCodeVersion},
		})
		if _, err := a.MSB.Run(ctx, msb.CommandRequest{
			Args:   ocArgs,
			Stdout: a.Stdout,
			Stderr: a.Stderr,
		}); err != nil {
			return fmt.Errorf("install OpenCode: %w", err)
		}
	}

	if opts.Agent == "antigravity" || opts.Agent == "both" {
		a.logf("Installing Google Antigravity CLI (agy) from %s...", a.Env.AgyInstallerURL)
		innerCmd := fmt.Sprintf("set -o pipefail; curl --proto '=https' --proto-redir '=https' --tlsv1.2 -fsSL -- %s | bash", msb.ShellQuote(a.Env.AgyInstallerURL))
		agyScript := fmt.Sprintf(`set -euo pipefail
su - %s -c %s
if [ -x /home/agent/.local/bin/agy ]; then
  ln -sf /home/agent/.local/bin/agy /usr/local/bin/agy
fi
su - %s -c "agy --version"
%s`, config.GuestUser, msb.ShellQuote(innerCmd), config.GuestUser, msb.ProvisionAgyRetryHookScript())
		agyArgs := msb.BuildExecArgs(msb.ExecCmdOpts{
			Sandbox: config.BaseSandbox,
			User:    "root",
			Stream:  true,
			NoStdin: true,
			Command: []string{"bash", "-c", agyScript},
		})
		if _, err := a.MSB.Run(ctx, msb.CommandRequest{
			Args:   agyArgs,
			Stdout: a.Stdout,
			Stderr: a.Stderr,
		}); err != nil {
			return fmt.Errorf("install agy: %w", err)
		}
	}

	if len(opts.Categories) > 0 {
		if err := a.installCategories(ctx, config.BaseSandbox, opts.Categories); err != nil {
			return err
		}
	}

	prevState, err := config.LoadFile(a.Env.ConfigFile)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("load base config %s: %w", a.Env.ConfigFile, err)
	}
	snapListRes, err := a.MSB.Run(ctx, msb.CommandRequest{Args: []string{"snap", "ls"}})
	if err != nil {
		return formatMSBError("list snapshots", snapListRes, err)
	}
	count, snapSelector := config.NextSnapshotMember(
		prevState.SnapCount,
		msb.ParseSnapshotList(snapListRes.Stdout),
		config.SnapGroup,
	)
	member := fmt.Sprintf("v%d", count)

	a.logf("Stopping base and snapshotting %s...", snapSelector)
	if stopRes, err := a.MSB.Run(ctx, msb.CommandRequest{Args: []string{"stop", config.BaseSandbox}}); err != nil {
		return formatMSBError("stop base sandbox", stopRes, err)
	}
	if _, err := a.MSB.Run(ctx, msb.CommandRequest{
		Args:   []string{"snap", "create", member, "--sandbox", config.BaseSandbox, "--group", config.SnapGroup},
		Stdout: a.Stdout,
		Stderr: a.Stderr,
	}); err != nil {
		return fmt.Errorf("create snapshot: %w", err)
	}

	newState := config.State{
		Agent:      opts.Agent,
		Image:      image,
		Snapshot:   snapSelector,
		SnapCount:  count,
		CPUs:       a.Env.CPUs,
		Memory:     a.Env.Memory,
		RootDisk:   a.Env.RootDisk,
		Categories: msb.MergeCategoryNames("", opts.Categories),
	}
	if err := config.SaveFile(a.Env.ConfigFile, newState); err != nil {
		return fmt.Errorf("save config: %w", err)
	}

	succeeded = true
	a.logf("Base ready: %s (agent=%s, image=%s, guest_user=%s).", snapSelector, opts.Agent, image, config.GuestUser)
	a.logf("Next: agbox run [options] [agent] [paths...]")
	return nil
}

func (a *appRuntime) provisionGuestUser(ctx context.Context, sandbox string) error {
	_, err := a.runGuestRootScript(ctx, sandbox, "provision guest user in "+sandbox, "bash", msb.ProvisionGuestUserScript())
	return err
}

func (a *appRuntime) installCategories(ctx context.Context, sandbox string, cats []msb.Category) error {
	names := make([]string, len(cats))
	for i, c := range cats {
		names[i] = c.Name
	}
	a.logf("Installing categories (%s) in %s...", strings.Join(names, ", "), sandbox)
	script := msb.BuildCategoriesScript(cats)
	execArgs := msb.BuildExecArgs(msb.ExecCmdOpts{
		Sandbox: sandbox,
		User:    "root",
		Stream:  true,
		NoStdin: true,
		Command: []string{"bash", "-c", script},
	})
	if res, err := a.MSB.Run(ctx, msb.CommandRequest{
		Args:   execArgs,
		Stdout: a.Stdout,
		Stderr: a.Stderr,
	}); err != nil {
		return fmt.Errorf("install categories (exit %d): %w", res.ExitCode, err)
	}
	return nil
}

func (a *appRuntime) editBase(ctx context.Context, args []string) error {
	opts, err := parseEditBaseArgs(args)
	if err != nil {
		return err
	}
	if opts.ListOnly {
		if err := a.verifyUser(opts.AllowRoot); err != nil {
			return err
		}
		fmt.Fprint(a.Stdout, msb.FormatCategoriesTable())
		return nil
	}
	if err := a.requireSetup(opts.AllowRoot); err != nil {
		return err
	}
	st, err := a.requireBase(ctx)
	if err != nil {
		return err
	}

	lsRes, err := a.MSB.Run(ctx, msb.CommandRequest{Args: []string{"ls"}})
	if err != nil {
		return formatMSBError("list sandboxes", lsRes, err)
	}
	baseInfo, exists := msb.FindSandbox(msb.ParseSandboxList(lsRes.Stdout), config.BaseSandbox)
	if !exists {
		return fmt.Errorf("no base sandbox %q. Run 'agbox create-base <agent>' first", config.BaseSandbox)
	}

	if len(opts.Categories) == 0 && opts.Cmd == "" && !opts.Shell {
		if a.IsTTY == nil || !a.IsTTY() {
			return errors.New("not a TTY and no --add or --cmd given. Use: agbox edit-base --add core,go,rust,esphome or --cmd \"...\"")
		}
		fmt.Fprint(a.Stdout, msb.FormatCategoriesTable())
		if st.Categories != "" {
			fmt.Fprintf(a.Stdout, "Installed categories: %s\n", st.Categories)
		}
		fmt.Fprintln(a.Stdout, "\nEnter categories to install (numbers or names, 'all', or press Enter for a shell):")
		sc := bufio.NewScanner(a.Stdin)
		if !sc.Scan() {
			if sErr := sc.Err(); sErr != nil {
				return fmt.Errorf("read category selection: %w", sErr)
			}
			return errors.New("aborted")
		}
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.EqualFold(line, "s") || strings.EqualFold(line, "shell") {
			opts.Shell = true
		} else {
			cats, cErr := msb.ResolveCategories([]string{line})
			if cErr != nil {
				return cErr
			}
			opts.Categories = cats
		}
	}

	wasRunning := baseInfo.Running
	if err := a.ensureSparseRootDiskSize(ctx, wasRunning); err != nil {
		a.warnf("Could not expand base root disk: %v", err)
		if checkRes, cErr := a.MSB.Run(ctx, msb.CommandRequest{Args: []string{"ls"}}); cErr == nil {
			if refreshed, ok := msb.FindSandbox(msb.ParseSandboxList(checkRes.Stdout), config.BaseSandbox); ok {
				wasRunning = refreshed.Running
			}
		}
	}

	baseStarted := false
	if !wasRunning {
		a.logf("Starting base sandbox...")
		if startRes, err := a.MSB.Run(ctx, msb.CommandRequest{Args: []string{"start", config.BaseSandbox}}); err != nil {
			return formatMSBError("start base sandbox", startRes, err)
		}
		baseStarted = true
	}
	baseStopped := false
	defer func() {
		if (baseStarted || wasRunning) && !baseStopped {
			teardownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			stopRes, stopErr := a.MSB.Run(teardownCtx, msb.CommandRequest{Args: []string{"stop", config.BaseSandbox}})
			cancel()
			if stopErr != nil {
				a.warnf("Could not stop base sandbox %s: %v", config.BaseSandbox, formatMSBError("msb stop", stopRes, stopErr))
			}
		}
	}()

	mergedCategories := st.Categories
	if len(opts.Categories) > 0 {
		if err := a.installCategories(ctx, config.BaseSandbox, opts.Categories); err != nil {
			return err
		}
		mergedCategories = msb.MergeCategoryNames(st.Categories, opts.Categories)
	}

	if opts.Cmd != "" {
		a.logf("Running command in the base sandbox...")
		cmdArgs := msb.BuildExecArgs(msb.ExecCmdOpts{
			Sandbox: config.BaseSandbox,
			User:    "root",
			Stream:  true,
			NoStdin: true,
			Command: []string{"sh", "-c", opts.Cmd},
		})
		if res, err := a.MSB.Run(ctx, msb.CommandRequest{
			Args:   cmdArgs,
			Stdout: a.Stdout,
			Stderr: a.Stderr,
		}); err != nil {
			return fmt.Errorf("run base command (exit %d): %w", res.ExitCode, err)
		}
	}

	if opts.Shell {
		fmt.Fprintln(a.Stdout, "Interactive shell in the base sandbox.")
		fmt.Fprintf(a.Stdout, "Changes persist in %q and (after snapshotting) in future run microVMs.\n", config.BaseSandbox)
		shellArgs := msb.BuildExecArgs(msb.ExecCmdOpts{
			Sandbox: config.BaseSandbox,
			User:    "root",
			TTY:     true,
			Command: []string{"sh", "-c", "cd /workspace 2>/dev/null || cd /; bash; exit 0"},
		})
		if res, err := a.MSB.Run(ctx, msb.CommandRequest{
			Args:        shellArgs,
			Interactive: true,
		}); err != nil {
			return fmt.Errorf("interactive shell failed (exit %d): %w", res.ExitCode, err)
		}
	}

	if err := a.provisionGuestUser(ctx, config.BaseSandbox); err != nil {
		return fmt.Errorf("check guest user: %w", err)
	}

	a.logf("Stopping base...")
	if stopRes, err := a.MSB.Run(ctx, msb.CommandRequest{Args: []string{"stop", config.BaseSandbox}}); err != nil {
		return formatMSBError("stop base sandbox", stopRes, err)
	}
	baseStopped = true

	if opts.NoSnap {
		a.logf("agbox did not save a snapshot of %q (--no-snap).", config.BaseSandbox)
		return nil
	}

	snapListRes, err := a.MSB.Run(ctx, msb.CommandRequest{Args: []string{"snap", "ls"}})
	if err != nil {
		return formatMSBError("list snapshots", snapListRes, err)
	}
	count, snapSelector := config.NextSnapshotMember(
		st.SnapCount,
		msb.ParseSnapshotList(snapListRes.Stdout),
		config.SnapGroup,
	)
	member := fmt.Sprintf("v%d", count)
	a.logf("Snapshotting new base -> %s", snapSelector)
	if _, err := a.MSB.Run(ctx, msb.CommandRequest{
		Args:   []string{"snap", "create", member, "--sandbox", config.BaseSandbox, "--group", config.SnapGroup},
		Stdout: a.Stdout,
		Stderr: a.Stderr,
	}); err != nil {
		return fmt.Errorf("create snapshot (edits remain in %q): %w", config.BaseSandbox, err)
	}

	st.Categories = mergedCategories
	st.Snapshot = snapSelector
	st.SnapCount = count
	st.RootDisk = a.Env.RootDisk
	if err := config.SaveFile(a.Env.ConfigFile, st); err != nil {
		return fmt.Errorf("save config: %w", err)
	}
	a.logf("New runs use %s. Previous snapshots remain intact.", member)
	return nil
}

func (a *appRuntime) ensureSparseRootDiskSize(ctx context.Context, isRunning bool) (retErr error) {
	targetBytes, ok := parseSizeBytes(a.Env.RootDisk)
	if !ok || targetBytes <= 0 {
		return nil
	}
	if a.Env.MSBHome == "" {
		return nil
	}
	upperPath := filepath.Join(a.Env.MSBHome, "sandboxes", config.BaseSandbox, "upper.ext4")
	info, err := os.Lstat(upperPath)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("stat %s: %w", upperPath, err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return fmt.Errorf("refusing non-regular base disk image %s", upperPath)
	}
	if info.Size() >= targetBytes {
		return nil
	}

	findTool := a.FindHostTool
	if findTool == nil {
		findTool = findHostAdminTool
	}
	r2fs, ok := findTool("resize2fs")
	if !ok {
		return errors.New("resize2fs is not installed. Install e2fsprogs to expand the base root disk")
	}
	e2fsck, hasE2fsck := findTool("e2fsck")

	a.logf("Expanding sparse base disk (%s) to %s...", upperPath, a.Env.RootDisk)
	if isRunning {
		stopRes, stopErr := a.MSB.Run(ctx, msb.CommandRequest{Args: []string{"stop", config.BaseSandbox}})
		if stopErr != nil {
			return formatMSBError("stop base sandbox before disk resize", stopRes, stopErr)
		}
		defer func() {
			startCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
			startRes, startErr := a.MSB.Run(startCtx, msb.CommandRequest{Args: []string{"start", config.BaseSandbox}})
			cancel()
			if startErr != nil {
				retErr = errors.Join(retErr, formatMSBError("restart base sandbox after disk resize", startRes, startErr))
			}
		}()
	}

	truncateFn := a.TruncateFile
	if truncateFn == nil {
		truncateFn = os.Truncate
	}
	if err := truncateFn(upperPath, targetBytes); err != nil {
		return fmt.Errorf("truncate %s: %w", upperPath, err)
	}

	runCmd := a.RunHostCmd
	if runCmd == nil {
		runCmd = func(c context.Context, name string, args ...string) ([]byte, error) {
			return exec.CommandContext(c, name, args...).CombinedOutput()
		}
	}
	if hasE2fsck {
		if out, cErr := runCmd(ctx, e2fsck, "-fp", upperPath); cErr != nil {
			// e2fsck exit code 1 indicates corrected filesystem errors.
			var exitErr *exec.ExitError
			if !errors.As(cErr, &exitErr) || exitErr.ExitCode() != 1 {
				return fmt.Errorf("e2fsck %s: %w (%s)", upperPath, cErr, strings.TrimSpace(string(out)))
			}
		}
	}
	if out, rErr := runCmd(ctx, r2fs, upperPath); rErr != nil {
		return fmt.Errorf("resize2fs %s: %w (%s)", upperPath, rErr, strings.TrimSpace(string(out)))
	}
	return nil
}

func findHostAdminTool(name string) (string, bool) {
	for _, dir := range []string{"/sbin", "/usr/sbin", "/bin", "/usr/bin"} {
		candidate := filepath.Join(dir, name)
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			return candidate, true
		}
	}
	return "", false
}
