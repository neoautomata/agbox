package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"agbox/internal/config"
	"agbox/internal/mounttab"
	"agbox/internal/msb"
	"agbox/internal/service"
)

type serviceOpts struct {
	Action    string
	Name      string
	AllowRoot bool
	Force     bool
	Enable    bool
	Now       bool
	NoLinger  bool
	Follow    bool
	Lines     int
	EnvFile   string
	LingerCmd string
	RunArgs   []string
}

func parseServiceArgs(args []string) (serviceOpts, error) {
	opts := serviceOpts{
		Action: "list",
		Lines:  100,
	}

	var rest []string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if len(rest) == 0 {
			switch arg {
			case "-h", "--help":
				return serviceOpts{}, errHelp
			case "--allow-root":
				opts.AllowRoot = true
				continue
			}
		}
		rest = append(rest, arg)
	}
	if len(rest) == 0 {
		return opts, nil
	}

	action := rest[0]
	tail := rest[1:]
	switch action {
	case "list", "status":
		opts.Action = "list"
		for _, a := range tail {
			switch a {
			case "-h", "--help":
				return serviceOpts{}, errHelp
			case "--allow-root":
				opts.AllowRoot = true
			default:
				return serviceOpts{}, fmt.Errorf("unknown service list option: %s", a)
			}
		}
		return opts, nil

	case "add", "create":
		opts.Action = "add"
		return parseServiceAddArgs(opts, tail)

	case "enable":
		opts.Action = "enable"
		var pos []string
		for _, a := range tail {
			switch a {
			case "-h", "--help":
				return serviceOpts{}, errHelp
			case "--allow-root":
				opts.AllowRoot = true
			case "--now":
				opts.Now = true
			case "--no-linger":
				opts.NoLinger = true
			default:
				if strings.HasPrefix(a, "-") {
					return serviceOpts{}, fmt.Errorf("unknown service enable option: %s", a)
				}
				pos = append(pos, a)
			}
		}
		if len(pos) != 1 {
			return serviceOpts{}, errors.New("usage: agbox service enable [--now] [--no-linger] <name>")
		}
		validName, err := service.ValidateName(pos[0])
		if err != nil {
			return serviceOpts{}, err
		}
		opts.Name = validName
		return opts, nil

	case "disable":
		opts.Action = "disable"
		var pos []string
		for _, a := range tail {
			switch a {
			case "-h", "--help":
				return serviceOpts{}, errHelp
			case "--allow-root":
				opts.AllowRoot = true
			case "--now":
				opts.Now = true
			default:
				if strings.HasPrefix(a, "-") {
					return serviceOpts{}, fmt.Errorf("unknown service disable option: %s", a)
				}
				pos = append(pos, a)
			}
		}
		if len(pos) != 1 {
			return serviceOpts{}, errors.New("usage: agbox service disable [--now] <name>")
		}
		validName, err := service.ValidateName(pos[0])
		if err != nil {
			return serviceOpts{}, err
		}
		opts.Name = validName
		return opts, nil

	case "start", "stop", "restart":
		opts.Action = action
		var pos []string
		for _, a := range tail {
			switch a {
			case "-h", "--help":
				return serviceOpts{}, errHelp
			case "--allow-root":
				opts.AllowRoot = true
			default:
				if strings.HasPrefix(a, "-") {
					return serviceOpts{}, fmt.Errorf("unknown service %s option: %s", action, a)
				}
				pos = append(pos, a)
			}
		}
		if len(pos) != 1 {
			return serviceOpts{}, fmt.Errorf("usage: agbox service %s <name>", action)
		}
		validName, err := service.ValidateName(pos[0])
		if err != nil {
			return serviceOpts{}, err
		}
		opts.Name = validName
		return opts, nil

	case "logs":
		opts.Action = "logs"
		var pos []string
		for i := 0; i < len(tail); i++ {
			if val, ok, err := consumeFlagValue(tail, &i, "-n", "--lines"); ok {
				if err != nil {
					return serviceOpts{}, errors.New("--lines requires a positive integer")
				}
				n, nErr := strconv.Atoi(val)
				if nErr != nil || !isDigits(val) || n < 1 {
					return serviceOpts{}, errors.New("--lines must be a positive integer")
				}
				opts.Lines = n
				continue
			}
			a := tail[i]
			switch a {
			case "-h", "--help":
				return serviceOpts{}, errHelp
			case "--allow-root":
				opts.AllowRoot = true
			case "-f", "--follow":
				opts.Follow = true
			default:
				if strings.HasPrefix(a, "-") {
					return serviceOpts{}, fmt.Errorf("unknown service logs option: %s", a)
				}
				pos = append(pos, a)
			}
		}
		if len(pos) != 1 {
			return serviceOpts{}, errors.New("usage: agbox service logs [-f|--follow] [-n|--lines N] <name>")
		}
		validName, err := service.ValidateName(pos[0])
		if err != nil {
			return serviceOpts{}, err
		}
		opts.Name = validName
		return opts, nil

	case "rm", "remove", "delete":
		opts.Action = "rm"
		var pos []string
		for _, a := range tail {
			switch a {
			case "-h", "--help":
				return serviceOpts{}, errHelp
			case "--allow-root":
				opts.AllowRoot = true
			case "--force":
				opts.Force = true
			default:
				if strings.HasPrefix(a, "-") {
					return serviceOpts{}, fmt.Errorf("unknown service rm option: %s", a)
				}
				pos = append(pos, a)
			}
		}
		if len(pos) != 1 {
			return serviceOpts{}, errors.New("usage: agbox service rm [--force] <name>")
		}
		validName, err := service.ValidateName(pos[0])
		if err != nil {
			return serviceOpts{}, err
		}
		opts.Name = validName
		return opts, nil

	case "linger":
		opts.Action = "linger"
		var pos []string
		for _, a := range tail {
			switch a {
			case "-h", "--help":
				return serviceOpts{}, errHelp
			case "--allow-root":
				opts.AllowRoot = true
			default:
				if strings.HasPrefix(a, "-") {
					return serviceOpts{}, fmt.Errorf("unknown service linger option: %s", a)
				}
				pos = append(pos, a)
			}
		}
		if len(pos) == 0 {
			opts.LingerCmd = "status"
			return opts, nil
		}
		if len(pos) == 1 && (pos[0] == "status" || pos[0] == "enable") {
			opts.LingerCmd = pos[0]
			return opts, nil
		}
		return serviceOpts{}, errors.New("usage: agbox service linger [status|enable]")

	default:
		return serviceOpts{}, fmt.Errorf("unknown service action %q (expected: list, add, enable, disable, start, stop, restart, logs, rm, linger)", action)
	}
}

func parseServiceAddArgs(opts serviceOpts, args []string) (serviceOpts, error) {
	// Parse service-specific flags until the service <name> positional token.
	// Everything after <name> is passed to parseRunArgs as run options and share paths.
	nameIdx := -1
	for i := 0; i < len(args); i++ {
		if val, ok, err := consumeFlagValue(args, &i, "--env-file"); ok {
			if err != nil || strings.TrimSpace(val) == "" {
				return serviceOpts{}, errors.New("--env-file requires a file path")
			}
			opts.EnvFile = val
			continue
		}
		a := args[i]
		switch a {
		case "-h", "--help":
			return serviceOpts{}, errHelp
		case "--allow-root":
			opts.AllowRoot = true
		case "--force":
			opts.Force = true
		case "--enable":
			opts.Enable = true
		case "--now":
			opts.Now = true
			opts.Enable = true
		case "--no-linger":
			opts.NoLinger = true
		default:
			if strings.HasPrefix(a, "-") {
				return serviceOpts{}, fmt.Errorf("unknown service add option before <name>: %s", a)
			}
			nameIdx = i
		}
		if nameIdx >= 0 {
			break
		}
	}
	if nameIdx < 0 {
		return serviceOpts{}, errors.New("usage: agbox service add [service-opts] <name> [run-opts] [agent] [path[:opts]...]")
	}
	validName, err := service.ValidateName(args[nameIdx])
	if err != nil {
		return serviceOpts{}, err
	}
	opts.Name = validName

	// Also allow service-specific flags immediately after <name> before paths.
	rawRun := args[nameIdx+1:]
	filteredRun := make([]string, 0, len(rawRun))
	for i := 0; i < len(rawRun); i++ {
		if rawRun[i] == "--" {
			filteredRun = append(filteredRun, rawRun[i:]...)
			break
		}
		if val, ok, err := consumeFlagValue(rawRun, &i, "--env-file"); ok {
			if err != nil || strings.TrimSpace(val) == "" {
				return serviceOpts{}, errors.New("--env-file requires a file path")
			}
			opts.EnvFile = val
			continue
		}
		switch rawRun[i] {
		case "--force":
			opts.Force = true
		case "--enable":
			opts.Enable = true
		case "--now":
			opts.Now = true
			opts.Enable = true
		case "--no-linger":
			opts.NoLinger = true
		case "--allow-root":
			opts.AllowRoot = true
		default:
			filteredRun = append(filteredRun, rawRun[i])
		}
	}
	opts.RunArgs = filteredRun
	return opts, nil
}

func (a *appRuntime) serviceController() service.Controller {
	if a.ServiceCtl != nil {
		return a.ServiceCtl
	}
	return service.OSController{}
}

func (a *appRuntime) currentUsername() (string, error) {
	if a.CurrentUser != nil {
		return a.CurrentUser()
	}
	if a.Getenv != nil {
		if u := strings.TrimSpace(a.Getenv("USER")); u != "" {
			return u, nil
		}
	}
	return "", errors.New("cannot determine current username")
}

func (a *appRuntime) serviceUnitPath() (string, error) {
	xdg := ""
	if a.Getenv != nil {
		xdg = a.Getenv("XDG_CONFIG_HOME")
	}
	return service.TemplateUnitPath(a.Env.HomeReal, xdg)
}

func (a *appRuntime) buildServicePathEnv() string {
	var parts []string
	seen := make(map[string]bool)
	addDir := func(dir string) {
		if dir == "" {
			return
		}
		clean := filepath.Clean(dir)
		if !seen[clean] {
			seen[clean] = true
			parts = append(parts, clean)
		}
	}
	if a.ExePath != "" {
		addDir(filepath.Dir(a.ExePath))
	}
	if msbPath, err := exec.LookPath("msb"); err == nil {
		addDir(filepath.Dir(msbPath))
	}
	if a.Env.HomeReal != "" {
		addDir(filepath.Join(a.Env.HomeReal, ".local", "bin"))
	}
	if a.Getenv != nil {
		for _, elem := range filepath.SplitList(a.Getenv("PATH")) {
			addDir(elem)
		}
	}
	if len(parts) == 0 {
		return "/usr/local/bin:/usr/bin:/bin"
	}
	return strings.Join(parts, string(os.PathListSeparator))
}

func (a *appRuntime) ensureTemplateUnitInstalled(ctx context.Context) (string, error) {
	unitPath, err := a.serviceUnitPath()
	if err != nil {
		return "", err
	}
	content, err := service.RenderTemplateUnit(service.TemplateUnitOpts{
		ExePath:          a.ExePath,
		DataDir:          a.Env.DataDir,
		MSBHome:          a.Env.MSBHome,
		PathEnv:          a.buildServicePathEnv(),
		AllowOutsideHome: a.Env.AllowOutsideHome,
	})
	if err != nil {
		return "", err
	}
	if err := service.InstallTemplateUnit(unitPath, content); err != nil {
		return "", err
	}
	return unitPath, nil
}

func (a *appRuntime) serviceMode(ctx context.Context, args []string) error {
	opts, err := parseServiceArgs(args)
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
	case "list":
		return a.serviceList(ctx)
	case "add":
		return a.serviceAdd(ctx, opts)
	case "enable":
		return a.serviceEnable(ctx, opts)
	case "disable":
		return a.serviceDisable(ctx, opts)
	case "start":
		return a.serviceControl(ctx, opts.Name, "start")
	case "stop":
		return a.serviceControl(ctx, opts.Name, "stop")
	case "restart":
		return a.serviceControl(ctx, opts.Name, "restart")
	case "logs":
		return a.serviceLogs(ctx, opts)
	case "rm":
		return a.serviceRemove(ctx, opts)
	case "linger":
		return a.serviceLinger(ctx, opts.LingerCmd)
	default:
		return fmt.Errorf("unknown service action %q", opts.Action)
	}
}

func (a *appRuntime) serviceAdd(ctx context.Context, opts serviceOpts) error {
	if !opts.Force {
		if _, err := os.Lstat(service.SpecPath(a.Env.DataDir, opts.Name)); err == nil {
			return fmt.Errorf("service %q already exists (pass --force to overwrite)", opts.Name)
		}
	}

	for _, rawArg := range opts.RunArgs {
		if rawArg == "--" {
			break
		}
		if rawArg == "--name" || strings.HasPrefix(rawArg, "--name=") {
			return errors.New("do not pass --name to 'agbox service add'. The service name sets the sandbox name")
		}
	}

	runArgsWithName := append([]string{"--name", opts.Name}, opts.RunArgs...)
	runOpts, err := parseRunArgs(runArgsWithName, a.Env.MaskVCS, nil)
	if err != nil {
		return err
	}
	if runOpts.Detach {
		return errors.New("do not pass --detach (-d) to 'agbox service add'. systemd supervises the service in the foreground")
	}
	if runOpts.Probe {
		return errors.New("cannot use --probe with 'agbox service add'")
	}
	if runOpts.Continue || runOpts.ContinueSession != "" {
		return errors.New("cannot use --continue or --session with 'agbox service add'")
	}

	var mode config.RunMode
	switch {
	case runOpts.RemoteControl:
		mode = config.RunModeRemoteControl
	case runOpts.Serve:
		if runOpts.Port == 0 {
			return errors.New("--serve services require a fixed --port N so the web UI port stays stable across reboots")
		}
		mode = config.RunModeServe
	case runOpts.Cmd != "":
		mode = config.RunModeCmd
	default:
		return errors.New("services require a headless mode: pass --remote-control, --serve --port N, or --cmd \"shell\"")
	}

	// Validate agent compatibility against base config if present.
	if st, sErr := config.LoadFile(a.Env.ConfigFile); sErr == nil && st.Snapshot != "" {
		effAgent, aErr := selectEffectiveAgent(st.Agent, runOpts)
		if aErr != nil {
			return aErr
		}
		runOpts.Agent = effAgent
	}

	// Validate shares immediately so bad paths fail at add time.
	validated, err := a.resolveRunShareTargets(runOpts)
	if err != nil {
		return err
	}
	canonicalShares := make([]string, 0, len(validated))
	for _, sh := range validated {
		specStr := fmt.Sprintf("%s:%s,%s,as=%s", sh.HostPath, shareAccessMode(sh.ReadOnly), sh.VCSPolicy, sh.GuestName)
		canonicalShares = append(canonicalShares, specStr)
	}

	var envFilePath string
	var envVars map[string]string
	if opts.EnvFile != "" {
		var eErr error
		envFilePath, eErr = service.ValidateEnvFile(opts.EnvFile)
		if eErr != nil {
			return eErr
		}
		envVars, eErr = service.ParseEnvFile(envFilePath)
		if eErr != nil {
			return eErr
		}
	}

	if mode == config.RunModeServe {
		hasPass := envVars["OPENCODE_SERVER_PASSWORD"] != ""
		if !hasPass && a.Getenv != nil {
			hasPass = a.Getenv("OPENCODE_SERVER_PASSWORD") != ""
		}
		if !hasPass {
			a.warnf("Service %s uses --serve without OPENCODE_SERVER_PASSWORD in --env-file. Set it in a mode 0600 env file on multi-user systems.", opts.Name)
		}
	}

	spec := service.Spec{
		Name:         opts.Name,
		Agent:        runOpts.Agent,
		Mode:         mode,
		Port:         runOpts.Port,
		Cmd:          runOpts.Cmd,
		Persist:      runOpts.Persist,
		Profile:      runOpts.Profile,
		ShareHub:     runOpts.ShareHub,
		ReadOnly:     runOpts.ReadOnly,
		LockAccess:   runOpts.LockAccess,
		DefaultVCS:   runOpts.DefaultVCS,
		LockVCS:      runOpts.LockVCS,
		MaskMode:     runOpts.MaskMode,
		Shares:       canonicalShares,
		NoNet:        runOpts.NoNet,
		NetSpecs:     runOpts.NetSpecs,
		CPUs:         runOpts.CPUs,
		Memory:       runOpts.Memory,
		NoAuth:       runOpts.NoAuth,
		NoSkills:     runOpts.NoSkills,
		NoRules:      runOpts.NoRules,
		NoAgentCache: runOpts.NoAgentCache,
		EnvFile:      envFilePath,
	}

	if err := service.SaveSpec(a.Env.DataDir, spec); err != nil {
		return err
	}

	unitPath, err := a.ensureTemplateUnitInstalled(ctx)
	if err != nil {
		return err
	}
	ctl := a.serviceController()
	if rErr := ctl.DaemonReload(ctx); rErr != nil {
		a.warnf("Could not reload systemd user daemon (%v). Run 'systemctl --user daemon-reload' later.", rErr)
	}

	a.logf("Saved service %s (%s) and installed %s.", spec.Name, describeServiceMode(spec), unitPath)
	if opts.Enable {
		return a.serviceEnable(ctx, opts)
	}
	a.logf("Enable at boot with 'agbox service enable --now %s'.", spec.Name)
	return nil
}

func (a *appRuntime) serviceEnable(ctx context.Context, opts serviceOpts) error {
	if _, err := service.LoadSpec(a.Env.DataDir, opts.Name); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("service %q does not exist. Create it with 'agbox service add %s ...'", opts.Name, opts.Name)
		}
		return err
	}

	if _, err := a.ensureTemplateUnitInstalled(ctx); err != nil {
		return err
	}
	ctl := a.serviceController()
	if err := ctl.DaemonReload(ctx); err != nil {
		return err
	}

	if !opts.NoLinger {
		a.ensureLingerBestEffort(ctx, ctl)
	}

	unit := service.UnitName(opts.Name)
	if err := ctl.Enable(ctx, unit, opts.Now); err != nil {
		return err
	}
	if opts.Now {
		a.logf("Enabled and started %s.", unit)
	} else {
		a.logf("Enabled %s. Start it now with 'agbox service start %s'.", unit, opts.Name)
	}
	return nil
}

func (a *appRuntime) ensureLingerBestEffort(ctx context.Context, ctl service.Controller) {
	username, err := a.currentUsername()
	if err != nil {
		a.warnf("Could not determine username to check user linger: %v", err)
		return
	}
	enabled, err := ctl.LingerEnabled(ctx, username)
	if err == nil && enabled {
		return
	}
	if err := ctl.EnableLinger(ctx, username); err != nil {
		a.warnf("Could not enable user linger automatically (%v). Run 'sudo loginctl enable-linger %s' so services start at boot without login and persist after logout.", err, username)
		return
	}
	a.logf("Enabled systemd user linger for %s (starts at boot without login and persists after logout).", username)
}

func (a *appRuntime) serviceDisable(ctx context.Context, opts serviceOpts) error {
	unit := service.UnitName(opts.Name)
	if err := a.serviceController().Disable(ctx, unit, opts.Now); err != nil {
		return err
	}
	if opts.Now {
		a.logf("Disabled and stopped %s.", unit)
	} else {
		a.logf("Disabled %s.", unit)
	}
	return nil
}

func (a *appRuntime) serviceControl(ctx context.Context, name, verb string) error {
	if _, err := service.LoadSpec(a.Env.DataDir, name); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("service %q does not exist", name)
		}
		return err
	}
	ctl := a.serviceController()
	unit := service.UnitName(name)
	var err error
	switch verb {
	case "start":
		err = ctl.Start(ctx, unit)
	case "stop":
		err = ctl.Stop(ctx, unit)
	case "restart":
		err = ctl.Restart(ctx, unit)
	}
	if err != nil {
		return err
	}
	a.logf("Executed %s on %s.", verb, unit)
	return nil
}

func (a *appRuntime) serviceLogs(ctx context.Context, opts serviceOpts) error {
	if _, err := service.LoadSpec(a.Env.DataDir, opts.Name); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("service %q does not exist", opts.Name)
		}
		return err
	}
	return a.serviceController().Logs(ctx, service.UnitName(opts.Name), opts.Follow, opts.Lines, a.Stdout, a.Stderr)
}

func (a *appRuntime) serviceRemove(ctx context.Context, opts serviceOpts) error {
	if _, err := service.LoadSpec(a.Env.DataDir, opts.Name); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("service %q does not exist", opts.Name)
		}
		return err
	}

	ctl := a.serviceController()
	unit := service.UnitName(opts.Name)
	if err := ctl.Disable(ctx, unit, true); err != nil {
		if !opts.Force {
			a.warnf("Could not disable/stop %s (%v). Continuing to delete service spec.", unit, err)
		}
	}
	if err := service.DeleteSpec(a.Env.DataDir, opts.Name); err != nil {
		return err
	}

	remaining, err := service.ListSpecs(a.Env.DataDir)
	if err == nil && len(remaining) == 0 {
		if unitPath, pErr := a.serviceUnitPath(); pErr == nil {
			if rErr := service.RemoveTemplateUnit(unitPath); rErr != nil {
				a.warnf("Could not delete %s: %v", unitPath, rErr)
			} else {
				_ = ctl.DaemonReload(ctx)
			}
		}
	}
	a.logf("Removed service %s.", opts.Name)
	return nil
}

func (a *appRuntime) serviceLinger(ctx context.Context, cmd string) error {
	ctl := a.serviceController()
	username, err := a.currentUsername()
	if err != nil {
		return err
	}
	switch cmd {
	case "status":
		enabled, err := ctl.LingerEnabled(ctx, username)
		if err != nil {
			return err
		}
		if enabled {
			fmt.Fprintf(a.Stdout, "linger: enabled (%s)\n", username)
		} else {
			fmt.Fprintf(a.Stdout, "linger: disabled (%s)\n", username)
		}
		return nil
	case "enable":
		if err := ctl.EnableLinger(ctx, username); err != nil {
			return fmt.Errorf("%w. Run 'sudo loginctl enable-linger %s'", err, username)
		}
		a.logf("Enabled systemd user linger for %s.", username)
		return nil
	default:
		return errors.New("usage: agbox service linger [status|enable]")
	}
}

func (a *appRuntime) serviceList(ctx context.Context) error {
	ctl := a.serviceController()
	if username, err := a.currentUsername(); err == nil {
		if enabled, lErr := ctl.LingerEnabled(ctx, username); lErr == nil {
			if enabled {
				fmt.Fprintf(a.Stdout, "linger: enabled (%s)\n", username)
			} else {
				fmt.Fprintf(a.Stdout, "linger: disabled (%s)\n", username)
			}
		} else {
			fmt.Fprintf(a.Stdout, "linger: unknown (%v)\n", lErr)
		}
	}

	specs, err := service.ListSpecs(a.Env.DataDir)
	if err != nil {
		return err
	}
	if len(specs) == 0 {
		fmt.Fprintln(a.Stdout, "services: none")
		return nil
	}
	for _, spec := range specs {
		unit := service.UnitName(spec.Name)
		stateStr := "unknown"
		if st, sErr := ctl.Status(ctx, unit); sErr == nil {
			uf := defaultStr(st.UnitFile, "disabled")
			act := defaultStr(st.ActiveState, "inactive")
			if st.SubState != "" {
				stateStr = fmt.Sprintf("%s, %s (%s)", uf, act, st.SubState)
			} else {
				stateStr = fmt.Sprintf("%s, %s", uf, act)
			}
		}
		fmt.Fprintf(a.Stdout, "%s  [%s]  %s  (%s)\n", spec.Name, describeServiceLifecycle(spec), describeServiceMode(spec), stateStr)
	}
	return nil
}

func (a *appRuntime) printServiceStatus(ctx context.Context) {
	specs, err := service.ListSpecs(a.Env.DataDir)
	if err != nil || len(specs) == 0 {
		return
	}
	names := make([]string, 0, len(specs))
	for _, sp := range specs {
		names = append(names, sp.Name)
	}
	lingerStr := "unknown"
	if username, uErr := a.currentUsername(); uErr == nil {
		if enabled, lErr := a.serviceController().LingerEnabled(ctx, username); lErr == nil {
			if enabled {
				lingerStr = "enabled"
			} else {
				lingerStr = "disabled"
			}
		}
	}
	fmt.Fprintf(a.Stdout, "services: %s (linger: %s)\n", strings.Join(names, ", "), lingerStr)
}

func (a *appRuntime) cleanupManagedServices(ctx context.Context) {
	specs, err := service.ListSpecs(a.Env.DataDir)
	if err != nil {
		a.warnf("Could not list managed services during remove: %v", err)
	}
	ctl := a.serviceController()
	hadUnits := len(specs) > 0
	for _, spec := range specs {
		unit := service.UnitName(spec.Name)
		if dErr := ctl.Disable(ctx, unit, true); dErr != nil {
			a.warnf("Could not stop/disable %s during remove: %v", unit, dErr)
		}
	}
	if unitPath, pErr := a.serviceUnitPath(); pErr == nil {
		if _, stErr := os.Lstat(unitPath); stErr == nil {
			hadUnits = true
			if rErr := service.RemoveTemplateUnit(unitPath); rErr != nil {
				a.warnf("Could not delete %s during remove: %v", unitPath, rErr)
			}
		}
	}
	if hadUnits {
		_ = ctl.DaemonReload(ctx)
	}
}

func (a *appRuntime) serviceRun(ctx context.Context, args []string) error {
	var allowRoot bool
	var pos []string
	for _, arg := range args {
		switch arg {
		case "--allow-root":
			allowRoot = true
		default:
			if strings.HasPrefix(arg, "-") {
				return fmt.Errorf("unknown __service-run option: %s", arg)
			}
			pos = append(pos, arg)
		}
	}
	if len(pos) != 1 {
		return errors.New("usage: agbox __service-run <name>")
	}
	name, err := service.ValidateName(pos[0])
	if err != nil {
		return err
	}
	if err := a.requireSetup(allowRoot); err != nil {
		return err
	}
	if err := config.EnsurePrivateDir(a.Env.DataDir); err != nil {
		return fmt.Errorf("prepare data dir: %w", err)
	}

	spec, err := service.LoadSpec(a.Env.DataDir, name)
	if err != nil {
		return fmt.Errorf("load service %q: %w", name, err)
	}

	// Overlay optional mode 0600 env file into a.Getenv without mutating global process environment.
	if spec.EnvFile != "" {
		envVals, eErr := service.ParseEnvFile(spec.EnvFile)
		if eErr != nil {
			return fmt.Errorf("load env file for service %q: %w", name, eErr)
		}
		baseGetenv := a.Getenv
		a.Getenv = func(k string) string {
			if v, ok := envVals[k]; ok {
				return v
			}
			if baseGetenv != nil {
				return baseGetenv(k)
			}
			return ""
		}
		defer func() {
			a.Getenv = baseGetenv
		}()
	}

	if err := a.recoverStaleServiceSandbox(ctx, spec); err != nil {
		return err
	}

	opts := runOptsFromSpec(spec, allowRoot)
	return a.runWithOpts(ctx, opts)
}

// recoverStaleServiceSandbox reconciles leftover sandbox state after an unclean host reboot.
func (a *appRuntime) recoverStaleServiceSandbox(ctx context.Context, spec service.Spec) error {
	sandbox := formatRunSandboxName(spec.Name, 0)
	dirID, err := runDirIDFromSandbox(sandbox)
	if err != nil {
		return err
	}
	lsRes, err := a.MSB.Run(ctx, msb.CommandRequest{Args: []string{"ls"}})
	if err != nil {
		return formatMSBError("list sandboxes", lsRes, err)
	}
	sb, exists := msb.FindSandbox(msb.ParseSandboxList(lsRes.Stdout), sandbox)
	if !exists {
		return nil
	}
	if sb.Running {
		return fmt.Errorf("sandbox %q is already running", sandbox)
	}

	runDir := filepath.Join(a.Env.DataDir, "run", dirID)
	suspendedPath := filepath.Join(runDir, "suspended")
	if spec.Persist {
		if hasMarker(suspendedPath) {
			return nil
		}
		meta, mErr := config.LoadRunMeta(filepath.Join(runDir, "run.meta"))
		if mErr != nil {
			return fmt.Errorf("stopped persistent sandbox %q has no recoverable metadata: %w", sandbox, mErr)
		}
		if uErr := mounttab.UnmountFilterDir(runDir, a.MountCtl); uErr != nil {
			return fmt.Errorf("unmount stale shares for %q: %w", sandbox, uErr)
		}
		meta.Continue = false
		meta.ContinueSession = ""
		if sErr := config.SaveRunMeta(suspendedPath, meta); sErr != nil {
			return fmt.Errorf("recover suspended metadata for %q: %w", sandbox, sErr)
		}
		_ = os.Remove(filepath.Join(runDir, "detached"))
		a.logf("Recovered stopped persistent sandbox %s after prior shutdown.", sandbox)
		return nil
	}

	// Non-persistent service: clean up stale stopped sandbox from a prior crash or reboot.
	if rmRes, rmErr := a.destroySandbox(ctx, sandbox, false, true); rmErr != nil {
		return formatMSBError("delete stale sandbox "+sandbox, rmRes, rmErr)
	}
	if _, stErr := os.Lstat(runDir); stErr == nil {
		if tdErr := mounttab.TeardownFilterDir(runDir, a.MountCtl); tdErr != nil {
			return tdErr
		}
	}
	a.logf("Cleaned stale stopped sandbox %s before fresh start.", sandbox)
	return nil
}

func (a *appRuntime) servicePollInterval() time.Duration {
	if a.ServicePollInterval > 0 {
		return a.ServicePollInterval
	}
	return 15 * time.Second
}

func (a *appRuntime) serviceFailThreshold() int {
	if a.ServiceFailThreshold > 0 {
		return a.ServiceFailThreshold
	}
	return 3
}

func (a *appRuntime) notifySystemd(state string) {
	if a.NotifySystemd != nil {
		a.NotifySystemd(state)
		return
	}
	if a.Getenv != nil {
		_ = service.Notify(a.Getenv("NOTIFY_SOCKET"), state)
	}
}

func isRemoteControlStatusHealthy(stdout, stderr string, err error) bool {
	if err != nil {
		return false
	}
	combined := strings.ToLower(stdout + "\n" + stderr)
	for _, bad := range []string{"not running", "stopped", "inactive", "disconnected", "offline"} {
		if strings.Contains(combined, bad) {
			return false
		}
	}
	return true
}

func (a *appRuntime) superviseRemoteControl(ctx context.Context, sandbox, workDir string, envFlags []string, initialHealthy bool) error {
	threshold := a.serviceFailThreshold()
	statusInner := fmt.Sprintf("%s cd %s && agy remote-control status", msb.KeyLoaderPrefix, msb.ShellQuote(workDir))
	statusArgs := msb.BuildExecArgs(msb.ExecCmdOpts{
		Sandbox: sandbox,
		User:    config.GuestUser,
		Stream:  true,
		NoStdin: true,
		Env:     envFlags,
		Command: []string{"sh", "-c", statusInner},
	})

	readySent := false
	if initialHealthy {
		a.notifySystemd("READY=1")
		a.notifySystemd("WATCHDOG=1")
		readySent = true
	}

	failures := 0
	ticker := time.NewTicker(a.servicePollInterval())
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			a.notifySystemd("STOPPING=1")
			return nil
		case <-ticker.C:
			var checkErr error
			if pingRes, pErr := a.MSB.Run(ctx, msb.CommandRequest{Args: []string{"ping", sandbox}}); pErr != nil {
				if ctx.Err() != nil {
					a.notifySystemd("STOPPING=1")
					return nil
				}
				checkErr = formatMSBError("sandbox ping failed for "+sandbox, pingRes, pErr)
			} else {
				stRes, stErr := a.MSB.Run(ctx, msb.CommandRequest{Args: statusArgs})
				if ctx.Err() != nil {
					a.notifySystemd("STOPPING=1")
					return nil
				}
				if !isRemoteControlStatusHealthy(stRes.Stdout, stRes.Stderr, stErr) {
					if stErr != nil {
						checkErr = formatMSBError("agy remote-control status failed for "+sandbox, stRes, stErr)
					} else {
						checkErr = fmt.Errorf("agy remote-control is unhealthy in %s (%s)", sandbox, strings.TrimSpace(stRes.Stdout+" "+stRes.Stderr))
					}
				}
			}

			if checkErr == nil {
				failures = 0
				if !readySent {
					a.notifySystemd("READY=1")
					readySent = true
				}
				a.notifySystemd("WATCHDOG=1")
				continue
			}

			failures++
			a.warnf("Health check failed for %s (%d/%d): %v", sandbox, failures, threshold, checkErr)
			if failures >= threshold {
				a.notifySystemd("STOPPING=1")
				return fmt.Errorf("health check failed %d consecutive times for %s: %w", failures, sandbox, checkErr)
			}
		}
	}
}

func (a *appRuntime) superviseServe(ctx context.Context, sandbox string, port int, execArgs []string) error {
	serveCtx, cancelServe := context.WithCancel(ctx)
	defer cancelServe()

	probeFn := a.ProbeServeUI
	if probeFn == nil {
		probeFn = a.defaultProbeServeUI
	}
	waitFn := a.WaitServeUI
	if waitFn == nil {
		waitFn = a.defaultWaitServeUI
	}
	threshold := a.serviceFailThreshold()

	var healthMu sync.Mutex
	var healthErr error
	setHealthErr := func(err error) {
		healthMu.Lock()
		if healthErr == nil {
			healthErr = err
		}
		healthMu.Unlock()
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		if !waitFn(serveCtx, port, sandbox) {
			if serveCtx.Err() == nil {
				setHealthErr(fmt.Errorf("opencode serve did not become ready on http://127.0.0.1:%d", port))
				cancelServe()
			}
			return
		}
		a.notifySystemd("READY=1")
		a.notifySystemd("WATCHDOG=1")

		failures := 0
		ticker := time.NewTicker(a.servicePollInterval())
		defer ticker.Stop()
		for {
			select {
			case <-serveCtx.Done():
				return
			case <-ticker.C:
				if probeFn(serveCtx, port) {
					failures = 0
					a.notifySystemd("WATCHDOG=1")
					continue
				}
				if serveCtx.Err() != nil {
					return
				}
				failures++
				a.warnf("OpenCode health check failed for %s on http://127.0.0.1:%d (%d/%d).", sandbox, port, failures, threshold)
				if failures >= threshold {
					setHealthErr(fmt.Errorf("opencode serve health check failed %d consecutive times on http://127.0.0.1:%d", failures, port))
					cancelServe()
					return
				}
			}
		}
	}()

	res, err := a.MSB.Run(serveCtx, msb.CommandRequest{
		Args:   execArgs,
		Stdout: a.Stdout,
		Stderr: a.Stderr,
	})
	cancelServe()
	wg.Wait()
	a.notifySystemd("STOPPING=1")

	if ctx.Err() != nil {
		return nil
	}
	healthMu.Lock()
	hErr := healthErr
	healthMu.Unlock()
	if hErr != nil {
		return hErr
	}
	return wrapPassthroughExit(res, err)
}

func (a *appRuntime) superviseCmd(ctx context.Context, sandbox string, execArgs []string) error {
	cmdCtx, cancelCmd := context.WithCancel(ctx)
	defer cancelCmd()

	a.notifySystemd("READY=1")
	a.notifySystemd("WATCHDOG=1")

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		ticker := time.NewTicker(a.servicePollInterval())
		defer ticker.Stop()
		for {
			select {
			case <-cmdCtx.Done():
				return
			case <-ticker.C:
				if _, pErr := a.MSB.Run(cmdCtx, msb.CommandRequest{Args: []string{"ping", sandbox}}); pErr == nil {
					a.notifySystemd("WATCHDOG=1")
				}
			}
		}
	}()

	res, err := a.MSB.Run(cmdCtx, msb.CommandRequest{
		Args:   execArgs,
		Stdout: a.Stdout,
		Stderr: a.Stderr,
	})
	cancelCmd()
	wg.Wait()
	a.notifySystemd("STOPPING=1")

	if ctx.Err() != nil {
		return nil
	}
	return wrapPassthroughExit(res, err)
}

func runOptsFromSpec(spec service.Spec, allowRoot bool) runOpts {
	maskMode := spec.MaskMode
	if maskMode == "" {
		maskMode = config.MaskStrict
	}
	defaultVCS := spec.DefaultVCS
	if defaultVCS == "" {
		defaultVCS = config.VCSMask
	}
	return runOpts{
		Name:          spec.Name,
		Agent:         spec.Agent,
		ShareSpecs:    spec.Shares,
		ShareHub:      spec.ShareHub,
		AllowRoot:     allowRoot,
		ReadOnly:      spec.ReadOnly,
		LockAccess:    spec.LockAccess,
		DefaultVCS:    defaultVCS,
		LockVCS:       spec.LockVCS,
		Serve:         spec.Mode == config.RunModeServe,
		Port:          spec.Port,
		RemoteControl: spec.Mode == config.RunModeRemoteControl,
		Cmd:           spec.Cmd,
		NoNet:         spec.NoNet,
		NetSpecs:      spec.NetSpecs,
		CPUs:          spec.CPUs,
		Memory:        spec.Memory,
		MaskMode:      maskMode,
		Persist:       spec.Persist,
		Profile:       spec.Profile,
		NoAuth:        spec.NoAuth,
		NoSkills:      spec.NoSkills,
		NoRules:       spec.NoRules,
		NoAgentCache:  spec.NoAgentCache,
		Supervised:    true,
	}
}

func describeServiceMode(spec service.Spec) string {
	switch spec.Mode {
	case config.RunModeServe:
		return fmt.Sprintf("serve 127.0.0.1:%d", spec.Port)
	case config.RunModeRemoteControl:
		return "remote-control"
	case config.RunModeCmd:
		return "cmd"
	default:
		return string(spec.Mode)
	}
}

func describeServiceLifecycle(spec service.Spec) string {
	if spec.Persist {
		return "persist"
	}
	if spec.Profile != "" {
		return "profile:" + spec.Profile
	}
	return "ephemeral"
}
