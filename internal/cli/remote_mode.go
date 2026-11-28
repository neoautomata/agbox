package cli

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"agbox/internal/config"
	"agbox/internal/remotebridge"
	"agbox/internal/remotebroker"
	"agbox/internal/remotedaemon"
	"agbox/internal/remotepolicy"
	"agbox/internal/remoteproto"
)

func remoteUsageText() string {
	return `Usage: agbox remote [--allow-root] <serve|connect|policy> [options...]

Manage remote command execution between an agbox sandbox and a remote machine.

Subcommands:
  agbox remote serve [options]
      Run the remote daemon on a target machine (needs no KVM, msb, or FUSE).
      Options:
        --listen <IP[:PORT]>       Bind a specific IP or IP:PORT (default: all interfaces, ephemeral port)
        --port <PORT>              Bind a specific port (conflicts with --listen IP:PORT)
        --allow-from <CIDR,...>    Allow only matching source IPs or CIDRs (repeatable)
        --allow-cwd <DIR>          Restrict remote working directories to DIR (repeatable)
        --path <DIR:...>           Override remote PATH before sanitization (conflicts with --strict-path)
        --strict-path              Restrict remote PATH to trusted system directories only
        --pass-env <VAR>           Forward host environment variable VAR to remote commands (repeatable)
        --max-output <BYTES>       Cap combined stdout and stderr (default: 256K, max: 2M)
        --max-stdin <BYTES>        Cap stdin payload size (default: 256K, max: 256K)
        --exec-timeout <DUR>       Cap remote command duration (default: 300s)
        --idle-timeout <DUR>       Exit after idle duration (default: 4h)
        --reconnect-grace <DUR>    Hold pinned peer identity after TCP drop (default: 5m)
        --allow-new-privs          Disable PR_SET_NO_NEW_PRIVS on remote child processes
        --allow-root               Allow running as the root user

  agbox remote connect [options] <HOST:PORT>
      Pair with a remote daemon over TLS 1.3 mTLS and mediate commands from a sandbox.
      Options:
        --sandbox <NAME>           Attach to sandbox NAME (waits and re-attaches automatically)
        --policy <PATH>            Load and hot-reload JSON policy file (default: $DATA_DIR/remote-policy.json)
        --no-policy                Ignore $DATA_DIR/remote-policy.json and ask on every command
        --output-review            Enable Phase 2 output review for every executed command
        --redact-pattern <REGEX>   Add an extra regex for secret redaction (repeatable)
        --max-output <BYTES>       Cap combined stdout and stderr (default: 256K, max: 2M)
        --ask-timeout <DUR>        Phase 1 and Phase 2 approval timeout (default: 120s)
        --audit-log <PATH>         Write redacted JSONL audit log (default: $DATA_DIR/remote-audit.jsonl)
        --allow-root               Allow running as the root user

  agbox remote policy <init|check|test> [options]
      Create, check, or dry-run a remote policy file (default: $DATA_DIR/remote-policy.json).
        init [-o|--output <PATH>] [-f|--force]
        check [--policy <PATH> | <PATH>]
        test [--policy <PATH>] [--cwd <DIR>] [--stdin] [--] <EXECUTABLE> [ARG...]
`
}

func (a *appRuntime) remoteMode(ctx context.Context, args []string) error {
	var allowRoot bool
	var rest []string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if len(rest) == 0 {
			switch arg {
			case "-h", "--help":
				return errHelp
			case "--allow-root":
				allowRoot = true
				continue
			}
		}
		rest = append(rest, arg)
	}
	if len(rest) == 0 {
		return errHelp
	}

	action := rest[0]
	tail := rest[1:]
	if allowRoot {
		tail = append([]string{"--allow-root"}, tail...)
	}

	switch action {
	case "serve":
		return a.remoteServe(ctx, tail)
	case "connect":
		return a.remoteConnect(ctx, tail)
	case "policy":
		return a.remotePolicy(tail)
	default:
		return fmt.Errorf("unknown remote subcommand %q (expected serve, connect, or policy)", action)
	}
}

type remoteServeOpts struct {
	ListenAddr     string
	AllowFrom      []netip.Prefix
	AllowCWD       []string
	PathOverride   string
	StrictPath     bool
	PassEnv        []string
	MaxOutputBytes int
	MaxStdinBytes  int
	ExecTimeout    time.Duration
	IdleTimeout    time.Duration
	ReconnectGrace time.Duration
	AllowNewPrivs  bool
	AllowRoot      bool
}

func parseRemoteServeArgs(args []string) (remoteServeOpts, error) {
	var opts remoteServeOpts
	var rawListen string
	var port int
	hasPort := false

	for i := 0; i < len(args); i++ {
		if val, ok, err := consumeFlagValue(args, &i, "--listen"); ok {
			if err != nil || strings.TrimSpace(val) == "" {
				return remoteServeOpts{}, errors.New("--listen requires an IP or IP:PORT")
			}
			rawListen = strings.TrimSpace(val)
			continue
		}
		if val, ok, err := consumeFlagValue(args, &i, "--port"); ok {
			if err != nil || !isDigits(val) {
				return remoteServeOpts{}, errors.New("--port requires an integer between 1 and 65535")
			}
			p, pErr := strconv.Atoi(val)
			if pErr != nil || p < 1 || p > 65535 {
				return remoteServeOpts{}, errors.New("--port must be an integer between 1 and 65535")
			}
			port = p
			hasPort = true
			continue
		}
		if val, ok, err := consumeFlagValue(args, &i, "--allow-from"); ok {
			if err != nil || strings.TrimSpace(val) == "" {
				return remoteServeOpts{}, errors.New("--allow-from requires an IP or CIDR")
			}
			for _, tok := range strings.Split(val, ",") {
				t := strings.TrimSpace(tok)
				if t == "" {
					return remoteServeOpts{}, fmt.Errorf("invalid --allow-from %q: empty IP or CIDR entry", val)
				}
				pfx, pErr := parseIPOrCIDR(t)
				if pErr != nil {
					return remoteServeOpts{}, pErr
				}
				opts.AllowFrom = append(opts.AllowFrom, pfx)
			}
			continue
		}
		if val, ok, err := consumeFlagValue(args, &i, "--allow-cwd"); ok {
			if err != nil || strings.TrimSpace(val) == "" {
				return remoteServeOpts{}, errors.New("--allow-cwd requires an absolute directory path")
			}
			opts.AllowCWD = append(opts.AllowCWD, strings.TrimSpace(val))
			continue
		}
		if val, ok, err := consumeFlagValue(args, &i, "--path"); ok {
			if err != nil || strings.TrimSpace(val) == "" {
				return remoteServeOpts{}, errors.New("--path requires a colon-separated PATH list")
			}
			opts.PathOverride = strings.TrimSpace(val)
			continue
		}
		if val, ok, err := consumeFlagValue(args, &i, "--pass-env"); ok {
			if err != nil || strings.TrimSpace(val) == "" {
				return remoteServeOpts{}, errors.New("--pass-env requires an environment variable name")
			}
			if vErr := remotedaemon.ValidatePassEnv(val); vErr != nil {
				return remoteServeOpts{}, vErr
			}
			opts.PassEnv = append(opts.PassEnv, val)
			continue
		}
		if val, ok, err := consumeFlagValue(args, &i, "--max-output"); ok {
			if err != nil {
				return remoteServeOpts{}, errors.New("--max-output requires a byte size")
			}
			sz, sErr := remoteproto.ParseByteSize(val)
			if sErr != nil {
				return remoteServeOpts{}, sErr
			}
			if sz > remoteproto.MaxOutputBytes {
				return remoteServeOpts{}, fmt.Errorf("--max-output %d exceeds hard limit %d bytes", sz, remoteproto.MaxOutputBytes)
			}
			opts.MaxOutputBytes = sz
			continue
		}
		if val, ok, err := consumeFlagValue(args, &i, "--max-stdin"); ok {
			if err != nil {
				return remoteServeOpts{}, errors.New("--max-stdin requires a byte size")
			}
			sz, sErr := remoteproto.ParseByteSize(val)
			if sErr != nil {
				return remoteServeOpts{}, sErr
			}
			if sz > remoteproto.MaxStdinBytes {
				return remoteServeOpts{}, fmt.Errorf("--max-stdin %d exceeds hard limit %d bytes", sz, remoteproto.MaxStdinBytes)
			}
			opts.MaxStdinBytes = sz
			continue
		}
		if val, ok, err := consumeFlagValue(args, &i, "--exec-timeout"); ok {
			if err != nil {
				return remoteServeOpts{}, errors.New("--exec-timeout requires a duration")
			}
			d, dErr := remoteproto.ParseDurationOrSeconds(val)
			if dErr != nil {
				return remoteServeOpts{}, dErr
			}
			opts.ExecTimeout = d
			continue
		}
		if val, ok, err := consumeFlagValue(args, &i, "--idle-timeout"); ok {
			if err != nil {
				return remoteServeOpts{}, errors.New("--idle-timeout requires a duration")
			}
			d, dErr := remoteproto.ParseDurationOrSeconds(val)
			if dErr != nil {
				return remoteServeOpts{}, dErr
			}
			opts.IdleTimeout = d
			continue
		}
		if val, ok, err := consumeFlagValue(args, &i, "--reconnect-grace"); ok {
			if err != nil {
				return remoteServeOpts{}, errors.New("--reconnect-grace requires a duration")
			}
			d, dErr := remoteproto.ParseDurationOrSeconds(val)
			if dErr != nil {
				return remoteServeOpts{}, dErr
			}
			opts.ReconnectGrace = d
			continue
		}

		switch args[i] {
		case "-h", "--help":
			return remoteServeOpts{}, errHelp
		case "--strict-path":
			opts.StrictPath = true
		case "--allow-new-privs":
			opts.AllowNewPrivs = true
		case "--allow-root":
			opts.AllowRoot = true
		default:
			return remoteServeOpts{}, fmt.Errorf("unknown remote serve option: %s (run 'agbox remote --help')", args[i])
		}
	}

	if opts.StrictPath && opts.PathOverride != "" {
		return remoteServeOpts{}, errors.New("conflicting options: cannot combine --strict-path and --path")
	}

	listenAddr, err := resolveListenAddr(rawListen, port, hasPort)
	if err != nil {
		return remoteServeOpts{}, err
	}
	opts.ListenAddr = listenAddr
	return opts, nil
}

func resolveListenAddr(rawListen string, port int, hasPort bool) (string, error) {
	if rawListen == "" {
		if hasPort {
			return fmt.Sprintf(":%d", port), nil
		}
		return ":0", nil
	}
	// Check if rawListen is a bare IP address (no port).
	if addr, err := netip.ParseAddr(strings.Trim(rawListen, "[]")); err == nil && !strings.Contains(rawListen, "]:") {
		p := 0
		if hasPort {
			p = port
		}
		return net.JoinHostPort(addr.String(), strconv.Itoa(p)), nil
	}
	host, portStr, err := net.SplitHostPort(rawListen)
	if err != nil {
		return "", fmt.Errorf("invalid --listen %q: expected IP or IP:PORT", rawListen)
	}
	if hasPort {
		return "", errors.New("conflicting options: cannot combine --listen IP:PORT with --port")
	}
	if portStr == "" {
		portStr = "0"
	}
	if !isDigits(portStr) {
		return "", fmt.Errorf("invalid --listen port %q", portStr)
	}
	p, pErr := strconv.Atoi(portStr)
	if pErr != nil || p < 0 || p > 65535 {
		return "", fmt.Errorf("invalid --listen port %q", portStr)
	}
	if host != "" {
		if _, aErr := netip.ParseAddr(host); aErr != nil {
			return "", fmt.Errorf("invalid --listen IP %q", host)
		}
	}
	return net.JoinHostPort(host, strconv.Itoa(p)), nil
}

func parseIPOrCIDR(raw string) (netip.Prefix, error) {
	if strings.Contains(raw, "/") {
		pfx, err := netip.ParsePrefix(raw)
		if err != nil {
			return netip.Prefix{}, fmt.Errorf("invalid --allow-from CIDR %q: %w", raw, err)
		}
		return pfx, nil
	}
	addr, err := netip.ParseAddr(raw)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("invalid --allow-from IP %q: %w", raw, err)
	}
	addr = addr.Unmap()
	return netip.PrefixFrom(addr, addr.BitLen()), nil
}

func (a *appRuntime) remoteServe(ctx context.Context, args []string) error {
	opts, err := parseRemoteServeArgs(args)
	if err != nil {
		return err
	}
	if err := a.verifyUser(opts.AllowRoot); err != nil {
		return err
	}
	if a.IsTTY == nil || !a.IsTTY() {
		return errors.New("interactive TTY required for SAS pairing. Pass 'ssh -t' when using SSH")
	}

	d, err := remotedaemon.New(remotedaemon.Config{
		ListenAddr:     opts.ListenAddr,
		AllowFrom:      opts.AllowFrom,
		AllowCWD:       opts.AllowCWD,
		PathOverride:   opts.PathOverride,
		StrictPath:     opts.StrictPath,
		PassEnv:        opts.PassEnv,
		MaxOutputBytes: opts.MaxOutputBytes,
		MaxStdinBytes:  opts.MaxStdinBytes,
		ExecTimeout:    opts.ExecTimeout,
		IdleTimeout:    opts.IdleTimeout,
		ReconnectGrace: opts.ReconnectGrace,
		AllowNewPrivs:  opts.AllowNewPrivs,
		AllowRoot:      opts.AllowRoot,
		Stdin:          a.Stdin,
		Stdout:         a.Stdout,
		Stderr:         a.Stderr,
		IsTTY:          a.IsTTY,
	})
	if err != nil {
		return err
	}
	if _, err := d.Listen(); err != nil {
		return err
	}
	d.PrintBanner()

	serveCtx, stopSig := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	defer stopSig()
	return d.Serve(serveCtx)
}

type remoteConnectOpts struct {
	RemoteAddr          string
	SandboxName         string
	PolicyPath          string
	NoPolicy            bool
	OutputReview        bool
	ExtraRedactPatterns []string
	MaxOutputBytes      int
	AskTimeout          time.Duration
	AuditLogPath        string
	AllowRoot           bool
}

func parseRemoteConnectArgs(args []string) (remoteConnectOpts, error) {
	var opts remoteConnectOpts
	var pos []string
	for i := 0; i < len(args); i++ {
		if val, ok, err := consumeFlagValue(args, &i, "--sandbox"); ok {
			if err != nil || strings.TrimSpace(val) == "" {
				return remoteConnectOpts{}, errors.New("--sandbox requires a sandbox name")
			}
			normalized := strings.TrimSpace(val)
			if !strings.HasPrefix(normalized, sandboxPrefix) {
				normalized = sandboxPrefix + normalized
			}
			validSB, vErr := validateTargetRunSandbox(normalized, "attach to")
			if vErr != nil {
				return remoteConnectOpts{}, vErr
			}
			opts.SandboxName = validSB
			continue
		}
		if val, ok, err := consumeFlagValue(args, &i, "--policy"); ok {
			if err != nil || strings.TrimSpace(val) == "" {
				return remoteConnectOpts{}, errors.New("--policy requires a JSON file path")
			}
			opts.PolicyPath = strings.TrimSpace(val)
			continue
		}
		if val, ok, err := consumeFlagValue(args, &i, "--redact-pattern"); ok {
			if err != nil || val == "" {
				return remoteConnectOpts{}, errors.New("--redact-pattern requires a regex pattern")
			}
			opts.ExtraRedactPatterns = append(opts.ExtraRedactPatterns, val)
			continue
		}
		if val, ok, err := consumeFlagValue(args, &i, "--max-output"); ok {
			if err != nil {
				return remoteConnectOpts{}, errors.New("--max-output requires a byte size")
			}
			sz, sErr := remoteproto.ParseByteSize(val)
			if sErr != nil {
				return remoteConnectOpts{}, sErr
			}
			if sz > remoteproto.MaxOutputBytes {
				return remoteConnectOpts{}, fmt.Errorf("--max-output %d exceeds hard limit %d bytes", sz, remoteproto.MaxOutputBytes)
			}
			opts.MaxOutputBytes = sz
			continue
		}
		if val, ok, err := consumeFlagValue(args, &i, "--ask-timeout"); ok {
			if err != nil {
				return remoteConnectOpts{}, errors.New("--ask-timeout requires a duration")
			}
			d, dErr := remoteproto.ParseDurationOrSeconds(val)
			if dErr != nil {
				return remoteConnectOpts{}, dErr
			}
			opts.AskTimeout = d
			continue
		}
		if val, ok, err := consumeFlagValue(args, &i, "--audit-log"); ok {
			if err != nil || strings.TrimSpace(val) == "" {
				return remoteConnectOpts{}, errors.New("--audit-log requires a file path")
			}
			opts.AuditLogPath = strings.TrimSpace(val)
			continue
		}

		switch args[i] {
		case "-h", "--help":
			return remoteConnectOpts{}, errHelp
		case "--no-policy":
			opts.NoPolicy = true
		case "--output-review":
			opts.OutputReview = true
		case "--allow-root":
			opts.AllowRoot = true
		default:
			if strings.HasPrefix(args[i], "-") {
				return remoteConnectOpts{}, fmt.Errorf("unknown remote connect option: %s (run 'agbox remote --help')", args[i])
			}
			pos = append(pos, args[i])
		}
	}

	if opts.NoPolicy && opts.PolicyPath != "" {
		return remoteConnectOpts{}, errors.New("conflicting options: cannot combine --policy and --no-policy")
	}
	if len(pos) != 1 {
		return remoteConnectOpts{}, errors.New("usage: agbox remote connect [options] <HOST:PORT>")
	}
	if _, _, err := net.SplitHostPort(pos[0]); err != nil {
		return remoteConnectOpts{}, fmt.Errorf("invalid remote address %q (expected HOST:PORT): %w", pos[0], err)
	}
	opts.RemoteAddr = pos[0]
	return opts, nil
}

func (a *appRuntime) remoteConnect(ctx context.Context, args []string) error {
	opts, err := parseRemoteConnectArgs(args)
	if err != nil {
		return err
	}
	if err := a.verifyUser(opts.AllowRoot); err != nil {
		return err
	}
	if a.IsTTY == nil || !a.IsTTY() {
		return errors.New("interactive TTY required for pairing and command review")
	}
	if err := config.EnsurePrivateDir(a.Env.DataDir); err != nil {
		return fmt.Errorf("prepare data dir: %w", err)
	}

	b, err := remotebroker.New(remotebroker.Config{
		RemoteAddr:          opts.RemoteAddr,
		SandboxName:         opts.SandboxName,
		DataDir:             a.Env.DataDir,
		PolicyPath:          opts.PolicyPath,
		NoPolicy:            opts.NoPolicy,
		OutputReview:        opts.OutputReview,
		ExtraRedactPatterns: opts.ExtraRedactPatterns,
		MaxOutputBytes:      opts.MaxOutputBytes,
		AskTimeout:          opts.AskTimeout,
		AuditLogPath:        opts.AuditLogPath,
		AllowRoot:           opts.AllowRoot,
		Stdin:               a.Stdin,
		Stdout:              a.Stdout,
		Stderr:              a.Stderr,
		Getenv:              a.Getenv,
		IsTTY:               a.IsTTY,
	})
	if err != nil {
		return err
	}
	return b.Run(ctx)
}

func (a *appRuntime) remotePolicy(args []string) error {
	var allowRoot bool
	var rest []string
	for i := 0; i < len(args); i++ {
		if len(rest) == 0 {
			switch args[i] {
			case "-h", "--help":
				return errHelp
			case "--allow-root":
				allowRoot = true
				continue
			}
		}
		rest = append(rest, args[i])
	}
	if len(rest) == 0 {
		return errHelp
	}
	sub := rest[0]
	tail := rest[1:]
	defaultPolPath := filepath.Join(a.Env.DataDir, "remote-policy.json")

	switch sub {
	case "init":
		outPath := defaultPolPath
		force := false
		for i := 0; i < len(tail); i++ {
			if val, ok, err := consumeFlagValue(tail, &i, "--output", "-o"); ok {
				if err != nil || strings.TrimSpace(val) == "" {
					return errors.New("--output requires a file path")
				}
				outPath = strings.TrimSpace(val)
				continue
			}
			switch tail[i] {
			case "-h", "--help":
				return errHelp
			case "--force", "-f":
				force = true
			case "--allow-root":
				allowRoot = true
			default:
				return fmt.Errorf("unknown remote policy init option: %s", tail[i])
			}
		}
		if err := a.verifyUser(allowRoot); err != nil {
			return err
		}
		absOut, err := filepath.Abs(outPath)
		if err != nil {
			return fmt.Errorf("resolve output path %s: %w", outPath, err)
		}
		parent := filepath.Dir(absOut)
		cleanDataDir := ""
		if a.Env.DataDir != "" {
			cleanDataDir = filepath.Clean(a.Env.DataDir)
		}
		if cleanDataDir != "" && (parent == cleanDataDir || strings.HasPrefix(parent, cleanDataDir+string(filepath.Separator))) {
			if err := config.EnsurePrivateDir(cleanDataDir); err != nil {
				return err
			}
		}
		if err := os.MkdirAll(parent, 0o700); err != nil {
			return fmt.Errorf("create policy directory %s: %w", parent, err)
		}
		if info, err := os.Lstat(outPath); err == nil {
			if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
				return fmt.Errorf("refusing to overwrite symlink or non-regular file %q", outPath)
			}
			if !force {
				return fmt.Errorf("policy file %s already exists (pass --force to overwrite)", outPath)
			}
		} else if !os.IsNotExist(err) {
			return fmt.Errorf("stat policy file %s: %w", outPath, err)
		}
		if err := writePolicyFileAtomic(outPath, remotepolicy.StarterPolicyJSON()); err != nil {
			return fmt.Errorf("write policy file %s: %w", outPath, err)
		}
		a.logf("Wrote starter remote policy to %s (mode 0600).", outPath)
		return nil

	case "check":
		var flagPath string
		var pos []string
		for i := 0; i < len(tail); i++ {
			if val, ok, err := consumeFlagValue(tail, &i, "--policy"); ok {
				if err != nil || strings.TrimSpace(val) == "" {
					return errors.New("--policy requires a file path")
				}
				flagPath = strings.TrimSpace(val)
				continue
			}
			switch tail[i] {
			case "-h", "--help":
				return errHelp
			case "--allow-root":
				allowRoot = true
			default:
				if strings.HasPrefix(tail[i], "-") {
					return fmt.Errorf("unknown remote policy check option: %s", tail[i])
				}
				pos = append(pos, tail[i])
			}
		}
		if err := a.verifyUser(allowRoot); err != nil {
			return err
		}
		if flagPath != "" && len(pos) > 0 {
			return errors.New("conflicting policy path: specify either --policy <PATH> or a positional <PATH>, not both")
		}
		if len(pos) > 1 {
			return errors.New("usage: agbox remote policy check [--policy <PATH> | <PATH>]")
		}
		target := defaultPolPath
		if flagPath != "" {
			target = flagPath
		} else if len(pos) == 1 {
			target = pos[0]
		}
		pol, warnings, err := remotepolicy.LoadCheckedFile(target, allowRoot)
		if err != nil {
			return err
		}
		fmt.Fprintf(a.Stdout, "Policy OK: %s (version=%d, default=%s, output_review=%s, rules=%d)\n",
			target, pol.Version, pol.DefaultAction, pol.PerRunOutputReview, len(pol.Rules))
		for _, w := range warnings {
			a.warnf("%s", w)
		}
		return nil

	case "test":
		polPath := defaultPolPath
		explicitPolicy := false
		var cwd string
		hasStdin := false
		var cmdTokens []string
		for i := 0; i < len(tail); i++ {
			tok := tail[i]
			if tok == "--" {
				cmdTokens = tail[i+1:]
				break
			}
			if !strings.HasPrefix(tok, "-") {
				cmdTokens = tail[i:]
				break
			}
			if val, ok, err := consumeFlagValue(tail, &i, "--policy"); ok {
				if err != nil || strings.TrimSpace(val) == "" {
					return errors.New("--policy requires a file path")
				}
				polPath = strings.TrimSpace(val)
				explicitPolicy = true
				continue
			}
			if val, ok, err := consumeFlagValue(tail, &i, "--cwd"); ok {
				if err != nil {
					return errors.New("--cwd requires a path")
				}
				cwd = val
				continue
			}
			switch tok {
			case "-h", "--help":
				return errHelp
			case "--stdin":
				hasStdin = true
			case "--allow-root":
				allowRoot = true
			default:
				return fmt.Errorf("unknown remote policy test option: %s", tok)
			}
		}
		if err := a.verifyUser(allowRoot); err != nil {
			return err
		}
		if len(cmdTokens) == 0 {
			return errors.New("usage: agbox remote policy test [--policy <PATH>] [--cwd <DIR>] [--stdin] [--] <EXECUTABLE> [ARG...]")
		}
		var pol *remotepolicy.Policy
		if _, statErr := os.Lstat(polPath); !explicitPolicy && os.IsNotExist(statErr) {
			pol = remotepolicy.DefaultPolicy()
		} else {
			var err error
			var warnings []string
			pol, warnings, err = remotepolicy.LoadCheckedFile(polPath, allowRoot)
			if err != nil {
				return err
			}
			for _, w := range warnings {
				a.warnf("%s", w)
			}
		}
		stdinSz := 0
		if hasStdin {
			stdinSz = 1
		}
		_, summary := remotebroker.EvaluateAndFormatPolicyTest(pol, remotepolicy.EvalInput{
			Executable: cmdTokens[0],
			Args:       cmdTokens[1:],
			CWD:        cwd,
			StdinSize:  stdinSz,
		})
		fmt.Fprint(a.Stdout, summary)
		return nil

	default:
		return fmt.Errorf("unknown remote policy subcommand %q (expected init, check, or test)", sub)
	}
}

func (a *appRuntime) printRemoteStatus() {
	fmt.Fprintln(a.Stdout, "\n== remote ==")
	defPol := filepath.Join(a.Env.DataDir, "remote-policy.json")
	if _, err := os.Lstat(defPol); err == nil {
		fmt.Fprintf(a.Stdout, "default_policy: %s\n", defPol)
	} else {
		fmt.Fprintln(a.Stdout, "default_policy: none")
	}
	cands, err := remotebroker.DiscoverSandboxes(a.Env.DataDir)
	if err != nil {
		fmt.Fprintf(a.Stdout, "bridges: error (%v)\n", err)
		return
	}
	shown := 0
	for _, c := range cands {
		if !c.HasBridge && !(c.IsRunning && !c.NoRemote) {
			continue
		}
		shown++
		st, sErr := remotebridge.QueryStatus(c.SockPath)
		if sErr != nil {
			fmt.Fprintf(a.Stdout, "%s: error (%v)\n", c.Name, sErr)
			continue
		}
		if st.Attached {
			pol := st.Policy
			if pol == "" {
				pol = "default"
			}
			fmt.Fprintf(a.Stdout, "%s: connected (%s, %s, policy=%s)\n",
				c.Name,
				remoteproto.SanitizeLine(st.Peer),
				remoteproto.SanitizeLine(st.RemoteID),
				remoteproto.SanitizeLine(pol),
			)
		} else {
			fmt.Fprintf(a.Stdout, "%s: ready (no broker attached)\n", c.Name)
		}
	}
	if shown == 0 {
		fmt.Fprintln(a.Stdout, "bridges: none")
	}
}

func writePolicyFileAtomic(path string, content []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".remote-policy-*")
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
	if _, err := tmp.Write(content); err != nil {
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

func (a *appRuntime) setupGuestRemote(ctx context.Context, sandbox string) error {
	_, err := a.runGuestRootScript(ctx, sandbox, "install agbox-remote symlink in "+sandbox, "sh", remotebridge.BuildGuestSetupScript())
	return err
}
