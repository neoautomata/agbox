// Package pathsec validates host paths before agbox shares them into a sandbox.
//
// Security properties:
//   - ValidateShare resolves all symlinks and rejects missing or dangling paths.
//   - ValidateShare rejects control characters, ':', ',', and unsafe basenames.
//   - ValidateShare restricts shares to $HOME unless AllowOutsideHome is true.
//   - DefaultBlocklist blocks credentials, agent state, VCS configs, shell startup
//     files, system paths, parent directories of blocked paths, and symlink targets.
//   - ContainsVCSComponent reports whether a path contains a VCS directory or
//     control file component (case-insensitive). ValidateShare blocks matching paths.
//   - ValidateShare rejects non-regular files and writable files with st_nlink != 1.
package pathsec

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"agbox/internal/config"
)

// DefaultVCSNames returns the version-control directory and control file names
// that agbox blocks from direct sharing and masks inside directory shares.
func DefaultVCSNames() []string {
	return []string{
		".git",
		".gitignore",
		".gitattributes",
		".gitmodules",
		".mailmap",
		".jj",
		".sl",
		".svn",
		".hg",
		".hgignore",
		".hgsub",
		".hgsubstate",
		".hgtags",
		".hgeol",
		".bzr",
		".bzrignore",
		"_darcs",
		".pijul",
		".fossil-settings",
		".fslckout",
		"_fossil_",
		".cvsignore",
	}
}

// DefaultBlocklist returns the host paths that agbox never shares into a guest.
// ValidateShare also blocks any parent directory that contains a blocked path.
func DefaultBlocklist(homeReal, dataDir, msbHome string) []string {
	h := filepath.Clean(homeReal)
	list := []string{
		filepath.Join(h, ".ssh"),
		filepath.Join(h, ".gnupg"),
		filepath.Join(h, ".gpg"),
		filepath.Join(h, ".pki"),
		filepath.Join(h, ".aws"),
		filepath.Join(h, ".azure"),
		filepath.Join(h, ".kube"),
		filepath.Join(h, ".docker"),
		filepath.Join(h, ".config", "gcloud"),
		filepath.Join(h, ".config", "gh"),
		filepath.Join(h, ".config", "rclone"),
		filepath.Join(h, ".config", "opencode"),
		filepath.Join(h, ".local", "share", "opencode"),
		filepath.Join(h, ".local", "state", "opencode"),
		filepath.Join(h, ".gemini"),
		filepath.Join(h, ".config", "antigravity"),
		filepath.Join(h, ".antigravity"),
		filepath.Join(h, ".claude"),
		filepath.Join(h, ".claude.json"),
		filepath.Join(h, ".codex"),
		filepath.Join(h, ".npmrc"),
		filepath.Join(h, ".netrc"),
		filepath.Join(h, ".pypirc"),
		filepath.Join(h, ".pgpass"),
		filepath.Join(h, ".my.cnf"),
		filepath.Join(h, ".vault-token"),
		filepath.Join(h, ".terraform.d"),
		filepath.Join(h, ".gem", "credentials"),
		filepath.Join(h, ".m2", "settings.xml"),
		filepath.Join(h, ".git-credentials"),
		filepath.Join(h, ".local", "share", "keyrings"),
		filepath.Join(h, ".password-store"),
		filepath.Join(h, ".local", "share", "containers"),
		filepath.Join(h, ".mozilla"),
		filepath.Join(h, ".config", "google-chrome"),
		filepath.Join(h, ".config", "chromium"),
		filepath.Join(h, ".config", "BraveSoftware"),
		filepath.Join(h, ".config", "Code"),
		filepath.Join(h, ".config", "Cursor"),
		filepath.Join(h, ".vscode"),
		filepath.Join(h, ".local", "bin"),
		filepath.Join(h, "bin"),
		filepath.Join(h, ".cargo"),
		filepath.Join(h, "go", "bin"),
		filepath.Join(h, ".bashrc"),
		filepath.Join(h, ".bash_aliases"),
		filepath.Join(h, ".bash_logout"),
		filepath.Join(h, ".bash_profile"),
		filepath.Join(h, ".bash_login"),
		filepath.Join(h, ".bash_history"),
		filepath.Join(h, ".zsh_history"),
		filepath.Join(h, ".profile"),
		filepath.Join(h, ".pam_environment"),
		filepath.Join(h, ".zshrc"),
		filepath.Join(h, ".zshenv"),
		filepath.Join(h, ".zprofile"),
		filepath.Join(h, ".zlogin"),
		filepath.Join(h, ".config", "zsh"),
		filepath.Join(h, ".config", "fish"),
		filepath.Join(h, ".local", "share", "fish"),
		filepath.Join(h, ".gitconfig"),
		filepath.Join(h, ".gitattributes"),
		filepath.Join(h, ".gitignore"),
		filepath.Join(h, ".gitignore_global"),
		filepath.Join(h, ".config", "git"),
		filepath.Join(h, ".jjconfig.toml"),
		filepath.Join(h, ".config", "jj"),
		filepath.Join(h, ".hgrc"),
		filepath.Join(h, ".subversion"),
		filepath.Join(h, ".bazaar"),
		filepath.Join(h, ".config", "hub"),
		filepath.Join(h, ".config", "glab"),
		filepath.Join(h, ".envrc"),
		filepath.Join(h, ".config", "direnv"),
		filepath.Join(h, ".inputrc"),
		filepath.Join(h, ".curlrc"),
		filepath.Join(h, ".wgetrc"),
		filepath.Join(h, ".lesskey"),
		filepath.Join(h, ".vimrc"),
		filepath.Join(h, ".vim"),
		filepath.Join(h, ".config", "nvim"),
		filepath.Join(h, ".emacs"),
		filepath.Join(h, ".emacs.d"),
		filepath.Join(h, ".config", "emacs"),
		filepath.Join(h, ".tmux.conf"),
		filepath.Join(h, ".screenrc"),
		filepath.Join(h, ".xinitrc"),
		filepath.Join(h, ".xserverrc"),
		filepath.Join(h, ".xsession"),
		filepath.Join(h, ".xsessionrc"),
		filepath.Join(h, ".xprofile"),
		filepath.Join(h, ".config", "autostart"),
		filepath.Join(h, ".config", "systemd"),
		filepath.Join(h, ".local", "share", "systemd"),
		filepath.Join(h, ".local", "share", "applications"),
		filepath.Join(h, ".local", "share", "dbus-1"),
		filepath.Join(h, ".config", "environment.d"),
		filepath.Join(h, ".microsandbox"),
		filepath.Join(h, ".local", "share", "agbox"),
		"/etc", "/proc", "/sys", "/dev", "/boot",
		"/run", "/var/run", "/usr", "/bin", "/sbin", "/lib", "/lib64",
		"/var/run/docker.sock", "/run/docker.sock",
	}
	// Block /root when homeReal is not /root.
	// When homeReal is /root, the dotfile entries block /root and sensitive subdirectories.
	// Project directories such as /root/myapp remain valid shares.
	if h != "/root" {
		list = append(list, "/root")
	}
	if dataDir != "" {
		list = append(list, filepath.Clean(dataDir))
	}
	if msbHome != "" {
		list = append(list, filepath.Clean(msbHome))
	}
	return list
}

// IsSubpath reports whether candidate equals root or resides inside root.
// It cleans both paths before comparison.
func IsSubpath(candidate, root string) bool {
	if candidate == "" || root == "" {
		return false
	}
	c := filepath.Clean(candidate)
	r := filepath.Clean(root)
	if r == "/" {
		return strings.HasPrefix(c, "/")
	}
	return c == r || strings.HasPrefix(c, r+"/")
}

// ContainsVCSComponent reports whether any path component of p matches one of
// the VCS names in vcsNames (case-insensitive).
func ContainsVCSComponent(p string, vcsNames []string) (string, bool) {
	vcsSet := make(map[string]struct{}, len(vcsNames))
	for _, v := range vcsNames {
		if v != "" {
			vcsSet[strings.ToLower(v)] = struct{}{}
		}
	}
	for _, part := range strings.Split(filepath.Clean(p), "/") {
		if part == "" {
			continue
		}
		if _, ok := vcsSet[strings.ToLower(part)]; ok {
			return part, true
		}
	}
	return "", false
}

func hasControlChar(s string) bool {
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return true
		}
		if (r >= 0x200B && r <= 0x200F) || (r >= 0x202A && r <= 0x202E) || (r >= 0x2066 && r <= 0x2069) || r == 0xFEFF {
			return true
		}
	}
	return false
}

// Policy defines the security rules that ValidateShare enforces.
type Policy struct {
	HomeReal         string
	AllowOutsideHome bool
	ReadOnly         bool
	Blocklist        []string
	VCSNames         []string
}

// ShareTarget describes a validated host entry for mounting at /workspace/<GuestName>.
type ShareTarget struct {
	HostPath      string
	BaseName      string
	GuestName     string
	IsDir         bool
	ReadOnly      bool
	VCSPolicy     config.VCSPolicy
	ExplicitAlias bool
}

// ShareSpec holds a parsed CLI share argument before filesystem validation.
type ShareSpec struct {
	RawPath      string
	ReadOnly     bool
	HasAccessOpt bool
	VCSPolicy    config.VCSPolicy
	HasVCSOpt    bool
	GuestAlias   string
}

// ResolveOpts sets default share permissions and conflict locks for ResolveShareSpecs.
type ResolveOpts struct {
	Policy     Policy
	DefaultRO  bool
	LockRO     bool
	DefaultVCS config.VCSPolicy
	LockVCS    bool
}

// ValidateGuestAlias validates a guest mount name (`as=<name>` or `--as <name>`).
func ValidateGuestAlias(name string) (string, error) {
	if name == "" {
		return "", errors.New("guest share name must not be empty")
	}
	if len(name) > 128 {
		return "", fmt.Errorf("guest share name %q exceeds 128 characters", name)
	}
	if name == "." || name == ".." || strings.ContainsAny(name, "/\\:, \t\n\r") || hasControlChar(name) {
		return "", fmt.Errorf("invalid guest share name %q", name)
	}
	if vcs, bad := ContainsVCSComponent(name, DefaultVCSNames()); bad {
		return "", fmt.Errorf("guest share name %q cannot match VCS entry %s", name, vcs)
	}
	return name, nil
}

// ParseShareSpec splits `<path>[:<mod1>,<mod2>,...]` and validates share modifiers.
// It returns an error on conflicting, duplicate, or unknown modifiers.
func ParseShareSpec(raw string) (ShareSpec, error) {
	return parseShareSpecWithStat(raw, os.Lstat)
}

func parseShareSpecWithStat(raw string, lstat func(string) (os.FileInfo, error)) (ShareSpec, error) {
	if raw == "" {
		return ShareSpec{}, errors.New("share path must not be empty")
	}
	if hasControlChar(raw) {
		return ShareSpec{}, fmt.Errorf("refusing path containing control character: %q", raw)
	}

	colonIdx := strings.IndexByte(raw, ':')
	if colonIdx < 0 {
		return ShareSpec{RawPath: raw}, nil
	}
	if lstat != nil {
		if _, err := lstat(raw); err == nil {
			return ShareSpec{}, fmt.Errorf("refusing to share path containing ':' (conflicts with share modifier syntax): %s", raw)
		}
	}

	rawPath := raw[:colonIdx]
	modStr := raw[colonIdx+1:]
	if rawPath == "" {
		return ShareSpec{}, fmt.Errorf("missing host path before ':' in %q", raw)
	}
	if strings.ContainsAny(rawPath, ":,") {
		return ShareSpec{}, fmt.Errorf("refusing to share path containing ':' or ',': %s", rawPath)
	}
	if modStr == "" {
		return ShareSpec{}, fmt.Errorf("empty share modifier after ':' in %q", raw)
	}

	spec := ShareSpec{RawPath: rawPath}
	for _, tok := range strings.Split(modStr, ",") {
		if tok == "" {
			return ShareSpec{}, fmt.Errorf("empty share modifier token in %q", raw)
		}
		if strings.HasPrefix(tok, "as=") {
			if spec.GuestAlias != "" {
				return ShareSpec{}, fmt.Errorf("duplicate guest alias modifier in %q", raw)
			}
			alias, err := ValidateGuestAlias(strings.TrimPrefix(tok, "as="))
			if err != nil {
				return ShareSpec{}, err
			}
			spec.GuestAlias = alias
			continue
		}
		switch tok {
		case "ro":
			if spec.HasAccessOpt {
				return ShareSpec{}, fmt.Errorf("conflicting or duplicate access modifiers in %q", raw)
			}
			spec.ReadOnly = true
			spec.HasAccessOpt = true
		case "rw":
			if spec.HasAccessOpt {
				return ShareSpec{}, fmt.Errorf("conflicting or duplicate access modifiers in %q", raw)
			}
			spec.ReadOnly = false
			spec.HasAccessOpt = true
		case "mask", "mask-vcs":
			if spec.HasVCSOpt {
				return ShareSpec{}, fmt.Errorf("conflicting or duplicate VCS modifiers in %q", raw)
			}
			spec.VCSPolicy = config.VCSMask
			spec.HasVCSOpt = true
		case "vcs":
			if spec.HasVCSOpt {
				return ShareSpec{}, fmt.Errorf("conflicting or duplicate VCS modifiers in %q", raw)
			}
			spec.VCSPolicy = config.VCSAllow
			spec.HasVCSOpt = true
		case "vcs-hooks":
			if spec.HasVCSOpt {
				return ShareSpec{}, fmt.Errorf("conflicting or duplicate VCS modifiers in %q", raw)
			}
			spec.VCSPolicy = config.VCSAllowHooks
			spec.HasVCSOpt = true
		default:
			return ShareSpec{}, fmt.Errorf("unknown share modifier %q in %q (expected ro, rw, mask, vcs, vcs-hooks, or as=<name>)", tok, raw)
		}
	}

	if spec.HasAccessOpt && spec.ReadOnly && spec.HasVCSOpt && spec.VCSPolicy == config.VCSAllowHooks {
		return ShareSpec{}, fmt.Errorf("conflicting modifiers ro and vcs-hooks in %q: read-only shares cannot write hooks", raw)
	}
	return spec, nil
}

// ResolveShareSpecs validates ShareSpecs against host policies and assigns guest names.
// It rejects conflicting options and overlapping host paths.
func ResolveShareSpecs(specs []ShareSpec, opts ResolveOpts) ([]ShareTarget, error) {
	defaultVCS := opts.DefaultVCS
	if defaultVCS == "" {
		defaultVCS = config.VCSMask
	}
	if opts.LockRO && opts.DefaultRO && defaultVCS == config.VCSAllowHooks {
		return nil, errors.New("conflicting options: cannot combine --ro and --vcs-hooks")
	}

	targets := make([]ShareTarget, 0, len(specs))
	for _, spec := range specs {
		ro := opts.DefaultRO
		if spec.HasAccessOpt {
			if opts.LockRO && spec.ReadOnly != opts.DefaultRO {
				return nil, fmt.Errorf("conflicting access options for %q: flag and modifier disagree on ro/rw", spec.RawPath)
			}
			ro = spec.ReadOnly
		}

		vcsPol := defaultVCS
		if spec.HasVCSOpt {
			if opts.LockVCS && spec.VCSPolicy != defaultVCS {
				return nil, fmt.Errorf("conflicting VCS options for %q: flag (%s) and modifier (%s) disagree", spec.RawPath, defaultVCS, spec.VCSPolicy)
			}
			vcsPol = spec.VCSPolicy
		}

		if ro && vcsPol == config.VCSAllowHooks {
			return nil, fmt.Errorf("conflicting options for %q: read-only share cannot enable vcs-hooks", spec.RawPath)
		}

		itemPol := opts.Policy
		itemPol.ReadOnly = ro
		target, err := ValidateShare(spec.RawPath, itemPol)
		if err != nil {
			return nil, err
		}
		if !target.IsDir {
			if spec.HasVCSOpt && spec.VCSPolicy != config.VCSMask {
				return nil, fmt.Errorf("VCS modifier %q applies only to directory shares: %s", spec.VCSPolicy, target.HostPath)
			}
			vcsPol = config.VCSMask
		}

		target.ReadOnly = ro
		target.VCSPolicy = vcsPol
		if spec.GuestAlias != "" {
			target.GuestName = spec.GuestAlias
			target.ExplicitAlias = true
		}
		targets = append(targets, target)
	}

	if err := CheckDisjointHostPaths(targets); err != nil {
		return nil, err
	}
	return AssignGuestNamesChecked(targets)
}

// CheckDisjointHostPaths rejects duplicate or nested host share paths.
func CheckDisjointHostPaths(targets []ShareTarget) error {
	for i := 0; i < len(targets); i++ {
		for j := i + 1; j < len(targets); j++ {
			a := targets[i].HostPath
			b := targets[j].HostPath
			if a == b {
				return fmt.Errorf("duplicate share path: %s", a)
			}
			if IsSubpath(a, b) || IsSubpath(b, a) {
				return fmt.Errorf("overlapping share paths %s and %s: shares must not nest", a, b)
			}
		}
	}
	return nil
}

const maxSymlinkHops = 40

// resolveBlocklistPath resolves symlinks in the longest existing prefix of p
// and follows dangling symlink components so blocklist targets stay protected
// before those targets exist.
func resolveBlocklistPath(p string) string {
	curPath := filepath.Clean(p)
	if !filepath.IsAbs(curPath) {
		return curPath
	}
	for hop := 0; hop < maxSymlinkHops; hop++ {
		if resolved, err := filepath.EvalSymlinks(curPath); err == nil {
			return filepath.Clean(resolved)
		}
		advanced := false
		cur := curPath
		for cur != "/" && cur != "." {
			if resolved, err := filepath.EvalSymlinks(cur); err == nil {
				rel, rErr := filepath.Rel(cur, curPath)
				if rErr == nil {
					return filepath.Clean(filepath.Join(resolved, rel))
				}
				return curPath
			}
			if info, lErr := os.Lstat(cur); lErr == nil && info.Mode()&os.ModeSymlink != 0 {
				target, rErr := os.Readlink(cur)
				if rErr != nil {
					return curPath
				}
				if !filepath.IsAbs(target) {
					parentDir := filepath.Dir(cur)
					if resolvedParent, pErr := filepath.EvalSymlinks(parentDir); pErr == nil {
						parentDir = resolvedParent
					}
					target = filepath.Join(parentDir, target)
				}
				rel, relErr := filepath.Rel(cur, curPath)
				if relErr != nil {
					return curPath
				}
				if rel == "." {
					curPath = filepath.Clean(target)
				} else {
					curPath = filepath.Clean(filepath.Join(target, rel))
				}
				advanced = true
				break
			}
			parent := filepath.Dir(cur)
			if parent == cur {
				break
			}
			cur = parent
		}
		if !advanced {
			return curPath
		}
	}
	return curPath
}

// ValidateShare resolves symlinks on rawPath and validates containment, blocklists,
// characters, VCS names, and hardlink counts.
func ValidateShare(rawPath string, pol Policy) (ShareTarget, error) {
	if rawPath == "" {
		return ShareTarget{}, errors.New("share path must not be empty")
	}
	if hasControlChar(rawPath) {
		return ShareTarget{}, fmt.Errorf("refusing path containing control character: %q", rawPath)
	}

	absPath, err := filepath.Abs(rawPath)
	if err != nil {
		return ShareTarget{}, fmt.Errorf("resolve share path %s: %w", rawPath, err)
	}
	resolved, err := filepath.EvalSymlinks(absPath)
	if err != nil {
		return ShareTarget{}, fmt.Errorf("resolve share path %s: %w", rawPath, err)
	}
	resolved = filepath.Clean(resolved)
	base := filepath.Base(resolved)
	if resolved == "/" || base == "." || base == ".." || hasControlChar(resolved) {
		return ShareTarget{}, fmt.Errorf("refusing unsafe share path: %q", resolved)
	}

	if strings.ContainsAny(resolved, ":,") || strings.ContainsAny(base, ":,") {
		return ShareTarget{}, fmt.Errorf("refusing to share path containing ':' or ',' (conflicts with msb volume syntax): %s", resolved)
	}

	if !pol.AllowOutsideHome {
		homeClean := filepath.Clean(pol.HomeReal)
		if pol.HomeReal == "" || !filepath.IsAbs(homeClean) || !IsSubpath(resolved, homeClean) {
			return ShareTarget{}, fmt.Errorf("refusing to share path outside $HOME: %s (set AGBOX_ALLOW_OUTSIDE_HOME=1 to override)", resolved)
		}
	}

	for _, item := range pol.Blocklist {
		if item == "" {
			continue
		}
		cleanItem := filepath.Clean(item)
		if IsSubpath(resolved, cleanItem) || IsSubpath(cleanItem, resolved) {
			return ShareTarget{}, fmt.Errorf("refusing to share a sensitive path: %s (matches blocklist entry %s)", resolved, cleanItem)
		}
		// Block the resolved target and its parents when a blocklist entry or ancestor is a symlink.
		evalItem := resolveBlocklistPath(cleanItem)
		if evalItem != "" && evalItem != cleanItem {
			if IsSubpath(resolved, evalItem) || IsSubpath(evalItem, resolved) {
				return ShareTarget{}, fmt.Errorf("refusing to share a sensitive path: %s (matches symlinked blocklist entry %s -> %s)", resolved, cleanItem, evalItem)
			}
		}
	}

	info, err := os.Lstat(resolved)
	if err != nil {
		return ShareTarget{}, fmt.Errorf("stat %s: %w", resolved, err)
	}

	vcsNames := pol.VCSNames
	if len(vcsNames) == 0 {
		vcsNames = DefaultVCSNames()
	}

	if vcs, bad := ContainsVCSComponent(resolved, vcsNames); bad {
		return ShareTarget{}, fmt.Errorf("refusing to share %s: path has VCS component %s. Share the project root instead", resolved, vcs)
	}

	if info.IsDir() {
		return ShareTarget{
			HostPath:  resolved,
			BaseName:  base,
			GuestName: base,
			IsDir:     true,
		}, nil
	}

	if !info.Mode().IsRegular() {
		return ShareTarget{}, fmt.Errorf("refusing to share non-regular file: %s", resolved)
	}

	if !pol.ReadOnly {
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			return ShareTarget{}, fmt.Errorf("cannot inspect link count for %s", resolved)
		}
		if st.Nlink != 1 {
			return ShareTarget{}, fmt.Errorf("refusing writable single-file share with multiple hard links (nlink=%d): %s (use --ro or remove extra links)", st.Nlink, resolved)
		}
	}

	return ShareTarget{
		HostPath:  resolved,
		BaseName:  base,
		GuestName: base,
		IsDir:     false,
	}, nil
}

// AssignGuestNamesChecked assigns unique guest names and validates every name.
func AssignGuestNamesChecked(targets []ShareTarget) ([]ShareTarget, error) {
	out := make([]ShareTarget, len(targets))
	used := make(map[string]bool, len(targets))

	for idx, t := range targets {
		if !t.ExplicitAlias {
			continue
		}
		if _, err := ValidateGuestAlias(t.GuestName); err != nil {
			return nil, err
		}
		if used[t.GuestName] {
			return nil, fmt.Errorf("duplicate guest share name %q", t.GuestName)
		}
		used[t.GuestName] = true
		if t.BaseName == "" {
			t.BaseName = filepath.Base(t.HostPath)
		}
		out[idx] = t
	}

	for idx, t := range targets {
		if t.ExplicitAlias {
			continue
		}
		base := t.BaseName
		if base == "" {
			base = filepath.Base(t.HostPath)
		}
		name := base
		for suffix := 2; used[name]; suffix++ {
			name = fmt.Sprintf("%s-%d", base, suffix)
		}
		if _, err := ValidateGuestAlias(name); err != nil {
			return nil, fmt.Errorf("invalid guest share name %q for %s: %w (use as=<name> to set a valid alias)", name, t.HostPath, err)
		}
		used[name] = true
		t.BaseName = base
		t.GuestName = name
		out[idx] = t
	}
	return out, nil
}
