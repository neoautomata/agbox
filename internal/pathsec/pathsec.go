// Package pathsec validates host paths before agbox shares them into a microVM.
//
// Security properties:
//   - ValidateShare resolves all symlinks and rejects missing or dangling paths.
//   - ValidateShare rejects control characters, ':', ',', and unsafe basenames.
//   - ValidateShare restricts shares to $HOME unless AllowOutsideHome is true.
//   - DefaultBlocklist blocks credentials, agent state, VCS configs, shell startup
//     files, system paths, parent directories of blocked paths, and symlink targets.
//   - ContainsVCSComponent blocks direct shares of any VCS directory, subdirectory,
//     or working-tree control file (case-insensitive).
//   - ValidateShare rejects non-regular files and writable files with st_nlink != 1.
package pathsec

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
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
// agbox also blocks any parent directory that contains a blocklisted path.
func DefaultBlocklist(homeReal, dataDir, msbHome string) []string {
	h := filepath.Clean(homeReal)
	list := []string{
		filepath.Join(h, ".ssh"),
		filepath.Join(h, ".gnupg"),
		filepath.Join(h, ".gpg"),
		filepath.Join(h, ".aws"),
		filepath.Join(h, ".azure"),
		filepath.Join(h, ".kube"),
		filepath.Join(h, ".docker"),
		filepath.Join(h, ".config", "gcloud"),
		filepath.Join(h, ".config", "gh"),
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
		filepath.Join(h, ".zshrc"),
		filepath.Join(h, ".zshenv"),
		filepath.Join(h, ".zprofile"),
		filepath.Join(h, ".zlogin"),
		filepath.Join(h, ".config", "zsh"),
		filepath.Join(h, ".config", "fish"),
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
		filepath.Join(h, ".emacs.d"),
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

// IsSubpath reports whether candidate is equal to root or resides inside root.
// Both paths are cleaned before comparison.
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
	}
	return false
}

// Policy defines the security rules applied by ValidateShare.
type Policy struct {
	HomeReal         string
	AllowOutsideHome bool
	ReadOnly         bool
	Blocklist        []string
	VCSNames         []string
}

// ShareTarget represents a validated host filesystem entry to be mounted at
// /workspace/<GuestName> inside the guest.
type ShareTarget struct {
	HostPath  string
	BaseName  string
	GuestName string
	IsDir     bool
}

// ValidateShare resolves symlinks on rawPath and verifies that it satisfies all
// path containment, blocklist, character, VCS, and hardlink invariants.
func ValidateShare(rawPath string, pol Policy) (ShareTarget, error) {
	if rawPath == "" {
		return ShareTarget{}, fmt.Errorf("share path must not be empty")
	}
	if hasControlChar(rawPath) {
		return ShareTarget{}, fmt.Errorf("refusing path containing control character: %q", rawPath)
	}

	resolved, err := filepath.EvalSymlinks(rawPath)
	if err != nil {
		return ShareTarget{}, fmt.Errorf("path does not exist (or resolves through a dangling link): %s", rawPath)
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
		if pol.HomeReal == "" || !IsSubpath(resolved, pol.HomeReal) {
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
		// If the blocklisted entry is a symlink, also block the resolved target
		// and its parent directories.
		if evalItem, err := filepath.EvalSymlinks(cleanItem); err == nil {
			evalItem = filepath.Clean(evalItem)
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
			return ShareTarget{}, fmt.Errorf("refusing writable single-file share with multiple hard links (nlink=%d): %s (use --ro or break extra links)", st.Nlink, resolved)
		}
	}

	return ShareTarget{
		HostPath:  resolved,
		BaseName:  base,
		GuestName: base,
		IsDir:     false,
	}, nil
}

// AssignGuestNames returns a new slice of ShareTargets where duplicate
// BaseNames receive collision-free suffixes ("foo", "foo-2", "foo-3", ...).
func AssignGuestNames(targets []ShareTarget) []ShareTarget {
	out := make([]ShareTarget, len(targets))
	used := make(map[string]bool, len(targets))
	for idx, t := range targets {
		base := t.BaseName
		if base == "" {
			base = filepath.Base(t.HostPath)
		}
		name := base
		for suffix := 2; used[name]; suffix++ {
			name = fmt.Sprintf("%s-%d", base, suffix)
		}
		used[name] = true
		t.BaseName = base
		t.GuestName = name
		out[idx] = t
	}
	return out
}

// FormatVolumeSpec formats an `msb -v` volume argument mapping hostSource to
// /workspace/<guestName> with the given read/write mode and guest UID/GID.
func FormatVolumeSpec(hostSource, guestName string, readOnly bool, uid, gid int) string {
	mode := "rw"
	if readOnly {
		mode = "ro"
	}
	return fmt.Sprintf("%s:/workspace/%s:%s,uid=%d,gid=%d", hostSource, guestName, mode, uid, gid)
}
