// Package persist manages persistent sandbox authentication, global skills, and profile metadata.
//
// Security properties:
//   - Stores sandbox credentials in $DATA_DIR/auth with directory mode 0700 and file mode 0600.
//   - Rejects symlinks via Lstat across $DATA_DIR/auth, $DATA_DIR/skills, and $DATA_DIR/profiles.
//   - Captures and restores only allowlisted credential files within a 64 KiB size limit.
//   - Streams credential restore scripts over stdin so tokens never appear in CLI arguments.
//   - Rejects symlinks, special files, and unsafe path delimiters in $DATA_DIR/skills.
//   - Enforces exclusive host flock locking per conversation profile to prevent concurrent ext4 mounts.
package persist

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"

	"agbox/internal/config"
	"agbox/internal/msb"
	"agbox/internal/pathsec"
)

const (
	// MaxAuthFileBytes caps each saved credential file at 64 KiB.
	MaxAuthFileBytes = 64 * 1024

	// MaxSkillFileBytes caps each global skill file at 10 MiB.
	MaxSkillFileBytes = 10 * 1024 * 1024

	// ProfileVolumePrefix precedes every msb disk volume created for --profile.
	ProfileVolumePrefix = "agbox-profile-"
)

type authFileSpec struct {
	Agent    string
	Name     string
	RelPath  string
	Required bool
	IsJSON   bool
}

var allowlistedAuthSpecs = []authFileSpec{
	{
		Agent:    "antigravity",
		Name:     "antigravity-oauth-token",
		RelPath:  ".gemini/antigravity-cli/antigravity-oauth-token",
		Required: true,
	},
	{
		Agent:   "antigravity",
		Name:    "installation_id",
		RelPath: ".gemini/antigravity-cli/installation_id",
	},
	{
		Agent:   "antigravity",
		Name:    "antigravity_state.pbtxt",
		RelPath: ".gemini/antigravity-cli/antigravity_state.pbtxt",
	},
	{
		Agent:   "antigravity",
		Name:    "jetski_state.pbtxt",
		RelPath: ".gemini/antigravity-cli/jetski_state.pbtxt",
	},
	{
		Agent:    "opencode",
		Name:     "auth.json",
		RelPath:  ".local/share/opencode/auth.json",
		Required: true,
		IsJSON:   true,
	},
}

// AuthFile represents one validated credential file for an agent.
type AuthFile struct {
	Agent string
	Name  string
	Data  []byte
}

// AuthBundle holds validated credential files for one or more agents.
type AuthBundle struct {
	Files []AuthFile
}

// IsEmpty reports whether bundle contains zero credential files.
func (b AuthBundle) IsEmpty() bool {
	return len(b.Files) == 0
}

func specsForAgent(agent string) ([]authFileSpec, error) {
	switch agent {
	case "antigravity", "opencode":
	default:
		return nil, fmt.Errorf("unsupported auth agent %q (expected antigravity or opencode)", agent)
	}
	var out []authFileSpec
	for _, sp := range allowlistedAuthSpecs {
		if sp.Agent == agent {
			out = append(out, sp)
		}
	}
	return out, nil
}

func lookupAuthSpec(agent, name string) (authFileSpec, bool) {
	for _, sp := range allowlistedAuthSpecs {
		if sp.Agent == agent && sp.Name == name {
			return sp, true
		}
	}
	return authFileSpec{}, false
}

// BuildAuthCaptureScript builds a POSIX sh script that encodes allowlisted
// credential files under /home/agent as base64 lines on stdout.
func BuildAuthCaptureScript(agent string) (string, error) {
	return BuildAuthCaptureScriptForHome(agent, config.GuestHome)
}

// BuildAuthCaptureScriptForHome builds the credential capture script for guestHome.
func BuildAuthCaptureScriptForHome(agent, guestHome string) (string, error) {
	specs, err := specsForAgent(agent)
	if err != nil {
		return "", err
	}
	if guestHome == "" {
		return "", errors.New("guest home path must not be empty")
	}
	limitPlusOne := MaxAuthFileBytes + 1
	var b strings.Builder
	b.WriteString("set -eu\n")
	for _, sp := range specs {
		full := filepath.Clean(filepath.Join(guestHome, sp.RelPath))
		qPath := msb.ShellQuote(full)
		fmt.Fprintf(&b, "if [ -L %s ]; then echo 'SYMLINK %s %s'; exit 1; fi\n", qPath, sp.Agent, sp.Name)
		fmt.Fprintf(&b, "if [ -f %s ]; then\n", qPath)
		fmt.Fprintf(&b, "  b64=$(head -c %d %s | base64 | tr -d '\\n\\r ')\n", limitPlusOne, qPath)
		fmt.Fprintf(&b, "  printf 'FILE %s %s %%s\\n' \"$b64\"\n", sp.Agent, sp.Name)
		b.WriteString("fi\n")
	}
	return b.String(), nil
}

// ParseAuthCapture validates stdout from BuildAuthCaptureScript and returns an AuthBundle.
func ParseAuthCapture(agent, stdout string) (AuthBundle, error) {
	specs, err := specsForAgent(agent)
	if err != nil {
		return AuthBundle{}, err
	}
	seen := make(map[string][]byte, len(specs))
	for _, rawLine := range strings.Split(stdout, "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "SYMLINK ") {
			return AuthBundle{}, fmt.Errorf("refusing symlinked credential file in guest (%s)", line)
		}
		fields := strings.Fields(line)
		if len(fields) != 4 || fields[0] != "FILE" {
			return AuthBundle{}, fmt.Errorf("unexpected credential capture output line")
		}
		gotAgent, name, b64 := fields[1], fields[2], fields[3]
		if gotAgent != agent {
			return AuthBundle{}, fmt.Errorf("captured credential agent mismatch: got %q, want %q", gotAgent, agent)
		}
		sp, ok := lookupAuthSpec(agent, name)
		if !ok {
			return AuthBundle{}, fmt.Errorf("refusing non-allowlisted credential file %q", name)
		}
		if _, dup := seen[name]; dup {
			return AuthBundle{}, fmt.Errorf("duplicate credential file %q in capture output", name)
		}
		decoded, dErr := base64.StdEncoding.DecodeString(b64)
		if dErr != nil {
			return AuthBundle{}, fmt.Errorf("decode credential file %q: %w", name, dErr)
		}
		if len(decoded) == 0 {
			continue
		}
		if len(decoded) > MaxAuthFileBytes {
			return AuthBundle{}, fmt.Errorf("credential file %q exceeds %d bytes", name, MaxAuthFileBytes)
		}
		if sp.IsJSON {
			if err := validateNonEmptyJSONObject(decoded, name); err != nil {
				return AuthBundle{}, err
			}
		}
		seen[name] = decoded
	}

	var files []AuthFile
	for _, sp := range specs {
		data, ok := seen[sp.Name]
		if !ok || len(data) == 0 {
			if sp.Required {
				return AuthBundle{}, fmt.Errorf("no %s credentials were saved (sign-in did not complete)", agent)
			}
			continue
		}
		files = append(files, AuthFile{
			Agent: sp.Agent,
			Name:  sp.Name,
			Data:  data,
		})
	}
	return AuthBundle{Files: files}, nil
}

func validateNonEmptyJSONObject(raw []byte, name string) error {
	var obj map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(raw), &obj); err != nil {
		return fmt.Errorf("credential file %q is not a valid JSON object: %w", name, err)
	}
	if len(obj) == 0 {
		return fmt.Errorf("credential file %q contains an empty JSON object", name)
	}
	return nil
}

// FormatAuthRestoreScript builds a POSIX sh script that writes bundle into /home/agent.
// Callers stream this script over stdin so secrets never appear in CLI arguments.
func FormatAuthRestoreScript(bundle AuthBundle) (string, error) {
	return FormatAuthRestoreScriptForHome(bundle, config.GuestHome)
}

// FormatAuthRestoreScriptForHome builds the credential restore script for guestHome.
func FormatAuthRestoreScriptForHome(bundle AuthBundle, guestHome string) (string, error) {
	if bundle.IsEmpty() {
		return "", nil
	}
	if guestHome == "" {
		return "", errors.New("guest home path must not be empty")
	}
	var b strings.Builder
	b.WriteString("set -eu\n")
	b.WriteString("umask 077\n")
	createdDirs := make(map[string]bool)
	for _, f := range bundle.Files {
		sp, ok := lookupAuthSpec(f.Agent, f.Name)
		if !ok {
			return "", fmt.Errorf("refusing non-allowlisted credential file %s/%s", f.Agent, f.Name)
		}
		if len(f.Data) == 0 || len(f.Data) > MaxAuthFileBytes {
			return "", fmt.Errorf("invalid credential size for %s/%s (%d bytes)", f.Agent, f.Name, len(f.Data))
		}
		target := filepath.Clean(filepath.Join(guestHome, sp.RelPath))
		parent := filepath.Dir(target)
		if !createdDirs[parent] {
			fmt.Fprintf(&b, "mkdir -p %s\n", msb.ShellQuote(parent))
			createdDirs[parent] = true
		}
		qTarget := msb.ShellQuote(target)
		b64 := base64.StdEncoding.EncodeToString(f.Data)
		fmt.Fprintf(&b, "rm -f %s\n", qTarget)
		fmt.Fprintf(&b, "printf '%%s' '%s' | base64 -d > %s\n", b64, qTarget)
		fmt.Fprintf(&b, "chmod 0600 %s\n", qTarget)
	}
	return b.String(), nil
}

// SaveAuthBundle writes validated credential files atomically into $DATA_DIR/auth/<agent> with mode 0600.
func SaveAuthBundle(dataDir string, bundle AuthBundle) error {
	if bundle.IsEmpty() {
		return errors.New("auth bundle is empty")
	}
	if err := config.EnsurePrivateDir(dataDir); err != nil {
		return err
	}
	authRoot := filepath.Join(dataDir, "auth")
	if err := config.EnsurePrivateDir(authRoot); err != nil {
		return err
	}

	byAgent := make(map[string][]AuthFile)
	for _, f := range bundle.Files {
		sp, ok := lookupAuthSpec(f.Agent, f.Name)
		if !ok {
			return fmt.Errorf("refusing non-allowlisted credential file %s/%s", f.Agent, f.Name)
		}
		if len(f.Data) == 0 || len(f.Data) > MaxAuthFileBytes {
			return fmt.Errorf("invalid credential size for %s/%s", f.Agent, f.Name)
		}
		if sp.IsJSON {
			if err := validateNonEmptyJSONObject(f.Data, f.Name); err != nil {
				return err
			}
		}
		byAgent[f.Agent] = append(byAgent[f.Agent], f)
	}

	for agent, files := range byAgent {
		specs, err := specsForAgent(agent)
		if err != nil {
			return err
		}
		agentDir := filepath.Join(authRoot, agent)
		if err := config.EnsurePrivateDir(agentDir); err != nil {
			return err
		}
		present := make(map[string]bool, len(files))
		for _, f := range files {
			present[f.Name] = true
			if err := writePrivateFileAtomic(filepath.Join(agentDir, f.Name), f.Data); err != nil {
				return err
			}
		}
		// Remove optional stale files from earlier logins that are no longer present.
		for _, sp := range specs {
			if !present[sp.Name] {
				_ = os.Remove(filepath.Join(agentDir, sp.Name))
			}
		}
	}
	return nil
}

// LoadAuthBundle reads saved credential files for the requested agents from $DATA_DIR/auth.
// Missing directories return an empty AuthBundle without error. Symlinks fail closed.
func LoadAuthBundle(dataDir string, agents []string) (AuthBundle, error) {
	if dataDir == "" {
		return AuthBundle{}, errors.New("data directory path must not be empty")
	}
	if err := verifyOptionalPrivateDir(dataDir); err != nil {
		return AuthBundle{}, err
	}
	authRoot := filepath.Join(dataDir, "auth")
	if err := verifyOptionalPrivateDir(authRoot); err != nil {
		return AuthBundle{}, err
	}
	if _, err := os.Lstat(authRoot); os.IsNotExist(err) {
		return AuthBundle{}, nil
	}

	var files []AuthFile
	seenAgents := make(map[string]bool, len(agents))
	for _, agent := range agents {
		if agent == "" || seenAgents[agent] {
			continue
		}
		seenAgents[agent] = true
		specs, err := specsForAgent(agent)
		if err != nil {
			return AuthBundle{}, err
		}
		agentDir := filepath.Join(authRoot, agent)
		if err := verifyOptionalPrivateDir(agentDir); err != nil {
			return AuthBundle{}, err
		}
		if _, err := os.Lstat(agentDir); os.IsNotExist(err) {
			continue
		}
		var agentFiles []AuthFile
		hasRequired := true
		for _, sp := range specs {
			p := filepath.Join(agentDir, sp.Name)
			data, exists, rErr := readSafeRegularFile(p, MaxAuthFileBytes)
			if rErr != nil {
				return AuthBundle{}, rErr
			}
			if !exists || len(data) == 0 {
				if sp.Required {
					hasRequired = false
				}
				continue
			}
			if sp.IsJSON {
				if err := validateNonEmptyJSONObject(data, sp.Name); err != nil {
					return AuthBundle{}, err
				}
			}
			agentFiles = append(agentFiles, AuthFile{
				Agent: sp.Agent,
				Name:  sp.Name,
				Data:  data,
			})
		}
		if hasRequired {
			files = append(files, agentFiles...)
		}
	}
	return AuthBundle{Files: files}, nil
}

// AuthStatus reports whether valid saved credentials exist for antigravity and opencode.
func AuthStatus(dataDir string) (map[string]bool, error) {
	status := map[string]bool{
		"antigravity": false,
		"opencode":    false,
	}
	for _, agent := range []string{"antigravity", "opencode"} {
		bundle, err := LoadAuthBundle(dataDir, []string{agent})
		if err != nil {
			return nil, err
		}
		status[agent] = !bundle.IsEmpty()
	}
	return status, nil
}

// RemoveAuth deletes saved credentials for antigravity, opencode, or all from $DATA_DIR/auth.
func RemoveAuth(dataDir, target string) error {
	if err := verifyOptionalPrivateDir(dataDir); err != nil {
		return err
	}
	authRoot := filepath.Join(dataDir, "auth")
	if err := verifyOptionalPrivateDir(authRoot); err != nil {
		return err
	}
	var agents []string
	switch target {
	case "", "all":
		agents = []string{"antigravity", "opencode"}
	case "antigravity", "opencode":
		agents = []string{target}
	default:
		return fmt.Errorf("unknown logout target %q (expected antigravity, opencode, or all)", target)
	}
	for _, ag := range agents {
		agentDir := filepath.Join(authRoot, ag)
		if err := verifyOptionalPrivateDir(agentDir); err != nil {
			return err
		}
		if err := os.RemoveAll(agentDir); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("remove %s auth: %w", ag, err)
		}
	}
	return nil
}

// ValidateSkillName checks a global skill directory name.
func ValidateSkillName(raw string) (string, error) {
	if raw == "" {
		return "", errors.New("skill name must not be empty")
	}
	if len(raw) > 63 {
		return "", errors.New("skill name must be 63 characters or fewer")
	}
	if _, bad := pathsec.ContainsVCSComponent(raw, pathsec.DefaultVCSNames()); bad {
		return "", fmt.Errorf("skill name %q conflicts with a reserved VCS name", raw)
	}
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		isAlphaNum := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
		if i == 0 {
			if !isAlphaNum {
				return "", fmt.Errorf("invalid skill name %q: must start with an ASCII letter or digit", raw)
			}
			continue
		}
		if !isAlphaNum && c != '-' && c != '_' {
			return "", fmt.Errorf("invalid skill name %q: use only ASCII letters, digits, '-' or '_'", raw)
		}
	}
	return raw, nil
}

// InspectSkillsDir validates $DATA_DIR/skills and returns sorted names of skills containing SKILL.md.
// If skillsDir does not exist, InspectSkillsDir returns nil, nil.
// Symlinks, special files, or msb delimiter characters fail closed.
func InspectSkillsDir(skillsDir string) ([]string, error) {
	if skillsDir == "" {
		return nil, errors.New("skills directory path must not be empty")
	}
	for _, r := range skillsDir {
		if r < 0x20 || r == 0x7f || r == ':' || r == ',' {
			return nil, fmt.Errorf("skills directory %q contains unsupported characters for msb mounts", skillsDir)
		}
	}
	info, err := os.Lstat(skillsDir)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("stat skills dir %q: %w", skillsDir, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("refusing symlinked skills directory %q", skillsDir)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("skills path %q is not a directory", skillsDir)
	}

	if err := walkRejectSymlinksAndSpecial(skillsDir); err != nil {
		return nil, err
	}

	entries, err := os.ReadDir(skillsDir)
	if err != nil {
		return nil, fmt.Errorf("read skills dir %q: %w", skillsDir, err)
	}
	var names []string
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		name := entry.Name()
		if _, vErr := ValidateSkillName(name); vErr != nil {
			return nil, vErr
		}
		skillFile := filepath.Join(skillsDir, name, "SKILL.md")
		st, sErr := os.Lstat(skillFile)
		if os.IsNotExist(sErr) {
			continue
		}
		if sErr != nil {
			return nil, fmt.Errorf("stat %s: %w", skillFile, sErr)
		}
		if !st.Mode().IsRegular() {
			return nil, fmt.Errorf("refusing non-regular SKILL.md at %s", skillFile)
		}
		names = append(names, name)
	}
	slices.Sort(names)
	return names, nil
}

func walkRejectSymlinksAndSpecial(root string) error {
	return filepath.WalkDir(root, func(p string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		typ := d.Type()
		if typ&os.ModeSymlink != 0 {
			return fmt.Errorf("refusing symlink inside skills directory: %s", p)
		}
		if !d.IsDir() && !typ.IsRegular() {
			return fmt.Errorf("refusing non-regular file inside skills directory: %s", p)
		}
		return nil
	})
}

// InstallSkill validates srcPath (a skill directory or SKILL.md path) and copies it into skillsDir/<name>.
func InstallSkill(skillsDir, srcPath string, force bool) (string, error) {
	if srcPath == "" {
		return "", errors.New("skill source path must not be empty")
	}
	resolved, err := filepath.EvalSymlinks(srcPath)
	if err != nil {
		return "", fmt.Errorf("resolve skill path %s: %w", srcPath, err)
	}
	info, err := os.Lstat(resolved)
	if err != nil {
		return "", fmt.Errorf("stat skill path %s: %w", resolved, err)
	}
	srcDir := resolved
	if !info.IsDir() {
		if filepath.Base(resolved) != "SKILL.md" {
			return "", fmt.Errorf("expected a skill directory or SKILL.md file, got %s", srcPath)
		}
		srcDir = filepath.Dir(resolved)
	}

	skillName, err := ValidateSkillName(filepath.Base(srcDir))
	if err != nil {
		return "", err
	}
	skillMD := filepath.Join(srcDir, "SKILL.md")
	mdInfo, err := os.Lstat(skillMD)
	if err != nil {
		return "", fmt.Errorf("skill directory %s is missing SKILL.md", srcDir)
	}
	if !mdInfo.Mode().IsRegular() {
		return "", fmt.Errorf("refusing non-regular SKILL.md in %s", srcDir)
	}

	if err := config.EnsurePrivateDir(filepath.Dir(skillsDir)); err != nil {
		return "", err
	}
	if err := config.EnsurePrivateDir(skillsDir); err != nil {
		return "", err
	}

	dstDir := filepath.Join(skillsDir, skillName)
	if _, statErr := os.Lstat(dstDir); statErr == nil {
		if !force {
			return "", fmt.Errorf("skill %q already exists (pass --force to replace it)", skillName)
		}
	}

	stageDir, err := os.MkdirTemp(skillsDir, ".skill-stage.*")
	if err != nil {
		return "", fmt.Errorf("create staging directory: %w", err)
	}
	cleanupStage := true
	defer func() {
		if cleanupStage {
			_ = os.RemoveAll(stageDir)
		}
	}()
	if err := os.Chmod(stageDir, 0o700); err != nil {
		return "", err
	}

	vcsNames := pathsec.DefaultVCSNames()
	err = filepath.WalkDir(srcDir, func(p string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, rErr := filepath.Rel(srcDir, p)
		if rErr != nil {
			return rErr
		}
		if rel == "." {
			return nil
		}
		if _, isVCS := pathsec.ContainsVCSComponent(rel, vcsNames); isVCS {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if d.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("refusing symlink in skill source: %s", p)
		}
		dstPath := filepath.Join(stageDir, rel)
		if d.IsDir() {
			return os.MkdirAll(dstPath, 0o755)
		}
		if !d.Type().IsRegular() {
			return fmt.Errorf("refusing non-regular file in skill source: %s", p)
		}
		fInfo, iErr := d.Info()
		if iErr != nil {
			return iErr
		}
		if fInfo.Size() > MaxSkillFileBytes {
			return fmt.Errorf("skill file %s exceeds %d bytes", p, MaxSkillFileBytes)
		}
		raw, readErr := os.ReadFile(p)
		if readErr != nil {
			return readErr
		}
		perm := fs.FileMode(0o644)
		if fInfo.Mode()&0o111 != 0 {
			perm = 0o755
		}
		return os.WriteFile(dstPath, raw, perm)
	})
	if err != nil {
		return "", err
	}

	if err := os.RemoveAll(dstDir); err != nil && !os.IsNotExist(err) {
		return "", fmt.Errorf("replace existing skill %q: %w", skillName, err)
	}
	if err := os.Rename(stageDir, dstDir); err != nil {
		return "", fmt.Errorf("commit skill %q: %w", skillName, err)
	}
	cleanupStage = false
	return skillName, nil
}

// RemoveSkill deletes skillsDir/<name>.
func RemoveSkill(skillsDir, rawName string) error {
	name, err := ValidateSkillName(rawName)
	if err != nil {
		return err
	}
	if err := verifyOptionalPrivateDir(skillsDir); err != nil {
		return err
	}
	target := filepath.Join(skillsDir, name)
	info, err := os.Lstat(target)
	if os.IsNotExist(err) {
		return fmt.Errorf("skill %q does not exist", name)
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("refusing symlinked skill entry %q", target)
	}
	return os.RemoveAll(target)
}

// BuildGuestSkillsMountScript returns an idempotent root sh script that bind-mounts
// /home/agent/.agbox-skills read-only into both agy and opencode global skill paths.
func BuildGuestSkillsMountScript() string {
	return `set -eu
mkdir -p /home/agent/.gemini/config/skills /home/agent/.config/opencode/skills
chown 1000:1000 /home/agent/.gemini /home/agent/.gemini/config /home/agent/.config /home/agent/.config/opencode
chmod 0700 /home/agent/.gemini /home/agent/.gemini/config /home/agent/.config /home/agent/.config/opencode
if ! grep -qs ' /home/agent/.gemini/config/skills ' /proc/self/mountinfo; then
  mount --bind /home/agent/.agbox-skills /home/agent/.gemini/config/skills
  mount -o remount,ro,bind /home/agent/.gemini/config/skills 2>/dev/null || true
fi
if ! grep -qs ' /home/agent/.config/opencode/skills ' /proc/self/mountinfo; then
  mount --bind /home/agent/.agbox-skills /home/agent/.config/opencode/skills
  mount -o remount,ro,bind /home/agent/.config/opencode/skills 2>/dev/null || true
fi
`
}

// ValidateProfileName checks a --profile name.
func ValidateProfileName(raw string) (string, error) {
	if raw == "" {
		return "", errors.New("profile name must not be empty")
	}
	if len(raw) > 48 {
		return "", errors.New("profile name must be 48 characters or fewer")
	}
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		isAlphaNum := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
		if i == 0 {
			if !isAlphaNum {
				return "", fmt.Errorf("invalid profile name %q: must start with an ASCII letter or digit", raw)
			}
			continue
		}
		if !isAlphaNum && c != '-' && c != '_' {
			return "", fmt.Errorf("invalid profile name %q: use only ASCII letters, digits, '-' or '_'", raw)
		}
	}
	return raw, nil
}

// FormatProfileVolumeName returns the msb disk volume name for profile name.
func FormatProfileVolumeName(name string) string {
	return ProfileVolumePrefix + name
}

// IsProfileVolumeName reports whether vol is a valid agbox-profile-<name> volume.
func IsProfileVolumeName(vol string) bool {
	if !strings.HasPrefix(vol, ProfileVolumePrefix) {
		return false
	}
	_, err := ValidateProfileName(strings.TrimPrefix(vol, ProfileVolumePrefix))
	return err == nil
}

// ProfileMeta records metadata for a persistent conversation profile in $DATA_DIR/profiles/<name>/profile.json.
type ProfileMeta struct {
	Name      string `json:"name"`
	Volume    string `json:"volume"`
	Size      string `json:"size"`
	CreatedAt string `json:"created_at"`
}

// ProfileLock holds an exclusive flock on $DATA_DIR/profiles/<name>/profile.lock.
type ProfileLock struct {
	file *os.File
}

// Unlock releases the flock and closes the underlying file descriptor.
func (l *ProfileLock) Unlock() error {
	if l == nil || l.file == nil {
		return nil
	}
	_ = syscall.Flock(int(l.file.Fd()), syscall.LOCK_UN)
	err := l.file.Close()
	l.file = nil
	return err
}

// LockProfile acquires a non-blocking exclusive lock for profile name.
func LockProfile(dataDir, rawName string) (*ProfileLock, error) {
	name, err := ValidateProfileName(rawName)
	if err != nil {
		return nil, err
	}
	if err := config.EnsurePrivateDir(dataDir); err != nil {
		return nil, err
	}
	profilesRoot := filepath.Join(dataDir, "profiles")
	if err := config.EnsurePrivateDir(profilesRoot); err != nil {
		return nil, err
	}
	profDir := filepath.Join(profilesRoot, name)
	if err := config.EnsurePrivateDir(profDir); err != nil {
		return nil, err
	}
	lockPath := filepath.Join(profDir, "profile.lock")
	if info, sErr := os.Lstat(lockPath); sErr == nil && info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("refusing symlinked profile lock %s", lockPath)
	}
	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open profile lock %s: %w", lockPath, err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("profile %q is locked by another active agbox process", name)
	}
	return &ProfileLock{file: f}, nil
}

// SaveProfileMeta writes profile.json atomically with mode 0600.
func SaveProfileMeta(dataDir string, meta ProfileMeta) error {
	name, err := ValidateProfileName(meta.Name)
	if err != nil {
		return err
	}
	if meta.Volume == "" {
		meta.Volume = FormatProfileVolumeName(name)
	}
	if meta.CreatedAt == "" {
		meta.CreatedAt = time.Now().UTC().Format(time.RFC3339)
	}
	if err := config.EnsurePrivateDir(dataDir); err != nil {
		return err
	}
	profDir := filepath.Join(dataDir, "profiles", name)
	if err := config.EnsurePrivateDir(filepath.Dir(profDir)); err != nil {
		return err
	}
	if err := config.EnsurePrivateDir(profDir); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return err
	}
	return writePrivateFileAtomic(filepath.Join(profDir, "profile.json"), append(raw, '\n'))
}

// ListProfiles returns sorted ProfileMeta entries stored under $DATA_DIR/profiles.
func ListProfiles(dataDir string) ([]ProfileMeta, error) {
	if err := verifyOptionalPrivateDir(dataDir); err != nil {
		return nil, err
	}
	profilesRoot := filepath.Join(dataDir, "profiles")
	if err := verifyOptionalPrivateDir(profilesRoot); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(profilesRoot)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []ProfileMeta
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		name, vErr := ValidateProfileName(entry.Name())
		if vErr != nil {
			continue
		}
		metaPath := filepath.Join(profilesRoot, name, "profile.json")
		raw, exists, rErr := readSafeRegularFile(metaPath, MaxAuthFileBytes)
		if rErr != nil {
			return nil, rErr
		}
		if !exists {
			continue
		}
		var pm ProfileMeta
		if err := json.Unmarshal(raw, &pm); err == nil && pm.Name != "" {
			out = append(out, pm)
		}
	}
	slices.SortFunc(out, func(a, b ProfileMeta) int {
		return strings.Compare(a.Name, b.Name)
	})
	return out, nil
}

// RemoveProfileDir deletes $DATA_DIR/profiles/<name>.
func RemoveProfileDir(dataDir, rawName string) error {
	name, err := ValidateProfileName(rawName)
	if err != nil {
		return err
	}
	if err := verifyOptionalPrivateDir(dataDir); err != nil {
		return err
	}
	profilesRoot := filepath.Join(dataDir, "profiles")
	if err := verifyOptionalPrivateDir(profilesRoot); err != nil {
		return err
	}
	profDir := filepath.Join(profilesRoot, name)
	if err := verifyOptionalPrivateDir(profDir); err != nil {
		return err
	}
	return os.RemoveAll(profDir)
}

// BuildGuestProfileMountScript returns an idempotent root sh script that initializes
// /home/agent/.agbox-profile on ext4 and bind-mounts agent conversation directories.
// Global skills, hooks, plugins, and MCP configs remain outside the profile disk.
func BuildGuestProfileMountScript() string {
	return `set -eu
mkdir -p \
  /home/agent/.agbox-profile \
  /home/agent/.agbox-profile/agy-cli \
  /home/agent/.agbox-profile/agy-projects \
  /home/agent/.agbox-profile/opencode-data \
  /home/agent/.agbox-profile/opencode-state
chown 1000:1000 \
  /home/agent/.agbox-profile \
  /home/agent/.agbox-profile/agy-cli \
  /home/agent/.agbox-profile/agy-projects \
  /home/agent/.agbox-profile/opencode-data \
  /home/agent/.agbox-profile/opencode-state
chmod 0700 \
  /home/agent/.agbox-profile \
  /home/agent/.agbox-profile/agy-cli \
  /home/agent/.agbox-profile/agy-projects \
  /home/agent/.agbox-profile/opencode-data \
  /home/agent/.agbox-profile/opencode-state

if ! grep -qs ' /home/agent/.gemini/antigravity-cli ' /proc/self/mountinfo; then
  for sub in bin builtin updater; do
    if [ -d "/home/agent/.gemini/antigravity-cli/${sub}" ]; then
      rm -rf "/home/agent/.agbox-profile/agy-cli/${sub}"
      cp -a "/home/agent/.gemini/antigravity-cli/${sub}" "/home/agent/.agbox-profile/agy-cli/${sub}"
      chown -R 1000:1000 "/home/agent/.agbox-profile/agy-cli/${sub}"
    fi
  done
fi

mkdir -p \
  /home/agent/.gemini/antigravity-cli \
  /home/agent/.gemini/config/projects \
  /home/agent/.local/share/opencode \
  /home/agent/.local/state/opencode
chown 1000:1000 \
  /home/agent/.gemini \
  /home/agent/.gemini/antigravity-cli \
  /home/agent/.gemini/config \
  /home/agent/.gemini/config/projects \
  /home/agent/.local \
  /home/agent/.local/share \
  /home/agent/.local/share/opencode \
  /home/agent/.local/state \
  /home/agent/.local/state/opencode

if ! grep -qs ' /home/agent/.gemini/antigravity-cli ' /proc/self/mountinfo; then
  mount --bind /home/agent/.agbox-profile/agy-cli /home/agent/.gemini/antigravity-cli
fi
if ! grep -qs ' /home/agent/.gemini/config/projects ' /proc/self/mountinfo; then
  mount --bind /home/agent/.agbox-profile/agy-projects /home/agent/.gemini/config/projects
fi
if ! grep -qs ' /home/agent/.local/share/opencode ' /proc/self/mountinfo; then
  mount --bind /home/agent/.agbox-profile/opencode-data /home/agent/.local/share/opencode
fi
if ! grep -qs ' /home/agent/.local/state/opencode ' /proc/self/mountinfo; then
  mount --bind /home/agent/.agbox-profile/opencode-state /home/agent/.local/state/opencode
fi
`
}

// ValidateSessionID checks a conversation or session identifier passed to --session or --conversation.
func ValidateSessionID(raw string) (string, error) {
	if raw == "" {
		return "", errors.New("session ID must not be empty")
	}
	if len(raw) > 128 {
		return "", errors.New("session ID must be 128 characters or fewer")
	}
	for i, r := range raw {
		isAlnum := (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')
		if i == 0 {
			if !isAlnum {
				return "", fmt.Errorf("invalid session ID %q: must start with a letter or digit", raw)
			}
			continue
		}
		if !isAlnum && r != '.' && r != '_' && r != ':' && r != '-' {
			return "", fmt.Errorf("invalid session ID %q: only letters, digits, '.', '_', ':', and '-' are allowed", raw)
		}
	}
	return raw, nil
}

func verifyOptionalPrivateDir(dir string) error {
	if dir == "" {
		return errors.New("directory path must not be empty")
	}
	info, err := os.Lstat(dir)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("refusing symlinked directory %q", dir)
	}
	if !info.IsDir() {
		return fmt.Errorf("path %q is not a directory", dir)
	}
	return nil
}

func readSafeRegularFile(path string, maxBytes int64) ([]byte, bool, error) {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, false, fmt.Errorf("refusing symlinked state file %q", path)
	}
	if !info.Mode().IsRegular() {
		return nil, false, fmt.Errorf("refusing non-regular state file %q", path)
	}
	if info.Size() > maxBytes {
		return nil, false, fmt.Errorf("state file %q exceeds %d bytes", path, maxBytes)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, false, err
	}
	return raw, true, nil
}

func writePrivateFileAtomic(path string, content []byte) error {
	dir := filepath.Dir(path)
	if err := config.EnsurePrivateDir(dir); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".tmp.*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpName)
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
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	cleanup = false
	return nil
}
