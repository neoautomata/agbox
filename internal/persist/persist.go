// Package persist manages sandbox credentials, global skills, global rules,
// cached agent binaries, and conversation profile metadata.
//
// Security properties:
//   - SaveAuthBundle writes credentials in $DATA_DIR/auth at mode 0600 inside 0700 directories.
//   - Every directory and file reader rejects symlinks with O_NOFOLLOW or Lstat.
//   - ParseAuthCapture and LoadAuthBundle accept only allowlisted files within 64 KiB.
//   - FormatAuthRestoreScript streams secrets over stdin and checks parent directories for symlinks.
//   - InspectAgentsDir checks ELF headers, link counts, and SHA-256 digests against manifest.json.
//   - LockProfile holds an exclusive host flock per profile outside the deleted profile directory.
package persist

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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
	maxAuthFileBytes    = 64 * 1024
	maxSkillFileBytes   = 10 * 1024 * 1024
	maxSkillTotalBytes  = 32 * 1024 * 1024
	maxSkillFiles       = 128
	maxRuleFileBytes    = 64 * 1024
	maxProfileMetaBytes = 16 * 1024

	// AgyRuleWarnBytes is Antigravity's inline limit (24,000 bytes) for one rule file.
	AgyRuleWarnBytes = 24000

	// ProfileVolumePrefix precedes every msb disk volume created for --profile.
	ProfileVolumePrefix = "agbox-profile-"
)

var supportedAgents = []struct {
	agent   string
	binName string
}{
	{agent: "antigravity", binName: "agy"},
	{agent: "opencode", binName: "opencode"},
}

func isSupportedAgent(agent string) bool {
	for _, entry := range supportedAgents {
		if entry.agent == agent {
			return true
		}
	}
	return false
}

func supportedAgentNames() []string {
	names := make([]string, len(supportedAgents))
	for i, entry := range supportedAgents {
		names[i] = entry.agent
	}
	return names
}

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

// AuthFile holds one checked credential file for an agent.
type AuthFile struct {
	Agent string
	Name  string
	Data  []byte
}

// AuthBundle holds checked credential files for one or more agents.
type AuthBundle struct {
	Files []AuthFile
}

// IsEmpty reports whether b contains zero credential files.
func (b AuthBundle) IsEmpty() bool {
	return len(b.Files) == 0
}

func specsForAgent(agent string) ([]authFileSpec, error) {
	if !isSupportedAgent(agent) {
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
	return buildAuthCaptureScriptForHome(agent, config.GuestHome)
}

func buildAuthCaptureScriptForHome(agent, guestHome string) (string, error) {
	specs, err := specsForAgent(agent)
	if err != nil {
		return "", err
	}
	if guestHome == "" {
		return "", errors.New("guest home path must not be empty")
	}
	cleanHome := filepath.Clean(guestHome)
	qHome := msb.ShellQuote(cleanHome)
	limitPlusOne := maxAuthFileBytes + 1

	var b strings.Builder
	b.WriteString("set -eu\n")
	fmt.Fprintf(&b, "if [ -L %s ]; then echo 'agbox rejects symlinked guest home' >&2; exit 1; fi\n", qHome)

	checkedDirs := map[string]bool{cleanHome: true}
	for _, sp := range specs {
		relDir := filepath.Dir(filepath.Clean(sp.RelPath))
		cur := cleanHome
		for _, part := range strings.Split(relDir, string(filepath.Separator)) {
			if part == "" || part == "." {
				continue
			}
			cur = filepath.Join(cur, part)
			if !checkedDirs[cur] {
				qCur := msb.ShellQuote(cur)
				fmt.Fprintf(&b, "if [ -L %s ]; then echo 'agbox rejects symlinked credential directory' >&2; exit 1; fi\n", qCur)
				checkedDirs[cur] = true
			}
		}
	}

	for _, sp := range specs {
		full := filepath.Clean(filepath.Join(cleanHome, sp.RelPath))
		qPath := msb.ShellQuote(full)
		fmt.Fprintf(&b, "if [ -L %s ]; then echo 'SYMLINK %s %s' >&2; exit 1; fi\n", qPath, sp.Agent, sp.Name)
		fmt.Fprintf(&b, "if [ -f %s ]; then\n", qPath)
		fmt.Fprintf(&b, "  if [ ! -r %s ]; then echo 'agbox cannot read credential file %s/%s' >&2; exit 1; fi\n", qPath, sp.Agent, sp.Name)
		fmt.Fprintf(&b, "  if [ -s %s ]; then\n", qPath)
		fmt.Fprintf(&b, "    b64=$(exec 3>&1; (head -c %d %s || printf '!' >&3) | (base64 || printf '!' >&3) | tr -d '\\n\\r ')\n", limitPlusOne, qPath)
		fmt.Fprintf(&b, "    case \"$b64\" in *'!'*) echo 'agbox failed to read credential file %s/%s' >&2; exit 1 ;; esac\n", sp.Agent, sp.Name)
		fmt.Fprintf(&b, "    printf 'FILE %s %s %%s\\n' \"$b64\"\n", sp.Agent, sp.Name)
		b.WriteString("  fi\n")
		b.WriteString("fi\n")
	}
	return b.String(), nil
}

// ParseAuthCapture checks stdout from BuildAuthCaptureScript and returns an AuthBundle.
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
		if fields[0] != "FILE" || (len(fields) != 3 && len(fields) != 4) {
			return AuthBundle{}, errors.New("unexpected credential capture output line")
		}
		gotAgent, name := fields[1], fields[2]
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
		if len(fields) == 3 {
			seen[name] = nil
			continue
		}
		decoded, dErr := base64.StdEncoding.DecodeString(fields[3])
		if dErr != nil {
			return AuthBundle{}, fmt.Errorf("decode credential file %q: %w", name, dErr)
		}
		if len(decoded) == 0 {
			seen[name] = nil
			continue
		}
		if len(decoded) > maxAuthFileBytes {
			return AuthBundle{}, fmt.Errorf("credential file %q exceeds %d bytes", name, maxAuthFileBytes)
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
				return AuthBundle{}, fmt.Errorf("sign-in did not save %s credentials", agent)
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
	return formatAuthRestoreScriptForHome(bundle, config.GuestHome)
}

func formatAuthRestoreScriptForHome(bundle AuthBundle, guestHome string) (string, error) {
	if bundle.IsEmpty() {
		return "", nil
	}
	if guestHome == "" {
		return "", errors.New("guest home path must not be empty")
	}
	cleanHome := filepath.Clean(guestHome)
	qHome := msb.ShellQuote(cleanHome)

	var b strings.Builder
	b.WriteString("set -eu\n")
	b.WriteString("umask 077\n")
	fmt.Fprintf(&b, "if [ -L %s ]; then echo 'agbox rejects symlinked guest home' >&2; exit 1; fi\n", qHome)

	checkedDirs := map[string]bool{cleanHome: true}
	for _, f := range bundle.Files {
		sp, ok := lookupAuthSpec(f.Agent, f.Name)
		if !ok {
			return "", fmt.Errorf("refusing non-allowlisted credential file %s/%s", f.Agent, f.Name)
		}
		if len(f.Data) == 0 || len(f.Data) > maxAuthFileBytes {
			return "", fmt.Errorf("invalid credential size for %s/%s (%d bytes)", f.Agent, f.Name, len(f.Data))
		}
		relDir := filepath.Dir(filepath.Clean(sp.RelPath))
		cur := cleanHome
		for _, part := range strings.Split(relDir, string(filepath.Separator)) {
			if part == "" || part == "." {
				continue
			}
			cur = filepath.Join(cur, part)
			if !checkedDirs[cur] {
				qCur := msb.ShellQuote(cur)
				fmt.Fprintf(&b, "if [ -L %s ]; then echo 'agbox rejects symlinked credential directory' >&2; exit 1; fi\n", qCur)
				fmt.Fprintf(&b, "mkdir -p %s\n", qCur)
				fmt.Fprintf(&b, "chmod 0700 %s\n", qCur)
				checkedDirs[cur] = true
			}
		}
		target := filepath.Clean(filepath.Join(cleanHome, sp.RelPath))
		qTarget := msb.ShellQuote(target)
		b64 := base64.StdEncoding.EncodeToString(f.Data)
		fmt.Fprintf(&b, "rm -f %s\n", qTarget)
		fmt.Fprintf(&b, "printf '%%s' '%s' | base64 -d > %s\n", b64, qTarget)
		fmt.Fprintf(&b, "chmod 0600 %s\n", qTarget)
	}
	return b.String(), nil
}

// SaveAuthBundle writes checked credential files atomically to $DATA_DIR/auth/<agent> at mode 0600.
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
		if len(f.Data) == 0 || len(f.Data) > maxAuthFileBytes {
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
		present := make(map[string]bool, len(files))
		for _, f := range files {
			present[f.Name] = true
		}
		for _, sp := range specs {
			if sp.Required && !present[sp.Name] {
				return fmt.Errorf("auth bundle for %s is missing required file %q", agent, sp.Name)
			}
		}
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
		// Delete optional files that the new bundle does not contain.
		for _, sp := range specs {
			if !present[sp.Name] {
				stalePath := filepath.Join(agentDir, sp.Name)
				if rErr := os.Remove(stalePath); rErr != nil && !os.IsNotExist(rErr) {
					return fmt.Errorf("remove stale credential %s: %w", stalePath, rErr)
				}
			}
		}
	}
	return nil
}

// LoadAuthBundle reads saved credential files for agents from $DATA_DIR/auth.
// Missing directories return an empty AuthBundle without error.
func LoadAuthBundle(dataDir string, agents []string) (AuthBundle, error) {
	if dataDir == "" {
		return AuthBundle{}, errors.New("data directory path must not be empty")
	}
	if err := verifyOptionalDir(dataDir); err != nil {
		return AuthBundle{}, err
	}
	authRoot := filepath.Join(dataDir, "auth")
	if err := verifyOptionalDir(authRoot); err != nil {
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
		if err := verifyOptionalDir(agentDir); err != nil {
			return AuthBundle{}, err
		}
		if _, err := os.Lstat(agentDir); os.IsNotExist(err) {
			continue
		}
		var agentFiles []AuthFile
		hasRequired := true
		for _, sp := range specs {
			p := filepath.Join(agentDir, sp.Name)
			data, exists, rErr := readSafeRegularFile(p, maxAuthFileBytes)
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

// AuthStatus reports whether valid saved credentials exist for each supported agent.
func AuthStatus(dataDir string) (map[string]bool, error) {
	status := make(map[string]bool, len(supportedAgents))
	for _, entry := range supportedAgents {
		bundle, err := LoadAuthBundle(dataDir, []string{entry.agent})
		if err != nil {
			return nil, err
		}
		status[entry.agent] = !bundle.IsEmpty()
	}
	return status, nil
}

// RemoveAuth deletes saved credentials for antigravity, opencode, or all from $DATA_DIR/auth.
func RemoveAuth(dataDir, target string) error {
	if err := verifyOptionalDir(dataDir); err != nil {
		return err
	}
	authRoot := filepath.Join(dataDir, "auth")
	if err := verifyOptionalDir(authRoot); err != nil {
		return err
	}
	var agents []string
	switch {
	case target == "" || target == "all":
		agents = supportedAgentNames()
	case isSupportedAgent(target):
		agents = []string{target}
	default:
		return fmt.Errorf("unknown logout target %q (expected antigravity, opencode, or all)", target)
	}
	for _, ag := range agents {
		agentDir := filepath.Join(authRoot, ag)
		if err := verifyOptionalDir(agentDir); err != nil {
			return err
		}
		if err := os.RemoveAll(agentDir); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("remove %s auth: %w", ag, err)
		}
	}
	return nil
}

func validateSkillName(raw string) (string, error) {
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

func validateMountDir(dir, label string) error {
	if dir == "" {
		return fmt.Errorf("%s directory path must not be empty", label)
	}
	if strings.ContainsAny(dir, ":,") {
		return fmt.Errorf("%s directory %q cannot contain ':' or ','", label, dir)
	}
	for _, r := range dir {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("%s directory %q contains control characters", label, dir)
		}
	}
	return nil
}

// InspectSkillsDir checks $DATA_DIR/skills and returns sorted skill names containing SKILL.md.
// If skillsDir does not exist, InspectSkillsDir returns nil, nil.
func InspectSkillsDir(skillsDir string) ([]string, error) {
	if err := validateMountDir(skillsDir, "skills"); err != nil {
		return nil, err
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
			return nil, fmt.Errorf("refusing non-directory entry %q in skills directory", entry.Name())
		}
		name := entry.Name()
		if strings.HasPrefix(name, ".") {
			return nil, fmt.Errorf("refusing hidden entry %q in skills directory", name)
		}
		if _, vErr := validateSkillName(name); vErr != nil {
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

// InstallSkill checks srcPath (a skill directory or SKILL.md path) and installs it in skillsDir/<name>.
func InstallSkill(skillsDir, srcPath string, force bool) (string, error) {
	if srcPath == "" {
		return "", errors.New("skill source path must not be empty")
	}
	if err := validateMountDir(skillsDir, "skills"); err != nil {
		return "", err
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

	skillName, err := validateSkillName(filepath.Base(srcDir))
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

	stageParent := filepath.Dir(skillsDir)
	if err := config.EnsurePrivateDir(stageParent); err != nil {
		return "", err
	}
	if err := config.EnsurePrivateDir(skillsDir); err != nil {
		return "", err
	}

	dstDir := filepath.Join(skillsDir, skillName)
	dstInfo, dstStatErr := os.Lstat(dstDir)
	dstExists := dstStatErr == nil
	if dstStatErr != nil && !os.IsNotExist(dstStatErr) {
		return "", dstStatErr
	}
	if dstExists {
		if dstInfo.Mode()&os.ModeSymlink != 0 {
			return "", fmt.Errorf("refusing symlinked skill destination %q", dstDir)
		}
		if !force {
			return "", fmt.Errorf("skill %q already exists (pass --force to replace it)", skillName)
		}
	}

	workDir, err := os.MkdirTemp(stageParent, ".agbox-stage-*")
	if err != nil {
		return "", fmt.Errorf("create staging directory: %w", err)
	}
	defer func() {
		_ = os.RemoveAll(workDir)
	}()

	stageDir := filepath.Join(workDir, "staged")
	if err := os.Mkdir(stageDir, 0o755); err != nil {
		return "", fmt.Errorf("create staged skill directory: %w", err)
	}

	vcsNames := pathsec.DefaultVCSNames()
	fileCount := 0
	var totalBytes int64
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
		fileCount++
		if fileCount > maxSkillFiles {
			return fmt.Errorf("skill %q exceeds %d files", skillName, maxSkillFiles)
		}
		raw, st, readErr := readRegularNoFollowWithStat(p, maxSkillFileBytes)
		if readErr != nil {
			return fmt.Errorf("read skill file %s: %w", p, readErr)
		}
		totalBytes += int64(len(raw))
		if totalBytes > maxSkillTotalBytes {
			return fmt.Errorf("skill %q exceeds %d total bytes", skillName, maxSkillTotalBytes)
		}
		perm := fs.FileMode(0o644)
		if st.Mode()&0o111 != 0 {
			perm = 0o755
		}
		return os.WriteFile(dstPath, raw, perm)
	})
	if err != nil {
		return "", err
	}

	backupDir := ""
	if dstExists {
		backupDir = filepath.Join(workDir, "backup")
		if err := os.Rename(dstDir, backupDir); err != nil {
			return "", fmt.Errorf("save backup of existing skill %q: %w", skillName, err)
		}
	}
	if err := os.Rename(stageDir, dstDir); err != nil {
		installErr := fmt.Errorf("commit skill %q: %w", skillName, err)
		if backupDir != "" {
			if rbErr := os.Rename(backupDir, dstDir); rbErr != nil {
				installErr = errors.Join(installErr, fmt.Errorf("restore skill backup %q: %w", skillName, rbErr))
			}
		}
		return "", installErr
	}
	return skillName, nil
}

// RemoveSkill deletes skillsDir/<name>.
func RemoveSkill(skillsDir, rawName string) error {
	name, err := validateSkillName(rawName)
	if err != nil {
		return err
	}
	if err := verifyOptionalDir(skillsDir); err != nil {
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

// BuildGuestSkillsMountScript returns a root sh script that bind-mounts
// /home/agent/.agbox-skills read-only into both agy and opencode skill paths.
func BuildGuestSkillsMountScript() string {
	return `set -eu
mkdir -p /home/agent/.gemini/config/skills /home/agent/.config/opencode/skills
chown 1000:1000 /home/agent/.gemini /home/agent/.gemini/config /home/agent/.config /home/agent/.config/opencode
chmod 0700 /home/agent/.gemini /home/agent/.gemini/config /home/agent/.config /home/agent/.config/opencode
if ! grep -Fqs ' /home/agent/.gemini/config/skills ' /proc/self/mountinfo; then
  mount --bind /home/agent/.agbox-skills /home/agent/.gemini/config/skills
  mount -o remount,ro,bind /home/agent/.gemini/config/skills
fi
if ! grep -Fqs ' /home/agent/.config/opencode/skills ' /proc/self/mountinfo; then
  mount --bind /home/agent/.agbox-skills /home/agent/.config/opencode/skills
  mount -o remount,ro,bind /home/agent/.config/opencode/skills
fi
`
}

// ValidateRuleName normalizes and checks a global rule name.
// It strips an optional lowercase .md suffix.
func ValidateRuleName(raw string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if len(trimmed) > 3 && strings.HasSuffix(trimmed, ".md") {
		trimmed = trimmed[:len(trimmed)-3]
	}
	if trimmed == "" {
		return "", errors.New("rule name must not be empty")
	}
	if len(trimmed) > 63 {
		return "", errors.New("rule name must be 63 characters or fewer")
	}
	for i := 0; i < len(trimmed); i++ {
		c := trimmed[i]
		isAlphaNum := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
		if i == 0 {
			if !isAlphaNum {
				return "", fmt.Errorf("invalid rule name %q: must start with an ASCII letter or digit", raw)
			}
			continue
		}
		if !isAlphaNum && c != '-' && c != '_' && c != '.' {
			return "", fmt.Errorf("invalid rule name %q: use only ASCII letters, digits, '.', '-', or '_'", raw)
		}
	}
	return trimmed, nil
}

// InspectRulesDir checks rulesDir and returns sorted rule names without .md.
// If rulesDir does not exist, InspectRulesDir returns nil, nil.
func InspectRulesDir(rulesDir string) ([]string, error) {
	if err := validateMountDir(rulesDir, "rules"); err != nil {
		return nil, err
	}
	if err := verifyOptionalDir(rulesDir); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(rulesDir)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read rules dir %s: %w", rulesDir, err)
	}

	var names []string
	for _, entry := range entries {
		entryPath := filepath.Join(rulesDir, entry.Name())
		info, sErr := os.Lstat(entryPath)
		if sErr != nil {
			return nil, fmt.Errorf("stat %s: %w", entryPath, sErr)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("refusing symlink inside rules directory: %s", entryPath)
		}
		if info.IsDir() {
			return nil, fmt.Errorf("refusing subdirectory inside rules directory: %s", entryPath)
		}
		if !info.Mode().IsRegular() {
			return nil, fmt.Errorf("refusing non-regular file inside rules directory: %s", entryPath)
		}
		base := entry.Name()
		if len(base) <= 3 || !strings.HasSuffix(base, ".md") {
			return nil, fmt.Errorf("refusing non-Markdown file inside rules directory: %s", entryPath)
		}
		stem, vErr := ValidateRuleName(base)
		if vErr != nil {
			return nil, vErr
		}
		if info.Size() == 0 || info.Size() > maxRuleFileBytes {
			return nil, fmt.Errorf("rule file %s has invalid size %d bytes (limit %d)", entryPath, info.Size(), maxRuleFileBytes)
		}
		names = append(names, stem)
	}
	slices.Sort(names)
	return names, nil
}

// InstallRule checks srcPath and writes it atomically to rulesDir/<name>.md.
func InstallRule(rulesDir, srcPath, overrideName string, force bool) (string, int, error) {
	if srcPath == "" {
		return "", 0, errors.New("rule source path must not be empty")
	}
	if err := validateMountDir(rulesDir, "rules"); err != nil {
		return "", 0, err
	}
	resolved, err := filepath.EvalSymlinks(srcPath)
	if err != nil {
		return "", 0, fmt.Errorf("resolve rule path %s: %w", srcPath, err)
	}
	info, err := os.Lstat(resolved)
	if err != nil {
		return "", 0, fmt.Errorf("stat rule path %s: %w", resolved, err)
	}
	if !info.Mode().IsRegular() {
		return "", 0, fmt.Errorf("expected a regular Markdown file, got %s", srcPath)
	}

	raw, _, err := readRegularNoFollowWithStat(resolved, maxRuleFileBytes)
	if err != nil {
		return "", 0, fmt.Errorf("rule file %s: %w", srcPath, err)
	}
	if len(raw) == 0 {
		return "", 0, fmt.Errorf("rule file %s is empty", srcPath)
	}

	rawName := overrideName
	if rawName == "" {
		base := filepath.Base(resolved)
		if len(base) <= 3 || !strings.HasSuffix(base, ".md") {
			return "", 0, fmt.Errorf("rule file %s must end in .md (or pass --name <name>)", srcPath)
		}
		rawName = base
	}
	ruleName, err := ValidateRuleName(rawName)
	if err != nil {
		return "", 0, err
	}
	if len(bytes.TrimSpace(raw)) == 0 {
		return "", 0, fmt.Errorf("rule file %s contains only whitespace", srcPath)
	}
	if bytes.IndexByte(raw, 0) >= 0 {
		return "", 0, fmt.Errorf("rule file %s contains binary NUL bytes", srcPath)
	}

	if err := config.EnsurePrivateDir(filepath.Dir(rulesDir)); err != nil {
		return "", 0, err
	}
	if err := config.EnsurePrivateDir(rulesDir); err != nil {
		return "", 0, err
	}

	// Check that rulesDir contains no symlinks or invalid files before writing.
	if _, err := InspectRulesDir(rulesDir); err != nil {
		return "", 0, err
	}

	dstPath := filepath.Join(rulesDir, ruleName+".md")
	if _, statErr := os.Lstat(dstPath); statErr == nil && !force {
		return "", 0, fmt.Errorf("rule %q already exists (pass --force to replace it)", ruleName)
	}
	if err := writeModeFileAtomic(dstPath, raw, 0o644); err != nil {
		return "", 0, fmt.Errorf("write rule %q: %w", ruleName, err)
	}
	return ruleName, len(raw), nil
}

// ReadRule reads rulesDir/<name>.md after checking rulesDir.
func ReadRule(rulesDir, rawName string) ([]byte, error) {
	name, err := ValidateRuleName(rawName)
	if err != nil {
		return nil, err
	}
	if _, err := InspectRulesDir(rulesDir); err != nil {
		return nil, err
	}
	target := filepath.Join(rulesDir, name+".md")
	raw, ok, err := readSafeRegularFile(target, maxRuleFileBytes)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fmt.Errorf("rule %q does not exist", name)
	}
	return raw, nil
}

// RemoveRule deletes rulesDir/<name>.md.
func RemoveRule(rulesDir, rawName string) error {
	name, err := ValidateRuleName(rawName)
	if err != nil {
		return err
	}
	if err := verifyOptionalDir(rulesDir); err != nil {
		return err
	}
	target := filepath.Join(rulesDir, name+".md")
	info, err := os.Lstat(target)
	if os.IsNotExist(err) {
		return fmt.Errorf("rule %q does not exist", name)
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("refusing symlinked rule entry %q", target)
	}
	return os.Remove(target)
}

// RemoveAllRules deletes every .md rule file inside rulesDir.
func RemoveAllRules(rulesDir string) error {
	names, err := InspectRulesDir(rulesDir)
	if err != nil {
		return err
	}
	for _, n := range names {
		if err := RemoveRule(rulesDir, n); err != nil {
			return err
		}
	}
	return nil
}

// DefaultEnvRuleName defines the stem of the default environment rule file.
const DefaultEnvRuleName = "AGBOX_ENV_RULES"

const defaultEnvRuleMarkdown = "" +
	"# Operating Inside an agbox Sandbox\n\n" +
	"## Guest Identity and Privileges\n\n" +
	"- You run as `agent` (`1000:1000`) inside a disposable Linux microVM with passwordless `sudo`.\n" +
	"- You control the guest OS. Use `sudo` to install packages, manage services, or run privileged tests.\n" +
	"- Installed system packages and files outside `/workspace` disappear on exit unless the host uses `--persist`.\n\n" +
	"## Workspace Shares and Permissions\n\n" +
	"- Host shares appear at `/workspace/<name>`. The `/workspace` root directory itself rejects direct file creation (`EROFS`).\n" +
	"- Assume `/workspace` masks `.git` and all other VCS directories and hooks by default (`ENOENT` or `EPERM`).\n" +
	"- When `git` commands fail, search and read files directly with `rg` instead of running `git init`.\n" +
	"- Stop and tell the user if `/workspace` returns `EROFS` (read-only share), `EPERM` (protected VCS path), or `ESTALE` (detached share).\n" +
	"- Ask the user to grant access from the host with `agbox share add` or `agbox share set --rw`.\n" +
	"- Never mount overlays or bind-mounts over `/workspace`. Never write project deliverables to `/tmp` or `/home/agent`.\n" +
	"- Keep symlinks relative and inside the same share. Host confinement rejects symlinks that escape a share root.\n\n" +
	"## Host Mounts, Hardware, and Network Boundaries\n\n" +
	"- Treat `/home/agent/.agbox-*` mounts, global skills, and global `AGENTS.md` files as host-managed mounts. Never unmount or shadow them.\n" +
	"- `/dev/kvm` and host `msb` commands do not exist inside the microVM. Do not run nested microVM workloads.\n" +
	"- Use `fusermount3` for unprivileged FUSE tests. Use `sudo` when `/dev/fuse` requires root access.\n" +
	"- Outbound DNS and public internet work by default unless the host starts the sandbox with `--no-net`.\n" +
	"- The default firewall blocks host, private LAN, link-local, multicast, and cloud metadata addresses. Stop and tell the user if a task needs `--net` changes.\n" +
	"- Run `agbox-remote` to request an approved command on a pre-connected remote machine. Read `/home/agent/.agbox-remote/INSTRUCTIONS.md` for rules.\n" +
	"- Never print, log, or copy credentials from `/home/agent/.agbox-keys.sh` or environment variables into `/workspace`.\n"

// EnsureDefaultEnvRule writes the default environment rule to rulesDir when missing.
// It returns true when it creates the file, or false when the file already exists.
func EnsureDefaultEnvRule(rulesDir string) (bool, error) {
	if err := validateMountDir(rulesDir, "rules"); err != nil {
		return false, err
	}
	if err := config.EnsurePrivateDir(filepath.Dir(rulesDir)); err != nil {
		return false, err
	}
	if err := config.EnsurePrivateDir(rulesDir); err != nil {
		return false, err
	}
	if _, err := InspectRulesDir(rulesDir); err != nil {
		return false, err
	}
	dstPath := filepath.Join(rulesDir, DefaultEnvRuleName+".md")
	_, err := os.Lstat(dstPath)
	if err == nil {
		return false, nil
	}
	if !os.IsNotExist(err) {
		return false, fmt.Errorf("stat default rule %s: %w", dstPath, err)
	}
	if err := writeModeFileAtomic(dstPath, []byte(defaultEnvRuleMarkdown), 0o644); err != nil {
		return false, fmt.Errorf("write default rule %s: %w", dstPath, err)
	}
	return true, nil
}

func buildGuestRulesStageScript(srcMount, stageRoot string) string {
	qSrc := msb.ShellQuote(srcMount)
	qStage := msb.ShellQuote(stageRoot)
	return fmt.Sprintf(`set -eu
src=%s
stage=%s
rm -rf "$stage"
mkdir -p "$stage/rules"
chmod 0755 "$stage" "$stage/rules"

process_rule() {
  f="$1"
  if [ -L "$f" ]; then
    echo "agbox rejects symlinked rule $f" >&2
    exit 1
  fi
  [ -f "$f" ] || return 0
  first_line=$(sed -n '1p' "$f" | tr -d '\r')
  has_close=$(awk '{sub(/\r$/, "")} NR>1 && $0=="---"{found=1; exit} END{print found+0}' "$f")
  if [ "$first_line" = "---" ] && [ "$has_close" = "1" ]; then
    fm=$(awk '{sub(/\r$/, "")} NR==1{next} $0=="---"{exit} {print}' "$f")
    if printf '%%s\n' "$fm" | grep -Eq '^[[:space:]]*trigger:[[:space:]]*(glob|model_decision|manual|"(glob|model_decision|manual)"|'\''(glob|model_decision|manual)'\'')([[:space:]]|$)'; then
      cp "$f" "$stage/rules/$(basename "$f")"
      chmod 0444 "$stage/rules/$(basename "$f")"
      return 0
    fi
    body=$(awk 'NR==1{in_fm=1; next} in_fm{line=$0; sub(/\r$/, "", line); if(line=="---"){in_fm=0; next}} !in_fm{print}' "$f")
    if [ -s "$stage/AGENTS.md" ]; then
      printf '\n\n' >> "$stage/AGENTS.md"
    fi
    printf '%%s\n' "$body" >> "$stage/AGENTS.md"
    return 0
  fi
  if [ -s "$stage/AGENTS.md" ]; then
    printf '\n\n' >> "$stage/AGENTS.md"
  fi
  cat "$f" >> "$stage/AGENTS.md"
}

for prio in AGENTS.md GEMINI.md; do
  if [ -e "$src/$prio" ] || [ -L "$src/$prio" ]; then
    process_rule "$src/$prio"
  fi
done
for f in "$src"/*.md; do
  [ -e "$f" ] || [ -L "$f" ] || continue
  b=$(basename "$f")
  if [ "$b" = "AGENTS.md" ] || [ "$b" = "GEMINI.md" ]; then
    continue
  fi
  process_rule "$f"
done
`, qSrc, qStage)
}

// BuildGuestRulesMountScript returns a root sh script that stages /home/agent/.agbox-rules
// and bind-mounts read-only global rules for agy and opencode.
func BuildGuestRulesMountScript() string {
	return BuildGuestRulesMountScriptWithOptions(true, false)
}

// BuildGuestRulesMountScriptWithOptions stages global rules and optional remote instructions
// into /etc/agbox-global-rules and bind-mounts them read-only for agy and opencode.
func BuildGuestRulesMountScriptWithOptions(hasRulesMount, includeRemote bool) string {
	var stagePart string
	if hasRulesMount {
		stagePart = buildGuestRulesStageScript(msb.GuestRulesMount, "/etc/agbox-global-rules")
	} else {
		stagePart = `rm -rf /etc/agbox-global-rules
mkdir -p /etc/agbox-global-rules/rules
chmod 0755 /etc/agbox-global-rules /etc/agbox-global-rules/rules
`
	}
	var remotePart string
	if includeRemote {
		remotePart = `if [ -f /home/agent/.agbox-remote/INSTRUCTIONS.md ] && [ ! -L /home/agent/.agbox-remote/INSTRUCTIONS.md ]; then
  if [ -s /etc/agbox-global-rules/AGENTS.md ]; then
    printf '\n\n' >> /etc/agbox-global-rules/AGENTS.md
  fi
  cat /home/agent/.agbox-remote/INSTRUCTIONS.md >> /etc/agbox-global-rules/AGENTS.md
fi
`
	}
	return `set -eu
mkdir -p /home/agent/.gemini/config /home/agent/.config/opencode
chown 1000:1000 /home/agent/.gemini /home/agent/.gemini/config /home/agent/.config /home/agent/.config/opencode
chmod 0700 /home/agent/.gemini /home/agent/.gemini/config /home/agent/.config /home/agent/.config/opencode

for mp in /home/agent/.gemini/config/AGENTS.md /home/agent/.config/opencode/AGENTS.md /home/agent/.gemini/config/rules; do
  if grep -Fqs " $mp " /proc/self/mountinfo; then
    umount "$mp" 2>/dev/null || umount -l "$mp" 2>/dev/null || true
  fi
done
` + stagePart + remotePart + `if [ -f /etc/agbox-global-rules/AGENTS.md ]; then
  chmod 0444 /etc/agbox-global-rules/AGENTS.md
fi
if [ -s /etc/agbox-global-rules/AGENTS.md ]; then
  for dst in /home/agent/.gemini/config/AGENTS.md /home/agent/.config/opencode/AGENTS.md; do
    rm -rf "$dst"
    : > "$dst"
    chown 1000:1000 "$dst"
    chmod 0644 "$dst"
    mount --bind /etc/agbox-global-rules/AGENTS.md "$dst"
    mount -o remount,ro,bind "$dst"
  done
else
  for dst in /home/agent/.gemini/config/AGENTS.md /home/agent/.config/opencode/AGENTS.md; do
    if [ -f "$dst" ] && [ ! -L "$dst" ] && [ ! -s "$dst" ]; then
      rm -f "$dst"
    fi
  done
fi
if [ -n "$(ls -A /etc/agbox-global-rules/rules 2>/dev/null)" ]; then
  mkdir -p /home/agent/.gemini/config/rules
  chown 1000:1000 /home/agent/.gemini/config/rules
  chmod 0755 /home/agent/.gemini/config/rules
  mount --bind /etc/agbox-global-rules/rules /home/agent/.gemini/config/rules
  mount -o remount,ro,bind /home/agent/.gemini/config/rules
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

// ProfileMeta records metadata for a conversation profile in $DATA_DIR/profiles/<name>/profile.json.
type ProfileMeta struct {
	Name      string `json:"name"`
	Volume    string `json:"volume"`
	Size      string `json:"size"`
	CreatedAt string `json:"created_at"`
}

// ProfileLock holds an exclusive flock on $DATA_DIR/profiles/.<name>.lock.
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

// LockProfile acquires a non-blocking exclusive lock for profile rawName.
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
	lockPath := filepath.Join(profilesRoot, "."+name+".lock")
	if info, sErr := os.Lstat(lockPath); sErr == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("refusing symlinked profile lock %s", lockPath)
		}
		if !info.Mode().IsRegular() {
			return nil, fmt.Errorf("refusing non-regular profile lock %s", lockPath)
		}
	}
	fd, err := syscall.Open(lockPath, syscall.O_CREAT|syscall.O_RDWR|syscall.O_NOFOLLOW|syscall.O_CLOEXEC|syscall.O_NONBLOCK, 0o600)
	if err != nil {
		if errors.Is(err, syscall.ELOOP) {
			return nil, fmt.Errorf("refusing symlinked profile lock %s", lockPath)
		}
		return nil, fmt.Errorf("open profile lock %s: %w", lockPath, err)
	}
	f := os.NewFile(uintptr(fd), lockPath)
	st, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("stat profile lock %s: %w", lockPath, err)
	}
	if !st.Mode().IsRegular() {
		_ = f.Close()
		return nil, fmt.Errorf("refusing non-regular profile lock %s", lockPath)
	}
	if err := syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return nil, fmt.Errorf("another active agbox process holds the lock on profile %q", name)
		}
		return nil, fmt.Errorf("lock profile %q: %w", name, err)
	}
	return &ProfileLock{file: f}, nil
}

// SaveProfileMeta writes profile.json atomically at mode 0600.
func SaveProfileMeta(dataDir string, meta ProfileMeta) error {
	return saveProfileMetaAt(dataDir, meta, time.Now)
}

func saveProfileMetaAt(dataDir string, meta ProfileMeta, now func() time.Time) error {
	name, err := ValidateProfileName(meta.Name)
	if err != nil {
		return err
	}
	if meta.Volume == "" {
		meta.Volume = FormatProfileVolumeName(name)
	}
	if meta.CreatedAt == "" {
		if now == nil {
			now = time.Now
		}
		meta.CreatedAt = now().UTC().Format(time.RFC3339)
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
	if err := verifyOptionalDir(dataDir); err != nil {
		return nil, err
	}
	profilesRoot := filepath.Join(dataDir, "profiles")
	if err := verifyOptionalDir(profilesRoot); err != nil {
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
		entryName := entry.Name()
		if strings.HasPrefix(entryName, ".") {
			continue
		}
		fullDir := filepath.Join(profilesRoot, entryName)
		info, lErr := os.Lstat(fullDir)
		if lErr != nil {
			return nil, lErr
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("refusing symlinked profile directory %s", fullDir)
		}
		if !info.IsDir() {
			continue
		}
		name, vErr := ValidateProfileName(entryName)
		if vErr != nil {
			continue
		}
		metaPath := filepath.Join(fullDir, "profile.json")
		raw, exists, rErr := readSafeRegularFile(metaPath, maxProfileMetaBytes)
		if rErr != nil {
			return nil, rErr
		}
		if !exists {
			continue
		}
		var pm ProfileMeta
		if err := json.Unmarshal(raw, &pm); err != nil {
			return nil, fmt.Errorf("parse profile metadata %s: %w", metaPath, err)
		}
		if pm.Name != name {
			return nil, fmt.Errorf("profile metadata name mismatch in %s: got %q, want %q", metaPath, pm.Name, name)
		}
		out = append(out, pm)
	}
	slices.SortFunc(out, func(a, b ProfileMeta) int {
		return strings.Compare(a.Name, b.Name)
	})
	return out, nil
}

// RemoveProfileDir deletes $DATA_DIR/profiles/<name>.
// The caller must hold ProfileLock across RemoveProfileDir and unlock afterward.
func RemoveProfileDir(dataDir, rawName string) error {
	name, err := ValidateProfileName(rawName)
	if err != nil {
		return err
	}
	if err := verifyOptionalDir(dataDir); err != nil {
		return err
	}
	profilesRoot := filepath.Join(dataDir, "profiles")
	if err := verifyOptionalDir(profilesRoot); err != nil {
		return err
	}
	profDir := filepath.Join(profilesRoot, name)
	if err := verifyOptionalDir(profDir); err != nil {
		return err
	}
	return os.RemoveAll(profDir)
}

// BuildGuestProfileMountScript returns a root sh script that initializes
// /home/agent/.agbox-profile on ext4 and bind-mounts conversation directories.
func BuildGuestProfileMountScript() string {
	return `set -eu
if ! grep -Fqs ' /home/agent/.agbox-profile ' /proc/self/mountinfo; then
  echo "agbox cannot find the profile disk at /home/agent/.agbox-profile" >&2
  exit 1
fi
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

if ! grep -Fqs ' /home/agent/.gemini/antigravity-cli ' /proc/self/mountinfo; then
  for sub in bin builtin updater; do
    if [ -d "/home/agent/.gemini/antigravity-cli/${sub}" ]; then
      rm -rf "/home/agent/.agbox-profile/agy-cli/${sub}"
      cp -a "/home/agent/.gemini/antigravity-cli/${sub}" "/home/agent/.agbox-profile/agy-cli/${sub}"
      chown -R 1000:1000 "/home/agent/.agbox-profile/agy-cli/${sub}"
    fi
  done
  if [ -f "/home/agent/.gemini/antigravity-cli/settings.json" ] && [ ! -e "/home/agent/.agbox-profile/agy-cli/settings.json" ]; then
    install -m 0600 -o 1000 -g 1000 "/home/agent/.gemini/antigravity-cli/settings.json" "/home/agent/.agbox-profile/agy-cli/settings.json"
  fi
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

if ! grep -Fqs ' /home/agent/.gemini/antigravity-cli ' /proc/self/mountinfo; then
  mount --bind /home/agent/.agbox-profile/agy-cli /home/agent/.gemini/antigravity-cli
fi
if ! grep -Fqs ' /home/agent/.gemini/config/projects ' /proc/self/mountinfo; then
  mount --bind /home/agent/.agbox-profile/agy-projects /home/agent/.gemini/config/projects
fi
if ! grep -Fqs ' /home/agent/.local/share/opencode ' /proc/self/mountinfo; then
  mount --bind /home/agent/.agbox-profile/opencode-data /home/agent/.local/share/opencode
fi
if ! grep -Fqs ' /home/agent/.local/state/opencode ' /proc/self/mountinfo; then
  mount --bind /home/agent/.agbox-profile/opencode-state /home/agent/.local/state/opencode
fi
sync
`
}

// ValidateSessionID checks a conversation or session ID passed to --session or --conversation.
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
				return "", fmt.Errorf("invalid session ID %q: must start with an ASCII letter or digit", raw)
			}
			continue
		}
		if !isAlnum && r != '.' && r != '_' && r != ':' && r != '-' {
			return "", fmt.Errorf("invalid session ID %q: use only ASCII letters, digits, '.', '_', ':', or '-'", raw)
		}
	}
	return raw, nil
}

func verifyOptionalDir(dir string) error {
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

func readRegularNoFollow(path string, maxBytes int64) ([]byte, error) {
	data, _, err := readRegularNoFollowWithStat(path, maxBytes)
	return data, err
}

func readRegularNoFollowWithStat(path string, maxBytes int64) ([]byte, os.FileInfo, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC|syscall.O_NONBLOCK, 0)
	if err != nil {
		if errors.Is(err, syscall.ELOOP) {
			return nil, nil, fmt.Errorf("refusing symlinked file %q", path)
		}
		if info, lErr := os.Lstat(path); lErr == nil && info.Mode()&os.ModeSymlink != 0 {
			return nil, nil, fmt.Errorf("refusing symlinked file %q", path)
		}
		return nil, nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()

	st, err := f.Stat()
	if err != nil {
		return nil, nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, nil, fmt.Errorf("refusing non-regular file %q", path)
	}
	if st.Size() > maxBytes {
		return nil, nil, fmt.Errorf("%s exceeds %d bytes", path, maxBytes)
	}
	data, err := io.ReadAll(io.LimitReader(f, maxBytes+1))
	if err != nil {
		return nil, nil, err
	}
	if int64(len(data)) > maxBytes {
		return nil, nil, fmt.Errorf("%s exceeds %d bytes", path, maxBytes)
	}
	return data, st, nil
}

func readSafeRegularFile(path string, maxBytes int64) ([]byte, bool, error) {
	raw, err := readRegularNoFollow(path, maxBytes)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, false, nil
		}
		return nil, false, err
	}
	return raw, true, nil
}

func writePrivateFileAtomic(path string, content []byte) error {
	return writeModeFileAtomic(path, content, 0o600)
}

func writeModeFileAtomic(path string, content []byte, mode fs.FileMode) error {
	dir := filepath.Dir(path)
	if err := config.EnsurePrivateDir(dir); err != nil {
		return err
	}
	stageParent := filepath.Dir(dir)
	if err := config.EnsurePrivateDir(stageParent); err != nil {
		return err
	}
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("refusing symlinked destination %q", path)
		}
		if info.IsDir() {
			return fmt.Errorf("refusing directory destination %q", path)
		}
	} else if !os.IsNotExist(err) {
		return err
	}

	stageDir, err := os.MkdirTemp(stageParent, ".agbox-stage-*")
	if err != nil {
		return fmt.Errorf("create staging directory: %w", err)
	}
	defer func() {
		_ = os.RemoveAll(stageDir)
	}()

	tmp, err := os.CreateTemp(stageDir, ".tmp.*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	if err := tmp.Chmod(mode); err != nil {
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
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("commit file %s: %w", path, err)
	}
	return syncParentDir(dir)
}

func syncParentDir(dir string) error {
	dirFD, err := syscall.Open(dir, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("open parent directory %q for sync: %w", dir, err)
	}
	defer syscall.Close(dirFD)
	if err := syscall.Fsync(dirFD); err != nil && !errors.Is(err, syscall.EINVAL) {
		return fmt.Errorf("sync parent directory %q: %w", dir, err)
	}
	return nil
}
