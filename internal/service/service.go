// Package service manages agbox systemd user service definitions and units.
//
// Security properties:
//   - ValidateName accepts only sandbox-safe ASCII names and rejects reserved names.
//   - LoadSpec and SaveSpec reject symlinks with O_NOFOLLOW and write specs at mode 0600.
//   - ValidateEnvFile and ParseEnvFile require regular files at mode 0600 or stricter with zero symlinks.
//   - RenderTemplateUnit never embeds secrets and sets KillMode=mixed so the supervisor stops the microVM before FUSE teardown.
//   - InstallTemplateUnit rejects symlinked unit directories and files and writes agbox@.service atomically.
package service

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"

	"agbox/internal/config"
)

const (
	// SubcommandName is the hidden CLI entrypoint that runs a supervised service in the foreground.
	SubcommandName = "__service-run"

	// TemplateUnitName is the shared systemd user template unit for all agbox services.
	TemplateUnitName = "agbox@.service"

	maxSpecFileBytes = 256 * 1024
	maxEnvFileBytes  = 64 * 1024
)

// Spec stores the validated configuration for one managed agbox service.
type Spec struct {
	Name         string           `json:"name"`
	Agent        string           `json:"agent,omitempty"`
	Mode         config.RunMode   `json:"mode"`
	Port         int              `json:"port,omitempty"`
	Cmd          string           `json:"cmd,omitempty"`
	Persist      bool             `json:"persist,omitempty"`
	Profile      string           `json:"profile,omitempty"`
	ShareHub     bool             `json:"share_hub,omitempty"`
	ReadOnly     bool             `json:"read_only,omitempty"`
	LockAccess   bool             `json:"lock_access,omitempty"`
	DefaultVCS   config.VCSPolicy `json:"default_vcs,omitempty"`
	LockVCS      bool             `json:"lock_vcs,omitempty"`
	MaskMode     config.MaskMode  `json:"mask_mode,omitempty"`
	Shares       []string         `json:"shares,omitempty"`
	NoNet        bool             `json:"no_net,omitempty"`
	NetSpecs     []string         `json:"net_specs,omitempty"`
	CPUs         string           `json:"cpus,omitempty"`
	Memory       string           `json:"memory,omitempty"`
	NoAuth       bool             `json:"no_auth,omitempty"`
	NoSkills     bool             `json:"no_skills,omitempty"`
	NoRules      bool             `json:"no_rules,omitempty"`
	NoAgentCache bool             `json:"no_agent_cache,omitempty"`
	EnvFile      string           `json:"env_file,omitempty"`
}

// TemplateUnitOpts configures the generated agbox@.service unit text.
type TemplateUnitOpts struct {
	ExePath          string
	DataDir          string
	MSBHome          string
	PathEnv          string
	AllowOutsideHome bool
}

// UnitState describes the live systemd state of one agbox@<name>.service instance.
type UnitState struct {
	ActiveState string
	SubState    string
	UnitFile    string
}

// Controller abstracts systemd user manager and loginctl commands for testability.
type Controller interface {
	DaemonReload(ctx context.Context) error
	Enable(ctx context.Context, unit string, now bool) error
	Disable(ctx context.Context, unit string, now bool) error
	Start(ctx context.Context, unit string) error
	Stop(ctx context.Context, unit string) error
	Restart(ctx context.Context, unit string) error
	Status(ctx context.Context, unit string) (UnitState, error)
	Logs(ctx context.Context, unit string, follow bool, lines int, stdout, stderr io.Writer) error
	LingerEnabled(ctx context.Context, username string) (bool, error)
	EnableLinger(ctx context.Context, username string) error
}

// OSController runs real systemctl, journalctl, and loginctl commands.
type OSController struct{}

// UnitName returns the systemd instance unit name for a validated service name.
func UnitName(name string) string {
	return "agbox@" + name + ".service"
}

// ValidateName checks that raw is a valid service name matching agbox sandbox naming rules.
func ValidateName(raw string) (string, error) {
	if raw == "" {
		return "", errors.New("service name must not be empty")
	}
	if len(raw) > 63 {
		return "", errors.New("service name must be 63 characters or fewer")
	}
	if raw == "base" {
		return "", errors.New("service name \"base\" is reserved for agbox-base")
	}
	if strings.HasPrefix(raw, "run-") && isDigits(strings.TrimPrefix(raw, "run-")) {
		return "", fmt.Errorf("invalid service name %q: names matching run-<digits> are reserved", raw)
	}
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		isAlphaNum := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
		if i == 0 {
			if !isAlphaNum {
				return "", fmt.Errorf("invalid service name %q: must start with an ASCII letter or digit", raw)
			}
			continue
		}
		if !isAlphaNum && c != '-' && c != '_' {
			return "", fmt.Errorf("invalid service name %q: use only ASCII letters, digits, '-' or '_'", raw)
		}
	}
	return raw, nil
}

// ServicesDir returns the private directory that stores service spec JSON files.
func ServicesDir(dataDir string) string {
	return filepath.Join(dataDir, "services")
}

// SpecPath returns the JSON spec file path for one service name.
func SpecPath(dataDir, name string) string {
	return filepath.Join(ServicesDir(dataDir), name+".json")
}

// SaveSpec writes a service Spec atomically at mode 0600 inside $DATA_DIR/services.
func SaveSpec(dataDir string, spec Spec) error {
	if _, err := ValidateName(spec.Name); err != nil {
		return err
	}
	if err := config.EnsurePrivateDir(dataDir); err != nil {
		return err
	}
	dir := ServicesDir(dataDir)
	if err := config.EnsurePrivateDir(dir); err != nil {
		return err
	}
	data, err := json.MarshalIndent(spec, "", "  ")
	if err != nil {
		return fmt.Errorf("encode service spec %q: %w", spec.Name, err)
	}
	data = append(data, '\n')
	return writeFileAtomicNoFollow(SpecPath(dataDir, spec.Name), data, 0o600)
}

// LoadSpec reads and validates a service Spec without following symlinks.
func LoadSpec(dataDir, name string) (Spec, error) {
	if _, err := ValidateName(name); err != nil {
		return Spec{}, err
	}
	raw, err := readRegularNoFollow(SpecPath(dataDir, name), maxSpecFileBytes)
	if err != nil {
		return Spec{}, err
	}
	var spec Spec
	if err := json.Unmarshal(raw, &spec); err != nil {
		return Spec{}, fmt.Errorf("parse service spec %q: %w", name, err)
	}
	if spec.Name != name {
		return Spec{}, fmt.Errorf("service spec name mismatch: got %q, want %q", spec.Name, name)
	}
	return spec, nil
}

// DeleteSpec deletes a saved service Spec without following symlinks.
func DeleteSpec(dataDir, name string) error {
	if _, err := ValidateName(name); err != nil {
		return err
	}
	p := SpecPath(dataDir, name)
	info, err := os.Lstat(p)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return fmt.Errorf("refusing to delete non-regular service spec %q", p)
	}
	return os.Remove(p)
}

// ListSpecs loads all saved service specs sorted by name.
func ListSpecs(dataDir string) ([]Spec, error) {
	dir := ServicesDir(dataDir)
	info, err := os.Lstat(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return nil, fmt.Errorf("refusing non-directory services path %q", dir)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var names []string
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasSuffix(name, ".json") {
			continue
		}
		svcName := strings.TrimSuffix(name, ".json")
		if _, vErr := ValidateName(svcName); vErr != nil {
			continue
		}
		names = append(names, svcName)
	}
	slices.Sort(names)
	specs := make([]Spec, 0, len(names))
	for _, name := range names {
		spec, lErr := LoadSpec(dataDir, name)
		if lErr != nil {
			return nil, lErr
		}
		specs = append(specs, spec)
	}
	return specs, nil
}

// ValidateEnvFile checks that rawPath is a regular mode-0600 (or stricter) env file with valid syntax.
// It returns the cleaned absolute path.
func ValidateEnvFile(rawPath string) (string, error) {
	if strings.TrimSpace(rawPath) == "" {
		return "", errors.New("env file path must not be empty")
	}
	if hasControlChars(rawPath) {
		return "", errors.New("env file path must not contain control characters")
	}
	absPath, err := filepath.Abs(rawPath)
	if err != nil {
		return "", fmt.Errorf("resolve env file path %q: %w", rawPath, err)
	}
	cleanPath := filepath.Clean(absPath)
	if _, err := ParseEnvFile(cleanPath); err != nil {
		return "", err
	}
	return cleanPath, nil
}

// ParseEnvFile reads a private env file without following symlinks and enforces mode 0600 or stricter.
func ParseEnvFile(path string) (map[string]string, error) {
	if !filepath.IsAbs(path) {
		return nil, fmt.Errorf("env file path %q must be absolute", path)
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		if errors.Is(err, syscall.ELOOP) {
			return nil, fmt.Errorf("refusing symlinked env file %q", path)
		}
		return nil, fmt.Errorf("open env file %q: %w", path, err)
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat env file %q: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("env file %q must be a regular file", path)
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		return nil, fmt.Errorf("env file %q has insecure permissions %04o (run 'chmod 600 %s')", path, perm, path)
	}
	if info.Size() > maxEnvFileBytes {
		return nil, fmt.Errorf("env file %q exceeds %d bytes", path, maxEnvFileBytes)
	}

	raw, err := io.ReadAll(io.LimitReader(f, maxEnvFileBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read env file %q: %w", path, err)
	}
	if len(raw) > maxEnvFileBytes {
		return nil, fmt.Errorf("env file %q exceeds %d bytes", path, maxEnvFileBytes)
	}
	if bytes.IndexByte(raw, 0) >= 0 {
		return nil, fmt.Errorf("env file %q contains a NUL byte", path)
	}

	values := make(map[string]string)
	sc := bufio.NewScanner(bytes.NewReader(raw))
	lineNum := 0
	for sc.Scan() {
		lineNum++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			return nil, fmt.Errorf("env file %q line %d: expected KEY=VALUE", path, lineNum)
		}
		key = strings.TrimSpace(key)
		if !isValidEnvKey(key) {
			return nil, fmt.Errorf("env file %q line %d: invalid variable name %q", path, lineNum, key)
		}
		parsedVal, err := unquoteEnvValue(strings.TrimSpace(val))
		if err != nil {
			return nil, fmt.Errorf("env file %q line %d: %w", path, lineNum, err)
		}
		values[key] = parsedVal
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("scan env file %q: %w", path, err)
	}
	return values, nil
}

// UserUnitDir returns the systemd user unit directory for the current user.
func UserUnitDir(homeReal, xdgConfigHome string) (string, error) {
	xdg := strings.TrimSpace(xdgConfigHome)
	if xdg != "" {
		if !filepath.IsAbs(xdg) {
			return "", fmt.Errorf("invalid XDG_CONFIG_HOME %q: must be an absolute path", xdg)
		}
		return filepath.Join(filepath.Clean(xdg), "systemd", "user"), nil
	}
	if homeReal == "" || !filepath.IsAbs(homeReal) {
		return "", errors.New("home directory must be an absolute path")
	}
	return filepath.Join(filepath.Clean(homeReal), ".config", "systemd", "user"), nil
}

// TemplateUnitPath returns the absolute path to agbox@.service for the current user.
func TemplateUnitPath(homeReal, xdgConfigHome string) (string, error) {
	dir, err := UserUnitDir(homeReal, xdgConfigHome)
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, TemplateUnitName), nil
}

// RenderTemplateUnit builds the systemd user template unit content for agbox@.service.
func RenderTemplateUnit(opts TemplateUnitOpts) (string, error) {
	if opts.ExePath == "" || !filepath.IsAbs(opts.ExePath) {
		return "", fmt.Errorf("invalid agbox binary path %q: must be absolute", opts.ExePath)
	}
	if hasControlChars(opts.ExePath) {
		return "", errors.New("agbox binary path must not contain control characters")
	}
	if opts.DataDir == "" || !filepath.IsAbs(opts.DataDir) || hasControlChars(opts.DataDir) {
		return "", fmt.Errorf("invalid DATA_DIR %q for systemd unit", opts.DataDir)
	}
	if opts.MSBHome == "" || !filepath.IsAbs(opts.MSBHome) || hasControlChars(opts.MSBHome) {
		return "", fmt.Errorf("invalid MSB_HOME %q for systemd unit", opts.MSBHome)
	}
	if hasControlChars(opts.PathEnv) {
		return "", errors.New("PATH must not contain control characters")
	}

	var b strings.Builder
	b.WriteString("# Managed by agbox. Run 'agbox service --help' for usage.\n")
	b.WriteString("[Unit]\n")
	b.WriteString("Description=agbox microVM sandbox (%i)\n")
	b.WriteString("After=network-online.target\n")
	b.WriteString("StartLimitIntervalSec=120\n")
	b.WriteString("StartLimitBurst=5\n")
	b.WriteString("\n")
	b.WriteString("[Service]\n")
	b.WriteString("Type=simple\n")
	fmt.Fprintf(&b, "ExecStart=%s %s %%i\n", FormatSystemdQuote(opts.ExePath), SubcommandName)
	if opts.PathEnv != "" {
		fmt.Fprintf(&b, "Environment=%s\n", FormatSystemdQuote("PATH="+opts.PathEnv))
	}
	fmt.Fprintf(&b, "Environment=%s\n", FormatSystemdQuote("AGBOX_DATA_DIR="+opts.DataDir))
	fmt.Fprintf(&b, "Environment=%s\n", FormatSystemdQuote("MSB_HOME="+opts.MSBHome))
	if opts.AllowOutsideHome {
		b.WriteString("Environment=\"AGBOX_ALLOW_OUTSIDE_HOME=1\"\n")
	}
	b.WriteString("Restart=on-failure\n")
	b.WriteString("RestartSec=5s\n")
	b.WriteString("KillMode=mixed\n")
	b.WriteString("TimeoutStopSec=30\n")
	b.WriteString("\n")
	b.WriteString("[Install]\n")
	b.WriteString("WantedBy=default.target\n")
	return b.String(), nil
}

// FormatSystemdQuote wraps s in double quotes and escapes backslashes, quotes, and percent signs.
func FormatSystemdQuote(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\\', '"':
			b.WriteByte('\\')
			b.WriteByte(s[i])
		case '%':
			b.WriteString("%%")
		default:
			b.WriteByte(s[i])
		}
	}
	b.WriteByte('"')
	return b.String()
}

// InstallTemplateUnit writes agbox@.service atomically and rejects symlinked directories or targets.
func InstallTemplateUnit(unitPath, content string) error {
	unitDir := filepath.Dir(unitPath)
	if err := ensureUnitDirNoSymlink(unitDir); err != nil {
		return err
	}
	return writeFileAtomicNoFollow(unitPath, []byte(content), 0o644)
}

// RemoveTemplateUnit deletes agbox@.service if it exists and is a regular file.
func RemoveTemplateUnit(unitPath string) error {
	info, err := os.Lstat(unitPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return fmt.Errorf("refusing to delete non-regular unit file %q", unitPath)
	}
	return os.Remove(unitPath)
}

func ensureUnitDirNoSymlink(dir string) error {
	clean := filepath.Clean(dir)
	if !filepath.IsAbs(clean) {
		return fmt.Errorf("unit directory %q must be absolute", dir)
	}
	if err := os.MkdirAll(clean, 0o755); err != nil {
		return fmt.Errorf("create unit directory %s: %w", clean, err)
	}
	info, err := os.Lstat(clean)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("refusing symlinked or non-directory unit path %q", clean)
	}
	return nil
}

func readRegularNoFollow(path string, maxBytes int64) ([]byte, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		if errors.Is(err, syscall.ELOOP) {
			return nil, fmt.Errorf("refusing symlinked file %q", path)
		}
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("refusing non-regular file %q", path)
	}
	if info.Size() > maxBytes {
		return nil, fmt.Errorf("file %q exceeds %d bytes", path, maxBytes)
	}
	raw, err := io.ReadAll(io.LimitReader(f, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > maxBytes {
		return nil, fmt.Errorf("file %q exceeds %d bytes", path, maxBytes)
	}
	return raw, nil
}

func writeFileAtomicNoFollow(path string, data []byte, mode os.FileMode) error {
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return fmt.Errorf("refusing non-regular target file %q", path)
		}
	} else if !os.IsNotExist(err) {
		return err
	}

	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".agbox-svc-*")
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
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
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

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

func hasControlChars(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] == 0x7f {
			return true
		}
	}
	return false
}

func isValidEnvKey(k string) bool {
	if k == "" {
		return false
	}
	for i := 0; i < len(k); i++ {
		c := k[i]
		isLetter := (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || c == '_'
		isDigit := c >= '0' && c <= '9'
		if i == 0 {
			if !isLetter {
				return false
			}
			continue
		}
		if !isLetter && !isDigit {
			return false
		}
	}
	return true
}

func unquoteEnvValue(raw string) (string, error) {
	if len(raw) >= 2 && raw[0] == '\'' && raw[len(raw)-1] == '\'' {
		return raw[1 : len(raw)-1], nil
	}
	if len(raw) >= 2 && raw[0] == '"' && raw[len(raw)-1] == '"' {
		unq, err := strconv.Unquote(raw)
		if err != nil {
			return "", fmt.Errorf("invalid double-quoted value: %w", err)
		}
		return unq, nil
	}
	if (strings.HasPrefix(raw, "'") && !strings.HasSuffix(raw, "'")) ||
		(strings.HasPrefix(raw, "\"") && !strings.HasSuffix(raw, "\"")) {
		return "", errors.New("unterminated quote")
	}
	return raw, nil
}

// DaemonReload reloads the systemd user manager configuration.
func (OSController) DaemonReload(ctx context.Context) error {
	return runSystemctl(ctx, "--user", "daemon-reload")
}

// Enable enables a systemd user unit and optionally starts it immediately.
func (OSController) Enable(ctx context.Context, unit string, now bool) error {
	args := []string{"--user", "enable"}
	if now {
		args = append(args, "--now")
	}
	args = append(args, unit)
	return runSystemctl(ctx, args...)
}

// Disable disables a systemd user unit and optionally stops it immediately.
func (OSController) Disable(ctx context.Context, unit string, now bool) error {
	args := []string{"--user", "disable"}
	if now {
		args = append(args, "--now")
	}
	args = append(args, unit)
	return runSystemctl(ctx, args...)
}

// Start starts a systemd user unit.
func (OSController) Start(ctx context.Context, unit string) error {
	return runSystemctl(ctx, "--user", "start", unit)
}

// Stop stops a systemd user unit.
func (OSController) Stop(ctx context.Context, unit string) error {
	return runSystemctl(ctx, "--user", "stop", unit)
}

// Restart restarts a systemd user unit.
func (OSController) Restart(ctx context.Context, unit string) error {
	return runSystemctl(ctx, "--user", "restart", unit)
}

// Status reads the active state, sub-state, and unit-file state of a user unit.
func (OSController) Status(ctx context.Context, unit string) (UnitState, error) {
	cmd := exec.CommandContext(ctx, "systemctl", "--user", "show",
		"--property=ActiveState,SubState,UnitFileState",
		unit,
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg != "" {
			return UnitState{}, fmt.Errorf("systemctl --user show %s: %w (%s)", unit, err, msg)
		}
		return UnitState{}, fmt.Errorf("systemctl --user show %s: %w", unit, err)
	}
	var st UnitState
	for _, line := range strings.Split(string(out), "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok {
			continue
		}
		switch k {
		case "ActiveState":
			st.ActiveState = v
		case "SubState":
			st.SubState = v
		case "UnitFileState":
			st.UnitFile = v
		}
	}
	return st, nil
}

// Logs streams systemd user journal logs for a unit.
func (OSController) Logs(ctx context.Context, unit string, follow bool, lines int, stdout, stderr io.Writer) error {
	args := []string{"--user", "-u", unit, "--no-pager"}
	if lines > 0 {
		args = append(args, "-n", strconv.Itoa(lines))
	}
	if follow {
		args = append(args, "-f")
	}
	cmd := exec.CommandContext(ctx, "journalctl", args...)
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("journalctl %s: %w", unit, err)
	}
	return nil
}

// LingerEnabled reports whether systemd-logind linger is active for username.
func (OSController) LingerEnabled(ctx context.Context, username string) (bool, error) {
	if username == "" {
		return false, errors.New("username must not be empty")
	}
	cmd := exec.CommandContext(ctx, "loginctl", "show-user", username, "-p", "Linger", "--value")
	out, err := cmd.CombinedOutput()
	if err == nil {
		val := strings.ToLower(strings.TrimSpace(string(out)))
		if val == "yes" {
			return true, nil
		}
		if val == "no" {
			return false, nil
		}
	}
	if _, statErr := os.Stat(filepath.Join("/var/lib/systemd/linger", username)); statErr == nil {
		return true, nil
	} else if os.IsNotExist(statErr) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("check linger for %s: %w (%s)", username, err, strings.TrimSpace(string(out)))
	}
	return false, nil
}

// EnableLinger activates systemd-logind linger for username.
func (OSController) EnableLinger(ctx context.Context, username string) error {
	if username == "" {
		return errors.New("username must not be empty")
	}
	cmd := exec.CommandContext(ctx, "loginctl", "enable-linger", username)
	out, err := cmd.CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg != "" {
			return fmt.Errorf("loginctl enable-linger %s: %w (%s)", username, err, msg)
		}
		return fmt.Errorf("loginctl enable-linger %s: %w", username, err)
	}
	return nil
}

func runSystemctl(ctx context.Context, args ...string) error {
	cmd := exec.CommandContext(ctx, "systemctl", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg != "" {
			return fmt.Errorf("systemctl %s: %w (%s)", strings.Join(args, " "), err, msg)
		}
		return fmt.Errorf("systemctl %s: %w", strings.Join(args, " "), err)
	}
	return nil
}
