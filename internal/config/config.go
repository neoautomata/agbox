// Package config manages environment settings and metadata files for agbox.
//
// Security properties:
//   - ParseMaskMode defaults empty AGBOX_MASK_VCS values to MaskStrict.
//   - FromLookup validates CPU counts, memory and disk sizes, package versions,
//     and HTTPS installer URLs before any command runs.
//   - EnsurePrivateDir rejects symlinks via Lstat and enforces mode 0700.
//   - SaveFile and SaveRunMeta write state files atomically with mode 0600.
package config

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const (
	BaseSandbox   = "agbox-base"
	SnapGroup     = "agbox"
	RunPrefix     = "agbox-run"
	GuestPort     = 3000
	GuestUser     = "agent"
	GuestUID      = 1000
	GuestGID      = 1000
	GuestHome     = "/home/agent"
	GuestKeysFile = "/home/agent/.agbox-keys.sh"

	DefaultCPUs            = "4"
	DefaultMemory          = "8G"
	DefaultRootDisk        = "50G"
	DefaultProfileDisk     = "10G"
	DefaultOpenCodeVersion = "latest"
	DefaultAgyInstallerURL = "https://antigravity.google/cli/install.sh"
)

// MaskMode controls whether directory shares are routed through the FUSE VCS filter.
type MaskMode string

const (
	MaskAuto   MaskMode = "auto"
	MaskStrict MaskMode = "strict"
	MaskOff    MaskMode = "off"
)

// ParseMaskMode converts a string (from AGBOX_MASK_VCS or CLI flags) into a
// validated MaskMode. Empty input defaults to MaskStrict.
func ParseMaskMode(raw string) (MaskMode, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", "strict", "1", "true", "yes":
		return MaskStrict, nil
	case "auto":
		return MaskAuto, nil
	case "off", "0", "false", "no":
		return MaskOff, nil
	default:
		return "", fmt.Errorf("invalid mask mode %q (expected: strict, auto, or off)", raw)
	}
}

// Env holds runtime configuration derived from the host environment.
type Env struct {
	HomeReal         string
	DataDir          string
	ConfigFile       string
	MSBHome          string
	CPUs             string
	Memory           string
	RootDisk         string
	ProfileDisk      string
	OpenCodeVersion  string
	AgyInstallerURL  string
	MaskVCS          MaskMode
	AllowOutsideHome bool
	AllowRoot        bool
}

// FromLookup constructs an Env using the provided environment lookup function
// and resolved home directory path.
func FromLookup(homeReal string, getenv func(string) string) (Env, error) {
	if homeReal == "" {
		return Env{}, fmt.Errorf("home directory path must not be empty")
	}
	cleanHome := filepath.Clean(homeReal)

	dataDir := strings.TrimSpace(getenv("AGBOX_DATA_DIR"))
	if dataDir == "" {
		dataDir = filepath.Join(cleanHome, ".local", "share", "agbox")
	} else {
		dataDir = filepath.Clean(dataDir)
	}
	if resolved, err := filepath.EvalSymlinks(dataDir); err == nil {
		dataDir = resolved
	}

	msbHome := strings.TrimSpace(getenv("MSB_HOME"))
	if msbHome == "" {
		msbHome = filepath.Join(cleanHome, ".microsandbox")
	} else {
		msbHome = filepath.Clean(msbHome)
	}

	maskMode, err := ParseMaskMode(getenv("AGBOX_MASK_VCS"))
	if err != nil {
		return Env{}, err
	}

	cpus := defaultIfEmpty(getenv("AGBOX_CPUS"), DefaultCPUs)
	if n, err := strconv.Atoi(cpus); err != nil || n < 1 {
		return Env{}, fmt.Errorf("invalid AGBOX_CPUS %q: must be a positive integer", cpus)
	}

	memory := defaultIfEmpty(getenv("AGBOX_MEMORY"), DefaultMemory)
	if !isValidSizeSpec(memory) {
		return Env{}, fmt.Errorf("invalid AGBOX_MEMORY %q: expected size such as 2G or 2048M", memory)
	}

	rootDisk := defaultIfEmpty(getenv("AGBOX_ROOT_DISK"), DefaultRootDisk)
	if !isValidSizeSpec(rootDisk) {
		return Env{}, fmt.Errorf("invalid AGBOX_ROOT_DISK %q: expected size such as 50G or 8192M", rootDisk)
	}

	profileDisk := defaultIfEmpty(getenv("AGBOX_PROFILE_DISK"), DefaultProfileDisk)
	if !isValidSizeSpec(profileDisk) {
		return Env{}, fmt.Errorf("invalid AGBOX_PROFILE_DISK %q: expected size such as 10G or 2048M", profileDisk)
	}

	openCodeVer := defaultIfEmpty(getenv("AGBOX_OPENCODE_VERSION"), DefaultOpenCodeVersion)
	if hasUnsafeTokenChars(openCodeVer) {
		return Env{}, fmt.Errorf("invalid AGBOX_OPENCODE_VERSION %q: whitespace and control characters are forbidden", openCodeVer)
	}

	agyURL := defaultIfEmpty(getenv("AGBOX_AGY_INSTALLER_URL"), DefaultAgyInstallerURL)
	if !strings.HasPrefix(agyURL, "https://") || hasUnsafeTokenChars(agyURL) {
		return Env{}, fmt.Errorf("invalid AGBOX_AGY_INSTALLER_URL %q: must be an https:// URL without whitespace", agyURL)
	}

	return Env{
		HomeReal:         cleanHome,
		DataDir:          dataDir,
		ConfigFile:       filepath.Join(dataDir, "config"),
		MSBHome:          msbHome,
		CPUs:             cpus,
		Memory:           memory,
		RootDisk:         rootDisk,
		ProfileDisk:      profileDisk,
		OpenCodeVersion:  openCodeVer,
		AgyInstallerURL:  agyURL,
		MaskVCS:          maskMode,
		AllowOutsideHome: strings.TrimSpace(getenv("AGBOX_ALLOW_OUTSIDE_HOME")) == "1",
		AllowRoot:        strings.TrimSpace(getenv("AGBOX_ALLOW_ROOT")) == "1",
	}, nil
}

// LoadEnv loads configuration from the current OS process environment.
func LoadEnv() (Env, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return Env{}, fmt.Errorf("determine $HOME: %w", err)
	}
	homeReal, err := filepath.EvalSymlinks(home)
	if err != nil {
		return Env{}, fmt.Errorf("resolve $HOME (%s): %w", home, err)
	}
	return FromLookup(homeReal, os.Getenv)
}

// State represents the persisted base-image configuration stored in DATA_DIR/config.
type State struct {
	Agent      string
	Image      string
	Snapshot   string
	SnapCount  int
	CPUs       string
	Memory     string
	RootDisk   string
	Categories string
}

// Parse reads a key=value config stream into a State struct.
func Parse(r io.Reader) (State, error) {
	var st State
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch strings.TrimSpace(k) {
		case "agent":
			st.Agent = v
		case "image":
			st.Image = v
		case "snapshot":
			st.Snapshot = v
		case "snap_count":
			if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil && n >= 0 {
				st.SnapCount = n
			}
		case "cpus":
			st.CPUs = v
		case "memory":
			st.Memory = v
		case "root_disk":
			st.RootDisk = v
		case "categories":
			st.Categories = v
		}
	}
	if err := sc.Err(); err != nil {
		return State{}, err
	}
	return st, nil
}

// Format serializes State into the canonical key=value file representation.
func Format(st State) string {
	var b strings.Builder
	writeKV(&b, "agent", st.Agent)
	writeKV(&b, "image", st.Image)
	writeKV(&b, "snapshot", st.Snapshot)
	writeKV(&b, "snap_count", strconv.Itoa(st.SnapCount))
	writeKV(&b, "cpus", st.CPUs)
	writeKV(&b, "memory", st.Memory)
	writeKV(&b, "root_disk", st.RootDisk)
	writeKV(&b, "categories", st.Categories)
	return b.String()
}

// LoadFile reads State from disk.
func LoadFile(path string) (State, error) {
	f, err := os.Open(path)
	if err != nil {
		return State{}, err
	}
	defer f.Close()
	return Parse(f)
}

// SaveFile atomically writes State to path (creating parent directories with mode 0700).
func SaveFile(path string, st State) error {
	return saveBytesAtomic(path, []byte(Format(st)))
}

// RunMode identifies the execution mode of an active or suspended sandbox.
type RunMode string

const (
	RunModeTUI           RunMode = "tui"
	RunModeServe         RunMode = "serve"
	RunModeRemoteControl RunMode = "remote-control"
	RunModeCmd           RunMode = "cmd"
)

// ShareRecord records one validated host share attached to a run sandbox.
type ShareRecord struct {
	Index     int    `json:"index"`
	HostPath  string `json:"host_path"`
	GuestName string `json:"guest_name"`
	IsDir     bool   `json:"is_dir"`
	Masked    bool   `json:"masked"`
}

// RunMeta stores per-run metadata in $DATA_DIR/run/<id>/run.meta and suspended.
type RunMeta struct {
	Sandbox         string        `json:"sandbox"`
	OwnerPID        int           `json:"owner_pid"`
	Agent           string        `json:"agent"`
	Mode            RunMode       `json:"mode"`
	Detached        bool          `json:"detached"`
	RemoteControl   bool          `json:"remote_control"`
	Port            int           `json:"port,omitempty"`
	Cmd             string        `json:"cmd,omitempty"`
	ReadOnly        bool          `json:"read_only"`
	MaskMode        MaskMode      `json:"mask_mode"`
	Persist         bool          `json:"persist,omitempty"`
	Profile         string        `json:"profile,omitempty"`
	Continue        bool          `json:"continue,omitempty"`
	ContinueSession string        `json:"continue_session,omitempty"`
	NoAuth          bool          `json:"no_auth,omitempty"`
	NoSkills        bool          `json:"no_skills,omitempty"`
	SkillsMounted   bool          `json:"skills_mounted,omitempty"`
	NoRules         bool          `json:"no_rules,omitempty"`
	RulesMounted    bool          `json:"rules_mounted,omitempty"`
	Shares          []ShareRecord `json:"shares,omitempty"`
}

// IsValidSizeSpec reports whether spec is a positive integer followed by M or G.
func IsValidSizeSpec(spec string) bool {
	return isValidSizeSpec(spec)
}

// FormatRunMeta serializes RunMeta as indented JSON bytes.
func FormatRunMeta(meta RunMeta) ([]byte, error) {
	raw, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(raw, '\n'), nil
}

// ParseRunMeta decodes RunMeta JSON from r.
func ParseRunMeta(r io.Reader) (RunMeta, error) {
	var meta RunMeta
	dec := json.NewDecoder(r)
	if err := dec.Decode(&meta); err != nil {
		return RunMeta{}, fmt.Errorf("parse run metadata: %w", err)
	}
	if meta.Sandbox == "" {
		return RunMeta{}, fmt.Errorf("parse run metadata: missing sandbox name")
	}
	for _, sh := range meta.Shares {
		if sh.Index < 0 {
			return RunMeta{}, fmt.Errorf("parse run metadata: negative share index %d", sh.Index)
		}
	}
	return meta, nil
}

// LoadRunMeta reads a RunMeta JSON file from disk.
func LoadRunMeta(path string) (RunMeta, error) {
	f, err := os.Open(path)
	if err != nil {
		return RunMeta{}, err
	}
	defer f.Close()
	return ParseRunMeta(f)
}

// SaveRunMeta atomically writes RunMeta JSON to path with mode 0600.
func SaveRunMeta(path string, meta RunMeta) error {
	raw, err := FormatRunMeta(meta)
	if err != nil {
		return err
	}
	return saveBytesAtomic(path, raw)
}

// EnsurePrivateDir creates dir with mode 0700 and rejects symlinks or non-directories.
func EnsurePrivateDir(dir string) error {
	if dir == "" {
		return fmt.Errorf("private directory path must not be empty")
	}
	if info, err := os.Lstat(dir); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("refusing symlinked directory %q", dir)
		}
		if !info.IsDir() {
			return fmt.Errorf("path %q is not a directory", dir)
		}
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create dir %q: %w", dir, err)
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return fmt.Errorf("stat dir %q: %w", dir, err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("refusing non-directory %q", dir)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return fmt.Errorf("chmod dir %q: %w", dir, err)
	}
	return nil
}

func saveBytesAtomic(path string, content []byte) error {
	dir := filepath.Dir(path)
	if err := EnsurePrivateDir(dir); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".conf.*")
	if err != nil {
		return fmt.Errorf("create temp config: %w", err)
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

// NextSnapshotMember calculates the next snapshot number and selector ("<group>:v<N>").
// It compares the recorded snap_count with existing snapshots from 'msb snap ls'.
// This prevents version collisions if the config file is reset while snapshots exist.
func NextSnapshotMember(recordedCount int, existingRefs []string, group string) (int, string) {
	maxN := recordedCount
	if maxN < 0 {
		maxN = 0
	}
	prefix := group + ":v"
	for _, ref := range existingRefs {
		ref = strings.TrimSpace(ref)
		if strings.HasPrefix(ref, prefix) {
			numStr := strings.TrimPrefix(ref, prefix)
			if n, err := strconv.Atoi(numStr); err == nil && n > maxN {
				maxN = n
			}
		}
	}
	next := maxN + 1
	return next, fmt.Sprintf("%s:v%d", group, next)
}

func isValidSizeSpec(spec string) bool {
	s := strings.ToUpper(strings.TrimSpace(spec))
	if len(s) < 2 {
		return false
	}
	unit := s[len(s)-1]
	if unit != 'M' && unit != 'G' {
		return false
	}
	n, err := strconv.Atoi(s[:len(s)-1])
	return err == nil && n > 0
}

func hasUnsafeTokenChars(s string) bool {
	if s == "" {
		return true
	}
	for _, r := range s {
		if r <= 0x20 || r == 0x7f {
			return true
		}
	}
	return false
}

func defaultIfEmpty(val, fallback string) string {
	v := strings.TrimSpace(val)
	if v == "" {
		return fallback
	}
	return v
}

func writeKV(b *strings.Builder, k, v string) {
	if v != "" {
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(v)
		b.WriteByte('\n')
	}
}
