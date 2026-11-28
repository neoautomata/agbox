// Package config manages environment settings and metadata files for agbox.
//
// Security properties:
//   - ParseMaskMode defaults empty AGBOX_MASK_VCS values to MaskStrict.
//   - FromLookup validates CPU counts, memory and disk sizes, package versions,
//     and HTTPS installer URLs before any command runs.
//   - FromLookup canonicalizes the longest existing ancestor of DataDir and MSBHome.
//   - EnsurePrivateDir rejects symlinks with O_NOFOLLOW and sets mode 0700.
//   - LoadFile and LoadRunMeta reject symlinks and cap file sizes.
//   - SaveFile and SaveRunMeta write state files atomically at mode 0600.
package config

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
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

	maxStateFileBytes = 256 * 1024
	maxSymlinkHops    = 40
)

// MaskMode controls whether the FUSE filter routes directory shares.
type MaskMode string

const (
	MaskAuto   MaskMode = "auto"
	MaskStrict MaskMode = "strict"
	MaskOff    MaskMode = "off"
)

// ParseMaskMode parses a raw AGBOX_MASK_VCS value into a validated MaskMode.
// Empty input defaults to MaskStrict.
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

// Env holds runtime settings read from the host environment.
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
	RemoteDefault    bool
}

// FromLookup builds an Env from getenv and the resolved home directory path.
func FromLookup(homeReal string, getenv func(string) string) (Env, error) {
	if homeReal == "" {
		return Env{}, errors.New("home directory path must not be empty")
	}
	if hasControlOrBidiChar(homeReal) {
		return Env{}, fmt.Errorf("invalid home directory path %q: must not contain control characters", homeReal)
	}
	cleanHome := filepath.Clean(homeReal)

	rawDataDir := getenv("AGBOX_DATA_DIR")
	if hasControlOrBidiChar(rawDataDir) {
		return Env{}, fmt.Errorf("invalid AGBOX_DATA_DIR %q: must not contain control characters", rawDataDir)
	}
	dataDirRaw := strings.TrimSpace(rawDataDir)
	var dataDir string
	if dataDirRaw == "" {
		dataDir = filepath.Join(cleanHome, ".local", "share", "agbox")
	} else {
		if !filepath.IsAbs(dataDirRaw) {
			return Env{}, fmt.Errorf("invalid AGBOX_DATA_DIR %q: must be an absolute path", dataDirRaw)
		}
		dataDir = filepath.Clean(dataDirRaw)
	}
	dataDir = resolveLongestExistingAncestor(dataDir)
	if hasControlOrBidiChar(dataDir) {
		return Env{}, fmt.Errorf("invalid AGBOX_DATA_DIR %q: resolved path must not contain control characters", dataDir)
	}

	rawMSBHome := getenv("MSB_HOME")
	if hasControlOrBidiChar(rawMSBHome) {
		return Env{}, fmt.Errorf("invalid MSB_HOME %q: must not contain control characters", rawMSBHome)
	}
	msbHomeRaw := strings.TrimSpace(rawMSBHome)
	var msbHome string
	if msbHomeRaw == "" {
		msbHome = filepath.Join(cleanHome, ".microsandbox")
	} else {
		if !filepath.IsAbs(msbHomeRaw) {
			return Env{}, fmt.Errorf("invalid MSB_HOME %q: must be an absolute path", msbHomeRaw)
		}
		msbHome = filepath.Clean(msbHomeRaw)
	}
	msbHome = resolveLongestExistingAncestor(msbHome)
	if hasControlOrBidiChar(msbHome) {
		return Env{}, fmt.Errorf("invalid MSB_HOME %q: resolved path must not contain control characters", msbHome)
	}

	maskMode, err := ParseMaskMode(getenv("AGBOX_MASK_VCS"))
	if err != nil {
		return Env{}, err
	}

	cpusRaw := defaultIfEmpty(getenv("AGBOX_CPUS"), DefaultCPUs)
	if strings.HasPrefix(cpusRaw, "+") {
		return Env{}, fmt.Errorf("invalid AGBOX_CPUS %q: must be a positive integer", cpusRaw)
	}
	cpuCount, err := strconv.Atoi(cpusRaw)
	if err != nil || cpuCount < 1 {
		return Env{}, fmt.Errorf("invalid AGBOX_CPUS %q: must be a positive integer", cpusRaw)
	}
	cpus := strconv.Itoa(cpuCount)

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
	if !isValidVersionToken(openCodeVer) {
		return Env{}, fmt.Errorf("invalid AGBOX_OPENCODE_VERSION %q: use only ASCII letters, digits, '.', '_', '+', and '-'", openCodeVer)
	}

	agyURL := defaultIfEmpty(getenv("AGBOX_AGY_INSTALLER_URL"), DefaultAgyInstallerURL)
	u, uErr := url.ParseRequestURI(agyURL)
	if uErr != nil || u.Scheme != "https" || u.Host == "" || hasUnsafeTokenChars(agyURL) || strings.ContainsAny(agyURL, ";|&`$'\"\\()<>\n\r\t ") {
		return Env{}, fmt.Errorf("invalid AGBOX_AGY_INSTALLER_URL %q: must be an https:// URL without whitespace or shell metacharacters", agyURL)
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
		RemoteDefault:    strings.TrimSpace(getenv("AGBOX_REMOTE")) != "0",
	}, nil
}

// resolveLongestExistingAncestor resolves symlinks in the longest existing prefix of absPath.
func resolveLongestExistingAncestor(absPath string) string {
	p := filepath.Clean(absPath)
	for hop := 0; hop < maxSymlinkHops; hop++ {
		if resolved, err := filepath.EvalSymlinks(p); err == nil {
			return filepath.Clean(resolved)
		}
		advanced := false
		cur := p
		for cur != "/" && cur != "." {
			if resolved, err := filepath.EvalSymlinks(cur); err == nil {
				rel, rErr := filepath.Rel(cur, p)
				if rErr == nil {
					return filepath.Clean(filepath.Join(resolved, rel))
				}
				return p
			}
			if info, lErr := os.Lstat(cur); lErr == nil && info.Mode()&os.ModeSymlink != 0 {
				target, rErr := os.Readlink(cur)
				if rErr != nil {
					return p
				}
				if !filepath.IsAbs(target) {
					parentDir := filepath.Dir(cur)
					if resolvedParent, pErr := filepath.EvalSymlinks(parentDir); pErr == nil {
						parentDir = resolvedParent
					}
					target = filepath.Join(parentDir, target)
				}
				rel, relErr := filepath.Rel(cur, p)
				if relErr != nil {
					return p
				}
				if rel == "." {
					p = filepath.Clean(target)
				} else {
					p = filepath.Clean(filepath.Join(target, rel))
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
			return p
		}
	}
	return p
}

// LoadEnv loads settings from the current OS process environment.
func LoadEnv() (Env, error) {
	return loadEnvWith(os.UserHomeDir, filepath.EvalSymlinks, os.Getenv)
}

func loadEnvWith(userHomeDir func() (string, error), evalSymlinks func(string) (string, error), getenv func(string) string) (Env, error) {
	home, err := userHomeDir()
	if err != nil {
		return Env{}, fmt.Errorf("determine $HOME: %w", err)
	}
	homeReal, err := evalSymlinks(home)
	if err != nil {
		return Env{}, fmt.Errorf("resolve $HOME (%s): %w", home, err)
	}
	return FromLookup(homeReal, getenv)
}

// State holds base snapshot settings stored in DATA_DIR/config.
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
	sc.Buffer(make([]byte, 0, 64*1024), maxStateFileBytes)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k = strings.TrimSpace(k)
		v = strings.TrimSpace(v)
		switch k {
		case "agent":
			st.Agent = v
		case "image":
			st.Image = v
		case "snapshot":
			st.Snapshot = v
		case "snap_count":
			if n, err := strconv.Atoi(v); err == nil && n >= 0 {
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

// Format serializes State into key=value text.
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

// LoadFile reads State from a regular file on disk without following symlinks.
func LoadFile(path string) (State, error) {
	raw, err := readRegularStateFile(path, maxStateFileBytes)
	if err != nil {
		return State{}, err
	}
	return Parse(bytes.NewReader(raw))
}

func validateState(st State) error {
	fields := []struct {
		name string
		val  string
	}{
		{"agent", st.Agent},
		{"image", st.Image},
		{"snapshot", st.Snapshot},
		{"cpus", st.CPUs},
		{"memory", st.Memory},
		{"root_disk", st.RootDisk},
		{"categories", st.Categories},
	}
	for _, f := range fields {
		if strings.ContainsAny(f.val, "\r\n") {
			return fmt.Errorf("invalid config field %q: must not contain line breaks", f.name)
		}
	}
	return nil
}

// SaveFile writes State atomically at mode 0600 and sets parent directories to 0700.
func SaveFile(path string, st State) error {
	if err := validateState(st); err != nil {
		return err
	}
	return saveBytesAtomic(path, []byte(Format(st)))
}

// RunMode identifies the session mode of an active or suspended sandbox.
type RunMode string

const (
	RunModeTUI           RunMode = "tui"
	RunModeServe         RunMode = "serve"
	RunModeRemoteControl RunMode = "remote-control"
	RunModeCmd           RunMode = "cmd"
)

// VCSPolicy controls access to VCS metadata and hooks inside a share.
type VCSPolicy string

const (
	VCSMask       VCSPolicy = "mask"
	VCSAllow      VCSPolicy = "vcs"
	VCSAllowHooks VCSPolicy = "vcs-hooks"
)

// ParseVCSPolicy validates a per-share VCS policy string. Empty input defaults to VCSMask.
func ParseVCSPolicy(raw string) (VCSPolicy, error) {
	switch VCSPolicy(strings.ToLower(strings.TrimSpace(raw))) {
	case "", VCSMask:
		return VCSMask, nil
	case VCSAllow:
		return VCSAllow, nil
	case VCSAllowHooks:
		return VCSAllowHooks, nil
	default:
		return "", fmt.Errorf("invalid VCS policy %q (expected: mask, vcs, or vcs-hooks)", raw)
	}
}

// ShareRecord records one validated host share attached to a sandbox.
type ShareRecord struct {
	Index      int       `json:"index"`
	HostPath   string    `json:"host_path"`
	GuestName  string    `json:"guest_name"`
	IsDir      bool      `json:"is_dir"`
	Masked     bool      `json:"masked"`
	AccessMode string    `json:"access_mode,omitempty"`
	ReadOnly   bool      `json:"read_only,omitempty"`
	VCSPolicy  VCSPolicy `json:"vcs_policy,omitempty"`
}

// EffectiveReadOnly returns true when the share forbids writes.
// It uses metaReadOnly for records without an explicit AccessMode.
func (s ShareRecord) EffectiveReadOnly(metaReadOnly bool) bool {
	switch s.AccessMode {
	case "ro":
		return true
	case "rw":
		return false
	default:
		return s.ReadOnly || metaReadOnly
	}
}

// EffectiveVCSPolicy returns the validated VCS policy of the share.
// It returns VCSMask for records without an explicit VCSPolicy when Masked is true or IsDir is false.
func (s ShareRecord) EffectiveVCSPolicy() VCSPolicy {
	if s.VCSPolicy != "" {
		return s.VCSPolicy
	}
	if !s.IsDir || s.Masked {
		return VCSMask
	}
	return VCSAllow
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
	WorkspaceHub    bool          `json:"workspace_hub,omitempty"`
	Persist         bool          `json:"persist,omitempty"`
	Profile         string        `json:"profile,omitempty"`
	Continue        bool          `json:"continue,omitempty"`
	ContinueSession string        `json:"continue_session,omitempty"`
	NoAuth          bool          `json:"no_auth,omitempty"`
	NoSkills        bool          `json:"no_skills,omitempty"`
	SkillsMounted   bool          `json:"skills_mounted,omitempty"`
	NoRules         bool          `json:"no_rules,omitempty"`
	RulesMounted    bool          `json:"rules_mounted,omitempty"`
	NoAgentCache    bool          `json:"no_agent_cache,omitempty"`
	AgentsMounted   bool          `json:"agents_mounted,omitempty"`
	NoRemote        bool          `json:"no_remote,omitempty"`
	RemoteBridge    bool          `json:"remote_bridge,omitempty"`
	Shares          []ShareRecord `json:"shares,omitempty"`
}

// IsValidSizeSpec reports whether spec is a positive integer followed by M or G.
func IsValidSizeSpec(spec string) bool {
	return isValidSizeSpec(spec)
}

func validateRunMeta(meta RunMeta, op string) error {
	if meta.Sandbox == "" {
		return fmt.Errorf("%s: missing sandbox name", op)
	}
	if meta.OwnerPID < 0 {
		return fmt.Errorf("%s: negative owner PID %d", op, meta.OwnerPID)
	}
	if meta.Port < 0 || meta.Port > 65535 {
		return fmt.Errorf("%s: invalid port %d", op, meta.Port)
	}
	if meta.Mode != "" {
		switch meta.Mode {
		case RunModeTUI, RunModeServe, RunModeRemoteControl, RunModeCmd:
		default:
			return fmt.Errorf("%s: invalid mode %q", op, meta.Mode)
		}
	}
	if meta.MaskMode != "" {
		switch meta.MaskMode {
		case MaskStrict, MaskAuto, MaskOff:
		default:
			return fmt.Errorf("%s: invalid mask_mode %q", op, meta.MaskMode)
		}
	}
	if meta.RemoteBridge && meta.NoRemote {
		return fmt.Errorf("%s: conflicting remote_bridge and no_remote flags", op)
	}
	for _, sh := range meta.Shares {
		if sh.Index < 0 {
			return fmt.Errorf("%s: negative share index %d", op, sh.Index)
		}
		if sh.AccessMode != "" && sh.AccessMode != "ro" && sh.AccessMode != "rw" {
			return fmt.Errorf("%s: invalid share access_mode %q", op, sh.AccessMode)
		}
		if sh.VCSPolicy != "" {
			switch sh.VCSPolicy {
			case VCSMask, VCSAllow, VCSAllowHooks:
			default:
				return fmt.Errorf("%s: invalid share vcs_policy %q", op, sh.VCSPolicy)
			}
		}
		if !sh.IsDir && sh.EffectiveVCSPolicy() != VCSMask {
			return fmt.Errorf("%s: single-file share %q must use mask VCS policy", op, sh.GuestName)
		}
		if meta.MaskMode != MaskOff && sh.EffectiveReadOnly(meta.ReadOnly) && sh.EffectiveVCSPolicy() == VCSAllowHooks {
			return fmt.Errorf("%s: read-only share %q cannot enable vcs-hooks", op, sh.GuestName)
		}
	}
	return nil
}

// FormatRunMeta validates and serializes RunMeta as indented JSON bytes.
func FormatRunMeta(meta RunMeta) ([]byte, error) {
	if err := validateRunMeta(meta, "format run metadata"); err != nil {
		return nil, err
	}
	raw, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(raw, '\n'), nil
}

// ParseRunMeta decodes and validates RunMeta JSON from r.
func ParseRunMeta(r io.Reader) (RunMeta, error) {
	var meta RunMeta
	dec := json.NewDecoder(r)
	if err := dec.Decode(&meta); err != nil {
		return RunMeta{}, fmt.Errorf("parse run metadata: %w", err)
	}
	if err := validateRunMeta(meta, "parse run metadata"); err != nil {
		return RunMeta{}, err
	}
	return meta, nil
}

// LoadRunMeta reads a RunMeta JSON file from disk without following symlinks.
func LoadRunMeta(path string) (RunMeta, error) {
	raw, err := readRegularStateFile(path, maxStateFileBytes)
	if err != nil {
		return RunMeta{}, err
	}
	return ParseRunMeta(bytes.NewReader(raw))
}

// SaveRunMeta writes RunMeta JSON atomically to path at mode 0600.
func SaveRunMeta(path string, meta RunMeta) error {
	raw, err := FormatRunMeta(meta)
	if err != nil {
		return err
	}
	return saveBytesAtomic(path, raw)
}

func readRegularStateFile(path string, maxBytes int64) ([]byte, error) {
	if path == "" {
		return nil, errors.New("state file path must not be empty")
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC|syscall.O_NONBLOCK, 0)
	if err != nil {
		if errors.Is(err, syscall.ELOOP) {
			return nil, &os.PathError{Op: "open", Path: path, Err: fmt.Errorf("refusing symlink: %w", err)}
		}
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat state file %q: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("refusing non-regular state file %q", path)
	}
	raw, err := io.ReadAll(io.LimitReader(f, maxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read state file %q: %w", path, err)
	}
	if int64(len(raw)) > maxBytes {
		return nil, fmt.Errorf("state file %q exceeds %d bytes", path, maxBytes)
	}
	return raw, nil
}

// EnsurePrivateDir creates dir with mode 0700 and rejects symlinks or non-directories.
func EnsurePrivateDir(dir string) error {
	if dir == "" {
		return errors.New("private directory path must not be empty")
	}
	cleanDir := filepath.Clean(dir)
	if cleanDir == "/" {
		return fmt.Errorf("refusing root directory %q", dir)
	}
	if info, err := os.Lstat(cleanDir); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("refusing symlinked directory %q", dir)
		}
		if !info.IsDir() {
			return fmt.Errorf("path %q is not a directory", dir)
		}
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("stat dir %q: %w", dir, err)
	}
	if err := os.MkdirAll(cleanDir, 0o700); err != nil {
		return fmt.Errorf("create dir %q: %w", dir, err)
	}
	fd, err := syscall.Open(cleanDir, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		if errors.Is(err, syscall.ELOOP) || errors.Is(err, syscall.ENOTDIR) {
			return fmt.Errorf("refusing symlink or non-directory %q: %w", dir, err)
		}
		return fmt.Errorf("open dir %q: %w", dir, err)
	}
	defer syscall.Close(fd)

	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil {
		return fmt.Errorf("stat dir %q: %w", dir, err)
	}
	if (st.Mode & syscall.S_IFMT) != syscall.S_IFDIR {
		return fmt.Errorf("refusing non-directory %q", dir)
	}
	if err := syscall.Fchmod(fd, 0o700); err != nil {
		return fmt.Errorf("chmod dir %q: %w", dir, err)
	}
	return nil
}

func saveBytesAtomic(path string, content []byte) error {
	if path == "" {
		return errors.New("target file path must not be empty")
	}
	dir := filepath.Dir(path)
	if err := EnsurePrivateDir(dir); err != nil {
		return err
	}
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("refusing symlinked state file %q", path)
		}
		if info.IsDir() {
			return fmt.Errorf("refusing to overwrite directory %q", path)
		}
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("stat target file %q: %w", path, err)
	}

	tmp, err := os.CreateTemp(dir, ".conf.*")
	if err != nil {
		return fmt.Errorf("create temp file in %q: %w", dir, err)
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
		return fmt.Errorf("chmod temp file for %q: %w", path, err)
	}
	if _, err := tmp.Write(content); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write temp file for %q: %w", path, err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("sync temp file for %q: %w", path, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp file for %q: %w", path, err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("rename temp file to %q: %w", path, err)
	}
	cleanup = false

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

// NextSnapshotMember calculates the next snapshot number and selector ("<group>:v<N>").
// It compares recordedCount with existing snapshots from 'msb snap ls'.
// This comparison avoids version collisions when snapshots exist without a config file.
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
	numPart := s[:len(s)-1]
	if strings.HasPrefix(numPart, "+") {
		return false
	}
	n, err := strconv.Atoi(numPart)
	return err == nil && n > 0
}

func hasControlOrBidiChar(s string) bool {
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

func isValidVersionToken(s string) bool {
	if s == "" || s[0] == '-' || s[0] == '.' {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		isAlphaNum := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
		if !isAlphaNum && c != '.' && c != '_' && c != '+' && c != '-' {
			return false
		}
	}
	return true
}

func hasUnsafeTokenChars(s string) bool {
	if s == "" {
		return true
	}
	for _, r := range s {
		if r <= 0x20 || r == 0x7f {
			return true
		}
		if (r >= 0x200B && r <= 0x200F) || (r >= 0x202A && r <= 0x202E) || (r >= 0x2066 && r <= 0x2069) || r == 0xFEFF {
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
	v = strings.NewReplacer("\r", "", "\n", "").Replace(v)
	if v != "" {
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(v)
		b.WriteByte('\n')
	}
}
