// Package config manages environment settings and base-image metadata for agbox.
// Parsing, formatting, and version calculation functions are pure.
// File I/O occurs only in LoadFile and SaveFile.
package config

import (
	"bufio"
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

	DefaultCPUs            = "2"
	DefaultMemory          = "2G"
	DefaultRootDisk        = "8G"
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

// ParseMaskMode normalizes a string (from AGBOX_MASK_VCS or CLI flags) into a
// validated MaskMode.
func ParseMaskMode(raw string) (MaskMode, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", "auto":
		return MaskAuto, nil
	case "strict", "1", "true", "yes":
		return MaskStrict, nil
	case "off", "0", "false", "no":
		return MaskOff, nil
	default:
		return "", fmt.Errorf("invalid mask mode %q (expected: auto, strict, or off)", raw)
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
	OpenCodeVersion  string
	AgyInstallerURL  string
	MaskVCS          MaskMode
	AllowOutsideHome bool
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

	return Env{
		HomeReal:         cleanHome,
		DataDir:          dataDir,
		ConfigFile:       filepath.Join(dataDir, "config"),
		MSBHome:          msbHome,
		CPUs:             defaultIfEmpty(getenv("AGBOX_CPUS"), DefaultCPUs),
		Memory:           defaultIfEmpty(getenv("AGBOX_MEMORY"), DefaultMemory),
		RootDisk:         defaultIfEmpty(getenv("AGBOX_ROOT_DISK"), DefaultRootDisk),
		OpenCodeVersion:  defaultIfEmpty(getenv("AGBOX_OPENCODE_VERSION"), DefaultOpenCodeVersion),
		AgyInstallerURL:  defaultIfEmpty(getenv("AGBOX_AGY_INSTALLER_URL"), DefaultAgyInstallerURL),
		MaskVCS:          maskMode,
		AllowOutsideHome: strings.TrimSpace(getenv("AGBOX_ALLOW_OUTSIDE_HOME")) == "1",
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
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return fmt.Errorf("chmod config dir: %w", err)
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
	if _, err := io.WriteString(tmp, Format(st)); err != nil {
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
