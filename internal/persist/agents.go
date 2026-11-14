package persist

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"

	"agbox/internal/config"
	"agbox/internal/msb"
)

const (
	// MaxAgentBinaryBytes caps each cached agent binary at 1 GiB.
	MaxAgentBinaryBytes = 1024 * 1024 * 1024

	// MinAgentBinaryBytes requires at least a 64-byte 64-bit ELF header.
	MinAgentBinaryBytes = 64

	// MaxAgentsManifestBytes caps $DATA_DIR/agents/manifest.json at 64 KiB.
	MaxAgentsManifestBytes = 64 * 1024
)

var elfMagic = []byte{0x7f, 'E', 'L', 'F'}

// CachedAgentInfo describes one verified agent binary stored in $DATA_DIR/agents.
type CachedAgentInfo struct {
	Agent     string `json:"agent"`
	BinName   string `json:"bin_name"`
	Version   string `json:"version"`
	SHA256    string `json:"sha256"`
	SizeBytes int64  `json:"size_bytes"`
	UpdatedAt string `json:"updated_at"`
}

type agentsManifest struct {
	Agents map[string]CachedAgentInfo `json:"agents"`
}

// AgentBinName maps an agbox agent identifier to its binary filename in $DATA_DIR/agents/bin.
func AgentBinName(agent string) (string, error) {
	switch agent {
	case "antigravity":
		return "agy", nil
	case "opencode":
		return "opencode", nil
	default:
		return "", fmt.Errorf("unsupported agent %q (expected antigravity or opencode)", agent)
	}
}

func agentFromBinName(binName string) (string, bool) {
	switch binName {
	case "agy":
		return "antigravity", true
	case "opencode":
		return "opencode", true
	default:
		return "", false
	}
}

// EnsureAgentsDir creates $DATA_DIR/agents (0700) and $DATA_DIR/agents/bin (0755)
// while rejecting symlinks and unsafe path delimiters.
func EnsureAgentsDir(agentsDir string) error {
	if agentsDir == "" {
		return errors.New("agents directory path must not be empty")
	}
	if strings.ContainsAny(agentsDir, ":,") {
		return fmt.Errorf("agents directory %q cannot contain ':' or ','", agentsDir)
	}
	if err := config.EnsurePrivateDir(agentsDir); err != nil {
		return fmt.Errorf("prepare agents dir: %w", err)
	}
	binDir := filepath.Join(agentsDir, "bin")
	if info, err := os.Lstat(binDir); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("refusing symlinked agents bin directory %q", binDir)
		}
		if !info.IsDir() {
			return fmt.Errorf("agents bin path %q is not a directory", binDir)
		}
	}
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		return fmt.Errorf("create agents bin dir %q: %w", binDir, err)
	}
	info, err := os.Lstat(binDir)
	if err != nil {
		return fmt.Errorf("stat agents bin dir %q: %w", binDir, err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("refusing non-directory agents bin path %q", binDir)
	}
	if err := os.Chmod(binDir, 0o755); err != nil {
		return fmt.Errorf("chmod agents bin dir %q: %w", binDir, err)
	}
	return nil
}

// InspectAgentsDir validates $DATA_DIR/agents and returns sorted metadata for cached
// agent binaries. Any symlink, unexpected entry, hardlink, non-ELF file, or SHA-256
// mismatch against manifest.json fails closed with an error.
func InspectAgentsDir(agentsDir string) ([]CachedAgentInfo, error) {
	if agentsDir == "" {
		return nil, nil
	}
	if strings.ContainsAny(agentsDir, ":,") {
		return nil, fmt.Errorf("agents directory %q cannot contain ':' or ','", agentsDir)
	}
	rootInfo, err := os.Lstat(agentsDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("stat agents dir %q: %w", agentsDir, err)
	}
	if rootInfo.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("refusing symlinked agents directory %q", agentsDir)
	}
	if !rootInfo.IsDir() {
		return nil, fmt.Errorf("agents path %q is not a directory", agentsDir)
	}

	rootEntries, err := os.ReadDir(agentsDir)
	if err != nil {
		return nil, fmt.Errorf("read agents dir %q: %w", agentsDir, err)
	}
	hasBin := false
	hasManifest := false
	for _, entry := range rootEntries {
		name := entry.Name()
		full := filepath.Join(agentsDir, name)
		st, lErr := os.Lstat(full)
		if lErr != nil {
			return nil, fmt.Errorf("stat %q: %w", full, lErr)
		}
		if st.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("refusing symlink inside agents directory: %s", full)
		}
		switch name {
		case "bin":
			if !st.IsDir() {
				return nil, fmt.Errorf("agents bin entry %s is not a directory", full)
			}
			hasBin = true
		case "manifest.json":
			if !st.Mode().IsRegular() {
				return nil, fmt.Errorf("agents manifest %s is not a regular file", full)
			}
			if st.Size() > MaxAgentsManifestBytes {
				return nil, fmt.Errorf("agents manifest %s exceeds %d bytes", full, MaxAgentsManifestBytes)
			}
			hasManifest = true
		default:
			return nil, fmt.Errorf("unexpected entry %q in agents directory %s", name, agentsDir)
		}
	}

	manifest := agentsManifest{Agents: map[string]CachedAgentInfo{}}
	if hasManifest {
		mPath := filepath.Join(agentsDir, "manifest.json")
		mBytes, err := readRegularNoFollow(mPath, MaxAgentsManifestBytes)
		if err != nil {
			return nil, fmt.Errorf("read agents manifest: %w", err)
		}
		if err := json.Unmarshal(mBytes, &manifest); err != nil {
			return nil, fmt.Errorf("parse agents manifest %s: %w", mPath, err)
		}
		if manifest.Agents == nil {
			manifest.Agents = map[string]CachedAgentInfo{}
		}
	}

	found := make(map[string]CachedAgentInfo)
	if hasBin {
		binDir := filepath.Join(agentsDir, "bin")
		binEntries, err := os.ReadDir(binDir)
		if err != nil {
			return nil, fmt.Errorf("read agents bin dir %q: %w", binDir, err)
		}
		for _, entry := range binEntries {
			binName := entry.Name()
			agentName, ok := agentFromBinName(binName)
			if !ok {
				return nil, fmt.Errorf("unexpected file %q in %s", binName, binDir)
			}
			binPath := filepath.Join(binDir, binName)
			digest, sz, err := verifyAgentBinaryFile(binPath)
			if err != nil {
				return nil, err
			}
			rec, ok := manifest.Agents[agentName]
			if !ok {
				return nil, fmt.Errorf("cached binary %s is missing from manifest.json", binPath)
			}
			if rec.BinName != binName || rec.Agent != agentName {
				return nil, fmt.Errorf("manifest metadata mismatch for %s", agentName)
			}
			if !strings.EqualFold(rec.SHA256, digest) || rec.SizeBytes != sz {
				return nil, fmt.Errorf("integrity check failed for cached %s binary (%s)", agentName, binPath)
			}
			found[agentName] = rec
		}
	}

	for agentName := range manifest.Agents {
		if _, ok := found[agentName]; !ok {
			return nil, fmt.Errorf("agents manifest lists %q, but its binary is missing from %s", agentName, filepath.Join(agentsDir, "bin"))
		}
	}

	var out []CachedAgentInfo
	for _, info := range found {
		out = append(out, info)
	}
	slices.SortFunc(out, func(a, b CachedAgentInfo) int {
		return strings.Compare(a.Agent, b.Agent)
	})
	return out, nil
}

func verifyAgentBinaryFile(path string) (string, int64, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return "", 0, fmt.Errorf("stat %s: %w", path, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return "", 0, fmt.Errorf("refusing symlinked agent binary %s", path)
	}
	if !info.Mode().IsRegular() {
		return "", 0, fmt.Errorf("refusing non-regular agent binary %s", path)
	}
	if info.Size() < MinAgentBinaryBytes || info.Size() > MaxAgentBinaryBytes {
		return "", 0, fmt.Errorf("agent binary %s has invalid size %d bytes", path, info.Size())
	}
	if st, ok := info.Sys().(*syscall.Stat_t); ok && st.Nlink != 1 {
		return "", 0, fmt.Errorf("refusing hardlinked agent binary %s (nlink=%d)", path, st.Nlink)
	}

	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return "", 0, fmt.Errorf("open %s: %w", path, err)
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()

	var hdr [4]byte
	if _, err := io.ReadFull(f, hdr[:]); err != nil {
		return "", 0, fmt.Errorf("read ELF header of %s: %w", path, err)
	}
	if !bytes.Equal(hdr[:], elfMagic) {
		return "", 0, fmt.Errorf("agent binary %s is not a valid ELF executable", path)
	}

	h := sha256.New()
	_, _ = h.Write(hdr[:])
	nRest, err := io.Copy(h, io.LimitReader(f, MaxAgentBinaryBytes))
	if err != nil {
		return "", 0, fmt.Errorf("hash %s: %w", path, err)
	}
	total := int64(len(hdr)) + nRest
	if total != info.Size() {
		return "", 0, fmt.Errorf("size changed while verifying %s", path)
	}
	return hex.EncodeToString(h.Sum(nil)), total, nil
}

func readRegularNoFollow(path string, maxBytes int64) ([]byte, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	if st.Size() > maxBytes {
		return nil, fmt.Errorf("%s exceeds %d bytes", path, maxBytes)
	}
	return io.ReadAll(io.LimitReader(f, maxBytes+1))
}

// AgentBinaryCaptureWriter streams a binary from msb stdout into a private temporary
// file on the host while enforcing MaxAgentBinaryBytes and computing its SHA-256 digest.
type AgentBinaryCaptureWriter struct {
	agentsDir string
	agent     string
	binName   string
	tmpFile   *os.File
	tmpPath   string
	hasher    hash.Hash
	header    []byte
	written   int64
	overflow  bool
}

// NewAgentBinaryCaptureWriter prepares a temporary file inside $DATA_DIR/agents/bin
// to receive a streamed ELF binary for agent.
func NewAgentBinaryCaptureWriter(agentsDir, agent string) (*AgentBinaryCaptureWriter, error) {
	binName, err := AgentBinName(agent)
	if err != nil {
		return nil, err
	}
	if err := EnsureAgentsDir(agentsDir); err != nil {
		return nil, err
	}
	// Create the temp file inside agentsDir (mode 0700) on the same filesystem,
	// then atomically rename the verified ELF binary into bin/<binName>.
	tmp, err := os.CreateTemp(agentsDir, ".tmp-"+binName+"-*")
	if err != nil {
		return nil, fmt.Errorf("create temp agent binary: %w", err)
	}
	if err := tmp.Chmod(0o600); err != nil {
		tmpName := tmp.Name()
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return nil, err
	}
	return &AgentBinaryCaptureWriter{
		agentsDir: agentsDir,
		agent:     agent,
		binName:   binName,
		tmpFile:   tmp,
		tmpPath:   tmp.Name(),
		hasher:    sha256.New(),
	}, nil
}

// Write appends p to the temporary file up to MaxAgentBinaryBytes.
func (w *AgentBinaryCaptureWriter) Write(p []byte) (int, error) {
	if w.tmpFile == nil {
		return 0, errors.New("capture writer is closed")
	}
	if int64(len(p))+w.written > MaxAgentBinaryBytes {
		w.overflow = true
		return 0, fmt.Errorf("agent binary stream exceeds maximum size (%d bytes)", MaxAgentBinaryBytes)
	}
	if len(w.header) < len(elfMagic) {
		need := len(elfMagic) - len(w.header)
		if need > len(p) {
			need = len(p)
		}
		w.header = append(w.header, p[:need]...)
	}
	n, err := w.tmpFile.Write(p)
	if n > 0 {
		_, _ = w.hasher.Write(p[:n])
		w.written += int64(n)
	}
	return n, err
}

// Written returns the number of bytes written to the temporary binary file so far.
func (w *AgentBinaryCaptureWriter) Written() int64 {
	return w.written
}

// Abort closes and deletes the temporary file without updating the cache.
func (w *AgentBinaryCaptureWriter) Abort() {
	if w.tmpFile != nil {
		_ = w.tmpFile.Close()
		w.tmpFile = nil
	}
	if w.tmpPath != "" {
		_ = os.Remove(w.tmpPath)
		w.tmpPath = ""
	}
}

// Commit verifies the captured ELF binary, moves it atomically to $DATA_DIR/agents/bin/<binName>
// with mode 0755, and updates $DATA_DIR/agents/manifest.json.
func (w *AgentBinaryCaptureWriter) Commit(version string) (CachedAgentInfo, error) {
	defer w.Abort()

	if w.tmpFile == nil {
		return CachedAgentInfo{}, errors.New("capture writer already finalized")
	}
	if w.overflow || w.written > MaxAgentBinaryBytes {
		return CachedAgentInfo{}, fmt.Errorf("agent binary exceeds %d bytes", MaxAgentBinaryBytes)
	}
	if w.written < MinAgentBinaryBytes {
		return CachedAgentInfo{}, fmt.Errorf("captured %s binary is too small (%d bytes)", w.agent, w.written)
	}
	if !bytes.Equal(w.header, elfMagic) {
		return CachedAgentInfo{}, fmt.Errorf("captured %s stream is not a valid ELF binary", w.agent)
	}
	if err := w.tmpFile.Chmod(0o755); err != nil {
		return CachedAgentInfo{}, fmt.Errorf("chmod temp %s binary: %w", w.agent, err)
	}
	if err := w.tmpFile.Sync(); err != nil {
		return CachedAgentInfo{}, fmt.Errorf("sync temp %s binary: %w", w.agent, err)
	}
	if err := w.tmpFile.Close(); err != nil {
		return CachedAgentInfo{}, fmt.Errorf("close temp %s binary: %w", w.agent, err)
	}
	w.tmpFile = nil

	cleanVer := sanitizeSingleLineVersion(version)
	info := CachedAgentInfo{
		Agent:     w.agent,
		BinName:   w.binName,
		Version:   cleanVer,
		SHA256:    hex.EncodeToString(w.hasher.Sum(nil)),
		SizeBytes: w.written,
		UpdatedAt: time.Now().UTC().Format(time.RFC3339),
	}

	manifest, err := loadAgentsManifestForUpdate(w.agentsDir)
	if err != nil {
		return CachedAgentInfo{}, err
	}
	manifest.Agents[w.agent] = info

	dstPath := filepath.Join(w.agentsDir, "bin", w.binName)
	if err := os.Rename(w.tmpPath, dstPath); err != nil {
		return CachedAgentInfo{}, fmt.Errorf("install %s binary: %w", w.agent, err)
	}
	w.tmpPath = ""

	if err := saveAgentsManifestAtomic(w.agentsDir, manifest); err != nil {
		return CachedAgentInfo{}, err
	}
	return info, nil
}

// InstallAgentBinaryFromReader streams an ELF binary from r and commits it to $DATA_DIR/agents.
func InstallAgentBinaryFromReader(agentsDir, agent, version string, r io.Reader) (CachedAgentInfo, error) {
	cw, err := NewAgentBinaryCaptureWriter(agentsDir, agent)
	if err != nil {
		return CachedAgentInfo{}, err
	}
	defer cw.Abort()
	if _, err := io.Copy(cw, r); err != nil {
		return CachedAgentInfo{}, err
	}
	return cw.Commit(version)
}

// RemoveCachedAgent deletes one ("antigravity" or "opencode") or "all" cached binaries
// from $DATA_DIR/agents while keeping $DATA_DIR/agents/bin mounted cleanly.
func RemoveCachedAgent(agentsDir, target string) error {
	if agentsDir == "" {
		return nil
	}
	if _, err := os.Lstat(agentsDir); os.IsNotExist(err) {
		return nil
	}
	if err := EnsureAgentsDir(agentsDir); err != nil {
		return err
	}
	manifest, err := loadAgentsManifestForUpdate(agentsDir)
	if err != nil {
		manifest = agentsManifest{Agents: map[string]CachedAgentInfo{}}
	}

	var targets []string
	switch target {
	case "all":
		targets = []string{"antigravity", "opencode"}
	case "antigravity", "opencode":
		targets = []string{target}
	default:
		return fmt.Errorf("unsupported agent %q (expected antigravity, opencode, or all)", target)
	}

	for _, ag := range targets {
		binName, _ := AgentBinName(ag)
		binPath := filepath.Join(agentsDir, "bin", binName)
		if err := os.Remove(binPath); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("remove %s: %w", binPath, err)
		}
		delete(manifest.Agents, ag)
	}
	if len(manifest.Agents) == 0 {
		mPath := filepath.Join(agentsDir, "manifest.json")
		if err := os.Remove(mPath); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("remove %s: %w", mPath, err)
		}
		return nil
	}
	return saveAgentsManifestAtomic(agentsDir, manifest)
}

func loadAgentsManifestForUpdate(agentsDir string) (agentsManifest, error) {
	m := agentsManifest{Agents: map[string]CachedAgentInfo{}}
	mPath := filepath.Join(agentsDir, "manifest.json")
	raw, err := readRegularNoFollow(mPath, MaxAgentsManifestBytes)
	if err != nil {
		if os.IsNotExist(err) {
			return m, nil
		}
		return m, fmt.Errorf("read agents manifest: %w", err)
	}
	if err := json.Unmarshal(raw, &m); err != nil {
		return m, fmt.Errorf("parse agents manifest: %w", err)
	}
	if m.Agents == nil {
		m.Agents = map[string]CachedAgentInfo{}
	}
	return m, nil
}

func saveAgentsManifestAtomic(agentsDir string, m agentsManifest) error {
	raw, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal agents manifest: %w", err)
	}
	raw = append(raw, '\n')
	tmp, err := os.CreateTemp(agentsDir, ".manifest-*")
	if err != nil {
		return fmt.Errorf("create temp manifest: %w", err)
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
	if _, err := tmp.Write(raw); err != nil {
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
	if err := os.Rename(tmpPath, filepath.Join(agentsDir, "manifest.json")); err != nil {
		return fmt.Errorf("save agents manifest: %w", err)
	}
	cleanup = false
	return nil
}

func sanitizeSingleLineVersion(v string) string {
	line, _, _ := strings.Cut(strings.TrimSpace(v), "\n")
	var b strings.Builder
	for _, r := range strings.TrimSpace(line) {
		if r >= 0x20 && r != 0x7f && b.Len() < 128 {
			b.WriteRune(r)
		}
	}
	if b.Len() == 0 {
		return "unknown"
	}
	return b.String()
}

// BuildAgentUpdateScript returns the bash script executed inside the disposable
// agbox-update-<pid> microVM to install or update agent, plus the guest command
// that streams the resulting ELF binary to stdout.
func BuildAgentUpdateScript(agent, openCodeVer, agyURL string) (updateScript string, streamCmd string, verCmd string, err error) {
	switch agent {
	case "antigravity":
		if agyURL == "" {
			agyURL = config.DefaultAgyInstallerURL
		}
		installCmd := fmt.Sprintf(
			"if [ -x /home/agent/.local/bin/agy ]; then /home/agent/.local/bin/agy update || (curl --proto '=https' --tlsv1.2 -fsSL -- %s | bash); else curl --proto '=https' --tlsv1.2 -fsSL -- %s | bash; fi",
			msb.ShellQuote(agyURL),
			msb.ShellQuote(agyURL),
		)
		script := fmt.Sprintf(`set -euo pipefail
su - %s -c %s
test -f /home/agent/.local/bin/agy
test ! -L /home/agent/.local/bin/agy
ln -sfn /home/agent/.local/bin/agy /usr/local/bin/agy
su - %s -c "/home/agent/.local/bin/agy --version" >/tmp/agbox-agy-version.txt
`, config.GuestUser, msb.ShellQuote(installCmd), config.GuestUser)
		return script, "cat /home/agent/.local/bin/agy", "cat /tmp/agbox-agy-version.txt", nil

	case "opencode":
		if openCodeVer == "" {
			openCodeVer = config.DefaultOpenCodeVersion
		}
		script := fmt.Sprintf(`set -euo pipefail
if ! command -v npm >/dev/null 2>&1; then
  echo "npm is not installed in this base snapshot (create-base with 'opencode' or 'both' first)" >&2
  exit 1
fi
npm install -g --no-fund --no-audit %s
bin_path="$(readlink -f "$(command -v opencode)")"
test -f "${bin_path}"
printf '%%s\n' "${bin_path}" >/tmp/agbox-opencode-binpath.txt
su - %s -c "opencode --version" >/tmp/agbox-opencode-version.txt
`, msb.ShellQuote("opencode-ai@"+openCodeVer), config.GuestUser)
		return script, `cat "$(cat /tmp/agbox-opencode-binpath.txt)"`, "cat /tmp/agbox-opencode-version.txt", nil

	default:
		return "", "", "", fmt.Errorf("unsupported agent %q", agent)
	}
}

// BuildGuestAgentsMountScript returns the root-executed POSIX shell script that
// bind-mounts cached agent binaries from GuestAgentsMount read-only (ro,bind)
// onto /home/agent/.local/bin/agy, /usr/local/bin/agy, and /usr/local/bin/opencode.
func BuildGuestAgentsMountScript() string {
	return fmt.Sprintf(`set -eu
src=%s
umount /home/agent/.local/bin/agy 2>/dev/null || true
umount /usr/local/bin/opencode 2>/dev/null || true

if [ -f /usr/local/bin/opencode ] && [ ! -L /usr/local/bin/opencode ] && [ ! -s /usr/local/bin/opencode ] && [ -x /usr/local/lib/node_modules/opencode-ai/bin/opencode.exe ]; then
  ln -sfn ../lib/node_modules/opencode-ai/bin/opencode.exe /usr/local/bin/opencode
fi

if [ -f "$src/bin/agy" ] && [ ! -L "$src/bin/agy" ]; then
  mkdir -p /home/agent/.local/bin
  chown 1000:1000 /home/agent/.local/bin
  if [ -L /home/agent/.local/bin/agy ] || [ ! -f /home/agent/.local/bin/agy ]; then
    rm -f /home/agent/.local/bin/agy
    install -m 0755 -o 1000 -g 1000 /dev/null /home/agent/.local/bin/agy
  fi
  mount --bind "$src/bin/agy" /home/agent/.local/bin/agy
  mount -o remount,ro,bind /home/agent/.local/bin/agy 2>/dev/null || true
  ln -sfn /home/agent/.local/bin/agy /usr/local/bin/agy
fi

if [ -f "$src/bin/opencode" ] && [ ! -L "$src/bin/opencode" ]; then
  if [ -L /usr/local/bin/opencode ] || [ ! -f /usr/local/bin/opencode ]; then
    rm -f /usr/local/bin/opencode
    install -m 0755 /dev/null /usr/local/bin/opencode
  fi
  mount --bind "$src/bin/opencode" /usr/local/bin/opencode
  mount -o remount,ro,bind /usr/local/bin/opencode 2>/dev/null || true
fi
`, msb.ShellQuote(msb.GuestAgentsMount))
}
