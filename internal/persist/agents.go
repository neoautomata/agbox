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
	maxAgentBinaryBytes    = 1024 * 1024 * 1024
	minAgentBinaryBytes    = 64
	maxAgentsManifestBytes = 64 * 1024
)

var elfMagic = []byte{0x7f, 'E', 'L', 'F'}

// CachedAgentInfo describes one checked agent binary stored in $DATA_DIR/agents.
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

func agentBinName(agent string) (string, error) {
	for _, entry := range supportedAgents {
		if entry.agent == agent {
			return entry.binName, nil
		}
	}
	return "", fmt.Errorf("unsupported agent %q (expected antigravity or opencode)", agent)
}

func agentFromBinName(binName string) (string, bool) {
	for _, entry := range supportedAgents {
		if entry.binName == binName {
			return entry.agent, true
		}
	}
	return "", false
}

func lockAgentsCache(agentsDir string) (*os.File, error) {
	dataDir := filepath.Dir(agentsDir)
	if err := config.EnsurePrivateDir(dataDir); err != nil {
		return nil, err
	}
	lockPath := filepath.Join(dataDir, ".agents.lock")
	if info, sErr := os.Lstat(lockPath); sErr == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("refusing symlinked agents lock %s", lockPath)
		}
		if !info.Mode().IsRegular() {
			return nil, fmt.Errorf("refusing non-regular agents lock %s", lockPath)
		}
	}
	fd, err := syscall.Open(lockPath, syscall.O_CREAT|syscall.O_RDWR|syscall.O_NOFOLLOW|syscall.O_CLOEXEC|syscall.O_NONBLOCK, 0o600)
	if err != nil {
		if errors.Is(err, syscall.ELOOP) {
			return nil, fmt.Errorf("refusing symlinked agents lock %s", lockPath)
		}
		return nil, fmt.Errorf("open agents lock %s: %w", lockPath, err)
	}
	f := os.NewFile(uintptr(fd), lockPath)
	st, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("stat agents lock %s: %w", lockPath, err)
	}
	if !st.Mode().IsRegular() {
		_ = f.Close()
		return nil, fmt.Errorf("refusing non-regular agents lock %s", lockPath)
	}
	if err := syscall.Flock(fd, syscall.LOCK_EX); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("lock agents cache: %w", err)
	}
	return f, nil
}

func lockAgentsCacheSharedIfExists(agentsDir string) (*os.File, error) {
	lockPath := filepath.Join(filepath.Dir(agentsDir), ".agents.lock")
	fd, err := syscall.Open(lockPath, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC|syscall.O_NONBLOCK, 0)
	if err != nil {
		if errors.Is(err, syscall.ENOENT) {
			return nil, nil
		}
		if errors.Is(err, syscall.ELOOP) {
			return nil, fmt.Errorf("refusing symlinked agents lock %s", lockPath)
		}
		return nil, fmt.Errorf("open agents lock %s: %w", lockPath, err)
	}
	f := os.NewFile(uintptr(fd), lockPath)
	st, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("stat agents lock %s: %w", lockPath, err)
	}
	if !st.Mode().IsRegular() {
		_ = f.Close()
		return nil, fmt.Errorf("refusing non-regular agents lock %s", lockPath)
	}
	if err := syscall.Flock(fd, syscall.LOCK_SH); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("lock agents cache: %w", err)
	}
	return f, nil
}

func unlockAgentsCache(f *os.File) {
	if f == nil {
		return
	}
	_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
	_ = f.Close()
}

// EnsureAgentsDir creates $DATA_DIR/agents (0700) and $DATA_DIR/agents/bin (0755).
// It rejects symlinks, control characters, and mount delimiters.
func EnsureAgentsDir(agentsDir string) error {
	if err := validateMountDir(agentsDir, "agents"); err != nil {
		return err
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
	dirFD, err := syscall.Open(binDir, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("open agents bin dir %q: %w", binDir, err)
	}
	defer syscall.Close(dirFD)
	if err := syscall.Fchmod(dirFD, 0o755); err != nil {
		return fmt.Errorf("chmod agents bin dir %q: %w", binDir, err)
	}
	return nil
}

// InspectAgentsDir checks $DATA_DIR/agents and returns sorted metadata for cached binaries.
// It fails closed on symlinks, unexpected entries, hardlinks, non-ELF files, or SHA-256 mismatches.
func InspectAgentsDir(agentsDir string) ([]CachedAgentInfo, error) {
	if agentsDir == "" {
		return nil, nil
	}
	if err := validateMountDir(agentsDir, "agents"); err != nil {
		return nil, err
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

	lockFile, err := lockAgentsCacheSharedIfExists(agentsDir)
	if err != nil {
		return nil, err
	}
	defer unlockAgentsCache(lockFile)

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
			if st.Size() > maxAgentsManifestBytes {
				return nil, fmt.Errorf("agents manifest %s exceeds %d bytes", full, maxAgentsManifestBytes)
			}
			hasManifest = true
		default:
			return nil, fmt.Errorf("unexpected entry %q in agents directory %s", name, agentsDir)
		}
	}

	manifest := agentsManifest{Agents: map[string]CachedAgentInfo{}}
	if hasManifest {
		mPath := filepath.Join(agentsDir, "manifest.json")
		mBytes, err := readRegularNoFollow(mPath, maxAgentsManifestBytes)
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
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC|syscall.O_NONBLOCK, 0)
	if err != nil {
		if errors.Is(err, syscall.ELOOP) {
			return "", 0, fmt.Errorf("refusing symlinked agent binary %s", path)
		}
		if info, lErr := os.Lstat(path); lErr == nil && info.Mode()&os.ModeSymlink != 0 {
			return "", 0, fmt.Errorf("refusing symlinked agent binary %s", path)
		}
		return "", 0, fmt.Errorf("open %s: %w", path, err)
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return "", 0, fmt.Errorf("stat %s: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return "", 0, fmt.Errorf("refusing non-regular agent binary %s", path)
	}
	if info.Size() < minAgentBinaryBytes || info.Size() > maxAgentBinaryBytes {
		return "", 0, fmt.Errorf("agent binary %s has invalid size %d bytes", path, info.Size())
	}
	if st, ok := info.Sys().(*syscall.Stat_t); ok && st.Nlink != 1 {
		return "", 0, fmt.Errorf("refusing hardlinked agent binary %s (nlink=%d)", path, st.Nlink)
	}

	var hdr [4]byte
	if _, err := io.ReadFull(f, hdr[:]); err != nil {
		return "", 0, fmt.Errorf("read ELF header of %s: %w", path, err)
	}
	if !bytes.Equal(hdr[:], elfMagic) {
		return "", 0, fmt.Errorf("agent binary %s is not a valid ELF executable", path)
	}

	h := sha256.New()
	_, _ = h.Write(hdr[:])
	nRest, err := io.Copy(h, io.LimitReader(f, maxAgentBinaryBytes))
	if err != nil {
		return "", 0, fmt.Errorf("hash %s: %w", path, err)
	}
	total := int64(len(hdr)) + nRest
	if total != info.Size() {
		return "", 0, fmt.Errorf("size changed while verifying %s", path)
	}
	return hex.EncodeToString(h.Sum(nil)), total, nil
}

// AgentBinaryCaptureWriter streams a binary into a private staging file on the host.
// It enforces maxAgentBinaryBytes and computes the SHA-256 digest.
type AgentBinaryCaptureWriter struct {
	Now       func() time.Time
	syncDir   func(string) error
	agentsDir string
	agent     string
	binName   string
	stageDir  string
	tmpFile   *os.File
	tmpPath   string
	hasher    hash.Hash
	header    []byte
	written   int64
	overflow  bool
}

// NewAgentBinaryCaptureWriter creates a temporary file inside $DATA_DIR/.agbox-stage-*
// to receive a streamed ELF binary for agent.
func NewAgentBinaryCaptureWriter(agentsDir, agent string) (*AgentBinaryCaptureWriter, error) {
	binName, err := agentBinName(agent)
	if err != nil {
		return nil, err
	}
	if err := EnsureAgentsDir(agentsDir); err != nil {
		return nil, err
	}
	stageParent := filepath.Dir(agentsDir)
	if err := config.EnsurePrivateDir(stageParent); err != nil {
		return nil, err
	}
	stageDir, err := os.MkdirTemp(stageParent, ".agbox-stage-*")
	if err != nil {
		return nil, fmt.Errorf("create staging directory: %w", err)
	}
	tmp, err := os.CreateTemp(stageDir, ".tmp-"+binName+"-*")
	if err != nil {
		_ = os.RemoveAll(stageDir)
		return nil, fmt.Errorf("create temp agent binary: %w", err)
	}
	if err := tmp.Chmod(0o600); err != nil {
		tmpName := tmp.Name()
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		_ = os.RemoveAll(stageDir)
		return nil, err
	}
	return &AgentBinaryCaptureWriter{
		Now:       time.Now,
		agentsDir: agentsDir,
		agent:     agent,
		binName:   binName,
		stageDir:  stageDir,
		tmpFile:   tmp,
		tmpPath:   tmp.Name(),
		hasher:    sha256.New(),
	}, nil
}

// Write appends p to the temporary file up to maxAgentBinaryBytes.
func (w *AgentBinaryCaptureWriter) Write(p []byte) (int, error) {
	if w.tmpFile == nil {
		return 0, errors.New("capture writer closed")
	}
	if int64(len(p))+w.written > maxAgentBinaryBytes {
		w.overflow = true
		return 0, fmt.Errorf("agent binary stream exceeds %d bytes", maxAgentBinaryBytes)
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

// Written returns the number of bytes written to the temporary binary file.
func (w *AgentBinaryCaptureWriter) Written() int64 {
	return w.written
}

// Abort closes and deletes the temporary staging files without modifying the cache.
func (w *AgentBinaryCaptureWriter) Abort() {
	if w.tmpFile != nil {
		_ = w.tmpFile.Close()
		w.tmpFile = nil
	}
	if w.tmpPath != "" {
		_ = os.Remove(w.tmpPath)
		w.tmpPath = ""
	}
	if w.stageDir != "" {
		_ = os.RemoveAll(w.stageDir)
		w.stageDir = ""
	}
}

// Commit checks the captured ELF binary, replaces $DATA_DIR/agents/bin/<binName>
// atomically at mode 0755, and updates $DATA_DIR/agents/manifest.json under flock.
func (w *AgentBinaryCaptureWriter) Commit(version string) (CachedAgentInfo, error) {
	defer w.Abort()

	if w.tmpFile == nil {
		return CachedAgentInfo{}, errors.New("capture writer already closed")
	}
	if w.overflow || w.written > maxAgentBinaryBytes {
		return CachedAgentInfo{}, fmt.Errorf("agent binary exceeds %d bytes", maxAgentBinaryBytes)
	}
	if w.written < minAgentBinaryBytes {
		return CachedAgentInfo{}, fmt.Errorf("captured %s binary is smaller than %d bytes (%d)", w.agent, minAgentBinaryBytes, w.written)
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

	lockFile, err := lockAgentsCache(w.agentsDir)
	if err != nil {
		return CachedAgentInfo{}, err
	}
	defer unlockAgentsCache(lockFile)

	nowFn := w.Now
	if nowFn == nil {
		nowFn = time.Now
	}
	cleanVer := sanitizeSingleLineVersion(version)
	info := CachedAgentInfo{
		Agent:     w.agent,
		BinName:   w.binName,
		Version:   cleanVer,
		SHA256:    hex.EncodeToString(w.hasher.Sum(nil)),
		SizeBytes: w.written,
		UpdatedAt: nowFn().UTC().Format(time.RFC3339),
	}

	manifest, err := loadAgentsManifestForUpdate(w.agentsDir)
	if err != nil {
		return CachedAgentInfo{}, err
	}
	manifest.Agents[w.agent] = info

	dstPath := filepath.Join(w.agentsDir, "bin", w.binName)
	backupPath := ""
	dstInfo, statErr := os.Lstat(dstPath)
	dstExisted := statErr == nil
	if statErr != nil && !os.IsNotExist(statErr) {
		return CachedAgentInfo{}, statErr
	}
	if dstExisted {
		if dstInfo.Mode()&os.ModeSymlink != 0 || !dstInfo.Mode().IsRegular() {
			return CachedAgentInfo{}, fmt.Errorf("refusing non-regular existing binary %s", dstPath)
		}
		backupPath = filepath.Join(w.stageDir, ".backup-"+w.binName)
		if err := copyBinaryForBackup(dstPath, backupPath); err != nil {
			return CachedAgentInfo{}, fmt.Errorf("save backup of existing %s binary: %w", w.agent, err)
		}
	}

	rollbackBinary := func(err error) error {
		outErr := err
		if dstExisted {
			if rbErr := os.Rename(backupPath, dstPath); rbErr != nil {
				outErr = errors.Join(outErr, fmt.Errorf("restore %s binary backup: %w", w.agent, rbErr))
			}
		} else {
			if rmErr := os.Remove(dstPath); rmErr != nil && !os.IsNotExist(rmErr) {
				outErr = errors.Join(outErr, fmt.Errorf("remove uncommitted %s binary: %w", w.agent, rmErr))
			}
		}
		return outErr
	}

	if err := os.Rename(w.tmpPath, dstPath); err != nil {
		return CachedAgentInfo{}, fmt.Errorf("install %s binary: %w", w.agent, err)
	}
	w.tmpPath = ""
	syncFn := w.syncDir
	if syncFn == nil {
		syncFn = syncParentDir
	}
	if err := syncFn(filepath.Dir(dstPath)); err != nil {
		return CachedAgentInfo{}, rollbackBinary(err)
	}

	if err := saveAgentsManifestAtomic(w.agentsDir, manifest); err != nil {
		return CachedAgentInfo{}, rollbackBinary(err)
	}
	return info, nil
}

func copyBinaryForBackup(srcPath, dstPath string) error {
	fd, err := syscall.Open(srcPath, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC|syscall.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	in := os.NewFile(uintptr(fd), srcPath)
	defer in.Close()

	st, err := in.Stat()
	if err != nil {
		return err
	}
	if !st.Mode().IsRegular() {
		return fmt.Errorf("refusing non-regular source %s", srcPath)
	}
	out, err := os.OpenFile(dstPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o755)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, io.LimitReader(in, maxAgentBinaryBytes)); err != nil {
		_ = out.Close()
		return err
	}
	if err := out.Chmod(0o755); err != nil {
		_ = out.Close()
		return err
	}
	if err := out.Sync(); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}

func installAgentBinaryFromReader(agentsDir, agent, version string, r io.Reader) (CachedAgentInfo, error) {
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
// from $DATA_DIR/agents without recreating $DATA_DIR/agents/bin.
func RemoveCachedAgent(agentsDir, target string) error {
	var targets []string
	switch {
	case target == "all":
		targets = supportedAgentNames()
	case isSupportedAgent(target):
		targets = []string{target}
	default:
		return fmt.Errorf("unsupported agent %q (expected antigravity, opencode, or all)", target)
	}
	if agentsDir == "" {
		return nil
	}
	if err := validateMountDir(agentsDir, "agents"); err != nil {
		return err
	}
	rootInfo, err := os.Lstat(agentsDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("stat agents dir %q: %w", agentsDir, err)
	}
	if rootInfo.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("refusing symlinked agents directory %q", agentsDir)
	}
	if !rootInfo.IsDir() {
		return fmt.Errorf("agents path %q is not a directory", agentsDir)
	}
	binDir := filepath.Join(agentsDir, "bin")
	if binInfo, bErr := os.Lstat(binDir); bErr == nil {
		if binInfo.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("refusing symlinked agents bin directory %q", binDir)
		}
		if !binInfo.IsDir() {
			return fmt.Errorf("agents bin path %q is not a directory", binDir)
		}
	} else if !os.IsNotExist(bErr) {
		return fmt.Errorf("stat agents bin dir %q: %w", binDir, bErr)
	}

	lockFile, err := lockAgentsCache(agentsDir)
	if err != nil {
		return err
	}
	defer unlockAgentsCache(lockFile)

	manifest, err := loadAgentsManifestForUpdate(agentsDir)
	if err != nil {
		if target != "all" {
			return err
		}
		manifest = agentsManifest{Agents: map[string]CachedAgentInfo{}}
	}

	for _, ag := range targets {
		binName, _ := agentBinName(ag)
		binPath := filepath.Join(binDir, binName)
		if info, lErr := os.Lstat(binPath); lErr == nil {
			if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
				return fmt.Errorf("refusing non-regular cached binary %s", binPath)
			}
			if err := os.Remove(binPath); err != nil && !os.IsNotExist(err) {
				return fmt.Errorf("remove %s: %w", binPath, err)
			}
		} else if !os.IsNotExist(lErr) {
			return fmt.Errorf("stat %s: %w", binPath, lErr)
		}
		delete(manifest.Agents, ag)
	}
	if len(manifest.Agents) == 0 {
		mPath := filepath.Join(agentsDir, "manifest.json")
		if info, lErr := os.Lstat(mPath); lErr == nil {
			if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
				return fmt.Errorf("refusing non-regular agents manifest %s", mPath)
			}
			if err := os.Remove(mPath); err != nil && !os.IsNotExist(err) {
				return fmt.Errorf("remove %s: %w", mPath, err)
			}
		} else if !os.IsNotExist(lErr) {
			return fmt.Errorf("stat %s: %w", mPath, lErr)
		}
		return nil
	}
	return saveAgentsManifestAtomic(agentsDir, manifest)
}

func loadAgentsManifestForUpdate(agentsDir string) (agentsManifest, error) {
	m := agentsManifest{Agents: map[string]CachedAgentInfo{}}
	mPath := filepath.Join(agentsDir, "manifest.json")
	raw, err := readRegularNoFollow(mPath, maxAgentsManifestBytes)
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
	if err := writeModeFileAtomic(filepath.Join(agentsDir, "manifest.json"), raw, 0o600); err != nil {
		return fmt.Errorf("save agents manifest: %w", err)
	}
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

// BuildAgentUpdateScript builds the script to update an agent inside a disposable sandbox.
// It also returns guest commands that stream the ELF binary and read its version.
func BuildAgentUpdateScript(agent, openCodeVer, agyURL string) (updateScript string, streamCmd string, verCmd string, err error) {
	switch agent {
	case "antigravity":
		if agyURL == "" {
			agyURL = config.DefaultAgyInstallerURL
		}
		installCmd := fmt.Sprintf(
			"set -o pipefail; if [ -x /home/agent/.local/bin/agy ]; then /home/agent/.local/bin/agy update || (curl --proto '=https' --proto-redir '=https' --tlsv1.2 -fsSL -- %s | bash); else curl --proto '=https' --proto-redir '=https' --tlsv1.2 -fsSL -- %s | bash; fi",
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
  echo "This base snapshot does not contain npm. Run 'agbox create-base opencode' or 'agbox create-base both'." >&2
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

// BuildGuestAgentsMountScript returns a root sh script that bind-mounts cached binaries read-only.
func BuildGuestAgentsMountScript() string {
	return fmt.Sprintf(`set -eu
src=%s
umount /home/agent/.local/bin/agy 2>/dev/null || true
umount /usr/local/bin/opencode 2>/dev/null || true

if [ -f /home/agent/.local/bin/agy ] && [ ! -L /home/agent/.local/bin/agy ] && [ ! -s /home/agent/.local/bin/agy ]; then
  rm -f /home/agent/.local/bin/agy
fi
if [ -L /usr/local/bin/agy ] && [ ! -e /usr/local/bin/agy ]; then
  rm -f /usr/local/bin/agy
fi

if [ -f /usr/local/bin/opencode ] && [ ! -L /usr/local/bin/opencode ] && [ ! -s /usr/local/bin/opencode ]; then
  if [ -x /usr/local/lib/node_modules/opencode-ai/bin/opencode ]; then
    ln -sfn ../lib/node_modules/opencode-ai/bin/opencode /usr/local/bin/opencode
  elif [ -x /usr/local/lib/node_modules/opencode-ai/bin/opencode.exe ]; then
    ln -sfn ../lib/node_modules/opencode-ai/bin/opencode.exe /usr/local/bin/opencode
  fi
fi

if [ -f "$src/bin/agy" ] && [ ! -L "$src/bin/agy" ]; then
  mkdir -p /home/agent/.local/bin
  chown 1000:1000 /home/agent/.local/bin
  if [ -L /home/agent/.local/bin/agy ] || [ ! -f /home/agent/.local/bin/agy ]; then
    rm -f /home/agent/.local/bin/agy
    install -m 0755 -o 1000 -g 1000 /dev/null /home/agent/.local/bin/agy
  fi
  mount --bind "$src/bin/agy" /home/agent/.local/bin/agy
  mount -o remount,ro,bind /home/agent/.local/bin/agy
  ln -sfn /home/agent/.local/bin/agy /usr/local/bin/agy
fi

if [ -f "$src/bin/opencode" ] && [ ! -L "$src/bin/opencode" ]; then
  if [ -L /usr/local/bin/opencode ] || [ ! -f /usr/local/bin/opencode ]; then
    rm -f /usr/local/bin/opencode
    install -m 0755 /dev/null /usr/local/bin/opencode
  fi
  mount --bind "$src/bin/opencode" /usr/local/bin/opencode
  mount -o remount,ro,bind /usr/local/bin/opencode
fi
`, msb.ShellQuote(msb.GuestAgentsMount))
}
