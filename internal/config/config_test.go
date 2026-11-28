package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) {
	return 0, errors.New("simulated read error")
}

func TestParseMaskMode(t *testing.T) {
	cases := []struct {
		in      string
		want    MaskMode
		wantErr bool
	}{
		{"", MaskStrict, false},
		{"auto", MaskAuto, false},
		{"AUTO", MaskAuto, false},
		{"strict", MaskStrict, false},
		{"1", MaskStrict, false},
		{"true", MaskStrict, false},
		{"yes", MaskStrict, false},
		{"off", MaskOff, false},
		{"0", MaskOff, false},
		{"false", MaskOff, false},
		{"no", MaskOff, false},
		{"invalid", "", true},
	}
	for _, tc := range cases {
		got, err := ParseMaskMode(tc.in)
		if (err != nil) != tc.wantErr {
			t.Errorf("ParseMaskMode(%q) err = %v, wantErr %v", tc.in, err, tc.wantErr)
		}
		if got != tc.want {
			t.Errorf("ParseMaskMode(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestFromLookupDefaultsAndOverrides(t *testing.T) {
	env, err := FromLookup("/home/alice/", func(string) string { return "" })
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if env.HomeReal != "/home/alice" {
		t.Errorf("HomeReal = %q, want /home/alice", env.HomeReal)
	}
	if env.DataDir != "/home/alice/.local/share/agbox" {
		t.Errorf("DataDir = %q", env.DataDir)
	}
	if env.CPUs != DefaultCPUs || env.Memory != DefaultMemory || env.RootDisk != DefaultRootDisk || env.ProfileDisk != DefaultProfileDisk {
		t.Errorf("unexpected defaults: %+v", env)
	}
	if env.MaskVCS != MaskStrict || env.AllowOutsideHome || env.AllowRoot || !env.RemoteDefault {
		t.Errorf("unexpected security defaults: %+v", env)
	}

	envRemoteOff, err := FromLookup("/home/alice", func(k string) string {
		if k == "AGBOX_REMOTE" {
			return "0"
		}
		return ""
	})
	if err != nil || envRemoteOff.RemoteDefault {
		t.Errorf("FromLookup(AGBOX_REMOTE=0) = (%+v, %v), want RemoteDefault=false", envRemoteOff, err)
	}
	envRemoteOn, err := FromLookup("/home/alice", func(k string) string {
		if k == "AGBOX_REMOTE" {
			return "1"
		}
		return ""
	})
	if err != nil || !envRemoteOn.RemoteDefault {
		t.Errorf("FromLookup(AGBOX_REMOTE=1) = (%+v, %v), want RemoteDefault=true", envRemoteOn, err)
	}

	overrides := map[string]string{
		"AGBOX_DATA_DIR":           "/custom/data/",
		"MSB_HOME":                 "/custom/msb/",
		"AGBOX_CPUS":               "04",
		"AGBOX_MEMORY":             "8G",
		"AGBOX_ROOT_DISK":          "16G",
		"AGBOX_PROFILE_DISK":       "20G",
		"AGBOX_OPENCODE_VERSION":   "1.19.5",
		"AGBOX_AGY_INSTALLER_URL":  "https://example.com/install.sh",
		"AGBOX_MASK_VCS":           "auto",
		"AGBOX_ALLOW_OUTSIDE_HOME": "1",
		"AGBOX_ALLOW_ROOT":         "1",
	}
	env2, err := FromLookup("/home/alice", func(k string) string { return overrides[k] })
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if env2.DataDir != "/custom/data" || env2.MSBHome != "/custom/msb" {
		t.Errorf("paths not cleaned: DataDir=%q MSBHome=%q", env2.DataDir, env2.MSBHome)
	}
	if env2.CPUs != "4" || env2.Memory != "8G" || env2.RootDisk != "16G" || env2.ProfileDisk != "20G" {
		t.Errorf("resource overrides failed: %+v", env2)
	}
	if env2.MaskVCS != MaskAuto || !env2.AllowOutsideHome || !env2.AllowRoot {
		t.Errorf("policy overrides failed: %+v", env2)
	}

	if _, err := FromLookup("", func(string) string { return "" }); err == nil {
		t.Errorf("expected error for empty homeReal")
	}
	if _, err := FromLookup("/home/alice", func(k string) string {
		if k == "AGBOX_MASK_VCS" {
			return "bad-mode"
		}
		return ""
	}); err == nil {
		t.Errorf("expected error for invalid AGBOX_MASK_VCS")
	}

	invalidEnvCases := []map[string]string{
		{"AGBOX_CPUS": "0"},
		{"AGBOX_CPUS": "-2"},
		{"AGBOX_CPUS": "+4"},
		{"AGBOX_CPUS": "abc"},
		{"AGBOX_MEMORY": "0G"},
		{"AGBOX_MEMORY": "+8G"},
		{"AGBOX_MEMORY": "4096"},
		{"AGBOX_MEMORY": "-v /:/mnt"},
		{"AGBOX_ROOT_DISK": "0M"},
		{"AGBOX_ROOT_DISK": "+50G"},
		{"AGBOX_ROOT_DISK": "bad"},
		{"AGBOX_PROFILE_DISK": "0G"},
		{"AGBOX_PROFILE_DISK": "+10G"},
		{"AGBOX_PROFILE_DISK": "bad"},
		{"AGBOX_OPENCODE_VERSION": "latest; id"},
		{"AGBOX_OPENCODE_VERSION": "1.0\nrm"},
		{"AGBOX_OPENCODE_VERSION": "1.0\x01"},
		{"AGBOX_OPENCODE_VERSION": "1.0\x7f"},
		{"AGBOX_OPENCODE_VERSION": "1.0\u200B"},
		{"AGBOX_OPENCODE_VERSION": "1.0\uFEFF"},
		{"AGBOX_AGY_INSTALLER_URL": "http://example.com/install.sh"},
		{"AGBOX_AGY_INSTALLER_URL": "file:///etc/passwd"},
		{"AGBOX_AGY_INSTALLER_URL": "https://example.com/a b"},
		{"AGBOX_AGY_INSTALLER_URL": "-K /tmp/curlrc"},
		{"AGBOX_AGY_INSTALLER_URL": "https://example.com/install.sh;id"},
		{"AGBOX_AGY_INSTALLER_URL": "https://example.com/install.sh&whoami"},
		{"AGBOX_AGY_INSTALLER_URL": "https://example.com/install.sh|cat"},
		{"AGBOX_AGY_INSTALLER_URL": "https://example.com/`id`"},
		{"AGBOX_AGY_INSTALLER_URL": "https://example.com/$VAR"},
		{"AGBOX_AGY_INSTALLER_URL": "https://example.com/\"test\""},
		{"AGBOX_AGY_INSTALLER_URL": "https://example.com/'test'"},
		{"AGBOX_AGY_INSTALLER_URL": "https://example.com/\\test"},
		{"AGBOX_AGY_INSTALLER_URL": "https://example.com/(test)"},
		{"AGBOX_AGY_INSTALLER_URL": "https://example.com/<test>"},
		{"AGBOX_AGY_INSTALLER_URL": "https://example.com/test\x7f"},
		{"AGBOX_AGY_INSTALLER_URL": "https://example.com/test\u200B"},
		{"AGBOX_AGY_INSTALLER_URL": "https://example.com/test\u202A"},
		{"AGBOX_AGY_INSTALLER_URL": "https://example.com/test\u2066"},
		{"AGBOX_AGY_INSTALLER_URL": "https://example.com/test\uFEFF"},
		{"AGBOX_AGY_INSTALLER_URL": "https:///"},
		{"AGBOX_DATA_DIR": "relative/data"},
		{"MSB_HOME": "relative/msb"},
	}
	for _, badMap := range invalidEnvCases {
		if _, err := FromLookup("/home/alice", func(k string) string { return badMap[k] }); err == nil {
			t.Errorf("expected error for invalid env override %v", badMap)
		}
	}
}

func TestFromLookupCanonicalizesSymlinkAncestors(t *testing.T) {
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	realRoot := filepath.Join(base, "real")
	if err := os.MkdirAll(realRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	symRoot := filepath.Join(base, "sym")
	if err := os.Symlink(realRoot, symRoot); err != nil {
		t.Fatal(err)
	}
	// Chained symlink pointing into a subdirectory of realRoot that does not exist yet.
	danglingSym := filepath.Join(base, "dangling-sym")
	if err := os.Symlink("real/future-parent", danglingSym); err != nil {
		t.Fatal(err)
	}

	env, err := FromLookup(realRoot, func(k string) string {
		switch k {
		case "AGBOX_DATA_DIR":
			return filepath.Join(symRoot, "nonexistent", "agbox-data")
		case "MSB_HOME":
			return filepath.Join(danglingSym, "msb-home")
		default:
			return ""
		}
	})
	if err != nil {
		t.Fatalf("FromLookup failed: %v", err)
	}

	wantData := filepath.Join(realRoot, "nonexistent", "agbox-data")
	if env.DataDir != wantData {
		t.Errorf("DataDir = %q, want %q", env.DataDir, wantData)
	}
	wantMSB := filepath.Join(realRoot, "future-parent", "msb-home")
	if env.MSBHome != wantMSB {
		t.Errorf("MSBHome = %q, want %q", env.MSBHome, wantMSB)
	}

	// Self-referential symlink loop terminates cleanly without hanging.
	loopA := filepath.Join(base, "loopA")
	loopB := filepath.Join(base, "loopB")
	_ = os.Symlink(loopB, loopA)
	_ = os.Symlink(loopA, loopB)
	if got := resolveLongestExistingAncestor(filepath.Join(loopA, "data")); got == "" {
		t.Error("expected non-empty fallback path on symlink loop")
	}
}

func TestParseFormatAndSaveLoadFile(t *testing.T) {
	orig := State{
		Agent:      "both",
		Image:      "node:24-bookworm-slim",
		Snapshot:   "agbox:v3",
		SnapCount:  3,
		CPUs:       "2",
		Memory:     "2G",
		RootDisk:   "8G",
		Categories: "go,rust",
	}
	formatted := Format(orig)
	parsed, err := Parse(strings.NewReader("# comment\n\n" + formatted + "malformed_line\nsnap_count=-5\nsnap_count=nan\n"))
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	if parsed != orig {
		t.Errorf("roundtrip mismatch: got %+v, want %+v", parsed, orig)
	}

	if _, err := Parse(failingReader{}); err == nil {
		t.Error("expected Parse to propagate reader error")
	}

	whitespaceCfg := "  agent  =  agy  \n  cpus =  8 \n  memory  = 16G \n snap_count = 10 \n "
	wsParsed, err := Parse(strings.NewReader(whitespaceCfg))
	if err != nil {
		t.Fatalf("Parse with whitespace failed: %v", err)
	}
	if wsParsed.Agent != "agy" || wsParsed.CPUs != "8" || wsParsed.Memory != "16G" || wsParsed.SnapCount != 10 {
		t.Errorf("unexpected parsed state from whitespace config: %+v", wsParsed)
	}

	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "sub", "config")
	if err := SaveFile(cfgPath, orig); err != nil {
		t.Fatalf("SaveFile failed: %v", err)
	}
	loaded, err := LoadFile(cfgPath)
	if err != nil {
		t.Fatalf("LoadFile failed: %v", err)
	}
	if loaded != orig {
		t.Errorf("LoadFile = %+v, want %+v", loaded, orig)
	}
	info, err := os.Stat(cfgPath)
	if err != nil {
		t.Fatalf("Stat failed: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("config file mode = %o, want 0600", info.Mode().Perm())
	}

	// Missing file preserves os.IsNotExist.
	if _, err := LoadFile(filepath.Join(tmpDir, "missing-config")); !os.IsNotExist(err) {
		t.Errorf("expected os.IsNotExist on missing config, got %v", err)
	}

	// LoadFile rejects directory, symlink, empty path, and oversized file.
	if _, err := LoadFile(""); err == nil {
		t.Error("expected LoadFile(\"\") to fail")
	}
	if _, err := LoadFile(tmpDir); err == nil {
		t.Error("expected LoadFile on directory to fail")
	}
	symCfg := filepath.Join(tmpDir, "sym-config")
	if err := os.Symlink(cfgPath, symCfg); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadFile(symCfg); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Errorf("expected LoadFile on symlink to fail, got %v", err)
	}
	bigCfg := filepath.Join(tmpDir, "big-config")
	if err := os.WriteFile(bigCfg, []byte(strings.Repeat("a", maxStateFileBytes+10)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadFile(bigCfg); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Errorf("expected LoadFile on oversized file to fail, got %v", err)
	}
}

func TestNextSnapshotMember(t *testing.T) {
	n0, ref0 := NextSnapshotMember(-3, nil, "agbox")
	if n0 != 1 || ref0 != "agbox:v1" {
		t.Errorf("got (%d, %q), want (1, agbox:v1)", n0, ref0)
	}

	n, ref := NextSnapshotMember(0, nil, "agbox")
	if n != 1 || ref != "agbox:v1" {
		t.Errorf("got (%d, %q), want (1, agbox:v1)", n, ref)
	}

	// Existing snapshots in msb exceed recorded count.
	n2, ref2 := NextSnapshotMember(1, []string{"other:v9", "agbox:v1", "agbox:v4", "agbox:notnum"}, "agbox")
	if n2 != 5 || ref2 != "agbox:v5" {
		t.Errorf("got (%d, %q), want (5, agbox:v5)", n2, ref2)
	}

	// Recorded count exceeds existing snapshots.
	n3, ref3 := NextSnapshotMember(6, []string{"agbox:v2"}, "agbox")
	if n3 != 7 || ref3 != "agbox:v7" {
		t.Errorf("got (%d, %q), want (7, agbox:v7)", n3, ref3)
	}
}

func TestRunMetaRoundTripAndValidation(t *testing.T) {
	orig := RunMeta{
		Sandbox:         "agbox-feat1",
		OwnerPID:        4242,
		Agent:           "opencode",
		Mode:            RunModeServe,
		Detached:        true,
		RemoteControl:   false,
		Port:            4096,
		ReadOnly:        true,
		MaskMode:        MaskStrict,
		Persist:         true,
		Profile:         "work",
		Continue:        true,
		ContinueSession: "sess-123",
		NoAuth:          true,
		NoSkills:        true,
		SkillsMounted:   true,
		Shares: []ShareRecord{
			{Index: 0, HostPath: "/home/alice/proj", GuestName: "proj", IsDir: true, Masked: true},
			{Index: 1, HostPath: "/home/alice/notes.md", GuestName: "notes.md", IsDir: false, Masked: false},
		},
	}

	tmpDir := t.TempDir()
	metaPath := filepath.Join(tmpDir, "run", "feat1", "suspended")
	if err := SaveRunMeta(metaPath, orig); err != nil {
		t.Fatalf("SaveRunMeta: %v", err)
	}
	info, err := os.Stat(metaPath)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("meta file mode = %o, want 0600", info.Mode().Perm())
	}

	loaded, err := LoadRunMeta(metaPath)
	if err != nil {
		t.Fatalf("LoadRunMeta: %v", err)
	}
	if !reflect.DeepEqual(loaded, orig) {
		t.Errorf("LoadRunMeta = %+v, want %+v", loaded, orig)
	}

	// Missing RunMeta preserves os.IsNotExist, and directory or symlink paths fail closed.
	if _, err := LoadRunMeta(filepath.Join(tmpDir, "missing.meta")); !os.IsNotExist(err) {
		t.Errorf("expected os.IsNotExist on missing RunMeta, got %v", err)
	}
	if _, err := LoadRunMeta(tmpDir); err == nil {
		t.Error("expected LoadRunMeta on directory to fail")
	}
	symMeta := filepath.Join(tmpDir, "sym.meta")
	if err := os.Symlink(metaPath, symMeta); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadRunMeta(symMeta); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Errorf("expected LoadRunMeta on symlink to fail, got %v", err)
	}

	// FormatRunMeta and SaveRunMeta reject invalid ShareRecord AccessMode and VCSPolicy.
	for _, invalidMeta := range []RunMeta{
		{},
		{Sandbox: "agbox-x", Shares: []ShareRecord{{Index: 0, AccessMode: "bad"}}},
		{Sandbox: "agbox-x", Shares: []ShareRecord{{Index: 0, VCSPolicy: "bad"}}},
	} {
		if _, err := FormatRunMeta(invalidMeta); err == nil {
			t.Errorf("expected FormatRunMeta(%+v) to fail", invalidMeta)
		}
		if err := SaveRunMeta(filepath.Join(tmpDir, "bad.meta"), invalidMeta); err == nil {
			t.Errorf("expected SaveRunMeta(%+v) to fail", invalidMeta)
		}
	}

	// EnsurePrivateDir rejects symlinks and regular files, and tightens 0755 to 0700.
	realTarget := filepath.Join(tmpDir, "real-dir")
	if err := os.MkdirAll(realTarget, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(realTarget, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := EnsurePrivateDir(realTarget); err != nil {
		t.Fatalf("EnsurePrivateDir on 0755 dir failed: %v", err)
	}
	tightInfo, err := os.Stat(realTarget)
	if err != nil {
		t.Fatal(err)
	}
	if tightInfo.Mode().Perm() != 0o700 {
		t.Errorf("EnsurePrivateDir perm = %o, want 0700", tightInfo.Mode().Perm())
	}

	symlinkDir := filepath.Join(tmpDir, "symlink-dir")
	if err := os.Symlink(realTarget, symlinkDir); err != nil {
		t.Fatal(err)
	}
	if err := EnsurePrivateDir(symlinkDir); err == nil {
		t.Error("expected EnsurePrivateDir to reject symlinked directory")
	}
	if err := SaveFile(filepath.Join(symlinkDir, "config"), State{Snapshot: "agbox:v1"}); err == nil {
		t.Error("expected SaveFile to reject symlinked parent directory")
	}
	regularFile := filepath.Join(tmpDir, "not-a-dir")
	if err := os.WriteFile(regularFile, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := EnsurePrivateDir(regularFile); err == nil || !strings.Contains(err.Error(), "not a directory") {
		t.Errorf("expected EnsurePrivateDir to reject regular file, got %v", err)
	}
}

func TestLoadEnv(t *testing.T) {
	env, err := LoadEnv()
	if err != nil {
		t.Fatalf("LoadEnv failed: %v", err)
	}
	if env.HomeReal == "" || !filepath.IsAbs(env.HomeReal) {
		t.Errorf("HomeReal must be a non-empty absolute path, got %q", env.HomeReal)
	}
	if env.DataDir == "" || !filepath.IsAbs(env.DataDir) {
		t.Errorf("DataDir must be a non-empty absolute path, got %q", env.DataDir)
	}

	if _, err := loadEnvWith(func() (string, error) {
		return "", errors.New("no home")
	}, filepath.EvalSymlinks, os.Getenv); err == nil {
		t.Error("expected error when userHomeDir fails")
	}
	if _, err := loadEnvWith(func() (string, error) {
		return "/nonexistent-home", nil
	}, func(string) (string, error) {
		return "", errors.New("dangling home")
	}, os.Getenv); err == nil {
		t.Error("expected error when evalSymlinks fails")
	}

	t.Setenv("AGBOX_CPUS", "0")
	if _, err := LoadEnv(); err == nil {
		t.Error("expected LoadEnv to reject invalid AGBOX_CPUS=0")
	}
}

func TestParseVCSPolicy(t *testing.T) {
	cases := []struct {
		in      string
		want    VCSPolicy
		wantErr bool
	}{
		{"", VCSMask, false},
		{"mask", VCSMask, false},
		{"MASK", VCSMask, false},
		{"vcs", VCSAllow, false},
		{"VCS", VCSAllow, false},
		{"vcs-hooks", VCSAllowHooks, false},
		{"VCS-HOOKS", VCSAllowHooks, false},
		{"invalid", "", true},
		{"bad", "", true},
	}
	for _, tc := range cases {
		got, err := ParseVCSPolicy(tc.in)
		if (err != nil) != tc.wantErr {
			t.Errorf("ParseVCSPolicy(%q) err = %v, wantErr %v", tc.in, err, tc.wantErr)
		}
		if got != tc.want {
			t.Errorf("ParseVCSPolicy(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestIsValidSizeSpec(t *testing.T) {
	cases := []struct {
		spec string
		want bool
	}{
		{"10G", true},
		{"512M", true},
		{"1g", true},
		{"256m", true},
		{"+10G", false},
		{"+512M", false},
		{"0G", false},
		{"0M", false},
		{"-5G", false},
		{"bad", false},
		{"", false},
		{"G", false},
		{"M", false},
		{"10GB", false},
	}
	for _, tc := range cases {
		if got := IsValidSizeSpec(tc.spec); got != tc.want {
			t.Errorf("IsValidSizeSpec(%q) = %v, want %v", tc.spec, got, tc.want)
		}
	}
}

func TestEffectiveReadOnlyAndVCSPolicy(t *testing.T) {
	roCases := []struct {
		rec          ShareRecord
		metaReadOnly bool
		want         bool
	}{
		{ShareRecord{AccessMode: "ro", ReadOnly: false}, false, true},
		{ShareRecord{AccessMode: "ro", ReadOnly: true}, false, true},
		{ShareRecord{AccessMode: "rw", ReadOnly: true}, true, false},
		{ShareRecord{AccessMode: "rw", ReadOnly: false}, false, false},
		{ShareRecord{AccessMode: "", ReadOnly: true}, false, true},
		{ShareRecord{AccessMode: "", ReadOnly: false}, true, true},
		{ShareRecord{AccessMode: "", ReadOnly: false}, false, false},
	}
	for _, tc := range roCases {
		if got := tc.rec.EffectiveReadOnly(tc.metaReadOnly); got != tc.want {
			t.Errorf("ShareRecord{%+v}.EffectiveReadOnly(%v) = %v, want %v", tc.rec, tc.metaReadOnly, got, tc.want)
		}
	}

	vcsCases := []struct {
		rec  ShareRecord
		want VCSPolicy
	}{
		{ShareRecord{VCSPolicy: VCSAllowHooks}, VCSAllowHooks},
		{ShareRecord{VCSPolicy: VCSAllow}, VCSAllow},
		{ShareRecord{VCSPolicy: VCSMask}, VCSMask},
		{ShareRecord{VCSPolicy: "", IsDir: true, Masked: true}, VCSMask},
		{ShareRecord{VCSPolicy: "", IsDir: true, Masked: false}, VCSAllow},
		{ShareRecord{VCSPolicy: "", IsDir: false, Masked: false}, VCSMask},
	}
	for _, tc := range vcsCases {
		if got := tc.rec.EffectiveVCSPolicy(); got != tc.want {
			t.Errorf("ShareRecord{%+v}.EffectiveVCSPolicy() = %v, want %v", tc.rec, got, tc.want)
		}
	}
}

func TestParseRunMetaNegativeInputs(t *testing.T) {
	cases := []struct {
		name string
		json string
	}{
		{"empty reader", ""},
		{"missing sandbox", `{"owner_pid": 10}`},
		{"negative owner_pid", `{"sandbox": "s1", "owner_pid": -1}`},
		{"negative port", `{"sandbox": "s1", "port": -1}`},
		{"port too large", `{"sandbox": "s1", "port": 65536}`},
		{"invalid mode", `{"sandbox": "s1", "mode": "invalid-mode"}`},
		{"negative share index", `{"sandbox": "s1", "shares": [{"index": -1}]}`},
		{"invalid share access_mode", `{"sandbox": "s1", "shares": [{"index": 0, "access_mode": "write"}]}`},
		{"invalid share vcs_policy", `{"sandbox": "s1", "shares": [{"index": 0, "vcs_policy": "bad"}]}`},
		{"read-only share with vcs-hooks", `{"sandbox": "s1", "read_only": true, "shares": [{"index": 0, "guest_name": "g1", "vcs_policy": "vcs-hooks"}]}`},
		{"conflicting remote_bridge and no_remote", `{"sandbox": "s1", "remote_bridge": true, "no_remote": true}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParseRunMeta(strings.NewReader(tc.json)); err == nil {
				t.Errorf("expected error for case %q", tc.name)
			}
		})
	}
}

func TestEnsurePrivateDirEmptyAndSaveBytesAtomic(t *testing.T) {
	if err := EnsurePrivateDir(""); err == nil {
		t.Error("expected error for empty path in EnsurePrivateDir")
	}
	if err := saveBytesAtomic("", []byte("x")); err == nil {
		t.Error("expected error for empty path in saveBytesAtomic")
	}

	tmpDir := t.TempDir()
	targetFile := filepath.Join(tmpDir, "sub", "test.dat")
	data := []byte("secret content\n")
	if err := saveBytesAtomic(targetFile, data); err != nil {
		t.Fatalf("saveBytesAtomic failed: %v", err)
	}
	content, err := os.ReadFile(targetFile)
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}
	if string(content) != string(data) {
		t.Errorf("content = %q, want %q", string(content), string(data))
	}
	info, err := os.Stat(targetFile)
	if err != nil {
		t.Fatalf("Stat failed: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("file permissions = %o, want 0600", info.Mode().Perm())
	}

	// Refuses to overwrite an existing directory or symlink.
	existingDir := filepath.Join(tmpDir, "existing-dir")
	if err := os.MkdirAll(existingDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := saveBytesAtomic(existingDir, data); err == nil || !strings.Contains(err.Error(), "refusing to overwrite directory") {
		t.Errorf("expected refusing to overwrite directory error, got %v", err)
	}
	symTarget := filepath.Join(tmpDir, "sym-target")
	if err := os.Symlink(targetFile, symTarget); err != nil {
		t.Fatal(err)
	}
	if err := saveBytesAtomic(symTarget, data); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Errorf("expected symlink target rejection, got %v", err)
	}

	// Concurrent SaveRunMeta and LoadRunMeta calls on the same file are race-free and never corrupt JSON.
	raceMetaPath := filepath.Join(tmpDir, "race", "run.meta")
	if err := SaveRunMeta(raceMetaPath, RunMeta{Sandbox: "agbox-init", OwnerPID: 1}); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for g := 0; g < 6; g++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for iter := 0; iter < 15; iter++ {
				m := RunMeta{
					Sandbox:  fmt.Sprintf("agbox-g%d", id),
					OwnerPID: id*100 + iter,
					Mode:     RunModeCmd,
				}
				if err := SaveRunMeta(raceMetaPath, m); err != nil {
					t.Errorf("concurrent SaveRunMeta failed: %v", err)
					return
				}
				if got, err := LoadRunMeta(raceMetaPath); err != nil || got.Sandbox == "" {
					t.Errorf("concurrent LoadRunMeta = (%+v, %v)", got, err)
					return
				}
			}
		}(g)
	}
	wg.Wait()
}

func TestFormatRunMetaPrefixAndNonBlockingFIFOOpen(t *testing.T) {
	if _, err := FormatRunMeta(RunMeta{}); err == nil || !strings.HasPrefix(err.Error(), "format run metadata:") {
		t.Errorf("FormatRunMeta(empty) = %v, want 'format run metadata:' prefix", err)
	}
	if _, err := ParseRunMeta(strings.NewReader(`{}`)); err == nil || !strings.HasPrefix(err.Error(), "parse run metadata:") {
		t.Errorf("ParseRunMeta(empty JSON) = %v, want 'parse run metadata:' prefix", err)
	}

	tmpDir := t.TempDir()
	fifoPath := filepath.Join(tmpDir, "state.fifo")
	if err := syscall.Mkfifo(fifoPath, 0o600); err != nil {
		t.Fatalf("Mkfifo: %v", err)
	}

	done := make(chan error, 2)
	go func() {
		_, err := LoadFile(fifoPath)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "refusing non-regular state file") {
			t.Errorf("LoadFile(FIFO) = %v, want non-regular state file error", err)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("LoadFile blocked on FIFO without writer")
	}

	go func() {
		_, err := LoadRunMeta(fifoPath)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "refusing non-regular state file") {
			t.Errorf("LoadRunMeta(FIFO) = %v, want non-regular state file error", err)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("LoadRunMeta blocked on FIFO without writer")
	}
}

func TestFromLookupVersionTokenAndPathControlChars(t *testing.T) {
	// Valid version tokens succeed.
	for _, validVer := range []string{"latest", "1.19.5", "v2.0.0-rc.1+build_42"} {
		env, err := FromLookup("/home/alice", func(k string) string {
			if k == "AGBOX_OPENCODE_VERSION" {
				return validVer
			}
			return ""
		})
		if err != nil || env.OpenCodeVersion != validVer {
			t.Errorf("FromLookup(AGBOX_OPENCODE_VERSION=%q) = (%q, %v), want success", validVer, env.OpenCodeVersion, err)
		}
	}

	// Shell metacharacters, leading dash/dot, and control chars in version fail.
	for _, badVer := range []string{
		"latest;id",
		"$(id)",
		"`id`",
		"-v1.0.0",
		".hidden",
		"1.0/2",
		"1.0|cat",
		"1.0&bg",
	} {
		if _, err := FromLookup("/home/alice", func(k string) string {
			if k == "AGBOX_OPENCODE_VERSION" {
				return badVer
			}
			return ""
		}); err == nil {
			t.Errorf("expected error for invalid AGBOX_OPENCODE_VERSION %q", badVer)
		}
	}

	// Control and bidi chars in homeReal, AGBOX_DATA_DIR, and MSB_HOME fail.
	for _, badHome := range []string{"/home/alice\x07", "/home/alice\n", "/home/alice\u202E"} {
		if _, err := FromLookup(badHome, func(string) string { return "" }); err == nil {
			t.Errorf("expected error for homeReal %q", badHome)
		}
	}
	for _, tc := range []struct {
		key string
		val string
	}{
		{"AGBOX_DATA_DIR", "/tmp/data\x07"},
		{"AGBOX_DATA_DIR", "/tmp/data\n"},
		{"AGBOX_DATA_DIR", "/tmp/data\u200B"},
		{"AGBOX_DATA_DIR", "/tmp/data\u202E"},
		{"MSB_HOME", "/tmp/msb\x01"},
		{"MSB_HOME", "/tmp/msb\r"},
		{"MSB_HOME", "/tmp/msb\uFEFF"},
	} {
		if _, err := FromLookup("/home/alice", func(k string) string {
			if k == tc.key {
				return tc.val
			}
			return ""
		}); err == nil {
			t.Errorf("expected error for %s=%q", tc.key, tc.val)
		}
	}
}

func TestValidateRunMetaCanonicalFieldsAndSingleFileVCS(t *testing.T) {
	cases := []struct {
		name string
		json string
	}{
		{"uppercase VCS-HOOKS on ro share", `{"sandbox": "s1", "read_only": true, "shares": [{"index": 0, "guest_name": "repo", "is_dir": true, "vcs_policy": "VCS-HOOKS"}]}`},
		{"uppercase VCS policy", `{"sandbox": "s1", "shares": [{"index": 0, "guest_name": "repo", "is_dir": true, "vcs_policy": "VCS"}]}`},
		{"whitespace VCS policy", `{"sandbox": "s1", "shares": [{"index": 0, "guest_name": "repo", "is_dir": true, "vcs_policy": " mask "}]}`},
		{"invalid mask_mode", `{"sandbox": "s1", "mask_mode": "STRICT"}`},
		{"unknown mask_mode", `{"sandbox": "s1", "mask_mode": "bogus"}`},
		{"single-file share with vcs policy", `{"sandbox": "s1", "shares": [{"index": 0, "guest_name": "note.md", "is_dir": false, "vcs_policy": "vcs"}]}`},
		{"single-file share with vcs-hooks policy", `{"sandbox": "s1", "shares": [{"index": 0, "guest_name": "note.md", "is_dir": false, "vcs_policy": "vcs-hooks"}]}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParseRunMeta(strings.NewReader(tc.json)); err == nil {
				t.Errorf("expected ParseRunMeta to reject %s", tc.name)
			}
		})
	}
}

func TestEnsurePrivateDirTrailingSlashRootAndStateLineEdges(t *testing.T) {
	tmpDir := t.TempDir()
	realDir := filepath.Join(tmpDir, "real")
	if err := os.MkdirAll(realDir, 0o700); err != nil {
		t.Fatal(err)
	}
	symDir := filepath.Join(tmpDir, "sym")
	if err := os.Symlink(realDir, symDir); err != nil {
		t.Fatal(err)
	}

	// Trailing slash on a symlinked directory must still be rejected.
	if err := EnsurePrivateDir(symDir + "/"); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Errorf("EnsurePrivateDir(symDir+\"/\") = %v, want symlink error", err)
	}

	// Filesystem root "/" and "//" must be rejected.
	for _, rootPath := range []string{"/", "//"} {
		if err := EnsurePrivateDir(rootPath); err == nil {
			t.Errorf("EnsurePrivateDir(%q) succeeded, want error", rootPath)
		}
	}

	// SaveFile rejects \n and \r in State fields.
	cfgPath := filepath.Join(tmpDir, "cfg")
	for _, badState := range []State{
		{Agent: "opencode\nimage=evil"},
		{Image: "node:24\r\nsnapshot=bad"},
		{Categories: "go\nrust"},
	} {
		if err := SaveFile(cfgPath, badState); err == nil {
			t.Errorf("SaveFile(%+v) succeeded, want line-break error", badState)
		}
	}
	// Format strips line breaks so direct callers cannot inject keys.
	formatted := Format(State{Agent: "opencode\nimage=evil"})
	if strings.Contains(formatted, "\nimage=evil") {
		t.Errorf("Format allowed injected key line: %q", formatted)
	}

	// Parse accepts a config line longer than 64 KiB (up to maxStateFileBytes).
	longCategories := strings.Repeat("a", 80*1024)
	longCfg := "agent=opencode\ncategories=" + longCategories + "\n"
	parsed, err := Parse(strings.NewReader(longCfg))
	if err != nil {
		t.Fatalf("Parse(>64KiB line) failed: %v", err)
	}
	if parsed.Agent != "opencode" || parsed.Categories != longCategories {
		t.Errorf("Parse(>64KiB line) returned Agent=%q len(Categories)=%d, want opencode and %d", parsed.Agent, len(parsed.Categories), len(longCategories))
	}
}

func TestResolveLongestExistingAncestorRelativeDanglingUnderSymlinkedParent(t *testing.T) {
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	realConfig := filepath.Join(base, "dotfiles", "config")
	targetParent := filepath.Join(base, "dotfiles", "state-store")
	for _, d := range []string{realConfig, targetParent} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(realConfig, filepath.Join(base, "config-link")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../state-store/missing", filepath.Join(realConfig, "agbox")); err != nil {
		t.Fatal(err)
	}

	input := filepath.Join(base, "config-link", "agbox", "data")
	want := filepath.Join(targetParent, "missing", "data")
	if got := resolveLongestExistingAncestor(input); got != want {
		t.Errorf("resolveLongestExistingAncestor(%q) = %q, want %q", input, got, want)
	}

	env, err := FromLookup(base, func(k string) string {
		if k == "AGBOX_DATA_DIR" {
			return input
		}
		return ""
	})
	if err != nil {
		t.Fatalf("FromLookup failed: %v", err)
	}
	if env.DataDir != want {
		t.Errorf("FromLookup DataDir = %q, want %q", env.DataDir, want)
	}
}
