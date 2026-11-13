package config

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

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
	if env.MaskVCS != MaskStrict || env.AllowOutsideHome || env.AllowRoot {
		t.Errorf("unexpected security defaults: %+v", env)
	}

	overrides := map[string]string{
		"AGBOX_DATA_DIR":           "/custom/data/",
		"MSB_HOME":                 "/custom/msb/",
		"AGBOX_CPUS":               "4",
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
		{"AGBOX_CPUS": "abc"},
		{"AGBOX_MEMORY": "0G"},
		{"AGBOX_MEMORY": "4096"},
		{"AGBOX_MEMORY": "-v /:/mnt"},
		{"AGBOX_ROOT_DISK": "0M"},
		{"AGBOX_ROOT_DISK": "bad"},
		{"AGBOX_PROFILE_DISK": "0G"},
		{"AGBOX_PROFILE_DISK": "bad"},
		{"AGBOX_OPENCODE_VERSION": "latest; id"},
		{"AGBOX_OPENCODE_VERSION": "1.0\nrm"},
		{"AGBOX_AGY_INSTALLER_URL": "http://example.com/install.sh"},
		{"AGBOX_AGY_INSTALLER_URL": "file:///etc/passwd"},
		{"AGBOX_AGY_INSTALLER_URL": "https://example.com/a b"},
		{"AGBOX_AGY_INSTALLER_URL": "-K /tmp/curlrc"},
	}
	for _, badMap := range invalidEnvCases {
		if _, err := FromLookup("/home/alice", func(k string) string { return badMap[k] }); err == nil {
			t.Errorf("expected error for invalid env override %v", badMap)
		}
	}
}

func TestParseFormatAndSaveLoadFile(t *testing.T) {
	orig := State{
		Agent:     "both",
		Image:     "node:24-bookworm-slim",
		Snapshot:  "agbox:v3",
		SnapCount: 3,
		CPUs:      "2",
		Memory:    "2G",
		RootDisk:  "8G",
	}
	formatted := Format(orig)
	parsed, err := Parse(strings.NewReader("# comment\n\n" + formatted + "malformed_line\nsnap_count=-5\n"))
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	if parsed != orig {
		t.Errorf("roundtrip mismatch: got %+v, want %+v", parsed, orig)
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
}

func TestNextSnapshotMember(t *testing.T) {
	n, ref := NextSnapshotMember(0, nil, "agbox")
	if n != 1 || ref != "agbox:v1" {
		t.Errorf("got (%d, %q), want (1, agbox:v1)", n, ref)
	}

	// Existing snapshots in msb exceed recorded count (e.g. config was reset).
	n2, ref2 := NextSnapshotMember(1, []string{"other:v9", "agbox:v1", "agbox:v4", "agbox:notnum"}, "agbox")
	if n2 != 5 || ref2 != "agbox:v5" {
		t.Errorf("got (%d, %q), want (5, agbox:v5)", n2, ref2)
	}

	// Recorded count exceeds existing snapshots (e.g. older snapshots pruned).
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

	if _, err := ParseRunMeta(strings.NewReader(`{"owner_pid": 1}`)); err == nil {
		t.Error("expected error when sandbox name is missing")
	}
	if _, err := ParseRunMeta(strings.NewReader(`{"sandbox":"agbox-a","shares":[{"index":-1,"host_path":"/a","guest_name":"a"}]}`)); err == nil {
		t.Error("expected error when share index is negative")
	}
	if _, err := ParseRunMeta(strings.NewReader(`{invalid`)); err == nil {
		t.Error("expected error on invalid JSON")
	}

	// EnsurePrivateDir must reject symlinks and non-directory files.
	realTarget := filepath.Join(tmpDir, "real-dir")
	if err := os.MkdirAll(realTarget, 0o755); err != nil {
		t.Fatal(err)
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
	if err := EnsurePrivateDir(regularFile); err == nil {
		t.Error("expected EnsurePrivateDir to reject regular file")
	}
}
