package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseMaskMode(t *testing.T) {
	cases := []struct {
		in      string
		want    MaskMode
		wantErr bool
	}{
		{"", MaskAuto, false},
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
	if env.CPUs != DefaultCPUs || env.Memory != DefaultMemory || env.RootDisk != DefaultRootDisk {
		t.Errorf("unexpected defaults: %+v", env)
	}
	if env.MaskVCS != MaskAuto || env.AllowOutsideHome {
		t.Errorf("unexpected mask/outside defaults: %+v", env)
	}

	overrides := map[string]string{
		"AGBOX_DATA_DIR":           "/custom/data/",
		"MSB_HOME":                 "/custom/msb/",
		"AGBOX_CPUS":               "4",
		"AGBOX_MEMORY":             "8G",
		"AGBOX_ROOT_DISK":          "16G",
		"AGBOX_OPENCODE_VERSION":   "1.19.5",
		"AGBOX_AGY_INSTALLER_URL":  "https://example.com/install.sh",
		"AGBOX_MASK_VCS":           "strict",
		"AGBOX_ALLOW_OUTSIDE_HOME": "1",
	}
	env2, err := FromLookup("/home/alice", func(k string) string { return overrides[k] })
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if env2.DataDir != "/custom/data" || env2.MSBHome != "/custom/msb" {
		t.Errorf("paths not cleaned: DataDir=%q MSBHome=%q", env2.DataDir, env2.MSBHome)
	}
	if env2.CPUs != "4" || env2.Memory != "8G" || env2.RootDisk != "16G" {
		t.Errorf("resource overrides failed: %+v", env2)
	}
	if env2.MaskVCS != MaskStrict || !env2.AllowOutsideHome {
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
