package service

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"agbox/internal/config"
)

func TestValidateName(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		wantErr bool
	}{
		{"work", false},
		{"web_01-prod", false},
		{"a", false},
		{strings.Repeat("a", 63), false},
		{"", true},
		{strings.Repeat("a", 64), true},
		{"base", true},
		{"run-123", true},
		{"-leading", true},
		{"_leading", true},
		{"has space", true},
		{"has/slash", true},
		{"has.dot", true},
		{"has@at", true},
	}

	for _, tc := range cases {
		got, err := ValidateName(tc.name)
		if tc.wantErr {
			if err == nil {
				t.Errorf("ValidateName(%q) succeeded (%q), want error", tc.name, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("ValidateName(%q) failed: %v", tc.name, err)
		}
		if got != tc.name {
			t.Errorf("ValidateName(%q) = %q, want %q", tc.name, got, tc.name)
		}
	}
}

func TestSpecSaveLoadListDelete(t *testing.T) {
	t.Parallel()

	dataDir := t.TempDir()
	specA := Spec{
		Name:    "work",
		Agent:   "antigravity",
		Mode:    config.RunModeRemoteControl,
		Persist: true,
		Shares:  []string{"/home/user/proj:rw,mask"},
	}
	specB := Spec{
		Name:    "alpha",
		Agent:   "opencode",
		Mode:    config.RunModeServe,
		Port:    4096,
		Profile: "dev",
	}

	if err := SaveSpec(dataDir, specA); err != nil {
		t.Fatalf("SaveSpec(work) failed: %v", err)
	}
	if err := SaveSpec(dataDir, specB); err != nil {
		t.Fatalf("SaveSpec(alpha) failed: %v", err)
	}

	info, err := os.Lstat(SpecPath(dataDir, "work"))
	if err != nil {
		t.Fatalf("Lstat spec failed: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("spec file perm = %04o, want 0600", got)
	}

	loaded, err := LoadSpec(dataDir, "work")
	if err != nil {
		t.Fatalf("LoadSpec(work) failed: %v", err)
	}
	if loaded.Name != "work" || !loaded.Persist || loaded.Mode != config.RunModeRemoteControl {
		t.Fatalf("unexpected loaded spec: %+v", loaded)
	}

	list, err := ListSpecs(dataDir)
	if err != nil {
		t.Fatalf("ListSpecs failed: %v", err)
	}
	if len(list) != 2 || list[0].Name != "alpha" || list[1].Name != "work" {
		t.Fatalf("unexpected sorted list: %+v", list)
	}

	if err := DeleteSpec(dataDir, "alpha"); err != nil {
		t.Fatalf("DeleteSpec(alpha) failed: %v", err)
	}
	if _, err := LoadSpec(dataDir, "alpha"); !os.IsNotExist(err) {
		t.Fatalf("LoadSpec(alpha) after delete = %v, want not exist", err)
	}
}

func TestSpecRejectsSymlinks(t *testing.T) {
	t.Parallel()

	dataDir := t.TempDir()
	svcDir := ServicesDir(dataDir)
	if err := os.MkdirAll(svcDir, 0o700); err != nil {
		t.Fatal(err)
	}
	realFile := filepath.Join(dataDir, "real.json")
	if err := os.WriteFile(realFile, []byte(`{"name":"evil","mode":"serve"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	linkPath := SpecPath(dataDir, "evil")
	if err := os.Symlink(realFile, linkPath); err != nil {
		t.Fatal(err)
	}

	if _, err := LoadSpec(dataDir, "evil"); err == nil {
		t.Fatal("LoadSpec accepted symlinked spec")
	}
	if err := SaveSpec(dataDir, Spec{Name: "evil", Mode: config.RunModeServe}); err == nil {
		t.Fatal("SaveSpec accepted symlinked target")
	}
	if err := DeleteSpec(dataDir, "evil"); err == nil {
		t.Fatal("DeleteSpec accepted symlinked target")
	}
}

func TestParseEnvFile(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	good := filepath.Join(dir, "secrets.env")
	content := strings.Join([]string{
		"# comment",
		"",
		"ANTHROPIC_API_KEY=sk-ant-123",
		"OPENCODE_SERVER_PASSWORD='p@ss word'",
		`QUOTED="line\nval"`,
		"EMPTY=",
	}, "\n") + "\n"
	if err := os.WriteFile(good, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := ParseEnvFile(good)
	if err != nil {
		t.Fatalf("ParseEnvFile failed: %v", err)
	}
	if got["ANTHROPIC_API_KEY"] != "sk-ant-123" ||
		got["OPENCODE_SERVER_PASSWORD"] != "p@ss word" ||
		got["QUOTED"] != "line\nval" ||
		got["EMPTY"] != "" {
		t.Fatalf("unexpected parsed env map: %+v", got)
	}

	if resolved, err := ValidateEnvFile(good); err != nil || resolved != good {
		t.Fatalf("ValidateEnvFile(%q) = (%q, %v)", good, resolved, err)
	}

	// Reject world/group readable permissions.
	insecure := filepath.Join(dir, "insecure.env")
	if err := os.WriteFile(insecure, []byte("FOO=bar\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(insecure, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := ParseEnvFile(insecure); err == nil {
		t.Fatal("ParseEnvFile accepted 0640 file")
	}

	// Reject symlink.
	link := filepath.Join(dir, "link.env")
	if err := os.Symlink(good, link); err != nil {
		t.Fatal(err)
	}
	if _, err := ParseEnvFile(link); err == nil {
		t.Fatal("ParseEnvFile accepted symlink")
	}

	// Reject malformed line.
	bad := filepath.Join(dir, "bad.env")
	if err := os.WriteFile(bad, []byte("NOT_A_PAIR\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ParseEnvFile(bad); err == nil {
		t.Fatal("ParseEnvFile accepted line without '='")
	}

	// Reject invalid key.
	badKey := filepath.Join(dir, "badkey.env")
	if err := os.WriteFile(badKey, []byte("1BAD=val\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ParseEnvFile(badKey); err == nil {
		t.Fatal("ParseEnvFile accepted invalid variable name")
	}
}

func TestRenderAndInstallTemplateUnit(t *testing.T) {
	t.Parallel()

	unit, err := RenderTemplateUnit(TemplateUnitOpts{
		ExePath:          "/home/alice/.local/bin/agbox",
		DataDir:          "/home/alice/.local/share/agbox",
		MSBHome:          "/home/alice/.microsandbox",
		PathEnv:          "/home/alice/.local/bin:/usr/bin:/bin",
		AllowOutsideHome: true,
	})
	if err != nil {
		t.Fatalf("RenderTemplateUnit failed: %v", err)
	}
	for _, want := range []string{
		"Type=notify",
		"NotifyAccess=main",
		`ExecStart="/home/alice/.local/bin/agbox" __service-run %i`,
		`Environment="PATH=/home/alice/.local/bin:/usr/bin:/bin"`,
		`Environment="AGBOX_DATA_DIR=/home/alice/.local/share/agbox"`,
		`Environment="MSB_HOME=/home/alice/.microsandbox"`,
		`Environment="AGBOX_ALLOW_OUTSIDE_HOME=1"`,
		"After=network-online.target",
		"Restart=on-failure",
		"KillMode=mixed",
		"TimeoutStartSec=120",
		"TimeoutStopSec=30",
		"WatchdogSec=90s",
		"WantedBy=default.target",
	} {
		if !strings.Contains(unit, want) {
			t.Errorf("unit missing %q:\n%s", want, unit)
		}
	}

	// Reject control characters in paths.
	if _, err := RenderTemplateUnit(TemplateUnitOpts{
		ExePath: "/usr/bin/agbox\nExecStart=/bin/evil",
		DataDir: "/tmp/data",
		MSBHome: "/tmp/msb",
	}); err == nil {
		t.Fatal("RenderTemplateUnit accepted newline in ExePath")
	}

	// Test InstallTemplateUnit and RemoveTemplateUnit.
	home := t.TempDir()
	unitPath, err := TemplateUnitPath(home, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := InstallTemplateUnit(unitPath, unit); err != nil {
		t.Fatalf("InstallTemplateUnit failed: %v", err)
	}
	got, err := os.ReadFile(unitPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != unit {
		t.Fatalf("installed unit mismatch")
	}
	if err := RemoveTemplateUnit(unitPath); err != nil {
		t.Fatalf("RemoveTemplateUnit failed: %v", err)
	}
	if _, err := os.Lstat(unitPath); !os.IsNotExist(err) {
		t.Fatalf("unit file still exists after remove: %v", err)
	}
}

func TestUserUnitDir(t *testing.T) {
	t.Parallel()

	got, err := UserUnitDir("/home/alice", "")
	if err != nil || got != "/home/alice/.config/systemd/user" {
		t.Fatalf("UserUnitDir default = (%q, %v)", got, err)
	}
	got, err = UserUnitDir("/home/alice", "/custom/cfg")
	if err != nil || got != "/custom/cfg/systemd/user" {
		t.Fatalf("UserUnitDir XDG = (%q, %v)", got, err)
	}
	if _, err := UserUnitDir("/home/alice", "relative/cfg"); err == nil {
		t.Fatal("UserUnitDir accepted relative XDG_CONFIG_HOME")
	}
}

func TestNotifyUnixgram(t *testing.T) {
	t.Parallel()

	// Empty socket path is a no-op.
	if err := Notify("", "READY=1"); err != nil {
		t.Fatalf("Notify empty socket failed: %v", err)
	}

	sockPath := filepath.Join(t.TempDir(), "notify.sock")
	conn, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: sockPath, Net: "unixgram"})
	if err != nil {
		t.Fatalf("ListenUnixgram failed: %v", err)
	}
	defer conn.Close()

	if err := Notify(sockPath, "READY=1"); err != nil {
		t.Fatalf("Notify READY=1 failed: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 64)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("Read datagram failed: %v", err)
	}
	if got := string(buf[:n]); got != "READY=1" {
		t.Fatalf("got %q, want READY=1", got)
	}
}
