package service

import (
	"bytes"
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
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
	if err := os.WriteFile(realFile, []byte(`{"name":"evil","mode":"serve","port":4096}`), 0o600); err != nil {
		t.Fatal(err)
	}
	linkPath := SpecPath(dataDir, "evil")
	if err := os.Symlink(realFile, linkPath); err != nil {
		t.Fatal(err)
	}

	if _, err := LoadSpec(dataDir, "evil"); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("LoadSpec accepted symlinked spec or unexpected error: %v", err)
	}
	if err := SaveSpec(dataDir, Spec{Name: "evil", Mode: config.RunModeServe, Port: 4096}); err == nil || !strings.Contains(err.Error(), "non-regular") {
		t.Fatalf("SaveSpec accepted symlinked target or unexpected error: %v", err)
	}
	if err := DeleteSpec(dataDir, "evil"); err == nil || !strings.Contains(err.Error(), "non-regular") {
		t.Fatalf("DeleteSpec accepted symlinked target or unexpected error: %v", err)
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

	// Empty state is a no-op. Missing socket paths return errors.
	if err := Notify(sockPath, ""); err != nil {
		t.Fatalf("Notify empty state failed: %v", err)
	}
	if err := Notify(filepath.Join(t.TempDir(), "missing.sock"), "READY=1"); err == nil {
		t.Fatal("Notify succeeded for missing unixgram socket")
	}
	if err := Notify("@agbox-nonexistent-abstract-notify-sock", "READY=1"); err == nil {
		t.Fatal("Notify succeeded for missing abstract unixgram socket")
	}
}

func TestFIFONonBlockingRejection(t *testing.T) {
	t.Parallel()

	td := t.TempDir()
	envFIFO := filepath.Join(td, "env.fifo")
	if err := syscall.Mkfifo(envFIFO, 0o600); err != nil {
		t.Fatalf("Mkfifo(%s): %v", envFIFO, err)
	}

	dataDir := filepath.Join(td, "data")
	svcDir := ServicesDir(dataDir)
	if err := os.MkdirAll(svcDir, 0o700); err != nil {
		t.Fatal(err)
	}
	specFIFO := SpecPath(dataDir, "fifosvc")
	if err := syscall.Mkfifo(specFIFO, 0o600); err != nil {
		t.Fatalf("Mkfifo(%s): %v", specFIFO, err)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		if _, err := ParseEnvFile(envFIFO); err == nil || !strings.Contains(err.Error(), "regular file") {
			t.Errorf("ParseEnvFile(FIFO) = %v, want regular file error", err)
		}
		if _, err := LoadSpec(dataDir, "fifosvc"); err == nil || !strings.Contains(err.Error(), "non-regular") {
			t.Errorf("LoadSpec(FIFO) = %v, want non-regular error", err)
		}
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("ParseEnvFile or LoadSpec blocked on FIFO without writer")
	}
}

func TestParseEnvFileEdgeCases(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	// Exact 64 KiB single-line env file must succeed with expanded scanner buffer.
	prefix := "BIG="
	exactVal := strings.Repeat("a", maxEnvFileBytes-len(prefix))
	exactPath := filepath.Join(dir, "exact.env")
	if err := os.WriteFile(exactPath, []byte(prefix+exactVal), 0o600); err != nil {
		t.Fatal(err)
	}
	gotExact, err := ParseEnvFile(exactPath)
	if err != nil {
		t.Fatalf("ParseEnvFile(exact 64 KiB) failed: %v", err)
	}
	if len(gotExact["BIG"]) != len(exactVal) {
		t.Fatalf("exact 64 KiB value length = %d, want %d", len(gotExact["BIG"]), len(exactVal))
	}

	// Empty quoted strings are valid.
	emptyQuoted := filepath.Join(dir, "empty-quoted.env")
	if err := os.WriteFile(emptyQuoted, []byte("A=''\nB=\"\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	gotEQ, err := ParseEnvFile(emptyQuoted)
	if err != nil || gotEQ["A"] != "" || gotEQ["B"] != "" {
		t.Fatalf("ParseEnvFile(empty quoted) = (%+v, %v)", gotEQ, err)
	}

	// >64 KiB file must fail.
	overPath := filepath.Join(dir, "over.env")
	if err := os.WriteFile(overPath, bytes.Repeat([]byte("A"), maxEnvFileBytes+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ParseEnvFile(overPath); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Errorf("ParseEnvFile(>64 KiB) = %v, want size error", err)
	}

	// Relative path and directory must fail.
	if _, err := ParseEnvFile("relative.env"); err == nil {
		t.Error("ParseEnvFile accepted relative path")
	}
	subDir := filepath.Join(dir, "adir")
	if err := os.Mkdir(subDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := ParseEnvFile(subDir); err == nil {
		t.Error("ParseEnvFile accepted directory")
	}

	// ValidateEnvFile rejects empty, whitespace, and control characters.
	for _, badRaw := range []string{"", "   ", "/tmp/bad\nfile.env", "/tmp/bad\x00file.env"} {
		if _, err := ValidateEnvFile(badRaw); err == nil {
			t.Errorf("ValidateEnvFile(%q) succeeded, want error", badRaw)
		}
	}

	// Syntax and NUL byte rejections.
	badContents := []struct {
		name    string
		content []byte
	}{
		{"single-quote-only", []byte("A='\n")},
		{"double-quote-only", []byte("A=\"\n")},
		{"unterminated-single", []byte("A='abc\n")},
		{"unterminated-double", []byte("A=\"abc\n")},
		{"interior-single-quote", []byte("A='a' 'b'\n")},
		{"invalid-double-escape", []byte("A=\"bad\\q\"\n")},
		{"nul-byte", []byte("A=foo\x00bar\n")},
		{"invalid-key-dash", []byte("BAD-KEY=val\n")},
	}
	for _, tc := range badContents {
		t.Run(tc.name, func(t *testing.T) {
			p := filepath.Join(dir, tc.name+".env")
			if err := os.WriteFile(p, tc.content, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := ParseEnvFile(p); err == nil {
				t.Errorf("ParseEnvFile accepted %s (%q)", tc.name, tc.content)
			}
		})
	}
}

func TestSpecValidationAndListSpecsEdgeCases(t *testing.T) {
	t.Parallel()

	dataDir := t.TempDir()

	// Missing services dir returns nil, nil.
	if list, err := ListSpecs(dataDir); err != nil || len(list) != 0 {
		t.Fatalf("ListSpecs(missing) = (%v, %v), want empty", list, err)
	}

	// Valid cmd mode with explicit MaskMode and DefaultVCS succeeds.
	cmdSpec := Spec{
		Name:       "runner",
		Mode:       config.RunModeCmd,
		Cmd:        "sleep 60",
		MaskMode:   config.MaskStrict,
		DefaultVCS: config.VCSAllow,
	}
	if err := SaveSpec(dataDir, cmdSpec); err != nil {
		t.Fatalf("SaveSpec(cmdSpec) failed: %v", err)
	}

	// Remote and NoRemote round-trip cleanly through SaveSpec and LoadSpec.
	remSpec := Spec{Name: "remtrue", Mode: config.RunModeCmd, Cmd: "true", Remote: true}
	if err := SaveSpec(dataDir, remSpec); err != nil {
		t.Fatalf("SaveSpec(remtrue) failed: %v", err)
	}
	gotRem, err := LoadSpec(dataDir, "remtrue")
	if err != nil || !gotRem.Remote || gotRem.NoRemote {
		t.Fatalf("LoadSpec(remtrue) = (%+v, %v), want Remote=true NoRemote=false", gotRem, err)
	}
	noRemSpec := Spec{Name: "remfalse", Mode: config.RunModeCmd, Cmd: "true", NoRemote: true}
	if err := SaveSpec(dataDir, noRemSpec); err != nil {
		t.Fatalf("SaveSpec(remfalse) failed: %v", err)
	}
	gotNoRem, err := LoadSpec(dataDir, "remfalse")
	if err != nil || gotNoRem.Remote || !gotNoRem.NoRemote {
		t.Fatalf("LoadSpec(remfalse) = (%+v, %v), want Remote=false NoRemote=true", gotNoRem, err)
	}
	if err := validateSpec(Spec{Name: "bothrem", Mode: config.RunModeCmd, Cmd: "true", Remote: true, NoRemote: true}); err == nil {
		t.Fatal("validateSpec accepted Remote=true with NoRemote=true")
	}

	// Invalid specs rejected by SaveSpec.
	invalidSpecs := []struct {
		name string
		spec Spec
	}{
		{"empty-name", Spec{Name: "", Mode: config.RunModeCmd, Cmd: "true"}},
		{"invalid-mode", Spec{Name: "badmode", Mode: config.RunModeTUI}},
		{"empty-mode", Spec{Name: "nomode", Mode: ""}},
		{"cmd-empty", Spec{Name: "emptycmd", Mode: config.RunModeCmd, Cmd: ""}},
		{"cmd-whitespace", Spec{Name: "blankcmd", Mode: config.RunModeCmd, Cmd: "   \t\n "}},
		{"serve-port-zero", Spec{Name: "p0", Mode: config.RunModeServe, Port: 0}},
		{"serve-port-neg", Spec{Name: "pneg", Mode: config.RunModeServe, Port: -1}},
		{"serve-port-high", Spec{Name: "phigh", Mode: config.RunModeServe, Port: 65536}},
		{"invalid-mask", Spec{Name: "badmask", Mode: config.RunModeCmd, Cmd: "true", MaskMode: "1"}},
		{"invalid-vcs", Spec{Name: "badvcs", Mode: config.RunModeCmd, Cmd: "true", DefaultVCS: "bogus"}},
		{"remote-and-no-remote", Spec{Name: "bothrem", Mode: config.RunModeCmd, Cmd: "true", Remote: true, NoRemote: true}},
	}
	for _, tc := range invalidSpecs {
		t.Run("save-"+tc.name, func(t *testing.T) {
			if err := SaveSpec(dataDir, tc.spec); err == nil {
				t.Errorf("SaveSpec accepted invalid spec %+v", tc.spec)
			}
		})
	}

	// LoadSpec rejects invalid name, corrupt JSON, name mismatch, invalid mode/cmd/port/mask/vcs, and oversized spec.
	if _, err := LoadSpec(dataDir, "bad/name"); err == nil {
		t.Error("LoadSpec accepted invalid name")
	}
	if err := DeleteSpec(dataDir, "bad/name"); err == nil {
		t.Error("DeleteSpec accepted invalid name")
	}

	svcDir := ServicesDir(dataDir)
	loadBadCases := []struct {
		name    string
		payload []byte
	}{
		{"corrupt", []byte("{not-json")},
		{"mismatch", []byte(`{"name":"other","mode":"cmd","cmd":"true"}`)},
		{"badmode", []byte(`{"name":"badmode","mode":"tui"}`)},
		{"emptycmd", []byte(`{"name":"emptycmd","mode":"cmd","cmd":""}`)},
		{"blankcmd", []byte(`{"name":"blankcmd","mode":"cmd","cmd":"  \t "}`)},
		{"badport", []byte(`{"name":"badport","mode":"serve","port":0}`)},
		{"badmask", []byte(`{"name":"badmask","mode":"cmd","cmd":"true","mask_mode":"yes"}`)},
		{"badvcs", []byte(`{"name":"badvcs","mode":"cmd","cmd":"true","default_vcs":"unknown"}`)},
		{"bothrem", []byte(`{"name":"bothrem","mode":"cmd","cmd":"true","remote":true,"no_remote":true}`)},
		{"oversized", bytes.Repeat([]byte(" "), maxSpecFileBytes+1)},
	}
	for _, tc := range loadBadCases {
		t.Run("load-"+tc.name, func(t *testing.T) {
			p := SpecPath(dataDir, tc.name)
			if err := os.WriteFile(p, tc.payload, 0o600); err != nil {
				t.Fatal(err)
			}
			defer os.Remove(p)
			if _, err := LoadSpec(dataDir, tc.name); err == nil {
				t.Errorf("LoadSpec(%s) succeeded, want error", tc.name)
			}
		})
	}

	// ListSpecs ignores non-JSON files and invalid service name JSON files, and fails on corrupt valid-name JSON.
	if err := os.WriteFile(filepath.Join(svcDir, "notes.txt"), []byte("ignore"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(svcDir, "base.json"), []byte(`{"name":"base"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	specs, err := ListSpecs(dataDir)
	if err != nil || len(specs) != 3 || specs[0].Name != "remfalse" || specs[1].Name != "remtrue" || specs[2].Name != "runner" {
		t.Fatalf("ListSpecs = (%+v, %v), want [remfalse remtrue runner]", specs, err)
	}

	corruptInList := SpecPath(dataDir, "broken")
	if err := os.WriteFile(corruptInList, []byte("{bad"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ListSpecs(dataDir); err == nil {
		t.Error("ListSpecs succeeded with corrupt spec")
	}
	_ = os.Remove(corruptInList)

	// ListSpecs rejects symlinked services directory.
	symData := t.TempDir()
	if err := os.Symlink(t.TempDir(), ServicesDir(symData)); err != nil {
		t.Fatal(err)
	}
	if _, err := ListSpecs(symData); err == nil {
		t.Error("ListSpecs accepted symlinked services directory")
	}
}

func TestUnitNameQuotingTemplateAndInstallSecurity(t *testing.T) {
	t.Parallel()

	if got := UnitName("web"); got != "agbox@web.service" {
		t.Fatalf("UnitName(web) = %q, want agbox@web.service", got)
	}

	// FormatSystemdQuote keeps '$' literal (for Environment=), while formatSystemdExecArg doubles '$' (for ExecStart=).
	raw := `/opt/a"b\c%d$HOME/agbox`
	wantEnv := `"/opt/a\"b\\c%%d$HOME/agbox"`
	wantExec := `"/opt/a\"b\\c%%d$$HOME/agbox"`
	if got := FormatSystemdQuote(raw); got != wantEnv {
		t.Errorf("FormatSystemdQuote = %q, want %q", got, wantEnv)
	}
	if got := formatSystemdExecArg(raw); got != wantExec {
		t.Errorf("formatSystemdExecArg = %q, want %q", got, wantExec)
	}

	unit, err := RenderTemplateUnit(TemplateUnitOpts{
		ExePath:   `/opt/dir$1/agbox`,
		DataDir:   `/var/lib/agbox`,
		MSBHome:   `/var/lib/msb`,
		AllowRoot: true,
	})
	if err != nil {
		t.Fatalf("RenderTemplateUnit failed: %v", err)
	}
	if !strings.Contains(unit, `ExecStart="/opt/dir$$1/agbox" __service-run %i`) {
		t.Errorf("ExecStart did not escape '$' properly:\n%s", unit)
	}
	if !strings.Contains(unit, `Environment="AGBOX_ALLOW_ROOT=1"`) {
		t.Errorf("unit missing AGBOX_ALLOW_ROOT=1:\n%s", unit)
	}

	// RenderTemplateUnit validation errors.
	badOpts := []TemplateUnitOpts{
		{ExePath: "relative/agbox", DataDir: "/d", MSBHome: "/m"},
		{ExePath: "/agbox", DataDir: "relative", MSBHome: "/m"},
		{ExePath: "/agbox", DataDir: "/d", MSBHome: "relative"},
		{ExePath: "/agbox", DataDir: "/d", MSBHome: "/m", PathEnv: "/bin\n/evil"},
	}
	for _, opt := range badOpts {
		if _, err := RenderTemplateUnit(opt); err == nil {
			t.Errorf("RenderTemplateUnit accepted invalid opts %+v", opt)
		}
	}

	// UserUnitDir and TemplateUnitPath reject empty/relative home.
	if _, err := UserUnitDir("", ""); err == nil {
		t.Error("UserUnitDir accepted empty home")
	}
	if _, err := TemplateUnitPath("relative/home", ""); err == nil {
		t.Error("TemplateUnitPath accepted relative home")
	}

	// InstallTemplateUnit rejects symlinked parent (~/.config/systemd), symlinked unit dir, and relative path.
	home := t.TempDir()
	cfgDir := filepath.Join(home, ".config")
	if err := os.MkdirAll(cfgDir, 0o755); err != nil {
		t.Fatal(err)
	}
	victim := t.TempDir()
	if err := os.Symlink(victim, filepath.Join(cfgDir, "systemd")); err != nil {
		t.Fatal(err)
	}
	unitPath, err := TemplateUnitPath(home, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := InstallTemplateUnit(unitPath, unit); err == nil {
		t.Fatal("InstallTemplateUnit accepted symlinked ~/.config/systemd parent directory")
	}
	if _, err := os.Lstat(filepath.Join(victim, "user")); !os.IsNotExist(err) {
		t.Fatal("InstallTemplateUnit created directory inside symlink target")
	}

	// Symlinked user dir rejected.
	home2 := t.TempDir()
	systemdDir2 := filepath.Join(home2, ".config", "systemd")
	if err := os.MkdirAll(systemdDir2, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, filepath.Join(systemdDir2, "user")); err != nil {
		t.Fatal(err)
	}
	unitPath2, _ := TemplateUnitPath(home2, "")
	if err := InstallTemplateUnit(unitPath2, unit); err == nil {
		t.Fatal("InstallTemplateUnit accepted symlinked systemd/user directory")
	}

	// Relative unit path rejected.
	if err := InstallTemplateUnit("relative/agbox@.service", unit); err == nil {
		t.Fatal("InstallTemplateUnit accepted relative path")
	}

	// RemoveTemplateUnit handles missing file, symlink, and directory.
	rmDir := t.TempDir()
	if err := RemoveTemplateUnit(filepath.Join(rmDir, "missing.service")); err != nil {
		t.Fatalf("RemoveTemplateUnit(missing) = %v, want nil", err)
	}
	symUnit := filepath.Join(rmDir, "sym.service")
	if err := os.Symlink("/etc/hosts", symUnit); err != nil {
		t.Fatal(err)
	}
	if err := RemoveTemplateUnit(symUnit); err == nil {
		t.Error("RemoveTemplateUnit accepted symlink")
	}
	dirUnit := filepath.Join(rmDir, "dir.service")
	if err := os.Mkdir(dirUnit, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := RemoveTemplateUnit(dirUnit); err == nil {
		t.Error("RemoveTemplateUnit accepted directory")
	}
}

func TestOSControllerUsernameValidationAndFakeCommands(t *testing.T) {
	ctl := OSController{}
	ctx := context.Background()

	// Invalid usernames rejected before invoking loginctl.
	for _, badUser := range []string{"", ".", "..", "-flag", "--option", "a/b", `a\b`, "has space", "ctrl\nchar", "del\x7f"} {
		if _, err := ctl.LingerEnabled(ctx, badUser); err == nil {
			t.Errorf("LingerEnabled(%q) succeeded, want error", badUser)
		}
		if err := ctl.EnableLinger(ctx, badUser); err == nil {
			t.Errorf("EnableLinger(%q) succeeded, want error", badUser)
		}
	}

	// Exercise OSController command builders using fake binaries on PATH.
	binDir := t.TempDir()
	logFile := filepath.Join(binDir, "calls.log")

	fakeSystemctl := "#!/bin/sh\nprintf 'systemctl %s\\n' \"$*\" >> " + logFile + "\n" +
		"if [ \"$2\" = \"show\" ]; then\n" +
		"  printf 'ActiveState=active\\nSubState=running\\nUnitFileState=enabled\\nIGNORED_LINE\\n'\n" +
		"fi\n"
	fakeJournalctl := "#!/bin/sh\nprintf 'journalctl %s\\n' \"$*\" >> " + logFile + "\necho 'log line'\n"
	fakeLoginctl := "#!/bin/sh\nprintf 'loginctl %s\\n' \"$*\" >> " + logFile + "\n" +
		"if [ \"$1\" = \"show-user\" ]; then\n" +
		"  case \"$*\" in\n" +
		"    *\"-- alice\"*) echo yes ;;\n" +
		"    *\"-- bob\"*) echo no ;;\n" +
		"    *) exit 1 ;;\n" +
		"  esac\n" +
		"fi\n"

	for name, body := range map[string]string{
		"systemctl":  fakeSystemctl,
		"journalctl": fakeJournalctl,
		"loginctl":   fakeLoginctl,
	} {
		if err := os.WriteFile(filepath.Join(binDir, name), []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", binDir+":"+os.Getenv("PATH"))

	if err := ctl.DaemonReload(ctx); err != nil {
		t.Fatalf("DaemonReload: %v", err)
	}
	if err := ctl.Enable(ctx, "agbox@web.service", true); err != nil {
		t.Fatalf("Enable: %v", err)
	}
	if err := ctl.Disable(ctx, "agbox@web.service", true); err != nil {
		t.Fatalf("Disable: %v", err)
	}
	if err := ctl.Start(ctx, "agbox@web.service"); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if err := ctl.Stop(ctx, "agbox@web.service"); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if err := ctl.Restart(ctx, "agbox@web.service"); err != nil {
		t.Fatalf("Restart: %v", err)
	}
	st, err := ctl.Status(ctx, "agbox@web.service")
	if err != nil || st.ActiveState != "active" || st.SubState != "running" || st.UnitFile != "enabled" {
		t.Fatalf("Status = (%+v, %v)", st, err)
	}
	var outBuf, errBuf bytes.Buffer
	if err := ctl.Logs(ctx, "agbox@web.service", true, 50, &outBuf, &errBuf); err != nil || !strings.Contains(outBuf.String(), "log line") {
		t.Fatalf("Logs = (%q, %v)", outBuf.String(), err)
	}
	if enabled, err := ctl.LingerEnabled(ctx, "alice"); err != nil || !enabled {
		t.Fatalf("LingerEnabled(alice) = (%v, %v), want (true, nil)", enabled, err)
	}
	if enabled, err := ctl.LingerEnabled(ctx, "bob"); err != nil || enabled {
		t.Fatalf("LingerEnabled(bob) = (%v, %v), want (false, nil)", enabled, err)
	}
	if err := ctl.EnableLinger(ctx, "alice"); err != nil {
		t.Fatalf("EnableLinger(alice): %v", err)
	}

	callsBytes, err := os.ReadFile(logFile)
	if err != nil {
		t.Fatal(err)
	}
	calls := string(callsBytes)
	for _, wantCall := range []string{
		"systemctl --user daemon-reload",
		"systemctl --user enable --now agbox@web.service",
		"systemctl --user disable --now agbox@web.service",
		"systemctl --user start agbox@web.service",
		"systemctl --user stop agbox@web.service",
		"systemctl --user restart agbox@web.service",
		"journalctl --user -u agbox@web.service --no-pager -n 50 -f",
		"loginctl show-user -p Linger --value -- alice",
		"loginctl enable-linger -- alice",
	} {
		if !strings.Contains(calls, wantCall) {
			t.Errorf("missing expected OSController call %q in:\n%s", wantCall, calls)
		}
	}
}
