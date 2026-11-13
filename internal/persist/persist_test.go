package persist

import (
	"bytes"
	"encoding/base64"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
)

func TestAuthCaptureSaveLoadRestoreRoundTripAndSecurity(t *testing.T) {
	guestSrcHome := t.TempDir()
	hostDataDir := filepath.Join(t.TempDir(), "agbox-data")
	guestDstHome := t.TempDir()

	// 1. Populate simulated guest credentials with adversarial shell characters and binary bytes.
	agyDir := filepath.Join(guestSrcHome, ".gemini", "antigravity-cli")
	if err := os.MkdirAll(agyDir, 0o700); err != nil {
		t.Fatal(err)
	}
	tokenPayload := []byte("oauth-token-'$(id)'-\"`uname`\"-\nline2-\x00\xff")
	installID := []byte("11111111-2222-3333-4444-555555555555\n")
	statePayload := []byte("user_email: \"dev@example.com\"\n")
	if err := os.WriteFile(filepath.Join(agyDir, "antigravity-oauth-token"), tokenPayload, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(agyDir, "installation_id"), installID, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(agyDir, "antigravity_state.pbtxt"), statePayload, 0o600); err != nil {
		t.Fatal(err)
	}

	ocDir := filepath.Join(guestSrcHome, ".local", "share", "opencode")
	if err := os.MkdirAll(ocDir, 0o700); err != nil {
		t.Fatal(err)
	}
	ocPayload := []byte(`{"anthropic":{"type":"oauth","refresh":"rt-'$(id)'","access":"at-123"}}` + "\n")
	if err := os.WriteFile(filepath.Join(ocDir, "auth.json"), ocPayload, 0o600); err != nil {
		t.Fatal(err)
	}

	// 2. Run real /bin/sh capture scripts for both agents.
	for _, agent := range []string{"antigravity", "opencode"} {
		capScript, err := BuildAuthCaptureScriptForHome(agent, guestSrcHome)
		if err != nil {
			t.Fatalf("BuildAuthCaptureScriptForHome(%s): %v", agent, err)
		}
		out, err := exec.Command("/bin/sh", "-c", capScript).Output()
		if err != nil {
			t.Fatalf("capture sh(%s) failed: %v", agent, err)
		}
		bundle, err := ParseAuthCapture(agent, string(out))
		if err != nil {
			t.Fatalf("ParseAuthCapture(%s): %v", agent, err)
		}
		if err := SaveAuthBundle(hostDataDir, bundle); err != nil {
			t.Fatalf("SaveAuthBundle(%s): %v", agent, err)
		}
	}

	// 3. Verify AuthStatus and host file permissions (0600).
	st, err := AuthStatus(hostDataDir)
	if err != nil || !st["antigravity"] || !st["opencode"] {
		t.Fatalf("AuthStatus = %+v, %v", st, err)
	}
	hostTokenInfo, err := os.Lstat(filepath.Join(hostDataDir, "auth", "antigravity", "antigravity-oauth-token"))
	if err != nil || hostTokenInfo.Mode().Perm() != 0o600 {
		t.Fatalf("host token mode = %v, err=%v", hostTokenInfo, err)
	}

	// 4. Plant a pre-existing symlink at the destination guest token path to verify restore unlinks it instead of following it.
	canary := filepath.Join(t.TempDir(), "host-victim")
	if err := os.WriteFile(canary, []byte("DO-NOT-OVERWRITE"), 0o600); err != nil {
		t.Fatal(err)
	}
	dstAgyDir := filepath.Join(guestDstHome, ".gemini", "antigravity-cli")
	if err := os.MkdirAll(dstAgyDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(canary, filepath.Join(dstAgyDir, "antigravity-oauth-token")); err != nil {
		t.Fatal(err)
	}

	// 5. Load bundle and run real /bin/sh restore over stdin.
	loaded, err := LoadAuthBundle(hostDataDir, []string{"antigravity", "opencode"})
	if err != nil || len(loaded.Files) != 4 {
		t.Fatalf("LoadAuthBundle = %d files, err=%v", len(loaded.Files), err)
	}
	restoreScript, err := FormatAuthRestoreScriptForHome(loaded, guestDstHome)
	if err != nil {
		t.Fatalf("FormatAuthRestoreScriptForHome: %v", err)
	}
	cmd := exec.Command("/bin/sh")
	cmd.Stdin = strings.NewReader(restoreScript)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("restore sh failed: %v, out=%s", err, string(out))
	}

	// Verify canary was NOT overwritten and restored files match byte-for-byte with mode 0600.
	canaryBytes, _ := os.ReadFile(canary)
	if string(canaryBytes) != "DO-NOT-OVERWRITE" {
		t.Fatalf("CRITICAL: restore script followed symlink and overwrote %s", canary)
	}
	restoredTokenPath := filepath.Join(dstAgyDir, "antigravity-oauth-token")
	restoredInfo, err := os.Lstat(restoredTokenPath)
	if err != nil || !restoredInfo.Mode().IsRegular() || restoredInfo.Mode().Perm() != 0o600 {
		t.Fatalf("restored token Lstat = %v, err=%v", restoredInfo, err)
	}
	gotToken, _ := os.ReadFile(restoredTokenPath)
	if !bytes.Equal(gotToken, tokenPayload) {
		t.Errorf("restored token bytes mismatch: got %q, want %q", gotToken, tokenPayload)
	}
	gotOC, _ := os.ReadFile(filepath.Join(guestDstHome, ".local", "share", "opencode", "auth.json"))
	if !bytes.Equal(gotOC, ocPayload) {
		t.Errorf("restored opencode auth.json mismatch: got %q, want %q", gotOC, ocPayload)
	}

	// 6. Security rejections: guest symlink during capture, oversized file, empty sign-in, invalid JSON, non-allowlisted file.
	symHome := t.TempDir()
	symAgy := filepath.Join(symHome, ".gemini", "antigravity-cli")
	_ = os.MkdirAll(symAgy, 0o700)
	_ = os.Symlink(canary, filepath.Join(symAgy, "antigravity-oauth-token"))
	symScript, _ := BuildAuthCaptureScriptForHome("antigravity", symHome)
	if _, err := exec.Command("/bin/sh", "-c", symScript).Output(); err == nil {
		t.Error("expected capture script to fail closed on symlinked guest token")
	}

	bigB64 := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte("a"), MaxAuthFileBytes+1))
	if _, err := ParseAuthCapture("antigravity", "FILE antigravity antigravity-oauth-token "+bigB64+"\n"); err == nil {
		t.Error("expected ParseAuthCapture to reject oversized credential file")
	}
	if _, err := ParseAuthCapture("antigravity", ""); err == nil {
		t.Error("expected ParseAuthCapture to fail when required token is missing")
	}
	emptyJSON := base64.StdEncoding.EncodeToString([]byte("{}"))
	if _, err := ParseAuthCapture("opencode", "FILE opencode auth.json "+emptyJSON+"\n"); err == nil {
		t.Error("expected ParseAuthCapture to reject empty JSON object in auth.json")
	}
	badJSON := base64.StdEncoding.EncodeToString([]byte("not-json"))
	if _, err := ParseAuthCapture("opencode", "FILE opencode auth.json "+badJSON+"\n"); err == nil {
		t.Error("expected ParseAuthCapture to reject invalid JSON in auth.json")
	}
	validB64 := base64.StdEncoding.EncodeToString([]byte("secret"))
	if _, err := ParseAuthCapture("antigravity", "FILE antigravity ../../.bashrc "+validB64+"\n"); err == nil {
		t.Error("expected ParseAuthCapture to reject non-allowlisted filename")
	}

	// 7. RemoveAuth(opencode) keeps antigravity intact, and symlinked host auth file fails closed.
	if err := RemoveAuth(hostDataDir, "opencode"); err != nil {
		t.Fatalf("RemoveAuth(opencode): %v", err)
	}
	st2, err := AuthStatus(hostDataDir)
	if err != nil || !st2["antigravity"] || st2["opencode"] {
		t.Fatalf("AuthStatus after RemoveAuth(opencode) = %+v, %v", st2, err)
	}

	hostTokenFile := filepath.Join(hostDataDir, "auth", "antigravity", "antigravity-oauth-token")
	_ = os.Remove(hostTokenFile)
	_ = os.Symlink(canary, hostTokenFile)
	if _, err := LoadAuthBundle(hostDataDir, []string{"antigravity"}); err == nil {
		t.Error("expected LoadAuthBundle to reject symlinked host credential file")
	}
}

func TestGlobalSkillsInstallInspectRemoveAndSecurity(t *testing.T) {
	dataDir := filepath.Join(t.TempDir(), "data")
	skillsDir := filepath.Join(dataDir, "skills")

	// Missing skills directory returns nil, nil.
	got, err := InspectSkillsDir(skillsDir)
	if err != nil || len(got) != 0 {
		t.Fatalf("InspectSkillsDir(missing) = %v, %v", got, err)
	}

	// Build a source skill directory containing SKILL.md, an executable helper script, and a .git dir that must be stripped.
	srcRoot := t.TempDir()
	mySkill := filepath.Join(srcRoot, "code-review")
	if err := os.MkdirAll(filepath.Join(mySkill, "scripts"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(mySkill, ".git", "hooks"), 0o755); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(mySkill, ".git", "config"), []byte("secret"), 0o600)
	_ = os.WriteFile(filepath.Join(mySkill, "SKILL.md"), []byte("---\nname: code-review\ndescription: Review code.\n---\n"), 0o644)
	_ = os.WriteFile(filepath.Join(mySkill, "scripts", "lint.sh"), []byte("#!/bin/sh\necho ok\n"), 0o755)

	// Install via SKILL.md path directly.
	installed, err := InstallSkill(skillsDir, filepath.Join(mySkill, "SKILL.md"), false)
	if err != nil || installed != "code-review" {
		t.Fatalf("InstallSkill = %q, %v", installed, err)
	}
	// Duplicate without --force fails.
	if _, err := InstallSkill(skillsDir, mySkill, false); err == nil {
		t.Error("expected duplicate InstallSkill without --force to fail")
	}
	// Duplicate with --force succeeds.
	if _, err := InstallSkill(skillsDir, mySkill, true); err != nil {
		t.Fatalf("InstallSkill(--force): %v", err)
	}
	// Verify .git was stripped and lint.sh kept 0755.
	if _, err := os.Lstat(filepath.Join(skillsDir, "code-review", ".git")); !os.IsNotExist(err) {
		t.Error("expected .git inside skill source to be stripped on install")
	}
	scriptInfo, err := os.Lstat(filepath.Join(skillsDir, "code-review", "scripts", "lint.sh"))
	if err != nil || scriptInfo.Mode().Perm() != 0o755 {
		t.Errorf("lint.sh mode = %v, err=%v", scriptInfo, err)
	}

	names, err := InspectSkillsDir(skillsDir)
	if err != nil || !slices.Equal(names, []string{"code-review"}) {
		t.Fatalf("InspectSkillsDir = %v, %v", names, err)
	}

	// Security checks: symlink inside skillsDir or FIFO inside skillsDir must fail closed!
	symLink := filepath.Join(skillsDir, "code-review", "escape")
	if err := os.Symlink("/etc/passwd", symLink); err != nil {
		t.Fatal(err)
	}
	if _, err := InspectSkillsDir(skillsDir); err == nil {
		t.Error("expected InspectSkillsDir to reject symlink inside skillsDir")
	}
	_ = os.Remove(symLink)

	fifoPath := filepath.Join(skillsDir, "code-review", "pipe")
	if err := syscall.Mkfifo(fifoPath, 0o600); err == nil {
		if _, err := InspectSkillsDir(skillsDir); err == nil {
			t.Error("expected InspectSkillsDir to reject FIFO inside skillsDir")
		}
		_ = os.Remove(fifoPath)
	}

	// Path containing ':' or ',' must fail closed.
	if _, err := InspectSkillsDir("/tmp/bad:dir/skills"); err == nil {
		t.Error("expected InspectSkillsDir to reject ':' in path")
	}

	// Invalid skill names.
	for _, bad := range []string{"", ".git", ".jj", "-bad", "bad/slash", "bad..dot"} {
		if _, err := ValidateSkillName(bad); err == nil {
			t.Errorf("expected ValidateSkillName(%q) to fail", bad)
		}
	}

	// RemoveSkill succeeds, and second RemoveSkill fails.
	if err := RemoveSkill(skillsDir, "code-review"); err != nil {
		t.Fatalf("RemoveSkill: %v", err)
	}
	if err := RemoveSkill(skillsDir, "code-review"); err == nil {
		t.Error("expected RemoveSkill on missing skill to fail")
	}

	mountScript := BuildGuestSkillsMountScript()
	if !strings.Contains(mountScript, "/home/agent/.gemini/config/skills") ||
		!strings.Contains(mountScript, "/home/agent/.config/opencode/skills") ||
		!strings.Contains(mountScript, "remount,ro,bind") {
		t.Errorf("unexpected BuildGuestSkillsMountScript: %s", mountScript)
	}
}

func TestProfileLockMetadataAndSessionIDValidation(t *testing.T) {
	dataDir := filepath.Join(t.TempDir(), "data")

	for _, okName := range []string{"default", "work-1", "oss_review"} {
		got, err := ValidateProfileName(okName)
		if err != nil || got != okName {
			t.Fatalf("ValidateProfileName(%q) = %q, %v", okName, got, err)
		}
		vol := FormatProfileVolumeName(okName)
		if !IsProfileVolumeName(vol) {
			t.Errorf("expected IsProfileVolumeName(%q) to be true", vol)
		}
	}
	for _, badName := range []string{"", "-bad", "bad/slash", "bad space", strings.Repeat("x", 49)} {
		if _, err := ValidateProfileName(badName); err == nil {
			t.Errorf("expected ValidateProfileName(%q) to fail", badName)
		}
	}
	if IsProfileVolumeName("other-vol") || IsProfileVolumeName("agbox-profile-") {
		t.Error("expected non-profile volume names to return false")
	}

	// Exclusive flock prevents concurrent acquisition on the same profile.
	lock1, err := LockProfile(dataDir, "work")
	if err != nil {
		t.Fatalf("LockProfile(1): %v", err)
	}
	if _, err := LockProfile(dataDir, "work"); err == nil {
		t.Fatal("expected second concurrent LockProfile(work) to fail")
	}
	// Different profile can lock concurrently.
	lockOther, err := LockProfile(dataDir, "oss")
	if err != nil {
		t.Fatalf("LockProfile(oss): %v", err)
	}
	_ = lockOther.Unlock()

	if err := lock1.Unlock(); err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	lock2, err := LockProfile(dataDir, "work")
	if err != nil {
		t.Fatalf("LockProfile after Unlock failed: %v", err)
	}
	_ = lock2.Unlock()

	if err := SaveProfileMeta(dataDir, ProfileMeta{Name: "work", Size: "10G"}); err != nil {
		t.Fatalf("SaveProfileMeta: %v", err)
	}
	if err := SaveProfileMeta(dataDir, ProfileMeta{Name: "alpha", Size: "20G"}); err != nil {
		t.Fatalf("SaveProfileMeta: %v", err)
	}
	profiles, err := ListProfiles(dataDir)
	if err != nil || len(profiles) != 2 || profiles[0].Name != "alpha" || profiles[1].Name != "work" {
		t.Fatalf("ListProfiles = %+v, %v", profiles, err)
	}
	if err := RemoveProfileDir(dataDir, "alpha"); err != nil {
		t.Fatalf("RemoveProfileDir: %v", err)
	}

	// Verify profile mount script isolates conversations and excludes global skills/mcp/plugins.
	profScript := BuildGuestProfileMountScript()
	for _, want := range []string{
		"/home/agent/.agbox-profile/agy-cli",
		"/home/agent/.agbox-profile/agy-projects",
		"/home/agent/.agbox-profile/opencode-data",
		"/home/agent/.agbox-profile/opencode-state",
	} {
		if !strings.Contains(profScript, want) {
			t.Errorf("profile mount script missing %q", want)
		}
	}
	for _, forbidden := range []string{
		"/home/agent/.gemini/config/skills",
		"/home/agent/.config/opencode",
		"mcp_config.json",
	} {
		if strings.Contains(profScript, forbidden) {
			t.Errorf("profile mount script should not bind global executable config %q", forbidden)
		}
	}

	// Session ID validation.
	for _, validID := range []string{"1c2a8c1e-6b56-4971-8429-ad0252c024a7", "ses_abc123"} {
		if got, err := ValidateSessionID(validID); err != nil || got != validID {
			t.Errorf("ValidateSessionID(%q) = %q, %v", validID, got, err)
		}
	}
	for _, badID := range []string{"", ".", "..", "-flag", "bad;id", "a/b", `a\b`, "has space", "line\nbreak", strings.Repeat("a", 129)} {
		if _, err := ValidateSessionID(badID); err == nil {
			t.Errorf("expected ValidateSessionID(%q) to fail", badID)
		}
	}
}

func TestGlobalRulesInstallInspectStageAndSecurity(t *testing.T) {
	base := t.TempDir()
	rulesDir := filepath.Join(base, "data", "rules")
	srcDir := filepath.Join(base, "src")
	if err := os.MkdirAll(srcDir, 0o755); err != nil {
		t.Fatal(err)
	}

	// Non-existent rulesDir returns nil, nil.
	if names, err := InspectRulesDir(rulesDir); err != nil || len(names) != 0 {
		t.Fatalf("InspectRulesDir(missing) = (%v, %v), want (nil, nil)", names, err)
	}

	// Install AGENTS.md, an always-on frontmatter rule, and a glob-triggered agy rule.
	agentsSrc := filepath.Join(srcDir, "AGENTS.md")
	alwaysSrc := filepath.Join(srcDir, "testing.md")
	globSrc := filepath.Join(srcDir, "go-style.md")
	if err := os.WriteFile(agentsSrc, []byte("# Core Standards\nRun gofmt.\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(alwaysSrc, []byte("---\ntrigger: always_on\n---\n# Testing\nRun go test -race.\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(globSrc, []byte("---\ntrigger: glob\nglobs: [\"*.go\"]\n---\n# Go Glob Rule\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	if name, sz, err := InstallRule(rulesDir, agentsSrc, "", false); err != nil || name != "AGENTS" || sz == 0 {
		t.Fatalf("InstallRule(AGENTS.md) = (%q, %d, %v)", name, sz, err)
	}
	if _, _, err := InstallRule(rulesDir, agentsSrc, "", false); err == nil {
		t.Fatal("expected duplicate InstallRule without force to fail")
	}
	if _, _, err := InstallRule(rulesDir, agentsSrc, "", true); err != nil {
		t.Fatalf("InstallRule(force=true) failed: %v", err)
	}
	if name, _, err := InstallRule(rulesDir, alwaysSrc, "", false); err != nil || name != "testing" {
		t.Fatalf("InstallRule(testing.md) = (%q, %v)", name, err)
	}
	if name, _, err := InstallRule(rulesDir, globSrc, "go-style.md", false); err != nil || name != "go-style" {
		t.Fatalf("InstallRule(go-style.md) = (%q, %v)", name, err)
	}

	names, err := InspectRulesDir(rulesDir)
	if err != nil || !slices.Equal(names, []string{"AGENTS", "go-style", "testing"}) {
		t.Fatalf("InspectRulesDir = (%v, %v)", names, err)
	}
	rawAgents, err := ReadRule(rulesDir, "AGENTS.md")
	if err != nil || !strings.Contains(string(rawAgents), "Core Standards") {
		t.Fatalf("ReadRule(AGENTS.md) = (%q, %v)", string(rawAgents), err)
	}

	// Execute BuildGuestRulesStageScript via real /bin/sh and verify combined AGENTS.md + modular rules/*.md.
	stageDir := filepath.Join(base, "staged")
	stageCmd := exec.Command("/bin/sh", "-c", BuildGuestRulesStageScript(rulesDir, stageDir))
	if out, sErr := stageCmd.CombinedOutput(); sErr != nil {
		t.Fatalf("BuildGuestRulesStageScript failed: %v (%s)", sErr, string(out))
	}
	combined, err := os.ReadFile(filepath.Join(stageDir, "AGENTS.md"))
	if err != nil {
		t.Fatalf("read staged AGENTS.md: %v", err)
	}
	combinedStr := string(combined)
	if !strings.Contains(combinedStr, "# Core Standards") || !strings.Contains(combinedStr, "# Testing") {
		t.Errorf("staged AGENTS.md missing expected content: %q", combinedStr)
	}
	if strings.Contains(combinedStr, "trigger: always_on") || strings.Contains(combinedStr, "Go Glob Rule") {
		t.Errorf("staged AGENTS.md leaked frontmatter or glob rule: %q", combinedStr)
	}
	if strings.Index(combinedStr, "# Core Standards") > strings.Index(combinedStr, "# Testing") {
		t.Errorf("expected AGENTS.md priority content before testing.md: %q", combinedStr)
	}
	globStaged, err := os.ReadFile(filepath.Join(stageDir, "rules", "go-style.md"))
	if err != nil || !strings.Contains(string(globStaged), "trigger: glob") {
		t.Errorf("staged modular rule = (%q, %v)", string(globStaged), err)
	}

	// Verify BuildGuestRulesMountScript binds read-only onto both agy and opencode paths.
	mntScript := BuildGuestRulesMountScript()
	for _, want := range []string{
		"/home/agent/.gemini/config/AGENTS.md",
		"/home/agent/.config/opencode/AGENTS.md",
		"/home/agent/.gemini/config/rules",
		"remount,ro,bind",
	} {
		if !strings.Contains(mntScript, want) {
			t.Errorf("BuildGuestRulesMountScript missing %q", want)
		}
	}

	// Boundary and security rejections: empty, binary NUL, oversize, non-.md without --name, symlink inside rulesDir.
	emptySrc := filepath.Join(srcDir, "empty.md")
	nulSrc := filepath.Join(srcDir, "nul.md")
	bigSrc := filepath.Join(srcDir, "big.md")
	txtSrc := filepath.Join(srcDir, "plain.txt")
	_ = os.WriteFile(emptySrc, []byte("  \n"), 0o644)
	_ = os.WriteFile(nulSrc, []byte("bad\x00rule"), 0o644)
	_ = os.WriteFile(bigSrc, bytes.Repeat([]byte("a"), MaxRuleFileBytes+1), 0o644)
	_ = os.WriteFile(txtSrc, []byte("# Plain\n"), 0o644)
	for _, badFile := range []string{emptySrc, nulSrc, bigSrc, txtSrc} {
		if _, _, bErr := InstallRule(rulesDir, badFile, "", true); bErr == nil {
			t.Errorf("expected InstallRule(%s) to fail", badFile)
		}
	}
	// Passing --name allows importing a .txt file as <name>.md.
	if name, _, nErr := InstallRule(rulesDir, txtSrc, "from-txt", false); nErr != nil || name != "from-txt" {
		t.Errorf("InstallRule(plain.txt --name from-txt) = (%q, %v)", name, nErr)
	}

	symRule := filepath.Join(rulesDir, "evil.md")
	if err := os.Symlink("/etc/passwd", symRule); err != nil {
		t.Fatal(err)
	}
	if _, sErr := InspectRulesDir(rulesDir); sErr == nil {
		t.Fatal("expected InspectRulesDir to reject symlink inside rulesDir")
	}
	_ = os.Remove(symRule)

	if err := RemoveRule(rulesDir, "from-txt"); err != nil {
		t.Fatalf("RemoveRule: %v", err)
	}
	if err := RemoveAllRules(rulesDir); err != nil {
		t.Fatalf("RemoveAllRules: %v", err)
	}
	if left, err := InspectRulesDir(rulesDir); err != nil || len(left) != 0 {
		t.Fatalf("InspectRulesDir after RemoveAllRules = (%v, %v)", left, err)
	}
}

func TestAgentsCacheInstallInspectRemoveAndSecurity(t *testing.T) {
	base := t.TempDir()
	agentsDir := filepath.Join(base, "agents")

	// Missing directory returns nil, nil.
	if got, err := InspectAgentsDir(agentsDir); err != nil || len(got) != 0 {
		t.Fatalf("InspectAgentsDir(missing) = (%v, %v)", got, err)
	}

	// Build valid synthetic 64-byte+ ELF payloads for agy and opencode.
	agyELF := append([]byte{0x7f, 'E', 'L', 'F'}, bytes.Repeat([]byte("A"), 128)...)
	ocELF := append([]byte{0x7f, 'E', 'L', 'F'}, bytes.Repeat([]byte("O"), 160)...)

	agyInfo, err := InstallAgentBinaryFromReader(agentsDir, "antigravity", "2.1.0\nextra-line", bytes.NewReader(agyELF))
	if err != nil {
		t.Fatalf("InstallAgentBinaryFromReader(antigravity): %v", err)
	}
	if agyInfo.BinName != "agy" || agyInfo.Version != "2.1.0" || agyInfo.SizeBytes != int64(len(agyELF)) {
		t.Fatalf("unexpected agyInfo: %+v", agyInfo)
	}
	ocInfo, err := InstallAgentBinaryFromReader(agentsDir, "opencode", "1.4.2", bytes.NewReader(ocELF))
	if err != nil {
		t.Fatalf("InstallAgentBinaryFromReader(opencode): %v", err)
	}
	if ocInfo.BinName != "opencode" || ocInfo.Version != "1.4.2" {
		t.Fatalf("unexpected ocInfo: %+v", ocInfo)
	}

	cached, err := InspectAgentsDir(agentsDir)
	if err != nil || len(cached) != 2 || cached[0].Agent != "antigravity" || cached[1].Agent != "opencode" {
		t.Fatalf("InspectAgentsDir = (%+v, %v)", cached, err)
	}

	// Reject non-ELF binary streams and undersized streams without corrupting existing cache.
	if _, err := InstallAgentBinaryFromReader(agentsDir, "antigravity", "bad", bytes.NewReader(bytes.Repeat([]byte("X"), 128))); err == nil {
		t.Fatal("expected non-ELF binary stream to be rejected")
	}
	if _, err := InstallAgentBinaryFromReader(agentsDir, "antigravity", "tiny", bytes.NewReader([]byte{0x7f, 'E', 'L', 'F'})); err == nil {
		t.Fatal("expected undersized ELF stream to be rejected")
	}
	if afterBad, err := InspectAgentsDir(agentsDir); err != nil || len(afterBad) != 2 || afterBad[0].Version != "2.1.0" {
		t.Fatalf("failed install corrupted cache: (%+v, %v)", afterBad, err)
	}

	// Tampering with cached binary bytes must fail SHA-256 verification.
	agyPath := filepath.Join(agentsDir, "bin", "agy")
	tampered := append([]byte{}, agyELF...)
	tampered[len(tampered)-1] = 'Z'
	if err := os.WriteFile(agyPath, tampered, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := InspectAgentsDir(agentsDir); err == nil {
		t.Fatal("expected InspectAgentsDir to reject SHA-256 mismatch")
	}
	if err := os.WriteFile(agyPath, agyELF, 0o755); err != nil {
		t.Fatal(err)
	}

	// Hardlinked binary must fail closed (st_nlink != 1).
	hardlinkOutside := filepath.Join(base, "outside-link")
	if err := os.Link(agyPath, hardlinkOutside); err != nil {
		t.Fatal(err)
	}
	if _, err := InspectAgentsDir(agentsDir); err == nil {
		t.Fatal("expected InspectAgentsDir to reject hardlinked binary")
	}
	_ = os.Remove(hardlinkOutside)

	// Unexpected file or symlink inside agentsDir/bin must fail closed.
	extraPath := filepath.Join(agentsDir, "bin", "evil")
	if err := os.WriteFile(extraPath, agyELF, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := InspectAgentsDir(agentsDir); err == nil {
		t.Fatal("expected InspectAgentsDir to reject unexpected binary name")
	}
	_ = os.Remove(extraPath)

	symPath := filepath.Join(agentsDir, "evil-sym")
	if err := os.Symlink("/etc/passwd", symPath); err != nil {
		t.Fatal(err)
	}
	if _, err := InspectAgentsDir(agentsDir); err == nil {
		t.Fatal("expected InspectAgentsDir to reject symlink in agentsDir")
	}
	_ = os.Remove(symPath)

	// RemoveCachedAgent(antigravity) leaves opencode intact, and RemoveCachedAgent(all) clears all.
	if err := RemoveCachedAgent(agentsDir, "antigravity"); err != nil {
		t.Fatalf("RemoveCachedAgent(antigravity): %v", err)
	}
	rem, err := InspectAgentsDir(agentsDir)
	if err != nil || len(rem) != 1 || rem[0].Agent != "opencode" {
		t.Fatalf("InspectAgentsDir after single remove = (%+v, %v)", rem, err)
	}
	if err := RemoveCachedAgent(agentsDir, "all"); err != nil {
		t.Fatalf("RemoveCachedAgent(all): %v", err)
	}
	empty, err := InspectAgentsDir(agentsDir)
	if err != nil || len(empty) != 0 {
		t.Fatalf("InspectAgentsDir after remove all = (%+v, %v)", empty, err)
	}

	// Verify BuildAgentUpdateScript, BuildGuestAgentsMountScript, and BuildGuestProfileMountScript.
	upAgy, catAgy, _, err := BuildAgentUpdateScript("antigravity", "", "")
	if err != nil || !strings.Contains(upAgy, "--proto") || !strings.Contains(upAgy, "=https") || !strings.Contains(upAgy, "--tlsv1.2") || catAgy == "" {
		t.Errorf("BuildAgentUpdateScript(antigravity) = (%q, %q, %v)", upAgy, catAgy, err)
	}
	upOC, catOC, _, err := BuildAgentUpdateScript("opencode", "latest", "")
	if err != nil || !strings.Contains(upOC, "'opencode-ai@latest'") || catOC == "" {
		t.Errorf("BuildAgentUpdateScript(opencode) = (%q, %q, %v)", upOC, catOC, err)
	}
	mntAgents := BuildGuestAgentsMountScript()
	for _, want := range []string{
		"/home/agent/.agbox-agents",
		"remount,ro,bind /home/agent/.local/bin/agy",
		"remount,ro,bind /usr/local/bin/opencode",
	} {
		if !strings.Contains(mntAgents, want) {
			t.Errorf("BuildGuestAgentsMountScript missing %q", want)
		}
	}
	profScript := BuildGuestProfileMountScript()
	if !strings.Contains(profScript, "/home/agent/.agbox-profile/agy-cli/settings.json") {
		t.Errorf("BuildGuestProfileMountScript missing settings.json profile seed")
	}
}
