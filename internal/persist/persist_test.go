package persist

import (
	"bytes"
	"encoding/base64"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"agbox/internal/msb"
)

func TestAuthCaptureSaveLoadRestoreRoundTripAndSecurity(t *testing.T) {
	guestSrcHome := t.TempDir()
	hostDataDir := filepath.Join(t.TempDir(), "agbox-data")
	guestDstHome := t.TempDir()

	// Exercise exported default-home wrappers.
	if s, err := BuildAuthCaptureScript("opencode"); err != nil || !strings.Contains(s, "/home/agent/.local/share/opencode/auth.json") {
		t.Fatalf("BuildAuthCaptureScript(opencode) = (%q, %v)", s, err)
	}
	if _, err := BuildAuthCaptureScript("invalid"); err == nil {
		t.Error("expected BuildAuthCaptureScript error for unsupported agent")
	}
	if _, err := buildAuthCaptureScriptForHome("opencode", ""); err == nil {
		t.Error("expected error for empty guestHome in buildAuthCaptureScriptForHome")
	}
	if s, err := FormatAuthRestoreScript(AuthBundle{}); err != nil || s != "" {
		t.Fatalf("FormatAuthRestoreScript(empty) = (%q, %v)", s, err)
	}
	if s, err := FormatAuthRestoreScript(AuthBundle{
		Files: []AuthFile{{Agent: "opencode", Name: "auth.json", Data: []byte(`{"ok":true}`)}},
	}); err != nil || !strings.Contains(s, "/home/agent/.local/share/opencode") {
		t.Fatalf("FormatAuthRestoreScript(non-empty) = (%q, %v)", s, err)
	}
	if _, err := formatAuthRestoreScriptForHome(AuthBundle{
		Files: []AuthFile{{Agent: "opencode", Name: "auth.json", Data: []byte(`{"ok":true}`)}},
	}, ""); err == nil {
		t.Error("expected error for empty guestHome in formatAuthRestoreScriptForHome")
	}

	// 1. Populate simulated guest credentials, including an empty 0-byte optional jetski_state.pbtxt file.
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
	// Empty 0-byte optional file must NOT break capture or ParseAuthCapture.
	if err := os.WriteFile(filepath.Join(agyDir, "jetski_state.pbtxt"), nil, 0o600); err != nil {
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

	// Unconfigured LoadAuthBundle returns empty bundle without error.
	if emptyB, err := LoadAuthBundle(hostDataDir, []string{"antigravity", "opencode"}); err != nil || !emptyB.IsEmpty() {
		t.Fatalf("LoadAuthBundle(unconfigured) = (%+v, %v)", emptyB, err)
	}

	// 2. Run /bin/sh capture scripts for both agents.
	for _, agent := range []string{"antigravity", "opencode"} {
		capScript, err := buildAuthCaptureScriptForHome(agent, guestSrcHome)
		if err != nil {
			t.Fatalf("buildAuthCaptureScriptForHome(%s): %v", agent, err)
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

	// 4. Plant a pre-existing symlink at the destination guest token path to verify restore unlinks it.
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

	// 5. Load bundle and run /bin/sh restore over stdin.
	loaded, err := LoadAuthBundle(hostDataDir, []string{"antigravity", "opencode", "", "opencode"})
	if err != nil || len(loaded.Files) != 4 {
		t.Fatalf("LoadAuthBundle = %d files, err=%v", len(loaded.Files), err)
	}
	restoreScript, err := formatAuthRestoreScriptForHome(loaded, guestDstHome)
	if err != nil {
		t.Fatalf("formatAuthRestoreScriptForHome: %v", err)
	}
	cmd := exec.Command("/bin/sh")
	cmd.Stdin = strings.NewReader(restoreScript)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("restore sh failed: %v, out=%s", err, string(out))
	}

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

	// [H6] Planted symlinks at guestHome or parent directories (.gemini or .gemini/antigravity-cli) must abort restore.
	victimDir := t.TempDir()
	symGuestHome := filepath.Join(t.TempDir(), "sym-home")
	if err := os.Symlink(victimDir, symGuestHome); err != nil {
		t.Fatal(err)
	}
	symHomeScript, err := formatAuthRestoreScriptForHome(loaded, symGuestHome)
	if err != nil {
		t.Fatal(err)
	}
	symHomeCmd := exec.Command("/bin/sh")
	symHomeCmd.Stdin = strings.NewReader(symHomeScript)
	if _, err := symHomeCmd.CombinedOutput(); err == nil {
		t.Fatal("expected restore script to reject symlinked guestHome")
	}

	parentSymHome := t.TempDir()
	if err := os.MkdirAll(filepath.Join(parentSymHome, ".gemini"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victimDir, filepath.Join(parentSymHome, ".gemini", "antigravity-cli")); err != nil {
		t.Fatal(err)
	}
	parentSymScript, err := formatAuthRestoreScriptForHome(loaded, parentSymHome)
	if err != nil {
		t.Fatal(err)
	}
	parentSymCmd := exec.Command("/bin/sh")
	parentSymCmd.Stdin = strings.NewReader(parentSymScript)
	if _, err := parentSymCmd.CombinedOutput(); err == nil {
		t.Fatal("expected restore script to reject symlinked .gemini/antigravity-cli parent directory")
	}
	if _, err := os.Lstat(filepath.Join(victimDir, "antigravity-oauth-token")); !os.IsNotExist(err) {
		t.Fatalf("CRITICAL: restore wrote secret through symlinked parent directory into %s", victimDir)
	}

	// Re-saving antigravity bundle without optional installation_id deletes stale installation_id on host.
	reAuthBundle := AuthBundle{
		Files: []AuthFile{{Agent: "antigravity", Name: "antigravity-oauth-token", Data: []byte("fresh-token")}},
	}
	if err := SaveAuthBundle(hostDataDir, reAuthBundle); err != nil {
		t.Fatalf("SaveAuthBundle(reAuth): %v", err)
	}
	if _, err := os.Lstat(filepath.Join(hostDataDir, "auth", "antigravity", "installation_id")); !os.IsNotExist(err) {
		t.Errorf("expected stale installation_id removed after re-auth, got err=%v", err)
	}

	// 6. Security rejections: guest symlink during capture, 3-field empty optional line, invalid base64, oversized, invalid JSON, duplicate, mismatch.
	symHome := t.TempDir()
	symAgy := filepath.Join(symHome, ".gemini", "antigravity-cli")
	_ = os.MkdirAll(symAgy, 0o700)
	_ = os.Symlink(canary, filepath.Join(symAgy, "antigravity-oauth-token"))
	symScript, _ := buildAuthCaptureScriptForHome("antigravity", symHome)
	symOut, symErr := exec.Command("/bin/sh", "-c", symScript).Output()
	if symErr == nil {
		t.Error("expected capture script to fail closed on symlinked guest token")
	}
	if _, err := ParseAuthCapture("antigravity", string(symOut)); err == nil || !strings.Contains(err.Error(), "refusing symlinked") {
		t.Errorf("expected ParseAuthCapture SYMLINK error, got %v", err)
	}

	validB64 := base64.StdEncoding.EncodeToString([]byte("secret"))
	threeFieldOut := "FILE antigravity antigravity-oauth-token " + validB64 + "\nFILE antigravity installation_id \n"
	if b3, err := ParseAuthCapture("antigravity", threeFieldOut); err != nil || len(b3.Files) != 1 {
		t.Errorf("expected 3-field empty optional line accepted, got (%+v, %v)", b3, err)
	}

	bigB64 := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte("a"), maxAuthFileBytes+1))
	for _, badCap := range []string{
		"",
		"BOGUS line",
		"FILE opencode auth.json " + validB64, // agent mismatch for antigravity
		"FILE antigravity ../../.bashrc " + validB64,
		"FILE antigravity antigravity-oauth-token !!!not-base64!!!",
		"FILE antigravity antigravity-oauth-token " + bigB64,
		"FILE antigravity antigravity-oauth-token " + validB64 + "\nFILE antigravity antigravity-oauth-token " + validB64,
	} {
		if _, err := ParseAuthCapture("antigravity", badCap); err == nil {
			t.Errorf("expected ParseAuthCapture(antigravity) error for %q", badCap)
		}
	}
	emptyJSON := base64.StdEncoding.EncodeToString([]byte("{}"))
	if _, err := ParseAuthCapture("opencode", "FILE opencode auth.json "+emptyJSON+"\n"); err == nil {
		t.Error("expected ParseAuthCapture to reject empty JSON object in auth.json")
	}
	badJSON := base64.StdEncoding.EncodeToString([]byte("not-json"))
	if _, err := ParseAuthCapture("opencode", "FILE opencode auth.json "+badJSON+"\n"); err == nil {
		t.Error("expected ParseAuthCapture to reject invalid JSON in auth.json")
	}
	if err := SaveAuthBundle(hostDataDir, AuthBundle{}); err == nil {
		t.Error("expected SaveAuthBundle error on empty bundle")
	}
	if err := SaveAuthBundle(hostDataDir, AuthBundle{Files: []AuthFile{{Agent: "opencode", Name: "evil", Data: []byte("x")}}}); err == nil {
		t.Error("expected SaveAuthBundle error on non-allowlisted file")
	}
	if _, err := LoadAuthBundle("", []string{"opencode"}); err == nil {
		t.Error("expected LoadAuthBundle error on empty dataDir")
	}

	// 7. RemoveAuth(opencode) keeps antigravity intact, LoadAuthBundle(both) returns only antigravity, and symlinked auth dir fails closed.
	if err := RemoveAuth(hostDataDir, "opencode"); err != nil {
		t.Fatalf("RemoveAuth(opencode): %v", err)
	}
	bothPartial, err := LoadAuthBundle(hostDataDir, []string{"antigravity", "opencode"})
	if err != nil || len(bothPartial.Files) != 1 || bothPartial.Files[0].Agent != "antigravity" {
		t.Fatalf("LoadAuthBundle(both with one configured) = (%+v, %v)", bothPartial, err)
	}
	st2, err := AuthStatus(hostDataDir)
	if err != nil || !st2["antigravity"] || st2["opencode"] {
		t.Fatalf("AuthStatus after RemoveAuth(opencode) = %+v, %v", st2, err)
	}

	hostTokenFile := filepath.Join(hostDataDir, "auth", "antigravity", "antigravity-oauth-token")
	_ = os.Remove(hostTokenFile)
	_ = os.Symlink(canary, hostTokenFile)
	if _, err := LoadAuthBundle(hostDataDir, []string{"antigravity"}); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Errorf("expected LoadAuthBundle symlink error, got: %v", err)
	}
	_ = os.Remove(hostTokenFile)

	if err := RemoveAuth(hostDataDir, "invalid-agent"); err == nil || !strings.Contains(err.Error(), "unknown logout target") {
		t.Errorf("expected unknown logout target error, got: %v", err)
	}
	if err := RemoveAuth(hostDataDir, ""); err != nil {
		t.Fatalf("RemoveAuth(all): %v", err)
	}

	// RemoveAuth fails closed when auth directory is a symlink.
	symDataDir := filepath.Join(t.TempDir(), "sym-auth-data")
	if err := os.MkdirAll(symDataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victimDir, filepath.Join(symDataDir, "auth")); err != nil {
		t.Fatal(err)
	}
	if err := RemoveAuth(symDataDir, "all"); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Errorf("expected RemoveAuth to reject symlinked auth directory, got %v", err)
	}
}

func TestGlobalSkillsInstallInspectRemoveAndSecurity(t *testing.T) {
	dataDir := filepath.Join(t.TempDir(), "data")
	skillsDir := filepath.Join(dataDir, "skills")

	got, err := InspectSkillsDir(skillsDir)
	if err != nil || len(got) != 0 {
		t.Fatalf("InspectSkillsDir(missing) = %v, %v", got, err)
	}

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

	installed, err := InstallSkill(skillsDir, filepath.Join(mySkill, "SKILL.md"), false)
	if err != nil || installed != "code-review" {
		t.Fatalf("InstallSkill = %q, %v", installed, err)
	}
	if _, err := InstallSkill(skillsDir, mySkill, false); err == nil {
		t.Error("expected duplicate InstallSkill without --force to fail")
	}

	// Update SKILL.md and replace atomically via backup swap with --force.
	_ = os.WriteFile(filepath.Join(mySkill, "SKILL.md"), []byte("---\nname: code-review\ndescription: Updated.\n---\n"), 0o644)
	if _, err := InstallSkill(skillsDir, mySkill, true); err != nil {
		t.Fatalf("InstallSkill(--force): %v", err)
	}
	updatedBytes, _ := os.ReadFile(filepath.Join(skillsDir, "code-review", "SKILL.md"))
	if !strings.Contains(string(updatedBytes), "Updated.") {
		t.Errorf("expected updated SKILL.md after --force, got %q", string(updatedBytes))
	}
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

	// Reject non-SKILL.md file path, empty path, symlink in source, and > maxSkillFiles.
	if _, err := InstallSkill(skillsDir, "", true); err == nil {
		t.Error("expected error for empty skill srcPath")
	}
	otherFile := filepath.Join(mySkill, "scripts", "lint.sh")
	if _, err := InstallSkill(skillsDir, otherFile, true); err == nil {
		t.Error("expected error when passing non-SKILL.md file path")
	}
	symSkill := filepath.Join(srcRoot, "sym-skill")
	_ = os.MkdirAll(symSkill, 0o755)
	_ = os.WriteFile(filepath.Join(symSkill, "SKILL.md"), []byte("# Sym\n"), 0o644)
	_ = os.Symlink("/etc/passwd", filepath.Join(symSkill, "leak"))
	if _, err := InstallSkill(skillsDir, symSkill, true); err == nil {
		t.Error("expected InstallSkill to reject symlink in source")
	}

	floodSkill := filepath.Join(srcRoot, "flood-skill")
	_ = os.MkdirAll(floodSkill, 0o755)
	_ = os.WriteFile(filepath.Join(floodSkill, "SKILL.md"), []byte("# Flood\n"), 0o644)
	for i := range maxSkillFiles + 1 {
		_ = os.WriteFile(filepath.Join(floodSkill, "f"+strconv.Itoa(i)+".txt"), []byte("x"), 0o644)
	}
	if _, err := InstallSkill(skillsDir, floodSkill, true); err == nil {
		t.Error("expected InstallSkill to reject skill exceeding maxSkillFiles")
	}

	// Security checks: symlink inside skillsDir, FIFO inside skillsDir, and symlinked skill entry on RemoveSkill.
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

	symSkillEntry := filepath.Join(skillsDir, "sym-entry")
	if err := os.Symlink(mySkill, symSkillEntry); err != nil {
		t.Fatal(err)
	}
	if err := RemoveSkill(skillsDir, "sym-entry"); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Errorf("expected RemoveSkill to reject symlinked skill entry, got %v", err)
	}
	_ = os.Remove(symSkillEntry)

	for _, badDir := range []string{"", "/tmp/bad:dir/skills", "/tmp/bad,dir/skills", "/tmp/bad\ndir/skills"} {
		if _, err := InspectSkillsDir(badDir); err == nil {
			t.Errorf("expected InspectSkillsDir(%q) to fail", badDir)
		}
	}

	for _, bad := range []string{"", ".git", ".jj", "-bad", "bad/slash", "bad..dot", strings.Repeat("s", 64)} {
		if _, err := validateSkillName(bad); err == nil {
			t.Errorf("expected validateSkillName(%q) to fail", bad)
		}
	}

	if err := RemoveSkill(skillsDir, "code-review"); err != nil {
		t.Fatalf("RemoveSkill: %v", err)
	}
	if err := RemoveSkill(skillsDir, "code-review"); err == nil {
		t.Error("expected RemoveSkill on missing skill to fail")
	}

	noMDSrc := filepath.Join(srcRoot, "no-md-skill")
	if err := os.MkdirAll(noMDSrc, 0o755); err != nil {
		t.Fatal(err)
	}
	freshSkillsDir := filepath.Join(t.TempDir(), "skills-fresh")
	if _, err := InstallSkill(freshSkillsDir, noMDSrc, false); err == nil {
		t.Error("expected InstallSkill to fail when SKILL.md is missing")
	}
	if entries, err := os.ReadDir(freshSkillsDir); err == nil && len(entries) > 0 {
		t.Errorf("expected clean skillsDir after failed install, got %d entries", len(entries))
	}

	strayFile := filepath.Join(skillsDir, "stray.txt")
	if err := os.WriteFile(strayFile, []byte("text"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := InspectSkillsDir(skillsDir); err == nil {
		t.Error("expected InspectSkillsDir to reject non-directory file")
	}
	_ = os.Remove(strayFile)

	hiddenDir := filepath.Join(skillsDir, ".hidden")
	if err := os.MkdirAll(hiddenDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := InspectSkillsDir(skillsDir); err == nil {
		t.Error("expected InspectSkillsDir to reject hidden directory")
	}
	_ = os.RemoveAll(hiddenDir)

	mountScript := BuildGuestSkillsMountScript()
	if !strings.Contains(mountScript, "/home/agent/.gemini/config/skills") ||
		!strings.Contains(mountScript, "/home/agent/.config/opencode/skills") ||
		!strings.Contains(mountScript, "remount,ro,bind") ||
		strings.Contains(mountScript, "|| true") {
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
		if _, err := LockProfile(dataDir, badName); err == nil {
			t.Errorf("expected LockProfile(%q) to fail", badName)
		}
		if err := RemoveProfileDir(dataDir, badName); err == nil {
			t.Errorf("expected RemoveProfileDir(%q) to fail", badName)
		}
	}
	if IsProfileVolumeName("other-vol") || IsProfileVolumeName("agbox-profile-") {
		t.Error("expected non-profile volume names to return false")
	}

	// [H9] Exclusive flock sits at profiles/.<name>.lock outside profiles/<name>,
	// so holding lock1 while calling RemoveProfileDir continues blocking concurrent LockProfile!
	if err := SaveProfileMeta(dataDir, ProfileMeta{Name: "work", Size: "10G"}); err != nil {
		t.Fatalf("SaveProfileMeta: %v", err)
	}
	lock1, err := LockProfile(dataDir, "work")
	if err != nil {
		t.Fatalf("LockProfile(1): %v", err)
	}
	if _, err := LockProfile(dataDir, "work"); err == nil || !strings.Contains(err.Error(), "holds the lock on profile") {
		t.Fatalf("expected EWOULDBLOCK lock message, got %v", err)
	}
	if err := RemoveProfileDir(dataDir, "work"); err != nil {
		t.Fatalf("RemoveProfileDir while locked: %v", err)
	}
	if _, err := LockProfile(dataDir, "work"); err == nil {
		t.Fatal("expected LockProfile(work) to remain blocked after RemoveProfileDir until lock1.Unlock()")
	}

	lockOther, err := LockProfile(dataDir, "oss")
	if err != nil {
		t.Fatalf("LockProfile(oss): %v", err)
	}
	_ = lockOther.Unlock()

	if err := lock1.Unlock(); err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	// Double Unlock is a safe no-op.
	if err := lock1.Unlock(); err != nil {
		t.Fatalf("second Unlock: %v", err)
	}
	var nilLock *ProfileLock
	if err := nilLock.Unlock(); err != nil {
		t.Fatalf("nil Unlock: %v", err)
	}

	lock2, err := LockProfile(dataDir, "work")
	if err != nil {
		t.Fatalf("LockProfile after Unlock failed: %v", err)
	}
	_ = lock2.Unlock()

	// Symlinked lock file fails closed.
	lockSym := filepath.Join(dataDir, "profiles", ".symprof.lock")
	if err := os.Symlink("/etc/passwd", lockSym); err != nil {
		t.Fatal(err)
	}
	if _, err := LockProfile(dataDir, "symprof"); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Errorf("expected LockProfile to reject symlinked lock file, got %v", err)
	}
	_ = os.Remove(lockSym)

	fixedTime := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	if err := saveProfileMetaAt(dataDir, ProfileMeta{Name: "work", Size: "10G"}, func() time.Time { return fixedTime }); err != nil {
		t.Fatalf("saveProfileMetaAt: %v", err)
	}
	if err := SaveProfileMeta(dataDir, ProfileMeta{Name: "alpha", Size: "20G"}); err != nil {
		t.Fatalf("SaveProfileMeta: %v", err)
	}
	// Directory without profile.json is skipped cleanly.
	if err := os.MkdirAll(filepath.Join(dataDir, "profiles", "emptyprof"), 0o700); err != nil {
		t.Fatal(err)
	}
	profiles, err := ListProfiles(dataDir)
	if err != nil || len(profiles) != 2 || profiles[0].Name != "alpha" || profiles[1].Name != "work" || profiles[1].CreatedAt != "2026-05-01T12:00:00Z" {
		t.Fatalf("ListProfiles = %+v, %v", profiles, err)
	}

	// Corrupt profile.json and mismatched pm.Name fail closed in ListProfiles.
	badDir := filepath.Join(dataDir, "profiles", "corrupt")
	_ = os.MkdirAll(badDir, 0o700)
	_ = os.WriteFile(filepath.Join(badDir, "profile.json"), []byte("{not-json"), 0o600)
	if _, err := ListProfiles(dataDir); err == nil {
		t.Error("expected ListProfiles error on corrupt profile.json")
	}
	_ = os.WriteFile(filepath.Join(badDir, "profile.json"), []byte(`{"name":"wrong","volume":"agbox-profile-corrupt","size":"10G"}`), 0o600)
	if _, err := ListProfiles(dataDir); err == nil || !strings.Contains(err.Error(), "name mismatch") {
		t.Errorf("expected ListProfiles error on name mismatch, got %v", err)
	}
	_ = os.RemoveAll(badDir)

	// Symlinked profile directory rejected by ListProfiles and RemoveProfileDir.
	symProfDir := filepath.Join(dataDir, "profiles", "symdir")
	_ = os.Symlink(t.TempDir(), symProfDir)
	if _, err := ListProfiles(dataDir); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Errorf("expected ListProfiles to reject symlinked profile dir, got %v", err)
	}
	if err := RemoveProfileDir(dataDir, "symdir"); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Errorf("expected RemoveProfileDir to reject symlinked profile dir, got %v", err)
	}
	_ = os.Remove(symProfDir)

	if err := RemoveProfileDir(dataDir, "alpha"); err != nil {
		t.Fatalf("RemoveProfileDir: %v", err)
	}

	profScript := BuildGuestProfileMountScript()
	for _, want := range []string{
		"grep -qs ' /home/agent/.agbox-profile ' /proc/self/mountinfo",
		"/home/agent/.agbox-profile/agy-cli",
		"/home/agent/.agbox-profile/agy-projects",
		"/home/agent/.agbox-profile/opencode-data",
		"/home/agent/.agbox-profile/opencode-state",
	} {
		if !strings.Contains(profScript, want) {
			t.Errorf("profile mount script missing %q", want)
		}
	}
	if !strings.HasSuffix(strings.TrimSpace(profScript), "sync") {
		t.Errorf("profile mount script should end with sync, got %q", profScript)
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

	// Non-existent rulesDir returns nil, nil on InspectRulesDir and nil on RemoveAllRules.
	if names, err := InspectRulesDir(rulesDir); err != nil || len(names) != 0 {
		t.Fatalf("InspectRulesDir(missing) = (%v, %v), want (nil, nil)", names, err)
	}
	if err := RemoveAllRules(rulesDir); err != nil {
		t.Fatalf("RemoveAllRules(missing) = %v, want nil", err)
	}

	for _, badRuleName := range []string{"", ".md", "-bad", ".bad", "bad/name", "bad$name", strings.Repeat("r", 64)} {
		if _, err := ValidateRuleName(badRuleName); err == nil {
			t.Errorf("expected ValidateRuleName(%q) to fail", badRuleName)
		}
	}

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
	if _, _, err := InstallRule(rulesDir, agentsSrc, "   ", true); err == nil {
		t.Error("expected InstallRule with whitespace overrideName to fail")
	}

	crlfSrc := filepath.Join(srcDir, "crlf-rule.md")
	crlfContent := "---\r\ntrigger: model_decision\r\ndescription: decision rule\r\n---\r\n# CRLF Rule Content\r\n"
	if err := os.WriteFile(crlfSrc, []byte(crlfContent), 0o644); err != nil {
		t.Fatal(err)
	}
	if name, _, err := InstallRule(rulesDir, crlfSrc, "", false); err != nil || name != "crlf-rule" {
		t.Fatalf("InstallRule(crlfSrc) = (%q, %v)", name, err)
	}

	manualSrc := filepath.Join(srcDir, "manual-rule.md")
	manualContent := "---\r\ntrigger: manual\r\ndescription: manual rule\r\n---\r\n# Manual Rule Content\r\n"
	if err := os.WriteFile(manualSrc, []byte(manualContent), 0o644); err != nil {
		t.Fatal(err)
	}
	if name, _, err := InstallRule(rulesDir, manualSrc, "", false); err != nil || name != "manual-rule" {
		t.Fatalf("InstallRule(manualSrc) = (%q, %v)", name, err)
	}

	names, err := InspectRulesDir(rulesDir)
	if err != nil || !slices.Equal(names, []string{"AGENTS", "crlf-rule", "go-style", "manual-rule", "testing"}) {
		t.Fatalf("InspectRulesDir = (%v, %v)", names, err)
	}
	rawAgents, err := ReadRule(rulesDir, "AGENTS.md")
	if err != nil || !strings.Contains(string(rawAgents), "Core Standards") {
		t.Fatalf("ReadRule(AGENTS.md) = (%q, %v)", string(rawAgents), err)
	}
	if _, err := ReadRule(rulesDir, "missing-rule"); err == nil {
		t.Error("expected ReadRule error on missing rule")
	}
	if err := RemoveRule(rulesDir, "missing-rule"); err == nil {
		t.Error("expected RemoveRule error on missing rule")
	}

	// Execute buildGuestRulesStageScript via /bin/sh and verify combined AGENTS.md and modular rules/*.md.
	stageDir := filepath.Join(base, "staged")
	stageCmd := exec.Command("/bin/sh", "-c", buildGuestRulesStageScript(rulesDir, stageDir))
	if out, sErr := stageCmd.CombinedOutput(); sErr != nil {
		t.Fatalf("buildGuestRulesStageScript failed: %v (%s)", sErr, string(out))
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
	if strings.Contains(combinedStr, "CRLF Rule Content") || strings.Contains(combinedStr, "Manual Rule Content") {
		t.Errorf("staged AGENTS.md leaked modular rule body: %q", combinedStr)
	}
	if strings.Index(combinedStr, "# Core Standards") > strings.Index(combinedStr, "# Testing") {
		t.Errorf("expected AGENTS.md priority content before testing.md: %q", combinedStr)
	}
	if globStaged, err := os.ReadFile(filepath.Join(stageDir, "rules", "go-style.md")); err != nil || !strings.Contains(string(globStaged), "trigger: glob") {
		t.Errorf("staged modular rule = (%q, %v)", string(globStaged), err)
	}

	// Symlink inside guest rules mount prints clear error and exits non-zero in buildGuestRulesStageScript.
	symStageSrc := filepath.Join(base, "sym-stage-src")
	_ = os.MkdirAll(symStageSrc, 0o700)
	_ = os.Symlink("/etc/passwd", filepath.Join(symStageSrc, "evil.md"))
	symStageOut, symStageErr := exec.Command("/bin/sh", "-c", buildGuestRulesStageScript(symStageSrc, filepath.Join(base, "sym-staged"))).CombinedOutput()
	if symStageErr == nil || !strings.Contains(string(symStageOut), "rejects symlinked rule") {
		t.Errorf("expected buildGuestRulesStageScript symlink error message, got err=%v out=%q", symStageErr, string(symStageOut))
	}

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
	if strings.Contains(mntScript, "remount,ro,bind \"$dst\" 2>/dev/null || true") || strings.Contains(mntScript, "remount,ro,bind /home/agent/.gemini/config/rules 2>/dev/null || true") {
		t.Errorf("BuildGuestRulesMountScript must not mask remount failure with || true: %s", mntScript)
	}

	// Boundary rejections: empty 0-byte, whitespace-only, binary NUL, oversize, non-.md, uppercase .MD, directory, symlink.
	zeroSrc := filepath.Join(srcDir, "zero.md")
	wsSrc := filepath.Join(srcDir, "ws.md")
	nulSrc := filepath.Join(srcDir, "nul.md")
	bigSrc := filepath.Join(srcDir, "big.md")
	txtSrc := filepath.Join(srcDir, "plain.txt")
	upperSrc := filepath.Join(srcDir, "UPPER.MD")
	_ = os.WriteFile(zeroSrc, nil, 0o644)
	_ = os.WriteFile(wsSrc, []byte("  \n"), 0o644)
	_ = os.WriteFile(nulSrc, []byte("bad\x00rule"), 0o644)
	_ = os.WriteFile(bigSrc, bytes.Repeat([]byte("a"), maxRuleFileBytes+1), 0o644)
	_ = os.WriteFile(txtSrc, []byte("# Plain\n"), 0o644)
	_ = os.WriteFile(upperSrc, []byte("# Upper\n"), 0o644)
	for _, badFile := range []string{"", srcDir, zeroSrc, wsSrc, nulSrc, bigSrc, txtSrc, upperSrc} {
		if _, _, bErr := InstallRule(rulesDir, badFile, "", true); bErr == nil {
			t.Errorf("expected InstallRule(%s) to fail", badFile)
		}
	}
	if name, _, nErr := InstallRule(rulesDir, txtSrc, "from-txt", false); nErr != nil || name != "from-txt" {
		t.Errorf("InstallRule(plain.txt --name from-txt) = (%q, %v)", name, nErr)
	}

	// Uppercase .MD file, subdirectory, or symlink inside rulesDir fails InspectRulesDir and RemoveAllRules.
	upperInDir := filepath.Join(rulesDir, "BadCase.MD")
	_ = os.WriteFile(upperInDir, []byte("# Bad\n"), 0o644)
	if _, err := InspectRulesDir(rulesDir); err == nil {
		t.Error("expected InspectRulesDir to reject uppercase .MD file")
	}
	_ = os.Remove(upperInDir)

	subInRules := filepath.Join(rulesDir, "subdir")
	_ = os.MkdirAll(subInRules, 0o700)
	if err := RemoveAllRules(rulesDir); err == nil {
		t.Error("expected RemoveAllRules to reject subdirectory inside rulesDir")
	}
	_ = os.RemoveAll(subInRules)

	symRule := filepath.Join(rulesDir, "evil.md")
	if err := os.Symlink("/etc/passwd", symRule); err != nil {
		t.Fatal(err)
	}
	if _, sErr := InspectRulesDir(rulesDir); sErr == nil {
		t.Fatal("expected InspectRulesDir to reject symlink inside rulesDir")
	}
	if err := RemoveRule(rulesDir, "evil"); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Errorf("expected RemoveRule to reject symlinked rule, got %v", err)
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

	if _, err := agentBinName("unknown"); err == nil {
		t.Error("expected agentBinName error on unknown agent")
	}
	for _, badDir := range []string{"", "/tmp/bad:agents", "/tmp/bad,agents", "/tmp/bad\nagents"} {
		if err := EnsureAgentsDir(badDir); err == nil {
			t.Errorf("expected EnsureAgentsDir(%q) to fail", badDir)
		}
	}
	if got, err := InspectAgentsDir(""); err != nil || got != nil {
		t.Errorf("InspectAgentsDir(empty) = (%v, %v)", got, err)
	}
	if got, err := InspectAgentsDir(agentsDir); err != nil || len(got) != 0 {
		t.Fatalf("InspectAgentsDir(missing) = (%v, %v)", got, err)
	}

	agyELF := append([]byte{0x7f, 'E', 'L', 'F'}, bytes.Repeat([]byte("A"), 128)...)
	ocELF := append([]byte{0x7f, 'E', 'L', 'F'}, bytes.Repeat([]byte("O"), 160)...)

	cwInit, err := NewAgentBinaryCaptureWriter(agentsDir, "antigravity")
	if err != nil {
		t.Fatalf("NewAgentBinaryCaptureWriter: %v", err)
	}
	fixedClock := time.Date(2026, 6, 15, 10, 30, 0, 0, time.UTC)
	cwInit.Now = func() time.Time { return fixedClock }
	if _, err := cwInit.Write(agyELF); err != nil {
		t.Fatal(err)
	}
	if cwInit.Written() != int64(len(agyELF)) {
		t.Fatalf("Written() = %d, want %d", cwInit.Written(), len(agyELF))
	}
	agyInfo, err := cwInit.Commit("2.1.0\nextra-line")
	if err != nil {
		t.Fatalf("Commit(antigravity): %v", err)
	}
	if agyInfo.BinName != "agy" || agyInfo.Version != "2.1.0" || agyInfo.SizeBytes != int64(len(agyELF)) || agyInfo.UpdatedAt != "2026-06-15T10:30:00Z" {
		t.Fatalf("unexpected agyInfo: %+v", agyInfo)
	}

	ocInfo, err := installAgentBinaryFromReader(agentsDir, "opencode", "1.4.2", bytes.NewReader(ocELF))
	if err != nil {
		t.Fatalf("installAgentBinaryFromReader(opencode): %v", err)
	}
	if ocInfo.BinName != "opencode" || ocInfo.Version != "1.4.2" {
		t.Fatalf("unexpected ocInfo: %+v", ocInfo)
	}

	// Update existing binary in place via copy-backup + atomic Rename (keeping st_nlink == 1).
	ocELF2 := append([]byte{0x7f, 'E', 'L', 'F'}, bytes.Repeat([]byte("P"), 180)...)
	if _, err := installAgentBinaryFromReader(agentsDir, "opencode", "1.5.0", bytes.NewReader(ocELF2)); err != nil {
		t.Fatalf("overwrite installAgentBinaryFromReader(opencode): %v", err)
	}

	cached, err := InspectAgentsDir(agentsDir)
	if err != nil || len(cached) != 2 || cached[0].Agent != "antigravity" || cached[1].Agent != "opencode" || cached[1].Version != "1.5.0" {
		t.Fatalf("InspectAgentsDir = (%+v, %v)", cached, err)
	}

	// Overflow test without allocating 1 GiB.
	cwOverflow, err := NewAgentBinaryCaptureWriter(agentsDir, "opencode")
	if err != nil {
		t.Fatal(err)
	}
	cwOverflow.written = maxAgentBinaryBytes - 2
	if _, err := cwOverflow.Write([]byte("1234")); err == nil {
		t.Error("expected Write error when exceeding maxAgentBinaryBytes")
	}
	if _, err := cwOverflow.Commit("9.9.9"); err == nil {
		t.Error("expected Commit error after overflow")
	}

	// Version sanitization: control chars stripped, >128 truncated, empty -> unknown.
	if got := sanitizeSingleLineVersion("  \x07\x7f  \nsecond"); got != "unknown" {
		t.Errorf("sanitizeSingleLineVersion(empty) = %q, want unknown", got)
	}
	if got := sanitizeSingleLineVersion(strings.Repeat("v", 200)); len(got) != 128 {
		t.Errorf("sanitizeSingleLineVersion(200) len = %d, want 128", len(got))
	}

	// Reject non-ELF binary streams and undersized streams without corrupting existing cache.
	if _, err := installAgentBinaryFromReader(agentsDir, "antigravity", "bad", bytes.NewReader(bytes.Repeat([]byte("X"), 128))); err == nil {
		t.Fatal("expected non-ELF binary stream to be rejected")
	}
	if _, err := installAgentBinaryFromReader(agentsDir, "antigravity", "tiny", bytes.NewReader([]byte{0x7f, 'E', 'L', 'F'})); err == nil {
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

	// RemoveCachedAgent(opencode) fails closed if manifest.json is corrupt, while target=="all" succeeds.
	mFile := filepath.Join(agentsDir, "manifest.json")
	origManifest, err := os.ReadFile(mFile)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(mFile, []byte("{corrupt"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := RemoveCachedAgent(agentsDir, "opencode"); err == nil {
		t.Fatal("expected RemoveCachedAgent(opencode) to fail on corrupt manifest.json instead of orphaning antigravity")
	}
	if err := os.WriteFile(mFile, origManifest, 0o600); err != nil {
		t.Fatal(err)
	}

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
	if err := RemoveCachedAgent(agentsDir, "bad-target"); err == nil {
		t.Error("expected RemoveCachedAgent error for unsupported target")
	}

	// Verify BuildAgentUpdateScript (pipefail + proto-redir) and BuildGuestAgentsMountScript (no || true on remount).
	upAgy, catAgy, _, err := BuildAgentUpdateScript("antigravity", "", "")
	if err != nil || !strings.Contains(upAgy, "set -o pipefail") || !strings.Contains(upAgy, "--proto-redir") || !strings.Contains(upAgy, "=https") || !strings.Contains(upAgy, "--tlsv1.2") || catAgy == "" {
		t.Errorf("BuildAgentUpdateScript(antigravity) = (%q, %q, %v)", upAgy, catAgy, err)
	}
	upOC, catOC, _, err := BuildAgentUpdateScript("opencode", "latest", "")
	if err != nil || !strings.Contains(upOC, "'opencode-ai@latest'") || catOC == "" {
		t.Errorf("BuildAgentUpdateScript(opencode) = (%q, %q, %v)", upOC, catOC, err)
	}
	if _, _, _, err := BuildAgentUpdateScript("unknown", "", ""); err == nil {
		t.Error("expected BuildAgentUpdateScript error for unsupported agent")
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
	if strings.Contains(mntAgents, "remount,ro,bind /home/agent/.local/bin/agy 2>/dev/null || true") {
		t.Errorf("BuildGuestAgentsMountScript must not ignore remount failure: %s", mntAgents)
	}

	customURL := "https://example.com/custom agy $(id).sh"
	upCustom, _, _, err := BuildAgentUpdateScript("antigravity", "", customURL)
	if err != nil {
		t.Fatalf("BuildAgentUpdateScript: %v", err)
	}
	wantEscaped := strings.TrimPrefix(strings.TrimSuffix(msb.ShellQuote(msb.ShellQuote(customURL)), "'"), "'")
	if !strings.Contains(upCustom, wantEscaped) {
		t.Errorf("BuildAgentUpdateScript missing quoted agyURL: %s", upCustom)
	}
	cmd := exec.Command("bash", "-n")
	cmd.Stdin = strings.NewReader(upCustom)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Errorf("BuildAgentUpdateScript bash -n failed: %v, out=%s", err, out)
	}

	// Writer abort, write-after-close, and double-commit checks.
	abortDir := filepath.Join(t.TempDir(), "agents-abort")
	cw, err := NewAgentBinaryCaptureWriter(abortDir, "opencode")
	if err != nil {
		t.Fatalf("NewAgentBinaryCaptureWriter: %v", err)
	}
	cw.Abort()
	if _, err := cw.Write([]byte("x")); err == nil {
		t.Error("expected Write after Abort to fail")
	}
	if _, err := cw.Commit("1.0.0"); err == nil {
		t.Error("expected Commit after Abort to fail")
	}

	// Rollback checks:
	rollbackDir := filepath.Join(t.TempDir(), "agents-rollback")
	origELF := append(bytes.Repeat([]byte{0x7f, 'E', 'L', 'F'}, 1), bytes.Repeat([]byte{0xaa}, 1024)...)
	newELF := append(bytes.Repeat([]byte{0x7f, 'E', 'L', 'F'}, 1), bytes.Repeat([]byte{0xbb}, 1024)...)
	if _, err := installAgentBinaryFromReader(rollbackDir, "opencode", "1.0.0", bytes.NewReader(origELF)); err != nil {
		t.Fatalf("initial install: %v", err)
	}
	binDst := filepath.Join(rollbackDir, "bin", "opencode")

	// Block manifest.json by replacing it with a directory.
	mPath := filepath.Join(rollbackDir, "manifest.json")
	if err := os.Remove(mPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(mPath, 0o700); err != nil {
		t.Fatal(err)
	}

	cw2, err := NewAgentBinaryCaptureWriter(rollbackDir, "opencode")
	if err != nil {
		t.Fatalf("NewAgentBinaryCaptureWriter: %v", err)
	}
	if _, err := cw2.Write(newELF); err != nil {
		t.Fatal(err)
	}
	if _, err := cw2.Commit("2.0.0"); err == nil {
		t.Error("expected Commit to fail when manifest save fails")
	}
	restored, err := os.ReadFile(binDst)
	if err != nil || !bytes.Equal(restored, origELF) {
		t.Fatalf("expected original binary restored on rollback: err=%v, match=%v", err, bytes.Equal(restored, origELF))
	}

	cw3, err := NewAgentBinaryCaptureWriter(rollbackDir, "antigravity")
	if err != nil {
		t.Fatalf("NewAgentBinaryCaptureWriter(antigravity): %v", err)
	}
	if _, err := cw3.Write(newELF); err != nil {
		t.Fatal(err)
	}
	if _, err := cw3.Commit("2.0.0"); err == nil {
		t.Error("expected Commit to fail when manifest save fails")
	}
	agyDst := filepath.Join(rollbackDir, "bin", "agy")
	if _, err := os.Lstat(agyDst); !os.IsNotExist(err) {
		t.Errorf("expected newly created binary removed on rollback, got err=%v", err)
	}

	// [M5] Concurrent updates across goroutines serialize cleanly via .agents.lock without corrupting manifest.json.
	concDir := filepath.Join(t.TempDir(), "conc-data", "agents")
	var wg sync.WaitGroup
	for i := range 6 {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			ag := "opencode"
			if idx%2 == 0 {
				ag = "antigravity"
			}
			payload := append([]byte{0x7f, 'E', 'L', 'F'}, bytes.Repeat([]byte{byte('a' + idx)}, 96)...)
			if _, cErr := installAgentBinaryFromReader(concDir, ag, "1.0."+strconv.Itoa(idx), bytes.NewReader(payload)); cErr != nil {
				t.Errorf("concurrent install %d failed: %v", idx, cErr)
			}
		}(i)
	}
	wg.Wait()
	if concCached, err := InspectAgentsDir(concDir); err != nil || len(concCached) != 2 {
		t.Fatalf("InspectAgentsDir after concurrent updates = (%+v, %v)", concCached, err)
	}

	// [M5] readRegularNoFollow rejects files exceeding maxBytes.
	growFile := filepath.Join(t.TempDir(), "grow.txt")
	if err := os.WriteFile(growFile, []byte("123456"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readRegularNoFollow(growFile, 5); err == nil || !strings.Contains(err.Error(), "exceeds 5 bytes") {
		t.Errorf("expected readRegularNoFollow size error, got %v", err)
	}
}

func TestDefaultEnvRuleAndEnsureIdempotent(t *testing.T) {
	// 1. Verify defaultEnvRuleMarkdown states EROFS on /workspace root ([L1]) and root file is valid Markdown rule.
	if !strings.Contains(defaultEnvRuleMarkdown, "rejects direct file creation (`EROFS`)") {
		t.Fatalf("expected defaultEnvRuleMarkdown to document EROFS on /workspace root: %s", defaultEnvRuleMarkdown)
	}
	rootContent, err := os.ReadFile("../../AGBOX_ENV_RULES.md")
	if err != nil {
		t.Fatalf("read root AGBOX_ENV_RULES.md: %v", err)
	}
	for _, heading := range []string{
		"# Operating Inside an agbox Sandbox",
		"## Guest Identity and Privileges",
		"## Workspace Shares and Permissions",
		"## Host Mounts, Hardware, and Network Boundaries",
	} {
		if !strings.Contains(string(rootContent), heading) || !strings.Contains(defaultEnvRuleMarkdown, heading) {
			t.Fatalf("missing required section %q in AGBOX_ENV_RULES.md or defaultEnvRuleMarkdown", heading)
		}
	}

	// 2. Fresh directory: EnsureDefaultEnvRule creates AGBOX_ENV_RULES.md with mode 0644.
	rulesDir := filepath.Join(t.TempDir(), "rules")
	created, err := EnsureDefaultEnvRule(rulesDir)
	if err != nil {
		t.Fatalf("EnsureDefaultEnvRule failed: %v", err)
	}
	if !created {
		t.Fatal("expected created == true on initial install")
	}
	rulePath := filepath.Join(rulesDir, DefaultEnvRuleName+".md")
	info, err := os.Lstat(rulePath)
	if err != nil {
		t.Fatalf("stat installed rule: %v", err)
	}
	if info.Mode().Perm() != 0o644 {
		t.Fatalf("expected permissions 0644, got %v", info.Mode().Perm())
	}
	names, err := InspectRulesDir(rulesDir)
	if err != nil {
		t.Fatalf("InspectRulesDir failed: %v", err)
	}
	if !slices.Equal(names, []string{DefaultEnvRuleName}) {
		t.Fatalf("expected [%s], got %v", DefaultEnvRuleName, names)
	}

	stageDir := filepath.Join(t.TempDir(), "staged")
	stageCmd := exec.Command("/bin/sh", "-c", buildGuestRulesStageScript(rulesDir, stageDir))
	if out, sErr := stageCmd.CombinedOutput(); sErr != nil {
		t.Fatalf("buildGuestRulesStageScript failed: %v (%s)", sErr, string(out))
	}
	staged, err := os.ReadFile(filepath.Join(stageDir, "AGENTS.md"))
	if err != nil {
		t.Fatalf("read staged AGENTS.md: %v", err)
	}
	if !strings.Contains(string(staged), "Operating Inside an agbox Sandbox") {
		t.Fatalf("staged AGENTS.md missing default rule text: %s", string(staged))
	}

	// 3. Second call returns created == false and preserves custom edits.
	customText := "# Custom Rules Content\n"
	if err := os.WriteFile(rulePath, []byte(customText), 0o644); err != nil {
		t.Fatalf("write custom edits: %v", err)
	}
	createdSecond, err := EnsureDefaultEnvRule(rulesDir)
	if err != nil {
		t.Fatalf("second EnsureDefaultEnvRule failed: %v", err)
	}
	if createdSecond {
		t.Fatal("expected created == false on existing rule")
	}
	contentAfter, err := os.ReadFile(rulePath)
	if err != nil {
		t.Fatalf("read rule after second call: %v", err)
	}
	if string(contentAfter) != customText {
		t.Fatalf("expected custom edits preserved, got: %s", string(contentAfter))
	}

	// 4. Failure cases: empty dir, ':', ',', control char, symlink dir, symlink entry.
	for _, badDir := range []string{"", "/tmp/bad:dir", "/tmp/bad,dir", "/tmp/bad\ndir"} {
		if _, err := EnsureDefaultEnvRule(badDir); err == nil {
			t.Errorf("expected error for invalid rulesDir %q", badDir)
		}
	}

	realRulesDir := filepath.Join(t.TempDir(), "real-rules")
	if err := os.MkdirAll(realRulesDir, 0o700); err != nil {
		t.Fatal(err)
	}
	symlinkRules := filepath.Join(t.TempDir(), "symlink-rules")
	if err := os.Symlink(realRulesDir, symlinkRules); err != nil {
		t.Fatal(err)
	}
	if _, err := EnsureDefaultEnvRule(symlinkRules); err == nil {
		t.Error("expected error when rulesDir is a symlink")
	}

	entryDir := filepath.Join(t.TempDir(), "entry-rules")
	if err := os.MkdirAll(entryDir, 0o700); err != nil {
		t.Fatal(err)
	}
	outsideFile := filepath.Join(t.TempDir(), "outside.md")
	if err := os.WriteFile(outsideFile, []byte("# Outside\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outsideFile, filepath.Join(entryDir, "linked.md")); err != nil {
		t.Fatal(err)
	}
	if _, err := EnsureDefaultEnvRule(entryDir); err == nil {
		t.Error("expected error when rulesDir contains a symlink entry")
	}
}

func TestNonBlockingFIFOOpensRejectImmediately(t *testing.T) {
	td := t.TempDir()
	fifoRule := filepath.Join(td, "pipe.md")
	if err := syscall.Mkfifo(fifoRule, 0o600); err != nil {
		t.Fatalf("Mkfifo(%s): %v", fifoRule, err)
	}
	fifoBin := filepath.Join(td, "agy-fifo")
	if err := syscall.Mkfifo(fifoBin, 0o600); err != nil {
		t.Fatalf("Mkfifo(%s): %v", fifoBin, err)
	}
	dstBackup := filepath.Join(td, "backup-out")
	rulesDir := filepath.Join(td, "rules")

	done := make(chan struct{})
	go func() {
		defer close(done)
		if _, err := readRegularNoFollow(fifoRule, 1024); err == nil {
			t.Error("expected readRegularNoFollow to reject FIFO")
		}
		if _, _, err := InstallRule(rulesDir, fifoRule, "pipe", false); err == nil {
			t.Error("expected InstallRule to reject FIFO")
		}
		if _, _, err := verifyAgentBinaryFile(fifoBin); err == nil {
			t.Error("expected verifyAgentBinaryFile to reject FIFO")
		}
		if err := copyBinaryForBackup(fifoBin, dstBackup); err == nil {
			t.Error("expected copyBinaryForBackup to reject FIFO")
		}
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("O_RDONLY open blocked on FIFO without writer")
	}
}
