package pathsec

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"agbox/internal/config"
)

func TestIsSubpath(t *testing.T) {
	cases := []struct {
		cand string
		root string
		want bool
	}{
		{"/home/alice/proj", "/home/alice", true},
		{"/home/alice", "/home/alice", true},
		{"/home/alice/", "/home/alice/", true},
		{"/home/alice2/proj", "/home/alice", false},
		{"/etc/passwd", "/", true},
		{"", "/home/alice", false},
		{"/home/alice", "", false},
	}
	for _, tc := range cases {
		if got := IsSubpath(tc.cand, tc.root); got != tc.want {
			t.Errorf("IsSubpath(%q, %q) = %v, want %v", tc.cand, tc.root, got, tc.want)
		}
	}
}

func TestContainsVCSComponent(t *testing.T) {
	vcs := DefaultVCSNames()
	if name, ok := ContainsVCSComponent("/home/u/proj/.git/config", vcs); !ok || name != ".git" {
		t.Errorf("expected .git match, got (%q, %v)", name, ok)
	}
	if name, ok := ContainsVCSComponent("/home/u/proj/.GIT/hooks", vcs); !ok || strings.ToLower(name) != ".git" {
		t.Errorf("expected case-insensitive .GIT match, got (%q, %v)", name, ok)
	}
	if name, ok := ContainsVCSComponent("/home/u/proj/.jj/repo/store", vcs); !ok || name != ".jj" {
		t.Errorf("expected .jj match, got (%q, %v)", name, ok)
	}
	if name, ok := ContainsVCSComponent("/home/u/proj/.gitignore", vcs); !ok || name != ".gitignore" {
		t.Errorf("expected .gitignore match, got (%q, %v)", name, ok)
	}
	if name, ok := ContainsVCSComponent("/home/u/proj/.github/workflows/ci.yml", vcs); ok {
		t.Errorf("unexpected match on .github: %q", name)
	}
}

func TestValidateShareHappyAndBoundaryConditions(t *testing.T) {
	root := t.TempDir()
	home, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatalf("EvalSymlinks: %v", err)
	}
	dataDir := filepath.Join(home, ".local", "share", "agbox")
	msbHome := filepath.Join(home, ".microsandbox")
	pol := Policy{
		HomeReal:  home,
		Blocklist: DefaultBlocklist(home, dataDir, msbHome),
		VCSNames:  DefaultVCSNames(),
	}

	// 1. Valid project directory and regular file.
	projDir := filepath.Join(home, "my-project")
	if err := os.MkdirAll(projDir, 0o700); err != nil {
		t.Fatal(err)
	}
	fileInProj := filepath.Join(projDir, "main.go")
	if err := os.WriteFile(fileInProj, []byte("package main\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	dt, err := ValidateShare(projDir, pol)
	if err != nil || !dt.IsDir || dt.BaseName != "my-project" {
		t.Fatalf("ValidateShare(projDir) = (%+v, %v)", dt, err)
	}
	ft, err := ValidateShare(fileInProj, pol)
	if err != nil || ft.IsDir || ft.BaseName != "main.go" {
		t.Fatalf("ValidateShare(fileInProj) = (%+v, %v)", ft, err)
	}

	// 2. Reject empty and newline paths.
	if _, err := ValidateShare("", pol); err == nil {
		t.Errorf("expected error for empty path")
	}
	if _, err := ValidateShare(projDir+"\n", pol); err == nil {
		t.Errorf("expected error for path with newline")
	}

	// 3. Reject nonexistent or dangling symlink.
	dangling := filepath.Join(projDir, "dangling")
	_ = os.Symlink("/nonexistent/target", dangling)
	if _, err := ValidateShare(dangling, pol); err == nil {
		t.Errorf("expected error for dangling symlink")
	}

	// 4. Reject colon or comma in path.
	colonDir := filepath.Join(home, "bad:dir")
	_ = os.MkdirAll(colonDir, 0o700)
	if _, err := ValidateShare(colonDir, pol); err == nil || !strings.Contains(err.Error(), "':'") {
		t.Errorf("expected colon error, got %v", err)
	}
	commaDir := filepath.Join(home, "bad,dir")
	_ = os.MkdirAll(commaDir, 0o700)
	if _, err := ValidateShare(commaDir, pol); err == nil {
		t.Errorf("expected comma error, got %v", err)
	}

	// 5. Reject path outside $HOME unless AllowOutsideHome is true.
	outsideDir := t.TempDir()
	outsideReal, _ := filepath.EvalSymlinks(outsideDir)
	if _, err := ValidateShare(outsideReal, pol); err == nil || !strings.Contains(err.Error(), "outside $HOME") {
		t.Errorf("expected outside $HOME error, got %v", err)
	}
	polOutside := pol
	polOutside.AllowOutsideHome = true
	if _, err := ValidateShare(outsideReal, polOutside); err != nil {
		t.Errorf("expected outside path to succeed with AllowOutsideHome=true, got %v", err)
	}
	// Even with AllowOutsideHome=true, /etc must remain blocked.
	if _, err := ValidateShare("/etc", polOutside); err == nil {
		t.Errorf("expected /etc to be blocked even with AllowOutsideHome=true")
	}

	// 6. Reject blocklisted paths (~/.ssh, ~/.gemini) and $HOME itself (contains blocklisted children).
	sshDir := filepath.Join(home, ".ssh")
	_ = os.MkdirAll(sshDir, 0o700)
	if _, err := ValidateShare(sshDir, pol); err == nil {
		t.Errorf("expected ~/.ssh to be blocked")
	}
	geminiDir := filepath.Join(home, ".gemini")
	_ = os.MkdirAll(geminiDir, 0o700)
	if _, err := ValidateShare(geminiDir, pol); err == nil {
		t.Errorf("expected ~/.gemini to be blocked")
	}
	if _, err := ValidateShare(home, pol); err == nil {
		t.Errorf("expected $HOME itself to be blocked because it contains sensitive subpaths")
	}

	// 7. Reject symlinked dotfile targets (e.g. ~/.bashrc -> ~/dotfiles/bashrc).
	dotfilesDir := filepath.Join(home, "dotfiles")
	_ = os.MkdirAll(dotfilesDir, 0o700)
	realBashrc := filepath.Join(dotfilesDir, "bashrc")
	_ = os.WriteFile(realBashrc, []byte("# rc\n"), 0o600)
	_ = os.Symlink(realBashrc, filepath.Join(home, ".bashrc"))
	if _, err := ValidateShare(realBashrc, pol); err == nil {
		t.Errorf("expected symlinked ~/.bashrc target to be blocked")
	}
	if _, err := ValidateShare(dotfilesDir, pol); err == nil {
		t.Errorf("expected parent of symlinked ~/.bashrc target (~/dotfiles) to be blocked")
	}

	// 8. Reject sharing VCS directories, subdirectories inside VCS dirs, case-folded VCS names, and VCS control files.
	gitDir := filepath.Join(projDir, ".git")
	gitHooksDir := filepath.Join(gitDir, "hooks")
	_ = os.MkdirAll(gitHooksDir, 0o700)
	gitCfg := filepath.Join(gitDir, "config")
	_ = os.WriteFile(gitCfg, []byte("[core]\n"), 0o600)
	jjRepoDir := filepath.Join(projDir, ".jj", "repo")
	_ = os.MkdirAll(jjRepoDir, 0o700)
	upperGitDir := filepath.Join(projDir, ".GIT")
	_ = os.MkdirAll(upperGitDir, 0o700)
	gitignoreFile := filepath.Join(projDir, ".gitignore")
	_ = os.WriteFile(gitignoreFile, []byte("*.secret\n"), 0o600)
	gitmodulesFile := filepath.Join(projDir, ".gitmodules")
	_ = os.WriteFile(gitmodulesFile, []byte("[submodule]\n"), 0o600)
	for _, blockedVCSPath := range []string{gitDir, gitHooksDir, gitCfg, jjRepoDir, upperGitDir, gitignoreFile, gitmodulesFile} {
		if _, err := ValidateShare(blockedVCSPath, pol); err == nil {
			t.Errorf("expected sharing VCS path %s to fail", blockedVCSPath)
		}
	}
	// .github directory is allowed (CI workflows, not git repository storage).
	githubDir := filepath.Join(projDir, ".github")
	_ = os.MkdirAll(githubDir, 0o700)
	if _, err := ValidateShare(githubDir, pol); err != nil {
		t.Errorf("expected .github directory to be allowed, got %v", err)
	}
	// ~/.config/jj and ~/.jjconfig.toml must be blocked via DefaultBlocklist.
	jjCfgDir := filepath.Join(home, ".config", "jj")
	_ = os.MkdirAll(jjCfgDir, 0o700)
	if _, err := ValidateShare(jjCfgDir, pol); err == nil {
		t.Errorf("expected ~/.config/jj to be blocked")
	}
	jjToml := filepath.Join(home, ".jjconfig.toml")
	_ = os.WriteFile(jjToml, []byte("[user]\n"), 0o600)
	if _, err := ValidateShare(jjToml, pol); err == nil {
		t.Errorf("expected ~/.jjconfig.toml to be blocked")
	}
	// Control characters in paths must be rejected.
	if _, err := ValidateShare(projDir+"\x07", pol); err == nil {
		t.Errorf("expected control character in path to be rejected")
	}

	// 9. Reject writable single file with nlink > 1, but allow when ReadOnly=true.
	hardlinkPeer := filepath.Join(projDir, "peer.go")
	if err := os.Link(fileInProj, hardlinkPeer); err != nil {
		t.Fatal(err)
	}
	if _, err := ValidateShare(fileInProj, pol); err == nil || !strings.Contains(err.Error(), "multiple hard links") {
		t.Errorf("expected hardlink rejection for writable file, got %v", err)
	}
	polRO := pol
	polRO.ReadOnly = true
	if _, err := ValidateShare(fileInProj, polRO); err != nil {
		t.Errorf("expected hardlinked file to be allowed with ReadOnly=true, got %v", err)
	}
	_ = os.Remove(hardlinkPeer)

	// 10. Reject non-regular file (FIFO).
	fifoPath := filepath.Join(projDir, "my.fifo")
	if err := syscall.Mkfifo(fifoPath, 0o600); err == nil {
		if _, err := ValidateShare(fifoPath, pol); err == nil || !strings.Contains(err.Error(), "non-regular") {
			t.Errorf("expected error for FIFO, got %v", err)
		}
	}
}

func TestAssignGuestNamesAndFormatVolumeSpec(t *testing.T) {
	in := []ShareTarget{
		{HostPath: "/home/u/a/app", BaseName: "app", IsDir: true},
		{HostPath: "/home/u/b/app", BaseName: "app", IsDir: true},
		{HostPath: "/home/u/c/app", BaseName: "app", IsDir: true},
		{HostPath: "/home/u/readme.md", BaseName: "readme.md", IsDir: false},
	}
	got := AssignGuestNames(in)
	wantNames := []string{"app", "app-2", "app-3", "readme.md"}
	for i, w := range wantNames {
		if got[i].GuestName != w {
			t.Errorf("index %d: GuestName = %q, want %q", i, got[i].GuestName, w)
		}
	}

	rwSpec := FormatVolumeSpec("/home/u/a/app", "app", false, 1000, 1000)
	if rwSpec != "/home/u/a/app:/workspace/app:rw,uid=1000,gid=1000" {
		t.Errorf("rwSpec = %q", rwSpec)
	}
	roSpec := FormatVolumeSpec("/home/u/a/app", "app-2", true, 1000, 1000)
	if roSpec != "/home/u/a/app:/workspace/app-2:ro,uid=1000,gid=1000" {
		t.Errorf("roSpec = %q", roSpec)
	}
}

func TestDefaultBlocklistForRootAndNonRootHomes(t *testing.T) {
	nonRootList := DefaultBlocklist("/home/alice", "/home/alice/.local/share/agbox", "/home/alice/.microsandbox")
	foundBlanketRoot := false
	for _, entry := range nonRootList {
		if entry == "/root" {
			foundBlanketRoot = true
			break
		}
	}
	if !foundBlanketRoot {
		t.Error("expected /root in blocklist when homeReal is /home/alice")
	}

	rootList := DefaultBlocklist("/root", "/root/.local/share/agbox", "/root/.microsandbox")
	for _, entry := range rootList {
		if entry == "/root" {
			t.Fatal("did not expect blanket /root entry when homeReal is /root")
		}
		if IsSubpath("/root/myapp", entry) {
			t.Errorf("expected /root/myapp not to match blocklist entry %q when homeReal is /root", entry)
		}
	}

	// Sensitive subpaths and /root itself (parent of /root/.ssh) remain blocked.
	foundRootSSH := false
	foundParentOfBlocked := false
	for _, entry := range rootList {
		if entry == "/root/.ssh" {
			foundRootSSH = true
		}
		if IsSubpath(entry, "/root") && entry != "/root" {
			foundParentOfBlocked = true
		}
	}
	if !foundRootSSH || !foundParentOfBlocked {
		t.Errorf("expected /root/.ssh and child entries under /root in blocklist: ssh=%v parent=%v", foundRootSSH, foundParentOfBlocked)
	}
}

func TestAllDefaultVCSNamesAndBlocklistCategories(t *testing.T) {
	root := t.TempDir()
	home, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}
	dataDir := filepath.Join(home, ".local", "share", "agbox")
	msbHome := filepath.Join(home, ".microsandbox")
	pol := Policy{
		HomeReal:  home,
		Blocklist: DefaultBlocklist(home, dataDir, msbHome),
		VCSNames:  DefaultVCSNames(),
	}

	projDir := filepath.Join(home, "workspace-repo")
	if err := os.MkdirAll(projDir, 0o700); err != nil {
		t.Fatal(err)
	}

	// Verify every DefaultVCSNames entry (exact and uppercase) is rejected as a file, directory, and subdirectory.
	for i, vcs := range DefaultVCSNames() {
		caseVariants := []string{vcs, strings.ToUpper(vcs)}
		for j, variant := range caseVariants {
			parent := filepath.Join(projDir, "c"+string(rune('a'+i%20)), "v"+string(rune('0'+j)))
			if err := os.MkdirAll(parent, 0o700); err != nil {
				t.Fatal(err)
			}
			asFile := filepath.Join(parent, variant)
			if err := os.WriteFile(asFile, []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := ValidateShare(asFile, pol); err == nil {
				t.Errorf("expected VCS file %q to be rejected", asFile)
			}
			_ = os.Remove(asFile)

			asDir := filepath.Join(parent, variant)
			subDir := filepath.Join(asDir, "nested")
			if err := os.MkdirAll(subDir, 0o700); err != nil {
				t.Fatal(err)
			}
			if _, err := ValidateShare(asDir, pol); err == nil {
				t.Errorf("expected VCS directory %q to be rejected", asDir)
			}
			if _, err := ValidateShare(subDir, pol); err == nil {
				t.Errorf("expected VCS subdirectory %q to be rejected", subDir)
			}
		}
	}

	// Verify representative paths from every DefaultBlocklist security category are rejected.
	blockedDirs := []string{
		filepath.Join(home, ".ssh"),
		filepath.Join(home, ".gnupg"),
		filepath.Join(home, ".aws"),
		filepath.Join(home, ".kube"),
		filepath.Join(home, ".config", "gcloud"),
		filepath.Join(home, ".config", "gh"),
		filepath.Join(home, ".gemini"),
		filepath.Join(home, ".antigravity"),
		filepath.Join(home, ".claude"),
		filepath.Join(home, ".config", "opencode"),
		filepath.Join(home, ".config", "git"),
		filepath.Join(home, ".config", "jj"),
		filepath.Join(home, ".subversion"),
		filepath.Join(home, ".bazaar"),
		filepath.Join(home, ".config", "direnv"),
		filepath.Join(home, ".local", "bin"),
		filepath.Join(home, "bin"),
		dataDir,
		msbHome,
	}
	for _, bd := range blockedDirs {
		if err := os.MkdirAll(bd, 0o700); err != nil {
			t.Fatal(err)
		}
		if _, err := ValidateShare(bd, pol); err == nil {
			t.Errorf("expected blocklisted dir %q to fail ValidateShare", bd)
		}
	}

	blockedFiles := []string{
		filepath.Join(home, ".git-credentials"),
		filepath.Join(home, ".gitconfig"),
		filepath.Join(home, ".jjconfig.toml"),
		filepath.Join(home, ".hgrc"),
		filepath.Join(home, ".bashrc"),
		filepath.Join(home, ".zshrc"),
		filepath.Join(home, ".profile"),
		filepath.Join(home, ".envrc"),
		filepath.Join(home, ".npmrc"),
		filepath.Join(home, ".netrc"),
	}
	for _, bf := range blockedFiles {
		if err := os.MkdirAll(filepath.Dir(bf), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(bf, []byte("secret"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := ValidateShare(bf, pol); err == nil {
			t.Errorf("expected blocklisted file %q to fail ValidateShare", bf)
		}
	}
}

func TestParseShareSpecAndResolveConflicts(t *testing.T) {
	root := t.TempDir()
	home, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}
	dataDir := filepath.Join(home, ".local", "share", "agbox")
	msbHome := filepath.Join(home, ".microsandbox")
	pol := Policy{
		HomeReal:  home,
		Blocklist: DefaultBlocklist(home, dataDir, msbHome),
		VCSNames:  DefaultVCSNames(),
	}

	dirA := filepath.Join(home, "projA")
	dirB := filepath.Join(home, "projB")
	dirC := filepath.Join(home, "projC")
	nestedInA := filepath.Join(dirA, "subpkg")
	for _, d := range []string{dirA, dirB, dirC, nestedInA} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	fileNote := filepath.Join(home, "notes.txt")
	if err := os.WriteFile(fileNote, []byte("hi\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	// 1. Valid modifier parsing (including trailing slash before :ro).
	s1, err := ParseShareSpec(dirA)
	if err != nil || s1.HasAccessOpt || s1.HasVCSOpt || s1.RawPath != dirA {
		t.Fatalf("ParseShareSpec(dirA) = %+v, %v", s1, err)
	}
	s2, err := ParseShareSpec(dirB + "/:ro,mask,as=docs")
	if err != nil || !s2.HasAccessOpt || !s2.ReadOnly || !s2.HasVCSOpt || s2.VCSPolicy != config.VCSMask || s2.GuestAlias != "docs" {
		t.Fatalf("ParseShareSpec(dirB:ro,mask,as=docs) = %+v, %v", s2, err)
	}
	s3, err := ParseShareSpec(dirC + ":rw,vcs-hooks")
	if err != nil || s3.ReadOnly || s3.VCSPolicy != config.VCSAllowHooks {
		t.Fatalf("ParseShareSpec(dirC:rw,vcs-hooks) = %+v, %v", s3, err)
	}

	// 2. Conflicting, duplicate, or invalid inline modifiers must fail.
	colonOnDisk := filepath.Join(home, "literal:ro")
	if err := os.MkdirAll(colonOnDisk, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{
		"",
		":ro",
		dirA + ":",
		dirA + ":ro,",
		dirA + ":ro,rw",
		dirA + ":ro,ro",
		dirA + ":mask,vcs",
		dirA + ":vcs,vcs-hooks",
		dirA + ":ro,vcs-hooks",
		dirA + ":as=a,as=b",
		dirA + ":as=.git",
		dirA + ":as=../bad",
		dirA + ":unknown",
		colonOnDisk,
	} {
		if _, err := ParseShareSpec(bad); err == nil {
			t.Errorf("ParseShareSpec(%q) succeeded, want error", bad)
		}
	}

	// 3. ResolveShareSpecs with mixed permissions and alias collision avoidance.
	resolved, err := ResolveShareSpecs([]ShareSpec{s1, s2, s3}, ResolveOpts{
		Policy:     pol,
		DefaultRO:  false,
		DefaultVCS: config.VCSMask,
	})
	if err != nil || len(resolved) != 3 {
		t.Fatalf("ResolveShareSpecs = %+v, %v", resolved, err)
	}
	if resolved[0].ReadOnly || resolved[0].VCSPolicy != config.VCSMask {
		t.Errorf("resolved[0] = %+v, want rw + mask", resolved[0])
	}
	if !resolved[1].ReadOnly || resolved[1].GuestName != "docs" {
		t.Errorf("resolved[1] = %+v, want ro + GuestName=docs", resolved[1])
	}
	if resolved[2].ReadOnly || resolved[2].VCSPolicy != config.VCSAllowHooks {
		t.Errorf("resolved[2] = %+v, want rw + vcs-hooks", resolved[2])
	}

	// 4. Global locked flag conflicts, file VCS modifier conflict, duplicate host path, nested path, and duplicate alias must fail.
	if _, err := ResolveShareSpecs([]ShareSpec{s3}, ResolveOpts{Policy: pol, DefaultRO: true, LockRO: true}); err == nil {
		t.Error("expected LockRO + :rw conflict to fail")
	}
	if _, err := ResolveShareSpecs([]ShareSpec{s3}, ResolveOpts{Policy: pol, DefaultVCS: config.VCSMask, LockVCS: true}); err == nil {
		t.Error("expected LockVCS(mask) + :vcs-hooks conflict to fail")
	}
	fileVCS, _ := ParseShareSpec(fileNote + ":vcs")
	if _, err := ResolveShareSpecs([]ShareSpec{fileVCS}, ResolveOpts{Policy: pol}); err == nil {
		t.Error("expected :vcs on single-file share to fail")
	}
	dupSpec, _ := ParseShareSpec(dirA + ":ro")
	if _, err := ResolveShareSpecs([]ShareSpec{s1, dupSpec}, ResolveOpts{Policy: pol}); err == nil {
		t.Error("expected duplicate host path to fail")
	}
	nestedSpec, _ := ParseShareSpec(nestedInA + ":ro")
	if _, err := ResolveShareSpecs([]ShareSpec{s1, nestedSpec}, ResolveOpts{Policy: pol}); err == nil {
		t.Error("expected nested host paths to fail")
	}
	alias1, _ := ParseShareSpec(dirA + ":as=same")
	alias2, _ := ParseShareSpec(dirB + ":as=same")
	if _, err := ResolveShareSpecs([]ShareSpec{alias1, alias2}, ResolveOpts{Policy: pol}); err == nil {
		t.Error("expected duplicate explicit alias to fail")
	}
}
