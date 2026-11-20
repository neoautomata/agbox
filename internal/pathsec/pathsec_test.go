package pathsec

import (
	"errors"
	"net"
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
	vcs := append([]string{""}, DefaultVCSNames()...)
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
		Blocklist: append([]string{""}, DefaultBlocklist(home, dataDir, msbHome)...),
		VCSNames:  nil, // exercise DefaultVCSNames fallback
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

	// 2. Reject empty, root "/", and newline paths.
	if _, err := ValidateShare("", pol); err == nil {
		t.Errorf("expected error for empty path")
	}
	if _, err := ValidateShare("/", Policy{AllowOutsideHome: true}); err == nil {
		t.Errorf("expected error for filesystem root /")
	}
	if _, err := ValidateShare(projDir+"\n", pol); err == nil {
		t.Errorf("expected error for path with newline")
	}

	// 3. Reject nonexistent or intermediate dangling symlink and wrap os.ErrNotExist.
	dangling := filepath.Join(projDir, "dangling")
	_ = os.Symlink("/nonexistent/target", dangling)
	if _, err := ValidateShare(dangling, pol); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("expected errors.Is(err, os.ErrNotExist) for dangling symlink, got %v", err)
	}
	if _, err := ValidateShare(filepath.Join(dangling, "child.txt"), pol); err == nil {
		t.Errorf("expected error for intermediate dangling symlink")
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

	// 6. Reject blocklisted paths (~/.ssh, ~/.gemini) and $HOME itself.
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
	// .github directory is allowed.
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

	// 9. Reject writable single file with nlink > 1, and allow when ReadOnly=true.
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

	// 10. Reject non-regular files (FIFO and Unix domain socket).
	fifoPath := filepath.Join(projDir, "my.fifo")
	if err := syscall.Mkfifo(fifoPath, 0o600); err == nil {
		if _, err := ValidateShare(fifoPath, pol); err == nil || !strings.Contains(err.Error(), "non-regular") {
			t.Errorf("expected error for FIFO, got %v", err)
		}
	}
	sockRoot, sErr := os.MkdirTemp("", "psock-")
	if sErr == nil {
		defer os.RemoveAll(sockRoot)
		sockReal, _ := filepath.EvalSymlinks(sockRoot)
		sockPath := filepath.Join(sockReal, "test.sock")
		if ln, lErr := net.Listen("unix", sockPath); lErr == nil {
			defer ln.Close()
			if _, err := ValidateShare(sockPath, Policy{AllowOutsideHome: true}); err == nil || !strings.Contains(err.Error(), "non-regular") {
				t.Errorf("expected error for Unix domain socket, got %v", err)
			}
		}
	}
}

func TestAssignGuestNamesChecked(t *testing.T) {
	in := []ShareTarget{
		{HostPath: "/home/u/a/app", BaseName: "app", IsDir: true},
		{HostPath: "/home/u/b/app", BaseName: "", IsDir: true},
		{HostPath: "/home/u/c/app", BaseName: "app", IsDir: true},
		{HostPath: "/home/u/readme.md", BaseName: "readme.md", IsDir: false},
	}
	got, err := AssignGuestNamesChecked(in)
	if err != nil {
		t.Fatalf("AssignGuestNamesChecked failed: %v", err)
	}
	wantNames := []string{"app", "app-2", "app-3", "readme.md"}
	for i, w := range wantNames {
		if got[i].GuestName != w {
			t.Errorf("index %d: GuestName = %q, want %q", i, got[i].GuestName, w)
		}
	}

	dupAliases := []ShareTarget{
		{HostPath: "/home/u/a/app", GuestName: "shared", ExplicitAlias: true},
		{HostPath: "/home/u/b/app", GuestName: "shared", ExplicitAlias: true},
	}
	if _, err := AssignGuestNamesChecked(dupAliases); err == nil {
		t.Error("expected error for duplicate explicit aliases")
	}

	// Reject invalid explicit alias.
	if _, err := AssignGuestNamesChecked([]ShareTarget{
		{HostPath: "/home/u/a/app", GuestName: "../bad", ExplicitAlias: true},
	}); err == nil {
		t.Error("expected error for invalid explicit alias")
	}

	// Auto-assigned GuestName with spaces, backslashes, or >128 chars fails early unless ExplicitAlias is set.
	for _, badBase := range []string{
		"dir with space",
		`dir\backslash`,
		strings.Repeat("x", 129),
	} {
		if _, err := AssignGuestNamesChecked([]ShareTarget{
			{HostPath: "/home/u/" + badBase, BaseName: badBase, IsDir: true},
		}); err == nil {
			t.Errorf("expected AssignGuestNamesChecked to reject auto-assigned basename %q", badBase)
		}
	}
	aliased, err := AssignGuestNamesChecked([]ShareTarget{
		{HostPath: "/home/u/dir with space", GuestName: "clean-name", ExplicitAlias: true, IsDir: true},
	})
	if err != nil || aliased[0].GuestName != "clean-name" {
		t.Fatalf("expected explicit alias to override space basename, got (%+v, %v)", aliased, err)
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

	// Verify representative paths from every DefaultBlocklist category (including [L1] additions) are rejected.
	blockedDirs := []string{
		filepath.Join(home, ".ssh"),
		filepath.Join(home, ".gnupg"),
		filepath.Join(home, ".pki"),
		filepath.Join(home, ".aws"),
		filepath.Join(home, ".kube"),
		filepath.Join(home, ".terraform.d"),
		filepath.Join(home, ".config", "gcloud"),
		filepath.Join(home, ".config", "gh"),
		filepath.Join(home, ".config", "rclone"),
		filepath.Join(home, ".gemini"),
		filepath.Join(home, ".antigravity"),
		filepath.Join(home, ".claude"),
		filepath.Join(home, ".config", "opencode"),
		filepath.Join(home, ".config", "git"),
		filepath.Join(home, ".config", "jj"),
		filepath.Join(home, ".subversion"),
		filepath.Join(home, ".bazaar"),
		filepath.Join(home, ".config", "direnv"),
		filepath.Join(home, ".local", "share", "fish"),
		filepath.Join(home, ".config", "emacs"),
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
		filepath.Join(home, ".pam_environment"),
		filepath.Join(home, ".emacs"),
		filepath.Join(home, ".envrc"),
		filepath.Join(home, ".npmrc"),
		filepath.Join(home, ".netrc"),
		filepath.Join(home, ".pgpass"),
		filepath.Join(home, ".my.cnf"),
		filepath.Join(home, ".vault-token"),
		filepath.Join(home, ".gem", "credentials"),
		filepath.Join(home, ".m2", "settings.xml"),
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
	spaceDir := filepath.Join(home, "space dir")
	nestedInA := filepath.Join(dirA, "subpkg")
	for _, d := range []string{dirA, dirB, dirC, spaceDir, nestedInA} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	fileNote := filepath.Join(home, "notes.txt")
	if err := os.WriteFile(fileNote, []byte("hi\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	// 1. Valid modifier parsing (including trailing slash before :ro and mask-vcs alias).
	s1, err := ParseShareSpec(dirA)
	if err != nil || s1.HasAccessOpt || s1.HasVCSOpt || s1.RawPath != dirA {
		t.Fatalf("ParseShareSpec(dirA) = %+v, %v", s1, err)
	}
	s2, err := ParseShareSpec(dirB + "/:ro,mask-vcs,as=docs")
	if err != nil || !s2.HasAccessOpt || !s2.ReadOnly || !s2.HasVCSOpt || s2.VCSPolicy != config.VCSMask || s2.GuestAlias != "docs" {
		t.Fatalf("ParseShareSpec(dirB:ro,mask-vcs,as=docs) = %+v, %v", s2, err)
	}
	s3, err := ParseShareSpec(dirC + ":rw,vcs-hooks")
	if err != nil || s3.ReadOnly || s3.VCSPolicy != config.VCSAllowHooks {
		t.Fatalf("ParseShareSpec(dirC:rw,vcs-hooks) = %+v, %v", s3, err)
	}
	if pureSpec, pErr := parseShareSpecWithStat("proj:vcs", nil); pErr != nil || pureSpec.VCSPolicy != config.VCSAllow {
		t.Fatalf("parseShareSpecWithStat(proj:vcs, nil) = (%+v, %v)", pureSpec, pErr)
	}

	// 2. Conflicting, duplicate, or invalid inline modifiers must fail (both with and without slashes).
	colonOnDisk := filepath.Join(home, "literal:ro")
	if err := os.MkdirAll(colonOnDisk, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{
		"",
		":ro",
		"foo:bar",
		"a,b:ro",
		"a:b:ro",
		dirA + ":",
		dirA + ":ro,",
		dirA + ":ro,rw",
		dirA + ":rw,ro",
		dirA + ":ro,ro",
		dirA + ":mask,vcs",
		dirA + ":vcs,mask",
		dirA + ":vcs,vcs-hooks",
		dirA + ":vcs-hooks,vcs",
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
		DefaultVCS: "",
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

	// 4. Unlocked DefaultRO=true + DefaultVCS=VCSAllowHooks allows per-share :rw override (e.g. share add --vcs-hooks sbx dir:rw).
	specExplicitRW, err := ParseShareSpec(dirC + ":rw")
	if err != nil {
		t.Fatal(err)
	}
	hookTargets, err := ResolveShareSpecs([]ShareSpec{specExplicitRW}, ResolveOpts{
		Policy:     pol,
		DefaultRO:  true,
		LockRO:     false,
		DefaultVCS: config.VCSAllowHooks,
	})
	if err != nil || len(hookTargets) != 1 || hookTargets[0].ReadOnly || hookTargets[0].VCSPolicy != config.VCSAllowHooks {
		t.Fatalf("ResolveShareSpecs(DefaultRO=true, LockRO=false, DefaultVCS=vcs-hooks, :rw) = (%+v, %v)", hookTargets, err)
	}
	// Without :rw, DefaultRO=true + DefaultVCS=VCSAllowHooks still fails per-share check.
	if _, err := ResolveShareSpecs([]ShareSpec{s1}, ResolveOpts{
		Policy:     pol,
		DefaultRO:  true,
		LockRO:     false,
		DefaultVCS: config.VCSAllowHooks,
	}); err == nil || !strings.Contains(err.Error(), "read-only share cannot enable vcs-hooks") {
		t.Errorf("expected per-share ro + vcs-hooks rejection, got %v", err)
	}

	// 5. Global locked flag conflicts, file VCS modifier conflict, duplicate host path, nested path, duplicate alias, and space basename without alias must fail.
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
	spaceSpec, _ := ParseShareSpec(spaceDir)
	if _, err := ResolveShareSpecs([]ShareSpec{spaceSpec}, ResolveOpts{Policy: pol}); err == nil {
		t.Error("expected space basename without as=<alias> to fail in ResolveShareSpecs")
	}
}

func TestValidateGuestAlias(t *testing.T) {
	validCases := []string{
		"my-app",
		"proj_1",
		"docs",
		strings.Repeat("a", 128),
	}
	for _, alias := range validCases {
		if got, err := ValidateGuestAlias(alias); err != nil || got != alias {
			t.Errorf("ValidateGuestAlias(%q) = (%q, %v), want success", alias, got, err)
		}
	}

	invalidCases := []struct {
		name  string
		alias string
	}{
		{"empty", ""},
		{"too long", strings.Repeat("a", 129)},
		{"dot", "."},
		{"dotdot", ".."},
		{"slash", "a/b"},
		{"backslash", "a\\b"},
		{"colon", "a:b"},
		{"comma", "a,b"},
		{"space", "a b"},
		{"tab", "a\tb"},
		{"newline", "a\nb"},
		{"control byte", "a\x01b"},
		{"delete byte", "a\x7fb"},
		{"zero width space", "alias\u200B"},
		{"zero width non joiner", "alias\u200C"},
		{"zero width joiner", "alias\u200D"},
		{"left to right mark", "alias\u200E"},
		{"right to left mark", "alias\u200F"},
		{"left to right embedding", "alias\u202A"},
		{"right to left override", "alias\u202E"},
		{"left to right isolate", "alias\u2066"},
		{"pop directional isolate", "alias\u2069"},
		{"byte order mark", "alias\uFEFF"},
		{"vcs git", ".git"},
		{"vcs jj", ".jj"},
		{"vcs gitignore", ".gitignore"},
		{"vcs hg", ".hg"},
	}
	for _, tc := range invalidCases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ValidateGuestAlias(tc.alias); err == nil {
				t.Errorf("ValidateGuestAlias(%q) succeeded, want error", tc.alias)
			}
		})
	}
}

func TestResolveShareSpecsConflictPermutations(t *testing.T) {
	pol := Policy{HomeReal: "/home/user", AllowOutsideHome: true}

	// LockRO + DefaultRO true with DefaultVCS VCSAllowHooks fails immediately.
	_, err := ResolveShareSpecs(nil, ResolveOpts{
		Policy:     pol,
		DefaultRO:  true,
		LockRO:     true,
		DefaultVCS: config.VCSAllowHooks,
	})
	if err == nil || !strings.Contains(err.Error(), "cannot combine --ro and --vcs-hooks") {
		t.Fatalf("expected LockRO + DefaultRO + VCSAllowHooks conflict error, got %v", err)
	}

	// LockRO true rejects disagreeing access modifier.
	specRW := ShareSpec{RawPath: "/home/user", ReadOnly: false, HasAccessOpt: true}
	_, err = ResolveShareSpecs([]ShareSpec{specRW}, ResolveOpts{
		Policy:    pol,
		DefaultRO: true,
		LockRO:    true,
	})
	if err == nil || !strings.Contains(err.Error(), "flag and modifier disagree") {
		t.Errorf("expected LockRO conflict error, got %v", err)
	}

	// LockVCS true rejects disagreeing VCS modifier.
	specVCS := ShareSpec{RawPath: "/home/user", VCSPolicy: config.VCSAllow, HasVCSOpt: true}
	_, err = ResolveShareSpecs([]ShareSpec{specVCS}, ResolveOpts{
		Policy:     pol,
		DefaultVCS: config.VCSMask,
		LockVCS:    true,
	})
	if err == nil || !strings.Contains(err.Error(), "flag (mask) and modifier (vcs) disagree") {
		t.Errorf("expected LockVCS conflict error, got %v", err)
	}

	// Read-only share cannot enable vcs-hooks.
	specHooks := ShareSpec{RawPath: "/home/user", VCSPolicy: config.VCSAllowHooks, HasVCSOpt: true}
	_, err = ResolveShareSpecs([]ShareSpec{specHooks}, ResolveOpts{
		Policy:    pol,
		DefaultRO: true,
	})
	if err == nil || !strings.Contains(err.Error(), "read-only share cannot enable vcs-hooks") {
		t.Errorf("expected ro + vcs-hooks conflict error, got %v", err)
	}
}

func TestValidateShareEmptyAndRelativeHomeReal(t *testing.T) {
	tmp := t.TempDir()
	for _, badHome := range []string{"", "relative/home"} {
		pol := Policy{
			HomeReal:         badHome,
			AllowOutsideHome: false,
		}
		_, err := ValidateShare(tmp, pol)
		if err == nil || !strings.Contains(err.Error(), "outside $HOME") {
			t.Fatalf("expected outside $HOME error for HomeReal=%q, got %v", badHome, err)
		}
	}
}

func TestUnicodeBidiRejection(t *testing.T) {
	bidiPaths := []string{
		"/home/user/proj\u200B",
		"/home/user/proj\u202A",
		"/home/user/proj\uFEFF",
	}
	for _, p := range bidiPaths {
		if _, err := ParseShareSpec(p); err == nil {
			t.Errorf("expected ParseShareSpec to reject bidi path %q", p)
		}
		if _, err := ValidateShare(p, Policy{AllowOutsideHome: true}); err == nil {
			t.Errorf("expected ValidateShare to reject bidi path %q", p)
		}
	}
}
