package pathsec

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
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

	// 8. Reject sharing .git directly or a single file inside .git.
	gitDir := filepath.Join(projDir, ".git")
	_ = os.MkdirAll(gitDir, 0o700)
	gitCfg := filepath.Join(gitDir, "config")
	_ = os.WriteFile(gitCfg, []byte("[core]\n"), 0o600)
	if _, err := ValidateShare(gitDir, pol); err == nil {
		t.Errorf("expected sharing .git dir directly to fail")
	}
	if _, err := ValidateShare(gitCfg, pol); err == nil {
		t.Errorf("expected sharing single file under .git to fail")
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
