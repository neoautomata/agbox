package complete

import (
	"os/exec"
	"slices"
	"strings"
	"testing"
)

func testProviders() Providers {
	return Providers{
		Categories: func() []string {
			return []string{"core", "go", "rust", "esphome", "embedded-rust", "chrome", "hugo", "caddy"}
		},
		Profiles: func() []string {
			return []string{"dev", "docs", "prod"}
		},
		Skills: func() []string {
			return []string{"code-review", "commit-msg"}
		},
		Rules: func() []string {
			return []string{"AGBOX_ENV_RULES", "team-style"}
		},
		Sandboxes: func(filter SandboxFilter) []string {
			switch filter {
			case SandboxRunning:
				return []string{"agbox-app", "agbox-run-101"}
			case SandboxSuspended:
				return []string{"agbox-paused"}
			default:
				return []string{"agbox-app", "agbox-paused", "agbox-run-101"}
			}
		},
		Shares: func(sandbox string) []string {
			if sandbox == "agbox-app" {
				return []string{"backend", "frontend"}
			}
			return nil
		},
	}
}

func TestCompleteTable(t *testing.T) {
	p := testProviders()

	tests := []struct {
		name      string
		args      []string
		wantCands []string
		wantDir   Directive
	}{
		{
			name:      "empty args lists all modes",
			args:      nil,
			wantCands: allModes,
			wantDir:   DirectiveNoFiles,
		},
		{
			name:      "top-level mode prefix",
			args:      []string{"co"},
			wantCands: []string{"completion"},
			wantDir:   DirectiveNoFiles,
		},
		{
			name:      "top-level global flag",
			args:      []string{"--a"},
			wantCands: []string{"--allow-root"},
			wantDir:   DirectiveNoFiles,
		},
		{
			name:      "leading allow-root then mode prefix",
			args:      []string{"--allow-root", "st"},
			wantCands: []string{"stop", "status"},
			wantDir:   DirectiveNoFiles,
		},
		{
			name:      "completion shell",
			args:      []string{"completion", ""},
			wantCands: []string{"bash"},
			wantDir:   DirectiveNoFiles,
		},
		{
			name:      "completion flag",
			args:      []string{"completion", "--"},
			wantCands: []string{"--allow-root", "--help"},
			wantDir:   DirectiveNoFiles,
		},
		{
			name:      "remove flags",
			args:      []string{"remove", "-"},
			wantCands: []string{"-y", "--yes", "--allow-root", "-h", "--help"},
			wantDir:   DirectiveNoFiles,
		},
		{
			name:      "create-base agent",
			args:      []string{"create-base", "--force", ""},
			wantCands: []string{"opencode", "antigravity", "both"},
			wantDir:   DirectiveNoFiles,
		},
		{
			name:      "create-base comma categories",
			args:      []string{"create-base", "--add", "core,g"},
			wantCands: []string{"core,go"},
			wantDir:   DirectiveNoFiles,
		},
		{
			name:      "create-base equals categories",
			args:      []string{"create-base", "--add=core,r"},
			wantCands: []string{"--add=core,rust"},
			wantDir:   DirectiveNoFiles,
		},
		{
			name:      "create-base deduplicates used categories",
			args:      []string{"create-base", "--add", "go,g"},
			wantCands: nil,
			wantDir:   DirectiveNoFiles,
		},
		{
			name:      "edit-base positional categories",
			args:      []string{"edit-base", "e"},
			wantCands: []string{"esphome", "embedded-rust"},
			wantDir:   DirectiveNoFiles,
		},
		{
			name:      "update clear target",
			args:      []string{"update", "clear", ""},
			wantCands: []string{"antigravity", "opencode", "all"},
			wantDir:   DirectiveNoFiles,
		},
		{
			name:      "auth logout target",
			args:      []string{"auth", "logout", "o"},
			wantCands: []string{"opencode"},
			wantDir:   DirectiveNoFiles,
		},
		{
			name:      "skills add uses file directive",
			args:      []string{"skills", "add", ""},
			wantCands: nil,
			wantDir:   DirectiveFile,
		},
		{
			name:      "skills rm lists installed skills",
			args:      []string{"skills", "rm", "co"},
			wantCands: []string{"code-review", "commit-msg"},
			wantDir:   DirectiveNoFiles,
		},
		{
			name:      "rules show lists installed rules",
			args:      []string{"rules", "show", "t"},
			wantCands: []string{"team-style"},
			wantDir:   DirectiveNoFiles,
		},
		{
			name:      "rules rm with --all suppresses names",
			args:      []string{"rules", "rm", "--all", ""},
			wantCands: nil,
			wantDir:   DirectiveNoFiles,
		},
		{
			name:      "profile create --size values",
			args:      []string{"profile", "create", "--size", "1"},
			wantCands: []string{"10G"},
			wantDir:   DirectiveNoFiles,
		},
		{
			name:      "profile rm lists profiles",
			args:      []string{"profile", "rm", "d"},
			wantCands: []string{"dev", "docs"},
			wantDir:   DirectiveNoFiles,
		},
		{
			name:      "share set lists sandboxes",
			args:      []string{"share", "set", "--ro", "agbox-"},
			wantCands: []string{"agbox-app", "agbox-paused", "agbox-run-101"},
			wantDir:   DirectiveNoFiles,
		},
		{
			name:      "share set lists shares for sandbox",
			args:      []string{"share", "set", "--ro", "agbox-app", ""},
			wantCands: []string{"backend", "frontend"},
			wantDir:   DirectiveNoFiles,
		},
		{
			name:      "share add path modifiers exclude conflicting ro and vcs-hooks",
			args:      []string{"share", "add", "agbox-app", "./proj:ro,"},
			wantCands: []string{"./proj:ro,mask", "./proj:ro,vcs", "./proj:ro,as="},
			wantDir:   DirectiveNoFiles,
		},
		{
			name:      "share add as= modifier uses nospace",
			args:      []string{"share", "add", "agbox-app", "./proj:a"},
			wantCands: []string{"./proj:as="},
			wantDir:   DirectiveNoSpace,
		},
		{
			name:      "run --profile lists profiles",
			args:      []string{"run", "--profile", "p"},
			wantCands: []string{"prod"},
			wantDir:   DirectiveNoFiles,
		},
		{
			name:      "run bare-bash split equals for --profile",
			args:      []string{"run", "--profile", "=", "d"},
			wantCands: []string{"dev", "docs"},
			wantDir:   DirectiveNoFiles,
		},
		{
			name:      "run bare-bash split colon for share opts",
			args:      []string{"run", "./proj", ":", "rw,v"},
			wantCands: []string{"rw,vcs", "rw,vcs-hooks"},
			wantDir:   DirectiveNoFiles,
		},
		{
			name:      "run --net lists profiles",
			args:      []string{"run", "--net", "p"},
			wantCands: []string{"public", "private"},
			wantDir:   DirectiveNoFiles,
		},
		{
			name:      "run first positional offers agents and files",
			args:      []string{"run", "--ro", ""},
			wantCands: []string{"opencode", "antigravity"},
			wantDir:   DirectiveFile,
		},
		{
			name:      "run disallows flags after path",
			args:      []string{"run", "./proj", "--r"},
			wantCands: nil,
			wantDir:   DirectiveFile,
		},
		{
			name:      "run disallows flags after double dash",
			args:      []string{"run", "--", "-"},
			wantCands: nil,
			wantDir:   DirectiveFile,
		},
		{
			name:      "suspend lists running sandboxes",
			args:      []string{"suspend", ""},
			wantCands: []string{"agbox-app", "agbox-run-101"},
			wantDir:   DirectiveNoFiles,
		},
		{
			name:      "resume lists suspended sandboxes",
			args:      []string{"resume", "-c", ""},
			wantCands: []string{"agbox-paused"},
			wantDir:   DirectiveNoFiles,
		},
		{
			name:      "stop lists all sandboxes",
			args:      []string{"stop", ""},
			wantCands: []string{"agbox-app", "agbox-paused", "agbox-run-101"},
			wantDir:   DirectiveNoFiles,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := Complete(tc.args, p)
			if got.Directive != tc.wantDir {
				t.Errorf("Complete(%q).Directive = %q, want %q", tc.args, got.Directive, tc.wantDir)
			}
			if !slices.Equal(got.Candidates, tc.wantCands) {
				t.Errorf("Complete(%q).Candidates = %v, want %v", tc.args, got.Candidates, tc.wantCands)
			}
		})
	}
}

func TestFormatResult(t *testing.T) {
	out := FormatResult(Result{
		Candidates: []string{"alpha", "", "bad\nline", "beta"},
		Directive:  DirectiveNoSpace,
	})
	want := "alpha\nbeta\n:nospace\n"
	if out != want {
		t.Fatalf("FormatResult = %q, want %q", out, want)
	}
}

func TestBashScriptSyntaxAndShellcheck(t *testing.T) {
	script := BashScript()
	if !strings.Contains(script, "complete -F _agbox_completions agbox") {
		t.Fatal("BashScript missing complete registration")
	}

	if bashPath, err := exec.LookPath("bash"); err == nil {
		cmd := exec.Command(bashPath, "-n")
		cmd.Stdin = strings.NewReader(script)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("bash -n failed: %v\n%s", err, string(out))
		}
	}

	if scPath, err := exec.LookPath("shellcheck"); err == nil {
		cmd := exec.Command(scPath, "-s", "bash", "-")
		cmd.Stdin = strings.NewReader(script)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("shellcheck failed: %v\n%s", err, string(out))
		}
	}
}
