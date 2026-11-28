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
		Services: func() []string {
			return []string{"web", "work"}
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

func TestCompleteService(t *testing.T) {
	p := testProviders()

	tests := []struct {
		name      string
		args      []string
		wantCands []string
		wantDir   Directive
	}{
		{
			name:      "service actions",
			args:      []string{"service", ""},
			wantCands: []string{"list", "add", "enable", "disable", "start", "stop", "restart", "logs", "rm", "linger"},
			wantDir:   DirectiveNoFiles,
		},
		{
			name:      "service leading flags",
			args:      []string{"service", "-"},
			wantCands: basicFlags,
			wantDir:   DirectiveNoFiles,
		},
		{
			name:      "service list flags",
			args:      []string{"service", "list", "--"},
			wantCands: []string{"--allow-root", "--help"},
			wantDir:   DirectiveNoFiles,
		},
		{
			name:      "service list no positionals",
			args:      []string{"service", "list", ""},
			wantCands: nil,
			wantDir:   DirectiveNoFiles,
		},
		{
			name:      "service add pre-name flags exclude run flags",
			args:      []string{"service", "add", "--"},
			wantCands: []string{"--force", "--env-file", "--enable", "--now", "--no-linger", "--allow-root", "--help"},
			wantDir:   DirectiveNoFiles,
		},
		{
			name:      "service add pre-name env-file space",
			args:      []string{"service", "add", "--env-file", ""},
			wantCands: nil,
			wantDir:   DirectiveFile,
		},
		{
			name:      "service add pre-name env-file equals",
			args:      []string{"service", "add", "--env-file=sec"},
			wantCands: nil,
			wantDir:   DirectiveFile,
		},
		{
			name:      "service add pre-name free-form name",
			args:      []string{"service", "add", "--force", ""},
			wantCands: nil,
			wantDir:   DirectiveNoFiles,
		},
		{
			name:      "service add post-name flags include run flags",
			args:      []string{"service", "add", "web", "--ser"},
			wantCands: []string{"--serve"},
			wantDir:   DirectiveNoFiles,
		},
		{
			name:      "service add post-name env-file space",
			args:      []string{"service", "add", "web", "--env-file", ""},
			wantCands: nil,
			wantDir:   DirectiveFile,
		},
		{
			name:      "service add post-name env-file equals",
			args:      []string{"service", "add", "web", "--env-file=foo"},
			wantCands: nil,
			wantDir:   DirectiveFile,
		},
		{
			name:      "service add post-name profile value",
			args:      []string{"service", "add", "web", "--profile", "d"},
			wantCands: []string{"dev", "docs"},
			wantDir:   DirectiveNoFiles,
		},
		{
			name:      "service add post-name profile equals",
			args:      []string{"service", "add", "web", "--profile=p"},
			wantCands: []string{"--profile=prod"},
			wantDir:   DirectiveNoFiles,
		},
		{
			name:      "service add post-name net value",
			args:      []string{"service", "add", "web", "--net", "p"},
			wantCands: []string{"public", "private"},
			wantDir:   DirectiveNoFiles,
		},
		{
			name:      "service add post-name cpus value",
			args:      []string{"service", "add", "web", "--cpus", "4"},
			wantCands: []string{"4"},
			wantDir:   DirectiveNoFiles,
		},
		{
			name:      "service add post-name memory value",
			args:      []string{"service", "add", "web", "--memory", "1"},
			wantCands: []string{"16G"},
			wantDir:   DirectiveNoFiles,
		},
		{
			name:      "service add post-name share modifiers",
			args:      []string{"service", "add", "web", "--share", "./app:rw,v"},
			wantCands: []string{"./app:rw,vcs", "./app:rw,vcs-hooks"},
			wantDir:   DirectiveNoFiles,
		},
		{
			name:      "service add post-name port value",
			args:      []string{"service", "add", "web", "--port", ""},
			wantCands: nil,
			wantDir:   DirectiveNoFiles,
		},
		{
			name:      "service add post-name cmd value",
			args:      []string{"service", "add", "web", "--cmd", ""},
			wantCands: nil,
			wantDir:   DirectiveNoFiles,
		},
		{
			name:      "service add post-name net-rule value",
			args:      []string{"service", "add", "web", "--net-rule", ""},
			wantCands: nil,
			wantDir:   DirectiveNoFiles,
		},
		{
			name:      "service create offers agents and files after name",
			args:      []string{"service", "create", "--env-file", "/etc/a.env", "web", "--serve", "--port", "4096", ""},
			wantCands: []string{"opencode", "antigravity"},
			wantDir:   DirectiveFile,
		},
		{
			name:      "service add after agent offers files only",
			args:      []string{"service", "add", "web", "opencode", ""},
			wantCands: nil,
			wantDir:   DirectiveFile,
		},
		{
			name:      "service add positional share modifiers",
			args:      []string{"service", "add", "web", "opencode", "./repo:ro,"},
			wantCands: []string{"./repo:ro,mask", "./repo:ro,vcs", "./repo:ro,as="},
			wantDir:   DirectiveNoFiles,
		},
		{
			name:      "service add after path disallows flags",
			args:      []string{"service", "add", "web", "./repo", "--s"},
			wantCands: nil,
			wantDir:   DirectiveFile,
		},
		{
			name:      "service add after double dash offers files",
			args:      []string{"service", "add", "web", "--", "-"},
			wantCands: nil,
			wantDir:   DirectiveFile,
		},
		{
			name:      "service enable flags",
			args:      []string{"service", "enable", "--n"},
			wantCands: []string{"--now", "--no-linger"},
			wantDir:   DirectiveNoFiles,
		},
		{
			name:      "service enable names",
			args:      []string{"service", "enable", "w"},
			wantCands: []string{"web", "work"},
			wantDir:   DirectiveNoFiles,
		},
		{
			name:      "service enable extra positional empty",
			args:      []string{"service", "enable", "web", ""},
			wantCands: nil,
			wantDir:   DirectiveNoFiles,
		},
		{
			name:      "service disable flags",
			args:      []string{"service", "disable", "--"},
			wantCands: []string{"--now", "--allow-root", "--help"},
			wantDir:   DirectiveNoFiles,
		},
		{
			name:      "service disable names",
			args:      []string{"service", "disable", "we"},
			wantCands: []string{"web"},
			wantDir:   DirectiveNoFiles,
		},
		{
			name:      "service start flags and names",
			args:      []string{"service", "start", "-"},
			wantCands: basicFlags,
			wantDir:   DirectiveNoFiles,
		},
		{
			name:      "service stop names",
			args:      []string{"service", "stop", "wo"},
			wantCands: []string{"work"},
			wantDir:   DirectiveNoFiles,
		},
		{
			name:      "service restart extra positional",
			args:      []string{"service", "restart", "web", ""},
			wantCands: nil,
			wantDir:   DirectiveNoFiles,
		},
		{
			name:      "service logs flags",
			args:      []string{"service", "logs", "-"},
			wantCands: []string{"-f", "--follow", "-n", "--lines", "--allow-root", "-h", "--help"},
			wantDir:   DirectiveNoFiles,
		},
		{
			name:      "service logs lines value",
			args:      []string{"service", "logs", "-n", ""},
			wantCands: nil,
			wantDir:   DirectiveNoFiles,
		},
		{
			name:      "service logs lines equals",
			args:      []string{"service", "logs", "--lines=50"},
			wantCands: nil,
			wantDir:   DirectiveNoFiles,
		},
		{
			name:      "service logs name after -n",
			args:      []string{"service", "logs", "-n", "20", "w"},
			wantCands: []string{"web", "work"},
			wantDir:   DirectiveNoFiles,
		},
		{
			name:      "service rm flags",
			args:      []string{"service", "rm", "--"},
			wantCands: []string{"--force", "--allow-root", "--help"},
			wantDir:   DirectiveNoFiles,
		},
		{
			name:      "service rm names",
			args:      []string{"service", "rm", "--force", "w"},
			wantCands: []string{"web", "work"},
			wantDir:   DirectiveNoFiles,
		},
		{
			name:      "service linger subcommands",
			args:      []string{"service", "linger", ""},
			wantCands: []string{"status", "enable"},
			wantDir:   DirectiveNoFiles,
		},
		{
			name:      "service linger flags",
			args:      []string{"service", "linger", "-"},
			wantCands: basicFlags,
			wantDir:   DirectiveNoFiles,
		},
		{
			name:      "service linger extra positional",
			args:      []string{"service", "linger", "status", ""},
			wantCands: nil,
			wantDir:   DirectiveNoFiles,
		},
		{
			name:      "service unknown action",
			args:      []string{"service", "unknown", ""},
			wantCands: nil,
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

func TestCompleteModeCoverageAndSymmetricShareConflict(t *testing.T) {
	p := testProviders()

	tests := []struct {
		name      string
		args      []string
		wantCands []string
		wantDir   Directive
	}{
		// Symmetric vcs-hooks/ro conflict in completeShareSpec.
		{
			name:      "share vcs-hooks excludes ro symmetrically",
			args:      []string{"share", "add", "agbox-app", "./proj:vcs-hooks,"},
			wantCands: []string{"./proj:vcs-hooks,rw", "./proj:vcs-hooks,as="},
			wantDir:   DirectiveNoFiles,
		},
		{
			name:      "share as= deduplicates as= modifier",
			args:      []string{"share", "add", "agbox-app", "./proj:as=app,"},
			wantCands: []string{"./proj:as=app,ro", "./proj:as=app,rw", "./proj:as=app,mask", "./proj:as=app,vcs", "./proj:as=app,vcs-hooks"},
			wantDir:   DirectiveNoFiles,
		},
		{
			name:      "share add path without colon uses file directive",
			args:      []string{"share", "add", "agbox-app", "./proj"},
			wantCands: nil,
			wantDir:   DirectiveFile,
		},
		{
			name:      "run --share= without colon returns nofiles",
			args:      []string{"run", "--share=./proj"},
			wantCands: nil,
			wantDir:   DirectiveNoFiles,
		},
		// Top-level edge cases and simple modes.
		{
			name:      "leading unknown flag returns empty",
			args:      []string{"--bogus", "run"},
			wantCands: nil,
			wantDir:   DirectiveNoFiles,
		},
		{
			name:      "setup flags",
			args:      []string{"setup", ""},
			wantCands: basicFlags,
			wantDir:   DirectiveNoFiles,
		},
		{
			name:      "status non-flag returns empty",
			args:      []string{"status", "foo"},
			wantCands: nil,
			wantDir:   DirectiveNoFiles,
		},
		{
			name:      "version returns empty",
			args:      []string{"version", ""},
			wantCands: nil,
			wantDir:   DirectiveNoFiles,
		},
		{
			name:      "help returns empty",
			args:      []string{"help", ""},
			wantCands: nil,
			wantDir:   DirectiveNoFiles,
		},
		{
			name:      "unknown mode returns empty",
			args:      []string{"nonexistent", ""},
			wantCands: nil,
			wantDir:   DirectiveNoFiles,
		},
		{
			name:      "completion extra positional",
			args:      []string{"completion", "bash", ""},
			wantCands: nil,
			wantDir:   DirectiveNoFiles,
		},
		// create-base & edit-base.
		{
			name:      "create-base flags",
			args:      []string{"create-base", "--f"},
			wantCands: []string{"--force"},
			wantDir:   DirectiveNoFiles,
		},
		{
			name:      "create-base extra positional",
			args:      []string{"create-base", "both", ""},
			wantCands: nil,
			wantDir:   DirectiveNoFiles,
		},
		{
			name:      "edit-base --add value",
			args:      []string{"edit-base", "--add", "h"},
			wantCands: []string{"hugo"},
			wantDir:   DirectiveNoFiles,
		},
		{
			name:      "edit-base --cmd value",
			args:      []string{"edit-base", "--cmd", ""},
			wantCands: nil,
			wantDir:   DirectiveNoFiles,
		},
		{
			name:      "edit-base --categories= value",
			args:      []string{"edit-base", "--categories=c"},
			wantCands: []string{"--categories=core", "--categories=chrome", "--categories=caddy"},
			wantDir:   DirectiveNoFiles,
		},
		{
			name:      "edit-base --cmd= value",
			args:      []string{"edit-base", "--cmd=ls"},
			wantCands: nil,
			wantDir:   DirectiveNoFiles,
		},
		{
			name:      "edit-base flags",
			args:      []string{"edit-base", "--no-"},
			wantCands: []string{"--no-snap"},
			wantDir:   DirectiveNoFiles,
		},
		// update.
		{
			name:      "update flags",
			args:      []string{"update", "-"},
			wantCands: basicFlags,
			wantDir:   DirectiveNoFiles,
		},
		{
			name:      "update first positional",
			args:      []string{"update", ""},
			wantCands: []string{"antigravity", "opencode", "both", "status", "clear"},
			wantDir:   DirectiveNoFiles,
		},
		{
			name:      "update extra positional",
			args:      []string{"update", "clear", "all", ""},
			wantCands: nil,
			wantDir:   DirectiveNoFiles,
		},
		// auth.
		{
			name:      "auth flags",
			args:      []string{"auth", "-"},
			wantCands: basicFlags,
			wantDir:   DirectiveNoFiles,
		},
		{
			name:      "auth first positional",
			args:      []string{"auth", ""},
			wantCands: []string{"antigravity", "opencode", "status", "logout"},
			wantDir:   DirectiveNoFiles,
		},
		{
			name:      "auth login target",
			args:      []string{"auth", "login", ""},
			wantCands: []string{"antigravity", "opencode"},
			wantDir:   DirectiveNoFiles,
		},
		{
			name:      "auth extra positional",
			args:      []string{"auth", "logout", "all", ""},
			wantCands: nil,
			wantDir:   DirectiveNoFiles,
		},
		// skills.
		{
			name:      "skills actions",
			args:      []string{"skills", ""},
			wantCands: []string{"list", "add", "rm"},
			wantDir:   DirectiveNoFiles,
		},
		{
			name:      "skills top flags",
			args:      []string{"skills", "-"},
			wantCands: basicFlags,
			wantDir:   DirectiveNoFiles,
		},
		{
			name:      "skills list flags",
			args:      []string{"skills", "list", "-"},
			wantCands: basicFlags,
			wantDir:   DirectiveNoFiles,
		},
		{
			name:      "skills list pos",
			args:      []string{"skills", "list", ""},
			wantCands: nil,
			wantDir:   DirectiveNoFiles,
		},
		{
			name:      "skills add flags",
			args:      []string{"skills", "add", "-"},
			wantCands: []string{"--force", "-f", "--allow-root", "-h", "--help"},
			wantDir:   DirectiveNoFiles,
		},
		{
			name:      "skills add extra pos",
			args:      []string{"skills", "add", "./my-skill", ""},
			wantCands: nil,
			wantDir:   DirectiveNoFiles,
		},
		{
			name:      "skills rm flags",
			args:      []string{"skills", "rm", "-"},
			wantCands: basicFlags,
			wantDir:   DirectiveNoFiles,
		},
		{
			name:      "skills rm extra pos",
			args:      []string{"skills", "rm", "code-review", ""},
			wantCands: nil,
			wantDir:   DirectiveNoFiles,
		},
		{
			name:      "skills unknown action",
			args:      []string{"skills", "unknown", ""},
			wantCands: nil,
			wantDir:   DirectiveNoFiles,
		},
		// rules.
		{
			name:      "rules actions",
			args:      []string{"rules", ""},
			wantCands: []string{"list", "add", "show", "rm"},
			wantDir:   DirectiveNoFiles,
		},
		{
			name:      "rules top flags",
			args:      []string{"rules", "-"},
			wantCands: basicFlags,
			wantDir:   DirectiveNoFiles,
		},
		{
			name:      "rules --name value",
			args:      []string{"rules", "add", "--name", ""},
			wantCands: nil,
			wantDir:   DirectiveNoFiles,
		},
		{
			name:      "rules --name= value",
			args:      []string{"rules", "add", "--name=foo"},
			wantCands: nil,
			wantDir:   DirectiveNoFiles,
		},
		{
			name:      "rules list flags",
			args:      []string{"rules", "list", "-"},
			wantCands: basicFlags,
			wantDir:   DirectiveNoFiles,
		},
		{
			name:      "rules list pos",
			args:      []string{"rules", "list", ""},
			wantCands: nil,
			wantDir:   DirectiveNoFiles,
		},
		{
			name:      "rules add flags",
			args:      []string{"rules", "add", "-"},
			wantCands: []string{"--force", "-f", "--name", "--allow-root", "-h", "--help"},
			wantDir:   DirectiveNoFiles,
		},
		{
			name:      "rules add file",
			args:      []string{"rules", "add", ""},
			wantCands: nil,
			wantDir:   DirectiveFile,
		},
		{
			name:      "rules add extra pos",
			args:      []string{"rules", "add", "style.md", ""},
			wantCands: nil,
			wantDir:   DirectiveNoFiles,
		},
		{
			name:      "rules show flags",
			args:      []string{"rules", "show", "-"},
			wantCands: basicFlags,
			wantDir:   DirectiveNoFiles,
		},
		{
			name:      "rules show extra pos",
			args:      []string{"rules", "show", "team-style", ""},
			wantCands: nil,
			wantDir:   DirectiveNoFiles,
		},
		{
			name:      "rules rm flags",
			args:      []string{"rules", "rm", "-"},
			wantCands: []string{"--all", "--allow-root", "-h", "--help"},
			wantDir:   DirectiveNoFiles,
		},
		{
			name:      "rules rm names",
			args:      []string{"rules", "rm", "AG"},
			wantCands: []string{"AGBOX_ENV_RULES"},
			wantDir:   DirectiveNoFiles,
		},
		{
			name:      "rules rm extra pos",
			args:      []string{"rules", "rm", "team-style", ""},
			wantCands: nil,
			wantDir:   DirectiveNoFiles,
		},
		{
			name:      "rules unknown action",
			args:      []string{"rules", "unknown", ""},
			wantCands: nil,
			wantDir:   DirectiveNoFiles,
		},
		// profile.
		{
			name:      "profile actions",
			args:      []string{"profile", ""},
			wantCands: []string{"list", "create", "rm"},
			wantDir:   DirectiveNoFiles,
		},
		{
			name:      "profile top flags",
			args:      []string{"profile", "-"},
			wantCands: basicFlags,
			wantDir:   DirectiveNoFiles,
		},
		{
			name:      "profile --size= value",
			args:      []string{"profile", "create", "--size=2"},
			wantCands: []string{"--size=20G"},
			wantDir:   DirectiveNoFiles,
		},
		{
			name:      "profile list flags",
			args:      []string{"profile", "list", "-"},
			wantCands: basicFlags,
			wantDir:   DirectiveNoFiles,
		},
		{
			name:      "profile list pos",
			args:      []string{"profile", "list", ""},
			wantCands: nil,
			wantDir:   DirectiveNoFiles,
		},
		{
			name:      "profile create flags",
			args:      []string{"profile", "create", "-"},
			wantCands: []string{"--size", "--allow-root", "-h", "--help"},
			wantDir:   DirectiveNoFiles,
		},
		{
			name:      "profile create pos",
			args:      []string{"profile", "create", ""},
			wantCands: nil,
			wantDir:   DirectiveNoFiles,
		},
		{
			name:      "profile rm flags",
			args:      []string{"profile", "rm", "-"},
			wantCands: []string{"--force", "-f", "--allow-root", "-h", "--help"},
			wantDir:   DirectiveNoFiles,
		},
		{
			name:      "profile rm extra pos",
			args:      []string{"profile", "rm", "dev", ""},
			wantCands: nil,
			wantDir:   DirectiveNoFiles,
		},
		{
			name:      "profile unknown action",
			args:      []string{"profile", "unknown", ""},
			wantCands: nil,
			wantDir:   DirectiveNoFiles,
		},
		// share.
		{
			name:      "share actions",
			args:      []string{"share", ""},
			wantCands: []string{"list", "add", "set", "rm"},
			wantDir:   DirectiveNoFiles,
		},
		{
			name:      "share top flags",
			args:      []string{"share", "-"},
			wantCands: basicFlags,
			wantDir:   DirectiveNoFiles,
		},
		{
			name:      "share --as value",
			args:      []string{"share", "add", "--as", ""},
			wantCands: nil,
			wantDir:   DirectiveNoFiles,
		},
		{
			name:      "share --as= value",
			args:      []string{"share", "add", "--as=alias"},
			wantCands: nil,
			wantDir:   DirectiveNoFiles,
		},
		{
			name:      "share list flags",
			args:      []string{"share", "list", "-"},
			wantCands: basicFlags,
			wantDir:   DirectiveNoFiles,
		},
		{
			name:      "share list sandboxes",
			args:      []string{"share", "list", "agbox-a"},
			wantCands: []string{"agbox-app"},
			wantDir:   DirectiveNoFiles,
		},
		{
			name:      "share list extra pos",
			args:      []string{"share", "list", "agbox-app", ""},
			wantCands: nil,
			wantDir:   DirectiveNoFiles,
		},
		{
			name:      "share add flags",
			args:      []string{"share", "add", "--v"},
			wantCands: []string{"--vcs", "--vcs-hooks"},
			wantDir:   DirectiveNoFiles,
		},
		{
			name:      "share add sandboxes",
			args:      []string{"share", "add", "agbox-a"},
			wantCands: []string{"agbox-app"},
			wantDir:   DirectiveNoFiles,
		},
		{
			name:      "share add extra pos",
			args:      []string{"share", "add", "agbox-app", "./p", ""},
			wantCands: nil,
			wantDir:   DirectiveNoFiles,
		},
		{
			name:      "share set flags",
			args:      []string{"share", "set", "--f"},
			wantCands: []string{"--force"},
			wantDir:   DirectiveNoFiles,
		},
		{
			name:      "share set extra pos",
			args:      []string{"share", "set", "agbox-app", "backend", ""},
			wantCands: nil,
			wantDir:   DirectiveNoFiles,
		},
		{
			name:      "share rm flags",
			args:      []string{"share", "rm", "-"},
			wantCands: []string{"--force", "-f", "--allow-root", "-h", "--help"},
			wantDir:   DirectiveNoFiles,
		},
		{
			name:      "share unknown action flag",
			args:      []string{"share", "unknown", "-"},
			wantCands: nil,
			wantDir:   DirectiveNoFiles,
		},
		{
			name:      "share unknown action pos",
			args:      []string{"share", "unknown", ""},
			wantCands: nil,
			wantDir:   DirectiveNoFiles,
		},
		// run flag values and resume.
		{
			name:      "run flags",
			args:      []string{"run", "--share-"},
			wantCands: []string{"--share-hub"},
			wantDir:   DirectiveNoFiles,
		},
		{
			name:      "run --cpus values",
			args:      []string{"run", "--cpus", ""},
			wantCands: cpuSuggestions,
			wantDir:   DirectiveNoFiles,
		},
		{
			name:      "run --memory values",
			args:      []string{"run", "--memory", "4"},
			wantCands: []string{"4G"},
			wantDir:   DirectiveNoFiles,
		},
		{
			name:      "run --share value",
			args:      []string{"run", "--share", "./dir:rw,m"},
			wantCands: []string{"./dir:rw,mask"},
			wantDir:   DirectiveNoFiles,
		},
		{
			name:      "run --port value",
			args:      []string{"run", "--port", ""},
			wantCands: nil,
			wantDir:   DirectiveNoFiles,
		},
		{
			name:      "resume flags",
			args:      []string{"resume", "--no-"},
			wantCands: []string{"--no-auth", "--no-skills", "--no-rules", "--no-agent-cache"},
			wantDir:   DirectiveNoFiles,
		},
		{
			name:      "resume -s value",
			args:      []string{"resume", "-s", ""},
			wantCands: nil,
			wantDir:   DirectiveNoFiles,
		},
		{
			name:      "resume --session= value",
			args:      []string{"resume", "--session=abc"},
			wantCands: nil,
			wantDir:   DirectiveNoFiles,
		},
		{
			name:      "resume extra pos",
			args:      []string{"resume", "agbox-paused", ""},
			wantCands: nil,
			wantDir:   DirectiveNoFiles,
		},
		{
			name:      "suspend flags",
			args:      []string{"suspend", "-"},
			wantCands: basicFlags,
			wantDir:   DirectiveNoFiles,
		},
		{
			name:      "stop extra pos",
			args:      []string{"stop", "agbox-app", ""},
			wantCands: nil,
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

	// Nil providers and default FormatResult directive behave safely.
	if got := Complete([]string{"share", "set", "agbox-app", ""}, Providers{}); len(got.Candidates) != 0 {
		t.Errorf("expected empty candidates with nil Providers, got %v", got.Candidates)
	}
	if got := Complete([]string{"stop", ""}, Providers{}); len(got.Candidates) != 0 {
		t.Errorf("expected empty sandbox candidates with nil Providers, got %v", got.Candidates)
	}
	if got := Complete([]string{"service", "start", ""}, Providers{}); len(got.Candidates) != 0 {
		t.Errorf("expected empty service candidates with nil Providers, got %v", got.Candidates)
	}
	if out := FormatResult(Result{Candidates: []string{"x"}}); out != "x\n:nofiles\n" {
		t.Errorf("FormatResult default directive = %q, want x\\n:nofiles\\n", out)
	}
}

func TestBashLtrimWordbreakRightmostSeparator(t *testing.T) {
	bashPath, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash not installed")
	}

	// Load BashScript in a subshell and verify _agbox_ltrim_wordbreak_completions trims up to the rightmost of ':' or '='.
	testDriver := BashScript() + `
COMP_WORDBREAKS=" :=	"

COMPREPLY=("./proj:as=app" "./proj:as=api")
_agbox_ltrim_wordbreak_completions "./proj:as=a"
printf 'case1=%s|%s\n' "${COMPREPLY[0]}" "${COMPREPLY[1]}"

COMPREPLY=("--share=./proj:rw,mask" "--share=./proj:rw,vcs")
_agbox_ltrim_wordbreak_completions "--share=./proj:rw"
printf 'case2=%s|%s\n' "${COMPREPLY[0]}" "${COMPREPLY[1]}"

COMPREPLY=("--share=./proj:as=web" "--share=./proj:as=work")
_agbox_ltrim_wordbreak_completions "--share=./proj:as=w"
printf 'case3=%s|%s\n' "${COMPREPLY[0]}" "${COMPREPLY[1]}"

COMPREPLY=("--profile=dev" "--profile=docs")
_agbox_ltrim_wordbreak_completions "--profile=d"
printf 'case4=%s|%s\n' "${COMPREPLY[0]}" "${COMPREPLY[1]}"
`
	cmd := exec.Command(bashPath, "-e")
	cmd.Stdin = strings.NewReader(testDriver)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("bash runtime test failed: %v\n%s", err, string(out))
	}
	got := string(out)
	for _, want := range []string{
		"case1=app|api\n",
		"case2=rw,mask|rw,vcs\n",
		"case3=web|work\n",
		"case4=dev|docs\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("bash wordbreak trim output missing %q:\n%s", want, got)
		}
	}
}
