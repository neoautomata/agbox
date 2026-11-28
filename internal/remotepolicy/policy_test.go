package remotepolicy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestStarterPolicyValidAndEvaluates(t *testing.T) {
	p, warnings, err := Parse(StarterPolicyJSON())
	if err != nil {
		t.Fatalf("StarterPolicyJSON failed Parse: %v", err)
	}
	if len(warnings) == 0 || !strings.Contains(strings.Join(warnings, "\n"), "git") {
		t.Fatalf("expected starter policy warning for broad git prefix rule, got %v", warnings)
	}

	// Deny wins over everything.
	d := Evaluate(p, EvalInput{Executable: "/bin/rm", Args: []string{"-rf", "/"}}, nil)
	if d.Action != ActionDeny {
		t.Fatalf("expected deny for /bin/rm, got %+v", d)
	}

	// Shell interpreter denied.
	d = Evaluate(p, EvalInput{Executable: "/usr/bin/bash", Args: []string{"-c", "id"}}, nil)
	if d.Action != ActionDeny {
		t.Fatalf("expected deny for /usr/bin/bash, got %+v", d)
	}

	// Allow exact uname -a.
	d = Evaluate(p, EvalInput{Executable: "uname", Args: []string{"-a"}}, nil)
	if d.Action != ActionAllow {
		t.Fatalf("expected allow for uname -a, got %+v", d)
	}

	// Stdin blocks allow rule when allow_stdin is false.
	d = Evaluate(p, EvalInput{Executable: "uname", Args: []string{"-a"}, StdinSize: 10}, nil)
	if d.Action != ActionAsk {
		t.Fatalf("expected ask when stdin is non-empty on allow_stdin=false rule, got %+v", d)
	}

	// git status --short allowed, git -c core.sshCommand=... denied/asked (not allowed).
	d = Evaluate(p, EvalInput{Executable: "git", Args: []string{"status", "--short"}}, nil)
	if d.Action != ActionAllow {
		t.Fatalf("expected allow for git status --short, got %+v", d)
	}
	d = Evaluate(p, EvalInput{Executable: "git", Args: []string{"-c", "core.sshCommand=id", "status"}}, nil)
	if d.Action == ActionAllow {
		t.Fatalf("expected git -c bypass NOT to be allowed, got %+v", d)
	}
}

func TestPolicyBypassAndGuardrails(t *testing.T) {
	// Reject default_action=allow.
	if _, _, err := Parse([]byte(`{"version":1,"default_action":"allow"}`)); err == nil {
		t.Fatal("expected error for default_action=allow")
	}

	// Reject allow wildcard executable.
	if _, _, err := Parse([]byte(`{"version":1,"rules":[{"id":"r1","action":"allow","executables":["*"],"args":{"allow_any_args":true}}]}`)); err == nil {
		t.Fatal("expected error for wildcard allow rule")
	}

	// Reject allow rule without args constraint unless allow_any_args=true.
	if _, _, err := Parse([]byte(`{"version":1,"rules":[{"id":"r1","action":"allow","executables":["ls"]}]}`)); err == nil {
		t.Fatal("expected error for unconstrained allow rule")
	}

	// Reject interpreter/wrapper allow rules (python3.12, bwrap, env, nice).
	for _, exe := range []string{"sh", "/bin/bash", "python3.12", "perl5.38", "bwrap", "env", "nice", "runuser", "deno"} {
		if !IsInterpreterOrWrapper(exe) {
			t.Errorf("expected IsInterpreterOrWrapper(%q) == true", exe)
		}
		raw := `{"version":1,"rules":[{"id":"r1","action":"allow","executables":["` + exe + `"],"args":{"exact":["--version"]}}]}`
		if _, _, err := Parse([]byte(raw)); err == nil {
			t.Errorf("expected allow rule for interpreter %q to be rejected by default", exe)
		}
	}

	// Anchored arg_patterns prevent suffix smuggling. CWD boundary blocks /srv/app-evil.
	raw := `{
		"version": 1,
		"default_action": "ask",
		"rules": [
			{
				"id": "deny-prod-deploy",
				"action": "deny",
				"executables": ["deploy"],
				"cwd_allow": ["/srv/prod"]
			},
			{
				"id": "allow-deploy-staging",
				"action": "allow",
				"executables": ["deploy"],
				"cwd_allow": ["/srv/app"],
				"args": {
					"prefix": ["check"],
					"arg_patterns": ["[a-z0-9-]+"],
					"max_args": 3
				}
			}
		]
	}`
	p, _, err := Parse([]byte(raw))
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	// Smuggled arg with flag/semicolon fails anchored arg_pattern.
	d := Evaluate(p, EvalInput{Executable: "deploy", Args: []string{"check", "ok;--evil"}, CWD: "/srv/app"}, nil)
	if d.Action == ActionAllow {
		t.Fatalf("expected unanchored arg smuggling to fail allow, got %+v", d)
	}

	// /srv/app-evil does not match /srv/app boundary.
	d = Evaluate(p, EvalInput{Executable: "deploy", Args: []string{"check", "web"}, CWD: "/srv/app-evil"}, nil)
	if d.Action == ActionAllow {
		t.Fatalf("expected /srv/app-evil NOT to match /srv/app, got %+v", d)
	}

	// Valid /srv/app/sub matches allow AND carries separate deny_cwd_scopes for /srv/prod.
	d = Evaluate(p, EvalInput{Executable: "deploy", Args: []string{"check", "web"}, CWD: "/srv/app/sub"}, nil)
	if d.Action != ActionAllow {
		t.Fatalf("expected allow for /srv/app/sub, got %+v", d)
	}
	if d.AllowCWDScope == nil || len(d.AllowCWDScope.In) != 1 || d.AllowCWDScope.In[0] != "/srv/app" {
		t.Fatalf("unexpected AllowCWDScope: %+v", d.AllowCWDScope)
	}
	if len(d.DenyCWDScopes) != 1 || len(d.DenyCWDScopes[0].In) != 1 || d.DenyCWDScopes[0].In[0] != "/srv/prod" {
		t.Fatalf("expected separate DenyCWDScopes for /srv/prod, got %+v", d.DenyCWDScopes)
	}

	// Empty CWD resolves DefaultCWD for deny rule check.
	d = Evaluate(p, EvalInput{Executable: "deploy", Args: []string{"check", "web"}, CWD: "", DefaultCWD: "/srv/prod/api"}, nil)
	if d.Action != ActionDeny {
		t.Fatalf("expected deny when default_cwd is in /srv/prod, got %+v", d)
	}

	// Relative executable rejected.
	d = Evaluate(p, EvalInput{Executable: "./deploy", Args: []string{"check"}}, nil)
	if d.Action != ActionDeny {
		t.Fatalf("expected deny for relative executable, got %+v", d)
	}

	// Exact-only session grant matches exact argv and rejects extra args.
	grants := []SessionGrant{{
		Executable:        "kubectl",
		Args:              []string{"get", "pods"},
		CWD:               "/srv/app",
		MaxExecTimeoutSec: 60,
		MaxOutputBytes:    65536,
	}}
	d = Evaluate(p, EvalInput{Executable: "kubectl", Args: []string{"get", "pods"}, CWD: "/srv/app", ExecTimeoutSec: 30}, grants)
	if d.Action != ActionAllow || !d.SessionMatched {
		t.Fatalf("expected exact session match, got %+v", d)
	}
	d = Evaluate(p, EvalInput{Executable: "kubectl", Args: []string{"get", "secrets", "-A"}, CWD: "/srv/app"}, grants)
	if d.Action == ActionAllow {
		t.Fatalf("expected non-exact args NOT to match session grant, got %+v", d)
	}
}

func TestReloaderFailClosedAndRecovery(t *testing.T) {
	dir := t.TempDir()
	polPath := filepath.Join(dir, "policy.json")
	if err := os.WriteFile(polPath, StarterPolicyJSON(), 0o600); err != nil {
		t.Fatal(err)
	}

	rel, _, err := newReloaderWith(polPath, false, os.Geteuid(), func(time.Duration) {})
	if err != nil {
		t.Fatalf("newReloaderWith failed: %v", err)
	}
	if _, denyAll, _ := rel.Current(); denyAll {
		t.Fatal("expected valid initial policy")
	}

	// Corrupt policy -> DENY-ALL.
	if err := os.WriteFile(polPath, []byte(`{"version":1, bad json`), 0o600); err != nil {
		t.Fatal(err)
	}
	res := rel.CheckReload()
	if !res.DenyAll || !res.Changed {
		t.Fatalf("expected fail-closed DENY-ALL on syntax error, got %+v", res)
	}

	// Restore valid policy -> recovers cleanly.
	if err := os.WriteFile(polPath, StarterPolicyJSON(), 0o600); err != nil {
		t.Fatal(err)
	}
	res = rel.CheckReload()
	if res.DenyAll || !res.Changed {
		t.Fatalf("expected recovery from DENY-ALL, got %+v", res)
	}

	// Group-writable permissions -> DENY-ALL.
	if err := os.Chmod(polPath, 0o620); err != nil {
		t.Fatal(err)
	}
	res = rel.CheckReload()
	if !res.DenyAll || res.Err == nil || !strings.Contains(res.Err.Error(), "insecure permissions") {
		t.Fatalf("expected DENY-ALL on group-writable policy, got %+v", res)
	}

	// Symlinked policy rejected.
	linkPath := filepath.Join(dir, "link.json")
	if err := os.Symlink(polPath, linkPath); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadCheckedFile(linkPath, false); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("expected symlink rejection, got %v", err)
	}

	// Deleted file switches Reloader to fail-closed DENY-ALL.
	if err := os.Remove(polPath); err != nil {
		t.Fatal(err)
	}
	res = rel.CheckReload()
	if !res.DenyAll || res.Err == nil {
		t.Fatalf("expected DENY-ALL when policy file disappears, got %+v", res)
	}

	// Transient parse error recovers during the 50 ms retry sleep.
	retried := false
	if err := os.WriteFile(polPath, StarterPolicyJSON(), 0o600); err != nil {
		t.Fatal(err)
	}
	relRetry, _, err := newReloaderWith(polPath, false, os.Geteuid(), func(d time.Duration) {
		retried = d == 50*time.Millisecond
		_ = os.WriteFile(polPath, StarterPolicyJSON(), 0o600)
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(polPath, []byte(`{"version":1,`), 0o600); err != nil {
		t.Fatal(err)
	}
	res = relRetry.CheckReload()
	if !retried || res.DenyAll {
		t.Fatalf("expected 50 ms retry to recover transient partial save, retried=%v res=%+v", retried, res)
	}
}

func TestSecurityFixesC1H3H5M11M12M15AndModes(t *testing.T) {
	// C1: bare allow pattern must match only bare executable, never /tmp/uname or /usr/bin/uname.
	starter, _, err := Parse(StarterPolicyJSON())
	if err != nil {
		t.Fatal(err)
	}
	if d := Evaluate(starter, EvalInput{Executable: "/tmp/uname", Args: []string{"-a"}}, nil); d.Action == ActionAllow {
		t.Fatalf("C1: bare allow rule must reject /tmp/uname, got %+v", d)
	}
	if d := Evaluate(starter, EvalInput{Executable: "/usr/bin/uname", Args: []string{"-a"}}, nil); d.Action == ActionAllow {
		t.Fatalf("C1: bare allow rule must reject /usr/bin/uname, got %+v", d)
	}

	// H3: ActionAllow checks effectiveCWD against cwd_deny, fails closed when both CWD and DefaultCWD are empty,
	// and rejects empty req.CWD when cwd_allow is configured.
	h3Pol, _, err := Parse([]byte(`{
		"version": 1,
		"default_action": "deny",
		"rules": [
			{
				"id": "allow-not-secret",
				"action": "allow",
				"executables": ["ls"],
				"cwd_deny": ["/srv/secret"],
				"args": {"allow_any_args": true}
			},
			{
				"id": "allow-app-only",
				"action": "allow",
				"executables": ["stat"],
				"cwd_allow": ["/srv/app"],
				"args": {"allow_any_args": true}
			}
		]
	}`))
	if err != nil {
		t.Fatalf("Parse h3Pol failed: %v", err)
	}
	if d := Evaluate(h3Pol, EvalInput{Executable: "ls", CWD: "", DefaultCWD: "/srv/secret/sub"}, nil); d.Action != ActionDeny {
		t.Fatalf("H3: expected deny when DefaultCWD hits cwd_deny, got %+v", d)
	}
	if d := Evaluate(h3Pol, EvalInput{Executable: "ls", CWD: "", DefaultCWD: ""}, nil); d.Action != ActionDeny {
		t.Fatalf("H3: expected fail-closed deny when effectiveCWD is empty with cwd_deny, got %+v", d)
	}
	if d := Evaluate(h3Pol, EvalInput{Executable: "ls", CWD: "", DefaultCWD: "/srv/public"}, nil); d.Action != ActionAllow {
		t.Fatalf("H3: expected allow when DefaultCWD is outside cwd_deny, got %+v", d)
	}
	if d := Evaluate(h3Pol, EvalInput{Executable: "stat", CWD: "", DefaultCWD: "/srv/app"}, nil); d.Action != ActionDeny {
		t.Fatalf("H3: expected empty req.CWD rejected for allow rule with cwd_allow, got %+v", d)
	}

	// H5: /usr/bin/rm denies /bin/rm, python3 denies python3.12 and python3m, bash denies bash-static.
	h5Pol, _, err := Parse([]byte(`{
		"version": 1,
		"rules": [
			{"id": "deny-rm", "action": "deny", "executables": ["/usr/bin/rm"]},
			{"id": "deny-py", "action": "deny", "executables": ["python3"]},
			{"id": "deny-bash", "action": "deny", "executables": ["bash"]}
		]
	}`))
	if err != nil {
		t.Fatalf("Parse h5Pol failed: %v", err)
	}
	for _, exe := range []string{"/bin/rm", "rm", "python3.12", "/usr/bin/python3m", "python3.13t", "python3.12-dbg", "/bin/bash-static"} {
		if d := Evaluate(h5Pol, EvalInput{Executable: exe}, nil); d.Action != ActionDeny {
			t.Errorf("H5: expected deny for %q, got %+v", exe, d)
		}
	}
	for _, interp := range []string{"python3m", "python3.13t", "python3.12d", "python3.12-dbg", "bash-static", "busybox-static", "nodejs"} {
		if !IsInterpreterOrWrapper(interp) {
			t.Errorf("H5: expected IsInterpreterOrWrapper(%q) == true", interp)
		}
	}
	for _, safe := range []string{"python-config", "bashbug", "uname"} {
		if IsInterpreterOrWrapper(safe) {
			t.Errorf("H5: expected IsInterpreterOrWrapper(%q) == false", safe)
		}
	}

	// M11: sessionGrantMatches permits req.MaxOutputBytes == 0 and clamps Decision.MaxOutputBytes.
	grants := []SessionGrant{{
		Executable:        "kubectl",
		Args:              []string{"get", "pods"},
		CWD:               "/srv/app",
		MaxExecTimeoutSec: 60,
		MaxOutputBytes:    8192,
	}}
	d := Evaluate(DefaultPolicy(), EvalInput{Executable: "kubectl", Args: []string{"get", "pods"}, CWD: "/srv/app"}, grants)
	if d.Action != ActionAllow || !d.SessionMatched || d.MaxOutputBytes != 8192 {
		t.Fatalf("M11: expected session match with clamped MaxOutputBytes=8192, got %+v", d)
	}
	d = Evaluate(DefaultPolicy(), EvalInput{Executable: "kubectl", Args: []string{"get", "pods"}, CWD: "/srv/app", MaxOutputBytes: 16384}, grants)
	if d.Action == ActionAllow {
		t.Fatalf("M11: expected explicit MaxOutputBytes > grant to not match, got %+v", d)
	}

	// M12: readCheckedPolicyFile rejects foreign owner UID for non-root even when allowRoot=true.
	polFile := filepath.Join(t.TempDir(), "pol.json")
	if err := os.WriteFile(polFile, StarterPolicyJSON(), 0o600); err != nil {
		t.Fatal(err)
	}
	fakeEUID := os.Geteuid() + 1
	if fakeEUID == 0 {
		fakeEUID = 1000
	}
	if _, err := readCheckedPolicyFile(polFile, true, fakeEUID); err == nil || !strings.Contains(err.Error(), "owner UID") {
		t.Fatalf("M12: expected owner UID rejection for non-root caller even with allowRoot=true, got %v", err)
	}

	// M15: empty exact: [] cannot combine with prefix, arg_patterns, or allow_any_args.
	for _, badArgs := range []string{
		`{"exact":[],"prefix":["status"]}`,
		`{"exact":[],"arg_patterns":["a"]}`,
		`{"exact":[],"allow_any_args":true}`,
	} {
		raw := `{"version":1,"rules":[{"id":"r1","action":"allow","executables":["ls"],"args":` + badArgs + `}]}`
		if _, _, err := Parse([]byte(raw)); err == nil {
			t.Errorf("M15: expected error for conflicting empty exact with %s", badArgs)
		}
	}

	// L7: relative executable error uses active voice wording.
	if err := ValidateExecutable("./foo"); err == nil || !strings.Contains(err.Error(), "omit relative paths") {
		t.Fatalf("L7: expected 'omit relative paths' error, got %v", err)
	}

	// Duplicate rule IDs rejected.
	if _, _, err := Parse([]byte(`{"version":1,"rules":[{"id":"dup","action":"deny","executables":["rm"]},{"id":"dup","action":"ask","executables":["ls"]}]}`)); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("expected duplicate rule id error, got %v", err)
	}

	// Ask rules beat allow rules, per_run_output_review modes, allow_stdin, and MaxStdinBytes.
	modePol, warnings, err := Parse([]byte(`{
		"version": 1,
		"default_action": "deny",
		"per_run_output_review": "ask_only",
		"limits": {"max_stdin_bytes": 16},
		"rules": [
			{"id": "ask-cat-etc", "action": "ask", "executables": ["cat"], "args": {"arg_patterns": ["/etc/.*"]}},
			{"id": "allow-cat-stdin", "action": "allow", "executables": ["cat"], "allow_stdin": true, "args": {"allow_any_args": true}},
			{"id": "allow-tar", "action": "allow", "executables": ["tar"], "args": {"allow_any_args": true}}
		]
	}`))
	if err != nil {
		t.Fatalf("Parse modePol failed: %v", err)
	}
	if len(warnings) == 0 || !strings.Contains(strings.Join(warnings, "\n"), "tar") {
		t.Fatalf("expected GTFOBins warning for tar allow_any_args, got %v", warnings)
	}
	if d := Evaluate(modePol, EvalInput{Executable: "cat", Args: []string{"/etc/hosts"}}, nil); d.Action != ActionAsk || !d.OutputReview || d.RuleID != "ask-cat-etc" {
		t.Fatalf("expected ask rule to beat allow rule with OutputReview=true, got %+v", d)
	}
	if d := Evaluate(modePol, EvalInput{Executable: "cat", Args: []string{"/tmp/x"}, StdinSize: 8}, nil); d.Action != ActionAllow || d.OutputReview {
		t.Fatalf("expected allow_stdin=true rule to allow 8-byte stdin without output review, got %+v", d)
	}
	if d := Evaluate(modePol, EvalInput{Executable: "cat", Args: []string{"/tmp/x"}, StdinSize: 17}, nil); d.Action != ActionDeny {
		t.Fatalf("expected stdin > max_stdin_bytes to be denied, got %+v", d)
	}
	if d := Evaluate(modePol, EvalInput{Executable: "whoami"}, nil); d.Action != ActionDeny {
		t.Fatalf("expected default_action=deny for unmatched executable, got %+v", d)
	}
}
