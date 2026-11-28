package main

import (
	"errors"
	"os"
	"os/exec"
	"slices"
	"strings"
	"testing"

	"agbox/internal/remotebridge"
	"agbox/internal/vcsfuse"
)

func TestRunRouting(t *testing.T) {
	tests := []struct {
		name          string
		args          []string
		wantFilter    bool
		wantForwarded []string
		wantCode      int
	}{
		{
			name:          "empty_args",
			args:          nil,
			wantFilter:    false,
			wantForwarded: nil,
			wantCode:      0,
		},
		{
			name:          "program_name_only",
			args:          []string{"agbox"},
			wantFilter:    false,
			wantForwarded: []string{},
			wantCode:      0,
		},
		{
			name:          "cli_mode_version",
			args:          []string{"agbox", "version"},
			wantFilter:    false,
			wantForwarded: []string{"version"},
			wantCode:      0,
		},
		{
			name:          "cli_error_exit",
			args:          []string{"agbox", "bad-mode"},
			wantFilter:    false,
			wantForwarded: []string{"bad-mode"},
			wantCode:      1,
		},
		{
			name:          "filter_subcommand_no_flags",
			args:          []string{"agbox", vcsfuse.SubcommandName},
			wantFilter:    true,
			wantForwarded: []string{},
			wantCode:      2,
		},
		{
			name:          "filter_subcommand_with_flags",
			args:          []string{"agbox", vcsfuse.SubcommandName, "--src", "/a", "--mnt", "/b"},
			wantFilter:    true,
			wantForwarded: []string{"--src", "/a", "--mnt", "/b"},
			wantCode:      0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			calledFilter := false
			calledCLI := false
			var gotArgs []string

			rc := run(
				tc.args,
				func(a []string) int {
					calledFilter = true
					gotArgs = a
					return tc.wantCode
				},
				func(a []string) int {
					calledCLI = true
					gotArgs = a
					return tc.wantCode
				},
			)

			if rc != tc.wantCode {
				t.Fatalf("run(%v) = %d, want %d", tc.args, rc, tc.wantCode)
			}
			if calledFilter != tc.wantFilter || calledCLI == tc.wantFilter {
				t.Fatalf("calledFilter=%v calledCLI=%v, wantFilter=%v", calledFilter, calledCLI, tc.wantFilter)
			}
			if !slices.Equal(gotArgs, tc.wantForwarded) {
				t.Fatalf("forwarded args = %v, want %v", gotArgs, tc.wantForwarded)
			}
		})
	}
}

func TestMainSubprocessRouting(t *testing.T) {
	if mode := os.Getenv("AGBOX_TEST_MAIN_SUBPROC"); mode != "" {
		switch mode {
		case "version":
			os.Args = []string{"agbox", "version"}
		case "filter-bad":
			os.Args = []string{"agbox", vcsfuse.SubcommandName, "--unknown-flag"}
		}
		main()
		return
	}

	t.Run("version_exits_zero", func(t *testing.T) {
		cmd := exec.Command(os.Args[0], "-test.run=^TestMainSubprocessRouting$")
		cmd.Env = append(os.Environ(), "AGBOX_TEST_MAIN_SUBPROC=version")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("main(version) failed: %v, out=%s", err, string(out))
		}
		if !strings.Contains(string(out), "agbox ") {
			t.Fatalf("unexpected version output: %q", string(out))
		}
	})

	t.Run("filter_invalid_flag_exits_nonzero", func(t *testing.T) {
		cmd := exec.Command(os.Args[0], "-test.run=^TestMainSubprocessRouting$")
		cmd.Env = append(os.Environ(), "AGBOX_TEST_MAIN_SUBPROC=filter-bad")
		out, err := cmd.CombinedOutput()
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) || exitErr.ExitCode() == 0 {
			t.Fatalf("expected non-zero exit from __filter --unknown-flag, got err=%v out=%s", err, string(out))
		}
	})
}

func TestRunWithRemoteDispatch(t *testing.T) {
	tests := []struct {
		name          string
		args          []string
		wantTarget    string
		wantForwarded []string
		wantCode      int
	}{
		{
			name:          "empty_args_to_cli",
			args:          nil,
			wantTarget:    "cli",
			wantForwarded: nil,
			wantCode:      0,
		},
		{
			name:          "argv0_basename_agbox_remote",
			args:          []string{"/usr/local/bin/" + remotebridge.GuestClientName, "--cwd", "/srv", "uname", "-a"},
			wantTarget:    "guest",
			wantForwarded: []string{"--cwd", "/srv", "uname", "-a"},
			wantCode:      7,
		},
		{
			name:          "argv0_plain_agbox_remote",
			args:          []string{remotebridge.GuestClientName, "--help"},
			wantTarget:    "guest",
			wantForwarded: []string{"--help"},
			wantCode:      0,
		},
		{
			name:          "guest_subcommand",
			args:          []string{"agbox", remotebridge.GuestSubcommandName, "ls", "-la"},
			wantTarget:    "guest",
			wantForwarded: []string{"ls", "-la"},
			wantCode:      3,
		},
		{
			name:          "filter_bridge_mode",
			args:          []string{"agbox", vcsfuse.SubcommandName, "-bridge", "-mnt", "/tmp/m", "-sock", "/tmp/s"},
			wantTarget:    "bridge",
			wantForwarded: []string{"-bridge", "-mnt", "/tmp/m", "-sock", "/tmp/s"},
			wantCode:      4,
		},
		{
			name:          "filter_vcsfuse_mode",
			args:          []string{"agbox", vcsfuse.SubcommandName, "-hub", "-mnt", "/tmp/m"},
			wantTarget:    "filter",
			wantForwarded: []string{"-hub", "-mnt", "/tmp/m"},
			wantCode:      5,
		},
		{
			name:          "normal_cli_remote_mode",
			args:          []string{"agbox", "remote", "serve", "--help"},
			wantTarget:    "cli",
			wantForwarded: []string{"remote", "serve", "--help"},
			wantCode:      0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var gotTarget string
			var gotArgs []string
			mk := func(name string) func([]string) int {
				return func(a []string) int {
					gotTarget = name
					gotArgs = a
					return tc.wantCode
				}
			}
			rc := runWithRemote(tc.args, mk("filter"), mk("bridge"), mk("guest"), mk("cli"))
			if rc != tc.wantCode {
				t.Fatalf("runWithRemote(%v) = %d, want %d", tc.args, rc, tc.wantCode)
			}
			if gotTarget != tc.wantTarget {
				t.Fatalf("dispatched target = %q, want %q", gotTarget, tc.wantTarget)
			}
			if !slices.Equal(gotArgs, tc.wantForwarded) {
				t.Fatalf("forwarded args = %v, want %v", gotArgs, tc.wantForwarded)
			}
		})
	}
}
