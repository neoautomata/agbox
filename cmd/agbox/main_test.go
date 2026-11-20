package main

import (
	"errors"
	"os"
	"os/exec"
	"slices"
	"strings"
	"testing"

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
