package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"agbox/internal/complete"
	"agbox/internal/config"
	"agbox/internal/msb"
	"agbox/internal/persist"
	"agbox/internal/service"
	"agbox/internal/vcsfuse"
)

const completionSocketTimeout = 100 * time.Millisecond

func parseCompletionArgs(args []string) (shell string, allowRoot bool, err error) {
	var pos []string
	for _, a := range args {
		switch a {
		case "-h", "--help":
			return "", false, errHelp
		case "--allow-root":
			allowRoot = true
		default:
			if strings.HasPrefix(a, "-") {
				return "", false, fmt.Errorf("unknown completion option: %s (run 'agbox completion --help')", a)
			}
			pos = append(pos, a)
		}
	}
	if len(pos) != 1 {
		return "", false, errors.New("usage: agbox completion [--allow-root] bash")
	}
	switch pos[0] {
	case "bash":
		return "bash", allowRoot, nil
	default:
		return "", false, fmt.Errorf("unsupported shell %q (supported: bash)", pos[0])
	}
}

func (a *appRuntime) completion(args []string) error {
	shell, allowRoot, err := parseCompletionArgs(args)
	if err != nil {
		return err
	}
	if err := a.verifyUser(allowRoot); err != nil {
		return err
	}
	if shell == "bash" {
		_, err = io.WriteString(a.Stdout, complete.BashScript())
		return err
	}
	return fmt.Errorf("unsupported shell %q (supported: bash)", shell)
}

func (a *appRuntime) runHiddenComplete(args []string) int {
	if len(args) > 0 && args[0] == "--" {
		args = args[1:]
	}
	res := complete.Complete(args, a.completionProviders())
	_, _ = io.WriteString(a.Stdout, complete.FormatResult(res))
	return 0
}

func (a *appRuntime) completionProviders() complete.Providers {
	dataDir := a.Env.DataDir
	return complete.Providers{
		Categories: msb.CategoryNames,
		Profiles: func() []string {
			return listCompletionProfiles(dataDir)
		},
		Skills: func() []string {
			return listCompletionSkills(dataDir)
		},
		Rules: func() []string {
			return listCompletionRules(dataDir)
		},
		Sandboxes: func(filter complete.SandboxFilter) []string {
			return listCompletionSandboxes(dataDir, filter)
		},
		Shares: func(sandbox string) []string {
			return listCompletionShares(dataDir, sandbox, completionSocketTimeout)
		},
		Services: func() []string {
			return listCompletionServices(dataDir)
		},
	}
}

func listCompletionProfiles(dataDir string) []string {
	if dataDir == "" {
		return nil
	}
	profiles, err := persist.ListProfiles(dataDir)
	if err != nil {
		return nil
	}
	names := make([]string, 0, len(profiles))
	for _, p := range profiles {
		if p.Name != "" {
			names = append(names, p.Name)
		}
	}
	slices.Sort(names)
	return names
}

func listCompletionSkills(dataDir string) []string {
	if dataDir == "" {
		return nil
	}
	names, err := persist.InspectSkillsDir(filepath.Join(dataDir, "skills"))
	if err != nil {
		return nil
	}
	return names
}

func listCompletionRules(dataDir string) []string {
	if dataDir == "" {
		return nil
	}
	names, err := persist.InspectRulesDir(filepath.Join(dataDir, "rules"))
	if err != nil {
		return nil
	}
	return names
}

func listCompletionServices(dataDir string) []string {
	if dataDir == "" {
		return nil
	}
	specs, err := service.ListSpecs(dataDir)
	if err != nil {
		return nil
	}
	names := make([]string, 0, len(specs))
	for _, sp := range specs {
		if sp.Name != "" {
			names = append(names, sp.Name)
		}
	}
	slices.Sort(names)
	return names
}

func isRegularNoFollow(path string) bool {
	info, err := os.Lstat(path)
	return err == nil && info.Mode()&os.ModeSymlink == 0 && info.Mode().IsRegular()
}

func isDirNoFollow(path string) bool {
	info, err := os.Lstat(path)
	return err == nil && info.Mode()&os.ModeSymlink == 0 && info.IsDir()
}

func listCompletionSandboxes(dataDir string, filter complete.SandboxFilter) []string {
	if dataDir == "" {
		return nil
	}
	runRoot := filepath.Join(dataDir, "run")
	if !isDirNoFollow(runRoot) {
		return nil
	}
	entries, err := os.ReadDir(runRoot)
	if err != nil {
		return nil
	}
	var out []string
	for _, entry := range entries {
		dirID := entry.Name()
		sandbox, ok := sandboxFromRunDirID(dirID)
		if !ok {
			continue
		}
		runDir := filepath.Join(runRoot, dirID)
		if !isDirNoFollow(runDir) {
			continue
		}
		if _, delErr := os.Lstat(filepath.Join(runDir, "deleting")); delErr == nil {
			continue
		}
		hasRunning := isRegularNoFollow(filepath.Join(runDir, "run.meta"))
		hasSuspended := isRegularNoFollow(filepath.Join(runDir, "suspended"))
		switch filter {
		case complete.SandboxRunning:
			if hasRunning && !hasSuspended {
				out = append(out, sandbox)
			}
		case complete.SandboxSuspended:
			if hasSuspended {
				out = append(out, sandbox)
			}
		default:
			if hasRunning || hasSuspended {
				out = append(out, sandbox)
			}
		}
	}
	slices.Sort(out)
	return out
}

func listCompletionShares(dataDir, sandbox string, timeout time.Duration) []string {
	if dataDir == "" || sandbox == "" {
		return nil
	}
	dirID, err := runDirIDFromSandbox(sandbox)
	if err != nil {
		return nil
	}
	runDir := filepath.Join(dataDir, "run", dirID)
	if !isDirNoFollow(runDir) {
		return nil
	}

	sockPath := filepath.Join(runDir, "ws.sock")
	if live, sockErr := vcsfuse.ListHubSharesWithTimeout(sockPath, timeout); sockErr == nil {
		names := make([]string, 0, len(live))
		for _, sh := range live {
			if sh.GuestName != "" {
				names = append(names, sh.GuestName)
			}
		}
		slices.Sort(names)
		return names
	}

	for _, metaName := range []string{"suspended", "run.meta"} {
		meta, mErr := config.LoadRunMeta(filepath.Join(runDir, metaName))
		if mErr != nil {
			continue
		}
		names := make([]string, 0, len(meta.Shares))
		for _, sh := range meta.Shares {
			if sh.GuestName != "" {
				names = append(names, sh.GuestName)
			}
		}
		slices.Sort(names)
		return names
	}
	return nil
}
