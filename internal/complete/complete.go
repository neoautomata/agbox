// Package complete implements shell completion for agbox.
//
// Security properties:
//   - Complete is a pure function with zero filesystem or subprocess side effects.
//   - Providers are injected by the caller and perform only read-only lookups.
//   - Completion output never exposes secrets or host credentials.
package complete

import (
	"slices"
	"strings"
)

// SubcommandName is the hidden CLI subcommand that returns completion candidates.
const SubcommandName = "__complete"

// Directive tells the shell completion wrapper how to post-process candidates.
type Directive string

const (
	DirectiveDefault Directive = "default"
	DirectiveNoSpace Directive = "nospace"
	DirectiveFile    Directive = "file"
	DirectiveDir     Directive = "dir"
	DirectiveNoFiles Directive = "nofiles"
)

// SandboxFilter narrows dynamic sandbox completion candidates by state.
type SandboxFilter int

const (
	SandboxAll SandboxFilter = iota
	SandboxRunning
	SandboxSuspended
)

// Providers supplies dynamic completion values from read-only host state.
type Providers struct {
	Categories func() []string
	Profiles   func() []string
	Skills     func() []string
	Rules      func() []string
	Sandboxes  func(filter SandboxFilter) []string
	Shares     func(sandbox string) []string
}

// Result holds completion candidates and a shell directive.
type Result struct {
	Candidates []string
	Directive  Directive
}

var allModes = []string{
	"setup",
	"version",
	"completion",
	"create-base",
	"edit-base",
	"update",
	"auth",
	"skills",
	"rules",
	"profile",
	"share",
	"run",
	"suspend",
	"resume",
	"stop",
	"remove",
	"status",
	"help",
}

var (
	globalFlags     = []string{"--allow-root", "-h", "--help", "--version"}
	basicFlags      = []string{"--allow-root", "-h", "--help"}
	removeFlags     = []string{"-y", "--yes", "--allow-root", "-h", "--help"}
	createBaseFlags = []string{"--force", "--allow-root", "--add", "--categories", "-h", "--help"}
	editBaseFlags   = []string{"--allow-root", "--add", "--categories", "--list", "--list-categories", "--shell", "--cmd", "--no-snap", "-h", "--help"}
	resumeFlags     = []string{
		"--allow-root", "-d", "--detach", "-c", "--continue",
		"-s", "--session", "--conversation",
		"--no-auth", "--no-skills", "--no-rules", "--no-agent-cache",
		"-h", "--help",
	}
	runFlags = []string{
		"--name", "--persist", "--profile",
		"-c", "--continue", "-s", "--session", "--conversation",
		"--no-auth", "--no-skills", "--no-rules", "--no-agent-cache",
		"--allow-root", "--share", "--share-hub",
		"--ro", "--rw", "--mask-vcs", "--vcs", "--vcs-hooks", "--no-mask",
		"--serve", "--port", "--probe", "--remote-control", "-d", "--detach",
		"--cmd", "--no-net", "--net", "--net-rule", "--cpus", "--memory",
		"-h", "--help",
	}
	netProfiles    = []string{"public", "none", "private", "host", "all"}
	cpuSuggestions = []string{"1", "2", "4", "8"}
	memSuggestions = []string{"2G", "4G", "8G", "16G"}
	sizeOptions    = []string{"5G", "10G", "20G", "50G"}
	shareModifiers = []string{"ro", "rw", "mask", "vcs", "vcs-hooks", "as="}
)

// FormatResult formats completion candidates and the trailing directive line.
func FormatResult(res Result) string {
	dir := res.Directive
	if dir == "" {
		dir = DirectiveNoFiles
	}
	var b strings.Builder
	for _, c := range res.Candidates {
		if c == "" || strings.ContainsAny(c, "\r\n") {
			continue
		}
		b.WriteString(c)
		b.WriteByte('\n')
	}
	b.WriteByte(':')
	b.WriteString(string(dir))
	b.WriteByte('\n')
	return b.String()
}

// Complete computes completion candidates for args, where args[len(args)-1] is the word being completed.
func Complete(args []string, p Providers) Result {
	if len(args) == 0 {
		return Result{Candidates: slices.Clone(allModes), Directive: DirectiveNoFiles}
	}

	// Rejoin words split by bare bash on '=' or ':' when bash-completion is absent.
	args, trimPrefix := normalizeWordBreaks(args)
	res := completeNormalized(args, p)
	if trimPrefix != "" && len(res.Candidates) > 0 {
		trimmed := make([]string, len(res.Candidates))
		for i, c := range res.Candidates {
			trimmed[i] = strings.TrimPrefix(c, trimPrefix)
		}
		res.Candidates = trimmed
	}
	return res
}

func normalizeWordBreaks(args []string) ([]string, string) {
	n := len(args)
	if n >= 2 && (args[n-2] == "=" || args[n-2] == ":") && n >= 3 {
		sep := args[n-2]
		base := args[n-3]
		if sep == "=" && strings.HasPrefix(base, "--") {
			merged := append(slices.Clone(args[:n-3]), base+"="+args[n-1])
			return merged, base + "="
		}
		if sep == ":" && base != "" && !strings.HasPrefix(base, "-") {
			merged := append(slices.Clone(args[:n-3]), base+":"+args[n-1])
			return merged, base + ":"
		}
	}
	return args, ""
}

func completeNormalized(args []string, p Providers) Result {
	cur := args[len(args)-1]
	prev := args[:len(args)-1]

	// Locate the mode token after any leading global flags.
	modeIdx := -1
	for i, tok := range prev {
		if tok == "--allow-root" {
			continue
		}
		if strings.HasPrefix(tok, "-") {
			return Result{Directive: DirectiveNoFiles}
		}
		modeIdx = i
		break
	}

	if modeIdx == -1 {
		if strings.HasPrefix(cur, "-") {
			return filterResult(globalFlags, cur, DirectiveNoFiles)
		}
		return filterResult(allModes, cur, DirectiveNoFiles)
	}

	mode := prev[modeIdx]
	modePrev := prev[modeIdx+1:]

	switch mode {
	case "completion":
		return completeCompletion(modePrev, cur)
	case "setup", "status":
		return completeFlagsOnly(basicFlags, cur)
	case "remove":
		return completeFlagsOnly(removeFlags, cur)
	case "version", "help":
		return Result{Directive: DirectiveNoFiles}
	case "create-base":
		return completeCreateBase(modePrev, cur, p)
	case "edit-base":
		return completeEditBase(modePrev, cur, p)
	case "update":
		return completeUpdate(modePrev, cur)
	case "auth":
		return completeAuth(modePrev, cur)
	case "skills":
		return completeSkills(modePrev, cur, p)
	case "rules":
		return completeRules(modePrev, cur, p)
	case "profile":
		return completeProfile(modePrev, cur, p)
	case "share":
		return completeShare(modePrev, cur, p)
	case "run":
		return completeRun(modePrev, cur, p)
	case "suspend":
		return completeSandboxMode(basicFlags, modePrev, cur, SandboxRunning, p)
	case "stop":
		return completeSandboxMode(basicFlags, modePrev, cur, SandboxAll, p)
	case "resume":
		return completeResume(modePrev, cur, p)
	default:
		return Result{Directive: DirectiveNoFiles}
	}
}

func completeFlagsOnly(flags []string, cur string) Result {
	if strings.HasPrefix(cur, "-") || cur == "" {
		return filterResult(flags, cur, DirectiveNoFiles)
	}
	return Result{Directive: DirectiveNoFiles}
}

func completeCompletion(prev []string, cur string) Result {
	pos := countPositionals(prev, nil)
	if strings.HasPrefix(cur, "-") {
		return filterResult(basicFlags, cur, DirectiveNoFiles)
	}
	if pos == 0 {
		return filterResult([]string{"bash"}, cur, DirectiveNoFiles)
	}
	return Result{Directive: DirectiveNoFiles}
}

func completeCreateBase(prev []string, cur string, p Providers) Result {
	valFlags := map[string]bool{"--add": true, "--categories": true}
	if flag, ok := pendingFlagValue(prev, valFlags); ok && (flag == "--add" || flag == "--categories") {
		return completeCategoryCSV("", cur, p)
	}
	if flag, val, ok := splitEqualsFlag(cur); ok && (flag == "--add" || flag == "--categories") {
		return completeCategoryCSV(flag+"=", val, p)
	}
	if strings.HasPrefix(cur, "-") {
		return filterResult(createBaseFlags, cur, DirectiveNoFiles)
	}
	if countPositionals(prev, valFlags) == 0 {
		return filterResult([]string{"opencode", "antigravity", "both"}, cur, DirectiveNoFiles)
	}
	return Result{Directive: DirectiveNoFiles}
}

func completeEditBase(prev []string, cur string, p Providers) Result {
	valFlags := map[string]bool{"--add": true, "--categories": true, "--cmd": true}
	if flag, ok := pendingFlagValue(prev, valFlags); ok {
		if flag == "--add" || flag == "--categories" {
			return completeCategoryCSV("", cur, p)
		}
		return Result{Directive: DirectiveNoFiles}
	}
	if flag, val, ok := splitEqualsFlag(cur); ok {
		if flag == "--add" || flag == "--categories" {
			return completeCategoryCSV(flag+"=", val, p)
		}
		return Result{Directive: DirectiveNoFiles}
	}
	if strings.HasPrefix(cur, "-") {
		return filterResult(editBaseFlags, cur, DirectiveNoFiles)
	}
	return completeCategoryCSV("", cur, p)
}

func completeUpdate(prev []string, cur string) Result {
	if strings.HasPrefix(cur, "-") {
		return filterResult(basicFlags, cur, DirectiveNoFiles)
	}
	pos := collectPositionals(prev, nil)
	if len(pos) == 0 {
		return filterResult([]string{"antigravity", "opencode", "both", "status", "clear"}, cur, DirectiveNoFiles)
	}
	if len(pos) == 1 && (pos[0] == "clear" || pos[0] == "rm") {
		return filterResult([]string{"antigravity", "opencode", "all"}, cur, DirectiveNoFiles)
	}
	return Result{Directive: DirectiveNoFiles}
}

func completeAuth(prev []string, cur string) Result {
	if strings.HasPrefix(cur, "-") {
		return filterResult(basicFlags, cur, DirectiveNoFiles)
	}
	pos := collectPositionals(prev, nil)
	if len(pos) == 0 {
		return filterResult([]string{"antigravity", "opencode", "status", "logout"}, cur, DirectiveNoFiles)
	}
	if len(pos) == 1 {
		switch pos[0] {
		case "logout":
			return filterResult([]string{"antigravity", "opencode", "all"}, cur, DirectiveNoFiles)
		case "login":
			return filterResult([]string{"antigravity", "opencode"}, cur, DirectiveNoFiles)
		}
	}
	return Result{Directive: DirectiveNoFiles}
}

func completeSkills(prev []string, cur string, p Providers) Result {
	pos := collectPositionals(prev, nil)
	if len(pos) == 0 {
		if strings.HasPrefix(cur, "-") {
			return filterResult(basicFlags, cur, DirectiveNoFiles)
		}
		return filterResult([]string{"list", "add", "rm"}, cur, DirectiveNoFiles)
	}
	switch pos[0] {
	case "list", "ls":
		if strings.HasPrefix(cur, "-") {
			return filterResult(basicFlags, cur, DirectiveNoFiles)
		}
		return Result{Directive: DirectiveNoFiles}
	case "add":
		if strings.HasPrefix(cur, "-") {
			return filterResult([]string{"--force", "-f", "--allow-root", "-h", "--help"}, cur, DirectiveNoFiles)
		}
		if len(pos) == 1 {
			return Result{Directive: DirectiveFile}
		}
		return Result{Directive: DirectiveNoFiles}
	case "rm", "remove":
		if strings.HasPrefix(cur, "-") {
			return filterResult(basicFlags, cur, DirectiveNoFiles)
		}
		if len(pos) == 1 {
			return filterResult(callStringSlice(p.Skills), cur, DirectiveNoFiles)
		}
		return Result{Directive: DirectiveNoFiles}
	default:
		return Result{Directive: DirectiveNoFiles}
	}
}

func completeRules(prev []string, cur string, p Providers) Result {
	valFlags := map[string]bool{"--name": true}
	if flag, ok := pendingFlagValue(prev, valFlags); ok && flag == "--name" {
		return Result{Directive: DirectiveNoFiles}
	}
	if flag, _, ok := splitEqualsFlag(cur); ok && flag == "--name" {
		return Result{Directive: DirectiveNoFiles}
	}
	pos := collectPositionals(prev, valFlags)
	if len(pos) == 0 {
		if strings.HasPrefix(cur, "-") {
			return filterResult(basicFlags, cur, DirectiveNoFiles)
		}
		return filterResult([]string{"list", "add", "show", "rm"}, cur, DirectiveNoFiles)
	}
	switch pos[0] {
	case "list", "ls":
		if strings.HasPrefix(cur, "-") {
			return filterResult(basicFlags, cur, DirectiveNoFiles)
		}
		return Result{Directive: DirectiveNoFiles}
	case "add":
		if strings.HasPrefix(cur, "-") {
			return filterResult([]string{"--force", "-f", "--name", "--allow-root", "-h", "--help"}, cur, DirectiveNoFiles)
		}
		if len(pos) == 1 {
			return Result{Directive: DirectiveFile}
		}
		return Result{Directive: DirectiveNoFiles}
	case "show", "cat":
		if strings.HasPrefix(cur, "-") {
			return filterResult(basicFlags, cur, DirectiveNoFiles)
		}
		if len(pos) == 1 {
			return filterResult(callStringSlice(p.Rules), cur, DirectiveNoFiles)
		}
		return Result{Directive: DirectiveNoFiles}
	case "rm", "remove":
		if strings.HasPrefix(cur, "-") {
			return filterResult([]string{"--all", "--allow-root", "-h", "--help"}, cur, DirectiveNoFiles)
		}
		if slices.Contains(prev, "--all") {
			return Result{Directive: DirectiveNoFiles}
		}
		if len(pos) == 1 {
			return filterResult(callStringSlice(p.Rules), cur, DirectiveNoFiles)
		}
		return Result{Directive: DirectiveNoFiles}
	default:
		return Result{Directive: DirectiveNoFiles}
	}
}

func completeProfile(prev []string, cur string, p Providers) Result {
	valFlags := map[string]bool{"--size": true}
	if flag, ok := pendingFlagValue(prev, valFlags); ok && flag == "--size" {
		return filterResult(sizeOptions, cur, DirectiveNoFiles)
	}
	if flag, val, ok := splitEqualsFlag(cur); ok && flag == "--size" {
		return filterPrefixedResult(flag+"=", sizeOptions, val, DirectiveNoFiles)
	}
	pos := collectPositionals(prev, valFlags)
	if len(pos) == 0 {
		if strings.HasPrefix(cur, "-") {
			return filterResult(basicFlags, cur, DirectiveNoFiles)
		}
		return filterResult([]string{"list", "create", "rm"}, cur, DirectiveNoFiles)
	}
	switch pos[0] {
	case "list", "ls":
		if strings.HasPrefix(cur, "-") {
			return filterResult(basicFlags, cur, DirectiveNoFiles)
		}
		return Result{Directive: DirectiveNoFiles}
	case "create":
		if strings.HasPrefix(cur, "-") {
			return filterResult([]string{"--size", "--allow-root", "-h", "--help"}, cur, DirectiveNoFiles)
		}
		return Result{Directive: DirectiveNoFiles}
	case "rm", "remove":
		if strings.HasPrefix(cur, "-") {
			return filterResult([]string{"--force", "-f", "--allow-root", "-h", "--help"}, cur, DirectiveNoFiles)
		}
		if len(pos) == 1 {
			return filterResult(callStringSlice(p.Profiles), cur, DirectiveNoFiles)
		}
		return Result{Directive: DirectiveNoFiles}
	default:
		return Result{Directive: DirectiveNoFiles}
	}
}

func completeShare(prev []string, cur string, p Providers) Result {
	valFlags := map[string]bool{"--as": true}
	if flag, ok := pendingFlagValue(prev, valFlags); ok && flag == "--as" {
		return Result{Directive: DirectiveNoFiles}
	}
	if flag, _, ok := splitEqualsFlag(cur); ok && flag == "--as" {
		return Result{Directive: DirectiveNoFiles}
	}
	pos, afterDoubleDash := collectPositionalsWithDoubleDash(prev, valFlags)
	if len(pos) == 0 {
		if !afterDoubleDash && strings.HasPrefix(cur, "-") {
			return filterResult(basicFlags, cur, DirectiveNoFiles)
		}
		return filterResult([]string{"list", "add", "set", "rm"}, cur, DirectiveNoFiles)
	}

	action := pos[0]
	if !afterDoubleDash && strings.HasPrefix(cur, "-") {
		switch action {
		case "list", "ls":
			return filterResult(basicFlags, cur, DirectiveNoFiles)
		case "add":
			return filterResult([]string{"--ro", "--rw", "--mask-vcs", "--vcs", "--vcs-hooks", "--as", "--allow-root", "-h", "--help"}, cur, DirectiveNoFiles)
		case "set":
			return filterResult([]string{"--ro", "--rw", "--mask-vcs", "--vcs", "--vcs-hooks", "--force", "-f", "--allow-root", "-h", "--help"}, cur, DirectiveNoFiles)
		case "rm", "remove":
			return filterResult([]string{"--force", "-f", "--allow-root", "-h", "--help"}, cur, DirectiveNoFiles)
		default:
			return Result{Directive: DirectiveNoFiles}
		}
	}

	switch action {
	case "list", "ls":
		if len(pos) == 1 {
			return filterResult(callSandboxes(p.Sandboxes, SandboxAll), cur, DirectiveNoFiles)
		}
		return Result{Directive: DirectiveNoFiles}
	case "add":
		if len(pos) == 1 {
			return filterResult(callSandboxes(p.Sandboxes, SandboxAll), cur, DirectiveNoFiles)
		}
		if len(pos) == 2 {
			return completeShareSpec("", cur)
		}
		return Result{Directive: DirectiveNoFiles}
	case "set", "rm", "remove":
		if len(pos) == 1 {
			return filterResult(callSandboxes(p.Sandboxes, SandboxAll), cur, DirectiveNoFiles)
		}
		if len(pos) == 2 {
			return filterResult(callShares(p.Shares, pos[1]), cur, DirectiveNoFiles)
		}
		return Result{Directive: DirectiveNoFiles}
	default:
		return Result{Directive: DirectiveNoFiles}
	}
}

func completeRun(prev []string, cur string, p Providers) Result {
	valFlags := map[string]bool{
		"--name":         true,
		"--share":        true,
		"--profile":      true,
		"--session":      true,
		"--conversation": true,
		"-s":             true,
		"--port":         true,
		"--cmd":          true,
		"--net":          true,
		"--net-rule":     true,
		"--cpus":         true,
		"--memory":       true,
	}

	// Scan previous tokens to detect --, paths, and agent selection.
	afterDoubleDash := false
	sawAgent := false
	sawPath := false
	pendingFlag := ""
	for i := 0; i < len(prev); i++ {
		tok := prev[i]
		if afterDoubleDash {
			sawPath = true
			continue
		}
		if tok == "--" {
			afterDoubleDash = true
			continue
		}
		if valFlags[tok] {
			if i == len(prev)-1 {
				pendingFlag = tok
				break
			}
			i++
			continue
		}
		if strings.HasPrefix(tok, "-") {
			continue
		}
		if !sawAgent && !sawPath && (tok == "opencode" || tok == "antigravity") {
			sawAgent = true
			continue
		}
		sawPath = true
	}

	if pendingFlag != "" {
		return completeRunFlagValue("", pendingFlag, cur, p)
	}
	if !afterDoubleDash && !sawPath {
		if flag, val, ok := splitEqualsFlag(cur); ok && valFlags[flag] {
			return completeRunFlagValue(flag+"=", flag, val, p)
		}
		if strings.HasPrefix(cur, "-") {
			return filterResult(runFlags, cur, DirectiveNoFiles)
		}
	}

	// Inside a path:opts modifier suffix.
	if strings.Contains(cur, ":") {
		return completeShareSpec("", cur)
	}

	if !afterDoubleDash && !sawAgent && !sawPath {
		agents := filterStrings([]string{"opencode", "antigravity"}, cur)
		return Result{Candidates: agents, Directive: DirectiveFile}
	}
	return Result{Directive: DirectiveFile}
}

func completeRunFlagValue(prefix, flag, cur string, p Providers) Result {
	switch flag {
	case "--profile":
		return filterPrefixedResult(prefix, callStringSlice(p.Profiles), cur, DirectiveNoFiles)
	case "--net":
		return filterPrefixedResult(prefix, netProfiles, cur, DirectiveNoFiles)
	case "--cpus":
		return filterPrefixedResult(prefix, cpuSuggestions, cur, DirectiveNoFiles)
	case "--memory":
		return filterPrefixedResult(prefix, memSuggestions, cur, DirectiveNoFiles)
	case "--share":
		return completeShareSpec(prefix, cur)
	default:
		return Result{Directive: DirectiveNoFiles}
	}
}

func completeSandboxMode(flags []string, prev []string, cur string, filter SandboxFilter, p Providers) Result {
	if strings.HasPrefix(cur, "-") {
		return filterResult(flags, cur, DirectiveNoFiles)
	}
	if countPositionals(prev, nil) == 0 {
		return filterResult(callSandboxes(p.Sandboxes, filter), cur, DirectiveNoFiles)
	}
	return Result{Directive: DirectiveNoFiles}
}

func completeResume(prev []string, cur string, p Providers) Result {
	valFlags := map[string]bool{
		"-s":             true,
		"--session":      true,
		"--conversation": true,
	}
	if _, ok := pendingFlagValue(prev, valFlags); ok {
		return Result{Directive: DirectiveNoFiles}
	}
	if flag, _, ok := splitEqualsFlag(cur); ok && valFlags[flag] {
		return Result{Directive: DirectiveNoFiles}
	}
	if strings.HasPrefix(cur, "-") {
		return filterResult(resumeFlags, cur, DirectiveNoFiles)
	}
	if countPositionals(prev, valFlags) == 0 {
		return filterResult(callSandboxes(p.Sandboxes, SandboxSuspended), cur, DirectiveNoFiles)
	}
	return Result{Directive: DirectiveNoFiles}
}

func completeCategoryCSV(flagPrefix, cur string, p Providers) Result {
	cats := callStringSlice(p.Categories)
	allChoices := make([]string, 0, len(cats)+1)
	allChoices = append(allChoices, cats...)
	allChoices = append(allChoices, "all")

	used := make(map[string]bool)
	csvPrefix := ""
	token := cur
	if idx := strings.LastIndex(cur, ","); idx >= 0 {
		csvPrefix = cur[:idx+1]
		token = cur[idx+1:]
		for _, part := range strings.Split(cur[:idx], ",") {
			if t := strings.ToLower(strings.TrimSpace(part)); t != "" {
				used[t] = true
			}
		}
	}

	var out []string
	for _, c := range allChoices {
		if used[c] {
			continue
		}
		if strings.HasPrefix(c, token) {
			out = append(out, flagPrefix+csvPrefix+c)
		}
	}
	return Result{Candidates: out, Directive: DirectiveNoFiles}
}

func completeShareSpec(flagPrefix, cur string) Result {
	colonIdx := strings.LastIndex(cur, ":")
	if colonIdx < 0 {
		if flagPrefix != "" {
			return Result{Directive: DirectiveNoFiles}
		}
		return Result{Directive: DirectiveFile}
	}

	pathPrefix := cur[:colonIdx+1]
	optsPart := cur[colonIdx+1:]
	optPrefix := ""
	token := optsPart
	used := make(map[string]bool)
	if commaIdx := strings.LastIndex(optsPart, ","); commaIdx >= 0 {
		optPrefix = optsPart[:commaIdx+1]
		token = optsPart[commaIdx+1:]
		for _, raw := range strings.Split(optsPart[:commaIdx], ",") {
			t := strings.ToLower(strings.TrimSpace(raw))
			if strings.HasPrefix(t, "as=") {
				used["as="] = true
				continue
			}
			if t != "" {
				used[t] = true
			}
		}
	}

	hasAccess := used["ro"] || used["rw"]
	hasVCS := used["mask"] || used["vcs"] || used["vcs-hooks"]

	var out []string
	needsNoSpace := false
	for _, mod := range shareModifiers {
		if used[mod] {
			continue
		}
		if (mod == "ro" || mod == "rw") && hasAccess {
			continue
		}
		if (mod == "mask" || mod == "vcs" || mod == "vcs-hooks") && hasVCS {
			continue
		}
		if mod == "vcs-hooks" && used["ro"] {
			continue
		}
		if strings.HasPrefix(mod, token) {
			out = append(out, flagPrefix+pathPrefix+optPrefix+mod)
			if mod == "as=" {
				needsNoSpace = true
			}
		}
	}
	dir := DirectiveNoFiles
	if needsNoSpace && len(out) == 1 {
		dir = DirectiveNoSpace
	}
	return Result{Candidates: out, Directive: dir}
}

func pendingFlagValue(prev []string, valFlags map[string]bool) (string, bool) {
	for i := 0; i < len(prev); i++ {
		tok := prev[i]
		if tok == "--" {
			return "", false
		}
		if valFlags[tok] {
			if i == len(prev)-1 {
				return tok, true
			}
			i++
		}
	}
	return "", false
}

func splitEqualsFlag(cur string) (string, string, bool) {
	if !strings.HasPrefix(cur, "--") {
		return "", "", false
	}
	idx := strings.IndexByte(cur, '=')
	if idx < 0 {
		return "", "", false
	}
	return cur[:idx], cur[idx+1:], true
}

func countPositionals(prev []string, valFlags map[string]bool) int {
	return len(collectPositionals(prev, valFlags))
}

func collectPositionals(prev []string, valFlags map[string]bool) []string {
	pos, _ := collectPositionalsWithDoubleDash(prev, valFlags)
	return pos
}

func collectPositionalsWithDoubleDash(prev []string, valFlags map[string]bool) ([]string, bool) {
	var pos []string
	afterDoubleDash := false
	for i := 0; i < len(prev); i++ {
		tok := prev[i]
		if afterDoubleDash {
			pos = append(pos, tok)
			continue
		}
		if tok == "--" {
			afterDoubleDash = true
			continue
		}
		if valFlags != nil && valFlags[tok] {
			i++
			continue
		}
		if strings.HasPrefix(tok, "-") {
			continue
		}
		pos = append(pos, tok)
	}
	return pos, afterDoubleDash
}

func filterResult(candidates []string, cur string, dir Directive) Result {
	return Result{
		Candidates: filterStrings(candidates, cur),
		Directive:  dir,
	}
}

func filterPrefixedResult(prefix string, candidates []string, cur string, dir Directive) Result {
	matches := filterStrings(candidates, cur)
	if prefix == "" || len(matches) == 0 {
		return Result{Candidates: matches, Directive: dir}
	}
	out := make([]string, len(matches))
	for i, m := range matches {
		out[i] = prefix + m
	}
	return Result{Candidates: out, Directive: dir}
}

func filterStrings(candidates []string, prefix string) []string {
	var out []string
	seen := make(map[string]bool, len(candidates))
	for _, c := range candidates {
		if c == "" || seen[c] {
			continue
		}
		if strings.HasPrefix(c, prefix) {
			seen[c] = true
			out = append(out, c)
		}
	}
	return out
}

func callStringSlice(fn func() []string) []string {
	if fn == nil {
		return nil
	}
	return fn()
}

func callSandboxes(fn func(SandboxFilter) []string, filter SandboxFilter) []string {
	if fn == nil {
		return nil
	}
	return fn(filter)
}

func callShares(fn func(string) []string, sandbox string) []string {
	if fn == nil || sandbox == "" {
		return nil
	}
	return fn(sandbox)
}
