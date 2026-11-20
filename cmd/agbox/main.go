// Command agbox runs OpenCode or Google Antigravity CLI inside an isolated
// microVM with an embedded FUSE filter for VCS files.
package main

import (
	"os"

	"agbox/internal/cli"
	"agbox/internal/vcsfuse"
)

func run(args []string, filterMain, cliMain func([]string) int) int {
	if len(args) == 0 {
		return cliMain(nil)
	}
	if len(args) > 1 && args[1] == vcsfuse.SubcommandName {
		return filterMain(args[2:])
	}
	return cliMain(args[1:])
}

func main() {
	os.Exit(run(os.Args, vcsfuse.RunMain, cli.Main))
}
