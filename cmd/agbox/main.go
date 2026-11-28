// Command agbox runs OpenCode or Google Antigravity CLI inside an isolated
// microVM with an embedded FUSE filter for VCS files.
package main

import (
	"os"
	"path/filepath"

	"agbox/internal/cli"
	"agbox/internal/remotebridge"
	"agbox/internal/remoteclient"
	"agbox/internal/vcsfuse"
)

func run(args []string, filterMain, cliMain func([]string) int) int {
	return runWithRemote(args, filterMain, remotebridge.RunMain, remoteclient.RunMain, cliMain)
}

func runWithRemote(args []string, filterMain, bridgeMain, guestClientMain, cliMain func([]string) int) int {
	if len(args) == 0 {
		return cliMain(nil)
	}
	if filepath.Base(args[0]) == remotebridge.GuestClientName {
		return guestClientMain(args[1:])
	}
	if len(args) > 1 && args[1] == remotebridge.GuestSubcommandName {
		return guestClientMain(args[2:])
	}
	if len(args) > 1 && args[1] == vcsfuse.SubcommandName {
		if len(args) > 2 && args[2] == "-bridge" {
			return bridgeMain(args[2:])
		}
		return filterMain(args[2:])
	}
	return cliMain(args[1:])
}

func main() {
	os.Exit(run(os.Args, vcsfuse.RunMain, cli.Main))
}
