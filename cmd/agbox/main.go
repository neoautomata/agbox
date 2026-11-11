// Command agbox runs OpenCode or Google Antigravity CLI inside an isolated
// hardware-virtualized microVM with embedded FUSE VCS filtering.
package main

import (
	"os"

	"agbox/internal/cli"
	"agbox/internal/vcsfuse"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == vcsfuse.SubcommandName {
		os.Exit(vcsfuse.RunMain(os.Args[2:]))
	}
	os.Exit(cli.Main(os.Args[1:]))
}
