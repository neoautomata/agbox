package cli

func usageText() string {
	return `Usage: agbox [--allow-root] <mode> [arguments...]

agbox runs OpenCode or Google Antigravity CLI inside an isolated microVM.

Global options:
  --allow-root
      Allow agbox to run as the root user (or set AGBOX_ALLOW_ROOT=1).

Modes:
  agbox setup [--allow-root]
      Check host prerequisites (msb, /dev/kvm, FUSE, and microVM smoke test).

  agbox version (or agbox --version)
      Print agbox version and exit.

  agbox create-base [--force] [--allow-root] [--add <categories>] <opencode|antigravity|both>
      Create the base microVM and save snapshot agbox:vN.

  agbox edit-base [--allow-root] [--add <categories>] [--list] [--shell] [--cmd "shell"] [--no-snap] [categories...]
      Start the base microVM and install categories or run custom updates.
      Save snapshot agbox:v<N+1> unless you pass --no-snap.

  agbox update [--allow-root] [antigravity|opencode|both|status|clear [antigravity|opencode|all]]
      Update agent binaries inside a disposable zero-share microVM.
      Cache checked ELF binaries in $DATA_DIR/agents without rebuilding the base snapshot.

  agbox auth [--allow-root] [antigravity|opencode|status|logout]
      Sign in inside a disposable microVM and save credentials in $DATA_DIR/auth.

  agbox skills [--allow-root] [list|add [--force] <path>|rm <name>]
      Manage global skills mounted read-only into sandboxes from $DATA_DIR/skills.

  agbox rules [--allow-root] [list|add [--force] [--name NAME] <file.md>|show [<name>]|rm <name|--all>]
      Manage global rules mounted read-only into sandboxes from $DATA_DIR/rules.

  agbox profile [--allow-root] [list|create [--size SIZE] <name>|rm [--force] <name>]
      Manage ext4 disk profiles for conversation history across ephemeral runs.

  agbox share [--allow-root] <list|add|set|rm> <sandbox> [...]
      List, attach, update, or detach /workspace shares on a running or suspended sandbox.
      agbox share add defaults to ro,mask.

  agbox run [options] [opencode|antigravity] [path[:opts]...]
      Restore a microVM and mask VCS files and directories.
      Block local, private, multicast, and cloud metadata IPs by default.
      Delete the microVM on exit unless you pass --persist or suspend it.
      Options (must precede paths):
        --name NAME          Name the sandbox agbox-NAME instead of agbox-run-PID
        --persist            Keep the named microVM on exit and resume it on repeat runs
        --profile NAME       Mount ext4 profile volume agbox-profile-NAME for conversations
        -c, --continue       Continue the most recent conversation in TUI mode
        -s, --session ID     Continue conversation ID in TUI mode (alias: --conversation)
        --no-auth            Skip saved login credentials from $DATA_DIR/auth
        --no-skills          Skip global skills from $DATA_DIR/skills
        --no-rules           Skip global rules from $DATA_DIR/rules
        --no-agent-cache     Skip cached agent binary updates from $DATA_DIR/agents
        --allow-root         Allow agbox to run as the root user
        --share PATH[:OPTS]  Share a host path with modifiers (ro,rw,mask,vcs,vcs-hooks,as=NAME)
        --share-hub          Mount an empty /workspace FUSE hub to add shares live
        --ro / --rw          Set default share access mode (rejects conflicting modifiers)
        --mask-vcs           Mask VCS metadata inside directory shares (default)
        --vcs                Allow VCS metadata inside shares and write-protect hooks
        --vcs-hooks          Allow VCS metadata and writable hooks inside writable shares
        --no-mask            Disable the FUSE VCS filter (exposes .git to guest)
        --serve              Run 'opencode serve' and bind the web UI on 127.0.0.1
        --port N             Use fixed loopback TCP port N for --serve
        --probe              With --serve: wait for the web UI, then exit
        --remote-control     Run 'agy' with Remote Control for https://antigravity.google.com
        -d, --detach         Keep --remote-control or --serve running in the background
        --cmd "shell"        Run one command in the microVM and exit
        --no-net             Disable guest network access
        --net SPEC           Set network profile (public|none|private|host|all) or rule
        --cpus N             Override vCPU count for this run
        --memory SIZE        Override RAM size for this run (for example, 4G)

  agbox suspend [--allow-root] <sandbox>
      Stop a run microVM, keep its root disk, and unmount host FUSE shares.

  agbox resume [--allow-root] [-d|--detach] [-c|--continue] [--session ID] [--no-auth] [--no-skills] [--no-rules] [--no-agent-cache] <sandbox>
      Check shares, mount FUSE filters, start a suspended microVM, and restart its agent.

  agbox stop [--allow-root] <sandbox>
      Delete a running or suspended run microVM and unmount its FUSE shares.

  agbox remove [--allow-root] [-y|--yes]
      Delete all agbox microVMs, snapshots, profile volumes, FUSE mounts, and $DATA_DIR.

  agbox status [--allow-root]
      Show base settings, persistence state, microVMs, snapshots, and disk usage.
`
}

func runUsageText() string {
	return `Usage: agbox run [options] [agent] [path[:opts]...]

  --name NAME          Name the sandbox agbox-NAME instead of agbox-run-PID
  --persist            Keep the named microVM on exit and resume it on repeat runs
  --profile NAME       Mount ext4 profile volume agbox-profile-NAME for conversations
  -c, --continue       Continue the most recent conversation in TUI mode
  -s, --session ID     Continue conversation ID in TUI mode (alias: --conversation)
  --no-auth            Skip saved login credentials from $DATA_DIR/auth
  --no-skills          Skip global skills from $DATA_DIR/skills
  --no-rules           Skip global rules from $DATA_DIR/rules
  --no-agent-cache     Skip cached agent binary updates from $DATA_DIR/agents
  --allow-root         Allow agbox to run as the root user
  --share PATH[:OPTS]  Share a host path with modifiers (ro,rw,mask,vcs,vcs-hooks,as=NAME)
  --share-hub          Mount an empty /workspace FUSE hub to add shares live
  --ro / --rw          Set default share access mode (rejects conflicting modifiers)
  --mask-vcs           Mask VCS metadata inside directory shares (default)
  --vcs                Allow VCS metadata inside shares and write-protect hooks
  --vcs-hooks          Allow VCS metadata and writable hooks inside writable shares
  --no-mask            Disable the FUSE VCS filter (exposes .git to guest)
  --serve              Run 'opencode serve' and bind the web UI on 127.0.0.1
  --port N             Use fixed loopback TCP port N for --serve (default: random)
  --probe              With --serve: wait for the web UI, then exit
  --remote-control     Run 'agy' with Remote Control for https://antigravity.google.com
  -d, --detach         Keep --remote-control or --serve running in the background
  --cmd 'shell'        Run one command in the microVM and exit
  --no-net             Disable guest network access
  --net SPEC           Set network profile (public|none|private|host|all) or rule
  --cpus N / --memory S   Override vCPU count or RAM size for this run
  agent                opencode | antigravity (default: the base agent)
  path[:opts]...       Host directories or files mounted at /workspace/<name>
`
}

func authUsageText() string {
	return `Usage:
  agbox auth [--allow-root] [antigravity|opencode]
      Sign in inside a disposable microVM and save credentials in $DATA_DIR/auth.
  agbox auth [--allow-root] status
      Show saved login status for antigravity and opencode.
  agbox auth [--allow-root] logout [antigravity|opencode|all]
      Delete saved login credentials from $DATA_DIR/auth.
`
}

func skillsUsageText() string {
	return `Usage:
  agbox skills [--allow-root] [list]
      List global skills stored in $DATA_DIR/skills.
  agbox skills [--allow-root] add [--force] <path>
      Check and copy a skill directory (or SKILL.md) into $DATA_DIR/skills/<name>.
  agbox skills [--allow-root] rm <name>
      Delete a global skill from $DATA_DIR/skills/<name>.
`
}

func rulesUsageText() string {
	return `Usage:
  agbox rules [--allow-root] [list]
      List global rules stored in $DATA_DIR/rules.
  agbox rules [--allow-root] add [--force] [--name NAME] <file.md>
      Check and save a Markdown rule file in $DATA_DIR/rules/<name>.md.
  agbox rules [--allow-root] show [<name>]
      Print one or all global rule files from $DATA_DIR/rules.
  agbox rules [--allow-root] rm <name|--all>
      Delete one or all global rules from $DATA_DIR/rules.
`
}

func profileUsageText() string {
	return `Usage:
  agbox profile [--allow-root] [list]
      List conversation profiles and disk volumes.
  agbox profile [--allow-root] create [--size SIZE] <name>
      Create an ext4 disk volume (agbox-profile-<name>) for --profile runs.
  agbox profile [--allow-root] rm [--force] <name>
      Delete profile disk volume agbox-profile-<name> and its metadata.
`
}

func shareUsageText() string {
	return `Usage:
  agbox share [--allow-root] list <sandbox>
      List shared directories and files on a running or suspended sandbox.

  agbox share [--allow-root] add [--ro|--rw] [--mask-vcs|--vcs|--vcs-hooks] [--as NAME] <sandbox> <path[:opts]>
      Attach a host directory or file at /workspace/<name> on a running or suspended sandbox.
      Default: read-only with VCS masked (ro,mask) unless you pass --rw or :rw.

  agbox share [--allow-root] set [--ro|--rw] [--mask-vcs|--vcs|--vcs-hooks] [--force] <sandbox> <guest-name-or-path>
      Update read-only, read-write, or VCS policy on an existing share.
      A change from rw to ro fails on open writable handles unless you pass --force.

  agbox share [--allow-root] rm [--force] <sandbox> <guest-name-or-path>
      Detach a share and revoke open host file descriptors immediately.
      Detaching fails on open writable handles unless you pass --force.
`
}

func updateUsageText() string {
	return `Usage:
  agbox update [--allow-root] [antigravity|opencode|both]
      Update agent binaries inside a disposable zero-share microVM.
      Cache checked ELF binaries in $DATA_DIR/agents for read-only sandbox mounts.
  agbox update [--allow-root] status
      Show cached agent versions and SHA-256 digests in $DATA_DIR/agents.
  agbox update [--allow-root] clear [antigravity|opencode|all]
      Delete cached agent updates and use base snapshot binaries on new runs.
`
}
