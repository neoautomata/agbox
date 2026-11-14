# agbox User Guide

This guide walks through every `agbox` workflow in the order you run it on a host, from installation and base-snapshot setup through daily runs, share controls, conversation persistence, agent updates, and teardown.

For architecture details, default-deny firewall rules, FUSE confinement guarantees, and security properties, see [README.md](README.md).

## Contents

1. [Install and Verify Host Prerequisites](#1-install-and-verify-host-prerequisites)
1. [Create the Base Snapshot and Choose Categories](#2-create-the-base-snapshot-and-choose-categories)
1. [Authenticate Agents](#3-authenticate-agents)
1. [Add Global Skills and Rules](#4-add-global-skills-and-rules)
1. [Run Agents and Share Project Directories](#5-run-agents-and-share-project-directories)
1. [Persist Conversations and Manage Sandbox Lifecycle](#6-persist-conversations-and-manage-sandbox-lifecycle)
1. [Connect via Web Interface or Remote Control](#7-connect-via-web-interface-or-remote-control)
1. [Update Agents and Customize the Base Image](#8-update-agents-and-customize-the-base-image)
1. [CLI Reference, Environment Variables, and Uninstallation](#9-cli-reference-environment-variables-and-uninstallation)

______________________________________________________________________

## 1. Install and Verify Host Prerequisites

Run the installer script from the repository root as your normal user:

```bash
./install.sh
```

To install as `root`, pass `--allow-root` (or set `AGBOX_ALLOW_ROOT=1`):

```bash
./install.sh --allow-root
```

`install.sh` performs these steps:

1. Rejects `root` unless you pass `--allow-root` or set `AGBOX_ALLOW_ROOT=1`.
1. Checks that `glibc` is version 2.28 or newer.
1. Requires the `go` toolchain and `fusermount3` (or `fusermount`).
1. Installs `msb` over HTTPS (TLS 1.2+) if `msb` is not already on `PATH`.
1. Builds `agbox` in a temporary directory and installs it to `~/.local/bin/agbox` (`/usr/local/bin/agbox` for `root`, or `$AGBOX_INSTALL_DIR`).
1. Runs `agbox setup` to verify `$DATA_DIR`, `/dev/kvm`, FUSE mount support, `msb doctor`, and an offline Alpine smoke microVM.

To re-check host prerequisites or inspect current state at any time:

```bash
agbox setup
agbox status
```

______________________________________________________________________

## 2. Create the Base Snapshot and Choose Categories

Create a base microVM snapshot with `opencode`, `antigravity` (`agy`), or `both`. Pass `--add` to include curated developer toolchains (`all` installs every category):

```bash
agbox create-base --add core,go,rust,esphome both
```

Inside the isolated microVM, `create-base` installs `shellcheck`, `mdformat`, and baseline CLI utilities (`git`, `ripgrep`, `curl`, `less`, `procps`, and `sudo`) in every snapshot and configures default agent settings for unattended sandbox execution:

- **Antigravity (`agy`):** Sets `toolPermission` to `"always-proceed"` (`turbo`), `queuedMessages` to `"send-immediately"`, `allowNonWorkspaceAccess` to `true`, and `trustedWorkspaces` to `["/workspace"]` in `/home/agent/.gemini/antigravity-cli/settings.json`.
- **OpenCode (`opencode`):** Sets `"permission": "allow"` in `/home/agent/.config/opencode/opencode.json`. Queued follow-up messages already steer active turns immediately by default.

When done, `agbox` stops `agbox-base` and saves snapshot `agbox:v1`.

### Base-Image Categories (`create-base` and `edit-base`)

Run `agbox edit-base --list` to print available categories from the CLI, or select from the table below:

| Category | Aliases | Installed Packages and Tools |
|---|---|---|
| `core` | `base`, `cli` | `build-essential`, `pkg-config`, `cmake`, `ninja-build`, `libffi-dev`, `libssl-dev`, `libsqlite3-dev`, `sqlite3`, `ca-certificates`, `curl`, `wget`, `git`, `htop`, `ncdu`, `net-tools`, `iproute2`, `dnsutils`, `rsync`, `unzip`, `zip`, `vim`, `jq`, `ripgrep`, `fd-find`, `shellcheck`, `less`, `procps`, `psmisc`, `lsof`, `strace`, `tree`, `file`, `openssh-client`, `python3`, `python3-pip`, `python3-setuptools`, `python3-venv`, `python3-wheel`, `pipx`, and `mdformat` (via `pipx`). |
| `go` | `golang` | Upstream Go toolchain in `/usr/local/go` (fallback: `golang-go`), `protobuf-compiler`, and `dlv`, `gopls`, `golangci-lint`, `goimports`, `staticcheck`, and `govulncheck` in `/home/agent/go/bin`. |
| `rust` | `cargo`, `rustup` | `rustup` stable toolchain with `clippy`, `rustfmt`, `rust-analyzer`, `rust-src`, plus `clang`, `lld`, `pkg-config`, `libssl-dev`, `libudev-dev`, `libusb-1.0-0-dev`, `protobuf-compiler`, and `sccache`. |
| `esphome` | `esp` | `esphome`, `esptool`, and `platformio` (via `pipx`), plus `libudev-dev`, `libusb-1.0-0-dev`, `udev`, `usbutils`, `cmake`, `ninja-build`, `gperf`, `ccache`, `dfu-util`, `picocom`, and `minicom`. |
| `embedded-rust` | `esp-rust` | `riscv32imc-unknown-none-elf` and `riscv32imac-unknown-none-elf` Rust targets, plus `espflash`, `cargo-espflash`, and `ldproxy` (includes `rust`). |
| `chrome` | `browser`, `chromium`, `devtools` | `chromium`, `chromium-driver`, `xvfb`, `fonts-liberation`, `fonts-noto-color-emoji`, `libnss3`, `libgbm1`, headless microVM flags (`--no-sandbox --disable-dev-shm-usage`), and `google-chrome` / `chrome` symlinks. |
| `hugo` | `static-site` | Hugo Extended binary (`/usr/local/bin/hugo`) with Sass/SCSS support. |
| `caddy` | `xcaddy` | Custom `caddy` binary built via `xcaddy` with `github.com/caddy-dns/cloudflare`, `github.com/greenpau/caddy-security`, and `github.com/mholt/caddy-l4` (includes `go`). |

______________________________________________________________________

## 3. Authenticate Agents

Before running sessions, configure persistent login credentials with `agbox auth` or export API keys in your host shell.

### Method 1: Persistent Sign-In (`agbox auth`)

Use `agbox auth` to sign in once for Google Antigravity (`agy`) or OpenCode OAuth providers without baking tokens into snapshots or sharing host credential directories:

```bash
# Sign in to Google Antigravity inside a zero-share microVM
agbox auth antigravity

# Sign in to OpenCode providers inside a zero-share microVM
agbox auth opencode

# Check saved credential status
agbox auth status

# Delete saved credentials
agbox auth logout all
```

`agbox auth` performs four steps:

1. Boots a disposable `agbox-auth-<pid>` microVM with zero host shares.
1. Runs the interactive login flow (`agy` or `opencode auth login`) as user `agent`.
1. Captures only allowlisted credential files (`antigravity-oauth-token`, `installation_id`, `antigravity_state.pbtxt`, `jetski_state.pbtxt`, or `auth.json`) within a 64 KiB limit and saves them in `$DATA_DIR/auth/<agent>` (`0600`).
1. Deletes `agbox-auth-<pid>` immediately on exit.

On every `agbox run` and `agbox resume`, `agbox` streams saved credentials over `stdin` into the microVM (`0600`). Pass `--no-auth` to skip saved login credentials for a single run or resume.

> **Temporary Sign-In:** You can also sign in directly inside `agbox run`. When you exit a non-persistent run, `agbox` deletes the microVM and the session token.

### Method 2: Per-Run API Keys

Export your provider API keys in your host shell before you run `agbox run`:

```bash
export ANTHROPIC_API_KEY="sk-ant-..."
export GEMINI_API_KEY="AIza..."
export OPENAI_API_KEY="sk-..."

agbox run opencode ~/projects/myapp
```

`agbox` streams non-empty keys over `stdin` into `/home/agent/.agbox-keys.sh` (`0600`) inside the microVM. `agbox` never passes secrets in CLI arguments. If key streaming fails, `agbox` stops immediately.

Supported passthrough variables:

- **Model Providers:** `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `GEMINI_API_KEY`, `GOOGLE_API_KEY`, `GOOGLE_GENERATIVE_AI_API_KEY`, `GROQ_API_KEY`, `OPENROUTER_API_KEY`, `MISTRAL_API_KEY`, `DEEPSEEK_API_KEY`, `COHERE_API_KEY`, `PERPLEXITY_API_KEY`, `TOGETHER_API_KEY`, `FIREWORKS_API_KEY`, `CEREBRAS_API_KEY`, `XAI_API_KEY`, `OLLAMA_HOST`
- **Cloud Providers:** `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`, `AWS_REGION`, `AWS_PROFILE`, `VERTEX_LOCATION`, `GOOGLE_CLOUD_PROJECT`, `GOOGLE_CLOUD_LOCATION`, `AZURE_OPENAI_API_KEY`, `AZURE_OPENAI_ENDPOINT`
- **GitHub and UI Auth:** `GITHUB_TOKEN`, `GH_TOKEN`, `OPENCODE_SERVER_PASSWORD`, `OPENCODE_SERVER_USERNAME`

______________________________________________________________________

## 4. Add Global Skills and Rules

`agbox` supports global read-only skills and rules across all projects, plus project-local skills and instructions inside shared directories.

### 1. Global Skills (`agbox skills`)

Store reusable skills in `$DATA_DIR/skills` on the host:

```bash
# Install a skill directory (or SKILL.md path) into $DATA_DIR/skills/<name>
agbox skills add ~/my-skills/code-review

# Replace an existing global skill
agbox skills add --force ~/my-skills/code-review

# List installed global skills
agbox skills list

# Delete a global skill
agbox skills rm code-review
```

When `$DATA_DIR/skills` contains one or more skills, `agbox run` mounts `$DATA_DIR/skills` read-only at `/home/agent/.agbox-skills` and bind-mounts it read-only (`ro,bind`) onto `/home/agent/.gemini/config/skills` and `/home/agent/.config/opencode/skills`. Guest processes, including guest `root`, cannot modify host files in `$DATA_DIR/skills`. Pass `--no-skills` to skip global skills for a single run or resume.

### 2. Global Rules (`agbox rules`)

Store standing Markdown instructions and engineering standards in `$DATA_DIR/rules` on the host:

```bash
# Install a Markdown rule file into $DATA_DIR/rules/<name>.md
agbox rules add ~/my-rules/engineering-standards.md

# Save or replace a rule under a custom name
agbox rules add --force --name standards ~/my-rules/engineering-standards.md

# List or print installed global rules
agbox rules list
agbox rules show standards

# Delete one rule or all global rules
agbox rules rm standards
agbox rules rm --all
```

When `$DATA_DIR/rules` contains one or more `.md` files (maximum 64 KiB per file), `agbox run` mounts `$DATA_DIR/rules` read-only at `/home/agent/.agbox-rules`. On every `agbox run` and `agbox resume`, `agbox` stages and bind-mounts the rules read-only (`ro,bind`):

- Plain Markdown files (and `trigger: always_on` files) merge in deterministic order (`AGENTS.md` and `GEMINI.md` first, then alphabetical `*.md`) into `/etc/agbox-global-rules/AGENTS.md` (`0444`). `agbox` bind-mounts that file read-only onto `/home/agent/.gemini/config/AGENTS.md` and `/home/agent/.config/opencode/AGENTS.md` so both `agy` and `opencode` enforce it on every session.
- Conditional Antigravity rule files with YAML frontmatter (`trigger: glob`, `trigger: model_decision`, or `trigger: manual`) stage into `/etc/agbox-global-rules/rules/*.md` (`0444`) and bind-mount read-only onto `/home/agent/.gemini/config/rules`.
- Editing `$DATA_DIR/rules` on the host takes effect automatically on the next `agbox run` or `agbox resume` without rebuilding `agbox:vN`. Pass `--no-rules` to skip global rules for a single run or resume.

### 3. Project Skills and Instructions (`.agents/skills` and `AGENTS.md`)

When you share one project directory, `agbox` starts the agent inside `/workspace/<name>`. Both `agy` and `opencode` discover `AGENTS.md`, `GEMINI.md`, `.agents/rules/*.md`, `.agents/skills/<skill>/SKILL.md`, and `.opencode/skills/<skill>/SKILL.md` automatically through the FUSE VCS filter while `.git` and `.jj` stay masked. When you share multiple directories with `antigravity`, `agbox` passes `--add-dir /workspace/<name>` for each shared directory.

______________________________________________________________________

## 5. Run Agents and Share Project Directories

`agbox` never mounts host directories unless you pass explicit paths or `--share-hub` to `agbox run`. Always place option flags before the agent name and shared paths.

### 1. Run Sessions and One-Shot Commands (`agbox run`)

```bash
# Run interactive OpenCode in a disposable microVM on one project
agbox run opencode ~/projects/myapp

# Run Antigravity (agy) in a named microVM (agbox-myapp)
agbox run --name myapp antigravity ~/projects/myapp

# Run one shell command inside an ephemeral microVM
agbox run --cmd "go test ./..." ~/projects/myapp

# Run with no guest network access and custom vCPU/RAM overrides
agbox run --no-net --cpus 2 --memory 4G --cmd "cargo test" ~/projects/crate
```

When `--name <name>` is passed, `agbox` names the sandbox `agbox-<name>` instead of `agbox-run-<pid>`. Names must use 1 to 63 ASCII letters, digits, `-`, or `_`, and must start with a letter or digit. If `agbox-<name>` already exists, `agbox run` fails immediately without modifying the existing microVM.

You can also adjust network access per run:

- `--no-net` (or `--net none`): Disables all guest network interfaces.
- `--net allow@api.anthropic.com:tcp:443`: Permits only the listed endpoint while keeping all local, private, multicast, and cloud-config deny rules active.
- `--net host`: Permits public internet and host services while blocking private LAN, loopback, link-local, multicast, and cloud-config ranges.
- `--net private`: Permits public and private networks while blocking host, loopback, link-local, multicast, and cloud-config ranges.
- `--net all`: Permits all outbound traffic.

### 2. Mix Permissions Across Project Directories

Pass per-share modifiers either as `<path>[:opts]` positional arguments or with repeatable `--share <path[:opts]>` flags:

```bash
# Reference docs read-only, shared library writable with VCS masked, main repo writable with VCS
agbox run antigravity \
  ~/projects/docs:ro \
  ~/projects/shared-lib:rw,mask \
  ~/projects/main-app:rw,vcs,as=app
```

Supported per-share modifiers:

- `ro`: Read-only access (`EROFS` on writes and `0222` permission bits masked).
- `rw`: Read-write access (default for `agbox run` unless you pass `--ro`).
- `mask`: Hide and write-protect all VCS directories and control files (default).
- `vcs`: Allow VCS operations (`git`, `jj`) while write-protecting `.git/hooks` and equivalent hook paths (`EPERM`).
- `vcs-hooks`: Allow VCS operations and writable hooks on a writable share.
- `as=<name>`: Mount the share at `/workspace/<name>` (`1..63` ASCII letters, digits, `.`, `_`, or `-`, starting with an alphanumeric character).

`agbox` rejects conflicting options immediately rather than overriding them silently. For example, passing both `--ro` and `--rw`, passing `:ro,rw` on one share, or combining `:ro` with `:vcs-hooks` returns an error.

### 3. Add, Update, or Remove Shares Live (`agbox share`)

Every sandbox with at least one share (or started with `--share-hub`) mounts a multiplexed `/workspace` FUSE hub controlled over a host-only `0600` Unix socket (`$DATA_DIR/run/<id>/ws.sock`, verified via `SO_PEERCRED`). You can list, attach, update, or detach project directories while the microVM is **running** or **suspended**:

```bash
# Start a sandbox with an empty /workspace hub ready for live shares
agbox run --name work --share-hub opencode

# Attach a share in another terminal (defaults to safe ro,mask)
agbox share add agbox-work ~/projects/docs

# Attach a writable VCS-enabled share under a custom alias
agbox share add --rw --vcs --as app agbox-work ~/projects/main-app

# Inspect active shares and open file-handle counts
agbox share list agbox-work

# Downgrade a live share to read-only or mask its VCS metadata
agbox share set --ro --mask agbox-work app

# Detach a share from /workspace
agbox share rm agbox-work docs
```

Safe-by-default rules for `agbox share`:

- `agbox share add` defaults to **`ro,mask`** unless you pass `--rw` (`:rw`) or `--vcs` (`:vcs`).
- `agbox share rm` and `agbox share set --ro` fail closed if the guest holds open writable file descriptors on that share. Pass `--force` to revoke open handles immediately (`ESTALE` on removed shares, `EROFS` on downgraded writers).
- Live changes persist in `$DATA_DIR/run/<id>/run.meta` across `agbox suspend` and `agbox resume`, and flush guest VFS lookup caches automatically.

______________________________________________________________________

## 6. Persist Conversations and Manage Sandbox Lifecycle

By default, `agbox run` is ephemeral and deletes conversation history on exit. Use `--persist`, `--profile`, or `agbox suspend`/`resume` when you need longer-lived work.

### Option 1: Named Persistent Sandbox (`--persist`)

Use `--persist --name <name>` to keep the microVM's `ext4` root disk across runs:

```bash
# First run creates agbox-myapp and suspends it automatically on exit
agbox run --persist --name myapp opencode ~/projects/myapp

# Next run resumes agbox-myapp and continues the latest conversation
agbox run --persist --name myapp -c opencode ~/projects/myapp

# Delete the persistent microVM when finished
agbox stop agbox-myapp
```

`--persist` preserves conversation databases, artifacts, installed `apt` packages, and build caches inside `agbox-<name>`. While stopped, `agbox-<name>` uses zero host CPU, RAM, or FUSE processes.

### Option 2: Conversation Profile Volume (`--profile`)

Use `--profile <name>` to keep conversation history on a dedicated `ext4` disk volume (`agbox-profile-<name>`) while every `agbox run` still boots a fresh root filesystem from `agbox:vN`:

```bash
# Optional: create a profile volume with a custom disk size (default: 10G)
agbox profile create --size 20G work

# Run an ephemeral microVM backed by conversation profile "work"
agbox run --profile work antigravity ~/projects/myapp

# Continue the most recent conversation or a specific conversation ID
agbox run --profile work -c antigravity ~/projects/myapp
agbox run --profile work --conversation 1c2a8c1e-6b56-4971-8429-ad0252c024a7 antigravity ~/projects/myapp

# List or delete profiles
agbox profile list
agbox profile rm work
```

`--profile` bind-mounts only the conversation state directories (`~/.gemini/antigravity-cli`, `~/.gemini/config/projects`, `~/.local/share/opencode`, and `~/.local/state/opencode`). Global skills, rules, hooks, plugins, `mcp_config.json`, and system binaries stay on the clean snapshot root disk. An exclusive host `flock` (`$DATA_DIR/profiles/<name>/profile.lock`) prevents two microVMs from mounting the same `ext4` profile volume at the same time.

You can also pass `-c` (`--continue`) or `-s <ID>` (`--session <ID>`, `--conversation <ID>`) to `agbox resume`.

### Suspend, Resume, and Delete Sandboxes

Suspend an active foreground or detached microVM to free host CPU, RAM, and FUSE processes while keeping its root disk:

```bash
agbox suspend agbox-feature-auth
```

`agbox suspend` performs three steps:

1. Writes `$DATA_DIR/run/<id>/suspended` with the recorded share paths and run mode.
1. Runs `msb stop <sandbox>` to halt the guest kernel while keeping the root disk image.
1. Unmounts all host FUSE filters so zero background processes remain on the host.

If you run `agbox suspend` from a second terminal while a foreground session is active, the foreground `agbox` process exits cleanly and skips `msb rm -f`.

> **Note:** `msb stop` halts the guest kernel rather than freezing guest RAM. All files on the guest root disk (such as installed packages or `/home/agent` state) persist, and `agbox resume` starts a fresh agent process.

Resume a suspended microVM when you are ready to continue:

```bash
agbox resume agbox-feature-auth
```

`agbox resume` performs four steps:

1. Validates every recorded share path again with `pathsec.ValidateShare`.
1. Mounts the FUSE Workspace Hub (or legacy `m*` filters) at the recorded `$DATA_DIR/run/<id>` mountpoint.
1. Runs `msb start <sandbox>` and streams current host API keys and auth tokens over `stdin`.
1. Starts the recorded TUI agent, `--serve` web server, `--remote-control` daemon, or command. Pass `-d` to detach a `--serve` or `--remote-control` session on resume.

If share validation, FUSE mounting, or `msb start` fails, `agbox resume` aborts and keeps the sandbox suspended.

Delete a running or suspended sandbox and remove its `$DATA_DIR/run/<id>` state:

```bash
agbox stop agbox-feature-auth
```

Run `agbox status` at any time to inspect running and suspended sandboxes, saved snapshots, skills, rules, and profiles.

______________________________________________________________________

## 7. Connect via Web Interface or Remote Control

Instead of a terminal TUI, you can expose OpenCode locally over HTTP (`--serve`) or tunnel Antigravity to `antigravity.google.com` (`--remote-control`). Both modes support `-d` (`--detach`) and `--persist`.

### 1. OpenCode Web Interface (`--serve`)

`agbox` runs `opencode serve` inside the microVM and binds port forwarding strictly on `127.0.0.1` on the host.

```bash
# Start on a random free loopback port (waits until /doc responds and prints the URL)
agbox run --serve ~/projects/myapp

# Start on a fixed host port 127.0.0.1:4096
agbox run --name web --serve --port 4096 ~/projects/myapp
```

Local host processes can connect to `127.0.0.1:<port>`. Set `OPENCODE_SERVER_PASSWORD` (and optional `OPENCODE_SERVER_USERNAME`, default `opencode`) to require HTTP Basic Authentication:

```bash
export OPENCODE_SERVER_USERNAME="admin"
export OPENCODE_SERVER_PASSWORD="choose-a-strong-password"

# Start detached in the background
agbox run --name web -d --serve --port 4096 ~/projects/myapp
```

Suspend the session with `agbox suspend agbox-web`, resume it with `agbox resume -d agbox-web`, or delete it with `agbox stop agbox-web`.

### 2. Antigravity Remote Control (`--remote-control`)

Antigravity Remote Control connects an `agy` session inside the microVM to [https://antigravity.google.com](https://antigravity.google.com). `agy` opens an outbound reverse tunnel over the default `public` network policy. You do not need `--port` or inbound firewall rules on the host.

1. Start a named detached Remote Control microVM (add `--persist` to keep its disk across stops):
   ```bash
   agbox run --persist --name work -d --remote-control ~/projects/myapp
   ```
1. If `agy` needs authentication and you have not run `agbox auth antigravity`, `agbox` opens `agy` interactively. Open the printed URL in your browser, paste the verification code, and run `/exit`.
1. `agbox` starts `agy remote-control start --name agbox-work` inside the microVM and returns your host shell prompt.
1. Open [https://antigravity.google.com](https://antigravity.google.com) and select `agbox-work` from the instance switcher.
1. Suspend the session with `agbox suspend agbox-work`, or delete it with `agbox stop agbox-work`.

Pass `--remote-control` without `-d` to keep the TUI open while Remote Control is active:

```bash
agbox run --remote-control ~/projects/myapp
```

You can also toggle Remote Control inside any interactive `agy` session with `/remote-control` and `/remote-control off`.

______________________________________________________________________

## 8. Update Agents and Customize the Base Image

Keep `agy` and `opencode` up to date quickly with `agbox update`, or add categories and system packages permanently to the base snapshot with `agbox edit-base`.

### 1. Update Agent Binaries Without Rebuilding the Base (`agbox update`)

Use `agbox update` to install newer `agy` or `opencode` releases into a read-only host cache (`$DATA_DIR/agents`) without rebuilding `agbox:vN` or losing logins, skills, rules, conversation profiles, or base-image categories:

```bash
# Update all agents installed in the base image
agbox update

# Update only Antigravity or only OpenCode
agbox update antigravity
agbox update opencode

# Check cached agent versions and SHA-256 digests
agbox update status

# Revert to the binaries baked into the base snapshot
agbox update clear
```

`agbox update` performs four steps:

1. Boots a disposable `agbox-update-<pid>` microVM with zero host shares, zero host API keys, and zero saved login tokens.
1. Runs the upstream HTTPS (TLS 1.2+) installer inside the isolated microVM and verifies `--version`.
1. Streams the updated binary back to the host, verifies the ELF header (`\x7fELF`), enforces size bounds and `st_nlink == 1`, records the SHA-256 digest in `$DATA_DIR/agents/manifest.json`, and seals the binary at mode `0755` inside `$DATA_DIR/agents/bin` (`0700` parent directory).
1. Mounts `$DATA_DIR/agents` read-only (`:ro`) at `/home/agent/.agbox-agents` on subsequent `agbox run` and `agbox resume` sessions, and bind-mounts the verified binaries read-only (`ro,bind`) over `/home/agent/.local/bin/agy`, `/usr/local/bin/agy`, and `/usr/local/bin/opencode`.

Pass `--no-agent-cache` to `agbox run` or `agbox resume` to skip `$DATA_DIR/agents` for a single session.

### 2. Add Categories or Packages to the Base Image (`agbox edit-base`)

Modify the base sandbox and save a new versioned snapshot (`agbox:v<N+1>`) with `edit-base`:

```bash
# Open the interactive category selector
agbox edit-base

# List available categories and packages
agbox edit-base --list

# Install specific categories and save a new snapshot
agbox edit-base --add chrome,hugo,caddy

# Run a custom command or open an interactive root shell in the base microVM
agbox edit-base --cmd "apt-get update && apt-get install -y jq"
agbox edit-base --shell
```

Pass `--no-snap` to keep edits only in `agbox-base` without creating a new snapshot yet.

______________________________________________________________________

## 9. CLI Reference, Environment Variables, and Uninstallation

### CLI Reference

```text
Global options:
  --allow-root
      Allow agbox to run as the root user (or set AGBOX_ALLOW_ROOT=1).

Modes:
  agbox setup [--allow-root]
      Check host prerequisites (msb, /dev/kvm, FUSE, and microVM smoke test).

  agbox create-base [--force] [--allow-root] [--add <categories>] <opencode|antigravity|both>
      Create the base microVM and save snapshot agbox:vN.

  agbox edit-base [--allow-root] [--add <categories>] [--list] [--shell] [--cmd "shell"] [--no-snap]
      Start the base microVM and install categories or run custom updates.
      Save snapshot agbox:v<N+1> unless you pass --no-snap.

  agbox update [--allow-root] [antigravity|opencode|both|status|clear]
      Update agent binaries inside a disposable zero-share microVM and cache
      verified ELF binaries in $DATA_DIR/agents without rebuilding the base snapshot.

  agbox auth [--allow-root] [antigravity|opencode|status|logout]
      Sign in inside a disposable microVM and save credentials in $DATA_DIR/auth.

  agbox skills [--allow-root] [list|add [--force] <path>|rm <name>]
      Manage global skills mounted read-only into sandboxes from $DATA_DIR/skills.

  agbox rules [--allow-root] [list|add [--force] [--name NAME] <file.md>|show [<name>]|rm <name|--all>]
      Manage global rules mounted read-only into sandboxes from $DATA_DIR/rules.

  agbox profile [--allow-root] [list|create [--size SIZE] <name>|rm [--force] <name>]
      Manage ext4 disk profiles for conversation history across ephemeral runs.

  agbox share [--allow-root] <list|add|set|rm> <sandbox> [...]
      List, attach, update permissions on, or detach /workspace shares on a running
      or suspended sandbox (agbox share add defaults to ro,mask).

  agbox run [options] [opencode|antigravity] [path[:opts]...]
      Restore a microVM and mask VCS files and directories.
      Block local, private, multicast, and cloud-config IPs by default.
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
        --share-hub          Mount an empty /workspace FUSE hub so shares can be added live
        --ro / --rw          Set default share access mode (conflicts with opposite modifier)
        --mask-vcs           Mask VCS metadata inside directory shares (default)
        --vcs                Allow VCS metadata inside shares while write-protecting hooks
        --vcs-hooks          Allow VCS metadata and writable hooks inside writable shares
        --no-mask            Disable the FUSE VCS filter (.git is visible to guest)
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

  agbox resume [--allow-root] [-d|--detach] [-c|--continue] [--session ID] <sandbox>
      Validate shares, mount FUSE filters, start a suspended microVM, and restart its agent.

  agbox stop [--allow-root] <sandbox>
      Delete a running or suspended run microVM and unmount its FUSE shares.

  agbox remove [--allow-root] [--yes]
      Delete all agbox microVMs, snapshots, profile volumes, FUSE mounts, and $DATA_DIR.

  agbox status [--allow-root]
      Show base configuration, persistence state, microVMs, snapshots, and disk usage.
```

### Configuration (Environment Variables)

| Variable | Default | Purpose |
|---|---|---|
| `AGBOX_DATA_DIR` | `~/.local/share/agbox` | Host directory for `config`, `auth`, `agents`, `skills`, `rules`, `profiles`, and `run/<id>`. |
| `AGBOX_INSTALL_DIR` | `~/.local/bin` (`/usr/local/bin` for `root`) | Target directory where `install.sh` installs the `agbox` binary. |
| `AGBOX_ALLOW_ROOT` | `0` | Set to `1` to allow `install.sh` and `agbox` to run as `root`. |
| `AGBOX_CPUS` | `4` | Default vCPU count for `create-base` and `run`. |
| `AGBOX_MEMORY` | `8G` | Default guest RAM size for `create-base` and `run`. |
| `AGBOX_ROOT_DISK` | `50G` | Default sparse guest root disk size for `create-base` and `edit-base`. |
| `AGBOX_PROFILE_DISK` | `10G` | Default `ext4` disk volume size for `agbox profile create` and `run --profile`. |
| `AGBOX_MASK_VCS` | `strict` | FUSE filter policy for directory shares: `strict`, `auto`, or `off`. |
| `AGBOX_ALLOW_OUTSIDE_HOME` | `0` | Set to `1` to allow shares outside `$HOME`. Blocklists still apply. |
| `AGBOX_OPENCODE_VERSION` | `latest` | npm version or tag for `opencode-ai` during `create-base` and `update`. |
| `AGBOX_AGY_INSTALLER_URL` | `https://antigravity.google/cli/install.sh` | Installer URL for `agy` during `create-base` and `update`. |
| `OPENCODE_SERVER_PASSWORD` | *(unset)* | Optional HTTP Basic Auth password for `agbox run --serve`. |
| `OPENCODE_SERVER_USERNAME` | `opencode` | Optional HTTP Basic Auth username for `agbox run --serve`. |

### Uninstall All State (`agbox remove`)

Delete all `agbox` microVMs, snapshots, profile volumes, active FUSE mounts, and `$DATA_DIR`:

```bash
# Prompts for confirmation before deleting state
agbox remove

# Skip confirmation prompt (for automation)
agbox remove --yes
```
