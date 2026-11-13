# agbox

`agbox` runs AI coding agents ([OpenCode](https://opencode.ai) or [Google Antigravity CLI (`agy`)](https://antigravity.google)) inside disposable [microsandbox (`msb`)](https://microsandbox.dev) microVMs on Linux.

Each run boots an isolated microVM from a local base snapshot. `agbox` mounts only the host paths that you pass on the command line. By default, `agbox` masks all version-control entries through FUSE and blocks local, private, multicast, and cloud-config IPs. If any check or setup step fails, `agbox` stops immediately and deletes partial state.

______________________________________________________________________

## Why This Design Exists

1. **Hardware VM Isolation (`/dev/kvm` and `libkrun`):**
   Containers share the host Linux kernel. `agbox` runs each session inside a dedicated guest kernel. Guest root commands (`sudo apt-get install ...`) stay inside the microVM.
1. **Secure-by-Default and Fail-Closed Execution:**
   `agbox` masks VCS metadata and blocks local, private, multicast, and cloud-config IP ranges by default. If any check fails during `install.sh`, `setup`, `create-base`, `edit-base`, `run`, or `resume`, `agbox` stops immediately.
1. **Disposable or Persistent Runs from Snapshots (`agbox:vN`):**
   `agbox create-base` builds the base image once. `agbox edit-base` updates the base image and saves a new snapshot. `agbox run` restores `agbox-<name>` (or `agbox-run-<pid>`) and deletes it on exit unless you pass `--persist`, detach it, or suspend it.
1. **Single Binary with Hardened FUSE Filter (`go-fuse/v2` and `openat2`):**
   A raw directory share exposes `.git/hooks`, `.jj`, and host symlinks to the guest. `agbox` embeds a hardened loopback FUSE filter (`/proc/self/exe __filter`) that confines the guest to regular files, directories, and intra-share relative symlinks:
   - The filter hides VCS directories and control files (`.git`, `.gitignore`, `.gitattributes`, `.gitmodules`, `.jj`, `.sl`, `.svn`, `.hg`, `.bzr`, `_darcs`, `.pijul`, and Fossil) case-insensitively (`ENOENT`).
   - The filter blocks creation, deletion, linking, or renaming of any VCS entry at every directory depth (`EPERM`).
   - The filter resolves all host paths with Linux `openat2` (`RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS`) so host symlinks cannot escape the share.
   - The filter rejects absolute symlinks, symlinks that escape the share root, and symlinks that reference VCS names (`EPERM`).
   - The filter blocks FIFOs, sockets, device nodes, `setuid`/`setgid` bits, ownership changes, raw host `ioctl` calls, and non-`user.*` extended attributes (`EPERM`).
1. **Non-Root Guest User (`agent`, `1000:1000`) with Passwordless `sudo`:**
   The guest runs agents and commands as user `agent` (`1000:1000`). `agbox` mounts shared volumes with `uid=1000,gid=1000` to match standard Linux file ownership. Passwordless `sudo` lets the agent install packages inside the microVM.
1. **Secret Delivery Over `stdin`:**
   `agbox` never stores host API keys in the base snapshot or on the host disk. `agbox` never passes secrets in CLI arguments where local processes can read `/proc/<pid>/cmdline`. Instead, `agbox` streams secrets over `stdin` into `/home/agent/.agbox-keys.sh` (`0600`) inside the microVM.

______________________________________________________________________

## Quick Start

### 1. Install and Check the Host

Run the installer script as your normal user:

```bash
./install.sh
```

To install as `root`, pass `--allow-root` (or set `AGBOX_ALLOW_ROOT=1`):

```bash
./install.sh --allow-root
```

`install.sh` runs these checks and build steps:

1. Rejects `root` unless you pass `--allow-root` or set `AGBOX_ALLOW_ROOT=1`.
1. Checks that `glibc` is version 2.28 or newer.
1. Requires the `go` toolchain and `fusermount3` (or `fusermount`).
1. Installs `msb` over HTTPS (TLS 1.2+) if `msb` is not on `PATH`.
1. Builds `agbox` in a temporary directory and installs it to `~/.local/bin/agbox` (`/usr/local/bin/agbox` for `root`).
1. Runs `agbox setup` to check `DATA_DIR`, `/dev/kvm`, FUSE mount support, `msb doctor`, and an offline Alpine microVM.

### 2. Create the Base Snapshot

Create a base snapshot with `opencode`, `antigravity` (`agy`), or `both`. You can also include developer categories (`core`, `go`, `rust`, `esphome`, `embedded-rust`, `chrome`, `hugo`, `caddy`, or `all`):

```bash
agbox create-base --add core,go,rust,esphome both
```

To add categories later, run `edit-base`:

```bash
# Open the interactive category menu
agbox edit-base

# List available categories and packages
agbox edit-base --list

# Install specific categories and save a new snapshot
agbox edit-base --add chrome,hugo,caddy
```

### 3. Run an Agent on a Project Directory

Place all option flags before the agent name and shared paths:

```bash
# Run the OpenCode TUI in a named sandbox (agbox-myapp)
agbox run --name myapp opencode ~/projects/myapp

# Run Google Antigravity CLI (agy) with read-only mounts
agbox run --ro antigravity ~/projects/myapp ~/projects/shared-lib

# Run one shell command inside an ephemeral microVM
agbox run --cmd "go test ./..." ~/projects/myapp

# Start the OpenCode web interface on 127.0.0.1:4096
agbox run --name web --serve --port 4096 ~/projects/myapp

# Start Antigravity Remote Control detached in the background
agbox run --name rc -d --remote-control ~/projects/myapp
```

______________________________________________________________________

## Secure-by-Default Networking and Shared Directories

`agbox` enforces strict network and filesystem isolation by default. If any security check fails, `agbox` stops immediately instead of running with reduced protection.

### Default Network Policy

By default, `agbox create-base` and `agbox run` configure `msb` with a default-deny egress firewall (`--net public`):

- **Default action:** `--net-default deny` drops unmatched outbound traffic.
- **Blocked groups:** `deny@host`, `deny@loopback`, `deny@private`, `deny@link-local`, `deny@multicast`, and `deny@metadata` block host services, loopback, RFC1918 private LANs (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), CGNAT (`100.64.0.0/10`), IPv6 ULA (`fc00::/7`), link-local ranges, multicast (`224.0.0.0/4`, `ff00::/8`), and cloud metadata endpoints.
- **Blocked CIDRs:** Explicit rules also block `0.0.0.0/8`, `169.254.0.0/16`, `fe80::/10`, `240.0.0.0/4` (including `255.255.255.255`), Azure WireServer (`168.63.129.16/32`), Alibaba Cloud IMDS (`100.100.100.200/32`), and AWS IPv6 IMDS (`fd00:ec2::254/128`) before any `allow@...` rule.
- **Allowed ranges:** `--net-rule allow@public` permits outbound public internet traffic for model APIs and package mirrors.

You can adjust network access per run:

- `--no-net` (or `--net none`): Disables all guest network interfaces.
- `--net allow@api.anthropic.com:tcp:443`: Permits only the listed endpoint while keeping all local, private, multicast, and cloud-config deny rules active.
- `--net host`: Permits public internet and host services while blocking private LAN, loopback, link-local, multicast, and cloud-config ranges.
- `--net private`: Permits public and private networks while blocking host, loopback, link-local, multicast, and cloud-config ranges.
- `--net all`: Permits all outbound traffic.

### Default Shared Directory Policy

`agbox` never mounts the host filesystem unless you pass explicit paths to `agbox run`:

1. **Strict VCS Masking and Syscall Confinement (`AGBOX_MASK_VCS=strict`):**
   Every shared directory mounts through the embedded FUSE filter (`nosuid,nodev`) by default. The filter hides and write-protects all 22 VCS directories and control files (`.git*`, `.jj`, `.sl`, `.svn`, `.hg*`, `.bzr*`, `_darcs`, `.pijul`, Fossil, and `.cvsignore`) case-insensitively at every depth. All host file operations use `openat2` (`RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS`). The filter allows regular files, directories, and intra-share relative symlinks that do not reference VCS names. It blocks out-of-tree symlinks, device/FIFO/socket nodes, `setuid`/`setgid` bits, cross-UID ownership changes, host `ioctl` calls, and non-`user.*` extended attributes. If the FUSE mount fails, `agbox` aborts immediately. Pass `--no-mask` (or set `AGBOX_MASK_VCS=off`) only when the guest must access VCS metadata directly.
1. **Path Canonicalization and Containment (`internal/pathsec`):**
   `pathsec.ValidateShare` resolves all symlinks before mounting. Missing paths, dangling symlinks, and paths containing `:`, `,`, or control characters fail validation. Paths outside `$HOME` fail validation unless you set `AGBOX_ALLOW_OUTSIDE_HOME=1`.
1. **VCS, Credential, and System Blocklist:**
   `agbox` rejects direct shares of any VCS directory, VCS subdirectory (such as `.git/hooks` or `.jj/repo`), or VCS control file. `agbox` also blocks SSH keys (`~/.ssh`), cloud and VCS credentials (`~/.aws`, `~/.config/gcloud`, `~/.config/gh`, `~/.config/hub`, `~/.config/glab`, `~/.gitconfig`, `~/.git-credentials`, `~/.jjconfig.toml`, `~/.config/jj`, `~/.hgrc`, `~/.subversion`, `~/.bazaar`), agent state (`~/.gemini`, `~/.antigravity`, `~/.claude`, `~/.config/opencode`), shell and `direnv` configs, `DATA_DIR` (rejecting symlinks), and system paths (`/etc`, `/proc`, `/sys`, `/dev`). Parent directories of blocklisted paths (including `$HOME` itself) also fail validation.
1. **Single-File Hardlink Check:**
   Writable single-file shares must be regular files with a hardlink count of `1` (`st_nlink == 1`) so the guest cannot alter a hardlinked file outside the share. Read-only shares (`--ro`) allow multiple hardlinks.

______________________________________________________________________

## User Guide: Named Sandboxes, Suspend, and Resume

### Named Sandboxes (`--name`)

By default, `agbox run` names each microVM `agbox-run-<pid>`. Pass `--name <name>` to name the microVM `agbox-<name>`:

```bash
agbox run --name feature-auth opencode ~/projects/myapp
```

Names must use 1 to 63 ASCII letters, digits, `-`, or `_`, and must start with a letter or digit. If `agbox-<name>` already exists, `agbox run` fails immediately without modifying the existing microVM.

### Suspend a Running Sandbox (`agbox suspend`)

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

### Resume a Suspended Sandbox (`agbox resume`)

Resume a suspended microVM when you are ready to continue:

```bash
agbox resume agbox-feature-auth
```

`agbox resume` performs four steps:

1. Validates every recorded share path again with `pathsec.ValidateShare`.
1. Mounts the FUSE VCS filters at the same `$DATA_DIR/run/<id>/m*` paths.
1. Runs `msb start <sandbox>` and streams current host API keys over `stdin`.
1. Starts the recorded TUI agent, `--serve` web server, `--remote-control` daemon, or command. Pass `-d` to detach a `--serve` or `--remote-control` session on resume.

If share validation, FUSE mounting, or `msb start` fails, `agbox resume` aborts and keeps the sandbox suspended.

### Delete a Sandbox (`agbox stop`)

Delete a running or suspended sandbox and remove its `$DATA_DIR/run/<id>` state:

```bash
agbox stop agbox-feature-auth
```

______________________________________________________________________

## User Guide: Authentication

You can authenticate agents with per-run environment variables or persistent `agbox auth` credentials.

### Method 1: Per-Run API Keys (Recommended for API Providers)

Export your provider API keys in your host shell before you run `agbox run`:

```bash
export ANTHROPIC_API_KEY="sk-ant-..."
export GEMINI_API_KEY="AIza..."
export OPENAI_API_KEY="sk-..."

agbox run opencode ~/projects/myapp
```

`agbox` streams non-empty keys over `stdin` into `/home/agent/.agbox-keys.sh` inside the microVM. If key streaming fails, `agbox` stops immediately.

Supported passthrough variables:

- **Model Providers:** `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `GEMINI_API_KEY`, `GOOGLE_API_KEY`, `GOOGLE_GENERATIVE_AI_API_KEY`, `GROQ_API_KEY`, `OPENROUTER_API_KEY`, `MISTRAL_API_KEY`, `DEEPSEEK_API_KEY`, `COHERE_API_KEY`, `PERPLEXITY_API_KEY`, `TOGETHER_API_KEY`, `FIREWORKS_API_KEY`, `CEREBRAS_API_KEY`, `XAI_API_KEY`, `OLLAMA_HOST`
- **Cloud Providers:** `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`, `AWS_REGION`, `AWS_PROFILE`, `VERTEX_LOCATION`, `GOOGLE_CLOUD_PROJECT`, `GOOGLE_CLOUD_LOCATION`, `AZURE_OPENAI_API_KEY`, `AZURE_OPENAI_ENDPOINT`
- **GitHub and UI Auth:** `GITHUB_TOKEN`, `GH_TOKEN`, `OPENCODE_SERVER_PASSWORD`, `OPENCODE_SERVER_USERNAME`

### Method 2: Persistent Sign-In (`agbox auth`)

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

______________________________________________________________________

## User Guide: Persistent Skills

`agbox` supports both global read-only skills across all projects and project-local skills inside shared directories.

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

When `$DATA_DIR/skills` contains one or more skills, `agbox run` mounts `$DATA_DIR/skills` read-only at `/home/agent/.agbox-skills` and bind-mounts it read-only (`ro,bind`) onto `/home/agent/.gemini/config/skills` and `/home/agent/.config/opencode/skills`. Guest processes, including guest `root`, cannot modify host files in `$DATA_DIR/skills`. Pass `--no-skills` to skip global skills for a run.

### 2. Project Skills and Instructions (`.agents/skills`)

When you share one project directory, `agbox` starts the agent inside `/workspace/<name>`. Both `agy` and `opencode` discover `.agents/skills/<skill>/SKILL.md`, `.opencode/skills/<skill>/SKILL.md`, `GEMINI.md`, and `AGENTS.md` automatically through the FUSE VCS filter while `.git` and `.jj` stay masked. When you share multiple directories with `antigravity`, `agbox` passes `--add-dir /workspace/<name>` for each shared directory.

______________________________________________________________________

## User Guide: Persistent Conversations (`--persist` and `--profile`)

By default, `agbox run` is ephemeral and deletes conversation history on exit. `agbox` provides two opt-in persistence modes so you can choose between full guest state and clean ephemeral root disks.

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

`--profile` bind-mounts only the conversation state directories (`~/.gemini/antigravity-cli`, `~/.gemini/config/projects`, `~/.local/share/opencode`, and `~/.local/state/opencode`). Global skills, hooks, plugins, `mcp_config.json`, and system binaries stay on the clean snapshot root disk. An exclusive host `flock` (`$DATA_DIR/profiles/<name>/profile.lock`) prevents two microVMs from mounting the same `ext4` profile volume at the same time.

You can also pass `-c` (`--continue`) or `-s <ID>` (`--session <ID>`, `--conversation <ID>`) to `agbox resume`.

______________________________________________________________________

## User Guide: Web Interface Access (`--serve`)

`agbox` can run the OpenCode web server inside the microVM and publish it on `127.0.0.1` on the host.

### 1. Start the Web Interface on a Random Port

```bash
agbox run --serve ~/projects/myapp
```

`agbox` binds a free host loopback port, starts `opencode serve`, waits until `/doc` responds, and prints the URL:

```text
[agbox] OpenCode web UI: http://127.0.0.1:34192
```

Open that URL in your host browser. Press `Ctrl-C` in the terminal to stop and delete the microVM.

### 2. Start the Web Interface on a Fixed Port

Use `--port <1-65535>` to bind a fixed host port on `127.0.0.1`:

```bash
agbox run --name web --serve --port 4096 ~/projects/myapp
```

### 3. Protect the Web Interface with a Password

Local host processes can connect to `127.0.0.1:<port>`. Set `OPENCODE_SERVER_PASSWORD` (and optional `OPENCODE_SERVER_USERNAME`, default `opencode`) to require HTTP Basic Authentication:

```bash
export OPENCODE_SERVER_USERNAME="admin"
export OPENCODE_SERVER_PASSWORD="choose-a-strong-password"

agbox run --name web --serve --port 4096 ~/projects/myapp
```

### 4. Run Detached in the Background

Pass `-d` (or `--detach`) to keep the microVM and its FUSE filters running after `agbox` exits:

```bash
agbox run --name web -d --serve --port 4096 ~/projects/myapp
```

Suspend the session with `agbox suspend agbox-web`, or delete it with `agbox stop agbox-web`.

______________________________________________________________________

## User Guide: Antigravity Remote Control (`antigravity.google.com`)

Antigravity Remote Control connects an `agy` session inside the microVM to [https://antigravity.google.com](https://antigravity.google.com). `agy` opens an outbound reverse tunnel over the default `public` network policy. You do not need `--port` or inbound firewall rules on the host.

### 1. Run Detached in the Background (`-d --remote-control`)

1. Start a named detached Remote Control microVM:
   ```bash
   agbox run --name work -d --remote-control ~/projects/myapp
   ```
1. If `agy` needs authentication, `agbox` opens `agy` interactively. Open the printed URL in your browser, paste the verification code, and run `/exit`.
1. `agbox` starts `agy remote-control start --name agbox-work` inside the microVM and returns your host shell prompt.
1. Open [https://antigravity.google.com](https://antigravity.google.com) and select `agbox-work` from the instance switcher.
1. Suspend the session with `agbox suspend agbox-work`, or delete it with `agbox stop agbox-work`.

### 2. Start Interactive `agy` with Remote Control

Pass `--remote-control` without `-d` to keep the TUI open while Remote Control is active:

```bash
agbox run --remote-control ~/projects/myapp
```

You can also toggle Remote Control inside any interactive `agy` session with `/remote-control` and `/remote-control off`.

______________________________________________________________________

## Base-Image Categories (`create-base` and `edit-base`)

| Category | Aliases | Installed Packages and Tools |
|---|---|---|
| `core` | `base`, `cli` | `build-essential`, `pkg-config`, `cmake`, `ninja-build`, `libffi-dev`, `libssl-dev`, `libsqlite3-dev`, `sqlite3`, `ca-certificates`, `curl`, `wget`, `git`, `htop`, `ncdu`, `net-tools`, `iproute2`, `dnsutils`, `rsync`, `unzip`, `zip`, `vim`, `jq`, `ripgrep`, `fd-find`, `less`, `procps`, `psmisc`, `lsof`, `strace`, `tree`, `file`, `openssh-client`, `python3`, `python3-pip`, `python3-setuptools`, `python3-venv`, `python3-wheel`, `pipx`, and `mdformat` (via `pipx`). |
| `go` | `golang` | Upstream Go toolchain in `/usr/local/go` (fallback: `golang-go`), `protobuf-compiler`, and `dlv`, `gopls`, `golangci-lint`, `goimports`, `staticcheck`, `govulncheck` in `/home/agent/go/bin`. |
| `rust` | `cargo`, `rustup` | `rustup` stable toolchain with `clippy`, `rustfmt`, `rust-analyzer`, `rust-src`, plus `clang`, `lld`, `pkg-config`, `libssl-dev`, `libudev-dev`, `libusb-1.0-0-dev`, `protobuf-compiler`, and `sccache`. |
| `esphome` | `esp` | `esphome`, `esptool`, and `platformio` (via `pipx`), plus `libudev-dev`, `libusb-1.0-0-dev`, `udev`, `usbutils`, `cmake`, `ninja-build`, `gperf`, `ccache`, `dfu-util`, `picocom`, and `minicom`. |
| `embedded-rust` | `esp-rust` | `riscv32imc-unknown-none-elf` and `riscv32imac-unknown-none-elf` Rust targets, plus `espflash`, `cargo-espflash`, and `ldproxy` (includes `rust`). |
| `chrome` | `browser`, `chromium`, `devtools` | `chromium`, `chromium-driver`, `xvfb`, `fonts-liberation`, `fonts-noto-color-emoji`, `libnss3`, `libgbm1`, headless microVM flags (`--no-sandbox --disable-dev-shm-usage`), and `google-chrome` / `chrome` symlinks. |
| `hugo` | `static-site` | Hugo Extended binary (`/usr/local/bin/hugo`) with Sass/SCSS support. |
| `caddy` | `xcaddy` | Custom `caddy` binary built via `xcaddy` with `github.com/caddy-dns/cloudflare`, `github.com/greenpau/caddy-security`, and `github.com/mholt/caddy-l4` (includes `go`). |

______________________________________________________________________

## CLI Reference

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

  agbox auth [--allow-root] [antigravity|opencode|status|logout]
      Sign in inside a disposable microVM and save credentials in $DATA_DIR/auth.

  agbox skills [--allow-root] [list|add [--force] <path>|rm <name>]
      Manage global skills mounted read-only into sandboxes from $DATA_DIR/skills.

  agbox profile [--allow-root] [list|create [--size SIZE] <name>|rm [--force] <name>]
      Manage ext4 disk profiles for conversation history across ephemeral runs.

  agbox run [options] [opencode|antigravity] [paths...]
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
        --allow-root         Allow agbox to run as the root user
        --ro                 Mount shared paths read-only
        --mask-vcs           Require the FUSE VCS filter for directory shares (default)
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

______________________________________________________________________

## Configuration (Environment Variables)

| Variable | Default | Purpose |
|---|---|---|
| `AGBOX_DATA_DIR` | `~/.local/share/agbox` | Host directory for `config`, `auth`, `skills`, `profiles`, and `run/<id>`. |
| `AGBOX_INSTALL_DIR` | `~/.local/bin` (`/usr/local/bin` for `root`) | Target directory where `install.sh` installs the `agbox` binary. |
| `AGBOX_ALLOW_ROOT` | `0` | Set to `1` to allow `install.sh` and `agbox` to run as `root`. |
| `AGBOX_CPUS` | `4` | Default vCPU count for `create-base` and `run`. |
| `AGBOX_MEMORY` | `8G` | Default guest RAM size for `create-base` and `run`. |
| `AGBOX_ROOT_DISK` | `50G` | Default sparse guest root disk size for `create-base` and `edit-base`. |
| `AGBOX_PROFILE_DISK` | `10G` | Default `ext4` disk volume size for `agbox profile create` and `run --profile`. |
| `AGBOX_MASK_VCS` | `strict` | FUSE filter policy for directory shares: `strict`, `auto`, or `off`. |
| `AGBOX_ALLOW_OUTSIDE_HOME` | `0` | Set to `1` to allow shares outside `$HOME`. Blocklists still apply. |
| `AGBOX_OPENCODE_VERSION` | `latest` | npm version or tag for `opencode-ai` during `create-base`. |
| `AGBOX_AGY_INSTALLER_URL` | `https://antigravity.google/cli/install.sh` | Installer URL for `agy` during `create-base`. |
| `OPENCODE_SERVER_PASSWORD` | *(unset)* | Optional HTTP Basic Auth password for `agbox run --serve`. |
| `OPENCODE_SERVER_USERNAME` | `opencode` | Optional HTTP Basic Auth username for `agbox run --serve`. |

______________________________________________________________________

## Mount Inspection and Cleanup (`internal/mounttab`)

- `mounttab` reads `/proc/self/mountinfo` and decodes octal escape sequences (`\040`, `\134`). It does not rely on `os.Stat` because a crashed FUSE daemon returns `ENOTCONN` while the mount stays active.
- `mounttab.OSController` checks `/proc/<pid>/cmdline` for `agbox __filter` before it signals a recorded PID. This check prevents signaling an unrelated host process after PID reuse.
- `mounttab.UnmountFilterDir` sends `SIGTERM` to verified FUSE daemons and unmounts each mountpoint with `fusermount3 -u` (or `fusermount -u`). If a mount stays active, it sends `SIGKILL`, runs a lazy unmount, and checks `/proc/self/mountinfo` again.
- `mounttab.TeardownFilterDir` calls `UnmountFilterDir` first and refuses to run `os.RemoveAll` if any mountpoint remains active.
- `ReapOrphanRuns` and `ReapStaleFilterDirs` delete crashed run sandboxes while preserving running detached sessions and stopped suspended sessions.

______________________________________________________________________

## Security Properties Reference

| Security Property | Enforcement Boundary | Guarantee |
|---|---|---|
| Hardware microVM isolation | `msb` (`/dev/kvm`, `libkrun`) | Each session boots its own guest kernel. Guest root commands do not affect the host kernel. |
| Non-root host execution | `cli.CheckRootExecution`, `install.sh` | Rejects `euid == 0` unless `--allow-root` or `AGBOX_ALLOW_ROOT=1` is set. |
| Private state directories | `config.EnsurePrivateDir`, `vcsfuse` | Rejects symlinks via `Lstat`, sets directory mode `0700`, and writes metadata files with mode `0600`. |
| Boundary input validation | `config.FromLookup`, `cli`, `persist` | Rejects invalid CPU/RAM/disk specs, control characters, unsafe session IDs, malformed `--net-rule` tokens, and non-`https://` installer URLs. |
| Explicit opt-in host shares | `cli.Run`, `pathsec.ValidateShare` | Mounts zero host paths unless passed on the CLI. Resolves symlinks and restricts shares to `$HOME` by default. |
| Credential and system blocklist | `pathsec.DefaultBlocklist` | Blocks SSH, cloud, agent, VCS, shell, `direnv`, `DATA_DIR`, `MSB_HOME`, and system paths (plus parent directories and symlink targets). |
| Direct VCS share prohibition | `pathsec.ContainsVCSComponent` | Blocks direct shares of any VCS directory, VCS subdirectory, or VCS working-tree file (case-insensitive). |
| Single-file hardlink check | `pathsec.ValidateShare` | Requires regular files and `st_nlink == 1` on writable single-file shares. |
| Case-insensitive VCS masking | `vcsfuse.FilteredNode` | Hides all 22 VCS directories and control files (`ENOENT`) and blocks all writes to those names (`EPERM`) at every depth. |
| Root-pinned `openat2` resolution | `vcsfuse.pinnedRoot` | Resolves every FUSE operation with `RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS` and rejects detached child inodes (`ENOENT`). |
| Intra-share symlink confinement | `vcsfuse.ValidateSymlinkTarget` | Blocks absolute targets, `..` root escapes, and VCS targets on both `Symlink` and `Readlink` (`EPERM`). |
| Special-file and `ioctl` blocking | `vcsfuse` (`safeFile`, `Mknod`, `Open`) | Mounts with `nosuid,nodev`, allows `S_IFREG` only, and hides `PassthroughFd` and `Ioctl` on file and directory handles. |
| Privilege-bit and `chown` blocking | `vcsfuse` (`sanitizeCreateMode`, `Setattr`) | Strips `setuid`/`setgid` on creation and rejects `setuid`/`setgid` modes and cross-UID/GID `chown` (`EPERM`). |
| Extended attribute isolation | `vcsfuse.IsProtectedXattr` | Allows `user.<name>` attributes only and blocks `security.*`, `system.*`, and `trusted.*` (`EPERM` / `ENODATA`). |
| Default-deny public-only network | `msb.BuildNetArgs` | Places `deny@host`, `deny@loopback`, `deny@private`, `deny@link-local`, `deny@multicast`, `deny@metadata`, and cloud-config CIDRs before `allow@public`. |
| Loopback-only web server binding | `cli.Run` (`--serve`) | Binds host TCP forwarding strictly on `127.0.0.1:<port>`. |
| HTTPS and TLS 1.2+ downloads | `install.sh`, `cli`, `msb` | Enforces `--proto '=https' --tlsv1.2` on all `curl` installer downloads. |
| Secret streaming over `stdin` | `msb.FormatEnvExports`, `cli.pushKeys` | Quotes values for POSIX `sh` and streams keys over `stdin` into `/home/agent/.agbox-keys.sh` (`0600`). Never passes secrets in CLI arguments. |
| Allowlisted `agbox auth` credentials | `persist`, `cli.Auth`, `cli.pushAuth` | Captures only allowlisted login files (max 64 KiB, `Lstat` no-symlink check) from a zero-share microVM, stores them at `0600` in `$DATA_DIR/auth`, and streams them over `stdin`. |
| Read-only global skills | `persist.InspectSkillsDir`, `cli` | Rejects symlinks and special files in `$DATA_DIR/skills`, mounts the volume read-only (`:ro`), and enforces `ro,bind` mounts inside the guest. |
| Isolated `ext4` conversation profiles | `persist.LockProfile`, `cli` | Guards each `agbox-profile-<name>` disk volume with an exclusive host `flock` and bind-mounts only conversation directories while keeping global skills, hooks, plugins, and `mcp_config.json` outside the profile disk. |
| PID-reuse signal protection | `mounttab.IsFilterCmdline` | Verifies `/proc/<pid>/cmdline` has `argv[1] == "__filter"` before sending `SIGTERM` or `SIGKILL`. |
| Mount-verified directory deletion | `mounttab.TeardownFilterDir` | Verifies zero active mounts in `/proc/self/mountinfo` before running `os.RemoveAll`. |
| Tamper-evident `resume` & fail-closed setup | `cli` (`Setup`, `EditBase`, `Run`, `Resume`), `install.sh` | Checks FUSE, KVM, and an offline smoke microVM in `setup`, re-validates shares, skills, profiles, and strict masking on `resume`, and aborts on any error. |

______________________________________________________________________

## Package Structure

```text
agbox/
├── cmd/agbox/         Main entrypoint (routes __filter to vcsfuse and commands to cli)
├── internal/
│   ├── cli/           Pure argument parsers and mode execution
│   ├── config/        Environment settings, state and run metadata files, and snapshot numbering
│   ├── mounttab/      /proc/self/mountinfo parser and FUSE unmount verification
│   ├── msb/           Argument builders, network rules, categories, and Runner interface
│   ├── pathsec/       Host path validation, blocklist checks, and mount naming
│   ├── persist/       Persistent login capture/streaming, read-only skills, and profile locking
│   └── vcsfuse/       Loopback FUSE filesystem that hides VCS directories and blocks xattrs
├── install.sh         Idempotent host check, build, and installation script
└── README.md          User and security documentation
```

## Run the Tests

```bash
go test -v -race ./...
```
