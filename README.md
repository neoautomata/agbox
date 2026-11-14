# agbox

`agbox` runs AI coding agents ([OpenCode](https://opencode.ai) or [Google Antigravity CLI (`agy`)](https://antigravity.google)) inside disposable [microsandbox (`msb`)](https://microsandbox.dev) microVMs on Linux.

Each run boots an isolated microVM from a local base snapshot. `agbox` mounts only the host paths that you pass on the command line. By default, `agbox` masks all version-control entries through FUSE and blocks local, private, multicast, and cloud-config IPs. If any check or setup step fails, `agbox` stops immediately and deletes partial state.

For detailed workflows, category packages, per-share options, conversation persistence, web/remote access, full CLI flags, and environment variables, see the **[User Guide (`USER_GUIDE.md`)](USER_GUIDE.md)**.

______________________________________________________________________

## Quick Start

### 1. Install and Check the Host

Run the installer script as your normal user (or pass `--allow-root` when running as `root`):

```bash
./install.sh
```

`install.sh` checks `glibc` (`>= 2.28`), `go`, and `fusermount3`/`fusermount`, downloads `msb` over HTTPS (TLS 1.2+) if missing, installs `agbox` to `~/.local/bin/agbox` (`/usr/local/bin/agbox` for `root`), and runs `agbox setup` to verify `/dev/kvm`, FUSE mounts, `msb doctor`, and an offline Alpine microVM.

### 2. Create the Base Snapshot

Build the base snapshot with `opencode`, `antigravity` (`agy`), or `both`, optionally adding developer toolchains (`core`, `go`, `rust`, `esphome`, `embedded-rust`, `chrome`, `hugo`, `caddy`, or `all`):

```bash
agbox create-base --add core,go,rust,esphome both
```

Inside the isolated microVM, `create-base` installs `shellcheck`, `mdformat`, and baseline CLI utilities (`git`, `ripgrep`, `curl`, `less`, `procps`, and `sudo`) in every snapshot. It also sets default unattended configs (`"toolPermission": "always-proceed"` and `"queuedMessages": "send-immediately"` for `agy`, and `"permission": "allow"` for `opencode`). Run `agbox edit-base --list` to inspect categories.

### 3. Authenticate

Sign in once inside a zero-share microVM with `agbox auth`, or export API keys in your host shell:

```bash
# Option A: Persistent OAuth sign-in stored at 0600 in $DATA_DIR/auth
agbox auth antigravity
agbox auth opencode

# Option B: Per-run API keys streamed over stdin (never placed in CLI args)
export ANTHROPIC_API_KEY="sk-ant-..."
export GEMINI_API_KEY="AIza..."
```

### 4. (Optional) Add Global Skills and Rules

Mount read-only global skills and standing Markdown instructions across all runs:

```bash
agbox skills add ~/my-skills/code-review
agbox rules add ~/my-rules/engineering-standards.md
```

### 5. Run and Manage Sandboxes

Place all option flags before the agent name and shared paths:

```bash
# Run interactive OpenCode in a disposable microVM
agbox run opencode ~/projects/myapp

# Mix read-only, writable, and VCS-enabled shares in one microVM
agbox run antigravity ~/projects/docs:ro ~/projects/lib:rw ~/projects/app:rw,vcs

# Persist a named sandbox across exits and continue the latest session
agbox run --persist --name myapp opencode ~/projects/myapp
agbox run --persist --name myapp -c opencode ~/projects/myapp

# Run one shell command inside an ephemeral microVM
agbox run --cmd "go test ./..." ~/projects/myapp

# Expose OpenCode web UI on 127.0.0.1:4096 or Antigravity Remote Control in the background
agbox run --name web --serve --port 4096 ~/projects/myapp
agbox run --name rc -d --remote-control ~/projects/myapp

# Inspect status, suspend/resume to save host resources, or delete sandboxes
agbox status
agbox suspend agbox-myapp
agbox resume agbox-myapp
agbox stop agbox-myapp
```

See [USER_GUIDE.md](USER_GUIDE.md) for live `/workspace` share management (`agbox share`), `ext4` conversation profiles (`--profile`), fast binary updates (`agbox update`), `edit-base`, the full CLI reference, and environment variables.

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
   The guest runs agents and commands as user `agent` (`1000:1000`). The FUSE Workspace Hub presents shared workspace files as `1000:1000` inside `/workspace` (`stat-virt=off`), avoiding host extended attribute writes. Read-only host caches (`skills`, `rules`, and `agents`) mount with `uid=1000,gid=1000` (`stat-virt=relaxed`). Passwordless `sudo` lets the agent install packages inside the microVM.
1. **Secret Delivery Over `stdin`:**
   `agbox` never stores host API keys in the base snapshot or on the host disk. `agbox` never passes secrets in CLI arguments where local processes can read `/proc/<pid>/cmdline`. Instead, `agbox` streams secrets over `stdin` into `/home/agent/.agbox-keys.sh` (`0600`) inside the microVM.

______________________________________________________________________

## Secure-by-Default Networking and Shared Directories

`agbox` enforces strict network and filesystem isolation by default. If any security check fails, `agbox` stops immediately instead of running with reduced protection.

### Default Network Policy

By default, `agbox create-base` and `agbox run` configure `msb` with a default-deny firewall (`--net public`):

- **Default action:** `--net-default deny` drops unmatched outbound and inbound traffic.
- **Guest DNS on port 53:** `--net-rule allow@dns` lets the guest resolve domain names before `deny@host` blocks all other host gateway ports.
- **Blocked groups:** `deny@host`, `deny@loopback`, `deny@private`, `deny@link-local`, `deny@multicast`, and `deny@meta` block host services, loopback, RFC1918 private LANs (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), CGNAT (`100.64.0.0/10`), IPv6 ULA (`fc00::/7`), link-local ranges, multicast (`224.0.0.0/4`, `ff00::/8`), and cloud metadata endpoints.
- **Blocked CIDRs:** Explicit rules also block `0.0.0.0/8`, `169.254.0.0/16`, `[fe80::/10]`, `240.0.0.0/4` (including `255.255.255.255`), Azure WireServer (`168.63.129.16/32`), Alibaba Cloud IMDS (`100.100.100.200/32`), and AWS IPv6 IMDS (`[fd00:ec2::254/128]`) before any `allow@...` rule.
- **Allowed ranges:** `--net-rule allow@public` permits outbound public internet traffic for model APIs and package mirrors. When `--serve` publishes a loopback port, `agbox` appends `--net-rule allow:ingress@loopback:tcp:3000`.

### Default Shared Directory Policy

`agbox` never mounts host paths or starts a host FUSE daemon unless you pass explicit paths or `--share-hub` to `agbox run`:

1. **Multiplexed FUSE Workspace Hub and Strict VCS Masking (`AGBOX_MASK_VCS=strict`):**
   Shared paths mount through an embedded FUSE Workspace Hub (`nosuid,nodev`) at `/workspace/<name>`. By default (`:mask`), the filter hides and write-protects all 22 VCS directories and control files (`.git*`, `.jj`, `.sl`, `.svn`, `.hg*`, `.bzr*`, `_darcs`, `.pijul`, Fossil, and `.cvsignore`) case-insensitively at every depth. All host file operations use `openat2` (`RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS`). The filter allows regular files, directories, and intra-share relative symlinks that do not reference masked VCS names. It blocks out-of-tree symlinks, device/FIFO/socket nodes, `setuid`/`setgid` bits, cross-UID ownership changes, host `ioctl` calls, and non-`user.*` extended attributes. If the FUSE mount fails, `agbox` aborts immediately.
1. **Hook Protection on VCS-Enabled Shares (`:vcs` vs `:vcs-hooks`):**
   When you opt into VCS access on a share with `:vcs` (or `--vcs`), the FUSE filter still keeps the share inside `openat2` confinement and write-protects executable VCS hook and config paths (`.git/hooks`, `.git/**/hooks`, `.jj/**/hooks`, `.svn/**/hooks`, `_darcs/**/prefs`, `.pijul/**/hooks`, and `.hg/hgrc`) with `EPERM`. Writable hooks require explicit `:vcs-hooks` (or `--vcs-hooks`).
1. **Path Canonicalization, Disjointness, and Containment (`internal/pathsec`):**
   `pathsec.ValidateShare` resolves all symlinks before mounting. Missing paths, dangling symlinks, overlapping or nested host directories, conflicting modifiers, and paths containing `:`, `,`, or control characters fail validation. Paths outside `$HOME` fail validation unless you set `AGBOX_ALLOW_OUTSIDE_HOME=1`.
1. **VCS, Credential, and System Blocklist:**
   `agbox` rejects direct shares of any VCS directory, VCS subdirectory (such as `.git/hooks` or `.jj/repo`), or VCS control file. `agbox` also blocks SSH keys (`~/.ssh`), cloud and VCS credentials (`~/.aws`, `~/.config/gcloud`, `~/.config/gh`, `~/.config/hub`, `~/.config/glab`, `~/.gitconfig`, `~/.git-credentials`, `~/.jjconfig.toml`, `~/.config/jj`, `~/.hgrc`, `~/.subversion`, `~/.bazaar`), agent state (`~/.gemini`, `~/.antigravity`, `~/.claude`, `~/.config/opencode`), shell and `direnv` configs, `DATA_DIR` (rejecting symlinks), and system paths (`/etc`, `/proc`, `/sys`, `/dev`). Parent directories of blocklisted paths (including `$HOME` itself) also fail validation.
1. **Single-File Hardlink Check:**
   Writable single-file shares must be regular files with a hardlink count of `1` (`st_nlink == 1`) so the guest cannot alter a hardlinked file outside the share. Read-only shares (`:ro` or `--ro`) allow multiple hardlinks.

______________________________________________________________________

## Mount Inspection and Cleanup (`internal/mounttab`)

- `mounttab` reads `/proc/self/mountinfo` and decodes octal escape sequences (`\040`, `\134`). It does not rely on `os.Stat` because a crashed FUSE daemon returns `ENOTCONN` while the mount stays active.
- `mounttab.OSController` checks `/proc/<pid>/cmdline` for `agbox __filter` before it signals a recorded PID. This check prevents signaling an unrelated host process after PID reuse.
- `mounttab.UnmountFilterDir` sends `SIGTERM` to verified FUSE daemons (`ws.pid` and `m*.pid`) and unmounts each mountpoint with `fusermount3 -u` (or `fusermount -u`). If a mount stays active, it sends `SIGKILL`, runs a lazy unmount, and checks `/proc/self/mountinfo` again.
- `mounttab.TeardownFilterDir` calls `UnmountFilterDir` first and refuses to run `os.RemoveAll` if any mountpoint remains active.
- `ReapOrphanRuns` and `ReapStaleFilterDirs` delete crashed run sandboxes while preserving running detached sessions and stopped suspended sessions.

______________________________________________________________________

## Security Properties Reference

| Security Property | Enforcement Boundary | Guarantee |
|---|---|---|
| Hardware microVM isolation | `msb` (`/dev/kvm`, `libkrun`) | Each session boots its own guest kernel. Guest root commands do not affect the host kernel. |
| Non-root host execution | `cli.CheckRootExecution`, `install.sh` | Rejects `euid == 0` unless `--allow-root` or `AGBOX_ALLOW_ROOT=1` is set. |
| Private state directories | `config.EnsurePrivateDir`, `vcsfuse` | Rejects symlinks via `Lstat`, sets directory mode `0700`, and writes metadata files with mode `0600`. |
| Boundary input validation | `config.FromLookup`, `cli`, `persist` | Rejects invalid CPU/RAM/disk specs, conflicting share flags, control characters, unsafe session IDs, malformed `--net-rule` tokens, and non-`https://` installer URLs. |
| Explicit opt-in host shares | `cli.Run`, `pathsec.ValidateShare` | Mounts zero host paths unless passed on the CLI. Resolves symlinks, rejects overlapping host trees, and restricts shares to `$HOME` by default. |
| Credential and system blocklist | `pathsec.DefaultBlocklist` | Blocks SSH, cloud, agent, VCS, shell, `direnv`, `DATA_DIR`, `MSB_HOME`, and system paths (plus parent directories and symlink targets). |
| Direct VCS share prohibition | `pathsec.ContainsVCSComponent` | Blocks direct shares of any VCS directory, VCS subdirectory, or VCS working-tree file (case-insensitive). |
| Single-file hardlink check | `pathsec.ValidateShare` | Requires regular files and `st_nlink == 1` on writable single-file shares. |
| Case-insensitive VCS masking | `vcsfuse.FilteredNode` | Hides all 22 VCS directories and control files (`ENOENT`) and blocks all writes to those names (`EPERM`) at every depth by default (`:mask`). |
| VCS hook write-protection | `vcsfuse.shareSlot` (`:vcs`) | Write-protects `.git/hooks`, `.git/**/hooks`, `.jj/**/hooks`, `.svn/**/hooks`, `_darcs/**/prefs`, `.pijul/**/hooks`, and `.hg/hgrc` (`EPERM`) unless `:vcs-hooks` is set. |
| Dynamic share control & FD revocation | `vcsfuse.WorkspaceHub`, `cli.Share` | Restricts `ws.sock` (`0600`) to the host UID via `SO_PEERCRED`, defaults `share add` to `ro,mask`, blocks busy detach/downgrade without `--force`, and revokes open descriptors (`ESTALE` / `EROFS`). |
| Root-pinned `openat2` resolution | `vcsfuse.pinnedRoot` | Resolves every FUSE operation with `RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS` and rejects detached child inodes (`ENOENT`). |
| Intra-share symlink confinement | `vcsfuse.ValidateSymlinkTarget` | Blocks absolute targets, `..` root escapes, and masked VCS targets on both `Symlink` and `Readlink` (`EPERM`). |
| Special-file and `ioctl` blocking | `vcsfuse` (`safeFile`, `Mknod`, `Open`) | Mounts with `nosuid,nodev`, allows `S_IFREG` only, and hides `PassthroughFd` and `Ioctl` on file and directory handles. |
| Privilege-bit and `chown` blocking | `vcsfuse` (`sanitizeCreateMode`, `Setattr`) | Strips `setuid`/`setgid` on creation and rejects `setuid`/`setgid` modes and cross-UID/GID `chown` (`EPERM`). |
| Extended attribute isolation | `vcsfuse.IsProtectedXattr` | Allows `user.<name>` attributes only and blocks `security.*`, `system.*`, and `trusted.*` (`EPERM` / `ENODATA`). |
| Default-deny public-only network | `msb.BuildNetArgs` | Places `allow@dns`, `deny@host`, `deny@loopback`, `deny@private`, `deny@link-local`, `deny@multicast`, `deny@meta`, and cloud-config CIDRs (including bracketed IPv6 ranges) before `allow@public`. |
| Loopback-only web server binding | `cli.Run` (`--serve`), `msb.BuildRestoreArgs` | Binds host TCP forwarding strictly on `127.0.0.1:<port>` and allows `allow:ingress@loopback:tcp:3000`. |
| HTTPS and TLS 1.2+ downloads | `install.sh`, `cli`, `msb`, `persist` | Enforces `--proto '=https' --tlsv1.2` on all `curl` installer downloads. |
| Secret streaming over `stdin` | `msb.FormatEnvExports`, `cli.pushKeys` | Quotes values for POSIX `sh` and streams keys over `stdin` into `/home/agent/.agbox-keys.sh` (`0600`). Never passes secrets in CLI arguments. |
| Allowlisted `agbox auth` credentials | `persist`, `cli.Auth`, `cli.pushAuth` | Captures only allowlisted login files (max 64 KiB, `Lstat` no-symlink check) from a zero-share microVM, stores them at `0600` in `$DATA_DIR/auth`, and streams them over `stdin`. |
| Verified read-only agent cache | `persist.InspectAgentsDir`, `cli.Update` | Fetches updates in a zero-share, zero-secret microVM, verifies ELF magic, SHA-256 digests, and `st_nlink == 1` in `$DATA_DIR/agents`, and enforces `:ro` + guest `ro,bind` mounts. |
| Read-only global skills | `persist.InspectSkillsDir`, `cli` | Rejects symlinks and special files in `$DATA_DIR/skills`, mounts the volume read-only (`:ro`), and enforces `ro,bind` mounts inside the guest. |
| Read-only global rules | `persist.InspectRulesDir`, `cli` | Rejects symlinks, subdirectories, non-`.md` entries, NUL bytes, and files over 64 KiB in `$DATA_DIR/rules`, mounts the volume read-only (`:ro`), and enforces `ro,bind` mounts inside the guest. |
| Isolated `ext4` conversation profiles | `persist.LockProfile`, `cli` | Guards each `agbox-profile-<name>` disk volume with an exclusive host `flock` and bind-mounts only conversation directories while keeping global skills, rules, hooks, plugins, and `mcp_config.json` outside the profile disk. |
| PID-reuse signal protection | `mounttab.IsFilterCmdline` | Verifies `/proc/<pid>/cmdline` has `argv[1] == "__filter"` before sending `SIGTERM` or `SIGKILL`. |
| Mount-verified directory deletion | `mounttab.TeardownFilterDir` | Verifies zero active mounts in `/proc/self/mountinfo` before running `os.RemoveAll`. |
| Tamper-evident `resume` & fail-closed setup | `cli` (`Setup`, `EditBase`, `Run`, `Resume`), `install.sh` | Checks FUSE, KVM, and an offline smoke microVM in `setup`, re-validates shares, cached agents, skills, rules, profiles, and strict masking on `resume`, and aborts on any error. |

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
│   ├── pathsec/       Host path validation, share spec parsing, blocklists, and alias checks
│   ├── persist/       Persistent login capture, verified agent cache, skills, rules, and profiles
│   └── vcsfuse/       Multiplexed FUSE Workspace Hub, VCS/hook filter, and control socket
├── install.sh         Idempotent host check, build, and installation script
├── test.sh            Automated end-to-end verification harness
├── AGENTS.md          Architecture, safe-by-default rules, and verification guide for agents
├── USER_GUIDE.md      Step-by-step user workflows, categories, CLI reference, and environment variables
└── README.md          Overview, chronological quick start, and security architecture
```

## Run the Tests

```bash
go test -v -race ./...
```

Run the automated verification harness (`./test.sh`) from the repository root. By default, `./test.sh` runs completely unattended, leaves existing binaries, images, sandboxes, and configuration untouched (verified by `99-verify-host-unchanged`), continues testing remaining checks if an error occurs, and writes per-check logs to `/tmp/agbox-test-logs-*`:

- `./test.sh`: Quick non-disruptive run covering static checks, race-tested unit tests, FUSE Workspace Hub, and core microVM workflows
- `./test.sh --full`: Extended non-disruptive run adding firewall, FD revocation, lock contention, authenticated `--serve`, live update, and isolated lifecycle checks
- `./test.sh --skip-vm`: Offline unit, style, CLI security contract, fake-`msb` validation, and FUSE Workspace Hub checks for environments without KVM or `msb`
- `./test.sh --disruptive`: Clean-slate test that backs up and restores the installed `agbox` binary (`ORIG_INSTALL_BIN`) while running `agbox remove --yes` before and after testing to verify a fresh `./install.sh`, `setup`, and `create-base` lifecycle
- `./test.sh --full --disruptive`: Maximum end-to-end coverage combining the extended suite with the clean-slate host lifecycle

Prerequisites: Go, `msb`, `/dev/kvm`, and FUSE for full runs (only Go and FUSE, or root for direct FUSE mounts without `fusermount`, for `--skip-vm`). Run `./test.sh --help` for filtering, logging, and root options, and see [`AGENTS.md`](AGENTS.md) for `test.sh` authoring rules and integration contracts.
