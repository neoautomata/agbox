# agbox

`agbox` runs AI coding agents ([OpenCode](https://opencode.ai) or [Google Antigravity CLI (`agy`)](https://antigravity.google)) inside ephemeral [microsandbox (`msb`)](https://microsandbox.dev) microVMs on Linux.

Each run boots a disposable microVM from a local base snapshot. `agbox` mounts only the host paths that you specify on the command line. An embedded FUSE filesystem hides version-control directories (`.git`, `.jj`, `.svn`, `.hg`, `.bzr`) from the guest. The guest runs the agent as non-root user `agent` (`1000:1000`) with passwordless `sudo`. When the session ends, `agbox` deletes the microVM.

---

## Why This Design Exists

1. **Hardware VM Isolation (`/dev/kvm` and `libkrun`):**
   Containers share the host Linux kernel. `agbox` runs each session inside a dedicated guest kernel. Guest root actions (`sudo apt-get install ...`) or kernel exploits stay inside the disposable microVM.
2. **Ephemeral Runs from Versioned Snapshots (`agbox:vN`):**
   `agbox create-base` builds the base environment once. `agbox edit-base` updates the base environment and creates a new snapshot version. `agbox run` restores a disposable `agbox-run-<pid>` microVM from the snapshot and deletes it on exit. No state from one run persists into the next run.
3. **Single Binary with Embedded FUSE Filter (`go-fuse/v2`):**
   A shared project directory normally exposes `.git/hooks` and `.git/config` to the guest. A compromised agent could write a malicious hook that executes on the host during `git status` or `git commit`. To prevent this, `agbox` embeds a loopback FUSE daemon (`/proc/self/exe __filter` with `Pdeathsig: SIGTERM`):
   - The filter hides `.git`, `.jj`, `.svn`, `.hg`, and `.bzr` (`ENOENT`).
   - The filter blocks creation, deletion, linking, or renaming of those names (`EPERM`) at every directory depth.
   - The filter blocks `setxattr` and `removexattr` on `security.*` and `system.posix_acl_*` (`EPERM`). This prevents the guest from setting file capabilities or changing host ACLs.
4. **Non-Root Guest User (`agent`, `1000:1000`) with Passwordless `sudo`:**
   The guest runs agents and commands as user `agent` (`1000:1000`). `agbox` mounts shared volumes with `uid=1000,gid=1000` so file ownership matches a standard single-user Linux workstation. Passwordless `sudo` allows the agent to install system packages inside the disposable microVM.
5. **Secret Delivery Over `stdin`:**
   `agbox` never stores host API keys in the base snapshot or on the host disk. `agbox` never passes secrets in command-line arguments, because `/proc/<pid>/cmdline` is readable by local processes. Instead, `agbox` streams secrets over `stdin` into `/home/agent/.agbox-keys.sh` (`0600`) inside the disposable microVM.

---

## Quick Start

### 1. Install and Verify the Host

Run the installer script as your normal user:

```bash
./install.sh
```

`install.sh` performs these steps:
1. Checks that you are not `root` and that `glibc` is version 2.28 or newer.
2. Checks for the `go` toolchain and `fusermount3`.
3. Installs `msb` if it is missing.
4. Compiles `agbox` and installs it to `~/.local/bin/agbox`.
5. Runs `agbox setup` to check `/dev/kvm`, run `msb doctor`, and test an Alpine microVM.

### 2. Create the Base Snapshot

Create a base snapshot with `opencode`, `antigravity` (`agy`), or `both`. You can also include developer categories (`core`, `go`, `rust`, `esphome`, `embedded-rust`, or `all`):

```bash
agbox create-base --add core,go,rust,esphome both
```

To add categories later (interactively or via flags), run `edit-base`:

```bash
# Interactive category picker
agbox edit-base

# List available categories and packages
agbox edit-base --list

# Install specific categories and create a new snapshot
agbox edit-base --add core,go,rust,esphome
```

### 3. Run an Agent on a Project Directory

Pass any run options before the agent name and shared paths:

```bash
# Run the OpenCode TUI with ~/projects/myapp mounted at /workspace/myapp
agbox run opencode ~/projects/myapp

# Run the Google Antigravity CLI (agy) with read-only mounts
agbox run --ro antigravity ~/projects/myapp ~/projects/shared-lib

# Run a single shell command inside a disposable microVM
agbox run --cmd "pytest -q" ~/projects/myapp

# Start the OpenCode web UI on 127.0.0.1:<port>
agbox run --serve --port 4096 ~/projects/myapp
```

---

## Base-Image Categories (`create-base` and `edit-base`)

| Category | Aliases | Installed Packages and Tools |
|---|---|---|
| `core` | `base`, `cli` | `build-essential`, `pkg-config`, `cmake`, `ninja-build`, `libffi-dev`, `libssl-dev`, `libsqlite3-dev`, `sqlite3`, `ca-certificates`, `curl`, `wget`, `git`, `htop`, `ncdu`, `net-tools`, `iproute2`, `dnsutils`, `rsync`, `unzip`, `zip`, `vim`, `jq`, `ripgrep`, `fd-find`, `less`, `procps`, `psmisc`, `lsof`, `strace`, `tree`, `file`, `openssh-client`, `python3`, `python3-pip`, `python3-setuptools`, `python3-venv`, `python3-wheel`, `pipx`, and `mdformat` (via `pipx`). |
| `go` | `golang` | Upstream Go toolchain in `/usr/local/go` (fallback: `golang-go`), `protobuf-compiler`, and `dlv`, `gopls`, `golangci-lint`, `goimports`, `staticcheck`, `govulncheck` in `/home/agent/go/bin`. |
| `rust` | `cargo`, `rustup` | `rustup` stable toolchain with `clippy`, `rustfmt`, `rust-analyzer`, `rust-src`, plus `clang`, `lld`, `pkg-config`, `libssl-dev`, `libudev-dev`, `libusb-1.0-0-dev`, `protobuf-compiler`, and `sccache`. |
| `esphome` | `esp` | `esphome`, `esptool`, and `platformio` (via `pipx`), plus `libudev-dev`, `libusb-1.0-0-dev`, `udev`, `usbutils`, `cmake`, `ninja-build`, `gperf`, `ccache`, `dfu-util`, `picocom`, and `minicom`. |
| `embedded-rust` | `esp-rust` | `riscv32imc-unknown-none-elf` and `riscv32imac-unknown-none-elf` Rust targets, plus `espflash`, `cargo-espflash`, and `ldproxy` (automatically includes `rust`). |
| `chrome` | `browser`, `chromium`, `devtools` | `chromium`, `chromium-driver`, `xvfb`, `fonts-liberation`, `fonts-noto-color-emoji`, `libnss3`, `libgbm1`, microVM headless flags (`--no-sandbox --disable-dev-shm-usage`), and `google-chrome` / `chrome` symlinks. |
| `hugo` | `static-site` | Hugo Extended binary (`/usr/local/bin/hugo`) with Sass/SCSS support. |
| `caddy` | `xcaddy` | Custom `caddy` binary built via `xcaddy` with `github.com/caddy-dns/cloudflare`, `github.com/greenpau/caddy-security`, `github.com/point-c/caddy/module@latest`, and `github.com/tailscale/caddy-tailscale` (automatically includes `go`). |

---

## CLI Reference

```text
agbox setup
    Check host prerequisites (glibc, msb, /dev/kvm, smoke test).

agbox create-base [--force] [--add <categories>] <opencode|antigravity|both>
    Create the base microVM and save snapshot agbox:vN.

agbox edit-base [--add <categories>] [--list] [--shell] [--cmd "shell"] [--no-snap]
    Start the base microVM, install developer categories (core, go, rust,
    esphome, embedded-rust, chrome, hugo, caddy, or all) or run custom
    updates, and save snapshot agbox:v<N+1>.

agbox run [options] [opencode|antigravity] [paths...]
    Restore an ephemeral microVM from the base snapshot and mount paths.
    Delete the microVM and unmount FUSE shares on exit.
    Options (must precede paths):
      --ro                 Mount shared paths read-only
      --mask-vcs           Require the FUSE filter for directory shares
      --no-mask            Disable the FUSE filter (.git is visible to guest)
      --serve              Run 'opencode serve' and bind the web UI on 127.0.0.1
      --port N             Use fixed loopback TCP port N for --serve
      --probe              With --serve: wait for the web UI, then exit
      --cmd "shell"        Run one command in the ephemeral microVM and exit
      --no-net             Disable guest network access
      --net SPEC           Set network profile (public|none|private|host|all) or rule
      --cpus N             Override vCPU count for this run
      --memory SIZE        Override RAM size for this run (for example, 4G)

agbox stop <agbox-run-pid>
    Stop a detached --serve microVM and unmount its FUSE shares.

agbox remove [--yes]
    Delete all agbox microVMs, snapshots, FUSE mounts, and ~/.local/share/agbox.

agbox status
    Show base configuration, microVMs, snapshots, and disk usage.
```

---

## Configuration (Environment Variables)

| Variable | Default | Purpose |
|---|---|---|
| `AGBOX_DATA_DIR` | `~/.local/share/agbox` | Host directory for `config` and per-run FUSE mounts (`run/<pid>`). |
| `AGBOX_CPUS` | `2` | Default vCPU count for `create-base`. |
| `AGBOX_MEMORY` | `2G` | Default guest RAM size for `create-base`. |
| `AGBOX_ROOT_DISK` | `8G` | Default guest root disk size for `create-base`. |
| `AGBOX_MASK_VCS` | `auto` | FUSE filter policy for directory shares: `auto`, `strict`, or `off`. |
| `AGBOX_ALLOW_OUTSIDE_HOME` | `0` | Set to `1` to allow shares outside `$HOME`. Blocklists still apply. |
| `AGBOX_OPENCODE_VERSION` | `latest` | npm version or tag for `opencode-ai` during `create-base`. |
| `AGBOX_AGY_INSTALLER_URL` | `https://antigravity.google/cli/install.sh` | Installer URL for `agy` during `create-base`. |
| `OPENCODE_SERVER_PASSWORD` | *(unset)* | Optional HTTP Basic Auth password for `agbox run --serve`. |
| `OPENCODE_SERVER_USERNAME` | `opencode` | Optional HTTP Basic Auth username for `agbox run --serve`. |

---

## Security Rules

### Host Path Validation (`internal/pathsec`)
`pathsec.ValidateShare` checks every path before `agbox` mounts it into a microVM:
1. **Symlink Resolution:** `filepath.EvalSymlinks` resolves all symlinks. Missing paths and dangling symlinks fail validation.
2. **Home Directory Containment:** Paths outside `$HOME` fail validation unless you set `AGBOX_ALLOW_OUTSIDE_HOME=1`.
3. **Blocklist Check:** Sensitive paths (`~/.ssh`, `~/.gnupg`, `~/.aws`, `~/.config/gcloud`, `~/.config/gh`, `~/.gemini`, `~/.antigravity`, `~/.claude`, `~/.kube`, `~/.docker`, shell startup files, and system paths `/etc`, `/proc`, `/sys`, `/dev`, `/root`) fail validation. Any parent directory of a blocklisted path (such as `$HOME` itself) also fails validation. If a blocklisted file is a symlink, `agbox` also blocks the symlink target and its parent directories.
4. **Delimiter Check:** Paths that contain `:`, `,`, or newline characters fail validation. This prevents option injection into the `msb -v <src>:<dst>:<opts>` flag.
5. **VCS and Hardlink Check:** Sharing `.git`, `.jj`, `.svn`, `.hg`, or `.bzr` directly (or sharing a single file inside them) fails validation. Writable single-file shares must have a hardlink count of `1` (`st_nlink == 1`). This prevents the guest from modifying a file that has a second hardlink in an unshared directory.

### Safe Mount Inspection and Unmount (`internal/mounttab`)
- `mounttab` reads `/proc/self/mountinfo` and decodes octal escape sequences (`\040`, `\134`). It does not rely on `os.Stat`. If a FUSE daemon crashes, `stat(2)` fails with `ENOTCONN` even though the kernel mount remains active.
- `mounttab.TeardownFilterDir` sends `SIGTERM` to recorded FUSE daemon PIDs and unmounts each mountpoint with `fusermount3 -u`. If a mount remains active, it sends `SIGKILL` and runs a lazy unmount (`fusermount3 -u -z` or `MNT_DETACH`).
- `mounttab.TeardownFilterDir` checks `/proc/self/mountinfo` again before it calls `os.RemoveAll`. It never deletes a directory that still contains an active mountpoint.

---

## Package Structure

```text
agbox/
├── cmd/agbox/         Main entrypoint (routes __filter to vcsfuse and commands to cli)
├── internal/
│   ├── cli/           Pure argument parsers and mode execution
│   ├── config/        Environment settings, state file parser, and snapshot numbering
│   ├── mounttab/      /proc/self/mountinfo parser and safe FUSE unmount logic
│   ├── msb/           Argument builders, output parsers, and Runner interface for msb
│   ├── pathsec/       Host path validation, blocklist checks, and mount naming
│   └── vcsfuse/       Loopback FUSE filesystem that hides VCS directories and blocks xattrs
├── install.sh         Host check, build, and installation script
└── README.md          User and architecture documentation
```

## Run the Tests

```bash
go test -v -race ./...
```
