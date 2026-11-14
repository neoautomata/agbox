# AGENTS.md

This file defines the architecture, safe-by-default security invariants, upstream `msb` contracts, `test.sh` rules, coding conventions, and verification steps for `agbox`. Every change to this repository must preserve these rules.

______________________________________________________________________

## 1. Project Overview and Architecture

`agbox` runs AI coding agents (`opencode` and `agy`) inside isolated Linux `msb` (`libkrun` and `/dev/kvm`) microVMs. A single compiled binary (`cmd/agbox`) serves both the user CLI and the embedded FUSE filesystem daemon (`agbox __filter ...`).

### Repository and Documentation Map

| Path | Responsibility |
|---|---|
| `cmd/agbox` | Main entrypoint. Routes `__filter` directly to `vcsfuse` and forwards all other commands to `cli.Main`. |
| `internal/config` | Environment parsing, private state directories (`0700` and `0600`), snapshot numbering, and `run.meta` serialization. |
| `internal/pathsec` | Host path canonicalization, `$HOME` containment, credential and VCS blocklists, share modifier parsing, alias validation, and disjointness checks. |
| `internal/vcsfuse` | Loopback FUSE filter and multiplexed `/workspace` Workspace Hub (`openat2` confinement, VCS/hook masking, guest `1000:1000` ownership mapping, FD revocation, and `ws.sock` control server). |
| `internal/mounttab` | `/proc/self/mountinfo` parsing, `/proc/<pid>/cmdline` verification before signaling, and mount-verified directory cleanup. |
| `internal/msb` | `msb` argument builders, default-deny network rules, `--mount-disk` and volume inspection helpers, guest provisioning scripts, developer categories, and the `Runner` interface. |
| `internal/persist` | Zero-share `agbox auth` credential capture, verified read-only `$DATA_DIR/agents` binary cache, read-only `$DATA_DIR/skills` and `$DATA_DIR/rules`, and `flock`-guarded `--profile` volumes. |
| `internal/cli` | Pure flag parsers, subcommand dispatch, and orchestration over injected interfaces (`msb.Runner`, `mounttab.Controller`, `FilterStarter`, `HubStarter`). |
| `install.sh` | Idempotent prerequisite check, static build, and user binary installation script. |
| `test.sh` | Automated end-to-end verification harness covering static checks, race-tested unit tests, CLI security contracts, live FUSE mounts, and live microVM workflows. |
| `README.md` | High-level overview, chronological quick start, security properties table, and test overview. |
| `USER_GUIDE.md` | Step-by-step user workflows, package categories, full CLI reference, and environment variable documentation. |
| `AGENTS.md` | Fresh-context onboarding, security invariants, upstream `msb` contracts, `test.sh` authoring rules, and verification checklist. |

Prefer pure functions for parsing, validation, and command construction. Inject external side effects through interfaces instead of package-level globals so tests run deterministically without root or `/dev/kvm`.

### Installed Binary vs Source Tree

- `./install.sh` compiles `./cmd/agbox` and installs the binary to `~/.local/bin/agbox` (or `/usr/local/bin/agbox` with `--allow-root`, overridden by `AGBOX_INSTALL_DIR`).
- Editing Go source code in `/workspace/agbox` does not update `~/.local/bin/agbox` until `./install.sh` runs again.
- Non-disruptive `./test.sh` runs build and execute an isolated binary inside `$TEST_ROOT/bin/agbox` and leave the host installed binary untouched.
- Disruptive `./test.sh --disruptive` runs back up existing host binaries, data, and sandboxes, run `./install.sh`, verify the newly installed binary end to end, and restore the original host state on exit.

______________________________________________________________________

## 2. Safe-by-Default Security Rules (Non-Negotiable)

All defaults must choose the most restrictive behavior. Any privilege expansion requires an explicit CLI flag or documented environment variable.

### Fail Closed Everywhere

- Abort immediately if any validation, FUSE mount, socket bind, network rule, snapshot lookup, or secret transfer fails.
- Never fall back to weaker isolation (such as raw directory mounts when `AGBOX_MASK_VCS=strict` or unauthenticated sockets) on error.
- Clean up partial microVMs, mounts, and state directories on failure.
- Exit silently with a child status code only for direct interactive session exits (`--cmd` and TUI). Print `[agbox] ERROR: ...` with captured `msb` diagnostics for every setup, mount, or `msb` failure.

### Host Execution and State Permissions

- Reject host `root` execution (`euid == 0`) unless `--allow-root` or `AGBOX_ALLOW_ROOT=1` is set.
- Create host state directories with `config.EnsurePrivateDir` (`Lstat` symlink rejection and mode `0700`) and write metadata or secret files at mode `0600`.
- Before signaling any recorded FUSE PID, verify `/proc/<pid>/cmdline` matches `agbox __filter` (`mounttab.IsFilterCmdline`).
- Before calling `os.RemoveAll` on any run directory, unmount FUSE shares and verify zero active mounts remain in `/proc/self/mountinfo` (`mounttab.TeardownFilterDir`).

### Host Shares, Guest Ownership Mapping, and FUSE Confinement

- Mount zero host paths and start zero FUSE daemons when `agbox run` receives no share paths and `--share-hub` is not set.
- Reject conflicting CLI flags or share modifiers with an explicit error (for example, `--ro` with `--rw`, `:ro,rw`, `:mask,vcs`, or `:ro,vcs-hooks`). Never resolve conflicts silently.
- Validate every host share with `pathsec.ValidateShare` on `run`, `resume`, and `agbox share add`:
  - Resolve symlinks and reject missing paths, dangling symlinks, and control characters.
  - Enforce `$HOME` containment unless `AGBOX_ALLOW_OUTSIDE_HOME=1`.
  - Enforce the credential, agent-state, shell-config, `DATA_DIR`, `MSB_HOME`, VCS, and system blocklists (including parent directories of blocklisted paths).
  - Reject overlapping or nested host directory shares within the same sandbox (`pathsec.CheckDisjointHostPaths`).
  - Require `st_nlink == 1` on writable single-file shares.
- Keep all Workspace Hub shares inside `vcsfuse` (`openat2` with `RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS`, `nosuid,nodev`, regular files and intra-share relative symlinks only, `setuid`/`setgid` stripped, raw `ioctl` blocked, and non-`user.*` xattrs blocked):
  - Default VCS policy is `mask` (`VCSMask`), which hides and write-protects all 22 VCS admin directories and control files case-insensitively.
  - `:vcs` (`VCSAllow`) exposes VCS metadata for `git`/`jj` operations while write-protecting `.git/hooks`, `.git/**/hooks`, `.jj/**/hooks`, `.svn/**/hooks`, `_darcs/**/prefs`, `.pijul/**/hooks`, `.hg/hgrc`, and top-level VCS admin directory deletion/renaming with `EPERM`.
  - Writable VCS hooks require explicit `:vcs-hooks` (`--vcs-hooks`) on a writable share.
  - `vcsfuse` (`WorkspaceHub` and `StartSubprocess`) maps host file ownership to guest `agent` (`1000:1000`) in memory (`guestIDMap`). Because FUSE handles UID/GID translation internally, `/workspace` mounts into `msb` with `:rw,stat-virt=off` and triggers zero `user.msb.*` xattr probes or writes on host files.
- When `AGBOX_MASK_VCS=off` (`--no-mask`) mounts a host share directly without FUSE:
  - Read-only direct shares mount with `:ro,stat-virt=relaxed,uid=1000,gid=1000`.
  - Writable direct shares whose host UID/GID already matches `1000:1000`, or whose host filesystem lacks `user.*` extended attribute support, mount with `:rw,stat-virt=off`.
  - Other writable direct shares mount with `:rw,stat-virt=relaxed,host-perms=mirror,uid=1000,gid=1000`.
- Default `agbox share add` to **`ro,mask`** unless `--rw` (`:rw`) or `--vcs` (`:vcs`) is explicitly passed.
- Bind `$DATA_DIR/run/<id>/ws.sock` at mode `0600` inside a `0700` directory and verify peer UID via `SO_PEERCRED` on every connection.
- Fail `agbox share rm` and `agbox share set --ro` when open writable file handles exist unless `--force` is passed. Immediately revoke open descriptors (`ESTALE` on detach, `EROFS` on read-only downgrade) and flush guest VFS caches.

### Networking, Secrets, Read-Only Host Caches, and Profile Disks

- Keep `--net public` default-deny (`--net-default deny`) with explicit `allow@dns` (on group profiles) before `deny@host`, `deny@loopback`, `deny@private`, `deny@link-local`, `deny@multicast`, `deny@meta`, and cloud IMDS CIDR blocks (with IPv6 CIDRs bracketed as `[fe80::/10]` and `[fd00:ec2::254/128]`), all placed before `allow@public`.
- Keep `--serve` host port forwarding bound strictly to `127.0.0.1`, and pair published guest ports with `--net-rule allow:ingress@loopback:<proto>:<guestPort>` under default-deny policy.
- Enforce `--proto '=https' --tlsv1.2` on all `curl` downloads.
- Never pass API keys or auth tokens in CLI arguments or bake them into snapshots. Stream secrets over `stdin` into `0600` files inside the guest.
- Run `agbox auth` and `agbox update` inside disposable zero-share microVMs. `agbox update` must pass zero API keys and zero saved login tokens, verify ELF magic (`\x7fELF`), size bounds, `st_nlink == 1`, and SHA-256 digests in `manifest.json`.
- Mount `$DATA_DIR/skills`, `$DATA_DIR/rules`, and `$DATA_DIR/agents` read-only with `:ro,stat-virt=relaxed,uid=1000,gid=1000` and re-bind them read-only (`ro,bind`) inside the guest after rejecting symlinks via `Lstat`.
- Always pass an explicit `-u root` or `-u agent` flag to `msb exec`. Because `msb snap restore -u agent` sets the default `msb exec` user to `agent`, every privileged guest setup or cache-flush command must pass `-u root`.
- Guard each `--profile` `ext4` disk volume with an exclusive host `flock` (`profile.lock`), resolve the backing `disk.raw` file via `msb.ResolveVolumeDiskPath` (`msb volume inspect` with fallback to `<MSB_HOME>/volumes/<vol>/disk.raw`), and attach it with `--mount-disk <disk.raw>:/home/agent/.agbox-profile:rw,format=raw,fstype=ext4`.

### Base-Image Agent Defaults

- `create-base` installs `shellcheck` and `mdformat` in every base snapshot alongside `git`, `ripgrep`, `curl`, `less`, `procps`, and `sudo`.
- `create-base` initializes default guest agent configs inside `/home/agent` (without overwriting user customizations on `edit-base` or `--profile`):
  - `agy` (`/home/agent/.gemini/antigravity-cli/settings.json`): `"toolPermission": "always-proceed"` (`turbo`), `"queuedMessages": "send-immediately"`, `"allowNonWorkspaceAccess": true`, and `"trustedWorkspaces": ["/workspace"]`.
  - `opencode` (`/home/agent/.config/opencode/opencode.json`): `"permission": "allow"` (`general.followup` defaults to `"steer"`).

______________________________________________________________________

## 3. Upstream `msb` Integration Contracts and Pitfalls

Changes touching `internal/msb`, `internal/cli`, or `internal/vcsfuse` must respect these upstream `microsandbox` (`msb`) behaviors:

- **`msb exec` streaming and user selection:** Non-TTY `msb exec` suppresses child stdout and stderr unless `--stream` is passed. Passing `--stream` fails unless stdin is piped or `--no-stdin` is passed. Always pass `-u root` or `-u agent` explicitly because `msb snap restore -u agent` changes the default `msb exec` user to `agent`.
- **`stat-virt` modes on FUSE and host mounts:** `msb snap restore -v` defaults to `stat-virt=strict`, which probes writeable mount roots with `setxattr(..., "user.msb._probe", ...)` and aborts with `EROFS` on the synthetic read-only `/workspace` Workspace Hub root. Both `strict` and `relaxed` also write `user.msb.override_stat` xattrs onto host files during writes, and `msb` rejects combining `stat-virt=off` with `uid=` or `gid=`. Therefore `WorkspaceHub` (`/workspace`) must mount `:rw,stat-virt=off` without `uid=`/`gid=` while `vcsfuse` presents `1000:1000` in memory. Read-only host caches (`skills`, `rules`, `agents`) must mount `:ro,stat-virt=relaxed,uid=1000,gid=1000`.
- **Disk volumes vs directory volumes on `snap restore`:** `msb snap restore -v` hardcodes `VolumeKind::Directory` and rejects `--kind disk` named volumes (`agbox-profile-<name>`). Always attach profile disk volumes with `--mount-disk <disk.raw>:<guest>:rw,format=raw,fstype=ext4` instead of `-v`.
- **Firewall rule ordering and IPv6 syntax:** Keep `--net-default deny`, place `allow@dns` before `deny@host`, place all `deny@...` groups and CIDRs before `allow@public`, and wrap IPv6 CIDRs in square brackets (`[fe80::/10]`, `[fd00:ec2::254/128]`).
- **No nesting inside microVMs:** An agent running inside an `agbox` microVM (`libkrun`) does not have `/dev/kvm` access (and minimal containers may also lack `fusermount`). Inside such environments, run `./test.sh --skip-vm` (or `sudo ./test.sh --allow-root --skip-vm` when root is needed for direct FUSE mounts), and run KVM checks on the host.

______________________________________________________________________

## 4. `test.sh` Requirements, Modes, and Authoring Rules

Every edit to `test.sh` or any new feature that adds user-visible behavior must obey all test suite requirements below.

### Non-Disruptive Default Guarantee

- Running `./test.sh` or `./test.sh --full` MUST NOT modify, stop, overwrite, or delete any existing host binary (`~/.local/bin/agbox`), `AGBOX_DATA_DIR`, `MSB_HOME`, base snapshots, profile disk volumes, or running or suspended sandboxes.
- Check `99-verify-host-unchanged` snapshots host fingerprints (`BASELINE_DIR`) before tests start and fails the suite if any pre-existing host binary, `DATA_DIR` file, `MSB_HOME` state, sandbox list, snapshot list, or volume list changed.
- `test.sh` places `TEST_ROOT` under `~/.cache/agbox-e2e-<id>` (and removes `~/.cache` on exit if it created that parent directory) so temporary test shares satisfy `$HOME` containment without weakening `AGBOX_ALLOW_OUTSIDE_HOME`.
- When preparing isolated `RUNTIME_DATA_DIR` for VM checks, `test.sh` copies existing `run/<id>` state markers into `RUNTIME_DATA_DIR/run/` so `agbox run` orphan reaping never terminates pre-existing host sandboxes, probes whether `msb` honors an isolated `MSB_HOME`, and namespaces every temporary sandbox and profile with `SUITE_ID`.

### Execution Modes and Options

| Flag | Coverage and Host State Behavior |
|---|---|
| *(default)* | Non-disruptive quick suite: static/style (`01`), `go vet` (`02`), `go test -race` (`03`), binary build (`04`), CLI help/tamper (`05`–`07`), FUSE Workspace Hub (`08`), KVM preflight & isolated base (`09`–`11`), and core VM checks (`20`–`23`), plus host invariance check (`99`). |
| `--full` | Non-disruptive extended suite: adds egress firewall (`30`), open-FD revocation (`31`), profile `flock` contention & orphan reaping (`32`), authenticated `--serve` + `suspend`/`resume` (`33`), non-disruptive live `update` check when host config allows (`34`), and full isolated lifecycle (`40`). |
| `--disruptive` | Clean-slate host suite: backs up existing host state, runs `remove --yes`, `./install.sh`, `create-base`/`edit-base` (`10`–`12`), runs VM checks (`20`–`23`), runs `remove --yes`, and restores all backed-up host state before exit (`99`). |
| `--full --disruptive` | Maximum coverage: combines the clean-slate host lifecycle (`10`–`12`), core VM checks (`20`–`23`), extended VM checks (`30`–`40`), and clean backup restoration (`99`). |
| `--skip-vm` | Runs offline phases (`01`–`08`) without requiring `/dev/kvm` or `msb`. Safe inside containers and nested VMs. |
| `--filter <substr>` | Runs only checks whose `<id>-<slug>` name contains `<substr>` (plus prerequisite dependencies when needed). |
| `--log-dir <dir>` | Overrides the default `/tmp/agbox-test-logs-<timestamp>-<pid>` log directory. |
| `-v`, `--verbose` | Streams live check output to stdout in addition to per-check log files. |
| `--allow-root` | Passes `--allow-root` to `./install.sh` and `agbox` invocations when running under root (`euid == 0`). |

### Automation, Resilience, and Diagnostics Rules

- **Completely automated execution:** Every check must run unattended from start to finish with zero interactive prompts (`</dev/null`, `--yes`, and `with_timeout` or `with_timeout_stdin` bounds on every external command).
- **Continue on failure:** `run_check` executes each check in an isolated subshell (`set -Eeuo pipefail`) so an earlier failure still lets independent checks and `99-verify-host-unchanged` run, then prints a final `PASS` / `FAIL` / `SKIP` summary with exact log file paths.
- **Never swallow error diagnostics under `set -e`:** Use `run_capture <var> <cmd...>` instead of `out="$(cmd 2>&1)"` for expected-success commands so captured stderr/stdout prints before returning non-zero. Keep `err_out="$(... 2>&1)" || rc=$?` only for expected-failure assertions, and dump background daemon logs (such as `fd-run.log` or `lkp.log`) whenever `wait_for_sandbox_running` times out.
- **Guaranteed teardown on exit or signal:** Register `trap cleanup EXIT INT TERM HUP` to stop leftover `SUITE_ID` background processes, unmount active FUSE mounts via `/proc/self/mountinfo`, remove temporary test directories and `SUITE_ID` sandboxes/volumes, and restore any disruptive host backups.

### Check Numbering Layout

- `01`–`07`: Offline static, style, `go vet`, `go test -race`, binary builds, CLI flag/security tamper checks, and fake-`msb` CLI contracts.
- `08`: Live FUSE Workspace Hub mount, VCS masking, and `:ro` enforcement (`agbox __filter`).
- `09`–`12`: KVM/`msb` preflight and either non-disruptive isolated base bootstrap or disruptive clean-slate `remove`, `install.sh`, `create-base`, and `edit-base`.
- `20`–`23`: Default quick live microVM suite (ephemeral run/shares/secrets, persistence/profiles, `--persist`/`--remote-control`/dynamic shares/suspend/resume, `--serve --probe`).
- `30`–`34`, `40`: `--full` extended VM suite (egress firewall, open-FD revocation, profile lock & orphan reaping, password `--serve`, live `update`, and isolated end-to-end lifecycle).
- `99`: Post-suite host state invariance check (`verify-host-unchanged`).

______________________________________________________________________

## 5. Code and Documentation Style

- Write comments, CLI help text, error messages, and Markdown documentation in clear technical English inspired by ASD-STE100:
  - Use active voice and concrete verbs.
  - Keep sentences short and focused on one instruction or claim.
  - Keep noun clusters to three words or fewer where practical.
  - Avoid marketing adjectives and vague qualifiers.
  - **Do not use semicolons (`;`) in Go `//` comments, error strings, CLI help text, `README.md`, `USER_GUIDE.md`, or `AGENTS.md` prose.** Split compound clauses into separate sentences instead.
- Format all Go files with `gofmt`, format all Markdown files with `mdformat`, and keep bash scripts clean under `bash -n` and `shellcheck`.

______________________________________________________________________

## 6. Verification Checklist

Run these commands from `/workspace/agbox` before finishing any change:

```bash
gofmt -w ./cmd ./internal
mdformat README.md USER_GUIDE.md AGENTS.md
bash -n install.sh test.sh
go vet ./...
go test -count=1 -race ./...
go build -o /dev/null ./cmd/agbox
./test.sh --skip-vm
```

In containers without `fusermount`, also verify live FUSE checks with `sudo ./test.sh --allow-root --skip-vm`. On a host with KVM and `msb` available, run `./test.sh` (or `./test.sh --full --disruptive` before a release) and run `./install.sh` when updating the host installed binary.
