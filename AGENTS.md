# AGENTS.md

This file defines the architecture, safe-by-default security invariants, coding rules, and verification steps for `agbox`. Every change to this repository must preserve these rules.

______________________________________________________________________

## 1. Project Overview and Architecture

`agbox` runs AI coding agents (`opencode` and `agy`) inside isolated Linux `msb` (`libkrun` / `/dev/kvm`) microVMs. A single compiled binary (`cmd/agbox`) serves both the user CLI and the embedded FUSE filesystem daemon (`agbox __filter ...`).

### Package Boundaries

Keep each package focused on one responsibility with a minimal exported API:

- `cmd/agbox`: Entrypoint. Routes `__filter` directly to `vcsfuse` and forwards all other invocations to `cli.Main`.
- `internal/config`: Environment parsing, private state directories (`0700` / `0600`), snapshot numbering, and `run.meta` serialization.
- `internal/pathsec`: Host path canonicalization, `$HOME` containment, credential and VCS blocklists, share modifier parsing, alias validation, and disjointness checks.
- `internal/vcsfuse`: Loopback FUSE filter and multiplexed `/workspace` Workspace Hub (`openat2` confinement, VCS/hook masking, FD revocation, and `ws.sock` control server).
- `internal/mounttab`: `/proc/self/mountinfo` parsing, `/proc/<pid>/cmdline` verification before signaling, and mount-verified directory cleanup.
- `internal/msb`: `msb` argument builders, default-deny network rules, guest provisioning scripts, developer categories, and the `Runner` interface.
- `internal/persist`: Zero-share `agbox auth` credential capture, verified read-only `$DATA_DIR/agents` binary cache, read-only `$DATA_DIR/skills` and `$DATA_DIR/rules`, and `flock`-guarded `--profile` volumes.
- `internal/cli`: Pure flag parsers, subcommand dispatch, and orchestration over injected interfaces (`msb.Runner`, `mounttab.Controller`, `FilterStarter`, `HubStarter`).

Prefer pure functions for parsing, validation, and command construction. Inject external side effects through interfaces instead of package-level globals so tests run deterministically without root or `/dev/kvm`.

______________________________________________________________________

## 2. Safe-by-Default Security Rules (Non-Negotiable)

All defaults must choose the most restrictive behavior. Any privilege expansion requires an explicit CLI flag or documented environment variable.

### Fail Closed Everywhere

- Abort immediately if any validation, FUSE mount, socket bind, network rule, snapshot lookup, or secret transfer fails.
- Never fall back to weaker isolation (such as raw directory mounts when `AGBOX_MASK_VCS=strict` or unauthenticated sockets) on error.
- Clean up partial microVMs, mounts, and state directories on failure.

### Host Execution and State Permissions

- Reject host `root` execution (`euid == 0`) unless `--allow-root` or `AGBOX_ALLOW_ROOT=1` is set.
- Create host state directories with `config.EnsurePrivateDir` (`Lstat` symlink rejection + `0700`) and write metadata or secret files at `0600`.
- Before signaling any recorded FUSE PID, verify `/proc/<pid>/cmdline` matches `agbox __filter` (`mounttab.IsFilterCmdline`).
- Before calling `os.RemoveAll` on any run directory, unmount FUSE shares and verify zero active mounts remain in `/proc/self/mountinfo` (`mounttab.TeardownFilterDir`).

### Host Shares and FUSE Confinement

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
- Default `agbox share add` to **`ro,mask`** unless `--rw` (`:rw`) or `--vcs` (`:vcs`) is explicitly passed.
- Bind `$DATA_DIR/run/<id>/ws.sock` at mode `0600` inside a `0700` directory and verify peer UID via `SO_PEERCRED` on every connection.
- Fail `agbox share rm` and `agbox share set --ro` when open writable file handles exist unless `--force` is passed. Immediately revoke open descriptors (`ESTALE` on detach, `EROFS` on read-only downgrade) and flush guest VFS caches.

### Networking, Secrets, and Read-Only Host Caches

- Keep `--net public` default-deny (`--net-default deny`) with explicit `allow@dns` (on group profiles) before `deny@host`, `deny@loopback`, `deny@private`, `deny@link-local`, `deny@multicast`, `deny@meta`, and cloud IMDS CIDR blocks (with IPv6 CIDRs bracketed as `[fe80::/10]` and `[fd00:ec2::254/128]`), all placed before `allow@public`.
- Keep `--serve` host port forwarding bound strictly to `127.0.0.1`, and pair published guest ports with `--net-rule allow:ingress@loopback:<proto>:<guestPort>` under default-deny policy.
- Enforce `--proto '=https' --tlsv1.2` on all `curl` downloads.
- Never pass API keys or auth tokens in CLI arguments or bake them into snapshots. Stream secrets over `stdin` into `0600` files inside the guest.
- Run `agbox auth` and `agbox update` inside disposable zero-share microVMs. `agbox update` must also pass zero API keys and zero saved login tokens, verify ELF magic (`\x7fELF`), size bounds, `st_nlink == 1`, and SHA-256 digests in `manifest.json`.
- Mount `$DATA_DIR/skills`, `$DATA_DIR/rules`, and `$DATA_DIR/agents` read-only (`:ro`) from the host and re-bind them read-only (`ro,bind`) inside the guest after rejecting symlinks via `Lstat`.
- Guard each `--profile` `ext4` volume with an exclusive host `flock` (`profile.lock`).

### Base-Image Agent Defaults

- `create-base` initializes default guest agent configs inside `/home/agent` (without overwriting user customizations on `edit-base` or `--profile`):
  - `agy` (`/home/agent/.gemini/antigravity-cli/settings.json`): `"toolPermission": "always-proceed"` (`turbo`), `"queuedMessages": "send-immediately"`, `"allowNonWorkspaceAccess": true`, and `"trustedWorkspaces": ["/workspace"]`.
  - `opencode` (`/home/agent/.config/opencode/opencode.json`): `"permission": "allow"` (`general.followup` defaults to `"steer"`).

______________________________________________________________________

## 3. Code and Documentation Style

- Write comments, CLI help text, error messages, and Markdown documentation in clear technical English inspired by ASD-STE100:
  - Use active voice and concrete verbs.
  - Keep sentences short and focused on one instruction or claim.
  - Keep noun clusters to three words or fewer where practical.
  - Avoid marketing adjectives and vague qualifiers.
  - **Do not use semicolons (`;`) in Go `//` comments, error strings, CLI help text, `README.md`, or `AGENTS.md` prose.** Split compound clauses into separate sentences instead.
- Format all Go files with `gofmt` and all Markdown files with `mdformat`.

______________________________________________________________________

## 4. Verification Checklist

Run these commands from `/workspace/agbox` before finishing any change:

```bash
gofmt -w ./cmd ./internal
mdformat README.md AGENTS.md
go vet ./...
go test -count=1 -race ./...
go build -o /dev/null ./cmd/agbox
```
