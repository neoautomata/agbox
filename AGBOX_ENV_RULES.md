# Operating Inside an agbox Sandbox

## Guest Identity and Privileges

- You run as `agent` (`1000:1000`) inside a disposable Linux microVM with passwordless `sudo`.
- You control the guest OS. Use `sudo` to install packages, manage services, or run privileged tests.
- Installed system packages and files outside `/workspace` disappear on exit unless the host uses `--persist`.

## Workspace Shares and Permissions

- Host shares appear at `/workspace/<name>`. The `/workspace` root directory itself rejects direct file creation (`EROFS`).
- Assume `/workspace` masks `.git` and all other VCS directories and hooks by default (`ENOENT` or `EPERM`).
- When `git` commands fail, search and read files directly with `rg` instead of running `git init`.
- Stop and tell the user if `/workspace` returns `EROFS` (read-only share), `EPERM` (protected VCS path), or `ESTALE` (detached share).
- Ask the user to grant access from the host with `agbox share add` or `agbox share set --rw`.
- Never mount overlays or bind-mounts over `/workspace`. Never write project deliverables to `/tmp` or `/home/agent`.
- Keep symlinks relative and inside the same share. Host confinement rejects symlinks that escape a share root.

## Host Mounts, Hardware, and Network Boundaries

- Treat `/home/agent/.agbox-*` mounts, global skills, and global `AGENTS.md` files as host-managed mounts. Never unmount or shadow them.
- `/dev/kvm` and host `msb` commands do not exist inside the microVM. Do not run nested microVM workloads.
- Use `fusermount3` for unprivileged FUSE tests. Use `sudo` when `/dev/fuse` requires root access.
- Outbound DNS and public internet work by default unless the host starts the sandbox with `--no-net`.
- The default firewall blocks host, private LAN, link-local, multicast, and cloud metadata addresses. Stop and tell the user if a task needs `--net` changes.
- Never print, log, or copy credentials from `/home/agent/.agbox-keys.sh` or environment variables into `/workspace`.
