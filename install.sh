#!/usr/bin/env bash
# install.sh — Check host prerequisites, build agbox, and install the binary.
#
# This script verifies non-root execution, glibc >= 2.28, the Go toolchain,
# fusermount3, and microsandbox (msb). It then compiles agbox, installs the
# binary to ~/.local/bin/agbox, and runs 'agbox setup'.

set -euo pipefail

log()  { printf '[agbox-install] %s\n' "$*"; }
warn() { printf '[agbox-install] WARN: %s\n' "$*" >&2; }
die()  { printf '[agbox-install] ERROR: %s\n' "$*" >&2; exit 1; }

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
INSTALL_DIR="${AGBOX_INSTALL_DIR:-${HOME}/.local/bin}"

main() {
  if [[ "${EUID}" -eq 0 ]]; then
    die "Do not run install.sh as root. Run it as your normal user."
  fi

  if [[ -f /etc/os-release ]]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    if [[ "${ID:-}" != "debian" && "${ID:-}" != "ubuntu" && "${ID_LIKE:-}" != *debian* ]]; then
      warn "Host OS is ${ID:-unknown}. agbox targets Debian and Ubuntu."
    fi
  fi

  # 1. Check for glibc 2.28 or newer (required by microsandbox).
  local gl=""
  gl="$(getconf GNU_LIBC_VERSION 2>/dev/null | awk '{print $2}' || true)"
  [[ -n "${gl}" ]] || die "getconf is missing. Cannot check glibc version."
  if [[ "$(printf '%s\n' 2.28 "${gl}" | sort -V | head -1)" != "2.28" ]]; then
    die "glibc 2.28 or newer is required (found ${gl})."
  fi
  log "glibc ${gl}: OK"

  # 2. Check for the Go toolchain and fusermount3.
  if ! command -v go >/dev/null 2>&1; then
    die "Go toolchain is missing. Install it with: sudo apt-get install -y golang-go"
  fi
  log "Go toolchain: $(go version)"

  if ! command -v fusermount3 >/dev/null 2>&1 && ! command -v fusermount >/dev/null 2>&1; then
    warn "fusermount3 is missing. Install fuse3 for unprivileged FUSE mounts:"
    warn "  sudo apt-get install -y fuse3"
  fi

  # 3. Install microsandbox (msb) if it is missing.
  export PATH="${HOME}/.local/bin:${PATH}"
  if ! command -v msb >/dev/null 2>&1; then
    log "msb is missing. Running the official microsandbox installer..."
    curl -fsSL https://install.microsandbox.dev | sh || die "msb installation failed."
    command -v msb >/dev/null 2>&1 || die "msb is not on PATH (${HOME}/.local/bin)."
  fi
  log "msb: $(msb --version 2>/dev/null | head -1)"

  # 4. Build and install the agbox binary.
  log "Building agbox in ${SCRIPT_DIR}..."
  (
    cd "${SCRIPT_DIR}"
    go build -o "${SCRIPT_DIR}/agbox" ./cmd/agbox
  )
  mkdir -p "${INSTALL_DIR}"
  install -m 0755 "${SCRIPT_DIR}/agbox" "${INSTALL_DIR}/agbox"
  log "Installed binary: ${INSTALL_DIR}/agbox"

  # 5. Run host verification and the microVM smoke test.
  log "Running 'agbox setup'..."
  "${INSTALL_DIR}/agbox" setup

  if [[ ":${PATH}:" != *":${INSTALL_DIR}:"* ]]; then
    echo
    warn "${INSTALL_DIR} is not in your PATH. Add this line to ~/.bashrc or ~/.zshrc:"
    echo "  export PATH=\"${INSTALL_DIR}:\$PATH\""
  fi
}

main "$@"
