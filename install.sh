#!/usr/bin/env bash
# install.sh - Check host prerequisites, build agbox, and install the binary.
#
# This script checks user permissions, glibc >= 2.28, Go, fusermount3, and msb.
# It builds a static agbox binary, installs default rules, and runs 'agbox setup'.

set -euo pipefail

log()  { printf '[agbox-install] %s\n' "$*"; }
warn() { printf '[agbox-install] WARN: %s\n' "$*" >&2; }
die()  { printf '[agbox-install] ERROR: %s\n' "$*" >&2; exit 1; }

usage() {
  cat <<'EOF'
Usage: ./install.sh [--allow-root] [--skip-setup] [--help]

Options:
  --allow-root   Allow installation as the root user (or set AGBOX_ALLOW_ROOT=1).
  --skip-setup   Skip 'agbox setup' during installation.
  -h, --help     Show this help message and exit.
EOF
}

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
BUILD_TMP_DIR=""
MSB_INSTALLER_TMP=""
INSTALL_STAGE_BIN=""

cleanup() {
  if [[ -n "${MSB_INSTALLER_TMP}" && -e "${MSB_INSTALLER_TMP}" ]]; then
    rm -f "${MSB_INSTALLER_TMP}"
  fi
  MSB_INSTALLER_TMP=""
  if [[ -n "${INSTALL_STAGE_BIN}" && -e "${INSTALL_STAGE_BIN}" ]]; then
    rm -f "${INSTALL_STAGE_BIN}"
  fi
  INSTALL_STAGE_BIN=""
  if [[ -n "${BUILD_TMP_DIR}" && -d "${BUILD_TMP_DIR}" ]]; then
    rm -rf "${BUILD_TMP_DIR}"
  fi
  BUILD_TMP_DIR=""
}
trap cleanup EXIT
trap 'cleanup; exit 130' INT TERM HUP

main() {
  local allow_root=0
  if [[ "${AGBOX_ALLOW_ROOT:-0}" == "1" ]]; then
    allow_root=1
  fi
  local skip_setup=0

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --allow-root)
        allow_root=1
        shift
        ;;
      --skip-setup)
        skip_setup=1
        shift
        ;;
      -h|--help)
        usage
        exit 0
        ;;
      *)
        die "Unknown option: $1 (run './install.sh --help')"
        ;;
    esac
  done

  local euid=""
  euid="$(id -u)"
  if [[ "${euid}" -eq 0 ]]; then
    if [[ "${allow_root}" -ne 1 ]]; then
      die "Do not run install.sh as root. Pass --allow-root or set AGBOX_ALLOW_ROOT=1 to override."
    fi
    warn "Root mode is active."
  fi

  if [[ -z "${HOME:-}" ]]; then
    HOME="$(getent passwd "${euid}" | cut -d: -f6 || true)"
    [[ -n "${HOME}" ]] || die "HOME is not set."
    export HOME
  fi

  local install_dir=""
  if [[ -n "${AGBOX_INSTALL_DIR:-}" ]]; then
    install_dir="${AGBOX_INSTALL_DIR}"
  elif [[ "${euid}" -eq 0 ]]; then
    install_dir="/usr/local/bin"
  else
    install_dir="${HOME}/.local/bin"
  fi
  while [[ "${install_dir}" != "/" && "${install_dir}" == */ ]]; do
    install_dir="${install_dir%/}"
  done

  if [[ -f /etc/os-release ]]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    if [[ "${ID:-}" != "debian" && "${ID:-}" != "ubuntu" && "${ID_LIKE:-}" != *debian* ]]; then
      warn "Host OS is ${ID:-unknown}. agbox targets Debian and Ubuntu."
    fi
  fi

  # 1. Check glibc 2.28 or newer (required by microsandbox).
  command -v getconf >/dev/null 2>&1 || die "getconf is missing. Cannot check glibc version."
  local gl=""
  gl="$(getconf GNU_LIBC_VERSION 2>/dev/null | awk '{print $2}' || true)"
  [[ -n "${gl}" ]] || die "install.sh requires GNU libc 2.28 or newer (getconf reports no glibc version)."
  if [[ "$(printf '%s\n' 2.28 "${gl}" | sort -V | head -1)" != "2.28" ]]; then
    die "install.sh requires glibc 2.28 or newer (found ${gl})."
  fi
  log "glibc ${gl}: OK"

  # 2. Check the Go toolchain and FUSE helper binary.
  if ! command -v go >/dev/null 2>&1; then
    die "Go toolchain is missing. Install it with: apt-get install -y golang-go"
  fi
  log "Go toolchain: $(go version)"

  if ! command -v fusermount3 >/dev/null 2>&1 && ! command -v fusermount >/dev/null 2>&1; then
    die "fusermount3 is missing. Install fuse3 with: apt-get install -y fuse3"
  fi

  # 3. Install microsandbox (msb) if it is missing.
  local orig_path="${PATH}"
  export PATH="${HOME}/.local/bin:/usr/local/bin:${PATH}"
  if ! command -v msb >/dev/null 2>&1; then
    log "msb is missing. Downloading the official microsandbox installer..."
    MSB_INSTALLER_TMP="$(mktemp)"
    curl --proto '=https' --proto-redir '=https' --tlsv1.2 -fsSL https://install.microsandbox.dev -o "${MSB_INSTALLER_TMP}" || die "Could not download the msb installer."
    [[ -s "${MSB_INSTALLER_TMP}" ]] || die "Downloaded msb installer is empty."
    sh "${MSB_INSTALLER_TMP}" || die "msb installation failed."
    rm -f "${MSB_INSTALLER_TMP}"
    MSB_INSTALLER_TMP=""
    command -v msb >/dev/null 2>&1 || die "msb is not on PATH."
  fi
  log "msb: $(msb --version 2>/dev/null | head -1)"

  # 4. Build and install the agbox binary.
  BUILD_TMP_DIR="$(mktemp -d)"
  log "Building agbox from ${SCRIPT_DIR}..."
  (
    cd "${SCRIPT_DIR}"
    CGO_ENABLED=0 go build -o "${BUILD_TMP_DIR}/agbox" -trimpath ./cmd/agbox
  )
  mkdir -p "${install_dir}"
  [[ ! -L "${install_dir}/agbox" ]] || die "Refusing to overwrite symlink at ${install_dir}/agbox."
  [[ ! -d "${install_dir}/agbox" ]] || die "Refusing to overwrite directory at ${install_dir}/agbox."
  INSTALL_STAGE_BIN="$(mktemp "${install_dir}/.agbox.tmp.XXXXXX")"
  install -m 0755 "${BUILD_TMP_DIR}/agbox" "${INSTALL_STAGE_BIN}"
  mv -f "${INSTALL_STAGE_BIN}" "${install_dir}/agbox"
  INSTALL_STAGE_BIN=""
  log "Installed binary: ${install_dir}/agbox"

  [[ -f "${SCRIPT_DIR}/AGBOX_ENV_RULES.md" ]] || die "AGBOX_ENV_RULES.md is missing in ${SCRIPT_DIR}."
  log "Installing default sandbox rules..."
  if [[ "${euid}" -eq 0 ]]; then
    "${install_dir}/agbox" rules add --allow-root --force "${SCRIPT_DIR}/AGBOX_ENV_RULES.md" >/dev/null
  else
    "${install_dir}/agbox" rules add --force "${SCRIPT_DIR}/AGBOX_ENV_RULES.md" >/dev/null
  fi

  # 5. Check host prerequisites and run the microVM smoke test.
  if [[ "${skip_setup}" -eq 1 ]]; then
    log "Skipping 'agbox setup' (--skip-setup)."
  else
    log "Running 'agbox setup'..."
    if [[ "${euid}" -eq 0 ]]; then
      "${install_dir}/agbox" setup --allow-root
    else
      "${install_dir}/agbox" setup
    fi
  fi

  if [[ ":${orig_path}:" != *":${install_dir}:"* ]]; then
    echo
    warn "${install_dir} is not in your PATH. Add this line to ~/.bashrc or ~/.zshrc:"
    echo "  export PATH=\"${install_dir}:\$PATH\""
  fi
}

main "$@"
