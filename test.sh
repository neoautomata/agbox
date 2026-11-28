#!/usr/bin/env bash
# test.sh - Automated integration and security test runner for agbox.
#
# By default, runs fast checks without modifying existing agbox data,
# snapshots, sandboxes, or installed binaries. Use --full for extended
# runtime checks and --disruptive to test clean-slate setup and teardown.
# shellcheck disable=SC2016,SC2030,SC2031,SC2317

set -uo pipefail

readonly SCRIPT_NAME="test.sh"
SCRIPT_START_EPOCH="$(date +%s)"
readonly SCRIPT_START_EPOCH

FULL_MODE=0
DISRUPTIVE_MODE=0
SKIP_VM=0
ALLOW_ROOT=0
VERBOSE=0
CUSTOM_LOG_DIR=""
FILTER_PATTERN=""

if [[ "${AGBOX_ALLOW_ROOT:-0}" == "1" ]]; then
  ALLOW_ROOT=1
fi

SUITE_ID="t$(date +%H%M%S)-$$"
REPO_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
HOME_REAL=""
CREATED_CACHE_DIR=0
TEST_ROOT=""
LOG_DIR=""
SUITE_LOG=""
ORIG_DATA_DIR=""
ORIG_MSB_HOME=""
ORIG_INSTALL_DIR=""
ORIG_INSTALL_BIN=""
BACKUP_INSTALL_BIN=""
ORIG_INSTALL_EXISTED=0
ORIG_COMP_DIR=""
ORIG_COMP_FILE=""
BACKUP_COMP_FILE=""
ORIG_COMP_EXISTED=0
BASELINE_DIR=""

TEST_BIN=""
ACTIVE_BIN=""
STUB_AGY_BIN=""
STYLECHECK_SRC=""
MSB_BIN_PATH=""
MDFORMAT_BIN=""

RUNTIME_DATA_DIR=""
RUNTIME_MSB_HOME=""
BASE_AGENT=""
BASE_SNAP=""
VM_READY=0
VM_ENV_READY=0
VM_PREFLIGHT_RAN=0
VM_BLOCK_REASON=""
DISRUPTIVE_SETUP_DONE=0
DISRUPTIVE_CLEANUP_DONE=0
CLEANUP_RAN=0
ACTIVE_CHILD_PGID=""
EUID_VAL="$(id -u)"

declare -a RESULT_IDS=()
declare -a RESULT_STATUSES=()
declare -a RESULT_DURATIONS=()
declare -a RESULT_DESCS=()
declare -a RESULT_LOGS=()
declare -a FAILED_IDS=()

PASS_COUNT=0
FAIL_COUNT=0
SKIP_COUNT=0

usage() {
  cat <<'EOF'
Usage: ./test.sh [options]

Automated test suite for agbox build, security boundaries, FUSE filtering, and microVM lifecycle.
Default mode is non-disruptive and fast. Existing agbox images, sandboxes, and config stay untouched.

Options:
  --full, --long    Run extended runtime tests (network firewall, open FD revocation, profile lock,
                    orphan reaping, --serve basic auth, and full isolated base lifecycle).
  --disruptive      Test clean-slate installation and teardown against live default paths
                    (runs remove, install.sh, setup, create-base, tests, and final cleanup).
  --skip-vm         Skip microVM tests when /dev/kvm or msb is unavailable.
  --allow-root      Allow running as host root (or set AGBOX_ALLOW_ROOT=1).
  --log-dir DIR     Store per-check logs under DIR instead of a temporary directory.
  --filter TEXT     Run checks whose ID or description contains TEXT (plus required setup and state checks).
  -v, --verbose     Print check logs in real time in addition to saving log files.
  -h, --help        Show this help message and exit.
EOF
}

timestamp_hms() {
  date '+%H:%M:%S'
}

append_suite_log() {
  if [[ -n "${SUITE_LOG:-}" ]]; then
    printf '%s\n' "$*" >> "${SUITE_LOG}" 2>/dev/null || true
  fi
}

log_msg() {
  local line
  line="[agbox-test $(timestamp_hms)] $*"
  printf '%s\n' "${line}"
  append_suite_log "${line}"
}

warn_msg() {
  local line
  line="[agbox-test $(timestamp_hms)] WARN: $*"
  printf '%s\n' "${line}" >&2
  append_suite_log "${line}"
}

die_msg() {
  local line
  line="[agbox-test $(timestamp_hms)] ERROR: $*"
  printf '%s\n' "${line}" >&2
  append_suite_log "${line}"
  exit 1
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --full|--long)
        FULL_MODE=1
        shift
        ;;
      --disruptive)
        DISRUPTIVE_MODE=1
        shift
        ;;
      --skip-vm)
        SKIP_VM=1
        shift
        ;;
      --allow-root)
        ALLOW_ROOT=1
        shift
        ;;
      --log-dir)
        [[ $# -ge 2 && -n "${2:-}" ]] || die_msg "--log-dir requires a directory path"
        CUSTOM_LOG_DIR="$2"
        shift 2
        ;;
      --log-dir=*)
        CUSTOM_LOG_DIR="${1#--log-dir=}"
        [[ -n "${CUSTOM_LOG_DIR}" ]] || die_msg "--log-dir requires a non-empty directory path"
        shift
        ;;
      --filter)
        [[ $# -ge 2 && -n "${2:-}" ]] || die_msg "--filter requires a substring"
        FILTER_PATTERN="$2"
        shift 2
        ;;
      --filter=*)
        FILTER_PATTERN="${1#--filter=}"
        [[ -n "${FILTER_PATTERN}" ]] || die_msg "--filter requires a non-empty substring"
        shift
        ;;
      -v|--verbose)
        VERBOSE=1
        shift
        ;;
      -h|--help)
        usage
        exit 0
        ;;
      *)
        die_msg "Unknown option: $1 (run './test.sh --help')"
        ;;
    esac
  done

  if [[ "${DISRUPTIVE_MODE}" -eq 1 && "${SKIP_VM}" -eq 1 ]]; then
    die_msg "Do not combine --disruptive and --skip-vm."
  fi
}

unset_passthrough_secrets() {
  local key
  local -a secret_keys=(
    ANTHROPIC_API_KEY
    OPENAI_API_KEY
    GEMINI_API_KEY
    GOOGLE_API_KEY
    GOOGLE_GENERATIVE_AI_API_KEY
    GROQ_API_KEY
    OPENROUTER_API_KEY
    MISTRAL_API_KEY
    DEEPSEEK_API_KEY
    COHERE_API_KEY
    PERPLEXITY_API_KEY
    TOGETHER_API_KEY
    FIREWORKS_API_KEY
    CEREBRAS_API_KEY
    XAI_API_KEY
    GITHUB_TOKEN
    GH_TOKEN
    AWS_ACCESS_KEY_ID
    AWS_SECRET_ACCESS_KEY
    AWS_SESSION_TOKEN
    AWS_REGION
    AWS_PROFILE
    VERTEX_LOCATION
    GOOGLE_CLOUD_PROJECT
    GOOGLE_CLOUD_LOCATION
    AZURE_OPENAI_API_KEY
    AZURE_OPENAI_ENDPOINT
    OLLAMA_HOST
    OPENCODE_SERVER_PASSWORD
    OPENCODE_SERVER_USERNAME
  )
  for key in "${secret_keys[@]}"; do
    unset "${key}" 2>/dev/null || true
  done
}

go_exec() {
  if [[ "${EUID_VAL}" -eq 0 ]]; then
    if [[ "$#" -gt 0 ]]; then
      local subcmd="$1"
      shift
      case "${subcmd}" in
        build|test|run)
          go "${subcmd}" -buildvcs=false "$@"
          return $?
          ;;
        *)
          go "${subcmd}" "$@"
          return $?
          ;;
      esac
    fi
  fi
  go "$@"
}

agbox_exec() {
  local bin_path="$1"
  shift
  if [[ "${ALLOW_ROOT}" -eq 1 ]]; then
    "${bin_path}" --allow-root "$@"
  else
    "${bin_path}" "$@"
  fi
}

kill_active_child() {
  if [[ -n "${ACTIVE_CHILD_PGID:-}" ]]; then
    kill -TERM -- "-${ACTIVE_CHILD_PGID}" "${ACTIVE_CHILD_PGID}" 2>/dev/null || true
    ACTIVE_CHILD_PGID=""
  fi
  local jpid=""
  while IFS= read -r jpid; do
    [[ -n "${jpid}" ]] || continue
    kill -TERM "${jpid}" 2>/dev/null || true
  done < <(jobs -pr 2>/dev/null || true)
}

_run_with_timeout() {
  local secs="$1"
  local stdin_mode="$2"
  shift 2

  local -a cmd=()
  if [[ "$1" == "go_exec" ]]; then
    shift
    if [[ "${EUID_VAL}" -eq 0 && "$#" -gt 0 ]]; then
      case "$1" in
        build|test|run)
          local sub="$1"
          shift
          cmd=(go "${sub}" -buildvcs=false "$@")
          ;;
        *)
          cmd=(go "$@")
          ;;
      esac
    else
      cmd=(go "$@")
    fi
  elif [[ "$1" == "agbox_exec" ]]; then
    shift
    local bin_path="$1"
    shift
    if [[ "${ALLOW_ROOT}" -eq 1 ]]; then
      cmd=("${bin_path}" --allow-root "$@")
    else
      cmd=("${bin_path}" "$@")
    fi
  else
    cmd=("$@")
  fi

  if [[ "${CLEANUP_RAN}" -eq 0 && "${BASH_SUBSHELL}" -gt 0 ]]; then
    trap 'kill_active_child; exit 130' INT
    trap 'kill_active_child; exit 143' TERM
    trap 'kill_active_child; exit 129' HUP
  fi

  local rc=0
  if [[ "${stdin_mode}" == "keep" ]]; then
    exec 3<&0
    timeout --kill-after=15s "${secs}s" "${cmd[@]}" <&3 3<&- &
    ACTIVE_CHILD_PGID=$!
    exec 3<&-
    wait "${ACTIVE_CHILD_PGID}" || rc=$?
    ACTIVE_CHILD_PGID=""
  else
    timeout --kill-after=15s "${secs}s" "${cmd[@]}" </dev/null &
    ACTIVE_CHILD_PGID=$!
    wait "${ACTIVE_CHILD_PGID}" || rc=$?
    ACTIVE_CHILD_PGID=""
  fi
  return "${rc}"
}

with_timeout() {
  local secs="$1"
  shift
  _run_with_timeout "${secs}" devnull "$@"
}

with_timeout_stdin() {
  local secs="$1"
  shift
  _run_with_timeout "${secs}" keep "$@"
}

resolve_msb_bin() {
  local candidate=""
  if command -v msb >/dev/null 2>&1; then
    command -v msb
    return 0
  fi
  for candidate in "${HOME_REAL}/.local/bin/msb" "/usr/local/bin/msb"; do
    if [[ -f "${candidate}" && -x "${candidate}" ]]; then
      printf '%s\n' "${candidate}"
      return 0
    fi
  done
  return 1
}

resolve_mdformat_bin() {
  if command -v mdformat >/dev/null 2>&1; then
    command -v mdformat
    return 0
  fi
  if [[ -x "${HOME_REAL}/.local/bin/mdformat" ]]; then
    printf '%s\n' "${HOME_REAL}/.local/bin/mdformat"
    return 0
  fi
  if [[ "${EUID_VAL}" -eq 0 && -n "${SUDO_USER:-}" && "${SUDO_USER}" != "root" ]]; then
    local sudo_home=""
    sudo_home="$(getent passwd "${SUDO_USER}" | cut -d: -f6 || true)"
    if [[ -n "${sudo_home}" && -x "${sudo_home}/.local/bin/mdformat" ]]; then
      printf '%s\n' "${sudo_home}/.local/bin/mdformat"
      return 0
    fi
  fi
  return 1
}

resolve_fusermount_bin() {
  if command -v fusermount3 >/dev/null 2>&1; then
    command -v fusermount3
    return 0
  fi
  if command -v fusermount >/dev/null 2>&1; then
    command -v fusermount
    return 0
  fi
  return 1
}

skip_check() {
  printf 'SKIP_REASON: %s\n' "$*"
  exit 77
}

should_run_check() {
  local id="$1"
  local desc="$2"
  if [[ -z "${FILTER_PATTERN}" ]]; then
    return 0
  fi
  if [[ "${id}" == *"${FILTER_PATTERN}"* || "${desc}" == *"${FILTER_PATTERN}"* ]]; then
    return 0
  fi
  return 1
}

list_active_mounts_under() {
  local prefix="$1"
  [[ -r /proc/self/mountinfo ]] || return 0
  awk -v pfx="${prefix}" '
    {
      mp = $5
      gsub(/\\040/, " ", mp)
      gsub(/\\011/, "\t", mp)
      gsub(/\\012/, "\n", mp)
      gsub(/\\134/, "\\", mp)
      if (mp == pfx || index(mp, pfx "/") == 1) {
        print mp
      }
    }
  ' /proc/self/mountinfo | LC_ALL=C sort -r
}

stop_filter_pidfile() {
  local pidfile="$1"
  local sig="$2"
  [[ -f "${pidfile}" ]] || return 0
  local pid=""
  pid="$(tr -d '[:space:]' < "${pidfile}" 2>/dev/null || true)"
  [[ "${pid}" =~ ^[0-9]+$ ]] || return 0
  [[ -r "/proc/${pid}/cmdline" ]] || return 0
  local cmdline=""
  cmdline="$(tr '\0' ' ' < "/proc/${pid}/cmdline" 2>/dev/null || true)"
  if [[ "${cmdline}" == *" __filter "* || "${cmdline}" == *" __filter" ]]; then
    kill "-${sig}" "${pid}" 2>/dev/null || true
  fi
}

unmount_tree() {
  local root_dir="$1"
  [[ -d "${root_dir}" ]] || return 0

  local pidf=""
  while IFS= read -r -d '' pidf; do
    stop_filter_pidfile "${pidf}" TERM
  done < <(find "${root_dir}" -type f \( -name 'ws.pid' -o -name 'remote.pid' -o -name 'm*.pid' \) -print0 2>/dev/null)

  local fm=""
  fm="$(resolve_fusermount_bin 2>/dev/null || true)"
  local mp=""
  while IFS= read -r mp; do
    [[ -n "${mp}" ]] || continue
    if [[ -n "${fm}" ]]; then
      "${fm}" -u "${mp}" 2>/dev/null || true
    fi
    umount "${mp}" 2>/dev/null || true
  done < <(list_active_mounts_under "${root_dir}")

  sleep 0.2
  if [[ -n "$(list_active_mounts_under "${root_dir}")" ]]; then
    while IFS= read -r -d '' pidf; do
      stop_filter_pidfile "${pidf}" KILL
    done < <(find "${root_dir}" -type f \( -name 'ws.pid' -o -name 'remote.pid' -o -name 'm*.pid' \) -print0 2>/dev/null)
    while IFS= read -r mp; do
      [[ -n "${mp}" ]] || continue
      if [[ -n "${fm}" ]]; then
        "${fm}" -uz "${mp}" 2>/dev/null || true
      fi
      umount -l "${mp}" 2>/dev/null || true
    done < <(list_active_mounts_under "${root_dir}")
  fi
}

sweep_msb_home_suite_resources() {
  local mh="$1"
  [[ -n "${MSB_BIN_PATH}" && -d "${mh}" ]] || return 0

  local ls_out=""
  ls_out="$(MSB_HOME="${mh}" with_timeout 30 "${MSB_BIN_PATH}" ls </dev/null 2>/dev/null || true)"
  if [[ -n "${ls_out}" ]]; then
    local sb=""
    while IFS= read -r sb; do
      [[ -n "${sb}" ]] || continue
      if [[ "${sb}" == agbox-${SUITE_ID}-* ]]; then
        MSB_HOME="${mh}" with_timeout 30 "${MSB_BIN_PATH}" rm -f "${sb}" </dev/null >/dev/null 2>&1 || true
      fi
    done < <(awk 'NR>0 && $1 !~ /^NAME$/ && $1 !~ /^-+$/ {print $1}' <<< "${ls_out}")
  fi

  local vol_out=""
  vol_out="$(MSB_HOME="${mh}" with_timeout 30 "${MSB_BIN_PATH}" volume ls </dev/null 2>/dev/null || true)"
  if [[ -n "${vol_out}" ]]; then
    local vol=""
    while IFS= read -r vol; do
      [[ -n "${vol}" ]] || continue
      if [[ "${vol}" == agbox-profile-${SUITE_ID}-* ]]; then
        MSB_HOME="${mh}" with_timeout 30 "${MSB_BIN_PATH}" volume rm "${vol}" </dev/null >/dev/null 2>&1 || true
      fi
    done < <(awk 'NR>0 && $1 !~ /^(NAME|VOLUME)$/ && $1 !~ /^-+$/ {print $1}' <<< "${vol_out}")
  fi
}

sweep_suite_resources() {
  if [[ -n "${TEST_ROOT}" && -d "${TEST_ROOT}" ]]; then
    unmount_tree "${TEST_ROOT}"
  fi
  if [[ -n "${ORIG_MSB_HOME}" ]]; then
    sweep_msb_home_suite_resources "${ORIG_MSB_HOME}"
  fi
  if [[ -n "${TEST_ROOT}" && -d "${TEST_ROOT}/iso-msb" ]]; then
    sweep_msb_home_suite_resources "${TEST_ROOT}/iso-msb"
  fi
  if [[ -n "${TEST_ROOT}" && -d "${TEST_ROOT}/full-iso-msb" ]]; then
    sweep_msb_home_suite_resources "${TEST_ROOT}/full-iso-msb"
  fi
}

restore_install_bin_if_needed() {
  [[ "${DISRUPTIVE_MODE}" -eq 1 ]] || return 0
  if [[ -n "${ORIG_INSTALL_BIN}" ]]; then
    if [[ "${ORIG_INSTALL_EXISTED}" -eq 1 && -n "${BACKUP_INSTALL_BIN}" && -f "${BACKUP_INSTALL_BIN}" ]]; then
      mkdir -p "$(dirname "${ORIG_INSTALL_BIN}")"
      install -m 0755 "${BACKUP_INSTALL_BIN}" "${ORIG_INSTALL_BIN}" 2>/dev/null || true
    elif [[ "${ORIG_INSTALL_EXISTED}" -eq 0 && -f "${ORIG_INSTALL_BIN}" && ! -L "${ORIG_INSTALL_BIN}" ]]; then
      rm -f "${ORIG_INSTALL_BIN}" 2>/dev/null || true
    fi
  fi
  if [[ -n "${ORIG_COMP_FILE}" ]]; then
    if [[ "${ORIG_COMP_EXISTED}" -eq 1 && -n "${BACKUP_COMP_FILE}" && -f "${BACKUP_COMP_FILE}" ]]; then
      mkdir -p "$(dirname "${ORIG_COMP_FILE}")"
      install -m 0644 "${BACKUP_COMP_FILE}" "${ORIG_COMP_FILE}" 2>/dev/null || true
    elif [[ "${ORIG_COMP_EXISTED}" -eq 0 && -f "${ORIG_COMP_FILE}" && ! -L "${ORIG_COMP_FILE}" ]]; then
      rm -f "${ORIG_COMP_FILE}" 2>/dev/null || true
    fi
  fi
}

global_cleanup() {
  if [[ "${CLEANUP_RAN}" -eq 1 ]]; then
    return 0
  fi
  CLEANUP_RAN=1

  sweep_suite_resources

  if [[ "${DISRUPTIVE_MODE}" -eq 1 && "${DISRUPTIVE_SETUP_DONE}" -eq 1 ]]; then
    local rem_bin="${ACTIVE_BIN:-${TEST_BIN:-}}"
    if [[ "${DISRUPTIVE_CLEANUP_DONE}" -ne 1 && -n "${rem_bin}" && -x "${rem_bin}" ]]; then
      MSB_HOME="${ORIG_MSB_HOME}" AGBOX_DATA_DIR="${ORIG_DATA_DIR}" with_timeout 60 agbox_exec "${rem_bin}" remove --yes >/dev/null 2>&1 || true
    fi
    restore_install_bin_if_needed
  fi

  if [[ -n "${TEST_ROOT}" && -d "${TEST_ROOT}" ]]; then
    unmount_tree "${TEST_ROOT}"
    if [[ -z "$(list_active_mounts_under "${TEST_ROOT}")" ]]; then
      rm -rf "${TEST_ROOT}" 2>/dev/null || true
    else
      warn_msg "Active mounts remain under ${TEST_ROOT}. Preserved directory to protect mount targets."
    fi
  fi

  if [[ "${CREATED_CACHE_DIR}" -eq 1 && -d "${HOME_REAL}/.cache" ]]; then
    rmdir "${HOME_REAL}/.cache" 2>/dev/null || true
  fi
}

handle_interrupt() {
  local sig="$1"
  local code="$2"
  trap - INT TERM HUP
  kill_active_child
  warn_msg "Interrupted by ${sig}. Removing temporary resources and exiting..."
  global_cleanup
  exit "${code}"
}

fingerprint_dir() {
  local dir="$1"
  local out_file="$2"
  : > "${out_file}"
  if [[ ! -e "${dir}" && ! -L "${dir}" ]]; then
    printf 'ABSENT\n' > "${out_file}"
    return 0
  fi

  local -a paths=()
  local p=""
  while IFS= read -r -d '' p; do
    paths+=("${p}")
  done < <(find "${dir}" -print0 2>/dev/null | LC_ALL=C sort -z)

  for p in "${paths[@]}"; do
    local rel="."
    if [[ "${p}" != "${dir}" ]]; then
      rel="${p#"${dir}/"}"
    fi
    local meta=""
    meta="$(stat -c '%F|%a' "${p}" 2>/dev/null || printf 'STATERR')"
    if [[ -L "${p}" ]]; then
      local tgt=""
      tgt="$(readlink "${p}" 2>/dev/null || printf 'READLINKERR')"
      printf '%s|%s|%s\n' "${rel}" "${meta}" "${tgt}" >> "${out_file}"
    elif [[ -f "${p}" ]]; then
      local sum=""
      sum="$(sha256sum "${p}" 2>/dev/null | awk '{print $1}' || printf 'HASHERR')"
      printf '%s|%s|%s\n' "${rel}" "${meta}" "${sum}" >> "${out_file}"
    else
      printf '%s|%s\n' "${rel}" "${meta}" >> "${out_file}"
    fi
  done
}

canonical_msb_sandboxes() {
  local mh="$1"
  local out_file="$2"
  : > "${out_file}"
  if [[ -z "${MSB_BIN_PATH}" ]]; then
    printf 'NO_MSB\n' > "${out_file}"
    return 0
  fi
  if [[ ! -d "${mh}" ]]; then
    printf 'ABSENT_MSB_HOME\n' > "${out_file}"
    return 0
  fi
  local out=""
  if ! out="$(MSB_HOME="${mh}" with_timeout 30 "${MSB_BIN_PATH}" ls </dev/null 2>/dev/null)"; then
    printf 'MSB_LS_ERR\n' > "${out_file}"
    return 0
  fi
  awk '
    BEGIN { status_col = 0 }
    {
      line = $0
      gsub(/\033\[[0-9;?]*[A-Za-z]/, "", line)
      gsub(/^[[:space:]]+|[[:space:]]+$/, "", line)
      if (line == "" || line ~ /^-+/) {
        next
      }
      n = split(line, f, /[[:space:]]+/)
      if (n == 0) {
        next
      }
      if (tolower(f[1]) == "name") {
        status_col = 0
        for (i = 2; i <= n; i++) {
          h = tolower(f[i])
          if (h == "status" || h == "state") {
            status_col = i
            break
          }
        }
        next
      }
      running = 0
      if (status_col > 1) {
        if (n >= status_col && tolower(f[status_col]) == "running") {
          running = 1
        }
      } else {
        for (i = 2; i <= n; i++) {
          if (tolower(f[i]) == "running") {
            running = 1
            break
          }
        }
      }
      print f[1] "\t" (running ? "running" : "stopped")
    }
  ' <<< "${out}" | LC_ALL=C sort > "${out_file}"
}

canonical_msb_snaps() {
  local mh="$1"
  local out_file="$2"
  : > "${out_file}"
  if [[ -z "${MSB_BIN_PATH}" ]]; then
    printf 'NO_MSB\n' > "${out_file}"
    return 0
  fi
  if [[ ! -d "${mh}" ]]; then
    printf 'ABSENT_MSB_HOME\n' > "${out_file}"
    return 0
  fi
  local out=""
  if ! out="$(MSB_HOME="${mh}" with_timeout 30 "${MSB_BIN_PATH}" snap ls </dev/null 2>/dev/null)"; then
    printf 'MSB_SNAP_LS_ERR\n' > "${out_file}"
    return 0
  fi
  awk '
    {
      line = $0
      gsub(/^[[:space:]]+|[[:space:]]+$/, "", line)
      if (line == "" || line ~ /^NAME/ || line ~ /^SNAPSHOT/ || line ~ /^-+/) {
        next
      }
      split(line, f, /[[:space:]]+/)
      if (index(f[1], ":") > 0) {
        print f[1]
      }
    }
  ' <<< "${out}" | LC_ALL=C sort > "${out_file}"
}

canonical_msb_volumes() {
  local mh="$1"
  local out_file="$2"
  : > "${out_file}"
  if [[ -z "${MSB_BIN_PATH}" ]]; then
    printf 'NO_MSB\n' > "${out_file}"
    return 0
  fi
  if [[ ! -d "${mh}" ]]; then
    printf 'ABSENT_MSB_HOME\n' > "${out_file}"
    return 0
  fi
  local out=""
  if ! out="$(MSB_HOME="${mh}" with_timeout 30 "${MSB_BIN_PATH}" volume ls </dev/null 2>/dev/null)"; then
    printf 'MSB_VOL_LS_ERR\n' > "${out_file}"
    return 0
  fi
  awk '
    {
      line = $0
      gsub(/^[[:space:]]+|[[:space:]]+$/, "", line)
      if (line == "" || line ~ /^NAME/ || line ~ /^VOLUME/ || line ~ /^-+/) {
        next
      }
      split(line, f, /[[:space:]]+/)
      if (f[1] != "") {
        print f[1]
      }
    }
  ' <<< "${out}" | LC_ALL=C sort > "${out_file}"
}

canonical_agbox_mounts() {
  local out_file="$1"
  : > "${out_file}"
  {
    list_active_mounts_under "${ORIG_DATA_DIR}"
    list_active_mounts_under "${TEST_ROOT}"
  } | LC_ALL=C sort -u > "${out_file}"
}

capture_state() {
  local dir="$1"
  mkdir -p "${dir}"
  canonical_msb_sandboxes "${ORIG_MSB_HOME}" "${dir}/msb_sandboxes.txt"
  canonical_msb_snaps "${ORIG_MSB_HOME}" "${dir}/msb_snaps.txt"
  canonical_msb_volumes "${ORIG_MSB_HOME}" "${dir}/msb_volumes.txt"
  canonical_agbox_mounts "${dir}/agbox_mounts.txt"
  fingerprint_dir "${ORIG_DATA_DIR}" "${dir}/data_dir.fp"
  if [[ -n "${ORIG_INSTALL_BIN}" && ( -e "${ORIG_INSTALL_BIN}" || -L "${ORIG_INSTALL_BIN}" ) ]]; then
    fingerprint_dir "${ORIG_INSTALL_BIN}" "${dir}/install_bin.fp"
  else
    printf 'ABSENT\n' > "${dir}/install_bin.fp"
  fi
  if [[ -n "${ORIG_COMP_FILE}" && ( -e "${ORIG_COMP_FILE}" || -L "${ORIG_COMP_FILE}" ) ]]; then
    fingerprint_dir "${ORIG_COMP_FILE}" "${dir}/comp_file.fp"
  else
    printf 'ABSENT\n' > "${dir}/comp_file.fp"
  fi
  if [[ -n "${ORIG_MSB_HOME}" && ( -e "${ORIG_MSB_HOME}" || -L "${ORIG_MSB_HOME}" ) ]]; then
    fingerprint_dir "${ORIG_MSB_HOME}" "${dir}/msb_home.fp"
    : > "${dir}/msb_home_bins.fp"
    local sub=""
    for sub in bin lib; do
      if [[ -e "${ORIG_MSB_HOME}/${sub}" || -L "${ORIG_MSB_HOME}/${sub}" ]]; then
        fingerprint_dir "${ORIG_MSB_HOME}/${sub}" "${dir}/msb_home_${sub}.fp"
        cat "${dir}/msb_home_${sub}.fp" >> "${dir}/msb_home_bins.fp"
      fi
    done
  else
    printf 'ABSENT\n' > "${dir}/msb_home.fp"
    printf 'ABSENT\n' > "${dir}/msb_home_bins.fp"
  fi
}

write_helpers() {
  if [[ -f "${TEST_ROOT}/helpers/.ready" ]]; then
    return 0
  fi
  local hdir="${TEST_ROOT}/helpers"
  mkdir -p "${hdir}/stylecheck" "${hdir}/stubagy"
  chmod 0700 "${hdir}" "${hdir}/stylecheck" "${hdir}/stubagy"

  cat > "${hdir}/go.mod" <<'EOF'
module agbox-e2e-helpers

go 1.21
EOF

  cat > "${hdir}/stylecheck/main.go" <<'EOF'
package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "Usage: stylecheck <repo-dir>")
		os.Exit(2)
	}
	root := os.Args[1]
	var violations []string

	for _, sub := range []string{"cmd", "internal"} {
		base := filepath.Join(root, sub)
		err := filepath.WalkDir(base, func(path string, d fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if d.IsDir() || !strings.HasSuffix(d.Name(), ".go") {
				return nil
			}
			rel, _ := filepath.Rel(root, path)
			v, err := checkGoFile(path, rel)
			if err != nil {
				return err
			}
			violations = append(violations, v...)
			return nil
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "walk %s: %v\n", sub, err)
			os.Exit(2)
		}
	}

	for _, md := range []string{"README.md", "USER_GUIDE.md", "AGENTS.md", "AGBOX_ENV_RULES.md"} {
		p := filepath.Join(root, md)
		if _, err := os.Stat(p); os.IsNotExist(err) {
			continue
		}
		v, err := checkMarkdownFile(p, md)
		if err != nil {
			fmt.Fprintf(os.Stderr, "check %s: %v\n", md, err)
			os.Exit(2)
		}
		violations = append(violations, v...)
	}

	if len(violations) > 0 {
		for _, v := range violations {
			fmt.Fprintln(os.Stderr, v)
		}
		os.Exit(1)
	}
	fmt.Println("Style and semicolon check OK")
}

func checkGoFile(path, rel string) ([]string, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, cg := range f.Comments {
		for _, c := range cg.List {
			if strings.HasPrefix(c.Text, "//") && strings.Contains(c.Text, ";") {
				pos := fset.Position(c.Pos())
				out = append(out, fmt.Sprintf("%s:%d: semicolon in comment", rel, pos.Line))
			}
		}
	}

	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || len(call.Args) == 0 {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		pkg, ok := sel.X.(*ast.Ident)
		if !ok {
			return true
		}
		isErrCall := (pkg.Name == "errors" && sel.Sel.Name == "New") ||
			(pkg.Name == "fmt" && sel.Sel.Name == "Errorf")
		if !isErrCall {
			return true
		}
		lit, ok := call.Args[0].(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return true
		}
		val, uErr := strconv.Unquote(lit.Value)
		if uErr == nil && strings.Contains(val, ";") {
			pos := fset.Position(lit.Pos())
			out = append(out, fmt.Sprintf("%s:%d: semicolon in error string", rel, pos.Line))
		}
		return true
	})
	return out, nil
}

func checkMarkdownFile(path, rel string) ([]string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	lines := strings.Split(string(raw), "\n")
	var out []string
	inFence := false
	fenceChar := byte(0)
	fenceLen := 0

	for i, line := range lines {
		trimmed := strings.TrimLeft(line, " ")
		if !inFence {
			if c, n := countFencePrefix(trimmed); n >= 3 {
				inFence = true
				fenceChar = c
				fenceLen = n
				continue
			}
			stripped := stripInlineCodeSpans(line)
			if strings.Contains(stripped, ";") {
				out = append(out, fmt.Sprintf("%s:%d: semicolon in Markdown prose", rel, i+1))
			}
		} else {
			if len(trimmed) >= fenceLen {
				allSame := true
				k := 0
				for k < len(trimmed) && trimmed[k] == fenceChar {
					k++
				}
				rest := strings.TrimSpace(trimmed[k:])
				if k >= fenceLen && rest == "" {
					allSame = true
				} else {
					allSame = false
				}
				if allSame {
					inFence = false
					fenceChar = 0
					fenceLen = 0
				}
			}
		}
	}
	return out, nil
}

func countFencePrefix(s string) (byte, int) {
	if len(s) == 0 || (s[0] != '`' && s[0] != '~') {
		return 0, 0
	}
	ch := s[0]
	n := 0
	for n < len(s) && s[n] == ch {
		n++
	}
	return ch, n
}

func stripInlineCodeSpans(s string) string {
	var b strings.Builder
	i := 0
	for i < len(s) {
		if s[i] != '`' {
			b.WriteByte(s[i])
			i++
			continue
		}
		ticks := 0
		for i+ticks < len(s) && s[i+ticks] == '`' {
			ticks++
		}
		j := i + ticks
		matched := false
		for j < len(s) {
			if s[j] != '`' {
				j++
				continue
			}
			closeTicks := 0
			for j+closeTicks < len(s) && s[j+closeTicks] == '`' {
				closeTicks++
			}
			if closeTicks == ticks {
				i = j + closeTicks
				matched = true
				break
			}
			j += closeTicks
		}
		if !matched {
			b.WriteString(s[i : i+ticks])
			i += ticks
		}
	}
	return b.String()
}
EOF

  cat > "${hdir}/stubagy/main.go" <<'EOF'
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const rcMarkerPath = "/home/agent/.agbox-e2e-rc-instance"

func main() {
	args := os.Args[1:]
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "stub agy requires arguments")
		os.Exit(2)
	}

	switch args[0] {
	case "--version", "version":
		fmt.Println("agy e2e-stub-1.0.0")
		return
	case "update":
		return
	case "remote-control":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "missing remote-control subcommand")
			os.Exit(2)
		}
		switch args[1] {
		case "start":
			if os.Getuid() != 1000 {
				fmt.Fprintf(os.Stderr, "expected uid 1000, got %d\n", os.Getuid())
				os.Exit(1)
			}
			name := ""
			for i := 2; i < len(args); i++ {
				if args[i] == "--name" && i+1 < len(args) {
					name = args[i+1]
					break
				}
				if strings.HasPrefix(args[i], "--name=") {
					name = strings.TrimPrefix(args[i], "--name=")
					break
				}
			}
			if name == "" {
				fmt.Fprintln(os.Stderr, "missing --name")
				os.Exit(2)
			}
			tokPath := "/home/agent/.gemini/antigravity-cli/antigravity-oauth-token"
			info, err := os.Lstat(tokPath)
			if err != nil {
				fmt.Fprintf(os.Stderr, "missing saved antigravity oauth token: %v\n", err)
				os.Exit(1)
			}
			if !info.Mode().IsRegular() || (info.Mode().Perm()&0o077) != 0 || info.Size() == 0 {
				fmt.Fprintf(os.Stderr, "invalid saved antigravity oauth token mode/size: %v\n", info.Mode())
				os.Exit(1)
			}
			if err := os.MkdirAll(filepath.Dir(rcMarkerPath), 0o700); err != nil {
				fmt.Fprintf(os.Stderr, "prepare marker dir: %v\n", err)
				os.Exit(1)
			}
			if err := os.WriteFile(rcMarkerPath, []byte(name+"\n"), 0o600); err != nil {
				fmt.Fprintf(os.Stderr, "write rc marker: %v\n", err)
				os.Exit(1)
			}
			fmt.Printf("Started Remote Control %s\n", name)
			return
		case "status":
			raw, err := os.ReadFile(rcMarkerPath)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Remote Control not running: %v\n", err)
				os.Exit(1)
			}
			name := strings.TrimSpace(string(raw))
			if name == "" {
				fmt.Fprintln(os.Stderr, "Remote Control marker empty")
				os.Exit(1)
			}
			fmt.Printf("Remote Control active (%s)\n", name)
			return
		default:
			fmt.Fprintf(os.Stderr, "unknown remote-control subcommand %q\n", args[1])
			os.Exit(2)
		}
	default:
		fmt.Fprintf(os.Stderr, "unknown stub agy command %q\n", args[0])
		os.Exit(2)
	}
}
EOF

  STYLECHECK_SRC="${hdir}/stylecheck/main.go"
  STUB_AGY_BIN="${hdir}/agy"
  : > "${hdir}/.ready"
}

build_test_binaries() {
  write_helpers
  if [[ -z "${ACTIVE_BIN}" ]]; then
    ACTIVE_BIN="${TEST_BIN}"
  fi
  if [[ -x "${TEST_BIN}" && -x "${STUB_AGY_BIN}" ]]; then
    return 0
  fi
  mkdir -p "${TEST_ROOT}/bin"
  chmod 0700 "${TEST_ROOT}/bin"

  (
    cd "${REPO_DIR}"
    CGO_ENABLED=0 go_exec build -o "${TEST_BIN}" ./cmd/agbox
  )
  chmod 0755 "${TEST_BIN}"

  (
    cd "${TEST_ROOT}/helpers"
    CGO_ENABLED=0 GOOS=linux go_exec build -ldflags="-s -w" -o "${STUB_AGY_BIN}" ./stubagy
  )
  chmod 0755 "${STUB_AGY_BIN}"
}

install_stub_agy_cache() {
  local data_dir="$1"
  local agents_dir="${data_dir}/agents"
  local bin_dir="${agents_dir}/bin"
  local dst_bin="${bin_dir}/agy"

  mkdir -p "${agents_dir}" "${bin_dir}"
  chmod 0700 "${agents_dir}"
  chmod 0755 "${bin_dir}"
  rm -f "${dst_bin}" "${agents_dir}/manifest.json"
  install -m 0755 "${STUB_AGY_BIN}" "${dst_bin}"

  local sha=""
  local sz=""
  sha="$(sha256sum "${dst_bin}" | awk '{print $1}')"
  sz="$(stat -c '%s' "${dst_bin}")"

  cat > "${agents_dir}/manifest.json" <<EOF
{
  "agents": {
    "antigravity": {
      "agent": "antigravity",
      "bin_name": "agy",
      "version": "e2e-stub-1.0.0",
      "sha256": "${sha}",
      "size_bytes": ${sz},
      "updated_at": "2026-11-14T00:00:00Z"
    }
  }
}
EOF
  chmod 0600 "${agents_dir}/manifest.json"
}

seed_test_auth() {
  local data_dir="$1"
  mkdir -p "${data_dir}" "${data_dir}/auth" "${data_dir}/auth/antigravity" "${data_dir}/auth/opencode"
  chmod 0700 "${data_dir}" "${data_dir}/auth" "${data_dir}/auth/antigravity" "${data_dir}/auth/opencode"

  printf 'stub-oauth-token-%s\n' "${SUITE_ID}" > "${data_dir}/auth/antigravity/antigravity-oauth-token"
  chmod 0600 "${data_dir}/auth/antigravity/antigravity-oauth-token"

  cat > "${data_dir}/auth/opencode/auth.json" <<'EOF'
{
  "anthropic": {
    "type": "api",
    "key": "sk-e2e-synthetic-opencode-key"
  }
}
EOF
  chmod 0600 "${data_dir}/auth/opencode/auth.json"
}

load_base_info_from_config() {
  local cfg="$1"
  BASE_AGENT="$(awk -F= '$1=="agent"{print $2}' "${cfg}" 2>/dev/null | head -n 1 || true)"
  BASE_SNAP="$(awk -F= '$1=="snapshot"{print $2}' "${cfg}" 2>/dev/null | head -n 1 || true)"
}

prepare_isolated_msb_home() {
  local target="$1"
  rm -rf "${target}"
  mkdir -p "${target}"
  chmod 0700 "${target}"

  if [[ -d "${ORIG_MSB_HOME}/bin" ]]; then
    ln -s "${ORIG_MSB_HOME}/bin" "${target}/bin"
  fi
  if [[ -d "${ORIG_MSB_HOME}/lib" ]]; then
    ln -s "${ORIG_MSB_HOME}/lib" "${target}/lib"
  fi

  local probe_vol="agbox-profile-${SUITE_ID}-probe"
  if ! MSB_HOME="${target}" with_timeout 30 "${MSB_BIN_PATH}" volume create "${probe_vol}" --kind disk --size 16M </dev/null >/dev/null 2>&1; then
    return 1
  fi

  if [[ "${target}" != "${ORIG_MSB_HOME}" ]]; then
    local orig_vols=""
    orig_vols="$(MSB_HOME="${ORIG_MSB_HOME}" with_timeout 30 "${MSB_BIN_PATH}" volume ls </dev/null 2>/dev/null || true)"
    if grep -Fq "${probe_vol}" <<< "${orig_vols}"; then
      MSB_HOME="${target}" with_timeout 30 "${MSB_BIN_PATH}" volume rm "${probe_vol}" </dev/null >/dev/null 2>&1 || true
      MSB_HOME="${ORIG_MSB_HOME}" with_timeout 30 "${MSB_BIN_PATH}" volume rm "${probe_vol}" </dev/null >/dev/null 2>&1 || true
      return 1
    fi
  fi

  MSB_HOME="${target}" with_timeout 30 "${MSB_BIN_PATH}" volume rm "${probe_vol}" </dev/null >/dev/null 2>&1 || true
  return 0
}

wait_for_sandbox_running() {
  local mh="$1"
  local sbx="$2"
  local max_tries="${3:-40}"
  local i=0
  while [[ "${i}" -lt "${max_tries}" ]]; do
    local out=""
    out="$(MSB_HOME="${mh}" with_timeout 30 "${MSB_BIN_PATH}" ls </dev/null 2>/dev/null || true)"
    if awk -v target="${sbx}" '
      BEGIN { status_col = 0; found = 0 }
      {
        line = $0
        gsub(/\033\[[0-9;?]*[A-Za-z]/, "", line)
        gsub(/^[[:space:]]+|[[:space:]]+$/, "", line)
        if (line == "" || line ~ /^-+/) {
          next
        }
        n = split(line, f, /[[:space:]]+/)
        if (n == 0) {
          next
        }
        if (tolower(f[1]) == "name") {
          status_col = 0
          for (i = 2; i <= n; i++) {
            h = tolower(f[i])
            if (h == "status" || h == "state") {
              status_col = i
              break
            }
          }
          next
        }
        if (f[1] != target) {
          next
        }
        if (status_col > 1) {
          if (n >= status_col && tolower(f[status_col]) == "running") {
            found = 1
          }
        } else {
          for (i = 2; i <= n; i++) {
            if (tolower(f[i]) == "running") {
              found = 1
              break
            }
          }
        }
      }
      END { exit(found ? 0 : 1) }
    ' <<< "${out}"; then
      return 0
    fi
    sleep 0.5
    i=$((i + 1))
  done
  return 1
}

wait_for_sandbox_gone() {
  local mh="$1"
  local sbx="$2"
  local max_tries="${3:-30}"
  local i=0
  while [[ "${i}" -lt "${max_tries}" ]]; do
    local out=""
    out="$(MSB_HOME="${mh}" with_timeout 30 "${MSB_BIN_PATH}" ls </dev/null 2>/dev/null || true)"
    if ! awk -v target="${sbx}" '
      { if ($1 == target) { found = 1 } }
      END { exit(found ? 0 : 1) }
    ' <<< "${out}"; then
      return 0
    fi
    sleep 0.5
    i=$((i + 1))
  done
  return 1
}

assert_contains() {
  local haystack="$1"
  local needle="$2"
  local label="${3:-output}"
  if ! grep -Fq -- "${needle}" <<< "${haystack}"; then
    printf 'Assertion failed: expected %s to contain %q\n' "${label}" "${needle}" >&2
    printf 'Actual %s:\n%s\n' "${label}" "${haystack}" >&2
    return 1
  fi
}

assert_not_contains() {
  local haystack="$1"
  local needle="$2"
  local label="${3:-output}"
  if grep -Fq -- "${needle}" <<< "${haystack}"; then
    printf 'Assertion failed: expected %s NOT to contain %q\n' "${label}" "${needle}" >&2
    printf 'Actual %s:\n%s\n' "${label}" "${haystack}" >&2
    return 1
  fi
}

run_capture() {
  local __var_name="$1"
  shift
  local __cap_dir="${TEST_ROOT:-/tmp}"
  if [[ ! -d "${__cap_dir}" ]]; then
    __cap_dir="/tmp"
  fi
  local __tmp=""
  __tmp="$(mktemp "${__cap_dir}/agbox-cap.XXXXXX")"
  local __rc=0
  "$@" >"${__tmp}" 2>&1 || __rc=$?
  local __out=""
  __out="$(<"${__tmp}")"
  rm -f "${__tmp}"
  printf -v "${__var_name}" '%s' "${__out}"
  if [[ "${__rc}" -ne 0 ]]; then
    printf '%s\n' "${__out}" >&2
  fi
  return "${__rc}"
}

run_check() {
  local id="$1"
  local desc="$2"
  local fn_name="$3"

  local step_log="${LOG_DIR}/${id}.log"
  local start_s=""
  local end_s=""
  local dur_s=""
  start_s="$(date +%s)"

  log_msg "START ${id} (${desc})"
  : > "${step_log}"

  local rc=0
  if [[ "${VERBOSE}" -eq 1 ]]; then
    (
      set -Eeuo pipefail
      trap 'trap - ERR; printf "[FAIL LINE %d] %s\n" "$LINENO" "$BASH_COMMAND" >&2' ERR
      trap 'kill_active_child; exit 130' INT
      trap 'kill_active_child; exit 143' TERM
      trap 'kill_active_child; exit 129' HUP
      "${fn_name}" </dev/null
    ) 2>&1 | tee -a "${step_log}"
    rc="${PIPESTATUS[0]}"
  else
    (
      set -Eeuo pipefail
      trap 'trap - ERR; printf "[FAIL LINE %d] %s\n" "$LINENO" "$BASH_COMMAND" >&2' ERR
      trap 'kill_active_child; exit 130' INT
      trap 'kill_active_child; exit 143' TERM
      trap 'kill_active_child; exit 129' HUP
      "${fn_name}" </dev/null
    ) >"${step_log}" 2>&1
    rc=$?
  fi

  if [[ "${rc}" -eq 130 ]]; then
    handle_interrupt INT 130
  elif [[ "${rc}" -eq 143 ]]; then
    handle_interrupt TERM 143
  elif [[ "${rc}" -eq 129 ]]; then
    handle_interrupt HUP 129
  fi

  end_s="$(date +%s)"
  dur_s=$((end_s - start_s))

  local status=""
  if [[ "${rc}" -eq 0 ]]; then
    status="PASS"
    PASS_COUNT=$((PASS_COUNT + 1))
    log_msg "PASS  ${id} (${dur_s}s)"
  elif [[ "${rc}" -eq 77 ]]; then
    status="SKIP"
    SKIP_COUNT=$((SKIP_COUNT + 1))
    local reason=""
    reason="$(grep '^SKIP_REASON: ' "${step_log}" 2>/dev/null | head -n 1 | sed 's/^SKIP_REASON: //' || true)"
    if [[ -n "${reason}" ]]; then
      log_msg "SKIP  ${id} (${dur_s}s): ${reason}"
    else
      log_msg "SKIP  ${id} (${dur_s}s)"
    fi
  else
    status="FAIL"
    FAIL_COUNT=$((FAIL_COUNT + 1))
    FAILED_IDS+=("${id}")
    log_msg "FAIL  ${id} (exit ${rc}, ${dur_s}s) - see ${step_log}"
  fi

  RESULT_IDS+=("${id}")
  RESULT_STATUSES+=("${status}")
  RESULT_DURATIONS+=("${dur_s}")
  RESULT_DESCS+=("${desc}")
  RESULT_LOGS+=("${step_log}")

  sweep_suite_resources
  return 0
}

record_blocked_skip() {
  local id="$1"
  local desc="$2"
  local reason="$3"
  local step_log="${LOG_DIR}/${id}.log"
  printf 'SKIP_REASON: %s\n' "${reason}" > "${step_log}"
  SKIP_COUNT=$((SKIP_COUNT + 1))
  log_msg "SKIP  ${id} (0s): ${reason}"
  RESULT_IDS+=("${id}")
  RESULT_STATUSES+=("SKIP")
  RESULT_DURATIONS+=("0")
  RESULT_DESCS+=("${desc}")
  RESULT_LOGS+=("${step_log}")
}

# ---------------------------------------------------------------------------
# Phase 1: Static, style, unit/race, and binary build
# ---------------------------------------------------------------------------

check_01_static_and_style() {
  write_helpers
  bash -n "${REPO_DIR}/install.sh" "${REPO_DIR}/test.sh"
  echo "bash -n install.sh test.sh: OK"

  local unformatted=""
  unformatted="$(cd "${REPO_DIR}" && gofmt -l ./cmd ./internal)"
  if [[ -n "${unformatted}" ]]; then
    printf 'Unformatted Go files:\n%s\n' "${unformatted}" >&2
    return 1
  fi
  echo "gofmt: OK"

  (
    cd "${TEST_ROOT}/helpers"
    go_exec run "${STYLECHECK_SRC}" "${REPO_DIR}"
  )

  if [[ -n "${MDFORMAT_BIN}" ]]; then
    (
      cd "${REPO_DIR}"
      "${MDFORMAT_BIN}" --check README.md USER_GUIDE.md AGENTS.md AGBOX_ENV_RULES.md
    )
    echo "mdformat --check README.md USER_GUIDE.md AGENTS.md AGBOX_ENV_RULES.md: OK"
  else
    echo "mdformat not found on PATH. Skipping Markdown formatting check."
  fi
}

check_02_go_vet() {
  (
    cd "${REPO_DIR}"
    with_timeout 240 go_exec vet ./...
  )
}

check_03_go_unit_race() {
  (
    cd "${REPO_DIR}"
    with_timeout 600 go_exec test -count=1 -race ./...
  )
}

check_04_build_binaries() {
  build_test_binaries
  "${TEST_BIN}" --help >/dev/null
  "${STUB_AGY_BIN}" --version
  echo "Built ${TEST_BIN} and ${STUB_AGY_BIN}"
}

# ---------------------------------------------------------------------------
# Phase 2: CLI validation, offline security boundaries, and error reporting
# ---------------------------------------------------------------------------

check_05_cli_help_and_categories() {
  build_test_binaries
  local sub=""
  local help_out=""
  help_out="$(with_timeout 15 agbox_exec "${TEST_BIN}" --help)"
  assert_contains "${help_out}" "Usage: agbox" "global --help"
  for sub in setup completion create-base edit-base update auth skills rules profile share service remote run suspend resume stop remove status; do
    help_out="$(with_timeout 15 agbox_exec "${TEST_BIN}" "${sub}" --help)"
    assert_contains "${help_out}" "Usage:" "${sub} --help"
    assert_contains "${help_out}" "agbox ${sub}" "${sub} --help command line"
  done
  for sub in serve connect policy; do
    help_out="$(with_timeout 15 agbox_exec "${TEST_BIN}" remote "${sub}" --help)"
    assert_contains "${help_out}" "agbox remote" "remote ${sub} --help"
  done

  local cats_out=""
  cats_out="$(with_timeout 15 agbox_exec "${TEST_BIN}" edit-base --list)"
  for sub in core go rust esphome embedded-rust chrome hugo caddy; do
    assert_contains "${cats_out}" "${sub}" "edit-base --list"
  done

  local err_out=""
  local rc=0
  err_out="$(AGBOX_DATA_DIR="${TEST_ROOT}/sec-data" with_timeout 15 agbox_exec "${TEST_BIN}" bogus-mode 2>&1)" || rc=$?
  [[ "${rc}" -ne 0 ]] || { echo "Expected bogus-mode to fail" >&2; return 1; }
  assert_contains "${err_out}" "[agbox] ERROR:" "bogus-mode stderr"

  rc=0
  err_out="$(AGBOX_DATA_DIR="${TEST_ROOT}/sec-data" with_timeout 15 agbox_exec "${TEST_BIN}" run --bogus-flag 2>&1)" || rc=$?
  [[ "${rc}" -ne 0 ]] || { echo "Expected --bogus-flag to fail" >&2; return 1; }
  assert_contains "${err_out}" "[agbox] ERROR:" "--bogus-flag stderr"

  # Check install.sh --help includes --remote-only, --skip-setup, and --skip-completion.
  local inst_help=""
  inst_help="$("${REPO_DIR}/install.sh" --help)"
  assert_contains "${inst_help}" "--remote-only" "install.sh --help contains --remote-only"
  assert_contains "${inst_help}" "--skip-setup" "install.sh --help contains --skip-setup"
  assert_contains "${inst_help}" "--skip-completion" "install.sh --help contains --skip-completion"

  # Check agbox completion bash output, syntax, and runtime COMPREPLY behavior.
  local comp_script="${TEST_ROOT}/agbox.bash"
  with_timeout 15 agbox_exec "${TEST_BIN}" completion bash > "${comp_script}"
  bash -n "${comp_script}"
  local comp_data="${TEST_ROOT}/comp-data"
  mkdir -p "${comp_data}/rules" "${comp_data}/profiles/devbox" "${comp_data}/run/myvm" "${comp_data}/services"
  chmod 0700 "${comp_data}" "${comp_data}/rules" "${comp_data}/profiles" "${comp_data}/profiles/devbox" "${comp_data}/run" "${comp_data}/run/myvm" "${comp_data}/services"
  printf '# rule\n' > "${comp_data}/rules/sample-rule.md"
  printf '{"name":"devbox","volume":"agbox-profile-devbox","size":"10G"}\n' > "${comp_data}/profiles/devbox/profile.json"
  printf '{"sandbox":"agbox-myvm"}\n' > "${comp_data}/run/myvm/run.meta"
  printf '{"name":"mybox","mode":"remote-control"}\n' > "${comp_data}/services/mybox.json"
  chmod 0600 "${comp_data}/rules/sample-rule.md" "${comp_data}/profiles/devbox/profile.json" "${comp_data}/run/myvm/run.meta" "${comp_data}/services/mybox.json"
  local comp_check=""
  comp_check="$(
    AGBOX_DATA_DIR="${comp_data}" bash -c '
      set -euo pipefail
      source "$1"
      COMP_WORDS=("$2" "co")
      COMP_CWORD=1
      _agbox_completions
      printf "mode=%s\n" "${COMPREPLY[*]}"
      COMP_WORDS=("$2" "create-base" "--add" "core,g")
      COMP_CWORD=3
      _agbox_completions
      printf "cat=%s\n" "${COMPREPLY[*]}"
      COMP_WORDS=("$2" "run" "--profile" "d")
      COMP_CWORD=3
      _agbox_completions
      printf "prof=%s\n" "${COMPREPLY[*]}"
      COMP_WORDS=("$2" "rules" "show" "s")
      COMP_CWORD=3
      _agbox_completions
      printf "rule=%s\n" "${COMPREPLY[*]}"
      COMP_WORDS=("$2" "suspend" "agbox-")
      COMP_CWORD=2
      _agbox_completions
      printf "sbx=%s\n" "${COMPREPLY[*]}"
      COMP_WORDS=("$2" "service" "")
      COMP_CWORD=2
      _agbox_completions
      printf "svc_act=%s\n" "${COMPREPLY[*]}"
      COMP_WORDS=("$2" "service" "add" "mybox" "--")
      COMP_CWORD=4
      _agbox_completions
      printf "svc_flags=%s\n" "${COMPREPLY[*]}"
      COMP_WORDS=("$2" "service" "logs" "my")
      COMP_CWORD=3
      _agbox_completions
      printf "svc_name=%s\n" "${COMPREPLY[*]}"
      COMP_WORDS=("$2" "remote" "")
      COMP_CWORD=2
      _agbox_completions
      printf "rem_act=%s\n" "${COMPREPLY[*]}"
    ' _ "${comp_script}" "${TEST_BIN}"
  )"
  assert_contains "${comp_check}" "mode=completion" "bash completion mode"
  assert_contains "${comp_check}" "cat=core,go" "bash completion category csv"
  assert_contains "${comp_check}" "prof=devbox" "bash completion profile"
  assert_contains "${comp_check}" "rule=sample-rule" "bash completion rule"
  assert_contains "${comp_check}" "sbx=agbox-myvm" "bash completion sandbox"
  local svc_act_line=""
  svc_act_line="$(grep '^svc_act=' <<< "${comp_check}" || true)"
  assert_contains "${svc_act_line}" "add" "bash completion service actions (add)"
  assert_contains "${svc_act_line}" "list" "bash completion service actions (list)"
  assert_contains "${svc_act_line}" "logs" "bash completion service actions (logs)"
  local svc_flags_line=""
  svc_flags_line="$(grep '^svc_flags=' <<< "${comp_check}" || true)"
  assert_contains "${svc_flags_line}" "--env-file" "bash completion service add flags (--env-file)"
  assert_contains "${svc_flags_line}" "--remote-control" "bash completion service add flags (--remote-control)"
  assert_contains "${svc_flags_line}" "--serve" "bash completion service add flags (--serve)"
  assert_contains "${svc_flags_line}" "--no-net" "bash completion service add flags (--no-net)"
  assert_contains "${comp_check}" "svc_name=mybox" "bash completion service name"
  local rem_act_line=""
  rem_act_line="$(grep '^rem_act=' <<< "${comp_check}" || true)"
  assert_contains "${rem_act_line}" "serve" "bash completion remote actions (serve)"
  assert_contains "${rem_act_line}" "connect" "bash completion remote actions (connect)"
  assert_contains "${rem_act_line}" "policy" "bash completion remote actions (policy)"

  # Check agbox --version and agbox version.
  local ver_out=""
  rc=0
  ver_out="$(with_timeout 15 agbox_exec "${TEST_BIN}" --version 2>&1)" || rc=$?
  [[ "${rc}" -eq 0 ]] || { echo "Expected agbox --version to exit 0, got ${rc}" >&2; return 1; }
  assert_contains "${ver_out}" "agbox " "agbox --version output"

  rc=0
  ver_out="$(with_timeout 15 agbox_exec "${TEST_BIN}" version 2>&1)" || rc=$?
  [[ "${rc}" -eq 0 ]] || { echo "Expected agbox version to exit 0, got ${rc}" >&2; return 1; }
  assert_contains "${ver_out}" "agbox " "agbox version output"
}

check_06_security_validation_and_tamper_checks() {
  build_test_binaries
  local sec_data="${TEST_ROOT}/sec-data"
  rm -rf "${sec_data}"
  mkdir -p "${sec_data}" "${TEST_ROOT}/sec-src"
  chmod 0700 "${sec_data}" "${TEST_ROOT}/sec-src"

  off_outside=""
  outside_tmp=""
  cleanup_06() {
    if [[ -n "${off_outside:-}" && -e "${off_outside}" ]]; then
      rm -rf "${off_outside}" 2>/dev/null || true
    fi
    if [[ -n "${outside_tmp:-}" && -e "${outside_tmp}" ]]; then
      rm -rf "${outside_tmp}" 2>/dev/null || true
    fi
  }
  trap cleanup_06 EXIT

  if [[ "${EUID_VAL}" -eq 0 ]]; then
    local root_err=""
    local root_rc=0
    root_err="$(AGBOX_ALLOW_ROOT=0 AGBOX_DATA_DIR="${sec_data}" with_timeout 15 "${TEST_BIN}" status 2>&1)" || root_rc=$?
    [[ "${root_rc}" -ne 0 ]] || { echo "Expected root run without --allow-root to fail" >&2; return 1; }
    assert_contains "${root_err}" "do not run as root" "root rejection stderr"
  fi

  local err_out=""
  local rc=0
  local -a bad_cli_cases=(
    "run --ro --rw ${TEST_ROOT}/sec-src|cannot combine --ro and --rw"
    "run --mask-vcs --vcs ${TEST_ROOT}/sec-src|conflicting VCS options"
    "run --ro --vcs-hooks ${TEST_ROOT}/sec-src|cannot combine --ro and --vcs-hooks"
    "run --share-hub --no-mask ${TEST_ROOT}/sec-src|cannot combine --no-mask and --share-hub"
    "run --serve --remote-control ${TEST_ROOT}/sec-src|--remote-control and --serve are mutually exclusive"
    "run -c -s sid ${TEST_ROOT}/sec-src|--continue (-c) and --session/--conversation are mutually exclusive"
    "run -c --serve ${TEST_ROOT}/sec-src|cannot combine --continue or --session with --serve or --cmd"
    "run -c -d --remote-control ${TEST_ROOT}/sec-src|cannot combine --continue or --session with detached --remote-control"
    "run --persist ${TEST_ROOT}/sec-src|--persist requires --name <NAME>"
    "run --persist --name p1 --profile prof ${TEST_ROOT}/sec-src|--persist and --profile are mutually exclusive"
    "run -d ${TEST_ROOT}/sec-src|--detach (-d) requires --remote-control or --serve"
    "run -d --probe|--probe"
    "run --name base ${TEST_ROOT}/sec-src|reserved for agbox-base"
    "run --name run-123 ${TEST_ROOT}/sec-src|names matching run-<digits> are reserved for PID runs"
    "run --cpus 0 ${TEST_ROOT}/sec-src|--cpus must be a positive integer"
    "run --serve --port 70000 ${TEST_ROOT}/sec-src|--port must be an integer between 1 and 65535"
    "share set agbox-test proj|agbox share set requires at least one permission flag"
    "share set --ro --rw agbox-test proj|cannot combine --ro and --rw"
    "share set --mask --vcs agbox-test proj|specify at most one of --mask-vcs, --vcs, or --vcs-hooks"
    "share set --ro --vcs-hooks agbox-test proj|cannot combine --ro and --vcs-hooks"
    "share set --ro agbox-test|usage: agbox share [--allow-root] set"
    "share rm agbox-test|usage: agbox share [--allow-root] rm"
    "share add --ro --rw agbox-test ${TEST_ROOT}/sec-src|cannot combine --ro and --rw"
    "share add --ro --vcs-hooks agbox-test ${TEST_ROOT}/sec-src|cannot combine --ro and --vcs-hooks"
    "share list agbox-base|it is the base sandbox"
    "profile create -leading-hyphen|unknown profile option"
    "service add mybox opencode|headless mode"
    "service add mybox --serve|fixed --port"
    "service add mybox -d --remote-control|do not pass --detach"
    "service add mybox --name other --remote-control|do not pass --name"
    "service add mybox --no-net --net public --cmd true|cannot combine --no-net"
    "service add base --remote-control|reserved for agbox-base"
    "service add run-123 --remote-control|names matching run-<digits> are reserved"
    "run --remote --no-remote ${TEST_ROOT}/sec-src|cannot combine --remote and --no-remote"
    "service add mybox --remote --no-remote --cmd true|cannot combine --remote and --no-remote"
    "remote serve --pass-env LD_PRELOAD|refusing dangerous --pass-env"
    "remote serve --listen 127.0.0.1:8080 --port 9090|cannot combine --listen IP:PORT with --port"
    "remote serve --allow-from ,|empty IP or CIDR entry"
    "remote connect --policy /tmp/a --no-policy 127.0.0.1:9000|cannot combine --policy and --no-policy"
    "remote connect --sandbox agbox-base 127.0.0.1:9000|it is the base sandbox"
    "remote policy check --policy /tmp/a /tmp/b|conflicting policy path"
  )
  local spec=""
  local cmd_part=""
  local want_err=""
  for spec in "${bad_cli_cases[@]}"; do
    cmd_part="${spec%%|*}"
    want_err="${spec##*|}"
    read -r -a parts <<< "${cmd_part}"
    rc=0
    err_out="$(AGBOX_DATA_DIR="${sec_data}" with_timeout 15 agbox_exec "${TEST_BIN}" "${parts[@]}" 2>&1)" || rc=$?
    [[ "${rc}" -ne 0 ]] || { echo "Expected CLI rejection for: ${cmd_part}" >&2; return 1; }
    assert_contains "${err_out}" "[agbox] ERROR:" "CLI rejection prefix for ${cmd_part}"
    assert_contains "${err_out}" "${want_err}" "CLI rejection substring for ${cmd_part}"
  done

  rc=0
  err_out="$(AGBOX_DATA_DIR="${sec_data}" with_timeout 15 agbox_exec "${TEST_BIN}" run "" 2>&1)" || rc=$?
  [[ "${rc}" -ne 0 ]] || { echo "Expected empty share path in run to fail" >&2; return 1; }
  assert_contains "${err_out}" "[agbox] ERROR:" "empty share path rejection prefix"
  assert_contains "${err_out}" "empty" "empty share path rejection detail"

  # Check that service add rejects mode-0644 and symlinked --env-file inputs.
  local bad_env_mode="${TEST_ROOT}/sec-src/bad-mode.env"
  local good_env_target="${TEST_ROOT}/sec-src/good-target.env"
  local bad_env_link="${TEST_ROOT}/sec-src/bad-link.env"
  printf 'OPENAI_API_KEY=sk-test-only\n' > "${bad_env_mode}"
  chmod 0644 "${bad_env_mode}"
  printf 'OPENAI_API_KEY=sk-test-only\n' > "${good_env_target}"
  chmod 0600 "${good_env_target}"
  ln -s "${good_env_target}" "${bad_env_link}"

  rc=0
  err_out="$(AGBOX_DATA_DIR="${sec_data}" with_timeout 15 agbox_exec "${TEST_BIN}" service add --env-file "${bad_env_mode}" mybox --cmd true 2>&1)" || rc=$?
  [[ "${rc}" -ne 0 ]] || { echo "Expected service add with mode-0644 --env-file to fail" >&2; return 1; }
  assert_contains "${err_out}" "[agbox] ERROR:" "service add 0644 env-file error prefix"
  assert_contains "${err_out}" "insecure permissions" "service add 0644 env-file error detail"

  rc=0
  err_out="$(AGBOX_DATA_DIR="${sec_data}" with_timeout 15 agbox_exec "${TEST_BIN}" service add --env-file "${bad_env_link}" mybox --cmd true 2>&1)" || rc=$?
  [[ "${rc}" -ne 0 ]] || { echo "Expected service add with symlinked --env-file to fail" >&2; return 1; }
  assert_contains "${err_out}" "[agbox] ERROR:" "service add symlink env-file error prefix"
  assert_contains "${err_out}" "symlink" "service add symlink env-file error detail"
  rm -f "${bad_env_mode}" "${good_env_target}" "${bad_env_link}"

  # Check that install.sh refuses a symlink at the target binary path.
  local inst_target_dir="${TEST_ROOT}/sec-install-dir"
  local inst_mock_bin="${TEST_ROOT}/sec-install-mock-bin"
  rm -rf "${inst_target_dir}" "${inst_mock_bin}"
  mkdir -p "${inst_target_dir}" "${inst_mock_bin}"
  chmod 0700 "${inst_target_dir}" "${inst_mock_bin}"
  ln -s /nonexistent/agbox-target "${inst_target_dir}/agbox"
  cat > "${inst_mock_bin}/msb" <<'EOF'
#!/usr/bin/env bash
echo "msb 0.7.14-mock"
EOF
  cat > "${inst_mock_bin}/fusermount3" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
  chmod 0755 "${inst_mock_bin}/msb" "${inst_mock_bin}/fusermount3"
  local -a inst_sym_args=(--skip-setup --skip-completion)
  if [[ "${ALLOW_ROOT}" -eq 1 ]]; then
    inst_sym_args+=(--allow-root)
  fi
  rc=0
  err_out="$(AGBOX_DATA_DIR="${sec_data}" AGBOX_INSTALL_DIR="${inst_target_dir}" PATH="${inst_mock_bin}:${PATH}" \
    with_timeout 120 "${REPO_DIR}/install.sh" "${inst_sym_args[@]}" 2>&1)" || rc=$?
  [[ "${rc}" -ne 0 ]] || { echo "Expected install.sh to refuse symlink at install target" >&2; return 1; }
  assert_contains "${err_out}" "Refusing to overwrite symlink" "install.sh symlink target refusal"
  [[ -L "${inst_target_dir}/agbox" ]] || { echo "Expected symlink at install target to stay untouched" >&2; return 1; }
  rm -rf "${inst_target_dir}" "${inst_mock_bin}"

  # Check that install.sh --remote-only --skip-completion works without msb or fusermount3 and installs a static ELF.
  local inst_ro_dir="${TEST_ROOT}/sec-install-ro-bin"
  local inst_ro_data="${TEST_ROOT}/sec-install-ro-data"
  local inst_ro_home="${TEST_ROOT}/sec-install-ro-home"
  local inst_ro_path="${TEST_ROOT}/sec-install-ro-path"
  rm -rf "${inst_ro_dir}" "${inst_ro_data}" "${inst_ro_home}" "${inst_ro_path}"
  mkdir -p "${inst_ro_dir}" "${inst_ro_data}" "${inst_ro_home}" "${inst_ro_path}"
  chmod 0700 "${inst_ro_dir}" "${inst_ro_data}" "${inst_ro_home}" "${inst_ro_path}"
  local ro_tool=""
  local ro_src=""
  for ro_tool in bash sh go id getent cut dirname pwd mkdir mktemp install mv rm chmod awk tr env cat; do
    ro_src="$(command -v "${ro_tool}" 2>/dev/null || true)"
    if [[ -n "${ro_src}" ]]; then
      ln -s "${ro_src}" "${inst_ro_path}/${ro_tool}"
    fi
  done
  local ro_gocache=""
  local ro_gopath=""
  local ro_gomodcache=""
  ro_gocache="$(go env GOCACHE)"
  ro_gopath="$(go env GOPATH)"
  ro_gomodcache="$(go env GOMODCACHE)"
  local -a inst_ro_args=(--remote-only --skip-completion)
  if [[ "${ALLOW_ROOT}" -eq 1 ]]; then
    inst_ro_args+=(--allow-root)
  fi
  local ro_out=""
  rc=0
  ro_out="$(
    with_timeout 120 env \
      HOME="${inst_ro_home}" \
      GOCACHE="${ro_gocache}" \
      GOPATH="${ro_gopath}" \
      GOMODCACHE="${ro_gomodcache}" \
      AGBOX_DATA_DIR="${inst_ro_data}" \
      AGBOX_INSTALL_DIR="${inst_ro_dir}" \
      PATH="${inst_ro_path}" \
      "${REPO_DIR}/install.sh" "${inst_ro_args[@]}" 2>&1
  )" || rc=$?
  [[ "${rc}" -eq 0 ]] || { echo "Expected install.sh --remote-only to succeed (rc=${rc}): ${ro_out}" >&2; return 1; }
  assert_contains "${ro_out}" "Remote-only install (--remote-only)" "install.sh --remote-only log"
  assert_contains "${ro_out}" "Skipping 'agbox setup' (--remote-only)" "install.sh --remote-only skips setup"
  [[ -x "${inst_ro_dir}/agbox" && ! -L "${inst_ro_dir}/agbox" ]] || { echo "Expected executable binary at ${inst_ro_dir}/agbox" >&2; return 1; }
  [[ ! -e "${inst_ro_data}/rules" ]] || { echo "Expected --remote-only not to install rules" >&2; return 1; }
  python3 -c '
import struct, sys
with open(sys.argv[1], "rb") as f:
    hdr = f.read(64)
    assert hdr[:4] == b"\x7fELF", "not an ELF binary"
    ei_class = hdr[4]
    ei_data = hdr[5]
    endian = "<" if ei_data == 1 else ">"
    if ei_class == 2:
        e_phoff = struct.unpack(endian + "Q", hdr[32:40])[0]
        e_phentsize, e_phnum = struct.unpack(endian + "HH", hdr[54:58])
    else:
        e_phoff = struct.unpack(endian + "I", hdr[28:32])[0]
        e_phentsize, e_phnum = struct.unpack(endian + "HH", hdr[42:44])
    for i in range(e_phnum):
        f.seek(e_phoff + i * e_phentsize)
        p_type = struct.unpack(endian + "I", f.read(4))[0]
        assert p_type != 3, "binary contains PT_INTERP (dynamic ELF)"
' "${inst_ro_dir}/agbox" || { echo "Expected static ELF binary from install.sh --remote-only" >&2; return 1; }
  local ro_help=""
  ro_help="$(with_timeout 15 agbox_exec "${inst_ro_dir}/agbox" remote --help)"
  assert_contains "${ro_help}" "agbox remote serve" "--remote-only binary remote --help"
  rm -rf "${inst_ro_dir}" "${inst_ro_data}" "${inst_ro_home}" "${inst_ro_path}"

  rc=0
  err_out="$(AGBOX_MASK_VCS=off AGBOX_DATA_DIR="${sec_data}" with_timeout 15 agbox_exec "${TEST_BIN}" run --share-hub "${TEST_ROOT}/sec-src" 2>&1)" || rc=$?
  [[ "${rc}" -ne 0 ]] || { echo "Expected AGBOX_MASK_VCS=off with --share-hub to fail" >&2; return 1; }
  assert_contains "${err_out}" "cannot combine --no-mask and --share-hub" "AGBOX_MASK_VCS=off --share-hub rejection"

  # Check that the parser rejects invalid --as guest aliases (/, .., ../escape, .git, >128 chars).
  local long_alias
  long_alias="$(printf 'a%.0s' {1..129})"
  local -a bad_alias_cases=(
    "share add --as / agbox-test ${TEST_ROOT}/sec-src|invalid guest share name"
    "share add --as .. agbox-test ${TEST_ROOT}/sec-src|invalid guest share name"
    "share add --as ../escape agbox-test ${TEST_ROOT}/sec-src|invalid guest share name"
    "share add --as .git agbox-test ${TEST_ROOT}/sec-src|cannot match VCS entry"
    "share add --as ${long_alias} agbox-test ${TEST_ROOT}/sec-src|exceeds 128 characters"
    "run ${TEST_ROOT}/sec-src:as=/|invalid guest share name"
    "run ${TEST_ROOT}/sec-src:as=..|invalid guest share name"
    "run ${TEST_ROOT}/sec-src:as=../escape|invalid guest share name"
    "run ${TEST_ROOT}/sec-src:as=.git|cannot match VCS entry"
    "run ${TEST_ROOT}/sec-src:as=${long_alias}|exceeds 128 characters"
  )
  local bad_as=""
  for bad_as in "${bad_alias_cases[@]}"; do
    cmd_part="${bad_as%%|*}"
    want_err="${bad_as##*|}"
    read -r -a parts <<< "${cmd_part}"
    rc=0
    err_out="$(AGBOX_DATA_DIR="${sec_data}" with_timeout 15 agbox_exec "${TEST_BIN}" "${parts[@]}" 2>&1)" || rc=$?
    [[ "${rc}" -ne 0 ]] || { echo "Expected alias rejection for: ${cmd_part}" >&2; return 1; }
    assert_contains "${err_out}" "[agbox] ERROR:" "alias rejection prefix for ${cmd_part}"
    assert_contains "${err_out}" "${want_err}" "alias rejection substring for ${cmd_part}"
  done

  # Check that the parser rejects --serve with antigravity.
  rc=0
  err_out="$(AGBOX_DATA_DIR="${sec_data}" with_timeout 15 agbox_exec "${TEST_BIN}" run --serve antigravity "${TEST_ROOT}/sec-src" 2>&1)" || rc=$?
  [[ "${rc}" -ne 0 ]] || { echo "Expected --serve antigravity rejection" >&2; return 1; }
  assert_contains "${err_out}" "[agbox] ERROR:" "--serve antigravity rejection"
  assert_contains "${err_out}" "--serve supports only the opencode agent" "--serve antigravity rejection detail"

  # Check offline rejection of a writable multi-hardlink single-file share via __filter -hub.
  local off_hl="${TEST_ROOT}/sec-src/off-hl.txt"
  local off_peer="${TEST_ROOT}/sec-src/off-peer.txt"
  local off_spec="${TEST_ROOT}/sec-src/off-spec.json"
  local off_mnt="${TEST_ROOT}/sec-src/off-mnt"
  mkdir -p "${off_mnt}"
  chmod 0700 "${off_mnt}"
  printf 'hardlink-offline\n' > "${off_hl}"
  ln "${off_hl}" "${off_peer}"
  cat > "${off_spec}" <<EOF
{
  "home_real": "${HOME_REAL}",
  "data_dir": "${sec_data}",
  "shares": [
    {"guest_name": "hl.txt", "host_path": "${off_hl}", "is_file": true, "read_only": false, "vcs_policy": "mask"}
  ]
}
EOF
  rc=0
  err_out="$(with_timeout 15 "${TEST_BIN}" __filter -hub -mnt "${off_mnt}" -sock "${TEST_ROOT}/sec-src/off.sock" -spec "${off_spec}" 2>&1)" || rc=$?
  [[ "${rc}" -ne 0 ]] || { echo "Expected writable multi-hardlink single-file share to fail offline" >&2; return 1; }
  assert_contains "${err_out}" "multiple hard links" "offline multi-hardlink writable file rejection"
  rm -rf "${off_hl}" "${off_peer}" "${off_spec}" "${off_mnt}"

  # Check offline rejection of a share outside $HOME via __filter -hub.
  off_outside="$(mktemp -d /tmp/agbox-sec-off-outside-XXXXXX)"
  local off_out_spec="${TEST_ROOT}/sec-src/off-out-spec.json"
  local off_out_mnt="${TEST_ROOT}/sec-src/off-out-mnt"
  mkdir -p "${off_out_mnt}"
  chmod 0700 "${off_out_mnt}"
  cat > "${off_out_spec}" <<EOF
{
  "home_real": "${HOME_REAL}",
  "data_dir": "${sec_data}",
  "allow_outside_home": false,
  "shares": [
    {"guest_name": "out", "host_path": "${off_outside}", "is_file": false, "read_only": false, "vcs_policy": "mask"}
  ]
}
EOF
  rc=0
  err_out="$(AGBOX_ALLOW_OUTSIDE_HOME=0 with_timeout 15 "${TEST_BIN}" __filter -hub -mnt "${off_out_mnt}" -sock "${TEST_ROOT}/sec-src/off-out.sock" -spec "${off_out_spec}" 2>&1)" || rc=$?
  rm -rf "${off_outside}" "${off_out_spec}" "${off_out_mnt}"
  off_outside=""
  [[ "${rc}" -ne 0 ]] || { echo 'Expected share outside $HOME to fail offline' >&2; return 1; }
  assert_contains "${err_out}" 'outside $HOME' 'offline outside-$HOME rejection'

  local sec_home="${TEST_ROOT}/sec-home"
  local sec_msb="${TEST_ROOT}/sec-msb"
  local sec_fake_bin="${TEST_ROOT}/sec-fake-bin"
  rm -rf "${sec_home}" "${sec_msb}" "${sec_fake_bin}"
  mkdir -p "${sec_home}/.ssh" "${sec_home}/.aws" "${sec_home}/proj/.git" "${sec_msb}" "${sec_fake_bin}"
  touch "${sec_home}/.gitconfig" "${sec_home}/proj/.gitignore"
  chmod 0700 "${sec_home}" "${sec_msb}" "${sec_fake_bin}"

  cat > "${sec_data}/config" <<'EOF'
agent=both
snapshot=agbox:v1
EOF
  chmod 0600 "${sec_data}/config"

  cat > "${sec_fake_bin}/msb" <<'EOF'
#!/usr/bin/env bash
sub="${1:-}"
shift || true
case "${sub}" in
  ls)
    exit 0
    ;;
  snap)
    if [[ "${1:-}" == "restore" ]]; then
      exit 0
    fi
    echo "agbox:v1 1m 100M"
    exit 0
    ;;
  rm)
    exit 0
    ;;
  *)
    exit 0
    ;;
esac
EOF
  chmod 0755 "${sec_fake_bin}/msb"

  if [[ -r /dev/kvm && -w /dev/kvm ]]; then
    # Check that pathsec rejects blocklisted paths (~/.ssh, ~/.aws, ~/.gitconfig, and $HOME root).
    local -a blocklist_shares=(
      "${sec_home}/.ssh"
      "${sec_home}/.aws"
      "${sec_home}/.gitconfig"
      "${sec_home}"
    )
    local bl=""
    for bl in "${blocklist_shares[@]}"; do
      rc=0
      err_out="$(HOME="${sec_home}" MSB_HOME="${sec_msb}" PATH="${sec_fake_bin}:${PATH}" AGBOX_DATA_DIR="${sec_data}" with_timeout 15 agbox_exec "${TEST_BIN}" run --no-net --cmd "true" "${bl}" 2>&1)" || rc=$?
      [[ "${rc}" -ne 0 ]] || { echo "Expected blocklist rejection for: ${bl}" >&2; return 1; }
      assert_contains "${err_out}" "refusing to share" "blocklist rejection for ${bl}"
    done

    # Check that the system blocklist rejects /etc and /proc even with AGBOX_ALLOW_OUTSIDE_HOME=1.
    for bl in "/etc" "/proc"; do
      rc=0
      err_out="$(HOME="${sec_home}" MSB_HOME="${sec_msb}" PATH="${sec_fake_bin}:${PATH}" AGBOX_ALLOW_OUTSIDE_HOME=1 AGBOX_DATA_DIR="${sec_data}" with_timeout 15 agbox_exec "${TEST_BIN}" run --no-net --cmd "true" "${bl}" 2>&1)" || rc=$?
      [[ "${rc}" -ne 0 ]] || { echo "Expected sensitive system rejection for: ${bl}" >&2; return 1; }
      assert_contains "${err_out}" "refusing to share a sensitive path" "system blocklist rejection for ${bl}"
    done

    # Check that pathsec rejects direct VCS paths (<proj>/.git, <proj>/.gitignore).
    for vcs_path in "${sec_home}/proj/.git" "${sec_home}/proj/.gitignore"; do
      rc=0
      err_out="$(HOME="${sec_home}" MSB_HOME="${sec_msb}" PATH="${sec_fake_bin}:${PATH}" AGBOX_DATA_DIR="${sec_data}" with_timeout 15 agbox_exec "${TEST_BIN}" run --no-net --cmd "true" "${vcs_path}" 2>&1)" || rc=$?
      [[ "${rc}" -ne 0 ]] || { echo "Expected direct VCS share rejection for: ${vcs_path}" >&2; return 1; }
      assert_contains "${err_out}" "path has VCS component" "direct VCS path rejection for ${vcs_path}"
    done

    # Check that pathsec rejects shares outside $HOME without AGBOX_ALLOW_OUTSIDE_HOME=1.
    outside_tmp="$(mktemp -d /tmp/agbox-sec-outside-XXXXXX)"
    local outside_path="${outside_tmp}"
    rc=0
    err_out="$(AGBOX_ALLOW_OUTSIDE_HOME=0 HOME="${sec_home}" MSB_HOME="${sec_msb}" PATH="${sec_fake_bin}:${PATH}" AGBOX_DATA_DIR="${sec_data}" with_timeout 15 agbox_exec "${TEST_BIN}" run --no-net --cmd "true" "${outside_tmp}" 2>&1)" || rc=$?
    rm -rf "${outside_tmp}"
    outside_tmp=""
    [[ "${rc}" -ne 0 ]] || { echo 'Expected outside-$HOME share rejection for '"${outside_path}" >&2; return 1; }
    assert_contains "${err_out}" 'outside $HOME' 'outside-$HOME rejection'

    # Check that pathsec rejects overlapping or nested host shares.
    mkdir -p "${sec_home}/proj/sub"
    rc=0
    err_out="$(HOME="${sec_home}" MSB_HOME="${sec_msb}" PATH="${sec_fake_bin}:${PATH}" AGBOX_DATA_DIR="${sec_data}" with_timeout 15 agbox_exec "${TEST_BIN}" run --no-net --cmd "true" "${sec_home}/proj" "${sec_home}/proj/sub" 2>&1)" || rc=$?
    [[ "${rc}" -ne 0 ]] || { echo "Expected overlapping shares to fail" >&2; return 1; }
    assert_contains "${err_out}" "overlapping share paths" "overlapping share paths rejection"
    rm -rf "${sec_home}/proj/sub"

    # Check that pathsec rejects writable multi-hardlink single-file shares and allows :ro multi-hardlink shares.
    local single_hl="${sec_home}/proj/hl-file.txt"
    local single_peer="${sec_home}/proj/hl-peer.txt"
    printf 'hardlink-test\n' > "${single_hl}"
    ln "${single_hl}" "${single_peer}"
    rc=0
    err_out="$(HOME="${sec_home}" MSB_HOME="${sec_msb}" PATH="${sec_fake_bin}:${PATH}" AGBOX_DATA_DIR="${sec_data}" with_timeout 15 agbox_exec "${TEST_BIN}" run --no-net --cmd "true" "${single_hl}" 2>&1)" || rc=$?
    [[ "${rc}" -ne 0 ]] || { echo "Expected writable multi-hardlink share to fail" >&2; return 1; }
    assert_contains "${err_out}" "multiple hard links" "multi-hardlink writable file rejection"

    local sec_fm_bin=""
    sec_fm_bin="$(resolve_fusermount_bin 2>/dev/null || true)"
    if [[ -r /dev/fuse && -w /dev/fuse ]] && [[ "${EUID_VAL}" -eq 0 || -n "${sec_fm_bin}" ]]; then
      HOME="${sec_home}" MSB_HOME="${sec_msb}" PATH="${sec_fake_bin}:${PATH}" AGBOX_DATA_DIR="${sec_data}" \
        with_timeout 15 agbox_exec "${TEST_BIN}" run --no-net --cmd "true" "${single_hl}:ro" >/dev/null
    fi
    rm -f "${single_hl}" "${single_peer}"

    # Check that the network builder rejects unbracketed IPv6 rules and conflicting --net none or --net all combinations.
    local -a bad_net_cases=(
      "run --net allow@2001:db8::1 --cmd true|wrap IPv6 targets in square brackets"
      "run --net deny@2001:db8::1 --cmd true|wrap IPv6 targets in square brackets"
      "run --net-rule allow@2001:db8::/32 --cmd true|wrap IPv6 targets in square brackets"
      "run --net none --net allow@example.com:tcp:443 --cmd true|cannot combine --net none with other network rules"
      "run --net all --net allow@example.com:tcp:443 --cmd true|cannot combine --net all with restrictive profiles or allow rules"
    )
    local net_spec=""
    for net_spec in "${bad_net_cases[@]}"; do
      cmd_part="${net_spec%%|*}"
      want_err="${net_spec##*|}"
      read -r -a parts <<< "${cmd_part}"
      rc=0
      err_out="$(HOME="${sec_home}" MSB_HOME="${sec_msb}" PATH="${sec_fake_bin}:${PATH}" AGBOX_DATA_DIR="${sec_data}" with_timeout 15 agbox_exec "${TEST_BIN}" "${parts[@]}" 2>&1)" || rc=$?
      [[ "${rc}" -ne 0 ]] || { echo "Expected network rule rejection for: ${cmd_part}" >&2; return 1; }
      assert_contains "${err_out}" "${want_err}" "network rule rejection for ${cmd_part}"
    done
  else
    (
      cd "${REPO_DIR}"
      with_timeout 120 go_exec test -count=1 -run TestTranslateNetSpecAndBuildNetArgs ./internal/msb >/dev/null
      with_timeout 120 go_exec test -count=1 ./internal/pathsec >/dev/null
    )
    echo "/dev/kvm not accessible. Checked network rule and share validations via offline hub and Go tests."
  fi
  rm -rf "${sec_home}" "${sec_msb}" "${sec_fake_bin}"

  # Check rules add >64 KiB and directory rejection.
  mkdir -p "${TEST_ROOT}/sec-src/rule-dir"
  rc=0
  err_out="$(AGBOX_DATA_DIR="${sec_data}" with_timeout 15 agbox_exec "${TEST_BIN}" rules add "${TEST_ROOT}/sec-src/rule-dir" 2>&1)" || rc=$?
  [[ "${rc}" -ne 0 ]] || { echo "Expected rules add on directory to fail" >&2; return 1; }
  assert_contains "${err_out}" "regular Markdown file" "rules add directory rejection"

  local big_rule="${TEST_ROOT}/sec-src/big-rule.md"
  python3 -c '
import sys
with open(sys.argv[1], "w", encoding="utf-8") as f:
    f.write("# Big\n" + "x" * 66000)
' "${big_rule}"
  rc=0
  err_out="$(AGBOX_DATA_DIR="${sec_data}" with_timeout 15 agbox_exec "${TEST_BIN}" rules add "${big_rule}" 2>&1)" || rc=$?
  [[ "${rc}" -ne 0 ]] || { echo "Expected rules add on >64 KiB file to fail" >&2; return 1; }
  assert_contains "${err_out}" "exceeds 65536 bytes" "rules add oversized rejection"
  rm -f "${big_rule}"
  rm -rf "${TEST_ROOT}/sec-src/rule-dir"

  # Check profile create invalid name rejection.
  local -a bad_profile_names=("_leading_underscore" "has/slash" "has:colon" "$(printf 'p%.0s' {1..50})")
  local bp=""
  for bp in "${bad_profile_names[@]}"; do
    rc=0
    err_out="$(AGBOX_DATA_DIR="${sec_data}" with_timeout 15 agbox_exec "${TEST_BIN}" profile create "${bp}" 2>&1)" || rc=$?
    [[ "${rc}" -ne 0 ]] || { echo "Expected profile create rejection for ${bp}" >&2; return 1; }
    assert_contains "${err_out}" "[agbox] ERROR:" "profile create rejection for ${bp}"
    assert_contains "${err_out}" "profile name" "profile create rejection detail for ${bp}"
  done

  local -a bad_envs=(
    "AGBOX_CPUS=0|invalid AGBOX_CPUS"
    "AGBOX_MEMORY=invalid|invalid AGBOX_MEMORY"
    "AGBOX_ROOT_DISK=0G|invalid AGBOX_ROOT_DISK"
    "AGBOX_AGY_INSTALLER_URL=http://plain.example.com/install.sh|invalid AGBOX_AGY_INSTALLER_URL"
    "AGBOX_AGY_INSTALLER_URL=https://example.com/install.sh;id|invalid AGBOX_AGY_INSTALLER_URL"
    "AGBOX_MASK_VCS=nope|invalid mask mode"
    "AGBOX_DATA_DIR=relative/path|invalid AGBOX_DATA_DIR"
    "MSB_HOME=relative/path|invalid MSB_HOME"
  )
  local spec_env=""
  local kv=""
  local want_env_err=""
  for spec_env in "${bad_envs[@]}"; do
    kv="${spec_env%%|*}"
    want_env_err="${spec_env##*|}"
    rc=0
    err_out="$( (
      export AGBOX_DATA_DIR="${sec_data}"
      export "${kv?}"
      with_timeout 15 agbox_exec "${TEST_BIN}" skills list
    ) 2>&1)" || rc=$?
    [[ "${rc}" -ne 0 ]] || { echo "Expected env rejection for ${kv}" >&2; return 1; }
    assert_contains "${err_out}" "[agbox] ERROR:" "env rejection for ${kv}"
    assert_contains "${err_out}" "${want_env_err}" "env rejection detail for ${kv}"
  done

  # Check skills CRUD and symlink tamper rejection.
  local out=""
  out="$(AGBOX_DATA_DIR="${sec_data}" with_timeout 15 agbox_exec "${TEST_BIN}" skills list)"
  assert_contains "${out}" "No global skills installed" "empty skills list"

  mkdir -p "${TEST_ROOT}/sec-src/myskill"
  printf '# My Skill\nTest skill instructions.\n' > "${TEST_ROOT}/sec-src/myskill/SKILL.md"
  AGBOX_DATA_DIR="${sec_data}" with_timeout 15 agbox_exec "${TEST_BIN}" skills add "${TEST_ROOT}/sec-src/myskill" >/dev/null
  out="$(AGBOX_DATA_DIR="${sec_data}" with_timeout 15 agbox_exec "${TEST_BIN}" skills list)"
  assert_contains "${out}" "myskill" "skills list"

  rc=0
  AGBOX_DATA_DIR="${sec_data}" with_timeout 15 agbox_exec "${TEST_BIN}" skills add "${TEST_ROOT}/sec-src/myskill" >/dev/null 2>&1 || rc=$?
  [[ "${rc}" -ne 0 ]] || { echo "Expected duplicate skills add without --force to fail" >&2; return 1; }
  AGBOX_DATA_DIR="${sec_data}" with_timeout 15 agbox_exec "${TEST_BIN}" skills add --force "${TEST_ROOT}/sec-src/myskill" >/dev/null

  ln -s /etc/passwd "${sec_data}/skills/evil-link"
  rc=0
  err_out="$(AGBOX_DATA_DIR="${sec_data}" with_timeout 15 agbox_exec "${TEST_BIN}" skills list 2>&1)" || rc=$?
  [[ "${rc}" -ne 0 ]] || { echo "Expected symlink in skills dir to fail closed" >&2; return 1; }
  assert_contains "${err_out}" "symlink" "skills symlink tamper error"
  rm -f "${sec_data}/skills/evil-link"
  AGBOX_DATA_DIR="${sec_data}" with_timeout 15 agbox_exec "${TEST_BIN}" skills rm myskill >/dev/null

  # Check rules CRUD and content/symlink tamper rejection.
  out="$(AGBOX_DATA_DIR="${sec_data}" with_timeout 15 agbox_exec "${TEST_BIN}" rules list)"
  assert_contains "${out}" "No global rules installed" "empty rules list"

  : > "${TEST_ROOT}/sec-src/empty.md"
  rc=0
  AGBOX_DATA_DIR="${sec_data}" with_timeout 15 agbox_exec "${TEST_BIN}" rules add "${TEST_ROOT}/sec-src/empty.md" >/dev/null 2>&1 || rc=$?
  [[ "${rc}" -ne 0 ]] || { echo "Expected empty rule file to fail" >&2; return 1; }

  printf 'hello\0world\n' > "${TEST_ROOT}/sec-src/nul.md"
  rc=0
  AGBOX_DATA_DIR="${sec_data}" with_timeout 15 agbox_exec "${TEST_BIN}" rules add "${TEST_ROOT}/sec-src/nul.md" >/dev/null 2>&1 || rc=$?
  [[ "${rc}" -ne 0 ]] || { echo "Expected NUL byte rule file to fail" >&2; return 1; }

  printf 'Always check outputs.\n' > "${TEST_ROOT}/sec-src/r1.md"
  AGBOX_DATA_DIR="${sec_data}" with_timeout 15 agbox_exec "${TEST_BIN}" rules add "${TEST_ROOT}/sec-src/r1.md" >/dev/null
  AGBOX_DATA_DIR="${sec_data}" with_timeout 15 agbox_exec "${TEST_BIN}" rules add --name named-rule "${TEST_ROOT}/sec-src/r1.md" >/dev/null
  out="$(AGBOX_DATA_DIR="${sec_data}" with_timeout 15 agbox_exec "${TEST_BIN}" rules show named-rule)"
  assert_contains "${out}" "Always check outputs." "rules show"

  ln -s /etc/passwd "${sec_data}/rules/evil.md"
  rc=0
  err_out="$(AGBOX_DATA_DIR="${sec_data}" with_timeout 15 agbox_exec "${TEST_BIN}" rules list 2>&1)" || rc=$?
  [[ "${rc}" -ne 0 ]] || { echo "Expected symlink in rules dir to fail closed" >&2; return 1; }
  assert_contains "${err_out}" "symlink" "rules symlink tamper error"
  rm -f "${sec_data}/rules/evil.md"
  AGBOX_DATA_DIR="${sec_data}" with_timeout 15 agbox_exec "${TEST_BIN}" rules rm r1 >/dev/null
  AGBOX_DATA_DIR="${sec_data}" with_timeout 15 agbox_exec "${TEST_BIN}" rules rm --all >/dev/null

  # Check default env rules installation and display.
  AGBOX_DATA_DIR="${sec_data}" with_timeout 15 agbox_exec "${TEST_BIN}" rules add "${REPO_DIR}/AGBOX_ENV_RULES.md" >/dev/null
  out="$(AGBOX_DATA_DIR="${sec_data}" with_timeout 15 agbox_exec "${TEST_BIN}" rules show AGBOX_ENV_RULES)"
  assert_contains "${out}" "Operating Inside an agbox Sandbox" "rules show AGBOX_ENV_RULES"
  AGBOX_DATA_DIR="${sec_data}" with_timeout 15 agbox_exec "${TEST_BIN}" rules rm --all >/dev/null

  # Check auth status, JSON/symlink tamper checks, and logout.
  out="$(AGBOX_DATA_DIR="${sec_data}" with_timeout 15 agbox_exec "${TEST_BIN}" auth status)"
  assert_contains "${out}" "antigravity: not configured" "auth status unconfigured"
  assert_contains "${out}" "opencode: not configured" "auth status unconfigured"

  seed_test_auth "${sec_data}"
  out="$(AGBOX_DATA_DIR="${sec_data}" with_timeout 15 agbox_exec "${TEST_BIN}" auth status)"
  assert_contains "${out}" "antigravity: configured" "auth status configured"
  assert_contains "${out}" "opencode: configured" "auth status configured"

  printf '{}\n' > "${sec_data}/auth/opencode/auth.json"
  rc=0
  err_out="$(AGBOX_DATA_DIR="${sec_data}" with_timeout 15 agbox_exec "${TEST_BIN}" auth status 2>&1)" || rc=$?
  [[ "${rc}" -ne 0 ]] || { echo "Expected empty auth.json object to fail closed" >&2; return 1; }
  assert_contains "${err_out}" "[agbox] ERROR:" "empty auth.json error prefix"
  assert_contains "${err_out}" "empty JSON object" "empty auth.json error detail"

  seed_test_auth "${sec_data}"
  ln -s /etc/passwd "${sec_data}/auth/antigravity/installation_id"
  rc=0
  err_out="$(AGBOX_DATA_DIR="${sec_data}" with_timeout 15 agbox_exec "${TEST_BIN}" auth status 2>&1)" || rc=$?
  [[ "${rc}" -ne 0 ]] || { echo "Expected symlink in auth dir to fail closed" >&2; return 1; }
  assert_contains "${err_out}" "symlink" "auth symlink tamper error"
  rm -f "${sec_data}/auth/antigravity/installation_id"

  AGBOX_DATA_DIR="${sec_data}" with_timeout 15 agbox_exec "${TEST_BIN}" auth logout all >/dev/null
  out="$(AGBOX_DATA_DIR="${sec_data}" with_timeout 15 agbox_exec "${TEST_BIN}" auth status)"
  assert_contains "${out}" "antigravity: not configured" "auth logout"

  # Check update cache SHA-256 tamper rejection, ELF magic check, and clear.
  out="$(AGBOX_DATA_DIR="${sec_data}" with_timeout 15 agbox_exec "${TEST_BIN}" update status)"
  assert_contains "${out}" "No cached agent updates." "empty update status"

  install_stub_agy_cache "${sec_data}"
  out="$(AGBOX_DATA_DIR="${sec_data}" with_timeout 15 agbox_exec "${TEST_BIN}" update status)"
  assert_contains "${out}" "antigravity: version=e2e-stub-1.0.0" "cached update status"

  printf '\xff' | dd of="${sec_data}/agents/bin/agy" bs=1 seek=64 count=1 conv=notrunc 2>/dev/null
  rc=0
  err_out="$(AGBOX_DATA_DIR="${sec_data}" with_timeout 15 agbox_exec "${TEST_BIN}" update status 2>&1)" || rc=$?
  [[ "${rc}" -ne 0 ]] || { echo "Expected SHA-256 mismatch in cached binary to fail closed" >&2; return 1; }
  assert_contains "${err_out}" "integrity check failed" "sha256 tamper error"

  printf '#!/bin/sh\necho fake-script-not-elf-padding-000000000000000000000000000000000\n' > "${sec_data}/agents/bin/agy"
  chmod 0755 "${sec_data}/agents/bin/agy"
  rc=0
  err_out="$(AGBOX_DATA_DIR="${sec_data}" with_timeout 15 agbox_exec "${TEST_BIN}" update status 2>&1)" || rc=$?
  [[ "${rc}" -ne 0 ]] || { echo "Expected non-ELF binary in cache to fail closed" >&2; return 1; }
  assert_contains "${err_out}" "ELF" "non-ELF tamper error"

  AGBOX_DATA_DIR="${sec_data}" with_timeout 15 agbox_exec "${TEST_BIN}" update clear all >/dev/null
  out="$(AGBOX_DATA_DIR="${sec_data}" with_timeout 15 agbox_exec "${TEST_BIN}" update status)"
  assert_contains "${out}" "No cached agent updates." "update clear all"
}

check_07_msb_error_diagnostics_not_swallowed() {
  build_test_binaries
  local fake_bin="${TEST_ROOT}/fake-msb-bin"
  mkdir -p "${fake_bin}" "${TEST_ROOT}/sec-data"
  chmod 0700 "${fake_bin}" "${TEST_ROOT}/sec-data"

  out_share=""
  cleanup_07() {
    if [[ -n "${out_share:-}" && -e "${out_share}" ]]; then
      rm -rf "${out_share}" 2>/dev/null || true
    fi
  }
  trap cleanup_07 EXIT

  cat > "${fake_bin}/msb" <<'EOF'
#!/usr/bin/env bash
echo "simulated msb backend failure detail" >&2
exit 23
EOF
  chmod 0755 "${fake_bin}/msb"

  local err_out=""
  local rc=0
  err_out="$(PATH="${fake_bin}:${PATH}" AGBOX_DATA_DIR="${TEST_ROOT}/sec-data" with_timeout 15 agbox_exec "${TEST_BIN}" stop "agbox-${SUITE_ID}-fake" 2>&1)" || rc=$?
  if [[ "${rc}" -ne 23 ]]; then
    printf 'Expected exit code 23 from fake msb stop, got %d\nOutput:\n%s\n' "${rc}" "${err_out}" >&2
    return 1
  fi
  assert_contains "${err_out}" "[agbox] ERROR:" "stop stderr prefix"
  assert_contains "${err_out}" "simulated msb backend failure detail" "stop stderr msb detail"

  rc=0
  err_out="$(PATH="${fake_bin}:${PATH}" AGBOX_DATA_DIR="${TEST_ROOT}/sec-data" with_timeout 15 agbox_exec "${TEST_BIN}" profile create "${SUITE_ID}-fakeprof" 2>&1)" || rc=$?
  if [[ "${rc}" -ne 23 ]]; then
    printf 'Expected exit code 23 from fake msb profile create, got %d\nOutput:\n%s\n' "${rc}" "${err_out}" >&2
    return 1
  fi
  assert_contains "${err_out}" "[agbox] ERROR:" "profile create stderr prefix"
  assert_contains "${err_out}" "simulated msb backend failure detail" "profile create stderr msb detail"

  rc=0
  err_out="$(PATH="${fake_bin}:${PATH}" AGBOX_DATA_DIR="${TEST_ROOT}/sec-data" with_timeout 15 agbox_exec "${TEST_BIN}" profile rm "${SUITE_ID}-fakeprof" 2>&1)" || rc=$?
  if [[ "${rc}" -ne 23 ]]; then
    printf 'Expected exit code 23 from fake msb profile rm, got %d\nOutput:\n%s\n' "${rc}" "${err_out}" >&2
    return 1
  fi
  assert_contains "${err_out}" "[agbox] ERROR:" "profile rm stderr prefix"
  assert_contains "${err_out}" "simulated msb backend failure detail" "profile rm stderr msb detail"

  err_out="$(PATH="${fake_bin}:${PATH}" AGBOX_DATA_DIR="${TEST_ROOT}/sec-data" with_timeout 15 agbox_exec "${TEST_BIN}" profile list 2>&1)"
  assert_contains "${err_out}" "simulated msb backend failure detail" "profile list warning msb detail"

  err_out="$(PATH="${fake_bin}:${PATH}" AGBOX_DATA_DIR="${TEST_ROOT}/sec-data" with_timeout 15 agbox_exec "${TEST_BIN}" remove --yes 2>&1)"
  assert_contains "${err_out}" "simulated msb backend failure detail" "remove --yes warning msb detail"
  mkdir -p "${TEST_ROOT}/sec-data"
  chmod 0700 "${TEST_ROOT}/sec-data"

  # Check remove --yes and status against a stateful fake msb with chained snapshots.
  local ok_fake_bin="${TEST_ROOT}/fake-msb-ok-bin"
  local ok_data="${TEST_ROOT}/clean-status-data"
  local ok_msb="${TEST_ROOT}/clean-status-msb"
  rm -rf "${ok_fake_bin}" "${ok_data}" "${ok_msb}"
  mkdir -p "${ok_fake_bin}" "${ok_data}/rules" "${ok_msb}/snapshots/agbox" "${ok_msb}/snapshots/other" "${ok_msb}/state"
  chmod 0700 "${ok_fake_bin}" "${ok_data}" "${ok_data}/rules" "${ok_msb}" "${ok_msb}/snapshots" "${ok_msb}/snapshots/agbox" "${ok_msb}/snapshots/other" "${ok_msb}/state"
  printf '# rule\n' > "${ok_data}/rules/r.md"
  chmod 0600 "${ok_data}/rules/r.md"
  printf '{"head":"v2"}\n' > "${ok_msb}/snapshots/agbox/group.json"
  printf '{"head":"v1"}\n' > "${ok_msb}/snapshots/other/group.json"
  chmod 0600 "${ok_msb}/snapshots/agbox/group.json" "${ok_msb}/snapshots/other/group.json"
  printf 'agbox:v2\n' > "${ok_msb}/state/head_agbox"
  printf 'other:v1\n' > "${ok_msb}/state/head_other"
  printf 'parent=agbox:v1\n' > "${ok_msb}/state/agbox_v2"
  printf 'child_count=1\n' > "${ok_msb}/state/agbox_v1"
  printf 'group=other\n' > "${ok_msb}/state/other_v1"
  chmod 0600 "${ok_msb}/state/head_agbox" "${ok_msb}/state/head_other" "${ok_msb}/state/agbox_v2" "${ok_msb}/state/agbox_v1" "${ok_msb}/state/other_v1"
  cat > "${ok_fake_bin}/msb" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
sub="${1:-}"
shift || true
state_dir="${MSB_HOME}/state"
case "${sub}" in
  ls)
    printf 'NAME          IMAGE                    STATUS     CREATED\n'
    exit 0
    ;;
  snap)
    ssub="${1:-}"
    shift || true
    case "${ssub}" in
      ls)
        printf 'NAME  SCOPE  MIGRATION  IMAGE  SIZE  CREATED  DIGEST\n'
        for s in agbox:v2 agbox:v1 other:v1; do
          if [[ -e "${state_dir}/${s//:/_}" ]]; then
            printf '%s  group  compatible  ubuntu  100M  1m  sha256:00\n' "${s}"
          fi
        done
        exit 0
        ;;
      head)
        target="${1:-}"
        if [[ -z "${target}" || "${target}" != *:* || ! -e "${state_dir}/${target//:/_}" ]]; then
          printf 'error: snapshot not found: %s\n' "${target}" >&2
          exit 1
        fi
        grp="${target%%:*}"
        member="${target#*:}"
        printf '%s\n' "${target}" > "${state_dir}/head_${grp}"
        if [[ -d "${MSB_HOME}/snapshots/${grp}" ]]; then
          printf '{"head":"%s"}\n' "${member}" > "${MSB_HOME}/snapshots/${grp}/group.json"
        fi
        printf 'head %s\n' "${target}" >> "${state_dir}/calls.log"
        exit 0
        ;;
      rm)
        force=0
        target=""
        while [[ $# -gt 0 ]]; do
          case "$1" in
            --force|-f)
              force=1
              shift
              ;;
            -*)
              printf 'error: unknown flag: %s\n' "$1" >&2
              exit 2
              ;;
            *)
              target="$1"
              shift
              ;;
          esac
        done
        if [[ -z "${target}" || "${target}" != *:* || ! -e "${state_dir}/${target//:/_}" ]]; then
          printf 'error: snapshot not found: %s\n' "${target}" >&2
          exit 1
        fi
        grp="${target%%:*}"
        grp_members=0
        for s in agbox:v2 agbox:v1 other:v1; do
          if [[ "${s%%:*}" == "${grp}" && -e "${state_dir}/${s//:/_}" ]]; then
            grp_members=$((grp_members + 1))
          fi
        done
        cur_head=""
        if [[ -f "${state_dir}/head_${grp}" ]]; then
          cur_head="$(<"${state_dir}/head_${grp}")"
        fi
        if [[ "${target}" == "${cur_head}" && "${grp_members}" -gt 1 ]]; then
          printf "error: invalid config: cannot remove current head '%s' while other snapshots remain in group '%s'\n" "${target}" "${grp}" >&2
          exit 1
        fi
        if [[ "${target}" == "agbox:v1" && -e "${state_dir}/agbox_v2" && "${force}" -eq 0 ]]; then
          printf 'error: snapshot %s has 1 indexed child snapshot(s): pass --force to remove anyway\n' "${target}" >&2
          exit 1
        fi
        rm -f "${state_dir}/${target//:/_}"
        if [[ "${target}" == "agbox:v2" && -f "${state_dir}/agbox_v1" ]]; then
          printf 'child_count=0\n' > "${state_dir}/agbox_v1"
        fi
        if [[ "${target}" == "${cur_head}" ]]; then
          rm -f "${state_dir}/head_${grp}"
        fi
        printf 'rm force=%d %s\n' "${force}" "${target}" >> "${state_dir}/calls.log"
        exit 0
        ;;
      reindex)
        printf 'reindex\n' >> "${state_dir}/calls.log"
        exit 0
        ;;
      *)
        exit 0
        ;;
    esac
    ;;
  volume)
    if [[ "${1:-}" == "ls" ]]; then
      printf 'NAME  KIND  SIZE\n'
    fi
    exit 0
    ;;
  image)
    exit 0
    ;;
  df)
    cat <<'DFEOF'
TYPE        COUNT   IN USE   LOGICAL SIZE   RECLAIMABLE
images      1       0        74.59 MB       74.59 MB (100%)
sandboxes   0       0        0 B            0 B
snapshots   0       -        0 B            -
volumes     0       -        0 B            -
DFEOF
    exit 0
    ;;
  *)
    exit 0
    ;;
esac
EOF
  chmod 0755 "${ok_fake_bin}/msb"

  # Check that the fake msb enforces current-head and child-snapshot rules.
  local fake_msb_err=""
  rc=0
  fake_msb_err="$(MSB_HOME="${ok_msb}" with_timeout 15 "${ok_fake_bin}/msb" snap rm --force agbox:v2 2>&1)" || rc=$?
  if [[ "${rc}" -ne 1 ]]; then
    printf 'Expected fake msb snap rm --force agbox:v2 to exit 1, got %d\nOutput:\n%s\n' "${rc}" "${fake_msb_err}" >&2
    return 1
  fi
  assert_contains "${fake_msb_err}" "error: invalid config: cannot remove current head" "fake msb current head error"

  rc=0
  fake_msb_err="$(MSB_HOME="${ok_msb}" with_timeout 15 "${ok_fake_bin}/msb" snap rm agbox:v1 2>&1)" || rc=$?
  if [[ "${rc}" -ne 1 ]]; then
    printf 'Expected fake msb snap rm agbox:v1 without --force to exit 1, got %d\nOutput:\n%s\n' "${rc}" "${fake_msb_err}" >&2
    return 1
  fi
  assert_contains "${fake_msb_err}" "has 1 indexed child snapshot(s): pass --force to remove anyway" "fake msb child snapshot error"

  local rm_out=""
  local rm_warn_out=""
  PATH="${ok_fake_bin}:${PATH}" MSB_HOME="${ok_msb}" AGBOX_DATA_DIR="${ok_data}" \
    run_capture rm_out with_timeout 30 agbox_exec "${TEST_BIN}" remove --yes
  if [[ "${EUID_VAL}" -eq 0 ]]; then
    rm_warn_out="$(grep -Fv '[agbox] WARN: Root mode is active ' <<< "${rm_out}" || true)"
  else
    rm_warn_out="${rm_out}"
  fi
  assert_not_contains "${rm_warn_out}" "[agbox] WARN:" "clean remove --yes warnings"
  if [[ -e "${ok_data}" ]]; then
    echo "Expected remove --yes to delete ${ok_data}" >&2
    return 1
  fi
  if [[ -e "${ok_msb}/state/agbox_v1" || -e "${ok_msb}/state/agbox_v2" ]]; then
    echo "Expected remove --yes to delete agbox:v1 and agbox:v2 from state" >&2
    return 1
  fi
  if [[ -e "${ok_msb}/snapshots/agbox" ]]; then
    echo "Expected remove --yes to delete ${ok_msb}/snapshots/agbox" >&2
    return 1
  fi
  if [[ ! -e "${ok_msb}/state/other_v1" || ! -f "${ok_msb}/snapshots/other/group.json" ]]; then
    echo "Expected remove --yes to keep other:v1 untouched" >&2
    return 1
  fi
  local snap_calls=""
  snap_calls="$(<"${ok_msb}/state/calls.log")"
  assert_contains "${snap_calls}" "head agbox:v1" "remove --yes switched head to agbox:v1"

  local clean_st=""
  PATH="${ok_fake_bin}:${PATH}" MSB_HOME="${ok_msb}" AGBOX_DATA_DIR="${ok_data}" \
    run_capture clean_st with_timeout 30 agbox_exec "${TEST_BIN}" status
  assert_contains "${clean_st}" "base_snapshot: not configured" "clean status base_snapshot not configured"
  assert_contains "${clean_st}" "other:v1" "clean status preserves other:v1"
  assert_not_contains "${clean_st}" "agbox:v" "clean status has no agbox snapshots"
  assert_contains "${clean_st}" "== storage ==" "clean status storage header"
  assert_contains "${clean_st}" "TYPE        COUNT   IN USE   LOGICAL SIZE   RECLAIMABLE" "clean status msb df header"
  assert_contains "${clean_st}" "volumes     0       -        0 B            -" "clean status msb df volumes row"
  if [[ -e "${ok_data}" ]]; then
    echo "Expected agbox status not to create ${ok_data}" >&2
    return 1
  fi
  rm -rf "${ok_fake_bin}" "${ok_msb}"

  if [[ -r /dev/kvm && -w /dev/kvm ]]; then
    local cmd_fake_bin="${TEST_ROOT}/fake-msb-cmd-bin"
    local cmd_data="${TEST_ROOT}/cmd-stream-data"
    local cmd_msb="${TEST_ROOT}/cmd-msb-home"
    local cmd_snap_log="${TEST_ROOT}/fake-msb-snap-restore.log"
    local cmd_stop_log="${TEST_ROOT}/fake-msb-stop.log"
    rm -rf "${cmd_fake_bin}" "${cmd_data}" "${cmd_msb}" "${cmd_snap_log}" "${cmd_stop_log}"
    mkdir -p "${cmd_fake_bin}" "${cmd_data}/skills/s1" "${cmd_msb}/volumes/agbox-profile-fakeprof"
    chmod 0700 "${cmd_fake_bin}" "${cmd_data}" "${cmd_msb}"
    : > "${cmd_stop_log}"
    cat > "${cmd_data}/config" <<'EOF'
agent=both
snapshot=agbox:v1
EOF
    chmod 0600 "${cmd_data}/config"
    printf 'FAKE_DISK' > "${cmd_msb}/volumes/agbox-profile-fakeprof/disk.raw"
    chmod 0600 "${cmd_msb}/volumes/agbox-profile-fakeprof/disk.raw"
    printf '# skill\n' > "${cmd_data}/skills/s1/SKILL.md"
    chmod 0600 "${cmd_data}/skills/s1/SKILL.md"

    cat > "${cmd_fake_bin}/msb" <<'EOF'
#!/usr/bin/env bash
sub="$1"
shift
case "${sub}" in
  ls)
    exit 0
    ;;
  snap)
    if [[ "${1:-}" == "restore" ]]; then
      if [[ -n "${FAKE_MSB_SNAP_LOG:-}" ]]; then
        printf '%s\n' "$*" >> "${FAKE_MSB_SNAP_LOG}"
      fi
      exit 0
    fi
    echo "agbox:v1 1m 100M"
    exit 0
    ;;
  volume)
    vsub="${1:-}"
    shift || true
    case "${vsub}" in
      ls)
        echo "agbox-profile-fakeprof disk 128M"
        exit 0
        ;;
      inspect)
        vname="${1:-agbox-profile-fakeprof}"
        printf 'Name: %s\nKind: disk\nPath: %s/volumes/%s/disk.raw\n' "${vname}" "${MSB_HOME}" "${vname}"
        exit 0
        ;;
      *)
        exit 0
        ;;
    esac
    ;;
  stop)
    timeout_val=""
    sbx=""
    while [[ $# -gt 0 ]]; do
      case "$1" in
        -t)
          timeout_val="$2"
          shift 2
          ;;
        -*)
          echo "unknown stop flag: $1" >&2
          exit 1
          ;;
        *)
          if [[ -z "${sbx}" ]]; then
            sbx="$1"
          else
            echo "unexpected multiple sandboxes for stop: $1" >&2
            exit 1
          fi
          shift
          ;;
      esac
    done
    if [[ -z "${sbx}" ]]; then
      echo "missing sandbox argument for stop" >&2
      exit 1
    fi
    if [[ -n "${timeout_val}" && ! "${timeout_val}" =~ ^[0-9]+$ ]]; then
      echo "invalid timeout value for stop: ${timeout_val}" >&2
      exit 1
    fi
    if [[ -n "${FAKE_MSB_STOP_LOG:-}" ]]; then
      printf 'stop %s %s\n' "${timeout_val:+-t ${timeout_val}}" "${sbx}" >> "${FAKE_MSB_STOP_LOG}"
    fi
    exit 0
    ;;
  exec)
    has_stream=0
    has_no_stdin=0
    user=""
    while [[ $# -gt 0 ]]; do
      case "$1" in
        --stream) has_stream=1; shift ;;
        --no-stdin) has_no_stdin=1; shift ;;
        -u) user="$2"; shift 2 ;;
        -e|-w) shift 2 ;;
        -t|--no-tty|-d) shift ;;
        --) shift; break ;;
        *) shift ;;
      esac
    done
    if [[ "${user}" == "root" ]]; then
      exit 0
    fi
    if [[ "${1:-}" == "sh" && "${2:-}" == "-c" ]] && grep -Fq "umask 077" <<< "${3:-}"; then
      cat >/dev/null
      exit 0
    fi
    if [[ "${1:-}" == "sh" && $# -eq 1 ]]; then
      stdin_data="$(cat)"
      if [[ -z "${stdin_data}" ]]; then
        echo "'sh' without --stream requires piped stdin" >&2
        exit 1
      fi
      exit 0
    fi
    if [[ "${has_stream}" -ne 1 ]]; then
      echo "missing --stream flag" >&2
      exit 1
    fi
    if [[ "${has_no_stdin}" -eq 0 ]]; then
      stdin_data="$(cat)"
      if [[ -z "${stdin_data}" ]]; then
        echo "'--stream' requires piped stdin or '--no-stdin'" >&2
        exit 1
      fi
      printf 'FAKE_CMD_PIPED:%s\n' "${stdin_data}"
      printf 'FAKE_CMD_PIPED_ERR\n' >&2
      exit 0
    fi
    printf 'FAKE_CMD_STDOUT_OK\n'
    printf 'FAKE_CMD_STDERR_OK\n' >&2
    exit 0
    ;;
  rm)
    exit 0
    ;;
  *)
    exit 0
    ;;
esac
EOF
    chmod 0755 "${cmd_fake_bin}/msb"

    local cmd_stdout="${TEST_ROOT}/fake-cmd.stdout"
    local cmd_stderr="${TEST_ROOT}/fake-cmd.stderr"
    PATH="${cmd_fake_bin}:${PATH}" MSB_HOME="${cmd_msb}" AGBOX_DATA_DIR="${cmd_data}" \
      FAKE_MSB_SNAP_LOG="${cmd_snap_log}" FAKE_MSB_STOP_LOG="${cmd_stop_log}" \
      with_timeout 30 agbox_exec "${TEST_BIN}" run --no-net --profile fakeprof --cmd "echo hi" </dev/null >"${cmd_stdout}" 2>"${cmd_stderr}"
    assert_contains "$(cat "${cmd_stdout}")" "FAKE_CMD_STDOUT_OK" "fake msb --cmd stdout"
    assert_not_contains "$(cat "${cmd_stdout}")" "FAKE_CMD_STDERR_OK" "fake msb --cmd stdout excludes stderr"
    assert_contains "$(cat "${cmd_stderr}")" "FAKE_CMD_STDERR_OK" "fake msb --cmd stderr"

    local stop_log=""
    stop_log="$(cat "${cmd_stop_log}")"
    assert_contains "${stop_log}" "stop -t 10" "fake msb teardown ran stop -t 10 on profile sandbox"

    local snap_log=""
    snap_log="$(cat "${cmd_snap_log}")"
    assert_contains "${snap_log}" "--mount-disk ${cmd_msb}/volumes/agbox-profile-fakeprof/disk.raw:/home/agent/.agbox-profile:rw,format=raw,fstype=ext4" "fake msb --profile mount-disk"
    assert_not_contains "${snap_log}" "-v agbox-profile-" "fake msb --profile omits dir volume flag"
    assert_contains "${snap_log}" ":ro,stat-virt=relaxed,uid=1000,gid=1000" "fake msb skills ro stat-virt=relaxed"
    assert_not_contains "${snap_log}" "stat-virt=off,uid=" "fake msb never combines stat-virt=off with uid"

    local fm_bin=""
    fm_bin="$(resolve_fusermount_bin 2>/dev/null || true)"
    if [[ -r /dev/fuse && -w /dev/fuse ]] && [[ "${EUID_VAL}" -eq 0 || -n "${fm_bin}" ]]; then
      local cmd_ws="${TEST_ROOT}/cmd-ws"
      rm -rf "${cmd_ws}"
      mkdir -p "${cmd_ws}"
      chmod 0700 "${cmd_ws}"
      : > "${cmd_snap_log}"
      PATH="${cmd_fake_bin}:${PATH}" MSB_HOME="${cmd_msb}" AGBOX_DATA_DIR="${cmd_data}" FAKE_MSB_SNAP_LOG="${cmd_snap_log}" \
        with_timeout 30 agbox_exec "${TEST_BIN}" run --no-net --cmd "echo hi" "${cmd_ws}" </dev/null >/dev/null
      snap_log="$(cat "${cmd_snap_log}")"
      assert_contains "${snap_log}" ":/workspace:rw,stat-virt=off" "fake msb workspace hub rw stat-virt=off"
      assert_not_contains "${snap_log}" "stat-virt=off,uid=" "fake msb workspace hub omits uid with stat-virt=off"
    fi

    # Check that pathsec rejects overlapping or nested host shares.
    local nest_parent="${TEST_ROOT}/nest-parent"
    local nest_child="${nest_parent}/sub"
    mkdir -p "${nest_child}"
    rc=0
    err_out="$(PATH="${cmd_fake_bin}:${PATH}" MSB_HOME="${cmd_msb}" AGBOX_DATA_DIR="${cmd_data}" \
      with_timeout 30 agbox_exec "${TEST_BIN}" run --no-net --cmd "true" "${nest_parent}" "${nest_child}" 2>&1)" || rc=$?
    [[ "${rc}" -ne 0 ]] || { echo "Expected overlapping shares to fail" >&2; return 1; }
    assert_contains "${err_out}" "overlapping share paths" "overlapping share paths rejection"
    rm -rf "${nest_parent}"

    # Check that pathsec rejects writable multi-hardlink single-file shares and allows :ro multi-hardlink shares.
    local single_hl="${TEST_ROOT}/hl-file.txt"
    local single_peer="${TEST_ROOT}/hl-peer.txt"
    printf 'hardlink-test\n' > "${single_hl}"
    ln "${single_hl}" "${single_peer}"
    rc=0
    err_out="$(PATH="${cmd_fake_bin}:${PATH}" MSB_HOME="${cmd_msb}" AGBOX_DATA_DIR="${cmd_data}" \
      with_timeout 30 agbox_exec "${TEST_BIN}" run --no-net --cmd "true" "${single_hl}" 2>&1)" || rc=$?
    [[ "${rc}" -ne 0 ]] || { echo "Expected writable multi-hardlink share to fail" >&2; return 1; }
    assert_contains "${err_out}" "multiple hard links" "multi-hardlink writable file rejection"

    if [[ -r /dev/fuse && -w /dev/fuse ]] && [[ "${EUID_VAL}" -eq 0 || -n "${fm_bin}" ]]; then
      PATH="${cmd_fake_bin}:${PATH}" MSB_HOME="${cmd_msb}" AGBOX_DATA_DIR="${cmd_data}" \
        with_timeout 30 agbox_exec "${TEST_BIN}" run --no-net --cmd "true" "${single_hl}:ro" >/dev/null
    fi
    rm -f "${single_hl}" "${single_peer}"

    # Check that pathsec accepts shares outside $HOME when AGBOX_ALLOW_OUTSIDE_HOME=1.
    if [[ -r /dev/fuse && -w /dev/fuse ]] && [[ "${EUID_VAL}" -eq 0 || -n "${fm_bin}" ]]; then
      out_share="$(mktemp -d /tmp/agbox-outshare-XXXXXX)"
      rc=0
      PATH="${cmd_fake_bin}:${PATH}" MSB_HOME="${cmd_msb}" AGBOX_DATA_DIR="${cmd_data}" AGBOX_ALLOW_OUTSIDE_HOME=1 \
        with_timeout 30 agbox_exec "${TEST_BIN}" run --no-net --cmd "true" "${out_share}" >/dev/null || rc=$?
      rm -rf "${out_share}"
      out_share=""
      [[ "${rc}" -eq 0 ]] || return "${rc}"
    fi

    local pipe_out=""
    PATH="${cmd_fake_bin}:${PATH}" MSB_HOME="${cmd_msb}" AGBOX_DATA_DIR="${cmd_data}" run_capture pipe_out \
      with_timeout_stdin 30 agbox_exec "${TEST_BIN}" run --no-net --cmd "cat" <<< 'piped-hello'
    assert_contains "${pipe_out}" "FAKE_CMD_PIPED:piped-hello" "fake msb --cmd piped stdin"
  else
    echo "/dev/kvm not accessible. Skipping CLI fake-msb --cmd streaming subcheck (covered by Go unit test)."
  fi
}

# ---------------------------------------------------------------------------
# Phase 3: Standalone embedded FUSE Workspace Hub (agbox __filter)
# ---------------------------------------------------------------------------

check_08_fuse_workspace_hub() {
  build_test_binaries

  if [[ ! -r /dev/fuse || ! -w /dev/fuse ]]; then
    if [[ "${SKIP_VM}" -eq 1 ]]; then
      skip_check "/dev/fuse is not accessible by uid ${EUID_VAL}"
    fi
    echo "/dev/fuse is not accessible by uid ${EUID_VAL}" >&2
    return 1
  fi

  local fm=""
  fm="$(resolve_fusermount_bin 2>/dev/null || true)"
  if [[ "${EUID_VAL}" -ne 0 && -z "${fm}" ]]; then
    if [[ "${SKIP_VM}" -eq 1 ]]; then
      skip_check "fusermount3/fusermount is not installed"
    fi
    echo "fusermount3/fusermount is required for unprivileged FUSE mounts" >&2
    return 1
  fi

  fbase="${TEST_ROOT}/fuse-test"
  local src_masked="${fbase}/src/masked"
  local src_vcs="${fbase}/src/vcs"
  local src_hooks="${fbase}/src/vcshooks"
  local src_ro="${fbase}/src/readonly"
  local src_single="${fbase}/src/single.txt"
  local src_hl="${fbase}/src/hl.txt"
  local src_hl_peer="${fbase}/src/hl-peer.txt"
  local fdata="${fbase}/data"
  local frun="${fbase}/run"
  local mnt="${frun}/ws"
  local sock="${frun}/ws.sock"
  local spec="${fbase}/spec.json"
  local hub_log="${fbase}/hub.log"

  rm -rf "${fbase}"
  mkdir -p "${src_masked}/.git" "${src_masked}/.GIT" "${src_masked}/.jj" "${src_masked}/.agents/skills/s1"
  mkdir -p "${src_vcs}/.git/hooks" "${src_vcs}/.bzr" "${src_vcs}/.sl" "${src_hooks}/.git/hooks" "${src_ro}" "${fdata}" "${frun}" "${mnt}"
  chmod 0700 "${fbase}" "${fdata}" "${frun}" "${mnt}"

  printf 'hello\n' > "${src_masked}/code.txt"
  printf 'secret\n' > "${src_masked}/.git/config"
  printf 'ref: main\n' > "${src_masked}/.GIT/HEAD"
  printf 'jj-secret\n' > "${src_masked}/.jj/repo"
  printf '*.secret\n' > "${src_masked}/.gitignore"
  printf '# Skill 1\n' > "${src_masked}/.agents/skills/s1/SKILL.md"
  printf '# Project Agents\n' > "${src_masked}/AGENTS.md"

  printf 'ref: main\n' > "${src_vcs}/.git/HEAD"
  printf '[core]\n\trepositoryformatversion = 0\n' > "${src_vcs}/.git/config"
  printf '#!/bin/sh\nexit 0\n' > "${src_vcs}/.git/hooks/pre-commit"

  printf 'ref: main\n' > "${src_hooks}/.git/HEAD"
  printf '#!/bin/sh\nexit 0\n' > "${src_hooks}/.git/hooks/pre-commit"
  printf 'normal-hooks\n' > "${src_hooks}/normal.txt"

  printf 'read-only-doc\n' > "${src_ro}/doc.txt"
  printf 'initial-single\n' > "${src_single}"
  printf 'hardlink-content\n' > "${src_hl}"
  ln "${src_hl}" "${src_hl_peer}"

  cat > "${spec}" <<EOF
{
  "home_real": "${HOME_REAL}",
  "data_dir": "${fdata}",
  "shares": [
    {"guest_name": "masked", "host_path": "${src_masked}", "is_file": false, "read_only": false, "vcs_policy": "mask"},
    {"guest_name": "vcs", "host_path": "${src_vcs}", "is_file": false, "read_only": false, "vcs_policy": "vcs"},
    {"guest_name": "vcshooks", "host_path": "${src_hooks}", "is_file": false, "read_only": false, "vcs_policy": "vcs-hooks"},
    {"guest_name": "single.txt", "host_path": "${src_single}", "is_file": true, "read_only": false, "vcs_policy": "mask"},
    {"guest_name": "readonly", "host_path": "${src_ro}", "is_file": false, "read_only": true, "vcs_policy": "mask"}
  ]
}
EOF

  hub_pid=""
  cleanup_fuse_check() {
    if [[ -n "${hub_pid:-}" ]]; then
      kill -TERM "${hub_pid}" 2>/dev/null || true
      wait "${hub_pid}" 2>/dev/null || true
    fi
    if [[ -n "${fbase:-}" ]]; then
      unmount_tree "${fbase}"
    fi
  }
  trap cleanup_fuse_check EXIT

  "${TEST_BIN}" __filter -hub -mnt "${mnt}" -sock "${sock}" -spec "${spec}" >"${hub_log}" 2>&1 </dev/null &
  hub_pid=$!

  local mounted=0
  local i=0
  while [[ "${i}" -lt 30 ]]; do
    if [[ -n "$(list_active_mounts_under "${mnt}")" && -S "${sock}" ]]; then
      mounted=1
      break
    fi
    if ! kill -0 "${hub_pid}" 2>/dev/null; then
      break
    fi
    sleep 0.1
    i=$((i + 1))
  done

  if [[ "${mounted}" -ne 1 ]]; then
    local htxt=""
    htxt="$(cat "${hub_log}" 2>/dev/null || true)"
    if [[ "${SKIP_VM}" -eq 1 ]]; then
      skip_check "FUSE hub could not mount in this environment (${htxt})"
    fi
    printf 'FUSE workspace hub failed to mount:\n%s\n' "${htxt}" >&2
    return 1
  fi

  local sock_mode=""
  sock_mode="$(stat -c '%a' "${sock}")"
  [[ "${sock_mode}" == "600" ]] || { echo "Expected ws.sock mode 600, got ${sock_mode}" >&2; return 1; }

  # Check single-file slot read, write, truncate, and writable hardlink (nlink > 1) rejection.
  [[ "$(cat "${mnt}/single.txt")" == "initial-single" ]] || return 1
  printf 'updated-single-content\n' > "${mnt}/single.txt"
  [[ "$(cat "${src_single}")" == "updated-single-content" ]] || return 1
  python3 -c '
import os, sys, socket, json
single_mnt = sys.argv[1]
sock_path = sys.argv[2]
hl_path = sys.argv[3]
os.truncate(single_mnt, 7)
with open(single_mnt, "r", encoding="utf-8") as f:
    assert f.read() == "updated"

s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect(sock_path)
req = {
    "op": "add",
    "add": {
        "guest_name": "hl.txt",
        "host_path": hl_path,
        "is_file": True,
        "read_only": False,
        "vcs_policy": "mask",
    },
}
s.sendall(json.dumps(req).encode("utf-8"))
s.shutdown(socket.SHUT_WR)
resp = json.loads(s.recv(4096).decode("utf-8"))
s.close()
assert resp.get("ok") is False, resp
assert "multiple hard links" in resp.get("error", ""), resp
' "${mnt}/single.txt" "${sock}" "${src_hl}" || { echo "Single-file share or hardlink check failed" >&2; return 1; }
  [[ "$(cat "${src_single}")" == "updated" ]] || return 1

  # Check masked share: code and agent files are readable, writes pass through, and VCS paths stay hidden.
  [[ "$(cat "${mnt}/masked/code.txt")" == "hello" ]] || return 1
  [[ -f "${mnt}/masked/.agents/skills/s1/SKILL.md" ]] || return 1
  [[ -f "${mnt}/masked/AGENTS.md" ]] || return 1
  printf 'updated\n' > "${mnt}/masked/code.txt"
  [[ "$(cat "${src_masked}/code.txt")" == "updated" ]] || return 1

  local hidden_path=""
  for hidden_path in ".git" ".GIT" ".jj" ".gitignore"; do
    if [[ -e "${mnt}/masked/${hidden_path}" || -L "${mnt}/masked/${hidden_path}" ]]; then
      echo "Expected ${hidden_path} to be hidden inside masked share" >&2
      return 1
    fi
  done

  python3 -c '
import os, sys, errno
mnt = sys.argv[1]
try:
    os.mkdir(os.path.join(mnt, "masked/.git"))
    sys.exit(1)
except OSError as e:
    if e.errno != errno.EPERM:
        sys.exit(2)
' "${mnt}" || { echo "Expected mkdir .git to fail with EPERM inside masked share" >&2; return 1; }

  python3 -c '
import os, sys, errno
mnt = sys.argv[1]
try:
    os.symlink("/etc/passwd", os.path.join(mnt, "masked/esc"))
    sys.exit(1)
except OSError as e:
    if e.errno != errno.EPERM:
        sys.exit(2)
' "${mnt}" || { echo "Expected outside symlink to fail with EPERM inside masked share" >&2; return 1; }

  python3 -c '
import os, sys, errno
mnt = sys.argv[1]
try:
    os.symlink(".git/config", os.path.join(mnt, "masked/gitlink"))
    sys.exit(1)
except OSError as e:
    if e.errno != errno.EPERM:
        sys.exit(2)
' "${mnt}" || { echo "Expected VCS symlink to fail with EPERM inside masked share" >&2; return 1; }

  python3 -c '
import os, sys, errno
mnt = sys.argv[1]
try:
    os.mkfifo(os.path.join(mnt, "masked/fifo"))
    sys.exit(1)
except OSError as e:
    if e.errno != errno.EPERM:
        sys.exit(2)
' "${mnt}" || { echo "Expected mkfifo inside masked share to fail with EPERM" >&2; return 1; }

  # Check that Setattr rejects SUID/SGID chmod with EPERM and Create strips SUID/SGID via sanitizeCreateMode.
  python3 -c '
import os, sys, stat, errno
mnt = sys.argv[1]
code_path = os.path.join(mnt, "masked/code.txt")
orig_mode = stat.S_IMODE(os.stat(code_path).st_mode)
try:
    os.chmod(code_path, orig_mode | stat.S_ISUID | stat.S_ISGID)
    sys.exit(1)
except OSError as e:
    if e.errno != errno.EPERM:
        sys.exit(2)

create_path = os.path.join(mnt, "masked/suid_create.txt")
fd = os.open(create_path, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o6755)
os.close(fd)
created_mode = stat.S_IMODE(os.lstat(create_path).st_mode)
os.unlink(create_path)
if created_mode & (stat.S_ISUID | stat.S_ISGID):
    sys.exit(3)
' "${mnt}" || { echo "SUID and SGID enforcement check failed on masked share" >&2; return 1; }

  # Check that Rename rejects symlink depth reduction that escapes the share root.
  python3 -c '
import os, sys, errno, shutil
mnt = sys.argv[1]
deep_dir = os.path.join(mnt, "masked/a/b")
os.makedirs(deep_dir, exist_ok=True)
sym_path = os.path.join(deep_dir, "deep_link")
os.symlink("../../code.txt", sym_path)
try:
    os.rename(sym_path, os.path.join(mnt, "masked/escaped_top"))
    sys.exit(1)
except OSError as e:
    if e.errno != errno.EPERM:
        sys.exit(2)
try:
    os.rename(deep_dir, os.path.join(mnt, "masked/b_top"))
    sys.exit(3)
except OSError as e:
    if e.errno != errno.EPERM:
        sys.exit(4)
shutil.rmtree(os.path.join(mnt, "masked/a"))
' "${mnt}" || { echo "Expected Rename escaping symlink depth reduction to fail with EPERM" >&2; return 1; }

  if python3 -c '
import os, sys, errno
mnt = sys.argv[1]
try:
    os.setxattr(os.path.join(mnt, "masked/code.txt"), "trusted.test", b"1")
    sys.exit(1)
except OSError as e:
    if e.errno != errno.EPERM:
        sys.exit(2)
' "${mnt}" 2>/dev/null; then
    :
  else
    echo "Expected setxattr(trusted.test) to fail with EPERM" >&2
    return 1
  fi

  python3 -c '
import os, sys, errno
mnt = sys.argv[1]
try:
    os.setxattr(os.path.join(mnt, "masked/code.txt"), "user.test", b"1")
except OSError as e:
    if e.errno == errno.EPERM:
        sys.exit(1)
    if e.errno not in (errno.EOPNOTSUPP, getattr(errno, "ENOTSUP", errno.EOPNOTSUPP)):
        sys.exit(2)
' "${mnt}" || { echo "Expected user.test xattr not to be blocked by EPERM" >&2; return 1; }

  # Check VCS-allowed share: .git/HEAD is writable, and the filter protects .git/config, hooks, and admin dirs.
  [[ -f "${mnt}/vcs/.git/HEAD" ]] || return 1
  [[ -f "${mnt}/vcs/.git/config" ]] || return 1
  printf 'ref: refs/heads/dev\n' > "${mnt}/vcs/.git/HEAD"
  python3 -c '
import os, sys, errno
mnt = sys.argv[1]
for cfg_rel in ("vcs/.git/config", "vcs/.git/config.worktree"):
    try:
        with open(os.path.join(mnt, cfg_rel), "a", encoding="utf-8") as f:
            f.write("# evil\n")
        sys.exit(1)
    except OSError as e:
        if e.errno != errno.EPERM:
            sys.exit(2)

os.mkdir(os.path.join(mnt, "vcs/sub"))
for admin_rel in ("vcs/.jj", "vcs/sub/.git"):
    try:
        os.mkdir(os.path.join(mnt, admin_rel))
        sys.exit(3)
    except OSError as e:
        if e.errno != errno.EPERM:
            sys.exit(4)
os.rmdir(os.path.join(mnt, "vcs/sub"))
' "${mnt}" || { echo "Expected .git/config.worktree write and top-level VCS admin mkdir to fail with EPERM under vcs policy" >&2; return 1; }
  if { printf 'evil\n' > "${mnt}/vcs/.git/hooks/pre-commit"; } 2>/dev/null; then
    echo "Expected write to .git/hooks/pre-commit to fail under vcs policy" >&2
    return 1
  fi
  if rm -rf "${mnt}/vcs/.git" 2>/dev/null; then
    echo "Expected rm -rf .git to fail under vcs policy" >&2
    return 1
  fi
  if rm -rf "${mnt}/vcs/.bzr" 2>/dev/null; then
    echo "Expected rm -rf .bzr to fail under vcs policy" >&2
    return 1
  fi
  if rm -rf "${mnt}/vcs/.sl" 2>/dev/null; then
    echo "Expected rm -rf .sl to fail under vcs policy" >&2
    return 1
  fi

  # Check vcs-hooks share: hook writes succeed, cross-boundary hardlinks and multi-link renames fail, and downgrade revokes open hook FDs.
  printf '#!/bin/sh\necho hook-updated\n' > "${mnt}/vcshooks/.git/hooks/pre-commit"
  grep -Fq "hook-updated" "${src_hooks}/.git/hooks/pre-commit" || return 1
  python3 -c '
import os, sys, socket, json, errno
mnt = sys.argv[1]
sock_path = sys.argv[2]

def hub_req(payload):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect(sock_path)
    s.sendall(json.dumps(payload).encode("utf-8"))
    s.shutdown(socket.SHUT_WR)
    resp = json.loads(s.recv(4096).decode("utf-8"))
    s.close()
    return resp

norm_path = os.path.join(mnt, "vcshooks/normal.txt")
pre_hook = os.path.join(mnt, "vcshooks/.git/hooks/pre-commit")
post_hook = os.path.join(mnt, "vcshooks/.git/hooks/post-commit")
head_path = os.path.join(mnt, "vcshooks/.git/HEAD")

for src_p, dst_p in (
    (norm_path, post_hook),
    (pre_hook, os.path.join(mnt, "vcshooks/hook_alias")),
    (norm_path, os.path.join(mnt, "vcshooks/.git/HEAD_ALIAS")),
    (head_path, os.path.join(mnt, "vcshooks/head_alias")),
):
    try:
        os.link(src_p, dst_p)
        sys.exit(1)
    except OSError as e:
        assert e.errno == errno.EPERM, (src_p, dst_p, e)

os.link(pre_hook, post_hook)
peer_path = os.path.join(mnt, "vcshooks/normal_peer.txt")
os.link(norm_path, peer_path)
try:
    os.rename(peer_path, os.path.join(mnt, "vcshooks/.git/hooks/multi_hook"))
    sys.exit(2)
except OSError as e:
    assert e.errno == errno.EPERM, e
os.unlink(peer_path)

hook_fd = os.open(pre_hook, os.O_RDWR)
norm_fd = os.open(norm_path, os.O_RDWR)

staged_dir = os.path.join(mnt, "vcshooks/staged_dir")
os.mkdir(staged_dir)
moved_dir_fd = os.open(os.path.join(staged_dir, "hook_script"), os.O_CREAT | os.O_RDWR | os.O_TRUNC, 0o755)
os.rename(staged_dir, os.path.join(mnt, "vcshooks/.git/hooks/sub"))

resp_noforce = hub_req({"op": "set", "name": "vcshooks", "vcs_policy": "vcs", "force": False})
assert resp_noforce.get("ok") is False, resp_noforce
assert "open writable file handle" in resp_noforce.get("error", ""), resp_noforce

resp_force = hub_req({"op": "set", "name": "vcshooks", "vcs_policy": "vcs", "force": True})
assert resp_force.get("ok") is True, resp_force

for revoked_fd in (hook_fd, moved_dir_fd):
    try:
        os.write(revoked_fd, b"# blocked\n")
        sys.exit(3)
    except OSError as e:
        assert e.errno == errno.EROFS, e
    finally:
        os.close(revoked_fd)

os.lseek(norm_fd, 0, os.SEEK_SET)
os.write(norm_fd, b"normal-still-ok\n")
os.close(norm_fd)
' "${mnt}" "${sock}" || { echo "vcs-hooks to vcs downgrade check failed" >&2; return 1; }
  grep -Fq "normal-still-ok" "${src_hooks}/normal.txt" || return 1

  # Check live SetShare VCS policy downgrade to mask over ws.sock.
  python3 -c '
import socket, json, os, sys, errno
mnt = sys.argv[1]
sock_path = sys.argv[2]
cfg_path = os.path.join(mnt, "vcs/.git/config")
cfg_fd = os.open(cfg_path, os.O_RDONLY)
try:
    data = os.read(cfg_fd, 64)
    assert b"repositoryformatversion" in data, data

    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect(sock_path)
    s.sendall(json.dumps({"op": "set", "name": "vcs", "vcs_policy": "mask", "force": True}).encode("utf-8"))
    s.shutdown(socket.SHUT_WR)
    resp = json.loads(s.recv(4096).decode("utf-8"))
    s.close()
    assert resp.get("ok") is True, resp

    os.lseek(cfg_fd, 0, os.SEEK_SET)
    try:
        os.read(cfg_fd, 64)
        raise AssertionError("revoked vcs read fd unexpectedly remained readable")
    except OSError as e:
        assert e.errno in (errno.ESTALE, errno.ENOENT, errno.EBADF, errno.EIO), e
finally:
    os.close(cfg_fd)
' "${mnt}" "${sock}" || { echo "SetShare VCS policy downgrade request failed" >&2; return 1; }
  if [[ -e "${mnt}/vcs/.git" ]]; then
    echo "Expected .git to be masked after live VCS policy downgrade to mask" >&2
    return 1
  fi
  if [[ -e "${mnt}/vcs/.git/config" ]]; then
    echo "Expected .git/config to be masked after live VCS policy downgrade to mask" >&2
    return 1
  fi

  # Check live ws.sock set rw -> ro (EROFS on open write FD with force, readable read FD) and live share rm (ESTALE).
  python3 -c '
import socket, json, os, sys, errno
mnt = sys.argv[1]
sock_path = sys.argv[2]

def hub_req(payload):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect(sock_path)
    s.sendall(json.dumps(payload).encode("utf-8"))
    s.shutdown(socket.SHUT_WR)
    resp = json.loads(s.recv(4096).decode("utf-8"))
    s.close()
    return resp

code_path = os.path.join(mnt, "masked/code.txt")
w_fd = os.open(code_path, os.O_RDWR)
r_fd = os.open(code_path, os.O_RDONLY)

r1 = hub_req({"op": "set", "name": "masked", "read_only": True, "force": False})
assert r1.get("ok") is False, r1
assert "open writable file handle" in r1.get("error", ""), r1

r2 = hub_req({"op": "set", "name": "masked", "read_only": True, "force": True})
assert r2.get("ok") is True, r2

try:
    os.write(w_fd, b"blocked\n")
    sys.exit(1)
except OSError as e:
    assert e.errno == errno.EROFS, e
finally:
    os.close(w_fd)

os.lseek(r_fd, 0, os.SEEK_SET)
assert os.read(r_fd, 64) == b"updated\n"
os.close(r_fd)

r3 = hub_req({"op": "set", "name": "masked", "read_only": False})
assert r3.get("ok") is True, r3

rm_fd = os.open(code_path, os.O_RDWR)
r4 = hub_req({"op": "rm", "name": "masked", "force": False})
assert r4.get("ok") is False, r4
assert "open writable file handle" in r4.get("error", ""), r4

r5 = hub_req({"op": "rm", "name": "masked", "force": True})
assert r5.get("ok") is True, r5

try:
    os.write(rm_fd, b"stale\n")
    sys.exit(2)
except OSError as e:
    assert e.errno == errno.ESTALE, e
finally:
    os.close(rm_fd)
' "${mnt}" "${sock}" || { echo "Live ws.sock rw->ro or remove revocation check failed" >&2; return 1; }
  if [[ -e "${mnt}/masked" ]]; then
    echo "Expected masked share directory to be deleted from /workspace after live remove" >&2
    return 1
  fi

  # Check read-only share: reads succeed and writes fail.
  [[ "$(cat "${mnt}/readonly/doc.txt")" == "read-only-doc" ]] || return 1
  if { printf 'nope\n' > "${mnt}/readonly/new.txt"; } 2>/dev/null; then
    echo "Expected write to read-only share to fail" >&2
    return 1
  fi

  # Check clean unmount.
  kill -TERM "${hub_pid}" 2>/dev/null || true
  wait "${hub_pid}" 2>/dev/null || true
  hub_pid=""
  unmount_tree "${fbase}"
  if [[ -n "$(list_active_mounts_under "${mnt}")" ]]; then
    echo "FUSE hub mount remained active after teardown" >&2
    return 1
  fi
}

check_08b_remote_bridge_and_loopback() {
  build_test_binaries

  if [[ ! -r /dev/fuse || ! -w /dev/fuse ]]; then
    if [[ "${SKIP_VM}" -eq 1 ]]; then
      skip_check "/dev/fuse is not accessible by uid ${EUID_VAL}"
    fi
    echo "/dev/fuse is not accessible by uid ${EUID_VAL}" >&2
    return 1
  fi

  local fm=""
  fm="$(resolve_fusermount_bin 2>/dev/null || true)"
  if [[ "${EUID_VAL}" -ne 0 && -z "${fm}" ]]; then
    if [[ "${SKIP_VM}" -eq 1 ]]; then
      skip_check "fusermount3/fusermount is not installed"
    fi
    echo "fusermount3/fusermount is required for unprivileged FUSE mounts" >&2
    return 1
  fi

  rbase="${TEST_ROOT}/remote-bridge-test"
  local rdata="${rbase}/data"
  local rrun="${rdata}/run/e2e"
  local mnt="${rrun}/remote"
  local sock="${rrun}/remote.sock"
  local pidfile="${rrun}/remote.pid"
  local pol="${rbase}/policy.json"
  local rwork="${rbase}/work"
  local bridge_log="${rbase}/bridge.log"

  rm -rf "${rbase}"
  mkdir -p "${rrun}" "${mnt}" "${rwork}"
  chmod 0700 "${rbase}" "${rdata}" "${rdata}/run" "${rrun}" "${mnt}" "${rwork}"
  printf '{"sandbox":"agbox-e2e","owner_pid":%d,"remote_bridge":true}\n' "$$" > "${rrun}/run.meta"
  chmod 0600 "${rrun}/run.meta"

  bridge_pid=""
  cleanup_remote_bridge_check() {
    if [[ -n "${bridge_pid:-}" ]]; then
      kill -TERM "${bridge_pid}" 2>/dev/null || true
      wait "${bridge_pid}" 2>/dev/null || true
    fi
    if [[ -n "${rbase:-}" ]]; then
      unmount_tree "${rbase}"
    fi
  }
  trap cleanup_remote_bridge_check EXIT

  "${TEST_BIN}" __filter -bridge -mnt "${mnt}" -sock "${sock}" -guest-uid "${EUID_VAL}" -guest-gid "$(id -g)" >"${bridge_log}" 2>&1 </dev/null &
  bridge_pid=$!
  printf '%d\n' "${bridge_pid}" > "${pidfile}"
  chmod 0600 "${pidfile}"

  local mounted=0
  local i=0
  while [[ "${i}" -lt 30 ]]; do
    if [[ -n "$(list_active_mounts_under "${mnt}")" && -S "${sock}" ]]; then
      mounted=1
      break
    fi
    if ! kill -0 "${bridge_pid}" 2>/dev/null; then
      echo "Remote bridge exited early:" >&2
      cat "${bridge_log}" >&2 || true
      return 1
    fi
    sleep 0.2
    i=$((i + 1))
  done
  if [[ "${mounted}" -ne 1 ]]; then
    echo "Timed out waiting for remote bridge mount:" >&2
    cat "${bridge_log}" >&2 || true
    return 1
  fi

  # Verify INSTRUCTIONS.md and direct execve of the FUSE-served static ELF agbox-remote.
  local instr_txt=""
  instr_txt="$(cat "${mnt}/INSTRUCTIONS.md")"
  assert_contains "${instr_txt}" "agbox-remote" "bridge INSTRUCTIONS.md"

  local help_rc=0
  "${mnt}/bin/agbox-remote" --help >/dev/null 2>&1 || help_rc=$?
  [[ "${help_rc}" -eq 0 ]] || { echo "Expected execve of ${mnt}/bin/agbox-remote --help to exit 0, got ${help_rc}" >&2; return 1; }

  # Unattached bridge returns uniform exit 126.
  local deny_out=""
  local deny_rc=0
  deny_out="$(AGBOX_REMOTE_DIR="${mnt}" with_timeout 15 "${mnt}/bin/agbox-remote" uname -a 2>&1)" || deny_rc=$?
  [[ "${deny_rc}" -eq 126 ]] || { echo "Expected exit 126 when unattached, got ${deny_rc}: ${deny_out}" >&2; return 1; }
  assert_contains "${deny_out}" "agbox-remote: command denied" "unattached deny stderr"

  # Initialize and check starter policy.
  AGBOX_DATA_DIR="${rdata}" with_timeout 15 agbox_exec "${TEST_BIN}" remote policy init --output "${pol}" >/dev/null
  AGBOX_DATA_DIR="${rdata}" with_timeout 15 agbox_exec "${TEST_BIN}" remote policy check "${pol}" >/dev/null

  # Exercise full PTY pairing (no test-only bypass flags), allow, deny, ask + redaction, and fail-closed reload.
  python3 -c '
import os, pty, re, select, signal, subprocess, sys, time

test_bin, mnt, rdata, pol, rwork, allow_root = sys.argv[1:7]
base_cmd = [test_bin] + (["--allow-root"] if allow_root == "1" else [])
client_bin = os.path.join(mnt, "bin", "agbox-remote")

env = os.environ.copy()
env["AGBOX_DATA_DIR"] = rdata
env["AGBOX_REMOTE_DIR"] = mnt

def spawn_pty(cmd, cwd=None):
    mfd, sfd = pty.openpty()
    p = subprocess.Popen(cmd, stdin=sfd, stdout=sfd, stderr=sfd, env=env, cwd=cwd, close_fds=True, start_new_session=True)
    os.close(sfd)
    return p, mfd

def read_until(mfd, pattern, buf, timeout=15.0):
    rx = re.compile(pattern)
    end = time.time() + timeout
    while time.time() < end:
        m = rx.search(buf)
        if m:
            return buf, m
        r, _, _ = select.select([mfd], [], [], 0.1)
        if r:
            try:
                chunk = os.read(mfd, 4096)
            except OSError:
                break
            if not chunk:
                break
            buf += chunk.decode("utf-8", "replace")
    raise RuntimeError(f"timeout waiting for {pattern!r}, got:\n{buf}")

def drain_fd(mfd, buf, wait=0.3):
    end = time.time() + wait
    while time.time() < end:
        r, _, _ = select.select([mfd], [], [], 0.05)
        if not r:
            continue
        try:
            chunk = os.read(mfd, 4096)
        except OSError:
            break
        if not chunk:
            break
        buf += chunk.decode("utf-8", "replace")
    return buf

srv_p, srv_fd = spawn_pty(base_cmd + ["remote", "serve", "--listen", "127.0.0.1:0", "--allow-from", "127.0.0.1/32", "--allow-cwd", rwork], cwd=rwork)
brk_p, brk_fd = None, None
try:
    srv_buf, m_addr = read_until(srv_fd, r"127\.0\.0\.1:(\d+)", "")
    addr = m_addr.group(0)

    brk_p, brk_fd = spawn_pty(base_cmd + ["remote", "connect", "--sandbox", "agbox-e2e", "--policy", pol, addr])
    sas_pat = r"([0-9A-Z]{4}-[0-9A-Z]{4}-[0-9A-Z]{4})"
    srv_buf, m_srv_sas = read_until(srv_fd, sas_pat, srv_buf)
    brk_buf, m_brk_sas = read_until(brk_fd, sas_pat, "")
    assert m_srv_sas.group(1) == m_brk_sas.group(1), (m_srv_sas.group(1), m_brk_sas.group(1))

    os.write(srv_fd, b"y\n")
    os.write(brk_fd, b"y\n")
    brk_buf, m_att = read_until(brk_fd, r"Attached to sandbox", brk_buf)
    brk_buf = brk_buf[m_att.end():]

    # 1. Auto-approved command succeeds.
    r1 = subprocess.run([client_bin, "uname", "-a"], env=env, capture_output=True, text=True, timeout=15)
    if not (r1.returncode == 0 and "Linux" in r1.stdout):
        brk_buf = drain_fd(brk_fd, brk_buf)
        srv_buf = drain_fd(srv_fd, srv_buf)
        raise AssertionError(f"r1 failed: rc={r1.returncode} out={r1.stdout!r} err={r1.stderr!r}\n--- BRK ---\n{brk_buf}\n--- SRV ---\n{srv_buf}")

    # 1b. --allow-cwd canonical rejection over live wire returns uniform exit 126.
    r_cwd = subprocess.run([client_bin, "--cwd", "/etc", "uname", "-a"], env=env, capture_output=True, text=True, timeout=15)
    assert r_cwd.returncode == 126 and r_cwd.stderr.strip() == "agbox-remote: command denied", (r_cwd.returncode, r_cwd.stdout, r_cwd.stderr)

    # 2. Auto-denied command returns uniform exit 126.
    r2 = subprocess.run([client_bin, "rm", "-rf", "/"], env=env, capture_output=True, text=True, timeout=15)
    assert r2.returncode == 126 and r2.stderr.strip() == "agbox-remote: command denied", (r2.returncode, r2.stderr)

    # 3. Prompted command approved with [a] returns baseline-redacted stdout.
    p3 = subprocess.Popen([client_bin, "echo", "AKIAIOSFODNN7EXAMPLE"], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    brk_buf, m_p3 = read_until(brk_fd, r"Choice \(\[a\]pprove", brk_buf)
    brk_buf = brk_buf[m_p3.end():]
    os.write(brk_fd, b"a\n")
    out3, err3 = p3.communicate(timeout=15)
    assert p3.returncode == 0, (p3.returncode, out3, err3)
    assert "[REDACTED:AWS_KEY]" in out3 and "AKIAIOSFODNN7EXAMPLE" not in out3, out3

    # 3b. --stdin-file over live FUSE mount echoes file contents cleanly.
    stdin_path = os.path.join(rwork, "stdin-payload.txt")
    with open(stdin_path, "w", encoding="utf-8") as f:
        f.write("hello-stdin-file-e2e\n")
    p_stdin = subprocess.Popen([client_bin, "--stdin-file", stdin_path, "cat"], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    brk_buf, m_ps = read_until(brk_fd, r"Choice \(\[a\]pprove", brk_buf)
    brk_buf = brk_buf[m_ps.end():]
    os.write(brk_fd, b"a\n")
    out_s, err_s = p_stdin.communicate(timeout=15)
    assert p_stdin.returncode == 0 and out_s == "hello-stdin-file-e2e\n", (p_stdin.returncode, out_s, err_s)

    # 3c. agbox status reports == remote == and agbox-e2e: connected while attached.
    st_res = subprocess.run(base_cmd + ["status"], env=env, capture_output=True, text=True, timeout=15)
    assert st_res.returncode == 0, (st_res.returncode, st_res.stdout, st_res.stderr)
    assert "== remote ==" in st_res.stdout and "agbox-e2e: connected" in st_res.stdout, st_res.stdout

    # 4. Corrupt policy hot-reloads to fail-closed DENY-ALL.
    with open(pol, "w") as f:
        f.write("{corrupt")
    r4 = subprocess.run([client_bin, "uname", "-a"], env=env, capture_output=True, text=True, timeout=15)
    assert r4.returncode == 126, (r4.returncode, r4.stdout, r4.stderr)

    # Clean quit.
    os.write(brk_fd, b"q\n")
    brk_p.wait(timeout=10)
finally:
    for p, fd in ((brk_p, brk_fd), (srv_p, srv_fd)):
        if p is not None and p.poll() is None:
            try:
                os.killpg(p.pid, signal.SIGTERM)
            except OSError:
                pass
            try:
                p.wait(timeout=5)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(p.pid, signal.SIGKILL)
                except OSError:
                    pass
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass
' "${TEST_BIN}" "${mnt}" "${rdata}" "${pol}" "${rwork}" "${ALLOW_ROOT}" || { echo "Live remote bridge PTY loopback failed" >&2; return 1; }

  # Verify clean unmount.
  kill -TERM "${bridge_pid}" 2>/dev/null || true
  wait "${bridge_pid}" 2>/dev/null || true
  bridge_pid=""
  unmount_tree "${rbase}"
  if [[ -n "$(list_active_mounts_under "${mnt}")" ]]; then
    echo "Remote FUSE bridge mount remained active after teardown" >&2
    return 1
  fi
}

# ---------------------------------------------------------------------------
# Phase 4: Virtualization preflight and environment preparation
# ---------------------------------------------------------------------------

check_09_kvm_and_msb_preflight() {
  build_test_binaries

  local missing=()
  if [[ -z "${MSB_BIN_PATH}" ]]; then
    missing+=("msb binary missing on PATH, ~/.local/bin/msb, or /usr/local/bin/msb")
  fi
  if [[ ! -r /dev/kvm || ! -w /dev/kvm ]]; then
    missing+=("/dev/kvm not accessible for read/write by uid ${EUID_VAL}")
  fi
  if [[ "${EUID_VAL}" -ne 0 ]] && [[ -z "$(resolve_fusermount_bin 2>/dev/null || true)" ]]; then
    missing+=("fusermount3/fusermount missing on PATH")
  fi

  if [[ "${#missing[@]}" -gt 0 ]]; then
    local summary=""
    summary="$(printf '%s. ' "${missing[@]}")"
    if [[ "${SKIP_VM}" -eq 1 ]]; then
      skip_check "${summary}"
    fi
    printf 'Virtualization preflight failed: %s\n' "${summary}" >&2
    return 1
  fi

  echo "msb: ${MSB_BIN_PATH}"
  echo "/dev/kvm accessible: OK"
  if [[ -n "${MSB_BIN_PATH}" ]]; then
    with_timeout 30 "${MSB_BIN_PATH}" --version </dev/null || true
  fi
}

check_10_agbox_setup() {
  build_test_binaries
  local out=""
  MSB_HOME="${RUNTIME_MSB_HOME}" AGBOX_DATA_DIR="${RUNTIME_DATA_DIR}" run_capture out with_timeout 180 agbox_exec "${ACTIVE_BIN}" setup
  printf '%s\n' "${out}"
  assert_contains "${out}" "Smoke test: OK" "agbox setup output"
  [[ -f "${RUNTIME_DATA_DIR}/rules/AGBOX_ENV_RULES.md" ]] || { echo "Expected default AGBOX_ENV_RULES.md in ${RUNTIME_DATA_DIR}/rules" >&2; return 1; }
}

check_11_bootstrap_isolated_base() {
  build_test_binaries
  local add_args=()
  if [[ "${FULL_MODE}" -eq 1 ]]; then
    add_args=(--add core)
  fi
  MSB_HOME="${RUNTIME_MSB_HOME}" AGBOX_DATA_DIR="${RUNTIME_DATA_DIR}" with_timeout 900 agbox_exec "${ACTIVE_BIN}" create-base "${add_args[@]}" both
  load_base_info_from_config "${RUNTIME_DATA_DIR}/config"
  [[ -n "${BASE_SNAP}" ]] || { echo "Missing snapshot in ${RUNTIME_DATA_DIR}/config" >&2; return 1; }
  echo "Isolated base ready: snapshot=${BASE_SNAP}, agent=${BASE_AGENT}"
}

check_10_disruptive_clean_pre() {
  build_test_binaries
  DISRUPTIVE_SETUP_DONE=1
  MSB_HOME="${ORIG_MSB_HOME}" AGBOX_DATA_DIR="${ORIG_DATA_DIR}" with_timeout 120 agbox_exec "${TEST_BIN}" remove --yes
  local st_out=""
  MSB_HOME="${ORIG_MSB_HOME}" AGBOX_DATA_DIR="${ORIG_DATA_DIR}" run_capture st_out with_timeout 30 agbox_exec "${TEST_BIN}" status
  printf '%s\n' "${st_out}"
  assert_contains "${st_out}" "base_snapshot: not configured" "status after pre-clean remove"
}

check_11_disruptive_install_sh() {
  DISRUPTIVE_SETUP_DONE=1
  local -a inst_args=()
  if [[ "${ALLOW_ROOT}" -eq 1 ]]; then
    inst_args+=(--allow-root)
  fi
  (
    cd "${REPO_DIR}"
    MSB_HOME="${ORIG_MSB_HOME}" AGBOX_DATA_DIR="${ORIG_DATA_DIR}" with_timeout 300 ./install.sh "${inst_args[@]}"
  )
  [[ -x "${ORIG_INSTALL_BIN}" ]] || { echo "Expected installed binary at ${ORIG_INSTALL_BIN}" >&2; return 1; }
  [[ -f "${ORIG_DATA_DIR}/rules/AGBOX_ENV_RULES.md" ]] || { echo "Expected default AGBOX_ENV_RULES.md in ${ORIG_DATA_DIR}/rules" >&2; return 1; }
  ACTIVE_BIN="${ORIG_INSTALL_BIN}"
}

check_12_disruptive_create_and_edit_base() {
  DISRUPTIVE_SETUP_DONE=1
  [[ -f "${ORIG_DATA_DIR}/rules/AGBOX_ENV_RULES.md" ]] || { echo "Expected default AGBOX_ENV_RULES.md in ${ORIG_DATA_DIR}/rules" >&2; return 1; }
  local base_cmd_out=""
  if [[ "${FULL_MODE}" -eq 1 ]]; then
    MSB_HOME="${ORIG_MSB_HOME}" AGBOX_DATA_DIR="${ORIG_DATA_DIR}" with_timeout 1200 agbox_exec "${ACTIVE_BIN}" create-base --add core,go both
    MSB_HOME="${ORIG_MSB_HOME}" AGBOX_DATA_DIR="${ORIG_DATA_DIR}" with_timeout 600 agbox_exec "${ACTIVE_BIN}" edit-base --add hugo --cmd "echo e2e-v2 > /etc/agbox-e2e-v2"
    MSB_HOME="${ORIG_MSB_HOME}" AGBOX_DATA_DIR="${ORIG_DATA_DIR}" with_timeout 180 agbox_exec "${ACTIVE_BIN}" edit-base --no-snap --cmd "echo unsnapped > /etc/agbox-unsnapped"

    load_base_info_from_config "${ORIG_DATA_DIR}/config"
    assert_contains "${BASE_SNAP}" "agbox:v2" "config snapshot after edit-base"

    MSB_HOME="${ORIG_MSB_HOME}" AGBOX_DATA_DIR="${ORIG_DATA_DIR}" run_capture base_cmd_out with_timeout 180 agbox_exec "${ACTIVE_BIN}" run --no-net --name "${SUITE_ID}-ebchk" --cmd \
      'command -v mdformat >/dev/null && command -v shellcheck >/dev/null && command -v jq >/dev/null && command -v go >/dev/null && command -v hugo >/dev/null && grep -qx e2e-v2 /etc/agbox-e2e-v2 && test ! -e /etc/agbox-unsnapped && grep -q "Operating Inside an agbox Sandbox" /home/agent/.gemini/config/AGENTS.md && echo BASE_CMD_STDOUT_OK'
    printf '%s\n' "${base_cmd_out}"
    assert_contains "${base_cmd_out}" "BASE_CMD_STDOUT_OK" "check_12 --cmd stdout"
  else
    MSB_HOME="${ORIG_MSB_HOME}" AGBOX_DATA_DIR="${ORIG_DATA_DIR}" with_timeout 900 agbox_exec "${ACTIVE_BIN}" create-base both
    load_base_info_from_config "${ORIG_DATA_DIR}/config"
    [[ -n "${BASE_SNAP}" ]] || { echo "Missing snapshot in config" >&2; return 1; }
    MSB_HOME="${ORIG_MSB_HOME}" AGBOX_DATA_DIR="${ORIG_DATA_DIR}" run_capture base_cmd_out with_timeout 180 agbox_exec "${ACTIVE_BIN}" run --no-net --name "${SUITE_ID}-basechk" --cmd \
      'command -v mdformat >/dev/null && command -v shellcheck >/dev/null && grep -q "Operating Inside an agbox Sandbox" /home/agent/.gemini/config/AGENTS.md && echo BASE_CMD_STDOUT_OK'
    printf '%s\n' "${base_cmd_out}"
    assert_contains "${base_cmd_out}" "BASE_CMD_STDOUT_OK" "check_12 --cmd stdout"
  fi
}

# ---------------------------------------------------------------------------
# Phase 5: Core live microVM integration suite
# ---------------------------------------------------------------------------

prepare_shared_test_dirs() {
  local proj="${TEST_ROOT}/proj1"
  local docs="${TEST_ROOT}/docs1"
  local extra="${TEST_ROOT}/extra1"
  local single_file="${TEST_ROOT}/single_file.txt"

  mkdir -p "${proj}/src" "${proj}/.git" "${proj}/.GIT" "${proj}/.jj" "${proj}/.agents/skills/ps"
  mkdir -p "${docs}" "${extra}/.git/hooks"
  chmod 0755 "${proj}" "${docs}" "${extra}"

  printf 'initial-app\n' > "${proj}/src/app.txt"
  printf 'secret-git-cfg\n' > "${proj}/.git/config"
  printf 'ref: main\n' > "${proj}/.GIT/HEAD"
  printf 'jj-state\n' > "${proj}/.jj/repo"
  printf '.env\n' > "${proj}/.gitignore"
  printf '# Project Skill\n' > "${proj}/.agents/skills/ps/SKILL.md"
  printf '# Project Rules\n' > "${proj}/AGENTS.md"
  printf 'readonly-readme\n' > "${docs}/readme.txt"
  printf 'single-file-ro-content\n' > "${single_file}"

  printf 'extra-note\n' > "${extra}/note.txt"
  printf 'ref: main\n' > "${extra}/.git/HEAD"
  printf '#!/bin/sh\nexit 0\n' > "${extra}/.git/hooks/pre-commit"
}

check_20_ephemeral_run_shares_and_secrets() {
  prepare_shared_test_dirs
  local proj="${TEST_ROOT}/proj1"
  local docs="${TEST_ROOT}/docs1"
  local single_file="${TEST_ROOT}/single_file.txt"

  # Inline modifier conflict checks fail closed with real base configured.
  local conflict=""
  local rc=0
  local err_out=""
  for conflict in "${proj}:ro,rw" "${proj}:mask,vcs" "${proj}:ro,vcs-hooks"; do
    rc=0
    err_out="$(MSB_HOME="${RUNTIME_MSB_HOME}" AGBOX_DATA_DIR="${RUNTIME_DATA_DIR}" with_timeout 30 agbox_exec "${ACTIVE_BIN}" run --no-net --cmd true "${conflict}" 2>&1)" || rc=$?
    [[ "${rc}" -ne 0 ]] || { echo "Expected share modifier conflict error for ${conflict}" >&2; return 1; }
    assert_contains "${err_out}" "[agbox] ERROR:" "conflict error for ${conflict}"
  done

  rc=0
  err_out="$(MSB_HOME="${RUNTIME_MSB_HOME}" AGBOX_DATA_DIR="${RUNTIME_DATA_DIR}" with_timeout 30 agbox_exec "${ACTIVE_BIN}" run --no-net --ro --cmd true "${proj}:rw" 2>&1)" || rc=$?
  [[ "${rc}" -ne 0 ]] || { echo "Expected --ro vs :rw conflict error" >&2; return 1; }
  assert_contains "${err_out}" "[agbox] ERROR:" "--ro vs :rw conflict"

  local guest_script='
set -eu
test "$(id -u)" -eq 1000
test "$(id -un)" = "agent"
test "$(sudo -n id -u)" -eq 0
test "$(pwd)" = "/workspace"
test "${OPENAI_API_KEY:-}" = "sk-e2e-stream-test"
test "$(stat -c "%a" /home/agent/.agbox-keys.sh)" = "600"
grep -q "always-proceed" /home/agent/.gemini/antigravity-cli/settings.json
grep -q "send-immediately" /home/agent/.gemini/antigravity-cli/settings.json
grep -q "\"permission\"" /home/agent/.config/opencode/opencode.json
grep -q "allow" /home/agent/.config/opencode/opencode.json
test -f /workspace/proj1/.agents/skills/ps/SKILL.md
test -f /workspace/proj1/AGENTS.md
test -f /etc/agbox-global-rules/AGENTS.md
for ag_md in /home/agent/.config/opencode/AGENTS.md /home/agent/.gemini/config/AGENTS.md /home/agent/.gemini/AGENTS.md; do
  if [ "$ag_md" = "/home/agent/.gemini/AGENTS.md" ] && [ ! -e "$ag_md" ]; then
    continue
  fi
  test -f "$ag_md"
  grep -q "Operating Inside an agbox Sandbox" "$ag_md"
  grep -q " $ag_md " /proc/self/mountinfo
  if touch "$ag_md" 2>/dev/null; then
    echo "GLOBAL_AGENTS_MD_WRITABLE: $ag_md" >&2
    exit 1
  fi
done
for h in .git .GIT .jj .gitignore; do
  if [ -e "/workspace/proj1/$h" ]; then
    echo "HIDDEN_VCS_EXPOSED: $h" >&2
    exit 1
  fi
done
if mkdir /workspace/proj1/.git 2>/dev/null; then
  echo "VCS_CREATE_NOT_BLOCKED" >&2
  exit 1
fi
echo "modified-in-vm" > /workspace/proj1/src/app.txt
test "$(cat /workspace/docs/readme.txt)" = "readonly-readme"
if echo "fail" > /workspace/docs/new.txt 2>/dev/null; then
  echo "RO_SHARE_WRITABLE" >&2
  exit 1
fi
test "$(cat /workspace/single_ro)" = "single-file-ro-content"
if echo "fail" > /workspace/single_ro 2>/dev/null; then
  echo "RO_SINGLE_FILE_WRITABLE" >&2
  exit 1
fi
echo "GUEST_EPH_OK"
'

  local out=""
  OPENAI_API_KEY="sk-e2e-stream-test" MSB_HOME="${RUNTIME_MSB_HOME}" AGBOX_DATA_DIR="${RUNTIME_DATA_DIR}" run_capture out with_timeout 180 \
    agbox_exec "${ACTIVE_BIN}" run --no-net --name "${SUITE_ID}-eph" --share "${docs}:ro,as=docs" --share "${single_file}:ro,as=single_ro" --cmd "${guest_script}" "${proj}"
  printf '%s\n' "${out}"
  assert_contains "${out}" "GUEST_EPH_OK" "ephemeral guest check"
  [[ "$(cat "${proj}/src/app.txt")" == "modified-in-vm" ]] || { echo "Expected guest write to persist to host" >&2; return 1; }

  wait_for_sandbox_gone "${RUNTIME_MSB_HOME}" "agbox-${SUITE_ID}-eph" 20 || { echo "Ephemeral sandbox was not deleted" >&2; return 1; }
  if [[ -n "$(list_active_mounts_under "${RUNTIME_DATA_DIR}/run")" ]]; then
    echo "FUSE mount left behind after ephemeral run" >&2
    return 1
  fi

  # Interactive --cmd must stream stdout and stderr separately and forward piped stdin.
  # Check that --no-mask direct mount exposes .git.
  local io_stdout="${TEST_ROOT}/cmd-io.stdout"
  local io_stderr="${TEST_ROOT}/cmd-io.stderr"
  MSB_HOME="${RUNTIME_MSB_HOME}" AGBOX_DATA_DIR="${RUNTIME_DATA_DIR}" with_timeout 120 \
    agbox_exec "${ACTIVE_BIN}" run --no-net --no-mask --name "${SUITE_ID}-io" --cmd \
    'test -d /workspace/proj1/.git && test -f /workspace/proj1/.git/config && printf "LIVE_STDOUT_LINE\n"; printf "LIVE_STDERR_LINE\n" >&2' \
    "${proj}" >"${io_stdout}" 2>"${io_stderr}"
  cat "${io_stdout}"
  cat "${io_stderr}" >&2
  assert_contains "$(cat "${io_stdout}")" "LIVE_STDOUT_LINE" "live --cmd stdout"
  assert_not_contains "$(cat "${io_stdout}")" "LIVE_STDERR_LINE" "live --cmd stdout excludes stderr"
  assert_contains "$(cat "${io_stderr}")" "LIVE_STDERR_LINE" "live --cmd stderr"

  local pipe_out=""
  MSB_HOME="${RUNTIME_MSB_HOME}" AGBOX_DATA_DIR="${RUNTIME_DATA_DIR}" run_capture pipe_out with_timeout_stdin 120 \
    agbox_exec "${ACTIVE_BIN}" run --no-net --name "${SUITE_ID}-pipe" --cmd 'cat' <<< 'LIVE_STDIN_PAYLOAD'
  printf '%s\n' "${pipe_out}"
  assert_contains "${pipe_out}" "LIVE_STDIN_PAYLOAD" "live --cmd piped stdin"

  # Interactive --cmd non-zero exit must pass through exit code 42 without [agbox] ERROR:.
  rc=0
  err_out="$(MSB_HOME="${RUNTIME_MSB_HOME}" AGBOX_DATA_DIR="${RUNTIME_DATA_DIR}" with_timeout 120 agbox_exec "${ACTIVE_BIN}" run --no-net --name "${SUITE_ID}-exit42" --cmd "exit 42" 2>&1)" || rc=$?
  if [[ "${rc}" -ne 42 ]]; then
    printf 'Expected passthrough exit code 42, got %d\nOutput:\n%s\n' "${rc}" "${err_out}" >&2
    return 1
  fi
  assert_not_contains "${err_out}" "[agbox] ERROR:" "passthrough exit stderr"
}

check_21_persistence_auth_skills_rules_agents_profile() {
  prepare_shared_test_dirs
  local proj="${TEST_ROOT}/proj1"
  local sdir="${TEST_ROOT}/p-src"
  prof="${SUITE_ID}-p1"
  rm -rf "${sdir}"
  mkdir -p "${sdir}/e2e-skill"

  had_env_rules=0
  if [[ -f "${RUNTIME_DATA_DIR}/rules/AGBOX_ENV_RULES.md" ]]; then
    had_env_rules=1
  fi

  cleanup_21() {
    AGBOX_DATA_DIR="${RUNTIME_DATA_DIR}" with_timeout 60 agbox_exec "${ACTIVE_BIN}" skills rm e2e-skill >/dev/null 2>&1 || true
    AGBOX_DATA_DIR="${RUNTIME_DATA_DIR}" with_timeout 60 agbox_exec "${ACTIVE_BIN}" rules rm --all >/dev/null 2>&1 || true
    if [[ "${had_env_rules:-0}" -eq 1 && -f "${REPO_DIR}/AGBOX_ENV_RULES.md" ]]; then
      AGBOX_DATA_DIR="${RUNTIME_DATA_DIR}" with_timeout 60 agbox_exec "${ACTIVE_BIN}" rules add --force "${REPO_DIR}/AGBOX_ENV_RULES.md" >/dev/null 2>&1 || true
    fi
    AGBOX_DATA_DIR="${RUNTIME_DATA_DIR}" with_timeout 60 agbox_exec "${ACTIVE_BIN}" auth logout all >/dev/null 2>&1 || true
    AGBOX_DATA_DIR="${RUNTIME_DATA_DIR}" with_timeout 60 agbox_exec "${ACTIVE_BIN}" update clear all >/dev/null 2>&1 || true
    if [[ -n "${prof:-}" ]]; then
      MSB_HOME="${RUNTIME_MSB_HOME}" AGBOX_DATA_DIR="${RUNTIME_DATA_DIR}" with_timeout 60 agbox_exec "${ACTIVE_BIN}" profile rm --force "${prof}" >/dev/null 2>&1 || true
    fi
  }
  trap cleanup_21 EXIT

  printf '# E2E Skill\nUse deterministic checks.\n' > "${sdir}/e2e-skill/SKILL.md"
  AGBOX_DATA_DIR="${RUNTIME_DATA_DIR}" with_timeout 60 agbox_exec "${ACTIVE_BIN}" skills add --force "${sdir}/e2e-skill" >/dev/null

  printf '# Always Rule\nNever skip verification.\n' > "${sdir}/always.md"
  cat > "${sdir}/cond.md" <<'EOF'
---
trigger: model_decision
description: Conditional e2e rule
---
Apply when checking persistence.
EOF
  AGBOX_DATA_DIR="${RUNTIME_DATA_DIR}" with_timeout 60 agbox_exec "${ACTIVE_BIN}" rules add --force "${sdir}/always.md" >/dev/null
  AGBOX_DATA_DIR="${RUNTIME_DATA_DIR}" with_timeout 60 agbox_exec "${ACTIVE_BIN}" rules add --force "${sdir}/cond.md" >/dev/null

  seed_test_auth "${RUNTIME_DATA_DIR}"
  install_stub_agy_cache "${RUNTIME_DATA_DIR}"

  MSB_HOME="${RUNTIME_MSB_HOME}" AGBOX_DATA_DIR="${RUNTIME_DATA_DIR}" with_timeout 60 agbox_exec "${ACTIVE_BIN}" profile create --size 128M "${prof}"

  local st_out=""
  MSB_HOME="${RUNTIME_MSB_HOME}" AGBOX_DATA_DIR="${RUNTIME_DATA_DIR}" run_capture st_out with_timeout 30 agbox_exec "${ACTIVE_BIN}" status
  assert_contains "${st_out}" "antigravity" "status auth"
  assert_contains "${st_out}" "e2e-skill" "status skills"
  assert_contains "${st_out}" "always" "status rules"
  assert_contains "${st_out}" "${prof}" "status profiles"

  local script1='
set -eu
test "$(pwd)" = "/workspace/proj1"
grep -q "E2E Skill" /home/agent/.gemini/config/skills/e2e-skill/SKILL.md
grep -q "E2E Skill" /home/agent/.config/opencode/skills/e2e-skill/SKILL.md
grep -q "Always Rule" /home/agent/.gemini/config/AGENTS.md
grep -q "Always Rule" /home/agent/.config/opencode/AGENTS.md
grep -q "Apply when checking persistence." /home/agent/.gemini/config/rules/cond.md
test "$(stat -c "%a" /home/agent/.gemini/antigravity-cli/antigravity-oauth-token)" = "600"
test "$(stat -c "%a" /home/agent/.local/share/opencode/auth.json)" = "600"
test "$(agy --version)" = "agy e2e-stub-1.0.0"
if touch /home/agent/.gemini/config/skills/e2e-skill/new.txt 2>/dev/null; then
  echo "SKILLS_MOUNT_WRITABLE" >&2
  exit 1
fi
if touch /home/agent/.gemini/config/rules/new.md 2>/dev/null; then
  echo "RULES_MOUNT_WRITABLE" >&2
  exit 1
fi
printf "agy-history-ok\n" > /home/agent/.gemini/config/projects/hist.txt
printf "oc-history-ok\n" > /home/agent/.local/share/opencode/hist.txt
echo "PERSIST_RUN1_OK"
'
  local out1=""
  MSB_HOME="${RUNTIME_MSB_HOME}" AGBOX_DATA_DIR="${RUNTIME_DATA_DIR}" run_capture out1 with_timeout 180 \
    agbox_exec "${ACTIVE_BIN}" run --no-net --profile "${prof}" --name "${SUITE_ID}-pr1" --cmd "${script1}" "${proj}"
  printf '%s\n' "${out1}"
  assert_contains "${out1}" "PERSIST_RUN1_OK" "persist run 1"

  local script2='
set -eu
test "$(cat /home/agent/.gemini/config/projects/hist.txt)" = "agy-history-ok"
test "$(cat /home/agent/.local/share/opencode/hist.txt)" = "oc-history-ok"
test ! -e /home/agent/.gemini/config/skills/e2e-skill
test ! -e /home/agent/.gemini/config/AGENTS.md
test ! -e /home/agent/.gemini/config/rules/cond.md
if test "$(agy --version 2>/dev/null || true)" = "agy e2e-stub-1.0.0"; then
  echo "STUB_AGY_NOT_SKIPPED" >&2
  exit 1
fi
echo "PERSIST_RUN2_OK"
'
  local out2=""
  MSB_HOME="${RUNTIME_MSB_HOME}" AGBOX_DATA_DIR="${RUNTIME_DATA_DIR}" run_capture out2 with_timeout 180 \
    agbox_exec "${ACTIVE_BIN}" run --no-net --profile "${prof}" --no-skills --no-rules --no-auth --no-agent-cache --name "${SUITE_ID}-pr2" --cmd "${script2}"
  printf '%s\n' "${out2}"
  assert_contains "${out2}" "PERSIST_RUN2_OK" "persist run 2 opt-out"

  MSB_HOME="${RUNTIME_MSB_HOME}" AGBOX_DATA_DIR="${RUNTIME_DATA_DIR}" with_timeout 60 agbox_exec "${ACTIVE_BIN}" profile rm "${prof}"
}

check_22_persist_remote_control_shares_suspend_resume() {
  prepare_shared_test_dirs
  local proj="${TEST_ROOT}/proj1"
  local extra="${TEST_ROOT}/extra1"
  local sdir="${TEST_ROOT}/rc-src"
  sbx_name="${SUITE_ID}-blip"
  sbx="agbox-${sbx_name}"
  fail_name="${SUITE_ID}-rcfail"
  fail_sbx="agbox-${fail_name}"
  rm -rf "${sdir}"
  mkdir -p "${sdir}/e2e-rc-skill"

  had_env_rules=0
  if [[ -f "${RUNTIME_DATA_DIR}/rules/AGBOX_ENV_RULES.md" ]]; then
    had_env_rules=1
  fi

  cleanup_22() {
    if [[ -n "${sbx:-}" ]]; then
      MSB_HOME="${RUNTIME_MSB_HOME}" AGBOX_DATA_DIR="${RUNTIME_DATA_DIR}" with_timeout 60 agbox_exec "${ACTIVE_BIN}" stop "${sbx}" >/dev/null 2>&1 || true
    fi
    if [[ -n "${fail_sbx:-}" ]]; then
      MSB_HOME="${RUNTIME_MSB_HOME}" AGBOX_DATA_DIR="${RUNTIME_DATA_DIR}" with_timeout 60 agbox_exec "${ACTIVE_BIN}" stop "${fail_sbx}" >/dev/null 2>&1 || true
    fi
    AGBOX_DATA_DIR="${RUNTIME_DATA_DIR}" with_timeout 60 agbox_exec "${ACTIVE_BIN}" skills rm e2e-rc-skill >/dev/null 2>&1 || true
    AGBOX_DATA_DIR="${RUNTIME_DATA_DIR}" with_timeout 60 agbox_exec "${ACTIVE_BIN}" rules rm --all >/dev/null 2>&1 || true
    if [[ "${had_env_rules:-0}" -eq 1 && -f "${REPO_DIR}/AGBOX_ENV_RULES.md" ]]; then
      AGBOX_DATA_DIR="${RUNTIME_DATA_DIR}" with_timeout 60 agbox_exec "${ACTIVE_BIN}" rules add --force "${REPO_DIR}/AGBOX_ENV_RULES.md" >/dev/null 2>&1 || true
    fi
    AGBOX_DATA_DIR="${RUNTIME_DATA_DIR}" with_timeout 60 agbox_exec "${ACTIVE_BIN}" auth logout all >/dev/null 2>&1 || true
    AGBOX_DATA_DIR="${RUNTIME_DATA_DIR}" with_timeout 60 agbox_exec "${ACTIVE_BIN}" update clear all >/dev/null 2>&1 || true
  }
  trap cleanup_22 EXIT

  printf '# RC Skill\nSkill active.\n' > "${sdir}/e2e-rc-skill/SKILL.md"
  AGBOX_DATA_DIR="${RUNTIME_DATA_DIR}" with_timeout 60 agbox_exec "${ACTIVE_BIN}" skills add --force "${sdir}/e2e-rc-skill" >/dev/null
  printf '# RC Rule\nRule active.\n' > "${sdir}/rc-rule.md"
  AGBOX_DATA_DIR="${RUNTIME_DATA_DIR}" with_timeout 60 agbox_exec "${ACTIVE_BIN}" rules add --force "${sdir}/rc-rule.md" >/dev/null
  seed_test_auth "${RUNTIME_DATA_DIR}"
  install_stub_agy_cache "${RUNTIME_DATA_DIR}"

  local out=""
  local rc=0
  local use_rc=1
  if [[ "${BASE_AGENT}" == "opencode" ]]; then
    use_rc=0
  fi

  if [[ "${use_rc}" -eq 1 ]]; then
    # Check that non-zero exit prints [agbox] ERROR: + stub stderr details and deletes the sandbox on failure.
    local fail_out=""
    local fail_tmp="${TEST_ROOT}/rc-fail.out"
    rm -f "${fail_tmp}"
    MSB_HOME="${RUNTIME_MSB_HOME}" AGBOX_DATA_DIR="${RUNTIME_DATA_DIR}" with_timeout 180 \
      agbox_exec "${ACTIVE_BIN}" run --no-auth --persist --name "${fail_name}" -d --remote-control "${proj}" >"${fail_tmp}" 2>&1 || rc=$?
    fail_out="$(<"${fail_tmp}")"
    rm -f "${fail_tmp}"
    [[ "${rc}" -ne 0 ]] || { echo "Expected --remote-control without auth to fail" >&2; return 1; }
    assert_contains "${fail_out}" "[agbox] ERROR:" "rc failure error prefix"
    assert_contains "${fail_out}" "missing saved antigravity oauth token" "rc failure stderr detail"
    wait_for_sandbox_gone "${RUNTIME_MSB_HOME}" "${fail_sbx}" 15 || { echo "Expected failed rc sandbox ${fail_sbx} to be deleted" >&2; return 1; }

    # Boot detached persistent Remote Control with auth + skill + rule + agent cache.
    MSB_HOME="${RUNTIME_MSB_HOME}" AGBOX_DATA_DIR="${RUNTIME_DATA_DIR}" run_capture out with_timeout 180 \
      agbox_exec "${ACTIVE_BIN}" run --persist --name "${sbx_name}" -d --remote-control "${proj}"
    printf '%s\n' "${out}"
    assert_contains "${out}" "Remote Control active (${sbx})" "remote-control status output"
    assert_contains "${out}" "agbox suspend ${sbx}" "detached suspend hint"
  else
    # Check that opencode-only base rejects --remote-control, then run --persist lifecycle via --serve -d.
    local rej_out=""
    local rej_tmp="${TEST_ROOT}/rc-rej.out"
    rm -f "${rej_tmp}"
    MSB_HOME="${RUNTIME_MSB_HOME}" AGBOX_DATA_DIR="${RUNTIME_DATA_DIR}" with_timeout 60 \
      agbox_exec "${ACTIVE_BIN}" run --persist --name "${fail_name}" -d --remote-control "${proj}" >"${rej_tmp}" 2>&1 || rc=$?
    rej_out="$(<"${rej_tmp}")"
    rm -f "${rej_tmp}"
    [[ "${rc}" -ne 0 ]] || return 1
    assert_contains "${rej_out}" "[agbox] ERROR:" "opencode base rejects remote-control"

    MSB_HOME="${RUNTIME_MSB_HOME}" AGBOX_DATA_DIR="${RUNTIME_DATA_DIR}" run_capture out with_timeout 180 \
      agbox_exec "${ACTIVE_BIN}" run --persist --name "${sbx_name}" -d --serve "${proj}"
    printf '%s\n' "${out}"
    assert_contains "${out}" "agbox suspend ${sbx}" "detached serve suspend hint"
  fi

  wait_for_sandbox_running "${RUNTIME_MSB_HOME}" "${sbx}" 20 || { echo "Expected ${sbx} running" >&2; return 1; }

  # Check live dynamic share list, add (ro,mask default), set (--vcs-hooks -> --vcs downgrade), and rm.
  MSB_HOME="${RUNTIME_MSB_HOME}" AGBOX_DATA_DIR="${RUNTIME_DATA_DIR}" run_capture out with_timeout 30 agbox_exec "${ACTIVE_BIN}" share list "${sbx}"
  assert_contains "${out}" "/workspace/proj1" "share list initial"
  assert_contains "${out}" "mode=rw" "share list initial mode"
  assert_contains "${out}" "vcs=mask" "share list initial vcs"

  MSB_HOME="${RUNTIME_MSB_HOME}" AGBOX_DATA_DIR="${RUNTIME_DATA_DIR}" with_timeout 60 agbox_exec "${ACTIVE_BIN}" share add "${sbx}" "${extra}"
  MSB_HOME="${RUNTIME_MSB_HOME}" with_timeout 30 "${MSB_BIN_PATH}" exec --no-stdin -u agent "${sbx}" -- sh -eu -c '
    test "$(cat /workspace/extra1/note.txt)" = "extra-note"
    test ! -e /workspace/extra1/.git
    if touch /workspace/extra1/blocked.txt 2>/dev/null; then exit 1; fi
  ' </dev/null

  MSB_HOME="${RUNTIME_MSB_HOME}" AGBOX_DATA_DIR="${RUNTIME_DATA_DIR}" with_timeout 60 agbox_exec "${ACTIVE_BIN}" share set --rw --vcs-hooks "${sbx}" extra1
  MSB_HOME="${RUNTIME_MSB_HOME}" with_timeout 30 "${MSB_BIN_PATH}" exec --no-stdin -u agent "${sbx}" -- sh -eu -c '
    test -f /workspace/extra1/.git/HEAD
    printf "#!/bin/sh\necho hook-allowed\n" > /workspace/extra1/.git/hooks/pre-commit
    grep -q "hook-allowed" /workspace/extra1/.git/hooks/pre-commit
  ' </dev/null

  MSB_HOME="${RUNTIME_MSB_HOME}" AGBOX_DATA_DIR="${RUNTIME_DATA_DIR}" with_timeout 60 agbox_exec "${ACTIVE_BIN}" share set --vcs "${sbx}" extra1
  MSB_HOME="${RUNTIME_MSB_HOME}" with_timeout 30 "${MSB_BIN_PATH}" exec --no-stdin -u agent "${sbx}" -- sh -eu -c '
    test -f /workspace/extra1/.git/HEAD
    printf "ref: refs/heads/e2e\n" > /workspace/extra1/.git/HEAD
    if printf "bad\n" > /workspace/extra1/.git/hooks/pre-commit 2>/dev/null; then exit 1; fi
  ' </dev/null

  MSB_HOME="${RUNTIME_MSB_HOME}" AGBOX_DATA_DIR="${RUNTIME_DATA_DIR}" with_timeout 60 agbox_exec "${ACTIVE_BIN}" share rm "${sbx}" extra1
  MSB_HOME="${RUNTIME_MSB_HOME}" with_timeout 30 "${MSB_BIN_PATH}" exec --no-stdin -u agent "${sbx}" -- sh -eu -c 'test ! -e /workspace/extra1' </dev/null

  # Suspend, add share while suspended, check share override rejection, and resume detached.
  MSB_HOME="${RUNTIME_MSB_HOME}" AGBOX_DATA_DIR="${RUNTIME_DATA_DIR}" with_timeout 60 agbox_exec "${ACTIVE_BIN}" suspend "${sbx}"
  if wait_for_sandbox_running "${RUNTIME_MSB_HOME}" "${sbx}" 2; then
    echo "Expected ${sbx} stopped after suspend" >&2
    return 1
  fi
  if [[ -n "$(list_active_mounts_under "${RUNTIME_DATA_DIR}/run/${sbx_name}")" ]]; then
    echo "Expected FUSE mounts unmounted after suspend" >&2
    return 1
  fi

  rc=0
  out="$(MSB_HOME="${RUNTIME_MSB_HOME}" AGBOX_DATA_DIR="${RUNTIME_DATA_DIR}" with_timeout 30 agbox_exec "${ACTIVE_BIN}" resume --no-share "${sbx}" 2>&1)" || rc=$?
  [[ "${rc}" -ne 0 ]] || { echo "Expected resume --no-share to fail" >&2; return 1; }
  assert_contains "${out}" "[agbox] ERROR:" "resume --no-share rejection"

  rc=0
  out="$(MSB_HOME="${RUNTIME_MSB_HOME}" AGBOX_DATA_DIR="${RUNTIME_DATA_DIR}" with_timeout 30 agbox_exec "${ACTIVE_BIN}" run --persist --name "${sbx_name}" --ro --cmd true "${proj}" 2>&1)" || rc=$?
  [[ "${rc}" -ne 0 ]] || { echo "Expected conflicting share override on suspended persistent sandbox to fail" >&2; return 1; }
  assert_contains "${out}" "different shared paths or mount flags" "suspended persistent share override rejection"

  MSB_HOME="${RUNTIME_MSB_HOME}" AGBOX_DATA_DIR="${RUNTIME_DATA_DIR}" with_timeout 30 agbox_exec "${ACTIVE_BIN}" share add "${sbx}" "${extra}"
  MSB_HOME="${RUNTIME_MSB_HOME}" AGBOX_DATA_DIR="${RUNTIME_DATA_DIR}" with_timeout 180 agbox_exec "${ACTIVE_BIN}" resume -d "${sbx}"
  wait_for_sandbox_running "${RUNTIME_MSB_HOME}" "${sbx}" 20 || { echo "Expected ${sbx} running after resume" >&2; return 1; }

  # Suspend again and test repeat `agbox run --persist --name ... --cmd ...`.
  MSB_HOME="${RUNTIME_MSB_HOME}" AGBOX_DATA_DIR="${RUNTIME_DATA_DIR}" with_timeout 60 agbox_exec "${ACTIVE_BIN}" suspend "${sbx}"
  local repeat_cmd='test -f /workspace/extra1/note.txt && grep -q "RC Skill" /home/agent/.gemini/config/skills/e2e-rc-skill/SKILL.md && grep -q "Rule active." /home/agent/.gemini/config/AGENTS.md'
  if [[ "${use_rc}" -eq 1 ]]; then
    repeat_cmd="${repeat_cmd} && test -f /home/agent/.agbox-e2e-rc-instance"
  fi
  MSB_HOME="${RUNTIME_MSB_HOME}" AGBOX_DATA_DIR="${RUNTIME_DATA_DIR}" with_timeout 180 \
    agbox_exec "${ACTIVE_BIN}" run --persist --name "${sbx_name}" --cmd "${repeat_cmd}"

  # Clean stop deletes sandbox and run directory.
  MSB_HOME="${RUNTIME_MSB_HOME}" AGBOX_DATA_DIR="${RUNTIME_DATA_DIR}" with_timeout 60 agbox_exec "${ACTIVE_BIN}" stop "${sbx}"
  wait_for_sandbox_gone "${RUNTIME_MSB_HOME}" "${sbx}" 15 || { echo "Expected ${sbx} deleted after stop" >&2; return 1; }
}

check_23_serve_loopback_probe() {
  if [[ "${BASE_AGENT}" == "antigravity" ]]; then
    skip_check "base snapshot was built without opencode"
  fi
  prepare_shared_test_dirs
  local out=""
  MSB_HOME="${RUNTIME_MSB_HOME}" AGBOX_DATA_DIR="${RUNTIME_DATA_DIR}" run_capture out with_timeout 180 \
    agbox_exec "${ACTIVE_BIN}" run --name "${SUITE_ID}-probe" --serve --probe "${TEST_ROOT}/proj1"
  printf '%s\n' "${out}"
  assert_contains "${out}" "OpenCode web UI: http://127.0.0.1:" "--serve URL output"
  assert_contains "${out}" "--probe: UI verified" "--probe verification message"
  wait_for_sandbox_gone "${RUNTIME_MSB_HOME}" "agbox-${SUITE_ID}-probe" 20 || return 1
}

check_24_remote_command_in_vm() {
  local sbx_def="${SUITE_ID}-remdef"
  local sbx_off="${SUITE_ID}-remoff"
  local sbx_live="${SUITE_ID}-remlive"
  sbx_live_full="agbox-${sbx_live}"
  rwork_24="${TEST_ROOT}/rem-vm-work"
  bg_pid_24=""
  local out=""

  cleanup_24() {
    if [[ -n "${sbx_live_full:-}" ]]; then
      MSB_HOME="${RUNTIME_MSB_HOME}" AGBOX_DATA_DIR="${RUNTIME_DATA_DIR}" with_timeout 60 agbox_exec "${ACTIVE_BIN}" stop "${sbx_live_full}" >/dev/null 2>&1 || true
    fi
    if [[ -n "${bg_pid_24:-}" ]]; then
      kill "${bg_pid_24}" 2>/dev/null || true
      wait "${bg_pid_24}" 2>/dev/null || true
    fi
    if [[ -n "${rwork_24:-}" && -d "${rwork_24}" ]]; then
      rm -rf "${rwork_24}" 2>/dev/null || true
    fi
  }
  trap cleanup_24 EXIT

  # Default run mounts the remote bridge, links agbox-remote, merges INSTRUCTIONS.md, and returns exit 126 when unattached.
  local guest_check='
set -eu
test -L /usr/local/bin/agbox-remote
test -x /usr/local/bin/agbox-remote
test -f /home/agent/.agbox-remote/INSTRUCTIONS.md
grep -q "agbox-remote" /etc/agbox-global-rules/AGENTS.md
rc=0
err="$(agbox-remote uname -a 2>&1)" || rc=$?
test "${rc}" -eq 126
test "${err}" = "agbox-remote: command denied"
echo "GUEST_REMOTE_DEFAULT_OK"
'
  MSB_HOME="${RUNTIME_MSB_HOME}" AGBOX_DATA_DIR="${RUNTIME_DATA_DIR}" run_capture out with_timeout 180 \
    agbox_exec "${ACTIVE_BIN}" run --no-net --name "${sbx_def}" --cmd "${guest_check}"
  assert_contains "${out}" "GUEST_REMOTE_DEFAULT_OK" "default in-VM remote bridge check"

  # --no-remote omits the bridge mount and symlink.
  local off_check='
set -eu
test ! -e /home/agent/.agbox-remote
test ! -e /usr/local/bin/agbox-remote
echo "GUEST_NO_REMOTE_OK"
'
  MSB_HOME="${RUNTIME_MSB_HOME}" AGBOX_DATA_DIR="${RUNTIME_DATA_DIR}" run_capture out with_timeout 180 \
    agbox_exec "${ACTIVE_BIN}" run --no-net --no-remote --name "${sbx_off}" --cmd "${off_check}"
  assert_contains "${out}" "GUEST_NO_REMOTE_OK" "--no-remote in-VM check"

  # Boot a live --no-net microVM, pair serve + connect --output-review via PTY, pause >2s in Phase 1,
  # emit >64 KiB + AWS key, approve Phase 1 and Phase 2, and verify exact bytes and redaction inside the guest.
  rm -rf "${rwork_24}"
  mkdir -p "${rwork_24}"
  chmod 0700 "${rwork_24}"
  local emit_bin="${rwork_24}/emit_big"
  cat > "${emit_bin}" <<'EOF'
#!/usr/bin/env python3
import sys
sys.stdout.write("A" * 70000 + "\nAKIAIOSFODNN7EXAMPLE\n")
EOF
  chmod 0755 "${emit_bin}"

  MSB_HOME="${RUNTIME_MSB_HOME}" AGBOX_DATA_DIR="${RUNTIME_DATA_DIR}" \
    agbox_exec "${ACTIVE_BIN}" run --no-net --name "${sbx_live}" --cmd "sleep 180" >"${TEST_ROOT}/rem-vm-run.log" 2>&1 </dev/null &
  bg_pid_24=$!

  wait_for_sandbox_running "${RUNTIME_MSB_HOME}" "${sbx_live_full}" 60 || {
    echo "Timeout waiting for ${sbx_live_full}" >&2
    cat "${TEST_ROOT}/rem-vm-run.log" >&2 || true
    return 1
  }
  local rsock="${RUNTIME_DATA_DIR}/run/${sbx_live}/remote.sock"
  local i=0
  while [[ ! -S "${rsock}" && "${i}" -lt 50 ]]; do
    sleep 0.2
    i=$((i + 1))
  done
  [[ -S "${rsock}" ]] || {
    echo "remote.sock did not appear for ${sbx_live_full}" >&2
    cat "${TEST_ROOT}/rem-vm-run.log" >&2 || true
    return 1
  }

  python3 -c '
import os, pty, re, select, signal, subprocess, sys, time

active_bin, msb_bin, runtime_msb, runtime_data, sbx_full, rwork, emit_bin, allow_root = sys.argv[1:9]
base_cmd = [active_bin] + (["--allow-root"] if allow_root == "1" else [])

env = os.environ.copy()
env["AGBOX_DATA_DIR"] = runtime_data
env["MSB_HOME"] = runtime_msb

def spawn_pty(cmd, cwd=None):
    mfd, sfd = pty.openpty()
    p = subprocess.Popen(cmd, stdin=sfd, stdout=sfd, stderr=sfd, env=env, cwd=cwd, close_fds=True, start_new_session=True)
    os.close(sfd)
    return p, mfd

def read_until(mfd, pattern, buf, timeout=30.0):
    rx = re.compile(pattern)
    end = time.time() + timeout
    while time.time() < end:
        m = rx.search(buf)
        if m:
            return buf, m
        r, _, _ = select.select([mfd], [], [], 0.1)
        if r:
            try:
                chunk = os.read(mfd, 4096)
            except OSError:
                break
            if not chunk:
                break
            buf += chunk.decode("utf-8", "replace")
    raise RuntimeError(f"timeout waiting for {pattern!r}, got:\n{buf}")

srv_p, srv_fd = spawn_pty(base_cmd + ["remote", "serve", "--listen", "127.0.0.1:0", "--allow-from", "127.0.0.1/32", "--allow-cwd", rwork], cwd=rwork)
brk_p, brk_fd = None, None
try:
    srv_buf, m_addr = read_until(srv_fd, r"127\.0\.0\.1:(\d+)", "")
    addr = m_addr.group(0)

    brk_p, brk_fd = spawn_pty(base_cmd + ["remote", "connect", "--sandbox", sbx_full, "--no-policy", "--output-review", addr])
    sas_pat = r"([0-9A-Z]{4}-[0-9A-Z]{4}-[0-9A-Z]{4})"
    srv_buf, m_srv_sas = read_until(srv_fd, sas_pat, srv_buf)
    brk_buf, m_brk_sas = read_until(brk_fd, sas_pat, "")
    assert m_srv_sas.group(1) == m_brk_sas.group(1), (m_srv_sas.group(1), m_brk_sas.group(1))

    os.write(srv_fd, b"y\n")
    os.write(brk_fd, b"y\n")
    brk_buf, m_att = read_until(brk_fd, r"Attached to sandbox", brk_buf)
    brk_buf = brk_buf[m_att.end():]

    guest_cmd = [msb_bin, "exec", "--stream", "--no-stdin", "-u", "agent", sbx_full, "--", "agbox-remote", "--cwd", rwork, emit_bin]
    p_guest = subprocess.Popen(guest_cmd, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    # Phase 1: pause >2s before approving to exercise adaptive done/ polling across virtiofs.
    brk_buf, m_p1 = read_until(brk_fd, r"Choice \(\[a\]pprove", brk_buf)
    brk_buf = brk_buf[m_p1.end():]
    time.sleep(2.2)
    os.write(brk_fd, b"a\n")

    # Phase 2: wait for output review card and approve.
    brk_buf, m_p2h = read_until(brk_fd, r"PHASE 2: OUTPUT REVIEW", brk_buf)
    brk_buf = brk_buf[m_p2h.end():]
    brk_buf, m_p2 = read_until(brk_fd, r"Choice \(\[a\]pprove", brk_buf)
    brk_buf = brk_buf[m_p2.end():]
    os.write(brk_fd, b"a\n")

    g_out, g_err = p_guest.communicate(timeout=30)
    assert p_guest.returncode == 0, (p_guest.returncode, len(g_out), g_err)
    expected = "A" * 70000 + "\n[REDACTED:AWS_KEY]\n"
    assert g_out == expected, (len(g_out), len(expected), g_out[:64], g_out[-64:], g_err)
    assert "AKIAIOSFODNN7EXAMPLE" not in g_out
    assert "[REDACTED:AWS_KEY]" in g_out

    os.write(brk_fd, b"q\n")
    brk_p.wait(timeout=10)
finally:
    for p, fd in ((brk_p, brk_fd), (srv_p, srv_fd)):
        if p is not None and p.poll() is None:
            try:
                os.killpg(p.pid, signal.SIGTERM)
            except OSError:
                pass
            try:
                p.wait(timeout=5)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(p.pid, signal.SIGKILL)
                except OSError:
                    pass
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass
' "${ACTIVE_BIN}" "${MSB_BIN_PATH}" "${RUNTIME_MSB_HOME}" "${RUNTIME_DATA_DIR}" "${sbx_live_full}" "${rwork_24}" "${emit_bin}" "${ALLOW_ROOT}" || {
    echo "Live in-VM Phase 1/2 remote command check failed" >&2
    return 1
  }

  MSB_HOME="${RUNTIME_MSB_HOME}" AGBOX_DATA_DIR="${RUNTIME_DATA_DIR}" with_timeout 60 agbox_exec "${ACTIVE_BIN}" stop "${sbx_live_full}" >/dev/null 2>&1 || true
  sbx_live_full=""
  if [[ -n "${bg_pid_24}" ]]; then
    kill "${bg_pid_24}" 2>/dev/null || true
    wait "${bg_pid_24}" 2>/dev/null || true
    bg_pid_24=""
  fi
}

# ---------------------------------------------------------------------------
# Phase 6: Extended runtime suite (--full)
# ---------------------------------------------------------------------------

check_30_network_isolation_firewall() {
  # --no-net must block outbound connections immediately.
  local rc=0
  MSB_HOME="${RUNTIME_MSB_HOME}" AGBOX_DATA_DIR="${RUNTIME_DATA_DIR}" with_timeout 120 \
    agbox_exec "${ACTIVE_BIN}" run --no-net --name "${SUITE_ID}-nonet" --cmd \
    '! curl -fsS --connect-timeout 2 --max-time 3 https://1.1.1.1 >/dev/null 2>&1' || rc=$?
  [[ "${rc}" -eq 0 ]] || { echo "Expected --no-net to block 1.1.1.1" >&2; return 1; }

  # Default --net public must block cloud IMDS and RFC1918 ranges.
  local net_script='
set -eu
for ip in 169.254.169.254 168.63.129.16 100.100.100.200 10.255.255.1 192.168.255.1; do
  if curl -fsS --connect-timeout 2 --max-time 3 "http://${ip}/" >/dev/null 2>&1; then
    echo "BLOCKED_IP_REACHABLE: ${ip}" >&2
    exit 1
  fi
done
echo "BLOCKED_RANGES_OK"
'
  local out=""
  MSB_HOME="${RUNTIME_MSB_HOME}" AGBOX_DATA_DIR="${RUNTIME_DATA_DIR}" run_capture out with_timeout 180 \
    agbox_exec "${ACTIVE_BIN}" run --name "${SUITE_ID}-pubfw" --cmd "${net_script}"
  printf '%s\n' "${out}"
  assert_contains "${out}" "BLOCKED_RANGES_OK" "guest firewall check"

  # Check public HTTPS only if the host itself can reach example.com.
  if with_timeout 10 curl -fsSI --connect-timeout 4 https://example.com >/dev/null 2>&1; then
    MSB_HOME="${RUNTIME_MSB_HOME}" AGBOX_DATA_DIR="${RUNTIME_DATA_DIR}" with_timeout 120 \
      agbox_exec "${ACTIVE_BIN}" run --name "${SUITE_ID}-pubok" --cmd 'curl -fsSI --connect-timeout 5 --max-time 10 https://example.com >/dev/null'
  else
    echo "Host offline or example.com unreachable. Skipping positive public egress check."
  fi
}

check_31_share_open_fd_revocation() {
  prepare_shared_test_dirs
  local proj="${TEST_ROOT}/proj1"
  sbx_name="${SUITE_ID}-fd"
  sbx="agbox-${sbx_name}"
  bg_pid=""

  cleanup_31() {
    if [[ -n "${sbx:-}" ]]; then
      MSB_HOME="${RUNTIME_MSB_HOME}" AGBOX_DATA_DIR="${RUNTIME_DATA_DIR}" with_timeout 60 agbox_exec "${ACTIVE_BIN}" stop "${sbx}" >/dev/null 2>&1 || true
    fi
    if [[ -n "${bg_pid:-}" ]]; then
      kill "${bg_pid}" 2>/dev/null || true
      wait "${bg_pid}" 2>/dev/null || true
    fi
  }
  trap cleanup_31 EXIT

  MSB_HOME="${RUNTIME_MSB_HOME}" AGBOX_DATA_DIR="${RUNTIME_DATA_DIR}" \
    agbox_exec "${ACTIVE_BIN}" run --no-net --persist --name "${sbx_name}" --share "${proj}:rw" --cmd "sleep 300" >"${TEST_ROOT}/fd-run.log" 2>&1 </dev/null &
  bg_pid=$!

  wait_for_sandbox_running "${RUNTIME_MSB_HOME}" "${sbx}" 40 || {
    echo "Timeout waiting for ${sbx}" >&2
    cat "${TEST_ROOT}/fd-run.log" >&2 || true
    return 1
  }
  local sock="${RUNTIME_DATA_DIR}/run/${sbx_name}/ws.sock"
  local i=0
  while [[ ! -S "${sock}" && "${i}" -lt 30 ]]; do
    sleep 0.2
    i=$((i + 1))
  done
  [[ -S "${sock}" ]] || { echo "ws.sock did not appear" >&2; return 1; }

  # Launch guest process holding open writable FD 3 until /tmp/fd-go appears.
  MSB_HOME="${RUNTIME_MSB_HOME}" with_timeout 30 "${MSB_BIN_PATH}" exec -d --no-stdin -u agent "${sbx}" -- sh -c \
    'exec 3>> /workspace/proj1/open-fd.txt; printf "before\n" >&3; : > /tmp/fd-ready; while [ ! -f /tmp/fd-go ]; do sleep 0.1; done; printf "after\n" >&3 2>/tmp/fd-err; echo "$?" > /tmp/fd-rc' </dev/null

  local fd_ready=0
  i=0
  while [[ "${i}" -lt 30 ]]; do
    if MSB_HOME="${RUNTIME_MSB_HOME}" with_timeout 30 "${MSB_BIN_PATH}" exec --no-stdin -u agent "${sbx}" -- test -f /tmp/fd-ready </dev/null 2>/dev/null; then
      fd_ready=1
      break
    fi
    sleep 0.2
    i=$((i + 1))
  done
  [[ "${fd_ready}" -eq 1 ]] || { echo "Timed out waiting for /tmp/fd-ready in ${sbx}" >&2; return 1; }

  local sl_out=""
  MSB_HOME="${RUNTIME_MSB_HOME}" AGBOX_DATA_DIR="${RUNTIME_DATA_DIR}" run_capture sl_out with_timeout 20 agbox_exec "${ACTIVE_BIN}" share list "${sbx}"
  assert_contains "${sl_out}" "open_writable=1" "open_writable=1 reported"

  local rc=0
  MSB_HOME="${RUNTIME_MSB_HOME}" AGBOX_DATA_DIR="${RUNTIME_DATA_DIR}" with_timeout 20 agbox_exec "${ACTIVE_BIN}" share set --ro "${sbx}" proj1 >/dev/null 2>&1 || rc=$?
  [[ "${rc}" -ne 0 ]] || { echo "Expected share set --ro without --force to fail with open writable FD" >&2; return 1; }

  rc=0
  MSB_HOME="${RUNTIME_MSB_HOME}" AGBOX_DATA_DIR="${RUNTIME_DATA_DIR}" with_timeout 20 agbox_exec "${ACTIVE_BIN}" share rm "${sbx}" proj1 >/dev/null 2>&1 || rc=$?
  [[ "${rc}" -ne 0 ]] || { echo "Expected share rm without --force to fail with open writable FD" >&2; return 1; }

  # Force downgrade rw -> ro must succeed and fail subsequent writes to FD 3.
  MSB_HOME="${RUNTIME_MSB_HOME}" AGBOX_DATA_DIR="${RUNTIME_DATA_DIR}" with_timeout 30 agbox_exec "${ACTIVE_BIN}" share set --ro --force "${sbx}" proj1
  MSB_HOME="${RUNTIME_MSB_HOME}" with_timeout 30 "${MSB_BIN_PATH}" exec --no-stdin -u agent "${sbx}" -- sh -c ': > /tmp/fd-go' </dev/null

  local fd_rc=""
  i=0
  while [[ "${i}" -lt 30 ]]; do
    fd_rc="$(MSB_HOME="${RUNTIME_MSB_HOME}" with_timeout 30 "${MSB_BIN_PATH}" exec --stream --no-stdin -u agent "${sbx}" -- cat /tmp/fd-rc </dev/null 2>/dev/null || true)"
    if [[ -n "${fd_rc}" ]]; then
      break
    fi
    sleep 0.2
    i=$((i + 1))
  done
  [[ -n "${fd_rc}" && "${fd_rc}" != "0" ]] || { echo "Expected FD write to fail after forced --ro downgrade (rc=${fd_rc})" >&2; return 1; }

  # Enable rw and vcs, hold open FDs inside .git/HEAD and .git/config, and check forced --mask VCS descriptor revocation.
  MSB_HOME="${RUNTIME_MSB_HOME}" AGBOX_DATA_DIR="${RUNTIME_DATA_DIR}" with_timeout 30 agbox_exec "${ACTIVE_BIN}" share set --rw --vcs "${sbx}" proj1
  MSB_HOME="${RUNTIME_MSB_HOME}" with_timeout 30 "${MSB_BIN_PATH}" exec -d --no-stdin -u agent "${sbx}" -- sh -c \
    'exec 5>> /workspace/proj1/.git/HEAD; exec 6< /workspace/proj1/.git/config; : > /tmp/fd-vcs-ready; while [ ! -f /tmp/fd-vcs-go ]; do sleep 0.1; done; printf "\n" >&5 2>/tmp/fd-vcs-err; echo "$?" > /tmp/fd-vcs-rc; cat <&6 >/dev/null 2>/tmp/fd-cfg-err; echo "$?" > /tmp/fd-cfg-rc' </dev/null
  local fd_vcs_ready=0
  i=0
  while [[ "${i}" -lt 30 ]]; do
    if MSB_HOME="${RUNTIME_MSB_HOME}" with_timeout 30 "${MSB_BIN_PATH}" exec --no-stdin -u agent "${sbx}" -- test -f /tmp/fd-vcs-ready </dev/null 2>/dev/null; then
      fd_vcs_ready=1
      break
    fi
    sleep 0.2
    i=$((i + 1))
  done
  [[ "${fd_vcs_ready}" -eq 1 ]] || { echo "Timed out waiting for /tmp/fd-vcs-ready in ${sbx}" >&2; return 1; }

  rc=0
  MSB_HOME="${RUNTIME_MSB_HOME}" AGBOX_DATA_DIR="${RUNTIME_DATA_DIR}" with_timeout 20 agbox_exec "${ACTIVE_BIN}" share set --mask "${sbx}" proj1 >/dev/null 2>&1 || rc=$?
  [[ "${rc}" -ne 0 ]] || { echo "Expected share set --mask without --force to fail with open writable VCS FD" >&2; return 1; }

  MSB_HOME="${RUNTIME_MSB_HOME}" AGBOX_DATA_DIR="${RUNTIME_DATA_DIR}" with_timeout 30 agbox_exec "${ACTIVE_BIN}" share set --mask --force "${sbx}" proj1
  MSB_HOME="${RUNTIME_MSB_HOME}" with_timeout 30 "${MSB_BIN_PATH}" exec --no-stdin -u agent "${sbx}" -- sh -c ': > /tmp/fd-vcs-go' </dev/null
  local fd_vcs_rc=""
  local fd_cfg_rc=""
  i=0
  while [[ "${i}" -lt 30 ]]; do
    fd_vcs_rc="$(MSB_HOME="${RUNTIME_MSB_HOME}" with_timeout 30 "${MSB_BIN_PATH}" exec --stream --no-stdin -u agent "${sbx}" -- cat /tmp/fd-vcs-rc </dev/null 2>/dev/null || true)"
    fd_cfg_rc="$(MSB_HOME="${RUNTIME_MSB_HOME}" with_timeout 30 "${MSB_BIN_PATH}" exec --stream --no-stdin -u agent "${sbx}" -- cat /tmp/fd-cfg-rc </dev/null 2>/dev/null || true)"
    if [[ -n "${fd_vcs_rc}" && -n "${fd_cfg_rc}" ]]; then
      break
    fi
    sleep 0.2
    i=$((i + 1))
  done
  [[ -n "${fd_vcs_rc}" && "${fd_vcs_rc}" != "0" ]] || { echo "Expected .git/HEAD FD write to fail after forced --mask downgrade (rc=${fd_vcs_rc})" >&2; return 1; }
  [[ -n "${fd_cfg_rc}" && "${fd_cfg_rc}" != "0" ]] || { echo "Expected .git/config FD read to fail after forced --mask downgrade (rc=${fd_cfg_rc})" >&2; return 1; }

  # Restore rw, open FD 4, then force share rm and check write revocation.
  MSB_HOME="${RUNTIME_MSB_HOME}" AGBOX_DATA_DIR="${RUNTIME_DATA_DIR}" with_timeout 30 agbox_exec "${ACTIVE_BIN}" share set --rw "${sbx}" proj1
  MSB_HOME="${RUNTIME_MSB_HOME}" with_timeout 30 "${MSB_BIN_PATH}" exec -d --no-stdin -u agent "${sbx}" -- sh -c \
    'exec 4>> /workspace/proj1/open-fd2.txt; printf "before2\n" >&4; : > /tmp/fd2-ready; while [ ! -f /tmp/fd2-go ]; do sleep 0.1; done; printf "after2\n" >&4 2>/tmp/fd2-err; echo "$?" > /tmp/fd2-rc' </dev/null
  local fd2_ready=0
  i=0
  while [[ "${i}" -lt 30 ]]; do
    if MSB_HOME="${RUNTIME_MSB_HOME}" with_timeout 30 "${MSB_BIN_PATH}" exec --no-stdin -u agent "${sbx}" -- test -f /tmp/fd2-ready </dev/null 2>/dev/null; then
      fd2_ready=1
      break
    fi
    sleep 0.2
    i=$((i + 1))
  done
  [[ "${fd2_ready}" -eq 1 ]] || { echo "Timed out waiting for /tmp/fd2-ready in ${sbx}" >&2; return 1; }

  MSB_HOME="${RUNTIME_MSB_HOME}" AGBOX_DATA_DIR="${RUNTIME_DATA_DIR}" with_timeout 30 agbox_exec "${ACTIVE_BIN}" share rm --force "${sbx}" proj1
  MSB_HOME="${RUNTIME_MSB_HOME}" with_timeout 30 "${MSB_BIN_PATH}" exec --no-stdin -u agent "${sbx}" -- sh -c ': > /tmp/fd2-go' </dev/null
  local fd2_rc=""
  i=0
  while [[ "${i}" -lt 30 ]]; do
    fd2_rc="$(MSB_HOME="${RUNTIME_MSB_HOME}" with_timeout 30 "${MSB_BIN_PATH}" exec --stream --no-stdin -u agent "${sbx}" -- cat /tmp/fd2-rc </dev/null 2>/dev/null || true)"
    if [[ -n "${fd2_rc}" ]]; then
      break
    fi
    sleep 0.2
    i=$((i + 1))
  done
  [[ -n "${fd2_rc}" && "${fd2_rc}" != "0" ]] || { echo "Expected FD write to fail after forced share rm (rc=${fd2_rc})" >&2; return 1; }

  MSB_HOME="${RUNTIME_MSB_HOME}" AGBOX_DATA_DIR="${RUNTIME_DATA_DIR}" with_timeout 60 agbox_exec "${ACTIVE_BIN}" stop "${sbx}"
  wait "${bg_pid}" 2>/dev/null || true
  bg_pid=""
}

check_32_profile_lock_and_orphan_reaping() {
  prof="${SUITE_ID}-lkp"
  sbx_name="${SUITE_ID}-lk"
  sbx="agbox-${sbx_name}"
  orph_id="${SUITE_ID}-orph"
  orph_sbx="agbox-${orph_id}"
  bg_pid=""

  cleanup_32() {
    if [[ -n "${sbx:-}" ]]; then
      MSB_HOME="${RUNTIME_MSB_HOME}" AGBOX_DATA_DIR="${RUNTIME_DATA_DIR}" with_timeout 60 agbox_exec "${ACTIVE_BIN}" stop "${sbx}" >/dev/null 2>&1 || true
    fi
    if [[ -n "${orph_sbx:-}" ]]; then
      MSB_HOME="${RUNTIME_MSB_HOME}" with_timeout 30 "${MSB_BIN_PATH}" rm -f "${orph_sbx}" </dev/null >/dev/null 2>&1 || true
    fi
    if [[ -n "${bg_pid:-}" ]]; then
      kill "${bg_pid}" 2>/dev/null || true
      wait "${bg_pid}" 2>/dev/null || true
    fi
    if [[ -n "${prof:-}" ]]; then
      MSB_HOME="${RUNTIME_MSB_HOME}" AGBOX_DATA_DIR="${RUNTIME_DATA_DIR}" with_timeout 60 agbox_exec "${ACTIVE_BIN}" profile rm --force "${prof}" >/dev/null 2>&1 || true
    fi
  }
  trap cleanup_32 EXIT

  # Profile lock contention check.
  MSB_HOME="${RUNTIME_MSB_HOME}" AGBOX_DATA_DIR="${RUNTIME_DATA_DIR}" with_timeout 60 agbox_exec "${ACTIVE_BIN}" profile create --size 128M "${prof}"
  MSB_HOME="${RUNTIME_MSB_HOME}" AGBOX_DATA_DIR="${RUNTIME_DATA_DIR}" \
    agbox_exec "${ACTIVE_BIN}" run --no-net --profile "${prof}" --name "${sbx_name}" --cmd "sleep 300" >"${TEST_ROOT}/lkp.log" 2>&1 </dev/null &
  bg_pid=$!

  wait_for_sandbox_running "${RUNTIME_MSB_HOME}" "${sbx}" 40 || {
    echo "Timeout waiting for ${sbx}" >&2
    cat "${TEST_ROOT}/lkp.log" >&2 || true
    return 1
  }

  local rc=0
  local err_out=""
  err_out="$(MSB_HOME="${RUNTIME_MSB_HOME}" AGBOX_DATA_DIR="${RUNTIME_DATA_DIR}" with_timeout 30 agbox_exec "${ACTIVE_BIN}" run --no-net --profile "${prof}" --name "${SUITE_ID}-lk2" --cmd true 2>&1)" || rc=$?
  [[ "${rc}" -ne 0 ]] || { echo "Expected concurrent profile run to fail" >&2; return 1; }
  assert_contains "${err_out}" "[agbox] ERROR:" "concurrent profile error"

  rc=0
  err_out="$(MSB_HOME="${RUNTIME_MSB_HOME}" AGBOX_DATA_DIR="${RUNTIME_DATA_DIR}" with_timeout 30 agbox_exec "${ACTIVE_BIN}" profile rm "${prof}" 2>&1)" || rc=$?
  [[ "${rc}" -ne 0 ]] || { echo "Expected active profile rm to fail" >&2; return 1; }

  MSB_HOME="${RUNTIME_MSB_HOME}" AGBOX_DATA_DIR="${RUNTIME_DATA_DIR}" with_timeout 60 agbox_exec "${ACTIVE_BIN}" stop "${sbx}"
  wait "${bg_pid}" 2>/dev/null || true
  bg_pid=""
  MSB_HOME="${RUNTIME_MSB_HOME}" AGBOX_DATA_DIR="${RUNTIME_DATA_DIR}" with_timeout 60 agbox_exec "${ACTIVE_BIN}" profile rm "${prof}"

  # Dead-owner orphan reaping check.
  local dead_pid=""
  (true) &
  dead_pid=$!
  wait "${dead_pid}" 2>/dev/null || true
  if kill -0 "${dead_pid}" 2>/dev/null; then
    echo "Could not obtain guaranteed dead PID for orphan test" >&2
    return 1
  fi

  MSB_HOME="${RUNTIME_MSB_HOME}" with_timeout 90 "${MSB_BIN_PATH}" snap restore "${BASE_SNAP}" --name "${orph_sbx}" -u agent --no-net </dev/null >/dev/null
  mkdir -p "${RUNTIME_DATA_DIR}/run/${orph_id}"
  chmod 0700 "${RUNTIME_DATA_DIR}/run/${orph_id}"
  cat > "${RUNTIME_DATA_DIR}/run/${orph_id}/run.meta" <<EOF
{
  "sandbox": "${orph_sbx}",
  "owner_pid": ${dead_pid},
  "agent": "opencode",
  "mode": "cmd",
  "mask_mode": "strict"
}
EOF
  chmod 0600 "${RUNTIME_DATA_DIR}/run/${orph_id}/run.meta"

  MSB_HOME="${RUNTIME_MSB_HOME}" AGBOX_DATA_DIR="${RUNTIME_DATA_DIR}" with_timeout 120 \
    agbox_exec "${ACTIVE_BIN}" run --no-net --name "${SUITE_ID}-reaper" --cmd true

  wait_for_sandbox_gone "${RUNTIME_MSB_HOME}" "${orph_sbx}" 15 || { echo "Expected orphan sandbox ${orph_sbx} to be reaped" >&2; return 1; }
  if [[ -d "${RUNTIME_DATA_DIR}/run/${orph_id}" ]]; then
    echo "Expected orphan run dir ${orph_id} to be deleted" >&2
    return 1
  fi
}

check_33_serve_detached_basic_auth_lifecycle() {
  if [[ "${BASE_AGENT}" == "antigravity" ]]; then
    skip_check "base snapshot was built without opencode"
  fi
  if ! command -v curl >/dev/null 2>&1; then
    skip_check "curl is not installed on host"
  fi
  prepare_shared_test_dirs
  sbx_name="${SUITE_ID}-wsrv"
  sbx="agbox-${sbx_name}"
  local pass="pw-${SUITE_ID}"

  cleanup_33() {
    if [[ -n "${sbx:-}" ]]; then
      MSB_HOME="${RUNTIME_MSB_HOME}" AGBOX_DATA_DIR="${RUNTIME_DATA_DIR}" with_timeout 60 agbox_exec "${ACTIVE_BIN}" stop "${sbx}" >/dev/null 2>&1 || true
    fi
  }
  trap cleanup_33 EXIT

  local out=""
  OPENCODE_SERVER_PASSWORD="${pass}" MSB_HOME="${RUNTIME_MSB_HOME}" AGBOX_DATA_DIR="${RUNTIME_DATA_DIR}" run_capture out with_timeout 180 \
    agbox_exec "${ACTIVE_BIN}" run --persist --name "${sbx_name}" -d --serve "${TEST_ROOT}/proj1"
  printf '%s\n' "${out}"

  local url=""
  url="$(grep -Eo 'http://127\.0\.0\.1:[0-9]+' <<< "${out}" | head -n 1 || true)"
  [[ -n "${url}" ]] || { echo "Failed to parse serve URL from output" >&2; return 1; }

  local code=""
  code="$(curl -sS --connect-timeout 5 --max-time 15 -o /dev/null -w '%{http_code}' "${url}/doc" || true)"
  [[ "${code}" == "401" ]] || { echo "Expected HTTP 401 without basic auth, got ${code}" >&2; return 1; }

  code="$(curl -sS --connect-timeout 5 --max-time 15 -u "opencode:${pass}" -o /dev/null -w '%{http_code}' "${url}/doc" || true)"
  [[ "${code}" == "200" ]] || { echo "Expected HTTP 200 with basic auth, got ${code}" >&2; return 1; }

  MSB_HOME="${RUNTIME_MSB_HOME}" AGBOX_DATA_DIR="${RUNTIME_DATA_DIR}" with_timeout 60 agbox_exec "${ACTIVE_BIN}" suspend "${sbx}"
  if curl -fsS --connect-timeout 1 --max-time 3 "${url}/doc" >/dev/null 2>&1; then
    echo "Expected port ${url} closed after suspend" >&2
    return 1
  fi

  local resume_out=""
  OPENCODE_SERVER_PASSWORD="${pass}" MSB_HOME="${RUNTIME_MSB_HOME}" AGBOX_DATA_DIR="${RUNTIME_DATA_DIR}" run_capture resume_out with_timeout 180 \
    agbox_exec "${ACTIVE_BIN}" resume -d "${sbx}"
  printf '%s\n' "${resume_out}"
  code="$(curl -sS --connect-timeout 5 --max-time 15 -u "opencode:${pass}" -o /dev/null -w '%{http_code}' "${url}/doc" || true)"
  [[ "${code}" == "200" ]] || { echo "Expected HTTP 200 after resume, got ${code}" >&2; return 1; }

  MSB_HOME="${RUNTIME_MSB_HOME}" AGBOX_DATA_DIR="${RUNTIME_DATA_DIR}" with_timeout 60 agbox_exec "${ACTIVE_BIN}" stop "${sbx}"
}

check_34_live_agent_update() {
  if [[ "${DISRUPTIVE_MODE}" -ne 1 ]]; then
    skip_check "covered in isolated lifecycle when non-disruptive"
  fi
  cleanup_34() {
    AGBOX_DATA_DIR="${ORIG_DATA_DIR}" with_timeout 30 agbox_exec "${ACTIVE_BIN}" update clear all >/dev/null 2>&1 || true
  }
  trap cleanup_34 EXIT

  MSB_HOME="${ORIG_MSB_HOME}" AGBOX_DATA_DIR="${ORIG_DATA_DIR}" with_timeout 600 agbox_exec "${ACTIVE_BIN}" update both
  local st=""
  AGBOX_DATA_DIR="${ORIG_DATA_DIR}" run_capture st with_timeout 30 agbox_exec "${ACTIVE_BIN}" update status
  assert_contains "${st}" "antigravity: version=" "live update status antigravity"
  assert_contains "${st}" "opencode: version=" "live update status opencode"

  MSB_HOME="${ORIG_MSB_HOME}" AGBOX_DATA_DIR="${ORIG_DATA_DIR}" with_timeout 180 agbox_exec "${ACTIVE_BIN}" run --no-net --name "${SUITE_ID}-updchk" --cmd \
    'agy --version && opencode --version && grep -q " /home/agent/.local/bin/agy " /proc/self/mountinfo'
  AGBOX_DATA_DIR="${ORIG_DATA_DIR}" with_timeout 30 agbox_exec "${ACTIVE_BIN}" update clear all
}

# ---------------------------------------------------------------------------
# Phase 7: Isolated full clean-slate lifecycle in non-disruptive --full mode
# ---------------------------------------------------------------------------

check_40_isolated_full_lifecycle() {
  build_test_binaries
  iso_msb="${TEST_ROOT}/full-iso-msb"
  iso_data="${TEST_ROOT}/full-iso-data"
  iso_bin_dir="${TEST_ROOT}/full-iso-bin"

  if ! prepare_isolated_msb_home "${iso_msb}"; then
    skip_check "msb does not isolate MSB_HOME (use --disruptive to test create-base, edit-base, and remove)"
  fi

  mkdir -p "${iso_bin_dir}"
  chmod 0700 "${iso_bin_dir}"

  cleanup_40() {
    if [[ -n "${iso_bin_dir:-}" && -x "${iso_bin_dir}/agbox" ]]; then
      MSB_HOME="${iso_msb}" AGBOX_DATA_DIR="${iso_data}" with_timeout 60 agbox_exec "${iso_bin_dir}/agbox" remove --yes >/dev/null 2>&1 || true
    fi
  }
  trap cleanup_40 EXIT

  local -a inst_args=()
  if [[ "${ALLOW_ROOT}" -eq 1 ]]; then
    inst_args+=(--allow-root)
  fi
  local iso_comp_dir="${TEST_ROOT}/full-iso-comp"
  mkdir -p "${iso_comp_dir}"
  (
    cd "${REPO_DIR}"
    MSB_HOME="${iso_msb}" AGBOX_DATA_DIR="${iso_data}" AGBOX_INSTALL_DIR="${iso_bin_dir}" AGBOX_COMPLETION_DIR="${iso_comp_dir}" with_timeout 300 ./install.sh "${inst_args[@]}"
  )
  local ibin="${iso_bin_dir}/agbox"
  [[ -x "${ibin}" ]] || return 1
  [[ -f "${iso_data}/rules/AGBOX_ENV_RULES.md" ]] || { echo "Expected default AGBOX_ENV_RULES.md in ${iso_data}/rules" >&2; return 1; }
  [[ -f "${iso_comp_dir}/agbox" ]] || { echo "Expected bash completion script in ${iso_comp_dir}/agbox" >&2; return 1; }
  bash -n "${iso_comp_dir}/agbox"

  MSB_HOME="${iso_msb}" AGBOX_DATA_DIR="${iso_data}" with_timeout 900 agbox_exec "${ibin}" create-base --add core both
  MSB_HOME="${iso_msb}" AGBOX_DATA_DIR="${iso_data}" with_timeout 300 agbox_exec "${ibin}" edit-base --cmd "echo iso-v2 > /etc/agbox-iso-v2"
  MSB_HOME="${iso_msb}" AGBOX_DATA_DIR="${iso_data}" with_timeout 180 agbox_exec "${ibin}" edit-base --no-snap --cmd "echo iso-nosnap > /etc/agbox-iso-nosnap"

  MSB_HOME="${iso_msb}" AGBOX_DATA_DIR="${iso_data}" with_timeout 180 agbox_exec "${ibin}" run --no-net --name "${SUITE_ID}-isochk" --cmd \
    'command -v mdformat >/dev/null && command -v shellcheck >/dev/null && command -v jq >/dev/null && grep -qx iso-v2 /etc/agbox-iso-v2 && test ! -e /etc/agbox-iso-nosnap && grep -q "Operating Inside an agbox Sandbox" /home/agent/.gemini/config/AGENTS.md'

  MSB_HOME="${iso_msb}" AGBOX_DATA_DIR="${iso_data}" with_timeout 600 agbox_exec "${ibin}" update both
  local up_st=""
  AGBOX_DATA_DIR="${iso_data}" run_capture up_st with_timeout 30 agbox_exec "${ibin}" update status
  assert_contains "${up_st}" "antigravity: version=" "iso update status"
  assert_contains "${up_st}" "opencode: version=" "iso update status"
  AGBOX_DATA_DIR="${iso_data}" with_timeout 30 agbox_exec "${ibin}" update clear all

  local abort_rc=0
  printf 'n\n' | MSB_HOME="${iso_msb}" AGBOX_DATA_DIR="${iso_data}" with_timeout_stdin 30 agbox_exec "${ibin}" remove >/dev/null 2>&1 || abort_rc=$?
  [[ "${abort_rc}" -ne 0 ]] || { echo "Expected remove without y confirmation to abort" >&2; return 1; }
  [[ -d "${iso_data}" ]] || { echo "Expected aborted remove to preserve ${iso_data}" >&2; return 1; }

  MSB_HOME="${iso_msb}" AGBOX_DATA_DIR="${iso_data}" with_timeout 120 agbox_exec "${ibin}" remove --yes
  if [[ -d "${iso_data}" ]]; then
    echo "Expected ${iso_data} deleted after remove --yes" >&2
    return 1
  fi

  local post_snaps=""
  post_snaps="$(MSB_HOME="${iso_msb}" with_timeout 30 "${MSB_BIN_PATH}" snap ls </dev/null 2>/dev/null || true)"
  if grep -Eq 'agbox(:| )|agbox-base(:| )' <<< "${post_snaps}"; then
    echo "Expected isolated snapshots deleted after remove --yes" >&2
    return 1
  fi
}

# ---------------------------------------------------------------------------
# Phase 8: Host state checks
# ---------------------------------------------------------------------------

check_99_verify_host_unchanged() {
  sweep_suite_resources
  local after_dir="${TEST_ROOT}/after-baseline"
  capture_state "${after_dir}"

  local -a items=(data_dir.fp install_bin.fp comp_file.fp msb_home_bins.fp msb_sandboxes.txt msb_snaps.txt msb_volumes.txt agbox_mounts.txt)
  if [[ "${RUNTIME_MSB_HOME}" != "${ORIG_MSB_HOME}" ]]; then
    items+=(msb_home.fp)
  fi

  local failed=0
  local item=""
  for item in "${items[@]}"; do
    if ! diff -u "${BASELINE_DIR}/${item}" "${after_dir}/${item}"; then
      printf 'Host state drift detected in %s\n' "${item}" >&2
      failed=1
    fi
  done
  [[ "${failed}" -eq 0 ]] || return 1
  echo "Verified host agbox data dir, installed binary, msb sandboxes/snapshots/volumes, and mounts are unchanged."
}

check_99_verify_disruptive_cleanup() {
  sweep_suite_resources
  local rem_bin="${ACTIVE_BIN:-${TEST_BIN}}"

  if [[ -d "${ORIG_DATA_DIR}" ]]; then
    local abort_rc=0
    printf 'n\n' | MSB_HOME="${ORIG_MSB_HOME}" AGBOX_DATA_DIR="${ORIG_DATA_DIR}" with_timeout_stdin 30 agbox_exec "${rem_bin}" remove >/dev/null 2>&1 || abort_rc=$?
    [[ "${abort_rc}" -ne 0 ]] || { echo "Expected remove confirmation abort" >&2; return 1; }
  fi

  MSB_HOME="${ORIG_MSB_HOME}" AGBOX_DATA_DIR="${ORIG_DATA_DIR}" with_timeout 120 agbox_exec "${rem_bin}" remove --yes
  restore_install_bin_if_needed

  if [[ -e "${ORIG_DATA_DIR}" ]]; then
    echo "Expected ${ORIG_DATA_DIR} removed after agbox remove --yes" >&2
    return 1
  fi
  if [[ -n "$(list_active_mounts_under "${ORIG_DATA_DIR}")" ]]; then
    echo "Active mounts remain under ${ORIG_DATA_DIR}" >&2
    return 1
  fi

  local after_dir="${TEST_ROOT}/after-disruptive"
  mkdir -p "${after_dir}"
  canonical_msb_sandboxes "${ORIG_MSB_HOME}" "${after_dir}/sandboxes.txt"
  canonical_msb_snaps "${ORIG_MSB_HOME}" "${after_dir}/snaps.txt"
  canonical_msb_volumes "${ORIG_MSB_HOME}" "${after_dir}/volumes.txt"

  if grep -Eq '^agbox(-base|-[[:alnum:]_-]+)[[:space:]]' "${after_dir}/sandboxes.txt"; then
    echo "agbox sandboxes remain after disruptive cleanup:" >&2
    cat "${after_dir}/sandboxes.txt" >&2
    return 1
  fi
  if grep -Eq '^agbox(-base)?:|^agbox-base$' "${after_dir}/snaps.txt"; then
    echo "agbox snapshots remain after disruptive cleanup:" >&2
    cat "${after_dir}/snaps.txt" >&2
    return 1
  fi
  if grep -Eq '^agbox-profile-' "${after_dir}/volumes.txt"; then
    echo "agbox profile volumes remain after disruptive cleanup:" >&2
    cat "${after_dir}/volumes.txt" >&2
    return 1
  fi

  echo "Disruptive cleanup verified complete."
}

# ---------------------------------------------------------------------------
# Environment initialization and suite orchestration
# ---------------------------------------------------------------------------

init_environment() {
  unset_passthrough_secrets
  unset AGBOX_ALLOW_OUTSIDE_HOME AGBOX_MASK_VCS 2>/dev/null || true

  if [[ "${EUID_VAL}" -eq 0 && "${ALLOW_ROOT}" -ne 1 ]]; then
    die_msg "Do not run ${SCRIPT_NAME} as root. Pass --allow-root or set AGBOX_ALLOW_ROOT=1."
  fi

  if [[ -z "${HOME:-}" ]]; then
    HOME="$(getent passwd "${EUID_VAL}" | cut -d: -f6 || true)"
    [[ -n "${HOME}" ]] || die_msg "HOME is not set."
    export HOME
  fi
  HOME_REAL="$(cd -- "${HOME}" && pwd -P)" || die_msg "Failed to resolve HOME directory ${HOME}."

  case "${HOME_REAL}" in
    *[[:space:]\\:,]*)
      die_msg "Resolved HOME (${HOME_REAL}) contains whitespace, backslash, colon, or comma unsupported by agbox mounts."
      ;;
  esac

  if [[ -n "${AGBOX_DATA_DIR:-}" ]]; then
    local raw_data_dir="${AGBOX_DATA_DIR}"
    while [[ "${raw_data_dir}" != "/" && "${raw_data_dir}" == */ ]]; do
      raw_data_dir="${raw_data_dir%/}"
    done
    if [[ "${raw_data_dir}" == "/" ]]; then
      ORIG_DATA_DIR="/"
    else
      local data_parent=""
      data_parent="$(if cd -- "$(dirname -- "${raw_data_dir}")" 2>/dev/null; then pwd -P; fi)"
      if [[ -n "${data_parent}" ]]; then
        if [[ "${data_parent}" == "/" ]]; then
          ORIG_DATA_DIR="/$(basename -- "${raw_data_dir}")"
        else
          ORIG_DATA_DIR="${data_parent}/$(basename -- "${raw_data_dir}")"
        fi
      else
        ORIG_DATA_DIR="${raw_data_dir}"
      fi
    fi
  else
    ORIG_DATA_DIR="${HOME_REAL}/.local/share/agbox"
  fi
  if [[ -n "${MSB_HOME:-}" ]]; then
    ORIG_MSB_HOME="${MSB_HOME}"
  else
    ORIG_MSB_HOME="${HOME_REAL}/.microsandbox"
  fi
  if [[ -n "${AGBOX_INSTALL_DIR:-}" ]]; then
    ORIG_INSTALL_DIR="${AGBOX_INSTALL_DIR}"
  elif [[ "${EUID_VAL}" -eq 0 ]]; then
    ORIG_INSTALL_DIR="/usr/local/bin"
  else
    ORIG_INSTALL_DIR="${HOME_REAL}/.local/bin"
  fi
  while [[ "${ORIG_INSTALL_DIR}" != "/" && "${ORIG_INSTALL_DIR}" == */ ]]; do
    ORIG_INSTALL_DIR="${ORIG_INSTALL_DIR%/}"
  done
  ORIG_INSTALL_BIN="${ORIG_INSTALL_DIR}/agbox"

  if [[ -n "${AGBOX_COMPLETION_DIR:-}" ]]; then
    ORIG_COMP_DIR="${AGBOX_COMPLETION_DIR}"
  elif [[ "${EUID_VAL}" -eq 0 ]]; then
    if [[ -d /usr/share/bash-completion/completions || ! -d /etc/bash_completion.d ]]; then
      ORIG_COMP_DIR="/usr/share/bash-completion/completions"
    else
      ORIG_COMP_DIR="/etc/bash_completion.d"
    fi
  else
    ORIG_COMP_DIR="${XDG_DATA_HOME:-${HOME_REAL}/.local/share}/bash-completion/completions"
  fi
  while [[ "${ORIG_COMP_DIR}" != "/" && "${ORIG_COMP_DIR}" == */ ]]; do
    ORIG_COMP_DIR="${ORIG_COMP_DIR%/}"
  done
  ORIG_COMP_FILE="${ORIG_COMP_DIR}/agbox"

  local cache_parent="${HOME_REAL}/.cache"
  if [[ -d "${cache_parent}" && ! -L "${cache_parent}" ]]; then
    TEST_ROOT="${cache_parent}/agbox-e2e-${SUITE_ID}"
  elif [[ ! -e "${cache_parent}" && ! -L "${cache_parent}" ]] && mkdir -p "${cache_parent}" 2>/dev/null; then
    CREATED_CACHE_DIR=1
    TEST_ROOT="${cache_parent}/agbox-e2e-${SUITE_ID}"
  else
    TEST_ROOT="${HOME_REAL}/.agbox-e2e-${SUITE_ID}"
  fi
  mkdir -p "${TEST_ROOT}"
  chmod 0700 "${TEST_ROOT}"
  trap global_cleanup EXIT
  trap 'handle_interrupt INT 130' INT
  trap 'handle_interrupt TERM 143' TERM
  trap 'handle_interrupt HUP 129' HUP

  STYLECHECK_SRC="${TEST_ROOT}/helpers/stylecheck/main.go"
  STUB_AGY_BIN="${TEST_ROOT}/helpers/agy"
  TEST_BIN="${TEST_ROOT}/bin/agbox"
  ACTIVE_BIN="${TEST_BIN}"

  if ! command -v go >/dev/null 2>&1; then
    if [[ -d /usr/local/go/bin && -x /usr/local/go/bin/go ]]; then
      export PATH="${PATH}:/usr/local/go/bin"
    fi
  fi

  if [[ "${EUID_VAL}" -eq 0 ]]; then
    if [[ -z "${GOCACHE:-}" && "$(stat -c %u "${HOME_REAL}" 2>/dev/null || echo 1)" -ne 0 ]]; then
      # Keep root Go build artifacts inside TEST_ROOT when HOME_REAL is non-root.
      export GOCACHE="${TEST_ROOT}/gocache"
      mkdir -p "${GOCACHE}"
      chmod 0700 "${GOCACHE}"
    fi
    if [[ -z "${GOMODCACHE:-}" && ! -d "${HOME_REAL}/go/pkg/mod" && -n "${SUDO_USER:-}" && "${SUDO_USER}" != "root" ]]; then
      local sudo_home=""
      sudo_home="$(getent passwd "${SUDO_USER}" | cut -d: -f6 || true)"
      if [[ -n "${sudo_home}" && -d "${sudo_home}/go/pkg/mod" ]]; then
        export GOMODCACHE="${sudo_home}/go/pkg/mod"
      fi
    fi
  fi

  if [[ -n "${CUSTOM_LOG_DIR}" ]]; then
    LOG_DIR="${CUSTOM_LOG_DIR}"
    mkdir -p "${LOG_DIR}"
  else
    LOG_DIR="$(mktemp -d "${TMPDIR:-/tmp}/agbox-test-logs-XXXXXXXX")"
  fi
  chmod 0700 "${LOG_DIR}"
  SUITE_LOG="${LOG_DIR}/suite.log"
  : > "${SUITE_LOG}"

  if [[ "${DISRUPTIVE_MODE}" -eq 1 && -f "${ORIG_INSTALL_BIN}" && ! -L "${ORIG_INSTALL_BIN}" ]]; then
    ORIG_INSTALL_EXISTED=1
    BACKUP_INSTALL_BIN="${TEST_ROOT}/backup-orig-agbox"
    cp -p "${ORIG_INSTALL_BIN}" "${BACKUP_INSTALL_BIN}"
  fi
  if [[ "${DISRUPTIVE_MODE}" -eq 1 && -f "${ORIG_COMP_FILE}" && ! -L "${ORIG_COMP_FILE}" ]]; then
    ORIG_COMP_EXISTED=1
    BACKUP_COMP_FILE="${TEST_ROOT}/backup-orig-agbox-completion"
    cp -p "${ORIG_COMP_FILE}" "${BACKUP_COMP_FILE}"
  fi

  export AGBOX_CPUS="${AGBOX_TEST_CPUS:-2}"
  export AGBOX_MEMORY="${AGBOX_TEST_MEMORY:-4G}"
  export AGBOX_ROOT_DISK="${AGBOX_TEST_ROOT_DISK:-20G}"
  export AGBOX_PROFILE_DISK="${AGBOX_TEST_PROFILE_DISK:-256M}"

  MSB_BIN_PATH="$(resolve_msb_bin 2>/dev/null || true)"
  MDFORMAT_BIN="$(resolve_mdformat_bin 2>/dev/null || true)"

  BASELINE_DIR="${TEST_ROOT}/baseline"
  capture_state "${BASELINE_DIR}"
}

last_check_passed() {
  local n="${#RESULT_STATUSES[@]}"
  [[ "${n}" -gt 0 && "${RESULT_STATUSES[$((n - 1))]}" == "PASS" ]]
}

ensure_vm_preflight_evaluated() {
  if [[ "${VM_PREFLIGHT_RAN}" -eq 1 ]]; then
    return 0
  fi
  VM_PREFLIGHT_RAN=1
  run_check "09-kvm-and-msb-preflight" "Verify msb, /dev/kvm, and FUSE prerequisites" check_09_kvm_and_msb_preflight
  local pre_status="${RESULT_STATUSES[$(( ${#RESULT_STATUSES[@]} - 1 ))]}"
  if [[ "${pre_status}" == "PASS" ]]; then
    VM_READY=1
  elif [[ "${pre_status}" == "SKIP" ]]; then
    VM_READY=0
    VM_BLOCK_REASON="$(grep '^SKIP_REASON: ' "${LOG_DIR}/09-kvm-and-msb-preflight.log" 2>/dev/null | head -n 1 | sed 's/^SKIP_REASON: //' || printf '%s' "skipped via preflight")"
  else
    VM_READY=0
    VM_BLOCK_REASON="blocked by failed 09-kvm-and-msb-preflight"
  fi
}

prepare_runtime_env_for_vm_tests() {
  if [[ "${VM_READY}" -ne 1 || "${VM_ENV_READY}" -eq 1 ]]; then
    return 0
  fi

  if [[ ! -x "${TEST_BIN}" || ! -x "${STUB_AGY_BIN}" ]]; then
    build_test_binaries
  fi

  if [[ "${DISRUPTIVE_MODE}" -eq 1 ]]; then
    RUNTIME_MSB_HOME="${ORIG_MSB_HOME}"
    RUNTIME_DATA_DIR="${ORIG_DATA_DIR}"
    DISRUPTIVE_SETUP_DONE=1

    run_check "10-disruptive-clean-pre" "Remove existing state before clean-slate test" check_10_disruptive_clean_pre
    if ! last_check_passed; then
      VM_READY=0
      VM_BLOCK_REASON="blocked by failed 10-disruptive-clean-pre"
      return 0
    fi

    run_check "11-disruptive-install-sh" "Run install.sh and setup on clean system" check_11_disruptive_install_sh
    if ! last_check_passed || [[ ! -x "${ORIG_INSTALL_BIN}" ]]; then
      VM_READY=0
      VM_BLOCK_REASON="blocked by failed 11-disruptive-install-sh"
      return 0
    fi
    ACTIVE_BIN="${ORIG_INSTALL_BIN}"

    run_check "12-disruptive-create-and-edit-base" "Create and edit live base snapshot" check_12_disruptive_create_and_edit_base
    if ! last_check_passed || [[ ! -f "${RUNTIME_DATA_DIR}/config" ]]; then
      VM_READY=0
      VM_BLOCK_REASON="blocked by failed 12-disruptive-create-and-edit-base"
      return 0
    fi

    load_base_info_from_config "${RUNTIME_DATA_DIR}/config"
    if [[ -z "${BASE_SNAP}" ]]; then
      VM_READY=0
      VM_BLOCK_REASON="missing snapshot in config"
      return 0
    fi
    VM_ENV_READY=1
    return 0
  fi

  local host_has_snap=0
  if [[ -f "${ORIG_DATA_DIR}/config" ]]; then
    load_base_info_from_config "${ORIG_DATA_DIR}/config"
    if [[ -n "${BASE_SNAP}" ]]; then
      local snaps_list=""
      snaps_list="$(MSB_HOME="${ORIG_MSB_HOME}" with_timeout 30 "${MSB_BIN_PATH}" snap ls </dev/null 2>/dev/null || true)"
      if awk -v target="${BASE_SNAP}" '$1==target{found=1} END{exit(found?0:1)}' <<< "${snaps_list}"; then
        host_has_snap=1
      fi
    fi
  fi

  if [[ "${host_has_snap}" -eq 1 ]]; then
    RUNTIME_MSB_HOME="${ORIG_MSB_HOME}"
    RUNTIME_DATA_DIR="${TEST_ROOT}/runtime-data"
    mkdir -p "${RUNTIME_DATA_DIR}/run"
    chmod 0700 "${RUNTIME_DATA_DIR}" "${RUNTIME_DATA_DIR}/run"
    install -m 0600 "${ORIG_DATA_DIR}/config" "${RUNTIME_DATA_DIR}/config"

    # Copy active user sandbox markers so ReapOrphanRuns and ReapStaleFilterDirs skip them.
    if [[ -d "${ORIG_DATA_DIR}/run" ]]; then
      local d=""
      for d in "${ORIG_DATA_DIR}/run"/*; do
        [[ -d "${d}" ]] || continue
        local bid=""
        bid="$(basename "${d}")"
        mkdir -p "${RUNTIME_DATA_DIR}/run/${bid}"
        chmod 0700 "${RUNTIME_DATA_DIR}/run/${bid}"
        local mf=""
        for mf in run.meta suspended detached deleting; do
          if [[ -f "${d}/${mf}" ]]; then
            install -m 0600 "${d}/${mf}" "${RUNTIME_DATA_DIR}/run/${bid}/${mf}"
          fi
        done
      done
    fi

    run_check "10-agbox-setup" "Run agbox setup against isolated runtime config" check_10_agbox_setup
    if ! last_check_passed; then
      VM_READY=0
      VM_BLOCK_REASON="blocked by failed 10-agbox-setup"
      return 0
    fi
    load_base_info_from_config "${RUNTIME_DATA_DIR}/config"
    VM_ENV_READY=1
    return 0
  fi

  # No host base snapshot exists yet, so build one inside an isolated MSB_HOME.
  if ! prepare_isolated_msb_home "${TEST_ROOT}/iso-msb"; then
    VM_READY=0
    VM_BLOCK_REASON="no existing base snapshot and msb does not isolate MSB_HOME (re-run with --disruptive)"
    return 0
  fi
  RUNTIME_MSB_HOME="${TEST_ROOT}/iso-msb"
  RUNTIME_DATA_DIR="${TEST_ROOT}/iso-data"
  mkdir -p "${RUNTIME_DATA_DIR}"
  chmod 0700 "${RUNTIME_DATA_DIR}"

  run_check "10-agbox-setup" "Run agbox setup inside isolated MSB_HOME" check_10_agbox_setup
  if ! last_check_passed; then
    VM_READY=0
    VM_BLOCK_REASON="blocked by failed 10-agbox-setup"
    return 0
  fi
  run_check "11-bootstrap-isolated-base" "Build isolated base snapshot for integration checks" check_11_bootstrap_isolated_base
  if ! last_check_passed; then
    VM_READY=0
    VM_BLOCK_REASON="blocked by failed 11-bootstrap-isolated-base"
    return 0
  fi
  load_base_info_from_config "${RUNTIME_DATA_DIR}/config"
  if [[ -z "${BASE_SNAP}" ]]; then
    VM_READY=0
    VM_BLOCK_REASON="missing snapshot in isolated config"
    return 0
  fi
  VM_ENV_READY=1
  return 0
}

maybe_run_phase_check() {
  local id="$1"
  local desc="$2"
  local fn_name="$3"
  local needs_vm="$4"

  if ! should_run_check "${id}" "${desc}"; then
    return 0
  fi

  if [[ "${needs_vm}" -eq 1 ]]; then
    if [[ ! -x "${TEST_BIN}" || ! -x "${STUB_AGY_BIN}" ]]; then
      build_test_binaries
    fi
    ensure_vm_preflight_evaluated
    if [[ "${VM_READY}" -ne 1 ]]; then
      record_blocked_skip "${id}" "${desc}" "${VM_BLOCK_REASON}"
      return 0
    fi
    if [[ "${VM_ENV_READY}" -ne 1 ]]; then
      prepare_runtime_env_for_vm_tests
      if [[ "${VM_READY}" -ne 1 || "${VM_ENV_READY}" -ne 1 ]]; then
        record_blocked_skip "${id}" "${desc}" "${VM_BLOCK_REASON:-runtime environment setup failed}"
        return 0
      fi
    fi
  fi

  run_check "${id}" "${desc}" "${fn_name}"
}

print_final_report() {
  local total_elapsed=$(( $(date +%s) - SCRIPT_START_EPOCH ))
  local summary=""
  summary=$(
    printf '\n'
    printf '====================================================================\n'
    printf 'agbox test.sh summary (%ds elapsed)\n' "${total_elapsed}"
    printf '====================================================================\n'
    local i=0
    while [[ "${i}" -lt "${#RESULT_IDS[@]}" ]]; do
      printf '  [%-4s] %-46s (%3ss)  %s\n' \
        "${RESULT_STATUSES[$i]}" "${RESULT_IDS[$i]}" "${RESULT_DURATIONS[$i]}" "${RESULT_DESCS[$i]}"
      i=$((i + 1))
    done
    printf '%s\n' '--------------------------------------------------------------------'
    printf 'Totals: PASS=%d  FAIL=%d  SKIP=%d\n' "${PASS_COUNT}" "${FAIL_COUNT}" "${SKIP_COUNT}"
    printf 'Master log: %s\n' "${SUITE_LOG}"
    if [[ "${FAIL_COUNT}" -gt 0 ]]; then
      printf '\nFailed checks:\n'
      local fid=""
      for fid in "${FAILED_IDS[@]}"; do
        local flog="${LOG_DIR}/${fid}.log"
        printf '  - %s: %s\n' "${fid}" "${flog}"
        if [[ -s "${flog}" ]]; then
          tail -n 10 "${flog}" | sed 's/^/      /'
        fi
      done
    fi
    printf '====================================================================\n'
  )
  printf '%s\n' "${summary}"
  printf '%s\n' "${summary}" >> "${SUITE_LOG}" 2>/dev/null || true
}

main() {
  parse_args "$@"
  init_environment

  log_msg "Starting agbox test suite (mode: full=${FULL_MODE}, disruptive=${DISRUPTIVE_MODE}, skip_vm=${SKIP_VM})"
  log_msg "Logs directory: ${LOG_DIR}"

  # Phase 1: Static, style, unit/race, and binary build.
  maybe_run_phase_check "01-static-and-style" "Check bash syntax, gofmt, style/semicolons, and mdformat" check_01_static_and_style 0
  maybe_run_phase_check "02-go-vet" "Run go vet across all packages" check_02_go_vet 0
  maybe_run_phase_check "03-go-unit-race" "Run full Go unit test suite with -race" check_03_go_unit_race 0
  maybe_run_phase_check "04-build-binaries" "Build agbox CLI and stub agy test binaries" check_04_build_binaries 0

  # Phase 2: CLI validation and offline security boundaries.
  maybe_run_phase_check "05-cli-help-and-categories" "Verify help output, category listing, and flag rejection" check_05_cli_help_and_categories 0
  maybe_run_phase_check "06-security-validation-and-tamper-checks" "Verify share conflicts, skills/rules/auth/update tamper checks" check_06_security_validation_and_tamper_checks 0
  maybe_run_phase_check "07-msb-error-diagnostics-not-swallowed" "Verify non-interactive msb errors surface diagnostics and exit code" check_07_msb_error_diagnostics_not_swallowed 0

  # Phase 3: Standalone embedded FUSE Workspace Hub and remote bridge.
  maybe_run_phase_check "08-fuse-workspace-hub" "Verify live FUSE Workspace Hub VCS masking and ro enforcement" check_08_fuse_workspace_hub 0
  maybe_run_phase_check "08b-remote-bridge-and-loopback" "Verify live remote FUSE bridge, static ELF execve, and PTY pairing loopback" check_08b_remote_bridge_and_loopback 0

  # Phases 4-6: Virtualization preflight and live microVM integration suite.
  local pair=""
  local -a core_vm_checks=(
    "20-ephemeral-run-shares-and-secrets|Verify ephemeral run, FUSE shares, secret streaming, and passthrough exit|check_20_ephemeral_run_shares_and_secrets"
    "21-persistence-auth-skills-rules-agents-profile|Verify auth, skills, rules, agent cache, and profile disk volume|check_21_persistence_auth_skills_rules_agents_profile"
    "22-persist-remote-control-shares-suspend-resume|Verify --persist remote-control, dynamic shares, suspend, resume, and stop|check_22_persist_remote_control_shares_suspend_resume"
    "23-serve-loopback-probe|Verify loopback-bound --serve --probe readiness and teardown|check_23_serve_loopback_probe"
    "24-remote-command-in-vm|Verify default in-VM remote bridge, INSTRUCTIONS.md merge, and --no-remote|check_24_remote_command_in_vm"
  )
  local -a full_vm_checks=(
    "30-network-isolation-firewall|Verify --no-net and default-deny IMDS/RFC1918 firewall rules|check_30_network_isolation_firewall"
    "31-share-open-fd-revocation|Verify open writable FD gating and forced EROFS/ESTALE revocation|check_31_share_open_fd_revocation"
    "32-profile-lock-and-orphan-reaping|Verify profile flock contention and dead-owner orphan reaping|check_32_profile_lock_and_orphan_reaping"
    "33-serve-detached-basic-auth-lifecycle|Verify detached --serve HTTP Basic Auth across suspend and resume|check_33_serve_detached_basic_auth_lifecycle"
    "34-live-agent-update|Verify live agbox update binary capture and read-only mount|check_34_live_agent_update"
  )

  if [[ -z "${FILTER_PATTERN}" ]]; then
    ensure_vm_preflight_evaluated
    if [[ "${VM_READY}" -eq 1 ]]; then
      prepare_runtime_env_for_vm_tests
    fi
  fi

  for pair in "${core_vm_checks[@]}"; do
    IFS='|' read -r cid cdesc cfn <<< "${pair}"
    maybe_run_phase_check "${cid}" "${cdesc}" "${cfn}" 1
  done

  if [[ "${FULL_MODE}" -eq 1 ]]; then
    for pair in "${full_vm_checks[@]}"; do
      IFS='|' read -r cid cdesc cfn <<< "${pair}"
      maybe_run_phase_check "${cid}" "${cdesc}" "${cfn}" 1
    done
    if [[ "${DISRUPTIVE_MODE}" -eq 0 ]]; then
      if should_run_check "40-isolated-full-lifecycle" "Run isolated clean-slate install, create-base, edit-base, update, and remove"; then
        if [[ ! -x "${TEST_BIN}" || ! -x "${STUB_AGY_BIN}" ]]; then
          build_test_binaries
        fi
        ensure_vm_preflight_evaluated
        if [[ "${VM_READY}" -ne 1 ]]; then
          record_blocked_skip "40-isolated-full-lifecycle" "Run isolated clean-slate install, create-base, edit-base, update, and remove" "${VM_BLOCK_REASON}"
        else
          run_check "40-isolated-full-lifecycle" "Run isolated clean-slate install, create-base, edit-base, update, and remove" check_40_isolated_full_lifecycle
        fi
      fi
    fi
  fi

  # Phase 8: Final teardown and state check (always runs).
  if [[ "${DISRUPTIVE_MODE}" -eq 1 && "${DISRUPTIVE_SETUP_DONE}" -eq 1 ]]; then
    run_check "99-verify-disruptive-cleanup" "Verify agbox remove --yes cleaned all live state" check_99_verify_disruptive_cleanup
    if last_check_passed; then
      DISRUPTIVE_CLEANUP_DONE=1
    fi
  else
    run_check "99-verify-host-unchanged" "Verify existing agbox state, binaries, and msb resources stayed unchanged" check_99_verify_host_unchanged
  fi

  print_final_report
  if [[ "${FAIL_COUNT}" -gt 0 ]]; then
    exit 1
  fi
  exit 0
}

main "$@"
