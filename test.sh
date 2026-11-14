#!/usr/bin/env bash
# test.sh - Automated integration and security test runner for agbox.
#
# By default, runs fast checks without modifying existing agbox data,
# snapshots, sandboxes, or installed binaries. Use --full for extended
# runtime checks and --disruptive to test clean-slate setup and teardown.

set -uo pipefail

readonly SCRIPT_NAME="test.sh"
readonly SCRIPT_START_EPOCH="$(date +%s)"

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
HELPERS_BUILT=0
AGBOX_BUILT=0
DISRUPTIVE_SETUP_DONE=0
DISRUPTIVE_CLEANUP_DONE=0
CLEANUP_RAN=0
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
  --skip-vm         Skip microVM tests gracefully when /dev/kvm or msb is unavailable.
  --allow-root      Allow running as host root (or set AGBOX_ALLOW_ROOT=1).
  --log-dir DIR     Store per-check logs under DIR instead of a temporary directory.
  --filter TEXT     Run checks whose ID or description contains TEXT (plus required setup/verify).
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
  local line="[agbox-test $(timestamp_hms)] $*"
  printf '%s\n' "${line}"
  append_suite_log "${line}"
}

warn_msg() {
  local line="[agbox-test $(timestamp_hms)] WARN: $*"
  printf '%s\n' "${line}" >&2
  append_suite_log "${line}"
}

die_msg() {
  local line="[agbox-test $(timestamp_hms)] ERROR: $*"
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

  if [[ "${stdin_mode}" == "keep" ]]; then
    timeout --kill-after=15s "${secs}s" "${cmd[@]}"
  else
    timeout --kill-after=15s "${secs}s" "${cmd[@]}" </dev/null
  fi
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
  done < <(find "${root_dir}" -type f \( -name 'ws.pid' -o -name 'm*.pid' \) -print0 2>/dev/null)

  local fm=""
  fm="$(resolve_fusermount_bin 2>/dev/null || true)"
  local mp=""
  for mp in $(list_active_mounts_under "${root_dir}"); do
    if [[ -n "${fm}" ]]; then
      "${fm}" -u "${mp}" 2>/dev/null || true
    fi
    umount "${mp}" 2>/dev/null || true
  done

  sleep 0.2
  if [[ -n "$(list_active_mounts_under "${root_dir}")" ]]; then
    while IFS= read -r -d '' pidf; do
      stop_filter_pidfile "${pidf}" KILL
    done < <(find "${root_dir}" -type f \( -name 'ws.pid' -o -name 'm*.pid' \) -print0 2>/dev/null)
    for mp in $(list_active_mounts_under "${root_dir}"); do
      if [[ -n "${fm}" ]]; then
        "${fm}" -uz "${mp}" 2>/dev/null || true
      fi
      umount -l "${mp}" 2>/dev/null || true
    done
  fi
}

sweep_msb_home_suite_resources() {
  local mh="$1"
  [[ -n "${MSB_BIN_PATH}" && -d "${mh}" ]] || return 0

  local ls_out=""
  ls_out="$(MSB_HOME="${mh}" with_timeout 20 "${MSB_BIN_PATH}" ls 2>/dev/null || true)"
  if [[ -n "${ls_out}" ]]; then
    local sb=""
    while IFS= read -r sb; do
      [[ -n "${sb}" ]] || continue
      if [[ "${sb}" == agbox-${SUITE_ID}-* ]]; then
        MSB_HOME="${mh}" with_timeout 20 "${MSB_BIN_PATH}" rm -f "${sb}" >/dev/null 2>&1 || true
      fi
    done < <(awk 'NR>0 && $1 !~ /^NAME$/ && $1 !~ /^-+$/ {print $1}' <<< "${ls_out}")
  fi

  local vol_out=""
  vol_out="$(MSB_HOME="${mh}" with_timeout 20 "${MSB_BIN_PATH}" volume ls 2>/dev/null || true)"
  if [[ -n "${vol_out}" ]]; then
    local vol=""
    while IFS= read -r vol; do
      [[ -n "${vol}" ]] || continue
      if [[ "${vol}" == agbox-profile-${SUITE_ID}-* ]]; then
        MSB_HOME="${mh}" with_timeout 20 "${MSB_BIN_PATH}" volume rm "${vol}" >/dev/null 2>&1 || true
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
  [[ "${DISRUPTIVE_MODE}" -eq 1 && -n "${ORIG_INSTALL_BIN}" ]] || return 0
  if [[ "${ORIG_INSTALL_EXISTED}" -eq 1 && -n "${BACKUP_INSTALL_BIN}" && -f "${BACKUP_INSTALL_BIN}" ]]; then
    mkdir -p "$(dirname "${ORIG_INSTALL_BIN}")"
    install -m 0755 "${BACKUP_INSTALL_BIN}" "${ORIG_INSTALL_BIN}" 2>/dev/null || true
  elif [[ "${ORIG_INSTALL_EXISTED}" -eq 0 && -e "${ORIG_INSTALL_BIN}" ]]; then
    rm -f "${ORIG_INSTALL_BIN}" 2>/dev/null || true
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
  if ! out="$(MSB_HOME="${mh}" with_timeout 20 "${MSB_BIN_PATH}" ls 2>/dev/null)"; then
    printf 'MSB_LS_ERR\n' > "${out_file}"
    return 0
  fi
  awk '
    {
      line = $0
      gsub(/^[[:space:]]+|[[:space:]]+$/, "", line)
      if (line == "" || line ~ /^NAME/ || line ~ /^-+/) {
        next
      }
      split(line, f, /[[:space:]]+/)
      low = tolower(line)
      state = (index(low, "running") > 0) ? "running" : "stopped"
      print f[1] "\t" state
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
  if ! out="$(MSB_HOME="${mh}" with_timeout 20 "${MSB_BIN_PATH}" snap ls 2>/dev/null)"; then
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
  if ! out="$(MSB_HOME="${mh}" with_timeout 20 "${MSB_BIN_PATH}" volume ls 2>/dev/null)"; then
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
  fingerprint_dir "${ORIG_DATA_DIR}" "${dir}/data_dir.fp"
  if [[ -n "${ORIG_INSTALL_BIN}" && ( -e "${ORIG_INSTALL_BIN}" || -L "${ORIG_INSTALL_BIN}" ) ]]; then
    fingerprint_dir "${ORIG_INSTALL_BIN}" "${dir}/install_bin.fp"
  else
    printf 'ABSENT\n' > "${dir}/install_bin.fp"
  fi
  canonical_msb_sandboxes "${ORIG_MSB_HOME}" "${dir}/msb_sandboxes.txt"
  canonical_msb_snaps "${ORIG_MSB_HOME}" "${dir}/msb_snaps.txt"
  canonical_msb_volumes "${ORIG_MSB_HOME}" "${dir}/msb_volumes.txt"
  canonical_agbox_mounts "${dir}/agbox_mounts.txt"
}

write_helpers() {
  if [[ -f "${TEST_ROOT}/helpers/.ready" ]]; then
    HELPERS_BUILT=1
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

	for _, md := range []string{"README.md", "USER_GUIDE.md", "AGENTS.md"} {
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
  HELPERS_BUILT=1
}

build_test_binaries() {
  write_helpers
  if [[ -z "${ACTIVE_BIN}" ]]; then
    ACTIVE_BIN="${TEST_BIN}"
  fi
  if [[ -x "${TEST_BIN}" && -x "${STUB_AGY_BIN}" ]]; then
    AGBOX_BUILT=1
    return 0
  fi
  mkdir -p "${TEST_ROOT}/bin"
  chmod 0700 "${TEST_ROOT}/bin"

  (
    cd "${REPO_DIR}"
    go_exec build -o "${TEST_BIN}" ./cmd/agbox
  )
  chmod 0755 "${TEST_BIN}"

  (
    cd "${TEST_ROOT}/helpers"
    CGO_ENABLED=0 GOOS=linux go_exec build -ldflags="-s -w" -o "${STUB_AGY_BIN}" ./stubagy
  )
  chmod 0755 "${STUB_AGY_BIN}"

  AGBOX_BUILT=1
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
  if ! MSB_HOME="${target}" with_timeout 30 "${MSB_BIN_PATH}" volume create "${probe_vol}" --kind disk --size 16M >/dev/null 2>&1; then
    return 1
  fi

  if [[ "${target}" != "${ORIG_MSB_HOME}" ]]; then
    local orig_vols=""
    orig_vols="$(MSB_HOME="${ORIG_MSB_HOME}" with_timeout 20 "${MSB_BIN_PATH}" volume ls 2>/dev/null || true)"
    if grep -Fq "${probe_vol}" <<< "${orig_vols}"; then
      MSB_HOME="${target}" with_timeout 20 "${MSB_BIN_PATH}" volume rm "${probe_vol}" >/dev/null 2>&1 || true
      MSB_HOME="${ORIG_MSB_HOME}" with_timeout 20 "${MSB_BIN_PATH}" volume rm "${probe_vol}" >/dev/null 2>&1 || true
      return 1
    fi
  fi

  MSB_HOME="${target}" with_timeout 20 "${MSB_BIN_PATH}" volume rm "${probe_vol}" >/dev/null 2>&1 || true
  return 0
}

wait_for_sandbox_running() {
  local mh="$1"
  local sbx="$2"
  local max_tries="${3:-40}"
  local i=0
  while [[ "${i}" -lt "${max_tries}" ]]; do
    local out=""
    out="$(MSB_HOME="${mh}" with_timeout 15 "${MSB_BIN_PATH}" ls 2>/dev/null || true)"
    if awk -v target="${sbx}" '
      {
        if ($1 == target && index(tolower($0), "running") > 0) {
          found = 1
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
    out="$(MSB_HOME="${mh}" with_timeout 15 "${MSB_BIN_PATH}" ls 2>/dev/null || true)"
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
      trap 'printf "[FAIL LINE %d] %s\n" "$LINENO" "$BASH_COMMAND" >&2' ERR
      "${fn_name}" </dev/null
    ) 2>&1 | tee -a "${step_log}"
    rc="${PIPESTATUS[0]}"
  else
    (
      set -Eeuo pipefail
      trap 'printf "[FAIL LINE %d] %s\n" "$LINENO" "$BASH_COMMAND" >&2' ERR
      "${fn_name}" </dev/null
    ) >"${step_log}" 2>&1
    rc=$?
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
      "${MDFORMAT_BIN}" --check README.md USER_GUIDE.md AGENTS.md
    )
    echo "mdformat --check README.md USER_GUIDE.md AGENTS.md: OK"
  else
    echo "mdformat not found on PATH. Skipping Markdown formatting check."
  fi
}

check_02_go_vet() {
  (
    cd "${REPO_DIR}"
    with_timeout 120 go vet ./...
  )
}

check_03_go_unit_race() {
  (
    cd "${REPO_DIR}"
    with_timeout 240 go_exec test -count=1 -race ./...
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
  agbox_exec "${TEST_BIN}" --help >/dev/null
  for sub in setup create-base edit-base update auth skills rules profile share run suspend resume stop remove status; do
    agbox_exec "${TEST_BIN}" "${sub}" --help >/dev/null
  done

  local cats_out=""
  cats_out="$(agbox_exec "${TEST_BIN}" edit-base --list)"
  for sub in core go rust esphome embedded-rust chrome hugo caddy; do
    assert_contains "${cats_out}" "${sub}" "edit-base --list"
  done

  local err_out=""
  local rc=0
  err_out="$(AGBOX_DATA_DIR="${TEST_ROOT}/sec-data" agbox_exec "${TEST_BIN}" bogus-mode 2>&1)" || rc=$?
  [[ "${rc}" -ne 0 ]] || { echo "Expected bogus-mode to fail" >&2; return 1; }
  assert_contains "${err_out}" "[agbox] ERROR:" "bogus-mode stderr"

  rc=0
  err_out="$(AGBOX_DATA_DIR="${TEST_ROOT}/sec-data" agbox_exec "${TEST_BIN}" run --bogus-flag 2>&1)" || rc=$?
  [[ "${rc}" -ne 0 ]] || { echo "Expected --bogus-flag to fail" >&2; return 1; }
  assert_contains "${err_out}" "[agbox] ERROR:" "--bogus-flag stderr"
}

check_06_security_validation_and_tamper_checks() {
  build_test_binaries
  local sec_data="${TEST_ROOT}/sec-data"
  rm -rf "${sec_data}"
  mkdir -p "${sec_data}" "${TEST_ROOT}/sec-src"
  chmod 0700 "${sec_data}" "${TEST_ROOT}/sec-src"

  if [[ "${EUID_VAL}" -eq 0 ]]; then
    local root_err=""
    local root_rc=0
    root_err="$(env -u AGBOX_ALLOW_ROOT AGBOX_ALLOW_ROOT=0 AGBOX_DATA_DIR="${sec_data}" "${TEST_BIN}" status 2>&1)" || root_rc=$?
    [[ "${root_rc}" -ne 0 ]] || { echo "Expected root run without --allow-root to fail" >&2; return 1; }
    assert_contains "${root_err}" "do not run as root" "root rejection stderr"
  fi

  local err_out=""
  local rc=0
  local -a bad_cli_cases=(
    "run --ro --rw ${TEST_ROOT}/sec-src"
    "run --mask-vcs --vcs ${TEST_ROOT}/sec-src"
    "run --ro --vcs-hooks ${TEST_ROOT}/sec-src"
    "run --serve --remote-control ${TEST_ROOT}/sec-src"
    "share set agbox-test proj"
    "share add --ro --rw agbox-test ${TEST_ROOT}/sec-src"
    "share add --ro --vcs-hooks agbox-test ${TEST_ROOT}/sec-src"
    "share list agbox-base"
  )
  local spec=""
  for spec in "${bad_cli_cases[@]}"; do
    read -r -a parts <<< "${spec}"
    rc=0
    err_out="$(AGBOX_DATA_DIR="${sec_data}" agbox_exec "${TEST_BIN}" "${parts[@]}" 2>&1)" || rc=$?
    [[ "${rc}" -ne 0 ]] || { echo "Expected CLI rejection for: ${spec}" >&2; return 1; }
    assert_contains "${err_out}" "[agbox] ERROR:" "CLI rejection for ${spec}"
  done

  local -a bad_envs=(
    "AGBOX_CPUS=0"
    "AGBOX_MEMORY=invalid"
    "AGBOX_ROOT_DISK=0G"
    "AGBOX_AGY_INSTALLER_URL=http://plain.example.com/install.sh"
    "AGBOX_MASK_VCS=nope"
  )
  local kv=""
  for kv in "${bad_envs[@]}"; do
    rc=0
    err_out="$( (
      export "${kv}"
      AGBOX_DATA_DIR="${sec_data}" agbox_exec "${TEST_BIN}" skills list
    ) 2>&1)" || rc=$?
    [[ "${rc}" -ne 0 ]] || { echo "Expected env rejection for ${kv}" >&2; return 1; }
    assert_contains "${err_out}" "[agbox] ERROR:" "env rejection for ${kv}"
  done

  # Skills CRUD and symlink tamper rejection.
  local out=""
  out="$(AGBOX_DATA_DIR="${sec_data}" agbox_exec "${TEST_BIN}" skills list)"
  assert_contains "${out}" "No global skills installed" "empty skills list"

  mkdir -p "${TEST_ROOT}/sec-src/myskill"
  printf '# My Skill\nTest skill instructions.\n' > "${TEST_ROOT}/sec-src/myskill/SKILL.md"
  AGBOX_DATA_DIR="${sec_data}" agbox_exec "${TEST_BIN}" skills add "${TEST_ROOT}/sec-src/myskill" >/dev/null
  out="$(AGBOX_DATA_DIR="${sec_data}" agbox_exec "${TEST_BIN}" skills list)"
  assert_contains "${out}" "myskill" "skills list"

  rc=0
  AGBOX_DATA_DIR="${sec_data}" agbox_exec "${TEST_BIN}" skills add "${TEST_ROOT}/sec-src/myskill" >/dev/null 2>&1 || rc=$?
  [[ "${rc}" -ne 0 ]] || { echo "Expected duplicate skills add without --force to fail" >&2; return 1; }
  AGBOX_DATA_DIR="${sec_data}" agbox_exec "${TEST_BIN}" skills add --force "${TEST_ROOT}/sec-src/myskill" >/dev/null

  ln -s /etc/passwd "${sec_data}/skills/evil-link"
  rc=0
  err_out="$(AGBOX_DATA_DIR="${sec_data}" agbox_exec "${TEST_BIN}" skills list 2>&1)" || rc=$?
  [[ "${rc}" -ne 0 ]] || { echo "Expected symlink in skills dir to fail closed" >&2; return 1; }
  assert_contains "${err_out}" "symlink" "skills symlink tamper error"
  rm -f "${sec_data}/skills/evil-link"
  AGBOX_DATA_DIR="${sec_data}" agbox_exec "${TEST_BIN}" skills rm myskill >/dev/null

  # Rules CRUD and content/symlink tamper rejection.
  out="$(AGBOX_DATA_DIR="${sec_data}" agbox_exec "${TEST_BIN}" rules list)"
  assert_contains "${out}" "No global rules installed" "empty rules list"

  : > "${TEST_ROOT}/sec-src/empty.md"
  rc=0
  AGBOX_DATA_DIR="${sec_data}" agbox_exec "${TEST_BIN}" rules add "${TEST_ROOT}/sec-src/empty.md" >/dev/null 2>&1 || rc=$?
  [[ "${rc}" -ne 0 ]] || { echo "Expected empty rule file to fail" >&2; return 1; }

  printf 'hello\0world\n' > "${TEST_ROOT}/sec-src/nul.md"
  rc=0
  AGBOX_DATA_DIR="${sec_data}" agbox_exec "${TEST_BIN}" rules add "${TEST_ROOT}/sec-src/nul.md" >/dev/null 2>&1 || rc=$?
  [[ "${rc}" -ne 0 ]] || { echo "Expected NUL byte rule file to fail" >&2; return 1; }

  printf 'Always verify outputs.\n' > "${TEST_ROOT}/sec-src/r1.md"
  AGBOX_DATA_DIR="${sec_data}" agbox_exec "${TEST_BIN}" rules add "${TEST_ROOT}/sec-src/r1.md" >/dev/null
  AGBOX_DATA_DIR="${sec_data}" agbox_exec "${TEST_BIN}" rules add --name named-rule "${TEST_ROOT}/sec-src/r1.md" >/dev/null
  out="$(AGBOX_DATA_DIR="${sec_data}" agbox_exec "${TEST_BIN}" rules show named-rule)"
  assert_contains "${out}" "Always verify outputs." "rules show"

  ln -s /etc/passwd "${sec_data}/rules/evil.md"
  rc=0
  err_out="$(AGBOX_DATA_DIR="${sec_data}" agbox_exec "${TEST_BIN}" rules list 2>&1)" || rc=$?
  [[ "${rc}" -ne 0 ]] || { echo "Expected symlink in rules dir to fail closed" >&2; return 1; }
  assert_contains "${err_out}" "symlink" "rules symlink tamper error"
  rm -f "${sec_data}/rules/evil.md"
  AGBOX_DATA_DIR="${sec_data}" agbox_exec "${TEST_BIN}" rules rm r1 >/dev/null
  AGBOX_DATA_DIR="${sec_data}" agbox_exec "${TEST_BIN}" rules rm --all >/dev/null

  # Auth status, JSON/symlink tamper checks, and logout.
  out="$(AGBOX_DATA_DIR="${sec_data}" agbox_exec "${TEST_BIN}" auth status)"
  assert_contains "${out}" "antigravity: not configured" "auth status unconfigured"
  assert_contains "${out}" "opencode: not configured" "auth status unconfigured"

  seed_test_auth "${sec_data}"
  out="$(AGBOX_DATA_DIR="${sec_data}" agbox_exec "${TEST_BIN}" auth status)"
  assert_contains "${out}" "antigravity: configured" "auth status configured"
  assert_contains "${out}" "opencode: configured" "auth status configured"

  printf '{}\n' > "${sec_data}/auth/opencode/auth.json"
  rc=0
  err_out="$(AGBOX_DATA_DIR="${sec_data}" agbox_exec "${TEST_BIN}" auth status 2>&1)" || rc=$?
  [[ "${rc}" -ne 0 ]] || { echo "Expected empty auth.json object to fail closed" >&2; return 1; }

  seed_test_auth "${sec_data}"
  ln -s /etc/passwd "${sec_data}/auth/antigravity/installation_id"
  rc=0
  err_out="$(AGBOX_DATA_DIR="${sec_data}" agbox_exec "${TEST_BIN}" auth status 2>&1)" || rc=$?
  [[ "${rc}" -ne 0 ]] || { echo "Expected symlink in auth dir to fail closed" >&2; return 1; }
  assert_contains "${err_out}" "symlink" "auth symlink tamper error"
  rm -f "${sec_data}/auth/antigravity/installation_id"

  AGBOX_DATA_DIR="${sec_data}" agbox_exec "${TEST_BIN}" auth logout all >/dev/null
  out="$(AGBOX_DATA_DIR="${sec_data}" agbox_exec "${TEST_BIN}" auth status)"
  assert_contains "${out}" "antigravity: not configured" "auth logout"

  # Update cache verification, SHA-256 tamper rejection, ELF magic check, and clear.
  out="$(AGBOX_DATA_DIR="${sec_data}" agbox_exec "${TEST_BIN}" update status)"
  assert_contains "${out}" "No cached agent updates." "empty update status"

  install_stub_agy_cache "${sec_data}"
  out="$(AGBOX_DATA_DIR="${sec_data}" agbox_exec "${TEST_BIN}" update status)"
  assert_contains "${out}" "antigravity: version=e2e-stub-1.0.0" "cached update status"

  printf '\xff' | dd of="${sec_data}/agents/bin/agy" bs=1 seek=64 count=1 conv=notrunc 2>/dev/null
  rc=0
  err_out="$(AGBOX_DATA_DIR="${sec_data}" agbox_exec "${TEST_BIN}" update status 2>&1)" || rc=$?
  [[ "${rc}" -ne 0 ]] || { echo "Expected SHA-256 mismatch in cached binary to fail closed" >&2; return 1; }
  assert_contains "${err_out}" "integrity check failed" "sha256 tamper error"

  printf '#!/bin/sh\necho fake-script-not-elf-padding-000000000000000000000000000000000\n' > "${sec_data}/agents/bin/agy"
  chmod 0755 "${sec_data}/agents/bin/agy"
  rc=0
  err_out="$(AGBOX_DATA_DIR="${sec_data}" agbox_exec "${TEST_BIN}" update status 2>&1)" || rc=$?
  [[ "${rc}" -ne 0 ]] || { echo "Expected non-ELF binary in cache to fail closed" >&2; return 1; }
  assert_contains "${err_out}" "ELF" "non-ELF tamper error"

  AGBOX_DATA_DIR="${sec_data}" agbox_exec "${TEST_BIN}" update clear all >/dev/null
  out="$(AGBOX_DATA_DIR="${sec_data}" agbox_exec "${TEST_BIN}" update status)"
  assert_contains "${out}" "No cached agent updates." "update clear all"
}

check_07_msb_error_diagnostics_not_swallowed() {
  build_test_binaries
  local fake_bin="${TEST_ROOT}/fake-msb-bin"
  mkdir -p "${fake_bin}" "${TEST_ROOT}/sec-data"
  chmod 0700 "${fake_bin}" "${TEST_ROOT}/sec-data"

  cat > "${fake_bin}/msb" <<'EOF'
#!/usr/bin/env bash
echo "simulated msb backend failure detail" >&2
exit 23
EOF
  chmod 0755 "${fake_bin}/msb"

  local err_out=""
  local rc=0
  err_out="$(PATH="${fake_bin}:${PATH}" AGBOX_DATA_DIR="${TEST_ROOT}/sec-data" agbox_exec "${TEST_BIN}" stop "agbox-${SUITE_ID}-fake" 2>&1)" || rc=$?
  if [[ "${rc}" -ne 23 ]]; then
    printf 'Expected exit code 23 from fake msb stop, got %d\nOutput:\n%s\n' "${rc}" "${err_out}" >&2
    return 1
  fi
  assert_contains "${err_out}" "[agbox] ERROR:" "stop stderr prefix"
  assert_contains "${err_out}" "simulated msb backend failure detail" "stop stderr msb detail"

  if [[ -r /dev/kvm && -w /dev/kvm ]]; then
    local cmd_fake_bin="${TEST_ROOT}/fake-msb-cmd-bin"
    local cmd_data="${TEST_ROOT}/cmd-stream-data"
    rm -rf "${cmd_fake_bin}" "${cmd_data}"
    mkdir -p "${cmd_fake_bin}" "${cmd_data}"
    chmod 0700 "${cmd_fake_bin}" "${cmd_data}"
    cat > "${cmd_data}/config" <<'EOF'
agent=both
snapshot=agbox:v1
EOF
    chmod 0600 "${cmd_data}/config"

    cat > "${cmd_fake_bin}/msb" <<'EOF'
#!/usr/bin/env bash
sub="$1"
shift
case "${sub}" in
  ls)
    exit 0
    ;;
  snap)
    echo "agbox:v1 1m 100M"
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
  *)
    exit 0
    ;;
esac
EOF
    chmod 0755 "${cmd_fake_bin}/msb"

    local cmd_stdout="${TEST_ROOT}/fake-cmd.stdout"
    local cmd_stderr="${TEST_ROOT}/fake-cmd.stderr"
    PATH="${cmd_fake_bin}:${PATH}" AGBOX_DATA_DIR="${cmd_data}" agbox_exec "${TEST_BIN}" run --no-net --cmd "echo hi" </dev/null >"${cmd_stdout}" 2>"${cmd_stderr}"
    assert_contains "$(cat "${cmd_stdout}")" "FAKE_CMD_STDOUT_OK" "fake msb --cmd stdout"
    assert_not_contains "$(cat "${cmd_stdout}")" "FAKE_CMD_STDERR_OK" "fake msb --cmd stdout excludes stderr"
    assert_contains "$(cat "${cmd_stderr}")" "FAKE_CMD_STDERR_OK" "fake msb --cmd stderr"

    local pipe_out=""
    pipe_out="$(printf 'piped-hello\n' | PATH="${cmd_fake_bin}:${PATH}" AGBOX_DATA_DIR="${cmd_data}" agbox_exec "${TEST_BIN}" run --no-net --cmd "cat" 2>&1)"
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

  local fbase="${TEST_ROOT}/fuse-test"
  local src_masked="${fbase}/src/masked"
  local src_vcs="${fbase}/src/vcs"
  local src_ro="${fbase}/src/readonly"
  local fdata="${fbase}/data"
  local frun="${fbase}/run"
  local mnt="${frun}/ws"
  local sock="${frun}/ws.sock"
  local spec="${fbase}/spec.json"
  local hub_log="${fbase}/hub.log"

  rm -rf "${fbase}"
  mkdir -p "${src_masked}/.git" "${src_masked}/.GIT" "${src_masked}/.jj" "${src_masked}/.agents/skills/s1"
  mkdir -p "${src_vcs}/.git/hooks" "${src_ro}" "${fdata}" "${frun}" "${mnt}"
  chmod 0700 "${fbase}" "${fdata}" "${frun}" "${mnt}"

  printf 'hello\n' > "${src_masked}/code.txt"
  printf 'secret\n' > "${src_masked}/.git/config"
  printf 'ref: main\n' > "${src_masked}/.GIT/HEAD"
  printf 'jj-secret\n' > "${src_masked}/.jj/repo"
  printf '*.secret\n' > "${src_masked}/.gitignore"
  printf '# Skill 1\n' > "${src_masked}/.agents/skills/s1/SKILL.md"
  printf '# Project Agents\n' > "${src_masked}/AGENTS.md"

  printf 'ref: main\n' > "${src_vcs}/.git/HEAD"
  printf '#!/bin/sh\nexit 0\n' > "${src_vcs}/.git/hooks/pre-commit"
  printf 'read-only-doc\n' > "${src_ro}/doc.txt"

  cat > "${spec}" <<EOF
{
  "data_dir": "${fdata}",
  "shares": [
    {"guest_name": "masked", "host_path": "${src_masked}", "is_file": false, "read_only": false, "vcs_policy": "mask"},
    {"guest_name": "vcs", "host_path": "${src_vcs}", "is_file": false, "read_only": false, "vcs_policy": "vcs"},
    {"guest_name": "readonly", "host_path": "${src_ro}", "is_file": false, "read_only": true, "vcs_policy": "mask"}
  ]
}
EOF

  local hub_pid=""
  cleanup_fuse_check() {
    if [[ -n "${hub_pid}" ]]; then
      kill -TERM "${hub_pid}" 2>/dev/null || true
      wait "${hub_pid}" 2>/dev/null || true
    fi
    unmount_tree "${fbase}"
  }
  trap cleanup_fuse_check RETURN

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

  # Masked share checks: code and agent files readable, writes pass through, VCS hidden and blocked.
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

  if mkdir "${mnt}/masked/.git" 2>/dev/null; then
    echo "Expected mkdir .git to fail inside masked share" >&2
    return 1
  fi
  if ln -s /etc/passwd "${mnt}/masked/esc" 2>/dev/null; then
    echo "Expected outside symlink to fail inside masked share" >&2
    return 1
  fi
  if ln -s .git/config "${mnt}/masked/gitlink" 2>/dev/null; then
    echo "Expected VCS symlink to fail inside masked share" >&2
    return 1
  fi

  # VCS-allowed share checks: .git/HEAD writable, hooks and top-level .git delete blocked.
  [[ -f "${mnt}/vcs/.git/HEAD" ]] || return 1
  printf 'ref: refs/heads/dev\n' > "${mnt}/vcs/.git/HEAD"
  if printf 'evil\n' > "${mnt}/vcs/.git/hooks/pre-commit" 2>/dev/null; then
    echo "Expected write to .git/hooks/pre-commit to fail under vcs policy" >&2
    return 1
  fi
  if rm -rf "${mnt}/vcs/.git" 2>/dev/null; then
    echo "Expected rm -rf .git to fail under vcs policy" >&2
    return 1
  fi

  # Read-only share checks: reads succeed, writes fail.
  [[ "$(cat "${mnt}/readonly/doc.txt")" == "read-only-doc" ]] || return 1
  if printf 'nope\n' > "${mnt}/readonly/new.txt" 2>/dev/null; then
    echo "Expected write to read-only share to fail" >&2
    return 1
  fi

  # Clean unmount check.
  kill -TERM "${hub_pid}" 2>/dev/null || true
  wait "${hub_pid}" 2>/dev/null || true
  hub_pid=""
  unmount_tree "${fbase}"
  if [[ -n "$(list_active_mounts_under "${mnt}")" ]]; then
    echo "FUSE hub mount remained active after teardown" >&2
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
    "${MSB_BIN_PATH}" --version || true
  fi
}

check_10_agbox_setup() {
  build_test_binaries
  local out=""
  out="$(MSB_HOME="${RUNTIME_MSB_HOME}" AGBOX_DATA_DIR="${RUNTIME_DATA_DIR}" with_timeout 180 agbox_exec "${ACTIVE_BIN}" setup 2>&1)"
  printf '%s\n' "${out}"
  assert_contains "${out}" "Smoke test: OK" "agbox setup output"
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
  st_out="$(MSB_HOME="${ORIG_MSB_HOME}" AGBOX_DATA_DIR="${ORIG_DATA_DIR}" agbox_exec "${TEST_BIN}" status)"
  printf '%s\n' "${st_out}"
  assert_contains "${st_out}" "(none - run create-base)" "status after pre-clean remove"
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
  ACTIVE_BIN="${ORIG_INSTALL_BIN}"
}

check_12_disruptive_create_and_edit_base() {
  DISRUPTIVE_SETUP_DONE=1
  local base_cmd_out=""
  if [[ "${FULL_MODE}" -eq 1 ]]; then
    MSB_HOME="${ORIG_MSB_HOME}" AGBOX_DATA_DIR="${ORIG_DATA_DIR}" with_timeout 1200 agbox_exec "${ACTIVE_BIN}" create-base --add core,go both
    MSB_HOME="${ORIG_MSB_HOME}" AGBOX_DATA_DIR="${ORIG_DATA_DIR}" with_timeout 600 agbox_exec "${ACTIVE_BIN}" edit-base --add hugo --cmd "echo e2e-v2 > /etc/agbox-e2e-v2"
    MSB_HOME="${ORIG_MSB_HOME}" AGBOX_DATA_DIR="${ORIG_DATA_DIR}" with_timeout 180 agbox_exec "${ACTIVE_BIN}" edit-base --no-snap --cmd "echo unsnapped > /etc/agbox-unsnapped"

    load_base_info_from_config "${ORIG_DATA_DIR}/config"
    assert_contains "${BASE_SNAP}" "agbox:v2" "config snapshot after edit-base"

    base_cmd_out="$(MSB_HOME="${ORIG_MSB_HOME}" AGBOX_DATA_DIR="${ORIG_DATA_DIR}" with_timeout 180 agbox_exec "${ACTIVE_BIN}" run --no-net --name "${SUITE_ID}-ebchk" --cmd \
      'command -v mdformat >/dev/null && command -v shellcheck >/dev/null && command -v jq >/dev/null && command -v go >/dev/null && command -v hugo >/dev/null && grep -qx e2e-v2 /etc/agbox-e2e-v2 && test ! -e /etc/agbox-unsnapped && echo BASE_CMD_STDOUT_OK' 2>&1)"
    printf '%s\n' "${base_cmd_out}"
    assert_contains "${base_cmd_out}" "BASE_CMD_STDOUT_OK" "check_12 --cmd stdout"
  else
    MSB_HOME="${ORIG_MSB_HOME}" AGBOX_DATA_DIR="${ORIG_DATA_DIR}" with_timeout 900 agbox_exec "${ACTIVE_BIN}" create-base both
    load_base_info_from_config "${ORIG_DATA_DIR}/config"
    [[ -n "${BASE_SNAP}" ]] || { echo "Missing snapshot in config" >&2; return 1; }
    base_cmd_out="$(MSB_HOME="${ORIG_MSB_HOME}" AGBOX_DATA_DIR="${ORIG_DATA_DIR}" with_timeout 180 agbox_exec "${ACTIVE_BIN}" run --no-net --name "${SUITE_ID}-basechk" --cmd \
      'command -v mdformat >/dev/null && command -v shellcheck >/dev/null && echo BASE_CMD_STDOUT_OK' 2>&1)"
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

  printf 'extra-note\n' > "${extra}/note.txt"
  printf 'ref: main\n' > "${extra}/.git/HEAD"
  printf '#!/bin/sh\nexit 0\n' > "${extra}/.git/hooks/pre-commit"
}

check_20_ephemeral_run_shares_and_secrets() {
  prepare_shared_test_dirs
  local proj="${TEST_ROOT}/proj1"
  local docs="${TEST_ROOT}/docs1"

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
echo "GUEST_EPH_OK"
'

  local out=""
  out="$(OPENAI_API_KEY="sk-e2e-stream-test" MSB_HOME="${RUNTIME_MSB_HOME}" AGBOX_DATA_DIR="${RUNTIME_DATA_DIR}" with_timeout 180 \
    agbox_exec "${ACTIVE_BIN}" run --no-net --name "${SUITE_ID}-eph" --share "${docs}:ro,as=docs" --cmd "${guest_script}" "${proj}" 2>&1)"
  printf '%s\n' "${out}"
  assert_contains "${out}" "GUEST_EPH_OK" "ephemeral guest verification"
  [[ "$(cat "${proj}/src/app.txt")" == "modified-in-vm" ]] || { echo "Expected guest write to persist to host" >&2; return 1; }

  wait_for_sandbox_gone "${RUNTIME_MSB_HOME}" "agbox-${SUITE_ID}-eph" 20 || { echo "Ephemeral sandbox was not deleted" >&2; return 1; }
  if [[ -n "$(list_active_mounts_under "${RUNTIME_DATA_DIR}/run")" ]]; then
    echo "FUSE mount left behind after ephemeral run" >&2
    return 1
  fi

  # Interactive --cmd must stream stdout and stderr separately and forward piped stdin.
  local io_stdout="${TEST_ROOT}/cmd-io.stdout"
  local io_stderr="${TEST_ROOT}/cmd-io.stderr"
  MSB_HOME="${RUNTIME_MSB_HOME}" AGBOX_DATA_DIR="${RUNTIME_DATA_DIR}" with_timeout 120 \
    agbox_exec "${ACTIVE_BIN}" run --no-net --name "${SUITE_ID}-io" --cmd \
    'printf "LIVE_STDOUT_LINE\n"; printf "LIVE_STDERR_LINE\n" >&2' \
    >"${io_stdout}" 2>"${io_stderr}"
  cat "${io_stdout}"
  cat "${io_stderr}" >&2
  assert_contains "$(cat "${io_stdout}")" "LIVE_STDOUT_LINE" "live --cmd stdout"
  assert_not_contains "$(cat "${io_stdout}")" "LIVE_STDERR_LINE" "live --cmd stdout excludes stderr"
  assert_contains "$(cat "${io_stderr}")" "LIVE_STDERR_LINE" "live --cmd stderr"

  local pipe_out=""
  pipe_out="$(printf 'LIVE_STDIN_PAYLOAD\n' | MSB_HOME="${RUNTIME_MSB_HOME}" AGBOX_DATA_DIR="${RUNTIME_DATA_DIR}" with_timeout_stdin 120 \
    agbox_exec "${ACTIVE_BIN}" run --no-net --name "${SUITE_ID}-pipe" --cmd 'cat' 2>&1)"
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
  local prof="${SUITE_ID}-p1"
  rm -rf "${sdir}"
  mkdir -p "${sdir}/e2e-skill"

  cleanup_21() {
    AGBOX_DATA_DIR="${RUNTIME_DATA_DIR}" agbox_exec "${ACTIVE_BIN}" skills rm e2e-skill >/dev/null 2>&1 || true
    AGBOX_DATA_DIR="${RUNTIME_DATA_DIR}" agbox_exec "${ACTIVE_BIN}" rules rm --all >/dev/null 2>&1 || true
    AGBOX_DATA_DIR="${RUNTIME_DATA_DIR}" agbox_exec "${ACTIVE_BIN}" auth logout all >/dev/null 2>&1 || true
    AGBOX_DATA_DIR="${RUNTIME_DATA_DIR}" agbox_exec "${ACTIVE_BIN}" update clear all >/dev/null 2>&1 || true
    MSB_HOME="${RUNTIME_MSB_HOME}" AGBOX_DATA_DIR="${RUNTIME_DATA_DIR}" agbox_exec "${ACTIVE_BIN}" profile rm --force "${prof}" >/dev/null 2>&1 || true
  }
  trap cleanup_21 RETURN

  printf '# E2E Skill\nUse deterministic checks.\n' > "${sdir}/e2e-skill/SKILL.md"
  AGBOX_DATA_DIR="${RUNTIME_DATA_DIR}" agbox_exec "${ACTIVE_BIN}" skills add --force "${sdir}/e2e-skill" >/dev/null

  printf '# Always Rule\nNever skip verification.\n' > "${sdir}/always.md"
  cat > "${sdir}/cond.md" <<'EOF'
---
trigger: model_decision
description: Conditional e2e rule
---
Apply when checking persistence.
EOF
  AGBOX_DATA_DIR="${RUNTIME_DATA_DIR}" agbox_exec "${ACTIVE_BIN}" rules add --force "${sdir}/always.md" >/dev/null
  AGBOX_DATA_DIR="${RUNTIME_DATA_DIR}" agbox_exec "${ACTIVE_BIN}" rules add --force "${sdir}/cond.md" >/dev/null

  seed_test_auth "${RUNTIME_DATA_DIR}"
  install_stub_agy_cache "${RUNTIME_DATA_DIR}"

  MSB_HOME="${RUNTIME_MSB_HOME}" AGBOX_DATA_DIR="${RUNTIME_DATA_DIR}" with_timeout 60 agbox_exec "${ACTIVE_BIN}" profile create --size 128M "${prof}"

  local st_out=""
  st_out="$(MSB_HOME="${RUNTIME_MSB_HOME}" AGBOX_DATA_DIR="${RUNTIME_DATA_DIR}" with_timeout 30 agbox_exec "${ACTIVE_BIN}" status)"
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
  out1="$(MSB_HOME="${RUNTIME_MSB_HOME}" AGBOX_DATA_DIR="${RUNTIME_DATA_DIR}" with_timeout 180 \
    agbox_exec "${ACTIVE_BIN}" run --no-net --profile "${prof}" --name "${SUITE_ID}-pr1" --cmd "${script1}" "${proj}")"
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
  out2="$(MSB_HOME="${RUNTIME_MSB_HOME}" AGBOX_DATA_DIR="${RUNTIME_DATA_DIR}" with_timeout 180 \
    agbox_exec "${ACTIVE_BIN}" run --no-net --profile "${prof}" --no-skills --no-rules --no-auth --no-agent-cache --name "${SUITE_ID}-pr2" --cmd "${script2}")"
  printf '%s\n' "${out2}"
  assert_contains "${out2}" "PERSIST_RUN2_OK" "persist run 2 opt-out"

  MSB_HOME="${RUNTIME_MSB_HOME}" AGBOX_DATA_DIR="${RUNTIME_DATA_DIR}" with_timeout 60 agbox_exec "${ACTIVE_BIN}" profile rm "${prof}"
}

check_22_persist_remote_control_shares_suspend_resume() {
  prepare_shared_test_dirs
  local proj="${TEST_ROOT}/proj1"
  local extra="${TEST_ROOT}/extra1"
  local sdir="${TEST_ROOT}/rc-src"
  local sbx_name="${SUITE_ID}-blip"
  local sbx="agbox-${sbx_name}"
  local fail_name="${SUITE_ID}-rcfail"
  local fail_sbx="agbox-${fail_name}"
  rm -rf "${sdir}"
  mkdir -p "${sdir}/e2e-rc-skill"

  cleanup_22() {
    MSB_HOME="${RUNTIME_MSB_HOME}" AGBOX_DATA_DIR="${RUNTIME_DATA_DIR}" agbox_exec "${ACTIVE_BIN}" stop "${sbx}" >/dev/null 2>&1 || true
    MSB_HOME="${RUNTIME_MSB_HOME}" AGBOX_DATA_DIR="${RUNTIME_DATA_DIR}" agbox_exec "${ACTIVE_BIN}" stop "${fail_sbx}" >/dev/null 2>&1 || true
    AGBOX_DATA_DIR="${RUNTIME_DATA_DIR}" agbox_exec "${ACTIVE_BIN}" skills rm e2e-rc-skill >/dev/null 2>&1 || true
    AGBOX_DATA_DIR="${RUNTIME_DATA_DIR}" agbox_exec "${ACTIVE_BIN}" rules rm --all >/dev/null 2>&1 || true
    AGBOX_DATA_DIR="${RUNTIME_DATA_DIR}" agbox_exec "${ACTIVE_BIN}" auth logout all >/dev/null 2>&1 || true
    AGBOX_DATA_DIR="${RUNTIME_DATA_DIR}" agbox_exec "${ACTIVE_BIN}" update clear all >/dev/null 2>&1 || true
  }
  trap cleanup_22 RETURN

  printf '# RC Skill\nSkill active.\n' > "${sdir}/e2e-rc-skill/SKILL.md"
  AGBOX_DATA_DIR="${RUNTIME_DATA_DIR}" agbox_exec "${ACTIVE_BIN}" skills add --force "${sdir}/e2e-rc-skill" >/dev/null
  printf '# RC Rule\nRule active.\n' > "${sdir}/rc-rule.md"
  AGBOX_DATA_DIR="${RUNTIME_DATA_DIR}" agbox_exec "${ACTIVE_BIN}" rules add --force "${sdir}/rc-rule.md" >/dev/null
  seed_test_auth "${RUNTIME_DATA_DIR}"
  install_stub_agy_cache "${RUNTIME_DATA_DIR}"

  local out=""
  local rc=0
  local use_rc=1
  if [[ "${BASE_AGENT}" == "opencode" ]]; then
    use_rc=0
  fi

  if [[ "${use_rc}" -eq 1 ]]; then
    # Verify non-zero exit prints [agbox] ERROR: + stub stderr details and cleans up on failure.
    local fail_out=""
    fail_out="$(MSB_HOME="${RUNTIME_MSB_HOME}" AGBOX_DATA_DIR="${RUNTIME_DATA_DIR}" with_timeout 180 \
      agbox_exec "${ACTIVE_BIN}" run --no-auth --persist --name "${fail_name}" -d --remote-control "${proj}" 2>&1)" || rc=$?
    [[ "${rc}" -ne 0 ]] || { echo "Expected --remote-control without auth to fail" >&2; return 1; }
    assert_contains "${fail_out}" "[agbox] ERROR:" "rc failure error prefix"
    assert_contains "${fail_out}" "missing saved antigravity oauth token" "rc failure stderr detail"
    wait_for_sandbox_gone "${RUNTIME_MSB_HOME}" "${fail_sbx}" 15 || { echo "Expected failed rc sandbox ${fail_sbx} to be cleaned up" >&2; return 1; }

    # Boot detached persistent Remote Control with auth + skill + rule + agent cache.
    out="$(MSB_HOME="${RUNTIME_MSB_HOME}" AGBOX_DATA_DIR="${RUNTIME_DATA_DIR}" with_timeout 180 \
      agbox_exec "${ACTIVE_BIN}" run --persist --name "${sbx_name}" -d --remote-control "${proj}" 2>&1)"
    printf '%s\n' "${out}"
    assert_contains "${out}" "Remote Control active (${sbx})" "remote-control status output"
    assert_contains "${out}" "agbox suspend ${sbx}" "detached suspend hint"
  else
    # Verify opencode-only base rejects --remote-control cleanly, then run --persist lifecycle via --serve -d.
    local rej_out=""
    rej_out="$(MSB_HOME="${RUNTIME_MSB_HOME}" AGBOX_DATA_DIR="${RUNTIME_DATA_DIR}" with_timeout 60 \
      agbox_exec "${ACTIVE_BIN}" run --persist --name "${fail_name}" -d --remote-control "${proj}" 2>&1)" || rc=$?
    [[ "${rc}" -ne 0 ]] || return 1
    assert_contains "${rej_out}" "[agbox] ERROR:" "opencode base rejects remote-control"

    out="$(MSB_HOME="${RUNTIME_MSB_HOME}" AGBOX_DATA_DIR="${RUNTIME_DATA_DIR}" with_timeout 180 \
      agbox_exec "${ACTIVE_BIN}" run --persist --name "${sbx_name}" -d --serve "${proj}" 2>&1)"
    printf '%s\n' "${out}"
    assert_contains "${out}" "agbox suspend ${sbx}" "detached serve suspend hint"
  fi

  wait_for_sandbox_running "${RUNTIME_MSB_HOME}" "${sbx}" 20 || { echo "Expected ${sbx} running" >&2; return 1; }

  # Live dynamic share list / add (ro,mask default) / set (rw,vcs) / rm.
  out="$(MSB_HOME="${RUNTIME_MSB_HOME}" AGBOX_DATA_DIR="${RUNTIME_DATA_DIR}" with_timeout 30 agbox_exec "${ACTIVE_BIN}" share list "${sbx}")"
  assert_contains "${out}" "/workspace/proj1" "share list initial"
  assert_contains "${out}" "mode=rw" "share list initial mode"
  assert_contains "${out}" "vcs=mask" "share list initial vcs"

  MSB_HOME="${RUNTIME_MSB_HOME}" AGBOX_DATA_DIR="${RUNTIME_DATA_DIR}" with_timeout 60 agbox_exec "${ACTIVE_BIN}" share add "${sbx}" "${extra}"
  MSB_HOME="${RUNTIME_MSB_HOME}" with_timeout 30 "${MSB_BIN_PATH}" exec --no-stdin -u agent "${sbx}" -- sh -eu -c '
    test "$(cat /workspace/extra1/note.txt)" = "extra-note"
    test ! -e /workspace/extra1/.git
    if touch /workspace/extra1/blocked.txt 2>/dev/null; then exit 1; fi
  '

  MSB_HOME="${RUNTIME_MSB_HOME}" AGBOX_DATA_DIR="${RUNTIME_DATA_DIR}" with_timeout 60 agbox_exec "${ACTIVE_BIN}" share set --rw --vcs "${sbx}" extra1
  MSB_HOME="${RUNTIME_MSB_HOME}" with_timeout 30 "${MSB_BIN_PATH}" exec --no-stdin -u agent "${sbx}" -- sh -eu -c '
    test -f /workspace/extra1/.git/HEAD
    printf "ref: refs/heads/e2e\n" > /workspace/extra1/.git/HEAD
    if printf "bad\n" > /workspace/extra1/.git/hooks/pre-commit 2>/dev/null; then exit 1; fi
  '

  MSB_HOME="${RUNTIME_MSB_HOME}" AGBOX_DATA_DIR="${RUNTIME_DATA_DIR}" with_timeout 60 agbox_exec "${ACTIVE_BIN}" share rm "${sbx}" extra1
  MSB_HOME="${RUNTIME_MSB_HOME}" with_timeout 30 "${MSB_BIN_PATH}" exec --no-stdin -u agent "${sbx}" -- sh -eu -c 'test ! -e /workspace/extra1'

  # Suspend, add share while suspended, and resume detached.
  MSB_HOME="${RUNTIME_MSB_HOME}" AGBOX_DATA_DIR="${RUNTIME_DATA_DIR}" with_timeout 60 agbox_exec "${ACTIVE_BIN}" suspend "${sbx}"
  if wait_for_sandbox_running "${RUNTIME_MSB_HOME}" "${sbx}" 2; then
    echo "Expected ${sbx} stopped after suspend" >&2
    return 1
  fi
  if [[ -n "$(list_active_mounts_under "${RUNTIME_DATA_DIR}/run/${sbx_name}")" ]]; then
    echo "Expected FUSE mounts unmounted after suspend" >&2
    return 1
  fi

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
  out="$(MSB_HOME="${RUNTIME_MSB_HOME}" AGBOX_DATA_DIR="${RUNTIME_DATA_DIR}" with_timeout 180 \
    agbox_exec "${ACTIVE_BIN}" run --name "${SUITE_ID}-probe" --serve --probe "${TEST_ROOT}/proj1" 2>&1)"
  printf '%s\n' "${out}"
  assert_contains "${out}" "OpenCode web UI: http://127.0.0.1:" "--serve URL output"
  assert_contains "${out}" "--probe: UI verified" "--probe verification message"
  wait_for_sandbox_gone "${RUNTIME_MSB_HOME}" "agbox-${SUITE_ID}-probe" 20 || return 1
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
  out="$(MSB_HOME="${RUNTIME_MSB_HOME}" AGBOX_DATA_DIR="${RUNTIME_DATA_DIR}" with_timeout 180 \
    agbox_exec "${ACTIVE_BIN}" run --name "${SUITE_ID}-pubfw" --cmd "${net_script}" 2>&1)"
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
  local sbx_name="${SUITE_ID}-fd"
  local sbx="agbox-${sbx_name}"
  local bg_pid=""

  cleanup_31() {
    MSB_HOME="${RUNTIME_MSB_HOME}" AGBOX_DATA_DIR="${RUNTIME_DATA_DIR}" agbox_exec "${ACTIVE_BIN}" stop "${sbx}" >/dev/null 2>&1 || true
    if [[ -n "${bg_pid}" ]]; then
      kill "${bg_pid}" 2>/dev/null || true
      wait "${bg_pid}" 2>/dev/null || true
    fi
  }
  trap cleanup_31 RETURN

  MSB_HOME="${RUNTIME_MSB_HOME}" AGBOX_DATA_DIR="${RUNTIME_DATA_DIR}" \
    agbox_exec "${ACTIVE_BIN}" run --no-net --persist --name "${sbx_name}" --share "${proj}:rw" --cmd "sleep 300" >"${TEST_ROOT}/fd-run.log" 2>&1 </dev/null &
  bg_pid=$!

  wait_for_sandbox_running "${RUNTIME_MSB_HOME}" "${sbx}" 40 || { echo "Timeout waiting for ${sbx}" >&2; return 1; }
  local sock="${RUNTIME_DATA_DIR}/run/${sbx_name}/ws.sock"
  local i=0
  while [[ ! -S "${sock}" && "${i}" -lt 30 ]]; do
    sleep 0.2
    i=$((i + 1))
  done
  [[ -S "${sock}" ]] || { echo "ws.sock did not appear" >&2; return 1; }

  # Launch guest process holding open writable FD 3 until /tmp/fd-go appears.
  MSB_HOME="${RUNTIME_MSB_HOME}" with_timeout 20 "${MSB_BIN_PATH}" exec -d --no-stdin -u agent "${sbx}" -- sh -c \
    'exec 3>> /workspace/proj1/open-fd.txt; printf "before\n" >&3; : > /tmp/fd-ready; while [ ! -f /tmp/fd-go ]; do sleep 0.1; done; printf "after\n" >&3 2>/tmp/fd-err; echo "$?" > /tmp/fd-rc'

  i=0
  while [[ "${i}" -lt 30 ]]; do
    if MSB_HOME="${RUNTIME_MSB_HOME}" with_timeout 10 "${MSB_BIN_PATH}" exec --no-stdin -u agent "${sbx}" -- test -f /tmp/fd-ready 2>/dev/null; then
      break
    fi
    sleep 0.2
    i=$((i + 1))
  done

  local sl_out=""
  sl_out="$(MSB_HOME="${RUNTIME_MSB_HOME}" AGBOX_DATA_DIR="${RUNTIME_DATA_DIR}" with_timeout 20 agbox_exec "${ACTIVE_BIN}" share list "${sbx}")"
  assert_contains "${sl_out}" "open_writable=1" "open_writable=1 reported"

  local rc=0
  MSB_HOME="${RUNTIME_MSB_HOME}" AGBOX_DATA_DIR="${RUNTIME_DATA_DIR}" with_timeout 20 agbox_exec "${ACTIVE_BIN}" share set --ro "${sbx}" proj1 >/dev/null 2>&1 || rc=$?
  [[ "${rc}" -ne 0 ]] || { echo "Expected share set --ro without --force to fail with open writable FD" >&2; return 1; }

  rc=0
  MSB_HOME="${RUNTIME_MSB_HOME}" AGBOX_DATA_DIR="${RUNTIME_DATA_DIR}" with_timeout 20 agbox_exec "${ACTIVE_BIN}" share rm "${sbx}" proj1 >/dev/null 2>&1 || rc=$?
  [[ "${rc}" -ne 0 ]] || { echo "Expected share rm without --force to fail with open writable FD" >&2; return 1; }

  # Force downgrade rw -> ro must succeed and fail subsequent writes to FD 3.
  MSB_HOME="${RUNTIME_MSB_HOME}" AGBOX_DATA_DIR="${RUNTIME_DATA_DIR}" with_timeout 30 agbox_exec "${ACTIVE_BIN}" share set --ro --force "${sbx}" proj1
  MSB_HOME="${RUNTIME_MSB_HOME}" with_timeout 15 "${MSB_BIN_PATH}" exec --no-stdin -u agent "${sbx}" -- sh -c ': > /tmp/fd-go'

  local fd_rc=""
  i=0
  while [[ "${i}" -lt 30 ]]; do
    fd_rc="$(MSB_HOME="${RUNTIME_MSB_HOME}" with_timeout 10 "${MSB_BIN_PATH}" exec --no-stdin -u agent "${sbx}" -- cat /tmp/fd-rc 2>/dev/null || true)"
    if [[ -n "${fd_rc}" ]]; then
      break
    fi
    sleep 0.2
    i=$((i + 1))
  done
  [[ -n "${fd_rc}" && "${fd_rc}" != "0" ]] || { echo "Expected FD write to fail after forced --ro downgrade (rc=${fd_rc})" >&2; return 1; }

  # Restore rw, open FD 4, then force remove share and verify write revocation.
  MSB_HOME="${RUNTIME_MSB_HOME}" AGBOX_DATA_DIR="${RUNTIME_DATA_DIR}" with_timeout 30 agbox_exec "${ACTIVE_BIN}" share set --rw "${sbx}" proj1
  MSB_HOME="${RUNTIME_MSB_HOME}" with_timeout 20 "${MSB_BIN_PATH}" exec -d --no-stdin -u agent "${sbx}" -- sh -c \
    'exec 4>> /workspace/proj1/open-fd2.txt; printf "before2\n" >&4; : > /tmp/fd2-ready; while [ ! -f /tmp/fd2-go ]; do sleep 0.1; done; printf "after2\n" >&4 2>/tmp/fd2-err; echo "$?" > /tmp/fd2-rc'
  i=0
  while [[ "${i}" -lt 30 ]]; do
    if MSB_HOME="${RUNTIME_MSB_HOME}" with_timeout 10 "${MSB_BIN_PATH}" exec --no-stdin -u agent "${sbx}" -- test -f /tmp/fd2-ready 2>/dev/null; then
      break
    fi
    sleep 0.2
    i=$((i + 1))
  done

  MSB_HOME="${RUNTIME_MSB_HOME}" AGBOX_DATA_DIR="${RUNTIME_DATA_DIR}" with_timeout 30 agbox_exec "${ACTIVE_BIN}" share rm --force "${sbx}" proj1
  MSB_HOME="${RUNTIME_MSB_HOME}" with_timeout 15 "${MSB_BIN_PATH}" exec --no-stdin -u agent "${sbx}" -- sh -c ': > /tmp/fd2-go'
  local fd2_rc=""
  i=0
  while [[ "${i}" -lt 30 ]]; do
    fd2_rc="$(MSB_HOME="${RUNTIME_MSB_HOME}" with_timeout 10 "${MSB_BIN_PATH}" exec --no-stdin -u agent "${sbx}" -- cat /tmp/fd2-rc 2>/dev/null || true)"
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
  local prof="${SUITE_ID}-lkp"
  local sbx_name="${SUITE_ID}-lk"
  local sbx="agbox-${sbx_name}"
  local orph_id="${SUITE_ID}-orph"
  local orph_sbx="agbox-${orph_id}"
  local bg_pid=""

  cleanup_32() {
    MSB_HOME="${RUNTIME_MSB_HOME}" AGBOX_DATA_DIR="${RUNTIME_DATA_DIR}" agbox_exec "${ACTIVE_BIN}" stop "${sbx}" >/dev/null 2>&1 || true
    MSB_HOME="${RUNTIME_MSB_HOME}" with_timeout 20 "${MSB_BIN_PATH}" rm -f "${orph_sbx}" >/dev/null 2>&1 || true
    if [[ -n "${bg_pid}" ]]; then
      kill "${bg_pid}" 2>/dev/null || true
      wait "${bg_pid}" 2>/dev/null || true
    fi
    MSB_HOME="${RUNTIME_MSB_HOME}" AGBOX_DATA_DIR="${RUNTIME_DATA_DIR}" agbox_exec "${ACTIVE_BIN}" profile rm --force "${prof}" >/dev/null 2>&1 || true
  }
  trap cleanup_32 RETURN

  # Profile lock contention check.
  MSB_HOME="${RUNTIME_MSB_HOME}" AGBOX_DATA_DIR="${RUNTIME_DATA_DIR}" with_timeout 60 agbox_exec "${ACTIVE_BIN}" profile create --size 128M "${prof}"
  MSB_HOME="${RUNTIME_MSB_HOME}" AGBOX_DATA_DIR="${RUNTIME_DATA_DIR}" \
    agbox_exec "${ACTIVE_BIN}" run --no-net --profile "${prof}" --name "${sbx_name}" --cmd "sleep 300" >"${TEST_ROOT}/lkp.log" 2>&1 </dev/null &
  bg_pid=$!

  wait_for_sandbox_running "${RUNTIME_MSB_HOME}" "${sbx}" 40 || { echo "Timeout waiting for ${sbx}" >&2; return 1; }

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

  MSB_HOME="${RUNTIME_MSB_HOME}" with_timeout 90 "${MSB_BIN_PATH}" snap restore "${BASE_SNAP}" --name "${orph_sbx}" -u agent --no-net >/dev/null
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
    echo "Expected orphan run dir ${orph_id} to be cleaned up" >&2
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
  local sbx_name="${SUITE_ID}-wsrv"
  local sbx="agbox-${sbx_name}"
  local pass="pw-${SUITE_ID}"

  cleanup_33() {
    MSB_HOME="${RUNTIME_MSB_HOME}" AGBOX_DATA_DIR="${RUNTIME_DATA_DIR}" agbox_exec "${ACTIVE_BIN}" stop "${sbx}" >/dev/null 2>&1 || true
  }
  trap cleanup_33 RETURN

  local out=""
  out="$(OPENCODE_SERVER_PASSWORD="${pass}" MSB_HOME="${RUNTIME_MSB_HOME}" AGBOX_DATA_DIR="${RUNTIME_DATA_DIR}" with_timeout 180 \
    agbox_exec "${ACTIVE_BIN}" run --persist --name "${sbx_name}" -d --serve "${TEST_ROOT}/proj1" 2>&1)"
  printf '%s\n' "${out}"

  local url=""
  url="$(grep -Eo 'http://127\.0\.0\.1:[0-9]+' <<< "${out}" | head -n 1 || true)"
  [[ -n "${url}" ]] || { echo "Failed to parse serve URL from output" >&2; return 1; }

  local code=""
  code="$(curl -sS -o /dev/null -w '%{http_code}' "${url}/doc")"
  [[ "${code}" == "401" ]] || { echo "Expected HTTP 401 without basic auth, got ${code}" >&2; return 1; }

  code="$(curl -sS -u "opencode:${pass}" -o /dev/null -w '%{http_code}' "${url}/doc")"
  [[ "${code}" == "200" ]] || { echo "Expected HTTP 200 with basic auth, got ${code}" >&2; return 1; }

  MSB_HOME="${RUNTIME_MSB_HOME}" AGBOX_DATA_DIR="${RUNTIME_DATA_DIR}" with_timeout 60 agbox_exec "${ACTIVE_BIN}" suspend "${sbx}"
  if curl -fsS --connect-timeout 1 "${url}/doc" >/dev/null 2>&1; then
    echo "Expected port ${url} closed after suspend" >&2
    return 1
  fi

  OPENCODE_SERVER_PASSWORD="${pass}" MSB_HOME="${RUNTIME_MSB_HOME}" AGBOX_DATA_DIR="${RUNTIME_DATA_DIR}" with_timeout 180 \
    agbox_exec "${ACTIVE_BIN}" resume -d "${sbx}"
  code="$(curl -sS -u "opencode:${pass}" -o /dev/null -w '%{http_code}' "${url}/doc")"
  [[ "${code}" == "200" ]] || { echo "Expected HTTP 200 after resume, got ${code}" >&2; return 1; }

  MSB_HOME="${RUNTIME_MSB_HOME}" AGBOX_DATA_DIR="${RUNTIME_DATA_DIR}" with_timeout 60 agbox_exec "${ACTIVE_BIN}" stop "${sbx}"
}

check_34_live_agent_update() {
  if [[ "${DISRUPTIVE_MODE}" -ne 1 ]]; then
    skip_check "covered in isolated lifecycle when non-disruptive"
  fi
  cleanup_34() {
    AGBOX_DATA_DIR="${ORIG_DATA_DIR}" agbox_exec "${ACTIVE_BIN}" update clear all >/dev/null 2>&1 || true
  }
  trap cleanup_34 RETURN

  MSB_HOME="${ORIG_MSB_HOME}" AGBOX_DATA_DIR="${ORIG_DATA_DIR}" with_timeout 600 agbox_exec "${ACTIVE_BIN}" update both
  local st=""
  st="$(AGBOX_DATA_DIR="${ORIG_DATA_DIR}" agbox_exec "${ACTIVE_BIN}" update status)"
  assert_contains "${st}" "antigravity: version=" "live update status antigravity"
  assert_contains "${st}" "opencode: version=" "live update status opencode"

  MSB_HOME="${ORIG_MSB_HOME}" AGBOX_DATA_DIR="${ORIG_DATA_DIR}" with_timeout 180 agbox_exec "${ACTIVE_BIN}" run --no-net --name "${SUITE_ID}-updchk" --cmd \
    'agy --version && opencode --version && grep -q " /home/agent/.local/bin/agy " /proc/self/mountinfo'
  AGBOX_DATA_DIR="${ORIG_DATA_DIR}" agbox_exec "${ACTIVE_BIN}" update clear all
}

# ---------------------------------------------------------------------------
# Phase 7: Isolated full clean-slate lifecycle in non-disruptive --full mode
# ---------------------------------------------------------------------------

check_40_isolated_full_lifecycle() {
  build_test_binaries
  local iso_msb="${TEST_ROOT}/full-iso-msb"
  local iso_data="${TEST_ROOT}/full-iso-data"
  local iso_bin_dir="${TEST_ROOT}/full-iso-bin"

  if ! prepare_isolated_msb_home "${iso_msb}"; then
    skip_check "msb does not isolate MSB_HOME (use --disruptive to test create-base, edit-base, and remove)"
  fi

  mkdir -p "${iso_bin_dir}"
  chmod 0700 "${iso_bin_dir}"

  cleanup_40() {
    if [[ -x "${iso_bin_dir}/agbox" ]]; then
      MSB_HOME="${iso_msb}" AGBOX_DATA_DIR="${iso_data}" agbox_exec "${iso_bin_dir}/agbox" remove --yes >/dev/null 2>&1 || true
    fi
  }
  trap cleanup_40 RETURN

  local -a inst_args=()
  if [[ "${ALLOW_ROOT}" -eq 1 ]]; then
    inst_args+=(--allow-root)
  fi
  (
    cd "${REPO_DIR}"
    MSB_HOME="${iso_msb}" AGBOX_DATA_DIR="${iso_data}" AGBOX_INSTALL_DIR="${iso_bin_dir}" with_timeout 300 ./install.sh "${inst_args[@]}"
  )
  local ibin="${iso_bin_dir}/agbox"
  [[ -x "${ibin}" ]] || return 1

  MSB_HOME="${iso_msb}" AGBOX_DATA_DIR="${iso_data}" with_timeout 900 agbox_exec "${ibin}" create-base --add core both
  MSB_HOME="${iso_msb}" AGBOX_DATA_DIR="${iso_data}" with_timeout 300 agbox_exec "${ibin}" edit-base --cmd "echo iso-v2 > /etc/agbox-iso-v2"
  MSB_HOME="${iso_msb}" AGBOX_DATA_DIR="${iso_data}" with_timeout 180 agbox_exec "${ibin}" edit-base --no-snap --cmd "echo iso-nosnap > /etc/agbox-iso-nosnap"

  MSB_HOME="${iso_msb}" AGBOX_DATA_DIR="${iso_data}" with_timeout 180 agbox_exec "${ibin}" run --no-net --name "${SUITE_ID}-isochk" --cmd \
    'command -v mdformat >/dev/null && command -v shellcheck >/dev/null && command -v jq >/dev/null && grep -qx iso-v2 /etc/agbox-iso-v2 && test ! -e /etc/agbox-iso-nosnap'

  MSB_HOME="${iso_msb}" AGBOX_DATA_DIR="${iso_data}" with_timeout 600 agbox_exec "${ibin}" update both
  local up_st=""
  up_st="$(AGBOX_DATA_DIR="${iso_data}" agbox_exec "${ibin}" update status)"
  assert_contains "${up_st}" "antigravity: version=" "iso update status"
  assert_contains "${up_st}" "opencode: version=" "iso update status"
  AGBOX_DATA_DIR="${iso_data}" agbox_exec "${ibin}" update clear all

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
  post_snaps="$(MSB_HOME="${iso_msb}" with_timeout 20 "${MSB_BIN_PATH}" snap ls 2>/dev/null || true)"
  if grep -Eq 'agbox(:| )|agbox-base(:| )' <<< "${post_snaps}"; then
    echo "Expected isolated snapshots deleted after remove --yes" >&2
    return 1
  fi
}

# ---------------------------------------------------------------------------
# Phase 8: Host state verification
# ---------------------------------------------------------------------------

check_99_verify_host_unchanged() {
  sweep_suite_resources
  local after_dir="${TEST_ROOT}/after-baseline"
  capture_state "${after_dir}"

  local failed=0
  local item=""
  for item in data_dir.fp install_bin.fp msb_sandboxes.txt msb_snaps.txt msb_volumes.txt agbox_mounts.txt; do
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
    ORIG_DATA_DIR="$(cd -- "$(dirname "${AGBOX_DATA_DIR}")" 2>/dev/null && printf '%s/%s' "$(pwd -P)" "$(basename "${AGBOX_DATA_DIR}")" || printf '%s' "${AGBOX_DATA_DIR}")"
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
  ORIG_INSTALL_BIN="${ORIG_INSTALL_DIR}/agbox"

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
    if [[ -z "${GOCACHE:-}" ]]; then
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
  else
    LOG_DIR="${TMPDIR:-/tmp}/agbox-test-logs-$(date +%Y%m%d-%H%M%S)-$$"
  fi
  mkdir -p "${LOG_DIR}"
  chmod 0700 "${LOG_DIR}"
  SUITE_LOG="${LOG_DIR}/suite.log"
  : > "${SUITE_LOG}"

  if [[ "${DISRUPTIVE_MODE}" -eq 1 && -f "${ORIG_INSTALL_BIN}" && ! -L "${ORIG_INSTALL_BIN}" ]]; then
    ORIG_INSTALL_EXISTED=1
    BACKUP_INSTALL_BIN="${TEST_ROOT}/backup-orig-agbox"
    cp -p "${ORIG_INSTALL_BIN}" "${BACKUP_INSTALL_BIN}"
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
      snaps_list="$(MSB_HOME="${ORIG_MSB_HOME}" with_timeout 20 "${MSB_BIN_PATH}" snap ls 2>/dev/null || true)"
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
        for mf in run.meta suspended detached; do
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
  trap global_cleanup EXIT INT TERM HUP

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

  # Phase 3: Standalone embedded FUSE Workspace Hub.
  maybe_run_phase_check "08-fuse-workspace-hub" "Verify live FUSE Workspace Hub VCS masking and ro enforcement" check_08_fuse_workspace_hub 0

  # Phases 4-6: Virtualization preflight and live microVM integration suite.
  local run_any_vm=0
  local pair=""
  local -a core_vm_checks=(
    "20-ephemeral-run-shares-and-secrets|Verify ephemeral run, FUSE shares, secret streaming, and passthrough exit|check_20_ephemeral_run_shares_and_secrets"
    "21-persistence-auth-skills-rules-agents-profile|Verify auth, skills, rules, agent cache, and profile disk volume|check_21_persistence_auth_skills_rules_agents_profile"
    "22-persist-remote-control-shares-suspend-resume|Verify --persist remote-control, dynamic shares, suspend, resume, and stop|check_22_persist_remote_control_shares_suspend_resume"
    "23-serve-loopback-probe|Verify loopback-bound --serve --probe readiness and teardown|check_23_serve_loopback_probe"
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

  # Phase 8: Final teardown and state verification (always runs).
  if [[ "${DISRUPTIVE_MODE}" -eq 1 ]]; then
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
