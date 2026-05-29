#!/usr/bin/env bash
# validate_stellar_poc.sh — static + smoke checks for stellar_poc*.sh
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT}"

failures=0
pass() { printf '[PASS] %s\n' "$1"; }
fail() { printf '[FAIL] %s\n' "$1"; failures=$((failures + 1)); }

# --- 0. Bundle version manifest ---
if [[ -f "${ROOT}/stellar_poc.version" ]]; then
    pass "stellar_poc.version present"
    bundle_ver="$(tr -d '[:space:]' < "${ROOT}/stellar_poc.version")"
    for f in stellar_poc.sh stellar_poc_humanize.sh stellar_poc_followup.sh; do
        hdr_ver=$(grep -m1 '^# @stellar-poc-version:' "${ROOT}/${f}" | awk '{print $3}')
        if [[ "${hdr_ver}" == "${bundle_ver}" ]]; then
            pass "version match ${f}=${bundle_ver}"
        else
            fail "version mismatch ${f}: header=${hdr_ver:-missing} manifest=${bundle_ver}"
        fi
    done
else
    fail "missing stellar_poc.version"
fi

# --- 1. Syntax ---
for f in stellar_poc.sh stellar_poc_humanize.sh stellar_poc_followup.sh; do
    if bash -n "${f}"; then
        pass "bash -n ${f}"
    else
        fail "bash -n ${f}"
    fi
done

# --- 2. Self-check blocks present ---
for f in stellar_poc_followup.sh stellar_poc_humanize.sh; do
    if grep -q '_self_check' "${f}"; then
        pass "self-check block in ${f}"
    else
        fail "missing self-check block in ${f}"
    fi
done

# --- 3. Required function definitions ---
defs_file="$(mktemp)"
for f in stellar_poc_humanize.sh stellar_poc_followup.sh stellar_poc.sh; do
    grep -E '^[a-zA-Z_][a-zA-Z0-9_]*\(\)' "${f}" | sed 's/().*//' >> "${defs_file}"
done
sort -u "${defs_file}" -o "${defs_file}"

required=(
    count_hosts_blob
    count_all_discovered_services
    count_remote_target_file
    count_discovered_ips_in_file
    get_local_hosts
    get_followup_hosts
    collect_ssh_burst_targets
    collect_http_followup_targets_unique
    run_ssh_auth_burst_for_host
    run_http_url_burst_for_host
    discovery_parse_nmap_stdout
    discovery_parse_probe_stdout
    safe_count_lines
    safe_int
    apply_user_intensity_profile
    apply_followup_intensity_defaults
    stage_mandatory_service_followups
    followup_stage_http
    stage_ssh_auth_burst
    run_webshell_long
    run_webshell_quick
)

for fn in "${required[@]}"; do
    if grep -qxF "${fn}" "${defs_file}"; then
        pass "defined: ${fn}"
    else
        fail "missing function definition: ${fn}"
    fi
done

# --- 4. Source scripts (no main) and unit-test helpers ---
smoke_env="$(mktemp -d)"
export LOCAL_STATE_DIR="${smoke_env}/state"
mkdir -p "${LOCAL_STATE_DIR}/remote_hosts"

DRY_RUN=true
WEB_SHELL_URL="http://127.0.0.1/shell.jsp"
TARGET_NET="221.139.249.0/24"
NETWORK_PREFIX="221.139.249"
REMOTE_RUNTIME_DIR="/tmp/.poc_runtime_test"
CAMPAIGN_ID="validate-smoke"
ATTACKER_BASE_URL="http://127.0.0.1:5000"
EFFECTIVE_REPORT_DIR="${smoke_env}/report"
LOG_DIR="${smoke_env}/logs"
REPORT_DIR="${smoke_env}/report"
mkdir -p "${EFFECTIVE_REPORT_DIR}" "${LOG_DIR}"
STOP_REQUESTED=false
SERVICES_DISCOVERED_TOTAL=0
SERVICES_USABLE_TOTAL=0
HAS_ssh=true
HAS_curl=true
POC_INTENSITY=normal
HTTP_FOLLOWUP_REQUESTS=100
SSH_BURST_ATTEMPTS=100
PIPELINE_OVERLAP=false

# shellcheck disable=SC1091
source "${ROOT}/stellar_poc.sh"

# Re-apply test paths (source resets globals)
LOCAL_STATE_DIR="${smoke_env}/state"
EFFECTIVE_REPORT_DIR="${smoke_env}/report"
LOG_DIR="${smoke_env}/logs"
REPORT_DIR="${smoke_env}/report"
mkdir -p "${LOCAL_STATE_DIR}/remote_hosts" "${EFFECTIVE_REPORT_DIR}" "${LOG_DIR}"
DRY_RUN=true

printf '%s\n' "221.139.249.113" "221.139.249.50" > "${LOCAL_STATE_DIR}/remote_hosts/ssh_hosts.txt"
printf '%s\n' "221.139.249.113" > "${LOCAL_STATE_DIR}/remote_hosts/https_targets.txt"

n=$(count_hosts_blob "$(cat "${LOCAL_STATE_DIR}/remote_hosts/ssh_hosts.txt")")
[[ "${n}" == "2" ]] && pass "count_hosts_blob" || fail "count_hosts_blob expected 2 got ${n}"

sample_nmap="Nmap scan report for 221.139.249.200
22/tcp  open  ssh
80/tcp  open  http"
discovery_parse_nmap_stdout "${sample_nmap}"
grep -qxF "221.139.249.200" "${LOCAL_STATE_DIR}/remote_hosts/ssh_hosts.txt" && \
    pass "discovery_parse_nmap_stdout" || fail "discovery_parse_nmap_stdout"

sample_probe="OK:http_targets.txt:80
OK:ssh_hosts.txt:22"
discovery_parse_probe_stdout "221.139.249.201" "${sample_probe}"
grep -qxF "221.139.249.201" "${LOCAL_STATE_DIR}/remote_hosts/http_targets.txt" && \
    pass "discovery_parse_probe_stdout" || fail "discovery_parse_probe_stdout"

ssh_t=$(collect_ssh_burst_targets | wc -l | tr -d ' ')
http_t=$(collect_http_followup_targets_unique http | wc -l | tr -d ' ')
(( ssh_t >= 2 && http_t >= 1 )) && pass "collect targets" || fail "collect targets ssh=${ssh_t} http=${http_t}"

total=$(count_all_discovered_services)
(( total >= 4 )) && pass "count_all_discovered_services=${total}" || fail "count_all_discovered_services=${total}"

apply_user_intensity_profile
[[ "${SSH_BURST_ATTEMPTS}" == "100" ]] && pass "apply_user_intensity_profile" || fail "intensity SSH=${SSH_BURST_ATTEMPTS}"

apply_followup_intensity_defaults
[[ "${SSH_AUTH_BURST_ENABLED}" == true ]] && pass "apply_followup_intensity_defaults" || fail "apply_followup_intensity_defaults"

# set -e safety: [[ -s empty ]] && must not abort
touch "${LOCAL_STATE_DIR}/remote_hosts/empty_hosts.txt"
dedupe_discovery_local_cache
pass "dedupe_discovery_local_cache (empty cache, set -e safe)"

rm -rf "${smoke_env}" "${defs_file}"

# --- 5. Dry-run CLI ---
dry_out="$(mktemp)"
if ./stellar_poc.sh --dry-run --target-net 221.139.249.0/24 --webshell http://127.0.0.1/shell.jsp \
    --attacker-ip 221.139.249.110 --attacker-port 5000 >"${dry_out}" 2>&1; then
    pass "stellar_poc.sh --dry-run exit 0"
else
    fail "stellar_poc.sh --dry-run exit $?"
fi

if grep -q "command not found" "${dry_out}"; then
    fail "dry-run contains 'command not found'"
    grep "command not found" "${dry_out}" >&2 || true
else
    pass "dry-run no 'command not found'"
fi

# --- 6. Single-stage dry-run smoke ---
for stage in service_discovery http_followup ssh_auth_burst; do
    stage_out="$(mktemp)"
    if ./stellar_poc.sh --dry-run --single-stage "${stage}" --target-net 221.139.249.0/24 \
        --webshell http://127.0.0.1/shell.jsp --attacker-ip 221.139.249.110 --attacker-port 5000 \
        >"${stage_out}" 2>&1; then
        if grep -q "command not found" "${stage_out}"; then
            fail "single-stage ${stage}: command not found"
        else
            pass "single-stage dry-run: ${stage}"
        fi
    else
        fail "single-stage dry-run ${stage} exit $?"
        tail -5 "${stage_out}" >&2 || true
    fi
    rm -f "${stage_out}"
done

rm -f "${dry_out}"

echo "---"
if (( failures == 0 )); then
    echo "All validation checks passed."
    exit 0
fi
echo "${failures} validation check(s) failed."
exit 1
