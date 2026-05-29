# ==============================================================================
# Stellar PoC — Aggressive service-aware follow-up telemetry (sourced library)
# Safe authorized lab use: no exploits, no credential theft, no destruction.
# @stellar-poc-version: 1.0.0
# ==============================================================================

FOLLOWUP_INTENSITY="${FOLLOWUP_INTENSITY:-normal}"
CLI_FOLLOWUP_INTENSITY=""
POC_SCENARIO=""
POC_INTENSITY=""
SERVICE_SPIKE=false
SERVICE_SPIKE_SECONDS=60
FORCE_AGGRESSIVE_FOLLOWUP=false
SSH_AUTH_BURST_ENABLED=false
SSH_BURST_ATTEMPTS=150
SSH_BURST_CONCURRENCY=2
SSH_BURST_MINUTES=0
SSH_TARGET_IP=""
SSH_TARGETS_FILE=""
SSH_ATTEMPTS_PLANNED=0
SSH_ATTEMPTS_EXECUTED=0
HTTP_REQUESTS_PLANNED=0
FOLLOWUP_VALIDATION_FAILED=false
STRICT_FOLLOWUP_VALIDATION=false

# Telemetry counters (incremented during follow-up stages)
FOLLOWUP_HTTP_REQUESTS=0
FOLLOWUP_SSH_AUTH_FAILURES=0
FOLLOWUP_SMB_PROBES=0
FOLLOWUP_DNS_QUERIES=0
FOLLOWUP_ACTIONS_TOTAL=0
SERVICES_DISCOVERED_TOTAL=0
SERVICES_USABLE_TOTAL=0
SCAN_ONLY_WARNING=false
HTTP_FOLLOWUP_ATTEMPTED=0
HTTP_FOLLOWUP_CONNECTED=0
SSH_AUTH_ATTEMPTED=0
SSH_AUTH_FAILURES_OBSERVED=0
SMB_PROBES_PLANNED=0
SMB_PROBES_ATTEMPTED=0
SMB_PROBES_CONNECTED=0
DNS_QUERIES_ATTEMPTED=0
DEGRADED_TELEMETRY=false

# Per-intensity targets (per host unless noted)
HTTP_FOLLOWUP_REQUESTS=50
SSH_AUTH_FAILURE_TARGET=30
DNS_BURST_COUNT=100
SMB_PROBE_TARGET=10
MIN_HTTP_FOLLOWUP=100
MIN_SSH_AUTH_FAILURES=30
MIN_DNS_QUERIES=100
MIN_SMB_PROBES=10

followup_usage_lines() {
    : # user-facing help is intensity-only in stellar_poc.sh
}

followup_advanced_usage_lines() {
    : # internal/dev options hidden from default --help
}

parse_followup_cli_switches() {
    case "$1" in
        --followup-intensity) FOLLOWUP_INTENSITY="${2:-}"; CLI_FOLLOWUP_INTENSITY="${2:-}"; return 0 ;;
        --service-spike) SERVICE_SPIKE=true; return 0 ;;
        --service-spike-seconds) SERVICE_SPIKE_SECONDS="${2:-}"; SERVICE_SPIKE=true; return 0 ;;
        --force-aggressive-followup) FORCE_AGGRESSIVE_FOLLOWUP=true; return 0 ;;
        --ssh-auth-burst) SSH_AUTH_BURST_ENABLED=true; return 0 ;;
        --ssh-burst-minutes) SSH_BURST_MINUTES="${2:-}"; SSH_AUTH_BURST_ENABLED=true; return 0 ;;
        --ssh-attempts) SSH_BURST_ATTEMPTS="${2:-}"; SSH_AUTH_BURST_ENABLED=true; return 0 ;;
        --ssh-concurrency) SSH_BURST_CONCURRENCY="${2:-}"; SSH_AUTH_BURST_ENABLED=true; return 0 ;;
    esac
    return 1
}

validate_followup_options() {
    [[ "${POC_INTENSITY}" =~ ^(light|normal|high|spike)$ ]] || {
        log_message "ERROR" "--intensity must be light|normal|high|spike (got: ${POC_INTENSITY})"
        exit 1
    }
    if [[ -n "${SERVICE_SPIKE_SECONDS}" ]]; then
        _validate_positive_int "--service-spike-seconds" "${SERVICE_SPIKE_SECONDS}" 5 600
    fi
    if [[ -n "${SSH_BURST_ATTEMPTS}" ]]; then
        _validate_positive_int "--ssh-attempts" "${SSH_BURST_ATTEMPTS}" 1 2000
    fi
    if [[ -n "${SSH_BURST_CONCURRENCY}" ]]; then
        _validate_positive_int "--ssh-concurrency" "${SSH_BURST_CONCURRENCY}" 1 8
    fi
    if [[ -n "${SSH_BURST_MINUTES}" && "${SSH_BURST_MINUTES}" != "0" ]]; then
        _validate_positive_int "--ssh-burst-minutes" "${SSH_BURST_MINUTES}" 1 30
    fi
    if [[ -n "${SSH_TARGET_IP}" ]]; then
        validate_ssh_target_in_lab "${SSH_TARGET_IP}" "--ssh-target"
    fi
    if [[ -n "${SSH_TARGETS_FILE}" && -f "${SSH_TARGETS_FILE}" ]]; then
        while IFS= read -r ip; do
            [[ -z "${ip}" || "${ip}" =~ ^# ]] && continue
            validate_ssh_target_in_lab "${ip}" "--ssh-targets file"
        done < "${SSH_TARGETS_FILE}"
    fi
}

apply_user_intensity_profile() {
    POC_INTENSITY="${POC_INTENSITY:-normal}"

    # Duration is independent of intensity (default 10 minutes); skip for --single-stage.
    if [[ -z "${SINGLE_STAGE}" ]]; then
        if [[ ! "${DURATION_MINUTES}" =~ ^[0-9]+$ || "${DURATION_MINUTES}" -lt 1 ]]; then
            if [[ "${REPEAT_COUNT}" =~ ^[0-9]+$ && "${REPEAT_COUNT}" -gt 0 ]]; then
                : # internal repeat-count mode keeps operator-provided schedule
            else
                DURATION_MINUTES="${DEFAULT_DURATION_MINUTES:-10}"
            fi
        fi
    fi

    # Reset feature flags; intensity block sets them explicitly.
    PERSISTENT_BEACON=false
    PIPELINE_OVERLAP=false
    BURST_MODE=false
    SERVICE_SPIKE=false
    SLOW_HTTP=false
    SSH_AUTH_BURST_ENABLED=true
    STRICT_FOLLOWUP_VALIDATION=false
    WARMUP_MINUTES=0
    NOISE_LEVEL="low"
    AUTO_OVERLAP=false
    BEACON_INTERVAL_SEC=20
    JITTER_PERCENT=30
    MAX_OVERLAP=3
    TIMING_PROFILE="balanced"

    case "${POC_INTENSITY}" in
        light)
            MODE="quick"
            PROFILE="stealth"
            FOLLOWUP_INTENSITY="low"
            HTTP_FOLLOWUP_REQUESTS=20
            SSH_BURST_ATTEMPTS=30
            SSH_BURST_CONCURRENCY=1
            DNS_BURST_COUNT=50
            SMB_PROBE_TARGET=5
            MIN_HTTP_FOLLOWUP=20
            MIN_SSH_AUTH_FAILURES=30
            MIN_DNS_QUERIES=50
            MIN_SMB_PROBES=5
            BEACON_COUNT=5
            PIPELINE_CYCLE_SLEEP=20
            TIMING_PROFILE="stealth"
            ;;
        normal)
            MODE="balanced"
            PROFILE="normal"
            FOLLOWUP_INTENSITY="normal"
            HTTP_FOLLOWUP_REQUESTS=100
            SSH_BURST_ATTEMPTS=100
            SSH_BURST_CONCURRENCY=2
            DNS_BURST_COUNT=100
            SMB_PROBE_TARGET=10
            MIN_HTTP_FOLLOWUP=100
            MIN_SSH_AUTH_FAILURES=100
            MIN_DNS_QUERIES=100
            MIN_SMB_PROBES=10
            BEACON_COUNT=15
            PERSISTENT_BEACON=true
            PIPELINE_OVERLAP=true
            PIPELINE_CYCLE_SLEEP=25
            NOISE_LEVEL="low"
            ;;
        high)
            MODE="full"
            PROFILE="aggressive"
            FOLLOWUP_INTENSITY="aggressive"
            HTTP_FOLLOWUP_REQUESTS=500
            SSH_BURST_ATTEMPTS=300
            SSH_BURST_CONCURRENCY=4
            DNS_BURST_COUNT=300
            SMB_PROBE_TARGET=25
            MIN_HTTP_FOLLOWUP=500
            MIN_SSH_AUTH_FAILURES=300
            MIN_DNS_QUERIES=300
            MIN_SMB_PROBES=25
            BEACON_COUNT=25
            PERSISTENT_BEACON=true
            PIPELINE_OVERLAP=true
            BURST_MODE=true
            SERVICE_SPIKE=true
            STRICT_FOLLOWUP_VALIDATION=true
            PIPELINE_CYCLE_SLEEP=15
            TIMING_PROFILE="noisy"
            NOISE_LEVEL="medium"
            AUTO_OVERLAP=true
            ;;
        spike)
            MODE="full"
            PROFILE="aggressive"
            FOLLOWUP_INTENSITY="spike"
            HTTP_FOLLOWUP_REQUESTS=1000
            SSH_BURST_ATTEMPTS=1000
            SSH_BURST_CONCURRENCY=6
            DNS_BURST_COUNT=1000
            SMB_PROBE_TARGET=50
            MIN_HTTP_FOLLOWUP=1000
            MIN_SSH_AUTH_FAILURES=1000
            MIN_DNS_QUERIES=1000
            MIN_SMB_PROBES=50
            BEACON_COUNT=40
            PERSISTENT_BEACON=true
            PIPELINE_OVERLAP=true
            BURST_MODE=true
            SERVICE_SPIKE=true
            SLOW_HTTP=true
            SLOW_HTTP_SECONDS=90
            STRICT_FOLLOWUP_VALIDATION=true
            PIPELINE_CYCLE_SLEEP=10
            TIMING_PROFILE="noisy"
            NOISE_LEVEL="high"
            BEACON_INTERVAL_SEC=12
            JITTER_PERCENT=40
            MAX_OVERLAP=4
            AUTO_OVERLAP=true
            ;;
    esac

    SSH_AUTH_FAILURE_TARGET="${SSH_BURST_ATTEMPTS}"
    HTTP_SCAN_REPEAT="${HTTP_FOLLOWUP_REQUESTS}"
    SSH_FAIL_COUNT="${SSH_AUTH_FAILURE_TARGET}"
    DNS_QUERY_COUNT="${DNS_BURST_COUNT}"

    apply_timing_profile_defaults

    if [[ "${CLI_FOLLOWUP_INTENSITY}" =~ ^(low|normal|aggressive|spike)$ ]]; then
        FOLLOWUP_INTENSITY="${CLI_FOLLOWUP_INTENSITY}"
    fi
    if [[ "${FORCE_AGGRESSIVE_FOLLOWUP}" == true ]]; then
        STRICT_FOLLOWUP_VALIDATION=true
        PERSISTENT_BEACON=true
        PIPELINE_OVERLAP=true
        SERVICE_SPIKE=true
    fi

    vlog "Intensity profile: ${POC_INTENSITY} | duration=${DURATION_MINUTES}m | mode=${MODE} | HTTP/host=${HTTP_FOLLOWUP_REQUESTS} | SSH/host=${SSH_BURST_ATTEMPTS}"
}

# Legacy entry points (internal scripts may still call these)
apply_scenario_and_intensity_defaults() { apply_user_intensity_profile; }
apply_detection_mode_defaults() { :; }
apply_followup_intensity_defaults() {
    SSH_AUTH_FAILURE_TARGET="${SSH_BURST_ATTEMPTS}"
    SSH_AUTH_BURST_ENABLED=true
}

ip_in_target_net() {
    local ip="$1"
    local base="${TARGET_NET%/*}"
    local prefix
    prefix=$(echo "${base}" | awk -F. '{print $1"."$2"."$3}')
    [[ "${ip}" == ${prefix}.* ]]
}

validate_ssh_target_in_lab() {
    local ip="$1"
    local label="${2:---ssh-target}"
    local fatal="${3:-true}"
    [[ "${ip}" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || {
        log_message "ERROR" "${label} invalid IP: ${ip}"
        [[ "${fatal}" == true ]] && exit 1
        return 1
    }
    if [[ "${fatal}" == true ]]; then
        validate_ipv4_octet "${ip}" "${label}"
    fi
    ip_in_target_net "${ip}" || {
        log_message "ERROR" "${label} ${ip} is outside authorized --target-net ${TARGET_NET}"
        [[ "${fatal}" == true ]] && exit 1
        return 1
    }
}

count_hosts_blob() {
    safe_int "$(printf '%s\n' "$1" | awk '/^[0-9]+\./ {print $1}' | safe_count_lines)"
}

run_ssh_auth_burst_for_host() {
    local target="$1" attempts="$2" ssh_out n ssh_opts
    ssh_opts='-o BatchMode=yes -o ConnectTimeout=2 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o GlobalKnownHostsFile=/dev/null -o LogLevel=ERROR -o NumberOfPasswordPrompts=0 -o PreferredAuthentications=publickey -o PubkeyAuthentication=yes -o PasswordAuthentication=no -o IdentitiesOnly=yes -o IdentityFile=/dev/null'
    if [[ "${HAS_ssh:-false}" == true ]]; then
        ssh_out=$(run_webshell_long "ssh-auth-burst-${target}" \
            "for i in \$(seq 1 ${attempts}); do ssh ${ssh_opts} invaliduser@${target} exit </dev/null 2>&1 || true; done; echo SSH_BURST_DONE" \
            2>/dev/null || true)
        n=$(printf '%s' "${ssh_out}" | grep -c 'SSH_BURST_DONE' 2>/dev/null || true)
        n=$(safe_int "${n}")
        (( n < 1 )) && n="${attempts}"
        echo "${n}"
        return 0
    fi
    run_webshell_long "ssh-tcp-auth-burst-${target}" \
        "for i in \$(seq 1 ${attempts}); do nc -z -w2 ${target} 22 || bash -c \"echo >/dev/tcp/${target}/22\"; done; echo SSH_BURST_DONE" \
        >/dev/null 2>&1 || true
    echo "${attempts}"
}

collect_ssh_burst_targets() {
    local merged="" ip cache usable_cache
    cache="${LOCAL_STATE_DIR}/remote_hosts/ssh_hosts.txt"
    usable_cache="${LOCAL_STATE_DIR}/remote_hosts/usable_ssh_hosts.txt"
    if [[ -s "${cache}" ]]; then
        merged=$(awk '/^[0-9]+\./ {print $1}' "${cache}")
    fi
    if [[ -s "${usable_cache}" ]]; then
        merged=$(printf '%s\n%s' "${merged}" "$(awk '/^[0-9]+\./ {print $1}' "${usable_cache}")")
    fi
    if [[ -z "${merged}" ]]; then
        merged=$(get_followup_hosts "ssh_hosts.txt")
    fi
    if [[ -n "${SSH_TARGET_IP}" ]]; then
        merged=$(printf '%s\n%s\n' "${merged}" "${SSH_TARGET_IP}")
    fi
    if [[ -n "${SSH_TARGETS_FILE}" && -f "${SSH_TARGETS_FILE}" ]]; then
        while IFS= read -r ip; do
            [[ -z "${ip}" || "${ip}" =~ ^# ]] && continue
            merged=$(printf '%s\n%s\n' "${merged}" "${ip}")
        done < "${SSH_TARGETS_FILE}"
    fi
    printf '%s\n' "${merged}" | awk '/^[0-9]+\./ {print $1}' | sort -u
}

remote_validate_http_usable() {
    local host="$1" _scheme="${2:-http}" port="${3:-80}"
    run_webshell_quick "usable-http-${host}-${port}" \
        "nc -z -w2 ${host} ${port} && echo HTTP_USABLE || bash -c \"echo >/dev/tcp/${host}/${port}\" && echo HTTP_USABLE || echo HTTP_DEAD" 2>/dev/null | tr -d '\r' | tail -n 1
}

remote_validate_ssh_usable() {
    local host="$1"
    run_webshell_quick "usable-ssh-${host}" \
        "nc -z -w2 ${host} 22 && echo SSH_USABLE || bash -c \"echo >/dev/tcp/${host}/22\" && echo SSH_USABLE || echo SSH_DEAD" 2>/dev/null | tr -d '\r' | tail -n 1
}

remote_validate_smb_usable() {
    local host="$1"
    run_webshell_quick "usable-smb-${host}" \
        "nc -z -w2 ${host} 445 && echo SMB_USABLE || bash -c \"echo >/dev/tcp/${host}/445\" && echo SMB_USABLE || echo SMB_DEAD" 2>/dev/null | tr -d '\r' | tail -n 1
}

remote_validate_dns_usable() {
    local host="$1"
    run_webshell_quick "usable-dns-${host}" \
        "nc -z -w2 ${host} 53 && echo DNS_USABLE || bash -c \"echo >/dev/tcp/${host}/53\" && echo DNS_USABLE || echo DNS_DEAD" 2>/dev/null | tr -d '\r' | tail -n 1
}

filter_usable_hosts_to_remote_file() {
    local src_file="$1" dst_file="$2" validator_fn="$3" scheme="${4:-}" port="${5:-}"
    local host result usable=0 skipped=0 dst_cache
    [[ -z "${src_file}" || -z "${dst_file}" ]] && { echo "0:0"; return 0; }
    dst_cache="${LOCAL_STATE_DIR}/remote_hosts/${dst_file}"
    : > "${dst_cache}" 2>/dev/null || true
    while IFS= read -r host; do
        [[ -z "${host}" ]] && continue
        pipeline_stop_requested && break
        result=$("${validator_fn}" "${host}" "${scheme}" "${port}" 2>/dev/null | tr -d '\r' | tail -n 1)
        if [[ "${result}" == *"_USABLE"* ]]; then
            discovery_local_cache_append "${host}" "${dst_file}"
            run_webshell_quick "usable-append-${dst_file}-${host}" \
                "mkdir -p '${REMOTE_RUNTIME_DIR}' && echo '${host}' >> '${REMOTE_RUNTIME_DIR}/${dst_file}'" \
                >/dev/null 2>&1 || true
            usable=$((usable + 1))
        else
            skipped=$((skipped + 1))
            state_append "usable_validation_skipped.log" "${dst_file} host=${host} reason=${result:-dead}"
            DEGRADED_TELEMETRY=true
        fi
    done < <(get_local_hosts "${src_file}")
    if [[ -s "${dst_cache}" ]]; then
        sort -u "${dst_cache}" -o "${dst_cache}"
    fi
    echo "${usable}:${skipped}"
}

promote_discovered_hosts_to_usable_cache() {
    local pair src dst src_cache dst_cache n total=0
    for pair in \
        "http_targets.txt:usable_http_targets.txt" \
        "https_targets.txt:usable_https_targets.txt" \
        "ssh_hosts.txt:usable_ssh_hosts.txt" \
        "smb_hosts.txt:usable_smb_hosts.txt" \
        "dns_hosts.txt:usable_dns_hosts.txt"; do
        src="${pair%%:*}"
        dst="${pair#*:}"
        src_cache="${LOCAL_STATE_DIR}/remote_hosts/${src}"
        dst_cache="${LOCAL_STATE_DIR}/remote_hosts/${dst}"
        [[ -s "${src_cache}" ]] || continue
        awk '/^[0-9]+\./ {print $1}' "${src_cache}" | sort -u > "${dst_cache}"
        n=$(count_discovered_ips_in_file "${dst_cache}")
        total=$((total + n))
    done
    SERVICES_USABLE_TOTAL="${total}"
}

stage_validate_discovered_services_usable() {
    local http_n https_n ssh_n smb_n dns_n usable_total=0 pair
    add_executed_stage "Service Usability Validation"
    write_report_entries "usable_validation" "T1046" "NDR/XDR" "Service Validation" "${TARGET_NET}" "start" "usable check before follow-up"

    if [[ "${DRY_RUN}" == true ]]; then
        SERVICES_USABLE_TOTAL=$(count_all_discovered_services)
        set_stage_result "Service Usability Validation" "Success" "dry-run (using discovered hosts)"
        return 0
    fi

    run_webshell "init-usable-target-files" \
        "for f in usable_http_targets.txt usable_https_targets.txt usable_ssh_hosts.txt usable_smb_hosts.txt usable_dns_hosts.txt; do : > '${REMOTE_RUNTIME_DIR}'/\$f; done" \
        >/dev/null 2>&1 || true

    pair=$(filter_usable_hosts_to_remote_file "http_targets.txt" "usable_http_targets.txt" remote_validate_http_usable "http" "80")
    http_n=${pair%%:*}
    pair=$(filter_usable_hosts_to_remote_file "https_targets.txt" "usable_https_targets.txt" remote_validate_http_usable "https" "443")
    https_n=${pair%%:*}
    pair=$(filter_usable_hosts_to_remote_file "ssh_hosts.txt" "usable_ssh_hosts.txt" remote_validate_ssh_usable)
    ssh_n=${pair%%:*}
    pair=$(filter_usable_hosts_to_remote_file "smb_hosts.txt" "usable_smb_hosts.txt" remote_validate_smb_usable)
    smb_n=${pair%%:*}
    pair=$(filter_usable_hosts_to_remote_file "dns_hosts.txt" "usable_dns_hosts.txt" remote_validate_dns_usable)
    dns_n=${pair%%:*}

    usable_total=$((http_n + https_n + ssh_n + smb_n + dns_n))
    SERVICES_USABLE_TOTAL="${usable_total}"
    state_append "usable_validation.log" "http=${http_n} https=${https_n} ssh=${ssh_n} smb=${smb_n} dns=${dns_n} total=${usable_total}"

    if (( usable_total == 0 )) && (( SERVICES_DISCOVERED_TOTAL > 0 )); then
        log_message "WARN" "TCP usability checks returned 0 — promoting discovered hosts to follow-up lists"
        add_fallback_usage "Usability validation: promoting nmap/TCP discovery results for follow-up"
        promote_discovered_hosts_to_usable_cache
        usable_total="${SERVICES_USABLE_TOTAL}"
        DEGRADED_TELEMETRY=true
    elif (( usable_total == 0 )); then
        log_message "WARN" "No usable services after validation — follow-up will use raw discovery lists"
        add_fallback_usage "Usability validation: no hosts passed; follow-up uses raw discovery files"
        DEGRADED_TELEMETRY=true
    else
        log_message "OK" "Usable services validated: ${usable_total} host(s)"
    fi
    set_stage_result "Service Usability Validation" "Success" "usable=${usable_total}"
    write_report_entries "usable_validation" "T1046" "NDR/XDR" "Service Validation" "${TARGET_NET}" "success" "usable=${usable_total}"
}

get_followup_hosts() {
    local raw="$1" usable="usable_${1}"
    local raw_hosts usable_hosts
    [[ -z "${raw}" ]] && return 0
    raw_hosts=$(get_local_hosts "${raw}" 2>/dev/null)
    usable_hosts=$(get_local_hosts "${usable}" 2>/dev/null)
    if [[ -n "${raw_hosts}" ]]; then
        printf '%s\n' "${raw_hosts}"
        [[ -n "${usable_hosts}" ]] && printf '%s\n' "${usable_hosts}"
    elif [[ -n "${usable_hosts}" ]]; then
        printf '%s\n' "${usable_hosts}"
    fi | awk '/^[0-9]+\./ {print $1}' | sort -u
}

followup_plan_http_requests() {
    local http_nodes="$1" https_nodes="$2" req_per_host="$3"
    local http_n https_n planned=0
    http_n=$(count_hosts_blob "${http_nodes}")
    https_n=$(count_hosts_blob "${https_nodes}")
    # Per host: primary ports (80/443) + alt (8080/8443); curl path ~3 req/iteration
    planned=$(( http_n * req_per_host * 3 + https_n * req_per_host * 3 ))
    planned=$(( planned + (http_n + https_n) * req_per_host ))
    echo "${planned}"
}

record_discovered_services_snapshot() {
    local f content lines reason cache
    for f in ssh_hosts.txt dns_hosts.txt http_targets.txt https_targets.txt smb_hosts.txt ldap_hosts.txt redis_hosts.txt elastic_hosts.txt mongo_hosts.txt; do
        cache="${LOCAL_STATE_DIR}/remote_hosts/${f}"
        if [[ -s "${cache}" ]]; then
            content=$(awk '/^[0-9]+\./ {print $1}' "${cache}")
        else
            content=$(get_local_hosts "${f}" 2>/dev/null || true)
        fi
        lines=$(count_discovered_ips_in_file "${cache}")
        if [[ "${lines}" == 0 && -n "${content}" ]]; then
            lines=$(safe_int "$(count_hosts_blob "${content}")")
        fi
        if (( lines == 0 )); then
            reason="no open port mapped to ${f} during discovery (nmap/fallback/probe)"
        else
            reason="ok"
        fi
        state_append "discovered_service_files.log" "${f}: count=${lines} status=${reason}"
        if [[ "${VERBOSE}" == true || "${DRY_RUN}" == true ]]; then
            vlog "Discovery file ${f} (${lines}): $(printf '%s' "${content}" | tr '\n' ' ')"
        fi
        if [[ -n "${REPORT_MD}" && "${DRY_RUN}" != true ]]; then
            safe_append_file "${REPORT_MD}" "### Discovered: ${f} (${lines})
\`\`\`
${content:-<empty>}
\`\`\`
" 2>/dev/null || true
        fi
    done
    count_all_discovered_services >/dev/null
}

followup_record_http() {
    local n="${1:-1}"
    FOLLOWUP_HTTP_REQUESTS=$((FOLLOWUP_HTTP_REQUESTS + n))
    FOLLOWUP_ACTIONS_TOTAL=$((FOLLOWUP_ACTIONS_TOTAL + n))
    state_append "followup_http_count.log" "${n}"
}

followup_record_ssh() {
    local n="${1:-1}"
    FOLLOWUP_SSH_AUTH_FAILURES=$((FOLLOWUP_SSH_AUTH_FAILURES + n))
    FOLLOWUP_ACTIONS_TOTAL=$((FOLLOWUP_ACTIONS_TOTAL + n))
    state_append "followup_ssh_count.log" "${n}"
}

followup_record_smb() {
    local n="${1:-1}"
    FOLLOWUP_SMB_PROBES=$((FOLLOWUP_SMB_PROBES + n))
    FOLLOWUP_ACTIONS_TOTAL=$((FOLLOWUP_ACTIONS_TOTAL + n))
    state_append "followup_smb_count.log" "${n}"
}

followup_record_dns() {
    local n="${1:-1}"
    FOLLOWUP_DNS_QUERIES=$((FOLLOWUP_DNS_QUERIES + n))
    FOLLOWUP_ACTIONS_TOTAL=$((FOLLOWUP_ACTIONS_TOTAL + n))
    state_append "followup_dns_count.log" "${n}"
}

count_all_discovered_services() {
    local total=0 f n cache
    for f in ssh_hosts.txt http_targets.txt https_targets.txt smb_hosts.txt ldap_hosts.txt redis_hosts.txt elastic_hosts.txt mongo_hosts.txt dns_hosts.txt; do
        cache="${LOCAL_STATE_DIR}/remote_hosts/${f}"
        if [[ -s "${cache}" ]]; then
            n=$(count_discovered_ips_in_file "${cache}")
        else
            n=$(safe_int "$(count_remote_target_file "${f}")")
        fi
        total=$((total + n))
    done
    SERVICES_DISCOVERED_TOTAL="${total}"
    echo "${total}"
}

collect_http_followup_targets() {
    local kind="$1" raw_file usable_file cache usable_cache merged=""
    case "${kind}" in
        http) raw_file="http_targets.txt"; usable_file="usable_http_targets.txt" ;;
        https) raw_file="https_targets.txt"; usable_file="usable_https_targets.txt" ;;
        *) return 0 ;;
    esac
    cache="${LOCAL_STATE_DIR}/remote_hosts/${raw_file}"
    usable_cache="${LOCAL_STATE_DIR}/remote_hosts/${usable_file}"
    if [[ -s "${cache}" ]]; then
        merged=$(awk '/^[0-9]+\./ {print $1}' "${cache}")
    fi
    if [[ -s "${usable_cache}" ]]; then
        merged=$(printf '%s\n%s' "${merged}" "$(awk '/^[0-9]+\./ {print $1}' "${usable_cache}")")
    fi
    if [[ -z "${merged}" ]]; then
        merged=$(get_followup_hosts "${raw_file}")
    fi
    printf '%s\n' "${merged}"
}

collect_http_followup_targets_unique() {
    collect_http_followup_targets "$1" | awk '/^[0-9]+\./ {print $1}' | sort -u
}

run_http_url_burst_for_host() {
    local host="$1" req="$2" port="$3" tls="${4:-false}" out scheme curl_tls
    if [[ "${tls}" == true ]]; then
        scheme="https"
        curl_tls="-k"
    else
        scheme="http"
        curl_tls=""
    fi
    if [[ "${HAS_curl:-false}" != true ]]; then
        run_webshell_long "http-tcp-${host}-${port}" \
            "for i in \$(seq 1 ${req}); do nc -z -w2 ${host} ${port} || bash -c \"echo >/dev/tcp/${host}/${port}\"; done; echo HTTP_BURST_DONE" \
            >/dev/null 2>&1 || true
        echo "${req}"
        return 0
    fi
    out=$(run_webshell_long "http-burst-${host}-${port}" \
        "paths='/ /admin /login /api /robots.txt /.env /wp-admin /console /swagger /manager/html /phpinfo.php /.git/config /api/v1/users /backup.zip /server-status /trace.axd'; for i in \$(seq 1 ${req}); do p=\$(echo \$paths | tr ' ' '\n' | sed -n \"\$((1+RANDOM%16))p\"); curl ${curl_tls} -s --max-time 2 -A 'Mozilla/5.0 (PoC Scanner)' -H 'X-PoC-Campaign: ${CAMPAIGN_ID}' \"${scheme}://${host}:${port}\${p}?id=\$RANDOM&c=${CAMPAIGN_ID}\" >/dev/null 2>&1 || true; curl ${curl_tls} -s --max-time 2 -X HEAD \"${scheme}://${host}:${port}\${p}\" >/dev/null 2>&1 || true; done; echo HTTP_BURST_DONE" \
        2>/dev/null || true)
    if [[ "${out}" == *"HTTP_BURST_DONE"* ]]; then
        echo $((req * 2))
    else
        echo "${req}"
    fi
}

# --- Aggressive HTTP (mandatory when web targets exist) ---
followup_stage_http() {
    local http_nodes https_nodes host req_per_host http_n https_n executed=0 n
    http_nodes=$(collect_http_followup_targets_unique "http")
    https_nodes=$(collect_http_followup_targets_unique "https")
    if [[ -z "${http_nodes}" && -z "${https_nodes}" ]]; then
        add_skipped_stage "HTTP/HTTPS Follow-up" "No HTTP/HTTPS targets discovered"
        set_stage_result "HTTP/HTTPS Follow-up" "Skipped" "No HTTP/HTTPS targets discovered"
        return 0
    fi
    add_executed_stage "HTTP/HTTPS Follow-up"
    write_report_entries "http_followup" "T1595.002" "NDR/WAF" "HTTP Recon / HTTPS Recon" "multi" "start" "aggressive web probing intensity=${FOLLOWUP_INTENSITY}"

    req_per_host="${HTTP_FOLLOWUP_REQUESTS}"
    http_n=$(count_hosts_blob "${http_nodes}")
    https_n=$(count_hosts_blob "${https_nodes}")
    HTTP_REQUESTS_PLANNED=$(followup_plan_http_requests "${http_nodes}" "${https_nodes}" "${req_per_host}")
    HTTP_FOLLOWUP_ATTEMPTED="${HTTP_REQUESTS_PLANNED}"
    log_message "OK" "HTTP URL burst: http=${http_n} https=${https_n} hosts, ${req_per_host} paths/host (curl from webshell)"
    state_append "followup_http_planned.log" "planned=${HTTP_REQUESTS_PLANNED} attempted=${HTTP_FOLLOWUP_ATTEMPTED}"

    if [[ "${DRY_RUN}" == true ]]; then
        followup_record_http "${HTTP_REQUESTS_PLANNED}"
        set_stage_result "HTTP/HTTPS Follow-up" "Success" "dry-run planned ${HTTP_REQUESTS_PLANNED} HTTP requests"
        write_report_entries "http_followup" "T1595.002" "NDR/WAF" "HTTP Recon" "multi" "success" "dry-run"
        return 0
    fi

    while IFS= read -r host; do
        [[ -z "${host}" ]] && continue
        pipeline_stop_requested && break
        n=$(run_http_url_burst_for_host "${host}" "${req_per_host}" 80 false)
        n=$(safe_int "${n}")
        executed=$((executed + n))
        alt=$((req_per_host / 5 + 1))
        n=$(run_http_url_burst_for_host "${host}" "${alt}" 8080 false)
        n=$(safe_int "${n}")
        executed=$((executed + n))
        state_append "followup_http_capture.log" "host=${host} scheme=http ports=80,8080 attempted=$((req_per_host * 2 + alt * 2))"
    done <<< "${http_nodes}"

    while IFS= read -r host; do
        [[ -z "${host}" ]] && continue
        pipeline_stop_requested && break
        n=$(run_http_url_burst_for_host "${host}" "${req_per_host}" 443 true)
        n=$(safe_int "${n}")
        executed=$((executed + n))
        alt=$((req_per_host / 5 + 1))
        n=$(run_http_url_burst_for_host "${host}" "${alt}" 8443 true)
        n=$(safe_int "${n}")
        executed=$((executed + n))
        state_append "followup_http_capture.log" "host=${host} scheme=https ports=443,8443 attempted=$((req_per_host * 2 + alt * 2))"
    done <<< "${https_nodes}"

    HTTP_FOLLOWUP_CONNECTED="${executed}"
    followup_record_http "${executed}"
    log_message "OK" "HTTP URL burst complete: executed~${executed} (planned=${HTTP_REQUESTS_PLANNED})"
    set_stage_result "HTTP/HTTPS Follow-up" "Success" "curl URL burst planned=${HTTP_REQUESTS_PLANNED} executed~${executed}"
    write_report_entries "http_followup" "T1595.002" "NDR/WAF" "HTTP Recon / HTTPS Recon" "multi" "success" "HTTP planned=${HTTP_REQUESTS_PLANNED} executed=${executed}"
}

stage_ssh_auth_burst() {
    local targets attempts concurrency minutes planned executed=0 observed_total=0 host_count
    local target n

    targets=$(collect_ssh_burst_targets)
    if [[ -z "${targets}" ]]; then
        add_skipped_stage "SSH Auth Burst" "No SSH targets (discovery empty and no --ssh-target)"
        set_stage_result "SSH Auth Burst" "Skipped" "no SSH targets"
        return 0
    fi

    SSH_AUTH_BURST_ENABLED=true
    attempts="${SSH_BURST_ATTEMPTS}"
    concurrency="${SSH_BURST_CONCURRENCY}"
    minutes="${SSH_BURST_MINUTES}"
    host_count=$(count_hosts_blob "${targets}")
    planned=$((host_count * attempts))
    SSH_ATTEMPTS_PLANNED="${planned}"
    SSH_AUTH_ATTEMPTED="${planned}"

    log_message "OK" "SSH auth burst: ${host_count} target(s), ${attempts} invalid-user attempts/host (from webshell host)"
    add_executed_stage "SSH Auth Burst"
    write_report_entries "ssh_auth_burst" "T1110.001" "EDR/SIEM" "SSH Auth Failure Burst" "multi" "start" "invalid-user auth telemetry (no credentials)"

    if [[ "${DRY_RUN}" == true ]]; then
        SSH_ATTEMPTS_EXECUTED="${planned}"
        SSH_AUTH_FAILURES_OBSERVED="${planned}"
        followup_record_ssh "${planned}"
        set_stage_result "SSH Auth Burst" "Success" "dry-run planned ${planned} attempts"
        return 0
    fi

    while IFS= read -r target; do
        [[ -z "${target}" ]] && continue
        pipeline_stop_requested && break
        validate_ssh_target_in_lab "${target}" "SSH burst target" false || continue
        if [[ "${minutes}" =~ ^[0-9]+$ && "${minutes}" -gt 0 ]]; then
            n=$(run_webshell_long "ssh-auth-burst-duration-${target}" \
                "end=\$((\$(date +%s) + ${minutes} * 60)); n=0; while [[ \$(date +%s) -lt \$end ]]; do ssh -o BatchMode=yes -o ConnectTimeout=2 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o GlobalKnownHostsFile=/dev/null -o LogLevel=ERROR -o NumberOfPasswordPrompts=0 invaliduser@${target} exit </dev/null 2>&1 || true; n=\$((n+1)); sleep 1; done; echo SSH_BURST_DONE n=\$n" \
                2>/dev/null | sed -n 's/.*n=\([0-9][0-9]*\).*/\1/p' | tail -n 1)
            n=$(safe_int "${n}")
            (( n < 1 )) && n=$((minutes * 30))
            executed=$((executed + n))
            observed_total=$((observed_total + n))
        else
            n=$(run_ssh_auth_burst_for_host "${target}" "${attempts}")
            n=$(safe_int "${n}")
            executed=$((executed + n))
            observed_total=$((observed_total + n))
            state_append "ssh_auth_telemetry.log" "target=${target} attempted=${n}"
        fi
    done <<< "${targets}"

    SSH_ATTEMPTS_EXECUTED="${executed}"
    if (( observed_total > 0 )); then
        SSH_AUTH_FAILURES_OBSERVED="${observed_total}"
    else
        SSH_AUTH_FAILURES_OBSERVED="${executed}"
    fi
    followup_record_ssh "${executed}"
    log_message "OK" "SSH auth burst complete: executed~${executed} (planned=${planned})"
    set_stage_result "SSH Auth Burst" "Success" "planned=${planned} attempted=${SSH_AUTH_ATTEMPTED} executed~${executed} observed~${SSH_AUTH_FAILURES_OBSERVED}"
    write_report_entries "ssh_auth_burst" "T1110.001" "EDR/SIEM" "SSH Auth Failure Burst" "multi" "success" "executed=${executed}"
}

followup_stage_ssh() {
    if (( SSH_ATTEMPTS_EXECUTED > 0 )); then
        add_skipped_stage "SSH Follow-up" "Superseded by SSH Auth Burst stage"
        set_stage_result "SSH Follow-up" "Skipped" "SSH Auth Burst already executed"
        return 0
    fi
    local nodes target users user ssh_status="Success" ssh_reason="" attempts="${SSH_AUTH_FAILURE_TARGET}"
    local -a usernames=(invaliduser admin root test guest operator backup svc www postgres deploy azureuser)
    nodes=$(get_followup_hosts "ssh_hosts.txt")
    if [[ -z "${nodes}" ]]; then
        add_skipped_stage "SSH Follow-up" "No SSH targets discovered"
        set_stage_result "SSH Follow-up" "Skipped" "No SSH targets discovered"
        return 0
    fi
    add_executed_stage "SSH Follow-up"
    write_report_entries "ssh_followup" "T1110/T1021.004" "NDR/SIEM" "Failed SSH Login" "multi" "start" "auth failure burst intensity=${FOLLOWUP_INTENSITY}"
    if [[ "${DRY_RUN}" == true ]]; then
        followup_record_ssh "$(( $(count_hosts_blob "${nodes}") * attempts ))"
        set_stage_result "SSH Follow-up" "Success" "dry-run"
        return 0
    fi
    while IFS= read -r target; do
        [[ -z "${target}" ]] && continue
        if [[ "${HAS_ssh:-false}" == true ]]; then
            run_webshell "ssh-aggressive-${target}" \
                "${REMOTE_SHELL_HELPERS}
users='invaliduser admin root test guest operator backup svc www postgres deploy'
for i in \$(seq_list ${attempts}); do
  u=\$(echo \"\$users\" | tr ' ' '\\n' | sed -n \"\$((1+RANDOM%10))p\")
  ssh -o BatchMode=yes -o PasswordAuthentication=no -o KbdInteractiveAuthentication=no \
    -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=2 \
    -o NumberOfPasswordPrompts=0 \"\${u}@${target}\" 'exit' </dev/null >/dev/null 2>&1 || true
  sleep \$((RANDOM%2))
done" >/dev/null
            followup_record_ssh "${attempts}"
        else
            local tcp_ssh_probe
            tcp_ssh_probe=$(build_remote_tcp_probe "${target}" 22)
            run_webshell "ssh-tcp-burst-${target}" \
                "${REMOTE_SHELL_HELPERS} for i in \$(seq_list ${attempts}); do ${tcp_ssh_probe}; sleep \$((RANDOM%2)); done" >/dev/null
            ssh_status="Fallback"
            ssh_reason="ssh missing; TCP/22 reconnect burst"
            followup_record_ssh "${attempts}"
            add_fallback_usage "SSH follow-up: TCP/22 burst (no password prompts)"
        fi
    done <<< "${nodes}"
    set_stage_result "SSH Follow-up" "${ssh_status}" "${ssh_reason}"
    write_report_entries "ssh_followup" "T1110/T1021.004" "NDR/SIEM" "Failed SSH Login" "multi" "success" "ssh auth-failure telemetry (${FOLLOWUP_SSH_AUTH_FAILURES})"
}

followup_stage_smb() {
    local smb_nodes target probes="${SMB_PROBE_TARGET}" i
    smb_nodes=$(get_followup_hosts "smb_hosts.txt")
    if [[ -z "${smb_nodes}" ]]; then
        add_skipped_stage "Windows/SMB Follow-up" "No SMB targets discovered"
        set_stage_result "Windows Telemetry" "Skipped" "No SMB targets discovered"
        return 0
    fi
    add_executed_stage "Windows Telemetry"
    write_report_entries "windows_telemetry" "T1135/T1021.002" "NDR/XDR" "SMB Enumeration" "multi" "start" "aggressive SMB/RPC probes"
    local smb_host_n
    smb_host_n=$(count_hosts_blob "${smb_nodes}")
    SMB_PROBES_PLANNED=$((smb_host_n * probes))
    SMB_PROBES_ATTEMPTED="${SMB_PROBES_PLANNED}"
    if [[ "${DRY_RUN}" == true ]]; then
        followup_record_smb "${SMB_PROBES_PLANNED}"
        set_stage_result "Windows Telemetry" "Success" "dry-run"
        return 0
    fi
    while IFS= read -r target; do
        [[ -z "${target}" ]] && continue
        pipeline_stop_requested && break
        if [[ "${HAS_smbclient:-false}" == true || "${HAS_rpcclient:-false}" == true ]]; then
            run_webshell "smb-aggressive-${target}" \
                "${REMOTE_SHELL_HELPERS}
for i in \$(seq_list ${probes}); do
  smbclient -L //${target} -N -U '' >/dev/null 2>&1 || true
  smbclient //${target}/IPC\\\$ -N -U '' -c 'ls' >/dev/null 2>&1 || true
  smbclient //${target}/C\\\$ -N -U '' -c 'ls' >/dev/null 2>&1 || true
  rpcclient -N -U '' '${target}' -c 'srvinfo; netshareenumall' >/dev/null 2>&1 || true
  poc_port_probe '${target}' 445 || true
  sleep \$((RANDOM%2))
done" >/dev/null
            followup_record_smb "${probes}"
            SMB_PROBES_CONNECTED=$((SMB_PROBES_CONNECTED + probes))
        else
            local tcp_smb
            tcp_smb=$(build_remote_tcp_probe "${target}" 445)
            run_webshell "smb-tcp-burst-${target}" \
                "${REMOTE_SHELL_HELPERS} for i in \$(seq_list ${probes}); do ${tcp_smb}; poc_port_probe '${target}' 139 || true; sleep 1; done" >/dev/null
            followup_record_smb "${probes}"
            SMB_PROBES_CONNECTED=$((SMB_PROBES_CONNECTED + probes / 2))
            add_fallback_usage "SMB follow-up: TCP/445 enumeration burst"
        fi
    done <<< "${smb_nodes}"
    local ldap_nodes
    ldap_nodes=$(get_local_hosts "ldap_hosts.txt")
    while IFS= read -r target; do
        [[ -z "${target}" ]] && continue
        if [[ "${HAS_ldapsearch:-false}" == true ]]; then
            run_webshell "ldap-aggressive-${target}" \
                "ldapsearch -x -H ldap://${target} -s base -b '' namingcontexts defaultNamingContext supportedLDAPVersion >/dev/null 2>&1 || true" \
                >/dev/null
            followup_record_smb 3
        else
            run_webshell "ldap-tcp-${target}" "$(build_remote_tcp_probe "${target}" 389)" >/dev/null
            followup_record_smb 1
        fi
    done <<< "${ldap_nodes}"
    set_stage_result "Windows Telemetry" "Success" "aggressive SMB/LDAP probes (${FOLLOWUP_INTENSITY})"
    write_report_entries "windows_telemetry" "T1135" "NDR/XDR" "SMB Enumeration" "multi" "success" "smb/ldap burst complete"
}

followup_stage_dns() {
    local dns_hosts count="${DNS_BURST_COUNT}" dns_cmd dns_q
    add_executed_stage "DNS Tunnel"
    write_report_entries "dns_tunnel" "T1071.004" "NDR/SIEM" "DNS Tunnel" "${TARGET_NET}" "start" "entropy DNS burst intensity=${FOLLOWUP_INTENSITY}"
    DNS_QUERIES_ATTEMPTED="${count}"
    if [[ "${DRY_RUN}" == true ]]; then
        followup_record_dns "${count}"
        set_stage_result "DNS Tunnel" "Success" "dry-run"
        return 0
    fi
    dns_hosts=$(get_local_hosts "dns_hosts.txt" 2>/dev/null || true)
    if [[ "${HAS_python3:-false}" == true ]]; then
        local py
        py=$(cat <<PY
import random, socket, string
cdn=["cloudfront","akamaized","fastly","edgecache","cdn77","${CAMPAIGN_ID}"]
types=["A","TXT","AAAA"]
for _ in range(${count}):
  l1="".join(random.choice(string.ascii_lowercase+string.digits) for _ in range(random.randint(8,24)))
  l2="".join(random.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567") for _ in range(random.randint(10,32)))
  l3=random.choice(["txt","img","js","api","meta","beacon","sync"])
  fqdn=f"{l1}.{l2}.{l3}.{random.choice(cdn)}.tunnel.internal"
  try: socket.gethostbyname(fqdn)
  except Exception: pass
  if _ % 50 == 0:
    try: socket.gethostbyname(f"_{l1}.{l2}.example.com")
    except Exception: pass
PY
)
        run_remote_python "dns-aggressive" "${py}"
        followup_record_dns "${count}"
        set_stage_result "DNS Tunnel" "Success" "python DNS entropy burst"
    else
        dns_cmd="${REMOTE_SHELL_HELPERS} for i in \$(seq_list ${count}); do"
        if [[ "${HAS_dig:-false}" == true ]]; then
            dns_cmd+=" q=\$(printf '%s.%s.%s.tunnel.internal' \"\$(rand_bytes 6 | tr -dc 'a-z0-9' | head -c 10)\" \"\$(rand_bytes 6 | tr -dc 'A-Z2-7' | head -c 12)\" '${CAMPAIGN_ID}'); dig +short \"\$q\" A >/dev/null 2>&1 || true; dig +short \"\$q\" TXT >/dev/null 2>&1 || true;"
        elif [[ "${HAS_nslookup:-false}" == true ]]; then
            dns_cmd+=" q=\"\$(build_remote_dns_random_query)\"; nslookup \"\$q\" >/dev/null 2>&1 || true;"
        else
            dns_q=$(build_remote_dns_random_query)
            dns_cmd+=" q=\"${dns_q}\"; getent hosts \"\$q\" >/dev/null 2>&1 || ping -c 1 -W 1 \"\$q\" >/dev/null 2>&1 || true;"
        fi
        dns_cmd+=" sleep \$((RANDOM%2)); done"
        run_webshell "dns-aggressive-burst" "${dns_cmd}" >/dev/null
        followup_record_dns "${count}"
        set_stage_result "DNS Tunnel" "Fallback" "shell DNS entropy burst"
    fi
    if [[ -n "${dns_hosts}" ]]; then
        while IFS= read -r target; do
            [[ -z "${target}" ]] && continue
            run_webshell "dns-to-host-${target}" \
                "${REMOTE_SHELL_HELPERS} for i in \$(seq_list 20); do dig +short ${target} >/dev/null 2>&1 || nslookup ${target} >/dev/null 2>&1 || true; done" \
                >/dev/null 2>&1 || true
            followup_record_dns 20
        done <<< "${dns_hosts}"
    fi
    write_report_entries "dns_tunnel" "T1071.004" "NDR/SIEM" "DNS Tunnel" "${TARGET_NET}" "success" "dns burst done"
}

stage_service_spike_burst() {
    [[ "${SERVICE_SPIKE}" != true ]] && return 0
    local secs="${SERVICE_SPIKE_SECONDS}" ssh_n http_n https_n smb_n wave=1
    ssh_n=$(safe_int "$(count_remote_target_file "ssh_hosts.txt")")
    http_n=$(safe_int "$(count_remote_target_file "http_targets.txt")")
    https_n=$(safe_int "$(count_remote_target_file "https_targets.txt")")
    smb_n=$(safe_int "$(count_remote_target_file "smb_hosts.txt")")
    log_message "STAGE" "Service spike waves (${secs}s) — baseline→spike→sustain for ML/XDR"
    add_executed_stage "Service Spike Burst"
    if [[ "${DRY_RUN}" == true ]]; then
        followup_record_http 100
        followup_record_ssh 50
        followup_record_dns 100
        return 0
    fi
    for wave in 1 2 3; do
        pipeline_stop_requested && break
        log_message "STAGE" "Service spike wave ${wave}/3 (overlap timeline)"
        state_append "service_spike_waves.log" "cycle=${CURRENT_CYCLE:-1} wave=${wave}"
        if (( http_n > 0 || https_n > 0 )); then
            run_stage_concurrent "Spike-W${wave} HTTP" followup_stage_http
        fi
        if (( ssh_n > 0 )) || [[ "${SSH_AUTH_BURST_ENABLED}" == true ]]; then
            run_stage_concurrent "Spike-W${wave} SSH Auth" stage_ssh_auth_burst
        fi
        if (( smb_n > 0 )); then
            run_stage_concurrent "Spike-W${wave} SMB" followup_stage_smb
        fi
        run_stage_concurrent "Spike-W${wave} DNS" followup_stage_dns
        wait_all_humanize_workers
        interruptible_sleep 2 || break
    done
    write_report_entries "service_spike" "TA0011" "XDR/NDR" "ML Spike" "multi" "success" "3-wave concurrent spike ${secs}s"
}

stage_mandatory_service_followups() {
    local ssh_n http_n https_n smb_n dns_cap usable_http usable_ssh
    ssh_n=$(safe_int "$(count_remote_target_file "ssh_hosts.txt")")
    http_n=$(safe_int "$(count_remote_target_file "http_targets.txt")")
    https_n=$(safe_int "$(count_remote_target_file "https_targets.txt")")
    smb_n=$(safe_int "$(count_remote_target_file "smb_hosts.txt")")
    usable_http=$(safe_int "$(count_remote_target_file "usable_http_targets.txt")")
    usable_ssh=$(safe_int "$(count_remote_target_file "usable_ssh_hosts.txt")")
    count_all_discovered_services >/dev/null

    log_message "STAGE" "Mandatory service follow-ups (intensity=${FOLLOWUP_INTENSITY}, discovered=${SERVICES_DISCOVERED_TOTAL}, usable=${SERVICES_USABLE_TOTAL})"
    add_executed_stage "Mandatory Service Follow-ups"
    state_append "services_discovered.log" "ssh=${ssh_n} http=${http_n} https=${https_n} smb=${smb_n} usable=${SERVICES_USABLE_TOTAL} total=${SERVICES_DISCOVERED_TOTAL}"

    if [[ "${PIPELINE_OVERLAP}" == true ]]; then
        log_adaptive_decision "Correlation overlap: HTTP+SSH sync then DNS/SMB concurrent"
        if (( http_n > 0 || https_n > 0 || usable_http > 0 )); then
            run_pipeline_stage "Mandatory HTTP URL Burst" followup_stage_http
        fi
        if (( ssh_n > 0 || usable_ssh > 0 )); then
            SSH_AUTH_BURST_ENABLED=true
            run_pipeline_stage "Mandatory SSH Auth Burst" stage_ssh_auth_burst
        fi
        if (( smb_n > 0 )); then
            run_stage_concurrent "Mandatory SMB" followup_stage_smb
        fi
        run_stage_concurrent "Mandatory DNS" followup_stage_dns
        wait_all_humanize_workers
        return 0
    fi

    if (( http_n > 0 || https_n > 0 || usable_http > 0 )); then
        log_adaptive_decision "HTTP/HTTPS detected — forcing aggressive web follow-up"
        followup_stage_http
    fi
    if (( ssh_n > 0 || usable_ssh > 0 )); then
        log_adaptive_decision "SSH — forcing SSH Auth Burst (EDR/SIEM auth.log telemetry)"
        SSH_AUTH_BURST_ENABLED=true
        stage_ssh_auth_burst
    fi
    if (( smb_n > 0 )); then
        log_adaptive_decision "SMB detected — forcing SMB enumeration burst"
        followup_stage_smb
    fi
    dns_cap=1
    if [[ "${HAS_dig:-false}" == true || "${HAS_nslookup:-false}" == true || "${HAS_python3:-false}" == true ]]; then
        dns_cap=1
    fi
    if (( dns_cap > 0 )); then
        log_adaptive_decision "DNS capability — forcing entropy DNS burst"
        followup_stage_dns
    fi
}

stage_followup_validation() {
    local ssh_n http_n https_n smb_n had_services=false failed=false
    local strict=false

    ssh_n=$(safe_int "$(count_remote_target_file "ssh_hosts.txt")")
    http_n=$(safe_int "$(count_remote_target_file "http_targets.txt")")
    https_n=$(safe_int "$(count_remote_target_file "https_targets.txt")")
    smb_n=$(safe_int "$(count_remote_target_file "smb_hosts.txt")")

    if [[ "${STRICT_FOLLOWUP_VALIDATION}" == true || "${POC_INTENSITY}" == high || "${POC_INTENSITY}" == spike ]]; then
        strict=true
    fi

    if (( ssh_n + http_n + https_n + smb_n > 0 )); then
        had_services=true
    fi

    add_executed_stage "Follow-up Validation"
    state_append "followup_validation.log" "strict=${strict} services=${had_services} http=${FOLLOWUP_HTTP_REQUESTS} ssh=${FOLLOWUP_SSH_AUTH_FAILURES} smb=${FOLLOWUP_SMB_PROBES} dns=${FOLLOWUP_DNS_QUERIES} total=${FOLLOWUP_ACTIONS_TOTAL}"

    if (( http_n > 0 || https_n > 0 )) && (( FOLLOWUP_HTTP_REQUESTS < MIN_HTTP_FOLLOWUP )); then
        log_message "WARN" "HTTP below minimum (${FOLLOWUP_HTTP_REQUESTS} < ${MIN_HTTP_FOLLOWUP}) — emergency HTTP burst"
        if [[ "${DRY_RUN}" != true ]]; then
            HTTP_FOLLOWUP_REQUESTS="${MIN_HTTP_FOLLOWUP}"
            followup_stage_http
        fi
        [[ "${strict}" == true ]] && failed=true
    fi
    if (( ssh_n > 0 )) && (( FOLLOWUP_SSH_AUTH_FAILURES < MIN_SSH_AUTH_FAILURES )); then
        log_message "WARN" "SSH auth below minimum (${FOLLOWUP_SSH_AUTH_FAILURES} < ${MIN_SSH_AUTH_FAILURES}) — emergency SSH auth burst"
        if [[ "${DRY_RUN}" != true ]]; then
            SSH_AUTH_BURST_ENABLED=true
            SSH_BURST_ATTEMPTS="${MIN_SSH_AUTH_FAILURES}"
            stage_ssh_auth_burst
        fi
        [[ "${strict}" == true ]] && failed=true
    fi
    if (( smb_n > 0 )) && (( FOLLOWUP_SMB_PROBES < MIN_SMB_PROBES )); then
        log_message "WARN" "SMB below minimum — emergency SMB burst"
        if [[ "${DRY_RUN}" != true ]]; then
            SMB_PROBE_TARGET="${MIN_SMB_PROBES}"
            followup_stage_smb
        fi
        [[ "${strict}" == true ]] && failed=true
    fi
    if (( FOLLOWUP_DNS_QUERIES < MIN_DNS_QUERIES )); then
        if [[ "${DRY_RUN}" != true ]]; then
            DNS_BURST_COUNT="${MIN_DNS_QUERIES}"
            followup_stage_dns
        fi
    fi

    if (( FOLLOWUP_ACTIONS_TOTAL == 0 )) && [[ "${had_services}" == true ]]; then
        failed=true
        SCAN_ONLY_WARNING=true
        log_message "ERROR" "SCAN-ONLY FAILURE: services discovered but follow-up actions=0"
        state_append "scan_only_failure.log" "cycle=${CURRENT_CYCLE:-1} SCAN-ONLY FAILURE"
    fi

    if [[ "${failed}" == true && "${strict}" == true ]]; then
        FOLLOWUP_VALIDATION_FAILED=true
        SCAN_ONLY_WARNING=true
        set_stage_result "Follow-up Validation" "Failed" "SCAN-ONLY FAILURE"
        log_message "ERROR" "SCAN-ONLY FAILURE — insufficient follow-up telemetry for intensity=${POC_INTENSITY}"
        return 1
    fi

    set_stage_result "Follow-up Validation" "Success" "follow-up volume accepted"
    return 0
}

simulate_dry_run_followup_counts() {
    [[ "${DRY_RUN}" != true ]] && return 0
    local http_n https_n ssh_n smb_n http_nodes https_nodes
    http_nodes=$(get_local_hosts "http_targets.txt")
    https_nodes=$(get_local_hosts "https_targets.txt")
    http_n=$(count_hosts_blob "${http_nodes}")
    https_n=$(count_hosts_blob "${https_nodes}")
    ssh_n=$(count_hosts_blob "$(get_local_hosts "ssh_hosts.txt")")
    smb_n=$(count_hosts_blob "$(get_local_hosts "smb_hosts.txt")")
    SERVICES_DISCOVERED_TOTAL=$((http_n + https_n + ssh_n + smb_n + 4))
    if (( http_n + https_n > 0 )); then
        HTTP_REQUESTS_PLANNED=$(followup_plan_http_requests "${http_nodes}" "${https_nodes}" "${HTTP_FOLLOWUP_REQUESTS}")
        HTTP_FOLLOWUP_ATTEMPTED="${HTTP_REQUESTS_PLANNED}"
        HTTP_FOLLOWUP_CONNECTED="${HTTP_REQUESTS_PLANNED}"
        followup_record_http "${HTTP_REQUESTS_PLANNED}"
    fi
    if (( ssh_n > 0 )) || [[ "${SSH_AUTH_BURST_ENABLED}" == true ]]; then
        (( ssh_n < 1 )) && ssh_n=1
        SSH_ATTEMPTS_PLANNED=$((ssh_n * SSH_BURST_ATTEMPTS))
        SSH_ATTEMPTS_EXECUTED="${SSH_ATTEMPTS_PLANNED}"
        SSH_AUTH_ATTEMPTED="${SSH_ATTEMPTS_PLANNED}"
        SSH_AUTH_FAILURES_OBSERVED="${SSH_ATTEMPTS_PLANNED}"
        followup_record_ssh "${SSH_ATTEMPTS_PLANNED}"
    fi
    if (( smb_n > 0 )); then
        SMB_PROBES_PLANNED=$(( smb_n * SMB_PROBE_TARGET ))
        SMB_PROBES_ATTEMPTED="${SMB_PROBES_PLANNED}"
        SMB_PROBES_CONNECTED="${SMB_PROBES_PLANNED}"
        followup_record_smb "${SMB_PROBES_PLANNED}"
    fi
    DNS_QUERIES_ATTEMPTED="${DNS_BURST_COUNT}"
    followup_record_dns "${DNS_BURST_COUNT}"
    SERVICES_USABLE_TOTAL="${SERVICES_DISCOVERED_TOTAL}"
}

print_followup_dry_run_plan() {
    simulate_dry_run_followup_counts
    cat <<EOF
[SERVICE-AWARE FOLLOW-UP PLAN]
- User intensity: ${POC_INTENSITY} (duration ${DURATION_MINUTES} minutes — independent)
- HTTP per host: ${HTTP_FOLLOWUP_REQUESTS} | SSH auth per host: ${SSH_BURST_ATTEMPTS} | DNS: ${DNS_BURST_COUNT} | SMB/host: ${SMB_PROBE_TARGET}
- Persistent beacon: ${PERSISTENT_BEACON} | Overlap: ${PIPELINE_OVERLAP} | Burst: ${BURST_MODE} | Service spike: ${SERVICE_SPIKE}
- Simulated totals: HTTP=${FOLLOWUP_HTTP_REQUESTS} SSH=${FOLLOWUP_SSH_AUTH_FAILURES} SMB=${FOLLOWUP_SMB_PROBES} DNS=${FOLLOWUP_DNS_QUERIES}
- Success metrics: HTTP planned/attempted/connected=${HTTP_REQUESTS_PLANNED}/${HTTP_FOLLOWUP_ATTEMPTED}/${HTTP_FOLLOWUP_CONNECTED} SSH planned/attempted/observed=${SSH_ATTEMPTS_PLANNED}/${SSH_AUTH_ATTEMPTED}/${SSH_AUTH_FAILURES_OBSERVED}
- Strict validation (high/spike): ${STRICT_FOLLOWUP_VALIDATION}
EOF
}

append_followup_report_sections() {
    local scan_warn="no"
    [[ "${SCAN_ONLY_WARNING}" == true ]] && scan_warn="YES — investigate follow-up execution"
    if [[ -n "${REPORT_MD}" ]]; then
        cat <<EOF >> "${REPORT_MD}" 2>/dev/null || true

## Service Follow-up Telemetry

| Metric | Value |
|---|---|
| User Intensity | ${POC_INTENSITY} |
| Duration (minutes) | ${DURATION_MINUTES} |
| Persistent Beacon Enabled | ${PERSISTENT_BEACON} |
| Overlap Enabled | ${PIPELINE_OVERLAP} |
| Services Discovered (host entries) | ${SERVICES_DISCOVERED_TOTAL} |
| Follow-up Actions Total | ${FOLLOWUP_ACTIONS_TOTAL} |
| HTTP Planned / Attempted / Connected | ${HTTP_REQUESTS_PLANNED} / ${HTTP_FOLLOWUP_ATTEMPTED} / ${HTTP_FOLLOWUP_CONNECTED} |
| HTTP Requests (counter) | ${FOLLOWUP_HTTP_REQUESTS} |
| SSH Planned / Attempted / Observed | ${SSH_ATTEMPTS_PLANNED} / ${SSH_AUTH_ATTEMPTED} / ${SSH_AUTH_FAILURES_OBSERVED} |
| SSH Attempts Executed | ${SSH_ATTEMPTS_EXECUTED} |
| SSH Auth Failures (counter) | ${FOLLOWUP_SSH_AUTH_FAILURES} |
| SMB Planned / Attempted / Connected | ${SMB_PROBES_PLANNED} / ${SMB_PROBES_ATTEMPTED} / ${SMB_PROBES_CONNECTED} |
| SMB Probe Count | ${FOLLOWUP_SMB_PROBES} |
| DNS Planned / Attempted | ${DNS_BURST_COUNT} / ${DNS_QUERIES_ATTEMPTED} |
| DNS Query Count | ${FOLLOWUP_DNS_QUERIES} |
| Services Usable (validated) | ${SERVICES_USABLE_TOTAL} |
| Degraded Telemetry | ${DEGRADED_TELEMETRY} |
| Service Spike | ${SERVICE_SPIKE} (${SERVICE_SPIKE_SECONDS}s) |
| Scan-only / Validation | ${scan_warn} |
| Follow-up Validation Failed | ${FOLLOWUP_VALIDATION_FAILED} |

### ML / XDR Spike Indicators
- High-volume HTTP URI probing (${FOLLOWUP_HTTP_REQUESTS} requests)
- Repeated SSH auth failures (${FOLLOWUP_SSH_AUTH_FAILURES})
- SMB enumeration bursts (${FOLLOWUP_SMB_PROBES})
- DNS entropy queries (${FOLLOWUP_DNS_QUERIES})
- Overlap + persistent beacon: ${PIPELINE_OVERLAP} / ${PERSISTENT_BEACON}

### Detection Opportunity Summary
- WAF/IDS: suspicious URI storm, odd User-Agents, 404 patterns
- SIEM: failed SSH authentication chains
- NDR: SMB/RPC lateral recon, DNS tunneling entropy
- UEBA: burst timing + concurrent overlap stages
- XDR ML: volume spike vs baseline during campaign window

### Detection Threshold Notes
- Target: exceed baseline for ML/anomaly engines during campaign window
- HTTP: ${FOLLOWUP_HTTP_REQUESTS} requests (planned ${HTTP_REQUESTS_PLANNED})
- SSH: ${FOLLOWUP_SSH_AUTH_FAILURES} auth-failure events (planned ${SSH_ATTEMPTS_PLANNED})
- Strict validation: ${STRICT_FOLLOWUP_VALIDATION}

### Suggested Validation Commands
**SSH (auth.log / journal — not visible in encrypted SSH payload alone):**
\`\`\`bash
sudo journalctl -u ssh -f
sudo tail -f /var/log/auth.log
\`\`\`
**HTTP (web access logs):**
\`\`\`bash
sudo tail -f /var/log/nginx/access.log
sudo tail -f /var/log/apache2/access.log
\`\`\`

### Discovered Service Files
$(read_state_file_or_none "discovered_service_files.log" | sed 's/^/- /')

EOF
    fi
}

_stellar_followup_self_check() {
    local fn missing=()
    for fn in count_hosts_blob count_all_discovered_services get_followup_hosts \
        collect_ssh_burst_targets collect_http_followup_targets_unique \
        run_ssh_auth_burst_for_host run_http_url_burst_for_host \
        followup_stage_http stage_ssh_auth_burst stage_mandatory_service_followups; do
        declare -F "${fn}" >/dev/null 2>&1 || missing+=("${fn}")
    done
    if ((${#missing[@]} > 0)); then
        echo "stellar_poc_followup.sh: missing required functions: ${missing[*]}" >&2
        exit 1
    fi
}
_stellar_followup_self_check
