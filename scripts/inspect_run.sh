#!/usr/bin/env bash
# DSP Run Directory inspector — traffic, validation, DNS tunnel evidence.
#
# Usage:
#   ./scripts/inspect_run.sh /root/.dsp/runs/20260621_c884ab
#   cd /root/.dsp/runs/20260621_c884ab && ../path/to/inspect_run.sh
#   RUN_DIR=/root/.dsp/runs/20260621_c884ab ./scripts/inspect_run.sh
#
set -euo pipefail

RUN_DIR="${1:-${RUN_DIR:-$(pwd)}}"
RUN_DIR="$(cd "${RUN_DIR}" && pwd)"

hr() { printf '\n%s\n' "================================================================================"; }
title() { hr; printf '  %s\n' "$1"; hr; }
need_file() {
  if [[ ! -f "${RUN_DIR}/$1" ]]; then
    printf '  [MISSING] %s\n' "$1"
    return 1
  fi
  return 0
}

have_jq() { command -v jq >/dev/null 2>&1; }

json_pretty() {
  local f="$1"
  if have_jq; then
    jq . "${f}"
  else
    python3 -m json.tool "${f}"
  fi
}

json_get() {
  # json_get FILE 'jq expression'
  local f="$1" expr="$2"
  if have_jq; then
    jq -r "${expr}" "${f}" 2>/dev/null || true
  else
    python3 -c "
import json, sys
data = json.load(open(sys.argv[1]))
expr = sys.argv[2]
# minimal jq-like paths used in this script
def get(d, path):
    for p in path:
        if isinstance(d, dict):
            d = d.get(p)
        else:
            return None
    return d
paths = {
    '.scenarios.dns_tunnel': ['scenarios','dns_tunnel'],
    '.results[].scenario_id': None,
}
" "${f}" "${expr}" 2>/dev/null || true
  fi
}

title "DSP Run Inspector"
printf 'Run Directory: %s\n' "${RUN_DIR}"

title "0. Directory listing"
ls -lah "${RUN_DIR}" || true

title "1. DNS Tunnel — traffic_summary.json"
if need_file traffic_summary.json; then
  json_pretty "${RUN_DIR}/traffic_summary.json"
  if have_jq; then
    printf '\n--- dns_tunnel summary (extract) ---\n'
    jq '.scenarios.dns_tunnel // .dns_tunnel // empty' "${RUN_DIR}/traffic_summary.json" 2>/dev/null || true
    printf '\nqueries_sent:        '
    jq -r '.scenarios.dns_tunnel.queries_sent // .dns_tunnel.queries_sent // "n/a"' "${RUN_DIR}/traffic_summary.json"
    printf 'dns_tunnel_query_sent_count: '
    jq -r '.scenarios.dns_tunnel.dns_tunnel_query_sent_count // "n/a"' "${RUN_DIR}/traffic_summary.json"
    printf 'payload_mb (started): '
    jq -r '.scenarios.dns_tunnel.payload_mb // .scenarios.dns_tunnel.started.payload_mb // "n/a"' "${RUN_DIR}/traffic_summary.json"
    printf 'webshell_http_dispatches: '
    jq -r '.scenarios.dns_tunnel.webshell_http_dispatches // "n/a"' "${RUN_DIR}/traffic_summary.json"
  fi
else
  printf '  traffic_summary.json not found — skip\n'
fi

title "2. Validation — validation.json"
if need_file validation.json; then
  json_pretty "${RUN_DIR}/validation.json"
  if have_jq; then
    printf '\n--- dns_tunnel validation (extract) ---\n'
    jq '.results[] | select(.scenario_id == "dns_tunnel")' "${RUN_DIR}/validation.json" 2>/dev/null || true
  fi
else
  printf '  validation.json not found — skip\n'
fi

title "3. DNS Tunnel events — events.jsonl"
if need_file events.jsonl; then
  dns_lines="$(grep -c 'dns_tunnel' "${RUN_DIR}/events.jsonl" 2>/dev/null || echo 0)"
  printf 'grep dns_tunnel lines: %s\n\n' "${dns_lines}"
  printf '--- first 20 dns_tunnel lines (raw) ---\n'
  grep 'dns_tunnel' "${RUN_DIR}/events.jsonl" | head -20 || true

  if have_jq; then
    printf '\n--- first 10 dns_tunnel events (parsed) ---\n'
    grep 'dns_tunnel' "${RUN_DIR}/events.jsonl" | head -10 | jq -c '{
      timestamp,
      scenario_id,
      event,
      status,
      target,
      fqdn: (.evidence.fqdn // .artifact // empty),
      query_role: (.evidence.query_role // empty),
      seq: (.evidence.seq // empty)
    }' 2>/dev/null || true

    printf '\n--- dns_tunnel event type counts ---\n'
    grep 'dns_tunnel' "${RUN_DIR}/events.jsonl" \
      | jq -r '.event' 2>/dev/null \
      | sort | uniq -c | sort -nr || true

    printf '\n--- dns_tunnel_query_sent by query_role ---\n'
    grep 'dns_tunnel' "${RUN_DIR}/events.jsonl" \
      | jq -r 'select(.event == "dns_tunnel_query_sent") | (.evidence.query_role // "idx_chunk")' 2>/dev/null \
      | sort | uniq -c | sort -nr || true

    printf '\n--- sample idx FQDNs (first 5) ---\n'
    grep 'dns_tunnel' "${RUN_DIR}/events.jsonl" \
      | jq -r 'select(.event == "dns_tunnel_query_sent") | select((.evidence.fqdn // .artifact // "") | startswith("idx-")) | (.evidence.fqdn // .artifact)' 2>/dev/null \
      | head -5 || true

    printf '\n--- session markers ---\n'
    grep 'dns_tunnel' "${RUN_DIR}/events.jsonl" \
      | jq -r 'select(.event == "dns_tunnel_query_sent") | (.evidence.fqdn // .artifact // "") | select(startswith("strt-") or startswith("end-"))' 2>/dev/null \
      | sort -u || true
  fi
else
  printf '  events.jsonl not found — trying events.db\n'
  if need_file events.db; then
    python3 <<'PY' "${RUN_DIR}/events.db" 2>/dev/null || true
import sqlite3, json, sys
db = sys.argv[1]
conn = sqlite3.connect(db)
conn.row_factory = sqlite3.Row
rows = conn.execute(
    "SELECT timestamp, scenario_id, event, status, target, artifact, evidence "
    "FROM events WHERE scenario_id = 'dns_tunnel' ORDER BY id LIMIT 20"
).fetchall()
print(f"dns_tunnel rows (first 20): {len(rows)} shown")
for r in rows:
    ev = json.loads(r["evidence"] or "{}")
    print(json.dumps({
        "timestamp": r["timestamp"],
        "event": r["event"],
        "status": r["status"],
        "target": r["target"],
        "fqdn": ev.get("fqdn") or r["artifact"],
        "query_role": ev.get("query_role"),
    }, ensure_ascii=False))
PY
  fi
fi

title "4. Event statistics — events.jsonl"
if need_file events.jsonl; then
  printf 'total lines: '
  wc -l < "${RUN_DIR}/events.jsonl" | tr -d ' '
  printf '\n'
  if have_jq; then
    printf '--- by scenario_id ---\n'
    jq -r '.scenario_id // empty' "${RUN_DIR}/events.jsonl" \
      | sort | uniq -c | sort -nr
    printf '\n--- by event (top 20) ---\n'
    jq -r '.event // empty' "${RUN_DIR}/events.jsonl" \
      | sort | uniq -c | sort -nr | head -20
  fi
fi

title "5. DNS Tunnel targets (alive host selection check)"
if need_file events.jsonl && have_jq; then
  printf 'unique targets in dns_tunnel events:\n'
  grep 'dns_tunnel' "${RUN_DIR}/events.jsonl" \
    | jq -r '.target // empty' \
    | sort -u
  printf '\nunique resolver/target from query_sent evidence:\n'
  grep 'dns_tunnel' "${RUN_DIR}/events.jsonl" \
    | jq -r 'select(.event == "dns_tunnel_query_sent") | (.evidence.target // .evidence.resolver // .target // empty)' \
    | sort -u
fi

title "6. Webshell HTTP dispatch count (dns_tunnel)"
if need_file events.jsonl && have_jq; then
  printf 'webshell_command_dispatched (dns_tunnel): '
  grep 'dns_tunnel' "${RUN_DIR}/events.jsonl" \
    | jq -r 'select(.event == "webshell_command_dispatched") | .evidence.command_category // empty' 2>/dev/null \
    | grep -c 'dns_tunnel_session' || echo 0
  printf '\nremote execution_mode sample:\n'
  grep 'dns_tunnel' "${RUN_DIR}/events.jsonl" \
    | jq -r 'select(.event == "dns_tunnel_started" or .event == "dns_tunnel_completed") | "\(.event): execution_mode=\(.evidence.execution_mode // "n/a") dns_query_method=\(.evidence.dns_query_method // "n/a")"' 2>/dev/null \
    | head -5 || true
fi

title "7. Quick report.md excerpt (DNS Tunnel)"
if need_file report.md; then
  grep -A 30 -i 'dns tunnel' "${RUN_DIR}/report.md" | head -40 || true
else
  printf '  report.md not found — skip\n'
fi

title "8. QUICK COPY BLOCK (3 outputs)"
printf '>>> traffic_summary.json\n'
if need_file traffic_summary.json; then cat "${RUN_DIR}/traffic_summary.json"; else echo '(missing)'; fi
printf '\n================\n>>> validation.json\n'
if need_file validation.json; then cat "${RUN_DIR}/validation.json"; else echo '(missing)'; fi
printf '\n================\n>>> grep dns_tunnel events.jsonl | head -20\n'
if need_file events.jsonl; then grep 'dns_tunnel' "${RUN_DIR}/events.jsonl" | head -20 || true; else echo '(missing)'; fi

title "Done"
