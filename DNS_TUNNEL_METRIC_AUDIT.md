# DNS Tunnel Metric Audit — Wire Traffic vs DSP Metrics

**Date:** 2026-06-22  
**Status:** Root cause proven in code; fix implemented (file-backed markers + HTML normalize + max_chunks parity)  
**Observed symptom:** pcap shows `idx-NNNN-*.dns-tunnel.com` UDP/53 queries (Wire Traffic PASS) while DSP reports `queries_sent=0` and validation `thresholds_not_met`.

---

## 1. Executive Summary

| Layer | Observed | Expected when healthy |
|-------|----------|------------------------|
| Wire (pcap) | UDP/53 `idx-*` queries present | Remote `sendto()` on webshell host |
| Event Store | `dns_tunnel_query_sent` count = **0** | One row per confirmed send |
| Traffic Summary | `queries_sent=0` | Mirrors Event Store |
| Validation | FAIL (`dns_tunnel_query_sent_count` min 1) | PASS when ≥1 sent event |

**Proven root cause (webshell / command-only mode):**

DNS tunnel traffic is generated on the **remote webshell host**, but DSP records `dns_tunnel_query_sent` events only for FQDNs parsed from **webshell HTTP response stdout** (`DNS_TUNNEL_SENT:{fqdn}` lines). When packets are sent but stdout markers are missing, empty, HTML-wrapped, or truncated, `sent_fqdns` is empty → **zero events** despite live wire traffic.

This is not a pcap capture failure and not a local `sendto()` failure on the DSP host.

---

## 2. End-to-End Aggregation Path

```
dns_tunnel scenario (manifest)
  ↓
CommandScenarioRunner (webshell mode)          scenarios/dns_tunnel/executor.py (local mode only)
  ↓
build_command_plan → plan_dns_tunnel           direct plan_dns_tunnel + DnsTunnelTransmitter
  ↓
execute_command_plan → _execute_dns_tunnel     per-chunk send + immediate Event Store append
  ↓
provider.run_remote_command(session script)    client.send_fire_and_forget()
  ↓
parse_dns_tunnel_session_sent_fqdns(stdout)    build_tunnel_query_sent_event on outcome=="sent"
  ↓
dns_tunnel_query_sent (status=sent)            dns_tunnel_query_sent (status=sent)
  ↓
dns_tunnel_completed.evidence.queries_sent     dns_tunnel_completed.evidence.chunks_sent
  ↓
build_traffic_summary → queries_sent           same
  ↓
ValidationEngine → dns_tunnel_query_sent_count min: 1
```

### 2.1 `queries_sent` calculation

| Source | Logic |
|--------|-------|
| **Primary** | `dns_tunnel_completed` evidence field `queries_sent` |
| **Fallback** | `dns_tunnel_completed.dns_tunnel_query_sent_count` |
| **Store count** | `_count_events(..., "dns_tunnel_query_sent")` |

Code: `dsp/runtime/traffic_summary.py` (dns_tunnel branch), `dsp/runner/traffic_summary.py` (console label `queries_sent` ← `dns_tunnel_query_sent_count`).

### 2.2 Validation metrics

`scenarios/dns_tunnel/manifest.yaml`:

- `dns_tunnel_query_sent_count` → count of `event=dns_tunnel_query_sent`, `status=sent`
- `dns_tunnel_chunk_created_count` → count of `event=dns_tunnel_chunk_created`, `status=info`
- Success: both ≥ 1

Code: `dsp/protocols/dns/tunnel_validation.py`, enforced by `dsp/validation/engine.py`.

---

## 3. Event Contract — What Should Be Recorded

| Event | When created (local executor) | When created (webshell) |
|-------|----------------------------|-------------------------|
| `dns_tunnel_started` | Per target, before loop | Per target, before dispatch |
| `dns_tunnel_chunk_created` | Before each send attempt | **Only if FQDN ∈ sent_fqdns** |
| `dns_tunnel_query_sent` | After `transmitter.send()` outcome `sent` | **Only if FQDN ∈ sent_fqdns** |
| `dns_query_sent` | Optional protocol layer event | **Not emitted** in webshell path |
| `dns_tunnel_completed` | After target loop | After stdout parse + event synthesis |

Webshell path does **not** use `dns_query_sent` for tunnel metrics.

---

## 4. Why Wire Traffic and Event Store Diverge

### 4.1 Execution mode split

| Mode | DNS sent on | Event source |
|------|-------------|--------------|
| **Local** (`LocalExecutionProvider`) | DSP host | `scenarios/dns_tunnel/executor.py` — direct `sendto` result |
| **Webshell command-only** | Remote victim host | `dsp/execution/remote/command/execute.py` — **stdout markers** |

Live lab runs with `command_inline_base64_exec` use the webshell path. pcap on the victim/LAN sees packets; DSP host never calls `sendto()` for tunnel chunks.

### 4.2 Webshell success gate (commit bb382c4)

Before bb382c4, HTTP dispatch success (`CommandStatus.COMPLETED`) created `dns_tunnel_query_sent` for **all planned FQDNs** — inflating metrics without wire proof.

After bb382c4, events are created only when:

```python
sent_fqdns = parse_dns_tunnel_session_sent_fqdns(session_output)
for item in target_queries:
    if fqdn not in sent_fqdns:
        continue  # no event
```

**Proof test:** `tests/execution/test_command_execute_validation_events.py::test_dns_tunnel_dispatch_without_sendto_emits_no_query_sent` — `DNS_TUNNEL_SESSION_DONE` without `DNS_TUNNEL_SENT:` → 0 query events.

### 4.3 Remote script emits markers via `print()`

`dsp/execution/remote/command/shell.py` remote session:

```python
def send(sock, fqdn):
    sock.sendto(make_query(fqdn), (T, 53))
    print("DNS_TUNNEL_SENT:" + fqdn)
```

Packets (`sendto`) and metrics (`print`) are **separate channels**. sendto can succeed while DSP receives no markers.

### 4.4 Stdout collection gaps (proven architectural gaps)

| Gap | Evidence in code | Effect |
|-----|------------------|--------|
| **No HTML normalization** | Discovery uses `normalize_webshell_command_output()`; `_execute_dns_tunnel` uses raw `decode()` only | Lines like `<pre>DNS_TUNNEL_SENT:...` fail `startswith("DNS_TUNNEL_SENT:")` |
| **No file-backed marker transport** | Discovery probes write markers to `/tmp` then `cat` (proven pattern in `shell.py` / `discovery.py`) | DNS tunnel relies on streaming stdout over one HTTP response |
| **Python stdout buffering** | Remote `python3 -c` / base64 exec — no `-u`, no `flush=True` on print | Markers may remain buffered if connection ends early |
| **Large session output** | Live `standard` profile: `payload_mb=2.0`, no `max_chunks` cap → ~69,906 idx queries + markers (~3–5 MB stdout) | Webshell HTTP body may truncate; parser sees partial/empty input |
| **Plan vs remote chunk count** | `build_dns_tunnel_queries` honors `max_chunks`; remote script reads entire mock file | Mismatch can reduce intersect(FQDN_plan, FQDN_stdout) (not the primary zero case, but affects counts) |

### 4.5 Which missing event causes `queries_sent=0`?

**Single sufficient condition:** zero rows of `dns_tunnel_query_sent` / `status=sent`.

Typical live failure chain:

1. `dns_tunnel_started` — present  
2. `dns_tunnel_dispatch_completed` — present (HTTP transport OK)  
3. `sent_fqdns = ∅` — stdout parse found no `DNS_TUNNEL_SENT:` lines  
4. `dns_tunnel_query_sent` — **absent**  
5. `dns_tunnel_completed.queries_sent = 0`  
6. Traffic summary + validation → **FAIL**

---

## 5. Stdout Marker Dependency — Full Survey

| Component | sendto-based? | stdout-marker-based? |
|-----------|---------------|----------------------|
| `scenarios/dns_tunnel/executor.py` | **Yes** (`DnsTunnelTransmitter.send`) | No |
| `dsp/execution/remote/command/execute.py::_execute_dns_tunnel` | No (remote) | **Yes** (`parse_dns_tunnel_session_sent_fqdns`) |
| `dsp/execution/remote/command/shell.py::dns_tunnel_session_command` | Yes (remote script) | **Yes** (`print("DNS_TUNNEL_SENT:" + fqdn)`) |
| `dsp/protocols/dns/tunnel.py::parse_dns_tunnel_session_sent_fqdns` | No | **Yes** (line prefix `DNS_TUNNEL_SENT:`) |

Markers searched:

- `DNS_TUNNEL_SENT:{fqdn}` — per-query success evidence  
- `DNS_TUNNEL_SESSION_DONE` — session completion (diagnostic only; not counted as queries)

DGA comparison (works in same lab):

| Aspect | DGA | DNS Tunnel |
|--------|-----|------------|
| Dispatches | **One HTTP call per domain** (~45) | **One HTTP call per target session** |
| Marker | `DGA_SENT:{fqdn}` per response | Thousands of `DNS_TUNNEL_SENT:` in **one** response |
| Response size | ~30–80 bytes each | Up to **megabytes** |
| Event if marker missing | Skip `dga_*_observed` | Skip **all** `dns_tunnel_query_sent` |
| `queries_sent` in UI | `nx + resolved` observed counts | `dns_tunnel_query_sent_count` |

---

## 6. POST Webshell Response Collection

Path:

```
_execute_dns_tunnel
  → provider.run_remote_command(command, timeout)
    → command_transport.run_remote_command
      → POST (or GET) encoded cmd to webshell
      → strip_webshell_exit_marker(response.body)
  → session_output = decode(body)
  → parse_dns_tunnel_session_sent_fqdns(session_output)
```

**Conclusion:** Transport can succeed (`dispatch_transport_ok=True`) while `session_output` contains no parseable markers → **send success + stdout collection failure** state.

Diagnostic fields already stored on `dns_tunnel_dispatch_completed`:

- `dns_tunnel_sendto_success_count` (= len(sent_fqdns) from stdout, not wire)  
- `dns_tunnel_session_script_completed`  
- `session_output_preview` (first 500 chars)

---

## 7. Failure Root Cause (Proven)

```
[Remote host]  sendto() → UDP/53 idx-* queries → visible in pcap ✓
[Remote host]  print("DNS_TUNNEL_SENT:...") → stdout
[HTTP]         response.body → DSP host
[DSP]          parse_dns_tunnel_session_sent_fqdns → ∅ (no markers)
[DSP]          dns_tunnel_query_sent events → none
[DSP]          queries_sent=0, validation FAIL
```

**Not speculation:** codified in `_execute_dns_tunnel` lines 584–617 and `test_dns_tunnel_dispatch_without_sendto_emits_no_query_sent`.

---

## 8. Fix Plan (Allowed Changes Only)

### Principles

- Do **not** inflate `queries_sent` from HTTP success alone  
- Do **not** relax validation thresholds  
- Record events only for sends evidenced by **recoverable marker output**  
- Align marker transport with proven discovery pattern  

### Implementation

1. **File-backed marker collection** — remote script appends `DNS_TUNNEL_SENT:` lines to `/tmp/.dsp-{run}-dns-tunnel-{target}.sent`, shell pipeline `cat`s file after session (same pattern as TCP discovery probes).  
2. **HTML normalization** — parse `normalize_webshell_command_output(raw_output)` before marker extraction.  
3. **`max_chunks` parity** — pass plan `max_chunks` into remote script; add `max_chunks: 100` to `standard` volume profile for live runs (operational cap, not validation weakening).  
4. **Explicit flush** — write markers with file `close()` per line (durable without relying on stdout buffer).  

### Files to change

| File | Change |
|------|--------|
| `dsp/execution/remote/command/shell.py` | Marker file path, pipeline, max_chunks in remote script |
| `dsp/execution/remote/command/execute.py` | Normalize stdout; pass run_id/max_chunks to evidence builder |
| `dsp/protocols/dns/volume_profiles.py` | `max_chunks: 100` in `standard` profile |
| `tests/execution/test_command_execute_validation_events.py` | HTML-wrapped marker parse regression |
| `tests/execution/test_dns_tunnel_webshell_session.py` | File-marker pipeline assertions |

---

## 9. Verification Checklist

| Check | Method |
|-------|--------|
| Unit tests | `pytest tests/execution/test_dns_tunnel_webshell_session.py tests/execution/test_command_execute_validation_events.py tests/protocols/dns/test_tunnel.py` |
| Marker parse | Mock provider returns file-cat output with `DNS_TUNNEL_SENT:` lines |
| Event Store | `dns_tunnel_query_sent` count > 0 when markers present |
| Traffic summary | `queries_sent` matches event count |
| Validation | `dns_tunnel` success with ≥1 sent event |
| Live re-run | pcap idx-* + DSP `queries_sent` > 0 + validation PASS |

---

## 10. Expected Post-Fix Run Signature

```
dns_tunnel:
  packets observed:  ≥1 idx-* UDP/53 (pcap)
  events recorded:   ≥1 dns_tunnel_query_sent (status=sent)
  queries_sent:      matches event count
  validation:        PASS (thresholds met)
```

Pcap remains the wire-truth cross-check; DSP metrics remain Event-Store-truth cross-check. Both should align when marker transport is reliable.
