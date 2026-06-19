# Rare Protocol Activity — RTSP Failure Audit

**Audit date:** 2026-06-19 (UTC)  
**Scope:** RTSP probe failure in `rare_protocol_activity` — code review only, no changes.  
**Reference run:** Local provider `20260618_3e74f2` (`docs/validation/FULL_REGRESSION_AFTER_OPERATIONAL_VISIBILITY.md`)

---

## Observed Result

| Protocol | attempts | success | failed | outcome |
|----------|----------|---------|--------|---------|
| TELNET | 1 | 0 | 1 | connection refused |
| RTSP | 1 | 0 | 1 | connection refused |
| SIP | 1 | 1 | 0 | request sent |
| RTP | 1 | 1 | 0 | packet sent |

User-reported summary: `success=3`, `failed=1` with **RTSP only failing** in their environment (TELNET may have succeeded or been absent depending on discovery state).

---

## Code Path Review

### Probe planning (`dsp/protocols/rare/attempts.py`)

- RTSP is probed on **TCP port 554** (`RARE_PROTOCOL_PORTS["RTSP"] = 554`).
- Discovery-first: if port 554 is not in discovery results, the planner falls back to the **execution host** (webshell host / `10.10.10.20`).
- One probe per protocol is planned in the normal profile (`planned=4`).

### RTSP client (`dsp/protocols/rare/client.py` — `_probe_rtsp`)

1. Opens TCP connection to `(host, 554)` with configured timeout (default 3.0s).
2. Sends `OPTIONS` then `DESCRIBE` RTSP/1.0 requests on the same socket.
3. Collects response status codes if data is received before timeout.
4. On `OSError` (including `ConnectionRefusedError`), returns `success=False` with outcome `connectionrefusederror` (lowercased exception name).

### Executor outcome mapping (`scenarios/rare_protocol_activity/executor.py`)

- `success=True` when outcome is `response_received` or `request_sent` (RTSP with no response still counts as success if TCP connect succeeded).
- `success=False` when TCP connect fails → logged as `rare_protocol_probe_failure` with status `connection_refused`.

---

## Root Cause Determination

**Verdict: environment / target port absence — not an implementation defect.**

Evidence:

1. **Failure mode matches closed port:** Regression run shows RTSP outcome `refused` with `success=0`. This is produced only when `socket.create_connection((host, 554))` raises `ConnectionRefusedError` — i.e., no process is listening on TCP/554 at the probe target.
2. **Implementation is consistent with other TCP probes:** TELNET (port 23) fails identically when the port is closed. SIP/RTP succeed because UDP sendto to 5060/5004 does not require an active listener (fire-and-forget semantics).
3. **No RTSP-specific logic bug found:** Request formatting (`OPTIONS` / `DESCRIBE`, CSeq, User-Agent) follows standard RTSP probe patterns. There is no incorrect port mapping, transport mismatch, or missing fallback in the code path.
4. **Discovery fallback is working as designed:** When RTSP is not discovered, the probe targets the execution host — which typically does **not** run an RTSP server on 554 in the lab (`victim-linux` / `10.10.10.20`).

---

## Why RTSP Fails While Others Succeed

| Protocol | Transport | Port | Listener required for "success"? |
|----------|-----------|------|----------------------------------|
| TELNET | TCP | 23 | Yes — connect must succeed |
| RTSP | TCP | 554 | Yes — connect must succeed |
| SIP | UDP+TCP | 5060 | No for UDP leg — packets sent = success |
| RTP | UDP | 5004 | No — UDP packets sent = success |

RTSP and TELNET require an **open TCP listener**. In the lab, neither port 23 nor 554 is typically exposed on the execution host. RTSP failure is **expected operational behavior** unless discovery finds a host with TCP/554 open or an RTSP service is deployed for testing.

---

## Recommendations (informational — no code change requested)

1. **For detection validation:** Ensure an RTSP listener (e.g., `rtsp-simple-server`, `vlc`, or lab media server) is running on a discovered host:554 if RTSP success is required.
2. **For operational reporting:** Current OV correctly surfaces `failed=1` / `refused` — this is accurate telemetry, not a scenario bug.
3. **Optional future enhancement (out of scope):** Document in runbook that RTSP/TELNET TCP probes require discovered endpoints; UDP protocols (SIP/RTP) succeed without listeners.

---

## Final Verdict

# RTSP failure = expected (port 554 not listening)

No code change required. The probe implementation is correct; the failure reflects the absence of an RTSP service at the selected target.
