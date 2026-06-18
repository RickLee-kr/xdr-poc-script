# Rare Protocol Activity Report

**Branch / tag:** `release/v1.4.0-rc` @ `6865db4` (tag `v1.4.0`)  
**Validation date:** 2026-06-18 (UTC)  
**DSP version:** 1.4.0  
**Stellar target:** Uncommon Application Anomaly (XDR App Anomaly / XT2003)  
**Scenario ID:** `rare_protocol_activity`

E2E artifacts:

- Local: [`../../lab/validation-runs/rare-protocol-local-20260618T110112Z/20260618_2ee086/`](../../lab/validation-runs/rare-protocol-local-20260618T110112Z/20260618_2ee086/)
- JSP: [`../../lab/validation-runs/rare-protocol-jsp-20260618T110207Z/20260618_4ce87b/`](../../lab/validation-runs/rare-protocol-jsp-20260618T110207Z/20260618_4ce87b/)
- PHP: [`../../lab/validation-runs/rare-protocol-php-20260618T110211Z/20260618_cf8ccf/`](../../lab/validation-runs/rare-protocol-php-20260618T110211Z/20260618_cf8ccf/)

---

## Design

`rare_protocol_activity` generates **safe rare-protocol probe traffic** from the execution vantage point to help lab operators reproduce Stellar Cyber **Uncommon Application Anomaly** (XT2003) class signals.

### Execution vantage

| Provider | Traffic origin |
|----------|----------------|
| **Local** | DSP runner host |
| **Webshell (JSP / PHP)** | Webshell host (`initial_compromise_endpoint` from `--webshell-url`) |

Internal lateral movement is **not** in scope — probes use discovery endpoints for rare ports first, then a **single-host probe fallback** (webshell host or configured `probe_hosts`).

### Internal phase flow

```
rare_protocol_activity_started
  → per-protocol probes (TELNET / RTSP / SIP / RTP)
  → rare_protocol_probe_attempt
  → rare_protocol_probe_success | rare_protocol_probe_failure
  → rare_protocol_activity_completed
```

### Code touchpoints

| File | Role |
|------|------|
| `dsp/protocols/rare/attempts.py` | Discovery-first target planning |
| `dsp/protocols/rare/client.py` | Safe probe client (no sessions/auth/media) |
| `dsp/protocols/rare/events.py` | Event builders |
| `scenarios/rare_protocol_activity/` | Scenario plugin (manifest, scenario, executor) |
| `dsp/execution/remote/bundle/planner.py` | Remote bundle plan |
| `dsp/execution/remote/bundle/assets/run_scenario.py` | Self-contained remote runner |
| `dsp/runtime/traffic_summary.py` | `traffic_summary.json` section |
| `dsp/reporting/engine.py` | `report.md` section |

---

## Protocol Coverage

| Protocol | Transport | Port | Behavior |
|----------|-----------|------|----------|
| **TELNET** | TCP | 23 | Connect, read banner (if any), close |
| **RTSP** | TCP | 554 | `OPTIONS` + `DESCRIBE`, read response, close |
| **SIP** | UDP + TCP | 5060 | Minimal `OPTIONS` + `REGISTER` (no call, no auth) |
| **RTP** | UDP | 5004 | Small burst of RTP-header test packets (no media stream) |

Discovery integration: if ports `23`, `554`, `5060`, or `5004` appear in `TargetSet.service_endpoints` / discovery metadata, those endpoints are probed first. Otherwise safe probe fallback to execution host.

---

## Local Validation

| Item | Value |
|------|-------|
| **Command** | `dsp run --scenarios rare_protocol_activity --execution-provider local --target-net 10.10.10.0/24` |
| **Run ID** | `20260618_2ee086` |
| **Exit** | 0 |
| **Validation** | `success` |

### Metrics (Local)

| Metric | Value |
|--------|------:|
| Attempts | 4 |
| Success | 2 |
| Failure | 2 |
| Protocols | TELNET, RTSP, SIP, RTP |

### Artifacts (Local)

| File | Present |
|------|:---:|
| `events.jsonl` | ✓ |
| `events.db` | ✓ |
| `report.md` | ✓ |
| `validation.json` | ✓ |
| `traffic_summary.json` | ✓ |

`report.md` contains **Rare Protocol Activity** section.

---

## JSP Validation

| Item | Value |
|------|-------|
| **URL** | `http://10.10.10.20:8080/shell.jsp` |
| **Run ID** | `20260618_4ce87b` |
| **Mode** | bundle (remote `run_scenario.py`) |
| **Exit** | 0 |
| **Validation** | `success` |

### Metrics (JSP)

| Metric | Value |
|--------|------:|
| Attempts | 4 |
| Success | 1 |
| Failure | 3 |
| Protocols | TELNET, RTSP, SIP, RTP |

Probe target host: `10.10.10.20` (webshell host). Failures are expected when rare services are not listening — traffic and events still generated.

### Artifacts (JSP)

All five evidence exports present.

---

## PHP Validation

| Item | Value |
|------|-------|
| **URL** | `http://10.10.10.20/shell.php` |
| **Run ID** | `20260618_cf8ccf` |
| **Mode** | bundle |
| **Exit** | 0 |
| **Validation** | `success` |

### Metrics (PHP)

| Metric | Value |
|--------|------:|
| Attempts | 4 |
| Success | 1 |
| Failure | 3 |
| Protocols | TELNET, RTSP, SIP, RTP |

### Artifacts (PHP)

All five evidence exports present.

---

## Safety Review

| Prohibited | Status |
|------------|--------|
| TeamViewer / AnyDesk / VNC | **Not used** |
| Real remote-control sessions | **Not performed** |
| SIP calls / RTP media streams | **Not performed** |
| Credentials / malware / persistence | **Not present** |
| Internal host attack expansion | **Not in scope** — single-host probe fallback |

Probes are **connection-level only**: banner read, protocol handshake requests, or UDP test packets. Response success is **not** required for DSP validation — only traffic generation and event emission.

### Unit / regression tests

```
pytest tests/protocols/rare/ tests/scenarios/test_rare_protocol_activity_e2e.py
→ 9 passed

pytest tests/ (full suite)
→ 1054 passed
```

---

## Final Result

# PASS

`rare_protocol_activity` is implemented and validated on **Local**, **JSP**, and **PHP** execution paths. All runs produce full evidence exports with TELNET, RTSP, SIP, and RTP probe traffic suitable for Stellar Cyber Uncommon Application Anomaly lab reproduction — without remote-control software, real sessions, or media streams.

---

*Generated after implementation + live E2E on `victim-linux` (10.10.10.20) and DSP local host.*
