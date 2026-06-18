# Non-Standard Port Burst Report

**Branch / tag:** `release/v1.4.0-rc` (tag `v1.4.0`)  
**Enhancement date:** 2026-06-18 (UTC)  
**Scope:** `http_followup` scenario extension only — JSP + PHP real webshell E2E  
**DSP version:** 1.4.0

E2E artifacts: [`../../lab/validation-runs/non-std-port-burst-20260618T095214Z/`](../../lab/validation-runs/non-std-port-burst-20260618T095214Z/)

---

## Design

Non-Standard Port Burst is an **internal phase of `http_followup`**, not a separate scenario.

### Execution order (unchanged)

```
HTTP Follow-up (URL scan)
  → Non-Standard Port Burst (new internal phase)
  → http_followup_completed
↓
SQL Injection (unchanged, separate scenario)
```

### Port selection

| Priority | Source |
|----------|--------|
| 1 | Discovered non-standard HTTP/HTTPS endpoints from existing `TargetSet` (excludes 80/8080) |
| 2 | Probe candidates on follow-up hosts: `8088`, `8443`, `9000`, `9001`, `9443` |

### Burst behavior

| Item | Value |
|------|-------|
| Method | HTTP GET `/` |
| User-Agent | Randomized per request (`pick_user_agent`) |
| Attempts | 50–200 (configurable: `non_standard_burst_min` / `non_standard_burst_max`) |
| Concurrency | Same as HTTP follow-up (`concurrency`, default 32) |
| Pattern goal | Application + non-standard port + connection burst (Stellar `external_non_std_port_anomaly` analogue) |

### Code touchpoints

| File | Role |
|------|------|
| `dsp/protocols/http/non_standard_port_burst.py` | Port/target selection + burst plan |
| `dsp/protocols/http/burst_executor.py` | Local burst execution + events |
| `scenarios/http_followup/executor.py` | Runs burst after URL scan, before completed |
| `dsp/execution/remote/bundle/planner.py` | Embeds burst plan in manifest |
| `dsp/execution/remote/bundle/assets/run_scenario.py` | Remote burst via curl |
| `dsp/protocols/http/events.py` | New burst event builders |
| `dsp/runtime/traffic_summary.py` | Burst section in scenario summary |
| `dsp/protocols/http/reporting.py` | Burst section in `report.md` |
| `dsp/protocols/http/validation.py` | Burst traffic metrics |

**Not changed:** Discovery Engine, webshell execution provider, scenario ordering, ASPX/Windows paths.

---

## Event Model

| Event | When |
|-------|------|
| `non_standard_port_burst_started` | Burst phase begins |
| `non_standard_port_connection_attempt` | Each GET dispatched |
| `non_standard_port_connection_success` | Response received with status &lt; 500 |
| `non_standard_port_connection_failure` | Timeout, connection error, or status ≥ 500 |
| `non_standard_port_burst_completed` | Burst phase ends (includes attempts/success/failure counts) |

Burst summary is also embedded in `http_followup_completed` evidence as `non_standard_port_burst`.

---

## JSP Validation

| Item | Value |
|------|-------|
| **URL** | `http://10.10.10.20:8080/shell.jsp` |
| **Run ID** | `20260618_f86921` |
| **Exit** | 0 |
| **Artifacts** | `events.jsonl`, `events.db`, `report.md`, `validation.json`, `traffic_summary.json` ✓ |

### Burst metrics (JSP)

| Metric | Value |
|--------|-------|
| Ports | 8088, 8443, 8888, 9000, 9001, 9443 |
| Attempts | 144 |
| Success | 144 |
| Failure | 0 |
| Validation | `success` |

### Events (JSP)

- `non_standard_port_burst_started`: 1
- `non_standard_port_connection_attempt`: 144
- `non_standard_port_connection_success`: 144
- `non_standard_port_burst_completed`: 1

`report.md` contains **Non-Standard Port Burst** section.

---

## PHP Validation

| Item | Value |
|------|-------|
| **URL** | `http://10.10.10.20/shell.php` |
| **Run ID** | `20260618_8c02f7` |
| **Exit** | 0 |
| **Artifacts** | All evidence exports ✓ |

### Burst metrics (PHP)

| Metric | Value |
|--------|-------|
| Ports | 8088, 8443, 8888, 9000, 9001, 9443 |
| Attempts | 104 |
| Success | 104 |
| Failure | 0 |
| Validation | `success` |

### Events (PHP)

- `non_standard_port_burst_started`: 1
- `non_standard_port_connection_attempt`: 104
- `non_standard_port_connection_success`: 104
- `non_standard_port_burst_completed`: 1

---

## Safety Review

| Prohibited | Status |
|------------|--------|
| Actual attack / exploit | **Not performed** — HTTP GET only |
| Malware / C2 / persistence | **Not present** |
| Privilege escalation | **Not attempted** |
| Stellar alert validation | **Out of scope** (traffic/events only) |

Burst generates **connection traffic only** to non-standard ports using harmless GET requests with randomized User-Agents. Probe targets for undiscovered ports may fail safely (connection refused/timeout) — failures are recorded as events, not treated as detection success.

### Unit tests

```
pytest tests/protocols/http/test_non_standard_port_burst.py \
       tests/protocols/http/ \
       tests/scenarios/test_http_followup_e2e.py
→ 63 passed (HTTP suite)
```

---

## Final Result

**PASS**

`http_followup` now includes a Non-Standard Port Burst phase that generates high-volume HTTP connections to non-standard ports with randomized User-Agents. JSP and PHP real-environment E2E runs produce full evidence exports, burst events, validation metrics, and reporting sections — without creating a new scenario or modifying Discovery.

---

*Generated after implementation + live E2E on `victim-linux` (10.10.10.20).*
