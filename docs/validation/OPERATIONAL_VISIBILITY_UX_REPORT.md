# Operational Visibility UX Report

**Version:** 1.4.1+  
**Date:** 2026-06-18  
**Scope:** Execution plan vs actual explanation only — no detection/attack/alert validation.

**Final verdict: PASS**

---

## 1. Changed files

| File | Change |
|------|--------|
| `dsp/reporting/operational_visibility.py` | **New** — reconciliation, skip reasons, discovery/selection trace, rare protocol & host behavior summaries |
| `dsp/runner/run_manager.py` | Exit code fix, per-scenario reconciliation emit, `operational_visibility.json` |
| `dsp/runner/console_output.py` | Planned/actual/skip console format |
| `dsp/reporting/engine.py` | `report.md` Operational Visibility sections |
| `dsp/validation/engine.py` | LDAP/Kerberos/DNS skip events |
| `dsp/discovery/legacy_bash.py` | LDAP (389), Kerberos (88) discovery ports |
| `scenarios/http_followup/executor.py` | `execution_status` / `execution_reason` on completed |
| `scenarios/sql_injection/executor.py` | Same reconciliation evidence |
| `scenarios/smb_login_failure/executor.py` | `no_smb_service_discovered` skip reason |
| `scenarios/ldap_enumeration/executor.py` | Discovery-first selection + skip |
| `scenarios/kerberos_failure/executor.py` | Discovery-first selection + skip |
| `scenarios/dns_tunnel/executor.py` | `dns_hosts` preference + skip |
| `dsp/protocols/dns/tunnel.py` | Prefer `dns_hosts` bucket |
| `tests/reporting/test_operational_visibility.py` | **New** unit tests |
| `tests/scenarios/test_dns_tunnel_target_selection.py` | Updated for dns_hosts preference |

---

## 2. Scenario Reconciliation design

Event Store evidence drives reconciliation — no stdout parsing.

Per scenario the system emits:

```text
planned=<N>
executed=<M>
execution_ratio=<pct>%
execution_status=full|partial|skipped
execution_reason=<code>
```

| `execution_status` | Meaning |
|--------------------|---------|
| `full` | `actual >= planned` |
| `partial` | `0 < actual < planned` |
| `skipped` | No execution (discovery miss, probe miss, etc.) |

| `execution_reason` (examples) | Meaning |
|-------------------------------|---------|
| `completed` | Full execution |
| `scenario_cap` | Profile/volume cap reduced actual below plan |
| `response_limit` | Timeouts / response limits during HTTP execution |
| `target_unavailable` | Planned work but zero units sent |
| `no_smb_service_discovered` | No SMB hosts in discovery |
| `no_ldap_service_discovered` | No LDAP (389) hosts |
| `no_kerberos_service_discovered` | No Kerberos (88) hosts |
| `no_dns_service_discovered` | No DNS (53) hosts |
| `no_http_service_discovered` | HTTP probe found no targets |

HTTP/SQL executors write `execution_status` / `execution_reason` into `*_completed` events via `derive_execution_reconciliation()`.

---

## 3. Skip Reason Framework design

Skip events use explicit `reason` codes in Event Store:

| Scenario | Skip event | Example reason |
|----------|------------|----------------|
| SMB | `smb_scenario_skipped` | `no_smb_service_discovered` |
| LDAP | `ldap_enumeration_skipped` | `no_ldap_service_discovered` |
| Kerberos | `kerberos_failure_skipped` | `no_kerberos_service_discovered` |
| DNS Tunnel | `dns_tunnel_skipped` | `no_dns_service_discovered` |
| HTTP | `http_followup_skipped` | `no_http_service_discovered` |
| Host Behavior | `host_behavior_check_skipped` | `no_webshell_target_host` |

Console skip output (never `attempts=0` alone):

```text
SMB Login Failure

status=skipped
reason=no_smb_service_discovered
discovered_smb_hosts=0
```

`ValidationEngine` marks skipped scenarios as `SKIPPED` (not `FAILED`).

---

## 4. Exit Code root cause

**Before:** `compute_exit_code()` returned `1` when any scenario had `ValidationDecision.PARTIAL` (e.g. HTTP request count below success threshold but above partial threshold). RunManager completed normally — events, `report.md`, `validation.json` all produced — yet CLI exited `1`.

**After:** Exit `0` when RunManager completes unless `FAILED` (thresholds_not_met) or `CODE_FAILURE`. `PARTIAL` and `SKIPPED` are operational outcomes, not run failures.

| Code | Condition |
|------|-----------|
| `0` | Normal completion (incl. PARTIAL/SKIPPED mix) |
| `1` | `FAILED` validation |
| `2` | `CODE_FAILURE` |

---

## 5. Sample execution log

```text
Discovery Summary

HTTP hosts=1
SSH hosts=0
LDAP hosts=0
SMB hosts=0
Kerberos hosts=0
DNS hosts=0

Scenario Selection

HTTP Follow-up
selected
reason=http_service_discovered

SQL Injection
skipped
reason=no_http_service_discovered

...

HTTP Follow-up

planned=40
executed=40
execution_ratio=100.0%
execution_status=full
execution_reason=completed

Run Completed
Events Generated: 2643
```

---

## 6. report.md excerpt

```markdown
## Operational Visibility

### Discovery Summary
HTTP hosts=1
...

### Scenario Selection Trace
HTTP Follow-up
selected
reason=http_service_discovered

### Planned vs Actual Summary
HTTP Follow-up
planned=40
actual=40
execution_status=full
execution_reason=completed
```

Artifact: `operational_visibility.json` in run directory.

---

## 7. pytest results

```text
tests/reporting/test_operational_visibility.py — 6 passed
tests/validation/test_path_equality.py — passed
tests/runtime/test_parity_v131.py — passed
tests/scenarios/test_dns_tunnel_target_selection.py — passed
```

Live run: `dsp run --profile low --target-net 127.0.0.1/32` → **exit 0**

---

## 8. Charter / WBS alignment

- Event Store = sole source of truth for reconciliation
- No detection success, attack success, alert, case, correlation, or scoring
- No stdout/stderr parsing or grep validation
- Discovery-first: LDAP/Kerberos/DNS follow discovery service buckets
- Explains **why executed / why skipped / why planned ≠ actual** only
