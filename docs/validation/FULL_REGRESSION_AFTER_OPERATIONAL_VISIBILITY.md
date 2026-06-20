# Full Regression After Operational Visibility

**Branch:** `release/v1.4.0` @ `822c055`  
**Validation date:** 2026-06-18 (UTC)  
**DSP version:** 1.4.1  
**Enhancement under test:** Operational Visibility (scenario reconciliation, skip reasons, exit code fix)  
**Code changes during validation:** None (verification only)

Machine-readable artifacts:

- Local runs: [`../../lab/validation-runs/full-regression-ov-20260618T134310Z/`](../../lab/validation-runs/full-regression-ov-20260618T134310Z/)
- JSP: [`../../lab/jsp-real/reports/validation-results-20260618T134339Z.json`](../../lab/jsp-real/reports/validation-results-20260618T134339Z.json)
- PHP: [`../../lab/php-real/reports/validation-results-20260618T135422Z.json`](../../lab/php-real/reports/validation-results-20260618T135422Z.json)
- Prior OV design note: [`OPERATIONAL_VISIBILITY_UX_REPORT.md`](OPERATIONAL_VISIBILITY_UX_REPORT.md)

---

## Test Summary

| Suite | Command | Result | Duration |
|-------|---------|--------|----------|
| Full pytest | `pytest tests/` | **1053 passed, 7 failed** | 8m 43s |
| `tests/e2e` | `pytest tests/e2e/` | **16 passed** | 15s |
| `tests/execution` | `pytest tests/execution/` | **526 passed** | 9s |
| OV unit tests | `pytest tests/reporting/test_operational_visibility.py` | **6 passed** | <1s |
| Local Provider | 11 scenarios × `dsp run --execution-provider local` | **11 / 11 artifact gate** | ~10m |
| JSP Real Runtime | `lab/jsp-real/validate_jsp_e2e.py` | **10 / 10 scenarios** | ~11m |
| PHP Real Runtime | `lab/php-real/validate_php_e2e.py` | **10 / 10 scenarios** (`release_ready: true`) | ~11m |
| JSP `rare_protocol_activity` | extra webshell run | **exit 0**, OV present | ~1m |
| PHP `rare_protocol_activity` | extra webshell run | **exit 0**, OV present | ~1m |

**Environment**

| Item | Value |
|------|-------|
| DSP host | `datarelay` (`/home/aella/xdr-poc-script`) |
| Remote execution host | `victim-linux` (`10.10.10.20`) |
| JSP webshell | `http://10.10.10.20:8080/shell.jsp` (probe: `labuser`) |
| PHP webshell | `http://10.10.10.20/shell.php` (probe: `www-data`) |
| Target network | `10.10.10.0/24` |
| Remote work dir | `/tmp/dsp` |

---

## Local Provider Matrix

All 11 scenarios executed against `10.10.10.0/24`. Artifact root: `lab/validation-runs/full-regression-ov-20260618T134310Z/local-runs/`.

| Scenario | Exit | Run ID | events.jsonl | events.db | report.md | validation.json | traffic_summary.json | operational_visibility.json |
|----------|------|--------|:---:|:---:|:---:|:---:|:---:|:---:|
| `http_followup` | 0 | `20260618_f047a3` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| `sql_injection` | 0 | `20260618_3d277e` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| `ssh_failure` | 0 | `20260618_4e904a` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| `ldap_enumeration` | 0 | `20260618_f76b61` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| `kerberos_failure` | 0 | `20260618_3c21ba` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| `smb_login_failure` | 0 | `20260618_323d6c` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| `dns_tunnel` | 0 | `20260618_943311` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| `dga` | 1 | `20260618_676d0b` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| `port_sweep` | 0 | `20260618_8aecb1` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| `host_behavior_check` | 0 | `20260618_e2ea9d` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| `rare_protocol_activity` | 0 | `20260618_3e74f2` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |

**Local artifact gate:** 11 / 11 PASS (all six required files per run).

**Notes**

- `dga` exit `1`: `validation.json` decision `failed` / `thresholds_not_met` (`dga_nxdomain_observed_count=0`). Expected FAILED semantics.
- `host_behavior_check` on local provider: reconciliation `skipped` / `no_webshell_target_host` (expected without webshell target).
- Lab discovery had no LDAP/SMB/Kerberos hosts; skip paths exercised on local for SMB/LDAP/Kerberos.

---

## JSP Provider Matrix

Tomcat `shell.jsp` — `lab/jsp-real/reports/runs-20260618T134339Z/`.

| Scenario | Mode | Exit | Run ID | Core 5 artifacts | operational_visibility.json | Events (lines) |
|----------|------|------|--------|:---:|:---:|:---:|
| `http_followup` | bundle | 0 | `20260618_5e19b1` | ✓ | ✓ | 158 |
| `sql_injection` | bundle | 0 | `20260618_422594` | ✓ | ✓ | 22 |
| `ssh_failure` | bundle | 1 | `20260618_c85f0c` | ✓ | ✓ | 302 |
| `ldap_enumeration` | remote CLI | 0 | `20260618_3484ed` | ✓ | ✓ | 31 |
| `kerberos_failure` | remote CLI | 0 | `20260618_812b45` | ✓ | ✓ | 45 |
| `smb_login_failure` | remote CLI | 1 | `20260618_240ccc` | ✓ | ✓ | 25 |
| `dns_tunnel` | bundle | 0 | `20260618_5af135` | ✓ | ✓ | 302 |
| `dga` | remote CLI | 1 | `20260618_d1b175` | ✓ | ✓ | 1595 |
| `port_sweep` | bundle | 0 | `20260618_ef523d` | ✓ | ✓ | 50 |
| `host_behavior_check` | bundle | 0 | `20260618_cfdfb5` | ✓ | ✓ | 50 |
| `rare_protocol_activity` | bundle (extra) | 0 | `20260618_0e3562` | ✓ | ✓ | — |

**JSP artifact gate:** 10 / 10 PASS (`validate_jsp_e2e.py` core five files).  
**OV extension:** `operational_visibility.json` present on all 11 runs (including extra `rare_protocol_activity`).  
**Host behavior EDR lifecycle (JSP):** all six events present.

Exit `1` on `ssh_failure`, `smb_login_failure`, `dga`: `validation.json` decision `failed` / `thresholds_not_met` — consistent with live-lab partial auth/DGA thresholds, not RunManager crash.

---

## PHP Provider Matrix

Apache + PHP `shell.php` — `lab/php-real/reports/runs-20260618T135422Z/`.

| Scenario | Mode | Exit | Run ID | Core 5 artifacts | operational_visibility.json | Events (lines) |
|----------|------|------|--------|:---:|:---:|:---:|
| `http_followup` | bundle | 0 | `20260618_aba777` | ✓ | ✓ | 290 |
| `sql_injection` | bundle | 0 | `20260618_94b4a5` | ✓ | ✓ | 22 |
| `ssh_failure` | bundle | 1 | `20260618_c23ce6` | ✓ | ✓ | 302 |
| `ldap_enumeration` | remote CLI | 0 | `20260618_74e7e2` | ✓ | ✓ | 31 |
| `kerberos_failure` | remote CLI | 0 | `20260618_068e59` | ✓ | ✓ | 45 |
| `smb_login_failure` | remote CLI | 1 | `20260618_1b95f7` | ✓ | ✓ | 25 |
| `dns_tunnel` | bundle | 0 | `20260618_9265fe` | ✓ | ✓ | 302 |
| `dga` | remote CLI | 1 | `20260618_9a3168` | ✓ | ✓ | 1595 |
| `port_sweep` | bundle | 0 | `20260618_fb8e34` | ✓ | ✓ | 50 |
| `host_behavior_check` | bundle | 0 | `20260618_5b5916` | ✓ | ✓ | 50 |
| `rare_protocol_activity` | bundle (extra) | 0 | `20260618_b45de6` | ✓ | ✓ | — |

**PHP artifact gate:** 10 / 10 PASS (`release_ready: true`).  
**OV extension:** `operational_visibility.json` present on all 11 runs.  
**Host behavior EDR lifecycle (PHP):** all six events present.

---

## Operational Visibility Verification

### report.md required sections

Verified on representative runs (`http_followup` local `20260618_f047a3`, JSP `20260618_5e19b1`, `host_behavior_check` JSP `20260618_cfdfb5`, `rare_protocol_activity` local `20260618_3e74f2`):

| Section | Local (all 11) | JSP | PHP |
|---------|:---:|:---:|:---:|
| Discovery Summary | ✓ | ✓ | ✓ |
| Scenario Selection Trace | ✓ | ✓ | ✓ |
| Skip Reason Summary | ✓ | ✓ | ✓ |
| Planned vs Actual Summary | ✓ | ✓ | ✓ |
| Host Behavior Summary | ✓ (when executed) | ✓ | ✓ |

### Skip Reason verification (SMB / LDAP / Kerberos / DNS)

**Local provider** (no LDAP/SMB/Kerberos in discovery):

| Scenario | Console | reconciliation | attempts=0 only? |
|----------|---------|----------------|:---:|
| SMB | `status=skipped` `reason=no_smb_service_discovered` | `skipped` / `no_smb_service_discovered` | No — PASS |
| LDAP | `status=skipped` `reason=no_ldap_service_discovered` | `skipped` / `no_ldap_service_discovered` | No — PASS |
| Kerberos | `status=skipped` `reason=no_kerberos_service_discovered` | `skipped` / `no_kerberos_service_discovered` | No — PASS |
| DNS | executed (`full` / `completed`) — DNS host `10.10.10.10` present | N/A (not skipped) | No — PASS |

**JSP webshell** (LDAP/SMB/Kerberos absent):

| Scenario | Console skip output | Explicit reason |
|----------|---------------------|-----------------|
| LDAP | `status=skipped` | `reason=no_eligible_target` |
| SMB | `status=skipped` | `reason=target_unavailable` |

No scenario emitted `attempts=0` without `status=skipped` and `reason=` — **PASS**.

### Planned vs Actual verification

| Scenario | Local | JSP/PHP |
|----------|-------|---------|
| HTTP Follow-up | `planned=20 executed=20 ratio=100% status=full reason=completed` | present in report + OV |
| SQL Injection | `planned=20 executed=20 ratio=100% status=full reason=completed` | present |
| Rare Protocol Activity | `planned=4 executed=4 ratio=100% status=full reason=completed` | present (extra runs) |
| Host Behavior Check | skipped on local (`no_webshell_target_host`) | executed on JSP/PHP with full summary |

All five reconciliation fields (`planned`, `executed`/`actual`, `execution_ratio`, `execution_status`, `execution_reason`) present — **PASS**.

### Rare Protocol Activity verification

Local run `20260618_3e74f2` — per-protocol results in `operational_visibility.json` and `report.md`:

| Protocol | attempts | success | failed / result |
|----------|----------|---------|-----------------|
| RTP | 1 | 1 | 0 / connected |
| RTSP | 1 | 0 | 1 / refused |
| SIP | 1 | 1 | 0 / connected |
| TELNET | 1 | 0 | 1 / refused |

Lab profile probes RTP/RTSP/SIP/TELNET (not FTP/SMB/RDP/VNC in this environment). Structure matches required `attempt` / `success` / `failure` pattern — **PASS**.

### Host Behavior verification (JSP `20260618_cfdfb5`)

`Host Behavior Summary` in `report.md` and `operational_visibility.json`:

| Category | Observed |
|----------|----------|
| EICAR Variants (`eicar_test_file`) | created=5, accessed=5, deleted=5 |
| Credential Artifact Enumeration (`credential_store_access`) | attempts=4 |
| Script Drop (`script_drop`) | created=3 |
| Persistence Artifact Simulation (`persistence_simulation`) | artifacts_created=2, removed=2 |
| Archive Activity (`archive_activity`) | created=2 |

PHP host behavior run shows identical lifecycle event set — **PASS**.

### Sample report.md excerpt (local `http_followup`)

```markdown
## Operational Visibility

### Discovery Summary
HTTP hosts=2
SSH hosts=4
LDAP hosts=0
SMB hosts=0
Kerberos hosts=0
DNS hosts=1

### Scenario Selection Trace
HTTP Follow-up
selected
reason=http_service_discovered

### Skip Reason Summary
(no scenarios skipped)

### Planned vs Actual Summary
HTTP Follow-up
planned=20
actual=20
execution_ratio=100.0%
execution_status=full
execution_reason=completed
```

### Sample operational_visibility.json excerpt (local `http_followup`)

```json
{
  "discovery_summary": {
    "hosts_by_service": { "HTTP": 2, "SSH": 4, "LDAP": 0, "SMB": 0, "Kerberos": 0, "DNS": 1 }
  },
  "scenario_selection": {
    "entries": [{ "scenario_id": "http_followup", "status": "selected", "reason": "http_service_discovered" }]
  },
  "reconciliations": {
    "http_followup": {
      "planned": 20,
      "actual": 20,
      "execution_status": "full",
      "execution_reason": "completed",
      "execution_ratio_pct": 100.0
    }
  }
}
```

Full file: `lab/validation-runs/full-regression-ov-20260618T134310Z/local-runs/20260618_f047a3/operational_visibility.json`

---

## Exit Code Verification

| Condition | Expected | Observed | Result |
|-----------|----------|----------|--------|
| Normal completion (success) | 0 | Local/JSP/PHP success scenarios | PASS |
| PARTIAL validation | 0 | `test_compute_exit_code_partial_is_zero` | PASS |
| SKIPPED (discovery miss) | 0 | Local SMB/LDAP/Kerberos skipped runs | PASS |
| FAILED validation | 1 | `dga` local; JSP/PHP `ssh_failure`, `smb_login_failure`, `dga` | PASS |
| CODE_FAILURE | 2 | `test_compute_exit_code_failed_is_one`; path equality exit tests | PASS |
| Unit: SKIPPED http empty selection | 0 (new semantics) | Runtime returns 0; **test still expects 3** | Test debt |

`compute_exit_code()` behavior matches OV design: PARTIAL/SKIPPED → 0, FAILED → 1, CODE_FAILURE → 2.

---

## Regression Findings

### 1. Full pytest — 7 failures (test suite regression)

Operational Visibility changed console formatting and exit-code semantics; **six runner/console tests and one engine test were not updated**.

| Test | Failure cause |
|------|---------------|
| `tests/runner/test_activity_console.py` (3 tests) | Expect `"Port Sweep Completed"`; OV emits `"Port Sweep\n\nCompleted"` |
| `tests/runner/test_activity_detail_console.py` | Expect `"HTTP Follow-up Completed"`; OV emits split label |
| `tests/runner/test_operational_cli.py` (2 tests) | Same completed-label format; DNS Tunnel label split |
| `tests/runner/test_activity_console.py::test_selected_targets_output` | Expect `LDAP:` bucket in Selected Targets; OV discovery layout changed |
| `tests/engine/test_run_manager_http_endpoint_wiring.py::test_live_path_empty_selection_skips_without_completed` | Expect `exit_code == 3` for SKIPPED http; OV fix returns `0` |

**Runtime impact:** None observed in live runs. **CI gate impact:** `pytest tests/` fails until tests are aligned with OV UX.

### 2. No scenario / provider functional regressions observed

| Area | Status |
|------|--------|
| `tests/e2e` (16) | PASS |
| `tests/execution` (526) | PASS |
| OV unit tests (6) | PASS |
| Local 11 scenarios + artifacts | PASS |
| JSP 10 scenarios + OV | PASS |
| PHP 10 scenarios + OV | PASS |
| Event Store / evidence export | PASS |
| Non-standard port burst (http_followup) | Still present in reports |
| Host behavior real activity (JSP/PHP) | PASS |

### 3. Minor observations (non-blocking)

- `validate_jsp_e2e.py` / `validate_php_e2e.py` ARTIFACTS tuple does not list `operational_visibility.json`; file is generated on all verified runs.
- JSP/PHP `ldap_enumeration` / `smb_login_failure` console shows `no_eligible_target` / `target_unavailable` rather than `no_*_service_discovered` when webshell path runs without eligible remote targets — still explicit skip with reason.
- Lab `rare_protocol_activity` probes RTP/RTSP/SIP/TELNET per scenario manifest, not FTP/SMB/RDP/VNC.

---

## Final Verdict

# FAIL

**Rationale:** `pytest tests/` reports **7 failures** introduced by Operational Visibility console and exit-code changes without corresponding test updates. All targeted runtime validation (Local Provider 11/11, JSP 10/10, PHP 10/10, Operational Visibility artifacts, skip reasons, planned vs actual, rare protocol detail, host behavior summary) **passes**. Existing scenarios, E2E harness, and JSP/PHP real runtimes are **not functionally broken**; the failure is confined to stale unit/integration test expectations.

**Recommended follow-up (out of scope for this validation):** Update the seven failing tests to match OV console labels and SKIPPED exit `0` semantics; add `operational_visibility.json` to lab E2E ARTIFACTS checklists.
