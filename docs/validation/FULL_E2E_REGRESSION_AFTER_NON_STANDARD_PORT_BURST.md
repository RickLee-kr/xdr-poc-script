# Full E2E Regression After Non-Standard Port Burst

**Branch / tag:** `release/v1.4.0-rc` @ `6865db4` (tag `v1.4.0`)  
**Validation date:** 2026-06-18 (UTC)  
**DSP version:** 1.4.0  
**Enhancement under test:** Non-Standard Port Burst (`http_followup` internal phase)  
**Code changes during validation:** None (verification only)

Machine-readable run artifacts:

- JSP: [`../../lab/jsp-real/reports/validation-results-20260618T101620Z.json`](../../lab/jsp-real/reports/validation-results-20260618T101620Z.json)
- PHP: [`../../lab/php-real/reports/validation-results-20260618T102614Z.json`](../../lab/php-real/reports/validation-results-20260618T102614Z.json)
- Prior burst design note: [`NON_STANDARD_PORT_BURST_REPORT.md`](NON_STANDARD_PORT_BURST_REPORT.md)

---

## Test Summary

| Suite | Command | Result | Duration |
|-------|---------|--------|----------|
| Full pytest | `pytest tests/` | **1045 passed** | 7m 21s |
| `tests/e2e` | `pytest tests/e2e/` | **16 passed** | 18s |
| `tests/execution` | `pytest tests/execution/` | **526 passed** | 9s |
| JSP Real Runtime | `lab/jsp-real/validate_jsp_e2e.py` | **10 / 10 scenarios** | ~9m 46s |
| PHP Real Runtime | `lab/php-real/validate_php_e2e.py` | **10 / 10 scenarios** | ~9m 47s |

**Environment**

| Item | Value |
|------|-------|
| DSP host | `datarelay` (`/home/aella/xdr-poc-script`) |
| Remote execution host | `victim-linux` (`10.10.10.20`) |
| JSP webshell | `http://10.10.10.20:8080/shell.jsp` (probe: `labuser`) |
| PHP webshell | `http://10.10.10.20/shell.php` (probe: `www-data`) |
| Target network | `10.10.10.0/24` |
| Remote work dir | `/tmp/dsp` |

**Success criteria:** Event generation, Event Store (`events.db`), evidence artifacts (`report.md`, `validation.json`, `traffic_summary.json`), RunManager completion — **no detection/alert evaluation**.

---

## JSP Result Matrix

| Scenario | Mode | Exit | Run ID | events.jsonl | events.db | report.md | validation.json | traffic_summary.json | Events (lines) | RunManager |
|----------|------|------|--------|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| `http_followup` | bundle | 0 | `20260618_b49a53` | ✓ | ✓ | ✓ | ✓ | ✓ | 152 | ✓ |
| `sql_injection` | bundle | 0 | `20260618_34165d` | ✓ | ✓ | ✓ | ✓ | ✓ | 22 | ✓ |
| `ssh_failure` | bundle | 1 | `20260618_28f7f9` | ✓ | ✓ | ✓ | ✓ | ✓ | 302 | ✓ |
| `ldap_enumeration` | remote CLI | 0 | `20260618_eed176` | ✓ | ✓ | ✓ | ✓ | ✓ | 31 | ✓ |
| `kerberos_failure` | remote CLI | 0 | `20260618_bc98de` | ✓ | ✓ | ✓ | ✓ | ✓ | 45 | ✓ |
| `smb_login_failure` | remote CLI | 1 | `20260618_6f7480` | ✓ | ✓ | ✓ | ✓ | ✓ | 25 | ✓ |
| `dns_tunnel` | bundle | 0 | `20260618_4b84d6` | ✓ | ✓ | ✓ | ✓ | ✓ | 302 | ✓ |
| `dga` | remote CLI | 1 | `20260618_a1ec28` | ✓ | ✓ | ✓ | ✓ | ✓ | 1595 | ✓ |
| `port_sweep` | bundle | 0 | `20260618_6912e9` | ✓ | ✓ | ✓ | ✓ | ✓ | 42 | ✓ |
| `host_behavior_check` | bundle | 0 | `20260618_fdbf21` | ✓ | ✓ | ✓ | ✓ | ✓ | 50 | ✓ |

**JSP artifact gate:** 10 / 10 PASS  
**Host behavior EDR lifecycle (JSP):** all six events present (`started`, `command_dispatched`, `eicar_*`, `completed`)

---

## PHP Result Matrix

| Scenario | Mode | Exit | Run ID | events.jsonl | events.db | report.md | validation.json | traffic_summary.json | Events (lines) | RunManager |
|----------|------|------|--------|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| `http_followup` | bundle | 0 | `20260618_b2c659` | ✓ | ✓ | ✓ | ✓ | ✓ | 228 | ✓ |
| `sql_injection` | bundle | 0 | `20260618_54dc75` | ✓ | ✓ | ✓ | ✓ | ✓ | 22 | ✓ |
| `ssh_failure` | bundle | 1 | `20260618_6c112d` | ✓ | ✓ | ✓ | ✓ | ✓ | 302 | ✓ |
| `ldap_enumeration` | remote CLI | 0 | `20260618_7a64cd` | ✓ | ✓ | ✓ | ✓ | ✓ | 31 | ✓ |
| `kerberos_failure` | remote CLI | 0 | `20260618_a82cf2` | ✓ | ✓ | ✓ | ✓ | ✓ | 45 | ✓ |
| `smb_login_failure` | remote CLI | 1 | `20260618_ef6a28` | ✓ | ✓ | ✓ | ✓ | ✓ | 25 | ✓ |
| `dns_tunnel` | bundle | 0 | `20260618_f2e364` | ✓ | ✓ | ✓ | ✓ | ✓ | 302 | ✓ |
| `dga` | remote CLI | 1 | `20260618_95c858` | ✓ | ✓ | ✓ | ✓ | ✓ | 1595 | ✓ |
| `port_sweep` | bundle | 0 | `20260618_f054d7` | ✓ | ✓ | ✓ | ✓ | ✓ | 42 | ✓ |
| `host_behavior_check` | bundle | 0 | `20260618_c1e95a` | ✓ | ✓ | ✓ | ✓ | ✓ | 50 | ✓ |

**PHP artifact gate:** 10 / 10 PASS (`release_ready: true`)  
**Host behavior EDR lifecycle (PHP):** all six events present

---

## Scenario Result Matrix

Cross-cutting checks across all 20 real-runtime runs (JSP + PHP × 10 scenarios):

| Check | JSP | PHP | Notes |
|-------|:---:|:---:|-------|
| `events.jsonl` created | 10/10 | 10/10 | |
| Event Store (`events.db`) populated | 10/10 | 10/10 | `http_followup` stores burst rows (JSP: 120, PHP: 196) |
| `report.md` created | 10/10 | 10/10 | |
| `validation.json` created | 10/10 | 10/10 | Burst metrics in `http_followup` validation |
| `traffic_summary.json` created | 10/10 | 10/10 | |
| RunManager completed (exit 0 or 1) | 10/10 | 10/10 | Exit 1 = partial validation (expected for live auth/DGA paths) |

---

## Non-Standard Port Burst Verification

### Event isolation (no cross-scenario leakage)

| Scenario | JSP burst events | PHP burst events | Wrong-scenario burst |
|----------|-----------------:|-----------------:|:---:|
| `http_followup` | **120** | **196** | 0 |
| `sql_injection` | 0 | 0 | 0 |
| `ssh_failure` | 0 | 0 | 0 |
| `ldap_enumeration` | 0 | 0 | 0 |
| `kerberos_failure` | 0 | 0 | 0 |
| `smb_login_failure` | 0 | 0 | 0 |
| `dns_tunnel` | 0 | 0 | 0 |
| `dga` | 0 | 0 | 0 |
| `port_sweep` | 0 | 0 | 0 |
| `host_behavior_check` | 0 | 0 | 0 |

**Result:** Burst events appear **only** in `http_followup`. **PASS**

### `http_followup` burst content

| Item | JSP | PHP |
|------|-----|-----|
| `non_standard_port_burst_started` | 1 | 1 |
| `non_standard_port_connection_attempt` | 59 | 97 |
| `non_standard_port_connection_success` | 59 | 97 |
| `non_standard_port_connection_failure` | 0 | 0 |
| `non_standard_port_burst_completed` | 1 | 1 |
| Ports (traffic_summary) | 8088, 8443, 8888, 9000, 9001, 9443 | same |
| `report.md` burst section | ✓ | ✓ |
| `validation.json` burst metrics | ✓ (59/59/0) | ✓ (97/97/0) |

### Internal phase ordering within `http_followup`

Verified from `events.jsonl` event index order:

```
http_followup_started
  → URL scan events (through index 29)
  → non_standard_port_burst_started (index 31)
  → non_standard_port_connection_* events
  → non_standard_port_burst_completed
  → http_followup_completed
```

**JSP:** burst after URL scan ✓, burst before `http_followup_completed` ✓  
**PHP:** burst after URL scan ✓, burst before `http_followup_completed` ✓

### Scenario execution order (unchanged)

**HTTP Follow-up → SQL Injection** (webshell host attack chain):

| Verification | Result |
|--------------|--------|
| `DISCOVERY_FIRST_SCENARIO_ORDER` | `http_followup` → `sql_injection` → … |
| `test_normal_profile_discovery_first_order` | PASS |
| `test_local_and_webshell_share_scenario_order_for_all_profiles` | PASS |
| Real-runtime validator run order | `http_followup` executed before `sql_injection` (both families) |

**Webshell Host Attack → Host Behavior Check → Internal Recon:**

| Step | Position in `DISCOVERY_FIRST_SCENARIO_ORDER` |
|------|-----------------------------------------------|
| Webshell host attack (`http_followup`, `sql_injection`) | indices 0–1 |
| `host_behavior_check` | index 2 (after `sql_injection`) |
| Internal recon (`port_sweep`) | index 9 (after identity/DNS scenarios) |
| `test_host_behavior_check_e2e` (10 tests) | PASS |

**Result:** Discovery-first ordering preserved. **PASS**

---

## Regression Findings

| Severity | Finding | Impact on gate |
|----------|---------|----------------|
| Info | Exit code **1** on `ssh_failure`, `smb_login_failure`, `dga` (JSP + PHP) | **None** — partial live validation; all artifacts and events still produced |
| Info | Remote bundle SSH inventory returned empty during validator `_remote_bundle_status()` | **None** — local artifact collection succeeded for all bundle scenarios |
| Info | PHP environment probe via SSH returned `unknown` (validator SSH metadata only) | **None** — webshell probe and all scenario runs succeeded |
| Info | Burst attempt counts vary run-to-run (JSP 59, PHP 97) within configured 50–200 range | **None** — expected randomized burst sizing |
| None | Cross-scenario burst leakage | Not observed |
| None | pytest / e2e / execution regressions | Not observed |
| None | Missing evidence artifacts | Not observed |
| None | Scenario order regression | Not observed |

**No blocking regressions identified.**

---

## Final Verdict

# PASS

Non-Standard Port Burst integrates into `http_followup` without breaking the `release/v1.4.0` E2E baseline:

- **1045** unit/integration tests pass (including e2e and execution suites).
- **JSP** and **PHP** real-runtime matrices: **10 / 10** scenarios each produce full evidence exports and Event Store data.
- Burst events, reporting, validation metrics, and traffic summary appear **only** in `http_followup`.
- HTTP Follow-up → SQL Injection and Webshell Host Attack → Host Behavior Check → Internal Recon ordering remain intact.

---

*Generated after full regression validation on `victim-linux` (10.10.10.20). No source code was modified during this run.*
