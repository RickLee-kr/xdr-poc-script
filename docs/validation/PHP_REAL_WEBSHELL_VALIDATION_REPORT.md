# PHP Real Webshell Validation Report

**Branch:** `release/v1.4.0-rc`  
**Validation date:** 2026-06-18 (UTC)  
**Webshell family:** **PHP only** (JSP already PASS; ASPX not tested)  
**Success criteria:** Event generation, Event Store, evidence artifacts, RunManager completion — **no detection/alert evaluation**

Machine-readable results: [`../../lab/php-real/reports/validation-results-20260618T005059Z.json`](../../lab/php-real/reports/validation-results-20260618T005059Z.json)

---

## Environment

| Item | Value |
|------|-------|
| DSP host | `datarelay` (`/home/aella/xdr-poc-script`) |
| Remote execution host | `victim-linux` (`10.10.10.20`) |
| **Webshell URL** | `http://10.10.10.20/shell.php` |
| **PHP Version** | **8.3.6** (mod_php + CLI) |
| **Web Server** | Apache **2.4.58** (Ubuntu) |
| **shell.php location (remote)** | `/var/www/html/shell.php` |
| Webshell OS user | `www-data` (Apache mod_php) |
| Target network | `10.10.10.0/24` |
| Remote work dir | `/tmp/dsp` |
| DSP version | 1.4.0 (`release/v1.4.0-rc`) |

**Note:** JSP Tomcat remains on port 8080 (`shell.jsp`) — unchanged. PHP was deployed on port 80 (Apache) for this validation.

---

## Deployment summary (Phase 2)

1. Fixed victim DNS (`nameserver 8.8.8.8`) — `apt` could not resolve Ubuntu mirrors.
2. Installed `apache2`, `libapache2-mod-php`, `php-cli` on `victim-linux`.
3. Deployed minimal lab `shell.php` (cmd / multipart upload / `remote_path` download).
4. Probe: `?cmd=whoami` → `www-data`.
5. Lab prerequisite for non-bundle scenarios: `chmod o+x /home/labuser` so `www-data` can reach `dsp-platform` via `dsp-remote-scenario`.

Lab assets: `lab/php-real/` (`shell.php`, `validate_php_e2e.py`, optional `docker-compose.yml`).

---

## Scenario Results

Each scenario run individually:

```bash
dsp run --verbose --scenarios <id> \
  --execution-provider webshell --webshell-family php \
  --webshell-url http://10.10.10.20/shell.php \
  --remote-work-dir /tmp/dsp --target-net 10.10.10.0/24
```

| Scenario | Mode | Exit code | Scenario events (lines) | Artifacts¹ | RunManager² |
|----------|------|-----------|---------------------------|------------|-------------|
| `http_followup` | bundle | 0 | 32 | all ✓ | ✓ |
| `sql_injection` | bundle | 0 | 22 | all ✓ | ✓ |
| `ssh_failure` | bundle | 1 | 302 | all ✓ | ✓ |
| `ldap_enumeration` | remote CLI | 0 | 31 | all ✓ | ✓ |
| `kerberos_failure` | remote CLI | 0 | 45 | all ✓ | ✓ |
| `smb_login_failure` | remote CLI | 1 | 25 | all ✓ | ✓ |
| `dns_tunnel` | bundle | 0 | 302 | all ✓ | ✓ |
| `dga` | remote CLI | 1 | 1595 | all ✓ | ✓ |
| `port_sweep` | bundle | 0 | 42 | all ✓ | ✓ |
| `host_behavior_check` | bundle | 0 | 13 | all ✓ | ✓ |

¹ `events.jsonl`, `events.db`, `report.md`, `validation.json`, `traffic_summary.json`  
² `run_manager_success` = exit code 0 or 1 (completed run; 1 = partial validation per DSP rules)

**Artifact / evidence generation:** **10 / 10 PASS**

Non-bundle scenarios (`ldap_enumeration`, `kerberos_failure`, `smb_login_failure`, `dga`) initially failed collection because `www-data` could not read `/home/labuser/dsp-platform`. After lab permission fix, all four were re-run successfully.

---

## host_behavior_check (Phase 4)

Run: `20260618_1ef3f0`

| Event | Present (local `events.jsonl`) |
|-------|-------------------------------|
| `host_behavior_check_started` | ✓ |
| `host_behavior_command_dispatched` | ✓ |
| `eicar_file_created` | ✓ |
| `eicar_file_accessed` | ✓ |
| `eicar_file_deleted` | ✓ |
| `host_behavior_check_completed` | ✓ |

Evidence includes `"webshell_family": "php"` on the started event.

---

## Event Store Results

For **every** scenario run, `events.db` was created and populated via `RemoteEventCollector` → `EventSyncBridge`.

Run directories: `lab/php-real/reports/runs-20260618T005059Z/<run_id>/`

---

## Evidence Export Results

For **every** scenario run, the following were **created**:

- `events.jsonl`
- `events.db` (Event Store)
- `report.md`
- `validation.json`
- `traffic_summary.json`

---

## Bundle Validation Results (Phase 5)

Example remote directory (`http_followup` run `20260618_6ffdc7` on `victim-linux`):

| Remote file | Present |
|-------------|---------|
| `manifest.json` | ✓ (2052 bytes) |
| `run_scenario.py` | ✓ (23538 bytes) |
| `events.jsonl` | ✓ (12329 bytes) |
| `traffic_summary.json` | ✓ |

`host_behavior_check` run `20260618_1ef3f0`: same bundle pattern (`manifest.json`, `run_scenario.py`, `events.jsonl`).

Collector: local run dirs contain merged `events.jsonl` from remote bundles — download/collection **confirmed** for all bundle scenarios.

---

## Parity Validation (Phase 6)

| Item | JSP | PHP | Notes |
|------|-----|-----|-------|
| `cmd` GET/POST transport | ✓ | ✓ | `PhpWebshellRuntime` delivery-only |
| Multipart upload (`remote_path` + `file`) | ✓ | ✓ | Verified via bundle runner |
| GET `remote_path` download | ✓ | ✓ | `RealHttpTransport.download()` |
| Runtime `download_artifact` `cat` fallback | ✓ | **✗** | `PhpWebshellRuntime` uses parent — no override |
| Collector `cat` fallback | ✓ | ✓ | `RemoteEventCollector.collect()` family-agnostic |
| `host_behavior_check` on Linux | ✓ | ✓ | All lifecycle events emitted |

---

## Remaining Gap

| Priority | Item | Impact |
|----------|------|--------|
| Low | `PhpWebshellRuntime.download_artifact` lacks JSP-style runtime `cat` fallback | Mitigated by collector-level fallback; direct `provider.download_file()` callers differ |
| Lab | `www-data` must access `dsp-platform` for non-bundle scenarios | Document in lab guide; JSP ran as `labuser` — PHP Apache differs |
| Lab | Victim DNS required manual fix before `apt install` | One-time deploy step |
| Out of scope | ASPX validation | Next phase |

**No code changes were made** — validation only, per scope.

---

## Release 1.0 Decision

### **Real PHP Execution: READY**

**Rationale:**

1. Real Apache + PHP 8.3.6 webshell executes commands, uploads bundles, and downloads artifacts on `victim-linux`.
2. All **10** required scenarios complete RunManager, produce `events.jsonl`, load Event Store, and export evidence.
3. `host_behavior_check` emits the full EDR lifecycle event set on PHP.
4. Remote bundle layout (`manifest.json`, `run_scenario.py`, `events.jsonl`) is created and collected successfully.
5. Exit code 1 on `ssh_failure`, `smb_login_failure`, `dga` reflects **partial validation** (same as JSP) — artifacts still generated.

PHP real webshell execution is **validated for `release/v1.4.0-rc`** at parity with the JSP sign-off criteria.

---

## Execution logs

| Scenario | Log file |
|----------|----------|
| All scenarios (initial) | `lab/php-real/reports/<scenario>-20260618T005059Z.log` |
| Non-bundle retries | `lab/php-real/reports/<scenario>-20260618T005059Z-retry.log` |
| E2E runner output | `lab/php-real/reports/e2e-run.log` (if present) |

Full run artifacts: `lab/php-real/reports/runs-20260618T005059Z/`
