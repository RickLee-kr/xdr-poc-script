# JSP Real Webshell Validation Report

**Branch:** `release/v1.4.0-rc`  
**Validation date:** 2026-06-17 (UTC)  
**Webshell family:** **JSP only** (PHP / ASPX not tested)  
**Success criteria:** Event generation, Event Store, evidence artifacts, RunManager completion — **no detection/alert evaluation**

Machine-readable results: [`../../lab/jsp-real/reports/validation-results-20260617T151347Z.json`](../../lab/jsp-real/reports/validation-results-20260617T151347Z.json)

---

## 1. Environment

| Item | Value |
|------|-------|
| DSP host | `datarelay` (`/home/aella/xdr-poc-script`) |
| Remote execution host | `victim-linux` (`10.10.10.20`) |
| **Webshell URL** | `http://10.10.10.20:8080/shell.jsp` |
| **Tomcat** | Apache Tomcat **9.0.96** (user-local `~/dsp-jsp-tomcat/`) |
| **JVM** | OpenJDK **11.0.24** (Eclipse Temurin JRE) |
| **shell.jsp path (remote)** | `~/dsp-jsp-tomcat/apache-tomcat-9.0.96/webapps/ROOT/shell.jsp` |
| Target network | `10.10.10.0/24` |
| Remote work dir | `/tmp/dsp` |
| DSP version | 1.4.0 (`release/v1.4.0-rc`) |

**Note:** Prior to this validation, port 8080 served a Python `BaseHTTP` simulator (`/tmp/shell.jsp.py`). It was replaced with **real Tomcat + JSP** for this run.

---

## 2. Deployment summary (Phase 2)

1. Transferred Tomcat 9.0.96 + Temurin JRE 11 tarball from DSP host to `victim-linux` (remote `wget` to Apache archive failed).
2. Deployed minimal lab `shell.jsp` (cmd / multipart upload / remote_path download).
3. Stopped Python simulator; started Tomcat on port 8080.
4. Probe: `?cmd=whoami` → `labuser`, `Server: HTTP/1.1` + `JSESSIONID` (Tomcat).

Lab assets: `lab/jsp-real/` (`shell.jsp`, `validate_jsp_e2e.py`, optional `docker-compose.yml`).

---

## 3. Scenarios executed (Phase 3)

Each scenario run individually:

```bash
dsp run --verbose --scenarios <id> \
  --execution-provider webshell --webshell-family jsp \
  --webshell-url http://10.10.10.20:8080/shell.jsp \
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

**Artifact / evidence generation:** **10 / 10 PASS** (all required files present for every scenario).

---

## 4. EDR host behavior check (Phase 4)

Run: `20260617_2d67a8`

| Event | Present (local `events.jsonl`) |
|-------|-------------------------------|
| `host_behavior_check_started` | ✓ |
| `host_behavior_command_dispatched` | ✓ |
| `eicar_file_created` | ✓ |
| `eicar_file_accessed` | ✓ |
| `eicar_file_deleted` | ✓ |
| `host_behavior_check_completed` | ✓ |

---

## 5. Bundle verification (Phase 5)

Example remote directory (`host_behavior_check` run `20260617_2d67a8` on `victim-linux`):

| Remote file | Present |
|-------------|---------|
| `manifest.json` | ✓ |
| `run_scenario.py` | ✓ |
| `events.jsonl` | ✓ (4451 bytes) |
| `traffic_summary.json` | ✓ |

Collector: local run dir `lab/jsp-real/reports/runs-20260617T151347Z/20260617_2d67a8/events.jsonl` contains **13** lines merged from remote bundle — download/collection **confirmed**.

Same bundle pattern observed for other bundle scenarios (`http_followup`, `sql_injection`, `dns_tunnel`, `port_sweep`, etc.) — per-run `manifest.json` + `run_scenario.py` + `events.jsonl` under `/tmp/dsp/<run_id>/`.

---

## 6. Evidence verification (Phase 6)

For **every** scenario run, the following were **created** (existence only; content not interpreted):

- `events.jsonl`
- `events.db` (Event Store)
- `report.md`
- `validation.json`
- `traffic_summary.json`

Run directories: `lab/jsp-real/reports/runs-20260617T151347Z/<run_id>/`

---

## 7. Failures / partial results

| Item | Detail | Impact on release gate |
|------|--------|------------------------|
| Exit code **1** on `ssh_failure`, `smb_login_failure`, `dga` | DSP validation **partial** (typical when live targets refuse connections or auth paths are inconclusive) | **No** — artifacts and events still generated; criteria was not “validation.json = pass” |
| Legacy Python simulator | Was not real JSP; remediated before test | Resolved |
| Docker Tomcat on DSP host | Docker not installed | Used `victim-linux` Tomcat instead |
| PHP / ASPX | **Not run** (per scope) | Deferred to next phase |

**No scenario failed to produce events or evidence artifacts.**

---

## 8. Follow-up / fixes recommended

| Priority | Item |
|----------|------|
| Low | Document Tomcat deploy procedure in lab guide (tarball copy path when victim cannot `wget`) |
| Low | Pin lab `shell.jsp` + Tomcat version in `RELEASE_1_0_LAB_GUIDE.md` |
| Next phase | **PHP** webshell validation (after JSP sign-off) |
| Out of scope | ASPX until PHP complete |

---

## 9. Conclusion

**Real JSP (Tomcat 9.0.96) webshell execution on `victim-linux` is validated** for `release/v1.4.0-rc`:

- Bundle scenarios execute via uploaded `run_scenario.py` on the remote host.
- Non-bundle scenarios execute via `dsp-remote-scenario` on the remote host.
- `host_behavior_check` EDR lifecycle events are emitted end-to-end.
- Event Store and evidence exports are produced for all tested scenarios.

**JSP E2E gate: PASS** (artifact / execution criteria).  
**PHP / ASPX: not tested.**

---

*Generated after automated run `validate_jsp_e2e.py` + manual Tomcat deployment audit.*
