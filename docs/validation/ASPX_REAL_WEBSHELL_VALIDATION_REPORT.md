# ASPX Real Webshell Validation Report

**Branch:** `release/v1.4.0-rc`  
**Validation date:** 2026-06-18 (UTC)  
**Webshell family:** **ASPX only** (JSP / PHP already READY — not re-tested)  
**Success criteria:** Real IIS endpoint → DSP transport → remote execution → bundle collection → Event Store → evidence export

Machine-readable results: [`../../lab/aspx-real/reports/validation-results-20260618T020534Z.json`](../../lab/aspx-real/reports/validation-results-20260618T020534Z.json)

---

## Release 1.0 Decision

### **Real ASPX Execution: NOT READY**

**Rationale:** No reachable IIS/ASPX webshell endpoint exists in the lab. HTTP probe to `http://10.10.10.30/shell.aspx` times out; IIS is not installed; `shell.aspx` is not deployed. Operator remote access (WinRM/SSH) with documented credentials failed from the DSP host, preventing unattended IIS setup. **Zero scenarios completed** the full E2E path. READY is not asserted without real execution evidence.

---

## Environment

| Item | Value |
|------|-------|
| DSP host | `datarelay` (`/home/aella/xdr-poc-script`) |
| Target Windows VM | `windows-victim` (`10.10.10.30`) — libvirt **running** |
| **Webshell URL (target)** | `http://10.10.10.30/shell.aspx` |
| **Windows Version** | Golden qcow2 (exact build **not verified** — no shell access) |
| **IIS Version** | **N/A** — not installed / no HTTP listener |
| **ASP.NET Version** | **N/A** |
| **shell.aspx location** | **Not deployed** |
| Remote work dir (proposed) | `C:\temp\dsp` |
| Target network | `10.10.10.0/24` |

### Connectivity observed

| Port | Status |
|------|--------|
| 3389 (RDP) | Open |
| 5985 (WinRM) | Open (auth failed with documented `labuser`/`lab1234`) |
| 22 (SSH) | Open (password auth denied) |
| 80 (HTTP/IIS) | Closed or filtered — **blocks all webshell traffic** |

---

## Scenario Results

**No scenario completed E2E.** DSP cannot pass webshell healthcheck.

| Scenario | Executed | RunManager | events.jsonl | Event Store | Evidence | Notes |
|----------|----------|------------|--------------|-------------|----------|-------|
| `http_followup` | Probe only | ✗ | ✗ | ✗ | ✗ | `TransportConnectionError` — healthcheck timeout |
| `sql_injection` | ✗ | ✗ | ✗ | ✗ | ✗ | Blocked — no endpoint |
| `ssh_failure` | ✗ | ✗ | ✗ | ✗ | ✗ | Blocked |
| `ldap_enumeration` | ✗ | ✗ | ✗ | ✗ | ✗ | Blocked |
| `kerberos_failure` | ✗ | ✗ | ✗ | ✗ | ✗ | Blocked |
| `smb_login_failure` | ✗ | ✗ | ✗ | ✗ | ✗ | Blocked |
| `dns_tunnel` | ✗ | ✗ | ✗ | ✗ | ✗ | Blocked |
| `dga` | ✗ | ✗ | ✗ | ✗ | ✗ | Blocked |
| `port_sweep` | ✗ | ✗ | ✗ | ✗ | ✗ | Blocked |
| `host_behavior_check` | ✗ (E2E) | ✗ | ✗ | ✗ | ✗ | Guard verified in **unit test** only (see below) |

Probe log: `lab/aspx-real/reports/http_followup-probe-20260618T015850Z.log`

---

## host_behavior_check (Phase 4)

### E2E on real IIS

**Not run** — no ASPX endpoint.

### ASPX family guard (code verification)

| Check | Result |
|-------|--------|
| Linux commands **not** executed for `aspx` | ✓ (unit test) |
| Plan `mode=skip` | ✓ |
| Plan `reason=windows_family_placeholder` | ✓ |
| `host_behavior_check_started` / `completed` on real IIS | **Not verified** |
| `host_behavior_check_skipped` on remote bundle | **Not verified** (requires IIS + bundle run) |

```bash
pytest tests/scenarios/test_host_behavior_check_e2e.py::test_aspx_family_guard_skips_linux_commands
# 1 passed
```

---

## Bundle Validation (Phase 5)

| Remote artifact | Status |
|-----------------|--------|
| `manifest.json` | **Not created** — no bundle upload possible |
| `run_scenario.py` | **Not created** |
| `events.jsonl` | **Not created** |
| Collector download | **Not exercised** |

---

## Event Store Results

**No runs produced `events.db`.** Healthcheck fails before scenario execution.

---

## Evidence Export Results

**No evidence artifacts** (`report.md`, `validation.json`, `traffic_summary.json`) from ASPX real runs.

---

## Parity Validation (Phase 6)

Code-level comparison (JSP READY / PHP READY vs ASPX — **not live-tested**):

| Item | JSP | PHP | ASPX |
|------|-----|-----|------|
| `cmd` GET/POST transport | ✓ live | ✓ live | **Not live-tested** |
| Multipart upload | ✓ live | ✓ live | **Not live-tested** |
| GET `remote_path` download | ✓ live | ✓ live | **Not live-tested** |
| Runtime `download_artifact` cat fallback | ✓ | ✗ | ✗ |
| Collector cat fallback | ✓ (`cat`) | ✓ (`cat`) | **Untested** — `cat` is Linux |
| Bundle `python3 run_scenario.py` | ✓ Linux | ✓ Linux | **Windows gap** |
| `host_behavior_check` | ✓ full lifecycle | ✓ full lifecycle | **skip placeholder** |

---

## Remaining Gap

| Priority | Blocker | Action required |
|----------|---------|-----------------|
| **P0** | No IIS / no `shell.aspx` on `10.10.10.30` | RDP + `lab/aspx-real/deploy-iis.ps1` |
| **P0** | Operator cannot automate Windows (WinRM/SSH auth fail) | Restore golden image creds or fix WinRM |
| **P1** | Bundle runner is Linux-oriented (`python3`, `sh`, `/tmp/dsp`) | Windows Python + path strategy (out of scope for this validation) |
| **P1** | Collector `cat` fallback | Windows `type` not implemented |
| **P2** | `AspxWebshellRuntime.download_artifact` — no JSP cat fallback | Code parity gap (collector may mitigate on Linux-style shells only) |
| **P2** | `host_behavior_check` Windows commands | Placeholder only — not EDR simulation |

---

## Lab reproduction

See [`../../lab/aspx-real/LAB_REPRODUCTION.md`](../../lab/aspx-real/LAB_REPRODUCTION.md).

**Quick probe (must pass before E2E):**

```bash
curl -fsS -m 10 "http://10.10.10.30/shell.aspx?cmd=whoami"
```

**E2E runner (after probe passes):**

```bash
cd /home/aella/xdr-poc-script && source .venv/bin/activate
env -u WEBSHELL_URL python3 lab/aspx-real/validate_aspx_e2e.py
```

---

## Execution logs

| Log | Path |
|-----|------|
| Webshell probe failure | `lab/aspx-real/reports/validation-results-20260618T020534Z.json` |
| DSP healthcheck attempt | `lab/aspx-real/reports/http_followup-probe-20260618T015850Z.log` |
| Validator probe | stderr from `validate_aspx_e2e.py` (exit 2) |

---

## Comparison with JSP / PHP

| Family | Status | Evidence |
|--------|--------|----------|
| JSP | **READY** | Real Tomcat on `10.10.10.20:8080` — 10/10 scenarios |
| PHP | **READY** | Real Apache on `10.10.10.20` — 10/10 scenarios |
| ASPX | **NOT READY** | No IIS endpoint — 0/10 scenarios |

---

## Conclusion

ASPX Provider **code and CLI exist**, but **Real ASPX Execution is not validated** on `release/v1.4.0-rc` because the lab lacks a functioning IIS/ASPX webshell. This report documents audit evidence and prepared lab assets (`lab/aspx-real/`) for a future validation run after IIS deployment.
