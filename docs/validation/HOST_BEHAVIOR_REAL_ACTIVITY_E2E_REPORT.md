# Host Behavior Check Real Activity E2E Report

**Branch / tag:** `release/v1.4.0-rc` @ `e7c61a9` (tag `v1.4.0`)  
**Validation date:** 2026-06-18 (UTC)  
**DSP version:** 1.4.0  
**Scope:** JSP + PHP real webshell hosts only (ASPX excluded)

Machine-readable run artifacts:

- JSP: [`../../lab/validation-runs/host-behavior-20260618T083706Z/20260618_d7adfc/`](../../lab/validation-runs/host-behavior-20260618T083706Z/20260618_d7adfc/)
- PHP: [`../../lab/validation-runs/host-behavior-20260618T083706Z/20260618_0e4384/`](../../lab/validation-runs/host-behavior-20260618T083706Z/20260618_0e4384/)

---

## Scope

- Detection validation: **out of scope**
- Alert validation: **out of scope**
- Real activity validation: **in scope**

This report verifies only that EDR-relevant host behaviors were **dispatched and executed on the remote webshell host** via the remote bundle (`run_scenario.py`). Command stdout/stderr was **not** parsed to infer success. No Stellar Cyber or endpoint EDR alert correlation was performed.

---

## Environment

### JSP

| Item | Value |
|------|-------|
| **URL** | `http://10.10.10.20:8080/shell.jsp` |
| **Host** | `victim-linux` (`10.10.10.20`) |
| **Runtime** | Apache Tomcat **9.0.96**, OpenJDK **11** (Temurin) |
| **Remote work dir** | `/tmp/dsp/20260618_d7adfc` |
| **Webshell OS user** | `labuser` (Tomcat process) |

### PHP

| Item | Value |
|------|-------|
| **URL** | `http://10.10.10.20/shell.php` |
| **Host** | `victim-linux` (`10.10.10.20`) |
| **Runtime** | Apache **2.4.58**, PHP **8.3.6** (mod_php) |
| **Remote work dir** | `/tmp/dsp/20260618_0e4384` |
| **Webshell OS user** | `www-data` |

**DSP host:** `datarelay` (`/home/aella/xdr-poc-script`)  
**Target network (discovery only):** `10.10.10.0/24`

---

## Execution command (both providers)

Each provider was run **in isolation** with only `host_behavior_check`:

```bash
dsp run --verbose --scenarios host_behavior_check \
  --execution-provider webshell \
  --webshell-family <jsp|php> \
  --webshell-url <url> \
  --remote-work-dir /tmp/dsp \
  --target-net 10.10.10.0/24
```

---

## Execution Results

| Provider | Run ID | Exit | Events | Evidence | Live Mode |
|---|---|---|---|---|---|
| JSP | `20260618_d7adfc` | 0 | 13 scenario events (+1 remote bundle metadata line) | Remote bundle present; `events.jsonl` collected; `dry_run: false` in `run.json` | **Yes** — `run.json` `dry_run: false`; remote `manifest.json` `mode: live` |
| PHP | `20260618_0e4384` | 0 | 13 scenario events (+1 remote bundle metadata line) | Remote bundle present; `events.jsonl` collected; `dry_run: false` in `run.json` | **Yes** — `run.json` `dry_run: false`; remote `manifest.json` `mode: live` |

### Live-mode evidence

| Check | JSP | PHP |
|-------|-----|-----|
| `run.json` → `dry_run` | `false` | `false` |
| Remote `manifest.json` → `dry_run` | `false` | `false` |
| Remote plan → `mode` | `live` | `live` |
| All lifecycle events → `evidence.mode` | `live` | `live` |
| Event `source` | `remote` (all 13 lines) | `remote` (all 13 lines) |

### Remote bundle artifacts (post-run, via webshell)

| Artifact | JSP | PHP |
|----------|-----|-----|
| `manifest.json` | ✓ (1290 bytes) | ✓ (1290 bytes) |
| `run_scenario.py` | ✓ (23538 bytes) | ✓ (23538 bytes) |
| `events.jsonl` | ✓ (13 events + bundle metadata header) | ✓ (13 events + bundle metadata header) |
| `traffic_summary.json` | ✓ | ✓ |

Remote `events.jsonl` line 1 is bundle metadata (`"_bundle_metadata": true`, `event_count: 13`). Scenario event names and order match the locally collected `events.jsonl` for both runs, confirming execution occurred on the remote host and was harvested back to the DSP run directory.

`execution_stdout_stderr.txt` reports bundle completion (`exit_code: 0`, `events: 13`) — used only to confirm remote runner finished, **not** to infer per-command success.

---

## Activity Verification

Dispatch verification pairs each `host_behavior_command_dispatched` event (`artifact`, `evidence.shell`) with the remote `manifest.json` plan command list. EICAR verification pairs lifecycle events with remote filesystem state (`test ! -e <path>` → `absent`).

| Activity | JSP | PHP | Evidence |
|---|---|---|---|
| whoami dispatched | **PASS** | **PASS** | `host_behavior_command_dispatched` seq=1, shell=`whoami`; manifest plan command `whoami` |
| id dispatched | **PASS** | **PASS** | seq=2, shell=`id`; manifest plan |
| hostname dispatched | **PASS** | **PASS** | seq=3, shell=`hostname`; manifest plan |
| uname -a dispatched | **PASS** | **PASS** | seq=4, shell=`uname -a`; manifest plan |
| ip addr dispatched | **PASS** | **PASS** | seq=5, shell=`ip addr`; manifest plan |
| ip route dispatched | **PASS** | **PASS** | seq=6, shell=`ip route`; manifest plan |
| cat /etc/passwd dispatched | **PASS** | **PASS** | seq=7, shell=`cat /etc/passwd`; manifest plan |
| base64 decode dispatched | **PASS** | **PASS** | seq=8, shell=`echo "d2hvYW1p" \| base64 -d`; manifest plan |
| EICAR created | **PASS** | **PASS** | `eicar_file_created` → `/tmp/dsp_eicar_<run_id>.txt`; remote bundle `mode: live` |
| EICAR accessed | **PASS** | **PASS** | `eicar_file_accessed` after create, before delete (timestamp order) |
| EICAR deleted | **PASS** | **PASS** | `eicar_file_deleted` event; post-run remote check: file **absent** |

### Required lifecycle events

| Event | JSP | PHP |
|-------|-----|-----|
| `host_behavior_check_started` | ✓ | ✓ |
| `host_behavior_command_dispatched` | ✓ (×8) | ✓ (×8) |
| `eicar_file_created` | ✓ | ✓ |
| `eicar_file_accessed` | ✓ | ✓ |
| `eicar_file_deleted` | ✓ | ✓ |
| `host_behavior_check_completed` | ✓ | ✓ |

All events list `target: "10.10.10.20"` (webshell compromise host parsed from `--webshell-url`).

---

## Targeting Verification

| Check | Result | Evidence |
|-------|--------|----------|
| Executed on webshell host only | **PASS** | Every event `target` = `10.10.10.20`; remote plan `target_host` = `10.10.10.20`; `traffic_summary.json` → `host_behavior_check.target_ips: []` |
| Did not target internal network | **PASS** | No `host_behavior_*` events reference hosts other than `10.10.10.20`. Discovery probed `10.10.10.0/24` separately; `host_behavior_check` did not fan out commands to discovered hosts. |
| Runs after webshell host attack and before internal recon | **PASS** (design + placement) | `DISCOVERY_FIRST_SCENARIO_ORDER` in `dsp/runtime/operational_profiles.py`: `http_followup` → `sql_injection` → **`host_behavior_check`** → `ssh_failure` / `ldap_enumeration` / `smb_login_failure` / `kerberos_failure` / `dns_tunnel` / `dga` → `port_sweep`. `host_behavior_check` is injected after `sql_injection` via `initial_compromise_endpoint` from `webshell_url`. |

**Note:** This validation executed `host_behavior_check` as a **standalone** scenario (not a full profile run). Ordering is confirmed from the canonical profile definition and `apply_webshell_initial_compromise_plan()` wiring; no multi-scenario run was required for this gate.

---

## What was explicitly not validated

- Endpoint EDR alert generation or correlation
- Stellar Cyber case / alert creation
- Command output content or exit codes as success criteria
- ASPX / Windows `host_behavior_check` placeholder path

---

## Final Verdict

**PASS**

`host_behavior_check` performs real EDR-relevant host behavior on JSP and PHP webshell hosts:

- Runs in **live** mode (`dry_run: false`).
- Uploads and executes the remote bundle on the compromise host.
- Dispatches all eight planned Linux recon commands plus full EICAR create → access → delete lifecycle.
- Targets only the webshell endpoint host (`10.10.10.20`), not the broader discovered network.
- Produces the complete required event set with `source: remote`, corroborated by on-host `events.jsonl` and post-run filesystem checks.

---

*Generated after live E2E runs on `release/v1.4.0-rc` / `v1.4.0` without code changes.*
