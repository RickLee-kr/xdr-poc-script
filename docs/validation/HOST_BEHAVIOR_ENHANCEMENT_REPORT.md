# Host Behavior Check Enhancement Report

**Branch / tag:** `release/v1.4.0-rc` @ `e7c61a9` (tag `v1.4.0`)  
**Enhancement date:** 2026-06-18 (UTC)  
**Scope:** `host_behavior_check` scenario only — JSP + PHP real webshell E2E  
**DSP version:** 1.4.0

E2E artifacts: [`../../lab/validation-runs/host-behavior-enhanced-20260618T085200Z/`](../../lab/validation-runs/host-behavior-enhanced-20260618T085200Z/)

---

## Added Behaviors

### Existing (unchanged)

| Category | Actions |
|----------|---------|
| Host enumeration | `whoami`, `id`, `hostname`, `uname -a`, `ip addr`, `ip route`, `cat /etc/passwd`, `base64 -d` |
| Primary EICAR | Single `.txt` file create → read → delete |

### P1 additions

| # | Behavior | Actions | Safety constraint |
|---|----------|---------|-------------------|
| 1 | **Multiple EICAR variants** | `eicar.com`, `eicar.txt`, `eicar.zip`, `eicar_nested.zip` — each create → read → delete | Standard EICAR test string only; no execution |
| 2 | **Credential access simulation** | `ls -al ~/.ssh`; `find ~ -name "*.pem"`; `find ~ -name "id_rsa"`; `find ~ -name "authorized_keys"` | Enumeration only — no credential collection or exfiltration |
| 3 | **Suspicious script drop** | `/tmp/update.sh`, `/tmp/install.sh`, `/tmp/run.sh` with `#!/bin/bash\necho test\n` — create → read → delete | **Scripts are never executed** (`chmod +x` not applied) |
| 4 | **Persistence artifact simulation** | `/tmp/systemd-update.service`, `/tmp/update.desktop` — create → read → delete | **No registration** — no systemd enable, cron, or desktop autostart |
| 5 | **Archive activity** | `archive.tar.gz`, `archive.zip` containing harmless `sample.txt` — create → read → delete | No malware payloads; archives deleted after access |

All behaviors execute on the **webshell compromise host only** (`initial_compromise_endpoint` from `--webshell-url`).

---

## Added Events

### 신규 이벤트 목록 (18 event types)

| Event | Trigger | Lifecycle |
|-------|---------|-----------|
| `eicar_variant_created` | EICAR variant file written | create |
| `eicar_variant_accessed` | EICAR variant read (`cat`) | access |
| `eicar_variant_deleted` | EICAR variant removed | delete |
| `credential_artifact_enumeration` | `ls -al ~/.ssh` dispatched | dispatch |
| `pem_file_enumeration` | `find ~ -name "*.pem"` dispatched | dispatch |
| `ssh_key_enumeration` | `find ~ -name "id_rsa"` / `authorized_keys` dispatched | dispatch |
| `suspicious_script_created` | Script file written to `/tmp/` | create |
| `suspicious_script_accessed` | Script read (`cat`) | access |
| `suspicious_script_deleted` | Script removed | delete |
| `persistence_artifact_created` | Placeholder `.service` / `.desktop` written | create |
| `persistence_artifact_accessed` | Artifact read (`cat`) | access |
| `persistence_artifact_deleted` | Artifact removed | delete |
| `archive_created` | `tar.gz` or `.zip` archive created | create |
| `archive_accessed` | Archive read (`cat`) | access |
| `archive_deleted` | Archive removed | delete |

### Retained events (unchanged)

| Event | Count per run |
|-------|---------------|
| `host_behavior_check_started` | 1 |
| `host_behavior_command_dispatched` | 8 |
| `eicar_file_created` / `accessed` / `deleted` | 1 each |
| `host_behavior_check_completed` | 1 |

**Total scenario events per run:** **50** (remote bundle; `source: remote`)

---

## JSP Validation

| Item | Value |
|------|-------|
| **URL** | `http://10.10.10.20:8080/shell.jsp` |
| **Runtime** | Apache Tomcat 9.0.96, OpenJDK 11 |
| **Run ID** | `20260618_edb599` |
| **Exit code** | 0 |
| **Mode** | live (`dry_run: false`) |
| **Events** | 50 |
| **Validation** | `success` |

### Artifacts

| File | Present |
|------|---------|
| `events.jsonl` | ✓ |
| `events.db` (Event Store) | ✓ |
| `report.md` / `report.json` | ✓ |
| `validation.json` | ✓ |
| `traffic_summary.json` | ✓ |

### Remote bundle (`/tmp/dsp/20260618_edb599/`)

| File | Present |
|------|---------|
| `manifest.json` | ✓ (3982 bytes — includes full enhanced plan) |
| `run_scenario.py` | ✓ (29481 bytes) |
| `events.jsonl` | ✓ (17654 bytes, 50 events + metadata) |

### Event coverage (JSP)

All 18 new event types present. Post-run cleanup verified: `/tmp/update.sh`, `/tmp/systemd-update.service` absent on host.

---

## PHP Validation

| Item | Value |
|------|-------|
| **URL** | `http://10.10.10.20/shell.php` |
| **Runtime** | Apache 2.4.58, PHP 8.3.6 |
| **Run ID** | `20260618_67f3fb` |
| **Exit code** | 0 |
| **Mode** | live (`dry_run: false`) |
| **Events** | 50 |
| **Validation** | `success` |

### Artifacts

| File | Present |
|------|---------|
| `events.jsonl` | ✓ |
| `events.db` (Event Store) | ✓ |
| `report.md` / `report.json` | ✓ |
| `validation.json` | ✓ |
| `traffic_summary.json` | ✓ |

### Remote bundle (`/tmp/dsp/20260618_67f3fb/`)

| File | Present |
|------|---------|
| `manifest.json` | ✓ |
| `run_scenario.py` | ✓ |
| `events.jsonl` | ✓ (50 events — identical event mix to JSP) |

---

## Safety Review

| Prohibited action | Status |
|-------------------|--------|
| Actual malware | **Not used** — EICAR standard test string only |
| Reverse shell | **Not implemented** |
| Persistence registration (cron/systemd enable) | **Not performed** — files created in `/tmp/` and deleted |
| Privilege escalation | **Not attempted** |
| Exploit / C2 / external callback | **Not present** |
| Malware download | **Not present** |
| Script execution (`/tmp/*.sh`) | **Not performed** — write/read/delete only |
| Credential exfiltration | **Not performed** — `ls`/`find` enumeration only |

### Code touchpoints (scenario-only)

| File | Change |
|------|--------|
| `dsp/protocols/host/behavior.py` | Extended plan (variants, credential checks, scripts, persistence, archives) |
| `dsp/protocols/host/behavior_events.py` | New event constants + `build_lifecycle_event` |
| `scenarios/host_behavior_check/executor.py` | Local execution of enhanced plan |
| `dsp/execution/remote/bundle/assets/run_scenario.py` | Remote bundle execution (self-contained mirror) |
| `scenarios/host_behavior_check/manifest.yaml` | Description + safety limits (`max_events: 120`) |

**Not changed:** Discovery, webshell execution provider, operational profiles, ASPX/Windows path (still skip placeholder).

### Unit tests

```
pytest tests/scenarios/test_host_behavior_check_e2e.py \
       tests/execution/test_bundle_scenario_runner.py
→ 18 passed
```

---

## Final Result

**PASS**

`host_behavior_check` EDR host behavior coverage is enhanced with five P1 behavior categories and 15 new lifecycle/dispatch event types. JSP (Tomcat) and PHP (Apache) real-environment E2E runs complete successfully with live mode, 50 events per run, full evidence export, and Event Store persistence.

---

*Generated after implementation + live E2E on `victim-linux` (10.10.10.20).*
