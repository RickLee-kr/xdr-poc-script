# ASPX Windows Compatibility Audit

**Branch:** `release/v1.4.0-rc`  
**Date:** 2026-06-18  
**Scope:** Bundle Runner, Remote Scenario Runner, Collector, Artifact Download, Event Collection — Linux assumption inventory and minimum ASPX fix scope

**Reference:** JSP/PHP READY on `victim-linux`; ASPX NOT READY (no IIS). This audit is **code-path analysis only** — no implementation in this document.

---

## 1. Executive summary

DSP webshell **transport** for ASPX (`cmd` GET/POST, multipart upload, `remote_path` GET download) is **family-neutral** and works with `cmd.exe` when `shell.aspx` is deployed.

Everything **after** transport — remote directory creation, upload verification, bundle execution, artifact checks, file read fallback, and the embedded `run_scenario.py` runtime — is **Linux-first**. ASPX Real Execution on Windows IIS requires a **bounded platform dispatch layer**, not a rewrite.

| Layer | Linux coupling | Blocks ASPX today? |
|-------|----------------|-------------------|
| Bundle Runner | **High** | Yes |
| Remote Scenario Runner (CLI) | Medium (wrapper only) | Yes (victim needs `dsp` on Windows) |
| Upload verification | **High** | Yes |
| Collector | Medium | Yes (if `remote_path` GET fails) |
| Artifact download (`download_artifact` / `cat`) | **High** | Yes |
| Event collection (EventSyncBridge) | **None** | No (local, after download) |
| `run_scenario.py` (remote) | **High** | Yes (per-scenario) |

**Minimum code scope (P0):** ~8 files, ~400–600 LOC — path helpers + Windows shell command dispatch for mkdir / python / file read / upload verify / collector diagnostics.

**Minimum lab scope:** IIS + `shell.aspx` + **Python 3 on Windows** + `C:\temp\dsp` writable by AppPool identity.

**Full 10-scenario parity** (match JSP/PHP validation) additionally requires `run_scenario.py` Windows branches and Windows install of `dsp-remote-scenario` for non-bundle scenarios — **out of P0**.

---

## 2. Component audit

### 2.1 Bundle Runner

**File:** `dsp/execution/remote/bundle/runner.py`

| Line / area | Linux assumption | Windows impact |
|-------------|------------------|----------------|
| L67 | `mkdir -p {path}` | `cmd.exe` has no `-p`; use `mkdir` / `if not exist mkdir` |
| L98–104 | Path join `{remote_run_dir}/run_scenario.py` | Forward slash often works on Windows; backslash safer |
| L100–104 | `python3 {script}` | Windows: `py -3`, `python`, or `python3` if on PATH |
| L104 | `2>&1` stderr redirect | Works in `cmd.exe` |
| L174 | `ls -la {dir}` | Use `dir` or PowerShell `Get-ChildItem` |

**File:** `dsp/execution/remote/bundle/packager.py`

| Area | Linux assumption | Windows impact |
|------|------------------|----------------|
| L40–42 | `f"{remote_run_dir}/manifest.json"` | Needs family-aware path join |
| L38 | `chmod(0o755)` | Harmless on staging host (DSP Linux); remote irrelevant |

**File:** `dsp/execution/remote/bundle/planner.py`

| Line | Linux assumption | Windows impact |
|------|------------------|----------------|
| L37–38 | `remote_work_dir.rstrip("/")` + `f"{base}/{run_id}"` | Default `/tmp/dsp`; Windows needs `C:\temp\dsp\run_id` |
| L71 | `f"{run_dir}/traffic_summary.json"` | Same |

**File:** `dsp/execution/remote/paths.py`

| Line | Linux assumption | Windows impact |
|------|------------------|----------------|
| L8–9 | `rstrip("/")`, `/` separators | All remote paths Unix-style |

**File:** `dsp/execution/remote/bundle/models.py` + `assets/run_scenario.py` L100–110

| Area | Linux assumption |
|------|------------------|
| `required_commands` | `python3`, `curl`, `ssh`/`nc`, `sh`/`bash` |

---

### 2.2 Remote Scenario Runner (non-bundle)

**File:** `dsp/execution/remote/runner.py`

- **Family-neutral** — only builds `dsp-remote-scenario <base64-payload>` and calls `provider.execute_command()`.
- **No Linux code** in runner itself.

**File:** `dsp/execution/remote/payload.py`

- Command name `dsp-remote-scenario` — victim must have wrapper script on PATH.

**File:** `dsp/runner/remote_scenario_cli.py`

- Runs **full DSP package** on remote host (`PluginLoader`, `EventStore`, scenario executors).
- Uses `Path` locally — OK on Windows **if** `dsp` package installed.
- **Blocker:** No Windows lab packaging of `dsp-remote-scenario` + dependencies (JSP/PHP use `/usr/local/bin/dsp-remote-scenario` + `~/dsp-platform`).

**Non-bundle scenarios:** `ldap_enumeration`, `kerberos_failure`, `smb_login_failure`, `dga` — all require remote CLI path above.

---

### 2.3 Upload / artifact verification

**File:** `dsp/execution/remote/bundle/upload.py`

| Function | Linux commands | Windows equivalent (minimum) |
|----------|----------------|------------------------------|
| `verify_remote_file` | `ls -l`, `wc -c <`, `sha256sum` | `dir`, PowerShell `(Get-Item).Length`, `certutil -hashfile` or PS `Get-FileHash` |
| `base64_upload_commands` | `echo '…' \| base64 -d > file` | PowerShell `[Convert]::FromBase64String` or `certutil -decode` |
| `_heredoc_base64_command` | Unix `echo \| base64 -d` | Not available in `cmd.exe` |
| `verify_remote_execution_artifacts` | `ls -la`, `wc -l <`, `cat` | `dir`, line count via PS, `type` |
| `_looks_missing` markers | `"no such file"`, `"cannot access"` | Add `"cannot find"`, `"system cannot find"` |

Multipart upload via HTTP (`RealHttpTransport.send_upload`) is **family-neutral** — works if `shell.aspx` implements multipart (same as JSP/PHP).

---

### 2.4 Collector

**File:** `dsp/execution/remote/collector.py`

| Area | Linux coupling | Notes |
|------|----------------|-------|
| `collect()` core | **Neutral** | Uses `provider.download_file()` then `EventSyncBridge` |
| L80 | `fetch_remote_file_via_cat` | Delegates to `cat` — **broken on Windows** |
| L192–195 | Diagnostics `ls -la` | Diagnostics only |
| L235–255 | Log messages say `cat fallback` | Semantic only |

**File:** `dsp/execution/webshell/command_transport.py`

| L55 | `cat {shlex.quote(path)}` | **Must be `type` for cmd.exe** (`shlex.quote` is POSIX-oriented) |

**File:** `dsp/execution/providers/webshell/jsp/jsp_runtime.py` L131–170

- JSP overrides `download_artifact` with `remote_path` GET + **`cat` fallback** + JSONL unwrap.

**File:** `dsp/execution/providers/webshell/aspx/aspx_runtime.py`

- **No** `download_artifact` override — uses parent `TransportBackedRuntime` only (same as PHP).
- Collector-level `cat` fallback still invoked — **fails on Windows**.

---

### 2.5 Event collection (post-download)

**Files:** `dsp/execution/webshell/event_sync/bridge.py`, `bundle_content.py`, `validation.py`

- Operate on **local** downloaded bytes — **no OS dependency**.
- **No changes required** for ASPX once valid JSONL reaches DSP host.

---

### 2.6 Remote `run_scenario.py` (uploaded bundle asset)

**File:** `dsp/execution/remote/bundle/assets/run_scenario.py`

| Area | Linux assumption | Windows notes |
|------|------------------|---------------|
| Shebang `python3` | Unix | Remote invoke uses `python3` from runner |
| `_command_available` | `shutil.which` | OK cross-platform |
| `_run_shell_command` L549–554 | `["sh", "-c", shell]` | **Must use `cmd /c` on Windows** |
| `_curl_request` L332+ | `curl` subprocess | curl not default on Windows; use `urllib` or PS |
| `_run_ssh_attempt` L459+ | `ssh`, `nc` | OpenSSH optional; `nc` rare |
| `_run_host_behavior_check` L609–641 | `printf`, `cat`, `rm -f`, `/tmp/...` paths | **Skipped for ASPX** via `windows_family_placeholder` |
| `port_sweep` | `socket` only | **Works on Windows** |
| `dns_tunnel` | `socket` UDP | **Works on Windows** |
| `path.parent.mkdir` | `pathlib` | **Works on Windows** |

---

### 2.7 Defaults and CLI

| File | Default | ASPX need |
|------|---------|-----------|
| `dsp/runner/run_manager.py` L49 | `DEFAULT_REMOTE_WORK_DIR = "/tmp/dsp"` | `C:\temp\dsp` when `webshell_family=aspx` |
| `dsp/runner/cli.py` L155 | Same default in help | Document / auto-select |
| `dsp/execution/webshell/security.py` L21 | `allowed_paths: /tmp/dsp_stub/` | Windows prefixes if enforced |

---

## 3. Scenario × platform matrix

| Scenario | Mode | Linux remote deps | Windows without code change | After P0 only | After P0+P1 |
|----------|------|-------------------|----------------------------|-------------|-------------|
| `port_sweep` | bundle | python3, socket | ✗ (mkdir, python3, verify) | **Likely** | ✓ |
| `dns_tunnel` | bundle | python3, socket | ✗ | **Likely** | ✓ |
| `http_followup` | bundle | python3, curl | ✗ | ✗ | ✓ (urllib) |
| `sql_injection` | bundle | python3, curl | ✗ | ✗ | ✓ |
| `ssh_failure` | bundle | python3, ssh\|nc | ✗ | ✗ | Partial (OpenSSH client) |
| `host_behavior_check` | bundle | skip for aspx | **Skip by design** | skip event | skip event |
| `ldap_enumeration` | CLI | dsp-remote-scenario | ✗ | ✗ | Needs Windows DSP install |
| `kerberos_failure` | CLI | dsp-remote-scenario | ✗ | ✗ | Needs Windows DSP install |
| `smb_login_failure` | CLI | dsp-remote-scenario | ✗ | ✗ | Needs Windows DSP install |
| `dga` | CLI | dsp-remote-scenario | ✗ | ✗ | Needs Windows DSP install |

---

## 4. Minimum modification scope

### P0 — Required for any ASPX bundle E2E (smoke: `port_sweep`)

**Goal:** upload → `run_scenario.py` → `events.jsonl` → collector → Event Store.

| # | File | Change |
|---|------|--------|
| 1 | **NEW** `dsp/execution/remote/platform.py` (or `paths.py` extend) | `is_windows_webshell(family)`, `remote_path_join()`, `remote_python_cmd()`, `remote_mkdir_cmd()`, `remote_read_file_cmd()`, `remote_dir_list_cmd()`, `remote_file_size_cmd()` |
| 2 | `dsp/execution/remote/paths.py` | Use `remote_path_join` for bundle path |
| 3 | `dsp/execution/remote/bundle/planner.py` | Windows path joins in manifest `paths` |
| 4 | `dsp/execution/remote/bundle/packager.py` | Windows remote file paths in `remote_files` |
| 5 | `dsp/execution/remote/bundle/runner.py` | Dispatch mkdir, python launcher, diagnostic dir list via platform helper; pass `webshell_family` from provider metadata |
| 6 | `dsp/execution/remote/bundle/upload.py` | Windows branch for verify + base64 fallback commands |
| 7 | `dsp/execution/webshell/command_transport.py` | `read_remote_file_via_cat` → dispatch `type` on Windows (rename optional: `read_remote_file_via_shell`) |
| 8 | `dsp/execution/providers/webshell/aspx/aspx_runtime.py` | Copy JSP `download_artifact` override using Windows `type` fallback |
| 9 | `dsp/execution/remote/collector.py` | Windows diagnostics commands only (optional P0) |
| 10 | `dsp/runner/run_manager.py` | When `webshell_family==aspx`, default `remote_work_dir` to `C:\temp\dsp` if unset |

**Estimated diff:** ~400–600 LOC + tests mirroring `test_provider_family_parity.py` for Windows command strings.

**Lab (not code):** IIS, `shell.aspx`, Python 3 on `windows-victim`, AppPool write access to `C:\temp\dsp`.

---

### P1 — Bundle scenario parity (6 bundle scenarios except full `ssh_failure`)

| # | File | Change |
|---|------|--------|
| 1 | `dsp/execution/remote/bundle/assets/run_scenario.py` | `sys.platform` / manifest flag `host_os: windows`; `_run_shell_command` → `cmd /c`; `_curl_request` → `urllib` fallback; `python3` → `py -3`/`python` in capability check |
| 2 | `dsp/execution/remote/bundle/models.py` | `SCENARIO_REMOTE_REQUIREMENTS` accept `python`/`py` on Windows |
| 3 | `run_scenario.py` `_required_commands` | Windows command names |

**Does not include** Windows `host_behavior_check` commands (remains skip/placeholder per product design).

---

### P2 — Full 10-scenario parity with JSP/PHP validation

| # | Area | Change |
|---|------|--------|
| 1 | Windows `dsp-remote-scenario` packaging | Install DSP on Windows victim (pip install / copy tree); wrapper `.cmd` or `dsp-remote-scenario.ps1` |
| 2 | Non-bundle scenarios | Validate `ldap_enumeration`, `kerberos_failure`, `smb_login_failure`, `dga` on Windows — scenario executors may use sockets (mostly portable) but need full plugin load |
| 3 | `ssh_failure` on Windows | Depend on OpenSSH client or degrade to skip |
| 4 | `PhpWebshellRuntime` parity | Optional: same `download_artifact` override as ASPX for consistency |
| 5 | `host_behavior_check` Windows | New feature — **explicitly out of current validation scope** |

---

## 5. Recommended implementation pattern

**Do not** fork runners per family. Add a single dispatch module:

```text
webshell_family / host_os
        ↓
remote_platform.commands(family) → RemoteShellCommands
        ↓
BundleScenarioRunner / upload / collector / command_transport
```

`RemoteShellCommands` minimally provides:

- `mkdir(path)`
- `python_executable()` → `python3` | `py -3`
- `read_file(path)` → `cat` | `type`
- `list_dir(path)` → `ls -la` | `dir`
- `file_byte_count(path)` → `wc -c <` | PowerShell one-liner
- `file_hash(path)` → `sha256sum` | `certutil -hashfile`
- `decode_base64_to_file(b64, path)` → shell pipeline | PowerShell

Pass `webshell_family` from `WebshellExecutionProvider` / `execution_metadata` (already set for `host_behavior_check`).

---

## 6. What needs NO change

| Component | Reason |
|-----------|--------|
| `AspxWebshellRuntime.execute_command` | Transport-only; `cmd.exe` via shell.aspx |
| `AspxCommandEncoder` | HTTP `cmd` param — same contract |
| `RealHttpTransport` upload/download | HTTP contract — family-neutral |
| `RemoteScenarioRunner` | Payload delivery only |
| `EventSyncBridge` / `EventStore` / reporting | Local DSP host |
| `host_behavior_check` ASPX guard | Already skips Linux commands |

---

## 7. Minimum path to flip ASPX NOT READY → READY

### Narrow (prove pipeline)

1. Implement **P0** code changes.
2. Deploy IIS + `lab/aspx-real/shell.aspx` on `10.10.10.30`.
3. Install Python 3 on Windows; ensure `py -3` or `python` on PATH for AppPool.
4. Run **`port_sweep`** bundle only → verify artifacts.
5. Document `host_behavior_check` skip as expected.

### Full (match JSP/PHP 10/10)

1. P0 + P1.
2. Windows `dsp-remote-scenario` install.
3. Re-run `lab/aspx-real/validate_aspx_e2e.py` full matrix.

---

## 8. Risk notes

| Risk | Mitigation |
|------|------------|
| `shlex.quote` on Windows paths | Use platform-specific quoter (`subprocess.list2cmdline` for cmd) |
| AppPool identity cannot write `C:\temp\dsp` | `icacls` in `deploy-iis.ps1` (lab asset exists) |
| `remote_path` GET returns HTML error page | JSP-style runtime + collector `type` fallback |
| Multipart base64 upload fallback | Required when verify fails — must not use Unix `base64 -d` on cmd.exe |

---

## 9. File inventory (Linux-assumption hotspots)

| Path | Severity |
|------|----------|
| `dsp/execution/remote/bundle/runner.py` | **Critical** |
| `dsp/execution/remote/bundle/upload.py` | **Critical** |
| `dsp/execution/remote/bundle/assets/run_scenario.py` | **Critical** (per scenario) |
| `dsp/execution/webshell/command_transport.py` | **Critical** |
| `dsp/execution/providers/webshell/aspx/aspx_runtime.py` | **High** |
| `dsp/execution/remote/collector.py` | **Medium** |
| `dsp/execution/remote/paths.py` | **High** |
| `dsp/execution/remote/bundle/planner.py` | **High** |
| `dsp/execution/remote/bundle/packager.py` | **Medium** |
| `dsp/execution/remote/bundle/models.py` | **Medium** |
| `dsp/runner/remote_scenario_cli.py` | **Low** (portable if DSP installed) |
| `dsp/execution/remote/runner.py` | **None** |
| `dsp/protocols/host/behavior.py` | **By design** (ASPX skip) |
