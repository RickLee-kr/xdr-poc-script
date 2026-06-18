# DSP Release 1.0 Summary

**Version:** 1.0.0 (package `1.4.0` on branch `release/v1.4.0-rc`)  
**Status:** **READY WITH KNOWN LIMITATIONS** — core platform, JSP/PHP webshell validation, evidence packaging, E2E harness

---

## Release 1.0 Status

Release recommendation: **READY WITH KNOWN LIMITATIONS**

### Validated (Release Scope)

| Capability | Status |
|------------|--------|
| Remote command execution | Validated (JSP / PHP) |
| Remote artifact upload | Validated (JSP / PHP) |
| Remote bundle download | Validated (JSP / PHP) |
| Remote scenario runner | Validated (JSP / PHP) |
| Remote event collection | Validated (JSP / PHP) |
| Evidence export | Validated (JSP / PHP) |
| Manual verification package | Validated (JSP / PHP) |

### Validated Execution Providers

| Provider | Status |
|----------|--------|
| Local | Validated |
| JSP Webshell | Validated |
| PHP Webshell | Validated |
| ASPX Webshell | **Not validated** — preview only |

### Known Limitation

- **ASPX** — contract and transport exist; real Windows IIS execution not validated

### Release Scope Criteria (CURRENT RELEASE SCOPE)

All four criteria met via JSP and PHP real-environment validation:

1. Remote execution works
2. Event bundles are collected
3. Evidence packages are exported
4. Manual verification workflow is usable

---

## Validated Runtime Platforms

| Platform | Status | Evidence |
|----------|--------|----------|
| **Linux** | Validated | Local provider; JSP (Tomcat) and PHP (Apache) on lab host `victim-linux` |
| **Windows** | Not yet validated | ASPX / IIS path not validated; bundle runner and collector remain Linux-oriented |

---

## Validated Webshell Families

| Family | Status | Notes |
|--------|--------|-------|
| **JSP** | Validated | Real Tomcat 9.0.96 + `shell.jsp` — 10/10 scenarios. See [`docs/validation/JSP_REAL_WEBSHELL_VALIDATION_REPORT.md`](docs/validation/JSP_REAL_WEBSHELL_VALIDATION_REPORT.md) |
| **PHP** | Validated | Real Apache 2.4.58 + PHP 8.3.6 + `shell.php` — 10/10 scenarios. See [`docs/validation/PHP_REAL_WEBSHELL_VALIDATION_REPORT.md`](docs/validation/PHP_REAL_WEBSHELL_VALIDATION_REPORT.md) |
| **ASPX** | Preview / not yet validated | Contract and HTTP transport exist. Real Windows IIS execution has not been validated. See [`docs/validation/ASPX_REAL_WEBSHELL_VALIDATION_REPORT.md`](docs/validation/ASPX_REAL_WEBSHELL_VALIDATION_REPORT.md) |

---

## Known Limitations

- ASPX runtime not validated on real Windows IIS
- Windows webshell execution path not validated (bundle runner, collector, artifact handling, platform dispatch are Linux-oriented)
- ASPX should be considered **preview status** until Windows lab validation completes
- Local provider: platform-ready; dedicated 10-scenario real-runtime sign-off on this release branch is not separately documented (JSP/PHP webshell path is the validated remote execution evidence)

---

## Supported Scope

Release 1.0 delivers a self-contained Detection Scenario Platform with:

| Area | Release 1.0 capability |
|------|------------------------|
| **Event Store** | SQLite append-only SOT per run (`events.db`, optional `events.jsonl` export) |
| **Scenario plugins** | 13+ discovered scenarios including `host_behavior_check` (see `dsp plugins list`) |
| **Local execution** | `LocalExecutionProvider` integrated with `RunManager` / `dsp run` |
| **Webshell execution** | `WebshellExecutionProvider` via `dsp run --execution-provider webshell` and Python API — **JSP and PHP validated**; ASPX preview only |
| **Remote scenario dispatch** | `RemoteScenarioRunner` + `BundleScenarioRunner` — command delivery and bundle execution on remote host |
| **Remote event collection** | `RemoteEventCollector` + `EventSyncBridge` — RunManager auto-collects per scenario on webshell runs |
| **Evidence export** | `EvidenceExporter` — JSON + Markdown; generated on run completion via RunManager |
| **Manual verification** | `ManualVerificationPackageGenerator` — checklist, investigation notes, evidence summary templates |
| **Validation / reporting** | `ValidationEngine` + `ReportingEngine` on local and webshell runs via `dsp run` |
| **E2E harness** | `tests/e2e/` — local and webshell flows without detection validation |

---

## Local Execution Flow

```
dsp run / RunManager
    ↓
LocalExecutionProvider.prepare()
    ↓
LocalExecutionProvider.execute() → run_scenario()
    ↓
Scenario traffic / event generation
    ↓
Event Store (events.db)
    ↓
ValidationEngine → validation.json
    ↓
ReportingEngine → report.md / report.json
    ↓
EvidenceExporter + ManualVerificationPackageGenerator
    ↓
events.jsonl export (on run completion)
```

**CLI example:**

```bash
dsp run --scenarios dummy --dry-run
dsp run --profile normal --target-net 10.10.10.0/24
```

Run artifacts: `~/.dsp/runs/<run_id>/` (override with `DSP_RUNS_DIR`).

---

## Webshell Execution Flow

Webshell execution is available via **`dsp run --execution-provider webshell`** and the Python API. Real runtime validation completed for **JSP** and **PHP** only.

```
dsp run --execution-provider webshell ...
    ↓
WebshellExecutionProvider.prepare()
    ↓
WebshellExecutionProvider.execute()
    ↓
BundleScenarioRunner or RemoteScenarioRunner on remote host
    ↓
Remote events.jsonl bundle produced (remote side)
    ↓
RemoteEventCollector.collect() → EventSyncBridge → Event Store
    ↓
ValidationEngine → ReportingEngine → EvidenceExporter → ManualVerificationPackageGenerator
```

**Validated families:** **jsp**, **php**  
**Preview (not validated):** **aspx** — contract and transport exist; Windows IIS execution pending  
Transport: HTTP GET/POST command delivery, multipart upload, GET download by `remote_path`.

**CLI example:**

```bash
dsp run --profile normal --target-net 10.10.10.0/24 \
  --execution-provider webshell \
  --webshell-family jsp \
  --webshell-url http://10.10.10.20:8080/shell.jsp \
  --remote-work-dir /tmp/dsp
```

---

## Event Collection Flow

After remote scenario execution, RunManager triggers collection per scenario:

```
RemoteEventCollector.collect()
    ↓
WebshellExecutionProvider.download_file(remote_bundle_path)
    ↓
EventSyncBridge.sync_bundle(local_bundle_path, event_store)
    ↓
Event Store (append-only import)
```

**Bundle contract:** JSONL with metadata header row (`_bundle_metadata: true`) followed by event rows.  
`run_id` in bundle metadata must match the open Event Store run.

**Conventional remote path:** `/tmp/dsp/<run_id>/events.jsonl` (Linux validated)

---

## Evidence Export Flow

Evidence export runs automatically on `dsp run` completion (local and webshell):

```
EvidenceExporter.export(EvidenceExportRequest)
    ↓
Event Store.list_events(run_id)
    ↓
run_<run_id>.json
run_<run_id>.md
```

---

## Manual Verification Flow

Manual verification templates are generated on run completion:

```
EvidenceExporter (prerequisite)
    ↓
ManualVerificationPackageGenerator.generate()
    ↓
verification_checklist.md
investigation_notes.md
evidence_summary_template.md
```

These files are **templates for human review**. They do not assert attack success, detection success, alert creation, or case correlation.

---

## E2E Test Command

```bash
cd xdr-poc-script
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"

# Release 1.0 E2E harness only
pytest tests/e2e -v

# Full test suite
pytest
```

E2E tests verify:

1. Local path reaches Event Store
2. Webshell path reaches Event Store via downloaded `events.jsonl`
3. Evidence export from imported events
4. Manual verification package generation
5. No detection / attack / alert validation logic in the harness

---

## Known Non-Goals (Release 1.0)

| Non-goal | Notes |
|----------|-------|
| **Dedicated evidence CLI** | No separate `dsp evidence export` command; export runs via RunManager on `dsp run` |
| **Detection validation in E2E** | E2E harness excludes detection adapters, alert/case checks |
| **Attack / detection success inference** | No `execution_success`, `attack_success`, or alert outcome fields |
| **Agent / SSH execution providers** | Local and webshell only |
| **ASPX production readiness** | ASPX is preview until Windows IIS validation completes |
| **Deployment automation integration** | DSP remains separate from XDR lab appliance tooling |
| **Live SIEM/XDR required for tests** | `pytest` and `tests/e2e` run offline |

---

## Related Documents

| Document | Purpose |
|----------|---------|
| [RELEASE_NOTES.md](./RELEASE_NOTES.md) | Version history and validation milestones |
| [docs/validation/RELEASE_DOCUMENTATION_AUDIT.md](./docs/validation/RELEASE_DOCUMENTATION_AUDIT.md) | Documentation audit and public statement draft |
| [RELEASE_1_0_LAB_GUIDE.md](./RELEASE_1_0_LAB_GUIDE.md) | Manual lab verification procedure |
| [README.md](./README.md) | Quick start and project overview |
| [docs/validation/JSP_REAL_WEBSHELL_VALIDATION_REPORT.md](./docs/validation/JSP_REAL_WEBSHELL_VALIDATION_REPORT.md) | JSP real validation evidence |
| [docs/validation/PHP_REAL_WEBSHELL_VALIDATION_REPORT.md](./docs/validation/PHP_REAL_WEBSHELL_VALIDATION_REPORT.md) | PHP real validation evidence |
| [docs/validation/ASPX_REAL_WEBSHELL_VALIDATION_REPORT.md](./docs/validation/ASPX_REAL_WEBSHELL_VALIDATION_REPORT.md) | ASPX status (NOT READY) |
| [ARCHITECTURE_SPEC.md](./ARCHITECTURE_SPEC.md) | Component architecture |
| [EVENT_SCHEMA_FREEZE.md](./EVENT_SCHEMA_FREEZE.md) | Event entity contract v1.0.0 |
