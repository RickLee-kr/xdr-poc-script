# Release Documentation Audit

**Branch:** `release/v1.4.0-rc`  
**Date:** 2026-06-18  
**Scope:** Release-facing documentation vs. Release 1.0 Readiness Audit results  
**Audit type:** Documentation only — no code, runtime, or test changes

---

## Audit Sources

| Document | Role |
|----------|------|
| `README.md` | Primary operator entry point |
| `RELEASE_1_0_SUMMARY.md` | Release 1.0 scope and flow reference |
| `RELEASE_NOTES.md` | Version history and validation milestones |
| `docs/DSP_MENU.md` | Operator menu reference |
| `RELEASE_1_0_LAB_GUIDE.md` | Manual lab verification procedure |

**Validation evidence (read-only reference):**

- `docs/validation/JSP_REAL_WEBSHELL_VALIDATION_REPORT.md`
- `docs/validation/PHP_REAL_WEBSHELL_VALIDATION_REPORT.md`
- `docs/validation/ASPX_REAL_WEBSHELL_VALIDATION_REPORT.md`
- `docs/ASPX_WINDOWS_COMPATIBILITY_AUDIT.md`

---

## Findings — Before Audit

### README.md

| Topic | Documented | Actual (audit) | Mismatch |
|-------|------------|----------------|----------|
| Release validation status | Not stated | Local, JSP, PHP READY; ASPX NOT READY | **Missing** |
| Validated platforms | Not stated | Linux validated (JSP/PHP on `victim-linux`) | **Missing** |
| Webshell families | JSP / PHP / ASPX listed equally | JSP + PHP real E2E; ASPX preview only | **Overstated for ASPX** |
| Windows webshell path | Not mentioned | Not validated | **Missing** |

### RELEASE_1_0_SUMMARY.md

| Topic | Documented | Actual (audit) | Mismatch |
|-------|------------|----------------|----------|
| Release status | "Release candidate" (generic) | READY WITH KNOWN LIMITATIONS | **Incomplete** |
| Webshell in `dsp run` | "Not wired into `dsp run`" | Wired since v1.2 (`--execution-provider webshell`) | **Stale** |
| Evidence export | "API-only in Release 1.0" | RunManager exports on `dsp run` completion | **Stale** |
| RunManager auto-collect | "Not triggered automatically" | Per-scenario collect on webshell runs | **Stale** |
| Webshell families | JSP / PHP / ASPX equally supported | JSP + PHP validated; ASPX not | **Overstated for ASPX** |
| Release 1.0 scope criteria | Not summarized | All 4 scope items validated via JSP/PHP | **Missing** |
| Known limitations | Non-goals only | ASPX runtime, Windows path pending | **Missing** |

### RELEASE_NOTES.md

| Topic | Documented | Actual (audit) | Mismatch |
|-------|------------|----------------|----------|
| Latest version section | v1.3.0 (2026-06-09) | Package `1.4.0`, branch `release/v1.4.0-rc` | **Out of date** |
| Validation milestones | v1.2.0 live traffic only | JSP 10/10, PHP 10/10, host_behavior_check E2E | **Missing** |
| Known limitations | v1.2.0 table (stale items) | ASPX runtime pending, Windows path pending | **Incomplete** |
| ASPX in v1.2.0 summary | "JSP/PHP/ASPX webshell" without distinction | ASPX not real-validated | **Overstated** |

### docs/DSP_MENU.md

| Topic | Documented | Actual (audit) | Mismatch |
|-------|------------|----------------|----------|
| Webshell family options | `jsp`, `php`, `aspx` in config example | ASPX not validated for production use | **No validation guidance** |
| Validated families | Not stated | JSP + PHP only | **Missing** |

### RELEASE_1_0_LAB_GUIDE.md

| Topic | Documented | Actual (audit) | Mismatch |
|-------|------------|----------------|----------|
| Webshell prerequisite | "JSP / PHP / ASPX reachable" | ASPX real IIS validation not completed | **Overstated for ASPX** |
| Validation status | Not stated | JSP/PHP lab reports exist | **Missing** |

---

## Remediation Applied

See modified document list and change summary below. All updates reflect audit facts only — ASPX is not marked READY.

---

## Modified Document List

| # | Document | Action |
|---|----------|--------|
| 1 | `docs/RELEASE_DOCUMENTATION_AUDIT.md` | **Created** — this audit record |
| 2 | `README.md` | **Updated** — validation status, platforms, families, limitations |
| 3 | `RELEASE_1_0_SUMMARY.md` | **Updated** — status, scope, stale fixes, validation sections |
| 4 | `RELEASE_NOTES.md` | **Updated** — v1.4.0 section, validation milestones, limitations |
| 5 | `docs/DSP_MENU.md` | **Updated** — webshell validation guidance |
| 6 | `RELEASE_1_0_LAB_GUIDE.md` | **Updated** — prerequisite validation status for webshell families |

---

## Change Summary

1. **Release 1.0 status** documented as **READY WITH KNOWN LIMITATIONS** across README and Release Summary.
2. **Validated Runtime Platforms:** Linux validated; Windows not yet validated.
3. **Validated Webshell Families:** JSP and PHP validated on real Tomcat/Apache; ASPX listed as preview / not yet validated.
4. **Known Limitations:** ASPX runtime, Windows webshell execution path, ASPX preview status — factual, no exaggeration.
5. **Stale RELEASE_1_0_SUMMARY corrections:** webshell CLI wiring, RunManager auto-collect, evidence export via `dsp run`.
6. **RELEASE_NOTES v1.4.0** section added with validation milestones and current limitations.
7. **Operator docs** (DSP_MENU, LAB_GUIDE) aligned so ASPX is not presented as production-ready.

---

## Before / After Comparison

### README — Execution modes (webshell families)

**Before:**

> Scenarios run on a remote host through a JSP / PHP / ASPX webshell endpoint

**After:**

> Scenarios run on a remote host through a webshell endpoint. **Validated families:** JSP, PHP. **Preview (not yet validated):** ASPX.

### README — Validation visibility

**Before:** No release validation section.

**After:** `## Release Validation Status` under Quick Start with Local / JSP / PHP validated and ASPX pending.

### RELEASE_1_0_SUMMARY — Webshell CLI

**Before:**

> Webshell execution is available through the Python API. It is **not** wired into `dsp run` in Release 1.0.

**After:**

> Webshell execution is available via `dsp run --execution-provider webshell` and the Python API. Real runtime validation completed for **JSP** and **PHP** only.

### RELEASE_1_0_SUMMARY — Auto-collect

**Before:**

> Remote bundle download not triggered automatically after webshell execute

**After:**

> RunManager triggers per-scenario remote bundle collection on webshell runs (validated on JSP/PHP).

### RELEASE_NOTES — Latest version

**Before:** Top section = DSP v1.3.0 (2026-06-09).

**After:** Top section = DSP v1.4.0 with Release 1.0 validation milestones and known limitations; v1.3.0 retained below.

### DSP_MENU — Webshell config

**Before:** Example `WEBSHELL_FAMILY=jsp` with no validation context.

**After:** Note that JSP and PHP are validated; ASPX is preview only until Windows IIS validation completes.

---

## Release 1.0 Public Statement (Draft)

**DSP Release 1.0**

Release recommendation: **READY WITH KNOWN LIMITATIONS**

### Validated

- **Local Provider** — platform execution, Event Store, validation, and reporting via `dsp run`
- **JSP Webshell Provider** — real Tomcat + `shell.jsp` on Linux (`victim-linux`); 10/10 scenarios including `host_behavior_check`
- **PHP Webshell Provider** — real Apache + PHP + `shell.php` on Linux; 10/10 scenarios including `host_behavior_check`

### Validated Workflows (JSP / PHP real environment)

- Remote command execution
- Remote artifact upload
- Remote bundle download
- Remote scenario runner (bundle + remote CLI scenarios)
- Remote event collection
- Evidence export (JSON + Markdown)
- Manual verification package (checklist, investigation notes, evidence summary templates)

### Validated Runtime Platforms

- **Linux** — local provider and webshell (JSP, PHP) paths validated in lab

### Known Limitations

- **ASPX runtime validation pending** — ASPX contract and HTTP transport exist in code, but real Windows IIS execution has not been validated
- **Windows webshell execution path pending** — bundle runner, collector, artifact handling, and platform dispatch remain Linux-oriented; Windows IIS lab not operational
- **ASPX should be considered preview status** — not recommended for production validation workflows until real IIS validation completes

### Release Scope (CURRENT RELEASE SCOPE — all met via JSP/PHP)

1. Remote execution works
2. Event bundles are collected
3. Evidence packages are exported
4. Manual verification workflow is usable

### References

- JSP validation: `docs/validation/JSP_REAL_WEBSHELL_VALIDATION_REPORT.md`
- PHP validation: `docs/validation/PHP_REAL_WEBSHELL_VALIDATION_REPORT.md`
- ASPX status: `docs/validation/ASPX_REAL_WEBSHELL_VALIDATION_REPORT.md`
- Windows compatibility: `docs/ASPX_WINDOWS_COMPATIBILITY_AUDIT.md`

---

*This audit and the public statement reflect documented lab evidence on `release/v1.4.0-rc` only. No detection, alert, or attack-success claims are made.*
