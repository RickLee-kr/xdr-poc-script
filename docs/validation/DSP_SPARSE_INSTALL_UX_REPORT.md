# DSP Sparse Install UX Report

**Release baseline:** `release/v1.4.0` @ tag `v1.4.1`  
**Date:** 2026-06-18  
**Scope:** Install/update UX only — no DSP runtime, scenario, or packaging refactor changes.

---

## Summary

Default `install-dsp.sh` and menu **Update latest patch** now use **git sparse-checkout (non-cone)** so operators receive a runtime-focused tree. Full clone remains available via `DSP_FULL_CLONE=1`. Existing full-clone installs are not auto-pruned; guidance is printed instead.

**Final verdict: PASS**

---

## 1. Before / after directory comparison

Validation host: Ubuntu, git 2.43.0, Python 3.12.

| Metric | Full clone (before / `DSP_FULL_CLONE=1`) | Sparse runtime (after / default) |
|--------|------------------------------------------|----------------------------------|
| Root-level entries (`ls -1`) | 49 | 10 |
| Total files on disk (`find -type f`) | 1,697 | 1,466 |
| Disk usage (`du -sh`, incl. `.venv`) | 24M | 22M |
| `tests/` present | Yes | No |
| Root `*_SPEC.md` / `ARCHITECTURE_*` / `PHASE_*` | Yes | No |
| `docs/validation/` | Yes | No |

### Sparse install root listing (`ls -1`)

```text
docs
dsp
dsp-menu.sh
install-dsp.sh
pyproject.toml
README.md
RELEASE_1_0_LAB_GUIDE.md
RELEASE_NOTES.md
scenarios
scripts
```

### `docs/` after sparse install

```text
DSP_BOOTSTRAP_INSTALL.md
DSP_MENU.md
```

---

## 2. Included paths (sparse cone)

Applied via `git sparse-checkout init --no-cone` and `git sparse-checkout set`:

| Path | Role |
|------|------|
| `/dsp` | DSP package |
| `/scenarios` | Scenario plugins |
| `/scripts` | Helper scripts (`dsp-menu.sh` shim, `dsp-runtime-sparse.sh`) |
| `/pyproject.toml` | Editable install metadata |
| `/README.md` | Operator readme |
| `/install-dsp.sh` | Bootstrap installer |
| `/dsp-menu.sh` | Operator TUI |
| `/docs/DSP_MENU.md` | Menu documentation |
| `/docs/DSP_BOOTSTRAP_INSTALL.md` | Install documentation |
| `/RELEASE_NOTES.md` | Optional release notes |
| `/RELEASE_1_0_LAB_GUIDE.md` | Optional lab guide |
| `/.gitignore` | Git ignore rules |

Canonical list: `scripts/dsp-runtime-sparse.sh` (kept in sync with `install-dsp.sh`).

---

## 3. Excluded paths (representative)

Not checked out in sparse mode (verified absent under `/tmp/dsp-sparse-val`):

| Category | Examples |
|----------|----------|
| Tests | `tests/` |
| Lab | `lab/` (not present on this branch; excluded by pattern) |
| Architecture / phase docs | `ARCHITECTURE_SPEC.md`, `PHASE_ROADMAP.md`, … |
| Specs | `*_SPEC.md`, `*_REVIEW.md`, `*_MATRIX.md` |
| Product / WBS | `PRODUCT-CHARTER*`, `MASTER-WBS*` |
| Validation / archive docs | `docs/validation/`, `docs/archive/` |
| IDE | `.cursor/` |
| Other dev docs | `WORKSPACE_BOUNDARY.md`, `RELEASE_1_0_SUMMARY.md`, … |

Sample of 38 root entries present in full clone but absent in sparse:

```text
ARCHITECTURE_SPEC.md
PHASE_ROADMAP.md
SCENARIO_MANIFEST_SPEC.md
PRODUCT-CHARTER-Version-1.2-Discovery-Execution-Model.md
tests
WORKSPACE_BOUNDARY.md
…
```

---

## 4. Full clone fallback

| Scenario | Behavior |
|----------|----------|
| **Developer needs entire repo** | `DSP_FULL_CLONE=1 bash install-dsp.sh` |
| **Git without sparse-checkout** | Installer logs fallback and performs full clone |
| **Existing full clone — reinstall** | Pull only; prints NOTE with clean-reinstall instructions; **does not delete** extra files |
| **Switch full → sparse** | `rm -rf "$DSP_REPO_DIR"` then re-run installer (default sparse) |

Clean runtime reinstall example:

```bash
rm -rf /path/to/xdr-poc-script
DSP_NO_LAUNCH=1 bash install-dsp.sh
```

---

## 5. Implementation touchpoints

| File | Change |
|------|--------|
| `install-dsp.sh` | Sparse clone/update, `DSP_FULL_CLONE`, full-clone notice |
| `scripts/dsp-runtime-sparse.sh` | Shared sparse path list and helpers |
| `dsp-menu.sh` | Update maintains sparse; status shows `Install type: sparse\|full` |
| `README.md` | Sparse default documented |
| `docs/DSP_BOOTSTRAP_INSTALL.md` | Sparse / full / migration documented |
| `docs/DSP_MENU.md` | Update row notes sparse maintenance |

---

## 6. Verification results

Environment: clean temp dirs under `/tmp`, local mirror `file:///home/aella/xdr-poc-script`, branch `release/v1.4.0-rc`, workspace `install-dsp.sh` (sparse logic not yet on remote tag).

| Check | Command / action | Result |
|-------|------------------|--------|
| Script syntax | `bash -n install-dsp.sh dsp-menu.sh scripts/dsp-runtime-sparse.sh` | PASS |
| Clean sparse install | `DSP_NO_LAUNCH=1 bash install-dsp.sh` → `/tmp/dsp-sparse-val` | PASS — `install type: sparse` |
| Runtime-focused `ls` | `ls -1` root + excluded path probes | PASS — 10 root entries; no `tests/`, specs, `docs/validation/` |
| `dsp --version` | `.venv/bin/dsp --version` | PASS — `dsp 1.4.1` |
| `dsp run` | `dsp run --profile low --target-net 127.0.0.1/32` | PASS — exit 0, run artifacts under `~/.dsp/runs/` |
| Scenario loading | Run completed with multi-scenario traffic summary | PASS |
| Re-install on sparse | Re-run installer on existing sparse repo | PASS — `maintaining sparse runtime checkout` |
| `git pull` on sparse | Pull + re-apply sparse paths | PASS — 12 sparse patterns retained |
| Full clone option | `DSP_FULL_CLONE=1` | PASS — 49 root entries, `install type: full` |
| Full clone re-install notice | Re-run installer on full clone | PASS — NOTE printed, no auto-delete |
| Menu update logic | `dsp_apply_sparse_checkout` after pull (helper sourced) | PASS |

**Note:** Interactive `dsp-menu.sh` TUI was not exercised in CI-style automation (whiptail blocks non-interactive stdin). Menu shell logic is covered by the same sparse helper used in install.

---

## 7. Known limitations

1. **GitHub raw installer** — operators should curl `install-dsp.sh` from tag `v1.4.1` (v1.4.0 tag unchanged).
2. **Manual `git clone`** without the installer still yields a full tree; canonical path is `install-dsp.sh`.
3. **`--filter=blob:none`** may log `filtering not recognized by server` for `file://` mirrors; sparse checkout still succeeds.
4. **Disk savings** are modest in this repo (~2M less with venv) because `dsp/` and `scenarios/` dominate; primary win is **operator-facing directory cleanliness**, not size.

---

## 8. Final verdict

**PASS** — Default install and update preserve a runtime-only working tree; full clone and migration paths behave as specified; `dsp --version`, `dsp run`, and scenario execution work on sparse installs.
