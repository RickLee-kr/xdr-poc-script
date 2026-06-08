# DSP Known Execution Modes

**문서 버전:** 1.0.0  
**상태:** Live Validation — 실행 경로 조사 결과  
**조사 일자:** 2026-06-05

---

## 1. Summary

| Method | Command | Officially Supported | Notes |
|--------|---------|---------------------|-------|
| **A** | `dsp ...` | **Yes — Primary** | Requires `pip install -e .` + venv activation |
| **B** | `.venv/bin/dsp ...` | **Yes — Primary** | Explicit venv path; CI/scripts 권장 |
| **C** | `python -m dsp.runner.cli ...` | **Yes — Secondary** | Module entry; no install script needed if PYTHONPATH set |
| **D** | `python -m dsp ...` | **No** | `dsp/__main__.py` absent → fails |
| **E** | `python -c "from dsp.runner.cli import main; ..."` | **No** | Programmatic only; not operator-facing |

---

## 2. Method A — Console Script (Primary)

**Registration:** `pyproject.toml` → `[project.scripts] dsp = "dsp.runner.cli:main"`

```bash
cd detection-scenario-platform
source .venv/bin/activate
pip install -e ".[dev]"

dsp --version
dsp plugins list
dsp run --scenarios dns_tunnel --dry-run
```

**When to use:** Interactive operator sessions, documented quick start.

**Failure mode:** `Command 'dsp' not found` — package not installed or venv not activated.

---

## 3. Method B — Venv Absolute Path (Primary)

```bash
/path/to/detection-scenario-platform/.venv/bin/dsp run --scenarios dummy --dry-run
```

**When to use:** Shell scripts, cron, CI pipelines, non-interactive lab automation.

**Verified:** `.venv/bin/dsp` shebang → `.venv/bin/python3`; entry point wrapper installed by pip.

---

## 4. Method C — Module Invocation (Secondary)

```bash
cd detection-scenario-platform
.venv/bin/python -m dsp.runner.cli run --scenarios dummy --dry-run
.venv/bin/python -m dsp.runner.cli --version
.venv/bin/python -m dsp.runner.cli plugins list
```

**Implementation:** `dsp/runner/cli.py` contains `if __name__ == "__main__": sys.exit(main())`

**When to use:** Debugging, environments where console_scripts shim is missing but package is importable.

**Officially supported:** Yes, as documented fallback. Not the primary operator path.

---

## 5. Method D — `python -m dsp` (NOT Supported)

```bash
python3 -m dsp
# /usr/bin/python3: No module named dsp.__main__; 'dsp' is a package and cannot be directly executed
```

**Root cause:** No `dsp/__main__.py` delegating to `dsp.runner.cli:main`.

**Impact:** Operators following generic Python `-m package` convention will fail.

**Workaround:** Use Method A, B, or C.

**Status:** Not officially supported. Adding `__main__.py` would be a packaging enhancement (out of scope for live validation freeze).

---

## 6. Method E — Python API (Internal / Advanced)

```python
from dsp.runner.run_manager import RunManager

manager = RunManager()
run, run_dir, exit_code = manager.run(
    scenario_ids=["dns_tunnel"],
    target_net="10.10.10.0/24",
    dry_run=True,
    scenario_params={"dns_tunnel": {"max_chunks": 50}},  # CLI does not expose this
    confirm_detection=False,
    stellar_client="mock",
)
```

**When to use:** Tests, custom tooling, scenario_params override.

**Officially supported for operators:** No. Supported for developers and test suite.

---

## 7. Subcommand Reference

All methods A–C share identical CLI surface via `dsp.runner.cli:main`:

```
dsp [-h] [--version] {run,plugins,report} ...

  run       Execute scenarios
  plugins   Plugin management (sub: list)
  report    Regenerate report from run artifacts
```

### 7.1 `run` arguments

```
--scenarios SCENARIOS     (required, comma-separated)
--dry-run                 (flag)
--target-net TARGET_NET   (default: 10.10.10.0/24)
--confirm-detection       (flag)
--detection-provider      (default: stellar)
--stellar-client {manual,mock,http}   (default: manual)
```

---

## 8. Installation Methods

| Method | Command | Produces `dsp` script |
|--------|---------|----------------------|
| Editable install | `pip install -e ".[dev]"` | Yes → `.venv/bin/dsp` |
| Wheel install | `pip install dist/dsp-1.0.0-py3-none-any.whl` | Yes → site-packages + scripts dir |
| No install + PYTHONPATH | `PYTHONPATH=. python -m dsp.runner.cli` | No script; module only |

**No `setup.py` / `setup.cfg` / `requirements.txt`** in DSP project — `pyproject.toml` only.

---

## 9. Path Equality Requirement

All execution modes must converge on:

```
RunManager.run() → EventStore → ValidationEngine → ReportingEngine
```

No alternate stdout/grep validation paths. Verified by `tests/validation/test_path_equality.py`.

---

## 10. Decision Matrix for Operators

| Situation | Recommended Mode |
|-----------|------------------|
| First-time lab setup | **A** — activate venv, use `dsp` |
| Automation script | **B** — `.venv/bin/dsp` full path |
| `dsp` not found debugging | **B** or reinstall `pip install -e .` |
| `-m dsp` habit | **C** — use `-m dsp.runner.cli` instead |
| Custom scenario_params | **E** — Python API (not CLI) |

---

## Related Documents

- [EXECUTION_GUIDE.md](./EXECUTION_GUIDE.md)
- [ENVIRONMENT_VALIDATION.md](./ENVIRONMENT_VALIDATION.md)
- [LIVE_VALIDATION_CHECKLIST.md](./LIVE_VALIDATION_CHECKLIST.md)
