# Detection Scenario Platform (DSP)

**Generate realistic, observable security activity for XDR and NDR customer POC validation.**

DSP helps POC engineers create repeatable security activity when a customer environment is too quiet to produce enough useful detections during an evaluation. It runs controlled scenarios against an authorized target network, records structured execution evidence, and produces reports that can be compared with XDR/NDR detections.

> DSP validates **activity and event generation**. It does not automatically claim that a vendor alert fired or that an XDR case was correlated.

## Install & run

Requirements: Linux, Git, curl, and Python 3.11+ with `venv` support.

```bash
curl -fsSL https://raw.githubusercontent.com/xdr-labs/xdr-poc-script/release/v1.4.0-rc/install-dsp.sh | bash
```

The installer uses `$HOME/xdr-poc-script` by default, creates `.venv`, installs DSP, preserves `~/.dsp/`, and opens the operator menu.

Then:

1. Choose **Configure environment**.
2. Set the authorized target CIDR.
3. Use **local** + **normal** for the first run.
4. Choose **Run scenario**.
5. Use **Show latest report** to review the result.

Run artifacts are stored under:

```text
~/.dsp/runs/<run_id>/
```

The most useful first files are `traffic_summary.json`, `report.md`, and `verification_checklist.md`.

## Operational profiles

| Profile | Behavior |
| --- | --- |
| `normal` | Default; representative target coverage |
| `high` | Same per-target volume, expanded across more discovered targets |

Legacy aliases are still normalized by the runtime (`low`/`balanced` → `normal`, `burst` → `high`), but new usage should use only `normal` and `high`.

## Execution modes

| Mode | Use |
| --- | --- |
| `local` | Generate activity directly from the DSP host |
| `webshell` | Generate activity from an authorized remote host inside the target environment |

Validated webshell families: **JSP** and **PHP**. **ASPX/Windows IIS remains preview** because real Windows runtime validation is still pending.

## Current release

- Package version: **1.4.0**
- Active operator branch: **`release/v1.4.0-rc`**
- Release status: **READY WITH KNOWN LIMITATIONS**
- Python requirement: **3.11+**

The older `release/v1.4.0` branch is retired by the installer/menu because it contains stale traffic-volume behavior.

## Documentation

Full English and Korean documentation:

**https://dsp.xdr.ooo**

The documentation covers Quick Start, POC workflow, scenario coverage, local/webshell operation, reports/evidence, safety guardrails, CLI reference, validation status, and architecture.

## Safety

Use DSP only in an explicitly authorized lab or customer POC scope. Networks wider than `/24` require both `--allow-large-target` and `--max-hosts`.

For detailed scope and limitations, see `RELEASE_1_0_SUMMARY.md`, `RELEASE_NOTES.md`, and the validation reports under `docs/validation/`.
