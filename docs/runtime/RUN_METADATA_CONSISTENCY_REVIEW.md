# Run Metadata Consistency Review

**Phase:** Live validation readiness  
**Status:** Root cause identified and corrected  
**Audience:** Platform engineers, lab operators

---

## 1. Observed Issue

After a successful run:

```
Run 20260606_xxxxxx status=completed
```

`run.json` correctly showed:

```json
"status": "completed",
"ended_at": "2026-06-06T..."
```

But `report.md` and `report.json` embedded run metadata with:

```json
"status": "running",
"ended_at": null
```

**Impact:** Operators and automation reading reports could conclude the run was still in progress, despite CLI and `run.json` indicating completion.

---

## 2. Execution Sequence (Before Fix)

`RunManager.run()` in `dsp/runner/run_manager.py`:

| Step | Action | `run.status` | `run.ended_at` | Artifacts written |
|------|--------|--------------|----------------|-------------------|
| 1 | Create run, open Event Store | `running` | `null` | — |
| 2 | Execute scenarios | `running` | `null` | manifest snapshots |
| 3 | S2 validation | `running` | `null` | `validation.json` |
| 4 | **Generate report** | `running` | `null` | **`report.md`, `report.json`** |
| 5 | Optional S3 confirmation | `running` | `null` | evidence pack |
| 6 | Rewrite report (if S3) | `running` | `null` | report rewrite |
| 7 | Export JSONL, close store | `running` | `null` | `events.jsonl` |
| 8 | **Finalize run state** | **`completed`** | **timestamp** | **`run.json`** |

**Root cause:** Reports snapshot `run.to_dict()` at step 4 while the in-memory `Run` object is still `status=running`, `ended_at=null`. Finalization occurs at step 8 — after reports are already written.

The reporting engine (`dsp/reporting/engine.py`) embeds run metadata verbatim:

```python
run_metadata = run.to_dict() if run else {"run_id": run_id}
```

There is no post-finalization refresh.

---

## 3. Divergence Analysis

| Artifact | Source of run metadata | Pre-fix final state |
|----------|------------------------|---------------------|
| `run.json` | Written after finalization | `completed` + `ended_at` |
| `report.json` → `run_metadata` | Snapshot at report generation | `running` + `null` |
| `report.md` → Run Metadata JSON block | Same snapshot | `running` + `null` |

**Can they diverge?** Yes — by design of the old ordering. This is not a serialization bug; it is a **lifecycle ordering bug**.

S3 confirmation (`--confirm-detection`) made the problem worse by rewriting reports (step 6) while still not finalizing run state.

---

## 4. Validation Failure Case

When S2 validation fails (`decision=failed`), the run **execution still completes**. DSP uses:

- `RunStatus.COMPLETED` — run lifecycle finished
- `ValidationDecision.FAILED` — S2 outcome (drives exit code)

There is no `RunStatus.FAILED`. Pre-fix, validation failures had the same metadata inconsistency (`running` in reports, `completed` in `run.json` after step 8).

---

## 5. Correction Applied

Reordered `RunManager.run()`:

1. Execute scenarios
2. S2 validation → `validation.json`
3. Optional S3 confirmation → evidence pack
4. **Finalize run:** `status=completed`, `ended_at=now`
5. **Generate report once** with finalized `Run`
6. Export JSONL, close store, write `run.json`

Reports and `run.json` now share the same finalized `Run` object.

---

## 6. Impact

| Area | Impact |
|------|--------|
| Operator trust | Reports now match CLI completion message |
| Automation | Parsers of `report.json` / `report.md` metadata reliable |
| S3 workflow | Manual evidence templates reference correct run window |
| Exit codes | Unchanged — still S2-derived only |

---

## 7. Recommended Ongoing Checks

- Run `tests/runner/test_run_metadata_consistency.py` in CI
- After live validation, verify: `run.json` status == `report.json` run_metadata status
- Use `dsp report --run-id <id>` to regenerate from finalized `run.json` if needed

---

## 8. Related Files

| File | Role |
|------|------|
| `dsp/runner/run_manager.py` | Run lifecycle ordering (corrected) |
| `dsp/reporting/engine.py` | Embeds `run.to_dict()` in reports |
| `dsp/event_store/models.py` | `Run`, `RunStatus` definitions |
| `tests/runner/test_run_metadata_consistency.py` | Regression tests |
