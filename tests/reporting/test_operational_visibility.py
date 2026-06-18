"""Tests for operational visibility reconciliation."""

from __future__ import annotations

from datetime import datetime, timezone

from dsp.event_store import Event, EventStore, ValidationDecision, ValidationResult
from dsp.reporting.operational_visibility import (
    build_scenario_reconciliations,
    derive_execution_reconciliation,
    reconcile_scenario,
)
from dsp.runner.run_manager import compute_exit_code


def _event(scenario_id: str, name: str, evidence: dict | None = None) -> Event:
    return Event(
        run_id="run1",
        scenario_id=scenario_id,
        timestamp=datetime.now(timezone.utc),
        stage="executor",
        event=name,
        status="info",
        source="local",
        evidence=evidence or {},
    )


def test_derive_execution_reconciliation_partial():
    status, reason = derive_execution_reconciliation(800, 400, timeouts=2)
    assert status == "partial"
    assert reason == "response_limit"


def test_build_scenario_reconciliations_skipped_smb():
    events = [
        _event(
            "smb_login_failure",
            "smb_scenario_skipped",
            {"reason": "no_smb_service_discovered"},
        ),
    ]
    recon = build_scenario_reconciliations(events, ["smb_login_failure"], {})
    row = recon["smb_login_failure"]
    assert row["execution_status"] == "skipped"
    assert row["execution_reason"] == "no_smb_service_discovered"
    assert row["planned"] == 0


def test_build_scenario_reconciliations_http_partial():
    events = [
        _event(
            "http_followup",
            "http_followup_started",
            {"planned_requests": 800},
        ),
        _event(
            "http_followup",
            "http_followup_completed",
            {
                "requests_sent": 400,
                "request_count": 400,
                "execution_status": "partial",
                "execution_reason": "scenario_cap",
            },
        ),
    ]
    recon = build_scenario_reconciliations(events, ["http_followup"], {})
    row = recon["http_followup"]
    assert row["planned"] == 800
    assert row["actual"] == 400
    assert row["execution_status"] == "partial"
    assert row["execution_reason"] == "scenario_cap"
    assert row["execution_ratio_pct"] == 50.0


def test_compute_exit_code_partial_is_zero():
    partial = ValidationResult(
        run_id="r",
        scenario_id="http_followup",
        decision=ValidationDecision.PARTIAL,
        reason="partial_thresholds_met",
        metrics={},
        validated_at=datetime.now(timezone.utc),
    )
    assert compute_exit_code([partial]) == 0


def test_compute_exit_code_failed_is_one():
    failed = ValidationResult(
        run_id="r",
        scenario_id="http_followup",
        decision=ValidationDecision.FAILED,
        reason="thresholds_not_met",
        metrics={},
        validated_at=datetime.now(timezone.utc),
    )
    assert compute_exit_code([failed]) == 1


def test_reconcile_scenario_from_store(tmp_path):
    store = EventStore(tmp_path / "events.db")
    store.open_run("run1")
    store.append(
        _event(
            "sql_injection",
            "sql_injection_started",
            {"planned_requests": 10},
        )
    )
    store.append(
        _event(
            "sql_injection",
            "sql_injection_completed",
            {
                "requests_sent": 10,
                "execution_status": "full",
                "execution_reason": "completed",
            },
        )
    )
    row = reconcile_scenario(store, "run1", "sql_injection")
    assert row["execution_status"] == "full"
    assert row["actual"] == 10
    store.close()
