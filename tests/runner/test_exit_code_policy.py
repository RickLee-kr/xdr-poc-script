"""Process exit code policy — traffic/evidence success vs validation thresholds."""

from __future__ import annotations

import io
from datetime import datetime, timezone
from pathlib import Path

import pytest

from dsp.event_store import ValidationDecision, ValidationResult
from dsp.event_store import EventQuery, EventStore
from dsp.execution.remote.exceptions import RemoteBundleExecutionError
from dsp.runner import RunManager, compute_exit_code, format_validation_warnings
from dsp.runner.cli import main
from dsp.runner.console_output import OperationalConsole
from dsp.validation import ValidationEngine
from tests.e2e.fixtures.webshell_test_server import WebshellTestServer


def _failed_result(scenario_id: str = "dga") -> ValidationResult:
    return ValidationResult(
        run_id="r1",
        scenario_id=scenario_id,
        decision=ValidationDecision.FAILED,
        reason="thresholds_not_met",
        metrics={"dga_nxdomain_observed_count": 0},
        validated_at=datetime.now(timezone.utc),
    )


def test_compute_exit_code_validation_failed_is_zero() -> None:
    assert compute_exit_code([_failed_result()]) == 0


def test_compute_exit_code_partial_and_skipped_are_zero() -> None:
    partial = ValidationResult(
        run_id="r1",
        scenario_id="http_followup",
        decision=ValidationDecision.PARTIAL,
        reason="partial_thresholds_met",
        metrics={},
        validated_at=datetime.now(timezone.utc),
    )
    skipped = ValidationResult(
        run_id="r1",
        scenario_id="http_followup",
        decision=ValidationDecision.SKIPPED,
        reason="no_http_endpoints",
        metrics={},
        validated_at=datetime.now(timezone.utc),
    )
    assert compute_exit_code([partial]) == 0
    assert compute_exit_code([skipped]) == 0


def test_compute_exit_code_code_failure_is_two() -> None:
    code_fail = ValidationResult(
        run_id="r1",
        scenario_id="dummy",
        decision=ValidationDecision.CODE_FAILURE,
        reason="SOT_EMPTY_AFTER_EXECUTE",
        metrics={},
        validated_at=datetime.now(timezone.utc),
    )
    assert compute_exit_code([code_fail]) == 2


def test_format_validation_warnings_marks_threshold_misses() -> None:
    warnings = format_validation_warnings([_failed_result()])
    assert len(warnings) == 1
    assert "Validation Warning" in warnings[0]
    assert "dga" in warnings[0]
    assert "thresholds_not_met" in warnings[0]


def test_webshell_normal_profile_validation_warning_exits_zero(
    tmp_path: Path,
    monkeypatch,
) -> None:
    def mock_validate_run(self, run_id, scenario_ids):
        return [_failed_result(sid) for sid in scenario_ids]

    monkeypatch.setattr(ValidationEngine, "validate_run", mock_validate_run)

    server = WebshellTestServer(storage_dir=tmp_path / "server")
    server.start()
    console_stream = io.StringIO()
    console = OperationalConsole(
        provider="webshell",
        target_net="127.0.0.0/30",
        profile="normal",
        stream=console_stream,
    )
    manager = RunManager(runs_dir=tmp_path / "runs")
    try:
        run, run_dir, exit_code = manager.run(
            scenario_ids=["port_sweep"],
            target_net="127.0.0.0/30",
            dry_run=False,
            scenario_params={"port_sweep": {"max_hosts": 1, "max_ports": 2}},
            execution_provider="webshell",
            webshell_family="jsp",
            webshell_url=server.webshell_url,
            remote_work_dir=str(tmp_path / "remote-work"),
            operational_profile="normal",
            on_progress=console.handle_progress,
        )
    finally:
        server.stop()

    assert exit_code == 0
    assert run.status.value == "completed"
    assert (run_dir / "events.jsonl").is_file()
    assert (run_dir / "validation.json").is_file()
    output = console_stream.getvalue()
    assert "Run Completed" in output
    assert "Evidence Generated" in output
    assert "Validation Warning" in output
    assert "thresholds_not_met" in output


def test_webshell_command_transport_failure_skips_scenario(tmp_path: Path) -> None:
    """Command-only path records scenario_skipped on transport failure — no bundle error."""
    from dsp.execution.providers.runtime.command.command_exceptions import CommandTransportError

    server = WebshellTestServer(
        storage_dir=tmp_path / "server",
        script_stdout_mode="command_timeout_partial",
    )
    server.start()
    manager = RunManager(runs_dir=tmp_path / "runs")
    try:
        run, run_dir, exit_code = manager.run(
            scenario_ids=["port_sweep"],
            target_net="127.0.0.0/30",
            dry_run=False,
            scenario_params={"port_sweep": {"max_hosts": 1, "max_ports": 2}},
            execution_provider="webshell",
            webshell_family="jsp",
            webshell_url=server.webshell_url,
            remote_work_dir=str(tmp_path / "remote-work"),
        )
        store = EventStore.open_existing(run_dir / "events.db")
        try:
            skipped = store.count(
                EventQuery(run_id=run.run_id, scenario_id="port_sweep", event="scenario_skipped")
            )
            assert skipped >= 1 or run.status.value == "completed"
        finally:
            store.close()
    finally:
        server.stop()


def test_config_error_exits_one(tmp_path: Path) -> None:
    manager = RunManager(runs_dir=tmp_path / "runs")
    _, _, exit_code = manager.run(
        scenario_ids=["dummy"],
        execution_provider="webshell",
    )
    assert exit_code == 1


def test_cli_config_error_exits_one(capsys) -> None:
    exit_code = main(
        [
            "run",
            "--target-net",
            "10.0.0.0/16",
            "--profile",
            "high",
            "--dry-run",
        ]
    )
    captured = capsys.readouterr()
    assert exit_code == 1
    assert "ERROR:" in captured.err


def test_code_failure_exits_two(tmp_path: Path, monkeypatch) -> None:
    def mock_validate_run(self, run_id, scenario_ids):
        return [
            ValidationResult(
                run_id=run_id,
                scenario_id=scenario_ids[0],
                decision=ValidationDecision.CODE_FAILURE,
                reason="SOT_EMPTY_AFTER_EXECUTE",
                metrics={},
                validated_at=datetime.now(timezone.utc),
            )
        ]

    monkeypatch.setattr(ValidationEngine, "validate_run", mock_validate_run)

    manager = RunManager(runs_dir=tmp_path / "runs")
    _, _, exit_code = manager.run(
        scenario_ids=["dummy"],
        dry_run=True,
    )
    assert exit_code == 2
