"""Command executor attaches discovery HTTP selection to follow-up events."""

from __future__ import annotations

from unittest.mock import MagicMock

from dsp.engine import RunConfig, RunContext
from dsp.event_store import EventStore
from dsp.execution.remote.command.execute import execute_command_plan
from dsp.execution.remote.models import ScenarioExecutionRequest


def test_http_followup_command_events_include_selected_targets(tmp_path) -> None:
    store = EventStore(tmp_path / "events.db")
    store.open_run("run-http")
    ctx = RunContext(
        run_id="run-http",
        target_net="221.139.249.0/24",
        event_store=store,
        config=RunConfig(scenario_params={}),
        dry_run=True,
    )
    provider = MagicMock()
    provider.execute_command.return_value = MagicMock(status=MagicMock(value="completed"))

    plan = {
        "type": "http_followup",
        "mode": "mock",
        "timeout": 5.0,
        "requests": [{"url": "http://221.139.249.110/", "method": "GET", "user_agent": "Mozilla/5.0"}],
        "selected_targets": [
            "221.139.249.110:80 (discovered_http_service_unverified_from_dsp_host)",
        ],
        "target_count": 1,
        "http_targets": ["221.139.249.110"],
        "hosts": ["221.139.249.110"],
    }
    request = ScenarioExecutionRequest(
        scenario_id="http_followup",
        scenario_params={},
        execution_metadata={},
        run_id="run-http",
        target_net="221.139.249.0/24",
        dry_run=True,
    )

    execute_command_plan(plan, provider, ctx, request)
    events = {event.event: event for event in store.list_events("run-http")}
    assert events["http_followup_started"].evidence["selected_targets"]
    assert events["http_followup_completed"].evidence["target_count"] == 1
    assert events["http_followup_completed"].evidence["requests_sent"] == 1
    completed = events["http_followup_completed"].evidence
    assert len(completed["request_evidence"]) == 1
    assert completed["request_evidence"][0]["dispatch_status"] == "completed"
    assert completed["request_dump_summary"]["sample_count"] == 1
    assert completed["response_tracking"] == "disabled_webshell_mode"
    store.close()
