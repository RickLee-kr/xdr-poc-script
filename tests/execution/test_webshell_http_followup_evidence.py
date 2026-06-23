"""Webshell HTTP follow-up evidence artifact parity tests."""

from __future__ import annotations

import json
from unittest.mock import MagicMock

from dsp.engine import RunConfig, RunContext
from dsp.event_store import EventStore
from dsp.execution.remote.command.execute import execute_command_plan
from dsp.execution.remote.models import ScenarioExecutionRequest
from dsp.runner.run_manager import RunManager, _write_http_followup_artifacts


def test_webshell_http_followup_artifacts_written_from_completed_evidence(tmp_path) -> None:
    store = EventStore(tmp_path / "events.db")
    store.open_run("run-ws-http")
    ctx = RunContext(
        run_id="run-ws-http",
        target_net="10.10.10.0/24",
        event_store=store,
        config=RunConfig(scenario_params={}),
        dry_run=True,
    )
    provider = MagicMock()
    provider.execute_command.return_value = MagicMock(status=MagicMock(value="completed"))

    requests = [
        {
            "url": f"http://10.10.10.1/path{i}",
            "method": "GET",
            "user_agent": "ThreatHunterAgent/8.2" if i % 2 else "Mozilla/5.0 Chrome/120.0.0.0",
        }
        for i in range(3)
    ]
    plan = {
        "type": "http_followup",
        "mode": "mock",
        "timeout": 5.0,
        "requests": requests,
        "hosts": ["10.10.10.1"],
    }
    request = ScenarioExecutionRequest(
        scenario_id="http_followup",
        scenario_params={},
        execution_metadata={},
        run_id="run-ws-http",
        target_net="10.10.10.0/24",
        dry_run=True,
    )

    execute_command_plan(plan, provider, ctx, request)
    completed = next(e for e in store.list_events("run-ws-http") if e.event == "http_followup_completed")
    run_dir = tmp_path / "artifact-run"
    run_dir.mkdir()
    _write_http_followup_artifacts(run_dir, completed.evidence)

    jsonl_path = run_dir / "http_followup_requests.jsonl"
    dump_path = run_dir / "http_request_dump.json"
    assert jsonl_path.exists()
    assert dump_path.exists()

    lines = [line for line in jsonl_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    assert len(lines) == 3
    record = json.loads(lines[0])
    for key in ("target", "url", "method", "user_agent", "timestamp", "dispatch_status"):
        assert key in record

    dump = json.loads(dump_path.read_text(encoding="utf-8"))
    assert dump["sample_count"] == 3
    assert dump["summary"]["path_distribution"]
    assert dump["summary"]["user_agent_distribution"]
    assert dump["summary"]["abnormal_user_agents"] >= 1
    assert dump["summary"]["normal_user_agents"] >= 1
    assert dump["summary"]["response_tracking"] == "disabled_webshell_mode"
    store.close()


def test_webshell_manager_run_http_followup_validation_unchanged(tmp_path) -> None:
    from tests.e2e.fixtures.webshell_test_server import WebshellTestServer

    server = WebshellTestServer(storage_dir=tmp_path / "server")
    server.start()
    try:
        manager = RunManager(runs_dir=tmp_path / "runs")
        _run, run_dir, exit_code = manager.run(
            scenario_ids=["http_followup"],
            target_net="10.10.10.0/24",
            dry_run=True,
            scenario_params={
                "http_followup": {
                    "hosts": ["10.10.10.20"],
                    "max_total": 3,
                    "max_per_host": 3,
                }
            },
            execution_provider="webshell",
            webshell_family="jsp",
            webshell_url=server.webshell_url,
        )
        assert exit_code == 0
        assert (run_dir / "http_followup_requests.jsonl").exists()
        assert (run_dir / "http_request_dump.json").exists()

        jsonl_lines = sum(
            1
            for line in (run_dir / "http_followup_requests.jsonl").read_text(encoding="utf-8").splitlines()
            if line.strip()
        )
        validation = json.loads((run_dir / "validation.json").read_text(encoding="utf-8"))
        traffic = json.loads((run_dir / "traffic_summary.json").read_text(encoding="utf-8"))
        http_val = next(r for r in validation["results"] if r["scenario_id"] == "http_followup")
        http_traffic = traffic["scenarios"]["http_followup"]

        assert jsonl_lines == http_val["metrics"]["http_request_sent_count"]
        assert http_val["decision"] == "success"
        assert http_traffic["requests_sent"] == http_val["metrics"]["http_request_sent_count"]
        assert http_traffic["responses_received"] == 0
        assert http_traffic.get("response_tracking") == "disabled_webshell_mode"
    finally:
        server.stop()
