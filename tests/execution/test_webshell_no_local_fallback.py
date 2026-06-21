"""Webshell provider must never fall back to local run_scenario execution."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from dsp.engine.orchestrator import run_scenario
from dsp.event_store import EventQuery, EventStore, RunStatus, ValidationDecision
from dsp.execution import ExecutionContext, WebshellExecutionConfig, WebshellExecutionProvider
from dsp.execution.providers.runtime.command import CommandResult, CommandStatus
from dsp.execution.providers.runtime.command.command_exceptions import CommandTransportError
from dsp.execution.providers.runtime.transport.transport_exceptions import TransportConnectionError
from dsp.execution.remote.exceptions import RemoteArtifactUploadError
from dsp.plugins import PluginLoader
from dsp.runner import RunManager
from dsp.runner.run_manager import WEBSHELL_CONNECT_FAILED_REASON
from dsp.runtime.webshell_phase1 import phase1_probe_paths, run_webshell_phase1_attack


def _webshell_provider_with_connect_failure() -> WebshellExecutionProvider:
    mock_family = MagicMock()
    mock_family.connect.side_effect = TransportConnectionError(
        "transport healthcheck failed",
        provider_type="jsp",
    )
    config = WebshellExecutionConfig(
        provider_type="jsp",
        webshell_url="https://lab.example/shell.jsp",
    )
    return WebshellExecutionProvider(config, family_provider=mock_family)


def _exec_context(*, dry_run: bool) -> ExecutionContext:
    return ExecutionContext(
        run_id="ws-fail-01",
        target_net="172.16.50.0/24",
        dry_run=dry_run,
        provider_type="webshell",
    )


@pytest.mark.parametrize("dry_run", [True, False], ids=["dry_run", "live"])
def test_webshell_connect_failure_does_not_call_run_scenario(dry_run: bool) -> None:
    provider = _webshell_provider_with_connect_failure()
    with patch("dsp.engine.orchestrator.run_scenario") as mock_run_scenario:
        with pytest.raises(TransportConnectionError):
            provider.prepare(_exec_context(dry_run=dry_run))
        mock_run_scenario.assert_not_called()


def test_webshell_connect_failure_dry_run_run_manager_skips_scenarios(
    tmp_path: Path,
) -> None:
    manager = RunManager(runs_dir=tmp_path / "runs")
    provider = _webshell_provider_with_connect_failure()

    with patch("dsp.engine.orchestrator.run_scenario") as mock_run_scenario:
        with patch.object(RunManager, "_create_execution_provider", return_value=provider):
            run, run_dir, exit_code = manager.run(
                scenario_ids=["port_sweep"],
                target_net="172.16.50.0/24",
                dry_run=True,
                execution_provider="webshell",
                webshell_family="jsp",
                webshell_url="https://lab.example/shell.jsp",
            )

    mock_run_scenario.assert_not_called()
    assert run.status == RunStatus.FAILED

    run_json = json.loads((run_dir / "run.json").read_text())
    assert run_json["status"] == "failed"

    store = EventStore.open_existing(run_dir / "events.db")
    try:
        skipped = store.count(
            EventQuery(
                run_id=run.run_id,
                scenario_id="port_sweep",
                event="scenario_skipped",
            )
        )
        assert skipped == 1
        events = store.list_events(run.run_id)
        skip = next(e for e in events if e.event == "scenario_skipped")
        assert skip.evidence["reason"] == WEBSHELL_CONNECT_FAILED_REASON
    finally:
        store.close()

    validation = json.loads((run_dir / "validation.json").read_text())
    assert validation["results"][0]["decision"] == ValidationDecision.SKIPPED.value


def test_webshell_connect_failure_live_run_manager_skips_scenarios(
    tmp_path: Path,
) -> None:
    manager = RunManager(runs_dir=tmp_path / "runs")
    provider = _webshell_provider_with_connect_failure()

    with patch("dsp.engine.orchestrator.run_scenario") as mock_run_scenario:
        with patch.object(RunManager, "_create_execution_provider", return_value=provider):
            run, run_dir, _exit_code = manager.run(
                scenario_ids=["port_sweep"],
                target_net="172.16.50.0/24",
                dry_run=False,
                execution_provider="webshell",
                webshell_family="jsp",
                webshell_url="https://lab.example/shell.jsp",
            )

    mock_run_scenario.assert_not_called()
    assert run.status == RunStatus.FAILED
    assert (run_dir / "phase1_webshell_attack.json").exists()


def test_command_transport_error_dry_run_does_not_call_run_scenario() -> None:
    mock_family = MagicMock()
    mock_family.connect.return_value = None
    mock_family.execute_command.side_effect = CommandTransportError("delivery failed")
    config = WebshellExecutionConfig(
        provider_type="jsp",
        webshell_url="https://lab.example/shell.jsp",
    )
    provider = WebshellExecutionProvider(config, family_provider=mock_family)
    loader = PluginLoader()
    record = loader.discover_and_load().get("dummy")
    assert record is not None

    from dsp.engine import RunConfig, RunContext

    store = EventStore(":memory:")
    store.open_run("transport-fail")
    run_ctx = RunContext(
        run_id="transport-fail",
        target_net="172.16.50.0/24",
        event_store=store,
        config=RunConfig(dry_run=True),
        dry_run=True,
    )
    exec_ctx = ExecutionContext(
        run_id="transport-fail",
        target_net="172.16.50.0/24",
        dry_run=True,
        provider_type="webshell",
    )
    exec_ctx.execution_metadata["remote_work_dir"] = "/tmp/dsp"
    exec_ctx.execution_metadata["remote_bundle_path"] = "/tmp/dsp/transport-fail/bundle.tgz"
    provider.prepare(exec_ctx)

    with patch("dsp.engine.orchestrator.run_scenario") as mock_run_scenario:
        with pytest.raises(CommandTransportError):
            provider.execute(exec_ctx, record, run_ctx, MagicMock())
        mock_run_scenario.assert_not_called()


def test_command_transport_error_dry_run_run_manager_skips_scenario(tmp_path: Path) -> None:
    mock_family = MagicMock()
    mock_family.connect.return_value = None
    mock_family.execute_command.return_value = CommandResult.new(
        "cmd01",
        status=CommandStatus.COMPLETED,
        execution_metadata={"transport_status": 200, "delivery_only": True},
    )
    config = WebshellExecutionConfig(
        provider_type="jsp",
        webshell_url="https://lab.example/shell.jsp",
    )
    provider = WebshellExecutionProvider(config, family_provider=mock_family)
    provider.prepare(
        ExecutionContext(
            run_id="x",
            target_net="172.16.50.0/24",
            dry_run=True,
            provider_type="webshell",
        )
    )

    manager = RunManager(runs_dir=tmp_path / "runs")
    with patch("dsp.engine.orchestrator.run_scenario") as mock_run_scenario:
        with patch.object(RunManager, "_create_execution_provider", return_value=provider):
            with patch(
                "dsp.execution.remote.command.runner.CommandScenarioRunner.run",
                side_effect=CommandTransportError("delivery failed"),
            ):
                run, run_dir, _exit_code = manager.run(
                    scenario_ids=["dummy"],
                    target_net="172.16.50.0/24",
                    dry_run=True,
                    execution_provider="webshell",
                    webshell_family="jsp",
                    webshell_url="https://lab.example/shell.jsp",
                )

    mock_run_scenario.assert_not_called()
    store = EventStore.open_existing(run_dir / "events.db")
    try:
        assert store.count(
            EventQuery(run_id=run.run_id, scenario_id="dummy", event="scenario_skipped")
        ) == 1
    finally:
        store.close()


def test_remote_artifact_upload_error_does_not_call_run_scenario() -> None:
    mock_family = MagicMock()
    mock_family.connect.return_value = None
    config = WebshellExecutionConfig(
        provider_type="jsp",
        webshell_url="https://lab.example/shell.jsp",
    )
    provider = WebshellExecutionProvider(config, family_provider=mock_family)
    loader = PluginLoader()
    record = loader.discover_and_load().get("dummy")
    assert record is not None

    from dsp.engine import RunConfig, RunContext

    exec_ctx = ExecutionContext(
        run_id="upload-fail",
        target_net="172.16.50.0/24",
        dry_run=True,
        provider_type="webshell",
    )
    exec_ctx.execution_metadata["remote_work_dir"] = "/tmp/dsp"
    exec_ctx.execution_metadata["remote_bundle_path"] = "/tmp/dsp/upload-fail/bundle.tgz"
    provider.prepare(exec_ctx)
    run_ctx = RunContext(
        run_id="upload-fail",
        target_net="172.16.50.0/24",
        event_store=EventStore(":memory:"),
        config=RunConfig(dry_run=True),
        dry_run=True,
    )

    with patch("dsp.engine.orchestrator.run_scenario") as mock_run_scenario:
        with patch(
            "dsp.execution.remote.command.runner.CommandScenarioRunner.run",
            side_effect=RemoteArtifactUploadError("upload failed"),
        ):
            with pytest.raises(RemoteArtifactUploadError):
                provider.execute(exec_ctx, record, run_ctx, MagicMock())
        mock_run_scenario.assert_not_called()


def test_phase1_url_scan_includes_webshell_execution_path() -> None:
    paths = phase1_probe_paths("http://10.10.10.20/custom.jsp")
    assert paths[0] == "/custom.jsp"
    assert "/WEB-INF/web.xml" in paths


def test_phase1_url_scan_targets_webshell_execution_path() -> None:
    captured_paths: list[str] = []

    class _TrackingClient:
        def request(self, request) -> None:
            captured_paths.append(request.path)

        def make_request(self, plan):
            from dsp.protocols.types import HttpRequest

            path = plan.path if not plan.query else f"{plan.path}?{plan.query}"
            return HttpRequest(
                url=plan.url,
                method=plan.method,
                host=plan.host,
                port=plan.port,
                path=path,
                headers=plan.headers,
            )

    result = run_webshell_phase1_attack(
        "http://10.10.10.20/custom.jsp",
        dry_run=True,
    )
    assert result.execution_path == "/custom.jsp"

    from dsp.runtime.scenario_plan import parse_initial_compromise_endpoint
    from dsp.runtime import webshell_phase1 as phase1_mod

    parsed = parse_initial_compromise_endpoint("http://10.10.10.20/custom.jsp")
    phase1_mod._run_url_scan_with_user_agents(
        parsed,
        _TrackingClient(),
        webshell_url="http://10.10.10.20/custom.jsp",
        params={"abnormal_ua_ratio": 0.0},
        dry_run=False,
        timeout=2.0,
        events=None,
        mode="live",
    )
    assert "/custom.jsp" in captured_paths


def test_phase1_records_events_for_all_phase1_scenarios(tmp_path: Path) -> None:
    db_path = tmp_path / "events.db"
    store = EventStore(db_path)
    store.open_run("phase1-run", metadata={})
    try:
        run_webshell_phase1_attack(
            "http://10.10.10.20/shell.jsp",
            dry_run=True,
            event_store=store,
            run_id="phase1-run",
        )
    finally:
        store.close()

    store = EventStore.open_existing(db_path)
    try:
        events = {e.event for e in store.list_events("phase1-run")}
        assert "http_followup_started" in events
        assert "http_request_sent" in events
        assert "sql_injection_started" in events
        assert "sql_request_sent" in events
        assert "ssh_failure_started" in events
        assert "ssh_auth_attempt" in events
        http_events = store.list_events("phase1-run", scenario_id="http_followup")
        sent_events = [e for e in http_events if e.event == "http_request_sent"]
        assert sent_events
        assert all(e.evidence.get("phase") == "phase1_webshell_attack" for e in sent_events)
        assert all(e.source == "dry_run" for e in sent_events)
    finally:
        store.close()


def test_phase1_webshell_burst_records_events(tmp_path: Path) -> None:
    from unittest.mock import MagicMock

    from dsp.execution.providers.runtime.command import CommandResult, CommandStatus
    from dsp.runtime.webshell_phase1 import run_webshell_phase1_non_standard_port_burst

    provider = MagicMock()
    provider.execute_command.return_value = CommandResult.new(
        "cmd01",
        status=CommandStatus.COMPLETED,
    )
    db_path = tmp_path / "events.db"
    store = EventStore(db_path)
    store.open_run("burst-run", metadata={})
    try:
        summary = run_webshell_phase1_non_standard_port_burst(
            provider,
            "http://10.10.10.20/shell.jsp",
            http_params={"non_standard_burst_min": 2, "non_standard_burst_max": 2},
            dry_run=True,
            event_store=store,
            run_id="burst-run",
        )
    finally:
        store.close()

    assert summary["enabled"] is True
    assert summary["attempts"] == 2
    assert provider.execute_command.call_count == 2

    store = EventStore.open_existing(db_path)
    try:
        events = {e.event for e in store.list_events("burst-run")}
        assert "non_standard_port_burst_started" in events
        assert "non_standard_port_connection_attempt" in events
        assert "non_standard_port_burst_completed" in events
        assert "webshell_command_dispatched" in events
        burst_started = next(
            e for e in store.list_events("burst-run") if e.event == "non_standard_port_burst_started"
        )
        assert burst_started.evidence.get("traffic_origin") == "webshell_host"
    finally:
        store.close()


def test_webshell_provider_source_has_no_run_scenario_import() -> None:
    import inspect

    from dsp.execution.webshell_provider import WebshellExecutionProvider

    source = inspect.getsource(WebshellExecutionProvider)
    assert "run_scenario" not in source
    assert "delivery_fallback_local" not in source
