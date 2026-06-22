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
    assert not (run_dir / "phase1_webshell_attack.json").exists()


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
    record = loader.discover_and_load().get("port_sweep")
    assert record is not None

    from dsp.engine import RunConfig, RunContext

    store = EventStore(":memory:")
    store.open_run("transport-fail")
    run_ctx = RunContext(
        run_id="transport-fail",
        target_net="172.16.50.0/24",
        event_store=store,
        config=RunConfig(
            dry_run=True,
            scenario_params={"port_sweep": {"max_hosts": 1, "max_ports": 1}},
        ),
        dry_run=True,
    )
    exec_ctx = ExecutionContext(
        run_id="transport-fail",
        target_net="172.16.50.0/24",
        dry_run=True,
        provider_type="webshell",
    )
    exec_ctx.execution_metadata["remote_work_dir"] = "/tmp/dsp"
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


def test_webshell_provider_source_has_no_run_scenario_import() -> None:
    import inspect

    from dsp.execution.webshell_provider import WebshellExecutionProvider

    source = inspect.getsource(WebshellExecutionProvider)
    assert "run_scenario" not in source
    assert "delivery_fallback_local" not in source
