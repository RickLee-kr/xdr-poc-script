"""Webshell command-only runtime tests — MASTER WBS v1.2."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from dsp.engine import RunConfig, RunContext, resolve_targets
from dsp.event_store import EventQuery, EventStore
from dsp.execution import ExecutionContext, WebshellExecutionConfig, WebshellExecutionProvider
from dsp.execution.providers.runtime.command import CommandExecutionPolicy, CommandStatus
from dsp.execution.providers.runtime.command.command_exceptions import CommandTransportError
from dsp.execution.providers.runtime.transport import TransportRuntimeConfiguration
from dsp.execution.providers.webshell.jsp import JspWebshellProvider
from dsp.execution.remote.command.models import (
    COMMAND_SCENARIOS,
    FORBIDDEN_REMOTE_ARTIFACTS,
    REMOTE_EXECUTION_MODE_COMMAND,
)
from dsp.execution.remote.command.discovery import (
    DISCOVERY_SCAN_MAX_HOSTS_KEY,
    REMOTE_DISCOVERY_CACHE_KEY,
)
from dsp.execution.remote.command.runner import CommandScenarioRunner
from dsp.execution.webshell.transport import RealHttpTransport, RetryPolicy
from dsp.execution.webshell_config import WebshellExecutionConfig as WsConfig
from dsp.plugins import PluginLoader
from dsp.runner import RunManager
from dsp.runtime.scenario_plan import apply_webshell_initial_compromise_plan
from tests.e2e.fixtures.webshell_test_server import WebshellTestServer


def _lab_discovery_cache() -> dict:
    return {
        "target_net": "10.10.10.0/24",
        "hosts": ["10.10.10.97", "10.10.10.98", "10.10.10.20"],
        "service_hosts": {
            "http_targets": ["10.10.10.97"],
            "ssh_hosts": ["10.10.10.98"],
            "dns_hosts": ["10.10.10.20"],
            "ldap_hosts": ["10.10.10.97"],
            "smb_hosts": ["10.10.10.97"],
            "kerberos_hosts": ["10.10.10.97"],
        },
        "service_endpoints": {
            "http_targets": [("10.10.10.97", 80)],
            "ssh_hosts": [("10.10.10.98", 22)],
            "dns_hosts": [("10.10.10.20", 53)],
            "ldap_hosts": [("10.10.10.97", 389)],
            "smb_hosts": [("10.10.10.97", 445)],
            "kerberos_hosts": [("10.10.10.97", 88)],
        },
        "discovery_enabled": True,
        "discovery_meta": {"discovery_origin": "webshell_host", "open_endpoints": 6},
    }


def _seed_discovery(scenario_params: dict[str, dict]) -> None:
    scenario_params[REMOTE_DISCOVERY_CACHE_KEY] = _lab_discovery_cache()


def _connected_provider(server: WebshellTestServer) -> WebshellExecutionProvider:
    transport = RealHttpTransport(retry_policy=RetryPolicy(max_retries=0))
    family_provider = JspWebshellProvider(
        transport=transport,
        webshell_url=server.webshell_url,
    )
    family_provider.create_runtime(
        config=TransportRuntimeConfiguration(
            enable_healthcheck_on_connect=False,
            command_policy=CommandExecutionPolicy(allow_command_execution=True),
        ),
    )
    family_provider.connect()
    config = WsConfig(provider_type="jsp", webshell_url=server.webshell_url)
    return WebshellExecutionProvider(config, transport=transport, family_provider=family_provider)


class TestNoRuntimeUpload:
    def test_webshell_execute_does_not_call_bundle_runner(self) -> None:
        mock_family = MagicMock()
        mock_family.execute_command.return_value = MagicMock(
            status=CommandStatus.COMPLETED,
            command_id="c1",
            execution_metadata={"delivery_only": True, "transport_status": 200},
        )
        config = WebshellExecutionConfig(
            provider_type="jsp",
            webshell_url="https://lab.example/shell.jsp",
        )
        provider = WebshellExecutionProvider(config, family_provider=mock_family)
        loader = PluginLoader()
        record = loader.discover_and_load().get("dummy")
        assert record is not None
        store = EventStore(":memory:")
        store.open_run("run01")
        run_ctx = RunContext(
            run_id="run01",
            target_net="10.10.10.0/24",
            event_store=store,
            config=RunConfig(dry_run=True),
            dry_run=True,
        )
        exec_ctx = ExecutionContext(
            run_id="run01",
            target_net="10.10.10.0/24",
            dry_run=True,
            provider_type="webshell",
            execution_metadata={"traffic_origin_host": "remote"},
        )
        with patch("dsp.execution.remote.bundle.runner.BundleScenarioRunner.run") as mock_bundle:
            provider.execute(exec_ctx, record, run_ctx, MagicMock())
            mock_bundle.assert_not_called()

    def test_live_path_never_uploads_forbidden_artifacts(
        self, tmp_path: Path,
    ) -> None:
        server = WebshellTestServer(storage_dir=tmp_path / "server")
        server.start()
        try:
            provider = _connected_provider(server)
            loader = PluginLoader()
            record = loader.discover_and_load().get("port_sweep")
            assert record is not None
            run_id = "cmd_no_upload"
            store = EventStore(tmp_path / "events.db")
            store.open_run(run_id)
            exec_ctx = ExecutionContext(
                run_id=run_id,
                target_net="10.10.10.0/24",
                dry_run=True,
                provider_type="webshell",
                execution_metadata={
                    "traffic_origin_host": "remote",
                    "remote_work_dir": "/tmp/dsp",
                },
            )
            run_ctx = RunContext(
                run_id=run_id,
                target_net="10.10.10.0/24",
                event_store=store,
                config=RunConfig(
                    dry_run=True,
                    scenario_params={
                        "port_sweep": {"max_hosts": 1, "max_ports": 1},
                        REMOTE_DISCOVERY_CACHE_KEY: _lab_discovery_cache(),
                    },
                ),
                dry_run=True,
            )
            targets = resolve_targets("10.10.10.0/24", dry_run=True)
            provider.prepare(exec_ctx)
            provider.execute(exec_ctx, record, run_ctx, targets)
            for forbidden in FORBIDDEN_REMOTE_ARTIFACTS:
                assert not any(forbidden in call for call in server.upload_calls)
                assert not any(forbidden in call for call in server.command_calls)
            assert exec_ctx.execution_metadata["remote_execution_mode"] == REMOTE_EXECUTION_MODE_COMMAND
            assert server.command_calls, "expected webshell command dispatch"
        finally:
            server.stop()

    def test_live_discovery_uses_command_only_tcp_probes(
        self, tmp_path: Path,
    ) -> None:
        server = WebshellTestServer(storage_dir=tmp_path / "server")
        server.start()
        try:
            provider = _connected_provider(server)
            loader = PluginLoader()
            record = loader.discover_and_load().get("http_followup")
            assert record is not None
            run_id = "cmd_probe_discovery"
            store = EventStore(tmp_path / "events.db")
            store.open_run(run_id)
            scenario_params: dict[str, dict] = {
                "http_followup": {"max_hosts": 1},
                DISCOVERY_SCAN_MAX_HOSTS_KEY: 2,
            }
            apply_webshell_initial_compromise_plan(
                scenario_params,
                ["http_followup"],
                server.webshell_url,
            )
            exec_ctx = ExecutionContext(
                run_id=run_id,
                target_net="10.10.10.0/30",
                dry_run=False,
                provider_type="webshell",
                execution_metadata={
                    "traffic_origin_host": "remote",
                    "remote_work_dir": "/tmp/dsp",
                },
            )
            run_ctx = RunContext(
                run_id=run_id,
                target_net="10.10.10.0/30",
                event_store=store,
                config=RunConfig(dry_run=False, scenario_params=scenario_params),
                dry_run=False,
            )
            provider.prepare(exec_ctx)
            provider.execute(
                exec_ctx,
                record,
                run_ctx,
                resolve_targets("10.10.10.0/30", dry_run=False, discovery=False),
            )
            joined_commands = "\n".join(server.command_calls)
            for forbidden in FORBIDDEN_REMOTE_ARTIFACTS:
                assert forbidden not in joined_commands
                assert not any(forbidden in call for call in server.upload_calls)
            assert "py_compile" not in joined_commands
            assert "discover_runner.py" not in joined_commands
            assert "python3 -c" in joined_commands
            assert "base64" in joined_commands
            discovery_events = [
                e for e in store.list_events(run_id) if e.event == "remote_discovery_completed"
            ]
            assert discovery_events
            assert discovery_events[0].evidence.get("discovery_method") == "tcp_probe_batch_sh"
        finally:
            server.stop()


@pytest.mark.parametrize(
    "scenario_id,params",
    [
        ("http_followup", {"max_hosts": 1}),
        ("sql_injection", {"max_hosts": 1}),
        ("ssh_failure", {"max_hosts": 1, "max_per_host": 2, "max_total": 2}),
        ("dns_tunnel", {"max_hosts": 1, "max_chunks": 1}),
        ("dga", {"phase1_count": 1, "phase2_count": 0}),
        ("ldap_enumeration", {"max_hosts": 1}),
        ("smb_login_failure", {"max_hosts": 1}),
        ("kerberos_failure", {"max_hosts": 1}),
        ("port_sweep", {"max_hosts": 1, "max_ports": 1}),
    ],
)
def test_scenario_dispatches_webshell_commands(
    tmp_path: Path,
    scenario_id: str,
    params: dict,
) -> None:
    server = WebshellTestServer(storage_dir=tmp_path / "server")
    server.start()
    try:
        provider = _connected_provider(server)
        loader = PluginLoader()
        record = loader.discover_and_load().get(scenario_id)
        assert record is not None
        run_id = f"cmd_{scenario_id}"
        store = EventStore(tmp_path / "events.db")
        store.open_run(run_id)
        scenario_params: dict[str, dict] = {scenario_id: dict(params)}
        _seed_discovery(scenario_params)
        apply_webshell_initial_compromise_plan(
            scenario_params,
            [scenario_id],
            server.webshell_url,
        )
        exec_ctx = ExecutionContext(
            run_id=run_id,
            target_net="10.10.10.0/24",
            dry_run=True,
            provider_type="webshell",
            execution_metadata={"traffic_origin_host": "remote", "remote_work_dir": "/tmp/dsp"},
        )
        run_ctx = RunContext(
            run_id=run_id,
            target_net="10.10.10.0/24",
            event_store=store,
            config=RunConfig(dry_run=True, scenario_params=scenario_params),
            dry_run=True,
        )
        targets = resolve_targets("10.10.10.0/24", dry_run=True)
        provider.prepare(exec_ctx)
        before = len(server.command_calls)
        provider.execute(exec_ctx, record, run_ctx, targets)
        assert len(server.command_calls) > before, f"{scenario_id} did not dispatch commands"
        dispatched = store.count(
            EventQuery(run_id=run_id, scenario_id=scenario_id, event="webshell_command_dispatched")
        )
        assert dispatched >= 1
    finally:
        server.stop()


def test_discovery_origin_is_webshell_host(tmp_path: Path) -> None:
    server = WebshellTestServer(storage_dir=tmp_path / "server")
    server.start()
    try:
        provider = _connected_provider(server)
        loader = PluginLoader()
        record = loader.discover_and_load().get("http_followup")
        assert record is not None
        run_id = "cmd_discovery"
        store = EventStore(tmp_path / "events.db")
        store.open_run(run_id)
        params: dict[str, dict] = {"http_followup": {"max_hosts": 1}}
        apply_webshell_initial_compromise_plan(params, ["http_followup"], server.webshell_url)
        exec_ctx = ExecutionContext(
            run_id=run_id,
            target_net="10.10.10.0/24",
            dry_run=True,
            provider_type="webshell",
            execution_metadata={"traffic_origin_host": "remote"},
        )
        run_ctx = RunContext(
            run_id=run_id,
            target_net="10.10.10.0/24",
            event_store=store,
            config=RunConfig(dry_run=True, scenario_params=params),
            dry_run=True,
        )
        provider.prepare(exec_ctx)
        provider.execute(exec_ctx, record, run_ctx, resolve_targets("10.10.10.0/24", dry_run=True))
        events = store.list_events(run_id)
        discovery = [e for e in events if e.event == "remote_discovery_started"]
        assert discovery
        assert discovery[0].evidence.get("discovery_origin") == "webshell_host"
    finally:
        server.stop()


def test_dsp_side_target_net_discovery_not_used_in_webshell_mode(tmp_path: Path) -> None:
    manager = RunManager(runs_dir=tmp_path / "runs")
    server = WebshellTestServer(storage_dir=tmp_path / "server")
    server.start()
    try:
        with patch("dsp.discovery.legacy_bash.discover_services") as mock_discover:
            manager.run(
                scenario_ids=["port_sweep"],
                target_net="10.10.10.0/24",
                dry_run=True,
                scenario_params={"port_sweep": {"max_hosts": 1, "max_ports": 1}},
                execution_provider="webshell",
                webshell_family="jsp",
                webshell_url=server.webshell_url,
            )
            mock_discover.assert_not_called()
    finally:
        server.stop()


def test_event_store_records_structured_dispatch_events(tmp_path: Path) -> None:
    server = WebshellTestServer(storage_dir=tmp_path / "server")
    server.start()
    try:
        manager = RunManager(runs_dir=tmp_path / "runs")
        run, run_dir, _ = manager.run(
            scenario_ids=["port_sweep"],
            target_net="10.10.10.0/24",
            dry_run=True,
            scenario_params={"port_sweep": {"max_hosts": 1, "max_ports": 1}},
            execution_provider="webshell",
            webshell_family="jsp",
            webshell_url=server.webshell_url,
        )
        store = EventStore.open_existing(run_dir / "events.db")
        try:
            dispatched = store.count(
                EventQuery(run_id=run.run_id, event="webshell_command_dispatched")
            )
            assert dispatched >= 1
            sample = next(
                e for e in store.list_events(run.run_id) if e.event == "webshell_command_dispatched"
            )
            assert sample.evidence.get("origin") == "webshell_host"
            assert sample.evidence.get("dispatch_status")
            assert "stdout" not in sample.evidence
            assert "stderr" not in sample.evidence
        finally:
            store.close()
    finally:
        server.stop()


def test_no_target_records_scenario_skipped(tmp_path: Path) -> None:
    server = WebshellTestServer(storage_dir=tmp_path / "server")
    server.start()
    try:
        manager = RunManager(runs_dir=tmp_path / "runs")
        run, run_dir, _ = manager.run(
            scenario_ids=["ssh_failure"],
            target_net="10.10.10.0/24",
            dry_run=True,
            scenario_params={"ssh_failure": {"max_hosts": 1, "hosts": []}},
            execution_provider="webshell",
            webshell_family="jsp",
            webshell_url=server.webshell_url,
        )
        store = EventStore.open_existing(run_dir / "events.db")
        try:
            assert store.count(
                EventQuery(run_id=run.run_id, scenario_id="ssh_failure", event="scenario_skipped")
            ) >= 1
        finally:
            store.close()
    finally:
        server.stop()


def test_transport_failure_no_local_fallback(tmp_path: Path) -> None:
    mock_family = MagicMock()
    mock_family.connect.return_value = None
    mock_family.execute_command.side_effect = CommandTransportError("delivery failed")
    config = WebshellExecutionConfig(
        provider_type="jsp",
        webshell_url="https://lab.example/shell.jsp",
    )
    provider = WebshellExecutionProvider(config, family_provider=mock_family)
    provider.prepare(
        ExecutionContext(
            run_id="x",
            target_net="10.10.10.0/24",
            dry_run=True,
            provider_type="webshell",
            execution_metadata={"traffic_origin_host": "remote"},
        )
    )
    manager = RunManager(runs_dir=tmp_path / "runs")
    with patch("dsp.engine.orchestrator.run_scenario") as mock_local:
        with patch.object(RunManager, "_create_execution_provider", return_value=provider):
            run, run_dir, _ = manager.run(
                scenario_ids=["port_sweep"],
                target_net="10.10.10.0/24",
                dry_run=True,
                execution_provider="webshell",
                webshell_family="jsp",
                webshell_url="https://lab.example/shell.jsp",
            )
    mock_local.assert_not_called()
    store = EventStore.open_existing(run_dir / "events.db")
    try:
        assert store.count(
            EventQuery(run_id=run.run_id, scenario_id="port_sweep", event="scenario_skipped")
        ) >= 1
    finally:
        store.close()


def test_command_scenarios_cover_required_set() -> None:
    required = {
        "http_followup",
        "sql_injection",
        "ssh_failure",
        "dns_tunnel",
        "dga",
        "ldap_enumeration",
        "smb_login_failure",
        "kerberos_failure",
        "port_sweep",
    }
    assert required.issubset(COMMAND_SCENARIOS)


def test_skipped_scenario_not_marked_completed_in_console(tmp_path: Path) -> None:
    from dsp.runner.console_output import OperationalConsole
    from io import StringIO

    stream = StringIO()
    console = OperationalConsole(provider="webshell", stream=stream)
    console.handle_progress(
        "scenario_skipped",
        {"scenario_id": "ssh_failure", "reason": "no_ssh_hosts", "evidence": {}},
    )
    output = stream.getvalue()
    assert "SKIPPED" in output
    assert "Completed" not in output
