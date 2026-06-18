"""Webshell bundle mode tests — no remote DSP install required."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from dsp.engine import RunConfig, RunContext, resolve_targets
from dsp.event_store import EventQuery, EventStore
from dsp.execution import ExecutionContext, WebshellExecutionProvider
from dsp.execution.providers.runtime.command import CommandExecutionPolicy
from dsp.execution.providers.runtime.transport import TransportRuntimeConfiguration
from dsp.execution.providers.webshell.jsp import JspWebshellProvider
from dsp.execution.remote import RemoteEventCollectionRequest, RemoteEventCollector
from dsp.execution.remote.bundle.models import BUNDLE_SCENARIOS, REMOTE_EXECUTION_MODE_BUNDLE
from dsp.execution.remote.bundle.packager import pack_scenario_bundle
from dsp.execution.remote.bundle.planner import build_manifest
from dsp.execution.remote.models import ScenarioExecutionRequest
from dsp.execution.webshell.event_sync import load_jsonl_bundle
from dsp.execution.webshell.transport import RealHttpTransport, RetryPolicy
from dsp.execution.webshell_config import WebshellExecutionConfig
from dsp.plugins import PluginLoader
from dsp.runtime.scenario_plan import apply_webshell_initial_compromise_plan
from tests.e2e.fixtures.bundle_helpers import remote_bundle_path_for_run
from tests.e2e.fixtures.webshell_test_server import WebshellTestServer


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
    config = WebshellExecutionConfig(provider_type="jsp", webshell_url=server.webshell_url)
    return WebshellExecutionProvider(config, transport=transport, family_provider=family_provider)


def test_bundle_scenarios_cover_mvp_set() -> None:
    assert BUNDLE_SCENARIOS == {
        "port_sweep",
        "dns_tunnel",
        "http_followup",
        "sql_injection",
        "ssh_failure",
        "host_behavior_check",
    }


def test_packager_writes_manifest_and_runner(tmp_path: Path) -> None:
    manifest = {
        "run_id": "run01",
        "scenario_id": "port_sweep",
        "paths": {"work_dir": "/tmp/dsp/run01", "bundle": "/tmp/dsp/run01/events.jsonl"},
        "plan": {"type": "port_sweep", "mode": "mock", "probes": []},
    }
    package = pack_scenario_bundle(manifest)
    assert (package.local_dir / "manifest.json").is_file()
    assert (package.local_dir / "run_scenario.py").is_file()
    assert package.remote_files[0][0] == "/tmp/dsp/run01/manifest.json"


def test_webshell_host_without_dsp_remote_scenario_runs_port_sweep(
    tmp_path: Path,
) -> None:
    server = WebshellTestServer(storage_dir=tmp_path / "server")
    url = server.start()
    try:
        loader = PluginLoader()
        record = loader.discover_and_load().get("port_sweep")
        assert record is not None
        provider = _connected_provider(server)
        run_id = "bundle_port_sweep"
        store = EventStore(tmp_path / "events.db")
        store.open_run(run_id)
        exec_ctx = ExecutionContext(
            run_id=run_id,
            target_net="10.10.10.0/24",
            dry_run=True,
            provider_type="webshell",
            scenario_id="port_sweep",
            execution_metadata={"remote_work_dir": "/tmp/dsp"},
        )
        run_ctx = RunContext(
            run_id=run_id,
            target_net="10.10.10.0/24",
            event_store=store,
            config=RunConfig(
                dry_run=True,
                scenario_params={"port_sweep": {"max_hosts": 2, "max_ports": 2}},
            ),
            dry_run=True,
        )
        targets = resolve_targets("10.10.10.0/24", dry_run=True)
        provider.prepare(exec_ctx)
        provider.execute(exec_ctx, record, run_ctx, targets)

        assert exec_ctx.execution_metadata["remote_execution_mode"] == REMOTE_EXECUTION_MODE_BUNDLE
        assert server.upload_calls, "bundle files were not uploaded"
        assert any("run_scenario.py" in call for call in server.upload_calls)
        assert not any(call.startswith("dsp-remote-scenario ") for call in server.command_calls)
        assert any(call.startswith("python3 ") for call in server.command_calls)

        bundle_path = remote_bundle_path_for_run(run_id)
        collection = RemoteEventCollector().collect(
            RemoteEventCollectionRequest(
                remote_execution_id=run_id,
                remote_bundle_path=bundle_path,
            ),
            provider,
            store,
        )
        provider.cleanup(exec_ctx)
        assert collection.events_imported >= 3
        bundle = load_jsonl_bundle(collection.local_bundle_path)
        assert bundle.metadata.scenario_id == "port_sweep"
        assert any(event["event"] == "port_sweep_started" for event in bundle.events)
    finally:
        server.stop()


def test_webshell_bundle_host_behavior_check_generates_events(tmp_path: Path) -> None:
    server = WebshellTestServer(storage_dir=tmp_path / "server")
    url = server.start()
    try:
        loader = PluginLoader()
        record = loader.discover_and_load().get("host_behavior_check")
        assert record is not None
        provider = _connected_provider(server)
        run_id = "bundle_host_behavior"
        store = EventStore(tmp_path / "events.db")
        store.open_run(run_id)
        scenario_params: dict[str, dict] = {}
        apply_webshell_initial_compromise_plan(
            scenario_params,
            ["host_behavior_check"],
            url,
        )
        scenario_params["host_behavior_check"]["webshell_family"] = "jsp"
        exec_ctx = ExecutionContext(
            run_id=run_id,
            target_net="127.0.0.0/30",
            dry_run=True,
            provider_type="webshell",
            scenario_id="host_behavior_check",
            execution_metadata={
                "remote_work_dir": "/tmp/dsp",
                "webshell_family": "jsp",
            },
        )
        run_ctx = RunContext(
            run_id=run_id,
            target_net="127.0.0.0/30",
            event_store=store,
            config=RunConfig(
                dry_run=True,
                scenario_params=scenario_params,
            ),
            dry_run=True,
        )
        targets = resolve_targets("127.0.0.0/30", dry_run=True)
        provider.prepare(exec_ctx)
        provider.execute(exec_ctx, record, run_ctx, targets)

        bundle_path = remote_bundle_path_for_run(run_id)
        collection = RemoteEventCollector().collect(
            RemoteEventCollectionRequest(
                remote_execution_id=run_id,
                remote_bundle_path=bundle_path,
            ),
            provider,
            store,
        )
        provider.cleanup(exec_ctx)
        bundle = load_jsonl_bundle(collection.local_bundle_path)
        event_names = {event["event"] for event in bundle.events}
        assert "host_behavior_check_started" in event_names
        assert "host_behavior_command_dispatched" in event_names
        assert "eicar_file_created" in event_names
        assert "eicar_variant_created" in event_names
        assert "credential_artifact_enumeration" in event_names
        assert "host_behavior_check_completed" in event_names
        assert collection.events_imported >= 20
    finally:
        server.stop()


def test_bundle_manifest_for_host_behavior_targets_webshell_host() -> None:
    loader = PluginLoader()
    record = loader.discover_and_load().get("host_behavior_check")
    assert record is not None
    params: dict[str, dict] = {}
    apply_webshell_initial_compromise_plan(
        params,
        ["host_behavior_check"],
        "http://10.10.10.50:8080/shell.jsp",
    )
    params["host_behavior_check"]["webshell_family"] = "jsp"
    request = ScenarioExecutionRequest(
        scenario_id="host_behavior_check",
        scenario_params=params["host_behavior_check"],
        execution_metadata={"remote_work_dir": "/tmp/dsp", "webshell_family": "jsp"},
        run_id="plan_hb",
        target_net="10.10.10.0/24",
        dry_run=True,
    )
    targets = resolve_targets("10.10.10.0/24", dry_run=True)
    manifest = build_manifest(request, targets, record)
    assert manifest["plan"]["type"] == "host_behavior_check"
    assert manifest["plan"]["target_host"] == "10.10.10.50"
    assert manifest["plan"]["mode"] == "mock"


def test_missing_remote_command_writes_skip_event(tmp_path: Path) -> None:
    runner_path = Path(__file__).resolve().parents[2] / "dsp/execution/remote/bundle/assets/run_scenario.py"
    work_dir = tmp_path / "skip-run"
    work_dir.mkdir()
    manifest = {
        "run_id": "skip01",
        "scenario_id": "http_followup",
        "scenario_version": "1.0.0",
        "schema_version": "1.0.0",
        "target_net": "10.10.10.0/24",
        "paths": {
            "work_dir": str(work_dir),
            "bundle": str(work_dir / "events.jsonl"),
            "traffic_summary": str(work_dir / "traffic_summary.json"),
        },
        "plan": {"type": "http_followup", "mode": "live", "requests": []},
    }
    (work_dir / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    import os
    import subprocess
    import sys

    env = os.environ.copy()
    env["PATH"] = ""
    env["DSP_BUNDLE_DIR"] = str(work_dir)
    completed = subprocess.run(
        [sys.executable, str(runner_path)],
        cwd=str(work_dir),
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 0
    bundle = load_jsonl_bundle(work_dir / "events.jsonl")
    assert bundle.events
    assert bundle.events[0]["event"] == "http_followup_skipped"
    assert "missing_commands" in bundle.events[0]["evidence"]


def test_bundle_runner_builds_manifest_for_supported_scenario() -> None:
    loader = PluginLoader()
    record = loader.discover_and_load().get("port_sweep")
    assert record is not None
    request = ScenarioExecutionRequest(
        scenario_id="port_sweep",
        scenario_params={"max_hosts": 1, "max_ports": 2},
        execution_metadata={"remote_work_dir": "/tmp/dsp"},
        run_id="plan01",
        target_net="10.10.10.0/24",
        dry_run=True,
    )
    targets = resolve_targets("10.10.10.0/24", dry_run=True)
    manifest = build_manifest(request, targets, record)
    assert manifest["plan"]["type"] == "port_sweep"
    assert manifest["paths"]["bundle"] == "/tmp/dsp/plan01/events.jsonl"


def test_webshell_provider_uses_bundle_mode_metadata(tmp_path: Path) -> None:
    backend_calls: list[str] = []

    class _Provider(WebshellExecutionProvider):
        def execute_command(self, command, *, arguments=None, timeout_seconds=300):
            backend_calls.append(str(command))
            return super().execute_command(command, arguments=arguments, timeout_seconds=timeout_seconds)

    server = WebshellTestServer(storage_dir=tmp_path / "server")
    server.start()
    provider = _connected_provider(server)
    loader = PluginLoader()
    record = loader.discover_and_load().get("port_sweep")
    assert record is not None
    exec_ctx = ExecutionContext(
        run_id="meta01",
        target_net="10.10.10.0/24",
        dry_run=True,
        provider_type="webshell",
        execution_metadata={"remote_work_dir": "/tmp/dsp"},
    )
    run_ctx = RunContext(
        run_id="meta01",
        target_net="10.10.10.0/24",
        event_store=EventStore(":memory:"),
        config=RunConfig(dry_run=True, scenario_params={"port_sweep": {"max_hosts": 1}}),
        dry_run=True,
    )
    provider.prepare(exec_ctx)
    provider.execute(exec_ctx, record, run_ctx, resolve_targets("10.10.10.0/24", dry_run=True))
    assert exec_ctx.execution_metadata["remote_execution_mode"] == REMOTE_EXECUTION_MODE_BUNDLE
    server.stop()
