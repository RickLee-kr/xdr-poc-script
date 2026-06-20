"""Remote bundle timeout and execution hardening tests."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from dsp.execution import WebshellExecutionProvider
from dsp.execution.providers.runtime.command import CommandExecutionPolicy
from dsp.execution.providers.runtime.transport import TransportRuntimeConfiguration
from dsp.execution.providers.webshell.jsp import JspWebshellProvider
from dsp.execution.remote.bundle.planner import build_manifest
from dsp.execution.remote.bundle.runner import BundleScenarioRunner
from dsp.execution.remote.bundle.timeout import (
    apply_remote_execution_budget,
    compute_bundle_execution_timeout_seconds,
)
from dsp.execution.remote.exceptions import RemoteBundleExecutionError
from dsp.execution.remote.models import ScenarioExecutionRequest
from dsp.execution.webshell.transport import RealHttpTransport, RetryPolicy
from dsp.execution.webshell_config import WebshellExecutionConfig
from dsp.engine import resolve_targets
from dsp.plugins import PluginLoader
from dsp.runtime.scenario_plan import apply_webshell_initial_compromise_plan
from dsp.runtime.traffic_profiles import build_scenario_params
from dsp.runner import RunManager
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


def test_compute_timeout_scales_with_http_followup_workload() -> None:
    manifest = {
        "plan": {
            "type": "http_followup",
            "mode": "live",
            "timeout": 2.0,
            "requests": [{"url": f"http://10.0.0.1/{idx}"} for idx in range(150)],
            "non_standard_port_burst": {
                "enabled": True,
                "requests": [{"url": f"http://10.0.0.1:8088/{idx}"} for idx in range(120)],
            },
        }
    }
    timeout = compute_bundle_execution_timeout_seconds(manifest)
    assert timeout >= 300


def test_apply_remote_execution_budget_caps_burst_attempts() -> None:
    plan = {
        "type": "http_followup",
        "mode": "live",
        "timeout": 2.0,
        "requests": [{"url": "http://10.0.0.1/"}] * 150,
        "non_standard_port_burst": {
            "enabled": True,
            "attempts_planned": 120,
            "requests": [{"url": f"http://10.0.0.1:8088/{idx}"} for idx in range(120)],
        },
    }
    capped = apply_remote_execution_budget(plan)
    burst = capped["non_standard_port_burst"]
    assert len(burst.get("requests") or []) <= 15


def test_http_followup_normal_profile_completes_without_command_timeout(
    tmp_path: Path,
) -> None:
    server = WebshellTestServer(storage_dir=tmp_path / "server")
    server.start()
    try:
        loader = PluginLoader()
        record = loader.discover_and_load().get("http_followup")
        assert record is not None
        provider = _connected_provider(server)
        run_id = "bundle_http_normal"
        scenario_params = build_scenario_params("http_followup", "normal")
        apply_webshell_initial_compromise_plan(
            scenario_params,
            ["http_followup"],
            server.webshell_url,
        )
        scenario_params["http_followup"]["webshell_family"] = "jsp"
        request = ScenarioExecutionRequest(
            scenario_id="http_followup",
            scenario_params=scenario_params["http_followup"],
            execution_metadata={"remote_work_dir": "/tmp/dsp"},
            run_id=run_id,
            target_net="10.10.10.0/24",
            dry_run=False,
        )
        targets = resolve_targets("10.10.10.0/24", dry_run=False)
        manifest = build_manifest(request, targets, record)
        assert manifest["execution_timeout_seconds"] >= 120
        burst = manifest["plan"]["non_standard_port_burst"]
        assert not burst.get("enabled") or len(burst.get("requests") or []) <= 15

        diag_dir = tmp_path / "diag"
        BundleScenarioRunner().run(
            request,
            provider,
            targets=targets,
            record=record,
            diagnostics_dir=diag_dir,
        )
        exec_output = (diag_dir / "execution_stdout_stderr.txt").read_text(encoding="utf-8")
        assert "command timeout" not in exec_output.lower()

        remote_run_dir = f"/tmp/dsp/{run_id}"
        events_path = f"{remote_run_dir}/events.jsonl"
        assert server._read_remote_file(events_path)
        status_path = f"{remote_run_dir}/remote_status.json"
        status_payload = json.loads(server._read_remote_file(status_path).decode("utf-8"))
        assert status_payload["phase"] == "completed"
    finally:
        server.stop()


def test_command_timeout_does_not_use_bundle_runner(tmp_path: Path) -> None:
    """Command-only path never raises RemoteBundleExecutionError from bundle runner."""
    from dsp.event_store import EventQuery, EventStore

    server = WebshellTestServer(
        storage_dir=tmp_path / "server",
        script_stdout_mode="command_timeout_partial",
    )
    server.start()
    manager = RunManager(runs_dir=tmp_path / "runs")
    try:
        run, run_dir, _exit_code = manager.run(
            scenario_ids=["port_sweep"],
            target_net="127.0.0.0/30",
            dry_run=False,
            scenario_params={"port_sweep": {"max_hosts": 1, "max_ports": 2}},
            execution_provider="webshell",
            webshell_family="jsp",
            webshell_url=server.webshell_url,
            remote_work_dir=str(tmp_path / "remote-work"),
        )
        assert not any("run_scenario.py" in call for call in server.upload_calls)
        store = EventStore.open_existing(run_dir / "events.db")
        try:
            assert store.count(EventQuery(run_id=run.run_id)) >= 1
        finally:
            store.close()
    finally:
        server.stop()
