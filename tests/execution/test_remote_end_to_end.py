"""End-to-end remote execution: webshell command dispatch → Event Store."""

from __future__ import annotations

from pathlib import Path

import pytest

from dsp.engine import RunConfig, RunContext, resolve_targets
from dsp.event_store import EventQuery, EventStore
from dsp.execution import ExecutionContext, WebshellExecutionProvider
from dsp.execution.providers.runtime.command import CommandExecutionPolicy
from dsp.execution.providers.runtime.transport import TransportRuntimeConfiguration
from dsp.execution.providers.webshell.jsp import JspWebshellProvider
from dsp.execution.remote.command.models import REMOTE_EXECUTION_MODE_COMMAND
from dsp.execution.webshell.transport import RealHttpTransport, RetryPolicy
from dsp.execution.webshell_config import WebshellExecutionConfig
from dsp.plugins import PluginLoader
from tests.e2e.fixtures.webshell_test_server import WebshellTestServer

RUN_ID = "remote_e2e_run"
SCENARIO_ID = "port_sweep"


def _connected_webshell_provider(server: WebshellTestServer) -> WebshellExecutionProvider:
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


@pytest.fixture
def remote_e2e_server(tmp_path: Path) -> WebshellTestServer:
    server = WebshellTestServer(storage_dir=tmp_path / "remote-storage")
    server.start()
    yield server
    server.stop()


def test_remote_end_to_end_command_dispatch_writes_event_store(
    remote_e2e_server: WebshellTestServer,
    tmp_path: Path,
) -> None:
    loader = PluginLoader()
    record = loader.discover_and_load().get(SCENARIO_ID)
    assert record is not None

    store = EventStore(tmp_path / "events.db")
    store.open_run(RUN_ID)

    provider = _connected_webshell_provider(remote_e2e_server)
    exec_ctx = ExecutionContext(
        run_id=RUN_ID,
        target_net="10.10.10.0/24",
        dry_run=True,
        provider_type="webshell",
        scenario_id=SCENARIO_ID,
        execution_metadata={
            "remote_work_dir": "/tmp/dsp",
            "traffic_origin_host": "remote",
        },
    )
    run_ctx = RunContext(
        run_id=RUN_ID,
        target_net="10.10.10.0/24",
        event_store=store,
        config=RunConfig(
            dry_run=True,
            scenario_params={SCENARIO_ID: {"max_hosts": 2, "max_ports": 2}},
        ),
        dry_run=True,
    )
    targets = resolve_targets("10.10.10.0/24")

    provider.prepare(exec_ctx)
    provider.execute(exec_ctx, record, run_ctx, targets)
    assert remote_e2e_server.command_calls
    assert exec_ctx.execution_metadata["remote_execution_mode"] == REMOTE_EXECUTION_MODE_COMMAND
    assert not any("run_scenario.py" in call for call in remote_e2e_server.upload_calls)
    provider.cleanup(exec_ctx)

    assert store.count(EventQuery(run_id=RUN_ID)) >= 3
    assert store.count(
        EventQuery(
            run_id=RUN_ID,
            scenario_id=SCENARIO_ID,
            event="port_sweep_started",
        )
    ) >= 1
    assert store.count(
        EventQuery(
            run_id=RUN_ID,
            scenario_id=SCENARIO_ID,
            event="webshell_command_dispatched",
        )
    ) >= 1
