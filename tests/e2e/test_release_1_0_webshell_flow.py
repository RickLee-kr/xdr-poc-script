"""Release 1.0 Flow B — webshell command-only execution path E2E harness."""

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
from tests.e2e.conftest import (
    assert_event_store_has_events,
    assert_evidence_exports_exist,
    assert_harness_excludes_validation_runtime,
    assert_manual_verification_package_exists,
    export_evidence,
    generate_manual_verification,
)
from tests.e2e.fixtures.webshell_test_server import WebshellTestServer

pytestmark = pytest.mark.e2e

RUN_ID = "release_1_0_webshell_run"
SCENARIO_ID = "port_sweep"


def _connected_webshell_provider(server: WebshellTestServer) -> WebshellExecutionProvider:
    transport = RealHttpTransport(retry_policy=RetryPolicy(max_retries=0))
    family_provider = JspWebshellProvider(
        transport=transport,
        webshell_url=server.webshell_url,
    )
    family_provider.create_runtime(
        config=TransportRuntimeConfiguration(
            enable_healthcheck_on_connect=True,
            command_policy=CommandExecutionPolicy(allow_command_execution=True),
        ),
    )
    family_provider.connect()
    config = WebshellExecutionConfig(
        provider_type="jsp",
        webshell_url=server.webshell_url,
        enable_healthcheck_on_connect=True,
    )
    return WebshellExecutionProvider(
        config,
        transport=transport,
        family_provider=family_provider,
    )


@pytest.fixture
def webshell_event_store(tmp_path: Path) -> EventStore:
    store = EventStore(tmp_path / "webshell_events.db")
    store.open_run(RUN_ID)
    return store


def test_webshell_execution_reaches_event_store_via_command_dispatch(
    webshell_test_server: WebshellTestServer,
    webshell_event_store: EventStore,
    e2e_output_dir: Path,
) -> None:
    loader = PluginLoader()
    record = loader.discover_and_load().get(SCENARIO_ID)
    assert record is not None

    provider = _connected_webshell_provider(webshell_test_server)
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
        event_store=webshell_event_store,
        config=RunConfig(
            dry_run=True,
            scenario_params={SCENARIO_ID: {"max_hosts": 2, "max_ports": 2}},
        ),
        dry_run=True,
    )
    targets = resolve_targets("10.10.10.0/24")

    provider.prepare(exec_ctx)
    summary = provider.execute(exec_ctx, record, run_ctx, targets)

    assert summary is None
    remote_result = exec_ctx.execution_metadata["remote_scenario_result"]
    remote_execution_id = exec_ctx.execution_metadata["remote_execution_id"]
    assert remote_execution_id == remote_result["remote_execution_id"]
    assert exec_ctx.execution_metadata["remote_execution_mode"] == REMOTE_EXECUTION_MODE_COMMAND
    assert webshell_test_server.command_calls, "remote command path was not invoked"
    assert not any("run_scenario.py" in call for call in webshell_test_server.upload_calls)
    assert not any("manifest.json" in call for call in webshell_test_server.upload_calls)
    assert not any("remote_discovery.py" in call for call in webshell_test_server.upload_calls)

    provider.cleanup(exec_ctx)

    event_count = assert_event_store_has_events(webshell_event_store, RUN_ID, minimum=3)
    assert webshell_event_store.count(
        EventQuery(run_id=RUN_ID, scenario_id=SCENARIO_ID, event="port_sweep_started")
    ) >= 1
    assert webshell_event_store.count(
        EventQuery(run_id=RUN_ID, scenario_id=SCENARIO_ID, event="webshell_command_dispatched")
    ) >= 1

    export_result = export_evidence(webshell_event_store, RUN_ID, e2e_output_dir)
    assert_evidence_exports_exist(e2e_output_dir, RUN_ID)
    assert export_result.export_metadata["event_count"] == event_count

    manual_result = generate_manual_verification(
        webshell_event_store,
        RUN_ID,
        e2e_output_dir,
    )
    assert_manual_verification_package_exists(e2e_output_dir)
    assert manual_result.run_id == RUN_ID
    assert len(manual_result.generated_files) == 3


def test_webshell_flow_excludes_validation_runtime() -> None:
    assert_harness_excludes_validation_runtime(Path(__file__))
