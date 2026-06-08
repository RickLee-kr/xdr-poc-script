"""Shared fixtures for command runtime binding tests."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest

from dsp.event_store import EventStore
from dsp.execution.providers.runtime.command import CommandExecutionPolicy
from dsp.execution.providers.runtime.transport import (
    TransportBackedRuntime,
    TransportRuntimeConfiguration,
)
from dsp.execution.webshell.event_sync.base import EventSyncBridgeBase
from dsp.execution.webshell.event_sync.models import (
    EventBundleMetadata,
    EventSyncResult,
)
from dsp.execution.webshell.transport import MockHttpTransport


@pytest.fixture
def mock_transport() -> MockHttpTransport:
    return MockHttpTransport()


@dataclass
class MockEventSyncBridge(EventSyncBridgeBase):
    """Test double — records sync_bundle calls without filesystem I/O."""

    result: EventSyncResult | None = None
    error: Exception | None = None
    calls: list[dict[str, Any]] = field(default_factory=list)

    def sync_bundle(
        self,
        bundle_path: str | Path,
        event_store: EventStore,
    ) -> EventSyncResult:
        self.calls.append(
            {
                "bundle_path": str(bundle_path),
                "event_store": event_store,
            }
        )
        if self.error is not None:
            raise self.error
        assert self.result is not None
        return self.result


def _default_sync_result() -> EventSyncResult:
    return EventSyncResult(
        imported_count=1,
        skipped_count=0,
        bundle_metadata=EventBundleMetadata(
            run_id="sync_run_01",
            scenario_id="dns_tunnel",
            scenario_version="1.0.0",
            generated_at=datetime(2026, 6, 6, 12, 0, 0, tzinfo=timezone.utc),
            event_count=1,
            schema_version="1.0.0",
        ),
    )


@pytest.fixture
def fake_event_store() -> EventStore:
    store = EventStore(":memory:")
    store.open_run("sync_run_01")
    return store


@pytest.fixture
def mock_event_sync_bridge() -> MockEventSyncBridge:
    return MockEventSyncBridge(result=_default_sync_result())


@pytest.fixture
def command_policy() -> CommandExecutionPolicy:
    return CommandExecutionPolicy(allow_command_execution=True)


@pytest.fixture
def command_runtime(
    mock_transport: MockHttpTransport,
    command_policy: CommandExecutionPolicy,
) -> TransportBackedRuntime:
    return TransportBackedRuntime(
        mock_transport,
        provider_type="jsp",
        webshell_url="https://lab.example/shell.jsp",
        config=TransportRuntimeConfiguration(
            command_policy=command_policy,
            command_get_post_threshold_bytes=256,
        ),
    )


@pytest.fixture
def connected_command_runtime(
    command_runtime: TransportBackedRuntime,
) -> TransportBackedRuntime:
    command_runtime.create_remote_session()
    command_runtime.connect()
    return command_runtime


@pytest.fixture
def connected_command_runtime_fresh_calls(
    connected_command_runtime: TransportBackedRuntime,
) -> TransportBackedRuntime:
    connected_command_runtime.transport.calls.clear()
    return connected_command_runtime
