"""Shared fixtures for transport-backed runtime tests."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest

from dsp.event_store import EventStore
from dsp.execution.providers.runtime.transport import TransportBackedRuntime
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
        imported_count=2,
        skipped_count=0,
        bundle_metadata=EventBundleMetadata(
            run_id="sync_run_01",
            scenario_id="dns_tunnel",
            scenario_version="1.0.0",
            generated_at=datetime(2026, 6, 6, 12, 0, 0, tzinfo=timezone.utc),
            event_count=2,
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
def transport_runtime(mock_transport: MockHttpTransport) -> TransportBackedRuntime:
    return TransportBackedRuntime(
        mock_transport,
        provider_type="jsp",
        webshell_url="https://lab.example/shell.jsp",
    )


@pytest.fixture
def bundle_runtime(
    mock_transport: MockHttpTransport,
    mock_event_sync_bridge: MockEventSyncBridge,
    fake_event_store: EventStore,
) -> TransportBackedRuntime:
    return TransportBackedRuntime(
        mock_transport,
        event_sync_bridge=mock_event_sync_bridge,
        event_store=fake_event_store,
        provider_type="jsp",
        webshell_url="https://lab.example/shell.jsp",
    )


@pytest.fixture
def connected_transport_runtime(
    transport_runtime: TransportBackedRuntime,
) -> TransportBackedRuntime:
    transport_runtime.create_remote_session()
    transport_runtime.connect()
    return transport_runtime


@pytest.fixture
def connected_bundle_runtime(
    bundle_runtime: TransportBackedRuntime,
) -> TransportBackedRuntime:
    bundle_runtime.create_remote_session()
    bundle_runtime.connect()
    return bundle_runtime


@pytest.fixture
def connected_runtime_fresh_calls(
    connected_transport_runtime: TransportBackedRuntime,
) -> TransportBackedRuntime:
    connected_transport_runtime.transport.calls.clear()
    return connected_transport_runtime


@pytest.fixture
def connected_bundle_runtime_fresh_calls(
    connected_bundle_runtime: TransportBackedRuntime,
) -> TransportBackedRuntime:
    connected_bundle_runtime.transport.calls.clear()
    return connected_bundle_runtime
