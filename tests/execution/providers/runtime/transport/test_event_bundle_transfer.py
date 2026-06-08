"""Event bundle transfer binding tests — MockHttpTransport only, no network."""

from __future__ import annotations

import json
from unittest.mock import MagicMock

import pytest

from dsp.event_store import EventQuery, EventStore
from dsp.execution.providers.runtime import (
    BundleDownloadError,
    RuntimeArtifact,
    RuntimeBundleReference,
    RuntimeCapabilityError,
)
from dsp.execution.providers.runtime.transport import (
    TransportBackedRuntime,
    TransportCapabilityError,
    TransportConnectionError,
    TransportRuntimeConfiguration,
    TransportStateError,
)
from dsp.execution.providers.webshell.jsp import JspWebshellProvider
from dsp.execution.webshell.event_sync import (
    BundleValidationError,
    EventSyncBridge,
)
from dsp.execution.webshell.transport import MockHttpTransport, MockTransportMode
from tests.execution.webshell.event_sync.conftest import (
    RUN_ID,
    event_record,
    metadata_record,
)


def _bundle_jsonl_bytes(*, event_count: int = 1) -> bytes:
    events = [event_record() for _ in range(event_count)]
    lines = [json.dumps(metadata_record(event_count=event_count))]
    lines.extend(json.dumps(event) for event in events)
    return ("\n".join(lines) + "\n").encode("utf-8")


def test_bundle_download_success(connected_bundle_runtime_fresh_calls: TransportBackedRuntime):
    runtime = connected_bundle_runtime_fresh_calls
    runtime.transport.body = _bundle_jsonl_bytes(event_count=2)
    bundle = RuntimeBundleReference.new(remote_path="/events/bundle.jsonl")
    result = runtime.download_event_bundle(runtime.active_session, bundle)
    assert result.sync_status == "synced"
    assert result.event_count == 2
    assert result.sync_metadata.get("imported_count") == 2
    download_calls = [
        call for call in runtime.transport.calls if call["operation"] == "download"
    ]
    assert len(download_calls) == 1
    assert download_calls[0]["remote_path"] == "/events/bundle.jsonl"


def test_bundle_requires_connected_state(bundle_runtime: TransportBackedRuntime):
    session = bundle_runtime.create_remote_session()
    bundle = RuntimeBundleReference.new(remote_path="/events/bundle.jsonl")
    with pytest.raises(TransportStateError, match="download_event_bundle"):
        bundle_runtime.download_event_bundle(session, bundle)


def _runtime_without_connect_healthcheck(
    mock_transport: MockHttpTransport,
    mock_event_sync_bridge,
    fake_event_store: EventStore,
    mode: MockTransportMode,
) -> TransportBackedRuntime:
    mock_transport.mode = mode
    runtime = TransportBackedRuntime(
        mock_transport,
        event_sync_bridge=mock_event_sync_bridge,
        event_store=fake_event_store,
        webshell_url="https://lab.example/shell.jsp",
        config=TransportRuntimeConfiguration(enable_healthcheck_on_connect=False),
    )
    runtime.create_remote_session()
    runtime.connect()
    return runtime


def test_bundle_timeout_handling(
    mock_transport: MockHttpTransport,
    mock_event_sync_bridge,
    fake_event_store: EventStore,
):
    runtime = _runtime_without_connect_healthcheck(
        mock_transport,
        mock_event_sync_bridge,
        fake_event_store,
        MockTransportMode.SUCCESS,
    )
    mock_transport.mode = MockTransportMode.TIMEOUT
    bundle = RuntimeBundleReference.new(remote_path="/events/bundle.jsonl")
    with pytest.raises(TransportConnectionError, match="download_event_bundle timed out"):
        runtime.download_event_bundle(runtime.active_session, bundle)


def test_bundle_auth_failure(
    mock_transport: MockHttpTransport,
    mock_event_sync_bridge,
    fake_event_store: EventStore,
):
    runtime = _runtime_without_connect_healthcheck(
        mock_transport,
        mock_event_sync_bridge,
        fake_event_store,
        MockTransportMode.SUCCESS,
    )
    mock_transport.mode = MockTransportMode.AUTH_FAILURE
    bundle = RuntimeBundleReference.new(remote_path="/events/bundle.jsonl")
    with pytest.raises(TransportCapabilityError, match="download_event_bundle rejected"):
        runtime.download_event_bundle(runtime.active_session, bundle)


def test_bundle_5xx_failure(
    mock_transport: MockHttpTransport,
    mock_event_sync_bridge,
    fake_event_store: EventStore,
):
    runtime = _runtime_without_connect_healthcheck(
        mock_transport,
        mock_event_sync_bridge,
        fake_event_store,
        MockTransportMode.SUCCESS,
    )
    mock_transport.mode = MockTransportMode.HTTP_5XX
    bundle = RuntimeBundleReference.new(remote_path="/events/bundle.jsonl")
    with pytest.raises(TransportCapabilityError, match="download_event_bundle rejected"):
        runtime.download_event_bundle(runtime.active_session, bundle)


def test_eventsync_bridge_invoked_exactly_once(
    connected_bundle_runtime_fresh_calls: TransportBackedRuntime,
    mock_event_sync_bridge,
):
    runtime = connected_bundle_runtime_fresh_calls
    bundle = RuntimeBundleReference.new(remote_path="/events/bundle.jsonl")
    runtime.download_event_bundle(runtime.active_session, bundle)
    assert len(mock_event_sync_bridge.calls) == 1
    assert mock_event_sync_bridge.calls[0]["event_store"] is runtime.event_store


def test_event_store_accessed_only_through_bridge(
    connected_bundle_runtime_fresh_calls: TransportBackedRuntime,
    fake_event_store: EventStore,
):
    runtime = connected_bundle_runtime_fresh_calls
    append_spy = MagicMock(wraps=fake_event_store.append)
    fake_event_store.append = append_spy
    bundle = RuntimeBundleReference.new(remote_path="/events/bundle.jsonl")
    runtime.download_event_bundle(runtime.active_session, bundle)
    append_spy.assert_not_called()


def test_sync_metadata_populated(connected_bundle_runtime_fresh_calls: TransportBackedRuntime):
    runtime = connected_bundle_runtime_fresh_calls
    bundle = RuntimeBundleReference.new(remote_path="/events/bundle.jsonl")
    result = runtime.download_event_bundle(runtime.active_session, bundle)
    assert result.sync_status == "synced"
    assert result.sync_metadata["imported_count"] == 2
    assert result.sync_metadata["skipped_count"] == 0
    assert "bundle_metadata" in result.sync_metadata
    assert result.sync_metadata["transport_metadata"]["operation"] == "download"
    roundtrip = RuntimeBundleReference.from_dict(result.to_dict())
    assert roundtrip.sync_status == "synced"
    assert roundtrip.sync_metadata["imported_count"] == 2


def test_bundle_failure_mapping(
    connected_bundle_runtime_fresh_calls: TransportBackedRuntime,
    mock_event_sync_bridge,
):
    runtime = connected_bundle_runtime_fresh_calls
    mock_event_sync_bridge.error = BundleValidationError(
        "malformed bundle",
        rule="malformed_json",
    )
    bundle = RuntimeBundleReference.new(remote_path="/events/bundle.jsonl", bundle_id="b-1")
    with pytest.raises(BundleDownloadError, match="event sync failed") as exc_info:
        runtime.download_event_bundle(runtime.active_session, bundle)
    assert exc_info.value.bundle_id == "b-1"


def test_send_get_never_called(connected_bundle_runtime_fresh_calls: TransportBackedRuntime):
    runtime = connected_bundle_runtime_fresh_calls
    bundle = RuntimeBundleReference.new(remote_path="/events/bundle.jsonl")
    runtime.download_event_bundle(runtime.active_session, bundle)
    assert not any(call["operation"] == "send_get" for call in runtime.transport.calls)


def test_send_post_never_called(connected_bundle_runtime_fresh_calls: TransportBackedRuntime):
    runtime = connected_bundle_runtime_fresh_calls
    bundle = RuntimeBundleReference.new(remote_path="/events/bundle.jsonl")
    runtime.download_event_bundle(runtime.active_session, bundle)
    assert not any(call["operation"] == "send_post" for call in runtime.transport.calls)


def test_artifact_transfer_unaffected(connected_runtime_fresh_calls: TransportBackedRuntime):
    runtime = connected_runtime_fresh_calls
    artifact = RuntimeArtifact.new(local_path="/tmp/x", remote_path="/remote/x")
    upload_result = runtime.upload_artifact(runtime.active_session, artifact)
    download_result = runtime.download_artifact(
        runtime.active_session,
        RuntimeArtifact.new(remote_path="/remote/y"),
    )
    assert upload_result.transfer_status == "uploaded"
    assert download_result.transfer_status == "downloaded"
    operations = {call["operation"] for call in runtime.transport.calls}
    assert operations == {"send_upload", "download"}


def test_upload_unaffected(connected_runtime_fresh_calls: TransportBackedRuntime):
    runtime = connected_runtime_fresh_calls
    artifact = RuntimeArtifact.new(local_path="/tmp/payload.bin", remote_path="/uploads/payload.bin")
    result = runtime.upload_artifact(runtime.active_session, artifact)
    assert result.transfer_status == "uploaded"
    assert any(call["operation"] == "send_upload" for call in runtime.transport.calls)


def test_provider_integration_unaffected(mock_transport: MockHttpTransport):
    runtime = TransportBackedRuntime(
        mock_transport,
        provider_type="jsp",
        webshell_url="https://lab.example/shell.jsp",
    )
    provider = JspWebshellProvider(transport=mock_transport)
    provider.attach_runtime(runtime)
    assert provider.get_runtime() is runtime
    caps = provider.get_runtime_capabilities()
    assert caps.supports_event_bundle is True


def test_no_direct_event_store_access(
    connected_bundle_runtime_fresh_calls: TransportBackedRuntime,
    fake_event_store: EventStore,
):
    runtime = connected_bundle_runtime_fresh_calls
    direct_append = MagicMock()
    direct_list = MagicMock()
    fake_event_store.append = direct_append
    fake_event_store.list_events = direct_list
    bundle = RuntimeBundleReference.new(remote_path="/events/bundle.jsonl")
    runtime.download_event_bundle(runtime.active_session, bundle)
    direct_append.assert_not_called()
    direct_list.assert_not_called()


def test_real_bridge_imports_into_event_store(
    mock_transport: MockHttpTransport,
    fake_event_store: EventStore,
):
    mock_transport.body = _bundle_jsonl_bytes(event_count=1)
    runtime = TransportBackedRuntime(
        mock_transport,
        event_sync_bridge=EventSyncBridge(),
        event_store=fake_event_store,
        webshell_url="https://lab.example/shell.jsp",
        config=TransportRuntimeConfiguration(enable_healthcheck_on_connect=False),
    )
    runtime.create_remote_session()
    runtime.connect()
    bundle = RuntimeBundleReference.new(remote_path="/events/bundle.jsonl")
    result = runtime.download_event_bundle(runtime.active_session, bundle)
    assert result.sync_status == "synced"
    assert result.event_count == 1
    assert fake_event_store.count(EventQuery(run_id=RUN_ID)) == 1


def test_bundle_requires_event_sync_dependencies(transport_runtime: TransportBackedRuntime):
    transport_runtime.create_remote_session()
    transport_runtime.connect()
    bundle = RuntimeBundleReference.new(remote_path="/events/bundle.jsonl")
    with pytest.raises(RuntimeCapabilityError, match="event_sync_bridge and event_store"):
        transport_runtime.download_event_bundle(transport_runtime.active_session, bundle)
