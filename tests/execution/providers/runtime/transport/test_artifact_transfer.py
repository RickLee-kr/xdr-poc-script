"""Artifact transfer binding tests — MockHttpTransport only, no network."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest

from dsp.execution.providers.runtime import RuntimeArtifact
from dsp.execution.providers.runtime.transport import (
    TransportBackedRuntime,
    TransportCapabilityError,
    TransportConnectionError,
    TransportRuntimeConfiguration,
    TransportStateError,
)
from dsp.execution.webshell.transport import MockHttpTransport, MockTransportMode


def test_upload_success(connected_runtime_fresh_calls: TransportBackedRuntime):
    runtime = connected_runtime_fresh_calls
    session = runtime.active_session
    artifact = RuntimeArtifact.new(
        local_path="/tmp/payload.bin",
        remote_path="/uploads/payload.bin",
        checksum="abc",
        size_bytes=128,
    )
    result = runtime.upload_artifact(session, artifact)
    assert result.transfer_status == "uploaded"
    assert result.remote_path == "/uploads/payload.bin"
    assert result.created_at is not None
    assert result.transfer_metadata.get("operation") == "send_upload"
    upload_calls = [
        call for call in runtime.transport.calls if call["operation"] == "send_upload"
    ]
    assert len(upload_calls) == 1


def test_upload_requires_connected_state(transport_runtime: TransportBackedRuntime):
    session = transport_runtime.create_remote_session()
    artifact = RuntimeArtifact.new(local_path="/tmp/x", remote_path="/remote/x")
    with pytest.raises(TransportStateError, match="upload_artifact"):
        transport_runtime.upload_artifact(session, artifact)


def _runtime_without_connect_healthcheck(
    mock_transport: MockHttpTransport,
    mode: MockTransportMode,
) -> TransportBackedRuntime:
    mock_transport.mode = mode
    runtime = TransportBackedRuntime(
        mock_transport,
        webshell_url="https://lab.example/shell.jsp",
        config=TransportRuntimeConfiguration(enable_healthcheck_on_connect=False),
    )
    runtime.create_remote_session()
    runtime.connect()
    return runtime


def test_upload_timeout_handling(mock_transport: MockHttpTransport):
    runtime = _runtime_without_connect_healthcheck(
        mock_transport,
        MockTransportMode.SUCCESS,
    )
    mock_transport.mode = MockTransportMode.TIMEOUT
    artifact = RuntimeArtifact.new(local_path="/tmp/x", remote_path="/remote/x")
    with pytest.raises(TransportConnectionError, match="upload_artifact timed out"):
        runtime.upload_artifact(runtime.active_session, artifact)


def test_upload_auth_failure(mock_transport: MockHttpTransport):
    runtime = _runtime_without_connect_healthcheck(
        mock_transport,
        MockTransportMode.SUCCESS,
    )
    mock_transport.mode = MockTransportMode.AUTH_FAILURE
    artifact = RuntimeArtifact.new(local_path="/tmp/x", remote_path="/remote/x")
    with pytest.raises(TransportCapabilityError, match="upload_artifact rejected"):
        runtime.upload_artifact(runtime.active_session, artifact)


def test_upload_5xx_failure(mock_transport: MockHttpTransport):
    runtime = _runtime_without_connect_healthcheck(
        mock_transport,
        MockTransportMode.SUCCESS,
    )
    mock_transport.mode = MockTransportMode.HTTP_5XX
    artifact = RuntimeArtifact.new(local_path="/tmp/x", remote_path="/remote/x")
    with pytest.raises(TransportCapabilityError, match="upload_artifact rejected"):
        runtime.upload_artifact(runtime.active_session, artifact)


def test_download_success(connected_runtime_fresh_calls: TransportBackedRuntime):
    runtime = connected_runtime_fresh_calls
    session = runtime.active_session
    artifact = RuntimeArtifact.new(remote_path="/remote/payload.bin")
    result = runtime.download_artifact(session, artifact)
    assert result.transfer_status == "downloaded"
    local_path = Path(result.local_path)
    assert local_path.is_file()
    assert local_path.read_bytes() == runtime.transport.body
    assert result.size_bytes == len(runtime.transport.body)
    download_calls = [
        call for call in runtime.transport.calls if call["operation"] == "download"
    ]
    assert len(download_calls) == 1


def test_download_requires_connected_state(transport_runtime: TransportBackedRuntime):
    session = transport_runtime.create_remote_session()
    artifact = RuntimeArtifact.new(remote_path="/remote/x")
    with pytest.raises(TransportStateError, match="download_artifact"):
        transport_runtime.download_artifact(session, artifact)


def test_download_timeout_handling(mock_transport: MockHttpTransport):
    runtime = _runtime_without_connect_healthcheck(
        mock_transport,
        MockTransportMode.SUCCESS,
    )
    mock_transport.mode = MockTransportMode.TIMEOUT
    artifact = RuntimeArtifact.new(remote_path="/remote/x")
    with pytest.raises(TransportConnectionError, match="download_artifact timed out"):
        runtime.download_artifact(runtime.active_session, artifact)


def test_download_auth_failure(mock_transport: MockHttpTransport):
    runtime = _runtime_without_connect_healthcheck(
        mock_transport,
        MockTransportMode.SUCCESS,
    )
    mock_transport.mode = MockTransportMode.AUTH_FAILURE
    artifact = RuntimeArtifact.new(remote_path="/remote/x")
    with pytest.raises(TransportCapabilityError, match="download_artifact rejected"):
        runtime.download_artifact(runtime.active_session, artifact)


def test_download_5xx_failure(mock_transport: MockHttpTransport):
    runtime = _runtime_without_connect_healthcheck(
        mock_transport,
        MockTransportMode.SUCCESS,
    )
    mock_transport.mode = MockTransportMode.HTTP_5XX
    artifact = RuntimeArtifact.new(remote_path="/remote/x")
    with pytest.raises(TransportCapabilityError, match="download_artifact rejected"):
        runtime.download_artifact(runtime.active_session, artifact)


def test_artifact_metadata_populated(connected_runtime_fresh_calls: TransportBackedRuntime):
    runtime = connected_runtime_fresh_calls
    artifact = RuntimeArtifact.new(
        local_path="/tmp/data.bin",
        remote_path="/uploads/data.bin",
        checksum="deadbeef",
        size_bytes=64,
    )
    result = runtime.upload_artifact(runtime.active_session, artifact)
    assert result.artifact_id == artifact.artifact_id
    assert result.checksum == "deadbeef"
    assert result.transfer_status == "uploaded"
    assert result.transfer_metadata
    roundtrip = RuntimeArtifact.from_dict(result.to_dict())
    assert roundtrip.transfer_status == "uploaded"
    assert roundtrip.created_at is not None


def test_transport_methods_invoked_exactly_once(
    connected_runtime_fresh_calls: TransportBackedRuntime,
):
    runtime = connected_runtime_fresh_calls
    artifact = RuntimeArtifact.new(
        local_path="/tmp/x",
        remote_path="/remote/x",
    )
    runtime.upload_artifact(runtime.active_session, artifact)
    runtime.download_artifact(
        runtime.active_session,
        RuntimeArtifact.new(remote_path="/remote/y"),
    )
    operations = [call["operation"] for call in runtime.transport.calls]
    assert operations.count("send_upload") == 1
    assert operations.count("download") == 1


def test_send_get_never_called(connected_runtime_fresh_calls: TransportBackedRuntime):
    runtime = connected_runtime_fresh_calls
    artifact = RuntimeArtifact.new(local_path="/tmp/x", remote_path="/remote/x")
    runtime.upload_artifact(runtime.active_session, artifact)
    runtime.download_artifact(runtime.active_session, artifact)
    assert not any(call["operation"] == "send_get" for call in runtime.transport.calls)


def test_send_post_never_called(connected_runtime_fresh_calls: TransportBackedRuntime):
    runtime = connected_runtime_fresh_calls
    artifact = RuntimeArtifact.new(local_path="/tmp/x", remote_path="/remote/x")
    runtime.upload_artifact(runtime.active_session, artifact)
    runtime.download_artifact(runtime.active_session, artifact)
    assert not any(call["operation"] == "send_post" for call in runtime.transport.calls)


def test_event_store_never_accessed(connected_runtime_fresh_calls: TransportBackedRuntime):
    runtime = connected_runtime_fresh_calls
    event_store = MagicMock()
    artifact = RuntimeArtifact.new(local_path="/tmp/x", remote_path="/remote/x")
    runtime.upload_artifact(runtime.active_session, artifact)
    runtime.download_artifact(runtime.active_session, artifact)
    event_store.append_event.assert_not_called()
    event_store.write.assert_not_called()


def test_eventsync_bridge_never_invoked(
    connected_runtime_fresh_calls: TransportBackedRuntime,
):
    runtime = connected_runtime_fresh_calls
    bridge = MagicMock()
    artifact = RuntimeArtifact.new(local_path="/tmp/x", remote_path="/remote/x")
    runtime.upload_artifact(runtime.active_session, artifact)
    runtime.download_artifact(runtime.active_session, artifact)
    bridge.sync_events.assert_not_called()
    bridge.collect.assert_not_called()
