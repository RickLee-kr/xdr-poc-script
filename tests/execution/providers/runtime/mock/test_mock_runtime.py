"""MockProviderRuntime tests — lifecycle simulation, no execution."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from dsp.execution.providers.runtime import (
    RuntimeArtifact,
    RuntimeBundleReference,
    RuntimeSessionState,
    SessionError,
)
from dsp.execution.providers.runtime.mock import (
    MockBundleError,
    MockConnectionError,
    MockDownloadError,
    MockProviderRuntime,
    MockRuntimeConfiguration,
    MockUploadError,
)
from dsp.execution.providers.runtime.runtime_contract import ProviderRuntimeContract
from dsp.execution.providers.webshell.jsp import JspWebshellProvider
from dsp.execution.webshell.transport import MockHttpTransport


def test_runtime_creation():
    runtime = MockProviderRuntime(provider_type="php")
    assert isinstance(runtime, ProviderRuntimeContract)
    assert runtime.provider_type == "php"


def test_session_creation(mock_runtime: MockProviderRuntime):
    session = mock_runtime.create_remote_session()
    assert session.provider_type == "jsp"
    assert session.state == RuntimeSessionState.CREATED
    assert mock_runtime.get_session(session.session_id).state == RuntimeSessionState.CREATED


def test_connect_lifecycle(mock_runtime: MockProviderRuntime):
    mock_runtime.create_remote_session()
    mock_runtime.connect()
    assert mock_runtime.active_session.state == RuntimeSessionState.CONNECTED


def test_disconnect_lifecycle(connected_runtime: MockProviderRuntime):
    connected_runtime.disconnect()
    assert connected_runtime.active_session.state == RuntimeSessionState.DISCONNECTED


def test_close_lifecycle(mock_runtime: MockProviderRuntime):
    session = mock_runtime.create_remote_session()
    mock_runtime.connect()
    mock_runtime.disconnect()
    disconnected = mock_runtime.get_session(session.session_id)
    mock_runtime.close_remote_session(disconnected)
    closed = mock_runtime.get_session(session.session_id)
    assert closed.state == RuntimeSessionState.CLOSED


def test_invalid_state_transition(mock_runtime: MockProviderRuntime):
    mock_runtime.create_remote_session()
    mock_runtime.connect()
    with pytest.raises(SessionError, match="invalid state for connect"):
        mock_runtime.connect()


def test_upload_metadata_operation(connected_runtime: MockProviderRuntime):
    session = connected_runtime.active_session
    artifact = RuntimeArtifact.new(
        local_path="/tmp/payload.bin",
        remote_path="",
        checksum="deadbeef",
        size_bytes=512,
    )
    result = connected_runtime.upload_artifact(session, artifact)
    assert result.artifact_id == artifact.artifact_id
    assert result.remote_path == f"/remote/{artifact.artifact_id}"
    assert result.checksum == "deadbeef"
    assert result.size_bytes == 512


def test_download_metadata_operation(connected_runtime: MockProviderRuntime):
    session = connected_runtime.active_session
    artifact = RuntimeArtifact.new(
        local_path="",
        remote_path="/remote/payload.bin",
        checksum="cafebabe",
        size_bytes=256,
    )
    result = connected_runtime.download_artifact(session, artifact)
    assert result.artifact_id == artifact.artifact_id
    assert result.local_path == f"/local/{artifact.artifact_id}"
    assert result.remote_path == "/remote/payload.bin"


def test_bundle_metadata_operation(connected_runtime: MockProviderRuntime):
    session = connected_runtime.active_session
    bundle = RuntimeBundleReference.new(
        remote_path="/events/bundle.json",
        event_count=10,
    )
    result = connected_runtime.download_event_bundle(session, bundle)
    assert result.bundle_id == bundle.bundle_id
    assert result.remote_path == "/events/bundle.json"
    assert result.event_count == 10


def test_healthcheck_success(mock_runtime: MockProviderRuntime):
    assert mock_runtime.healthcheck() is True


def test_cleanup_success(mock_runtime: MockProviderRuntime):
    session = mock_runtime.create_remote_session()
    mock_runtime.connect()
    mock_runtime.cleanup()
    with pytest.raises(SessionError, match="session not found"):
        mock_runtime.get_session(session.session_id)


def test_connection_failure_simulation():
    runtime = MockProviderRuntime(
        provider_type="jsp",
        config=MockRuntimeConfiguration(simulate_connection_failure=True),
    )
    runtime.create_remote_session()
    with pytest.raises(MockConnectionError, match="simulated connection failure"):
        runtime.connect()


def test_upload_failure_simulation(connected_runtime: MockProviderRuntime):
    connected_runtime._config.simulate_upload_failure = True  # noqa: SLF001
    artifact = RuntimeArtifact.new(local_path="/tmp/x")
    with pytest.raises(MockUploadError, match="simulated upload failure"):
        connected_runtime.upload_artifact(connected_runtime.active_session, artifact)


def test_download_failure_simulation(connected_runtime: MockProviderRuntime):
    connected_runtime._config.simulate_download_failure = True  # noqa: SLF001
    artifact = RuntimeArtifact.new(remote_path="/remote/x")
    with pytest.raises(MockDownloadError, match="simulated download failure"):
        connected_runtime.download_artifact(connected_runtime.active_session, artifact)


def test_bundle_failure_simulation(connected_runtime: MockProviderRuntime):
    connected_runtime._config.simulate_bundle_failure = True  # noqa: SLF001
    bundle = RuntimeBundleReference.new(remote_path="/events/x")
    with pytest.raises(MockBundleError, match="simulated bundle failure"):
        connected_runtime.download_event_bundle(connected_runtime.active_session, bundle)


def test_provider_runtime_attachment(mock_runtime: MockProviderRuntime):
    provider = JspWebshellProvider()
    assert provider.get_runtime() is None
    provider.attach_runtime(mock_runtime)
    assert provider.get_runtime() is mock_runtime


def test_runtime_capability_exposure(jsp_provider_with_runtime):
    caps = jsp_provider_with_runtime.get_runtime_capabilities()
    assert caps.supports_connect is True
    assert caps.supports_upload is True
    assert caps.supports_download is True
    assert caps.supports_event_bundle is True
    assert caps.supports_healthcheck is True
    assert caps.supports_cleanup is True


def test_no_transport_or_eventsync_calls(mock_runtime: MockProviderRuntime):
    """Runtime lifecycle must not invoke transport or EventSyncBridge."""
    transport = MagicMock(spec=MockHttpTransport)
    transport.send_get = MagicMock()
    transport.healthcheck = MagicMock()

    mock_runtime.create_remote_session()
    mock_runtime.connect()
    mock_runtime.healthcheck()
    mock_runtime.cleanup()

    transport.send_get.assert_not_called()
    transport.healthcheck.assert_not_called()
