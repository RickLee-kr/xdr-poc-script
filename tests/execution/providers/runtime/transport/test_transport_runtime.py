"""TransportBackedRuntime tests — transport boundary only, no execution."""

from __future__ import annotations

import pytest

from dsp.execution.providers.runtime import (
    RuntimeArtifact,
    RuntimeBundleReference,
    RuntimeCapabilityError,
    RuntimeSessionState,
    SessionError,
)
from dsp.execution.providers.runtime.transport import (
    TransportBackedRuntime,
    TransportConnectionError,
    TransportRuntimeConfiguration,
)
from dsp.execution.providers.runtime.runtime_contract import ProviderRuntimeContract
from dsp.execution.providers.webshell.jsp import JspWebshellProvider
from dsp.execution.webshell.transport import MockHttpTransport, MockTransportMode


def test_runtime_creation(mock_transport: MockHttpTransport):
    runtime = TransportBackedRuntime(
        mock_transport,
        provider_type="php",
        webshell_url="https://lab.example/shell.php",
    )
    assert isinstance(runtime, ProviderRuntimeContract)
    assert runtime.transport is mock_transport
    assert runtime.provider_type == "php"


def test_transport_injection(mock_transport: MockHttpTransport):
    runtime = TransportBackedRuntime(
        mock_transport,
        webshell_url="https://lab.example/shell.jsp",
    )
    assert runtime.transport is mock_transport


def test_session_creation(transport_runtime: TransportBackedRuntime):
    session = transport_runtime.create_remote_session()
    assert session.provider_type == "jsp"
    assert session.state == RuntimeSessionState.CREATED


def test_connect_success(transport_runtime: TransportBackedRuntime):
    transport_runtime.create_remote_session()
    transport_runtime.connect()
    assert transport_runtime.active_session.state == RuntimeSessionState.CONNECTED
    assert any(call["operation"] == "healthcheck" for call in transport_runtime.transport.calls)
    assert not any(
        call["operation"] in {"send_get", "send_post", "send_upload", "download"}
        for call in transport_runtime.transport.calls
    )


def test_connect_failure(mock_transport: MockHttpTransport):
    mock_transport.mode = MockTransportMode.HTTP_5XX
    runtime = TransportBackedRuntime(
        mock_transport,
        provider_type="jsp",
        webshell_url="https://lab.example/shell.jsp",
    )
    session = runtime.create_remote_session()
    with pytest.raises(TransportConnectionError, match="healthcheck failed"):
        runtime.connect()
    assert runtime.get_session(session.session_id).state == RuntimeSessionState.ERROR


def test_disconnect_lifecycle(connected_transport_runtime: TransportBackedRuntime):
    connected_transport_runtime.disconnect()
    assert (
        connected_transport_runtime.active_session.state
        == RuntimeSessionState.DISCONNECTED
    )


def test_close_lifecycle(transport_runtime: TransportBackedRuntime):
    session = transport_runtime.create_remote_session()
    transport_runtime.connect()
    transport_runtime.disconnect()
    disconnected = transport_runtime.get_session(session.session_id)
    transport_runtime.close_remote_session(disconnected)
    assert (
        transport_runtime.get_session(session.session_id).state
        == RuntimeSessionState.CLOSED
    )


def test_healthcheck_delegation(mock_transport: MockHttpTransport):
    runtime = TransportBackedRuntime(
        mock_transport,
        webshell_url="https://lab.example/shell.jsp",
    )
    assert runtime.healthcheck() is True
    assert mock_transport.calls[-1]["operation"] == "healthcheck"


def test_cleanup_success(transport_runtime: TransportBackedRuntime):
    session = transport_runtime.create_remote_session()
    transport_runtime.connect()
    transport_runtime.cleanup()
    with pytest.raises(SessionError, match="session not found"):
        transport_runtime.get_session(session.session_id)


def test_event_bundle_requires_sync_dependencies(
    connected_transport_runtime: TransportBackedRuntime,
):
    session = connected_transport_runtime.active_session
    bundle = RuntimeBundleReference.new(remote_path="/events/bundle.json")
    with pytest.raises(
        RuntimeCapabilityError,
        match="event_sync_bridge and event_store",
    ):
        connected_transport_runtime.download_event_bundle(session, bundle)


def test_invalid_state_transition(transport_runtime: TransportBackedRuntime):
    transport_runtime.create_remote_session()
    transport_runtime.connect()
    with pytest.raises(SessionError, match="invalid state for connect"):
        transport_runtime.connect()


def test_provider_runtime_attachment(mock_transport: MockHttpTransport):
    runtime = TransportBackedRuntime(
        mock_transport,
        provider_type="jsp",
        webshell_url="https://lab.example/shell.jsp",
    )
    provider = JspWebshellProvider(transport=mock_transport)
    provider.attach_runtime(runtime)
    assert provider.get_runtime() is runtime


def test_capability_exposure(mock_transport: MockHttpTransport):
    runtime = TransportBackedRuntime(
        mock_transport,
        webshell_url="https://lab.example/shell.jsp",
    )
    provider = JspWebshellProvider()
    assert provider.get_runtime_capabilities().supports_connect is False
    provider.attach_runtime(runtime)
    caps = provider.get_runtime_capabilities()
    assert caps.supports_connect is True
    assert caps.supports_upload is True
    assert caps.supports_download is True
    assert caps.supports_event_bundle is True
    assert caps.supports_healthcheck is True
    assert caps.supports_cleanup is True


def test_forbidden_command_transport_calls_not_invoked(
    connected_transport_runtime: TransportBackedRuntime,
):
    """Connect uses healthcheck only — send_get/post must never be called."""
    forbidden = {"send_get", "send_post"}
    operations = {
        call["operation"] for call in connected_transport_runtime.transport.calls
    }
    assert "healthcheck" in operations
    assert operations.isdisjoint(forbidden)
