"""Provider runtime contract tests — definition only, no execution."""

from __future__ import annotations

import inspect

import pytest

from dsp.execution.providers.runtime import (
    ArtifactTransferError,
    BundleDownloadError,
    CleanupError,
    ConnectionError,
    HealthcheckError,
    ProviderRuntimeContract,
    ProviderRuntimeError,
    RuntimeArtifact,
    RuntimeBundleReference,
    RuntimeCapabilities,
    RuntimeCapabilityError,
    RuntimeSession,
    RuntimeSessionState,
    SessionError,
)
from dsp.execution.providers.webshell.jsp import JspWebshellProvider
from dsp.execution.providers.webshell.php import PhpWebshellProvider
from dsp.execution.providers.webshell.aspx import AspxWebshellProvider


def test_runtime_session_creation():
    session = RuntimeSession.new("jsp", remote_identifier="remote-abc")
    assert session.provider_type == "jsp"
    assert session.state == RuntimeSessionState.CREATED
    assert session.remote_identifier == "remote-abc"
    assert session.session_id


def test_runtime_artifact_creation():
    artifact = RuntimeArtifact.new(
        local_path="/tmp/payload.bin",
        remote_path="/uploads/payload.bin",
        checksum="abc123",
        size_bytes=1024,
    )
    assert artifact.local_path == "/tmp/payload.bin"
    assert artifact.remote_path == "/uploads/payload.bin"
    assert artifact.checksum == "abc123"
    assert artifact.size_bytes == 1024
    assert artifact.artifact_id


def test_bundle_reference_creation():
    bundle = RuntimeBundleReference.new(
        remote_path="/events/bundle.json",
        event_count=42,
    )
    assert bundle.remote_path == "/events/bundle.json"
    assert bundle.event_count == 42
    assert bundle.bundle_id
    assert bundle.created_at


def test_runtime_capability_defaults():
    caps = RuntimeCapabilities()
    assert caps.supports_connect is False
    assert caps.supports_upload is False
    assert caps.supports_download is False
    assert caps.supports_event_bundle is False
    assert caps.supports_healthcheck is False
    assert caps.supports_cleanup is False


def test_runtime_exception_hierarchy():
    assert issubclass(ConnectionError, ProviderRuntimeError)
    assert issubclass(SessionError, ProviderRuntimeError)
    assert issubclass(ArtifactTransferError, ProviderRuntimeError)
    assert issubclass(BundleDownloadError, ProviderRuntimeError)
    assert issubclass(RuntimeCapabilityError, ProviderRuntimeError)
    assert issubclass(HealthcheckError, ProviderRuntimeError)
    assert issubclass(CleanupError, ProviderRuntimeError)


def test_runtime_state_lifecycle_enum_validation():
    expected = {
        "created",
        "connecting",
        "connected",
        "disconnected",
        "error",
        "closed",
    }
    assert {state.value for state in RuntimeSessionState} == expected

    session = RuntimeSession.new("php")
    connected = session.transition(RuntimeSessionState.CONNECTING)
    assert connected.state == RuntimeSessionState.CONNECTING

    active = connected.transition(RuntimeSessionState.CONNECTED)
    assert active.state == RuntimeSessionState.CONNECTED

    disconnected = active.transition(RuntimeSessionState.DISCONNECTED)
    assert disconnected.state == RuntimeSessionState.DISCONNECTED

    closed = disconnected.transition(RuntimeSessionState.CLOSED)
    assert closed.state == RuntimeSessionState.CLOSED


def test_contract_abstract_method_validation():
    with pytest.raises(TypeError):
        ProviderRuntimeContract()

    abstract_methods = {
        name
        for name, value in inspect.getmembers(ProviderRuntimeContract)
        if getattr(value, "__isabstractmethod__", False)
    }
    assert abstract_methods == {
        "cleanup",
        "close_remote_session",
        "connect",
        "create_remote_session",
        "disconnect",
        "download_artifact",
        "download_event_bundle",
        "healthcheck",
        "upload_artifact",
    }


@pytest.mark.parametrize(
    "provider_cls",
    [JspWebshellProvider, PhpWebshellProvider, AspxWebshellProvider],
)
def test_provider_runtime_capability_exposure(provider_cls):
    provider = provider_cls()
    caps = provider.get_runtime_capabilities()
    assert isinstance(caps, RuntimeCapabilities)
    assert caps.to_dict() == {
        "supports_connect": False,
        "supports_upload": False,
        "supports_download": False,
        "supports_event_bundle": False,
        "supports_healthcheck": False,
        "supports_cleanup": False,
    }
