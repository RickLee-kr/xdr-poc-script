"""Command runtime binding tests — MockHttpTransport only, no network."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from dsp.execution.providers.runtime.command import (
    CommandEncoder,
    CommandExecutionContract,
    CommandExecutionError,
    CommandExecutionPolicy,
    CommandPolicyViolationError,
    CommandRequest,
    CommandStatus,
    CommandTransportError,
)
from dsp.execution.providers.runtime.transport import (
    TransportBackedRuntime,
    TransportRuntimeConfiguration,
    TransportStateError,
)
from dsp.execution.providers.webshell.jsp import JspWebshellProvider
from dsp.execution.webshell.transport import MockHttpTransport, MockTransportMode


def test_execute_command_success(connected_command_runtime_fresh_calls: TransportBackedRuntime):
    runtime = connected_command_runtime_fresh_calls
    request = CommandRequest.new("whoami")
    result = runtime.execute_command(request)
    assert result.status == CommandStatus.COMPLETED
    assert result.command_id == request.command_id
    assert result.started_at is not None
    assert result.completed_at is not None
    assert result.execution_metadata["delivery_only"] is True
    assert result.execution_metadata["transport_method"] in {"send_get", "send_post"}
    operations = [call["operation"] for call in runtime.transport.calls]
    assert "send_get" in operations or "send_post" in operations


def test_execute_requires_connected_state(command_runtime: TransportBackedRuntime):
    command_runtime.create_remote_session()
    request = CommandRequest.new("id")
    with pytest.raises(TransportStateError, match="execute_command"):
        command_runtime.execute_command(request)


def test_policy_violation(mock_transport: MockHttpTransport):
    runtime = TransportBackedRuntime(
        mock_transport,
        webshell_url="https://lab.example/shell.jsp",
        config=TransportRuntimeConfiguration(
            enable_healthcheck_on_connect=False,
            command_policy=CommandExecutionPolicy(),
        ),
    )
    runtime.create_remote_session()
    runtime.connect()
    request = CommandRequest.new("id")
    with pytest.raises(CommandPolicyViolationError, match="disabled by policy"):
        runtime.execute_command(request)


def test_timeout_violation(connected_command_runtime_fresh_calls: TransportBackedRuntime):
    runtime = connected_command_runtime_fresh_calls
    request = CommandRequest.new("id", timeout_seconds=600)
    with pytest.raises(CommandPolicyViolationError, match="exceeds policy maximum"):
        runtime.execute_command(request)


def test_encoder_invocation(connected_command_runtime_fresh_calls: TransportBackedRuntime):
    runtime = connected_command_runtime_fresh_calls
    encoder = MagicMock(spec=CommandEncoder, wraps=runtime.command_encoder)
    runtime._command_encoder = encoder
    request = CommandRequest.new("hostname")
    runtime.execute_command(request)
    encoder.encode_request.assert_called_once()


def test_get_selection(connected_command_runtime_fresh_calls: TransportBackedRuntime):
    runtime = connected_command_runtime_fresh_calls
    request = CommandRequest.new("id")
    result = runtime.execute_command(request)
    assert result.execution_metadata["transport_method"] == "send_get"
    assert runtime.transport.calls[-1]["operation"] == "send_get"


def test_post_selection(connected_command_runtime_fresh_calls: TransportBackedRuntime):
    runtime = connected_command_runtime_fresh_calls
    large_argument = "x" * 400
    request = CommandRequest.new("run", arguments=[large_argument])
    result = runtime.execute_command(request)
    assert result.execution_metadata["transport_method"] == "send_post"
    assert runtime.transport.calls[-1]["operation"] == "send_post"


def test_transport_timeout_mapping(
    mock_transport: MockHttpTransport,
    command_policy: CommandExecutionPolicy,
):
    runtime = TransportBackedRuntime(
        mock_transport,
        webshell_url="https://lab.example/shell.jsp",
        config=TransportRuntimeConfiguration(
            enable_healthcheck_on_connect=False,
            command_policy=command_policy,
        ),
    )
    runtime.create_remote_session()
    runtime.connect()
    mock_transport.mode = MockTransportMode.TIMEOUT
    request = CommandRequest.new("id")
    with pytest.raises(CommandTransportError, match="execute_command timed out"):
        runtime.execute_command(request)


def test_transport_rejection_mapping(
    mock_transport: MockHttpTransport,
    command_policy: CommandExecutionPolicy,
):
    runtime = TransportBackedRuntime(
        mock_transport,
        webshell_url="https://lab.example/shell.jsp",
        config=TransportRuntimeConfiguration(
            enable_healthcheck_on_connect=False,
            command_policy=command_policy,
        ),
    )
    runtime.create_remote_session()
    runtime.connect()
    mock_transport.mode = MockTransportMode.AUTH_FAILURE
    request = CommandRequest.new("id")
    with pytest.raises(CommandTransportError, match="execute_command rejected"):
        runtime.execute_command(request)


def test_command_metadata_populated(connected_command_runtime_fresh_calls: TransportBackedRuntime):
    runtime = connected_command_runtime_fresh_calls
    request = CommandRequest.new("uname", arguments=["-a"])
    result = runtime.execute_command(request)
    metadata = result.execution_metadata
    assert metadata["transport_method"] in {"send_get", "send_post"}
    assert isinstance(metadata["request_size"], int)
    assert metadata["request_size"] > 0
    assert metadata["transport_status"] == 200
    assert metadata["delivery_only"] is True


def test_stdout_not_present(connected_command_runtime_fresh_calls: TransportBackedRuntime):
    runtime = connected_command_runtime_fresh_calls
    runtime.transport.body = b"command output should be ignored"
    result = runtime.execute_command(CommandRequest.new("id"))
    metadata = result.execution_metadata
    forbidden = {"stdout", "stderr", "output", "parsed_output", "execution_success"}
    assert forbidden.isdisjoint(metadata.keys())
    assert "command output should be ignored" not in str(metadata)


def test_stderr_not_present(connected_command_runtime_fresh_calls: TransportBackedRuntime):
    runtime = connected_command_runtime_fresh_calls
    result = runtime.execute_command(CommandRequest.new("id"))
    metadata = result.execution_metadata
    assert "stderr" not in metadata
    assert "stdout" not in metadata


def test_event_store_not_accessed(
    connected_command_runtime_fresh_calls: TransportBackedRuntime,
    fake_event_store,
):
    runtime = connected_command_runtime_fresh_calls
    append_spy = MagicMock(wraps=fake_event_store.append)
    fake_event_store.append = append_spy
    runtime.execute_command(CommandRequest.new("id"))
    append_spy.assert_not_called()


def test_eventsync_bridge_not_invoked(
    connected_command_runtime_fresh_calls: TransportBackedRuntime,
    mock_event_sync_bridge,
):
    runtime = connected_command_runtime_fresh_calls
    runtime.execute_command(CommandRequest.new("id"))
    assert mock_event_sync_bridge.calls == []


def test_cancel_command(command_runtime: TransportBackedRuntime):
    result = command_runtime.cancel_command("cmd-cancel-1")
    assert result.status == CommandStatus.CANCELLED
    assert result.command_id == "cmd-cancel-1"
    assert result.execution_metadata["cancelled_locally"] is True


def test_provider_integration(
    mock_transport: MockHttpTransport,
    command_policy: CommandExecutionPolicy,
):
    runtime = TransportBackedRuntime(
        mock_transport,
        provider_type="jsp",
        webshell_url="https://lab.example/shell.jsp",
        config=TransportRuntimeConfiguration(command_policy=command_policy),
    )
    provider = JspWebshellProvider(transport=mock_transport)
    provider.attach_runtime(runtime)
    assert provider.get_runtime() is runtime
    assert isinstance(runtime, CommandExecutionContract)


def test_command_capability_exposure(
    mock_transport: MockHttpTransport,
    command_policy: CommandExecutionPolicy,
):
    runtime = TransportBackedRuntime(
        mock_transport,
        config=TransportRuntimeConfiguration(command_policy=command_policy),
    )
    provider = JspWebshellProvider()
    assert provider.get_command_capabilities().allow_command_execution is False
    provider.attach_runtime(runtime)
    caps = provider.get_command_capabilities()
    assert caps.allow_command_execution is True
    assert caps.max_timeout_seconds == 300


def test_encoder_failure_mapping(connected_command_runtime_fresh_calls: TransportBackedRuntime):
    runtime = connected_command_runtime_fresh_calls
    encoder = MagicMock(spec=CommandEncoder)
    encoder.encode_request.side_effect = ValueError("bad payload")
    runtime._command_encoder = encoder
    with pytest.raises(CommandExecutionError, match="command encoding failed"):
        runtime.execute_command(CommandRequest.new("id"))
