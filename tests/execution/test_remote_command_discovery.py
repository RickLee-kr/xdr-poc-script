"""Webshell command-only discovery must not assume open services without probe results."""

from __future__ import annotations

import socket
import subprocess
import threading
from unittest.mock import MagicMock

from dsp.execution.remote.command.discovery import (
    DISCOVERY_MAX_HOSTS,
    DISCOVERY_PROBE_BATCH_SIZE,
    DISCOVERY_SCAN_MAX_HOSTS_KEY,
    build_discovery_probe_specs,
    build_discovery_targets_from_open_endpoints,
    build_mock_discovery_targets,
    parse_tcp_probe_discovery_output,
    resolve_discovery_scan_max_hosts,
    run_discovery_from_tcp_probes,
    run_webshell_host_discovery,
)
from dsp.execution.remote.command.models import (
    COMMAND_DELIVERY_INLINE_BASE64_EXEC,
    DISCOVERY_METHOD_COMMAND_INLINE_BASE64_EXEC,
)
from dsp.execution.remote.command.shell import (
    PROBE_OPEN_MARKER,
    tcp_probe_batch_discovery_command,
    tcp_probe_discovery_command,
)


def test_tcp_probe_discovery_commands_execute_without_syntax_error() -> None:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]
    accepted: list[socket.socket] = []

    def _accept() -> None:
        conn, _addr = listener.accept()
        accepted.append(conn)

    thread = threading.Thread(target=_accept, daemon=True)
    thread.start()

    try:
        commands = (
            tcp_probe_discovery_command(
                "127.0.0.1",
                port,
                output_path="/tmp/dsp-probe-single-test.out",
            ),
            tcp_probe_batch_discovery_command(
                [("127.0.0.1", port), ("127.0.0.1", port + 1)],
                output_path="/tmp/dsp-probe-batch-test.out",
            ),
        )
        single_output = subprocess.run(
            ["bash", "-lc", commands[0]],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        batch_output = subprocess.run(
            ["bash", "-lc", commands[1]],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        for completed in (single_output, batch_output):
            assert "SyntaxError" not in (completed.stderr or "")
            assert PROBE_OPEN_MARKER in (completed.stdout or "")
        assert f"{PROBE_OPEN_MARKER} 127.0.0.1:{port}" in (batch_output.stdout or "")
    finally:
        listener.close()
        for conn in accepted:
            conn.close()
        thread.join(timeout=2)


def test_mock_discovery_does_not_assign_services_without_probe_results() -> None:
    targets = build_mock_discovery_targets("10.10.10.0/24", {}, max_hosts=4)
    assert targets["hosts"]
    assert not any(targets["service_hosts"].values())
    assert not any(targets["service_endpoints"].values())
    assert targets["discovery_meta"]["open_endpoints"] == 0
    assert targets["discovery_meta"].get("planned_only") is False


def test_discovery_targets_only_include_open_endpoints() -> None:
    specs = build_discovery_probe_specs("10.10.10.0/24", max_hosts=2)
    open_only = {("10.10.10.1", 80), ("10.10.10.2", 22)}
    targets = build_discovery_targets_from_open_endpoints(
        "10.10.10.0/24",
        specs,
        open_only,
    )
    assert targets["hosts"] == ["10.10.10.1", "10.10.10.2"]
    assert targets["service_hosts"]["http_targets"] == ["10.10.10.1"]
    assert targets["service_hosts"]["ssh_hosts"] == ["10.10.10.2"]
    assert ("10.10.10.1", 443) not in targets["service_endpoints"]["https_targets"]


def test_parse_tcp_probe_discovery_output_collects_open_endpoints() -> None:
    raw = b"DSP_PROBE_OPEN 10.10.10.1:80\nnoise\nDSP_PROBE_OPEN 10.10.10.2:22\n"
    assert parse_tcp_probe_discovery_output(raw) == {
        ("10.10.10.1", 80),
        ("10.10.10.2", 22),
    }


def test_run_discovery_from_tcp_probes_uses_python_inline_batches() -> None:
    provider = MagicMock()
    specs = build_discovery_probe_specs("10.10.10.0/30", max_hosts=2)
    marker_line = f"{PROBE_OPEN_MARKER} 10.10.10.1:80\n".encode()

    def _run_remote_command(command: str, *, timeout_seconds: float = 300.0) -> bytes:
        assert "python3 -c" in command
        assert "base64" in command
        assert "discover_runner.py" not in command
        assert "py_compile" not in command
        return marker_line

    provider.run_remote_command.side_effect = _run_remote_command
    targets = run_discovery_from_tcp_probes(
        provider,
        "10.10.10.0/30",
        specs,
        run_id="run123",
        batch_size=DISCOVERY_PROBE_BATCH_SIZE,
    )
    assert targets["hosts"] == ["10.10.10.1"]
    assert targets["service_hosts"]["http_targets"] == ["10.10.10.1"]
    assert targets["discovery_meta"]["discovery_method"] == DISCOVERY_METHOD_COMMAND_INLINE_BASE64_EXEC
    assert targets["discovery_meta"]["command_delivery"] == COMMAND_DELIVERY_INLINE_BASE64_EXEC
    assert targets["discovery_meta"]["runner_upload"] is False
    assert provider.run_remote_command.call_count >= 1


def test_live_discovery_uses_tcp_probe_batches_only() -> None:
    provider = MagicMock()
    marker_line = f"{PROBE_OPEN_MARKER} 10.10.10.1:80\n".encode()

    def _run_remote_command(command: str, *, timeout_seconds: float = 300.0) -> bytes:
        if "discover_runner.py" in command or "py_compile" in command:
            raise AssertionError(f"forbidden deployed discovery command: {command!r}")
        if "base64.b64decode" in command and "discover_runner" in command:
            raise AssertionError(f"forbidden upload command: {command!r}")
        return marker_line

    provider.run_remote_command.side_effect = _run_remote_command
    request = MagicMock(
        scenario_params={"max_hosts": 2},
        target_net="10.10.10.0/30",
        dry_run=False,
        run_id="run123",
        scenario_id="http_followup",
        execution_metadata={"remote_work_dir": "/tmp/dsp"},
    )
    ctx = MagicMock()
    ctx.config.scenario_params = {DISCOVERY_SCAN_MAX_HOSTS_KEY: 2}
    specs = build_discovery_probe_specs("10.10.10.0/30", max_hosts=2)
    targets = run_webshell_host_discovery(provider, ctx, request, specs)
    assert targets["service_hosts"]["http_targets"] == ["10.10.10.1"]
    assert targets["discovery_meta"]["discovery_method"] == DISCOVERY_METHOD_COMMAND_INLINE_BASE64_EXEC
    assert targets["discovery_meta"]["command_delivery"] == COMMAND_DELIVERY_INLINE_BASE64_EXEC
    assert targets["discovery_meta"]["runner_upload"] is False


def test_live_discovery_without_open_ports_returns_empty_service_buckets() -> None:
    provider = MagicMock()
    provider.run_remote_command.return_value = b""

    request = MagicMock(
        scenario_params={"max_hosts": 2},
        target_net="10.10.10.0/30",
        dry_run=False,
        run_id="run123",
        scenario_id="http_followup",
        execution_metadata={"remote_work_dir": "/tmp/dsp"},
    )
    ctx = MagicMock()
    ctx.config.scenario_params = {DISCOVERY_SCAN_MAX_HOSTS_KEY: 2}
    specs = build_discovery_probe_specs("10.10.10.0/30", max_hosts=2)
    targets = run_webshell_host_discovery(provider, ctx, request, specs)
    assert targets["hosts"] == []
    assert not any(targets["service_hosts"].values())
    assert targets["discovery_meta"]["discovery_method"] == DISCOVERY_METHOD_COMMAND_INLINE_BASE64_EXEC
    assert targets["discovery_meta"]["command_delivery"] == COMMAND_DELIVERY_INLINE_BASE64_EXEC
    assert targets["discovery_meta"]["runner_upload"] is False


def test_resolve_discovery_scan_max_hosts_defaults_to_full_subnet() -> None:
    assert resolve_discovery_scan_max_hosts({}, "10.10.10.0/24") == DISCOVERY_MAX_HOSTS
    assert resolve_discovery_scan_max_hosts({}, "192.168.55.0/30") == 2


def test_resolve_discovery_scan_max_hosts_honors_run_level_cap() -> None:
    params = {DISCOVERY_SCAN_MAX_HOSTS_KEY: 10}
    assert resolve_discovery_scan_max_hosts(params, "10.10.10.0/24") == 10


def test_run_webshell_host_discovery_ignores_scenario_follow_up_max_hosts() -> None:
    provider = MagicMock()
    provider.run_remote_command.return_value = b""

    request = MagicMock(
        scenario_params={"max_hosts": 2},
        target_net="10.10.10.0/24",
        dry_run=False,
        run_id="run123",
        scenario_id="http_followup",
        execution_metadata={"remote_work_dir": "/tmp/dsp"},
    )
    ctx = MagicMock()
    ctx.config.scenario_params = {DISCOVERY_SCAN_MAX_HOSTS_KEY: DISCOVERY_MAX_HOSTS}
    specs = build_discovery_probe_specs("10.10.10.0/24", max_hosts=DISCOVERY_MAX_HOSTS)
    run_webshell_host_discovery(provider, ctx, request, specs)
    expected_batches = (
        len(specs) + DISCOVERY_PROBE_BATCH_SIZE - 1
    ) // DISCOVERY_PROBE_BATCH_SIZE
    assert provider.run_remote_command.call_count == expected_batches


def test_build_discovery_probe_specs_for_normal_profile_uses_scan_cap() -> None:
    specs = build_discovery_probe_specs("10.10.10.0/24", max_hosts=DISCOVERY_MAX_HOSTS)
    hosts = {spec["host"] for spec in specs}
    assert len(hosts) == DISCOVERY_MAX_HOSTS
    assert "10.10.10.110" in hosts
