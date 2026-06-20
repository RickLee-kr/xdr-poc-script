"""Webshell command-only discovery must not assume open services without probe results."""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

from dsp.execution.remote.command.discovery import (
    DISCOVERY_HOST_CHUNK_SIZE,
    DISCOVERY_MAX_HOSTS,
    DISCOVERY_SCAN_MAX_HOSTS_KEY,
    _discovery_host_chunk_plan,
    _merge_discovery_chunk_targets,
    build_discovery_probe_specs,
    build_discovery_targets_from_open_endpoints,
    build_mock_discovery_targets,
    parse_deployed_discovery_output,
    parse_tcp_probe_discovery_output,
    resolve_discovery_scan_max_hosts,
    run_deployed_webshell_discovery,
    run_webshell_host_discovery,
)


def test_discovery_host_chunk_plan_splits_full_subnet() -> None:
    plan = _discovery_host_chunk_plan(DISCOVERY_MAX_HOSTS)
    assert sum(limit for _, limit in plan) == DISCOVERY_MAX_HOSTS
    assert all(limit <= DISCOVERY_HOST_CHUNK_SIZE for _, limit in plan)
    assert plan[0] == (0, DISCOVERY_HOST_CHUNK_SIZE)


def test_merge_discovery_chunk_targets_combines_alive_hosts() -> None:
    chunks = [
        {
            "hosts": ["10.10.10.1"],
            "service_hosts": {"http_targets": ["10.10.10.1"]},
            "service_endpoints": {"http_targets": [("10.10.10.1", 80)]},
            "discovery_meta": {
                "probed_hosts": 40,
                "alive_hosts": ["10.10.10.1"],
                "open_endpoints": 1,
            },
        },
        {
            "hosts": ["10.10.10.50"],
            "service_hosts": {"ssh_hosts": ["10.10.10.50"]},
            "service_endpoints": {"ssh_hosts": [("10.10.10.50", 22)]},
            "discovery_meta": {
                "probed_hosts": 40,
                "alive_hosts": ["10.10.10.50"],
                "open_endpoints": 1,
            },
        },
    ]
    merged = _merge_discovery_chunk_targets(
        chunks,
        target_net="10.10.10.0/24",
        discovery_max_hosts=DISCOVERY_MAX_HOSTS,
        upload_method="multipart",
    )
    assert merged["hosts"] == ["10.10.10.1", "10.10.10.50"]
    assert merged["service_hosts"]["http_targets"] == ["10.10.10.1"]
    assert merged["service_hosts"]["ssh_hosts"] == ["10.10.10.50"]
    assert merged["discovery_meta"]["discovery_chunks"] == 2
    assert merged["discovery_meta"]["open_endpoints"] == 2


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


def test_parse_deployed_discovery_output_normalizes_service_endpoints() -> None:
    payload = {
        "hosts": ["10.10.10.1"],
        "service_hosts": {"http_targets": ["10.10.10.1"]},
        "service_endpoints": {"http_targets": [["10.10.10.1", 80]]},
        "discovery_meta": {"alive_hosts": ["10.10.10.1"], "open_endpoints": 1},
    }
    raw = json.dumps(payload).encode()
    targets = parse_deployed_discovery_output(raw)
    assert targets["service_endpoints"]["http_targets"] == [("10.10.10.1", 80)]
    assert targets["discovery_meta"]["discovery_method"] == "deployed_runner"


def test_run_deployed_webshell_discovery_uploads_runner_and_parses_json() -> None:
    provider = MagicMock()
    discovery_json = json.dumps(
        {
            "hosts": ["10.10.10.97"],
            "service_hosts": {"http_targets": ["10.10.10.97"]},
            "service_endpoints": {"http_targets": [["10.10.10.97", 80]]},
            "discovery_meta": {
                "alive_hosts": ["10.10.10.97"],
                "open_endpoints": 1,
                "service_hosts": {"http_targets": ["10.10.10.97"]},
            },
        }
    ).encode()

    def _run_remote_command(command: str, *, timeout_seconds: float = 300.0) -> bytes:
        if "py_compile" in command:
            return b""
        if "discover_runner.py" in command or "DSP_DISCOVERY" in command:
            return discovery_json
        return b""

    provider.run_remote_command.side_effect = _run_remote_command
    request = MagicMock(
        run_id="run123",
        execution_metadata={"remote_work_dir": "/tmp/dsp"},
    )
    with patch(
        "dsp.execution.remote.command.discovery._upload_discovery_runner_asset",
        return_value="multipart",
    ) as mock_upload:
        targets = run_deployed_webshell_discovery(
            provider,
            request,
            "10.10.10.0/24",
            254,
        )
    mock_upload.assert_called_once()
    assert targets["hosts"] == ["10.10.10.97"]
    assert targets["discovery_meta"]["discovery_method"] == "deployed_runner"
    assert targets["discovery_meta"]["upload_method"] == "multipart"


def test_live_discovery_prefers_deployed_runner() -> None:
    provider = MagicMock()
    discovery_json = json.dumps(
        {
            "hosts": ["10.10.10.1"],
            "service_hosts": {"http_targets": ["10.10.10.1"]},
            "service_endpoints": {"http_targets": [["10.10.10.1", 80]]},
            "discovery_meta": {
                "alive_hosts": ["10.10.10.1"],
                "open_endpoints": 1,
                "service_hosts": {"http_targets": ["10.10.10.1"]},
            },
        }
    ).encode()

    def _run_remote_command(command: str, *, timeout_seconds: float = 300.0) -> bytes:
        if "py_compile" in command:
            return b""
        if "discover_runner.py" in command:
            return discovery_json
        if "DSP_PROBE_OPEN" in command or "dsp-probe-" in command:
            raise AssertionError(f"unexpected tcp probe fallback command: {command!r}")
        return b""

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
    with patch(
        "dsp.execution.remote.command.discovery._upload_discovery_runner_asset",
        return_value="multipart",
    ):
        targets = run_webshell_host_discovery(provider, ctx, request, specs)
    assert targets["service_hosts"]["http_targets"] == ["10.10.10.1"]
    assert targets["discovery_meta"]["discovery_method"] == "deployed_runner"


def test_live_discovery_without_open_ports_returns_empty_service_buckets() -> None:
    provider = MagicMock()
    discovery_json = json.dumps(
        {
            "hosts": [],
            "service_hosts": {},
            "service_endpoints": {},
            "discovery_meta": {
                "alive_hosts": [],
                "open_endpoints": 0,
                "service_hosts": {},
            },
        }
    ).encode()

    def _run_remote_command(command: str, *, timeout_seconds: float = 300.0) -> bytes:
        if "py_compile" in command:
            return b""
        if "discover_runner.py" in command or "DSP_DISCOVERY" in command:
            return discovery_json
        return b""

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
    with patch(
        "dsp.execution.remote.command.discovery._upload_discovery_runner_asset",
        return_value="python_base64",
    ):
        targets = run_webshell_host_discovery(provider, ctx, request, specs)
    assert targets["hosts"] == []
    assert not any(targets["service_hosts"].values())
    assert targets["discovery_meta"]["discovery_method"] == "deployed_runner"
    assert "parse_failed" not in targets["discovery_meta"]


def test_resolve_discovery_scan_max_hosts_defaults_to_full_subnet() -> None:
    assert resolve_discovery_scan_max_hosts({}, "10.10.10.0/24") == DISCOVERY_MAX_HOSTS
    assert resolve_discovery_scan_max_hosts({}, "192.168.55.0/30") == 2


def test_resolve_discovery_scan_max_hosts_honors_run_level_cap() -> None:
    params = {DISCOVERY_SCAN_MAX_HOSTS_KEY: 10}
    assert resolve_discovery_scan_max_hosts(params, "10.10.10.0/24") == 10


def test_run_webshell_host_discovery_ignores_scenario_follow_up_max_hosts() -> None:
    provider = MagicMock()
    discovery_json = json.dumps(
        {
            "hosts": [],
            "service_hosts": {},
            "service_endpoints": {},
            "discovery_meta": {"alive_hosts": [], "open_endpoints": 0, "service_hosts": {}},
        }
    ).encode()

    def _run_remote_command(command: str, *, timeout_seconds: float = 300.0) -> bytes:
        if "py_compile" in command:
            return b""
        if "discover_runner.py" in command or "DSP_DISCOVERY" in command:
            return discovery_json
        return b""

    provider.run_remote_command.side_effect = _run_remote_command
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
    with patch(
        "dsp.execution.remote.command.discovery._upload_discovery_runner_asset",
        return_value="multipart",
    ) as mock_upload:
        run_webshell_host_discovery(provider, ctx, request, specs)
    mock_upload.assert_called_once()
    assert provider.run_remote_command.call_count >= 2


def test_build_discovery_probe_specs_for_normal_profile_uses_scan_cap() -> None:
    specs = build_discovery_probe_specs("10.10.10.0/24", max_hosts=DISCOVERY_MAX_HOSTS)
    hosts = {spec["host"] for spec in specs}
    assert len(hosts) == DISCOVERY_MAX_HOSTS
    assert "10.10.10.110" in hosts
