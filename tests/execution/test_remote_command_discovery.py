"""Webshell command-only discovery must not assume open services without probe results."""

from __future__ import annotations

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
    run_webshell_host_discovery,
)


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


def test_live_discovery_uses_batched_tcp_probes() -> None:
    provider = MagicMock()
    provider.run_remote_command.return_value = b"DSP_PROBE_OPEN 10.10.10.1:80\n"
    request = MagicMock(
        scenario_params={"max_hosts": 2},
        target_net="10.10.10.0/30",
        dry_run=False,
    )
    ctx = MagicMock()
    ctx.config.scenario_params = {DISCOVERY_SCAN_MAX_HOSTS_KEY: 2}
    specs = build_discovery_probe_specs("10.10.10.0/30", max_hosts=2)
    targets = run_webshell_host_discovery(provider, ctx, request, specs)
    assert provider.run_remote_command.called
    command = provider.run_remote_command.call_args[0][0]
    assert command.startswith("python3 -c")
    assert "socket.create_connection" in command
    assert targets["service_hosts"]["http_targets"] == ["10.10.10.1"]
    assert targets["discovery_meta"]["discovery_method"] == "tcp_probe_batch"
    assert "parse_failed" not in targets["discovery_meta"]


def test_live_discovery_without_open_ports_returns_empty_service_buckets() -> None:
    provider = MagicMock()
    provider.run_remote_command.return_value = b""
    request = MagicMock(
        scenario_params={"max_hosts": 2},
        target_net="10.10.10.0/30",
        dry_run=False,
    )
    ctx = MagicMock()
    ctx.config.scenario_params = {DISCOVERY_SCAN_MAX_HOSTS_KEY: 2}
    specs = build_discovery_probe_specs("10.10.10.0/30", max_hosts=2)
    targets = run_webshell_host_discovery(provider, ctx, request, specs)
    assert targets["hosts"] == []
    assert not any(targets["service_hosts"].values())
    assert targets["discovery_meta"]["discovery_method"] == "tcp_probe_batch"
    assert "parse_failed" not in targets["discovery_meta"]


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
    )
    ctx = MagicMock()
    ctx.config.scenario_params = {DISCOVERY_SCAN_MAX_HOSTS_KEY: DISCOVERY_MAX_HOSTS}
    specs = build_discovery_probe_specs("10.10.10.0/24", max_hosts=DISCOVERY_MAX_HOSTS)
    run_webshell_host_discovery(provider, ctx, request, specs)
    expected_batches = (len(specs) + DISCOVERY_PROBE_BATCH_SIZE - 1) // DISCOVERY_PROBE_BATCH_SIZE
    assert provider.run_remote_command.call_count == expected_batches


def test_build_discovery_probe_specs_for_normal_profile_uses_scan_cap() -> None:
    specs = build_discovery_probe_specs("10.10.10.0/24", max_hosts=DISCOVERY_MAX_HOSTS)
    hosts = {spec["host"] for spec in specs}
    assert len(hosts) == DISCOVERY_MAX_HOSTS
    assert "10.10.10.110" in hosts
