"""Webshell command-only discovery must not assume open services without probe results."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from dsp.execution.remote.command.discovery import (
    DISCOVERY_MAX_HOSTS,
    DISCOVERY_SCAN_MAX_HOSTS_KEY,
    build_discovery_probe_specs,
    build_discovery_targets_from_open_endpoints,
    build_mock_discovery_targets,
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


def test_discovery_parse_failure_returns_empty_targets() -> None:
    from unittest.mock import MagicMock

    from dsp.execution.remote.command.discovery import run_webshell_host_discovery

    provider = MagicMock()
    provider.run_remote_command.return_value = b"not-json"
    request = MagicMock(
        scenario_params={"max_hosts": 4},
        target_net="10.10.10.0/24",
        dry_run=False,
    )
    ctx = MagicMock()
    ctx.config.scenario_params = {}
    targets = run_webshell_host_discovery(provider, ctx, request, [])
    assert targets["hosts"] == []
    assert not any(targets["service_hosts"].values())
    assert targets["discovery_meta"].get("parse_failed") is True
    assert "fallback" not in targets["discovery_meta"]


def test_resolve_discovery_scan_max_hosts_defaults_to_full_subnet() -> None:
    assert resolve_discovery_scan_max_hosts({}, "10.10.10.0/24") == DISCOVERY_MAX_HOSTS
    assert resolve_discovery_scan_max_hosts({}, "192.168.55.0/30") == 2


def test_resolve_discovery_scan_max_hosts_honors_run_level_cap() -> None:
    params = {DISCOVERY_SCAN_MAX_HOSTS_KEY: 10}
    assert resolve_discovery_scan_max_hosts(params, "10.10.10.0/24") == 10


def test_run_webshell_host_discovery_ignores_scenario_follow_up_max_hosts() -> None:
    provider = MagicMock()
    provider.run_remote_command.return_value = (
        b'{"hosts":[],"service_hosts":{},"service_endpoints":{},'
        b'"discovery_meta":{"probed_hosts":254,"alive_hosts":[],"open_endpoints":0}}'
    )
    request = MagicMock(
        scenario_params={"max_hosts": 2},
        target_net="10.10.10.0/24",
        dry_run=False,
    )
    ctx = MagicMock()
    ctx.config.scenario_params = {DISCOVERY_SCAN_MAX_HOSTS_KEY: DISCOVERY_MAX_HOSTS}

    with patch(
        "dsp.execution.remote.command.discovery.build_remote_discovery_command",
    ) as mock_build:
        mock_build.return_value = "echo discovery"
        run_webshell_host_discovery(provider, ctx, request, [])

    mock_build.assert_called_once_with("10.10.10.0/24", max_hosts=DISCOVERY_MAX_HOSTS)


def test_build_discovery_probe_specs_for_normal_profile_uses_scan_cap() -> None:
    specs = build_discovery_probe_specs("10.10.10.0/24", max_hosts=DISCOVERY_MAX_HOSTS)
    hosts = {spec["host"] for spec in specs}
    assert len(hosts) == DISCOVERY_MAX_HOSTS
    assert "10.10.10.110" in hosts
