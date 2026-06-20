"""Webshell command-only discovery must not assume open services without probe results."""

from __future__ import annotations

from dsp.execution.remote.command.discovery import (
    build_discovery_targets_from_open_endpoints,
    build_mock_discovery_targets,
    build_discovery_probe_specs,
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
