"""Webshell-origin discovery planning — command dispatch only, no DSP-side probes."""

from __future__ import annotations

from typing import Any

from dsp.discovery.legacy_bash import DISCOVERY_MAX_HOSTS, FAST_SAFE_DISCOVERY_PORTS
from dsp.execution.remote.command.models import DISCOVERY_ORIGIN_WEBSHELL
from dsp.execution.remote.command.shell import mock_noop_command, tcp_probe_command
from dsp.execution.remote.bundle.assets.remote_discovery import (
    DISCOVERY_PORTS,
    PORT_CAPABILITY_MAP,
    expand_target_net_hosts,
)


def build_discovery_probe_specs(
    target_net: str,
    *,
    max_hosts: int = DISCOVERY_MAX_HOSTS,
    ports: tuple[int, ...] | None = None,
) -> list[dict[str, Any]]:
    """Plan host:port probes — DSP plans targets; webshell host executes probes."""
    port_list = ports or FAST_SAFE_DISCOVERY_PORTS
    candidates = expand_target_net_hosts(target_net, max_hosts=max_hosts)
    specs: list[dict[str, Any]] = []
    for host in candidates:
        for port in port_list:
            specs.append({"host": host, "port": int(port), "capability": PORT_CAPABILITY_MAP.get(int(port))})
    return specs


def build_planned_discovery_targets(
    target_net: str,
    params: dict[str, Any],
    *,
    max_hosts: int = DISCOVERY_MAX_HOSTS,
    ports: tuple[int, ...] | None = None,
) -> dict[str, Any]:
    """Build discovery-first target buckets for follow-up planning without parsing probe output."""
    port_list = ports or DISCOVERY_PORTS
    candidates = expand_target_net_hosts(target_net, max_hosts=max_hosts)
    if params.get("hosts"):
        candidates = [str(h) for h in params["hosts"]][:max_hosts]

    service_hosts: dict[str, list[str]] = {
        "ssh_hosts": [],
        "dns_hosts": [],
        "kerberos_hosts": [],
        "ldap_hosts": [],
        "http_targets": [],
        "https_targets": [],
        "smb_hosts": [],
    }
    service_endpoints: dict[str, list[tuple[str, int]]] = {
        key: [] for key in service_hosts
    }
    for host in candidates:
        for port in port_list:
            capability = PORT_CAPABILITY_MAP.get(int(port))
            if capability is None:
                continue
            bucket = service_hosts.setdefault(capability, [])
            if host not in bucket:
                bucket.append(host)
            service_endpoints.setdefault(capability, []).append((host, int(port)))

    for key in service_hosts:
        service_hosts[key] = sorted(
            service_hosts[key],
            key=lambda h: tuple(int(p) for p in h.split(".")),
        )

    return {
        "target_net": target_net,
        "hosts": sorted(candidates, key=lambda h: tuple(int(p) for p in h.split("."))),
        "service_hosts": service_hosts,
        "service_endpoints": {key: list(value) for key, value in service_endpoints.items()},
        "discovery_enabled": True,
        "discovery_meta": {
            "probed_hosts": len(candidates),
            "alive_hosts": list(candidates),
            "open_endpoints": sum(len(v) for v in service_endpoints.values()),
            "service_hosts": service_hosts,
            "discovery_origin": DISCOVERY_ORIGIN_WEBSHELL,
            "planned_only": True,
        },
    }


def probe_commands_for_specs(
    specs: list[dict[str, Any]],
    *,
    timeout: float = 0.5,
    mock: bool = False,
) -> list[str]:
    if mock:
        return [mock_noop_command() for _ in specs]
    return [tcp_probe_command(spec["host"], spec["port"], timeout=timeout) for spec in specs]
