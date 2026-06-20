#!/usr/bin/env python3
"""Self-contained target_net discovery for webshell command-only runs."""

from __future__ import annotations

import ipaddress
import json
import socket
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

DISCOVERY_PORTS: tuple[int, ...] = (
    22,
    53,
    80,
    88,
    389,
    443,
    445,
    636,
    8080,
    8443,
    8888,
    9000,
    9090,
)
PORT_CAPABILITY_MAP: dict[int, str] = {
    443: "https_targets",
    8443: "https_targets",
    80: "http_targets",
    8080: "http_targets",
    8888: "http_targets",
    9000: "http_targets",
    9090: "http_targets",
    22: "ssh_hosts",
    53: "dns_hosts",
    88: "kerberos_hosts",
    389: "ldap_hosts",
    636: "ldap_hosts",
    445: "smb_hosts",
}
DEFAULT_PROBE_TIMEOUT = 0.5
DEFAULT_PROBE_WORKERS = 32


def expand_target_net_hosts(target_net: str, *, max_hosts: int = 254) -> list[str]:
    network = ipaddress.ip_network(target_net.strip(), strict=False)
    hosts: list[str] = []
    for addr in network.hosts():
        hosts.append(str(addr))
        if len(hosts) >= max_hosts:
            break
    return hosts


def _tcp_probe(host: str, port: int, timeout: float) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def discover_target_net(
    target_net: str,
    *,
    ports: tuple[int, ...] = DISCOVERY_PORTS,
    max_hosts: int = 254,
    timeout: float = DEFAULT_PROBE_TIMEOUT,
    workers: int = DEFAULT_PROBE_WORKERS,
) -> dict[str, Any]:
    """Live host + service discovery from the webshell host vantage point."""
    candidates = expand_target_net_hosts(target_net, max_hosts=max_hosts)
    service_hosts: dict[str, list[str]] = {
        "ssh_hosts": [],
        "dns_hosts": [],
        "kerberos_hosts": [],
        "ldap_hosts": [],
        "http_targets": [],
        "https_targets": [],
        "smb_hosts": [],
    }
    service_endpoints: dict[str, list[list[Any]]] = {
        key: [] for key in service_hosts
    }
    alive: set[str] = set()
    open_endpoints = 0

    def _probe(host: str, port: int) -> tuple[str, int, str | None]:
        if not _tcp_probe(host, port, timeout):
            return host, port, None
        return host, port, PORT_CAPABILITY_MAP.get(port)

    tasks = [(host, port) for host in candidates for port in ports if port in PORT_CAPABILITY_MAP]
    with ThreadPoolExecutor(max_workers=min(workers, max(1, len(tasks)))) as pool:
        futures = [pool.submit(_probe, host, port) for host, port in tasks]
        for future in as_completed(futures):
            host, port, capability = future.result()
            if capability is None:
                continue
            alive.add(host)
            open_endpoints += 1
            bucket = service_hosts.setdefault(capability, [])
            if host not in bucket:
                bucket.append(host)
            service_endpoints.setdefault(capability, []).append([host, port])

    for key in service_hosts:
        service_hosts[key] = sorted(
            service_hosts[key],
            key=lambda host: tuple(int(part) for part in host.split(".")),
        )
    alive_hosts = sorted(alive, key=lambda host: tuple(int(part) for part in host.split(".")))
    return {
        "target_net": target_net,
        "hosts": alive_hosts,
        "service_hosts": service_hosts,
        "service_endpoints": service_endpoints,
        "discovery_enabled": True,
        "discovery_meta": {
            "probed_hosts": len(candidates),
            "alive_hosts": alive_hosts,
            "open_endpoints": open_endpoints,
            "service_hosts": service_hosts,
            "discovery_origin": "webshell_host",
        },
    }


def _empty_payload(target_net: str, *, runner_error: str | None = None) -> dict[str, Any]:
    service_hosts = {
        "ssh_hosts": [],
        "dns_hosts": [],
        "kerberos_hosts": [],
        "ldap_hosts": [],
        "http_targets": [],
        "https_targets": [],
        "smb_hosts": [],
    }
    service_endpoints = {key: [] for key in service_hosts}
    discovery_meta: dict[str, Any] = {
        "probed_hosts": 0,
        "alive_hosts": [],
        "open_endpoints": 0,
        "service_hosts": service_hosts,
        "discovery_origin": "webshell_host",
    }
    if runner_error:
        discovery_meta["runner_error"] = runner_error
    return {
        "target_net": target_net,
        "hosts": [],
        "service_hosts": service_hosts,
        "service_endpoints": service_endpoints,
        "discovery_enabled": True,
        "discovery_meta": discovery_meta,
    }


def main(argv: list[str] | None = None) -> int:
    args = list(argv if argv is not None else sys.argv[1:])
    output_path = args[2] if len(args) > 2 else "/tmp/discovery_out.json"
    target_net = args[0] if args else ""
    try:
        if len(args) < 3:
            raise ValueError(
                "usage: discover_runner.py TARGET_NET MAX_HOSTS OUTPUT_JSON [TIMEOUT]"
            )
        target_net = args[0]
        max_hosts = int(args[1])
        timeout = float(args[3]) if len(args) > 3 else DEFAULT_PROBE_TIMEOUT
        payload = discover_target_net(target_net, max_hosts=max_hosts, timeout=timeout)
    except Exception as exc:
        payload = _empty_payload(target_net, runner_error=str(exc))
    with open(output_path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle)
    return 0 if not (payload.get("discovery_meta") or {}).get("runner_error") else 1


if __name__ == "__main__":
    raise SystemExit(main())
