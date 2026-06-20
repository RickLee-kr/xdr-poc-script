"""Self-contained target_net discovery and scenario planning for webshell bundle runs."""

from __future__ import annotations

import base64
import ipaddress
import random
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

from dsp.protocols.http.sqli_payloads import plan_sqli_requests
from dsp.protocols.http.urls import HTTP_PORT_PRIORITY, plan_followup_requests
from dsp.runtime.http_endpoint_selection import select_discovered_http_endpoint_tuples

DISCOVERY_PORTS: tuple[int, ...] = (22, 53, 80, 88, 389, 443, 445, 636, 8080, 8443, 8888, 9000, 9090)
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
SSH_USERNAMES = ("invaliduser", "admin", "root")
DEFAULT_PORTS = (22, 80, 443, 445, 8080, 8443)


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
    service_endpoints: dict[str, list[tuple[str, int]]] = {
        "ssh_hosts": [],
        "dns_hosts": [],
        "kerberos_hosts": [],
        "ldap_hosts": [],
        "http_targets": [],
        "https_targets": [],
        "smb_hosts": [],
    }
    alive: set[str] = set()
    open_endpoints = 0

    def _probe(host: str, port: int) -> tuple[str, int, str | None]:
        if not _tcp_probe(host, port, timeout):
            return host, port, None
        return host, port, PORT_CAPABILITY_MAP.get(port)

    tasks = [(host, port) for host in candidates for port in ports]
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
            service_endpoints.setdefault(capability, []).append((host, port))

    for key in service_hosts:
        service_hosts[key] = sorted(service_hosts[key], key=lambda h: tuple(int(p) for p in h.split(".")))
    alive_hosts = sorted(alive, key=lambda h: tuple(int(p) for p in h.split(".")))
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


def _hosts_for(targets: dict[str, Any], capability: str) -> list[str]:
    return list((targets.get("service_hosts") or {}).get(capability, []))


def _select_http_endpoints(targets: dict[str, Any], params: dict[str, Any]) -> list[tuple[str, int]]:
    max_hosts = int(params.get("max_hosts", 2))
    explicit = [str(h) for h in params["hosts"]] if params.get("hosts") else None
    http_hosts = _hosts_for(targets, "http_targets")
    http_endpoints = list((targets.get("service_endpoints") or {}).get("http_targets", []))
    return select_discovered_http_endpoint_tuples(
        http_hosts=http_hosts,
        http_endpoints=http_endpoints,
        max_hosts=max_hosts,
        explicit_hosts=explicit,
        explicit_port=int(params.get("port", 80)),
    )


def _plan_http_followup(targets: dict[str, Any], params: dict[str, Any], *, dry_run: bool) -> dict[str, Any]:
    endpoints = _select_http_endpoints(targets, params)
    if not endpoints:
        return {"type": "http_followup", "mode": "skip", "reason": "no_http_endpoints"}
    max_hosts = int(params.get("max_hosts", 2))
    plans = plan_followup_requests(
        endpoints=endpoints,
        max_hosts=max_hosts,
        max_per_host=int(params.get("max_per_host", 10)),
        max_total=int(params.get("max_total", 20)),
        include_attack_paths=bool(params.get("include_attack_paths", True)),
    )
    return {
        "type": "http_followup",
        "mode": "mock" if dry_run else "live",
        "timeout": float(params.get("timeout", 10.0)),
        "requests": [
            {
                "url": plan.url,
                "method": plan.method,
                "user_agent": (plan.headers or {}).get("User-Agent", "Mozilla/5.0"),
            }
            for plan in plans
        ],
        "non_standard_port_burst": {"enabled": False},
    }


def _plan_sql_injection(targets: dict[str, Any], params: dict[str, Any], *, dry_run: bool) -> dict[str, Any]:
    endpoints = _select_http_endpoints(targets, params)
    if not endpoints:
        return {"type": "sql_injection", "mode": "skip", "reason": "no_http_endpoints"}
    max_hosts = int(params.get("max_hosts", 2))
    plans = plan_sqli_requests(
        endpoints=endpoints,
        max_hosts=max_hosts,
        max_per_host=int(params.get("max_per_host", 10)),
        max_total=int(params.get("max_total", 20)),
    )
    requests: list[dict[str, Any]] = []
    for plan in plans:
        item: dict[str, Any] = {
            "url": plan.url,
            "method": plan.method,
            "payload_category": plan.payload_category,
            "parameter": plan.parameter,
        }
        if plan.body is not None:
            item["body_b64"] = base64.b64encode(plan.body).decode("ascii")
            item["content_type"] = plan.content_type
        requests.append(item)
    return {
        "type": "sql_injection",
        "mode": "mock" if dry_run else "live",
        "timeout": float(params.get("timeout", 10.0)),
        "requests": requests,
    }


def _plan_ssh_failure(targets: dict[str, Any], params: dict[str, Any], *, dry_run: bool) -> dict[str, Any]:
    max_hosts = int(params.get("max_hosts", 2))
    if "hosts" in params:
        hosts = [str(h) for h in params["hosts"]][:max_hosts]
    else:
        hosts = _hosts_for(targets, "ssh_hosts")[:max_hosts]
    if not hosts:
        return {"type": "ssh_failure", "mode": "skip", "reason": "no_ssh_hosts"}
    port = int(params.get("port", 22))
    max_total = int(params.get("max_total", 150))
    attempts: list[dict[str, Any]] = []
    for host in hosts:
        for index in range(min(int(params.get("max_per_host", 150)), max_total - len(attempts))):
            attempts.append(
                {
                    "host": host,
                    "port": port,
                    "username": SSH_USERNAMES[index % len(SSH_USERNAMES)],
                    "password_label": "Password123",
                }
            )
            if len(attempts) >= max_total:
                break
    return {
        "type": "ssh_failure",
        "mode": "mock" if dry_run else "live",
        "timeout": float(params.get("timeout", 5.0)),
        "attempts": attempts,
    }


def _plan_port_sweep(targets: dict[str, Any], params: dict[str, Any], *, dry_run: bool) -> dict[str, Any]:
    max_hosts = int(params.get("max_hosts", 2))
    hosts = list(targets.get("hosts") or [])[:max_hosts]
    if params.get("hosts"):
        hosts = [str(h) for h in params["hosts"]][:max_hosts]
    if not hosts:
        hosts = expand_target_net_hosts(str(targets.get("target_net") or "10.10.10.0/24"), max_hosts=max_hosts)
    ports = tuple(int(p) for p in (params.get("ports") or DEFAULT_PORTS))
    max_ports = int(params.get("max_ports", len(ports)))
    selected_ports = ports[:max_ports]
    probes = [
        {"host": host, "port": port, "artifact": f"{host}:{port}"}
        for host in hosts
        for port in selected_ports
    ]
    return {
        "type": "port_sweep",
        "mode": "mock" if dry_run else "live",
        "timeout": float(params.get("timeout", 3.0)),
        "concurrency": max(1, int(params.get("concurrency", 32))),
        "probes": probes,
    }


def _plan_dns_tunnel(targets: dict[str, Any], params: dict[str, Any], *, dry_run: bool) -> dict[str, Any]:
    max_hosts = int(params.get("max_hosts", 2))
    hosts = _hosts_for(targets, "dns_hosts")[:max_hosts]
    if params.get("hosts"):
        hosts = [str(h) for h in params["hosts"]][:max_hosts]
    if not hosts:
        return {"type": "dns_tunnel", "mode": "skip", "reason": "no_dns_hosts"}
    domain = str(params.get("domain", "dns-tunnel.com"))
    total = int(params.get("max_chunks", 3))
    queries = []
    for target in hosts:
        for seq in range(1, total + 1):
            fqdn = f"{seq:04d}.chunk.dns-tunnel.{domain}"
            queries.append(
                {
                    "target": target,
                    "seq": seq,
                    "fqdn": fqdn,
                    "chunk_bytes": 32,
                    "label_length": len(fqdn),
                }
            )
    return {
        "type": "dns_tunnel",
        "mode": "mock" if dry_run else "live",
        "domain": domain,
        "timeout": float(params.get("timeout", 0.05)),
        "queries": queries,
        "burst_schedule": [len(queries)],
    }


def _plan_host_behavior_check(params: dict[str, Any], *, dry_run: bool) -> dict[str, Any]:
    endpoint = params.get("initial_compromise_endpoint") or {}
    host = str(endpoint.get("host") or params.get("target_host") or "127.0.0.1")
    return {
        "type": "host_behavior_check",
        "mode": "mock" if dry_run else "live",
        "timeout": float(params.get("timeout", 30.0)),
        "target_host": host,
        "commands": list(params.get("commands") or [{"name": "whoami", "shell": "whoami"}]),
        "credential_checks": list(params.get("credential_checks") or []),
        "eicar": params.get("eicar"),
        "eicar_variants": list(params.get("eicar_variants") or []),
        "suspicious_scripts": list(params.get("suspicious_scripts") or []),
        "persistence_artifacts": list(params.get("persistence_artifacts") or []),
        "archives": list(params.get("archives") or []),
    }


def _plan_rare_protocol_activity(targets: dict[str, Any], params: dict[str, Any], *, dry_run: bool) -> dict[str, Any]:
    host = str(params.get("host") or (targets.get("hosts") or ["127.0.0.1"])[0])
    return {
        "type": "rare_protocol_activity",
        "mode": "mock" if dry_run else "live",
        "timeout": float(params.get("timeout", 3.0)),
        "probes": [
            {
                "protocol": "rtsp",
                "host": host,
                "port": int(params.get("port", 554)),
                "transport": "tcp",
                "artifact": f"rtsp://{host}:554/",
                "rtp_packets": 0,
            }
        ],
    }


def build_plan_from_discovery(
    scenario_id: str,
    targets: dict[str, Any],
    params: dict[str, Any],
    *,
    dry_run: bool,
) -> dict[str, Any]:
    """Build an executable scenario plan from remote discovery results."""
    builders = {
        "http_followup": _plan_http_followup,
        "sql_injection": _plan_sql_injection,
        "ssh_failure": _plan_ssh_failure,
        "port_sweep": _plan_port_sweep,
        "dns_tunnel": _plan_dns_tunnel,
        "rare_protocol_activity": _plan_rare_protocol_activity,
    }
    if scenario_id == "host_behavior_check":
        return _plan_host_behavior_check(params, dry_run=dry_run)
    builder = builders.get(scenario_id)
    if builder is None:
        return {"type": "skip", "mode": "skip", "reason": f"unsupported_scenario:{scenario_id}"}
    return builder(targets, params, dry_run=dry_run)


def resolve_remote_discovery_plan(plan: dict[str, Any]) -> dict[str, Any]:
    """Run discovery on the webshell host and materialize the scenario plan."""
    discovery_cfg = dict(plan.get("discovery") or {})
    target_net = str(discovery_cfg.get("target_net") or "")
    max_hosts = int(discovery_cfg.get("max_hosts", 254))
    ports = tuple(int(p) for p in (discovery_cfg.get("ports") or DISCOVERY_PORTS))
    dry_run = plan.get("mode") == "mock"
    scenario_id = str(plan.get("scenario_id") or "")
    params = dict(plan.get("params") or {})
    targets = discover_target_net(target_net, ports=ports, max_hosts=max_hosts)
    executable = build_plan_from_discovery(scenario_id, targets, params, dry_run=dry_run)
    executable["discovery_result"] = targets.get("discovery_meta")
    return executable
