"""Rare protocol activity planning — discovery-first target selection."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from dsp.engine.scenario_engine import TargetSet
from dsp.engine.target_engine import expand_target_net_hosts
from dsp.runtime.scenario_plan import INITIAL_COMPROMISE_ENDPOINT_KEY, WEBSHELL_EXECUTION_KEY

RARE_PROTOCOL_PORTS: dict[str, int] = {
    "TELNET": 23,
    "RTSP": 554,
    "SIP": 5060,
    "RTP": 5004,
}

DEFAULT_RTP_BURST = 8
MAX_RTP_BURST = 32


@dataclass(frozen=True)
class PlannedRareProbe:
    """Single rare-protocol probe action."""

    protocol: str
    host: str
    port: int
    transport: str
    artifact: str
    rtp_packets: int = 0


def _execution_host(targets: TargetSet, params: dict[str, Any]) -> str:
    endpoint = params.get(INITIAL_COMPROMISE_ENDPOINT_KEY)
    if isinstance(endpoint, dict) and endpoint.get("host"):
        return str(endpoint["host"])
    ws_ctx = params.get(WEBSHELL_EXECUTION_KEY)
    if isinstance(ws_ctx, dict) and ws_ctx.get("execution_host"):
        return str(ws_ctx["execution_host"])
    if params.get("execution_host"):
        return str(params["execution_host"])
    if targets.hosts:
        return str(targets.hosts[0])
    expanded = expand_target_net_hosts(targets.target_net, max_hosts=1)
    return expanded[0] if expanded else "127.0.0.1"


def _discovered_rare_endpoints(targets: TargetSet) -> list[tuple[str, int, str]]:
    rare_ports = set(RARE_PROTOCOL_PORTS.values())
    port_to_protocol = {port: name for name, port in RARE_PROTOCOL_PORTS.items()}
    found: list[tuple[str, int, str]] = []
    seen: set[tuple[str, int]] = set()

    for endpoints in targets.service_endpoints.values():
        for host, port in endpoints:
            if port in rare_ports and (host, port) not in seen:
                seen.add((host, port))
                found.append((host, port, port_to_protocol[port]))

    meta = targets.discovery_meta or {}
    open_eps = meta.get("open_endpoints")
    if isinstance(open_eps, list):
        for item in open_eps:
            if isinstance(item, (list, tuple)) and len(item) >= 2:
                host, port = str(item[0]), int(item[1])
                if port in rare_ports and (host, port) not in seen:
                    seen.add((host, port))
                    found.append((host, port, port_to_protocol[port]))

    return found


def _alive_probe_hosts(targets: TargetSet, params: dict[str, Any]) -> list[str]:
    """One discovery alive host for rare-protocol fallback, excluding the webshell origin."""
    execution_host = _execution_host(targets, params)
    meta = targets.discovery_meta or {}
    raw_alive = meta.get("alive_hosts") or targets.hosts or []
    alive = [str(h) for h in raw_alive if str(h) != execution_host]
    if alive:
        return [alive[0]]
    if raw_alive:
        return [str(raw_alive[0])]
    return []


def _probe_fallback_hosts(targets: TargetSet, params: dict[str, Any]) -> list[str]:
    if params.get("probe_hosts"):
        return [str(h) for h in params["probe_hosts"]]
    if params.get("hosts"):
        return [str(h) for h in params["hosts"]]
    alive = _alive_probe_hosts(targets, params)
    if alive:
        return alive
    return [_execution_host(targets, params)]


def _transport_for(protocol: str) -> str:
    if protocol == "RTP":
        return "udp"
    if protocol == "SIP":
        return "udp_tcp"
    return "tcp"


def plan_rare_protocol_activity(
    targets: TargetSet,
    params: dict[str, Any],
) -> list[PlannedRareProbe]:
    """Build rare-protocol probes — discovery endpoints first, safe probe fallback."""
    plans: list[PlannedRareProbe] = []
    seen: set[tuple[str, int, str]] = set()
    rtp_burst = min(
        MAX_RTP_BURST,
        max(1, int(params.get("rtp_burst_count", DEFAULT_RTP_BURST))),
    )

    explicit = params.get("targets") or []
    for item in explicit:
        protocol = str(item.get("protocol", "")).upper()
        host = str(item.get("host", ""))
        port = int(item.get("port", RARE_PROTOCOL_PORTS.get(protocol, 0)))
        if not protocol or not host or port <= 0:
            continue
        key = (host, port, protocol)
        if key in seen:
            continue
        seen.add(key)
        plans.append(
            PlannedRareProbe(
                protocol=protocol,
                host=host,
                port=port,
                transport=_transport_for(protocol),
                artifact=f"{protocol.lower()}:{host}:{port}",
                rtp_packets=rtp_burst if protocol == "RTP" else 0,
            )
        )

    for host, port, protocol in _discovered_rare_endpoints(targets):
        key = (host, port, protocol)
        if key in seen:
            continue
        seen.add(key)
        plans.append(
            PlannedRareProbe(
                protocol=protocol,
                host=host,
                port=port,
                transport=_transport_for(protocol),
                artifact=f"{protocol.lower()}:{host}:{port}",
                rtp_packets=rtp_burst if protocol == "RTP" else 0,
            )
        )

    protocols_needed = {p for p in RARE_PROTOCOL_PORTS if not any(pl.protocol == p for pl in plans)}
    if protocols_needed:
        for host in _probe_fallback_hosts(targets, params):
            for protocol in sorted(protocols_needed):
                port = RARE_PROTOCOL_PORTS[protocol]
                key = (host, port, protocol)
                if key in seen:
                    continue
                seen.add(key)
                plans.append(
                    PlannedRareProbe(
                        protocol=protocol,
                        host=host,
                        port=port,
                        transport=_transport_for(protocol),
                        artifact=f"{protocol.lower()}:{host}:{port}",
                        rtp_packets=rtp_burst if protocol == "RTP" else 0,
                    )
                )

    return plans
