"""Rare protocol activity planning — discovery-first target selection."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from dsp.engine.scenario_engine import TargetSet

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
    """Build rare-protocol probes from discovery endpoints only."""
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

    return plans
