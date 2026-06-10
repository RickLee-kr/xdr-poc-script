"""Port sweep probe planning — horizontal port sweep across hosts."""

from __future__ import annotations

from dataclasses import dataclass

from dsp.discovery.legacy_bash import FAST_SAFE_DISCOVERY_PORTS
from dsp.protocols.base import ReconProtocolError

# Bash fast-safe discovery ports (stellar_poc_fast_safe.sh)
DEFAULT_PORTS: tuple[int, ...] = FAST_SAFE_DISCOVERY_PORTS
MAX_HOSTS_DEFAULT = 32
MAX_PORTS_DEFAULT = len(FAST_SAFE_DISCOVERY_PORTS)
MAX_PORTS_LIMIT = 100

SAFE_ALLOWED_PORTS = frozenset(DEFAULT_PORTS)


@dataclass(frozen=True)
class PlannedPortProbe:
    host: str
    port: int
    safe_mode: bool = True

    @property
    def target(self) -> str:
        return f"{self.host}:{self.port}"

    @property
    def artifact(self) -> str:
        return f"{self.host}:{self.port}"


def plan_port_sweep(
    hosts: list[str],
    *,
    max_hosts: int = MAX_HOSTS_DEFAULT,
    ports: tuple[int, ...] | list[int] | None = None,
    max_ports: int = MAX_PORTS_DEFAULT,
    safe_mode: bool = True,
) -> list[PlannedPortProbe]:
    """
    Plan horizontal port sweep probes — same port set across each host.

    Caps: max 32 hosts (bash /24 sweep), max 100 ports (default 10 fast-safe ports).
    Safe mode restricts ports to the default allowlist.
    """
    if max_hosts < 1:
        raise ReconProtocolError("max_hosts must be positive")
    if max_ports < 1:
        raise ReconProtocolError("max_ports must be positive")
    if max_ports > MAX_PORTS_LIMIT:
        raise ReconProtocolError(f"max_ports exceeds maximum ({MAX_PORTS_LIMIT})")

    selected_hosts = [h.strip() for h in hosts if h.strip()][:max_hosts]
    if not selected_hosts:
        raise ReconProtocolError("at least one host is required")

    port_list = list(ports if ports is not None else DEFAULT_PORTS)[:max_ports]
    if not port_list:
        raise ReconProtocolError("at least one port is required")

    for port in port_list:
        if port < 1 or port > 65535:
            raise ReconProtocolError(f"invalid port: {port}")
        if safe_mode and port not in SAFE_ALLOWED_PORTS:
            raise ReconProtocolError(f"port {port} not allowed in safe mode")

    plans: list[PlannedPortProbe] = []
    for host in selected_hosts:
        for port in port_list:
            plans.append(PlannedPortProbe(host=host, port=port, safe_mode=safe_mode))

    return plans
