"""Provider-independent scenario planning — shared by local and remote execution."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from dsp.engine.scenario_engine import TargetSet
from dsp.engine.target_engine import expand_target_net_hosts
from dsp.protocols.recon import DEFAULT_PORTS, MAX_PORTS_DEFAULT, plan_port_sweep


@dataclass(frozen=True)
class PortSweepPlanView:
    """Canonical port_sweep plan snapshot before provider execution."""

    selected_hosts: list[str]
    selected_ports: tuple[int, ...]
    planned_probes: int
    selection_reason: str
    full_sweep_requested: bool
    max_hosts: int
    max_ports: int


def select_port_sweep_hosts(
    targets: TargetSet,
    config: dict[str, Any],
    *,
    max_hosts: int,
) -> tuple[list[str], str]:
    """Select port sweep hosts using bash-compatible, provider-independent rules."""
    if config.get("hosts"):
        hosts = [str(h) for h in config["hosts"]][:max_hosts]
        return hosts, "explicit_hosts"
    if targets.hosts:
        reason = "alive_hosts" if targets.discovery_enabled else "discovered_hosts"
        return [str(h) for h in targets.hosts][:max_hosts], reason
    hosts = expand_target_net_hosts(targets.target_net, max_hosts=max_hosts)[:max_hosts]
    return hosts, "target_net_expansion"


def resolve_port_sweep_ports(config: dict[str, Any], max_ports: int) -> tuple[int, ...]:
    raw = config.get("ports")
    if raw is None:
        return DEFAULT_PORTS[:max_ports]
    return tuple(int(p) for p in raw)[:max_ports]


def build_port_sweep_plan_view(
    targets: TargetSet,
    params: dict[str, Any],
) -> PortSweepPlanView:
    """Build the canonical port_sweep execution plan for any provider."""
    max_hosts = int(params.get("max_hosts", 2))
    max_ports = int(params.get("max_ports", MAX_PORTS_DEFAULT))
    hosts, reason = select_port_sweep_hosts(targets, params, max_hosts=max_hosts)
    ports = resolve_port_sweep_ports(params, max_ports)
    probes = plan_port_sweep(
        hosts,
        max_hosts=max_hosts,
        ports=ports,
        max_ports=max_ports,
        safe_mode=bool(params.get("safe_mode", True)),
    )
    return PortSweepPlanView(
        selected_hosts=hosts,
        selected_ports=ports,
        planned_probes=len(probes),
        selection_reason=reason,
        full_sweep_requested=bool(params.get("full_sweep")),
        max_hosts=max_hosts,
        max_ports=max_ports,
    )
