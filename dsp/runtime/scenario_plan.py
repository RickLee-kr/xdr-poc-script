"""Provider-independent scenario planning — shared by local and remote execution."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

from dsp.engine.scenario_engine import TargetSet
from dsp.engine.target_engine import expand_target_net_hosts
from dsp.protocols.http.urls import HTTP_DETECTION_PORTS
from dsp.protocols.recon import DEFAULT_PORTS, MAX_PORTS_DEFAULT, plan_port_sweep

INITIAL_COMPROMISE_ENDPOINT_KEY = "initial_compromise_endpoint"
INITIAL_COMPROMISE_SELECTION_REASON = "initial_compromise_host_explicit_phase1"
WEBSHELL_EXECUTION_KEY = "_webshell_execution"
PHASE1_WEBSHELL_ATTACK_KEY = "phase1_webshell_attack"
DISCOVERED_HTTP_SERVICE_REASON = "discovered_http_service"
DISCOVERED_HTTPS_SERVICE_REASON = "discovered_https_service"
DISCOVERED_HTTP_SERVICE_UNVERIFIED_FROM_DSP_HOST = (
    "discovered_http_service_unverified_from_dsp_host"
)
FALLBACK_NO_DISCOVERED_HTTP_REASON = "fallback_no_discovered_http"


@dataclass(frozen=True)
class InitialCompromiseEndpoint:
    """Webshell host endpoint derived from ``webshell_url`` (Phase A target)."""

    host: str
    port: int
    scheme: str

    def to_dict(self) -> dict[str, str | int]:
        return {"host": self.host, "port": self.port, "scheme": self.scheme}


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


def parse_initial_compromise_endpoint(webshell_url: str) -> InitialCompromiseEndpoint:
    """Derive Phase A compromise target host:port from a webshell URL."""
    parsed = urlparse(webshell_url.strip())
    if not parsed.hostname:
        raise ValueError(f"invalid webshell_url: {webshell_url!r}")
    host = parsed.hostname
    if parsed.port is not None:
        port = parsed.port
    elif parsed.scheme == "https":
        port = 443
    else:
        port = 80
    scheme = parsed.scheme or "http"
    if port in HTTP_DETECTION_PORTS:
        scheme = "http"
    return InitialCompromiseEndpoint(host=host, port=port, scheme=scheme)


def apply_webshell_initial_compromise_plan(
    scenario_params: dict[str, dict[str, Any]],
    scenario_ids: list[str],
    webshell_url: str,
) -> InitialCompromiseEndpoint:
    """Record webshell execution host and Phase-1 targets for host-behavior scenarios."""
    endpoint = parse_initial_compromise_endpoint(webshell_url)
    payload = endpoint.to_dict()
    parsed = urlparse(webshell_url)
    execution_context = {
        "webshell_url": webshell_url,
        "execution_host": endpoint.host,
        "execution_port": endpoint.port,
        "execution_path": parsed.path or "/",
        "endpoint": payload,
    }
    scenario_params[WEBSHELL_EXECUTION_KEY] = execution_context
    for sid in scenario_ids:
        scenario_params.setdefault(sid, {})[WEBSHELL_EXECUTION_KEY] = execution_context
    for sid in ("host_behavior_check", "rare_protocol_activity"):
        if sid in scenario_ids:
            scenario_params.setdefault(sid, {})[INITIAL_COMPROMISE_ENDPOINT_KEY] = payload
    return endpoint


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
