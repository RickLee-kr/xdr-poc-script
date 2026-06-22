"""Shared scenario plan builders for webshell command-only execution."""

from __future__ import annotations

import base64
from typing import Any

from dsp.discovery.legacy_bash import DISCOVERY_MAX_HOSTS, FAST_SAFE_DISCOVERY_PORTS
from dsp.engine.host_selection import resolve_http_endpoint_selection, select_hosts_for_capability
from dsp.engine.scenario_engine import TargetSet
from dsp.execution.remote.models import ScenarioExecutionRequest
from dsp.protocols.dns.tunnel import plan_dns_tunnel as build_dns_tunnel_plan
from dsp.protocols.host.behavior import build_host_behavior_plan
from dsp.protocols.http.non_standard_port_burst import plan_non_standard_port_burst
from dsp.protocols.http.sqli_payloads import plan_sqli_requests
from dsp.protocols.http.urls import plan_followup_requests
from dsp.protocols.rare.attempts import plan_rare_protocol_activity as build_rare_protocol_plans
from dsp.protocols.recon import plan_port_sweep as build_port_sweep_plans
from dsp.protocols.ssh.attempts import SSH_PORT_DEFAULT, plan_ssh_attempts
from dsp.runtime.scenario_plan import build_port_sweep_plan_view


def uses_remote_discovery(request: ScenarioExecutionRequest) -> bool:
    """Webshell scenarios discover target_net on the remote host."""
    return request.execution_metadata.get("traffic_origin_host") == "remote"


def plan_remote_discovery_execute(
    request: ScenarioExecutionRequest,
    *,
    dry_run: bool,
) -> dict[str, Any]:
    params = dict(request.scenario_params)
    return {
        "type": "remote_discovery_execute",
        "scenario_id": request.scenario_id,
        "params": params,
        "discovery": {
            "target_net": request.target_net,
            "max_hosts": DISCOVERY_MAX_HOSTS,
            "ports": list(FAST_SAFE_DISCOVERY_PORTS),
            "origin": "webshell_host",
        },
        "mode": "mock" if dry_run else "live",
    }


def build_scenario_plan(request: ScenarioExecutionRequest, targets: TargetSet) -> dict[str, Any]:
    params = dict(request.scenario_params)
    scenario_id = request.scenario_id
    if uses_remote_discovery(request):
        if scenario_id == "host_behavior_check":
            return plan_host_behavior_check(request, params, dry_run=request.dry_run)
        return plan_remote_discovery_execute(request, dry_run=request.dry_run)
    if scenario_id == "port_sweep":
        return plan_port_sweep(targets, params, dry_run=request.dry_run)
    if scenario_id == "dns_tunnel":
        return plan_dns_tunnel(targets, params, dry_run=request.dry_run)
    if scenario_id == "http_followup":
        return plan_http_followup(targets, params, dry_run=request.dry_run)
    if scenario_id == "sql_injection":
        return plan_sql_injection(targets, params, dry_run=request.dry_run)
    if scenario_id == "ssh_failure":
        return plan_ssh_failure(targets, params, dry_run=request.dry_run)
    if scenario_id == "host_behavior_check":
        return plan_host_behavior_check(request, params, dry_run=request.dry_run)
    if scenario_id == "rare_protocol_activity":
        return plan_rare_protocol_activity(targets, params, dry_run=request.dry_run)
    raise ValueError(f"unsupported scenario: {scenario_id!r}")


def plan_port_sweep(targets: TargetSet, params: dict[str, Any], *, dry_run: bool) -> dict[str, Any]:
    plan_view = build_port_sweep_plan_view(targets, params)
    plans = build_port_sweep_plans(
        plan_view.selected_hosts,
        max_hosts=plan_view.max_hosts,
        ports=plan_view.selected_ports,
        max_ports=plan_view.max_ports,
        safe_mode=bool(params.get("safe_mode", True)),
    )
    return {
        "type": "port_sweep",
        "mode": "mock" if dry_run else "live",
        "timeout": float(params.get("timeout", 3.0)),
        "concurrency": max(1, int(params.get("concurrency", 32))),
        "probes": [
            {"host": plan.host, "port": plan.port, "artifact": plan.artifact}
            for plan in plans
        ],
    }


def plan_dns_tunnel(targets: TargetSet, params: dict[str, Any], *, dry_run: bool) -> dict[str, Any]:
    return build_dns_tunnel_plan(targets, params, dry_run=dry_run)


def plan_http_followup(targets: TargetSet, params: dict[str, Any], *, dry_run: bool) -> dict[str, Any]:
    max_hosts = int(params.get("max_hosts", 2))
    selection = resolve_http_endpoint_selection(
        targets,
        params,
        max_hosts=max_hosts,
        dry_run=dry_run,
        timeout=float(params.get("timeout", 10.0)),
    )
    if not selection.selected:
        return {"type": "http_followup", "mode": "skip", "reason": "no_http_endpoints"}

    endpoints = [(ep.host, ep.port) for ep in selection.selected]
    followup_hosts = [host for host, _ in endpoints]
    plans = plan_followup_requests(
        endpoints=endpoints,
        max_hosts=max_hosts,
        max_per_host=int(params.get("max_per_host", 10)),
        max_total=int(params.get("max_total", 20)),
        include_attack_paths=bool(params.get("include_attack_paths", True)),
    )
    burst_plan = plan_non_standard_port_burst(targets, followup_hosts, params)
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
        "non_standard_port_burst": burst_plan,
    }


def plan_sql_injection(targets: TargetSet, params: dict[str, Any], *, dry_run: bool) -> dict[str, Any]:
    max_hosts = int(params.get("max_hosts", 2))
    selection = resolve_http_endpoint_selection(
        targets,
        params,
        max_hosts=max_hosts,
        dry_run=dry_run,
        timeout=float(params.get("timeout", 10.0)),
    )
    if not selection.selected:
        return {"type": "sql_injection", "mode": "skip", "reason": "no_http_endpoints"}

    endpoints = [(ep.host, ep.port) for ep in selection.selected]
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


def plan_ssh_failure(targets: TargetSet, params: dict[str, Any], *, dry_run: bool) -> dict[str, Any]:
    max_hosts = int(params.get("max_hosts", 2))
    hosts = select_hosts_for_capability(
        targets, params, capability="ssh_hosts", max_hosts=max_hosts
    )
    if not hosts:
        return {"type": "ssh_failure", "mode": "skip", "reason": "no_ssh_hosts"}

    port = int(params.get("port", SSH_PORT_DEFAULT))
    plans = plan_ssh_attempts(
        hosts,
        max_hosts=max_hosts,
        max_per_host=int(params.get("max_per_host", 150)),
        max_total=int(params.get("max_total", 150)),
        port=port,
    )
    return {
        "type": "ssh_failure",
        "mode": "mock" if dry_run else "live",
        "timeout": float(params.get("timeout", 5.0)),
        "attempts": [
            {
                "host": plan.host,
                "port": plan.port,
                "username": plan.username,
                "password_label": plan.password_label,
            }
            for plan in plans
        ],
    }


def plan_host_behavior_check(
    request: ScenarioExecutionRequest,
    params: dict[str, Any],
    *,
    dry_run: bool,
) -> dict[str, Any]:
    family = params.get("webshell_family") or request.execution_metadata.get(
        "webshell_family"
    )
    merged = dict(params)
    if family:
        merged["webshell_family"] = family
    return build_host_behavior_plan(
        merged,
        run_id=str(request.run_id),
        dry_run=dry_run,
        webshell_family=str(family) if family else None,
    )


def plan_rare_protocol_activity(
    targets: TargetSet,
    params: dict[str, Any],
    *,
    dry_run: bool,
) -> dict[str, Any]:
    plans = build_rare_protocol_plans(targets, params)
    if not plans:
        return {"type": "rare_protocol_activity", "mode": "skip", "reason": "no_probe_plans"}
    return {
        "type": "rare_protocol_activity",
        "mode": "mock" if dry_run else "live",
        "timeout": float(params.get("timeout", 3.0)),
        "probes": [
            {
                "protocol": plan.protocol,
                "host": plan.host,
                "port": plan.port,
                "transport": plan.transport,
                "artifact": plan.artifact,
                "rtp_packets": plan.rtp_packets,
            }
            for plan in plans
        ],
    }

_uses_remote_discovery = uses_remote_discovery
_plan_remote_discovery_execute = plan_remote_discovery_execute
_build_plan = build_scenario_plan
_plan_port_sweep = plan_port_sweep
_plan_dns_tunnel = plan_dns_tunnel
_plan_http_followup = plan_http_followup
_plan_sql_injection = plan_sql_injection
_plan_ssh_failure = plan_ssh_failure
_plan_host_behavior_check = plan_host_behavior_check
_plan_rare_protocol_activity = plan_rare_protocol_activity
