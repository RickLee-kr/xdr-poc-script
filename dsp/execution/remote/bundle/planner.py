"""Build serializable execution manifests for webshell bundle mode."""

from __future__ import annotations

import base64
from typing import Any

from dsp import EVENT_SCHEMA_VERSION
from dsp.engine.host_selection import resolve_http_endpoint_selection, select_hosts_for_capability
from dsp.engine.scenario_engine import TargetSet
from dsp.engine.target_engine import expand_target_net_hosts
from dsp.execution.remote.bundle.models import BUNDLE_SCENARIOS, RemoteScenarioSkip
from dsp.execution.remote.models import ScenarioExecutionRequest
from dsp.execution.remote.paths import resolve_remote_bundle_path
from dsp.plugins.models import PluginRecord
from dsp.protocols.dns.tunnel import (
    CHUNK_SIZE_DEFAULT,
    PAYLOAD_MB_DEFAULT,
    TUNNEL_DOMAIN_DEFAULT,
    build_tunnel_fqdn,
    chunk_to_b32_label,
    iter_payload_chunks,
    plan_chunk_count,
)
from dsp.protocols.dns.volume_profiles import apply_volume_profile
from dsp.protocols.http.sqli_payloads import plan_sqli_requests
from dsp.protocols.http.urls import MAX_HOSTS_DEFAULT, plan_followup_requests
from dsp.protocols.recon import DEFAULT_PORTS, MAX_HOSTS_DEFAULT as PORT_SWEEP_MAX_HOSTS
from dsp.protocols.recon import MAX_PORTS_DEFAULT, plan_port_sweep
from dsp.protocols.ssh.attempts import SSH_PORT_DEFAULT, plan_ssh_attempts


def resolve_remote_run_dir(remote_work_dir: str, run_id: str) -> str:
    base = remote_work_dir.rstrip("/")
    return f"{base}/{run_id}"


def build_manifest(
    request: ScenarioExecutionRequest,
    targets: TargetSet,
    record: PluginRecord,
) -> dict[str, Any]:
    """Plan scenario traffic locally and serialize a remote execution manifest."""
    if not request.run_id:
        raise ValueError("run_id is required")
    if request.scenario_id not in BUNDLE_SCENARIOS:
        raise ValueError(f"unsupported bundle scenario: {request.scenario_id!r}")

    work_dir = str(
        request.execution_metadata.get("remote_work_dir") or "/tmp/dsp"
    )
    run_dir = resolve_remote_run_dir(work_dir, request.run_id)
    bundle_path = str(
        request.execution_metadata.get("remote_bundle_path")
        or resolve_remote_bundle_path(work_dir, request.run_id)
    )

    manifest: dict[str, Any] = {
        "run_id": request.run_id,
        "scenario_id": request.scenario_id,
        "scenario_version": record.manifest.version,
        "schema_version": EVENT_SCHEMA_VERSION,
        "target_net": request.target_net,
        "dry_run": request.dry_run,
        "paths": {
            "work_dir": run_dir,
            "bundle": bundle_path,
            "traffic_summary": f"{run_dir}/traffic_summary.json",
        },
        "plan": _build_plan(request, targets),
    }
    return manifest


def build_skip_manifest(
    request: ScenarioExecutionRequest,
    record: PluginRecord,
    skip: RemoteScenarioSkip,
) -> dict[str, Any]:
    work_dir = str(request.execution_metadata.get("remote_work_dir") or "/tmp/dsp")
    run_dir = resolve_remote_run_dir(work_dir, str(request.run_id))
    bundle_path = str(
        request.execution_metadata.get("remote_bundle_path")
        or resolve_remote_bundle_path(work_dir, str(request.run_id))
    )
    return {
        "run_id": request.run_id,
        "scenario_id": request.scenario_id,
        "scenario_version": record.manifest.version,
        "schema_version": EVENT_SCHEMA_VERSION,
        "target_net": request.target_net,
        "dry_run": request.dry_run,
        "paths": {
            "work_dir": run_dir,
            "bundle": bundle_path,
            "traffic_summary": f"{run_dir}/traffic_summary.json",
        },
        "plan": {"type": "skip"},
        **skip.to_manifest(),
    }


def _build_plan(request: ScenarioExecutionRequest, targets: TargetSet) -> dict[str, Any]:
    params = dict(request.scenario_params)
    scenario_id = request.scenario_id
    if scenario_id == "port_sweep":
        return _plan_port_sweep(targets, params, dry_run=request.dry_run)
    if scenario_id == "dns_tunnel":
        return _plan_dns_tunnel(targets, params, dry_run=request.dry_run)
    if scenario_id == "http_followup":
        return _plan_http_followup(targets, params, dry_run=request.dry_run)
    if scenario_id == "sql_injection":
        return _plan_sql_injection(targets, params, dry_run=request.dry_run)
    if scenario_id == "ssh_failure":
        return _plan_ssh_failure(targets, params, dry_run=request.dry_run)
    raise ValueError(f"unsupported scenario: {scenario_id!r}")


def _select_port_sweep_hosts(targets: TargetSet, config: dict[str, Any], *, max_hosts: int) -> list[str]:
    if config.get("hosts"):
        return [str(h) for h in config["hosts"]][:max_hosts]
    return expand_target_net_hosts(targets.target_net, max_hosts=max_hosts)[:max_hosts]


def _select_tunnel_targets(targets: TargetSet, config: dict[str, Any], *, max_hosts: int) -> list[str]:
    if config.get("targets"):
        return [str(t) for t in config["targets"]][:max_hosts]
    if targets.hosts:
        return list(targets.hosts)[:max_hosts]
    return ["10.10.10.20"][:max_hosts]


def _plan_port_sweep(targets: TargetSet, params: dict[str, Any], *, dry_run: bool) -> dict[str, Any]:
    max_hosts = int(params.get("max_hosts", PORT_SWEEP_MAX_HOSTS))
    max_ports = int(params.get("max_ports", MAX_PORTS_DEFAULT))
    hosts = _select_port_sweep_hosts(targets, params, max_hosts=max_hosts)
    ports = params.get("ports")
    port_tuple = tuple(int(p) for p in ports)[:max_ports] if ports else DEFAULT_PORTS[:max_ports]
    plans = plan_port_sweep(
        hosts,
        max_hosts=max_hosts,
        ports=port_tuple,
        max_ports=max_ports,
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


def _plan_dns_tunnel(targets: TargetSet, params: dict[str, Any], *, dry_run: bool) -> dict[str, Any]:
    tuned = apply_volume_profile(params, dry_run=dry_run)
    payload_mb = float(tuned.get("payload_mb", PAYLOAD_MB_DEFAULT))
    chunk_size = int(tuned.get("chunk_size", CHUNK_SIZE_DEFAULT))
    domain = str(tuned.get("domain", TUNNEL_DOMAIN_DEFAULT))
    max_hosts = int(tuned.get("max_hosts", 2))
    max_chunks = tuned.get("max_chunks")
    hosts = _select_tunnel_targets(targets, tuned, max_hosts=max_hosts)
    total = plan_chunk_count(payload_mb, chunk_size)
    if max_chunks is not None:
        total = min(total, int(max_chunks))

    queries: list[dict[str, Any]] = []
    for target in hosts:
        for seq, chunk in enumerate(iter_payload_chunks(payload_mb, chunk_size), start=1):
            if seq > total:
                break
            label = chunk_to_b32_label(chunk)
            fqdn = build_tunnel_fqdn(seq, label, domain)
            queries.append(
                {
                    "target": target,
                    "seq": seq,
                    "fqdn": fqdn,
                    "chunk_bytes": len(chunk),
                    "label_length": len(label),
                }
            )

    return {
        "type": "dns_tunnel",
        "mode": "mock" if dry_run else "live",
        "domain": domain,
        "timeout": float(tuned.get("timeout", 0.05)),
        "queries": queries,
    }


def _plan_http_followup(targets: TargetSet, params: dict[str, Any], *, dry_run: bool) -> dict[str, Any]:
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
    }


def _plan_sql_injection(targets: TargetSet, params: dict[str, Any], *, dry_run: bool) -> dict[str, Any]:
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


def _plan_ssh_failure(targets: TargetSet, params: dict[str, Any], *, dry_run: bool) -> dict[str, Any]:
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
