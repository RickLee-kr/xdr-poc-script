"""Executable plan builders for webshell command-only scenarios."""

from __future__ import annotations

from typing import Any

from dsp.engine.scenario_engine import TargetSet
from dsp.execution.remote.command.discovery_plans import build_plan_from_discovery
from dsp.execution.remote.command.scenario_plans import (
    _plan_host_behavior_check,
    _plan_http_followup,
    _plan_port_sweep,
    _plan_ssh_failure,
    _uses_remote_discovery,
)
from dsp.execution.remote.models import ScenarioExecutionRequest
from dsp.plugins.models import PluginRecord
from dsp.protocols.dns.dga import (
    EFFECTIVE_TLD_DEFAULT,
    PHASE1_COUNT_DEFAULT,
    PHASE2_COUNT_DEFAULT,
    generate_nxdomain_fqdn,
    generate_resolvable_fqdn,
)
from dsp.protocols.dns.tunnel import plan_dns_tunnel
from dsp.protocols.http.urls import plan_followup_requests
from dsp.protocols.kerberos.attempts import plan_kerberos_attempts
from dsp.protocols.ldap.attempts import plan_ldap_enumeration
from dsp.protocols.smb.attempts import plan_smb_attempts
from dsp.runtime.http_endpoint_selection import select_discovered_http_endpoint_tuples
from dsp.runtime.scenario_plan import webshell_server_endpoint


def targets_dict_to_target_set(data: dict[str, Any]) -> TargetSet:
    return TargetSet(
        target_net=str(data.get("target_net") or ""),
        hosts=list(data.get("hosts") or []),
        service_hosts=dict(data.get("service_hosts") or {}),
        service_endpoints={
            key: [tuple(item) for item in value]
            for key, value in (data.get("service_endpoints") or {}).items()
        },
        discovery_enabled=bool(data.get("discovery_enabled", True)),
        discovery_meta=dict(data.get("discovery_meta") or {}),
    )


def build_command_plan(
    request: ScenarioExecutionRequest,
    targets: TargetSet | dict[str, Any],
    record: PluginRecord,
) -> dict[str, Any]:
    """Build an executable scenario plan for command dispatch."""
    from dsp.execution.remote.command.scenario_plans import build_scenario_execution_plan

    if isinstance(targets, dict):
        target_set = targets_dict_to_target_set(targets)
    else:
        target_set = targets

    params = dict(request.scenario_params)
    scenario_id = request.scenario_id
    dry_run = request.dry_run

    if scenario_id == "host_behavior_check":
        from dsp.execution.remote.command.scenario_plans import plan_host_behavior_check

        return plan_host_behavior_check(request, params, dry_run=dry_run)

    if _uses_remote_discovery(request) and not target_set.discovery_enabled and not target_set.hosts:
        return build_plan_from_discovery(scenario_id, {}, params, dry_run=dry_run)

    if _uses_remote_discovery(request):
        targets_dict = {
            "target_net": target_set.target_net,
            "hosts": target_set.hosts,
            "service_hosts": target_set.service_hosts,
            "service_endpoints": {
                key: list(value) for key, value in target_set.service_endpoints.items()
            },
            "discovery_meta": target_set.discovery_meta,
            "discovery_enabled": target_set.discovery_enabled,
        }
        return build_plan_from_discovery(scenario_id, targets_dict, params, dry_run=dry_run)

    return build_scenario_execution_plan(scenario_id, target_set, params, dry_run=dry_run)


def _extended_plan(
    scenario_id: str,
    targets: dict[str, Any],
    params: dict[str, Any],
    *,
    dry_run: bool,
) -> dict[str, Any] | None:
    builders = {
        "sql_injection": _plan_sql_injection,
        "dns_tunnel": _plan_dns_tunnel,
        "dga": _plan_dga,
        "ldap_enumeration": _plan_ldap_enumeration,
        "smb_login_failure": _plan_smb_login_failure,
        "kerberos_failure": _plan_kerberos_failure,
    }
    builder = builders.get(scenario_id)
    if builder is None:
        return None
    return builder(targets, params, dry_run=dry_run)


def _hosts_for(targets: dict[str, Any], capability: str) -> list[str]:
    return list((targets.get("service_hosts") or {}).get(capability, []))


def _plan_sql_injection(targets: dict[str, Any], params: dict[str, Any], *, dry_run: bool) -> dict[str, Any]:
    from dsp.execution.remote.command.scenario_plans import plan_sql_injection

    return plan_sql_injection(targets_dict_to_target_set(targets), params, dry_run=dry_run)


def _plan_dns_tunnel(targets: dict[str, Any], params: dict[str, Any], *, dry_run: bool) -> dict[str, Any]:
    return plan_dns_tunnel(targets_dict_to_target_set(targets), params, dry_run=dry_run)


def _plan_dga(targets: dict[str, Any], params: dict[str, Any], *, dry_run: bool) -> dict[str, Any]:
    effective_tld = str(params.get("effective_tld", EFFECTIVE_TLD_DEFAULT))
    phase1_count = int(params.get("phase1_count", PHASE1_COUNT_DEFAULT))
    phase2_count = int(params.get("phase2_count", PHASE2_COUNT_DEFAULT))
    dns_hosts = _hosts_for(targets, "dns_hosts")
    if params.get("resolver"):
        resolver = str(params["resolver"])
    elif dns_hosts:
        resolver = dns_hosts[0]
    else:
        return {"type": "dga", "mode": "skip", "reason": "no_dns_hosts"}
    domains: list[dict[str, Any]] = []
    seq = 0
    for phase, count, generator, phase_name in (
        (1, phase1_count, generate_nxdomain_fqdn, "nxdomain"),
        (2, phase2_count, generate_resolvable_fqdn, "resolvable"),
    ):
        for _ in range(count):
            seq += 1
            fqdn = generator(effective_tld)
            domains.append(
                {
                    "seq": seq,
                    "phase": phase,
                    "phase_name": phase_name,
                    "fqdn": fqdn,
                    "resolver": resolver,
                }
            )
    if not domains:
        return {"type": "dga", "mode": "skip", "reason": "no_domains_planned"}
    return {
        "type": "dga",
        "mode": "mock" if dry_run else "live",
        "resolver": resolver,
        "effective_tld": effective_tld,
        "domains": domains,
        "timeout": float(params.get("timeout", 0.05)),
    }


def _plan_ldap_enumeration(targets: dict[str, Any], params: dict[str, Any], *, dry_run: bool) -> dict[str, Any]:
    max_hosts = int(params.get("max_hosts", 2))
    hosts = _hosts_for(targets, "ldap_hosts")[:max_hosts]
    if not hosts:
        return {"type": "ldap_enumeration", "mode": "skip", "reason": "no_ldap_hosts"}
    ports = tuple(int(p) for p in (params.get("ports") or (389,)))
    plans = plan_ldap_enumeration(
        hosts,
        max_hosts=max_hosts,
        max_queries_per_host=int(params.get("max_queries_per_host", 10)),
        ports=ports,
        safe_mode=bool(params.get("safe_mode", True)),
    )
    return {
        "type": "ldap_enumeration",
        "mode": "mock" if dry_run else "live",
        "timeout": float(params.get("timeout", 5.0)),
        "actions": [
            {
                "host": plan.host,
                "port": plan.port,
                "action_type": plan.action_type,
                "search_filter": plan.search_filter,
            }
            for plan in plans
        ],
    }


def _plan_smb_login_failure(targets: dict[str, Any], params: dict[str, Any], *, dry_run: bool) -> dict[str, Any]:
    max_hosts = int(params.get("max_hosts", 2))
    hosts = _hosts_for(targets, "smb_hosts")[:max_hosts]
    if not hosts:
        return {"type": "smb_login_failure", "mode": "skip", "reason": "no_smb_hosts"}
    port = int(params.get("port", 445))
    plans = plan_smb_attempts(
        hosts,
        max_hosts=max_hosts,
        attempts_per_host=int(params.get("attempts_per_host", 10)),
        port=port,
        safe_mode=bool(params.get("safe_mode", True)),
    )
    return {
        "type": "smb_login_failure",
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


def _plan_kerberos_failure(targets: dict[str, Any], params: dict[str, Any], *, dry_run: bool) -> dict[str, Any]:
    max_hosts = int(params.get("max_hosts", 2))
    hosts = _hosts_for(targets, "kerberos_hosts")[:max_hosts]
    if not hosts:
        return {"type": "kerberos_failure", "mode": "skip", "reason": "no_kerberos_hosts"}
    port = int(params.get("port", 88))
    realm = str(params.get("realm", "LOCAL.REALM"))
    plans = plan_kerberos_attempts(
        hosts,
        max_hosts=max_hosts,
        attempts_per_host=int(params.get("attempts_per_host", 10)),
        port=port,
        realm=realm,
        safe_mode=bool(params.get("safe_mode", True)),
    )
    return {
        "type": "kerberos_failure",
        "mode": "mock" if dry_run else "live",
        "timeout": float(params.get("timeout", 10.0)),
        "realm": realm,
        "attempts": [
            {
                "host": plan.host,
                "port": plan.port,
                "username": plan.username,
                "realm": plan.realm,
            }
            for plan in plans
        ],
    }
