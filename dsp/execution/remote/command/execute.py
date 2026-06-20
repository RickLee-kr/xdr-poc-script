"""Execute scenario plans via webshell command dispatch and Event Store append."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from dsp.engine.scenario_engine import RunContext
from dsp.execution.providers.runtime.command import CommandRequest
from dsp.execution.remote.command import events as cmd_events
from dsp.execution.remote.command.shell import (
    curl_request_command,
    dns_query_command,
    host_behavior_shell_command,
    kerberos_attempt_command,
    ldap_action_command,
    mock_noop_command,
    rare_protocol_probe_command,
    smb_probe_command,
    ssh_attempt_command,
    tcp_probe_command,
)
from dsp.execution.remote.models import ScenarioExecutionRequest

if TYPE_CHECKING:
    from dsp.execution.webshell_provider import WebshellExecutionProvider


def execute_command_plan(
    plan: dict[str, Any],
    provider: WebshellExecutionProvider,
    ctx: RunContext,
    request: ScenarioExecutionRequest,
) -> int:
    """Dispatch plan commands through webshell and append Event Store evidence."""
    plan_type = str(plan.get("type") or "")
    handlers = {
        "port_sweep": _execute_port_sweep,
        "http_followup": _execute_http_followup,
        "sql_injection": _execute_sql_injection,
        "ssh_failure": _execute_ssh_failure,
        "dns_tunnel": _execute_dns_tunnel,
        "dga": _execute_dga,
        "ldap_enumeration": _execute_ldap_enumeration,
        "smb_login_failure": _execute_smb_login_failure,
        "kerberos_failure": _execute_kerberos_failure,
        "host_behavior_check": _execute_host_behavior_check,
        "rare_protocol_activity": _execute_rare_protocol_activity,
    }
    handler = handlers.get(plan_type)
    if handler is None:
        return 0
    return handler(plan, provider, ctx, request)


def _dispatch(
    provider: WebshellExecutionProvider,
    command: str,
    *,
    timeout_seconds: int = 300,
) -> str:
    result = provider.execute_command(
        CommandRequest.new(command, timeout_seconds=timeout_seconds)
    )
    return str(result.status.value)


def _execute_port_sweep(
    plan: dict[str, Any],
    provider: WebshellExecutionProvider,
    ctx: RunContext,
    request: ScenarioExecutionRequest,
) -> int:
    store = ctx.event_store
    run_id = str(request.run_id)
    scenario_id = request.scenario_id
    probes = plan.get("probes") or []
    timeout = float(plan.get("timeout", 3.0))
    mock = plan.get("mode") == "mock"
    first_host = probes[0]["host"] if probes else ""
    cmd_events.append_event(
        store,
        run_id=run_id,
        scenario_id=scenario_id,
        event="port_sweep_started",
        status="info",
        target=first_host,
        artifact="port_sweep_session",
        evidence={"planned_probes": len(probes), "mode": plan.get("mode", "live")},
    )
    dispatched = 0
    for index, probe in enumerate(probes, start=1):
        host = str(probe["host"])
        port = int(probe["port"])
        artifact = str(probe.get("artifact") or f"{host}:{port}")
        command = mock_noop_command() if mock else tcp_probe_command(host, port, timeout=timeout)
        status = _dispatch(provider, command, timeout_seconds=int(timeout) + 5)
        cmd_events.append_command_dispatched(
            store,
            run_id=run_id,
            scenario_id=scenario_id,
            command_category="port_probe",
            target=host,
            protocol="tcp",
            dispatch_status=status,
            artifact=artifact,
            traffic_event="port_probe_sent",
            evidence={"seq": index, "host": host, "port": port},
        )
        cmd_events.append_event(
            store,
            run_id=run_id,
            scenario_id=scenario_id,
            event="port_connection_failed",
            status="sent",
            target=host,
            artifact=artifact,
            evidence={"host": host, "port": port, "outcome": "command_dispatched"},
        )
        dispatched += 1
    cmd_events.append_event(
        store,
        run_id=run_id,
        scenario_id=scenario_id,
        event="port_sweep_completed",
        status="info",
        target=first_host,
        artifact="port_sweep_session",
        evidence={"probe_count": len(probes), "commands_dispatched": dispatched},
    )
    return dispatched


def _execute_http_followup(
    plan: dict[str, Any],
    provider: WebshellExecutionProvider,
    ctx: RunContext,
    request: ScenarioExecutionRequest,
) -> int:
    store = ctx.event_store
    run_id = str(request.run_id)
    scenario_id = request.scenario_id
    requests_list = plan.get("requests") or []
    timeout = float(plan.get("timeout", 10.0))
    mock = plan.get("mode") == "mock"
    cmd_events.append_event(
        store,
        run_id=run_id,
        scenario_id=scenario_id,
        event="http_followup_started",
        status="info",
        evidence={"requests_planned": len(requests_list), "mode": plan.get("mode", "live")},
    )
    dispatched = 0
    for index, item in enumerate(requests_list, start=1):
        url = str(item["url"])
        method = str(item.get("method") or "GET")
        user_agent = str(item.get("user_agent") or "Mozilla/5.0")
        command = (
            mock_noop_command()
            if mock
            else curl_request_command(url, method=method, user_agent=user_agent, timeout=timeout)
        )
        status = _dispatch(provider, command, timeout_seconds=int(timeout) + 5)
        cmd_events.append_event(
            store,
            run_id=run_id,
            scenario_id=scenario_id,
            event="http_request_created",
            status="info",
            target=url,
            evidence={"seq": index, "url": url, "method": method},
        )
        cmd_events.append_command_dispatched(
            store,
            run_id=run_id,
            scenario_id=scenario_id,
            command_category="http_request",
            target=url,
            protocol="http",
            dispatch_status=status,
            traffic_event="http_request_sent",
            evidence={"url": url, "method": method},
        )
        dispatched += 1
    cmd_events.append_event(
        store,
        run_id=run_id,
        scenario_id=scenario_id,
        event="http_followup_completed",
        status="info",
        evidence={"requests_sent": dispatched},
    )
    return dispatched


def _execute_sql_injection(
    plan: dict[str, Any],
    provider: WebshellExecutionProvider,
    ctx: RunContext,
    request: ScenarioExecutionRequest,
) -> int:
    store = ctx.event_store
    run_id = str(request.run_id)
    scenario_id = request.scenario_id
    requests_list = plan.get("requests") or []
    timeout = float(plan.get("timeout", 10.0))
    mock = plan.get("mode") == "mock"
    cmd_events.append_event(
        store,
        run_id=run_id,
        scenario_id=scenario_id,
        event="sql_injection_started",
        status="info",
        evidence={"requests_planned": len(requests_list), "mode": plan.get("mode", "live")},
    )
    dispatched = 0
    for index, item in enumerate(requests_list, start=1):
        url = str(item["url"])
        method = str(item.get("method") or "GET")
        command = (
            mock_noop_command()
            if mock
            else curl_request_command(
                url,
                method=method,
                timeout=timeout,
                body_b64=item.get("body_b64"),
                content_type=item.get("content_type"),
            )
        )
        status = _dispatch(provider, command, timeout_seconds=int(timeout) + 5)
        cmd_events.append_event(
            store,
            run_id=run_id,
            scenario_id=scenario_id,
            event="sql_payload_generated",
            status="info",
            target=url,
            evidence={
                "seq": index,
                "payload_category": item.get("payload_category"),
                "parameter": item.get("parameter"),
            },
        )
        cmd_events.append_command_dispatched(
            store,
            run_id=run_id,
            scenario_id=scenario_id,
            command_category="sql_request",
            target=url,
            protocol="http",
            dispatch_status=status,
            traffic_event="sql_request_sent",
            evidence={"url": url, "method": method},
        )
        dispatched += 1
    cmd_events.append_event(
        store,
        run_id=run_id,
        scenario_id=scenario_id,
        event="sql_injection_completed",
        status="info",
        evidence={"requests_sent": dispatched},
    )
    return dispatched


def _execute_ssh_failure(
    plan: dict[str, Any],
    provider: WebshellExecutionProvider,
    ctx: RunContext,
    request: ScenarioExecutionRequest,
) -> int:
    store = ctx.event_store
    run_id = str(request.run_id)
    scenario_id = request.scenario_id
    attempts = plan.get("attempts") or []
    timeout = float(plan.get("timeout", 5.0))
    mock = plan.get("mode") == "mock"
    first_host = attempts[0]["host"] if attempts else ""
    cmd_events.append_event(
        store,
        run_id=run_id,
        scenario_id=scenario_id,
        event="ssh_failure_started",
        status="info",
        target=first_host,
        evidence={"auth_attempts_planned": len(attempts), "mode": plan.get("mode", "live")},
    )
    dispatched = 0
    for index, item in enumerate(attempts, start=1):
        host = str(item["host"])
        port = int(item["port"])
        username = str(item["username"])
        artifact = f"{username}@{host}:{port}"
        command = (
            mock_noop_command()
            if mock
            else ssh_attempt_command(host, port, username, timeout=timeout)
        )
        status = _dispatch(provider, command, timeout_seconds=int(timeout) + 5)
        cmd_events.append_command_dispatched(
            store,
            run_id=run_id,
            scenario_id=scenario_id,
            command_category="ssh_auth",
            target=host,
            protocol="ssh",
            dispatch_status=status,
            artifact=artifact,
            traffic_event="ssh_auth_attempt",
            evidence={"seq": index, "username": username, "port": port},
        )
        cmd_events.append_event(
            store,
            run_id=run_id,
            scenario_id=scenario_id,
            event="ssh_auth_failed",
            status="auth_failed",
            target=host,
            artifact=artifact,
            evidence={"username": username, "outcome": "command_dispatched"},
        )
        dispatched += 1
    cmd_events.append_event(
        store,
        run_id=run_id,
        scenario_id=scenario_id,
        event="ssh_failure_completed",
        status="info",
        target=first_host,
        evidence={"auth_attempts": dispatched},
    )
    return dispatched


def _execute_dns_tunnel(
    plan: dict[str, Any],
    provider: WebshellExecutionProvider,
    ctx: RunContext,
    request: ScenarioExecutionRequest,
) -> int:
    store = ctx.event_store
    run_id = str(request.run_id)
    scenario_id = request.scenario_id
    queries = plan.get("queries") or []
    timeout = float(plan.get("timeout", 0.05))
    mock = plan.get("mode") == "mock"
    first_target = queries[0]["target"] if queries else ""
    cmd_events.append_event(
        store,
        run_id=run_id,
        scenario_id=scenario_id,
        event="dns_tunnel_started",
        status="info",
        target=first_target,
        evidence={"planned_chunks": len(queries), "mode": plan.get("mode", "live")},
    )
    dispatched = 0
    for item in queries:
        target = str(item["target"])
        fqdn = str(item["fqdn"])
        command = (
            mock_noop_command()
            if mock
            else dns_query_command(target, fqdn, timeout=max(timeout, 1.0))
        )
        status = _dispatch(provider, command, timeout_seconds=10)
        cmd_events.append_event(
            store,
            run_id=run_id,
            scenario_id=scenario_id,
            event="dns_tunnel_chunk_created",
            status="info",
            target=target,
            artifact=fqdn,
            evidence={"seq": item.get("seq"), "fqdn": fqdn},
        )
        cmd_events.append_command_dispatched(
            store,
            run_id=run_id,
            scenario_id=scenario_id,
            command_category="dns_query",
            target=target,
            protocol="dns",
            dispatch_status=status,
            artifact=fqdn,
            traffic_event="dns_query_sent",
            evidence={"fqdn": fqdn, "seq": item.get("seq")},
        )
        cmd_events.append_event(
            store,
            run_id=run_id,
            scenario_id=scenario_id,
            event="dns_tunnel_query_sent",
            status="sent",
            target=target,
            artifact=fqdn,
            evidence={"fqdn": fqdn, "outcome": "command_dispatched"},
        )
        dispatched += 1
    cmd_events.append_event(
        store,
        run_id=run_id,
        scenario_id=scenario_id,
        event="dns_tunnel_completed",
        status="info",
        target=first_target,
        evidence={"queries_sent": dispatched},
    )
    return dispatched


def _execute_dga(
    plan: dict[str, Any],
    provider: WebshellExecutionProvider,
    ctx: RunContext,
    request: ScenarioExecutionRequest,
) -> int:
    store = ctx.event_store
    run_id = str(request.run_id)
    scenario_id = request.scenario_id
    domains = plan.get("domains") or []
    timeout = float(plan.get("timeout", 0.05))
    mock = plan.get("mode") == "mock"
    resolver = str(plan.get("resolver") or "")
    cmd_events.append_event(
        store,
        run_id=run_id,
        scenario_id=scenario_id,
        event="dga_started",
        status="info",
        target=resolver,
        artifact="dga_session",
        evidence={"domains_planned": len(domains), "mode": plan.get("mode", "live")},
    )
    dispatched = 0
    for item in domains:
        fqdn = str(item["fqdn"])
        target = str(item.get("resolver") or resolver)
        command = (
            mock_noop_command()
            if mock
            else dns_query_command(target, fqdn, timeout=max(timeout, 1.0))
        )
        status = _dispatch(provider, command, timeout_seconds=10)
        cmd_events.append_event(
            store,
            run_id=run_id,
            scenario_id=scenario_id,
            event="dga_domain_generated",
            status="info",
            target=target,
            artifact=fqdn,
            evidence={"phase": item.get("phase"), "seq": item.get("seq")},
        )
        traffic_event = (
            "dga_nxdomain_observed"
            if item.get("phase_name") == "nxdomain"
            else "dga_resolved_observed"
        )
        cmd_events.append_command_dispatched(
            store,
            run_id=run_id,
            scenario_id=scenario_id,
            command_category="dga_query",
            target=target,
            protocol="dns",
            dispatch_status=status,
            artifact=fqdn,
            traffic_event=traffic_event,
            evidence={"fqdn": fqdn, "phase": item.get("phase_name")},
        )
        dispatched += 1
    cmd_events.append_event(
        store,
        run_id=run_id,
        scenario_id=scenario_id,
        event="dga_completed",
        status="info",
        target=resolver,
        artifact="dga_session",
        evidence={"domains_generated": dispatched},
    )
    return dispatched


def _execute_ldap_enumeration(
    plan: dict[str, Any],
    provider: WebshellExecutionProvider,
    ctx: RunContext,
    request: ScenarioExecutionRequest,
) -> int:
    store = ctx.event_store
    run_id = str(request.run_id)
    scenario_id = request.scenario_id
    actions = plan.get("actions") or []
    timeout = float(plan.get("timeout", 5.0))
    mock = plan.get("mode") == "mock"
    first_host = actions[0]["host"] if actions else ""
    cmd_events.append_event(
        store,
        run_id=run_id,
        scenario_id=scenario_id,
        event="ldap_enum_started",
        status="info",
        target=first_host,
        evidence={"planned_actions": len(actions), "mode": plan.get("mode", "live")},
    )
    dispatched = 0
    for index, item in enumerate(actions, start=1):
        host = str(item["host"])
        port = int(item["port"])
        action_type = str(item["action_type"])
        command = (
            mock_noop_command()
            if mock
            else ldap_action_command(
                host,
                port,
                action_type,
                search_filter=str(item.get("search_filter") or ""),
                timeout=timeout,
            )
        )
        status = _dispatch(provider, command, timeout_seconds=int(timeout) + 5)
        event_map = {
            "connection": "ldap_connection_attempt",
            "bind": "ldap_bind_attempt",
            "search": "ldap_search_attempt",
        }
        cmd_events.append_command_dispatched(
            store,
            run_id=run_id,
            scenario_id=scenario_id,
            command_category=f"ldap_{action_type}",
            target=host,
            protocol="ldap",
            dispatch_status=status,
            artifact=f"{host}:{port}:{action_type}",
            traffic_event=event_map.get(action_type, "ldap_connection_attempt"),
            evidence={"seq": index, "action_type": action_type, "port": port},
        )
        dispatched += 1
    cmd_events.append_event(
        store,
        run_id=run_id,
        scenario_id=scenario_id,
        event="ldap_enum_completed",
        status="info",
        target=first_host,
        evidence={"actions_dispatched": dispatched},
    )
    return dispatched


def _execute_smb_login_failure(
    plan: dict[str, Any],
    provider: WebshellExecutionProvider,
    ctx: RunContext,
    request: ScenarioExecutionRequest,
) -> int:
    store = ctx.event_store
    run_id = str(request.run_id)
    scenario_id = request.scenario_id
    attempts = plan.get("attempts") or []
    timeout = float(plan.get("timeout", 5.0))
    mock = plan.get("mode") == "mock"
    first_host = attempts[0]["host"] if attempts else ""
    cmd_events.append_event(
        store,
        run_id=run_id,
        scenario_id=scenario_id,
        event="smb_scenario_started",
        status="info",
        target=first_host,
        evidence={"attempts_planned": len(attempts), "mode": plan.get("mode", "live")},
    )
    dispatched = 0
    for index, item in enumerate(attempts, start=1):
        host = str(item["host"])
        port = int(item["port"])
        username = str(item["username"])
        artifact = f"{username}@{host}:{port}"
        command = mock_noop_command() if mock else smb_probe_command(host, port, timeout=timeout)
        status = _dispatch(provider, command, timeout_seconds=int(timeout) + 5)
        cmd_events.append_command_dispatched(
            store,
            run_id=run_id,
            scenario_id=scenario_id,
            command_category="smb_auth",
            target=host,
            protocol="smb",
            dispatch_status=status,
            artifact=artifact,
            traffic_event="smb_auth_attempt",
            evidence={"seq": index, "username": username, "port": port},
        )
        cmd_events.append_event(
            store,
            run_id=run_id,
            scenario_id=scenario_id,
            event="smb_auth_failed",
            status="auth_failed",
            target=host,
            artifact=artifact,
            evidence={"username": username, "outcome": "command_dispatched"},
        )
        dispatched += 1
    cmd_events.append_event(
        store,
        run_id=run_id,
        scenario_id=scenario_id,
        event="smb_scenario_completed",
        status="info",
        target=first_host,
        evidence={"auth_attempts": dispatched},
    )
    return dispatched


def _execute_kerberos_failure(
    plan: dict[str, Any],
    provider: WebshellExecutionProvider,
    ctx: RunContext,
    request: ScenarioExecutionRequest,
) -> int:
    store = ctx.event_store
    run_id = str(request.run_id)
    scenario_id = request.scenario_id
    attempts = plan.get("attempts") or []
    timeout = float(plan.get("timeout", 10.0))
    mock = plan.get("mode") == "mock"
    first_host = attempts[0]["host"] if attempts else ""
    cmd_events.append_event(
        store,
        run_id=run_id,
        scenario_id=scenario_id,
        event="kerberos_scenario_started",
        status="info",
        target=first_host,
        evidence={"attempts_planned": len(attempts), "mode": plan.get("mode", "live")},
    )
    dispatched = 0
    for index, item in enumerate(attempts, start=1):
        host = str(item["host"])
        port = int(item["port"])
        username = str(item["username"])
        realm = str(item.get("realm") or plan.get("realm") or "LOCAL.REALM")
        artifact = f"{username}@{realm}@{host}:{port}"
        command = (
            mock_noop_command()
            if mock
            else kerberos_attempt_command(host, port, username, realm, timeout=timeout)
        )
        status = _dispatch(provider, command, timeout_seconds=int(timeout) + 5)
        cmd_events.append_command_dispatched(
            store,
            run_id=run_id,
            scenario_id=scenario_id,
            command_category="kerberos_auth",
            target=host,
            protocol="kerberos",
            dispatch_status=status,
            artifact=artifact,
            traffic_event="kerberos_auth_attempt",
            evidence={"seq": index, "username": username, "realm": realm},
        )
        cmd_events.append_event(
            store,
            run_id=run_id,
            scenario_id=scenario_id,
            event="kerberos_auth_failed",
            status="auth_failed",
            target=host,
            artifact=artifact,
            evidence={"username": username, "outcome": "command_dispatched"},
        )
        dispatched += 1
    cmd_events.append_event(
        store,
        run_id=run_id,
        scenario_id=scenario_id,
        event="kerberos_scenario_completed",
        status="info",
        target=first_host,
        evidence={"auth_attempts": dispatched},
    )
    return dispatched


def _execute_host_behavior_check(
    plan: dict[str, Any],
    provider: WebshellExecutionProvider,
    ctx: RunContext,
    request: ScenarioExecutionRequest,
) -> int:
    store = ctx.event_store
    run_id = str(request.run_id)
    scenario_id = request.scenario_id
    target = str(plan.get("target_host") or "127.0.0.1")
    commands = plan.get("commands") or []
    timeout = float(plan.get("timeout", 30.0))
    mock = plan.get("mode") == "mock"
    cmd_events.append_event(
        store,
        run_id=run_id,
        scenario_id=scenario_id,
        event="host_behavior_check_started",
        status="info",
        target=target,
        artifact="host_behavior_session",
        evidence={"commands_planned": len(commands), "mode": plan.get("mode", "live")},
    )
    dispatched = 0
    for index, item in enumerate(commands, start=1):
        shell = str(item.get("shell") or item.get("name") or "true")
        command = mock_noop_command() if mock else host_behavior_shell_command(shell)
        status = _dispatch(provider, command, timeout_seconds=int(timeout))
        cmd_events.append_command_dispatched(
            store,
            run_id=run_id,
            scenario_id=scenario_id,
            command_category="host_behavior",
            target=target,
            protocol="host",
            dispatch_status=status,
            artifact=str(item.get("name") or f"cmd_{index}"),
            traffic_event="host_behavior_command_dispatched",
            evidence={"seq": index, "command_name": item.get("name")},
        )
        dispatched += 1
    cmd_events.append_event(
        store,
        run_id=run_id,
        scenario_id=scenario_id,
        event="host_behavior_check_completed",
        status="info",
        target=target,
        artifact="host_behavior_session",
        evidence={"commands_dispatched": dispatched},
    )
    return dispatched


def _execute_rare_protocol_activity(
    plan: dict[str, Any],
    provider: WebshellExecutionProvider,
    ctx: RunContext,
    request: ScenarioExecutionRequest,
) -> int:
    store = ctx.event_store
    run_id = str(request.run_id)
    scenario_id = request.scenario_id
    probes = plan.get("probes") or []
    timeout = float(plan.get("timeout", 3.0))
    mock = plan.get("mode") == "mock"
    cmd_events.append_event(
        store,
        run_id=run_id,
        scenario_id=scenario_id,
        event="rare_protocol_activity_started",
        status="info",
        evidence={"probes_planned": len(probes), "mode": plan.get("mode", "live")},
    )
    dispatched = 0
    for index, probe in enumerate(probes, start=1):
        host = str(probe["host"])
        port = int(probe["port"])
        protocol = str(probe.get("protocol") or "tcp")
        command = (
            mock_noop_command()
            if mock
            else rare_protocol_probe_command(host, port, protocol)
        )
        status = _dispatch(provider, command, timeout_seconds=int(timeout) + 5)
        cmd_events.append_command_dispatched(
            store,
            run_id=run_id,
            scenario_id=scenario_id,
            command_category="rare_protocol",
            target=host,
            protocol=protocol,
            dispatch_status=status,
            artifact=str(probe.get("artifact") or f"{host}:{port}"),
            traffic_event="rare_protocol_probe_sent",
            evidence={"seq": index, "port": port, "transport": probe.get("transport")},
        )
        dispatched += 1
    cmd_events.append_event(
        store,
        run_id=run_id,
        scenario_id=scenario_id,
        event="rare_protocol_activity_completed",
        status="info",
        evidence={"probes_dispatched": dispatched},
    )
    return dispatched
