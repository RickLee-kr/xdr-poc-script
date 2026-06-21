"""Phase 1 webshell server attack — traffic against the user-provided webshell host."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

from dsp.event_store import EventStore
from dsp.protocols.http.client import HttpClient
from dsp.protocols.http.events import (
    append_outcome_event,
    build_http_followup_completed_event,
    build_http_followup_started_event,
    build_http_request_sent_event,
)
from dsp.protocols.http.sqli_events import (
    append_sqli_outcome_event,
    build_sql_injection_completed_event,
    build_sql_injection_started_event,
    build_sql_payload_generated_event,
    build_sql_request_sent_event,
)
from dsp.protocols.http.sqli_payloads import PlannedSqliRequest, plan_sqli_requests
from dsp.protocols.http.target_probe import PROBE_PATHS, probe_http_endpoint
from dsp.protocols.http.urls import PlannedHttpRequest
from dsp.protocols.http.user_agents import attach_followup_user_agents
from dsp.protocols.ssh.attempts import plan_ssh_attempts
from dsp.protocols.ssh.client import SshClient
from dsp.protocols.ssh.events import (
    append_outcome_event as append_ssh_outcome_event,
    build_ssh_auth_attempt_event,
    build_ssh_failure_completed_event,
    build_ssh_failure_started_event,
)
from dsp.protocols.types import HttpRequest
from dsp.runtime.scenario_plan import InitialCompromiseEndpoint, parse_initial_compromise_endpoint

PHASE1_TRAFFIC_ORIGIN = "dsp_host"
PHASE1_BURST_TRAFFIC_ORIGIN = "webshell_host"
PHASE1_HTTP_SCENARIO = "http_followup"
PHASE1_SQLI_SCENARIO = "sql_injection"
PHASE1_SSH_SCENARIO = "ssh_failure"


def _phase1_event_source(dry_run: bool) -> str:
    return "dry_run" if dry_run else "local"


@dataclass(frozen=True)
class WebshellPhase1Result:
    """Summary of Phase 1 traffic dispatched from the DSP host."""

    endpoint: InitialCompromiseEndpoint
    url_scan_probes: int
    sqli_requests: int
    ssh_attempts: int
    dry_run: bool
    execution_path: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "endpoint": self.endpoint.to_dict(),
            "url_scan_probes": self.url_scan_probes,
            "sqli_requests": self.sqli_requests,
            "ssh_attempts": self.ssh_attempts,
            "dry_run": self.dry_run,
            "execution_path": self.execution_path,
            "traffic_origin": PHASE1_TRAFFIC_ORIGIN,
            "phase": "phase1_webshell_attack",
        }


@dataclass
class _Phase1Events:
    store: EventStore
    run_id: str
    source: str

    def _evidence(self, **extra: Any) -> dict[str, Any]:
        return {"phase": "phase1_webshell_attack", "traffic_origin": PHASE1_TRAFFIC_ORIGIN, **extra}

    def http_started(self, endpoint: InitialCompromiseEndpoint, *, probes: int, mode: str) -> None:
        self.store.append(
            build_http_followup_started_event(
                run_id=self.run_id,
                scenario_id=PHASE1_HTTP_SCENARIO,
                target=endpoint.host,
                source=self.source,
                evidence=self._evidence(
                    requests_planned=probes,
                    mode=mode,
                    host=endpoint.host,
                    port=endpoint.port,
                ),
            )
        )

    def http_sent(self, request: HttpRequest, result_evidence: dict[str, Any]) -> None:
        self.store.append(
            build_http_request_sent_event(
                run_id=self.run_id,
                scenario_id=PHASE1_HTTP_SCENARIO,
                target=request.host,
                url=request.url,
                source=self.source,
                evidence=self._evidence(**result_evidence),
            )
        )

    def http_outcome(self, request: HttpRequest, result) -> None:
        self.store.append(
            append_outcome_event(
                run_id=self.run_id,
                scenario_id=PHASE1_HTTP_SCENARIO,
                request=request,
                result=result,
                source=self.source,
            )
        )

    def http_completed(self, endpoint: InitialCompromiseEndpoint, *, sent: int) -> None:
        self.store.append(
            build_http_followup_completed_event(
                run_id=self.run_id,
                scenario_id=PHASE1_HTTP_SCENARIO,
                target=endpoint.host,
                source=self.source,
                evidence=self._evidence(requests_sent=sent),
            )
        )

    def sqli_started(self, endpoint: InitialCompromiseEndpoint, *, requests: int, mode: str) -> None:
        self.store.append(
            build_sql_injection_started_event(
                run_id=self.run_id,
                scenario_id=PHASE1_SQLI_SCENARIO,
                target=endpoint.host,
                source=self.source,
                evidence=self._evidence(requests_planned=requests, mode=mode),
            )
        )

    def sqli_payload(self, plan: PlannedSqliRequest) -> None:
        self.store.append(
            build_sql_payload_generated_event(
                run_id=self.run_id,
                scenario_id=PHASE1_SQLI_SCENARIO,
                target=plan.host,
                url=plan.url,
                source=self.source,
                evidence=self._evidence(
                    host=plan.host,
                    port=plan.port,
                    path=plan.path,
                    parameter=plan.parameter,
                    payload=plan.payload,
                    payload_category=plan.payload_category,
                    transport=plan.transport,
                ),
            )
        )

    def sqli_sent(self, request: HttpRequest, plan: PlannedSqliRequest) -> None:
        self.store.append(
            build_sql_request_sent_event(
                run_id=self.run_id,
                scenario_id=PHASE1_SQLI_SCENARIO,
                target=plan.host,
                url=request.url,
                source=self.source,
                evidence=self._evidence(
                    method=request.method,
                    host=plan.host,
                    port=plan.port,
                    path=plan.path,
                    payload=plan.payload,
                ),
            )
        )

    def sqli_outcome(self, request: HttpRequest, result, plan: PlannedSqliRequest) -> None:
        self.store.append(
            append_sqli_outcome_event(
                run_id=self.run_id,
                scenario_id=PHASE1_SQLI_SCENARIO,
                request=request,
                result=result,
                source=self.source,
                payload=plan.payload,
            )
        )

    def sqli_completed(self, endpoint: InitialCompromiseEndpoint, *, sent: int) -> None:
        self.store.append(
            build_sql_injection_completed_event(
                run_id=self.run_id,
                scenario_id=PHASE1_SQLI_SCENARIO,
                target=endpoint.host,
                source=self.source,
                evidence=self._evidence(requests_sent=sent),
            )
        )

    def ssh_started(self, endpoint: InitialCompromiseEndpoint, *, attempts: int, mode: str) -> None:
        self.store.append(
            build_ssh_failure_started_event(
                run_id=self.run_id,
                scenario_id=PHASE1_SSH_SCENARIO,
                target=endpoint.host,
                source=self.source,
                evidence=self._evidence(
                    planned_attempts=attempts,
                    auth_attempts_planned=attempts,
                    mode=mode,
                    port=22,
                ),
            )
        )

    def ssh_completed(self, endpoint: InitialCompromiseEndpoint, *, dispatched: int) -> None:
        self.store.append(
            build_ssh_failure_completed_event(
                run_id=self.run_id,
                scenario_id=PHASE1_SSH_SCENARIO,
                target=endpoint.host,
                source=self.source,
                evidence=self._evidence(
                    auth_attempts=dispatched,
                    auth_failures=dispatched,
                ),
            )
        )


def execution_path_for_webshell_url(webshell_url: str) -> str:
    """Return the URL path component from a webshell URL for Phase 1 probing."""
    parsed = urlparse(webshell_url.strip())
    return parsed.path or "/"


def phase1_probe_paths(webshell_url: str) -> tuple[str, ...]:
    """Build URL-scan paths with the webshell execution path first."""
    execution_path = execution_path_for_webshell_url(webshell_url)
    ordered: list[str] = []
    for path in (execution_path, *PROBE_PATHS):
        if path not in ordered:
            ordered.append(path)
    return tuple(ordered)


def run_webshell_phase1_attack(
    webshell_url: str,
    *,
    scenario_params: dict[str, dict[str, Any]] | None = None,
    dry_run: bool = False,
    timeout: float = 10.0,
    event_store: EventStore | None = None,
    run_id: str | None = None,
) -> WebshellPhase1Result:
    """
    Dispatch Phase 1 attack traffic against the webshell server from the DSP host.

    Runs URL scan with User-Agent anomaly mix, SQL injection, and SSH login failures
    against the host derived from ``webshell_url`` only.
    """
    params = scenario_params or {}
    http_params = params.get("http_followup", {})
    sqli_params = params.get("sql_injection", {})
    ssh_params = params.get("ssh_failure", {})

    endpoint = parse_initial_compromise_endpoint(webshell_url)
    execution_path = execution_path_for_webshell_url(webshell_url)
    mode = "mock" if dry_run else "live"
    http_client = HttpClient(mode=mode, timeout=timeout)
    ssh_client = SshClient(mode=mode, timeout=timeout)
    events = (
        _Phase1Events(event_store, run_id, _phase1_event_source(dry_run))
        if event_store is not None and run_id
        else None
    )

    url_scan_probes = _run_url_scan_with_user_agents(
        endpoint,
        http_client,
        webshell_url=webshell_url,
        params=http_params,
        dry_run=dry_run,
        timeout=timeout,
        events=events,
        mode=mode,
    )
    sqli_requests = _run_sqli(endpoint, http_client, sqli_params, events=events, mode=mode)
    ssh_attempts = _run_ssh_failure(endpoint, ssh_client, ssh_params, events=events, mode=mode)

    return WebshellPhase1Result(
        endpoint=endpoint,
        url_scan_probes=url_scan_probes,
        sqli_requests=sqli_requests,
        ssh_attempts=ssh_attempts,
        dry_run=dry_run,
        execution_path=execution_path,
    )


def _run_url_scan_with_user_agents(
    endpoint: InitialCompromiseEndpoint,
    client: HttpClient,
    *,
    webshell_url: str,
    params: dict[str, Any],
    dry_run: bool,
    timeout: float,
    events: _Phase1Events | None,
    mode: str,
) -> int:
    paths = phase1_probe_paths(webshell_url)
    if dry_run:
        probe_http_endpoint(
            endpoint.host,
            endpoint.port,
            endpoint.scheme,
            dry_run=True,
            timeout=timeout,
        )
        if events is not None:
            events.http_started(endpoint, probes=len(paths), mode=mode)
            for path in paths:
                url = f"http://{endpoint.host}:{endpoint.port}{path}"
                request = HttpRequest(
                    url=url,
                    method="GET",
                    host=endpoint.host,
                    port=endpoint.port,
                    path=path,
                )
                result = client.request(request)
                events.http_sent(
                    request,
                    {"method": "GET", "path": path, "dry_run": True, "outcome": result.outcome},
                )
                events.http_outcome(request, result)
            events.http_completed(endpoint, sent=len(paths))
        return len(paths)

    plans = [
        PlannedHttpRequest(
            host=endpoint.host,
            port=endpoint.port,
            path=path,
            method="GET",
        )
        for path in paths
    ]
    abnormal_ratio = float(params.get("abnormal_ua_ratio", 0.10))
    enriched_plans, _ = attach_followup_user_agents(
        plans,
        abnormal_ratio=abnormal_ratio,
    )
    if events is not None:
        events.http_started(endpoint, probes=len(enriched_plans), mode=mode)
    sent = 0
    for plan in enriched_plans:
        request = client.make_request(plan)
        result = client.request(request)
        if events is not None:
            events.http_sent(
                request,
                {
                    "method": plan.method,
                    "path": plan.path,
                    "user_agent": (plan.headers or {}).get("User-Agent", ""),
                    "outcome": result.outcome,
                },
            )
            events.http_outcome(request, result)
        sent += 1
    if events is not None:
        events.http_completed(endpoint, sent=sent)
    return sent


def _sqli_http_request(plan: PlannedSqliRequest) -> HttpRequest:
    path = plan.path if not plan.query else f"{plan.path}?{plan.query}"
    headers: dict[str, str] = {"User-Agent": "dsp-sql-injection/1.0"}
    if plan.content_type:
        headers["Content-Type"] = plan.content_type
    return HttpRequest(
        url=plan.url,
        method=plan.method,
        host=plan.host,
        port=plan.port,
        path=path,
        headers=headers,
        body=plan.body,
        content_type=plan.content_type,
    )


def _run_sqli(
    endpoint: InitialCompromiseEndpoint,
    client: HttpClient,
    params: dict[str, Any],
    *,
    events: _Phase1Events | None,
    mode: str,
) -> int:
    max_hosts = int(params.get("max_hosts", 1))
    plans = plan_sqli_requests(
        endpoints=[(endpoint.host, endpoint.port)],
        max_hosts=max_hosts,
        max_per_host=int(params.get("max_per_host", 10)),
        max_total=int(params.get("max_total", 20)),
    )
    if events is not None:
        events.sqli_started(endpoint, requests=len(plans), mode=mode)
    sent = 0
    for plan in plans:
        request = _sqli_http_request(plan)
        if events is not None:
            events.sqli_payload(plan)
        result = client.request(request)
        if events is not None:
            events.sqli_sent(request, plan)
            events.sqli_outcome(request, result, plan)
        sent += 1
    if events is not None:
        events.sqli_completed(endpoint, sent=sent)
    return sent


def _run_ssh_failure(
    endpoint: InitialCompromiseEndpoint,
    client: SshClient,
    params: dict[str, Any],
    *,
    events: _Phase1Events | None,
    mode: str,
) -> int:
    max_hosts = int(params.get("max_hosts", 1))
    plans = plan_ssh_attempts(
        [endpoint.host],
        max_hosts=max_hosts,
        max_per_host=int(params.get("max_per_host", 150)),
        max_total=int(params.get("max_total", 150)),
        port=int(params.get("port", 22)),
    )
    if events is not None:
        events.ssh_started(endpoint, attempts=len(plans), mode=mode)
    dispatched = 0
    for plan in plans:
        attempt = client.make_attempt(plan)
        if events is not None:
            artifact = f"{plan.username}@{plan.host}:{plan.port}"
            events.store.append(
                build_ssh_auth_attempt_event(
                    run_id=events.run_id,
                    scenario_id=PHASE1_SSH_SCENARIO,
                    target=plan.host,
                    artifact=artifact,
                    source=events.source,
                    evidence=events._evidence(
                        host=plan.host,
                        port=plan.port,
                        username=plan.username,
                        password_label=plan.password_label,
                    ),
                )
            )
        result = client.attempt(plan)
        if events is not None:
            events.store.append(
                append_ssh_outcome_event(
                    run_id=events.run_id,
                    scenario_id=PHASE1_SSH_SCENARIO,
                    attempt=attempt,
                    result=result,
                    source=events.source,
                    password_label=plan.password_label,
                )
            )
        dispatched += 1
    if events is not None:
        events.ssh_completed(endpoint, dispatched=dispatched)
    return dispatched


def _phase1_burst_evidence(**extra: Any) -> dict[str, Any]:
    return {
        "phase": "phase1_webshell_attack",
        "traffic_origin": PHASE1_BURST_TRAFFIC_ORIGIN,
        **extra,
    }


def run_webshell_phase1_non_standard_port_burst(
    provider: Any,
    webshell_url: str,
    *,
    http_params: dict[str, Any],
    dry_run: bool,
    event_store: EventStore,
    run_id: str,
) -> dict[str, Any]:
    """
    Run non-standard port burst from the webshell host against itself (Phase 1).

    Dispatches curl commands through the webshell provider so traffic originates
    on the compromised web server.
    """
    from dsp.execution.providers.runtime.command import CommandRequest
    from dsp.execution.remote.command import events as cmd_events
    from dsp.execution.remote.command.shell import curl_request_command, mock_noop_command
    from dsp.protocols.http.events import (
        build_non_standard_port_burst_completed_event,
        build_non_standard_port_burst_started_event,
        build_non_standard_port_connection_failure_event,
        build_non_standard_port_connection_success_event,
    )
    from dsp.protocols.http.non_standard_port_burst import (
        burst_connection_success,
        plan_webshell_host_non_standard_port_burst,
    )

    endpoint = parse_initial_compromise_endpoint(webshell_url)
    burst_plan = plan_webshell_host_non_standard_port_burst(
        endpoint.host,
        endpoint.port,
        http_params,
    )
    if not burst_plan.get("enabled"):
        return burst_plan

    scenario_id = PHASE1_HTTP_SCENARIO
    source = "dry_run" if dry_run else "remote"
    mode = "mock" if dry_run else "live"
    timeout = float(http_params.get("timeout", 10.0))
    requests = list(burst_plan.get("requests") or [])
    ports = list(burst_plan.get("ports") or [])
    targets = list(burst_plan.get("targets") or [])
    primary_target = endpoint.host

    event_store.append(
        build_non_standard_port_burst_started_event(
            run_id=run_id,
            scenario_id=scenario_id,
            target=primary_target,
            source=source,
            evidence=_phase1_burst_evidence(
                attempts_planned=len(requests),
                ports=ports,
                targets=targets,
                mode=mode,
                host=endpoint.host,
                port=endpoint.port,
            ),
        )
    )

    attempts = 0
    successes = 0
    failures = 0
    for item in requests:
        url = str(item["url"])
        method = str(item.get("method") or "GET")
        user_agent = str(item.get("user_agent") or "Mozilla/5.0")
        host = str(item.get("host") or endpoint.host)
        port = int(item.get("port") or 0)
        base_evidence = _phase1_burst_evidence(
            seq=item.get("seq"),
            host=host,
            port=port,
            url=url,
            method=method,
            user_agent=user_agent,
            discovered=item.get("discovered"),
            probe=item.get("probe"),
        )
        command = (
            mock_noop_command()
            if mode == "mock"
            else curl_request_command(url, method=method, user_agent=user_agent, timeout=timeout)
        )
        dispatch_status = provider.execute_command(
            CommandRequest.new(command, timeout_seconds=int(timeout) + 5)
        ).status.value
        cmd_events.append_command_dispatched(
            event_store,
            run_id=run_id,
            scenario_id=scenario_id,
            command_category="non_standard_port_burst",
            target=host,
            protocol="http",
            dispatch_status=str(dispatch_status),
            traffic_event="non_standard_port_connection_attempt",
            traffic_status="sent",
            evidence=dict(base_evidence),
            artifact=url,
        )
        attempts += 1

        if mode == "mock":
            status_code = 200 if int(item.get("seq") or 0) % 3 else 404
            outcome = "response"
            result_evidence = dict(base_evidence)
            result_evidence["status_code"] = status_code
            result_evidence["outcome"] = outcome
            result_evidence["dispatch_status"] = str(dispatch_status)
            if burst_connection_success(outcome, status_code):
                successes += 1
                event_store.append(
                    build_non_standard_port_connection_success_event(
                        run_id=run_id,
                        scenario_id=scenario_id,
                        target=host,
                        source=source,
                        evidence=result_evidence,
                    )
                )
            else:
                failures += 1
                event_store.append(
                    build_non_standard_port_connection_failure_event(
                        run_id=run_id,
                        scenario_id=scenario_id,
                        target=host,
                        source=source,
                        evidence=result_evidence,
                        status="error",
                    )
                )

    summary = {
        "enabled": True,
        "ports": ports,
        "targets": targets,
        "attempts": attempts,
        "success": successes,
        "failure": failures,
        "traffic_origin": PHASE1_BURST_TRAFFIC_ORIGIN,
    }
    event_store.append(
        build_non_standard_port_burst_completed_event(
            run_id=run_id,
            scenario_id=scenario_id,
            target=primary_target,
            source=source,
            evidence=_phase1_burst_evidence(**summary),
        )
    )
    return summary
