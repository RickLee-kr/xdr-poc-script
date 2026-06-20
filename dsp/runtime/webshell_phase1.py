"""Phase 1 webshell server attack — traffic against the user-provided webshell host."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

from dsp.protocols.http.client import HttpClient
from dsp.protocols.http.sqli_payloads import PlannedSqliRequest, plan_sqli_requests
from dsp.protocols.http.target_probe import PROBE_PATHS, probe_http_endpoint
from dsp.protocols.http.urls import PlannedHttpRequest, build_url
from dsp.protocols.http.user_agents import attach_followup_user_agents
from dsp.protocols.ssh.attempts import plan_ssh_attempts
from dsp.protocols.ssh.client import SshClient
from dsp.protocols.types import HttpRequest
from dsp.runtime.scenario_plan import InitialCompromiseEndpoint, parse_initial_compromise_endpoint


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
            "traffic_origin": "dsp_host",
            "phase": "phase1_webshell_attack",
        }


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
    http_client = HttpClient(mode="mock" if dry_run else "live", timeout=timeout)
    ssh_client = SshClient(mode="mock" if dry_run else "live", timeout=timeout)

    url_scan_probes = _run_url_scan_with_user_agents(
        endpoint,
        http_client,
        webshell_url=webshell_url,
        params=http_params,
        dry_run=dry_run,
        timeout=timeout,
    )
    sqli_requests = _run_sqli(endpoint, http_client, sqli_params)
    ssh_attempts = _run_ssh_failure(endpoint, ssh_client, ssh_params)

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
    for plan in enriched_plans:
        client.request(client.make_request(plan))
    return len(enriched_plans)


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
) -> int:
    max_hosts = int(params.get("max_hosts", 1))
    plans = plan_sqli_requests(
        endpoints=[(endpoint.host, endpoint.port)],
        max_hosts=max_hosts,
        max_per_host=int(params.get("max_per_host", 10)),
        max_total=int(params.get("max_total", 20)),
    )
    for plan in plans:
        client.request(_sqli_http_request(plan))
    return len(plans)


def _run_ssh_failure(
    endpoint: InitialCompromiseEndpoint,
    client: SshClient,
    params: dict[str, Any],
) -> int:
    max_hosts = int(params.get("max_hosts", 1))
    plans = plan_ssh_attempts(
        [endpoint.host],
        max_hosts=max_hosts,
        max_per_host=int(params.get("max_per_host", 150)),
        max_total=int(params.get("max_total", 150)),
        port=int(params.get("port", 22)),
    )
    for plan in plans:
        client.attempt(plan)
    return len(plans)
