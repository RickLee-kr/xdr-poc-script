"""Phase 1 webshell host attack — DSP-side traffic before webshell connect."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

from dsp.protocols.http.client import HttpClient
from dsp.protocols.http.sqli_payloads import PlannedSqliRequest, plan_sqli_requests
from dsp.protocols.http.target_probe import PROBE_PATHS, probe_http_endpoint
from dsp.protocols.http.urls import build_url, plan_followup_requests
from dsp.protocols.ssh.attempts import SSH_PORT_DEFAULT, plan_ssh_attempts
from dsp.protocols.ssh.client import SshClient
from dsp.protocols.types import HttpRequest
from dsp.runtime.scenario_plan import InitialCompromiseEndpoint, parse_initial_compromise_endpoint

PHASE1_HTTP_MAX_HOSTS = 1
PHASE1_HTTP_MAX_PER_HOST = 5
PHASE1_HTTP_MAX_TOTAL = 10
PHASE1_SQLI_MAX_PER_HOST = 3
PHASE1_SQLI_MAX_TOTAL = 6
PHASE1_SSH_MAX_PER_HOST = 5
PHASE1_SSH_MAX_TOTAL = 5


@dataclass(frozen=True)
class WebshellPhase1Result:
    """Summary of Phase 1 traffic dispatched from the DSP host."""

    endpoint: InitialCompromiseEndpoint
    url_scan_probes: int
    http_requests: int
    sqli_requests: int
    ssh_attempts: int
    dry_run: bool
    execution_path: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "endpoint": self.endpoint.to_dict(),
            "url_scan_probes": self.url_scan_probes,
            "http_requests": self.http_requests,
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
    """Build Phase 1 URL-scan paths with the webshell execution path first."""
    execution_path = execution_path_for_webshell_url(webshell_url)
    ordered: list[str] = []
    for path in (execution_path, *PROBE_PATHS):
        if path not in ordered:
            ordered.append(path)
    return tuple(ordered)


def run_webshell_phase1_attack(
    webshell_url: str,
    *,
    dry_run: bool = False,
    timeout: float = 10.0,
) -> WebshellPhase1Result:
    """
    Dispatch Phase 1 attack traffic against the webshell host from the DSP host.

    Runs URL-scan probes, HTTP follow-up requests, SQL injection requests, and
    SSH login failure attempts. Does not evaluate attack success.
    """
    endpoint = parse_initial_compromise_endpoint(webshell_url)
    execution_path = execution_path_for_webshell_url(webshell_url)
    http_client = HttpClient(mode="mock" if dry_run else "live", timeout=timeout)
    ssh_client = SshClient(mode="mock" if dry_run else "live", timeout=timeout)

    url_scan_probes = _run_url_scan_probes(
        endpoint,
        http_client,
        webshell_url=webshell_url,
        dry_run=dry_run,
        timeout=timeout,
    )
    http_requests = _run_http_followup(endpoint, http_client, execution_path=execution_path)
    sqli_requests = _run_sqli(endpoint, http_client)
    ssh_attempts = _run_ssh_failure(endpoint, ssh_client)

    return WebshellPhase1Result(
        endpoint=endpoint,
        url_scan_probes=url_scan_probes,
        http_requests=http_requests,
        sqli_requests=sqli_requests,
        ssh_attempts=ssh_attempts,
        dry_run=dry_run,
        execution_path=execution_path,
    )


def _run_url_scan_probes(
    endpoint: InitialCompromiseEndpoint,
    client: HttpClient,
    *,
    webshell_url: str,
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

    sent = 0
    for path in paths:
        url = build_url(endpoint.host, endpoint.port, path)
        request = HttpRequest(
            url=url,
            method="GET",
            host=endpoint.host,
            port=endpoint.port,
            path=path,
        )
        client.request(request)
        sent += 1
    return sent


def _run_http_followup(
    endpoint: InitialCompromiseEndpoint,
    client: HttpClient,
    *,
    execution_path: str,
) -> int:
    sent = 0
    if execution_path and execution_path != "/":
        request = HttpRequest(
            url=build_url(endpoint.host, endpoint.port, execution_path),
            method="GET",
            host=endpoint.host,
            port=endpoint.port,
            path=execution_path,
        )
        client.request(request)
        sent += 1

    plans = plan_followup_requests(
        endpoints=[(endpoint.host, endpoint.port)],
        max_hosts=PHASE1_HTTP_MAX_HOSTS,
        max_per_host=PHASE1_HTTP_MAX_PER_HOST,
        max_total=max(PHASE1_HTTP_MAX_TOTAL - sent, 0),
        include_attack_paths=True,
    )
    for plan in plans:
        client.request(client.make_request(plan))
    sent += len(plans)
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


def _run_sqli(endpoint: InitialCompromiseEndpoint, client: HttpClient) -> int:
    plans = plan_sqli_requests(
        endpoints=[(endpoint.host, endpoint.port)],
        max_hosts=PHASE1_HTTP_MAX_HOSTS,
        max_per_host=PHASE1_SQLI_MAX_PER_HOST,
        max_total=PHASE1_SQLI_MAX_TOTAL,
    )
    for plan in plans:
        client.request(_sqli_http_request(plan))
    return len(plans)


def _run_ssh_failure(endpoint: InitialCompromiseEndpoint, client: SshClient) -> int:
    plans = plan_ssh_attempts(
        [endpoint.host],
        max_hosts=PHASE1_HTTP_MAX_HOSTS,
        max_per_host=PHASE1_SSH_MAX_PER_HOST,
        max_total=PHASE1_SSH_MAX_TOTAL,
        port=SSH_PORT_DEFAULT,
    )
    for plan in plans:
        client.attempt(plan)
    return len(plans)
