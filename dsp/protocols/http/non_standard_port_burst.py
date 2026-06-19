"""Non-standard port HTTP burst — Stellar external_non_std_port_anomaly pattern simulation."""

from __future__ import annotations

import random
from dataclasses import dataclass
from typing import Any

from dsp.engine.scenario_engine import TargetSet
from dsp.protocols.http.urls import PlannedHttpRequest
from dsp.protocols.http.user_agents import pick_user_agent

STANDARD_FOLLOWUP_PORTS = frozenset({80, 8080})
NON_STANDARD_BURST_CANDIDATES: tuple[int, ...] = (8088, 8443, 9000, 9001, 9443)
HTTPS_BURST_PORTS = frozenset({8443, 9443})
DEFAULT_BURST_MIN = 50
DEFAULT_BURST_MAX = 200


@dataclass(frozen=True)
class NonStandardBurstTarget:
    host: str
    port: int
    scheme: str
    discovered: bool
    probe: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "host": self.host,
            "port": self.port,
            "scheme": self.scheme,
            "discovered": self.discovered,
            "probe": self.probe,
        }


def _scheme_for_port(port: int) -> str:
    return "https" if port in HTTPS_BURST_PORTS else "http"


def _discovered_non_standard_endpoints(targets: TargetSet) -> list[tuple[str, int]]:
    seen: set[tuple[str, int]] = set()
    endpoints: list[tuple[str, int]] = []
    for capability in ("http_targets", "https_targets"):
        for host, port in targets.endpoints_for_capability(capability):
            if port in STANDARD_FOLLOWUP_PORTS:
                continue
            key = (host, port)
            if key in seen:
                continue
            seen.add(key)
            endpoints.append(key)
    return endpoints


def select_non_standard_burst_targets(
    targets: TargetSet,
    followup_hosts: list[str],
    *,
    candidate_ports: tuple[int, ...] = NON_STANDARD_BURST_CANDIDATES,
) -> list[NonStandardBurstTarget]:
    """Prefer discovered non-standard HTTP endpoints; probe undiscovered candidates."""
    discovered = _discovered_non_standard_endpoints(targets)
    discovered_by_host: dict[str, set[int]] = {}
    for host, port in discovered:
        discovered_by_host.setdefault(host, set()).add(port)

    selected: list[NonStandardBurstTarget] = []
    seen: set[tuple[str, int]] = set()

    for host, port in discovered:
        key = (host, port)
        if key in seen:
            continue
        seen.add(key)
        selected.append(
            NonStandardBurstTarget(
                host=host,
                port=port,
                scheme=_scheme_for_port(port),
                discovered=True,
                probe=False,
            )
        )

    hosts = followup_hosts or sorted({host for host, _ in discovered})
    for host in hosts:
        known_ports = discovered_by_host.get(host, set())
        for port in candidate_ports:
            key = (host, port)
            if key in seen:
                continue
            seen.add(key)
            selected.append(
                NonStandardBurstTarget(
                    host=host,
                    port=port,
                    scheme=_scheme_for_port(port),
                    discovered=port in known_ports,
                    probe=port not in known_ports,
                )
            )
    return selected


def resolve_burst_attempt_count(params: dict[str, Any]) -> int:
    minimum = int(params.get("non_standard_burst_min", DEFAULT_BURST_MIN))
    maximum = int(params.get("non_standard_burst_max", DEFAULT_BURST_MAX))
    if minimum > maximum:
        minimum, maximum = maximum, minimum
    minimum = max(1, minimum)
    maximum = max(minimum, maximum)
    if minimum == maximum:
        return minimum
    return random.randint(minimum, maximum)


def _build_burst_url(host: str, port: int, path: str, scheme: str) -> str:
    if scheme == "https":
        if port == 443:
            return f"https://{host}{path}"
        return f"https://{host}:{port}{path}"
    if port == 80:
        return f"http://{host}{path}"
    return f"http://{host}:{port}{path}"


def plan_non_standard_port_burst(
    targets: TargetSet,
    followup_hosts: list[str],
    params: dict[str, Any],
) -> dict[str, Any]:
    """Build serializable burst plan for local or remote execution."""
    if not bool(params.get("non_standard_port_burst_enabled", True)):
        return {"enabled": False}

    burst_targets = select_non_standard_burst_targets(targets, followup_hosts)
    if not burst_targets:
        return {"enabled": False, "reason": "no_burst_targets"}

    attempts = resolve_burst_attempt_count(params)
    path = str(params.get("non_standard_burst_path", "/"))
    plans: list[dict[str, Any]] = []
    for seq in range(1, attempts + 1):
        target = burst_targets[(seq - 1) % len(burst_targets)]
        ua = pick_user_agent()
        plan = PlannedHttpRequest(
            host=target.host,
            port=target.port,
            path=path,
            method="GET",
            headers={"User-Agent": ua},
        )
        plans.append(
            {
                "seq": seq,
                "host": target.host,
                "port": target.port,
                "scheme": target.scheme,
                "url": _build_burst_url(target.host, target.port, path, target.scheme),
                "method": "GET",
                "path": path,
                "user_agent": ua,
                "discovered": target.discovered,
                "probe": target.probe,
            }
        )

    ports = sorted({target.port for target in burst_targets})
    return {
        "enabled": True,
        "attempts_planned": attempts,
        "targets": [target.to_dict() for target in burst_targets],
        "ports": ports,
        "path": path,
        "requests": plans,
    }


def burst_connection_success(result_outcome: str, status_code: int | None) -> bool:
    if result_outcome == "response" and status_code is not None:
        return int(status_code) < 500
    return False
