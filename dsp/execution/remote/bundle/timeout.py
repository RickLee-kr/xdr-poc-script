"""Remote bundle execution timeout estimation from serialized manifests."""

from __future__ import annotations

from typing import Any

DEFAULT_BUNDLE_TIMEOUT_SECONDS = 300
MIN_BUNDLE_TIMEOUT_SECONDS = 120
MAX_BUNDLE_TIMEOUT_SECONDS = 900
REMOTE_SHELL_BUDGET_SECONDS = 30
STARTUP_OVERHEAD_SECONDS = 15
PER_EVENT_FLUSH_SECONDS = 0.05

REMOTE_BURST_CONNECT_TIMEOUT_SECONDS = 1.0
REMOTE_BURST_MAX_ATTEMPTS_DEFAULT = 15


def compute_bundle_execution_timeout_seconds(manifest: dict[str, Any]) -> int:
    """Estimate remote ``run_scenario.py`` wall time from a serialized manifest."""
    plan = manifest.get("plan") or {}
    plan_type = str(plan.get("type") or "")
    mode = str(plan.get("mode") or "")

    if mode in {"skip", "mock"} or plan_type == "skip":
        return MIN_BUNDLE_TIMEOUT_SECONDS

    per_op = max(0.5, float(plan.get("timeout", 3.0)))
    connect = max(0.5, float(plan.get("connect_timeout", per_op)))
    overhead = STARTUP_OVERHEAD_SECONDS

    if plan_type == "port_sweep":
        probes = len(plan.get("probes") or [])
        concurrency = max(1, int(plan.get("concurrency", 32)))
        batches = (probes + concurrency - 1) // concurrency
        estimate = batches * per_op
    elif plan_type == "dns_tunnel":
        estimate = len(plan.get("queries") or []) * per_op
    elif plan_type == "http_followup":
        requests = len(plan.get("requests") or [])
        burst = plan.get("non_standard_port_burst") or {}
        burst_count = len(burst.get("requests") or []) if burst.get("enabled") else 0
        estimate = requests * per_op + burst_count * max(
            connect, REMOTE_BURST_CONNECT_TIMEOUT_SECONDS
        )
    elif plan_type == "sql_injection":
        estimate = len(plan.get("requests") or []) * per_op
    elif plan_type == "ssh_failure":
        estimate = len(plan.get("attempts") or []) * per_op
    elif plan_type == "host_behavior_check":
        commands = len(plan.get("commands") or [])
        credential_checks = len(plan.get("credential_checks") or [])
        estimate = (commands + credential_checks) * per_op + 30.0
    elif plan_type == "rare_protocol_activity":
        estimate = len(plan.get("probes") or []) * per_op
    else:
        estimate = per_op * 10

    event_budget = _planned_event_count(plan) * PER_EVENT_FLUSH_SECONDS
    total = overhead + estimate + event_budget + 30.0
    return int(
        min(MAX_BUNDLE_TIMEOUT_SECONDS, max(MIN_BUNDLE_TIMEOUT_SECONDS, total))
    )


def apply_remote_execution_budget(plan: dict[str, Any]) -> dict[str, Any]:
    """Cap expensive remote-only work so typical webshell command budgets can finish."""
    if str(plan.get("type")) != "http_followup":
        return plan
    if str(plan.get("mode")) in {"skip", "mock"}:
        return plan

    updated = dict(plan)
    per_op = max(0.5, float(updated.get("timeout", 10.0)))
    main_requests = len(updated.get("requests") or [])
    main_budget = main_requests * per_op

    burst = dict(updated.get("non_standard_port_burst") or {})
    if not burst.get("enabled"):
        updated["connect_timeout"] = REMOTE_BURST_CONNECT_TIMEOUT_SECONDS
        return updated

    remaining = max(
        0.0,
        REMOTE_SHELL_BUDGET_SECONDS - STARTUP_OVERHEAD_SECONDS - main_budget,
    )
    max_attempts = max(
        0,
        min(
            int(burst.get("attempts_planned") or len(burst.get("requests") or [])),
            int(remaining // REMOTE_BURST_CONNECT_TIMEOUT_SECONDS)
            if remaining > 0
            else 0,
            REMOTE_BURST_MAX_ATTEMPTS_DEFAULT,
        ),
    )
    requests = list(burst.get("requests") or [])[:max_attempts]
    burst["requests"] = requests
    burst["attempts_planned"] = len(requests)
    if not requests:
        burst["enabled"] = False
        burst["reason"] = "remote_execution_budget_exhausted"
    updated["non_standard_port_burst"] = burst
    updated["connect_timeout"] = REMOTE_BURST_CONNECT_TIMEOUT_SECONDS
    return updated


def _planned_event_count(plan: dict[str, Any]) -> int:
    plan_type = str(plan.get("type") or "")
    if plan_type == "port_sweep":
        return len(plan.get("probes") or []) * 2 + 2
    if plan_type == "dns_tunnel":
        return len(plan.get("queries") or []) + 2
    if plan_type == "http_followup":
        requests = len(plan.get("requests") or [])
        burst = plan.get("non_standard_port_burst") or {}
        burst_count = len(burst.get("requests") or []) if burst.get("enabled") else 0
        return requests * 3 + burst_count * 2 + 4
    if plan_type == "sql_injection":
        return len(plan.get("requests") or []) * 2 + 2
    if plan_type == "ssh_failure":
        return len(plan.get("attempts") or []) + 2
    if plan_type == "host_behavior_check":
        return len(plan.get("commands") or []) + len(plan.get("credential_checks") or []) + 2
    if plan_type == "rare_protocol_activity":
        return len(plan.get("probes") or []) * 2 + 2
    return 4


def planned_workload_summary(plan: dict[str, Any]) -> dict[str, Any]:
    """Return a compact planned-workload snapshot for remote status reporting."""
    plan_type = str(plan.get("type") or "")
    summary: dict[str, Any] = {"type": plan_type, "mode": plan.get("mode")}
    if plan_type == "http_followup":
        summary["requests"] = len(plan.get("requests") or [])
        burst = plan.get("non_standard_port_burst") or {}
        summary["burst_attempts"] = (
            len(burst.get("requests") or []) if burst.get("enabled") else 0
        )
    elif plan_type == "port_sweep":
        summary["probes"] = len(plan.get("probes") or [])
    elif plan_type == "dns_tunnel":
        summary["queries"] = len(plan.get("queries") or [])
    elif plan_type == "sql_injection":
        summary["requests"] = len(plan.get("requests") or [])
    elif plan_type == "ssh_failure":
        summary["attempts"] = len(plan.get("attempts") or [])
    elif plan_type == "host_behavior_check":
        summary["commands"] = len(plan.get("commands") or [])
    elif plan_type == "rare_protocol_activity":
        summary["probes"] = len(plan.get("probes") or [])
    return summary
