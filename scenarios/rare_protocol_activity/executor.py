"""Rare protocol activity executor — safe TELNET/RTSP/SIP/RTP probes."""

from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import Any

from dsp.engine.scenario_engine import RunContext, ScenarioSkipError, TargetSet
from dsp.event_store import Event
from dsp.execution.remote.command.scenario_plans import (
    plan_rare_protocol_activity as build_rare_protocol_plan,
)
from dsp.protocols.rare import (
    RareProtocolClient,
    build_rare_protocol_activity_completed_event,
    build_rare_protocol_activity_started_event,
    build_rare_protocol_probe_attempt_event,
    build_rare_protocol_probe_failure_event,
    build_rare_protocol_probe_success_event,
)
from dsp.protocols.rare.attempts import PlannedRareProbe
from dsp.protocols.rare.events import RARE_PROTOCOL_ACTIVITY_SKIPPED
from dsp.runner.activity_reporter import ActivityReporter
from dsp.runtime.scenario_plan import WEBSHELL_EXECUTION_KEY


ALLOWED_OUTCOME_STATUSES = frozenset(
    {"error", "timeout", "connection_refused", "unsupported_protocol", "connection_error"}
)


def _failure_status(outcome: str) -> str:
    if outcome in ALLOWED_OUTCOME_STATUSES:
        return outcome
    if "timeout" in outcome:
        return "timeout"
    if "refused" in outcome:
        return "connection_refused"
    return "error"


def _execution_vantage(
    targets: TargetSet,
    params: dict[str, Any],
    probes: list[PlannedRareProbe],
) -> str:
    ws_ctx = params.get(WEBSHELL_EXECUTION_KEY)
    if isinstance(ws_ctx, dict) and ws_ctx.get("execution_host"):
        return str(ws_ctx["execution_host"])
    if probes:
        return probes[0].host
    if targets.hosts:
        return str(targets.hosts[0])
    return ""


def _probes_from_plan(plan: dict[str, Any]) -> list[PlannedRareProbe]:
    return [
        PlannedRareProbe(
            protocol=str(probe["protocol"]),
            host=str(probe["host"]),
            port=int(probe["port"]),
            transport=str(probe["transport"]),
            artifact=str(probe["artifact"]),
            rtp_packets=int(probe.get("rtp_packets") or 0),
        )
        for probe in plan.get("probes") or []
    ]


def _emit_skipped(
    ctx: RunContext,
    *,
    scenario_id: str,
    source: str,
    reason: str,
    execution_host: str,
) -> None:
    ctx.event_store.append(
        Event(
            run_id=ctx.run_id,
            scenario_id=scenario_id,
            timestamp=datetime.now(timezone.utc),
            stage="executor",
            event=RARE_PROTOCOL_ACTIVITY_SKIPPED,
            status="info",
            source=source,
            evidence={
                "reason": reason,
                "execution_host": execution_host,
            },
        )
    )


def run(
    ctx: RunContext,
    targets: TargetSet,
    config: dict | None = None,
    scenario_id: str = "rare_protocol_activity",
) -> None:
    """Execute rare-protocol probes from the provider-independent scenario plan."""
    params = config or {}
    source = "dry_run" if ctx.dry_run else "local"
    execution_plan = build_rare_protocol_plan(targets, params, dry_run=ctx.dry_run)

    if execution_plan.get("mode") == "skip":
        reason = str(execution_plan.get("reason") or "no_probe_plans")
        _emit_skipped(
            ctx,
            scenario_id=scenario_id,
            source=source,
            reason=reason,
            execution_host=_execution_vantage(targets, params, []),
        )
        raise ScenarioSkipError(reason)

    plans = _probes_from_plan(execution_plan)
    mode = str(execution_plan.get("mode") or ("mock" if ctx.dry_run else "live"))
    timeout = float(execution_plan.get("timeout", params.get("timeout", 3.0)))
    client = RareProtocolClient(mode=mode, timeout=timeout)
    vantage = _execution_vantage(targets, params, plans)

    protocols = sorted({plan.protocol for plan in plans})
    attempt_count = 0
    success_count = 0
    failure_count = 0
    t0 = time.monotonic()
    activity = ActivityReporter(ctx, scenario_id, total=len(plans))

    ctx.event_store.append(
        build_rare_protocol_activity_started_event(
            run_id=ctx.run_id,
            scenario_id=scenario_id,
            target=vantage,
            source=source,
            evidence={
                "execution_host": vantage,
                "planned_probes": len(plans),
                "protocols": protocols,
                "mode": mode,
                "discovery": targets.discovery_enabled,
            },
        )
    )

    for seq, plan in enumerate(plans, start=1):
        if ctx.cancelled:
            break

        probe_evidence = {
            "seq": seq,
            "protocol": plan.protocol,
            "host": plan.host,
            "port": plan.port,
            "transport": plan.transport,
        }
        ctx.event_store.append(
            build_rare_protocol_probe_attempt_event(
                run_id=ctx.run_id,
                scenario_id=scenario_id,
                target=plan.host,
                artifact=plan.artifact,
                source=source,
                evidence=probe_evidence,
            )
        )
        attempt_count += 1

        if mode == "mock":
            result = client.probe(plan, mock_outcome="probe_sent")
        else:
            result = client.probe(plan)

        outcome_evidence = {
            **probe_evidence,
            "outcome": result.outcome,
            "packets_sent": result.packets_sent,
            **result.evidence,
        }
        if result.success:
            success_count += 1
            ctx.event_store.append(
                build_rare_protocol_probe_success_event(
                    run_id=ctx.run_id,
                    scenario_id=scenario_id,
                    target=plan.host,
                    artifact=plan.artifact,
                    source=source,
                    evidence=outcome_evidence,
                )
            )
        else:
            failure_count += 1
            ctx.event_store.append(
                build_rare_protocol_probe_failure_event(
                    run_id=ctx.run_id,
                    scenario_id=scenario_id,
                    target=plan.host,
                    artifact=plan.artifact,
                    source=source,
                    evidence=outcome_evidence,
                    status=_failure_status(result.outcome),
                )
            )

        activity.update(success=success_count, failed=failure_count, current=plan.artifact)
        activity.record(
            action="rare_probe",
            target=plan.host,
            port=plan.port,
            result=result.outcome,
        )

    activity.emit_final_progress()
    elapsed = round(time.monotonic() - t0, 3)
    ctx.event_store.append(
        build_rare_protocol_activity_completed_event(
            run_id=ctx.run_id,
            scenario_id=scenario_id,
            target=vantage,
            source=source,
            evidence={
                "execution_host": vantage,
                "protocols": protocols,
                "attempt_count": attempt_count,
                "success_count": success_count,
                "failure_count": failure_count,
                "duration_sec": elapsed,
                "targets": sorted({plan.host for plan in plans}),
            },
        )
    )
