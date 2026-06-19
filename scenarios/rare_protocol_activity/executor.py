"""Rare protocol activity executor — safe TELNET/RTSP/SIP/RTP probes."""

from __future__ import annotations

import time
from datetime import datetime, timezone

from dsp.engine.scenario_engine import RunContext, TargetSet
from dsp.event_store import Event
from dsp.protocols.rare import (
    RareProtocolClient,
    build_rare_protocol_activity_completed_event,
    build_rare_protocol_activity_started_event,
    build_rare_protocol_probe_attempt_event,
    build_rare_protocol_probe_failure_event,
    build_rare_protocol_probe_success_event,
    plan_rare_protocol_activity,
)
from dsp.protocols.rare.attempts import _execution_host
from dsp.runner.activity_reporter import ActivityReporter


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


def run(
    ctx: RunContext,
    targets: TargetSet,
    config: dict | None = None,
    scenario_id: str = "rare_protocol_activity",
) -> None:
    """Plan and execute rare-protocol probes from the execution vantage point."""
    params = config or {}
    source = "dry_run" if ctx.dry_run else "local"
    mode = "mock" if ctx.dry_run else "live"
    client = RareProtocolClient(
        mode=mode,
        timeout=float(params.get("timeout", 3.0)),
    )

    plans = plan_rare_protocol_activity(targets, params)
    vantage = _execution_host(targets, params)

    if not plans:
        ctx.event_store.append(
            Event(
                run_id=ctx.run_id,
                scenario_id=scenario_id,
                timestamp=datetime.now(timezone.utc),
                stage="executor",
                event="rare_protocol_activity_skipped",
                status="info",
                source=source,
                evidence={
                    "reason": "no_probe_plans",
                    "execution_host": vantage,
                },
            )
        )
        return

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
