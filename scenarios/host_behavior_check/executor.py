"""Host behavior check executor — harmless commands on webshell host only."""

from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import Any

from dsp.engine.scenario_engine import RunContext, TargetSet
from dsp.event_store import Event
from dsp.protocols.host.behavior import build_host_behavior_plan
from dsp.protocols.host.behavior_executor import execute_host_behavior_plan


def run(
    ctx: RunContext,
    targets: TargetSet,
    config: dict | None = None,
    scenario_id: str = "host_behavior_check",
) -> None:
    """Execute host behavior commands on the webshell compromise host."""
    _ = targets
    params = dict(config or {})
    source = "dry_run" if ctx.dry_run else "local"
    plan = build_host_behavior_plan(
        params,
        run_id=ctx.run_id,
        dry_run=ctx.dry_run,
        webshell_family=params.get("webshell_family"),
    )

    if plan.get("mode") == "skip":
        ctx.event_store.append(
            Event(
                run_id=ctx.run_id,
                scenario_id=scenario_id,
                timestamp=datetime.now(timezone.utc),
                stage="executor",
                event=f"{scenario_id}_skipped",
                status="info",
                source=source,
                evidence={
                    "reason": plan.get("reason", "skipped"),
                    "webshell_family": plan.get("webshell_family"),
                },
            )
        )
        return

    timeout = float(params.get("timeout", 30.0))
    t0 = time.monotonic()
    execute_host_behavior_plan(
        ctx.event_store,
        plan,
        run_id=ctx.run_id,
        scenario_id=scenario_id,
        source=source,
        cancelled=lambda: ctx.cancelled,
        timeout=timeout,
    )
    _ = round(time.monotonic() - t0, 3)
