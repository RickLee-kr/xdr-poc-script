"""Host behavior check scenario — EDR observation on webshell compromise host."""

from __future__ import annotations

import importlib.util
from datetime import datetime, timezone
from pathlib import Path

from dsp.engine.scenario_engine import RunContext, Scenario, ScenarioSummary, TargetSet
from dsp.event_store import Event, EventQuery
from dsp.protocols.host.behavior_events import HOST_BEHAVIOR_TRAFFIC_EVENTS


def _load_executor():
    path = Path(__file__).with_name("executor.py")
    spec = importlib.util.spec_from_file_location("host_behavior_check_executor", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class HostBehaviorCheckScenario(Scenario):
    @classmethod
    def scenario_id(cls) -> str:
        return "host_behavior_check"

    def prepare(self, ctx: RunContext, targets: TargetSet) -> None:
        mode = "mock" if ctx.dry_run else "live"
        ctx.event_store.append(
            Event(
                run_id=ctx.run_id,
                scenario_id=self.scenario_id(),
                timestamp=datetime.now(timezone.utc),
                stage="prepare",
                event="scenario_prepared",
                status="info",
                source="dry_run" if ctx.dry_run else "local",
                evidence={
                    "target_net": ctx.target_net,
                    "protocol": "host_behavior_check",
                    "mode": mode,
                },
            )
        )

    def execute(self, ctx: RunContext, targets: TargetSet) -> None:
        executor = _load_executor()
        params = dict(ctx.config.scenario_params.get("host_behavior_check", {}))
        executor.run(ctx, targets, params, scenario_id=self.scenario_id())

    def summarize(self, ctx: RunContext) -> ScenarioSummary:
        scenario_id = self.scenario_id()
        total = ctx.event_store.count(EventQuery(run_id=ctx.run_id, scenario_id=scenario_id))
        commands = ctx.event_store.count(
            EventQuery(
                run_id=ctx.run_id,
                scenario_id=scenario_id,
                event="host_behavior_command_dispatched",
                status="sent",
            )
        )
        eicar_created = ctx.event_store.count(
            EventQuery(
                run_id=ctx.run_id,
                scenario_id=scenario_id,
                event="eicar_create",
                status="info",
            )
        )
        mode = "mock" if ctx.dry_run else "live"
        return ScenarioSummary(
            scenario_id=scenario_id,
            metrics={
                "host_behavior_command_count": commands,
                "eicar_lifecycle_count": eicar_created,
                "total_events": total,
            },
            event_count=total,
            notes=[
                f"Host Behavior Check — mode={mode}, webshell host only",
                f"Traffic events: {', '.join(sorted(HOST_BEHAVIOR_TRAFFIC_EVENTS))}",
            ],
        )
