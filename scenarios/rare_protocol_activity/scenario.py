"""Rare protocol activity scenario — uncommon application traffic generation."""

from __future__ import annotations

import importlib.util
from datetime import datetime, timezone
from pathlib import Path

from dsp.engine.scenario_engine import RunContext, Scenario, ScenarioSummary, TargetSet
from dsp.event_store import Event, EventQuery
from dsp.protocols.rare.events import RARE_PROTOCOL_TRAFFIC_EVENTS


def _load_executor():
    path = Path(__file__).with_name("executor.py")
    spec = importlib.util.spec_from_file_location("rare_protocol_activity_executor", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class RareProtocolActivityScenario(Scenario):
    @classmethod
    def scenario_id(cls) -> str:
        return "rare_protocol_activity"

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
                    "protocols": ["TELNET", "RTSP", "SIP", "RTP"],
                    "mode": mode,
                    "safe_mode": True,
                },
            )
        )

    def execute(self, ctx: RunContext, targets: TargetSet) -> None:
        executor = _load_executor()
        params = dict(ctx.config.scenario_params.get("rare_protocol_activity", {}))
        executor.run(ctx, targets, params, scenario_id=self.scenario_id())

    def summarize(self, ctx: RunContext) -> ScenarioSummary:
        scenario_id = self.scenario_id()
        total = ctx.event_store.count(EventQuery(run_id=ctx.run_id, scenario_id=scenario_id))
        attempts = ctx.event_store.count(
            EventQuery(
                run_id=ctx.run_id,
                scenario_id=scenario_id,
                event="rare_protocol_probe_attempt",
                status="sent",
            )
        )
        success = ctx.event_store.count(
            EventQuery(
                run_id=ctx.run_id,
                scenario_id=scenario_id,
                event="rare_protocol_probe_success",
                status="sent",
            )
        )
        failures = ctx.event_store.count(
            EventQuery(
                run_id=ctx.run_id,
                scenario_id=scenario_id,
                event="rare_protocol_probe_failure",
            )
        )

        protocols: list[str] = []
        for ev in ctx.event_store.list_events(ctx.run_id, scenario_id):
            if ev.event == "rare_protocol_activity_completed":
                protocols = list(ev.evidence.get("protocols", []))

        mode = "mock" if ctx.dry_run else "live"
        return ScenarioSummary(
            scenario_id=scenario_id,
            metrics={
                "rare_protocol_probe_attempt_count": attempts,
                "rare_protocol_probe_success_count": success,
                "rare_protocol_probe_failure_count": failures,
                "total_events": total,
            },
            event_count=total,
            notes=[
                f"Rare Protocol Activity — mode={mode}, safe_mode=true",
                f"Traffic events: {', '.join(sorted(RARE_PROTOCOL_TRAFFIC_EVENTS))}",
                f"protocols={','.join(protocols)}",
            ],
        )
