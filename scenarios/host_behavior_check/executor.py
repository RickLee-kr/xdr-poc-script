"""Host behavior check executor — harmless commands on webshell host only."""

from __future__ import annotations

import shlex
import subprocess
import time
from datetime import datetime, timezone

from dsp.engine.scenario_engine import RunContext, TargetSet
from dsp.event_store import Event
from dsp.protocols.host.behavior import build_host_behavior_plan
from dsp.protocols.host.behavior_events import (
    build_eicar_file_accessed_event,
    build_eicar_file_created_event,
    build_eicar_file_deleted_event,
    build_host_behavior_check_completed_event,
    build_host_behavior_check_started_event,
    build_host_behavior_command_dispatched_event,
)


def _run_shell_command(shell: str, *, timeout: float) -> None:
    subprocess.run(
        ["sh", "-c", shell],
        capture_output=True,
        timeout=timeout,
        check=False,
    )


def _run_eicar_lifecycle(
    ctx: RunContext,
    *,
    scenario_id: str,
    target: str,
    source: str,
    path: str,
    content: str,
    mode: str,
    timeout: float,
) -> None:
    ctx.event_store.append(
        build_eicar_file_created_event(
            run_id=ctx.run_id,
            scenario_id=scenario_id,
            target=target,
            source=source,
            path=path,
        )
    )
    if mode == "live":
        quoted = shlex.quote(content)
        _run_shell_command(f"printf %s {quoted} > {shlex.quote(path)}", timeout=timeout)

    ctx.event_store.append(
        build_eicar_file_accessed_event(
            run_id=ctx.run_id,
            scenario_id=scenario_id,
            target=target,
            source=source,
            path=path,
        )
    )
    if mode == "live":
        subprocess.run(
            ["cat", path],
            capture_output=True,
            timeout=timeout,
            check=False,
        )

    ctx.event_store.append(
        build_eicar_file_deleted_event(
            run_id=ctx.run_id,
            scenario_id=scenario_id,
            target=target,
            source=source,
            path=path,
        )
    )
    if mode == "live":
        subprocess.run(
            ["rm", "-f", path],
            capture_output=True,
            timeout=timeout,
            check=False,
        )


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

    target = str(plan["target_host"])
    mode = str(plan.get("mode", "mock"))
    timeout = float(params.get("timeout", 30.0))
    commands = list(plan.get("commands") or [])
    eicar = dict(plan.get("eicar") or {})

    t0 = time.monotonic()
    ctx.event_store.append(
        build_host_behavior_check_started_event(
            run_id=ctx.run_id,
            scenario_id=scenario_id,
            target=target,
            source=source,
            evidence={
                "target_host": target,
                "commands_planned": len(commands),
                "mode": mode,
                "webshell_family": plan.get("webshell_family"),
            },
        )
    )

    for index, item in enumerate(commands, start=1):
        if ctx.cancelled:
            break
        name = str(item["name"])
        shell = str(item["shell"])
        ctx.event_store.append(
            build_host_behavior_command_dispatched_event(
                run_id=ctx.run_id,
                scenario_id=scenario_id,
                target=target,
                source=source,
                command_name=name,
                evidence={"seq": index, "shell": shell},
            )
        )
        if mode == "live":
            _run_shell_command(shell, timeout=timeout)

    if eicar.get("path") and eicar.get("content"):
        _run_eicar_lifecycle(
            ctx,
            scenario_id=scenario_id,
            target=target,
            source=source,
            path=str(eicar["path"]),
            content=str(eicar["content"]),
            mode=mode,
            timeout=timeout,
        )

    elapsed = round(time.monotonic() - t0, 3)
    ctx.event_store.append(
        build_host_behavior_check_completed_event(
            run_id=ctx.run_id,
            scenario_id=scenario_id,
            target=target,
            source=source,
            evidence={
                "target_host": target,
                "commands_dispatched": len(commands),
                "mode": mode,
                "duration_sec": elapsed,
            },
        )
    )
