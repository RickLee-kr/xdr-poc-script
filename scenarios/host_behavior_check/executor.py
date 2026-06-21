"""Host behavior check executor — harmless commands on webshell host only."""

from __future__ import annotations

import shlex
import subprocess
import time
from datetime import datetime, timezone
from typing import Any, Callable

from dsp.engine.scenario_engine import RunContext, TargetSet
from dsp.event_store import Event
from dsp.protocols.host.behavior import build_host_behavior_plan
from dsp.protocols.host.behavior_observability import (
    append_command_executed_event,
    append_eicar_verification_event,
    append_host_behavior_summary_event,
    command_key_for_plan_name,
    command_label_for_plan_name,
    host_behavior_report_payload,
)
from dsp.protocols.host.behavior_events import (
    ARCHIVE_ACCESSED,
    ARCHIVE_CREATED,
    ARCHIVE_DELETED,
    EICAR_VARIANT_ACCESSED,
    EICAR_VARIANT_CREATED,
    EICAR_VARIANT_DELETED,
    PERSISTENCE_ARTIFACT_ACCESSED,
    PERSISTENCE_ARTIFACT_CREATED,
    PERSISTENCE_ARTIFACT_DELETED,
    SUSPICIOUS_SCRIPT_ACCESSED,
    SUSPICIOUS_SCRIPT_CREATED,
    SUSPICIOUS_SCRIPT_DELETED,
    build_host_behavior_check_completed_event,
    build_host_behavior_check_started_event,
    build_host_behavior_command_dispatched_event,
    build_lifecycle_event,
)


def _run_shell_command(shell: str, *, timeout: float) -> None:
    subprocess.run(
        ["sh", "-c", shell],
        capture_output=True,
        timeout=timeout,
        check=False,
    )


def _read_file(path: str, *, timeout: float) -> None:
    subprocess.run(
        ["cat", path],
        capture_output=True,
        timeout=timeout,
        check=False,
    )


def _delete_file(path: str, *, timeout: float) -> None:
    subprocess.run(
        ["rm", "-f", path],
        capture_output=True,
        timeout=timeout,
        check=False,
    )


def _write_plain_file(path: str, content: str, *, timeout: float) -> None:
    quoted = shlex.quote(content)
    _run_shell_command(f"printf %s {quoted} > {shlex.quote(path)}", timeout=timeout)


def _create_eicar_variant(path: str, item: dict[str, Any], *, timeout: float) -> None:
    content = str(item["content"])
    quoted = shlex.quote(content)
    kind = str(item.get("kind") or "plain")
    if kind == "plain":
        _write_plain_file(path, content, timeout=timeout)
        return
    if kind == "zip":
        inner = str(item.get("inner_name") or "eicar.txt")
        _run_shell_command(
            "tmpdir=$(mktemp -d) && "
            f"printf %s {quoted} > \"$tmpdir/{inner}\" && "
            f"zip -j {shlex.quote(path)} \"$tmpdir/{inner}\" && "
            "rm -rf \"$tmpdir\"",
            timeout=timeout,
        )
        return
    if kind == "nested_zip":
        inner = str(item.get("inner_name") or "eicar.txt")
        _run_shell_command(
            "tmpdir=$(mktemp -d) && "
            f"printf %s {quoted} > \"$tmpdir/{inner}\" && "
            f"cd \"$tmpdir\" && zip inner.zip {inner} && "
            f"zip -j {shlex.quote(path)} inner.zip && "
            "rm -rf \"$tmpdir\"",
            timeout=timeout,
        )


def _create_archive(path: str, item: dict[str, Any], *, timeout: float) -> None:
    kind = str(item.get("kind") or "tar_gz")
    if kind == "zip":
        _run_shell_command(
            "tmpdir=$(mktemp -d) && echo test > \"$tmpdir/sample.txt\" && "
            f"zip -j {shlex.quote(path)} \"$tmpdir/sample.txt\" && rm -rf \"$tmpdir\"",
            timeout=timeout,
        )
        return
    _run_shell_command(
        "tmpdir=$(mktemp -d) && echo test > \"$tmpdir/sample.txt\" && "
        f"tar czf {shlex.quote(path)} -C \"$tmpdir\" sample.txt && rm -rf \"$tmpdir\"",
        timeout=timeout,
    )


def _run_file_lifecycle(
    ctx: RunContext,
    *,
    scenario_id: str,
    target: str,
    source: str,
    path: str,
    mode: str,
    timeout: float,
    created_event: str,
    accessed_event: str,
    deleted_event: str,
    create_fn: Callable[[], None],
    evidence: dict[str, Any] | None = None,
) -> None:
    payload = {"path": path, **(evidence or {})}
    ctx.event_store.append(
        build_lifecycle_event(
            run_id=ctx.run_id,
            scenario_id=scenario_id,
            target=target,
            source=source,
            event=created_event,
            artifact=path,
            evidence=dict(payload),
        )
    )
    if mode == "live":
        create_fn()
    ctx.event_store.append(
        build_lifecycle_event(
            run_id=ctx.run_id,
            scenario_id=scenario_id,
            target=target,
            source=source,
            event=accessed_event,
            artifact=path,
            evidence=dict(payload),
        )
    )
    if mode == "live":
        _read_file(path, timeout=timeout)
    ctx.event_store.append(
        build_lifecycle_event(
            run_id=ctx.run_id,
            scenario_id=scenario_id,
            target=target,
            source=source,
            event=deleted_event,
            artifact=path,
            evidence=dict(payload),
        )
    )
    if mode == "live":
        _delete_file(path, timeout=timeout)


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
    if mode == "live":
        _write_plain_file(path, content, timeout=timeout)
    append_eicar_verification_event(
        ctx.event_store,
        run_id=ctx.run_id,
        phase="create",
        scenario_id=scenario_id,
        target=target,
        source=source,
        path=path,
    )
    ctx.event_store.append(
        build_lifecycle_event(
            run_id=ctx.run_id,
            scenario_id=scenario_id,
            target=target,
            source=source,
            event="eicar_file_created",
            artifact=path,
            evidence={"path": path},
        )
    )
    append_eicar_verification_event(
        ctx.event_store,
        run_id=ctx.run_id,
        phase="read",
        scenario_id=scenario_id,
        target=target,
        source=source,
        path=path,
    )
    ctx.event_store.append(
        build_lifecycle_event(
            run_id=ctx.run_id,
            scenario_id=scenario_id,
            target=target,
            source=source,
            event="eicar_file_accessed",
            artifact=path,
            evidence={"path": path},
        )
    )
    if mode == "live":
        _read_file(path, timeout=timeout)
    append_eicar_verification_event(
        ctx.event_store,
        run_id=ctx.run_id,
        phase="delete",
        scenario_id=scenario_id,
        target=target,
        source=source,
        path=path,
    )
    ctx.event_store.append(
        build_lifecycle_event(
            run_id=ctx.run_id,
            scenario_id=scenario_id,
            target=target,
            source=source,
            event="eicar_file_deleted",
            artifact=path,
            evidence={"path": path},
        )
    )
    if mode == "live":
        _delete_file(path, timeout=timeout)


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
    credential_checks = list(plan.get("credential_checks") or [])
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
                "credential_checks_planned": len(credential_checks),
                "eicar_variants_planned": len(plan.get("eicar_variants") or []),
                "suspicious_scripts_planned": len(plan.get("suspicious_scripts") or []),
                "persistence_artifacts_planned": len(
                    plan.get("persistence_artifacts") or []
                ),
                "archives_planned": len(plan.get("archives") or []),
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
        append_command_executed_event(
            ctx.event_store,
            run_id=ctx.run_id,
            scenario_id=scenario_id,
            command=command_label_for_plan_name(name),
            command_key=command_key_for_plan_name(name),
            target=target,
            source=source,
        )
        if mode == "live":
            _run_shell_command(shell, timeout=timeout)

    for index, item in enumerate(credential_checks, start=1):
        if ctx.cancelled:
            break
        event_name = str(item["event"])
        name = str(item["name"])
        shell = str(item["shell"])
        ctx.event_store.append(
            build_lifecycle_event(
                run_id=ctx.run_id,
                scenario_id=scenario_id,
                target=target,
                source=source,
                event=event_name,
                artifact=name,
                evidence={"seq": index, "shell": shell, "check": name},
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

    for variant in plan.get("eicar_variants") or []:
        if ctx.cancelled:
            break
        path = str(variant["path"])
        _run_file_lifecycle(
            ctx,
            scenario_id=scenario_id,
            target=target,
            source=source,
            path=path,
            mode=mode,
            timeout=timeout,
            created_event=EICAR_VARIANT_CREATED,
            accessed_event=EICAR_VARIANT_ACCESSED,
            deleted_event=EICAR_VARIANT_DELETED,
            create_fn=lambda v=variant, p=path: _create_eicar_variant(
                p, v, timeout=timeout
            ),
            evidence={"variant": str(variant.get("variant") or ""), "kind": variant.get("kind")},
        )

    for script in plan.get("suspicious_scripts") or []:
        if ctx.cancelled:
            break
        path = str(script["path"])
        content = str(script["content"])
        _run_file_lifecycle(
            ctx,
            scenario_id=scenario_id,
            target=target,
            source=source,
            path=path,
            mode=mode,
            timeout=timeout,
            created_event=SUSPICIOUS_SCRIPT_CREATED,
            accessed_event=SUSPICIOUS_SCRIPT_ACCESSED,
            deleted_event=SUSPICIOUS_SCRIPT_DELETED,
            create_fn=lambda p=path, c=content: _write_plain_file(
                p, c, timeout=timeout
            ),
            evidence={"name": str(script.get("name") or "")},
        )

    for artifact in plan.get("persistence_artifacts") or []:
        if ctx.cancelled:
            break
        path = str(artifact["path"])
        content = str(artifact["content"])
        _run_file_lifecycle(
            ctx,
            scenario_id=scenario_id,
            target=target,
            source=source,
            path=path,
            mode=mode,
            timeout=timeout,
            created_event=PERSISTENCE_ARTIFACT_CREATED,
            accessed_event=PERSISTENCE_ARTIFACT_ACCESSED,
            deleted_event=PERSISTENCE_ARTIFACT_DELETED,
            create_fn=lambda p=path, c=content: _write_plain_file(
                p, c, timeout=timeout
            ),
            evidence={"name": str(artifact.get("name") or "")},
        )

    for archive in plan.get("archives") or []:
        if ctx.cancelled:
            break
        path = str(archive["path"])
        _run_file_lifecycle(
            ctx,
            scenario_id=scenario_id,
            target=target,
            source=source,
            path=path,
            mode=mode,
            timeout=timeout,
            created_event=ARCHIVE_CREATED,
            accessed_event=ARCHIVE_ACCESSED,
            deleted_event=ARCHIVE_DELETED,
            create_fn=lambda a=archive, p=path: _create_archive(p, a, timeout=timeout),
            evidence={"name": str(archive.get("name") or ""), "kind": archive.get("kind")},
        )

    elapsed = round(time.monotonic() - t0, 3)
    checklist = append_host_behavior_summary_event(
        ctx.event_store,
        run_id=ctx.run_id,
        scenario_id=scenario_id,
        target=target,
        source=source,
    )
    ctx.event_store.append(
        build_host_behavior_check_completed_event(
            run_id=ctx.run_id,
            scenario_id=scenario_id,
            target=target,
            source=source,
            evidence={
                "target_host": target,
                "commands_dispatched": len(commands),
                "credential_checks_dispatched": len(credential_checks),
                "mode": mode,
                "duration_sec": elapsed,
                "host_behavior": host_behavior_report_payload(checklist),
            },
        )
    )
