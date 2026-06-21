"""Shared host behavior check execution — local, webshell, and remote bundle."""

from __future__ import annotations

import shlex
import subprocess
from typing import Any, Callable

from dsp.event_store import EventStore
from dsp.protocols.host.behavior_observability import (
    append_command_executed_event,
    append_eicar_lifecycle_event,
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


def run_shell_command(shell: str, *, timeout: float) -> None:
    subprocess.run(
        ["sh", "-c", shell],
        capture_output=True,
        timeout=timeout,
        check=False,
    )


def read_file(path: str, *, timeout: float) -> None:
    subprocess.run(
        ["cat", path],
        capture_output=True,
        timeout=timeout,
        check=False,
    )


def delete_file(path: str, *, timeout: float) -> None:
    subprocess.run(
        ["rm", "-f", path],
        capture_output=True,
        timeout=timeout,
        check=False,
    )


def write_plain_file(path: str, content: str, *, timeout: float) -> None:
    quoted = shlex.quote(content)
    run_shell_command(f"printf %s {quoted} > {shlex.quote(path)}", timeout=timeout)


def create_eicar_variant(path: str, item: dict[str, Any], *, timeout: float) -> None:
    content = str(item["content"])
    quoted = shlex.quote(content)
    kind = str(item.get("kind") or "plain")
    if kind == "plain":
        write_plain_file(path, content, timeout=timeout)
        return
    if kind == "zip":
        inner = str(item.get("inner_name") or "eicar.txt")
        run_shell_command(
            "tmpdir=$(mktemp -d) && "
            f"printf %s {quoted} > \"$tmpdir/{inner}\" && "
            f"zip -j {shlex.quote(path)} \"$tmpdir/{inner}\" && "
            "rm -rf \"$tmpdir\"",
            timeout=timeout,
        )
        return
    if kind == "nested_zip":
        inner = str(item.get("inner_name") or "eicar.txt")
        run_shell_command(
            "tmpdir=$(mktemp -d) && "
            f"printf %s {quoted} > \"$tmpdir/{inner}\" && "
            f"cd \"$tmpdir\" && zip inner.zip {inner} && "
            f"zip -j {shlex.quote(path)} inner.zip && "
            "rm -rf \"$tmpdir\"",
            timeout=timeout,
        )


def create_archive(path: str, item: dict[str, Any], *, timeout: float) -> None:
    kind = str(item.get("kind") or "tar_gz")
    if kind == "zip":
        run_shell_command(
            "tmpdir=$(mktemp -d) && echo test > \"$tmpdir/sample.txt\" && "
            f"zip -j {shlex.quote(path)} \"$tmpdir/sample.txt\" && rm -rf \"$tmpdir\"",
            timeout=timeout,
        )
        return
    run_shell_command(
        "tmpdir=$(mktemp -d) && echo test > \"$tmpdir/sample.txt\" && "
        f"tar czf {shlex.quote(path)} -C \"$tmpdir\" sample.txt && rm -rf \"$tmpdir\"",
        timeout=timeout,
    )


def run_file_lifecycle(
    store: EventStore,
    *,
    run_id: str,
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
    run_shell: Callable[[str], None] | None = None,
) -> None:
    payload = {"path": path, **(evidence or {})}
    shell_runner = run_shell if run_shell is not None else (
        lambda shell: run_shell_command(shell, timeout=timeout)
    )
    store.append(
        build_lifecycle_event(
            run_id=run_id,
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
    store.append(
        build_lifecycle_event(
            run_id=run_id,
            scenario_id=scenario_id,
            target=target,
            source=source,
            event=accessed_event,
            artifact=path,
            evidence=dict(payload),
        )
    )
    if mode == "live":
        read_file(path, timeout=timeout)
    store.append(
        build_lifecycle_event(
            run_id=run_id,
            scenario_id=scenario_id,
            target=target,
            source=source,
            event=deleted_event,
            artifact=path,
            evidence=dict(payload),
        )
    )
    if mode == "live":
        delete_file(path, timeout=timeout)


def run_planned_lifecycle_steps(
    store: EventStore,
    *,
    run_id: str,
    scenario_id: str,
    target: str,
    source: str,
    mode: str,
    steps: list[dict[str, str]],
    run_shell: Callable[[str], None] | None = None,
    timeout: float = 30.0,
) -> None:
    shell_runner = run_shell if run_shell is not None else (
        lambda shell: run_shell_command(shell, timeout=timeout)
    )
    for step in steps:
        event_name = str(step["event"])
        shell = str(step["shell"])
        artifact = str(step.get("artifact") or event_name)
        append_eicar_lifecycle_event(
            store,
            run_id=run_id,
            event=event_name,
            scenario_id=scenario_id,
            target=target,
            source=source,
            artifact=artifact,
            shell=shell,
        )
        if mode == "live":
            shell_runner(shell)


def execute_host_behavior_plan(
    store: EventStore,
    plan: dict[str, Any],
    *,
    run_id: str,
    scenario_id: str = "host_behavior_check",
    source: str = "local",
    cancelled: Callable[[], bool] | None = None,
    run_shell: Callable[[str], None] | None = None,
    timeout: float = 30.0,
) -> dict[str, Any]:
    """Execute a host behavior plan and append Event Store evidence."""
    is_cancelled = cancelled or (lambda: False)
    target = str(plan["target_host"])
    mode = str(plan.get("mode", "mock"))
    commands = list(plan.get("commands") or [])
    credential_checks = list(plan.get("credential_checks") or [])
    eicar_lifecycle = list(plan.get("eicar_lifecycle") or [])
    encoded_file_activity = list(plan.get("encoded_file_activity") or [])

    store.append(
        build_host_behavior_check_started_event(
            run_id=run_id,
            scenario_id=scenario_id,
            target=target,
            source=source,
            evidence={
                "target_host": target,
                "commands_planned": len(commands),
                "credential_checks_planned": len(credential_checks),
                "eicar_lifecycle_planned": len(eicar_lifecycle),
                "encoded_file_activity_planned": len(encoded_file_activity),
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

    shell_runner = run_shell if run_shell is not None else (
        lambda shell: run_shell_command(shell, timeout=timeout)
    )

    for index, item in enumerate(commands, start=1):
        if is_cancelled():
            break
        name = str(item["name"])
        shell = str(item["shell"])
        store.append(
            build_host_behavior_command_dispatched_event(
                run_id=run_id,
                scenario_id=scenario_id,
                target=target,
                source=source,
                command_name=name,
                evidence={"seq": index, "shell": shell},
            )
        )
        append_command_executed_event(
            store,
            run_id=run_id,
            scenario_id=scenario_id,
            command=command_label_for_plan_name(name),
            command_key=command_key_for_plan_name(name),
            target=target,
            source=source,
        )
        if mode == "live":
            shell_runner(shell)

    for index, item in enumerate(credential_checks, start=1):
        if is_cancelled():
            break
        event_name = str(item["event"])
        name = str(item["name"])
        shell = str(item["shell"])
        store.append(
            build_lifecycle_event(
                run_id=run_id,
                scenario_id=scenario_id,
                target=target,
                source=source,
                event=event_name,
                artifact=name,
                evidence={"seq": index, "shell": shell, "check": name},
            )
        )
        if mode == "live":
            shell_runner(shell)

    if eicar_lifecycle and not is_cancelled():
        run_planned_lifecycle_steps(
            store,
            run_id=run_id,
            scenario_id=scenario_id,
            target=target,
            source=source,
            mode=mode,
            steps=eicar_lifecycle,
            run_shell=run_shell,
            timeout=timeout,
        )

    if encoded_file_activity and not is_cancelled():
        run_planned_lifecycle_steps(
            store,
            run_id=run_id,
            scenario_id=scenario_id,
            target=target,
            source=source,
            mode=mode,
            steps=encoded_file_activity,
            run_shell=run_shell,
            timeout=timeout,
        )

    for variant in plan.get("eicar_variants") or []:
        if is_cancelled():
            break
        path = str(variant["path"])
        run_file_lifecycle(
            store,
            run_id=run_id,
            scenario_id=scenario_id,
            target=target,
            source=source,
            path=path,
            mode=mode,
            timeout=timeout,
            created_event=EICAR_VARIANT_CREATED,
            accessed_event=EICAR_VARIANT_ACCESSED,
            deleted_event=EICAR_VARIANT_DELETED,
            create_fn=lambda v=variant, p=path: create_eicar_variant(p, v, timeout=timeout),
            evidence={"variant": str(variant.get("variant") or ""), "kind": variant.get("kind")},
            run_shell=run_shell,
        )

    for script in plan.get("suspicious_scripts") or []:
        if is_cancelled():
            break
        path = str(script["path"])
        content = str(script["content"])
        run_file_lifecycle(
            store,
            run_id=run_id,
            scenario_id=scenario_id,
            target=target,
            source=source,
            path=path,
            mode=mode,
            timeout=timeout,
            created_event=SUSPICIOUS_SCRIPT_CREATED,
            accessed_event=SUSPICIOUS_SCRIPT_ACCESSED,
            deleted_event=SUSPICIOUS_SCRIPT_DELETED,
            create_fn=lambda p=path, c=content: write_plain_file(p, c, timeout=timeout),
            evidence={"name": str(script.get("name") or "")},
            run_shell=run_shell,
        )

    for artifact in plan.get("persistence_artifacts") or []:
        if is_cancelled():
            break
        path = str(artifact["path"])
        content = str(artifact["content"])
        run_file_lifecycle(
            store,
            run_id=run_id,
            scenario_id=scenario_id,
            target=target,
            source=source,
            path=path,
            mode=mode,
            timeout=timeout,
            created_event=PERSISTENCE_ARTIFACT_CREATED,
            accessed_event=PERSISTENCE_ARTIFACT_ACCESSED,
            deleted_event=PERSISTENCE_ARTIFACT_DELETED,
            create_fn=lambda p=path, c=content: write_plain_file(p, c, timeout=timeout),
            evidence={"name": str(artifact.get("name") or "")},
            run_shell=run_shell,
        )

    for archive in plan.get("archives") or []:
        if is_cancelled():
            break
        path = str(archive["path"])
        run_file_lifecycle(
            store,
            run_id=run_id,
            scenario_id=scenario_id,
            target=target,
            source=source,
            path=path,
            mode=mode,
            timeout=timeout,
            created_event=ARCHIVE_CREATED,
            accessed_event=ARCHIVE_ACCESSED,
            deleted_event=ARCHIVE_DELETED,
            create_fn=lambda a=archive, p=path: create_archive(p, a, timeout=timeout),
            evidence={"name": str(archive.get("name") or ""), "kind": archive.get("kind")},
            run_shell=run_shell,
        )

    checklist = append_host_behavior_summary_event(
        store,
        run_id=run_id,
        scenario_id=scenario_id,
        target=target,
        source=source,
    )
    completed_evidence = {
        "target_host": target,
        "commands_dispatched": len(commands),
        "credential_checks_dispatched": len(credential_checks),
        "eicar_lifecycle_dispatched": len(eicar_lifecycle),
        "encoded_file_activity_dispatched": len(encoded_file_activity),
        "mode": mode,
        "host_behavior": host_behavior_report_payload(checklist),
    }
    store.append(
        build_host_behavior_check_completed_event(
            run_id=run_id,
            scenario_id=scenario_id,
            target=target,
            source=source,
            evidence=completed_evidence,
        )
    )
    return completed_evidence
