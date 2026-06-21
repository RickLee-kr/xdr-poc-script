"""Host behavior check observability — verification events and run summaries."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Iterable

from dsp.event_store import Event, EventStore


def _now() -> datetime:
    return datetime.now(timezone.utc)

HOST_BEHAVIOR_SCENARIO_ID = "host_behavior_check"

COMMAND_EXECUTED = "command_executed"
EICAR_CREATE = "eicar_create"
EICAR_READ = "eicar_read"
EICAR_COPY = "eicar_copy"
EICAR_MOVE = "eicar_move"
EICAR_ARCHIVE = "eicar_archive"
EICAR_ENCODE = "eicar_encode"
EICAR_DECODE = "eicar_decode"
EICAR_DELETE = "eicar_delete"
ENCODED_FILE_CREATE = "encoded_file_create"
ENCODED_FILE_DECODE = "encoded_file_decode"
HOST_BEHAVIOR_SUMMARY_EVENT = "host_behavior_summary"

EICAR_CHECKLIST_KEYS: tuple[str, ...] = (
    "eicar_create",
    "eicar_read",
    "eicar_copy",
    "eicar_move",
    "eicar_archive",
    "eicar_encode",
    "eicar_decode",
    "eicar_delete",
)

EICAR_EVENT_TO_CHECKLIST_KEY: dict[str, str] = {
    EICAR_CREATE: "eicar_create",
    EICAR_READ: "eicar_read",
    EICAR_COPY: "eicar_copy",
    EICAR_MOVE: "eicar_move",
    EICAR_ARCHIVE: "eicar_archive",
    EICAR_ENCODE: "eicar_encode",
    EICAR_DECODE: "eicar_decode",
    EICAR_DELETE: "eicar_delete",
    # Legacy lifecycle names (variants / older runs)
    "eicar_created": "eicar_create",
    "eicar_file_created": "eicar_create",
    "eicar_variant_created": "eicar_create",
    "eicar_read_legacy": "eicar_read",
    "eicar_file_accessed": "eicar_read",
    "eicar_variant_accessed": "eicar_read",
    "eicar_deleted": "eicar_delete",
    "eicar_file_deleted": "eicar_delete",
    "eicar_variant_deleted": "eicar_delete",
}

# Internal command plan names → checklist / report keys
COMMAND_NAME_TO_KEY: dict[str, str] = {
    "whoami": "whoami",
    "id": "id",
    "hostname": "hostname",
    "uname": "uname",
    "ip_addr": "ip_addr",
    "ip_route": "ip_route",
    "passwd": "passwd_read",
    "base64_decode": "base64_exec",
}

# Display labels for console output (grouped sections)
CHECKLIST_SECTIONS: tuple[tuple[str, tuple[tuple[str, str], ...]], ...] = (
    (
        "Recon Commands",
        (
            ("whoami", "whoami"),
            ("id", "id"),
            ("hostname", "hostname"),
            ("uname", "uname"),
        ),
    ),
    (
        "Network Commands",
        (
            ("ip_addr", "ip addr"),
            ("ip_route", "ip route"),
        ),
    ),
    (
        "Credential Access",
        (("passwd_read", "/etc/passwd"),),
    ),
    (
        "Encoded Commands",
        (("base64_exec", "base64_exec"),),
    ),
    (
        "EICAR",
        (
            ("eicar_create", "create"),
            ("eicar_read", "read"),
            ("eicar_copy", "copy"),
            ("eicar_move", "move"),
            ("eicar_archive", "archive"),
            ("eicar_encode", "encode"),
            ("eicar_decode", "decode"),
            ("eicar_delete", "delete"),
        ),
    ),
)

ALL_CHECKLIST_KEYS: frozenset[str] = frozenset(
    key for _section, items in CHECKLIST_SECTIONS for key, _label in items
)


@dataclass(frozen=True)
class HostBehaviorChecklist:
    """Boolean checklist derived from Event Store verification events."""

    whoami: bool = False
    id: bool = False
    hostname: bool = False
    uname: bool = False
    ip_addr: bool = False
    ip_route: bool = False
    passwd_read: bool = False
    base64_exec: bool = False
    eicar_create: bool = False
    eicar_read: bool = False
    eicar_copy: bool = False
    eicar_move: bool = False
    eicar_archive: bool = False
    eicar_encode: bool = False
    eicar_decode: bool = False
    eicar_delete: bool = False

    def to_dict(self) -> dict[str, bool]:
        return {key: bool(getattr(self, key)) for key in sorted(ALL_CHECKLIST_KEYS)}

    def missing_keys(self) -> list[str]:
        return [key for key in sorted(ALL_CHECKLIST_KEYS) if not getattr(self, key)]


def command_key_for_plan_name(name: str) -> str:
    return COMMAND_NAME_TO_KEY.get(name, name)


def command_label_for_plan_name(name: str) -> str:
    key = command_key_for_plan_name(name)
    for _section, items in CHECKLIST_SECTIONS:
        for item_key, label in items:
            if item_key == key:
                return label
    return name


def append_command_executed_event(
    store: EventStore,
    *,
    run_id: str,
    scenario_id: str = HOST_BEHAVIOR_SCENARIO_ID,
    command: str,
    command_key: str,
    target: str = "",
    source: str = "local",
    dispatch_status: str = "sent",
    stage: str = "executor",
) -> None:
    store.append(
        Event(
            run_id=run_id,
            scenario_id=scenario_id,
            timestamp=_now(),
            stage=stage,
            event=COMMAND_EXECUTED,
            status="info",
            target=target,
            artifact=command_key,
            evidence={
                "command": command,
                "command_key": command_key,
                "dispatch_status": dispatch_status,
            },
            source=source,
        )
    )


def append_eicar_lifecycle_event(
    store: EventStore,
    *,
    run_id: str,
    event: str,
    scenario_id: str = HOST_BEHAVIOR_SCENARIO_ID,
    target: str = "",
    source: str = "local",
    artifact: str = "",
    shell: str = "",
    stage: str = "executor",
) -> None:
    store.append(
        Event(
            run_id=run_id,
            scenario_id=scenario_id,
            timestamp=_now(),
            stage=stage,
            event=event,
            status="info",
            target=target,
            artifact=artifact or event,
            evidence={"shell": shell, "artifact": artifact},
            source=source,
        )
    )


def append_eicar_verification_event(
    store: EventStore,
    *,
    run_id: str,
    phase: str,
    scenario_id: str = HOST_BEHAVIOR_SCENARIO_ID,
    target: str = "",
    source: str = "local",
    path: str = "",
    stage: str = "executor",
) -> None:
    """Legacy helper — maps create/read/delete phases to lifecycle event names."""
    event_map = {
        "create": EICAR_CREATE,
        "read": EICAR_READ,
        "delete": EICAR_DELETE,
    }
    event_name = event_map.get(phase)
    if not event_name:
        return
    append_eicar_lifecycle_event(
        store,
        run_id=run_id,
        event=event_name,
        scenario_id=scenario_id,
        target=target,
        source=source,
        artifact=path or f"eicar_{phase}",
        stage=stage,
    )


def build_host_behavior_checklist(
    store: EventStore,
    run_id: str,
    scenario_id: str = HOST_BEHAVIOR_SCENARIO_ID,
) -> HostBehaviorChecklist:
    """Build execution checklist from verification events in the Event Store."""
    events = store.list_events(run_id, scenario_id)
    executed_keys: set[str] = set()
    eicar_flags = {key: False for key in EICAR_CHECKLIST_KEYS}

    for event in events:
        name = str(event.event)
        evidence = dict(event.evidence or {})

        if name == COMMAND_EXECUTED:
            key = str(evidence.get("command_key") or "")
            if key:
                executed_keys.add(key)
            continue

        checklist_key = EICAR_EVENT_TO_CHECKLIST_KEY.get(name)
        if checklist_key:
            eicar_flags[checklist_key] = True

        if name == "host_behavior_command_dispatched":
            plan_name = str(evidence.get("command") or evidence.get("command_name") or "")
            if plan_name:
                executed_keys.add(command_key_for_plan_name(plan_name))

    return HostBehaviorChecklist(
        whoami="whoami" in executed_keys,
        id="id" in executed_keys,
        hostname="hostname" in executed_keys,
        uname="uname" in executed_keys,
        ip_addr="ip_addr" in executed_keys,
        ip_route="ip_route" in executed_keys,
        passwd_read="passwd_read" in executed_keys,
        base64_exec="base64_exec" in executed_keys,
        **eicar_flags,
    )


def append_host_behavior_summary_event(
    store: EventStore,
    *,
    run_id: str,
    scenario_id: str = HOST_BEHAVIOR_SCENARIO_ID,
    target: str = "",
    source: str = "local",
    stage: str = "executor",
) -> HostBehaviorChecklist:
    checklist = build_host_behavior_checklist(store, run_id, scenario_id)
    store.append(
        Event(
            run_id=run_id,
            scenario_id=scenario_id,
            timestamp=_now(),
            stage=stage,
            event=HOST_BEHAVIOR_SUMMARY_EVENT,
            status="info",
            target=target,
            artifact="host_behavior_checklist",
            evidence={"host_behavior": checklist.to_dict()},
            source=source,
        )
    )
    return checklist


def format_host_behavior_summary_lines(
    checklist: HostBehaviorChecklist | dict[str, bool],
) -> list[str]:
    """Format grouped Host Behavior Summary lines for console or report output."""
    if isinstance(checklist, HostBehaviorChecklist):
        values = checklist.to_dict()
    else:
        values = dict(checklist)

    lines = ["Host Behavior Summary", ""]
    for section, items in CHECKLIST_SECTIONS:
        lines.append(f"{section}:")
        for key, label in items:
            status = "OK" if values.get(key) else "MISSING"
            lines.append(f"  {label:<14}  {status}")
        lines.append("")
    if lines and lines[-1] == "":
        lines.pop()
    return lines


def missing_items_for_validation(
    checklist: HostBehaviorChecklist,
    *,
    metrics: dict[str, int | float | str | bool] | None = None,
) -> list[str]:
    """Return human-readable missing checklist keys for validation output."""
    _ = metrics
    return checklist.missing_keys()


def host_behavior_report_payload(
    checklist: HostBehaviorChecklist,
) -> dict[str, bool]:
    """Compact host_behavior block for report.json / traffic_summary.json."""
    return dict(checklist.to_dict())


def iter_host_behavior_events(
    store: EventStore,
    run_id: str,
    scenario_id: str = HOST_BEHAVIOR_SCENARIO_ID,
) -> Iterable[Event]:
    verification_events = {
        COMMAND_EXECUTED,
        EICAR_CREATE,
        EICAR_READ,
        EICAR_COPY,
        EICAR_MOVE,
        EICAR_ARCHIVE,
        EICAR_ENCODE,
        EICAR_DECODE,
        EICAR_DELETE,
        ENCODED_FILE_CREATE,
        ENCODED_FILE_DECODE,
        HOST_BEHAVIOR_SUMMARY_EVENT,
    }
    for event in store.list_events(run_id, scenario_id):
        if event.event in verification_events:
            yield event


def count_verification_events(
    store: EventStore,
    run_id: str,
    scenario_id: str = HOST_BEHAVIOR_SCENARIO_ID,
) -> dict[str, int]:
    counts = {
        COMMAND_EXECUTED: 0,
        EICAR_CREATE: 0,
        EICAR_READ: 0,
        EICAR_COPY: 0,
        EICAR_MOVE: 0,
        EICAR_ARCHIVE: 0,
        EICAR_ENCODE: 0,
        EICAR_DECODE: 0,
        EICAR_DELETE: 0,
        ENCODED_FILE_CREATE: 0,
        ENCODED_FILE_DECODE: 0,
    }
    for event in iter_host_behavior_events(store, run_id, scenario_id):
        if event.event in counts:
            counts[str(event.event)] += 1
    return counts
