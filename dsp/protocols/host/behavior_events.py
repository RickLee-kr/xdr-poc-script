"""Host behavior check event builders."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from dsp.event_store import Event

HOST_BEHAVIOR_CHECK_STARTED = "host_behavior_check_started"
HOST_BEHAVIOR_COMMAND_DISPATCHED = "host_behavior_command_dispatched"
EICAR_FILE_CREATED = "eicar_file_created"
EICAR_FILE_ACCESSED = "eicar_file_accessed"
EICAR_FILE_DELETED = "eicar_file_deleted"
HOST_BEHAVIOR_CHECK_COMPLETED = "host_behavior_check_completed"

HOST_BEHAVIOR_TRAFFIC_EVENTS = frozenset(
    {
        HOST_BEHAVIOR_COMMAND_DISPATCHED,
        EICAR_FILE_CREATED,
        EICAR_FILE_ACCESSED,
        EICAR_FILE_DELETED,
    }
)


def _event(
    *,
    run_id: str,
    scenario_id: str,
    event: str,
    status: str,
    target: str,
    source: str,
    artifact: str = "",
    evidence: dict[str, Any] | None = None,
) -> Event:
    return Event(
        run_id=run_id,
        scenario_id=scenario_id,
        timestamp=datetime.now(timezone.utc),
        stage="executor",
        event=event,
        status=status,
        target=target,
        artifact=artifact,
        evidence=dict(evidence or {}),
        source=source,
    )


def build_host_behavior_check_started_event(
    *,
    run_id: str,
    scenario_id: str,
    target: str,
    source: str,
    evidence: dict[str, Any],
) -> Event:
    return _event(
        run_id=run_id,
        scenario_id=scenario_id,
        event=HOST_BEHAVIOR_CHECK_STARTED,
        status="info",
        target=target,
        source=source,
        artifact="host_behavior_session",
        evidence=evidence,
    )


def build_host_behavior_command_dispatched_event(
    *,
    run_id: str,
    scenario_id: str,
    target: str,
    source: str,
    command_name: str,
    evidence: dict[str, Any] | None = None,
) -> Event:
    payload = {"command": command_name}
    if evidence:
        payload.update(evidence)
    return _event(
        run_id=run_id,
        scenario_id=scenario_id,
        event=HOST_BEHAVIOR_COMMAND_DISPATCHED,
        status="sent",
        target=target,
        source=source,
        artifact=command_name,
        evidence=payload,
    )


def build_eicar_file_created_event(
    *,
    run_id: str,
    scenario_id: str,
    target: str,
    source: str,
    path: str,
) -> Event:
    return _event(
        run_id=run_id,
        scenario_id=scenario_id,
        event=EICAR_FILE_CREATED,
        status="info",
        target=target,
        source=source,
        artifact=path,
        evidence={"path": path},
    )


def build_eicar_file_accessed_event(
    *,
    run_id: str,
    scenario_id: str,
    target: str,
    source: str,
    path: str,
) -> Event:
    return _event(
        run_id=run_id,
        scenario_id=scenario_id,
        event=EICAR_FILE_ACCESSED,
        status="info",
        target=target,
        source=source,
        artifact=path,
        evidence={"path": path},
    )


def build_eicar_file_deleted_event(
    *,
    run_id: str,
    scenario_id: str,
    target: str,
    source: str,
    path: str,
) -> Event:
    return _event(
        run_id=run_id,
        scenario_id=scenario_id,
        event=EICAR_FILE_DELETED,
        status="info",
        target=target,
        source=source,
        artifact=path,
        evidence={"path": path},
    )


def build_host_behavior_check_completed_event(
    *,
    run_id: str,
    scenario_id: str,
    target: str,
    source: str,
    evidence: dict[str, Any],
) -> Event:
    return _event(
        run_id=run_id,
        scenario_id=scenario_id,
        event=HOST_BEHAVIOR_CHECK_COMPLETED,
        status="info",
        target=target,
        source=source,
        artifact="host_behavior_session",
        evidence=evidence,
    )
