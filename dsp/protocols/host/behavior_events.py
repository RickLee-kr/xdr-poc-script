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
EICAR_VARIANT_CREATED = "eicar_variant_created"
EICAR_VARIANT_ACCESSED = "eicar_variant_accessed"
EICAR_VARIANT_DELETED = "eicar_variant_deleted"
CREDENTIAL_ARTIFACT_ENUMERATION = "credential_artifact_enumeration"
SSH_KEY_ENUMERATION = "ssh_key_enumeration"
PEM_FILE_ENUMERATION = "pem_file_enumeration"
SUSPICIOUS_SCRIPT_CREATED = "suspicious_script_created"
SUSPICIOUS_SCRIPT_ACCESSED = "suspicious_script_accessed"
SUSPICIOUS_SCRIPT_DELETED = "suspicious_script_deleted"
PERSISTENCE_ARTIFACT_CREATED = "persistence_artifact_created"
PERSISTENCE_ARTIFACT_ACCESSED = "persistence_artifact_accessed"
PERSISTENCE_ARTIFACT_DELETED = "persistence_artifact_deleted"
ARCHIVE_CREATED = "archive_created"
ARCHIVE_ACCESSED = "archive_accessed"
ARCHIVE_DELETED = "archive_deleted"
HOST_BEHAVIOR_CHECK_COMPLETED = "host_behavior_check_completed"

HOST_BEHAVIOR_TRAFFIC_EVENTS = frozenset(
    {
        HOST_BEHAVIOR_COMMAND_DISPATCHED,
        EICAR_FILE_CREATED,
        EICAR_FILE_ACCESSED,
        EICAR_FILE_DELETED,
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
        EICAR_VARIANT_CREATED,
        EICAR_VARIANT_ACCESSED,
        EICAR_VARIANT_DELETED,
        CREDENTIAL_ARTIFACT_ENUMERATION,
        SSH_KEY_ENUMERATION,
        PEM_FILE_ENUMERATION,
        SUSPICIOUS_SCRIPT_CREATED,
        SUSPICIOUS_SCRIPT_ACCESSED,
        SUSPICIOUS_SCRIPT_DELETED,
        PERSISTENCE_ARTIFACT_CREATED,
        PERSISTENCE_ARTIFACT_ACCESSED,
        PERSISTENCE_ARTIFACT_DELETED,
        ARCHIVE_CREATED,
        ARCHIVE_ACCESSED,
        ARCHIVE_DELETED,
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


def build_lifecycle_event(
    *,
    run_id: str,
    scenario_id: str,
    target: str,
    source: str,
    event: str,
    artifact: str,
    evidence: dict[str, Any] | None = None,
) -> Event:
    return _event(
        run_id=run_id,
        scenario_id=scenario_id,
        event=event,
        status="info",
        target=target,
        source=source,
        artifact=artifact,
        evidence=evidence,
    )


def build_eicar_file_created_event(
    *,
    run_id: str,
    scenario_id: str,
    target: str,
    source: str,
    path: str,
) -> Event:
    return build_lifecycle_event(
        run_id=run_id,
        scenario_id=scenario_id,
        target=target,
        source=source,
        event=EICAR_FILE_CREATED,
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
    return build_lifecycle_event(
        run_id=run_id,
        scenario_id=scenario_id,
        target=target,
        source=source,
        event=EICAR_FILE_ACCESSED,
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
    return build_lifecycle_event(
        run_id=run_id,
        scenario_id=scenario_id,
        target=target,
        source=source,
        event=EICAR_FILE_DELETED,
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
