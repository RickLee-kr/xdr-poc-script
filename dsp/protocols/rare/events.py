"""Rare protocol activity event definitions."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from dsp.event_store import Event

RARE_PROTOCOL_ACTIVITY_STARTED = "rare_protocol_activity_started"
RARE_PROTOCOL_PROBE_ATTEMPT = "rare_protocol_probe_attempt"
RARE_PROTOCOL_PROBE_SUCCESS = "rare_protocol_probe_success"
RARE_PROTOCOL_PROBE_FAILURE = "rare_protocol_probe_failure"
RARE_PROTOCOL_ACTIVITY_COMPLETED = "rare_protocol_activity_completed"
RARE_PROTOCOL_ACTIVITY_SKIPPED = "rare_protocol_activity_skipped"

RARE_PROTOCOL_TRAFFIC_EVENTS = frozenset(
    {
        RARE_PROTOCOL_PROBE_ATTEMPT,
        RARE_PROTOCOL_PROBE_SUCCESS,
        RARE_PROTOCOL_PROBE_FAILURE,
    }
)


def build_rare_protocol_activity_started_event(
    *,
    run_id: str,
    scenario_id: str,
    target: str,
    source: str,
    evidence: dict[str, Any],
) -> Event:
    return Event(
        run_id=run_id,
        scenario_id=scenario_id,
        timestamp=datetime.now(timezone.utc),
        stage="executor",
        event=RARE_PROTOCOL_ACTIVITY_STARTED,
        status="info",
        target=target,
        artifact="rare_protocol_session",
        evidence=dict(evidence),
        source=source,
    )


def build_rare_protocol_probe_attempt_event(
    *,
    run_id: str,
    scenario_id: str,
    target: str,
    artifact: str,
    source: str,
    evidence: dict[str, Any],
) -> Event:
    return Event(
        run_id=run_id,
        scenario_id=scenario_id,
        timestamp=datetime.now(timezone.utc),
        stage="executor",
        event=RARE_PROTOCOL_PROBE_ATTEMPT,
        status="sent",
        target=target,
        artifact=artifact,
        evidence=dict(evidence),
        source=source,
    )


def build_rare_protocol_probe_success_event(
    *,
    run_id: str,
    scenario_id: str,
    target: str,
    artifact: str,
    source: str,
    evidence: dict[str, Any],
) -> Event:
    return Event(
        run_id=run_id,
        scenario_id=scenario_id,
        timestamp=datetime.now(timezone.utc),
        stage="executor",
        event=RARE_PROTOCOL_PROBE_SUCCESS,
        status="sent",
        target=target,
        artifact=artifact,
        evidence=dict(evidence),
        source=source,
    )


def build_rare_protocol_probe_failure_event(
    *,
    run_id: str,
    scenario_id: str,
    target: str,
    artifact: str,
    source: str,
    evidence: dict[str, Any],
    status: str = "failure",
) -> Event:
    return Event(
        run_id=run_id,
        scenario_id=scenario_id,
        timestamp=datetime.now(timezone.utc),
        stage="executor",
        event=RARE_PROTOCOL_PROBE_FAILURE,
        status=status,
        target=target,
        artifact=artifact,
        evidence=dict(evidence),
        source=source,
    )


def build_rare_protocol_activity_completed_event(
    *,
    run_id: str,
    scenario_id: str,
    target: str,
    source: str,
    evidence: dict[str, Any],
) -> Event:
    return Event(
        run_id=run_id,
        scenario_id=scenario_id,
        timestamp=datetime.now(timezone.utc),
        stage="executor",
        event=RARE_PROTOCOL_ACTIVITY_COMPLETED,
        status="info",
        target=target,
        artifact="rare_protocol_session",
        evidence=dict(evidence),
        source=source,
    )
