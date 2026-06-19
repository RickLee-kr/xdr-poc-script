"""HTTP Follow-up event definitions and Event Store mapping."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from dsp.event_store import Event
from dsp.protocols.types import HttpRequest, HttpResponseResult

HTTP_FOLLOWUP_STARTED = "http_followup_started"
HTTP_REQUEST_CREATED = "http_request_created"
HTTP_REQUEST_SENT = "http_request_sent"
HTTP_RESPONSE_RECEIVED = "http_response_received"
HTTP_REQUEST_ERROR = "http_request_error"
HTTP_FOLLOWUP_COMPLETED = "http_followup_completed"
NON_STANDARD_PORT_BURST_STARTED = "non_standard_port_burst_started"
NON_STANDARD_PORT_CONNECTION_ATTEMPT = "non_standard_port_connection_attempt"
NON_STANDARD_PORT_CONNECTION_SUCCESS = "non_standard_port_connection_success"
NON_STANDARD_PORT_CONNECTION_FAILURE = "non_standard_port_connection_failure"
NON_STANDARD_PORT_BURST_COMPLETED = "non_standard_port_burst_completed"

HTTP_FOLLOWUP_TRAFFIC_EVENTS = frozenset(
    {
        HTTP_REQUEST_CREATED,
        HTTP_REQUEST_SENT,
        HTTP_RESPONSE_RECEIVED,
        HTTP_REQUEST_ERROR,
        NON_STANDARD_PORT_CONNECTION_ATTEMPT,
        NON_STANDARD_PORT_CONNECTION_SUCCESS,
        NON_STANDARD_PORT_CONNECTION_FAILURE,
    }
)

OUTCOME_TO_STATUS: dict[str, str] = {
    "response": "response",
    "timeout": "error",
    "connection_refused": "connection_refused",
    "dns_failure": "dns_failure",
    "error": "error",
}


def build_http_followup_started_event(
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
        event=HTTP_FOLLOWUP_STARTED,
        status="info",
        target=target,
        artifact="http_followup_session",
        evidence=dict(evidence),
        source=source,
    )


def build_http_request_created_event(
    *,
    run_id: str,
    scenario_id: str,
    target: str,
    url: str,
    source: str,
    evidence: dict[str, Any],
) -> Event:
    return Event(
        run_id=run_id,
        scenario_id=scenario_id,
        timestamp=datetime.now(timezone.utc),
        stage="executor",
        event=HTTP_REQUEST_CREATED,
        status="info",
        target=target,
        artifact=url,
        evidence=dict(evidence),
        source=source,
    )


def build_http_request_sent_event(
    *,
    run_id: str,
    scenario_id: str,
    target: str,
    url: str,
    source: str,
    evidence: dict[str, Any],
) -> Event:
    return Event(
        run_id=run_id,
        scenario_id=scenario_id,
        timestamp=datetime.now(timezone.utc),
        stage="executor",
        event=HTTP_REQUEST_SENT,
        status="sent",
        target=target,
        artifact=url,
        evidence=dict(evidence),
        source=source,
    )


def build_http_response_received_event(
    *,
    run_id: str,
    scenario_id: str,
    target: str,
    url: str,
    source: str,
    evidence: dict[str, Any],
) -> Event:
    return Event(
        run_id=run_id,
        scenario_id=scenario_id,
        timestamp=datetime.now(timezone.utc),
        stage="executor",
        event=HTTP_RESPONSE_RECEIVED,
        status="response",
        target=target,
        artifact=url,
        evidence=dict(evidence),
        source=source,
    )


def build_http_request_error_event(
    *,
    run_id: str,
    scenario_id: str,
    target: str,
    url: str,
    source: str,
    evidence: dict[str, Any],
    status: str = "error",
) -> Event:
    return Event(
        run_id=run_id,
        scenario_id=scenario_id,
        timestamp=datetime.now(timezone.utc),
        stage="executor",
        event=HTTP_REQUEST_ERROR,
        status=status,
        target=target,
        artifact=url,
        evidence=dict(evidence),
        source=source,
    )


def build_http_followup_completed_event(
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
        event=HTTP_FOLLOWUP_COMPLETED,
        status="info",
        target=target,
        artifact="http_followup_session",
        evidence=dict(evidence),
        source=source,
    )


def build_non_standard_port_burst_started_event(
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
        event=NON_STANDARD_PORT_BURST_STARTED,
        status="info",
        target=target,
        artifact="non_standard_port_burst",
        evidence=dict(evidence),
        source=source,
    )


def build_non_standard_port_connection_attempt_event(
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
        event=NON_STANDARD_PORT_CONNECTION_ATTEMPT,
        status="sent",
        target=target,
        artifact=str(evidence.get("url") or target),
        evidence=dict(evidence),
        source=source,
    )


def build_non_standard_port_connection_success_event(
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
        event=NON_STANDARD_PORT_CONNECTION_SUCCESS,
        status="response",
        target=target,
        artifact=str(evidence.get("url") or target),
        evidence=dict(evidence),
        source=source,
    )


def build_non_standard_port_connection_failure_event(
    *,
    run_id: str,
    scenario_id: str,
    target: str,
    source: str,
    evidence: dict[str, Any],
    status: str = "error",
) -> Event:
    return Event(
        run_id=run_id,
        scenario_id=scenario_id,
        timestamp=datetime.now(timezone.utc),
        stage="executor",
        event=NON_STANDARD_PORT_CONNECTION_FAILURE,
        status=status,
        target=target,
        artifact=str(evidence.get("url") or target),
        evidence=dict(evidence),
        source=source,
    )


def build_non_standard_port_burst_completed_event(
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
        event=NON_STANDARD_PORT_BURST_COMPLETED,
        status="info",
        target=target,
        artifact="non_standard_port_burst",
        evidence=dict(evidence),
        source=source,
    )


def append_outcome_event(
    *,
    run_id: str,
    scenario_id: str,
    request: HttpRequest,
    result: HttpResponseResult,
    source: str,
) -> Event:
    """Build response or error event from HTTP result."""
    evidence: dict[str, Any] = {
        "method": request.method,
        "host": request.host,
        "port": request.port,
        "path": request.path,
        "request_id": result.request_id,
        "outcome": result.outcome,
        "dry_run": result.dry_run,
    }
    if result.status_code is not None:
        evidence["status_code"] = result.status_code
    if result.response_summary:
        evidence["response"] = result.response_summary

    if result.outcome == "response":
        return build_http_response_received_event(
            run_id=run_id,
            scenario_id=scenario_id,
            target=request.host,
            url=request.url,
            source=source,
            evidence=evidence,
        )

    status = OUTCOME_TO_STATUS.get(result.outcome, "error")
    return build_http_request_error_event(
        run_id=run_id,
        scenario_id=scenario_id,
        target=request.host,
        url=request.url,
        source=source,
        evidence=evidence,
        status=status,
    )
