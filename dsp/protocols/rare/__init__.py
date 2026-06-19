"""Rare protocol activity library — safe TELNET/RTSP/SIP/RTP probe traffic."""

from dsp.protocols.rare.attempts import (
    DEFAULT_RTP_BURST,
    MAX_RTP_BURST,
    RARE_PROTOCOL_PORTS,
    PlannedRareProbe,
    plan_rare_protocol_activity,
)
from dsp.protocols.rare.client import RareProtocolClient, RareProbeResult
from dsp.protocols.rare.events import (
    RARE_PROTOCOL_ACTIVITY_COMPLETED,
    RARE_PROTOCOL_ACTIVITY_SKIPPED,
    RARE_PROTOCOL_ACTIVITY_STARTED,
    RARE_PROTOCOL_PROBE_ATTEMPT,
    RARE_PROTOCOL_PROBE_FAILURE,
    RARE_PROTOCOL_PROBE_SUCCESS,
    RARE_PROTOCOL_TRAFFIC_EVENTS,
    build_rare_protocol_activity_completed_event,
    build_rare_protocol_activity_started_event,
    build_rare_protocol_probe_attempt_event,
    build_rare_protocol_probe_failure_event,
    build_rare_protocol_probe_success_event,
)
from dsp.protocols.rare.reporting import (
    build_rare_protocol_report_section,
    rare_protocol_report_profile,
)
from dsp.protocols.rare.validation import (
    RARE_PROTOCOL_METRIC_NAMES,
    rare_protocol_validation_profile,
)

__all__ = [
    "DEFAULT_RTP_BURST",
    "MAX_RTP_BURST",
    "RARE_PROTOCOL_ACTIVITY_COMPLETED",
    "RARE_PROTOCOL_ACTIVITY_SKIPPED",
    "RARE_PROTOCOL_ACTIVITY_STARTED",
    "RARE_PROTOCOL_METRIC_NAMES",
    "RARE_PROTOCOL_PORTS",
    "RARE_PROTOCOL_PROBE_ATTEMPT",
    "RARE_PROTOCOL_PROBE_FAILURE",
    "RARE_PROTOCOL_PROBE_SUCCESS",
    "RARE_PROTOCOL_TRAFFIC_EVENTS",
    "PlannedRareProbe",
    "RareProbeResult",
    "RareProtocolClient",
    "build_rare_protocol_activity_completed_event",
    "build_rare_protocol_activity_started_event",
    "build_rare_protocol_probe_attempt_event",
    "build_rare_protocol_probe_failure_event",
    "build_rare_protocol_probe_success_event",
    "build_rare_protocol_report_section",
    "plan_rare_protocol_activity",
    "rare_protocol_report_profile",
    "rare_protocol_validation_profile",
]
