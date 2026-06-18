"""Rare protocol activity validation profile templates."""

from __future__ import annotations

from typing import Any

RARE_PROTOCOL_METRIC_NAMES = [
    "rare_protocol_probe_attempt_count",
    "rare_protocol_probe_success_count",
    "rare_protocol_probe_failure_count",
]


def rare_protocol_validation_profile(**overrides: Any) -> dict[str, Any]:
    """Standard rare protocol validation profile for manifest.yaml."""
    profile: dict[str, Any] = {
        "profile_version": "1.0.0",
        "metrics": [
            {
                "name": "rare_protocol_probe_attempt_count",
                "event_filter": {
                    "event": "rare_protocol_probe_attempt",
                    "status": "sent",
                },
                "aggregate": "count",
            },
            {
                "name": "rare_protocol_probe_success_count",
                "event_filter": {
                    "event": "rare_protocol_probe_success",
                    "status": "sent",
                },
                "aggregate": "count",
            },
            {
                "name": "rare_protocol_probe_failure_count",
                "event_filter": {
                    "event": "rare_protocol_probe_failure",
                },
                "aggregate": "count",
            },
        ],
        "success": {
            "rare_protocol_probe_attempt_count": {"min": 1},
        },
        "fail_fast": ["SOT_EMPTY_AFTER_EXECUTE"],
    }
    profile.update(overrides)
    return profile
