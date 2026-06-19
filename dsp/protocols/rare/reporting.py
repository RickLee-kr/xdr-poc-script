"""Rare protocol activity reporting profile and report section builders."""

from __future__ import annotations

from typing import Any

from dsp.event_store import ValidationResult
from dsp.protocols.rare.validation import RARE_PROTOCOL_METRIC_NAMES


def rare_protocol_report_profile(**overrides: Any) -> dict[str, Any]:
    """Standard rare protocol report_profile block for manifest.yaml."""
    profile: dict[str, Any] = {
        "profile_version": "1.0.0",
        "protocol": "rare_protocol_activity",
        "highlight_metrics": list(RARE_PROTOCOL_METRIC_NAMES),
        "sample_events": 5,
        "sample_filter": {"event": "rare_protocol_probe_attempt"},
    }
    profile.update(overrides)
    return profile


def build_rare_protocol_report_section(
    result: ValidationResult,
    event_samples: list[dict[str, Any]] | None = None,
    summary: dict[str, Any] | None = None,
) -> list[str]:
    """Build supplementary Rare Protocol Activity section for report.md."""
    summary = summary or {}
    lines = [
        f"### Rare Protocol Activity — {result.scenario_id}",
        "",
        "| Metric | Value | Store Source |",
        "|--------|-------|--------------|",
    ]
    trace_map = {
        "rare_protocol_probe_attempt_count": "event=rare_protocol_probe_attempt, status=sent",
        "rare_protocol_probe_success_count": "event=rare_protocol_probe_success, status=sent",
        "rare_protocol_probe_failure_count": "event=rare_protocol_probe_failure",
    }
    for name in RARE_PROTOCOL_METRIC_NAMES:
        value = result.metrics.get(name, 0)
        source = trace_map.get(name, "—")
        lines.append(f"| {name} | {value} | {source} |")

    protocols = summary.get("protocols", [])
    attempts = summary.get("attempt_count", result.metrics.get("rare_protocol_probe_attempt_count", 0))
    success = summary.get("success_count", result.metrics.get("rare_protocol_probe_success_count", 0))
    failure = summary.get("failure_count", result.metrics.get("rare_protocol_probe_failure_count", 0))

    lines.extend(["", "**Rare Protocol Activity**", ""])
    if protocols:
        lines.append(f"- **Protocols:** {', '.join(str(p) for p in protocols)}")
    lines.append(f"- **Attempts:** {attempts}")
    lines.append(f"- **Success:** {success}")
    lines.append(f"- **Failure:** {failure}")
    lines.append(f"- **Validation status:** {result.decision.value}")

    duration = summary.get("duration_sec")
    if duration is not None:
        lines.append(f"- **Duration:** {duration}s")

    lines.extend(
        [
            "",
            f"**Decision:** {result.decision.value} ({result.reason})",
            "",
        ]
    )

    if event_samples:
        lines.append(f"**Sample events:** {len(event_samples)} excerpt(s) from Event Store")
        lines.append("")

    return lines
