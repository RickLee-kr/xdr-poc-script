"""Shared Event Store metrics — single source for validation and traffic_summary."""

from __future__ import annotations

from typing import TYPE_CHECKING

from dsp.event_store import EventStore, MetricDef

if TYPE_CHECKING:
    from dsp.plugins.registry import PluginRegistry


def parse_validation_metric_defs(validation_profile: dict) -> list[MetricDef]:
    """Parse manifest validation_profile.metrics into MetricDef objects."""
    from dsp.validation.engine import _parse_metrics

    return _parse_metrics(validation_profile.get("metrics", []))


def aggregate_scenario_metrics(
    store: EventStore,
    registry: PluginRegistry,
    run_id: str,
    scenario_id: str,
) -> dict[str, int | float]:
    """Aggregate scenario metrics from Event Store using manifest validation profile."""
    record = registry.get(scenario_id)
    if record is None:
        return {}

    vp = record.manifest.validation_profile
    metric_defs = parse_validation_metric_defs(vp)
    metrics = store.aggregate(run_id, scenario_id, metric_defs)

    if scenario_id == "dns_tunnel":
        from dsp.protocols.dns.tunnel_validation import count_dns_tunnel_idx_pattern_queries

        metrics["dns_tunnel_idx_pattern_count"] = count_dns_tunnel_idx_pattern_queries(
            store,
            run_id,
            scenario_id,
        )

    return metrics
