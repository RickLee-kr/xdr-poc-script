"""Live-path regression tests — HTTP endpoint cache wired through RunManager."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from dsp.discovery.legacy_bash import DiscoveryResult
from dsp.engine.host_selection import (
    HTTP_ENDPOINT_SELECTION_CACHE_KEY,
    SKIP_REASON_HTTP_TARGETS_NOT_FOUND,
    cache_http_endpoint_selection,
)
from dsp.engine.orchestrator import run_scenario
from dsp.engine.scenario_engine import RunConfig, RunContext, TargetSet
from dsp.event_store import EventStore, ValidationDecision
from dsp.plugins import PluginLoader
from dsp.protocols.http.client import HttpClient
from dsp.protocols.http.target_probe import HttpEndpointProbeStats
from dsp.runner.run_manager import RunManager
from dsp.runtime.traffic_summary import build_traffic_summary
from dsp.validation import ValidationEngine


def _probe_stats_for(host: str, port: int) -> HttpEndpointProbeStats:
    stats = HttpEndpointProbeStats(host=host, port=port, scheme="http")
    if (host, port) == ("221.139.249.110", 80):
        stats.status_counts = {301: 7}
    elif (host, port) == ("221.139.249.110", 8080):
        stats.status_counts = {400: 2}
    elif (host, port) == ("221.139.249.118", 9000):
        stats.status_counts = {400: 3}
    else:
        stats.timeouts = 5
    return stats


def _lab_targets() -> TargetSet:
    return TargetSet(
        target_net="221.139.249.0/24",
        service_hosts={
            "http_targets": ["221.139.249.110", "221.139.249.118"],
        },
        service_endpoints={
            "http_targets": [
                ("221.139.249.110", 80),
                ("221.139.249.118", 9000),
            ],
        },
        discovery_enabled=True,
    )


def test_live_path_empty_selection_skips_without_completed(monkeypatch, tmp_path: Path):
    def fake_probe(host, port, scheme, *, client, index=0):
        stats = HttpEndpointProbeStats(host=host, port=port, scheme="http")
        stats.timeouts = 5
        return stats

    monkeypatch.setattr(
        "dsp.protocols.http.target_probe.probe_http_endpoint",
        fake_probe,
    )
    monkeypatch.setattr(
        "dsp.discovery.legacy_bash.discover_services",
        lambda *args, **kwargs: DiscoveryResult(
            target_net="221.139.249.0/24",
            service_hosts={"http_targets": ["221.139.249.110"]},
            service_endpoints={"http_targets": [("221.139.249.110", 80)]},
            alive_hosts=["221.139.249.110"],
            probed_hosts=1,
            open_endpoints=1,
        ),
    )

    manager = RunManager(runs_dir=tmp_path / "runs")
    run, run_dir, exit_code = manager.run(
        scenario_ids=["http_followup"],
        target_net="221.139.249.0/24",
        dry_run=False,
        scenario_params={"http_followup": {"max_hosts": 2, "max_total": 10, "max_per_host": 5}},
        export_evidence=False,
    )

    store = EventStore.open_existing(run_dir / "events.db")
    skipped = [e for e in store.list_events(run.run_id) if e.event == "http_followup_skipped"]
    completed = [e for e in store.list_events(run.run_id) if e.event == "http_followup_completed"]
    lifecycle_completed = [
        e for e in store.list_events(run.run_id) if e.event == "scenario_completed"
    ]
    assert skipped
    assert not completed
    assert not lifecycle_completed
    assert skipped[0].evidence["reason"] == SKIP_REASON_HTTP_TARGETS_NOT_FOUND

    summary = build_traffic_summary(
        store,
        run_id=run.run_id,
        scenario_ids=["http_followup"],
        targets=_lab_targets(),
        traffic_profile="normal",
    )
    http = summary["scenarios"]["http_followup"]
    assert http["skipped"] is True
    assert http["skip_reason"] == SKIP_REASON_HTTP_TARGETS_NOT_FOUND
    assert http["requests_sent"] == 0
    assert http["requests_planned"] == 0
    assert summary.get("target_probe")

    results = ValidationEngine(store, manager.registry).validate_run(
        run.run_id, ["http_followup"]
    )
    assert results[0].decision == ValidationDecision.SKIPPED
    assert exit_code == 3
    store.close()

    probe_path = run_dir / "http_target_probe.json"
    assert probe_path.exists()
    probe_doc = json.loads(probe_path.read_text())
    assert probe_doc["target_probe"]


def test_live_path_selected_endpoints_send_requests(monkeypatch, tmp_path: Path):
    def fake_probe(host, port, scheme, *, client, index=0):
        return _probe_stats_for(host, port)

    monkeypatch.setattr(
        "dsp.protocols.http.target_probe.probe_http_endpoint",
        fake_probe,
    )
    monkeypatch.setattr(
        "dsp.discovery.legacy_bash.discover_services",
        lambda *args, **kwargs: DiscoveryResult(
            target_net="221.139.249.0/24",
            service_hosts={
                "http_targets": ["221.139.249.110", "221.139.249.118"],
            },
            service_endpoints={
                "http_targets": [
                    ("221.139.249.110", 80),
                    ("221.139.249.118", 9000),
                ],
            },
            alive_hosts=["221.139.249.110", "221.139.249.118"],
            probed_hosts=2,
            open_endpoints=2,
        ),
    )

    manager = RunManager(runs_dir=tmp_path / "runs")
    scenario_params = {
        "http_followup": {
            "max_hosts": 2,
            "max_total": 10,
            "max_per_host": 5,
            "timeout": 5.0,
        },
    }
    run, run_dir, exit_code = manager.run(
        scenario_ids=["http_followup"],
        target_net="221.139.249.0/24",
        dry_run=False,
        scenario_params=scenario_params,
        export_evidence=False,
    )

    cache = scenario_params["http_followup"][HTTP_ENDPOINT_SELECTION_CACHE_KEY]
    selected_ports = {(ep["host"], ep["port"]) for ep in cache["endpoints"]}
    assert selected_ports == {("221.139.249.110", 8080), ("221.139.249.118", 9000)}

    store = EventStore.open_existing(run_dir / "events.db")
    completed = [e for e in store.list_events(run.run_id) if e.event == "http_followup_completed"]
    assert completed
    assert completed[0].evidence["requests_sent"] > 0
    assert 9000 in completed[0].evidence["ports_used"]
    assert 8080 in completed[0].evidence["ports_used"]
    store.close()


def test_orchestrator_skip_does_not_emit_scenario_completed(monkeypatch):
    def fake_probe(host, port, scheme, *, client, index=0):
        stats = HttpEndpointProbeStats(host=host, port=port, scheme="http")
        stats.timeouts = 5
        return stats

    monkeypatch.setattr(
        "dsp.protocols.http.target_probe.probe_http_endpoint",
        fake_probe,
    )

    targets = TargetSet(
        target_net="221.139.249.0/24",
        service_hosts={"http_targets": ["221.139.249.110"]},
        service_endpoints={"http_targets": [("221.139.249.110", 80)]},
        discovery_enabled=True,
    )
    scenario_params = {"http_followup": {"max_hosts": 2, "max_total": 10, "max_per_host": 5}}
    cache_http_endpoint_selection(
        scenario_params,
        scenario_ids=["http_followup"],
        targets=targets,
        dry_run=True,
    )

    store = EventStore(":memory:")
    run_id = "orch_skip"
    store.open_run(run_id)
    ctx = RunContext(
        run_id=run_id,
        target_net="221.139.249.0/24",
        event_store=store,
        config=RunConfig(dry_run=True, scenario_params=scenario_params),
        dry_run=True,
    )
    loader = PluginLoader()
    record = loader.discover_and_load().get("http_followup")
    assert record is not None

    summary = run_scenario(record, ctx, targets)
    assert summary is None
    assert any(e.event == "http_followup_skipped" for e in store.list_events(run_id))
    assert any(e.event == "scenario_skipped" for e in store.list_events(run_id))
    assert not any(e.event == "scenario_completed" for e in store.list_events(run_id))
    assert not any(e.event == "http_followup_completed" for e in store.list_events(run_id))
