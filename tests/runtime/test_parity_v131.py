"""DSP v1.3.1 parity unit/integration tests — traffic summary and scenario behavior."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from unittest.mock import MagicMock

import pytest

from dsp.engine.host_selection import select_hosts_for_capability, select_merged_http_hosts
from dsp.engine.scenario_engine import TargetSet
from dsp.event_store import Event, EventStore
from dsp.protocols.http.user_agents import classify_user_agent, pick_user_agent
from dsp.protocols.http.urls import ATTACK_SCAN_PATHS
from dsp.protocols.ssh.attempts import MAX_ATTEMPTS_PER_HOST_DEFAULT, plan_ssh_attempts
from dsp.runtime.traffic_summary import _normalize_event, build_traffic_summary
from scenarios.smb_login_failure import executor as smb_executor


def _targets_with_discovery() -> TargetSet:
    return TargetSet(
        target_net="221.139.249.0/24",
        hosts=["221.139.249.101", "221.139.249.110", "221.139.249.113"],
        discovery_enabled=True,
        discovery_meta={
            "probed_hosts": 254,
            "alive_hosts": ["221.139.249.101", "221.139.249.110", "221.139.249.113"],
        },
        service_hosts={
            "ssh_hosts": ["221.139.249.101", "221.139.249.110"],
            "http_targets": ["221.139.249.110", "221.139.249.113"],
            "https_targets": ["221.139.249.113"],
            "smb_hosts": [],
        },
    )


def test_normalize_event_from_event_object():
    event = Event(
        run_id="r1",
        scenario_id="port_sweep",
        timestamp=datetime.now(timezone.utc),
        stage="executor",
        event="port_sweep_completed",
        status="info",
        evidence={"probe_count": 10},
        target="221.139.249.101",
    )
    normalized = _normalize_event(event)
    assert normalized["scenario_id"] == "port_sweep"
    assert normalized["event"] == "port_sweep_completed"
    assert normalized["evidence"]["probe_count"] == 10


def test_normalize_event_from_dict():
    normalized = _normalize_event(
        {
            "scenario_id": "ssh_failure",
            "event": "ssh_failure_completed",
            "evidence": {"failure_count": 150},
            "target": "221.139.249.101",
        }
    )
    assert normalized["evidence"]["failure_count"] == 150


def test_normalize_event_from_to_dict_object():
    class _Record:
        def to_dict(self) -> dict:
            return {
                "scenario_id": "http_followup",
                "event": "http_followup_completed",
                "evidence": {"user_agent_classes": {"rare": 3}},
                "target": "221.139.249.110",
            }

    normalized = _normalize_event(_Record())
    assert normalized["evidence"]["user_agent_classes"]["rare"] == 3


def test_build_traffic_summary_mixed_event_inputs():
    store = MagicMock()
    store.list_events.return_value = [
        Event(
            run_id="r1",
            scenario_id="port_sweep",
            timestamp=datetime.now(timezone.utc),
            stage="executor",
            event="port_sweep_started",
            status="info",
            evidence={"planned_probes": 2540, "ports": [22, 80, 443]},
        ),
        {
            "scenario_id": "port_sweep",
            "event": "port_sweep_completed",
            "evidence": {"probe_count": 2540, "connection_success_count": 1, "connection_failure_count": 2539},
            "target": "221.139.249.0/24",
        },
        Event(
            run_id="r1",
            scenario_id="http_followup",
            timestamp=datetime.now(timezone.utc),
            stage="executor",
            event="http_followup_completed",
            status="info",
            evidence={
                "paths_used": ["/.env", "/login"],
                "user_agent_classes": {"normal": 2, "rare": 5, "payload_sqli": 3},
                "request_count": 10,
                "response_count": 8,
            },
        ),
        Event(
            run_id="r1",
            scenario_id="ssh_failure",
            timestamp=datetime.now(timezone.utc),
            stage="executor",
            event="ssh_failure_completed",
            status="info",
            evidence={"failure_count": 150, "attempt_count": 150},
        ),
        Event(
            run_id="r1",
            scenario_id="smb_login_failure",
            timestamp=datetime.now(timezone.utc),
            stage="executor",
            event="smb_scenario_completed",
            status="info",
            evidence={
                "skipped_no_open_service": True,
                "auth_attempts": 0,
                "auth_failed": 0,
                "tcp_connect_attempts": 0,
            },
        ),
    ]

    summary = build_traffic_summary(
        store,
        run_id="r1",
        scenario_ids=["port_sweep", "http_followup", "ssh_failure", "smb_login_failure"],
        targets=_targets_with_discovery(),
        traffic_profile="normal",
    )

    assert summary["traffic_profile"] == "normal"
    assert summary["scenarios"]["port_sweep"]["probes_sent"] == 2540
    assert "/.env" in summary["scenarios"]["http_followup"]["paths_sample"]
    assert summary["scenarios"]["http_followup"]["user_agent_classes"]["rare"] == 5
    assert summary["scenarios"]["ssh_failure"]["auth_failed"] == 150
    assert summary["scenarios"]["smb_login_failure"]["skipped_no_open_service"] is True
    assert summary["scenarios"]["smb_login_failure"]["auth_attempts"] == 0


def test_pick_user_agent_not_fixed_dsp_http_followup():
    samples = {pick_user_agent() for _ in range(30)}
    assert "dsp-http-followup/1.0" not in samples
    assert len(samples) > 1


def test_classify_user_agent_distribution_categories():
    assert classify_user_agent(
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0 Safari/537.36"
    ) == "normal"
    assert classify_user_agent("ReconEngine/5.4") == "rare"
    assert classify_user_agent("'; OR 1=1--") == "payload_sqli"


def test_ssh_invaliduser_burst_default_150():
    plans = plan_ssh_attempts(["221.139.249.101"])
    assert len(plans) == MAX_ATTEMPTS_PER_HOST_DEFAULT
    assert all(p.username == "invaliduser" for p in plans)


def test_smb_skipped_when_no_smb_hosts(tmp_path):
    store = EventStore(tmp_path / "events.db")
    store.open_run("smb_skip_run")
    ctx = MagicMock()
    ctx.run_id = "smb_skip_run"
    ctx.dry_run = False
    ctx.cancelled = False
    ctx.event_store = store

    targets = _targets_with_discovery()
    smb_executor.run(ctx, targets, config={})

    events = store.list_events("smb_skip_run")
    skipped = [e for e in events if e.event == "smb_scenario_skipped"]
    completed = [e for e in events if e.event == "smb_scenario_completed"]
    assert skipped
    assert completed
    assert completed[0].evidence.get("skipped_no_open_service") is True
    assert completed[0].evidence.get("auth_attempts", 0) == 0
    assert completed[0].evidence.get("auth_failed", 0) == 0

    summary = build_traffic_summary(
        store,
        run_id="smb_skip_run",
        scenario_ids=["smb_login_failure"],
        targets=targets,
        traffic_profile="normal",
    )
    smb = summary["scenarios"]["smb_login_failure"]
    assert smb["skipped_no_open_service"] is True
    assert smb["auth_attempts"] == 0


def test_host_selection_uses_discovery_not_cidr_dot_one_two():
    targets = _targets_with_discovery()

    ssh_hosts = select_hosts_for_capability(targets, {}, capability="ssh_hosts", max_hosts=5)
    http_hosts = select_merged_http_hosts(targets, {}, max_hosts=5)

    assert ssh_hosts == ["221.139.249.101", "221.139.249.110"]
    assert http_hosts == ["221.139.249.110", "221.139.249.113"]
    assert "221.139.249.1" not in ssh_hosts
    assert "221.139.249.2" not in http_hosts


def test_http_attack_paths_included_in_planned_paths():
    from dsp.protocols.http.urls import plan_followup_requests

    plans = plan_followup_requests(
        endpoints=[("221.139.249.110", 80)],
        max_per_host=20,
        max_total=20,
    )
    paths = {p.path for p in plans}
    assert any(path in ATTACK_SCAN_PATHS for path in paths)


def test_smb_skip_validation_marks_skipped_not_failed(tmp_path):
    from dsp.event_store import EventStore, ValidationDecision
    from dsp.plugins import PluginLoader
    from dsp.runner import compute_exit_code
    from dsp.validation import ValidationEngine

    store = EventStore(tmp_path / "events.db")
    store.open_run("skip_val_run")
    ctx = MagicMock()
    ctx.run_id = "skip_val_run"
    ctx.dry_run = False
    ctx.cancelled = False
    ctx.event_store = store

    targets = _targets_with_discovery()
    smb_executor.run(ctx, targets, config={})

    registry = PluginLoader().discover_and_load()
    engine = ValidationEngine(store, registry)
    results = engine.validate_run("skip_val_run", ["smb_login_failure"])
    assert len(results) == 1
    assert results[0].decision == ValidationDecision.SKIPPED

    mixed = [
        MagicMock(decision=ValidationDecision.SUCCESS),
        results[0],
    ]
    assert compute_exit_code(mixed) == 0


def test_traffic_summary_written_on_run_completion(tmp_runs_dir):
    from dsp.runner import RunManager

    manager = RunManager(runs_dir=tmp_runs_dir)
    _, run_dir, exit_code = manager.run(
        scenario_ids=["port_sweep"],
        target_net="10.10.10.0/24",
        dry_run=True,
        scenario_params={"port_sweep": {"max_hosts": 1, "max_ports": 2}},
    )

    assert exit_code == 0
    summary_path = run_dir / "traffic_summary.json"
    assert summary_path.exists()
    summary = json.loads(summary_path.read_text())
    assert "scenarios" in summary
    assert "port_sweep" in summary["scenarios"]
