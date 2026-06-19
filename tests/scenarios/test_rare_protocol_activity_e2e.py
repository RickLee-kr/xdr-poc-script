"""Rare protocol activity scenario E2E tests."""

from __future__ import annotations

import json
from unittest.mock import patch

import pytest

from dsp.runner import RunManager


RARE_TEST_PARAMS = {
    "rare_protocol_activity": {
        "probe_hosts": ["10.10.10.20"],
        "timeout": 1.0,
        "rtp_burst_count": 3,
    }
}


@pytest.fixture
def mock_rare_socket():
    with patch("socket.create_connection") as connect_mock, patch(
        "socket.socket"
    ) as socket_cls:
        tcp_sock = connect_mock.return_value.__enter__.return_value
        tcp_sock.recv.return_value = b"OK"
        udp_sock = socket_cls.return_value
        yield connect_mock


def test_rare_protocol_activity_dry_run_e2e(tmp_runs_dir):
    manager = RunManager(runs_dir=tmp_runs_dir)
    run, run_dir, exit_code = manager.run(
        scenario_ids=["rare_protocol_activity"],
        target_net="10.10.10.0/24",
        dry_run=True,
        scenario_params=RARE_TEST_PARAMS,
    )

    assert run.status.value == "completed"
    assert exit_code == 0
    assert (run_dir / "events.db").exists()
    assert (run_dir / "validation.json").exists()
    assert (run_dir / "report.md").exists()
    assert (run_dir / "traffic_summary.json").exists()

    validation = json.loads((run_dir / "validation.json").read_text())
    result = validation["results"][0]
    assert result["scenario_id"] == "rare_protocol_activity"
    assert result["decision"] == "success"
    assert result["metrics"]["rare_protocol_probe_attempt_count"] >= 4

    report = (run_dir / "report.md").read_text()
    assert "Rare Protocol Activity" in report

    events = (run_dir / "events.jsonl").read_text()
    assert "rare_protocol_activity_started" in events
    assert "rare_protocol_probe_attempt" in events
    assert "rare_protocol_activity_completed" in events


def test_rare_protocol_activity_live_e2e(tmp_runs_dir, mock_rare_socket):
    manager = RunManager(runs_dir=tmp_runs_dir)
    run, run_dir, exit_code = manager.run(
        scenario_ids=["rare_protocol_activity"],
        target_net="10.10.10.0/24",
        dry_run=False,
        scenario_params=RARE_TEST_PARAMS,
    )

    assert run.status.value == "completed"
    assert exit_code == 0
    validation = json.loads((run_dir / "validation.json").read_text())
    assert validation["results"][0]["decision"] == "success"


def test_rare_protocol_activity_plugins_list():
    from dsp.plugins import PluginLoader, PluginStatus

    registry = PluginLoader().discover_and_load()
    record = registry.get("rare_protocol_activity")
    assert record is not None
    assert record.status == PluginStatus.ACTIVE
