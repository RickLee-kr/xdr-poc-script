"""Non-standard port burst planner and event tests."""

from __future__ import annotations

import json
from unittest.mock import patch

from dsp.engine.host_selection import (
    HTTP_ENDPOINT_SELECTION_CACHE_KEY,
    HttpFollowupSelection,
    selection_to_cache,
)
from dsp.engine.scenario_engine import TargetSet
from dsp.protocols.http.non_standard_port_burst import (
    DEFAULT_BURST_MAX,
    DEFAULT_BURST_MIN,
    NON_STANDARD_BURST_CANDIDATES,
    plan_non_standard_port_burst,
    resolve_burst_attempt_count,
    select_non_standard_burst_targets,
)
from dsp.protocols.http.target_probe import HTTPEndpointProbeResult
from dsp.runner import RunManager
from dsp.runtime.scenario_plan import INITIAL_COMPROMISE_ENDPOINT_KEY


def _targets_with_http() -> TargetSet:
    return TargetSet(
        target_net="10.10.10.0/24",
        hosts=["10.10.10.20"],
        discovery_enabled=True,
        service_endpoints={
            "http_targets": [("10.10.10.20", 80), ("10.10.10.20", 8080), ("10.10.10.20", 8888)],
            "https_targets": [("10.10.10.20", 8443)],
        },
    )


def test_select_non_standard_burst_targets_prefers_discovered() -> None:
    targets = _targets_with_http()
    selected = select_non_standard_burst_targets(targets, ["10.10.10.20"])
    discovered_ports = {item.port for item in selected if item.discovered and not item.probe}
    assert 8888 in discovered_ports
    assert 8443 in discovered_ports
    probe_ports = {item.port for item in selected if item.probe}
    for port in NON_STANDARD_BURST_CANDIDATES:
        if port not in discovered_ports:
            assert port in probe_ports


def test_plan_non_standard_port_burst_attempt_range() -> None:
    targets = _targets_with_http()
    plan = plan_non_standard_port_burst(
        targets,
        ["10.10.10.20"],
        {
            "non_standard_burst_min": 50,
            "non_standard_burst_max": 50,
        },
    )
    assert plan["enabled"] is True
    assert plan["attempts_planned"] == 50
    assert len(plan["requests"]) == 50
    assert plan["requests"][0]["method"] == "GET"
    assert plan["requests"][0]["user_agent"]


def test_resolve_burst_attempt_count_bounds() -> None:
    assert resolve_burst_attempt_count({"non_standard_burst_min": 10, "non_standard_burst_max": 10}) == 10
    count = resolve_burst_attempt_count(
        {"non_standard_burst_min": DEFAULT_BURST_MIN, "non_standard_burst_max": DEFAULT_BURST_MAX}
    )
    assert DEFAULT_BURST_MIN <= count <= DEFAULT_BURST_MAX


def test_http_followup_dry_run_emits_burst_events(tmp_runs_dir) -> None:
    selection = HttpFollowupSelection(
        selected=[
            HTTPEndpointProbeResult(
                host="10.10.10.50",
                port=8080,
                scheme="http",
                selected=True,
                selection_reason="explicit",
            )
        ],
        selected_http_target_reason="explicit",
    )
    params = {
        "http_followup": {
            INITIAL_COMPROMISE_ENDPOINT_KEY: {
                "host": "10.10.10.50",
                "port": 8080,
                "scheme": "http",
            },
            HTTP_ENDPOINT_SELECTION_CACHE_KEY: selection_to_cache(selection),
            "non_standard_burst_min": 50,
            "non_standard_burst_max": 50,
            "max_hosts": 1,
            "max_per_host": 5,
            "max_total": 5,
        }
    }
    with patch("subprocess.run") as run_mock:
        manager = RunManager(runs_dir=tmp_runs_dir)
        _, run_dir, exit_code = manager.run(
            scenario_ids=["http_followup"],
            target_net="10.10.10.0/24",
            dry_run=True,
            scenario_params=params,
        )
    assert exit_code == 0
    run_mock.assert_not_called()
    events = [json.loads(line) for line in (run_dir / "events.jsonl").read_text().splitlines() if line.strip()]
    hb = [e for e in events if e.get("scenario_id") == "http_followup"]
    names = {e["event"] for e in hb}
    assert "non_standard_port_burst_started" in names
    assert "non_standard_port_connection_attempt" in names
    assert "non_standard_port_burst_completed" in names
    assert sum(1 for e in hb if e["event"] == "non_standard_port_connection_attempt") == 50

    validation = json.loads((run_dir / "validation.json").read_text())
    result = next(r for r in validation["results"] if r["scenario_id"] == "http_followup")
    assert result["metrics"]["non_standard_port_connection_attempt_count"] == 50

    traffic = json.loads((run_dir / "traffic_summary.json").read_text())
    burst = traffic["scenarios"]["http_followup"].get("non_standard_port_burst") or {}
    assert burst.get("attempts") == 50

    report = (run_dir / "report.md").read_text()
    assert "Non-Standard Port Burst" in report
