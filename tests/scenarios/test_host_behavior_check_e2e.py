"""Host behavior check integration tests."""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

from dsp.execution.remote.bundle.planner import _plan_host_behavior_check
from dsp.execution.remote.models import ScenarioExecutionRequest
from dsp.protocols.host.behavior import build_host_behavior_plan
from dsp.runner import RunManager
from dsp.runtime.operational_profiles import (
    DISCOVERY_FIRST_SCENARIO_ORDER,
    HOST_BEHAVIOR_CHECK_SCENARIO_ID,
    ensure_webshell_phase1_scenarios,
    insert_host_behavior_check,
    resolve_runnable_scenarios,
    scenarios_for_profile,
)
from dsp.runtime.scenario_plan import (
    WEBSHELL_EXECUTION_KEY,
    apply_webshell_initial_compromise_plan,
)


def test_normal_profile_includes_host_behavior_check() -> None:
    normal = scenarios_for_profile("normal")
    assert normal == list(DISCOVERY_FIRST_SCENARIO_ORDER)
    assert normal.index(HOST_BEHAVIOR_CHECK_SCENARIO_ID) == 0
    assert normal.index(HOST_BEHAVIOR_CHECK_SCENARIO_ID) < normal.index("port_sweep")
    assert normal.index("port_sweep") < normal.index("ssh_failure")


def test_insert_host_behavior_check_prepends_before_target_net_scenarios() -> None:
    ordered = insert_host_behavior_check(
        ["http_followup", "sql_injection", "port_sweep"]
    )
    assert ordered.index(HOST_BEHAVIOR_CHECK_SCENARIO_ID) == 0
    assert ordered.index("port_sweep") > ordered.index(HOST_BEHAVIOR_CHECK_SCENARIO_ID)


def test_ensure_webshell_phase1_scenarios_injects_host_behavior() -> None:
    active = ["http_followup", "sql_injection", "port_sweep", HOST_BEHAVIOR_CHECK_SCENARIO_ID]
    ordered = ensure_webshell_phase1_scenarios(
        ["http_followup", "sql_injection", "port_sweep"],
        active_ids=active,
    )
    assert ordered.index(HOST_BEHAVIOR_CHECK_SCENARIO_ID) == 0


def test_resolve_runnable_includes_host_behavior_in_normal_profile() -> None:
    active = [
        "http_followup",
        "sql_injection",
        HOST_BEHAVIOR_CHECK_SCENARIO_ID,
        "port_sweep",
    ]
    resolved = resolve_runnable_scenarios("normal", active)
    assert HOST_BEHAVIOR_CHECK_SCENARIO_ID in resolved
    assert resolved.index(HOST_BEHAVIOR_CHECK_SCENARIO_ID) == 0


def test_webshell_host_target_only() -> None:
    params: dict[str, dict] = {}
    apply_webshell_initial_compromise_plan(
        params,
        [HOST_BEHAVIOR_CHECK_SCENARIO_ID],
        "http://10.10.10.50:8080/shell.jsp",
    )
    plan = build_host_behavior_plan(
        params[HOST_BEHAVIOR_CHECK_SCENARIO_ID],
        run_id="run01",
        dry_run=True,
    )
    assert plan["target_host"] == "10.10.10.50"
    assert plan["mode"] == "mock"
    assert len(plan["commands"]) == 8


def test_aspx_family_guard_skips_linux_commands() -> None:
    params = {
        WEBSHELL_EXECUTION_KEY: {
            "webshell_url": "http://10.10.10.50:8080/shell.jsp",
            "execution_host": "10.10.10.50",
            "execution_port": 8080,
            "execution_path": "/shell.jsp",
            "endpoint": {"host": "10.10.10.50", "port": 8080, "scheme": "http"},
        },
        "webshell_family": "aspx",
    }
    plan = build_host_behavior_plan(params, run_id="run01", dry_run=False, webshell_family="aspx")
    assert plan["mode"] == "skip"
    assert plan["reason"] == "windows_family_placeholder"


def test_remote_planner_uses_webshell_family_from_metadata() -> None:
    params = {}
    apply_webshell_initial_compromise_plan(
        params,
        [HOST_BEHAVIOR_CHECK_SCENARIO_ID],
        "http://10.10.10.77:8080/shell.jsp",
    )
    request = ScenarioExecutionRequest(
        scenario_id=HOST_BEHAVIOR_CHECK_SCENARIO_ID,
        scenario_params=params[HOST_BEHAVIOR_CHECK_SCENARIO_ID],
        execution_metadata={"webshell_family": "jsp"},
        run_id="run-remote",
        target_net="10.10.10.0/24",
        dry_run=True,
    )
    plan = _plan_host_behavior_check(request, params[HOST_BEHAVIOR_CHECK_SCENARIO_ID], dry_run=True)
    assert plan["target_host"] == "10.10.10.77"


def test_host_behavior_check_dry_run_generates_events_without_shell(tmp_runs_dir) -> None:
    params: dict[str, dict] = {}
    apply_webshell_initial_compromise_plan(
        params,
        [HOST_BEHAVIOR_CHECK_SCENARIO_ID],
        "http://10.10.10.50:8080/shell.jsp",
    )
    params[HOST_BEHAVIOR_CHECK_SCENARIO_ID]["webshell_family"] = "jsp"
    with patch("subprocess.run") as run_mock:
        manager = RunManager(runs_dir=tmp_runs_dir)
        run, run_dir, exit_code = manager.run(
            scenario_ids=[
                "http_followup",
                "sql_injection",
                HOST_BEHAVIOR_CHECK_SCENARIO_ID,
            ],
            target_net="10.10.10.0/24",
            dry_run=True,
            scenario_params=params,
        )

    assert exit_code == 0
    assert run.status.value == "completed"
    run_mock.assert_not_called()

    events_path = run_dir / "events.jsonl"
    assert events_path.is_file()
    events = [json.loads(line) for line in events_path.read_text().splitlines() if line.strip()]
    hb_events = [e for e in events if e.get("scenario_id") == HOST_BEHAVIOR_CHECK_SCENARIO_ID]
    event_names = {e["event"] for e in hb_events}
    assert "host_behavior_check_started" in event_names
    assert "host_behavior_command_dispatched" in event_names
    assert "eicar_file_created" in event_names
    assert "eicar_file_accessed" in event_names
    assert "eicar_file_deleted" in event_names
    assert "eicar_variant_created" in event_names
    assert "credential_artifact_enumeration" in event_names
    assert "ssh_key_enumeration" in event_names
    assert "pem_file_enumeration" in event_names
    assert "suspicious_script_created" in event_names
    assert "persistence_artifact_created" in event_names
    assert "archive_created" in event_names
    assert "host_behavior_check_completed" in event_names
    assert sum(1 for e in hb_events if e["event"] == "host_behavior_command_dispatched") == 8
    assert len(hb_events) >= 50

    validation = json.loads((run_dir / "validation.json").read_text())
    hb_result = next(
        r for r in validation["results"] if r["scenario_id"] == HOST_BEHAVIOR_CHECK_SCENARIO_ID
    )
    assert hb_result["decision"] == "success"


def test_host_behavior_check_live_dispatches_shell_commands(tmp_runs_dir) -> None:
    params: dict[str, dict] = {}
    apply_webshell_initial_compromise_plan(
        params,
        [HOST_BEHAVIOR_CHECK_SCENARIO_ID],
        "http://10.10.10.50:8080/shell.jsp",
    )
    params[HOST_BEHAVIOR_CHECK_SCENARIO_ID]["webshell_family"] = "jsp"
    completed = MagicMock(returncode=0, stdout=b"", stderr=b"")
    with patch("subprocess.run", return_value=completed) as run_mock:
        manager = RunManager(runs_dir=tmp_runs_dir)
        _, run_dir, exit_code = manager.run(
            scenario_ids=[HOST_BEHAVIOR_CHECK_SCENARIO_ID],
            target_net="10.10.10.0/24",
            dry_run=False,
            scenario_params=params,
        )

    assert exit_code == 0
    assert run_mock.call_count >= 20


def test_host_behavior_check_plugins_list() -> None:
    from dsp.plugins import PluginLoader, PluginStatus

    registry = PluginLoader().discover_and_load()
    record = registry.get(HOST_BEHAVIOR_CHECK_SCENARIO_ID)
    assert record is not None
    assert record.status == PluginStatus.ACTIVE
