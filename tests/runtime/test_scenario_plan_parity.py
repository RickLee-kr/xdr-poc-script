"""Provider-independent scenario planning parity and bash regression tests."""

from __future__ import annotations

from dsp.engine.scenario_engine import TargetSet
from dsp.engine.target_engine import resolve_targets
from dsp.execution.remote.bundle.planner import _plan_http_followup, _plan_port_sweep, _plan_sql_injection
from dsp.runner.target_selection import resolve_scenario_targets, scenario_start_metadata
from dsp.runtime.operational_profiles import build_operational_scenario_params
from dsp.runtime.scenario_plan import build_port_sweep_plan_view


def _targets_with_alive(*alive: str) -> TargetSet:
    return TargetSet(
        target_net="10.10.10.0/24",
        hosts=list(alive),
        discovery_enabled=True,
        discovery_meta={"alive_hosts": list(alive)},
    )


def test_low_profile_port_sweep_does_not_scan_full_slash24() -> None:
    params = build_operational_scenario_params(
        "low",
        ["port_sweep"],
        target_net="10.10.10.0/24",
    )
    assert params["port_sweep"]["max_hosts"] == 1

    targets = _targets_with_alive("10.10.10.97", "10.10.10.98", "10.10.10.99")
    plan = build_port_sweep_plan_view(targets, params["port_sweep"])
    assert plan.planned_probes == 10
    assert plan.selected_hosts == ["10.10.10.97"]
    assert plan.selection_reason == "alive_hosts"
    assert plan.full_sweep_requested is False


def test_low_profile_planned_probes_bounded_for_webshell_execution() -> None:
    params = build_operational_scenario_params(
        "low",
        ["port_sweep"],
        target_net="10.10.10.0/24",
    )
    targets = resolve_targets("10.10.10.0/24", max_hosts=254, discovery=False, dry_run=True)
    plan = build_port_sweep_plan_view(targets, params["port_sweep"])
    assert plan.planned_probes <= 10


def test_high_profile_allows_intentional_full_sweep() -> None:
    params = build_operational_scenario_params(
        "high",
        ["port_sweep"],
        target_net="10.10.10.0/24",
    )
    assert params["port_sweep"]["max_hosts"] == 254
    targets = resolve_targets("10.10.10.0/24", max_hosts=254, discovery=False, dry_run=True)
    plan = build_port_sweep_plan_view(targets, params["port_sweep"])
    assert plan.planned_probes == 2540
    assert plan.full_sweep_requested is False


def test_explicit_full_sweep_params_bypass_profile_host_cap() -> None:
    params = build_operational_scenario_params(
        "low",
        ["port_sweep"],
        target_net="10.10.10.0/24",
    )
    params["port_sweep"]["full_sweep"] = True
    params["port_sweep"]["max_hosts"] = 254
    targets = resolve_targets("10.10.10.0/24", max_hosts=254, discovery=False, dry_run=True)
    plan = build_port_sweep_plan_view(targets, params["port_sweep"])
    assert plan.full_sweep_requested is True
    assert plan.planned_probes == 2540


def test_local_and_webshell_port_sweep_plan_parity() -> None:
    params = build_operational_scenario_params(
        "low",
        ["port_sweep"],
        target_net="10.10.10.0/24",
    )
    targets = _targets_with_alive("10.10.10.97", "10.10.10.98")

    local_plan = build_port_sweep_plan_view(targets, params["port_sweep"])
    local_hosts = resolve_scenario_targets("port_sweep", targets, params["port_sweep"])
    remote_plan = _plan_port_sweep(targets, params["port_sweep"], dry_run=False)

    assert local_hosts == local_plan.selected_hosts
    assert len(remote_plan["probes"]) == local_plan.planned_probes


def test_local_and_webshell_http_followup_endpoint_parity() -> None:
    from dsp.engine.host_selection import (
        HTTP_ENDPOINT_SELECTION_CACHE_KEY,
        HttpFollowupSelection,
        selection_to_cache,
    )
    from dsp.protocols.http.target_probe import HTTPEndpointProbeResult

    params = build_operational_scenario_params(
        "low",
        ["http_followup"],
        target_net="10.10.10.0/24",
    )
    targets = TargetSet(
        target_net="10.10.10.0/24",
        hosts=["10.10.10.97"],
        service_hosts={"http_targets": ["10.10.10.97"]},
        service_endpoints={"http_targets": [("10.10.10.97", 8080)]},
        discovery_enabled=True,
    )
    selected = HTTPEndpointProbeResult(
        host="10.10.10.97",
        port=8080,
        scheme="http",
        status_counts={404: 1},
        selected=True,
        selection_reason="error_responses_available",
    )
    params["http_followup"][HTTP_ENDPOINT_SELECTION_CACHE_KEY] = selection_to_cache(
        HttpFollowupSelection(probed=[selected], selected=[selected])
    )

    local_meta = scenario_start_metadata("http_followup", targets, params["http_followup"])
    remote_plan = _plan_http_followup(targets, params["http_followup"], dry_run=False)

    assert local_meta["selected_targets"] == ["10.10.10.97:8080 (error_responses_available)"]
    assert remote_plan["requests"]
    assert remote_plan["requests"][0]["url"].startswith("http://10.10.10.97:8080")


def test_local_and_webshell_sql_injection_endpoint_parity() -> None:
    from dsp.engine.host_selection import (
        HTTP_ENDPOINT_SELECTION_CACHE_KEY,
        HttpFollowupSelection,
        selection_to_cache,
    )
    from dsp.protocols.http.target_probe import HTTPEndpointProbeResult

    params = build_operational_scenario_params(
        "normal",
        ["sql_injection"],
        target_net="10.10.10.0/24",
    )
    targets = TargetSet(
        target_net="10.10.10.0/24",
        hosts=["10.10.10.97"],
        service_hosts={"http_targets": ["10.10.10.97"]},
        service_endpoints={"http_targets": [("10.10.10.97", 8080)]},
        discovery_enabled=True,
    )
    selected = HTTPEndpointProbeResult(
        host="10.10.10.97",
        port=8080,
        scheme="http",
        status_counts={500: 1},
        selected=True,
        selection_reason="error_responses_available",
    )
    params["sql_injection"][HTTP_ENDPOINT_SELECTION_CACHE_KEY] = selection_to_cache(
        HttpFollowupSelection(probed=[selected], selected=[selected])
    )

    local_meta = scenario_start_metadata("sql_injection", targets, params["sql_injection"])
    remote_plan = _plan_sql_injection(targets, params["sql_injection"], dry_run=False)

    assert local_meta["selected_targets"] == ["10.10.10.97:8080 (error_responses_available)"]
    assert remote_plan["requests"]


def test_bash_parity_low_profile_metadata_documents_bounded_selection() -> None:
    params = build_operational_scenario_params(
        "low",
        ["port_sweep"],
        target_net="10.10.10.0/24",
    )
    targets = _targets_with_alive("10.10.10.97")
    meta = scenario_start_metadata(
        "port_sweep",
        targets,
        params["port_sweep"],
        profile="low",
    )
    assert meta["profile"] == "low"
    assert meta["targets"] == 1
    assert meta["planned_probes"] == 10
    assert meta["selection_reason"] == "alive_hosts"
    assert meta["full_sweep_requested"] is False


def test_remote_timeout_regression_low_profile_probe_count(tmp_path) -> None:
    """Low profile must stay bounded so short webshell timeouts can still succeed."""
    from tests.e2e.fixtures.webshell_test_server import WebshellTestServer
    from dsp.runner.run_manager import RunManager

    server = WebshellTestServer(
        storage_dir=tmp_path / "storage",
        script_stdout_mode="command_timeout",
    )
    server.start()
    manager = RunManager(runs_dir=tmp_path / "runs")
    try:
        _, run_dir, exit_code = manager.run(
            scenario_ids=["port_sweep"],
            target_net="10.10.10.0/24",
            dry_run=False,
            operational_profile="low",
            execution_provider="webshell",
            webshell_family="jsp",
            webshell_url=server.webshell_url,
            remote_work_dir=str(tmp_path / "remote-work"),
        )
        assert exit_code == 0
        meta = scenario_start_metadata(
            "port_sweep",
            _targets_with_alive("10.10.10.97"),
            build_operational_scenario_params(
                "low",
                ["port_sweep"],
                target_net="10.10.10.0/24",
            )["port_sweep"],
            profile="low",
        )
        assert meta["planned_probes"] <= 10
        assert (run_dir / "events.jsonl").is_file()
    finally:
        server.stop()
