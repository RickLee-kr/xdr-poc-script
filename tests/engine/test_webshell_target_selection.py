"""Webshell execution host vs attack target separation tests."""

from __future__ import annotations

import io

from dsp.engine.host_selection import (
    HTTP_ENDPOINT_SELECTION_CACHE_KEY,
    cache_http_endpoint_selection,
    http_target_probe_payload,
    resolve_http_attack_endpoint_selection,
    resolve_http_endpoint_selection,
)
from dsp.engine.scenario_engine import TargetSet
from dsp.execution.remote.bundle.planner import _plan_http_followup, _plan_sql_injection
from dsp.runtime.scenario_plan import (
    DISCOVERED_HTTP_SERVICE_REASON,
    FALLBACK_NO_DISCOVERED_HTTP_REASON,
    INITIAL_COMPROMISE_ENDPOINT_KEY,
    INITIAL_COMPROMISE_SELECTION_REASON,
    PHASE1_WEBSHELL_ATTACK_KEY,
    WEBSHELL_EXECUTION_KEY,
    apply_webshell_initial_compromise_plan,
)
from dsp.runner.console_output import OperationalConsole


def _lab_targets() -> TargetSet:
    return TargetSet(
        target_net="221.139.249.0/24",
        hosts=[
            "221.139.249.110",
            "221.139.249.113",
            "221.139.249.118",
            "221.139.249.122",
            "221.139.249.126",
        ],
        service_hosts={
            "http_targets": [
                "221.139.249.110",
                "221.139.249.113",
                "221.139.249.118",
                "221.139.249.122",
                "221.139.249.126",
            ],
        },
        service_endpoints={
            "http_targets": [
                ("221.139.249.110", 80),
                ("221.139.249.113", 80),
                ("221.139.249.118", 9000),
                ("221.139.249.122", 8080),
                ("221.139.249.126", 80),
            ],
        },
        discovery_enabled=True,
    )


def _webshell_params(scenario_ids: list[str]) -> dict[str, dict]:
    params: dict[str, dict] = {sid: {"max_hosts": 2, "timeout": 2.0} for sid in scenario_ids}
    apply_webshell_initial_compromise_plan(
        params,
        scenario_ids,
        "http://10.10.10.50:8080/shell.jsp",
    )
    cache_http_endpoint_selection(
        params,
        scenario_ids=scenario_ids,
        targets=_lab_targets(),
        dry_run=True,
    )
    return params


def test_webshell_http_attack_targets_use_discovered_hosts_not_webshell_host() -> None:
    params = _webshell_params(["http_followup"])
    targets = _lab_targets()

    selection = resolve_http_endpoint_selection(
        targets,
        params["http_followup"],
        max_hosts=2,
        dry_run=True,
    )
    assert selection.selected
    assert all(ep.host.startswith("221.139.249.") for ep in selection.selected)
    assert all(ep.host != "10.10.10.50" for ep in selection.selected)
    assert selection.selected_http_target_reason == DISCOVERED_HTTP_SERVICE_REASON

    remote_plan = _plan_http_followup(targets, params["http_followup"], dry_run=True)
    assert remote_plan["requests"]
    assert all("221.139.249." in item["url"] for item in remote_plan["requests"])
    assert all("10.10.10.50" not in item["url"] for item in remote_plan["requests"])


def test_webshell_sql_attack_targets_use_discovered_hosts_not_webshell_host() -> None:
    params = _webshell_params(["sql_injection"])
    targets = _lab_targets()

    selection = resolve_http_endpoint_selection(
        targets,
        params["sql_injection"],
        max_hosts=2,
        dry_run=True,
    )
    assert selection.selected[0].host.startswith("221.139.249.")

    remote_plan = _plan_sql_injection(targets, params["sql_injection"], dry_run=True)
    assert remote_plan["requests"]
    assert "221.139.249." in remote_plan["requests"][0]["url"]
    assert "10.10.10.50" not in remote_plan["requests"][0]["url"]


def test_initial_compromise_host_only_for_explicit_phase1_or_no_discovery() -> None:
    targets = TargetSet(
        target_net="10.10.10.0/24",
        service_hosts={},
        service_endpoints={},
        discovery_enabled=True,
    )
    params: dict[str, dict] = {"http_followup": {"max_hosts": 1, "timeout": 2.0}}
    apply_webshell_initial_compromise_plan(params, ["http_followup"], "http://10.10.10.50:8080/shell.jsp")

    fallback = resolve_http_attack_endpoint_selection(
        targets,
        params["http_followup"],
        max_hosts=1,
        dry_run=True,
    )
    assert fallback.selected[0].host == "10.10.10.50"
    assert fallback.selected_http_target_reason == FALLBACK_NO_DISCOVERED_HTTP_REASON

    params["http_followup"][PHASE1_WEBSHELL_ATTACK_KEY] = True
    phase1 = resolve_http_attack_endpoint_selection(
        targets,
        params["http_followup"],
        max_hosts=1,
        dry_run=True,
    )
    assert phase1.selected[0].host == "10.10.10.50"
    assert phase1.selected_http_target_reason == INITIAL_COMPROMISE_SELECTION_REASON


def test_host_behavior_still_receives_initial_compromise_endpoint() -> None:
    params: dict[str, dict] = {}
    apply_webshell_initial_compromise_plan(
        params,
        ["host_behavior_check"],
        "http://10.10.10.50:8080/shell.jsp",
    )
    endpoint = params["host_behavior_check"][INITIAL_COMPROMISE_ENDPOINT_KEY]
    assert endpoint["host"] == "10.10.10.50"
    assert endpoint["port"] == 8080
    assert INITIAL_COMPROMISE_ENDPOINT_KEY not in params.get("http_followup", {})


def test_console_output_separates_execution_host_and_attack_targets() -> None:
    stream = io.StringIO()
    console = OperationalConsole(stream=stream)
    console.handle_progress(
        "targets_selected",
        {
            "execution_host": {
                "host": "10.10.10.50",
                "port": 8080,
                "path": "/shell.jsp",
            },
            "webshell_url": "http://10.10.10.50:8080/shell.jsp",
            "attack_target_net": "221.139.249.0/24",
            "groups": {
                "HTTP": ["221.139.249.110", "221.139.249.113"],
            },
        },
    )
    output = stream.getvalue()
    assert "Execution Host:" in output
    assert "10.10.10.50:8080/shell.jsp" in output
    assert "Attack Targets:" in output
    assert "221.139.249.110" in output
    assert "Attack Target Net: 221.139.249.0/24" in output


def test_http_probe_payload_splits_webshell_and_attack_diagnostics() -> None:
    params = _webshell_params(["http_followup"])
    targets = _lab_targets()
    selection = resolve_http_endpoint_selection(
        targets,
        params["http_followup"],
        max_hosts=2,
        dry_run=True,
    )
    ws_ctx = params[WEBSHELL_EXECUTION_KEY]
    payload = http_target_probe_payload(
        selection,
        discovered_http_hosts=targets.hosts_for_capability("http_targets"),
        webshell_execution=ws_ctx,
        attack_target_net=targets.target_net,
    )
    assert payload["execution_host"] == "10.10.10.50"
    assert payload["webshell_url"] == "http://10.10.10.50:8080/shell.jsp"
    assert payload["attack_target_net"] == "221.139.249.0/24"
    assert payload["selected_target_reason"] == DISCOVERED_HTTP_SERVICE_REASON
    assert payload["webshell_endpoint_diagnostics"]
    assert payload["discovered_attack_http_endpoints"]
    assert INITIAL_COMPROMISE_ENDPOINT_KEY not in params["http_followup"]
    assert HTTP_ENDPOINT_SELECTION_CACHE_KEY in params["http_followup"]
