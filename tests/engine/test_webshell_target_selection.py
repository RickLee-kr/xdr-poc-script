"""Webshell execution host vs attack target separation tests."""

from __future__ import annotations

import io
import json
import tempfile
from pathlib import Path
from unittest.mock import patch
from urllib.parse import urlparse

from tests.e2e.fixtures.webshell_test_server import WebshellTestServer

from dsp.engine.host_selection import (
    HTTP_ENDPOINT_SELECTION_CACHE_KEY,
    cache_http_endpoint_selection,
    http_target_probe_payload,
    resolve_http_attack_endpoint_selection,
    resolve_http_endpoint_selection,
)
from dsp.engine.scenario_engine import TargetSet
from dsp.execution.remote.bundle.planner import _plan_http_followup, _plan_sql_injection
from dsp.protocols.http.target_probe import HTTPEndpointProbeResult
from dsp.runner import RunManager
from dsp.runtime.scenario_plan import (
    DISCOVERED_HTTP_SERVICE_REASON,
    DISCOVERED_HTTP_SERVICE_UNVERIFIED_FROM_DSP_HOST,
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


def _failed_dsp_probe_results(targets: TargetSet) -> list[HTTPEndpointProbeResult]:
    probed: list[HTTPEndpointProbeResult] = []
    for host, port in targets.service_endpoints.get("http_targets", []):
        probed.append(
            HTTPEndpointProbeResult(
                host=host,
                port=port,
                scheme="http",
                errors=7,
                rejection_reason="connection_error",
            )
        )
    return probed


def test_webshell_keeps_discovered_hosts_when_dsp_probe_fails() -> None:
    targets = _lab_targets()
    params: dict[str, dict] = {
        "http_followup": {"max_hosts": 2, "timeout": 2.0},
        "sql_injection": {"max_hosts": 2, "timeout": 2.0},
    }
    apply_webshell_initial_compromise_plan(
        params,
        ["http_followup", "sql_injection"],
        "http://10.10.10.50:8080/shell.jsp",
    )

    with patch(
        "dsp.engine.host_selection.probe_all_http_candidates",
        return_value=_failed_dsp_probe_results(targets),
    ):
        cache_http_endpoint_selection(
            params,
            scenario_ids=["http_followup", "sql_injection"],
            targets=targets,
            dry_run=False,
        )

    http_selection = resolve_http_endpoint_selection(
        targets,
        params["http_followup"],
        max_hosts=2,
        dry_run=False,
    )
    sql_selection = resolve_http_endpoint_selection(
        targets,
        params["sql_injection"],
        max_hosts=2,
        dry_run=False,
    )

    assert http_selection.selected
    assert sql_selection.selected
    assert all(ep.host.startswith("221.139.249.") for ep in http_selection.selected)
    assert all(ep.host.startswith("221.139.249.") for ep in sql_selection.selected)
    assert all(ep.host != "10.10.10.50" for ep in http_selection.selected)
    assert (
        http_selection.selected_http_target_reason
        == DISCOVERED_HTTP_SERVICE_UNVERIFIED_FROM_DSP_HOST
    )
    assert http_selection.selected[0].selection_reason == (
        DISCOVERED_HTTP_SERVICE_UNVERIFIED_FROM_DSP_HOST
    )

    http_plan = _plan_http_followup(targets, params["http_followup"], dry_run=False)
    sql_plan = _plan_sql_injection(targets, params["sql_injection"], dry_run=False)
    assert all("221.139.249." in item["url"] for item in http_plan["requests"])
    assert all("221.139.249." in item["url"] for item in sql_plan["requests"])
    assert all("10.10.10.50" not in item["url"] for item in http_plan["requests"])
    assert all("127.0.0.1" not in item["url"] for item in http_plan["requests"])

    burst = http_plan.get("non_standard_port_burst") or {}
    if burst.get("enabled"):
        burst_hosts = {item["host"] for item in burst.get("requests") or []}
        main_hosts = {urlparse(item["url"]).hostname for item in http_plan["requests"]}
        assert burst_hosts.issubset(
            {
                "221.139.249.110",
                "221.139.249.113",
                "221.139.249.118",
                "221.139.249.122",
                "221.139.249.126",
            }
        )
        assert all(h and h.startswith("221.139.249.") for h in main_hosts)


def test_webshell_stage_regression_probe_fail_preserves_221_targets() -> None:
    tmpdir = Path(tempfile.mkdtemp())
    server = WebshellTestServer(storage_dir=tmpdir / "remote-storage")
    url = server.start()
    ws_host = urlparse(url).hostname

    targets = TargetSet(
        target_net="221.139.249.0/24",
        hosts=["221.139.249.110", "221.139.249.118", "221.139.249.113"],
        service_hosts={
            "http_targets": ["221.139.249.110", "221.139.249.118", "221.139.249.113"],
        },
        service_endpoints={
            "http_targets": [
                ("221.139.249.110", 80),
                ("221.139.249.118", 9000),
                ("221.139.249.113", 8888),
            ],
        },
        discovery_enabled=True,
    )

    with patch(
        "dsp.engine.host_selection.probe_all_http_candidates",
        return_value=_failed_dsp_probe_results(targets),
    ):
        with patch("dsp.runner.run_manager.resolve_targets", return_value=targets):
            manager = RunManager(runs_dir=tmpdir / "runs")
            run, run_dir, exit_code = manager.run(
                scenario_ids=["http_followup"],
                target_net="221.139.249.0/24",
                dry_run=False,
                execution_provider="webshell",
                webshell_url=url,
                webshell_family="jsp",
                remote_work_dir=str(tmpdir / "remote-work"),
                scenario_params={
                    "http_followup": {
                        "max_hosts": 2,
                        "max_per_host": 2,
                        "max_total": 4,
                        "timeout": 5.0,
                        "non_standard_port_burst": {"enabled": False},
                    }
                },
            )

    probe = json.loads((run_dir / "http_target_probe.json").read_text())
    discovered = probe.get("discovered_attack_http_endpoints") or probe.get(
        "discovery_http_hosts"
    )
    selected = probe.get("selected_targets") or []
    assert all(h.startswith("221.139.249.") for h in discovered)
    assert selected
    assert all("221.139.249." in label for label in selected)
    assert probe.get("selected_target_reason") == (
        DISCOVERED_HTTP_SERVICE_UNVERIFIED_FROM_DSP_HOST
    )
    assert ws_host not in "".join(selected)
    assert "127.0.0.1" not in "".join(selected)

    manifest_files = list((tmpdir / "remote-storage").rglob("manifest.json"))
    assert manifest_files
    manifest = json.loads(manifest_files[0].read_text())
    urls = [r["url"] for r in manifest.get("plan", {}).get("requests", [])]
    assert urls
    assert all("221.139.249." in url for url in urls)
    assert all(ws_host not in url for url in urls)

    events = [
        json.loads(line)
        for line in (run_dir / "events.jsonl").read_text().splitlines()
        if line.strip()
    ]
    sent = [
        e
        for e in events
        if e.get("event") == "http_request_sent" and e.get("scenario_id") == "http_followup"
    ]
    assert sent
    assert all("221.139.249." in e.get("target", "") for e in sent)
    assert all(e.get("source") == "remote" for e in sent)
    assert exit_code == 0
    server.stop()


def test_webshell_console_shows_unverified_discovered_hosts_on_dsp_probe_fail() -> None:
    targets = _lab_targets()
    params: dict[str, dict] = {"http_followup": {"max_hosts": 2, "timeout": 2.0}}
    apply_webshell_initial_compromise_plan(
        params,
        ["http_followup"],
        "http://10.10.10.50:8080/shell.jsp",
    )
    with patch(
        "dsp.engine.host_selection.probe_all_http_candidates",
        return_value=_failed_dsp_probe_results(targets),
    ):
        cache_http_endpoint_selection(
            params,
            scenario_ids=["http_followup"],
            targets=targets,
            dry_run=False,
        )
    selection = resolve_http_endpoint_selection(
        targets,
        params["http_followup"],
        max_hosts=2,
        dry_run=False,
    )
    payload = http_target_probe_payload(
        selection,
        discovered_http_hosts=targets.hosts_for_capability("http_targets"),
        webshell_execution=params[WEBSHELL_EXECUTION_KEY],
        attack_target_net=targets.target_net,
    )
    stream = io.StringIO()
    console = OperationalConsole(stream=stream)
    console.handle_progress("http_probe_diagnostics", payload)
    output = stream.getvalue()
    assert "Discovered HTTP attack hosts:" in output
    assert "221.139.249.110" in output
    assert "DSP-side endpoint probe:" in output
    assert "Webshell mode decision:" in output
    assert "keeping discovered attack hosts" in output
    assert "Selected attack targets:" in output
    assert DISCOVERED_HTTP_SERVICE_UNVERIFIED_FROM_DSP_HOST in output
