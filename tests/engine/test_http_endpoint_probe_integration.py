"""Integration tests — HTTP endpoint probe selection via mocked curl transport."""

from __future__ import annotations

from collections import defaultdict

import pytest

from dsp.engine import RunConfig
from dsp.engine.host_selection import (
    HTTP_ENDPOINT_SELECTION_CACHE_KEY,
    SKIP_REASON_HTTP_TARGETS_NOT_FOUND,
    probe_and_select_http_followup_endpoints,
    selection_to_cache,
)
from dsp.engine.scenario_engine import RunContext, ScenarioSkipError, TargetSet
from dsp.event_store import EventStore
from dsp.protocols.http.curl_transport import CurlHttpResult, endpoint_key_from_url
from dsp.protocols.http.target_probe import (
    HTTPEndpointProbeResult,
    is_selectable_http_endpoint,
)
from scenarios.http_followup import executor as http_followup_executor
from scenarios.sql_injection import executor as sql_injection_executor


def _targets(*, hosts: list[str], endpoints: list[tuple[str, int]]) -> TargetSet:
    return TargetSet(
        target_net="10.10.10.0/24",
        service_hosts={"http_targets": hosts},
        service_endpoints={"http_targets": endpoints},
        discovery_enabled=True,
    )


def _install_curl_mock(monkeypatch, endpoint_map: dict[tuple[str, int], CurlHttpResult]):
    call_counts: dict[tuple[str, int], int] = defaultdict(int)

    def fake_curl_http_request(url: str, **kwargs) -> CurlHttpResult:
        host, port = endpoint_key_from_url(url)
        key = (host, port)
        if key not in endpoint_map:
            return CurlHttpResult(outcome="connection_refused", status_code=None, exit_code=7)
        call_counts[key] += 1
        return endpoint_map[key]

    monkeypatch.setattr(
        "dsp.protocols.http.target_probe.curl_http_request",
        fake_curl_http_request,
    )
    return call_counts


def _select(monkeypatch, targets: TargetSet, endpoint_map: dict[tuple[str, int], CurlHttpResult]):
    _install_curl_mock(monkeypatch, endpoint_map)
    return probe_and_select_http_followup_endpoints(
        targets,
        {},
        max_hosts=1,
        dry_run=False,
        timeout=3.0,
    )


def test_http_11_400_is_selectable(monkeypatch):
    selection = _select(
        monkeypatch,
        _targets(hosts=["10.10.10.20"], endpoints=[("10.10.10.20", 8080)]),
        {
            ("10.10.10.20", 8080): CurlHttpResult(
                outcome="response",
                status_code=400,
                http_version="1.1",
            )
        },
    )
    assert selection.selected
    assert selection.selected[0].port == 8080
    assert is_selectable_http_endpoint(selection.selected[0])
    assert selection.selected[0].http_versions.get("1.1", 0) > 0


def test_http_10_400_is_selectable(monkeypatch):
    selection = _select(
        monkeypatch,
        _targets(hosts=["10.10.10.20"], endpoints=[("10.10.10.20", 9000)]),
        {
            ("10.10.10.20", 9000): CurlHttpResult(
                outcome="response",
                status_code=400,
                http_version="1.0",
            )
        },
    )
    assert selection.selected
    assert selection.selected[0].port == 9000
    assert selection.selected[0].http_versions.get("1.0", 0) > 0


def test_http_11_301_is_redirect_only_rejected(monkeypatch):
    selection = _select(
        monkeypatch,
        _targets(hosts=["10.10.10.20"], endpoints=[("10.10.10.20", 80)]),
        {
            ("10.10.10.20", 80): CurlHttpResult(
                outcome="response",
                status_code=301,
                http_version="1.1",
            )
        },
    )
    assert not selection.selected
    assert selection.skip_reason == SKIP_REASON_HTTP_TARGETS_NOT_FOUND
    probed = selection.probed[0]
    assert probed.is_redirect_only
    assert probed.rejection_reason == "redirect_only"


def test_connection_refused_is_rejected(monkeypatch):
    selection = _select(
        monkeypatch,
        _targets(hosts=["10.10.10.20"], endpoints=[("10.10.10.20", 8080)]),
        {
            ("10.10.10.20", 8080): CurlHttpResult(
                outcome="connection_refused",
                status_code=None,
                exit_code=7,
            )
        },
    )
    assert not selection.selected
    assert selection.probed[0].errors > 0
    assert selection.probed[0].rejection_reason in {
        "connection_error",
        "timeout_or_connection_error",
    }


def test_selected_endpoint_passes_unchanged_to_http_followup_executor(monkeypatch):
    selected_port = 8080
    targets = _targets(
        hosts=["10.10.10.20"],
        endpoints=[("10.10.10.20", 80), ("10.10.10.20", selected_port)],
    )
    selection = _select(
        monkeypatch,
        targets,
        {
            ("10.10.10.20", 80): CurlHttpResult(outcome="response", status_code=301, http_version="1.1"),
            ("10.10.10.20", selected_port): CurlHttpResult(
                outcome="response",
                status_code=400,
                http_version="1.1",
            ),
        },
    )
    assert selection.selected[0].port == selected_port
    store = EventStore(":memory:")
    run_id = "followup_endpoint_passthrough"
    store.open_run(run_id)
    scenario_params = {
        "max_hosts": 1,
        "max_total": 5,
        "max_per_host": 5,
        HTTP_ENDPOINT_SELECTION_CACHE_KEY: selection_to_cache(selection),
    }
    ctx = RunContext(
        run_id=run_id,
        target_net="10.10.10.0/24",
        event_store=store,
        config=RunConfig(dry_run=True, scenario_params={"http_followup": scenario_params}),
        dry_run=True,
    )
    http_followup_executor.run(ctx, targets, scenario_params)
    started = next(e for e in store.list_events(run_id) if e.event == "http_followup_started")
    completed = next(e for e in store.list_events(run_id) if e.event == "http_followup_completed")
    assert started.evidence["endpoints"][0]["port"] == selected_port
    assert completed.evidence["requests_sent"] > 0
    assert selected_port in completed.evidence["ports_used"]
    assert all(
        f":{selected_port}" in url or f":{selected_port}/" in url
        for url in completed.evidence.get("sample_urls", [])
        if url
    ) or selected_port in completed.evidence["ports_used"]


def test_selected_endpoint_passes_unchanged_to_sql_injection_executor(monkeypatch):
    selected_port = 9000
    targets = _targets(
        hosts=["10.10.10.20"],
        endpoints=[("10.10.10.20", 80), ("10.10.10.20", selected_port)],
    )
    selection = _select(
        monkeypatch,
        targets,
        {
            ("10.10.10.20", 80): CurlHttpResult(outcome="response", status_code=301, http_version="1.1"),
            ("10.10.10.20", selected_port): CurlHttpResult(
                outcome="response",
                status_code=400,
                http_version="1.1",
            ),
        },
    )
    assert selection.selected[0].port == selected_port
    store = EventStore(":memory:")
    run_id = "sqli_endpoint_passthrough"
    store.open_run(run_id)
    scenario_params = {
        "max_hosts": 1,
        "max_total": 5,
        "max_per_host": 5,
        HTTP_ENDPOINT_SELECTION_CACHE_KEY: selection_to_cache(selection),
    }
    ctx = RunContext(
        run_id=run_id,
        target_net="10.10.10.0/24",
        event_store=store,
        config=RunConfig(dry_run=True, scenario_params={"sql_injection": scenario_params}),
        dry_run=True,
    )
    sql_injection_executor.run(ctx, targets, scenario_params)
    started = next(e for e in store.list_events(run_id) if e.event == "sql_injection_started")
    completed = next(e for e in store.list_events(run_id) if e.event == "sql_injection_completed")
    assert started.evidence["endpoints"][0]["port"] == selected_port
    assert completed.evidence["requests_sent"] > 0
    assert selected_port in completed.evidence["ports_used"]


def test_no_completed_event_when_requests_sent_zero(monkeypatch):
    targets = _targets(hosts=["10.10.10.20"], endpoints=[("10.10.10.20", 8080)])
    selection = _select(
        monkeypatch,
        targets,
        {
            ("10.10.10.20", 8080): CurlHttpResult(
                outcome="connection_refused",
                status_code=None,
                exit_code=7,
            )
        },
    )
    assert not selection.selected
    store = EventStore(":memory:")
    run_id = "zero_send_skip"
    store.open_run(run_id)
    scenario_params = {
        HTTP_ENDPOINT_SELECTION_CACHE_KEY: selection_to_cache(selection),
        "max_hosts": 1,
        "max_total": 5,
        "max_per_host": 5,
    }
    ctx = RunContext(
        run_id=run_id,
        target_net="10.10.10.0/24",
        event_store=store,
        config=RunConfig(dry_run=True, scenario_params={"http_followup": scenario_params}),
        dry_run=True,
    )
    with pytest.raises(ScenarioSkipError):
        http_followup_executor.run(ctx, targets, scenario_params)
    assert not [e for e in store.list_events(run_id) if e.event == "http_followup_completed"]
    skipped = [e for e in store.list_events(run_id) if e.event == "http_followup_skipped"]
    assert skipped
    assert skipped[0].evidence["requests_sent"] == 0


def test_probe_result_is_canonical_across_selection_and_summaries(monkeypatch):
    selection = _select(
        monkeypatch,
        _targets(hosts=["10.10.10.20"], endpoints=[("10.10.10.20", 8080)]),
        {
            ("10.10.10.20", 8080): CurlHttpResult(
                outcome="response",
                status_code=400,
                http_version="1.1",
            )
        },
    )
    assert isinstance(selection.selected[0], HTTPEndpointProbeResult)
    selected_row = next(
        row
        for row in selection.probe_summaries
        if row["host"] == selection.selected[0].host and row["port"] == selection.selected[0].port
    )
    assert selected_row["host"] == selection.selected[0].host
    assert selected_row["port"] == selection.selected[0].port
    assert selected_row["selected"] is True
