"""Webshell HTTP endpoint selection cache — shared across http_followup and sql_injection."""

from __future__ import annotations

from unittest.mock import patch

from dsp.engine.host_selection import (
    HTTP_ENDPOINT_SELECTION_CACHE_KEY,
    cache_http_endpoint_selection,
    resolve_http_endpoint_selection,
)
from dsp.engine.scenario_engine import TargetSet
from dsp.execution.remote.command.discovery import emit_webshell_discovery_progress
from dsp.engine import RunConfig, RunContext
from dsp.event_store import EventStore


def _discovery_targets() -> dict:
    return {
        "target_net": "10.10.10.0/24",
        "hosts": ["10.10.10.97", "10.10.10.98"],
        "service_hosts": {
            "http_targets": ["10.10.10.97"],
            "ssh_hosts": ["10.10.10.98"],
        },
        "service_endpoints": {
            "http_targets": [("10.10.10.97", 8080)],
            "ssh_hosts": [("10.10.10.98", 22)],
        },
        "discovery_enabled": True,
        "discovery_meta": {
            "alive_hosts": ["10.10.10.97", "10.10.10.98"],
            "open_endpoints": 2,
            "probed_hosts": 254,
        },
    }


def test_webshell_discovery_populates_shared_http_cache(tmp_path) -> None:
    store = EventStore(tmp_path / "events.db")
    store.open_run("run-cache")
    scenario_params: dict[str, dict] = {
        "http_followup": {"max_hosts": 1},
        "sql_injection": {"max_hosts": 1},
    }
    ctx = RunContext(
        run_id="run-cache",
        target_net="10.10.10.0/24",
        event_store=store,
        config=RunConfig(scenario_params=scenario_params),
        dry_run=True,
        scenario_ids=["http_followup", "sql_injection"],
    )
    emit_webshell_discovery_progress(ctx, targets=_discovery_targets())

    http_cache = scenario_params["http_followup"].get(HTTP_ENDPOINT_SELECTION_CACHE_KEY)
    sqli_cache = scenario_params["sql_injection"].get(HTTP_ENDPOINT_SELECTION_CACHE_KEY)
    assert http_cache is not None
    assert http_cache == sqli_cache


def test_cached_http_selection_avoids_reprobe() -> None:
    targets = TargetSet(
        target_net="10.10.10.0/24",
        hosts=["10.10.10.97"],
        service_hosts={"http_targets": ["10.10.10.97"]},
        service_endpoints={"http_targets": [("10.10.10.97", 8080)]},
        discovery_enabled=True,
    )
    scenario_params: dict[str, dict] = {
        "http_followup": {"max_hosts": 1},
        "sql_injection": {"max_hosts": 1},
    }
    cache_http_endpoint_selection(
        scenario_params,
        scenario_ids=["http_followup", "sql_injection"],
        targets=targets,
        dry_run=True,
        webshell_mode=True,
    )
    with patch(
        "dsp.engine.host_selection.resolve_http_attack_endpoint_selection",
    ) as probe:
        followup = resolve_http_endpoint_selection(
            targets,
            scenario_params["http_followup"],
            max_hosts=1,
            dry_run=True,
        )
        sqli = resolve_http_endpoint_selection(
            targets,
            scenario_params["sql_injection"],
            max_hosts=1,
            dry_run=True,
        )
        probe.assert_not_called()
    assert followup.selected
    assert sqli.selected
    assert followup.selected[0].host == sqli.selected[0].host == "10.10.10.97"
