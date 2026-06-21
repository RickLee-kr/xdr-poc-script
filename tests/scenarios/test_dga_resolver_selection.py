"""DGA resolver selection — discovery-only, no hardcoded fallback."""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import MagicMock

from dsp.engine.scenario_engine import RunContext, TargetSet
from dsp.event_store import EventStore
from scenarios.dga.executor import run, select_dga_resolver


def _targets(*, dns_hosts: list[str] | None = None) -> TargetSet:
    return TargetSet(
        target_net="10.10.10.0/24",
        hosts=["10.10.10.97"],
        service_hosts={"dns_hosts": dns_hosts or []},
        service_endpoints={"dns_hosts": [(h, 53) for h in (dns_hosts or [])]},
        discovery_enabled=True,
    )


def test_select_dga_resolver_returns_none_without_dns_hosts() -> None:
    assert select_dga_resolver(_targets(), {}) is None


def test_select_dga_resolver_uses_discovered_dns_hosts() -> None:
    assert select_dga_resolver(_targets(dns_hosts=["10.10.10.98"]), {}) == "10.10.10.98"


def test_select_dga_resolver_honors_explicit_override() -> None:
    assert select_dga_resolver(_targets(), {"resolver": "192.168.1.1"}) == "192.168.1.1"


def test_dga_skipped_when_no_dns_hosts(tmp_path) -> None:
    store = EventStore(tmp_path / "events.db")
    store.open_run("run-dga-skip")
    ctx = RunContext(
        run_id="run-dga-skip",
        target_net="10.10.10.0/24",
        event_store=store,
        config=MagicMock(),
        dry_run=True,
    )
    run(ctx, _targets(), {"phase1_count": 1, "phase2_count": 1})
    events = store.list_events("run-dga-skip")
    assert any(e.event == "dga_skipped" for e in events)
    assert not any(e.event == "dga_started" for e in events)
