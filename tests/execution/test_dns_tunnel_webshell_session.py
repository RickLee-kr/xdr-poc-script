"""Webshell DNS tunnel session dispatch tests."""

from __future__ import annotations

from unittest.mock import MagicMock

from dsp.engine import RunConfig, RunContext
from dsp.engine.scenario_engine import TargetSet
from dsp.event_store import EventQuery, EventStore
from dsp.execution.remote.command.execute import execute_command_plan
from dsp.execution.remote.command.models import DNS_QUERY_METHOD_PYTHON_SOCKET_UDP53
from dsp.execution.remote.command.planner import _plan_dns_tunnel
from dsp.execution.remote.models import ScenarioExecutionRequest
from dsp.protocols.dns.tunnel import (
    CHUNK_SIZE_DEFAULT,
    MOCK_PAYLOAD_FILENAME,
    PAYLOAD_MB_DEFAULT,
    TUNNEL_DOMAIN_DEFAULT,
    build_tunnel_end_fqdn,
    build_tunnel_start_fqdn,
    plan_chunk_count,
    plan_dns_tunnel,
)


def _targets() -> TargetSet:
    return TargetSet(
        target_net="10.10.10.0/24",
        hosts=["10.10.10.97"],
        service_hosts={"dns_hosts": [], "http_targets": ["10.10.10.97"]},
        discovery_enabled=True,
        discovery_meta={"alive_hosts": ["10.10.10.97"]},
    )


def test_webshell_dns_tunnel_one_http_dispatch_per_target(tmp_path) -> None:
    store = EventStore(tmp_path / "events.db")
    store.open_run("run-session")
    ctx = RunContext(
        run_id="run-session",
        target_net="10.10.10.0/24",
        event_store=store,
        config=RunConfig(dry_run=False),
        dry_run=False,
    )
    params = {
        "payload_mb": 0.0001,
        "max_chunks": 3,
        "domain": TUNNEL_DOMAIN_DEFAULT,
        "max_hosts": 1,
        "plan_seed": 42,
    }
    plan = plan_dns_tunnel(_targets(), params, dry_run=False)
    provider = MagicMock()
    provider.execute_command.return_value = MagicMock(status=MagicMock(value="completed"))

    http_calls = execute_command_plan(
        plan,
        provider,
        ctx,
        ScenarioExecutionRequest(
            run_id="run-session",
            scenario_id="dns_tunnel",
            target_net="10.10.10.0/24",
            dry_run=False,
            scenario_params={},
            execution_metadata={},
        ),
    )

    assert http_calls == 1
    assert provider.execute_command.call_count == 1
    remote_command = provider.execute_command.call_args[0][0].command
    assert "python3 -c" in remote_command
    assert "sendto" in remote_command
    assert "recvfrom" not in remote_command
    assert "DNS_TUNNEL_SESSION_DONE" in remote_command
    assert "04d" in remote_command

    dispatched = store.count(
        EventQuery(run_id="run-session", scenario_id="dns_tunnel", event="webshell_command_dispatched")
    )
    assert dispatched == 1

    idx_events = [
        e
        for e in store.list_events("run-session", "dns_tunnel")
        if e.event == "dns_tunnel_query_sent"
        and (e.evidence or {}).get("query_role") == "idx_chunk"
    ]
    assert len(idx_events) == 3
    assert all(str(e.evidence.get("fqdn", "")).startswith("idx-") for e in idx_events)
    assert any(
        str(e.evidence.get("fqdn", "")).startswith("idx-0000-") for e in idx_events
    )

    roles = {
        str((e.evidence or {}).get("query_role"))
        for e in store.list_events("run-session", "dns_tunnel")
        if e.event == "dns_tunnel_query_sent"
    }
    assert "session_start" in roles
    assert "session_end" in roles
    assert "idx_chunk" in roles

    end_fqdn = build_tunnel_end_fqdn(TUNNEL_DOMAIN_DEFAULT)
    strt_fqdn = build_tunnel_start_fqdn(MOCK_PAYLOAD_FILENAME, TUNNEL_DOMAIN_DEFAULT)
    fqdns = {str(e.evidence.get("fqdn")) for e in store.list_events("run-session", "dns_tunnel")}
    assert end_fqdn in fqdns
    assert strt_fqdn in fqdns


def test_local_webshell_planner_fqdn_parity() -> None:
    params = {
        "payload_mb": 0.0001,
        "max_chunks": 2,
        "domain": TUNNEL_DOMAIN_DEFAULT,
        "max_hosts": 1,
        "plan_seed": 7,
    }
    targets = _targets()
    local = plan_dns_tunnel(targets, params, dry_run=False)
    webshell = _plan_dns_tunnel(
        {
            "target_net": targets.target_net,
            "hosts": targets.hosts,
            "service_hosts": targets.service_hosts,
            "discovery_meta": targets.discovery_meta,
        },
        params,
        dry_run=False,
    )
    assert [q["fqdn"] for q in local["queries"]] == [q["fqdn"] for q in webshell["queries"]]
    idx_fqdns = [
        q["fqdn"] for q in local["queries"] if q.get("query_role") == "idx_chunk"
    ]
    assert idx_fqdns[0].startswith("idx-0000-")


def test_two_mb_plan_idx_count() -> None:
    total = plan_chunk_count(PAYLOAD_MB_DEFAULT, CHUNK_SIZE_DEFAULT)
    assert total == (2 * 1024 * 1024 + CHUNK_SIZE_DEFAULT - 1) // CHUNK_SIZE_DEFAULT
    assert total >= 69900
