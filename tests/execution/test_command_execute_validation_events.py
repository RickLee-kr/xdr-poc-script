"""Command-only executors must emit validation-aligned DNS/DGA/Rare events."""

from __future__ import annotations

from unittest.mock import MagicMock

from dsp.engine import RunConfig, RunContext
from dsp.event_store import EventStore
from dsp.execution.remote.command.execute import execute_command_plan
from dsp.execution.remote.command.models import DNS_QUERY_METHOD_PYTHON_SOCKET_UDP53
from dsp.execution.remote.models import ScenarioExecutionRequest


def _ctx(tmp_path) -> RunContext:
    store = EventStore(tmp_path / "events.db")
    store.open_run("run-val")
    return RunContext(
        run_id="run-val",
        target_net="10.10.10.0/24",
        event_store=store,
        config=RunConfig(dry_run=False),
        dry_run=False,
    )


def _request(scenario_id: str) -> ScenarioExecutionRequest:
    return ScenarioExecutionRequest(
        run_id="run-val",
        scenario_id=scenario_id,
        target_net="10.10.10.0/24",
        dry_run=False,
        scenario_params={},
        execution_metadata={},
    )


def test_dns_tunnel_command_evidence_includes_python_socket_method(tmp_path) -> None:
    ctx = _ctx(tmp_path)
    provider = MagicMock()
    provider.execute_command.return_value = MagicMock(status=MagicMock(value="completed"))
    plan = {
        "type": "dns_tunnel",
        "mode": "live",
        "payload_mb": 0.0001,
        "chunk_size": 30,
        "domain": "dns-tunnel.com",
        "mock_filename": "mock_exfil.dat",
        "send_interval_sec": 0.01,
        "session_id": "sess01",
        "queries": [
            {
                "target": "10.10.10.20",
                "fqdn": "idx-0000-abc.dns-tunnel.com",
                "seq": 0,
                "query_role": "idx_chunk",
                "protocol": "dns_udp",
                "port": 53,
            },
        ],
    }
    http_calls = execute_command_plan(plan, provider, ctx, _request("dns_tunnel"))
    events = ctx.event_store.list_events("run-val")
    completed = next(e for e in events if e.event == "dns_tunnel_completed")
    assert completed.evidence.get("dns_query_method") == DNS_QUERY_METHOD_PYTHON_SOCKET_UDP53
    assert completed.evidence.get("dns_tunnel_query_sent_count") == 1
    assert completed.evidence.get("webshell_http_dispatches") == 1
    assert http_calls == 1
    assert provider.execute_command.call_count == 1
    dispatched = next(e for e in events if e.event == "webshell_command_dispatched")
    remote_command = str(dispatched.evidence.get("remote_command"))
    assert "python3 -c" in remote_command
    assert "sendto" in remote_command
    assert "recvfrom" not in remote_command
    assert "DNS_TUNNEL_SESSION_DONE" in remote_command


def test_dga_command_emits_validation_status_events(tmp_path) -> None:
    ctx = _ctx(tmp_path)
    provider = MagicMock()
    provider.execute_command.return_value = MagicMock(status=MagicMock(value="completed"))
    plan = {
        "type": "dga",
        "mode": "live",
        "resolver": "10.10.10.20",
        "timeout": 1.0,
        "domains": [
            {"fqdn": "abcd1234567890.xdr.ooo", "phase": 1, "phase_name": "nxdomain", "seq": 1},
            {"fqdn": "abcd1234567890.live.xdr.ooo", "phase": 2, "phase_name": "resolvable", "seq": 2},
        ],
    }
    execute_command_plan(plan, provider, ctx, _request("dga"))
    events = ctx.event_store.list_events("run-val")
    nx = [e for e in events if e.event == "dga_nxdomain_observed"]
    resolved = [e for e in events if e.event == "dga_resolved_observed"]
    assert len(nx) == 1
    assert nx[0].status == "nxdomain"
    assert len(resolved) == 1
    assert resolved[0].status == "response"


def test_rare_protocol_command_emits_probe_attempt_events(tmp_path) -> None:
    ctx = _ctx(tmp_path)
    provider = MagicMock()
    provider.execute_command.return_value = MagicMock(status=MagicMock(value="completed"))
    plan = {
        "type": "rare_protocol_activity",
        "mode": "live",
        "timeout": 3.0,
        "probes": [
            {
                "host": "10.10.10.97",
                "port": 23,
                "protocol": "TELNET",
                "transport": "tcp",
                "artifact": "10.10.10.97:23:TELNET",
            },
        ],
    }
    execute_command_plan(plan, provider, ctx, _request("rare_protocol_activity"))
    events = ctx.event_store.list_events("run-val")
    attempts = [e for e in events if e.event == "rare_protocol_probe_attempt"]
    assert len(attempts) == 1
    assert attempts[0].status == "sent"
