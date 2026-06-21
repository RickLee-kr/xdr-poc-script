"""traffic_summary and validation.json must share Event Store metric source."""

from __future__ import annotations

from datetime import datetime, timezone

from dsp.engine.scenario_engine import TargetSet
from dsp.event_store import Event, EventStore
from dsp.plugins import PluginLoader
from dsp.runtime.traffic_summary import build_traffic_summary
from dsp.validation import ValidationEngine


def _lab_targets() -> TargetSet:
    return TargetSet(
        target_net="221.139.249.0/24",
        hosts=["221.139.249.110", "221.139.249.113"],
        service_hosts={
            "http_targets": ["221.139.249.110", "221.139.249.113"],
        },
        service_endpoints={
            "http_targets": [
                ("221.139.249.110", 80),
                ("221.139.249.113", 8080),
            ],
        },
        discovery_enabled=True,
        discovery_meta={
            "service_hosts": {
                "http_targets": ["221.139.249.110", "221.139.249.113"],
            },
        },
    )


def _append(store: EventStore, **kwargs) -> None:
    store.append(
        Event(
            run_id=kwargs.pop("run_id"),
            scenario_id=kwargs.pop("scenario_id"),
            timestamp=datetime.now(timezone.utc),
            stage=kwargs.pop("stage", "executor"),
            event=kwargs.pop("event"),
            status=kwargs.pop("status", "info"),
            target=kwargs.pop("target", ""),
            artifact=kwargs.pop("artifact", ""),
            evidence=kwargs.pop("evidence", {}),
            source=kwargs.pop("source", "remote"),
        )
    )


def test_traffic_summary_matches_validation_for_http_port_sql(tmp_path) -> None:
    store = EventStore(tmp_path / "events.db")
    run_id = "parity_run"
    store.open_run(run_id)
    registry = PluginLoader().discover_and_load()

    for seq in range(1, 4):
        _append(
            store,
            run_id=run_id,
            scenario_id="http_followup",
            event="http_request_sent",
            status="sent",
            target="221.139.249.110",
            artifact=f"http://221.139.249.110/path{seq}",
            evidence={"url": f"http://221.139.249.110/path{seq}", "seq": seq},
        )
    for seq in range(1, 3):
        _append(
            store,
            run_id=run_id,
            scenario_id="http_followup",
            event="http_response_received",
            status="response",
            target="221.139.249.110",
            artifact=f"http://221.139.249.110/path{seq}",
            evidence={"url": f"http://221.139.249.110/path{seq}", "status_code": 200},
        )
    _append(
        store,
        run_id=run_id,
        scenario_id="http_followup",
        event="http_followup_started",
        evidence={"planned_requests": 3, "selected_targets": ["221.139.249.110:80 (discovered)"]},
    )

    for seq in range(1, 6):
        _append(
            store,
            run_id=run_id,
            scenario_id="sql_injection",
            event="sql_payload_generated",
            status="info",
            target="221.139.249.113",
            artifact=f"http://221.139.249.113:8080/login?x={seq}",
            evidence={
                "url": f"http://221.139.249.113:8080/login?x={seq}",
                "payload_category": "boolean",
            },
        )
        _append(
            store,
            run_id=run_id,
            scenario_id="sql_injection",
            event="sql_request_sent",
            status="sent",
            target="221.139.249.113",
            artifact=f"http://221.139.249.113:8080/login?x={seq}",
            evidence={"url": f"http://221.139.249.113:8080/login?x={seq}", "method": "GET"},
        )
    _append(
        store,
        run_id=run_id,
        scenario_id="sql_injection",
        event="sql_injection_started",
        evidence={"planned_requests": 5},
    )

    for port in (22, 80, 443):
        _append(
            store,
            run_id=run_id,
            scenario_id="port_sweep",
            event="port_probe_sent",
            status="sent",
            target="221.139.249.110",
            artifact=f"221.139.249.110:{port}",
            evidence={"host": "221.139.249.110", "port": port},
        )
        _append(
            store,
            run_id=run_id,
            scenario_id="port_sweep",
            event="port_connection_failed",
            status="error",
            target="221.139.249.110",
            artifact=f"221.139.249.110:{port}",
            evidence={"host": "221.139.249.110", "port": port},
        )
    _append(
        store,
        run_id=run_id,
        scenario_id="port_sweep",
        event="port_sweep_started",
        evidence={"planned_probes": 3, "ports": [22, 80, 443]},
    )

    summary = build_traffic_summary(
        store,
        run_id=run_id,
        scenario_ids=["http_followup", "sql_injection", "port_sweep"],
        targets=_lab_targets(),
        traffic_profile="normal",
        registry=registry,
    )
    results = {
        item.scenario_id: item.metrics
        for item in ValidationEngine(store, registry).validate_run(
            run_id,
            ["http_followup", "sql_injection", "port_sweep"],
        )
    }

    http = summary["scenarios"]["http_followup"]
    assert http["requests_sent"] == results["http_followup"]["http_request_sent_count"] == 3
    assert http["responses_received"] == results["http_followup"]["http_response_received_count"] == 2
    assert http["requests_planned"] == 3
    assert http["selected_targets"]

    sqli = summary["scenarios"]["sql_injection"]
    assert sqli["requests_sent"] == results["sql_injection"]["sql_request_sent_count"] == 5
    assert sqli["payload_count"] == results["sql_injection"]["sql_payload_generated_count"] == 5
    assert sqli["requests_planned"] == 5
    assert sqli["selected_targets"]
    assert sqli["ports_used"] == [8080]
    assert sqli["payload_category_distribution"]["boolean"] == 5

    port = summary["scenarios"]["port_sweep"]
    assert port["probes_sent"] == results["port_sweep"]["port_probe_count"] == 3
    assert port["connection_failures"] == results["port_sweep"]["port_connection_failure_count"] == 3
    assert port["target_ips"] == ["221.139.249.110"]
    assert port["ports"] == [22, 80, 443]


def test_traffic_summary_excludes_phase1_counts_but_keeps_attack_metadata(tmp_path) -> None:
    store = EventStore(tmp_path / "phase1.db")
    run_id = "phase1_run"
    store.open_run(run_id)
    registry = PluginLoader().discover_and_load()

    _append(
        store,
        run_id=run_id,
        scenario_id="http_followup",
        event="http_followup_completed",
        evidence={"phase": "phase1_webshell_attack", "requests_sent": 99, "response_count": 99},
    )
    _append(
        store,
        run_id=run_id,
        scenario_id="http_followup",
        event="http_request_sent",
        status="sent",
        target="221.139.249.110",
        artifact="http://221.139.249.110/admin",
        evidence={"phase": "phase1_webshell_attack", "url": "http://221.139.249.110/admin"},
    )
    _append(
        store,
        run_id=run_id,
        scenario_id="http_followup",
        event="http_followup_started",
        evidence={
            "planned_requests": 2,
            "selected_targets": ["221.139.249.110:80 (discovered)"],
            "http_targets": ["221.139.249.110"],
        },
    )
    _append(
        store,
        run_id=run_id,
        scenario_id="http_followup",
        event="http_request_sent",
        status="sent",
        target="221.139.249.110",
        artifact="http://221.139.249.110/login",
        evidence={"url": "http://221.139.249.110/login"},
    )
    _append(
        store,
        run_id=run_id,
        scenario_id="http_followup",
        event="http_response_received",
        status="response",
        target="221.139.249.110",
        artifact="http://221.139.249.110/login",
        evidence={"url": "http://221.139.249.110/login", "status_code": 200},
    )

    summary = build_traffic_summary(
        store,
        run_id=run_id,
        scenario_ids=["http_followup"],
        targets=_lab_targets(),
        traffic_profile="normal",
        registry=registry,
    )
    http = summary["scenarios"]["http_followup"]
    assert http["requests_sent"] == 2
    assert http["responses_received"] == 1
    assert http["requests_planned"] == 2
    assert http["selected_targets"]
