"""traffic_summary — discovery HTTP targets flow into follow-up selection fields."""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import MagicMock

from dsp.engine.scenario_engine import TargetSet
from dsp.event_store import Event
from dsp.runtime.traffic_summary import build_traffic_summary


def _lab_targets() -> TargetSet:
    return TargetSet(
        target_net="221.139.249.0/24",
        hosts=[
            "221.139.249.110",
            "221.139.249.113",
            "221.139.249.118",
        ],
        service_hosts={
            "http_targets": [
                "221.139.249.110",
                "221.139.249.113",
                "221.139.249.118",
            ],
        },
        service_endpoints={
            "http_targets": [
                ("221.139.249.110", 80),
                ("221.139.249.113", 8080),
                ("221.139.249.118", 9000),
            ],
        },
        discovery_enabled=True,
        discovery_meta={
            "alive_hosts": [
                "221.139.249.110",
                "221.139.249.113",
                "221.139.249.118",
            ],
            "service_hosts": {
                "http_targets": [
                    "221.139.249.110",
                    "221.139.249.113",
                    "221.139.249.118",
                ],
            },
        },
    )


def test_traffic_summary_uses_attack_http_events_not_phase1() -> None:
    store = MagicMock()
    store.list_events.return_value = [
        Event(
            run_id="r1",
            scenario_id="http_followup",
            timestamp=datetime.now(timezone.utc),
            stage="executor",
            event="http_followup_completed",
            status="info",
            evidence={
                "phase": "phase1_webshell_attack",
                "requests_sent": 12,
            },
        ),
        Event(
            run_id="r1",
            scenario_id="http_followup",
            timestamp=datetime.now(timezone.utc),
            stage="executor",
            event="http_request_sent",
            status="sent",
            evidence={"phase": "phase1_webshell_attack"},
        ),
        Event(
            run_id="r1",
            scenario_id="http_followup",
            timestamp=datetime.now(timezone.utc),
            stage="executor",
            event="http_followup_started",
            status="info",
            evidence={
                "requests_planned": 40,
                "selected_targets": [
                    "221.139.249.110:80 (discovered_http_service_unverified_from_dsp_host)",
                ],
                "target_count": 1,
                "http_targets": ["221.139.249.110", "221.139.249.113"],
            },
        ),
        Event(
            run_id="r1",
            scenario_id="http_followup",
            timestamp=datetime.now(timezone.utc),
            stage="executor",
            event="http_followup_completed",
            status="info",
            evidence={
                "requests_sent": 40,
                "request_count": 40,
                "selected_targets": [
                    "221.139.249.110:80 (discovered_http_service_unverified_from_dsp_host)",
                ],
                "target_count": 1,
            },
        ),
    ]

    summary = build_traffic_summary(
        store,
        run_id="r1",
        scenario_ids=["http_followup"],
        targets=_lab_targets(),
        traffic_profile="normal",
        scenario_params={"http_followup": {"max_hosts": 1}},
    )
    http = summary["scenarios"]["http_followup"]
    assert http["requests_sent"] == 40
    assert http["target_count"] == 1
    assert http["selected_targets"]
    assert "221.139.249.110" in http["selected_targets"][0]


def test_traffic_summary_falls_back_to_discovery_when_events_empty() -> None:
    store = MagicMock()
    store.list_events.return_value = [
        Event(
            run_id="r1",
            scenario_id="sql_injection",
            timestamp=datetime.now(timezone.utc),
            stage="executor",
            event="sql_injection_completed",
            status="info",
            evidence={"requests_sent": 20},
        ),
    ]

    summary = build_traffic_summary(
        store,
        run_id="r1",
        scenario_ids=["sql_injection"],
        targets=_lab_targets(),
        traffic_profile="normal",
        scenario_params={"sql_injection": {"max_hosts": 2}},
    )
    sqli = summary["scenarios"]["sql_injection"]
    assert sqli["requests_sent"] == 20
    assert sqli["target_count"] == 2
    assert len(sqli["selected_targets"]) == 2
    assert sqli["http_targets"] == [
        "221.139.249.110",
        "221.139.249.113",
        "221.139.249.118",
    ]
