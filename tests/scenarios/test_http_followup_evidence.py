"""HTTP follow-up per-request evidence dump tests."""

from __future__ import annotations

import json

from dsp.engine.scenario_engine import RunConfig, RunContext, TargetSet
from dsp.event_store import EventStore
from dsp.protocols.http.urls import PlannedHttpRequest
from dsp.protocols.types import HttpRequest, HttpResponseResult
from dsp.runner import RunManager
from scenarios.http_followup.executor import run

HTTP_TEST_PARAMS = {
    "http_followup": {
        "hosts": ["10.10.10.20"],
        "max_total": 5,
        "max_per_host": 5,
    }
}

_EVIDENCE_FIELDS = (
    "timestamp",
    "target",
    "port",
    "method",
    "path",
    "query",
    "user_agent",
    "response_code",
)


def test_evidence_dump_record_fields():
    from scenarios.http_followup import executor as mod

    plan = PlannedHttpRequest(
        host="10.10.10.20",
        port=80,
        path="/WEB-INF/web.xml",
        query="?id=%00%00%00",
        method="GET",
        headers={"User-Agent": "ThreatHunterAgent/8.2"},
    )
    record = mod._evidence_dump_record(
        mod._RequestOutcome(
            seq=1,
            plan=plan,
            request=HttpRequest(url=plan.url, method="GET", host=plan.host, port=80, path=plan.full_path),
            result=HttpResponseResult(
                url=plan.url,
                method="GET",
                outcome="response",
                status_code=302,
                request_id="abc",
                dry_run=False,
            ),
            ua="ThreatHunterAgent/8.2",
            ua_kind="rare",
            timestamp="2026-06-11T12:00:00+00:00",
        )
    )
    assert set(record) == set(_EVIDENCE_FIELDS)
    assert record["target"] == "10.10.10.20"
    assert record["port"] == 80
    assert record["path"] == "/WEB-INF/web.xml"
    assert record["query"] == "?id=%00%00%00"
    assert record["user_agent"] == "ThreatHunterAgent/8.2"
    assert record["response_code"] == 302


def test_http_followup_writes_requests_jsonl(tmp_runs_dir):
    manager = RunManager(runs_dir=tmp_runs_dir)
    _run, run_dir, exit_code = manager.run(
        scenario_ids=["http_followup"],
        target_net="10.10.10.0/24",
        dry_run=True,
        scenario_params=HTTP_TEST_PARAMS,
    )

    assert exit_code == 0
    evidence_path = run_dir / "http_followup_requests.jsonl"
    assert evidence_path.exists()

    lines = [line for line in evidence_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    assert len(lines) == 5

    for line in lines:
        record = json.loads(line)
        assert set(record) == set(_EVIDENCE_FIELDS)
        assert record["target"] == "10.10.10.20"
        assert record["user_agent"]
        assert record["path"].startswith("/")


def test_http_followup_completed_event_has_full_request_evidence(tmp_path):
    store = EventStore(db_path=tmp_path / "events.db")
    store.open_run("evidence-test")
    ctx = RunContext(
        run_id="evidence-test",
        target_net="10.10.10.0/24",
        event_store=store,
        config=RunConfig(),
        dry_run=True,
    )
    targets = TargetSet(
        target_net="10.10.10.0/24",
        service_hosts={"http_targets": ["10.10.10.20"]},
        service_endpoints={"http_targets": [("10.10.10.20", 80)]},
        discovery_enabled=True,
    )
    run(ctx, targets, config={"max_total": 3, "max_per_host": 3})

    completed = next(e for e in store.list_events("evidence-test") if e.event == "http_followup_completed")
    evidence = completed.evidence["request_evidence"]
    assert len(evidence) == 3
    assert all(set(row) == set(_EVIDENCE_FIELDS) for row in evidence)
