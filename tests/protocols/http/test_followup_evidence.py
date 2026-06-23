"""HTTP follow-up evidence helper tests."""

from __future__ import annotations

from dsp.protocols.http.followup_evidence import (
    WEBSHELL_RESPONSE_TRACKING,
    build_dispatch_request_evidence,
    summarize_http_followup_evidence,
)


def test_build_dispatch_request_evidence_fields() -> None:
    record = build_dispatch_request_evidence(
        url="http://10.10.10.1:8888/WEB-INF/web.xml?id=1",
        method="GET",
        user_agent="ThreatHunterAgent/8.2",
        dispatch_status="completed",
        timestamp="2026-06-23T01:00:00+00:00",
        seq=1,
    )
    assert record["target"] == "10.10.10.1"
    assert record["port"] == 8888
    assert record["path"] == "/WEB-INF/web.xml"
    assert record["query"] == "?id=1"
    assert record["url"].startswith("http://10.10.10.1:8888/")
    assert record["method"] == "GET"
    assert record["user_agent"] == "ThreatHunterAgent/8.2"
    assert record["dispatch_status"] == "completed"
    assert record["timestamp"] == "2026-06-23T01:00:00+00:00"


def test_summarize_http_followup_evidence_distributions() -> None:
    records = [
        build_dispatch_request_evidence(
            url="http://10.10.10.1/WEB-INF/web.xml",
            method="GET",
            user_agent="ThreatHunterAgent/8.2",
            dispatch_status="completed",
        ),
        build_dispatch_request_evidence(
            url="http://10.10.10.1/cmd.jsp",
            method="GET",
            user_agent="Mozilla/5.0 Chrome/120.0.0.0",
            dispatch_status="completed",
        ),
    ]
    dump, summary = summarize_http_followup_evidence(
        records,
        response_tracking=WEBSHELL_RESPONSE_TRACKING,
    )
    assert len(dump) == 2
    assert summary["unique_paths"] == 2
    assert summary["abnormal_user_agents"] == 1
    assert summary["normal_user_agents"] == 1
    assert summary["path_distribution"]["/WEB-INF/web.xml"] == 1
    assert summary["target_distribution"]["10.10.10.1:80"] == 2
    assert summary["response_tracking"] == WEBSHELL_RESPONSE_TRACKING
