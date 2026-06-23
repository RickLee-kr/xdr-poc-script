"""HTTP Follow-up request evidence helpers (local + webshell visibility parity)."""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

from dsp.protocols.http.user_agents import is_abnormal_user_agent

WEBSHELL_RESPONSE_TRACKING = "disabled_webshell_mode"


def utc_timestamp() -> str:
    return datetime.now(timezone.utc).isoformat()


def parse_http_request_url(url: str) -> dict[str, Any]:
    parsed = urlparse(url)
    port = parsed.port
    if port is None:
        port = 443 if parsed.scheme == "https" else 80
    query = f"?{parsed.query}" if parsed.query else ""
    return {
        "target": parsed.hostname or "",
        "port": port,
        "path": parsed.path or "/",
        "query": query,
    }


def build_dispatch_request_evidence(
    *,
    url: str,
    method: str,
    user_agent: str,
    dispatch_status: str,
    timestamp: str | None = None,
    seq: int | None = None,
) -> dict[str, Any]:
    """Per-request evidence for webshell command-dispatch HTTP follow-up."""
    parts = parse_http_request_url(url)
    record: dict[str, Any] = {
        "timestamp": timestamp or utc_timestamp(),
        "target": parts["target"],
        "url": url,
        "method": method,
        "user_agent": user_agent,
        "dispatch_status": dispatch_status,
        "port": parts["port"],
        "path": parts["path"],
    }
    if parts["query"]:
        record["query"] = parts["query"]
    if seq is not None:
        record["seq"] = seq
    return record


def summarize_http_followup_evidence(
    records: list[dict[str, Any]],
    *,
    response_tracking: str | None = None,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Build request_dump samples and summary distribution from request evidence."""
    path_dist: Counter[str] = Counter()
    ua_dist: Counter[str] = Counter()
    target_dist: Counter[str] = Counter()
    abnormal = 0

    for rec in records:
        path = str(rec.get("path") or "/")
        path_dist[path] += 1
        ua = str(rec.get("user_agent") or "")
        ua_dist[ua] += 1
        target = str(rec.get("target") or "")
        port = rec.get("port") or 80
        target_dist[f"{target}:{port}"] += 1
        if ua and is_abnormal_user_agent(ua):
            abnormal += 1

    total = len(records)
    summary: dict[str, Any] = {
        "sample_count": total,
        "unique_paths": len(path_dist),
        "unique_user_agents": len(ua_dist),
        "path_distribution": dict(path_dist),
        "user_agent_distribution": dict(ua_dist),
        "target_distribution": dict(target_dist),
        "abnormal_user_agents": abnormal,
        "normal_user_agents": total - abnormal,
        "abnormal_user_agent_ratio": round(abnormal / total, 4) if total else 0.0,
    }
    if response_tracking:
        summary["response_tracking"] = response_tracking
    return list(records), summary
