"""Execute non-standard port HTTP burst within http_followup."""

from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

from dsp.engine.scenario_engine import RunContext
from dsp.protocols.http.client import HttpClient
from dsp.protocols.http.events import (
    build_non_standard_port_burst_completed_event,
    build_non_standard_port_burst_started_event,
    build_non_standard_port_connection_attempt_event,
    build_non_standard_port_connection_failure_event,
    build_non_standard_port_connection_success_event,
)
from dsp.protocols.http.non_standard_port_burst import burst_connection_success
from dsp.protocols.types import HttpRequest, HttpResponseResult


def _execute_burst_request(
    *,
    item: dict[str, Any],
    client: HttpClient,
    mode: str,
) -> tuple[dict[str, Any], HttpResponseResult]:
    host = str(item["host"])
    port = int(item["port"])
    path = str(item.get("path") or "/")
    url = str(item.get("url") or "")
    headers = {"User-Agent": str(item.get("user_agent") or "Mozilla/5.0")}
    request = HttpRequest(
        url=url,
        method="GET",
        host=host,
        port=port,
        path=path,
        headers=headers,
    )
    if mode == "mock":
        mock_code = 200 if int(item["seq"]) % 3 else 404
        result = client.request(request, mock_outcome="response", mock_status_code=mock_code)
    else:
        result = client.request(request)
    return item, result


def run_non_standard_port_burst(
    ctx: RunContext,
    *,
    burst_plan: dict[str, Any],
    client: HttpClient,
    mode: str,
    source: str,
    scenario_id: str,
    concurrency: int,
    primary_target: str,
) -> dict[str, Any]:
    """Run burst phase and append events to the context store."""
    requests = list(burst_plan.get("requests") or [])
    if not requests:
        return {"enabled": False, "reason": "no_burst_requests"}

    ports = list(burst_plan.get("ports") or [])
    targets = list(burst_plan.get("targets") or [])
    t0 = time.monotonic()

    ctx.event_store.append(
        build_non_standard_port_burst_started_event(
            run_id=ctx.run_id,
            scenario_id=scenario_id,
            target=primary_target,
            source=source,
            evidence={
                "attempts_planned": len(requests),
                "ports": ports,
                "targets": targets,
                "mode": mode,
            },
        )
    )

    attempts = 0
    successes = 0
    failures = 0
    worker_count = max(1, min(concurrency, len(requests)))
    with ThreadPoolExecutor(max_workers=worker_count) as pool:
        futures = {
            pool.submit(
                _execute_burst_request,
                item=item,
                client=client,
                mode=mode,
            ): item
            for item in requests
        }
        for future in as_completed(futures):
            if ctx.cancelled:
                break
            item = futures[future]
            try:
                req_item, result = future.result()
            except Exception as exc:
                req_item = item
                result = HttpResponseResult(
                    url=str(item.get("url") or ""),
                    method="GET",
                    outcome="error",
                    request_id="burst-error",
                    dry_run=mode == "mock",
                    evidence={"error": str(exc)},
                )

            host = str(req_item["host"])
            port = int(req_item["port"])
            url = str(req_item.get("url") or "")
            base_evidence = {
                "seq": req_item.get("seq"),
                "host": host,
                "port": port,
                "url": url,
                "method": "GET",
                "user_agent": req_item.get("user_agent"),
                "discovered": req_item.get("discovered"),
                "probe": req_item.get("probe"),
                "outcome": result.outcome,
            }
            if result.status_code is not None:
                base_evidence["status_code"] = result.status_code

            ctx.event_store.append(
                build_non_standard_port_connection_attempt_event(
                    run_id=ctx.run_id,
                    scenario_id=scenario_id,
                    target=host,
                    source=source,
                    evidence=dict(base_evidence),
                )
            )
            attempts += 1

            if burst_connection_success(result.outcome, result.status_code):
                successes += 1
                ctx.event_store.append(
                    build_non_standard_port_connection_success_event(
                        run_id=ctx.run_id,
                        scenario_id=scenario_id,
                        target=host,
                        source=source,
                        evidence=dict(base_evidence),
                    )
                )
            else:
                failures += 1
                ctx.event_store.append(
                    build_non_standard_port_connection_failure_event(
                        run_id=ctx.run_id,
                        scenario_id=scenario_id,
                        target=host,
                        source=source,
                        evidence=dict(base_evidence),
                        status=result.outcome if result.outcome != "response" else "error",
                    )
                )

    elapsed = round(time.monotonic() - t0, 3)
    summary = {
        "enabled": True,
        "ports": ports,
        "targets": targets,
        "attempts": attempts,
        "success": successes,
        "failure": failures,
        "duration_sec": elapsed,
    }
    ctx.event_store.append(
        build_non_standard_port_burst_completed_event(
            run_id=ctx.run_id,
            scenario_id=scenario_id,
            target=primary_target,
            source=source,
            evidence=dict(summary),
        )
    )
    return summary
