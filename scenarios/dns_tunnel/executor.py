"""DNS Tunnel executor — chunk generation, FQDN encoding, UDP/53 transmission."""

from __future__ import annotations

import time
import uuid

from dsp.engine.scenario_engine import RunContext, TargetSet
from dsp.runner.activity_reporter import ActivityReporter
from dsp.protocols.dns import DnsClient, build_dns_events
from dsp.protocols.dns.tunnel import (
    CHUNK_SIZE_DEFAULT,
    PAYLOAD_MB_DEFAULT,
    TUNNEL_DOMAIN_DEFAULT,
    build_tunnel_fqdn,
    chunk_to_b32_label,
    dns_tunnel_query_evidence,
    iter_payload_chunks,
    plan_burst_schedule,
    plan_chunk_count,
    sample_burst_pause_sec,
    select_tunnel_targets,
)
from dsp.protocols.dns.tunnel_events import (
    build_tunnel_chunk_created_event,
    build_tunnel_completed_event,
    build_tunnel_query_sent_event,
    build_tunnel_started_event,
)
from dsp.protocols.dns.volume_profiles import apply_volume_profile


def run(
    ctx: RunContext,
    targets: TargetSet,
    config: dict | None = None,
    scenario_id: str = "dns_tunnel",
) -> None:
    """Generate tunnel chunks, transmit DNS queries, append events to Event Store."""
    params = apply_volume_profile(config or {}, dry_run=ctx.dry_run)
    payload_mb = float(params.get("payload_mb", PAYLOAD_MB_DEFAULT))
    chunk_size = int(params.get("chunk_size", CHUNK_SIZE_DEFAULT))
    domain = str(params.get("domain", TUNNEL_DOMAIN_DEFAULT))
    max_hosts = int(params.get("max_hosts", 2))
    max_chunks = params.get("max_chunks")
    source = "dry_run" if ctx.dry_run else "local"
    mode = "mock" if ctx.dry_run else "live"
    client = DnsClient(mode=mode, timeout=0.05)

    host_targets = select_tunnel_targets(targets, params, max_hosts=max_hosts)
    total_planned = plan_chunk_count(payload_mb, chunk_size)
    if max_chunks is not None:
        total_planned = min(total_planned, int(max_chunks))

    session_id = uuid.uuid4().hex[:6]
    sample_fqdns: list[str] = []

    for target in host_targets:
        if ctx.cancelled:
            break

        started_evidence = {
            "session_id": session_id,
            "payload_mb": payload_mb,
            "chunk_size": chunk_size,
            "domain": domain,
            "planned_chunks": total_planned,
            "mode": mode,
        }
        ctx.event_store.append(
            build_tunnel_started_event(
                run_id=ctx.run_id,
                scenario_id=scenario_id,
                target=target,
                source=source,
                evidence=started_evidence,
            )
        )

        chunks_sent = 0
        bytes_encoded = 0
        t0 = time.monotonic()
        activity = ActivityReporter(ctx, scenario_id, total=total_planned)
        burst_schedule = plan_burst_schedule(total_planned)
        chunk_iter = iter_payload_chunks(payload_mb, chunk_size)
        seq = 0

        for burst_idx, burst_size in enumerate(burst_schedule):
            if ctx.cancelled:
                break
            for _ in range(burst_size):
                if ctx.cancelled:
                    break
                seq += 1
                chunk = next(chunk_iter)

                b32_label = chunk_to_b32_label(chunk)
                fqdn = build_tunnel_fqdn(seq, b32_label, domain)
                if len(sample_fqdns) < 3:
                    sample_fqdns.append(fqdn)

                chunk_evidence = {
                    "session_id": session_id,
                    "seq": seq,
                    "chunk_bytes": len(chunk),
                    "label_length": len(b32_label),
                    "domain": domain,
                    "burst_index": burst_idx + 1,
                }
                ctx.event_store.append(
                    build_tunnel_chunk_created_event(
                        run_id=ctx.run_id,
                        scenario_id=scenario_id,
                        target=target,
                        fqdn=fqdn,
                        source=source,
                        evidence=chunk_evidence,
                    )
                )

                query = client.make_query(target, fqdn)
                activity.update(target=target, sample_query=fqdn)
                activity.record(action="send", target=target, query=fqdn)
                if mode == "mock":
                    result = client.query(target, fqdn, mock_outcome="response")
                else:
                    result = client.send_fire_and_forget(target, fqdn)

                query_evidence = dns_tunnel_query_evidence(
                    {
                        "target": target,
                        "fqdn": fqdn,
                        "seq": seq,
                        "label_length": len(b32_label),
                    }
                )
                query_evidence.update(
                    {
                        "session_id": session_id,
                        "qtype": query.qtype,
                        "query_id": result.query_id,
                        "outcome": result.outcome,
                        "burst_index": burst_idx + 1,
                    }
                )
                if result.evidence.get("bytes_sent") is not None:
                    query_evidence["bytes_sent"] = result.evidence["bytes_sent"]
                ctx.event_store.append(
                    build_tunnel_query_sent_event(
                        run_id=ctx.run_id,
                        scenario_id=scenario_id,
                        target=target,
                        fqdn=fqdn,
                        source=source,
                        evidence=query_evidence,
                    )
                )

                for event in build_dns_events(
                    run_id=ctx.run_id,
                    scenario_id=scenario_id,
                    query=query,
                    result=result,
                    source=source,
                    include_created=False,
                ):
                    ctx.event_store.append(event)

                chunks_sent += 1
                bytes_encoded += len(chunk)

            if burst_idx < len(burst_schedule) - 1 and not ctx.cancelled:
                time.sleep(sample_burst_pause_sec())

        activity.emit_final_progress()
        elapsed = round(time.monotonic() - t0, 3)
        completed_evidence = {
            "session_id": session_id,
            "chunks_sent": chunks_sent,
            "bytes_encoded": bytes_encoded,
            "duration_sec": elapsed,
            "targets": host_targets,
            "sample_fqdns": sample_fqdns,
            "domain": domain,
            "burst_schedule": burst_schedule,
        }
        ctx.event_store.append(
            build_tunnel_completed_event(
                run_id=ctx.run_id,
                scenario_id=scenario_id,
                target=target,
                source=source,
                evidence=completed_evidence,
            )
        )
