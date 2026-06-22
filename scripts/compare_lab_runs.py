#!/usr/bin/env python3
"""Compare local vs webshell lab run artifacts for plan/traffic parity."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any


def _load(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def _scenario_block(traffic: dict[str, Any], scenario_id: str) -> dict[str, Any]:
    scenarios = traffic.get("scenarios") or {}
    block = scenarios.get(scenario_id) or {}
    if block:
        return block
    return traffic.get(scenario_id) or {}


def _extract_run_summary(run_dir: Path) -> dict[str, Any]:
    run = _load(run_dir / "run.json")
    traffic = _load(run_dir / "traffic_summary.json")
    validation = _load(run_dir / "validation.json")
    report = _load(run_dir / "report.json")
    probe = _load(run_dir / "http_target_probe.json")

    scenarios = traffic.get("scenarios") or {}
    out: dict[str, Any] = {
        "run_id": run.get("run_id"),
        "run_dir": str(run_dir),
        "target_net": run.get("target_net"),
        "execution_provider": (run.get("config_snapshot") or {}).get("execution_provider"),
        "operational_profile": (run.get("config_snapshot") or {}).get("operational_profile"),
        "status": run.get("status"),
        "dry_run": run.get("dry_run"),
        "traffic_origin": traffic.get("traffic_origin") or traffic.get("execution_origin"),
        "discovery": traffic.get("discovery") or {},
        "selected_targets": traffic.get("selected_targets") or traffic.get("targets_selected"),
        "http_probe": probe,
        "scenarios": {},
        "validation_summary": {
            "overall": validation.get("overall_status") or validation.get("status"),
            "results": validation.get("results") or [],
        },
        "report_scenarios": (report.get("scenarios") if isinstance(report, dict) else None),
    }

    for sid in (
        "port_sweep",
        "http_followup",
        "sql_injection",
        "ssh_failure",
        "dns_tunnel",
        "dga",
        "rare_protocol_activity",
        "ldap_enumeration",
        "smb_login_failure",
        "kerberos_failure",
        "host_behavior_check",
    ):
        block = _scenario_block(traffic, sid)
        if not block:
            continue
        out["scenarios"][sid] = {
            "status": block.get("status") or block.get("outcome"),
            "skipped": block.get("skipped"),
            "skip_reason": block.get("skip_reason"),
            "targets": block.get("targets") or block.get("selected_targets"),
            "endpoints": block.get("endpoints") or block.get("selected_endpoints"),
            "probes_sent": block.get("probes_sent") or block.get("probe_count"),
            "queries_sent": block.get("queries_sent") or block.get("dns_tunnel_query_sent_count"),
            "resolver": block.get("resolver"),
            "traffic_origin": block.get("traffic_origin") or block.get("execution_origin"),
        }

    # Event-store backed upload check (command-only webshell must not upload runtime)
    events_path = run_dir / "events.jsonl"
    upload_markers: list[str] = []
    if events_path.is_file():
        forbidden = (
            "run_scenario.py",
            "remote_discovery.py",
            "manifest.json",
            "runner_upload",
        )
        for line in events_path.read_text(encoding="utf-8").splitlines():
            lower = line.lower()
            if any(marker in lower for marker in forbidden):
                if "runner_upload\": false" in lower or '"runner_upload": false' in line:
                    continue
                upload_markers.append(line[:200])
                if len(upload_markers) >= 5:
                    break
    out["forbidden_upload_evidence"] = upload_markers

    return out


def _compare_keys(local: dict[str, Any], webshell: dict[str, Any]) -> dict[str, Any]:
    parity_fields = [
        "port_sweep",
        "http_followup",
        "sql_injection",
        "ssh_failure",
        "dns_tunnel",
        "dga",
        "rare_protocol_activity",
    ]
    comparison: dict[str, Any] = {"match": True, "scenarios": {}, "diffs": []}

    for sid in parity_fields:
        loc = (local.get("scenarios") or {}).get(sid, {})
        ws = (webshell.get("scenarios") or {}).get(sid, {})
        loc_cmp = {
            "status": loc.get("status") or ("skipped" if loc.get("skipped") else None),
            "skip_reason": loc.get("skip_reason"),
            "targets": loc.get("targets"),
            "endpoints": loc.get("endpoints"),
            "probes_sent": loc.get("probes_sent"),
            "queries_sent": loc.get("queries_sent"),
            "resolver": loc.get("resolver"),
        }
        ws_cmp = {
            "status": ws.get("status") or ("skipped" if ws.get("skipped") else None),
            "skip_reason": ws.get("skip_reason"),
            "targets": ws.get("targets"),
            "endpoints": ws.get("endpoints"),
            "probes_sent": ws.get("probes_sent"),
            "queries_sent": ws.get("queries_sent"),
            "resolver": ws.get("resolver"),
        }
        same = loc_cmp == ws_cmp
        comparison["scenarios"][sid] = {"local": loc_cmp, "webshell": ws_cmp, "match": same}
        if not same:
            comparison["match"] = False
            comparison["diffs"].append(sid)

    loc_origin = local.get("traffic_origin")
    ws_origin = webshell.get("traffic_origin")
    comparison["traffic_origin"] = {"local": loc_origin, "webshell": ws_origin}
    comparison["traffic_origin_differs_only"] = loc_origin != ws_origin

    return comparison


def main(argv: list[str] | None = None) -> int:
    args = argv if argv is not None else sys.argv[1:]
    if len(args) != 2:
        print("usage: compare_lab_runs.py <local_run_dir> <webshell_run_dir>", file=sys.stderr)
        return 2
    local_dir = Path(args[0]).resolve()
    webshell_dir = Path(args[1]).resolve()
    local = _extract_run_summary(local_dir)
    webshell = _extract_run_summary(webshell_dir)
    comparison = _compare_keys(local, webshell)
    payload = {"local": local, "webshell": webshell, "comparison": comparison}
    print(json.dumps(payload, indent=2))
    return 0 if comparison["match"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
