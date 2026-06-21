"""Traffic summary — planned vs actual counters from Event Store."""

from __future__ import annotations

from typing import Any

from dsp.engine.scenario_engine import TargetSet
from dsp.event_store import Event, EventStore


def _normalize_event(event: Event | dict[str, Any]) -> dict[str, Any]:
    """Normalize Event objects, dicts, or to_dict()-capable records for summary."""
    if isinstance(event, dict):
        return {
            "scenario_id": event.get("scenario_id", ""),
            "event": event.get("event", ""),
            "evidence": event.get("evidence") or {},
            "target": event.get("target", ""),
        }
    to_dict = getattr(event, "to_dict", None)
    if callable(to_dict):
        data = to_dict()
        return {
            "scenario_id": data.get("scenario_id", ""),
            "event": data.get("event", ""),
            "evidence": data.get("evidence") or {},
            "target": data.get("target", ""),
        }
    return {
        "scenario_id": event.scenario_id,
        "event": event.event,
        "evidence": event.evidence or {},
        "target": event.target,
    }


def _event_dict(event: Event) -> dict[str, Any]:
    return _normalize_event(event)


def _is_phase1_webshell_evidence(evidence: dict[str, Any]) -> bool:
    return evidence.get("phase") == "phase1_webshell_attack"


def _last_evidence(
    events: list[dict[str, Any]],
    scenario_id: str,
    event_name: str,
    *,
    exclude_phase1: bool = False,
) -> dict[str, Any]:
    for e in reversed(events):
        if e.get("scenario_id") != scenario_id or e.get("event") != event_name:
            continue
        evidence = dict(e.get("evidence") or {})
        if exclude_phase1 and _is_phase1_webshell_evidence(evidence):
            continue
        return evidence
    return {}


def _count_events(
    events: list[dict[str, Any]],
    scenario_id: str,
    event_name: str,
    *,
    exclude_phase1: bool = False,
) -> int:
    total = 0
    for e in events:
        if e.get("scenario_id") != scenario_id or e.get("event") != event_name:
            continue
        evidence = e.get("evidence") or {}
        if exclude_phase1 and _is_phase1_webshell_evidence(evidence):
            continue
        total += 1
    return total


def _http_scenario_fallback_fields(
    targets: TargetSet,
    scenario_params: dict[str, dict[str, Any]] | None,
    scenario_id: str,
) -> dict[str, Any]:
    if scenario_id not in ("http_followup", "sql_injection"):
        return {}
    params = (scenario_params or {}).get(scenario_id) or {}
    from dsp.engine.host_selection import (
        http_selection_summary_fields,
        resolve_discovery_http_selection,
    )

    selection = resolve_discovery_http_selection(
        targets,
        params,
        webshell_mode=True,
    )
    if not selection.selected:
        http_hosts = targets.hosts_for_capability("http_targets")
        if not http_hosts:
            return {}
        return {
            "http_targets": http_hosts,
            "https_targets": targets.hosts_for_capability("https_targets"),
            "selected_targets": [str(host) for host in http_hosts[: int(params.get("max_hosts", 2))]],
            "target_count": min(len(http_hosts), int(params.get("max_hosts", 2))),
        }
    return http_selection_summary_fields(selection, targets)


def _merge_http_summary_fields(
    scenario_summary: dict[str, Any],
    fallback: dict[str, Any],
) -> None:
    if not fallback:
        return
    for key in (
        "selected_targets",
        "target_count",
        "http_targets",
        "https_targets",
        "selected_http_target_reason",
        "probe_summaries",
        "target_probe",
        "rejected_targets",
    ):
        if not scenario_summary.get(key) and fallback.get(key):
            scenario_summary[key] = fallback[key]
    if not scenario_summary.get("target_count") and scenario_summary.get("selected_targets"):
        scenario_summary["target_count"] = len(scenario_summary["selected_targets"])


def build_traffic_summary(
    store: EventStore,
    *,
    run_id: str,
    scenario_ids: list[str],
    targets: TargetSet,
    traffic_profile: str,
    webshell_execution: dict[str, Any] | None = None,
    scenario_params: dict[str, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Build planned vs actual traffic summary for a run."""
    events = [_normalize_event(e) for e in store.list_events(run_id)]

    summary: dict[str, Any] = {
        "traffic_profile": traffic_profile,
        "target_net": targets.target_net,
        "attack_target_net": targets.target_net,
        "discovery": {
            "enabled": targets.discovery_enabled,
            **targets.discovery_meta,
        },
        "scenarios": {},
    }
    if webshell_execution:
        summary["execution_host"] = webshell_execution.get("execution_host")
        summary["webshell_url"] = webshell_execution.get("webshell_url")

    for sid in scenario_ids:
        exclude_phase1 = sid in ("http_followup", "sql_injection")
        started = _last_evidence(events, sid, f"{sid}_started", exclude_phase1=exclude_phase1)
        if not started:
            started = _last_evidence(events, sid, "host_behavior_check_started")
        if not started:
            started = _last_evidence(events, sid, "port_sweep_started")
        if not started:
            started = _last_evidence(events, sid, "http_followup_started")
        if not started:
            started = _last_evidence(events, sid, "ssh_failure_started")
        if not started:
            started = _last_evidence(events, sid, "dns_tunnel_started")
        if not started:
            started = _last_evidence(events, sid, "dga_started")
        if not started:
            started = _last_evidence(events, sid, "rare_protocol_activity_started")
        if not started:
            started = _last_evidence(events, sid, "smb_scenario_started")
        if not started:
            started = _last_evidence(events, sid, "sql_injection_started")

        completed = _last_evidence(events, sid, f"{sid}_completed", exclude_phase1=exclude_phase1)
        if not completed:
            completed = _last_evidence(events, sid, "host_behavior_check_completed")
        if not completed:
            completed = _last_evidence(events, sid, "port_sweep_completed")
        if not completed:
            completed = _last_evidence(events, sid, "http_followup_completed")
        if not completed:
            completed = _last_evidence(events, sid, "ssh_failure_completed")
        if not completed:
            completed = _last_evidence(events, sid, "dns_tunnel_completed")
        if not completed:
            completed = _last_evidence(events, sid, "dga_completed")
        if not completed:
            completed = _last_evidence(events, sid, "rare_protocol_activity_completed")
        if not completed:
            completed = _last_evidence(events, sid, "smb_scenario_completed")
        if not completed:
            completed = _last_evidence(events, sid, "sql_injection_completed")

        skipped = _last_evidence(events, sid, f"{sid}_skipped")
        if not skipped:
            skipped = _last_evidence(events, sid, "smb_scenario_skipped")
        if not skipped:
            skipped = _last_evidence(events, sid, "http_followup_skipped")
        if not skipped:
            skipped = _last_evidence(events, sid, "sql_injection_skipped")
        if not skipped:
            skipped = _last_evidence(events, sid, "ssh_failure_skipped")
        if not skipped:
            skipped = _last_evidence(events, sid, "rare_protocol_activity_skipped")

        scenario_summary: dict[str, Any] = {
            "target_ips": completed.get("targets") or started.get("hosts") or skipped.get("hosts") or [],
            "skipped": bool(skipped),
            "skip_reason": skipped.get("reason"),
        }

        if sid == "host_behavior_check":
            started = started or _last_evidence(events, sid, "host_behavior_check_started")
            completed = completed or _last_evidence(events, sid, "host_behavior_check_completed")
            scenario_summary.update({
                "commands_planned": started.get("commands_planned", 0),
                "commands_dispatched": completed.get("commands_dispatched", 0),
                "host_behavior": completed.get("host_behavior") or {},
            })
        elif sid == "port_sweep":
            scenario_summary.update({
                "probes_planned": started.get("planned_probes", 0),
                "probes_sent": completed.get("probe_count") or _count_events(events, sid, "port_probe_sent"),
                "connections_open": completed.get("connection_success_count", 0),
                "connection_failures": completed.get("connection_failure_count", 0),
                "ports": started.get("ports", []),
                "duration_sec": completed.get("duration_sec"),
                "probes_per_second": completed.get("probes_per_second"),
                "concurrency": started.get("concurrency") or completed.get("concurrency"),
            })
        elif sid == "http_followup":
            request_count = (
                completed.get("request_count")
                or completed.get("requests_sent")
                or _count_events(events, sid, "http_request_sent", exclude_phase1=True)
            )
            scenario_summary.update({
                "requests_planned": 0 if skipped else started.get("planned_requests", 0),
                "requests_sent": request_count,
                "responses_received": completed.get("response_count")
                or completed.get("responses_received", 0),
                "paths_sample": completed.get("paths_used") or started.get("paths_planned"),
                "user_agent_classes": completed.get("user_agent_classes", {}),
                "malicious_rare_ua_count": completed.get("malicious_rare_ua_count", 0),
                "ports_used": completed.get("ports_used", []),
                "schemes_used": completed.get("schemes_used", []),
                "scheme_by_port": completed.get("scheme_by_port", {}),
                "https_fallback": False,
                "https_targets_skipped": completed.get("https_targets_skipped")
                or started.get("https_targets_skipped")
                or skipped.get("https_targets_skipped", []),
                "http_targets": completed.get("http_targets") or started.get("http_targets", []),
                "https_targets": completed.get("https_targets") or started.get("https_targets", []),
                "skipped_no_http_service": skipped.get("skipped_no_http_service", False),
                "http_targets_not_found": skipped.get("http_targets_not_found", False)
                or skipped.get("reason") == "HTTP_TARGETS_NOT_FOUND",
                "duration_sec": completed.get("duration_sec"),
                "response_code_distribution": completed.get("response_code_distribution", {}),
                "selected_http_target_reason": completed.get("selected_http_target_reason")
                or started.get("selected_http_target_reason", ""),
                "redirect_only_warning": completed.get("redirect_only_warning", False),
                "probe_summaries": completed.get("probe_summaries")
                or started.get("probe_summaries")
                or skipped.get("probe_summaries", []),
                "target_probe": completed.get("target_probe")
                or started.get("target_probe")
                or skipped.get("target_probe")
                or completed.get("probe_summaries")
                or started.get("probe_summaries")
                or skipped.get("probe_summaries", []),
                "rejected_targets": completed.get("rejected_targets")
                or started.get("rejected_targets")
                or skipped.get("rejected_targets", []),
                "redirect_only_candidates": completed.get("redirect_only_candidates")
                or started.get("redirect_only_candidates", []),
                "target_count": completed.get("target_count", len(completed.get("target_distribution", {}))),
                "concentrated_target": completed.get("concentrated_target", ""),
                "target_distribution": completed.get("target_distribution", {}),
                "selected_targets": completed.get("selected_targets")
                or started.get("selected_targets", [])
                or skipped.get("selected_targets", []),
                "requests_per_target": completed.get("requests_per_target")
                or started.get("requests_per_target", {}),
                "per_target_request_count": completed.get("per_target_request_count", {}),
                "per_target_error_count": completed.get("per_target_error_count", {}),
                "abnormal_user_agents": completed.get("abnormal_user_agents", 0),
                "normal_user_agents": completed.get("normal_user_agents", 0),
                "abnormal_user_agent_ratio": completed.get("abnormal_user_agent_ratio", 0.0),
                "payload_only_ua": completed.get("payload_only_ua", 0),
                "abnormal_ua_ratio": completed.get("abnormal_ua_ratio")
                or started.get("abnormal_ua_ratio", 0.0),
                "expected_url_scan_distribution": completed.get("expected_url_scan_distribution")
                or started.get("expected_url_scan_distribution", {}),
            })
            burst = (
                completed.get("non_standard_port_burst")
                or _last_evidence(events, sid, "non_standard_port_burst_completed")
                or {}
            )
            if burst.get("enabled"):
                scenario_summary["non_standard_port_burst"] = {
                    "ports": burst.get("ports", []),
                    "attempts": burst.get("attempts", 0),
                    "success": burst.get("success", 0),
                    "failure": burst.get("failure", 0),
                }
            _merge_http_summary_fields(
                scenario_summary,
                _http_scenario_fallback_fields(targets, scenario_params, sid),
            )
        elif sid == "ssh_failure":
            scenario_summary.update({
                "auth_attempts_planned": started.get("planned_attempts", 0),
                "auth_attempts": completed.get("attempt_count") or _count_events(events, sid, "ssh_auth_attempt"),
                "auth_failed": completed.get("failure_count") or _count_events(events, sid, "ssh_auth_failed"),
                "timeouts": _count_events(events, sid, "ssh_auth_timeout"),
                "sample_usernames": completed.get("sample_usernames", []),
            })
        elif sid == "dns_tunnel":
            dns_dispatch = _last_evidence(events, sid, "webshell_command_dispatched")
            scenario_summary.update({
                "queries_planned": started.get("planned_chunks", 0),
                "dns_tunnel_query_sent_count": _count_events(events, sid, "dns_tunnel_query_sent"),
                "dns_tunnel_chunk_created_count": _count_events(events, sid, "dns_tunnel_chunk_created"),
                "queries_sent": completed.get("queries_sent")
                or completed.get("dns_tunnel_query_sent_count")
                or _count_events(events, sid, "dns_tunnel_query_sent"),
                "dns_query_method": completed.get("dns_query_method")
                or started.get("dns_query_method")
                or dns_dispatch.get("dns_query_method"),
                "remote_command_sample": completed.get("remote_command_sample")
                or dns_dispatch.get("remote_command"),
            })
        elif sid == "dga":
            scenario_summary.update({
                "domains_planned": started.get("domains_planned", 0),
                "dga_domain_generated_count": _count_events(events, sid, "dga_domain_generated"),
                "dga_nxdomain_observed_count": _count_events(events, sid, "dga_nxdomain_observed"),
                "dga_resolved_observed_count": _count_events(events, sid, "dga_resolved_observed"),
                "dns_query_method": completed.get("dns_query_method"),
            })
        elif sid == "rare_protocol_activity":
            scenario_summary.update({
                "probes_planned": started.get("planned_probes", 0),
                "attempts": completed.get("attempt_count")
                or _count_events(events, sid, "rare_protocol_probe_attempt"),
                "success": completed.get("success_count")
                or _count_events(events, sid, "rare_protocol_probe_success"),
                "failure": completed.get("failure_count")
                or _count_events(events, sid, "rare_protocol_probe_failure"),
                "protocols": completed.get("protocols") or started.get("protocols", []),
                "execution_host": completed.get("execution_host") or started.get("execution_host", ""),
                "duration_sec": completed.get("duration_sec"),
            })
        elif sid == "smb_login_failure":
            scenario_summary.update({
                "attempts_planned": started.get("planned_attempts", 0),
                "tcp_connect_attempts": completed.get("tcp_connect_attempts", 0),
                "tcp_connect_open": completed.get("tcp_connect_open", 0),
                "tcp_connect_failed": completed.get("tcp_connect_failed", 0),
                "skipped_no_open_service": completed.get("skipped_no_open_service", False),
                "auth_attempts": 0,
                "auth_failed": 0,
            })
        elif sid == "sql_injection":
            request_count = (
                completed.get("requests_sent")
                or completed.get("request_count")
                or _count_events(events, sid, "sql_request_sent", exclude_phase1=True)
            )
            scenario_summary.update({
                "requests_planned": 0 if skipped else started.get("planned_requests", 0),
                "requests_sent": request_count,
                "responses_received": completed.get("response_count", 0),
                "payload_count": completed.get("payload_count", 0),
                "payload_category_distribution": completed.get("payload_category_distribution", {}),
                "transport_distribution": completed.get("transport_distribution", {}),
                "ports_used": completed.get("ports_used", started.get("ports_used", [])),
                "schemes_used": completed.get("schemes_used", started.get("schemes_used", [])),
                "https_targets_skipped": completed.get("https_targets_skipped")
                or started.get("https_targets_skipped")
                or skipped.get("https_targets_skipped", []),
                "http_targets_not_found": skipped.get("http_targets_not_found", False)
                or skipped.get("reason") == "HTTP_TARGETS_NOT_FOUND",
                "duration_sec": completed.get("duration_sec"),
                "selected_http_target_reason": completed.get("selected_http_target_reason")
                or started.get("selected_http_target_reason", ""),
                "probe_summaries": completed.get("probe_summaries")
                or started.get("probe_summaries")
                or skipped.get("probe_summaries", []),
                "target_probe": completed.get("target_probe")
                or started.get("target_probe")
                or skipped.get("target_probe")
                or completed.get("probe_summaries")
                or started.get("probe_summaries")
                or skipped.get("probe_summaries", []),
                "rejected_targets": completed.get("rejected_targets")
                or started.get("rejected_targets")
                or skipped.get("rejected_targets", []),
                "selected_targets": completed.get("selected_targets")
                or started.get("selected_targets", [])
                or skipped.get("selected_targets", []),
                "sql_injection_requests_jsonl": completed.get("sql_injection_requests_jsonl", ""),
            })
            _merge_http_summary_fields(
                scenario_summary,
                _http_scenario_fallback_fields(targets, scenario_params, sid),
            )

        summary["scenarios"][sid] = scenario_summary

    from dsp.protocols.host.behavior_observability import (
        HOST_BEHAVIOR_SCENARIO_ID,
        build_host_behavior_checklist,
        host_behavior_report_payload,
    )

    if HOST_BEHAVIOR_SCENARIO_ID in scenario_ids:
        checklist = build_host_behavior_checklist(store, run_id, HOST_BEHAVIOR_SCENARIO_ID)
        payload = host_behavior_report_payload(checklist)
        summary["host_behavior"] = payload
        hb = summary["scenarios"].setdefault(HOST_BEHAVIOR_SCENARIO_ID, {})
        hb["host_behavior"] = payload

    for sid in ("http_followup", "sql_injection"):
        scenario_probe = summary["scenarios"].get(sid, {})
        target_probe = scenario_probe.get("target_probe")
        if target_probe:
            summary["target_probe"] = target_probe
            summary["selected_targets"] = scenario_probe.get("selected_targets", [])
            summary["selected_attack_targets"] = scenario_probe.get("selected_targets", [])
            summary["rejected_targets"] = scenario_probe.get("rejected_targets", [])
            summary["selected_target_reason"] = scenario_probe.get(
                "selected_http_target_reason", ""
            )
            if scenario_probe.get("skip_reason"):
                summary["http_endpoint_skip_reason"] = scenario_probe["skip_reason"]
            break

    return summary
