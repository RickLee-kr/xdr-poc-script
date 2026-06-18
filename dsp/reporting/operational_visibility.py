"""Operational visibility — planned vs actual reconciliation from Event Store only."""

from __future__ import annotations

from typing import Any

from dsp.engine.scenario_engine import TargetSet
from dsp.event_store import EventStore
from dsp.runtime.operational_profiles import scenario_display_name
from dsp.runtime.traffic_summary import build_traffic_summary

# Discovery capability → operator-facing service label
_DISCOVERY_SERVICE_LABELS: dict[str, str] = {
    "http_targets": "HTTP",
    "https_targets": "HTTPS",
    "ssh_hosts": "SSH",
    "ldap_hosts": "LDAP",
    "smb_hosts": "SMB",
    "kerberos_hosts": "Kerberos",
    "dns_hosts": "DNS",
}

# Scenario → discovery capability for selection trace (when not skipped at runtime)
_SCENARIO_DISCOVERY_CAPABILITY: dict[str, str | tuple[str, ...]] = {
    "http_followup": ("http_targets", "https_targets"),
    "sql_injection": ("http_targets", "https_targets"),
    "ssh_failure": "ssh_hosts",
    "ldap_enumeration": "ldap_hosts",
    "smb_login_failure": "smb_hosts",
    "kerberos_failure": "kerberos_hosts",
    "dns_tunnel": "dns_hosts",
    "dga": "dns_hosts",
    "host_behavior_check": (),
    "rare_protocol_activity": (),
    "port_sweep": (),
}

_SKIP_REASON_ALIASES: dict[str, str] = {
    "skipped_no_open_service": "no_smb_service_discovered",
    "skipped_no_open_service: no smb_hosts (TCP/445) from discovery": "no_smb_service_discovered",
    "no_open_445_service": "no_smb_service_discovered",
    "HTTP_TARGETS_NOT_FOUND": "no_http_service_discovered",
    "skipped_no_http_service": "no_http_service_discovered",
    "no_ldap_hosts_discovered": "no_ldap_service_discovered",
    "no_kerberos_hosts_discovered": "no_kerberos_service_discovered",
    "no_dns_hosts_discovered": "no_dns_service_discovered",
    "no_probe_plans": "no_eligible_target",
    "windows_family_placeholder": "webshell_family_not_supported",
    "no_webshell_target_host": "no_webshell_target_host",
    "ssh_failure_skipped": "no_ssh_service_discovered",
}


def _normalize_event(event: Any) -> dict[str, Any]:
    if isinstance(event, dict):
        return {
            "scenario_id": event.get("scenario_id", ""),
            "event": event.get("event", ""),
            "evidence": event.get("evidence") or {},
            "status": event.get("status", ""),
        }
    to_dict = getattr(event, "to_dict", None)
    if callable(to_dict):
        data = to_dict()
        return {
            "scenario_id": data.get("scenario_id", ""),
            "event": data.get("event", ""),
            "evidence": data.get("evidence") or {},
            "status": data.get("status", ""),
        }
    return {
        "scenario_id": event.scenario_id,
        "event": event.event,
        "evidence": event.evidence or {},
        "status": event.status,
    }


def _last_evidence(events: list[dict[str, Any]], scenario_id: str, event_name: str) -> dict[str, Any]:
    for item in reversed(events):
        if item.get("scenario_id") == scenario_id and item.get("event") == event_name:
            return dict(item.get("evidence") or {})
    return {}


def _find_skip_evidence(events: list[dict[str, Any]], scenario_id: str) -> dict[str, Any]:
    skip_names = (
        f"{scenario_id}_skipped",
        "smb_scenario_skipped",
        "http_followup_skipped",
        "sql_injection_skipped",
        "ssh_failure_skipped",
        "rare_protocol_activity_skipped",
        "ldap_enumeration_skipped",
        "kerberos_failure_skipped",
        "dns_tunnel_skipped",
        "scenario_skipped",
    )
    for name in skip_names:
        evidence = _last_evidence(events, scenario_id, name)
        if evidence:
            return evidence
    return {}


def _normalize_skip_reason(raw: str | None) -> str:
    if not raw:
        return "scenario_skipped"
    text = str(raw).strip()
    if text in _SKIP_REASON_ALIASES:
        return _SKIP_REASON_ALIASES[text]
    lowered = text.lower()
    for key, value in _SKIP_REASON_ALIASES.items():
        if key.lower() in lowered:
            return value
    if "ldap" in lowered and "no" in lowered:
        return "no_ldap_service_discovered"
    if "kerberos" in lowered and "no" in lowered:
        return "no_kerberos_service_discovered"
    if "dns" in lowered and "no" in lowered:
        return "no_dns_service_discovered"
    if "smb" in lowered:
        return "no_smb_service_discovered"
    if "http" in lowered:
        return "no_http_service_discovered"
    if "ssh" in lowered:
        return "no_ssh_service_discovered"
    return text.replace(" ", "_")


def _planned_actual_fields(
    scenario_id: str,
    started: dict[str, Any],
    completed: dict[str, Any],
    skipped: dict[str, Any],
    scenario_traffic: dict[str, Any],
) -> tuple[int, int, str, str]:
    """Return planned, actual, execution_status, execution_reason."""
    if skipped:
        reason = _normalize_skip_reason(skipped.get("reason"))
        return 0, 0, "skipped", reason

    planned = 0
    actual = 0
    unit = "units"

    if scenario_id in ("http_followup", "sql_injection"):
        planned = int(
            started.get("planned_requests")
            or completed.get("requests_planned")
            or scenario_traffic.get("requests_planned", 0)
        )
        actual = int(
            completed.get("requests_sent")
            or completed.get("request_count")
            or scenario_traffic.get("requests_sent", 0)
        )
        unit = "requests"
    elif scenario_id == "port_sweep":
        planned = int(started.get("planned_probes") or scenario_traffic.get("probes_planned", 0))
        actual = int(completed.get("probe_count") or scenario_traffic.get("probes_sent", 0))
        unit = "probes"
    elif scenario_id == "ssh_failure":
        planned = int(started.get("planned_attempts") or scenario_traffic.get("auth_attempts_planned", 0))
        actual = int(completed.get("attempt_count") or scenario_traffic.get("auth_attempts", 0))
        unit = "attempts"
    elif scenario_id == "dns_tunnel":
        planned = int(started.get("planned_chunks") or scenario_traffic.get("queries_planned", 0))
        actual = int(completed.get("chunks_sent") or scenario_traffic.get("queries_sent", 0))
        unit = "queries"
    elif scenario_id == "dga":
        planned = int(started.get("planned_domains") or scenario_traffic.get("domains_planned", 0))
        actual = int(completed.get("domains_generated") or scenario_traffic.get("domains_generated", 0))
        unit = "domains"
    elif scenario_id == "rare_protocol_activity":
        planned = int(started.get("planned_probes") or scenario_traffic.get("probes_planned", 0))
        actual = int(completed.get("attempt_count") or scenario_traffic.get("attempts", 0))
        unit = "attempts"
    elif scenario_id == "smb_login_failure":
        planned = int(started.get("planned_attempts") or scenario_traffic.get("attempts_planned", 0))
        actual = int(completed.get("tcp_connect_attempts") or scenario_traffic.get("tcp_connect_attempts", 0))
        unit = "attempts"
    elif scenario_id in ("ldap_enumeration", "kerberos_failure"):
        planned = int(started.get("planned_attempts") or started.get("planned_queries", 0))
        actual = int(completed.get("attempt_count") or completed.get("query_count", 0))
        unit = "attempts"
    elif scenario_id == "host_behavior_check":
        planned = int(started.get("commands_planned") or 0)
        actual = int(completed.get("commands_dispatched") or 0)
        unit = "commands"
    else:
        planned = int(started.get("planned_requests") or started.get("planned_probes") or 0)
        actual = int(completed.get("request_count") or completed.get("attempt_count") or 0)

    stored_status = completed.get("execution_status")
    stored_reason = completed.get("execution_reason")
    if stored_status and stored_reason:
        return planned, actual, str(stored_status), str(stored_reason)

    if planned == 0 and actual == 0:
        return 0, 0, "skipped", "no_eligible_target"
    if actual == 0:
        return planned, 0, "skipped", "target_unavailable"
    if actual < planned:
        ratio = actual / planned if planned else 0.0
        reason = "scenario_cap"
        if completed.get("timeouts") or completed.get("timeout_count"):
            reason = "response_limit"
        if completed.get("rate_limited"):
            reason = "rate_limit"
        _ = ratio
        return planned, actual, "partial", reason
    return planned, actual, "full", "completed"

    _ = unit  # reserved for formatted output labels


def build_discovery_summary(discovery: dict[str, Any]) -> dict[str, Any]:
    service_hosts: dict[str, list[str]] = discovery.get("service_hosts") or {}
    lines: list[str] = ["Discovery Summary", ""]
    summary_hosts: dict[str, int] = {}
    for cap, label in _DISCOVERY_SERVICE_LABELS.items():
        count = len(service_hosts.get(cap, []))
        summary_hosts[label] = count
        lines.append(f"{label} hosts={count}")
    http_n = len(service_hosts.get("http_targets", []))
    https_n = len(service_hosts.get("https_targets", []))
    if http_n or https_n:
        summary_hosts["HTTP"] = http_n + https_n
    lines.append("")
    return {"hosts_by_service": summary_hosts, "service_hosts": service_hosts, "lines": lines}


def _selection_reason_for_scenario(
    scenario_id: str,
    *,
    skipped: bool,
    skip_reason: str,
    discovery: dict[str, Any],
    scenario_traffic: dict[str, Any],
) -> tuple[str, str]:
    """Return (status, reason) for scenario selection trace."""
    if skipped:
        return "skipped", skip_reason or "scenario_skipped"

    caps = _SCENARIO_DISCOVERY_CAPABILITY.get(scenario_id)
    service_hosts: dict[str, list[str]] = discovery.get("service_hosts") or {}

    if scenario_id == "http_followup":
        if service_hosts.get("http_targets") or service_hosts.get("https_targets"):
            return "selected", "http_service_discovered"
        return "selected", "http_followup_executed"
    if scenario_id == "sql_injection":
        if scenario_traffic.get("http_targets_not_found"):
            return "skipped", "no_http_service_discovered"
        return "selected", "http_error_responses_available"
    if scenario_id == "ssh_failure":
        if service_hosts.get("ssh_hosts"):
            return "selected", "ssh_service_discovered"
        return "selected", "ssh_failure_executed"
    if scenario_id == "smb_login_failure":
        if not service_hosts.get("smb_hosts"):
            return "skipped", "no_smb_service_discovered"
        return "selected", "smb_service_discovered"
    if scenario_id == "ldap_enumeration":
        if not service_hosts.get("ldap_hosts"):
            return "skipped", "no_ldap_service_discovered"
        return "selected", "ldap_service_discovered"
    if scenario_id == "kerberos_failure":
        if not service_hosts.get("kerberos_hosts"):
            return "skipped", "no_kerberos_service_discovered"
        return "selected", "kerberos_service_discovered"
    if scenario_id == "dns_tunnel":
        if not service_hosts.get("dns_hosts"):
            return "skipped", "no_dns_service_discovered"
        return "selected", "dns_service_discovered"
    if scenario_id == "dga":
        if not service_hosts.get("dns_hosts"):
            return "skipped", "no_dns_service_discovered"
        return "selected", "dns_resolver_available"
    if scenario_id == "host_behavior_check":
        return "selected", "host_behavior_check_enabled"
    if scenario_id == "rare_protocol_activity":
        return "selected", "rare_protocol_probe_plan"
    if scenario_id == "port_sweep":
        return "selected", "internal_recon_port_sweep"
    if caps:
        return "selected", f"{scenario_id}_executed"
    return "selected", f"{scenario_id}_executed"


def build_scenario_selection_trace(
    scenario_ids: list[str],
    *,
    reconciliations: dict[str, dict[str, Any]],
    discovery: dict[str, Any],
    scenario_traffic: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    lines: list[str] = ["Scenario Selection", ""]
    entries: list[dict[str, str]] = []
    for sid in scenario_ids:
        recon = reconciliations.get(sid, {})
        skipped = recon.get("execution_status") == "skipped"
        skip_reason = str(recon.get("execution_reason", ""))
        status, reason = _selection_reason_for_scenario(
            sid,
            skipped=skipped,
            skip_reason=skip_reason,
            discovery=discovery,
            scenario_traffic=scenario_traffic.get(sid, {}),
        )
        if skipped and skip_reason:
            status = "skipped"
            reason = skip_reason
        label = scenario_display_name(sid)
        lines.append(label)
        lines.append(status)
        lines.append(f"reason={reason}")
        extra_key = {
            "no_smb_service_discovered": "discovered_smb_hosts",
            "no_ldap_service_discovered": "discovered_ldap_hosts",
            "no_kerberos_service_discovered": "discovered_kerberos_hosts",
            "no_dns_service_discovered": "discovered_dns_hosts",
        }.get(reason)
        if extra_key:
            service_hosts = discovery.get("service_hosts") or {}
            cap = extra_key.replace("discovered_", "").replace("_hosts", "_hosts")
            cap_map = {
                "smb_hosts": "smb_hosts",
                "ldap_hosts": "ldap_hosts",
                "kerberos_hosts": "kerberos_hosts",
                "dns_hosts": "dns_hosts",
            }
            count = len(service_hosts.get(cap_map.get(cap, cap), []))
            lines.append(f"{extra_key}={count}")
        lines.append("")
        entries.append({"scenario_id": sid, "status": status, "reason": reason})
    return {"entries": entries, "lines": lines}


def build_scenario_reconciliations(
    events: list[dict[str, Any]],
    scenario_ids: list[str],
    scenario_traffic: dict[str, dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    normalized = [_normalize_event(e) for e in events]
    result: dict[str, dict[str, Any]] = {}
    for sid in scenario_ids:
        started = _last_evidence(normalized, sid, f"{sid}_started")
        if not started:
            for alt in (
                "port_sweep_started",
                "http_followup_started",
                "ssh_failure_started",
                "rare_protocol_activity_started",
                "smb_scenario_started",
                "sql_injection_started",
                "ldap_enum_started",
                "kerberos_scenario_started",
                "dns_tunnel_started",
                "dga_started",
                "host_behavior_check_started",
            ):
                started = _last_evidence(normalized, sid, alt)
                if started:
                    break
        completed = _last_evidence(normalized, sid, f"{sid}_completed")
        if not completed:
            for alt in (
                "port_sweep_completed",
                "http_followup_completed",
                "ssh_failure_completed",
                "rare_protocol_activity_completed",
                "smb_scenario_completed",
                "sql_injection_completed",
                "ldap_enum_completed",
                "kerberos_scenario_completed",
                "dns_tunnel_completed",
                "dga_completed",
                "host_behavior_check_completed",
            ):
                completed = _last_evidence(normalized, sid, alt)
                if completed:
                    break
        skipped = _find_skip_evidence(normalized, sid)
        traffic = scenario_traffic.get(sid, {})
        if traffic.get("skipped") and not skipped:
            skipped = {"reason": traffic.get("skip_reason")}

        planned, actual, status, reason = _planned_actual_fields(
            sid, started, completed, skipped, traffic
        )
        ratio = round((actual / planned) * 100, 1) if planned else 0.0
        result[sid] = {
            "planned": planned,
            "actual": actual,
            "execution_status": status,
            "execution_reason": reason,
            "execution_ratio_pct": ratio,
        }
    return result


def _outcome_label(outcome: str, *, success: bool) -> str:
    if success:
        return "connected"
    text = (outcome or "").lower()
    if "timeout" in text:
        return "timeout"
    if "refused" in text:
        return "refused"
    if "error" in text:
        return "error"
    return outcome or "failed"


def build_rare_protocol_detail(events: list[dict[str, Any]], scenario_id: str = "rare_protocol_activity") -> dict[str, Any]:
    protocol_rows: list[dict[str, str]] = []
    per_protocol: dict[str, dict[str, int]] = {}
    for item in events:
        if item.get("scenario_id") != scenario_id:
            continue
        name = item.get("event", "")
        if name not in (
            "rare_protocol_probe_attempt",
            "rare_protocol_probe_success",
            "rare_protocol_probe_failure",
        ):
            continue
        evidence = item.get("evidence") or {}
        protocol = str(evidence.get("protocol", "unknown")).upper()
        bucket = per_protocol.setdefault(protocol.lower(), {"attempts": 0, "success": 0, "failed": 0})
        if name == "rare_protocol_probe_attempt":
            bucket["attempts"] += 1
        elif name == "rare_protocol_probe_success":
            bucket["success"] += 1
            protocol_rows.append(
                {
                    "protocol": protocol,
                    "status": "attempted",
                    "result": _outcome_label(str(evidence.get("outcome", "")), success=True),
                }
            )
        else:
            bucket["failed"] += 1
            protocol_rows.append(
                {
                    "protocol": protocol,
                    "status": "attempted",
                    "result": _outcome_label(str(evidence.get("outcome", "")), success=False),
                }
            )

    lines: list[str] = []
    for row in protocol_rows:
        lines.append(row["protocol"])
        lines.append(row["status"])
        lines.append(f"result={row['result']}")
        lines.append("")

    summary_lines: list[str] = [scenario_display_name(scenario_id), ""]
    for proto in sorted(per_protocol):
        counts = per_protocol[proto]
        summary_lines.append(f"{proto}_attempts={counts['attempts']}")
        if counts["success"]:
            summary_lines.append(f"{proto}_success={counts['success']}")
        if counts["failed"]:
            summary_lines.append(f"{proto}_failed={counts['failed']}")
    summary_lines.append("")

    return {
        "protocol_rows": protocol_rows,
        "per_protocol": per_protocol,
        "detail_lines": lines,
        "summary_lines": summary_lines,
    }


def build_host_behavior_summary(events: list[dict[str, Any]], scenario_id: str = "host_behavior_check") -> dict[str, Any]:
    def _count(event_name: str) -> int:
        return sum(
            1
            for item in events
            if item.get("scenario_id") == scenario_id and item.get("event") == event_name
        )

    eicar_created = _count("eicar_file_created") + _count("eicar_variant_created")
    eicar_accessed = _count("eicar_file_accessed") + _count("eicar_variant_accessed")
    eicar_deleted = _count("eicar_file_deleted") + _count("eicar_variant_deleted")
    credential = (
        _count("credential_artifact_enumeration")
        + _count("ssh_key_enumeration")
        + _count("pem_file_enumeration")
    )
    script_created = _count("suspicious_script_created")
    persistence_created = _count("persistence_artifact_created")
    persistence_removed = _count("persistence_artifact_deleted")
    archive_created = _count("archive_created")
    commands = _count("host_behavior_command_dispatched")

    lines = [
        "Host Behavior Summary",
        "",
        "eicar_test_file",
        f"created={eicar_created}",
        f"accessed={eicar_accessed}",
        f"deleted={eicar_deleted}",
        "",
        "credential_store_access",
        f"attempts={credential}",
        "",
        "script_drop",
        f"created={script_created}",
        "",
        "persistence_simulation",
        f"artifacts_created={persistence_created}",
        f"artifacts_removed={persistence_removed}",
        "",
        "archive_activity",
        f"created={archive_created}",
        "",
        "service_manipulation",
        f"actions={persistence_created + persistence_removed}",
        "",
        "suspicious_admin_tool_usage",
        f"executions={script_created + commands}",
        "",
    ]
    return {
        "eicar_test_file": {"created": eicar_created, "accessed": eicar_accessed, "deleted": eicar_deleted},
        "credential_store_access": {"attempts": credential},
        "script_drop": {"created": script_created},
        "persistence_simulation": {
            "artifacts_created": persistence_created,
            "artifacts_removed": persistence_removed,
        },
        "archive_activity": {"created": archive_created},
        "service_manipulation": {"actions": persistence_created + persistence_removed},
        "suspicious_admin_tool_usage": {"executions": script_created + commands},
        "lines": lines,
    }


def format_reconciliation_lines(reconciliations: dict[str, dict[str, Any]]) -> list[str]:
    lines: list[str] = ["Planned vs Actual Summary", ""]
    for sid, recon in reconciliations.items():
        label = scenario_display_name(sid)
        lines.append(label)
        lines.append("")
        lines.append(f"planned={recon['planned']}")
        lines.append(f"actual={recon['actual']}")
        if recon["planned"]:
            lines.append(f"execution_ratio={recon['execution_ratio_pct']}%")
        lines.append(f"execution_status={recon['execution_status']}")
        lines.append(f"execution_reason={recon['execution_reason']}")
        lines.append("")
    return lines


def format_skip_reason_summary(reconciliations: dict[str, dict[str, Any]]) -> list[str]:
    lines: list[str] = ["Skip Reason Summary", ""]
    any_skip = False
    for sid, recon in reconciliations.items():
        if recon.get("execution_status") != "skipped":
            continue
        any_skip = True
        lines.append(scenario_display_name(sid))
        lines.append("status=skipped")
        lines.append(f"reason={recon.get('execution_reason', 'scenario_skipped')}")
        lines.append("")
    if not any_skip:
        lines.append("(no scenarios skipped)")
        lines.append("")
    return lines


def reconcile_scenario(
    store: EventStore,
    run_id: str,
    scenario_id: str,
    *,
    scenario_traffic: dict[str, Any] | None = None,
) -> dict[str, Any]:
    events = [_normalize_event(e) for e in store.list_events(run_id)]
    traffic = {scenario_id: scenario_traffic or {}}
    return build_scenario_reconciliations(events, [scenario_id], traffic).get(scenario_id, {})


def build_operational_visibility(
    store: EventStore,
    *,
    run_id: str,
    scenario_ids: list[str],
    targets: TargetSet,
    traffic_profile: str,
) -> dict[str, Any]:
    """Build full operational visibility package from Event Store."""
    events = [_normalize_event(e) for e in store.list_events(run_id)]
    traffic_summary = build_traffic_summary(
        store,
        run_id=run_id,
        scenario_ids=scenario_ids,
        targets=targets,
        traffic_profile=traffic_profile,
    )
    discovery = traffic_summary.get("discovery") or {}
    scenario_traffic = traffic_summary.get("scenarios") or {}

    reconciliations = build_scenario_reconciliations(events, scenario_ids, scenario_traffic)
    discovery_block = build_discovery_summary(discovery)
    selection_block = build_scenario_selection_trace(
        scenario_ids,
        reconciliations=reconciliations,
        discovery=discovery,
        scenario_traffic=scenario_traffic,
    )
    rare_detail = build_rare_protocol_detail(events)
    host_summary = build_host_behavior_summary(events)

    console_lines: list[str] = []
    console_lines.extend(discovery_block["lines"])
    console_lines.extend(selection_block["lines"])
    console_lines.extend(format_skip_reason_summary(reconciliations))
    console_lines.extend(format_reconciliation_lines(reconciliations))
    if "rare_protocol_activity" in scenario_ids:
        console_lines.extend(rare_detail["detail_lines"])
        console_lines.extend(rare_detail["summary_lines"])
    if "host_behavior_check" in scenario_ids:
        console_lines.extend(host_summary["lines"])

    return {
        "discovery_summary": discovery_block,
        "scenario_selection": selection_block,
        "reconciliations": reconciliations,
        "rare_protocol_detail": rare_detail,
        "host_behavior_summary": host_summary,
        "traffic_summary": traffic_summary,
        "console_lines": console_lines,
        "report_sections": _build_report_sections(
            discovery_block,
            selection_block,
            reconciliations,
            rare_detail,
            host_summary,
            scenario_ids,
        ),
    }


def _build_report_sections(
    discovery_block: dict[str, Any],
    selection_block: dict[str, Any],
    reconciliations: dict[str, dict[str, Any]],
    rare_detail: dict[str, Any],
    host_summary: dict[str, Any],
    scenario_ids: list[str],
) -> list[str]:
    lines: list[str] = [
        "## Operational Visibility",
        "",
        "### Discovery Summary",
        "",
        *discovery_block["lines"],
        "### Scenario Selection Trace",
        "",
        *selection_block["lines"],
        "### Skip Reason Summary",
        "",
        *format_skip_reason_summary(reconciliations),
        "### Planned vs Actual Summary",
        "",
        *format_reconciliation_lines(reconciliations),
    ]
    if "rare_protocol_activity" in scenario_ids:
        lines.extend(["### Rare Protocol Activity Detail", "", *rare_detail["detail_lines"]])
        lines.extend(["### Rare Protocol Activity Summary", "", *rare_detail["summary_lines"]])
    if "host_behavior_check" in scenario_ids:
        lines.extend(["### Host Behavior Summary", "", *host_summary["lines"]])
    return lines


def derive_execution_reconciliation(
    planned: int,
    actual: int,
    *,
    cancelled: bool = False,
    timeouts: int = 0,
) -> tuple[str, str]:
    """Return execution_status and execution_reason for completed scenario evidence."""
    if actual == 0:
        return "skipped", "target_unavailable"
    if actual >= planned:
        return "full", "completed"
    if cancelled:
        return "partial", "scenario_cap"
    if timeouts:
        return "partial", "response_limit"
    return "partial", "scenario_cap"


def reconciliation_fields_for_console(reconciliations: dict[str, dict[str, Any]], scenario_id: str) -> list[str]:
    recon = reconciliations.get(scenario_id)
    if not recon:
        return []
    lines = [
        f"planned={recon['planned']}",
        f"executed={recon['actual']}",
    ]
    if recon["planned"]:
        lines.append(f"execution_ratio={recon['execution_ratio_pct']}%")
    lines.append(f"execution_status={recon['execution_status']}")
    lines.append(f"execution_reason={recon['execution_reason']}")
    return lines
