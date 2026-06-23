"""Human-readable progress and evidence output for operational `dsp run`."""

from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, TextIO

from dsp.runner.log_timestamps import format_utc_timestamp
from dsp.runner.traffic_summary import (
    format_scenario_traffic_block,
    traffic_lines_for_scenario,
)
from dsp.runtime.operational_profiles import scenario_display_name

try:
    from dsp.protocols.host.behavior_observability import format_host_behavior_summary_lines
except ImportError:  # pragma: no cover
    format_host_behavior_summary_lines = None  # type: ignore[assignment]

_PROVIDER_LABELS = {
    "local": "local",
    "webshell": "webshell",
}

_SCENARIO_ARTIFACTS: dict[str, tuple[str, ...]] = {
    "http_followup": ("http_followup_requests.jsonl", "http_request_dump.json"),
}


class OperationalConsole:
    """Emit structured progress lines during an operational run."""

    def __init__(
        self,
        *,
        provider: str = "local",
        target_net: str = "",
        profile: str | None = None,
        stream: TextIO | None = None,
    ) -> None:
        self.provider = provider
        self.target_net = target_net
        self.profile = profile
        self._stream = stream or sys.stdout
        self._run_started = False
        self._traffic_summaries: dict[str, dict[str, Any]] = {}
        self._scenario_total = 0
        self._scenario_index = 0
        self._run_dir: Path | None = None
        self._run_started_at: datetime | None = None

    def handle_progress(self, phase: str, data: dict[str, Any]) -> None:
        if phase == "run_started":
            self._emit_run_started(data)
        elif phase == "discovery_started":
            target_net = data.get("target_net") or self.target_net
            self._write_ts("Discovery Started")
            if target_net:
                self._write(f"target_net={target_net}")
            if data.get("candidate_hosts"):
                self._write(f"candidate_hosts={data['candidate_hosts']}")
            if data.get("planned_probes"):
                self._write(f"planned_probes={data['planned_probes']}")
            self._write("")
        elif phase == "discovery_progress":
            completed = data.get("completed", 0)
            total = data.get("total", 0)
            open_endpoints = data.get("open_endpoints", 0)
            alive_hosts = data.get("alive_hosts", 0)
            pct = round((completed / total) * 100, 1) if total else 0.0
            self._write_ts(
                f"Discovery progress: probes={completed}/{total} ({pct}%), "
                f"open={open_endpoints}, alive={alive_hosts}"
            )
        elif phase == "discovery_completed":
            hosts = data.get("hosts_found", 0)
            probed = data.get("probed_hosts", 0)
            alive = data.get("alive_hosts") or []
            open_endpoints = data.get("open_endpoints", 0)
            service_hosts: dict[str, list[str]] = data.get("service_hosts") or {}
            self._write_ts("Discovery Completed")
            if data.get("discovery_method"):
                self._write(f"  discovery_method={data['discovery_method']}")
            if data.get("command_delivery"):
                self._write(f"  command_delivery={data['command_delivery']}")
            if data.get("runner_upload") is False:
                self._write("  runner_upload=false")
            if probed:
                self._write(f"Probed Hosts: {probed}")
            if open_endpoints:
                self._write(f"Open Endpoints: {open_endpoints}")
            self._write(f"Hosts Found: {hosts}")
            if alive:
                self._write(f"Alive: {', '.join(str(h) for h in alive[:8])}{'...' if len(alive) > 8 else ''}")
            for cap, cap_hosts in sorted(service_hosts.items()):
                if cap_hosts:
                    preview = ", ".join(cap_hosts[:4])
                    suffix = "..." if len(cap_hosts) > 4 else ""
                    self._write(f"  {cap}: {len(cap_hosts)} ({preview}{suffix})")
            self._write("")
        elif phase == "targets_selected":
            self._emit_selected_targets(data)
        elif phase == "http_probe_diagnostics":
            self._emit_http_probe_diagnostics(data)
        elif phase == "scenario_started":
            self._emit_scenario_started(data)
        elif phase == "activity":
            self._emit_activity(data)
        elif phase == "heartbeat":
            self._emit_heartbeat(data)
        elif phase == "scenario_completed":
            self._emit_scenario_completed(data)
        elif phase == "scenario_skipped":
            self._emit_scenario_skipped(data)
        elif phase == "evidence_generated":
            self._write_ts("Evidence Generated")
            self._write("")
        elif phase == "run_completed":
            duration = data.get("duration_sec", 0.0)
            events = data.get("event_count", 0)
            raw_summaries = data.get("summaries")
            if raw_summaries:
                self._traffic_summaries = self._normalize_summaries(raw_summaries)
            if data.get("run_dir"):
                self._run_dir = Path(data["run_dir"])
            completed_at = self._coerce_timestamp(data.get("completed_at")) or self._utc_now()
            started_at = self._coerce_timestamp(data.get("started_at")) or self._run_started_at
            git_commit = data.get("git_commit")
            git_branch = data.get("git_branch")
            if git_commit:
                self._write(f"Git Commit: {git_commit}")
            if git_branch:
                self._write(f"Git Branch: {git_branch}")
            if git_commit or git_branch:
                self._write("")
            self._write_ts("Run Completed", at=completed_at)
            self._write("")
            if started_at is not None:
                self._write(f"Started At: {format_utc_timestamp(started_at)}")
            self._write(f"Completed At: {format_utc_timestamp(completed_at)}")
            self._write(f"Duration: {format_duration(duration)}")
            self._write(f"Events Generated: {events}")
            self._write("")
            for warning in data.get("validation_warnings") or []:
                self._write(warning)
            if data.get("validation_warnings"):
                self._write("")

    def print_traffic_summary(self) -> None:
        """Print aggregated per-scenario traffic counters."""
        if not self._traffic_summaries:
            return
        self._write("Traffic Summary")
        self._write("")
        for scenario_id, metrics in self._traffic_summaries.items():
            block = format_scenario_traffic_block(scenario_id, metrics)
            if not block:
                continue
            for line in block:
                self._write(line)
            self._write("")

    def _emit_run_started(self, data: dict[str, Any]) -> None:
        if self._run_started:
            return
        self._run_started = True
        profile = data.get("profile") or self.profile or "normal"
        provider = data.get("provider") or self.provider
        target_net = data.get("target_net") or self.target_net
        started_at = self._coerce_timestamp(data.get("started_at")) or self._utc_now()
        self._run_started_at = started_at
        self._write_ts("DSP Run Started", at=started_at)
        self._write("")
        self._write(f"Provider: {_PROVIDER_LABELS.get(provider, provider)}")
        self._write(f"Target Net: {target_net}")
        self._write(f"Profile: {profile}")
        self._write("")

    def _emit_selected_targets(self, data: dict[str, Any]) -> None:
        groups: dict[str, list[str]] = data.get("groups") or {}
        execution_host = data.get("execution_host")
        if execution_host:
            host = execution_host.get("host", "")
            port = execution_host.get("port", "")
            path = execution_host.get("path", "/")
            self._write("Execution Host:")
            self._write(f"  {host}:{port}{path}")
            self._write("")
            if data.get("attack_target_net"):
                self._write(f"Attack Target Net: {data['attack_target_net']}")
                self._write("")
            alive_hosts = data.get("alive_hosts") or []
            open_endpoints = data.get("open_endpoints")
            if alive_hosts or open_endpoints is not None:
                if open_endpoints is not None:
                    self._write(f"Open Endpoints: {open_endpoints}")
                if alive_hosts:
                    preview = ", ".join(str(h) for h in alive_hosts[:8])
                    suffix = "..." if len(alive_hosts) > 8 else ""
                    self._write(f"Alive Hosts: {preview}{suffix}")
                self._write("")
            self._write("Attack Targets:")
            if not groups:
                self._write("  (none)")
            else:
                for protocol, hosts in groups.items():
                    self._write(f"  {protocol}:")
                    for host_label in hosts:
                        self._write(f"    {host_label}")
            self._write("")
            return
        if not groups:
            return
        self._write("Selected Targets")
        self._write("")
        for protocol, hosts in groups.items():
            self._write(f"{protocol}:")
            for host in hosts:
                self._write(f"  {host}")
            self._write("")

    def _emit_http_probe_diagnostics(self, data: dict[str, Any]) -> None:
        from dsp.engine.host_selection import HttpFollowupSelection, format_http_probe_diagnostic_lines
        from dsp.protocols.http.target_probe import HTTPEndpointProbeResult

        probe_rows = data.get("target_probe") or []
        selected_rows = data.get("selected_endpoint_probe") or []
        if not probe_rows and not selected_rows and not data.get("selected_targets"):
            self._write("HTTP endpoint probe diagnostics:")
            self._write("  (no endpoints probed)")
            self._write("")
            return
        probed = [HTTPEndpointProbeResult.from_dict(dict(row)) for row in probe_rows]
        if selected_rows:
            selected = [HTTPEndpointProbeResult.from_dict(dict(row)) for row in selected_rows]
        else:
            selected = [item for item in probed if item.selected]
        selection = HttpFollowupSelection(
            probed=probed,
            selected=selected,
            skip_reason=data.get("skip_reason"),
            selected_http_target_reason=str(data.get("selected_target_reason") or ""),
        )
        for line in format_http_probe_diagnostic_lines(
            selection,
            discovered_http_hosts=list(data.get("discovered_attack_http_endpoints") or data.get("discovery_http_hosts") or []),
            webshell_endpoint_diagnostics=list(data.get("webshell_endpoint_diagnostics") or []),
            webshell_mode=bool(
                data.get("webshell_url")
                or data.get("execution_host")
                or data.get("webshell_endpoint_diagnostics")
            ),
        ):
            self._write(line)
        if data.get("attack_target_net"):
            self._write(f"attack_target_net={data['attack_target_net']}")
        if data.get("selected_target_reason"):
            self._write(f"selected_target_reason={data['selected_target_reason']}")
        self._write("")

    def _emit_scenario_skipped(self, data: dict[str, Any]) -> None:
        sid = data.get("scenario_id", "")
        reason = data.get("reason", "scenario_skipped")
        if sid:
            self._write_ts(f"{scenario_display_name(sid)} SKIPPED")
            self._write(f"  skip_reason={reason}")
            evidence = data.get("evidence") or {}
            if evidence.get("requests_sent") == 0:
                self._write("  requests_sent=0")
            self._write("")

    def _emit_scenario_started(self, data: dict[str, Any]) -> None:
        scenario_id = data.get("scenario_id", "")
        if not scenario_id:
            return
        index = int(data.get("index", self._scenario_index + 1))
        total = int(data.get("total", self._scenario_total or 1))
        self._scenario_index = index
        self._scenario_total = total
        if data.get("run_dir"):
            self._run_dir = Path(data["run_dir"])
        self._write_ts(f"[{index}/{total}] {scenario_id} STARTED")
        meta = data.get("metadata") or {}
        for key in (
            "target",
            "selected_http_target_reason",
            "planned_requests",
            "planned_probes",
            "planned_attempts",
            "planned_queries",
            "planned_domains",
            "payload_mb",
            "payload_bytes",
            "chunk_size",
            "transport",
            "evidence",
            "concurrency",
            "targets",
            "ports",
            "user_agent_policy",
            "selection_reason",
            "full_sweep_requested",
            "profile",
        ):
            if key in meta and meta[key] is not None:
                self._write(f"{key}={meta[key]}")
        if scenario_id == "http_followup":
            requests_per_target = meta.get("requests_per_target") or {}
            if requests_per_target:
                self._write("HTTP:")
                for target, count in sorted(requests_per_target.items()):
                    self._write(f"  {target} requests={count}")
            if meta.get("selected_targets"):
                self._write(f"selected_targets={meta['selected_targets']}")
            if meta.get("expected_url_scan_distribution"):
                self._write(
                    f"expected_url_scan_distribution={meta['expected_url_scan_distribution']}"
                )
        self._write("")

    def _emit_activity(self, data: dict[str, Any]) -> None:
        scenario_id = data.get("scenario_id", "")
        if not scenario_id:
            return
        kind = data.get("kind", "detail")

        if kind == "skipped":
            self._write(f"[{scenario_id}] skipped")
            for key in ("reason", "auth_attempts"):
                if key in data:
                    self._write(f"{key}={data[key]}")
            self._write("")
            return

        if kind == "discovery":
            self._write("Webshell Discovery")
            for key in (
                "discovery_method",
                "command_delivery",
                "runner_upload",
                "alive_hosts",
                "open_endpoints",
                "probe_batches",
                "output_preview",
            ):
                if key in data and data[key] not in (None, "", 0):
                    self._write(f"  {key}={data[key]}")
            self._write("")
            return

        if kind == "open":
            self._write(f"[{scenario_id}] open")
            if "target" in data:
                self._write(f"target={data['target']}")
            if "port" in data:
                self._write(f"port={data['port']}")
            self._write("")
            return

        if kind == "progress":
            self._write_ts(f"[{scenario_id}] progress")
            self._emit_progress_lines(scenario_id, data)
            self._write("")
            return

        if kind == "started":
            self._write(f"[{scenario_id}]")
            for key, value in data.items():
                if key not in ("scenario_id", "kind"):
                    self._write(f"{key}={value}")
            self._write("")
            return

        self._emit_detail_activity(scenario_id, data)

    def _emit_detail_activity(self, scenario_id: str, data: dict[str, Any]) -> None:
        seq = data.get("seq")
        total = data.get("total")
        label = scenario_id
        if seq is not None and total is not None:
            if scenario_id == "http_followup":
                label = f"[{scenario_id}] request {seq}/{total}"
            elif scenario_id == "ssh_failure":
                label = f"[{scenario_id}] attempt {seq}/{total}"
            elif scenario_id == "port_sweep":
                label = f"[{scenario_id}] probe {seq}/{total}"
            else:
                label = f"[{scenario_id}] {seq}/{total}"
        else:
            label = f"[{scenario_id}]"

        self._write(label)
        field_order = (
            "target",
            "port",
            "method",
            "url",
            "path",
            "query",
            "user_agent",
            "username",
            "user",
            "payload_type",
            "action",
            "result",
            "response_code",
        )
        emitted: set[str] = set()
        for key in field_order:
            if key not in data or key in ("scenario_id", "kind", "seq", "total"):
                continue
            self._write(self._format_field(key, data[key]))
            emitted.add(key)
        for key in sorted(data):
            if key in ("scenario_id", "kind", "seq", "total", *emitted):
                continue
            self._write(self._format_field(key, data[key]))
        self._write("")

    def _emit_progress_lines(self, scenario_id: str, data: dict[str, Any]) -> None:
        sent = data.get("sent")
        total = data.get("total")
        if sent is not None and total is not None:
            if scenario_id == "port_sweep":
                self._write(f"sent={sent}/{total}")
            elif scenario_id in ("dns_tunnel", "dga"):
                label = "queries_sent" if scenario_id == "dns_tunnel" else "domains_generated"
                self._write(f"{label}={sent}/{total}")
            elif scenario_id == "ssh_failure":
                self._write(f"attempts={sent}/{total}")
            else:
                self._write(f"sent={sent}/{total}")

        for key in (
            "open",
            "failed",
            "responses",
            "auth_failed",
            "timeouts",
            "current",
            "target",
            "sample_query",
            "sample_domain",
            "unique_paths",
            "unique_user_agents",
        ):
            if key in data:
                self._write(f"{key}={data[key]}")

        if "elapsed_sec" in data:
            self._write(f"elapsed={format_elapsed(float(data['elapsed_sec']))}")
        if "rate" in data:
            unit = "probes/sec" if scenario_id == "port_sweep" else "rps"
            self._write(f"rate={data['rate']} {unit}")

    def _emit_scenario_completed(self, data: dict[str, Any]) -> None:
        sid = data.get("scenario_id", "")
        metrics = data.get("metrics") or {}
        extras = data.get("extras") or {}
        artifacts = data.get("artifacts") or {}
        if sid:
            if metrics:
                summary = dict(metrics)
                if sid == "http_followup" and extras.get("response_tracking"):
                    summary["response_tracking"] = extras["response_tracking"]
                self._traffic_summaries[sid] = summary
            self._write_ts(f"{scenario_display_name(sid)} Completed")
            for label, value in traffic_lines_for_scenario(sid, metrics):
                self._write(f"  {label}={value}")
            for key in (
                "duration_sec",
                "requests_per_second",
                "probes_per_second",
                "concurrency",
                "unique_paths",
                "unique_user_agents",
                "malicious_rare_ua_count",
                "abnormal_user_agents",
                "normal_user_agents",
                "abnormal_user_agent_ratio",
                "payload_only_ua",
                "target_count",
                "selected_http_target_reason",
            ):
                if key in extras:
                    self._write(f"  {key}={extras[key]}")
            if sid == "http_followup":
                dist = extras.get("response_code_distribution") or {}
                if dist:
                    dist_text = ", ".join(f"{code}={count}" for code, count in sorted(dist.items()))
                    self._write(f"  response_code_distribution={dist_text}")
                if extras.get("response_tracking"):
                    self._write(f"  response_tracking={extras['response_tracking']}")
                target_dist = extras.get("target_distribution") or {}
                if target_dist:
                    self._write(f"  target_distribution={target_dist}")
                if extras.get("redirect_only_warning"):
                    self._write(
                        "  WARN: redirect-only HTTP responses — "
                        "target may be unsuitable for URL/User-Agent detection parity"
                    )
            for name, path in artifacts.items():
                self._write(f"  {name}={path}")
            if sid == "host_behavior_check":
                self._emit_host_behavior_summary(extras)
            self._write("")

    def _emit_host_behavior_summary(self, extras: dict[str, Any]) -> None:
        summary = extras.get("host_behavior_summary")
        if not summary or format_host_behavior_summary_lines is None:
            return
        for line in format_host_behavior_summary_lines(summary):
            self._write(line)
        self._write("")

    def _emit_heartbeat(self, data: dict[str, Any]) -> None:
        scenario_id = data.get("scenario_id", "")
        if not scenario_id:
            return
        elapsed = float(data.get("elapsed_sec", 0.0))
        counters: dict[str, int] = data.get("counters") or {}
        if not counters:
            return
        self._write(f"[{scenario_id}]")
        self._write("running")
        self._write(f"elapsed={format_elapsed(elapsed)}")
        for key in sorted(counters):
            self._write(f"{key}={counters[key]}")

    def print_evidence_summary(self, run_dir: Path) -> None:
        """Print artifact paths after run completion."""
        self.print_traffic_summary()
        resolved = run_dir.resolve()
        self._write("Evidence Summary")
        self._write("")
        self._write("Run Directory:")
        self._write(str(resolved))
        self._write("")

        always: list[tuple[str, list[str]]] = [
            ("Events", ["events.jsonl", "events.db"]),
            ("Report", ["report.md", "report.json"]),
            ("Validation", ["validation.json"]),
        ]
        optional: list[tuple[str, list[str]]] = [
            ("HTTP Evidence", ["http_followup_requests.jsonl", "http_request_dump.json"]),
            ("Traffic Summary", ["traffic_summary.json"]),
            (
                "Manual Verification",
                ["verification_checklist.md", "investigation_notes.md"],
            ),
        ]
        for title, names in always:
            self._write(f"{title}:")
            for name in names:
                self._write(name)
            self._write("")
        for title, names in optional:
            present = [name for name in names if (resolved / name).exists()]
            if not present:
                continue
            self._write(f"{title}:")
            for name in present:
                self._write(name)
            self._write("")

    @staticmethod
    def _format_field(key: str, value: Any) -> str:
        if key == "user_agent":
            return f'user_agent="{value}"'
        return f"{key}={value}"

    @staticmethod
    def _normalize_summaries(
        summaries: dict[str, Any],
    ) -> dict[str, dict[str, Any]]:
        normalized: dict[str, dict[str, Any]] = {}
        for scenario_id, payload in summaries.items():
            if isinstance(payload, dict) and "metrics" in payload:
                normalized[scenario_id] = dict(payload["metrics"])
            elif isinstance(payload, dict):
                normalized[scenario_id] = dict(payload)
        return normalized

    def _write(self, line: str) -> None:
        print(line, file=self._stream, flush=True)

    def _write_ts(self, line: str, *, at: datetime | None = None) -> None:
        self._write(f"{format_utc_timestamp(at or self._utc_now())} | {line}")

    @staticmethod
    def _utc_now() -> datetime:
        return datetime.now(timezone.utc)

    @staticmethod
    def _coerce_timestamp(value: datetime | str | None) -> datetime | None:
        if value is None:
            return None
        if isinstance(value, datetime):
            return value
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))


def format_duration(seconds: float) -> str:
    """Format seconds as HH:MM:SS."""
    total = max(0, int(seconds))
    return str(timedelta(seconds=total))


def format_elapsed(seconds: float) -> str:
    """Format elapsed seconds as HH:MM:SS for heartbeat output."""
    total = max(0, int(seconds))
    hours, remainder = divmod(total, 3600)
    minutes, secs = divmod(remainder, 60)
    return f"{hours:02d}:{minutes:02d}:{secs:02d}"
