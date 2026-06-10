"""Human-readable progress and evidence output for operational `dsp run`."""

from __future__ import annotations

import sys
from datetime import timedelta
from pathlib import Path
from typing import Any, TextIO

from dsp.runner.traffic_summary import (
    format_scenario_traffic_block,
    traffic_lines_for_scenario,
)
from dsp.runtime.operational_profiles import scenario_display_name

_PROVIDER_LABELS = {
    "local": "local",
    "webshell": "webshell",
}


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

    def handle_progress(self, phase: str, data: dict[str, Any]) -> None:
        if phase == "run_started":
            self._emit_run_started(data)
        elif phase == "discovery_started":
            self._write("Discovery Started")
        elif phase == "discovery_completed":
            hosts = data.get("hosts_found", 0)
            probed = data.get("probed_hosts", 0)
            alive = data.get("alive_hosts") or []
            self._write("Discovery Completed")
            if probed:
                self._write(f"Probed Hosts: {probed}")
            self._write(f"Hosts Found: {hosts}")
            if alive:
                self._write(f"Alive: {', '.join(str(h) for h in alive[:8])}{'...' if len(alive) > 8 else ''}")
            self._write("")
        elif phase == "targets_selected":
            self._emit_selected_targets(data)
        elif phase == "scenario_started":
            self._emit_scenario_started(data)
        elif phase == "activity":
            self._emit_activity(data)
        elif phase == "heartbeat":
            self._emit_heartbeat(data)
        elif phase == "scenario_completed":
            sid = data.get("scenario_id", "")
            metrics = data.get("metrics") or {}
            if sid:
                if metrics:
                    self._traffic_summaries[sid] = dict(metrics)
                self._write(f"{scenario_display_name(sid)} Completed")
                for label, value in traffic_lines_for_scenario(sid, metrics):
                    self._write(f"  {label}={value}")
                self._write("")
        elif phase == "evidence_generated":
            self._write("Evidence Generated")
            self._write("")
        elif phase == "run_completed":
            duration = data.get("duration_sec", 0.0)
            events = data.get("event_count", 0)
            raw_summaries = data.get("summaries")
            if raw_summaries:
                self._traffic_summaries = self._normalize_summaries(raw_summaries)
            self._write("Run Completed")
            self._write("")
            self._write(f"Duration: {format_duration(duration)}")
            self._write(f"Events Generated: {events}")
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
        self._write("DSP Run Started")
        self._write("")
        self._write(f"Provider: {_PROVIDER_LABELS.get(provider, provider)}")
        self._write(f"Target Net: {target_net}")
        self._write(f"Profile: {profile}")
        self._write("")

    def _emit_selected_targets(self, data: dict[str, Any]) -> None:
        groups: dict[str, list[str]] = data.get("groups") or {}
        if not groups:
            return
        self._write("Selected Targets")
        self._write("")
        for protocol, hosts in groups.items():
            self._write(f"{protocol}:")
            for host in hosts:
                self._write(f"  {host}")
            self._write("")

    def _emit_scenario_started(self, data: dict[str, Any]) -> None:
        scenario_id = data.get("scenario_id", "")
        if not scenario_id:
            return
        index = int(data.get("index", self._scenario_index + 1))
        total = int(data.get("total", self._scenario_total or 1))
        self._scenario_index = index
        self._scenario_total = total
        self._write(f"[{index}/{total}] {scenario_id} STARTED")
        self._write("")
        meta = data.get("metadata") or {}
        if "targets" in meta:
            self._write(f"targets={meta['targets']}")
        if "ports" in meta:
            self._write(f"ports={meta['ports']}")
        if meta:
            self._write("")

    _ACTIVITY_FIELD_ORDER = (
        "target",
        "port",
        "url",
        "query",
        "user",
        "action",
        "result",
    )

    def _emit_activity(self, data: dict[str, Any]) -> None:
        scenario_id = data.get("scenario_id", "")
        if not scenario_id:
            return
        self._write(f"[{scenario_id}]")
        emitted: set[str] = set()
        for key in self._ACTIVITY_FIELD_ORDER:
            if key in data:
                self._write(f"{key}={data[key]}")
                emitted.add(key)
        for key in sorted(data):
            if key in ("scenario_id", *emitted):
                continue
            self._write(f"{key}={data[key]}")

    def _emit_heartbeat(self, data: dict[str, Any]) -> None:
        scenario_id = data.get("scenario_id", "")
        if not scenario_id:
            return
        elapsed = float(data.get("elapsed_sec", 0.0))
        counters: dict[str, int] = data.get("counters") or {}
        self._write(f"[{scenario_id}]")
        self._write("running")
        self._write(f"elapsed={format_elapsed(elapsed)}")
        for key in sorted(counters):
            self._write(f"{key}={counters[key]}")

    def print_evidence_summary(self, run_dir: Path) -> None:
        """Print artifact paths after run completion."""
        self.print_traffic_summary()
        self._write("Evidence Summary")
        self._write("")
        self._write("Run Directory:")
        self._write(str(run_dir.resolve()))
        self._write("")
        self._write("Events:")
        self._write("events.jsonl")
        self._write("")
        self._write("Report:")
        self._write("report.md")
        self._write("")
        self._write("Validation:")
        self._write("validation.json")

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
