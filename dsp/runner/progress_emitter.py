"""Progress emitter — bridges RunManager, scenarios, and OperationalConsole."""

from __future__ import annotations

import threading
import time
from collections.abc import Callable
from typing import Any

HEARTBEAT_INTERVAL_SEC = 5.0

_ACTIVITY_COUNTER_KEYS: dict[str, str] = {
    "probe": "probes_sent",
    "send": "queries_sent",
    "request": "requests_sent",
    "bind_attempt": "attempts_sent",
    "auth_attempt": "attempts_sent",
}


class ProgressEmitter:
    """Emit runtime progress phases to an optional callback."""

    def __init__(
        self,
        callback: Callable[[str, dict[str, Any]], None] | None = None,
    ) -> None:
        self._callback = callback
        self._scenario_id: str | None = None
        self._scenario_start: float = 0.0
        self._counters: dict[str, int] = {}
        self._stop_heartbeat = threading.Event()
        self._heartbeat_thread: threading.Thread | None = None

    def emit(self, phase: str, data: dict[str, Any]) -> None:
        if self._callback is not None:
            self._callback(phase, data)

    def on_scenario_started(self, scenario_id: str) -> None:
        self._stop_heartbeat_thread()
        self._scenario_id = scenario_id
        self._scenario_start = time.monotonic()
        self._counters = {}
        self._stop_heartbeat.clear()
        self._heartbeat_thread = threading.Thread(
            target=self._heartbeat_loop,
            name=f"dsp-heartbeat-{scenario_id}",
            daemon=True,
        )
        self._heartbeat_thread.start()

    def on_scenario_completed(self) -> None:
        self._stop_heartbeat_thread()
        self._scenario_id = None
        self._counters = {}

    def emit_activity(self, scenario_id: str, **fields: Any) -> None:
        action = fields.get("action")
        if isinstance(action, str):
            counter_key = _ACTIVITY_COUNTER_KEYS.get(action)
            if counter_key:
                self._counters[counter_key] = self._counters.get(counter_key, 0) + 1
        self.emit("activity", {"scenario_id": scenario_id, **fields})

    def _heartbeat_loop(self) -> None:
        while not self._stop_heartbeat.wait(HEARTBEAT_INTERVAL_SEC):
            scenario_id = self._scenario_id
            if scenario_id is None:
                continue
            elapsed = time.monotonic() - self._scenario_start
            self.emit(
                "heartbeat",
                {
                    "scenario_id": scenario_id,
                    "elapsed_sec": elapsed,
                    "counters": dict(self._counters),
                },
            )

    def _stop_heartbeat_thread(self) -> None:
        self._stop_heartbeat.set()
        thread = self._heartbeat_thread
        if thread is not None and thread.is_alive():
            thread.join(timeout=HEARTBEAT_INTERVAL_SEC + 1.0)
        self._heartbeat_thread = None
