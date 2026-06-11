"""Throttled runtime activity output for operational scenario executors."""

from __future__ import annotations

import time
from typing import Any

from dsp.engine.scenario_engine import RunContext, emit_activity

PROGRESS_EVERY_N = 10
PROGRESS_EVERY_SEC = 5.0


class ActivityReporter:
    """Emit detail and progress lines without flooding stdout."""

    def __init__(
        self,
        ctx: RunContext,
        scenario_id: str,
        *,
        total: int | None = None,
    ) -> None:
        self._ctx = ctx
        self._scenario_id = scenario_id
        self._total = total
        self._count = 0
        self._t0 = time.monotonic()
        self._last_progress_at = self._t0
        self._stats: dict[str, Any] = {}

    @property
    def count(self) -> int:
        return self._count

    def update(self, **stats: Any) -> None:
        self._stats.update(stats)

    def record(self, *, action: str, **fields: Any) -> None:
        """Record one unit of work; emit detail every N items and progress every N or 5s."""
        self._count += 1
        now = time.monotonic()
        show_detail = self._count == 1 or self._count % PROGRESS_EVERY_N == 0
        show_progress = show_detail or (now - self._last_progress_at) >= PROGRESS_EVERY_SEC

        if show_detail:
            emit_activity(
                self._ctx,
                self._scenario_id,
                kind="detail",
                seq=self._count,
                total=self._total,
                action=action,
                **fields,
            )

        if show_progress:
            self._emit_progress()
            self._last_progress_at = now

    def emit_open(self, **fields: Any) -> None:
        emit_activity(self._ctx, self._scenario_id, kind="open", **fields)

    def emit_skipped(self, **fields: Any) -> None:
        emit_activity(self._ctx, self._scenario_id, kind="skipped", **fields)

    def emit_started(self, **fields: Any) -> None:
        emit_activity(self._ctx, self._scenario_id, kind="started", **fields)

    def emit_final_progress(self) -> None:
        self._emit_progress()

    def _emit_progress(self) -> None:
        elapsed = time.monotonic() - self._t0
        rate = round(self._count / elapsed, 1) if elapsed > 0 else 0.0
        payload: dict[str, Any] = {
            "kind": "progress",
            "sent": self._count,
            "elapsed_sec": elapsed,
            "rate": rate,
        }
        if self._total is not None:
            payload["total"] = self._total
        payload.update(self._stats)
        emit_activity(self._ctx, self._scenario_id, **payload)
