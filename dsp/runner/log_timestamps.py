"""UTC timestamp formatting and git metadata for operational run logging."""

from __future__ import annotations

import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def format_utc_timestamp(value: datetime | str | None) -> str:
    """Format a datetime as ``2026-06-23T01:22:33Z``."""
    if value is None:
        return ""
    if isinstance(value, str):
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    else:
        dt = value
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    else:
        dt = dt.astimezone(timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def collect_git_info(repo_root: Path | None = None) -> dict[str, str | None]:
    """Return short commit hash and branch name for the installed DSP checkout."""
    root = repo_root or _default_repo_root()
    if root is None:
        return {"git_commit": None, "git_branch": None}
    try:
        commit = subprocess.check_output(
            ["git", "-C", str(root), "rev-parse", "--short", "HEAD"],
            stderr=subprocess.DEVNULL,
            text=True,
        ).strip()
        branch = subprocess.check_output(
            ["git", "-C", str(root), "rev-parse", "--abbrev-ref", "HEAD"],
            stderr=subprocess.DEVNULL,
            text=True,
        ).strip()
    except (subprocess.CalledProcessError, FileNotFoundError, OSError):
        return {"git_commit": None, "git_branch": None}
    return {"git_commit": commit or None, "git_branch": branch or None}


def _default_repo_root() -> Path | None:
    here = Path(__file__).resolve()
    for parent in here.parents:
        if (parent / ".git").exists():
            return parent
    return None


def apply_run_timing_metadata(
    run: Any,
    *,
    started_at: datetime,
    ended_at: datetime | None,
) -> None:
    """Populate UTC timing fields on a Run before writing run.json."""
    run.started_at_utc = format_utc_timestamp(started_at)
    if ended_at is not None:
        run.completed_at_utc = format_utc_timestamp(ended_at)
        run.duration_seconds = max(0.0, (ended_at - started_at).total_seconds())
    else:
        run.completed_at_utc = None
        run.duration_seconds = None
