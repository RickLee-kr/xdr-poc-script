"""Command execution data models — metadata only, no execution."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any
from uuid import uuid4


class CommandStatus(StrEnum):
    """Lifecycle states for a command execution request."""

    CREATED = "created"
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    TIMEOUT = "timeout"
    CANCELLED = "cancelled"


@dataclass
class CommandRequest:
    """Command execution request metadata — no transport or network binding."""

    command_id: str
    command: str
    arguments: list[str] = field(default_factory=list)
    working_directory: str = ""
    environment: dict[str, str] = field(default_factory=dict)
    timeout_seconds: int = 300
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> dict[str, Any]:
        return {
            "command_id": self.command_id,
            "command": self.command,
            "arguments": list(self.arguments),
            "working_directory": self.working_directory,
            "environment": dict(self.environment),
            "timeout_seconds": self.timeout_seconds,
            "created_at": self.created_at.isoformat().replace("+00:00", "Z"),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CommandRequest:
        return cls(
            command_id=data["command_id"],
            command=data["command"],
            arguments=[str(arg) for arg in data.get("arguments") or []],
            working_directory=str(data.get("working_directory", "")),
            environment={
                str(key): str(value)
                for key, value in (data.get("environment") or {}).items()
            },
            timeout_seconds=int(data.get("timeout_seconds", 300)),
            created_at=datetime.fromisoformat(
                data["created_at"].replace("Z", "+00:00")
            ),
        )

    @classmethod
    def new(
        cls,
        command: str,
        *,
        command_id: str | None = None,
        arguments: list[str] | None = None,
        working_directory: str = "",
        environment: dict[str, str] | None = None,
        timeout_seconds: int = 300,
        created_at: datetime | None = None,
    ) -> CommandRequest:
        """Create a command request record without execution side effects."""
        return cls(
            command_id=command_id or uuid4().hex,
            command=command,
            arguments=list(arguments or []),
            working_directory=working_directory,
            environment=dict(environment or {}),
            timeout_seconds=timeout_seconds,
            created_at=created_at or datetime.now(timezone.utc),
        )


@dataclass
class CommandResult:
    """Command execution result metadata — no stdout/stderr capture."""

    command_id: str
    status: CommandStatus
    started_at: datetime | None = None
    completed_at: datetime | None = None
    execution_metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "command_id": self.command_id,
            "status": self.status.value,
            "execution_metadata": dict(self.execution_metadata),
        }
        if self.started_at is not None:
            payload["started_at"] = self.started_at.isoformat().replace("+00:00", "Z")
        if self.completed_at is not None:
            payload["completed_at"] = self.completed_at.isoformat().replace("+00:00", "Z")
        return payload

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CommandResult:
        started_at_raw = data.get("started_at")
        completed_at_raw = data.get("completed_at")
        return cls(
            command_id=data["command_id"],
            status=CommandStatus(data["status"]),
            started_at=(
                datetime.fromisoformat(str(started_at_raw).replace("Z", "+00:00"))
                if started_at_raw
                else None
            ),
            completed_at=(
                datetime.fromisoformat(str(completed_at_raw).replace("Z", "+00:00"))
                if completed_at_raw
                else None
            ),
            execution_metadata=dict(data.get("execution_metadata") or {}),
        )

    @classmethod
    def new(
        cls,
        command_id: str,
        *,
        status: CommandStatus = CommandStatus.CREATED,
        started_at: datetime | None = None,
        completed_at: datetime | None = None,
        execution_metadata: dict[str, Any] | None = None,
    ) -> CommandResult:
        """Create a command result record without execution side effects."""
        return cls(
            command_id=command_id,
            status=status,
            started_at=started_at,
            completed_at=completed_at,
            execution_metadata=dict(execution_metadata or {}),
        )
