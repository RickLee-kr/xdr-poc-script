"""Command execution policy model — future runtime enforcement only."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class CommandExecutionPolicy:
    """Policy constraints for future command execution enforcement.

    Defaults deny all privileged operations. No enforcement behavior in
    Phase X+7 — metadata and serialization only.
    """

    allow_command_execution: bool = False
    allow_file_modification: bool = False
    allow_network_access: bool = False
    allow_privilege_escalation: bool = False
    max_timeout_seconds: int = 600

    def to_dict(self) -> dict[str, Any]:
        return {
            "allow_command_execution": self.allow_command_execution,
            "allow_file_modification": self.allow_file_modification,
            "allow_network_access": self.allow_network_access,
            "allow_privilege_escalation": self.allow_privilege_escalation,
            "max_timeout_seconds": self.max_timeout_seconds,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CommandExecutionPolicy:
        return cls(
            allow_command_execution=bool(
                data.get("allow_command_execution", False)
            ),
            allow_file_modification=bool(
                data.get("allow_file_modification", False)
            ),
            allow_network_access=bool(data.get("allow_network_access", False)),
            allow_privilege_escalation=bool(
                data.get("allow_privilege_escalation", False)
            ),
            max_timeout_seconds=int(data.get("max_timeout_seconds", 600)),
        )
