"""Transport-backed runtime configuration."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from dsp.execution.providers.runtime.command import CommandExecutionPolicy

# Payloads at or below this size use send_get(); larger payloads use send_post().
DEFAULT_COMMAND_GET_POST_THRESHOLD_BYTES = 2048


@dataclass
class TransportRuntimeConfiguration:
    """Configuration for transport-backed runtime skeleton behavior."""

    enable_healthcheck_on_connect: bool = True
    command_get_post_threshold_bytes: int = DEFAULT_COMMAND_GET_POST_THRESHOLD_BYTES
    command_policy: CommandExecutionPolicy = field(
        default_factory=CommandExecutionPolicy
    )

    def to_dict(self) -> dict[str, Any]:
        return {
            "enable_healthcheck_on_connect": self.enable_healthcheck_on_connect,
            "command_get_post_threshold_bytes": self.command_get_post_threshold_bytes,
            "command_policy": self.command_policy.to_dict(),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> TransportRuntimeConfiguration:
        policy_data = data.get("command_policy")
        command_policy = (
            CommandExecutionPolicy.from_dict(policy_data)
            if isinstance(policy_data, dict)
            else CommandExecutionPolicy()
        )
        return cls(
            enable_healthcheck_on_connect=bool(
                data.get("enable_healthcheck_on_connect", True)
            ),
            command_get_post_threshold_bytes=int(
                data.get(
                    "command_get_post_threshold_bytes",
                    DEFAULT_COMMAND_GET_POST_THRESHOLD_BYTES,
                )
            ),
            command_policy=command_policy,
        )
