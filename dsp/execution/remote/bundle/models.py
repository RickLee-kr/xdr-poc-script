"""Webshell bundle mode models — remote host assumptions and skip reasons."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

BUNDLE_SCENARIOS = frozenset(
    {
        "port_sweep",
        "dns_tunnel",
        "http_followup",
        "sql_injection",
        "ssh_failure",
        "host_behavior_check",
        "rare_protocol_activity",
    }
)

# Deprecated: bundle mode uploads manifest/run_scenario.py — not used on webshell live path.
REMOTE_EXECUTION_MODE_BUNDLE = "bundle"
REMOTE_EXECUTION_MODE_CLI = "cli"


@dataclass(frozen=True)
class ScenarioRemoteRequirements:
    """Commands that must exist on the webshell host for a scenario."""

    scenario_id: str
    required_commands: tuple[str, ...] = ()
    any_of_commands: tuple[str, ...] = ()

    def missing_from(self, available: set[str]) -> list[str]:
        missing = [cmd for cmd in self.required_commands if cmd not in available]
        if self.any_of_commands and not any(cmd in available for cmd in self.any_of_commands):
            missing.append("|".join(self.any_of_commands))
        return missing


SCENARIO_REMOTE_REQUIREMENTS: dict[str, ScenarioRemoteRequirements] = {
    "port_sweep": ScenarioRemoteRequirements("port_sweep", required_commands=("python3",)),
    "dns_tunnel": ScenarioRemoteRequirements("dns_tunnel", required_commands=("python3",)),
    "http_followup": ScenarioRemoteRequirements(
        "http_followup",
        required_commands=("python3", "curl"),
    ),
    "sql_injection": ScenarioRemoteRequirements(
        "sql_injection",
        required_commands=("python3", "curl"),
    ),
    "ssh_failure": ScenarioRemoteRequirements(
        "ssh_failure",
        required_commands=("python3",),
        any_of_commands=("ssh", "nc"),
    ),
    "host_behavior_check": ScenarioRemoteRequirements(
        "host_behavior_check",
        required_commands=("python3",),
        any_of_commands=("sh", "bash"),
    ),
    "rare_protocol_activity": ScenarioRemoteRequirements(
        "rare_protocol_activity",
        required_commands=("python3",),
    ),
}


@dataclass
class RemoteScenarioSkip:
    scenario_id: str
    reason: str
    missing_commands: list[str] = field(default_factory=list)

    def to_manifest(self) -> dict[str, Any]:
        return {
            "skipped": True,
            "skip_reason": self.reason,
            "missing_commands": list(self.missing_commands),
        }
