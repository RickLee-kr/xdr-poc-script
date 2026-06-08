"""Command execution contract — abstract API, no implementation."""

from __future__ import annotations

from abc import ABC, abstractmethod

from dsp.execution.providers.runtime.command.command_models import CommandRequest, CommandResult


class CommandExecutionContract(ABC):
    """Abstract command execution lifecycle contract.

    Defines prepare / validate / execute / cancel surface. No transport,
    webshell, or network logic in this module — contract only.
    """

    @abstractmethod
    def prepare_command(self, request: CommandRequest) -> CommandRequest:
        """Normalize and enrich a command request before validation."""

    @abstractmethod
    def validate_command(self, request: CommandRequest) -> None:
        """Validate a prepared command request against policy constraints."""

    @abstractmethod
    def execute_command(self, request: CommandRequest) -> CommandResult:
        """Execute a validated command and return result metadata."""

    @abstractmethod
    def cancel_command(self, command_id: str) -> CommandResult:
        """Cancel an in-flight command by identifier."""
