"""Command execution exception hierarchy — contract only, no execution."""


class CommandExecutionError(Exception):
    """Base exception for command execution errors."""


class CommandValidationError(CommandExecutionError):
    """Command request failed validation."""

    def __init__(
        self,
        message: str,
        *,
        command_id: str | None = None,
        field: str | None = None,
    ) -> None:
        self.command_id = command_id
        self.field = field
        super().__init__(message)


class CommandTimeoutError(CommandExecutionError):
    """Command exceeded its timeout."""

    def __init__(
        self,
        message: str,
        *,
        command_id: str | None = None,
        timeout_seconds: int | None = None,
    ) -> None:
        self.command_id = command_id
        self.timeout_seconds = timeout_seconds
        super().__init__(message)


class CommandCancelledError(CommandExecutionError):
    """Command was cancelled before completion."""

    def __init__(
        self,
        message: str,
        *,
        command_id: str | None = None,
    ) -> None:
        self.command_id = command_id
        super().__init__(message)


class CommandPolicyViolationError(CommandExecutionError):
    """Command violated execution policy constraints."""

    def __init__(
        self,
        message: str,
        *,
        command_id: str | None = None,
        policy_field: str | None = None,
    ) -> None:
        self.command_id = command_id
        self.policy_field = policy_field
        super().__init__(message)


class CommandTransportError(CommandExecutionError):
    """Transport layer error during command execution."""

    def __init__(
        self,
        message: str,
        *,
        command_id: str | None = None,
    ) -> None:
        self.command_id = command_id
        super().__init__(message)
