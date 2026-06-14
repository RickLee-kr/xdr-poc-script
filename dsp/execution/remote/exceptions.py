"""Remote scenario execution exceptions."""

from __future__ import annotations


class RemoteScenarioRunnerError(Exception):
    """Base exception for remote scenario runner errors."""


class UnsupportedRemoteProviderError(RemoteScenarioRunnerError, TypeError):
    """Raised when a provider does not support remote scenario execution."""

    def __init__(self, provider_type: str) -> None:
        self.provider_type = provider_type
        super().__init__(
            f"unsupported remote scenario provider: {provider_type!r}; "
            "expected WebshellExecutionProvider"
        )


class RemoteEventCollectionError(Exception):
    """Base exception for remote event collection errors."""

    def __init__(
        self,
        message: str,
        *,
        diagnostics_dir: str | None = None,
        remote_validation: object | None = None,
        cat_validation: object | None = None,
    ) -> None:
        self.diagnostics_dir = diagnostics_dir
        self.remote_validation = remote_validation
        self.cat_validation = cat_validation
        super().__init__(message)


class RemoteArtifactUploadError(RemoteScenarioRunnerError):
    """Raised when a remote artifact upload cannot be verified on the webshell host."""

    def __init__(
        self,
        message: str,
        *,
        remote_path: str | None = None,
        verification: object | None = None,
        multipart_verification: object | None = None,
    ) -> None:
        self.remote_path = remote_path
        self.verification = verification
        self.multipart_verification = multipart_verification
        super().__init__(message)


class RemoteBundleExecutionError(RemoteScenarioRunnerError):
    """Raised when a remote bundle runner script fails or leaves no events.jsonl."""

    def __init__(
        self,
        message: str,
        *,
        remote_path: str | None = None,
        execution_output: str | None = None,
        verification: object | None = None,
    ) -> None:
        self.remote_path = remote_path
        self.execution_output = execution_output
        self.verification = verification
        super().__init__(message)
