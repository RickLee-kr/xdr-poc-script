"""Provider runtime contract exception hierarchy."""

from __future__ import annotations


class ProviderRuntimeError(Exception):
    """Base exception for provider runtime contract errors."""


class ConnectionError(ProviderRuntimeError):
    """Provider connection lifecycle error."""

    def __init__(
        self,
        message: str,
        *,
        provider_type: str | None = None,
    ) -> None:
        self.provider_type = provider_type
        super().__init__(message)


class SessionError(ProviderRuntimeError):
    """Provider remote session lifecycle error."""

    def __init__(
        self,
        message: str,
        *,
        session_id: str | None = None,
        state: str | None = None,
    ) -> None:
        self.session_id = session_id
        self.state = state
        super().__init__(message)


class ArtifactTransferError(ProviderRuntimeError):
    """Artifact upload or download error."""

    def __init__(
        self,
        message: str,
        *,
        artifact_id: str | None = None,
        direction: str | None = None,
    ) -> None:
        self.artifact_id = artifact_id
        self.direction = direction
        super().__init__(message)


class BundleDownloadError(ProviderRuntimeError):
    """Event bundle download error."""

    def __init__(
        self,
        message: str,
        *,
        bundle_id: str | None = None,
    ) -> None:
        self.bundle_id = bundle_id
        super().__init__(message)


class RuntimeCapabilityError(ProviderRuntimeError):
    """Requested runtime capability is not supported."""

    def __init__(
        self,
        message: str,
        *,
        capability: str | None = None,
    ) -> None:
        self.capability = capability
        super().__init__(message)


class HealthcheckError(ProviderRuntimeError):
    """Provider healthcheck error."""

    def __init__(
        self,
        message: str,
        *,
        provider_type: str | None = None,
    ) -> None:
        self.provider_type = provider_type
        super().__init__(message)


class CleanupError(ProviderRuntimeError):
    """Provider cleanup error."""

    def __init__(
        self,
        message: str,
        *,
        session_id: str | None = None,
    ) -> None:
        self.session_id = session_id
        super().__init__(message)
