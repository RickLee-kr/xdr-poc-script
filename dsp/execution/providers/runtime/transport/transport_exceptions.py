"""Transport-backed runtime exception types."""

from dsp.execution.providers.runtime.runtime_exceptions import ProviderRuntimeError


class TransportRuntimeError(ProviderRuntimeError):
    """Base exception for transport-backed runtime errors."""


class TransportConnectionError(TransportRuntimeError):
    """Transport connection or healthcheck failure."""

    def __init__(
        self,
        message: str,
        *,
        provider_type: str | None = None,
    ) -> None:
        self.provider_type = provider_type
        super().__init__(message)


class TransportCapabilityError(TransportRuntimeError):
    """Transport-backed runtime capability not available."""

    def __init__(
        self,
        message: str,
        *,
        capability: str | None = None,
    ) -> None:
        self.capability = capability
        super().__init__(message)


class TransportStateError(TransportRuntimeError):
    """Invalid transport-backed runtime session state."""

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
