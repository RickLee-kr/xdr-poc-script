"""Mock provider runtime exception types."""

from dsp.execution.providers.runtime.runtime_exceptions import ProviderRuntimeError


class MockRuntimeError(ProviderRuntimeError):
    """Base exception for mock provider runtime errors."""


class MockConnectionError(MockRuntimeError):
    """Simulated connection failure."""


class MockUploadError(MockRuntimeError):
    """Simulated upload failure."""


class MockDownloadError(MockRuntimeError):
    """Simulated download failure."""


class MockBundleError(MockRuntimeError):
    """Simulated event bundle failure."""
