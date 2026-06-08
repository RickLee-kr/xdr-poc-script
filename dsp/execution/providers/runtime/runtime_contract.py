"""ProviderRuntimeContract — abstract runtime lifecycle API (no implementation)."""

from __future__ import annotations

from abc import ABC, abstractmethod

from dsp.execution.providers.runtime.runtime_models import (
    RuntimeArtifact,
    RuntimeBundleReference,
    RuntimeSession,
)


class ProviderRuntimeContract(ABC):
    """Abstract provider runtime lifecycle contract.

    Defines the API surface for connect/disconnect, remote session management,
    artifact transfer, event bundle download, healthcheck, and cleanup.

    Must NOT perform transport calls, network I/O, or EventSyncBridge invocation
    in this contract-definition phase. Implementations belong to future phases.
    """

    @abstractmethod
    def connect(self) -> None:
        """Establish provider runtime connection."""

    @abstractmethod
    def disconnect(self) -> None:
        """Tear down provider runtime connection."""

    @abstractmethod
    def create_remote_session(self) -> RuntimeSession:
        """Create a remote runtime session."""

    @abstractmethod
    def close_remote_session(self, session: RuntimeSession) -> None:
        """Close an active remote runtime session."""

    @abstractmethod
    def upload_artifact(
        self,
        session: RuntimeSession,
        artifact: RuntimeArtifact,
    ) -> RuntimeArtifact:
        """Upload an artifact to the remote target."""

    @abstractmethod
    def download_artifact(
        self,
        session: RuntimeSession,
        artifact: RuntimeArtifact,
    ) -> RuntimeArtifact:
        """Download an artifact from the remote target."""

    @abstractmethod
    def download_event_bundle(
        self,
        session: RuntimeSession,
        bundle_ref: RuntimeBundleReference,
    ) -> RuntimeBundleReference:
        """Download an event bundle reference from the remote target."""

    @abstractmethod
    def healthcheck(self) -> bool:
        """Verify provider runtime reachability."""

    @abstractmethod
    def cleanup(self) -> None:
        """Release all provider runtime resources."""
