"""MockProviderRuntime — lifecycle simulation (no execution, no network)."""

from __future__ import annotations

from dsp.execution.providers.runtime.mock.mock_exceptions import (
    MockBundleError,
    MockConnectionError,
    MockDownloadError,
    MockUploadError,
)
from dsp.execution.providers.runtime.mock.mock_models import MockRuntimeConfiguration
from dsp.execution.providers.runtime.runtime_contract import ProviderRuntimeContract
from dsp.execution.providers.runtime.runtime_exceptions import SessionError
from dsp.execution.providers.runtime.runtime_models import (
    RuntimeArtifact,
    RuntimeBundleReference,
    RuntimeSession,
    RuntimeSessionState,
)


class MockProviderRuntime(ProviderRuntimeContract):
    """Simulates provider runtime lifecycle without transport or network I/O.

    State transitions are deterministic. Artifact and bundle operations return
    metadata only. No filesystem, EventSyncBridge, or Event Store access.
    """

    def __init__(
        self,
        provider_type: str = "mock",
        *,
        config: MockRuntimeConfiguration | None = None,
    ) -> None:
        self._provider_type = provider_type
        self._config = config or MockRuntimeConfiguration()
        self._sessions: dict[str, RuntimeSession] = {}
        self._active_session_id: str | None = None

    @property
    def provider_type(self) -> str:
        return self._provider_type

    @property
    def config(self) -> MockRuntimeConfiguration:
        return self._config

    def _get_session(self, session_id: str) -> RuntimeSession:
        session = self._sessions.get(session_id)
        if session is None:
            raise SessionError(
                f"session not found: {session_id!r}",
                session_id=session_id,
            )
        return session

    def _active_session(self) -> RuntimeSession:
        if self._active_session_id is None:
            raise SessionError("no active runtime session")
        return self._get_session(self._active_session_id)

    def _update_session(self, session: RuntimeSession) -> None:
        self._sessions[session.session_id] = session
        self._active_session_id = session.session_id

    def _require_state(
        self,
        session: RuntimeSession,
        expected: RuntimeSessionState,
        *,
        operation: str,
    ) -> RuntimeSession:
        if session.state != expected:
            raise SessionError(
                f"invalid state for {operation}: expected {expected.value!r}, "
                f"got {session.state.value!r}",
                session_id=session.session_id,
                state=session.state.value,
            )
        return session

    def create_remote_session(self) -> RuntimeSession:
        session = RuntimeSession.new(self._provider_type)
        self._update_session(session)
        return session

    def connect(self) -> None:
        if self._config.simulate_connection_failure:
            raise MockConnectionError("simulated connection failure")

        session = self._require_state(
            self._active_session(),
            RuntimeSessionState.CREATED,
            operation="connect",
        )
        connecting = session.transition(RuntimeSessionState.CONNECTING)
        connected = connecting.transition(RuntimeSessionState.CONNECTED)
        self._update_session(connected)

    def disconnect(self) -> None:
        session = self._require_state(
            self._active_session(),
            RuntimeSessionState.CONNECTED,
            operation="disconnect",
        )
        disconnected = session.transition(RuntimeSessionState.DISCONNECTED)
        self._update_session(disconnected)

    def close_remote_session(self, session: RuntimeSession) -> None:
        stored = self._get_session(session.session_id)
        closed_source = self._require_state(
            stored,
            RuntimeSessionState.DISCONNECTED,
            operation="close_remote_session",
        )
        closed = closed_source.transition(RuntimeSessionState.CLOSED)
        self._sessions[closed.session_id] = closed
        if self._active_session_id == closed.session_id:
            self._active_session_id = None

    def upload_artifact(
        self,
        session: RuntimeSession,
        artifact: RuntimeArtifact,
    ) -> RuntimeArtifact:
        if self._config.simulate_upload_failure:
            raise MockUploadError(
                "simulated upload failure",
            )

        stored = self._get_session(session.session_id)
        self._require_state(
            stored,
            RuntimeSessionState.CONNECTED,
            operation="upload_artifact",
        )
        return RuntimeArtifact(
            artifact_id=artifact.artifact_id,
            local_path=artifact.local_path,
            remote_path=artifact.remote_path or f"/remote/{artifact.artifact_id}",
            checksum=artifact.checksum,
            size_bytes=artifact.size_bytes,
        )

    def download_artifact(
        self,
        session: RuntimeSession,
        artifact: RuntimeArtifact,
    ) -> RuntimeArtifact:
        if self._config.simulate_download_failure:
            raise MockDownloadError(
                "simulated download failure",
            )

        stored = self._get_session(session.session_id)
        self._require_state(
            stored,
            RuntimeSessionState.CONNECTED,
            operation="download_artifact",
        )
        return RuntimeArtifact(
            artifact_id=artifact.artifact_id,
            local_path=artifact.local_path or f"/local/{artifact.artifact_id}",
            remote_path=artifact.remote_path,
            checksum=artifact.checksum,
            size_bytes=artifact.size_bytes,
        )

    def download_event_bundle(
        self,
        session: RuntimeSession,
        bundle_ref: RuntimeBundleReference,
    ) -> RuntimeBundleReference:
        if self._config.simulate_bundle_failure:
            raise MockBundleError(
                "simulated bundle failure",
            )

        stored = self._get_session(session.session_id)
        self._require_state(
            stored,
            RuntimeSessionState.CONNECTED,
            operation="download_event_bundle",
        )
        return RuntimeBundleReference(
            bundle_id=bundle_ref.bundle_id,
            remote_path=bundle_ref.remote_path,
            event_count=bundle_ref.event_count,
            created_at=bundle_ref.created_at,
        )

    def healthcheck(self) -> bool:
        return True

    def cleanup(self) -> None:
        self._sessions.clear()
        self._active_session_id = None

    def get_session(self, session_id: str) -> RuntimeSession:
        """Return tracked session state (for tests)."""
        return self._get_session(session_id)

    @property
    def active_session(self) -> RuntimeSession:
        """Return the current active runtime session."""
        return self._active_session()
