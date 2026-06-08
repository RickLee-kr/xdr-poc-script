"""TransportBackedRuntime — runtime ↔ transport boundary with artifact transfer."""

from __future__ import annotations

import os
import tempfile
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path

from dsp.event_store import EventStore
from dsp.execution.providers.runtime.command import (
    CommandEncoder,
    CommandExecutionContract,
    CommandExecutionError,
    CommandExecutionPolicy,
    CommandPolicyViolationError,
    CommandRequest,
    CommandResult,
    CommandStatus,
    CommandTransportError,
)
from dsp.execution.providers.runtime.runtime_contract import ProviderRuntimeContract
from dsp.execution.providers.runtime.runtime_exceptions import (
    BundleDownloadError,
    RuntimeCapabilityError,
    SessionError,
)
from dsp.execution.providers.runtime.runtime_models import (
    RuntimeArtifact,
    RuntimeBundleReference,
    RuntimeSession,
    RuntimeSessionState,
)
from dsp.execution.providers.runtime.transport.transport_exceptions import (
    TransportCapabilityError,
    TransportConnectionError,
    TransportStateError,
)
from dsp.execution.providers.runtime.transport.transport_models import (
    TransportRuntimeConfiguration,
)
from dsp.execution.webshell.event_sync.base import EventSyncBridgeBase
from dsp.execution.webshell.event_sync.exceptions import EventSyncError
from dsp.execution.webshell.transport.base import WebshellTransport
from dsp.execution.webshell.transport.errors import (
    WebshellTransportError,
    WebshellTransportTimeoutError,
)
from dsp.execution.webshell.transport.models import TransportRequest, TransportResponse


class TransportBackedRuntime(ProviderRuntimeContract, CommandExecutionContract):
    """Transport-backed runtime — lifecycle, transfer, bundle, and command delivery.

    Allows ``transport.healthcheck()``, ``send_upload()``, ``download()``, and
    command delivery via ``send_get`` / ``send_post`` through ``execute_command``
    only. Event Store access is delegated exclusively to ``EventSyncBridge``.
    """

    def __init__(
        self,
        transport: WebshellTransport,
        *,
        event_sync_bridge: EventSyncBridgeBase | None = None,
        event_store: EventStore | None = None,
        command_encoder: CommandEncoder | None = None,
        provider_type: str = "webshell",
        webshell_url: str = "",
        config: TransportRuntimeConfiguration | None = None,
    ) -> None:
        self._transport = transport
        self._event_sync_bridge = event_sync_bridge
        self._event_store = event_store
        self._command_encoder = command_encoder or CommandEncoder()
        self._provider_type = provider_type
        self._webshell_url = webshell_url
        self._config = config or TransportRuntimeConfiguration()
        self._sessions: dict[str, RuntimeSession] = {}
        self._active_session_id: str | None = None

    @property
    def transport(self) -> WebshellTransport:
        return self._transport

    @property
    def event_sync_bridge(self) -> EventSyncBridgeBase | None:
        return self._event_sync_bridge

    @property
    def event_store(self) -> EventStore | None:
        return self._event_store

    @property
    def provider_type(self) -> str:
        return self._provider_type

    @property
    def config(self) -> TransportRuntimeConfiguration:
        return self._config

    @property
    def command_encoder(self) -> CommandEncoder:
        return self._command_encoder

    @property
    def command_policy(self) -> CommandExecutionPolicy:
        return self._config.command_policy

    @property
    def command_get_post_threshold_bytes(self) -> int:
        return self._config.command_get_post_threshold_bytes

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

    def _require_connected(
        self,
        session: RuntimeSession,
        *,
        operation: str,
    ) -> RuntimeSession:
        if session.state != RuntimeSessionState.CONNECTED:
            raise TransportStateError(
                f"invalid state for {operation}: expected "
                f"{RuntimeSessionState.CONNECTED.value!r}, "
                f"got {session.state.value!r}",
                session_id=session.session_id,
                state=session.state.value,
            )
        return session

    def _transfer_request(self) -> TransportRequest:
        return TransportRequest(url=self._webshell_url)

    def _healthcheck_request(self) -> TransportRequest:
        return self._transfer_request()

    def _set_error_state(self, session: RuntimeSession) -> None:
        error_session = session.transition(RuntimeSessionState.ERROR)
        self._update_session(error_session)

    def _dispatch_transfer(
        self,
        operation: str,
        invoke: Callable[[], TransportResponse],
    ) -> TransportResponse:
        try:
            response = invoke()
        except WebshellTransportTimeoutError as exc:
            raise TransportConnectionError(
                f"{operation} timed out: {exc}",
                provider_type=self._provider_type,
            ) from exc
        except WebshellTransportError as exc:
            raise TransportCapabilityError(
                f"{operation} failed: {exc}",
                capability=operation,
            ) from exc
        if not response.success:
            raise TransportCapabilityError(
                f"{operation} rejected by transport",
                capability=operation,
            )
        return response

    def _artifact_from_response(
        self,
        artifact: RuntimeArtifact,
        *,
        transfer_status: str,
        response: TransportResponse,
        local_path: str | None = None,
        remote_path: str | None = None,
        size_bytes: int | None = None,
    ) -> RuntimeArtifact:
        return RuntimeArtifact(
            artifact_id=artifact.artifact_id,
            local_path=local_path if local_path is not None else artifact.local_path,
            remote_path=remote_path if remote_path is not None else artifact.remote_path,
            checksum=artifact.checksum,
            size_bytes=size_bytes if size_bytes is not None else artifact.size_bytes,
            transfer_status=transfer_status,
            created_at=datetime.now(timezone.utc),
            transfer_metadata=dict(response.metadata),
        )

    def create_remote_session(self) -> RuntimeSession:
        session = RuntimeSession.new(self._provider_type)
        self._update_session(session)
        return session

    def connect(self) -> None:
        session = self._require_state(
            self._active_session(),
            RuntimeSessionState.CREATED,
            operation="connect",
        )
        connecting = session.transition(RuntimeSessionState.CONNECTING)
        self._update_session(connecting)

        if self._config.enable_healthcheck_on_connect:
            try:
                response = self._transport.healthcheck(self._healthcheck_request())
            except WebshellTransportTimeoutError as exc:
                self._set_error_state(connecting)
                raise TransportConnectionError(
                    f"transport healthcheck failed: {exc}",
                    provider_type=self._provider_type,
                ) from exc
            except WebshellTransportError as exc:
                self._set_error_state(connecting)
                raise TransportConnectionError(
                    f"transport healthcheck failed: {exc}",
                    provider_type=self._provider_type,
                ) from exc
            if not response.success:
                self._set_error_state(connecting)
                raise TransportConnectionError(
                    "transport healthcheck failed",
                    provider_type=self._provider_type,
                )

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
        stored = self._get_session(session.session_id)
        self._require_connected(stored, operation="upload_artifact")
        response = self._dispatch_transfer(
            "upload_artifact",
            lambda: self._transport.send_upload(
                self._transfer_request(),
                local_path=Path(artifact.local_path),
                remote_path=artifact.remote_path,
            ),
        )
        return self._artifact_from_response(
            artifact,
            transfer_status="uploaded",
            response=response,
        )

    def download_artifact(
        self,
        session: RuntimeSession,
        artifact: RuntimeArtifact,
    ) -> RuntimeArtifact:
        stored = self._get_session(session.session_id)
        self._require_connected(stored, operation="download_artifact")
        response = self._dispatch_transfer(
            "download_artifact",
            lambda: self._transport.download(
                self._transfer_request(),
                remote_path=artifact.remote_path,
            ),
        )
        if artifact.local_path:
            local_path = artifact.local_path
            dest = Path(local_path)
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(response.body)
        else:
            with tempfile.NamedTemporaryFile(
                mode="wb",
                suffix=".jsonl",
                delete=False,
            ) as bundle_file:
                bundle_file.write(response.body)
                local_path = bundle_file.name
        return self._artifact_from_response(
            artifact,
            transfer_status="downloaded",
            response=response,
            local_path=local_path,
            size_bytes=len(response.body),
        )

    def _require_event_sync(self) -> tuple[EventSyncBridgeBase, EventStore]:
        if self._event_sync_bridge is None or self._event_store is None:
            raise RuntimeCapabilityError(
                "Event bundle download requires event_sync_bridge and event_store",
                capability="download_event_bundle",
            )
        return self._event_sync_bridge, self._event_store

    def _bundle_from_sync(
        self,
        bundle_ref: RuntimeBundleReference,
        *,
        sync_status: str,
        event_count: int,
        sync_metadata: dict[str, object],
    ) -> RuntimeBundleReference:
        return RuntimeBundleReference(
            bundle_id=bundle_ref.bundle_id,
            remote_path=bundle_ref.remote_path,
            event_count=event_count,
            created_at=datetime.now(timezone.utc),
            sync_status=sync_status,
            sync_metadata=dict(sync_metadata),
        )

    def download_event_bundle(
        self,
        session: RuntimeSession,
        bundle_ref: RuntimeBundleReference,
    ) -> RuntimeBundleReference:
        stored = self._get_session(session.session_id)
        self._require_connected(stored, operation="download_event_bundle")
        bridge, event_store = self._require_event_sync()
        response = self._dispatch_transfer(
            "download_event_bundle",
            lambda: self._transport.download(
                self._transfer_request(),
                remote_path=bundle_ref.remote_path,
            ),
        )
        bundle_path: str | None = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="wb",
                suffix=".jsonl",
                delete=False,
            ) as bundle_file:
                bundle_file.write(response.body)
                bundle_path = bundle_file.name
            try:
                sync_result = bridge.sync_bundle(bundle_path, event_store)
            except EventSyncError as exc:
                raise BundleDownloadError(
                    f"event sync failed: {exc}",
                    bundle_id=bundle_ref.bundle_id,
                ) from exc
        finally:
            if bundle_path is not None:
                os.unlink(bundle_path)
        sync_metadata: dict[str, object] = {
            "imported_count": sync_result.imported_count,
            "skipped_count": sync_result.skipped_count,
            "bundle_metadata": sync_result.bundle_metadata.to_dict(),
            "transport_metadata": dict(response.metadata),
        }
        return self._bundle_from_sync(
            bundle_ref,
            sync_status="synced",
            event_count=sync_result.bundle_metadata.event_count,
            sync_metadata=sync_metadata,
        )

    def prepare_command(self, request: CommandRequest) -> CommandRequest:
        """Normalize a command request before validation — no transport."""
        return CommandRequest(
            command_id=request.command_id,
            command=request.command.strip(),
            arguments=list(request.arguments),
            working_directory=request.working_directory,
            environment=dict(request.environment),
            timeout_seconds=request.timeout_seconds,
            created_at=request.created_at,
        )

    def validate_command(self, request: CommandRequest) -> None:
        """Validate a prepared command request against execution policy."""
        policy = self._config.command_policy
        if not policy.allow_command_execution:
            raise CommandPolicyViolationError(
                "command execution is disabled by policy",
                command_id=request.command_id,
                policy_field="allow_command_execution",
            )
        if request.timeout_seconds > policy.max_timeout_seconds:
            raise CommandPolicyViolationError(
                f"timeout_seconds {request.timeout_seconds} exceeds policy maximum "
                f"{policy.max_timeout_seconds}",
                command_id=request.command_id,
                policy_field="max_timeout_seconds",
            )
        if not request.command:
            raise CommandExecutionError(
                "command must not be empty",
            )

    def _select_command_transport_method(self, payload_size: int) -> str:
        threshold = self._config.command_get_post_threshold_bytes
        if payload_size <= threshold:
            return "send_get"
        return "send_post"

    def _command_transport_request(
        self,
        encoded_payload: str,
        *,
        transport_method: str,
        timeout_seconds: float,
    ) -> TransportRequest:
        if transport_method == "send_get":
            return TransportRequest(
                url=self._webshell_url,
                method="GET",
                params={"command_payload": encoded_payload},
                timeout_seconds=timeout_seconds,
                metadata={"command_transport": True},
            )
        return TransportRequest(
            url=self._webshell_url,
            method="POST",
            body=encoded_payload,
            headers={"Content-Type": "application/json"},
            timeout_seconds=timeout_seconds,
            metadata={"command_transport": True},
        )

    def _dispatch_command(
        self,
        operation: str,
        command_id: str,
        invoke: Callable[[], TransportResponse],
    ) -> TransportResponse:
        try:
            response = invoke()
        except WebshellTransportTimeoutError as exc:
            raise CommandTransportError(
                f"{operation} timed out: {exc}",
                command_id=command_id,
            ) from exc
        except WebshellTransportError as exc:
            raise CommandTransportError(
                f"{operation} failed: {exc}",
                command_id=command_id,
            ) from exc
        if not response.success:
            raise CommandTransportError(
                f"{operation} rejected by transport",
                command_id=command_id,
            )
        return response

    def execute_command(self, request: CommandRequest) -> CommandResult:
        """Deliver a command via transport — COMPLETED means delivery only."""
        session = self._active_session()
        self._require_connected(session, operation="execute_command")
        prepared = self.prepare_command(request)
        self.validate_command(prepared)
        started_at = datetime.now(timezone.utc)
        try:
            encoded_payload = self._command_encoder.encode_request(prepared)
        except (TypeError, ValueError) as exc:
            raise CommandExecutionError(
                f"command encoding failed: {exc}",
            ) from exc
        payload_size = len(encoded_payload.encode("utf-8"))
        transport_method = self._select_command_transport_method(payload_size)
        transport_request = self._command_transport_request(
            encoded_payload,
            transport_method=transport_method,
            timeout_seconds=float(prepared.timeout_seconds),
        )
        if transport_method == "send_get":
            response = self._dispatch_command(
                "execute_command",
                prepared.command_id,
                lambda: self._transport.send_get(transport_request),
            )
        else:
            response = self._dispatch_command(
                "execute_command",
                prepared.command_id,
                lambda: self._transport.send_post(transport_request),
            )
        completed_at = datetime.now(timezone.utc)
        return CommandResult(
            command_id=prepared.command_id,
            status=CommandStatus.COMPLETED,
            started_at=started_at,
            completed_at=completed_at,
            execution_metadata={
                "transport_method": transport_method,
                "request_size": payload_size,
                "transport_status": response.status_code,
                "delivery_only": True,
            },
        )

    def cancel_command(self, command_id: str) -> CommandResult:
        """Return a cancelled result — no transport or remote cancellation."""
        cancelled_at = datetime.now(timezone.utc)
        return CommandResult(
            command_id=command_id,
            status=CommandStatus.CANCELLED,
            started_at=cancelled_at,
            completed_at=cancelled_at,
            execution_metadata={"cancelled_locally": True},
        )

    def healthcheck(self) -> bool:
        response = self._transport.healthcheck(self._healthcheck_request())
        return response.success

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
