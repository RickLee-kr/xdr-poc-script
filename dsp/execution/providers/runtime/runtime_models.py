"""Provider runtime contract data models."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any
from uuid import uuid4


class RuntimeSessionState(StrEnum):
    """Lifecycle states for a provider runtime session."""

    CREATED = "created"
    CONNECTING = "connecting"
    CONNECTED = "connected"
    DISCONNECTED = "disconnected"
    ERROR = "error"
    CLOSED = "closed"


@dataclass
class RuntimeSession:
    """Provider runtime session metadata — no transport or network binding."""

    session_id: str
    provider_type: str
    created_at: datetime
    state: RuntimeSessionState = RuntimeSessionState.CREATED
    remote_identifier: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "session_id": self.session_id,
            "provider_type": self.provider_type,
            "created_at": self.created_at.isoformat().replace("+00:00", "Z"),
            "state": self.state.value,
            "remote_identifier": self.remote_identifier,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> RuntimeSession:
        return cls(
            session_id=data["session_id"],
            provider_type=data["provider_type"],
            created_at=datetime.fromisoformat(
                data["created_at"].replace("Z", "+00:00")
            ),
            state=RuntimeSessionState(data["state"]),
            remote_identifier=str(data.get("remote_identifier", "")),
        )

    @classmethod
    def new(
        cls,
        provider_type: str,
        *,
        session_id: str | None = None,
        state: RuntimeSessionState = RuntimeSessionState.CREATED,
        remote_identifier: str = "",
    ) -> RuntimeSession:
        """Create a runtime session record without side effects."""
        return cls(
            session_id=session_id or uuid4().hex,
            provider_type=provider_type,
            created_at=datetime.now(timezone.utc),
            state=state,
            remote_identifier=remote_identifier,
        )

    def transition(self, new_state: RuntimeSessionState) -> RuntimeSession:
        """Return a copy with an updated lifecycle state."""
        return RuntimeSession(
            session_id=self.session_id,
            provider_type=self.provider_type,
            created_at=self.created_at,
            state=new_state,
            remote_identifier=self.remote_identifier,
        )


@dataclass
class RuntimeArtifact:
    """Artifact metadata for provider runtime upload/download operations."""

    artifact_id: str
    local_path: str = ""
    remote_path: str = ""
    checksum: str = ""
    size_bytes: int = 0
    transfer_status: str = ""
    created_at: datetime | None = None
    transfer_metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "artifact_id": self.artifact_id,
            "local_path": self.local_path,
            "remote_path": self.remote_path,
            "checksum": self.checksum,
            "size_bytes": self.size_bytes,
            "transfer_status": self.transfer_status,
            "transfer_metadata": dict(self.transfer_metadata),
        }
        if self.created_at is not None:
            payload["created_at"] = self.created_at.isoformat().replace("+00:00", "Z")
        return payload

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> RuntimeArtifact:
        created_at_raw = data.get("created_at")
        created_at = (
            datetime.fromisoformat(str(created_at_raw).replace("Z", "+00:00"))
            if created_at_raw
            else None
        )
        return cls(
            artifact_id=data["artifact_id"],
            local_path=str(data.get("local_path", "")),
            remote_path=str(data.get("remote_path", "")),
            checksum=str(data.get("checksum", "")),
            size_bytes=int(data.get("size_bytes", 0)),
            transfer_status=str(data.get("transfer_status", "")),
            created_at=created_at,
            transfer_metadata=dict(data.get("transfer_metadata") or {}),
        )

    @classmethod
    def new(
        cls,
        *,
        artifact_id: str | None = None,
        local_path: str = "",
        remote_path: str = "",
        checksum: str = "",
        size_bytes: int = 0,
        transfer_status: str = "",
        created_at: datetime | None = None,
        transfer_metadata: dict[str, Any] | None = None,
    ) -> RuntimeArtifact:
        """Create an artifact record without filesystem side effects."""
        return cls(
            artifact_id=artifact_id or uuid4().hex,
            local_path=local_path,
            remote_path=remote_path,
            checksum=checksum,
            size_bytes=size_bytes,
            transfer_status=transfer_status,
            created_at=created_at,
            transfer_metadata=dict(transfer_metadata or {}),
        )


@dataclass
class RuntimeBundleReference:
    """Reference to a remote event bundle — metadata only."""

    bundle_id: str
    remote_path: str = ""
    event_count: int = 0
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    sync_status: str = ""
    sync_metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "bundle_id": self.bundle_id,
            "remote_path": self.remote_path,
            "event_count": self.event_count,
            "created_at": self.created_at.isoformat().replace("+00:00", "Z"),
            "sync_status": self.sync_status,
            "sync_metadata": dict(self.sync_metadata),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> RuntimeBundleReference:
        return cls(
            bundle_id=data["bundle_id"],
            remote_path=str(data.get("remote_path", "")),
            event_count=int(data.get("event_count", 0)),
            created_at=datetime.fromisoformat(
                data["created_at"].replace("Z", "+00:00")
            ),
            sync_status=str(data.get("sync_status", "")),
            sync_metadata=dict(data.get("sync_metadata") or {}),
        )

    @classmethod
    def new(
        cls,
        *,
        bundle_id: str | None = None,
        remote_path: str = "",
        event_count: int = 0,
        created_at: datetime | None = None,
        sync_status: str = "",
        sync_metadata: dict[str, Any] | None = None,
    ) -> RuntimeBundleReference:
        """Create a bundle reference record without download side effects."""
        return cls(
            bundle_id=bundle_id or uuid4().hex,
            remote_path=remote_path,
            event_count=event_count,
            created_at=created_at or datetime.now(timezone.utc),
            sync_status=sync_status,
            sync_metadata=dict(sync_metadata or {}),
        )
