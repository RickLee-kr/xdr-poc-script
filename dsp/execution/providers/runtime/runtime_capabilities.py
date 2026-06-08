"""Provider runtime capability model."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class RuntimeCapabilities:
    """Runtime lifecycle capability matrix — defaults indicate no implementation."""

    supports_connect: bool = False
    supports_upload: bool = False
    supports_download: bool = False
    supports_event_bundle: bool = False
    supports_healthcheck: bool = False
    supports_cleanup: bool = False

    def to_dict(self) -> dict[str, bool]:
        return {
            "supports_connect": self.supports_connect,
            "supports_upload": self.supports_upload,
            "supports_download": self.supports_download,
            "supports_event_bundle": self.supports_event_bundle,
            "supports_healthcheck": self.supports_healthcheck,
            "supports_cleanup": self.supports_cleanup,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> RuntimeCapabilities:
        return cls(
            supports_connect=bool(data.get("supports_connect", False)),
            supports_upload=bool(data.get("supports_upload", False)),
            supports_download=bool(data.get("supports_download", False)),
            supports_event_bundle=bool(data.get("supports_event_bundle", False)),
            supports_healthcheck=bool(data.get("supports_healthcheck", False)),
            supports_cleanup=bool(data.get("supports_cleanup", False)),
        )
