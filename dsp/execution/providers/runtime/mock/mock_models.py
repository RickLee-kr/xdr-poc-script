"""Mock provider runtime configuration."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class MockRuntimeConfiguration:
    """Deterministic failure simulation flags for mock runtime testing."""

    simulate_connection_failure: bool = False
    simulate_upload_failure: bool = False
    simulate_download_failure: bool = False
    simulate_bundle_failure: bool = False

    def to_dict(self) -> dict[str, bool]:
        return {
            "simulate_connection_failure": self.simulate_connection_failure,
            "simulate_upload_failure": self.simulate_upload_failure,
            "simulate_download_failure": self.simulate_download_failure,
            "simulate_bundle_failure": self.simulate_bundle_failure,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> MockRuntimeConfiguration:
        return cls(
            simulate_connection_failure=bool(
                data.get("simulate_connection_failure", False)
            ),
            simulate_upload_failure=bool(data.get("simulate_upload_failure", False)),
            simulate_download_failure=bool(
                data.get("simulate_download_failure", False)
            ),
            simulate_bundle_failure=bool(data.get("simulate_bundle_failure", False)),
        )
