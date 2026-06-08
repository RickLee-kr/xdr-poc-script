"""Command encoder — generic JSON serialization only."""

from __future__ import annotations

import json
from typing import Any

from dsp.execution.providers.runtime.command.command_models import CommandRequest, CommandResult


class CommandEncoder:
    """Serialize and deserialize command models.

    Phase X+7 supports JSON only. JSP/PHP/ASPX encodings are reserved for
    future phases.
    """

    SUPPORTED_ENCODINGS: tuple[str, ...] = ("json",)

    def encode_request(
        self,
        request: CommandRequest,
        *,
        encoding: str = "json",
    ) -> str:
        """Serialize a command request to the requested encoding."""
        self._require_encoding(encoding)
        return json.dumps(request.to_dict(), sort_keys=True)

    def decode_request(
        self,
        payload: str,
        *,
        encoding: str = "json",
    ) -> CommandRequest:
        """Deserialize a command request from the requested encoding."""
        self._require_encoding(encoding)
        data = self._load_json(payload)
        return CommandRequest.from_dict(data)

    def encode_result(
        self,
        result: CommandResult,
        *,
        encoding: str = "json",
    ) -> str:
        """Serialize a command result to the requested encoding."""
        self._require_encoding(encoding)
        return json.dumps(result.to_dict(), sort_keys=True)

    def decode_result(
        self,
        payload: str,
        *,
        encoding: str = "json",
    ) -> CommandResult:
        """Deserialize a command result from the requested encoding."""
        self._require_encoding(encoding)
        data = self._load_json(payload)
        return CommandResult.from_dict(data)

    def _require_encoding(self, encoding: str) -> None:
        if encoding not in self.SUPPORTED_ENCODINGS:
            supported = ", ".join(self.SUPPORTED_ENCODINGS)
            raise ValueError(
                f"unsupported encoding {encoding!r}; supported: {supported}"
            )

    def _load_json(self, payload: str) -> dict[str, Any]:
        data = json.loads(payload)
        if not isinstance(data, dict):
            raise ValueError("payload must decode to a JSON object")
        return data
