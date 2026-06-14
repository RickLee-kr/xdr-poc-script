"""Verified remote bundle uploads with command-based base64 fallback."""

from __future__ import annotations

import base64
import hashlib
import re
import shlex
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from dsp.execution.remote.exceptions import RemoteArtifactUploadError

if TYPE_CHECKING:
    from dsp.execution.webshell_provider import WebshellExecutionProvider

_BASE64_CHUNK_CHARS = 4000
_MISSING_FILE_MARKERS = (
    "no such file",
    "cannot access",
    "cannot open",
    "not found",
)
_WC_BYTES_RE = re.compile(rb"(\d+)")


@dataclass(frozen=True)
class RemoteFileVerification:
    """Outcome of verifying a remote file after upload."""

    ok: bool
    remote_path: str
    expected_size: int
    actual_size: int | None
    expected_sha256: str
    actual_sha256: str | None
    ls_output: str
    wc_output: str
    sha256_output: str | None
    reason: str | None = None

    def format_report(self, *, method: str) -> str:
        lines = [
            f"method: {method}",
            f"remote_path: {self.remote_path}",
            f"expected_size: {self.expected_size}",
            f"actual_size: {self.actual_size}",
            f"expected_sha256: {self.expected_sha256}",
            f"actual_sha256: {self.actual_sha256}",
            f"ok: {self.ok}",
        ]
        if self.reason:
            lines.append(f"reason: {self.reason}")
        lines.extend(
            [
                "",
                "ls -l:",
                self.ls_output,
                "",
                "wc -c:",
                self.wc_output,
            ]
        )
        if self.sha256_output is not None:
            lines.extend(["", "sha256sum:", self.sha256_output])
        return "\n".join(lines)


@dataclass(frozen=True)
class VerifiedUploadResult:
    """Verified upload outcome including transport method used."""

    verification: RemoteFileVerification
    method: str


def upload_remote_file_verified(
    provider: WebshellExecutionProvider,
    local_path: Path | str,
    remote_path: str,
) -> VerifiedUploadResult:
    """Upload a local file and verify it exists remotely with expected size/hash."""
    path = Path(local_path)
    payload = path.read_bytes()
    expected_size = len(payload)
    expected_sha256 = hashlib.sha256(payload).hexdigest()

    provider.upload_file(path, remote_path)
    verification = verify_remote_file(
        provider,
        remote_path,
        expected_size=expected_size,
        expected_sha256=expected_sha256,
    )
    if verification.ok:
        return VerifiedUploadResult(verification=verification, method="multipart")

    for command in base64_upload_commands(path, remote_path):
        provider.run_remote_command(command)

    fallback = verify_remote_file(
        provider,
        remote_path,
        expected_size=expected_size,
        expected_sha256=expected_sha256,
    )
    if fallback.ok:
        return VerifiedUploadResult(verification=fallback, method="base64")

    raise RemoteArtifactUploadError(
        f"remote upload verification failed for {remote_path}: "
        f"{fallback.reason or 'unknown error'}",
        remote_path=remote_path,
        verification=fallback,
        multipart_verification=verification,
    )


def verify_remote_file(
    provider: WebshellExecutionProvider,
    remote_path: str,
    *,
    expected_size: int,
    expected_sha256: str,
) -> RemoteFileVerification:
    """Verify a remote file using ``ls``, ``wc -c``, and optional ``sha256sum``."""
    ls_output = _decode_output(
        provider.run_remote_command(f"ls -l {shlex.quote(remote_path)} 2>&1")
    )
    if _looks_missing(ls_output):
        return RemoteFileVerification(
            ok=False,
            remote_path=remote_path,
            expected_size=expected_size,
            actual_size=None,
            expected_sha256=expected_sha256,
            actual_sha256=None,
            ls_output=ls_output,
            wc_output="",
            sha256_output=None,
            reason="file not found",
        )

    wc_output = _decode_output(
        provider.run_remote_command(f"wc -c < {shlex.quote(remote_path)} 2>&1")
    )
    actual_size = _parse_byte_count(wc_output)
    if actual_size is None:
        return RemoteFileVerification(
            ok=False,
            remote_path=remote_path,
            expected_size=expected_size,
            actual_size=None,
            expected_sha256=expected_sha256,
            actual_sha256=None,
            ls_output=ls_output,
            wc_output=wc_output,
            sha256_output=None,
            reason="could not parse remote byte count",
        )
    if actual_size <= 0:
        return RemoteFileVerification(
            ok=False,
            remote_path=remote_path,
            expected_size=expected_size,
            actual_size=actual_size,
            expected_sha256=expected_sha256,
            actual_sha256=None,
            ls_output=ls_output,
            wc_output=wc_output,
            sha256_output=None,
            reason="remote file is empty",
        )
    if actual_size != expected_size:
        return RemoteFileVerification(
            ok=False,
            remote_path=remote_path,
            expected_size=expected_size,
            actual_size=actual_size,
            expected_sha256=expected_sha256,
            actual_sha256=None,
            ls_output=ls_output,
            wc_output=wc_output,
            sha256_output=None,
            reason=f"size mismatch: expected {expected_size}, got {actual_size}",
        )

    sha256_output = _decode_output(
        provider.run_remote_command(
            f"sha256sum {shlex.quote(remote_path)} 2>&1"
        )
    )
    actual_sha256 = _parse_sha256(sha256_output)
    if actual_sha256 is not None and actual_sha256 != expected_sha256:
        return RemoteFileVerification(
            ok=False,
            remote_path=remote_path,
            expected_size=expected_size,
            actual_size=actual_size,
            expected_sha256=expected_sha256,
            actual_sha256=actual_sha256,
            ls_output=ls_output,
            wc_output=wc_output,
            sha256_output=sha256_output,
            reason="sha256 mismatch",
        )

    return RemoteFileVerification(
        ok=True,
        remote_path=remote_path,
        expected_size=expected_size,
        actual_size=actual_size,
        expected_sha256=expected_sha256,
        actual_sha256=actual_sha256,
        ls_output=ls_output,
        wc_output=wc_output,
        sha256_output=sha256_output,
        reason=None,
    )


def base64_upload_commands(local_path: Path | str, remote_path: str) -> list[str]:
    """Build shell commands that write a local file via base64 decode."""
    payload = Path(local_path).read_bytes()
    encoded = base64.b64encode(payload).decode("ascii")
    quoted_remote = shlex.quote(remote_path)
    commands: list[str] = []
    if len(encoded) <= _BASE64_CHUNK_CHARS:
        commands.append(
            _heredoc_base64_command(
                encoded,
                redirect=f"> {quoted_remote}",
            )
        )
        return commands

    commands.append(f": > {quoted_remote}")
    for offset in range(0, len(encoded), _BASE64_CHUNK_CHARS):
        chunk = encoded[offset : offset + _BASE64_CHUNK_CHARS]
        commands.append(
            _heredoc_base64_command(
                chunk,
                redirect=f">> {quoted_remote}",
            )
        )
    return commands


def _heredoc_base64_command(payload_b64: str, *, redirect: str) -> str:
    return f"echo '{payload_b64}' | base64 -d {redirect}"


def _decode_output(raw: bytes) -> str:
    return raw.decode("utf-8", errors="replace").strip()


def _looks_missing(output: str) -> bool:
    lowered = output.lower()
    if not lowered:
        return True
    return any(marker in lowered for marker in _MISSING_FILE_MARKERS)


def _parse_byte_count(output: str) -> int | None:
    match = _WC_BYTES_RE.search(output.encode("utf-8", errors="replace"))
    if match is None:
        return None
    return int(match.group(1))


def _parse_sha256(output: str) -> str | None:
    if not output or "sha256sum" in output.lower():
        return None
    token = output.split()[0]
    if len(token) != 64 or not all(ch in "0123456789abcdef" for ch in token.lower()):
        return None
    return token.lower()
