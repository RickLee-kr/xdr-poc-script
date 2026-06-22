"""Webshell command-only execution guards — block legacy bundle/runner paths."""

from __future__ import annotations

from pathlib import PurePosixPath

from dsp.execution.remote.exceptions import RemoteArtifactUploadError, RemoteBundleExecutionError

FORBIDDEN_REMOTE_ARTIFACTS: frozenset[str] = frozenset(
    {
        "manifest.json",
        "run_scenario.py",
        "remote_discovery.py",
        "discover_runner.py",
    }
)

FORBIDDEN_COMMAND_SUBSTRINGS: tuple[str, ...] = (
    "manifest.json",
    "run_scenario.py",
    "remote_discovery.py",
    "discover_runner.py",
    "dsp-remote-scenario",
    "python3 /tmp/dsp/",
)


def assert_webshell_upload_allowed(remote_path: str) -> None:
    """Fail fast when a forbidden DSP runtime artifact would be uploaded."""
    normalized = remote_path.replace("\\", "/")
    basename = PurePosixPath(normalized).name
    if basename in FORBIDDEN_REMOTE_ARTIFACTS:
        raise RemoteArtifactUploadError(
            f"forbidden webshell upload blocked: {remote_path!r}",
            remote_path=remote_path,
        )
    lowered = normalized.lower()
    for token in FORBIDDEN_COMMAND_SUBSTRINGS:
        if token in lowered:
            raise RemoteArtifactUploadError(
                f"forbidden webshell upload blocked: {remote_path!r}",
                remote_path=remote_path,
            )


def assert_webshell_command_allowed(command: str) -> None:
    normalized = command.strip()
    lowered = normalized.lower()
    if lowered == "dsp-remote-scenario" or lowered.startswith("dsp-remote-scenario "):
        raise RemoteBundleExecutionError(
            "dsp-remote-scenario is disabled; webshell runs must use command-only execution",
            execution_output=normalized[:500],
        )
    for token in FORBIDDEN_COMMAND_SUBSTRINGS:
        if token in lowered:
            raise RemoteBundleExecutionError(
                f"forbidden webshell command blocked: {token}",
                execution_output=normalized[:500],
            )
