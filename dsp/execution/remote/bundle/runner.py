"""BundleScenarioRunner — upload and execute self-contained remote scenario scripts."""

from __future__ import annotations

import json
import shlex
from pathlib import Path
from typing import TYPE_CHECKING

from dsp.engine.scenario_engine import TargetSet
from dsp.execution.providers.runtime.command import CommandRequest, CommandResult, CommandStatus
from dsp.execution.remote.bundle.models import BUNDLE_SCENARIOS
from dsp.execution.remote.bundle.packager import pack_scenario_bundle
from dsp.execution.remote.bundle.planner import build_manifest
from dsp.execution.remote.bundle.upload import (
    VerifiedUploadResult,
    upload_remote_file_verified,
    verify_remote_bundle_exists,
)
from dsp.execution.remote.exceptions import (
    RemoteArtifactUploadError,
    RemoteBundleExecutionError,
    UnsupportedRemoteProviderError,
)
from dsp.execution.remote.models import RemoteScenarioExecutionResult, ScenarioExecutionRequest
from dsp.execution.remote.runner import RemoteScenarioRunner
from dsp.execution.webshell.event_sync.bundle_content import normalize_webshell_command_output
from dsp.plugins.models import PluginRecord

if TYPE_CHECKING:
    from dsp.execution.webshell_provider import WebshellExecutionProvider

_DIAG_MANIFEST = "upload_manifest_result.txt"
_DIAG_SCRIPT = "upload_script_result.txt"
_DIAG_REMOTE_LS = "remote_ls_after_upload.txt"
_DIAG_EXEC_OUTPUT = "execution_stdout_stderr.txt"


class BundleScenarioRunner:
    """Generate, upload, and execute self-contained scenario bundles on webshell hosts."""

    def run(
        self,
        request: ScenarioExecutionRequest,
        provider: WebshellExecutionProvider,
        *,
        targets: TargetSet,
        record: PluginRecord,
        timeout_seconds: int = 300,
        diagnostics_dir: Path | str | None = None,
    ) -> RemoteScenarioExecutionResult:
        self._validate_provider(provider)
        if request.scenario_id not in BUNDLE_SCENARIOS:
            return RemoteScenarioRunner().run(request, provider, timeout_seconds=timeout_seconds)

        manifest = build_manifest(request, targets, record)
        package = pack_scenario_bundle(manifest)
        remote_run_dir = package.remote_run_dir
        diag_dir = self._resolve_diagnostics_dir(request, diagnostics_dir)

        provider.execute_command(
            CommandRequest.new(f"mkdir -p {shlex.quote(remote_run_dir)}")
        )

        manifest_remote, manifest_local = package.remote_files[0]
        script_remote, script_local = package.remote_files[1]
        manifest_upload = upload_remote_file_verified(
            provider,
            manifest_local,
            manifest_remote,
        )
        script_upload = upload_remote_file_verified(
            provider,
            script_local,
            script_remote,
        )
        self._write_upload_diagnostics(
            diag_dir,
            manifest_upload=manifest_upload,
            script_upload=script_upload,
            remote_run_dir=remote_run_dir,
            provider=provider,
        )

        script_verification = script_upload.verification
        if not script_verification.ok or (script_verification.actual_size or 0) <= 0:
            raise RemoteArtifactUploadError(
                "run_scenario.py missing or empty; execution not attempted",
                remote_path=script_remote,
                verification=script_verification,
            )

        script_path = f"{remote_run_dir}/run_scenario.py"
        command = CommandRequest.new(
            f"python3 {shlex.quote(script_path)}",
            timeout_seconds=timeout_seconds,
        )
        exec_output = provider.run_remote_command(
            f"python3 {shlex.quote(script_path)} 2>&1",
            timeout_seconds=float(timeout_seconds),
        )
        if diag_dir is not None:
            diag_dir.mkdir(parents=True, exist_ok=True)
            (diag_dir / _DIAG_EXEC_OUTPUT).write_bytes(exec_output)

        bundle_path = str(
            request.execution_metadata.get("remote_bundle_path")
            or (manifest.get("paths") or {}).get("bundle")
            or f"{remote_run_dir}/events.jsonl"
        )
        self._validate_remote_execution(
            exec_output,
            remote_bundle_path=bundle_path,
            provider=provider,
        )

        command_result = CommandResult(
            command_id=command.command_id,
            status=CommandStatus.COMPLETED,
            started_at=command.created_at,
            completed_at=command.created_at,
            execution_metadata={
                "delivery_only": True,
                "execution_output_bytes": len(exec_output),
            },
        )
        result = RemoteScenarioRunner._build_result(request, provider, command_result)
        request.execution_metadata["remote_run_dir"] = remote_run_dir
        if diag_dir is not None:
            request.execution_metadata["bundle_diagnostics_dir"] = str(diag_dir)
        return result

    @staticmethod
    def _resolve_diagnostics_dir(
        request: ScenarioExecutionRequest,
        diagnostics_dir: Path | str | None,
    ) -> Path | None:
        if diagnostics_dir is not None:
            return Path(diagnostics_dir)
        raw = request.execution_metadata.get("diagnostics_dir")
        if raw:
            return Path(str(raw))
        return None

    @staticmethod
    def _write_upload_diagnostics(
        diag_dir: Path | None,
        *,
        manifest_upload: VerifiedUploadResult,
        script_upload: VerifiedUploadResult,
        remote_run_dir: str,
        provider: WebshellExecutionProvider,
    ) -> None:
        if diag_dir is None:
            return
        diag_dir.mkdir(parents=True, exist_ok=True)
        (diag_dir / _DIAG_MANIFEST).write_text(
            manifest_upload.verification.format_report(method=manifest_upload.method),
            encoding="utf-8",
        )
        (diag_dir / _DIAG_SCRIPT).write_text(
            script_upload.verification.format_report(method=script_upload.method),
            encoding="utf-8",
        )
        ls_output = provider.run_remote_command(
            f"ls -la {shlex.quote(remote_run_dir)} 2>&1"
        )
        (diag_dir / _DIAG_REMOTE_LS).write_text(
            ls_output.decode("utf-8", errors="replace"),
            encoding="utf-8",
        )

    @staticmethod
    def _validate_provider(provider: object) -> None:
        from dsp.execution.webshell_provider import WebshellExecutionProvider

        if not isinstance(provider, WebshellExecutionProvider):
            provider_type = getattr(provider, "provider_type", type(provider).__name__)
            raise UnsupportedRemoteProviderError(str(provider_type))

    @staticmethod
    def _parse_execution_result(exec_output: bytes) -> dict[str, object] | None:
        text = normalize_webshell_command_output(exec_output)
        for line in reversed(text.splitlines()):
            candidate = line.strip()
            if not candidate.startswith("{"):
                continue
            try:
                payload = json.loads(candidate)
            except json.JSONDecodeError:
                continue
            if isinstance(payload, dict):
                return payload
        return None

    @classmethod
    def _validate_remote_execution(
        cls,
        exec_output: bytes,
        *,
        remote_bundle_path: str,
        provider: WebshellExecutionProvider,
    ) -> None:
        execution_text = normalize_webshell_command_output(exec_output)
        parsed = cls._parse_execution_result(exec_output)
        if parsed is None or int(parsed.get("exit_code", 1)) != 0:
            raise RemoteBundleExecutionError(
                "run_scenario.py failed or returned no success marker; "
                "see execution_stdout_stderr.txt",
                remote_path=remote_bundle_path,
                execution_output=execution_text,
            )

        bundle_verification = verify_remote_bundle_exists(provider, remote_bundle_path)
        if not bundle_verification.ok:
            raise RemoteBundleExecutionError(
                "events.jsonl missing or empty after run_scenario.py; "
                f"{bundle_verification.reason or 'verification failed'}; "
                "see execution_stdout_stderr.txt, upload_script_result.txt, "
                "and remote_ls_after_upload.txt",
                remote_path=remote_bundle_path,
                execution_output=execution_text,
                verification=bundle_verification,
            )
