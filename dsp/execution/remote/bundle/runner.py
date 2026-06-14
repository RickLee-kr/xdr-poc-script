"""BundleScenarioRunner — upload and execute self-contained remote scenario scripts."""

from __future__ import annotations

import shlex
from typing import TYPE_CHECKING

from dsp.engine.scenario_engine import TargetSet
from dsp.execution.providers.runtime.command import CommandRequest
from dsp.execution.remote.bundle.models import BUNDLE_SCENARIOS
from dsp.execution.remote.bundle.packager import pack_scenario_bundle
from dsp.execution.remote.bundle.planner import build_manifest
from dsp.execution.remote.exceptions import UnsupportedRemoteProviderError
from dsp.execution.remote.models import RemoteScenarioExecutionResult, ScenarioExecutionRequest
from dsp.execution.remote.runner import RemoteScenarioRunner
from dsp.plugins.models import PluginRecord

if TYPE_CHECKING:
    from dsp.execution.webshell_provider import WebshellExecutionProvider


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
    ) -> RemoteScenarioExecutionResult:
        self._validate_provider(provider)
        if request.scenario_id not in BUNDLE_SCENARIOS:
            return RemoteScenarioRunner().run(request, provider, timeout_seconds=timeout_seconds)

        manifest = build_manifest(request, targets, record)
        package = pack_scenario_bundle(manifest)
        remote_run_dir = package.remote_run_dir

        provider.execute_command(
            CommandRequest.new(f"mkdir -p {shlex.quote(remote_run_dir)}")
        )
        for remote_path, local_path in package.remote_files:
            provider.upload_file(local_path, remote_path)

        command = CommandRequest.new(
            f"python3 {shlex.quote(f'{remote_run_dir}/run_scenario.py')}",
            timeout_seconds=timeout_seconds,
        )
        command_result = provider.execute_command(command)
        return RemoteScenarioRunner._build_result(request, provider, command_result)

    @staticmethod
    def _validate_provider(provider: object) -> None:
        from dsp.execution.webshell_provider import WebshellExecutionProvider

        if not isinstance(provider, WebshellExecutionProvider):
            provider_type = getattr(provider, "provider_type", type(provider).__name__)
            raise UnsupportedRemoteProviderError(str(provider_type))
