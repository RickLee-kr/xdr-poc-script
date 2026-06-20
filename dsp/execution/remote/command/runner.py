"""CommandScenarioRunner — webshell command-only execution (MASTER WBS v1.2)."""

from __future__ import annotations

from typing import TYPE_CHECKING

from dsp.engine.scenario_engine import RunContext, TargetSet
from dsp.execution.remote.bundle.planner import _uses_remote_discovery
from dsp.execution.remote.command.discovery import (
    build_discovery_probe_specs,
    get_cached_remote_discovery,
    probe_commands_for_specs,
    resolve_discovery_scan_max_hosts,
    run_webshell_host_discovery,
)
from dsp.execution.remote.command.events import (
    append_discovery_events,
    append_scenario_lifecycle,
    append_scenario_skipped,
)
from dsp.execution.remote.command.execute import execute_command_plan
from dsp.execution.remote.command.models import COMMAND_SCENARIOS, REMOTE_EXECUTION_MODE_COMMAND
from dsp.execution.remote.command.planner import build_command_plan
from dsp.execution.remote.exceptions import UnsupportedRemoteProviderError
from dsp.execution.remote.models import RemoteScenarioExecutionResult, ScenarioExecutionRequest
from dsp.execution.remote.runner import RemoteScenarioRunner
from dsp.plugins.models import PluginRecord

if TYPE_CHECKING:
    from dsp.execution.webshell_provider import WebshellExecutionProvider


class CommandScenarioRunner:
    """Dispatch scenario traffic through webshell commands — no DSP runtime upload."""

    def run(
        self,
        request: ScenarioExecutionRequest,
        provider: WebshellExecutionProvider,
        *,
        targets: TargetSet,
        record: PluginRecord,
        ctx: RunContext,
        timeout_seconds: int = 300,
    ) -> RemoteScenarioExecutionResult:
        self._validate_provider(provider)
        store = ctx.event_store
        run_id = str(request.run_id)
        scenario_id = request.scenario_id

        if scenario_id not in COMMAND_SCENARIOS:
            return RemoteScenarioRunner().run(request, provider, timeout_seconds=timeout_seconds)

        append_scenario_lifecycle(
            store,
            run_id=run_id,
            scenario_id=scenario_id,
            event="scenario_started",
            evidence={"remote_execution_mode": REMOTE_EXECUTION_MODE_COMMAND},
        )

        working_targets = targets
        if _uses_remote_discovery(request) and scenario_id != "host_behavior_check":
            working_targets = self._run_remote_discovery(request, provider, ctx)

        plan = build_command_plan(request, working_targets, record)
        if plan.get("mode") == "skip" or plan.get("type") == "skip":
            append_scenario_skipped(
                store,
                run_id=run_id,
                scenario_id=scenario_id,
                reason=str(plan.get("reason") or "no_targets"),
            )
            result = RemoteScenarioRunner._build_result(
                request,
                provider,
                _skipped_command_result(request),
            )
            request.execution_metadata["scenario_skipped"] = True
            request.execution_metadata["remote_execution_mode"] = REMOTE_EXECUTION_MODE_COMMAND
            return result

        commands_dispatched = execute_command_plan(plan, provider, ctx, request)
        append_scenario_lifecycle(
            store,
            run_id=run_id,
            scenario_id=scenario_id,
            event="scenario_completed",
            evidence={
                "commands_dispatched": commands_dispatched,
                "remote_execution_mode": REMOTE_EXECUTION_MODE_COMMAND,
            },
        )

        from dsp.execution.providers.runtime.command import CommandResult, CommandStatus

        command_result = CommandResult(
            command_id=f"cmd-{run_id}-{scenario_id}",
            status=CommandStatus.COMPLETED,
            execution_metadata={
                "delivery_only": True,
                "commands_dispatched": commands_dispatched,
                "remote_execution_mode": REMOTE_EXECUTION_MODE_COMMAND,
            },
        )
        result = RemoteScenarioRunner._build_result(request, provider, command_result)
        request.execution_metadata["remote_execution_mode"] = REMOTE_EXECUTION_MODE_COMMAND
        request.execution_metadata["commands_dispatched"] = commands_dispatched
        request.execution_metadata["scenario_skipped"] = False
        return result

    def _run_remote_discovery(
        self,
        request: ScenarioExecutionRequest,
        provider: WebshellExecutionProvider,
        ctx: RunContext,
    ) -> dict:
        target_net = str(request.target_net or "")
        discovery_max_hosts = resolve_discovery_scan_max_hosts(
            ctx.config.scenario_params,
            target_net,
        )
        specs = build_discovery_probe_specs(target_net, max_hosts=discovery_max_hosts)
        mock = request.dry_run
        cached = get_cached_remote_discovery(ctx.config.scenario_params, target_net)
        if cached is not None:
            return cached

        dispatch_status = "mock" if mock else "completed"
        if mock:
            commands = probe_commands_for_specs(specs, mock=True)
            for command in commands:
                provider.execute_command(command)

        targets = run_webshell_host_discovery(provider, ctx, request, specs)
        append_discovery_events(
            ctx.event_store,
            run_id=str(request.run_id),
            scenario_id=request.scenario_id,
            target_net=target_net,
            probe_specs=specs,
            dispatch_status=dispatch_status,
            discovery_result=targets.get("discovery_meta"),
        )
        return targets

    @staticmethod
    def _validate_provider(provider: object) -> None:
        from dsp.execution.webshell_provider import WebshellExecutionProvider

        if not isinstance(provider, WebshellExecutionProvider):
            provider_type = getattr(provider, "provider_type", type(provider).__name__)
            raise UnsupportedRemoteProviderError(str(provider_type))


def _skipped_command_result(request: ScenarioExecutionRequest):
    from dsp.execution.providers.runtime.command import CommandResult, CommandStatus

    return CommandResult(
        command_id=f"skip-{request.run_id}-{request.scenario_id}",
        status=CommandStatus.COMPLETED,
        execution_metadata={
            "delivery_only": True,
            "scenario_skipped": True,
            "remote_execution_mode": REMOTE_EXECUTION_MODE_COMMAND,
        },
    )
