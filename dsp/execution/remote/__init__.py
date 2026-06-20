"""Remote scenario execution and event collection."""

from dsp.execution.remote.collector import RemoteEventCollector
from dsp.execution.remote.collection_models import (
    RemoteEventCollectionRequest,
    RemoteEventCollectionResult,
)
from dsp.execution.remote.exceptions import (
    RemoteArtifactUploadError,
    RemoteBundleExecutionError,
    RemoteEventCollectionError,
    RemoteScenarioRunnerError,
    UnsupportedRemoteProviderError,
)
from dsp.execution.remote.models import (
    FORBIDDEN_RESULT_FIELDS,
    RemoteScenarioExecutionResult,
    ScenarioExecutionRequest,
)
from dsp.execution.remote.payload import REMOTE_SCENARIO_COMMAND, build_scenario_command
from dsp.execution.remote.runner import RemoteScenarioRunner
from dsp.execution.remote.bundle.runner import BundleScenarioRunner
from dsp.execution.remote.command import (
    COMMAND_SCENARIOS,
    CommandScenarioRunner,
    REMOTE_EXECUTION_MODE_COMMAND,
)

__all__ = [
    "COMMAND_SCENARIOS",
    "CommandScenarioRunner",
    "REMOTE_EXECUTION_MODE_COMMAND",
    "FORBIDDEN_RESULT_FIELDS",
    "REMOTE_SCENARIO_COMMAND",
    "BundleScenarioRunner",
    "RemoteArtifactUploadError",
    "RemoteBundleExecutionError",
    "RemoteEventCollectionError",
    "RemoteEventCollectionRequest",
    "RemoteEventCollectionResult",
    "RemoteEventCollector",
    "RemoteScenarioExecutionResult",
    "RemoteScenarioRunner",
    "RemoteScenarioRunnerError",
    "ScenarioExecutionRequest",
    "UnsupportedRemoteProviderError",
    "build_scenario_command",
]
