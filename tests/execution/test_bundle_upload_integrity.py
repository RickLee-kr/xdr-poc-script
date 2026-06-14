"""Webshell bundle upload integrity tests."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest

from dsp.engine import RunConfig, RunContext, resolve_targets
from dsp.event_store import EventStore
from dsp.execution import ExecutionContext, WebshellExecutionProvider
from dsp.execution.providers.runtime.command import CommandExecutionPolicy
from dsp.execution.providers.runtime.transport import TransportRuntimeConfiguration
from dsp.execution.providers.webshell.jsp import JspWebshellProvider
from dsp.execution.remote import (
    RemoteArtifactUploadError,
    RemoteEventCollectionError,
    RemoteEventCollectionRequest,
    RemoteEventCollector,
)
from dsp.execution.remote.bundle.runner import BundleScenarioRunner
from dsp.execution.remote.bundle.upload import base64_upload_commands, upload_remote_file_verified
from dsp.execution.remote.models import ScenarioExecutionRequest
from dsp.execution.webshell.transport import RealHttpTransport, RetryPolicy
from dsp.execution.webshell_config import WebshellExecutionConfig
from dsp.plugins import PluginLoader
from tests.e2e.fixtures.bundle_helpers import remote_bundle_path_for_run
from tests.e2e.fixtures.webshell_test_server import WebshellTestServer


def _connected_provider(server: WebshellTestServer) -> WebshellExecutionProvider:
    transport = RealHttpTransport(retry_policy=RetryPolicy(max_retries=0))
    family_provider = JspWebshellProvider(
        transport=transport,
        webshell_url=server.webshell_url,
    )
    family_provider.create_runtime(
        config=TransportRuntimeConfiguration(
            enable_healthcheck_on_connect=False,
            command_policy=CommandExecutionPolicy(allow_command_execution=True),
        ),
    )
    family_provider.connect()
    config = WebshellExecutionConfig(provider_type="jsp", webshell_url=server.webshell_url)
    return WebshellExecutionProvider(config, transport=transport, family_provider=family_provider)


def test_post_success_without_remote_file_raises_upload_error(tmp_path: Path) -> None:
    provider = MagicMock(spec=WebshellExecutionProvider)
    provider.provider_type = "webshell"
    local = tmp_path / "payload.txt"
    local.write_text("hello", encoding="utf-8")

    def _run_remote_command(command: str, *, timeout_seconds: float = 300.0) -> bytes:
        if command.startswith("ls -l"):
            return b"ls: cannot access '/tmp/x/payload.txt': No such file or directory\n"
        if command.startswith("wc -c"):
            return b"0\n"
        if command.startswith("sha256sum"):
            return b"sha256sum: /tmp/x/payload.txt: No such file or directory\n"
        if "base64 -d" in command:
            return b""
        return b""

    provider.run_remote_command.side_effect = _run_remote_command
    with pytest.raises(RemoteArtifactUploadError, match="verification failed"):
        upload_remote_file_verified(provider, local, "/tmp/x/payload.txt")
    provider.upload_file.assert_called_once()
    server = WebshellTestServer(
        storage_dir=tmp_path / "server",
        ignore_multipart_upload=True,
    )
    server.start()
    provider = _connected_provider(server)
    local = tmp_path / "runner.py"
    local.write_text("print('ok')\n", encoding="utf-8")
    remote = "/tmp/dsp/run01/run_scenario.py"
    result = upload_remote_file_verified(provider, local, remote)
    assert result.method == "base64"
    assert result.verification.ok is True
    assert server._files[remote] == local.read_bytes()
    server.stop()


def test_base64_upload_commands_support_chunked_payload(tmp_path: Path) -> None:
    local = tmp_path / "big.bin"
    local.write_bytes(b"x" * 5000)
    commands = base64_upload_commands(local, "/tmp/dsp/run01/big.bin")
    assert len(commands) > 1
    assert commands[0].startswith(": >")
    assert all("base64 -d" in command for command in commands[1:])


def test_run_scenario_not_executed_when_script_missing(tmp_path: Path) -> None:
    server = WebshellTestServer(
        storage_dir=tmp_path / "server",
        ignore_multipart_upload=True,
        ignore_command_upload=True,
    )
    server.start()
    provider = _connected_provider(server)
    loader = PluginLoader()
    record = loader.discover_and_load().get("port_sweep")
    assert record is not None
    request = ScenarioExecutionRequest(
        scenario_id="port_sweep",
        scenario_params={"max_hosts": 1, "max_ports": 1},
        execution_metadata={"remote_work_dir": "/tmp/dsp"},
        run_id="missing_script",
        target_net="10.10.10.0/24",
        dry_run=True,
    )
    runner = BundleScenarioRunner()
    with pytest.raises(RemoteArtifactUploadError, match="verification failed"):
        runner.run(
            request,
            provider,
            targets=resolve_targets("10.10.10.0/24", dry_run=True),
            record=record,
            diagnostics_dir=tmp_path / "diag",
        )
    assert not any(
        call.startswith("python3 ")
        for call in server.command_calls
    )
    server.stop()


def test_bundle_runner_writes_upload_diagnostics(tmp_path: Path) -> None:
    server = WebshellTestServer(storage_dir=tmp_path / "server")
    server.start()
    provider = _connected_provider(server)
    loader = PluginLoader()
    record = loader.discover_and_load().get("port_sweep")
    assert record is not None
    diag_dir = tmp_path / "diag"
    request = ScenarioExecutionRequest(
        scenario_id="port_sweep",
        scenario_params={"max_hosts": 1, "max_ports": 1},
        execution_metadata={"remote_work_dir": "/tmp/dsp"},
        run_id="diag_run",
        target_net="10.10.10.0/24",
        dry_run=True,
    )
    BundleScenarioRunner().run(
        request,
        provider,
        targets=resolve_targets("10.10.10.0/24", dry_run=True),
        record=record,
        diagnostics_dir=diag_dir,
    )
    assert (diag_dir / "upload_manifest_result.txt").is_file()
    assert (diag_dir / "upload_script_result.txt").is_file()
    assert (diag_dir / "remote_ls_after_upload.txt").is_file()
    assert (diag_dir / "execution_stdout_stderr.txt").is_file()
    server.stop()


def test_events_jsonl_missing_raises_diagnostic_error_not_validation(tmp_path: Path) -> None:
    server = WebshellTestServer(storage_dir=tmp_path / "server")
    server.start()
    provider = _connected_provider(server)
    run_id = "no_events"
    bundle_path = remote_bundle_path_for_run(run_id)
    store = EventStore(":memory:")
    store.open_run(run_id)
    diag_dir = tmp_path / "collection-diag"
    with pytest.raises(RemoteEventCollectionError, match="events.jsonl missing") as exc_info:
        RemoteEventCollector().collect(
            RemoteEventCollectionRequest(
                remote_execution_id=run_id,
                remote_bundle_path=bundle_path,
                diagnostics_dir=diag_dir,
            ),
            provider,
            store,
        )
    assert exc_info.type is RemoteEventCollectionError
    assert (diag_dir / "remote_ls_after_collection.txt").is_file()
    assert (diag_dir / "downloaded_events.cat.raw").is_file()
    error_text = (diag_dir / "collection_error.txt").read_text(encoding="utf-8")
    assert "cat fallback" in error_text
    server.stop()


def test_mock_provider_upload_verification_failure(tmp_path: Path) -> None:
    provider = MagicMock(spec=WebshellExecutionProvider)
    provider.provider_type = "webshell"
    local = tmp_path / "manifest.json"
    local.write_text("{}", encoding="utf-8")

    def _run_remote_command(command: str, *, timeout_seconds: float = 300.0) -> bytes:
        if command.startswith("ls -l"):
            return b"ls: cannot access '/tmp/x/manifest.json': No such file or directory\n"
        if command.startswith("wc -c"):
            return b"0\n"
        if command.startswith("sha256sum"):
            return b"sha256sum: /tmp/x/manifest.json: No such file or directory\n"
        return b""

    provider.run_remote_command.side_effect = _run_remote_command
    with pytest.raises(RemoteArtifactUploadError):
        upload_remote_file_verified(provider, local, "/tmp/x/manifest.json")
