"""Real webshell bundle-mode E2E — local fake JSP server, real CLI/RunManager path."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from dsp.event_store import EventQuery, EventStore
from dsp.execution.remote.exceptions import (
    RemoteBundleExecutionError,
    RemoteEventCollectionError,
)
from dsp.runner import RunManager
from tests.e2e.fixtures.webshell_test_server import WebshellTestServer


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _run_dsp_cli(
    *,
    webshell_url: str,
    remote_work_dir: str,
    runs_dir: Path,
    extra_env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    env = dict(**{k: v for k, v in __import__("os").environ.items()})
    env["DSP_RUNS_DIR"] = str(runs_dir)
    if extra_env:
        env.update(extra_env)
    cmd = [
        sys.executable,
        "-m",
        "dsp.runner.cli",
        "run",
        "--profile",
        "low",
        "--execution-provider",
        "webshell",
        "--webshell-family",
        "jsp",
        "--webshell-url",
        webshell_url,
        "--remote-work-dir",
        remote_work_dir,
        "--target-net",
        "127.0.0.0/30",
        "--quiet",
    ]
    return subprocess.run(
        cmd,
        cwd=str(_repo_root()),
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )


def _latest_run_dir(runs_dir: Path) -> Path:
    candidates = sorted(
        (path for path in runs_dir.iterdir() if path.is_dir()),
        key=lambda path: path.stat().st_mtime,
        reverse=True,
    )
    assert candidates, f"no run directories under {runs_dir}"
    return candidates[0]


def _first_jsonl_line(path: Path) -> str:
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            return line
    raise AssertionError(f"no non-empty lines in {path}")


@pytest.fixture
def webshell_fixture(tmp_path: Path):
    server = WebshellTestServer(storage_dir=tmp_path / "remote-storage")
    remote_work_dir = str(tmp_path / "remote-work")
    url = server.start()
    try:
        yield server, remote_work_dir, tmp_path / "runs"
    finally:
        server.stop()


def test_real_webshell_bundle_mode_cli_success(webshell_fixture) -> None:
    server, remote_work_dir, runs_dir = webshell_fixture
    runs_dir.mkdir(parents=True, exist_ok=True)

    completed = _run_dsp_cli(
        webshell_url=server.webshell_url,
        remote_work_dir=remote_work_dir,
        runs_dir=runs_dir,
    )
    assert completed.returncode == 0, completed.stderr or completed.stdout

    run_dir = _latest_run_dir(runs_dir)
    run_id = run_dir.name
    remote_run_dir = f"{remote_work_dir.rstrip('/')}/{run_id}"
    remote_bundle_path = f"{remote_run_dir}/events.jsonl"

    assert any(call.startswith("mkdir -p ") for call in server.command_calls)
    assert f"{remote_run_dir}/manifest.json" in server.upload_calls
    assert f"{remote_run_dir}/run_scenario.py" in server.upload_calls
    assert any(
        call.startswith("python3 ") and "run_scenario.py" in call
        for call in server.command_calls
    )
    assert remote_bundle_path in server._files or (
        Path(server.storage_dir or Path("/tmp")) / remote_bundle_path.lstrip("/")
    ).exists()

    bundle_bytes = server._read_remote_file(remote_bundle_path)
    assert bundle_bytes, "events.jsonl must exist remotely"
    first_remote_line = next(
        line for line in bundle_bytes.decode("utf-8").splitlines() if line.strip()
    )
    assert first_remote_line.startswith("{")

    for name in (
        "events.jsonl",
        "events.db",
        "report.json",
        "validation.json",
        "upload_manifest_result.txt",
        "upload_script_result.txt",
        "remote_ls_after_upload.txt",
        "execution_stdout_stderr.txt",
    ):
        assert (run_dir / name).is_file(), f"missing {name}"

    exec_output = (run_dir / "execution_stdout_stderr.txt").read_text(encoding="utf-8")
    assert "Traceback" not in exec_output
    parsed = json.loads(exec_output.strip().splitlines()[-1])
    assert parsed.get("exit_code") == 0

    store = EventStore.open_existing(run_dir / "events.db")
    try:
        imported = store.count(EventQuery(run_id=run_id))
        assert imported >= 1
        assert store.count(
            EventQuery(run_id=run_id, scenario_id="port_sweep", event="port_probe_sent")
        ) >= 1
    finally:
        store.close()

    local_events = (run_dir / "events.jsonl").read_text(encoding="utf-8")
    assert local_events.strip()
    assert _first_jsonl_line(run_dir / "events.jsonl").startswith("{")


def test_real_webshell_bundle_mode_run_manager_success(
    tmp_path: Path,
    webshell_fixture,
) -> None:
    server, remote_work_dir, runs_dir = webshell_fixture
    manager = RunManager(runs_dir=runs_dir)
    run, run_dir, exit_code = manager.run(
        operational_profile="low",
        scenario_ids=["port_sweep", "dns_tunnel", "http_followup"],
        target_net="127.0.0.0/30",
        dry_run=False,
        execution_provider="webshell",
        webshell_family="jsp",
        webshell_url=server.webshell_url,
        remote_work_dir=remote_work_dir,
    )

    assert exit_code == 0
    assert run.status.value == "completed"
    assert (run_dir / "events.jsonl").is_file()
    assert (run_dir / "report.json").is_file()
    assert not any(call.startswith("dsp-remote-scenario") for call in server.command_calls)


def test_upload_post_success_without_file_uses_base64_fallback(
    tmp_path: Path,
) -> None:
    server = WebshellTestServer(
        storage_dir=tmp_path / "storage",
        ignore_multipart_upload=True,
    )
    server.start()
    manager = RunManager(runs_dir=tmp_path / "runs")
    try:
        _, run_dir, exit_code = manager.run(
            scenario_ids=["port_sweep"],
            target_net="127.0.0.0/30",
            dry_run=False,
            scenario_params={"port_sweep": {"max_hosts": 1, "max_ports": 2}},
            execution_provider="webshell",
            webshell_family="jsp",
            webshell_url=server.webshell_url,
            remote_work_dir=str(tmp_path / "remote-work"),
        )
        assert exit_code == 0
        script_report = (run_dir / "upload_script_result.txt").read_text(encoding="utf-8")
        assert "method: base64" in script_report
        assert (run_dir / "events.jsonl").is_file()
    finally:
        server.stop()


def test_remote_path_html_download_uses_cat_fallback(
    tmp_path: Path,
) -> None:
    server = WebshellTestServer(
        storage_dir=tmp_path / "storage",
        invalid_download_wrapper=True,
    )
    server.start()
    manager = RunManager(runs_dir=tmp_path / "runs")
    try:
        _, run_dir, exit_code = manager.run(
            scenario_ids=["port_sweep"],
            target_net="127.0.0.0/30",
            dry_run=False,
            scenario_params={"port_sweep": {"max_hosts": 1, "max_ports": 2}},
            execution_provider="webshell",
            webshell_family="jsp",
            webshell_url=server.webshell_url,
            remote_work_dir=str(tmp_path / "remote-work"),
        )
        assert exit_code == 0
        assert (run_dir / "events.jsonl").is_file()
        assert _first_jsonl_line(run_dir / "events.jsonl").startswith("{")
        assert any(call.startswith("cat ") for call in server.command_calls)
    finally:
        server.stop()


def test_run_scenario_failure_surfaces_execution_output(
    tmp_path: Path,
) -> None:
    server = WebshellTestServer(
        storage_dir=tmp_path / "storage",
        fail_script_execution=True,
    )
    server.start()
    manager = RunManager(runs_dir=tmp_path / "runs")
    try:
        with pytest.raises(RemoteBundleExecutionError, match="run_scenario.py failed"):
            manager.run(
                scenario_ids=["port_sweep"],
                target_net="127.0.0.0/30",
                dry_run=False,
                scenario_params={"port_sweep": {"max_hosts": 1, "max_ports": 2}},
                execution_provider="webshell",
                webshell_family="jsp",
                webshell_url=server.webshell_url,
                remote_work_dir=str(tmp_path / "remote-work"),
            )
        run_dir = _latest_run_dir(tmp_path / "runs")
        exec_output = (run_dir / "execution_stdout_stderr.txt").read_text(encoding="utf-8")
        assert "simulated remote bundle failure" in exec_output
    finally:
        server.stop()


def test_events_jsonl_missing_raises_collection_error_with_diagnostics(
    tmp_path: Path,
) -> None:
    from dsp.execution.providers.runtime.command import CommandExecutionPolicy
    from dsp.execution.providers.runtime.transport import TransportRuntimeConfiguration
    from dsp.execution.providers.webshell.jsp import JspWebshellProvider
    from dsp.execution import WebshellExecutionProvider
    from dsp.execution.remote import RemoteEventCollectionRequest, RemoteEventCollector
    from dsp.execution.webshell.transport import RealHttpTransport, RetryPolicy
    from dsp.execution.webshell_config import WebshellExecutionConfig
    from tests.e2e.fixtures.bundle_helpers import remote_bundle_path_for_run

    server = WebshellTestServer(storage_dir=tmp_path / "storage")
    server.start()
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
    provider = WebshellExecutionProvider(
        WebshellExecutionConfig(provider_type="jsp", webshell_url=server.webshell_url),
        transport=transport,
        family_provider=family_provider,
    )
    run_id = "missing_events_run"
    bundle_path = remote_bundle_path_for_run(run_id)
    store = EventStore(":memory:")
    store.open_run(run_id)
    diag_dir = tmp_path / "collection-diag"

    try:
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
        assert "Traceback" not in str(exc_info.value)
        assert (diag_dir / "remote_ls_after_collection.txt").is_file()
        assert (diag_dir / "collection_error.txt").is_file()
        assert (diag_dir / "downloaded_events.cat.raw").is_file()
    finally:
        server.stop()


def test_html_wrapped_command_output_still_uploads_and_collects(
    tmp_path: Path,
) -> None:
    server = WebshellTestServer(
        storage_dir=tmp_path / "storage",
        wrap_command_output_in_html=True,
        wrap_download_in_html=True,
    )
    server.start()
    manager = RunManager(runs_dir=tmp_path / "runs")
    try:
        _, run_dir, exit_code = manager.run(
            scenario_ids=["port_sweep"],
            target_net="127.0.0.0/30",
            dry_run=False,
            scenario_params={"port_sweep": {"max_hosts": 1, "max_ports": 2}},
            execution_provider="webshell",
            webshell_family="jsp",
            webshell_url=server.webshell_url,
            remote_work_dir=str(tmp_path / "remote-work"),
        )
        assert exit_code == 0
        assert (run_dir / "events.jsonl").is_file()
    finally:
        server.stop()
