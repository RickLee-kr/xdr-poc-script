"""Webshell discovery should refresh console attack targets after remote probe."""

from __future__ import annotations

from unittest.mock import MagicMock

from dsp.engine import RunConfig, RunContext
from dsp.event_store import EventStore
from dsp.execution.remote.command.discovery import emit_webshell_discovery_progress


def test_emit_webshell_discovery_progress_updates_targets(tmp_path) -> None:
    phases: list[tuple[str, dict]] = []

    store = EventStore(tmp_path / "events.db")
    store.open_run("run-console")
    ctx = RunContext(
        run_id="run-console",
        target_net="221.139.249.0/24",
        event_store=store,
        config=RunConfig(
            scenario_params={
                "_webshell_execution": {
                    "execution_host": "10.10.10.50",
                    "execution_port": 8080,
                    "execution_path": "/shell.jsp",
                    "webshell_url": "http://10.10.10.50:8080/shell.jsp",
                },
                "http_followup": {"max_hosts": 2},
                "ssh_failure": {"max_hosts": 2},
            }
        ),
        progress_emitter=lambda phase, data: phases.append((phase, data)),
        scenario_ids=["http_followup", "ssh_failure"],
    )
    targets = {
        "target_net": "221.139.249.0/24",
        "hosts": ["221.139.249.110", "221.139.249.118"],
        "service_hosts": {
            "http_targets": ["221.139.249.110"],
            "ssh_hosts": ["221.139.249.118"],
        },
        "service_endpoints": {
            "http_targets": [("221.139.249.110", 80)],
            "ssh_hosts": [("221.139.249.118", 22)],
        },
        "discovery_enabled": True,
        "discovery_meta": {
            "alive_hosts": ["221.139.249.110", "221.139.249.118"],
            "open_endpoints": 2,
            "probed_hosts": 254,
            "discovery_method": "command_inline_base64_exec",
            "command_delivery": "inline_base64_exec",
            "runner_upload": False,
        },
    }
    emit_webshell_discovery_progress(ctx, targets=targets)

    assert phases[0][0] == "discovery_completed"
    assert phases[0][1]["alive_hosts"] == ["221.139.249.110", "221.139.249.118"]
    assert phases[1][0] == "targets_selected"
    groups = phases[1][1]["groups"]
    assert "HTTP" in groups
    assert "SSH" in groups
    assert "221.139.249.110" in groups["HTTP"][0]
    assert "221.139.249.118" in groups["SSH"]
