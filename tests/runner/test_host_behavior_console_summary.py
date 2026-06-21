"""Console output tests for host behavior summary."""

from __future__ import annotations

import io

from dsp.runner.console_output import OperationalConsole


def test_scenario_completed_prints_host_behavior_summary() -> None:
    stream = io.StringIO()
    console = OperationalConsole(stream=stream)
    console.handle_progress(
        "scenario_completed",
        {
            "scenario_id": "host_behavior_check",
            "metrics": {},
            "extras": {
                "host_behavior_summary": {
                    "whoami": True,
                    "id": True,
                    "hostname": True,
                    "uname": True,
                    "ip_addr": True,
                    "ip_route": True,
                    "passwd_read": True,
                    "base64_exec": True,
                    "eicar_create": False,
                    "eicar_read": False,
                    "eicar_delete": False,
                }
            },
            "artifacts": {},
        },
    )
    output = stream.getvalue()
    assert "Host Behavior Check Completed" in output
    assert "Host Behavior Summary" in output
    assert "whoami" in output
    assert "MISSING" in output
    assert "create" in output
