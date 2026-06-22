"""Webshell Phase 3 target_net discovery prefetch."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from dsp.execution.remote.command.discovery import (
    REMOTE_DISCOVERY_CACHE_KEY,
    prefetch_webshell_target_net_discovery,
)
from dsp.execution.webshell_provider import WebshellExecutionProvider


def _provider_mock() -> MagicMock:
    provider = MagicMock()
    provider.__class__ = WebshellExecutionProvider
    return provider


def test_prefetch_caches_discovery_for_follow_up_scenarios() -> None:
    provider = _provider_mock()
    ctx = MagicMock()
    ctx.config.scenario_params = {}
    ctx.event_store = MagicMock()
    ctx.scenario_ids = ["http_followup", "ssh_failure"]
    ctx.dry_run = True
    ctx.target_net = "10.10.10.0/24"

    with patch(
        "dsp.execution.remote.command.discovery.run_webshell_host_discovery",
        return_value={
            "target_net": "10.10.10.0/24",
            "hosts": ["10.10.10.97"],
            "service_hosts": {"http_targets": ["10.10.10.97"]},
            "service_endpoints": {"http_targets": [("10.10.10.97", 8080)]},
            "discovery_enabled": True,
            "discovery_meta": {
                "alive_hosts": ["10.10.10.97"],
                "open_endpoints": 1,
                "probed_hosts": 254,
                "service_hosts": {"http_targets": ["10.10.10.97"]},
            },
        },
    ) as run_discovery:
        first = prefetch_webshell_target_net_discovery(
            provider,
            ctx,
            run_id="run-1",
            target_net="10.10.10.0/24",
            dry_run=True,
            execution_metadata={"traffic_origin_host": "remote"},
            event_store=ctx.event_store,
        )
        second = prefetch_webshell_target_net_discovery(
            provider,
            ctx,
            run_id="run-1",
            target_net="10.10.10.0/24",
            dry_run=True,
            execution_metadata={"traffic_origin_host": "remote"},
            event_store=ctx.event_store,
        )

    assert run_discovery.call_count == 1
    assert first == second
    cached = ctx.config.scenario_params[REMOTE_DISCOVERY_CACHE_KEY]
    assert cached["target_net"] == "10.10.10.0/24"
    assert cached["service_hosts"]["http_targets"] == ["10.10.10.97"]


def test_run_manager_prefetches_discovery_before_scenario_execute() -> None:
    from pathlib import Path
    import tempfile

    from dsp.runner import RunManager

    call_order: list[str] = []

    def _phase1(*_args, **_kwargs):
        call_order.append("phase1")
        return MagicMock(to_dict=lambda: {"phase": "phase1"})

    def _prepare(_ctx):
        call_order.append("prepare")

    def _prefetch(*_args, **_kwargs):
        call_order.append("prefetch")
        return {
            "target_net": "10.10.10.0/24",
            "hosts": [],
            "service_hosts": {},
            "service_endpoints": {},
            "discovery_enabled": True,
            "discovery_meta": {"alive_hosts": [], "open_endpoints": 0, "probed_hosts": 0},
        }

    def _execute(*_args, **_kwargs):
        call_order.append("execute")
        return None

    tmpdir = Path(tempfile.mkdtemp())
    with patch("dsp.runner.run_manager.run_webshell_phase1_attack", side_effect=_phase1):
        with patch(
            "dsp.runner.run_manager.run_webshell_phase1_non_standard_port_burst",
            return_value={"planned_requests": 0},
        ):
            with patch(
                "dsp.runner.run_manager.prefetch_webshell_target_net_discovery",
                side_effect=_prefetch,
            ):
                with patch.object(RunManager, "_create_execution_provider") as create_provider:
                    provider = _provider_mock()
                    provider.prepare.side_effect = _prepare
                    provider.execute.side_effect = _execute
                    provider.cleanup.return_value = None
                    create_provider.return_value = provider

                    manager = RunManager(runs_dir=tmpdir / "runs")
                    manager.run(
                        scenario_ids=["http_followup"],
                        target_net="10.10.10.0/24",
                        dry_run=True,
                        execution_provider="webshell",
                        webshell_url="http://10.10.10.50:8080/shell.jsp",
                        webshell_family="jsp",
                    )

    assert call_order.index("prefetch") < call_order.index("execute")
    assert call_order[:3] == ["phase1", "prepare", "prefetch"]
