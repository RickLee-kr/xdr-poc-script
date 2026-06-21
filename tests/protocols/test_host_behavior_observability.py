"""Tests for host behavior observability helpers."""

from __future__ import annotations

import pytest

from dsp.event_store import EventStore, ValidationDecision
from dsp.plugins.loader import PluginLoader
from dsp.protocols.host.behavior_observability import (
    append_command_executed_event,
    append_eicar_verification_event,
    append_host_behavior_summary_event,
    build_host_behavior_checklist,
    format_host_behavior_summary_lines,
)
from dsp.runner.run_manager import format_validation_warnings
from dsp.validation import ValidationEngine


@pytest.fixture
def store(tmp_path) -> EventStore:
    s = EventStore(tmp_path / "events.db")
    s.open_run("run-obs")
    yield s
    s.close()


def test_command_executed_events_build_checklist(store: EventStore) -> None:
    run_id = "run-obs"
    sid = "host_behavior_check"
    for key, label in (
        ("whoami", "whoami"),
        ("id", "id"),
        ("hostname", "hostname"),
        ("uname", "uname"),
        ("ip_addr", "ip addr"),
        ("ip_route", "ip route"),
        ("passwd_read", "/etc/passwd"),
        ("base64_exec", "base64_exec"),
    ):
        append_command_executed_event(
            store,
            run_id=run_id,
            scenario_id=sid,
            command=label,
            command_key=key,
        )

    checklist = build_host_behavior_checklist(store, run_id, sid)
    assert checklist.whoami
    assert checklist.passwd_read
    assert checklist.base64_exec
    assert not checklist.eicar_create
    assert checklist.missing_keys() == [
        "eicar_archive",
        "eicar_copy",
        "eicar_create",
        "eicar_decode",
        "eicar_delete",
        "eicar_encode",
        "eicar_move",
        "eicar_read",
    ]


def test_eicar_lifecycle_events(store: EventStore) -> None:
    run_id = "run-obs"
    sid = "host_behavior_check"
    from dsp.protocols.host.behavior_observability import append_eicar_lifecycle_event

    for event in (
        "eicar_create",
        "eicar_read",
        "eicar_copy",
        "eicar_move",
        "eicar_archive",
        "eicar_encode",
        "eicar_decode",
        "eicar_delete",
    ):
        append_eicar_lifecycle_event(
            store,
            run_id=run_id,
            event=event,
            scenario_id=sid,
        )

    checklist = build_host_behavior_checklist(store, run_id, sid)
    assert checklist.eicar_create
    assert checklist.eicar_read
    assert checklist.eicar_copy
    assert checklist.eicar_move
    assert checklist.eicar_archive
    assert checklist.eicar_encode
    assert checklist.eicar_decode
    assert checklist.eicar_delete
    assert checklist.missing_keys() == [
        "base64_exec",
        "hostname",
        "id",
        "ip_addr",
        "ip_route",
        "passwd_read",
        "uname",
        "whoami",
    ]


def test_eicar_verification_events(store: EventStore) -> None:
    run_id = "run-obs"
    sid = "host_behavior_check"
    append_eicar_verification_event(store, run_id=run_id, phase="create", scenario_id=sid)
    append_eicar_verification_event(store, run_id=run_id, phase="read", scenario_id=sid)
    append_eicar_verification_event(store, run_id=run_id, phase="delete", scenario_id=sid)

    checklist = build_host_behavior_checklist(store, run_id, sid)
    assert checklist.eicar_create
    assert checklist.eicar_read
    assert checklist.eicar_delete


def test_format_host_behavior_summary_lines() -> None:
    lines = format_host_behavior_summary_lines(
        {
            "whoami": True,
            "id": True,
            "hostname": True,
            "uname": True,
            "ip_addr": True,
            "ip_route": True,
            "passwd_read": True,
            "base64_exec": True,
            "eicar_create": True,
            "eicar_read": True,
            "eicar_copy": False,
            "eicar_move": False,
            "eicar_archive": False,
            "eicar_encode": False,
            "eicar_decode": False,
            "eicar_delete": False,
        }
    )
    text = "\n".join(lines)
    assert "Host Behavior Summary" in text
    assert "OK" in text
    assert "MISSING" in text


def test_validation_missing_items_for_host_behavior(store: EventStore) -> None:
    run_id = "run-obs"
    sid = "host_behavior_check"
    append_command_executed_event(
        store,
        run_id=run_id,
        scenario_id=sid,
        command="whoami",
        command_key="whoami",
    )
    registry = PluginLoader().discover_and_load()
    engine = ValidationEngine(store, registry)
    result = engine.validate(run_id, sid)
    assert result.decision == ValidationDecision.FAILED
    assert "eicar_create" in result.missing_items

    warnings = format_validation_warnings([result])
    assert any("host_behavior_check" in line for line in warnings)
    assert "Missing:" in warnings
    assert "  eicar_create" in warnings


def test_append_host_behavior_summary_event(store: EventStore) -> None:
    run_id = "run-obs"
    sid = "host_behavior_check"
    append_command_executed_event(
        store,
        run_id=run_id,
        scenario_id=sid,
        command="whoami",
        command_key="whoami",
    )
    checklist = append_host_behavior_summary_event(store, run_id=run_id, scenario_id=sid)
    assert checklist.whoami
    events = store.list_events(run_id, sid)
    summary_events = [e for e in events if e.event == "host_behavior_summary"]
    assert len(summary_events) == 1
    assert summary_events[0].evidence["host_behavior"]["whoami"] is True
