"""SSH attempt planning and username generation unit tests."""

from __future__ import annotations

import pytest

from dsp.protocols.base import SshProtocolError
from dsp.protocols.ssh.attempts import (
    DEFAULT_PASSWORDS,
    DEFAULT_USERNAMES,
    MAX_ATTEMPTS_PER_HOST_DEFAULT,
    plan_ssh_attempts,
)


def test_default_usernames_bash_burst_list():
    assert DEFAULT_USERNAMES[0] == "invaliduser"
    assert "admin" in DEFAULT_USERNAMES


def test_default_passwords_dummy_values_only():
    assert DEFAULT_PASSWORDS == ("Password123", "Welcome123", "Test123")


def test_plan_ssh_attempts_single_host_default_caps():
    plans = plan_ssh_attempts(["10.10.10.20"])
    assert len(plans) == MAX_ATTEMPTS_PER_HOST_DEFAULT
    assert all(p.host == "10.10.10.20" for p in plans)
    assert all(p.port == 22 for p in plans)
    assert all(p.username == "invaliduser" for p in plans)


def test_plan_ssh_attempts_two_hosts_max_total():
    plans = plan_ssh_attempts(
        ["10.10.10.20", "10.10.10.21"],
        max_per_host=30,
        max_total=60,
    )
    assert len(plans) == 60
    host_counts = {
        "10.10.10.20": sum(1 for p in plans if p.host == "10.10.10.20"),
        "10.10.10.21": sum(1 for p in plans if p.host == "10.10.10.21"),
    }
    assert host_counts["10.10.10.20"] == 30
    assert host_counts["10.10.10.21"] == 30


def test_plan_ssh_attempts_respects_max_total():
    plans = plan_ssh_attempts(["10.10.10.20"], max_total=5, max_per_host=30)
    assert len(plans) == 5


def test_plan_ssh_attempts_invaliduser_burst():
    plans = plan_ssh_attempts(["10.10.10.20"], max_total=10, max_per_host=10)
    assert all(p.username == "invaliduser" for p in plans)


def test_plan_ssh_attempts_cycles_password_labels():
    plans = plan_ssh_attempts(["10.10.10.20"], max_total=6, max_per_host=6)
    labels = [p.password_label for p in plans]
    assert labels == ["Password123", "Welcome123", "Test123"] * 2


def test_plan_ssh_attempts_target_property():
    plans = plan_ssh_attempts(["lab.local"], max_total=1, max_per_host=1)
    assert plans[0].target == "invaliduser@lab.local:22"


def test_plan_ssh_attempts_requires_host():
    with pytest.raises(SshProtocolError, match="at least one host"):
        plan_ssh_attempts([])
