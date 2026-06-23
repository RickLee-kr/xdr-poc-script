"""User-Agent burst policy tests — Stellar suspected-UA CSV."""

from __future__ import annotations

from dsp.protocols.http.user_agents import (
    classify_user_agent,
    is_abnormal_user_agent,
    malicious_user_agents,
    pick_url_scan_user_agent,
)


def test_malicious_user_agents_loaded_from_csv():
    uas = malicious_user_agents()
    assert len(uas) >= 100
    assert "' OR 1=1--" in uas
    assert "TelemetryCollector/9.7 ${jndi:ldap://127.0.0.1/a}" in uas


def test_pick_url_scan_user_agent_never_normal_browser():
    samples = [pick_url_scan_user_agent() for _ in range(200)]
    assert not any(classify_user_agent(ua) == "normal" for ua in samples)
    assert all(is_abnormal_user_agent(ua) for ua in samples)


def test_pick_url_scan_user_agent_draws_from_csv_pool():
    pool = set(malicious_user_agents())
    samples = {pick_url_scan_user_agent() for _ in range(500)}
    assert samples <= pool
