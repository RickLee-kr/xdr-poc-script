"""HTTP follow-up detection parity helpers."""

from __future__ import annotations

from dsp.protocols.http.target_probe import HttpEndpointProbeStats, is_eligible_url_scan_target
from dsp.protocols.http.user_agents import (
    is_payload_only_user_agent,
    is_scanner_user_agent,
    pick_url_scan_user_agent,
)


def test_pick_url_scan_user_agent_never_payload_only():
    for _ in range(100):
        ua = pick_url_scan_user_agent()
        assert is_scanner_user_agent(ua)
        assert not is_payload_only_user_agent(ua)


def test_redirect_only_probe_stats():
    stats = HttpEndpointProbeStats(host="1.2.3.4", port=80, scheme="http", status_counts={301: 7})
    assert stats.is_redirect_only
    assert stats.detection_score() < 0
    assert not is_eligible_url_scan_target(stats)

    mixed = HttpEndpointProbeStats(
        host="1.2.3.4", port=80, scheme="http", status_counts={301: 2, 404: 3}
    )
    assert not mixed.is_redirect_only
    assert is_eligible_url_scan_target(mixed)

    timeout_only = HttpEndpointProbeStats(host="1.2.3.4", port=80, scheme="http", timeouts=7)
    assert not is_eligible_url_scan_target(timeout_only)
