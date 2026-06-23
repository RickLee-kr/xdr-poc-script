"""Tests for dsp.runtime.traffic_profiles."""

from __future__ import annotations

import pytest

from dsp.runtime.traffic_profiles import (
    SUPPORTED_TRAFFIC_PROFILES,
    build_scenario_params,
    parse_traffic_profile,
    profile_for_scenario,
    resolve_traffic_profile,
    scenario_params_for_profile,
)


@pytest.mark.parametrize("name", sorted(SUPPORTED_TRAFFIC_PROFILES))
def test_parse_traffic_profile_accepts_supported_names(name: str) -> None:
    assert parse_traffic_profile(name) == name
    assert parse_traffic_profile(name.upper()) == name


def test_parse_traffic_profile_rejects_invalid() -> None:
    with pytest.raises(ValueError, match="unknown traffic profile"):
        parse_traffic_profile("aggressive")


def test_resolve_traffic_profile_metadata() -> None:
    profile = resolve_traffic_profile("normal")
    assert profile.name == "normal"
    assert profile.intensity == 2
    assert "moderate" in profile.description.lower()


def test_parse_traffic_profile_accepts_legacy_aliases() -> None:
    assert parse_traffic_profile("balanced") == "normal"
    assert parse_traffic_profile("burst") == "high"


def test_dns_tunnel_profile_mapping_increases_with_intensity() -> None:
    low = scenario_params_for_profile("dns_tunnel", "low")
    normal = scenario_params_for_profile("dns_tunnel", "normal")
    high = scenario_params_for_profile("dns_tunnel", "high")

    assert low["payload_mb"] < normal["payload_mb"] < high["payload_mb"]
    assert low["traffic_profile"] == "low"
    assert high["traffic_profile"] == "high"


def test_profile_dns_tunnel_payload_mb() -> None:
    assert scenario_params_for_profile("dns_tunnel", "low")["payload_mb"] == 1.0
    assert scenario_params_for_profile("dns_tunnel", "normal")["payload_mb"] == 2.0
    assert scenario_params_for_profile("dns_tunnel", "high")["payload_mb"] == 4.0


def test_dns_tunnel_start_metadata_uses_payload_volume_not_fixed_cap() -> None:
    from dsp.engine.scenario_engine import TargetSet
    from dsp.protocols.dns.tunnel import CHUNK_SIZE_DEFAULT, plan_chunk_count
    from dsp.runner.target_selection import scenario_start_metadata

    alive = ["10.10.10.97", "10.10.10.98"]
    targets = TargetSet(
        target_net="10.10.10.0/24",
        hosts=alive,
        service_hosts={"dns_hosts": ["10.10.10.1"], "http_targets": alive},
        discovery_enabled=True,
        discovery_meta={"alive_hosts": alive},
    )
    params = scenario_params_for_profile("dns_tunnel", "normal")
    meta = scenario_start_metadata("dns_tunnel", targets, params)
    idx_per_host = plan_chunk_count(2.0, CHUNK_SIZE_DEFAULT)
    assert meta["payload_mb"] == 2.0
    assert meta["payload_bytes"] == 2 * 1024 * 1024
    assert meta["planned_queries"] == (idx_per_host + 2) * 2
    assert meta["planned_queries"] != 50


def _dga_total_domains(params: dict) -> int:
    return int(params["phase1_count"]) + int(params["phase2_count"])


def test_dga_domain_counts_increase_with_profile_intensity() -> None:
    low = scenario_params_for_profile("dga", "low")
    normal = scenario_params_for_profile("dga", "normal")
    high = scenario_params_for_profile("dga", "high")

    low_total = _dga_total_domains(low)
    normal_total = _dga_total_domains(normal)
    high_total = _dga_total_domains(high)

    assert low_total == 15
    assert normal_total == 45
    assert high_total == 90
    assert low_total < normal_total < high_total


def test_build_scenario_params_wraps_scenario_id() -> None:
    params = build_scenario_params("dummy", "low")
    assert "dummy" in params
    assert params["dummy"]["action_count"] == 3


def test_build_scenario_params_applies_overrides() -> None:
    params = build_scenario_params("dummy", "low", overrides={"action_count": 2})
    assert params["dummy"]["action_count"] == 2


def test_profile_for_scenario_includes_scenario_params() -> None:
    profile = profile_for_scenario("http_followup", "high")
    assert profile.name == "high"
    assert profile.scenario_params["max_total"] == 300
    assert profile.scenario_params["max_hosts"] == 1


def test_normal_profile_http_followup_dual_target_v139() -> None:
    params = scenario_params_for_profile("http_followup", "normal")
    assert params.get("include_attack_paths") is True
    assert params["max_hosts"] == 2
    assert params["max_total"] == 300
    assert params["max_per_host"] == 150
    assert "abnormal_ua_ratio" not in params


def test_normal_profile_sql_injection_318_requests_v139() -> None:
    params = scenario_params_for_profile("sql_injection", "normal")
    assert params["max_total"] == 318
    assert params["max_per_host"] == 159
    assert params["max_hosts"] == 2
