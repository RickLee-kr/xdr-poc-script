"""Target-net scenario execution order — discovery prefetch then ordered follow-ups."""

from __future__ import annotations

from dsp.runtime.operational_profiles import (
    DISCOVERY_FIRST_SCENARIO_ORDER,
    HOST_BEHAVIOR_CHECK_SCENARIO_ID,
    scenarios_for_profile,
)


def test_normal_profile_matches_documented_target_net_sequence() -> None:
    scenarios = scenarios_for_profile("normal")
    assert scenarios == list(DISCOVERY_FIRST_SCENARIO_ORDER)
    assert scenarios[0] == HOST_BEHAVIOR_CHECK_SCENARIO_ID
    assert scenarios[1] == "port_sweep"
    service_block = (
        "http_followup",
        "sql_injection",
        "ssh_failure",
        "ldap_enumeration",
        "smb_login_failure",
        "kerberos_failure",
        "dga",
        "rare_protocol_activity",
    )
    assert scenarios[2 : 2 + len(service_block)] == list(service_block)
    assert scenarios[-1] == "dns_tunnel"
