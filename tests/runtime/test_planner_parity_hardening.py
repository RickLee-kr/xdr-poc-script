"""P1/P2 hardening — local/remote planner parity and discovery bucket alignment."""

from __future__ import annotations

from dsp.discovery.legacy_bash import FAST_SAFE_DISCOVERY_PORTS, PORT_CAPABILITY_MAP
from dsp.engine.host_selection import _discovered_http_endpoint_tuples
from dsp.engine.scenario_engine import TargetSet
from dsp.execution.remote.command.discovery_plans import (
    DISCOVERY_PORTS,
    _select_http_endpoints,
    build_plan_from_discovery,
)
from dsp.protocols.http.sqli_payloads import plan_sqli_requests
from dsp.protocols.http.urls import plan_followup_requests
from dsp.protocols.dns.tunnel import select_tunnel_targets
from dsp.runtime.http_endpoint_selection import select_discovered_http_endpoint_tuples
from scenarios.dga.executor import select_dga_resolver
from scenarios.kerberos_failure.executor import select_kerberos_hosts
from scenarios.ldap_enumeration.executor import select_ldap_hosts
from scenarios.smb_login_failure.executor import select_smb_hosts


def _discovery_dict() -> dict:
    return {
        "target_net": "10.10.10.0/24",
        "hosts": ["10.10.10.97", "10.10.10.50"],
        "service_hosts": {
            "http_targets": ["10.10.10.97", "10.10.10.50"],
            "dns_hosts": ["10.10.10.98"],
            "kerberos_hosts": ["10.10.10.40"],
            "ldap_hosts": ["10.10.10.41"],
            "smb_hosts": ["10.10.10.42"],
        },
        "service_endpoints": {
            "http_targets": [
                ("10.10.10.97", 8080),
                ("10.10.10.50", 80),
            ],
            "dns_hosts": [("10.10.10.98", 53)],
            "kerberos_hosts": [("10.10.10.40", 88)],
            "ldap_hosts": [("10.10.10.41", 389)],
            "smb_hosts": [("10.10.10.42", 445)],
        },
    }


def _target_set() -> TargetSet:
    data = _discovery_dict()
    return TargetSet(
        target_net=data["target_net"],
        hosts=data["hosts"],
        service_hosts=data["service_hosts"],
        service_endpoints=data["service_endpoints"],
        discovery_enabled=True,
        discovery_meta={"alive_hosts": data["hosts"]},
    )


def test_shared_http_endpoint_selection_matches_local_and_remote() -> None:
    targets = _target_set()
    params = {"max_hosts": 2}
    local = _discovered_http_endpoint_tuples(targets, params, max_hosts=2)
    remote = _select_http_endpoints(_discovery_dict(), params)
    assert local == remote == [("10.10.10.50", 80), ("10.10.10.97", 8080)]


def test_http_followup_path_parity_between_local_and_remote_planner() -> None:
    import random

    targets_dict = _discovery_dict()
    params = {"max_hosts": 1, "max_per_host": 5, "max_total": 5, "include_attack_paths": True}
    endpoints = _select_http_endpoints(targets_dict, params)
    random.seed(7)
    local_plans = plan_followup_requests(
        endpoints=endpoints,
        max_hosts=1,
        max_per_host=5,
        max_total=5,
        include_attack_paths=True,
    )
    random.seed(7)
    remote_plan = build_plan_from_discovery(
        "http_followup",
        targets_dict,
        params,
        dry_run=True,
    )
    local_urls = {plan.url for plan in local_plans}
    remote_urls = {req["url"] for req in remote_plan["requests"]}
    assert local_urls == remote_urls


def test_sql_injection_uses_plan_sqli_requests_on_remote() -> None:
    import random

    params = {"max_hosts": 1, "max_total": 3}
    endpoints = _select_http_endpoints(_discovery_dict(), params)
    random.seed(42)
    expected = plan_sqli_requests(
        endpoints=endpoints,
        max_hosts=1,
        max_total=3,
    )
    random.seed(42)
    plan = build_plan_from_discovery(
        "sql_injection",
        _discovery_dict(),
        params,
        dry_run=True,
    )
    assert len(plan["requests"]) == len(expected)
    assert {item["url"] for item in plan["requests"]} == {item.url for item in expected}


def test_discovery_ports_include_kerberos_ldap_and_match_local() -> None:
    assert 88 in FAST_SAFE_DISCOVERY_PORTS
    assert 389 in FAST_SAFE_DISCOVERY_PORTS
    assert 636 in FAST_SAFE_DISCOVERY_PORTS
    assert PORT_CAPABILITY_MAP[88] == "kerberos_hosts"
    assert PORT_CAPABILITY_MAP[389] == "ldap_hosts"
    assert PORT_CAPABILITY_MAP[636] == "ldap_hosts"
    assert 88 in DISCOVERY_PORTS
    assert 389 in DISCOVERY_PORTS
    assert 636 in DISCOVERY_PORTS


def test_kerberos_discovery_bucket_selection() -> None:
    targets = _target_set()
    assert select_kerberos_hosts(targets, {}, max_hosts=2) == ["10.10.10.40"]
    assert select_kerberos_hosts(targets, {"hosts": ["10.0.0.5"]}, max_hosts=2) == ["10.0.0.5"]


def test_ldap_discovery_bucket_selection() -> None:
    targets = _target_set()
    assert select_ldap_hosts(targets, {}, max_hosts=2) == ["10.10.10.41"]


def test_smb_discovery_bucket_selection() -> None:
    targets = _target_set()
    assert select_smb_hosts(targets, {}, max_hosts=2) == ["10.10.10.42"]


def test_dns_tunnel_uses_alive_hosts_only() -> None:
    targets = TargetSet(
        target_net="10.10.10.0/24",
        hosts=["10.10.10.97", "10.10.10.98"],
        service_hosts={"dns_hosts": ["10.10.10.20"]},
        discovery_enabled=True,
        discovery_meta={"alive_hosts": ["10.10.10.97", "10.10.10.98"]},
    )
    assert select_tunnel_targets(targets, {}, max_hosts=2) == ["10.10.10.97", "10.10.10.98"]


def test_dga_resolver_returns_none_without_dns_hosts() -> None:
    targets = TargetSet(
        target_net="10.10.10.0/24",
        hosts=["10.10.10.97", "10.10.10.98"],
        service_hosts={"http_targets": ["10.10.10.97"]},
        discovery_enabled=True,
        discovery_meta={"alive_hosts": ["10.10.10.97", "10.10.10.98"]},
    )
    assert select_dga_resolver(targets, {}) is None


def test_dga_resolver_uses_dns_hosts_bucket() -> None:
    targets = _target_set()
    assert select_dga_resolver(targets, {}) == "10.10.10.98"


def test_select_discovered_http_endpoint_tuples_port_ranking() -> None:
    endpoints = select_discovered_http_endpoint_tuples(
        http_hosts=["10.10.10.5"],
        http_endpoints=[("10.10.10.5", 8080), ("10.10.10.5", 80)],
        max_hosts=1,
    )
    assert endpoints == [("10.10.10.5", 80)]


def test_webshell_scenario_start_metadata_defers_target_selection() -> None:
    from dsp.runner.target_selection import scenario_start_metadata

    targets = TargetSet(
        target_net="172.16.50.0/24",
        hosts=["10.10.10.97"],
        service_hosts={"http_targets": ["10.10.10.97"]},
        service_endpoints={"http_targets": [("10.10.10.97", 8080)]},
        discovery_enabled=True,
    )
    meta = scenario_start_metadata(
        "http_followup",
        targets,
        {"max_hosts": 1},
        webshell_mode=True,
    )
    assert meta["discovery_origin"] == "webshell_host"
    assert meta["remote_discovery"] == "remote_discovery_execute"
    assert meta["target_net"] == "172.16.50.0/24"
    assert meta["selected_targets"]
    assert meta["target_count"] == 1
    endpoints = select_discovered_http_endpoint_tuples(
        http_hosts=["10.10.10.5"],
        http_endpoints=[("10.10.10.5", 8080), ("10.10.10.5", 80)],
        max_hosts=1,
    )
    assert endpoints == [("10.10.10.5", 80)]


def test_rare_protocol_plan_parity_between_local_and_remote() -> None:
    from dsp.execution.remote.command.discovery_plans import build_plan_from_discovery
    from dsp.execution.remote.command.scenario_plans import _plan_rare_protocol_activity

    targets = _target_set()
    params = {"timeout": 3.0, "rtp_burst_count": 2}
    local = _plan_rare_protocol_activity(targets, params, dry_run=True)
    remote = build_plan_from_discovery(
        "rare_protocol_activity",
        _discovery_dict(),
        params,
        dry_run=True,
    )
    local_probes = {
        (p["protocol"], p["host"], p["port"], p["transport"])
        for p in local["probes"]
    }
    remote_probes = {
        (p["protocol"], p["host"], p["port"], p["transport"])
        for p in remote["probes"]
    }
    assert local_probes == remote_probes
    assert len(local_probes) >= 4
