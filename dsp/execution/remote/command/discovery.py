"""Webshell-origin discovery planning — command dispatch only, no DSP-side probes."""

from __future__ import annotations

import base64
import json
import shlex
from typing import Any

from dsp.discovery.legacy_bash import (
    DISCOVERY_MAX_HOSTS,
    FAST_SAFE_DISCOVERY_PORTS,
    PORT_CAPABILITY_MAP as LOCAL_PORT_CAPABILITY_MAP,
)
from dsp.execution.remote.command.models import DISCOVERY_ORIGIN_WEBSHELL
from dsp.execution.remote.command.shell import mock_noop_command, tcp_probe_command
from dsp.execution.remote.bundle.assets.remote_discovery import (
    DISCOVERY_PORTS,
    PORT_CAPABILITY_MAP,
    discover_target_net,
    expand_target_net_hosts,
)

REMOTE_DISCOVERY_CACHE_KEY = "_remote_discovery_targets"
DEFAULT_REMOTE_DISCOVERY_TIMEOUT = 0.5
DEFAULT_REMOTE_DISCOVERY_WORKERS = 32


def build_discovery_probe_specs(
    target_net: str,
    *,
    max_hosts: int = DISCOVERY_MAX_HOSTS,
    ports: tuple[int, ...] | None = None,
) -> list[dict[str, Any]]:
    """Plan host:port probes — DSP plans targets; webshell host executes probes."""
    port_list = ports or FAST_SAFE_DISCOVERY_PORTS
    candidates = expand_target_net_hosts(target_net, max_hosts=max_hosts)
    specs: list[dict[str, Any]] = []
    for host in candidates:
        for port in port_list:
            specs.append(
                {
                    "host": host,
                    "port": int(port),
                    "capability": PORT_CAPABILITY_MAP.get(int(port)),
                }
            )
    return specs


def _empty_service_buckets() -> tuple[dict[str, list[str]], dict[str, list[tuple[str, int]]]]:
    keys = (
        "ssh_hosts",
        "dns_hosts",
        "kerberos_hosts",
        "ldap_hosts",
        "http_targets",
        "https_targets",
        "smb_hosts",
    )
    service_hosts = {key: [] for key in keys}
    service_endpoints = {key: [] for key in keys}
    return service_hosts, service_endpoints


def _sort_service_buckets(
    service_hosts: dict[str, list[str]],
    service_endpoints: dict[str, list[tuple[str, int]]],
) -> None:
    for key in service_hosts:
        service_hosts[key] = sorted(
            service_hosts[key],
            key=lambda h: tuple(int(p) for p in h.split(".")),
        )
        service_endpoints[key] = sorted(
            service_endpoints[key],
            key=lambda ep: (tuple(int(p) for p in ep[0].split(".")), ep[1]),
        )


def build_discovery_targets_from_open_endpoints(
    target_net: str,
    probe_specs: list[dict[str, Any]],
    open_endpoints: set[tuple[str, int]],
    *,
    candidate_hosts: list[str] | None = None,
) -> dict[str, Any]:
    """Materialize discovery buckets from successful host:port probes only."""
    service_hosts, service_endpoints = _empty_service_buckets()
    alive: set[str] = set()
    candidates = candidate_hosts or sorted(
        {str(spec["host"]) for spec in probe_specs},
        key=lambda h: tuple(int(p) for p in h.split(".")),
    )

    for spec in probe_specs:
        host = str(spec["host"])
        port = int(spec["port"])
        if (host, port) not in open_endpoints:
            continue
        capability = spec.get("capability") or PORT_CAPABILITY_MAP.get(port)
        if capability is None:
            continue
        alive.add(host)
        bucket = service_hosts.setdefault(str(capability), [])
        if host not in bucket:
            bucket.append(host)
        endpoint_bucket = service_endpoints.setdefault(str(capability), [])
        if (host, port) not in endpoint_bucket:
            endpoint_bucket.append((host, port))

    _sort_service_buckets(service_hosts, service_endpoints)
    alive_hosts = sorted(alive, key=lambda h: tuple(int(p) for p in h.split(".")))
    open_count = len(open_endpoints)

    return {
        "target_net": target_net,
        "hosts": alive_hosts,
        "service_hosts": service_hosts,
        "service_endpoints": {
            key: list(value) for key, value in service_endpoints.items()
        },
        "discovery_enabled": True,
        "discovery_meta": {
            "probed_hosts": len(candidates),
            "alive_hosts": alive_hosts,
            "open_endpoints": open_count,
            "service_hosts": service_hosts,
            "discovery_origin": DISCOVERY_ORIGIN_WEBSHELL,
            "planned_only": False,
        },
    }


def build_mock_discovery_targets(
    target_net: str,
    params: dict[str, Any],
    *,
    max_hosts: int = DISCOVERY_MAX_HOSTS,
    ports: tuple[int, ...] | None = None,
) -> dict[str, Any]:
    """
    Dry-run discovery buckets — never assume services are open.

    Candidate hosts remain available for port_sweep; service-specific follow-ups
    require explicit ``params.hosts`` or real live discovery output.
    """
    port_list = ports or DISCOVERY_PORTS
    candidates = expand_target_net_hosts(target_net, max_hosts=max_hosts)
    if params.get("hosts"):
        candidates = [str(h) for h in params["hosts"]][:max_hosts]

    service_hosts, service_endpoints = _empty_service_buckets()
    return {
        "target_net": target_net,
        "hosts": sorted(candidates, key=lambda h: tuple(int(p) for p in h.split("."))),
        "service_hosts": service_hosts,
        "service_endpoints": {key: list(value) for key, value in service_endpoints.items()},
        "discovery_enabled": True,
        "discovery_meta": {
            "probed_hosts": len(candidates),
            "alive_hosts": [],
            "open_endpoints": 0,
            "service_hosts": service_hosts,
            "discovery_origin": DISCOVERY_ORIGIN_WEBSHELL,
            "planned_only": False,
            "mock_discovery": True,
            "ports_planned": list(port_list),
        },
    }


def build_planned_discovery_targets(
    target_net: str,
    params: dict[str, Any],
    *,
    max_hosts: int = DISCOVERY_MAX_HOSTS,
    ports: tuple[int, ...] | None = None,
) -> dict[str, Any]:
    """Deprecated alias — use mock or probe-result builders instead."""
    return build_mock_discovery_targets(
        target_net,
        params,
        max_hosts=max_hosts,
        ports=ports,
    )


def build_remote_discovery_command(
    target_net: str,
    *,
    max_hosts: int = DISCOVERY_MAX_HOSTS,
    ports: tuple[int, ...] | None = None,
    timeout: float = DEFAULT_REMOTE_DISCOVERY_TIMEOUT,
    workers: int = DEFAULT_REMOTE_DISCOVERY_WORKERS,
) -> str:
    """Build a single webshell command that runs target_net discovery on the remote host."""
    port_list = ports or FAST_SAFE_DISCOVERY_PORTS
    port_map = {int(k): v for k, v in LOCAL_PORT_CAPABILITY_MAP.items()}
    script = f"""import ipaddress,json,socket
from concurrent.futures import ThreadPoolExecutor,as_completed
TARGET_NET={target_net!r}
MAX_HOSTS={max_hosts}
PORTS={list(port_list)!r}
PORT_MAP={json.dumps(port_map)!r}
TIMEOUT={timeout}
WORKERS={workers}
def expand_hosts(net,max_hosts):
 n=ipaddress.ip_network(net.strip(),strict=False)
 out=[]
 for addr in n.hosts():
  out.append(str(addr))
  if len(out)>=max_hosts:
   break
 return out
def probe(host,port):
 try:
  s=socket.create_connection((host,port),timeout=TIMEOUT)
  s.close()
  return True
 except OSError:
  return False
candidates=expand_hosts(TARGET_NET,MAX_HOSTS)
service_hosts={{cap:[] for cap in set(PORT_MAP.values())}}
service_endpoints={{cap:[] for cap in set(PORT_MAP.values())}}
alive=set()
open_endpoints=0
tasks=[(h,p) for h in candidates for p in PORTS if p in PORT_MAP]
with ThreadPoolExecutor(max_workers=min(WORKERS,max(1,len(tasks)))) as pool:
 futures={{pool.submit(probe,h,p):(h,p) for h,p in tasks}}
 for fut in as_completed(futures):
  h,p=futures[fut]
  if not fut.result():
   continue
  cap=PORT_MAP[p]
  alive.add(h)
  open_endpoints+=1
  if h not in service_hosts[cap]:
   service_hosts[cap].append(h)
  service_endpoints[cap].append([h,p])
for key in service_hosts:
 service_hosts[key]=sorted(service_hosts[key],key=lambda x:tuple(int(p) for p in x.split('.')))
for key in service_endpoints:
 service_endpoints[key]=sorted(service_endpoints[key],key=lambda ep:(tuple(int(p) for p in ep[0].split('.')),ep[1]))
alive_hosts=sorted(alive,key=lambda x:tuple(int(p) for p in x.split('.')))
print(json.dumps({{
 "target_net": TARGET_NET,
 "hosts": alive_hosts,
 "service_hosts": service_hosts,
 "service_endpoints": service_endpoints,
 "discovery_enabled": True,
 "discovery_meta": {{
  "probed_hosts": len(candidates),
  "alive_hosts": alive_hosts,
  "open_endpoints": open_endpoints,
  "service_hosts": service_hosts,
  "discovery_origin": "webshell_host",
 }},
}}))
"""
    encoded = base64.b64encode(script.encode("utf-8")).decode("ascii")
    return f"echo {shlex.quote(encoded)} | base64 -d | python3"


def parse_remote_discovery_output(raw: bytes) -> dict[str, Any]:
    """Parse JSON discovery payload returned by the webshell host."""
    text = raw.decode("utf-8", errors="replace").strip()
    start = text.find("{")
    end = text.rfind("}")
    if start < 0 or end <= start:
        raise ValueError("remote discovery output did not contain JSON")
    payload = json.loads(text[start : end + 1])
    service_endpoints = payload.get("service_endpoints") or {}
    normalized_endpoints: dict[str, list[tuple[str, int]]] = {}
    for key, values in service_endpoints.items():
        normalized_endpoints[str(key)] = [
            (str(item[0]), int(item[1])) for item in values
        ]
    payload["service_endpoints"] = normalized_endpoints
    discovery_meta = dict(payload.get("discovery_meta") or {})
    discovery_meta.setdefault("discovery_origin", DISCOVERY_ORIGIN_WEBSHELL)
    discovery_meta["planned_only"] = False
    payload["discovery_meta"] = discovery_meta
    payload["discovery_enabled"] = True
    return payload


def get_cached_remote_discovery(
    scenario_params: dict[str, Any],
    target_net: str,
) -> dict[str, Any] | None:
    cached = scenario_params.get(REMOTE_DISCOVERY_CACHE_KEY)
    if isinstance(cached, dict) and str(cached.get("target_net") or "") == target_net:
        return cached
    return None


def cache_remote_discovery(
    scenario_params: dict[str, Any],
    targets: dict[str, Any],
) -> None:
    scenario_params[REMOTE_DISCOVERY_CACHE_KEY] = targets


def run_webshell_host_discovery(
    provider: Any,
    ctx: Any,
    request: Any,
    probe_specs: list[dict[str, Any]],
) -> dict[str, Any]:
    """Execute or reuse webshell-origin discovery and return TargetSet-compatible dict."""
    params = dict(request.scenario_params)
    target_net = str(request.target_net or "")
    max_hosts = int(params.get("max_hosts", DISCOVERY_MAX_HOSTS))
    cached = get_cached_remote_discovery(ctx.config.scenario_params, target_net)
    if cached is not None:
        return cached

    if request.dry_run:
        targets = build_mock_discovery_targets(target_net, params, max_hosts=max_hosts)
        cache_remote_discovery(ctx.config.scenario_params, targets)
        return targets

    command = build_remote_discovery_command(target_net, max_hosts=max_hosts)
    raw = provider.run_remote_command(
        command,
        timeout_seconds=max(60.0, max_hosts * 2.0),
    )
    try:
        targets = parse_remote_discovery_output(raw)
    except (ValueError, json.JSONDecodeError):
        targets = discover_target_net(target_net, max_hosts=max_hosts)
        targets["discovery_meta"] = dict(targets.get("discovery_meta") or {})
        targets["discovery_meta"]["discovery_origin"] = DISCOVERY_ORIGIN_WEBSHELL
        targets["discovery_meta"]["planned_only"] = False
        targets["discovery_meta"]["fallback"] = "local_discover_target_net"

    cache_remote_discovery(ctx.config.scenario_params, targets)
    return targets


def probe_commands_for_specs(
    specs: list[dict[str, Any]],
    *,
    timeout: float = 0.5,
    mock: bool = False,
) -> list[str]:
    if mock:
        return [mock_noop_command() for _ in specs]
    return [tcp_probe_command(spec["host"], spec["port"], timeout=timeout) for spec in specs]
