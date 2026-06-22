"""Webshell-origin discovery planning — command dispatch only, no DSP-side probes."""

from __future__ import annotations

from typing import Any, Callable

from dsp.discovery.legacy_bash import (
    DISCOVERY_MAX_HOSTS,
    FAST_SAFE_DISCOVERY_PORTS,
)
from dsp.execution.remote.command.models import (
    COMMAND_DELIVERY_INLINE_BASE64_EXEC,
    DISCOVERY_METHOD_COMMAND_INLINE_BASE64_EXEC,
    DISCOVERY_ORIGIN_WEBSHELL,
)
from dsp.execution.remote.command.shell import (
    PROBE_OPEN_MARKER,
    discovery_probe_output_path,
    mock_noop_command,
    tcp_probe_batch_discovery_command,
    tcp_probe_command,
)
from dsp.execution.webshell.event_sync.bundle_content import (
    content_preview,
    normalize_webshell_command_output,
)
from dsp.execution.remote.command.discovery_plans import (
    DISCOVERY_PORTS,
    PORT_CAPABILITY_MAP,
    expand_target_net_hosts,
)

REMOTE_DISCOVERY_CACHE_KEY = "_remote_discovery_targets"
DISCOVERY_SCAN_MAX_HOSTS_KEY = "_discovery_scan_max_hosts"
DEFAULT_REMOTE_DISCOVERY_TIMEOUT = 0.5
DISCOVERY_PROBE_BATCH_SIZE = 32
DISCOVERY_PROBE_WORKERS = 32
# Keep each webshell command under typical JSP max_execution_time (~50s).
DISCOVERY_PROBE_BATCH_COMMAND_TIMEOUT_CAP = 45.0


def resolve_discovery_scan_max_hosts(
    scenario_params: dict[str, Any],
    target_net: str,
) -> int:
    """Hosts to probe during webshell-origin discovery (independent of follow-up caps)."""
    configured = scenario_params.get(DISCOVERY_SCAN_MAX_HOSTS_KEY)
    cap = int(configured) if configured is not None else DISCOVERY_MAX_HOSTS
    return len(expand_target_net_hosts(target_net.strip(), max_hosts=cap))


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
    require real live discovery output.
    """
    port_list = ports or DISCOVERY_PORTS
    candidates = expand_target_net_hosts(target_net, max_hosts=max_hosts)

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


def _chunk_probe_specs(
    probe_specs: list[dict[str, Any]],
    batch_size: int,
) -> list[list[dict[str, Any]]]:
    size = max(1, int(batch_size))
    return [
        probe_specs[index : index + size]
        for index in range(0, len(probe_specs), size)
    ]


def _probe_batch_command_timeout(probe_count: int, *, per_probe_timeout: float) -> float:
    workers = max(1, min(DISCOVERY_PROBE_WORKERS, probe_count))
    estimated = (probe_count / workers) * (per_probe_timeout + 0.15) + 10.0
    return min(
        DISCOVERY_PROBE_BATCH_COMMAND_TIMEOUT_CAP,
        max(15.0, estimated),
    )


def parse_tcp_probe_discovery_output(raw: bytes) -> set[tuple[str, int]]:
    """Collect host:port pairs marked open by batched or single probe commands."""
    open_endpoints: set[tuple[str, int]] = set()
    for line in normalize_webshell_command_output(raw).splitlines():
        stripped = line.strip()
        if PROBE_OPEN_MARKER not in stripped:
            continue
        marker_index = stripped.find(PROBE_OPEN_MARKER)
        payload = stripped[marker_index + len(PROBE_OPEN_MARKER) :].strip()
        if not payload:
            continue
        host, _, port_text = payload.rpartition(":")
        if not host or not port_text.isdigit():
            continue
        open_endpoints.add((host, int(port_text)))
    return open_endpoints


def run_discovery_from_tcp_probes(
    provider: Any,
    target_net: str,
    probe_specs: list[dict[str, Any]],
    *,
    run_id: str = "",
    timeout: float = DEFAULT_REMOTE_DISCOVERY_TIMEOUT,
    batch_size: int = DISCOVERY_PROBE_BATCH_SIZE,
    on_probe_batch: Callable[[list[dict[str, Any]], set[tuple[str, int]], bytes], None]
    | None = None,
) -> dict[str, Any]:
    """Webshell-origin discovery via batched python3 -c socket probes (command-only)."""
    open_endpoints: set[tuple[str, int]] = set()
    batches = _chunk_probe_specs(probe_specs, batch_size)
    per_probe_timeout = max(0.1, float(timeout))
    first_batch_preview: str | None = None
    timed_out_batches = 0

    for batch_index, batch in enumerate(batches):
        probes = [(str(spec["host"]), int(spec["port"])) for spec in batch]
        output_path = discovery_probe_output_path(run_id, batch_index)
        command_timeout = _probe_batch_command_timeout(
            len(probes),
            per_probe_timeout=per_probe_timeout,
        )
        raw = provider.run_remote_command(
            tcp_probe_batch_discovery_command(
                probes,
                timeout=per_probe_timeout,
                output_path=output_path,
                workers=DISCOVERY_PROBE_WORKERS,
            ),
            timeout_seconds=command_timeout,
        )
        if batch_index == 0 and first_batch_preview is None:
            first_batch_preview = content_preview(raw)
        text = normalize_webshell_command_output(raw)
        if "command timeout" in text.lower():
            timed_out_batches += 1
            if on_probe_batch is not None:
                on_probe_batch(batch, set(), raw)
            continue
        batch_open = parse_tcp_probe_discovery_output(raw)
        open_endpoints.update(batch_open)
        if on_probe_batch is not None:
            on_probe_batch(batch, batch_open, raw)

    candidates = sorted(
        {str(spec["host"]) for spec in probe_specs},
        key=lambda h: tuple(int(p) for p in h.split(".")),
    )
    targets = build_discovery_targets_from_open_endpoints(
        target_net,
        probe_specs,
        open_endpoints,
        candidate_hosts=candidates,
    )
    discovery_meta = dict(targets.get("discovery_meta") or {})
    discovery_meta["discovery_method"] = DISCOVERY_METHOD_COMMAND_INLINE_BASE64_EXEC
    discovery_meta["command_delivery"] = COMMAND_DELIVERY_INLINE_BASE64_EXEC
    discovery_meta["runner_upload"] = False
    discovery_meta["probe_batches"] = len(batches)
    discovery_meta["probes_executed"] = len(probe_specs)
    discovery_meta["open_endpoints"] = len(open_endpoints)
    if timed_out_batches:
        discovery_meta["timed_out_batches"] = timed_out_batches
    if not open_endpoints and first_batch_preview is not None:
        discovery_meta["first_batch_output_preview"] = first_batch_preview
    targets["discovery_meta"] = discovery_meta
    return targets


def _emit_webshell_discovery_activity(ctx: Any, scenario_id: str, targets: dict[str, Any]) -> None:
    from dsp.engine.scenario_engine import emit_activity

    meta = dict(targets.get("discovery_meta") or {})
    emit_activity(
        ctx,
        scenario_id,
        kind="discovery",
        discovery_method=meta.get("discovery_method"),
        command_delivery=meta.get("command_delivery"),
        runner_upload=meta.get("runner_upload"),
        alive_hosts=len(meta.get("alive_hosts") or []),
        open_endpoints=meta.get("open_endpoints", 0),
        output_preview=meta.get("first_batch_output_preview"),
        probe_batches=meta.get("probe_batches"),
    )
    emit_webshell_discovery_progress(ctx, targets=targets)


def emit_webshell_discovery_progress(ctx: Any, *, targets: dict[str, Any]) -> None:
    """Refresh console discovery summary and attack target groups after remote probe."""
    from dsp.engine.host_selection import cache_http_endpoint_selection
    from dsp.engine.scenario_engine import emit_progress
    from dsp.execution.remote.command.planner import targets_dict_to_target_set
    from dsp.runner.target_selection import resolve_webshell_discovered_targets_by_protocol
    from dsp.runtime.scenario_plan import WEBSHELL_EXECUTION_KEY

    meta = dict(targets.get("discovery_meta") or {})
    alive = list(meta.get("alive_hosts") or targets.get("hosts") or [])
    open_count = int(meta.get("open_endpoints", 0))
    emit_progress(
        ctx,
        "discovery_completed",
        {
            "hosts_found": len(alive),
            "probed_hosts": meta.get("probed_hosts", 0),
            "alive_hosts": alive,
            "open_endpoints": open_count,
            "service_hosts": meta.get("service_hosts") or {},
            "discovery_method": meta.get("discovery_method"),
            "command_delivery": meta.get("command_delivery"),
            "runner_upload": meta.get("runner_upload"),
        },
    )
    scenario_ids = list(getattr(ctx, "scenario_ids", None) or [])
    target_set = targets_dict_to_target_set(targets)
    if scenario_ids:
        cache_http_endpoint_selection(
            ctx.config.scenario_params,
            scenario_ids=scenario_ids,
            targets=target_set,
            dry_run=bool(getattr(ctx, "dry_run", False)),
            webshell_mode=True,
        )
    groups = (
        resolve_webshell_discovered_targets_by_protocol(
            scenario_ids,
            target_set,
            ctx.config.scenario_params,
        )
        if scenario_ids
        else {}
    )
    payload: dict[str, Any] = {
        "groups": groups,
        "alive_hosts": alive,
        "open_endpoints": open_count,
    }
    ws_ctx = ctx.config.scenario_params.get(WEBSHELL_EXECUTION_KEY)
    if isinstance(ws_ctx, dict):
        payload["execution_host"] = {
            "host": ws_ctx.get("execution_host"),
            "port": ws_ctx.get("execution_port"),
            "path": ws_ctx.get("execution_path", "/"),
        }
        payload["webshell_url"] = ws_ctx.get("webshell_url")
        payload["attack_target_net"] = str(targets.get("target_net") or ctx.target_net)
    emit_progress(ctx, "targets_selected", payload)


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
    *,
    on_probe_batch: Callable[[list[dict[str, Any]], set[tuple[str, int]], bytes], None]
    | None = None,
) -> dict[str, Any]:
    """Execute or reuse webshell-origin discovery and return TargetSet-compatible dict."""
    params = dict(request.scenario_params)
    target_net = str(request.target_net or "")
    discovery_max_hosts = resolve_discovery_scan_max_hosts(
        ctx.config.scenario_params,
        target_net,
    )
    cached = get_cached_remote_discovery(ctx.config.scenario_params, target_net)
    if cached is not None:
        ensure_webshell_http_selection_cache(ctx, cached, dry_run=request.dry_run)
        return cached

    if request.dry_run:
        targets = build_mock_discovery_targets(
            target_net,
            params,
            max_hosts=discovery_max_hosts,
        )
        cache_remote_discovery(ctx.config.scenario_params, targets)
        _emit_webshell_discovery_activity(
            ctx,
            str(getattr(request, "scenario_id", "") or ""),
            targets,
        )
        return targets

    if not probe_specs:
        probe_specs = build_discovery_probe_specs(
            target_net,
            max_hosts=discovery_max_hosts,
        )

    targets = run_discovery_from_tcp_probes(
        provider,
        target_net,
        probe_specs,
        run_id=str(getattr(request, "run_id", "") or ""),
        on_probe_batch=on_probe_batch,
    )
    _emit_webshell_discovery_activity(ctx, str(getattr(request, "scenario_id", "") or ""), targets)

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


TARGET_NET_DISCOVERY_SCENARIO_ID = "target_net_discovery"


def ensure_webshell_http_selection_cache(
    ctx: Any,
    targets: dict[str, Any],
    *,
    dry_run: bool,
) -> None:
    """Populate shared HTTP endpoint selection after webshell-origin discovery."""
    from dsp.engine.host_selection import cache_http_endpoint_selection
    from dsp.execution.remote.command.planner import targets_dict_to_target_set

    scenario_ids = list(getattr(ctx, "scenario_ids", None) or [])
    if not scenario_ids:
        return
    cache_http_endpoint_selection(
        ctx.config.scenario_params,
        scenario_ids=scenario_ids,
        targets=targets_dict_to_target_set(targets),
        dry_run=dry_run,
        webshell_mode=True,
    )


def prefetch_webshell_target_net_discovery(
    provider: Any,
    ctx: Any,
    *,
    run_id: str,
    target_net: str,
    dry_run: bool,
    execution_metadata: dict[str, Any],
    event_store: Any | None = None,
) -> dict[str, Any]:
    """
    Phase 3 prelude: probe ``target_net`` from the webshell host once.

    Expands the target CIDR and TCP-probes FAST_SAFE_DISCOVERY_PORTS on each
    candidate host to populate alive_hosts and service buckets for later
    port_sweep, service follow-ups, and dns_tunnel (run order in
    ``DISCOVERY_FIRST_SCENARIO_ORDER``).
    """
    from dsp.execution.remote.command.events import append_discovery_events
    from dsp.execution.remote.models import ScenarioExecutionRequest

    cached = get_cached_remote_discovery(ctx.config.scenario_params, target_net)
    if cached is not None:
        ensure_webshell_http_selection_cache(ctx, cached, dry_run=dry_run)
        return cached

    discovery_max_hosts = resolve_discovery_scan_max_hosts(
        ctx.config.scenario_params,
        target_net,
    )
    specs = build_discovery_probe_specs(target_net, max_hosts=discovery_max_hosts)
    request = ScenarioExecutionRequest(
        scenario_id=TARGET_NET_DISCOVERY_SCENARIO_ID,
        scenario_params={},
        execution_metadata=dict(execution_metadata),
        run_id=run_id,
        target_net=target_net,
        dry_run=dry_run,
    )

    dispatch_status = "mock" if dry_run else "completed"

    targets = run_webshell_host_discovery(
        provider,
        ctx,
        request,
        specs,
    )
    if get_cached_remote_discovery(ctx.config.scenario_params, target_net) is None:
        cache_remote_discovery(ctx.config.scenario_params, targets)
    if event_store is not None:
        append_discovery_events(
            event_store,
            run_id=run_id,
            scenario_id=TARGET_NET_DISCOVERY_SCENARIO_ID,
            target_net=target_net,
            probe_specs=specs,
            dispatch_status=dispatch_status,
            discovery_result=targets.get("discovery_meta"),
            batch_results=None,
        )
    return targets
