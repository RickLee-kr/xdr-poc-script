"""Webshell-origin discovery planning — command dispatch only, no DSP-side probes."""

from __future__ import annotations

import base64
import json
import shlex
from pathlib import Path
from typing import Any, Callable

from dsp.discovery.legacy_bash import (
    DISCOVERY_MAX_HOSTS,
    FAST_SAFE_DISCOVERY_PORTS,
)
from dsp.execution.remote.command.models import DISCOVERY_ORIGIN_WEBSHELL
from dsp.execution.remote.command.shell import (
    PROBE_OPEN_MARKER,
    discovery_probe_output_path,
    mock_noop_command,
    tcp_probe_batch_discovery_command,
    tcp_probe_command,
    wrap_remote_shell_command,
)
from dsp.execution.webshell.event_sync.bundle_content import (
    content_preview,
    normalize_webshell_command_output,
)
from dsp.execution.remote.bundle.assets.remote_discovery import (
    DISCOVERY_PORTS,
    PORT_CAPABILITY_MAP,
    expand_target_net_hosts,
)

REMOTE_DISCOVERY_CACHE_KEY = "_remote_discovery_targets"
DISCOVERY_SCAN_MAX_HOSTS_KEY = "_discovery_scan_max_hosts"
DEFAULT_REMOTE_DISCOVERY_TIMEOUT = 0.5
DISCOVERY_PROBE_BATCH_SIZE = 32
DISCOVERY_RUNNER_NAME = "discover_runner.py"
DISCOVERY_RUNNER_ASSET = (
    Path(__file__).resolve().parent / "assets" / "webshell_discovery_runner.py"
)
_BASE64_UPLOAD_CHUNK_CHARS = 2000


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
    """Webshell-origin discovery via batched sh-wrapped TCP probes with file capture."""
    open_endpoints: set[tuple[str, int]] = set()
    batches = _chunk_probe_specs(probe_specs, batch_size)
    per_probe_timeout = max(0.1, float(timeout))
    first_batch_preview: str | None = None

    for batch_index, batch in enumerate(batches):
        probes = [(str(spec["host"]), int(spec["port"])) for spec in batch]
        output_path = discovery_probe_output_path(run_id, batch_index)
        command_timeout = max(
            45.0,
            len(probes) * (per_probe_timeout + 0.15) / max(1, min(32, len(probes))),
        )
        raw = provider.run_remote_command(
            tcp_probe_batch_discovery_command(
                probes,
                timeout=per_probe_timeout,
                output_path=output_path,
            ),
            timeout_seconds=command_timeout,
        )
        if batch_index == 0 and first_batch_preview is None:
            first_batch_preview = content_preview(raw)
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
    discovery_meta["discovery_method"] = "tcp_probe_batch_sh"
    discovery_meta["probe_batches"] = len(batches)
    discovery_meta["probes_executed"] = len(probe_specs)
    discovery_meta["open_endpoints"] = len(open_endpoints)
    if not open_endpoints and first_batch_preview is not None:
        discovery_meta["first_batch_output_preview"] = first_batch_preview
    targets["discovery_meta"] = discovery_meta
    return targets


def _resolve_remote_discovery_dir(request: Any) -> tuple[str, str, str]:
    metadata = dict(getattr(request, "execution_metadata", {}) or {})
    work_dir = str(metadata.get("remote_work_dir") or "/tmp/dsp").rstrip("/")
    run_id = str(getattr(request, "run_id", "") or "run")
    remote_dir = f"{work_dir}/{run_id}"
    remote_script = f"{remote_dir}/{DISCOVERY_RUNNER_NAME}"
    remote_output = f"{remote_dir}/discovery_out.json"
    return remote_dir, remote_script, remote_output


def parse_deployed_discovery_output(raw: bytes) -> dict[str, Any]:
    """Parse JSON discovery payload written by the remote discover_runner script."""
    text = normalize_webshell_command_output(raw)
    start = text.find("{")
    end = text.rfind("}")
    if start < 0 or end <= start:
        raise ValueError(
            f"deployed discovery output did not contain JSON (preview={content_preview(raw)})"
        )
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
    discovery_meta["discovery_method"] = "deployed_runner"
    payload["discovery_meta"] = discovery_meta
    payload["discovery_enabled"] = True
    return payload


def _upload_discovery_runner_asset(provider: Any, remote_script: str) -> str:
    """Stage discover_runner.py on the webshell host (multipart, pipe, or python base64)."""
    from dsp.execution.remote.bundle.upload import upload_remote_file_verified
    from dsp.execution.remote.exceptions import RemoteArtifactUploadError

    try:
        result = upload_remote_file_verified(provider, DISCOVERY_RUNNER_ASSET, remote_script)
        return result.method
    except RemoteArtifactUploadError:
        pass

    return _upload_discovery_runner_via_python_base64(provider, remote_script)


def _upload_discovery_runner_via_python_base64(provider: Any, remote_script: str) -> str:
    payload = DISCOVERY_RUNNER_ASSET.read_bytes()
    encoded = base64.b64encode(payload).decode("ascii")
    provider.run_remote_command(
        wrap_remote_shell_command(f": > {shlex.quote(remote_script)}"),
        timeout_seconds=30.0,
    )
    for offset in range(0, len(encoded), _BASE64_UPLOAD_CHUNK_CHARS):
        chunk = encoded[offset : offset + _BASE64_UPLOAD_CHUNK_CHARS]
        write_script = (
            "import base64;"
            f"p={remote_script!r};d={chunk!r};"
            "open(p,'ab').write(base64.b64decode(d.encode()))"
        )
        provider.run_remote_command(
            wrap_remote_shell_command(f"python3 -c {shlex.quote(write_script)}"),
            timeout_seconds=60.0,
        )

    expected_size = DISCOVERY_RUNNER_ASSET.stat().st_size
    size_raw = provider.run_remote_command(
        wrap_remote_shell_command(f"wc -c < {shlex.quote(remote_script)} 2>&1"),
        timeout_seconds=30.0,
    )
    size_text = normalize_webshell_command_output(size_raw).split()[0:1]
    if not size_text or not size_text[0].isdigit() or int(size_text[0]) < expected_size:
        raise ValueError(
            "discover_runner python base64 upload verification failed "
            f"(expected>={expected_size}, got={normalize_webshell_command_output(size_raw)!r})"
        )
    return "python_base64"


def _emit_webshell_discovery_activity(ctx: Any, scenario_id: str, targets: dict[str, Any]) -> None:
    from dsp.engine.scenario_engine import emit_activity

    meta = dict(targets.get("discovery_meta") or {})
    emit_activity(
        ctx,
        scenario_id,
        kind="discovery",
        discovery_method=meta.get("discovery_method"),
        alive_hosts=len(meta.get("alive_hosts") or []),
        open_endpoints=meta.get("open_endpoints", 0),
        deploy_error=meta.get("deploy_error"),
        output_preview=meta.get("output_preview"),
        upload_method=meta.get("upload_method"),
    )


def run_deployed_webshell_discovery(
    provider: Any,
    request: Any,
    target_net: str,
    discovery_max_hosts: int,
) -> dict[str, Any]:
    """Upload and execute the self-contained discovery runner on the webshell host."""
    remote_dir, remote_script, remote_output = _resolve_remote_discovery_dir(request)
    try:
        provider.run_remote_command(
            wrap_remote_shell_command(f"mkdir -p {shlex.quote(remote_dir)}"),
            timeout_seconds=30.0,
        )
        upload_method = _upload_discovery_runner_asset(provider, remote_script)

        run_command = (
            f"python3 {shlex.quote(remote_script)} "
            f"{shlex.quote(target_net)} {int(discovery_max_hosts)} "
            f"{shlex.quote(remote_output)} {DEFAULT_REMOTE_DISCOVERY_TIMEOUT}"
        )
        provider.run_remote_command(
            wrap_remote_shell_command(run_command),
            timeout_seconds=max(180.0, discovery_max_hosts * 2.0),
        )
        raw = provider.run_remote_command(
            wrap_remote_shell_command(f"cat {shlex.quote(remote_output)} 2>&1"),
            timeout_seconds=60.0,
        )
        targets = parse_deployed_discovery_output(raw)
        discovery_meta = dict(targets.get("discovery_meta") or {})
        discovery_meta["upload_method"] = upload_method
        targets["discovery_meta"] = discovery_meta
        return targets
    except (ValueError, json.JSONDecodeError) as exc:
        return _failed_deployed_discovery_targets(
            target_net,
            discovery_max_hosts=discovery_max_hosts,
            error=str(exc),
            output_preview=content_preview(raw) if "raw" in locals() else None,
            parse_failed=True,
        )
    except Exception as exc:
        return _failed_deployed_discovery_targets(
            target_net,
            discovery_max_hosts=discovery_max_hosts,
            error=str(exc),
        )


def _failed_deployed_discovery_targets(
    target_net: str,
    *,
    discovery_max_hosts: int,
    error: str,
    output_preview: str | None = None,
    parse_failed: bool = False,
) -> dict[str, Any]:
    service_hosts, service_endpoints = _empty_service_buckets()
    discovery_meta: dict[str, Any] = {
        "probed_hosts": discovery_max_hosts,
        "alive_hosts": [],
        "open_endpoints": 0,
        "service_hosts": service_hosts,
        "discovery_origin": DISCOVERY_ORIGIN_WEBSHELL,
        "planned_only": False,
        "discovery_method": "deployed_runner",
        "deploy_error": error,
    }
    if parse_failed:
        discovery_meta["parse_failed"] = True
    if output_preview is not None:
        discovery_meta["output_preview"] = output_preview
    return {
        "target_net": target_net,
        "hosts": [],
        "service_hosts": service_hosts,
        "service_endpoints": {
            key: list(value) for key, value in service_endpoints.items()
        },
        "discovery_enabled": True,
        "discovery_meta": discovery_meta,
    }



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
        return cached

    if request.dry_run:
        targets = build_mock_discovery_targets(
            target_net,
            params,
            max_hosts=discovery_max_hosts,
        )
        cache_remote_discovery(ctx.config.scenario_params, targets)
        return targets

    if not probe_specs:
        probe_specs = build_discovery_probe_specs(
            target_net,
            max_hosts=discovery_max_hosts,
        )

    targets = run_deployed_webshell_discovery(
        provider,
        request,
        target_net,
        discovery_max_hosts,
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
