#!/usr/bin/env python3
"""Self-contained remote scenario runner — no DSP package required on webshell host."""

from __future__ import annotations

import base64
import json
import os
import shlex
import shutil
import socket
import subprocess
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _command_available(name: str) -> bool:
    return shutil.which(name) is not None


class EventLog:
    def __init__(
        self,
        *,
        run_id: str,
        scenario_id: str,
        scenario_version: str,
        schema_version: str,
        source: str = "remote",
    ) -> None:
        self.run_id = run_id
        self.scenario_id = scenario_id
        self.scenario_version = scenario_version
        self.schema_version = schema_version
        self.source = source
        self.events: list[dict[str, Any]] = []

    def append(
        self,
        *,
        event: str,
        status: str,
        stage: str = "executor",
        target: str = "",
        artifact: str = "",
        evidence: dict[str, Any] | None = None,
    ) -> None:
        self.events.append(
            {
                "run_id": self.run_id,
                "scenario_id": self.scenario_id,
                "timestamp": _utcnow(),
                "stage": stage,
                "event": event,
                "status": status,
                "target": target,
                "artifact": artifact,
                "evidence": dict(evidence or {}),
                "source": self.source,
                "tags": [],
            }
        )

    def write_bundle(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        metadata = {
            "_bundle_metadata": True,
            "run_id": self.run_id,
            "scenario_id": self.scenario_id,
            "scenario_version": self.scenario_version,
            "generated_at": _utcnow(),
            "event_count": len(self.events),
            "schema_version": self.schema_version,
        }
        lines = [json.dumps(metadata, separators=(",", ":"))]
        lines.extend(json.dumps(record, separators=(",", ":")) for record in self.events)
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    def write_traffic_summary(self, path: Path, *, target_net: str | None) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        summary = {
            "run_id": self.run_id,
            "scenario_id": self.scenario_id,
            "target_net": target_net,
            "event_count": len(self.events),
            "events": [record["event"] for record in self.events],
        }
        path.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")


def _required_commands(manifest: dict[str, Any]) -> tuple[list[str], list[str]]:
    scenario_id = manifest["scenario_id"]
    required = ["python3"]
    any_of: list[str] = []
    if scenario_id in {"http_followup", "sql_injection"}:
        required.append("curl")
    if scenario_id == "ssh_failure":
        any_of = ["ssh", "nc"]
    return required, any_of


def _check_capabilities(manifest: dict[str, Any]) -> list[str]:
    required, any_of = _required_commands(manifest)
    missing = [cmd for cmd in required if not _command_available(cmd)]
    if any_of and not any(_command_available(cmd) for cmd in any_of):
        missing.append("|".join(any_of))
    return missing


def _write_skip(log: EventLog, manifest: dict[str, Any], reason: str, missing: list[str]) -> None:
    log.append(
        event=f"{manifest['scenario_id']}_skipped",
        status="info",
        evidence={
            "reason": reason,
            "missing_commands": missing,
            "remote_execution_mode": "bundle",
        },
    )


def _tcp_probe(host: str, port: int, timeout: float) -> tuple[bool, str]:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True, "connection_opened"
    except ConnectionRefusedError:
        return False, "connection_refused"
    except TimeoutError:
        return False, "timeout"
    except OSError as exc:
        message = str(exc).lower()
        if "timed out" in message:
            return False, "timeout"
        if "refused" in message:
            return False, "connection_refused"
        return False, "error"


def _run_port_sweep(log: EventLog, plan: dict[str, Any]) -> None:
    probes = plan.get("probes") or []
    timeout = float(plan.get("timeout", 3.0))
    mode = plan.get("mode", "live")
    concurrency = max(1, int(plan.get("concurrency", 32)))
    first_host = probes[0]["host"] if probes else ""
    log.append(
        event="port_sweep_started",
        status="info",
        target=first_host,
        artifact="port_sweep_session",
        evidence={
            "planned_probes": len(probes),
            "mode": mode,
            "timeout": timeout,
            "concurrency": concurrency,
        },
    )
    success = 0
    failure = 0

    def _handle_probe(index: int, probe: dict[str, Any]) -> tuple[int, dict[str, Any], bool, str]:
        host = probe["host"]
        port = int(probe["port"])
        artifact = probe.get("artifact") or f"{host}:{port}"
        if mode == "mock":
            opened, outcome = False, "connection_refused"
        else:
            opened, outcome = _tcp_probe(host, port, timeout)
        return index, probe, opened, outcome

    from concurrent.futures import ThreadPoolExecutor, as_completed

    worker_count = min(concurrency, len(probes)) if probes else 1
    with ThreadPoolExecutor(max_workers=worker_count) as pool:
        futures = [
            pool.submit(_handle_probe, index, probe)
            for index, probe in enumerate(probes, start=1)
        ]
        for future in as_completed(futures):
            index, probe, opened, outcome = future.result()
            host = probe["host"]
            port = int(probe["port"])
            artifact = probe.get("artifact") or f"{host}:{port}"
            log.append(
                event="port_probe_sent",
                status="sent",
                target=host,
                artifact=artifact,
                evidence={"seq": index, "host": host, "port": port},
            )
            if opened:
                success += 1
                log.append(
                    event="port_connection_opened",
                    status="sent",
                    target=host,
                    artifact=artifact,
                    evidence={"host": host, "port": port, "outcome": outcome},
                )
            else:
                failure += 1
                log.append(
                    event="port_connection_failed",
                    status=outcome,
                    target=host,
                    artifact=artifact,
                    evidence={"host": host, "port": port, "outcome": outcome},
                )
    log.append(
        event="port_sweep_completed",
        status="info",
        target=first_host,
        artifact="port_sweep_session",
        evidence={
            "probe_count": len(probes),
            "connection_success_count": success,
            "connection_failure_count": failure,
        },
    )


def _run_dns_tunnel(log: EventLog, plan: dict[str, Any]) -> None:
    queries = plan.get("queries") or []
    timeout = float(plan.get("timeout", 0.05))
    mode = plan.get("mode", "live")
    domain = plan.get("domain", "dns-tunnel.com")
    session_id = uuid.uuid4().hex[:6]
    first_target = queries[0]["target"] if queries else ""
    log.append(
        event="dns_tunnel_started",
        status="info",
        target=first_target,
        evidence={"session_id": session_id, "domain": domain, "planned_chunks": len(queries)},
    )
    sent = 0
    for item in queries:
        target = item["target"]
        fqdn = item["fqdn"]
        log.append(
            event="dns_tunnel_chunk_created",
            status="info",
            target=target,
            artifact=fqdn,
            evidence={"seq": item["seq"], "fqdn": fqdn, "domain": domain},
        )
        if mode != "mock":
            try:
                payload = b"\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
                label = fqdn.split(".", 1)[0]
                for part in label.split("."):
                    payload += bytes([len(part)]) + part.encode("ascii")
                payload += b"\x00\x00\x01\x00\x01"
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                    sock.settimeout(timeout)
                    sock.sendto(payload, (target, 53))
            except OSError:
                pass
        log.append(
            event="dns_tunnel_query_sent",
            status="sent",
            target=target,
            artifact=fqdn,
            evidence={"fqdn": fqdn, "seq": item["seq"]},
        )
        sent += 1
    log.append(
        event="dns_tunnel_completed",
        status="info",
        target=first_target,
        evidence={"queries_sent": sent, "session_id": session_id},
    )


def _curl_request(url: str, method: str, timeout: float, user_agent: str, body: bytes | None, content_type: str | None) -> tuple[int | None, str]:
    cmd = [
        "curl",
        "-sS",
        "-o",
        "/dev/null",
        "-w",
        "%{http_code}",
        "--max-time",
        str(max(1, int(timeout))),
        "-A",
        user_agent,
        "-X",
        method,
    ]
    if body is not None:
        cmd.extend(["-H", f"Content-Type: {content_type or 'application/octet-stream'}", "--data-binary", "@-"])
    cmd.append(url)
    try:
        completed = subprocess.run(
            cmd,
            input=body,
            capture_output=True,
            timeout=timeout + 2,
            check=False,
        )
        code_text = (completed.stdout or b"").decode("utf-8", errors="replace").strip()
        return int(code_text) if code_text.isdigit() else None, "sent"
    except (subprocess.TimeoutExpired, OSError):
        return None, "timeout"


def _run_http_followup(log: EventLog, plan: dict[str, Any]) -> None:
    if plan.get("mode") == "skip":
        _write_skip(log, {"scenario_id": "http_followup"}, plan.get("reason", "no_http_endpoints"), [])
        return
    requests = plan.get("requests") or []
    timeout = float(plan.get("timeout", 10.0))
    mode = plan.get("mode", "live")
    log.append(
        event="http_followup_started",
        status="info",
        evidence={"requests_planned": len(requests), "mode": mode},
    )
    sent = 0
    for index, item in enumerate(requests, start=1):
        url = item["url"]
        method = item.get("method", "GET")
        user_agent = item.get("user_agent", "Mozilla/5.0")
        log.append(
            event="http_request_created",
            status="info",
            target=url,
            evidence={"seq": index, "url": url, "method": method},
        )
        if mode == "mock":
            status_code = 404
            outcome = "sent"
        else:
            status_code, outcome = _curl_request(url, method, timeout, user_agent, None, None)
        log.append(
            event="http_request_sent",
            status="sent",
            target=url,
            evidence={"url": url, "method": method, "status_code": status_code},
        )
        if status_code is None or status_code >= 400:
            log.append(
                event="http_request_error",
                status=outcome,
                target=url,
                evidence={"url": url, "status_code": status_code},
            )
        sent += 1
    log.append(
        event="http_followup_completed",
        status="info",
        evidence={"requests_sent": sent},
    )


def _run_sql_injection(log: EventLog, plan: dict[str, Any]) -> None:
    if plan.get("mode") == "skip":
        _write_skip(log, {"scenario_id": "sql_injection"}, plan.get("reason", "no_http_endpoints"), [])
        return
    requests = plan.get("requests") or []
    timeout = float(plan.get("timeout", 10.0))
    mode = plan.get("mode", "live")
    log.append(
        event="sql_injection_started",
        status="info",
        evidence={"requests_planned": len(requests), "mode": mode},
    )
    sent = 0
    for index, item in enumerate(requests, start=1):
        url = item["url"]
        method = item.get("method", "GET")
        body = base64.b64decode(item["body_b64"]) if item.get("body_b64") else None
        content_type = item.get("content_type")
        log.append(
            event="sql_payload_generated",
            status="info",
            target=url,
            evidence={
                "seq": index,
                "payload_category": item.get("payload_category"),
                "parameter": item.get("parameter"),
            },
        )
        if mode == "mock":
            status_code = 404
        else:
            status_code, _ = _curl_request(url, method, timeout, "Mozilla/5.0", body, content_type)
        log.append(
            event="sql_request_sent",
            status="sent",
            target=url,
            evidence={"url": url, "method": method, "status_code": status_code},
        )
        sent += 1
    log.append(
        event="sql_injection_completed",
        status="info",
        evidence={"requests_sent": sent},
    )


def _run_ssh_attempt(host: str, port: int, username: str, timeout: float) -> str:
    if _command_available("ssh"):
        cmd = [
            "ssh",
            "-o",
            "BatchMode=yes",
            "-o",
            f"ConnectTimeout={max(1, int(timeout))}",
            "-o",
            "StrictHostKeyChecking=no",
            "-p",
            str(port),
            f"{username}@{host}",
            "exit",
        ]
        try:
            completed = subprocess.run(cmd, capture_output=True, timeout=timeout + 2, check=False)
            if completed.returncode == 0:
                return "auth_success"
            stderr = (completed.stderr or b"").decode("utf-8", errors="replace").lower()
            if "permission denied" in stderr or "authentication failed" in stderr:
                return "auth_failed"
            return "connection_failed"
        except (subprocess.TimeoutExpired, OSError):
            return "timeout"
    if _command_available("nc"):
        probe = f"exit\n"
        try:
            completed = subprocess.run(
                ["nc", "-w", str(max(1, int(timeout))), host, str(port)],
                input=probe.encode("utf-8"),
                capture_output=True,
                timeout=timeout + 2,
                check=False,
            )
            return "connection_failed" if completed.returncode != 0 else "auth_failed"
        except (subprocess.TimeoutExpired, OSError):
            return "timeout"
    return "missing_tool"


def _run_ssh_failure(log: EventLog, plan: dict[str, Any]) -> None:
    if plan.get("mode") == "skip":
        _write_skip(log, {"scenario_id": "ssh_failure"}, plan.get("reason", "no_ssh_hosts"), [])
        return
    attempts = plan.get("attempts") or []
    timeout = float(plan.get("timeout", 5.0))
    mode = plan.get("mode", "live")
    first_host = attempts[0]["host"] if attempts else ""
    log.append(
        event="ssh_failure_started",
        status="info",
        target=first_host,
        evidence={"auth_attempts_planned": len(attempts), "mode": mode},
    )
    failure_count = 0
    for index, item in enumerate(attempts, start=1):
        host = item["host"]
        port = int(item["port"])
        username = item["username"]
        artifact = f"{username}@{host}:{port}"
        log.append(
            event="ssh_auth_attempt",
            status="sent",
            target=host,
            artifact=artifact,
            evidence={"seq": index, "username": username, "port": port},
        )
        if mode == "mock":
            outcome = "auth_failed"
        else:
            outcome = _run_ssh_attempt(host, port, username, timeout)
        if outcome != "auth_success":
            failure_count += 1
        log.append(
            event="ssh_auth_outcome",
            status=outcome,
            target=host,
            artifact=artifact,
            evidence={"username": username, "outcome": outcome},
        )
    log.append(
        event="ssh_failure_completed",
        status="info",
        target=first_host,
        evidence={"auth_attempts": len(attempts), "auth_failure_count": failure_count},
    )


def _dispatch(log: EventLog, manifest: dict[str, Any]) -> None:
    plan = manifest.get("plan") or {}
    plan_type = plan.get("type")
    if manifest.get("skipped"):
        _write_skip(
            log,
            manifest,
            str(manifest.get("skip_reason") or "skipped"),
            list(manifest.get("missing_commands") or []),
        )
        return
    if plan_type == "skip":
        _write_skip(log, manifest, str(plan.get("reason") or "skipped"), [])
        return
    handlers = {
        "port_sweep": _run_port_sweep,
        "dns_tunnel": _run_dns_tunnel,
        "http_followup": _run_http_followup,
        "sql_injection": _run_sql_injection,
        "ssh_failure": _run_ssh_failure,
    }
    handler = handlers.get(plan_type)
    if handler is None:
        _write_skip(log, manifest, f"unsupported_plan:{plan_type}", [])
        return
    handler(log, plan)


def main() -> int:
    work_dir = Path(os.environ.get("DSP_BUNDLE_DIR", Path(__file__).resolve().parent))
    manifest_path = work_dir / "manifest.json"
    if not manifest_path.is_file():
        print(json.dumps({"error": "manifest.json not found", "exit_code": 1}), file=sys.stderr)
        return 1
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    paths = manifest.get("paths") or {}
    bundle_path = work_dir / "events.jsonl"
    summary_path = work_dir / "traffic_summary.json"
    # Preserve remote convention for diagnostics only.
    _ = paths.get("bundle")

    missing = _check_capabilities(manifest)
    if missing and not manifest.get("skipped"):
        manifest = dict(manifest)
        manifest["skipped"] = True
        manifest["skip_reason"] = f"missing_remote_commands:{','.join(missing)}"
        manifest["missing_commands"] = missing

    log = EventLog(
        run_id=str(manifest["run_id"]),
        scenario_id=str(manifest["scenario_id"]),
        scenario_version=str(manifest.get("scenario_version") or "1.0.0"),
        schema_version=str(manifest.get("schema_version") or "1.0.0"),
    )
    _dispatch(log, manifest)
    log.write_bundle(bundle_path)
    log.write_traffic_summary(summary_path, target_net=manifest.get("target_net"))
    print(json.dumps({"exit_code": 0, "bundle": str(bundle_path), "events": len(log.events)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
