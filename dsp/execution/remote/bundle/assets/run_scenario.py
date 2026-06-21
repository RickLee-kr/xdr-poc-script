#!/usr/bin/env python3
"""Self-contained remote scenario runner — no DSP package required on webshell host."""

from __future__ import annotations

import base64
import json
import os
import random
import shlex
import shutil
import socket
import struct
import subprocess
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    from remote_discovery import resolve_remote_discovery_plan
except ImportError:  # pragma: no cover - local unit tests without bundle layout
    resolve_remote_discovery_plan = None


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
        bundle_path: Path | None = None,
        status_writer: RemoteStatusWriter | None = None,
    ) -> None:
        self.run_id = run_id
        self.scenario_id = scenario_id
        self.scenario_version = scenario_version
        self.schema_version = schema_version
        self.source = source
        self.events: list[dict[str, Any]] = []
        self._bundle_path = bundle_path
        self._status_writer = status_writer

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
        self._flush_bundle()
        if self._status_writer is not None:
            self._status_writer.update(
                attempted={"events": len(self.events), "last_event": event},
            )

    def _flush_bundle(self) -> None:
        if self._bundle_path is not None:
            self.write_bundle(self._bundle_path)

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
        if self._status_writer is not None:
            self._status_writer.update(
                phase="summary_written",
                attempted={"events": len(self.events)},
            )


class RemoteStatusWriter:
    """Heartbeat file for remote bundle execution progress."""

    def __init__(
        self,
        path: Path,
        *,
        scenario_id: str,
        planned: dict[str, Any],
    ) -> None:
        self.path = path
        started_at = _utcnow()
        self._data: dict[str, Any] = {
            "phase": "starting",
            "scenario": scenario_id,
            "started_at": started_at,
            "last_update": started_at,
            "planned": planned,
            "attempted": {"events": 0},
            "error": None,
        }
        self.write()

    def update(self, **fields: Any) -> None:
        self._data["last_update"] = _utcnow()
        for key, value in fields.items():
            if key == "attempted" and isinstance(value, dict):
                attempted = dict(self._data.get("attempted") or {})
                attempted.update(value)
                self._data["attempted"] = attempted
            else:
                self._data[key] = value
        self.write()

    def write(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(self._data, indent=2) + "\n", encoding="utf-8")


def _required_commands(manifest: dict[str, Any]) -> tuple[list[str], list[str]]:
    scenario_id = manifest["scenario_id"]
    required = ["python3"]
    any_of: list[str] = []
    if scenario_id in {"http_followup", "sql_injection"}:
        required.append("curl")
    if scenario_id == "ssh_failure":
        any_of = ["ssh", "nc"]
    if scenario_id == "host_behavior_check":
        any_of = ["sh", "bash"]
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


def _encode_qname(fqdn: str) -> bytes:
    fqdn = fqdn.rstrip(".")
    encoded = b""
    for label in fqdn.split("."):
        if not label or len(label) > 63:
            raise ValueError(f"invalid DNS label: {label!r}")
        encoded += struct.pack("B", len(label)) + label.encode("ascii")
    return encoded + b"\x00"


def _build_dns_query_packet(fqdn: str, *, qtype: int = 1) -> tuple[int, bytes]:
    txn_id = struct.unpack("!H", uuid.uuid4().bytes[:2])[0]
    header = struct.pack("!HHHHHH", txn_id, 0x0100, 1, 0, 0, 0)
    question = _encode_qname(fqdn) + struct.pack("!HH", qtype, 1)
    return txn_id, header + question


def _send_dns_tunnel_query(target: str, fqdn: str, port: int = 53) -> dict[str, Any]:
    txn_id, packet = _build_dns_query_packet(fqdn)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.sendto(packet, (target, port))
    finally:
        sock.close()
    return {
        "query_id": f"{txn_id:04x}",
        "bytes_sent": len(packet),
        "port": port,
        "outcome": "sent",
    }


def _run_dns_tunnel(log: EventLog, plan: dict[str, Any]) -> None:
    queries = plan.get("queries") or []
    mode = plan.get("mode", "live")
    domain = plan.get("domain", "dns-tunnel.com")
    session_id = uuid.uuid4().hex[:6]
    first_target = queries[0]["target"] if queries else ""
    burst_schedule = list(plan.get("burst_schedule") or [len(queries)])
    log.append(
        event="dns_tunnel_started",
        status="info",
        target=first_target,
        evidence={
            "session_id": session_id,
            "domain": domain,
            "planned_chunks": len(queries),
            "burst_schedule": burst_schedule,
        },
    )
    sent = 0
    query_idx = 0
    for burst_idx, burst_size in enumerate(burst_schedule):
        for _ in range(burst_size):
            if query_idx >= len(queries):
                break
            item = queries[query_idx]
            query_idx += 1
            target = item["target"]
            fqdn = item["fqdn"]
            seq = item["seq"]
            log.append(
                event="dns_tunnel_chunk_created",
                status="info",
                target=target,
                artifact=fqdn,
                evidence={
                    "seq": seq,
                    "fqdn": fqdn,
                    "domain": domain,
                    "chunk_bytes": item.get("chunk_bytes"),
                    "label_length": item.get("label_length"),
                    "burst_index": burst_idx + 1,
                },
            )
            send_meta: dict[str, Any] = {"outcome": "mock"}
            if mode != "mock":
                try:
                    send_meta = _send_dns_tunnel_query(target, fqdn)
                except OSError as exc:
                    send_meta = {"outcome": "error", "message": str(exc)}

            query_evidence = {
                "session_id": session_id,
                "seq": seq,
                "fqdn": fqdn,
                "qtype": "A",
                "port": 53,
                "burst_index": burst_idx + 1,
                **send_meta,
            }
            log.append(
                event="dns_query_sent",
                status="sent",
                target=target,
                artifact=fqdn,
                evidence=dict(query_evidence),
            )
            log.append(
                event="dns_tunnel_query_sent",
                status="sent",
                target=target,
                artifact=fqdn,
                evidence=query_evidence,
            )
            sent += 1
        if burst_idx < len(burst_schedule) - 1 and query_idx < len(queries):
            time.sleep(random.uniform(0.5, 2.0))
    log.append(
        event="dns_tunnel_completed",
        status="info",
        target=first_target,
        evidence={
            "queries_sent": sent,
            "chunks_sent": sent,
            "session_id": session_id,
            "burst_schedule": burst_schedule,
        },
    )


def _curl_request(
    url: str,
    method: str,
    timeout: float,
    user_agent: str,
    body: bytes | None,
    content_type: str | None,
    *,
    connect_timeout: float | None = None,
) -> tuple[int | None, str]:
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
    if connect_timeout is not None:
        cmd.extend(["--connect-timeout", str(max(1, int(connect_timeout)))])
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
    connect_timeout = float(plan.get("connect_timeout", timeout))
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
            status_code, outcome = _curl_request(
                url,
                method,
                timeout,
                user_agent,
                None,
                None,
                connect_timeout=connect_timeout,
            )
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
    burst_plan = dict(plan.get("non_standard_port_burst") or {})
    burst_summary: dict[str, Any] = {"enabled": False}
    if burst_plan.get("enabled"):
        burst_summary = _run_non_standard_port_burst(
            log,
            burst_plan,
            timeout=timeout,
            connect_timeout=connect_timeout,
            mode=mode,
        )
    log.append(
        event="http_followup_completed",
        status="info",
        evidence={"requests_sent": sent, "non_standard_port_burst": burst_summary},
    )


def _run_non_standard_port_burst(
    log: EventLog,
    burst_plan: dict[str, Any],
    *,
    timeout: float,
    connect_timeout: float,
    mode: str,
) -> dict[str, Any]:
    requests = list(burst_plan.get("requests") or [])
    ports = list(burst_plan.get("ports") or [])
    targets = list(burst_plan.get("targets") or [])
    primary = str(targets[0]["host"]) if targets else ""
    log.append(
        event="non_standard_port_burst_started",
        status="info",
        target=primary,
        evidence={
            "attempts_planned": len(requests),
            "ports": ports,
            "targets": targets,
            "mode": mode,
        },
    )
    attempts = 0
    successes = 0
    failures = 0
    for item in requests:
        url = str(item["url"])
        method = str(item.get("method") or "GET")
        user_agent = str(item.get("user_agent") or "Mozilla/5.0")
        host = str(item.get("host") or "")
        port = int(item.get("port") or 0)
        base_evidence = {
            "seq": item.get("seq"),
            "host": host,
            "port": port,
            "url": url,
            "method": method,
            "user_agent": user_agent,
            "discovered": item.get("discovered"),
            "probe": item.get("probe"),
        }
        log.append(
            event="non_standard_port_connection_attempt",
            status="sent",
            target=host or url,
            evidence=dict(base_evidence),
        )
        attempts += 1
        if mode == "mock":
            status_code = 200 if int(item.get("seq") or 0) % 3 else 404
            outcome = "sent"
        else:
            status_code, outcome = _curl_request(
                url,
                method,
                timeout,
                user_agent,
                None,
                None,
                connect_timeout=connect_timeout,
            )
        result_evidence = dict(base_evidence)
        if status_code is not None:
            result_evidence["status_code"] = status_code
        result_evidence["outcome"] = outcome
        success = status_code is not None and int(status_code) < 500
        if success:
            successes += 1
            log.append(
                event="non_standard_port_connection_success",
                status="response",
                target=host or url,
                evidence=result_evidence,
            )
        else:
            failures += 1
            log.append(
                event="non_standard_port_connection_failure",
                status=outcome if outcome != "sent" else "error",
                target=host or url,
                evidence=result_evidence,
            )
    log.append(
        event="non_standard_port_burst_completed",
        status="info",
        target=primary,
        evidence={
            "enabled": True,
            "ports": ports,
            "targets": targets,
            "attempts": attempts,
            "success": successes,
            "failure": failures,
        },
    )
    return {
        "enabled": True,
        "ports": ports,
        "targets": targets,
        "attempts": attempts,
        "success": successes,
        "failure": failures,
    }


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


def _rare_rtsp_request(method: str, host: str, port: int, cseq: int) -> bytes:
    url = f"rtsp://{host}:{port}/"
    lines = [f"{method} {url} RTSP/1.0", f"CSeq: {cseq}", "User-Agent: DSP-RareProtocol-Lab/1.0"]
    if method == "DESCRIBE":
        lines.append("Accept: application/sdp")
    lines.extend(["", ""])
    return "\r\n".join(lines).encode("ascii")


def _rare_sip_request(method: str, host: str, port: int, transport: str) -> bytes:
    via = "UDP" if transport == "udp" else "TCP"
    lines = [
        f"{method} sip:{host}:{port} SIP/2.0",
        f"Via: SIP/2.0/{via} {host}:{port};branch=z9hG4bK-dsp-rare",
        "Max-Forwards: 70",
        f"To: <sip:probe@{host}>",
        "From: <sip:dsp-lab@local>;tag=dsp-rare",
        "Call-ID: dsp-rare-proto-activity@lab",
        f"CSeq: 1 {method}",
        f"Contact: <sip:dsp-lab@{host}:{port}>",
        "Content-Length: 0",
        "",
        "",
    ]
    return "\r\n".join(lines).encode("ascii")


def _rare_rtp_packet(seq: int) -> bytes:
    header = struct.pack("!BBHII", 0x80, 96, seq & 0xFFFF, 0, 0x44535001)
    return header + b"DSP-LAB"


def _rare_execute_probe(probe: dict[str, Any], timeout: float) -> tuple[bool, str, dict[str, Any]]:
    protocol = str(probe.get("protocol", "")).upper()
    host = str(probe["host"])
    port = int(probe["port"])
    transport = str(probe.get("transport", "tcp"))
    try:
        if protocol == "TELNET":
            with socket.create_connection((host, port), timeout=timeout) as sock:
                sock.settimeout(timeout)
                banner = b""
                try:
                    banner = sock.recv(256)
                except socket.timeout:
                    pass
            return True, "banner_read" if banner else "connected", {"banner_bytes": len(banner)}
        if protocol == "RTSP":
            with socket.create_connection((host, port), timeout=timeout) as sock:
                sock.settimeout(timeout)
                for cseq, method in enumerate(("OPTIONS", "DESCRIBE"), start=1):
                    sock.sendall(_rare_rtsp_request(method, host, port, cseq))
                    try:
                        sock.recv(512)
                    except socket.timeout:
                        pass
            return True, "request_sent", {"methods": ["OPTIONS", "DESCRIBE"]}
        if protocol == "SIP":
            sent = 0
            for tr in (("udp", "tcp") if transport == "udp_tcp" else (transport,)):
                for method in ("OPTIONS", "REGISTER"):
                    payload = _rare_sip_request(method, host, port, tr)
                    if tr == "udp":
                        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                            sock.settimeout(timeout)
                            sock.sendto(payload, (host, port))
                    else:
                        with socket.create_connection((host, port), timeout=timeout) as sock:
                            sock.settimeout(timeout)
                            sock.sendall(payload)
                    sent += 1
            return True, "request_sent", {"sent": sent}
        if protocol == "RTP":
            count = max(1, int(probe.get("rtp_packets", 8)))
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                base = random.randint(1, 0xFFFF)
                for offset in range(count):
                    sock.sendto(_rare_rtp_packet(base + offset), (host, port))
            return True, "packet_sent", {"rtp_packets": count}
    except OSError as exc:
        return False, type(exc).__name__.lower(), {"error": str(exc)}
    return False, "unsupported_protocol", {}


def _run_rare_protocol_activity(log: EventLog, plan: dict[str, Any]) -> None:
    if plan.get("mode") == "skip":
        _write_skip(
            log,
            {"scenario_id": "rare_protocol_activity"},
            str(plan.get("reason") or "no_probe_plans"),
            [],
        )
        return
    probes = plan.get("probes") or []
    timeout = float(plan.get("timeout", 3.0))
    mode = plan.get("mode", "live")
    vantage = probes[0]["host"] if probes else ""
    protocols = sorted({str(p.get("protocol", "")) for p in probes if p.get("protocol")})
    log.append(
        event="rare_protocol_activity_started",
        status="info",
        target=vantage,
        artifact="rare_protocol_session",
        evidence={
            "planned_probes": len(probes),
            "protocols": protocols,
            "mode": mode,
        },
    )
    attempt_count = 0
    success_count = 0
    failure_count = 0
    for index, probe in enumerate(probes, start=1):
        host = str(probe["host"])
        artifact = str(probe.get("artifact") or f"{probe.get('protocol')}:{host}:{probe.get('port')}")
        base_evidence = {
            "seq": index,
            "protocol": probe.get("protocol"),
            "host": host,
            "port": int(probe["port"]),
            "transport": probe.get("transport"),
        }
        log.append(
            event="rare_protocol_probe_attempt",
            status="sent",
            target=host,
            artifact=artifact,
            evidence=dict(base_evidence),
        )
        attempt_count += 1
        if mode == "mock":
            ok, outcome, extra = True, "probe_sent", {"mode": "mock"}
        else:
            ok, outcome, extra = _rare_execute_probe(probe, timeout)
        outcome_evidence = {**base_evidence, "outcome": outcome, **extra}
        if ok:
            success_count += 1
            log.append(
                event="rare_protocol_probe_success",
                status="sent",
                target=host,
                artifact=artifact,
                evidence=outcome_evidence,
            )
        else:
            failure_count += 1
            failure_status = outcome if outcome in {"error", "timeout", "connection_refused"} else "error"
            log.append(
                event="rare_protocol_probe_failure",
                status=failure_status,
                target=host,
                artifact=artifact,
                evidence=outcome_evidence,
            )
    log.append(
        event="rare_protocol_activity_completed",
        status="info",
        target=vantage,
        artifact="rare_protocol_session",
        evidence={
            "protocols": protocols,
            "attempt_count": attempt_count,
            "success_count": success_count,
            "failure_count": failure_count,
        },
    )


def _run_shell_command(shell: str, *, timeout: float) -> None:
    subprocess.run(
        ["sh", "-c", shell],
        capture_output=True,
        timeout=timeout,
        check=False,
    )


def _hb_write_plain_file(path: str, content: str, *, timeout: float) -> None:
    quoted = shlex.quote(content)
    _run_shell_command(f"printf %s {quoted} > {shlex.quote(path)}", timeout=timeout)


def _hb_create_eicar_variant(path: str, item: dict[str, Any], *, timeout: float) -> None:
    content = str(item["content"])
    quoted = shlex.quote(content)
    kind = str(item.get("kind") or "plain")
    if kind == "plain":
        _hb_write_plain_file(path, content, timeout=timeout)
        return
    if kind == "zip":
        inner = str(item.get("inner_name") or "eicar.txt")
        _run_shell_command(
            "tmpdir=$(mktemp -d) && "
            f"printf %s {quoted} > \"$tmpdir/{inner}\" && "
            f"zip -j {shlex.quote(path)} \"$tmpdir/{inner}\" && "
            "rm -rf \"$tmpdir\"",
            timeout=timeout,
        )
        return
    if kind == "nested_zip":
        inner = str(item.get("inner_name") or "eicar.txt")
        _run_shell_command(
            "tmpdir=$(mktemp -d) && "
            f"printf %s {quoted} > \"$tmpdir/{inner}\" && "
            f"cd \"$tmpdir\" && zip inner.zip {inner} && "
            f"zip -j {shlex.quote(path)} inner.zip && "
            "rm -rf \"$tmpdir\"",
            timeout=timeout,
        )


def _hb_create_archive(path: str, item: dict[str, Any], *, timeout: float) -> None:
    kind = str(item.get("kind") or "tar_gz")
    if kind == "zip":
        _run_shell_command(
            "tmpdir=$(mktemp -d) && echo test > \"$tmpdir/sample.txt\" && "
            f"zip -j {shlex.quote(path)} \"$tmpdir/sample.txt\" && rm -rf \"$tmpdir\"",
            timeout=timeout,
        )
        return
    _run_shell_command(
        "tmpdir=$(mktemp -d) && echo test > \"$tmpdir/sample.txt\" && "
        f"tar czf {shlex.quote(path)} -C \"$tmpdir\" sample.txt && rm -rf \"$tmpdir\"",
        timeout=timeout,
    )


def _hb_file_lifecycle(
    log: EventLog,
    *,
    target: str,
    mode: str,
    timeout: float,
    path: str,
    created_event: str,
    accessed_event: str,
    deleted_event: str,
    create_fn: Any,
    evidence: dict[str, Any] | None = None,
) -> None:
    payload = {"path": path, **(evidence or {})}
    log.append(
        event=created_event,
        status="info",
        target=target,
        artifact=path,
        evidence=dict(payload),
    )
    if mode == "live":
        create_fn()
    log.append(
        event=accessed_event,
        status="info",
        target=target,
        artifact=path,
        evidence=dict(payload),
    )
    if mode == "live":
        subprocess.run(
            ["cat", path],
            capture_output=True,
            timeout=timeout,
            check=False,
        )
    log.append(
        event=deleted_event,
        status="info",
        target=target,
        artifact=path,
        evidence=dict(payload),
    )
    if mode == "live":
        subprocess.run(
            ["rm", "-f", path],
            capture_output=True,
            timeout=timeout,
            check=False,
        )


def _hb_run_planned_steps(
    log: EventLog,
    *,
    target: str,
    mode: str,
    timeout: float,
    steps: list[dict[str, str]],
) -> None:
    for step in steps:
        event_name = str(step["event"])
        shell = str(step["shell"])
        artifact = str(step.get("artifact") or event_name)
        log.append(
            event=event_name,
            status="info",
            target=target,
            artifact=artifact,
            evidence={"shell": shell, "artifact": artifact},
        )
        if mode == "live":
            _run_shell_command(shell, timeout=timeout)


def _run_host_behavior_check(log: EventLog, plan: dict[str, Any]) -> None:
    if plan.get("mode") == "skip":
        _write_skip(
            log,
            {"scenario_id": "host_behavior_check"},
            str(plan.get("reason") or "skipped"),
            [],
        )
        return

    target = str(plan.get("target_host") or "")
    mode = str(plan.get("mode", "live"))
    timeout = float(plan.get("timeout", 30.0))
    commands = list(plan.get("commands") or [])
    credential_checks = list(plan.get("credential_checks") or [])
    eicar_lifecycle = list(plan.get("eicar_lifecycle") or [])
    encoded_file_activity = list(plan.get("encoded_file_activity") or [])

    log.append(
        event="host_behavior_check_started",
        status="info",
        target=target,
        artifact="host_behavior_session",
        evidence={
            "target_host": target,
            "commands_planned": len(commands),
            "credential_checks_planned": len(credential_checks),
            "eicar_lifecycle_planned": len(eicar_lifecycle),
            "encoded_file_activity_planned": len(encoded_file_activity),
            "eicar_variants_planned": len(plan.get("eicar_variants") or []),
            "suspicious_scripts_planned": len(plan.get("suspicious_scripts") or []),
            "persistence_artifacts_planned": len(plan.get("persistence_artifacts") or []),
            "archives_planned": len(plan.get("archives") or []),
            "mode": mode,
            "webshell_family": plan.get("webshell_family"),
        },
    )

    for index, item in enumerate(commands, start=1):
        name = str(item["name"])
        shell = str(item["shell"])
        log.append(
            event="host_behavior_command_dispatched",
            status="sent",
            target=target,
            artifact=name,
            evidence={"seq": index, "command": name, "shell": shell},
        )
        if mode == "live":
            _run_shell_command(shell, timeout=timeout)

    for index, item in enumerate(credential_checks, start=1):
        event_name = str(item["event"])
        name = str(item["name"])
        shell = str(item["shell"])
        log.append(
            event=event_name,
            status="info",
            target=target,
            artifact=name,
            evidence={"seq": index, "shell": shell, "check": name},
        )
        if mode == "live":
            _run_shell_command(shell, timeout=timeout)

    if eicar_lifecycle:
        _hb_run_planned_steps(
            log,
            target=target,
            mode=mode,
            timeout=timeout,
            steps=eicar_lifecycle,
        )

    if encoded_file_activity:
        _hb_run_planned_steps(
            log,
            target=target,
            mode=mode,
            timeout=timeout,
            steps=encoded_file_activity,
        )

    for variant in plan.get("eicar_variants") or []:
        variant_path = str(variant["path"])
        _hb_file_lifecycle(
            log,
            target=target,
            mode=mode,
            timeout=timeout,
            path=variant_path,
            created_event="eicar_variant_created",
            accessed_event="eicar_variant_accessed",
            deleted_event="eicar_variant_deleted",
            create_fn=lambda p=variant_path, v=variant: _hb_create_eicar_variant(
                p, v, timeout=timeout
            ),
            evidence={
                "variant": str(variant.get("variant") or ""),
                "kind": variant.get("kind"),
            },
        )

    for script in plan.get("suspicious_scripts") or []:
        script_path = str(script["path"])
        script_content = str(script["content"])
        _hb_file_lifecycle(
            log,
            target=target,
            mode=mode,
            timeout=timeout,
            path=script_path,
            created_event="suspicious_script_created",
            accessed_event="suspicious_script_accessed",
            deleted_event="suspicious_script_deleted",
            create_fn=lambda p=script_path, c=script_content: _hb_write_plain_file(
                p, c, timeout=timeout
            ),
            evidence={"name": str(script.get("name") or "")},
        )

    for artifact in plan.get("persistence_artifacts") or []:
        artifact_path = str(artifact["path"])
        artifact_content = str(artifact["content"])
        _hb_file_lifecycle(
            log,
            target=target,
            mode=mode,
            timeout=timeout,
            path=artifact_path,
            created_event="persistence_artifact_created",
            accessed_event="persistence_artifact_accessed",
            deleted_event="persistence_artifact_deleted",
            create_fn=lambda p=artifact_path, c=artifact_content: _hb_write_plain_file(
                p, c, timeout=timeout
            ),
            evidence={"name": str(artifact.get("name") or "")},
        )

    for archive in plan.get("archives") or []:
        archive_path = str(archive["path"])
        _hb_file_lifecycle(
            log,
            target=target,
            mode=mode,
            timeout=timeout,
            path=archive_path,
            created_event="archive_created",
            accessed_event="archive_accessed",
            deleted_event="archive_deleted",
            create_fn=lambda p=archive_path, a=archive: _hb_create_archive(
                p, a, timeout=timeout
            ),
            evidence={"name": str(archive.get("name") or ""), "kind": archive.get("kind")},
        )

    log.append(
        event="host_behavior_check_completed",
        status="info",
        target=target,
        artifact="host_behavior_session",
        evidence={
            "target_host": target,
            "commands_dispatched": len(commands),
            "credential_checks_dispatched": len(credential_checks),
            "eicar_lifecycle_dispatched": len(eicar_lifecycle),
            "encoded_file_activity_dispatched": len(encoded_file_activity),
            "mode": mode,
        },
    )


def _dispatch(log: EventLog, manifest: dict[str, Any]) -> None:
    plan = manifest.get("plan") or {}
    plan_type = plan.get("type")
    if plan_type == "remote_discovery_execute":
        if resolve_remote_discovery_plan is None:
            _write_skip(log, manifest, "remote_discovery_module_missing", [])
            return
        log.append(
            event="remote_discovery_started",
            status="info",
            evidence={
                "target_net": (plan.get("discovery") or {}).get("target_net"),
                "discovery_origin": "webshell_host",
            },
        )
        resolved_plan = resolve_remote_discovery_plan(plan)
        discovery_result = resolved_plan.pop("discovery_result", None)
        log.append(
            event="remote_discovery_completed",
            status="info",
            evidence={"discovery_result": discovery_result or {}},
        )
        plan = resolved_plan
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
        "host_behavior_check": _run_host_behavior_check,
        "rare_protocol_activity": _run_rare_protocol_activity,
    }
    handler = handlers.get(plan_type)
    if handler is None:
        _write_skip(log, manifest, f"unsupported_plan:{plan_type}", [])
        return
    handler(log, plan)


def _planned_status(manifest: dict[str, Any]) -> dict[str, Any]:
    plan = manifest.get("plan") or {}
    plan_type = str(plan.get("type") or manifest.get("scenario_id") or "")
    planned: dict[str, Any] = {"type": plan_type, "mode": plan.get("mode")}
    if plan_type == "remote_discovery_execute":
        planned["discovery_origin"] = "webshell_host"
        planned["target_net"] = (plan.get("discovery") or {}).get("target_net")
    elif plan_type == "http_followup":
        planned["requests"] = len(plan.get("requests") or [])
        burst = plan.get("non_standard_port_burst") or {}
        planned["burst_attempts"] = (
            len(burst.get("requests") or []) if burst.get("enabled") else 0
        )
    elif plan_type == "port_sweep":
        planned["probes"] = len(plan.get("probes") or [])
    elif plan_type == "dns_tunnel":
        planned["queries"] = len(plan.get("queries") or [])
    elif plan_type == "sql_injection":
        planned["requests"] = len(plan.get("requests") or [])
    elif plan_type == "ssh_failure":
        planned["attempts"] = len(plan.get("attempts") or [])
    elif plan_type == "host_behavior_check":
        planned["commands"] = len(plan.get("commands") or [])
    elif plan_type == "rare_protocol_activity":
        planned["probes"] = len(plan.get("probes") or [])
    return planned


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
    status_path = work_dir / "remote_status.json"
    # Preserve remote convention for diagnostics only.
    _ = paths.get("bundle")

    missing = _check_capabilities(manifest)
    if missing and not manifest.get("skipped"):
        manifest = dict(manifest)
        manifest["skipped"] = True
        manifest["skip_reason"] = f"missing_remote_commands:{','.join(missing)}"
        manifest["missing_commands"] = missing

    status = RemoteStatusWriter(
        status_path,
        scenario_id=str(manifest["scenario_id"]),
        planned=_planned_status(manifest),
    )
    log = EventLog(
        run_id=str(manifest["run_id"]),
        scenario_id=str(manifest["scenario_id"]),
        scenario_version=str(manifest.get("scenario_version") or "1.0.0"),
        schema_version=str(manifest.get("schema_version") or "1.0.0"),
        bundle_path=bundle_path,
        status_writer=status,
    )
    status.update(phase="running")
    try:
        _dispatch(log, manifest)
    except Exception as exc:
        status.update(phase="failed", error=str(exc))
        log.write_bundle(bundle_path)
        raise
    log.write_bundle(bundle_path)
    log.write_traffic_summary(summary_path, target_net=manifest.get("target_net"))
    status.update(phase="completed", attempted={"events": len(log.events)})
    print(json.dumps({"exit_code": 0, "bundle": str(bundle_path), "events": len(log.events)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
