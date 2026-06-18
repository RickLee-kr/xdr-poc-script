"""Rare protocol client — safe probe-only traffic generation."""

from __future__ import annotations

import random
import socket
import struct
from dataclasses import dataclass, field
from typing import Any

from dsp.protocols.rare.attempts import PlannedRareProbe

DEFAULT_TIMEOUT = 3.0


@dataclass
class RareProbeResult:
    protocol: str
    host: str
    port: int
    transport: str
    outcome: str
    success: bool
    packets_sent: int = 0
    evidence: dict[str, Any] = field(default_factory=dict)


def _build_rtsp_request(method: str, host: str, port: int, cseq: int) -> bytes:
    url = f"rtsp://{host}:{port}/"
    lines = [
        f"{method} {url} RTSP/1.0",
        f"CSeq: {cseq}",
        "User-Agent: DSP-RareProtocol-Lab/1.0",
    ]
    if method == "DESCRIBE":
        lines.append("Accept: application/sdp")
    lines.extend(["", ""])
    return "\r\n".join(lines).encode("ascii")


def _build_sip_request(method: str, host: str, port: int, transport: str) -> bytes:
    via_transport = "UDP" if transport == "udp" else "TCP"
    lines = [
        f"{method} sip:{host}:{port} SIP/2.0",
        f"Via: SIP/2.0/{via_transport} {host}:{port};branch=z9hG4bK-dsp-rare",
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


def _build_rtp_packet(seq: int) -> bytes:
    """Minimal RTP v2 header + tiny safe payload (no media stream)."""
    version = 2
    payload_type = 96
    ssrc = 0x44535001
    header = struct.pack(
        "!BBHII",
        (version << 6),
        payload_type & 0x7F,
        seq & 0xFFFF,
        0,
        ssrc,
    )
    return header + b"DSP-LAB"


class RareProtocolClient:
    """Execute safe rare-protocol probes — no sessions, auth, or media streams."""

    def __init__(self, *, mode: str = "live", timeout: float = DEFAULT_TIMEOUT) -> None:
        self.mode = mode
        self.timeout = timeout

    def probe(
        self,
        plan: PlannedRareProbe,
        *,
        mock_outcome: str | None = None,
    ) -> RareProbeResult:
        if self.mode == "mock":
            outcome = mock_outcome or "probe_sent"
            return RareProbeResult(
                protocol=plan.protocol,
                host=plan.host,
                port=plan.port,
                transport=plan.transport,
                outcome=outcome,
                success=outcome in {"probe_sent", "banner_read", "response_received", "packet_sent"},
                packets_sent=plan.rtp_packets if plan.protocol == "RTP" else 1,
                evidence={"mode": "mock", "protocol": plan.protocol},
            )

        if plan.protocol == "TELNET":
            return self._probe_telnet(plan)
        if plan.protocol == "RTSP":
            return self._probe_rtsp(plan)
        if plan.protocol == "SIP":
            return self._probe_sip(plan)
        if plan.protocol == "RTP":
            return self._probe_rtp(plan)
        return RareProbeResult(
            protocol=plan.protocol,
            host=plan.host,
            port=plan.port,
            transport=plan.transport,
            outcome="unsupported_protocol",
            success=False,
            evidence={"protocol": plan.protocol},
        )

    def _probe_telnet(self, plan: PlannedRareProbe) -> RareProbeResult:
        banner = b""
        try:
            with socket.create_connection((plan.host, plan.port), timeout=self.timeout) as sock:
                sock.settimeout(self.timeout)
                try:
                    banner = sock.recv(256)
                except socket.timeout:
                    pass
            return RareProbeResult(
                protocol=plan.protocol,
                host=plan.host,
                port=plan.port,
                transport="tcp",
                outcome="banner_read" if banner else "connected",
                success=True,
                evidence={"banner_bytes": len(banner)},
            )
        except OSError as exc:
            return RareProbeResult(
                protocol=plan.protocol,
                host=plan.host,
                port=plan.port,
                transport="tcp",
                outcome=type(exc).__name__.lower(),
                success=False,
                evidence={"error": str(exc)},
            )

    def _probe_rtsp(self, plan: PlannedRareProbe) -> RareProbeResult:
        responses: list[int] = []
        try:
            with socket.create_connection((plan.host, plan.port), timeout=self.timeout) as sock:
                sock.settimeout(self.timeout)
                for cseq, method in enumerate(("OPTIONS", "DESCRIBE"), start=1):
                    sock.sendall(_build_rtsp_request(method, plan.host, plan.port, cseq))
                    try:
                        data = sock.recv(512)
                        if data:
                            first_line = data.split(b"\r\n", 1)[0]
                            if b"RTSP/1." in first_line:
                                try:
                                    responses.append(int(first_line.split()[1]))
                                except (IndexError, ValueError):
                                    responses.append(0)
                    except socket.timeout:
                        pass
            return RareProbeResult(
                protocol=plan.protocol,
                host=plan.host,
                port=plan.port,
                transport="tcp",
                outcome="response_received" if responses else "request_sent",
                success=True,
                evidence={"response_codes": responses, "methods": ["OPTIONS", "DESCRIBE"]},
            )
        except OSError as exc:
            return RareProbeResult(
                protocol=plan.protocol,
                host=plan.host,
                port=plan.port,
                transport="tcp",
                outcome=type(exc).__name__.lower(),
                success=False,
                evidence={"error": str(exc)},
            )

    def _probe_sip(self, plan: PlannedRareProbe) -> RareProbeResult:
        methods = ("OPTIONS", "REGISTER")
        transports = ("udp", "tcp") if plan.transport == "udp_tcp" else (plan.transport,)
        sent = 0
        last_error = ""
        for transport in transports:
            for method in methods:
                payload = _build_sip_request(method, plan.host, plan.port, transport)
                try:
                    if transport == "udp":
                        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                            sock.settimeout(self.timeout)
                            sock.sendto(payload, (plan.host, plan.port))
                            try:
                                sock.recvfrom(512)
                            except socket.timeout:
                                pass
                    else:
                        with socket.create_connection((plan.host, plan.port), timeout=self.timeout) as sock:
                            sock.settimeout(self.timeout)
                            sock.sendall(payload)
                            try:
                                sock.recv(512)
                            except socket.timeout:
                                pass
                    sent += 1
                except OSError as exc:
                    last_error = str(exc)
        if sent:
            return RareProbeResult(
                protocol=plan.protocol,
                host=plan.host,
                port=plan.port,
                transport=plan.transport,
                outcome="request_sent",
                success=True,
                packets_sent=sent,
                evidence={"methods": list(methods), "transports": list(transports), "sent": sent},
            )
        return RareProbeResult(
            protocol=plan.protocol,
            host=plan.host,
            port=plan.port,
            transport=plan.transport,
            outcome="connection_error",
            success=False,
            evidence={"error": last_error},
        )

    def _probe_rtp(self, plan: PlannedRareProbe) -> RareProbeResult:
        count = max(1, plan.rtp_packets)
        sent = 0
        last_error = ""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(self.timeout)
                base_seq = random.randint(1, 0xFFFF)
                for offset in range(count):
                    packet = _build_rtp_packet(base_seq + offset)
                    sock.sendto(packet, (plan.host, plan.port))
                    sent += 1
            return RareProbeResult(
                protocol=plan.protocol,
                host=plan.host,
                port=plan.port,
                transport="udp",
                outcome="packet_sent",
                success=True,
                packets_sent=sent,
                evidence={"rtp_packets": sent},
            )
        except OSError as exc:
            return RareProbeResult(
                protocol=plan.protocol,
                host=plan.host,
                port=plan.port,
                transport="udp",
                outcome=type(exc).__name__.lower(),
                success=False,
                packets_sent=sent,
                evidence={"error": str(exc), "rtp_packets": sent},
            )
