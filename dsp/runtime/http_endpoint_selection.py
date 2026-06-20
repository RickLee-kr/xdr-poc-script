"""Shared HTTP endpoint tuple selection from discovery buckets."""

from __future__ import annotations

from dsp.protocols.http.urls import HTTP_PORT_PRIORITY

_HTTP_PORT_RANK = {port: idx for idx, port in enumerate(HTTP_PORT_PRIORITY)}


def select_discovered_http_endpoint_tuples(
    *,
    http_hosts: list[str],
    http_endpoints: list[tuple[str, int]],
    max_hosts: int,
    explicit_hosts: list[str] | None = None,
    explicit_port: int = 80,
) -> list[tuple[str, int]]:
    """
    Pick one HTTP endpoint per discovered host using port-priority ranking.

    Shared by local host selection and webshell remote discovery planning so
    identical discovery buckets produce identical endpoint tuples.
    """
    if explicit_hosts:
        return [(str(h), explicit_port) for h in explicit_hosts][:max_hosts]

    if not http_hosts:
        return []

    hosts = sorted(http_hosts, key=lambda h: tuple(int(p) for p in h.split(".")))[:max_hosts]

    ports_by_host: dict[str, set[int]] = {}
    for host, port in http_endpoints:
        ports_by_host.setdefault(host, set()).add(port)

    endpoints: list[tuple[str, int]] = []
    for host in hosts:
        ports = ports_by_host.get(host)
        if ports:
            port = min(
                ports,
                key=lambda p: (_HTTP_PORT_RANK.get(p, len(HTTP_PORT_PRIORITY)), p),
            )
        else:
            port = HTTP_PORT_PRIORITY[0]
        endpoints.append((host, port))
    return endpoints[:max_hosts]
