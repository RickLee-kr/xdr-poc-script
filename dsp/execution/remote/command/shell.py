"""Shell command builders for webshell command-only execution."""

from __future__ import annotations

import base64
import re
import shlex


def mock_noop_command() -> str:
    """Minimal command for dry-run / mock delivery."""
    return "true"


def wrap_remote_shell_command(command: str) -> str:
    """Run a command through /bin/sh -c so JSP exec() receives a shell pipeline."""
    return f"/bin/sh -c {shlex.quote(command.strip())}"


def _sanitize_run_token(run_id: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_-]+", "_", str(run_id or "run").strip())
    return cleaned[:48] or "run"


def discovery_probe_output_path(run_id: str, batch_index: int) -> str:
    token = _sanitize_run_token(run_id)
    return f"/tmp/.dsp-{token}-probe-{int(batch_index)}.out"


def tcp_probe_command(host: str, port: int, *, timeout: float = 3.0) -> str:
    """TCP connect probe via python3 stdlib — no file upload required."""
    t = max(1, int(timeout))
    script = (
        "import socket;"
        f"s=socket.socket();s.settimeout({t});"
        f"s.connect(({host!r},{int(port)}));s.close()"
    )
    return wrap_remote_shell_command(f"python3 -c {shlex.quote(script)} 2>/dev/null || true")


PROBE_OPEN_MARKER = "DSP_PROBE_OPEN"


def tcp_probe_discovery_command(
    host: str,
    port: int,
    *,
    timeout: float = 0.5,
    output_path: str = "/tmp/.dsp-probe.out",
) -> str:
    """TCP probe that records open ports in a file, then cats it for transport capture."""
    t = max(0.1, float(timeout))
    write_script = (
        "import socket;"
        f"h={host!r};p={int(port)};t={t};m={PROBE_OPEN_MARKER!r};out={output_path!r};"
        "lines=[];"
        "try:"
        " socket.create_connection((h,p),timeout=t).close();"
        " lines.append(m);"
        "except OSError:"
        " pass;"
        "open(out,'w').write(chr(10).join(lines))"
    )
    pipeline = (
        f"rm -f {shlex.quote(output_path)}; "
        f"python3 -c {shlex.quote(write_script)}; "
        f"cat {shlex.quote(output_path)} 2>/dev/null"
    )
    return wrap_remote_shell_command(pipeline)


def tcp_probe_batch_discovery_command(
    probes: list[tuple[str, int]],
    *,
    timeout: float = 0.5,
    output_path: str = "/tmp/.dsp-probe.out",
    workers: int = 32,
) -> str:
    """Batch TCP probes via sh -c, writing markers to a file and catting it back."""
    t = max(0.1, float(timeout))
    worker_count = max(1, min(int(workers), len(probes) or 1))
    write_script = (
        "import socket;"
        "from concurrent.futures import ThreadPoolExecutor,as_completed;"
        f"probes={probes!r};t={t};m={PROBE_OPEN_MARKER!r};out={output_path!r};w={worker_count};"
        "def probe(tup):"
        " h,p=tup;"
        " try:"
        "  socket.create_connection((h,p),timeout=t).close();"
        "  return f'{m} {h}:{p}';"
        " except OSError:"
        "  return None;"
        "lines=[];"
        "with ThreadPoolExecutor(max_workers=min(w,max(1,len(probes)))) as pool:"
        " futures=[pool.submit(probe,x) for x in probes];"
        " for fut in as_completed(futures):"
        "  row=fut.result();"
        "  if row: lines.append(row);"
        "open(out,'w').write(chr(10).join(lines))"
    )
    pipeline = (
        f"rm -f {shlex.quote(output_path)}; "
        f"python3 -c {shlex.quote(write_script)}; "
        f"cat {shlex.quote(output_path)} 2>/dev/null"
    )
    return wrap_remote_shell_command(pipeline)


def curl_request_command(
    url: str,
    *,
    method: str = "GET",
    user_agent: str = "Mozilla/5.0",
    timeout: float = 10.0,
    body_b64: str | None = None,
    content_type: str | None = None,
) -> str:
    """Build a curl command that discards response body (no parsing on DSP host)."""
    t = max(1, int(timeout))
    parts = [
        "curl",
        "-sS",
        "-o",
        "/dev/null",
        "--max-time",
        str(t),
        "-A",
        user_agent,
        "-X",
        method,
    ]
    if body_b64:
        body = base64.b64decode(body_b64)
        ctype = content_type or "application/octet-stream"
        parts.extend(
            [
                "-H",
                f"Content-Type: {ctype}",
                "--data-binary",
                shlex.quote(body.decode("latin-1", errors="replace")),
            ]
        )
    parts.append(shlex.quote(url))
    return " ".join(parts)


def ssh_attempt_command(
    host: str,
    port: int,
    username: str,
    *,
    timeout: float = 5.0,
) -> str:
    """SSH auth attempt — transport only; outcome not interpreted on DSP host."""
    t = max(1, int(timeout))
    target = f"{username}@{host}"
    return (
        f"ssh -o BatchMode=yes -o ConnectTimeout={t} "
        f"-o StrictHostKeyChecking=no -p {int(port)} "
        f"{shlex.quote(target)} exit 2>/dev/null || true"
    )


def nc_probe_command(host: str, port: int, *, timeout: float = 5.0) -> str:
    t = max(1, int(timeout))
    return f"nc -z -w {t} {shlex.quote(host)} {int(port)} 2>/dev/null || true"


def dns_query_command(resolver: str, fqdn: str, *, timeout: float = 0.05) -> str:
    """UDP/53 DNS query via python3 stdlib."""
    t = max(1, int(max(timeout, 1.0)))
    script = (
        "import socket,struct,uuid;"
        f"fqdn={fqdn!r};resolver={resolver!r};port=53;"
        "def enc(n):"
        " b=b'';"
        " [b:=b+struct.pack('B',len(l))+l.encode() for l in n.rstrip('.').split('.')];"
        " return b+b'\\x00';"
        "txn=struct.unpack('!H',uuid.uuid4().bytes[:2])[0];"
        "pkt=struct.pack('!HHHHHH',txn,0x0100,1,0,0,0)+enc(fqdn)+struct.pack('!HH',1,1);"
        f"s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.settimeout({t});"
        "s.sendto(pkt,(resolver,port));s.close()"
    )
    return f"python3 -c {shlex.quote(script)} 2>/dev/null || true"


def ldap_action_command(
    host: str,
    port: int,
    action_type: str,
    *,
    search_filter: str = "",
    timeout: float = 5.0,
) -> str:
    t = max(1, int(timeout))
    uri = f"ldap://{host}:{port}"
    if action_type == "connection":
        return f"ldapsearch -x -H {shlex.quote(uri)} -s base -b '' -l {t} '(objectClass=*)' 2>/dev/null || true"
    if action_type == "bind":
        return (
            f"ldapsearch -x -H {shlex.quote(uri)} -D cn=admin -w invalid "
            f"-s base -b '' -l {t} '(objectClass=*)' 2>/dev/null || true"
        )
    filt = search_filter or "(objectClass=*)"
    return (
        f"ldapsearch -x -H {shlex.quote(uri)} -s sub -b dc=example,dc=com "
        f"-l {t} {shlex.quote(filt)} 2>/dev/null || true"
    )


def smb_probe_command(host: str, port: int, *, timeout: float = 5.0) -> str:
    t = max(1, int(timeout))
    script = (
        "import socket;"
        f"s=socket.socket();s.settimeout({t});"
        f"s.connect(({host!r},{int(port)}));s.close()"
    )
    return f"python3 -c {shlex.quote(script)} 2>/dev/null || true"


def kerberos_attempt_command(
    host: str,
    port: int,
    username: str,
    realm: str,
    *,
    timeout: float = 10.0,
) -> str:
    t = max(1, int(timeout))
    script = (
        "import socket;"
        f"s=socket.socket();s.settimeout({t});"
        f"s.connect(({host!r},{int(port)}));s.close()"
    )
    return (
        f"python3 -c {shlex.quote(script)} 2>/dev/null || "
        f"kinit {shlex.quote(f'{username}@{realm}')} 2>/dev/null || true"
    )


def host_behavior_shell_command(shell: str) -> str:
    return shell


def rare_protocol_probe_command(host: str, port: int, protocol: str) -> str:
    if protocol == "rtsp":
        return (
            f"printf 'OPTIONS rtsp://{host}:{port}/ RTSP/1.0\\r\\nCSeq: 1\\r\\n\\r\\n' | "
            f"nc -w 3 {shlex.quote(host)} {int(port)} 2>/dev/null || true"
        )
    return tcp_probe_command(host, port)
