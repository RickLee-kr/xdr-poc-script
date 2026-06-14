"""HTTP transport via curl — shared by endpoint probing and scenario execution."""

from __future__ import annotations

import re
import shutil
import subprocess
import uuid
from dataclasses import dataclass
from typing import Any, Callable
from urllib.parse import urlparse

from dsp.protocols.types import HttpResponseResult

CurlCommandRunner = Callable[[list[str], float], "CurlExecResult"]

_default_command_runner: CurlCommandRunner | None = None


@dataclass(frozen=True)
class CurlExecResult:
    exit_code: int
    stdout: str
    stderr: str


@dataclass(frozen=True)
class CurlHttpResult:
    outcome: str
    status_code: int | None
    http_version: str | None = None
    exit_code: int = 0
    message: str = ""


def set_curl_command_runner(runner: CurlCommandRunner | None) -> None:
    """Install a test double for subprocess curl invocation."""
    global _default_command_runner
    _default_command_runner = runner


def curl_available() -> bool:
    if _default_command_runner is not None:
        return True
    return shutil.which("curl") is not None


def _real_curl_command_runner(argv: list[str], timeout: float) -> CurlExecResult:
    completed = subprocess.run(
        argv,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    return CurlExecResult(
        exit_code=completed.returncode,
        stdout=completed.stdout,
        stderr=completed.stderr,
    )


def _parse_curl_write_out(stdout: str) -> tuple[int | None, str | None]:
    lines = [line.strip() for line in stdout.splitlines() if line.strip()]
    if not lines:
        return None, None
    http_code: int | None = None
    http_version: str | None = None
    for line in lines:
        if line.isdigit():
            code = int(line)
            if 0 < code < 1000:
                http_code = code
            continue
        if re.fullmatch(r"1\.[01]", line):
            http_version = line
    if http_code is None and lines[0].isdigit():
        http_code = int(lines[0])
    if http_version is None and len(lines) > 1 and re.fullmatch(r"1\.[01]", lines[1]):
        http_version = lines[1]
    return http_code, http_version


def _exit_code_to_outcome(exit_code: int) -> str:
    if exit_code == 0:
        return "response"
    if exit_code == 28:
        return "timeout"
    if exit_code == 7:
        return "connection_refused"
    return "error"


def run_curl_command(
    argv: list[str],
    *,
    timeout: float,
    command_runner: CurlCommandRunner | None = None,
) -> CurlExecResult:
    runner = command_runner or _default_command_runner or _real_curl_command_runner
    return runner(argv, timeout)


def curl_http_request(
    url: str,
    *,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    body: bytes | None = None,
    timeout: float = 10.0,
    verify_tls: bool = False,
    command_runner: CurlCommandRunner | None = None,
) -> CurlHttpResult:
    """Execute one HTTP request through curl (no redirect follow)."""
    argv = [
        "curl",
        "-sS",
        "-o",
        "/dev/null",
        "-w",
        "%{http_code}\n%{http_version}",
        "--max-time",
        str(max(1, int(timeout))),
        "-X",
        method.upper(),
    ]
    if url.lower().startswith("https://") and not verify_tls:
        argv.append("-k")
    for key, value in (headers or {}).items():
        argv.extend(["-H", f"{key}: {value}"])
    if body is not None:
        argv.extend(["--data-binary", "@-"])
    argv.append(url)

    try:
        if body is not None:
            completed = subprocess.run(
                argv,
                input=body,
                capture_output=True,
                text=False,
                timeout=timeout,
                check=False,
            )
            exec_result = CurlExecResult(
                exit_code=completed.returncode,
                stdout=completed.stdout.decode("utf-8", errors="replace"),
                stderr=completed.stderr.decode("utf-8", errors="replace"),
            )
        else:
            exec_result = run_curl_command(argv, timeout=timeout, command_runner=command_runner)
    except subprocess.TimeoutExpired:
        return CurlHttpResult(outcome="timeout", status_code=None, exit_code=28, message="timeout")

    http_code, http_version = _parse_curl_write_out(exec_result.stdout)
    outcome = _exit_code_to_outcome(exec_result.exit_code)
    if outcome == "response" and http_code == 0:
        outcome = "error"
    if outcome == "response" and http_code is None:
        outcome = "error"
    return CurlHttpResult(
        outcome=outcome,
        status_code=http_code,
        http_version=http_version,
        exit_code=exec_result.exit_code,
        message=exec_result.stderr.strip(),
    )


def curl_send_request(
    url: str,
    *,
    method: str = "GET",
    timeout: float = 10.0,
    verify_tls: bool = False,
    headers: dict[str, str] | None = None,
    body: bytes | None = None,
    content_type: str | None = None,
    command_runner: CurlCommandRunner | None = None,
) -> HttpResponseResult:
    """Map curl transport to HttpResponseResult for HttpClient."""
    request_id = uuid.uuid4().hex[:8]
    request_headers = dict(headers) if headers else {}
    if content_type:
        request_headers.setdefault("Content-Type", content_type)
    result = curl_http_request(
        url,
        method=method,
        headers=request_headers,
        body=body,
        timeout=timeout,
        verify_tls=verify_tls,
        command_runner=command_runner,
    )
    evidence: dict[str, Any] = {
        "url": url,
        "method": method.upper(),
        "transport": "curl",
        "http_version": result.http_version,
        "curl_exit_code": result.exit_code,
    }
    if result.outcome == "response" and result.status_code is not None:
        return HttpResponseResult(
            url=url,
            method=method.upper(),
            outcome="response",
            status_code=result.status_code,
            response_summary={
                "status_code": result.status_code,
                "http_version": result.http_version,
            },
            request_id=request_id,
            dry_run=False,
            evidence=evidence,
        )
    return HttpResponseResult(
        url=url,
        method=method.upper(),
        outcome=result.outcome,
        status_code=result.status_code,
        response_summary={"message": result.message or result.outcome},
        request_id=request_id,
        dry_run=False,
        evidence=evidence,
    )


def endpoint_key_from_url(url: str) -> tuple[str, int]:
    parsed = urlparse(url)
    host = parsed.hostname or ""
    port = parsed.port
    if port is None:
        port = 443 if parsed.scheme == "https" else 80
    return host, port
