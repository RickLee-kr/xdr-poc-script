"""Bash-parity curl transport tests."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from dsp.protocols.http.curl_transport import CurlExecResult, curl_http_request, curl_send_request


def test_curl_http_request_get_bash_parity():
    captured: list[list[str]] = []

    def runner(argv: list[str], timeout: float) -> CurlExecResult:
        captured.append(argv)
        return CurlExecResult(exit_code=0, stdout="302\n1.1", stderr="")

    result = curl_http_request(
        "http://10.10.10.20/admin?id=%00%00%00",
        method="GET",
        timeout=2.0,
        headers={
            "Host": "10.10.10.20",
            "User-Agent": "ThreatHunterAgent/8.2",
            "X-External-URL-Recon": "camp123",
            "X-PoC-Mode": "external_url_scan",
            "X-PoC-Campaign": "camp123",
        },
        command_runner=runner,
    )
    argv = captured[0]
    assert argv[0] == "curl"
    assert "-H" in argv
    assert any("User-Agent: ThreatHunterAgent/8.2" in part for part in argv)
    assert any("X-PoC-Campaign: camp123" in part for part in argv)
    assert argv[-1] == "http://10.10.10.20/admin?id=%00%00%00"
    assert "--max-time" in argv
    assert result.status_code == 302


def test_curl_http_request_post_includes_data():
    captured: list[list[str]] = []

    def fake_run(*args, **kwargs):
        captured.append(list(args[0]) if args else kwargs.get("args", []))
        proc = MagicMock()
        proc.returncode = 0
        proc.stdout = b"200\n1.1"
        proc.stderr = b""
        return proc

    with patch("dsp.protocols.http.curl_transport.subprocess.run", side_effect=fake_run):
        curl_http_request(
            "http://10.10.10.20/",
            method="POST",
            timeout=2.0,
            headers={"User-Agent": "ReconEngine/5.4"},
            body=b"probe=camp123",
        )
    argv = captured[0]
    assert "-X" in argv
    assert "POST" in argv
    assert "--data-binary" in argv


def test_curl_send_request_parses_status():
    def runner(argv: list[str], timeout: float) -> CurlExecResult:
        return CurlExecResult(exit_code=0, stdout="302\n1.1", stderr="")

    result = curl_send_request(
        "http://10.10.10.20/WEB-INF/web.xml",
        method="GET",
        timeout=2.0,
        headers={"User-Agent": "TelemetryCollector/9.7"},
        command_runner=runner,
    )
    assert result.outcome == "response"
    assert result.status_code == 302
    assert result.evidence.get("transport") == "curl"
