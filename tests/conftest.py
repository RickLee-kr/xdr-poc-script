"""Shared pytest fixtures."""

from __future__ import annotations

from unittest.mock import patch

import pytest


@pytest.fixture
def mock_curl_http():
    """Mock curl transport for probe and live HTTP execution."""
    from dsp.protocols.http.curl_transport import CurlHttpResult

    def fake_curl_http_request(url: str, **kwargs) -> CurlHttpResult:
        return CurlHttpResult(outcome="response", status_code=400, http_version="1.1")

    with patch(
        "dsp.protocols.http.curl_transport.curl_http_request",
        side_effect=fake_curl_http_request,
    ), patch(
        "dsp.protocols.http.target_probe.curl_http_request",
        side_effect=fake_curl_http_request,
    ):
        yield


@pytest.fixture
def tmp_runs_dir(tmp_path, monkeypatch):
    runs = tmp_path / "runs"
    runs.mkdir()
    monkeypatch.setenv("DSP_RUNS_DIR", str(runs))
    return runs
