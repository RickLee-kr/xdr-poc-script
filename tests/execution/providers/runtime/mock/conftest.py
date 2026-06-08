"""Shared fixtures for mock provider runtime tests."""

from __future__ import annotations

import pytest

from dsp.execution.providers.runtime.mock import (
    MockProviderRuntime,
    MockRuntimeConfiguration,
)
from dsp.execution.providers.webshell.jsp import JspWebshellProvider


@pytest.fixture
def mock_runtime() -> MockProviderRuntime:
    return MockProviderRuntime(provider_type="jsp")


@pytest.fixture
def connected_runtime(mock_runtime: MockProviderRuntime) -> MockProviderRuntime:
    mock_runtime.create_remote_session()
    mock_runtime.connect()
    return mock_runtime


@pytest.fixture
def jsp_provider_with_runtime(mock_runtime: MockProviderRuntime) -> JspWebshellProvider:
    provider = JspWebshellProvider()
    provider.attach_runtime(mock_runtime)
    return provider
