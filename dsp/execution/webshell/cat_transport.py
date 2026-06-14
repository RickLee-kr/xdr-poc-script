"""Webshell ``cat`` transport helper for remote file reads."""

from __future__ import annotations

from typing import TYPE_CHECKING

from dsp.execution.webshell.command_transport import read_remote_file_via_cat

if TYPE_CHECKING:
    from dsp.execution.providers.runtime.transport import TransportBackedRuntime

__all__ = ["read_remote_file_via_cat"]
