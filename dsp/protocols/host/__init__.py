"""Host behavior protocol helpers."""

from dsp.protocols.host.behavior import (
    EICAR_TEST_STRING,
    LINUX_HOST_BEHAVIOR_COMMANDS,
    WINDOWS_PLACEHOLDER_FAMILIES,
    build_host_behavior_plan,
    default_eicar_path,
    is_linux_family_supported,
)

__all__ = [
    "EICAR_TEST_STRING",
    "LINUX_HOST_BEHAVIOR_COMMANDS",
    "WINDOWS_PLACEHOLDER_FAMILIES",
    "build_host_behavior_plan",
    "default_eicar_path",
    "is_linux_family_supported",
]
