"""Webshell command-only execution models — MASTER WBS v1.2."""

from __future__ import annotations

# Live webshell path uses command dispatch only (no DSP runtime upload).
REMOTE_EXECUTION_MODE_COMMAND = "command"

# Deprecated bundle mode — experimental; not used on webshell live path.
REMOTE_EXECUTION_MODE_BUNDLE = "bundle"

COMMAND_SCENARIOS = frozenset(
    {
        "port_sweep",
        "dns_tunnel",
        "dga",
        "http_followup",
        "sql_injection",
        "ssh_failure",
        "ldap_enumeration",
        "smb_login_failure",
        "kerberos_failure",
        "host_behavior_check",
        "rare_protocol_activity",
    }
)

FORBIDDEN_REMOTE_ARTIFACTS = frozenset(
    {
        "manifest.json",
        "run_scenario.py",
        "remote_discovery.py",
    }
)

DISCOVERY_ORIGIN_WEBSHELL = "webshell_host"
# Event Store source tag — traffic executed on remote webshell host.
EVENT_SOURCE_WEBSHELL = "remote"
