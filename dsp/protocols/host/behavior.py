"""Host behavior check planning — harmless EDR observation commands on webshell host."""

from __future__ import annotations

from typing import Any

from dsp.runtime.scenario_plan import INITIAL_COMPROMISE_ENDPOINT_KEY

EICAR_TEST_STRING = (
    r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
)

WINDOWS_PLACEHOLDER_FAMILIES = frozenset({"aspx"})

LINUX_HOST_BEHAVIOR_COMMANDS: tuple[tuple[str, str], ...] = (
    ("whoami", "whoami"),
    ("id", "id"),
    ("hostname", "hostname"),
    ("uname", "uname -a"),
    ("ip_addr", "ip addr"),
    ("ip_route", "ip route"),
    ("passwd", "cat /etc/passwd"),
    ("base64_decode", 'echo "d2hvYW1p" | base64 -d'),
)


def is_linux_family_supported(webshell_family: str | None) -> bool:
    """Return False for Windows/ASPX families (placeholder — no Linux shell commands)."""
    if not webshell_family:
        return True
    return webshell_family.strip().lower() not in WINDOWS_PLACEHOLDER_FAMILIES


def default_eicar_path(run_id: str) -> str:
    safe = "".join(ch if ch.isalnum() or ch in "-_" else "_" for ch in run_id)
    return f"/tmp/dsp_eicar_{safe}.txt"


def resolve_webshell_target_host(params: dict[str, Any]) -> str | None:
    """Return the webshell compromise host when injected by scenario_plan."""
    endpoint = params.get(INITIAL_COMPROMISE_ENDPOINT_KEY)
    if isinstance(endpoint, dict) and endpoint.get("host"):
        return str(endpoint["host"])
    explicit = params.get("target_host")
    if explicit:
        return str(explicit)
    return None


def build_host_behavior_plan(
    params: dict[str, Any],
    *,
    run_id: str,
    dry_run: bool,
    webshell_family: str | None = None,
) -> dict[str, Any]:
    """Build serializable host behavior plan for local or remote execution."""
    family = webshell_family or params.get("webshell_family")
    if not is_linux_family_supported(str(family) if family else None):
        return {
            "type": "host_behavior_check",
            "mode": "skip",
            "reason": "windows_family_placeholder",
            "webshell_family": family,
        }

    target_host = resolve_webshell_target_host(params)
    if not target_host:
        return {
            "type": "host_behavior_check",
            "mode": "skip",
            "reason": "no_webshell_target_host",
        }

    return {
        "type": "host_behavior_check",
        "mode": "mock" if dry_run else "live",
        "target_host": target_host,
        "webshell_family": family,
        "commands": [
            {"name": name, "shell": shell}
            for name, shell in LINUX_HOST_BEHAVIOR_COMMANDS
        ],
        "eicar": {
            "path": str(params.get("eicar_path") or default_eicar_path(run_id)),
            "content": EICAR_TEST_STRING,
        },
    }
