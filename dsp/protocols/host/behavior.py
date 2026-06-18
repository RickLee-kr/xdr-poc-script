"""Host behavior check planning — harmless EDR observation commands on webshell host."""

from __future__ import annotations

from typing import Any

from dsp.runtime.scenario_plan import INITIAL_COMPROMISE_ENDPOINT_KEY

EICAR_TEST_STRING = (
    r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
)

SUSPICIOUS_SCRIPT_CONTENT = "#!/bin/bash\necho test\n"

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

# (event_name, artifact_name, shell_command)
CREDENTIAL_ENUMERATION_CHECKS: tuple[tuple[str, str, str], ...] = (
    ("credential_artifact_enumeration", "ssh_dir_listing", "ls -al ~/.ssh"),
    ("pem_file_enumeration", "pem_find", 'find ~ -name "*.pem" 2>/dev/null'),
    ("ssh_key_enumeration", "id_rsa_find", 'find ~ -name "id_rsa" 2>/dev/null'),
    (
        "ssh_key_enumeration",
        "authorized_keys_find",
        'find ~ -name "authorized_keys" 2>/dev/null',
    ),
)

SUSPICIOUS_SCRIPT_NAMES: tuple[str, ...] = ("update.sh", "install.sh", "run.sh")

PERSISTENCE_ARTIFACT_NAMES: tuple[str, ...] = (
    "systemd-update.service",
    "update.desktop",
)

ARCHIVE_NAMES: tuple[str, ...] = ("archive.tar.gz", "archive.zip")

EICAR_VARIANT_NAMES: tuple[str, ...] = (
    "eicar.com",
    "eicar.txt",
    "eicar.zip",
    "eicar_nested.zip",
)


def is_linux_family_supported(webshell_family: str | None) -> bool:
    """Return False for Windows/ASPX families (placeholder — no Linux shell commands)."""
    if not webshell_family:
        return True
    return webshell_family.strip().lower() not in WINDOWS_PLACEHOLDER_FAMILIES


def _safe_run_token(run_id: str) -> str:
    return "".join(ch if ch.isalnum() or ch in "-_" else "_" for ch in run_id)


def default_eicar_path(run_id: str) -> str:
    return f"/tmp/dsp_eicar_{_safe_run_token(run_id)}.txt"


def _tmp_path(run_id: str, name: str) -> str:
    token = _safe_run_token(run_id)
    return f"/tmp/dsp_hb_{token}_{name}"


def resolve_webshell_target_host(params: dict[str, Any]) -> str | None:
    """Return the webshell compromise host when injected by scenario_plan."""
    endpoint = params.get(INITIAL_COMPROMISE_ENDPOINT_KEY)
    if isinstance(endpoint, dict) and endpoint.get("host"):
        return str(endpoint["host"])
    explicit = params.get("target_host")
    if explicit:
        return str(explicit)
    return None


def _build_eicar_variants(run_id: str) -> list[dict[str, Any]]:
    variants: list[dict[str, Any]] = []
    for name in EICAR_VARIANT_NAMES:
        path = _tmp_path(run_id, name)
        entry: dict[str, Any] = {
            "variant": name,
            "path": path,
            "content": EICAR_TEST_STRING,
        }
        if name == "eicar.zip":
            entry["kind"] = "zip"
            entry["inner_name"] = "eicar.txt"
        elif name == "eicar_nested.zip":
            entry["kind"] = "nested_zip"
            entry["inner_name"] = "eicar.txt"
        else:
            entry["kind"] = "plain"
        variants.append(entry)
    return variants


def _build_suspicious_scripts(run_id: str) -> list[dict[str, Any]]:
    return [
        {
            "name": name,
            "path": f"/tmp/{name}",
            "content": SUSPICIOUS_SCRIPT_CONTENT,
        }
        for name in SUSPICIOUS_SCRIPT_NAMES
    ]


def _build_persistence_artifacts(run_id: str) -> list[dict[str, Any]]:
    return [
        {
            "name": "systemd-update.service",
            "path": "/tmp/systemd-update.service",
            "content": "[Unit]\nDescription=DSP placeholder service\n",
        },
        {
            "name": "update.desktop",
            "path": "/tmp/update.desktop",
            "content": "[Desktop Entry]\nName=DSP Update\nType=Application\n",
        },
    ]


def _build_archives(run_id: str) -> list[dict[str, Any]]:
    token = _safe_run_token(run_id)
    return [
        {
            "name": "archive.tar.gz",
            "path": f"/tmp/dsp_hb_{token}_archive.tar.gz",
            "kind": "tar_gz",
        },
        {
            "name": "archive.zip",
            "path": f"/tmp/dsp_hb_{token}_archive.zip",
            "kind": "zip",
        },
    ]


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

    credential_checks = [
        {"event": event, "name": name, "shell": shell}
        for event, name, shell in CREDENTIAL_ENUMERATION_CHECKS
    ]

    return {
        "type": "host_behavior_check",
        "mode": "mock" if dry_run else "live",
        "target_host": target_host,
        "webshell_family": family,
        "commands": [
            {"name": name, "shell": shell}
            for name, shell in LINUX_HOST_BEHAVIOR_COMMANDS
        ],
        "credential_checks": credential_checks,
        "eicar": {
            "path": str(params.get("eicar_path") or default_eicar_path(run_id)),
            "content": EICAR_TEST_STRING,
        },
        "eicar_variants": _build_eicar_variants(run_id),
        "suspicious_scripts": _build_suspicious_scripts(run_id),
        "persistence_artifacts": _build_persistence_artifacts(run_id),
        "archives": _build_archives(run_id),
    }
