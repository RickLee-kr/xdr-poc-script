"""Host behavior check planning — harmless EDR observation commands on webshell host."""

from __future__ import annotations

import shlex
from typing import Any

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


EICAR_PRIMARY_PATH = "/tmp/dsp_eicar.txt"
EICAR_COPY_PATH = "/tmp/dsp_eicar_copy.txt"
EICAR_MOVED_PATH = "/tmp/dsp_eicar_moved.txt"
EICAR_ARCHIVE_PATH = "/tmp/dsp_eicar.tar.gz"
EICAR_B64_PATH = "/tmp/dsp_eicar.b64"
EICAR_DECODED_PATH = "/tmp/dsp_eicar_decoded.txt"

ENCODED_TEST_PATH = "/tmp/dsp_encoded_test.txt"
ENCODED_B64_PATH = "/tmp/dsp_encoded_test.b64"
ENCODED_RESTORED_PATH = "/tmp/dsp_encoded_restored.txt"


def default_eicar_path(run_id: str) -> str:
    _ = run_id
    return EICAR_PRIMARY_PATH


def _eicar_create_shell(path: str, content: str) -> str:
    return f"printf %s {shlex.quote(content)} > {shlex.quote(path)}"


def build_eicar_lifecycle_steps(
    *,
    path: str | None = None,
    content: str = EICAR_TEST_STRING,
) -> list[dict[str, str]]:
    """Ordered EICAR lifecycle steps — event name and shell command pairs."""
    primary = path or EICAR_PRIMARY_PATH
    delete_shell = "rm -f " + " ".join(
        shlex.quote(p)
        for p in (
            primary,
            EICAR_MOVED_PATH,
            EICAR_DECODED_PATH,
            EICAR_B64_PATH,
            EICAR_ARCHIVE_PATH,
        )
    )
    return [
        {
            "event": "eicar_create",
            "shell": _eicar_create_shell(primary, content),
            "artifact": primary,
        },
        {
            "event": "eicar_read",
            "shell": f"cat {shlex.quote(primary)}",
            "artifact": primary,
        },
        {
            "event": "eicar_copy",
            "shell": f"cp {shlex.quote(primary)} {shlex.quote(EICAR_COPY_PATH)}",
            "artifact": EICAR_COPY_PATH,
        },
        {
            "event": "eicar_move",
            "shell": f"mv {shlex.quote(EICAR_COPY_PATH)} {shlex.quote(EICAR_MOVED_PATH)}",
            "artifact": EICAR_MOVED_PATH,
        },
        {
            "event": "eicar_archive",
            "shell": (
                f"tar czf {shlex.quote(EICAR_ARCHIVE_PATH)} {shlex.quote(primary)}"
            ),
            "artifact": EICAR_ARCHIVE_PATH,
        },
        {
            "event": "eicar_encode",
            "shell": f"base64 {shlex.quote(primary)} > {shlex.quote(EICAR_B64_PATH)}",
            "artifact": EICAR_B64_PATH,
        },
        {
            "event": "eicar_decode",
            "shell": (
                f"base64 -d {shlex.quote(EICAR_B64_PATH)} > "
                f"{shlex.quote(EICAR_DECODED_PATH)}"
            ),
            "artifact": EICAR_DECODED_PATH,
        },
        {
            "event": "eicar_delete",
            "shell": delete_shell,
            "artifact": primary,
        },
    ]


def build_encoded_file_activity_steps() -> list[dict[str, str]]:
    """Non-EICAR base64 encode/decode file activity."""
    return [
        {
            "event": "encoded_file_create",
            "shell": (
                f'echo "hello" > {shlex.quote(ENCODED_TEST_PATH)} && '
                f"base64 {shlex.quote(ENCODED_TEST_PATH)} > "
                f"{shlex.quote(ENCODED_B64_PATH)}"
            ),
            "artifact": ENCODED_B64_PATH,
        },
        {
            "event": "encoded_file_decode",
            "shell": (
                f"base64 -d {shlex.quote(ENCODED_B64_PATH)} > "
                f"{shlex.quote(ENCODED_RESTORED_PATH)}"
            ),
            "artifact": ENCODED_RESTORED_PATH,
        },
    ]


def _tmp_path(run_id: str, name: str) -> str:
    token = _safe_run_token(run_id)
    return f"/tmp/dsp_hb_{token}_{name}"


def resolve_webshell_target_host(params: dict[str, Any]) -> str | None:
    """Return the webshell server host from the user-provided webshell URL."""
    from dsp.runtime.scenario_plan import webshell_server_endpoint

    endpoint = webshell_server_endpoint(params)
    return endpoint.host if endpoint else None


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
        "eicar_lifecycle": build_eicar_lifecycle_steps(
            path=str(params.get("eicar_path") or default_eicar_path(run_id)),
            content=EICAR_TEST_STRING,
        ),
        "encoded_file_activity": build_encoded_file_activity_steps(),
        "eicar_variants": _build_eicar_variants(run_id),
        "suspicious_scripts": _build_suspicious_scripts(run_id),
        "persistence_artifacts": _build_persistence_artifacts(run_id),
        "archives": _build_archives(run_id),
    }
