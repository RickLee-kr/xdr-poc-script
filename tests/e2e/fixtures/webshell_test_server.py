"""Local disposable HTTP server that simulates the webshell transport contract."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import subprocess
import sys
import threading
import urllib.parse
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from tests.e2e.fixtures.bundle_helpers import remote_bundle_path_for_run


@dataclass
class WebshellTestServer:
    """In-process HTTP server for webshell E2E tests — no external network."""

    host: str = "127.0.0.1"
    port: int = 0
    storage_dir: Path | None = None
    ignore_multipart_upload: bool = False
    ignore_command_upload: bool = False
    _files: dict[str, bytes] = field(default_factory=dict)
    _command_calls: list[str] = field(default_factory=list)
    _download_calls: list[str] = field(default_factory=list)
    _upload_calls: list[str] = field(default_factory=list)
    _httpd: ThreadingHTTPServer | None = field(default=None, init=False, repr=False)
    _thread: threading.Thread | None = field(default=None, init=False, repr=False)

    @property
    def webshell_url(self) -> str:
        if self._httpd is None:
            raise RuntimeError("server is not started")
        return f"http://{self.host}:{self._httpd.server_address[1]}/shell.jsp"

    @property
    def command_calls(self) -> list[str]:
        return list(self._command_calls)

    @property
    def download_calls(self) -> list[str]:
        return list(self._download_calls)

    @property
    def upload_calls(self) -> list[str]:
        return list(self._upload_calls)

    def start(self) -> str:
        server = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, format: str, *args: object) -> None:
                return

            def do_GET(self) -> None:
                parsed = urllib.parse.urlparse(self.path)
                params = urllib.parse.parse_qs(parsed.query)
                if "remote_path" in params:
                    remote_path = params["remote_path"][0]
                    server._download_calls.append(remote_path)
                    payload = server._files.get(remote_path, b"")
                    self._respond(200, payload)
                    return
                if "cmd" in params:
                    output = server._handle_command(params["cmd"][0])
                    self._respond(200, output if output else b"ok")
                    return
                self._respond(200, b"ok")

            def do_POST(self) -> None:
                content_type = self.headers.get("Content-Type", "")
                content_length = int(self.headers.get("Content-Length", "0"))
                body = self.rfile.read(content_length) if content_length else b""
                if content_type.startswith("multipart/form-data"):
                    server._handle_upload(body, content_type)
                    self._respond(200, b"uploaded")
                    return
                if content_type.startswith("application/x-www-form-urlencoded"):
                    params = urllib.parse.parse_qs(body.decode("utf-8"))
                    if "cmd" in params:
                        output = server._handle_command(params["cmd"][0])
                        self._respond(200, output if output else b"ok")
                        return
                self._respond(400, b"unsupported post")

            def _respond(self, status: int, payload: bytes) -> None:
                self.send_response(status)
                self.send_header("Content-Type", "application/octet-stream")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

        self._httpd = ThreadingHTTPServer((self.host, self.port), Handler)
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._thread.start()
        return self.webshell_url

    def stop(self) -> None:
        if self._httpd is not None:
            self._httpd.shutdown()
            self._httpd.server_close()
            self._httpd = None
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None

    def _handle_command(self, command_line: str) -> bytes:
        self._command_calls.append(command_line)
        if command_line.startswith("mkdir -p "):
            remote_dir = command_line[len("mkdir -p ") :].strip()
            storage_root = self.storage_dir or Path("/tmp/dsp-test-server")
            (storage_root / remote_dir.lstrip("/")).mkdir(parents=True, exist_ok=True)
            return b""
        if command_line.startswith(": >"):
            remote_path = command_line[3:].strip()
            self._write_remote_file(remote_path, b"")
            return b""
        if "base64 -d" in command_line and "echo '" in command_line:
            return self._handle_base64_write(command_line)
        if command_line.startswith("ls "):
            return self._handle_ls(command_line)
        if "wc -c <" in command_line:
            path_part = command_line.split("<", 1)[1]
            remote_path = _strip_shell_quotes(path_part.replace("2>&1", "").strip())
            payload = self._read_remote_file(remote_path)
            if payload is None:
                return f"wc: {remote_path}: No such file\n".encode()
            return f"{len(payload)}\n".encode()
        if command_line.startswith("sha256sum "):
            remote_path = _strip_shell_quotes(
                command_line[len("sha256sum ") :].replace("2>&1", "").strip()
            )
            payload = self._read_remote_file(remote_path)
            if payload is None:
                return f"sha256sum: {remote_path}: No such file or directory\n".encode()
            digest = hashlib.sha256(payload).hexdigest()
            return f"{digest}  {remote_path}\n".encode()
        if command_line.startswith("cat "):
            remote_path = _strip_shell_quotes(command_line[len("cat ") :].strip())
            payload = self._read_remote_file(remote_path)
            if payload is None:
                return f"cat: {remote_path}: No such file or directory\n".encode()
            return payload
        if command_line.startswith("python3 "):
            script_path = _strip_shell_quotes(
                command_line[len("python3 ") :].split(" 2>&1")[0].strip()
            )
            return self._execute_bundle_script(script_path)
        return b""

    def _handle_ls(self, command_line: str) -> bytes:
        stripped = command_line.strip().replace(" 2>&1", "")
        if stripped.startswith("ls -la "):
            remote_path = _strip_shell_quotes(stripped[7:].strip())
        elif stripped.startswith("ls -l "):
            remote_path = _strip_shell_quotes(stripped[6:].strip())
        elif stripped.startswith("ls "):
            remote_path = _strip_shell_quotes(stripped[3:].strip())
        else:
            return b""
        payload = self._read_remote_file(remote_path)
        if payload is None:
            if remote_path.endswith("/") or self._remote_dir_exists(remote_path):
                entries = self._list_remote_dir(remote_path.rstrip("/"))
                if not entries:
                    return b"total 0\n"
                lines = ["total 0"]
                for name in entries:
                    lines.append(f"-rw-r--r-- 1 root root {len(self._read_remote_file(name) or b'')} {name}")
                return ("\n".join(lines) + "\n").encode()
            return f"ls: cannot access '{remote_path}': No such file or directory\n".encode()
        return f"-rw-r--r-- 1 root root {len(payload)} {remote_path}\n".encode()

    def _list_remote_dir(self, remote_dir: str) -> list[str]:
        prefix = remote_dir.rstrip("/") + "/"
        return sorted(
            path
            for path in self._files
            if path.startswith(prefix) and "/" not in path[len(prefix) :]
        )

    def _remote_dir_exists(self, remote_dir: str) -> bool:
        prefix = remote_dir.rstrip("/") + "/"
        return any(path.startswith(prefix) for path in self._files)

    def _handle_base64_write(self, command_line: str) -> bytes:
        if self.ignore_command_upload:
            return b""
        match = re.search(
            r"echo '([^']*)' \| base64 -d (>>?)\s*(.+)$",
            command_line,
        )
        if match is None:
            return b""
        payload_b64 = match.group(1)
        append = match.group(2) == ">>"
        remote_path = _strip_shell_quotes(match.group(3).strip())
        chunk = base64.b64decode(payload_b64.encode("ascii"))
        if append:
            existing = self._read_remote_file(remote_path) or b""
            self._write_remote_file(remote_path, existing + chunk)
        else:
            self._write_remote_file(remote_path, chunk)
        return b""

    def _execute_bundle_script(self, remote_script_path: str) -> bytes:
        storage_root = self.storage_dir or Path("/tmp/dsp-test-server")
        local_script = self._resolve_local_path(storage_root, remote_script_path)
        if not local_script.is_file():
            script_bytes = self._files.get(remote_script_path)
            if script_bytes is None:
                return f"python3: can't open file '{remote_script_path}'\n".encode()
            local_script.parent.mkdir(parents=True, exist_ok=True)
            local_script.write_bytes(script_bytes)

        env = os.environ.copy()
        env["DSP_BUNDLE_DIR"] = str(local_script.parent)
        completed = subprocess.run(
            [sys.executable, str(local_script)],
            cwd=str(local_script.parent),
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )
        stdout = completed.stdout or ""
        stderr = completed.stderr or ""
        combined = stdout + stderr

        manifest_path = local_script.parent / "manifest.json"
        if completed.returncode == 0 and manifest_path.is_file():
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            paths = manifest.get("paths") or {}
            bundle_path = str(paths.get("bundle") or "")
            local_bundle = local_script.parent / "events.jsonl"
            if local_bundle.is_file() and bundle_path:
                self._files[bundle_path] = local_bundle.read_bytes()
                self._files[remote_bundle_path_for_run(str(manifest["run_id"]))] = (
                    local_bundle.read_bytes()
                )
        return combined.encode()

    def _read_remote_file(self, remote_path: str) -> bytes | None:
        if remote_path in self._files:
            return self._files[remote_path]
        storage_root = self.storage_dir or Path("/tmp/dsp-test-server")
        local_path = self._resolve_local_path(storage_root, remote_path)
        if local_path.is_file():
            return local_path.read_bytes()
        return None

    def _write_remote_file(self, remote_path: str, payload: bytes) -> None:
        self._files[remote_path] = payload
        storage_root = self.storage_dir or Path("/tmp/dsp-test-server")
        local_path = self._resolve_local_path(storage_root, remote_path)
        local_path.parent.mkdir(parents=True, exist_ok=True)
        local_path.write_bytes(payload)

    @staticmethod
    def _resolve_local_path(storage_root: Path, remote_path: str) -> Path:
        normalized = remote_path.lstrip("/")
        return storage_root / normalized

    def _handle_upload(self, body: bytes, content_type: str) -> None:
        boundary = _extract_boundary(content_type)
        remote_path = _extract_form_field(body, boundary, "remote_path")
        file_bytes = _extract_file_bytes(body, boundary)
        if remote_path:
            self._upload_calls.append(remote_path)
            if self.ignore_multipart_upload:
                return
            self._write_remote_file(remote_path, file_bytes)


def _extract_boundary(content_type: str) -> str:
    for part in content_type.split(";"):
        part = part.strip()
        if part.startswith("boundary="):
            return part.split("=", 1)[1]
    raise ValueError("multipart boundary missing")


def _extract_form_field(body: bytes, boundary: str, name: str) -> str:
    marker = f'name="{name}"'.encode()
    if marker not in body:
        return ""
    section = body.split(marker, 1)[1]
    value = section.split(b"\r\n\r\n", 1)[1]
    return value.split(b"\r\n", 1)[0].decode("utf-8")


def _extract_file_bytes(body: bytes, boundary: str) -> bytes:
    marker = b'name="file"'
    if marker not in body:
        return b""
    section = body.split(marker, 1)[1]
    payload = section.split(b"\r\n\r\n", 1)[1]
    return payload.split(f"\r\n--{boundary}".encode(), 1)[0]


def _strip_shell_quotes(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        return value[1:-1]
    return value
