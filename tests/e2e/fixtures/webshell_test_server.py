"""Local disposable HTTP server that simulates the webshell transport contract."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
import urllib.parse
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from tests.e2e.fixtures.bundle_helpers import remote_bundle_path_for_run


@dataclass
class WebshellTestServer:
    """In-process HTTP server for webshell E2E tests — no external network."""

    host: str = "127.0.0.1"
    port: int = 0
    storage_dir: Path | None = None
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
                    status = 200 if payload else 404
                    self._respond(status, payload)
                    return
                if "cmd" in params:
                    server._handle_command(params["cmd"][0])
                    self._respond(200, b"ok")
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
                        server._handle_command(params["cmd"][0])
                        self._respond(200, b"ok")
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

    def _handle_command(self, command_line: str) -> None:
        self._command_calls.append(command_line)
        if command_line.startswith("mkdir -p "):
            remote_dir = command_line[len("mkdir -p ") :].strip()
            storage_root = self.storage_dir or Path("/tmp/dsp-test-server")
            (storage_root / remote_dir.lstrip("/")).mkdir(parents=True, exist_ok=True)
            return
        if command_line.startswith("python3 "):
            script_path = command_line[len("python3 ") :].strip()
            self._execute_bundle_script(script_path)
            return

    def _execute_bundle_script(self, remote_script_path: str) -> None:
        storage_root = self.storage_dir or Path("/tmp/dsp-test-server")
        local_script = self._resolve_local_path(storage_root, remote_script_path)
        if not local_script.is_file():
            script_bytes = self._files.get(remote_script_path)
            if script_bytes is None:
                raise RuntimeError(f"bundle script not found: {remote_script_path}")
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
        if completed.returncode != 0:
            raise RuntimeError(
                f"bundle script failed ({completed.returncode}): {completed.stderr or completed.stdout}"
            )

        manifest_path = local_script.parent / "manifest.json"
        if manifest_path.is_file():
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            paths = manifest.get("paths") or {}
            bundle_path = str(paths.get("bundle") or "")
            local_bundle = local_script.parent / "events.jsonl"
            if local_bundle.is_file() and bundle_path:
                self._files[bundle_path] = local_bundle.read_bytes()
                self._files[remote_bundle_path_for_run(str(manifest["run_id"]))] = (
                    local_bundle.read_bytes()
                )

    @staticmethod
    def _resolve_local_path(storage_root: Path, remote_path: str) -> Path:
        normalized = remote_path.lstrip("/")
        if normalized.startswith("tmp/"):
            return storage_root / normalized
        return storage_root / normalized

    def _handle_upload(self, body: bytes, content_type: str) -> None:
        boundary = _extract_boundary(content_type)
        remote_path = _extract_form_field(body, boundary, "remote_path")
        file_bytes = _extract_file_bytes(body, boundary)
        if remote_path:
            self._upload_calls.append(remote_path)
            self._files[remote_path] = file_bytes
            storage_root = self.storage_dir or Path("/tmp/dsp-test-server")
            local_path = self._resolve_local_path(storage_root, remote_path)
            local_path.parent.mkdir(parents=True, exist_ok=True)
            local_path.write_bytes(file_bytes)


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
