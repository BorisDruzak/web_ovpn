from __future__ import annotations

import argparse
import hashlib
import json
import re
from collections.abc import Sequence
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from alt_deploy.config import Settings
from alt_deploy.errors import ControlError
from alt_deploy.install_execution import ExecutionAuthorizationService
from alt_deploy.install_session_auth import verify_credential
from alt_deploy.install_session_repository import InstallSessionRepository
from alt_deploy.install_session_state import validate_execution_status
from alt_deploy.install_tls import (
    TLSMaterial,
    create_execution_server_context,
    load_execution_tls_material,
)


INSTALL_EXECUTION_LISTEN_ADDRESS = "192.168.100.17"
INSTALL_EXECUTION_LISTEN_PORT = 18092
_SESSION_ID = r"install-\d{8}T\d{6}Z-[0-9a-f]{8}"
_MANIFEST_PATH_RE = re.compile(
    rf"^/v2/install-sessions/({_SESSION_ID})/execution/manifest$"
)
_ARTIFACT_PATH_RE = re.compile(
    rf"^/v2/install-sessions/({_SESSION_ID})/execution/artifacts/"
    r"(autoinstall\.scm|vm-profile\.scm|pkg-groups\.tar|install-scripts\.tar)$"
)
_CLAIM_PATH_RE = re.compile(
    rf"^/v2/install-sessions/({_SESSION_ID})/execution/claim$"
)
_MAX_MANIFEST_BYTES = 1024 * 1024
_MAX_ARTIFACT_BYTES = 64 * 1024 * 1024


def _http_status(exc: ControlError) -> int:
    if exc.code == "install_session_not_found":
        return 404
    if exc.code == "execution_expired":
        return 410
    if exc.code in {
        "install_session_storage_failed",
        "install_session_status_commit_uncertain",
    }:
        return 500
    return 409


def create_execution_tls_server(
    settings: Settings,
    material: TLSMaterial,
    *,
    listen_port: int | None = None,
    credential_key_path: Path | None = None,
) -> ThreadingHTTPServer:
    repository = InstallSessionRepository(settings)
    execution = ExecutionAuthorizationService(
        settings,
        repository=repository,
        clock=lambda: datetime.now(timezone.utc).isoformat(),
    )

    class Handler(BaseHTTPRequestHandler):
        server_version = "ALTInstallExecution/1.0"

        def log_message(self, format: str, *args: object) -> None:
            return

        def _send_bytes(
            self,
            status: int,
            body: bytes,
            *,
            content_type: str,
        ) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(body)

        def _send_json(
            self, status: int, payload: dict[str, object]
        ) -> None:
            body = json.dumps(
                payload,
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
            self._send_bytes(
                status,
                body,
                content_type="application/json; charset=utf-8",
            )

        def _error(self, status: int, code: str) -> None:
            self._send_json(
                status,
                {"status": "error", "error": {"code": code}},
            )

        def _authorize(self, session_id: str) -> bool:
            header = self.headers.get("Authorization")
            if (
                not header
                or not header.startswith("Bearer ")
                or header.count(" ") != 1
            ):
                self._error(401, "authorization_required")
                return False
            try:
                expected = repository.load_credential_sha256(session_id)
            except ControlError as exc:
                self._error(_http_status(exc), exc.code)
                return False
            if not verify_credential(header[7:], expected):
                self._error(403, "credential_forbidden")
                return False
            return True

        def _execution_available(self, session_id: str) -> bool:
            try:
                status = repository.load_status(session_id)
                execution_status = status.get("execution")
                if (
                    status.get("state") != "plan_published"
                    or not isinstance(execution_status, dict)
                ):
                    self._error(409, "execution_not_authorized")
                    return False
                validate_execution_status(execution_status)
                state = execution_status.get("state")
                if state == "expired":
                    self._error(410, "execution_expired")
                    return False
                if state not in {"authorized", "claimed"}:
                    self._error(409, "execution_unavailable")
                    return False
                expires_at = datetime.fromisoformat(
                    str(execution_status["expires_at"])
                )
                if (
                    expires_at.tzinfo is None
                    or expires_at <= datetime.now(timezone.utc)
                ):
                    self._error(410, "execution_expired")
                    return False
                return True
            except (KeyError, TypeError, ValueError):
                self._error(409, "execution_status_invalid")
                return False
            except ControlError as exc:
                self._error(_http_status(exc), exc.code)
                return False

        def _read_execution(
            self,
            session_id: str,
            filename: str,
            *,
            maximum: int,
        ) -> bytes | None:
            try:
                files = repository.read_execution_files(session_id)
                body = files[filename]
                status = repository.load_status(session_id)
                execution_status = status["execution"]
                if (
                    not isinstance(execution_status, dict)
                    or hashlib.sha256(
                        files["execution-manifest.json"]
                    ).hexdigest()
                    != execution_status.get("manifest_sha256")
                    or not 1 <= len(body) <= maximum
                ):
                    raise ValueError
                return body
            except (KeyError, TypeError, ValueError):
                self._error(409, "execution_bundle_invalid")
                return None
            except ControlError as exc:
                self._error(_http_status(exc), "execution_bundle_invalid")
                return None

        def do_GET(self) -> None:
            if "?" in self.path or len(self.path) > 4096:
                self._error(404, "not_found")
                return
            if self.path == "/health":
                self._send_json(
                    200,
                    {
                        "schema_version": 1,
                        "service": "alt-install-execution",
                        "status": "ok",
                    },
                )
                return
            manifest_match = _MANIFEST_PATH_RE.fullmatch(self.path)
            artifact_match = _ARTIFACT_PATH_RE.fullmatch(self.path)
            match = manifest_match or artifact_match
            if match is None:
                self._error(404, "not_found")
                return
            session_id = match.group(1)
            if (
                not self._authorize(session_id)
                or not self._execution_available(session_id)
            ):
                return
            filename = (
                "execution-manifest.json"
                if manifest_match is not None
                else match.group(2)
            )
            body = self._read_execution(
                session_id,
                filename,
                maximum=(
                    _MAX_MANIFEST_BYTES
                    if manifest_match is not None
                    else _MAX_ARTIFACT_BYTES
                ),
            )
            if body is None:
                return
            self._send_bytes(
                200,
                body,
                content_type=(
                    "application/json; charset=utf-8"
                    if manifest_match is not None
                    else "application/octet-stream"
                ),
            )

        def do_POST(self) -> None:
            if "?" in self.path or len(self.path) > 4096:
                self._error(404, "not_found")
                return
            match = _CLAIM_PATH_RE.fullmatch(self.path)
            if match is None:
                self._error(404, "not_found")
                return
            session_id = match.group(1)
            if not self._authorize(session_id):
                return
            if self.headers.get("Transfer-Encoding"):
                self._error(400, "claim_body_forbidden")
                return
            try:
                content_length = int(
                    self.headers.get("Content-Length", "0")
                )
            except ValueError:
                self._error(400, "claim_body_forbidden")
                return
            if content_length != 0:
                self._error(400, "claim_body_forbidden")
                return
            try:
                claimed = execution.claim(session_id)
            except ControlError as exc:
                self._error(_http_status(exc), exc.code)
                return
            execution_status = claimed.get("execution")
            state = (
                execution_status.get("state")
                if isinstance(execution_status, dict)
                else None
            )
            if state != "claimed":
                self._error(500, "execution_claim_invalid")
                return
            self._send_json(
                200,
                {
                    "status": "ok",
                    "execution": {"state": "claimed"},
                },
            )

    server = ThreadingHTTPServer(
        (settings.install_execution_listen_address, listen_port or settings.install_execution_listen_port),
        Handler,
    )
    server.socket = create_execution_server_context(
        material, key_path=credential_key_path
    ).wrap_socket(server.socket, server_side=True)
    return server


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--listen-address", required=True)
    parser.add_argument("--listen-port", required=True, type=int)
    parser.add_argument("--credential-key", required=True)
    parsed = parser.parse_args(argv)
    if parsed.listen_address != INSTALL_EXECUTION_LISTEN_ADDRESS:
        parser.error("listen address must be 192.168.100.17")
    if parsed.listen_port != INSTALL_EXECUTION_LISTEN_PORT:
        parser.error("listen port must be 18092")
    settings = Settings.from_env()
    if (
        settings.install_execution_listen_address != INSTALL_EXECUTION_LISTEN_ADDRESS
        or settings.install_execution_listen_port != INSTALL_EXECUTION_LISTEN_PORT
    ):
        parser.error("configured V2 listener does not match fixed endpoint")
    material = load_execution_tls_material(settings)
    server = create_execution_tls_server(
        settings,
        material,
        listen_port=parsed.listen_port,
        credential_key_path=Path(parsed.credential_key),
    )
    try:
        server.serve_forever()
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
