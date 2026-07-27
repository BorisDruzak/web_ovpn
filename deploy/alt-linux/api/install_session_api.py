from __future__ import annotations

import hmac
import json
import os
import re
from contextlib import nullcontext
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from alt_deploy.config import Settings
from alt_deploy.errors import ControlError
from alt_deploy.install_session_auth import verify_credential
from alt_deploy.install_session_repository import InstallSessionRepository
from alt_deploy.install_session_service import InstallSessionService
from alt_deploy.install_session_state import InstallSessionStageManager


_PATH_RE = re.compile(r"^/v1/install-sessions/(install-[A-Za-z0-9-]{4,64})/(status|heartbeat|plan|plan-signature)$")
_REPORTED_STAGES = frozenset({
    "agent_started",
    "inventory_validated",
    "waiting_for_approval",
    "plan_available",
    "plan_downloaded",
})


def create_install_session_server(
    settings: Settings,
    *,
    listen_address: str,
    listen_port: int,
) -> ThreadingHTTPServer:
    repository = InstallSessionRepository(settings)
    service = InstallSessionService(settings, repository=repository)

    class Handler(BaseHTTPRequestHandler):
        server_version = "ALTInstallSession/1.0"

        def log_message(self, format: str, *args: object) -> None:
            return

        def _send(self, status: int, payload: dict[str, object]) -> None:
            body = json.dumps(payload, ensure_ascii=True, sort_keys=True).encode("utf-8")
            self._send_bytes(status, body)

        def _send_bytes(self, status: int, body: bytes) -> None:
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(body)

        def _error(self, status: int, code: str) -> None:
            self._send(status, {"status": "error", "error": {"code": code}})

        def _body(self) -> object | None:
            if self.headers.get("Transfer-Encoding"):
                self._error(400, "chunked_not_supported")
                return None
            try:
                size = int(self.headers.get("Content-Length", ""))
            except ValueError:
                self._error(400, "invalid_content_length")
                return None
            if size < 1 or size > 65536:
                self._error(413, "invalid_payload_size")
                return None
            try:
                return json.loads(self.rfile.read(size).decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                self._error(400, "invalid_json")
                return None

        def _authorize(self, session_id: str) -> bool:
            header = self.headers.get("Authorization")
            if not header or not header.startswith("Bearer ") or header.count(" ") != 1:
                self._error(401, "authorization_required")
                return False
            try:
                expected = repository.load_credential_sha256(session_id)
            except ControlError as exc:
                self._error(404 if exc.code == "install_session_not_found" else 400, exc.code)
                return False
            if not verify_credential(header[7:], expected):
                self._error(403, "credential_forbidden")
                return False
            return True

        def do_POST(self) -> None:
            if "?" in self.path or len(self.path) > 4096:
                self._error(404, "not_found")
                return
            if self.path == "/v1/install-sessions":
                body = self._body()
                if body is None:
                    return
                try:
                    created = service.create(body, source_ip=self.client_address[0])
                except ControlError as exc:
                    self._error(403 if exc.code == "install_session_source_forbidden" else 400, exc.code)
                    return
                self._send(201, {"session_id": created.session_id, "credential": created.credential, "state": created.state, "poll_after_seconds": created.poll_after_seconds})
                return
            match = _PATH_RE.fullmatch(self.path)
            if not match or match.group(2) != "heartbeat":
                self._error(404, "not_found")
                return
            session_id = match.group(1)
            if not self._authorize(session_id):
                return
            body = self._body()
            if body is None:
                return
            if not isinstance(body, dict) or set(body) != {"schema_version", "boot_id", "agent_version", "sequence", "reported_stage", "sent_at"}:
                self._error(400, "heartbeat_invalid")
                return
            sequence = body.get("sequence")
            if (
                body.get("schema_version") != 1
                or type(sequence) is not int
                or sequence < 0
                or not all(
                    isinstance(body.get(key), str)
                    and 1 <= len(body[key]) <= 128
                    for key in {"boot_id", "agent_version", "reported_stage", "sent_at"}
                )
                or body["reported_stage"] not in _REPORTED_STAGES
            ):
                self._error(400, "heartbeat_invalid")
                return
            try:
                sent_at = datetime.fromisoformat(body["sent_at"])
            except ValueError:
                self._error(400, "heartbeat_invalid")
                return
            if sent_at.tzinfo is None:
                self._error(400, "heartbeat_invalid")
                return
            lock = nullcontext() if os.name == "nt" else __import__(
                "alt_deploy.locks", fromlist=["exclusive_lock"]
            ).exclusive_lock(settings.install_sessions_lock)
            with lock:
                status = repository.load_status(session_id)
                stages = InstallSessionStageManager(
                    repository, clock=lambda: datetime.now(timezone.utc).isoformat()
                )
                stages.validate_status(status)
                previous = status.get("agent_status")
                if isinstance(previous, dict) and sequence < previous.get("sequence", -1):
                    self._error(409, "heartbeat_conflict")
                    return
                if isinstance(previous, dict) and sequence == previous.get("sequence") and previous != body:
                    self._error(409, "heartbeat_conflict")
                    return
                if previous != body:
                    status["agent_status"] = body
                    status["last_seen_at"] = datetime.now(timezone.utc).isoformat()
                    status["updated_at"] = status["last_seen_at"]
                    stages.validate_status(status)
                    repository.replace_status(session_id, status)
            self._send(200, {"status": "ok"})

        def do_GET(self) -> None:
            if "?" in self.path or len(self.path) > 4096:
                self._error(404, "not_found")
                return
            match = _PATH_RE.fullmatch(self.path)
            if not match:
                self._error(404, "not_found")
                return
            session_id, operation = match.groups()
            if not self._authorize(session_id):
                return
            status = repository.load_status(session_id)
            if operation == "status":
                self._send(200, {key: value for key, value in status.items() if key not in {"source_ip", "agent_boot_id"}})
                return
            if status.get("state") == "cancelled":
                self._error(409, "session_cancelled")
                return
            if status.get("state") != "plan_published":
                self._error(409, "plan_not_available")
                return
            filename = "plan.json" if operation == "plan" else "plan-signature.json"
            try:
                payload = repository.read_revision_file(session_id, filename)
                plan = json.loads(repository.read_revision_file(session_id, "plan.json").decode("utf-8"))
                expires_at = datetime.fromisoformat(str(plan["expires_at"]))
            except (UnicodeDecodeError, json.JSONDecodeError, ControlError, KeyError, ValueError):
                self._error(500, "published_plan_invalid")
                return
            if expires_at <= datetime.now(timezone.utc):
                self._error(410, "plan_expired")
                return
            self._send_bytes(200, payload)

    return ThreadingHTTPServer((listen_address, listen_port), Handler)
