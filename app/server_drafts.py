"""Validated, public-only boundary between the web app and SSH draft worker."""

from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
import tempfile
from typing import Any
from uuid import UUID


REQUEST_FILE_MODE = 0o640
_SAFE_SSH_USER = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}$")
_SAFE_SSH_HOST = re.compile(r"[A-Za-z0-9][A-Za-z0-9.-]{0,253}$")
_SAFE_ACTIONS = frozenset({"scan", "confirm", "check", "cleanup"})
_SAFE_FINGERPRINT = re.compile(r"SHA256:[A-Za-z0-9+/]{1,86}={0,2}$")
_SAFE_PUBLIC_KEY = re.compile(
    r"(?:ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp(?:256|384|521)) [A-Za-z0-9+/]+={0,3}(?: [^\r\n]+)?"
)
_PUBLIC_RESULT_FIELDS = frozenset({"status", "algorithm", "fingerprint", "checked_at"})
_SAFE_STATUSES = frozenset(
    {"pending", "ok", "timeout", "host_key_mismatch", "authentication", "transport", "invalid_response"}
)


@dataclass(frozen=True)
class DraftRequest:
    id: str
    action: str
    host: str
    ssh_user: str
    port: int
    expected_fingerprint: str | None = None


def make_draft_request(
    draft_id: str,
    host: str,
    ssh_user: str,
    port: int,
    action: str,
    expected_fingerprint: str | None = None,
) -> DraftRequest:
    """Build a request after rejecting data that cannot be SSH arguments."""
    _validate_uuid(draft_id)
    if not isinstance(host, str) or not _SAFE_SSH_HOST.fullmatch(host):
        raise ValueError("host must be a safe SSH destination component")
    if not isinstance(ssh_user, str) or not _SAFE_SSH_USER.fullmatch(ssh_user):
        raise ValueError("ssh_user must be a safe SSH destination component")
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        raise ValueError("port must be between 1 and 65535")
    if action not in _SAFE_ACTIONS:
        raise ValueError("action is not allowed")
    if expected_fingerprint is not None and (
        not isinstance(expected_fingerprint, str) or not _SAFE_FINGERPRINT.fullmatch(expected_fingerprint)
    ):
        raise ValueError("expected_fingerprint must be an SSH SHA-256 fingerprint")
    return DraftRequest(draft_id, action, host, ssh_user, port, expected_fingerprint)


def create_draft_request(queue_dir: Path, request: DraftRequest) -> Path:
    """Atomically place a validated, public-only request in the worker queue."""
    validated = make_draft_request(
        request.id,
        request.host,
        request.ssh_user,
        request.port,
        request.action,
        request.expected_fingerprint,
    )
    payload: dict[str, Any] = {
        "id": validated.id,
        "action": validated.action,
        "host": validated.host,
        "ssh_user": validated.ssh_user,
        "port": validated.port,
    }
    if validated.expected_fingerprint is not None:
        payload["expected_fingerprint"] = validated.expected_fingerprint
    destination = Path(queue_dir) / f"{validated.id}.json"
    _atomic_json_write(destination, payload, REQUEST_FILE_MODE)
    return destination


def read_public_result(results_dir: Path, draft_id: str) -> dict[str, str]:
    """Return the narrow public result projection, never worker diagnostics."""
    _validate_uuid(draft_id)
    path = Path(results_dir) / f"{draft_id}.json"
    try:
        result = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {"status": "pending"}
    except (OSError, json.JSONDecodeError, UnicodeDecodeError):
        return {"status": "invalid_response"}
    if not isinstance(result, dict) or result.get("status") not in _SAFE_STATUSES:
        return {"status": "invalid_response"}
    return {
        field: value
        for field, value in result.items()
        if field in _PUBLIC_RESULT_FIELDS and isinstance(value, str)
    }


def write_public_result(results_dir: Path, draft_id: str, result: dict[str, str]) -> Path:
    """Atomically save a result after enforcing its deliberately small schema."""
    _validate_uuid(draft_id)
    if not isinstance(result, dict) or result.get("status") not in _SAFE_STATUSES:
        raise ValueError("result status is not allowed")
    safe_result = {
        field: value
        for field, value in result.items()
        if field in _PUBLIC_RESULT_FIELDS and isinstance(value, str)
    }
    if safe_result.get("status") != result["status"]:
        raise ValueError("result status is not allowed")
    path = Path(results_dir) / f"{draft_id}.json"
    _atomic_json_write(path, safe_result, REQUEST_FILE_MODE)
    return path


def observer_public_key(path: Path) -> str:
    """Read one OpenSSH public-key line without ever accepting private material."""
    try:
        key = Path(path).read_text(encoding="utf-8").strip()
    except (OSError, UnicodeDecodeError) as exc:
        raise ValueError("observer public key is unavailable") from exc
    if not _SAFE_PUBLIC_KEY.fullmatch(key):
        raise ValueError("observer key must be one OpenSSH public key")
    return f"{key}\n"


def _validate_uuid(value: str) -> None:
    if not isinstance(value, str):
        raise ValueError("draft id must be a UUID")
    try:
        UUID(value)
    except (ValueError, AttributeError, TypeError) as exc:
        raise ValueError("draft id must be a UUID") from exc


def _atomic_json_write(path: Path, payload: dict[str, Any], mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as temporary_file:
            json.dump(payload, temporary_file, sort_keys=True)
            temporary_file.flush()
            os.fsync(temporary_file.fileno())
        os.chmod(temporary_path, mode)
        os.replace(temporary_path, path)
    except Exception:
        try:
            temporary_path.unlink()
        except FileNotFoundError:
            pass
        raise
