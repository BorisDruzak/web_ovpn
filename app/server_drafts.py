"""Validated, public-only boundary between the web app and SSH draft worker."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
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
_SAFE_FINGERPRINT = re.compile(r"SHA256:[A-Za-z0-9+/]{43}$")
_SAFE_PUBLIC_KEY = re.compile(
    r"(?:ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp(?:256|384|521)) [A-Za-z0-9+/]+={0,3}(?: [^\r\n]+)?"
)
_CANONICAL_UTC = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$")
_PUBLIC_RESULT_FIELDS = frozenset({"status", "algorithm", "fingerprint", "checked_at", "pin_generation"})
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
    pin_generation: str | None = None


def make_draft_request(
    draft_id: str,
    host: str,
    ssh_user: str,
    port: int,
    action: str,
    expected_fingerprint: str | None = None,
    pin_generation: str | None = None,
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
    if pin_generation is not None:
        _validate_uuid(pin_generation)
    if action == "confirm" and (expected_fingerprint is None or pin_generation is None):
        raise ValueError("confirm requires a fingerprint and pin generation")
    if action == "check" and (expected_fingerprint is not None or pin_generation is None):
        raise ValueError("check requires only a pin generation")
    if action in {"scan", "cleanup"} and (expected_fingerprint is not None or pin_generation is not None):
        raise ValueError("action does not accept pin state")
    return DraftRequest(draft_id, action, host, ssh_user, port, expected_fingerprint, pin_generation)


def create_draft_request(queue_dir: Path, request: DraftRequest) -> Path:
    """Publish one immutable request without replacing a pending or active action."""
    validated = make_draft_request(
        request.id,
        request.host,
        request.ssh_user,
        request.port,
        request.action,
        request.expected_fingerprint,
        request.pin_generation,
    )
    payload: dict[str, Any] = {"id": validated.id, "action": validated.action}
    if validated.action != "cleanup":
        payload.update(
            host=validated.host,
            ssh_user=validated.ssh_user,
            port=validated.port,
        )
    if validated.expected_fingerprint is not None:
        payload["expected_fingerprint"] = validated.expected_fingerprint
    if validated.pin_generation is not None:
        payload["pin_generation"] = validated.pin_generation
    queue_path = Path(queue_dir)
    cleanup_path = queue_path / f"{validated.id}.cleanup.json"
    terminal_path = queue_path / f"{validated.id}.deleted"
    if validated.action == "cleanup":
        destination = cleanup_path
        if destination.is_file() or terminal_path.is_file():
            return destination if destination.is_file() else terminal_path
    else:
        if cleanup_path.is_file() or terminal_path.is_file():
            raise FileExistsError("draft cleanup is already reserved")
        destination = queue_path / f"{validated.id}.json"
    _exclusive_json_publish(destination, payload, REQUEST_FILE_MODE)
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
    try:
        safe_result = _validate_public_result(result)
    except ValueError:
        return {"status": "invalid_response"}
    return safe_result


def write_public_result(results_dir: Path, draft_id: str, result: dict[str, str]) -> Path:
    """Atomically save a result after enforcing its deliberately small schema."""
    _validate_uuid(draft_id)
    safe_result = _validate_public_result(result)
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
        parsed = UUID(value)
    except (ValueError, AttributeError, TypeError) as exc:
        raise ValueError("draft id must be a UUID") from exc
    if str(parsed) != value:
        raise ValueError("draft id must be a canonical UUID")


def _validate_public_result(result: object) -> dict[str, str]:
    if not isinstance(result, dict) or not all(isinstance(key, str) for key in result):
        raise ValueError("result must be an object")
    if not all(isinstance(value, str) for value in result.values()):
        raise ValueError("result values must be strings")
    if not set(result) <= _PUBLIC_RESULT_FIELDS or result.get("status") not in _SAFE_STATUSES:
        raise ValueError("result fields or status are not allowed")
    status = result["status"]
    fields = set(result)
    if status == "pending":
        if fields != {"status", "algorithm", "fingerprint"} or result["algorithm"] != "ssh-ed25519":
            raise ValueError("pending result is not an exact scan projection")
        _validate_fingerprint(result["fingerprint"])
    elif status == "ok" and fields != {"status"}:
        if fields != {"status", "fingerprint", "checked_at", "pin_generation"}:
            raise ValueError("completed pin is not an exact projection")
        _validate_fingerprint(result["fingerprint"])
        _validate_canonical_utc(result["checked_at"])
        _validate_uuid(result["pin_generation"])
    elif fields != {"status"}:
        raise ValueError("worker outcome must contain only its safe status")
    return dict(result)


def _validate_fingerprint(value: str) -> None:
    if not _SAFE_FINGERPRINT.fullmatch(value):
        raise ValueError("fingerprint must be an SSH SHA-256 fingerprint")


def _validate_canonical_utc(value: str) -> None:
    if not _CANONICAL_UTC.fullmatch(value):
        raise ValueError("checked_at must be canonical UTC")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("checked_at must be canonical UTC") from exc
    if parsed.tzinfo != timezone.utc:
        raise ValueError("checked_at must be canonical UTC")


def _exclusive_json_publish(path: Path, payload: dict[str, Any], mode: int) -> None:
    """Link a complete temp file into place; hard-link creation is exclusive."""
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as temporary_file:
            json.dump(payload, temporary_file, sort_keys=True)
            temporary_file.flush()
            os.fsync(temporary_file.fileno())
        os.chmod(temporary_path, mode)
        os.link(temporary_path, path)
        fsync_parent_directory(path)
    finally:
        try:
            temporary_path.unlink()
        except FileNotFoundError:
            pass


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
        fsync_parent_directory(path)
    except Exception:
        try:
            temporary_path.unlink()
        except FileNotFoundError:
            pass
        raise


def fsync_parent_directory(path: Path) -> None:
    """Persist a directory entry after a durable filesystem state transition.

    Windows does not expose the POSIX directory-fsync primitive used by the
    deployed Linux worker, so it is deliberately a no-op there.  On POSIX,
    failure is propagated: continuing would weaken the queue's durability
    contract.
    """
    if os.name == "nt":
        return
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    descriptor = os.open(os.fspath(path.parent), flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
