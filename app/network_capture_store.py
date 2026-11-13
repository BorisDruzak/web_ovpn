from __future__ import annotations

import hashlib
import json
import os
import stat
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID, uuid4

from fastapi import HTTPException, Response

from .export_artifacts import ExportLimit, storage_lock
from .network_capture import CAPTURE_MAX_KIB, capture_packets
from .network_probe_profiles import CaptureProfile

CAPTURE_DIRECTORY = Path("/run/ui-vpn-network-captures")
CAPTURE_TTL = timedelta(minutes=30)
MAX_CAPTURE_ARTIFACTS = 32


def _store_available() -> bool:
    try:
        info = CAPTURE_DIRECTORY.lstat()
    except OSError:
        return False
    return stat.S_ISDIR(info.st_mode) and (
        os.name == "nt" or info.st_uid == os.geteuid() and info.st_mode & 0o077 == 0
    )


def _paths(capture_id: UUID) -> tuple[Path, Path]:
    return CAPTURE_DIRECTORY / f"{capture_id}.pcap", CAPTURE_DIRECTORY / f"{capture_id}.json"


def _owner_key(owner: str) -> str:
    return hashlib.sha256(owner.encode()).hexdigest()


def _receipt(path: Path, now: datetime) -> dict | None:
    try:
        if path.is_symlink() or not 0 < path.stat().st_size <= 2048:
            return None
        receipt = json.loads(path.read_bytes())
        if not isinstance(receipt, dict) or receipt["capture_id"] != path.stem:
            return None
        expires_at = datetime.fromisoformat(receipt["expires_at"])
        size = receipt["size_bytes"]
        if expires_at <= now or type(size) is not int or not 24 <= size <= CAPTURE_MAX_KIB * 1024:
            return None
        return receipt
    except (OSError, TypeError, ValueError, KeyError):
        return None


def _purge(now: datetime) -> None:
    for path in CAPTURE_DIRECTORY.iterdir():
        if path.suffix not in {".pcap", ".json"}:
            continue
        try:
            capture_id = UUID(path.stem)
        except ValueError:
            continue
        if str(capture_id) == path.stem and _receipt(_paths(capture_id)[1], now) is None:
            path.unlink(missing_ok=True)


def purge_captures(*, now: datetime | None = None) -> None:
    try:
        if _store_available():
            with storage_lock(CAPTURE_DIRECTORY, timeout=0):
                _purge(now or datetime.now(UTC))
    except (OSError, ExportLimit):
        pass


def create_capture(owner: str, profile: CaptureProfile, *, now: datetime | None = None) -> dict:
    if not _store_available():
        return {"status": "unavailable", "result": {"error": "capture_storage_unavailable"}}
    try:
        with storage_lock(CAPTURE_DIRECTORY, timeout=0):
            return _capture_to_store(owner, profile, now or datetime.now(UTC))
    except ExportLimit:
        return {"status": "busy", "result": {}}
    except OSError:
        return {"status": "unavailable", "result": {"error": "capture_storage_unavailable"}}


def _capture_to_store(owner: str, profile: CaptureProfile, started: datetime) -> dict:
    capture_id = uuid4()
    output, metadata = _paths(capture_id)
    try:
        _purge(started)
        if sum(1 for _ in CAPTURE_DIRECTORY.glob("*.json")) >= MAX_CAPTURE_ARTIFACTS:
            return {"status": "busy", "result": {"error": "capture_storage_full"}}
        reading = capture_packets(output, **profile.model_dump(exclude={"label"}))
        if reading["status"] != "ok":
            output.unlink(missing_ok=True)
            error = reading.get("error", "capture_failed")
            status = "unavailable" if error.endswith("_unavailable") else "failed"
            return {"status": status, "result": {"error": error}}
        receipt = {
            "capture_id": str(capture_id),
            "label": profile.label,
            "filter": profile.model_dump(include={"interface", "peer", "port", "protocol"}),
            "size_bytes": reading["size_bytes"],
            "packets": reading["packets"],
            "expires_at": (started + CAPTURE_TTL).isoformat(),
        }
        with os.fdopen(os.open(metadata, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600), "w", encoding="utf-8") as file:
            json.dump({**receipt, "owner": _owner_key(owner)}, file)
        return {"status": "captured" if receipt["packets"] else "empty_capture", "result": receipt}
    except (OSError, ValueError):
        for path in (output, metadata):
            try:
                path.unlink(missing_ok=True)
            except OSError:
                pass
        return {"status": "failed", "result": {"error": "capture_storage_failed"}}


def list_captures(owner: str, *, now: datetime | None = None) -> list[dict]:
    if not _store_available():
        return []
    owner_key = _owner_key(owner)
    at = now or datetime.now(UTC)
    try:
        rows = [_receipt(path, at) for path in CAPTURE_DIRECTORY.glob("*.json")]
    except OSError:
        return []
    return sorted(
        [{key: value for key, value in row.items() if key != "owner"}
         for row in rows if row is not None and row.get("owner") == owner_key],
        key=lambda row: row["expires_at"], reverse=True,
    )


def read_capture(capture_id: UUID, owner: str, *, now: datetime | None = None) -> bytes | None:
    if not _store_available():
        return None
    output, metadata = _paths(capture_id)
    receipt = _receipt(metadata, now or datetime.now(UTC))
    if receipt is None or receipt.get("owner") != _owner_key(owner):
        return None
    try:
        if output.is_symlink():
            return None
        with output.open("rb") as file:
            payload = file.read(receipt["size_bytes"] + 1)
        return payload if len(payload) == receipt["size_bytes"] else None
    except OSError:
        return None


def download_capture(capture_id: UUID, owner: str) -> Response:
    payload = read_capture(capture_id, owner)
    if payload is None:
        raise HTTPException(status_code=404, detail="Capture not found or expired")
    return Response(
        payload, media_type="application/vnd.tcpdump.pcap",
        headers={
            "Content-Disposition": f'attachment; filename="network-{capture_id}.pcap"',
            "Cache-Control": "private, no-store",
            "X-Content-Type-Options": "nosniff",
        },
    )
