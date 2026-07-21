from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .errors import ControlError

REGISTRATION_ID_RE = re.compile(r"^reg-[0-9a-f]{32}$")
ACTIVE_REGISTRATION_STATES = (
    "pending",
    "ready",
    "failed",
)
MAX_REGISTRATION_RECORD_BYTES = 1_048_576


@dataclass(frozen=True)
class RegistrationGeneration:
    value: str
    legacy: bool


@dataclass(frozen=True)
class MachineIdentity:
    machine_key: str
    machine_uuid: str
    mac: str


@dataclass(frozen=True)
class RegistrationCandidate:
    path: Path
    registration_state: str
    machine_key: str
    machine_uuid: str
    hostname: str
    ip: str
    mac: str
    registered_at: str
    status: str
    generation: RegistrationGeneration
    raw_bytes: bytes
    payload: dict[str, Any]


def registration_generation(
    payload: dict[str, Any],
    raw_bytes: bytes,
) -> RegistrationGeneration:
    value = str(
        payload.get("registration_id") or ""
    ).strip().lower()

    if value:
        if not REGISTRATION_ID_RE.fullmatch(value):
            raise ControlError(
                code="machine_record_invalid",
                message=(
                    "Registration record has an invalid "
                    "generation identifier"
                ),
                exit_code=4,
            )

        return RegistrationGeneration(
            value=value,
            legacy=False,
        )

    digest = hashlib.sha256(raw_bytes).hexdigest()
    return RegistrationGeneration(
        value=f"legacy-sha256:{digest}",
        legacy=True,
    )


def _unsafe_record(message: str) -> ControlError:
    return ControlError(
        code="machine_record_unsafe",
        message=message,
        exit_code=4,
    )


def _read_regular_bytes(path: Path) -> bytes:
    try:
        before_open = path.lstat()
    except OSError as exc:
        raise _unsafe_record(
            "Registration record cannot be inspected safely"
        ) from exc

    if not stat.S_ISREG(before_open.st_mode):
        raise _unsafe_record(
            "Registration record is not a regular file"
        )

    if before_open.st_size > MAX_REGISTRATION_RECORD_BYTES:
        raise _unsafe_record(
            "Registration record exceeds the safe size limit"
        )

    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW

    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise _unsafe_record(
            "Registration record cannot be opened safely"
        ) from exc

    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode):
            raise _unsafe_record(
                "Registration record is not a regular file"
            )

        if (
            opened.st_dev != before_open.st_dev
            or opened.st_ino != before_open.st_ino
        ):
            raise _unsafe_record(
                "Registration record changed during safe open"
            )

        if opened.st_size > MAX_REGISTRATION_RECORD_BYTES:
            raise _unsafe_record(
                "Registration record exceeds the safe size limit"
            )

        chunks: list[bytes] = []
        total = 0

        while True:
            chunk = os.read(descriptor, 64 * 1024)
            if not chunk:
                break

            total += len(chunk)
            if total > MAX_REGISTRATION_RECORD_BYTES:
                raise _unsafe_record(
                    "Registration record exceeds the safe size limit"
                )
            chunks.append(chunk)

        after_read = os.fstat(descriptor)
        if (
            after_read.st_dev != opened.st_dev
            or after_read.st_ino != opened.st_ino
            or after_read.st_size != opened.st_size
            or total != after_read.st_size
        ):
            raise _unsafe_record(
                "Registration record changed while being read"
            )

        return b"".join(chunks)
    finally:
        os.close(descriptor)


def load_registration_candidate(
    path: Path,
    registration_state: str,
) -> RegistrationCandidate:
    if registration_state not in ACTIVE_REGISTRATION_STATES:
        raise ControlError(
            code="machine_record_invalid",
            message=(
                "Registration record has an invalid state directory"
            ),
            exit_code=4,
        )

    raw_bytes = _read_regular_bytes(path)

    try:
        decoded = json.loads(raw_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ControlError(
            code="machine_record_invalid",
            message=(
                "Registration record is not valid UTF-8 JSON"
            ),
            exit_code=4,
        ) from exc

    if not isinstance(decoded, dict):
        raise ControlError(
            code="machine_record_invalid",
            message=(
                "Registration record must be a JSON object"
            ),
            exit_code=4,
        )

    machine_key = str(
        decoded.get("machine_key") or ""
    ).strip().lower()
    machine_uuid = str(
        decoded.get("uuid") or machine_key
    ).strip().lower()
    mac = str(
        decoded.get("mac") or ""
    ).strip().lower()

    if not machine_key or not machine_uuid:
        raise ControlError(
            code="machine_record_invalid",
            message="Registration record identity is missing",
            exit_code=4,
        )

    return RegistrationCandidate(
        path=path,
        registration_state=registration_state,
        machine_key=machine_key,
        machine_uuid=machine_uuid,
        hostname=str(decoded.get("hostname") or ""),
        ip=str(decoded.get("ip") or ""),
        mac=mac,
        registered_at=str(
            decoded.get("registered_at") or ""
        ),
        status=str(
            decoded.get("status") or registration_state
        ),
        generation=registration_generation(
            decoded,
            raw_bytes,
        ),
        raw_bytes=raw_bytes,
        payload=dict(decoded),
    )
