#!/usr/bin/env python3
"""Strict, validation-only gate for an ALT execution pilot record."""

from __future__ import annotations

import argparse
from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import sys
from typing import Any, Sequence
from uuid import UUID


_TOP_LEVEL_FIELDS = {
    "schema_version",
    "asset_id",
    "dmi_uuid",
    "disk",
    "iso_sha256",
    "maintenance_window",
    "rollback_owner",
}
_DISK_FIELDS = {"fingerprint", "path"}
_WINDOW_FIELDS = {"starts_at", "ends_at"}
_ASSET_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:+-]{0,127}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_FINGERPRINT_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_DISK_PATH_RE = re.compile(
    r"^/dev/(?:disk/by-id/)?[A-Za-z0-9][A-Za-z0-9._:+-]{0,255}$"
)
_UTC_SECOND_RE = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T"
    r"[0-9]{2}:[0-9]{2}:[0-9]{2}Z$"
)


@dataclass(frozen=True)
class PilotValidation:
    valid: bool
    code: str
    record: dict[str, Any] = field(default_factory=dict)
    record_sha256: str | None = None


def _invalid(code: str) -> PilotValidation:
    return PilotValidation(valid=False, code=code)


def _utc_second(value: object) -> datetime | None:
    if not isinstance(value, str) or not _UTC_SECOND_RE.fullmatch(value):
        return None
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )
    except ValueError:
        return None


def validate_pilot_record(
    path: Path,
    *,
    expected_iso_sha256: str,
) -> PilotValidation:
    """Validate declared identity strings without opening the declared disk."""
    if not _SHA256_RE.fullmatch(expected_iso_sha256):
        return _invalid("pilot_expected_iso_digest_invalid")
    try:
        raw = path.read_bytes()
        document = json.loads(raw)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return _invalid("pilot_record_invalid")
    if not isinstance(document, dict):
        return _invalid("pilot_record_invalid")
    if "maintenance_window" not in document:
        return _invalid("pilot_window_missing")
    if set(document) != _TOP_LEVEL_FIELDS:
        return _invalid("pilot_fields_invalid")
    if document.get("schema_version") != 1:
        return _invalid("pilot_schema_invalid")

    asset_id = document.get("asset_id")
    if (
        not isinstance(asset_id, str)
        or not _ASSET_ID_RE.fullmatch(asset_id)
    ):
        return _invalid("pilot_asset_id_invalid")

    dmi_uuid = document.get("dmi_uuid")
    if not isinstance(dmi_uuid, str):
        return _invalid("pilot_dmi_uuid_invalid")
    try:
        parsed_uuid = UUID(dmi_uuid)
    except ValueError:
        return _invalid("pilot_dmi_uuid_invalid")
    if (
        parsed_uuid.int == 0
        or str(parsed_uuid) != dmi_uuid.casefold()
        or len(dmi_uuid) != 36
    ):
        return _invalid("pilot_dmi_uuid_invalid")

    disk = document.get("disk")
    if not isinstance(disk, dict):
        return _invalid("pilot_disk_missing")
    if set(disk) != _DISK_FIELDS:
        return _invalid("pilot_disk_fields_invalid")
    fingerprint = disk.get("fingerprint")
    if (
        not isinstance(fingerprint, str)
        or not _FINGERPRINT_RE.fullmatch(fingerprint)
    ):
        return _invalid("pilot_disk_fingerprint_invalid")
    disk_path = disk.get("path")
    if (
        not isinstance(disk_path, str)
        or not _DISK_PATH_RE.fullmatch(disk_path)
        or ".." in disk_path
    ):
        return _invalid("pilot_disk_path_invalid")

    iso_sha256 = document.get("iso_sha256")
    if (
        not isinstance(iso_sha256, str)
        or not _SHA256_RE.fullmatch(iso_sha256)
    ):
        return _invalid("pilot_iso_digest_invalid")
    if iso_sha256 != expected_iso_sha256:
        return _invalid("pilot_iso_digest_mismatch")

    window = document.get("maintenance_window")
    if not isinstance(window, dict) or set(window) != _WINDOW_FIELDS:
        return _invalid("pilot_window_invalid")
    starts_at = _utc_second(window.get("starts_at"))
    ends_at = _utc_second(window.get("ends_at"))
    if starts_at is None or ends_at is None or ends_at <= starts_at:
        return _invalid("pilot_window_invalid")

    rollback_owner = document.get("rollback_owner")
    if (
        not isinstance(rollback_owner, str)
        or not 1 <= len(rollback_owner) <= 128
        or rollback_owner != rollback_owner.strip()
        or any(ord(character) < 0x20 for character in rollback_owner)
    ):
        return _invalid("pilot_rollback_owner_invalid")

    return PilotValidation(
        valid=True,
        code="pilot_record_valid",
        record=document,
        record_sha256=hashlib.sha256(raw).hexdigest(),
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Validate a real-machine pilot identity record. "
            "This command does not authorize execution or access a disk."
        ),
        allow_abbrev=False,
    )
    parser.add_argument("--record", required=True, type=Path)
    parser.add_argument("--expected-iso-sha256", required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    result = validate_pilot_record(
        arguments.record,
        expected_iso_sha256=arguments.expected_iso_sha256,
    )
    if not result.valid:
        print(
            json.dumps(
                {
                    "code": result.code,
                    "result": "invalid",
                    "schema_version": 1,
                    "validation_only": True,
                },
                sort_keys=True,
                separators=(",", ":"),
            ),
            file=sys.stderr,
        )
        return 1
    print(
        json.dumps(
            {
                "code": result.code,
                "pilot_record_sha256": result.record_sha256,
                "result": "valid",
                "schema_version": 1,
                "validation_only": True,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
