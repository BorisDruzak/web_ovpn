from __future__ import annotations

import re
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from .config import Settings
from .errors import ControlError
from .jsonio import (
    atomic_write_json,
    ensure_private_dir,
    read_json,
)


MACHINE_ID_RE = re.compile(r"^[0-9a-f-]{8,64}$")

FORBIDDEN_KEY_PARTS = (
    "password",
    "secret",
    "token",
    "private_key",
    "vault",
)


def _find_unsafe_key(
    value: object,
    path: str = "",
) -> str | None:
    if isinstance(value, Mapping):
        for raw_key, nested_value in value.items():
            key = str(raw_key)
            key_lower = key.lower()
            key_path = f"{path}.{key}" if path else key

            if any(
                forbidden in key_lower
                for forbidden in FORBIDDEN_KEY_PARTS
            ):
                return key_path

            nested_result = _find_unsafe_key(
                nested_value,
                key_path,
            )

            if nested_result:
                return nested_result

    elif isinstance(value, (list, tuple)):
        for index, nested_value in enumerate(value):
            nested_result = _find_unsafe_key(
                nested_value,
                f"{path}[{index}]",
            )

            if nested_result:
                return nested_result

    return None


def assert_safe_payload(
    payload: Mapping[str, object],
) -> None:
    unsafe_key = _find_unsafe_key(payload)

    if unsafe_key:
        raise ControlError(
            code="unsafe_payload",
            message=(
                "Payload contains a secret-like key"
            ),
            exit_code=4,
            details={
                "key": unsafe_key,
            },
        )


class AssignmentRepository:
    def __init__(self, settings: Settings):
        self.settings = settings

    def _path(self, machine_uuid: str) -> Path:
        normalized = machine_uuid.strip().lower()

        if not MACHINE_ID_RE.fullmatch(normalized):
            raise ControlError(
                code="invalid_machine_uuid",
                message=(
                    f"Invalid machine UUID: {machine_uuid}"
                ),
                exit_code=4,
            )

        return (
            self.settings.assignments_dir
            / f"{normalized}.json"
        )

    def get(
        self,
        machine_uuid: str,
    ) -> dict[str, Any] | None:
        path = self._path(machine_uuid)

        if not path.is_file():
            return None

        try:
            return read_json(path)
        except (OSError, ValueError) as exc:
            raise ControlError(
                code="assignment_invalid",
                message=(
                    f"Invalid assignment record: {path}"
                ),
                exit_code=4,
            ) from exc

    def write(
        self,
        machine_uuid: str,
        payload: Mapping[str, object],
    ) -> None:
        normalized = machine_uuid.strip().lower()
        destination = self._path(normalized)
        record = dict(payload)

        assert_safe_payload(record)

        payload_uuid = str(
            record.get("machine_uuid") or normalized
        ).strip().lower()

        if payload_uuid != normalized:
            raise ControlError(
                code="assignment_uuid_mismatch",
                message=(
                    "Assignment UUID does not match "
                    "the destination machine"
                ),
                exit_code=4,
            )

        record["machine_uuid"] = normalized

        ensure_private_dir(
            self.settings.assignments_dir
        )

        existing = self.get(normalized)

        if existing is not None:
            if existing == record:
                return

            raise ControlError(
                code="assignment_conflict",
                message=(
                    "A different successful assignment "
                    "already exists"
                ),
                exit_code=4,
                details={
                    "machine_uuid": normalized,
                },
            )

        atomic_write_json(
            destination,
            record,
        )
