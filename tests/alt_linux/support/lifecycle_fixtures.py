from __future__ import annotations

import json
from pathlib import Path

from alt_deploy.config import Settings

TEST_MACHINE_UUID = "53b03180-5d78-11f0-bd95-f027db877a00"
TEST_MACHINE_MAC = "c0:9b:f4:62:54:e5"
TEST_REGISTRATION_ID = "reg-11111111111111111111111111111111"


def registration_payload(
    *,
    machine_uuid: str = TEST_MACHINE_UUID,
    machine_key: str | None = None,
    mac: str = TEST_MACHINE_MAC,
    registration_id: str | None = TEST_REGISTRATION_ID,
    status: str = "pending",
    registered_at: str = "2026-07-21T12:00:00+00:00",
) -> dict[str, object]:
    payload: dict[str, object] = {
        "machine_key": machine_key or machine_uuid,
        "uuid": machine_uuid,
        "hostname": "alt-lifecycle-test",
        "ip": "192.0.2.56",
        "mac": mac,
        "registered_at": registered_at,
        "status": status,
    }
    if registration_id is not None:
        payload["registration_id"] = registration_id
    return payload


def write_registration(
    settings: Settings,
    state: str,
    payload: dict[str, object],
    *,
    filename: str | None = None,
) -> Path:
    path = settings.registration_root / state / (
        filename or f"{payload['machine_key']}.json"
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    path.chmod(0o600)
    return path
