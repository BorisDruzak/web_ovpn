from __future__ import annotations

import json
import os
from pathlib import Path

from alt_deploy.config import Settings
from alt_deploy.machine_archive_repository import (
    ArchiveTransaction,
    MachineArchiveRepository,
)
from alt_deploy.registration_records import (
    MachineIdentity,
    load_registration_candidate,
)

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


def snapshot_tree(
    root: Path,
) -> dict[str, tuple[str, bytes | None]]:
    result: dict[str, tuple[str, bytes | None]] = {}
    if not root.exists():
        return result
    for path in sorted(root.rglob("*")):
        relative = str(path.relative_to(root))
        if path.is_symlink():
            result[relative] = (
                "symlink",
                os.readlink(path).encode("utf-8"),
            )
        elif path.is_file():
            result[relative] = ("file", path.read_bytes())
        elif path.is_dir():
            result[relative] = ("directory", None)
        else:
            result[relative] = ("other", None)
    return result


def commit_candidate_without_cleanup(
    settings: Settings,
    source: Path,
    state: str,
) -> ArchiveTransaction:
    candidate = load_registration_candidate(source, state)
    repository = MachineArchiveRepository(settings)
    transaction = repository.prepare(
        MachineIdentity(
            machine_key=candidate.machine_key,
            machine_uuid=candidate.machine_uuid,
            mac=candidate.mac,
        ),
        (candidate,),
        {
            "reason": "Synthetic archive fixture",
            "operator_uid": os.getuid(),
            "operator_username": "test-operator",
            "archived_at": "2026-07-21T12:00:00+00:00",
        },
    )
    copied = repository.copy_and_verify(
        transaction,
        (candidate,),
    )
    return repository.commit(copied)


def complete_candidate_archive(
    settings: Settings,
    source: Path,
    state: str,
) -> ArchiveTransaction:
    repository = MachineArchiveRepository(settings)
    committed = commit_candidate_without_cleanup(
        settings,
        source,
        state,
    )
    cleaned = repository.cleanup_sources(committed)
    repository.finalize(cleaned)
    return cleaned
