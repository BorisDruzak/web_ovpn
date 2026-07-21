from __future__ import annotations

import hashlib
import json
import os
import stat
from pathlib import Path

import pytest

from alt_deploy.errors import ControlError
from alt_deploy.machine_archive_repository import (
    ArchiveTransaction,
    MachineArchiveRepository,
)
from alt_deploy.registration_records import (
    MachineIdentity,
    load_registration_candidate,
)
from support.controller_sandbox import (
    ControllerSandbox,
    make_controller_sandbox,
)
from support.lifecycle_fixtures import (
    TEST_MACHINE_UUID,
    registration_payload,
    write_registration,
)


def audit_payload() -> dict[str, object]:
    return {
        "reason": "Synthetic repository test",
        "operator_uid": os.getuid(),
        "operator_username": "test-operator",
        "archived_at": "2026-07-21T12:00:00+00:00",
    }


def prepare_source(
    tmp_path: Path,
    state: str = "ready",
) -> tuple[
    ControllerSandbox,
    Path,
    MachineArchiveRepository,
    ArchiveTransaction,
]:
    sandbox = make_controller_sandbox(tmp_path)
    source = write_registration(
        sandbox.settings,
        state,
        registration_payload(
            status=(
                "awaiting_assignment"
                if state == "ready"
                else state
            )
        ),
    )
    candidate = load_registration_candidate(source, state)
    repository = MachineArchiveRepository(sandbox.settings)
    transaction = repository.prepare(
        MachineIdentity(
            machine_key=candidate.machine_key,
            machine_uuid=candidate.machine_uuid,
            mac=candidate.mac,
        ),
        (candidate,),
        audit_payload(),
    )
    return sandbox, source, repository, transaction


def commit_source(
    tmp_path: Path,
    state: str = "ready",
) -> tuple[
    ControllerSandbox,
    Path,
    MachineArchiveRepository,
    ArchiveTransaction,
]:
    sandbox, source, repository, transaction = prepare_source(
        tmp_path,
        state,
    )
    candidate = load_registration_candidate(source, state)
    copied = repository.copy_and_verify(
        transaction,
        (candidate,),
    )
    committed = repository.commit(copied)
    return sandbox, source, repository, committed


def test_prepare_creates_private_transaction_without_commit(
    tmp_path: Path,
) -> None:
    sandbox, _, _, transaction = prepare_source(tmp_path)

    assert transaction.phase == "prepared"
    assert transaction.audit == audit_payload()
    assert transaction.directory.parent == (
        sandbox.settings.archive_transactions_dir
    )
    assert stat.S_IMODE(
        transaction.directory.stat().st_mode
    ) == 0o700
    assert stat.S_IMODE(
        sandbox.settings.machine_archives_dir.stat().st_mode
    ) == 0o700
    assert stat.S_IMODE(
        sandbox.settings.archive_transactions_dir.stat().st_mode
    ) == 0o700
    assert (
        transaction.directory / "transaction.json"
    ).is_file()
    assert not (
        transaction.directory / "manifest.json"
    ).exists()
    assert not (
        transaction.directory / "commit.json"
    ).exists()


def test_copy_preserves_exact_bytes_and_manifest_hash(
    tmp_path: Path,
) -> None:
    _, source, repository, transaction = prepare_source(tmp_path)
    original = source.read_bytes()
    candidate = load_registration_candidate(source, "ready")

    copied = repository.copy_and_verify(
        transaction,
        (candidate,),
    )

    archived = copied.directory / "records" / "ready.json"
    assert copied.phase == "copied"
    assert archived.read_bytes() == original
    assert stat.S_IMODE(archived.stat().st_mode) == 0o600

    manifest_path = copied.directory / "manifest.json"
    manifest_bytes = manifest_path.read_bytes()
    manifest = json.loads(manifest_bytes.decode("utf-8"))

    assert manifest["reason"] == audit_payload()["reason"]
    assert manifest["operator_uid"] == os.getuid()
    assert manifest["source_states"] == ["ready"]
    assert manifest["registration_generations"] == [
        candidate.generation.value
    ]
    assert manifest["records"] == [
        {
            "state": "ready",
            "filename": "ready.json",
            "size": len(original),
            "sha256": hashlib.sha256(original).hexdigest(),
        }
    ]
    assert stat.S_IMODE(manifest_path.stat().st_mode) == 0o600


def test_commit_marker_indexes_exact_generation(
    tmp_path: Path,
) -> None:
    _, source, repository, committed = commit_source(tmp_path)
    candidate = load_registration_candidate(source, "ready")

    assert committed.phase == "committed"
    assert repository.committed_generation_index() == {
        candidate.generation.value: committed.archive_id
    }

    commit_path = committed.directory / "commit.json"
    commit_payload = json.loads(
        commit_path.read_text(encoding="utf-8")
    )
    manifest_bytes = (
        committed.directory / "manifest.json"
    ).read_bytes()

    assert commit_payload["archive_id"] == committed.archive_id
    assert commit_payload["registration_generations"] == [
        candidate.generation.value
    ]
    assert commit_payload["manifest_sha256"] == (
        hashlib.sha256(manifest_bytes).hexdigest()
    )
    assert stat.S_IMODE(commit_path.stat().st_mode) == 0o600


def test_cleanup_and_finalize_remove_only_matching_source(
    tmp_path: Path,
) -> None:
    sandbox, source, repository, committed = commit_source(
        tmp_path
    )

    cleaned = repository.cleanup_sources(committed)
    final_path = repository.finalize(cleaned)

    assert not source.exists()
    assert cleaned.phase == "cleaned"
    assert final_path == (
        sandbox.settings.machine_archives_dir
        / cleaned.archive_id
    )
    assert final_path.is_dir()
    assert not cleaned.directory.exists()

    latest = repository.find_latest_completed(TEST_MACHINE_UUID)
    assert latest is not None
    assert latest["archive_id"] == cleaned.archive_id
    assert latest["source_states"] == ["ready"]


def test_cleanup_treats_missing_matching_source_as_cleaned(
    tmp_path: Path,
) -> None:
    _, source, repository, committed = commit_source(tmp_path)
    source.unlink()

    cleaned = repository.cleanup_sources(committed)

    assert cleaned.phase == "cleaned"


def test_cleanup_refuses_new_generation_at_same_path(
    tmp_path: Path,
) -> None:
    sandbox, source, repository, committed = commit_source(
        tmp_path,
        "pending",
    )
    write_registration(
        sandbox.settings,
        "pending",
        registration_payload(
            registration_id=(
                "reg-22222222222222222222222222222222"
            )
        ),
    )

    with pytest.raises(ControlError) as exc:
        repository.cleanup_sources(committed)

    assert exc.value.code == "machine_archive_cleanup_required"
    assert exc.value.details == {
        "archive_id": committed.archive_id
    }
    assert source.is_file()
    current = load_registration_candidate(source, "pending")
    assert current.generation.value == (
        "reg-22222222222222222222222222222222"
    )


def test_find_resumable_matches_uuid_or_machine_key(
    tmp_path: Path,
) -> None:
    _, _, repository, committed = commit_source(tmp_path)

    by_uuid = repository.find_resumable(TEST_MACHINE_UUID)
    by_key = repository.find_resumable(
        committed.machine_key.upper()
    )

    assert by_uuid is not None
    assert by_key is not None
    assert by_uuid.archive_id == committed.archive_id
    assert by_key.archive_id == committed.archive_id


def test_archive_root_symlink_fails_closed(
    tmp_path: Path,
) -> None:
    sandbox = make_controller_sandbox(tmp_path)
    target = sandbox.settings.state_root / "outside"
    target.mkdir(parents=True)
    sandbox.settings.machine_archives_dir.parent.mkdir(
        parents=True,
        exist_ok=True,
    )
    sandbox.settings.machine_archives_dir.symlink_to(
        target,
        target_is_directory=True,
    )

    with pytest.raises(ControlError) as exc:
        MachineArchiveRepository(
            sandbox.settings
        ).committed_generation_index()

    assert exc.value.code == "machine_archive_invalid"


def test_malformed_transaction_fails_closed(
    tmp_path: Path,
) -> None:
    sandbox, _, _, transaction = prepare_source(tmp_path)
    (transaction.directory / "transaction.json").write_text(
        "{broken\n",
        encoding="utf-8",
    )

    with pytest.raises(ControlError) as exc:
        MachineArchiveRepository(
            sandbox.settings
        ).find_resumable(TEST_MACHINE_UUID)

    assert exc.value.code == "machine_archive_invalid"


def test_wrong_manifest_hash_fails_closed(
    tmp_path: Path,
) -> None:
    sandbox, _, repository, committed = commit_source(tmp_path)
    manifest = committed.directory / "manifest.json"
    manifest.write_text(
        manifest.read_text(encoding="utf-8") + " ",
        encoding="utf-8",
    )

    with pytest.raises(ControlError) as exc:
        repository.committed_generation_index()

    assert exc.value.code == "machine_archive_invalid"


def test_symlink_commit_marker_fails_closed(
    tmp_path: Path,
) -> None:
    sandbox, _, repository, committed = commit_source(tmp_path)
    commit_path = committed.directory / "commit.json"
    commit_bytes = commit_path.read_bytes()
    commit_path.unlink()
    target = sandbox.root / "commit-target.json"
    target.write_bytes(commit_bytes)
    commit_path.symlink_to(target)

    with pytest.raises(ControlError) as exc:
        repository.committed_generation_index()

    assert exc.value.code == "machine_archive_invalid"


def test_unexpected_archive_child_type_fails_closed(
    tmp_path: Path,
) -> None:
    sandbox, _, repository, committed = commit_source(tmp_path)
    unexpected = committed.directory / "unexpected.fifo"
    if not hasattr(os, "mkfifo"):
        pytest.skip("FIFO creation is unavailable")
    os.mkfifo(unexpected)

    with pytest.raises(ControlError) as exc:
        repository.committed_generation_index()

    assert exc.value.code == "machine_archive_invalid"
