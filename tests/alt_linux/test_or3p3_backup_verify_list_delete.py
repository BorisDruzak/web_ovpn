from __future__ import annotations

import json
from pathlib import Path

import pytest

from alt_deploy_backup.errors import BackupError
from support.backup_management_sandbox import BackupSandbox


def test_verify_writes_evidence_and_read_only_verify_is_byte_stable(
    tmp_path: Path,
) -> None:
    sandbox = BackupSandbox.create(tmp_path)
    backup_id = sandbox.create_valid_backup()

    first = sandbox.repository().verify(backup_id, write_evidence=True)
    evidence = sandbox.bundle(backup_id) / "verification.json"
    before = evidence.read_bytes()
    second = sandbox.repository().verify(backup_id, write_evidence=False)

    assert first.evidence_written is True
    assert second.evidence_written is False
    assert evidence.read_bytes() == before


def test_verify_detects_component_corruption(tmp_path: Path) -> None:
    sandbox = BackupSandbox.create(tmp_path)
    backup_id = sandbox.create_valid_backup()
    component = sandbox.bundle(backup_id) / "runtime.tar.zst"
    component.write_bytes(component.read_bytes() + b"corrupt")

    with pytest.raises(BackupError) as error:
        sandbox.repository().verify(backup_id, write_evidence=True)

    assert error.value.code == "backup_integrity_failed"
    assert not (sandbox.bundle(backup_id) / "verification.json").exists()


def test_bundle_mutation_invalidates_existing_evidence(tmp_path: Path) -> None:
    sandbox = BackupSandbox.create(tmp_path)
    backup_id = sandbox.create_verified_backup()
    manifest = sandbox.bundle(backup_id) / "manifest.json"
    manifest.write_bytes(manifest.read_bytes() + b" ")

    summary = sandbox.repository().list()[0]

    assert summary.backup_id == backup_id
    assert summary.valid is True
    assert summary.verified is False
    assert summary.rehearsed is False


def test_list_ignores_non_normal_backup_directories(tmp_path: Path) -> None:
    sandbox = BackupSandbox.create(tmp_path)
    backup_id = sandbox.create_valid_backup()
    for name in (
        ".creating-backup-20260722T120000Z-11111111",
        "pre-restore-20260722T120000Z",
        ".restore-transactions",
    ):
        path = sandbox.settings.backup_root / name
        path.mkdir(mode=0o700)

    summaries = sandbox.repository().list()

    assert [summary.backup_id for summary in summaries] == [backup_id]


def test_delete_allows_corrupt_safe_direct_child(tmp_path: Path) -> None:
    sandbox = BackupSandbox.create(tmp_path)
    backup_id = sandbox.create_valid_backup()
    (sandbox.bundle(backup_id) / "manifest.json").write_text(
        "broken",
        encoding="utf-8",
    )

    result = sandbox.repository().delete(backup_id)

    assert result.backup_id == backup_id
    assert result.deleted_bytes > 0
    assert not sandbox.bundle(backup_id).exists()


def test_delete_rejects_traversal_and_symlink_target(tmp_path: Path) -> None:
    sandbox = BackupSandbox.create(tmp_path)
    sandbox.seed_complete_controller()

    with pytest.raises(BackupError) as traversal:
        sandbox.repository().delete("../escape")
    assert traversal.value.code == "backup_not_found"

    backup_id = "backup-20260722T120000Z-11111111"
    outside = sandbox.root / "outside"
    outside.mkdir()
    (sandbox.settings.backup_root / backup_id).symlink_to(outside)
    with pytest.raises(BackupError) as symlink:
        sandbox.repository().delete(backup_id)
    assert symlink.value.code == "backup_delete_unsafe"
    assert outside.is_dir()


def test_verify_list_delete_cli_returns_exact_safe_results(
    tmp_path: Path,
) -> None:
    sandbox = BackupSandbox.create(tmp_path)
    backup_id = sandbox.create_valid_backup()

    verified = sandbox.run_cli("verify", backup_id, effective_uid=0)
    assert verified.returncode == 0, verified.stderr
    verify_payload = json.loads(verified.stdout)
    assert verify_payload == {
        "status": "ok",
        "result": "backup_verified",
        "backup_id": backup_id,
        "component_count": 6,
        "manifest_sha256": verify_payload["manifest_sha256"],
        "evidence_written": True,
    }
    assert len(verify_payload["manifest_sha256"]) == 64

    listed = sandbox.run_cli("list", effective_uid=0)
    assert listed.returncode == 0, listed.stderr
    list_payload = json.loads(listed.stdout)
    assert list_payload["status"] == "ok"
    assert list_payload["result"] == "backups_listed"
    assert list_payload["count"] == 1
    assert list_payload["backups"][0]["backup_id"] == backup_id
    assert list_payload["backups"][0]["verified"] is True

    deleted = sandbox.run_cli("delete", backup_id, effective_uid=0)
    assert deleted.returncode == 0, deleted.stderr
    delete_payload = json.loads(deleted.stdout)
    assert delete_payload["status"] == "ok"
    assert delete_payload["result"] == "backup_deleted"
    assert delete_payload["backup_id"] == backup_id
    assert delete_payload["deleted_bytes"] > 0
