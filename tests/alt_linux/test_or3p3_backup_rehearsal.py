from __future__ import annotations

import json
from pathlib import Path

import pytest

from alt_deploy_backup.errors import BackupError
from support.backup_rehearsal_sandbox import BackupSandbox


def test_rehearsal_never_writes_production_paths(tmp_path: Path) -> None:
    sandbox = BackupSandbox.create(tmp_path)
    backup_id = sandbox.create_verified_backup()
    before = sandbox.production_snapshot()

    result = sandbox.rehearsal_service().rehearse(backup_id)

    assert result.rehearsal_passed is True
    assert result.check_count >= 10
    assert sandbox.production_snapshot() == before
    assert not (sandbox.settings.rehearsal_root / backup_id).exists()
    assert (sandbox.bundle(backup_id) / "rehearsal.json").is_file()
    summary = sandbox.repository().list()[0]
    assert summary.verified is True
    assert summary.rehearsed is True


def test_failed_rehearsal_preserves_private_tree(tmp_path: Path) -> None:
    sandbox = BackupSandbox.create(tmp_path)
    sandbox.seed_complete_controller()
    broken = (
        sandbox.settings.runtime_control_root
        / "alt_deploy"
        / "__init__.py"
    )
    broken.write_text("def broken(:\n", encoding="utf-8")
    backup_id = sandbox.repository().create().backup_id
    sandbox.repository().verify(backup_id, write_evidence=True)

    with pytest.raises(BackupError) as error:
        sandbox.rehearsal_service().rehearse(backup_id)

    assert error.value.code == "backup_rehearsal_failed"
    failed_root = sandbox.settings.rehearsal_root / backup_id
    assert failed_root.is_dir()
    assert not (sandbox.bundle(backup_id) / "rehearsal.json").exists()


def test_state_validator_rejects_malformed_job_state(tmp_path: Path) -> None:
    sandbox = BackupSandbox.create(tmp_path)
    root = sandbox.malformed_rehearsal_tree()

    with pytest.raises(BackupError) as error:
        sandbox.rehearsal_service().state_validator.validate_tree(
            root,
            manifest=None,  # type: ignore[arg-type]
        )

    assert error.value.code == "backup_rehearsal_failed"


def test_rehearse_status_is_byte_identical_for_bundle_evidence(
    tmp_path: Path,
) -> None:
    sandbox = BackupSandbox.create(tmp_path)
    backup_id = sandbox.create_rehearsed_backup()
    verification = sandbox.bundle(backup_id) / "verification.json"
    rehearsal = sandbox.bundle(backup_id) / "rehearsal.json"
    before = (verification.read_bytes(), rehearsal.read_bytes())

    result = sandbox.run_cli(
        "rehearse-status",
        backup_id,
        effective_uid=0,
    )

    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["status"] == "ok"
    assert payload["result"] == "backup_rehearsed"
    assert (verification.read_bytes(), rehearsal.read_bytes()) == before


def test_rehearse_cli_returns_bounded_success_result(tmp_path: Path) -> None:
    sandbox = BackupSandbox.create(tmp_path)
    backup_id = sandbox.create_verified_backup()

    result = sandbox.run_cli("rehearse", backup_id, effective_uid=0)

    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["status"] == "ok"
    assert payload["result"] == "backup_rehearsed"
    assert payload["backup_id"] == backup_id
    assert payload["rehearsal_passed"] is True
    assert payload["check_count"] >= 10
    assert len(payload["manifest_sha256"]) == 64
