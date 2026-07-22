from __future__ import annotations

import json
import os
import stat
from pathlib import Path

import pytest

from alt_deploy_backup.audit import AuditLog
from alt_deploy_backup.errors import BackupError
from alt_deploy_backup.fs import (
    read_regular_bytes,
    source_inventory,
    validate_private_directory,
)
from alt_deploy_backup.jsonio import atomic_write_json
from alt_deploy_backup.locks import (
    exclusive_lifecycle_lock,
    exclusive_operation_lock,
)
from support.backup_sandbox import BackupSandbox


def test_read_regular_bytes_rejects_symlink(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.write_bytes(b"secret")
    link = tmp_path / "link"
    link.symlink_to(target)

    with pytest.raises(BackupError) as error:
        read_regular_bytes(link)

    assert error.value.code == "backup_source_unsafe"


def test_read_regular_bytes_enforces_maximum(tmp_path: Path) -> None:
    path = tmp_path / "large"
    path.write_bytes(b"12345")

    with pytest.raises(BackupError) as error:
        read_regular_bytes(path, max_bytes=4)

    assert error.value.code == "backup_source_unsafe"


def test_atomic_json_replaces_complete_file(tmp_path: Path) -> None:
    destination = tmp_path / "record.json"

    atomic_write_json(destination, {"status": "ok"})

    assert destination.read_bytes() == b'{\n  "status": "ok"\n}\n'
    assert stat.S_IMODE(destination.stat().st_mode) == 0o600
    assert not list(tmp_path.glob(".record.json.*.tmp"))


def test_validate_private_directory_uses_resolved_expected_ids(
    tmp_path: Path,
) -> None:
    directory = tmp_path / "private"
    directory.mkdir(mode=0o700)

    validate_private_directory(
        directory,
        uid=os.getuid(),
        gid=os.getgid(),
        mode=0o700,
    )


def test_operation_lock_is_non_blocking(tmp_path: Path) -> None:
    sandbox = BackupSandbox.create(tmp_path)

    with exclusive_operation_lock(sandbox.settings):
        with pytest.raises(BackupError) as error:
            with exclusive_operation_lock(sandbox.settings):
                pass

    assert error.value.code == "backup_lock_busy"


def test_operation_lock_symlink_ancestor_does_not_mutate_outside(
    tmp_path: Path,
) -> None:
    sandbox = BackupSandbox.create(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    (sandbox.root / "run").symlink_to(
        outside,
        target_is_directory=True,
    )

    with pytest.raises(BackupError) as error:
        with exclusive_operation_lock(sandbox.settings):
            pass

    assert error.value.code == "backup_source_unsafe"
    assert not (outside / "lock").exists()


def test_lifecycle_lock_is_never_created_implicitly(
    tmp_path: Path,
) -> None:
    sandbox = BackupSandbox.create(tmp_path)

    with pytest.raises(BackupError) as error:
        with exclusive_lifecycle_lock(sandbox.settings):
            pass

    assert error.value.code == "controller_lock_unsafe"
    assert not sandbox.settings.lifecycle_lock.exists()


def test_lifecycle_lock_opens_existing_private_file(
    tmp_path: Path,
) -> None:
    sandbox = BackupSandbox.create(tmp_path)
    lock = sandbox.settings.lifecycle_lock
    lock.parent.mkdir(parents=True)
    lock.write_bytes(b"")
    lock.chmod(0o600)

    with exclusive_lifecycle_lock(sandbox.settings):
        assert lock.is_file()


def test_source_inventory_rejects_external_symlink(
    tmp_path: Path,
) -> None:
    root = tmp_path / "root"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.write_text("outside", encoding="utf-8")
    (root / "escape").symlink_to(outside)

    with pytest.raises(BackupError) as error:
        source_inventory((root,))

    assert error.value.code == "backup_source_unsafe"


def test_source_inventory_records_safe_internal_symlink(
    tmp_path: Path,
) -> None:
    root = tmp_path / "root"
    root.mkdir()
    (root / "data").write_bytes(b"data")
    (root / "link").symlink_to("data")

    entries = source_inventory((root,))

    by_path = {entry.path: entry for entry in entries}
    assert by_path[str(root / "data")].kind == "regular"
    assert by_path[str(root / "link")].kind == "symlink"


def test_audit_log_writes_bounded_safe_json(tmp_path: Path) -> None:
    sandbox = BackupSandbox.create(tmp_path)
    audit = AuditLog(
        sandbox.settings,
        operation_id="op-test",
        command="create",
        backup_id="backup-20260722T000000Z-11111111",
    )

    audit.write("phase", phase="prepared", check="sources_safe")

    line = json.loads(
        sandbox.settings.log_file.read_text(encoding="utf-8")
    )
    assert line["event"] == "phase"
    assert line["phase"] == "prepared"
    assert stat.S_IMODE(sandbox.settings.log_file.stat().st_mode) == 0o600


def test_audit_log_rejects_unknown_or_unbounded_fields(
    tmp_path: Path,
) -> None:
    sandbox = BackupSandbox.create(tmp_path)
    audit = AuditLog(
        sandbox.settings,
        operation_id="op-test",
        command="create",
        backup_id=None,
    )

    with pytest.raises(BackupError):
        audit.write("unsafe", secret="must-not-log")
    with pytest.raises(BackupError):
        audit.write("unsafe", phase="x" * 501)
