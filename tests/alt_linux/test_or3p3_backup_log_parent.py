from __future__ import annotations

from pathlib import Path

from support.backup_repository_sandbox import BackupSandbox


def test_create_accepts_root_owned_non_writable_0755_log_parent(
    tmp_path: Path,
) -> None:
    sandbox = BackupSandbox.create(tmp_path)
    sandbox.seed_complete_controller()
    sandbox.settings.log_file.parent.chmod(0o755)

    result = sandbox.repository().create()

    assert result.component_count == 6
