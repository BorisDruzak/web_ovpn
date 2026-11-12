from __future__ import annotations

from pathlib import Path

from alt_deploy_backup.audit import AuditLog
from support.backup_repository_sandbox import BackupSandbox


def test_create_uses_private_audit_with_group_writable_system_logs(
    tmp_path: Path,
) -> None:
    sandbox = BackupSandbox.create(tmp_path)
    sandbox.seed_complete_controller()
    system_log = sandbox.root / "var/log"
    system_log.mkdir(parents=True, exist_ok=True)
    system_log.chmod(0o775)

    result = sandbox.repository().create()

    assert result.component_count == 6
    audit = AuditLog(sandbox.settings, operation_id="probe", command="create", backup_id=None)
    audit.write("backup_probe")
    assert sandbox.settings.log_file.stat().st_mode & 0o777 == 0o600
    assert system_log.stat().st_mode & 0o777 == 0o775
