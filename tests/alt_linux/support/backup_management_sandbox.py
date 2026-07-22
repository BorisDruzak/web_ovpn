from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from support.backup_repository_sandbox import BackupSandbox as RepositorySandbox


@dataclass(frozen=True)
class BackupSandbox(RepositorySandbox):
    @classmethod
    def create(cls, tmp_path: Path) -> "BackupSandbox":
        base = RepositorySandbox.create(tmp_path)
        return cls(
            root=base.root,
            fake_bin=base.fake_bin,
            command_log_path=base.command_log_path,
            systemd_state_path=base.systemd_state_path,
            settings=base.settings,
        )

    def bundle(self, backup_id: str) -> Path:
        return self.settings.backup_root / backup_id

    def create_valid_backup(self) -> str:
        self.seed_complete_controller()
        return self.repository().create().backup_id

    def create_verified_backup(self) -> str:
        backup_id = self.create_valid_backup()
        self.repository().verify(backup_id, write_evidence=True)
        return backup_id
