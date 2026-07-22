from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from alt_deploy_backup.rehearsal import RehearsalService
from alt_deploy_backup.state_validation import StateValidator
from support.backup_management_sandbox import BackupSandbox as ManagementSandbox


@dataclass(frozen=True)
class BackupSandbox(ManagementSandbox):
    @classmethod
    def create(cls, tmp_path: Path) -> "BackupSandbox":
        base = ManagementSandbox.create(tmp_path)
        return cls(
            root=base.root,
            fake_bin=base.fake_bin,
            command_log_path=base.command_log_path,
            systemd_state_path=base.systemd_state_path,
            settings=base.settings,
        )

    def rehearsal_service(self) -> RehearsalService:
        return RehearsalService(
            self.repository(),
            state_validator=StateValidator(),
        )

    def create_verified_backup(self) -> str:
        backup_id = super().create_verified_backup()
        return backup_id

    def create_rehearsed_backup(self) -> str:
        backup_id = self.create_verified_backup()
        self.rehearsal_service().rehearse(backup_id)
        return backup_id

    def production_snapshot(self) -> dict[str, bytes]:
        excluded = (
            self.settings.backup_root,
            self.settings.rehearsal_root,
            self.settings.operation_lock,
            self.settings.log_file,
        )
        result: dict[str, bytes] = {}
        for path in sorted(self.root.rglob("*")):
            if not path.is_file() or path.is_symlink():
                continue
            if any(path == root or root in path.parents for root in excluded):
                continue
            relative = path.relative_to(self.root)
            if any(
                part.startswith(".alt-deploy-restore-")
                for part in relative.parts
            ):
                continue
            result[str(relative)] = path.read_bytes()
        return result

    def malformed_rehearsal_tree(self) -> Path:
        root = self.root / "malformed-rehearsal"
        job = (
            root
            / "controller-state"
            / "var"
            / "lib"
            / "alt-deploy"
            / "jobs"
            / "job-bad"
        )
        job.mkdir(parents=True)
        (job / "status.json").write_text(
            json.dumps({"state": "successful", "stage": "complete"}),
            encoding="utf-8",
        )
        return root
