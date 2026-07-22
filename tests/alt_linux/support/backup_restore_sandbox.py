from __future__ import annotations

import json
import shutil
from dataclasses import dataclass
from pathlib import Path

from alt_deploy_backup.restore import RestoreService
from alt_deploy_backup.restore_journal import RestoreJournal
from support.backup_rehearsal_sandbox import BackupSandbox as RehearsalSandbox


@dataclass(frozen=True)
class BackupSandbox(RehearsalSandbox):
    @classmethod
    def create(cls, tmp_path: Path) -> "BackupSandbox":
        base = RehearsalSandbox.create(tmp_path)
        return cls(
            root=base.root,
            fake_bin=base.fake_bin,
            command_log_path=base.command_log_path,
            systemd_state_path=base.systemd_state_path,
            settings=base.settings,
        )

    def restore_service(
        self,
        *,
        fail_stage_component: str | None = None,
        fail_health_check: str | None = None,
        fail_rollback: bool = False,
    ) -> RestoreService:
        return RestoreService(
            self.repository(),
            fail_stage_component=fail_stage_component,
            fail_health_check=fail_health_check,
            fail_rollback=fail_rollback,
        )

    def prepare_restore(self, backup_id: str) -> RestoreJournal:
        return self.restore_service().prepare_restore(backup_id)

    def mutate_every_production_component(self) -> None:
        mutations = {
            self.settings.runtime_control_root / "generation.txt": b"new-runtime\n",
            self.settings.runtime_api_root / "generation.txt": b"new-api\n",
            self.settings.workstationctl_path: b"#!/usr/bin/python3\nprint('new')\n",
            self.settings.worker_path: b"#!/usr/bin/python3\nprint('new')\n",
            self.settings.stage_helper_path: b"#!/usr/bin/python3\nprint('new')\n",
            self.settings.systemd_root / "alt-deploy-http.service": b"[Unit]\nDescription=new\n",
            self.settings.ansible_root / "generation.txt": b"new-ansible\n",
            self.settings.controller_state_root / "generation.txt": b"new-state\n",
            self.settings.registration_root / "generation.txt": b"new-registration\n",
            self.settings.bootstrap_root / "generation.txt": b"new-bootstrap\n",
            self.settings.metadata_root / "generation.txt": b"new-metadata\n",
        }
        for path, raw in mutations.items():
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)
            path.chmod(0o644)

    def latest_restore_phase(self) -> str | None:
        root = self.settings.backup_root / ".restore-transactions"
        if not root.exists():
            return None
        journals = sorted(root.glob("restore-*/journal.json"))
        if not journals:
            return None
        payload = json.loads(journals[-1].read_text(encoding="utf-8"))
        return str(payload["phase"])

    def maintenance_units_are_stopped(self) -> bool:
        return all(
            self.unit_state(unit)[1] == "inactive"
            for unit in (
                "alt-deploy-http.service",
                "alt-deploy-register.service",
                "alt-deploy-process.path",
            )
        )

    def remove_runtime_api_before_backup(self) -> None:
        shutil.rmtree(self.settings.runtime_api_root)
