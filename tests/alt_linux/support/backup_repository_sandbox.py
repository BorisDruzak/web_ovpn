from __future__ import annotations

import fcntl
import json
import os
import shutil
from dataclasses import dataclass, field
from pathlib import Path

from alt_deploy_backup.archive import ArchiveEngine
from alt_deploy_backup.components import ComponentSpec
from alt_deploy_backup.repository import BackupRepository
from support.backup_archive_sandbox import BackupSandbox as ArchiveSandbox


class ObservedArchiveEngine(ArchiveEngine):
    def __init__(self, sandbox: "BackupSandbox") -> None:
        super().__init__(sandbox.settings)
        self.sandbox = sandbox

    def capture(self, spec: ComponentSpec, destination: Path):
        self.sandbox.capture_order.append(spec.name)
        descriptor = os.open(self.sandbox.settings.lifecycle_lock, os.O_RDWR)
        try:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                self.sandbox.lifecycle_lock_observations.append(spec.name)
            else:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)
        if self.sandbox.failed_component == spec.name:
            raise self.sandbox.component_failure(spec.name)
        return super().capture(spec, destination)


@dataclass(frozen=True)
class BackupSandbox(ArchiveSandbox):
    capture_order: list[str] = field(default_factory=list)
    lifecycle_lock_observations: list[str] = field(default_factory=list)
    failed_component: str | None = None

    @classmethod
    def create(cls, tmp_path: Path) -> "BackupSandbox":
        base = ArchiveSandbox.create(tmp_path)
        return cls(
            root=base.root,
            fake_bin=base.fake_bin,
            command_log_path=base.command_log_path,
            systemd_state_path=base.systemd_state_path,
            settings=base.settings,
        )

    def component_failure(self, name: str):
        from alt_deploy_backup.errors import BackupError

        return BackupError(
            code="backup_component_failed",
            message=f"Injected component failure: {name}",
            exit_code=4,
        )

    def _write(self, absolute_path: str, content: bytes, mode: int) -> Path:
        path = self.root / absolute_path.lstrip("/")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        path.chmod(mode)
        return path

    def seed_complete_controller(self) -> None:
        for path in (
            self.settings.backup_root,
            self.settings.private_state_root,
            self.settings.log_file.parent,
            self.settings.rehearsal_root.parent,
        ):
            path.mkdir(parents=True, exist_ok=True)
            path.chmod(0o700)

        lifecycle = self.settings.lifecycle_lock
        lifecycle.parent.mkdir(parents=True, exist_ok=True)
        lifecycle.write_bytes(b"")
        lifecycle.chmod(0o600)

        self.seed_runtime_tree()
        self.seed_ansible_tree(
            vault_bytes=b"$ANSIBLE_VAULT;1.1;AES256\nfixture-vault\n"
        )
        self.seed_secrets(
            vault=b"$ANSIBLE_VAULT;1.1;AES256\nfixture-vault\n"
        )

        for unit in (
            "alt-deploy-http.service",
            "alt-deploy-register.service",
            "alt-deploy-process.path",
            "alt-deploy-process.service",
        ):
            self._write(
                f"/etc/systemd/system/{unit}",
                f"[Unit]\nDescription={unit}\n".encode(),
                0o644,
            )

        self._write(
            "/var/lib/alt-deploy/jobs/job-20260722T000000Z-00000001/status.json",
            json.dumps(
                {
                    "job_id": "job-20260722T000000Z-00000001",
                    "state": "successful",
                    "stage": "complete",
                },
                indent=2,
            ).encode()
            + b"\n",
            0o600,
        )
        self._write(
            "/var/lib/alt-deploy/assignments/fixture.json",
            b"{}\n",
            0o600,
        )
        for state in ("pending", "ready", "failed"):
            directory = self.settings.registration_root / state
            directory.mkdir(parents=True, exist_ok=True)
            directory.chmod(0o700)
        self._write(
            "/srv/alt-deploy/registration/ready/fixture.json",
            b"{}\n",
            0o600,
        )
        self._write(
            "/srv/alt-deploy/bootstrap/bootstrap.sh",
            b"#!/bin/sh\nexit 0\n",
            0o644,
        )
        self._write(
            "/srv/alt-deploy/bootstrap/ansible_authorized_keys",
            b"ssh-ed25519 AAAAFIXTURE\n",
            0o644,
        )
        self._write(
            "/srv/alt-deploy/metadata/autoinstall.scm",
            b"fixture\n",
            0o644,
        )
        self._write(
            "/etc/machine-id",
            b"0123456789abcdef0123456789abcdef\n",
            0o444,
        )
        self._write(
            "/etc/os-release",
            (
                b"ID=altlinux\n"
                b"VERSION_ID=11.2\n"
                b"PRETTY_NAME=ALT Workstation K 11.2\n"
            ),
            0o644,
        )
        self._write(
            "/etc/hostname",
            b"alt-controller\n",
            0o644,
        )
        self._write(
            "/opt/alt-deploy-control/.repository-commit",
            b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n",
            0o644,
        )

        for name in ("ansible-playbook", "systemd-analyze"):
            executable = self.fake_bin / name
            executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            executable.chmod(0o755)

    def repository(self) -> BackupRepository:
        return BackupRepository(
            self.settings,
            archive_engine=ObservedArchiveEngine(self),
            systemd_manager=self.systemd_manager(),
            quiescence_checker=self.quiescence_checker(),
            secret_provider=self.secret_provider(),
        )

    def fail_component(self, name: str) -> None:
        object.__setattr__(self, "failed_component", name)

    def managed_unit_snapshot(self) -> dict[str, tuple[str, str]]:
        return {
            name: self.unit_state(name)
            for name in (
                "alt-deploy-http.service",
                "alt-deploy-register.service",
                "alt-deploy-process.path",
                "alt-deploy-process.service",
            )
        }

    def published_backups(self) -> list[Path]:
        if not self.settings.backup_root.exists():
            return []
        return sorted(
            path
            for path in self.settings.backup_root.iterdir()
            if path.name.startswith("backup-")
        )

    def lifecycle_lock_observed_for_all_components(self) -> bool:
        return self.lifecycle_lock_observations == [
            "runtime",
            "systemd",
            "ansible",
            "controller_state",
            "registration_state",
            "deployment_assets",
        ]

    def cleanup(self) -> None:
        shutil.rmtree(self.root, ignore_errors=True)
