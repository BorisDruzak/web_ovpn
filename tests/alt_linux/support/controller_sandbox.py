from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from alt_deploy.config import Settings
from alt_deploy.jsonio import atomic_write_json

from .payloads import TEST_MACHINE_UUID, machine_registration_payload


@dataclass(frozen=True)
class ControllerSandbox:
    settings: Settings
    root: Path

    def _write_executable(self, path: Path, content: str) -> Path:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        path.chmod(0o755)
        return path

    def register_machine(
        self,
        *,
        state: str = "ready",
        machine_uuid: str = TEST_MACHINE_UUID,
        preflight_ok: bool = False,
    ) -> Path:
        path = (
            self.settings.registration_root
            / state
            / f"{machine_uuid}.json"
        )
        atomic_write_json(
            path,
            machine_registration_payload(
                machine_uuid=machine_uuid,
                status=state,
                preflight_ok=preflight_ok,
            ),
        )
        return path

    def install_fake_stage_helper(self) -> Path:
        return self._write_executable(
            self.settings.job_stage_helper_path,
            "#!/bin/sh\nexit 0\n",
        )

    def install_fake_ansible_playbook(self) -> Path:
        return self._write_executable(
            self.settings.ansible_playbook_path,
            "#!/bin/sh\nexit 0\n",
        )

    def configure_preflight_boundary(self) -> dict[str, Path]:
        ansible_playbook = self.install_fake_ansible_playbook()

        self.settings.private_key_file.parent.mkdir(
            parents=True,
            exist_ok=True,
        )
        self.settings.private_key_file.write_text(
            "test-only-private-key-placeholder\n",
            encoding="utf-8",
        )
        self.settings.private_key_file.chmod(0o600)

        self.settings.known_hosts_file.write_text(
            "test-only-known-host-placeholder\n",
            encoding="utf-8",
        )
        self.settings.known_hosts_file.chmod(0o600)

        preflight_playbook = (
            self.settings.ansible_project_dir
            / "playbooks"
            / "01-preflight.yml"
        )
        preflight_playbook.parent.mkdir(parents=True, exist_ok=True)
        preflight_playbook.write_text("---\n", encoding="utf-8")

        return {
            "ansible_playbook": ansible_playbook,
            "private_key": self.settings.private_key_file,
            "known_hosts": self.settings.known_hosts_file,
            "preflight_playbook": preflight_playbook,
        }

    def configure_fake_vault(self) -> tuple[Path, Path]:
        vault_file = (
            self.settings.ansible_project_dir
            / "group_vars"
            / "vault.yml"
        )
        vault_file.parent.mkdir(parents=True, exist_ok=True)
        vault_file.write_text(
            "$ANSIBLE_VAULT;1.1;AES256\ntest-ciphertext\n",
            encoding="utf-8",
        )
        vault_file.chmod(0o600)

        password_file = (
            self.settings.ansible_project_dir.parent
            / ".ansible-vault-pass"
        )
        password_file.write_text(
            "test-only-passphrase\n",
            encoding="utf-8",
        )
        password_file.chmod(0o600)
        return vault_file, password_file


def make_controller_sandbox(tmp_path: Path) -> ControllerSandbox:
    root = tmp_path / "alt-controller"
    registration = root / "registration"
    state = root / "state"
    ansible_project = root / "ansible"
    bin_dir = root / "bin"

    settings = Settings(
        registration_root=registration,
        state_root=state,
        jobs_dir=state / "jobs",
        assignments_dir=state / "assignments",
        lock_file=state / "workstationctl.lock",
        ansible_project_dir=ansible_project,
        known_hosts_file=root / "ssh" / "known_hosts",
        private_key_file=root / "ssh" / "id_ed25519",
        ansible_playbook_path=bin_dir / "ansible-playbook",
        systemd_run_path=bin_dir / "systemd-run",
        worker_path=bin_dir / "alt-provision-worker",
        job_stage_helper_path=bin_dir / "alt-job-stage",
        workstationctl_path=bin_dir / "workstationctl",
    )
    return ControllerSandbox(settings=settings, root=root)
