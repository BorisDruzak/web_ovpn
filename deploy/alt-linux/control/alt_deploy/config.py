from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Settings:
    registration_root: Path
    state_root: Path
    jobs_dir: Path
    assignments_dir: Path
    lock_file: Path
    ansible_project_dir: Path
    known_hosts_file: Path
    private_key_file: Path
    ansible_playbook_path: Path
    systemd_run_path: Path
    worker_path: Path
    workstationctl_path: Path

    @classmethod
    def from_env(cls) -> "Settings":
        registration_root = Path(
            os.environ.get(
                "ALT_DEPLOY_REGISTRATION_ROOT",
                "/srv/alt-deploy/registration",
            )
        )
        state_root = Path(
            os.environ.get(
                "ALT_DEPLOY_STATE_ROOT",
                "/var/lib/alt-deploy",
            )
        )
        ansible_project = Path(
            os.environ.get(
                "ALT_DEPLOY_ANSIBLE_PROJECT",
                "/home/altserver/ansible",
            )
        )

        return cls(
            registration_root=registration_root,
            state_root=state_root,
            jobs_dir=state_root / "jobs",
            assignments_dir=state_root / "assignments",
            lock_file=state_root / "workstationctl.lock",
            ansible_project_dir=ansible_project,
            known_hosts_file=Path(
                os.environ.get(
                    "ALT_DEPLOY_KNOWN_HOSTS",
                    "/home/altserver/.ssh/known_hosts_autoinstall",
                )
            ),
            private_key_file=Path(
                os.environ.get(
                    "ALT_DEPLOY_PRIVATE_KEY",
                    "/home/altserver/.ssh/id_ed25519",
                )
            ),
            ansible_playbook_path=Path(
                os.environ.get(
                    "ALT_DEPLOY_ANSIBLE_PLAYBOOK",
                    "/usr/bin/ansible-playbook",
                )
            ),
            systemd_run_path=Path(
                os.environ.get(
                    "ALT_DEPLOY_SYSTEMD_RUN",
                    "/usr/bin/systemd-run",
                )
            ),
            worker_path=Path(
                os.environ.get(
                    "ALT_DEPLOY_WORKER",
                    "/usr/local/libexec/alt-provision-worker",
                )
            ),
            workstationctl_path=Path(
                os.environ.get(
                    "ALT_DEPLOY_WORKSTATIONCTL",
                    "/usr/local/sbin/workstationctl",
                )
            ),
        )
