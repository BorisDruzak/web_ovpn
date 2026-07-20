from __future__ import annotations

import subprocess

from .config import Settings
from .errors import ControlError


class SystemdLauncher:
    def __init__(self, settings: Settings):
        self.settings = settings

    def launch(self, job_id: str) -> str:
        unit_name = f"alt-provision-{job_id}"

        command = [
            str(self.settings.systemd_run_path),
            f"--unit={unit_name}",
            (
                "--description=ALT workstation provision "
                f"{job_id}"
            ),
            "--uid=altserver",
            "--gid=altserver",
            (
                "--working-directory="
                f"{self.settings.ansible_project_dir}"
            ),
            "--property=Type=exec",
            "--property=NoNewPrivileges=yes",
            "--property=PrivateTmp=yes",
            "--collect",
            str(self.settings.worker_path),
            "--job-id",
            job_id,
        ]

        try:
            completed = subprocess.run(
                command,
                shell=False,
                text=True,
                capture_output=True,
                timeout=30,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise ControlError(
                code="job_launch_failed",
                message=(
                    "Unable to launch transient "
                    "provision service"
                ),
                exit_code=6,
                details={
                    "stderr": (
                        f"systemd-run timeout after "
                        f"{exc.timeout} seconds"
                    ),
                },
            ) from exc
        except OSError as exc:
            raise ControlError(
                code="job_launch_failed",
                message=(
                    "Unable to launch transient "
                    "provision service"
                ),
                exit_code=6,
                details={
                    "stderr": str(exc),
                },
            ) from exc

        if completed.returncode != 0:
            raise ControlError(
                code="job_launch_failed",
                message=(
                    "Unable to launch transient "
                    "provision service"
                ),
                exit_code=6,
                details={
                    "stderr": (
                        completed.stderr or ""
                    )[-4000:],
                },
            )

        return f"{unit_name}.service"
