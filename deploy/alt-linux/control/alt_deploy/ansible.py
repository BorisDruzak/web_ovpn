from __future__ import annotations

import os
import subprocess
import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import TextIO

from .config import Settings
from .errors import ControlError
from .jsonio import read_json
from .models import JobRecord, MachineRecord
from .registry import MachineRepository


Runner = Callable[
    [list[str], int],
    subprocess.CompletedProcess[str],
]


def _bounded(value: str | None) -> str:
    return (value or "")[-10000:]


_PREFLIGHT_FAILURE_KINDS = frozenset(
    {
        "ssh_timeout",
        "ssh_unreachable",
        "ssh_host_key_mismatch",
        "ssh_authentication_failed",
        "sudo_unavailable",
        "ansible_failed",
    }
)

_CONTROLLED_PREFLIGHT_MARKERS = {
    "ALT_PREFLIGHT_FAILURE:sudo_unavailable": "sudo_unavailable",
}


def _classify_preflight_failure(
    *,
    stdout: str | None,
    stderr: str | None,
) -> str:
    combined = "\n".join(
        value
        for value in (stdout, stderr)
        if isinstance(value, str) and value
    )

    for marker, failure_kind in _CONTROLLED_PREFLIGHT_MARKERS.items():
        if marker in combined:
            return failure_kind

    normalized = combined.casefold()

    if (
        "remote host identification has changed" in normalized
        or "host key verification failed" in normalized
        or (
            "offending " in normalized
            and " key in " in normalized
        )
    ):
        return "ssh_host_key_mismatch"

    if any(
        marker in normalized
        for marker in (
            "permission denied (publickey",
            "authentication failed",
            "no more authentication methods to try",
        )
    ):
        return "ssh_authentication_failed"

    if any(
        marker in normalized
        for marker in (
            "connection timed out",
            "operation timed out",
            "timeout waiting for",
        )
    ):
        return "ssh_timeout"

    if any(
        marker in normalized
        for marker in (
            "connection refused",
            "no route to host",
            "network is unreachable",
            "connection reset by peer",
            "connection closed by remote host",
        )
    ):
        return "ssh_unreachable"

    return "ansible_failed"


class AnsibleController:
    def __init__(
        self,
        settings: Settings,
        *,
        runner: Runner | None = None,
    ) -> None:
        self.settings = settings
        self.runner = runner or self._run_default

    @property
    def ansible_config(self) -> Path:
        return (
            self.settings.ansible_project_dir
            / "ansible.cfg"
        )

    def _ansible_environment(
        self,
    ) -> dict[str, str]:
        environment = os.environ.copy()
        environment["ANSIBLE_CONFIG"] = str(
            self.ansible_config
        )
        return environment

    def _run_default(
        self,
        command: list[str],
        timeout: int,
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            command,
            shell=False,
            text=True,
            capture_output=True,
            timeout=timeout,
            check=False,
            cwd=self.settings.ansible_project_dir,
            env=self._ansible_environment(),
        )

    @property
    def preflight_playbook(self) -> Path:
        return (
            self.settings.ansible_project_dir
            / "playbooks"
            / "01-preflight.yml"
        )

    def _validate_preflight_files(self) -> None:
        required_files = {
            "ansible_playbook": (
                self.settings.ansible_playbook_path
            ),
            "private_key": (
                self.settings.private_key_file
            ),
            "known_hosts": (
                self.settings.known_hosts_file
            ),
            "preflight_playbook": (
                self.preflight_playbook
            ),
        }

        missing = [
            {
                "name": name,
                "path": str(path),
            }
            for name, path in required_files.items()
            if not path.is_file()
        ]

        if missing:
            raise ControlError(
                code="preflight_not_configured",
                message=(
                    "ALT workstation preflight "
                    "is not fully configured"
                ),
                exit_code=5,
                details={
                    "missing": missing,
                },
            )

    def run_preflight(
        self,
        machine: MachineRecord,
        employee_login: str = "",
    ) -> dict[str, object]:
        self._validate_preflight_files()

        if not machine.ip:
            raise ControlError(
                code="machine_missing_ip",
                message=(
                    "Registered machine has no IP address"
                ),
                exit_code=5,
                details={
                    "machine_uuid": machine.uuid,
                },
            )

        strict_ssh_arguments = (
            "-o UserKnownHostsFile="
            f"{self.settings.known_hosts_file} "
            "-o StrictHostKeyChecking=yes "
            "-o ProxyCommand=none "
            "-o IdentitiesOnly=yes "
            "-o ConnectTimeout=10"
        )

        with tempfile.TemporaryDirectory(
            prefix="alt-deploy-preflight-",
        ) as temporary_name:
            temporary_dir = Path(temporary_name)
            os.chmod(temporary_dir, 0o700)

            result_path = temporary_dir / "result.json"

            command = [
                str(
                    self.settings.ansible_playbook_path
                ),
                "-i",
                f"{machine.ip},",
                "-u",
                "ansible",
                (
                    "--private-key="
                    f"{self.settings.private_key_file}"
                ),
                (
                    "--ssh-common-args="
                    f"{strict_ssh_arguments}"
                ),
                "-e",
                (
                    "ansible_python_interpreter="
                    "/usr/bin/python3"
                ),
                "-e",
                f"machine_uuid={machine.uuid}",
                "-e",
                (
                    "preflight_employee_login="
                    f"{employee_login}"
                ),
                "-e",
                (
                    "preflight_result_file="
                    f"{result_path}"
                ),
                str(self.preflight_playbook),
            ]

            try:
                completed = self.runner(
                    command,
                    180,
                )
            except subprocess.TimeoutExpired as exc:
                raise ControlError(
                    code="preflight_failed",
                    message=(
                        "Ansible preflight timed out"
                    ),
                    exit_code=5,
                    details={
                        "timeout": exc.timeout,
                    },
                ) from exc

            if completed.returncode != 0:
                raise ControlError(
                    code="preflight_failed",
                    message=(
                        "Ansible preflight failed"
                    ),
                    exit_code=5,
                    details={
                        "returncode": (
                            completed.returncode
                        ),
                        "stdout": _bounded(
                            completed.stdout
                        ),
                        "stderr": _bounded(
                            completed.stderr
                        ),
                    },
                )

            if not result_path.is_file():
                raise ControlError(
                    code="preflight_failed",
                    message=(
                        "Ansible preflight did not "
                        "produce a result"
                    ),
                    exit_code=5,
                    details={
                        "stdout": _bounded(
                            completed.stdout
                        ),
                        "stderr": _bounded(
                            completed.stderr
                        ),
                    },
                )

            try:
                result = read_json(result_path)
            except (OSError, ValueError) as exc:
                raise ControlError(
                    code="preflight_failed",
                    message=(
                        "Ansible preflight produced "
                        "an invalid result"
                    ),
                    exit_code=5,
                ) from exc

            return result

    @property
    def provision_playbook(self) -> Path:
        return (
            self.settings.ansible_project_dir
            / "playbooks"
            / "02-provision-account.yml"
        )

    def _validate_provision_files(
        self,
        job: JobRecord,
    ) -> None:
        required_files = {
            "ansible_playbook": (
                self.settings.ansible_playbook_path
            ),
            "private_key": (
                self.settings.private_key_file
            ),
            "known_hosts": (
                self.settings.known_hosts_file
            ),
            "provision_playbook": (
                self.provision_playbook
            ),
            "request_file": (
                job.job_dir / "request.json"
            ),
            "job_stage_helper": (
                self.settings.job_stage_helper_path
            ),
        }

        missing = [
            {
                "name": name,
                "path": str(path),
            }
            for name, path in required_files.items()
            if not path.is_file()
        ]

        if missing:
            raise ControlError(
                code="provision_not_configured",
                message=(
                    "ALT workstation provisioning "
                    "is not fully configured"
                ),
                exit_code=7,
                details={"missing": missing},
            )

    def run_provision(
        self,
        job: JobRecord,
        log_stream: TextIO,
    ) -> dict[str, object]:
        self._validate_provision_files(job)

        machine = MachineRepository(
            self.settings
        ).get(job.machine_uuid)

        if not machine.ip:
            raise ControlError(
                code="machine_missing_ip",
                message=(
                    "Registered machine has no IP address"
                ),
                exit_code=7,
                details={
                    "machine_uuid": machine.uuid,
                },
            )

        result_path = (
            job.job_dir / "provision-result.json"
        )
        result_path.unlink(missing_ok=True)

        strict_ssh_arguments = (
            "-o UserKnownHostsFile="
            f"{self.settings.known_hosts_file} "
            "-o StrictHostKeyChecking=yes "
            "-o ProxyCommand=none "
            "-o IdentitiesOnly=yes "
            "-o ConnectTimeout=10"
        )

        command = [
            str(self.settings.ansible_playbook_path),
            "-i",
            f"{machine.ip},",
            "-u",
            "ansible",
            (
                "--private-key="
                f"{self.settings.private_key_file}"
            ),
            (
                "--ssh-common-args="
                f"{strict_ssh_arguments}"
            ),
            "-e",
            (
                "ansible_python_interpreter="
                "/usr/bin/python3"
            ),
            "-e",
            f"@{job.job_dir / 'request.json'}",
            "-e",
            f"job_id={job.job_id}",
            "-e",
            (
                "provision_result_file="
                f"{result_path}"
            ),
            "-e",
            (
                "job_stage_helper_path="
                f"{self.settings.job_stage_helper_path}"
            ),
            str(self.provision_playbook),
        ]

        try:
            completed = subprocess.run(
                command,
                shell=False,
                text=True,
                stdout=log_stream,
                stderr=subprocess.STDOUT,
                timeout=1800,
                check=False,
                cwd=self.settings.ansible_project_dir,
                env=self._ansible_environment(),
            )
        except subprocess.TimeoutExpired as exc:
            raise ControlError(
                code="ansible_provision_failed",
                message=(
                    "Ansible provision timed out"
                ),
                exit_code=7,
                details={
                    "timeout": exc.timeout,
                },
            ) from exc
        except OSError as exc:
            raise ControlError(
                code="ansible_provision_failed",
                message=(
                    "Unable to execute Ansible provision"
                ),
                exit_code=7,
                details={
                    "error": str(exc),
                },
            ) from exc

        if completed.returncode != 0:
            raise ControlError(
                code="ansible_provision_failed",
                message=(
                    "Ansible workstation provision failed"
                ),
                exit_code=7,
                details={
                    "returncode": completed.returncode,
                    "log_file": str(
                        job.job_dir / "ansible.log"
                    ),
                },
            )

        if not result_path.is_file():
            raise ControlError(
                code="ansible_provision_failed",
                message=(
                    "Ansible provision did not produce "
                    "a result"
                ),
                exit_code=7,
            )

        try:
            return read_json(result_path)
        except (OSError, ValueError) as exc:
            raise ControlError(
                code="ansible_provision_failed",
                message=(
                    "Ansible provision produced "
                    "an invalid result"
                ),
                exit_code=7,
            ) from exc
