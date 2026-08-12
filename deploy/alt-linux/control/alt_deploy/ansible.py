from __future__ import annotations

import os
import re
import subprocess
import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import TextIO

from .assignments import assert_safe_payload
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

_PROVISION_FAILURE_RESULT_FIELDS = frozenset(
    {
        "schema_version",
        "status",
        "machine_uuid",
        "final_hostname",
        "employee_login",
        "profile",
        "job_id",
        "phase",
        "retryable",
        "error",
    }
)
_PROVISION_FAILURE_PHASES = frozenset(
    {"identity", "employee", "login_screen", "verifying", "finalize"}
)
_PROVISION_FAILURE_CLASSES = frozenset(
    {
        "fatal_invariant",
        "retryable_transient",
        "ambiguous_mutation",
        "cleanup_failure",
    }
)
_SAFE_ERROR_CODE_RE = re.compile(r"^[a-z][a-z0-9_]{1,79}$")


def _read_provision_failure_result(
    result_path: Path,
    *,
    job: JobRecord,
) -> dict[str, object] | None:
    try:
        result = read_json(result_path)
    except (OSError, ValueError):
        return None

    if "schema_version" not in result:
        return None

    if set(result) != _PROVISION_FAILURE_RESULT_FIELDS:
        raise ControlError(
            code="provision_result_contract_invalid",
            message="Provision produced an invalid failure result",
            exit_code=7,
        )

    expected = {
        "schema_version": 1,
        "status": "failed",
        "machine_uuid": job.machine_uuid,
        "final_hostname": str(job.request["final_hostname"]),
        "employee_login": str(job.request["employee_login"]),
        "profile": str(job.request["profile"]),
        "job_id": job.job_id,
    }

    for key, expected_value in expected.items():
        if result.get(key) != expected_value:
            raise ControlError(
                code="provision_result_contract_invalid",
                message="Provision failure result does not match its job",
                exit_code=7,
            )

    if result.get("phase") not in _PROVISION_FAILURE_PHASES:
        raise ControlError(
            code="provision_result_contract_invalid",
            message="Provision failure result has an invalid phase",
            exit_code=7,
        )

    if not isinstance(result.get("retryable"), bool):
        raise ControlError(
            code="provision_result_contract_invalid",
            message="Provision failure result has an invalid retry flag",
            exit_code=7,
        )

    error = result.get("error")
    if not isinstance(error, dict) or set(error) != {
        "code",
        "class",
        "safe_message",
    }:
        raise ControlError(
            code="provision_result_contract_invalid",
            message="Provision failure result has an invalid error",
            exit_code=7,
        )

    code = error.get("code")
    error_class = error.get("class")
    safe_message = error.get("safe_message")
    if not (
        isinstance(code, str)
        and _SAFE_ERROR_CODE_RE.fullmatch(code)
        and error_class in _PROVISION_FAILURE_CLASSES
        and isinstance(safe_message, str)
        and safe_message
        and len(safe_message) <= 240
    ):
        raise ControlError(
            code="provision_result_contract_invalid",
            message="Provision failure result contains unsafe error fields",
            exit_code=7,
        )

    assert_safe_payload(result)
    return result


def _raise_structured_provision_failure(
    result_path: Path,
    *,
    job: JobRecord,
) -> None:
    failure_result = _read_provision_failure_result(
        result_path,
        job=job,
    )
    if failure_result is None:
        return

    failure_error = failure_result["error"]
    assert isinstance(failure_error, dict)
    raise ControlError(
        code=str(failure_error["code"]),
        message=str(failure_error["safe_message"]),
        exit_code=7,
        details={
            "phase": failure_result["phase"],
            "retryable": failure_result["retryable"],
            "result_file": str(result_path),
        },
    )


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
                        "failure_kind": "ssh_timeout",
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
                        "failure_kind": _classify_preflight_failure(
                            stdout=completed.stdout,
                            stderr=completed.stderr,
                        ),
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
                        "failure_kind": "ansible_failed",
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
                    details={
                        "failure_kind": "ansible_failed",
                    },
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

        helper = self.settings.job_stage_helper_path
        not_executable = []
        if helper.is_file() and not os.access(helper, os.X_OK):
            not_executable.append(
                {
                    "name": "job_stage_helper",
                    "path": str(helper),
                }
            )

        details: dict[str, object] = {}
        if missing:
            details["missing"] = missing
        if not_executable:
            details["not_executable"] = not_executable

        if details:
            raise ControlError(
                code="provision_not_configured",
                message=(
                    "ALT workstation provisioning "
                    "is not fully configured"
                ),
                exit_code=7,
                details=details,
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
            _raise_structured_provision_failure(
                result_path,
                job=job,
            )
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
            _raise_structured_provision_failure(
                result_path,
                job=job,
            )
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
            _raise_structured_provision_failure(
                result_path,
                job=job,
            )

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
