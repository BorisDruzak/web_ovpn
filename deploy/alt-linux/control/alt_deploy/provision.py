from __future__ import annotations

import os
import pwd
import re
import unicodedata
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from .assignments import AssignmentRepository
from .config import Settings
from .errors import ControlError
from .job_stages import JobStageManager
from .jobs import JobRepository, utc_now
from .launcher import SystemdLauncher
from .jsonio import read_json
from .locks import exclusive_lock
from .registry import MachineRepository
from .vault import VaultHealthChecker


REQUEST_FIELDS = frozenset(
    {
        "machine_uuid",
        "employee_login",
        "employee_full_name",
        "final_hostname",
        "profile",
    }
)

PROTECTED_LOGINS = frozenset(
    {
        "root",
        "ansible",
        "osn-admin",
    }
)

LOGIN_RE = re.compile(
    r"^[a-z0-9](?:[a-z0-9_-]{0,30}[a-z0-9])?$"
)

HOSTNAME_RE = re.compile(
    r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$"
)

PROVISION_ACTIONS = (
    "validate_registered_machine",
    "run_preflight",
    "set_final_hostname",
    "create_or_reconcile_local_employee",
    "remove_employee_admin_rights",
    "hide_ansible_from_lightdm",
    "keep_employee_visible_in_lightdm",
    "disable_lightdm_autologin",
    "verify_provisioning",
    "write_assignment_records",
)


@dataclass(frozen=True)
class ProvisionRequest:
    machine_uuid: str
    employee_login: str
    employee_full_name: str
    final_hostname: str
    profile: str

    @classmethod
    def from_mapping(
        cls,
        payload: Mapping[str, object],
        expected_uuid: str,
    ) -> "ProvisionRequest":
        payload_keys = set(payload)

        unknown_fields = sorted(
            payload_keys - REQUEST_FIELDS
        )
        if unknown_fields:
            raise ControlError(
                code="unknown_request_fields",
                message="Provision request contains unknown fields",
                exit_code=4,
                details={"fields": unknown_fields},
            )

        missing_fields = sorted(
            REQUEST_FIELDS - payload_keys
        )
        if missing_fields:
            raise ControlError(
                code="missing_request_fields",
                message="Provision request is missing required fields",
                exit_code=4,
                details={"fields": missing_fields},
            )

        expected_machine_uuid = (
            expected_uuid.strip().lower()
        )
        machine_uuid = str(
            payload["machine_uuid"]
        ).strip().lower()

        if machine_uuid != expected_machine_uuid:
            raise ControlError(
                code="machine_uuid_mismatch",
                message=(
                    "Provision request UUID does not match "
                    "the selected machine"
                ),
                exit_code=4,
                details={
                    "expected": expected_machine_uuid,
                    "actual": machine_uuid,
                },
            )

        raw_login = str(
            payload["employee_login"]
        ).strip()
        employee_login = raw_login.lower()

        if (
            employee_login in PROTECTED_LOGINS
            and raw_login != employee_login
        ):
            raise ControlError(
                code="invalid_employee_login",
                message="Employee login has an invalid format",
                exit_code=4,
            )

        if not LOGIN_RE.fullmatch(employee_login):
            raise ControlError(
                code="invalid_employee_login",
                message="Employee login has an invalid format",
                exit_code=4,
            )

        if employee_login in PROTECTED_LOGINS:
            raise ControlError(
                code="protected_employee_login",
                message=(
                    "The requested employee login is reserved"
                ),
                exit_code=4,
            )

        employee_full_name = str(
            payload["employee_full_name"]
        ).strip()

        has_control_characters = any(
            unicodedata.category(character).startswith("C")
            for character in employee_full_name
        )

        if (
            not employee_full_name
            or len(employee_full_name) > 200
            or has_control_characters
        ):
            raise ControlError(
                code="invalid_employee_full_name",
                message="Employee full name is invalid",
                exit_code=4,
            )

        final_hostname = str(
            payload["final_hostname"]
        ).strip().lower()

        if not HOSTNAME_RE.fullmatch(final_hostname):
            raise ControlError(
                code="invalid_hostname",
                message="Final hostname has an invalid format",
                exit_code=4,
            )

        profile = str(
            payload["profile"]
        ).strip().lower()

        if profile != "standard":
            raise ControlError(
                code="invalid_profile",
                message=(
                    "Only the standard workstation profile "
                    "is supported"
                ),
                exit_code=4,
            )

        return cls(
            machine_uuid=machine_uuid,
            employee_login=employee_login,
            employee_full_name=employee_full_name,
            final_hostname=final_hostname,
            profile=profile,
        )

    def to_dict(self) -> dict[str, str]:
        return {
            "machine_uuid": self.machine_uuid,
            "employee_login": self.employee_login,
            "employee_full_name": self.employee_full_name,
            "final_hostname": self.final_hostname,
            "profile": self.profile,
        }


class ProvisionPlanner:
    def __init__(
        self,
        settings: Settings,
        *,
        launcher: SystemdLauncher | None = None,
    ):
        self.settings = settings
        self.machines = MachineRepository(settings)
        self.jobs = JobRepository(settings)
        self.stages = JobStageManager(
            settings,
            repository=self.jobs,
        )
        self.assignments = AssignmentRepository(settings)
        self.launcher = launcher or SystemdLauncher(
            settings
        )

    @property
    def vault_file(self):
        return (
            self.settings.ansible_project_dir
            / "group_vars"
            / "vault.yml"
        )

    @property
    def vault_password_file(self):
        return (
            self.settings.ansible_project_dir.parent
            / ".ansible-vault-pass"
        )

    def _validate_vault(self) -> None:
        try:
            VaultHealthChecker(self.settings).check()
        except ControlError as exc:
            if exc.code != "vault_unhealthy":
                raise

            checks = dict(exc.details.get("checks") or {})
            details: dict[str, object] = {"checks": checks}

            missing: list[str] = []
            if not checks.get("vault_file_exists", False):
                missing.append(str(self.vault_file))
            if not checks.get("password_file_exists", False):
                missing.append(str(self.vault_password_file))

            if missing:
                details["missing"] = missing
            elif not checks.get("vault_header", False):
                details["path"] = str(self.vault_file)

            raise ControlError(
                code="vault_not_configured",
                message=(
                    "Ansible Vault is not configured "
                    "for workstation provisioning"
                ),
                exit_code=4,
                details=details,
            ) from exc

    def _validate_assignment_uniqueness(
        self,
        request: ProvisionRequest,
    ) -> None:
        directory = self.settings.assignments_dir

        if not directory.exists():
            return

        for path in sorted(directory.glob("*.json")):
            try:
                assignment = read_json(path)
            except (OSError, ValueError) as exc:
                raise ControlError(
                    code="assignment_store_invalid",
                    message=(
                        "An assignment record cannot be read"
                    ),
                    exit_code=4,
                    details={"path": str(path)},
                ) from exc

            assignment_uuid = str(
                assignment.get("machine_uuid") or ""
            ).strip().lower()

            if assignment_uuid == request.machine_uuid:
                continue

            assigned_hostname = str(
                assignment.get("final_hostname") or ""
            ).strip().lower()

            if assigned_hostname == request.final_hostname:
                raise ControlError(
                    code="hostname_already_assigned",
                    message=(
                        "The requested hostname is already "
                        "assigned to another workstation"
                    ),
                    exit_code=4,
                    details={
                        "final_hostname": request.final_hostname,
                        "machine_uuid": assignment_uuid,
                    },
                )

            assigned_login = str(
                assignment.get("employee_login") or ""
            ).strip().lower()

            if assigned_login == request.employee_login:
                raise ControlError(
                    code="employee_login_already_assigned",
                    message=(
                        "The employee login is already assigned "
                        "to another workstation"
                    ),
                    exit_code=4,
                    details={
                        "employee_login": request.employee_login,
                        "machine_uuid": assignment_uuid,
                    },
                )

    def _preview_unlocked(
        self,
        machine_uuid: str,
        request: ProvisionRequest,
    ) -> dict[str, Any]:
        normalized_uuid = machine_uuid.strip().lower()

        if request.machine_uuid != normalized_uuid:
            raise ControlError(
                code="machine_uuid_mismatch",
                message=(
                    "Provision request UUID does not match "
                    "the selected machine"
                ),
                exit_code=4,
            )

        machine = self.machines.get(normalized_uuid)

        assignment = self.assignments.get(
            normalized_uuid
        )
        if assignment is not None:
            raise ControlError(
                code="machine_already_assigned",
                message=(
                    "The workstation already has a successful "
                    "employee assignment"
                ),
                exit_code=4,
                details={"machine_uuid": normalized_uuid},
            )

        preflight = machine.raw.get("preflight")

        if (
            machine.status != "awaiting_assignment"
            or not isinstance(preflight, dict)
            or preflight.get("status") != "ok"
        ):
            raise ControlError(
                code="machine_not_ready",
                message=(
                    "The workstation has not passed preflight"
                ),
                exit_code=4,
                details={
                    "machine_uuid": normalized_uuid,
                    "status": machine.status,
                },
            )

        active_job = self.jobs.active_for_machine(
            normalized_uuid
        )

        if active_job is not None:
            raise ControlError(
                code="machine_job_active",
                message=(
                    "The workstation already has an active "
                    "provision job"
                ),
                exit_code=4,
                details={"job_id": active_job.job_id},
            )

        self._validate_assignment_uniqueness(request)
        self._validate_vault()

        return {
            "status": "ok",
            "machine_uuid": normalized_uuid,
            "request": request.to_dict(),
            "actions": list(PROVISION_ACTIONS),
            "secrets_required": [
                "vault_employee_password_hash"
            ],
        }

    def preview(
        self,
        machine_uuid: str,
        request: ProvisionRequest,
    ) -> dict[str, Any]:
        with exclusive_lock(self.settings.lock_file):
            return self._preview_unlocked(
                machine_uuid,
                request,
            )

    def _prepare_job_for_worker(
        self,
        job,
    ) -> None:
        try:
            worker_account = pwd.getpwnam(
                "altserver"
            )
        except KeyError as exc:
            raise ControlError(
                code="worker_account_missing",
                message=(
                    "Controller account altserver "
                    "does not exist"
                ),
                exit_code=6,
            ) from exc

        paths = (
            job.job_dir,
            job.job_dir / "request.json",
            job.job_dir / "status.json",
            job.job_dir / "ansible.log",
        )

        try:
            for target in paths:
                os.chown(
                    target,
                    worker_account.pw_uid,
                    worker_account.pw_gid,
                )
        except OSError as exc:
            raise ControlError(
                code="job_ownership_failed",
                message=(
                    "Unable to prepare provision job "
                    "for the altserver worker"
                ),
                exit_code=6,
                details={
                    "path": str(target),
                    "error": str(exc),
                },
            ) from exc

    def start(
        self,
        machine_uuid: str,
        request: ProvisionRequest,
    ):
        if os.geteuid() != 0:
            raise ControlError(
                code="root_required",
                message=(
                    "Provision start must be executed "
                    "as root"
                ),
                exit_code=6,
            )

        with exclusive_lock(self.settings.lock_file):
            self._preview_unlocked(
                machine_uuid,
                request,
            )

            job = self.jobs.create(
                request.to_dict()
            )

            expected_systemd_unit = (
                f"alt-provision-{job.job_id}.service"
            )

            try:
                job = self.stages.advance_unlocked(
                    job.job_id,
                    "launching",
                    updates={
                        "systemd_unit": expected_systemd_unit,
                    },
                )

                self._prepare_job_for_worker(job)

                actual_systemd_unit = (
                    self.launcher.launch(
                        job.job_id
                    )
                )

                if (
                    actual_systemd_unit
                    != expected_systemd_unit
                ):
                    raise ControlError(
                        code="job_launch_failed",
                        message=(
                            "Provision service returned "
                            "an unexpected unit name"
                        ),
                        exit_code=6,
                        details={
                            "expected": (
                                expected_systemd_unit
                            ),
                            "actual": (
                                actual_systemd_unit
                            ),
                        },
                    )

            except ControlError as exc:
                launch_detail = str(
                    exc.details.get("stderr")
                    or exc.details.get("error")
                    or ""
                )

                error_text = (
                    f"{exc.message}\n{launch_detail}"
                ).strip()[-10000:]

                failed_job = self.jobs.update(
                    job.job_id,
                    state="failed",
                    finished_at=utc_now(),
                    error=error_text,
                )

                try:
                    self._prepare_job_for_worker(
                        failed_job
                    )
                except ControlError:
                    pass

                raise

            return self.jobs.get(job.job_id)
