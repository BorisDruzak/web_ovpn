from __future__ import annotations

import argparse
import json
import os
import sys
from collections.abc import Sequence
from datetime import datetime, timezone
from pathlib import Path
from typing import TextIO

from .ansible import AnsibleController
from .config import Settings
from .controller_permissions import ControllerPermissionAuditor
from .controller_readiness import ControllerReadinessChecker
from .errors import ControlError
from .install_execution import (
    ExecutionAuthorizationService,
    load_execution_release_archives,
)
from .job_reconcile import JobReconciler
from .job_retention import JobRetentionManager
from .install_session_approval import InstallSessionApprovalService
from .install_session_repository import InstallSessionRepository
from .jobs import ACTIVE_STATES, JobRepository
from .jsonio import read_json
from .machine_archive import MachineArchiveService
from .stale_registration_recovery import (
    StaleRegistrationRecoveryService,
)
from .provision import (
    ProvisionPlanner,
    ProvisionRequest,
)
from .registry import MachineRepository
from .vault import VaultHealthChecker


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="workstationctl"
    )

    parser.add_argument(
        "--json",
        action="store_true",
        dest="as_json",
    )

    commands = parser.add_subparsers(
        dest="command",
        required=True,
    )

    machines = commands.add_parser("machines")
    machine_commands = machines.add_subparsers(
        dest="machine_command",
        required=True,
    )

    machine_commands.add_parser("list")

    show = machine_commands.add_parser("show")
    show.add_argument("machine_uuid")

    remove = machine_commands.add_parser("remove")
    remove_commands = remove.add_subparsers(
        dest="machine_remove_command",
        required=True,
    )

    remove_preview = remove_commands.add_parser("preview")
    remove_preview.add_argument("machine_identifier")

    remove_apply = remove_commands.add_parser("apply")
    remove_apply.add_argument("machine_identifier")
    remove_apply.add_argument(
        "--reason",
        required=True,
    )

    recovery = machine_commands.add_parser(
        "recover-stale-registration"
    )
    recovery_commands = recovery.add_subparsers(
        dest="machine_recovery_command",
        required=True,
    )
    recovery_preview = recovery_commands.add_parser("preview")
    recovery_preview.add_argument("machine_identifier")
    recovery_apply = recovery_commands.add_parser("apply")
    recovery_apply.add_argument("machine_identifier")
    recovery_apply.add_argument("--reason", required=True)

    preflight = commands.add_parser("preflight")
    preflight.add_argument("machine_uuid")

    provision = commands.add_parser("provision")
    provision_commands = provision.add_subparsers(
        dest="provision_command",
        required=True,
    )

    preview = provision_commands.add_parser("preview")
    preview.add_argument("machine_uuid")
    preview.add_argument(
        "--vars-file",
        required=True,
    )

    start = provision_commands.add_parser("start")
    start.add_argument("machine_uuid")
    start.add_argument(
        "--vars-file",
        required=True,
    )

    jobs = commands.add_parser("jobs")
    job_commands = jobs.add_subparsers(
        dest="job_command",
        required=True,
    )

    job_commands.add_parser("active")

    job_status = job_commands.add_parser("status")
    job_status.add_argument("job_id")

    job_log = job_commands.add_parser("log")
    job_log.add_argument("job_id")

    job_commands.add_parser("reconcile")

    job_cleanup = job_commands.add_parser("cleanup")
    job_cleanup.add_argument(
        "--apply",
        action="store_true",
    )

    vault = commands.add_parser("vault")
    vault_commands = vault.add_subparsers(
        dest="vault_command",
        required=True,
    )
    vault_commands.add_parser("check")

    controller = commands.add_parser("controller")
    controller_commands = controller.add_subparsers(
        dest="controller_command",
        required=True,
    )
    controller_commands.add_parser("readiness")
    permissions = controller_commands.add_parser(
        "permissions"
    )
    permissions.add_argument(
        "permission_action",
        nargs="?",
        choices=("repair",),
    )

    install_sessions = commands.add_parser(
        "install-sessions", allow_abbrev=False
    )
    install_commands = install_sessions.add_subparsers(
        dest="install_session_command", required=True
    )
    install_commands.add_parser("list")
    install_show = install_commands.add_parser("show")
    install_show.add_argument("session_id")
    install_preview = install_commands.add_parser("preview")
    install_preview.add_argument("session_id")
    install_approve = install_commands.add_parser("approve")
    install_approve.add_argument("session_id")
    install_approve.add_argument("--inventory-sha256", required=True)
    install_approve.add_argument("--disk-fingerprint", required=True)
    install_approve.add_argument("--reason", required=True)
    install_cancel = install_commands.add_parser("cancel")
    install_cancel.add_argument("session_id")
    install_cancel.add_argument("--reason", required=True)
    install_authorize_execution = install_commands.add_parser(
        "authorize-execution", allow_abbrev=False
    )
    install_authorize_execution.add_argument("session_id")
    install_authorize_execution.add_argument(
        "--plan-sha256", required=True
    )
    install_authorize_execution.add_argument(
        "--inventory-sha256", required=True
    )
    install_authorize_execution.add_argument(
        "--disk-fingerprint", required=True
    )
    install_authorize_execution.add_argument(
        "--confirm-target", required=True
    )
    install_authorize_execution.add_argument("--reason", required=True)
    install_cancel_execution = install_commands.add_parser(
        "cancel-execution", allow_abbrev=False
    )
    install_cancel_execution.add_argument("session_id")
    install_cancel_execution.add_argument("--reason", required=True)

    return parser


def _write_json(
    stream: TextIO,
    payload: dict[str, object],
) -> None:
    stream.write(
        json.dumps(
            payload,
            ensure_ascii=False,
            indent=2,
        )
        + "\n"
    )


def _read_request_file(
    path_text: str,
) -> dict[str, object]:
    path = Path(path_text)

    try:
        return read_json(path)
    except (OSError, ValueError) as exc:
        raise ControlError(
            code="invalid_request_file",
            message=(
                "Unable to read provision request: "
                f"{path}"
            ),
            exit_code=4,
        ) from exc


_PRIVATE_INSTALL_SESSION_FIELDS = frozenset(
    {"source_ip", "agent_boot_id", "execution"}
)
_SENSITIVE_KEY_PARTS = (
    "bearer",
    "credential",
    "password",
    "private_key",
    "secret",
    "token",
)
_SENSITIVE_VALUE_MARKERS = ("$y$", "PRIVATE KEY-----")


def _public_value(value: object) -> object:
    if isinstance(value, dict):
        return {
            key: _public_value(nested)
            for key, nested in value.items()
            if isinstance(key, str)
            and not any(
                part in key.casefold() for part in _SENSITIVE_KEY_PARTS
            )
        }
    if isinstance(value, list):
        return [_public_value(item) for item in value]
    if isinstance(value, str) and any(
        marker in value for marker in _SENSITIVE_VALUE_MARKERS
    ):
        return "[redacted]"
    return value


def _public_install_session(
    session: dict[str, object],
) -> dict[str, object]:
    return {
        key: _public_value(value)
        for key, value in session.items()
        if key not in _PRIVATE_INSTALL_SESSION_FIELDS
    }


def _require_execution_root() -> None:
    if getattr(os, "geteuid", lambda: -1)() != 0:
        raise ControlError(
            code="execution_root_required",
            message="Execution command requires root",
            exit_code=4,
        )


def _execution_result(
    session_id: str,
    status: dict[str, object],
    *,
    expected_state: str,
) -> dict[str, object]:
    execution = status.get("execution")
    state = (
        execution.get("state")
        if isinstance(execution, dict)
        else None
    )
    if state != expected_state:
        raise ControlError(
            code="execution_status_invalid",
            message="Execution command result is invalid",
            exit_code=6,
        )
    return {
        "status": "ok",
        "session": {
            "execution_id": (
                f"{session_id}:execution-{int(execution['revision']):04d}"
            ),
            "session_id": session_id,
            "execution_state": state,
        },
    }


def main(
    argv: Sequence[str] | None = None,
    *,
    settings: Settings | None = None,
    stdout: TextIO = sys.stdout,
    stderr: TextIO = sys.stderr,
) -> int:
    parsed = build_parser().parse_args(
        list(argv) if argv is not None else None
    )

    active_settings = (
        settings or Settings.from_env()
    )

    repository = MachineRepository(
        active_settings
    )

    try:
        if (
            parsed.command == "machines"
            and parsed.machine_command == "list"
        ):
            payload: dict[str, object] = {
                "status": "ok",
                "machines": [
                    machine.to_public_dict()
                    for machine in repository.list()
                ],
            }

        elif (
            parsed.command == "install-sessions"
            and parsed.install_session_command == "list"
        ):
            sessions = InstallSessionRepository(active_settings).list_statuses()
            payload = {"status": "ok", "sessions": [
                _public_install_session(session)
                for session in sessions
            ]}

        elif (
            parsed.command == "install-sessions"
            and parsed.install_session_command == "show"
        ):
            session = InstallSessionRepository(active_settings).load_status(parsed.session_id)
            payload = {
                "status": "ok",
                "session": _public_install_session(session),
            }

        elif (
            parsed.command == "install-sessions"
            and parsed.install_session_command == "preview"
        ):
            payload = {"status": "ok", "preview": InstallSessionApprovalService(
                active_settings, clock=lambda: "", euid=lambda: -1
            ).preview(parsed.session_id)}

        elif (
            parsed.command == "install-sessions"
            and parsed.install_session_command == "approve"
        ):
            payload = {"status": "ok", "session": InstallSessionApprovalService(
                active_settings, clock=lambda: datetime.now(timezone.utc).isoformat()
            ).approve(parsed.session_id, inventory_sha256=parsed.inventory_sha256,
                      disk_fingerprint_value=parsed.disk_fingerprint, reason=parsed.reason)}

        elif (
            parsed.command == "install-sessions"
            and parsed.install_session_command == "cancel"
        ):
            payload = {"status": "ok", "session": InstallSessionApprovalService(
                active_settings, clock=lambda: datetime.now(timezone.utc).isoformat()
            ).cancel(parsed.session_id, reason=parsed.reason)}

        elif (
            parsed.command == "install-sessions"
            and parsed.install_session_command == "authorize-execution"
        ):
            _require_execution_root()
            result = ExecutionAuthorizationService(
                active_settings,
                clock=lambda: datetime.now(timezone.utc).isoformat(),
                release_archives=load_execution_release_archives(
                    active_settings
                ),
            ).authorize(
                parsed.session_id,
                plan_sha256=parsed.plan_sha256,
                inventory_sha256=parsed.inventory_sha256,
                disk_fingerprint_value=parsed.disk_fingerprint,
                confirm_target=parsed.confirm_target,
                reason=parsed.reason,
            )
            payload = _execution_result(
                parsed.session_id,
                dict(result.status),
                expected_state="authorized",
            )

        elif (
            parsed.command == "install-sessions"
            and parsed.install_session_command == "cancel-execution"
        ):
            _require_execution_root()
            execution_status = ExecutionAuthorizationService(
                active_settings,
                clock=lambda: datetime.now(timezone.utc).isoformat(),
            ).cancel(parsed.session_id, reason=parsed.reason)
            payload = _execution_result(
                parsed.session_id,
                execution_status,
                expected_state="cancelled",
            )

        elif (
            parsed.command == "machines"
            and parsed.machine_command == "show"
        ):
            payload = {
                "status": "ok",
                "machine": repository.get(
                    parsed.machine_uuid
                ).to_public_dict(),
            }

        elif (
            parsed.command == "machines"
            and parsed.machine_command == "remove"
            and parsed.machine_remove_command == "preview"
        ):
            payload = {
                "status": "ok",
                "preview": MachineArchiveService(
                    active_settings
                ).preview(
                    parsed.machine_identifier
                ).to_public_dict(),
            }

        elif (
            parsed.command == "machines"
            and parsed.machine_command == "remove"
            and parsed.machine_remove_command == "apply"
        ):
            if os.geteuid() != 0:
                raise ControlError(
                    code="root_required",
                    message=(
                        "Machine archive apply must be executed "
                        "as root"
                    ),
                    exit_code=6,
                )

            payload = {
                "status": "ok",
                "archive": MachineArchiveService(
                    active_settings
                ).apply(
                    parsed.machine_identifier,
                    parsed.reason,
                ).to_public_dict(),
            }

        elif (
            parsed.command == "machines"
            and parsed.machine_command
            == "recover-stale-registration"
            and parsed.machine_recovery_command == "preview"
        ):
            payload = {
                "status": "ok",
                "preview": StaleRegistrationRecoveryService(
                    active_settings
                ).preview(parsed.machine_identifier).to_public_dict(),
            }

        elif (
            parsed.command == "machines"
            and parsed.machine_command
            == "recover-stale-registration"
            and parsed.machine_recovery_command == "apply"
        ):
            if os.geteuid() != 0:
                raise ControlError(
                    code="root_required",
                    message=(
                        "Stale registration recovery apply must be "
                        "executed as root"
                    ),
                    exit_code=6,
                )
            payload = {
                "status": "ok",
                "recovery": StaleRegistrationRecoveryService(
                    active_settings
                ).apply(
                    parsed.machine_identifier,
                    parsed.reason,
                ).to_public_dict(),
            }

        elif parsed.command == "preflight":
            machine = repository.get(
                parsed.machine_uuid
            )

            controller = AnsibleController(
                active_settings
            )

            try:
                preflight_result = (
                    controller.run_preflight(machine)
                )
            except ControlError as exc:
                repository.persist_preflight(
                    machine,
                    {
                        "status": "error",
                        "error": (
                            exc.to_dict()["error"]
                        ),
                    },
                    succeeded=False,
                )
                raise

            repository.persist_preflight(
                machine,
                preflight_result,
                succeeded=True,
            )

            payload = {
                "status": "ok",
                "machine_uuid": machine.uuid,
                "preflight": preflight_result,
            }

        elif (
            parsed.command == "provision"
            and parsed.provision_command
            in {"preview", "start"}
        ):
            request_payload = _read_request_file(
                parsed.vars_file
            )

            request = ProvisionRequest.from_mapping(
                request_payload,
                expected_uuid=parsed.machine_uuid,
            )

            planner = ProvisionPlanner(
                active_settings
            )

            if parsed.provision_command == "preview":
                payload = planner.preview(
                    parsed.machine_uuid,
                    request,
                )
            else:
                job = planner.start(
                    parsed.machine_uuid,
                    request,
                )

                payload = {
                    "status": "ok",
                    "job": job.to_public_dict(),
                }

        elif (
            parsed.command == "jobs"
            and parsed.job_command == "active"
        ):
            active_jobs = [
                job
                for job in JobRepository(
                    active_settings
                ).list()
                if job.state in ACTIVE_STATES
            ]

            payload = {
                "status": "ok",
                "active_jobs": [
                    {
                        "job_id": job.job_id,
                        "machine_uuid": job.machine_uuid,
                        "state": job.state,
                        "stage": job.stage,
                        "created_at": job.created_at,
                    }
                    for job in active_jobs
                ],
                "count": len(active_jobs),
            }

        elif (
            parsed.command == "jobs"
            and parsed.job_command == "status"
        ):
            job = JobRepository(
                active_settings
            ).get(parsed.job_id)

            payload = {
                "status": "ok",
                "job": job.to_public_dict(),
            }

        elif (
            parsed.command == "jobs"
            and parsed.job_command == "log"
        ):
            log_result = JobRepository(
                active_settings
            ).read_log(parsed.job_id)

            payload = {
                "status": "ok",
                **log_result,
            }

        elif (
            parsed.command == "jobs"
            and parsed.job_command == "reconcile"
        ):
            payload = {
                "status": "ok",
                "reconciliation": JobReconciler(
                    active_settings
                ).reconcile(),
            }

        elif (
            parsed.command == "jobs"
            and parsed.job_command == "cleanup"
        ):
            if parsed.apply and os.geteuid() != 0:
                raise ControlError(
                    code="root_required",
                    message=(
                        "Mutating job cleanup must be executed "
                        "as root"
                    ),
                    exit_code=6,
                )

            payload = {
                "status": "ok",
                "cleanup": JobRetentionManager(
                    active_settings
                ).cleanup(apply=parsed.apply),
            }

        elif (
            parsed.command == "vault"
            and parsed.vault_command == "check"
        ):
            payload = {
                "status": "ok",
                "vault": VaultHealthChecker(
                    active_settings
                ).check(),
            }

        elif (
            parsed.command == "controller"
            and parsed.controller_command == "readiness"
        ):
            payload = {
                "status": "ok",
                "controller_readiness": ControllerReadinessChecker(
                    active_settings
                ).check(),
            }

        elif (
            parsed.command == "controller"
            and parsed.controller_command == "permissions"
        ):
            auditor = ControllerPermissionAuditor(
                active_settings
            )
            if parsed.permission_action == "repair":
                permissions_result = auditor.repair()
            else:
                permissions_result = auditor.check()

            payload = {
                "status": "ok",
                "controller_permissions": permissions_result,
            }

        else:
            raise ControlError(
                code="unsupported_command",
                message="Unsupported command",
                exit_code=2,
            )

    except ControlError as exc:
        if parsed.as_json:
            _write_json(
                stdout,
                exc.to_dict(),
            )
        else:
            stderr.write(
                f"ERROR [{exc.code}]: "
                f"{exc.message}\n"
            )

        return exc.exit_code

    _write_json(stdout, payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
