from __future__ import annotations

import argparse
import json
import os
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import TextIO

from .ansible import AnsibleController
from .config import Settings
from .controller_permissions import ControllerPermissionAuditor
from .controller_readiness import ControllerReadinessChecker
from .errors import ControlError
from .job_reconcile import JobReconciler
from .job_retention import JobRetentionManager
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
