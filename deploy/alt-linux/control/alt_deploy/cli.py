from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import TextIO

from .ansible import AnsibleController
from .config import Settings
from .errors import ControlError
from .jobs import JobRepository
from .jsonio import read_json
from .provision import (
    ProvisionPlanner,
    ProvisionRequest,
)
from .registry import MachineRepository


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

    job_status = job_commands.add_parser("status")
    job_status.add_argument("job_id")

    job_log = job_commands.add_parser("log")
    job_log.add_argument("job_id")

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
