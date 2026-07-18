from __future__ import annotations

import argparse
import os
import sys
from collections.abc import Sequence
from typing import Any

from .ansible import AnsibleController
from .assignments import (
    AssignmentRepository,
    assert_safe_payload,
)
from .config import Settings
from .errors import ControlError
from .job_stages import JobStageManager
from .jobs import JobRepository, utc_now
from .jsonio import atomic_write_json
from .models import JobRecord
from .registry import MachineRepository


RESULT_FIELDS = frozenset(
    {
        "machine_uuid",
        "final_hostname",
        "employee_login",
        "employee_full_name",
        "profile",
        "job_id",
        "completed_at",
        "verification",
    }
)

VERIFICATION_FIELDS = frozenset(
    {
        "hostname",
        "employee_exists",
        "employee_not_wheel",
        "employee_no_sudo",
        "ansible_sudo",
        "lightdm_hides_ansible",
        "lightdm_shows_employee",
        "lightdm_autologin_disabled",
    }
)


def _validate_result(
    job: JobRecord,
    result: dict[str, object],
) -> dict[str, object]:
    if set(result) != RESULT_FIELDS:
        raise ControlError(
            code="invalid_provision_result",
            message=(
                "Provision result contains unexpected "
                "or missing fields"
            ),
            exit_code=7,
            details={
                "fields": sorted(result),
            },
        )

    expected = {
        "machine_uuid": job.machine_uuid,
        "final_hostname": str(
            job.request["final_hostname"]
        ),
        "employee_login": str(
            job.request["employee_login"]
        ),
        "employee_full_name": str(
            job.request["employee_full_name"]
        ),
        "profile": str(job.request["profile"]),
        "job_id": job.job_id,
    }

    for key, expected_value in expected.items():
        if str(result.get(key) or "") != expected_value:
            raise ControlError(
                code="invalid_provision_result",
                message=(
                    f"Provision result mismatch: {key}"
                ),
                exit_code=7,
            )

    if not str(result.get("completed_at") or ""):
        raise ControlError(
            code="invalid_provision_result",
            message=(
                "Provision result has no completion time"
            ),
            exit_code=7,
        )

    verification = result.get("verification")

    if (
        not isinstance(verification, dict)
        or set(verification) != VERIFICATION_FIELDS
        or not all(
            value is True
            for value in verification.values()
        )
    ):
        raise ControlError(
            code="invalid_provision_result",
            message=(
                "Provision result verification "
                "is incomplete or unsuccessful"
            ),
            exit_code=7,
            details={
                "verification": verification,
            },
        )

    assert_safe_payload(result)

    return dict(result)


def run_job(
    job_id: str,
    settings: Settings,
    controller: Any,
) -> int:
    jobs = JobRepository(settings)
    stages = JobStageManager(
        settings,
        repository=jobs,
    )
    assignments = AssignmentRepository(settings)
    machines = MachineRepository(settings)

    job = jobs.get(job_id)

    if job.state != "queued":
        raise ControlError(
            code="job_not_queued",
            message=(
                f"Job is not queued: {job.job_id}"
            ),
            exit_code=7,
        )

    log_path = job.job_dir / "ansible.log"
    os.chmod(log_path, 0o600)

    try:
        machine = machines.get(job.machine_uuid)

        if not machine.ip:
            raise ControlError(
                code="machine_missing_ip",
                message=(
                    "Registered machine has no IP address"
                ),
                exit_code=7,
            )

        started_at = utc_now()

        job = stages.advance(
            job.job_id,
            "validating",
            updates={
                "state": "running",
                "started_at": started_at,
            },
        )
        job = stages.advance(
            job.job_id,
            "connecting",
        )

        with log_path.open(
            "a",
            encoding="utf-8",
        ) as log_stream:
            log_stream.write(
                "\n=== ALT provision started ===\n"
            )
            log_stream.write(
                f"job_id={job.job_id}\n"
            )
            log_stream.write(
                f"machine_uuid={job.machine_uuid}\n"
            )
            log_stream.write(
                f"ip={machine.ip}\n"
            )
            log_stream.write(
                "employee_login="
                f"{job.request['employee_login']}\n"
            )
            log_stream.write(
                "final_hostname="
                f"{job.request['final_hostname']}\n"
            )
            log_stream.write(
                f"started_at={started_at}\n"
            )
            log_stream.flush()

            raw_result = controller.run_provision(
                job,
                log_stream,
            )

            if not isinstance(raw_result, dict):
                raise ControlError(
                    code="invalid_provision_result",
                    message=(
                        "Provision result is not "
                        "a JSON object"
                    ),
                    exit_code=7,
                )

            result = _validate_result(
                job,
                raw_result,
            )

            atomic_write_json(
                job.job_dir / "result.json",
                result,
            )

            assignments.write(
                job.machine_uuid,
                result,
            )

            finished_at = utc_now()

            jobs.update(
                job.job_id,
                state="successful",
                stage="complete",
                finished_at=finished_at,
                result_file=str(
                    job.job_dir / "result.json"
                ),
            )

            log_stream.write(
                "=== ALT provision completed "
                f"at {finished_at} ===\n"
            )
            log_stream.flush()

        return 0

    except Exception as exc:
        if isinstance(exc, ControlError):
            error_text = (
                f"{exc.code}: {exc.message}"
            )[-10000:]
        else:
            error_text = (
                f"{type(exc).__name__}: {exc}"
            )[-10000:]

        with log_path.open(
            "a",
            encoding="utf-8",
        ) as log_stream:
            log_stream.write(
                "\nProvision failed: "
                f"{error_text}\n"
            )
            log_stream.flush()

        jobs.update(
            job.job_id,
            state="failed",
            finished_at=utc_now(),
            error=error_text,
        )

        return 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="alt-provision-worker"
    )
    parser.add_argument(
        "--job-id",
        required=True,
    )
    return parser


def main(
    argv: Sequence[str] | None = None,
) -> int:
    parsed = build_parser().parse_args(
        list(argv) if argv is not None else None
    )

    settings = Settings.from_env()
    controller = AnsibleController(settings)

    try:
        return run_job(
            parsed.job_id,
            settings,
            controller,
        )
    except ControlError as exc:
        sys.stderr.write(
            f"ERROR [{exc.code}]: {exc.message}\n"
        )
        return exc.exit_code


if __name__ == "__main__":
    raise SystemExit(main())
