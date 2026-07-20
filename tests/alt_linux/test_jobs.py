from __future__ import annotations

import fcntl
import gzip
import multiprocessing
import re
import stat
from pathlib import Path

import pytest

from alt_deploy.assignments import AssignmentRepository
from alt_deploy.errors import ControlError
from alt_deploy.job_stages import JobStageManager
from alt_deploy.jobs import JobRepository
from alt_deploy.jsonio import read_json
from alt_deploy.locks import exclusive_lock
from alt_deploy.registry import MachineRepository

from test_registry_cli import (
    MACHINE_UUID,
    make_settings,
    write_machine,
)


JOB_ID_RE = re.compile(
    r"^job-\d{8}T\d{6}Z-[0-9a-f]{8}$"
)


def provision_request(
    machine_uuid: str = MACHINE_UUID,
) -> dict[str, str]:
    return {
        "machine_uuid": machine_uuid,
        "employee_login": "i-ivanov",
        "employee_full_name": "Иванов Иван Иванович",
        "final_hostname": "buh-023",
        "profile": "standard",
    }


def assignment_payload(
    *,
    job_id: str = "job-test",
) -> dict[str, object]:
    return {
        "machine_uuid": MACHINE_UUID,
        "employee_login": "i-ivanov",
        "employee_full_name": "Иванов Иван Иванович",
        "final_hostname": "buh-023",
        "profile": "standard",
        "job_id": job_id,
        "completed_at": "2026-07-16T12:30:00+00:00",
        "verification": {
            "hostname": True,
            "employee_exists": True,
        },
    }


def try_nonblocking_lock(
    path_text: str,
    connection,
) -> None:
    path = Path(path_text)

    with path.open("a+", encoding="utf-8") as handle:
        try:
            fcntl.flock(
                handle.fileno(),
                fcntl.LOCK_EX | fcntl.LOCK_NB,
            )
        except BlockingIOError:
            connection.send("blocked")
        else:
            connection.send("acquired")
            fcntl.flock(
                handle.fileno(),
                fcntl.LOCK_UN,
            )
        finally:
            connection.close()


def test_create_job_uses_private_files_and_valid_id(
    tmp_path: Path,
) -> None:
    settings = make_settings(tmp_path)
    repository = JobRepository(settings)

    job = repository.create(provision_request())

    assert JOB_ID_RE.fullmatch(job.job_id)
    assert job.machine_uuid == MACHINE_UUID
    assert job.state == "queued"
    assert job.stage == "created"

    assert stat.S_IMODE(job.job_dir.stat().st_mode) == 0o700
    assert stat.S_IMODE(
        (job.job_dir / "request.json").stat().st_mode
    ) == 0o600
    assert stat.S_IMODE(
        (job.job_dir / "status.json").stat().st_mode
    ) == 0o600
    assert stat.S_IMODE(
        (job.job_dir / "ansible.log").stat().st_mode
    ) == 0o600

    assert read_json(
        job.job_dir / "request.json"
    ) == provision_request()

    status = read_json(job.job_dir / "status.json")

    assert status["job_id"] == job.job_id
    assert status["machine_uuid"] == MACHINE_UUID
    assert status["state"] == "queued"
    assert status["stage"] == "created"
    assert status["stage_history"] == [
        {
            "stage": "created",
            "entered_at": status["created_at"],
        }
    ]


def test_update_preserves_job_identity(
    tmp_path: Path,
) -> None:
    settings = make_settings(tmp_path)
    repository = JobRepository(settings)
    original = repository.create(provision_request())
    unit = f"alt-provision-{original.job_id}.service"

    updated = JobStageManager(
        settings,
        repository=repository,
    ).advance(
        original.job_id,
        "launching",
        updates={"systemd_unit": unit},
    )

    assert updated.job_id == original.job_id
    assert updated.machine_uuid == MACHINE_UUID
    assert updated.state == "queued"
    assert updated.stage == "launching"
    assert updated.status["systemd_unit"] == unit


def test_active_for_machine_accepts_only_queued_or_running(
    tmp_path: Path,
) -> None:
    settings = make_settings(tmp_path)
    repository = JobRepository(settings)
    job = repository.create(provision_request())
    manager = JobStageManager(
        settings,
        repository=repository,
    )

    active = repository.active_for_machine(MACHINE_UUID)
    assert active is not None
    assert active.state == "queued"

    manager.advance(job.job_id, "launching")
    manager.advance(
        job.job_id,
        "validating",
        updates={
            "state": "running",
            "started_at": "2026-07-18T12:00:00+00:00",
        },
    )

    active = repository.active_for_machine(MACHINE_UUID)
    assert active is not None
    assert active.state == "running"
    assert active.stage == "validating"

    repository.update(
        job.job_id,
        state="failed",
        finished_at="2026-07-18T12:01:00+00:00",
        error="test failure",
    )

    assert repository.active_for_machine(MACHINE_UUID) is None


def test_read_log_returns_bounded_tail(
    tmp_path: Path,
) -> None:
    settings = make_settings(tmp_path)
    repository = JobRepository(settings)
    job = repository.create(provision_request())

    log_path = job.job_dir / "ansible.log"
    log_path.write_bytes(
        b"A" * 25
        + b"B" * 2_000_000
    )

    result = repository.read_log(job.job_id)

    assert result["truncated"] is True
    assert len(result["log"].encode("utf-8")) == 2_000_000
    assert result["log"].startswith("B")
    assert result["log"].endswith("B")


def test_read_log_reads_archived_gzip(
    tmp_path: Path,
) -> None:
    settings = make_settings(tmp_path)
    repository = JobRepository(settings)
    job = repository.create(provision_request())

    log_path = job.job_dir / "ansible.log"
    archive_path = job.job_dir / "ansible.log.gz"
    content = "archived first line\narchived second line\n"
    with gzip.open(archive_path, "wt", encoding="utf-8") as handle:
        handle.write(content)
    log_path.unlink()

    result = repository.read_log(job.job_id)

    assert result["archived"] is True
    assert result["truncated"] is False
    assert result["log"] == content


@pytest.mark.parametrize(
    "forbidden_key",
    [
        "password",
        "employee_password_hash",
        "secret_value",
        "api_token",
        "private_key_path",
        "vault_employee_password_hash",
    ],
)
def test_assignment_rejects_secret_like_keys(
    tmp_path: Path,
    forbidden_key: str,
) -> None:
    settings = make_settings(tmp_path)
    repository = AssignmentRepository(settings)

    payload = assignment_payload()
    payload["nested"] = {
        forbidden_key: "must-not-be-saved",
    }

    with pytest.raises(ControlError) as exc:
        repository.write(MACHINE_UUID, payload)

    assert exc.value.code == "unsafe_payload"


def test_assignment_write_is_idempotent_but_rejects_conflict(
    tmp_path: Path,
) -> None:
    settings = make_settings(tmp_path)
    repository = AssignmentRepository(settings)
    payload = assignment_payload()

    repository.write(MACHINE_UUID, payload)
    repository.write(MACHINE_UUID, payload)

    assert repository.get(MACHINE_UUID) == payload

    conflicting = dict(payload)
    conflicting["employee_login"] = "p.petrov"

    with pytest.raises(ControlError) as exc:
        repository.write(MACHINE_UUID, conflicting)

    assert exc.value.code == "assignment_conflict"


def test_job_request_rejects_secret_like_keys(
    tmp_path: Path,
) -> None:
    settings = make_settings(tmp_path)
    repository = JobRepository(settings)
    request = provision_request()
    request["employee_password"] = "forbidden"

    with pytest.raises(ControlError) as exc:
        repository.create(request)

    assert exc.value.code == "unsafe_payload"


def test_machine_output_includes_assignment_and_active_job(
    tmp_path: Path,
) -> None:
    settings = make_settings(tmp_path)

    write_machine(
        settings,
        "ready",
        "2026-07-16T08:00:00+00:00",
    )

    jobs = JobRepository(settings)
    assignments = AssignmentRepository(settings)

    job = jobs.create(provision_request())
    assignment = assignment_payload(job_id=job.job_id)

    assignments.write(MACHINE_UUID, assignment)

    machine = MachineRepository(
        settings
    ).get(MACHINE_UUID).to_public_dict()

    assert machine["assignment"] == assignment
    assert machine["active_job"]["job_id"] == job.job_id
    assert machine["active_job"]["state"] == "queued"


def test_exclusive_lock_blocks_second_process(
    tmp_path: Path,
) -> None:
    settings = make_settings(tmp_path)
    context = multiprocessing.get_context("fork")
    receiver, sender = context.Pipe(duplex=False)

    with exclusive_lock(settings.lock_file):
        process = context.Process(
            target=try_nonblocking_lock,
            args=(
                str(settings.lock_file),
                sender,
            ),
        )
        process.start()

        assert receiver.poll(5)
        assert receiver.recv() == "blocked"

        process.join(5)
        assert process.exitcode == 0
