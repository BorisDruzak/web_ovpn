from __future__ import annotations

import re
import threading
from pathlib import Path

import pytest

from alt_deploy.assignments import AssignmentRepository
from alt_deploy.errors import ControlError
from alt_deploy.jobs import JobRepository
from alt_deploy.jsonio import read_json
from alt_deploy.registration_admission import (
    RegistrationAdmissionService,
    RegistrationRequest,
)
from support.controller_sandbox import make_controller_sandbox
from support.lifecycle_fixtures import (
    TEST_MACHINE_MAC,
    TEST_MACHINE_UUID,
    commit_candidate_without_cleanup,
    complete_candidate_archive,
    registration_payload,
    write_registration,
)
from support.payloads import provision_request


def request() -> RegistrationRequest:
    return RegistrationRequest(
        hostname="alt-lifecycle-test",
        mac=TEST_MACHINE_MAC,
        machine_uuid=TEST_MACHINE_UUID,
        ip="192.0.2.56",
    )


def assignment_payload() -> dict[str, object]:
    return {
        "machine_uuid": TEST_MACHINE_UUID,
        "employee_login": "test-user",
        "employee_full_name": "Тестовый Пользователь",
        "final_hostname": "alt-lifecycle-test",
        "profile": "standard",
        "job_id": "job-test",
        "completed_at": "2026-07-21T12:30:00+00:00",
        "verification": {"hostname": True},
    }


def test_new_registration_gets_controller_generation(
    tmp_path: Path,
) -> None:
    sandbox = make_controller_sandbox(tmp_path)

    decision = RegistrationAdmissionService(
        sandbox.settings
    ).admit(request())

    assert decision.http_status == 201
    assert decision.payload["status"] == "registered"
    registration_id = str(
        decision.payload["registration_id"]
    )
    assert re.fullmatch(
        r"reg-[0-9a-f]{32}",
        registration_id,
    )
    pending = read_json(
        sandbox.settings.registration_root
        / "pending"
        / f"{TEST_MACHINE_UUID}.json"
    )
    assert pending["registration_id"] == registration_id
    assert pending["status"] == "pending"
    assert pending["ip"] == "192.0.2.56"


def test_active_registration_is_not_overwritten(
    tmp_path: Path,
) -> None:
    sandbox = make_controller_sandbox(tmp_path)
    service = RegistrationAdmissionService(sandbox.settings)
    first = service.admit(request())
    path = (
        sandbox.settings.registration_root
        / "pending"
        / f"{TEST_MACHINE_UUID}.json"
    )
    before = path.read_bytes()

    second = service.admit(request())

    assert first.http_status == 201
    assert second.http_status == 200
    assert second.payload == {
        "status": "already_registered",
        "machine_key": TEST_MACHINE_UUID,
        "registration_id": first.payload["registration_id"],
        "registration_state": "pending",
    }
    assert path.read_bytes() == before


def test_legacy_active_registration_is_idempotent(
    tmp_path: Path,
) -> None:
    sandbox = make_controller_sandbox(tmp_path)
    path = write_registration(
        sandbox.settings,
        "ready",
        registration_payload(
            registration_id=None,
            status="awaiting_assignment",
        ),
    )
    before = path.read_bytes()

    decision = RegistrationAdmissionService(
        sandbox.settings
    ).admit(request())

    assert decision.http_status == 200
    assert decision.payload == {
        "status": "already_registered",
        "machine_key": TEST_MACHINE_UUID,
        "registration_state": "ready",
        "legacy": True,
    }
    assert path.read_bytes() == before


def test_assigned_machine_is_rejected(
    tmp_path: Path,
) -> None:
    sandbox = make_controller_sandbox(tmp_path)
    write_registration(
        sandbox.settings,
        "ready",
        registration_payload(status="awaiting_assignment"),
    )
    AssignmentRepository(sandbox.settings).write(
        TEST_MACHINE_UUID,
        assignment_payload(),
    )

    with pytest.raises(ControlError) as exc:
        RegistrationAdmissionService(
            sandbox.settings
        ).admit(request())

    assert exc.value.code == "machine_assigned"
    assert not (
        sandbox.settings.registration_root
        / "pending"
        / f"{TEST_MACHINE_UUID}.json"
    ).exists()


def test_busy_machine_is_rejected_with_safe_details(
    tmp_path: Path,
) -> None:
    sandbox = make_controller_sandbox(tmp_path)
    write_registration(
        sandbox.settings,
        "ready",
        registration_payload(status="awaiting_assignment"),
    )
    job = JobRepository(sandbox.settings).create(
        provision_request()
    )

    with pytest.raises(ControlError) as exc:
        RegistrationAdmissionService(
            sandbox.settings
        ).admit(request())

    assert exc.value.code == "machine_busy"
    assert exc.value.details == {
        "job_id": job.job_id,
        "state": "queued",
        "stage": "created",
    }


def test_committed_cleanup_is_rejected(
    tmp_path: Path,
) -> None:
    sandbox = make_controller_sandbox(tmp_path)
    source = write_registration(
        sandbox.settings,
        "pending",
        registration_payload(),
    )
    committed = commit_candidate_without_cleanup(
        sandbox.settings,
        source,
        "pending",
    )

    with pytest.raises(ControlError) as exc:
        RegistrationAdmissionService(
            sandbox.settings
        ).admit(request())

    assert exc.value.code == "machine_archive_cleanup_required"
    assert exc.value.details == {
        "archive_id": committed.archive_id
    }


def test_completed_archive_accepts_new_generation(
    tmp_path: Path,
) -> None:
    sandbox = make_controller_sandbox(tmp_path)
    source = write_registration(
        sandbox.settings,
        "ready",
        registration_payload(status="awaiting_assignment"),
    )
    completed = complete_candidate_archive(
        sandbox.settings,
        source,
        "ready",
    )

    decision = RegistrationAdmissionService(
        sandbox.settings
    ).admit(request())

    assert decision.http_status == 201
    assert decision.payload["status"] == "registered"
    assert decision.payload["registration_id"] not in {
        plan.generation for plan in completed.record_plans
    }


def test_conflicting_active_identity_is_rejected(
    tmp_path: Path,
) -> None:
    sandbox = make_controller_sandbox(tmp_path)
    write_registration(
        sandbox.settings,
        "ready",
        registration_payload(
            mac="00:11:22:33:44:55",
            status="awaiting_assignment",
        ),
    )

    with pytest.raises(ControlError) as exc:
        RegistrationAdmissionService(
            sandbox.settings
        ).admit(request())

    assert exc.value.code == "machine_identity_conflict"


def test_concurrent_admission_creates_one_generation(
    tmp_path: Path,
) -> None:
    sandbox = make_controller_sandbox(tmp_path)
    results: list[tuple[int, dict[str, object]]] = []
    failures: list[BaseException] = []
    barrier = threading.Barrier(2)

    def run() -> None:
        try:
            barrier.wait()
            decision = RegistrationAdmissionService(
                sandbox.settings
            ).admit(request())
            results.append(
                (decision.http_status, decision.payload)
            )
        except BaseException as exc:
            failures.append(exc)

    threads = [threading.Thread(target=run) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=10)

    assert failures == []
    assert sorted(status for status, _ in results) == [200, 201]
    registration_ids = {
        str(payload["registration_id"])
        for _, payload in results
    }
    assert len(registration_ids) == 1
    assert len(list(
        (sandbox.settings.registration_root / "pending").glob("*.json")
    )) == 1
