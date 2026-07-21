from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType

import pytest

from alt_deploy.assignments import AssignmentRepository
from alt_deploy.errors import ControlError
from alt_deploy.jobs import JobRepository
from support.controller_sandbox import make_controller_sandbox
from support.lifecycle_fixtures import (
    TEST_MACHINE_MAC,
    TEST_MACHINE_UUID,
    commit_candidate_without_cleanup,
    registration_payload,
    write_registration,
)
from support.payloads import provision_request

REGISTER_API_PATH = (
    Path(__file__).resolve().parents[2]
    / "deploy"
    / "alt-linux"
    / "api"
    / "register_api.py"
)


def load_register_api() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "register_api_under_test",
        REGISTER_API_PATH,
    )
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def valid_payload() -> dict[str, str]:
    return {
        "hostname": "alt-lifecycle-test",
        "mac": TEST_MACHINE_MAC,
        "uuid": TEST_MACHINE_UUID,
    }


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


def test_handle_registration_returns_created(
    tmp_path: Path,
) -> None:
    module = load_register_api()
    sandbox = make_controller_sandbox(tmp_path)

    status, payload = module.handle_registration(
        valid_payload(),
        "192.168.101.56",
        sandbox.settings,
    )

    assert status == 201
    assert payload["status"] == "registered"
    assert payload["machine_key"] == TEST_MACHINE_UUID
    assert payload["registration_id"].startswith("reg-")


def test_handle_registration_returns_already_registered(
    tmp_path: Path,
) -> None:
    module = load_register_api()
    sandbox = make_controller_sandbox(tmp_path)

    first_status, first = module.handle_registration(
        valid_payload(),
        "192.168.101.56",
        sandbox.settings,
    )
    second_status, second = module.handle_registration(
        valid_payload(),
        "192.168.101.56",
        sandbox.settings,
    )

    assert first_status == 201
    assert second_status == 200
    assert second["status"] == "already_registered"
    assert second["registration_id"] == first["registration_id"]


def test_handle_registration_maps_assigned_to_conflict(
    tmp_path: Path,
) -> None:
    module = load_register_api()
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

    status, payload = module.handle_registration(
        valid_payload(),
        "192.168.101.56",
        sandbox.settings,
    )

    assert status == 409
    assert payload["error"]["code"] == "machine_assigned"


def test_handle_registration_maps_busy_with_safe_details(
    tmp_path: Path,
) -> None:
    module = load_register_api()
    sandbox = make_controller_sandbox(tmp_path)
    write_registration(
        sandbox.settings,
        "ready",
        registration_payload(status="awaiting_assignment"),
    )
    job = JobRepository(sandbox.settings).create(
        provision_request()
    )

    status, payload = module.handle_registration(
        valid_payload(),
        "192.168.101.56",
        sandbox.settings,
    )

    assert status == 409
    assert payload["error"]["code"] == "machine_busy"
    assert payload["error"]["details"] == {
        "job_id": job.job_id,
        "state": "queued",
        "stage": "created",
    }


def test_handle_registration_maps_cleanup_required(
    tmp_path: Path,
) -> None:
    module = load_register_api()
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

    status, payload = module.handle_registration(
        valid_payload(),
        "192.168.101.56",
        sandbox.settings,
    )

    assert status == 409
    assert payload["error"]["code"] == (
        "machine_archive_cleanup_required"
    )
    assert payload["error"]["details"] == {
        "archive_id": committed.archive_id
    }


@pytest.mark.parametrize(
    ("field", "value", "expected_status"),
    [
        ("hostname", "bad host", "invalid_hostname"),
        ("mac", "not-a-mac", "invalid_mac"),
        ("uuid", "bad uuid", "invalid_uuid"),
    ],
)
def test_handle_registration_preserves_field_validation(
    tmp_path: Path,
    field: str,
    value: str,
    expected_status: str,
) -> None:
    module = load_register_api()
    sandbox = make_controller_sandbox(tmp_path)
    payload = valid_payload()
    payload[field] = value

    status, response = module.handle_registration(
        payload,
        "192.168.101.56",
        sandbox.settings,
    )

    assert status == 400
    assert response == {"status": expected_status}


def test_handle_registration_rejects_non_object(
    tmp_path: Path,
) -> None:
    module = load_register_api()
    sandbox = make_controller_sandbox(tmp_path)

    status, payload = module.handle_registration(
        [],
        "192.168.101.56",
        sandbox.settings,
    )

    assert status == 400
    assert payload == {"status": "invalid_json_object"}


def test_unexpected_storage_error_is_safe(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = load_register_api()
    sandbox = make_controller_sandbox(tmp_path)

    def fail(self, request):
        raise ControlError(
            code="registration_storage_failed",
            message="Registration storage operation failed",
            exit_code=6,
        )

    monkeypatch.setattr(
        module.RegistrationAdmissionService,
        "admit",
        fail,
    )

    status, payload = module.handle_registration(
        valid_payload(),
        "192.168.101.56",
        sandbox.settings,
    )

    assert status == 500
    assert payload["error"]["code"] == (
        "registration_storage_failed"
    )
    assert str(tmp_path) not in str(payload)


def test_client_network_policy_is_preserved() -> None:
    module = load_register_api()
    allowed = module.RegisterHandler.__new__(
        module.RegisterHandler
    )
    allowed.client_address = ("192.168.101.56", 12345)
    forbidden = module.RegisterHandler.__new__(
        module.RegisterHandler
    )
    forbidden.client_address = ("203.0.113.10", 12345)

    assert allowed.client_is_allowed() is True
    assert forbidden.client_is_allowed() is False
