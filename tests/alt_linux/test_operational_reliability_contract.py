from __future__ import annotations

from support.payloads import (
    SECOND_TEST_MACHINE_UUID,
    TEST_MACHINE_UUID,
    assignment_payload,
    machine_registration_payload,
    provision_request,
    successful_provision_result,
)


def test_payload_factories_return_independent_mappings() -> None:
    first = provision_request()
    second = provision_request()

    assert first == second
    assert first is not second
    first["employee_login"] = "changed"
    assert second["employee_login"] == "i-ivanov"


def test_payload_factories_use_test_identifiers() -> None:
    assert machine_registration_payload()["uuid"] == TEST_MACHINE_UUID
    assert provision_request()["machine_uuid"] == TEST_MACHINE_UUID
    assert assignment_payload(job_id="job-test")["machine_uuid"] == (
        TEST_MACHINE_UUID
    )
    assert successful_provision_result(
        job_id="job-test"
    )["machine_uuid"] == TEST_MACHINE_UUID
    assert SECOND_TEST_MACHINE_UUID != TEST_MACHINE_UUID


def test_successful_result_has_complete_verification_contract() -> None:
    result = successful_provision_result(job_id="job-test")

    assert result["verification"] == {
        "hostname": True,
        "employee_exists": True,
        "employee_not_wheel": True,
        "employee_no_sudo": True,
        "ansible_sudo": True,
        "lightdm_hides_ansible": True,
        "lightdm_shows_employee": True,
        "lightdm_autologin_disabled": True,
    }
