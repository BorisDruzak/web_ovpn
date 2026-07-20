from __future__ import annotations

from typing import Any

TEST_MACHINE_UUID = "53b03180-5d78-11f0-bd95-f027db877a00"
SECOND_TEST_MACHINE_UUID = "11111111-2222-3333-4444-555555555555"
TEST_REGISTERED_AT = "2026-07-16T08:00:00+00:00"
TEST_COMPLETED_AT = "2026-07-16T13:00:00+00:00"


def machine_registration_payload(
    *,
    machine_uuid: str = TEST_MACHINE_UUID,
    hostname: str = "alt-auto-test",
    ip: str = "192.0.2.56",
    mac: str = "02:00:00:00:00:56",
    status: str = "ready",
    registered_at: str = TEST_REGISTERED_AT,
    preflight_ok: bool = False,
) -> dict[str, object]:
    payload: dict[str, object] = {
        "machine_key": machine_uuid,
        "uuid": machine_uuid,
        "hostname": hostname,
        "ip": ip,
        "mac": mac,
        "registered_at": registered_at,
        "status": status,
    }
    if preflight_ok:
        payload["status"] = "awaiting_assignment"
        payload["preflight"] = {
            "status": "ok",
            "checks": {"uuid": True, "alt_release": True},
        }
    return payload


def provision_request(
    *,
    machine_uuid: str = TEST_MACHINE_UUID,
    employee_login: str = "i-ivanov",
    employee_full_name: str = "Иванов Иван Иванович",
    final_hostname: str = "buh-023",
    profile: str = "standard",
) -> dict[str, str]:
    return {
        "machine_uuid": machine_uuid,
        "employee_login": employee_login,
        "employee_full_name": employee_full_name,
        "final_hostname": final_hostname,
        "profile": profile,
    }


def assignment_payload(
    *,
    machine_uuid: str = TEST_MACHINE_UUID,
    job_id: str = "job-test",
) -> dict[str, object]:
    return {
        **provision_request(machine_uuid=machine_uuid),
        "job_id": job_id,
        "completed_at": TEST_COMPLETED_AT,
        "verification": {"hostname": True, "employee_exists": True},
    }


def successful_provision_result(
    *,
    job_id: str,
    machine_uuid: str = TEST_MACHINE_UUID,
) -> dict[str, Any]:
    return {
        **provision_request(machine_uuid=machine_uuid),
        "job_id": job_id,
        "completed_at": TEST_COMPLETED_AT,
        "verification": {
            "hostname": True,
            "employee_exists": True,
            "employee_not_wheel": True,
            "employee_no_sudo": True,
            "ansible_sudo": True,
            "lightdm_hides_ansible": True,
            "lightdm_shows_employee": True,
            "lightdm_autologin_disabled": True,
        },
    }
