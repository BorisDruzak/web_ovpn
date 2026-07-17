from __future__ import annotations

import io
import json
from pathlib import Path

import pytest

from alt_deploy.assignments import AssignmentRepository
from alt_deploy.cli import main
from alt_deploy.errors import ControlError
from alt_deploy.jobs import JobRepository
from alt_deploy.jsonio import atomic_write_json
from alt_deploy.provision import ProvisionPlanner, ProvisionRequest

from test_registry_cli import (
    MACHINE_UUID,
    make_settings,
)


SECOND_UUID = "11111111-2222-3333-4444-555555555555"

EXPECTED_ACTIONS = [
    "validate_registered_machine",
    "run_preflight",
    "set_final_hostname",
    "create_or_reconcile_local_employee",
    "remove_employee_admin_rights",
    "hide_ansible_from_sddm",
    "disable_sddm_autologin",
    "verify_provisioning",
    "write_assignment_records",
]


def valid_request(
    *,
    machine_uuid: str = MACHINE_UUID,
    employee_login: str = "i.ivanov",
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


def prepare_preview_environment(tmp_path: Path):
    settings = make_settings(tmp_path)

    ready_path = (
        settings.registration_root
        / "ready"
        / f"{MACHINE_UUID}.json"
    )

    atomic_write_json(
        ready_path,
        {
            "machine_key": MACHINE_UUID,
            "uuid": MACHINE_UUID,
            "hostname": "alt-auto-test",
            "ip": "192.168.101.56",
            "mac": "c0:9b:f4:62:54:e5",
            "registered_at": "2026-07-16T08:00:00+00:00",
            "status": "awaiting_assignment",
            "preflight": {
                "status": "ok",
                "checks": {
                    "uuid": True,
                    "alt_release": True,
                },
            },
        },
    )

    vault_file = (
        settings.ansible_project_dir
        / "group_vars"
        / "vault.yml"
    )
    vault_file.parent.mkdir(parents=True)
    vault_file.write_text(
        "$ANSIBLE_VAULT;1.1;AES256\nfixture\n",
        encoding="utf-8",
    )

    vault_password_file = (
        settings.ansible_project_dir.parent
        / ".ansible-vault-pass"
    )
    vault_password_file.write_text(
        "test-vault-password\n",
        encoding="utf-8",
    )

    return settings


@pytest.mark.parametrize(
    ("changes", "expected_code"),
    [
        (
            {"employee_login": "Root"},
            "invalid_employee_login",
        ),
        (
            {"employee_login": "ansible"},
            "protected_employee_login",
        ),
        (
            {"employee_login": "ivanov@local"},
            "invalid_employee_login",
        ),
        (
            {"employee_full_name": ""},
            "invalid_employee_full_name",
        ),
        (
            {"final_hostname": "-buh-01"},
            "invalid_hostname",
        ),
        (
            {"final_hostname": "buh_01"},
            "invalid_hostname",
        ),
        (
            {"profile": "crypto"},
            "invalid_profile",
        ),
    ],
)
def test_request_validation_errors(
    changes: dict[str, str],
    expected_code: str,
) -> None:
    payload = valid_request()
    payload.update(changes)

    with pytest.raises(ControlError) as exc:
        ProvisionRequest.from_mapping(
            payload,
            expected_uuid=MACHINE_UUID,
        )

    assert exc.value.code == expected_code


def test_request_rejects_unknown_fields() -> None:
    payload = valid_request()
    payload["employee_password"] = "must-not-be-accepted"

    with pytest.raises(ControlError) as exc:
        ProvisionRequest.from_mapping(
            payload,
            expected_uuid=MACHINE_UUID,
        )

    assert exc.value.code == "unknown_request_fields"


def test_request_rejects_machine_uuid_mismatch() -> None:
    with pytest.raises(ControlError) as exc:
        ProvisionRequest.from_mapping(
            valid_request(machine_uuid=SECOND_UUID),
            expected_uuid=MACHINE_UUID,
        )

    assert exc.value.code == "machine_uuid_mismatch"


def test_preview_returns_deterministic_non_secret_plan(
    tmp_path: Path,
) -> None:
    settings = prepare_preview_environment(tmp_path)

    request = ProvisionRequest.from_mapping(
        valid_request(),
        expected_uuid=MACHINE_UUID,
    )

    result = ProvisionPlanner(settings).preview(
        MACHINE_UUID,
        request,
    )

    assert result["status"] == "ok"
    assert result["machine_uuid"] == MACHINE_UUID
    assert result["request"] == valid_request()
    assert result["actions"] == EXPECTED_ACTIONS
    assert result["secrets_required"] == [
        "vault_employee_password_hash"
    ]

    serialized_request = json.dumps(
        result["request"],
        ensure_ascii=False,
    ).lower()

    assert "employee_password" not in serialized_request
    assert "password_hash" not in serialized_request


def test_preview_rejects_existing_assignment(
    tmp_path: Path,
) -> None:
    settings = prepare_preview_environment(tmp_path)

    AssignmentRepository(settings).write(
        MACHINE_UUID,
        {
            **valid_request(),
            "job_id": "job-existing",
            "completed_at": "2026-07-16T12:00:00+00:00",
            "verification": {
                "hostname": True,
            },
        },
    )

    request = ProvisionRequest.from_mapping(
        valid_request(),
        expected_uuid=MACHINE_UUID,
    )

    with pytest.raises(ControlError) as exc:
        ProvisionPlanner(settings).preview(
            MACHINE_UUID,
            request,
        )

    assert exc.value.code == "machine_already_assigned"


def test_preview_rejects_active_job(
    tmp_path: Path,
) -> None:
    settings = prepare_preview_environment(tmp_path)

    JobRepository(settings).create(valid_request())

    request = ProvisionRequest.from_mapping(
        valid_request(),
        expected_uuid=MACHINE_UUID,
    )

    with pytest.raises(ControlError) as exc:
        ProvisionPlanner(settings).preview(
            MACHINE_UUID,
            request,
        )

    assert exc.value.code == "machine_job_active"


@pytest.mark.parametrize(
    ("assignment_field", "expected_code"),
    [
        (
            "final_hostname",
            "hostname_already_assigned",
        ),
        (
            "employee_login",
            "employee_login_already_assigned",
        ),
    ],
)
def test_preview_rejects_duplicate_assignment_values(
    tmp_path: Path,
    assignment_field: str,
    expected_code: str,
) -> None:
    settings = prepare_preview_environment(tmp_path)

    existing = {
        **valid_request(machine_uuid=SECOND_UUID),
        "employee_login": "p.petrov",
        "final_hostname": "kadry-01",
        "job_id": "job-other",
        "completed_at": "2026-07-16T12:00:00+00:00",
        "verification": {
            "hostname": True,
        },
    }

    existing[assignment_field] = valid_request()[
        assignment_field
    ]

    AssignmentRepository(settings).write(
        SECOND_UUID,
        existing,
    )

    request = ProvisionRequest.from_mapping(
        valid_request(),
        expected_uuid=MACHINE_UUID,
    )

    with pytest.raises(ControlError) as exc:
        ProvisionPlanner(settings).preview(
            MACHINE_UUID,
            request,
        )

    assert exc.value.code == expected_code


def test_preview_requires_vault_files(
    tmp_path: Path,
) -> None:
    settings = prepare_preview_environment(tmp_path)

    (
        settings.ansible_project_dir
        / "group_vars"
        / "vault.yml"
    ).unlink()

    request = ProvisionRequest.from_mapping(
        valid_request(),
        expected_uuid=MACHINE_UUID,
    )

    with pytest.raises(ControlError) as exc:
        ProvisionPlanner(settings).preview(
            MACHINE_UUID,
            request,
        )

    assert exc.value.code == "vault_not_configured"


def test_provision_preview_cli(
    tmp_path: Path,
) -> None:
    settings = prepare_preview_environment(tmp_path)

    request_path = tmp_path / "request.json"
    request_path.write_text(
        json.dumps(valid_request()),
        encoding="utf-8",
    )

    stdout = io.StringIO()

    rc = main(
        [
            "--json",
            "provision",
            "preview",
            MACHINE_UUID,
            "--vars-file",
            str(request_path),
        ],
        settings=settings,
        stdout=stdout,
        stderr=io.StringIO(),
    )

    assert rc == 0

    payload = json.loads(stdout.getvalue())

    assert payload["status"] == "ok"
    assert payload["actions"] == EXPECTED_ACTIONS


def test_preview_rejects_plaintext_vault_file(
    tmp_path: Path,
) -> None:
    settings = prepare_preview_environment(tmp_path)

    vault_file = (
        settings.ansible_project_dir
        / "group_vars"
        / "vault.yml"
    )
    vault_file.write_text(
        "vault_employee_password_hash: plaintext-fixture\n",
        encoding="utf-8",
    )

    request = ProvisionRequest.from_mapping(
        valid_request(),
        expected_uuid=MACHINE_UUID,
    )

    with pytest.raises(ControlError) as exc:
        ProvisionPlanner(settings).preview(
            MACHINE_UUID,
            request,
        )

    assert exc.value.code == "vault_not_configured"
