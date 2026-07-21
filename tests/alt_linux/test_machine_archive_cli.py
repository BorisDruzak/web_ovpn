from __future__ import annotations

import io
import json
import os
from pathlib import Path

import pytest

import alt_deploy.cli as cli_module
from alt_deploy.assignments import AssignmentRepository
from alt_deploy.cli import main
from alt_deploy.jobs import JobRepository
from support.controller_sandbox import make_controller_sandbox
from support.lifecycle_fixtures import (
    TEST_MACHINE_UUID,
    registration_payload,
    snapshot_tree,
    write_registration,
)
from support.payloads import provision_request


def run_json_cli(
    arguments: list[str],
    settings,
) -> tuple[int, dict[str, object], str]:
    stdout = io.StringIO()
    stderr = io.StringIO()
    rc = main(
        arguments,
        settings=settings,
        stdout=stdout,
        stderr=stderr,
    )
    return rc, json.loads(stdout.getvalue()), stderr.getvalue()


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


def test_remove_preview_contract(tmp_path: Path) -> None:
    sandbox = make_controller_sandbox(tmp_path)
    write_registration(
        sandbox.settings,
        "ready",
        registration_payload(status="awaiting_assignment"),
    )

    rc, payload, stderr = run_json_cli(
        [
            "--json",
            "machines",
            "remove",
            "preview",
            TEST_MACHINE_UUID,
        ],
        sandbox.settings,
    )

    assert rc == 0
    assert stderr == ""
    assert payload == {
        "status": "ok",
        "preview": {
            "machine_uuid": TEST_MACHINE_UUID,
            "machine_key": TEST_MACHINE_UUID,
            "source_states": ["ready"],
            "record_count": 1,
            "assignment_present": False,
            "active_job": None,
            "action": "archive_registration_records",
        },
    }
    assert not sandbox.settings.machine_archives_dir.exists()


def test_remove_apply_requires_root_before_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sandbox = make_controller_sandbox(tmp_path)
    write_registration(
        sandbox.settings,
        "pending",
        registration_payload(),
    )
    before = snapshot_tree(sandbox.root)
    monkeypatch.setattr(cli_module.os, "geteuid", lambda: 1000)

    rc, payload, stderr = run_json_cli(
        [
            "--json",
            "machines",
            "remove",
            "apply",
            TEST_MACHINE_UUID,
            "--reason",
            "Переустановка",
        ],
        sandbox.settings,
    )

    assert rc == 6
    assert stderr == ""
    assert payload["error"]["code"] == "root_required"
    assert snapshot_tree(sandbox.root) == before


def test_remove_apply_success_contract(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sandbox = make_controller_sandbox(tmp_path)
    write_registration(
        sandbox.settings,
        "ready",
        registration_payload(status="awaiting_assignment"),
    )
    monkeypatch.setattr(cli_module.os, "geteuid", lambda: 0)

    rc, payload, stderr = run_json_cli(
        [
            "--json",
            "machines",
            "remove",
            "apply",
            TEST_MACHINE_UUID,
            "--reason",
            "Переустановка тестовой машины",
        ],
        sandbox.settings,
    )

    assert rc == 0
    assert stderr == ""
    archive = payload["archive"]
    assert payload["status"] == "ok"
    assert set(archive) == {
        "result",
        "archive_id",
        "machine_uuid",
        "machine_key",
        "source_states",
    }
    assert archive["result"] == "archived"
    assert archive["machine_uuid"] == TEST_MACHINE_UUID
    assert archive["machine_key"] == TEST_MACHINE_UUID
    assert archive["source_states"] == ["ready"]


def test_remove_apply_repeat_is_idempotent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sandbox = make_controller_sandbox(tmp_path)
    write_registration(
        sandbox.settings,
        "ready",
        registration_payload(status="awaiting_assignment"),
    )
    monkeypatch.setattr(cli_module.os, "geteuid", lambda: 0)
    arguments = [
        "--json",
        "machines",
        "remove",
        "apply",
        TEST_MACHINE_UUID,
        "--reason",
        "Переустановка тестовой машины",
    ]

    first_rc, first, _ = run_json_cli(arguments, sandbox.settings)
    second_rc, second, _ = run_json_cli(arguments, sandbox.settings)

    assert first_rc == 0
    assert second_rc == 0
    assert second["archive"]["result"] == "already_archived"
    assert second["archive"]["archive_id"] == (
        first["archive"]["archive_id"]
    )


def test_remove_apply_invalid_reason_has_no_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sandbox = make_controller_sandbox(tmp_path)
    write_registration(
        sandbox.settings,
        "pending",
        registration_payload(),
    )
    before = snapshot_tree(sandbox.root)
    monkeypatch.setattr(cli_module.os, "geteuid", lambda: 0)

    rc, payload, _ = run_json_cli(
        [
            "--json",
            "machines",
            "remove",
            "apply",
            TEST_MACHINE_UUID,
            "--reason",
            "bad\nreason",
        ],
        sandbox.settings,
    )

    assert rc == 4
    assert payload["error"]["code"] == "invalid_archive_reason"
    assert snapshot_tree(sandbox.root) == before


def test_remove_preview_rejects_assigned_machine(
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
    before = snapshot_tree(sandbox.root)

    rc, payload, _ = run_json_cli(
        [
            "--json",
            "machines",
            "remove",
            "preview",
            TEST_MACHINE_UUID,
        ],
        sandbox.settings,
    )

    assert rc == 4
    assert payload["error"]["code"] == "machine_assigned"
    assert snapshot_tree(sandbox.root) == before


def test_remove_preview_rejects_busy_machine_with_safe_details(
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

    rc, payload, _ = run_json_cli(
        [
            "--json",
            "machines",
            "remove",
            "preview",
            TEST_MACHINE_UUID,
        ],
        sandbox.settings,
    )

    assert rc == 4
    assert payload["error"]["code"] == "machine_busy"
    assert payload["error"]["details"] == {
        "job_id": job.job_id,
        "state": "queued",
        "stage": "created",
    }


def test_non_json_error_uses_safe_stderr(
    tmp_path: Path,
) -> None:
    sandbox = make_controller_sandbox(tmp_path)
    stdout = io.StringIO()
    stderr = io.StringIO()

    rc = main(
        [
            "machines",
            "remove",
            "preview",
            "00000000-0000-0000-0000-000000000000",
        ],
        settings=sandbox.settings,
        stdout=stdout,
        stderr=stderr,
    )

    assert rc == 3
    assert stdout.getvalue() == ""
    assert stderr.getvalue().startswith("ERROR [machine_not_found]:")
    assert str(tmp_path) not in stderr.getvalue()
