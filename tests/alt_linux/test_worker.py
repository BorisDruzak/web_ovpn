from __future__ import annotations

import subprocess
from dataclasses import replace
from pathlib import Path
from typing import Any, TextIO

from alt_deploy.ansible import AnsibleController
from alt_deploy.assignments import AssignmentRepository
from alt_deploy.errors import ControlError
from alt_deploy.jobs import JobRepository
from alt_deploy.jsonio import atomic_write_json, read_json
from alt_deploy.worker import run_job

from test_provision_preview import (
    prepare_preview_environment,
    valid_request,
)
from test_registry_cli import MACHINE_UUID


FORBIDDEN_KEY_PARTS = (
    "password",
    "secret",
    "token",
    "private_key",
    "vault",
)


def successful_result(job_id: str) -> dict[str, Any]:
    return {
        "machine_uuid": MACHINE_UUID,
        "final_hostname": "buh-023",
        "employee_login": "i.ivanov",
        "employee_full_name": "Иванов Иван Иванович",
        "profile": "standard",
        "job_id": job_id,
        "completed_at": "2026-07-16T13:00:00+00:00",
        "verification": {
            "hostname": True,
            "employee_exists": True,
            "employee_not_wheel": True,
            "employee_no_sudo": True,
            "ansible_sudo": True,
            "sddm_hides_ansible": True,
            "sddm_autologin_disabled": True,
        },
    }


def assert_no_secret_keys(
    value: object,
    path: str = "",
) -> None:
    if isinstance(value, dict):
        for key, nested_value in value.items():
            key_text = str(key).lower()
            current_path = (
                f"{path}.{key}" if path else str(key)
            )

            assert not any(
                forbidden in key_text
                for forbidden in FORBIDDEN_KEY_PARTS
            ), current_path

            assert_no_secret_keys(
                nested_value,
                current_path,
            )

    elif isinstance(value, list):
        for index, nested_value in enumerate(value):
            assert_no_secret_keys(
                nested_value,
                f"{path}[{index}]",
            )


class SuccessfulController:
    def __init__(self) -> None:
        self.received_job_id = ""

    def run_provision(
        self,
        job,
        log_stream: TextIO,
    ) -> dict[str, Any]:
        self.received_job_id = job.job_id

        log_stream.write(
            "TASK [local_employee : Create employee]\n"
        )
        log_stream.write("changed: [192.168.101.56]\n")
        log_stream.flush()

        return successful_result(job.job_id)


class FailingController:
    def run_provision(
        self,
        job,
        log_stream: TextIO,
    ) -> dict[str, Any]:
        log_stream.write("TASK [failed task]\n")
        log_stream.flush()

        raise RuntimeError("X" * 12000)


def test_ansible_run_provision_uses_safe_command(
    tmp_path: Path,
    monkeypatch,
) -> None:
    settings = prepare_preview_environment(tmp_path)

    fake_ansible = tmp_path / "ansible-playbook"
    fake_ansible.write_text(
        "#!/bin/sh\n",
        encoding="utf-8",
    )
    fake_ansible.chmod(0o755)

    settings = replace(
        settings,
        ansible_playbook_path=fake_ansible,
    )

    settings.private_key_file.write_text(
        "private fixture",
        encoding="utf-8",
    )
    settings.known_hosts_file.write_text(
        "host key fixture",
        encoding="utf-8",
    )

    playbook = (
        settings.ansible_project_dir
        / "playbooks"
        / "02-provision-account.yml"
    )
    playbook.parent.mkdir(parents=True, exist_ok=True)
    playbook.write_text("---\n", encoding="utf-8")

    job = JobRepository(settings).create(
        valid_request()
    )

    expected_result = successful_result(job.job_id)
    captured: dict[str, object] = {}

    def fake_run(
        command: list[str],
        *,
        shell: bool,
        text: bool,
        stdout: TextIO,
        stderr: int,
        timeout: int,
        check: bool,
    ) -> subprocess.CompletedProcess[str]:
        captured.update(
            {
                "command": command,
                "shell": shell,
                "text": text,
                "stderr": stderr,
                "timeout": timeout,
                "check": check,
            }
        )

        result_argument = next(
            value
            for value in command
            if value.startswith(
                "provision_result_file="
            )
        )
        result_path = Path(
            result_argument.split("=", 1)[1]
        )

        atomic_write_json(
            result_path,
            expected_result,
        )

        stdout.write("PLAY RECAP\n")
        stdout.flush()

        return subprocess.CompletedProcess(
            command,
            0,
        )

    monkeypatch.setattr(
        "alt_deploy.ansible.subprocess.run",
        fake_run,
    )

    log_path = job.job_dir / "ansible.log"

    with log_path.open(
        "a",
        encoding="utf-8",
    ) as log_stream:
        result = AnsibleController(
            settings
        ).run_provision(
            job,
            log_stream,
        )

    command = captured["command"]

    assert isinstance(command, list)
    assert command[0] == str(fake_ansible)
    assert "192.168.101.56," in command
    assert (
        f"--private-key={settings.private_key_file}"
        in command
    )
    assert any(
        "StrictHostKeyChecking=yes" in value
        for value in command
    )
    assert (
        f"@{job.job_dir / 'request.json'}"
        in command
    )
    assert f"job_id={job.job_id}" in command
    assert command[-1] == str(playbook)

    assert captured["shell"] is False
    assert captured["stderr"] is subprocess.STDOUT
    assert captured["timeout"] == 1800
    assert captured["check"] is False
    assert result == expected_result


def test_worker_success_finalizes_assignment(
    tmp_path: Path,
) -> None:
    settings = prepare_preview_environment(tmp_path)
    jobs = JobRepository(settings)
    assignments = AssignmentRepository(settings)

    job = jobs.create(valid_request())
    controller = SuccessfulController()

    result_code = run_job(
        job.job_id,
        settings,
        controller,
    )

    assert result_code == 0
    assert controller.received_job_id == job.job_id

    stored_job = jobs.get(job.job_id)

    assert stored_job.state == "successful"
    assert stored_job.stage == "complete"
    assert stored_job.status["started_at"]
    assert stored_job.status["finished_at"]

    result = read_json(
        job.job_dir / "result.json"
    )
    assignment = assignments.get(MACHINE_UUID)

    assert result == successful_result(job.job_id)
    assert assignment == result

    log = (
        job.job_dir / "ansible.log"
    ).read_text(encoding="utf-8")

    assert job.job_id in log
    assert MACHINE_UUID in log
    assert "i.ivanov" in log
    assert "buh-023" in log
    assert "TASK [local_employee" in log

    assert_no_secret_keys(
        read_json(job.job_dir / "request.json")
    )
    assert_no_secret_keys(
        read_json(job.job_dir / "status.json")
    )
    assert_no_secret_keys(result)
    assert_no_secret_keys(assignment)


def test_worker_failure_preserves_log_without_assignment(
    tmp_path: Path,
) -> None:
    settings = prepare_preview_environment(tmp_path)
    jobs = JobRepository(settings)
    assignments = AssignmentRepository(settings)

    job = jobs.create(valid_request())

    result_code = run_job(
        job.job_id,
        settings,
        FailingController(),
    )

    assert result_code == 1

    stored_job = jobs.get(job.job_id)

    assert stored_job.state == "failed"
    assert stored_job.stage == "ansible"
    assert stored_job.status["finished_at"]
    assert len(stored_job.status["error"]) <= 10000

    assert assignments.get(MACHINE_UUID) is None
    assert not (
        job.job_dir / "result.json"
    ).exists()

    log = (
        job.job_dir / "ansible.log"
    ).read_text(encoding="utf-8")

    assert "TASK [failed task]" in log
    assert "Provision failed" in log


class FailedVerificationController:
    def run_provision(
        self,
        job,
        log_stream: TextIO,
    ) -> dict[str, Any]:
        result = successful_result(job.job_id)
        result["verification"]["hostname"] = False

        log_stream.write(
            "Provision returned failed verification\n"
        )
        log_stream.flush()

        return result


def test_worker_rejects_failed_verification(
    tmp_path: Path,
) -> None:
    settings = prepare_preview_environment(tmp_path)
    jobs = JobRepository(settings)
    assignments = AssignmentRepository(settings)

    job = jobs.create(valid_request())

    result_code = run_job(
        job.job_id,
        settings,
        FailedVerificationController(),
    )

    assert result_code == 1

    stored_job = jobs.get(job.job_id)

    assert stored_job.state == "failed"
    assert stored_job.stage == "ansible"
    assert "invalid_provision_result" in (
        stored_job.status["error"].lower()
    )

    assert assignments.get(MACHINE_UUID) is None
    assert not (job.job_dir / "result.json").exists()
