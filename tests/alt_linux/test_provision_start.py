from __future__ import annotations

import io
import json
import subprocess
from dataclasses import replace
from pathlib import Path

import pytest

from alt_deploy.cli import main
from alt_deploy.errors import ControlError
from alt_deploy.jobs import JobRepository
from alt_deploy.launcher import SystemdLauncher
from alt_deploy.provision import ProvisionPlanner, ProvisionRequest

from test_provision_preview import (
    prepare_preview_environment,
    valid_request,
)
from test_registry_cli import MACHINE_UUID


class RecordingLauncher:
    def __init__(self) -> None:
        self.job_ids: list[str] = []

    def launch(self, job_id: str) -> str:
        self.job_ids.append(job_id)
        return f"alt-provision-{job_id}.service"


class FailingLauncher:
    def launch(self, job_id: str) -> str:
        raise ControlError(
            code="job_launch_failed",
            message=(
                "Unable to launch transient provision service"
            ),
            exit_code=6,
            details={"stderr": "systemd-run failed"},
        )


def parsed_request() -> ProvisionRequest:
    return ProvisionRequest.from_mapping(
        valid_request(),
        expected_uuid=MACHINE_UUID,
    )


def test_systemd_launcher_uses_safe_argument_list(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = prepare_preview_environment(tmp_path)

    settings = replace(
        settings,
        systemd_run_path=Path("/usr/bin/systemd-run"),
        worker_path=Path(
            "/usr/local/libexec/alt-provision-worker"
        ),
        ansible_project_dir=Path(
            "/home/altserver/ansible"
        ),
    )

    captured: dict[str, object] = {}

    def fake_run(
        command: list[str],
        *,
        shell: bool,
        text: bool,
        capture_output: bool,
        timeout: int,
        check: bool,
    ) -> subprocess.CompletedProcess[str]:
        captured.update(
            {
                "command": command,
                "shell": shell,
                "text": text,
                "capture_output": capture_output,
                "timeout": timeout,
                "check": check,
            }
        )

        return subprocess.CompletedProcess(
            command,
            0,
            "Running as unit\n",
            "",
        )

    monkeypatch.setattr(
        "alt_deploy.launcher.subprocess.run",
        fake_run,
    )

    job_id = "job-20260716T121530Z-a1b2c3d4"

    unit = SystemdLauncher(settings).launch(job_id)

    assert unit == (
        "alt-provision-"
        "job-20260716T121530Z-a1b2c3d4.service"
    )

    assert captured["command"] == [
        "/usr/bin/systemd-run",
        (
            "--unit=alt-provision-"
            "job-20260716T121530Z-a1b2c3d4"
        ),
        (
            "--description=ALT workstation provision "
            "job-20260716T121530Z-a1b2c3d4"
        ),
        "--uid=altserver",
        "--gid=altserver",
        "--working-directory=/home/altserver/ansible",
        "--property=Type=exec",
        "--property=NoNewPrivileges=yes",
        "--property=PrivateTmp=yes",
        "--collect",
        "/usr/local/libexec/alt-provision-worker",
        "--job-id",
        job_id,
    ]

    assert captured["shell"] is False
    assert captured["check"] is False
    assert captured["timeout"] == 30


def test_provision_start_creates_and_launches_job(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = prepare_preview_environment(tmp_path)
    launcher = RecordingLauncher()

    monkeypatch.setattr(
        "alt_deploy.provision.os.geteuid",
        lambda: 0,
    )

    planner = ProvisionPlanner(
        settings,
        launcher=launcher,
    )

    job = planner.start(
        MACHINE_UUID,
        parsed_request(),
    )

    assert job.state == "queued"
    assert job.stage == "created"
    assert launcher.job_ids == [job.job_id]

    stored = JobRepository(settings).get(job.job_id)

    assert stored.status["systemd_unit"] == (
        f"alt-provision-{job.job_id}.service"
    )


def test_provision_start_requires_root(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = prepare_preview_environment(tmp_path)

    monkeypatch.setattr(
        "alt_deploy.provision.os.geteuid",
        lambda: 1000,
    )

    planner = ProvisionPlanner(
        settings,
        launcher=RecordingLauncher(),
    )

    with pytest.raises(ControlError) as exc:
        planner.start(
            MACHINE_UUID,
            parsed_request(),
        )

    assert exc.value.code == "root_required"
    assert JobRepository(settings).list() == []


def test_launch_failure_is_persisted(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = prepare_preview_environment(tmp_path)

    monkeypatch.setattr(
        "alt_deploy.provision.os.geteuid",
        lambda: 0,
    )

    planner = ProvisionPlanner(
        settings,
        launcher=FailingLauncher(),
    )

    with pytest.raises(ControlError) as exc:
        planner.start(
            MACHINE_UUID,
            parsed_request(),
        )

    assert exc.value.code == "job_launch_failed"

    jobs = JobRepository(settings).list()

    assert len(jobs) == 1
    assert jobs[0].state == "failed"
    assert jobs[0].stage == "launch"
    assert jobs[0].status["finished_at"]
    assert "systemd-run failed" in jobs[0].status["error"]


def test_second_active_job_is_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = prepare_preview_environment(tmp_path)

    monkeypatch.setattr(
        "alt_deploy.provision.os.geteuid",
        lambda: 0,
    )

    planner = ProvisionPlanner(
        settings,
        launcher=RecordingLauncher(),
    )

    planner.start(
        MACHINE_UUID,
        parsed_request(),
    )

    with pytest.raises(ControlError) as exc:
        planner.start(
            MACHINE_UUID,
            parsed_request(),
        )

    assert exc.value.code == "machine_job_active"
    assert len(JobRepository(settings).list()) == 1


def test_provision_start_cli_returns_queued_job(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = prepare_preview_environment(tmp_path)
    request_path = tmp_path / "request.json"

    request_path.write_text(
        json.dumps(valid_request()),
        encoding="utf-8",
    )

    job = JobRepository(settings).create(
        valid_request()
    )
    job = JobRepository(settings).update(
        job.job_id,
        systemd_unit=(
            f"alt-provision-{job.job_id}.service"
        ),
    )

    monkeypatch.setattr(
        "alt_deploy.cli.ProvisionPlanner.start",
        lambda self, machine_uuid, request: job,
    )

    stdout = io.StringIO()

    rc = main(
        [
            "--json",
            "provision",
            "start",
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
    assert payload["job"]["job_id"] == job.job_id
    assert payload["job"]["state"] == "queued"


def test_jobs_status_and_log_cli(
    tmp_path: Path,
) -> None:
    settings = prepare_preview_environment(tmp_path)
    repository = JobRepository(settings)

    job = repository.create(valid_request())

    (job.job_dir / "ansible.log").write_text(
        "TASK [preflight]\nok\n",
        encoding="utf-8",
    )

    status_stdout = io.StringIO()

    status_rc = main(
        [
            "--json",
            "jobs",
            "status",
            job.job_id,
        ],
        settings=settings,
        stdout=status_stdout,
        stderr=io.StringIO(),
    )

    assert status_rc == 0

    status_payload = json.loads(
        status_stdout.getvalue()
    )

    assert status_payload["status"] == "ok"
    assert status_payload["job"]["job_id"] == job.job_id
    assert status_payload["job"]["state"] == "queued"

    log_stdout = io.StringIO()

    log_rc = main(
        [
            "--json",
            "jobs",
            "log",
            job.job_id,
        ],
        settings=settings,
        stdout=log_stdout,
        stderr=io.StringIO(),
    )

    assert log_rc == 0

    log_payload = json.loads(log_stdout.getvalue())

    assert log_payload["status"] == "ok"
    assert log_payload["job_id"] == job.job_id
    assert log_payload["state"] == "queued"
    assert "TASK [preflight]" in log_payload["log"]
    assert log_payload["truncated"] is False


def test_start_prepares_altserver_owned_job_before_launch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import types

    import alt_deploy.provision as provision_module

    settings = prepare_preview_environment(tmp_path)
    ownership_calls: list[Path] = []

    monkeypatch.setattr(
        provision_module.os,
        "geteuid",
        lambda: 0,
    )
    monkeypatch.setattr(
        provision_module,
        "pwd",
        types.SimpleNamespace(
            getpwnam=lambda username: types.SimpleNamespace(
                pw_uid=1200,
                pw_gid=1200,
            )
        ),
        raising=False,
    )
    monkeypatch.setattr(
        provision_module.os,
        "chown",
        lambda path, uid, gid: ownership_calls.append(
            Path(path)
        ),
    )

    class OwnershipCheckingLauncher:
        def launch(self, job_id: str) -> str:
            job = JobRepository(settings).get(job_id)

            assert job.status["systemd_unit"] == (
                f"alt-provision-{job_id}.service"
            )

            required_paths = {
                job.job_dir,
                job.job_dir / "request.json",
                job.job_dir / "status.json",
                job.job_dir / "ansible.log",
            }

            assert required_paths <= set(ownership_calls)

            return f"alt-provision-{job_id}.service"

    planner = ProvisionPlanner(
        settings,
        launcher=OwnershipCheckingLauncher(),
    )

    job = planner.start(
        MACHINE_UUID,
        parsed_request(),
    )

    assert job.status["systemd_unit"] == (
        f"alt-provision-{job.job_id}.service"
    )
