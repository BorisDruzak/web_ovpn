from __future__ import annotations

import subprocess
from dataclasses import replace
from pathlib import Path
from typing import TextIO

import pytest

from alt_deploy.ansible import AnsibleController
from alt_deploy.errors import ControlError
from alt_deploy.jobs import JobRepository
from alt_deploy.jsonio import atomic_write_json

from test_provision_preview import (
    prepare_preview_environment,
    valid_request,
)
from test_worker import successful_result


def prepare_provision_files(
    tmp_path: Path,
    *,
    include_stage_helper: bool,
):
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

    if include_stage_helper:
        settings.job_stage_helper_path.write_text(
            "#!/usr/bin/python3\n",
            encoding="utf-8",
        )
        settings.job_stage_helper_path.chmod(0o755)
    else:
        settings.job_stage_helper_path.unlink(missing_ok=True)

    return settings, fake_ansible, playbook


def test_run_provision_passes_stage_helper_extra_var(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings, fake_ansible, playbook = prepare_provision_files(
        tmp_path,
        include_stage_helper=True,
    )
    job = JobRepository(settings).create(valid_request())
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
        cwd: Path,
        env: dict[str, str],
    ) -> subprocess.CompletedProcess[str]:
        captured["command"] = command
        result_argument = next(
            value
            for value in command
            if value.startswith("provision_result_file=")
        )
        result_path = Path(result_argument.split("=", 1)[1])
        atomic_write_json(result_path, expected_result)
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(
        "alt_deploy.ansible.subprocess.run",
        fake_run,
    )

    with (job.job_dir / "ansible.log").open(
        "a",
        encoding="utf-8",
    ) as log_stream:
        result = AnsibleController(settings).run_provision(
            job,
            log_stream,
        )

    command = captured["command"]
    assert isinstance(command, list)
    assert command[0] == str(fake_ansible)
    assert (
        "job_stage_helper_path="
        f"{settings.job_stage_helper_path}"
    ) in command
    assert command[-1] == str(playbook)
    assert result == expected_result


def test_run_provision_requires_stage_helper_before_ansible(
    tmp_path: Path,
) -> None:
    settings, _, _ = prepare_provision_files(
        tmp_path,
        include_stage_helper=False,
    )
    job = JobRepository(settings).create(valid_request())

    with pytest.raises(ControlError) as exc:
        with (job.job_dir / "ansible.log").open(
            "a",
            encoding="utf-8",
        ) as log_stream:
            AnsibleController(settings).run_provision(
                job,
                log_stream,
            )

    assert exc.value.code == "provision_not_configured"
    assert any(
        item["name"] == "job_stage_helper"
        for item in exc.value.details["missing"]
    )
