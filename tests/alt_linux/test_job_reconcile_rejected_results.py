from __future__ import annotations

from pathlib import Path

import pytest

from alt_deploy.assignments import AssignmentRepository
from alt_deploy.job_reconcile import JobReconciler
from alt_deploy.job_stages import JobStageManager
from alt_deploy.jobs import JobRepository
from alt_deploy.jsonio import atomic_write_json

from test_job_reconcile_stages import (
    advance_to_employee,
    missing_unit_result,
)
from test_jobs import provision_request
from test_registry_cli import make_settings
from test_worker import successful_result


def advance_to_recording(
    settings,
    job_id: str,
    unit_name: str,
) -> None:
    advance_to_employee(settings, job_id, unit_name)
    manager = JobStageManager(settings)
    for stage in (
        "login_screen",
        "verifying",
        "recording",
    ):
        manager.advance(job_id, stage)


@pytest.mark.parametrize(
    "result_kind",
    [
        pytest.param("malformed", id="malformed-json"),
        pytest.param(
            "failed_verification",
            id="failed-verification",
        ),
    ],
)
def test_reconcile_rejected_recording_result_preserves_stage(
    monkeypatch,
    tmp_path: Path,
    result_kind: str,
) -> None:
    settings = make_settings(tmp_path)
    jobs = JobRepository(settings)
    assignments = AssignmentRepository(settings)
    created = jobs.create(provision_request())
    unit_name = f"alt-provision-{created.job_id}.service"
    advance_to_recording(
        settings,
        created.job_id,
        unit_name,
    )
    running = jobs.get(created.job_id)
    result_path = running.job_dir / "result.json"

    if result_kind == "malformed":
        result_path.write_text(
            "{not-json\n",
            encoding="utf-8",
        )
    else:
        payload = successful_result(running.job_id)
        payload["verification"]["hostname"] = False
        atomic_write_json(result_path, payload)

    def fake_systemctl(
        command,
        *,
        shell,
        text,
        capture_output,
        timeout,
        check,
    ):
        assert shell is False
        assert text is True
        assert capture_output is True
        assert timeout == 15
        assert check is False
        return missing_unit_result(command, unit_name)

    monkeypatch.setattr(
        "alt_deploy.job_reconcile.subprocess.run",
        fake_systemctl,
    )

    reconciliation = JobReconciler(settings).reconcile()

    assert reconciliation["changed"] == [
        {
            "job_id": running.job_id,
            "previous_state": "running",
            "state": "failed",
            "action": "result_rejected",
            "retryable": True,
            "error_code": "invalid_provision_result",
        }
    ]

    rejected = jobs.get(running.job_id)
    assert rejected.state == "failed"
    assert rejected.stage == "recording"
    assert rejected.status["error_code"] == (
        "invalid_provision_result"
    )
    assert rejected.status["retryable"] is True
    assert [
        item["stage"]
        for item in rejected.status["stage_history"]
    ][-1] == "recording"
    assert assignments.get(running.machine_uuid) is None
