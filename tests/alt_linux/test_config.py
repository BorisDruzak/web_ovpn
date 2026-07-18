from __future__ import annotations

from pathlib import Path

from alt_deploy.config import Settings


def test_settings_accept_environment_overrides(
    monkeypatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setenv(
        "ALT_DEPLOY_REGISTRATION_ROOT",
        str(tmp_path / "registration"),
    )
    monkeypatch.setenv(
        "ALT_DEPLOY_STATE_ROOT",
        str(tmp_path / "state"),
    )
    monkeypatch.setenv(
        "ALT_DEPLOY_ANSIBLE_PROJECT",
        str(tmp_path / "ansible"),
    )
    monkeypatch.setenv(
        "ALT_DEPLOY_JOB_STAGE_HELPER",
        str(tmp_path / "alt-job-stage"),
    )

    settings = Settings.from_env()

    assert settings.registration_root == tmp_path / "registration"
    assert settings.jobs_dir == tmp_path / "state" / "jobs"
    assert settings.assignments_dir == tmp_path / "state" / "assignments"
    assert settings.ansible_project_dir == tmp_path / "ansible"
    assert settings.job_stage_helper_path == (
        tmp_path / "alt-job-stage"
    )
