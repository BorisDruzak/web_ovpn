from __future__ import annotations

import io
import json

import pytest

from alt_deploy.cli import main

from test_registry_cli import make_settings


def _cleanup_report(*, dry_run: bool) -> dict[str, object]:
    return {
        "status": "ok",
        "dry_run": dry_run,
        "policy": {
            "retention_days": 90,
            "archive_after_days": 14,
        },
        "checked": 0,
        "actions": [],
        "skipped": [],
    }


def test_jobs_cleanup_cli_defaults_to_dry_run(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = make_settings(tmp_path)
    calls: list[bool] = []

    def fake_cleanup(self, *, apply: bool = False):
        calls.append(apply)
        return _cleanup_report(dry_run=not apply)

    monkeypatch.setattr(
        "alt_deploy.cli.JobRetentionManager.cleanup",
        fake_cleanup,
    )

    stdout = io.StringIO()
    rc = main(
        ["--json", "jobs", "cleanup"],
        settings=settings,
        stdout=stdout,
        stderr=io.StringIO(),
    )

    assert rc == 0
    assert calls == [False]
    assert json.loads(stdout.getvalue()) == {
        "status": "ok",
        "cleanup": _cleanup_report(dry_run=True),
    }


def test_jobs_cleanup_apply_requires_root(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = make_settings(tmp_path)
    called = False

    def fake_cleanup(self, *, apply: bool = False):
        nonlocal called
        called = True
        return _cleanup_report(dry_run=not apply)

    monkeypatch.setattr(
        "alt_deploy.cli.JobRetentionManager.cleanup",
        fake_cleanup,
    )
    monkeypatch.setattr(
        "alt_deploy.cli.os.geteuid",
        lambda: 1000,
    )

    stdout = io.StringIO()
    rc = main(
        ["--json", "jobs", "cleanup", "--apply"],
        settings=settings,
        stdout=stdout,
        stderr=io.StringIO(),
    )

    assert rc == 6
    assert called is False
    assert json.loads(stdout.getvalue())["error"]["code"] == (
        "root_required"
    )


def test_jobs_cleanup_apply_invokes_mutating_cleanup_as_root(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = make_settings(tmp_path)
    calls: list[bool] = []

    def fake_cleanup(self, *, apply: bool = False):
        calls.append(apply)
        return _cleanup_report(dry_run=not apply)

    monkeypatch.setattr(
        "alt_deploy.cli.JobRetentionManager.cleanup",
        fake_cleanup,
    )
    monkeypatch.setattr(
        "alt_deploy.cli.os.geteuid",
        lambda: 0,
    )

    stdout = io.StringIO()
    rc = main(
        ["--json", "jobs", "cleanup", "--apply"],
        settings=settings,
        stdout=stdout,
        stderr=io.StringIO(),
    )

    assert rc == 0
    assert calls == [True]
    assert json.loads(stdout.getvalue()) == {
        "status": "ok",
        "cleanup": _cleanup_report(dry_run=False),
    }
