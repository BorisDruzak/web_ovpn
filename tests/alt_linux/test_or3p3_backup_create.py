from __future__ import annotations

import json
from pathlib import Path

import pytest

from alt_deploy_backup.errors import BackupError
from support.backup_repository_sandbox import BackupSandbox


def test_create_publishes_only_after_all_components_verify(
    tmp_path: Path,
) -> None:
    sandbox = BackupSandbox.create(tmp_path)
    sandbox.seed_complete_controller()

    result = sandbox.repository().create()

    bundle = sandbox.settings.backup_root / result.backup_id
    assert bundle.is_dir()
    assert sorted(path.name for path in bundle.iterdir()) == [
        "ansible.tar.zst",
        "controller-state.tar.zst",
        "deployment-assets.tar.zst",
        "manifest.json",
        "registration-state.tar.zst",
        "runtime.tar.zst",
        "systemd.tar.zst",
    ]
    assert result.component_count == 6
    assert result.services_restored is True
    assert len(result.manifest_sha256) == 64
    assert not list(sandbox.settings.backup_root.glob(".creating-*"))


def test_create_failure_restores_units_and_does_not_publish(
    tmp_path: Path,
) -> None:
    sandbox = BackupSandbox.create(tmp_path)
    sandbox.seed_complete_controller()
    sandbox.fail_component("controller_state")
    before = sandbox.managed_unit_snapshot()

    with pytest.raises(BackupError):
        sandbox.repository().create()

    assert sandbox.managed_unit_snapshot() == before
    assert sandbox.published_backups() == []
    assert not list(sandbox.settings.backup_root.glob(".creating-*"))


def test_create_holds_lifecycle_lock_during_capture(
    tmp_path: Path,
) -> None:
    sandbox = BackupSandbox.create(tmp_path)
    sandbox.seed_complete_controller()

    sandbox.repository().create()

    assert sandbox.lifecycle_lock_observed_for_all_components()


def test_create_captures_components_in_exact_restore_order(
    tmp_path: Path,
) -> None:
    sandbox = BackupSandbox.create(tmp_path)
    sandbox.seed_complete_controller()

    sandbox.repository().create()

    assert sandbox.capture_order == [
        "runtime",
        "systemd",
        "ansible",
        "controller_state",
        "registration_state",
        "deployment_assets",
    ]


def test_create_cli_returns_exact_safe_json(tmp_path: Path) -> None:
    sandbox = BackupSandbox.create(tmp_path)
    sandbox.seed_complete_controller()

    result = sandbox.run_cli("create", effective_uid=0)

    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["status"] == "ok"
    assert payload["result"] == "backup_created"
    assert payload["component_count"] == 6
    assert payload["services_restored"] is True
    assert len(payload["manifest_sha256"]) == 64
    assert set(payload) == {
        "status",
        "result",
        "backup_id",
        "component_count",
        "manifest_sha256",
        "services_restored",
    }


def test_create_rejects_active_job_before_stopping_services(
    tmp_path: Path,
) -> None:
    sandbox = BackupSandbox.create(tmp_path)
    sandbox.seed_complete_controller()
    sandbox.seed_job(state="running", stage="connecting")
    before = sandbox.managed_unit_snapshot()

    with pytest.raises(BackupError) as error:
        sandbox.repository().create()

    assert error.value.code == "backup_active_jobs"
    assert sandbox.managed_unit_snapshot() == before
    assert sandbox.capture_order == []
