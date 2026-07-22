from __future__ import annotations

import json
from pathlib import Path

import pytest

from alt_deploy_backup.errors import BackupError
from support.backup_sandbox import BackupSandbox


def test_restore_reproduces_enabled_and_active_states(
    tmp_path: Path,
) -> None:
    sandbox = BackupSandbox.create(tmp_path)
    sandbox.set_unit_state(
        "alt-deploy-http.service",
        enabled="enabled",
        active="active",
    )
    sandbox.set_unit_state(
        "alt-deploy-register.service",
        enabled="disabled",
        active="inactive",
    )
    sandbox.set_unit_state(
        "alt-deploy-process.path",
        enabled="enabled",
        active="active",
    )

    manager = sandbox.systemd_manager()
    states = manager.capture()
    manager.stop_maintenance()
    manager.restore(states, activate_health_services=True)

    assert sandbox.unit_state("alt-deploy-http.service") == (
        "enabled",
        "active",
    )
    assert sandbox.unit_state("alt-deploy-register.service") == (
        "disabled",
        "inactive",
    )
    assert sandbox.unit_state("alt-deploy-process.path") == (
        "enabled",
        "active",
    )


def test_maintenance_stop_and_restore_orders_are_safe(
    tmp_path: Path,
) -> None:
    sandbox = BackupSandbox.create(tmp_path)
    manager = sandbox.systemd_manager()
    states = manager.capture()

    manager.stop_maintenance()
    manager.restore(states, activate_health_services=True)

    mutations = [
        command
        for command in sandbox.command_log()
        if command and command[0] in {"stop", "start"}
    ]
    stop_commands = [command for command in mutations if command[0] == "stop"]
    start_commands = [command for command in mutations if command[0] == "start"]
    assert stop_commands[:3] == [
        ["stop", "alt-deploy-process.path"],
        ["stop", "alt-deploy-register.service"],
        ["stop", "alt-deploy-http.service"],
    ]
    assert start_commands[-1] == ["start", "alt-deploy-process.path"]
    assert ["start", "alt-deploy-process.service"] not in start_commands


def test_capture_rejects_malformed_systemctl_output(
    tmp_path: Path,
) -> None:
    sandbox = BackupSandbox.create(tmp_path)
    sandbox.set_systemctl_malformed(True)

    with pytest.raises(BackupError) as error:
        sandbox.systemd_manager().capture()

    assert error.value.code == "backup_preflight_failed"


def test_quiescence_rejects_active_job(tmp_path: Path) -> None:
    sandbox = BackupSandbox.create(tmp_path)
    job_id = sandbox.seed_job(state="running", stage="connecting")

    with pytest.raises(BackupError) as error:
        sandbox.quiescence_checker().assert_quiescent()

    assert error.value.code == "backup_active_jobs"
    assert error.value.details == {
        "jobs": [
            {
                "job_id": job_id,
                "state": "running",
                "stage": "connecting",
            }
        ]
    }


def test_quiescence_rejects_malformed_job_without_payload_leak(
    tmp_path: Path,
) -> None:
    sandbox = BackupSandbox.create(tmp_path)
    job_id = sandbox.seed_job(state="successful", stage="complete")
    status_path = (
        sandbox.settings.controller_state_root
        / "jobs"
        / job_id
        / "status.json"
    )
    status_path.write_text('{"state": ["secret"]}\n', encoding="utf-8")

    with pytest.raises(BackupError) as error:
        sandbox.quiescence_checker().assert_quiescent()

    assert error.value.code == "backup_preflight_failed"
    assert "secret" not in json.dumps(error.value.to_dict())


def test_quiescence_rejects_pending_registration(tmp_path: Path) -> None:
    sandbox = BackupSandbox.create(tmp_path)
    pending = sandbox.seed_pending("machine.json")

    with pytest.raises(BackupError) as error:
        sandbox.quiescence_checker().assert_quiescent()

    assert error.value.code == "backup_pending_registration"
    assert error.value.details == {"pending": [pending.name]}


def test_quiescence_rejects_active_processor(tmp_path: Path) -> None:
    sandbox = BackupSandbox.create(tmp_path)
    sandbox.set_unit_state(
        "alt-deploy-process.service",
        enabled="static",
        active="active",
    )

    with pytest.raises(BackupError) as error:
        sandbox.quiescence_checker().assert_quiescent()

    assert error.value.code == "backup_processor_active"


def test_quiescence_rejects_transient_provision_unit(
    tmp_path: Path,
) -> None:
    sandbox = BackupSandbox.create(tmp_path)
    sandbox.set_transient_units(
        ["alt-provision-job-20260722T000000Z-11111111.service"]
    )

    with pytest.raises(BackupError) as error:
        sandbox.quiescence_checker().assert_quiescent()

    assert error.value.code == "backup_active_jobs"
    assert error.value.details == {
        "transient_units": [
            "alt-provision-job-20260722T000000Z-11111111.service"
        ]
    }


def test_quiescence_returns_empty_safe_snapshot(tmp_path: Path) -> None:
    sandbox = BackupSandbox.create(tmp_path)
    sandbox.seed_job(state="successful", stage="complete")

    snapshot = sandbox.quiescence_checker().assert_quiescent()

    assert snapshot.active_job_ids == ()
    assert snapshot.pending_filenames == ()
    assert snapshot.processor_active is False
    assert snapshot.transient_units == ()
