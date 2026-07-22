from __future__ import annotations

import json
from pathlib import Path

import pytest

from alt_deploy_backup.settings import BackupSettings
from support.backup_sandbox import BackupSandbox


def test_cli_rejects_non_root_before_service_construction(
    tmp_path: Path,
) -> None:
    sandbox = BackupSandbox.create(tmp_path)

    result = sandbox.run_cli("list", effective_uid=1000)

    assert result.returncode == 6
    assert json.loads(result.stdout) == {
        "status": "error",
        "error": {
            "code": "backup_not_root",
            "message": "Backup operation requires root",
        },
    }
    assert sandbox.command_log() == []


def test_cli_requires_exact_backup_id_for_verify(tmp_path: Path) -> None:
    sandbox = BackupSandbox.create(tmp_path)

    result = sandbox.run_cli("verify", effective_uid=0)

    assert result.returncode == 2
    assert json.loads(result.stdout)["error"]["code"] == "backup_usage"


def test_cli_accepts_root_list_with_synthetic_settings(
    tmp_path: Path,
) -> None:
    sandbox = BackupSandbox.create(tmp_path)

    result = sandbox.run_cli("list", effective_uid=0)

    assert result.returncode == 0
    assert json.loads(result.stdout) == {
        "status": "ok",
        "result": "backups_listed",
        "count": 0,
        "backups": [],
    }


def test_cli_renders_invalid_settings_as_one_safe_json_object(
    tmp_path: Path,
) -> None:
    sandbox = BackupSandbox.create(tmp_path)

    result = sandbox.run_cli(
        "list",
        effective_uid=0,
        ALT_DEPLOY_BACKUP_EXPECTED_ROOT_UID="not-a-number",
    )

    assert result.returncode == 6
    assert result.stderr == ""
    assert json.loads(result.stdout) == {
        "status": "error",
        "error": {
            "code": "backup_preflight_failed",
            "message": "Backup configuration is invalid",
        },
    }


def test_identity_override_is_rejected_for_production_root() -> None:
    environment = {
        "ALT_DEPLOY_BACKUP_TEST_MODE": "1",
        "ALT_DEPLOY_BACKUP_TEST_ROOT": "/",
        "ALT_DEPLOY_BACKUP_EXPECTED_ROOT_UID": "1000",
        "ALT_DEPLOY_BACKUP_EXPECTED_ROOT_GID": "1000",
        "ALT_DEPLOY_BACKUP_EXPECTED_SERVICE_UID": "1000",
        "ALT_DEPLOY_BACKUP_EXPECTED_SERVICE_GID": "1000",
    }

    with pytest.raises(ValueError):
        BackupSettings.from_env(environment)


def test_production_mode_rejects_identity_override() -> None:
    environment = {
        "ALT_DEPLOY_BACKUP_EXPECTED_ROOT_UID": "1000",
    }

    with pytest.raises(ValueError):
        BackupSettings.from_env(environment)


def test_cli_writes_bounded_start_and_success_audit_records(
    tmp_path: Path,
) -> None:
    sandbox = BackupSandbox.create(tmp_path)

    result = sandbox.run_cli("list", effective_uid=0)

    assert result.returncode == 0
    records = [
        json.loads(line)
        for line in sandbox.settings.log_file.read_text(
            encoding="utf-8"
        ).splitlines()
    ]
    assert [record["event"] for record in records] == [
        "command_started",
        "command_completed",
    ]
    assert records[0]["operation_id"] == records[1]["operation_id"]
    assert records[0]["command"] == "list"
    assert records[0]["backup_id"] is None
    assert records[0]["status"] == "started"
    assert records[1]["status"] == "ok"
    assert records[1]["result"] == "backups_listed"


def test_cli_writes_terminal_failure_audit_record(tmp_path: Path) -> None:
    sandbox = BackupSandbox.create(tmp_path)
    backup_id = "backup-20260722T120000Z-11111111"

    result = sandbox.run_cli("verify", backup_id, effective_uid=0)

    payload = json.loads(result.stdout)
    assert result.returncode != 0
    records = [
        json.loads(line)
        for line in sandbox.settings.log_file.read_text(
            encoding="utf-8"
        ).splitlines()
    ]
    assert [record["event"] for record in records] == [
        "command_started",
        "command_failed",
    ]
    assert records[0]["operation_id"] == records[1]["operation_id"]
    assert records[1]["backup_id"] == backup_id
    assert records[1]["error_code"] == payload["error"]["code"]


def test_install_check_creates_or_validates_fingerprint_key(
    tmp_path: Path,
) -> None:
    sandbox = BackupSandbox.create(tmp_path)
    key = sandbox.settings.fingerprint_key

    result = sandbox.run_cli("install-check", effective_uid=0)

    assert result.returncode == 0, result.stdout
    assert json.loads(result.stdout) == {
        "status": "ok",
        "result": "backup_tool_ready",
    }
    assert key.is_file()
    assert key.stat().st_size == 32
    before = key.read_bytes()

    repeated = sandbox.run_cli("install-check", effective_uid=0)

    assert repeated.returncode == 0
    assert key.read_bytes() == before
