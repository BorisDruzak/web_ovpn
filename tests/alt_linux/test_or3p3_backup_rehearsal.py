from __future__ import annotations

import json
from pathlib import Path

import pytest

from alt_deploy_backup.errors import BackupError
from support.backup_rehearsal_sandbox import BackupSandbox


def test_rehearsal_never_writes_production_paths(tmp_path: Path) -> None:
    sandbox = BackupSandbox.create(tmp_path)
    backup_id = sandbox.create_verified_backup()
    before = sandbox.production_snapshot()

    result = sandbox.rehearsal_service().rehearse(backup_id)

    assert result.rehearsal_passed is True
    assert result.check_count >= 10
    assert sandbox.production_snapshot() == before
    assert not (sandbox.settings.rehearsal_root / backup_id).exists()
    assert (sandbox.bundle(backup_id) / "rehearsal.json").is_file()
    summary = sandbox.repository().list()[0]
    assert summary.verified is True
    assert summary.rehearsed is True


def test_rehearsal_accepts_ready_registration_awaiting_assignment(
    tmp_path: Path,
) -> None:
    sandbox = BackupSandbox.create(tmp_path)
    sandbox.seed_complete_controller()
    machine_id = "a" * 32
    registration = sandbox.settings.registration_root / "ready" / (
        machine_id + ".json"
    )
    registration.parent.mkdir(parents=True, exist_ok=True)
    registration.write_text(
        json.dumps(
            {
                "machine_key": machine_id,
                "uuid": machine_id,
                "status": "awaiting_assignment",
                "registration_id": "reg-" + "b" * 32,
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    registration.chmod(0o600)
    backup_id = sandbox.repository().create().backup_id
    sandbox.repository().verify(backup_id, write_evidence=True)

    result = sandbox.rehearsal_service().rehearse(backup_id)

    assert result.rehearsal_passed is True


def test_failed_rehearsal_preserves_private_tree(tmp_path: Path) -> None:
    sandbox = BackupSandbox.create(tmp_path)
    sandbox.seed_complete_controller()
    broken = (
        sandbox.settings.runtime_control_root
        / "alt_deploy"
        / "__init__.py"
    )
    broken.write_text("def broken(:\n", encoding="utf-8")
    backup_id = sandbox.repository().create().backup_id
    sandbox.repository().verify(backup_id, write_evidence=True)

    with pytest.raises(BackupError) as error:
        sandbox.rehearsal_service().rehearse(backup_id)

    assert error.value.code == "backup_rehearsal_failed"
    failed_root = sandbox.settings.rehearsal_root / backup_id
    assert failed_root.is_dir()
    assert not (sandbox.bundle(backup_id) / "rehearsal.json").exists()


@pytest.mark.parametrize('defect', [None, 'missing_result', 'wrong_machine', 'wrong_hostname', 'failed_result', 'unverified_domain',
    'bool_schema', 'float_schema', 'missing_error', 'nonnull_error',
    *[kind + ':' + key for kind in ['missing', 'nonbool'] for key in ['domain_join', 'sssd', 'domain_user_lookup', 'group_policy']],
])
def test_first_domain_login_state_requires_matching_successful_configuration(tmp_path: Path, defect) -> None:
    sandbox = BackupSandbox.create(tmp_path)
    sandbox.seed_complete_controller()
    machine_id = 'a' * 32
    registration_root = tmp_path / 'registrations'
    ready = registration_root / 'ready'
    ready.mkdir(parents=True)
    result = {
        'schema_version': 1, 'status': 'successful', 'error': None, 'machine_uuid': machine_id,
        'hostname': 'alt-test', 'verification': {
            'domain_join': True, 'sssd': True, 'domain_user_lookup': True, 'group_policy': True,
        },
    }
    if defect == 'wrong_machine':
        result['machine_uuid'] = 'b' * 32
    elif defect == 'wrong_hostname':
        result['hostname'] = 'other-host'
    elif defect == 'failed_result':
        result['status'] = 'failed'
    elif defect == 'unverified_domain':
        result['verification']['domain_join'] = False
    elif defect == 'bool_schema':
        result['schema_version'] = True
    elif defect == 'float_schema':
        result['schema_version'] = 1.0
    elif defect == 'missing_error':
        result.pop('error')
    elif defect == 'nonnull_error':
        result['error'] = {'code': 'failed'}
    elif defect and defect.startswith('missing:'):
        result['verification'].pop(defect.split(':')[1])
    elif defect and defect.startswith('nonbool:'):
        result['verification'][defect.split(':')[1]] = 1
    record = {
        'machine_key': machine_id, 'uuid': machine_id, 'hostname': 'alt-test',
        'status': 'awaiting_first_domain_login', 'registration_id': 'reg-' + 'b' * 32,
    }
    if defect != 'missing_result':
        record['configure_result'] = result
    path = ready / (machine_id + '.json')
    path.write_text(json.dumps(record), encoding='utf-8')
    before = path.read_bytes()
    validator = sandbox.rehearsal_service().state_validator
    if defect:
        with pytest.raises(BackupError):
            validator._validate_registrations(registration_root)
    else:
        assert validator._validate_registrations(registration_root) == 'registrations'
    assert path.read_bytes() == before


def test_rehearsal_accepts_documented_completed_job_artifacts(
    tmp_path: Path,
) -> None:
    sandbox = BackupSandbox.create(tmp_path)
    sandbox.seed_complete_controller()
    job = (
        sandbox.settings.controller_state_root
        / "jobs"
        / "job-20260722T000000Z-00000001"
    )
    provision_result = job / "provision-result.json"
    provision_result.write_text(
        json.dumps({"status": "ok"}, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    provision_result.chmod(0o600)
    archived_log = job / "ansible.log.gz"
    archived_log.write_bytes(
        b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x02\x03"
        b"\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    )
    archived_log.chmod(0o600)
    backup_id = sandbox.repository().create().backup_id
    sandbox.repository().verify(backup_id, write_evidence=True)

    result = sandbox.rehearsal_service().rehearse(backup_id)

    assert result.rehearsal_passed is True
    assert (sandbox.bundle(backup_id) / "rehearsal.json").is_file()


def test_state_validator_rejects_malformed_job_state(tmp_path: Path) -> None:
    sandbox = BackupSandbox.create(tmp_path)
    root = sandbox.malformed_rehearsal_tree()

    with pytest.raises(BackupError) as error:
        sandbox.rehearsal_service().state_validator.validate_tree(
            root,
            manifest=None,  # type: ignore[arg-type]
        )

    assert error.value.code == "backup_rehearsal_failed"


def test_rehearse_status_is_byte_identical_for_bundle_evidence(
    tmp_path: Path,
) -> None:
    sandbox = BackupSandbox.create(tmp_path)
    backup_id = sandbox.create_rehearsed_backup()
    verification = sandbox.bundle(backup_id) / "verification.json"
    rehearsal = sandbox.bundle(backup_id) / "rehearsal.json"
    before = (verification.read_bytes(), rehearsal.read_bytes())

    result = sandbox.run_cli(
        "rehearse-status",
        backup_id,
        effective_uid=0,
    )

    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["status"] == "ok"
    assert payload["result"] == "backup_rehearsed"
    assert (verification.read_bytes(), rehearsal.read_bytes()) == before


def test_rehearse_cli_returns_bounded_success_result(tmp_path: Path) -> None:
    sandbox = BackupSandbox.create(tmp_path)
    backup_id = sandbox.create_verified_backup()

    result = sandbox.run_cli("rehearse", backup_id, effective_uid=0)

    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["status"] == "ok"
    assert payload["result"] == "backup_rehearsed"
    assert payload["backup_id"] == backup_id
    assert payload["rehearsal_passed"] is True
    assert payload["check_count"] >= 10
    assert len(payload["manifest_sha256"]) == 64
