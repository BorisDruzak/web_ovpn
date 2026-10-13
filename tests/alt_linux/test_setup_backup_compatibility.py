"""Synthetic maintenance must preserve consumed V2 admissions across restore."""
import json
import shutil
import multiprocessing
from dataclasses import replace

import pytest

from alt_deploy.errors import ControlError
from alt_deploy.setup_jobs import SetupJobRepository, setup_queue_lock
from alt_deploy_backup.errors import BackupError
from alt_deploy_backup.locks import exclusive_operation_lock, exclusive_setup_maintenance
from alt_deploy_backup.manifest import parse_manifest
from alt_deploy_backup.systemd import MANAGED_UNITS
from support.backup_restore_sandbox import BackupSandbox
from test_component_setup import component_service
from test_component_catalog import project
from test_setup_jobs import jobs_fixture
from test_or3p3_backup_manifest import valid_manifest


def seed_v2(sandbox, component_service, state='successful'):
    if not sandbox.settings.lifecycle_lock.exists():
        sandbox.seed_complete_controller()
    jobs, plan, settings = jobs_fixture(component_service)
    job = jobs.submit(plan, operation='component')
    jobs.claim(job.job_id, {'boot_id': 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee', 'pid': 123, 'start_ticks': 1})
    jobs.transition(job.job_id, 'running')
    if state == 'successful':
        jobs.transition(job.job_id, 'verifying')
    jobs.transition(job.job_id, state)
    for name in ('jobs', 'setup-job-plan-claims', 'setup-job-reservations'):
        shutil.copytree(settings.state_root/name, sandbox.settings.controller_state_root/name, dirs_exist_ok=True)
    return job


def test_legacy_four_unit_manifest_remains_readable():
    old = valid_manifest().to_dict()
    old['systemd_units'] = old['systemd_units'][:4]
    assert len(parse_manifest(json.dumps(old).encode()).systemd_units) == 4
    assert 'alt-setup-worker.service' in MANAGED_UNITS


def test_finished_v2_job_can_be_backed_up_and_rehearsed(tmp_path, component_service):
    sandbox = BackupSandbox.create(tmp_path)
    seed_v2(sandbox, component_service)
    backup_id = sandbox.repository().create().backup_id
    sandbox.repository().verify(backup_id, write_evidence=True)
    sandbox.rehearsal_service().rehearse(backup_id)
    assert sandbox.restore_service().restore(backup_id).phase == 'committed'


def test_unresolved_v2_job_blocks_maintenance(tmp_path, component_service):
    sandbox = BackupSandbox.create(tmp_path)
    seed_v2(sandbox, component_service, 'unknown_requires_review')
    with pytest.raises(BackupError) as caught:
        sandbox.repository().create()
    assert caught.value.code == 'backup_active_jobs'


@pytest.mark.parametrize('missing', ['setup-job-plan-claims', 'jobs'])
def test_v2_jobs_with_missing_claim_directory_require_review(tmp_path, component_service, missing):
    sandbox = BackupSandbox.create(tmp_path)
    seed_v2(sandbox, component_service)
    folder = sandbox.settings.controller_state_root/missing
    shutil.rmtree(folder)  # Synthetic fixture only; controller exclusion must survive this corruption.
    with pytest.raises(BackupError) as caught:
        sandbox.repository().create()
    assert caught.value.code == 'backup_preflight_failed'


def test_restoring_older_generation_cannot_erase_new_consumed_plan(tmp_path, component_service):
    sandbox = BackupSandbox.create(tmp_path)
    old = sandbox.create_rehearsed_backup()
    job = seed_v2(sandbox, component_service)
    before = (sandbox.settings.controller_state_root/'jobs'/job.job_id/'status.json').read_bytes()
    with pytest.raises(BackupError) as caught:
        sandbox.restore_service().restore(old)
    assert caught.value.code == 'setup_history_restore_conflict'
    assert (sandbox.settings.controller_state_root/'jobs'/job.job_id/'status.json').read_bytes() == before


def test_maintenance_rejects_admission_before_state_root_is_opened(tmp_path, component_service):
    sandbox = BackupSandbox.create(tmp_path)
    sandbox.seed_complete_controller()
    _, _, settings = jobs_fixture(component_service)
    settings.state_root = sandbox.settings.controller_state_root
    with exclusive_operation_lock(sandbox.settings), exclusive_setup_maintenance(sandbox.settings):
        with pytest.raises(ControlError) as caught:
            with setup_queue_lock(settings):
                pytest.fail('Admission entered maintenance')
        assert caught.value.code == 'setup_controller_maintenance'


def test_maintenance_guard_blocks_another_process_even_with_lifecycle_held(tmp_path, component_service):
    sandbox = BackupSandbox.create(tmp_path)
    sandbox.seed_complete_controller()
    _, _, settings = jobs_fixture(component_service)
    settings.state_root = sandbox.settings.controller_state_root
    parent, child = multiprocessing.Pipe(False)
    def admit():
        try:
            from alt_deploy.locks import exclusive_lock
            with exclusive_lock(sandbox.settings.lifecycle_lock), setup_queue_lock(settings):
                child.send('admitted')
        except ControlError as exc:
            child.send(exc.code)
    with exclusive_setup_maintenance(sandbox.settings):
        process = multiprocessing.get_context('fork').Process(target=admit)
        process.start()
        assert parent.poll(5)
        assert parent.recv() == 'setup_controller_maintenance'
        process.join(5)
        assert process.exitcode == 0


def test_new_worker_unit_and_helper_are_captured_stopped_and_resumed(tmp_path):
    sandbox = BackupSandbox.create(tmp_path)
    sandbox.seed_complete_controller()
    helper = sandbox.settings.worker_path.parent/'alt-setup-worker'
    helper.write_bytes(b'#!/usr/bin/python3\nraise SystemExit(0)\n')
    helper.chmod(0o755)
    unit = sandbox.settings.systemd_root/'alt-setup-worker.service'
    unit.write_text('[Unit]\nDescription=fixture\n[Service]\nExecStart=/usr/local/libexec/alt-setup-worker\n')
    unit.chmod(0o644)
    sandbox.set_unit_state(unit.name, enabled='enabled', active='active')
    backup_id = sandbox.repository().create().backup_id
    manifest = parse_manifest((sandbox.bundle(backup_id)/'manifest.json').read_bytes())
    assert manifest.systemd_units[-1].name == unit.name
    assert manifest.systemd_units[-1].active_state == 'active'
    assert '/usr/local/libexec/alt-setup-worker' in {p.absolute_path for p in manifest.components[0].paths}
    assert sandbox.unit_state(unit.name) == ('enabled', 'active')
    commands = sandbox.command_log()
    assert any(args[-2:] == ['stop', unit.name] for args in commands)


def test_actual_pre_v2_bundle_restores_without_leaving_new_worker(tmp_path, monkeypatch):
    from alt_deploy_backup.components import component_specs
    sandbox = BackupSandbox.create(tmp_path)
    sandbox.seed_complete_controller()
    helper = sandbox.settings.worker_path.parent/'alt-setup-worker'
    unit = sandbox.settings.systemd_root/'alt-setup-worker.service'
    old_specs = tuple(replace(spec, paths=tuple(p for p in spec.paths if p not in (helper, unit)))
                      for spec in component_specs(sandbox.settings))
    with monkeypatch.context() as patch:
        patch.setattr('alt_deploy_backup.repository.component_specs', lambda settings:old_specs)
        backup_id = sandbox.repository().create().backup_id
    # Represent an actual V1 four-unit manifest with V1 runtime/systemd path sets,
    # before verification/rehearsal evidence is generated.
    path = sandbox.bundle(backup_id)/'manifest.json'
    manifest = parse_manifest(path.read_bytes())
    path.write_bytes(replace(manifest, systemd_units=manifest.systemd_units[:4]).to_bytes())
    sandbox.repository().verify(backup_id, write_evidence=True)
    sandbox.rehearsal_service().rehearse(backup_id)
    helper.write_text('#!/usr/bin/python3\nraise SystemExit(0)\n'); helper.chmod(0o755)
    unit.write_text('[Unit]\nDescription=new worker\n'); unit.chmod(0o644)
    sandbox.set_unit_state(unit.name, enabled='enabled', active='active')
    service = sandbox.restore_service()
    reload_units = service._daemon_reload
    def reload_fixture():
        reload_units()
        # Fake systemctl has no unit-file discovery; mirror real daemon-reload.
        if not unit.exists():
            sandbox.set_unit_state(unit.name, enabled='not-found', active='inactive', load='not-found')
    monkeypatch.setattr(service, '_daemon_reload', reload_fixture)
    assert service.restore(backup_id).phase == 'committed'
    assert not helper.exists() and not unit.exists()
    assert sandbox.unit_state(unit.name) == ('not-found', 'inactive')
