"""Maintenance receipts preserve UNKNOWN and cannot authorize workstation writers."""
import copy
from datetime import timedelta
import fcntl

import pytest

from alt_deploy.errors import ControlError
from alt_deploy.setup_jobs import legacy_setup_execution
from alt_deploy.setup_plans import private_create, private_read
from test_component_setup import component_service
from test_component_catalog import project
from test_setup_detach import full_fixture
from test_setup_service import UUID, OU


@pytest.fixture
def stopped(component_service, monkeypatch):
    setup, jobs, engine, worker, calls = full_fixture(component_service, monkeypatch)
    def fail_configure(identifier, request, **kwargs):
        run_id = 'f'*32
        with legacy_setup_execution(setup.settings, UUID, component_service[2].hostname,
                                    operation='configure', run_id=run_id):
            private_create(setup.settings.state_root/'configure-runs'/run_id/'request.json', request.to_dict())
            private_create(setup.settings.state_root/'configure-runs'/run_id/'result.json', {
                'schema_version': 1, 'machine_uuid': UUID, 'hostname': component_service[2].hostname,
                'profile': request.profile, 'status': 'failed', 'phase': 'domain_core_verify',
                'retryable': False, 'recovered': False, 'reboot_required': True,
                'error': {'code': 'configure_critical_phase_failed', 'class': 'fatal-invariant',
                          'safe_message': 'Synthetic partial configuration failure'},
                'components': {}, 'verification': {'group_policy_flag_preserved': True}})
            raise ControlError('configure_critical_phase_failed', 'Synthetic failure', 7,
                               {'run_id': run_id, 'phase': 'configuration'})
    setup.planner.start = fail_configure
    plan = setup.plan(UUID, component_service[3]['login'], OU, 'core-apps')
    submission = setup.apply(plan['plan_id'], plan['sha256'], detach=True)
    assert worker.run_once()['status'] == 'unknown_requires_review'
    job = jobs.get(submission['job_id'])
    assert len(list((setup.settings.state_root/'legacy-setup-reservations').glob('*.json'))) == 2
    assert private_read(job.job_dir/'execution.json')['finished_at']
    snapshot = plan['payload']
    facts = {'machine': copy.deepcopy(snapshot['machine']), 'user': copy.deepcopy(snapshot['user']),
             'ou_identity': copy.deepcopy(snapshot['ou_identity']),
             'computer': copy.deepcopy(snapshot['computer']),
             'observed': setup.probe(component_service[2], component_service[3]),
             'ssh_binding': copy.deepcopy(snapshot['ssh_binding']),
             'package_manager': copy.deepcopy(component_service[4]['package_manager']),
             'user_runtime': copy.deepcopy(component_service[4]['user']),
             'boot_id': '12345678-1234-1234-1234-123456789abc'}
    return setup.settings, job, facts, component_service[5]


def service(stopped):
    from alt_deploy_backup.setup_maintenance_review import MaintenanceReview
    settings, job, facts, date = stopped
    return MaintenanceReview(settings, observer=lambda job: copy.deepcopy(facts), clock=lambda: date[0])


def retained(root):
    return {str(p.relative_to(root)): p.read_bytes() for p in root.rglob('*') if p.is_file()
            and not p.parts[-2].startswith('setup-maintenance-')}


def test_finished_unknown_with_alive_idle_worker_can_review_without_reclassifying(stopped):
    settings, job, facts, date = stopped
    before = retained(settings.state_root)
    review = service(stopped)
    plan = review.plan(job.job_id)
    receipt = review.confirm(plan['plan_id'], plan['sha256'])
    assert receipt['purpose'] == 'controller_maintenance_only'
    exclusion = review.exclusions(receipt['review_sha256'])
    assert exclusion['job_ids'] == {job.job_id} and len(exclusion['lease_ids']) == 2
    assert retained(settings.state_root) == before
    assert private_read(job.job_dir/'status.json')['state'] == 'unknown_requires_review'
    assert 'user' not in receipt and 'payload' not in receipt


@pytest.mark.parametrize('field', ['machine', 'user', 'ou_identity', 'ssh_binding', 'package_manager', 'boot_id', 'user_runtime'])
def test_fresh_identity_health_or_boot_drift_denies_confirm_and_receipt(stopped, field):
    settings, job, facts, date = stopped
    review = service(stopped)
    plan = review.plan(job.job_id)
    old = copy.deepcopy(facts[field])
    facts[field] = 'changed'
    with pytest.raises(ControlError): review.confirm(plan['plan_id'], plan['sha256'])
    facts[field] = old
    receipt = review.confirm(plan['plan_id'], plan['sha256'])
    facts[field] = 'changed'
    with pytest.raises(ControlError): review.exclusions(receipt['review_sha256'])


def test_history_change_and_expired_window_deny(stopped):
    settings, job, facts, date = stopped
    review = service(stopped)
    plan = review.plan(job.job_id)
    receipt = review.confirm(plan['plan_id'], plan['sha256'])
    original = (job.job_dir/'execution.json').read_bytes()
    (job.job_dir/'execution.json').write_bytes(original+b' ')
    with pytest.raises(ControlError): review.exclusions(receipt['review_sha256'])
    (job.job_dir/'execution.json').write_bytes(original)
    date[0] += timedelta(hours=6)
    with pytest.raises(ControlError): review.exclusions(receipt['review_sha256'])


def test_confirmation_deadline_and_duplicate_cannot_extend_window(stopped):
    settings, job, facts, date = stopped
    review = service(stopped)
    plan = review.plan(job.job_id)
    receipt = review.confirm(plan['plan_id'], plan['sha256'])
    date[0] += timedelta(minutes=1)
    assert review.confirm(plan['plan_id'], plan['sha256']) == receipt
    date[0] += timedelta(minutes=29)
    with pytest.raises(ControlError): review.confirm(plan['plan_id'], plan['sha256'])
    assert review.exclusions(receipt['review_sha256'])['job_ids'] == {job.job_id}


def test_foreign_held_lifecycle_lock_denies_before_observation(stopped):
    import multiprocessing
    settings, job, facts, date = stopped
    ready_recv, ready_send = multiprocessing.get_context('fork').Pipe(False)
    done_recv, done_send = multiprocessing.get_context('fork').Pipe(False)
    def hold():
        with settings.lock_file.open('r') as handle:
            fcntl.flock(handle, fcntl.LOCK_EX)
            ready_send.send(True)
            done_recv.recv()
    child = multiprocessing.get_context('fork').Process(target=hold)
    child.start()
    try:
        assert ready_recv.poll(5) and ready_recv.recv()
        with pytest.raises(ControlError): service(stopped).plan(job.job_id)
    finally:
        done_send.send(True)
        child.join(5)
        if child.is_alive(): child.terminate(); child.join(5)


def test_backup_existing_same_process_lock_is_usable(stopped):
    settings, job, facts, date = stopped
    review = service(stopped)
    plan = review.plan(job.job_id)
    receipt = review.confirm(plan['plan_id'], plan['sha256'])
    with settings.lock_file.open('r') as handle:
        fcntl.flock(handle, fcntl.LOCK_EX)
        assert review.exclusions(receipt['review_sha256'])['job_ids'] == {job.job_id}


@pytest.mark.parametrize('drift', ['extra_lease', 'lease_running', 'private_mode', 'symlink', 'missing_result', 'busy_packages', 'computer_identity'])
def test_unsafe_or_unrelated_evidence_cannot_create_review(stopped, drift):
    settings, job, facts, date = stopped
    leases = settings.state_root/'legacy-setup-reservations'
    if drift == 'extra_lease':
        record = private_read(next(leases.glob('*.json')))
        record['reservation_id'] = 'e'*32
        private_create(leases/('e'*32+'.json'), record)
    elif drift == 'lease_running':
        from alt_deploy.setup_plans import private_replace
        path = next(leases.glob('*.json'))
        private_replace(path, dict(private_read(path), state='running'))
    elif drift == 'private_mode': (job.job_dir/'execution.json').chmod(0o644)
    elif drift == 'symlink':
        path = job.job_dir/'execution.json'
        other = settings.state_root/'other.json'
        path.rename(other)
        path.symlink_to(other)
    elif drift == 'missing_result':
        next((settings.state_root/'configure-runs').glob('*/result.json')).unlink()
    elif drift == 'busy_packages': facts['package_manager']['remote_execution_absent'] = False
    elif drift == 'computer_identity': facts['computer']['objects'][0]['object_guid'] = 'e'*36
    with pytest.raises(ControlError): service(stopped).plan(job.job_id)


def test_explicit_native_backup_scope_keeps_default_and_target_admission_blocked(stopped, monkeypatch):
    from alt_deploy_backup import setup_compat, setup_maintenance_review
    settings, job, facts, date = stopped
    review = service(stopped)
    plan = review.plan(job.job_id)
    receipt = review.confirm(plan['plan_id'], plan['sha256'])
    monkeypatch.setattr(setup_maintenance_review, 'MaintenanceReview', lambda settings: review)
    assert job.job_id in setup_compat.unresolved_jobs(settings.state_root)
    assert setup_compat.unresolved_jobs(settings.state_root, maintenance_review=receipt['review_sha256']) == []
    with pytest.raises(Exception):
        setup_compat.unresolved_jobs(settings.state_root, recovery_admission='a'*64,
                                     maintenance_review=receipt['review_sha256'])
    from alt_deploy.setup_retry import predecessor
    with pytest.raises(ControlError):
        predecessor(settings, job.job_id, {'execution': {'retry_policy': 'idempotent'}}, UUID)


def test_maintenance_records_are_retained_restore_history(stopped):
    from alt_deploy_backup.setup_compat import history_fingerprint
    settings, job, facts, date = stopped
    before = history_fingerprint(settings.state_root)
    review = service(stopped)
    plan = review.plan(job.job_id)
    review.confirm(plan['plan_id'], plan['sha256'])
    after = history_fingerprint(settings.state_root)
    assert before.items() <= after.items()
    assert len(after) == len(before)+2


def test_readiness_and_cli_require_explicit_scope(stopped, monkeypatch):
    from alt_deploy.controller_readiness import ControllerReadinessChecker
    from alt_deploy import setup_maintenance_review_bridge
    from alt_deploy.cli import build_parser
    settings, job, facts, date = stopped
    review = service(stopped)
    plan = review.plan(job.job_id)
    receipt = review.confirm(plan['plan_id'], plan['sha256'])
    monkeypatch.setattr(setup_maintenance_review_bridge, 'review_service', lambda settings: review)
    assert not ControllerReadinessChecker(settings).active_jobs_empty()
    assert ControllerReadinessChecker(settings, maintenance_review=receipt['review_sha256']).active_jobs_empty()
    parser = build_parser()
    assert parser.parse_args(['setup', 'jobs', 'maintenance-plan', job.job_id]).setup_job_action == 'maintenance-plan'
    assert parser.parse_args(['jobs', 'active', '--maintenance-review', receipt['review_sha256']]).maintenance_review
    assert parser.parse_args(['controller', 'readiness', '--maintenance-review', receipt['review_sha256']]).maintenance_review


def test_native_backup_flag_is_strict_and_optional():
    from alt_deploy_backup.cli import maintenance_args
    assert maintenance_args(['create']) == (['create'], None)
    assert maintenance_args(['create', '--maintenance-review', 'a'*64]) == (['create'], 'a'*64)
    from alt_deploy_backup.errors import BackupError
    for args in (['create', '--maintenance-review'], ['create', '--maintenance-review', 'wrong'],
                 ['create-recovery', 'b'*64, '--maintenance-review', 'a'*64],
                 ['delete', 'backup-20261013T120000Z-12345678', '--maintenance-review', 'a'*64]):
        with pytest.raises(BackupError): maintenance_args(args)


def test_native_capture_rehearsal_restore_preserve_review_and_unknown(stopped, tmp_path, monkeypatch):
    import shutil
    from dataclasses import replace
    from types import SimpleNamespace
    from alt_deploy_backup import setup_maintenance_review
    from alt_deploy_backup.errors import BackupError
    from support.backup_restore_sandbox import BackupSandbox
    settings, job, facts, date = stopped
    sandbox = BackupSandbox.create(tmp_path)
    sandbox.seed_complete_controller()
    root = sandbox.settings.controller_state_root
    shutil.copytree(settings.state_root, root, dirs_exist_ok=True)
    settings = SimpleNamespace(**vars(settings))
    settings.state_root, settings.jobs_dir = root, root/'jobs'
    settings.lock_file = sandbox.settings.lifecycle_lock
    review = setup_maintenance_review.MaintenanceReview(settings,
        observer=lambda job: copy.deepcopy(facts), clock=lambda: date[0])
    plan = review.plan(job.job_id)
    receipt = review.confirm(plan['plan_id'], plan['sha256'])
    monkeypatch.setattr(setup_maintenance_review, 'MaintenanceReview', lambda settings: review)
    before = retained(root)
    with pytest.raises(BackupError): sandbox.repository().create()
    scoped = replace(sandbox, settings=replace(sandbox.settings, maintenance_review=receipt['review_sha256']))
    backup_id = scoped.repository().create().backup_id
    scoped.repository().verify(backup_id, write_evidence=True)
    scoped.rehearsal_service().rehearse(backup_id)
    assert scoped.restore_service().restore(backup_id).phase == 'committed'
    assert retained(root) == before
    assert review.exclusions(receipt['review_sha256'])['job_ids'] == {job.job_id}
    with pytest.raises(BackupError): sandbox.repository().create()


@pytest.mark.parametrize('drift', ['unsafe_home', 'unresolved_user', 'realm'])
def test_runtime_user_and_realm_must_be_proven(stopped, drift):
    settings, job, facts, date = stopped
    if drift == 'unsafe_home': facts['user_runtime']['home_safe'] = False
    elif drift == 'unresolved_user': facts['user_runtime'].update(uid=None, gid=None, home_exists=False, home_safe=False)
    else: facts['observed']['domain'] = 'other.invalid'
    with pytest.raises(ControlError): service(stopped).plan(job.job_id)


def test_resolved_safe_user_does_not_require_first_login(stopped):
    settings, job, facts, date = stopped
    facts['user_runtime'].update(home_exists=False, home_safe=True)
    review = service(stopped)
    plan = review.plan(job.job_id)
    assert review.confirm(plan['plan_id'], plan['sha256'])['purpose'] == 'controller_maintenance_only'


def test_native_observer_reuses_read_only_collectors(stopped, component_service, monkeypatch):
    from alt_deploy_backup.setup_maintenance_review import MaintenanceReview
    from alt_deploy import setup, component_probe
    settings, job, facts, date = stopped
    monkeypatch.setattr(setup, 'SetupService', lambda settings: component_service[1])
    monkeypatch.setattr(component_probe, 'ComponentProbe', lambda settings: component_service[0].probe)
    review = MaintenanceReview(settings, clock=lambda: date[0])
    plan = review.plan(job.job_id)
    receipt = review.confirm(plan['plan_id'], plan['sha256'])
    assert review.exclusions(receipt['review_sha256'])['job_ids'] == {job.job_id}
