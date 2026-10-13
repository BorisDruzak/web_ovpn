"""The actual native backup accepts only the exact closed reserved V2 attempt."""
import copy
import json
from datetime import timedelta
from types import SimpleNamespace

import pytest

from alt_deploy.setup_jobs import SetupJobRepository, legacy_setup_execution, setup_job_execution
from alt_deploy.setup_plans import SetupPlanStore, private_create, private_read, private_replace
from alt_deploy_backup.cli import _dispatch
from alt_deploy_backup.errors import BackupError
from support.backup_restore_sandbox import BackupSandbox
from test_setup_recovery_controller_backup import fixture
from test_setup_recovery_history import NOW, RUN


def v2_history(path):
    from test_setup_recovery_history import scenario as historical
    old, paths = historical(path)
    payload = copy.deepcopy(old['payload'])
    payload.update(engine_schema_version=2, catalog_sha256='c'*64,
                   profile={'id': 'core-apps', 'version': 1}, components=[{'id': 'domain.ready', 'version': 1}])
    new = SetupPlanStore(path, clock=lambda: NOW).create(payload)
    run = private_read(paths['run'])
    run.update(plan_id=new['plan_id'], plan_sha256=new['sha256'])
    private_replace(paths['run'], run)
    paths['plan'] = path/'setup-plans'/(new['plan_id']+'.json')
    paths['index'] = path/'setup-plan-runs'/(new['plan_id']+'.json')
    private_create(paths['index'], {'run_id': RUN})
    return new, paths


@pytest.mark.parametrize('fault', [None, 'wrong_sha', 'changed_claim', 'unrelated_lease', 'same_run_foreign_lease', 'terminal', 'expired'])
def test_reserved_v2_recovery_prepares_real_backup_without_resolving_unknown(tmp_path, monkeypatch, fault):
    sandbox = BackupSandbox.create(tmp_path)
    sandbox.seed_complete_controller()
    root = sandbox.settings.controller_state_root
    root.chmod(0o700)
    (root/'jobs').chmod(0o700)
    from test_setup_recovery_planning import UUID
    monkeypatch.setattr('test_setup_recovery_planning.historical_scenario', v2_history)
    producer, service, plan, claim, credentials, paths, calls = fixture(root)
    service.settings.jobs_dir = root/'jobs'
    service.settings.service_user = 'altserver'
    original = private_read(paths['plan'])
    jobs = SetupJobRepository(service.settings, clock=lambda: NOW+timedelta(seconds=1))
    job = jobs.submit(original, operation='full_setup')
    jobs.claim(job.job_id, {'boot_id':'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee', 'pid':123,'start_ticks':1})
    jobs.transition(job.job_id, 'running')
    private_create(job.job_dir/'execution.json', {'schema_version':2, 'job_id':job.job_id,
        'plan_sha256': original['sha256'], 'legacy_error_run_id':RUN})
    run = private_read(paths['run'])
    # Both nested legacy leases participate in ordinary maintenance exclusion.
    with pytest.raises(RuntimeError):
        with setup_job_execution(service.settings, job.job_id, original), legacy_setup_execution(service.settings, UUID, original['payload']['machine']['hostname'], operation='full_setup', run_id=RUN):
            with legacy_setup_execution(service.settings, UUID, original['payload']['machine']['hostname'], operation='configure', run_id=run['configuration_run_id']):
                raise RuntimeError('synthetic stopped execution')
    jobs.transition(job.job_id, 'unknown_requires_review')
    with pytest.raises(BackupError) as blocked:
        sandbox.repository().create()
    assert blocked.value.code == 'backup_active_jobs'
    old_bytes = (job.job_dir/'status.json').read_bytes()
    lease_bytes = {p.name:p.read_bytes() for p in (root/'legacy-setup-reservations').iterdir()}
    monkeypatch.setattr('alt_deploy.setup_recovery_backup_admission.datetime',
        SimpleNamespace(fromisoformat=__import__('datetime').datetime.fromisoformat,
                        now=lambda *a:NOW+timedelta(days=1, minutes=1)))
    def native(command, **kwargs):
        operation = command[3]
        identifier = command[4] if len(command) == 5 else None
        if operation == 'create-recovery':
            if fault == 'wrong_sha': identifier = 'f'*64
            elif fault == 'changed_claim':
                path = service.attempts.claim_path(plan['payload']['failed_run_id'], plan['payload']['computer_guid'])
                document = private_read(path); document['plan_sha256'] = 'f'*64
                private_replace(path, document)
            elif fault in ('unrelated_lease', 'same_run_foreign_lease'):
                path = next((root/'legacy-setup-reservations').iterdir())
                document = private_read(path)
                document.update(reservation_id='f'*32, hostname='alt-other', machine_uuid='22222222-2222-2222-2222-222222222222')
                if fault == 'unrelated_lease': document['run_id'] = 'e'*32
                private_create(path.parent/('f'*32+'.json'), document)
            elif fault == 'terminal':
                private_create(service.attempts._path(plan['payload']['failed_run_id'], plan['payload']['computer_guid'], '.receipt.json'), {'status':'failed'})
            elif fault == 'expired':
                monkeypatch.setattr('alt_deploy.setup_recovery_backup_admission.datetime',
                    SimpleNamespace(fromisoformat=__import__('datetime').datetime.fromisoformat,
                                    now=lambda *a:NOW+timedelta(days=2)))
        # All native create/verify/rehearse operations use the real backup package.
        try:
            return 0, json.dumps(_dispatch(operation, identifier, sandbox.settings)), ''
        except BackupError as exc:
            native_errors.append((operation, exc.code, exc.message))
            raise
    native_errors = []
    producer.runner = native
    if fault:
        from alt_deploy.errors import ControlError
        with pytest.raises(ControlError) as rejected:
            producer.prepare(plan['payload'])
        assert rejected.value.code == 'recovery_controller_backup_failed'
        assert native_errors[0][0] == 'create-recovery'
        assert (job.job_dir/'status.json').read_bytes() == old_bytes
        assert not (root/'setup-job-reviews').exists()
        return
    try:
        receipt = producer.prepare(plan['payload'])
    except Exception:
        pytest.fail(str(native_errors))
    assert receipt['backup_id'].startswith('backup-')
    assert producer.verify(plan['payload']) == receipt
    assert (job.job_dir/'status.json').read_bytes() == old_bytes
    assert {p.name:p.read_bytes() for p in (root/'legacy-setup-reservations').iterdir()} == lease_bytes
    assert not (root/'setup-job-reviews').exists()
    with pytest.raises(BackupError):
        sandbox.repository().create()


@pytest.mark.parametrize('fault', [None, 'relation', 'predecessor'])
def test_native_successor_snapshot_rechecks_current_lineage(tmp_path, monkeypatch, fault):
    from alt_deploy.setup_recovery_attempt_context import with_context
    from alt_deploy.setup_recovery import RecoveryAttemptStore
    from alt_deploy.setup_recovery_credential import RecoveryCredentialStore
    from alt_deploy.setup_recovery_controller_backup import RecoveryControllerBackup
    from test_setup_recovery_credential import codec_fixture
    from test_setup_recovery_successor import scenario as successor_fixture
    from alt_deploy.errors import ControlError
    sandbox = BackupSandbox.create(tmp_path)
    sandbox.seed_complete_controller()
    root = sandbox.settings.controller_state_root
    root.chmod(0o700); (root/'jobs').chmod(0o700)
    monkeypatch.setattr('test_setup_recovery_planning.historical_scenario', v2_history)
    admission, legacy, pair, operator, paths = successor_fixture(root)
    context = admission.prepare(**pair, predecessor_sha=operator['sha256'])
    # The startup fixture embeds a synthetic workstation filesystem beside its
    # controller files. It is not controller state and must not enter the archive.
    (root/'workstation').rename(tmp_path/'synthetic-target-workstation')
    old = legacy.plans.load(operator['payload']['recovery']['plan_id'], operator['payload']['recovery']['sha256'])
    raw_files = legacy.history.load(RUN)['raw_files']
    original = private_read(paths['plan'])
    # The combined startup fixture nests controller state under /controller.
    # Copy its bookkeeping into the native sandbox's canonical state location.
    import shutil
    shutil.copytree(legacy.settings.state_root, root, dirs_exist_ok=True)
    canonical_settings = copy.copy(legacy.settings); canonical_settings.state_root = root
    settings = with_context(canonical_settings, context)
    settings.jobs_dir, settings.service_user = root/'jobs', 'altserver'
    attempts = RecoveryAttemptStore.for_settings(settings, clock=legacy.clock)
    payload = copy.deepcopy(old['payload']); payload['snapshot']['recovery_attempt_context'] = context
    from alt_deploy.setup_recovery import RecoveryPlanStore
    plan = RecoveryPlanStore(root, clock=legacy.clock).create(payload)
    attempts.reserve(plan['plan_id'], plan['sha256'], raw_files)
    credentials = RecoveryCredentialStore(root, codec=codec_fixture(root)[0], attempts=attempts)
    credentials.create(**pair)
    jobs = SetupJobRepository(settings, clock=lambda:NOW+timedelta(seconds=1))
    job = jobs.submit(original, operation='full_setup')
    jobs.claim(job.job_id, {'boot_id':'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee','pid':123,'start_ticks':1})
    jobs.transition(job.job_id, 'running'); jobs.transition(job.job_id, 'unknown_requires_review')
    private_create(job.job_dir/'execution.json', {'schema_version':2,'job_id':job.job_id,
        'plan_sha256':original['sha256'],'legacy_error_run_id':RUN})
    monkeypatch.setattr('alt_deploy.setup_recovery_backup_admission.datetime',
        SimpleNamespace(fromisoformat=__import__('datetime').datetime.fromisoformat,
                        now=lambda *a:NOW+timedelta(days=1, minutes=1)))
    observed_codes = []
    operations = []
    def native(command, **kwargs):
        operation, identifier = command[3], command[4] if len(command)==5 else None
        operations.append(operation)
        if operation == 'create-recovery':
            if fault == 'relation':
                from alt_deploy.setup_plans import digest
                (root/'setup-recovery-successor-relations'/(digest(pair)+'.json')).unlink()
            elif fault == 'predecessor':
                from alt_deploy.setup_plans import digest
                (root/'setup-recovery-attempts'/(digest(pair)+'.operator-failed.json')).unlink()
        try:
            return 0, json.dumps(_dispatch(operation, identifier, sandbox.settings)), ''
        except BackupError as exc:
            observed_codes.append((exc.code, exc.message))
            raise
    # The preceding factory covers real successor admission; this producer isolates
    # the native lineage boundary after the caller's already fresh snapshot.
    producer = RecoveryControllerBackup(settings, credentials=credentials,
        fresh_check=lambda p:copy.deepcopy(payload['snapshot']), runner=native)
    assert len(SetupJobRepository(producer.settings).list(payload['machine_uuid'])) == 1
    if fault:
        with pytest.raises(ControlError): producer.prepare(payload)
        assert [c for c, _ in observed_codes] == ['backup_preflight_failed']
        assert not list(sandbox.settings.backup_root.glob('backup-*'))
    else:
        try:
            assert producer.prepare(payload)['backup_id'].startswith('backup-')
        except ControlError:
            pytest.fail(str(observed_codes))
        assert operations[1] == 'create-recovery'
    assert jobs.get(job.job_id).state == 'unknown_requires_review'
