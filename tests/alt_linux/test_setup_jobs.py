"""Durable claims and schema dispatch preserve legacy provision history."""
import copy
from datetime import datetime, timedelta, timezone

import pytest

from alt_deploy.setup_jobs import SetupJobRepository
from alt_deploy.jobs import JobRepository
from alt_deploy.errors import ControlError
from alt_deploy.setup_plans import private_read, private_replace
from test_component_setup import component_service
from test_component_catalog import project
from test_component_verification import UUID


def jobs_fixture(component_service):
    service, setup, *_ = component_service
    setup.settings.jobs_dir = setup.settings.state_root/'jobs'
    setup.settings.service_user = 'altserver'
    setup.settings.service_group = 'altserver'
    setup.settings.state_root.chmod(0o700)
    return SetupJobRepository(setup.settings, clock=service.clock), service.plan(UUID, 'software.onlyoffice'), setup.settings


def test_job_claim_consumes_plan_once_and_is_readable_by_shared_repository(component_service):
    jobs, plan, settings = jobs_fixture(component_service)
    job = jobs.submit(plan, operation='component')
    assert job.state == 'queued'
    assert job.status['schema_version'] == 2 and job.status['kind'] == 'setup'
    assert JobRepository(settings).get(job.job_id).request['plan'] == plan
    assert jobs.submit(plan, operation='component').job_id == job.job_id
    identity = {'boot_id': 'a'*8+'-bbbb-cccc-dddd-'+'e'*12, 'pid': 1234, 'start_ticks': 100}
    claimed = jobs.claim(job.job_id, identity)
    assert claimed.status['claimed'] is True
    with pytest.raises(ControlError): jobs.claim(job.job_id, identity)
    jobs.transition(job.job_id, 'running')
    jobs.transition(job.job_id, 'verifying')
    jobs.transition(job.job_id, 'successful')
    assert jobs.submit(plan, operation='component').job_id == job.job_id
    with pytest.raises(ControlError): jobs.claim(job.job_id, identity)
    assert jobs.get(job.job_id).request['plan'] == plan


@pytest.mark.parametrize('boundary', ['claim', 'reservation', 'request', 'status'])
def test_reservation_crash_boundaries_never_revive_consumed_plan(component_service, boundary, monkeypatch):
    from alt_deploy import setup_jobs
    jobs, plan, settings = jobs_fixture(component_service)
    original = setup_jobs.publish
    fired = []
    def crash(path, payload, *, create=False):
        original(path, payload, create=create)
        if ((boundary == 'claim' and path.parent.name == 'setup-job-plan-claims')
                or (boundary == 'reservation' and path.parent.name == 'setup-job-reservations')
                or (boundary == 'request' and path.name == 'request.json')
                or (boundary == 'status' and path.name == 'status.json')) and not fired:
            fired.append(True)
            raise KeyboardInterrupt('synthetic process termination')
    monkeypatch.setattr(setup_jobs, 'publish', crash)
    with pytest.raises(KeyboardInterrupt): jobs.submit(plan, operation='component')
    monkeypatch.setattr(setup_jobs, 'publish', original)
    restored = SetupJobRepository(settings, clock=jobs.clock)
    if boundary == 'status':
        result = restored.submit(plan, operation='component')
        assert result.state == 'queued' and result.status['claimed'] is False
    else:
        with pytest.raises(ControlError) as caught: restored.submit(plan, operation='component')
        assert caught.value.code == 'setup_job_admission_requires_review'
    assert len(list((settings.state_root/'setup-job-plan-claims').glob('*.json'))) == 1


def test_conflicting_uuid_hostname_and_computer_guid_reservations(component_service):
    jobs, plan, _ = jobs_fixture(component_service)
    jobs.submit(plan, operation='component')
    for conflict in ('uuid', 'hostname', 'computer_guid'):
        different = copy.deepcopy(plan)
        # Keep exactly one identity equal and change the other two.
        if conflict != 'uuid': different['payload']['machine']['uuid'] = '2'*8+'-2222-2222-2222-'+'2'*12
        if conflict != 'hostname': different['payload']['machine']['hostname'] = 'alt-other'
        if conflict != 'computer_guid': different['payload']['computer']['objects'][0]['object_guid'] = 'd'*8+'-dddd-dddd-dddd-'+'d'*12
        service = component_service[0]
        different = service.plans.create(different['payload'])
        with pytest.raises(ControlError) as caught: jobs.submit(different, operation='component')
        assert caught.value.code == 'setup_job_identity_reserved'


def test_job_request_or_status_corruption_is_not_interpreted_as_provision(component_service):
    jobs, plan, settings = jobs_fixture(component_service)
    job = jobs.submit(plan, operation='component')
    path = job.job_dir/'status.json'
    status = private_read(path)
    status['schema_version'] = 1
    private_replace(path, status)
    with pytest.raises(ControlError): JobRepository(settings).get(job.job_id)


def test_review_and_waiting_states_remain_active_and_are_not_retained_as_provision(component_service):
    from alt_deploy.job_retention import JobRetentionManager
    jobs, plan, settings = jobs_fixture(component_service)
    job = jobs.submit(plan, operation='component')
    jobs.claim(job.job_id, {'boot_id': 'a'*8+'-bbbb-cccc-dddd-'+'e'*12, 'pid': 1234, 'start_ticks': 100})
    jobs.transition(job.job_id, 'running')
    jobs.transition(job.job_id, 'unknown_requires_review')
    assert JobRepository(settings).active_for_machine(UUID).job_id == job.job_id
    action, preserved = JobRetentionManager(settings)._classify(jobs.get(job.job_id),
        now=datetime.now(timezone.utc)+timedelta(days=365), retention_days=30, archive_after_days=14)
    assert action is None
    assert preserved['reason'] == 'setup_evidence_retained'


def test_mixed_history_does_not_enter_legacy_reconcile_or_worker(component_service, monkeypatch):
    from alt_deploy.job_reconcile import JobReconciler
    from alt_deploy.job_stages import JobStageManager
    from alt_deploy.worker import run_job
    from test_jobs import provision_request
    jobs, plan, settings = jobs_fixture(component_service)
    setup_job = jobs.submit(plan, operation='component')
    legacy = JobRepository(settings).create(provision_request('22222222-2222-3333-4444-555555555555'))
    assert len(JobRepository(settings).list()) == 2
    reconciler = JobReconciler(settings)
    result = reconciler.reconcile()
    assert result['checked'] == 1 and result['changed'][0]['job_id'] == legacy.job_id
    assert jobs.get(setup_job.job_id).state == 'queued'
    with pytest.raises(ControlError) as caught: run_job(setup_job.job_id, settings, object())
    assert caught.value.code == 'setup_job_worker_required'
    with pytest.raises(ControlError): JobStageManager(settings).advance(setup_job.job_id, 'launching')
    with pytest.raises(ControlError): JobRepository(settings).update(setup_job.job_id, state='failed')


@pytest.mark.parametrize('tamper', ['symlink', 'ancestor', 'large', 'mode', 'duplicate', 'request', 'claim_removed', 'reservation_removed', 'orphan_reservation'])
def test_unsafe_or_inconsistent_admission_blocks_dispatch(component_service, tamper):
    jobs, plan, settings = jobs_fixture(component_service)
    job = jobs.submit(plan, operation='component')
    status = job.job_dir/'status.json'
    if tamper == 'symlink':
        original = status.with_name('original.json')
        status.rename(original)
        status.symlink_to(original)
    elif tamper == 'ancestor':
        original = job.job_dir.with_name('original')
        job.job_dir.rename(original)
        job.job_dir.symlink_to(original, target_is_directory=True)
    elif tamper == 'large': status.write_text('x'*524289)
    elif tamper == 'mode': status.chmod(0o644)
    elif tamper == 'duplicate': status.write_text('{"schema_version":2,"schema_version":1}')
    elif tamper == 'request':
        request = private_read(job.job_dir/'request.json')
        request['plan']['payload']['machine']['hostname'] = 'alt-other'
        private_replace(job.job_dir/'request.json', request)
    elif tamper == 'claim_removed': (jobs.claims/(plan['sha256']+'.json')).unlink()
    elif tamper == 'reservation_removed': (jobs.reservations/(job.job_id+'.json')).unlink()
    elif tamper == 'orphan_reservation':
        from alt_deploy.setup_jobs import publish
        publish(jobs.reservations/'orphan.json', private_read(jobs.reservations/(job.job_id+'.json')), create=True)
    with pytest.raises(ControlError):
        jobs.claim(job.job_id, {'boot_id': 'a'*8+'-bbbb-cccc-dddd-'+'e'*12, 'pid': 1234, 'start_ticks': 100})


def test_expiration_and_bad_operation_reject_before_consuming_plan(component_service):
    jobs, plan, settings = jobs_fixture(component_service)
    with pytest.raises(ControlError): jobs.submit(plan, operation='recovery')
    component_service[5][0] += timedelta(minutes=30)
    with pytest.raises(ControlError) as caught: jobs.submit(plan, operation='component')
    assert caught.value.code == 'setup_plan_expired'
    assert not list(jobs.claims.glob('*.json'))


def test_publication_syncs_parent_directories(component_service, monkeypatch):
    from alt_deploy import setup_jobs
    jobs, plan, _ = jobs_fixture(component_service)
    real_sync = setup_jobs.fsync_directory
    synced = []
    def sync(path):
        synced.append(path)
        real_sync(path)
    monkeypatch.setattr(setup_jobs, 'fsync_directory', sync)
    job = jobs.submit(plan, operation='component')
    assert jobs.claims in synced and jobs.reservations in synced
    assert jobs.settings.jobs_dir in synced and synced.count(job.job_dir) == 2
