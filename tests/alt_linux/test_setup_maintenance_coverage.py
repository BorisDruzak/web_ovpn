"""Complete controller-only coverage never grants target or queue execution."""
import copy
from datetime import timedelta
from pathlib import Path
import shutil

import pytest

from alt_deploy.errors import ControlError
from alt_deploy.setup_jobs import SetupJobRepository
from alt_deploy.setup_plans import digest, private_read, private_replace
from test_component_catalog import project
from test_component_setup import component_service
from test_setup_maintenance_review import stopped, retained
from test_setup_closed_failure import make_partial_failure, backend
from test_setup_partial_observation import observer


@pytest.fixture
def mixed(stopped, tmp_path, project, monkeypatch):
    import test_setup_service, test_component_setup, test_component_verification, test_setup_closed_failure
    settings, joined, joined_facts, date = stopped
    second_uuid = '22222222-3333-4444-5555-666666666666'
    with monkeypatch.context() as patch:
        for module in (test_setup_service, test_component_setup, test_component_verification, test_setup_closed_failure):
            patch.setattr(module, 'UUID', second_uuid)
        fixture = component_service.__wrapped__(tmp_path/'second', project, patch)
        fixture[2].hostname = 'alt-t2-pc2'
        fixture[2].raw['hostname'] = 'alt-t2-pc2'
        fixture[4]['machine']['hostname'] = 'alt-t2-pc2'
        partial = make_partial_failure(fixture, patch, configuration_id='e'*32)
        partial_observer, *_ = observer(partial)
        partial_facts = partial_observer.observe(backend('setup_closed_failure').ClosedFailureEvidence(partial[0].settings).load(partial[1].job_id), mode='partial_ad')
    second_root = partial[0].settings.state_root
    # Merge two independently validated fixture histories, assigning the second
    # admission its native globally unique sequence and matching request digest.
    job = partial[1]
    request = private_read(job.job_dir/'request.json'); request['admission_sequence'] = 2
    private_replace(job.job_dir/'request.json', request)
    status = private_read(job.job_dir/'status.json'); status.update(admission_sequence=2, request_sha256=digest(request))
    private_replace(job.job_dir/'status.json', status)
    for directory in ('setup-job-plan-claims', 'setup-job-reservations'):
        for path in (second_root/directory).glob('*.json'):
            value = private_read(path); value.update(admission_sequence=2, request_sha256=digest(request))
            private_replace(path, value)
    for name in ('jobs', 'setup-plans', 'setup-runs', 'setup-plan-runs', 'configure-runs', 'domain-assignments',
                 'legacy-setup-reservations', 'setup-job-plan-claims', 'setup-job-reservations'):
        shutil.copytree(second_root/name, settings.state_root/name, dirs_exist_ok=True)
    SetupJobRepository(settings)._check_admissions()
    settings._partial_fixture = partial  # Reuse real retained fixture provenance in successor/queue integration tests.
    facts = {joined.job_id: joined_facts, job.job_id: partial_facts}
    return settings, joined, SetupJobRepository(settings).get(job.job_id), facts, date


def coverage(mixed):
    settings, _, _, facts, date = mixed
    return backend('setup_maintenance_coverage').MaintenanceCoverage(settings,
        observer=lambda job: copy.deepcopy(facts[job.job_id]), clock=lambda: date[0])


def test_joined_and_partial_failures_have_exact_maintenance_coverage(mixed):
    settings, joined, partial, _, date = mixed
    before = retained(settings.state_root)
    review = coverage(mixed)
    plan = review.plan()
    assert plan['schema_version'] == 2
    receipt = review.confirm(plan['plan_id'], plan['sha256'])
    assert receipt['purpose'] == 'controller_maintenance_only'
    exclusion = review.exclusions(plan['sha256'])
    assert exclusion['job_ids'] == {joined.job_id, partial.job_id} and len(exclusion['lease_ids']) == 4
    assert retained(settings.state_root) == before
    assert SetupJobRepository(settings).get(joined.job_id).state == 'unknown_requires_review'
    assert SetupJobRepository(settings).get(partial.job_id).state == 'unknown_requires_review'


@pytest.mark.parametrize('fault', ['running_lease', 'foreign_lease', 'unclaimed_queue', 'changed_history', 'changed_evidence'])
def test_foreign_or_running_lease_is_not_covered(mixed, fault):
    settings, joined, partial, facts, date = mixed
    review = coverage(mixed)
    plan = review.plan()
    if fault in ('running_lease', 'foreign_lease'):
        path = next((settings.state_root/'legacy-setup-reservations').glob('*.json'))
        value = private_read(path)
        if fault == 'running_lease': value['state'] = 'running'
        else: value['machine_uuid'] = '33333333-4444-5555-6666-777777777777'
        private_replace(path, value)
    elif fault == 'unclaimed_queue':
        payload = copy.deepcopy(partial.request['plan']['payload'])
        payload['machine'].update(uuid='33333333-4444-5555-6666-777777777777', hostname='alt-t3-pc3')
        payload['request'].update(machine_uuid=payload['machine']['uuid'], final_hostname=payload['machine']['hostname'])
        from alt_deploy.setup_plans import SetupPlanStore
        candidate = SetupPlanStore(settings.state_root, clock=lambda: date[0]).create(payload)
        SetupJobRepository(settings, clock=lambda: date[0]).submit(candidate, operation='full_setup')
    elif fault == 'changed_history':
        path = joined.job_dir/'execution.json'; path.write_bytes(path.read_bytes()+b' ')
    else: facts[partial.job_id]['partial_local']['native']['clock_synchronized'] = False
    with pytest.raises(ControlError): review.confirm(plan['plan_id'], plan['sha256'])


def test_confirmation_is_nonrenewable_and_archival_records_remain_valid(mixed):
    settings, _, _, _, date = mixed
    review = coverage(mixed)
    plan = review.plan(); receipt = review.confirm(plan['plan_id'], plan['sha256'])
    date[0] += timedelta(minutes=1)
    assert review.confirm(plan['plan_id'], plan['sha256']) == receipt
    date[0] += timedelta(hours=6)
    backend('setup_maintenance_review').validate_artifacts(settings.state_root)
    with pytest.raises(ControlError): review.exclusions(plan['sha256'])


def test_late_closed_failure_invalidates_coverage(mixed, tmp_path):
    settings, _, partial, _, _ = mixed
    root = settings.state_root
    closed = backend('setup_closed_failure').ClosedFailureEvidence(settings).load(partial.job_id)
    paths = [partial.job_dir, root/'setup-job-plan-claims'/(partial.status['plan_sha256']+'.json'),
             root/'setup-job-reservations'/(partial.job_id+'.json')]
    paths += [root/'legacy-setup-reservations'/(identifier+'.json') for identifier in closed['lease_ids']]
    holding = tmp_path/'late'; holding.mkdir()
    for index, path in enumerate(paths): path.rename(holding/str(index))
    review = coverage(mixed)
    plan = review.plan()
    assert plan['covered_jobs'] == 1
    for index, path in enumerate(paths): (holding/str(index)).rename(path)
    with pytest.raises(ControlError): review.confirm(plan['plan_id'], plan['sha256'])


def test_partial_maintenance_receipt_cannot_admit_queue(mixed):
    settings, joined, _, facts, date = mixed
    review = coverage(mixed)
    plan = review.plan(); review.confirm(plan['plan_id'], plan['sha256'])
    from alt_deploy_backup.setup_queue_review import QueueAdmissionReview
    queue = QueueAdmissionReview(settings, observer=lambda job: facts[job.job_id], clock=lambda: date[0])
    with pytest.raises(ControlError): queue.confirm(plan['plan_id'], plan['sha256'])


def test_changed_validator_dependency_denies_existing_coverage(mixed, monkeypatch):
    review = coverage(mixed)
    plan = review.plan()
    original = review._validators()
    changed = dict(original, **{'partial_local_probe.py': 'f'*64})
    monkeypatch.setattr(review, '_validators', lambda: changed)
    with pytest.raises(ControlError): review.confirm(plan['plan_id'], plan['sha256'])


def test_native_capture_rehearsal_restore_preserve_complete_coverage(mixed, tmp_path, monkeypatch):
    from dataclasses import replace
    from types import SimpleNamespace
    from alt_deploy_backup import setup_maintenance_review
    from alt_deploy_backup.errors import BackupError
    from support.backup_restore_sandbox import BackupSandbox
    settings, joined, partial, facts, date = mixed
    sandbox = BackupSandbox.create(tmp_path)
    sandbox.seed_complete_controller()
    root = sandbox.settings.controller_state_root
    shutil.copytree(settings.state_root, root, dirs_exist_ok=True)
    settings = SimpleNamespace(**vars(settings))
    settings.state_root, settings.jobs_dir, settings.lock_file = root, root/'jobs', sandbox.settings.lifecycle_lock
    review = backend('setup_maintenance_coverage').MaintenanceCoverage(settings,
        observer=lambda job: copy.deepcopy(facts[job.job_id]), clock=lambda: date[0])
    plan = review.plan(); receipt = review.confirm(plan['plan_id'], plan['sha256'])
    monkeypatch.setattr(setup_maintenance_review, 'MaintenanceReview', lambda settings: review)
    before = retained(root)
    with pytest.raises(BackupError): sandbox.repository().create()
    scoped = replace(sandbox, settings=replace(sandbox.settings, maintenance_review=receipt['review_sha256']))
    backup_id = scoped.repository().create().backup_id
    scoped.repository().verify(backup_id, write_evidence=True)
    scoped.rehearsal_service().rehearse(backup_id)
    assert scoped.restore_service().restore(backup_id).phase == 'committed'
    assert retained(root) == before
    assert review.exclusions(receipt['review_sha256'])['job_ids'] == {joined.job_id, partial.job_id}


def test_all_closed_cli_is_mutually_exclusive_and_uses_native_service(component_service, monkeypatch):
    from alt_deploy import cli, setup_maintenance_review_bridge
    from test_setup_jobs_cli import invoke
    from types import SimpleNamespace
    calls = []
    monkeypatch.setattr(setup_maintenance_review_bridge, 'review_service',
        lambda settings: SimpleNamespace(plan_all_closed=lambda: (calls.append('all') or {'schema_version': 2})))
    assert invoke(component_service[0].settings, 'maintenance-plan', '--all-closed') == (0, {'schema_version': 2})
    assert calls == ['all']
    for args in ([], ['job-example', '--all-closed']):
        with pytest.raises(SystemExit): cli.build_parser().parse_args(['setup', 'jobs', 'maintenance-plan', *args])
