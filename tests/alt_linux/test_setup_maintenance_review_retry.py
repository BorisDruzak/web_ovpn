"""Maintenance shares native reviewed-predecessor semantics with backup admission."""
import copy

import pytest

from alt_deploy.component_setup import ComponentPlanStore
from alt_deploy.errors import ControlError
from alt_deploy.setup_plans import private_read, private_replace
from alt_deploy.setup_retry import predecessor, reviewed_jobs
from alt_deploy.setup_worker import process_identity
from test_component_catalog import project
from test_component_setup import component_service
from test_setup_maintenance_review import stopped, service, retained
from test_setup_queue_review import queued


def retry_chain(queued, component_service, *, state='successful'):
    settings, old, full, facts, date, jobs = queued
    jobs.claim(full.job_id, process_identity(settings))
    jobs.transition(full.job_id, 'failed')
    payload = copy.deepcopy(full.request['plan']['payload'])
    payload.pop('engine_schema_version')
    payload['component'] = next(c for c in payload['components'] if c['id'] == 'software.onlyoffice')
    payload['observed'] = copy.deepcopy(component_service[4])
    store = ComponentPlanStore(settings.state_root, clock=lambda: date[0])
    interrupted = jobs.submit(store.create(payload), operation='component')
    jobs.claim(interrupted.job_id, process_identity(settings))
    jobs.transition(interrupted.job_id, 'unknown_requires_review')
    payload['predecessor_job'] = predecessor(settings, interrupted.job_id, payload['component'], interrupted.machine_uuid)
    successor = jobs.submit(store.create(payload), operation='component')
    if state != 'queued':
        jobs.claim(successor.job_id, process_identity(settings))
        if state == 'successful':
            jobs.transition(successor.job_id, 'verifying')
        jobs.transition(successor.job_id, state)
    return interrupted, successor


def test_maintenance_backup_and_readiness_accept_completed_native_retry(queued, component_service, monkeypatch):
    from alt_deploy import setup_maintenance_review_bridge
    from alt_deploy.controller_readiness import ControllerReadinessChecker
    from alt_deploy_backup import setup_compat, setup_maintenance_review
    settings, old, _, facts, date, jobs = queued
    interrupted, successor = retry_chain(queued, component_service)
    assert interrupted.job_id in reviewed_jobs(settings)
    before = retained(settings.state_root)
    review = service((settings, old, facts, date))
    plan = review.plan(old.job_id)
    receipt = review.confirm(plan['plan_id'], plan['sha256'])
    assert review.exclusions(receipt['review_sha256'])['job_ids'] == {old.job_id}
    monkeypatch.setattr(setup_maintenance_review, 'MaintenanceReview', lambda settings: review)
    monkeypatch.setattr(setup_maintenance_review_bridge, 'review_service', lambda settings: review)
    assert setup_compat.unresolved_jobs(settings.state_root, maintenance_review=receipt['review_sha256']) == []
    assert ControllerReadinessChecker(settings, maintenance_review=receipt['review_sha256']).active_jobs_empty()
    assert old.job_id in setup_compat.unresolved_jobs(settings.state_root)
    assert not ControllerReadinessChecker(settings).active_jobs_empty()
    assert retained(settings.state_root) == before
    assert jobs.get(interrupted.job_id).state == 'unknown_requires_review'
    assert jobs.get(successor.job_id).state == 'successful'


@pytest.mark.parametrize('state', ['queued', 'running', 'unknown_requires_review'])
def test_maintenance_still_blocks_active_retry_successor(queued, component_service, state):
    settings, old, _, facts, date, _ = queued
    retry_chain(queued, component_service, state=state)
    with pytest.raises(ControlError):
        service((settings, old, facts, date)).plan(old.job_id)


@pytest.mark.parametrize('fault', ['missing_review', 'tampered_review', 'changed_predecessor'])
def test_maintenance_requires_intact_native_review_link(queued, component_service, fault):
    settings, old, _, facts, date, _ = queued
    interrupted, _ = retry_chain(queued, component_service)
    path = settings.state_root/'setup-job-reviews'/(interrupted.job_id+'.json')
    if fault == 'missing_review':
        path.unlink()
    elif fault == 'tampered_review':
        private_replace(path, dict(private_read(path), successor_plan_sha256='f'*64))
    else:
        status = private_read(interrupted.job_dir/'status.json')
        status['stage_history'][-1]['stage'] = status['stage'] = 'changed_review_evidence'
        private_replace(interrupted.job_dir/'status.json', status)
    with pytest.raises(ControlError):
        service((settings, old, facts, date)).plan(old.job_id)


def test_existing_maintenance_receipt_rejects_later_retry_history_change(queued, component_service):
    settings, old, _, facts, date, jobs = queued
    interrupted, successor = retry_chain(queued, component_service)
    review = service((settings, old, facts, date))
    plan = review.plan(old.job_id)
    receipt = review.confirm(plan['plan_id'], plan['sha256'])
    path = successor.job_dir/'status.json'
    original = path.read_bytes()
    path.write_bytes(original+b' ')
    with pytest.raises(ControlError):
        review.exclusions(receipt['review_sha256'])
    path.write_bytes(original)
    assert review.exclusions(receipt['review_sha256'])['job_ids'] == {old.job_id}
