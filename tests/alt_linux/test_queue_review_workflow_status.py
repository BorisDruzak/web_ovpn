"""Retained queue reviews bind admission status before post-login evolution."""
import copy
from dataclasses import replace
from types import SimpleNamespace

import pytest

from alt_deploy.setup_plans import digest
from test_setup_phases import phase_job
from test_full_workflow_binding import full_setup
from test_component_catalog import project


def admission_status(job):
    request = job.request
    created = job.status['stage_history'][0]['at']
    return {'schema_version': 2, 'kind': 'setup', 'operation': request['operation'],
        'job_id': job.job_id, 'machine_uuid': request['machine_uuid'],
        'plan_id': request['plan']['plan_id'], 'plan_sha256': request['plan']['sha256'],
        'request_sha256': digest(request), 'admission_sequence': request['admission_sequence'],
        'state': 'queued', 'stage': 'created', 'stage_history': [job.status['stage_history'][0]],
        'created_at': created, 'updated_at': created, 'claimed': False, 'process_identity': None}


def test_post_login_workflow_does_not_change_retained_initial_status_hash(phase_job):
    from alt_deploy_backup.setup_queue_review import initial_candidate_status
    _, jobs, job, *_ = phase_job
    before = {p: p.read_bytes() for p in job.job_dir.rglob('*') if p.is_file()}
    assert 'workflow' in job.status
    assert digest(initial_candidate_status(job, phase_job[6].settings)) == digest(admission_status(job))
    assert all(p.read_bytes() == value for p, value in before.items())
    assert jobs.get(job.job_id).status == job.status


def test_malformed_workflow_cannot_be_discarded_to_pass_history_validation(phase_job):
    from alt_deploy_backup.setup_queue_review import initial_candidate_status
    job = phase_job[2]
    status = copy.deepcopy(job.status)
    status['workflow']['system_result_sha256'] = 'invalid'
    with pytest.raises(ValueError):
        initial_candidate_status(SimpleNamespace(request=job.request, status=status), phase_job[6].settings)


def test_other_status_changes_still_fail_the_original_hash(phase_job):
    from alt_deploy.errors import ControlError
    from alt_deploy_backup.setup_queue_review import initial_candidate_status
    job = phase_job[2]
    status = copy.deepcopy(job.status)
    status['request_sha256'] = 'f' * 64
    changed = replace(job, status=status)
    with pytest.raises(ControlError):
        initial_candidate_status(changed, phase_job[6].settings)


@pytest.mark.parametrize('fault', ['valid_but_wrong_digest', 'missing_phase_authority'])
def test_workflow_authority_is_checked_before_reconstructing_initial_status(phase_job, fault):
    from alt_deploy.errors import ControlError
    from alt_deploy_backup.setup_queue_review import initial_candidate_status
    store, _, original, *_ = phase_job
    job = replace(original, status=copy.deepcopy(original.status))
    settings = phase_job[6].settings
    if fault == 'valid_but_wrong_digest':
        job.status['workflow']['system_result_sha256'] = 'f' * 64
    else:
        for directory in settings.state_root.glob('setup-phase-*'):
            if directory.is_dir():
                for path in directory.glob(job.job_id + '--*.json'):
                    path.unlink()
    with pytest.raises((ControlError, ValueError)):
        initial_candidate_status(job, settings)
