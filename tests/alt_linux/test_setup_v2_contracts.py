"""Public projections reject corrupted/unbounded files and never print raw fields."""
import pytest

from alt_deploy.setup_jobs_view import SetupJobsService
from alt_deploy.errors import ControlError
from alt_deploy.setup_plans import private_replace
from test_setup_execution import claimed, engine_for
from test_component_setup import component_service
from test_component_catalog import project


@pytest.mark.parametrize('fault', ['unexpected_field', 'raw_code', 'wrong_identity', 'wrong_component', 'large'])
def test_v2_public_contract_has_no_secret_or_unbounded_fields(component_service, fault):
    jobs, plan, settings, job = claimed(component_service)
    engine, _ = engine_for(component_service, jobs, settings)
    result = engine.execute(job.job_id)
    sentinel = 'SENTINEL-password-from-result'
    if fault == 'unexpected_field': result['stdout'] = sentinel
    elif fault == 'raw_code': result['error_code'] = sentinel
    elif fault == 'wrong_identity': result['job_id'] = 'different'
    elif fault == 'wrong_component': result['components'] = {'domain.ready': {}}
    else:
        (job.job_dir/'execution.json').write_text(sentinel*30000)
    if fault != 'large': private_replace(job.job_dir/'execution.json', result)
    with pytest.raises(ControlError) as caught: SetupJobsService(settings).status(job.job_id)
    assert sentinel not in str(caught.value) and sentinel not in str(caught.value.details)


def test_unknown_worker_without_result_is_actionable(component_service):
    jobs, _, settings, job = claimed(component_service)
    jobs.transition(job.job_id, 'unknown_requires_review', stage={'id': 'worker_identity_unverified'})
    result = SetupJobsService(settings).status(job.job_id)['job']
    assert result['state'] == 'unknown_requires_review'
    assert result['operator_action_required'] is True
    assert result['recommended_action'] == 'inspect_fresh_target_before_new_plan'


def test_missing_success_evidence_is_reported_unknown_without_rewriting_history(component_service):
    jobs, _, settings, job = claimed(component_service)
    engine, _ = engine_for(component_service, jobs, settings)
    engine.execute(job.job_id)
    (job.job_dir/'execution.json').unlink()
    result = SetupJobsService(settings).status(job.job_id)['job']
    assert result['state'] == 'unknown_requires_review'
    assert result['recorded_state'] == jobs.get(job.job_id).state == 'successful'
    assert result['error_code'] == 'setup_completion_evidence_missing'
