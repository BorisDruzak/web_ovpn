"""Read-only public phase progress never exposes protected execution values."""
import copy
import json

import pytest

from alt_deploy.errors import ControlError
from alt_deploy.locks import exclusive_lock
from alt_deploy.setup_jobs import publish
from alt_deploy.setup_jobs_view import SetupJobsService
from alt_deploy.setup_plans import private_read
from test_setup_phases import phase_job,phase_result
from test_full_workflow_binding import full_setup
from test_component_catalog import project


def test_public_phase_status_is_typed_bounded_and_does_not_dispatch_or_change_files(phase_job):
    store,jobs,job,ready,identity,admissions,setup=phase_job
    before={p:p.read_bytes() for p in setup.settings.state_root.rglob('*') if p.is_file()}
    service=SetupJobsService(setup.settings)
    value=service.status(job.job_id)['job']
    assert value['workflow']['phase']=='user'
    assert value['workflow']['phases']['system']['state']=='successful'
    assert value['workflow']['phases']['user']['state']=='waiting_first_login'
    assert value['workflow']['phases']['final_dns']['state']=='pending'
    assert all(p.read_bytes()==data for p,data in before.items())
    assert 'process_identity' not in json.dumps(value['workflow'])
    assert service.list()['jobs'][0]['workflow']==value['workflow']


@pytest.mark.parametrize('fault',['extra_private_field','wrong_ref','wrong_phase'])
def test_invalid_private_workflow_result_cannot_be_copied_to_public_progress(phase_job,fault):
    store,jobs,job,ready,identity,admissions,setup=phase_job
    with exclusive_lock(setup.settings.lock_file):store.enqueue(job,'user',ready)
    execution=private_read(job.job_dir/'execution.json')
    if fault=='extra_private_field':execution['workflow']['environment']={'TOKEN':'PRIVATE-SENTINEL'}
    elif fault=='wrong_ref':execution['workflow']['phases']['user']['ticket_sha256']='0'*64
    else:execution['workflow']['phase']='system'
    publish(job.job_dir/'execution.json',execution)
    with pytest.raises(ControlError) as caught:SetupJobsService(setup.settings).status(job.job_id)
    assert 'SENTINEL' not in str(caught.value)
