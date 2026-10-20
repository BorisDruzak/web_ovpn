"""The acknowledged controller child cannot run before durable authority."""
import os
from pathlib import Path
import sys

import pytest

from alt_deploy.errors import ControlError
from alt_deploy.locks import exclusive_lock
from alt_deploy.setup_plans import private_read
from test_setup_phases import phase_job
from test_full_workflow_binding import full_setup
from test_component_catalog import project


@pytest.mark.parametrize('failure',['none','before_receipt','timeout'])
def test_child_gate_records_birth_before_exec_and_never_reuses_claim(phase_job,tmp_path,monkeypatch,failure):
    from alt_deploy.workflow_phase_process import run_claimed,child_quiet
    from alt_deploy.setup_jobs import publish
    store,jobs,job,ready,identity,admissions,setup=phase_job
    marker=tmp_path/'effect'
    command=[sys.executable,'-c',"from pathlib import Path; import sys,time; Path(sys.argv[1]).write_text('effect'); time.sleep(float(sys.argv[2]))",str(marker),'10' if failure=='timeout' else '0']
    with exclusive_lock(setup.settings.lock_file):
        store.enqueue(job,'user',ready);claim=store.claim(jobs.get(job.job_id),'user',identity)
        if failure=='before_receipt':
            monkeypatch.setattr('alt_deploy.workflow_phase_process.publish',lambda *a,**k:(_ for _ in ()).throw(OSError('receipt unavailable')))
        call=lambda:run_claimed(setup.settings,jobs.get(job.job_id),'user',claim,command,env=os.environ.copy(),timeout=0.5,
                                cwd=tmp_path)
        if failure=='none':assert call()==0
        else:
            with pytest.raises(ControlError):call()
        assert marker.exists() is (failure!='before_receipt')
        assert child_quiet(setup.settings,jobs.get(job.job_id),'user',claim) is True
        with pytest.raises(ControlError):call()


@pytest.mark.parametrize('change',['same_birth','old_boot','reused_pid'])
def test_child_exit_uses_boot_and_birth_even_if_the_old_uid_probe_is_unavailable(phase_job,monkeypatch,change):
    from alt_deploy.workflow_phase_process import child_quiet
    from alt_deploy.setup_worker import process_identity
    from alt_deploy.setup_plans import digest,private_create
    store,jobs,job,ready,identity,admissions,setup=phase_job
    with exclusive_lock(setup.settings.lock_file):
        store.enqueue(job,'user',ready);claim=store.claim(jobs.get(job.job_id),'user',identity)
    child=process_identity(setup.settings)
    if change=='old_boot':child['boot_id']='99999999-2222-3333-4444-555555555555'
    elif change=='reused_pid':child['start_ticks']+=1
    private_create(job.job_dir/'phase-user-process.json',{'schema_version':1,'job_id':job.job_id,'phase':'user',
        'claim_sha256':digest(claim),'worker':claim['process_identity'],'child':child,'command_sha256':'a'*64})
    monkeypatch.setattr('alt_deploy.workflow_phase_process.process_alive',lambda *a:None,raising=False)
    assert child_quiet(setup.settings,job,'user',claim) is (change!='same_birth')
