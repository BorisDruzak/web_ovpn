"""Phase records are retained restore history, not disposable queue metadata."""
import shutil

import pytest

from alt_deploy.locks import exclusive_lock
from alt_deploy.errors import ControlError
from alt_deploy.setup_plans import private_create
from alt_deploy_backup.errors import BackupError
from alt_deploy_backup.setup_compat import history_fingerprint,assert_restore_history,validate_ledger
from test_setup_phases import phase_job,phase_result
from test_full_workflow_binding import full_setup
from test_component_catalog import project


def test_phase_authority_and_private_execution_files_survive_history_restore_check(phase_job,tmp_path):
    store,jobs,job,ready,identity,admissions,setup=phase_job
    with exclusive_lock(setup.settings.lock_file):
        store.enqueue(job,'user',ready);store.claim(jobs.get(job.job_id),'user',identity)
        store.complete(jobs.get(job.job_id),'user',phase_result())
    private_create(job.job_dir/'phase-user-vars.json',{'value':'PRIVATE-SENTINEL'})
    before=history_fingerprint(setup.settings.state_root)
    assert 'PRIVATE-SENTINEL' not in str(before)
    names={key.split('/')[0] for key in before}
    assert {'setup-phase-tickets','setup-phase-claims','setup-phase-results'}<=names
    assert 'jobs/'+job.job_id+'/phase-user-vars.json' in before
    copy=tmp_path/'restored';shutil.copytree(setup.settings.state_root,copy)
    assert_restore_history(setup.settings.state_root,copy)
    path=copy/'setup-phase-results'/(job.job_id+'--user.json');path.unlink()
    with pytest.raises((BackupError,ValueError,ControlError)):
        assert_restore_history(setup.settings.state_root,copy)


def test_historical_phase_records_do_not_load_changed_source_or_extend_expired_plan(phase_job):
    store,jobs,job,ready,identity,admissions,setup=phase_job
    with exclusive_lock(setup.settings.lock_file):store.enqueue(job,'user',ready)
    path=setup.settings.ansible_project_dir/'roles/desktop_shortcuts/tasks/main.yml'
    path.write_text(path.read_text()+'\n# changed source\n')
    assert store.records(jobs.get(job.job_id))['user']['ticket']['readiness']==ready
    validate_ledger(setup.settings.state_root)
