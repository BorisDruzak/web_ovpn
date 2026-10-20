"""A proven idle new workflow cannot head-block an unrelated initial job."""
import copy
import shutil

from alt_deploy.setup_jobs import publish
from alt_deploy.setup_plans import digest,private_read
from alt_deploy_backup.setup_queue_review import QueueAdmissionReview
from test_setup_queue_review import queued,freeze_old
from test_setup_maintenance_review import stopped
from test_component_setup import component_service
from test_component_catalog import project


def test_native_queue_review_allows_intact_gui_wait_and_keeps_all_old_history(queued,tmp_path,project,monkeypatch):
    import test_setup_service,test_component_verification,test_setup_phases,test_full_workflow_binding
    from alt_deploy.setup_jobs import SetupJobRepository
    settings,old,candidate,facts,date,jobs=queued
    third_uuid='33333333-4444-5555-6666-777777777777'
    original_result=test_setup_phases.system_result
    def system_result():
        value=original_result();value['computer'].update(object_guid='99999999-aaaa-bbbb-cccc-dddddddddddd',
            object_sid='S-1-5-21-1-2-3-3003',dn='CN=alt-t3-pc3,'+test_setup_service.OU,dns_hostname='alt-t3-pc3.sosnadmin.local')
        return value
    with monkeypatch.context() as patch:
        for module in (test_setup_service,test_component_verification,test_setup_phases):patch.setattr(module,'UUID',third_uuid)
        patch.setattr(test_setup_phases,'system_result',system_result)
        base=test_full_workflow_binding.full_setup.__wrapped__(tmp_path/'third',project,patch)
        machine=base[1];machine.hostname='alt-t3-pc3';machine.raw['hostname']=machine.hostname
        base[3]['machine']['hostname']=machine.hostname
        for fact in base[3]['components'].values():
            value=fact.get('wallet_readiness') or fact.get('final_dns',{}).get('observation')
            if value is not None:
                value['hostname']=machine.hostname
                value['snapshot_sha256']=digest({k:v for k,v in value.items() if k!='snapshot_sha256'})
        probe=base[0].probe
        base[0].probe=lambda m,u:dict(probe(m,u),hostname=machine.hostname)
        _,third_jobs,third,ready,*_=test_setup_phases.phase_job.__wrapped__(base)
    # Merge independent synthetic histories with a new native sequence. This
    # fixture-only rewrite is never an operation against retained real jobs.
    root=third.job_dir.parent.parent;request=private_read(third.job_dir/'request.json');request['admission_sequence']=3
    request_sha=digest(request);publish(third.job_dir/'request.json',request)
    claim=private_read(third_jobs.claims/(third.status['plan_sha256']+'.json'))
    claim.update(admission_sequence=3,request_sha256=request_sha)
    publish(third_jobs.claims/(third.status['plan_sha256']+'.json'),claim);publish(third_jobs.reservations/(third.job_id+'.json'),claim)
    path=root/'setup-phase-results'/(third.job_id+'--system.json');system=private_read(path)
    system.update(request_sha256=request_sha,claim_sha256=digest(claim));publish(path,system)
    status=private_read(third.job_dir/'status.json');status.update(admission_sequence=3,request_sha256=request_sha)
    status['workflow']['system_result_sha256']=digest(system);publish(third.job_dir/'status.json',status)
    execution=private_read(third.job_dir/'execution.json');execution['workflow']['system_result_sha256']=digest(system)
    publish(third.job_dir/'execution.json',execution)
    for name in ('jobs','setup-plans','setup-job-plan-claims','setup-job-reservations','setup-phase-results'):
        shutil.copytree(root/name,settings.state_root/name,dirs_exist_ok=True)
    jobs=SetupJobRepository(settings,clock=lambda:date[0]);jobs._check_admissions()
    before=freeze_old(old,settings.state_root)
    review=QueueAdmissionReview(settings,observer=lambda j:copy.deepcopy(facts),clock=lambda:date[0])
    plan=review.plan(old.job_id,candidate.job_id);review.confirm(plan['plan_id'],plan['sha256'])
    result=review.for_candidate(candidate.job_id)
    assert result['job_ids']=={old.job_id}
    assert freeze_old(old,settings.state_root)==before
    assert jobs.get(third.job_id).state=='waiting_first_login'
    assert jobs.get(candidate.job_id).status['claimed'] is False
