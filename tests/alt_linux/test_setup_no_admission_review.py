"""Expired terminal UNKNOWN may receive an archival negative fact, never a replay."""
from datetime import timedelta
import io
import subprocess
import sys
import uuid

import pytest

from alt_deploy.errors import ControlError
from alt_deploy.setup_plans import private_create, private_read, private_replace
from alt_deploy.workstations_receipts import GatewayReceiptStore
from test_setup_prejoin_compatibility import prejoin, component_service, project, inject_bridge
from test_setup_closed_failure import backend
from test_setup_service import UUID, OU


@pytest.fixture
def unadmitted(prejoin, monkeypatch):
    inject_bridge(monkeypatch, prejoin)
    setup = prejoin[0]
    plan = setup.plan(UUID, prejoin[4]['login'], OU, 'office-standard-v1')
    request_id = str(uuid.uuid4())
    intent = dict(operation='plans.apply', parameters=dict(plan_id=plan['plan_id'], sha256=plan['sha256'], kind='full_setup'))
    store = GatewayReceiptStore(setup.settings.state_root)
    def interrupted():
        raise ControlError('full_workflow_policy_unavailable', 'Synthetic interrupted pre-admission lookup', 7)
    with pytest.raises(ControlError): store.execute(request_id, intent, interrupted)
    path=store.root/(request_id+'.json')
    record=private_read(path); record['created_at']=setup.clock().isoformat(); private_replace(path,record)
    prejoin[-1][0] += timedelta(minutes=31)
    return prejoin, plan, request_id, store


def review_for(case):
    p = case[0]
    return backend('setup_no_admission').NoAdmissionReview(p[0].settings, observer=p[10], clock=p[0].clock)


def test_review_is_archival_only_and_keeps_original_unknown_and_binding(unadmitted):
    p, original, request_id, store = unadmitted
    setup, jobs, job = p[:3]
    root = setup.settings.state_root
    protected = [root/'workstations-gateway-receipts'/(request_id+'.json'),
                 root/'domain-assignments'/(UUID+'.json'), *job.job_dir.rglob('*.json')]
    before = {path: path.read_bytes() for path in protected}
    review = review_for(unadmitted)
    with review._locks(request_id):
        assert review._snapshot(request_id)['request_id'] == request_id
    plan = review.plan(request_id)
    assert plan['payload']['request_id'] == request_id
    from alt_deploy.setup_cli import write_text
    output=io.StringIO(); write_text(output,plan)
    assert request_id in output.getvalue() and 'Execution available: false' in output.getvalue()
    fact = review.confirm(plan['plan_id'], plan['sha256'])
    assert fact['purpose'] == 'historical_no_admission_only'
    assert fact['request_id'] == request_id
    assert {path: path.read_bytes() for path in protected} == before
    assert store.status(request_id)['state'] == 'unknown'
    assert len(jobs.list()) == 1 and jobs.get(job.job_id).state == 'unknown_requires_review'
    # A duplicate gateway call still cannot execute its callback.
    store.execute(request_id, private_read(protected[0])['intent'], lambda: pytest.fail('replayed'))
    with pytest.raises(ControlError, match='expired'):
        setup.apply(original['plan_id'], original['sha256'], detach=True)
    backend('setup_no_admission').validate_artifacts(root)


@pytest.mark.parametrize('fault', ['pending', 'successful', 'other_operation', 'wrong_kind', 'not_expired',
    'claim', 'reservation', 'plan_run', 'plan_tamper', 'receipt_tamper', 'receipt_mode', 'receipt_link',
    'credentials', 'processes', 'collision', 'native', 'clock', 'package', 'binding', 'event'])
def test_review_requires_complete_unchanged_no_admission_and_live_proof(unadmitted, fault):
    p, plan, request_id, store = unadmitted
    setup = p[0]; root = setup.settings.state_root
    receipt = root/'workstations-gateway-receipts'/(request_id+'.json')
    value = private_read(receipt)
    if fault in ('pending', 'successful'):
        value['state'] = fault; private_replace(receipt, value)
    elif fault in ('other_operation', 'wrong_kind'):
        from alt_deploy.setup_plans import digest
        if fault == 'other_operation': value['intent']['operation'] = 'plans.create'
        else: value['intent']['parameters']['kind'] = 'component'
        value['intent_sha256'] = digest(value['intent']); private_replace(receipt, value)
    elif fault == 'not_expired': p[-1][0] -= timedelta(minutes=2)
    elif fault == 'claim': private_create(root/'setup-job-plan-claims'/(plan['sha256']+'.json'), {})
    elif fault == 'reservation': private_create(root/'setup-job-reservations'/('job-orphan.json'), {})
    elif fault == 'plan_run': private_create(root/'setup-plan-runs'/(plan['plan_id']+'.json'), {})
    elif fault == 'plan_tamper':
        path=root/'setup-plans'/(plan['plan_id']+'.json'); v=private_read(path); v['payload']['engine_schema_version']=1; private_replace(path,v)
    elif fault == 'receipt_tamper': value['intent_sha256']='a'*64; private_replace(receipt,value)
    elif fault == 'receipt_mode': receipt.chmod(0o644)
    elif fault == 'receipt_link':
        destination=receipt.with_suffix('.retained'); receipt.rename(destination); receipt.symlink_to(destination)
    elif fault == 'credentials': p[8]['credentials_absent']=False
    elif fault == 'processes': p[8]['processes_absent']=False
    elif fault == 'collision': p[9]['matches']=1
    elif fault == 'native': p[7]['auth_scheme']='sssd'
    elif fault == 'clock': p[7]['clock_synchronized']=False
    elif fault == 'package': p[5]['package_manager']['processes_absent']=False
    elif fault == 'binding':
        path=root/'domain-assignments'/(UUID+'.json'); v=private_read(path); v['revision']+=1; private_replace(path,v)
    else:
        path=next((p[2].job_dir/'events').glob('*.json')); path.write_bytes(path.read_bytes()+b' ')
    with pytest.raises(ControlError): review_for(unadmitted).plan(request_id)
    assert len(p[1].list()) == 1


@pytest.mark.parametrize('fault', ['receipt', 'live', 'expired', 'claim'])
def test_confirmation_repeats_proof(unadmitted, fault):
    p, original, request_id, _ = unadmitted
    review = review_for(unadmitted); plan = review.plan(request_id)
    if fault == 'receipt':
        path=p[0].settings.state_root/'workstations-gateway-receipts'/(request_id+'.json')
        path.write_bytes(path.read_bytes()+b' ')
    elif fault == 'live': p[8]['processes_absent']=False
    elif fault == 'expired': p[-1][0] += timedelta(minutes=30)
    else: private_create(p[0].settings.state_root/'setup-job-plan-claims'/(original['sha256']+'.json'),{})
    with pytest.raises(ControlError): review.confirm(plan['plan_id'],plan['sha256'])
    assert not list((p[0].settings.state_root/'setup-no-admission-facts').glob('*.json'))


def test_restore_history_retains_unknown_receipt_and_archival_fact(unadmitted):
    p, _, request_id, _ = unadmitted
    root=p[0].settings.state_root
    compat=backend('setup_compat')
    before=compat.history_fingerprint(root)
    assert 'workstations-gateway-receipts/'+request_id+'.json' in before
    review=review_for(unadmitted); plan=review.plan(request_id); review.confirm(plan['plan_id'],plan['sha256'])
    after=compat.history_fingerprint(root)
    assert any(k.startswith('setup-no-admission-facts/') for k in after)
    assert all(after[k]==v for k,v in before.items())


@pytest.mark.parametrize('lock', ['receipt','lifecycle'])
def test_review_cannot_race_a_still_owned_callback_or_lifecycle(unadmitted, lock):
    p, _, request_id, _ = unadmitted
    path=(p[0].settings.state_root/'workstations-gateway-receipts'/(request_id+'.lock')
          if lock=='receipt' else p[0].settings.lock_file)
    program='import fcntl,sys; f=open(sys.argv[1],"r"); fcntl.flock(f,fcntl.LOCK_EX); print("held",flush=True); sys.stdin.read()'
    child=subprocess.Popen([sys.executable,'-c',program,str(path)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,text=True)
    try:
        assert child.stdout.readline().strip()=='held'
        with pytest.raises(ControlError): review_for(unadmitted).plan(request_id)
    finally:
        child.communicate('',timeout=5)


def test_cli_no_admission_review_has_no_execution_switch(monkeypatch):
    from alt_deploy import cli,setup_cli
    calls=[]
    class Review:
        def plan(self,request): calls.append(('plan',request)); return {'purpose':'review'}
        def confirm(self,plan,sha): calls.append(('confirm',plan,sha)); return {'purpose':'fact'}
    monkeypatch.setattr('alt_deploy.setup_maintenance_review_bridge.no_admission_service',lambda s:Review())
    for tail in (['no-admission-plan','request'],['no-admission-confirm','plan','--confirm-sha256','a'*64]):
        setup_cli.handle(cli.build_parser().parse_args(['setup','requests',*tail]),object())
    assert calls==[('plan','request'),('confirm','plan','a'*64)]
    with pytest.raises(SystemExit):
        cli.build_parser().parse_args(['setup','requests','no-admission-plan','request','--apply'])
