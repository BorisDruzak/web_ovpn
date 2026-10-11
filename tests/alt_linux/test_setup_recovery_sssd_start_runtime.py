from __future__ import annotations

import copy
from datetime import datetime,timedelta,timezone
import json
from pathlib import Path
import shlex
from types import SimpleNamespace

import pytest

from alt_deploy.errors import ControlError
from alt_deploy.setup_plans import digest,private_replace
from test_setup_recovery_sssd_start import scenario as local_fixture


def scenario(root):
    from alt_deploy.setup_recovery import RecoveryAttemptStore
    from alt_deploy.setup_recovery_sssd_start_runtime import RecoverySSSDStartRuntime
    from alt_deploy.setup_recovery_sssd_policy_runtime import RecoverySSSDPolicyRuntime
    from alt_deploy import setup_recovery_sssd_policy as policy,setup_recovery_backup as backup
    _,request,args,_,_=local_fixture(root/'workstation')
    directory=Path(__file__).parents[2]/'deploy/alt-linux/control/alt_deploy'
    names=('probe','backup','native','process','rehearsal','keytab','import','services','kerberos','sssd_policy')
    sources=[(directory/('setup_recovery_'+name+'.py')).read_text() for name in names]
    prepared=request['policy_request'];prepared['source_sha256']=digest(sources)
    meta=prepared['kerberos_request']['import_request']['rehearsal_request']['metadata']
    receipt=policy._receipt(prepared,{},policy._snippet(meta),backup)
    receipt['tools_sha256']=request['policy_receipt']['tools_sha256'];request['policy_receipt']=receipt
    pair={key:request['service_request']['backup_request'][key] for key in ('failed_run_id','computer_guid')}
    settings=SimpleNamespace(state_root=root/'controller',lock_file=root/'controller.lock',
        known_hosts_file=root/'known_hosts',private_key_file=root/'key')
    attempts=RecoveryAttemptStore(settings.state_root)
    payload={'snapshot':{'prerequisites':{'source_sha256':'b'*64}}}
    context=dict(pair=pair,address='192.0.2.10',request=request['policy_request'],service_request=request['service_request'],
        service_receipt=request['service_receipt'],sources=sources,
        kerberos_context={'import_context':{'protected':{'payload':payload}}})
    created=datetime.now(timezone.utc)
    plan={'plan_id':request['plan_id'],'sha256':request['plan_sha256'],'payload':payload,
        'created_at':created.isoformat(),'expires_at':(created+timedelta(minutes=30)).isoformat()}
    postwrite=SimpleNamespace(fingerprint=lambda:'b'*64,
        service_gate=SimpleNamespace(preparation=SimpleNamespace(plans=SimpleNamespace(load=lambda *a:copy.deepcopy(plan)))))
    postwrite.fixture_protected=dict(payload=payload,history_sha256='1'*64)
    postwrite.load=lambda *a:dict(copy.deepcopy(postwrite.fixture_protected),machine=SimpleNamespace())
    def current_context(*a):
        value=copy.deepcopy(context)
        value['kerberos_context']['import_context']['protected']={key:item for key,item in postwrite.load(*a).items() if key!='machine'}
        return value
    policy_runtime=SimpleNamespace(settings=settings,attempts=attempts,_sources=lambda:copy.deepcopy(sources),
        _context=current_context,_receipt=RecoverySSSDPolicyRuntime._receipt,
        kerberos_runtime=SimpleNamespace(import_runtime=SimpleNamespace(postwrite=postwrite)))
    intended=dict(schema_version=1,plan_id=request['plan_id'],plan_sha256=request['plan_sha256'],request_sha256=digest(context['request']),
        kerberos_receipt_sha256=digest(context['request']['kerberos_receipt']),services_receipt_sha256=digest(context['service_receipt']))
    for suffix,value in (('.sssd-policy-intent.json',intended),('.sssd-policy-result.json',request['policy_receipt'])):
        private_replace(attempts._path(**pair,suffix=suffix),value)
    approval=dict(schema_version=1,plan_id=request['plan_id'],plan_sha256=request['plan_sha256'],source_sha256='',
        sssd_unit=request['sssd_unit'],effects_ledger_sha256='f'*64,approval_sha256='3'*64)
    calls=[]
    def authorize(*a):return copy.deepcopy(approval)
    def runner(command,**options):
        calls.append((command,options))
        from alt_deploy import setup_recovery_sssd_start as start
        wire=json.loads(options['input_text']);bound=wire['request'];state=copy.deepcopy(bound['sssd_unit'])
        state['properties'].update(ActiveState='active',SubState='running',MainPID='123',InvocationID='a'*32)
        return 0,json.dumps(start._receipt(bound,state,backup)),'SYNTHETIC_PRIVATE_OUTPUT'
    runtime=RecoverySSSDStartRuntime(policy_runtime=policy_runtime,authorization=authorize,runner=runner)
    approval['source_sha256']=digest(runtime._sources())
    return runtime,request,context,approval,calls,plan


def test_one_start_transport_has_small_argv_retained_intent_and_readonly_verification(tmp_path):
    runtime,request,context,approval,calls,_=scenario(tmp_path)
    receipt=runtime.start_once(request['plan_id'],request['plan_sha256'])
    assert receipt['status']=='sssd_started' and receipt['trust_verified'] is False
    command,options=calls[0];assert len(command[-1].encode())<8192
    assert command[:3]==['/usr/bin/ssh','-F','/dev/null'] and command[-2]=='ansible@192.0.2.10'
    for option in ('StrictHostKeyChecking=yes','BatchMode=yes','IdentitiesOnly=yes','ProxyJump=none','ProxyCommand=none'):assert option in command
    compile(shlex.split(command[-1])[-1],'<startup-bootstrap>','exec')
    assert json.loads(options['input_text'])['action']=='start'
    assert 'SYNTHETIC_PRIVATE_OUTPUT' not in str(receipt)
    with pytest.raises(ControlError):runtime.start_once(request['plan_id'],request['plan_sha256'])
    assert len(calls)==1
    assert runtime.verify(request['plan_id'],request['plan_sha256'])==receipt
    assert json.loads(calls[-1][1]['input_text'])['action']=='verify'


def test_last_pretransport_authorization_drift_refuses_ssh(tmp_path):
    runtime,request,context,approval,calls,_=scenario(tmp_path);authorize=runtime.authorization;observed=[]
    postwrite=runtime.policy_runtime.kerberos_runtime.import_runtime.postwrite
    def changed(*a):
        value=authorize(*a);observed.append(True)
        if len(observed)==4:postwrite.fixture_protected['history_sha256']='0'*64
        return value
    runtime.authorization=changed
    with pytest.raises(ControlError):runtime.start_once(request['plan_id'],request['plan_sha256'])
    assert not calls


def test_cached_mutable_authorization_cannot_change_the_captured_request(tmp_path):
    runtime,request,context,approval,calls,_=scenario(tmp_path);observed=[]
    def cached(*a):
        observed.append(True)
        if len(observed)==4:approval['sssd_unit']['opaque_sha256']['Environment']='0'*64
        return approval
    runtime.authorization=cached
    with pytest.raises(ControlError):runtime.start_once(request['plan_id'],request['plan_sha256'])
    assert not calls


@pytest.mark.parametrize('change',['authorization','approval_extra','source','policy_intent','policy_receipt','fingerprint','plan'])
def test_changed_controller_inputs_block_before_ssh(tmp_path,change,monkeypatch):
    runtime,request,context,approval,calls,plan=scenario(tmp_path)
    if change=='authorization':approval['plan_sha256']='0'*64
    elif change=='approval_extra':approval['command']='restart'
    elif change=='source':monkeypatch.setattr(runtime,'_sources',lambda:['changed']*12)
    elif change=='fingerprint':runtime.policy_runtime.kerberos_runtime.import_runtime.postwrite.fingerprint=lambda:'0'*64
    elif change=='plan':plan['sha256']='0'*64
    else:
        suffix='.sssd-policy-intent.json' if change=='policy_intent' else '.sssd-policy-result.json'
        path=runtime.attempts._path(**context['pair'],suffix=suffix)
        private_replace(path,{'schema_version':True})
    with pytest.raises(ControlError):runtime.start_once(request['plan_id'],request['plan_sha256'])
    assert not calls


@pytest.mark.parametrize('change',['nonzero','duplicate','receipt_pid','receipt_bool','history_after','approval_after','sources_after','oversized'])
def test_entered_failure_is_permanent_and_never_replayed(tmp_path,change,monkeypatch):
    runtime,request,context,approval,calls,_=scenario(tmp_path);original=runtime.runner
    def broken(command,**options):
        rc,out,err=original(command,**options)
        if change=='nonzero':rc=1
        elif change=='duplicate':out=out[:-1]+',"schema_version":1}'
        elif change=='oversized':out=' '*16385
        elif change in ('receipt_pid','receipt_bool'):
            value=json.loads(out);value['main_pid' if change=='receipt_pid' else 'n_restarts']=0 if change=='receipt_pid' else False
            out=json.dumps(value)
        elif change=='history_after':context['service_receipt']['request_sha256']='0'*64
        elif change=='approval_after':approval['approval_sha256']='0'*64
        else:monkeypatch.setattr(runtime,'_sources',lambda:['changed']*12)
        return rc,out,err
    runtime.runner=broken
    with pytest.raises(ControlError) as error:runtime.start_once(request['plan_id'],request['plan_sha256'])
    assert 'SYNTHETIC_PRIVATE_OUTPUT' not in str(error.value)
    assert runtime.attempts._path(**context['pair'],suffix='.sssd-start-intent.json').is_file()
    with pytest.raises(ControlError):runtime.start_once(request['plan_id'],request['plan_sha256'])
    assert len(calls)==1


@pytest.mark.parametrize('change',['intent_sync','intent_type','result_sync','approval_after_persist'])
def test_durable_record_failure_or_final_persist_drift_never_allows_replay(tmp_path,change,monkeypatch):
    from alt_deploy.setup_recovery_controller_backup import RecoveryControllerBackup
    from alt_deploy.setup_plans import private_read
    runtime,request,context,approval,calls,_=scenario(tmp_path);persist=RecoveryControllerBackup._persist
    def changed(path,value):
        persist(path,value)
        if path.name.endswith('.sssd-start-intent.json'):
            if change=='intent_sync':raise OSError('SYNTHETIC_PRIVATE_OUTPUT')
            if change=='intent_type':
                stored=private_read(path);stored['schema_version']=True;private_replace(path,stored)
        elif path.name.endswith('.sssd-start-result.json'):
            if change=='result_sync':raise OSError('SYNTHETIC_PRIVATE_OUTPUT')
            if change=='approval_after_persist':approval['approval_sha256']='0'*64
    monkeypatch.setattr(RecoveryControllerBackup,'_persist',staticmethod(changed))
    with pytest.raises(ControlError):runtime.start_once(request['plan_id'],request['plan_sha256'])
    assert len(calls)==(0 if change.startswith('intent') else 1)
    with pytest.raises(ControlError):runtime.start_once(request['plan_id'],request['plan_sha256'])
    assert len(calls)==(0 if change.startswith('intent') else 1)
