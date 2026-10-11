from __future__ import annotations

import copy,json

import pytest

from alt_deploy.errors import ControlError
from alt_deploy.setup_plans import digest,private_replace
from test_setup_recovery_sssd_start_runtime import scenario as startup_fixture


def scenario(root):
    from alt_deploy.setup_recovery_native_runtime import RecoveryNativeRuntime
    from alt_deploy import setup_recovery_native_testjoin as worker
    startup,request,context,approval,previous_calls,plan=startup_fixture(root)
    postwrite=startup.policy_runtime.kerberos_runtime.import_runtime.postwrite
    postwrite._protected=lambda *values:(copy.deepcopy(postwrite.fixture_protected),None)
    started=startup.start_once(request['plan_id'],request['plan_sha256'])
    calls=[];authorizations=[]
    def authorize(plan_id,sha,sources,request_hash,receipt_hash):
        value=dict(schema_version=1,plan_id=plan_id,plan_sha256=sha,source_sha256=sources,
            startup_request_sha256=request_hash,startup_receipt_sha256=receipt_hash,
            startup_approval_sha256=approval['approval_sha256'],effects_ledger_sha256=approval['effects_ledger_sha256'],
            approval_sha256='7'*64)
        authorizations.append(value)
        return value
    def runner(command,**options):
        calls.append((command,options));value=json.loads(options['input_text'])
        facts=value['request']['policy_request']['kerberos_request']['import_request']['rehearsal_request']['backup_request']['facts']
        tools={path:dict(facts['tools'][path.rsplit('/',1)[1]],package=package) for path,package in worker.TOOLS.items()}
        result=worker._receipt(value['request'],value['started'],tools,__import__('alt_deploy.setup_recovery_backup',fromlist=['']))
        return 0,json.dumps(result),'SYNTHETIC_PRIVATE_OUTPUT'
    runtime=RecoveryNativeRuntime(startup_runtime=startup,authorization=authorize,runner=runner)
    return runtime,request,context,approval,calls,plan,started,authorizations


def test_controller_sends_native_once_and_retained_verification_never_restarts_sssd(tmp_path):
    runtime,request,context,approval,calls,_,started,_=scenario(tmp_path)
    result=runtime.testjoin_once(request['plan_id'],request['plan_sha256'])
    assert result['status']=='native_testjoin_succeeded' and result['trust_verified'] is False
    command,options=calls[0]
    assert command[:3]==['/usr/bin/ssh','-F','/dev/null'] and len(command[-1].encode())<8192
    assert 'StrictHostKeyChecking=yes' in command
    value=json.loads(options['input_text']);assert value['action']=='testjoin' and value['started']==started
    assert 'SYNTHETIC_PRIVATE_OUTPUT' not in str(result)
    with pytest.raises(ControlError):runtime.testjoin_once(request['plan_id'],request['plan_sha256'])
    assert len(calls)==1
    assert runtime.verify(request['plan_id'],request['plan_sha256'])==result
    assert json.loads(calls[-1][1]['input_text'])['action']=='verify'


@pytest.mark.parametrize('change',['approval','extra','source','startup_intent','startup_receipt','plan'])
def test_unbound_controller_inputs_refuse_before_native_ssh(tmp_path,change,monkeypatch):
    runtime,request,context,approval,calls,plan,_,_=scenario(tmp_path)
    if change in ('approval','extra'):
        previous=runtime.authorization
        def changed(*values):
            result=previous(*values);result['source_sha256' if change=='approval' else 'command']='changed'
            return result
        runtime.authorization=changed
    elif change=='source':monkeypatch.setattr(runtime,'_sources',lambda:['changed']*13)
    elif change=='plan':plan['sha256']='0'*64
    else:
        suffix='.sssd-start-intent.json' if change=='startup_intent' else '.sssd-start-result.json'
        private_replace(runtime.attempts._path(**context['pair'],suffix=suffix),{})
    with pytest.raises(ControlError):runtime.testjoin_once(request['plan_id'],request['plan_sha256'])
    assert not calls


@pytest.mark.parametrize('change',['nonzero','duplicate','oversized','trust_claim','tool_hash','approval_after','history_after'])
def test_entered_native_failure_is_retained_redacted_and_excludes_replay(tmp_path,change):
    runtime,request,context,approval,calls,_,_,_=scenario(tmp_path);previous=runtime.runner
    def changed(command,**options):
        rc,out,err=previous(command,**options)
        if change=='nonzero':rc=1
        elif change=='duplicate':out=out[:-1]+',"schema_version":1}'
        elif change=='oversized':out=' '*16385
        elif change in ('trust_claim','tool_hash'):
            value=json.loads(out);value['trust_verified' if change=='trust_claim' else 'tools_sha256']=True if change=='trust_claim' else '0'*64
            out=json.dumps(value)
        elif change=='approval_after':approval['approval_sha256']='0'*64
        else:context['service_receipt']['request_sha256']='0'*64
        return rc,out,err
    runtime.runner=changed
    with pytest.raises(ControlError) as error:runtime.testjoin_once(request['plan_id'],request['plan_sha256'])
    assert 'SYNTHETIC_PRIVATE_OUTPUT' not in str(error.value)
    assert runtime.attempts._path(**context['pair'],suffix='.native-testjoin-intent.json').is_file()
    with pytest.raises(ControlError):runtime.testjoin_once(request['plan_id'],request['plan_sha256'])
    assert len(calls)==1


@pytest.mark.parametrize('change',['native_approval','source','failed_marker'])
def test_last_startup_callback_cannot_change_native_authority_before_ssh(tmp_path,change,monkeypatch):
    runtime,request,context,_,calls,_,_,_=scenario(tmp_path)
    original=runtime.startup_runtime._context;observed=[];native_approval=['7'*64]
    authorize=runtime.authorization
    def authorization(*values):
        value=authorize(*values);value['approval_sha256']=native_approval[0]
        return value
    runtime.authorization=authorization
    sources=runtime._sources();source_changed=[]
    monkeypatch.setattr(runtime,'_sources',lambda:copy.deepcopy(sources if not source_changed else sources[:-1]+['changed']))
    def changed(*values):
        value=original(*values);observed.append(True)
        if len(observed)==4:
            if change=='native_approval':native_approval[0]='0'*64
            elif change=='source':source_changed.append(True)
            else:private_replace(runtime.attempts._path(**context['pair'],suffix='.native-testjoin-failed.json'),{'schema_version':1})
        return value
    runtime.startup_runtime._context=changed
    with pytest.raises(ControlError):runtime.testjoin_once(request['plan_id'],request['plan_sha256'])
    assert len(observed)>=4 and not calls


@pytest.mark.parametrize('change',['plan_expiry','protected_history','startup_intent','failed_marker'])
def test_final_native_authorization_callback_cannot_leave_stale_local_guards(tmp_path,change):
    runtime,request,context,_,calls,plan,_,_=scenario(tmp_path);previous=runtime.authorization;observed=[]
    def changed(*values):
        result=previous(*values);observed.append(True)
        if len(observed)==6:
            if change=='plan_expiry':plan['expires_at']='2000-01-01T00:00:00+00:00'
            elif change=='protected_history':
                runtime.startup_runtime.policy_runtime.kerberos_runtime.import_runtime.postwrite.fixture_protected['history_sha256']='0'*64
            else:
                suffix='.sssd-start-intent.json' if change=='startup_intent' else '.native-testjoin-failed.json'
                private_replace(runtime.attempts._path(**context['pair'],suffix=suffix),{})
        return result
    runtime.authorization=changed
    with pytest.raises(ControlError):runtime.testjoin_once(request['plan_id'],request['plan_sha256'])
    assert len(observed)>=6 and not calls


@pytest.mark.parametrize('suffix',['.native-testjoin-intent.json','.native-testjoin-result.json'])
def test_native_record_persistence_failure_excludes_future_verification(tmp_path,monkeypatch,suffix):
    from alt_deploy.setup_recovery_controller_backup import RecoveryControllerBackup
    runtime,request,context,_,calls,_,_,_=scenario(tmp_path);previous=RecoveryControllerBackup._persist
    def changed(path,value):
        previous(path,value)
        if path.name.endswith(suffix):raise OSError('SYNTHETIC_PERSISTENCE_ERROR')
    monkeypatch.setattr(RecoveryControllerBackup,'_persist',staticmethod(changed))
    with pytest.raises(ControlError):runtime.testjoin_once(request['plan_id'],request['plan_sha256'])
    assert len(calls)==(1 if suffix.endswith('result.json') else 0)
    assert runtime.attempts._path(**context['pair'],suffix='.native-testjoin-failed.json').exists()
    with pytest.raises(ControlError):runtime.verify(request['plan_id'],request['plan_sha256'])
