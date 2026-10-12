from __future__ import annotations

import copy,json

import pytest

from alt_deploy.errors import ControlError
from alt_deploy.setup_plans import digest,private_replace
from test_setup_recovery_native_runtime import scenario as native_fixture
from test_setup_recovery_user_check import EMPLOYEE


def scenario(root):
    from alt_deploy.setup_recovery_user_runtime import RecoveryUserRuntime
    from alt_deploy import setup_recovery_user_check as worker,setup_recovery_backup as backup
    native,request,parent,previous,prior_calls,plan,started,headers=native_fixture(root)
    receipt=native.testjoin_once(request['plan_id'],request['plan_sha256'])
    calls=[];employee=copy.deepcopy(EMPLOYEE);scope=['a'*64]
    def authorize(plan_id,sha,sources,request_sha,started_sha,native_sha):
        return dict(schema_version=1,plan_id=plan_id,plan_sha256=sha,source_sha256=sources,
            startup_request_sha256=request_sha,startup_receipt_sha256=started_sha,native_receipt_sha256=native_sha,
            employee=copy.deepcopy(employee),user_scope_sha256=scope[0],approval_sha256=request['approval_sha256'])
    def runner(command,**options):
        calls.append((command,options));wire=json.loads(options['input_text']);selected=wire['request']
        facts=selected['startup_request']['policy_request']['kerberos_request']['import_request']['rehearsal_request']['backup_request']['facts']
        tools={key:dict(facts['tools'][key],package=package) for key,package in
            (('getent',worker.PACKAGE),('nss_sss',worker.NSS_PACKAGE))}
        result=worker._receipt(selected,dict(uid=100100,gid=100100),tools,{},backup)
        return 0,json.dumps(result),'SYNTHETIC_PRIVATE_OUTPUT'
    runtime=RecoveryUserRuntime(native_runtime=native,authorization=authorize,runner=runner)
    return runtime,request,calls,native,receipt,parent,employee,scope


def test_user_lookup_is_sent_once_and_verify_uses_retained_receipt(tmp_path):
    runtime,request,calls,native,receipt,parent,employee,scope=scenario(tmp_path)
    result=runtime.check_once(request['plan_id'],request['plan_sha256'])
    assert result['user_lookup'] is True and result['login_verified'] is False
    assert result['online_user_authentication_verified'] is False and result['employee']==employee
    command,options=calls[0];value=json.loads(options['input_text'])
    assert command[:3]==['/usr/bin/ssh','-F','/dev/null'] and 'StrictHostKeyChecking=yes' in command
    assert value['action']=='check' and value['request']['native_receipt']==receipt
    assert len(command[-1].encode())<8192
    with pytest.raises(ControlError):runtime.check_once(request['plan_id'],request['plan_sha256'])
    assert len(calls)==1
    assert runtime.verify(request['plan_id'],request['plan_sha256'])==result
    assert json.loads(calls[-1][1]['input_text'])['action']=='verify'


@pytest.mark.parametrize('change',['approval','extra','employee','sources','native_intent','native_result','native_failed'])
def test_unbound_user_runtime_refuses_before_ssh(tmp_path,change,monkeypatch):
    runtime,request,calls,native,receipt,parent,employee,scope=scenario(tmp_path)
    if change in ('approval','extra'):
        previous=runtime.authorization
        def changed(*args):
            value=previous(*args);value['approval_sha256' if change=='approval' else 'command']='changed';return value
        runtime.authorization=changed
    elif change=='employee':employee['upn']='other@sosnadmin.local'
    elif change=='sources':monkeypatch.setattr(runtime,'_sources',lambda:['changed']*14)
    else:
        suffix={'native_intent':'.native-testjoin-intent.json','native_result':'.native-testjoin-result.json','native_failed':'.native-testjoin-failed.json'}[change]
        private_replace(native.attempts._path(**parent['pair'],suffix=suffix),{})
    with pytest.raises(ControlError):runtime.check_once(request['plan_id'],request['plan_sha256'])
    assert calls==[]


@pytest.mark.parametrize('change',['rc','duplicate','oversize','login_claim','online_claim','tool','uid','native_after','scope_after'])
def test_entered_user_failure_is_redacted_and_permanently_excludes_replay(tmp_path,change):
    runtime,request,calls,native,receipt,parent,employee,scope=scenario(tmp_path);previous=runtime.runner
    def changed(command,**options):
        rc,out,err=previous(command,**options)
        if change=='rc':rc=1
        elif change=='duplicate':out=out[:-1]+',"schema_version":1}'
        elif change=='oversize':out=' '*(16384+1)
        elif change in ('login_claim','online_claim','tool','uid'):
            value=json.loads(out)
            key={'login_claim':'login_verified','online_claim':'online_user_authentication_verified','tool':'getent_sha256','uid':'uid'}[change]
            value[key]='0'*64 if change=='tool' else (0 if change=='uid' else True);out=json.dumps(value)
        elif change=='scope_after':scope[0]='b'*64
        else:private_replace(native.attempts._path(**parent['pair'],suffix='.native-testjoin-result.json'),{})
        return rc,out,err
    runtime.runner=changed
    with pytest.raises(ControlError) as caught:runtime.check_once(request['plan_id'],request['plan_sha256'])
    assert 'SYNTHETIC_PRIVATE_OUTPUT' not in str(caught.value)
    assert runtime.attempts._path(**parent['pair'],suffix='.user-check-failed.json').exists()
    with pytest.raises(ControlError):runtime.check_once(request['plan_id'],request['plan_sha256'])
    assert len(calls)==1


def test_user_runtime_requires_explicit_authority(tmp_path):
    from alt_deploy.setup_recovery_user_runtime import RecoveryUserRuntime
    with pytest.raises(ValueError):RecoveryUserRuntime(native_runtime=None,authorization=None)


@pytest.mark.parametrize('change',['native_result','user_failed','user_intent','protected','sources'])
def test_last_authority_callback_cannot_change_evidence_before_ssh(tmp_path,change,monkeypatch):
    runtime,request,calls,native,receipt,parent,employee,scope=scenario(tmp_path)
    previous=runtime.authorization;observed=[]
    def changed(*args):
        value=previous(*args);observed.append(True)
        if len(observed)==4:
            if change=='sources':monkeypatch.setattr(runtime,'_sources',lambda:['changed']*14)
            elif change=='protected':
                postwrite=native.startup_runtime.policy_runtime.kerberos_runtime.import_runtime.postwrite
                postwrite.fixture_protected['credential_document']={'schema_version':1,'sha256':'c'*64}
            else:
                suffix={'native_result':'.native-testjoin-result.json','user_failed':'.user-check-failed.json','user_intent':'.user-check-intent.json'}[change]
                private_replace(runtime.attempts._path(**parent['pair'],suffix=suffix),{})
        return value
    runtime.authorization=changed
    with pytest.raises(ControlError):runtime.check_once(request['plan_id'],request['plan_sha256'])
    assert calls==[]
