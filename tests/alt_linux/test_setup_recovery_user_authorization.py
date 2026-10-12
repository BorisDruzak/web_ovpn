from __future__ import annotations

import copy
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from alt_deploy.errors import ControlError
from alt_deploy.setup_plans import digest,private_replace
from test_setup_recovery_user_scope import fixture as scope_fixture


def scenario(root,*,user_check=True):
    import test_setup_recovery_native_authorization as fixture
    from alt_deploy import setup_recovery_native_testjoin as worker,setup_recovery_backup as backup
    from alt_deploy.setup_recovery_native_runtime import RecoveryNativeRuntime
    with patch.object(fixture,'scenario',scope_fixture):
        native,arguments,gate,context,started,attachment,protected=fixture.native_fixture(root,user_check=user_check)
    request=context['request'];pair=context['pair'];plans=gate.plans
    tools=copy.deepcopy(plans._base(arguments[0],arguments[1])['plan']['payload']['snapshot']['workstation_facts']['snapshot']['tools'])
    for path,package in worker.TOOLS.items():
        tools[path.rsplit('/',1)[1]]=dict(present=True,sha256='b'*64,size=100,uid=0,gid=0,mode=0o755,package=package)
    request['policy_request']['kerberos_request']['import_request']['rehearsal_request']={'backup_request':{'facts':{'tools':tools}}}
    started['request_sha256']=digest(request)
    intent=dict(schema_version=1,plan_id=arguments[0],plan_sha256=arguments[1],request_sha256=digest(request),
        policy_receipt_sha256=digest(request['policy_receipt']),services_receipt_sha256=digest(request['service_receipt']),
        approval_sha256=request['approval_sha256'],effects_ledger_sha256=request['effects_ledger_sha256'])
    attempts=gate.preparation.attempts
    for suffix,value in (('.sssd-start-intent.json',intent),('.sssd-start-result.json',started)):
        private_replace(attempts._path(**pair,suffix=suffix),value)
    arguments=(arguments[0],arguments[1],digest(plans._native_sources()),digest(request),digest(started))
    def current(*values):
        return dict(pair=pair,address='192.0.2.10',request=copy.deepcopy(request),started=copy.deepcopy(started),
            sources=plans._native_sources(),authorization=native(*arguments))
    runtime=SimpleNamespace(authorization=native,startup_runtime=native.startup_runtime,_context=current,_receipt=RecoveryNativeRuntime._receipt,
        attempts=attempts,_sources=plans._native_sources)
    ctx=current();mapped={path:dict(tools[path.rsplit('/',1)[1]],package=package) for path,package in worker.TOOLS.items()}
    result=worker._receipt(request,started,mapped,backup)
    intended=dict(schema_version=1,plan_id=arguments[0],plan_sha256=arguments[1],request_sha256=digest(request),
        startup_receipt_sha256=digest(started),sources_sha256=digest(ctx['sources']),authorization_sha256=digest(ctx['authorization']))
    for suffix,value in (('.native-testjoin-intent.json',intended),('.native-testjoin-result.json',result)):
        private_replace(attempts._path(**pair,suffix=suffix),value)
    from alt_deploy.setup_recovery_user_authorization import RecoveryUserAuthorization
    authorization=RecoveryUserAuthorization(native_runtime=runtime)
    args=(arguments[0],arguments[1],digest(plans._user_sources()),digest(request),digest(started),digest(result))
    return authorization,args,gate,runtime,ctx,result,attachment,protected


def test_user_gate_requires_confirmed_scope_native_proof_and_same_employee(tmp_path):
    authorization,args,gate,runtime,ctx,result,attachment,protected=scenario(tmp_path)
    value=authorization(*args)
    assert value['approval_sha256']==attachment['sha256']==ctx['request']['approval_sha256']
    assert value['employee']==attachment['payload']['user_check']['employee']
    assert value['user_scope_sha256']==digest(attachment['payload']['user_check'])
    assert value['native_receipt_sha256']==digest(result) and value['source_sha256']==args[2]
    assert value['startup_request_sha256']==args[3] and value['startup_receipt_sha256']==args[4]


def test_native_only_confirmation_cannot_authorize_user_lookup(tmp_path):
    authorization,args,*_=scenario(tmp_path,user_check=False)
    with pytest.raises(ControlError):authorization(*args)


@pytest.mark.parametrize('change',['source','request','started','native','employee','disabled','dependencies',
    'native_intent','native_result','native_failed','revoked','protected_after'])
def test_user_gate_refuses_unbound_or_changed_evidence(tmp_path,change):
    authorization,args,gate,runtime,ctx,result,attachment,protected=scenario(tmp_path);args=list(args)
    if change in ('source','request','started','native'):args[{'source':2,'request':3,'started':4,'native':5}[change]]='0'*64
    elif change in ('employee','disabled'):
        current=gate.postwrite.directory.user(attachment['payload']['user_check']['employee']['login'])
        current['object_guid' if change=='employee' else 'state']='changed' if change=='employee' else 'disabled'
    elif change=='dependencies':
        previous=runtime._context
        def changed(*values):
            value=previous(*values)
            value['request']['policy_request']['kerberos_request']['import_request']['rehearsal_request']['backup_request']['facts']['tools']['getent']['sha256']='c'*64
            return value
        runtime._context=changed
    elif change=='protected_after':
        previous=runtime._context;calls=[]
        def changed(*values):
            value=previous(*values);calls.append(True)
            if len(calls)==2:protected['credential_document']={'schema_version':1,'sha256':'c'*64}
            return value
        runtime._context=changed
    elif change=='revoked':private_replace(gate._marker(gate._load(args[0],args[1])['base']['plan'],'revoked'),{})
    else:
        suffix={'native_intent':'.native-testjoin-intent.json','native_result':'.native-testjoin-result.json','native_failed':'.native-testjoin-failed.json'}[change]
        private_replace(runtime.attempts._path(**ctx['pair'],suffix=suffix),{})
    with pytest.raises(ControlError):authorization(*args)
