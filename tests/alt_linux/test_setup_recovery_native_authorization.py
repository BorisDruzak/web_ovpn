from __future__ import annotations

import copy

import pytest

from alt_deploy.errors import ControlError
from alt_deploy.setup_plans import digest
from alt_deploy.setup_plans import private_replace
from test_setup_recovery_startup_authorization import scenario,reserve


def test_native_scope_is_explicit_and_old_startup_approval_remains_start_only(tmp_path):
    gate,plans,preparation,planning,recovery,old,paths,ledger,unit,protected=scenario(tmp_path)
    before={key:path.read_bytes() for key,path in paths.items()}
    new=plans.create(recovery['plan_id'],recovery['sha256'],sssd_unit=unit,effects_ledger=ledger,native_check=True)
    assert 'native_check' not in old['payload']
    assert new['payload']['scope']=='one_fixed_sssd_start_and_native_check_with_retained_temporary_policy'
    scope=new['payload']['native_check']
    assert scope['operation']=='fixed_native_testjoin_once' and scope['trust_verified'] is False
    assert scope['peer_pinning_verified'] is False
    assert scope['source_sha256']==digest(plans._native_sources())
    assert {key:path.read_bytes() for key,path in paths.items()}==before
    assert plans.load(new['plan_id'],new['sha256'],recovery['plan_id'],recovery['sha256'])['attachment']==new


@pytest.mark.parametrize('flag',[None,1,'yes',{},[]])
def test_native_scope_requires_explicit_boolean_selection(tmp_path,flag):
    _,plans,_,_,recovery,_,_,ledger,unit,_=scenario(tmp_path)
    with pytest.raises(ControlError):plans.create(recovery['plan_id'],recovery['sha256'],sssd_unit=unit,effects_ledger=ledger,native_check=flag)


def test_start_only_confirmed_binding_cannot_authorize_native_check(tmp_path):
    from alt_deploy.setup_recovery_native_authorization import RecoveryNativeAuthorization
    gate,plans,_,_,recovery,attachment,_,_,_,protected=scenario(tmp_path)
    gate.bind_once(recovery['plan_id'],recovery['sha256']);reserve(gate,recovery,protected)
    from types import SimpleNamespace
    authorization=RecoveryNativeAuthorization(startup_authorization=gate,startup_runtime=SimpleNamespace(authorization=gate))
    with pytest.raises(ControlError):authorization(recovery['plan_id'],recovery['sha256'],digest(plans._sources()),'1'*64,'2'*64)


def native_fixture(root,*,user_check=False):
    from types import SimpleNamespace
    from alt_deploy.setup_recovery_startup_authorization import RecoveryStartupAuthorization
    from alt_deploy.setup_recovery_native_authorization import RecoveryNativeAuthorization
    from alt_deploy.setup_recovery_sssd_start_runtime import RecoverySSSDStartRuntime
    from alt_deploy import setup_recovery_sssd_start as start,setup_recovery_backup as backup
    _,plans,preparation,_,recovery,_,_,ledger,unit,protected=scenario(root)
    attachment=plans.create(recovery['plan_id'],recovery['sha256'],sssd_unit=unit,effects_ledger=ledger,native_check=True,user_check=user_check)
    postwrite=SimpleNamespace(directory=plans.planning.directory,load=lambda *a:dict(copy.deepcopy(protected),machine=None),
        _protected=lambda *a:(copy.deepcopy(protected),None))
    postwrite._directory_config=lambda expected:('gssapi','join-vault',128,expected['dc']['uri'])
    gate=RecoveryStartupAuthorization(preparation=preparation,postwrite=postwrite,plans=plans,
        startup_plan_id=attachment['plan_id'],confirmed_startup_sha=attachment['sha256'])
    gate.bind_once(recovery['plan_id'],recovery['sha256']);reserve(gate,recovery,protected)
    pair=gate._pair(recovery);approved=gate(recovery['plan_id'],recovery['sha256'],digest(plans._sources()))
    original={key:recovery['payload'][key] for key in ('failed_run_id','computer_guid','computer_sid','machine_uuid')}
    original['kvno']=3
    protected['directory_result']=copy.deepcopy(original)
    request=dict(policy_request={'kerberos_request':{'import_request':{'directory_result':original}}},
        policy_receipt={},service_receipt={},sssd_unit=unit,source_sha256=digest(plans._sources()),
        approval_sha256=approved['approval_sha256'],effects_ledger_sha256=approved['effects_ledger_sha256'])
    state=copy.deepcopy(unit);state['properties'].update(ActiveState='active',SubState='running',MainPID='123',InvocationID='a'*32)
    result=start._receipt(request,state,backup)
    intent=dict(schema_version=1,plan_id=recovery['plan_id'],plan_sha256=recovery['sha256'],request_sha256=digest(request),
        policy_receipt_sha256=digest(request['policy_receipt']),services_receipt_sha256=digest(request['service_receipt']),
        approval_sha256=approved['approval_sha256'],effects_ledger_sha256=approved['effects_ledger_sha256'])
    for suffix,value in (('.sssd-start-intent.json',intent),('.sssd-start-result.json',result)):
        private_replace(preparation.attempts._path(**pair,suffix=suffix),value)
    context=dict(pair=pair,request=request,sources=plans._sources(),authorization=approved,
        policy_context={'kerberos_context':{'import_context':{'protected':protected}}})
    runtime=SimpleNamespace(authorization=gate,_context=lambda *a:copy.deepcopy(context),_receipt=RecoverySSSDStartRuntime._receipt)
    authorization=RecoveryNativeAuthorization(startup_authorization=gate,startup_runtime=runtime)
    arguments=(recovery['plan_id'],recovery['sha256'],digest(plans._native_sources()),digest(request),digest(result))
    return authorization,arguments,gate,context,result,attachment,protected


def test_explicit_native_gate_uses_same_confirmed_pair_and_retained_startup_hashes(tmp_path):
    authorization,arguments,gate,context,result,attachment,protected=native_fixture(tmp_path)
    value=authorization(*arguments)
    assert value['approval_sha256']==attachment['sha256']==value['startup_approval_sha256']
    assert value['source_sha256']==arguments[2] and value['startup_request_sha256']==arguments[3]
    assert value['startup_receipt_sha256']==arguments[4]
    assert value['effects_ledger_sha256']==context['request']['effects_ledger_sha256']


@pytest.mark.parametrize('change',['sources','request','receipt','context','protected','result','revoked'])
def test_native_gate_refuses_unbound_or_revoked_inputs(tmp_path,change):
    authorization,arguments,gate,context,result,attachment,protected=native_fixture(tmp_path)
    arguments=list(arguments)
    if change in ('sources','request','receipt'):arguments[{'sources':2,'request':3,'receipt':4}[change]]='0'*64
    elif change=='context':context['authorization']['approval_sha256']='0'*64
    elif change=='protected':protected['claim']['plan_sha256']='0'*64
    elif change=='result':
        result['main_pid']=0
        private_replace(gate.preparation.attempts._path(**gate._pair(gate._load(arguments[0],arguments[1])['base']['plan']),suffix='.sssd-start-result.json'),result)
    else:private_replace(gate._marker(gate._load(arguments[0],arguments[1])['base']['plan'],'revoked'),{})
    with pytest.raises(ControlError):authorization(*arguments)
