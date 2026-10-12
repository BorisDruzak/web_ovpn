from __future__ import annotations

import copy
from unittest.mock import patch

import pytest

from alt_deploy.errors import ControlError
from alt_deploy.setup_plans import digest
from test_setup_recovery_startup_authorization import scenario


def fixture(root):
    import test_setup_recovery_prepare as preparation
    original=preparation.planning_scenario
    def dependencies(directory):
        values=original(directory);facts=values[7]
        facts['snapshot']['tools']={name:dict(present=True,sha256='a'*64,size=100,
            uid=0,gid=0,mode=0o755,package=package) for name,package in
            (('getent','glibc-utils 2.38.0.223.f053ff-alt1.p11.1'),('nss_sss','sssd-client 2.9.8-alt3'))}
        facts['snapshot_sha256']=digest(facts['snapshot'])
        return values
    with patch.object(preparation,'planning_scenario',dependencies):return scenario(root)


def create(plans,recovery,unit,ledger,**flags):
    return plans.create(recovery['plan_id'],recovery['sha256'],sssd_unit=unit,effects_ledger=ledger,**flags)


def test_user_scope_is_explicit_complete_and_old_approvals_remain_unchanged(tmp_path):
    gate,plans,_,_,recovery,old,paths,ledger,unit,_=fixture(tmp_path)
    original={name:path.read_bytes() for name,path in paths.items()}
    native=create(plans,recovery,unit,ledger,native_check=True)
    selected=create(plans,recovery,unit,ledger,native_check=True,user_check=True)
    assert 'user_check' not in old['payload'] and 'user_check' not in native['payload']
    value=selected['payload']['user_check']
    assert selected['payload']['scope']=='one_fixed_sssd_start_native_and_user_check_with_retained_temporary_policy'
    user=recovery['payload']['snapshot']['user']
    assert value['employee']=={key:user[key] for key in ('object_guid','object_sid','login','upn')}
    assert value['source_sha256']==digest(plans._user_sources())
    assert len(plans._user_sources())==14 and plans._user_sources()[:-1]==plans._native_sources()
    assert value['argv']==['/usr/bin/getent','-s','sss','passwd',user['upn']]
    assert value['login_verified'] is False and value['online_user_authentication_verified'] is False
    assert value['dependencies']==recovery['payload']['snapshot']['workstation_facts']['snapshot']['tools']
    assert plans.load(selected['plan_id'],selected['sha256'],recovery['plan_id'],recovery['sha256'])['attachment']==selected
    assert {name:path.read_bytes() for name,path in paths.items()}==original
    assert not plans.planning.attempts.claim_path(**gate._pair(recovery)).exists()


@pytest.mark.parametrize('flag',[None,1,'yes',{},[]])
def test_user_scope_refuses_nonboolean_selection(tmp_path,flag):
    _,plans,_,_,recovery,_,_,ledger,unit,_=fixture(tmp_path)
    before=set(plans.store.root.iterdir())
    with pytest.raises(ControlError):create(plans,recovery,unit,ledger,native_check=True,user_check=flag)
    assert set(plans.store.root.iterdir())==before


def test_user_scope_requires_native_check(tmp_path):
    _,plans,_,_,recovery,_,_,ledger,unit,_=fixture(tmp_path)
    with pytest.raises(ControlError):create(plans,recovery,unit,ledger,user_check=True)


def test_native_gate_retains_its_scope_inside_explicit_user_attachment(tmp_path):
    import test_setup_recovery_native_authorization as native_fixture
    with patch.object(native_fixture,'scenario',fixture):
        authorization,arguments,gate,context,result,attachment,protected=native_fixture.native_fixture(tmp_path,user_check=True)
    value=authorization(*arguments)
    assert value['approval_sha256']==attachment['sha256']
    assert value['source_sha256']==attachment['payload']['native_check']['source_sha256']
    assert 'user_check' in attachment['payload']


@pytest.mark.parametrize('change',['state','object_guid','object_sid','login','upn','late_state'])
def test_user_attachment_requires_fresh_enabled_same_ad_employee(tmp_path,change):
    import test_setup_recovery_native_authorization as native_fixture
    with patch.object(native_fixture,'scenario',fixture):
        authorization,arguments,gate,context,result,attachment,protected=native_fixture.native_fixture(tmp_path,user_check=True)
    directory=gate.postwrite.directory
    current=copy.deepcopy(directory.user(attachment['payload']['user_check']['employee']['login']))
    if change=='late_state':
        original=gate.postwrite._protected
        def changed(*args):
            value=original(*args);current['state']='disabled';return value
        gate.postwrite._protected=changed
    else:current[change]='disabled' if change=='state' else 'changed'
    directory.user=lambda login:copy.deepcopy(current)
    with pytest.raises(ControlError):authorization(*arguments)


@pytest.mark.parametrize('change',['ad_result','credential'])
def test_final_employee_callback_cannot_change_protected_context(tmp_path,change):
    import test_setup_recovery_native_authorization as native_fixture
    with patch.object(native_fixture,'scenario',fixture):
        authorization,arguments,gate,context,result,attachment,protected=native_fixture.native_fixture(tmp_path,user_check=True)
    directory=gate.postwrite.directory;previous=directory.user;calls=[]
    def changed(login):
        value=copy.deepcopy(previous(login));calls.append(login)
        if len(calls)==2:
            if change=='ad_result':protected['directory_result']['kvno']+=1
            else:protected['credential_document']={'schema_version':1,'sha256':'b'*64}
        return value
    directory.user=changed
    with pytest.raises(ControlError):authorization(*arguments)
    assert len(calls)==2


@pytest.mark.parametrize('change',['missing','package','owner','mode','hash','size','employee','source'])
def test_unreviewed_user_dependencies_fail_before_plan(tmp_path,change,monkeypatch):
    _,plans,_,_,recovery,_,_,ledger,unit,_=fixture(tmp_path)
    base=copy.deepcopy(plans._base(recovery['plan_id'],recovery['sha256']))
    tools=base['plan']['payload']['snapshot']['workstation_facts']['snapshot']['tools']
    if change=='missing':del tools['nss_sss']
    elif change=='package':tools['nss_sss']['package']='unreviewed'
    elif change=='owner':tools['nss_sss']['uid']=1
    elif change=='mode':tools['nss_sss']['mode']=0o777
    elif change=='hash':tools['nss_sss']['sha256']='invalid'
    elif change=='size':tools['nss_sss']['size']=True
    elif change=='employee':base['plan']['payload']['snapshot']['user']['upn']='other@sosnadmin.local'
    else:monkeypatch.setattr(plans,'_user_sources',lambda:['changed']*14)
    with pytest.raises(ValueError):plans._user_scope(base)


@pytest.mark.parametrize('change',['employee','dependencies','scope','source','extra','missing_native'])
def test_modified_user_attachment_is_rejected(tmp_path,change):
    _,plans,_,_,recovery,_,_,ledger,unit,_=fixture(tmp_path)
    selected=create(plans,recovery,unit,ledger,native_check=True,user_check=True)
    payload=copy.deepcopy(selected['payload'])
    if change=='scope':payload['scope']='one_fixed_sssd_start_and_native_check_with_retained_temporary_policy'
    elif change=='missing_native':del payload['native_check']
    elif change=='extra':payload['user_check']['command']='anything'
    elif change=='employee':payload['user_check']['employee']['object_guid']='00000000-0000-0000-0000-000000000000'
    elif change=='dependencies':payload['user_check']['dependencies']['getent']['sha256']='b'*64
    else:payload['user_check']['source_sha256']='b'*64
    forged=plans.store.create(payload)
    with pytest.raises(ValueError):plans.load(forged['plan_id'],forged['sha256'],recovery['plan_id'],recovery['sha256'])

def test_scope_accepts_stock_readonly_nss_library_while_getent_stays_executable(tmp_path):
    _,plans,_,_,recovery,_,_,ledger,unit,_=fixture(tmp_path)
    base=copy.deepcopy(plans._base(recovery['plan_id'],recovery['sha256']))
    tools=base['plan']['payload']['snapshot']['workstation_facts']['snapshot']['tools']
    tools['nss_sss']['mode']=0o644
    scope=plans._user_scope(base)
    assert scope['dependencies']['nss_sss']['mode']==0o644
    tools['getent']['mode']=0o644
    with pytest.raises(ValueError):plans._user_scope(base)

@pytest.mark.parametrize('mode',[0o111,0o664,0o666])
def test_scope_rejects_unreadable_or_writable_nss_module(tmp_path,mode):
    _,plans,_,_,recovery,_,_,ledger,unit,_=fixture(tmp_path)
    base=copy.deepcopy(plans._base(recovery['plan_id'],recovery['sha256']))
    base['plan']['payload']['snapshot']['workstation_facts']['snapshot']['tools']['nss_sss']['mode']=mode
    with pytest.raises(ValueError):plans._user_scope(base)
