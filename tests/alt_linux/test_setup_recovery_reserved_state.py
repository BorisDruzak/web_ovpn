from __future__ import annotations

import copy
from contextlib import contextmanager
from datetime import timedelta
from types import SimpleNamespace

import pytest

from alt_deploy.errors import ControlError
from alt_deploy.setup_plans import private_read, private_replace, private_create
from alt_deploy.setup_recovery_provider import PROVIDER
from test_setup_recovery_planning import scenario as planning_scenario, COMPUTER_GUID
from test_setup_recovery_history import NOW, RUN


def scenario(root):
    build,paths,machine,user,computer,ou,observed,facts,ready,calls=planning_scenario(root)
    service=build()
    computer['dc']['uri']='ldap://synthetic-dc.sosnadmin.local'
    computer['dc'].update(dns_hostname='synthetic-dc.sosnadmin.local',
        domain_guid='11111111-2222-3333-4444-555555555555',domain_sid='S-1-5-21-111-222-333')
    computer['pwd_last_set']=134046000000000000
    snapshot=service.snapshot(RUN,COMPUTER_GUID)
    payload={key:snapshot[key] for key in ('failed_run_id','computer_guid','machine_uuid','computer_sid','evidence_sha256')}
    payload.update(execution_available=True,provider=PROVIDER,snapshot=copy.deepcopy(snapshot))
    plan=service.plans.create(payload)
    original=service.history.load(RUN)['raw_files']
    claim=service.attempts.reserve(plan['plan_id'],plan['sha256'],original)
    from alt_deploy.setup_recovery_reserved_state import RecoveryReservedState
    checker=RecoveryReservedState(service)
    return checker,service,plan,claim,paths,machine,user,computer,ou,observed,facts,ready,calls


def test_reserved_inspection_requires_exact_live_plan_and_keeps_public_exclusion(tmp_path):
    checker,service,plan,claim,paths,*_=scenario(tmp_path)
    original={key:path.read_bytes() for key,path in paths.items()}
    assert checker(plan['payload'])==plan['payload']['snapshot']
    assert private_read(service.attempts.claim_path(RUN,COMPUTER_GUID))==claim
    assert {key:path.read_bytes() for key,path in paths.items()}==original
    with pytest.raises(ControlError) as caught:service.plan(RUN,COMPUTER_GUID)
    assert caught.value.code=='recovery_attempt_reserved'
    assert not (tmp_path/'workstationctl.lock').exists()


@pytest.mark.parametrize('changed',['payload','snapshot','plan_sha','claim','evidence','terminal','intent','result','expiry'])
def test_invalid_reserved_state_fails_before_workstation_reads(tmp_path,changed):
    checker,service,plan,claim,paths,*rest=scenario(tmp_path)
    calls=rest[-1];calls.clear();payload=copy.deepcopy(plan['payload'])
    claim_path=service.attempts.claim_path(RUN,COMPUTER_GUID)
    if changed=='payload':payload['execution_available']=False
    elif changed=='snapshot':payload['snapshot']['prerequisites']['source_sha256']='f'*64
    elif changed=='plan_sha':claim['plan_sha256']='f'*64;private_replace(claim_path,claim)
    elif changed=='claim':claim['created_at']='bad';private_replace(claim_path,claim)
    elif changed=='evidence':private_replace(service.attempts.evidence_path(RUN,COMPUTER_GUID),{'changed':True})
    elif changed=='terminal':private_create(service.attempts._path(RUN,COMPUTER_GUID,'.receipt.json'),{'status':'failed'})
    elif changed in ('intent','result'):
        private_create(service.attempts._path(RUN,COMPUTER_GUID,'.ad-write-'+changed+'.json'),{'interrupted':True})
    else:service.plans.clock=lambda:NOW+timedelta(days=2)
    with pytest.raises(ControlError):checker(payload)
    assert calls==[]


@pytest.mark.parametrize('changed',['registration','user','ou','computer','facts','source','history'])
def test_current_drift_is_refused_even_for_valid_reserved_claim(tmp_path,changed):
    checker,service,plan,claim,paths,machine,user,computer,ou,observed,facts,ready,calls=scenario(tmp_path)
    if changed=='registration':machine.raw['revision']=2
    elif changed=='user':user['object_sid']='S-1-5-21-111-222-333-5555'
    elif changed=='ou':ou['object_guid']=COMPUTER_GUID
    elif changed=='computer':computer['kvno']+=1
    elif changed=='facts':facts['snapshot']['clock_synchronized']=False
    elif changed=='source':ready['source_sha256']='f'*64
    else:
        doc=private_read(paths['run']);doc['reboot_required']=False;private_replace(paths['run'],doc)
    with pytest.raises(ControlError):checker(plan['payload'])


@pytest.mark.parametrize('changed',['claim','terminal','intent','expiry'])
def test_reservation_drift_during_inspection_is_refused(tmp_path,changed):
    checker,service,plan,claim,paths,*_=scenario(tmp_path)
    original=service.runtime.facts
    def altered(machine):
        result=original(machine)
        if changed=='claim':
            claim['created_at']=(NOW+timedelta(days=1,seconds=1)).isoformat()
            private_replace(service.attempts.claim_path(RUN,COMPUTER_GUID),claim)
        elif changed=='terminal':private_create(service.attempts._path(RUN,COMPUTER_GUID,'.receipt.json'),{'status':'failed'})
        elif changed=='intent':private_create(service.attempts._path(RUN,COMPUTER_GUID,'.ad-write-intent.json'),{'interrupted':True})
        else:service.plans.clock=lambda:NOW+timedelta(days=2)
        return result
    service.runtime.facts=altered
    with pytest.raises(ControlError):checker(plan['payload'])


def test_original_history_drift_inside_final_claim_validation_is_refused(tmp_path):
    checker,service,plan,claim,paths,*_=scenario(tmp_path)
    original=checker.credentials._reservation;count=[0]
    def changed(**pair):
        result=original(**pair);count[0]+=1
        if count[0]==3:
            document=private_read(paths['run']);document['reboot_required']=False
            private_replace(paths['run'],document)
        return result
    checker.credentials._reservation=changed
    with pytest.raises(ControlError):checker(plan['payload'])


@pytest.mark.parametrize('drift',[False,True])
def test_reserved_adapter_integrates_with_one_write_provider_and_refuses_prewrite_drift(tmp_path,drift):
    from alt_deploy.setup_recovery_credential import RecoveryCredentialStore
    from alt_deploy.setup_recovery_provider import RecoveryPasswordProvider
    from alt_deploy.setup_plans import digest
    from test_setup_recovery_credential import codec_fixture
    checker,service,plan,claim,paths,machine,user,computer,ou,observed,facts,ready,calls=scenario(tmp_path)
    codec,_,_=codec_fixture(tmp_path)
    credentials=RecoveryCredentialStore(tmp_path,codec=codec)
    credentials.create(RUN,COMPUTER_GUID)
    @contextmanager
    def authentication(environment):yield environment,[]
    service.directory.transport=SimpleNamespace(minimum_ssf=128,_credentials=authentication,
        config=SimpleNamespace(auth='gssapi',credential_source='join-vault',uri=computer['dc']['uri']))
    writes=[]
    def runner(command,**kwargs):
        writes.append(command);computer['kvno']+=1;computer['pwd_last_set']+=10000000
        return 0,'',''
    def prepare(payload,reserved,sealed,password):
        if drift:computer['kvno']+=1
        return dict(schema_version=1,claim_sha256=digest(reserved),sealed_sha256=sealed['sealed_sha256'],
            snapshot_sha256=digest(payload['snapshot']),controller_backup_verified=True,
            workstation_backup_verified=True,local_rehearsal_verified=True,
            controller_backup_sha256='1'*64,workstation_backup_sha256='2'*64,local_rehearsal_sha256='3'*64)
    provider=RecoveryPasswordProvider(SimpleNamespace(state_root=tmp_path,lock_file=tmp_path/'workstationctl.lock'),
        directory=service.directory,credentials=credentials,fresh_check=checker,prewrite=prepare,
        runner=runner,fingerprint=lambda:ready['source_sha256'],clock=service.clock)
    originals={key:path.read_bytes() for key,path in paths.items()}
    if drift:
        with pytest.raises(ControlError):provider.write_once(plan['plan_id'],plan['sha256'])
        assert writes==[]
    else:
        assert provider.write_once(plan['plan_id'],plan['sha256'])['status']=='directory_password_written'
        assert len(writes)==1
        with pytest.raises(ControlError):provider.write_once(plan['plan_id'],plan['sha256'])
        with pytest.raises(ControlError):checker(plan['payload'])
    assert {key:path.read_bytes() for key,path in paths.items()}==originals
