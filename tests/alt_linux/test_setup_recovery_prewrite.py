from __future__ import annotations

import copy

import pytest

from alt_deploy.errors import ControlError
from alt_deploy.setup_plans import digest, private_create, private_read, private_replace
from test_setup_recovery_controller_backup import fixture as controller_fixture


def scenario(root):
    controller,service,plan,claim,credentials,paths,calls=controller_fixture(root)
    payload=plan['payload'];pair={key:payload[key] for key in ('failed_run_id','computer_guid')}
    dc=payload['snapshot']['computer']['dc']
    document=private_read(credentials.path(**pair))
    machine=service.machines.resolve(payload['machine_uuid'])
    request=dict(pair,schema_version=1,claim_sha256=digest(claim),machine_uuid=machine.uuid,
        hostname=machine.hostname,facts=payload['snapshot']['workstation_facts']['snapshot'],
        snapshot_sha256=digest(payload['snapshot']['workstation_facts']['snapshot']),source_sha256='c'*64)
    backup={'manifest_sha256':'b'*64}
    rehearsal={'rehearsal_sha256':'d'*64}
    runtime_calls=[]
    class Runtime:
        def backup_request(self,*args,**kwargs):return copy.deepcopy(request)
        def verify_backup(self,*args,**kwargs):runtime_calls.append('backup');return copy.deepcopy(backup)
        def verify_rehearsal(self,*args,**kwargs):runtime_calls.append('rehearsal');return copy.deepcopy(rehearsal)
    from alt_deploy.setup_recovery_prewrite import RecoveryPrewriteGate
    gate=RecoveryPrewriteGate(service.settings,machines=service.machines,credentials=credentials,
        fresh_check=controller.fresh_check,controller=controller,runtime=Runtime(),plans=service.plans)
    record=dict(schema_version=1,plan_sha256=claim['plan_sha256'],claim_sha256=digest(claim),
        snapshot_sha256=digest(payload['snapshot']),sealed_sha256=document['sealed_sha256'],
        controller_backup=controller.prepare(payload),backup_request=request,workstation_backup=backup,
        rehearsal_metadata=dict(hostname=machine.hostname,realm='sosnadmin.local',workgroup='SOSNADM',
            domain_guid=dc['domain_guid'],domain_sid=dc['domain_sid'],dc_hostname=dc['dns_hostname'],dc_address='192.0.2.11'),
        local_rehearsal=rehearsal)
    record=copy.deepcopy(record)
    private_create(gate.path(payload),record)
    private_create(gate.attempts._path(**pair,suffix='.preparation-intent.json'),
        {key:record[key] for key in ('schema_version','plan_sha256','claim_sha256','snapshot_sha256','sealed_sha256')})
    private_create(gate.attempts._path(**pair,suffix='.preparation-ready.json'),
        {'schema_version':1,'preparation_sha256':digest(record)})
    sealed={'claim_sha256':digest(claim),'sealed_sha256':document['sealed_sha256']}
    password=credentials.open(**pair)
    return gate,payload,claim,sealed,password,record,credentials,paths,runtime_calls


def test_prewrite_requires_all_three_actual_verifiers_and_preserves_history(tmp_path):
    gate,payload,claim,sealed,password,record,credentials,paths,calls=scenario(tmp_path)
    originals={key:path.read_bytes() for key,path in paths.items()}
    result=gate(payload,claim,sealed,password)
    from alt_deploy.setup_recovery_provider import RecoveryPasswordProvider
    # Preparation alone no longer authorizes the password writer.
    with pytest.raises(ValueError):RecoveryPasswordProvider._preparation(payload,claim,sealed,result)
    assert calls==['backup','rehearsal']
    assert result['controller_backup_sha256']==digest(record['controller_backup'])
    assert result['workstation_backup_sha256']==digest(record['workstation_backup'])
    assert result['local_rehearsal_sha256']==digest(record['local_rehearsal'])
    assert {key:path.read_bytes() for key,path in paths.items()}==originals
    assert password not in str(result)


@pytest.mark.parametrize('changed',['schema','claim','plan','snapshot','sealed','controller','backup','rehearsal',
                                   'request','metadata','password','missing'])
def test_drift_or_missing_preparation_cannot_authorize_writing(tmp_path,changed):
    gate,payload,claim,sealed,password,record,credentials,paths,calls=scenario(tmp_path)
    if changed=='schema':record['schema_version']=True
    elif changed in ('claim','plan','snapshot','sealed'):record[changed+'_sha256']='f'*64
    elif changed=='controller':record['controller_backup']['manifest_sha256']='f'*64
    elif changed=='backup':record['workstation_backup']['manifest_sha256']='f'*64
    elif changed=='rehearsal':record['local_rehearsal']['rehearsal_sha256']='f'*64
    elif changed=='request':record['backup_request']['source_sha256']='f'*64
    elif changed=='metadata':record['rehearsal_metadata']['domain_guid']='ffffffff-ffff-ffff-ffff-ffffffffffff'
    elif changed=='password':password='Aa9!'+'x'*64
    else:gate.path(payload).unlink()
    if changed!='missing':private_replace(gate.path(payload),record)
    with pytest.raises(ControlError):gate(payload,claim,sealed,password)


def test_original_history_drift_during_final_vault_open_is_refused(tmp_path):
    gate,payload,claim,sealed,password,record,credentials,paths,calls=scenario(tmp_path)
    original=credentials.open;count=[0]
    def changed(**pair):
        result=original(**pair);count[0]+=1
        if count[0]==2:
            doc=private_read(paths['run']);doc['reboot_required']=False;private_replace(paths['run'],doc)
        return result
    credentials.open=changed
    with pytest.raises(ControlError):gate(payload,claim,sealed,password)


def test_record_drift_during_remote_verification_is_refused(tmp_path):
    gate,payload,claim,sealed,password,record,credentials,paths,calls=scenario(tmp_path)
    original=gate.runtime.verify_rehearsal
    def changed(*args,**kwargs):
        result=original(*args,**kwargs)
        doc=private_read(gate.path(payload));doc['sealed_sha256']='f'*64;private_replace(gate.path(payload),doc)
        return result
    gate.runtime.verify_rehearsal=changed
    with pytest.raises(ControlError):gate(payload,claim,sealed,password)


@pytest.mark.parametrize('marker',['intent','ready'])
def test_missing_preparation_marker_cannot_authorize_writing(tmp_path,marker):
    gate,payload,claim,sealed,password,record,credentials,paths,calls=scenario(tmp_path)
    pair={key:payload[key] for key in ('failed_run_id','computer_guid')}
    gate.attempts._path(**pair,suffix='.preparation-'+marker+'.json').unlink()
    with pytest.raises(ControlError):gate(payload,claim,sealed,password)
    assert calls==[]


@pytest.mark.parametrize('changed',[False,True])
def test_real_provider_requires_verified_gate_before_single_guid_write(tmp_path,changed):
    from contextlib import contextmanager
    from types import SimpleNamespace
    from alt_deploy.setup_recovery_provider import RecoveryPasswordProvider
    gate,payload,claim,sealed,password,record,credentials,paths,calls=scenario(tmp_path)
    service=gate.controller.fresh_check.planning
    computer=service.directory.inspect_computer(payload['snapshot']['machine']['hostname'],payload['computer_guid'])
    @contextmanager
    def authentication(environment):yield environment,[]
    service.directory.transport=SimpleNamespace(minimum_ssf=128,_credentials=authentication,
        config=SimpleNamespace(auth='gssapi',credential_source='join-vault',uri=computer['dc']['uri']))
    writes=[]
    def runner(command,**kwargs):
        writes.append(command);computer['kvno']+=1;computer['pwd_last_set']+=10000000
        return 0,'',''
    if changed:
        record['local_rehearsal']['rehearsal_sha256']='f'*64;private_replace(gate.path(payload),record)
    provider=RecoveryPasswordProvider(SimpleNamespace(state_root=tmp_path,lock_file=tmp_path/'workstationctl.lock'),
        directory=service.directory,credentials=credentials,fresh_check=gate.fresh_check,prewrite=gate,
        runner=runner,fingerprint=lambda:payload['snapshot']['prerequisites']['source_sha256'],clock=service.clock)
    # Both valid preparation and changed preparation lack service proof.
    with pytest.raises(ControlError):provider.write_once(claim['plan_id'],claim['plan_sha256'])
    assert writes==[]
