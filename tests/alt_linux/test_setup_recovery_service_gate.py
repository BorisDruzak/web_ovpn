from __future__ import annotations

import copy

import pytest

from alt_deploy.errors import ControlError
from alt_deploy.setup_plans import digest, private_read, private_replace
from test_setup_recovery_prewrite import scenario as fixture


def scenario(root):
    from alt_deploy.setup_recovery_service_gate import RecoveryServiceGate
    from alt_deploy import setup_recovery_services as services
    # Extend the planning fixture before it seals its plan: the real service
    # request requires all five file records, unlike the minimal planner mock.
    from unittest.mock import patch
    import test_setup_recovery_reserved_state as reserved
    from alt_deploy import setup_recovery_backup as backup
    planning=reserved.planning_scenario
    def complete(*args,**kwargs):
        result=planning(*args,**kwargs);facts=result[7]
        facts['snapshot']['files']={path:{'present':False} for path in backup.AUTH_FILES}
        facts['snapshot_sha256']=digest(facts['snapshot'])
        return result
    with patch.object(reserved,'planning_scenario',complete):
        base,payload,claim,sealed,password,record,credentials,paths,calls=fixture(root)
    snapshot=dict(schema_version=1,machine_uuid=payload['machine_uuid'],
        hostname=record['backup_request']['hostname'],systemctl={},systemd_package='systemd 258.9-alt1',dependencies={},
        units={unit:dict(unit_file={},properties={name:('active' if name=='ActiveState' else '') for name in services.PROPERTIES}) for unit in services.UNITS})
    request=dict(schema_version=1,backup_request=record['backup_request'],backup_receipt=record['workstation_backup'],
        services=snapshot,services_sha256=digest(snapshot),source_sha256='e'*64)
    remote_receipt=services._receipt(request,backup=backup)
    remote_calls=[]
    class Runtime:
        def capture_services(self,*args,**kw):remote_calls.append('capture');return copy.deepcopy(snapshot)
        def quiesce_services(self,*args,**kw):remote_calls.append('quiesce');return copy.deepcopy(remote_receipt)
        def verify_services(self,*args,**kw):remote_calls.append('verify');return copy.deepcopy(remote_receipt)
    settings=base.controller.fresh_check.planning.settings
    settings.lock_file=root/'workstationctl.lock'
    gate=RecoveryServiceGate(settings,base,runtime=Runtime())
    args=(payload,claim,sealed,password)
    return gate,args,record,snapshot,remote_receipt,remote_calls,paths


def test_prepared_services_are_captured_quiesced_and_verified_before_writer(tmp_path):
    gate,args,record,snapshot,receipt,calls,paths=scenario(tmp_path)
    before={key:path.read_bytes() for key,path in paths.items()}
    prepared=gate.prepare(*args)
    assert prepared['status']=='recovery_services_prepared'
    assert calls==['capture']
    assert gate.quiesce(*args)==receipt
    proof=gate(*args)
    assert proof['services_quiesced_verified'] is True
    assert proof['services_quiesced_sha256']==digest(receipt)
    from alt_deploy.setup_recovery_provider import RecoveryPasswordProvider
    RecoveryPasswordProvider._preparation(args[0],args[1],args[2],proof)
    assert {key:path.read_bytes() for key,path in paths.items()}==before
    assert args[3] not in str(proof)
    with pytest.raises(ControlError):gate.prepare(*args)
    with pytest.raises(ControlError):gate.quiesce(*args)
    assert calls.count('quiesce')==1


@pytest.mark.parametrize('failure',['missing_record','missing_ready','missing_receipt','record','ready','receipt','remote','record_after','history_after'])
def test_missing_changed_or_restarted_services_refuse_prewrite(tmp_path,failure):
    gate,args,record,snapshot,receipt,calls,paths=scenario(tmp_path)
    gate.prepare(*args);gate.quiesce(*args)
    path=gate.path(args[0],'.services-preparation.json')
    if failure=='missing_record':path.unlink()
    elif failure=='missing_ready':gate.path(args[0],'.services-ready.json').unlink()
    elif failure=='missing_receipt':gate.path(args[0],'.services-quiesced.json').unlink()
    elif failure=='record':
        value=private_read(path);value['services_sha256']='f'*64;private_replace(path,value)
    elif failure=='ready':private_replace(gate.path(args[0],'.services-ready.json'),{'schema_version':1,'services_preparation_sha256':'f'*64})
    elif failure=='receipt':
        value=private_read(gate.path(args[0],'.services-quiesced.json'));value['claim_sha256']='f'*64
        private_replace(gate.path(args[0],'.services-quiesced.json'),value)
    else:
        original=gate.runtime.verify_services
        def changed(*a,**kw):
            result=original(*a,**kw)
            if failure=='remote':raise RuntimeError('SYNTHETIC_SECRET')
            elif failure=='record_after':
                value=private_read(path);value['preparation_sha256']='f'*64;private_replace(path,value)
            else:
                value=private_read(paths['run']);value['reboot_required']=False;private_replace(paths['run'],value)
            return result
        gate.runtime.verify_services=changed
    with pytest.raises(ControlError) as caught:gate(*args)
    assert 'SYNTHETIC_SECRET' not in str(caught.value)


@pytest.mark.parametrize('failure',['remote','receipt','persistence','history'])
def test_partial_quiescence_is_terminal_and_never_replayed(tmp_path,monkeypatch,failure):
    import alt_deploy.setup_recovery_service_gate as module
    gate,args,record,snapshot,receipt,calls,paths=scenario(tmp_path)
    gate.prepare(*args)
    original=gate.runtime.quiesce_services
    def changed(*a,**kw):
        result=original(*a,**kw)
        if failure=='remote':raise RuntimeError('SYNTHETIC_SECRET')
        elif failure=='receipt':return {}
        elif failure=='history':
            value=private_read(paths['run']);value['reboot_required']=False;private_replace(paths['run'],value)
        return result
    gate.runtime.quiesce_services=changed
    persist=module.RecoveryControllerBackup._persist
    if failure=='persistence':
        def broken(path,value):
            if path.name.endswith('.services-quiesced.json'):raise OSError('SYNTHETIC_SECRET')
            return persist(path,value)
        monkeypatch.setattr(module.RecoveryControllerBackup,'_persist',broken)
    with pytest.raises(ControlError) as caught:gate.quiesce(*args)
    assert 'SYNTHETIC_SECRET' not in str(caught.value)
    assert gate.path(args[0],'.services-stop-intent.json').exists()
    assert private_read(gate.preparation.attempts._path(args[0]['failed_run_id'],args[0]['computer_guid'],'.receipt.json'))['status']=='failed'
    with pytest.raises(ControlError):gate.quiesce(*args)
    assert calls.count('quiesce')==1


@pytest.mark.parametrize('changed',[False,True,'authentication','final_open','last_cipher','last_preparation_ready'])
def test_real_provider_requires_live_service_gate_for_its_single_guid_write(tmp_path,changed):
    from contextlib import contextmanager
    from types import SimpleNamespace
    from alt_deploy.setup_recovery_provider import RecoveryPasswordProvider
    gate,args,record,snapshot,receipt,calls,paths=scenario(tmp_path)
    gate.prepare(*args);gate.quiesce(*args)
    payload,claim,sealed,password=args
    base=gate.preparation;service=base.controller.fresh_check.planning
    computer=copy.deepcopy(payload['snapshot']['computer'])
    service.directory.inspect_computer=lambda hostname,guid:copy.deepcopy(computer)
    @contextmanager
    def authentication(environment):
        if changed=='authentication':gate.runtime.verify_services=lambda *a,**kw:{}
        yield environment,[]
    service.directory.transport=SimpleNamespace(minimum_ssf=128,_credentials=authentication,
        config=SimpleNamespace(auth='gssapi',credential_source='join-vault',uri=computer['dc']['uri']))
    writes=[]
    def writer(command,**kwargs):
        writes.append(command);computer['kvno']+=1;computer['pwd_last_set']+=10000000
        return 0,'',''
    if changed is True:gate.runtime.verify_services=lambda *a,**kw:{}
    if changed in ('last_cipher','last_preparation_ready'):
        original_verify=gate.runtime.verify_services
        def altered_verify(*a,**kw):
            result=original_verify(*a,**kw)
            pair={key:payload[key] for key in ('failed_run_id','computer_guid')}
            if provider.intent_path(**pair).exists():
                if changed=='last_preparation_ready':base.attempts._path(**pair,suffix='.preparation-ready.json').unlink()
                else:
                    path=base.credentials.path(**pair);document=private_read(path)
                    document['ciphertext']='SYNTHETIC_BROKEN_CIPHERTEXT';private_replace(path,document)
                    ready_path=base.credentials._ready_path(**pair);ready=private_read(ready_path)
                    ready['document_sha256']=digest(document);private_replace(ready_path,ready)
            return result
        gate.runtime.verify_services=altered_verify
    provider=RecoveryPasswordProvider(SimpleNamespace(state_root=tmp_path,lock_file=tmp_path/'workstationctl.lock'),
        directory=service.directory,credentials=base.credentials,fresh_check=base.fresh_check,prewrite=gate,
        runner=writer,fingerprint=lambda:payload['snapshot']['prerequisites']['source_sha256'],clock=service.clock)
    if changed=='final_open':
        original=base.credentials.open
        def altered(**pair):
            result=original(**pair)
            if provider.intent_path(**pair).exists():gate.runtime.verify_services=lambda *a,**kw:{}
            return result
        base.credentials.open=altered
    if changed:
        with pytest.raises(ControlError):provider.write_once(claim['plan_id'],claim['plan_sha256'])
        assert writes==[]
    else:
        assert provider.write_once(claim['plan_id'],claim['plan_sha256'])['status']=='directory_password_written'
        assert len(writes)==1


def test_changed_stop_intent_is_refused_before_remote_stop(tmp_path,monkeypatch):
    gate,args,record,snapshot,receipt,calls,paths=scenario(tmp_path)
    gate.prepare(*args);original=gate._unchanged
    def changed(*a,**kw):
        original(*a,**kw)
        private_replace(gate.path(args[0],'.services-stop-intent.json'),{'schema_version':1,'services_preparation_sha256':'f'*64})
    monkeypatch.setattr(gate,'_unchanged',changed)
    with pytest.raises(ControlError):gate.quiesce(*args)
    assert 'quiesce' not in calls


def test_capture_and_stop_transport_run_under_the_controller_lifecycle_lock(tmp_path):
    import fcntl
    import os
    gate,args,record,snapshot,receipt,calls,paths=scenario(tmp_path)
    for name in ('capture_services','quiesce_services'):
        original=getattr(gate.runtime,name)
        def checked(*a,_original=original,**kw):
            descriptor=os.open(gate.settings.lock_file,os.O_RDWR)
            try:
                with pytest.raises(BlockingIOError):fcntl.flock(descriptor,fcntl.LOCK_EX|fcntl.LOCK_NB)
            finally:os.close(descriptor)
            return _original(*a,**kw)
        setattr(gate.runtime,name,checked)
    gate.prepare(*args);gate.quiesce(*args)
