from __future__ import annotations

import copy
import fcntl
import json

import pytest

from alt_deploy.errors import ControlError
from alt_deploy.setup_plans import digest,private_read,private_replace
from alt_deploy.setup_recovery_provider import PROVIDER
from alt_deploy.setup_recovery_credential import RecoveryCredentialStore
from test_setup_recovery_planning import scenario as planning_scenario,COMPUTER_GUID
from test_setup_recovery_history import RUN
from test_setup_recovery_credential import codec_fixture


def scenario(root):
    build,paths,machine,user,computer,ou,observed,facts,ready,calls=planning_scenario(root)
    computer['dc'].update(uri='ldap://synthetic-dc.sosnadmin.local',dns_hostname='synthetic-dc.sosnadmin.local',
        domain_guid='11111111-2222-3333-4444-555555555555',domain_sid='S-1-5-21-111-222-333')
    computer['pwd_last_set']=134046000000000000
    from alt_deploy.setup_recovery_backup import AUTH_FILES
    facts['snapshot']['files']={name:{'present':False} for name in AUTH_FILES}
    facts['snapshot_sha256']=digest(facts['snapshot'])
    service=build();service.settings.lock_file=root/'workstationctl.lock'
    snapshot=service.snapshot(RUN,COMPUTER_GUID)
    payload={key:snapshot[key] for key in ('failed_run_id','computer_guid','machine_uuid','computer_sid','evidence_sha256')}
    payload.update(execution_available=True,provider=PROVIDER,snapshot=copy.deepcopy(snapshot))
    plan=service.plans.create(payload)
    codec,_,_=codec_fixture(root)
    credentials=RecoveryCredentialStore(root,codec=codec)
    from alt_deploy.setup_recovery_reserved_state import RecoveryReservedState
    fresh=RecoveryReservedState(service,credentials=credentials)
    native_calls=[]
    def native(command,**kwargs):
        operation=command[3];native_calls.append(operation)
        with service.settings.lock_file.open('r+') as stream:
            fcntl.flock(stream,fcntl.LOCK_EX|fcntl.LOCK_NB)
            fcntl.flock(stream,fcntl.LOCK_UN)
        result={'status':'ok','result':'control_plane_allowed'}
        if operation!='guard':
            result.update(backup_id='backup-20261011T123456Z-12345678',manifest_sha256='a'*64)
            if operation=='create':result.update(result='backup_created',component_count=6,services_restored=True)
            elif operation=='verify':result.update(result='backup_verified',component_count=6,evidence_written=True)
            elif operation=='rehearse':result.update(result='backup_rehearsed',check_count=11,rehearsal_passed=True)
            else:result.update(result='backup_rehearsed',verification_sha256='b'*64)
        return 0,json.dumps(result),''
    from alt_deploy.setup_recovery_controller_backup import RecoveryControllerBackup
    controller=RecoveryControllerBackup(service.settings,credentials=credentials,fresh_check=fresh,runner=native)
    # Eligibility verification uses only the nonblocking backup operation lock,
    # while native creation requires the controller lifecycle lock to be free.
    original_native=controller._native
    def checked(operation,*args):
        if operation in ('guard','rehearse-status'):
            runner=controller.runner
            controller.runner=lambda command,**kwargs: native_without_lock(command,**kwargs)
            try:return original_native(operation,*args)
            finally:controller.runner=runner
        return original_native(operation,*args)
    def native_without_lock(command,**kwargs):
        operation=command[3]
        if operation=='guard':return 0,json.dumps({'status':'ok','result':'control_plane_allowed'}),''
        return 0,json.dumps(dict(status='ok',result='backup_rehearsed',backup_id=command[4],
            manifest_sha256='a'*64,verification_sha256='b'*64)),''
    controller._native=checked
    from alt_deploy.setup_recovery_backup_runtime import RecoveryWorkstationBackupRuntime
    base=RecoveryWorkstationBackupRuntime(service.settings,credentials=credentials)
    runtime_calls=[]
    class Runtime:
        backup_request=base.backup_request
        def verify_backup(self,*args,**kwargs):return {'manifest_sha256':'c'*64}
        def create_backup(self,*args,**kwargs):
            runtime_calls.append('backup')
            with service.settings.lock_file.open('r+') as stream:
                with pytest.raises(BlockingIOError):fcntl.flock(stream,fcntl.LOCK_EX|fcntl.LOCK_NB)
            return self.verify_backup(*args,**kwargs)
        def verify_rehearsal(self,*args,**kwargs):return {'request_sha256':'d'*64}
        def create_rehearsal(self,*args,**kwargs):runtime_calls.append('rehearsal');return self.verify_rehearsal(*args,**kwargs)
    from alt_deploy.setup_recovery_prepare import RecoveryPreparationCoordinator
    coordinator=RecoveryPreparationCoordinator(service,credentials=credentials,controller=controller,runtime=Runtime(),
        resolver=lambda hostname:'192.0.2.11')
    return coordinator,service,plan,paths,native_calls,runtime_calls


def test_preparation_reserves_once_preserves_originals_and_verifies_real_gate(tmp_path):
    coordinator,service,plan,paths,native_calls,runtime_calls=scenario(tmp_path)
    original={key:path.read_bytes() for key,path in paths.items()}
    result=coordinator.prepare(plan['plan_id'],plan['sha256'])
    assert result['status']=='recovery_prepared' and result['plan_sha256']==plan['sha256']
    assert native_calls==['create','verify','rehearse']
    assert runtime_calls==['backup','rehearsal']
    assert {key:path.read_bytes() for key,path in paths.items()}==original
    with pytest.raises(ControlError):coordinator.prepare(plan['plan_id'],plan['sha256'])
    assert runtime_calls==['backup','rehearsal']


@pytest.mark.parametrize('changed',['backup','rehearsal','controller','dns','expired','plan'])
def test_failure_never_replays_preparation_and_preserves_failed_history(tmp_path,changed):
    coordinator,service,plan,paths,native_calls,runtime_calls=scenario(tmp_path)
    originals={key:path.read_bytes() for key,path in paths.items()}
    def failure(*args,**kwargs):raise RuntimeError('SYNTHETIC_SECRET')
    if changed=='backup':coordinator.runtime.create_backup=failure
    elif changed=='rehearsal':coordinator.runtime.create_rehearsal=failure
    elif changed=='controller':coordinator.controller.prepare=failure
    elif changed=='dns':coordinator.resolver=lambda hostname:'not-an-address'
    elif changed=='expired':
        from datetime import timedelta
        from test_setup_recovery_history import NOW
        service.plans.clock=lambda:NOW+timedelta(days=2)
    else:plan['sha256']='f'*64
    with pytest.raises(ControlError) as error:coordinator.prepare(plan['plan_id'],plan['sha256'])
    assert 'SYNTHETIC_SECRET' not in str(error.value)
    before=list(runtime_calls)
    with pytest.raises(ControlError):coordinator.prepare(plan['plan_id'],plan['sha256'])
    assert runtime_calls==before
    assert {key:path.read_bytes() for key,path in paths.items()}==originals


def test_visible_ready_marker_after_failed_persistence_cannot_authorize_write(tmp_path,monkeypatch):
    coordinator,service,plan,paths,native_calls,runtime_calls=scenario(tmp_path)
    from alt_deploy.setup_recovery_controller_backup import RecoveryControllerBackup
    original=RecoveryControllerBackup._persist
    def changed(path,document):
        original(path,document)
        if path.name.endswith('.preparation-ready.json'):raise OSError('failed sync')
    monkeypatch.setattr(RecoveryControllerBackup,'_persist',staticmethod(changed))
    with pytest.raises(ControlError):coordinator.prepare(plan['plan_id'],plan['sha256'])
    payload=plan['payload'];pair={key:payload[key] for key in ('failed_run_id','computer_guid')}
    assert coordinator.attempts._path(**pair,suffix='.preparation-ready.json').exists()
    assert private_read(coordinator.attempts._path(**pair,suffix='.receipt.json'))['status']=='failed'
    with pytest.raises(ControlError):coordinator.credentials.open(**pair)


def test_intervening_history_change_after_native_backup_prevents_password_transport(tmp_path):
    coordinator,service,plan,paths,native_calls,runtime_calls=scenario(tmp_path)
    original=coordinator.controller.prepare
    def changed(payload):
        result=original(payload)
        doc=private_read(paths['run']);doc['reboot_required']=False;private_replace(paths['run'],doc)
        return result
    coordinator.controller.prepare=changed
    with pytest.raises(ControlError):coordinator.prepare(plan['plan_id'],plan['sha256'])
    assert runtime_calls==[]


@pytest.mark.parametrize('output,accepted',[
    ('192.0.2.11 STREAM synthetic-dc.sosnadmin.local\n192.0.2.11 DGRAM\n192.0.2.11 RAW\n',True),
    ('192.0.2.11 STREAM\n192.0.2.12 STREAM\n',False),('',False),('bad STREAM\n',False)])
def test_fixed_native_dns_resolution_requires_one_ipv4(tmp_path,monkeypatch,output,accepted):
    from alt_deploy import setup_recovery_prepare as module
    calls=[]
    def run(command,**kwargs):calls.append((command,kwargs));return 0,output,''
    monkeypatch.setattr(module,'bounded_recovery_run',run)
    if accepted is True:assert module._resolve_dc('synthetic-dc.sosnadmin.local')=='192.0.2.11'
    else:
        with pytest.raises(ValueError):module._resolve_dc('synthetic-dc.sosnadmin.local')
    assert calls[0][0]==['/usr/bin/getent','ahostsv4','synthetic-dc.sosnadmin.local']
    assert calls[0][1]['timeout']==10 and calls[0][1]['input_text']==''
