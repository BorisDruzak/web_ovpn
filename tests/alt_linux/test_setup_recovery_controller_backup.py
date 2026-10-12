from __future__ import annotations

import json
import subprocess
import sys

import pytest

from alt_deploy.errors import ControlError
from alt_deploy.setup_plans import digest, private_read, private_replace
from test_setup_recovery_reserved_state import scenario
from test_setup_recovery_credential import codec_fixture
from alt_deploy.setup_recovery_credential import RecoveryCredentialStore

BACKUP='backup-20261011T123456Z-12345678'


def fixture(root, *, changed=None):
    checker,service,plan,claim,paths,*_=scenario(root)
    codec,_,_=codec_fixture(root)
    credentials=RecoveryCredentialStore(root,codec=codec)
    credentials.create(plan['payload']['failed_run_id'],plan['payload']['computer_guid'])
    calls=[]
    def run(command, **kwargs):
        operation=command[3];calls.append(operation)
        assert command[:3]==['/usr/bin/sudo','-n','/usr/local/sbin/alt-deploy-backup']
        assert kwargs['input_text']=='' and kwargs['timeout']==360
        assert kwargs['environment']=={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C.UTF-8'}
        result={'status':'ok'}
        if operation=='guard':result['result']='control_plane_allowed'
        else:
            result.update(backup_id=BACKUP,manifest_sha256='a'*64)
            if operation=='create':result.update(result='backup_created',component_count=6,services_restored=True)
            elif operation=='verify':result.update(result='backup_verified',component_count=6,evidence_written=True)
            elif operation=='rehearse':result.update(result='backup_rehearsed',check_count=11,rehearsal_passed=True)
            else:result.update(result='backup_rehearsed',verification_sha256='b'*64)
            assert len(command)==(4 if operation=='create' else 5)
            if operation!='create':assert command[4]==BACKUP
        if changed==operation:result['manifest_sha256']='c'*64
        if changed=='bad_id' and operation=='create':result['backup_id']='../../bad'
        if changed=='services' and operation=='create':result['services_restored']=False
        if changed=='rehearsal' and operation=='rehearse':result['rehearsal_passed']=False
        if changed=='stderr' and operation=='create':return 1,'password should not escape','secret failure'
        return 0,json.dumps(result),''
    from alt_deploy.setup_recovery_controller_backup import RecoveryControllerBackup
    producer=RecoveryControllerBackup(service.settings,credentials=credentials,fresh_check=checker,runner=run)
    return producer,service,plan,claim,credentials,paths,calls


def test_native_rehearsal_process_receives_utf8_locale(tmp_path):
    producer,*_=fixture(tmp_path)
    native=producer.runner
    def inspect_locale(command,**kwargs):
        result=subprocess.run([sys.executable,'-I','-c',
            "import locale; locale.setlocale(locale.LC_ALL, ''); print(locale.getencoding())"],
            env=kwargs['environment'],capture_output=True,text=True,check=True)
        assert result.stdout.strip().lower().replace('-','')=='utf8'
        return native(command,**kwargs)
    producer.runner=inspect_locale
    assert producer._native('rehearse',BACKUP)['rehearsal_passed'] is True


def test_native_backup_is_bound_to_exact_reserved_history_and_sealed_document(tmp_path):
    producer,service,plan,claim,credentials,paths,calls=fixture(tmp_path)
    originals={key:path.read_bytes() for key,path in paths.items()}
    result=producer.prepare(plan['payload'])
    assert calls==['guard','create','verify','rehearse','rehearse-status','guard']
    assert result['claim_sha256']==digest(claim)
    assert result['snapshot_sha256']==digest(plan['payload']['snapshot'])
    assert result['backup_id']==BACKUP and result['manifest_sha256']=='a'*64
    assert producer.verify(plan['payload'])==result
    assert calls[-2:]==['guard','rehearse-status']
    assert {key:path.read_bytes() for key,path in paths.items()}==originals
    with pytest.raises(ControlError):producer.prepare(plan['payload'])
    assert calls.count('create')==1


@pytest.mark.parametrize('changed',['verify','rehearse','rehearse-status','bad_id','services','rehearsal','stderr'])
def test_native_failure_excludes_retry_and_never_accepts_evidence(tmp_path,changed):
    producer,service,plan,claim,credentials,paths,calls=fixture(tmp_path,changed=changed)
    with pytest.raises(ControlError) as error:producer.prepare(plan['payload'])
    assert 'password' not in str(error.value) and 'secret' not in str(error.value)
    previous=list(calls)
    with pytest.raises(ControlError):producer.prepare(plan['payload'])
    with pytest.raises(ControlError):producer.verify(plan['payload'])
    assert calls==previous


@pytest.mark.parametrize('changed',['claim','sealed','receipt','intent','expiry'])
def test_verification_refuses_changed_local_protected_evidence_before_native_calls(tmp_path,changed):
    producer,service,plan,claim,credentials,paths,calls=fixture(tmp_path)
    producer.prepare(plan['payload']);calls.clear()
    pair={key:plan['payload'][key] for key in ('failed_run_id','computer_guid')}
    if changed=='claim':path=service.attempts.claim_path(**pair)
    elif changed=='sealed':path=credentials.path(**pair)
    elif changed=='expiry':
        from datetime import timedelta
        from test_setup_recovery_history import NOW
        service.plans.clock=lambda:NOW+timedelta(days=2)
        path=None
    else:path=producer.path(plan['payload'],'.'+changed+'.json')
    if path:
        doc=private_read(path);doc['changed']=True;private_replace(path,doc)
    with pytest.raises(ControlError):producer.verify(plan['payload'])
    assert calls==[]


def test_visible_receipt_after_sync_failure_is_excluded(tmp_path,monkeypatch):
    producer,service,plan,claim,credentials,paths,calls=fixture(tmp_path)
    original=producer._persist
    def fail_after_write(path,document):
        original(path,document)
        if path==producer.path(plan['payload'],'.receipt.json'):raise OSError('sync failed')
    monkeypatch.setattr(producer,'_persist',fail_after_write)
    with pytest.raises(ControlError):producer.prepare(plan['payload'])
    assert producer.path(plan['payload'],'.receipt.json').exists()
    before=list(calls)
    with pytest.raises(ControlError):producer.verify(plan['payload'])
    assert calls==before


def test_changed_intent_during_native_preparation_is_refused(tmp_path,monkeypatch):
    producer,service,plan,claim,credentials,paths,calls=fixture(tmp_path)
    original=producer._native
    def changed(operation,*args):
        result=original(operation,*args)
        if operation=='rehearse':private_replace(producer.path(plan['payload'],'.intent.json'),{'changed':True})
        return result
    monkeypatch.setattr(producer,'_native',changed)
    with pytest.raises(ControlError):producer.prepare(plan['payload'])


def test_producer_accepts_actual_native_dispatch_contract_in_isolated_sandbox(tmp_path):
    from support.backup_rehearsal_sandbox import BackupSandbox
    from alt_deploy_backup.cli import _dispatch
    producer,service,plan,claim,credentials,paths,calls=fixture(tmp_path/'recovery')
    (tmp_path/'native').mkdir(mode=0o700)
    sandbox=BackupSandbox.create(tmp_path/'native')
    sandbox.seed_complete_controller()
    def native(command,**kwargs):
        result=_dispatch(command[3],command[4] if len(command)==5 else None,sandbox.settings)
        return 0,json.dumps(result),''
    producer.runner=native
    receipt=producer.prepare(plan['payload'])
    assert producer.verify(plan['payload'])==receipt
    assert sandbox.repository().list()[0].rehearsed is True
