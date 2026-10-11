from __future__ import annotations

import fcntl
import json
import os
from pathlib import Path

import pytest

from test_setup_recovery_rehearsal import scenario as rehearsal_scenario
from test_setup_recovery_native import PASSWORD, keytab_dump
from test_setup_recovery_keytab import fixture as binary_keytab


def scenario(root):
    from alt_deploy import setup_recovery_rehearsal as rehearsal
    from alt_deploy import setup_recovery_keytab as keytab
    from alt_deploy import setup_recovery_probe as probe
    backup,native,original,collect,runner,calls=rehearsal_scenario(root)
    receipt=rehearsal.create(original,PASSWORD,backup=backup,native=native,collect=collect,
        runner=runner,root=root,owner=os.geteuid())
    pair={key:original['backup_request'][key] for key in ('failed_run_id','computer_guid')}
    result=dict(pair,schema_version=1,status='directory_password_written',
        machine_uuid=original['backup_request']['machine_uuid'],computer_sid=original['metadata']['domain_sid']+'-1234',
        claim_sha256=original['backup_request']['claim_sha256'],intent_sha256='f'*64,
        sealed_sha256=original['credential_sha256'],kvno=257,pwd_last_set=133000000000000000)
    request={'schema_version':1,'rehearsal_request':original,'rehearsal_receipt':receipt,
        'directory_result':result,'source_sha256':'9'*64}
    calls.clear()
    def install_runner(command,**kwargs):
        if command[0]=='/usr/bin/systemctl':
            calls.append((command,None));return 3,'inactive\ninactive\ninactive\ninactive\n',''
        work=Path(command[command.index('--bind')+1])
        if command[-3:]==['ads','keytab','create']:
            (work/'private/secrets.tdb').write_bytes(b'NEW_SYNTHETIC_SECRET')
            (work/'private/secrets.tdb').chmod(0o600)
            (work/'krb5.keytab').write_bytes(binary_keytab(previous=True))
            (work/'krb5.keytab').chmod(0o600)
        if 'list' in command and (work/'krb5.keytab').read_bytes()!=binary_keytab(previous=True):
            calls.append((command,kwargs.get('input_text')))
            return 0,keytab_dump(257),''
        return runner(command,**kwargs)
    return dict(backup=backup,native=native,keytab=keytab,rehearsal=rehearsal,probe=probe,
        request=request,collect=collect,runner=install_runner,root=root,owner=os.geteuid()),calls


def api():
    from alt_deploy import setup_recovery_import
    return setup_recovery_import


def apply(data):
    request=data['request'];args={k:v for k,v in data.items() if k!='request'}
    return api().install_once(request,PASSWORD,**args)


def test_fixed_install_preserves_backups_and_never_claims_trust(tmp_path):
    data,calls=scenario(tmp_path);request=data['request'];before=data['collect']()
    receipt=apply(data)
    assert receipt['status']=='local_credentials_installed' and receipt['trust_verified'] is False
    assert receipt['kvno']==257
    assert (tmp_path/'var/lib/samba/private/secrets.tdb').read_bytes()==b'NEW_SYNTHETIC_SECRET'
    assert data['backup'].verify(request['rehearsal_request']['backup_request'],root=tmp_path,owner=os.geteuid())==request['rehearsal_request']['backup_receipt']
    after=data['collect']()
    for path in ('/etc/samba/smb.conf','/etc/sssd/sssd.conf','/etc/krb5.conf'):
        assert after['files'][path]==before['files'][path]
    assert api().verify(request,**{k:v for k,v in data.items() if k not in ('request','native','keytab','rehearsal','runner')})==receipt
    assert all(PASSWORD not in str(command) for command,_ in calls)
    assert not any(command[0]=='/usr/bin/ldapmodify' or 'restart' in command or 'join' in command for command,_ in calls)
    leaf=api().path_for(request,backup=data['backup'],root=tmp_path)
    assert PASSWORD not in json.dumps(receipt) and PASSWORD not in (leaf/'request.json').read_text()
    with pytest.raises(ValueError):apply(data)


@pytest.mark.parametrize('field',['extra','schema','guid','uuid','claim','sealed','sid','kvno','status','intent','source','receipt'])
def test_unbound_write_result_refused_without_install(tmp_path,field):
    data,calls=scenario(tmp_path);request=data['request'];result=request['directory_result']
    if field=='extra':request['command']='join'
    elif field=='schema':request['schema_version']=True
    elif field=='guid':result['computer_guid']='11111111-1111-1111-1111-111111111111'
    elif field=='uuid':result['machine_uuid']='11111111-1111-1111-1111-111111111111'
    elif field=='claim':result['claim_sha256']='0'*64
    elif field=='sealed':result['sealed_sha256']='0'*64
    elif field=='sid':result['computer_sid']='S-1-5-21-9-9-9-1234'
    elif field=='kvno':result['kvno']=True
    elif field=='status':result['status']='trust_recovered'
    elif field=='intent':result['intent_sha256']='bad'
    elif field=='source':request['source_sha256']='bad'
    else:request['rehearsal_receipt']['status']='forged'
    before=(tmp_path/'var/lib/samba/private/secrets.tdb').read_bytes()
    with pytest.raises(ValueError):apply(data)
    assert calls==[] and (tmp_path/'var/lib/samba/private/secrets.tdb').read_bytes()==before


@pytest.mark.parametrize('step',range(10))
def test_native_or_service_failure_excludes_replay_and_retains_original_bytes(tmp_path,step):
    data,calls=scenario(tmp_path);runner=data['runner'];count=[0]
    def broken(command,**kwargs):
        current=count[0];count[0]+=1
        if current==step:return 1,PASSWORD,PASSWORD
        return runner(command,**kwargs)
    data['runner']=broken
    before=(tmp_path/'var/lib/samba/private/secrets.tdb').read_bytes()
    with pytest.raises(ValueError):apply(data)
    assert (tmp_path/'var/lib/samba/private/secrets.tdb').read_bytes()==before
    with pytest.raises(ValueError):apply(data)


@pytest.mark.parametrize('drift',['keytab','config','clock','service'])
def test_fresh_state_drift_prevents_file_replacement(tmp_path,drift):
    data,calls=scenario(tmp_path);before=(tmp_path/'var/lib/samba/private/secrets.tdb').read_bytes()
    runner=data['runner'];count=[0]
    def changed(command,**kwargs):
        result=runner(command,**kwargs);count[0]+=1
        if count[0]==9:
            if drift=='keytab':(tmp_path/'etc/krb5.keytab').write_bytes(b'changed')
            elif drift=='config':(tmp_path/'etc/krb5.conf').write_bytes(b'changed')
        if drift=='service' and command[0]=='/usr/bin/systemctl':return 0,'active\ninactive\ninactive\ninactive\n',''
        return result
    data['runner']=changed
    if drift=='clock':
        original=data['collect'];count_collect=[0]
        def collect():
            result=original();count_collect[0]+=1
            if count_collect[0]>2:result['clock_synchronized']=False
            return result
        data['collect']=collect
    with pytest.raises(ValueError):apply(data)
    assert (tmp_path/'var/lib/samba/private/secrets.tdb').read_bytes()==before


@pytest.mark.parametrize('which',['secret','keytab','ready_sync'])
def test_interrupted_pair_install_is_nonretryable_and_never_restores_old_password(tmp_path,monkeypatch,which):
    data,calls=scenario(tmp_path);backup=data['backup'];original_replace=os.replace;sync=backup._sync
    def interrupted(source,destination):
        if (which=='secret' and destination==tmp_path/'var/lib/samba/private/secrets.tdb') or (which=='keytab' and destination==tmp_path/'etc/krb5.keytab'):
            raise OSError('synthetic interruption')
        original_replace(source,destination)
    def broken_sync(path):
        if which=='ready_sync' and (path/'installed.json').exists():raise OSError('synthetic fsync failure')
        sync(path)
    with monkeypatch.context() as patch:
        patch.setattr(os,'replace',interrupted);patch.setattr(backup,'_sync',broken_sync)
        with pytest.raises(ValueError):apply(data)
    leaf=api().path_for(data['request'],backup=backup,root=tmp_path)
    assert (leaf/'install-intent.json').exists() and (leaf/'failed.json').exists()
    if which!='secret':assert (tmp_path/'var/lib/samba/private/secrets.tdb').read_bytes()==b'NEW_SYNTHETIC_SECRET'
    with pytest.raises(ValueError):apply(data)
    with pytest.raises(ValueError):api().verify(data['request'],**{k:v for k,v in data.items() if k not in ('request','native','keytab','rehearsal','runner')})


@pytest.mark.parametrize('unsafe',['busy','symlink','mode'])
def test_local_lock_refuses_concurrent_or_unsafe_install_without_commands(tmp_path,unsafe):
    data,calls=scenario(tmp_path);path=tmp_path/'var/lib/alt-deploy-recovery/.import.lock'
    fd=None
    try:
        if unsafe=='symlink':path.symlink_to(tmp_path/'etc/krb5.conf')
        else:
            path.write_bytes(b'');path.chmod(0o600 if unsafe=='busy' else 0o644)
            if unsafe=='busy':
                fd=os.open(path,os.O_RDWR);fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        with pytest.raises((ValueError,OSError)):apply(data)
        assert calls==[]
        assert not api().path_for(data['request'],backup=data['backup'],root=tmp_path).exists()
    finally:
        if fd is not None:os.close(fd)


@pytest.mark.parametrize('drift',['staged','services'])
def test_last_prewrite_changes_are_refused_before_secret_replacement(tmp_path,drift):
    data,calls=scenario(tmp_path);runner=data['runner'];count=[0]
    before=(tmp_path/'var/lib/samba/private/secrets.tdb').read_bytes()
    def changed(command,**kwargs):
        if command[0]=='/usr/bin/systemctl':
            count[0]+=1
            if count[0]==3:
                if drift=='services':return 0,'active\ninactive\ninactive\ninactive\n',''
                for path in (tmp_path/'var/lib/samba/private').glob('secrets.tdb.alt-recovery-*.tmp'):
                    path.write_bytes(b'CHANGED_STAGED_SECRET')
        return runner(command,**kwargs)
    data['runner']=changed
    with pytest.raises(ValueError):apply(data)
    assert (tmp_path/'var/lib/samba/private/secrets.tdb').read_bytes()==before
    leaf=api().path_for(data['request'],backup=data['backup'],root=tmp_path)
    assert (leaf/'install-intent.json').exists() and (leaf/'failed.json').exists()


def test_prewrite_intent_sync_failure_permits_no_file_replacement(tmp_path,monkeypatch):
    data,calls=scenario(tmp_path);backup=data['backup'];sync=backup._sync
    before=(tmp_path/'var/lib/samba/private/secrets.tdb').read_bytes()
    leaf=api().path_for(data['request'],backup=backup,root=tmp_path)
    def failed(path):
        if path==leaf and (leaf/'install-intent.json').exists():raise OSError('synthetic sync failure')
        sync(path)
    with monkeypatch.context() as patch:
        patch.setattr(backup,'_sync',failed)
        with pytest.raises(ValueError):apply(data)
    assert (tmp_path/'var/lib/samba/private/secrets.tdb').read_bytes()==before
    with pytest.raises(ValueError):apply(data)
