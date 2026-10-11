from __future__ import annotations

import os
from datetime import datetime,timezone
from pathlib import Path
from unittest.mock import patch

import pytest

from test_setup_recovery_import import scenario as import_fixture,apply

NOW=datetime(2026,10,11,12,1,tzinfo=timezone.utc)


def scenario(root):
    import test_setup_recovery_backup as facts
    original=facts.scenario
    def with_kerberos(directory):
        probe,calls,values,runner=original(directory)
        (directory/'usr/bin/klist').chmod(0o755)
        for name in ('kinit','kdestroy'):
            path=directory/('usr/bin/'+name);path.write_bytes(b'SYNTHETIC_KERBEROS_TOOL');path.chmod(0o755)
        def read(command):
            if command[:3]==['/usr/bin/rpm','-qf','/usr/bin/klist']:return 'krb5-kinit 1.21.3-alt2.1'
            return runner(command)
        return probe,calls,values,read
    with patch.object(facts,'scenario',with_kerberos):data,_=import_fixture(root)
    installed=apply(data)
    request=dict(schema_version=1,import_request=data['request'],import_receipt=installed,source_sha256='a'*64)
    calls=[]
    def runner(command,**options):
        calls.append((command,options))
        if command[0]=='/usr/bin/rpm':return 0,'krb5-kinit 1.21.3-alt2.1\n',''
        if command[0]=='/usr/bin/kinit':
            cache=Path(command[command.index('-c')+1].removeprefix('FILE:'));cache.write_bytes(b'SYNTHETIC_TICKET');cache.chmod(0o600)
            return 0,'',''
        if command[0]=='/usr/bin/kdestroy':
            Path(command[-1].removeprefix('FILE:')).unlink();return 0,'',''
        if command[0]=='/usr/bin/klist':
            if '-s' in command:return 0,'',''
            return 0,('Ticket cache: '+command[-1]+'\nDefault principal: ALT-A1-PC3$@SOSNADMIN.LOCAL\n\n'
                'Valid starting     Expires            Service principal\n'
                '10/11/26 12:00:00  10/11/26 12:05:00  krbtgt/SOSNADMIN.LOCAL@SOSNADMIN.LOCAL\n'),''
        return data['runner'](command,**options)
    return data,request,runner,calls


def prove(data,request,runner):
    from alt_deploy import setup_recovery_kerberos as kerberos
    return kerberos.prove_once(request,backup=data['backup'],importer=__import__('alt_deploy.setup_recovery_import',fromlist=['x']),
        probe=data['probe'],native=data['native'],collect=data['collect'],runner=runner,
        root=data['root'],owner=os.geteuid(),clock=lambda:NOW)


def test_fixed_machine_keytab_proof_uses_private_cache_and_changes_no_authentication_file(tmp_path):
    data,request,runner,calls=scenario(tmp_path);before=data['collect']()
    result=prove(data,request,runner)
    assert result['status']=='machine_keytab_authenticated' and result['trust_verified'] is False
    assert result['principal']=='ALT-A1-PC3$@SOSNADMIN.LOCAL'
    assert data['collect']()==before
    kinit=[value for value in calls if value[0][0]=='/usr/bin/kinit'][0]
    assert '-k' in kinit[0] and '-t' in kinit[0] and '-C' not in kinit[0]
    assert kinit[1]['environment']['KRB5CCNAME'].startswith('FILE:')
    assert not Path(kinit[1]['environment']['KRB5CCNAME'][5:]).exists()
    assert not Path(kinit[1]['environment']['KRB5_CONFIG']).exists()
    assert all('machine_password' not in str(value) and 'SYNTHETIC_TICKET' not in str(value) for value in calls)
    from alt_deploy import setup_recovery_kerberos as kerberos,setup_recovery_import as importer
    assert kerberos.verify(request,backup=data['backup'],importer=importer,probe=data['probe'],native=data['native'],
        collect=data['collect'],runner=runner,root=tmp_path,owner=os.geteuid())==result
    with pytest.raises(ValueError):prove(data,request,runner)


@pytest.mark.parametrize('change',['extra','import_receipt','version','kinit','expired','wrong_principal','wrong_realm',
    'extra_ticket','cache_mode','destroy','file_drift','tool_drift','intent_drift','request_drift'])
def test_invalid_or_failed_proof_retains_failure_and_no_ticket_material(tmp_path,change):
    data,request,runner,calls=scenario(tmp_path)
    if change=='extra':request['command']='kpasswd'
    elif change=='import_receipt':request['import_receipt']['kvno']+=1
    def changed(command,**options):
        rc,out,err=runner(command,**options)
        if change=='version' and command[0]=='/usr/bin/rpm':out='krb5-kinit 9.9\n'
        elif change=='kinit' and command[0]=='/usr/bin/kinit':rc=1;err='SYNTHETIC_TICKET'
        elif command[0]=='/usr/bin/klist' and '-s' not in command:
            if change=='expired':out=out.replace('12:05:00','12:00:30')
            elif change=='wrong_principal':out=out.replace('ALT-A1-PC3$','OTHER$')
            elif change=='wrong_realm':out=out.replace('krbtgt/SOSNADMIN.LOCAL@SOSNADMIN.LOCAL','krbtgt/OTHER@SOSNADMIN.LOCAL')
            elif change=='extra_ticket':out+=out.splitlines()[-1]+'\n'
            elif change=='cache_mode':Path(command[-1][5:]).chmod(0o644)
            elif change=='file_drift':(tmp_path/'etc/krb5.conf').write_bytes(b'changed')
            elif change=='tool_drift':(tmp_path/'usr/bin/kinit').write_bytes(b'changed')
            elif change in ('intent_drift','request_drift'):
                from alt_deploy import setup_recovery_kerberos as kerberos
                leaf=kerberos.path_for(request,backup=data['backup'],root=tmp_path)
                path=leaf/('intent.json' if change=='intent_drift' else 'request.json');path.write_text('{"schema_version":1}')
        elif change=='destroy' and command[0]=='/usr/bin/kdestroy':rc=1
        return rc,out,err
    with pytest.raises(ValueError) as caught:prove(data,request,changed)
    assert 'SYNTHETIC_TICKET' not in str(caught.value)
    assert not list((tmp_path/'var/lib/alt-deploy-recovery').glob('kerberos-*/cache-*'))


@pytest.mark.parametrize('change',['extra','missing','intent','receipt','tool'])
def test_retained_proof_verification_refuses_missing_changed_or_failed_evidence(tmp_path,change):
    from alt_deploy import setup_recovery_kerberos as kerberos,setup_recovery_import as importer
    data,request,runner,calls=scenario(tmp_path);prove(data,request,runner)
    leaf=kerberos.path_for(request,backup=data['backup'],root=tmp_path)
    if change=='extra':(leaf/'failed.json').write_text('{}')
    elif change=='missing':(leaf/'intent.json').unlink()
    elif change=='intent':(leaf/'intent.json').write_text('{}')
    elif change=='receipt':(leaf/'verified.json').write_text('{}')
    else:(tmp_path/'usr/bin/kinit').write_bytes(b'changed')
    before=len([command for command,options in calls if command[0]=='/usr/bin/kinit'])
    with pytest.raises(ValueError):kerberos.verify(request,backup=data['backup'],importer=importer,probe=data['probe'],
        native=data['native'],collect=data['collect'],runner=runner,root=tmp_path,owner=os.geteuid())
    assert len([command for command,options in calls if command[0]=='/usr/bin/kinit'])==before


@pytest.mark.parametrize('change',['bytes','mode','postauthentication'])
def test_private_configuration_drift_refuses_proof_and_cleans_cache(tmp_path,change):
    data,request,runner,calls=scenario(tmp_path)
    changed_once=False
    def changed(command,**options):
        nonlocal changed_once
        rc,out,err=runner(command,**options)
        paths=list((tmp_path/'var/lib/alt-deploy-recovery').glob('kerberos-*/cache-*/krb5.conf'))
        trigger=(command[0]=='/usr/bin/klist' and '-s' not in command) if change=='postauthentication' else command[0]=='/usr/bin/rpm'
        if paths and trigger and not changed_once:
            changed_once=True
            if change=='mode':paths[0].chmod(0o644)
            else:paths[0].write_bytes(paths[0].read_bytes().replace(b'kdc = ',b'kdc = 203.0.113.9 # '))
        return rc,out,err
    with pytest.raises(ValueError):prove(data,request,changed)
    assert changed_once
    if change!='postauthentication':assert not any(command[0]=='/usr/bin/kinit' for command,options in calls)
    assert not list((tmp_path/'var/lib/alt-deploy-recovery').glob('kerberos-*/cache-*'))
    assert not list((tmp_path/'var/lib/alt-deploy-recovery').glob('kerberos-*/verified.json'))


def test_native_mit_klist_format_with_synthetic_private_cache_and_no_network(tmp_path):
    import struct
    import subprocess
    import time
    from alt_deploy import setup_recovery_kerberos as kerberos
    if not all(Path(path).is_file() for path in ('/usr/bin/klist','/usr/bin/kdestroy')):
        pytest.skip('native MIT tools unavailable')
    u32=lambda value:struct.pack('>I',value)
    blob=lambda value:u32(len(value))+value
    realm=b'SOSNADMIN.LOCAL'
    def principal(parts):return u32(1)+u32(len(parts))+blob(realm)+b''.join(blob(part) for part in parts)
    client=principal([b'ALT-A1-PC3$']);server=principal([b'krbtgt',realm]);now=int(time.time())
    # Public, invalid ticket/key bytes test parsing only. No AS request is made.
    credential=client+server+struct.pack('>H',18)+blob(b'x'*32)+b''.join(u32(t) for t in (now-60,now-60,now+240,0))
    credential+=b'\0'+u32(0)+u32(0)+u32(0)+blob(b'SYNTHETIC_TICKET')+blob(b'')
    path=tmp_path/'cache';path.write_bytes(b'\x05\x04\x00\x00'+client+credential);path.chmod(0o600)
    cache='FILE:'+str(path);env={'PATH':'/usr/bin:/bin','LC_ALL':'C','TZ':'UTC'}
    try:
        result=subprocess.run(['/usr/bin/klist','-c',cache],env=env,stdin=subprocess.DEVNULL,capture_output=True,text=True,timeout=10)
        assert result.returncode==0
        kerberos._ticket(result.stdout,cache,'ALT-A1-PC3$@SOSNADMIN.LOCAL','SOSNADMIN.LOCAL',datetime.now(timezone.utc))
        assert subprocess.run(['/usr/bin/klist','-s','-c',cache],env=env,stdin=subprocess.DEVNULL,capture_output=True,timeout=10).returncode==0
        assert subprocess.run(['/usr/bin/kdestroy','-c',cache],env=env,stdin=subprocess.DEVNULL,capture_output=True,timeout=10).returncode==0
        assert not path.exists()
    finally:
        if path.exists():path.unlink()
