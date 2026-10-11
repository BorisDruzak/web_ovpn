from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import patch

import pytest

from test_setup_recovery_native import META
from test_setup_recovery_sssd_start import scenario as startup_fixture
from alt_deploy import setup_recovery_native as native_module

PACKAGES={'/usr/bin/net':'samba-common-tools 4.21.9-alt4.p11.1',
    '/usr/bin/testparm':'samba-common-tools 4.21.9-alt4.p11.1',
    '/usr/bin/bwrap':'bubblewrap 0.13.0-alt1'}


def api():
    from alt_deploy import setup_recovery_native_testjoin
    return setup_recovery_native_testjoin


def scenario(root):
    import test_setup_recovery_backup as fixture
    original=fixture.scenario
    def tools(directory):
        probe,calls,values,read=original(directory)
        for path in ('/usr/bin/net','/usr/bin/testparm'):(directory/path.lstrip('/')).chmod(0o755)
        def wrapped(command):
            if command[:2]==['/usr/bin/rpm','-qf'] and command[2] in PACKAGES:return PACKAGES[command[2]]
            return read(command)
        return probe,calls,values,wrapped
    with patch.object(fixture,'scenario',tools):start,request,args,calls,states=startup_fixture(root)
    receipt=start.start_once(request,**args);previous=args['runner'];native=[]
    def runner(command,**options):
        if command[:2]==['/usr/bin/rpm','-qf'] and command[2] in PACKAGES:return 0,PACKAGES[command[2]]+'\n',''
        if command[0]=='/usr/bin/bwrap' and command[-2:]==['ads','testjoin']:
            work=Path(command[command.index('--bind')+1]);native.append((command,options,work))
            assert (work/'private/secrets.tdb').read_bytes()==(root/'var/lib/samba/private/secrets.tdb').read_bytes()
            assert not (work/'krb5.keytab').exists()
            (work/'private/secrets.tdb').write_bytes(b'ALLOWED_SCRATCH_WRITE')
            (work/'ccache').write_bytes(b'SYNTHETIC_TICKET')
            return 0,'Join is OK\n',''
        return previous(command,**options)
    args.update(start=start,runner=runner)
    return request,receipt,args,native,states


def test_native_success_preserves_live_credentials_and_cleans_scratch_before_receipt(tmp_path):
    module=api();request,started,args,calls,_=scenario(tmp_path)
    before=args['collect']();result=module.testjoin_once(request,started,**args)
    assert result['status']=='native_testjoin_succeeded'
    assert result['native_testjoin_peer_pinning_verified'] is False
    assert result['trust_verified'] is False and result['temporary_policy_retained'] is True
    assert result['startup_receipt_sha256']==args['backup'].digest(started)
    assert args['collect']()==before and len(calls)==1
    assert not calls[0][2].exists() and 'SYNTHETIC_TICKET' not in str(result)
    assert module.verify(request,started,result,**args)==result and len(calls)==1
    with pytest.raises(ValueError):module.testjoin_once(request,started,**args)


@pytest.mark.parametrize('change',['failure','unexpected_output','keytab','restart','pid','intent','tool','expired'])
def test_entered_failure_retains_exclusion_and_never_replays_native_command(tmp_path,change):
    module=api();request,started,args,calls,states=scenario(tmp_path);previous=args['runner']
    def changed(command,**options):
        rc,out,err=previous(command,**options)
        if command[0]=='/usr/bin/bwrap' and command[-2:]==['ads','testjoin']:
            if change=='failure':rc=1;err='SYNTHETIC_SECRET'
            elif change=='unexpected_output':out+='unbound extra\n'
            elif change=='keytab':(tmp_path/'etc/krb5.keytab').write_bytes(b'changed')
            elif change=='restart':states['sssd.service']['NRestarts']='1'
            elif change=='pid':states['sssd.service']['MainPID']='124'
            elif change=='intent':
                leaf=module.path_for(request,backup=args['backup'],root=tmp_path);(leaf/'intent.json').write_text('{}')
            elif change=='tool':(tmp_path/'usr/bin/net').write_bytes(b'changed')
            else:
                from datetime import datetime,timedelta,timezone
                request['plan_expires_at']=(datetime.now(timezone.utc)-timedelta(seconds=1)).isoformat()
        return rc,out,err
    args['runner']=changed
    with pytest.raises(ValueError) as error:module.testjoin_once(request,started,**args)
    assert 'SYNTHETIC_SECRET' not in str(error.value)
    assert calls and not calls[0][2].exists()
    leaf=module.path_for(request,backup=args['backup'],root=tmp_path)
    assert (leaf/'failed.json').exists() and not (leaf/'verified.json').exists()
    with pytest.raises(ValueError):module.testjoin_once(request,started,**args)
    assert len(calls)==1


@pytest.mark.parametrize('change',['extra','startup_receipt','version','active_job'])
def test_bad_preconditions_do_not_enter_native_check(tmp_path,change):
    module=api();request,started,args,calls,_=scenario(tmp_path)
    if change=='extra':request['command']='join'
    elif change=='startup_receipt':started['main_pid']+=1
    else:
        previous=args['runner']
        def changed(command,**options):
            if change=='version' and command[:3]==['/usr/bin/rpm','-qf','/usr/bin/net']:return 0,'samba-common-tools 9.9\n',''
            if change=='active_job' and command[:2]==['/usr/bin/systemctl','list-jobs']:return 0,'1 other.service start running\n',''
            return previous(command,**options)
        args['runner']=changed
    with pytest.raises(ValueError):module.testjoin_once(request,started,**args)
    assert not calls


def test_fixed_online_sandbox_excludes_host_auth_ipc_and_inherited_nss(tmp_path):
    module=api();tmp_path.chmod(0o700)
    command=module.sandbox_command(tmp_path,META,native=native_module,owner=os.geteuid())
    assert '--unshare-net' not in command and '--unshare-pid' in command and '--unshare-ipc' in command
    assert '--cap-drop' in command and '--clearenv' in command
    assert command[-2:]==['ads','testjoin'] and '--use-kerberos=required' in command
    assert command.count('--bind')==1 and '/var/lib/samba' not in command and '/run' not in command
    index=command.index('/etc/nsswitch.conf');assert command[index-1]==str(tmp_path/'nsswitch.conf')
    assert '/etc/krb5.keytab' not in command and '/etc/samba/smb.conf' not in command
    config=module.sandbox_config(META,native=native_module)
    assert 'create krb5 conf = no\n' in config and 'include system krb5 conf = no\n' in config
    assert 'client ldap sasl wrapping = seal\n' in config and 'sync machine password to keytab = disabled' in config


def test_unsafe_scratch_ancestry_is_refused(tmp_path):
    module=api();tmp_path.chmod(0o755)
    with pytest.raises(ValueError):module.sandbox_command(tmp_path,META,native=native_module,owner=os.geteuid())


def test_real_bubblewrap_exposes_only_private_configs_and_no_host_authentication(tmp_path):
    import subprocess,json
    module=api()
    if os.geteuid()!=0 or not Path('/usr/bin/bwrap').exists():pytest.skip('Root bubblewrap fixture required')
    tmp_path.chmod(0o700)
    for name in ('nsswitch.conf','hosts','resolv.conf','krb5.conf','smb.conf'):
        (tmp_path/name).write_text('PRIVATE_'+name);(tmp_path/name).chmod(0o600)
    command=module.sandbox_command(tmp_path,META,native=native_module,owner=0)
    code="""import json,os,pathlib
result={name:pathlib.Path('/etc/'+name).read_text()=='PRIVATE_'+name for name in
('nsswitch.conf','hosts','resolv.conf','krb5.conf')}
result['samba']=pathlib.Path('/work/smb.conf').read_text()=='PRIVATE_smb.conf'
result['no_live']=not any(pathlib.Path(p).exists() for p in
('/var/lib/samba/private/secrets.tdb','/etc/krb5.keytab','/etc/sssd/sssd.conf','/run/sssd'))
try:pathlib.Path('/etc/krb5.conf').write_text('changed');result['readonly']=False
except OSError:result['readonly']=True
result['cache']=os.environ.get('KRB5CCNAME')=='FILE:/work/ccache'
print(json.dumps(result))"""
    probe=command[:command.index('--')+1]+['/usr/bin/python3','-I','-B','-c',code]
    result=subprocess.run(probe,text=True,capture_output=True,timeout=15)
    assert result.returncode==0,result.stderr
    values=json.loads(result.stdout)
    assert len(values)==8 and all(values.values())


@pytest.mark.parametrize('failure',['intent_sync','receipt_sync'])
def test_persistence_failure_cannot_turn_into_later_verified_evidence(tmp_path,monkeypatch,failure):
    module=api();request,started,args,calls,_=scenario(tmp_path)
    backup=args['backup'];write=backup._write
    def changed(path,raw,**options):
        write(path,raw,**options)
        if path.name==('intent.json' if failure=='intent_sync' else 'verified.json') and path.parent.name.startswith('native-testjoin-'):
            raise OSError('SYNTHETIC_SYNC')
    monkeypatch.setattr(backup,'_write',changed)
    with pytest.raises(ValueError):module.testjoin_once(request,started,**args)
    leaf=module.path_for(request,backup=backup,root=tmp_path)
    assert (leaf/'failed.json').exists()
    if failure=='receipt_sync':
        result=backup._json(leaf/'verified.json',root=tmp_path,owner=os.geteuid())
        with pytest.raises(ValueError):module.verify(request,started,result,**args)
    assert len(calls)==(1 if failure=='receipt_sync' else 0)


@pytest.mark.parametrize('name',['smb.conf','krb5.conf','nsswitch.conf','private/secrets.tdb'])
def test_scratch_replacement_during_native_guards_refuses_before_testjoin(tmp_path,name):
    module=api();request,started,args,calls,_=scenario(tmp_path);previous=args['runner'];changed=[]
    def replacing(command,**options):
        result=previous(command,**options)
        leaf=module.path_for(request,backup=args['backup'],root=tmp_path)
        scratch=list(leaf.glob('scratch-*')) if leaf.exists() else []
        if scratch and not changed and command[:2]==['/usr/bin/rpm','-qf']:
            (scratch[0]/name).write_bytes(b'UNREVIEWED_REPLACEMENT');changed.append(True)
        return result
    args['runner']=replacing
    with pytest.raises(ValueError):module.testjoin_once(request,started,**args)
    assert changed and not calls


@pytest.mark.parametrize('path',['/etc/krb5.keytab','/etc/sssd/conf.d/99-alt-deploy-recovery.conf'])
def test_final_tool_query_cannot_return_success_after_live_artifact_drift(tmp_path,path):
    module=api();request,started,args,_,_=scenario(tmp_path)
    result=module.testjoin_once(request,started,**args);previous=args['runner'];queries=[]
    def observing(command,**options):
        if command[:2]==['/usr/bin/rpm','-qf']:queries.append(command)
        return previous(command,**options)
    args['runner']=observing;module.verify(request,started,result,**args);total=len(queries);count=[]
    def changing(command,**options):
        value=previous(command,**options)
        if command[:2]==['/usr/bin/rpm','-qf']:
            count.append(True)
            if len(count)==total:(tmp_path/path.lstrip('/')).write_bytes(b'CHANGED_AFTER_FINAL_RPM')
        return value
    args['runner']=changing
    with pytest.raises(ValueError):module.verify(request,started,result,**args)


def test_worker_helpers_run_in_fixed_source_namespace_without_package_imports(tmp_path):
    module=api();tmp_path.chmod(0o700)
    scope={'__name__':'fixed_recovery_native_testjoin','__package__':None}
    exec(compile(Path(module.__file__).read_text(),'fixed_recovery_native_testjoin','exec'),scope)
    assert 'client ldap sasl wrapping = seal' in scope['sandbox_config'](META,native=native_module)
    command=scope['sandbox_command'](tmp_path,META,native=native_module,owner=os.geteuid())
    assert command[-2:]==['ads','testjoin']


@pytest.mark.parametrize('name',['request.json','intent.json'])
def test_last_startup_verification_record_drift_refuses_before_native(tmp_path,monkeypatch,name):
    module=api();request,started,args,calls,_=scenario(tmp_path)
    start=args['start'];previous=start.verify_started;changed=[]
    def replacing(*values,**options):
        result=previous(*values,**options)
        leaf=module.path_for(request,backup=args['backup'],root=tmp_path)
        if leaf.exists() and list(leaf.glob('scratch-*')) and not changed:
            (leaf/name).write_text('{}');changed.append(True)
        return result
    monkeypatch.setattr(start,'verify_started',replacing)
    with pytest.raises(ValueError):module.testjoin_once(request,started,**args)
    assert changed and not calls
