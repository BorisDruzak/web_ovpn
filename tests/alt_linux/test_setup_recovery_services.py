from __future__ import annotations

import fcntl
import json
import os

import pytest

from test_setup_recovery_backup import fixture


def api():
    from alt_deploy import setup_recovery_services
    return setup_recovery_services


def scenario(root):
    from alt_deploy import setup_recovery_probe as probe
    from alt_deploy import setup_recovery_import as importer
    module=api();backup,bound,collect=fixture(root)
    receipt=backup.create(bound,collect=collect,root=root,owner=os.geteuid())
    tool=root/'usr/bin/systemctl';tool.write_bytes(b'SYNTHETIC_SYSTEMCTL');tool.chmod(0o755)
    states={unit:{'Id':unit,'LoadState':'loaded','ActiveState':'active' if unit in ('smb.service','nmb.service') else 'inactive',
        'SubState':'running' if unit in ('smb.service','nmb.service') else 'dead','MainPID':'100' if unit in ('smb.service','nmb.service') else '0',
        'ControlPID':'0','KillMode':'control-group',
        'SuccessAction':'none','FailureAction':'none','UpheldBy':'',
        'StopWhenUnneeded':'no',
        'Requires':'','Wants':'','Requisite':'','BindsTo':'','Upholds':'',
        'FragmentPath':'/usr/lib/systemd/system/'+unit,'DropInPaths':'','NeedDaemonReload':'no','Job':'',
        **{name:'' for name in module.EDGES}} for unit in module.UNITS}
    for unit in module.UNITS:
        path=root/('usr/lib/systemd/system/'+unit);path.parent.mkdir(parents=True,exist_ok=True)
        path.write_bytes(b'SYNTHETIC_FIXED_SERVICE');path.chmod(0o644)
    calls=[]
    def runner(command,**kwargs):
        calls.append(command)
        if command[0]=='/usr/bin/rpm':return 0,'systemd 258.9-alt1\n',''
        if command[1]=='show':
            properties=command[-1].removeprefix('--property=').split(',')
            return 0,''.join(key+'='+value+'\n' for key,value in states[command[2]].items() if key in properties),''
        assert command==['/usr/bin/systemctl','stop',command[2],'--job-mode=fail'] and command[2] in module.UNITS
        state=states[command[2]];state.update(ActiveState='inactive',SubState='dead',MainPID='0')
        return 0,'',''
    args=dict(backup=backup,probe=probe,collect=collect,runner=runner,root=root,owner=os.geteuid())
    snapshot=module.snapshot(**args)
    request={'schema_version':1,'backup_request':bound,'backup_receipt':receipt,
        'services':snapshot,'services_sha256':backup.digest(snapshot),'source_sha256':'d'*64}
    calls.clear()
    return dict(args,importer=importer),request,states,calls


def apply(data,request):return api().quiesce_once(request,**data)


def test_only_originally_active_fixed_services_are_stopped_with_durable_intents(tmp_path):
    data,request,states,calls=scenario(tmp_path);backup=data['backup'];before=data['collect']()
    receipt=apply(data,request)
    stops=[command for command in calls if command[0]=='/usr/bin/systemctl' and command[1]=='stop']
    assert stops==[['/usr/bin/systemctl','stop','smb.service','--job-mode=fail'],['/usr/bin/systemctl','stop','nmb.service','--job-mode=fail']]
    assert receipt['status']=='services_quiesced' and receipt['active_services']==['smb.service','nmb.service']
    assert data['collect']()==before
    assert backup.verify(request['backup_request'],root=tmp_path,owner=os.geteuid())==request['backup_receipt']
    assert api().verify(request,**{key:value for key,value in data.items() if key!='importer'})==receipt
    with pytest.raises(ValueError):apply(data,request)
    assert not any('start' in command or 'restart' in command or 'reset-failed' in command for command in calls)


@pytest.mark.parametrize('change',['schema','extra','snapshot','source','claim','receipt','reload','job','dependency','dropin','unit_file','tool','pid'])
def test_changed_or_unsafe_service_state_refuses_all_stops(tmp_path,change):
    data,request,states,calls=scenario(tmp_path)
    if change=='schema':request['schema_version']=True
    elif change=='extra':request['command']='start'
    elif change=='snapshot':request['services_sha256']='0'*64
    elif change=='source':request['source_sha256']='bad'
    elif change=='claim':request['backup_request']['claim_sha256']='0'*64
    elif change=='receipt':request['backup_receipt']['manifest_sha256']='0'*64
    elif change=='reload':states['smb.service']['NeedDaemonReload']='yes'
    elif change=='job':states['smb.service']['Job']='1'
    elif change=='dependency':states['smb.service']['BoundBy']='other.service'
    elif change=='dropin':states['smb.service']['DropInPaths']='/etc/systemd/system/override.conf'
    elif change=='unit_file':(tmp_path/'usr/lib/systemd/system/smb.service').write_bytes(b'changed')
    elif change=='tool':(tmp_path/'usr/bin/systemctl').write_bytes(b'changed')
    else:states['smb.service']['MainPID']='101'
    with pytest.raises(ValueError):apply(data,request)
    assert not any(command[0]=='/usr/bin/systemctl' and command[1]=='stop' for command in calls)


@pytest.mark.parametrize('failure',['stop','timeout','config','unit','other_service','intent_sync','ready_sync'])
def test_failed_or_partial_stop_is_retained_without_restart_or_retry(tmp_path,monkeypatch,failure):
    data,request,states,calls=scenario(tmp_path);runner=data['runner'];backup=data['backup'];sync=backup._sync
    leaf=api().path_for(request,backup=backup,root=tmp_path)
    def broken(command,**kwargs):
        if command[0]=='/usr/bin/systemctl' and command[1]=='stop':
            assert (leaf/('stopping-'+command[2]+'.json')).exists()
            if failure=='stop':return 1,'SYNTHETIC_SECRET','SYNTHETIC_SECRET'
            if failure=='timeout':raise TimeoutError('SYNTHETIC_SECRET')
            result=runner(command,**kwargs)
            if failure=='config':(tmp_path/'etc/krb5.conf').write_bytes(b'changed')
            elif failure=='unit':(tmp_path/'usr/lib/systemd/system/sssd.service').write_bytes(b'changed')
            elif failure=='other_service':states['sssd.service'].update(ActiveState='active',SubState='running',MainPID='999')
            return result
        return runner(command,**kwargs)
    def failed_sync(path):
        if path==leaf and ((failure=='intent_sync' and (leaf/'stopping-smb.service.json').exists())
                or (failure=='ready_sync' and (leaf/'verified.json').exists())):raise OSError('synthetic fsync failure')
        sync(path)
    data['runner']=broken
    with monkeypatch.context() as patch:
        patch.setattr(backup,'_sync',failed_sync)
        with pytest.raises(ValueError) as error:apply(data,request)
    assert 'SYNTHETIC_SECRET' not in str(error.value)
    assert (leaf/'failed.json').exists()
    assert 'SYNTHETIC_SECRET' not in json.dumps([p.read_text() for p in leaf.iterdir() if p.suffix=='.json'])
    if failure=='intent_sync':assert not any(command[1]=='stop' for command in calls if command[0]=='/usr/bin/systemctl')
    with pytest.raises(ValueError):apply(data,request)
    with pytest.raises(ValueError):api().verify(request,**{key:value for key,value in data.items() if key!='importer'})
    assert not any('start' in command or 'restart' in command for command in calls)


@pytest.mark.parametrize('property',['LoadState','ActiveState','FragmentPath','MainPID','ControlPID','KillMode','TriggeredBy'])
def test_snapshot_rejects_unsupported_runtime_without_changes(tmp_path,property):
    data,request,states,calls=scenario(tmp_path)
    states['sssd.service'][property]={'LoadState':'not-found','ActiveState':'failed','FragmentPath':'/etc/custom.service','MainPID':'invalid',
        'ControlPID':'1','KillMode':'process','TriggeredBy':'unapproved.socket'}[property]
    with pytest.raises(ValueError):api().snapshot(**{key:value for key,value in data.items() if key!='importer'})
    assert not any(command[1]=='stop' for command in calls if command[0]=='/usr/bin/systemctl')


def test_already_inactive_services_produce_bound_receipt_without_stop(tmp_path):
    data,request,states,calls=scenario(tmp_path)
    for state in states.values():state.update(ActiveState='inactive',SubState='dead',MainPID='0')
    request['services']=api().snapshot(**{key:value for key,value in data.items() if key!='importer'})
    request['services_sha256']=data['backup'].digest(request['services'])
    calls.clear()
    assert apply(data,request)['active_services']==[]
    assert not any(command[1]=='stop' for command in calls if command[0]=='/usr/bin/systemctl')


def test_local_install_lock_prevents_service_mutation(tmp_path):
    data,request,states,calls=scenario(tmp_path)
    path=tmp_path/'var/lib/alt-deploy-recovery/.import.lock'
    fd=os.open(path,os.O_RDWR|os.O_CREAT,0o600)
    try:
        fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        with pytest.raises(ValueError):apply(data,request)
        assert calls==[]
        assert not api().path_for(request,backup=data['backup'],root=tmp_path).exists()
    finally:os.close(fd)


def test_service_pid_drift_during_intent_sync_stops_before_command(tmp_path,monkeypatch):
    data,request,states,calls=scenario(tmp_path);backup=data['backup'];sync=backup._sync
    leaf=api().path_for(request,backup=backup,root=tmp_path)
    def changed(path):
        sync(path)
        if path==leaf and (leaf/'stopping-smb.service.json').exists():states['smb.service']['MainPID']='101'
    with monkeypatch.context() as patch:
        patch.setattr(backup,'_sync',changed)
        with pytest.raises(ValueError):apply(data,request)
    assert (leaf/'failed.json').exists()
    assert not any(command[1]=='stop' for command in calls if command[0]=='/usr/bin/systemctl')


@pytest.mark.parametrize('mechanism',['SuccessAction','FailureAction','UpheldBy','StopWhenUnneeded'])
def test_review_stop_side_effects_are_rejected_in_readonly_snapshot(tmp_path,mechanism):
    data,request,states,calls=scenario(tmp_path)
    if mechanism=='StopWhenUnneeded':
        states['smb.service']['Wants']='cleanup.service'
        path=tmp_path/'usr/lib/systemd/system/cleanup.service';path.write_bytes(b'SYNTHETIC_CLEANUP_UNIT');path.chmod(0o644)
        states['cleanup.service']={'Id':'cleanup.service','LoadState':'loaded','StopWhenUnneeded':'yes',
            'FragmentPath':'/usr/lib/systemd/system/cleanup.service','DropInPaths':'','NeedDaemonReload':'no','Job':''}
    else:states['smb.service'][mechanism]='reboot' if mechanism!='UpheldBy' else 'outside.service'
    with pytest.raises(ValueError):api().snapshot(**{key:value for key,value in data.items() if key!='importer'})
    with pytest.raises(ValueError):apply(data,request)
    assert not any(command[1]=='stop' for command in calls if command[0]=='/usr/bin/systemctl')


def safe_dependency(root,data,request,states):
    states['smb.service']['Wants']='helper.target'
    folder=root/'usr/lib/systemd/system/helper.target.d';folder.mkdir()
    for path in (folder/'override.conf',root/'usr/lib/systemd/system/helper.target'):
        path.write_bytes(b'SYNTHETIC_SAFE_DEPENDENCY');path.chmod(0o644)
    states['helper.target']={'Id':'helper.target','LoadState':'loaded','StopWhenUnneeded':'no',
        'FragmentPath':'/usr/lib/systemd/system/helper.target','DropInPaths':'/usr/lib/systemd/system/helper.target.d/override.conf',
        'NeedDaemonReload':'no','Job':''}
    request['services']=api().snapshot(**{key:value for key,value in data.items() if key!='importer'})
    request['services_sha256']=data['backup'].digest(request['services'])


def test_safe_dependency_sources_are_bound_and_never_stopped(tmp_path):
    data,request,states,calls=scenario(tmp_path);safe_dependency(tmp_path,data,request,states)
    assert len(request['services']['dependencies']['helper.target']['sources'])==2
    apply(data,request)
    assert [command[2] for command in calls if command[0]=='/usr/bin/systemctl' and command[1]=='stop']==['smb.service','nmb.service']


@pytest.mark.parametrize('drift',['policy','fragment','dropin'])
def test_dependency_drift_during_intent_sync_refuses_stop(tmp_path,monkeypatch,drift):
    data,request,states,calls=scenario(tmp_path);safe_dependency(tmp_path,data,request,states)
    backup=data['backup'];sync=backup._sync;leaf=api().path_for(request,backup=backup,root=tmp_path)
    def changed(path):
        sync(path)
        if path==leaf and (leaf/'stopping-smb.service.json').exists():
            if drift=='policy':states['helper.target']['StopWhenUnneeded']='yes'
            elif drift=='fragment':(tmp_path/'usr/lib/systemd/system/helper.target').write_bytes(b'CHANGED')
            else:(tmp_path/'usr/lib/systemd/system/helper.target.d/override.conf').write_bytes(b'CHANGED')
    with monkeypatch.context() as patch:
        patch.setattr(backup,'_sync',changed)
        with pytest.raises(ValueError):apply(data,request)
    assert (leaf/'failed.json').exists()
    assert not any(command[1]=='stop' for command in calls if command[0]=='/usr/bin/systemctl')


def test_implicit_system_slice_with_protected_dropin_is_supported(tmp_path):
    data,request,states,calls=scenario(tmp_path)
    folder=tmp_path/'usr/lib/systemd/system/system.slice.d';folder.mkdir()
    path=folder/'oomd.conf';path.write_bytes(b'SYNTHETIC_OOM_SETTINGS');path.chmod(0o644)
    states['smb.service']['Requires']='system.slice'
    states['system.slice']={'Id':'system.slice','LoadState':'loaded','StopWhenUnneeded':'no',
        'FragmentPath':'','DropInPaths':'/usr/lib/systemd/system/system.slice.d/oomd.conf','NeedDaemonReload':'no','Job':''}
    request['services']=api().snapshot(**{key:value for key,value in data.items() if key!='importer'})
    request['services_sha256']=data['backup'].digest(request['services'])
    assert apply(data,request)['status']=='services_quiesced'
