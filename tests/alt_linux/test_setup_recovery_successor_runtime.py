import json,os
from pathlib import Path
from types import SimpleNamespace
import pytest

PAIR=dict(failed_run_id='setup-run-'+'1'*32,computer_guid='11111111-2222-3333-4444-555555555555')
REQUEST=dict(schema_version=1,pair=PAIR,machine_uuid='aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee',hostname='alt-a1-pc3')

def fixture(root):
    for path,data in [('sys/class/dmi/id/product_uuid',REQUEST['machine_uuid']),('proc/sys/kernel/hostname',REQUEST['hostname'])]:
        target=root/path;target.parent.mkdir(parents=True,mode=0o700,exist_ok=True);target.write_text(data)
    (root/'var/lib/alt-deploy-recovery').mkdir(parents=True,mode=0o700)
    return root

def test_fixed_inspection_is_readonly_and_identity_bound(tmp_path):
    from alt_deploy.setup_recovery_successor_probe import inspect
    root=fixture(tmp_path);before={str(p):p.read_bytes() for p in root.rglob('*') if p.is_file()}
    proof=inspect(REQUEST,root=root,owner=os.getuid())
    assert proof==dict(REQUEST,footprints_absent=True,no_active_recovery=True)
    assert {str(p):p.read_bytes() for p in root.rglob('*') if p.is_file()}==before

def test_kernel_fqdn_matches_same_registered_short_hostname(tmp_path):
    from alt_deploy.setup_recovery_successor_probe import inspect
    root=fixture(tmp_path);(root/'proc/sys/kernel/hostname').write_text(REQUEST['hostname']+'.sosnadmin.local')
    assert inspect(REQUEST,root=root,owner=os.getuid())['hostname']==REQUEST['hostname']

def test_unrelated_kernel_dns_suffix_is_not_a_matching_machine(tmp_path):
    from alt_deploy.setup_recovery_successor_probe import inspect
    root=fixture(tmp_path);(root/'proc/sys/kernel/hostname').write_text(REQUEST['hostname']+'.unrelated.invalid')
    with pytest.raises(ValueError):inspect(REQUEST,root=root,owner=os.getuid())

@pytest.mark.parametrize('prefix',['backup-','rehearsal-','services-','import-','kerberos-','sssd-policy-','sssd-start-','native-testjoin-','user-check-','terminal-'])
def test_any_entered_workstation_stage_refuses(tmp_path,prefix):
    from alt_deploy.setup_recovery_successor_probe import inspect,encoded
    import hashlib
    root=fixture(tmp_path);token=hashlib.sha256(encoded(PAIR)).hexdigest()
    (root/'var/lib/alt-deploy-recovery'/(prefix+token)).mkdir()
    with pytest.raises(ValueError):inspect(REQUEST,root=root,owner=os.getuid())

@pytest.mark.parametrize('change',['uuid','hostname','symlink','active_worker','active_apply'])
def test_wrong_identity_unsafe_ancestry_or_active_recovery_refuses(tmp_path,change):
    from alt_deploy.setup_recovery_successor_probe import inspect
    root=fixture(tmp_path)
    if change=='uuid':(root/'sys/class/dmi/id/product_uuid').write_text('11111111-2222-3333-4444-555555555555')
    elif change=='hostname':(root/'proc/sys/kernel/hostname').write_text('alt-a1-pc4')
    elif change=='symlink':
        parent=root/'var/lib/alt-deploy-recovery';parent.rmdir();parent.symlink_to(root/'proc',target_is_directory=True)
    else:
        proc=root/'proc/123';proc.mkdir()
        args=['/usr/bin/python3','-c','exec fixed_recovery_worker'] if change=='active_worker' else ['/usr/bin/python3','/usr/local/sbin/workstationctl','--json','setup','recovery','apply','recovery-operator-'+'a'*64]
        (proc/'cmdline').write_bytes(b'\0'.join(a.encode() for a in args)+b'\0')
    with pytest.raises(ValueError):inspect(REQUEST,root=root,owner=os.getuid())

def test_source_stdin_transport_has_no_arbitrary_command_or_target_override(tmp_path):
    from alt_deploy.setup_recovery_successor_runtime import RecoverySuccessorRuntime
    calls=[]
    def runner(command,**kwargs):
        calls.append((command,kwargs))
        return 0,json.dumps(dict(REQUEST,footprints_absent=True,no_active_recovery=True)),''
    settings=SimpleNamespace(known_hosts_file=Path('/known-hosts'),private_key_file=Path('/key'))
    runtime=RecoverySuccessorRuntime(settings,runner=runner)
    machine=SimpleNamespace(uuid=REQUEST['machine_uuid'],hostname=REQUEST['hostname'],ip='192.0.2.70')
    assert runtime.inspect(machine,PAIR)['footprints_absent'] is True
    command,kwargs=calls[0]
    assert command[:3]==['/usr/bin/ssh','-F','/dev/null']
    assert 'StrictHostKeyChecking=yes' in command and 'ProxyCommand=none' in command
    assert len(command[-1].encode())<8192 and kwargs['input_text']
    frame=json.loads(kwargs['input_text']);assert frame['request']==REQUEST
    assert '_worker' in frame

def test_invalid_reply_does_not_expose_remote_diagnostics(tmp_path):
    from alt_deploy.setup_recovery_successor_runtime import RecoverySuccessorRuntime
    from alt_deploy.errors import ControlError
    settings=SimpleNamespace(known_hosts_file=Path('/known-hosts'),private_key_file=Path('/key'))
    runtime=RecoverySuccessorRuntime(settings,runner=lambda *a,**kw:(1,'SYNTHETIC_SECRET','SYNTHETIC_SECRET'))
    with pytest.raises(ControlError) as error:runtime.inspect(SimpleNamespace(uuid=REQUEST['machine_uuid'],hostname=REQUEST['hostname'],ip='192.0.2.70'),PAIR)
    assert 'SYNTHETIC_SECRET' not in str(error.value)

def test_protected_native_audit_requires_one_complete_failed_create(tmp_path):
    from alt_deploy.setup_recovery_successor_capacity import audit_preflight_failed
    path=tmp_path/'audit.log'
    common=dict(command='create',operation_id='op-'+'a'*16,backup_id=None)
    rows=[dict(common,event='command_started',timestamp='2026-10-12T12:20:00+00:00',status='started'),dict(common,event='command_failed',timestamp='2026-10-12T12:20:01+00:00',status='error',error_code='backup_preflight_failed')]
    path.write_text('\n'.join(json.dumps(row) for row in rows)+'\n');path.chmod(0o600)
    assert audit_preflight_failed(path,'2026-10-12T12:18:00+00:00','2026-10-12T12:21:03+00:00',owner=os.getuid())['preflight_failed'] is True
    path.write_text(json.dumps(rows[0])+'\n')
    with pytest.raises(ValueError):audit_preflight_failed(path,'2026-10-12T12:18:00+00:00','2026-10-12T12:21:03+00:00',owner=os.getuid())

def test_native_audit_handles_bounded_large_history_without_exporting_records(tmp_path):
    from alt_deploy.setup_recovery_successor_capacity import audit_preflight_failed
    path=tmp_path/'audit.log'
    unrelated=json.dumps(dict(command='guard',operation_id='op-'+'b'*16,backup_id=None,event='command_completed',timestamp='2026-07-12T12:00:00+00:00',status='ok',result='control_plane_allowed'))+'\n'
    common=dict(command='create',operation_id='op-'+'a'*16,backup_id=None)
    rows=[dict(common,event='command_started',timestamp='2026-10-12T12:20:00+00:00',status='started'),dict(common,event='command_failed',timestamp='2026-10-12T12:20:01+00:00',status='error',error_code='backup_preflight_failed')]
    path.write_text(unrelated*24000+'\n'.join(json.dumps(row) for row in rows)+'\n');path.chmod(0o600)
    assert path.stat().st_size>4194304
    proof=audit_preflight_failed(path,'2026-10-12T12:18:00+00:00','2026-10-12T12:21:03+00:00',owner=os.getuid())
    assert set(proof)=={'preflight_failed','operation_sha256'} and proof['preflight_failed'] is True

def test_controller_observation_is_fixed_root_readonly_source_and_requires_readiness():
    from alt_deploy.setup_recovery_successor_runtime import RecoverySuccessorRuntime
    calls=[]
    def runner(command,**kwargs):
        calls.append((command,kwargs));return 0,json.dumps(dict(schema_version=1,native_guard=True,no_active_recovery=True,capacity=dict(required_free_bytes=100,actual_free_bytes=200),backup_audit=dict(preflight_failed=True))),''
    runtime=RecoverySuccessorRuntime(SimpleNamespace(),runner=runner,readiness=lambda:dict(ready=True,checks={'fixture':True},failed_checks=[]))
    assert runtime.controller(approved_at='2026-10-12T12:18:00+00:00',finished_at='2026-10-12T12:21:03+00:00')['readiness'] is True
    command,kwargs=calls[0]
    assert command[:6]==['/usr/bin/sudo','-n','/usr/bin/python3','-I','-B','-c']
    assert json.loads(kwargs['input_text'])['request']['finished_at']=='2026-10-12T12:21:03+00:00'

def test_readonly_native_operation_lock_refuses_a_live_native_backup(tmp_path):
    import fcntl
    from alt_deploy.setup_recovery_successor_capacity import readonly_operation_lock
    path=tmp_path/'native-operation.lock';path.write_bytes(b'');path.chmod(0o600)
    with path.open('rb') as stream:
        fcntl.flock(stream,fcntl.LOCK_EX|fcntl.LOCK_NB)
        with pytest.raises((ValueError,BlockingIOError)):
            with readonly_operation_lock(path,owner=os.getuid(),group=os.getgid()):pass
    before=path.stat()
    with readonly_operation_lock(path,owner=os.getuid(),group=os.getgid()):pass
    after=path.stat()
    assert (before.st_ino,before.st_mode,before.st_uid,before.st_gid,before.st_mtime_ns,before.st_ctime_ns)==(after.st_ino,after.st_mode,after.st_uid,after.st_gid,after.st_mtime_ns,after.st_ctime_ns)

@pytest.mark.parametrize('action',['create','rehearse','restore','recover','delete'])
def test_pending_native_backup_process_refuses_even_before_lock_acquisition(tmp_path,action):
    from alt_deploy.setup_recovery_successor_probe import inspect
    root=fixture(tmp_path);proc=root/'proc/123';proc.mkdir()
    (proc/'cmdline').write_bytes(b'/usr/bin/python3\0/usr/local/sbin/alt-deploy-backup\0'+action.encode()+b'\0')
    with pytest.raises(ValueError):inspect(REQUEST,root=root,owner=os.getuid())
