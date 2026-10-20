"""Compose the one-shot KRFB transaction without signalling any real desktop."""
import hashlib
import json
import os
from pathlib import Path
import stat

import pytest

from test_krfb_user_session import desktop
from test_user_session import graphical
from test_krfb_managed_runtime import prepared_assessment, desired_configuration


def tree(root):
    return {str(p.relative_to(root)):p.read_bytes() for p in root.rglob('*')
            if p.is_file() and not p.is_symlink()}


def transaction_fixture(f,monkeypatch,*,running=True,correct=False,clients=False):
    from alt_deploy import krfb_managed_runtime as module
    if correct:f['config'].write_bytes(desired_configuration())
    if not running:
        (f['krfb']/'exe').unlink();(f['root']/'proc/net/tcp').write_text('header\n')
    if clients:
        (f['krfb']/'fd/8').symlink_to('socket:[2000]')
        (f['root']/'proc/net/tcp').write_text('header\n'+f['row']()+f['row'](inode=2000,state='01'))
    request,assessment=prepared_assessment(f,monkeypatch)
    directory=f['root']/'var/lib/alt-krfb-user-runtime'/request['context']['claim_sha256']
    trace=[]
    def stop(context,record,**kwargs):
        assert (directory/'manifest.json').exists()
        assert (directory/'krfbrc').read_bytes()==f['config'].read_bytes()
        trace.append('stop')
        (f['krfb']/'exe').unlink();(f['root']/'proc/net/tcp').write_text('header\n')
        # KRFB saves its last in-memory configuration while exiting. Merge the
        # desired values after exit, preserving newly saved unrelated values.
        f['config'].write_bytes(f['config'].read_bytes()+b'\n[Employee]\nPosition=42,73\n')
    def write(context,contents,expected,*,register_child,**kwargs):
        assert (directory/'manifest.json').is_file()
        assert register_child({'pid':os.getpid(),'start_ticks':123,'parent_pid':os.getpid(),
                               'uid':f['uid'],'gid':f['gid']}) is True
        assert (directory/'writer.json').is_file()
        trace.append('write')
        for name,target in [('krfbrc',f['config']),('org.sosn.krfb.desktop',f['autostart'])]:
            assert hashlib.sha256(target.read_bytes()).hexdigest()==expected[name]
            target.write_bytes(contents[name])
    def launch(context,*,register_child):
        assert (directory/'manifest.json').is_file()
        assert b'fixture-desktop' not in f['config'].read_bytes()
        assert module.prepare_configuration(f['config'].read_bytes(),request['configuration'].encode(),context)==f['config'].read_bytes()
        identity={'pid':104,'start_ticks':10400,'boot_id':assessment.snapshot['boot_id'],
                  'uid':context.uid,'gid':context.gid,'command_sha256':'d'*64}
        assert register_child(identity) is True
        trace.append('launch')
        process=f['process'](104,'/usr/bin/krfb',f['env'],f'/user.slice/user-{f["uid"]}.slice/user@{f["uid"]}.service/app.slice/app-alt-krfb-{f["uid"]}-40.scope')
        (process/'fd').mkdir();(process/'fd/7').symlink_to('socket:[1999]')
        (f['root']/'proc/net/tcp').write_text('header\n'+f['row']())
        return identity
    monkeypatch.setattr(module,'stop_krfb',stop,raising=False)
    monkeypatch.setattr(module,'write_user_configuration',write)
    monkeypatch.setattr(module,'launch_krfb',launch,raising=False)
    return module,request,assessment,directory,trace


def apply(module,request,f):
    return module.ensure_session(request,root=f['root'],call=f['probe_call'],limits_reader=f['limits_reader'])


@pytest.mark.parametrize('case',['reload','new','noop','clients_wait','stale','consumed'])
def test_transaction_proves_order_preserves_data_and_never_replays(desktop,monkeypatch,case):
    f=desktop
    module,request,initial,directory,trace=transaction_fixture(f,monkeypatch,
        running=case!='new',correct=case=='noop',clients=case=='clients_wait')
    before=tree(f['root'])
    if case=='stale':request['expected_snapshot_sha256']='0'*64
    if case=='consumed':
        module.create_runtime_backup(request,initial,root=f['root']);before=tree(f['root'])
    if case in ('stale','consumed'):
        with pytest.raises(module.KRFBSessionError):apply(module,request,f)
        assert trace==[] and f['config'].read_bytes()==before[str(f['config'].relative_to(f['root']))]
        return
    result=apply(module,request,f)
    assert 'SENTINEL' not in json.dumps(result) and 'Password' not in json.dumps(result)
    if case in ('noop','clients_wait'):
        assert result['status']==('noop' if case=='noop' else 'waiting')
        assert result['changed'] is False and trace==[] and not directory.exists()
        assert f['config'].read_bytes()==before[str(f['config'].relative_to(f['root']))]
    else:
        assert result['status']=='configured' and result['requires_direct_probe'] is True
        assert result['changed'] is True
        assert trace==(['write','launch'] if case=='new' else ['stop','write','launch'])
        if case=='reload':assert b'[Employee]\nPosition=42,73\n' in f['config'].read_bytes()
        receipt=json.loads((directory/'result.json').read_text())
        assert receipt['result']==result and receipt['context']==request['context']
        assert stat.S_IMODE((directory/'writer.json').stat().st_mode)==0o600
        frozen=tree(directory)
        with pytest.raises(module.KRFBSessionError):apply(module,request,f)
        assert tree(directory)==frozen


@pytest.mark.parametrize('fault',['stop_timeout','write_failure','launch_failure','policy_drift','writer_receipt_failure',
                                 'new_process_before_write','session_changed','client_race'])
def test_uncertain_effects_keep_claim_and_never_repeat_or_kill_new_process(desktop,monkeypatch,fault):
    f=desktop;module,request,initial,directory,trace=transaction_fixture(f,monkeypatch)
    original_stop=module.stop_krfb;original_write=module.write_user_configuration
    def stop(*a,**kw):
        if fault=='client_race':raise module.KRFBSessionError('krfb_clients_connected')
        original_stop(*a,**kw)
        if fault=='stop_timeout':raise module.KRFBSessionError('krfb_runtime_outcome_unverified')
        if fault=='new_process_before_write':
            process=f['process'](105,'/usr/bin/krfb',f['env'],'/another/group')
            (process/'fd').mkdir();(process/'fd/7').symlink_to('socket:[1999]')
            (f['root']/'proc/net/tcp').write_text('header\n'+f['row']())
        if fault=='session_changed':f['properties']['40']['State']='closing'
        if fault=='policy_drift':
            monkeypatch.setattr(module,'read_direct_policy',lambda *a,**k:dict(initial.policy,snapshot_sha256='9'*64,external_policy_sha256='8'*64))
    def write(*a,**kw):
        original_write(*a,**kw)
        if fault=='write_failure':raise RuntimeError('PRIVATE-PASSWORD-SENTINEL')
    monkeypatch.setattr(module,'stop_krfb',stop)
    monkeypatch.setattr(module,'write_user_configuration',write)
    if fault=='launch_failure':monkeypatch.setattr(module,'launch_krfb',lambda *_:(_ for _ in ()).throw(RuntimeError('PRIVATE-SECRET-SENTINEL')))
    if fault=='writer_receipt_failure':
        original=module._write_private
        def fail(path,data):
            if path.name=='writer.json':raise OSError('PRIVATE-SECRET-SENTINEL')
            original(path,data)
        monkeypatch.setattr(module,'_write_private',fail)
    result=apply(module,request,f)
    assert result['status']==('blocked' if fault=='client_race' else 'unknown')
    assert result['code']==('krfb_clients_connected' if fault=='client_race' else 'krfb_runtime_outcome_unverified')
    assert result['changed'] is (fault!='client_race')
    assert 'SENTINEL' not in json.dumps(result)
    assert (directory/'manifest.json').exists() and (directory/'result.json').exists()
    assert 'launch' not in trace
    if fault=='new_process_before_write':assert (f['root']/'proc/105/exe').is_symlink() and 'write' not in trace
    frozen=tree(directory)
    with pytest.raises(module.KRFBSessionError):apply(module,request,f)
    assert tree(directory)==frozen


def test_target_lock_rejects_concurrent_helper_without_user_effects(desktop,monkeypatch):
    import fcntl
    f=desktop;module,request,initial,directory,trace=transaction_fixture(f,monkeypatch)
    namespace=directory.parent;namespace.mkdir(mode=0o700)
    path=namespace/'runtime.lock';path.touch(mode=0o600)
    with path.open('r+b') as stream:
        fcntl.flock(stream,fcntl.LOCK_EX|fcntl.LOCK_NB)
        with pytest.raises(module.KRFBSessionError,match='krfb_runtime_busy'):apply(module,request,f)
    assert trace==[] and not directory.exists()


def test_already_configured_stopped_server_starts_without_rewriting_user_files(desktop,monkeypatch):
    f=desktop;module,request,initial,directory,trace=transaction_fixture(f,monkeypatch,running=False,correct=True)
    before=(f['config'].read_bytes(),f['config'].stat().st_mtime_ns,f['autostart'].stat().st_mtime_ns)
    result=apply(module,request,f)
    assert result['status']=='configured' and trace==['launch']
    assert not (directory/'writer.json').exists()
    assert before==(f['config'].read_bytes(),f['config'].stat().st_mtime_ns,f['autostart'].stat().st_mtime_ns)


def test_next_fresh_claim_is_true_noop_after_success(desktop,monkeypatch):
    f=desktop;module,request,initial,directory,trace=transaction_fixture(f,monkeypatch)
    assert apply(module,request,f)['status']=='configured'
    fresh,_=prepared_assessment(f,monkeypatch);fresh['context']['claim_sha256']='9'*64
    before=tree(f['root']);events=list(trace)
    result=apply(module,fresh,f)
    assert result['status']=='noop' and result['changed'] is False and trace==events
    assert tree(f['root'])==before


def test_human_process_appearing_after_write_is_not_stopped_or_launched_again(desktop,monkeypatch):
    f=desktop;module,request,initial,directory,trace=transaction_fixture(f,monkeypatch,running=False)
    original=module.write_user_configuration;launch=module.launch_krfb
    def write(*a,**kw):
        original(*a,**kw)
        launch(a[0],register_child=lambda _:True);trace.remove('launch')
    monkeypatch.setattr(module,'write_user_configuration',write)
    monkeypatch.setattr(module,'launch_krfb',lambda *_:pytest.fail('Do not launch over a human-started process'))
    result=apply(module,request,f)
    assert result['status']=='configured' and result['requires_direct_probe'] is True
    assert trace==['write'] and (f['root']/'proc/104/exe').is_symlink()


def test_listener_startup_timeout_never_relaunches_or_stops_the_new_child(desktop,monkeypatch):
    f=desktop;module,request,initial,directory,trace=transaction_fixture(f,monkeypatch,running=False)
    def launch(*_,register_child):
        identity={'pid':104,'start_ticks':10400,'boot_id':initial.snapshot['boot_id'],
                  'uid':f['uid'],'gid':f['gid'],'command_sha256':'d'*64}
        assert register_child(identity) is True
        trace.append('launch');return identity
    ticks=iter([0,0,21])
    monkeypatch.setattr(module,'launch_krfb',launch)
    monkeypatch.setattr(module.time,'monotonic',lambda:next(ticks))
    monkeypatch.setattr(module.time,'sleep',lambda *_:None)
    result=apply(module,request,f)
    assert result['status']=='unknown' and trace==['write','launch']
    assert json.loads((directory/'launch.json').read_text())['child']['pid']==104
    assert not (directory/'launch-confirmed.json').exists()


@pytest.mark.parametrize('case',['symlink','hardlink','mode'])
def test_unsafe_target_lock_is_rejected_before_backup_or_user_effects(desktop,monkeypatch,case):
    f=desktop;module,request,initial,directory,trace=transaction_fixture(f,monkeypatch)
    directory.parent.mkdir(mode=0o700)
    lock=directory.parent/'runtime.lock';other=f['root']/'unrelated';other.write_bytes(b'')
    if case=='symlink':lock.symlink_to(other)
    elif case=='hardlink':os.link(other,lock)
    else:lock.touch(mode=0o644)
    with pytest.raises(module.KRFBSessionError,match='krfb_runtime_lock_unverified'):apply(module,request,f)
    assert trace==[] and not directory.exists()
