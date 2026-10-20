"""Only the confirmed empty-name wallet defect permits the bounded repair."""
import hashlib
import importlib.util
import os
from pathlib import Path
import stat

import pytest

from test_component_catalog import SOURCE
from test_user_session import graphical,discover


def helper():
    import sys
    spec=importlib.util.spec_from_file_location('fixed_wallet_repair',
        SOURCE/'roles/kwallet_empty_name_repair/files/repair_empty_wallet.py')
    module=importlib.util.module_from_spec(spec);sys.modules[spec.name]=module;spec.loader.exec_module(module)
    return module


@pytest.fixture
def wallet(graphical):
    f=graphical;home=f['root']/f['home'].lstrip('/')
    directory=home/'.local/share/kwalletd';directory.mkdir(mode=0o700,parents=True)
    config=home/'.config/kwalletrc';config.parent.mkdir(mode=0o700,exist_ok=True)
    config.write_bytes(b'# employee preference\n[Unrelated]\nDefault Wallet=keep-me\n[Wallet]\nDefault Wallet=\nFirst Use=false\nEnabled=true\n')
    config.chmod(0o600)
    for name,data in {'.kwl':b'PRIVATE-WALLET-CONTENT-SENTINEL','.salt':b'PRIVATE-SALT-SENTINEL',
                      '_attributes.json':b'{"PRIVATE-METADATA-SENTINEL":42}',
                      'other-wallet.kwl':b'PRESERVE-OTHER-WALLET'}.items():
        (directory/name).write_bytes(data);(directory/name).chmod(0o600)
    (directory/'.salt').chmod(0o400)
    return dict(f,directory=directory,config=config,context=discover(f))


def files(root):
    return {p.relative_to(root).as_posix():(p.read_bytes(),stat.S_IMODE(p.stat().st_mode),p.stat().st_mtime_ns)
            for p in root.rglob('*') if p.is_file() and not p.is_symlink()}


def inspect(module,f,name='recovered-wallet'):
    return module.inspect_wallet(f['context'],name,root=f['root'])


def test_confirmed_defect_is_readonly_and_keeps_private_bytes_out_of_observation(wallet):
    m=helper();f=wallet;before=files(f['root'])
    result=inspect(m,f)
    assert result.disposition=='repair' and result.wallet_name=='recovered-wallet'
    assert set(result.files)=={'.kwl','.salt','_attributes.json','other-wallet.kwl'}
    assert len(result.snapshot_sha256)==64
    assert 'SENTINEL' not in repr(result) and 'SESSION-' not in repr(result)
    assert files(f['root'])==before


@pytest.mark.parametrize('case',['absent','already_fixed','different_healthy_wallet'])
def test_healthy_wallet_is_a_true_noop_without_backup_or_changes(wallet,case):
    m=helper();f=wallet
    for name in ('.kwl','.salt','_attributes.json'):(f['directory']/name).unlink()
    if case=='absent':f['config'].unlink()
    else:
        f['config'].write_bytes(b'[Wallet]\nDefault Wallet='+
            (b'recovered-wallet' if case=='already_fixed' else b'other-wallet')+b'\nFirst Use=false\n')
    before=files(f['root'])
    result=inspect(m,f)
    assert result.disposition=='noop'
    assert files(f['root'])==before


@pytest.mark.parametrize('fault',['missing_kwl','missing_salt','missing_metadata','wrong_default','first_use',
    'duplicate_key','symlink','hardlink','world_readable','foreign_uid','target_collision','target_symlink'])
def test_unconfirmed_unsafe_or_conflicted_wallet_is_never_modified(wallet,fault):
    m=helper();f=wallet;context=f['context']
    if fault.startswith('missing_'):
        (f['directory']/{'missing_kwl':'.kwl','missing_salt':'.salt','missing_metadata':'_attributes.json'}[fault]).unlink()
    elif fault=='wrong_default':f['config'].write_bytes(f['config'].read_bytes().replace(b'Default Wallet=\n',b'Default Wallet=other-wallet\n'))
    elif fault=='first_use':f['config'].write_bytes(f['config'].read_bytes().replace(b'First Use=false',b'First Use=true'))
    elif fault=='duplicate_key':f['config'].write_bytes(f['config'].read_bytes()+b'Default Wallet=another\n')
    elif fault=='symlink':
        (f['directory']/'.kwl').unlink();(f['directory']/'.kwl').symlink_to(f['directory']/'other-wallet.kwl')
    elif fault=='hardlink':os.link(f['directory']/'.kwl',f['directory']/'additional-link')
    elif fault=='world_readable':(f['directory']/'.kwl').chmod(0o644)
    elif fault=='foreign_uid':
        from dataclasses import replace
        context=replace(context,uid=context.uid+1)
    elif fault=='target_collision':(f['directory']/'recovered-wallet.kwl').write_bytes(b'FOREIGN-TARGET-SENTINEL')
    elif fault=='target_symlink':(f['directory']/'recovered-wallet.kwl').symlink_to(f['directory']/'other-wallet.kwl')
    before=files(f['root'])
    with pytest.raises(m.WalletError) as caught:m.inspect_wallet(context,'recovered-wallet',root=f['root'])
    assert 'SENTINEL' not in str(caught.value) and files(f['root'])==before


@pytest.mark.parametrize('name',['','../wallet','/tmp/wallet','.','..','recovered/wallet','wallet\nInjected=true','-wallet','x'*65])
def test_wallet_basename_cannot_select_an_arbitrary_path(wallet,name):
    m=helper();before=files(wallet['root'])
    with pytest.raises(m.WalletError):inspect(m,wallet,name)
    assert files(wallet['root'])==before


@pytest.mark.parametrize('newline',[b'\n',b'\r\n'])
def test_configuration_edit_changes_only_the_empty_default_wallet_value(wallet,newline):
    m=helper();f=wallet
    original=f['config'].read_bytes().replace(b'\n',newline)
    result=m.repair_configuration(original,'custom-wallet')
    assert result==original.replace(b'Default Wallet='+newline,b'Default Wallet=custom-wallet'+newline)
    assert b'Default Wallet=keep-me' in result and b'First Use=false' in result
    with pytest.raises(m.WalletError):m.repair_configuration(result,'different-wallet')


def test_file_hash_drift_during_read_is_not_accepted_as_defect_evidence(wallet,monkeypatch):
    m=helper();f=wallet;original=m.os.read;changed=False
    def read(fd,count):
        nonlocal changed
        data=original(fd,count)
        try:selected=os.readlink('/proc/self/fd/'+str(fd))==str(f['directory']/'.kwl')
        except OSError:selected=False
        if selected and not changed:
            changed=True;(f['directory']/'.kwl').write_bytes(b'CONCURRENT-USER-EDIT')
        return data
    monkeypatch.setattr(m.os,'read',read)
    with pytest.raises(m.WalletError):inspect(m,f)
    assert changed is True


@pytest.mark.parametrize('case',['normal','reused','source_changed','state_symlink'])
def test_private_whole_wallet_backup_is_verified_before_any_daemon_or_file_effect(wallet,case):
    m=helper();f=wallet;evidence=inspect(m,f)
    (f['root']/'var/lib').mkdir(parents=True)
    namespace=f['root']/'var/lib/alt-kwallet-empty-name-repair'
    if case=='source_changed':(f['directory']/'.kwl').write_bytes(b'NEW-EMPLOYEE-CONTENT')
    if case=='state_symlink':
        other=f['root']/'foreign';other.mkdir();namespace.symlink_to(other,target_is_directory=True)
    before=files(f['directory']);config=f['config'].read_bytes()
    if case in ('source_changed','state_symlink'):
        with pytest.raises(m.WalletError):m.create_backup(evidence,'a'*64,root=f['root'])
    else:
        directory=m.create_backup(evidence,'a'*64,root=f['root'])
        assert stat.S_IMODE(directory.stat().st_mode)==0o700
        assert (directory/'kwalletrc').read_bytes()==config
        for name,value in evidence.files.items():
            path=directory/'wallets'/name
            assert path.read_bytes()==value['data']
            assert stat.S_IMODE(path.stat().st_mode)==0o600
        import json
        manifest=json.loads((directory/'manifest.json').read_text())
        assert manifest['snapshot_sha256']==evidence.snapshot_sha256
        assert manifest['helper']['pid']==os.getpid() and manifest['helper']['start_ticks']>0
        assert 'SENTINEL' not in (directory/'manifest.json').read_text()
        assert set(manifest['files'])==set(evidence.files)
        if case=='reused':
            frozen=files(directory)
            with pytest.raises(m.WalletError,match='kwallet_claim_consumed'):m.create_backup(evidence,'a'*64,root=f['root'])
            assert files(directory)==frozen
    assert files(f['directory'])==before and f['config'].read_bytes()==config


@pytest.fixture
def wallet_daemons(wallet):
    f=wallet;processes={}
    for pid,name in [(102,'kwalletd6'),(103,'ksecretd')]:
        binary=f['root']/'usr/bin'/name;binary.write_text('trusted package executable');binary.chmod(0o755)
        processes[name]=f['process'](pid,'/usr/bin/'+name,f['env'],f'/user.slice/user-{f["uid"]}.slice/user@{f["uid"]}.service')
    return dict(f,daemons=processes)


@pytest.mark.parametrize('case',['normal','other_program','duplicate','wrong_bus','changed_birth','timeout','session_changed'])
def test_only_proven_selected_wallet_daemons_receive_sigterm_once(wallet_daemons,monkeypatch,case):
    import signal,select
    m=helper();f=wallet_daemons;context=f['context']
    m._revalidate=lambda value:None
    if case=='duplicate':f['process'](104,'/usr/bin/kwalletd6',f['env'],'/another/group')
    if case=='wrong_bus':
        p=f['daemons']['kwalletd6']/'environ';p.write_bytes(p.read_bytes().replace(b'/bus',b'/other-bus'))
    if case in ('duplicate','wrong_bus'):
        with pytest.raises(m.WalletError):m.observe_daemons(context,root=f['root'])
        return
    evidence=m.observe_daemons(context,root=f['root'])
    assert len(evidence.records)==2 and 'SENTINEL' not in repr(evidence)
    opened=[];closed=[];sent=[];original_close=os.close
    monkeypatch.setattr(os,'pidfd_open',lambda pid,flags:opened.append(pid) or pid+1000)
    monkeypatch.setattr(os,'close',lambda fd:closed.append(fd) if fd in (1102,1103) else original_close(fd))
    monkeypatch.setattr(os,'kill',lambda *_:pytest.fail('No existing process may be selected by PID alone'))
    def send(fd,sig,*args):
        assert sig==signal.SIGTERM and fd in (1102,1103)
        sent.append(fd)
        if case!='timeout':(f['root']/('proc/'+str(fd-1000)+'/exe')).unlink()
    monkeypatch.setattr(signal,'pidfd_send_signal',send)
    monkeypatch.setattr(select,'select',lambda ready,*args:(ready if sent and case!='timeout' else [],[],[]))
    if case=='changed_birth':
        p=f['daemons']['kwalletd6']/'stat';p.write_text(p.read_text().replace('10200','10201'))
    elif case=='other_program':
        p=f['daemons']['kwalletd6']/'exe';p.unlink();p.symlink_to('/usr/bin/plasmashell')
    elif case=='session_changed':
        def bad(_):raise m.SessionError('graphical_session_unverified')
        m._revalidate=bad
    before=files(f['directory'])
    if case=='normal':m.stop_daemons(context,evidence,root=f['root'])
    else:
        with pytest.raises(m.WalletError):m.stop_daemons(context,evidence,root=f['root'])
    assert len(sent)==(2 if case in ('normal','timeout') else 0)
    assert len(opened)==len(closed) and files(f['directory'])==before


def test_real_same_user_no_replace_renames_preserve_wallet_bytes_modes_and_other_files(wallet,monkeypatch):
    m=helper();f=wallet;evidence=inspect(m,f);m._revalidate=lambda *_:None
    original=files(f['directory']);config=f['config'].read_bytes()
    result=m.apply_wallet_files(evidence,'a'*64,root=f['root'])
    assert result['status']=='applied'
    for source,target in [('.kwl','recovered-wallet.kwl'),('.salt','recovered-wallet.salt'),
                          ('_attributes.json','recovered-wallet_attributes.json')]:
        assert not (f['directory']/source).exists()
        assert (f['directory']/target).read_bytes()==original[source][0]
        assert stat.S_IMODE((f['directory']/target).stat().st_mode)==original[source][1]
    assert (f['directory']/'other-wallet.kwl').read_bytes()==original['other-wallet.kwl'][0]
    assert f['config'].read_bytes()==config.replace(b'Default Wallet=\n',b'Default Wallet=recovered-wallet\n')
    assert stat.S_IMODE(f['config'].stat().st_mode)==0o600
    assert inspect(m,f).disposition=='noop'
    assert 'SENTINEL' not in str(result)


@pytest.mark.parametrize('fault',['first_rename','second_rename','third_rename','config_exchange','verify_after_exchange',
    'target_race','source_edit','new_daemon','rollback_conflict','configuration_race'])
def test_failed_file_transition_rolls_back_only_proven_owned_state(wallet,monkeypatch,fault):
    m=helper();f=wallet;evidence=inspect(m,f);m._revalidate=lambda *_:None
    before={p.name:p.read_bytes() for p in f['directory'].iterdir()};oldconfig=f['config'].read_bytes()
    original=m._rename_at2;calls=0;injected=False
    def rename(oldfd,old,newfd,new,flags):
        nonlocal calls,injected
        calls+=1
        trigger={'first_rename':1,'second_rename':2,'third_rename':3,'config_exchange':4}.get(fault)
        if not injected and trigger==calls:injected=True;raise OSError('PRIVATE-SECRET-SENTINEL')
        if not injected and fault=='target_race' and calls==2:
            injected=True;(f['directory']/'recovered-wallet.salt').write_bytes(b'FOREIGN-COLLISION');(f['directory']/'recovered-wallet.salt').chmod(0o600)
        if not injected and fault=='source_edit' and calls==2:
            injected=True;(f['directory']/'recovered-wallet.kwl').write_bytes(b'NEW-USER-DATA');raise OSError('stop')
        if not injected and fault=='rollback_conflict' and calls==2:
            injected=True;(f['directory']/'.kwl').write_bytes(b'NEW-USER-SOURCE');raise OSError('stop')
        if not injected and fault=='configuration_race' and calls==4:
            injected=True;f['config'].write_bytes(oldconfig+b'# concurrent user setting\n')
        result=original(oldfd,old,newfd,new,flags)
        if not injected and fault=='verify_after_exchange' and calls==4:
            injected=True;raise OSError('PRIVATE-SECRET-SENTINEL')
        return result
    monkeypatch.setattr(m,'_rename_at2',rename)
    if fault=='new_daemon':
        original_observe=m.observe_daemons;checks=0
        def observe(*a,**kw):
            nonlocal checks
            checks+=1
            if checks>=2:return m.DaemonEvidence('f'*64,({'pid':777},))
            return original_observe(*a,**kw)
        monkeypatch.setattr(m,'observe_daemons',observe)
    with pytest.raises(m.WalletError) as caught:m.apply_wallet_files(evidence,'a'*64,root=f['root'])
    assert 'SENTINEL' not in str(caught.value)
    if fault in ('source_edit','rollback_conflict','new_daemon'):
        assert str(caught.value)=='kwallet_rollback_unverified'
        if fault=='source_edit':assert (f['directory']/'recovered-wallet.kwl').read_bytes()==b'NEW-USER-DATA'
        if fault=='rollback_conflict':assert (f['directory']/'.kwl').read_bytes()==b'NEW-USER-SOURCE'
    else:
        assert str(caught.value)=='kwallet_rollback_verified'
        for name,value in before.items():assert (f['directory']/name).read_bytes()==value
        assert f['config'].read_bytes()==oldconfig+(b'# concurrent user setting\n' if fault=='configuration_race' else b'')
        if fault=='target_race':assert (f['directory']/'recovered-wallet.salt').read_bytes()==b'FOREIGN-COLLISION'


def test_writer_refuses_to_touch_wallet_with_root_privilege(wallet,monkeypatch):
    m=helper();f=wallet;evidence=inspect(m,f);before=files(f['root'])
    monkeypatch.setattr(os,'geteuid',lambda:0)
    with pytest.raises(m.WalletError,match='kwallet_writer_identity_unverified'):
        m.apply_wallet_files(evidence,'a'*64,root=f['root'])
    assert files(f['root'])==before


def test_real_owned_writer_child_is_recorded_before_permission_to_change_files(wallet,monkeypatch):
    m=helper();f=wallet;evidence=inspect(m,f);m._revalidate=lambda *_:None
    (f['root']/'var/lib').mkdir(parents=True)
    backup=m.create_backup(evidence,'a'*64,root=f['root'])
    result=m.run_writer(evidence,'a'*64,backup,root=f['root'])
    assert result['status']=='applied'
    import json
    record=json.loads((backup/'writer.json').read_text())
    assert record['child']['uid']==f['uid'] and record['child']['gid']==f['gid']
    assert record['child']['parent_pid']==os.getpid() and record['child']['start_ticks']>0
    assert stat.S_IMODE((backup/'writer.json').stat().st_mode)==0o600
    assert 'SENTINEL' not in json.dumps(record)
    assert json.loads((backup/'file-result.json').read_text())['result']==result
    assert inspect(m,f).disposition=='noop'


def test_writer_receipt_failure_cannot_release_the_child_to_mutate(wallet,monkeypatch):
    m=helper();f=wallet;evidence=inspect(m,f);m._revalidate=lambda *_:None
    (f['root']/'var/lib').mkdir(parents=True)
    backup=m.create_backup(evidence,'a'*64,root=f['root']);before=files(f['directory'])
    original=m._private_file
    def fail(path,data):
        if path.name=='writer.json':raise OSError('PRIVATE-PASSWORD-SENTINEL')
        original(path,data)
    monkeypatch.setattr(m,'_private_file',fail)
    with pytest.raises(m.WalletError) as caught:m.run_writer(evidence,'a'*64,backup,root=f['root'])
    assert 'SENTINEL' not in str(caught.value) and files(f['directory'])==before


@pytest.mark.parametrize('case',['ok','false','timeout','unexpected'])
def test_dbus_check_uses_actual_gui_environment_and_finite_deadline(wallet,monkeypatch,case):
    m=helper();f=wallet;calls=[]
    from types import SimpleNamespace
    def run(context,argv,*,timeout):
        assert context==f['context'] and context.environment['KDE_SESSION_VERSION']=='6'
        assert context.limits
        calls.append((argv,timeout))
        if case=='timeout':raise m.SessionError('graphical_command_timeout')
        return SimpleNamespace(returncode=0,stdout={'ok':'b true\n','false':'b false\n','unexpected':'PRIVATE-SECRET-SENTINEL'}[case])
    monkeypatch.setattr(m,'run_session_command',run,raising=False)
    if case=='ok':
        result=m.verify_wallet_bus(f['context'])
        assert result['enabled'] is True and 0<=result['latency_ms']<1000
    else:
        with pytest.raises(m.WalletError,match='kwallet_dbus_unverified'):m.verify_wallet_bus(f['context'])
    assert calls==[(['/usr/bin/busctl','--user','--timeout=5','call','org.kde.kwalletd6',
                    '/modules/kwalletd6','org.kde.KWallet','isEnabled'],7)]


@pytest.mark.parametrize('case',['success','healthy','stale','repeat','stop_failure','writer_unknown','bus_failure'])
def test_root_coordinator_orders_backup_stop_writer_bus_and_never_repeats(wallet_daemons,monkeypatch,case):
    m=helper();f=wallet_daemons;m._revalidate=lambda *_:None
    (f['root']/'var/lib').mkdir(parents=True)
    if case=='healthy':
        for source in m.SOURCES:(f['directory']/source).unlink()
    readiness=m.observe_wallet(f['context'],root=f['root'])
    assert 'SENTINEL' not in repr(readiness)
    expected=readiness.snapshot_sha256 if case!='stale' else 'f'*64
    directory=f['root']/'var/lib/alt-kwallet-empty-name-repair'/('a'*64)
    trace=[];original_writer=m.run_writer
    def stop(context,proof,**kwargs):
        assert (directory/'manifest.json').is_file() and (directory/'invocation.json').is_file()
        trace.append('stop')
        if case=='stop_failure':raise m.WalletError('kwallet_daemon_exit_unverified')
        for p in f['daemons'].values():(p/'exe').unlink()
    def write(*a,**kw):
        assert trace==['stop'];trace.append('write')
        if case=='writer_unknown':return {'status':'unknown','code':'kwallet_rollback_unverified'}
        return original_writer(*a,**kw)
    def bus(context):
        assert trace==['stop','write'] and (directory/'activation.json').is_file()
        assert m.inspect_wallet(context,root=f['root']).disposition=='noop'
        trace.append('bus')
        if case=='bus_failure':raise m.WalletError('kwallet_dbus_unverified')
        for name,p in f['daemons'].items():(p/'exe').symlink_to('/usr/bin/'+name)
        return {'enabled':True,'latency_ms':140}
    monkeypatch.setattr(m,'stop_daemons',stop)
    monkeypatch.setattr(m,'run_writer',write)
    monkeypatch.setattr(m,'verify_wallet_bus',bus)
    before=files(f['directory'])
    if case=='stale':
        with pytest.raises(m.WalletError,match='kwallet_readiness_changed'):
            m.repair_wallet(f['context'],'recovered-wallet',expected,'a'*64,root=f['root'])
        assert trace==[] and not directory.exists() and files(f['directory'])==before
        return
    result=m.repair_wallet(f['context'],'recovered-wallet',expected,'a'*64,root=f['root'])
    assert 'SENTINEL' not in str(result)
    if case=='healthy':
        assert result['status']=='noop' and result['changed'] is False
        assert trace==[] and not directory.parent.exists()
    elif case in ('success','repeat'):
        assert result['status']=='repaired' and result['dbus_enabled'] is True and trace==['stop','write','bus']
        assert result['wallet_files_verified']==3 and result['latency_ms']==140
        import json
        assert json.loads((directory/'result.json').read_text())['result']==result
        if case=='repeat':
            fresh=m.observe_wallet(f['context'],root=f['root']);frozen=files(f['root']);events=list(trace)
            second=m.repair_wallet(f['context'],'recovered-wallet',fresh.snapshot_sha256,'b'*64,root=f['root'])
            assert second['status']=='noop' and trace==events and files(f['root'])==frozen
    else:
        assert result['status']=='unknown' and (directory/'result.json').is_file()
        assert trace==(['stop'] if case=='stop_failure' else ['stop','write'] if case=='writer_unknown' else ['stop','write','bus'])
        with pytest.raises(m.WalletError):
            m.repair_wallet(f['context'],'recovered-wallet',expected,'a'*64,root=f['root'])


def test_partial_rename_without_configuration_commit_never_looks_healthy(wallet):
    m=helper();f=wallet
    for old,new in [('.kwl','recovered-wallet.kwl'),('.salt','recovered-wallet.salt'),
                    ('_attributes.json','recovered-wallet_attributes.json')]:
        (f['directory']/old).rename(f['directory']/new)
    before=files(f['root'])
    with pytest.raises(m.WalletError,match='kwallet_partial_repair_unverified'):inspect(m,f)
    assert files(f['root'])==before


@pytest.mark.parametrize('case',['live','prior_boot','reused_pid'])
def test_target_guard_detects_an_orphan_writer_even_after_its_parent_exits(wallet,case):
    import json
    m=helper();f=wallet;evidence=inspect(m,f)
    (f['root']/'var/lib').mkdir(parents=True)
    backup=m.create_backup(evidence,'a'*64,root=f['root'])
    process=Path('/proc')/str(os.getpid())
    ticks=int((process/'stat').read_text().rsplit(')',1)[1].split()[19])
    boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    if case=='prior_boot':
        manifest=json.loads((backup/'manifest.json').read_text());manifest['boot_id']='aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
        (backup/'manifest.json').write_text(json.dumps(manifest));(backup/'manifest.json').chmod(0o600)
        boot='aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
    m._record(backup,'writer.json',{'schema_version':1,'operation_sha256':'a'*64,
        'snapshot_sha256':evidence.snapshot_sha256,'boot_id':boot,
        'child':{'pid':os.getpid(),'start_ticks':ticks+(1 if case=='reused_pid' else 0),
                 'parent_pid':2147483647,'uid':f['uid'],'gid':f['gid']}})
    before=files(f['directory'])
    if case=='live':
        with pytest.raises(m.WalletError,match='kwallet_previous_mutator_active'):
            m.guard_previous_mutators(backup.parent,root=f['root'])
    else:m.guard_previous_mutators(backup.parent,root=f['root'])
    assert files(f['directory'])==before
