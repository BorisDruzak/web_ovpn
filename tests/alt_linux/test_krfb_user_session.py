"""Bind the RFB listener to the selected employee's actual Plasma session."""
import json
import os
import signal
from pathlib import Path

import pytest

from test_user_session import graphical,discover

UUID='11111111-2222-3333-4444-555555555555'
BOOT='aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'


@pytest.fixture
def desktop(graphical):
    f=graphical;root=f['root'];home=root/f['home'].lstrip('/')
    for name,value in [('sys/class/dmi/id/product_uuid',UUID),('proc/sys/kernel/random/boot_id',BOOT)]:
        p=root/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_text(value+'\n')
    config=home/'.config/krfbrc';config.parent.mkdir(parents=True)
    config.write_text('[MainWindow]\nstartMinimized=true\n[FrameBuffer]\npreferredFrameBufferPlugin=xcb\n'
        '[Security]\nallowDesktopControl=true\nallowUnattendedAccess=true\nnoWallet=true\n'
        'desktopPassword=PRIVATE-OBSCURED-SENTINEL\nunattendedPassword=PRIVATE-OBSCURED-SENTINEL\n')
    config.chmod(0o600)
    autostart=home/'.config/autostart/org.sosn.krfb.desktop';autostart.parent.mkdir()
    autostart.write_text('[Desktop Entry]\nType=Application\nExec=/usr/bin/krfb\nTerminal=false\n')
    autostart.chmod(0o644)
    process=f['process'](102,'/usr/bin/krfb',f['env'],f'/user.slice/user-{f["uid"]}.slice/session-40.scope')
    (process/'fd').mkdir();(process/'fd/7').symlink_to('socket:[1999]')
    # Linux /proc/net is a kernel link to the observer's own network namespace.
    network=root/f'proc/{os.getpid()}/net';network.mkdir(parents=True)
    (root/'proc/net').symlink_to(str(os.getpid())+'/net',target_is_directory=True)
    def row(inode=1999,uid=f['uid'],state='0A'):
        return f' 0: 00000000:170C 00000000:0000 {state} 00000000:00000000 00:00000000 00000000 {uid} 0 {inode}\n'
    (network/'tcp').write_text('header\n'+row());(network/'tcp6').write_text('header\n')
    def call(argv):
        if argv==['hostname','-s']:return 0,'alt-test-pc1'
        if argv==['getent','-s','sss','passwd','synthetic.user@sosnadmin.local']:
            return 0,f'synthetic.user:x:{f["uid"]}:{f["gid"]}:Synthetic:{f["home"]}:/bin/bash\n'
        return f['call'](argv)
    return dict(f,config=config,autostart=autostart,krfb=process,row=row,probe_call=call)


def inspect(f):
    from alt_deploy.krfb_user_session import observe_session
    request={'machine_uuid':UUID,'hostname':'alt-test-pc1','login':'synthetic.user'}
    return observe_session(request,root=f['root'],call=f['probe_call'],limits_reader=f['limits_reader'])


def test_selected_listener_has_private_real_graphical_identity(desktop):
    result=inspect(desktop)
    assert result['machine_uuid']==UUID and result['boot_id']==BOOT
    assert result['uid']==desktop['uid'] and result['session_id']=='40'
    assert result['krfb_pid']==102 and result['krfb_start_ticks']==10200
    assert result['listener_present'] is True and result['connected_clients']==0
    assert result['configuration_safe'] is True and result['autostart_safe'] is True
    assert len(result['snapshot_sha256'])==64 and len(result['session_sha256'])==64
    assert 'SENTINEL' not in json.dumps(result)


@pytest.mark.parametrize('fault',['uuid','hostname','local_shadow','no_session','wrong_display','second_process',
    'untrusted_exe','wrong_socket_owner','foreign_listener','config_symlink','config_mode','duplicate_key'])
def test_unproven_session_process_or_configuration_never_becomes_ready(desktop,fault):
    from alt_deploy.krfb_user_session import KRFBSessionError as KRFBError
    f=desktop;root=f['root']
    if fault=='uuid':(root/'sys/class/dmi/id/product_uuid').write_text(BOOT)
    elif fault=='hostname':f['probe_call']=lambda argv:(0,'another-host')
    elif fault=='local_shadow':
        old=f['probe_call'];f['probe_call']=lambda argv:(0,'root:x:0:0:Root:/root:/bin/bash') if argv[0]=='getent' else old(argv)
    elif fault=='no_session':f['properties'].clear()
    elif fault=='wrong_display':
        (f['krfb']/'environ').write_bytes((f['krfb']/'environ').read_bytes().replace(b':10.0',b':99.0'))
    elif fault=='second_process':f['process'](103,'/usr/bin/krfb',f['env'],'/another/group')
    elif fault=='untrusted_exe':(root/'usr/bin/krfb').chmod(0o777)
    elif fault=='wrong_socket_owner':(root/'proc/net/tcp').write_text('header\n'+f['row'](uid=f['uid']+1))
    elif fault=='foreign_listener':(f['krfb']/'fd/7').unlink()
    elif fault=='config_symlink':
        target=f['config'].with_suffix('.original');f['config'].rename(target);f['config'].symlink_to(target)
    elif fault=='config_mode':f['config'].chmod(0o666)
    elif fault=='duplicate_key':f['config'].write_text(f['config'].read_text()+'noWallet=false\n')
    with pytest.raises(KRFBError) as caught:inspect(f)
    assert 'SENTINEL' not in str(caught.value)


def test_connected_clients_are_observed_without_signalling_or_writing(desktop,monkeypatch):
    f=desktop;before=f['config'].read_bytes();(f['krfb']/'fd/8').symlink_to('socket:[2000]')
    (f['root']/'proc/net/tcp').write_text('header\n'+f['row']()+f['row'](inode=2000,state='01'))
    monkeypatch.setattr(os,'kill',lambda *a:pytest.fail('Read-only observer must not signal a process'))
    assert inspect(f)['connected_clients']==1
    assert f['config'].read_bytes()==before


def test_absent_server_is_a_valid_unready_observation(desktop):
    f=desktop;(f['krfb']/'exe').unlink();(f['root']/'proc/net/tcp').write_text('header\n')
    result=inspect(f)
    assert result['krfb_pid'] is None and result['listener_present'] is False


def test_absent_employee_home_waits_for_a_real_first_login(desktop):
    from alt_deploy.krfb_user_session import KRFBSessionError
    f=desktop;home=f['root']/f['home'].lstrip('/')
    home.rename(home.with_name('not-yet-created-employee-home'))
    with pytest.raises(KRFBSessionError) as caught:inspect(f)
    assert str(caught.value)=='graphical_session_unavailable'


@pytest.mark.parametrize('case',['security','autostart'])
def test_kconfig_has_no_configparser_default_inheritance(desktop,case):
    f=desktop
    if case=='security':
        f['config'].write_text(f['config'].read_text().replace('[Security]','[DEFAULT]')+'\n[Security]\n')
        assert inspect(f)['configuration_safe'] is False
    else:
        f['autostart'].write_text(f['autostart'].read_text().replace('[Desktop Entry]','[DEFAULT]')+'\n[Desktop Entry]\n')
        assert inspect(f)['autostart_safe'] is False


@pytest.mark.parametrize('case',['graceful','clients','birth_changed','timeout','session_changed'])
def test_only_proven_client_free_krfb_may_receive_one_graceful_pidfd_signal(desktop,monkeypatch,case):
    from alt_deploy import krfb_user_session as module
    from alt_deploy.user_session import _process
    f=desktop;context=discover(f)
    record=_process(f['root'],f['krfb'],f['uid'],f['gid'],{'/usr/bin/krfb'})
    sent=[];closed=[];opened=[];selected=[]
    def revalidate(value):
        assert value==context
        if case=='session_changed':raise module.SessionError('graphical_session_unverified')
    monkeypatch.setattr(module,'_revalidate',revalidate,raising=False)
    monkeypatch.setattr(os,'pidfd_open',lambda pid,flags:opened.append((pid,flags)) or 999)
    monkeypatch.setattr(os,'close',lambda fd:closed.append(fd))
    monkeypatch.setattr(os,'kill',lambda *a:pytest.fail('Never select an existing process by PID alone'))
    def send(fd,sig,*args):
        sent.append((fd,sig));assert (fd,sig)==(999,signal.SIGTERM)
        if case!='timeout':(f['krfb']/'exe').unlink()
    monkeypatch.setattr(signal,'pidfd_send_signal',send)
    def wait(read,write,error,timeout):
        selected.append(timeout)
        return ((read if sent and case!='timeout' else []),[],[])
    import select
    monkeypatch.setattr(select,'select',wait)
    if case=='clients':
        (f['krfb']/'fd/8').symlink_to('socket:[2000]')
        (f['root']/'proc/net/tcp').write_text('header\n'+f['row']()+f['row'](inode=2000,state='01'))
    elif case=='birth_changed':record['start_ticks']+=1
    before=f['config'].read_bytes()
    if case=='graceful':module.stop_krfb(context,record,root=f['root'])
    else:
        with pytest.raises(module.KRFBSessionError):module.stop_krfb(context,record,root=f['root'])
    assert f['config'].read_bytes()==before
    assert len(sent)==(1 if case in ('graceful','timeout') else 0)
    assert len(closed)==len(opened)
    assert all(0<=timeout<=10 for timeout in selected)


def test_long_lived_launcher_preserves_gui_limits_and_drops_privilege_before_exec(desktop,monkeypatch):
    from alt_deploy import krfb_user_session as module
    f=desktop;context=discover(f);operations=[];started=[]
    monkeypatch.setattr(module,'_revalidate',lambda value:None,raising=False)
    monkeypatch.setattr(module,'_trusted_program',lambda argv:argv[0],raising=False)
    monkeypatch.setattr(os,'geteuid',lambda:0)
    for name in ('setgroups','setgid','setuid','umask'):
        monkeypatch.setattr(os,name,lambda value,name=name:operations.append((name,value)))
    import resource,subprocess
    monkeypatch.setattr(resource,'setrlimit',lambda key,value:operations.append(('limit',(key,value))))
    class Pipe:
        closed=False
        def write(self,value):operations.append(('dispatch',value))
        def flush(self):pass
        def close(self):self.closed=True
    class Process:
        pid=999
        stdin=Pipe()
        def poll(self):return None
    def start(argv,**options):
        started.append((argv,options));options['preexec_fn']();return Process()
    monkeypatch.setattr(subprocess,'Popen',start)
    identity={'pid':999,'start_ticks':123,'uid':context.uid,'gid':context.gid}
    monkeypatch.setattr(module,'_launch_identity',lambda *a:identity)
    monkeypatch.setattr(os,'pidfd_open',lambda *a:998)
    monkeypatch.setattr(os,'close',lambda *a:None)
    monkeypatch.setattr(module.select,'select',lambda *a:([],[],[]))
    def register(value):operations.append(('register',value));return True
    assert module.launch_krfb(context,register_child=register)==identity
    argv,options=started[0]
    assert argv[1:4]==['-I','-c',module._DISPATCH_GATE]
    assert argv[4:]==['/usr/bin/systemd-run','--user','--scope','--collect','--quiet',
                  '--unit=app-alt-krfb-'+str(context.uid)+'-'+context.session_id,
                  '--','/usr/bin/krfb']
    assert options['env']==context.environment
    assert options['stdin']==subprocess.PIPE and options['stdout']==options['stderr']==subprocess.DEVNULL
    assert options['start_new_session'] is True and options['close_fds'] is True
    assert options['cwd']==context.home
    assert [entry for entry in operations if entry[0]=='limit']==[('limit',item) for item in context.limits.items()]
    assert operations[-5:]==[('setgroups',context.groups),('setgid',context.gid),('setuid',context.uid),
                             ('register',identity),('dispatch',b'1')]


def test_launcher_never_falls_back_to_the_ssh_session_when_user_manager_is_untrusted(desktop,monkeypatch):
    from alt_deploy import krfb_user_session as module
    from alt_deploy.user_session import SessionError
    import subprocess
    context=discover(desktop)
    monkeypatch.setattr(module,'_revalidate',lambda value:None)
    def trusted(argv):
        if argv[0]=='/usr/bin/systemd-run':raise SessionError('graphical_command_unverified')
        return argv[0]
    monkeypatch.setattr(module,'_trusted_program',trusted)
    monkeypatch.setattr(subprocess,'Popen',lambda *_a,**_k:pytest.fail('No launch from the SSH session'))
    with pytest.raises(module.KRFBSessionError,match='krfb_runtime_launch_unverified'):
        module.launch_krfb(context,register_child=lambda _:True)


def test_dispatch_gate_eof_cannot_launch_after_parent_disappears(tmp_path):
    import subprocess,sys
    from alt_deploy.krfb_user_session import _DISPATCH_GATE
    marker=tmp_path/'dispatched'
    command=[sys.executable,'-I','-c',_DISPATCH_GATE,sys.executable,'-I','-c',
             'from pathlib import Path;Path('+repr(str(marker))+').write_text("started")']
    assert subprocess.run(command,input=b'',capture_output=True,timeout=5).returncode==4
    assert not marker.exists()
    assert subprocess.run(command,input=b'1',capture_output=True,timeout=5).returncode==0
    assert marker.read_text()=='started'


def test_failed_durable_launch_receipt_leaves_no_dispatchable_child(desktop,monkeypatch,tmp_path):
    import dataclasses,sys
    from alt_deploy import krfb_user_session as module
    context=dataclasses.replace(discover(desktop),home=str(tmp_path))
    monkeypatch.setattr(module,'_revalidate',lambda _:None)
    monkeypatch.setattr(module,'_trusted_program',lambda argv:str(Path(sys.executable).resolve()) if argv[0]==sys.executable else argv[0])
    observed=[]
    def register(identity):
        observed.append(identity)
        assert Path('/proc',str(identity['pid'])).exists()
        raise OSError('durability failure')
    with pytest.raises(module.KRFBSessionError,match='krfb_runtime_launch_unverified'):
        module.launch_krfb(context,register_child=register)
    assert len(observed)==1
    assert not Path('/proc',str(observed[0]['pid'])).exists()
