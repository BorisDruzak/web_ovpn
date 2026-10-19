"""Use genuine session evidence and environment, without changing a desktop."""
import os
import json
from pathlib import Path
import resource
import socket

import pytest


@pytest.fixture
def graphical(tmp_path):
    uid, gid = os.getuid(), os.getgid()
    assert uid > 0, 'Run ALT tests as the non-root service account'
    home = '/home/synthetic.user'
    (tmp_path/home.lstrip('/')).mkdir(parents=True)
    runtime = tmp_path/f'run/user/{uid}'; runtime.mkdir(parents=True)
    runtime.chmod(0o700)
    bus = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    bus.bind(str(runtime/'bus'))
    env = {'HOME':home, 'DISPLAY':':10.0', 'XDG_SESSION_TYPE':'x11', 'XDG_SESSION_ID':'40',
           'XDG_RUNTIME_DIR':f'/run/user/{uid}', 'DBUS_SESSION_BUS_ADDRESS':f'unix:path=/run/user/{uid}/bus',
           'KDE_SESSION_VERSION':'6', 'PATH':'/usr/bin:/bin', 'PRIVATE_VALUE':'SESSION-SECRET-SENTINEL'}
    def process(pid, executable, environment, group):
        directory = tmp_path/f'proc/{pid}'; directory.mkdir(parents=True)
        binary = tmp_path/executable.lstrip('/'); binary.parent.mkdir(parents=True, exist_ok=True)
        binary.write_text('root-owned fixture executable'); binary.chmod(0o755)
        (directory/'exe').symlink_to(executable)
        groups=' '.join(str(g) for g in os.getgroups())
        (directory/'status').write_text(f'Uid:\t{uid}\t{uid}\t{uid}\t{uid}\nGid:\t{gid}\t{gid}\t{gid}\t{gid}\nGroups:\t{groups}\n')
        (directory/'stat').write_text(str(pid)+' (session process) '+' '.join(['S']+['0']*18+[str(pid*100)]+['0']*20))
        (directory/'cgroup').write_text('0::'+group+'\n')
        (directory/'environ').write_bytes(b'\0'.join((k+'='+v).encode() for k,v in environment.items())+b'\0')
        return directory
    # The launcher lacks KDE_SESSION_VERSION. Plasma's actual complete
    # environment is authoritative; never reconstruct it from the SSH shell.
    launcher_env = {k:v for k,v in env.items() if k!='KDE_SESSION_VERSION'}
    launcher = process(100, '/usr/bin/startplasma-x11', launcher_env,
                       f'/user.slice/user-{uid}.slice/session-40.scope')
    plasma = process(101, '/usr/bin/plasmashell', env,
                     f'/user.slice/user-{uid}.slice/user@{uid}.service/session.slice/plasma-plasmashell.service')
    properties = {'40':{'User':str(uid),'Leader':'99','Type':'x11','Class':'user','State':'active','Remote':'yes'}}
    calls = []
    def call(argv):
        calls.append(argv)
        assert argv[0]=='loginctl'
        if argv[1]=='list-sessions': return 0, '\n'.join(s+' synthetic' for s in properties)
        if argv[1]=='show-session': return 0, '\n'.join(k+'='+v for k,v in properties[argv[2]].items())
        raise AssertionError('Unexpected command')
    def limits(pid, option):
        assert pid==101
        return (128, 1024) if option==resource.RLIMIT_NOFILE else resource.getrlimit(option)
    yield dict(root=tmp_path, uid=uid, gid=gid, home=home, call=call, limits_reader=limits,
               env=env, launcher=launcher, plasma=plasma, properties=properties, process=process, calls=calls)
    bus.close()


def discover(fixture):
    from alt_deploy.user_session import discover_session
    return discover_session(fixture['uid'],fixture['gid'],fixture['home'],root=fixture['root'],
                            call=fixture['call'],limits_reader=fixture['limits_reader'])


def test_plasma_environment_and_normal_limits_are_preserved_privately(graphical):
    context = discover(graphical)
    assert context.session_id=='40' and context.pid==101 and context.start_ticks==10100
    assert context.environment==graphical['env']
    assert context.environment['KDE_SESSION_VERSION']=='6'
    assert context.limits[resource.RLIMIT_NOFILE]==(128,1024)
    assert 'SESSION-SECRET-SENTINEL' not in repr(context)
    assert all(a[1] in ('list-sessions','show-session') for a in graphical['calls'])


@pytest.mark.parametrize('change', ['no_session','manager_only','not_graphical','inactive','wrong_uid',
    'wrong_cgroup','missing_launcher','wrong_exe','untrusted_exe','unsafe_home','no_bus',
    'wrong_display','wrong_bus','missing_kde','wrong_session','two_sessions','two_plasma'])
def test_unsafe_missing_or_ambiguous_session_is_never_ready(graphical, change):
    from alt_deploy.user_session import SessionError
    f=graphical; props=f['properties']; env=f['env']
    if change=='no_session': props.clear()
    elif change=='manager_only': props['40']['Class']='manager'
    elif change=='not_graphical': props['40']['Type']='unspecified'
    elif change=='inactive': props['40']['State']='closing'
    elif change=='wrong_uid': props['40']['User']=str(f['uid']+1)
    elif change=='wrong_cgroup': (f['launcher']/'cgroup').write_text('0::/unrelated/session-400.scope\n')
    elif change=='missing_launcher': (f['launcher']/'exe').unlink()
    elif change=='wrong_exe':
        (f['plasma']/'exe').unlink(); (f['plasma']/'exe').symlink_to('/tmp/plasmashell')
    elif change=='untrusted_exe': (f['root']/'usr/bin/plasmashell').chmod(0o777)
    elif change=='unsafe_home':
        home=f['root']/f['home'].lstrip('/'); home.rmdir(); home.symlink_to(f['root']/'tmp')
    elif change=='no_bus': (f['root']/f'run/user/{f["uid"]}/bus').unlink()
    elif change=='wrong_display': env['DISPLAY']='remote.example:10'
    elif change=='wrong_bus': env['DBUS_SESSION_BUS_ADDRESS']='tcp:host=remote.example,port=1000'
    elif change=='missing_kde': env.pop('KDE_SESSION_VERSION')
    elif change=='wrong_session': env['XDG_SESSION_ID']='41'
    elif change=='two_sessions': props['42']=dict(props['40'])
    elif change=='two_plasma':
        f['process'](102,'/usr/bin/plasmashell',env,
            f'/user.slice/user-{f["uid"]}.slice/user@{f["uid"]}.service/session.slice/plasma-plasmashell.service')
    (f['plasma']/'environ').write_bytes(b'\0'.join((k+'='+v).encode() for k,v in env.items())+b'\0')
    with pytest.raises(SessionError) as caught: discover(f)
    assert 'SESSION-SECRET-SENTINEL' not in str(caught.value)


def test_pid_reuse_during_environment_observation_is_blocked(graphical):
    from alt_deploy.user_session import SessionError
    original=graphical['limits_reader']
    def limits(pid, option):
        path=graphical['plasma']/'stat'
        path.write_text(path.read_text().replace('10100','99999'))
        return original(pid, option)
    graphical['limits_reader']=limits
    with pytest.raises(SessionError): discover(graphical)


def test_short_command_inherits_gui_environment_and_limits_without_parent_change(graphical, monkeypatch):
    from alt_deploy import user_session
    context=discover(graphical)
    monkeypatch.setattr(user_session,'_revalidate',lambda ctx:None)
    before=resource.getrlimit(resource.RLIMIT_NOFILE)
    script="import os,resource,json;print(json.dumps({'kde':os.environ['KDE_SESSION_VERSION'],'secret_preserved':os.environ['PRIVATE_VALUE']=='SESSION-SECRET-SENTINEL','limit':resource.getrlimit(resource.RLIMIT_NOFILE)[0],'uid':os.getuid()}))"
    result=user_session.run_session_command(context,['/usr/bin/python3','-c',script])
    assert result.returncode==0
    assert json.loads(result.stdout)=={'kde':'6','secret_preserved':True,'limit':128,'uid':context.uid}
    assert resource.getrlimit(resource.RLIMIT_NOFILE)==before
    assert 'SESSION-SECRET-SENTINEL' not in repr(result)


def test_stale_context_stops_before_any_launch(graphical, monkeypatch):
    from alt_deploy import user_session
    context=discover(graphical)
    def stale(ctx):raise user_session.SessionError('graphical_session_unverified')
    monkeypatch.setattr(user_session,'_revalidate',stale)
    monkeypatch.setattr(user_session.subprocess,'Popen',lambda *a,**k:pytest.fail('Must not launch'))
    with pytest.raises(user_session.SessionError):
        user_session.run_session_command(context,['/usr/bin/python3','-c','print(1)'])


def test_exec_uses_the_verified_root_binary_instead_of_a_mutable_alias(graphical, monkeypatch):
    from alt_deploy import user_session
    context=discover(graphical)
    monkeypatch.setattr(user_session,'_revalidate',lambda ctx:None)
    alias=graphical['root']/'mutable-python';alias.symlink_to('/usr/bin/python3')
    original=user_session.subprocess.Popen;commands=[]
    def start(command,**options):
        commands.append(command)
        return original(command,**options)
    monkeypatch.setattr(user_session.subprocess,'Popen',start)
    assert user_session.run_session_command(context,[str(alias),'-c','print(1)']).returncode==0
    assert commands[0][0]==str(Path('/usr/bin/python3').resolve())


@pytest.mark.parametrize('case', ['timeout','output','unsafe_binary'])
def test_own_short_lived_probe_is_bounded_without_exposing_private_output(graphical, monkeypatch, case):
    from alt_deploy import user_session
    context=discover(graphical)
    monkeypatch.setattr(user_session,'_revalidate',lambda ctx:None)
    if case=='timeout':command=['/usr/bin/python3','-c','import time;time.sleep(5)']
    elif case=='output':command=['/usr/bin/python3','-c',"print('SESSION-SECRET-SENTINEL'*10000)"]
    else:
        script=graphical['root']/'untrusted.py';script.write_text('#!/usr/bin/python3\n');script.chmod(0o777)
        command=[str(script)]
    with pytest.raises(user_session.SessionError) as caught:
        user_session.run_session_command(context,command,timeout=0.1 if case=='timeout' else 5)
    assert 'SESSION-SECRET-SENTINEL' not in str(caught.value)
