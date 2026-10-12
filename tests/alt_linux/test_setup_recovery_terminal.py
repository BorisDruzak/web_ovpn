import pytest
import copy,json,time,os,shutil,subprocess,sys
from pathlib import Path

@pytest.fixture(autouse=True)
def root_owned_worker_child_coverage(request):
    wrappers={'test_root_owned_terminal_cases_in_root_child','test_root_owned_terminal_runtime_cases_in_root_child'}
    if os.geteuid()!=0 and request.node.name not in wrappers:
        pytest.skip('Root-owned terminal worker cases execute in the required root child wrapper')

def run_root_owned_child(test_file,tmp_path,wrapper_name):
    if os.geteuid()==0:
        return  # The ordinary cases already exercise root ownership directly.
    sudo=shutil.which('sudo')
    root_available=sudo is not None and subprocess.run([sudo,'-n','true'],capture_output=True,timeout=10).returncode==0
    if root_available:prefix=[sudo,'-n']
    else:
        fakeroot=shutil.which('fakeroot')
        assert fakeroot is not None,'Non-root terminal fixtures require sudo or fakeroot root child coverage'
        prefix=[]
    timeout=Path('/usr/bin/timeout')
    assert timeout.is_file() and timeout.stat().st_uid==0 and timeout.stat().st_mode&0o022==0,'Fixed trusted root child timeout is required'
    prefix.extend([str(timeout),'--signal=TERM','--kill-after=5','360'])
    if not root_available:prefix.extend([fakeroot,'--'])
    parent=tmp_path.resolve();child=parent/'root-worker-child'
    assert child.is_absolute() and child.parent==parent and not child.is_symlink(),'Root child must stay beneath the owned fixture parent'
    info=parent.lstat();identity=[str(getattr(info,name)) for name in ('st_dev','st_ino','st_uid','st_gid','st_mode')]
    try:
        result=subprocess.run([*prefix,sys.executable,'-B','-m','pytest','-p','no:cacheprovider',str(Path(test_file).resolve()),'-q',
            '-k','not '+wrapper_name,'--basetemp',str(child)],
            cwd=Path(test_file).resolve().parents[2],text=True,capture_output=True,timeout=390)
    finally:
        # Outside fakeroot: compare actual parent metadata in either branch.
        cleanup='''import os,shutil,sys
assert shutil.rmtree.avoids_symlink_attacks
fd=os.open(sys.argv[1],os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
try:
 info=os.fstat(fd)
 assert tuple(getattr(info,name) for name in ('st_dev','st_ino','st_uid','st_gid','st_mode'))==tuple(map(int,sys.argv[2:]))
 try:os.stat('root-worker-child',dir_fd=fd,follow_symlinks=False)
 except FileNotFoundError:pass
 else:shutil.rmtree('root-worker-child',dir_fd=fd)
finally:os.close(fd)
'''
        cleanup_prefix=[sudo,'-n'] if root_available else []
        removed=subprocess.run([*cleanup_prefix,str(timeout),'--signal=TERM','--kill-after=5','30',sys.executable,'-B','-c',cleanup,str(parent),*identity],
            text=True,capture_output=True,timeout=40)
        assert removed.returncode==0,removed.stdout+removed.stderr
    assert not child.exists(),'Root-owned fixture artifacts must be removed before the parent exits'
    assert result.returncode==0,result.stdout+result.stderr
    assert ' skipped' not in result.stdout,'Root child must execute every selected root worker case: '+result.stdout

def test_root_owned_terminal_cases_in_root_child(tmp_path):
    run_root_owned_child(__file__,tmp_path,'test_root_owned_terminal_cases_in_root_child')

def scenario(root):
    from test_setup_recovery_user_check import scenario as user_fixture
    from alt_deploy import setup_recovery_user_check as user,setup_recovery_original_policy as original,setup_recovery_policy_baseline as baseline
    request,args,calls,states=user_fixture(root)
    result=user.check_once(request,**args);args['user']=user
    startup=request['startup_request'];args.update(original=original,baseline=baseline)
    previous=args['runner'];actions=[]
    values={key:'' for key in args['policy']._values(startup['policy_request']['kerberos_request']['import_request']['rehearsal_request']['metadata'])};values.update(domains='SOSNADMIN.LOCAL',id_provider='ad')
    def runner(command,**options):
        if command[0]=='/usr/bin/bwrap' and '/usr/bin/python3.12' in command:
            previous(command,**options);return 0,json.dumps(values),''
        if command[:2] in (['/usr/bin/systemctl','stop'],['/usr/bin/systemctl','start']):
            actions.append(command);unit=command[2]
            if command[1]=='stop':states[unit].update(ActiveState='inactive',SubState='dead',MainPID='0')
            else:states[unit].update(ActiveState='active',SubState='running',MainPID='321' if unit=='sssd.service' else '222',InvocationID=('b' if unit=='sssd.service' else 'c')*32)
            return 0,'',''
        return previous(command,**options)
    args['runner']=runner
    observed=original.observe(dict(schema_version=1,policy_request=startup['policy_request'],policy_receipt=startup['policy_receipt'],source_sha256='f'*64),**{k:v for k,v in args.items() if k not in ('start','services','graph','checker','user','original','baseline')})
    meta=startup['policy_request']['kerberos_request']['import_request']['rehearsal_request']['metadata']
    from alt_deploy.setup_recovery_terminal import DEPENDENCIES,DAEMON_LINKS
    dependencies={}
    for absolute in DEPENDENCIES|{'/usr/sbin/sssd'}:
        path=root/absolute.lstrip('/');path.parent.mkdir(parents=True,exist_ok=True)
        if not path.exists():path.write_bytes(b'SYNTHETIC_EFFECT_DEPENDENCY');path.chmod(0o755)
        dependencies[absolute]=args['probe']._file(root,absolute,maximum=args['probe'].MAX_TOOL_BYTES,owner=args['owner'])
    units={unit:args['graph']._unit(unit,runner=runner,probe=args['probe'],root=root,owner=args['owner'],deadline=time.monotonic()+30) for unit in ('smb.service','nmb.service')}
    (root/'run/samba').mkdir(parents=True,exist_ok=True)
    import stat
    links={}
    for absolute,target in DAEMON_LINKS.items():
        path=root/absolute.lstrip('/');path.parent.mkdir(parents=True,exist_ok=True);path.symlink_to(target);info=path.lstat()
        links[absolute]=dict(uid=info.st_uid,gid=info.st_gid,mode=stat.S_IMODE(info.st_mode),size=info.st_size,target=target)
    terminal=dict(schema_version=1,user_request=request,user_receipt=result,baseline=baseline.projection(observed,original=original,policy=args['policy'],native=args['native'],meta=meta),source_sha256='f'*64,effects_sha256='e'*64,approval_sha256='d'*64,identity_sha256='c'*64,terminal_units=units,runtime_dependencies=dependencies,environment_files={path:args['probe']._file(root,path,owner=args['owner']) for path in ('/etc/sysconfig/sssd','/etc/sysconfig/samba')},credential_cache={'present':False},daemon_links=links)
    return terminal,args,actions,states


def test_terminal_requires_exact_request():
    from alt_deploy import setup_recovery_terminal as terminal
    with pytest.raises(ValueError):
        terminal._request({})


def test_terminal_commands_are_fixed_and_no_restart_or_reset():
    from alt_deploy import setup_recovery_terminal as terminal
    assert terminal.STOP == ['/usr/bin/systemctl', 'stop', 'sssd.service', '--job-mode=fail']
    assert terminal.START == ['/usr/bin/systemctl', 'start', 'sssd.service', '--job-mode=ignore-requirements']


def test_source_bundle_is_extended_without_changing_retained_user_prefix():
    from alt_deploy import setup_recovery_terminal_wire as wire, setup_recovery_user_wire as user
    assert wire.NAMES[:len(user.NAMES)] == user.NAMES
    with pytest.raises(ValueError): wire.build('handoff', [], {})

def test_genuine_chain_handoff_preserves_records_and_starts_once(tmp_path):
    from alt_deploy import setup_recovery_terminal as terminal
    request,args,actions,states=scenario(tmp_path)
    result=terminal.handoff_once(request,**args)
    assert [c[1:3] for c in actions]==[['stop','sssd.service'],['start','smb.service'],['start','nmb.service'],['start','sssd.service']]
    assert result['credential_continuity']=='unchanged' and result['temporary_policy_retained'] is False
    assert result['native_trust_verified'] is True and result['login_verified'] is False
    assert result['invocation_id']=='b'*32
    assert terminal.verify(request,result,**args)==result
    with pytest.raises(ValueError):terminal.handoff_once(request,**args)
    assert len(actions)==4

@pytest.mark.parametrize('change',['baseline','dependency_missing','restore_unapproved','extra_snippet','history','environment','typed_metadata'])
def test_unapproved_terminal_refuses_before_intent_or_service_action(tmp_path,change):
    from alt_deploy import setup_recovery_terminal as terminal
    request,args,actions,states=scenario(tmp_path)
    if change=='baseline':request['baseline']['original_sha256']='0'*64
    elif change=='dependency_missing':request['runtime_dependencies'].pop('/usr/libexec/sssd/sssd_pac')
    elif change=='restore_unapproved':request['terminal_units']['smb.service']['opaque_sha256']['ExecStartPost']='0'*64
    elif change=='extra_snippet':(tmp_path/'etc/sssd/conf.d/unowned.conf').write_text('unreviewed')
    elif change=='environment':
        path=tmp_path/'etc/sysconfig/samba';path.parent.mkdir(exist_ok=True);path.write_text('SMBDOPTIONS=unreviewed\n')
    elif change=='typed_metadata':request['environment_files']['/etc/sysconfig/samba']['present']=0
    else:(args['user'].path_for(request['user_request'],backup=args['backup'],root=tmp_path)/'verified.json').write_text('{}')
    with pytest.raises(ValueError):terminal.handoff_once(request,**args)
    assert actions==[] and not terminal.path_for(request,backup=args['backup'],root=tmp_path).exists()

@pytest.mark.parametrize('change',['pid','jobs','main','snippet','passwd','restart','credential','sssd_process','restore_hook','effect_dependency','retained_user'])
def test_failed_entered_terminal_is_permanently_excluded_without_cleanup(tmp_path,change):
    from alt_deploy import setup_recovery_terminal as terminal
    request,args,actions,states=scenario(tmp_path);previous=args['runner']
    def runner(command,**options):
        rc,out,err=previous(command,**options)
        if command==terminal.STOP:
            if change=='pid':states['sssd.service']['MainPID']='999'
            elif change=='main':(tmp_path/'etc/sssd/sssd.conf').write_bytes(b'changed')
            elif change=='snippet':(tmp_path/args['policy'].SNIPPET.lstrip('/')).write_bytes(b'changed')
            elif change=='sssd_process':
                proc=tmp_path/'proc/999';proc.mkdir();(proc/'comm').write_text('sssd_pac\n')
            elif change=='restore_hook':states['smb.service']['ExecStartPost']='unexpected hook'
            elif change=='effect_dependency':(tmp_path/'usr/sbin/sssd').write_bytes(b'changed')
            elif change=='retained_user':
                (args['user'].path_for(request['user_request'],backup=args['backup'],root=tmp_path)/'verified.json').write_text('{}')
        if command==terminal.START:
            if change=='restart':states['sssd.service']['NRestarts']='1'
            elif change=='passwd':(tmp_path/'etc/passwd').write_text('test.user:x:1:1::/:/bin/bash\n')
            elif change=='credential':(tmp_path/'etc/krb5.keytab').write_bytes(b'changed')
        if change=='jobs' and actions and command[:2]==['/usr/bin/systemctl','list-jobs']:out='1 unexpected.service start running\n'
        return rc,out,err
    args['runner']=runner
    with pytest.raises(ValueError):terminal.handoff_once(request,**args)
    before=len(actions);leaf=terminal.path_for(request,backup=args['backup'],root=tmp_path)
    assert (leaf/'failed.json').exists()
    assert json.loads((leaf/'failed.json').read_text())['status']=='UNKNOWN'
    with pytest.raises(ValueError):terminal.handoff_once(request,**args)
    assert len(actions)==before

@pytest.mark.parametrize('change',['keytab','configuration','verified','request','intent','failed'])
def test_final_nss_package_callback_cannot_change_retained_ordinary_proof(tmp_path,change):
    from alt_deploy import setup_recovery_terminal as terminal
    request,args,actions,states=scenario(tmp_path);result=terminal.handoff_once(request,**args)
    previous=args['runner'];observations=[];leaf=terminal.path_for(request,backup=args['backup'],root=tmp_path)
    def changed(command,**options):
        reply=previous(command,**options)
        if command[:3]==['/usr/bin/rpm','-qf','/usr/lib64/libnss_sss.so.2']:
            observations.append(True)
            if len(observations)==2:
                if change=='keytab':(tmp_path/'etc/krb5.keytab').write_bytes(b'changed')
                elif change=='configuration':(tmp_path/'etc/sssd/sssd.conf').write_bytes(b'changed')
                elif change=='failed':(leaf/'failed.json').write_text('{}')
                else:(leaf/(change+'.json')).write_text('{}')
        return reply
    args['runner']=changed
    with pytest.raises(ValueError):terminal.verify(request,result,**args)
    assert len(observations)==2 and len(actions)==4

@pytest.mark.parametrize('kind',['regular','mode','symlink'])
def test_existing_service_cache_refuses_before_terminal_intent(tmp_path,kind):
    from alt_deploy import setup_recovery_terminal as terminal
    request,args,actions,states=scenario(tmp_path);cache=tmp_path/'run/samba/krb5cc_samba'
    if kind=='symlink':cache.symlink_to(tmp_path/'etc/krb5.keytab')
    else:cache.write_bytes(b'SYNTHETIC_CACHE');cache.chmod(0o640 if kind=='mode' else 0o600)
    with pytest.raises(ValueError):terminal.handoff_once(request,**args)
    assert actions==[] and not terminal.path_for(request,backup=args['backup'],root=tmp_path).exists()

@pytest.mark.parametrize('kind',['safe','mode','symlink','hardlink','owner'])
def test_normal_service_cache_creation_is_metadata_only_and_unsafe_cache_is_unknown(tmp_path,kind,monkeypatch):
    from alt_deploy import setup_recovery_terminal as terminal
    from pathlib import Path
    from types import SimpleNamespace
    import os
    request,args,actions,states=scenario(tmp_path);cache=tmp_path/'run/samba/krb5cc_samba';previous=args['runner']
    original_open=Path.open;original_lstat=Path.lstat
    def forbidden_content(self,*args,**kwargs):
        if self==cache:raise AssertionError('Cache contents must never be read')
        return original_open(self,*args,**kwargs)
    def wrong_owner(self):
        value=original_lstat(self)
        if self==cache and kind=='owner':
            values={name:getattr(value,name) for name in ('st_mode','st_uid','st_gid','st_nlink','st_dev','st_ino','st_size','st_mtime_ns','st_ctime_ns')};values['st_uid']+=1
            return SimpleNamespace(**values)
        return value
    def changed(command,**options):
        reply=previous(command,**options)
        if command[:3]==['/usr/bin/systemctl','start','smb.service']:
            if kind=='symlink':cache.symlink_to(tmp_path/'etc/krb5.keytab')
            else:
                fd=os.open(cache,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600);os.write(fd,b'SYNTHETIC_CACHE');os.close(fd)
                if kind=='mode':cache.chmod(0o640)
                if kind=='hardlink':os.link(cache,cache.with_name('other-cache'))
        return reply
    monkeypatch.setattr(Path,'open',forbidden_content);monkeypatch.setattr(Path,'lstat',wrong_owner);args['runner']=changed
    if kind=='safe':
        result=terminal.handoff_once(request,**args);assert terminal.verify(request,result,**args)==result
        assert result['login_verified'] is False and len(actions)==4
    else:
        with pytest.raises(ValueError):terminal.handoff_once(request,**args)
        leaf=terminal.path_for(request,backup=args['backup'],root=tmp_path)
        assert json.loads((leaf/'failed.json').read_text())['status']=='UNKNOWN'

@pytest.mark.parametrize('when',['before','after_stop'])
def test_fixed_daemon_alias_substitution_refuses_without_following_link(tmp_path,when):
    from alt_deploy import setup_recovery_terminal as terminal
    request,args,actions,states=scenario(tmp_path);alias=tmp_path/'etc/alternatives/links/|usr|sbin|smbd';previous=args['runner']
    def substitute():alias.unlink();alias.symlink_to('/usr/bin/unreviewed')
    if when=='before':substitute()
    else:
        def changed(command,**options):
            reply=previous(command,**options)
            if command==terminal.STOP:substitute()
            return reply
        args['runner']=changed
    with pytest.raises(ValueError):terminal.handoff_once(request,**args)
    leaf=terminal.path_for(request,backup=args['backup'],root=tmp_path)
    if when=='before':assert actions==[] and not leaf.exists()
    else:assert len(actions)==1 and json.loads((leaf/'failed.json').read_text())['status']=='UNKNOWN'
