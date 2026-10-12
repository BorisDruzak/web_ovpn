import copy,os,shutil,subprocess,sys
from pathlib import Path
import pytest
from alt_deploy import setup_recovery_probe as probe

@pytest.fixture(autouse=True)
def root_owned_policy_worker_cases(request):
    if os.geteuid()!=0 and request.node.name!='test_policy_worker_root_metadata_on_nonroot_runner':
        pytest.skip('Root metadata cases are required in the fakeroot child test below')


def test_policy_worker_root_metadata_on_nonroot_runner():
    if os.geteuid()==0:return
    fakeroot=shutil.which('fakeroot')
    assert fakeroot is not None,'Non-root protected-policy fixtures require fakeroot'
    result=subprocess.run([fakeroot,'--','/usr/bin/timeout','--signal=TERM','--kill-after=5','60',sys.executable,'-B','-m','pytest','-q','--tb=short',
        '-p','no:cacheprovider',str(Path(__file__).resolve()),'-k','not test_policy_worker_root_metadata_on_nonroot_runner'],
        capture_output=True,text=True,timeout=75)
    assert result.returncode==0,result.stdout+result.stderr
    assert "18 passed" in result.stdout and "skipped" not in result.stdout,result.stdout+result.stderr


TEXT='''[sssd]
config_file_version=2
services=nss, pam
user=_sssd
domains=SOSNADMIN.LOCAL
[domain/SOSNADMIN.LOCAL]
id_provider=ad
auth_provider=ad
access_provider=ad
ad_update_samba_machine_account_password=true
ad_gpo_access_control=permissive
ad_gpo_ignore_unreadable=true
chpass_provider=ad
debug_level=0
default_shell=/bin/bash
fallback_homedir=/home/%d/%u
krb5_renew_interval=1h
'''

def fixture(root):
    root.mkdir(mode=0o700)
    for path,data,mode in [('/etc/sssd/sssd.conf',TEXT.encode(),0o600),('/usr/libexec/sssd/sssd_pac',b'fixture-pac',0o755),('/usr/lib64/samba/sbin/smbd',b'fixture-smbd',0o755),('/usr/lib64/samba/sbin/nmbd',b'fixture-nmbd',0o755)]:
        file=root/path.lstrip('/');file.parent.mkdir(parents=True,exist_ok=True);file.write_bytes(data);file.chmod(mode)
    for name in ('smbd','nmbd'):
        links={f'/usr/sbin/{name}':f'/etc/alternatives/links/|usr|sbin|{name}',f'/etc/alternatives/links/|usr|sbin|{name}':f'/usr/lib64/samba/sbin/{name}'}
        for path,target in links.items():file=root/path.lstrip('/');file.parent.mkdir(parents=True,exist_ok=True);file.symlink_to(target)
    request=dict(schema_version=1,configuration=probe._file(root,'/etc/sssd/sssd.conf',private=True),domain='SOSNADMIN.LOCAL')
    return request

def test_fixed_raw_values_and_pac_protected_without_writes(tmp_path):
    from alt_deploy.setup_recovery_policy_review import observe
    root=tmp_path/'root';request=fixture(root);original=(root/'etc/sssd/sssd.conf').read_bytes();calls=[]
    def runner(command,**options):calls.append(command);return 0,'sssd-pac 2.9.8-alt3\n' if command[2].endswith('sssd_pac') else 'samba 4.21.9-alt4.p11.1\n',''
    result=observe(request,probe=probe,runner=runner,root=root)
    assert result['semantics']=='raw_configured_values_only'
    assert result['values']['domain']['fallback_homedir']==dict(present=True,value='/home/%d/%u')
    assert result['pac']['package']=='sssd-pac 2.9.8-alt3'
    assert result['execution_authorized'] is False
    assert (root/'etc/sssd/sssd.conf').read_bytes()==original
    assert calls==[['/usr/bin/rpm','-qf',path,'--qf','%{NAME} %{VERSION}-%{RELEASE}\n'] for path in ('/usr/libexec/sssd/sssd_pac','/usr/lib64/samba/sbin/smbd','/usr/lib64/samba/sbin/nmbd')]

def test_fixed_samba_environment_is_pinned_and_empty_options_reviewed(tmp_path):
    from alt_deploy.setup_recovery_policy_review import observe
    root=tmp_path/'root';request=fixture(root);file=root/'etc/sysconfig/samba';file.parent.mkdir(parents=True);file.write_text('SMBDOPTIONS=""\nNMBDOPTIONS=\nWINBINDOPTIONS=""\n');file.chmod(0o644)
    result=observe(request,probe=probe,runner=lambda cmd,**k:(0,'sssd-pac 2.9.8-alt3\n' if cmd[2].endswith('sssd_pac') else 'samba 4.21.9-alt4.p11.1\n',''),root=root)
    assert result['environment_files']['/etc/sysconfig/samba']==probe._file(root,'/etc/sysconfig/samba')
    assert result['environment_files']['/etc/sysconfig/sssd']==dict(present=False)
    assert result['environment_values']['SMBDOPTIONS']==''

def test_packaged_samba_cache_environment_is_observed_without_cache_contents(tmp_path):
    from alt_deploy.setup_recovery_policy_review import observe
    root=tmp_path/'root';request=fixture(root);file=root/'etc/sysconfig/samba';file.parent.mkdir(parents=True)
    file.write_text('SAMBAOPTIONS=""\nSMBDOPTIONS=""\nNMBDOPTIONS=""\nWINBINDOPTIONS=""\nKRB5CCNAME=FILE:/run/samba/krb5cc_samba\n');file.chmod(0o644)
    result=observe(request,probe=probe,runner=lambda cmd,**k:(0,'sssd-pac 2.9.8-alt3\n' if cmd[2].endswith('sssd_pac') else 'samba 4.21.9-alt4.p11.1\n',''),root=root)
    assert result['environment_values']['KRB5CCNAME']=='FILE:/run/samba/krb5cc_samba'
    assert result['credential_cache']=={'present':False}
    assert set(result['daemon_dependencies'])=={'/usr/lib64/samba/sbin/smbd','/usr/lib64/samba/sbin/nmbd'}
    assert len(result['daemon_links'])==4

@pytest.mark.parametrize('content',['SMBDOPTIONS="--password=PRIVATE"','UNKNOWN=PRIVATE','export SMBDOPTIONS=""','NMBDOPTIONS="$(cmd)"'])
def test_unreviewed_environment_refused_without_exposing_values(tmp_path,content):
    from alt_deploy.setup_recovery_policy_review import observe
    root=tmp_path/'root';request=fixture(root);file=root/'etc/sysconfig/samba';file.parent.mkdir(parents=True);file.write_text(content);file.chmod(0o644)
    with pytest.raises(ValueError) as caught:observe(request,probe=probe,runner=lambda *a,**k:(0,'sssd-pac 2.9.8-alt3\n',''),root=root)
    assert 'PRIVATE' not in str(caught.value)

@pytest.mark.parametrize('change',['duplicate','default','metadata','symlink','large','domain','extra','pac_package','pac_drift'])
def test_unsafe_extra_config_refused(tmp_path,change):
    from alt_deploy.setup_recovery_policy_review import observe
    root=tmp_path/'root';request=fixture(root);file=root/'etc/sssd/sssd.conf'
    if change=='duplicate':file.write_text(TEXT+'debug_level=0\n')
    elif change=='default':file.write_text('[DEFAULT]\ndebug_level=0\n'+TEXT)
    elif change=='metadata':request['configuration']['mode']=True
    elif change=='symlink':file.unlink();file.symlink_to(root/'usr/libexec/sssd/sssd_pac')
    elif change=='large':file.write_text('x'*2097153)
    elif change=='domain':request['domain']='evil'
    elif change=='extra':request['command']='start'
    if change in ('duplicate','default'):request['configuration']=probe._file(root,'/etc/sssd/sssd.conf',private=True)
    def runner(command,**options):
        if change=='pac_drift':(root/'usr/libexec/sssd/sssd_pac').write_bytes(b'drift')
        return 0,'wrong package\n' if change=='pac_package' else 'sssd-pac 2.9.8-alt3\n' if command[2].endswith('sssd_pac') else 'samba 4.21.9-alt4.p11.1\n',''
    with pytest.raises(ValueError):observe(request,probe=probe,runner=runner,root=root)

@pytest.mark.parametrize('timing',['before','after'])
def test_exact_daemon_alias_substitution_refused(tmp_path,timing):
    from alt_deploy.setup_recovery_policy_review import observe
    root=tmp_path/'root';request=fixture(root);link=root/'usr/sbin/smbd'
    def change():link.unlink();link.symlink_to('/usr/bin/other')
    if timing=='before':change()
    def runner(cmd,**options):
        if timing=='after':change()
        return 0,'sssd-pac 2.9.8-alt3\n' if cmd[2].endswith('sssd_pac') else 'samba 4.21.9-alt4.p11.1\n',''
    with pytest.raises(ValueError):observe(request,probe=probe,runner=runner,root=root)
