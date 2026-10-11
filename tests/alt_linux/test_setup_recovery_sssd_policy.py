from __future__ import annotations

import json
import os
from pathlib import Path
from unittest.mock import patch

import pytest

from test_setup_recovery_kerberos import scenario as kerberos_fixture,prove


def scenario(root):
    from alt_deploy import setup_recovery_sssd_policy as policy,setup_recovery_kerberos as kerberos,setup_recovery_import as importer
    import test_setup_recovery_backup as facts
    original=facts.scenario
    def configured(directory):
        probe,calls,values,runner=original(directory)
        (directory/'etc/sssd/sssd.conf').write_bytes(b'[sssd]\nservices = nss, pam\ndomains = SOSNADMIN.LOCAL\n[domain/SOSNADMIN.LOCAL]\nid_provider = ad\n')
        for path in policy.TOOLS:
            local=directory/path.lstrip('/');local.parent.mkdir(parents=True,exist_ok=True)
            local.write_bytes(b'SYNTHETIC_POLICY_TOOL');local.chmod(0o644 if path.endswith('.so') else 0o755)
        (directory/'etc/sssd/conf.d').mkdir(mode=0o750)
        modules=directory/policy.MODULE_DIRECTORY.lstrip('/');modules.mkdir(mode=0o755,parents=True)
        (modules.parent/'ldb').symlink_to('/etc/alternatives/links/|usr|lib64|samba|ldb')
        (modules/'tdb.so').write_bytes(b'SYNTHETIC_LDB_MODULE');(modules/'tdb.so').chmod(0o644)
        def read(command):
            if command[0]=='/usr/bin/rpm' and command[2] in policy.TOOLS:return policy.TOOLS[command[2]]
            return runner(command)
        return probe,calls,values,read
    with patch.object(facts,'scenario',configured):data,bound,runner,calls=kerberos_fixture(root)
    receipt=prove(data,bound,runner)
    request=dict(schema_version=1,kerberos_request=bound,kerberos_receipt=receipt,source_sha256='c'*64)
    calls.clear()
    def policy_runner(command,**options):
        calls.append((command,options))
        if command[0]=='/usr/bin/rpm':
            if command[1]=='-q':return 0,'libini_config 1.3.1-alt6\n',''
            if command[2] in policy.TOOLS:return 0,policy.TOOLS[command[2]]+'\n',''
            if command[2].startswith(policy.MODULE_DIRECTORY+'/'):return 0,'libldb-modules-ldap 4.21.9-alt4.p11.1\n',''
            return runner(command,**options)
        if command[0]=='/usr/bin/bwrap':
            if '/usr/sbin/sssd' in command:
                database=Path(command[command.index('--bind')+1])/'sss/db/config.ldb'
                database.write_bytes(b'SYNTHETIC_CONFIGURATION_DATABASE');database.chmod(0o600)
            if '/usr/bin/python3.12' in command:return 0,json.dumps(policy._values(bound['import_request']['rehearsal_request']['metadata'])),''
            return 0,'',''
        return runner(command,**options)
    args=dict(backup=data['backup'],probe=data['probe'],native=data['native'],kerberos=kerberos,importer=importer,
        collect=data['collect'],runner=policy_runner,root=root,owner=os.geteuid())
    return policy,request,args,calls


def test_fixed_policy_preserves_main_credentials_and_does_not_start_services(tmp_path):
    policy,request,args,calls=scenario(tmp_path);before=args['collect']()
    result=policy.install_once(request,**args)
    assert result['status']=='sssd_policy_prepared' and result['trust_verified'] is False
    assert args['collect']()==before
    assert (tmp_path/policy.SNIPPET.lstrip('/')).read_bytes()==policy._snippet(request['kerberos_request']['import_request']['rehearsal_request']['metadata'])
    assert policy.verify(request,**args)==result
    for command,options in calls:
        if command[0]=='/usr/bin/bwrap':
            assert '/etc/alternatives/links/|usr|lib64|samba|ldb' in command
            assert command[command.index('--symlink')+1]=='/usr/lib64/samba/ldb.mit'
            assert any(item.endswith('/passwd') and '/scratch-' in item for item in command)
    assert not any('start' in command or 'stop' in command or command[0]=='/usr/bin/kinit' for command,options in calls)
    with pytest.raises(ValueError):policy.install_once(request,**args)


@pytest.mark.parametrize('change',['extra','receipt','other_snippet','symlink','directory_mode','package','syntax','effective','drift','intent','scratch_drift','nss_drift','module_drift','module_link_drift'])
def test_changed_or_unsafe_policy_retains_failure_without_service_action(tmp_path,change):
    policy,request,args,calls=scenario(tmp_path)
    if change=='extra':request['command']='start'
    elif change=='receipt':request['kerberos_receipt']['kvno']+=1
    elif change=='other_snippet':(tmp_path/'etc/sssd/conf.d/other.conf').write_text('unsafe')
    elif change=='symlink':(tmp_path/policy.SNIPPET.lstrip('/')).symlink_to(tmp_path/'etc/sssd/sssd.conf')
    elif change=='directory_mode':(tmp_path/'etc/sssd/conf.d').chmod(0o777)
    original=args['runner']
    def changed(command,**options):
        rc,out,err=original(command,**options)
        if change=='package' and command[0]=='/usr/bin/rpm' and command[1]=='-qf' and command[2]=='/usr/sbin/sssctl':out='sssd-tools 9.9\n'
        if command[0]=='/usr/bin/bwrap':
            if change=='syntax' and '/usr/sbin/sssctl' in command:rc=1
            elif change=='effective' and '/usr/bin/python3.12' in command:out='{"dyndns_update":"true"}'
            elif change=='drift':(tmp_path/'etc/sssd/sssd.conf').write_bytes(b'changed')
            elif change=='intent':(policy.path_for(request,backup=args['backup'],root=tmp_path)/'intent.json').write_text('{}')
            elif change=='scratch_drift':(Path(command[command.index('--bind')+1])/'config/sssd.conf').write_bytes(b'changed')
            elif change=='nss_drift':(Path(command[command.index('--bind')+1])/'passwd').write_bytes(b'changed')
            elif change=='module_drift':(tmp_path/policy.MODULE_DIRECTORY.lstrip('/')/'tdb.so').write_bytes(b'changed')
            elif change=='module_link_drift':
                lookup=tmp_path/'usr/lib64/samba/ldb';lookup.unlink();lookup.symlink_to('/usr/lib64/samba/unreviewed')
        return rc,out,err
    args['runner']=changed
    with pytest.raises(ValueError):policy.install_once(request,**args)
    assert not any('start' in command or 'stop' in command or command[0]=='/usr/bin/kinit' for command,options in calls)
    assert not list((tmp_path/'var/lib/alt-deploy-recovery').glob('sssd-policy-*/scratch-*'))


def test_verifier_rejects_substituted_snippet(tmp_path):
    policy,request,args,calls=scenario(tmp_path);policy.install_once(request,**args)
    (tmp_path/policy.SNIPPET.lstrip('/')).write_bytes(b'changed')
    with pytest.raises(ValueError):policy.verify(request,**args)
