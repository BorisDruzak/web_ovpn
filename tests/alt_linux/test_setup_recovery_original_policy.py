from __future__ import annotations

import json
from pathlib import Path

import pytest

from test_setup_recovery_sssd_policy import scenario as policy_fixture


def scenario(root):
    policy,bound,args,calls=policy_fixture(root)
    retained=policy.install_once(bound,**args)
    request=dict(schema_version=1,policy_request=bound,policy_receipt=retained,source_sha256='d'*64)
    values={key:'' for key in policy._values(bound['kerberos_request']['import_request']['rehearsal_request']['metadata'])}
    values.update(domains='SOSNADMIN.LOCAL',id_provider='ad')
    previous=args['runner']
    def runner(command,**options):
        result=previous(command,**options)
        if command[0]=='/usr/bin/bwrap' and '/usr/bin/python3.12' in command:
            return 0,json.dumps(values),''
        return result
    args['runner']=runner;calls.clear()
    return request,args,calls,values,policy


def test_original_policy_observation_and_restored_verification_preserve_files(tmp_path):
    from alt_deploy import setup_recovery_original_policy as original
    request,args,calls,values,policy=scenario(tmp_path)
    before=args['collect']();leaf=policy.path_for(request['policy_request'],backup=args['backup'],root=tmp_path)
    records={path.name:path.read_bytes() for path in leaf.iterdir()}
    receipt=original.observe(request,policy=policy,**args)
    assert receipt['configured_values']==values and receipt['defaults_verified'] is False
    assert receipt['running_policy_verified'] is False and receipt['trust_verified'] is False
    assert args['collect']()==before
    assert {path.name:path.read_bytes() for path in leaf.iterdir()}==records
    assert (tmp_path/policy.SNIPPET.lstrip('/')).exists()
    (tmp_path/policy.SNIPPET.lstrip('/')).unlink()  # Synthetic terminal action; worker never removes it.
    assert original.verify_restored(request,receipt,policy=policy,**args)==receipt
    assert args['collect']()==before and {path.name:path.read_bytes() for path in leaf.iterdir()}==records
    assert not any('start' in command or 'stop' in command or 'restart' in command or command[0]=='/usr/bin/kinit' for command,_ in calls)


@pytest.mark.parametrize('change',['extra','source','receipt','receipt_type','main','original','intent','failure','snippet','extra_snippet','mode','package'])
def test_original_observation_rejects_changed_protected_evidence(tmp_path,change):
    from alt_deploy import setup_recovery_original_policy as original
    request,args,calls,values,policy=scenario(tmp_path)
    leaf=policy.path_for(request['policy_request'],backup=args['backup'],root=tmp_path)
    if change=='extra':request['command']='restart'
    elif change=='source':request['source_sha256']='bad'
    elif change=='receipt':request['policy_receipt']['snippet_sha256']='0'*64
    elif change=='receipt_type':request['policy_receipt']['trust_verified']=0
    elif change=='main':(tmp_path/'etc/sssd/sssd.conf').write_bytes(b'changed')
    elif change=='original':(leaf/'original.conf').write_bytes(b'changed')
    elif change in ('intent','failure'):(leaf/('intent.json' if change=='intent' else 'failed.json')).write_text('{}')
    elif change=='snippet':(tmp_path/policy.SNIPPET.lstrip('/')).write_bytes(b'changed')
    elif change=='extra_snippet':(tmp_path/'etc/sssd/conf.d/other.conf').write_text('changed')
    elif change=='mode':(tmp_path/'etc/sssd/conf.d').chmod(0o777)
    else:
        previous=args['runner']
        def changed(command,**options):
            rc,out,err=previous(command,**options)
            if command[0]=='/usr/bin/rpm' and '/usr/sbin/sssctl' in command:out='unreviewed package\n'
            return rc,out,err
        args['runner']=changed
    with pytest.raises(ValueError):original.observe(request,policy=policy,**args)


@pytest.mark.parametrize('change',['duplicate','extra','domain','oversize','syntax','scratch','module','main','intent','native_final'])
def test_offline_parser_refuses_malformed_output_and_callback_drift(tmp_path,change):
    from alt_deploy import setup_recovery_original_policy as original
    request,args,calls,values,policy=scenario(tmp_path);previous=args['runner']
    leaf=policy.path_for(request['policy_request'],backup=args['backup'],root=tmp_path)
    def changed(command,**options):
        rc,out,err=previous(command,**options)
        if command[0]=='/usr/bin/bwrap':
            if change=='syntax' and '/usr/sbin/sssctl' in command:rc=1
            if '/usr/bin/python3.12' in command:
                if change=='duplicate':out=out[:-1]+',"domains":"SOSNADMIN.LOCAL"}'
                elif change=='extra':out=out[:-1]+',"password":"SYNTHETIC_SECRET"}'
                elif change=='domain':out=out.replace('SOSNADMIN.LOCAL','OTHER.LOCAL')
                elif change=='oversize':out=' '*(16384+1)
                elif change=='scratch':(Path(command[command.index('--bind')+1])/'config/sssd.conf').write_bytes(b'changed')
                elif change=='module':(tmp_path/policy.MODULE_DIRECTORY.lstrip('/')/'tdb.so').write_bytes(b'changed')
                elif change=='main':(tmp_path/'etc/sssd/sssd.conf').write_bytes(b'changed')
                elif change=='intent':(leaf/'intent.json').write_text('{}')
        return rc,out,err
    args['runner']=changed
    if change=='native_final':
        previous_collect=args['collect'];observed=[]
        def collect():
            value=previous_collect();observed.append(True)
            if len(observed)>=2:(tmp_path/'etc/sssd/sssd.conf').write_bytes(b'changed')
            return value
        args['collect']=collect
    with pytest.raises(ValueError) as caught:original.observe(request,policy=policy,**args)
    assert 'SYNTHETIC_SECRET' not in str(caught.value)
    assert not list(leaf.glob('original-policy-*'))


@pytest.mark.parametrize('change',['present','symlink','value','receipt','extra','claim_type'])
def test_restored_policy_requires_absence_and_exact_preapproved_observation(tmp_path,change):
    from alt_deploy import setup_recovery_original_policy as original
    request,args,calls,values,policy=scenario(tmp_path)
    receipt=original.observe(request,policy=policy,**args)
    path=tmp_path/policy.SNIPPET.lstrip('/')
    if change!='present':path.unlink()
    if change=='symlink':path.symlink_to(tmp_path/'etc/sssd/sssd.conf')
    elif change=='value':values['dyndns_update']='true'
    elif change=='receipt':receipt['original_sha256']='0'*64
    elif change=='extra':receipt['command']='restart'
    elif change=='claim_type':receipt['defaults_verified']=0
    with pytest.raises(ValueError):original.verify_restored(request,receipt,policy=policy,**args)


@pytest.mark.parametrize('change',['missing','provider','age','dns','server','nonascii','nonstring'])
def test_configured_values_remain_allowlisted_without_inferred_defaults(tmp_path,change):
    from alt_deploy import setup_recovery_original_policy as original
    request,args,calls,values,policy=scenario(tmp_path)
    if change=='missing':values.pop('auth_provider')
    elif change=='provider':values['id_provider']='ldap'
    elif change=='age':values['ad_maximum_machine_account_password_age']='-1'
    elif change=='dns':values['dyndns_update']='maybe'
    elif change=='server':values['ad_server']='$(command)'
    elif change=='nonascii':values['ad_server']='\u0430'
    else:values['dyndns_update']=False
    with pytest.raises(ValueError):original.observe(request,policy=policy,**args)
