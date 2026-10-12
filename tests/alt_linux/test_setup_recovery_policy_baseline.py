from __future__ import annotations

import copy
from pathlib import Path
import shutil

import pytest

from test_setup_recovery_original_policy import scenario as original_fixture


def scenario(root):
    from alt_deploy import setup_recovery_original_policy as original
    request,args,calls,values,policy=original_fixture(root)
    bound=request['policy_request']['kerberos_request']['import_request']['rehearsal_request']
    backup_request=copy.deepcopy(bound['backup_request'])
    backup_request['facts']=args['collect']();backup_request['snapshot_sha256']=args['backup'].digest(backup_request['facts'])
    baseline=dict(schema_version=1,backup_request=backup_request,metadata=copy.deepcopy(bound['metadata']),source_sha256='e'*64)
    (root/policy.SNIPPET.lstrip('/')).unlink()
    shutil.rmtree(root/'var/lib/alt-deploy-recovery')
    options={key:args[key] for key in ('backup','probe','native','collect','runner','root','owner')}
    options.update(policy=policy,original=original);calls.clear()
    return baseline,options,calls,values


def test_baseline_needs_no_future_artifacts_and_preserves_original_configuration(tmp_path):
    from alt_deploy import setup_recovery_policy_baseline as baseline
    request,args,calls,values=scenario(tmp_path);before=args['collect']()
    result=baseline.observe(request,**args)
    assert result['status']=='original_sssd_policy_baseline' and result['configured_values']==values
    assert result['defaults_verified'] is result['running_policy_verified'] is result['trust_verified'] is False
    assert args['collect']()==before and not (tmp_path/'var/lib/alt-deploy-recovery').exists()
    assert not list((tmp_path/'var/lib').glob('alt-original-policy-*'))
    assert not any('start' in command or 'stop' in command or command[0]=='/usr/bin/kinit' for command,_ in calls)


def test_baseline_worker_can_be_loaded_without_package_imports(tmp_path):
    from alt_deploy import setup_recovery_policy_baseline as baseline
    request,args,calls,values=scenario(tmp_path)
    scope={'__name__':'fixed_baseline','__package__':None}
    exec(compile(Path(baseline.__file__).read_text(),'fixed_baseline','exec'),scope)
    result=scope['observe'](request,**args)
    assert result['configured_values']==values


def test_baseline_projection_matches_later_original_observer_without_receipt_cycle(tmp_path):
    from alt_deploy import setup_recovery_policy_baseline as baseline,setup_recovery_original_policy as original
    request,args,calls,values=scenario(tmp_path/'before')
    result=baseline.observe(request,**args)
    later,options,_,_,policy=original_fixture(tmp_path/'after')
    observed=original.observe(later,policy=policy,**options)
    options=dict(original=original,policy=args['policy'],native=args['native'],meta=request['metadata'])
    assert baseline.projection(result,**options)==baseline.projection(observed,**options)
    assert result['request_sha256']!=observed['request_sha256']


def test_baseline_does_not_require_imported_machine_credentials(tmp_path):
    from alt_deploy import setup_recovery_policy_baseline as baseline,setup_recovery_import as importer
    request,args,calls,values=scenario(tmp_path)
    for path in importer.FILES:(tmp_path/path.lstrip('/')).unlink()
    request['backup_request']['facts']=args['collect']()
    request['backup_request']['snapshot_sha256']=args['backup'].digest(request['backup_request']['facts'])
    result=baseline.observe(request,**args)
    assert result['configured_values']==values and not request['backup_request']['facts']['keytab_present']
    assert not any((tmp_path/path.lstrip('/')).exists() for path in importer.FILES)


@pytest.mark.parametrize('change',['extra','source','metadata','facts','main','snippet','symlink','mode','package'])
def test_unbound_or_changed_original_baseline_refuses_before_policy_parsing(tmp_path,change):
    from alt_deploy import setup_recovery_policy_baseline as baseline
    request,args,calls,values=scenario(tmp_path)
    if change=='extra':request['command']='restart'
    elif change=='source':request['source_sha256']='bad'
    elif change=='metadata':request['metadata']['hostname']='alt-a1-pc99'
    elif change=='facts':request['backup_request']['facts']['hostname']='alt-a1-pc99'
    elif change=='main':(tmp_path/'etc/sssd/sssd.conf').write_bytes(b'changed')
    elif change=='snippet':(tmp_path/args['policy'].SNIPPET.lstrip('/')).write_bytes(b'changed')
    elif change=='symlink':(tmp_path/args['policy'].SNIPPET.lstrip('/')).symlink_to(tmp_path/'etc/sssd/sssd.conf')
    elif change=='mode':(tmp_path/'etc/sssd/conf.d').chmod(0o777)
    else:
        previous=args['runner']
        def runner(command,**options):
            rc,out,err=previous(command,**options)
            if command[0]=='/usr/bin/rpm' and '/usr/sbin/sssctl' in command:out='unreviewed package\n'
            return rc,out,err
        args['runner']=runner
    with pytest.raises(ValueError):baseline.observe(request,**args)
    assert not any(command[0]=='/usr/bin/bwrap' for command,_ in calls)


@pytest.mark.parametrize('change',['main','request','module','scratch','database','last_collect'])
def test_baseline_closes_parser_and_collector_callbacks_with_protected_reads(tmp_path,change):
    from alt_deploy import setup_recovery_policy_baseline as baseline
    request,args,calls,values=scenario(tmp_path);previous=args['runner']
    def runner(command,**options):
        rc,out,err=previous(command,**options)
        if command[0]=='/usr/bin/bwrap' and '/usr/bin/python3.12' in command:
            if change=='main':(tmp_path/'etc/sssd/sssd.conf').write_bytes(b'changed')
            elif change=='request':request['source_sha256']='f'*64
            elif change=='module':(tmp_path/args['policy'].MODULE_DIRECTORY.lstrip('/')/'tdb.so').write_bytes(b'changed')
            elif change in ('scratch','database'):
                path=Path(command[command.index('--bind')+1])/('config/sssd.conf' if change=='scratch' else 'sss/db/config.ldb')
                path.write_bytes(b'changed')
        return rc,out,err
    args['runner']=runner
    if change=='last_collect':
        previous_collect=args['collect'];observed=[]
        def collect():
            value=previous_collect();observed.append(True)
            if len(observed)==2:(tmp_path/'etc/sssd/sssd.conf').write_bytes(b'changed')
            return value
        args['collect']=collect
    with pytest.raises(ValueError):baseline.observe(request,**args)
    assert not list((tmp_path/'var/lib').glob('alt-original-policy-*'))


@pytest.mark.parametrize('change',['extra','claim','schema','hash','values'])
def test_baseline_projection_is_closed_and_does_not_accept_default_or_runtime_claims(tmp_path,change):
    from alt_deploy import setup_recovery_policy_baseline as baseline
    request,args,calls,values=scenario(tmp_path);result=baseline.observe(request,**args)
    if change=='extra':result['command']='restart'
    elif change=='claim':result['defaults_verified']=0
    elif change=='schema':result['schema_version']=True
    elif change=='hash':result['original_sha256']='bad'
    else:result['configured_values']['dyndns_update']='maybe'
    with pytest.raises(ValueError):baseline.projection(result,original=args['original'],policy=args['policy'],native=args['native'],meta=request['metadata'])
