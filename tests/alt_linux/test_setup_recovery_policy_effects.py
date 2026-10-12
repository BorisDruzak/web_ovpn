from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from test_setup_recovery_policy_baseline import scenario as baseline_fixture


def scenario(root):
    from alt_deploy import setup_recovery_policy_baseline as baseline
    from alt_deploy import setup_recovery_policy_effects as effects
    bound,args,calls,values=baseline_fixture(root)
    receipt=baseline.observe(bound,**args)
    request=dict(schema_version=1,baseline_request=bound,baseline_receipt=receipt,source_sha256='f'*64)
    options=dict(args,baseline=baseline)
    inventory={'cn=sssd,cn=config':['domains'],
               'cn=SOSNADMIN.LOCAL,cn=domain,cn=config':['id_provider']}
    effect_values={key:dict(present=False,value='') for key in effects.KEYS}
    effect_values['id_provider']=dict(present=True,value='ad')
    data=dict(configured=effect_values,key_inventory=inventory,domains='SOSNADMIN.LOCAL')
    for path,package in effects.DEPENDENCIES.items():
        file=root/path.lstrip('/');file.parent.mkdir(parents=True,exist_ok=True)
        file.write_bytes(path.encode());file.chmod(0o755)
    previous=args['runner']
    def runner(command,**keywords):
        if command[0]=='/usr/bin/rpm' and command[1]=='-qf' and command[2] in effects.DEPENDENCIES:
            return 0,effects.DEPENDENCIES[command[2]]+'\n',''
        rc,out,err=previous(command,**keywords)
        if command[0]=='/usr/bin/bwrap' and '/usr/bin/python3.12' in command:
            out=json.dumps(data)
        return rc,out,err
    options['runner']=runner;calls.clear()
    return effects,request,options,calls,data


def test_effect_inventory_preserves_files_and_claims_no_review_or_execution(tmp_path):
    effects,request,args,calls,data=scenario(tmp_path)
    before={str(p.relative_to(tmp_path)):p.read_bytes() for p in tmp_path.rglob('*') if p.is_file()}
    receipt=effects.observe(request,**args)
    assert receipt['status']=='original_policy_effect_inventory'
    assert receipt['configured']==data['configured'] and receipt['key_inventory']==data['key_inventory']
    assert receipt['defaults_reviewed'] is receipt['effects_reviewed'] is receipt['execution_authorized'] is False
    assert set(receipt['runtime_dependencies'])==set(effects.DEPENDENCIES)
    assert before=={str(p.relative_to(tmp_path)):p.read_bytes() for p in tmp_path.rglob('*') if p.is_file()}
    assert not list((tmp_path/'var/lib').glob('alt-policy-effects-*'))
    assert not any('start' in c or 'stop' in c or 'update' in c or c[0]=='/usr/bin/nsupdate' for c,_ in calls)


def test_effect_worker_loads_without_package_imports(tmp_path):
    effects,request,args,_,_=scenario(tmp_path)
    scope={'__name__':'fixed_effects','__package__':None}
    exec(compile(Path(effects.__file__).read_text(),'fixed_effects','exec'),scope)
    assert scope['observe'](request,**args)['status']=='original_policy_effect_inventory'


@pytest.mark.parametrize('change',['extra','baseline_request','baseline_receipt','false_claim','source','helper','helper_mode','package','main','snippet'])
def test_effect_inventory_refuses_unbound_inputs_before_parser(tmp_path,change):
    effects,request,args,calls,data=scenario(tmp_path)
    if change=='extra':request['command']='start'
    elif change=='baseline_request':request['baseline_request']['metadata']['hostname']='alt-a1-pc99'
    elif change=='baseline_receipt':request['baseline_receipt']['original_sha256']='0'*64
    elif change=='false_claim':request['baseline_receipt']['defaults_verified']=0
    elif change=='source':request['source_sha256']='bad'
    elif change=='helper':(tmp_path/next(iter(effects.DEPENDENCIES)).lstrip('/')).unlink()
    elif change=='helper_mode':(tmp_path/next(iter(effects.DEPENDENCIES)).lstrip('/')).chmod(0o777)
    elif change=='package':
        previous=args['runner']
        def runner(command,**options):
            if command[0]=='/usr/bin/rpm' and command[2] in effects.DEPENDENCIES:return 0,'wrong package\n',''
            return previous(command,**options)
        args['runner']=runner
    elif change=='main':(tmp_path/'etc/sssd/sssd.conf').write_bytes(b'changed')
    else:(tmp_path/'etc/sssd/conf.d/other.conf').write_bytes(b'changed')
    with pytest.raises(ValueError):effects.observe(request,**args)
    assert not any(command[0]=='/usr/bin/bwrap' for command,_ in calls)


@pytest.mark.parametrize('change',['extra','missing','present_type','absent_value','boolean','number','multivalue','inventory_duplicate','inventory_unknown','inventory_mismatch','secret_field'])
def test_effect_parser_refuses_malformed_closed_projection(tmp_path,change):
    effects,request,args,_,data=scenario(tmp_path)
    if change=='extra':data['execution']=True
    elif change=='missing':data['configured'].pop('dyndns_update')
    elif change=='present_type':data['configured']['dyndns_update']['present']=0
    elif change=='absent_value':data['configured']['dyndns_update']['value']='true'
    elif change=='boolean':data['configured']['dyndns_update']=dict(present=True,value='yes')
    elif change=='number':data['configured']['dyndns_refresh_interval']=dict(present=True,value='-1')
    elif change=='multivalue':data['configured']['ad_server']['value']=['dc']
    elif change=='inventory_duplicate':data['key_inventory']['cn=sssd,cn=config']=['domains','domains']
    elif change=='inventory_unknown':data['key_inventory']['other']=['domains']
    elif change=='inventory_mismatch':data['key_inventory']['cn=SOSNADMIN.LOCAL,cn=domain,cn=config']=[]
    else:data['configured']['ldap_default_authtok']=dict(present=True,value='SYNTHETIC_SECRET')
    with pytest.raises(ValueError):effects.observe(request,**args)
    assert not list((tmp_path/'var/lib').glob('alt-policy-effects-*'))


@pytest.mark.parametrize('change',['main','helper','source_request','last_collect','database','scratch'])
def test_effect_inventory_closes_native_callbacks_with_protected_rereads(tmp_path,change):
    effects,request,args,_,_=scenario(tmp_path);previous=args['runner']
    def runner(command,**options):
        result=previous(command,**options)
        if command[0]=='/usr/bin/bwrap' and '/usr/bin/python3.12' in command:
            if change=='main':(tmp_path/'etc/sssd/sssd.conf').write_bytes(b'changed')
            elif change=='helper':(tmp_path/next(iter(effects.DEPENDENCIES)).lstrip('/')).write_bytes(b'changed')
            elif change=='source_request':request['source_sha256']='e'*64
            elif change in ('database','scratch'):
                work=Path(command[command.index('--bind')+1])
                (work/('sss/db/config.ldb' if change=='database' else 'config/sssd.conf')).write_bytes(b'changed')
        return result
    args['runner']=runner
    if change=='last_collect':
        collect=args['collect'];count=0
        def changed():
            nonlocal count
            count+=1
            result=collect()
            if count==2:(tmp_path/next(iter(effects.DEPENDENCIES)).lstrip('/')).write_bytes(b'changed')
            return result
        args['collect']=changed
    with pytest.raises(ValueError):effects.observe(request,**args)


def test_unknown_configured_keys_are_retained_as_names_without_values(tmp_path):
    effects,request,args,_,data=scenario(tmp_path)
    data['key_inventory']['cn=SOSNADMIN.LOCAL,cn=domain,cn=config']=['id_provider','ldap_default_authtok']
    result=effects.observe(request,**args)
    assert result['unreviewed_keys']==['cn=SOSNADMIN.LOCAL,cn=domain,cn=config:ldap_default_authtok']
    assert 'SYNTHETIC_SECRET' not in json.dumps(result)
    assert result['effects_reviewed'] is False
