import copy
import pytest
from alt_deploy.setup_plans import digest
from alt_deploy.setup_recovery_policy_effects import KEYS

def sample():
    from alt_deploy.setup_recovery_policy_review_runtime import EXTRA_VALUES,RUNTIME_HASHES,DAEMON_LINKS
    values={k:dict(present=k in ('id_provider','auth_provider','access_provider','ad_update_samba_machine_account_password'),value='true' if k=='ad_update_samba_machine_account_password' else 'ad' if k in ('id_provider','auth_provider','access_provider') else '') for k in KEYS}
    domain='cn=SOSNADMIN.LOCAL,cn=domain,cn=config'
    inv={domain:sorted([k for k,v in values.items() if v['present']]+list(EXTRA_VALUES['domain'])),
         'cn=sssd,cn=config':sorted(['domains']+list(EXTRA_VALUES['sssd'])),'cn=pam,cn=config':[],'cn=nss,cn=config':[]}
    unknown=sorted([domain+':'+k for k in EXTRA_VALUES['domain']]+['cn=sssd,cn=config:'+k for k in EXTRA_VALUES['sssd']])
    deps={path:dict(present=True,sha256=sha,size=100,uid=0,gid=0,mode=0o755,package='fixture') for path,sha in RUNTIME_HASHES.items()}
    from alt_deploy.setup_recovery_policy_effects import DEPENDENCIES
    for path,info in deps.items():info['package']=DEPENDENCIES.get(path,'sssd-pac 2.9.8-alt3' if path.endswith('sssd_pac') else 'samba 4.21.9-alt4.p11.1')
    config=dict(present=True,sha256='a'*64,size=100,uid=0,gid=0,mode=0o600)
    projection=dict(original_sha256=digest(config))
    pair=dict(projection=projection,receipt=dict(effect_receipt=dict(configured=values,key_inventory=inv,unreviewed_keys=unknown,runtime_dependencies={k:v for k,v in deps.items() if k not in ('/usr/libexec/sssd/sssd_pac','/usr/lib64/samba/sbin/smbd','/usr/lib64/samba/sbin/nmbd')})))
    extra=dict(configuration=config,values={section:{k:dict(present=True,value=v) for k,v in keys.items()} for section,keys in EXTRA_VALUES.items()},pac=deps['/usr/libexec/sssd/sssd_pac'],daemon_dependencies={key:deps[key] for key in ('/usr/lib64/samba/sbin/smbd','/usr/lib64/samba/sbin/nmbd')},daemon_links={path:dict(uid=0,gid=0,mode=0o777,size=len(target.encode()),target=target) for path,target in DAEMON_LINKS.items()},environment_files={'/etc/sysconfig/sssd':dict(present=False),'/etc/sysconfig/samba':dict(present=True,sha256='b'*64,size=468,uid=0,gid=0,mode=0o644)},environment_values=dict(SAMBAOPTIONS='',SMBDOPTIONS='',NMBDOPTIONS='',WINBINDOPTIONS='',KRB5CCNAME='FILE:/run/samba/krb5cc_samba'),credential_cache={'present':False},execution_authorized=False,semantics='raw_configured_values_only',schema_version=1)
    return pair,extra

def test_closed_review_resolves_pinned_defaults_and_conditional_effects():
    from alt_deploy.setup_recovery_policy_review_runtime import manifest
    pair,extra=sample();result=manifest(pair,extra)
    assert result['execution_authorized'] is False
    assert result['renewal']['schedule']=='86400:750:300'
    assert result['renewal']['samba_sync'] is True
    assert result['responders']==['nss','pam','pac']
    assert result['dns']['partial_success_possible'] is True
    assert result['renewal_attribution_verified'] is False

@pytest.mark.parametrize('change',['unknown','configured','extra_value','extra_missing','extra_schema','config_drift','binary_drift','section','key','pac_extra','daemon_package','environment_sha','cache_type','alias_target','alias_metadata'])
def test_review_refuses_unreviewed_effects(change):
    from alt_deploy.setup_recovery_policy_review_runtime import manifest
    pair,extra=sample()
    if change=='unknown':pair['receipt']['effect_receipt']['unreviewed_keys'].append('unreviewed')
    elif change=='configured':pair['receipt']['effect_receipt']['configured']['dyndns_auth']=dict(present=True,value='none')
    elif change=='extra_value':extra['values']['sssd']['services']['value']='nss,pam,sudo'
    elif change=='extra_missing':extra['values']['domain']['chpass_provider']['present']=False
    elif change=='extra_schema':extra['schema_version']=True
    elif change=='config_drift':extra['configuration']['sha256']='b'*64
    elif change=='binary_drift':next(iter(pair['receipt']['effect_receipt']['runtime_dependencies'].values()))['sha256']='b'*64
    elif change=='section':pair['receipt']['effect_receipt']['key_inventory']['cn=sudo,cn=config']=[]
    elif change=='key':pair['receipt']['effect_receipt']['key_inventory']['cn=pam,cn=config']=['unknown']
    elif change=='pac_extra':extra['pac']['command']='start'
    elif change=='daemon_package':extra['daemon_dependencies']['/usr/lib64/samba/sbin/smbd']['package']='wrong'
    elif change=='environment_sha':extra['environment_files']['/etc/sysconfig/samba']['sha256']='invalid'
    elif change=='cache_type':extra['credential_cache']['present']=0
    elif change=='alias_target':extra['daemon_links']['/usr/sbin/smbd']['target']='/usr/bin/other'
    elif change=='alias_metadata':extra['daemon_links']['/usr/sbin/smbd']['uid']=True
    with pytest.raises(ValueError):manifest(pair,extra)
