"""Version-pinned closed normal-policy review for the supported recovery profile."""
from __future__ import annotations
import copy,ipaddress,json,re,shlex
from pathlib import Path
from .ad_directory import fail
from .setup_plans import canonical,digest,decode_state_bytes
from .setup_recovery_runtime import _read_source
from .setup_recovery_process import bounded_bundle_run
from .setup_recovery_source_stdin import build_source_stdin
from .setup_recovery_policy_effects_runtime import RecoveryPolicyEffectsRuntime
from .setup_recovery_policy_review import KEYS,PAC,DAEMON_LINKS

EXTRA_VALUES={'domain':dict(ad_gpo_access_control='permissive',ad_gpo_ignore_unreadable='true',chpass_provider='ad',debug_level='0',default_shell='/bin/bash',fallback_homedir='/home/%d/%u',krb5_renew_interval='1h'),
              'sssd':dict(config_file_version='2',services='nss, pam',user='_sssd')}
RUNTIME_HASHES={
 '/usr/libexec/sssd/sssd_be':'14b9ef1fd41859184c81403c27bd16ed2fbd398ab950df8ebc70eeb782482fb2',
 '/usr/lib64/sssd/libsss_ad.so':'62740e0aa6743dfbc8f4927d9c2c35c4b0b80f9c5963bb98d2364a817874aed6',
 '/usr/sbin/adcli':'b2df359ba57e94658138e536bd3675955a8339efbdf92a653bfe743f62bf4c5f',
 '/usr/bin/nsupdate':'839bdd40a97675b0f881f7a4d1b02972cf4f4dcae5bc99cd671db8ea68e3cde0',
 '/usr/lib64/samba/sbin/smbd':'f80a8fdbb471e3daefa9236bf48c723b1f6ed193e52cec285633351f3ee52d63',
 '/usr/lib64/samba/sbin/nmbd':'0e6017c4dd4f9e17440de3ae794290f9d81f6c37265101c5ba657ebeac837e4d',
 PAC:'1f86842ea2392c462af5932813581094c202339c49d883966cf16d19829d0129'}
SOURCE_REVIEW={
 'sssd':dict(package='2.9.8-alt3',packaging='735f9bd77dc114daa4508e20af2f4178cd18387e',effective='31669d9c2d25aa3382bba68c1889ee3252de9cd7'),
 'adcli':dict(package='0.9.2-alt1',packaging='334494f9cab4a72825e6643ba5b65729b45bc2a8',effective='27afd5222c73df51044c16145c3bcb426b05cf2e'),
 'bind':dict(package='9.18.49-alt1',packaging='05573d8b67fd4311caea548be188ccb0ce85a370',gssapi_build=True,dot_supported=False)}
SOURCE_REVIEW['samba']=dict(package='4.21.9-alt4.p11.1',packaging='5dd1c18386d33a4b51ea060c83f111a2c9433984',upstream_tag='samba-4.21.9',environment_source='samba4.spec_and_packaging/systemd/samba.sysconfig')
SOURCE_REVIEW['samba'].update(effective='532170350db04e6b9b96943c6ecac92a8c4ae0d2',upstream='565ba9fe4d73adae185114153ffeb6cc51c5a8d1')

def manifest(result,extra):
    if (not isinstance(extra,dict) or set(extra)!={'schema_version','semantics','configuration','values','pac','daemon_dependencies','daemon_links','environment_files','environment_values','credential_cache','execution_authorized'}
            or type(extra['schema_version']) is not int or extra['schema_version']!=1
            or extra['semantics']!='raw_configured_values_only' or extra['execution_authorized'] is not False
            or result['projection']['original_sha256']!=digest(extra['configuration'])
            or canonical(extra['values'])!=canonical({section:{key:dict(present=True,value=value) for key,value in values.items()} for section,values in EXTRA_VALUES.items()})):
        raise ValueError('Unreviewed original configured values')
    if (not isinstance(extra['environment_files'],dict) or set(extra['environment_files'])!={'/etc/sysconfig/sssd','/etc/sysconfig/samba'}
            or canonical(extra['environment_files']['/etc/sysconfig/sssd'])!=canonical({'present':False})
            or canonical(extra['credential_cache'])!=canonical({'present':False})
            or canonical(extra['environment_values'])!=canonical(dict(SAMBAOPTIONS='',SMBDOPTIONS='',NMBDOPTIONS='',WINBINDOPTIONS='',KRB5CCNAME='FILE:/run/samba/krb5cc_samba'))):raise ValueError('Unreviewed service environment')
    environment=extra['environment_files']['/etc/sysconfig/samba']
    if (set(environment)!={'present','sha256','size','uid','gid','mode'} or environment['present'] is not True
            or not isinstance(environment['sha256'],str) or not re.fullmatch('[0-9a-f]{64}',environment['sha256'])
            or any(type(environment[key]) is not int for key in ('uid','gid','mode','size'))
            or environment['uid']!=0 or environment['gid']!=0 or environment['mode']!=0o644 or not 1<=environment['size']<=65536):raise ValueError('Unsafe reviewed service environment')
    links=extra['daemon_links']
    if not isinstance(links,dict) or set(links)!=set(DAEMON_LINKS):raise ValueError('Missing reviewed daemon aliases')
    for path,target in DAEMON_LINKS.items():
        record=links[path]
        if (not isinstance(record,dict) or set(record)!={'uid','gid','mode','size','target'}
            or any(type(record[key]) is not int for key in ('uid','gid','mode','size'))
            or record['uid']!=0 or record['gid']!=0 or record['mode']!=0o777
            or record['size']!=len(target.encode()) or record['target']!=target):raise ValueError('Unreviewed daemon alias')
    receipt=result['receipt']['effect_receipt'];configured=receipt['configured']
    expected={key:dict(present=key in ('id_provider','auth_provider','access_provider','ad_update_samba_machine_account_password'),
        value='ad' if key in ('id_provider','auth_provider','access_provider') else 'true' if key=='ad_update_samba_machine_account_password' else '') for key in configured}
    from .setup_recovery_policy_effects import KEYS as OPERATIVE
    if set(configured)!=set(OPERATIVE) or canonical(configured)!=canonical(expected):raise ValueError('Unreviewed operative option')
    domain='cn=SOSNADMIN.LOCAL,cn=domain,cn=config'
    inventory={domain:sorted([key for key,record in configured.items() if record['present']]+list(EXTRA_VALUES['domain'])),
               'cn=sssd,cn=config':sorted(['domains']+list(EXTRA_VALUES['sssd'])),'cn=nss,cn=config':[],'cn=pam,cn=config':[]}
    unknown=sorted([domain+':'+key for key in EXTRA_VALUES['domain']]+['cn=sssd,cn=config:'+key for key in EXTRA_VALUES['sssd']])
    if receipt['key_inventory']!=inventory or receipt['unreviewed_keys']!=unknown:raise ValueError('Unreviewed configured key')
    deps=dict(copy.deepcopy(receipt['runtime_dependencies']));deps[PAC]=copy.deepcopy(extra['pac'])
    if not isinstance(extra['daemon_dependencies'],dict) or set(extra['daemon_dependencies'])!={'/usr/lib64/samba/sbin/smbd','/usr/lib64/samba/sbin/nmbd'}:raise ValueError('Missing restoration daemon')
    deps.update(copy.deepcopy(extra['daemon_dependencies']))
    if set(deps)!=set(RUNTIME_HASHES):raise ValueError('Missing reviewed helper')
    from .setup_recovery_policy_effects import DEPENDENCIES
    packages=dict(DEPENDENCIES,**{PAC:'sssd-pac 2.9.8-alt3','/usr/lib64/samba/sbin/smbd':'samba 4.21.9-alt4.p11.1','/usr/lib64/samba/sbin/nmbd':'samba 4.21.9-alt4.p11.1'})
    for path,value in deps.items():
        if (set(value)!={'present','sha256','size','uid','gid','mode','package'} or value['present'] is not True
                or value['package']!=packages[path]
                or value['sha256']!=RUNTIME_HASHES[path] or type(value['uid']) is not int or value['uid']!=0
                or type(value['gid']) is not int or value['gid']!=0 or type(value['size']) is not int
                or not 1<=value['size']<=67108864 or type(value['mode']) is not int
                or value['mode'] not in ((0o644,0o755) if path.endswith('.so') else (0o755,))):raise ValueError('Unreviewed protected binary')
    return dict(schema_version=1,status='reviewed_original_policy_effects',baseline_projection_sha256=digest(result['projection']),
        configured_inventory_sha256=digest(receipt),supplemental_sha256=digest(extra),package_sources=copy.deepcopy(SOURCE_REVIEW),source_files=copy.deepcopy(SOURCE_FILES),
        runtime_dependencies=deps,daemon_links=copy.deepcopy(links),environment_files=copy.deepcopy(extra['environment_files']),environment_values=copy.deepcopy(extra['environment_values']),
        credential_cache=copy.deepcopy(extra['credential_cache']),service_cache_effects='absent_before_start_or_approved_private_mutable_cache_after_start_not_authentication_evidence',
        configured_presence=copy.deepcopy(configured),extra_configured_values=copy.deepcopy(extra['values']),
        renewal=dict(age_days=30,schedule='86400:750:300',samba_sync=True,ldaps=False,
            conditional_effects=['machine_password_and_keytab','local_samba_sid_and_secrets','dns_hostname','encryption_types','spns']),
        dns=dict(enabled=True,initial_delay=10,interval=86400,random_offset=300,ttl=3600,ptr=True,per_family=True,
            auth='gss-tsig',ptr_auth='gss-tsig',force_tcp=False,server_selection='soa_discovery_and_native_fallback',
            rrset_replacement_possible=True,partial_success_possible=True,dot_supported=False,peer_pinning_verified=False),
        identity_resolution=dict(domain='configured_domain_name',hostname='gethostname_with_native_fqdn_expansion',server='native_discovery'),
        responders=['nss','pam','pac'],renewal_attribution_verified=False,execution_authorized=False,
        limitations=['source_review_and_binary_pins_are_not_reproducible_build_attestation','manager_observations_are_not_an_exclusive_lease',
                     'ordinary_adcli_target_is_not_guid_pinned','ordinary_cache_and_log_writes','nss_is_not_gui_or_password_authentication',
                     'any_observed_renewal_is_UNKNOWN_in_this_recovery'])

class RecoveryPolicyReviewRuntime:
    def __init__(self,settings,*,effects=None,runner=None):
        self.settings=settings;self.effects=effects or RecoveryPolicyEffectsRuntime(settings);self.runner=runner or bounded_bundle_run

    def _sources(self):
        directory=Path(__file__).parent;owner=Path(__file__).lstat().st_uid
        return [_read_source(directory/('setup_recovery_'+name+'.py'),owner=owner) for name in ('probe','process','policy_review')]

    def capture(self,machine,snapshot,metadata):
        try:
            selected=copy.deepcopy(snapshot);sources=self._sources();result=self.effects.capture(machine,selected,metadata)
            request=dict(schema_version=1,configuration=selected['workstation_facts']['snapshot']['files']['/etc/sssd/sssd.conf'],domain=metadata['realm'].upper())
            program='import json,sys,types\nwire=json.load(sys.stdin)\nmodules=[]\n'
            for name,source in zip(('probe','process','review'),sources):
                program+='ns={"__name__":'+repr('fixed_'+name)+',"__package__":""}\nexec(compile('+repr(source)+',"<fixed-'+name+'>","exec"),ns)\nmodules.append(types.SimpleNamespace(**ns))\n'
            program+='print(json.dumps(modules[2].observe(wire["request"],probe=modules[0],runner=modules[1].bounded_recovery_run),sort_keys=True))\n'
            script,payload=build_source_stdin(program,dict(request=request))
            remote='sudo -n /usr/bin/python3 -I -B -c '+shlex.quote(script)
            if len(remote.encode())>=8192:raise ValueError
            address=str(ipaddress.ip_address(machine.ip))
            command=['/usr/bin/ssh','-F','/dev/null','-o','BatchMode=yes','-o','StrictHostKeyChecking=yes','-o','ProxyCommand=none',
                '-o','ProxyJump=none','-o','PermitLocalCommand=no','-o','IdentitiesOnly=yes','-o','ConnectTimeout=10',
                '-o','UserKnownHostsFile='+str(self.settings.known_hosts_file),'-i',str(self.settings.private_key_file),'ansible@'+address,remote]
            rc,out,_=self.runner(command,environment={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'},input_text=payload,timeout=45)
            if type(rc) is not int or rc or not isinstance(out,str) or len(out.encode())>16384:raise ValueError
            extra=decode_state_bytes(out.encode());reviewed=manifest(result,extra)
            if self._sources()!=sources or canonical(snapshot)!=canonical(selected):raise ValueError
            return dict(baseline=result['projection'],effects=reviewed,effects_sha256=digest(reviewed),runtime_dependencies=reviewed['runtime_dependencies'],daemon_links=reviewed['daemon_links'],environment_files=reviewed['environment_files'],credential_cache=reviewed['credential_cache'],source_sha256=digest(sources))
        except Exception:raise fail('recovery_policy_review_failed','Supported exact original policy, defaults and helper review did not verify') from None

SOURCE_FILES={
  "src/providers/ad/ad_opts.c": "75ae85e8c542f8c2b63252ed26ae8b834c736a1ffc29adc12c258be756079505",
  "src/providers/ad/ad_common.c": "966de56c24e3c1fe9d998f36ee503813efdfa35f50bda59af84a0b7fefec4e90",
  "src/providers/ad/ad_machine_pw_renewal.c": "1d4668b94e0bb6f7fb289a847fced1786c265697dc951168306dc246fffc85cf",
  "src/providers/ad/ad_dyndns.c": "d4fb26700b518a15cf60af476ca29a84626275df077601faa048495de73253cc",
  "src/providers/ldap/sdap_dyndns.c": "5da3b32969d0ba5c0e38726c5a0ff24c687b491402e71322231ef2b157f167a5",
  "src/providers/be_dyndns.c": "c91c3e6c10a34342470b6f1a894a6215d8ee8b8edd14880b737362c85b01ad8e",
  "src/providers/be_ptask.c": "7f33631dea7fea351cb869184de5a74005fa86ec396293d97a1c6210db05e277",
  "src/monitor/monitor.c": "36855d1ed28fd4011e6997677e1cbfceff3f24f57588b855ce424fa827b30860",
  "src/confdb/confdb.c": "f51fb02a1651bea7aad631daa9ed9d4effe975373daa4ab632701962126d302c",
  "src/providers/krb5/krb5_renew_tgt.c": "7dccaf656bc2e0641e80dbf0d5d2f2d81a95d9813aeede746ccefeb45dd5f1db",
  "library/adenroll.c": "cf1a4b955a1a75597e74b17b443f42b7ef9091cb85c10ac771e4ace97b5863e0",
  "tools/computer.c": "913e6120df7866ce9fe4552e2365dda15fe0a0540ef7cbfb59b2b092322c380a",
  "bind/bin/nsupdate/nsupdate.c": "4b9d27b45f8b0937aa3c9d30e6671614631d1655f0b63256cb8afd9965cf353f",
  "bind/lib/dns/gssapi_link.c": "72ba27e434860ca96226ff5e2b2170fde38c1816963ac9642a2ad11b75b06a77",
  "bind.spec": "804b254683d2bcae3cec54251a3fae5b5076331160f7dd3800da0b2b9bc6789d",
  "src/responder/pac/pacsrv.c": "4be5ee4d8866f73023eda65e3d8fb63494efda98aafa22302ff4cb8a9ebc544c",
  "sssd.spec": "94064c95c6a3be99f58c74ba1ed4fd8108b74b5fdd7b079ca02357ab6b8acbac"
}

SOURCE_FILES.update({"samba4.spec":"b02890b41470569b2f5b5888c8aa7fad0a210454aee5db6ce5c7c82774920213","samba/packaging/systemd/samba.sysconfig":"f2d11032015ef917f4af50f3933d432fa744b5f846ab4d980247e329e52d34bc","samba/auth/credentials/credentials_krb5.c":"37bd5b2cc20be767780e668c2415b8e16e9540e0a861567497df747c4aa5c5dc","samba/lib/krb5_wrap/krb5_samba.c":"b8ae488cc16377c780236b75a443f9db33570586bcb5515abadd69108dd4023f"})
