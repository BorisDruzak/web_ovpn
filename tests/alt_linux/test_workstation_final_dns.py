"""DNS-only persistence, compare-and-swap and rollback on synthetic networks."""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys

import pytest

from test_component_catalog import SOURCE


UUID='11111111-2222-3333-4444-555555555555'
CONNECTION='aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'


def helper():
    name='synthetic_final_dns'
    if name not in sys.modules:
        path=SOURCE/'roles/workstation_final_dns/files/finalize_dns.py'
        spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec)
        sys.modules[name]=module;spec.loader.exec_module(module)
    return sys.modules[name]


@pytest.fixture(params=['nm_etcnet','nm_keyfile','etcnet'])
def network(tmp_path,request):
    root=tmp_path/'target';root.mkdir(mode=0o700)
    def put(path,text,mode=0o644):
        p=root/path;p.parent.mkdir(parents=True,exist_ok=True);p.write_text(text);p.chmod(mode);return p
    put('sys/class/dmi/id/product_uuid',UUID+'\n')
    put('proc/sys/kernel/random/boot_id',CONNECTION+'\n')
    active=put('etc/resolv.conf','# Generated resolver\nsearch example.test\nnameserver 192.0.2.11\noptions timeout:2\n')
    options=put('etc/net/ifaces/eth0/options','TYPE=eth\nBOOTPROTO=dhcp\nNM_CONTROLLED='+('no' if request.param=='etcnet' else 'yes')+'\n')
    persistent=put('etc/net/ifaces/eth0/resolv.conf',active.read_text())
    profile=None
    if request.param=='nm_keyfile':
        profile=put('etc/NetworkManager/system-connections/test.nmconnection',
            '[connection]\nid=Employee connection\nuuid='+CONNECTION+'\ninterface-name=eth0\n'
            '[ipv4]\nmethod=auto\ndns=192.0.2.11;\ndns-search=example.test;\nignore-auto-dns=true\n'
            '[ipv6]\nmethod=auto\nignore-auto-dns=true\n[proxy]\nmethod=0\n',0o600)
        persistent=profile
    source=put('run/resolvconf/interfaces/eth0',active.read_text()) if request.param=='etcnet' else None
    calls=[];state={'connection':CONNECTION,'after_failure':False,'rollback_failure':False,'race':False}
    def call(args,*,input_text=None,timeout=15,**unused):
        calls.append((args,input_text))
        if args[:2]==['hostname','-s']:return 0,'alt-test-pc1\n'
        if args[:4]==['ip','-j','-4','route']:
            return 0,json.dumps([{'dst':'default','dev':'eth0','gateway':'192.0.2.1','protocol':'dhcp'}])
        if args[:4]==['ip','-j','-6','route']:return 0,'[]'
        if args[:4] in (['ip','-j','-4','address'],['ip','-j','-6','address']):
            return 0,json.dumps([{'ifname':'eth0','addr_info':[{'family':'inet','local':'192.0.2.10','prefixlen':24,'valid_life_time':8000}]}])
        if args[:2]==['nmcli','-t']:
            if request.param=='etcnet':return 10,''
            if args[-1]=='--active':return 0,state['connection']+':eth0\n'
            return 0,state['connection']+':'+('/etc/NetworkManager/system-connections/test.nmconnection' if profile else '--')+'\n'
        if args[:3]==['nmcli','connection','reload'] or args[:3]==['nmcli','connection','load']:return 0,''
        if args[0]=='/usr/bin/busctl':
            if 'get-property' in args:return 0,json.dumps({'type':'s','data':'1.54.4'})
            if 'GetDeviceByIpIface' in args:return 0,json.dumps({'type':'o','data':['/org/freedesktop/NetworkManager/Devices/2']})
            if 'GetAppliedConnection' in args:
                return 0,json.dumps({'type':'a{sa{sv}}t','data':[{'connection':{'uuid':{'type':'s','data':state['connection']}},
                    'ipv4':{'method':{'type':'s','data':'auto'}},'ipv6':{'method':{'type':'s','data':'ignore'}}},7]})
        if args[:3]==['nmcli','device','reapply'] or args[:2]==['resolvconf','-a'] or args[0]=='/usr/bin/busctl' and 'Reapply' in args:
            if state['race']:
                persistent.write_text(persistent.read_text()+'# concurrent employee edit\n')
            if profile:
                import configparser
                cfg=configparser.ConfigParser();cfg.read(profile)
                addresses=[x for s in ('ipv4','ipv6') for x in cfg.get(s,'dns',fallback='').split(';') if x]
                active.write_text('search example.test\n'+''.join('nameserver '+a+'\n' for a in addresses))
            else:active.write_text(persistent.read_text())
            if source:source.write_text(input_text)
            return (1,'PRIVATE-SECRET-SENTINEL') if state['rollback_failure'] else (0,'')
        raise AssertionError('Unexpected DNS command '+repr(args))
    query={'schema_version':1,'machine_uuid':UUID,'hostname':'alt-test-pc1','servers':['192.0.2.53']}
    context={'schema_version':1,'kind':'complete_workstation','phase':'final_dns',
        'job_id':'job-20261020T010000Z-12345678','claim_sha256':'a'*64,'plan_sha256':'b'*64,
        'workflow_policy_sha256':'c'*64,'machine_uuid':UUID,'source_sha256':'d'*64,
        'policy_sha256':hashlib.sha256(json.dumps({'servers':query['servers']},sort_keys=True,separators=(',',':')).encode()).hexdigest()}
    return dict(root=root,put=put,active=active,persistent=persistent,options=options,profile=profile,
                source=source,calls=calls,state=state,call=call,request=query,context=context,backend=request.param)


def files(root):
    return {str(p.relative_to(root)):(p.read_bytes(),p.stat().st_mode,p.stat().st_uid,p.stat().st_gid)
            for p in root.rglob('*') if p.is_file()}


def test_original_failure_survives_failed_rollback_without_private_output(network):
    m=helper();f=network;initial=m.observe(f['request'],root=f['root'],call=f['call'])
    def verify(value,*,phase,**options):
        if phase=='after':
            f['state']['rollback_failure']=True
            raise m.DnsError('final_dns_lookup_failed')
    result=m.apply(f['request'],initial.public['snapshot_sha256'],f['context'],root=f['root'],call=f['call'],verify=verify)
    assert result=={'status':'outcome_unverified','changed':None,'code':'final_dns_rollback_unverified'}
    path=f['root']/'var/lib/alt-workstation-final-dns'/f['context']['claim_sha256']/'failure.json'
    failure=json.loads(path.read_text())
    assert failure=={'schema_version':1,'stage':'verify_after','code':'final_dns_lookup_failed','rollback_code':'final_dns_apply_failed'}
    assert path.stat().st_mode & 0o777==0o600
    assert 'SENTINEL' not in path.read_text()


def test_supported_backend_observation_and_dns_edit_preserve_every_other_byte(network):
    m=helper();f=network;before=files(f['root'])
    value=m.observe(f['request'],root=f['root'],call=f['call'])
    assert value.public['backend']==f['backend'] and value.public['interface']=='eth0'
    assert value.public['servers']==['192.0.2.11']
    assert files(f['root'])==before
    changed=m.rewrite(value,f['request']['servers'])
    old=f['persistent'].read_bytes()
    if f['profile']:
        assert changed==old.replace(b'dns=192.0.2.11;',b'dns=192.0.2.53;')
    else:assert changed==old.replace(b'nameserver 192.0.2.11',b'nameserver 192.0.2.53')
    assert files(f['root'])==before


@pytest.mark.parametrize('fault',['symlink','mode','owner','options','connection','duplicate','multi_route'])
def test_unproven_or_changed_backend_never_writes(network,monkeypatch,fault):
    m=helper();f=network
    if fault=='symlink':
        saved=f['persistent'].with_suffix('.saved');f['persistent'].rename(saved);f['persistent'].symlink_to(saved)
    elif fault=='mode':f['persistent'].chmod(0o666)
    elif fault=='owner':monkeypatch.setattr(m.os,'getuid',lambda:2147483640)
    elif fault=='options':f['options'].write_text('NM_CONTROLLED=maybe\n')
    elif fault=='connection':f['state']['connection']='not-a-uuid'
    elif fault=='duplicate':f['persistent'].write_text(f['persistent'].read_text()+'nameserver invalid\n')
    elif fault=='multi_route':
        old=f['call']
        f['call']=lambda args,**kw:(0,'[{"dev":"eth0"},{"dev":"eth1"}]') if args==['ip','-j','-4','route','show','default'] else old(args,**kw)
    before=files(f['root'])
    # Options only govern Etcnet, and standalone has no connection UUID.
    if fault=='options' and f['profile'] or fault=='connection' and f['backend']=='etcnet':return
    with pytest.raises(m.DnsError):m.observe(f['request'],root=f['root'],call=f['call'])
    assert files(f['root'])==before


@pytest.mark.parametrize('case',['success','post_dns','post_kerberos','race','rollback_failure','lost_reply','stale','wrong_phase','wrong_policy'])
def test_one_shot_dns_transition_and_verified_rollback(network,case):
    m=helper();f=network;initial=m.observe(f['request'],root=f['root'],call=f['call'])
    before=f['persistent'].read_bytes();trace=[]
    def verify(value,*,phase,**options):
        trace.append(phase)
        assert (f['root']/'var/lib/alt-workstation-final-dns'/('a'*64)/'manifest.json').is_file()
        if phase=='after' and case in ('post_dns','post_kerberos','race','rollback_failure'):
            raise m.DnsError('final_dns_kerberos_failed' if case=='post_kerberos' else 'final_dns_lookup_failed')
        if phase=='after' and case=='lost_reply':raise TimeoutError('PRIVATE-SECRET-SENTINEL')
    if case=='stale':f['persistent'].write_bytes(before+b'# new policy\n')
    if case=='wrong_phase':f['context']['phase']='user'
    if case=='wrong_policy':f['context']['policy_sha256']='0'*64
    if case=='race':f['state']['race']=True
    if case=='rollback_failure':f['state']['rollback_failure']=True
    result=m.apply(f['request'],initial.public['snapshot_sha256'],f['context'],root=f['root'],call=f['call'],verify=verify)
    assert 'SENTINEL' not in json.dumps(result)
    if case=='success':
        assert result['status']=='applied_verified' and result['changed'] is True
        assert m.observe(f['request'],root=f['root'],call=f['call']).public['servers']==['192.0.2.53']
    elif case in ('post_dns','post_kerberos','lost_reply'):
        assert result['status']=='rolled_back_verified'
        assert f['persistent'].read_bytes()==before and trace[-1]=='rollback'
    else:assert result['status']=='outcome_unverified'
    if case=='race':assert '# concurrent employee edit' in f['persistent'].read_text()
    assert not any('down' in a or 'reboot' in a or 'modify' in a for a,_ in f['calls'])
    if case not in ('stale','wrong_phase','wrong_policy'):
        snapshot=files(f['root']);calls=list(f['calls'])
        second=m.apply(f['request'],initial.public['snapshot_sha256'],f['context'],root=f['root'],call=f['call'],verify=verify)
        assert second['status']=='outcome_unverified' and second['code']=='final_dns_claim_consumed'
        assert files(f['root'])==snapshot and f['calls']==calls


def test_invalid_dns_or_machine_context_is_readonly(network):
    m=helper();f=network;before=files(f['root'])
    query=dict(f['request'],machine_uuid='99999999-2222-3333-4444-555555555555')
    with pytest.raises(m.DnsError):m.observe(query,root=f['root'],call=f['call'])
    query=dict(f['request'],command='PRIVATE-SECRET-SENTINEL')
    with pytest.raises(m.DnsError):m.observe(query,root=f['root'],call=f['call'])
    assert files(f['root'])==before


def test_activation_failure_before_runtime_update_restores_owned_persistent_file(network):
    m=helper();f=network;initial=m.observe(f['request'],root=f['root'],call=f['call'])
    original={p:p.read_bytes() for p in (f['persistent'],f['source']) if p is not None}
    activations=[];checks=[]
    def call(args,**kwargs):
        if args[:3]==['nmcli','device','reapply'] or args[:2]==['resolvconf','-a'] or args[0]=='/usr/bin/busctl' and 'Reapply' in args:
            activations.append(args)
            if len(activations)==1:return 1,'PRIVATE-SECRET-SENTINEL'
        return f['call'](args,**kwargs)
    result=m.apply(f['request'],initial.public['snapshot_sha256'],f['context'],root=f['root'],call=call,
        verify=lambda value,phase,**unused:checks.append(phase))
    assert result=={'status':'rolled_back_verified','changed':False,'code':'final_dns_apply_failed'}
    assert len(activations)==2 and checks==['before','rollback']
    assert all(path.read_bytes()==content for path,content in original.items())
    assert m.resolvers(f['active'].read_bytes())==initial.public['servers']
    before=files(f['root'])
    repeated=m.apply(f['request'],initial.public['snapshot_sha256'],f['context'],root=f['root'],call=call)
    assert repeated['code']=='final_dns_claim_consumed' and files(f['root'])==before and len(activations)==2


@pytest.mark.parametrize('network',['etcnet'],indirect=True)
@pytest.mark.parametrize('foreign',['source','persistent_inode','network'])
def test_failed_activation_never_restores_over_foreign_state(network,foreign):
    m=helper();f=network;initial=m.observe(f['request'],root=f['root'],call=f['call']);failed=[]
    def call(args,**kwargs):
        if args[:2]==['resolvconf','-a']:
            failed.append(args)
            if foreign=='source':f['source'].write_text('nameserver 192.0.2.99\n')
            if foreign=='persistent_inode':
                replacement=f['persistent'].with_suffix('.foreign');replacement.write_bytes(f['persistent'].read_bytes())
                replacement.chmod(f['persistent'].stat().st_mode&0o777);replacement.replace(f['persistent'])
            return 1,''
        if failed and foreign=='network' and args==['ip','-j','-4','route','show','dev','eth0']:
            return 0,'[{"dst":"default","dev":"eth0","gateway":"192.0.2.99"}]'
        return f['call'](args,**kwargs)
    result=m.apply(f['request'],initial.public['snapshot_sha256'],f['context'],root=f['root'],call=call,verify=lambda *a,**kw:None)
    assert result['status']=='outcome_unverified' and result['code']=='final_dns_rollback_unverified'
    assert len(failed)==1 and b'192.0.2.53' in f['persistent'].read_bytes()
    if foreign=='source':assert b'192.0.2.99' in f['source'].read_bytes()


@pytest.mark.parametrize('network',['etcnet'],indirect=True)
def test_readonly_observer_still_rejects_source_persistent_skew(network):
    m=helper();f=network;initial=m.observe(f['request'],root=f['root'],call=f['call'])
    f['persistent'].write_bytes(m.rewrite(initial,f['request']['servers']))
    before=files(f['root'])
    with pytest.raises(m.DnsError):m.observe(f['request'],root=f['root'],call=f['call'])
    assert files(f['root'])==before


@pytest.mark.parametrize('active_correct',[False,True])
def test_already_persistent_policy_still_reapplies_stale_active_dns_and_then_is_noop(network,active_correct):
    m=helper();f=network
    first=m.observe(f['request'],root=f['root'],call=f['call'])
    f['persistent'].write_bytes(m.rewrite(first,f['request']['servers']))
    if active_correct:f['active'].write_text('search example.test\nnameserver 192.0.2.53\n')
    if f['source']:f['source'].write_bytes(f['persistent'].read_bytes())
    value=m.observe(f['request'],root=f['root'],call=f['call'])
    result=m.apply(f['request'],value.public['snapshot_sha256'],f['context'],root=f['root'],call=f['call'],verify=lambda *a,**k:None)
    assert result['status']=='applied_verified'
    assert result['changed'] is (not active_correct)
    assert m.observe(f['request'],root=f['root'],call=f['call']).public['servers']==['192.0.2.53']


def test_dns_replacement_preserves_owned_extended_attributes(network):
    m=helper();f=network
    try:os.setxattr(f['persistent'],'user.synthetic.dns',b'preserve-attributes')
    except OSError:pytest.skip('This fixture filesystem has no user xattrs')
    value=m.observe(f['request'],root=f['root'],call=f['call'])
    result=m.apply(f['request'],value.public['snapshot_sha256'],f['context'],root=f['root'],call=f['call'],verify=lambda *a,**k:None)
    assert result['status']=='applied_verified'
    assert os.getxattr(f['persistent'],'user.synthetic.dns')==b'preserve-attributes'


def test_generated_active_resolver_may_have_owned_readonly_hardlinks(network):
    m=helper();f=network
    linked=f['root']/'etc/generated-resolver-link';os.link(f['active'],linked)
    before=files(f['root'])
    value=m.observe(f['request'],root=f['root'],call=f['call'])
    assert value.public['servers']==['192.0.2.11'] and files(f['root'])==before
    # The exception never applies to the persistent file that will be edited.
    os.link(f['persistent'],f['persistent'].with_suffix('.linked'))
    with pytest.raises(m.DnsError):m.observe(f['request'],root=f['root'],call=f['call'])


@pytest.mark.parametrize('fault',['bytes','mode','attributes'])
def test_atomic_exchange_preserves_a_concurrent_edit_and_never_claims_success(network,monkeypatch,fault):
    m=helper();f=network;value=m.observe(f['request'],root=f['root'],call=f['call'])
    new=m.rewrite(value,f['request']['servers']);libc=m.ctypes.CDLL(None,use_errno=True)
    def exchange(*args):
        if fault=='bytes':f['persistent'].write_bytes(value.content+b'# concurrent edit at exchange\n')
        elif fault=='mode':f['persistent'].chmod(0o640)
        else:os.setxattr(f['persistent'],'user.synthetic.race',b'concurrent-attribute')
        return libc.renameat2(*args)
    monkeypatch.setattr(m.ctypes,'CDLL',lambda *a,**k:type('Libc',(),{'renameat2':staticmethod(exchange)})())
    with pytest.raises(m.DnsError) as caught:m.exchange(value.path,value.content,new,value.info,f['root'],value.attributes)
    assert str(caught.value)=='final_dns_configuration_changed'
    displaced=list(value.path.parent.glob('.alt-dns-*'));assert len(displaced)==1
    if fault=='bytes':assert displaced[0].read_bytes().endswith(b'# concurrent edit at exchange\n')
    elif fault=='mode':assert displaced[0].stat().st_mode&0o777==0o640
    else:assert os.getxattr(displaced[0],'user.synthetic.race')==b'concurrent-attribute'

@pytest.mark.parametrize('network',['nm_etcnet'],indirect=True)
@pytest.mark.parametrize('case',['success','rollback','activation_failure','appeared','foreign_replacement'])
def test_dhcp_etcnet_without_persistent_resolver_is_guarded(network,case):
    m=helper();f=network;f['persistent'].unlink()
    before=files(f['root']);initial=m.observe(f['request'],root=f['root'],call=f['call'])
    assert initial.public['backend']=='nm_etcnet' and initial.public['persistent_servers']==[]
    assert not f['persistent'].exists() and files(f['root'])==before
    activations=[]
    def call(args,**kwargs):
        if args[:3]==['nmcli','device','reapply'] or args[0]=='/usr/bin/busctl' and 'Reapply' in args:
            activations.append(args)
            if case=='activation_failure' and len(activations)==1:return 1,''
            if not f['persistent'].exists():
                f['active'].write_text('search example.test\nnameserver 192.0.2.11\n');return 0,''
        return f['call'](args,**kwargs)
    def verify(value,*,phase,**kwargs):
        if phase=='after' and case in ('rollback','foreign_replacement'):
            if case=='foreign_replacement':
                foreign=f['persistent'].with_suffix('.foreign');foreign.write_text('nameserver 192.0.2.99\n')
                foreign.replace(f['persistent'])
            raise m.DnsError('final_dns_lookup_failed')
    if case=='appeared':f['persistent'].write_text('nameserver 192.0.2.99\n')
    result=m.apply(f['request'],initial.public['snapshot_sha256'],f['context'],root=f['root'],call=call,verify=verify)
    if case=='success':
        assert result=={'status':'applied_verified','changed':True,'code':'final_dns_applied'}
        assert f['persistent'].read_text()=='nameserver 192.0.2.53\n'
        assert f['persistent'].stat().st_mode&0o777==0o644
        assert m.observe(f['request'],root=f['root'],call=call).public['persistent_servers']==['192.0.2.53']
    elif case in ('rollback','activation_failure'):
        assert result['status']=='rolled_back_verified' and not f['persistent'].exists()
        assert m.observe(f['request'],root=f['root'],call=call).public==initial.public
    else:
        assert result['status']=='outcome_unverified' and '192.0.2.99' in f['persistent'].read_text()
    assert f['options'].read_bytes()==before['etc/net/ifaces/eth0/options'][0]
    assert not any('down' in a or 'modify' in a for a,_ in f['calls'])


@pytest.mark.parametrize('network',['nm_etcnet'],indirect=True)
def test_missing_etcnet_resolver_is_supported_only_for_proven_dhcp(network):
    m=helper();f=network;f['persistent'].unlink()
    f['options'].write_text(f['options'].read_text().replace('BOOTPROTO=dhcp','BOOTPROTO=static'))
    with pytest.raises(m.DnsError):m.observe(f['request'],root=f['root'],call=f['call'])

@pytest.mark.parametrize('network',['nm_etcnet'],indirect=True)
@pytest.mark.parametrize('fault',['appeared','parent','rollback_race'])
def test_absent_resolver_atomic_publication_preserves_concurrent_state(network,monkeypatch,fault):
    m=helper();f=network;f['persistent'].unlink();value=m.observe(f['request'],root=f['root'],call=f['call'])
    namespace=f['root']/'journal';namespace.mkdir(mode=0o700)
    data=m.rewrite(value,f['request']['servers']);libc=m.ctypes.CDLL(None,use_errno=True)
    if fault=='parent':
        f['persistent'].parent.chmod(0o750)
        with pytest.raises(m.DnsError):m.publish_absent(value,data,f['root'],namespace)
        assert not f['persistent'].exists();return
    def rename(*args):
        if fault=='appeared':f['persistent'].write_text('nameserver 192.0.2.99\n')
        else:
            foreign=f['persistent'].with_suffix('.foreign');foreign.write_text('nameserver 192.0.2.99\n')
            foreign.replace(f['persistent'])
        return libc.renameat2(*args)
    if fault=='rollback_race':info=m.publish_absent(value,data,f['root'],namespace)
    monkeypatch.setattr(m.ctypes,'CDLL',lambda *a,**k:type('Libc',(),{'renameat2':staticmethod(rename)})())
    with pytest.raises(m.DnsError):
        if fault=='appeared':m.publish_absent(value,data,f['root'],namespace)
        else:m.restore_absent(value.path,data,info,f['root'],namespace)
    # The concurrent resolver remains available or retained; it is never lost.
    assert any(b'192.0.2.99' in p.read_bytes() for p in f['persistent'].parent.iterdir() if p.is_file())
    if fault=='appeared':assert f['persistent'].read_text()=='nameserver 192.0.2.99\n'
