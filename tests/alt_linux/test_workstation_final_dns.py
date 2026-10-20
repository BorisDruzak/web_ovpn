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
        if args[:3]==['nmcli','device','reapply'] or args[:2]==['resolvconf','-a']:
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
