"""Reproduce real NM reapply loss without relaxing network identity checks."""
import json
import os
import shutil
import signal
import subprocess

import pytest

from test_workstation_final_dns import helper, network, files


@pytest.mark.parametrize('network',['nm_etcnet','nm_keyfile'],indirect=True)
def test_dns_reapply_preserves_external_ipv6_link_address_and_route(network):
    m=helper();f=network;state={'ipv6_alive':True,'mutations':0}
    def call(args,**kwargs):
        if args[:4]==['ip','-j','-6','route']:
            return 0,json.dumps([{'dst':'fe80::/64','protocol':'kernel','metric':256}] if state['ipv6_alive'] else [])
        if args[:4]==['ip','-j','-6','address']:
            return 0,json.dumps([{'ifname':'eth0','addr_info':[{'family':'inet6','local':'fe80::1234','prefixlen':64,'scope':'link'}]}] if state['ipv6_alive'] else [])
        if args[:3]==['nmcli','device','reapply']:
            state['mutations']+=1;state['ipv6_alive']=False
        if args[0]=='/usr/bin/busctl' and 'Reapply' in args:
            state['mutations']+=1
            assert args[-2:]==['7','1']
            assert args[args.index('a{sa{sv}}tu')+1]!='0'
        return f['call'](args,**kwargs)
    before=m.observe(f['request'],root=f['root'],call=call)
    result=m.apply(f['request'],before.public['snapshot_sha256'],f['context'],root=f['root'],call=call,
                   verify=lambda *a,**kw:None)
    assert result=={'status':'applied_verified','changed':True,'code':'final_dns_applied'}
    assert state=={'ipv6_alive':True,'mutations':1}
    assert m.observe(f['request'],root=f['root'],call=call).public['network_sha256']==before.public['network_sha256']


@pytest.mark.parametrize('network',['nm_etcnet','nm_keyfile'],indirect=True)
def test_dns_reapply_waits_read_only_for_transient_dhcp_without_repeating_mutation(network,monkeypatch):
    m=helper();f=network;state={'applied':False,'polls':0,'mutations':0}
    monkeypatch.setattr(m.time,'sleep',lambda duration:None)
    def call(args,**kwargs):
        if args[:3]==['nmcli','device','reapply'] or args[0]=='/usr/bin/busctl' and 'Reapply' in args:
            state['applied']=True;state['mutations']+=1
        if state['applied'] and args==['ip','-j','-4','route','show','default']:
            state['polls']+=1
            if state['polls']==1:return 0,'[]'
        return f['call'](args,**kwargs)
    before=m.observe(f['request'],root=f['root'],call=call)
    result=m.apply(f['request'],before.public['snapshot_sha256'],f['context'],root=f['root'],call=call,
                   verify=lambda *a,**kw:None)
    assert result=={'status':'applied_verified','changed':True,'code':'final_dns_applied'}
    assert state['mutations']==1 and state['polls']>=2


@pytest.mark.parametrize('network',['nm_etcnet','nm_keyfile'],indirect=True)
@pytest.mark.parametrize('fault',['unsupported','foreign_uuid','zero_version','foreign_device_path','unknown_type'])
def test_nm_preserve_capability_is_checked_before_any_write(network,fault):
    m=helper();f=network;before=files(f['root'])
    def call(args,**kwargs):
        if args[0]=='/usr/bin/busctl':
            if fault=='unsupported' and 'get-property' in args:return 0,json.dumps({'type':'s','data':'1.40.16'})
            if fault=='foreign_device_path' and 'GetDeviceByIpIface' in args:return 0,json.dumps({'type':'o','data':['/foreign/device']})
            if 'GetAppliedConnection' in args and fault in ('foreign_uuid','zero_version'):
                return 0,json.dumps({'type':'a{sa{sv}}t','data':[{'connection':{'uuid':{'type':'s','data':'ffffffff-ffff-ffff-ffff-ffffffffffff' if fault=='foreign_uuid' else f['state']['connection']}}},0 if fault=='zero_version' else 7]})
            if 'GetAppliedConnection' in args and fault=='unknown_type':
                rc,raw=f['call'](args,**kwargs);value=json.loads(raw)
                value['data'][0]['ipv4']['unsupported']={'type':'h','data':7}
                return rc,json.dumps(value)
        return f['call'](args,**kwargs)
    with pytest.raises(m.DnsError):m.observe(f['request'],root=f['root'],call=call)
    assert files(f['root'])==before
    assert not (f['root']/'var/lib/alt-workstation-final-dns').exists()


@pytest.mark.parametrize('network',['nm_etcnet','nm_keyfile'],indirect=True)
def test_reapply_cannot_activate_unapplied_saved_mtu(network):
    m=helper();f=network;state={'mutations':0}
    def call(args,**kwargs):
        if args[0]=='/usr/bin/busctl' and 'GetAppliedConnection' in args:
            rc,raw=f['call'](args,**kwargs);value=json.loads(raw)
            value['data'][0]['802-3-ethernet']={'mtu':{'type':'u','data':1500}}
            value['data'][0]['ipv4']={'method':{'type':'s','data':'auto'},'dns-search':{'type':'as','data':['example.test']}}
            value['data'][0]['ipv6']={'method':{'type':'s','data':'ignore'}}
            return rc,json.dumps(value)
        if args[:3]==['nmcli','connection','reload'] or args[:3]==['nmcli','connection','load']:
            # Saved MTU=9000 must not replace the applied MTU=1500.
            return 0,''
        if args[0]=='/usr/bin/busctl' and 'Reapply' in args:
            state['mutations']+=1
            assert args[args.index('a{sa{sv}}tu')+1]!='0'
            assert args[args.index('mtu'):args.index('mtu')+3]==['mtu','u','1500']
            assert '9000' not in args and '192.0.2.53' in args and 'example.test' in args
        return f['call'](args,**kwargs)
    before=m.observe(f['request'],root=f['root'],call=call)
    result=m.apply(f['request'],before.public['snapshot_sha256'],f['context'],root=f['root'],call=call,verify=lambda *a,**kw:None)
    assert result['status']=='applied_verified' and state['mutations']==1


def test_nm_settings_encoding_is_accepted_by_real_private_dbus():
    if not shutil.which('dbus-daemon') or not shutil.which('busctl'):pytest.skip('Private D-Bus tools unavailable')
    settings={'connection':{'id':{'type':'s','data':'Employee connection'}},
        '802-3-ethernet':{'auto-negotiate':{'type':'b','data':False},'s390-options':{'type':'a{ss}','data':{}}},
        'ipv4':{'dns-data':{'type':'as','data':['192.0.2.53']},'dns':{'type':'au','data':[1]},
            'address-data':{'type':'aa{sv}','data':[{'prefix':{'type':'u','data':24},'address':{'type':'s','data':'192.0.2.10'}}]},
            'addresses':{'type':'aau','data':[[1,24,2]]}},
        'ipv6':{'addresses':{'type':'a(ayuay)','data':[[[0]*16,64,[0]*16]]},
            'routes':{'type':'a(ayuayu)','data':[[[0]*16,64,[0]*16,256]]}}}
    encoded=helper().nm_settings_args(settings)
    daemon=subprocess.run(['dbus-daemon','--session','--fork','--print-address=1','--print-pid=1'],capture_output=True,text=True,check=True,timeout=5)
    address,pid=daemon.stdout.splitlines()
    try:
        # The real daemon must decode this complete settings signature before
        # rejecting the deliberately nonexistent method. No system bus is used.
        result=subprocess.run(['busctl','--address='+address,'--timeout=3','call','org.freedesktop.DBus',
            '/org/freedesktop/DBus','org.freedesktop.DBus','NoSuchMethod','a{sa{sv}}tu']+encoded+['7','1'],capture_output=True,text=True,timeout=5)
        assert result.returncode!=0 and ('Unknown method' in result.stderr or 'does not understand message' in result.stderr),result.stderr
    finally:os.kill(int(pid),signal.SIGTERM)


@pytest.mark.parametrize('network',['nm_etcnet','nm_keyfile'],indirect=True)
def test_foreign_applied_dns_is_preserved_after_version_cas_rejection(network):
    m=helper();f=network;state={'foreign':False,'mutations':0}
    def call(args,**kwargs):
        if args[0]=='/usr/bin/busctl' and 'GetAppliedConnection' in args:
            rc,raw=f['call'](args,**kwargs);value=json.loads(raw)
            if state['foreign']:
                value['data'][1]=8
                value['data'][0]['ipv4']['dns-data']={'type':'as','data':['192.0.2.99']}
            return rc,json.dumps(value)
        if args[0]=='/usr/bin/busctl' and 'Reapply' in args:
            state['mutations']+=1
            if state['mutations']==1:
                state['foreign']=True
                return 1,'version mismatch'
        return f['call'](args,**kwargs)
    before=m.observe(f['request'],root=f['root'],call=call)
    result=m.apply(f['request'],before.public['snapshot_sha256'],f['context'],root=f['root'],call=call,verify=lambda *a,**kw:None)
    assert result['status']=='outcome_unverified'
    assert state=={'foreign':True,'mutations':1}
