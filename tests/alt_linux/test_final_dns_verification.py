"""Bounded DNS wire parsing and protected machine-ticket verification."""
import socket
import struct

import pytest

from test_workstation_final_dns import helper,network


def name(text):return b''.join(bytes([len(v)])+v.encode() for v in text.split('.'))+b'\0'


@pytest.mark.parametrize('bad',[False,True,'truncated','pointer_loop','wrong_question','wrong_type'])
def test_dns_wire_reply_binds_question_type_transaction_and_server(monkeypatch,bad):
    m=helper();calls=[]
    class Wire:
        def __enter__(self):return self
        def __exit__(self,*unused):pass
        def settimeout(self,value):assert 0<value<=3
        def connect(self,address):calls.append(address)
        def send(self,query):self.query=query
        def recv(self,maximum):
            query=self.query;transaction=query[:2] if bad is not True else b'00'
            data=transaction+struct.pack('!HHHHH',0x8180,1,1,0,0)+query[12:]
            target=b'\xc0\x0c' if bad=='pointer_loop' else name('dc.example.test')
            resource=struct.pack('!HHH',0,100,389)+target
            data+=b'\xc0\x0c'+struct.pack('!HHIH',33 if bad!='wrong_type' else 16,1,60,len(resource))+resource
            if bad=='truncated':data=data[:9]
            if bad=='wrong_question':data=data[:12]+data[12:].replace(b'_ldap',b'_noop',1)
            if bad=='pointer_loop':
                # A pointer to itself in the answer owner, not a valid alias.
                offset=12+len(query[12:]);data=data[:offset]+struct.pack('!H',0xc000|offset)+data[offset+2:]
            return data
    monkeypatch.setattr(m.socket,'socket',lambda *a,**kw:Wire())
    if bad:
        with pytest.raises(m.DnsError):m.query_dns('192.0.2.53','_ldap._tcp.example.test',33)
    else:assert m.query_dns('192.0.2.53','_ldap._tcp.example.test',33)==[(389,'dc.example.test')]
    assert calls==[('192.0.2.53',53)]


@pytest.mark.parametrize('fault',[None,'srv','controller','external','ticket','keytab'])
def test_verification_checks_dns_discovery_addresses_and_real_machine_keytab(network,monkeypatch,fault):
    m=helper();f=network;value=m.observe(f['request'],root=f['root'],call=f['call'])
    keytab=f['put']('etc/krb5.keytab','SYNTHETIC-PRIVATE-KEYTAB',0o600)
    if fault=='keytab':keytab.chmod(0o666)
    trace=[]
    def query(server,domain,type_):
        trace.append(('dns',server,domain,type_))
        if type_==33:return [] if fault=='srv' else [(389 if domain.startswith('_ldap') else 88,'dc.sosnadmin.local')]
        if fault=='controller' and domain=='dc.sosnadmin.local' or fault=='external' and domain=='download.basealt.ru':return []
        return ['192.0.2.11'] if type_==1 else []
    monkeypatch.setattr(m,'query_dns',query)
    monkeypatch.setattr(m.socket,'getaddrinfo',lambda *a,**kw:[] if fault=='controller' else [(2,1,6,'',('192.0.2.11',0))])
    def call(args,**options):
        trace.append(('command',args))
        if args[:2]==['klist','-k']:return 0,'Keytab name: FILE:/etc/krb5.keytab\n   1 ALT-TEST-PC1$@SOSNADMIN.LOCAL\n'
        if args[0]=='kinit':
            assert args[1:4]==['-k','-t',str(keytab)]
            assert args[-1]=='ALT-TEST-PC1$@SOSNADMIN.LOCAL'
            cache=args[args.index('-c')+1];assert cache.startswith('FILE:')
            directory=__import__('pathlib').Path(cache[5:]).parent
            assert directory.stat().st_mode&0o777==0o700
            return (1,'PRIVATE-SECRET-SENTINEL') if fault=='ticket' else (0,'')
        if args[0]=='kdestroy':return 0,''
        if args[:2]==['getent','ahosts']:
            return (2,'') if fault=='controller' else (0,'192.0.2.11 STREAM '+args[-1]+'\n')
        raise AssertionError(args)
    if fault:
        with pytest.raises(m.DnsError) as caught:m.verify_dns(value,phase='after',request=f['request'],root=f['root'],call=call)
        assert 'SENTINEL' not in str(caught.value)
    else:
        m.verify_dns(value,phase='after',request=f['request'],root=f['root'],call=call)
        assert any(t[0]=='command' and t[1][0]=='kinit' for t in trace)
    assert not list((f['root']/'run').glob('alt-final-dns-*'))
