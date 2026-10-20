"""Bounded RFB read probe: authentication and one discarded pixel, no input."""
import json
import socket
import struct
import sys
from pathlib import Path
import threading
import hashlib
import subprocess
from types import SimpleNamespace

import pytest


def policy_observation():
    value={'schema_version':1,'machine_uuid':'11111111-2222-3333-4444-555555555555',
        'hostname':'alt-test-pc1','boot_id':'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee',
        'source_sha256':'a'*64,'policy_sha256':hashlib.sha256(json.dumps(
            {'port':5900,'scope':'direct','authentication':'password_required'},sort_keys=True,
            separators=(',',':')).encode()).hexdigest(),
        'legacy':{'owned_legacy':False,'legacy_table_present':False,'retirement_required':False,
                  'service_disabled':True,'external_policy_clear':True},
        'listener_present':False,'external_policy_sha256':'b'*64,'marker_sha256':None,'ready':False}
    value['snapshot_sha256']=hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    return value


@pytest.mark.parametrize('case',['clean','listener','identity','digest','bool','extra','duplicate',
                                 'helper','source_drift','ssh_drift','boot_drift','auth_failure',
                                 'returned_auth_failure','missing_pixel','boolean_auth','unknown_failure',
                                 'pin_source','pin_ssh','pin_boot'])
def test_published_policy_observer_binds_identity_source_and_password_proof(tmp_path,monkeypatch,case):
    from alt_deploy import krfb_runtime as module
    from alt_deploy import component_probe,setup_runtime
    from alt_deploy.errors import ControlError
    project=tmp_path/'ansible';template=project/'roles/remote_access_policy/templates/alt-vnc-access-policy.py.j2'
    template.parent.mkdir(parents=True);template.write_text('# fixed published observer\n')
    settings=SimpleNamespace(ansible_project_dir=project,known_hosts_file=tmp_path/'known',private_key_file=tmp_path/'key')
    machine=SimpleNamespace(ip='192.0.2.4',uuid=policy_observation()['machine_uuid'],hostname='alt-test-pc1')
    fingerprints=iter(['a'*64,'b'*64] if case=='source_drift' else ['a'*64]*4)
    monkeypatch.setattr(setup_runtime,'source_fingerprint',lambda *a:next(fingerprints))
    bindings=iter([{'host_public_sha256':'c'*64,'controller_public_sha256':'d'*64},
                  {'host_public_sha256':('e' if case=='ssh_drift' else 'c')*64,'controller_public_sha256':'d'*64}])
    monkeypatch.setattr(component_probe,'ssh_binding',lambda *a,**k:next(bindings))
    proofs=[];transports=[]
    monkeypatch.setattr(module,'_protected_password',lambda settings:b'PRIVATE-SECRET-SENTINEL')
    def authenticate(*args,**kwargs):
        proofs.append(args)
        assert not case.startswith('pin_'),'Original pins must be checked before RFB'
        if case=='auth_failure':raise module._ProbeError('krfb_authentication_failed')
        kwargs['connector']((machine.ip,5900),timeout=3)
        result={'status':'ok','code':None,'password_authenticated':True,'server_init_verified':True,
                'pixel_update_verified':True,'width':1600,'height':900}
        if case=='returned_auth_failure':result.update(status='blocked',code='krfb_authentication_failed',password_authenticated=False)
        elif case=='missing_pixel':result['pixel_update_verified']=False
        elif case=='boolean_auth':result['password_authenticated']=1
        elif case=='unknown_failure':result.update(status='blocked',code='PRIVATE-SECRET-SENTINEL')
        return result
    monkeypatch.setattr(module,'_probe_rfb',authenticate)
    calls=[]
    def run(argv,**options):
        calls.append(argv);payload=json.loads(options['input_text'])
        value=policy_observation()
        value['listener_present']=case in ('listener','boot_drift','auth_failure','returned_auth_failure',
                                           'missing_pixel','boolean_auth','unknown_failure','pin_source','pin_ssh','pin_boot')
        value['snapshot_sha256']=hashlib.sha256(json.dumps({k:v for k,v in value.items() if k!='snapshot_sha256'},
                                    sort_keys=True,separators=(',',':')).encode()).hexdigest()
        if case=='identity':value['hostname']='another-host'
        elif case=='digest':value['snapshot_sha256']='e'*64
        elif case=='bool':value['legacy']['external_policy_clear']=1
        elif case=='extra':value['password']='PRIVATE-SECRET-SENTINEL'
        elif case=='boot_drift' and len(calls)>1:value['boot_id']='bbbbbbbb-bbbb-cccc-dddd-eeeeeeeeeeee'
        envelope={'schema_version':1,'status':'ok','operation':'observe',
                  'helper_sha256':payload['helper_sha256'],'observation':value}
        if case=='helper':envelope['helper_sha256']='e'*64
        raw=json.dumps(envelope)
        if case=='duplicate':raw=raw[:-1]+',"status":"PRIVATE-SECRET-SENTINEL"}'
        return 0,raw,''
    def connector(address,**kwargs):
        transports.append(address);return Connection(server_wire())
    # The production administrative connector must use its own pinned SSH child.
    monkeypatch.setattr(module,'_SSHChannel',lambda command,*,timeout: connector(command,timeout=timeout))
    policy={'port':5900,'scope':'direct','authentication':'password_required'}
    if case in ('clean','listener'):
        result=module.observe_vnc_policy(settings,machine,policy,runner=run)
        assert result['observation']['ready'] is False
        assert result['listener_authenticated'] is (case=='listener')
        assert bool(proofs) is (case=='listener')
        assert 'SENTINEL' not in json.dumps(result)
    else:
        pins={}
        if case=='pin_source':pins['expected_source']='f'*64
        if case=='pin_ssh':pins['expected_ssh_binding']={'host_public_sha256':'f'*64,'controller_public_sha256':'d'*64}
        if case=='pin_boot':pins['expected_boot_id']='ffffffff-bbbb-cccc-dddd-eeeeeeeeeeee'
        with pytest.raises(ControlError) as caught:module.observe_vnc_policy(settings,machine,policy,runner=run,**pins)
        if case.startswith('pin_'):assert caught.value.code=='vnc_policy_snapshot_changed' and proofs==[]
        assert 'SENTINEL' not in str(caught.value)
    assert all('PRIVATE-SECRET-SENTINEL' not in str(argv) for argv in calls)


@pytest.mark.parametrize('case',['ready','policy_unprepared','source_drift','ssh_drift','boot_drift',
    'config_drift','pid_drift','no_graphical_session','auth_failure','invalid_user','pin_boot','pin_session'])
def test_direct_public_probe_requires_selected_graphical_identity_and_fresh_rfb_evidence(tmp_path,monkeypatch,case):
    from alt_deploy import krfb_runtime as module
    from alt_deploy import component_probe,setup_runtime
    from alt_deploy.errors import ControlError
    machine=SimpleNamespace(ip='192.0.2.4',uuid=policy_observation()['machine_uuid'],hostname='alt-test-pc1')
    settings=SimpleNamespace(ansible_project_dir=tmp_path)
    helper=tmp_path/'roles/remote_access_policy/templates/alt-vnc-access-policy.py.j2'
    helper.parent.mkdir(parents=True);helper.write_text('# fixed published helper\n')
    user={'login':'synthetic.user','upn':'synthetic.user@sosnadmin.local',
          'object_guid':'cccccccc-dddd-eeee-ffff-aaaaaaaaaaaa','object_sid':'S-1-5-21-1-2-3-1001'}
    if case=='invalid_user':user['upn']='other.user@sosnadmin.local'
    binding={'host_public_sha256':'c'*64,'controller_public_sha256':'d'*64}
    before=policy_observation();before['ready']=case!='policy_unprepared'
    evidence={'schema_version':1,'ssh_binding':binding,'helper_sha256':hashlib.sha256(helper.read_bytes()).hexdigest(),
              'observation':before,'listener_authenticated':True}
    monkeypatch.setattr(module,'observe_vnc_policy',lambda *a,**k:evidence)
    monkeypatch.setattr(module,'_policy_read',lambda *a,**k:before)
    monkeypatch.setattr(module,'_protected_password',lambda *a:b'PRIVATE-SECRET-SENTINEL')
    source_calls=[]
    def fingerprint(*a):
        source_calls.append(a);return ('b' if case=='source_drift' else 'a')*64
    monkeypatch.setattr(setup_runtime,'source_fingerprint',fingerprint)
    monkeypatch.setattr(component_probe,'ssh_binding',lambda *a,**k:
        dict(binding,host_public_sha256='e'*64) if case=='ssh_drift' else binding)
    session={'machine_uuid':machine.uuid,'hostname':machine.hostname,'boot_id':before['boot_id'],
        'login':user['login'],'uid':1001,'gid':1001,'session_id':'40','session_sha256':'7'*64,
        'krfb_pid':102,'krfb_start_ticks':10200,'listener_present':True,'connected_clients':0,
        'configuration_safe':True,'autostart_safe':True,'configuration_sha256':'8'*64,
        'autostart_sha256':'9'*64,'schema_version':1,'snapshot_sha256':'6'*64}
    reads=[];probes=[]
    def session_read(*a,**k):
        reads.append(a)
        if case=='no_graphical_session':raise module._ProbeError('graphical_session_unavailable')
        result=dict(session)
        if len(reads)>1:
            if case=='boot_drift':result['boot_id']='bbbbbbbb-bbbb-cccc-dddd-eeeeeeeeeeee'
            elif case=='config_drift':result['configuration_sha256']='4'*64
            elif case=='pid_drift':result['krfb_pid']=103
        return result
    monkeypatch.setattr(module,'_session_read',session_read,raising=False)
    def direct(address,password,**options):
        probes.append(address);assert address==machine.ip and password==b'PRIVATE-SECRET-SENTINEL'
        if case=='auth_failure':return {'status':'blocked','code':'krfb_authentication_failed'}
        return {'status':'ok','code':None,'password_authenticated':True,'server_init_verified':True,
                'pixel_update_verified':True,'width':1600,'height':900}
    monkeypatch.setattr(module,'_probe_rfb',direct)
    if case in ('ready','policy_unprepared'):
        result=module.probe_krfb(settings,machine,user,module.DIRECT_POLICY)
        assert result['ready'] is (case=='ready')
        assert result['checks']['password_authenticated'] is True and result['width']==1600
        assert len(probes)==1 and len(reads)==2
        assert 'SENTINEL' not in json.dumps(result)
    else:
        pins={}
        if case=='pin_boot':pins['expected_boot_id']='ffffffff-bbbb-cccc-dddd-eeeeeeeeeeee'
        if case=='pin_session':pins['expected_session_sha256']='f'*64
        with pytest.raises(ControlError) as caught:module.probe_krfb(settings,machine,user,module.DIRECT_POLICY,**pins)
        if case.startswith('pin_'):assert caught.value.code=='vnc_policy_snapshot_changed' and probes==[]
        assert 'SENTINEL' not in str(caught.value)
        if case in ('no_graphical_session','invalid_user'):assert probes==[]


@pytest.mark.parametrize('payload',['{','{"login":"PRIVATE-SECRET-SENTINEL"}',
    '{"login":"a","login":"PRIVATE-SECRET-SENTINEL"}','PRIVATE-SECRET-SENTINEL'*500])
def test_fixed_graphical_program_rejects_untrusted_stdin_without_a_traceback(payload):
    from alt_deploy.krfb_runtime import _session_program
    result=subprocess.run([sys.executable,'-I','-B','-c',_session_program()],input=payload,
                          capture_output=True,text=True,timeout=10)
    assert result.returncode==4
    assert json.loads(result.stdout)['status']=='blocked'
    assert 'SENTINEL' not in result.stdout+result.stderr and result.stderr==''


@pytest.mark.parametrize('case',['ok','extra','identity','bool','digest','duplicate','blocked','unknown_error'])
def test_graphical_wire_envelope_is_strict_and_bound(tmp_path,case):
    from alt_deploy.krfb_runtime import _session_read,_ProbeError
    settings=SimpleNamespace(known_hosts_file=tmp_path/'known',private_key_file=tmp_path/'key')
    machine=SimpleNamespace(ip='192.0.2.4',uuid=policy_observation()['machine_uuid'],hostname='alt-test-pc1')
    user={'login':'synthetic.user'}
    value={'machine_uuid':machine.uuid,'hostname':machine.hostname,'boot_id':policy_observation()['boot_id'],
        'login':user['login'],'uid':1001,'gid':1001,'session_id':'40','session_sha256':'7'*64,
        'krfb_pid':102,'krfb_start_ticks':10200,'listener_present':True,'connected_clients':0,
        'configuration_safe':True,'autostart_safe':True,'configuration_sha256':'8'*64,
        'autostart_sha256':'9'*64,'schema_version':1}
    value['snapshot_sha256']=hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    if case=='extra':value['password']='PRIVATE-SECRET-SENTINEL'
    elif case=='identity':value['login']='another.user'
    elif case=='bool':value['uid']=True
    elif case=='digest':value['snapshot_sha256']='0'*64
    def runner(argv,**options):
        assert '-F' in argv and '/dev/null' in argv
        assert json.loads(options['input_text'])==dict(machine_uuid=machine.uuid,hostname=machine.hostname,login=user['login'])
        assert 'PRIVATE-SECRET-SENTINEL' not in str(argv)
        document={'schema_version':1,'status':'ok','observation':value};rc=0
        if case in ('blocked','unknown_error'):
            document={'schema_version':1,'status':'blocked','code':
                      'graphical_session_unavailable' if case=='blocked' else 'PRIVATE-SECRET-SENTINEL'};rc=4
        raw=json.dumps(document)
        if case=='duplicate':raw=raw[:-1]+',"status":"PRIVATE-SECRET-SENTINEL"}'
        return rc,raw,''
    if case=='ok':assert _session_read(settings,machine,user,runner)==value
    else:
        with pytest.raises((_ProbeError,ValueError)) as caught:_session_read(settings,machine,user,runner)
        assert 'SENTINEL' not in str(caught.value)


def server_wire(*, security=b'\x02', auth=0, name=b'PRIVATE-DESKTOP-SENTINEL',
                width=1600, height=900, encoding=0, pixels=b'\x01\x02\x03\x04'):
    challenge = bytes.fromhex('0123456789abcdef') * 2
    fmt = struct.pack('>BBBBHHHBBBxxx', 32, 24, 0, 1, 255, 255, 255, 16, 8, 0)
    return (b'RFB 003.008\n' + bytes([len(security)]) + security + challenge
            + struct.pack('>I', auth) + struct.pack('>HH', width, height) + fmt
            + struct.pack('>I', len(name)) + name + b'\0\0\0\x01'
            + struct.pack('>HHHHi', 0, 0, 1, 1, encoding) + pixels)


class Connection:
    def __init__(self, wire):
        self.wire = bytearray(wire)
        self.sent = []
        self.closed = False
        self.timeouts = []

    def settimeout(self, timeout):
        self.timeouts.append(timeout)

    def recv(self, size):
        # Exercise fragmentation throughout all headers and the challenge.
        result = self.wire[:min(size, 2)]
        del self.wire[:len(result)]
        return bytes(result)

    def sendall(self, data):
        self.sent.append(data)

    def close(self):
        self.closed = True


def password():
    # Bit-reversed NIST DES key; not a live service password.
    return bytes.fromhex('c82cea9ed93dfb8f')


def probe(wire, **options):
    from alt_deploy.krfb_runtime import _probe_rfb
    connection = Connection(wire)
    calls = []
    def connect(destination, *, timeout):
        calls.append(destination)
        assert 0 < timeout <= 8
        return connection
    result = _probe_rfb('192.0.2.7', password(), connector=connect, **options)
    assert calls == [('192.0.2.7', 5900)]
    assert connection.closed
    assert b'PRIVATE-DESKTOP-SENTINEL' not in json.dumps(result).encode()
    assert b'01020304' not in json.dumps(result).encode()
    return result, connection


def test_vnc_challenge_matches_independent_nist_des_vector():
    from alt_deploy.krfb_runtime import _vnc_response
    assert _vnc_response(password(), bytes.fromhex('0123456789abcdef')*2) == \
        bytes.fromhex('85e813540f0ab405')*2


def test_authenticated_probe_shares_desktop_and_discards_one_pixel():
    result, connection = probe(server_wire())
    assert result == {'status':'ok','code':None,'password_authenticated':True,
        'server_init_verified':True,'pixel_update_verified':True,'width':1600,'height':900}
    assert connection.sent[0] == b'RFB 003.008\n'
    assert connection.sent[1] == b'\x02'
    assert connection.sent[2] == bytes.fromhex('85e813540f0ab405')*2
    assert connection.sent[3] == b'\x01'  # shared: never disconnect human clients
    assert connection.sent[-1] == struct.pack('>BBHHHH',3,0,0,0,1,1)
    assert connection.sent[-2] == struct.pack('>BBHi',2,0,1,0)
    assert len(connection.sent) == 7  # no keyboard, mouse or clipboard message


@pytest.mark.parametrize('security', [b'\x01', b'\x01\x02', b'\x02\x01', b'\x10', b'', bytes(range(32))])
def test_no_authentication_or_unbounded_security_list_is_never_accepted(security):
    result, connection = probe(server_wire(security=security))
    assert result['status'] == 'blocked'
    assert result['password_authenticated'] is False
    assert len(connection.sent) == 1


@pytest.mark.parametrize('change', ['auth', 'version', 'oversized_name', 'zero_width',
    'encoding', 'missing_pixel', 'truncated_init', 'unexpected_message'])
def test_protocol_and_authentication_failures_never_claim_ready(change):
    if change == 'auth': wire = server_wire(auth=1)
    elif change == 'version': wire = server_wire().replace(b'003.008',b'003.003',1)
    elif change == 'oversized_name': wire = server_wire(name=b'x'*4097)
    elif change == 'zero_width': wire = server_wire(width=0)
    elif change == 'encoding': wire = server_wire(encoding=5)
    elif change == 'missing_pixel': wire = server_wire(pixels=b'')
    elif change == 'truncated_init': wire = server_wire()[:50]
    else: wire = server_wire().replace(b'\0\0\0\x01'+struct.pack('>HHHHi',0,0,1,1,0),
                                     b'\x06\0\0\x01'+struct.pack('>HHHHi',0,0,1,1,0))
    result, _ = probe(wire)
    assert result['status'] == 'blocked'
    assert result['pixel_update_verified'] is False
    assert result['code'].startswith('krfb_')


@pytest.mark.parametrize('error', [TimeoutError, ConnectionRefusedError, OSError])
def test_transport_error_is_safe_without_raw_exception(error):
    from alt_deploy.krfb_runtime import _probe_rfb
    def connect(*a, **k):
        raise error('PRIVATE-PASSWORD-ERROR-SENTINEL')
    result = _probe_rfb('192.0.2.7', password(), connector=connect)
    assert result['status']=='blocked'
    assert result['code']=='krfb_network_policy_or_transport_blocked'
    assert 'SENTINEL' not in json.dumps(result)


@pytest.mark.parametrize('error,code', [(ConnectionResetError,'krfb_network_policy_or_transport_blocked'),
                                      (TimeoutError,'krfb_probe_timeout')])
def test_transport_loss_after_connect_keeps_the_actual_error_class(error,code):
    from alt_deploy.krfb_runtime import _probe_rfb
    connection=Connection(server_wire())
    def receive(size):raise error('PRIVATE-TRANSPORT-SENTINEL')
    connection.recv=receive
    result=_probe_rfb('192.0.2.7',password(),connector=lambda *a,**k:connection)
    assert connection.closed and result['code']==code
    assert 'SENTINEL' not in json.dumps(result)


def test_total_probe_deadline_survives_a_slow_fragmented_peer():
    clock = iter(range(100))
    result, connection = probe(server_wire(), clock=lambda: next(clock))
    assert result['status']=='blocked'
    assert result['code']=='krfb_probe_timeout'
    assert len(connection.timeouts) <= 8


def test_empty_or_unsafe_password_stops_before_connect():
    from alt_deploy.krfb_runtime import _probe_rfb
    for value in (b'', b'x'*257, None, 'password'):
        result = _probe_rfb('192.0.2.7', value, connector=lambda *a,**k:pytest.fail('Unexpected network access'))
        assert result['status']=='blocked'
        assert result['code']=='krfb_password_unavailable'


def test_existing_kde_obscured_secret_is_decoded_only_in_memory():
    from alt_deploy.krfb_runtime import _decode_password
    assert _decode_password('\uffaf\uffbe\uffac\uffac\uffa8\uffb0\uffad\uffbb')==b'password'
    assert _decode_password(' !\uffbe')==b' !a'


@pytest.mark.parametrize('value', ['', None, 'unencoded-plaintext', '\n', 'x'*257, '\ud800'])
def test_invalid_obscured_secret_has_fixed_private_failure(value):
    from alt_deploy.krfb_runtime import _decode_password, _ProbeError
    with pytest.raises(_ProbeError) as caught:_decode_password(value)
    assert str(caught.value)=='krfb_password_unavailable'


def test_admin_stream_transport_is_bounded_and_closes_only_its_own_child(tmp_path):
    from alt_deploy.krfb_runtime import _SSHChannel
    script=tmp_path/'stream.py'
    script.write_text("import sys,time;sys.stdout.buffer.write(b'hello');sys.stdout.buffer.flush();v=sys.stdin.buffer.read(5);sys.stdout.buffer.write(v);sys.stdout.buffer.flush();time.sleep(5)")
    channel=_SSHChannel([sys.executable,str(script)],timeout=1)
    channel.settimeout(1)
    assert channel.recv(5)==b'hello'
    channel.sendall(b'world')
    assert channel.recv(5)==b'world'
    pid=channel.process.pid
    channel.close()
    assert channel.process.pid==pid and channel.process.poll() is not None


def test_administrative_transport_read_timeout_does_not_hang(tmp_path):
    from alt_deploy.krfb_runtime import _SSHChannel
    script=tmp_path/'stream.py';script.write_text('import time;time.sleep(5)')
    channel=_SSHChannel([sys.executable,str(script)],timeout=0.05)
    channel.settimeout(0.05)
    try:
        with pytest.raises(TimeoutError):channel.recv(12)
    finally:channel.close()


def test_password_material_comes_only_from_protected_vault(monkeypatch):
    from alt_deploy.krfb_runtime import _protected_password
    from alt_deploy.vault import VaultHealthChecker
    monkeypatch.setattr(VaultHealthChecker,'_build_checks',lambda self:{'owned_private':True})
    monkeypatch.setattr(VaultHealthChecker,'_decrypt',lambda self:
        'vault_krfb_unattended_password_obscured: "\uffaf\uffbe\uffac\uffac\uffa8\uffb0\uffad\uffbb"\n')
    assert _protected_password(object())==b'password'


@pytest.mark.parametrize('case', ['unsafe','missing','wrong_type','duplicate','parse','plaintext'])
def test_unavailable_vault_or_ambiguous_secret_is_private_failure(monkeypatch,case):
    from alt_deploy.krfb_runtime import _protected_password,_ProbeError
    from alt_deploy.vault import VaultHealthChecker
    monkeypatch.setattr(VaultHealthChecker,'_build_checks',lambda self:{'owned_private':case!='unsafe'})
    if case=='unsafe':
        monkeypatch.setattr(VaultHealthChecker,'_decrypt',lambda self:pytest.fail('Unsafe Vault must not be read'))
    else:
        values={'missing':'another_key: "PRIVATE-SECRET-SENTINEL"\n',
                'wrong_type':'vault_krfb_unattended_password_obscured: true\n',
                'duplicate':'vault_krfb_unattended_password_obscured: x\nvault_krfb_unattended_password_obscured: y\n',
                'parse':'vault_krfb_unattended_password_obscured: [\n',
                'plaintext':'vault_krfb_unattended_password_obscured: PRIVATE-SECRET-SENTINEL\n'}
        monkeypatch.setattr(VaultHealthChecker,'_decrypt',lambda self:values[case])
    with pytest.raises(_ProbeError) as caught:_protected_password(object())
    assert str(caught.value)=='krfb_password_unavailable'


def test_admin_command_is_pinned_and_cannot_select_a_remote_proxy_or_command(tmp_path):
    from alt_deploy.krfb_runtime import _admin_command, _ADMIN_PROXY
    settings=SimpleNamespace(known_hosts_file=tmp_path/'known_hosts',private_key_file=tmp_path/'key')
    machine=SimpleNamespace(ip='192.0.2.7')
    command=_admin_command(settings,machine)
    assert command[0]=='/usr/bin/ssh' and command[-2]=='ansible@192.0.2.7'
    assert command[1:3]==['-F','/dev/null']
    assert all(option in command for option in ('StrictHostKeyChecking=yes','ProxyCommand=none',
        'ProxyJump=none','IdentitiesOnly=yes','IdentityAgent=none','PermitLocalCommand=no',
        'ClearAllForwardings=yes','ForwardAgent=no','ForwardX11=no','ControlMaster=no','ControlPath=none',
        'UpdateHostKeys=no','VerifyHostKeyDNS=no','HostKeyAlias=192.0.2.7','GSSAPIAuthentication=no',
        'PreferredAuthentications=publickey'))
    assert "('127.0.0.1',5900)" in _ADMIN_PROXY
    assert 'PRIVATE-' not in repr(command)


def test_fixed_administrative_proxy_carries_real_tcp_handshake_without_input(tmp_path):
    from alt_deploy.krfb_runtime import _ADMIN_PROXY,_SSHChannel,_probe_rfb
    listener=socket.socket();listener.bind(('127.0.0.1',0));listener.listen(1);listener.settimeout(3)
    port=listener.getsockname()[1];received=bytearray();errors=[]
    def serve():
        try:
            connection,_=listener.accept();connection.settimeout(3)
            with connection:
                wire=server_wire()
                connection.sendall(wire[:-20])
                while len(received)<68:
                    block=connection.recv(8192)
                    if not block:raise AssertionError('Premature close')
                    received.extend(block)
                connection.sendall(wire[-20:])
                while True:
                    block=connection.recv(8192)
                    if not block:break
                    received.extend(block)
        except Exception as exc:errors.append(type(exc).__name__)
    worker=threading.Thread(target=serve,daemon=True);worker.start()
    proxy=tmp_path/'fixed-proxy.py'
    assert _ADMIN_PROXY.count("('127.0.0.1',5900)")==1
    proxy.write_text(_ADMIN_PROXY.replace("('127.0.0.1',5900)",repr(('127.0.0.1',port))))
    try:
        result=_probe_rfb('192.0.2.7',password(),connector=lambda *a,**k:
                         _SSHChannel([sys.executable,str(proxy)],timeout=k['timeout']))
        assert result['status']=='ok'
    finally:
        worker.join(4);listener.close()
    assert not worker.is_alive() and errors==[]
    assert received.startswith(b'RFB 003.008\n\x02'+bytes.fromhex('85e813540f0ab405')*2+b'\x01')
    assert received.endswith(struct.pack('>BBHHHH',3,0,0,0,1,1))
