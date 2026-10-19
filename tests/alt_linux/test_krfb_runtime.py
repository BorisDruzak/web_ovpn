"""Bounded RFB read probe: authentication and one discarded pixel, no input."""
import json
import socket
import struct
import sys
from pathlib import Path
import threading
from types import SimpleNamespace

import pytest


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
