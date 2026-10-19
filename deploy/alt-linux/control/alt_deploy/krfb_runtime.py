"""Fixed RFB interoperability probe; never send input or retain desktop pixels.

Protocol: RFC 6143 sections 7.1-7.7. Only the legacy VNC challenge uses DES.
No system crypto policy is changed if the existing backend cannot provide it.
"""
from __future__ import annotations

import ipaddress
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import shlex
import socket
import struct
import subprocess
import time


DIRECT_POLICY = {'port':5900,'scope':'direct','authentication':'password_required'}


def _canonical(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()


def _unique_object(pairs):
    value = {}
    for key,item in pairs:
        if key in value:raise ValueError
        value[key] = item
    return value


def _policy_read(settings, machine, source, helper, runner):
    request = {'schema_version':1,'machine_uuid':machine.uuid,'hostname':machine.hostname,
               'source_sha256':source,'helper_sha256':hashlib.sha256(helper.encode()).hexdigest()}
    command = _admin_command(settings,machine)[:-1]+[
        'sudo -n /usr/bin/python3 -I -B -c '+shlex.quote(helper)+' --observe']
    rc,raw,_ = runner(command,environment={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'},
                      input_text=json.dumps(request),timeout=60,max_bytes=65536)
    if not isinstance(raw,str) or len(raw.encode())>65536:raise ValueError
    document = json.loads(raw,object_pairs_hook=_unique_object)
    if (rc or not isinstance(document,dict)
            or set(document)!={'schema_version','status','operation','helper_sha256','observation'}
            or type(document['schema_version']) is not int or document['schema_version']!=1
            or document['status']!='ok' or document['operation']!='observe'
            or document['helper_sha256']!=request['helper_sha256']):raise ValueError
    value = document['observation']
    if (not isinstance(value,dict) or set(value)!={'schema_version','machine_uuid','hostname','boot_id',
            'source_sha256','policy_sha256','legacy','listener_present','external_policy_sha256',
            'marker_sha256','ready','snapshot_sha256'}
            or type(value['schema_version']) is not int or value['schema_version']!=1
            or value['machine_uuid']!=machine.uuid or value['hostname']!=machine.hostname
            or value['source_sha256']!=source
            or value['policy_sha256']!=hashlib.sha256(_canonical(DIRECT_POLICY)).hexdigest()
            or not isinstance(value['boot_id'],str)
            or not re.fullmatch('[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}',value['boot_id'])
            or any(type(value[k]) is not bool for k in ('listener_present','ready'))):raise ValueError
    legacy = value['legacy']
    if (not isinstance(legacy,dict) or set(legacy)!={'owned_legacy','legacy_table_present',
            'retirement_required','service_disabled','external_policy_clear'}
            or any(type(item) is not bool for item in legacy.values())):raise ValueError
    for key in ('external_policy_sha256','snapshot_sha256','marker_sha256'):
        if key=='marker_sha256' and value[key] is None:continue
        if not isinstance(value[key],str) or not re.fullmatch('[0-9a-f]{64}',value[key]):raise ValueError
    if value['snapshot_sha256']!=hashlib.sha256(_canonical(
            {key:item for key,item in value.items() if key!='snapshot_sha256'})).hexdigest():raise ValueError
    if value['ready'] and (legacy['retirement_required'] or not legacy['service_disabled']
            or not legacy['external_policy_clear'] or value['marker_sha256'] is None):raise ValueError
    return value


def observe_vnc_policy(settings, machine, policy, *, runner=None):
    """Read current policy and independently authenticate any existing listener."""
    from .ad_transport import bounded_run
    from .ad_directory import fail
    from .component_catalog import _regular
    from .component_probe import ssh_binding
    from .setup_runtime import source_fingerprint
    runner = runner or bounded_run
    try:
        if (not isinstance(policy,dict) or set(policy)!=set(DIRECT_POLICY)
                or type(policy['port']) is not int or policy!=DIRECT_POLICY):raise ValueError
        path = settings.ansible_project_dir/'roles/remote_access_policy/templates/alt-vnc-access-policy.py.j2'
        _regular(path)
        helper = path.read_text(encoding='utf-8')
        if not 0<len(helper.encode())<=65536:raise ValueError
        source = source_fingerprint(settings.ansible_project_dir,Path(__file__).parent)
        binding = ssh_binding(settings,machine,runner=runner)
        before = _policy_read(settings,machine,source,helper,runner)
        if not before['legacy']['external_policy_clear']:
            raise _ProbeError('vnc_policy_external_blocker')
        authenticated = False
        if before['listener_present']:
            password = _protected_password(settings)
            _probe_rfb(str(ipaddress.ip_address(machine.ip)),password,
                       connector=lambda *a,**k:_SSHChannel(_admin_command(settings,machine),timeout=k['timeout']))
            authenticated = True
            if _policy_read(settings,machine,source,helper,runner)!=before:
                raise _ProbeError('vnc_policy_snapshot_changed')
        if (source_fingerprint(settings.ansible_project_dir,Path(__file__).parent)!=source
                or ssh_binding(settings,machine,runner=runner)!=binding):
            raise _ProbeError('vnc_policy_snapshot_changed')
        return {'schema_version':1,'helper_sha256':hashlib.sha256(helper.encode()).hexdigest(),
                'ssh_binding':binding,'observation':before,
                'listener_authenticated':authenticated}
    except Exception as error:
        allowed = {'vnc_policy_external_blocker','vnc_policy_snapshot_changed',
                   'krfb_password_unavailable','krfb_authentication_failed','krfb_transport_blocked',
                   'krfb_timeout','krfb_protocol_unverified','krfb_authentication_required'}
        code = str(error) if isinstance(error,_ProbeError) else ''
        if code not in allowed:code = 'vnc_policy_observation_unverified'
        raise fail(code,'Direct VNC policy evidence cannot be verified') from None


# A fixed loopback-only binary bridge avoids requiring SSH port-forwarding or
# a crypto package on the target. Both directions are private and bounded;
# credentials travel only inside the already pinned administrative SSH channel.
_ADMIN_PROXY = r'''
import os,select,socket,time
connection=socket.create_connection(('127.0.0.1',5900),timeout=3)
connection.setblocking(False)
os.set_blocking(0,False);os.set_blocking(1,False)
to_server=bytearray();to_client=bytearray();server_eof=False;total=0
deadline=time.monotonic()+12
try:
    while time.monotonic()<deadline:
        if server_eof and not to_client:break
        readers=[0]+([] if server_eof else [connection])
        writers=([connection] if to_server else [])+([1] if to_client else [])
        ready,writeable,_=select.select(readers,writers,[],min(0.2,max(0,deadline-time.monotonic())))
        if 0 in ready:
            try:block=os.read(0,4096)
            except BlockingIOError:block=None
            if block==b'':break
            if block:to_server.extend(block);total+=len(block)
        if connection in ready:
            try:block=connection.recv(4096)
            except BlockingIOError:block=None
            if block==b'':server_eof=True
            if block:to_client.extend(block);total+=len(block)
        if total>32768:break
        if connection in writeable:
            try:count=connection.send(to_server)
            except BlockingIOError:count=0
            del to_server[:count]
        if 1 in writeable:
            try:count=os.write(1,to_client)
            except BlockingIOError:count=0
            del to_client[:count]
finally:
    connection.close()
'''


def _admin_command(settings, machine):
    address = str(ipaddress.ip_address(machine.ip))
    return ['/usr/bin/ssh','-F','/dev/null','-T','-o','BatchMode=yes','-o','StrictHostKeyChecking=yes',
            '-o','ProxyCommand=none','-o','ProxyJump=none','-o','IdentitiesOnly=yes',
            '-o','IdentityAgent=none','-o','PermitLocalCommand=no','-o','LogLevel=ERROR',
            '-o','ClearAllForwardings=yes','-o','ForwardAgent=no','-o','ForwardX11=no',
            '-o','ControlMaster=no','-o','ControlPath=none','-o','UpdateHostKeys=no',
            '-o','VerifyHostKeyDNS=no','-o','HostKeyAlias='+address,
            '-o','GSSAPIAuthentication=no','-o','PreferredAuthentications=publickey',
            '-o','ConnectTimeout=3','-o','UserKnownHostsFile='+str(settings.known_hosts_file),
            '-i',str(settings.private_key_file),'ansible@'+address,
            '/usr/bin/python3 -I -B -c '+shlex.quote(_ADMIN_PROXY)]


class _ProbeError(Exception):
    pass


def _decode_password(value):
    # KStringHandler::obscure is involutive on Qt's ushort code units.
    # The protected field explicitly contains that existing representation.
    if not isinstance(value,str) or not 0<len(value)<=256:
        raise _ProbeError('krfb_password_unavailable')
    try:
        decoded = ''.join(ch if ord(ch)<=0x21 else chr((0x1001F-ord(ch)) & 0xffff) for ch in value)
        if not decoded.strip() or any(not 0x20<=ord(ch)<=0x7e for ch in decoded):
            raise ValueError
        return decoded.encode('ascii')
    except (ValueError,UnicodeError):
        raise _ProbeError('krfb_password_unavailable') from None


def _protected_password(settings):
    try:
        import yaml
        from .component_catalog import _StrictLoader
        from .vault import VaultHealthChecker, KRFB_UNATTENDED_PASSWORD_VARIABLE
        checker = VaultHealthChecker(settings)
        checks = checker._build_checks()
        if not isinstance(checks,dict) or not checks or not all(value is True for value in checks.values()):
            raise ValueError
        decrypted = checker._decrypt()
        if not isinstance(decrypted,str) or not 0<len(decrypted)<=1048576:
            raise ValueError
        values = yaml.load(decrypted,Loader=_StrictLoader)
        if not isinstance(values,dict):
            raise ValueError
        return _decode_password(values.get(KRFB_UNATTENDED_PASSWORD_VARIABLE))
    except Exception:
        # Never format the decrypted document, YAML exception or secret value.
        raise _ProbeError('krfb_password_unavailable') from None


class _SSHChannel:
    """Socket-like private stdin/stdout stream over one owned SSH subprocess."""
    def __init__(self, command, *, timeout):
        self.timeout = timeout
        self.process = subprocess.Popen(command,stdin=subprocess.PIPE,stdout=subprocess.PIPE,
                                        stderr=subprocess.DEVNULL,bufsize=0,close_fds=True)
        os.set_blocking(self.process.stdout.fileno(),False)
        os.set_blocking(self.process.stdin.fileno(),False)

    def settimeout(self, value):
        if not 0<value<=8:
            raise TimeoutError
        self.timeout = value

    def _wait(self, descriptor, event, deadline):
        remaining = deadline-time.monotonic()
        if remaining<=0:
            raise TimeoutError
        with selectors.DefaultSelector() as selected:
            selected.register(descriptor,event)
            if not selected.select(remaining):
                raise TimeoutError

    def recv(self, size):
        self._wait(self.process.stdout.fileno(),selectors.EVENT_READ,time.monotonic()+self.timeout)
        return os.read(self.process.stdout.fileno(),size)

    def sendall(self, data):
        if not isinstance(data,bytes) or len(data)>8192:
            raise OSError('bounded stream')
        deadline = time.monotonic()+self.timeout
        offset = 0
        while offset<len(data):
            self._wait(self.process.stdin.fileno(),selectors.EVENT_WRITE,deadline)
            offset += os.write(self.process.stdin.fileno(),data[offset:])

    def close(self):
        for stream in (self.process.stdin,self.process.stdout):
            try:
                stream.close()
            except OSError:
                pass
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=1)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=1)


def _vnc_response(password: bytes, challenge: bytes) -> bytes:
    if (not isinstance(password, bytes) or not 0 < len(password) <= 256
            or not isinstance(challenge, bytes) or len(challenge) != 16):
        raise _ProbeError('krfb_password_unavailable')
    try:
        # The repository pins 46.0.5; deployed ALT also supplies 42.0.5. Prefer
        # the current API, retaining the earlier existing distribution API.
        try:
            from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
        except ImportError:
            from cryptography.hazmat.primitives.ciphers.algorithms import TripleDES
        from cryptography.hazmat.primitives.ciphers import Cipher, modes
        from cryptography.exceptions import UnsupportedAlgorithm
    except ImportError:
        raise _ProbeError('krfb_crypto_unavailable') from None
    key = bytes(int(f'{byte:08b}'[::-1], 2) for byte in password[:8].ljust(8, b'\0'))
    try:
        # An eight-byte TripleDES key repeats its single DES key. This is the
        # exact RFB compatibility operation, not a new encryption scheme.
        encryptor = Cipher(TripleDES(key), modes.ECB()).encryptor()
        return encryptor.update(challenge) + encryptor.finalize()
    except UnsupportedAlgorithm:
        raise _ProbeError('krfb_crypto_unavailable') from None


def _probe_rfb(address, password, *, connector=socket.create_connection, clock=time.monotonic):
    """Read at most one raw pixel on fixed port 5900, with one total deadline."""
    result = {'status':'blocked', 'code':None, 'password_authenticated':False,
              'server_init_verified':False, 'pixel_update_verified':False}
    if not isinstance(password, bytes) or not 0 < len(password) <= 256:
        return dict(result, code='krfb_password_unavailable')
    connection = None
    try:
        destination = ipaddress.ip_address(address)
        if destination.is_multicast or destination.is_unspecified:
            raise ValueError
    except (ValueError, TypeError):
        return dict(result, code='krfb_target_unverified')
    deadline = clock() + 8

    def remaining():
        value = deadline - clock()
        if value <= 0:
            raise _ProbeError('krfb_probe_timeout')
        return min(value, 8)

    def receive(size):
        if not 0 <= size <= 4096:
            raise _ProbeError('krfb_protocol_unverified')
        data = bytearray()
        while len(data) < size:
            connection.settimeout(remaining())
            block = connection.recv(size-len(data))
            if not block:
                raise _ProbeError('krfb_protocol_unverified')
            data.extend(block)
        return bytes(data)

    def send(data):
        connection.settimeout(remaining())
        connection.sendall(data)

    try:
        connection = connector((str(destination), 5900), timeout=remaining())
        if receive(12) != b'RFB 003.008\n':
            raise _ProbeError('krfb_protocol_unverified')
        send(b'RFB 003.008\n')
        count = receive(1)[0]
        if not 0 < count <= 16:
            raise _ProbeError('krfb_authentication_unverified')
        types = receive(count)
        if 1 in types or 2 not in types:
            raise _ProbeError('krfb_authentication_unverified')
        send(b'\x02')
        send(_vnc_response(password, receive(16)))
        if struct.unpack('>I', receive(4))[0] != 0:
            # Never retain a server-supplied failure reason or retry passwords.
            raise _ProbeError('krfb_authentication_failed')
        result['password_authenticated'] = True
        send(b'\x01')  # shared desktop; never evict existing human clients
        width, height = struct.unpack('>HH', receive(4))
        receive(16)  # native format; request our bounded explicit format below
        name_size = struct.unpack('>I', receive(4))[0]
        if not (1 <= width <= 16384 and 1 <= height <= 16384 and name_size <= 4096):
            raise _ProbeError('krfb_protocol_unverified')
        receive(name_size)  # private desktop name is immediately discarded
        result['server_init_verified'] = True
        pixel_format = struct.pack('>BBBBHHHBBBxxx', 32, 24, 0, 1, 255, 255, 255, 16, 8, 0)
        send(b'\0\0\0\0' + pixel_format)
        send(struct.pack('>BBHi', 2, 0, 1, 0))  # Raw only
        send(struct.pack('>BBHHHH', 3, 0, 0, 0, 1, 1))
        if receive(4) != b'\0\0\0\x01':
            raise _ProbeError('krfb_framebuffer_unverified')
        if struct.unpack('>HHHHi', receive(12)) != (0, 0, 1, 1, 0):
            raise _ProbeError('krfb_framebuffer_unverified')
        receive(4)  # discard exactly one pixel, never expose/store its bytes
        result.update(status='ok', pixel_update_verified=True, width=width, height=height)
    except _ProbeError as exc:
        result['code'] = str(exc)
    except TimeoutError:
        result['code'] = ('krfb_network_policy_or_transport_blocked' if connection is None
                          else 'krfb_probe_timeout')
    except OSError:
        result['code'] = 'krfb_network_policy_or_transport_blocked'
    except Exception:
        result['code'] = 'krfb_probe_unverified'
    finally:
        if connection is not None:
            try:
                connection.close()
            except OSError:
                pass
    return result
