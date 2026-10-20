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
import uuid


DIRECT_POLICY = {'port':5900,'scope':'direct','authentication':'password_required'}
RFB_CODES = frozenset('krfb_'+code for code in ('authentication_failed','authentication_unverified',
    'crypto_unavailable','framebuffer_unverified','network_policy_or_transport_blocked',
    'password_unavailable','probe_timeout','probe_unverified','protocol_unverified','target_unverified'))
GUI_CODES = frozenset({'graphical_session_unavailable','graphical_session_ambiguous',
    'krfb_graphical_session_unverified','krfb_machine_unverified','krfb_user_identity_unverified',
    'krfb_configuration_unverified','krfb_listener_unverified','krfb_process_unverified',
    'krfb_session_observation_unverified'})


def _require_rfb(result):
    if (isinstance(result,dict) and set(result)=={'status','code','password_authenticated',
            'server_init_verified','pixel_update_verified','width','height'}
            and result['status']=='ok' and result['code'] is None
            and all(result[key] is True for key in
                    ('password_authenticated','server_init_verified','pixel_update_verified'))
            and all(type(result[key]) is int and 1<=result[key]<=16384 for key in ('width','height'))):
        return result
    code = result.get('code') if isinstance(result,dict) else None
    raise _ProbeError(code if isinstance(code,str) and code in RFB_CODES else 'krfb_probe_unverified')


def _canonical(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()


def _unique_object(pairs):
    value = {}
    for key,item in pairs:
        if key in value:raise ValueError
        value[key] = item
    return value


def _session_program():
    from .component_catalog import _regular
    program = "import sys,types,json\np=types.ModuleType('alt_deploy');p.__path__=[];sys.modules['alt_deploy']=p\n"
    for name in ('user_session','krfb_user_session'):
        source = Path(__file__).with_name(name+'.py')
        _regular(source)
        program += ("m=types.ModuleType('alt_deploy."+name+"');sys.modules[m.__name__]=m;exec(compile("
                    +repr(source.read_text(encoding='utf-8'))+",'<published-"+name+">','exec'),m.__dict__)\n")
    program += '''
def unique(pairs):
    result={}
    for key,value in pairs:
        if key in result:raise ValueError
        result[key]=value
    return result
try:
    raw=sys.stdin.read(8193)
    if len(raw.encode())>8192:raise ValueError
    value=m.observe_session(json.loads(raw,object_pairs_hook=unique))
    print(json.dumps({'schema_version':1,'status':'ok','observation':value}))
except Exception as error:
    code=str(error) if isinstance(error,m.KRFBSessionError) else ''
    if code not in '''+repr(tuple(sorted(GUI_CODES)))+''':code='krfb_session_observation_unverified'
    print(json.dumps({'schema_version':1,'status':'blocked','code':code}))
    raise SystemExit(4)
'''
    return program


def _session_read(settings, machine, user, runner):
    request = {'machine_uuid':machine.uuid,'hostname':machine.hostname,'login':user['login']}
    command = _admin_command(settings,machine)[:-1]+[
        'sudo -n /usr/bin/python3 -I -B -c '+shlex.quote(_session_program())]
    rc,raw,_ = runner(command,environment={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'},
                      input_text=json.dumps(request),timeout=90,max_bytes=65536)
    if not isinstance(raw,str) or len(raw.encode())>65536:raise ValueError
    document = json.loads(raw,object_pairs_hook=_unique_object)
    if (isinstance(document,dict) and set(document)=={'schema_version','status','code'} and rc==4
            and type(document['schema_version']) is int and document['schema_version']==1
            and document['status']=='blocked' and isinstance(document['code'],str) and document['code'] in GUI_CODES):
        raise _ProbeError(document['code'])
    if (rc or not isinstance(document,dict) or set(document)!={'schema_version','status','observation'}
            or type(document['schema_version']) is not int or document['schema_version']!=1
            or document['status']!='ok'):raise ValueError
    value = document['observation']
    if (not isinstance(value,dict) or set(value)!={'schema_version','machine_uuid','hostname','boot_id','login',
            'uid','gid','session_id','session_sha256','krfb_pid','krfb_start_ticks','listener_present',
            'connected_clients','configuration_safe','autostart_safe','configuration_sha256','autostart_sha256','snapshot_sha256'}
            or type(value['schema_version']) is not int or value['schema_version']!=1
            or any(value[key]!=request[key] for key in ('machine_uuid','hostname','login'))
            or not isinstance(value['boot_id'],str)
            or not re.fullmatch('[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}',value['boot_id'])
            or not isinstance(value['session_id'],str) or not re.fullmatch('[a-zA-Z0-9_-]{1,32}',value['session_id'])
            or any(type(value[key]) is not int or not 0<value[key]<2**32 for key in ('uid','gid'))
            or type(value['connected_clients']) is not int or not 0<=value['connected_clients']<=1024
            or any(type(value[key]) is not bool for key in ('listener_present','configuration_safe','autostart_safe'))):raise ValueError
    if ((value['krfb_pid'] is None)!=(value['krfb_start_ticks'] is None)
            or any(type(value[key]) is not int or value[key]<=0 for key in ('krfb_pid','krfb_start_ticks')
                   if value[key] is not None)
            or value['listener_present'] and value['krfb_pid'] is None):raise ValueError
    for key in ('session_sha256','snapshot_sha256','configuration_sha256','autostart_sha256'):
        if key in ('configuration_sha256','autostart_sha256') and value[key] is None:continue
        if not isinstance(value[key],str) or not re.fullmatch('[0-9a-f]{64}',value[key]):raise ValueError
    if value['snapshot_sha256']!=hashlib.sha256(_canonical(
            {key:item for key,item in value.items() if key!='snapshot_sha256'})).hexdigest():raise ValueError
    return value


def probe_krfb(settings, machine, user, policy, *, runner=None,expected_source=None,
               expected_ssh_binding=None,expected_boot_id=None,expected_session_sha256=None):
    """Prove one selected user's live direct service without sending input."""
    from .ad_transport import bounded_run
    from .ad_directory import fail,normalize_login,DOMAIN
    from .component_probe import ssh_binding
    from .setup_runtime import source_fingerprint
    from .component_catalog import _regular
    runner = runner or bounded_run
    try:
        login = normalize_login(user['login'])
        if (user['login']!=login or user['upn']!=login+'@'+DOMAIN
                or str(uuid.UUID(user['object_guid']))!=user['object_guid'] or not uuid.UUID(user['object_guid']).int
                or not re.fullmatch(r'S-1-[0-9]+(?:-[0-9]+){1,15}',user['object_sid'])):raise ValueError
        evidence = observe_vnc_policy(settings,machine,policy,runner=runner,expected_source=expected_source,
            expected_ssh_binding=expected_ssh_binding,expected_boot_id=expected_boot_id)
        before = _session_read(settings,machine,user,runner)
        if (expected_boot_id is not None and before['boot_id']!=expected_boot_id
                or expected_session_sha256 is not None and before['session_sha256']!=expected_session_sha256):
            raise _ProbeError('vnc_policy_snapshot_changed')
        if before['boot_id']!=evidence['observation']['boot_id']:
            raise _ProbeError('vnc_policy_snapshot_changed')
        if not before['listener_present'] or before['krfb_pid'] is None:
            raise _ProbeError('krfb_listener_unverified')
        proof = _require_rfb(_probe_rfb(str(ipaddress.ip_address(machine.ip)),_protected_password(settings)))
        after = _session_read(settings,machine,user,runner)
        # Human clients may connect/disconnect while this read-only shared
        # connection runs. All identity/session/configuration evidence is fixed.
        stable = lambda value:{key:item for key,item in value.items() if key not in ('connected_clients','snapshot_sha256')}
        helper = settings.ansible_project_dir/'roles/remote_access_policy/templates/alt-vnc-access-policy.py.j2'
        _regular(helper)
        helper_source = helper.read_text(encoding='utf-8')
        if hashlib.sha256(helper_source.encode()).hexdigest()!=evidence['helper_sha256']:
            raise _ProbeError('vnc_policy_snapshot_changed')
        if (stable(before)!=stable(after)
                or _policy_read(settings,machine,evidence['observation']['source_sha256'],
                                helper_source,runner)!=evidence['observation']
                or source_fingerprint(settings.ansible_project_dir,Path(__file__).parent)!=evidence['observation']['source_sha256']
                or ssh_binding(settings,machine,runner=runner)!=evidence['ssh_binding']):
            raise _ProbeError('vnc_policy_snapshot_changed')
        checks = {'policy_prepared':evidence['observation']['ready'],
                  'configuration_safe':after['configuration_safe'],'autostart_safe':after['autostart_safe'],
                  'selected_user_graphical_session':True,'selected_user_listener':True,
                  'password_authenticated':True,'server_init_verified':True,'pixel_update_verified':True}
        identity = {key:user[key] for key in ('login','upn','object_guid','object_sid')}
        return {'schema_version':1,'machine_uuid':machine.uuid,'boot_id':before['boot_id'],
            'source_sha256':evidence['observation']['source_sha256'],'policy_sha256':evidence['observation']['policy_sha256'],
            'ssh_binding':evidence['ssh_binding'],'session_sha256':before['session_sha256'],
            'selected_user_sha256':hashlib.sha256(_canonical(identity)).hexdigest(),
            'checks':checks,'ready':all(checks.values()),'width':proof['width'],'height':proof['height']}
    except Exception as error:
        allowed = GUI_CODES | RFB_CODES | {'vnc_policy_snapshot_changed','vnc_policy_external_blocker'}
        code = str(error) if isinstance(error,_ProbeError) else getattr(error,'code','')
        if code not in allowed:code = 'krfb_probe_unverified'
        raise fail(code,'Selected employee direct VNC evidence cannot be verified') from None


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


def observe_vnc_policy(settings, machine, policy, *, runner=None,expected_source=None,
                       expected_ssh_binding=None,expected_boot_id=None):
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
        if (expected_source is not None and source!=expected_source
                or expected_ssh_binding is not None and binding!=expected_ssh_binding):
            raise _ProbeError('vnc_policy_snapshot_changed')
        before = _policy_read(settings,machine,source,helper,runner)
        if expected_boot_id is not None and before['boot_id']!=expected_boot_id:
            raise _ProbeError('vnc_policy_snapshot_changed')
        if not before['legacy']['external_policy_clear']:
            raise _ProbeError('vnc_policy_external_blocker')
        authenticated = False
        if before['listener_present']:
            password = _protected_password(settings)
            _require_rfb(_probe_rfb(str(ipaddress.ip_address(machine.ip)),password,
                       connector=lambda *a,**k:_SSHChannel(_admin_command(settings,machine),timeout=k['timeout'])))
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
        allowed = {'vnc_policy_external_blocker','vnc_policy_snapshot_changed'} | RFB_CODES
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
    from .target_transport import ssh_prefix
    return ssh_prefix(settings,machine)+['/usr/bin/python3 -I -B -c '+shlex.quote(_ADMIN_PROXY)]


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
    from .workflow_read_deadline import read_timeout
    deadline = clock() + read_timeout(8)

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
