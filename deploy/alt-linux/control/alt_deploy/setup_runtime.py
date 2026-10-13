"""Fixed read-only workstation probe and controller component prerequisites."""
from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import shlex
from pathlib import Path

from .ad_directory import DOMAIN, fail, normalize_login
from .ad_transport import bounded_run
from .configure import KRFB_NETWORK_CONFIRMATION_VARIABLE
from .setup_plans import digest
from .vault import VaultHealthChecker

# The operator supplies no script, shell fragment, or command selection.
PROBE_SCRIPT = r'''
import json, os, pathlib, re, subprocess, sys, uuid
login, upn = sys.argv[1:3]
dc = sys.argv[3] if len(sys.argv) == 4 else ''
if dc and not re.fullmatch(r'[a-zA-Z0-9.-]+', dc):
    raise RuntimeError('directory controller name invalid')
server = ['-S', dc] if dc else []
def read(args):
    result = subprocess.run(args, capture_output=True, text=True, timeout=10,
                            env=dict(os.environ, LC_ALL='C'))
    if len(result.stdout.encode('utf-8')) > 262144 or len(result.stderr.encode('utf-8')) > 262144:
        raise RuntimeError('probe output exceeds limit')
    return result.returncode, result.stdout.strip()
auth_rc, auth = read(['system-auth', 'status'])
if auth_rc != 0:
    raise RuntimeError('authentication scheme unavailable')
parts = auth.lower().split()
if not parts or parts[0] not in ('ad', 'local', 'local-users', 'ldap', 'krb5'):
    raise RuntimeError('unknown authentication scheme')
if parts[0] not in ('ad', 'local', 'local-users'):
    raise RuntimeError('incompatible authentication scheme')
domain = parts[1] if parts[0] == 'ad' and len(parts) > 1 else ''
hostname = read(['hostname', '-s'])[1].lower()
if not re.fullmatch(r'[a-z][a-z0-9]*(?:-[a-z0-9]+)*', hostname) or len(hostname) > 63:
    raise RuntimeError('machine hostname invalid')
trust_rc, _ = read(['net', *server, 'ads', 'testjoin'])
computer_identity = None
if trust_rc == 0:
    # Samba's status command has a fixed attribute list which omits GUID/DN.
    # Request exactly the attributes needed for immutable identity checks.
    status_rc, status = read(['net', '-P', *server, 'ads', 'search',
        '(&(objectClass=computer)(sAMAccountName=' + hostname + '$))',
        'objectGUID', 'objectSid', 'sAMAccountName', 'distinguishedName', 'dNSHostName'])
    if status_rc != 0:
        raise RuntimeError('machine account identity unavailable')
    if not status.splitlines() or status.splitlines()[0] != 'Got 1 replies':
        raise RuntimeError('machine account identity ambiguous')
    values = {}
    names = {'objectguid', 'objectsid', 'samaccountname', 'distinguishedname', 'dnshostname'}
    for line in status.splitlines():
        key, sep, value = line.partition(':')
        key = key.strip().lower()
        if sep and key in names:
            if key in values:
                raise RuntimeError('machine account identity ambiguous')
            values[key] = value.strip()
    if set(values) != names or not re.fullmatch(r'S-1-[0-9]+(?:-[0-9]+)+', values['objectsid']):
        raise RuntimeError('machine account identity invalid')
    computer_identity = dict(object_guid=str(uuid.UUID(values['objectguid'])), object_sid=values['objectsid'],
        sam_account_name=values['samaccountname'].lower(), dn=values['distinguishedname'],
        dns_hostname=values['dnshostname'].lower())
sssd_rc, sssd = read(['systemctl', 'is-active', 'sssd'])
user_rc, passwd = read(['getent', 'passwd', upn])
if user_rc not in (0, 2):
    raise RuntimeError('user lookup unavailable')
fields = passwd.split(':') if user_rc == 0 else []
if fields and (len(fields) != 7 or fields[0].lower() not in (login, upn)):
    raise RuntimeError('user lookup identity differs')
local_names = [line.split(':', 1)[0].lower() for line in pathlib.Path('/etc/passwd').read_text().splitlines()]
result = dict(uuid=pathlib.Path('/sys/class/dmi/id/product_uuid').read_text().strip().lower(),
              hostname=hostname, domain=domain,
              trust=trust_rc == 0, sssd=sssd_rc == 0 and sssd == 'active',
              user_lookup=user_rc == 0, local_duplicate=login in local_names or upn in local_names,
              home_exists=bool(fields and os.path.isdir(fields[5])), computer_identity=computer_identity)
print(json.dumps(result))
'''

READONLY_TDB_KEYS_SCRIPT = r'''
import ctypes, fcntl, os, stat

class TdbData(ctypes.Structure):
    _fields_ = [('dptr', ctypes.c_void_p), ('dsize', ctypes.c_size_t)]

class ReadLock(ctypes.Structure):
    _fields_ = [('l_type', ctypes.c_short), ('l_whence', ctypes.c_short),
                ('l_start', ctypes.c_longlong), ('l_len', ctypes.c_longlong), ('l_pid', ctypes.c_int)]

def readonly_tdb_keys(path):
    # Samba 4.21 lib/tdb/include/tdb.h: key iteration returns malloc-owned keys.
    # NOMMAP avoids mapping value pages; O_RDONLY forbids all database writes.
    lib = ctypes.CDLL('libtdb.so.1')
    lib.tdb_open.argtypes = [ctypes.c_char_p, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_uint]
    lib.tdb_open.restype = ctypes.c_void_p
    lib.tdb_firstkey.argtypes = [ctypes.c_void_p]
    lib.tdb_firstkey.restype = TdbData
    lib.tdb_nextkey.argtypes = [ctypes.c_void_p, TdbData]
    lib.tdb_nextkey.restype = TdbData
    lib.tdb_error.argtypes = [ctypes.c_void_p]
    lib.tdb_error.restype = ctypes.c_int
    lib.tdb_close.argtypes = [ctypes.c_void_p]
    lib.tdb_close.restype = ctypes.c_int
    lib.tdb_fd.argtypes = [ctypes.c_void_p]
    lib.tdb_fd.restype = ctypes.c_int
    libc = ctypes.CDLL(None)
    libc.free.argtypes = [ctypes.c_void_p]
    libc.free.restype = None
    # libtdb rejects lockall on O_RDONLY contexts. A Linux OFD read lock
    # conflicts with Samba's POSIX writers and survives its per-key unlocks.
    guard = None
    handle = None
    key = TdbData()
    try:
        guard = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        before = os.fstat(guard)
        if not stat.S_ISREG(before.st_mode):
            raise RuntimeError('credential database is not a regular file')
        fcntl.fcntl(guard, fcntl.F_OFD_SETLK, bytes(ReadLock(fcntl.F_RDLCK, os.SEEK_SET, 0, 0, 0)))
        # TDB1 fixed header (tdb_private.h). Reject mutex/unknown features:
        # mutex-only writers do not honor the POSIX/OFD read lock.
        header = os.pread(guard, 68, 0)
        if (len(header) != 68 or header[:9] != b'TDB file\n' or
                not any(int.from_bytes(header[32:36], endian) == 0x2601196d for endian in ('little', 'big')) or
                any(header[60:68])):
            raise RuntimeError('credential database format is not supported for safe key reads')
        handle = lib.tdb_open(os.fsencode(path), 0, 8, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, 0)
        if not handle:
            raise RuntimeError('credential database cannot be read safely')
        opened = os.fstat(lib.tdb_fd(handle))
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise RuntimeError('credential database was replaced')
        result = []
        key = lib.tdb_firstkey(handle)
        while key.dptr:
            if not 0 < key.dsize <= 65536 or len(result) >= 1024:
                raise RuntimeError('credential database key bounds exceeded')
            raw = ctypes.string_at(key.dptr, key.dsize)
            result.append(raw.removesuffix(b'\0').decode('ascii'))
            following = lib.tdb_nextkey(handle, key)
            libc.free(key.dptr)
            key = following
        if lib.tdb_error(handle) != 0:
            raise RuntimeError('credential database iteration failed')
        after = os.stat(path, follow_symlinks=False)
        if (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) != (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns):
            raise RuntimeError('credential database changed')
        return result
    except OSError as exc:
        raise RuntimeError('credential database read lock unavailable') from exc
    finally:
        if key.dptr:
            libc.free(key.dptr)
        closed = lib.tdb_close(handle) if handle else 0
        if guard is not None:
            os.close(guard)
        if closed != 0:
            raise RuntimeError('credential database cleanup failed')
'''

PREJOIN_PROBE_SCRIPT = READONLY_TDB_KEYS_SCRIPT + r'''
import json, os, pathlib, re, socket, stat, subprocess, sys
expected_uuid, expected_hostname = sys.argv[1:3]
actual_uuid = pathlib.Path('/sys/class/dmi/id/product_uuid').read_text().strip().lower()
actual_hostname = socket.gethostname().split('.')[0].lower()
if actual_uuid != expected_uuid or actual_hostname != expected_hostname or os.geteuid() != 0:
    raise RuntimeError('prejoin identity differs')

def read(args):
    result = subprocess.run(args, capture_output=True, text=True, timeout=5,
                            env=dict(os.environ, LC_ALL='C'))
    if len(result.stdout.encode()) > 262144 or len(result.stderr.encode()) > 262144:
        raise RuntimeError('prejoin output exceeds limit')
    return result

private = read(['testparm', '-s', '--parameter-name=private dir'])
credentials_absent = private.returncode == 0 and private.stdout.strip() == '/var/lib/samba/private'
for path in ('/etc/krb5.keytab', '/var/lib/samba/private/secrets.ldb', '/var/lib/samba/secrets.tdb'):
    p = pathlib.Path(path)
    if p.exists() or p.is_symlink():
        credentials_absent = False
tdb = pathlib.Path('/var/lib/samba/private/secrets.tdb')
if tdb.is_symlink():
    credentials_absent = False
elif tdb.exists():
    info = tdb.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0:
        credentials_absent = False
    else:
        # Read only key names through O_RDONLY firstkey/nextkey, never values.
        keys = readonly_tdb_keys(tdb)
        credentials_absent = credentials_absent and all(
            re.fullmatch(r'SECRETS/SID/[A-Za-z0-9_.-]+', key) for key in keys)
processes = read(['ps', '-eo', 'comm,args'])
process_lines = processes.stdout.splitlines()
busy_names = {'apt-get', 'http', 'https', 'rpm', 'system-auth', 'net', 'ansible', 'ansible-playboo', 'ansible-playbook'}
busy = False
for line in process_lines[1:]:
    fields = line.split(maxsplit=1)
    if fields and (fields[0] in busy_names or (len(fields) == 2 and re.search(
            r'(?:^|\s)/[^ ]*/AnsiballZ_[^ ]+\.py(?:\s|$)', fields[1]))):
        busy = True
print(json.dumps(dict(uuid=actual_uuid, hostname=actual_hostname,
    credentials_absent=bool(credentials_absent), processes_absent=processes.returncode == 0 and bool(process_lines)
    and process_lines[0].split() == ['COMMAND', 'COMMAND'] and not busy)))
'''


def source_fingerprint(project, control):
    """Bind published role assets and source without reading local Vault secrets."""
    hashes = {}
    for path in sorted(project.rglob('*')):
        relative = path.relative_to(project).as_posix()
        if relative == 'group_vars/vault.yml' or '__pycache__' in path.parts or path.suffix in ('.pyc', '.pyo'):
            continue
        included = (relative.startswith(('roles/', 'callback_plugins/', 'filter_plugins/', 'files/government_ca/'))
                    or path.suffix in ('.yml', '.yaml', '.cfg'))
        if not included:
            continue
        if path.is_symlink():
            raise fail('setup_source_unsafe', 'Controller Ansible source is unsafe')
        if path.is_dir():
            continue
        if not path.is_file() or path.stat().st_size > 1048576:
            raise fail('setup_source_unsafe', 'Controller Ansible source is unsafe')
        hashes[relative] = hashlib.sha256(path.read_bytes()).hexdigest()
    for path in sorted(control.glob('*.py')):
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 1048576:
            raise fail('setup_source_unsafe', 'Controller Python source is unsafe')
        hashes['control/' + path.name] = hashlib.sha256(path.read_bytes()).hexdigest()
    return digest(hashes)


class SetupRuntime:
    def __init__(self, settings, *, runner=None):
        self.settings = settings
        self.runner = runner or bounded_run

    def probe_prejoin(self, machine, config_id):
        """Read-only process and credential gate for a new pre-join plan."""
        import re
        import subprocess
        if not re.fullmatch('[0-9a-f]{32}', config_id):
            raise fail('setup_previous_run_unresolved', 'Previous configuration ID is invalid')
        try:
            address = str(ipaddress.ip_address(machine.ip))
            if not re.fullmatch('[0-9a-f-]{36}', machine.uuid) or not re.fullmatch('[a-z][a-z0-9-]{0,62}', machine.hostname):
                raise ValueError
            workers = subprocess.run(['ps', '-eo', 'args'], capture_output=True, text=True, timeout=5)
            marker = str(self.settings.state_root/'configure-runs'/config_id) + '/'
            if workers.returncode or len(workers.stdout.encode()) > 1048576 or marker in workers.stdout:
                raise ValueError
            command = ['/usr/bin/ssh', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes',
                '-o', 'ProxyCommand=none', '-o', 'IdentitiesOnly=yes', '-o', 'ConnectTimeout=10',
                '-o', 'UserKnownHostsFile=' + str(self.settings.known_hosts_file), '-i', str(self.settings.private_key_file),
                'ansible@' + address, 'sudo -n /usr/bin/python3 -I -B -c ' + shlex.quote(PREJOIN_PROBE_SCRIPT) +
                ' ' + shlex.quote(machine.uuid) + ' ' + shlex.quote(machine.hostname)]
            rc, stdout, _ = self.runner(command, environment=dict(os.environ), timeout=30)
            if rc:
                raise ValueError
            result = json.loads(stdout)
            if (set(result) != {'uuid', 'hostname', 'credentials_absent', 'processes_absent'} or
                    any(type(result[key]) is not bool for key in ('credentials_absent', 'processes_absent'))):
                raise ValueError
            return result
        except Exception as exc:
            raise fail('setup_previous_run_unresolved', 'Pre-join process and credential absence could not be verified') from exc

    def probe(self, machine, user):
        try:
            address = str(ipaddress.ip_address(machine.ip))
        except ValueError as exc:
            raise fail('machine_missing_ip', 'Machine has no valid registered IP') from exc
        login = normalize_login(user['login'])
        if user['upn'] != login + '@' + DOMAIN:
            raise fail('ad_user_identity_invalid', 'Selected domain user name differs')
        from urllib.parse import urlsplit
        from .ad_transport import DirectoryConfig
        dc = urlsplit(DirectoryConfig.load().uri).hostname
        command = ['/usr/bin/ssh', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes',
                   '-o', 'ProxyCommand=none', '-o', 'IdentitiesOnly=yes', '-o', 'ConnectTimeout=10',
                   '-o', 'UserKnownHostsFile=' + str(self.settings.known_hosts_file),
                   '-i', str(self.settings.private_key_file), 'ansible@' + address,
                   'sudo -n /usr/bin/python3 -I -B -c ' + shlex.quote(PROBE_SCRIPT) + ' ' + shlex.quote(login) + ' ' + shlex.quote(user['upn']) + ' ' + shlex.quote(dc)]
        rc, stdout, _ = self.runner(command, environment=dict(os.environ), timeout=90)
        if rc:
            raise fail('setup_probe_failed', 'Read-only SSH probe failed; check host key, SSH, sudo and domain tools')
        try:
            document = json.loads(stdout)
            if (not isinstance(document, dict) or set(document) != {'uuid', 'hostname', 'domain', 'trust', 'sssd', 'user_lookup', 'local_duplicate', 'home_exists', 'computer_identity'}
                    or any(type(document[key]) is not bool for key in ('trust', 'sssd', 'user_lookup', 'local_duplicate', 'home_exists'))
                    or any(not isinstance(document[key], str) for key in ('uuid', 'hostname', 'domain'))):
                raise ValueError
            return document
        except (ValueError, TypeError) as exc:
            raise fail('setup_probe_invalid', 'Read-only SSH probe returned invalid state') from exc

    def prerequisites(self, request):
        settings = self.settings
        fixed = settings.ansible_project_dir / 'playbooks/03-setup-controller-preflight.yml'
        required = [settings.ansible_playbook_path, settings.private_key_file, settings.known_hosts_file,
                    settings.ansible_project_dir / 'playbooks/03-configure-domain-workstation.yml', fixed,
                    settings.ansible_project_dir / 'ansible.cfg']
        if any(not path.is_file() or path.is_symlink() for path in required):
            raise fail('configure_not_configured', 'Required fixed controller playbooks, SSH files or Ansible runtime are missing')
        checker = VaultHealthChecker(settings)
        checker.check_ad_join()
        if request.remote_access_profile == 'krfb':
            checker.check_krfb()
            if os.environ.get(KRFB_NETWORK_CONFIRMATION_VARIABLE) != 'true':
                raise fail('remote_access_network_restriction_unconfirmed', 'Restricted TCP 5900 access must be explicitly confirmed')
        environment = dict(os.environ)
        environment['ANSIBLE_CONFIG'] = str(settings.ansible_project_dir / 'ansible.cfg')
        # No workstation inventory and no mutation role can be selected here.
        command = [str(settings.ansible_playbook_path), '-i', 'localhost,', '-c', 'local',
                   '-e', json.dumps({'software_profile': request.software_profile,
                                    'remote_access_profile': request.remote_access_profile}), str(fixed)]
        rc, _, _ = self.runner(command, environment=environment, timeout=120)
        if rc:
            raise fail('setup_component_prerequisites_failed', 'Controller component artifacts, catalog or required Vault values failed preflight')
        # Bind all published Ansible content to the plan; encrypted Vault and
        # local secret paths are excluded from the public source fingerprint.
        from .ad_transport import DirectoryConfig
        return {'ready': True, 'directory_uri': DirectoryConfig.load().uri,
                'source_sha256': source_fingerprint(settings.ansible_project_dir, Path(__file__).parent), 'ssh_files_present': True,
                'vault_ad_join_ready': True, 'component_preflight': True,
                'krfb_network_confirmed': request.remote_access_profile == 'krfb'}
