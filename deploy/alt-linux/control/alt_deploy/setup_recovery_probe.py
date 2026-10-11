"""Standalone fixed read-only root probe, transmitted by the controller.

No command, path or credential is accepted from workstationctl arguments.
Only hashes/metadata of fixed authentication files leave this process.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import uuid
from pathlib import Path
from threading import Thread

MAX_AUTH_BYTES = 2097152
MAX_TOOL_BYTES = 67108864
MAX_OUTPUT_BYTES = 16384
AUTH_FILES = {'/etc/samba/smb.conf': False, '/etc/sssd/sssd.conf': True,
              '/etc/krb5.conf': False, '/etc/krb5.keytab': True,
              '/var/lib/samba/private/secrets.tdb': True}
TOOLS = {'net': '/usr/bin/net', 'testparm': '/usr/bin/testparm', 'bwrap': '/usr/bin/bwrap',
         'klist': '/usr/bin/klist', 'ktutil': '/usr/bin/ktutil',
         'system-auth': '/usr/sbin/system-auth', 'sssd': '/usr/sbin/sssd'}
PARAMETERS = {'netbios_name': 'netbios name', 'workgroup': 'workgroup', 'realm': 'realm',
              'security': 'security', 'server_role': 'server role', 'private_dir': 'private dir',
              'kerberos_method': 'kerberos method'}
INCOMPATIBLE = frozenset({'net', 'samba-tool', 'system-auth', 'apt-get', 'apt', 'rpm', 'dnf'})


def _signature(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns,
            info.st_uid, info.st_gid, info.st_mode)


def _file(root, absolute, *, private=False, maximum=MAX_AUTH_BYTES, owner=0):
    path = root / absolute.lstrip('/')
    for ancestor in (path.parent, *path.parent.parents):
        if ancestor == root.parent and root != Path('/'):
            break
        try:
            info = ancestor.lstat()
        except FileNotFoundError:
            continue
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != owner or info.st_mode & 0o022:
            raise ValueError('Unsafe snapshot ancestry')
        if ancestor == root:
            break
    try:
        before = path.lstat()
    except FileNotFoundError:
        return {'present': False}
    mode = stat.S_IMODE(before.st_mode)
    if (not stat.S_ISREG(before.st_mode) or before.st_uid != owner or mode & 0o022
            or (private and mode != 0o600) or before.st_size > maximum):
        raise ValueError('Unsafe snapshot file')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as stream:
        opened = os.fstat(stream.fileno())
        if _signature(opened) != _signature(before):
            raise ValueError('Snapshot file changed')
        hashed = hashlib.sha256()
        count = 0
        while chunk := stream.read(min(65536, maximum + 1 - count)):
            count += len(chunk)
            if count > maximum:
                raise ValueError('Snapshot file exceeds limit')
            hashed.update(chunk)
        if _signature(os.fstat(stream.fileno())) != _signature(before):
            raise ValueError('Snapshot file changed')
    if _signature(path.lstat()) != _signature(before):
        raise ValueError('Snapshot file changed')
    return {'present': True, 'sha256': hashed.hexdigest(), 'size': count,
            'uid': before.st_uid, 'gid': before.st_gid, 'mode': mode}


def _read_command(argv):
    environment = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'}
    process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, env=environment, shell=False)
    captured = [b'', b'']
    excessive = []
    def read(index, pipe):
        captured[index] = pipe.read(MAX_OUTPUT_BYTES + 1)
        if len(captured[index]) > MAX_OUTPUT_BYTES:
            excessive.append(True)
            process.kill()
        pipe.close()
    readers = [Thread(target=read, args=(index, pipe), daemon=True)
               for index, pipe in enumerate((process.stdout, process.stderr))]
    for reader in readers:
        reader.start()
    try:
        process.wait(timeout=15)
    except subprocess.TimeoutExpired:
        process.kill(); process.wait()
        raise ValueError('Native read timed out') from None
    finally:
        for reader in readers:
            reader.join(timeout=2)
    if excessive or any(reader.is_alive() for reader in readers) or process.returncode:
        raise ValueError('Native read failed')
    return captured[0].decode('utf-8').strip()


def collect(*, root=Path('/'), runner=None, owner=0):
    # Alternate root/runner/owner exist only for isolated unit fixtures; the
    # standalone entrypoint below has no argument parser and always uses root.
    if os.geteuid() != owner or not root.is_absolute():
        raise ValueError('Root snapshot required')
    runner = runner or _read_command
    identifier = root / 'sys/class/dmi/id/product_uuid'
    with identifier.open('rb') as stream:
        value = stream.read(129)
    machine_uuid = value.decode('ascii').strip().lower()
    if len(value) > 128 or str(uuid.UUID(machine_uuid)) != machine_uuid or uuid.UUID(machine_uuid).int == 0:
        raise ValueError('Invalid workstation UUID')
    hostname = runner(['/usr/bin/hostname', '-s']).lower()
    if not re.fullmatch(r'(?:lin|alt|win|deb)-[a-z][0-9]?-(?:pc[1-9][0-9]*)', hostname):
        raise ValueError('Invalid workstation hostname')
    files = {path: _file(root, path, private=private, owner=owner) for path, private in AUTH_FILES.items()}
    tools = {}
    for name, path in TOOLS.items():
        metadata = _file(root, path, maximum=MAX_TOOL_BYTES, owner=owner)
        if not metadata['present']:
            if name != 'ktutil':
                raise ValueError('Required native tool missing')
            tools[name] = metadata
            continue
        package = runner(['/usr/bin/rpm', '-qf', path, '--qf', '%{NAME} %{VERSION}-%{RELEASE}\n'])
        if not re.fullmatch(r'[a-zA-Z0-9+_.-]{1,80} [a-zA-Z0-9+_.:~%-]{1,100}', package):
            raise ValueError('Invalid native package identity')
        tools[name] = dict(metadata, package=package)
    version = runner(['/usr/bin/net', '--version'])
    if not re.fullmatch(r'Version [0-9]+\.[0-9]+\.[0-9]+[a-zA-Z0-9+_.-]*', version):
        raise ValueError('Invalid Samba version')
    samba = {key: runner(['/usr/bin/testparm', '-s', '--parameter-name', parameter])
             for key, parameter in PARAMETERS.items()}
    if (any(not isinstance(value, str) or not value or len(value) > 4096
            or any(ord(char) < 32 or ord(char) == 127 for char in value) for value in samba.values())
            or runner(['/usr/bin/testparm', '-s', '--parameter-name', 'sync machine password script'])):
        raise ValueError('Unsupported effective Samba configuration')
    sync = runner(['/usr/bin/testparm', '-s', '--parameter-name', 'sync machine password to keytab'])
    samba['sync_keytab_sha256'] = hashlib.sha256(sync.encode('utf-8')).hexdigest()
    samba['password_hook_empty'] = True
    clock = runner(['/usr/bin/timedatectl', 'show', '-p', 'NTPSynchronized', '--value'])
    if clock not in ('yes', 'no'):
        raise ValueError('Clock synchronization unknown')
    incompatible = set()
    for index, directory in enumerate((root / 'proc').iterdir()):
        if index >= 16384:
            raise ValueError('Process enumeration exceeds limit')
        if not directory.name.isdigit():
            continue
        try:
            with (directory / 'comm').open('rb') as stream:
                name = stream.read(65).decode('utf-8', errors='replace').strip()
        except FileNotFoundError:
            continue
        if name in INCOMPATIBLE:
            incompatible.add(name)
    return {'schema_version': 1, 'uuid': machine_uuid, 'hostname': hostname, 'files': files,
            'tools': tools, 'samba_version': version.removeprefix('Version '), 'samba': samba,
            'keytab_present': files['/etc/krb5.keytab']['present'], 'clock_synchronized': clock == 'yes',
            'incompatible_processes': sorted(incompatible)}


if __name__ == '__main__':
    try:
        print(json.dumps(collect(), sort_keys=True))
    except Exception:
        print(json.dumps({'schema_version': 1, 'error_code': 'recovery_facts_failed'}))
        sys.exit(1)
