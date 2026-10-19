"""Fixed read-only ALT authentication snapshot. Never returns account contents."""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import uuid

LIMIT = 2*1024*1024
PAM = {'system-auth': ('system-auth-local', 'system-auth-sss'),
       'system-auth-use_first_pass': ('system-auth-use_first_pass-local', 'system-auth-use_first_pass-sss'),
       'system-policy': ('system-policy-local', 'system-policy-remote')}
AUTH_FILES = ('/etc/nsswitch.conf', '/etc/samba/smb.conf', '/etc/sssd/sssd.conf',
              '/etc/krb5.conf', '/etc/krb5.keytab', '/var/lib/samba/private/secrets.tdb')
TOOLS = ('/usr/sbin/system-auth', '/usr/sbin/control', '/etc/control.d/functions',
         '/etc/control.d/facilities/system-auth', '/bin/alterator-datetime-functions',
         '/bin/shell-config', '/bin/shell-ini-config', '/bin/shell-quote', '/bin/shell-error',
         '/usr/sbin/service', '/usr/sbin/chkconfig', '/bin/systemctl', '/usr/bin/rpm',
         '/usr/bin/sudo', '/bin/hostname', '/usr/bin/timedatectl')


def collect(request, *, root=Path('/'), owner=0):
    root = Path(root)
    account_owners = {}
    if (set(request) != {'schema_version', 'uuid', 'hostname', 'domain', 'workgroup'}
            or type(request['schema_version']) is not int or request['schema_version'] != 1
            or str(uuid.UUID(request['uuid'])) != request['uuid']
            or not re.fullmatch('[a-z][a-z0-9-]{0,14}', request['hostname'])
            or not re.fullmatch('[a-z0-9]+(?:[.-][a-z0-9]+)*', request['domain'])
            or not re.fullmatch('[A-Z0-9]{1,15}', request['workgroup'])):
        raise ValueError('Invalid fixed observation request')

    def safe(path, *, optional=False):
        # ALT usrmerge aliases are the only permitted tool-path aliases.
        relative = path.lstrip('/')
        first = relative.split('/')[0]
        alias = root/first
        if first in ('bin', 'sbin', 'lib', 'lib64') and alias.is_symlink():
            if os.readlink(alias) != 'usr/'+first or alias.lstat().st_uid != owner:
                raise ValueError('Unsafe tool alias')
            relative = 'usr/'+relative
        result = root/relative
        info = root.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != owner or info.st_mode & 0o022:
            raise ValueError('Unsafe observation root')
        current = root
        for part in Path(relative).parts[:-1]:
            current /= part
            if not current.exists() and not current.is_symlink() and optional:
                return result
            info = current.lstat()
            expected_owner = account_owners.get('/'+str(current.relative_to(root)), owner)
            if (not stat.S_ISDIR(info.st_mode) or info.st_uid not in (owner, expected_owner)
                    or info.st_mode & 0o022):
                raise ValueError('Unsafe observation ancestor')
        return result

    def read(path, *, optional=False, link=False):
        actual = safe(path, optional=optional)
        try:
            before = actual.lstat()
        except FileNotFoundError:
            if optional: return {'present': False}, None
            raise ValueError('Required observation file absent') from None
        expected_owner = account_owners.get(str(Path(path).parent), owner)
        if before.st_uid not in (owner, expected_owner) or (not stat.S_ISLNK(before.st_mode) and before.st_mode & 0o022):
            raise ValueError('Unsafe observation ownership or mode')
        meta = {'present': True, 'uid': before.st_uid, 'gid': before.st_gid,
                'mode': stat.S_IMODE(before.st_mode)}
        if stat.S_ISLNK(before.st_mode):
            if not link: raise ValueError('Unexpected observation link')
            target = os.readlink(actual)
            if target not in PAM[Path(path).name]: raise ValueError('Unsupported PAM link')
            return dict(meta, kind='symlink', target=target), None
        if not stat.S_ISREG(before.st_mode) or before.st_size > LIMIT:
            raise ValueError('Unsafe observation file')
        fd = os.open(actual, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            info = os.fstat(fd)
            data = os.read(fd, LIMIT+1)
            after = actual.lstat()
            signature = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
            if signature(before) != signature(info) or signature(info) != signature(after) or len(data) != info.st_size:
                raise ValueError('Observation changed while reading')
        finally:
            os.close(fd)
        return dict(meta, kind='file', size=len(data), sha256=hashlib.sha256(data).hexdigest()), data

    tools = {path: read(path)[0] for path in TOOLS}
    files = {path: read(path, optional=True)[0] for path in AUTH_FILES}
    for name, templates in PAM.items():
        path = '/etc/pam.d/'+name
        files[path] = read(path, link=True)[0]
        for template in templates:
            files['/etc/pam.d/'+template] = read('/etc/pam.d/'+template)[0]

    def run(path, *args, allowed=(0,)):
        result = subprocess.run([str(safe(path)), *args], capture_output=True, text=True,
            timeout=15, env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'})
        if (result.returncode not in allowed or len(result.stdout.encode()) > 32768
                or len(result.stderr.encode()) > 32768):
            raise ValueError('Native read-only observation failed')
        return result

    # These kernel pseudo-files have a fixed canonical location; no caller paths.
    dmi = root/'sys/class/dmi/id'
    if dmi.is_symlink():
        if os.readlink(dmi) != '../../devices/virtual/dmi/id': raise ValueError('Unsafe DMI path')
        dmi = root/'sys/devices/virtual/dmi/id'
    machine_uuid = (dmi/'product_uuid').read_text().strip().lower()
    boot = (root/'proc/sys/kernel/random/boot_id').read_text().strip().lower()
    if str(uuid.UUID(boot)) != boot or machine_uuid != request['uuid']:
        raise ValueError('Machine identity differs')
    hostname = run('/bin/hostname', '-s').stdout.strip().lower()
    if hostname != request['hostname']: raise ValueError('Machine hostname differs')
    status = run('/usr/sbin/system-auth', 'status').stdout.split()
    if status == ['local']:
        scheme, domain = 'local', ''
    elif status == ['ad', request['domain'].upper(), hostname.upper(), request['workgroup']]:
        scheme, domain = 'ad', request['domain']
    else:
        raise ValueError('Unsupported authentication scheme')
    services = {}
    for name in ('sssd', 'winbind'):
        output = run('/bin/systemctl', 'show', name+'.service',
            '--property=LoadState,ActiveState,UnitFileState,FragmentPath,DropInPaths').stdout
        pairs = [line.split('=', 1) for line in output.splitlines()]
        if any(len(pair) != 2 for pair in pairs) or len(dict(pairs)) != len(pairs):
            raise ValueError('Invalid service observation')
        values = dict(pairs)
        if set(values) != {'LoadState', 'ActiveState', 'UnitFileState', 'FragmentPath', 'DropInPaths'}:
            raise ValueError('Incomplete service observation')
        fragment = values['FragmentPath'] or None
        services[name] = {'load_state': values['LoadState'], 'active_state': values['ActiveState'],
            'unit_file_state': values['UnitFileState'], 'fragment': read(fragment)[0] if fragment else None,
            'drop_ins': values['DropInPaths'].split()}
        # Native disable_service can also touch sockets, timers and SysV hooks.
        for suffix in ('service', 'socket', 'timer'):
            path = '/lib/systemd/system/'+name+'.'+suffix
            # ALT /lib is an usrmerge alias too; handle only the exact fixed alias.
            if (root/'lib').is_symlink():
                if os.readlink(root/'lib') != 'usr/lib': raise ValueError('Unsafe library alias')
                path = '/usr'+path
            files[path] = read(path, optional=True)[0]
        files['/etc/rc.d/init.d/'+name] = read('/etc/rc.d/init.d/'+name, optional=True)[0]
    goa = run('/usr/bin/rpm', '-q', 'gnome-online-accounts', '--qf', '%{NAME}\n', allowed=(0, 1))
    if goa.returncode == 1 and goa.stdout.strip(): raise ValueError('Ambiguous GOA absence')
    meta, data = read('/etc/passwd')
    accounts = {'/etc/passwd': meta}
    all_entries = [line.split(':') for line in data.decode().splitlines()]
    if (len(all_entries) > 4096 or any(len(entry) != 7 or not entry[2].isdigit() or not entry[3].isdigit()
            or not re.fullmatch('[a-zA-Z0-9_][a-zA-Z0-9_.-]{0,63}', entry[0]) for entry in all_entries)
            or len({entry[0] for entry in all_entries}) != len(all_entries)):
        raise ValueError('Local account database is ambiguous')
    entries = [entry for entry in all_entries if entry[0] == 'ansible']
    if (len(entries) != 1 or len(entries[0]) != 7 or not entries[0][2].isdigit()
            or not entries[0][3].isdigit() or min(int(entries[0][2]), int(entries[0][3])) <= 0):
        raise ValueError('Managed administrator is missing or ambiguous')
    for entry in all_entries:
        account_owners['/etc/tcb/'+entry[0]] = int(entry[2])
    paths = ['/etc/group', '/etc/shadow', '/etc/gshadow']
    tcb = safe('/etc/tcb', optional=True)
    if tcb.exists() or tcb.is_symlink():
        info = tcb.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != owner or info.st_mode & 0o022:
            raise ValueError('Unsafe TCB root')
        children = list(tcb.iterdir())
        if len(children) > 4096: raise ValueError('TCB account limit exceeded')
        for child in children:
            key = '/etc/tcb/'+child.name
            if key not in account_owners: raise ValueError('Unrecognized TCB account')
            paths.append(key+'/shadow')
    for path in sorted(paths):
        accounts[path] = read(path, optional=path != '/etc/group')[0]
    # Production collect is entered through a fresh pinned ansible SSH session
    # and sudo -n python. ALT deliberately need not put root in sudoers.
    sudo = root != Path('/') or (os.geteuid() == 0 and os.environ.get('SUDO_USER') == 'ansible')
    if not sudo: raise ValueError('Managed administrator sudo context missing')
    return {'schema_version': 1, 'uuid': machine_uuid, 'hostname': hostname, 'boot_id': boot,
        'auth_scheme': scheme, 'domain': domain, 'tools': tools, 'files': files, 'services': services,
        'goa': {'installed': goa.returncode == 0},
        'clock_synchronized': run('/usr/bin/timedatectl', 'show', '-p', 'NTPSynchronized', '--value').stdout.strip() == 'yes',
        'local_admin': {'login': 'ansible', 'uid': int(entries[0][2]), 'gid': int(entries[0][3]), 'sudo': sudo},
        'local_accounts_sha256': hashlib.sha256(json.dumps(accounts, sort_keys=True, separators=(',', ':')).encode()).hexdigest()}


if __name__ == '__main__':
    import sys
    try:
        raw = sys.stdin.buffer.read(4097)
        if len(raw) > 4096: raise ValueError
        print(json.dumps(collect(json.loads(raw))))
    except Exception:
        sys.exit(4)
