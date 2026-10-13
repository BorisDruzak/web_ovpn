"""Fixed read-only target program. Receives validated declarations over stdin."""
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import ssl
import stat
import subprocess
import sys
import fcntl
import pwd
from urllib.parse import urlsplit


def run(argv):
    options = {}
    if argv[0] == 'apt-get':
        # ALT APT 0.5 may rebuild disk caches even during --simulate. Drop all
        # privileges for APT so the read-only collector cannot write system state.
        account = pwd.getpwnam('nobody')
        if account.pw_uid <= 0 or account.pw_gid <= 0:
            raise ValueError('unprivileged package probe unavailable')
        for value in ('/var/cache/apt', '/var/cache/apt/pkgcache.bin', '/var/cache/apt/srcpkgcache.bin'):
            target = Path(value)
            if target.exists() or target.is_symlink():
                info = target.lstat()
                if target.is_symlink() or info.st_uid != 0 or info.st_mode & 0o022:
                    raise ValueError('package cache is not protected')
        options = {'user': account.pw_uid, 'group': account.pw_gid, 'extra_groups': []}
    environment = dict(os.environ, LC_ALL='C')
    if argv[0] == 'apt-get':
        environment = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C', 'HOME': '/'}
    result = subprocess.run(argv, capture_output=True, text=True, timeout=30 if argv[0] == 'apt-get' else 10,
                            env=environment, **options)
    if len(result.stdout.encode()) > 262144 or len(result.stderr.encode()) > 262144:
        raise ValueError('probe limit')
    return result.returncode, result.stdout.strip()


def path(root, value):
    if not isinstance(value, str) or not value.startswith('/') or any(p == '..' for p in value.split('/')):
        raise ValueError('probe path')
    return root / value.lstrip('/')


def safe_file(target, *, uid=None, mode=None):
    if any(p.is_symlink() for p in (target, *target.parents)):
        return False
    try:
        info = target.stat()
        return (stat.S_ISREG(info.st_mode) and info.st_size <= 1048576
                and (uid is None or info.st_uid == uid)
                and (mode is None or stat.S_IMODE(info.st_mode) == mode))
    except FileNotFoundError:
        return False


def text(target):
    if not safe_file(target):
        raise ValueError('probe file unavailable')
    return target.read_text(encoding='utf-8')


def ini_value(target, groups, key):
    if not safe_file(target):
        return None
    section, value = [], None
    for line in text(target).splitlines():
        line = line.strip()
        if line.startswith('['):
            section = re.findall(r'\[([^\]]+)\]', line)
        else:
            name, sep, current = line.partition('=')
            if sep and section == groups and name == key:
                if value is not None:
                    raise ValueError('ambiguous probe configuration')
                value = current
    return value


def package(name, call):
    if not re.fullmatch('[A-Za-z0-9][A-Za-z0-9+_.-]{0,127}', name):
        raise ValueError('package identity')
    rc, output = call(['rpm', '-q', '--queryformat', '%{NAME}|%{VERSION}-%{RELEASE}|%{ARCH}|%{EPOCH}', name])
    if rc == 1:
        return None
    fields = output.split('|')
    if rc or len(fields) != 4 or fields[0] != name:
        raise ValueError('package probe unavailable')
    epoch = 0 if fields[3] in ('(none)', '(null)') else int(fields[3])
    return dict(name=fields[0], evr=fields[1], architecture=fields[2], epoch=epoch)


def active(service, call):
    rc, output = call(['systemctl', 'is-active', service])
    if rc not in (0, 3, 4):
        raise ValueError('service probe unavailable')
    return rc == 0 and output == 'active'


def package_health(root, recipes, call):
    """Read existing locks/database/dependencies; never update or acquire a write lock."""
    result = {'processes_absent': None, 'remote_execution_absent': None, 'locks_clear': None,
              'database_readable': None, 'dependencies_healthy': None,
              'source': {'status': 'unknown'}, 'simulation': {}}
    simulation_command = ['apt-get', '--simulate', '--no-download', '-o', 'Debug::NoLocking=true',
                          '-o', 'Dir::Cache::pkgcache=/var/cache/apt/pkgcache.bin',
                          '-o', 'Dir::Cache::srcpkgcache=/var/cache/apt/srcpkgcache.bin']
    try:
        rc, processes = call(['ps', '-eo', 'comm'])
        result['processes_absent'] = None if rc else not any(p.strip() in
            ('rpm', 'apt-get', 'apt', 'http', 'https', 'epm', 'eepm') for p in processes.splitlines()[1:])
        rc, processes = call(['ps', '-eo', 'pid,args'])
        if not rc:
            rows = [line.strip().split(None, 1) for line in processes.splitlines()[1:]]
            if all(len(row) == 2 and row[0].isdigit() for row in rows):
                result['remote_execution_absent'] = not any(int(pid) != os.getpid() and
                    (re.search(r'(?:^|/)AnsiballZ_[a-zA-Z0-9_]+\.py(?:\s|$)', args)
                     or re.search(r'(?:^|/)(ansible-playbook|system-auth|adcli)(?:\s|$)', args)) for pid, args in rows)
    except Exception:
        pass
    try:
        clear = True
        for name in ('/var/lib/rpm/.rpm.lock', '/var/lib/apt/lists/lock', '/var/cache/apt/archives/lock'):
            target = path(root, name)
            if not target.exists() and not target.is_symlink():
                continue
            if not safe_file(target):
                raise ValueError
            fd = os.open(target, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
            try:
                for lock in (fcntl.flock, fcntl.lockf):
                    try:
                        lock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
                        lock(fd, fcntl.LOCK_UN)
                    except BlockingIOError:
                        clear = False
            finally:
                os.close(fd)
        result['locks_clear'] = clear
    except Exception:
        pass
    try:
        rc, names = call(['rpm', '-qa', '--queryformat', '%{NAME}\n'])
        result['database_readable'] = (rc == 0 and bool(names) and
            all(re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9+_.-]{0,127}', name) for name in names.splitlines()))
        rc, _ = call(simulation_command+['check'])
        result['dependencies_healthy'] = True if rc == 0 else None
    except Exception:
        pass
    try:
        paths = [path(root, '/etc/apt/sources.list')]
        paths.extend(sorted(path(root, '/etc/apt/sources.list.d').glob('*.list')))
        enabled, fingerprints = 0, []
        for source in paths:
            if not source.exists() and not source.is_symlink():
                continue
            expected_owner = 0 if root == Path('/') else os.getuid()
            if not safe_file(source, uid=expected_owner) or source.stat().st_mode & 0o022:
                raise ValueError
            content = text(source)
            for line in content.splitlines():
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                fields = line.split()
                if len(fields) != 5 or fields[0] not in ('rpm', 'rpm-src') or fields[1] != '[p11]' or fields[4] != 'classic':
                    raise ValueError
                urls = [v for v in fields if v.startswith(('https://', 'http://'))]
                if len(urls) != 1:
                    raise ValueError
                uri = urlsplit(urls[0])
                if (uri.scheme != 'https' or uri.hostname != 'download.basealt.ru'
                        or uri.username or uri.password or uri.query or uri.fragment
                        or uri.path != '/pub/distributions/ALTLinux'
                        or not any(re.fullmatch(r'p11/branch/(x86_64|x86_64-i586|i586|noarch)', f) for f in fields)):
                    raise ValueError
                enabled += 1
            # Fingerprint validated active entries only, never comments/private URLs.
            fingerprints.extend(hashlib.sha256(' '.join(line.split()).encode()).hexdigest()
                for line in content.splitlines() if line.strip() and not line.strip().startswith('#'))
        if enabled:
            result['source'] = {'status': 'approved_p11', 'enabled_entries': enabled,
                                'sha256': hashlib.sha256(json.dumps(fingerprints).encode()).hexdigest()}
    except Exception:
        pass
    for recipe in recipes:
        artifact = recipe.get('artifact')
        if not artifact:
            continue
        simulation = {'status': 'unavailable', 'install': [], 'remove': []}
        if artifact['source'] == 'alt-repository':
            try:
                rc, output = call(simulation_command+['install', *artifact['packages']])
                if rc == 0:
                    installs, removals = [], []
                    for line in output.splitlines():
                        if line.startswith(('Inst ', 'Remv ')):
                            operation, name, *_ = line.split()
                            if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9+_.-]{0,127}', name):
                                raise ValueError
                            (installs if operation == 'Inst' else removals).append(name)
                    if len(installs)+len(removals) <= 256:
                        simulation = {'status': 'available', 'install': sorted(set(installs)), 'remove': sorted(set(removals))}
            except Exception:
                pass
        result['simulation'][recipe['id']] = simulation
    return result


def os_id(root):
    config = {}
    for line in text(path(root, '/etc/os-release')).splitlines():
        key, sep, value = line.partition('=')
        if sep:
            config[key] = value.strip('"')
    description = (config.get('NAME', '')+' '+config.get('PRETTY_NAME', '')).lower()
    if config.get('ID') == 'altlinux' and config.get('VERSION_ID', '').split('.')[0] == '11' and 'workstation k' in description:
        return 'alt-kworkstation-11'
    return 'unsupported'


def user_identity(root, query, call):
    rc, output = call(['getent', '-s', 'sss', 'passwd', query['upn']])
    entries = output.splitlines()
    if rc in (0, 2) and not entries:
        # Explicitly unresolved SSS identity is useful before first domain join.
        # It is never accepted by component apply or post-apply verification.
        return {'login': query['login'], 'uid': None, 'gid': None,
                'home_exists': False, 'home_safe': False}, '', query['upn']
    if rc or len(entries) != 1 or len(entries[0].split(':')) != 7:
        raise ValueError('user identity unavailable')
    name, _, uid, gid, _, home, _ = entries[0].split(':')
    uid, gid = int(uid), int(gid)
    if name.lower() not in (query['login'], query['upn']) or uid <= 0 or gid <= 0:
        raise ValueError('user identity mismatch')
    target = path(root, home)
    safe = (home.startswith('/home/') and '//' not in home and
            not any(p.is_symlink() for p in (target, *target.parents)))
    if target.exists():
        info = target.stat()
        safe = safe and stat.S_ISDIR(info.st_mode) and info.st_uid == uid and info.st_gid == gid
    return {'login': query['login'], 'uid': uid, 'gid': gid,
            'home_exists': target.is_dir(), 'home_safe': bool(safe)}, home, name


def desktop_ready(root, recipe, home, uid):
    skel, config = path(root, recipe['skel']), path(root, home+'/.config')
    skel_ready = all(ini_value(skel/'powerdevilrc', groups, key) == desired for groups, key, desired in recipe['skel_power'])
    for groups, key, desired in recipe['keyboard']:
        skel_ready = skel_ready and ini_value(skel/'kxkbrc', groups, key) == desired
        if (not safe_file(config/'kxkbrc', uid=uid)
                or ini_value(config/'kxkbrc', groups, key) != desired):
            return False
    for location, base in (('skel', skel), ('user', config)):
        for filename, group, key, desired in recipe['desktop']:
            target = base/filename
            if location == 'user' and not safe_file(target, uid=uid):
                return False
            current = ini_value(target, [group], key)
            if filename == 'mimeapps.list' and group == 'Added Associations':
                if current is None or not current.startswith(desired):
                    return False
            elif current != desired:
                return False
    for profile in ('AC', 'Battery', 'LowBattery'):
        for section, key, desired in recipe['power']:
            if ini_value(config/'powerdevilrc', [profile, section], key) != desired:
                return False
    return skel_ready


def certificates_ready(root, recipe, home, name, uid, call):
    entries = recipe['certificates']
    directory = path(root, '/usr/local/share/alt-government-ca')
    # Read the already extracted public system bundle; do not create a probe file.
    bundle = path(root, '/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem')
    if not bundle.is_file() or bundle.stat().st_size > 8*1048576:
        raise ValueError('system trust evidence unavailable')
    anchors = {hashlib.sha256(ssl.PEM_cert_to_DER_cert(pem)).hexdigest()
               for pem in re.findall(r'-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----', bundle.read_text(), re.S)}
    manager = path(root, '/opt/cprocsp/bin/amd64/certmgr')
    database = path(root, home+'/.pki/nssdb/cert9.db')
    if not safe_file(database, uid=uid):
        return False
    if any(p.is_symlink() or (p.exists() and p.stat().st_uid != uid)
           for p in (database.parent, database.parent.parent)):
        return False
    for entry in entries:
        certificate = directory/entry['filename']
        if not safe_file(certificate) or hashlib.sha256(certificate.read_bytes()).hexdigest() != entry['sha256']:
            return False
        fingerprint = hashlib.sha256(ssl.PEM_cert_to_DER_cert(text(certificate))).hexdigest()
        if fingerprint != entry['fingerprint_sha256']:
            return False
        rc, _ = call(['openssl', 'x509', '-in', str(certificate), '-checkend', '0', '-noout'])
        if rc:
            return False
        if entry['kind'] == 'root':
            if fingerprint not in anchors:
                return False
        elif path(root, '/etc/pki/ca-trust/source/anchors/'+entry['filename']).exists():
            return False
        if not entry['gost']:
            nickname = 'ALT Government CA '+entry['filename']
            with sqlite3.connect(database.as_uri()+'?mode=ro', uri=True) as db:
                records = db.execute('SELECT a11 FROM nssPublic WHERE a3 = ? AND a11 IS NOT NULL', (nickname.encode(),)).fetchall()
            if len(records) != 1 or hashlib.sha256(records[0][0]).hexdigest() != fingerprint:
                return False
            rc, listing = call(['runuser', '-u', name, '--', 'certutil', '-L', '-d', 'sql:'+str(database.parent)])
            match = re.search('^'+re.escape(nickname)+r'\s+(\S+)\s*$', listing, re.M)
            if rc or not match or match[1] != ('C,,' if entry['kind'] == 'root' else ',,'):
                return False
        if manager.exists():
            for prefix in ('m', 'u'):
                args = [str(manager), '-list', '-store', prefix+('Root' if entry['kind'] == 'root' else 'CA'),
                        '-thumbprint', entry['thumbprint_sha1']]
                if prefix == 'u':
                    args = ['runuser', '-u', name, '--', *args]
                rc, output = call(args)
                if rc or entry['thumbprint_sha1'] not in re.sub('[^0-9a-f]', '', output.lower()):
                    return False
    root_uid = 0 if root == Path('/') else os.getuid()
    for name, expected in recipe['installed_files'].items():
        target = path(root, name)
        if (not safe_file(target, uid=root_uid, mode=expected['mode'])
                or hashlib.sha256(target.read_bytes()).hexdigest() != expected['sha256']):
            return False
    return True


def inspect_component(root, recipe, user, home, name, call):
    fact = {'schema_version': 1, 'checks': {'ready': False}, 'error_code': None}
    kind = recipe['recipe']
    if kind == 'package':
        artifact = recipe['artifact']
        if artifact['source'] == 'alt-repository':
            names = artifact['packages']
        elif artifact['source'] == 'archive':
            names = [p['package_name'] for p in artifact['packages']]
        else:
            names = [artifact['package_name']]
        fact['packages'] = [p for p in (package(n, call) for n in names) if p is not None]
        executable = path(root, artifact['executable'])
        fact['executable'] = executable.is_file() and os.access(executable, os.X_OK)
        fact['checks']['ready'] = all(active(s, call) for s in recipe['services'])
    elif kind == 'system_base':
        session = recipe['session']
        fact['checks']['ready'] = (all(package(p, call) is not None for p in recipe['packages'])
            and path(root, session['executable']).is_file()
            and ini_value(path(root, '/etc/lightdm/lightdm.conf.d/90-alt-workstation-session.conf'),
                          ['Seat:*'], 'user-session') == session['lightdm_session'])
    elif kind == 'domain':
        joined, _ = call(['net', 'ads', 'testjoin'])
        gp_rc, gp = call(['gpupdate-setup', 'status'])
        backend_rc, backend = call(['gpupdate-setup', 'active-backend'])
        policy_rc, policy = call(['gpupdate-setup', 'active-policy'])
        state_rc, state = call(['systemctl', 'show', 'gpupdate.service', '--property=Result',
                               '--property=ExecMainStatus', '--property=ExecMainStartTimestampMonotonic'])
        properties = dict(line.split('=', 1) for line in state.splitlines() if '=' in line)
        fact['checks']['ready'] = (joined == 0 and active('sssd', call) and gp_rc == 0 and gp == 'workstation'
            and backend_rc == 0 and backend == 'samba' and policy_rc == 0 and policy == 'workstation'
            and state_rc == 0 and properties.get('Result') == 'success' and properties.get('ExecMainStatus') == '0'
            and int(properties.get('ExecMainStartTimestampMonotonic', '0')) > 0)
    elif kind in ('plasma', 'government_ca', 'shortcuts', 'krfb'):
        if not user['home_safe']:
            return fact
        if not user['home_exists']:
            fact['deferred'] = True
            return fact
        uid = user['uid']
        if kind == 'plasma':
            fact['checks']['ready'] = desktop_ready(root, recipe, home, uid)
        elif kind == 'government_ca':
            fact['checks']['ready'] = certificates_ready(root, recipe, home, name, uid, call)
        elif kind == 'shortcuts':
            defaults = recipe['defaults']
            entries = recipe['entries']
            targets = [path(root, home+'/'+defaults['desktop_shortcuts_user_desktop_name']+'/'+e) for e in entries]
            autostart = path(root, home+'/.config/autostart/'+defaults['desktop_shortcuts_nextcloud_entry'])
            original_autostart = path(root, defaults['desktop_shortcuts_applications_dir']+'/'+defaults['desktop_shortcuts_nextcloud_entry'])
            fact['checks']['ready'] = (all(safe_file(p, uid=uid, mode=0o755) for p in targets)
                and safe_file(autostart, uid=uid, mode=0o644) and safe_file(original_autostart)
                and autostart.read_bytes() == original_autostart.read_bytes())
            for entry in entries:
                original = path(root, defaults['desktop_shortcuts_applications_dir']+'/'+entry)
                target = path(root, home+'/'+defaults['desktop_shortcuts_user_desktop_name']+'/'+entry)
                fact['checks']['ready'] = fact['checks']['ready'] and original.is_file() and target.is_file() and original.read_bytes() == target.read_bytes()
            for link in defaults['desktop_shortcuts_relative_links']:
                target = path(root, home+'/'+defaults['desktop_shortcuts_user_desktop_name']+'/'+link['name'])
                fact['checks']['ready'] = (fact['checks']['ready'] and target.is_symlink()
                    and target.lstat().st_uid == uid and target.lstat().st_gid == user['gid']
                    and os.readlink(target) == link['src'])
        else:
            config = path(root, home+'/.config/krfbrc')
            autostart = path(root, home+'/.config/autostart/org.sosn.krfb.desktop')
            fact['checks']['ready'] = (package('krfb', call) is not None and safe_file(config, uid=uid, mode=0o600)
                and safe_file(autostart, uid=uid, mode=0o644)
                and all(ini_value(config, groups, key) == desired for groups, key, desired in recipe['settings'])
                and bool(ini_value(config, ['Security'], 'desktopPassword'))
                and bool(ini_value(config, ['Security'], 'unattendedPassword')))
    else:
        raise ValueError('unsupported recipe')
    return fact


def collect(query, *, root=Path('/'), call=run):
    if set(query) != {'schema_version', 'machine_uuid', 'hostname', 'login', 'upn', 'components'}:
        raise ValueError('probe query')
    if type(query['schema_version']) is not int or query['schema_version'] != 1:
        raise ValueError('probe query version')
    if not re.fullmatch('[a-z0-9][a-z0-9._-]{0,62}', query['login']) or query['upn'] != query['login']+'@sosnadmin.local':
        raise ValueError('probe user')
    if not isinstance(query['components'], list) or not 0 < len(query['components']) <= 256:
        raise ValueError('probe selection')
    actual_uuid = text(path(root, '/sys/class/dmi/id/product_uuid')).strip().lower()
    rc, hostname = call(['hostname', '-s'])
    if actual_uuid != query['machine_uuid'] or rc or hostname.lower() != query['hostname']:
        raise ValueError('probe machine identity')
    user, home, name = user_identity(root, query, call)
    manager = package_health(root, query['components'], call)
    components = {}
    for recipe in query['components']:
        identifier = recipe['id']
        if identifier in components:
            raise ValueError('duplicate probe selection')
        try:
            components[identifier] = inspect_component(root, recipe, user, home, name, call)
        except Exception:
            components[identifier] = {'schema_version': 1, 'checks': {'ready': None}, 'error_code': 'probe_unavailable'}
    return {'schema_version': 1, 'observed_at': datetime.now(timezone.utc).isoformat(),
            'machine': {'uuid': actual_uuid, 'hostname': hostname.lower(), 'os_id': os_id(root),
                        'boot_id': text(path(root, '/proc/sys/kernel/random/boot_id')).strip()},
            'user': user, 'package_manager': manager, 'components': components}


if __name__ == '__main__':
    try:
        raw = sys.stdin.read(524289)
        if len(raw) > 524288:
            raise ValueError('probe limit')
        print(json.dumps(collect(json.loads(raw)), allow_nan=False))
    except Exception:
        # No path, command result, configuration contents or secret is printed.
        print('{"schema_version":1,"error_code":"probe_unavailable"}')
        raise SystemExit(1)
