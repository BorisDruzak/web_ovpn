"""Optional personal SMB links. AD verifies identity; the file server decides access.

No administrative credentials, mounts, test files, ACL changes or guessed group
name mappings. The entire probe runs with the selected graphical user's ticket.
"""
from __future__ import annotations

import base64
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import stat
import subprocess
import sys
import time
from urllib.parse import quote, urlsplit

MARKER = 'X-Alt-Setup-Network-Folder=true\n'
KINDS = ('Рабочая', 'Сканы')
MAX_DEPARTMENTS = 64
MAX_QUERIES = 128


def safe_name(value):
    if (not isinstance(value, str) or not 0 < len(value) <= 200
            or value.strip() != value or value in ('.', '..')
            or any(ord(c) < 32 or c in '/\\";*?[]' for c in value)):
        raise ValueError('unsafe_name')
    return value


def directories(output):
    """Parse only directory records from Samba's C-locale ls, never commands."""
    result = []
    for line in output.splitlines():
        match = re.fullmatch(r'  (.+?)\s+([A-Z]+)\s+\d+\s+(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun)\s+.+', line)
        if match and 'D' in match[2] and match[1] not in ('.', '..'):
            result.append(safe_name(match[1]))
    if len(result) > MAX_DEPARTMENTS or len(result) != len(set(result)):
        raise ValueError('directory_limit')
    return result


def _run(argv, *, timeout):
    # All callers are already unprivileged. No password or root cache fallback.
    env = dict(os.environ, LC_ALL='C.UTF-8', LANG='C.UTF-8', LDAPTLS_REQCERT='demand')
    process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, env=env)
    deadline = time.monotonic() + timeout
    buffers = {'stdout': bytearray(), 'stderr': bytearray()}
    try:
        with selectors.DefaultSelector() as selected:
            selected.register(process.stdout, selectors.EVENT_READ, 'stdout')
            selected.register(process.stderr, selectors.EVENT_READ, 'stderr')
            while selected.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError
                for key, _ in selected.select(remaining):
                    block = os.read(key.fd, 8192)
                    if not block:
                        selected.unregister(key.fileobj)
                    else:
                        buffers[key.data].extend(block)
                    if sum(len(b) for b in buffers.values()) > 2 * 1024 * 1024:
                        raise ValueError('output_limit')
        process.wait(timeout=max(.001, deadline - time.monotonic()))
        return subprocess.CompletedProcess(argv, process.returncode,
            buffers['stdout'].decode('utf-8'), buffers['stderr'].decode('utf-8'))
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()
        process.stdout.close()
        process.stderr.close()


def _attributes(output):
    attributes = {}
    # ldapsearch -o ldif-wrap=no avoids folded values. Duplicate identities fail.
    for line in output.splitlines():
        if not line or line.startswith('#'):
            continue
        match = re.fullmatch(r'([A-Za-z][A-Za-z0-9]*)(::?) (.*)', line)
        if not match:
            raise ValueError('ad_response_unverified')
        key = match[1].lower()
        # AD subtree responses include several naming-context continuation
        # references. They are not additional users and must not be followed.
        if key == 'ref':
            continue
        if key in attributes:
            raise ValueError('ad_response_ambiguous')
        attributes[key] = (base64.b64decode(match[3], validate=True) if match[2] == '::'
                           else match[3].encode('utf-8'))
    return attributes


def _sid(value):
    if len(value) < 8 or value[0] != 1 or len(value) != 8 + 4 * value[1]:
        raise ValueError('ad_sid_invalid')
    return 'S-1-' + str(int.from_bytes(value[2:8], 'big')) + ''.join(
        '-' + str(int.from_bytes(value[i:i + 4], 'little')) for i in range(8, len(value), 4))


def validate(request):
    domain, login = request['domain'], request['login']
    if not re.fullmatch(r'[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)+', domain):
        raise ValueError('domain_invalid')
    if not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9._-]{0,62}(?:@' + re.escape(domain) + ')?', login, re.I):
        raise ValueError('login_invalid')
    if not re.fullmatch(r'[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)*', request['server']):
        raise ValueError('server_invalid')
    safe_name(request['share'])
    safe_name(request['desktop'])
    uri = urlsplit(request['ldap_uri'])
    if (uri.scheme not in ('ldap', 'ldaps') or not uri.hostname or uri.username or uri.password
            or uri.path or uri.query or uri.fragment or uri.port not in (None, 389, 636)):
        raise ValueError('ldap_invalid')
    if request.get('sid') and not re.fullmatch(r'S-1-\d+(?:-\d+)+', request['sid']):
        raise ValueError('sid_invalid')
    return login.split('@')[0], domain


def probe(request, *, runner=_run):
    result = {'status': 'unknown', 'code': 'network_folders_unverified', 'ad_verified': False,
              'folders': [], 'denied_count': 0, 'unknown_count': 0}
    deadline = time.monotonic() + 22
    try:
        login, domain = validate(request)

        def call(argv):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError
            return runner(argv, timeout=min(4, remaining))

        ticket = call(['/usr/bin/klist'])
        principal = re.search(r'^Default principal:\s*(\S+)\s*$', ticket.stdout, re.M)
        if ticket.returncode or not principal or principal[1].casefold() != (login + '@' + domain).casefold():
            raise ValueError('selected_user_ticket_unavailable')
        who = call(['/usr/bin/ldapwhoami', '-Q', '-Y', 'GSSAPI', '-O', 'minssf=56', '-H', request['ldap_uri']])
        identity = who.stdout.strip()
        if who.returncode or not identity.startswith('u:') or not (
                identity.rsplit('\\', 1)[-1].casefold() == login.casefold()
                or identity[2:].casefold() == (login + '@' + domain).casefold()):
            raise ValueError('ad_ticket_identity_mismatch')
        query = call(['/usr/bin/ldapsearch', '-LLL', '-Q', '-Y', 'GSSAPI', '-O', 'minssf=56',
                      '-o', 'nettimeout=3', '-o', 'ldif-wrap=no', '-l', '3', '-z', '2',
                      '-H', request['ldap_uri'], '-b', ','.join('DC=' + p for p in domain.split('.')),
                      '(&(objectClass=user)(sAMAccountName=' + login + '))',
                      'sAMAccountName', 'userPrincipalName', 'objectSid', 'userAccountControl'])
        if query.returncode:
            raise ValueError('ad_unavailable')
        user = _attributes(query.stdout)
        if (user['samaccountname'].decode().casefold() != login.casefold()
                or user['userprincipalname'].decode().casefold() != (login + '@' + domain).casefold()
                or int(user['useraccountcontrol']) & 2
                or request.get('sid') and _sid(user['objectsid']) != request['sid']):
            raise ValueError('ad_identity_changed')
        _sid(user['objectsid'])
        result['ad_verified'] = True

        def listing(path=''):
            argv = ['/usr/bin/smbclient', '//' + request['server'] + '/' + request['share'],
                    '--use-kerberos=required', '--client-protection=sign', '-N', '-t', '3']
            if path:
                argv += ['-D', path]
            reply = call(argv + ['-c', 'ls'])
            output = reply.stdout + reply.stderr
            statuses = re.findall(r'\bNT_STATUS_[A-Z_]+\b', output)
            if statuses:
                if all(s in ('NT_STATUS_ACCESS_DENIED', 'NT_STATUS_OBJECT_NAME_NOT_FOUND',
                             'NT_STATUS_OBJECT_PATH_NOT_FOUND', 'NT_STATUS_NO_SUCH_FILE') for s in statuses):
                    return 'denied', ''
                return 'unknown', ''
            if reply.returncode or 'blocks of size' not in output:
                return 'unknown', ''
            return 'ok', reply.stdout

        status, output = listing()
        if status != 'ok':
            raise ValueError('share_unavailable')
        departments = directories(output)
        if not departments:
            result.update(status='ok', code='no_accessible_folders')
            return result

        def check(parts):
            try:
                status, output = listing('\\'.join(parts))
            except (OSError, ValueError, TimeoutError, subprocess.SubprocessError):
                status, output = 'unknown', ''
            return status, parts, output

        # Bounded parallel reads, all child processes finish or time out before return.
        # Follow structural subdepartments too, but never recurse into employee
        # work/scans data or shared exchange folders.
        pending = [(d,) for d in departments]
        queries = 0
        with ThreadPoolExecutor(max_workers=4) as pool:
            while pending:
                batch = pending[:max(0, MAX_QUERIES - queries)]
                result['unknown_count'] += len(pending) - len(batch)
                pending = []
                queries += len(batch)
                for status, parts, output in pool.map(check, batch):
                    if status != 'ok':
                        result[status + '_count'] += 1
                    elif parts[-1] in KINDS:
                        result['folders'].append({'department': ' / '.join(parts[:-1]),
                                                  'parents': list(parts[:-1]), 'kind': parts[-1]})
                    else:
                        try:
                            for name in directories(output):
                                if name in KINDS or (len(parts) < 3 and name.casefold() != 'обмен'
                                                     and not name.startswith('.')):
                                    pending.append((*parts, name))
                                elif len(parts) >= 3 and name.casefold() != 'обмен' and not name.startswith('.'):
                                    result['unknown_count'] += 1
                        except ValueError:
                            result['unknown_count'] += 1
        result['unknown_count'] = min(MAX_QUERIES, result['unknown_count'])
        result.update(status='partial' if result['unknown_count'] else 'ok', code='checked')
    except (OSError, ValueError, KeyError, TypeError, TimeoutError, subprocess.SubprocessError):
        pass
    return result


def launcher(server, share, department, kind, *, qualified=False):
    parents = list(department) if isinstance(department, (tuple, list)) else [department]
    for name in (share, *parents, kind):
        safe_name(name)
    label = kind + (' — ' + ' / '.join(parents) if qualified else '')
    url = 'smb://' + server + '/' + '/'.join(quote(v, safe='') for v in (share, *parents, kind))
    return ('[Desktop Entry]\nType=Link\nName=' + label + '\nURL=' + url
            + '\nIcon=folder-network\n' + MARKER)


def write_launcher(desktop, filename, content):
    """Called as the employee: never follow or overwrite a personal destination."""
    import tempfile
    safe_name(filename)
    path = Path(desktop) / filename
    if path.is_symlink():
        raise ValueError('personal_destination_preserved')
    if path.exists():
        info = path.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or (os.name != 'nt' and info.st_uid != os.getuid()) or info.st_size > 16384):
            raise ValueError('personal_destination_preserved')
        old = path.read_text(encoding='utf-8')
        if MARKER not in old:
            raise ValueError('personal_destination_preserved')
        if old == content:
            return False
    descriptor, temporary = tempfile.mkstemp(prefix='.alt-network-', dir=desktop)
    try:
        with os.fdopen(descriptor, 'w', encoding='utf-8', newline='\n') as stream:
            stream.write(content)
        os.chmod(temporary, 0o644)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    return True


def retire_legacy(desktop):
    """Remove only the exact inherited old link, after a replacement exists."""
    path = Path(desktop) / 'Сетевая папка'
    if path.is_symlink() and os.readlink(path) == '../net.drives/Public':
        path.unlink()
        return True
    return False


def personal_apply(request):
    import pwd
    account = pwd.getpwuid(os.getuid())
    desktop = Path(account.pw_dir) / safe_name(request['desktop'])
    if (os.getuid() <= 0 or not desktop.is_dir() or desktop.is_symlink()
            or desktop.stat().st_uid != os.getuid()
            or Path(account.pw_dir).is_symlink()):
        raise ValueError('personal_desktop_unverified')
    result = probe(request)
    changed, created, conflicts = False, 0, 0
    for folder in result['folders']:
        department, kind = folder['parents'], folder['kind']
        key = hashlib.sha256(('/'.join(department) + '/' + kind).encode()).hexdigest()[:16]
        try:
            content = launcher(request['server'], request['share'], department, kind,
                               qualified=sum(f['kind'] == kind for f in result['folders']) > 1)
            changed = write_launcher(desktop, 'alt-setup-network-' + key + '.desktop', content) or changed
            created += 1
        except (OSError, ValueError):
            conflicts += 1
    if created:
        try:
            changed = retire_legacy(desktop) or changed
        except OSError:
            conflicts += 1
    # Never expose employee identities, group membership, filenames or folder names.
    return {'status': ('partial' if conflicts and result['status'] == 'ok' else result['status']),
            'code': result['code'], 'ad_verified': result['ad_verified'], 'created_count': created,
            'unknown_count': result['unknown_count'], 'preserved_count': conflicts, 'changed': changed}


def main():
    fallback = {'status': 'unknown', 'code': 'network_folders_unverified', 'changed': False,
                'ad_verified': False, 'created_count': 0}
    try:
        if sys.argv[1:] and sys.argv[1] == '--personal':
            result = personal_apply(json.loads(sys.argv[2]))
        else:
            import pwd
            import signal
            def expired(signum, frame):
                raise TimeoutError
            signal.signal(signal.SIGALRM, expired)
            signal.setitimer(signal.ITIMER_REAL, 45)
            if os.geteuid() != 0:
                raise ValueError('root_required')
            request = json.loads(sys.stdin.read(8193))
            validate(request)
            account = pwd.getpwnam(request['login'])
            if request.get('uid') is not None and account.pw_uid != request['uid']:
                raise ValueError('selected_uid_changed')
            session = sys.modules['alt_network_user_session']
            context = session.discover_session(account.pw_uid, account.pw_gid, account.pw_dir)
            reply = session.run_session_command(context, ['/usr/bin/python3', '-I', '-B', '-c',
                PERSONAL_PROGRAM, '--personal', json.dumps(request)], timeout=30)
            if reply.returncode:
                raise ValueError('personal_probe_unavailable')
            result = json.loads(reply.stdout)
        print(json.dumps(result, ensure_ascii=True))
    except Exception:
        print(json.dumps(fallback))
    finally:
        if sys.argv[1:2] != ['--personal'] and os.name == 'posix':
            import signal
            signal.setitimer(signal.ITIMER_REAL, 0)
    # Optional outcome: report UNKNOWN, do not fail the full Setup process.
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
