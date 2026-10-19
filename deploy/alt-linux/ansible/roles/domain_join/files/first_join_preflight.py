"""Fixed read-only AD creation admission under the actual Kerberos identity."""
import base64
import json
import os
import re
import subprocess
import sys
import time
import uuid
from threading import Thread
from urllib.parse import urlsplit

DOMAIN = 'sosnadmin.local'
BASE = 'DC=sosnadmin,DC=local'
MAX_BYTES = 2 * 1024 * 1024
MAX_OBJECTS = 4096


class PreflightError(ValueError):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def reject(code='ad_join_evidence_invalid'):
    raise PreflightError(code)


def entries(raw):
    if not isinstance(raw, str) or len(raw.encode()) > MAX_BYTES:
        reject()
    unfolded = []
    for line in raw.splitlines():
        if line.startswith(' '):
            if not unfolded or not unfolded[-1]:
                reject()
            unfolded[-1] += line[1:]
        else:
            unfolded.append(line)
    result, current = [], {}
    for line in [*unfolded, '']:
        if not line:
            if current:
                if 'dn' not in current or len(result) >= MAX_OBJECTS:
                    reject()
                result.append(current)
                current = {}
            continue
        if line.startswith('#'):
            continue
        name, sep, value = line.partition(':')
        name = name.lower()
        if (not sep or not re.fullmatch('[a-z][a-z0-9-]*', name)
                or name == 'ref' or value.startswith('<')
                or name in current and name != 'allowedchildclasseseffective'):
            reject()
        try:
            value = (base64.b64decode(value[1:].lstrip(), validate=True)
                     if value.startswith(':') else value.lstrip(' ').encode())
        except ValueError:
            reject()
        if len(value) > 8192:
            reject()
        current.setdefault(name, []).append(value)
    return result


def single(entry, name, *, binary=False):
    values = entry.get(name.lower(), [])
    if len(values) != 1:
        reject()
    if binary:
        return values[0]
    try:
        value = values[0].decode('utf-8')
    except UnicodeError:
        reject()
    if any(ord(c) < 32 or ord(c) == 127 for c in value):
        reject()
    return value


def guid(entry):
    raw = single(entry, 'objectGUID', binary=True)
    if len(raw) != 16 or not any(raw):
        reject()
    return str(uuid.UUID(bytes_le=raw))


def check(uri, ou, expected_principal, runner):
    """Return safe evidence or fail, with no filesystem or directory write API."""
    try:
        endpoint = urlsplit(uri)
        if (endpoint.scheme != 'ldap' or endpoint.netloc != endpoint.hostname
                or endpoint.path or endpoint.query or endpoint.fragment
                or not re.fullmatch(r'[a-zA-Z0-9.-]+', endpoint.hostname or '')
                or not (endpoint.hostname.lower() == DOMAIN or
                        endpoint.hostname.lower().endswith('.' + DOMAIN))
                or not re.fullmatch(r'(?:OU=[^,\\\x00-\x1f]+,)+DC=sosnadmin,DC=local', ou)):
            reject('ad_join_request_invalid')
        ticket = runner(['/usr/bin/klist'])
        if ticket.returncode or len(ticket.stdout.encode()) > 65536:
            reject('ad_join_kerberos_failed')
        principals = re.findall(r'^Default principal: ([^\r\n]+)$', ticket.stdout, re.M)
        if len(principals) != 1:
            reject('ad_join_principal_unproven')
        principal = principals[0].lower()
        if not re.fullmatch(r'[a-z0-9][a-z0-9._-]{0,62}@sosnadmin\.local', principal):
            reject('ad_join_principal_unproven')
        if expected_principal:
            expected = expected_principal.lower()
            if '@' not in expected:
                expected += '@' + DOMAIN
            if expected != principal:
                reject('ad_join_principal_changed')

        def query(base, scope, ldap_filter, attributes, *, many=False):
            command = ['/usr/bin/ldapsearch', '-LLL', '-Q', '-Y', 'GSSAPI',
                       '-O', 'minssf=56', '-o', 'nettimeout=10', '-o', 'ldif-wrap=no',
                       '-l', '10', '-z', str(MAX_OBJECTS + 1),
                       '-H', active_uri, '-b', base, '-s', scope]
            if many:
                command += ['-E', 'pr=256/noprompt']
            result = runner(command + [ldap_filter, *attributes])
            if result.returncode:
                reject({4: 'ad_join_results_incomplete', 49: 'ad_join_authentication_failed',
                        50: 'ad_join_read_denied', 81: 'ad_join_dc_unavailable',
                        91: 'ad_join_dc_unavailable'}.get(result.returncode, 'ad_join_query_failed'))
            rows = entries(result.stdout)
            if many:
                return rows
            if len(rows) != 1:
                reject()
            return rows[0]

        active_uri = uri
        root = query('', 'base', '(objectClass=*)', ('dnsHostName', 'defaultNamingContext'))
        dc = single(root, 'dnsHostName').lower()
        if (not re.fullmatch(r'[a-z0-9.-]+', dc) or not dc.endswith('.' + DOMAIN)
                or single(root, 'defaultNamingContext').lower() != BASE.lower()):
            reject('ad_join_directory_mismatch')
        active_uri = 'ldap://' + dc
        domain = query(BASE, 'base', '(objectClass=*)', ('ms-DS-MachineAccountQuota',))
        quota = int(single(domain, 'ms-DS-MachineAccountQuota'))
        if not 0 <= quota <= 2147483647:
            reject()
        user = query(BASE, 'sub', '(&(objectCategory=person)(objectClass=user)(userPrincipalName=' +
                     principal + '))', ('objectGUID', 'objectSid', 'userPrincipalName',
                     'sAMAccountName', 'userAccountControl', 'msDS-User-Account-Control-Computed',
                     'accountExpires'))
        if (single(user, 'userPrincipalName').lower() != principal
                or single(user, 'sAMAccountName').lower() != principal.split('@')[0]):
            reject('ad_join_principal_changed')
        flags = int(single(user, 'userAccountControl'))
        computed = int(single(user, 'msDS-User-Account-Control-Computed'))
        expiry = int(single(user, 'accountExpires'))
        now = int((time.time() + 11644473600) * 10000000)
        if (flags < 0 or computed < 0 or not 0 <= expiry <= 9223372036854775807
                or flags & 18 or computed & (16 | 8388608)
                or expiry not in (0, 9223372036854775807) and expiry <= now):
            reject('ad_join_principal_unusable')
        sid = single(user, 'objectSid', binary=True)
        if len(sid) < 12 or sid[0] != 1 or not 1 <= sid[1] <= 15 or len(sid) != 8 + sid[1] * 4:
            reject()
        sid_text = 'S-1-' + str(int.from_bytes(sid[2:8], 'big')) + '-' + '-'.join(
            str(int.from_bytes(sid[i:i+4], 'little')) for i in range(8, len(sid), 4))
        target = query(ou, 'base', '(objectClass=organizationalUnit)',
                       ('objectGUID', 'allowedChildClassesEffective'))
        if single(target, 'dn').casefold() != ou.casefold():
            reject('ad_join_ou_changed')
        ou_guid = guid(target)
        effective = [value.decode('ascii').lower() for value in
                     target.get('allowedchildclasseseffective', [])]
        creator_filter = ''.join('\\' + format(value, '02x') for value in sid)
        created = query(BASE, 'sub', '(&(objectClass=computer)(ms-DS-CreatorSID=' +
                        creator_filter + '))', ('objectGUID',), many=True)
        identities = [guid(row) for row in created]
        if len(set(identities)) != len(identities):
            reject('ad_join_results_incomplete')
        if 'computer' not in effective:
            reject('ad_join_quota_exhausted' if len(created) >= quota
                   else 'ad_join_create_rights_unproven')
        return dict(schema_version=1, dc=dc, join_principal_guid=guid(user),
                    join_principal_sid=sid_text, ou_guid=ou_guid, domain_quota=quota,
                    created_computers=len(created), quota_remaining=max(0, quota-len(created)),
                    quota_applicable=False, creation_mode='delegated')
    except PreflightError:
        raise
    except (ValueError, TypeError, KeyError, UnicodeError, OSError, subprocess.SubprocessError):
        reject()


def read_process(command, *, timeout=20, max_bytes=MAX_BYTES):
    with subprocess.Popen(command, stdin=subprocess.DEVNULL,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          env=dict(os.environ, LC_ALL='C')) as process:
        captured, excessive = [b'', b''], []
        def drain(index, stream):
            try:
                captured[index] = stream.read(max_bytes + 1)
                if len(captured[index]) > max_bytes:
                    excessive.append(True)
                    process.kill()
            finally:
                stream.close()
        readers = [Thread(target=drain, args=(i, pipe), daemon=True)
                   for i, pipe in enumerate((process.stdout, process.stderr))]
        for thread in readers:
            thread.start()
        try:
            process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
            reject('ad_join_timeout')
        except BaseException:
            process.kill()
            process.wait()
            raise
        finally:
            for thread in readers:
                thread.join(timeout=2)
        if excessive or any(thread.is_alive() for thread in readers):
            if process.poll() is None:
                process.kill()
                process.wait()
            reject('ad_join_results_incomplete')
        return subprocess.CompletedProcess(command, process.returncode,
            captured[0].decode(), captured[1].decode(errors='replace'))


def main():
    if len(sys.argv) != 4:
        reject('ad_join_request_invalid')
    try:
        print(json.dumps({'status': 'ready', 'evidence': check(*sys.argv[1:], read_process)}, sort_keys=True))
    except PreflightError as exc:
        print(json.dumps({'status': 'blocked', 'code': exc.code}, sort_keys=True))
        return 4
    return 0


if __name__ == '__main__':
    sys.exit(main())
