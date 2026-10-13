"""Keep native ALT first join within delegated computer-account rights.

No existing-account repair is admitted. The root-private adapter changes only
the native script's net executable; the packaged script itself is untouched.
Optional OS metadata is omitted; only affected Samba splits keytab creation.
"""
import importlib.util
import json
import os
from pathlib import Path
import re
import shlex
import stat
import subprocess
import sys
import tempfile
from urllib.parse import urlparse

SYSTEM_KEYTAB = '/etc/krb5.keytab'


def affected(version):
    match = re.fullmatch(r'4\.21\.([0-9]+)', version.strip())
    return bool(match and int(match[1]) < 10)


def validate_identity(hostname, realm, dc):
    label = r'[a-z0-9](?:[a-z0-9-]*[a-z0-9])?'
    if (not re.fullmatch(label, hostname) or len(hostname) > 15
            or not re.fullmatch(label + r'(?:\.' + label + r')+', realm)
            or not re.fullmatch(label + r'\.' + re.escape(realm), dc)):
        raise ValueError('Unsupported first-join identity')


def adapt_system_auth(source, executable):
    needle = 'net_cmd="/usr/bin/net"'
    if source.count(needle) != 1 or 'target-server:' not in source:
        raise ValueError('Unsupported native system-auth interface')
    if not re.fullmatch(r'/run/alt-first-join-[a-zA-Z0-9_-]+/net', executable):
        raise ValueError('Unsafe native adapter path')
    return source.replace(needle, 'net_cmd=' + json.dumps(executable))


def net_command(keytab, hostname, realm, argv):
    return ['/usr/bin/net', '--option=sync machine password to keytab=' +
            keytab + ':account_name:spns=host/' + hostname + '.' + realm +
            ':machine_password', *argv]


def native_join_args(argv, hostname, realm, dc, ou):
    """Keep the admitted join, without requiring optional OS-property rights.

    Native ALT adds osName/osVer; Samba turns those into a separate atomic
    write of three OS attributes before storing credentials. Computer-create,
    password and validated SPN rights do not authorize that optional write.
    Reject a changed native interface before invoking the directory writer.
    """
    if not isinstance(argv, list) or argv[:2] != ['ads', 'join']:
        raise ValueError('Unsupported native join interface')
    createcomputer = 'createcomputer=' + '/'.join(reversed(re.findall(r'(?:^|,)OU=([^,]+)', ou)))
    counts = {}
    result = argv[:2]
    position = 2
    while position < len(argv):
        value = argv[position]
        if not isinstance(value, str) or not value or len(value) > 4096 or any(ord(c) < 32 for c in value):
            raise ValueError('Unsupported native join argument')
        if value == '-S':
            if position + 1 >= len(argv) or argv[position + 1] != dc:
                raise ValueError('Unsupported native join controller')
            name = 'server'
            result.extend([value, argv[position + 1]])
            position += 2
        else:
            if value in ('--use-kerberos=required', '--no-dns-updates', createcomputer):
                name = value
            elif value.startswith('--use-krb5-ccache=') and value.partition('=')[2]:
                name = 'cache'
            elif value == 'dnshostname=' + hostname + '.' + realm:
                name = 'dns'
            elif value.startswith(('osName=', 'osVer=')) and value.partition('=')[2]:
                name = value.partition('=')[0]
            else:
                raise ValueError('Unsupported native join argument')
            if name not in ('osName', 'osVer'):
                result.append(value)
            position += 1
        counts[name] = counts.get(name, 0) + 1
        if counts[name] != 1:
            raise ValueError('Ambiguous native join argument')
    required = {'--use-kerberos=required', '--no-dns-updates', createcomputer,
                'cache', 'server', 'osName', 'osVer'}
    if not required.issubset(counts):
        raise ValueError('Incomplete native join interface')
    return result


def attributes(raw):
    if not isinstance(raw, str) or len(raw) > 65536 or '\x00' in raw:
        raise ValueError('Invalid LDAP result')
    result = {}
    for line in raw.splitlines():
        if not line or line.startswith('#'):
            continue
        match = re.fullmatch(r'([a-zA-Z][a-zA-Z0-9-]*): (.+)', line)
        if not match or match[1].lower() in result:
            raise ValueError('Ambiguous or encoded LDAP result')
        result[match[1].lower()] = match[2]
    return result


def account_kvno(raw, hostname, realm, ou):
    fields = attributes(raw)
    expected = {'dn': 'CN=' + hostname + ',' + ou,
                'samaccountname': hostname + '$',
                'dnshostname': hostname + '.' + realm}
    if set(fields) != {*expected, 'msds-keyversionnumber'} or any(
            fields.get(name, '').lower() != value.lower() for name, value in expected.items()):
        raise ValueError('Joined computer identity mismatch')
    value = fields['msds-keyversionnumber']
    if not re.fullmatch(r'[1-9][0-9]{0,9}', value) or int(value) > 2147483647:
        raise ValueError('Invalid machine-password version')
    return int(value)


def run(argv, **kwargs):
    result = subprocess.run(argv, capture_output=True, text=True, timeout=180, **kwargs)
    if len(result.stdout) + len(result.stderr) > 65536:
        raise ValueError('Oversized native result')
    return result


def relay(result):
    sys.stdout.write(result.stdout)
    sys.stderr.write(result.stderr)
    return result.returncode


def trusted_file(path):
    path = Path(path)
    for parent in (path.parent, *path.parent.parents):
        info = parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError('Unsafe native source parent')
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
        raise ValueError('Unsafe native source')
    return path


def ldap(dc, realm, hostname, *fields):
    base = ','.join('DC=' + part for part in realm.split('.'))
    result = run(['/usr/bin/ldapsearch', '-LLL', '-o', 'ldif-wrap=no', '-Y', 'GSSAPI',
                  '-H', 'ldap://' + dc, '-b', base, '-s', 'sub',
                  '(&(objectClass=computer)(sAMAccountName=' + hostname + '$))', *fields])
    if result.returncode:
        raise ValueError('First-join directory observation failed')
    return result.stdout


class KeytabIdentity:
    @staticmethod
    def validate_metadata(meta):
        if set(meta) != {'hostname', 'realm'}:
            raise ValueError('Invalid keytab identity')
        validate_identity(meta['hostname'], meta['realm'], 'dc.' + meta['realm'])
        return dict(meta)


def keytab_parser():
    # The unchanged, reviewed byte parser binds offline keys; it performs no
    # AD write and does not constitute a recovery execution entry point.
    path = trusted_file('/usr/local/libexec/alt-first-join-keytab.py')
    spec = importlib.util.spec_from_file_location('first_join_keytab', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    if not callable(module.bind_offline_keytab):
        raise ValueError('Invalid keytab parser')
    return module


def bind_keytab(directory, hostname, realm, dc, ou):
    module = keytab_parser()
    kvno = account_kvno(ldap(dc, realm, hostname, 'sAMAccountName', 'dNSHostName',
                            'msDS-KeyVersionNumber'), hostname, realm, ou)
    raw = (directory / 'offline.keytab').read_bytes()
    bound = module.bind_offline_keytab(raw, {'hostname': hostname, 'realm': realm},
                                      kvno, native=KeytabIdentity)
    # Publish complete bytes atomically, without replacing an existing keytab.
    target = Path(SYSTEM_KEYTAB)
    parent = target.parent.lstat()
    if not stat.S_ISDIR(parent.st_mode) or parent.st_uid != 0 or parent.st_mode & 0o022:
        raise ValueError('Unsafe keytab directory')
    descriptor, temporary = tempfile.mkstemp(prefix='.alt-first-join-keytab-', dir=target.parent)
    try:
        with os.fdopen(descriptor, 'wb') as stream:
            stream.write(bound)
            stream.flush()
            os.fsync(stream.fileno())
        os.link(temporary, target, follow_symlinks=False)
        parent_fd = os.open(target.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(parent_fd)
        finally:
            os.close(parent_fd)
    finally:
        os.unlink(temporary)
    return kvno


def net_wrapper(directory, hostname, realm, dc, ou, argv, *, split_keytab=True):
    trusted_file(directory / 'net')
    validate_identity(hostname, realm, dc)
    joining = argv[:2] == ['ads', 'join']
    if joining:
        argv = native_join_args(argv, hostname, realm, dc, ou)
    # Separate the directory write from local keytab generation; keep Samba's
    # inline synchronization outside this first-join path.
    if not split_keytab:
        command = ['/usr/bin/net', *argv]
    else:
        command = (['/usr/bin/net', '--option=sync machine password to keytab=disabled', *argv]
                   if joining else net_command(str(directory / 'offline.keytab'), hostname, realm, argv))
    result = run(command)
    sys.stdout.write(result.stdout)
    sys.stderr.write(result.stderr)
    if result.returncode:
        return result.returncode
    if joining and split_keytab:
        created = run(net_command(str(directory / 'offline.keytab'), hostname, realm,
                                  ['ads', 'keytab', 'create']))
        sys.stdout.write(created.stdout)
        sys.stderr.write(created.stderr)
        if created.returncode:
            return created.returncode
        bind_keytab(directory, hostname, realm, dc, ou)
    return 0


def first_join(uri, ou, command):
    if len(command) != 9 or command[:3] != ['system-auth', 'write', 'ad'] or command[-1] != '--gpo':
        raise ValueError('Invalid fixed native join command')
    realm, hostname, workgroup, user = command[3:7]
    dc = urlparse(uri)
    if dc.scheme != 'ldap' or dc.netloc != dc.hostname or dc.path or dc.query or dc.fragment:
        raise ValueError('Invalid approved LDAP endpoint')
    version = run(['/usr/bin/rpm', '-q', '--qf', '%{VERSION}', 'samba-client'])
    if version.returncode:
        raise ValueError('Samba version unavailable')
    split_keytab = affected(version.stdout)
    validate_identity(hostname, realm, dc.hostname)
    if (not re.fullmatch(r'[A-Za-z0-9_-]{1,15}', workgroup)
            or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._@-]{0,127}', user)
            or not re.fullmatch(r'(?:OU=[A-Za-z0-9 _.-]+,)+DC=' + re.escape(realm.replace('.', ',DC=')), ou)
            or command[7] != '--createcomputer=' + '/'.join(
                reversed(re.findall(r'(?:^|,)OU=([^,]+)', ou)))):
        raise ValueError('Invalid fixed first-join request')
    source = trusted_file('/usr/sbin/system-auth').read_text()
    if run(['/usr/bin/net', 'ads', 'testjoin']).returncode == 0:
        raise ValueError('First join cannot replace existing trust')
    if run(['/usr/sbin/system-auth', 'status']).stdout.strip().lower() != 'local':
        raise ValueError('First join requires local authentication')
    if Path(SYSTEM_KEYTAB).exists() or Path(SYSTEM_KEYTAB).is_symlink():
        raise ValueError('First join cannot replace existing keytab')
    if attributes(ldap(dc.hostname, realm, hostname, 'dn')):
        raise ValueError('Existing computer requires separate recovery')
    # Validate the parser before the only domain write.
    if split_keytab:
        keytab_parser()
    with tempfile.TemporaryDirectory(prefix='alt-first-join-', dir='/run') as temporary:
        directory = Path(temporary)
        native = directory / 'system-auth'
        native.write_text(adapt_system_auth(source, str(directory / 'net')))
        native.chmod(0o700)
        wrapper = directory / 'net'
        args = [sys.executable, '-I', str(trusted_file('/usr/local/libexec/alt-first-join.py')),
                '--net-wrapper', str(directory), hostname, realm, dc.hostname, ou,
                'split' if split_keytab else 'native', '--']
        wrapper.write_text('#!/bin/sh\nexec ' + shlex.join(args) + ' "$@"\n')
        wrapper.chmod(0o700)
        result = run([str(native), *command[1:], '--target-server=' + dc.hostname])
        relay(result)
        if result.returncode:
            # A later native stage can fail after the AD write/keytab bind.
            # Trust-only reconciliation must not turn this into acceptance.
            raise ValueError('Native first-join configuration did not complete')
        # Fresh trust and a real machine AS exchange are both required.
        if run(['/usr/bin/net', '-S', dc.hostname, 'ads', 'testjoin']).returncode:
            raise ValueError('First-join trust verification failed')
        env = os.environ.copy()
        env['KRB5CCNAME'] = 'FILE:' + str(directory / 'machine.ccache')
        config = directory / 'machine.krb5.conf'
        config.write_text('[libdefaults]\n default_realm = ' + realm.upper() +
                          '\n dns_lookup_kdc = false\n[realms]\n ' + realm.upper() +
                          ' = {\n  kdc = ' + dc.hostname + '\n }\n')
        config.chmod(0o600)
        env['KRB5_CONFIG'] = str(config)
        if run(['/usr/bin/kinit', '-k', '-t', SYSTEM_KEYTAB,
                hostname.upper() + '$@' + realm.upper()], env=env).returncode:
            raise ValueError('First-join machine credentials verification failed')
        return 0


def main():
    if os.geteuid() != 0:
        raise ValueError('First join requires root')
    if sys.argv[1:2] == ['--net-wrapper']:
        if len(sys.argv) < 11 or sys.argv[7] not in ('split', 'native') or sys.argv[8] != '--':
            raise ValueError('Invalid native adapter invocation')
        return net_wrapper(Path(sys.argv[2]), *sys.argv[3:7], sys.argv[9:],
                           split_keytab=sys.argv[7] == 'split')
    if len(sys.argv) < 4:
        raise ValueError('Invalid first-join invocation')
    return first_join(sys.argv[1], sys.argv[2], sys.argv[3:])


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception:
        print('ALT_PREFLIGHT_FAILURE:domain_join_compatibility_failed first-join credentials or verification failed', file=sys.stderr)
        raise SystemExit(89) from None
