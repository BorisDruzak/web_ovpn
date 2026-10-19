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
DIAGNOSTICS = None
DIAGNOSTIC_BINDING = None


class NativeOutputLimit(ValueError):
    pass


def phase(value):
    if DIAGNOSTICS is not None:
        DIAGNOSTICS.intent(value)


def diagnostic_result(value, code, returncode=None):
    if DIAGNOSTICS is not None:
        DIAGNOSTICS.result(value, code=code, returncode=returncode)


def diagnostic_module():
    path = trusted_file('/usr/local/libexec/alt-first-join-diagnostics.py')
    spec = importlib.util.spec_from_file_location('first_join_diagnostics', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def diagnostic_error(exc):
    if DIAGNOSTICS is None:
        return
    current = DIAGNOSTICS.current()
    if isinstance(exc, subprocess.TimeoutExpired):
        code = 'first_join_timeout'
    elif isinstance(exc, NativeOutputLimit):
        code = 'first_join_output_limit'
    elif current['code'] not in ('first_join_ok', 'first_join_internal_error'):
        return  # Keep the more precise child failure across native rescue.
    elif isinstance(exc, ValueError):
        code = 'first_join_' + {'request': 'request_invalid',
            'native_interface': 'native_interface_invalid', 'preconditions': 'local_state_conflict',
            'directory_observation': 'directory_unavailable', 'native_arguments': 'native_arguments_invalid',
            'native_execution': 'native_failed', 'offline_keytab': 'keytab_create_failed',
            'keytab_bind': 'keytab_bind_failed', 'trust_verify': 'trust_failed',
            'machine_as': 'machine_as_failed'}[current['phase']]
    else:
        code = 'first_join_internal_error'
    diagnostic_result(current['phase'], code)


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
    if len(result.stdout.encode('utf-8')) + len(result.stderr.encode('utf-8')) > 65536:
        raise NativeOutputLimit('Oversized native result')
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
        phase('native_arguments')
        argv = native_join_args(argv, hostname, realm, dc, ou)
    # Separate the directory write from local keytab generation; keep Samba's
    # inline synchronization outside this first-join path.
    if not split_keytab:
        command = ['/usr/bin/net', *argv]
    else:
        command = (['/usr/bin/net', '--option=sync machine password to keytab=disabled', *argv]
                   if joining else net_command(str(directory / 'offline.keytab'), hostname, realm, argv))
    if joining:
        phase('native_execution')
    result = run(command)
    sys.stdout.write(result.stdout)
    sys.stderr.write(result.stderr)
    if result.returncode:
        if joining:
            code = diagnostic_module().native_failure_code(result.stdout + result.stderr) if DIAGNOSTICS else 'first_join_native_failed'
            diagnostic_result('native_execution', code, result.returncode)
        return result.returncode
    if joining:
        diagnostic_result('native_execution', 'first_join_ok', 0)
    if joining and split_keytab:
        phase('offline_keytab')
        created = run(net_command(str(directory / 'offline.keytab'), hostname, realm,
                                  ['ads', 'keytab', 'create']))
        sys.stdout.write(created.stdout)
        sys.stderr.write(created.stderr)
        if created.returncode:
            diagnostic_result('offline_keytab', 'first_join_keytab_create_failed', created.returncode)
            return created.returncode
        phase('keytab_bind')
        bind_keytab(directory, hostname, realm, dc, ou)
        diagnostic_result('keytab_bind', 'first_join_ok', 0)
    return 0


def first_join(uri, ou, command):
    phase('request')
    if len(command) != 9 or command[:3] != ['system-auth', 'write', 'ad'] or command[-1] != '--gpo':
        raise ValueError('Invalid fixed native join command')
    realm, hostname, workgroup, user = command[3:7]
    dc = urlparse(uri)
    if dc.scheme != 'ldap' or dc.netloc != dc.hostname or dc.path or dc.query or dc.fragment:
        raise ValueError('Invalid approved LDAP endpoint')
    phase('native_interface')
    version = run(['/usr/bin/rpm', '-q', '--qf', '%{VERSION}', 'samba-client'])
    if version.returncode:
        raise ValueError('Samba version unavailable')
    split_keytab = affected(version.stdout)
    phase('request')
    validate_identity(hostname, realm, dc.hostname)
    if (not re.fullmatch(r'[A-Za-z0-9_-]{1,15}', workgroup)
            or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._@-]{0,127}', user)
            or not re.fullmatch(r'(?:OU=[A-Za-z0-9 _.-]+,)+DC=' + re.escape(realm.replace('.', ',DC=')), ou)
            or command[7] != '--createcomputer=' + '/'.join(
                reversed(re.findall(r'(?:^|,)OU=([^,]+)', ou)))):
        raise ValueError('Invalid fixed first-join request')
    phase('native_interface')
    source = trusted_file('/usr/sbin/system-auth').read_text()
    phase('preconditions')
    if run(['/usr/bin/net', 'ads', 'testjoin']).returncode == 0:
        raise ValueError('First join cannot replace existing trust')
    if run(['/usr/sbin/system-auth', 'status']).stdout.strip().lower() != 'local':
        raise ValueError('First join requires local authentication')
    if Path(SYSTEM_KEYTAB).exists() or Path(SYSTEM_KEYTAB).is_symlink():
        raise ValueError('First join cannot replace existing keytab')
    phase('directory_observation')
    if attributes(ldap(dc.hostname, realm, hostname, 'dn')):
        raise ValueError('Existing computer requires separate recovery')
    # Validate the parser before the only domain write.
    if split_keytab:
        phase('native_interface')
        keytab_parser()
    with tempfile.TemporaryDirectory(prefix='alt-first-join-', dir='/run') as temporary:
        directory = Path(temporary)
        native = directory / 'system-auth'
        native.write_text(adapt_system_auth(source, str(directory / 'net')))
        native.chmod(0o700)
        wrapper = directory / 'net'
        args = [sys.executable, '-I', str(trusted_file('/usr/local/libexec/alt-first-join.py')),
                *(['--diagnostic', json.dumps(DIAGNOSTIC_BINDING, sort_keys=True)] if DIAGNOSTIC_BINDING else []),
                '--net-wrapper', str(directory), hostname, realm, dc.hostname, ou,
                'split' if split_keytab else 'native', '--']
        wrapper.write_text('#!/bin/sh\nexec ' + shlex.join(args) + ' "$@"\n')
        wrapper.chmod(0o700)
        # Intent precedes dispatch of the native configuration chain. A child
        # receipt refines it; its absence can never prove no directory effect.
        phase('native_execution')
        result = run([str(native), *command[1:], '--target-server=' + dc.hostname])
        if result.returncode:
            # A later native stage can fail after the AD write/keytab bind.
            # Trust-only reconciliation must not turn this into acceptance.
            if DIAGNOSTICS and DIAGNOSTICS.current()['code'] in ('first_join_ok', 'first_join_internal_error'):
                # Only the net child can establish the directory writer's
                # return code. The enclosing script may fail after losing it.
                diagnostic_result('native_execution', diagnostic_module().native_failure_code(result.stdout + result.stderr))
            raise ValueError('Native first-join configuration did not complete')
        # Fresh trust and a real machine AS exchange are both required.
        phase('trust_verify')
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
        phase('machine_as')
        if run(['/usr/bin/kinit', '-k', '-t', SYSTEM_KEYTAB,
                hostname.upper() + '$@' + realm.upper()], env=env).returncode:
            raise ValueError('First-join machine credentials verification failed')
        diagnostic_result('machine_as', 'first_join_ok', 0)
        return 0


def main():
    global DIAGNOSTICS, DIAGNOSTIC_BINDING
    if os.geteuid() != 0:
        raise ValueError('First join requires root')
    argv = sys.argv[1:]
    if argv[:1] == ['--read-diagnostic']:
        if len(argv) != 2 or len(argv[1]) > 4096:
            raise ValueError('Invalid diagnostic read')
        print(json.dumps(diagnostic_module().read_public(json.loads(argv[1])), sort_keys=True))
        return 0
    if argv[:1] == ['--diagnostic']:
        if len(argv) < 3 or len(argv[1]) > 4096:
            raise ValueError('Invalid diagnostic request')
        module = diagnostic_module()
        DIAGNOSTIC_BINDING = module.binding(json.loads(argv[1]))
        DIAGNOSTICS = module.Diagnostics(DIAGNOSTIC_BINDING)
        argv = argv[2:]
    elif os.environ.get('ALT_FIRST_JOIN_BINDING'):
        raw = os.environ['ALT_FIRST_JOIN_BINDING']
        if len(raw) > 4096:
            raise ValueError('Invalid diagnostic request')
        module = diagnostic_module()
        DIAGNOSTIC_BINDING = module.binding(json.loads(raw))
        DIAGNOSTICS = module.Diagnostics(DIAGNOSTIC_BINDING)
    wrapper = argv[:1] == ['--net-wrapper']
    try:
        if wrapper:
            if len(argv) < 10 or argv[6] not in ('split', 'native') or argv[7] != '--':
                raise ValueError('Invalid native adapter invocation')
            return net_wrapper(Path(argv[1]), *argv[2:6], argv[8:],
                               split_keytab=argv[6] == 'split')
        if len(argv) < 3:
            raise ValueError('Invalid first-join invocation')
        result = first_join(argv[0], argv[1], argv[2:])
        if DIAGNOSTICS and DIAGNOSTICS.current()['directory_effect'] != 'returned_success':
            diagnostic_result('native_execution', 'first_join_internal_error')
            raise RuntimeError('Native completion receipt is unavailable')
        return result
    except Exception as exc:
        diagnostic_error(exc)
        raise
    finally:
        if DIAGNOSTICS and not wrapper:
            DIAGNOSTICS.publish()


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception:
        print('ALT_PREFLIGHT_FAILURE:domain_join_compatibility_failed first-join credentials or verification failed', file=sys.stderr)
        raise SystemExit(89) from None
