"""Fixed target protocol: verified private backup, one native local transition."""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess

TARGET_ROOT = '/var/lib/alt-deploy-partial-local'
TARGET_LIMIT = 2*1024*1024


def _canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(',', ':'), allow_nan=False).encode()


def _digest(value): return hashlib.sha256(_canonical(value)).hexdigest()


def _collect(request, **kwargs):
    # Production embeds the exact trusted probe source in the same isolated
    # interpreter; controller tests import the canonical read-only package.
    collector = globals().get('collect')
    if collector is None:
        from alt_deploy_backup.partial_local_probe import collect as collector
    return collector(request, **kwargs)


def _private_directory(path, owner, *, create=False):
    if create:
        path.mkdir(mode=0o700)
    for parent in path.parents:
        if not stat.S_ISDIR(parent.lstat().st_mode): raise ValueError('Unsafe backup ancestor')
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != owner or stat.S_IMODE(info.st_mode) != 0o700:
        raise ValueError('Unsafe private backup')


def _sync(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try: os.fsync(fd)
    finally: os.close(fd)


def _write(path, raw):
    if len(raw) > TARGET_LIMIT: raise ValueError('Backup file limit')
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw); stream.flush(); os.fsync(stream.fileno())
    _sync(path.parent)


def _read(path, owner):
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_uid != owner or stat.S_IMODE(before.st_mode) != 0o600:
        raise ValueError('Unsafe private backup file')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        raw = stream.read(TARGET_LIMIT+1)
        after = path.lstat()
        signature = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        if (signature(before) != signature(info) or signature(info) != signature(after)
                or len(raw) > TARGET_LIMIT or len(raw) != info.st_size): raise ValueError('Backup changed')
    return raw


def _request(request):
    if (set(request) != {'schema_version', 'claim_key', 'plan_sha256', 'machine', 'before'}
            or type(request['schema_version']) is not int or request['schema_version'] != 1
            or any(not isinstance(request[k], str) or not re.fullmatch('[0-9a-f]{64}', request[k])
                   for k in ('claim_key', 'plan_sha256'))
            or request['before'].get('auth_scheme') != 'ad' or request['before'].get('domain') != request['machine']['domain']
            or request['before'].get('uuid') != request['machine']['uuid']
            or request['before'].get('hostname') != request['machine']['hostname']): raise ValueError('Invalid fixed target request')


def _backup_path(root, claim): return root/TARGET_ROOT.lstrip('/')/claim


def _verify_backup(request, directory, owner):
    _private_directory(directory, owner)
    _private_directory(directory/'files', owner)
    manifest = json.loads(_read(directory/'manifest.json', owner))
    if (set(manifest) != {'schema_version', 'claim_key', 'plan_sha256', 'before', 'files'}
            or manifest['schema_version'] != 1 or manifest['claim_key'] != request['claim_key']
            or manifest['plan_sha256'] != request['plan_sha256'] or manifest['before'] != request['before']):
        raise ValueError('Backup request differs')
    expected = {}
    for name, record in request['before']['files'].items():
        if record.get('present') and record.get('kind') == 'file':
            filename = hashlib.sha256(name.encode()).hexdigest()+'.bin'
            raw = _read(directory/'files'/filename, owner)
            if len(raw) != record['size'] or hashlib.sha256(raw).hexdigest() != record['sha256']:
                raise ValueError('Backup contents differ')
            expected[name] = filename
    if manifest['files'] != expected or {p.name for p in (directory/'files').iterdir()} != set(expected.values()):
        raise ValueError('Backup inventory differs')
    return manifest


def _source_bytes(root, name, record):
    if not name.startswith(('/etc/', '/usr/lib/systemd/system/', '/lib/systemd/system/', '/var/lib/samba/private/')) or '..' in Path(name).parts:
        raise ValueError('Unsupported forensic path')
    path = root/name.lstrip('/')
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode): raise ValueError('Backup source redirected')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        raw = stream.read(TARGET_LIMIT+1)
    after = path.lstat()
    signature = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
    if (signature(before) != signature(info) or signature(info) != signature(after) or len(raw) != record['size']
            or len(raw) > TARGET_LIMIT or hashlib.sha256(raw).hexdigest() != record['sha256']
            or info.st_uid != record['uid'] or info.st_gid != record['gid']
            or stat.S_IMODE(info.st_mode) != record['mode']): raise ValueError('Backup source changed')
    return raw


def _verify_after(request, after, before_nss, after_nss):
    before = request['before']
    for key in ('schema_version', 'uuid', 'hostname', 'boot_id', 'tools', 'local_admin', 'local_accounts_sha256', 'goa', 'services'):
        if after[key] != before[key]: raise ValueError('Unexpected native effect')
    if after['auth_scheme'] != 'local' or after['domain'] != '' or after['clock_synchronized'] is not True:
        raise ValueError('Local authentication not verified')
    links = {'/etc/pam.d/'+name: name+'-local' for name in ('system-auth', 'system-auth-use_first_pass', 'system-policy')}
    if set(before['files']) != set(after['files']): raise ValueError('Unexpected file inventory')
    for name, record in before['files'].items():
        if name in links:
            expected = dict(record, target=links[name])
            if after['files'][name] != expected: raise ValueError('Local PAM link differs')
        elif name != '/etc/nsswitch.conf' and after['files'][name] != record:
            raise ValueError('Unexpected authentication file change')
    old = before_nss.decode().splitlines(keepends=True)
    new = after_nss.decode().splitlines(keepends=True)
    keys = {'passwd': ['files'], 'group': ['files'], 'shadow': ['tcb', 'files']}
    def selected(line): return line.partition(':')[0].strip() in keys and ':' in line
    if [line for line in old if not selected(line)] != [line for line in new if not selected(line)]:
        raise ValueError('Other NSS settings changed')
    for key, wanted in keys.items():
        values = [line.partition(':')[2].split('#', 1)[0].split() for line in new if line.partition(':')[0].strip() == key]
        if values != [wanted]: raise ValueError('Local NSS sources differ')
    nss = after['files']['/etc/nsswitch.conf']
    original_nss = before['files']['/etc/nsswitch.conf']
    if any(nss[k] != original_nss[k] for k in ('kind', 'uid', 'gid', 'mode')): raise ValueError('NSS metadata changed')


def execute(request, *, root=Path('/'), owner=0):
    root = Path(root)
    _request(request)
    before = _collect(request['machine'], root=root, owner=owner)
    if before != request['before']: raise ValueError('Target snapshot changed')
    parent = root/TARGET_ROOT.lstrip('/')
    # Fixed public ancestors must already be safe. Only this private namespace
    # and one create-only attempt directory are created by the protocol.
    if not parent.parent.exists():
        if root == Path('/'): raise ValueError('Target state root missing')
        parent.parent.mkdir(parents=True, mode=0o755)
    if not parent.exists() and not parent.is_symlink(): _private_directory(parent, owner, create=True)
    _private_directory(parent, owner)
    directory = _backup_path(root, request['claim_key'])
    if directory.exists() or directory.is_symlink(): raise ValueError('Original target claim already entered')
    _private_directory(directory, owner, create=True); _sync(parent)
    result = {'schema_version': 1, 'claim_key': request['claim_key'], 'plan_sha256': request['plan_sha256'],
              'status': 'unknown_requires_review', 'backup_sha256': None,
              'before_sha256': _digest(before), 'after_sha256': None}
    try:
        _private_directory(directory/'files', owner, create=True)
        files = {}
        for name, record in before['files'].items():
            if record.get('present') and record.get('kind') == 'file':
                filename = hashlib.sha256(name.encode()).hexdigest()+'.bin'
                _write(directory/'files'/filename, _source_bytes(root, name, record))
                files[name] = filename
        manifest = {'schema_version': 1, 'claim_key': request['claim_key'], 'plan_sha256': request['plan_sha256'],
                    'before': before, 'files': files}
        _write(directory/'manifest.json', _canonical(manifest))
        if _verify_backup(request, directory, owner) != manifest: raise ValueError('Backup verification failed')
        result['backup_sha256'] = _digest(manifest)
        if _collect(request['machine'], root=root, owner=owner) != before: raise ValueError('Prewrite snapshot changed')
        _write(directory/'intent.json', _canonical({'schema_version': 1, 'claim_key': request['claim_key'],
            'plan_sha256': request['plan_sha256'], 'backup_sha256': result['backup_sha256'],
            'command': ['/usr/sbin/system-auth', 'write', 'local']}))
        completed = subprocess.run([str(root/'usr/sbin/system-auth'), 'write', 'local'],
            capture_output=True, text=True, timeout=60,
            env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'})
        if completed.returncode or max(len(completed.stdout.encode()), len(completed.stderr.encode())) > 65536:
            raise ValueError('Native local transition incomplete')
        after = _collect(request['machine'], root=root, owner=owner)
        old_nss = _read(directory/'files'/files['/etc/nsswitch.conf'], owner)
        new_nss = _source_bytes(root, '/etc/nsswitch.conf', after['files']['/etc/nsswitch.conf'])
        _verify_after(request, after, old_nss, new_nss)
        result.update(status='successful', after_sha256=_digest(after))
    except Exception:
        pass  # The immutable UNKNOWN receipt deliberately contains no exception/output.
    _write(directory/'result.json', _canonical(result))
    return result


def inspect(request, *, root=Path('/'), owner=0):
    _request(request)
    directory = _backup_path(Path(root), request['claim_key'])
    manifest = _verify_backup(request, directory, owner)
    result = json.loads(_read(directory/'result.json', owner))
    if (set(result) != {'schema_version', 'claim_key', 'plan_sha256', 'status', 'backup_sha256', 'before_sha256', 'after_sha256'}
            or type(result['schema_version']) is not int or result['schema_version'] != 1
            or result['status'] not in ('successful', 'unknown_requires_review')
            or result['claim_key'] != request['claim_key'] or result['plan_sha256'] != request['plan_sha256']
            or result['before_sha256'] != _digest(request['before']) or result['backup_sha256'] != _digest(manifest)):
        raise ValueError('Original target result cannot be verified')
    if result['status'] == 'successful':
        intent = json.loads(_read(directory/'intent.json', owner))
        if intent != {'schema_version': 1, 'claim_key': request['claim_key'], 'plan_sha256': request['plan_sha256'],
                      'backup_sha256': result['backup_sha256'], 'command': ['/usr/sbin/system-auth', 'write', 'local']}:
            raise ValueError('Original target intent differs')
        if not isinstance(result['after_sha256'], str) or not re.fullmatch('[0-9a-f]{64}', result['after_sha256']):
            raise ValueError('Target postcondition digest missing')
    return result
