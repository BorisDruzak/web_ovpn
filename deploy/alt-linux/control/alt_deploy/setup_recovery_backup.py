"""Fixed private workstation evidence; no restore or auth-file writes.

The controller supplies only a bound request and the fixed read-only collector.
Production uses root '/' and UID 0; alternate roots exist for isolated fixtures.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import uuid
from pathlib import Path

AUTH_FILES = ('/etc/samba/smb.conf', '/etc/sssd/sssd.conf', '/etc/krb5.conf',
              '/etc/krb5.keytab', '/var/lib/samba/private/secrets.tdb')
MAX_BYTES = 2097152


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False).encode()


def digest(value):
    return hashlib.sha256(encoded(value)).hexdigest()


def _request(request):
    fields = {'schema_version', 'failed_run_id', 'computer_guid', 'claim_sha256',
              'machine_uuid', 'hostname', 'facts', 'snapshot_sha256', 'source_sha256'}
    if (not isinstance(request, dict) or set(request) != fields
            or type(request['schema_version']) is not int or request['schema_version'] != 1
            or not isinstance(request['failed_run_id'], str)
            or not re.fullmatch('setup-run-[0-9a-f]{32}', request['failed_run_id'])
            or any(not isinstance(request[key], str) or not re.fullmatch('[0-9a-f]{64}', request[key])
                   for key in ('claim_sha256', 'snapshot_sha256', 'source_sha256'))
            or not isinstance(request['hostname'], str)
            or not re.fullmatch(r'(?=.{1,15}$)(?:lin|alt|win|deb)-[a-z]+[0-9]?-(?:pc[1-9][0-9]*)', request['hostname'])):
        raise ValueError('Invalid fixed backup request')
    for key in ('computer_guid', 'machine_uuid'):
        if str(uuid.UUID(request[key])) != request[key] or uuid.UUID(request[key]).int == 0:
            raise ValueError('Invalid backup identity')
    facts = request['facts']
    if (not isinstance(facts, dict) or digest(facts) != request['snapshot_sha256']
            or facts.get('uuid') != request['machine_uuid'] or facts.get('hostname') != request['hostname']
            or facts.get('clock_synchronized') is not True or facts.get('incompatible_processes') != []
            or not isinstance(facts.get('files'), dict) or set(facts['files']) != set(AUTH_FILES)):
        raise ValueError('Invalid backup snapshot')


def path_for(request, *, root=Path('/')):
    _request(request)
    pair = {key: request[key] for key in ('failed_run_id', 'computer_guid')}
    return root/'var/lib/alt-deploy-recovery'/('backup-' + digest(pair))


def _signature(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns,
            info.st_ctime_ns, info.st_uid, info.st_gid, info.st_mode)


def _ancestry(path, root, owner):
    for ancestor in (path.parent, *path.parent.parents):
        info = ancestor.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != owner or info.st_mode & 0o022:
            raise ValueError('Unsafe backup ancestry')
        if ancestor == root: return
    raise ValueError('Backup outside root')


def _read(path, metadata, *, root, owner, maximum=MAX_BYTES):
    _ancestry(path, root, owner)
    before = path.lstat()
    fields = {'present', 'sha256', 'size', 'uid', 'gid', 'mode'}
    if (not isinstance(metadata, dict) or set(metadata) != fields or metadata['present'] is not True
            or not stat.S_ISREG(before.st_mode) or before.st_uid != owner
            or before.st_size > maximum or before.st_mode & 0o022
            or any(type(metadata[key]) is not int for key in ('size', 'uid', 'gid', 'mode'))
            or (before.st_size, before.st_uid, before.st_gid, stat.S_IMODE(before.st_mode))
               != tuple(metadata[key] for key in ('size', 'uid', 'gid', 'mode'))):
        raise ValueError('Unsafe or changed backup file')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as stream:
        if _signature(os.fstat(stream.fileno())) != _signature(before): raise ValueError('Changed backup file')
        raw = stream.read(maximum + 1)
        if len(raw) > maximum or _signature(os.fstat(stream.fileno())) != _signature(before):
            raise ValueError('Changed backup file')
    if _signature(path.lstat()) != _signature(before) or hashlib.sha256(raw).hexdigest() != metadata['sha256']:
        raise ValueError('Changed backup file')
    return raw


def _sync(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try: os.fsync(fd)
    finally: os.close(fd)


def _write(path, raw, *, mode=0o600, gid=None):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        if gid is not None and os.fstat(stream.fileno()).st_gid != gid:
            os.fchown(stream.fileno(), -1, gid)
        os.fchmod(stream.fileno(), mode)
        stream.write(raw); stream.flush(); os.fsync(stream.fileno())


def _directory(path, owner):
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != owner or stat.S_IMODE(info.st_mode) != 0o700:
        raise ValueError('Private backup directory required')


def _json(path, *, root, owner):
    before = path.lstat()
    _ancestry(path, root, owner)
    if not stat.S_ISREG(before.st_mode) or before.st_uid != owner or stat.S_IMODE(before.st_mode) != 0o600 or before.st_size > 131072:
        raise ValueError('Protected backup document required')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result: raise ValueError('Duplicate backup field')
            result[key] = value
        return result
    with os.fdopen(fd, 'rb') as stream:
        if _signature(os.fstat(stream.fileno())) != _signature(before): raise ValueError('Changed backup document')
        raw = stream.read(131073)
        if len(raw) > 131072 or _signature(os.fstat(stream.fileno())) != _signature(before):
            raise ValueError('Changed backup document')
    if _signature(path.lstat()) != _signature(before): raise ValueError('Changed backup document')
    return json.loads(raw, object_pairs_hook=unique)


def _verify(request, *, root, owner, marker):
    leaf = path_for(request, root=root)
    _ancestry(leaf, root, owner)
    for path in (leaf.parent, leaf, leaf/'files'): _directory(path, owner)
    manifest = _json(leaf/'manifest.json', root=root, owner=owner)
    if manifest != {'schema_version': 1, 'request': request, 'backup_id': leaf.name}:
        raise ValueError('Backup manifest mismatch')
    expected = set()
    for index, source in enumerate(AUTH_FILES):
        metadata = request['facts']['files'][source]
        if metadata == {'present': False}: continue
        expected.add(str(index))
        _read(leaf/'files'/str(index), metadata, root=root, owner=owner)
    if {path.name for path in (leaf/'files').iterdir()} != expected:
        raise ValueError('Unexpected backup files')
    receipt = {key: request[key] for key in ('schema_version', 'failed_run_id', 'computer_guid',
        'claim_sha256', 'machine_uuid', 'snapshot_sha256', 'source_sha256')}
    receipt.update(backup_id=leaf.name, manifest_sha256=digest(manifest))
    if marker and _json(leaf/'verified.json', root=root, owner=owner) != receipt:
        raise ValueError('Verified backup marker mismatch')
    if {path.name for path in leaf.iterdir()} != {'files', 'manifest.json'} | ({'verified.json'} if marker else set()):
        raise ValueError('Unexpected backup evidence')
    return receipt


def verify(request, *, root=Path('/'), owner=0):
    if os.geteuid() != owner or not root.is_absolute(): raise ValueError('Root backup required')
    receipt = _verify(request, root=root, owner=owner, marker=True)
    _sync(path_for(request, root=root))
    return receipt


def create(request, *, collect=None, root=Path('/'), owner=0):
    if os.geteuid() != owner or not root.is_absolute() or collect is None:
        raise ValueError('Fixed root collector required')
    leaf = path_for(request, root=root)
    if collect() != request['facts']: raise ValueError('Workstation snapshot changed')
    _ancestry(leaf.parent, root, owner)
    try: leaf.parent.mkdir(mode=0o700)
    except FileExistsError: pass
    _directory(leaf.parent, owner)
    # Exclusive leaf is retained after every failure; never overwrite/retry.
    try: leaf.mkdir(mode=0o700)
    except FileExistsError: raise ValueError('Backup attempt already exists') from None
    try:
        return _populate(request, collect=collect, root=root, owner=owner, leaf=leaf)
    except Exception:
        # A visible ready marker after a failed final sync is not success.
        # Keep a separate failure exclusion, even if its fsync also fails.
        try:
            _write(leaf/'failed.json', encoded({'schema_version': 1, 'error_code': 'recovery_backup_failed'}))
            _sync(leaf)
        except Exception: pass
        raise


def _populate(request, *, collect, root, owner, leaf):
    (leaf/'files').mkdir(mode=0o700)
    for index, source in enumerate(AUTH_FILES):
        metadata = request['facts']['files'][source]
        if metadata == {'present': False}: continue
        raw = _read(root/source.lstrip('/'), metadata, root=root, owner=owner)
        _write(leaf/'files'/str(index), raw, mode=metadata['mode'], gid=metadata['gid'])
    _write(leaf/'manifest.json', encoded({'schema_version': 1, 'request': request, 'backup_id': leaf.name}))
    if collect() != request['facts']: raise ValueError('Workstation snapshot changed during backup')
    _sync(leaf/'files'); _sync(leaf)
    for parent in (leaf.parent, *leaf.parent.parents):
        _sync(parent)
        if parent == root: break
    receipt = _verify(request, root=root, owner=owner, marker=False)
    _write(leaf/'verified.json', encoded(receipt)); _sync(leaf)
    return verify(request, root=root, owner=owner)
