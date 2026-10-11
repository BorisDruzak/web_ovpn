"""Exclusive backup-seeded offline rehearsal; no live authentication writes.

Dependencies are fixed trusted controller sources, not request-supplied code.
Alternate roots/owners/runners exist only for isolated test fixtures.
"""
from __future__ import annotations

import os
from pathlib import Path
import re
import tempfile


def _request(request, *, backup, native=None):
    fields = {'schema_version', 'backup_request', 'backup_receipt', 'metadata',
              'credential_sha256', 'source_sha256'}
    if (not isinstance(request, dict) or set(request) != fields
            or type(request['schema_version']) is not int or request['schema_version'] != 1
            or any(not isinstance(request[key], str) or not re.fullmatch('[0-9a-f]{64}', request[key])
                   for key in ('credential_sha256', 'source_sha256'))):
        raise ValueError('Invalid rehearsal request')
    backup._request(request['backup_request'])
    meta = request['metadata']
    if native is not None:
        native.validate_metadata(meta)
    if not isinstance(meta, dict) or meta.get('hostname') != request['backup_request']['hostname']:
        raise ValueError('Invalid rehearsal target')
    facts = request['backup_request']['facts']
    samba = facts.get('samba', {})
    if (meta.get('realm', '').upper() != samba.get('realm', '').upper()
            or meta.get('workgroup') != samba.get('workgroup')
            or samba.get('netbios_name') != meta['hostname'].upper()
            or facts.get('samba_version') not in ('4.21.9', '4.21.9-alt4.p11.1')):
        raise ValueError('Unreviewed native metadata or version')


def path_for(request, *, backup, root=Path('/')):
    _request(request, backup=backup)
    pair = {key: request['backup_request'][key] for key in ('failed_run_id', 'computer_guid')}
    return root/'var/lib/alt-deploy-recovery'/('rehearsal-' + backup.digest(pair))


def _receipt(request, *, backup):
    evidence = request['backup_receipt']
    return dict(evidence, status='local_rehearsal_verified', request_sha256=backup.digest(request),
                credential_sha256=request['credential_sha256'],
                rehearsal_source_sha256=request['source_sha256'],
                metadata_sha256=backup.digest(request['metadata']))


def _validate_backup(request, *, backup, collect, root, owner):
    original = request['backup_request']
    if collect() != original['facts'] or backup.verify(original, root=root, owner=owner) != request['backup_receipt']:
        raise ValueError('Changed rehearsal backup or snapshot')


def verify(request, *, backup, collect, root=Path('/'), owner=0):
    if os.geteuid() != owner or collect is None or not root.is_absolute():
        raise ValueError('Fixed root rehearsal required')
    leaf = path_for(request, backup=backup, root=root)
    backup._ancestry(leaf, root, owner)
    backup._directory(leaf.parent, owner); backup._directory(leaf, owner)
    if {path.name for path in leaf.iterdir()} != {'request.json', 'verified.json'}:
        raise ValueError('Incomplete or failed rehearsal')
    if backup._json(leaf/'request.json', root=root, owner=owner) != request:
        raise ValueError('Rehearsal request mismatch')
    receipt = _receipt(request, backup=backup)
    if backup._json(leaf/'verified.json', root=root, owner=owner) != receipt:
        raise ValueError('Rehearsal evidence mismatch')
    _validate_backup(request, backup=backup, collect=collect, root=root, owner=owner)
    backup._sync(leaf)
    return receipt


def create(request, password, *, backup, native, collect, runner, root=Path('/'), owner=0):
    if (os.geteuid() != owner or collect is None or runner is None or not root.is_absolute()
            or not isinstance(password, str) or not re.fullmatch(r'Aa9![A-Za-z0-9_-]{64}', password)):
        raise ValueError('Fixed root rehearsal required')
    _request(request, backup=backup, native=native)
    _validate_backup(request, backup=backup, collect=collect, root=root, owner=owner)
    leaf = path_for(request, backup=backup, root=root)
    backup._ancestry(leaf, root, owner); backup._directory(leaf.parent, owner)
    # Reservation is permanent, including an interrupted native process.  Never
    # replace its receipt or reuse the leaf after any error.
    try: leaf.mkdir(mode=0o700)
    except FileExistsError: raise ValueError('Rehearsal attempt already exists') from None
    try:
        backup._write(leaf/'request.json', backup.encoded(request))
        backup._sync(leaf); backup._sync(leaf.parent)
        _run(request, password, backup=backup, native=native, runner=runner, root=root, owner=owner, leaf=leaf)
        _validate_backup(request, backup=backup, collect=collect, root=root, owner=owner)
        receipt = _receipt(request, backup=backup)
        backup._write(leaf/'verified.json', backup.encoded(receipt)); backup._sync(leaf)
        return verify(request, backup=backup, collect=collect, root=root, owner=owner)
    except Exception:
        try:
            backup._write(leaf/'failed.json', backup.encoded({'schema_version': 1, 'error_code': 'recovery_rehearsal_failed'}))
            backup._sync(leaf)
        except Exception: pass
        raise ValueError('Offline rehearsal failed') from None


def _run(request, password, *, backup, native, runner, root, owner, leaf):
    meta = request['metadata']
    original = request['backup_request']
    source = '/var/lib/samba/private/secrets.tdb'
    metadata = original['facts']['files'][source]
    if metadata.get('present') is not True:
        raise ValueError('Original secrets backup required')
    index = backup.AUTH_FILES.index(source)
    seed = backup._read(backup.path_for(original, root=root)/'files'/str(index), metadata, root=root, owner=owner)
    # All native-derived secrets live inside a temporary root-private directory;
    # deletion failure prevents the verified receipt.  Interrupted attempts retain
    # private temporary state and are excluded from automatic reuse.
    with tempfile.TemporaryDirectory(prefix='sandbox-', dir=leaf) as directory:
        work = Path(directory); work.chmod(0o700)
        for name in ('private', 'state', 'cache', 'lock', 'pid', 'logs', 'ncalrpc', 'winbind'):
            (work/name).mkdir(mode=0o700)
        backup._write(work/'private/secrets.tdb', seed)
        backup._write(work/'smb.conf', native.sandbox_config(meta).encode('utf-8'))
        def run(operation, input_text=None):
            rc, stdout, _ = runner(native.sandbox_command(work, meta, operation, owner=owner),
                environment={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C.UTF-8'}, input_text=input_text, timeout=20)
            if (rc or not isinstance(stdout, str) or len(stdout.encode('utf-8')) > 16384):
                raise ValueError('Native rehearsal failed')
            return stdout
        auth = f"username = {meta['hostname'].upper()}$\npassword = {password}\ndomain = {meta['workgroup']}\n"
        blob = run('compose', auth)
        if not re.fullmatch(r'[A-Za-z0-9+/]+={0,2}\n?', blob):
            raise ValueError('Invalid offline native blob')
        run('import', blob)
        native.validate_native_metadata(run('metadata'), meta)
        run('password', password)
        if run('password_check', password) != 'true\n': raise ValueError('Native password mismatch')
        native.validate_native_metadata(run('metadata'), meta)
        run('keytab')
        native.validate_rehearsal_keytab(run('keytab_list'), meta)
