#!/usr/bin/env python3
"""Readiness and administrator-only scoped API credential provisioning.

Only hashes and owned paths enter the protected receipt. Secrets never enter
argv/stdout, tracked configuration, or legacy service-token defaults.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import sys
import tempfile
import time
import uuid
import unicodedata


class DeploymentError(Exception):
    pass


def readiness(*, settings, schema_check, client):
    if not settings.workstations_enabled:
        return {'status': 'disabled'}
    try:
        schema_check()
    except Exception:
        raise DeploymentError('workstations_schema_not_ready') from None
    try:
        client = client.with_deadline(time.monotonic() + 270)
        value = client.call('status', {}, request_id=str(uuid.uuid4()))
        if value.get('observer_configured') is not True or value.get('execution_mode') != 'sequential':
            raise DeploymentError('workstations_gateway_not_ready')
        for source in ('ad', 'dns'):
            value = client.call('directory.snapshot', {'source': source}, request_id=str(uuid.uuid4()))
            if value.get('schema_version') != 1 or value.get('complete') is not True:
                raise DeploymentError('workstations_readiness_incomplete')
    except DeploymentError:
        raise
    except Exception:
        raise DeploymentError('workstations_gateway_not_ready') from None
    return {'status': 'ready', 'schema': True, 'gateway': True, 'readonly_sources': True}


def _safe_path(path):
    path = Path(path)
    if not path.is_absolute() or any(part.is_symlink() for part in (path, *path.parents)):
        raise DeploymentError('workstations_file_unsafe')
    if not path.parent.is_dir():
        raise DeploymentError('workstations_file_unsafe')
    if path.exists() and (not path.is_file() or path.stat().st_size > 65536):
        raise DeploymentError('workstations_file_unsafe')
    return path


def _private_read(path, uid):
    info = path.lstat()
    if os.name != 'nt' and (info.st_uid not in (0, uid) or info.st_mode & 0o077):
        raise DeploymentError('workstations_file_unsafe')
    return path.read_text(encoding='utf-8')


def _atomic(path, value, uid, gid):
    descriptor, name = tempfile.mkstemp(prefix='.workstations-', dir=path.parent)
    try:
        os.fchmod(descriptor, 0o600)
        if os.name != 'nt': os.fchown(descriptor, uid, gid)
        with os.fdopen(descriptor, 'w', encoding='utf-8') as stream:
            stream.write(value); stream.flush(); os.fsync(stream.fileno())
        os.replace(name, path)
        if os.name != 'nt':
            directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try: os.fsync(directory)
            finally: os.close(directory)
    finally:
        if os.path.exists(name): os.unlink(name)


def provision_credential(*, registry, token_output, receipt, actor, grants, uid, gid):
    allowed = {'workstations:' + value for value in ('read', 'plan', 'apply', 'link', 'diagnose')}
    if (not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_.:-]{0,119}', actor) or not grants
            or not set(grants) <= allowed or len(set(grants)) != len(grants)):
        raise DeploymentError('workstations_grants_invalid')
    registry, token_output, receipt = map(_safe_path, (registry, token_output, receipt))
    if len({registry, token_output, receipt}) != 3:
        raise DeploymentError('workstations_file_unsafe')
    # A protected parent and root administrator own provisioning. Serialize
    # registry updates so concurrent actor enrollment cannot lose records.
    lock_path = _safe_path(registry.parent / '.workstations-api.lock')
    descriptor = os.open(lock_path, os.O_RDWR | os.O_CREAT | getattr(os, 'O_NOFOLLOW', 0), 0o600)
    try:
        if os.name != 'nt':
            import fcntl
            fcntl.flock(descriptor, fcntl.LOCK_EX)
        try:
            records = json.loads(_private_read(registry, uid)) if registry.exists() else []
            if not isinstance(records, list) or len(records) > 100:
                raise ValueError()
            actors, hashes = set(), set()
            for row in records:
                if (not isinstance(row, dict) or set(row) != {'token_hash', 'actor', 'grants'}
                        or not re.fullmatch(r'[0-9a-f]{64}', row['token_hash'])
                        or not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_.:-]{0,119}', row['actor'])
                        or not isinstance(row['grants'], list) or not set(row['grants']) <= allowed
                        or row['actor'] in actors or row['token_hash'] in hashes):
                    raise ValueError()
                actors.add(row['actor']); hashes.add(row['token_hash'])
        except (ValueError, TypeError, KeyError):
            raise DeploymentError('workstations_registry_invalid') from None
        existing = next((row for row in records if row['actor'] == actor), None)
        if existing:
            if (not token_output.exists() or sorted(existing['grants']) != sorted(grants)
                    or hashlib.sha256(_private_read(token_output, uid).strip().encode()).hexdigest() != existing['token_hash']):
                raise DeploymentError('workstations_credential_collision')
            digest = existing['token_hash']
            if receipt.exists():
                try:
                    prior = json.loads(_private_read(receipt, uid))
                    if (prior.get('actor') != actor or prior.get('token_hash') != digest
                            or prior.get('owned_paths') != [str(token_output), str(registry)]):
                        raise ValueError()
                except (ValueError, TypeError, AttributeError):
                    raise DeploymentError('workstations_credential_collision') from None
        else:
            if token_output.exists() or receipt.exists() or len(records) >= 100:
                raise DeploymentError('workstations_credential_collision')
            token = secrets.token_urlsafe(48)
            digest = hashlib.sha256(token.encode()).hexdigest()
            _atomic(token_output, token + '\n', uid, gid)
            records.append({'actor': actor, 'grants': sorted(grants), 'token_hash': digest})
            _atomic(registry, json.dumps(records, sort_keys=True) + '\n', uid, gid)
        _atomic(receipt, json.dumps({'schema_version': 1, 'actor': actor, 'grants': sorted(grants),
            'token_hash': digest, 'owned_paths': [str(token_output), str(registry)]}, sort_keys=True) + '\n', 0 if os.name != 'nt' and os.geteuid() == 0 else uid, gid)
    finally:
        os.close(descriptor)


def load_environment(path):
    path = _safe_path(path)
    info = path.stat()
    if os.name != 'nt' and (info.st_uid != 0 or stat.S_IMODE(info.st_mode) & 0o027):
        raise DeploymentError('workstations_environment_unsafe')
    values = {}
    content = path.read_text(encoding='utf-8')
    if any(c not in '\t\r\n ' and unicodedata.category(c) in {'Cc', 'Cf', 'Cs', 'Zl', 'Zp', 'Zs'} for c in content):
        raise DeploymentError('workstations_environment_invalid')
    for line in content.split('\n'):
        line = line.strip(' \t\r')
        if not line or line.startswith(('#', ';')): continue
        key, separator, value = line.partition('='); key, value = key.strip(), value.strip()
        if not separator or not re.fullmatch('[A-Za-z_][A-Za-z0-9_]*', key) or key in values:
            raise DeploymentError('workstations_environment_invalid')
        if value.startswith(('"', "'")):
            if len(value) < 2 or value[-1] != value[0] or value[0] in value[1:-1]:
                raise DeploymentError('workstations_environment_invalid')
            value = value[1:-1]
        if '\\' in value or any(ord(c) < 32 for c in value):
            raise DeploymentError('workstations_environment_invalid')
        values[key] = value
    os.environ.update(values)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--app-dir', type=Path, default=Path('/opt/openvpn-web'))
    parser.add_argument('--env-file', type=Path)
    parser.add_argument('--initialize-schema', action='store_true')
    parser.add_argument('--provision-credential', action='store_true')
    parser.add_argument('--registry', type=Path)
    parser.add_argument('--token-output', type=Path)
    parser.add_argument('--receipt', type=Path)
    parser.add_argument('--actor')
    parser.add_argument('--grants', nargs='+')
    args = parser.parse_args()
    try:
        if args.provision_credential:
            import pwd
            if os.geteuid() != 0: raise DeploymentError('workstations_administrator_required')
            if not all((args.registry, args.token_output, args.receipt, args.actor, args.grants)):
                raise DeploymentError('workstations_provisioning_invalid')
            account = pwd.getpwnam('openvpn-web')
            provision_credential(registry=args.registry, token_output=args.token_output, receipt=args.receipt,
                actor=args.actor, grants=args.grants, uid=account.pw_uid, gid=account.pw_gid)
            print(json.dumps({'status': 'ready', 'scoped_credential': True})); return 0
        if args.env_file: load_environment(args.env_file)
        sys.path.insert(0, str(args.app_dir.resolve()))
        from app.config import get_settings
        from app.db import get_engine
        from app.workstations.schema import ensure_schema, check_schema
        from app.workstations.client import WorkstationsClient
        settings = get_settings()
        if args.initialize_schema: ensure_schema(get_engine())
        result = readiness(settings=settings, schema_check=lambda: check_schema(get_engine()), client=WorkstationsClient(settings))
        print(json.dumps(result, sort_keys=True))
        return 77 if result['status'] == 'disabled' else 0
    except Exception as exc:
        print(json.dumps({'status': 'error', 'code': str(exc) if isinstance(exc, DeploymentError) else 'workstations_deployment_failed'}))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
