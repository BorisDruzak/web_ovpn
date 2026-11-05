#!/usr/bin/python3
"""Root-created full/scoped verification snapshots, never rollout permission."""
import fcntl
import importlib.util
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import stat
import tempfile
import time
import uuid


def load_module(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


gate = load_module('release_checkpoint_support', 'verification_checkpoint.py')
policy = load_module('release_selection_policy', 'verification_policy.py')
HEX = re.compile('[0-9a-f]{64}')
IDENTITY = {'schema', 'suite', 'source_sha256', 'directories_sha256', 'environment_sha256', 'policy_sha256'}
FIELDS = IDENTITY | {'manifest', 'directories', 'created_at', 'result', 'plan', 'parent', 'foundation', 'attempt_id'}
PLAN_FIELDS = {'mode', 'reason', 'components', 'affected', 'changed_paths', 'targets'}


def validate_manifest(rows):
    if not isinstance(rows, list) or not rows or len(rows) > 100000:
        raise ValueError('verification_evidence_invalid')
    names = []
    for row in rows:
        if (not isinstance(row, list) or len(row) != 3 or not isinstance(row[0], str)
                or not row[0] or '\\' in row[0] or any(ord(c) < 32 or ord(c) == 127 for c in row[0])
                or PurePosixPath(row[0]).is_absolute() or '..' in PurePosixPath(row[0]).parts
                or str(PurePosixPath(row[0])) != row[0]
                or any(p in gate.IGNORED for p in PurePosixPath(row[0]).parts)
                or type(row[1]) is not int or not 0 <= row[1] <= 0o777 or row[1] & 0o022
                or not isinstance(row[2], str) or not HEX.fullmatch(row[2])):
            raise ValueError('verification_evidence_invalid')
        names.append(row[0])
    if names != sorted(set(names)):
        raise ValueError('verification_evidence_invalid')


def validate_directories(rows, files):
    if not isinstance(rows, list) or not rows or len(rows) > 100000:
        raise ValueError('verification_evidence_invalid')
    names = []
    for row in rows:
        if (not isinstance(row, list) or len(row) != 2 or not isinstance(row[0], str) or not row[0]
                or '\\' in row[0] or any(ord(c) < 32 for c in row[0]) or PurePosixPath(row[0]).is_absolute()
                or '..' in PurePosixPath(row[0]).parts or str(PurePosixPath(row[0])) != row[0]
                or any(p in gate.IGNORED for p in PurePosixPath(row[0]).parts)
                or type(row[1]) is not int or not 0 <= row[1] <= 0o777 or row[1] & 0o022):
            raise ValueError('verification_evidence_invalid')
        names.append(row[0])
    if names != sorted(set(names)) or names[0] != '.':
        raise ValueError('verification_evidence_invalid')
    dirs = set(names)
    if any(str(PurePosixPath(p).parent) not in dirs for p in names if p != '.'):
        raise ValueError('verification_evidence_invalid')
    if any(p in dirs or str(PurePosixPath(p).parent) not in dirs for p, _, _ in files):
        raise ValueError('verification_evidence_invalid')


def snapshot(source, owner):
    value = gate.source_snapshot(source, owner)
    rows = [list(row) for row in value['files']]
    directories = [list(row) for row in value['directories']]
    validate_manifest(rows); validate_directories(directories, rows)
    return rows, directories


def unique_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError('verification_evidence_invalid')
        value[key] = item
    return value


class EvidenceStore:
    def __init__(self, cache, owner):
        self.cache, self.owner = cache, owner
        self.baseline_reason = 'no_matching_verified_baseline'
        self.validated = {}

    def read(self, path, limit=4*1024*1024):
        try:
            info = gate.checked(path, self.owner, mode=0o600)
        except FileNotFoundError:
            return None
        if info.st_size > limit:
            raise ValueError('verification_evidence_invalid')
        try:
            return json.loads(path.read_text(), object_pairs_hook=unique_object)
        except (UnicodeError, json.JSONDecodeError):
            raise ValueError('verification_evidence_invalid') from None

    def write(self, path, value):
        if path.exists() or path.is_symlink():
            gate.checked(path, self.owner, mode=0o600)
        temporary = None
        try:
            with tempfile.NamedTemporaryFile(mode='w', dir=path.parent, prefix='.release-', delete=False) as stream:
                temporary = Path(stream.name)
                os.fchmod(stream.fileno(), 0o600)
                json.dump(value, stream, sort_keys=True, allow_nan=False)
                stream.flush(); os.fsync(stream.fileno())
            os.replace(temporary, path); temporary = None
            descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try: os.fsync(descriptor)
            finally: os.close(descriptor)
        finally:
            if temporary is not None: temporary.unlink(missing_ok=True)

    def remove(self, path):
        if path.exists() or path.is_symlink():
            gate.checked(path, self.owner, mode=0o600); path.unlink()
            descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try: os.fsync(descriptor)
            finally: os.close(descriptor)

    def blocked(self, identity):
        path = self.cache/('release-blocked-'+gate.digest(identity)+'.json')
        present = path.exists() or path.is_symlink()
        if present: self.read(path, 512)
        return present

    def family_blocked(self, key):
        path = self.cache/('release-family-blocked-'+key+'.json')
        present = path.exists() or path.is_symlink()
        if present: self.read(path, 512)
        return present

    def pointer(self, path):
        value = self.read(path, 512)
        if (not isinstance(value, dict) or set(value) != {'schema', 'proof'} or type(value['schema']) is not int
                or value['schema'] != 2 or not isinstance(value['proof'], str) or not HEX.fullmatch(value['proof'])):
            raise ValueError('verification_receipt_missing_or_invalid')
        return value['proof']

    def raw_proof(self, key, identity, now):
        if not isinstance(key, str) or not HEX.fullmatch(key):
            raise ValueError('verification_evidence_invalid')
        gate.checked(self.cache/'.release-proofs', self.owner, directory=True, mode=0o700)
        value = self.read(self.cache/'.release-proofs'/(key+'.json'))
        if not isinstance(value, dict) or set(value) != FIELDS or gate.digest(value) != key:
            raise ValueError('verification_evidence_invalid')
        if (type(value['schema']) is not int or value['schema'] != 2 or value['suite'] != 'alt-release-v2'
                or value['result'] != 'passed'
                or not isinstance(value['attempt_id'], str) or not re.fullmatch('[0-9a-f]{32}', value['attempt_id'])
                or type(value['created_at']) not in (int, float) or not math.isfinite(value['created_at'])
                or not 0 < value['created_at'] <= now):
            raise ValueError('verification_evidence_stale')
        if value['environment_sha256'] != identity['environment_sha256']:
            raise ValueError('verification_environment_changed')
        if value['policy_sha256'] != identity['policy_sha256']:
            raise ValueError('verification_policy_changed')
        rows = value['manifest']
        validate_manifest(rows)
        validate_directories(value['directories'], rows)
        if gate.digest(rows) != value['source_sha256'] or gate.digest(value['directories']) != value['directories_sha256']:
            raise ValueError('verification_evidence_invalid')
        if self.blocked({k: value[k] for k in IDENTITY}):
            raise ValueError('verification_evidence_revoked')
        plan = value['plan']
        if not isinstance(plan, dict) or set(plan) != PLAN_FIELDS or plan['mode'] not in ('full', 'selective'):
            raise ValueError('verification_evidence_invalid')
        return value

    def proof(self, key, identity, now):
        """Validate every immutable ancestor, including revocation and scope."""
        chain, seen, cursor = [], set(), key
        while True:
            if cursor in seen or len(chain) >= 4096:
                raise ValueError('verification_evidence_chain_invalid')
            seen.add(cursor)
            node = self.raw_proof(cursor, identity, now)
            chain.append((cursor, node))
            if node['plan']['mode'] == 'full': break
            cursor = node['parent']
        foundation_key, foundation = chain[-1]
        plan = foundation['plan']
        if (foundation['parent'] is not None or foundation['foundation'] is not None
                or plan['targets'] != policy.full_targets() or plan['components'] or plan['affected']
                or self.family_blocked(foundation_key)):
            raise ValueError('verification_evidence_invalid')
        for index in range(len(chain)-2, -1, -1):
            _, child = chain[index]; _, parent = chain[index+1]
            expected = policy.select(parent['manifest'], child['manifest'],
                before_dirs=parent['directories'], after_dirs=child['directories'])
            if child['foundation'] != foundation_key or expected != child['plan'] or expected['mode'] != 'selective':
                raise ValueError('verification_evidence_invalid')
        self.validated.update(chain)
        return chain[0][1]

    def lookup(self, identity, now):
        key = self.pointer(self.cache/('release-'+gate.digest(identity)+'.json'))
        node = self.proof(key, identity, now)
        if any(node[k] != identity[k] for k in IDENTITY):
            raise ValueError('verification_receipt_missing_or_invalid')
        return key, node


def prior(store, identity, now):
    try:
        key = store.pointer(store.cache/'release-baseline.json')
        return key, store.proof(key, identity, now)
    except FileNotFoundError:
        return None, None
    except ValueError as error:
        if str(error) == 'verification_path_unsafe': raise
        store.baseline_reason = {'verification_environment_changed': 'environment_changed',
            'verification_policy_changed': 'selection_policy_changed'}.get(str(error), 'no_matching_verified_baseline')
        return None, None


def decision(identity, rows, directories, parent, *, full, reason='no_matching_verified_baseline', source=None):
    if parent is None:
        plan = policy.select([], rows, full=True)
        plan['reason'] = 'forced_full' if full else reason
        plan['changed_paths'] = []  # No trusted comparison exists yet.
        return plan
    return policy.select(parent['manifest'], rows, full=full, source=source,
        before_dirs=parent['directories'], after_dirs=directories)


def verify_release(source, cache, environment, execute, *, resume=False, full=False,
                   plan_only=False, owner=0, now=None):
    for original in (Path(source), Path(cache)):
        for path in (original, *original.parents):
            try:
                if stat.S_ISLNK(path.lstat().st_mode): raise ValueError('verification_path_unsafe')
            except FileNotFoundError: pass
    source, cache = Path(os.path.abspath(source)), Path(os.path.abspath(cache))
    if source.is_relative_to(cache) or cache.is_relative_to(source):
        raise ValueError('verification_cache_source_overlap')
    clock = time.time if now is None else lambda: now
    env = environment if callable(environment) else lambda: environment
    rows, directories = snapshot(source, owner)
    identity = {'schema': 2, 'suite': 'alt-release-v2', 'source_sha256': gate.digest(rows),
                'directories_sha256': gate.digest(directories),
                'environment_sha256': gate.digest(env()), 'policy_sha256': policy.signature(source)}
    store = EvidenceStore(cache, owner)
    if cache.exists() or cache.is_symlink():
        gate.checked(cache, owner, directory=True, mode=0o700)
    if plan_only:
        if resume: raise ValueError('verification_plan_cannot_resume')
        _, parent = prior(store, identity, clock()) if cache.exists() else (None, None)
        return dict(decision(identity, rows, directories, parent, full=full, reason=store.baseline_reason, source=source),
                    verification='planned', rollout_authorized=False)
    if not cache.exists(): cache.mkdir(mode=0o700)
    gate.checked(cache, owner, directory=True, mode=0o700)
    descriptor = os.open(cache/'.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        gate.checked(cache/'.lock', owner, mode=0o600)
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        # Re-read source and environment under the native lock. Planning is not
        # execution authority, including when another verifier has just finished.
        if snapshot(source, owner) != (rows, directories) or gate.digest(env()) != identity['environment_sha256']:
            raise ValueError('verification_inputs_changed')
        proof_dir = cache/'.release-proofs'
        if not proof_dir.exists(): proof_dir.mkdir(mode=0o700)
        gate.checked(proof_dir, owner, directory=True, mode=0o700)
        parent_key, parent = prior(store, identity, clock())
        receipt = cache/('release-'+gate.digest(identity)+'.json')
        if resume:
            key, node = store.lookup(identity, clock())
            if not 0 <= clock()-node['created_at'] <= gate.MAX_AGE or full and node['plan']['mode'] != 'full':
                raise ValueError('verification_receipt_invalid_or_expired')
            if (snapshot(source, owner) != (rows, directories)
                    or gate.digest(env()) != identity['environment_sha256']
                    or policy.signature(source) != identity['policy_sha256']):
                raise ValueError('verification_inputs_changed')
            store.write(cache/'release-baseline.json', {'schema': 2, 'proof': key})
            return dict(node['plan'], verification='reused', proof=key, foundation=node['foundation'] or key,
                        rollout_authorized=False)
        plan = decision(identity, rows, directories, parent, full=full, reason=store.baseline_reason, source=source)
        for target in plan['targets']:
            if not (source/target).exists(): raise ValueError('verification_test_target_missing')
        # A contradictory retest of an already trusted snapshot invalidates all
        # inherited proofs from that foundation. A first failing candidate does
        # not revoke a different, unchanged verified parent.
        known = None
        try: known = store.lookup(identity, clock())
        except ValueError as error:
            if str(error) == 'verification_path_unsafe': raise
        if known is None:
            known = next(((k, n) for k, n in store.validated.items() if all(n[f] == identity[f] for f in IDENTITY)), None)
        blocked = cache/('release-blocked-'+gate.digest(identity)+'.json')
        store.write(blocked, {'identity': gate.digest(identity)})
        family_marker = None
        if known is not None:
            family = known[1]['foundation'] or known[0]
            family_marker = cache/('release-family-blocked-'+family+'.json')
            store.write(family_marker, {'identity': gate.digest(identity), 'foundation': family})
        store.remove(receipt)
        if execute(list(plan['targets'])) != 0:
            raise ValueError('verification_failed')
        if (snapshot(source, owner) != (rows, directories) or gate.digest(env()) != identity['environment_sha256']
                or policy.signature(source) != identity['policy_sha256']):
            raise ValueError('verification_inputs_changed')
        completed = clock()
        if (type(completed) not in (int, float) or not math.isfinite(completed) or completed <= 0
                or parent is not None and completed < parent['created_at']):
            raise ValueError('verification_time_invalid')
        foundation = None if plan['mode'] == 'full' else parent['foundation'] or parent_key
        node = dict(identity, manifest=rows, directories=directories, created_at=completed,
                    result='passed', plan=plan, attempt_id=uuid.uuid4().hex,
                    parent=None if plan['mode'] == 'full' else parent_key, foundation=foundation)
        key = gate.digest(node)
        store.write(proof_dir/(key+'.json'), node)
        store.remove(blocked)
        if family_marker is not None: store.remove(family_marker)
        store.write(receipt, {'schema': 2, 'proof': key})
        store.write(cache/'release-baseline.json', {'schema': 2, 'proof': key})
        return dict(plan, verification='verified', proof=key, foundation=foundation or key, rollout_authorized=False)
    finally:
        os.close(descriptor)
