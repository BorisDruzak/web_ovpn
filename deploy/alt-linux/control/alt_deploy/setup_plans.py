"""Private, immutable, content-addressed setup plans and safe state I/O."""
from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .ad_directory import fail

MAX_STATE_BYTES = 524288
PLAN_ID_RE = re.compile(r'^setup-[0-9a-f]{64}$')


def canonical(payload) -> bytes:
    return json.dumps(payload, sort_keys=True, ensure_ascii=True, separators=(',', ':'), allow_nan=False).encode('utf-8')


def digest(payload) -> str:
    return hashlib.sha256(canonical(payload)).hexdigest()


def private_directory(path: Path) -> None:
    # Never follow a redirected state root or chmod somebody else's directory.
    for ancestor in reversed((path, *path.parents)):
        if ancestor.exists() or ancestor.is_symlink():
            info = ancestor.lstat()
            if not stat.S_ISDIR(info.st_mode):
                raise fail('setup_state_unsafe', 'Setup state path is unsafe')
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    info = path.lstat()
    if os.name != 'nt' and (stat.S_IMODE(info.st_mode) != 0o700 or info.st_uid != os.geteuid()):
        raise fail('setup_state_unsafe', 'Setup state directory must be private and owned by the operator service')


def private_read_bytes(path: Path, *, owner_uid: int | None = None) -> bytes:
    """Read protected bytes without following redirected ancestors or files."""
    try:
        actor_uid = getattr(os, 'geteuid', lambda: 0)()
        expected_uid = actor_uid if owner_uid is None else owner_uid
        if actor_uid not in (0, expected_uid):
            raise ValueError
        for ancestor in path.parents:
            if not stat.S_ISDIR(ancestor.lstat().st_mode):
                raise ValueError
        before = path.lstat()
        if not stat.S_ISREG(before.st_mode):
            raise ValueError
        flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0)
        fd = os.open(path, flags)
        with os.fdopen(fd, 'rb') as stream:
            info = os.fstat(stream.fileno())
            if ((info.st_dev, info.st_ino) != (before.st_dev, before.st_ino)
                    or not stat.S_ISREG(info.st_mode) or info.st_size > MAX_STATE_BYTES
                    or (os.name != 'nt' and (stat.S_IMODE(info.st_mode) != 0o600 or info.st_uid != expected_uid))):
                raise ValueError
            raw = stream.read(MAX_STATE_BYTES + 1)
            if len(raw) > MAX_STATE_BYTES:
                raise ValueError
        return raw
    except (OSError, ValueError) as exc:
        raise fail('setup_state_invalid', 'Protected setup state is missing, unsafe or invalid') from exc


def decode_state_bytes(raw: bytes):
    try:
        if not isinstance(raw, bytes) or len(raw) > MAX_STATE_BYTES:
            raise ValueError
        def strict(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError
                result[key] = value
            return result
        document = json.loads(raw, object_pairs_hook=strict)
        if not isinstance(document, dict):
            raise ValueError
        return document
    except (ValueError, UnicodeError) as exc:
        raise fail('setup_state_invalid', 'Protected setup state is missing, unsafe or invalid') from exc


def private_read(path: Path, *, owner_uid: int | None = None):
    return decode_state_bytes(private_read_bytes(path, owner_uid=owner_uid))


def private_create(path: Path, payload) -> None:
    private_directory(path.parent)
    raw = canonical(payload) + b'\n'
    if len(raw) > MAX_STATE_BYTES:
        raise fail('setup_state_invalid', 'Setup state exceeds size limit')
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0)
    fd = os.open(path, flags, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def private_replace(path: Path, payload) -> None:
    import uuid
    temporary = path.with_name('.' + path.name + '-' + uuid.uuid4().hex)
    private_create(temporary, payload)
    try:
        if path.is_symlink():
            raise fail('setup_state_unsafe', 'Setup state path is unsafe')
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


class SetupPlanStore:
    prefix = 'setup-'
    directory = 'setup-plans'
    plan_schema_version = 1
    plan_operation = None

    def __init__(self, state_root: Path, *, clock=None):
        self.root = state_root / self.directory
        self.clock = clock or (lambda: datetime.now(timezone.utc))

    def create(self, payload):
        now = self.clock().replace(microsecond=0)
        body = {'schema_version': self.plan_schema_version, 'created_at': now.isoformat(),
                'expires_at': (now + timedelta(minutes=30)).isoformat(),
                'content_sha256': digest(payload), 'payload': payload}
        if self.plan_operation is not None:
            body['operation'] = self.plan_operation
        sha = digest(body)
        plan = dict(body, plan_id=self.prefix + sha, sha256=sha)
        path = self.root / (plan['plan_id'] + '.json')
        try:
            private_create(path, plan)
        except FileExistsError:
            existing = private_read(path)
            if existing != plan:
                raise fail('setup_plan_invalid', 'Existing setup plan differs')
        return plan

    def load(self, plan_id: str, confirmed_sha: str):
        if not isinstance(plan_id, str) or not re.fullmatch(re.escape(self.prefix) + '[0-9a-f]{64}', plan_id):
            raise fail('setup_plan_invalid', 'Setup plan identifier is invalid')
        if not isinstance(confirmed_sha, str) or not re.fullmatch('[0-9a-f]{64}', confirmed_sha) or plan_id != self.prefix + confirmed_sha:
            raise fail('setup_plan_mismatch', 'Setup plan SHA confirmation differs')
        try:
            plan = private_read(self.root / (plan_id + '.json'))
            fields = {'schema_version', 'created_at', 'expires_at', 'content_sha256', 'payload', 'plan_id', 'sha256'}
            if self.plan_operation is not None:
                fields.add('operation')
            if set(plan) != fields:
                raise ValueError
            body = {key: value for key, value in plan.items() if key not in ('plan_id', 'sha256')}
            if (plan['plan_id'] != plan_id or plan['sha256'] != confirmed_sha
                    or digest(body) != confirmed_sha or plan['schema_version'] != self.plan_schema_version
                    or type(plan['schema_version']) is not int
                    or (self.plan_operation is not None and plan['operation'] != self.plan_operation)
                    or not isinstance(plan['payload'], dict)
                    or digest(plan['payload']) != plan['content_sha256']):
                raise ValueError
            created = datetime.fromisoformat(plan['created_at'])
            expires = datetime.fromisoformat(plan['expires_at'])
            now = self.clock()
            if created.tzinfo is None or expires.tzinfo is None or expires - created != timedelta(minutes=30) or created > now:
                raise ValueError
        except Exception as exc:
            raise fail('setup_plan_invalid', 'Setup plan integrity or metadata is invalid') from exc
        if now >= expires:
            raise fail('setup_plan_expired', 'Setup plan expired; create a new plan')
        return plan
