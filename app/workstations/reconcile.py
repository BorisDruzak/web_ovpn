"""Singleton read-only collection and atomic inventory-aware publication."""
from __future__ import annotations

import json
import os
import re
import stat
import time
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path

from sqlalchemy import delete, select, update

from ..config import get_settings
from ..db import get_sessionmaker
from ..inventory.models import InventoryNetworkProjectionVersion
from ..inventory.network_projection import projection_epoch
from ..netctl_client import run_netctl
from .client import WorkstationsClient
from .models import Finding, SourceRun, SourceSnapshot
from .projection import build_projection, fingerprint
from .schema import check_schema
from .sources import SourceError, collect_source, timestamp

SOURCES = ('controller', 'ad', 'dns', 'netctl')


@contextmanager
def reconciliation_lock(path):
    path = Path(path)
    for ancestor in (path.parent, *path.parents):
        if ancestor.is_symlink():
            raise SourceError('workstations_lock_unsafe')
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor = os.open(path, os.O_RDWR | os.O_CREAT | getattr(os, 'O_NOFOLLOW', 0), 0o600)
    acquired = False
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or os.name != 'nt' and (metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) != 0o600):
            raise SourceError('workstations_lock_unsafe')
        try:
            if os.name == 'nt':
                import msvcrt
                msvcrt.locking(descriptor, msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            acquired = True
        except (BlockingIOError, PermissionError):
            pass
        yield acquired
    finally:
        if acquired:
            if os.name == 'nt':
                import msvcrt
                os.lseek(descriptor, 0, os.SEEK_SET)
                msvcrt.locking(descriptor, msvcrt.LK_UNLCK, 1)
            else:
                import fcntl
                fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


def _safe_code(exc):
    code = getattr(exc, 'code', '')
    return code if isinstance(code, str) and re.fullmatch(r'(?:workstations|directory|ad)_[a-z0-9_]{1,96}', code) else 'workstations_source_unavailable'


def _snapshot(db, source, payload, batch_id, now, *, inventory_revision=None):
    row = db.get(SourceSnapshot, source)
    if row is None:
        row = SourceSnapshot(source=source)
        db.add(row)
    row.generation, row.batch_id = payload['generation'], batch_id
    row.observed_at, row.captured_at = timestamp(payload['generated_at']), now
    row.data_json, row.inventory_revision = payload, inventory_revision


def reconcile_once(*, client=None, netctl_call=run_netctl, session_factory=None, clock=None,
                   lock_path=None, before_publish=None):
    clock = clock or (lambda: datetime.now(timezone.utc))
    factory = session_factory or get_sessionmaker()
    client = client or WorkstationsClient()
    lock_path = lock_path or get_settings().workstations_reconcile_lock
    with reconciliation_lock(lock_path) as acquired:
        if not acquired:
            return {'status': 'busy', 'error_code': 'workstations_reconcile_busy'}
        with factory() as db:
            check_schema(db.get_bind())
        deadline = time.monotonic() + 270
        if isinstance(client, WorkstationsClient):
            client = client.with_deadline(deadline)
        original_netctl = netctl_call
        def bounded_netctl(args, timeout=60):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise SourceError('workstations_source_timeout')
            return original_netctl(args, timeout=min(timeout, remaining))
        batch_id, sources, errors = str(uuid.uuid4()), {}, {}
        for name in SOURCES:
            with factory() as db:
                run = SourceRun(batch_id=batch_id, source=name, status='running', started_at=clock())
                db.add(run); db.commit()
                run_id = run.id
            try:
                if time.monotonic() >= deadline:
                    raise SourceError('workstations_source_timeout')
                payload = collect_source(name, client=client, netctl_call=bounded_netctl, clock=clock)
                with factory() as db:
                    row = db.get(SourceRun, run_id)
                    row.status, row.finished_at, row.generation = 'success', clock(), payload['generation']
                    row.object_count = sum(len(payload.get(key, [])) for key in ('users', 'computers', 'machines', 'records', 'hosts'))
                    _snapshot(db, name, payload, batch_id, clock())
                    db.commit()
                sources[name] = payload
            except Exception as exc:
                errors[name] = _safe_code(exc)
                with factory() as db:
                    row = db.get(SourceRun, run_id)
                    row.status, row.finished_at, row.error_code = 'error', clock(), errors[name]
                    db.commit()
        if not errors:
            try:
                with factory() as db:
                    epoch = projection_epoch(db)
                    payload = build_projection(db, sources, clock())
                    if before_publish is not None:
                        before_publish()
                    # The same row is advanced by existing inventory mutation
                    # triggers. This short CAS locks it through our publication.
                    changed = db.execute(update(InventoryNetworkProjectionVersion)
                        .where(InventoryNetworkProjectionVersion.id == 1, InventoryNetworkProjectionVersion.version == epoch)
                        .values(version=epoch)).rowcount
                    if changed != 1:
                        raise SourceError('workstations_inventory_revision_changed')
                    payload.update(schema_version=1, complete=True, generated_at=clock().isoformat(), inventory_revision=epoch)
                    payload['generation'] = fingerprint([payload['generations'], epoch, payload['devices'], payload['findings']])
                    _snapshot(db, 'reconciliation', payload, batch_id, clock(), inventory_revision=epoch)
                    current = {item['id']: item for item in payload['findings']}
                    old = {row.id: row for row in db.scalars(select(Finding))}
                    for identifier, item in current.items():
                        row = old.get(identifier)
                        if row is None:
                            row = Finding(id=identifier, device_key=item['device_key'], code=item['code'], first_seen_at=clock())
                            db.add(row)
                        elif row.status == 'resolved':
                            row.status, row.resolved_at, row.revision = 'open', None, row.revision + 1
                        row.last_seen_at, row.evidence_json = clock(), item['evidence']
                    for identifier, row in old.items():
                        if identifier not in current and row.status != 'resolved':
                            row.status, row.resolved_at, row.revision = 'resolved', clock(), row.revision + 1
                    db.commit()
            except Exception as exc:
                errors['reconciliation'] = _safe_code(exc)
                with factory() as db:
                    db.add(SourceRun(batch_id=batch_id, source='reconciliation', status='error', started_at=clock(),
                                     finished_at=clock(), error_code=errors['reconciliation']))
                    db.commit()
        with factory() as db:
            db.execute(delete(SourceRun).where(SourceRun.finished_at < clock() - timedelta(days=30)))
            db.commit()
        return {'status': 'degraded' if errors else 'success', 'run_id': batch_id, 'errors': errors,
                'sources_succeeded': len(sources), 'devices': len(payload.get('devices', [])) if not errors else None}


def main():
    try:
        result = reconcile_once()
    except Exception as exc:
        result = {'status': 'error', 'error_code': _safe_code(exc)}
    print(json.dumps(result, sort_keys=True))
    return 0 if result['status'] == 'success' else 1


if __name__ == '__main__':
    raise SystemExit(main())
