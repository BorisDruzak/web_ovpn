"""Small, durable status executor for existing panel operations.

Only the process-local payload is executable. Losing it never causes replay;
expired work becomes unknown. Workers own their SQLAlchemy sessions.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from contextvars import ContextVar
from datetime import timedelta
from typing import Callable

from fastapi import HTTPException
from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError

from .config import get_settings
from .db import get_sessionmaker
from .models import PanelOperation, utcnow

LEASE_SECONDS = 1800
_pool = ThreadPoolExecutor(max_workers=2, thread_name_prefix="panel-operation")
_slots = threading.BoundedSemaphore(32)
_futures = {}


def execution_future(operation_id):
    return _futures.get(operation_id)


def forget_future(operation_id):
    _futures.pop(operation_id, None)


_artifacts: ContextVar[list | None] = ContextVar("panel_operation_artifacts", default=None)
_active: ContextVar[list | None] = ContextVar("panel_operation_phases", default=None)


def phase(name: str, status: str) -> None:
    """Names/statuses are fixed public codes; callers must never pass CLI output."""
    phases = _active.get()
    if phases is not None:
        phases.append({"phase": name, "status": status})


def record_artifact(record_id: int) -> None:
    artifacts = _artifacts.get()
    if artifacts is not None:
        artifacts.append(record_id)
        phase("file", "succeeded")


def recover(factory=None) -> None:
    factory = factory or get_sessionmaker()
    with factory() as db:
        db.execute(update(PanelOperation).where(
            PanelOperation.status.in_(("registered", "running")),
            PanelOperation.lease_until < utcnow(),
        ).values(status="unknown", finished_at=utcnow()))
        db.commit()


def public_operation(row: PanelOperation) -> dict:
    return {"id": row.id, "action": row.action, "status": row.status,
            "phases": json.loads(row.phases_json),
            "status_url": f"/operations/{row.id}",
            "artifacts": [f"/operations/{row.id}/files/{file_id}" for file_id in json.loads(row.artifact_ids_json)],
            "verification_required": row.status in {"unknown", "partial"} and row.verified_at is None}


def register(owner: str, action: str, permission: str, parameters: bytes, execute: Callable,
             *, factory=None, intent: bytes | None = None) -> tuple[dict, bool]:
    factory = factory or get_sessionmaker()
    recover(factory)
    key = hmac.new(get_settings().app_secret_key.encode(),
                   owner.encode() + b"\0" + action.encode() + b"\0" + parameters,
                   hashlib.sha256).hexdigest()
    intent_key = hmac.new(get_settings().app_secret_key.encode(),
        owner.encode() + b"\0" + action.encode() + b"\0" + (intent if intent is not None else parameters),
        hashlib.sha256).hexdigest()
    with factory() as db:
        existing = db.scalar(select(PanelOperation).where(PanelOperation.fingerprint == key))
        if existing:
            return public_operation(existing), False
        unresolved = db.scalar(select(PanelOperation).where(
            PanelOperation.intent_hash == intent_key,
            (PanelOperation.status.in_(("registered", "running"))) |
            ((PanelOperation.status.in_(("unknown", "partial"))) & PanelOperation.verified_at.is_(None)),
        ).order_by(PanelOperation.created_at.desc()))
        if unresolved:
            return public_operation(unresolved), False
    if not _slots.acquire(blocking=False):
        raise HTTPException(503, "Очередь операций заполнена; повторите позже")
    operation_id = str(uuid.uuid4())
    try:
        with factory() as db:
            row = PanelOperation(id=operation_id, owner=owner, action=action,
                permission=permission, fingerprint=key, intent_hash=intent_key, status="registered",
                lease_until=utcnow() + timedelta(seconds=LEASE_SECONDS))
            db.add(row)
            try:
                db.commit()
            except IntegrityError:
                db.rollback()
                row = db.scalar(select(PanelOperation).where(
                    (PanelOperation.fingerprint == key) |
                    ((PanelOperation.intent_hash == intent_key) & PanelOperation.status.in_(("registered", "running")))))
                if row is None:
                    raise
                _slots.release()
                return public_operation(row), False
            result = public_operation(row)
        # Bound compatibility-only in-memory response retention. The durable
        # ledger is authoritative; old results are never replayed as effects.
        for old_id, future in list(_futures.items()):
            if len(_futures) < 128:
                break
            if future.done():
                _futures.pop(old_id, None)
        _futures[operation_id] = _pool.submit(_execute, operation_id, execute, factory)
        return result, True
    except Exception:
        _slots.release()
        raise


def _execute(operation_id: str, execute: Callable, factory) -> None:
    phases: list[dict] = []
    token = _active.set(phases)
    artifacts = []
    artifact_token = _artifacts.set(artifacts)
    status = "unknown"
    response = None
    failure = None
    try:
        with factory() as db:
            claimed = db.execute(update(PanelOperation).where(
                PanelOperation.id == operation_id,
                PanelOperation.status == "registered",
                PanelOperation.lease_until > utcnow(),
            ).values(status="running"))
            db.commit()
            if claimed.rowcount != 1:
                db.execute(update(PanelOperation).where(
                    PanelOperation.id == operation_id, PanelOperation.status == "registered",
                    PanelOperation.lease_until <= utcnow(),
                ).values(status="unknown", finished_at=utcnow()))
                db.commit()
                return
        try:
            # The callable owns any domain Session it needs. Ledger writes use
            # independent short transactions, never the request Session.
            response = execute()
            from fastapi.responses import FileResponse
            if isinstance(response, FileResponse):
                from .download_tokens import create_download_token
                with factory() as artifact_db:
                    owner = artifact_db.get(PanelOperation, operation_id).owner
                create_download_token(client_name="operation-file", file_path=response.path,
                    file_type="ovpn", created_by=owner.removeprefix("user:"),
                    expires_at=utcnow() + timedelta(minutes=get_settings().download_ttl_minutes))
            errors = any(item["status"] != "succeeded" for item in phases)
            successes = any(item["status"] == "succeeded" for item in phases)
            if errors:
                status = "partial" if successes else ("unknown" if any(p["status"] == "unknown" for p in phases) else "failed")
            elif getattr(response, "status_code", 200) >= 400:
                status = "partial" if successes else "failed"
            else:
                status = "succeeded"
        except HTTPException as exc:
            failure = exc
            status = "partial" if any(p["status"] == "succeeded" for p in phases) else ("unknown" if phases else "failed")
        except Exception as exc:
            failure = exc
            # External effects cannot be inferred from a Python exception.
            status = "partial" if any(p["status"] == "succeeded" for p in phases) else "unknown"
        with factory() as db:
            db.execute(update(PanelOperation).where(
                PanelOperation.id == operation_id,
                PanelOperation.status == "running",
            ).values(status=status, phases_json=json.dumps(phases), artifact_ids_json=json.dumps(artifacts), finished_at=utcnow()))
            db.commit()
        if failure is not None:
            raise failure
        return response
    finally:
        _active.reset(token)
        _artifacts.reset(artifact_token)
        _slots.release()


def observed_cli(provider: str):
    """Observe fixed command codes without persisting arguments or diagnostics."""
    from functools import wraps
    read_commands = {"profiles", "preview", "list", "status", "web-summary", "inspect",
        "config-view", "connected", "nat-status", "runtime-health", "validate-network-plan", "dashboard",
        "logs", "host-snapshot", "context-view", "ipsec"}
    def decorate(fn):
        @wraps(fn)
        def observed(args, *positional, **kwargs):
            command = str(args[0]) if args else "command"
            mutating = command not in read_commands
            if command in {"networks", "network-templates", "sources", "interfaces", "routes", "observations", "site-routes", "management", "server-config", "hosts", "users", "network-sessions"}:
                mutating = len(args) > 1 and args[1] not in {"list", "inspect", "status", "test", "snapshot-status"}
            if command == "generate-batch" and "--dry-run" in args:
                mutating = False
            name = provider + ":" + (command if command in {
                "generate", "generate-batch", "sync", "disable", "delete", "repair-artifacts",
                "client-template-apply", "client-networks-apply", "config-edit", "ovpn-update", "reconnect-client",
                "management", "server-config", "networks", "network-templates", "site-routes",
                "sources", "collect", "monitoring", "assets", "availability", "observations",
                "force-monitor"} else "external-action")
            try:
                result = fn(args, *positional, **kwargs)
            except Exception:
                if mutating:
                    phase(name, "unknown")
                raise
            if mutating:
                phase(name, "succeeded" if result.get("status") not in {"error", "failed", "partial", "not_configured"} else "unknown")
            return result
        return observed
    return decorate
