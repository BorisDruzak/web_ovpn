"""Apply verified Endpoint receipts to the exact approved inventory target."""

from datetime import datetime, timedelta, timezone
import re
import time
from uuid import UUID

from fastapi import HTTPException
from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError

from ..endpoint_platform_client import (
    EndpointPlatformInstallationConflict,
    EndpointPlatformInstallationUnavailable,
    EndpointPlatformServiceError,
)
from ..inventory.endpoint import InventoryEndpointService, InventoryValidationError, _utc
from ..inventory.models import InventoryAsset, InventoryExternalBinding
from ..inventory.revision import InventoryRevisionConflict
from .models import SourceSnapshot, WorkstationRequest
from .projection import fingerprint
from .sources import SourceError, valid_uuid
from .windows_installation import ACTION as WINDOWS_ASSIGNMENT, assignment_window_ended, installation_id_for, lock_card


FINAL_STATES = ("connected", "conflict", "expired")
MAX_PER_PASS = 16
POLL_BUDGET_SECONDS = 12


def _target(row, windows_secret=None):
    if row is None or row.action not in ("plans.apply", WINDOWS_ASSIGNMENT):
        return None
    params, data = row.parameters_json, row.data_json or {}
    if not isinstance(params, dict) or not isinstance(data, dict):
        return None
    target = params.get("_endpoint_installation")
    if not isinstance(target, dict) or data.get("installation_binding_state") in FINAL_STATES:
        return None
    try:
        asset = valid_uuid(target["asset_id"])
        machine = valid_uuid(target["machine_uuid"])
        revision = target["asset_revision"]
        if type(revision) is not int or revision < 1:
            return None
        if row.action == WINDOWS_ASSIGNMENT:
            if not windows_secret or row.status not in ("registered", "succeeded"):
                return None
            installation_id = installation_id_for(windows_secret, row, asset)
            if (target.get("platform") == "windows" and asset == machine
                and target.get("installation_digest") == fingerprint(installation_id)):
                return asset, machine, revision, installation_id
            return None
        installation_id = target["installation_id"]
        sha = params["sha256"]
        if not (
            row.status == "succeeded" and isinstance(installation_id, str)
            and re.fullmatch(rf"inventory-{asset}-{machine}-[0-9a-f]{{32}}", installation_id)
            and re.fullmatch(r"[0-9a-f]{64}", sha)
            and params["kind"] == "component" and params["plan_id"] == "setup-component-" + sha
            and data.get("machine_uuid") == machine
            and data.get("plan_id") == params["plan_id"] and data.get("plan_sha256") == sha
            and re.fullmatch(r"job-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}", data.get("job_id", ""))
        ):
            return None
    except (KeyError, TypeError, SourceError):
        return None
    return asset, machine, revision, installation_id


def _apply(db, row, target, receipt, now):
    from .api import endpoint_install_asset, endpoint_install_platform, endpoint_install_target

    asset_id, machine_uuid, revision, _ = target
    if receipt.state != "connected":
        return receipt.state
    if not (
        isinstance(receipt.device_id, UUID) and receipt.device_id.int
        and _utc(row.created_at) <= receipt.registered_at <= receipt.heartbeat_at <= now
        and now - receipt.heartbeat_at <= timedelta(seconds=90)
    ):
        return "waiting_connection"
    asset = db.get(InventoryAsset, asset_id)
    if asset is None or asset.deleted_at is not None:
        return "conflict"
    device_id = str(receipt.device_id)
    service = InventoryEndpointService()
    already = db.scalar(select(InventoryExternalBinding.id).where(
        *service._active(), InventoryExternalBinding.asset_id == asset_id,
        InventoryExternalBinding.external_id == device_id,
    ))
    if already is not None:
        return "connected"
    if asset.manual_revision != revision:
        return "conflict"
    try:
        if row.action == WINDOWS_ASSIGNMENT:
            _, os_name, linked = endpoint_install_asset(db, asset_id)
            if linked or endpoint_install_platform(os_name) != 'windows':
                return "conflict"
        else:
            db.get(SourceSnapshot, 'reconciliation', with_for_update=True)
            if endpoint_install_target(db, asset_id) != machine_uuid:
                return "conflict"
    except HTTPException as exc:
        return "waiting_connection" if exc.detail == "workstations_endpoint_source_stale" else "conflict"
    try:
        with db.begin_nested():
            service.confirm_installation(
                db, asset, device_id, revision, now, request_id=row.id,
                registered_at=receipt.registered_at, heartbeat_at=receipt.heartbeat_at,
            )
    except (IntegrityError, InventoryValidationError, InventoryRevisionConflict):
        return "conflict"
    return "connected"


def installation_reservations(db):
    """Keep approved cards and network keys out of MAC-only auto-confirmation."""
    target = WorkstationRequest.parameters_json["_endpoint_installation"]
    asset_id = target["asset_id"].as_string()
    state = WorkstationRequest.data_json["installation_binding_state"].as_string()
    rows = db.execute(select(asset_id, target["network_keys"]).where(
        WorkstationRequest.action.in_(("plans.apply", WINDOWS_ASSIGNMENT)),
        WorkstationRequest.status.in_(("registered", "running", "unknown", "succeeded")),
        asset_id.is_not(None),
        (state.is_(None) | (state != "connected")),
    ))
    assets, mac_keys = set(), set()
    for asset, keys in rows:
        assets.add(asset)
        if isinstance(keys, list):
            mac_keys.update(
                "mac-" + key[4:].replace(":", "").lower()
                for key in keys
                if isinstance(key, str) and re.fullmatch(r"mac:(?:[0-9A-F]{2}:){5}[0-9A-F]{2}", key)
            )
    return frozenset(assets), frozenset(mac_keys)


def _locked_request(db, request_id):
    # A write starts a real SQLite transaction before any evidence is reread.
    db.execute(update(WorkstationRequest).where(WorkstationRequest.id == request_id)
               .values(status=WorkstationRequest.status))
    return db.get(WorkstationRequest, request_id, populate_existing=True)


def _record_poll(row, now, state=None, *, unavailable=False):
    data = dict(row.data_json) if isinstance(row.data_json, dict) else {}
    data["installation_receipt_checked_at"] = now.isoformat()
    if state is not None:
        data["installation_binding_state"] = state
    if row.action == WINDOWS_ASSIGNMENT:
        data["installation_receipt_unavailable"] = unavailable
    row.data_json = data


def sync_installation_receipts(session_factory, client, *, clock=None, windows_secret=None):
    """Poll admitted plans fairly. Recover uncertain admission using its original receipt."""
    from .client import WorkstationsClient
    from .service import WorkstationsService

    clock = clock or (lambda: datetime.now(timezone.utc))
    deadline = time.monotonic() + POLL_BUDGET_SECONDS
    checked = WorkstationRequest.data_json["installation_receipt_checked_at"].as_string()
    state = WorkstationRequest.data_json["installation_binding_state"].as_string()
    with session_factory() as db:
        candidates = db.execute(select(
            WorkstationRequest.id, WorkstationRequest.status, WorkstationRequest.actor, WorkstationRequest.action,
        ).where(
            ((WorkstationRequest.action == "plans.apply") & WorkstationRequest.status.in_(("succeeded", "unknown"))
                & (WorkstationRequest.created_at >= clock() - timedelta(minutes=45)))
            | ((WorkstationRequest.action == WINDOWS_ASSIGNMENT) & WorkstationRequest.status.in_(("registered", "succeeded"))
                & bool(windows_secret)),
            WorkstationRequest.parameters_json["_endpoint_installation"]["asset_id"].as_string().is_not(None),
            state.is_(None) | state.not_in(FINAL_STATES),
        ).order_by(checked.is_not(None), checked, WorkstationRequest.created_at).limit(MAX_PER_PASS)).all()
    for request_id, status, actor, action in candidates:
        if time.monotonic() >= deadline:
            break
        if status == "unknown":
            controller = WorkstationsClient().with_deadline(deadline)
            WorkstationsService(client=controller, session_factory=session_factory).operation(request_id, actor=actor)
        with session_factory() as db:
            row = db.get(WorkstationRequest, request_id)
            target = _target(row, windows_secret)
        if target is None:
            with session_factory() as db:
                row = _locked_request(db, request_id)
                if row and row.status in ("registered", "succeeded", "unknown") and _target(row, windows_secret) is None:
                    prior = row.data_json.get("installation_binding_state") if isinstance(row.data_json, dict) else None
                    if prior not in FINAL_STATES:
                        _record_poll(row, clock(), "conflict" if row.status != "unknown" else None)
                        db.commit()
            continue
        if time.monotonic() >= deadline:
            break
        receipt, result, unavailable, missing = None, None, False, False
        try:
            receipt = client.lookup_inventory_installation(target[3])
        except EndpointPlatformInstallationUnavailable:
            missing = True
        except EndpointPlatformInstallationConflict:
            result = "conflict"
        except EndpointPlatformServiceError:
            unavailable = True
        with session_factory() as db:
            if action == WINDOWS_ASSIGNMENT:
                lock_card(db, target[0])
            row = _locked_request(db, request_id)
            if _target(row, windows_secret) != target:
                continue
            now = clock()
            if missing:
                if action != WINDOWS_ASSIGNMENT or row.status == "succeeded":
                    result = "waiting_registration"
                if action == WINDOWS_ASSIGNMENT and assignment_window_ended(row, now):
                    result = "expired"
            if receipt is not None:
                result = _apply(db, row, target, receipt, now)
            _record_poll(row, now, result, unavailable=unavailable)
            db.commit()
        if unavailable:
            break
