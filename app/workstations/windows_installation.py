"""Durable manual Windows Setup handoff for an approved inventory card."""

from datetime import datetime, timedelta, timezone
import hmac

from fastapi import HTTPException
from sqlalchemy import select, update

from ..endpoint_platform_client import (
    EndpointPlatformInstallationConflict, EndpointPlatformServiceError, get_endpoint_installation_client,
)
from ..inventory.models import (
    InventoryAsset, InventoryAssetIdentifier, InventoryExternalBindingStatus, InventoryIdentifierType,
    InventoryNetctlBinding, InventoryObservationSource,
)
from .models import WorkstationRequest
from .projection import fingerprint, mac_key
from .sources import valid_uuid


ACTION = "endpoint_agent.windows_assignment"
STAGING_ORIGIN = "https://endpoint-staging.sosnadmin.local"
ASSIGNMENT_WINDOW = timedelta(minutes=30)


def setup_release(settings):
    release = settings.endpoint_platform_windows_inventory_setup_release
    if (
        settings.workstations_enabled
        and settings.endpoint_platform_enabled
        and settings.endpoint_platform_base_url == STAGING_ORIGIN
        and settings.endpoint_platform_installation_token_file
        and settings.app_secret_key != "dev-only-change-me"
        and release and release.int
    ):
        return str(release)
    return None


def latest_assignment(db, asset_id):
    return db.scalar(select(WorkstationRequest).where(
        WorkstationRequest.action == ACTION,
        WorkstationRequest.parameters_json["_endpoint_installation"]["asset_id"].as_string() == asset_id,
    ).order_by(WorkstationRequest.created_at.desc(), WorkstationRequest.id.desc()).limit(1))


def _state(row):
    return (row.data_json or {}).get("installation_binding_state")


def installation_id_for(secret, row, asset_id):
    message = f"windows-inventory-assignment/v1/{row.id}/{asset_id}/{row.intent_sha256}"
    nonce = hmac.digest(secret.encode(), message.encode(), "sha256").hex()[:32]
    return f"inventory-{asset_id}-{asset_id}-{nonce}"


def assignment_window_ended(row, now):
    data = row.data_json or {}
    if data.get("expires_at"):
        return datetime.fromisoformat(data["expires_at"]) <= now
    if data.get("last_issue_started_at"):
        # The provider's window starts on receipt. Leave time for clock skew
        # and the bounded delivery before treating a missing receipt as ended.
        return datetime.fromisoformat(data["last_issue_started_at"]) + ASSIGNMENT_WINDOW + timedelta(minutes=2) <= now
    return False


def assignment_status(row, actor):
    if row is None:
        return None
    data = row.data_json or {}
    return {
        "state": _state(row) or "issuance_pending",
        "expires_at": data.get("expires_at"),
        "receipt_unavailable": data.get("installation_receipt_unavailable", False),
        "request_id": row.id if row.actor == actor else None,
    }


def lock_card(db, asset_id):
    # Acquire the write lock before any revision reads, including on SQLite.
    db.execute(update(InventoryAsset).where(InventoryAsset.id == asset_id)
               .values(manual_revision=InventoryAsset.manual_revision, updated_at=InventoryAsset.updated_at)
               .execution_options(synchronize_session=False))


def _require_current_card(db, asset_id, revision):
    from .api import endpoint_install_asset, endpoint_install_platform

    lock_card(db, asset_id)
    db.expire_all()
    asset, os_name, linked = endpoint_install_asset(db, asset_id)
    if linked or endpoint_install_platform(os_name) != "windows" or revision != asset.manual_revision:
        raise HTTPException(409, "workstations_endpoint_asset_unavailable")


def _known_network_keys(db, asset_id):
    network_keys = db.scalars(select(InventoryNetctlBinding.network_key).where(
        InventoryNetctlBinding.asset_id == asset_id,
        InventoryNetctlBinding.status == InventoryExternalBindingStatus.CONFIRMED,
        InventoryNetctlBinding.ended_at.is_(None),
        InventoryNetctlBinding.network_key.startswith("mac:"),
    ))
    manual_macs = db.scalars(select(InventoryAssetIdentifier.value).where(
        InventoryAssetIdentifier.asset_id == asset_id,
        InventoryAssetIdentifier.identifier_type == InventoryIdentifierType.MAC,
        InventoryAssetIdentifier.source == InventoryObservationSource.MANUAL,
    ))
    known_macs = [item[4:] for item in network_keys]
    known_macs.extend(manual_macs)
    return sorted({key for value in known_macs if (key := mac_key(value))})


def issue_assignment(db, settings, *, asset_id, actor, request_id, revision, hardware_fingerprint):
    release = setup_release(settings)
    if not release:
        raise HTTPException(409, "workstations_endpoint_assignment_unavailable")
    valid_uuid(asset_id)
    valid_uuid(request_id)
    intent = fingerprint([ACTION, asset_id, revision, release, hardware_fingerprint])
    _require_current_card(db, asset_id, revision)
    row = db.get(WorkstationRequest, request_id)
    if row is None:
        active = latest_assignment(db, asset_id)
        if active is not None and _state(active) != "expired":
            raise HTTPException(409, "workstations_endpoint_assignment_pending")
        target = {
            "asset_id": asset_id, "asset_revision": revision, "machine_uuid": asset_id, "platform": "windows",
            "network_keys": _known_network_keys(db, asset_id),
        }
        row = WorkstationRequest(
            id=request_id, actor=actor, action=ACTION, permission="workstations:apply",
            intent_sha256=intent, status="registered",
            parameters_json={"_endpoint_installation": target, "setup_release": release},
        )
        target["installation_digest"] = fingerprint(installation_id_for(settings.app_secret_key, row, asset_id))
        db.add(row)
    if row.actor != actor or row.action != ACTION or row.intent_sha256 != intent:
        raise HTTPException(409, "workstations_request_conflict")
    if _state(row) in {"expired", "connected", "conflict"}:
        raise HTTPException(409, "workstations_endpoint_assignment_closed")

    installation_id = installation_id_for(settings.app_secret_key, row, asset_id)
    if row.parameters_json["_endpoint_installation"].get("installation_digest") != fingerprint(installation_id):
        raise HTTPException(409, "workstations_endpoint_assignment_closed")
    if row.status == "registered":
        now = datetime.now(timezone.utc)
        if row.created_at is not None and now >= row.created_at + ASSIGNMENT_WINDOW:
            raise HTTPException(409, "workstations_endpoint_assignment_window_short")
        row.data_json = dict(row.data_json or {}, last_issue_started_at=now.isoformat())
        db.commit()
        client = None
        conflict = False
        try:
            client = get_endpoint_installation_client(settings)
            window = client.issue_inventory_installation(installation_id, hardware_fingerprint, "windows")
        except EndpointPlatformInstallationConflict:
            conflict = True
        except EndpointPlatformServiceError:
            raise HTTPException(503, "workstations_endpoint_assignment_unavailable") from None
        finally:
            if client is not None:
                client.close()
        _require_current_card(db, asset_id, revision)
        if row.status == "registered" and _state(row) not in {"expired", "connected", "conflict"}:
            if conflict:
                row.status = "failed"
                row.data_json = {"installation_binding_state": "conflict"}
            else:
                row.status = "succeeded"
                row.data_json = dict(row.data_json or {}, installation_binding_state="waiting_registration",
                                     expires_at=window.expires_at.isoformat())
            row.finished_at = datetime.now(timezone.utc)
            db.commit()
    if row.status != "succeeded" or _state(row) in {"expired", "connected", "conflict"}:
        raise HTTPException(409, "workstations_endpoint_assignment_closed")
    expires_at = row.data_json["expires_at"]
    if datetime.fromisoformat(expires_at) - datetime.now(timezone.utc) < timedelta(minutes=10):
        raise HTTPException(409, "workstations_endpoint_assignment_window_short")
    return {
        "assignment": {
            "schema_version": "endpoint_windows_inventory_assignment_v1",
            "installation_id": installation_id,
            "hardware_fingerprint": hardware_fingerprint,
        },
        "expires_at": expires_at,
    }
