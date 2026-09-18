"""Single scheduled owner of Inventory's safe Endpoint state.

Only the published adapter performs remote reads. Rendering consumes persisted
state; failures never replace the last successful state or compatibility cache.
"""

from __future__ import annotations

import logging
import ipaddress
import time
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4

from sqlalchemy import or_, select, update
from sqlalchemy.exc import IntegrityError

from ..db import init_inventory_endpoint_schema, session_scope
from ..endpoint_agent_network import (
    mark_endpoint_agent_refresh_failed,
    store_endpoint_agent_statuses,
    sync_endpoint_agent_fingerprint_evidence,
)
from ..endpoint_context_adapter import get_endpoint_context_adapter
from ..endpoint_platform_client import (
    EndpointPlatformServiceDisabled,
    EndpointPlatformServiceScopeDenied,
    EndpointPlatformServiceUnavailable,
)
from ..netctl_client import run_netctl
from .endpoint import InventoryEndpointService, _parsed, _text, _utc
from .lookup import InventoryLookupError, normalize_mac
from .models import (
    InventoryAssetIdentifier,
    InventoryEndpointState,
    InventoryEndpointSyncControl,
    InventoryExternalBinding,
    InventoryIdentifierType,
    InventoryObservation,
    InventoryObservationSource,
)

log = logging.getLogger(__name__)
PROFILES = {"baseline_v1": "baseline", "health_v1": "health", "network_v1": "network"}
PRESENCE_INTERVAL = timedelta(minutes=1)
FULL_INTERVAL = timedelta(minutes=5)
LEASE_INTERVAL = timedelta(minutes=10)
MAX_DEVICES = 1000


@dataclass(frozen=True)
class SyncResult:
    confirmed_bindings: int
    observations_created: int
    full_pass: bool


@dataclass(frozen=True)
class _PreparedAdapter:
    identities: list
    snapshots: dict

    def list_agent_network_identities(self):
        return self.identities

    def read_profiles(self, device_id):
        if str(device_id) not in self.snapshots:
            # A manual binding changed while the remote reads were in flight.
            # Retry next pass rather than apply an incomplete snapshot set.
            raise EndpointPlatformServiceUnavailable()
        return self.snapshots[str(device_id)]


def _control(db):
    row = db.get(InventoryEndpointSyncControl, 1)
    if row is None:
        try:
            with db.begin_nested():
                db.add(InventoryEndpointSyncControl(id=1))
                db.flush()
        except IntegrityError:
            pass  # A concurrent worker created the singleton first.
        row = db.get(InventoryEndpointSyncControl, 1)
    return row


def acquire_endpoint_sync_lease(db, now: datetime) -> bool:
    """Compare-and-set in SQL, so two processes cannot both acquire a lease."""
    _control(db)
    now = _utc(now)
    result = db.execute(
        update(InventoryEndpointSyncControl)
        .where(
            InventoryEndpointSyncControl.id == 1,
            or_(
                InventoryEndpointSyncControl.lease_expires_at.is_(None),
                InventoryEndpointSyncControl.lease_expires_at <= now,
            ),
            or_(
                InventoryEndpointSyncControl.last_presence_sync_at.is_(None),
                InventoryEndpointSyncControl.last_presence_sync_at
                <= now - PRESENCE_INTERVAL,
            ),
        )
        .values(lease_owner=str(uuid4()), lease_expires_at=now + LEASE_INTERVAL)
        .execution_options(synchronize_session=False)
    )
    db.expire_all()
    return result.rowcount == 1


def _baseline_fields(snapshot):
    """Normalize only fields provided by the published safe baseline contract."""
    sections = snapshot.get("sections") or {}
    system = sections.get("system") or {}
    hardware = sections.get("hardware") or {}
    fields = {}
    for target, value in (
        ("os_name", system.get("distribution") or system.get("platform")),
        ("os_family", system.get("platform")),
        ("cpu_model", hardware.get("cpu_model")),
        ("manufacturer", hardware.get("manufacturer")),
        ("model", hardware.get("model")),
    ):
        if (safe := _text(value)) is not None:
            fields[target] = safe
    memory = hardware.get("memory_bytes")
    if type(memory) is int and 0 < memory <= 2**60:
        fields["ram_gb"] = max(1, round(memory / 2**30))
    storage = sections.get("storage") or []
    sizes = [disk.get("size_bytes") for disk in storage[:64] if isinstance(disk, dict)]
    if sizes and all(type(size) is int and 0 < size <= 2**60 for size in sizes):
        fields["storage_gb"] = max(1, round(sum(sizes) / 2**30))
    return fields


def _network_fields(snapshot):
    interfaces = (snapshot.get("sections") or {}).get("interfaces") or []
    for interface in interfaces[:64]:
        for value in (interface.get("addresses") or [])[:64]:
            if not isinstance(value, str) or len(value) > 64:
                continue
            try:
                address = ipaddress.ip_interface(value).ip
            except ValueError:
                continue
            if address.version == 4 and not (
                address.is_loopback
                or address.is_link_local
                or address.is_multicast
                or address.is_unspecified
            ):
                return {"ip": str(address)}
    return {}


def sync_confirmed_bindings(db, adapter, now: datetime) -> SyncResult:
    """Read a bounded safe pass and persist it in the caller's transaction."""
    now = _utc(now)
    control = _control(db)
    full = (
        control.last_full_sync_at is None
        or now - control.last_full_sync_at >= FULL_INTERVAL
    )
    identities = adapter.list_agent_network_identities()
    if len(identities) > MAX_DEVICES:
        raise EndpointPlatformServiceUnavailable()
    # Duplicate UUIDs are malformed input; do not silently select a record.
    by_device = {item["id"]: item for item in identities}
    if len(by_device) != len(identities):
        raise EndpointPlatformServiceUnavailable()
    service = InventoryEndpointService()
    service.reconcile_candidates(db, identities, now)
    bindings = db.scalars(
        select(InventoryExternalBinding).where(*service._active())
    ).all()
    if len(bindings) > MAX_DEVICES:
        raise EndpointPlatformServiceUnavailable()
    observations = 0
    for binding in bindings:
        state = db.get(InventoryEndpointState, binding.id)
        if state is None:
            state = InventoryEndpointState(
                binding_id=binding.id,
                asset_id=binding.asset_id,
                endpoint_device_id=binding.external_id,
                safe_context_json={},
            )
            db.add(state)
        state.last_checked_at = now
        identity = by_device.get(binding.external_id)
        if identity is not None:
            last_seen = _parsed(identity.get("last_seen_at"))
            if last_seen is not None and last_seen <= now:
                state.last_seen_at = last_seen
        # UUID is already stable: a changed/missing MAC never reassigns a binding.
        if full:
            profiles = adapter.read_profiles(UUID(binding.external_id))
            context = dict(state.safe_context_json)
            statuses = {}
            for profile, prefix in PROFILES.items():
                snapshot = profiles.get(profile)
                statuses[profile] = (
                    "available" if snapshot is not None else "unavailable"
                )
                if snapshot is None:
                    continue
                collected = _parsed(snapshot.get("collected_at"))
                digest = _text(snapshot.get("semantic_hash"))
                snapshot_id = _text(snapshot.get("id"))
                if snapshot.get("semantic_hash") is None:
                    # Older/optional snapshots may have no comparable hash.
                    # Retain previous state rather than inventing upstream history.
                    statuses[profile] = "unavailable"
                    continue
                if (
                    snapshot.get("profile") != profile
                    or collected is None
                    or collected > now
                    or not digest
                    or len(digest) > 64
                    or not snapshot_id
                ):
                    raise EndpointPlatformServiceUnavailable()
                fields = (
                    _baseline_fields(snapshot)
                    if profile == "baseline_v1"
                    else _network_fields(snapshot)
                    if profile == "network_v1"
                    else {}
                )
                context.update(fields)
                if getattr(state, prefix + "_semantic_hash") != digest:
                    db.add(
                        InventoryObservation(
                            asset_id=binding.asset_id,
                            binding_id=binding.id,
                            endpoint_device_id=binding.external_id,
                            source=InventoryObservationSource.ENDPOINT,
                            profile=profile,
                            snapshot_id=snapshot_id,
                            semantic_hash=digest,
                            collected_at=collected,
                            observed_at=now,
                            data_json=fields,
                        )
                    )
                    observations += 1
                setattr(state, prefix + "_snapshot_id", snapshot_id)
                setattr(state, prefix + "_semantic_hash", digest)
                state.refreshed_at = max(state.refreshed_at or collected, collected)
            context["profile_status"] = statuses
            state.safe_context_json = context
        state.last_success_at = now
        state.unavailable_since = None
    control.last_presence_sync_at = now
    if full:
        control.last_full_sync_at = now
    control.last_safe_error_code = None
    db.flush()
    return SyncResult(len(bindings), observations, full)


def _compatibility_statuses(db):
    """Project canonical bindings onto unique current MAC runtime asset keys."""
    owners = defaultdict(set)
    for identifier in db.scalars(
        select(InventoryAssetIdentifier).where(
            InventoryAssetIdentifier.identifier_type == InventoryIdentifierType.MAC,
            InventoryAssetIdentifier.is_current.is_(True),
        )
    ):
        try:
            owners[normalize_mac(identifier.normalized_value)].add(identifier.asset_id)
        except InventoryLookupError:
            continue
    statuses = {}
    for binding, state in db.execute(
        select(InventoryExternalBinding, InventoryEndpointState)
        .join(
            InventoryEndpointState,
            InventoryEndpointState.binding_id == InventoryExternalBinding.id,
        )
        .where(*InventoryEndpointService._active())
    ):
        if (
            state.asset_id != binding.asset_id
            or state.endpoint_device_id != binding.external_id
        ):
            continue
        for mac, asset_ids in owners.items():
            if asset_ids != {binding.asset_id}:
                continue
            statuses["mac:" + mac] = {
                "state": "confirmed",
                "device_id": binding.external_id,
                "device_display_name": None,
                "gateway_last_seen_at": state.last_seen_at.isoformat()
                if state.last_seen_at
                else None,
                "baseline_collected_at": state.refreshed_at.isoformat()
                if state.refreshed_at
                else None,
                "profiles": [
                    profile
                    for profile, prefix in PROFILES.items()
                    if getattr(state, prefix + "_snapshot_id")
                ],
                "evidence_kind": "inventory_confirmed_binding",
                "device_type": "pc",
                "os_family": state.safe_context_json.get("os_family")
                if state.safe_context_json.get("os_family") in {"windows", "linux"}
                else None,
            }
    return statuses


def rebuild_endpoint_agent_network_cache(db, now: datetime) -> None:
    store_endpoint_agent_statuses(db, _compatibility_statuses(db), _utc(now))
    db.flush()


def _failure(owner, now, code):
    with session_scope() as db:
        result = db.execute(
            update(InventoryEndpointSyncControl)
            .where(
                InventoryEndpointSyncControl.id == 1,
                InventoryEndpointSyncControl.lease_owner == owner,
            )
            .values(lease_owner=None, lease_expires_at=None, last_safe_error_code=code)
        )
        if result.rowcount != 1:
            return
        for state in db.scalars(
            select(InventoryEndpointState)
            .join(
                InventoryExternalBinding,
                InventoryExternalBinding.id == InventoryEndpointState.binding_id,
            )
            .where(*InventoryEndpointService._active())
        ):
            state.last_checked_at = now
            state.unavailable_since = state.unavailable_since or now
        mark_endpoint_agent_refresh_failed(db, code)


def _renew(owner, now):
    with session_scope() as db:
        result = db.execute(
            update(InventoryEndpointSyncControl)
            .where(
                InventoryEndpointSyncControl.id == 1,
                InventoryEndpointSyncControl.lease_owner == owner,
            )
            .values(lease_expires_at=now + LEASE_INTERVAL)
        )
        if result.rowcount != 1:
            raise EndpointPlatformServiceUnavailable()


def _prepare_pass(adapter, owner, now):
    started = time.monotonic()
    identities = adapter.list_agent_network_identities()
    if len(identities) > MAX_DEVICES:
        raise EndpointPlatformServiceUnavailable()
    _renew(owner, now + timedelta(seconds=time.monotonic() - started))
    with session_scope() as db:
        control = db.get(InventoryEndpointSyncControl, 1)
        full = (
            control.last_full_sync_at is None
            or now - control.last_full_sync_at >= FULL_INTERVAL
        )
        # Dry-run canonical discovery to select only confirmed UUIDs to fetch.
        # Roll it back before any upstream wait, and revalidate on final apply.
        with db.begin_nested() as provisional:
            InventoryEndpointService().reconcile_candidates(db, identities, now)
            device_ids = db.scalars(
                select(InventoryExternalBinding.external_id).where(
                    *InventoryEndpointService._active()
                )
            ).all()
            provisional.rollback()
    if len(device_ids) > MAX_DEVICES:
        raise EndpointPlatformServiceUnavailable()
    snapshots = {}
    if full:
        for device_id in device_ids:
            snapshots[device_id] = adapter.read_profiles(UUID(device_id))
            _renew(owner, now + timedelta(seconds=time.monotonic() - started))
    return _PreparedAdapter(identities, snapshots)


def run_inventory_endpoint_sync(now: datetime | None = None) -> int:
    now = _utc(now or datetime.now(timezone.utc))
    owner = None
    adapter = None
    try:
        init_inventory_endpoint_schema()
        with session_scope() as db:
            if not acquire_endpoint_sync_lease(db, now):
                return 0
            owner = db.get(InventoryEndpointSyncControl, 1).lease_owner
        adapter = get_endpoint_context_adapter()
        prepared = _prepare_pass(adapter, owner, now)
        with session_scope() as db:
            # Fence ownership and hold the control row write lock for the pass.
            held = db.execute(
                update(InventoryEndpointSyncControl)
                .where(
                    InventoryEndpointSyncControl.id == 1,
                    InventoryEndpointSyncControl.lease_owner == owner,
                )
                .values(updated_at=now)
            )
            if held.rowcount != 1:
                return 0
            sync_confirmed_bindings(db, prepared, now)
            statuses = _compatibility_statuses(db)
            rebuild_endpoint_agent_network_cache(db, now)
        # CLI IO is also outside the database transaction. Canonical Endpoint
        # state remains useful if the independent Netctl projection is unavailable.
        sync_endpoint_agent_fingerprint_evidence(
            [{"device_key": key} for key in statuses],
            statuses,
            executor=run_netctl,
        )
        with session_scope() as db:
            control = db.get(InventoryEndpointSyncControl, 1)
            if control.lease_owner == owner:
                control.lease_owner = control.lease_expires_at = None
        return 0
    except EndpointPlatformServiceDisabled:
        code = "endpoint_platform_disabled"
    except EndpointPlatformServiceScopeDenied:
        code = "endpoint_platform_scope_denied"
    except Exception:
        code = "endpoint_platform_unavailable"
    finally:
        if adapter is not None:
            adapter.close()
    if owner is not None:
        try:
            _failure(owner, now, code)
        except Exception:
            pass  # A database outage cannot safely record a control result.
    log.warning("inventory.endpoint_sync outcome=failed code=%s", code)
    return 1


if __name__ == "__main__":
    raise SystemExit(run_inventory_endpoint_sync())
