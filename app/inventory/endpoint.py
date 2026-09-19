"""Local Inventory authority for Endpoint relations and source-aware context.

No transport belongs here. Callers supply published safe identities and persist
normalized state in the worker; this service never commits the caller's session.
"""

from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from collections.abc import Mapping, Sequence
from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import UUID

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from .lookup import InventoryLookupError, normalize_mac
from .models import (
    InventoryAsset,
    InventoryAssetIdentifier,
    InventoryAssetRelation,
    InventoryAssetType,
    InventoryEndpointState,
    InventoryExternalBinding,
    InventoryExternalBindingStatus as Status,
    InventoryIdentifierType,
    InventoryLocation,
    InventoryObservation,
    InventoryObservationSource,
    InventoryPCDetails,
)
from .service import (
    ASSET_FIELDS,
    PC_DETAIL_FIELDS,
    InventoryService,
    InventoryValidationError,
)

SOURCE = "endpoint_platform"
CANDIDATE_MAX_AGE = timedelta(days=1)
STATE_MAX_AGE = timedelta(minutes=10)
TECHNICAL_FIELDS = frozenset(PC_DETAIL_FIELDS) | {
    "hostname",
    "current_user",
    "agent_version",
    "online",
    "last_seen_at",
    "manufacturer",
    "model",
    "product_uuid",
    "os_build",
    "storage_summary",
}
ENDPOINT_FIELDS = TECHNICAL_FIELDS | {"serial_number", "ip", "mac"}
PROFILE_FIELDS = {
    "baseline_v1": TECHNICAL_FIELDS
    - {"online", "last_seen_at", "current_user", "agent_version"},
    "network_v1": {"ip", "mac"},
    "inventory_v1": TECHNICAL_FIELDS
    - {"online", "last_seen_at", "current_user", "agent_version"},
    "session_v1": {"current_user"},
}


class InventoryEndpointConflict(InventoryValidationError):
    """The rendered discrepancy no longer identifies the current comparison."""


def _discrepancy_revision(asset_id: str, binding_id: str, device_id: str, field: str, manual: Any, endpoint: Any) -> str:
    value = json.dumps([asset_id, binding_id, device_id, field, manual, endpoint], separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _utc(value: datetime) -> datetime:
    return (
        value.replace(tzinfo=timezone.utc)
        if value.tzinfo is None
        else value.astimezone(timezone.utc)
    )


def _timestamp(value: datetime | None) -> str | None:
    return _utc(value).isoformat() if value is not None else None


def _parsed(value: Any) -> datetime | None:
    try:
        result = (
            value
            if isinstance(value, datetime)
            else datetime.fromisoformat(value.replace("Z", "+00:00"))
        )
        return _utc(result) if result.tzinfo is not None else None
    except (AttributeError, TypeError, ValueError):
        return None


def _text(value: Any) -> str | None:
    return (
        value.strip()
        if isinstance(value, str) and 0 < len(value.strip()) <= 255
        else None
    )


def _product_uuid(value: Any) -> str | None:
    try:
        return str(UUID(value)) if isinstance(value, str) else None
    except ValueError:
        return None


def _safe_fields(raw: Mapping[str, Any]) -> dict[str, Any]:
    """Defense in depth against raw or unexpectedly nested persisted payloads."""
    return {
        key: value
        for key, value in raw.items()
        if key in ENDPOINT_FIELDS
        and value is not None
        and (
            isinstance(value, (bool, int, float))
            or isinstance(value, str)
            and len(value) <= 255
        )
    }


def endpoint_profile_freshness(
    cached: InventoryEndpointState, now: datetime
) -> dict[str, dict[str, Any]]:
    """Project bounded profile freshness separately from retained display fields."""
    context = cached.safe_context_json
    statuses = context.get("profile_status")
    if not isinstance(statuses, dict):
        return {}  # Legacy local state has only the aggregate timestamps.
    result = {}
    for profile in (
        "baseline_v1", "health_v1", "network_v1", "inventory_v1", "session_v1"
    ):
        dates = {}
        for source, target in (
            ("profile_collected_at", "collected_at"),
            ("profile_checked_at", "last_checked_at"),
            ("profile_last_success_at", "last_success_at"),
        ):
            values = context.get(source)
            dates[target] = (
                _parsed(values.get(profile)) if isinstance(values, dict) else None
            )
        if (
            cached.unavailable_since
            or context.get("identity_status") == "unavailable"
            or statuses.get(profile) != "available"
        ):
            status = "unavailable"
        else:
            status = (
                "fresh"
                if all(
                    value is not None
                    and timedelta(0) <= _utc(now) - value <= STATE_MAX_AGE
                    for value in (dates["collected_at"], dates["last_checked_at"])
                )
                else "stale"
            )
        result[profile] = {
            "status": status,
            **{key: _timestamp(value) for key, value in dates.items()},
        }
    return result


def _asset_dict(asset: InventoryAsset) -> dict[str, Any]:
    result = {name: getattr(asset, name) for name in sorted(ASSET_FIELDS)}
    result.update(
        id=asset.id, asset_type=asset.asset_type.value, location_id=asset.location_id
    )
    return {
        key: _timestamp(value) if isinstance(value, datetime) else value
        for key, value in result.items()
    }


class InventoryEndpointService:
    def _pc(self, db: Session, asset_id: str) -> InventoryAsset:
        asset = InventoryService._asset_or_error(db, asset_id)
        if asset.asset_type != InventoryAssetType.PC:
            raise InventoryValidationError("only PC can bind Endpoint")
        return asset

    @staticmethod
    def _active():
        return (
            InventoryExternalBinding.source == SOURCE,
            InventoryExternalBinding.status == Status.CONFIRMED,
            InventoryExternalBinding.ended_at.is_(None),
        )

    def _binding(self, db, asset_id, binding_id, status):
        self._pc(db, asset_id)
        row = db.get(InventoryExternalBinding, binding_id)
        if row is None or row.asset_id != asset_id or row.source != SOURCE:
            raise InventoryValidationError("Endpoint binding not found")
        if row.status != status or row.ended_at is not None:
            raise InventoryValidationError("Endpoint binding is not eligible")
        return row

    @staticmethod
    def _actor(actor):
        if not isinstance(actor, str) or not actor.strip() or len(actor) > 120:
            raise InventoryValidationError("valid actor is required")
        return actor.strip()

    def _audit(self, db, row, action, actor, now, **evidence):
        record = InventoryObservation(
            asset_id=row.asset_id,
            binding_id=row.id,
            endpoint_device_id=row.external_id,
            source=InventoryObservationSource.MANUAL,
            observed_at=now,
            data_json={
                "kind": "endpoint_binding",
                "action": action,
                "actor": self._actor(actor),
                "timestamp": _timestamp(now),
                **evidence,
            },
        )
        db.add(record)
        return record

    @staticmethod
    def _anchors(db):
        anchors = defaultdict(lambda: defaultdict(set))
        for asset in db.scalars(
            select(InventoryAsset).where(
                InventoryAsset.asset_type == InventoryAssetType.PC
            )
        ):
            serial = _text(asset.serial_number)
            if serial:
                anchors[asset.id]["serial_exact"].add(serial.casefold())
        for row in db.scalars(
            select(InventoryAssetIdentifier)
            .join(
                InventoryAsset, InventoryAsset.id == InventoryAssetIdentifier.asset_id
            )
            .where(
                InventoryAsset.asset_type == InventoryAssetType.PC,
                InventoryAssetIdentifier.is_current.is_(True),
            )
        ):
            if row.identifier_type == InventoryIdentifierType.MAC:
                try:
                    anchors[row.asset_id]["mac_exact"].add(normalize_mac(row.value))
                except InventoryLookupError:
                    continue
            elif row.identifier_type == InventoryIdentifierType.OTHER:
                value = row.normalized_value
                if value.startswith("product_uuid:"):
                    product = _product_uuid(value[len("product_uuid:") :])
                    if product is not None and value == "product_uuid:" + product:
                        anchors[row.asset_id]["product_uuid_exact"].add(product)
        return anchors

    def reconcile_candidates(
        self, db: Session, identities: Sequence[Mapping[str, Any]], now: datetime
    ) -> list[InventoryExternalBinding]:
        """Reconcile a complete current identity snapshot; never re-match bound PCs.

        Candidate freshness and identity baseline age are capped at 24 hours.
        MAC ambiguity is computed over the whole bipartite graph before writes,
        including already-bound PCs/devices, so iteration order cannot bind one
        of several competing interfaces. UUIDs are opaque, case-preserved IDs.
        """
        now = _utc(now)
        anchors = self._anchors(db)
        asset_index = defaultdict(set)
        for asset_id, methods in anchors.items():
            for method, values in methods.items():
                for value in values:
                    asset_index[(method, value)].add(asset_id)
        matches = defaultdict(lambda: defaultdict(set))
        collected = {}
        for identity in identities:
            device = identity.get("id")
            at = _parsed(identity.get("baseline_collected_at"))
            if not isinstance(device, str) or not device.strip() or len(device) > 255:
                continue
            if at is None or not timedelta(0) <= now - at <= CANDIDATE_MAX_AGE:
                continue
            collected[device] = min(at, collected.get(device, at))
            values = defaultdict(set)
            keys = identity.get("baseline_mac_keys")
            for key in keys if isinstance(keys, list) else []:
                if isinstance(key, str) and key.startswith("mac-") and len(key) == 16:
                    try:
                        values["mac_exact"].add(normalize_mac(key[4:]))
                    except InventoryLookupError:
                        pass
            serial = _text(identity.get("serial_number"))
            product = _product_uuid(identity.get("product_uuid"))
            if serial:
                values["serial_exact"].add(serial.casefold())
            if product:
                values["product_uuid_exact"].add(product)
            for method, items in values.items():
                for value in items:
                    for asset_id in asset_index[(method, value)]:
                        matches[(asset_id, device)][method].add(value)
        mac_assets, mac_devices = defaultdict(set), defaultdict(set)
        for (asset_id, device), methods in matches.items():
            if methods.get("mac_exact"):
                mac_assets[device].add(asset_id)
                mac_devices[asset_id].add(device)
        rows = list(
            db.scalars(
                select(InventoryExternalBinding).where(
                    InventoryExternalBinding.source == SOURCE
                )
            )
        )
        bound_assets = {
            r.asset_id
            for r in rows
            if r.status == Status.CONFIRMED and r.ended_at is None
        }
        bound_devices = {
            r.external_id
            for r in rows
            if r.status == Status.CONFIRMED and r.ended_at is None
        }
        ended_pairs = {
            (r.asset_id, r.external_id)
            for r in rows
            if r.status in {Status.ENDED, Status.REPLACED} and r.ended_at is not None
        }
        previously_bound_assets = {asset_id for asset_id, _ in ended_pairs}
        for row in rows:
            if row.status == Status.CANDIDATE and row.ended_at is None:
                row.evidence_json = {**row.evidence_json, "current": False}
        result = []
        for (asset_id, device), methods in sorted(matches.items()):
            # Discovery must not undo a manual detach or resurrect a replaced
            # UUID, even when the device's network identifiers have changed.
            if asset_id in bound_assets or (asset_id, device) in ended_pairs:
                continue
            method = next(
                m
                for m in ("mac_exact", "serial_exact", "product_uuid_exact")
                if methods.get(m)
            )
            material = {
                "matches": {m: sorted(v)[:64] for m, v in sorted(methods.items())},
                "mac_pc_count": len(mac_assets[device]),
                "mac_endpoint_count": len(mac_devices[asset_id]),
            }
            if any(
                r.asset_id == asset_id
                and r.external_id == device
                and r.status == Status.REJECTED
                and r.evidence_json.get("material") == material
                for r in rows
            ):
                continue
            row = next(
                (
                    r
                    for r in rows
                    if r.asset_id == asset_id
                    and r.external_id == device
                    and r.status == Status.CANDIDATE
                    and r.ended_at is None
                ),
                None,
            )
            evidence = {
                "material": material,
                "current": True,
                "observed_at": _timestamp(collected[device]),
            }
            auto = (
                method == "mac_exact"
                and len(mac_assets[device]) == len(mac_devices[asset_id]) == 1
                and device not in bound_devices
                and asset_id not in previously_bound_assets
            )
            if row is None:
                row = InventoryExternalBinding(
                    asset_id=asset_id,
                    source=SOURCE,
                    external_id=device,
                    status=Status.CANDIDATE,
                    binding_method=method,
                    confidence=100 if auto else 50,
                    first_seen_at=now,
                    created_at=now,
                    created_by="inventory-endpoint-sync",
                )
                db.add(row)
            row.evidence_json = evidence
            row.binding_method = method
            row.last_verified_at = now
            row.updated_at = now
            if auto:
                row.status = Status.CONFIRMED
                row.confidence = 100
            db.flush()
            result.append(row)
        db.flush()
        return result

    def _unique(self, db, asset_id, external_id, *, except_id=None):
        conflict = db.scalar(
            select(InventoryExternalBinding).where(
                *self._active(),
                or_(
                    InventoryExternalBinding.asset_id == asset_id,
                    InventoryExternalBinding.external_id == external_id,
                ),
                InventoryExternalBinding.id != except_id if except_id else True,
            )
        )
        if conflict:
            raise InventoryValidationError(
                "Endpoint binding conflicts with an active binding"
            )

    def confirm_binding(
        self, db: Session, asset_id: str, binding_id: str, actor: str, now: datetime
    ) -> InventoryExternalBinding:
        actor = self._actor(actor)
        row = self._binding(db, asset_id, binding_id, Status.CANDIDATE)
        at = row.last_verified_at
        observed = _parsed(row.evidence_json.get("observed_at"))
        if (
            not row.evidence_json.get("current")
            or at is None
            or observed is None
            or not timedelta(0) <= _utc(now) - _utc(at) <= CANDIDATE_MAX_AGE
            or not timedelta(0) <= _utc(now) - observed <= CANDIDATE_MAX_AGE
        ):
            raise InventoryValidationError("Endpoint candidate is stale")
        anchors = self._anchors(db).get(asset_id, {})
        matches = row.evidence_json.get("material", {}).get("matches", {})
        if not any(
            set(values) & anchors.get(method, set())
            for method, values in matches.items()
        ):
            raise InventoryValidationError("Endpoint candidate evidence changed")
        self._unique(db, asset_id, row.external_id)
        row.status, row.last_verified_at, row.updated_at = (
            Status.CONFIRMED,
            _utc(now),
            _utc(now),
        )
        self._audit(db, row, "confirm", actor, now)
        db.flush()
        return row

    def reject_binding(
        self, db: Session, asset_id: str, binding_id: str, actor: str, now: datetime
    ) -> InventoryExternalBinding:
        actor = self._actor(actor)
        row = self._binding(db, asset_id, binding_id, Status.CANDIDATE)
        row.status, row.ended_at, row.updated_at = Status.REJECTED, _utc(now), _utc(now)
        self._audit(db, row, "reject", actor, now)
        db.flush()
        return row

    def detach_binding(
        self, db: Session, asset_id: str, binding_id: str, actor: str, now: datetime
    ) -> InventoryExternalBinding:
        actor = self._actor(actor)
        row = self._binding(db, asset_id, binding_id, Status.CONFIRMED)
        row.status, row.ended_at, row.updated_at = Status.ENDED, _utc(now), _utc(now)
        self._audit(db, row, "detach", actor, now)
        db.flush()
        return row

    def replace_binding(
        self,
        db: Session,
        asset_id: str,
        binding_id: str,
        endpoint_device_id: str,
        actor: str,
        now: datetime,
    ) -> InventoryExternalBinding:
        actor = self._actor(actor)
        old = self._binding(db, asset_id, binding_id, Status.CONFIRMED)
        if (
            not isinstance(endpoint_device_id, str)
            or not endpoint_device_id.strip()
            or len(endpoint_device_id) > 255
            or endpoint_device_id == old.external_id
        ):
            raise InventoryValidationError("a different Endpoint device is required")
        self._unique(db, asset_id, endpoint_device_id, except_id=old.id)
        with db.begin_nested():
            old.status, old.ended_at, old.updated_at = (
                Status.REPLACED,
                _utc(now),
                _utc(now),
            )
            candidates = db.scalars(
                select(InventoryExternalBinding).where(
                    InventoryExternalBinding.asset_id == asset_id,
                    InventoryExternalBinding.source == SOURCE,
                    InventoryExternalBinding.external_id == endpoint_device_id,
                    InventoryExternalBinding.status == Status.CANDIDATE,
                    InventoryExternalBinding.ended_at.is_(None),
                )
            ).all()
            for candidate in candidates:
                candidate.status = Status.REPLACED
                candidate.ended_at = candidate.updated_at = _utc(now)
                self._audit(db, candidate, "superseded_by_replacement", actor, now)
            db.flush()
            new = InventoryExternalBinding(
                asset_id=asset_id,
                source=SOURCE,
                external_id=endpoint_device_id,
                status=Status.CONFIRMED,
                binding_method="manual",
                confidence=100,
                evidence_json={"replaces_binding_id": old.id},
                created_by=actor,
                first_seen_at=_utc(now),
                last_verified_at=_utc(now),
                created_at=_utc(now),
                updated_at=_utc(now),
            )
            db.add(new)
            db.flush()
            self._audit(db, old, "replace", actor, now, replacement_binding_id=new.id)
            self._audit(
                db, new, "confirm_replacement", actor, now, replaced_binding_id=old.id
            )
        return new

    def reconnect_binding(
        self, db: Session, asset_id: str, binding_id: str, actor: str, now: datetime
    ) -> InventoryExternalBinding:
        """Explicitly reconnect a detached relationship, retaining its history."""
        actor = self._actor(actor)
        self._pc(db, asset_id)
        old = db.get(InventoryExternalBinding, binding_id)
        if (
            old is None or old.asset_id != asset_id or old.source != SOURCE
            or old.status != Status.ENDED or old.ended_at is None
            or old.evidence_json.get("reconnected_binding_id")
        ):
            raise InventoryValidationError("Endpoint binding is not eligible for reconnect")
        self._unique(db, asset_id, old.external_id)
        new = InventoryExternalBinding(
            asset_id=asset_id, source=SOURCE, external_id=old.external_id,
            status=Status.CONFIRMED, binding_method="manual", confidence=100,
            evidence_json={"reconnects_binding_id": old.id}, created_by=actor,
            first_seen_at=_utc(now), last_verified_at=_utc(now),
            created_at=_utc(now), updated_at=_utc(now),
        )
        db.add(new)
        db.flush()
        old.evidence_json = {**old.evidence_json, "reconnected_binding_id": new.id}
        old.updated_at = _utc(now)
        self._audit(db, new, "reconnect", actor, now, detached_binding_id=old.id)
        db.flush()
        return new

    def lookup_confirmed_endpoint(
        self, db: Session, endpoint_device_id: str
    ) -> InventoryAsset | None:
        return db.scalar(
            select(InventoryAsset)
            .join(
                InventoryExternalBinding,
                InventoryExternalBinding.asset_id == InventoryAsset.id,
            )
            .where(
                *self._active(),
                InventoryExternalBinding.external_id == endpoint_device_id,
                InventoryAsset.asset_type == InventoryAssetType.PC,
            )
        )

    def asset_context(
        self, db: Session, asset_id: str, now: datetime
    ) -> dict[str, Any]:
        inventory = InventoryService()
        asset = inventory._asset_or_error(db, asset_id)
        manual = {
            "asset": _asset_dict(asset),
            "details": inventory.details_for(db, asset),
            "identifiers": [],
        }
        netctl = {"identifiers": []}
        effective = {
            field: {
                "value": value,
                "source": "manual",
                "observed_at": _timestamp(asset.updated_at),
            }
            for field, value in {**manual["asset"], **manual["details"]}.items()
            if value is not None
        }
        for identifier in inventory.identifiers_for(db, asset):
            record = {
                "type": identifier.identifier_type.value,
                "value": identifier.value,
                "observed_at": _timestamp(identifier.last_seen_at),
            }
            if identifier.source == InventoryObservationSource.NETCTL:
                netctl["identifiers"].append(record)
            elif identifier.source == InventoryObservationSource.MANUAL:
                manual["identifiers"].append(record)
            if identifier.source in (
                InventoryObservationSource.NETCTL,
                InventoryObservationSource.MANUAL,
            ):
                field = identifier.identifier_type.value
                if field != "other" and (
                    field not in effective
                    or identifier.source == InventoryObservationSource.NETCTL
                ):
                    effective[field] = {
                        "value": identifier.value,
                        "source": identifier.source.value,
                        "observed_at": record["observed_at"],
                    }
        binding = db.scalar(
            select(InventoryExternalBinding).where(
                *self._active(), InventoryExternalBinding.asset_id == asset_id
            )
        )
        cached = db.get(InventoryEndpointState, binding.id) if binding else None
        if cached and (
            cached.asset_id != asset_id
            or cached.endpoint_device_id != binding.external_id
        ):
            cached = None
        endpoint = _safe_fields(cached.safe_context_json) if cached else {}
        if cached:
            endpoint.update(
                {
                    k: v
                    for k, v in {
                        "online": cached.online,
                        "last_seen_at": _timestamp(cached.last_seen_at),
                        "agent_version": cached.agent_version,
                    }.items()
                    if v is not None
                }
            )
        observed_at = _timestamp(cached.refreshed_at) if cached else None
        profile_freshness = endpoint_profile_freshness(cached, now) if cached else {}
        for field, value in endpoint.items():
            if field in TECHNICAL_FIELDS or field not in effective:
                effective[field] = {
                    "value": value,
                    "source": "endpoint",
                    "observed_at": observed_at,
                }
                profile = next(
                    (
                        name
                        for name, fields in PROFILE_FIELDS.items()
                        if field in fields
                    ),
                    None,
                )
                if profile in profile_freshness:
                    effective[field]["observed_at"] = profile_freshness[profile][
                        "collected_at"
                    ]
                    effective[field]["freshness"] = profile_freshness[profile]["status"]
        discrepancies = []
        decisions = list(
            db.scalars(
                select(InventoryObservation)
                .where(
                    InventoryObservation.asset_id == asset_id,
                    InventoryObservation.source == InventoryObservationSource.MANUAL,
                )
                .order_by(
                    InventoryObservation.observed_at.desc(),
                    InventoryObservation.id.desc(),
                )
            )
        )
        for field in ("ram_gb", "serial_number"):
            manual_value = (
                manual["details"].get(field)
                if field == "ram_gb"
                else asset.serial_number
            )
            endpoint_value = endpoint.get(field)
            if (
                manual_value is None
                or endpoint_value is None
                or manual_value == endpoint_value
            ):
                continue
            disposition = next(
                (
                    r.data_json
                    for r in decisions
                    if r.binding_id == binding.id
                    and r.data_json.get("kind") == "endpoint_disposition"
                    and r.data_json.get("field") == field
                    and r.data_json.get("old_value") == manual_value
                    and r.data_json.get("endpoint_value") == endpoint_value
                ),
                None,
            )
            if disposition is not None and disposition.get("action") == "keep_manual":
                effective[field] = {
                    "value": manual_value,
                    "source": "manual",
                    "observed_at": _timestamp(asset.updated_at),
                }
            discrepancies.append(
                {
                    "field": field,
                    "manual": manual_value,
                    "endpoint": endpoint_value,
                    "revision": _discrepancy_revision(asset_id, binding.id, binding.external_id, field, manual_value, endpoint_value),
                    "disposition": disposition,
                }
            )
        freshness = "missing"
        if cached:
            freshness = (
                "unavailable"
                if cached.unavailable_since
                else (
                    "fresh"
                    if cached.last_success_at
                    and timedelta(0)
                    <= _utc(now) - _utc(cached.last_success_at)
                    <= STATE_MAX_AGE
                    else "stale"
                )
            )
            if profile_freshness:
                freshness = profile_freshness["baseline_v1"]["status"]
        location = (
            db.get(InventoryLocation, asset.location_id) if asset.location_id else None
        )
        children = db.scalars(
            select(InventoryAsset)
            .join(
                InventoryAssetRelation,
                InventoryAssetRelation.child_asset_id == InventoryAsset.id,
            )
            .where(
                InventoryAssetRelation.parent_asset_id == asset_id,
                InventoryAssetRelation.ended_at.is_(None),
            )
            .order_by(InventoryAsset.id)
        ).all()
        return {
            "asset": manual["asset"],
            "detached_bindings": [
                {"id": row.id, "external_id": row.external_id}
                for row in db.scalars(select(InventoryExternalBinding).where(
                    InventoryExternalBinding.asset_id == asset_id,
                    InventoryExternalBinding.source == SOURCE,
                    InventoryExternalBinding.status == Status.ENDED,
                    InventoryExternalBinding.ended_at.is_not(None),
                ).order_by(InventoryExternalBinding.ended_at.desc()).limit(100))
                if not row.evidence_json.get("reconnected_binding_id")
            ] if binding is None else [],
            "location": {
                "id": location.id,
                "name": location.name,
                "comment": location.comment,
            }
            if location
            else None,
            "related_devices": [_asset_dict(child) for child in children],
            "sources": {"manual": manual, "netctl": netctl, "endpoint": endpoint},
            "manual": manual,
            "binding": {
                "id": binding.id,
                "external_id": binding.external_id,
                "status": binding.status.value,
                "binding_method": binding.binding_method,
            }
            if binding
            else None,
            "effective": effective,
            "discrepancies": discrepancies,
            "freshness": {
                "endpoint": {
                    "status": freshness,
                    "last_success_at": _timestamp(cached.last_success_at)
                    if cached
                    else None,
                    "last_checked_at": _timestamp(cached.last_checked_at)
                    if cached
                    else None,
                    "refreshed_at": observed_at,
                    "unavailable_since": _timestamp(cached.unavailable_since)
                    if cached
                    else None,
                    "profiles": profile_freshness,
                }
            },
        }

    def resolve_discrepancy(
        self,
        db: Session,
        asset_id: str,
        field: str,
        action: str,
        actor: str,
        now: datetime,
        expected_revision: str | None = None,
    ) -> InventoryObservation:
        actor = self._actor(actor)
        asset = self._pc(db, asset_id)
        if field not in {"ram_gb", "serial_number"} or action not in {
            "accept_endpoint",
            "keep_manual",
            "mark_verified",
        }:
            raise InventoryValidationError("unsupported discrepancy disposition")
        context = self.asset_context(db, asset_id, now)
        discrepancy = next(
            (d for d in context["discrepancies"] if d["field"] == field), None
        )
        if expected_revision is not None and (
            discrepancy is None or discrepancy["revision"] != expected_revision
        ):
            raise InventoryEndpointConflict("inventory_endpoint_discrepancy_changed")
        if discrepancy is None:
            raise InventoryValidationError("current Endpoint discrepancy not found")
        old, endpoint_value = discrepancy["manual"], discrepancy["endpoint"]
        if field == "ram_gb" and (
            type(endpoint_value) is not int or endpoint_value <= 0
        ):
            raise InventoryValidationError("invalid Endpoint RAM value")
        if field == "serial_number" and _text(endpoint_value) is None:
            raise InventoryValidationError("invalid Endpoint serial value")
        new = old
        if action == "accept_endpoint":
            new = endpoint_value
            if field == "ram_gb":
                # Updating just RAM must not reset other manual detail choices.
                db.get(InventoryPCDetails, asset_id).ram_gb = new
            else:
                asset.serial_number = new
        elif action == "mark_verified":
            asset.last_verified_at = _utc(now)
        record = InventoryObservation(
            asset_id=asset_id,
            binding_id=context["binding"]["id"],
            endpoint_device_id=context["binding"]["external_id"],
            source=InventoryObservationSource.MANUAL,
            observed_at=_utc(now),
            data_json={
                "kind": "endpoint_disposition",
                "field": field,
                "action": action,
                "old_value": old,
                "new_value": new,
                "endpoint_value": endpoint_value,
                "actor": actor,
                "timestamp": _timestamp(now),
                "endpoint_observed_at": context["freshness"]["endpoint"][
                    "refreshed_at"
                ],
            },
        )
        db.add(record)
        db.flush()
        return record
