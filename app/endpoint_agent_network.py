"""MAC-only correlation between safe Endpoint identities and network assets."""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import delete
from sqlalchemy.orm import Session

from .models import EndpointAgentNetworkLink, EndpointAgentNetworkRefresh


_BASELINE_MAC_KEY_RE = re.compile(r"^mac-([0-9a-f]{12})$")
_SAFE_PROFILES = frozenset(("baseline_v1", "health_v1", "network_v1"))
_REFRESH_INTERVAL_SECONDS = 300
_REFRESH_LEASE_SECONDS = 60


def normalize_mac(value: object) -> str | None:
    """Normalize standard MAC notation without accepting non-hex identifiers."""
    if not isinstance(value, str):
        return None
    raw = value.strip()
    if not raw or any(character.isalnum() and character.lower() not in "0123456789abcdef" for character in raw):
        return None
    compact = "".join(character for character in raw if character.lower() in "0123456789abcdef")
    return compact.lower() if len(compact) == 12 else None


def _safe_profiles(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return sorted(
        {
            profile
            for item in value
            if isinstance(item, Mapping)
            and isinstance((profile := item.get("profile")), str)
            and profile in _SAFE_PROFILES
        }
    )


def _ambiguous() -> dict[str, object]:
    return {
        "state": "ambiguous",
        "device_id": None,
        "device_display_name": None,
        "gateway_last_seen_at": None,
        "baseline_collected_at": None,
        "profiles": [],
        "evidence_kind": "baseline_interface_mac",
    }


def correlate_endpoint_agents(
    inventory: Iterable[Mapping[str, object]], identities: Iterable[Mapping[str, object]]
) -> dict[str, dict[str, object]]:
    """Confirm only one-asset/one-device exact MAC relationships.

    The function deliberately does not read IP, hostname, device name or agent
    identifier while establishing a relationship.  MAC keys are transient input
    only and are absent from its result.
    """
    assets_by_mac: dict[str, set[str]] = {}
    for asset in inventory:
        asset_key = asset.get("device_key")
        mac = normalize_mac(asset.get("mac"))
        if not isinstance(asset_key, str) or not asset_key or mac is None:
            continue
        assets_by_mac.setdefault(mac, set()).add(asset_key)

    identities_by_id: dict[str, Mapping[str, object]] = {}
    devices_by_mac: dict[str, set[str]] = {}
    for identity in identities:
        device_id = identity.get("id")
        mac_keys = identity.get("baseline_mac_keys")
        if not isinstance(device_id, str) or not device_id or not isinstance(mac_keys, list):
            continue
        identities_by_id[device_id] = identity
        for key in mac_keys:
            if not isinstance(key, str) or (match := _BASELINE_MAC_KEY_RE.fullmatch(key)) is None:
                continue
            devices_by_mac.setdefault(match.group(1), set()).add(device_id)

    results: dict[str, dict[str, object]] = {}
    for mac, asset_keys in assets_by_mac.items():
        device_ids = devices_by_mac.get(mac)
        if not device_ids:
            continue
        if len(asset_keys) != 1 or len(device_ids) != 1:
            for asset_key in asset_keys:
                results[asset_key] = _ambiguous()
            continue
        device_id = next(iter(device_ids))
        identity = identities_by_id[device_id]
        display_name = identity.get("display_name")
        results[next(iter(asset_keys))] = {
            "state": "confirmed",
            "device_id": device_id,
            "device_display_name": display_name if isinstance(display_name, str) else None,
            "gateway_last_seen_at": identity.get("last_seen_at")
            if isinstance(identity.get("last_seen_at"), str)
            else None,
            "baseline_collected_at": identity.get("baseline_collected_at")
            if isinstance(identity.get("baseline_collected_at"), str)
            else None,
            "profiles": _safe_profiles(identity.get("profiles")),
            "evidence_kind": "baseline_interface_mac",
        }
    return results


def _parse_timestamp(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=UTC)


def _timestamp_text(value: datetime | None) -> str | None:
    if value is None:
        return None
    aware = value if value.tzinfo is not None else value.replace(tzinfo=UTC)
    return aware.isoformat().replace("+00:00", "Z")


def _as_utc(value: datetime) -> datetime:
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)


def _refresh_row(db: Session) -> EndpointAgentNetworkRefresh:
    row = db.get(EndpointAgentNetworkRefresh, 1)
    if row is None:
        row = EndpointAgentNetworkRefresh(id=1)
        db.add(row)
        db.flush()
    return row


def acquire_refresh_lease(db: Session, now: datetime) -> bool:
    """Acquire the singleton lease only when a successful result is older than five minutes."""
    refresh = _refresh_row(db)
    current = _as_utc(now)
    if (
        refresh.last_success_at is not None
        and (current - _as_utc(refresh.last_success_at)).total_seconds() < _REFRESH_INTERVAL_SECONDS
    ):
        return False
    if refresh.lease_expires_at is not None and _as_utc(refresh.lease_expires_at) > current:
        return False
    refresh.lease_expires_at = current + timedelta(seconds=_REFRESH_LEASE_SECONDS)
    return True


def mark_endpoint_agent_refresh_failed(db: Session, code: str) -> None:
    """Release a failed refresh without deleting the last successful safe cache."""
    refresh = _refresh_row(db)
    refresh.lease_expires_at = None
    refresh.last_error_code = (
        "endpoint_platform_disabled"
        if code == "endpoint_platform_disabled"
        else "endpoint_platform_unavailable"
    )


def store_endpoint_agent_statuses(
    db: Session, statuses: Mapping[str, Mapping[str, object]], calculated_at: datetime
) -> None:
    """Atomically replace safe cache rows after a fully successful refresh."""
    db.execute(delete(EndpointAgentNetworkLink))
    for asset_key, status in statuses.items():
        state = status.get("state")
        evidence_kind = status.get("evidence_kind")
        if state not in {"confirmed", "ambiguous"} or evidence_kind != "baseline_interface_mac":
            continue
        profiles = status.get("profiles")
        profile_summary = ",".join(
            sorted(profile for profile in profiles if isinstance(profile, str))
        ) if isinstance(profiles, list) else ""
        db.add(
            EndpointAgentNetworkLink(
                asset_key=asset_key,
                state=state,
                device_id=status.get("device_id") if isinstance(status.get("device_id"), str) else None,
                device_display_name=status.get("device_display_name") if isinstance(status.get("device_display_name"), str) else None,
                gateway_last_seen_at=_parse_timestamp(status.get("gateway_last_seen_at")),
                baseline_collected_at=_parse_timestamp(status.get("baseline_collected_at")),
                profile_summary=profile_summary,
                evidence_kind="baseline_interface_mac",
                calculated_at=calculated_at,
            )
        )
    refresh = _refresh_row(db)
    refresh.last_success_at = calculated_at
    refresh.lease_expires_at = None
    refresh.last_error_code = ""


def cached_endpoint_agent_statuses(
    db: Session, _: datetime | None = None
) -> dict[str, dict[str, object]]:
    """Read the MAC-free cache in the exact render shape used by network pages."""
    rows = db.query(EndpointAgentNetworkLink).order_by(EndpointAgentNetworkLink.asset_key).all()
    return {
        row.asset_key: {
            "state": row.state,
            "device_id": row.device_id,
            "device_display_name": row.device_display_name,
            "gateway_last_seen_at": _timestamp_text(row.gateway_last_seen_at),
            "baseline_collected_at": _timestamp_text(row.baseline_collected_at),
            "profiles": [profile for profile in row.profile_summary.split(",") if profile],
            "evidence_kind": row.evidence_kind,
        }
        for row in rows
    }
