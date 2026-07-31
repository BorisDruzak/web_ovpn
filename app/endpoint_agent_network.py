"""MAC-only correlation between safe Endpoint identities and network assets."""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from typing import Any


_BASELINE_MAC_KEY_RE = re.compile(r"^mac-([0-9a-f]{12})$")
_SAFE_PROFILES = frozenset(("baseline_v1", "health_v1", "network_v1"))


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

