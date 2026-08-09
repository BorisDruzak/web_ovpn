from __future__ import annotations

import ipaddress
import os
import sqlite3
from collections.abc import Mapping

from .models import FingerprintProfile, FingerprintTarget


ASSET_FINGERPRINT_PROFILE = FingerprintProfile(
    name="asset-fingerprint-v1",
    ttl_seconds=3600,
    stale_running_seconds=60,
)


class FingerprintPolicyError(ValueError):
    """A fingerprint request does not satisfy the bounded asset policy."""


def _timing_setting(
    environment: Mapping[str, str],
    name: str,
    default: int,
    *,
    minimum: int,
    maximum: int,
) -> int:
    raw = environment.get(name)
    if raw is None:
        return default
    try:
        value = int(raw)
    except (TypeError, ValueError):
        raise ValueError(f"{name} must be an integer") from None
    if not minimum <= value <= maximum:
        raise ValueError(f"{name} must be between {minimum} and {maximum}")
    return value


def configured_fingerprint_profile(
    environment: Mapping[str, str] | None = None,
) -> FingerprintProfile:
    """Return the immutable v1 profile with bounded timing configuration."""
    values = os.environ if environment is None else environment
    return FingerprintProfile(
        name=ASSET_FINGERPRINT_PROFILE.name,
        ttl_seconds=_timing_setting(
            values,
            "NETCTL_NMAP_TTL_SECONDS",
            ASSET_FINGERPRINT_PROFILE.ttl_seconds,
            minimum=1,
            maximum=86400,
        ),
        stale_running_seconds=_timing_setting(
            values,
            "NETCTL_NMAP_STALE_RUNNING_SECONDS",
            ASSET_FINGERPRINT_PROFILE.stale_running_seconds,
            minimum=31,
            maximum=600,
        ),
    )


def validate_target_ipv4(value: object) -> str:
    """Return one canonical unicast IPv4 host address or reject it."""
    raw = value if isinstance(value, str) else ""
    try:
        address = ipaddress.IPv4Address(raw)
    except (ipaddress.AddressValueError, ValueError):
        raise FingerprintPolicyError("target must be one canonical IPv4 host address") from None
    if (
        raw != str(address)
        or address.is_unspecified
        or address.is_loopback
        or address.is_multicast
        or address.packed[-1] in {0, 255}
    ):
        raise FingerprintPolicyError("target must be one canonical IPv4 host address")
    return str(address)


def resolve_asset_target(conn: sqlite3.Connection, asset_key: str) -> FingerprintTarget:
    """Resolve exactly one current canonical IPv4 for a known runtime asset."""
    asset = conn.execute(
        "SELECT id, asset_key FROM assets WHERE asset_key = ?",
        (asset_key,),
    ).fetchone()
    if asset is None:
        raise FingerprintPolicyError("asset not found")

    addresses: set[str] = set()
    rows = conn.execute(
        """SELECT ip FROM ip_observations
           WHERE asset_id = ? AND is_current = 1
           ORDER BY last_seen_at DESC, id DESC""",
        (int(asset["id"]),),
    ).fetchall()
    for row in rows:
        raw = row["ip"]
        try:
            observed = ipaddress.ip_address(raw)
        except (TypeError, ValueError):
            raise FingerprintPolicyError(
                "asset must have exactly one current canonical IPv4 address"
            ) from None
        if isinstance(observed, ipaddress.IPv6Address):
            continue
        try:
            addresses.add(validate_target_ipv4(raw))
        except FingerprintPolicyError:
            raise FingerprintPolicyError(
                "asset must have exactly one current canonical IPv4 address"
            ) from None
    if len(addresses) != 1:
        raise FingerprintPolicyError(
            "asset must have exactly one current canonical IPv4 address"
        )
    return FingerprintTarget(
        asset_id=int(asset["id"]),
        asset_key=str(asset["asset_key"]),
        ip=next(iter(addresses)),
    )
