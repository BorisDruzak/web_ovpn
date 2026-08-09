from __future__ import annotations

from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest


def _asset_db(tmp_path: Path, ips: list[str]):
    from netctl.db import connect

    conn = connect(f"sqlite:///{(tmp_path / 'nmap-policy.sqlite').as_posix()}")
    now = "2026-08-09T08:00:00Z"
    asset_id = conn.execute(
        """INSERT INTO assets
           (asset_key, identity_method, identity_confidence, provisional,
            first_seen_at, last_seen_at, created_at, updated_at)
           VALUES ('mac:AA:BB:CC:DD:EE:01', 'manual', 100, 0, ?, ?, ?, ?)""",
        (now, now, now, now),
    ).lastrowid
    for index, ip in enumerate(ips):
        conn.execute(
            """INSERT INTO ip_observations
               (asset_id, source_key, ip, first_seen_at, last_seen_at,
                is_current, observation_source)
               VALUES (?, ?, ?, ?, ?, 1, 'collector_host')""",
            (asset_id, f"source-{index}", ip, now, now),
        )
    conn.commit()
    return conn


def test_asset_fingerprint_profile_is_immutable_and_bounded() -> None:
    """Making the scan profile mutable would let request data expand scan scope."""
    from netctl.nmap.policy import ASSET_FINGERPRINT_PROFILE

    assert ASSET_FINGERPRINT_PROFILE.name == "asset-fingerprint-v1"
    assert ASSET_FINGERPRINT_PROFILE.ttl_seconds == 3600
    assert ASSET_FINGERPRINT_PROFILE.stale_running_seconds > 30
    with pytest.raises(FrozenInstanceError):
        ASSET_FINGERPRINT_PROFILE.name = "browser-supplied"  # type: ignore[misc]


@pytest.mark.parametrize(
    "value",
    [
        "192.0.2.0/24",
        "host.example",
        "192.168.1.10 -p 1-65535",
        "192.168.001.010",
        " 192.168.1.10",
        "0.0.0.0",
        "127.0.0.1",
        "224.0.0.1",
        "192.168.1.0",
        "192.168.1.255",
        "255.255.255.255",
        "2001:db8::1",
    ],
)
def test_validate_target_ipv4_rejects_noncanonical_or_unsafe_targets(value: str) -> None:
    """Weak validation would turn the helper into a hostname/CIDR/argument scanner."""
    from netctl.nmap.policy import FingerprintPolicyError, validate_target_ipv4

    with pytest.raises(FingerprintPolicyError, match="canonical IPv4"):
        validate_target_ipv4(value)


def test_validate_target_ipv4_accepts_one_canonical_host_address() -> None:
    from netctl.nmap.policy import validate_target_ipv4

    assert validate_target_ipv4("192.168.100.55") == "192.168.100.55"


def test_resolve_asset_target_requires_an_existing_runtime_asset(tmp_path: Path) -> None:
    """Accepting a caller-provided IP would bypass the runtime asset boundary."""
    from netctl.nmap.policy import FingerprintPolicyError, resolve_asset_target

    conn = _asset_db(tmp_path, ["192.168.100.55"])
    try:
        with pytest.raises(FingerprintPolicyError, match="asset not found"):
            resolve_asset_target(conn, "192.168.100.99")
    finally:
        conn.close()


def test_resolve_asset_target_requires_exactly_one_current_canonical_ipv4(
    tmp_path: Path,
) -> None:
    """Choosing among distinct current addresses could fingerprint the wrong host."""
    from netctl.nmap.policy import FingerprintPolicyError, resolve_asset_target

    conn = _asset_db(tmp_path, ["192.168.100.55", "192.168.100.56"])
    try:
        with pytest.raises(FingerprintPolicyError, match="exactly one current canonical IPv4"):
            resolve_asset_target(conn, "mac:AA:BB:CC:DD:EE:01")
    finally:
        conn.close()


def test_resolve_asset_target_deduplicates_same_current_address_evidence(
    tmp_path: Path,
) -> None:
    """Two sources observing the same IP are still one canonical target."""
    from netctl.nmap.policy import resolve_asset_target

    conn = _asset_db(tmp_path, ["192.168.100.55", "192.168.100.55"])
    try:
        target = resolve_asset_target(conn, "mac:AA:BB:CC:DD:EE:01")
    finally:
        conn.close()

    assert target.asset_id == 1
    assert target.asset_key == "mac:AA:BB:CC:DD:EE:01"
    assert target.ip == "192.168.100.55"


def test_resolve_asset_target_ignores_current_ipv6_evidence(tmp_path: Path) -> None:
    """Version 1 must select the one IPv4 without treating IPv6 as a second target."""
    from netctl.nmap.policy import resolve_asset_target

    conn = _asset_db(tmp_path, ["192.168.100.55", "2001:db8::55"])
    try:
        target = resolve_asset_target(conn, "mac:AA:BB:CC:DD:EE:01")
    finally:
        conn.close()

    assert target.ip == "192.168.100.55"


@pytest.mark.parametrize(
    "invalid",
    ["192.168.100.0/24", "host.example", "192.168.100.0", "192.168.100.255"],
)
def test_resolve_asset_target_rejects_invalid_current_values_beside_ipv4(
    tmp_path: Path, invalid: str
) -> None:
    """Only valid IPv6 is irrelevant; malformed or unsafe IP evidence is ambiguous."""
    from netctl.nmap.policy import FingerprintPolicyError, resolve_asset_target

    conn = _asset_db(tmp_path, ["192.168.100.55", invalid])
    try:
        with pytest.raises(
            FingerprintPolicyError,
            match="exactly one current canonical IPv4",
        ):
            resolve_asset_target(conn, "mac:AA:BB:CC:DD:EE:01")
    finally:
        conn.close()
