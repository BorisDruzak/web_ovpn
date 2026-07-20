from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from netctl.db import connect, get_source, upsert_source
from netctl.switch_discovery_store import (
    UnknownSwitchFingerprint,
    list_unknown_fingerprints,
    record_unknown_fingerprint,
)


def _db_url(path: Path) -> str:
    return f"sqlite:///{path.as_posix()}"


def _source(conn: sqlite3.Connection, name: str = "unknown-switch") -> int:
    upsert_source(
        conn,
        {
            "name": name,
            "driver": "snmp_switch",
            "host": "192.0.2.7",
            "port": 161,
            "username": "",
            "secret_ref": "test-secret-ref",
            "tls": False,
            "verify_tls": False,
            "site": "test",
            "role": "switch",
            "enabled": False,
            "driver_options": {},
        },
    )
    source = get_source(conn, name)
    assert source is not None
    return int(source["id"])


def _observation(
    *,
    source_id: int,
    digest: str = "a" * 64,
    capabilities_json: str = '[{"capability":"sys_descr","outcome":"success_with_rows"}]',
    sys_object_id: str = "1.3.6.1.4.1.9999.1",
    sys_descr: str = "Unknown test switch",
) -> UnknownSwitchFingerprint:
    return UnknownSwitchFingerprint(
        source_id=source_id,
        sys_object_id=sys_object_id,
        sys_descr=sys_descr,
        fingerprint_sha256=digest,
        capabilities_json=capabilities_json,
        status="requires_profile",
        observed_at="2026-07-20T10:00:00Z",
    )


def test_unknown_fingerprint_upserts_one_row_per_source(tmp_path: Path) -> None:
    conn = connect(_db_url(tmp_path / "discovery.sqlite"))
    try:
        source_id = _source(conn)
        record_unknown_fingerprint(conn, _observation(source_id=source_id, digest="a" * 64))
        record_unknown_fingerprint(conn, _observation(source_id=source_id, digest="b" * 64))

        assert [row["fingerprint_sha256"] for row in list_unknown_fingerprints(conn)] == ["b" * 64]
    finally:
        conn.close()


def test_unknown_fingerprint_rejects_secret_like_capability_value(tmp_path: Path) -> None:
    conn = connect(_db_url(tmp_path / "discovery.sqlite"))
    try:
        source_id = _source(conn)
        with pytest.raises(ValueError, match="capabilities"):
            record_unknown_fingerprint(
                conn,
                _observation(
                    source_id=source_id,
                    capabilities_json=(
                        '[{"capability":"sys_descr","outcome":"community=private"}]'
                    ),
                ),
            )
        assert list_unknown_fingerprints(conn) == []
    finally:
        conn.close()


@pytest.mark.parametrize(
    ("sys_object_id", "sys_descr"),
    [
        ("192.0.2.7", "Unknown test switch"),
        ("1.3.6.1.4.1.9999.1", "Unknown switch password=private"),
    ],
)
def test_unknown_fingerprint_rejects_endpoint_or_credential_identity(
    tmp_path: Path, sys_object_id: str, sys_descr: str
) -> None:
    conn = connect(_db_url(tmp_path / "discovery.sqlite"))
    try:
        source_id = _source(conn)
        with pytest.raises(ValueError, match="system identity"):
            record_unknown_fingerprint(
                conn,
                _observation(
                    source_id=source_id,
                    sys_object_id=sys_object_id,
                    sys_descr=sys_descr,
                ),
            )
        assert list_unknown_fingerprints(conn) == []
    finally:
        conn.close()


def test_unknown_fingerprint_list_skips_unsafe_persisted_values(tmp_path: Path) -> None:
    conn = connect(_db_url(tmp_path / "discovery.sqlite"))
    try:
        source_id = _source(conn)
        conn.execute(
            """
            INSERT INTO switch_unknown_fingerprints (
                source_id, sys_object_id, sys_descr, fingerprint_sha256,
                capabilities_json, status, observed_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                source_id,
                "192.0.2.7",
                "Unknown switch password=private",
                "a" * 64,
                '[{"capability":"sys_descr","outcome":"community=private"}]',
                "requires_profile",
                "2026-07-20T10:00:00Z",
            ),
        )
        conn.commit()

        assert list_unknown_fingerprints(conn) == []
    finally:
        conn.close()


def test_unknown_fingerprint_rejects_private_capability_keys(tmp_path: Path) -> None:
    conn = connect(_db_url(tmp_path / "discovery.sqlite"))
    try:
        source_id = _source(conn)
        with pytest.raises(ValueError, match="capabilities"):
            record_unknown_fingerprint(
                conn,
                _observation(
                    source_id=source_id,
                    capabilities_json='[{"community":"x"}]',
                ),
            )
    finally:
        conn.close()
