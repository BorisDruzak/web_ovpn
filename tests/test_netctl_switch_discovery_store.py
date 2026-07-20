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
    capabilities_json: str = '[{"capability":"fdb","outcome":"unsupported"}]',
) -> UnknownSwitchFingerprint:
    return UnknownSwitchFingerprint(
        source_id=source_id,
        sys_object_id="1.3.6.1.4.1.9999.1",
        sys_descr="Unknown test switch",
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
