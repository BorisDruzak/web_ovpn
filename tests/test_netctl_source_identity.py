from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest


def _router_source(**overrides: object) -> dict[str, object]:
    source: dict[str, object] = {
        "name": "router-main",
        "driver": "mikrotik_api",
        "host": "192.0.2.1",
        "username": "netctl",
        "secret_ref": "router_main",
        "runtime_asset_key": "mac:D4:01:C3:9C:83:5F",
        "intent_context_id": "sosn-admin-network",
        "intent_stable_id": "mikrotik-rb3011-sosn",
        "topology_role": "core",
    }
    source.update(overrides)
    return source


def test_generic_source_identity_options_are_normalized_and_persistable() -> None:
    from netctl.config import normalize_source
    from netctl.db import _encode_driver_options

    normalized = normalize_source(_router_source())

    assert normalized["driver_options"] == {
        "runtime_asset_key": "mac:D4:01:C3:9C:83:5F",
        "intent_context_id": "sosn-admin-network",
        "intent_stable_id": "mikrotik-rb3011-sosn",
        "topology_role": "core",
    }
    assert _encode_driver_options("mikrotik_api", normalized["driver_options"]) == (
        '{"intent_context_id":"sosn-admin-network",'
        '"intent_stable_id":"mikrotik-rb3011-sosn",'
        '"runtime_asset_key":"mac:D4:01:C3:9C:83:5F",'
        '"topology_role":"core"}'
    )


def test_source_readiness_reports_stable_blocking_reason_without_secret_data(tmp_path: Path) -> None:
    from netctl.db import connect
    from netctl.source_identity import source_readiness

    conn = connect(_db_url(tmp_path / "readiness.sqlite"))
    try:
        _insert_source(conn, name="unbound-switch", driver="snmp_switch", options={})
        conn.commit()
        assert source_readiness(conn) == [{
            "source": "unbound-switch", "driver": "snmp_switch", "site": "",
            "topology_role": "unknown", "runtime_asset_status": "missing",
            "intent_binding_status": "missing", "management_mac_count": 0,
            "latest_authoritative_fdb_run_id": None, "known_switch_port_count": 0,
            "eligible_for_topology": False, "blocking_reasons": ["missing_topology_role"],
        }]
    finally:
        conn.close()


@pytest.mark.parametrize(
    ("override", "message"),
    [
        ({"topology_role": "aggregation"}, "topology_role is invalid"),
        ({"topology_role": "   "}, "topology_role is invalid"),
        ({"intent_stable_id": "   "}, "intent_stable_id must not be whitespace only"),
        ({"intent_context_id": "\t"}, "intent_context_id must not be whitespace only"),
        ({"runtime_asset_key": " "}, "runtime_asset_key must not be whitespace only"),
    ],
)
def test_generic_source_identity_options_reject_invalid_scalars(
    override: dict[str, object], message: str
) -> None:
    from netctl.config import normalize_source

    with pytest.raises(ValueError, match=message):
        normalize_source(_router_source(**override))


def _db_url(path: Path) -> str:
    return f"sqlite:///{path.as_posix()}"


def _insert_asset(
    conn: sqlite3.Connection, *, asset_key: str, macs: tuple[str, ...]
) -> int:
    now = "2026-07-22T08:00:00Z"
    cursor = conn.execute(
        """
        INSERT INTO assets (
            asset_key, identity_method, identity_confidence, provisional,
            first_seen_at, last_seen_at, created_at, updated_at
        ) VALUES (?, 'manual', 100, 0, ?, ?, ?, ?)
        """,
        (asset_key, now, now, now, now),
    )
    asset_id = int(cursor.lastrowid)
    for index, mac in enumerate(macs, start=1):
        conn.execute(
            """
            INSERT INTO asset_interfaces (
                asset_id, interface_key, mac, first_seen_at, last_seen_at
            ) VALUES (?, ?, ?, ?, ?)
            """,
            (asset_id, f"iface-{index}", mac, now, now),
        )
    return asset_id


def _insert_source(
    conn: sqlite3.Connection,
    *,
    name: str,
    driver: str,
    options: dict[str, object],
    secret_ref: str = "source_secret",
) -> int:
    now = "2026-07-22T08:00:00Z"
    cursor = conn.execute(
        """
        INSERT INTO network_sources (
            name, driver, host, port, username, secret_ref,
            driver_options_json, created_at, updated_at
        ) VALUES (?, ?, '192.0.2.1', 8729, 'netctl', ?, ?, ?, ?)
        """,
        (name, driver, secret_ref, json.dumps(options), now, now),
    )
    return int(cursor.lastrowid)


def _activate_intent_asset(
    conn: sqlite3.Connection, *, context_id: str, stable_id: str, lifecycle: str = "active"
) -> None:
    now = "2026-07-22T08:00:00Z"
    revision_id = int(
        conn.execute(
            """
            INSERT INTO context_revisions (
                context_id, schema_version, sha256, source_path, validated_at,
                git_sha, status, error_json, counts_json, validation_order
            ) VALUES (?, '2.2.0', ?, 'context.yaml', ?, 'test', 'ok', '[]', '{}', 1)
            """,
            (context_id, f"{context_id}-sha", now),
        ).lastrowid
    )
    run_id = int(
        conn.execute(
            """
            INSERT INTO context_import_runs (
                context_id, context_revision_id, input_sha256, git_sha,
                source_path, started_at, finished_at, status
            ) VALUES (?, ?, 'a', 'test', 'context.yaml', ?, ?, 'success_imported')
            """,
            (context_id, revision_id, now, now),
        ).lastrowid
    )
    conn.execute(
        """
        INSERT INTO context_heads (
            context_id, context_revision_id, activated_by_import_run_id, activated_at
        ) VALUES (?, ?, ?, ?)
        """,
        (context_id, revision_id, run_id, now),
    )
    conn.execute(
        """
        INSERT INTO intent_assets (
            context_revision_id, stable_id, lifecycle, canonical_json,
            canonical_hash, origin_context_revision_id
        ) VALUES (?, ?, ?, '{}', ?, ?)
        """,
        (revision_id, stable_id, lifecycle, f"{stable_id}-hash", revision_id),
    )


def test_list_source_identities_resolves_switch_and_router_bindings(tmp_path: Path) -> None:
    from netctl.db import connect
    from netctl.source_identity import list_source_identities

    conn = connect(_db_url(tmp_path / "identities.sqlite"))
    try:
        router_asset_id = _insert_asset(
            conn,
            asset_key="mac:D4:01:C3:9C:83:5F",
            macs=("d4-01-c3-9c-83-5f",),
        )
        switch_asset_id = _insert_asset(
            conn,
            asset_key="mac:02:00:00:00:00:16",
            macs=("02:00:00:00:00:16",),
        )
        _activate_intent_asset(
            conn, context_id="sosn-admin-network", stable_id="mikrotik-rb3011-sosn"
        )
        router_source_id = _insert_source(
            conn,
            name="router-main",
            driver="mikrotik_api",
            secret_ref="router_private_secret",
            options={
                "runtime_asset_key": "mac:D4:01:C3:9C:83:5F",
                "intent_context_id": "sosn-admin-network",
                "intent_stable_id": "mikrotik-rb3011-sosn",
                "topology_role": "core",
            },
        )
        switch_source_id = _insert_source(
            conn,
            name="switch-main",
            driver="snmp_switch",
            options={"topology_role": "access"},
        )
        conn.execute(
            """
            INSERT INTO switch_devices (source_id, runtime_asset_id, updated_at)
            VALUES (?, ?, '2026-07-22T08:00:00Z')
            """,
            (switch_source_id, switch_asset_id),
        )
        conn.commit()

        identities = {identity.source_name: identity for identity in list_source_identities(conn)}

        assert identities["router-main"].source_id == router_source_id
        assert identities["router-main"].runtime_asset_id == router_asset_id
        assert identities["router-main"].management_macs == ("D4:01:C3:9C:83:5F",)
        assert identities["router-main"].topology_role == "core"
        assert identities["router-main"].intent_context_id == "sosn-admin-network"
        assert identities["router-main"].intent_stable_id == "mikrotik-rb3011-sosn"
        assert identities["switch-main"].runtime_asset_id == switch_asset_id
        assert identities["switch-main"].runtime_asset_key == "mac:02:00:00:00:00:16"
        assert identities["switch-main"].management_macs == ("02:00:00:00:00:16",)
        assert identities["switch-main"].topology_role == "access"
        assert "router_private_secret" not in repr(identities["router-main"])
    finally:
        conn.close()


def test_list_source_identities_keeps_unknown_bindings_unresolved(tmp_path: Path) -> None:
    from netctl.db import connect
    from netctl.source_identity import list_source_identities

    conn = connect(_db_url(tmp_path / "unknown-identities.sqlite"))
    try:
        _activate_intent_asset(
            conn,
            context_id="sosn-admin-network",
            stable_id="retired-switch",
            lifecycle="retired",
        )
        _insert_source(
            conn,
            name="unresolved-router",
            driver="mikrotik_api",
            options={
                "runtime_asset_key": "mac:FF:FF:FF:FF:FF:FF",
                "intent_context_id": "sosn-admin-network",
                "intent_stable_id": "retired-switch",
            },
        )
        conn.commit()

        (identity,) = list_source_identities(conn)

        assert identity.runtime_asset_id is None
        assert identity.runtime_asset_key == "mac:FF:FF:FF:FF:FF:FF"
        assert identity.management_macs == ()
        assert identity.intent_context_id == ""
        assert identity.intent_stable_id == ""
        assert identity.topology_role == "unknown"
        assert conn.execute("SELECT COUNT(*) FROM assets").fetchone()[0] == 0
    finally:
        conn.close()
