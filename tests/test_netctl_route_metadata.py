from __future__ import annotations

from pathlib import Path


def test_route_metadata_survives_driver_normalization_and_sqlite_storage(tmp_path: Path) -> None:
    from netctl.db import connect
    from netctl.drivers.mikrotik_api import MikroTikApiDriver
    from netctl.store import save_collection

    conn = connect(f"sqlite:///{(tmp_path / 'routes.sqlite').as_posix()}")
    now = "2026-07-22T12:00:00Z"
    try:
        source_id = conn.execute(
            """INSERT INTO network_sources (name, driver, host, port, username, secret_ref, tls, verify_tls, enabled, created_at, updated_at)
               VALUES ('router', 'mikrotik_api', '127.0.0.1', 8729, '', 'env:TEST', 0, 0, 1, ?, ?)""",
            (now, now),
        ).lastrowid
        route = MikroTikApiDriver.normalize_route_rows([{
            "dst-address": "192.0.2.0/24", "gateway": "10.0.0.1", "distance": "1", "active": "true",
            "routing-table": "vpn", "scope": "30", "target-scope": "10", "immediate-gw": "10.0.0.1%ether1", "type": "blackhole",
        }])[0]
        assert route["routing_table"] == "vpn"
        assert route["scope"] == 30
        assert route["target_scope"] == 10
        assert route["immediate_gateway"] == "10.0.0.1%ether1"
        assert route["route_type"] == "blackhole"
        save_collection(conn, {"id": source_id, "name": "router"}, {"routes": [route]}, now)
        stored = conn.execute(
            "SELECT routing_table, scope, target_scope, immediate_gateway, route_type FROM network_routes"
        ).fetchone()
        assert tuple(stored) == ("vpn", 30, 10, "10.0.0.1%ether1", "blackhole")
    finally:
        conn.close()
