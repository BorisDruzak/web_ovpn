from __future__ import annotations

import json
from pathlib import Path


def test_path_explain_reads_asset_context_and_current_router_facts(tmp_path: Path, capsys) -> None:
    from netctl.cli import main
    from netctl.db import connect
    from netctl.path_facts import save_path_facts
    from netctl.util import utc_now

    db_url = f"sqlite:///{(tmp_path / 'netctl.sqlite').as_posix()}"
    now = utc_now()
    conn = connect(db_url)
    try:
        source_id = conn.execute(
            """INSERT INTO network_sources (name, driver, host, port, username, secret_ref, tls, verify_tls, enabled, created_at, updated_at)
               VALUES ('router', 'mikrotik_api', '127.0.0.1', 8729, '', 'env:TEST', 0, 0, 1, ?, ?)""",
            (now, now),
        ).lastrowid
        asset_id = conn.execute(
            """INSERT INTO assets
               (asset_key, identity_method, identity_confidence, provisional, first_seen_at, last_seen_at, created_at, updated_at)
               VALUES ('mac:AA:BB:CC:DD:EE:FF', 'manual', 100, 0, ?, ?, ?, ?)""",
            (now, now, now, now),
        ).lastrowid
        conn.execute(
            """INSERT INTO ip_observations
               (asset_id, source_id, source_key, ip, first_seen_at, last_seen_at, is_current, observation_source)
               VALUES (?, ?, 'router', '192.0.2.10', ?, ?, 1, 'manual')""",
            (asset_id, source_id, now, now),
        )
        conn.execute(
            """INSERT INTO network_routes
               (source_id, dst_address, gateway, distance, active, disabled, dynamic, comment, routing_table, immediate_gateway, route_type, last_seen_at)
               VALUES (?, '0.0.0.0/0', '192.0.2.1', '1', 1, 0, 0, '', 'main', '', 'unicast', ?)""",
            (source_id, now),
        )
        save_path_facts(conn, source_id, {"firewall_filter_rules": []}, {"firewall_filter_rules": "success"}, now)
        conn.commit()
    finally:
        conn.close()

    assert main([
        "--json", "--db", db_url, "path", "explain", "--asset-key", "mac:AA:BB:CC:DD:EE:FF",
        "--destination", "198.51.100.25", "--protocol", "tcp", "--port", "443",
    ]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["explanation"]["verdict"] == "allowed"
    assert payload["explanation"]["source_asset_key"] == "mac:AA:BB:CC:DD:EE:FF"
