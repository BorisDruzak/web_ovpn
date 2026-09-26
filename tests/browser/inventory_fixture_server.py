r"""Isolated local browser fixture. Never opens the configured deployment DB.

Run: python -m tests.browser.inventory_fixture_server --output C:\Temp\inventory-browser
Only synthetic data and credentials, bound to loopback. Stop with Ctrl+C.
"""
import argparse
import json
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--port", type=int, default=8874)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    database = args.output.resolve() / "synthetic.sqlite"
    os.environ.update(DATABASE_URL=f"sqlite:///{database.as_posix()}",
        APP_SECRET_KEY="synthetic-browser-only", ADMIN_USERNAME="synthetic",
        ADMIN_PASSWORD="synthetic-browser-only", ENDPOINT_PLATFORM_ENABLED="false")
    from app.db import init_db, get_sessionmaker, reset_engine_cache
    reset_engine_cache()
    init_db()
    from tests.test_inventory_endpoint_api import seed
    from app.inventory.models import InventoryAsset, InventoryEndpointState
    asset_id, binding_id = seed()
    with get_sessionmaker()() as db:
        asset = db.get(InventoryAsset, asset_id)
        asset.custom_name = "Synthetic browser PC"
        state = db.get(InventoryEndpointState, binding_id)
        state.safe_context_json = {"ip": "192.0.2.24", "mac": "02:00:00:00:00:24",
            "hostname": "synthetic-pc", "ram_gb": 0, "os_name": "Unsupported OS",
            "manufacturer": "Synthetic maker", "cpu_model": "AMD"}
        db.commit()
    (args.output / "fixture.json").write_text(json.dumps({"asset_id": asset_id}), encoding="utf-8")
    from netctl.db import connect
    from netctl.host_snapshot import list_host_snapshot, refresh_host_snapshot, snapshot_status
    network_database = args.output.resolve() / "synthetic-network.sqlite"
    now = datetime.now(timezone.utc).isoformat()
    network = connect(f"sqlite:///{network_database.as_posix()}")
    for number in range(1, 231):
        network.execute("INSERT OR REPLACE INTO network_hosts (ip,hostname,category,status,last_seen_at,tags_json) VALUES (?,?,'unknown','seen',?,'{}')",
            (f"192.0.2.{number}", f"synthetic-{number}", now))
    network.commit()
    refresh_host_snapshot(network, now=now)
    network.close()
    import app.main
    def forbidden(*args, **kwargs):
        raise RuntimeError("External CLI is forbidden in browser fixture")
    app.main.run_vpnctl = forbidden
    app.main.run_netctl = forbidden
    import app.inventory.web
    app.inventory.web.run_netctl = forbidden
    def saved_network(args, **kwargs):
        if args[:2] not in (["hosts", "list"], ["hosts", "snapshot-status"]):
            return forbidden()
        connection = sqlite3.connect(network_database)
        connection.row_factory = sqlite3.Row
        try:
            if args[1] == "snapshot-status":
                from dataclasses import asdict
                return {"snapshot": asdict(snapshot_status(connection))}
            filters = {}
            page, limit = 1, 100
            for index, value in enumerate(args[2:], 2):
                if value == "--page": page = int(args[index + 1])
                elif value == "--limit": limit = int(args[index + 1])
                elif value.startswith("--") and "=" in value:
                    key, item = value[2:].split("=", 1)
                    filters[key.replace("-", "_")] = item
            data = list_host_snapshot(connection, filters, page, limit)
            data["pagination"] = {key: data[key] for key in ("page", "limit", "total", "pages")}
            return data
        finally:
            connection.close()
    app.main.run_netctl = saved_network
    import app.api
    app.api.run_netctl = saved_network
    import uvicorn
    uvicorn.run(app.main.app, host="127.0.0.1", port=args.port)


if __name__ == "__main__":
    main()
