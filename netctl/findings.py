from __future__ import annotations

import json
import sqlite3
from typing import Any


def findings_for_asset(conn: sqlite3.Connection, asset_id: int, limit: int = 100) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for table, source in (("runtime_identity_findings", "runtime_identity"), ("topology_findings", "topology")):
        for row in conn.execute(
            f"SELECT finding_key, finding_type, severity, status, first_seen_at, last_seen_at, details_json FROM {table} WHERE asset_id = ? ORDER BY last_seen_at DESC, finding_key LIMIT ?",
            (asset_id, limit),
        ):
            item = dict(row)
            try:
                item["details"] = json.loads(item.pop("details_json"))
            except (TypeError, ValueError, json.JSONDecodeError):
                item["details"] = {}
            item["source"] = source
            rows.append(item)
    return sorted(rows, key=lambda item: (str(item["last_seen_at"]), str(item["finding_key"])), reverse=True)[:limit]
