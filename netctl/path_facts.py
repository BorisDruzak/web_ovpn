from __future__ import annotations

import json
import sqlite3
from typing import Any


_FAMILIES = {
    "firewall_filter_rules": "router_filter_rules",
    "firewall_nat_rules": "router_nat_rules",
    "firewall_mangle_rules": "router_mangle_rules",
}


def save_path_facts(
    conn: sqlite3.Connection,
    source_id: int,
    snapshot: dict[str, Any],
    outcomes: dict[str, str],
    observed_at: str,
    *,
    commit: bool = True,
) -> dict[str, Any]:
    statuses = set(outcomes.values())
    status = "success" if statuses == {"success"} else ("failed" if "success" not in statuses else "partial")
    cursor = conn.execute(
        """INSERT INTO router_path_fact_runs (source_id, started_at, finished_at, status, capabilities_json)
           VALUES (?, ?, ?, ?, ?)""",
        (source_id, observed_at, observed_at, status, json.dumps(outcomes, sort_keys=True)),
    )
    run_id = int(cursor.lastrowid)
    for family, table in _FAMILIES.items():
        if outcomes.get(family) != "success":
            continue
        conn.execute(f"DELETE FROM {table} WHERE source_id = ?", (source_id,))
        for position, row in enumerate(snapshot.get(family, [])):
            conn.execute(
                f"""INSERT INTO {table}
                   (source_id, rule_key, chain, position, disabled, action, src_cidr, dst_cidr,
                    protocol, dst_port, in_interface, out_interface, src_address_list,
                    dst_address_list, routing_mark, connection_state, comment, observed_at,
                    collector_run_id, unsupported_matchers_json)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    source_id, str(row.get("id") or position), str(row.get("chain") or ""), position,
                    int(bool(row.get("disabled"))), str(row.get("action") or ""),
                    str(row.get("src_address") or ""), str(row.get("dst_address") or ""),
                    str(row.get("protocol") or ""), str(row.get("dst_port") or ""),
                    str(row.get("in_interface") or ""), str(row.get("out_interface") or ""),
                    str(row.get("src_address_list") or ""), str(row.get("dst_address_list") or ""),
                    str(row.get("routing_mark") or ""), str(row.get("connection_state") or ""),
                    str(row.get("comment") or ""), observed_at, run_id,
                    json.dumps(sorted(str(item) for item in row.get("unsupported_matchers", []))),
                ),
            )
    if outcomes.get("router_routing_rules") == "success":
        conn.execute("DELETE FROM router_routing_rules WHERE source_id = ?", (source_id,))
        for position, row in enumerate(snapshot.get("router_routing_rules", [])):
            conn.execute(
                """INSERT INTO router_routing_rules
                   (source_id, rule_key, position, disabled, action, src_cidr, dst_cidr, routing_mark,
                    table_name, comment, observed_at, collector_run_id, unsupported_matchers_json)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (source_id, str(row.get("id") or position), position, int(bool(row.get("disabled"))),
                 str(row.get("action") or ""), str(row.get("src_address") or ""), str(row.get("dst_address") or ""),
                 str(row.get("routing_mark") or ""), str(row.get("table_name") or ""), str(row.get("comment") or ""),
                 observed_at, run_id, json.dumps(sorted(str(item) for item in row.get("unsupported_matchers", [])))),
            )
    if outcomes.get("firewall_address_lists") == "success":
        conn.execute("DELETE FROM router_address_list_entries WHERE source_id = ?", (source_id,))
        for position, row in enumerate(snapshot.get("firewall_address_lists", [])):
            conn.execute(
                """INSERT INTO router_address_list_entries
                   (source_id, rule_key, list_name, address, disabled, comment, observed_at, collector_run_id, unsupported_matchers_json)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (source_id, str(row.get("id") or position), str(row.get("list") or ""), str(row.get("address") or ""),
                 int(bool(row.get("disabled"))), str(row.get("comment") or ""), observed_at, run_id,
                 json.dumps(sorted(str(item) for item in row.get("unsupported_matchers", [])))),
            )
    if outcomes.get("ipsec_policies") == "success":
        conn.execute("DELETE FROM router_ipsec_policies WHERE source_id = ?", (source_id,))
        for position, row in enumerate(snapshot.get("ipsec_policies", [])):
            conn.execute(
                """INSERT INTO router_ipsec_policies
                   (source_id, rule_key, position, disabled, action, src_cidr, dst_cidr, protocol,
                    comment, observed_at, collector_run_id, unsupported_matchers_json)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (source_id, str(row.get("id") or position), position, int(bool(row.get("disabled"))),
                 str(row.get("action") or ""), str(row.get("src_address") or ""), str(row.get("dst_address") or ""),
                 str(row.get("protocol") or ""), str(row.get("comment") or ""), observed_at, run_id,
                 json.dumps(sorted(str(item) for item in row.get("unsupported_matchers", [])))),
            )
    if commit:
        conn.commit()
    return {"run_id": run_id, "status": status, "outcomes": dict(outcomes)}
