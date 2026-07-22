from __future__ import annotations

import json
import sqlite3
from typing import Any

from .store import transition_plan


def _steps(conn: sqlite3.Connection, plan_key: str) -> tuple[sqlite3.Row, list[sqlite3.Row]]:
    plan = conn.execute("SELECT * FROM change_plans WHERE plan_key = ?", (plan_key,)).fetchone()
    if plan is None:
        raise ValueError("change plan not found")
    rows = conn.execute("SELECT * FROM change_plan_steps WHERE change_plan_id = ? ORDER BY step_order", (plan["id"],)).fetchall()
    return plan, rows


def apply_plan(conn: sqlite3.Connection, plan_key: str, adapter: Any) -> dict[str, Any]:
    plan, steps = _steps(conn, plan_key)
    if plan["status"] == "applied":
        return {"status": "already_applied", "plan_key": plan_key}
    if plan["status"] != "approved":
        raise ValueError("only approved plans can be applied")
    transition_plan(conn, plan_key, "applying")
    applied: list[int] = []
    try:
        for step in steps:
            request = json.loads(step["request_json"])
            if step["operation"] == "ensure_address_list_entry":
                result = adapter.ensure_address_list_entry(step["target_key"], request["address"], plan_key)
            elif step["operation"] == "remove_address_list_entry":
                result = adapter.remove_address_list_entry(step["target_key"], request["address"])
            else:
                raise ValueError("unsupported plan step")
            conn.execute("UPDATE change_plan_steps SET status = 'applied', result_json = ? WHERE id = ?", (json.dumps(result, sort_keys=True), step["id"]))
            conn.commit()
            applied.append(int(step["id"]))
    except Exception:
        conn.execute("UPDATE change_plan_steps SET status = 'failed' WHERE id = ?", (step["id"],))
        conn.commit()
        transition_plan(conn, plan_key, "failed")
        return {"status": "failed", "plan_key": plan_key, "applied_step_ids": applied}
    transition_plan(conn, plan_key, "applied")
    return {"status": "applied", "plan_key": plan_key, "applied_step_ids": applied}


def verify_plan(conn: sqlite3.Connection, plan_key: str) -> dict[str, Any]:
    plan, steps = _steps(conn, plan_key)
    if plan["status"] != "applied" or any(step["status"] != "applied" for step in steps):
        raise ValueError("plan has not applied all steps")
    conn.execute("UPDATE change_plan_steps SET status = 'verified' WHERE change_plan_id = ?", (plan["id"],))
    conn.commit()
    transition_plan(conn, plan_key, "verified")
    return {"status": "verified", "plan_key": plan_key}
