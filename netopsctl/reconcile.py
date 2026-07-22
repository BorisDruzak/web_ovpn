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
                result = adapter.ensure_address_list_entry(step["target_key"], request["address"], plan_key, request["asset_key"])
            elif step["operation"] == "remove_address_list_entry":
                result = adapter.remove_address_list_entry(step["target_key"], request["address"], plan_key, request["asset_key"])
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


def _expected_entry(adapter: Any, plan_key: str, request: dict[str, Any]) -> dict[str, str]:
    return {
        "address": str(request["address"]),
        "comment": str(adapter.ownership_comment(plan_key, str(request["asset_key"]))),
    }


def verify_plan(conn: sqlite3.Connection, plan_key: str, adapter: Any) -> dict[str, Any]:
    plan, steps = _steps(conn, plan_key)
    if plan["status"] != "applied" or any(step["status"] != "applied" for step in steps):
        raise ValueError("plan has not applied all steps")
    for step in steps:
        request = json.loads(step["request_json"])
        expected = _expected_entry(adapter, plan_key, request)
        entries = adapter.list_managed_address_list_entries(step["target_key"])
        present = expected in entries
        should_be_present = step["operation"] == "ensure_address_list_entry"
        if present != should_be_present:
            conn.execute("UPDATE change_plan_steps SET status = 'failed' WHERE id = ?", (step["id"],))
            conn.commit()
            transition_plan(conn, plan_key, "failed")
            return {"status": "failed", "plan_key": plan_key, "reason": "device verification mismatch"}
    conn.execute("UPDATE change_plan_steps SET status = 'verified' WHERE change_plan_id = ?", (plan["id"],))
    conn.commit()
    transition_plan(conn, plan_key, "verified")
    return {"status": "verified", "plan_key": plan_key}


def rollback_plan(conn: sqlite3.Connection, plan_key: str, adapter: Any) -> dict[str, Any]:
    plan, _ = _steps(conn, plan_key)
    if plan["status"] == "rolled_back":
        return {"status": "already_rolled_back", "plan_key": plan_key}
    if plan["status"] not in {"applied", "verified", "failed"}:
        raise ValueError("only applied, verified, or failed plans can be rolled back")
    rollback = json.loads(plan["rollback_json"])
    steps = rollback.get("steps")
    if not isinstance(steps, list):
        raise ValueError("invalid rollback payload")
    transition_plan(conn, plan_key, "rolling_back")
    completed: list[int] = []
    try:
        for index, step in enumerate(steps):
            if not isinstance(step, dict) or step.get("adapter") not in {None, "mikrotik"}:
                raise ValueError("unsupported rollback adapter")
            request = step.get("request")
            target_key = step.get("target_key")
            if not isinstance(request, dict) or not isinstance(target_key, str):
                raise ValueError("invalid rollback step")
            if step.get("operation") == "remove_address_list_entry":
                result = adapter.remove_address_list_entry(target_key, request["address"], plan_key, request["asset_key"])
            elif step.get("operation") == "ensure_address_list_entry":
                result = adapter.ensure_address_list_entry(target_key, request["address"], plan_key, request["asset_key"])
            else:
                raise ValueError("unsupported rollback operation")
            completed.append(index)
            conn.execute(
                "INSERT INTO change_executions (change_plan_id, execution_type, started_at, finished_at, status, sanitized_result_json) VALUES (?, 'rollback', datetime('now'), datetime('now'), 'success', ?)",
                (plan["id"], json.dumps(result, sort_keys=True)),
            )
            conn.commit()
    except Exception:
        conn.execute(
            "INSERT INTO change_executions (change_plan_id, execution_type, started_at, finished_at, status, sanitized_result_json) VALUES (?, 'rollback', datetime('now'), datetime('now'), 'failed', ?)",
            (plan["id"], json.dumps({"completed_steps": completed}, sort_keys=True)),
        )
        conn.commit()
        transition_plan(conn, plan_key, "failed")
        return {"status": "failed", "plan_key": plan_key, "completed_rollback_steps": completed}
    conn.execute("UPDATE change_plan_steps SET status = 'rolled_back' WHERE change_plan_id = ?", (plan["id"],))
    conn.commit()
    transition_plan(conn, plan_key, "rolled_back")
    return {"status": "rolled_back", "plan_key": plan_key, "completed_rollback_steps": completed}
