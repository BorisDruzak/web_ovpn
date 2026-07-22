from __future__ import annotations

import json
import os
import sqlite3
import uuid
from collections.abc import Callable
from typing import Any

from .store import transition_plan


def _steps(conn: sqlite3.Connection, plan_key: str) -> tuple[sqlite3.Row, list[sqlite3.Row]]:
    plan = conn.execute("SELECT * FROM change_plans WHERE plan_key = ?", (plan_key,)).fetchone()
    if plan is None:
        raise ValueError("change plan not found")
    rows = conn.execute("SELECT * FROM change_plan_steps WHERE change_plan_id = ? ORDER BY step_order", (plan["id"],)).fetchall()
    return plan, rows


def _device_lock_for_target(conn: sqlite3.Connection, device_key: str) -> tuple[str, str]:
    holder = str(uuid.uuid4())
    try:
        conn.execute(
            "INSERT INTO device_operation_locks (device_key, holder, acquired_at, owner_pid) VALUES (?, ?, datetime('now'), ?)",
            (device_key, holder, os.getpid()),
        )
        conn.commit()
    except sqlite3.IntegrityError as exc:
        conn.rollback()
        existing = conn.execute(
            "SELECT holder, owner_pid FROM device_operation_locks WHERE device_key = ?", (device_key,)
        ).fetchone()
        owner_pid = int(existing["owner_pid"]) if existing is not None else 0
        if existing is None or owner_pid <= 0 or _process_is_alive(owner_pid):
            raise ValueError("device operation is already in progress") from exc
        try:
            conn.execute("BEGIN IMMEDIATE")
            deleted = conn.execute(
                "DELETE FROM device_operation_locks WHERE device_key = ? AND holder = ? AND owner_pid = ?",
                (device_key, str(existing["holder"]), owner_pid),
            )
            if deleted.rowcount != 1:
                raise ValueError("device operation is already in progress")
            conn.execute(
                "INSERT INTO device_operation_locks (device_key, holder, acquired_at, owner_pid) VALUES (?, ?, datetime('now'), ?)",
                (device_key, holder, os.getpid()),
            )
            conn.commit()
        except Exception:
            conn.rollback()
            raise
    return device_key, holder


def _process_is_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except PermissionError:
        return True
    except OSError:
        return False
    return True


def _device_lock(conn: sqlite3.Connection, steps: list[sqlite3.Row]) -> tuple[str, str]:
    targets = {str(step["target_key"]) for step in steps}
    if len(targets) != 1:
        raise ValueError("plan must target exactly one enforcement device")
    return _device_lock_for_target(conn, targets.pop())


def _release_device_lock(conn: sqlite3.Connection, lock: tuple[str, str]) -> None:
    conn.execute("DELETE FROM device_operation_locks WHERE device_key = ? AND holder = ?", lock)
    conn.commit()


def apply_plan(
    conn: sqlite3.Connection,
    plan_key: str,
    adapter: Any,
    *,
    preflight: Callable[[sqlite3.Row], list[str]] | None = None,
) -> dict[str, Any]:
    plan, steps = _steps(conn, plan_key)
    if plan["status"] == "applied":
        return {"status": "already_applied", "plan_key": plan_key}
    if plan["status"] != "approved":
        raise ValueError("only approved plans can be applied")
    lock = _device_lock(conn, steps)
    try:
        changed_preconditions = preflight(plan) if preflight is not None else []
        if changed_preconditions:
            transition_plan(conn, plan_key, "failed")
            return {
                "status": "stale_precondition", "plan_key": plan_key,
                "replan_required": True, "changed_preconditions": sorted(set(changed_preconditions)),
            }
        transition_plan(conn, plan_key, "applying")
        applied: list[int] = []
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
    finally:
        _release_device_lock(conn, lock)
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
        present = any(
            str(entry.get("address") or "") == expected["address"]
            and str(entry.get("comment") or "") == expected["comment"]
            for entry in entries
        )
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
    plan, plan_steps = _steps(conn, plan_key)
    if plan["status"] == "rolled_back":
        return {"status": "already_rolled_back", "plan_key": plan_key}
    if plan["status"] not in {"applied", "verified", "failed"}:
        raise ValueError("only applied, verified, or failed plans can be rolled back")
    rollback = json.loads(plan["rollback_json"])
    steps = rollback.get("steps")
    if not isinstance(steps, list):
        raise ValueError("invalid rollback payload")
    lock = _device_lock(conn, plan_steps)
    try:
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
    finally:
        _release_device_lock(conn, lock)


def _record_policy_stale_identity(conn: sqlite3.Connection, policy_id: int, reason: str) -> None:
    conn.execute(
        """INSERT INTO network_policy_findings
           (desired_policy_id, finding_type, status, first_seen_at, last_seen_at, details_json)
           VALUES (?, 'policy_stale_identity', 'open', datetime('now'), datetime('now'), ?)
           ON CONFLICT(desired_policy_id, finding_type) DO UPDATE SET
             status = 'open', last_seen_at = excluded.last_seen_at, details_json = excluded.details_json""",
        (policy_id, json.dumps({"reason": reason}, sort_keys=True)),
    )
    conn.commit()


def _resolve_reconcile_asset(context: sqlite3.Connection, policy: sqlite3.Row) -> str:
    if str(policy["subject_type"]) == "asset":
        return str(policy["subject_key"])
    if str(policy["subject_type"]) == "user":
        from netctl.user_context import resolve_policy_asset_for_user

        resolved = resolve_policy_asset_for_user(context, str(policy["subject_key"]))
        if resolved is None:
            raise ValueError("user policy no longer has an eligible confirmed primary asset")
        return str(resolved["asset_key"])
    raise ValueError("unsupported desired policy subject")


def reconcile_desired_policies(
    conn: sqlite3.Connection,
    netctl_db_url: str,
    adapter: Any,
    *,
    enforcement_sources_by_site: dict[str, str],
    source_sla_seconds: int,
    anchor_check: Callable[[str], bool],
    limit: int = 64,
) -> dict[str, int]:
    """Reconcile only existing deny intent; identity failures retain the old deny entries."""
    if not 1 <= limit <= 256:
        raise ValueError("invalid reconcile limit")
    from .policy_resolver import _open_context_immutable, resolve_asset_targets

    policies = conn.execute(
        """SELECT policies.*, plans.plan_key AS source_plan_key
           FROM desired_network_policies AS policies
           JOIN change_plans AS plans ON plans.id = policies.source_plan_id
           WHERE policies.status = 'active' AND policies.policy_type = 'internet_access'
           ORDER BY policies.id LIMIT ?""",
        (limit,),
    ).fetchall()
    reconciled = stale = skipped = 0
    for policy in policies:
        if str(policy["desired_state"]) != "deny":
            skipped += 1
            continue
        context = _open_context_immutable(netctl_db_url)
        try:
            asset_key = _resolve_reconcile_asset(context, policy)
            targets = resolve_asset_targets(
                context, asset_key, enforcement_sources_by_site=enforcement_sources_by_site,
                source_sla_seconds=source_sla_seconds, anchor_check=anchor_check,
            )
        except ValueError as exc:
            _record_policy_stale_identity(conn, int(policy["id"]), str(exc))
            stale += 1
            continue
        finally:
            context.close()
        devices = {str(target["source"]) for target in targets}
        if len(devices) != 1:
            _record_policy_stale_identity(conn, int(policy["id"]), "policy spans multiple enforcement devices")
            stale += 1
            continue
        device_key = devices.pop()
        plan_key = str(policy["source_plan_key"])
        expected_addresses = {str(target["address"]) for target in targets}
        lock = _device_lock_for_target(conn, device_key)
        try:
            comment = str(adapter.ownership_comment(plan_key, asset_key))
            existing = {
                str(entry.get("address") or "")
                for entry in adapter.list_managed_address_list_entries(device_key)
                if str(entry.get("comment") or "") == comment
            }
            for address in sorted(expected_addresses - existing):
                adapter.ensure_address_list_entry(device_key, address, plan_key, asset_key)
            verified = {
                str(entry.get("address") or "")
                for entry in adapter.list_managed_address_list_entries(device_key)
                if str(entry.get("comment") or "") == comment
            }
            if not expected_addresses <= verified:
                raise ValueError("new deny entry did not verify")
            for address in sorted(existing - expected_addresses):
                adapter.remove_address_list_entry(device_key, address, plan_key, asset_key)
            conn.execute(
                """INSERT INTO change_executions
                   (change_plan_id, execution_type, started_at, finished_at, status, sanitized_result_json)
                   VALUES (?, 'reconcile', datetime('now'), datetime('now'), 'success', ?)""",
                (policy["source_plan_id"], json.dumps({"addresses": sorted(expected_addresses)}, sort_keys=True)),
            )
            conn.execute(
                "UPDATE network_policy_findings SET status = 'resolved', last_seen_at = datetime('now') WHERE desired_policy_id = ? AND finding_type = 'policy_stale_identity'",
                (policy["id"],),
            )
            conn.commit()
            reconciled += 1
        except Exception as exc:
            _record_policy_stale_identity(conn, int(policy["id"]), str(exc))
            stale += 1
        finally:
            _release_device_lock(conn, lock)
    return {"reconciled": reconciled, "stale_identity": stale, "skipped": skipped}
