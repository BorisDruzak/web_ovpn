from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from netctl.db import connect_read_only

from .migrations import apply_migrations
from .models import PLAN_TRANSITIONS


def _utc_now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _db_path(db_url: str) -> Path:
    if not db_url.startswith("sqlite:///"):
        raise ValueError("only sqlite:/// DB URLs are supported")
    return Path(db_url.removeprefix("sqlite:///"))


def connect(db_url: str) -> sqlite3.Connection:
    path = _db_path(db_url)
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    apply_migrations(conn)
    return conn


def open_netctl_context_read_only(db_url: str) -> sqlite3.Connection:
    """The control plane may inspect context but must never open it for writes."""
    return connect_read_only(db_url)


def _plan(conn: sqlite3.Connection, plan_key: str) -> sqlite3.Row:
    row = conn.execute("SELECT * FROM change_plans WHERE plan_key = ?", (plan_key,)).fetchone()
    if row is None:
        raise ValueError("change plan not found")
    return row


def _public_plan(row: sqlite3.Row) -> dict[str, Any]:
    value = dict(row)
    for key in ("desired_state_json", "resolved_targets_json", "precheck_json", "rollback_json"):
        value[key.removesuffix("_json")] = json.loads(value.pop(key))
    return value


def create_change_plan(
    conn: sqlite3.Connection,
    *,
    plan_key: str,
    actor: str,
    reason: str,
    subject_type: str,
    subject_key: str,
    operation_type: str,
    desired_state: dict[str, Any],
    resolved_targets: list[dict[str, Any]],
    context_evidence_hash: str,
    precheck: dict[str, Any],
    rollback: dict[str, Any],
) -> dict[str, Any]:
    if subject_type not in {"asset", "user", "infrastructure"} or operation_type not in {"internet_access_set", "internet_policy_bootstrap"}:
        raise ValueError("unsupported change-plan subject or operation")
    if not plan_key or not actor or not reason or not subject_key or len(context_evidence_hash) != 64:
        raise ValueError("invalid change plan identity or evidence hash")
    now = _utc_now()
    cursor = conn.execute(
        """INSERT INTO change_plans
           (plan_key, actor, reason, subject_type, subject_key, operation_type, desired_state_json,
            resolved_targets_json, context_evidence_hash, precheck_json, rollback_json, status, created_at, updated_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'draft', ?, ?)""",
        (plan_key, actor, reason, subject_type, subject_key, operation_type, _json(desired_state), _json(resolved_targets),
         context_evidence_hash, _json(precheck), _json(rollback), now, now),
    )
    conn.commit()
    return _public_plan(conn.execute("SELECT * FROM change_plans WHERE id = ?", (cursor.lastrowid,)).fetchone())


def update_draft_plan(conn: sqlite3.Connection, plan_key: str, *, reason: str) -> dict[str, Any]:
    row = _plan(conn, plan_key)
    if str(row["status"]) not in {"draft", "validated"}:
        raise ValueError("approved change plan is immutable")
    if not reason:
        raise ValueError("reason is required")
    conn.execute("UPDATE change_plans SET reason = ?, updated_at = ? WHERE id = ?", (reason, _utc_now(), row["id"]))
    conn.commit()
    return _public_plan(_plan(conn, plan_key))


def add_plan_step(conn: sqlite3.Connection, plan_key: str, *, adapter: str, operation: str, target_key: str, request: dict[str, Any]) -> dict[str, Any]:
    row = _plan(conn, plan_key)
    if str(row["status"]) not in {"draft", "validated"}:
        raise ValueError("approved change plan is immutable")
    step_order = int(conn.execute("SELECT COALESCE(MAX(step_order), -1) + 1 FROM change_plan_steps WHERE change_plan_id = ?", (row["id"],)).fetchone()[0])
    cursor = conn.execute(
        """INSERT INTO change_plan_steps (change_plan_id, step_order, adapter, operation, target_key, request_json, status)
           VALUES (?, ?, ?, ?, ?, ?, 'pending')""",
        (row["id"], step_order, adapter, operation, target_key, _json(request)),
    )
    conn.commit()
    return dict(conn.execute("SELECT * FROM change_plan_steps WHERE id = ?", (cursor.lastrowid,)).fetchone())


def transition_plan(conn: sqlite3.Connection, plan_key: str, target_status: str) -> dict[str, Any]:
    row = _plan(conn, plan_key)
    current = str(row["status"])
    if target_status not in PLAN_TRANSITIONS.get(current, frozenset()):
        raise ValueError(f"invalid status transition: {current} -> {target_status}")
    now = _utc_now()
    timestamps: dict[str, str | None] = {"approved_at": None, "applied_at": None, "verified_at": None}
    if target_status == "approved":
        timestamps["approved_at"] = now
    elif target_status == "applied":
        timestamps["applied_at"] = now
    elif target_status == "verified":
        timestamps["verified_at"] = now
    assignments = ["status = ?", "updated_at = ?"]
    params: list[object] = [target_status, now]
    for key, value in timestamps.items():
        if value is not None:
            assignments.append(f"{key} = ?")
            params.append(value)
    params.append(row["id"])
    conn.execute(f"UPDATE change_plans SET {', '.join(assignments)} WHERE id = ?", params)
    conn.commit()
    return _public_plan(_plan(conn, plan_key))


def upsert_desired_policy(
    conn: sqlite3.Connection,
    plan_key: str,
    *,
    subject_type: str,
    subject_key: str,
    desired_state: str,
    reason: str,
    enforcement_scope: str,
) -> dict[str, Any]:
    plan = _plan(conn, plan_key)
    if str(plan["status"]) != "verified":
        raise ValueError("desired policy requires a verified change plan")
    if subject_type not in {"asset", "user"} or desired_state not in {"allow", "deny"}:
        raise ValueError("invalid desired policy")
    now = _utc_now()
    conn.execute(
        """INSERT INTO desired_network_policies
           (subject_type, subject_key, policy_type, desired_state, enforcement_scope, reason, valid_from, source_plan_id, status, updated_at)
           VALUES (?, ?, 'internet_access', ?, ?, ?, ?, ?, 'active', ?)
           ON CONFLICT(subject_type, subject_key, policy_type, enforcement_scope)
           DO UPDATE SET desired_state = excluded.desired_state, reason = excluded.reason,
                         valid_from = excluded.valid_from, source_plan_id = excluded.source_plan_id,
                         status = 'active', updated_at = excluded.updated_at""",
        (subject_type, subject_key, desired_state, enforcement_scope, reason, now, plan["id"], now),
    )
    conn.commit()
    row = conn.execute(
        """SELECT policies.*, plans.plan_key AS source_plan_key FROM desired_network_policies AS policies
           JOIN change_plans AS plans ON plans.id = policies.source_plan_id
           WHERE policies.subject_type = ? AND policies.subject_key = ?
             AND policies.policy_type = 'internet_access' AND policies.enforcement_scope = ?""",
        (subject_type, subject_key, enforcement_scope),
    ).fetchone()
    return dict(row)
