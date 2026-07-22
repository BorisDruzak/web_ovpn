from __future__ import annotations

import json
import sqlite3
from typing import Any

from .util import utc_now


_USER_STATUSES = frozenset({"active", "disabled", "retired"})
_USER_SOURCES = frozenset({"manual", "directory", "helpdesk"})
_BINDING_RELATIONS = frozenset({"primary_user", "shared_user", "temporary_user", "owner"})
_BINDING_SOURCES = frozenset({"manual", "directory", "helpdesk", "session_inference"})
_SESSION_SOURCES = frozenset({"captive_portal", "radius", "directory_agent", "manual"})


def create_user(
    conn: sqlite3.Connection,
    user_key: str,
    display_name: str,
    *,
    department: str = "",
    status: str = "active",
    source_type: str = "manual",
    external_id: str = "",
    evidence: dict[str, Any] | None = None,
    now: str | None = None,
) -> dict[str, Any]:
    if not user_key.strip() or not display_name.strip():
        raise ValueError("user key and display name are required")
    if status not in _USER_STATUSES or source_type not in _USER_SOURCES:
        raise ValueError("invalid user status or source")
    timestamp = now or utc_now()
    conn.execute(
        """INSERT INTO users
           (user_key, display_name, status, department, source_type, external_id, created_at, updated_at, evidence_json)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (user_key.strip(), display_name.strip(), status, department.strip(), source_type, external_id.strip(), timestamp, timestamp, json.dumps(evidence or {}, sort_keys=True)),
    )
    conn.commit()
    return _user_public(_user_row(conn, user_key.strip()))


def bind_user_asset(
    conn: sqlite3.Connection,
    user_key: str,
    asset_key: str,
    *,
    relation: str,
    confidence: int,
    reason: str,
    binding_source: str = "manual",
    status: str = "confirmed",
    valid_until: str | None = None,
    now: str | None = None,
) -> dict[str, Any]:
    if relation not in _BINDING_RELATIONS or binding_source not in _BINDING_SOURCES:
        raise ValueError("invalid binding relation or source")
    if status not in {"candidate", "confirmed", "rejected", "retired"} or not 0 <= confidence <= 100:
        raise ValueError("invalid binding status or confidence")
    user = _user_row(conn, user_key)
    asset = conn.execute("SELECT id, asset_key FROM assets WHERE asset_key = ?", (asset_key,)).fetchone()
    if asset is None:
        raise ValueError("asset not found")
    timestamp = now or utc_now()
    cursor = conn.execute(
        """INSERT INTO user_asset_bindings
           (user_id, asset_id, relation, status, binding_source, confidence, valid_from, valid_until, created_at, updated_at, evidence_json)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (int(user["id"]), int(asset["id"]), relation, status, binding_source, confidence, timestamp, valid_until, timestamp, timestamp, json.dumps({"reason": reason}, sort_keys=True)),
    )
    conn.commit()
    return _binding_public(_binding_row(conn, int(cursor.lastrowid)))


def retire_user_asset_binding(
    conn: sqlite3.Connection,
    binding_id: int,
    reason: str,
    *,
    now: str | None = None,
) -> dict[str, Any]:
    timestamp = now or utc_now()
    row = _binding_row(conn, binding_id)
    try:
        evidence = json.loads(str(row["evidence_json"]))
    except (TypeError, ValueError, json.JSONDecodeError):
        evidence = {}
    evidence["retired_reason"] = reason
    conn.execute(
        """UPDATE user_asset_bindings
           SET status = 'retired', valid_until = ?, updated_at = ?, evidence_json = ?
           WHERE id = ?""",
        (timestamp, timestamp, json.dumps(evidence, sort_keys=True), binding_id),
    )
    conn.commit()
    return _binding_public(_binding_row(conn, binding_id))


def ingest_network_session(
    conn: sqlite3.Connection,
    user_key: str,
    *,
    session_key: str,
    source_type: str,
    started_at: str,
    asset_key: str | None = None,
    evidence: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if source_type not in _SESSION_SOURCES or not session_key.strip() or len(session_key) > 255 or len(started_at) > 64:
        raise ValueError("invalid network session")
    user = _user_row(conn, user_key)
    asset_id: int | None = None
    if asset_key:
        asset = conn.execute("SELECT id FROM assets WHERE asset_key = ?", (asset_key,)).fetchone()
        if asset is None:
            raise ValueError("asset not found")
        asset_id = int(asset["id"])
    cursor = conn.execute(
        """INSERT INTO network_sessions
           (user_id, asset_id, source_type, session_key, started_at, evidence_json)
           VALUES (?, ?, ?, ?, ?, ?)""",
        (user["id"], asset_id, source_type, session_key.strip(), started_at, json.dumps(evidence or {}, sort_keys=True)),
    )
    conn.commit()
    return _session_public(conn.execute("SELECT sessions.*, assets.asset_key FROM network_sessions AS sessions LEFT JOIN assets ON assets.id = sessions.asset_id WHERE sessions.id = ?", (cursor.lastrowid,)).fetchone())


def close_network_session(conn: sqlite3.Connection, session_key: str, *, ended_at: str) -> dict[str, Any]:
    row = conn.execute("SELECT id FROM network_sessions WHERE session_key = ?", (session_key,)).fetchone()
    if row is None:
        raise ValueError("network session not found")
    conn.execute("UPDATE network_sessions SET ended_at = ? WHERE id = ?", (ended_at, row["id"]))
    conn.commit()
    return _session_public(conn.execute("SELECT sessions.*, assets.asset_key FROM network_sessions AS sessions LEFT JOIN assets ON assets.id = sessions.asset_id WHERE sessions.id = ?", (row["id"],)).fetchone())


def inspect_user_context(conn: sqlite3.Connection, user_key: str) -> dict[str, Any] | None:
    user = conn.execute("SELECT * FROM users WHERE user_key = ?", (user_key,)).fetchone()
    if user is None:
        return None
    user_id = int(user["id"])
    identities = [
        dict(row)
        for row in conn.execute(
            """SELECT identity_type, identity_value, source_type, first_seen_at, last_seen_at
               FROM user_identities WHERE user_id = ?
               ORDER BY identity_type, identity_value, source_type""",
            (user_id,),
        )
    ]
    bindings = [
        _binding_public(row)
        for row in conn.execute(
            """SELECT bindings.*, assets.asset_key
               FROM user_asset_bindings AS bindings
               JOIN assets ON assets.id = bindings.asset_id
               WHERE bindings.user_id = ? ORDER BY bindings.id""",
            (user_id,),
        )
    ]
    sessions = [
        dict(row)
        for row in conn.execute(
            """SELECT source_type, session_key, started_at, ended_at, accepted_policy_version
               FROM network_sessions WHERE user_id = ? ORDER BY started_at DESC, id DESC LIMIT 100""",
            (user_id,),
        )
    ]
    return {"user": _user_public(user), "identities": identities, "bindings": bindings, "sessions": sessions}


def resolve_policy_asset_for_user(
    conn: sqlite3.Connection,
    user_key: str,
    now: str | None = None,
) -> dict[str, str] | None:
    timestamp = now or utc_now()
    primary = conn.execute(
        """SELECT bindings.asset_id, assets.asset_key
           FROM user_asset_bindings AS bindings
           JOIN users ON users.id = bindings.user_id
           JOIN assets ON assets.id = bindings.asset_id
           WHERE users.user_key = ? AND users.status = 'active'
             AND bindings.relation = 'primary_user' AND bindings.status = 'confirmed'
             AND bindings.confidence = 100 AND bindings.valid_from <= ?
             AND (bindings.valid_until IS NULL OR bindings.valid_until > ?)
           ORDER BY bindings.id""",
        (user_key, timestamp, timestamp),
    ).fetchall()
    if len(primary) != 1:
        return None
    asset_id = int(primary[0]["asset_id"])
    shared = conn.execute(
        """SELECT 1 FROM user_asset_bindings
           WHERE asset_id = ? AND relation = 'shared_user' AND status = 'confirmed'
             AND valid_from <= ? AND (valid_until IS NULL OR valid_until > ?)
           LIMIT 1""",
        (asset_id, timestamp, timestamp),
    ).fetchone()
    return None if shared is not None else {"asset_key": str(primary[0]["asset_key"])}


def _user_row(conn: sqlite3.Connection, user_key: str) -> sqlite3.Row:
    row = conn.execute("SELECT * FROM users WHERE user_key = ?", (user_key,)).fetchone()
    if row is None:
        raise ValueError("user not found")
    return row


def _binding_row(conn: sqlite3.Connection, binding_id: int) -> sqlite3.Row:
    row = conn.execute(
        """SELECT bindings.*, assets.asset_key
           FROM user_asset_bindings AS bindings
           JOIN assets ON assets.id = bindings.asset_id
           WHERE bindings.id = ?""",
        (binding_id,),
    ).fetchone()
    if row is None:
        raise ValueError("binding not found")
    return row


def _user_public(row: sqlite3.Row) -> dict[str, Any]:
    return {key: row[key] for key in ("user_key", "display_name", "status", "department", "source_type")}


def _binding_public(row: sqlite3.Row) -> dict[str, Any]:
    return {
        key: row[key]
        for key in ("id", "asset_key", "relation", "status", "binding_source", "confidence", "valid_from", "valid_until")
    }


def _session_public(row: sqlite3.Row) -> dict[str, Any]:
    return {key: row[key] for key in ("session_key", "source_type", "asset_key", "started_at", "ended_at", "accepted_policy_version")}
