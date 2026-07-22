from __future__ import annotations

import sqlite3
from pathlib import Path


USER_CONTEXT_TABLES = {"users", "user_identities", "user_asset_bindings", "network_sessions"}


def _db(tmp_path: Path) -> sqlite3.Connection:
    from netctl.db import connect

    conn = connect(f"sqlite:///{(tmp_path / 'users.sqlite').as_posix()}")
    now = "2026-07-22T12:00:00Z"
    conn.execute(
        """INSERT INTO assets
           (asset_key, identity_method, identity_confidence, provisional, first_seen_at, last_seen_at, created_at, updated_at)
           VALUES ('mac:AA:BB:CC:DD:EE:FF', 'manual', 100, 0, ?, ?, ?, ?)""",
        (now, now, now, now),
    )
    conn.commit()
    return conn


def test_migration_10_creates_user_context_schema(tmp_path: Path) -> None:
    conn = _db(tmp_path)
    try:
        tables = {str(row[0]) for row in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
        versions = [int(row[0]) for row in conn.execute("SELECT version FROM schema_migrations ORDER BY version")]
        assert USER_CONTEXT_TABLES <= tables
        assert versions == list(range(1, 11))
    finally:
        conn.close()


def test_user_asset_binding_resolves_only_exclusive_current_primary_assignment(tmp_path: Path) -> None:
    from netctl.user_context import bind_user_asset, create_user, resolve_policy_asset_for_user

    conn = _db(tmp_path)
    try:
        create_user(conn, "employee:ivanov", "Иванов Иван Иванович", now="2026-07-22T12:00:00Z")
        binding = bind_user_asset(
            conn,
            "employee:ivanov",
            "mac:AA:BB:CC:DD:EE:FF",
            relation="primary_user",
            confidence=100,
            reason="approved workstation assignment",
            now="2026-07-22T12:00:00Z",
        )
        assert binding["status"] == "confirmed"
        assert resolve_policy_asset_for_user(conn, "employee:ivanov", "2026-07-22T12:01:00Z") == {
            "asset_key": "mac:AA:BB:CC:DD:EE:FF"
        }
        bind_user_asset(
            conn,
            "employee:ivanov",
            "mac:AA:BB:CC:DD:EE:FF",
            relation="shared_user",
            confidence=100,
            reason="temporary shared access",
            now="2026-07-22T12:02:00Z",
        )
        assert resolve_policy_asset_for_user(conn, "employee:ivanov", "2026-07-22T12:03:00Z") is None
    finally:
        conn.close()


def test_retired_binding_is_not_current_and_inspection_uses_safe_public_fields(tmp_path: Path) -> None:
    from netctl.user_context import bind_user_asset, create_user, inspect_user_context, retire_user_asset_binding

    conn = _db(tmp_path)
    try:
        create_user(conn, "employee:petrov", "Петров Пётр", department="IT", now="2026-07-22T12:00:00Z")
        binding = bind_user_asset(
            conn,
            "employee:petrov",
            "mac:AA:BB:CC:DD:EE:FF",
            relation="primary_user",
            confidence=100,
            reason="assigned",
            now="2026-07-22T12:00:00Z",
        )
        retired = retire_user_asset_binding(conn, int(binding["id"]), "workstation reassigned", now="2026-07-22T13:00:00Z")
        context = inspect_user_context(conn, "employee:petrov")
        assert retired["status"] == "retired"
        assert context == {
            "user": {
                "user_key": "employee:petrov",
                "display_name": "Петров Пётр",
                "status": "active",
                "department": "IT",
                "source_type": "manual",
            },
            "identities": [],
            "bindings": [
                {
                    "id": int(binding["id"]),
                    "asset_key": "mac:AA:BB:CC:DD:EE:FF",
                    "relation": "primary_user",
                    "status": "retired",
                    "binding_source": "manual",
                    "confidence": 100,
                    "valid_from": "2026-07-22T12:00:00Z",
                    "valid_until": "2026-07-22T13:00:00Z",
                }
            ],
            "sessions": [],
        }
    finally:
        conn.close()
