from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest


CORRELATION_TABLES = {
    "network_correlation_runs",
    "current_switch_links",
    "switch_link_events",
    "asset_attachment_resolutions",
    "asset_attachment_candidates",
    "asset_attachment_events",
    "topology_findings",
}


def _db_url(path: Path) -> str:
    return f"sqlite:///{path.as_posix()}"


def _table_names(conn: sqlite3.Connection) -> set[str]:
    return {
        str(row[0])
        for row in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
    }


def _database_at_migration_8(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> sqlite3.Connection:
    from netctl import migrations
    from netctl.db import connect

    migration_8_and_before = tuple(
        entry for entry in migrations.MIGRATIONS if entry[0] <= 8
    )
    with monkeypatch.context() as migration_patch:
        migration_patch.setattr(migrations, "MIGRATIONS", migration_8_and_before)
        return connect(_db_url(tmp_path / "netctl.sqlite"))


def _migration_versions(conn: sqlite3.Connection) -> list[int]:
    return [
        int(row[0])
        for row in conn.execute("SELECT version FROM schema_migrations ORDER BY version")
    ]


def test_migration_9_creates_correlation_schema(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from netctl import migrations

    conn = _database_at_migration_8(tmp_path, monkeypatch)
    try:
        migrations.apply_migrations(conn)

        assert _migration_versions(conn) == list(range(1, 10))
        assert CORRELATION_TABLES <= _table_names(conn)
        assert {
            row[1]
            for row in conn.execute("PRAGMA index_list(asset_interfaces)")
        } >= {"asset_interfaces_id_asset_idx"}
    finally:
        conn.close()


def test_migration_9_failure_rolls_back_schema_and_ledger(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from netctl import migrations

    assert hasattr(migrations, "_migration_9")
    original_migration_9 = migrations._migration_9
    conn = _database_at_migration_8(tmp_path, monkeypatch)

    def fail_after_migration_9(connection: sqlite3.Connection) -> None:
        original_migration_9(connection)
        raise RuntimeError("injected migration 9 failure")

    migration_8_and_before = tuple(
        entry for entry in migrations.MIGRATIONS if entry[0] <= 8
    )
    monkeypatch.setattr(
        migrations,
        "MIGRATIONS",
        (*migration_8_and_before, (9, fail_after_migration_9)),
    )
    try:
        with pytest.raises(RuntimeError, match="injected migration 9 failure"):
            migrations.apply_migrations(conn)

        assert CORRELATION_TABLES.isdisjoint(_table_names(conn))
        assert _migration_versions(conn) == list(range(1, 9))
        assert {
            row[1]
            for row in conn.execute("PRAGMA index_list(asset_interfaces)")
        }.isdisjoint({"asset_interfaces_id_asset_idx"})
    finally:
        conn.close()
