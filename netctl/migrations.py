from __future__ import annotations

import sqlite3
from collections.abc import Callable

from .util import utc_now


def _migration_1(conn: sqlite3.Connection) -> None:
    for statement in """
        CREATE TABLE context_import_runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            context_id TEXT NOT NULL DEFAULT '',
            context_revision_id INTEGER REFERENCES context_revisions(id) ON DELETE RESTRICT,
            base_context_revision_id INTEGER REFERENCES context_revisions(id) ON DELETE RESTRICT,
            input_sha256 TEXT NOT NULL DEFAULT '',
            git_sha TEXT NOT NULL,
            source_path TEXT NOT NULL,
            started_at TEXT NOT NULL,
            finished_at TEXT,
            status TEXT NOT NULL CHECK (status IN (
                'running',
                'success_imported',
                'success_noop_same_content',
                'success_activated_existing_content',
                'validation_error',
                'db_error'
            )),
            errors_json TEXT NOT NULL DEFAULT '[]'
        );
        CREATE INDEX context_import_runs_context_started_idx
            ON context_import_runs(context_id, started_at DESC, id DESC);

        CREATE TABLE context_heads (
            context_id TEXT PRIMARY KEY,
            context_revision_id INTEGER NOT NULL
                REFERENCES context_revisions(id) ON DELETE RESTRICT,
            activated_by_import_run_id INTEGER NOT NULL
                REFERENCES context_import_runs(id) ON DELETE RESTRICT,
            activated_at TEXT NOT NULL
        );

        CREATE TABLE intent_sites (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            context_revision_id INTEGER NOT NULL REFERENCES context_revisions(id) ON DELETE RESTRICT,
            stable_id TEXT NOT NULL,
            lifecycle TEXT NOT NULL CHECK (lifecycle IN ('active', 'retired')),
            canonical_json TEXT NOT NULL,
            canonical_hash TEXT NOT NULL,
            origin_context_revision_id INTEGER NOT NULL REFERENCES context_revisions(id) ON DELETE RESTRICT,
            UNIQUE(context_revision_id, stable_id)
        );
        CREATE INDEX intent_sites_revision_lifecycle_idx ON intent_sites(context_revision_id, lifecycle);
        CREATE INDEX intent_sites_revision_hash_idx ON intent_sites(context_revision_id, canonical_hash);

        CREATE TABLE intent_locations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            context_revision_id INTEGER NOT NULL REFERENCES context_revisions(id) ON DELETE RESTRICT,
            stable_id TEXT NOT NULL,
            lifecycle TEXT NOT NULL CHECK (lifecycle IN ('active', 'retired')),
            canonical_json TEXT NOT NULL,
            canonical_hash TEXT NOT NULL,
            origin_context_revision_id INTEGER NOT NULL REFERENCES context_revisions(id) ON DELETE RESTRICT,
            UNIQUE(context_revision_id, stable_id)
        );
        CREATE INDEX intent_locations_revision_lifecycle_idx ON intent_locations(context_revision_id, lifecycle);
        CREATE INDEX intent_locations_revision_hash_idx ON intent_locations(context_revision_id, canonical_hash);

        CREATE TABLE intent_segments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            context_revision_id INTEGER NOT NULL REFERENCES context_revisions(id) ON DELETE RESTRICT,
            stable_id TEXT NOT NULL,
            lifecycle TEXT NOT NULL CHECK (lifecycle IN ('active', 'retired')),
            canonical_json TEXT NOT NULL,
            canonical_hash TEXT NOT NULL,
            origin_context_revision_id INTEGER NOT NULL REFERENCES context_revisions(id) ON DELETE RESTRICT,
            UNIQUE(context_revision_id, stable_id)
        );
        CREATE INDEX intent_segments_revision_lifecycle_idx ON intent_segments(context_revision_id, lifecycle);
        CREATE INDEX intent_segments_revision_hash_idx ON intent_segments(context_revision_id, canonical_hash);

        CREATE TABLE intent_assets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            context_revision_id INTEGER NOT NULL REFERENCES context_revisions(id) ON DELETE RESTRICT,
            stable_id TEXT NOT NULL,
            lifecycle TEXT NOT NULL CHECK (lifecycle IN ('active', 'retired')),
            canonical_json TEXT NOT NULL,
            canonical_hash TEXT NOT NULL,
            origin_context_revision_id INTEGER NOT NULL REFERENCES context_revisions(id) ON DELETE RESTRICT,
            UNIQUE(context_revision_id, stable_id)
        );
        CREATE INDEX intent_assets_revision_lifecycle_idx ON intent_assets(context_revision_id, lifecycle);
        CREATE INDEX intent_assets_revision_hash_idx ON intent_assets(context_revision_id, canonical_hash);

        CREATE TABLE intent_services (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            context_revision_id INTEGER NOT NULL REFERENCES context_revisions(id) ON DELETE RESTRICT,
            stable_id TEXT NOT NULL,
            lifecycle TEXT NOT NULL CHECK (lifecycle IN ('active', 'retired')),
            canonical_json TEXT NOT NULL,
            canonical_hash TEXT NOT NULL,
            origin_context_revision_id INTEGER NOT NULL REFERENCES context_revisions(id) ON DELETE RESTRICT,
            UNIQUE(context_revision_id, stable_id)
        );
        CREATE INDEX intent_services_revision_lifecycle_idx ON intent_services(context_revision_id, lifecycle);
        CREATE INDEX intent_services_revision_hash_idx ON intent_services(context_revision_id, canonical_hash);

        CREATE TABLE intent_links (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            context_revision_id INTEGER NOT NULL REFERENCES context_revisions(id) ON DELETE RESTRICT,
            stable_id TEXT NOT NULL,
            lifecycle TEXT NOT NULL CHECK (lifecycle IN ('active', 'retired')),
            canonical_json TEXT NOT NULL,
            canonical_hash TEXT NOT NULL,
            origin_context_revision_id INTEGER NOT NULL REFERENCES context_revisions(id) ON DELETE RESTRICT,
            relation TEXT NOT NULL CHECK (relation IN (
                'CONNECTED_TO', 'MEMBER_OF', 'ROUTED_VIA', 'RUNS_ON', 'USED_BY',
                'LOCATED_AT', 'CAN_ACCESS', 'AFFECTED_BY', 'RESOLVED_BY'
            )),
            endpoint_a_json TEXT NOT NULL,
            endpoint_b_json TEXT NOT NULL,
            UNIQUE(context_revision_id, stable_id)
        );
        CREATE INDEX intent_links_revision_lifecycle_idx ON intent_links(context_revision_id, lifecycle);
        CREATE INDEX intent_links_revision_hash_idx ON intent_links(context_revision_id, canonical_hash);
        """.split(";"):
        if statement.strip():
            conn.execute(statement)


MIGRATIONS: tuple[tuple[int, Callable[[sqlite3.Connection], None]], ...] = ((1, _migration_1),)


def apply_migrations(conn: sqlite3.Connection) -> None:
    conn.execute("SAVEPOINT apply_migrations")
    try:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS schema_migrations (
                version INTEGER PRIMARY KEY,
                applied_at TEXT NOT NULL
            )
            """
        )
        applied_versions = {row[0] for row in conn.execute("SELECT version FROM schema_migrations")}
        for version, migration in sorted(MIGRATIONS):
            if version not in applied_versions:
                migration(conn)
                conn.execute(
                    "INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)",
                    (version, utc_now()),
                )
        conn.execute("RELEASE SAVEPOINT apply_migrations")
    except Exception:
        conn.execute("ROLLBACK TO SAVEPOINT apply_migrations")
        conn.execute("RELEASE SAVEPOINT apply_migrations")
        raise
