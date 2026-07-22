from __future__ import annotations

import sqlite3
from collections.abc import Callable


def _migration_1(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        CREATE TABLE change_plans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            plan_key TEXT NOT NULL UNIQUE, actor TEXT NOT NULL, reason TEXT NOT NULL,
            subject_type TEXT NOT NULL CHECK (subject_type IN ('asset','user','infrastructure')),
            subject_key TEXT NOT NULL,
            operation_type TEXT NOT NULL CHECK (operation_type IN ('internet_access_set','internet_policy_bootstrap')),
            desired_state_json TEXT NOT NULL, resolved_targets_json TEXT NOT NULL,
            context_evidence_hash TEXT NOT NULL, precheck_json TEXT NOT NULL, rollback_json TEXT NOT NULL,
            status TEXT NOT NULL CHECK (status IN ('draft','validated','approved','applying','applied','verified','failed','rolling_back','rolled_back','cancelled')),
            created_at TEXT NOT NULL, approved_at TEXT, applied_at TEXT, verified_at TEXT, updated_at TEXT NOT NULL
        );
        CREATE TABLE change_plan_steps (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            change_plan_id INTEGER NOT NULL REFERENCES change_plans(id) ON DELETE RESTRICT,
            step_order INTEGER NOT NULL, adapter TEXT NOT NULL, operation TEXT NOT NULL, target_key TEXT NOT NULL,
            request_json TEXT NOT NULL, result_json TEXT NOT NULL DEFAULT '{}',
            status TEXT NOT NULL CHECK (status IN ('pending','applied','verified','failed','rolled_back')),
            UNIQUE(change_plan_id, step_order)
        );
        CREATE TABLE change_executions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            change_plan_id INTEGER NOT NULL REFERENCES change_plans(id) ON DELETE RESTRICT,
            execution_type TEXT NOT NULL CHECK (execution_type IN ('apply','verify','rollback','reconcile')),
            started_at TEXT NOT NULL, finished_at TEXT,
            status TEXT NOT NULL CHECK (status IN ('running','success','failed')),
            sanitized_result_json TEXT NOT NULL DEFAULT '{}'
        );
        CREATE TABLE desired_network_policies (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            subject_type TEXT NOT NULL CHECK (subject_type IN ('asset','user')),
            subject_key TEXT NOT NULL, policy_type TEXT NOT NULL CHECK (policy_type = 'internet_access'),
            desired_state TEXT NOT NULL CHECK (desired_state IN ('allow','deny')),
            enforcement_scope TEXT NOT NULL DEFAULT 'all-sites', reason TEXT NOT NULL,
            valid_from TEXT NOT NULL, valid_until TEXT,
            source_plan_id INTEGER NOT NULL REFERENCES change_plans(id) ON DELETE RESTRICT,
            status TEXT NOT NULL CHECK (status IN ('active','expired','retired')),
            updated_at TEXT NOT NULL,
            UNIQUE(subject_type, subject_key, policy_type, enforcement_scope)
        );
        """
    )


def _migration_2(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        CREATE TABLE audit_events (
            sequence INTEGER PRIMARY KEY,
            event_id TEXT NOT NULL UNIQUE,
            event_type TEXT NOT NULL,
            created_at TEXT NOT NULL,
            payload_hash TEXT NOT NULL,
            previous_hash TEXT NOT NULL,
            event_hash TEXT NOT NULL UNIQUE,
            signer_key_id TEXT NOT NULL,
            signature BLOB NOT NULL
        );
        CREATE TRIGGER audit_events_no_update
        BEFORE UPDATE ON audit_events
        BEGIN SELECT RAISE(ABORT, 'audit_events are append-only'); END;
        CREATE TRIGGER audit_events_no_delete
        BEFORE DELETE ON audit_events
        BEGIN SELECT RAISE(ABORT, 'audit_events are append-only'); END;
        CREATE TABLE used_authorization_nonces (
            nonce TEXT PRIMARY KEY,
            expires_at TEXT NOT NULL,
            consumed_at TEXT NOT NULL
        );
        """
    )


def _migration_3(conn: sqlite3.Connection) -> None:
    conn.execute("ALTER TABLE audit_events ADD COLUMN payload_json TEXT NOT NULL DEFAULT '{}'")


def _migration_4(conn: sqlite3.Connection) -> None:
    conn.execute(
        """CREATE TABLE device_operation_locks (
            device_key TEXT PRIMARY KEY,
            holder TEXT NOT NULL,
            acquired_at TEXT NOT NULL
        )"""
    )


def _migration_5(conn: sqlite3.Connection) -> None:
    """Persist the exact immutable context evidence behind a change plan."""
    conn.execute("ALTER TABLE change_plans ADD COLUMN plan_basis_json TEXT NOT NULL DEFAULT '{}'")
    conn.execute("ALTER TABLE change_plans ADD COLUMN plan_basis_hash TEXT NOT NULL DEFAULT ''")


def _migration_6(conn: sqlite3.Connection) -> None:
    """Make the versioned control contract an immutable part of every plan."""
    conn.execute("ALTER TABLE change_plans ADD COLUMN plan_schema_version INTEGER NOT NULL DEFAULT 1 CHECK (plan_schema_version = 1)")
    conn.execute("ALTER TABLE change_plans ADD COLUMN authorization_version INTEGER NOT NULL DEFAULT 1 CHECK (authorization_version = 1)")
    conn.execute("ALTER TABLE change_plans ADD COLUMN operation_version INTEGER NOT NULL DEFAULT 1 CHECK (operation_version = 1)")


def _migration_7(conn: sqlite3.Connection) -> None:
    """Keep stale desired-policy identity visible without changing device state."""
    conn.execute(
        """CREATE TABLE network_policy_findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            desired_policy_id INTEGER NOT NULL REFERENCES desired_network_policies(id) ON DELETE RESTRICT,
            finding_type TEXT NOT NULL CHECK (finding_type = 'policy_stale_identity'),
            status TEXT NOT NULL CHECK (status IN ('open', 'resolved')),
            first_seen_at TEXT NOT NULL,
            last_seen_at TEXT NOT NULL,
            details_json TEXT NOT NULL DEFAULT '{}',
            UNIQUE(desired_policy_id, finding_type)
        )"""
    )


def _migration_8(conn: sqlite3.Connection) -> None:
    """Allow a new broker process to identify locks abandoned by a crashed PID."""
    conn.execute("ALTER TABLE device_operation_locks ADD COLUMN owner_pid INTEGER NOT NULL DEFAULT 0")


MIGRATIONS: tuple[tuple[int, Callable[[sqlite3.Connection], None]], ...] = (
    (1, _migration_1),
    (2, _migration_2),
    (3, _migration_3),
    (4, _migration_4),
    (5, _migration_5),
    (6, _migration_6),
    (7, _migration_7),
    (8, _migration_8),
)


def apply_migrations(conn: sqlite3.Connection) -> None:
    conn.execute("CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)")
    for version, migration in MIGRATIONS:
        if conn.execute("SELECT 1 FROM schema_migrations WHERE version = ?", (version,)).fetchone():
            continue
        migration(conn)
        conn.execute("INSERT INTO schema_migrations (version, applied_at) VALUES (?, datetime('now'))", (version,))
    conn.commit()
