from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

from .context import (
    IMPORT_COLLECTIONS,
    canonical_entity_hash,
    canonical_entity_json,
    context_summary,
    normalise_import_entities,
    validate_import_semantics,
)
from .db import (
    create_context_import_run,
    finish_context_import_run,
    get_context_head,
    record_context_revision,
    set_context_head,
)


SUCCESS_STATUSES = (
    "success_imported",
    "success_noop_same_content",
    "success_activated_existing_content",
)


def import_context(
    conn: sqlite3.Connection,
    document: dict[str, Any],
    raw_bytes: bytes,
    source_path: Path,
    git_sha: str,
) -> dict[str, Any]:
    """Validate, materialise, and atomically activate a context document."""
    summary = context_summary(document, raw_bytes)
    context_id = summary["context_id"]
    input_sha256 = summary["sha256"]
    semantic_errors = validate_import_semantics(document)
    initial_head = get_context_head(conn, context_id)
    base_revision_id = initial_head["context_revision_id"] if initial_head else None

    if semantic_errors:
        return _record_validation_error(
            conn,
            context_id=context_id,
            base_revision_id=base_revision_id,
            input_sha256=input_sha256,
            git_sha=git_sha,
            source_path=source_path,
            errors=semantic_errors,
            head=initial_head,
        )

    candidate_rows = _prepare_candidate_rows(document)
    try:
        revision = record_context_revision(conn, summary, source_path, git_sha)
        run = create_context_import_run(
            conn,
            context_id=context_id,
            context_revision_id=revision["id"],
            base_context_revision_id=base_revision_id,
            input_sha256=input_sha256,
            git_sha=git_sha,
            source_path=source_path,
        )
        conn.commit()
    except Exception:
        conn.rollback()
        raise

    try:
        conn.execute("BEGIN IMMEDIATE")
        head = get_context_head(conn, context_id)
        if head and head["context_revision_id"] == revision["id"]:
            status = "success_noop_same_content"
        elif _revision_has_snapshot(conn, revision["id"]):
            head = set_context_head(conn, context_id, revision["id"], run["id"])
            status = "success_activated_existing_content"
        else:
            prior_revision_id = head["context_revision_id"] if head else None
            _materialise_snapshot(conn, revision["id"], prior_revision_id, candidate_rows)
            head = set_context_head(conn, context_id, revision["id"], run["id"])
            status = "success_imported"
        run = finish_context_import_run(conn, run["id"], status, [])
        conn.commit()
        return _import_result(status, run, revision, head, [])
    except Exception as exc:
        conn.rollback()
        return _record_database_error(conn, run, revision, context_id, exc)


def load_active_snapshot(
    conn: sqlite3.Connection,
    context_id: str,
) -> dict[str, dict[str, dict[str, Any]]] | None:
    """Load active entities from the selected head, keyed by type and stable ID."""
    head = get_context_head(conn, context_id)
    if head is None:
        return None

    snapshot: dict[str, dict[str, dict[str, Any]]] = {}
    for _collection, (table, entity_type) in IMPORT_COLLECTIONS.items():
        rows = conn.execute(
            f"""
            SELECT stable_id, canonical_json
            FROM {table}
            WHERE context_revision_id = ? AND lifecycle = 'active'
            ORDER BY stable_id
            """,
            (head["context_revision_id"],),
        ).fetchall()
        snapshot[entity_type] = {
            str(row["stable_id"]): json.loads(row["canonical_json"])
            for row in rows
        }
    return snapshot


def _record_validation_error(
    conn: sqlite3.Connection,
    *,
    context_id: str,
    base_revision_id: int | None,
    input_sha256: str,
    git_sha: str,
    source_path: Path,
    errors: list[dict[str, str]],
    head: dict[str, Any] | None,
) -> dict[str, Any]:
    try:
        run = create_context_import_run(
            conn,
            context_id=context_id,
            context_revision_id=None,
            base_context_revision_id=base_revision_id,
            input_sha256=input_sha256,
            git_sha=git_sha,
            source_path=source_path,
        )
        run = finish_context_import_run(conn, run["id"], "validation_error", errors)
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    return _import_result("validation_error", run, None, head, errors)


def _record_database_error(
    conn: sqlite3.Connection,
    run: dict[str, Any],
    revision: dict[str, Any],
    context_id: str,
    materialisation_error: Exception,
) -> dict[str, Any]:
    errors = [{"path": "database", "message": str(materialisation_error)}]
    try:
        finished_run = finish_context_import_run(conn, run["id"], "db_error", errors)
        conn.commit()
    except Exception as audit_error:
        conn.rollback()
        raise RuntimeError(
            f"{materialisation_error}; failed to persist db_error audit: {audit_error}"
        ) from materialisation_error
    return _import_result(
        "db_error",
        finished_run,
        revision,
        get_context_head(conn, context_id),
        errors,
    )


def _prepare_candidate_rows(
    document: dict[str, Any],
) -> dict[str, dict[str, dict[str, Any]]]:
    normalised = normalise_import_entities(document)
    prepared: dict[str, dict[str, dict[str, Any]]] = {}
    for _collection, (table, entity_type) in IMPORT_COLLECTIONS.items():
        prepared[table] = {}
        for stable_id, entity in normalised[entity_type].items():
            row = {
                "stable_id": stable_id,
                "canonical_json": canonical_entity_json(entity),
                "canonical_hash": canonical_entity_hash(entity),
            }
            if entity_type == "link":
                row.update(
                    {
                        "relation": entity["relation"],
                        "endpoint_a_json": canonical_entity_json(entity["endpoint_a"]),
                        "endpoint_b_json": canonical_entity_json(entity["endpoint_b"]),
                    }
                )
            prepared[table][stable_id] = row
    return prepared


def _revision_has_snapshot(conn: sqlite3.Connection, revision_id: int) -> bool:
    placeholders = ", ".join("?" for _status in SUCCESS_STATUSES)
    row = conn.execute(
        f"""
        SELECT 1
        FROM context_import_runs
        WHERE context_revision_id = ? AND status IN ({placeholders})
        LIMIT 1
        """,
        (revision_id, *SUCCESS_STATUSES),
    ).fetchone()
    return row is not None


def _materialise_snapshot(
    conn: sqlite3.Connection,
    revision_id: int,
    prior_revision_id: int | None,
    candidate_rows: dict[str, dict[str, dict[str, Any]]],
) -> None:
    for table, entities in candidate_rows.items():
        prior_rows = _load_revision_rows(conn, table, prior_revision_id)
        for stable_id, candidate in sorted(entities.items()):
            origin_revision_id = _find_entity_origin(
                conn,
                table,
                revision_id,
                stable_id,
                candidate["canonical_hash"],
                candidate["canonical_json"],
            ) or revision_id
            _insert_intent_row(
                conn,
                table,
                revision_id,
                "active",
                candidate,
                origin_revision_id,
            )

        for stable_id, prior in sorted(prior_rows.items()):
            if stable_id not in entities:
                _insert_intent_row(
                    conn,
                    table,
                    revision_id,
                    "retired",
                    prior,
                    int(prior["origin_context_revision_id"]),
                )


def _load_revision_rows(
    conn: sqlite3.Connection,
    table: str,
    revision_id: int | None,
) -> dict[str, dict[str, Any]]:
    if revision_id is None:
        return {}
    extra_columns = ", relation, endpoint_a_json, endpoint_b_json" if table == "intent_links" else ""
    rows = conn.execute(
        f"""
        SELECT stable_id, canonical_json, canonical_hash, origin_context_revision_id{extra_columns}
        FROM {table}
        WHERE context_revision_id = ?
        ORDER BY stable_id
        """,
        (revision_id,),
    ).fetchall()
    return {str(row["stable_id"]): dict(row) for row in rows}


def _find_entity_origin(
    conn: sqlite3.Connection,
    table: str,
    revision_id: int,
    stable_id: str,
    canonical_hash: str,
    canonical_json: str,
) -> int | None:
    row = conn.execute(
        f"""
        SELECT origin_context_revision_id
        FROM {table}
        WHERE context_revision_id IN (
            SELECT id
            FROM context_revisions
            WHERE context_id = (
                SELECT context_id FROM context_revisions WHERE id = ?
            )
        )
          AND stable_id = ? AND canonical_hash = ? AND canonical_json = ?
        ORDER BY id
        LIMIT 1
        """,
        (revision_id, stable_id, canonical_hash, canonical_json),
    ).fetchone()
    return int(row["origin_context_revision_id"]) if row else None


def _insert_intent_row(
    conn: sqlite3.Connection,
    table: str,
    revision_id: int,
    lifecycle: str,
    row: dict[str, Any],
    origin_revision_id: int,
) -> None:
    columns = (
        "context_revision_id, stable_id, lifecycle, canonical_json, "
        "canonical_hash, origin_context_revision_id"
    )
    values: tuple[Any, ...] = (
        revision_id,
        row["stable_id"],
        lifecycle,
        row["canonical_json"],
        row["canonical_hash"],
        origin_revision_id,
    )
    if table == "intent_links":
        columns += ", relation, endpoint_a_json, endpoint_b_json"
        values += (row["relation"], row["endpoint_a_json"], row["endpoint_b_json"])
    placeholders = ", ".join("?" for _value in values)
    conn.execute(
        f"INSERT INTO {table} ({columns}) VALUES ({placeholders})",
        values,
    )


def _import_result(
    status: str,
    run: dict[str, Any],
    revision: dict[str, Any] | None,
    head: dict[str, Any] | None,
    errors: list[dict[str, str]],
) -> dict[str, Any]:
    return {
        "result": status,
        "run": run,
        "context": revision,
        "head": head,
        "errors": errors,
    }
