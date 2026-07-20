from __future__ import annotations

import json
import re
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass


_FINGERPRINT_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_CAPABILITY_KEYS = frozenset({"capability", "outcome"})
_MAX_CAPABILITIES = 32
_MAX_CAPABILITY_VALUE_LENGTH = 128


@dataclass(frozen=True)
class UnknownSwitchFingerprint:
    source_id: int
    sys_object_id: str
    sys_descr: str
    fingerprint_sha256: str
    capabilities_json: str
    status: str
    observed_at: str


def record_unknown_fingerprint(
    conn: sqlite3.Connection, observation: UnknownSwitchFingerprint
) -> None:
    """Atomically store the current safe unknown-switch observation per source."""
    values = _validated_values(conn, observation)
    with _atomic(conn):
        conn.execute(
            """
            INSERT INTO switch_unknown_fingerprints (
                source_id, sys_object_id, sys_descr, fingerprint_sha256,
                capabilities_json, status, observed_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(source_id) DO UPDATE SET
                sys_object_id = excluded.sys_object_id,
                sys_descr = excluded.sys_descr,
                fingerprint_sha256 = excluded.fingerprint_sha256,
                capabilities_json = excluded.capabilities_json,
                status = excluded.status,
                observed_at = excluded.observed_at
            """,
            values,
        )


def list_unknown_fingerprints(conn: sqlite3.Connection) -> list[dict[str, object]]:
    """Return only public source names and the bounded fingerprint fields."""
    return [
        dict(row)
        for row in conn.execute(
            """
            SELECT sources.name AS source, fingerprints.sys_object_id,
                   fingerprints.sys_descr, fingerprints.fingerprint_sha256,
                   fingerprints.capabilities_json, fingerprints.status,
                   fingerprints.observed_at
            FROM switch_unknown_fingerprints AS fingerprints
            JOIN network_sources AS sources ON sources.id = fingerprints.source_id
            ORDER BY fingerprints.observed_at DESC, fingerprints.source_id
            """
        ).fetchall()
    ]


def _validated_values(
    conn: sqlite3.Connection, observation: UnknownSwitchFingerprint
) -> tuple[int, str, str, str, str, str, str]:
    if not isinstance(observation, UnknownSwitchFingerprint):
        raise ValueError("unknown fingerprint observation is invalid")
    if type(observation.source_id) is not int or observation.source_id < 1:
        raise ValueError("unknown fingerprint source is invalid")
    if conn.execute(
        "SELECT 1 FROM network_sources WHERE id = ?", (observation.source_id,)
    ).fetchone() is None:
        raise ValueError("unknown fingerprint source is invalid")

    sys_object_id = _bounded_text(observation.sys_object_id, 255, "system identity")
    sys_descr = _bounded_text(observation.sys_descr, 1024, "system identity")
    observed_at = _bounded_text(observation.observed_at, 64, "observed time")
    if observation.status != "requires_profile":
        raise ValueError("unknown fingerprint status is invalid")
    if (
        type(observation.fingerprint_sha256) is not str
        or _FINGERPRINT_SHA256.fullmatch(observation.fingerprint_sha256) is None
    ):
        raise ValueError("unknown fingerprint digest is invalid")

    capabilities_json = _canonical_capabilities(observation.capabilities_json)
    return (
        observation.source_id,
        sys_object_id,
        sys_descr,
        observation.fingerprint_sha256,
        capabilities_json,
        observation.status,
        observed_at,
    )


def _bounded_text(value: object, maximum: int, field: str) -> str:
    if type(value) is not str or not value or len(value) > maximum:
        raise ValueError(f"unknown fingerprint {field} is invalid")
    return value


def _canonical_capabilities(value: object) -> str:
    if type(value) is not str or len(value) > 4096:
        raise ValueError("unknown fingerprint capabilities are invalid")
    try:
        rows = json.loads(value)
    except (TypeError, ValueError):
        raise ValueError("unknown fingerprint capabilities are invalid") from None
    if type(rows) is not list or len(rows) > _MAX_CAPABILITIES:
        raise ValueError("unknown fingerprint capabilities are invalid")
    for row in rows:
        if type(row) is not dict or set(row) != _CAPABILITY_KEYS:
            raise ValueError("unknown fingerprint capabilities are invalid")
        if any(
            type(item) is not str
            or not item
            or len(item) > _MAX_CAPABILITY_VALUE_LENGTH
            for item in (row["capability"], row["outcome"])
        ):
            raise ValueError("unknown fingerprint capabilities are invalid")
    return json.dumps(rows, ensure_ascii=True, sort_keys=True, separators=(",", ":"))


@contextmanager
def _atomic(conn: sqlite3.Connection) -> Iterator[None]:
    if conn.in_transaction:
        conn.execute("SAVEPOINT switch_unknown_fingerprint_atomic")
        try:
            yield
        except BaseException:
            conn.execute("ROLLBACK TO SAVEPOINT switch_unknown_fingerprint_atomic")
            conn.execute("RELEASE SAVEPOINT switch_unknown_fingerprint_atomic")
            raise
        else:
            conn.execute("RELEASE SAVEPOINT switch_unknown_fingerprint_atomic")
        return

    conn.execute("BEGIN IMMEDIATE")
    try:
        yield
    except BaseException:
        conn.rollback()
        raise
    else:
        try:
            conn.commit()
        except BaseException:
            conn.rollback()
            raise
