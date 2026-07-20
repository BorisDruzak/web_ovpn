from __future__ import annotations

import json
import re
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass

from .snmp.outcomes import SnmpOutcome

_FINGERPRINT_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_NUMERIC_DOTTED_OID = re.compile(r"[0-9]+(?:\.[0-9]+)+\Z")
_CAPABILITY_KEYS = frozenset({"capability", "outcome"})
_DISCOVERY_CAPABILITIES = frozenset(
    {"sys_descr", "sys_object_id", "sys_uptime", "sys_name", "sys_location"}
)
_SNMP_OUTCOMES = frozenset(outcome.value for outcome in SnmpOutcome)
_UNSAFE_IDENTITY_TEXT = re.compile(
    r"\b(?:community|password|secret|credential|token|api[_ -]?key|"
    r"authorization|bearer|username|endpoint|host|address|varbind|fdb)\b|"
    r"(?:https?|snmp)://|\b(?:\d{1,3}\.){3}\d{1,3}\b|"
    r"(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}|=",
    re.IGNORECASE,
)
_MAX_CAPABILITIES = 32


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
    result: list[dict[str, object]] = []
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
        ).fetchall():
        public_row = _safe_public_row(dict(row))
        if public_row is not None:
            result.append(public_row)
    return result


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

    sys_object_id, sys_descr, fingerprint_sha256, capabilities_json, status, observed_at = (
        _public_values(
            sys_object_id=observation.sys_object_id,
            sys_descr=observation.sys_descr,
            fingerprint_sha256=observation.fingerprint_sha256,
            capabilities_json=observation.capabilities_json,
            status=observation.status,
            observed_at=observation.observed_at,
        )
    )
    return (
        observation.source_id,
        sys_object_id,
        sys_descr,
        fingerprint_sha256,
        capabilities_json,
        status,
        observed_at,
    )


def _safe_public_row(row: dict[str, object]) -> dict[str, object] | None:
    try:
        sys_object_id, sys_descr, fingerprint_sha256, capabilities_json, status, observed_at = _public_values(
            sys_object_id=row["sys_object_id"],
            sys_descr=row["sys_descr"],
            fingerprint_sha256=row["fingerprint_sha256"],
            capabilities_json=row["capabilities_json"],
            status=row["status"],
            observed_at=row["observed_at"],
        )
        if type(row["source"]) is not str or not row["source"]:
            raise ValueError("unknown fingerprint source is invalid")
    except (KeyError, ValueError):
        return None
    return {
        "source": row["source"],
        "sys_object_id": sys_object_id,
        "sys_descr": sys_descr,
        "fingerprint_sha256": fingerprint_sha256,
        "capabilities_json": capabilities_json,
        "status": status,
        "observed_at": observed_at,
    }


def _public_values(
    *,
    sys_object_id: object,
    sys_descr: object,
    fingerprint_sha256: object,
    capabilities_json: object,
    status: object,
    observed_at: object,
) -> tuple[str, str, str, str, str, str]:
    sys_object_id = _numeric_dotted_oid(sys_object_id)
    sys_descr = _safe_identity_text(sys_descr)
    if type(fingerprint_sha256) is not str or _FINGERPRINT_SHA256.fullmatch(fingerprint_sha256) is None:
        raise ValueError("unknown fingerprint digest is invalid")
    if status != "requires_profile":
        raise ValueError("unknown fingerprint status is invalid")
    return (
        sys_object_id,
        sys_descr,
        fingerprint_sha256,
        _canonical_capabilities(capabilities_json),
        status,
        _bounded_text(observed_at, 64, "observed time"),
    )


def _numeric_dotted_oid(value: object) -> str:
    if type(value) is not str or _NUMERIC_DOTTED_OID.fullmatch(value) is None:
        raise ValueError("unknown fingerprint system identity is invalid")
    parts = tuple(int(part) for part in value.split("."))
    if (
        len(value) > 255
        or parts[0] > 2
        or (parts[0] < 2 and parts[1] > 39)
        or any(part > 2_147_483_647 for part in parts)
    ):
        raise ValueError("unknown fingerprint system identity is invalid")
    return value


def _safe_identity_text(value: object) -> str:
    if type(value) is not str:
        raise ValueError("unknown fingerprint system identity is invalid")
    normalized = " ".join(value.split())
    if not normalized or len(normalized) > 256 or _UNSAFE_IDENTITY_TEXT.search(normalized):
        raise ValueError("unknown fingerprint system identity is invalid")
    return normalized


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
        if (
            row["capability"] not in _DISCOVERY_CAPABILITIES
            or row["outcome"] not in _SNMP_OUTCOMES
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
