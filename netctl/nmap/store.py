from __future__ import annotations

import json
import sqlite3
from collections.abc import Callable
from dataclasses import asdict
from datetime import UTC, datetime
from typing import Any

from .models import FingerprintProfile, NmapFingerprint
from .policy import ASSET_FINGERPRINT_PROFILE, resolve_asset_target
from .runner import NmapRunnerError, run_nmap_fingerprint
from ..util import utc_now
from ..fingerprint.providers import recompute_asset_fingerprint


FingerprintExecutor = Callable[[str], NmapFingerprint]
_RUNNER_MESSAGES = {
    "timeout": "fingerprint helper timed out",
    "helper_unavailable": "fingerprint helper is unavailable",
    "helper_permission_denied": "fingerprint helper permission denied",
    "helper_error": "fingerprint helper failed",
    "scan_failed": "fingerprint helper failed",
    "invalid_output": "fingerprint helper returned invalid output",
}


def _parse_utc(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        raise ValueError("fingerprint timestamp must be UTC") from None
    if parsed.tzinfo is None or parsed.utcoffset() != UTC.utcoffset(parsed):
        raise ValueError("fingerprint timestamp must be UTC")
    return parsed.astimezone(UTC)


def _age_seconds(now: str, then: str) -> float:
    return max(0.0, (_parse_utc(now) - _parse_utc(then)).total_seconds())


def _validate_profile(profile: FingerprintProfile) -> None:
    if profile.name != ASSET_FINGERPRINT_PROFILE.name:
        raise ValueError("unsupported fingerprint profile")
    if profile.ttl_seconds <= 0 or profile.stale_running_seconds <= 30:
        raise ValueError("invalid fingerprint profile timing")


def _json_list(value: object) -> list[Any]:
    try:
        decoded = json.loads(str(value or "[]"))
    except (TypeError, ValueError, json.JSONDecodeError):
        return []
    return decoded if isinstance(decoded, list) else []


def _run_public(
    conn: sqlite3.Connection,
    row: sqlite3.Row | dict[str, Any],
    *,
    now: str,
    profile: FingerprintProfile,
) -> dict[str, Any]:
    run = dict(row)
    run_id = int(run["id"])
    ports = [
        {
            "protocol": str(item["protocol"]),
            "port": int(item["port"]),
            "state": str(item["state"]),
            "service_name": str(item["service_name"]),
            "product": str(item["product"]),
            "version": str(item["version"]),
            "extra_info": str(item["extra_info"]),
            "tunnel": str(item["tunnel"]),
            "method": str(item["method"]),
            "confidence": (
                int(item["confidence"]) if item["confidence"] is not None else None
            ),
            "cpes": [str(value) for value in _json_list(item["cpe_json"])],
        }
        for item in conn.execute(
            """SELECT * FROM nmap_fingerprint_ports
               WHERE run_id = ? ORDER BY protocol, port, id""",
            (run_id,),
        )
    ]
    os_matches = [
        {
            "name": str(item["name"]),
            "accuracy": int(item["accuracy"]) if item["accuracy"] is not None else None,
            "classes": _json_list(item["classes_json"]),
        }
        for item in conn.execute(
            """SELECT * FROM nmap_fingerprint_os_matches
               WHERE run_id = ? ORDER BY position, id""",
            (run_id,),
        )
    ]
    status = str(run["status"])
    finished_at = str(run["finished_at"] or "")
    fresh = bool(
        status == "success"
        and finished_at
        and _age_seconds(now, finished_at) < profile.ttl_seconds
    )
    asset = conn.execute(
        "SELECT asset_key FROM assets WHERE id = ?", (int(run["asset_id"]),)
    ).fetchone()
    return {
        "id": run_id,
        "asset_key": str(asset["asset_key"]) if asset is not None else "",
        "target_ip": str(run["target_ip"]),
        "profile": str(run["profile"]),
        "status": status,
        "started_at": str(run["started_at"]),
        "finished_at": finished_at,
        "nmap_version": str(run["nmap_version"] or ""),
        "error_class": str(run["error_class"] or ""),
        "error_message": str(run["error_message"] or ""),
        "fresh": fresh,
        "ports": ports,
        "os_matches": os_matches,
    }


def _row_by_id(conn: sqlite3.Connection, run_id: int) -> sqlite3.Row:
    row = conn.execute(
        "SELECT * FROM nmap_fingerprint_runs WHERE id = ?", (run_id,)
    ).fetchone()
    if row is None:
        raise RuntimeError("fingerprint run not found")
    return row


def fingerprint_status(
    conn: sqlite3.Connection,
    asset_key: str,
    *,
    now: str | None = None,
    profile: FingerprintProfile = ASSET_FINGERPRINT_PROFILE,
) -> dict[str, Any]:
    """Return the newest stored run for the asset's one current target."""
    _validate_profile(profile)
    effective_now = now or utc_now()
    _parse_utc(effective_now)
    target = resolve_asset_target(conn, asset_key)
    row = conn.execute(
        """SELECT * FROM nmap_fingerprint_runs
           WHERE asset_id = ? AND target_ip = ? AND profile = ?
           ORDER BY started_at DESC, id DESC LIMIT 1""",
        (target.asset_id, target.ip, profile.name),
    ).fetchone()
    if row is None:
        return {
            "asset_key": target.asset_key,
            "target_ip": target.ip,
            "profile": profile.name,
            "status": "not_run",
            "fresh": False,
            "ports": [],
            "os_matches": [],
        }
    return _run_public(conn, row, now=effective_now, profile=profile)


def _claim(
    conn: sqlite3.Connection,
    asset_key: str,
    *,
    now: str,
    profile: FingerprintProfile,
) -> tuple[sqlite3.Row, bool]:
    if conn.in_transaction:
        raise RuntimeError("fingerprint ensure requires a clean transaction")
    conn.execute("BEGIN IMMEDIATE")
    try:
        target = resolve_asset_target(conn, asset_key)
        fresh = conn.execute(
            """SELECT * FROM nmap_fingerprint_runs
               WHERE asset_id = ? AND target_ip = ? AND profile = ?
                 AND status = 'success'
               ORDER BY finished_at DESC, id DESC LIMIT 1""",
            (target.asset_id, target.ip, profile.name),
        ).fetchone()
        if fresh is not None and _age_seconds(
            now, str(fresh["finished_at"])
        ) < profile.ttl_seconds:
            conn.commit()
            return fresh, False

        running = conn.execute(
            """SELECT * FROM nmap_fingerprint_runs
               WHERE asset_id = ? AND profile = ? AND status = 'running'
               ORDER BY started_at DESC, id DESC LIMIT 1""",
            (target.asset_id, profile.name),
        ).fetchone()
        if running is not None:
            stale = _age_seconds(now, str(running["started_at"])) >= (
                profile.stale_running_seconds
            )
            if not stale:
                conn.commit()
                return running, False
            conn.execute(
                """UPDATE nmap_fingerprint_runs
                   SET status = 'failed', finished_at = ?,
                       error_class = ?, error_message = ?
                   WHERE id = ? AND status = 'running'""",
                (
                    now,
                    "stale_running",
                    "fingerprint run exceeded stale timeout",
                    int(running["id"]),
                ),
            )

        run_id = int(
            conn.execute(
                """INSERT INTO nmap_fingerprint_runs
                   (asset_id, target_ip, profile, status, started_at)
                   VALUES (?, ?, ?, 'running', ?)""",
                (target.asset_id, target.ip, profile.name, now),
            ).lastrowid
        )
        claimed = _row_by_id(conn, run_id)
        conn.commit()
        return claimed, True
    except BaseException:
        if conn.in_transaction:
            conn.rollback()
        raise


def _finish_failed(
    conn: sqlite3.Connection,
    run_id: int,
    *,
    now: str,
    error_class: str,
    error_message: str,
) -> None:
    conn.execute("BEGIN IMMEDIATE")
    try:
        conn.execute(
            """UPDATE nmap_fingerprint_runs
               SET status = 'failed', finished_at = ?, error_class = ?, error_message = ?
               WHERE id = ? AND status = 'running'""",
            (now, error_class, error_message, run_id),
        )
        conn.commit()
    except BaseException:
        if conn.in_transaction:
            conn.rollback()
        raise


def _finish_success(
    conn: sqlite3.Connection,
    run_id: int,
    fingerprint: NmapFingerprint,
    *,
    now: str,
) -> None:
    conn.execute("BEGIN IMMEDIATE")
    try:
        updated = conn.execute(
            """UPDATE nmap_fingerprint_runs
               SET status = 'success', finished_at = ?, nmap_version = ?,
                   error_class = '', error_message = ''
               WHERE id = ? AND status = 'running'""",
            (now, fingerprint.nmap_version, run_id),
        )
        if updated.rowcount == 1:
            conn.executemany(
                """INSERT INTO nmap_fingerprint_ports
                   (run_id, protocol, port, state, service_name, product, version,
                    extra_info, tunnel, method, confidence, cpe_json)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                [
                    (
                        run_id,
                        port.protocol,
                        port.port,
                        port.state,
                        port.service_name,
                        port.product,
                        port.version,
                        port.extra_info,
                        port.tunnel,
                        port.method,
                        port.confidence,
                        json.dumps(list(port.cpes), separators=(",", ":")),
                    )
                    for port in fingerprint.ports
                ],
            )
            conn.executemany(
                """INSERT INTO nmap_fingerprint_os_matches
                   (run_id, position, name, accuracy, classes_json)
                   VALUES (?, ?, ?, ?, ?)""",
                [
                    (
                        run_id,
                        position,
                        match.name,
                        match.accuracy,
                        json.dumps(
                            [asdict(item) for item in match.classes],
                            separators=(",", ":"),
                        ),
                    )
                    for position, match in enumerate(fingerprint.os_matches)
                ],
            )
            asset = conn.execute(
                "SELECT asset_id FROM nmap_fingerprint_runs WHERE id = ?", (run_id,)
            ).fetchone()
            if asset is not None:
                recompute_asset_fingerprint(
                    conn, int(asset["asset_id"]), computed_at=now
                )
        conn.commit()
    except BaseException:
        if conn.in_transaction:
            conn.rollback()
        raise


def ensure_fingerprint(
    conn: sqlite3.Connection,
    asset_key: str,
    *,
    executor: FingerprintExecutor = run_nmap_fingerprint,
    now: str | None = None,
    profile: FingerprintProfile = ASSET_FINGERPRINT_PROFILE,
    clock: Callable[[], str] = utc_now,
) -> dict[str, Any]:
    """Atomically reuse, join, reclaim, or execute one asset fingerprint."""
    _validate_profile(profile)
    started_at = now or clock()
    _parse_utc(started_at)
    run, claimed = _claim(conn, asset_key, now=started_at, profile=profile)
    if not claimed:
        return _run_public(conn, run, now=started_at, profile=profile)
    run_id = int(run["id"])
    try:
        fingerprint = executor(str(run["target_ip"]))
    except NmapRunnerError as exc:
        finished_at = now or clock()
        error_message = _RUNNER_MESSAGES.get(exc.error_class)
        error_class = exc.error_class if error_message is not None else "internal_error"
        _finish_failed(
            conn,
            run_id,
            now=finished_at,
            error_class=error_class,
            error_message=error_message or "fingerprint execution failed",
        )
    except Exception:
        finished_at = now or clock()
        _finish_failed(
            conn,
            run_id,
            now=finished_at,
            error_class="internal_error",
            error_message="fingerprint execution failed",
        )
    else:
        finished_at = now or clock()
        _finish_success(conn, run_id, fingerprint, now=finished_at)
    return _run_public(
        conn, _row_by_id(conn, run_id), now=finished_at, profile=profile
    )
