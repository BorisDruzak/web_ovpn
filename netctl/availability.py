from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
import ipaddress
import sqlite3

from .context_classifier import load_active_availability_segments


@dataclass(frozen=True)
class AvailabilityResult:
    ip: str
    state: str
    method: str | None
    checked_at: str | None = None
    failure_class: str = ""


@dataclass(frozen=True)
class AvailabilityRun:
    cidr: str
    started_at: str
    finished_at: str
    status: str
    target_count: int
    completed_target_count: int
    results: tuple[AvailabilityResult, ...]
    error_class: str = ""

    @classmethod
    def success(cls, cidr: str, *, started: str, finished: str, results: list[AvailabilityResult], target_count: int | None = None) -> AvailabilityRun:
        completed_target_count = len(results)
        return cls(cidr, started, finished, "success", completed_target_count if target_count is None else target_count, completed_target_count, tuple(results))

    @classmethod
    def failed(cls, cidr: str, *, started: str, error_class: str, finished: str | None = None, target_count: int = 0, completed_target_count: int = 0) -> AvailabilityRun:
        return cls(cidr, started, finished or started, "failed", target_count, completed_target_count, (), error_class)


def _utc_timestamp(value: str, *, field: str) -> str:
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{field} must be a UTC timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != UTC.utcoffset(parsed):
        raise ValueError(f"{field} must be a UTC timestamp")
    return parsed.astimezone(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _sanitize_reason(value: str) -> str:
    return " ".join(value.split())[:200]


def _active_context_revision_for_cidr(conn: sqlite3.Connection, cidr: str) -> tuple[int, str, ipaddress.IPv4Network | ipaddress.IPv6Network]:
    try:
        network = ipaddress.ip_network(cidr, strict=False)
    except ValueError as exc:
        raise ValueError("cidr must be valid") from exc
    normalized = str(network)
    matching_rules = [rule for rule in load_active_availability_segments(conn) if str(rule.network) == normalized]
    if len(matching_rules) != 1:
        raise ValueError("cidr is not an active availability segment")
    row = conn.execute(
        """SELECT heads.context_revision_id
           FROM context_heads AS heads JOIN intent_segments AS segments
             ON segments.context_revision_id = heads.context_revision_id
           WHERE segments.lifecycle = 'active' AND segments.stable_id = ?""",
        (matching_rules[0].segment_id,),
    ).fetchone()
    if row is None:
        raise ValueError("active availability context is unavailable")
    return int(row[0]), normalized, network


def _validate_run(run: AvailabilityRun, network: ipaddress.IPv4Network | ipaddress.IPv6Network) -> tuple[str, str, tuple[AvailabilityResult, ...]]:
    started_at = _utc_timestamp(run.started_at, field="started_at")
    finished_at = _utc_timestamp(run.finished_at, field="finished_at")
    if run.status not in {"success", "failed"}:
        raise ValueError("status must be success or failed")
    if not isinstance(run.target_count, int) or isinstance(run.target_count, bool) or run.target_count < 0:
        raise ValueError("target_count must be non-negative")
    if not isinstance(run.completed_target_count, int) or isinstance(run.completed_target_count, bool) or run.completed_target_count < 0:
        raise ValueError("completed_target_count must be non-negative")
    if run.completed_target_count > run.target_count:
        raise ValueError("completed_target_count must not exceed target_count")
    if run.status == "success" and run.completed_target_count != run.target_count:
        raise ValueError("successful run completed_target_count must equal target_count")
    if run.status == "failed" and run.results:
        raise ValueError("failed run must not contain results")
    if len(run.results) != run.completed_target_count:
        raise ValueError("completed_target_count must equal result count")
    seen_ips: set[str] = set()
    normalized_results: list[AvailabilityResult] = []
    for result in run.results:
        try:
            address = ipaddress.ip_address(result.ip)
        except ValueError as exc:
            raise ValueError("result ip must be valid") from exc
        if address not in network:
            raise ValueError("result ip must belong to cidr")
        ip = str(address)
        if ip in seen_ips:
            raise ValueError("result ips must be unique")
        if result.state not in {"reachable", "unreachable"}:
            raise ValueError("result state must be reachable or unreachable")
        seen_ips.add(ip)
        normalized_results.append(AvailabilityResult(ip, result.state, str(result.method or "") or None, _utc_timestamp(result.checked_at or finished_at, field="checked_at"), _sanitize_reason(result.failure_class)))
    return started_at, finished_at, tuple(normalized_results)


def _current_rows(conn: sqlite3.Connection, cidr: str) -> dict[str, AvailabilityResult]:
    return {
        str(row["ip"]): AvailabilityResult(str(row["ip"]), str(row["active_state"]), str(row["active_method"]) or None, str(row["checked_at"]), str(row["failure_class"]))
        for row in conn.execute("SELECT ip, active_state, active_method, checked_at, failure_class FROM availability_results WHERE cidr = ? ORDER BY ip", (cidr,))
    }


def _insert_change_event(conn: sqlite3.Connection, *, run_id: int, ip: str, old: AvailabilityResult | None, new: AvailabilityResult | None, observed_at: str) -> None:
    reason = "initial result" if old is None else "result removed" if new is None else "availability changed"
    conn.execute(
        """INSERT INTO availability_result_events
           (run_id, ip, old_active_state, new_active_state, old_active_method, new_active_method, observed_at, reason)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (run_id, ip, old.state if old else "", new.state if new else "", old.method if old and old.method else "", new.method if new and new.method else "", observed_at, _sanitize_reason(reason)),
    )


def _active_result_changed(old: AvailabilityResult | None, new: AvailabilityResult | None) -> bool:
    if old is None or new is None:
        return old is not new
    return (old.state, old.method, old.failure_class) != (new.state, new.method, new.failure_class)


def save_availability_run(conn: sqlite3.Connection, run: AvailabilityRun) -> int:
    """Persist one completed run and atomically publish only complete successful CIDR results."""
    revision_id, cidr, network = _active_context_revision_for_cidr(conn, run.cidr)
    started_at, finished_at, results = _validate_run(run, network)
    conn.execute("BEGIN IMMEDIATE")
    try:
        run_id = int(conn.execute(
            """INSERT INTO availability_runs
               (context_revision_id, cidr, started_at, finished_at, status, target_count, completed_target_count, error_class)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (revision_id, cidr, started_at, finished_at, run.status, run.target_count, run.completed_target_count, _sanitize_reason(run.error_class)),
        ).lastrowid)
        if run.status == "success":
            old_rows = _current_rows(conn, cidr)
            new_rows = {result.ip: result for result in results}
            for ip in sorted(set(old_rows) | set(new_rows)):
                old, new = old_rows.get(ip), new_rows.get(ip)
                if _active_result_changed(old, new):
                    _insert_change_event(conn, run_id=run_id, ip=ip, old=old, new=new, observed_at=finished_at)
            conn.execute("DELETE FROM availability_results WHERE cidr = ?", (cidr,))
            conn.executemany(
                """INSERT INTO availability_results
                   (cidr, ip, run_id, active_state, active_method, checked_at, failure_class)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                [(cidr, result.ip, run_id, result.state, result.method or "", result.checked_at, result.failure_class) for result in results],
            )
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    return run_id


def current_availability_results(conn: sqlite3.Connection, cidr: str) -> dict[str, AvailabilityResult]:
    """Return the complete current result set stored for one canonical CIDR."""
    try:
        normalized = str(ipaddress.ip_network(cidr, strict=False))
    except ValueError as exc:
        raise ValueError("cidr must be valid") from exc
    return _current_rows(conn, normalized)
