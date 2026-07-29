from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
import errno
import ipaddress
import sqlite3
import socket
import subprocess
import time
from collections.abc import Callable
from typing import Any

from .context_classifier import load_active_availability_segments
from .normalizer import normalize_mac


COLLECTOR_INTERVAL = timedelta(minutes=5)
AVAILABILITY_INTERVAL = timedelta(minutes=5)
PASSIVE_EVIDENCE_FRESHNESS = COLLECTOR_INTERVAL * 2
AVAILABILITY_FRESHNESS = AVAILABILITY_INTERVAL * 2
TARGET_NEGATIVE_CONNECT_ERRNOS = frozenset(
    {
        errno.ECONNREFUSED,
        errno.ETIMEDOUT,
        errno.EHOSTUNREACH,
    }
)


@dataclass(frozen=True)
class AvailabilityResult:
    ip: str
    state: str
    method: str | None
    checked_at: str | None = None
    failure_class: str = ""

    @property
    def active_state(self) -> str:
        return self.state

    @property
    def active_method(self) -> str | None:
        return self.method


@dataclass(frozen=True)
class ProbeTarget:
    ip: str
    tcp_ports: tuple[int, ...]
    cidr: str


@dataclass(frozen=True)
class ProbeExecutor:
    ping: Callable[[str], bool]
    connect: Callable[[str, int], bool]
    now: Callable[[], float]


@dataclass(frozen=True)
class AvailabilityCollection:
    status: str
    runs: tuple[AvailabilityRun, ...]
    summary: dict[str, int]
    error_class: str = ""


class SubprocessPing:
    """One bounded Linux ICMP probe with no shell interpretation."""

    def __call__(self, ip: str) -> bool:
        address = ipaddress.ip_address(ip)
        if address.version != 4:
            raise ValueError("ping target must be IPv4")
        try:
            result = subprocess.run(
                ["ping", "-n", "-c", "1", "-W", "1", str(address)],
                shell=False,
                capture_output=True,
                text=True,
                timeout=2,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError("ping_executor_error") from exc
        if result.returncode == 0:
            return True
        if result.returncode == 1:
            return False
        raise RuntimeError("ping_executor_error")


class SocketConnector:
    """One bounded TCP probe; the successful socket is never retained."""

    def __call__(self, ip: str, port: int) -> bool:
        address = ipaddress.ip_address(ip)
        if address.version != 4:
            raise ValueError("TCP target must be IPv4")
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe_socket:
            probe_socket.settimeout(1)
            try:
                probe_socket.connect((str(address), port))
            except TimeoutError:
                return False
            except OSError as exc:
                if exc.errno in TARGET_NEGATIVE_CONNECT_ERRNOS:
                    return False
                raise
        return True


def default_probe_executor() -> ProbeExecutor:
    return ProbeExecutor(SubprocessPing(), SocketConnector(), time.monotonic)


def expand_targets(segments: tuple[Any, ...]) -> tuple[ProbeTarget, ...]:
    """Expand only canonical IPv4 hosts, assigning overlap to the most-specific rule."""
    ordered = sorted(segments, key=lambda rule: (-rule.network.prefixlen, rule.segment_id))
    targets: dict[str, ProbeTarget] = {}
    for rule in ordered:
        network = rule.network
        if network.version != 4:
            raise ValueError("availability cidr must be IPv4")
        cidr = str(network)
        ports = tuple(rule.availability_tcp_ports)
        for address in network.hosts():
            ip = str(address)
            if ip not in targets:
                targets[ip] = ProbeTarget(ip, ports, cidr)
    return tuple(targets[ip] for ip in sorted(targets, key=lambda value: int(ipaddress.ip_address(value))))


def probe_target(target: ProbeTarget, executor: ProbeExecutor) -> AvailabilityResult:
    """ICMP wins; TCP is only a bounded fallback after ICMP failure."""
    if executor.ping(target.ip):
        return AvailabilityResult(target.ip, "reachable", "icmp")
    for port in target.tcp_ports:
        if executor.connect(target.ip, port):
            return AvailabilityResult(target.ip, "reachable", f"tcp:{port}")
    return AvailabilityResult(target.ip, "unreachable", None, failure_class="unreachable")


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


def _collection_timestamp(now: Callable[[], str | datetime]) -> str:
    value = now()
    if isinstance(value, datetime):
        if value.tzinfo is None:
            raise ValueError("collection clock must be UTC")
        return value.astimezone(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    return str(value)


def _bucket_key(target: ProbeTarget) -> str:
    return str(ipaddress.ip_network(f"{target.ip}/24", strict=False))


def _collect_bucket(
    targets: tuple[ProbeTarget, ...], executor: ProbeExecutor
) -> tuple[tuple[ProbeTarget, AvailabilityResult] | None, str]:
    """Run one /24-equivalent with at most 64 submitted address jobs."""
    futures: dict[Future[AvailabilityResult], ProbeTarget] = {}
    completed: list[tuple[ProbeTarget, AvailabilityResult]] = []
    pool: ThreadPoolExecutor | None = None
    failed = ""
    try:
        deadline = executor.now() + 90
        pending = iter(targets)
        pool = ThreadPoolExecutor(max_workers=64)
        exhausted = False
        while futures or not exhausted:
            while not exhausted and len(futures) < 64 and executor.now() < deadline:
                try:
                    target = next(pending)
                except StopIteration:
                    exhausted = True
                    break
                futures[pool.submit(probe_target, target, executor)] = target
            if not futures:
                if exhausted:
                    break
                failed = "deadline_exceeded"
                break
            timeout = max(0.0, deadline - executor.now())
            done, _ = wait(tuple(futures), timeout=timeout, return_when=FIRST_COMPLETED)
            if not done:
                failed = "deadline_exceeded"
                break
            for future in done:
                target = futures.pop(future)
                try:
                    completed.append((target, future.result()))
                except Exception:
                    failed = "executor_error"
                    break
            if failed:
                break
            if executor.now() >= deadline and (futures or not exhausted):
                failed = "deadline_exceeded"
                break
    except Exception:
        failed = "executor_error"
    finally:
        for future in futures:
            try:
                future.cancel()
            except Exception:
                failed = "executor_error"
        if pool is not None:
            try:
                pool.shutdown(wait=not failed, cancel_futures=True)
            except Exception:
                failed = "executor_error"
    if failed:
        return None, failed
    return tuple(completed), ""


def _failed_collection(
    conn: sqlite3.Connection,
    targets_by_cidr: dict[str, list[ProbeTarget]],
    *,
    started: str,
    finished: str,
    error_class: str,
    total_targets: int | None = None,
) -> AvailabilityCollection:
    runs: list[AvailabilityRun] = []
    for cidr, targets in sorted(targets_by_cidr.items()):
        run = AvailabilityRun.failed(
            cidr, started=started, finished=finished, error_class=error_class,
            target_count=len(targets), completed_target_count=0,
        )
        try:
            save_availability_run(conn, run)
        except (sqlite3.Error, ValueError):
            # Context validity is the persistence boundary; never invent a fallback CIDR.
            continue
        runs.append(run)
    return AvailabilityCollection(
        "failed", tuple(runs),
        {"targets": total_targets if total_targets is not None else sum(len(items) for items in targets_by_cidr.values()), "completed": 0, "reachable": 0, "unreachable": 0},
        error_class,
    )


def collect_availability(
    conn: sqlite3.Connection,
    executor: ProbeExecutor,
    *,
    now: Callable[[], str | datetime],
) -> AvailabilityCollection:
    """Collect canonical availability atomically: incomplete probes never publish current state."""
    try:
        segments = load_active_availability_segments(conn)
        if not segments:
            return AvailabilityCollection("failed", (), {"targets": 0, "completed": 0, "reachable": 0, "unreachable": 0}, "context_unavailable")
    except (sqlite3.Error, ValueError):
        return AvailabilityCollection("failed", (), {"targets": 0, "completed": 0, "reachable": 0, "unreachable": 0}, "context_unavailable")
    return _collect_availability_segments(conn, executor, now=now, segments=segments)


def _collect_availability_segments(
    conn: sqlite3.Connection,
    executor: ProbeExecutor,
    *,
    now: Callable[[], str | datetime],
    segments: tuple[Any, ...],
) -> AvailabilityCollection:
    """Collect exactly the already-authorized effective segment rules."""
    started = _collection_timestamp(now)
    try:
        targets = expand_targets(segments)
    except ValueError:
        return AvailabilityCollection(
            "failed",
            (),
            {"targets": 0, "completed": 0, "reachable": 0, "unreachable": 0},
            "context_unavailable",
        )

    targets_by_cidr: dict[str, list[ProbeTarget]] = {str(segment.network): [] for segment in segments}
    for target in targets:
        targets_by_cidr[target.cidr].append(target)
    buckets: dict[str, list[ProbeTarget]] = {}
    for target in targets:
        buckets.setdefault(_bucket_key(target), []).append(target)
    completed: list[tuple[ProbeTarget, AvailabilityResult]] = []
    error_class = ""
    failed_cidrs: set[str] = set()
    for key in sorted(buckets, key=lambda value: int(ipaddress.ip_network(value).network_address)):
        bucket_results, error_class = _collect_bucket(tuple(buckets[key]), executor)
        if error_class:
            failed_cidrs = {target.cidr for target in buckets[key]}
            break
        assert bucket_results is not None
        completed.extend(bucket_results)
    finished = _collection_timestamp(now)
    if error_class:
        return _failed_collection(
            conn,
            {cidr: targets_by_cidr[cidr] for cidr in failed_cidrs},
            started=started,
            finished=finished,
            error_class=error_class,
            total_targets=len(targets),
        )

    results_by_cidr: dict[str, list[AvailabilityResult]] = {cidr: [] for cidr in targets_by_cidr}
    for target, result in completed:
        results_by_cidr[target.cidr].append(result)
    runs = [
        AvailabilityRun.success(
            cidr, started=started, finished=finished, results=sorted(results, key=lambda item: int(ipaddress.ip_address(item.ip))),
            target_count=len(targets_by_cidr[cidr]),
        )
        for cidr, results in sorted(results_by_cidr.items())
    ]
    try:
        save_availability_runs(conn, tuple(runs))
    except (sqlite3.Error, ValueError):
        return _failed_collection(
            conn, targets_by_cidr, started=started, finished=finished, error_class="context_unavailable",
        )
    reachable = sum(result.state == "reachable" for _, result in completed)
    return AvailabilityCollection(
        "success", tuple(runs),
        {"targets": len(targets), "completed": len(completed), "reachable": reachable, "unreachable": len(completed) - reachable},
    )


def collect_due_availability(
    conn: sqlite3.Connection,
    executor: ProbeExecutor,
    *,
    now: Callable[[], str | datetime],
) -> AvailabilityCollection:
    """Collect only enabled canonical segments whose configured interval has elapsed."""
    checked_at = _collection_timestamp(now)
    timestamp = _as_utc(checked_at)
    if timestamp is None:
        return AvailabilityCollection(
            "failed",
            (),
            {"targets": 0, "completed": 0},
            "context_unavailable",
        )
    try:
        segments = load_active_availability_segments(conn)
    except (sqlite3.Error, ValueError):
        return AvailabilityCollection(
            "failed",
            (),
            {"targets": 0, "completed": 0},
            "context_unavailable",
        )
    if not segments:
        try:
            from .context_classifier import load_active_segment_rules

            if not load_active_segment_rules(conn):
                return AvailabilityCollection(
                    "failed",
                    (),
                    {"targets": 0, "completed": 0},
                    "context_unavailable",
                )
        except (sqlite3.Error, ValueError):
            return AvailabilityCollection(
                "failed",
                (),
                {"targets": 0, "completed": 0},
                "context_unavailable",
            )
    due: list[Any] = []
    for rule in segments:
        row = conn.execute(
            """SELECT finished_at
               FROM availability_runs
               WHERE cidr = ? AND status = 'success'
                 AND completed_target_count = target_count
               ORDER BY finished_at DESC, id DESC
               LIMIT 1""",
            (str(rule.network),),
        ).fetchone()
        latest = _as_utc(str(row["finished_at"])) if row is not None else None
        interval = timedelta(minutes=rule.availability_interval_minutes)
        if latest is None or timestamp - latest >= interval:
            due.append(rule)
    if not due:
        return AvailabilityCollection(
            "success",
            (),
            {"targets": 0, "completed": 0},
        )
    return _collect_availability_segments(
        conn,
        executor,
        now=lambda: checked_at,
        segments=tuple(due),
    )


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


def _active_context_revision_for_cidr(conn: sqlite3.Connection, cidr: str) -> tuple[int, str, ipaddress.IPv4Network]:
    try:
        network = ipaddress.ip_network(cidr, strict=False)
    except ValueError as exc:
        raise ValueError("cidr must be valid") from exc
    if network.version != 4:
        raise ValueError("availability cidr must be IPv4")
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


def _validate_run(run: AvailabilityRun, network: ipaddress.IPv4Network) -> tuple[str, str, tuple[AvailabilityResult, ...]]:
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
    return (old.state, old.method) != (new.state, new.method)


def _validated_run(
    conn: sqlite3.Connection, run: AvailabilityRun
) -> tuple[AvailabilityRun, int, str, str, str, tuple[AvailabilityResult, ...]]:
    revision_id, cidr, network = _active_context_revision_for_cidr(conn, run.cidr)
    started_at, finished_at, results = _validate_run(run, network)
    return run, revision_id, cidr, started_at, finished_at, results


def _insert_validated_run(
    conn: sqlite3.Connection,
    validated: tuple[AvailabilityRun, int, str, str, str, tuple[AvailabilityResult, ...]],
) -> int:
    run, revision_id, cidr, started_at, finished_at, results = validated
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
    return run_id


def save_availability_runs(conn: sqlite3.Connection, runs: tuple[AvailabilityRun, ...]) -> tuple[int, ...]:
    """Atomically publish all successful CIDR runs from one collection, or none of them."""
    validated = tuple(_validated_run(conn, run) for run in runs)
    conn.execute("BEGIN IMMEDIATE")
    try:
        run_ids = tuple(_insert_validated_run(conn, run) for run in validated)
        conn.commit()
        return run_ids
    except Exception:
        conn.rollback()
        raise


def save_availability_run(conn: sqlite3.Connection, run: AvailabilityRun) -> int:
    """Persist one completed run and atomically publish only complete successful CIDR results."""
    return save_availability_runs(conn, (run,))[0]


def current_availability_results(conn: sqlite3.Connection, cidr: str) -> dict[str, AvailabilityResult]:
    """Return the complete current result set stored for one canonical CIDR."""
    try:
        normalized = str(ipaddress.ip_network(cidr, strict=False))
    except ValueError as exc:
        raise ValueError("cidr must be valid") from exc
    return _current_rows(conn, normalized)


def monitored_rule_for_ip(conn: sqlite3.Connection, ip: str) -> Any | None:
    """Return the one effective monitored rule authorizing a usable IPv4 host."""
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return None
    if address.version != 4:
        return None
    matches = [
        rule
        for rule in load_active_availability_segments(conn)
        if address in rule.network
        and (
            rule.network.prefixlen >= 31
            or address
            not in (rule.network.network_address, rule.network.broadcast_address)
        )
    ]
    if not matches:
        return None
    return sorted(
        matches,
        key=lambda rule: (-rule.network.prefixlen, rule.segment_id),
    )[0]


def save_manual_result(
    conn: sqlite3.Connection,
    *,
    segment_id: str,
    result: AvailabilityResult,
    checked_at: str | datetime,
) -> AvailabilityResult:
    """Append one bounded manual check without touching complete CIDR results."""
    timestamp = _utc_timestamp(
        checked_at.isoformat() if isinstance(checked_at, datetime) else checked_at,
        field="checked_at",
    )
    rule = monitored_rule_for_ip(conn, result.ip)
    if rule is None or rule.segment_id != segment_id:
        raise ValueError("not monitored")
    if result.state not in {"reachable", "unreachable"}:
        raise ValueError("result state must be reachable or unreachable")
    allowed_methods = {"icmp"} | {
        f"tcp:{port}" for port in rule.availability_tcp_ports
    }
    if (
        result.state == "reachable"
        and result.method not in allowed_methods
    ) or (
        result.state == "unreachable"
        and result.method is not None
    ):
        raise ValueError("result method is not allowed by monitored segment")
    normalized = AvailabilityResult(
        str(ipaddress.ip_address(result.ip)),
        result.state,
        str(result.method or "") or None,
        timestamp,
        _sanitize_reason(result.failure_class),
    )
    conn.execute(
        """INSERT INTO availability_manual_results
           (segment_id, ip, requested_at, checked_at, active_state,
            active_method, failure_class)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (
            segment_id,
            normalized.ip,
            timestamp,
            timestamp,
            normalized.state,
            normalized.method or "",
            normalized.failure_class,
        ),
    )
    conn.commit()
    return normalized


def probe_one_availability(
    conn: sqlite3.Connection,
    ip: str,
    executor: ProbeExecutor,
    now: str | datetime,
) -> AvailabilityResult:
    """Probe one usable host authorized by its effective canonical segment rule."""
    rule = monitored_rule_for_ip(conn, ip)
    if rule is None:
        raise ValueError("not monitored")
    normalized_ip = str(ipaddress.ip_address(ip))
    result = probe_target(
        ProbeTarget(
            normalized_ip,
            tuple(rule.availability_tcp_ports),
            str(rule.network),
        ),
        executor,
    )
    return save_manual_result(
        conn,
        segment_id=rule.segment_id,
        result=result,
        checked_at=now,
    )


def _as_utc(value: str | datetime) -> datetime | None:
    try:
        if isinstance(value, datetime):
            parsed = value
        else:
            parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(UTC)


def _fresh_at(value: Any, *, now: datetime, budget: timedelta) -> bool:
    observed = _as_utc(str(value or ""))
    return observed is not None and timedelta(0) <= now - observed <= budget


def _availability_cidr(conn: sqlite3.Connection, ip: str) -> str | None:
    rule = monitored_rule_for_ip(conn, ip)
    return str(rule.network) if rule is not None else None


def _passive_evidence(conn: sqlite3.Connection, *, ip: str, mac: str | None, now: datetime) -> list[str]:
    if not mac:
        return []
    evidence: list[str] = []
    for row in conn.execute(
        """SELECT entries.mac, entries.complete, entries.last_seen_at,
                  sources.enabled AS source_enabled, sources.last_status AS source_status,
                  sources.last_collect_at AS source_collected_at
           FROM arp_entries AS entries
           JOIN network_sources AS sources ON sources.id = entries.source_id
           WHERE entries.ip = ?""",
        (ip,),
    ):
        if (
            bool(row["complete"])
            and normalize_mac(row["mac"]) == mac
            and _healthy_passive_source(row, now=now)
            and _fresh_at(row["last_seen_at"], now=now, budget=PASSIVE_EVIDENCE_FRESHNESS)
        ):
            evidence.append("mikrotik_arp")
            break
    for row in conn.execute(
        """SELECT leases.mac, leases.status, leases.last_seen_at,
                  sources.enabled AS source_enabled, sources.last_status AS source_status,
                  sources.last_collect_at AS source_collected_at
           FROM dhcp_leases AS leases
           JOIN network_sources AS sources ON sources.id = leases.source_id
           WHERE leases.ip = ?""",
        (ip,),
    ):
        if (
            str(row["status"] or "").lower() in {"bound", "online"}
            and normalize_mac(row["mac"]) == mac
            and _healthy_passive_source(row, now=now)
            and _fresh_at(row["last_seen_at"], now=now, budget=PASSIVE_EVIDENCE_FRESHNESS)
        ):
            evidence.append("mikrotik_dhcp")
            break
    for row in conn.execute(
        """SELECT hosts.mac, hosts.last_seen_at,
                  sources.enabled AS source_enabled, sources.last_status AS source_status,
                  sources.last_collect_at AS source_collected_at
           FROM bridge_hosts AS hosts
           JOIN network_sources AS sources ON sources.id = hosts.source_id"""
    ):
        if (
            normalize_mac(row["mac"]) == mac
            and _healthy_passive_source(row, now=now)
            and _fresh_at(row["last_seen_at"], now=now, budget=PASSIVE_EVIDENCE_FRESHNESS)
        ):
            evidence.append("mikrotik_bridge")
            break
    for row in conn.execute(
        """SELECT f.mac, f.last_seen_at,
                  sources.enabled AS source_enabled, sources.last_status AS source_status,
                  sources.last_collect_at AS source_collected_at
           FROM current_switch_fdb AS f
           JOIN switch_collection_runs AS runs
             ON runs.id = f.collector_run_id AND runs.source_id = f.source_id
           JOIN network_sources AS sources ON sources.id = f.source_id
           WHERE runs.status = 'success' AND lower(f.status) NOT IN ('self', 'mgmt')"""
    ):
        if (
            normalize_mac(row["mac"]) == mac
            and _healthy_passive_source(row, now=now)
            and _fresh_at(row["last_seen_at"], now=now, budget=PASSIVE_EVIDENCE_FRESHNESS)
        ):
            evidence.append("snmp_fdb")
            break
    return evidence


def _healthy_passive_source(row: sqlite3.Row, *, now: datetime) -> bool:
    return (
        bool(row["source_enabled"])
        and str(row["source_status"] or "") in {"ok", "success"}
        and _fresh_at(
            row["source_collected_at"],
            now=now,
            budget=PASSIVE_EVIDENCE_FRESHNESS,
        )
    )


def _availability_payload(
    *,
    state: str,
    cidr: str | None,
    active_method: str | None,
    checked_at: str | None,
    run_status: str,
    passive_evidence: list[str],
    reason: str,
    check_origin: str = "",
) -> dict[str, Any]:
    return {
        "state": state,
        "active_method": active_method,
        "checked_at": checked_at,
        "run_status": run_status,
        "cidr": cidr,
        "passive_evidence": passive_evidence,
        "reason": reason,
        "check_origin": check_origin,
    }


def project_host_availability(conn: sqlite3.Connection, host: dict[str, Any], *, now: str | datetime) -> dict[str, Any]:
    """Derive the public host status from current active and passive evidence."""
    projected = dict(host)
    rule = monitored_rule_for_ip(conn, str(host["ip"]))
    if bool(host.get("openvpn_connected")):
        projected["status"] = "connected"
        projected["availability"] = (
            _availability_payload(
                state="connected", cidr=str(rule.network), active_method=None, checked_at=None,
                run_status="", passive_evidence=[], reason="openvpn_management",
            )
            if rule is not None else None
        )
        return projected
    timestamp = _as_utc(now)
    if timestamp is None:
        raise ValueError("now must be a UTC timestamp")
    evidence = _passive_evidence(
        conn,
        ip=str(host["ip"]),
        mac=normalize_mac(host.get("mac")),
        now=timestamp,
    )
    if rule is None:
        projected["status"] = "seen" if evidence else "stale"
        projected["availability"] = _availability_payload(
            state="not_monitored",
            cidr=None,
            active_method=None,
            checked_at=None,
            run_status="",
            passive_evidence=evidence,
            reason="not_monitored",
        )
        return projected

    cidr = str(rule.network)
    freshness = timedelta(minutes=rule.availability_interval_minutes * 2)
    manual = conn.execute(
        """SELECT active_state, active_method, checked_at
           FROM availability_manual_results
           WHERE segment_id = ? AND ip = ?
           ORDER BY checked_at DESC, id DESC
           LIMIT 1""",
        (rule.segment_id, str(host["ip"])),
    ).fetchone()
    if manual is not None and _fresh_at(
        manual["checked_at"],
        now=timestamp,
        budget=freshness,
    ):
        reason = ""
        result = manual
        run_status = "success"
        checked_at = str(manual["checked_at"])
        check_origin = "manual"
    else:
        result = None
        run_status = ""
        checked_at = None
        check_origin = "scheduled"
        reason = ""
    run = conn.execute(
        """SELECT id, status, finished_at, error_class FROM availability_runs
           WHERE cidr = ? ORDER BY finished_at DESC, id DESC LIMIT 1""",
        (cidr,),
        ).fetchone()
    if result is None:
        if run is None:
            reason = "missing_run"
        elif str(run["status"]) != "success":
            reason = "run_failed"
        elif not _fresh_at(run["finished_at"], now=timestamp, budget=freshness):
            reason = "run_stale"
        else:
            result = conn.execute(
                """SELECT active_state, active_method, checked_at
                   FROM availability_results
                   WHERE cidr = ? AND ip = ? AND run_id = ?""",
                (cidr, host["ip"], int(run["id"])),
            ).fetchone()
            reason = "missing_result" if result is None else ""
        run_status = str(run["status"]) if run is not None else ""
        checked_at = (
            str(result["checked_at"])
            if result is not None
            else (str(run["finished_at"]) if run is not None else None)
        )
    if result is not None and str(result["active_state"]) == "reachable":
        projected["status"] = "online"
        projected["availability"] = _availability_payload(
            state="online", cidr=cidr, active_method=str(result["active_method"]) or None,
            checked_at=checked_at, run_status=run_status, passive_evidence=[], reason="active_probe",
            check_origin=check_origin,
        )
        return projected
    if reason:
        projected["status"] = "stale"
        projected["availability"] = _availability_payload(
            state="stale", cidr=cidr, active_method=None, checked_at=checked_at,
            run_status=run_status, passive_evidence=[], reason=reason,
            check_origin=check_origin,
        )
        return projected
    if evidence:
        projected["status"] = "seen"
        projected["availability"] = _availability_payload(
            state="seen", cidr=cidr, active_method=None, checked_at=checked_at,
            run_status=run_status, passive_evidence=evidence, reason="passive_evidence",
            check_origin=check_origin,
        )
        return projected
    projected["status"] = "offline"
    projected["availability"] = _availability_payload(
        state="offline", cidr=cidr, active_method=None, checked_at=checked_at,
        run_status=run_status, passive_evidence=[], reason="active_negative_no_passive_evidence",
        check_origin=check_origin,
    )
    return projected
