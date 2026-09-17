from __future__ import annotations

import logging
from collections.abc import Callable, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Iterator

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ..db import init_inventory_identifier_sync_schema, session_scope
from ..netctl_client import NetctlError, run_netctl
from .models import InventoryIdentifierSyncRun
from .service import InventoryService


log = logging.getLogger(__name__)

NetctlCall = Callable[[list[str], int | None], Mapping[str, object]]
SessionFactory = Callable[[], Session]


@dataclass(frozen=True)
class NetctlSnapshot:
    snapshot_id: int
    generated_at: datetime
    hosts: Sequence[dict[str, object]]


@dataclass(frozen=True)
class SyncSummary:
    status: str
    snapshot_id: int | None = None
    matched_assets: int = 0
    updated_assets: int = 0
    skipped_assets: int = 0
    failure_reason: str | None = None


class SnapshotReadError(ValueError):
    def __init__(self, reason: str, *, snapshot_id: int | None = None, generated_at: datetime | None = None) -> None:
        super().__init__(reason)
        self.reason = reason
        self.snapshot_id = snapshot_id
        self.generated_at = generated_at


class StaleSnapshot(SnapshotReadError):
    pass


def read_current_snapshot(netctl_call: NetctlCall) -> NetctlSnapshot:
    """Read every page of one fresh published snapshot without triggering collection."""
    page_number = 1
    snapshot_id: int | None = None
    generated_at: datetime | None = None
    pagination_total: int | None = None
    pagination_limit: int | None = None
    pagination_pages: int | None = None
    hosts: list[dict[str, object]] = []

    while True:
        try:
            payload = netctl_call(
                ["hosts", "list", "--status=current", "--page", str(page_number), "--limit", "250"],
                timeout=60,
            )
        except NetctlError as exc:
            raise SnapshotReadError("netctl snapshot unavailable") from exc
        except Exception as exc:
            raise SnapshotReadError("netctl snapshot unavailable") from exc

        page_snapshot_id, page_generated_at, stale, page, total, limit, pages, page_hosts = _parse_page(payload)
        if stale:
            raise StaleSnapshot(
                "stale netctl snapshot",
                snapshot_id=page_snapshot_id,
                generated_at=page_generated_at,
            )
        if snapshot_id is None:
            snapshot_id = page_snapshot_id
            generated_at = page_generated_at
            pagination_total = total
            pagination_limit = limit
            pagination_pages = pages
        elif (
            snapshot_id != page_snapshot_id
            or generated_at != page_generated_at
            or pagination_total != total
            or pagination_limit != limit
            or pagination_pages != pages
        ):
            raise SnapshotReadError(
                "netctl snapshot changed during pagination",
                snapshot_id=snapshot_id,
                generated_at=generated_at,
            )
        if page != page_number:
            raise SnapshotReadError(
                "malformed netctl snapshot",
                snapshot_id=snapshot_id,
                generated_at=generated_at,
            )
        if total > 0:
            expected_page_count = limit if page < pages else total - limit * (pages - 1)
            if len(page_hosts) != expected_page_count:
                raise SnapshotReadError(
                    "malformed netctl snapshot",
                    snapshot_id=snapshot_id,
                    generated_at=generated_at,
                )
        hosts.extend(page_hosts)
        if page >= pages:
            if len(hosts) != total:
                raise SnapshotReadError(
                    "malformed netctl snapshot",
                    snapshot_id=snapshot_id,
                    generated_at=generated_at,
                )
            return NetctlSnapshot(snapshot_id=snapshot_id, generated_at=generated_at, hosts=tuple(hosts))
        page_number += 1


def synchronize_current_snapshot(
    *,
    netctl_call: NetctlCall = run_netctl,
    session_factory: SessionFactory | None = None,
) -> SyncSummary:
    """Record and reconcile one immutable Netctl snapshot, preserving failure visibility."""
    try:
        snapshot = read_current_snapshot(netctl_call)
    except StaleSnapshot as exc:
        summary = _record_terminal_run(
            "skipped",
            session_factory=session_factory,
            snapshot_id=exc.snapshot_id,
            generated_at=exc.generated_at,
            failure_reason=exc.reason,
        )
        _log_summary(summary)
        return summary
    except SnapshotReadError as exc:
        summary = _record_terminal_run(
            "failed",
            session_factory=session_factory,
            snapshot_id=exc.snapshot_id,
            generated_at=exc.generated_at,
            failure_reason=exc.reason,
        )
        _log_summary(summary)
        return summary

    try:
        with _transaction(session_factory) as db:
            existing = db.scalar(
                select(InventoryIdentifierSyncRun).where(
                    InventoryIdentifierSyncRun.snapshot_id == snapshot.snapshot_id,
                    InventoryIdentifierSyncRun.status == "success",
                )
            )
            latest_successful_at = db.scalar(
                select(InventoryIdentifierSyncRun.snapshot_generated_at)
                .where(
                    InventoryIdentifierSyncRun.status == "success",
                    InventoryIdentifierSyncRun.snapshot_generated_at.is_not(None),
                )
                .order_by(InventoryIdentifierSyncRun.snapshot_generated_at.desc())
                .limit(1)
            )
            if latest_successful_at is not None and latest_successful_at.tzinfo is None:
                latest_successful_at = latest_successful_at.replace(tzinfo=timezone.utc)
            if existing is not None or (
                latest_successful_at is not None and snapshot.generated_at <= latest_successful_at
            ):
                failure_reason = (
                    "snapshot already synchronized"
                    if existing is not None
                    else "snapshot is not newer than successful run"
                )
                _add_run(
                    db,
                    status="skipped",
                    snapshot_id=snapshot.snapshot_id,
                    generated_at=snapshot.generated_at,
                    failure_reason=failure_reason,
                )
                summary = SyncSummary(
                    status="skipped",
                    snapshot_id=snapshot.snapshot_id,
                    failure_reason=failure_reason,
                )
            else:
                result = InventoryService().reconcile_netctl_identifiers(
                    db,
                    snapshot.hosts,
                    observed_at=snapshot.generated_at,
                )
                _add_run(
                    db,
                    status="success",
                    snapshot_id=snapshot.snapshot_id,
                    generated_at=snapshot.generated_at,
                    matched_assets=result.matched_assets,
                    updated_assets=result.updated_assets,
                    skipped_assets=result.skipped_assets,
                )
                summary = SyncSummary(
                    status="success",
                    snapshot_id=snapshot.snapshot_id,
                    matched_assets=result.matched_assets,
                    updated_assets=result.updated_assets,
                    skipped_assets=result.skipped_assets,
                )
    except IntegrityError:
        summary = _record_terminal_run(
            "failed",
            session_factory=session_factory,
            snapshot_id=snapshot.snapshot_id,
            generated_at=snapshot.generated_at,
            failure_reason="database synchronization conflict",
        )
    except Exception:
        summary = _record_terminal_run(
            "failed",
            session_factory=session_factory,
            snapshot_id=snapshot.snapshot_id,
            generated_at=snapshot.generated_at,
            failure_reason="database synchronization failed",
        )
    _log_summary(summary)
    return summary


def main(argv: Sequence[str] | None = None) -> int:
    """Run the inventory snapshot synchronizer as a one-shot service command."""
    del argv
    logging.basicConfig(level=logging.INFO)
    try:
        init_inventory_identifier_sync_schema()
        summary = synchronize_current_snapshot()
    except Exception:
        log.error(
            "inventory.netctl_sync outcome=failed snapshot_id=- matched_assets=0 updated_assets=0 "
            "skipped_assets=0 failure_reason=worker schema unavailable"
        )
        return 1
    return 0 if summary.status in {"success", "skipped"} else 1


def _parse_page(payload: Mapping[str, object]) -> tuple[int, datetime, bool, int, int, int, int, list[dict[str, object]]]:
    if not isinstance(payload, Mapping):
        raise SnapshotReadError("malformed netctl snapshot")
    snapshot = payload.get("snapshot")
    pagination = payload.get("pagination")
    hosts = payload.get("hosts")
    if not isinstance(snapshot, Mapping) or not isinstance(pagination, Mapping) or not isinstance(hosts, list):
        raise SnapshotReadError("malformed netctl snapshot")
    snapshot_id = snapshot.get("snapshot_id")
    generated_at = _parse_generated_at(snapshot.get("generated_at"))
    stale = snapshot.get("stale")
    page = pagination.get("page")
    total = pagination.get("total")
    limit = pagination.get("limit")
    pages = pagination.get("pages")
    if (
        not _is_positive_int(snapshot_id)
        or not isinstance(stale, bool)
        or not _is_positive_int(page)
        or not _is_nonnegative_int(total)
        or not _is_positive_int(limit)
        or not _is_nonnegative_int(pages)
        or not all(isinstance(host, Mapping) for host in hosts)
    ):
        raise SnapshotReadError("malformed netctl snapshot")
    if pages != (total + limit - 1) // limit:
        raise SnapshotReadError("malformed netctl snapshot")
    if total == 0:
        if page != 1 or pages != 0 or hosts:
            raise SnapshotReadError("malformed netctl snapshot")
    elif page > pages:
        raise SnapshotReadError("malformed netctl snapshot")
    return snapshot_id, generated_at, stale, page, total, limit, pages, [dict(host) for host in hosts]


def _parse_generated_at(value: object) -> datetime:
    if not isinstance(value, str) or not value:
        raise SnapshotReadError("malformed netctl snapshot")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise SnapshotReadError("malformed netctl snapshot") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise SnapshotReadError("malformed netctl snapshot")
    return parsed.astimezone(timezone.utc)


def _is_positive_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 1


def _is_nonnegative_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


@contextmanager
def _transaction(session_factory: SessionFactory | None) -> Iterator[Session]:
    if session_factory is None:
        with session_scope() as db:
            yield db
        return
    db = session_factory()
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise


def _record_terminal_run(
    status: str,
    *,
    session_factory: SessionFactory | None,
    snapshot_id: int | None,
    generated_at: datetime | None,
    failure_reason: str,
) -> SyncSummary:
    try:
        with _transaction(session_factory) as db:
            _add_run(
                db,
                status=status,
                snapshot_id=snapshot_id,
                generated_at=generated_at,
                failure_reason=failure_reason,
            )
    except Exception:
        pass
    return SyncSummary(status=status, snapshot_id=snapshot_id, failure_reason=failure_reason)


def _add_run(
    db: Session,
    *,
    status: str,
    snapshot_id: int | None,
    generated_at: datetime | None,
    matched_assets: int = 0,
    updated_assets: int = 0,
    skipped_assets: int = 0,
    failure_reason: str | None = None,
) -> None:
    now = datetime.now(timezone.utc)
    db.add(
        InventoryIdentifierSyncRun(
            snapshot_id=snapshot_id,
            snapshot_generated_at=generated_at,
            status=status,
            started_at=now,
            finished_at=now,
            matched_assets=matched_assets,
            updated_assets=updated_assets,
            skipped_assets=skipped_assets,
            failure_reason=failure_reason,
        )
    )
    db.flush()


def _log_summary(summary: SyncSummary) -> None:
    snapshot_id = summary.snapshot_id if summary.snapshot_id is not None else "-"
    failure_reason = _sanitize_failure_reason(summary.failure_reason)
    log.info(
        "inventory.netctl_sync outcome=%s snapshot_id=%s matched_assets=%d updated_assets=%d skipped_assets=%d failure_reason=%s",
        summary.status,
        snapshot_id,
        summary.matched_assets,
        summary.updated_assets,
        summary.skipped_assets,
        failure_reason,
    )


def _sanitize_failure_reason(reason: str | None) -> str:
    allowed = {
        "stale netctl snapshot",
        "netctl snapshot unavailable",
        "netctl snapshot changed during pagination",
        "malformed netctl snapshot",
        "snapshot already synchronized",
        "snapshot is not newer than successful run",
        "database synchronization conflict",
        "database synchronization failed",
    }
    if reason is None:
        return "-"
    return reason if reason in allowed else "unspecified failure"


if __name__ == "__main__":
    raise SystemExit(main())
