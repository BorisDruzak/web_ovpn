from __future__ import annotations

import json
import re
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from typing import Any, Protocol

from .snmp.models import (
    CapabilityResult,
    SwitchCounterSample,
    SwitchFdbEntry,
    SwitchPort,
    SwitchSnapshot,
    SwitchSystem,
    SnmpVarBind,
)
from .snmp.outcomes import SnmpOutcome


_REPLACING_FDB_OUTCOMES = {
    SnmpOutcome.SUCCESS_WITH_ROWS,
    SnmpOutcome.SUCCESS_EMPTY,
}
_VLAN_CAPABILITIES = (
    "vlan_current_egress",
    "vlan_current_untagged",
    "pvid",
)
_LLDP_CAPABILITIES = ("lldp_remote",)
_VLAN_MEMBERSHIP_FIELDS = frozenset(
    {
        "vlan_id",
        "port_key",
        "if_index",
        "bridge_port",
        "physical_port",
        "port_name",
        "egress",
        "untagged",
        "pvid",
    }
)
_EMPTY_COUNTS = {
    "ports": 0,
    "fdb_current": 0,
    "appeared": 0,
    "moved": 0,
    "disappeared": 0,
}
_MAC = re.compile(r"(?:[0-9A-F]{2}:){5}[0-9A-F]{2}\Z")
_VLAN_KEY = re.compile(r"(vid|fid):([1-9][0-9]*)\Z")
_FDB_STATUSES = frozenset({"other", "invalid", "learned", "self", "mgmt"})
_SQLITE_INTEGER_MAX = 2**63 - 1


class SwitchDriver(Protocol):
    def collect(self) -> SwitchSnapshot: ...


class SwitchPersistenceError(RuntimeError):
    """A fixed, secret-safe error raised after an atomic store failure."""


def collect_and_save_switch(
    conn: sqlite3.Connection,
    source: dict[str, Any],
    driver: SwitchDriver,
    started_at: str,
) -> dict[str, Any]:
    """Collect and atomically persist one typed switch snapshot.

    Only an explicit, internally consistent successful FDB capability replaces
    ``current_switch_fdb``. Transport failures and malformed snapshots are
    reported with fixed messages and never interpreted as an empty FDB.
    """
    try:
        source_id = _source_id(conn, source)
    except SwitchPersistenceError:
        raise
    except Exception:
        raise SwitchPersistenceError("Switch collection persistence failed") from None
    try:
        started_time = _parse_started_at(started_at)
        capability_ttl_hours = _capability_ttl_hours(source)
    except Exception:
        raise SwitchPersistenceError("Switch collection persistence failed") from None
    try:
        snapshot = driver.collect()
    except Exception:
        return _record_failed_run(
            conn,
            source_id=source_id,
            started_at=started_at,
            error_class="collection_error",
            error_message="Switch collection failed",
        )

    try:
        validation_error = _validate_snapshot(snapshot)
        if not validation_error:
            assert isinstance(snapshot, SwitchSnapshot)
            fdb_capability = next(
                capability
                for capability in snapshot.capabilities
                if capability.capability == "fdb"
            )
            fdb_outcome = fdb_capability.outcome.value
    except Exception:
        validation_error = "invalid_snapshot"
    if validation_error:
        return _invalid_snapshot_result(
            conn,
            source_id=source_id,
        )

    assert isinstance(snapshot, SwitchSnapshot)
    try:
        with _atomic(conn):
            run_id = _create_run(
                conn,
                source_id=source_id,
                started_at=started_at,
                profile_id=snapshot.profile_id,
                sys_uptime_ticks=snapshot.system.sys_uptime_ticks,
            )
            outcome = fdb_capability.outcome
            outcomes = {
                capability.capability: capability.outcome.value
                for capability in snapshot.capabilities
            }
            if outcome not in _REPLACING_FDB_OUTCOMES:
                counts = dict(_EMPTY_COUNTS)
                counts["fdb_current"] = _current_fdb_count(conn, source_id)
                status = "failed"
                error_class = "fdb_unavailable"
                error_message = "Switch FDB collection was not successful"
            elif _has_newer_or_equal_success(
                conn,
                source_id=source_id,
                started_time=started_time,
                exclude_run_id=run_id,
            ):
                counts = dict(_EMPTY_COUNTS)
                counts["fdb_current"] = _current_fdb_count(conn, source_id)
                status = "failed"
                error_class = "stale_snapshot"
                error_message = "Switch snapshot is not newer than current state"
            else:
                _upsert_device(conn, source_id, snapshot, started_at)
                _upsert_ports(conn, source_id, run_id, snapshot.ports, started_at)
                _upsert_capabilities(
                    conn,
                    source_id,
                    snapshot,
                    checked_at=started_at,
                    capability_ttl_hours=capability_ttl_hours,
                )
                counts = _replace_fdb(
                    conn,
                    source_id=source_id,
                    run_id=run_id,
                    entries=snapshot.fdb,
                    observed_at=started_at,
                )
                _replace_optional_current_state(
                    conn,
                    source_id=source_id,
                    run_id=run_id,
                    snapshot=snapshot,
                    observed_at=started_at,
                )
                status = "success"
                error_class = ""
                error_message = ""
                counts["ports"] = len(snapshot.ports)
            _finish_run(
                conn,
                run_id=run_id,
                source_id=source_id,
                finished_at=started_at,
                status=status,
                error_class=error_class,
                error_message=error_message,
                outcomes=outcomes,
                counts=counts,
            )
    except Exception:
        raise SwitchPersistenceError("Switch collection persistence failed") from None

    return _result(
        run_id=run_id,
        source_id=source_id,
        status=status,
        fdb_outcome=fdb_outcome,
        counts=counts,
        error_class=error_class,
        error_message=error_message,
    )


def _source_id(conn: sqlite3.Connection, source: dict[str, Any]) -> int:
    value = source.get("id")
    if (
        type(value) is not int
        or value < 1
        or value > _SQLITE_INTEGER_MAX
    ):
        raise SwitchPersistenceError("Switch collection source is invalid")
    try:
        row = conn.execute(
            "SELECT driver FROM network_sources WHERE id = ?", (value,)
        ).fetchone()
    except sqlite3.Error:
        raise SwitchPersistenceError("Switch collection persistence failed") from None
    if row is None or str(row[0]) != "snmp_switch":
        raise SwitchPersistenceError("Switch collection source is invalid")
    return value


def _validate_snapshot(snapshot: object) -> str:
    if type(snapshot) is not SwitchSnapshot:
        return "invalid_type"
    if type(snapshot.snapshot_kind) is not str or snapshot.snapshot_kind != "snmp_switch":
        return "invalid_kind"
    if type(snapshot.system) is not SwitchSystem or not _valid_system(
        snapshot.system
    ):
        return "invalid_system"
    if not _valid_text(snapshot.profile_id) or not _valid_text(
        snapshot.profile_fingerprint
    ):
        return "invalid_profile"
    if type(snapshot.ports) is not tuple or not all(
        type(port) is SwitchPort and _valid_port(port)
        for port in snapshot.ports
    ):
        return "invalid_ports"
    if type(snapshot.fdb) is not tuple or not all(
        type(entry) is SwitchFdbEntry and _valid_fdb_entry(entry)
        for entry in snapshot.fdb
    ):
        return "invalid_fdb"
    if type(snapshot.capabilities) is not tuple or not all(
        type(capability) is CapabilityResult and _valid_capability(capability)
        for capability in snapshot.capabilities
    ):
        return "invalid_capabilities"
    if type(snapshot.vlan_memberships) is not tuple:
        return "invalid_vlan_memberships"
    if snapshot.stp is not None and type(snapshot.stp) is not dict:
        return "invalid_stp"
    if type(snapshot.lldp_neighbors) is not tuple:
        return "invalid_lldp"
    if type(snapshot.counter_samples) is not tuple or not all(
        type(sample) is SwitchCounterSample and _valid_counter_sample(sample)
        for sample in snapshot.counter_samples
    ):
        return "invalid_counter_samples"

    port_keys = [port.port_key for port in snapshot.ports]
    if any(not _valid_text(key) for key in port_keys) or len(port_keys) != len(
        set(port_keys)
    ):
        return "invalid_ports"

    capability_names = [
        capability.capability for capability in snapshot.capabilities
    ]
    if any(not _valid_text(name) for name in capability_names) or len(
        capability_names
    ) != len(set(capability_names)):
        return "invalid_capabilities"
    if any(
        not isinstance(capability.outcome, SnmpOutcome)
        for capability in snapshot.capabilities
    ):
        return "invalid_capabilities"
    fdb_capabilities = [
        capability
        for capability in snapshot.capabilities
        if capability.capability == "fdb"
    ]
    if len(fdb_capabilities) != 1:
        return "invalid_fdb_outcome"

    fdb_keys: list[tuple[str, str]] = []
    for entry in snapshot.fdb:
        if not all(
            _valid_text(value)
            for value in (entry.vlan_key, entry.mac, entry.port_key)
        ):
            return "invalid_fdb"
        fdb_keys.append((entry.vlan_key, entry.mac))
    if len(fdb_keys) != len(set(fdb_keys)):
        return "duplicate_fdb_key"

    fdb_outcome = fdb_capabilities[0].outcome
    if fdb_outcome is SnmpOutcome.SUCCESS_WITH_ROWS and not snapshot.fdb:
        return "missing_fdb_rows"
    if fdb_outcome is SnmpOutcome.SUCCESS_EMPTY and snapshot.fdb:
        return "unexpected_fdb_rows"
    if fdb_outcome not in _REPLACING_FDB_OUTCOMES and snapshot.fdb:
        return "failed_fdb_has_rows"
    return ""


def _valid_text(value: object) -> bool:
    return type(value) is str and bool(value.strip())


def _valid_system(system: SwitchSystem) -> bool:
    return all(
        type(value) is str
        for value in (
            system.sys_descr,
            system.sys_object_id,
            system.sys_name,
            system.sys_location,
        )
    ) and _valid_optional_int(system.sys_uptime_ticks, minimum=0)


def _valid_port(port: SwitchPort) -> bool:
    return (
        _valid_text(port.port_key)
        and _valid_optional_int(port.if_index, minimum=1, maximum=2_147_483_647)
        and _valid_optional_int(port.bridge_port, minimum=1, maximum=65_535)
        and _valid_optional_int(port.physical_port, minimum=1, maximum=65_535)
        and type(port.name) is str
        and type(port.alias) is str
        and (port.mac is None or _valid_mac(port.mac))
        and _valid_text(port.admin_status)
        and _valid_text(port.oper_status)
        and _valid_optional_int(port.speed_bps, minimum=0)
    )


def _valid_fdb_entry(entry: SwitchFdbEntry) -> bool:
    if not (
        _valid_optional_int(entry.fdb_id, minimum=1, maximum=4_294_967_295)
        and _valid_mac(entry.mac)
        and _valid_text(entry.port_key)
        and _valid_optional_int(entry.bridge_port, minimum=1, maximum=65_535)
        and _valid_optional_int(entry.if_index, minimum=1, maximum=2_147_483_647)
        and _valid_optional_int(entry.physical_port, minimum=1, maximum=65_535)
        and type(entry.port_name) is str
        and type(entry.status) is str
        and entry.status in _FDB_STATUSES
        and type(entry.vlan_key) is str
    ):
        return False
    if entry.vlan_key == "legacy:unknown":
        return entry.fdb_id is None and entry.vlan_id is None
    match = _VLAN_KEY.fullmatch(entry.vlan_key)
    if match is None:
        return False
    kind, raw_value = match.groups()
    if len(raw_value) > 10:
        return False
    value = int(raw_value)
    if kind == "vid":
        return (
            _valid_optional_int(entry.vlan_id, minimum=1, maximum=4094)
            and entry.vlan_id == value
        )
    return entry.vlan_id is None and entry.fdb_id == value


def _valid_capability(capability: CapabilityResult) -> bool:
    return (
        _valid_text(capability.capability)
        and isinstance(capability.outcome, SnmpOutcome)
        and type(capability.rows) is tuple
        and all(_valid_varbind(row) for row in capability.rows)
        and type(capability.error_code) is str
        and type(capability.error_message) is str
        and type(capability.details) is dict
    )


def _valid_counter_sample(sample: SwitchCounterSample) -> bool:
    return (
        _valid_text(sample.port_key)
        and _valid_optional_int(sample.if_index, minimum=1, maximum=2_147_483_647)
        and _valid_optional_int(sample.sys_uptime_ticks, minimum=0)
        and all(
            _valid_optional_int(value, minimum=0)
            for value in (
                sample.in_errors,
                sample.in_discards,
                sample.out_errors,
                sample.out_discards,
                sample.in_octets,
                sample.out_octets,
            )
        )
    )


def _valid_varbind(row: object) -> bool:
    if type(row) is not SnmpVarBind:
        return False
    return (
        type(row.oid) is tuple
        and bool(row.oid)
        and all(
            type(part) is int and part >= 0
            for part in row.oid
        )
        and _valid_text(row.value_type)
        and type(row.value) in (int, str, bytes)
    )


def _valid_mac(value: object) -> bool:
    return type(value) is str and _MAC.fullmatch(value) is not None


def _valid_optional_int(
    value: object,
    *,
    minimum: int,
    maximum: int | None = None,
) -> bool:
    if value is None:
        return True
    if type(value) is not int or value < minimum:
        return False
    effective_maximum = _SQLITE_INTEGER_MAX if maximum is None else maximum
    return value <= effective_maximum


def _valid_vlan_memberships(rows: tuple[dict[str, Any], ...]) -> bool:
    keys: list[tuple[int, str]] = []
    for row in rows:
        if type(row) is not dict or not _VLAN_MEMBERSHIP_FIELDS <= row.keys():
            return False
        vlan_id = row.get("vlan_id")
        port_key = row.get("port_key")
        if not (
            _valid_optional_int(vlan_id, minimum=1, maximum=4094)
            and vlan_id is not None
            and _valid_text(port_key)
            and _valid_optional_int(
                row.get("if_index"), minimum=1, maximum=2_147_483_647
            )
            and _valid_optional_int(
                row.get("bridge_port"), minimum=1, maximum=65_535
            )
            and _valid_optional_int(
                row.get("physical_port"), minimum=1, maximum=65_535
            )
            and type(row.get("port_name")) is str
            and type(row.get("egress")) is bool
            and type(row.get("untagged")) is bool
            and type(row.get("pvid")) is bool
        ):
            return False
        keys.append((vlan_id, port_key))
    return len(keys) == len(set(keys))


def _valid_lldp_neighbors(rows: tuple[dict[str, Any], ...]) -> bool:
    keys: list[tuple[str, str, str]] = []
    for row in rows:
        if type(row) is not dict:
            return False
        local_port_key = row.get("local_port_key")
        chassis_id = row.get("chassis_id")
        port_id = row.get("port_id")
        if not (
            _valid_text(local_port_key)
            and _valid_text(chassis_id)
            and _valid_text(port_id)
            and type(row.get("system_name")) is str
        ):
            return False
        keys.append((local_port_key, chassis_id, port_id))
    return len(keys) == len(set(keys))


def _capabilities_confirm_success(
    snapshot: SwitchSnapshot, names: tuple[str, ...]
) -> bool:
    by_name = {
        capability.capability: capability.outcome
        for capability in snapshot.capabilities
    }
    return all(by_name.get(name) in _REPLACING_FDB_OUTCOMES for name in names)


def _parse_started_at(value: object) -> datetime:
    if type(value) is not str:
        raise ValueError("started_at is invalid")
    normalized = f"{value[:-1]}+00:00" if value.endswith("Z") else value
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("started_at is invalid")
    return parsed.astimezone(timezone.utc)


def _capability_ttl_hours(source: dict[str, Any]) -> int:
    options = source.get("driver_options", {})
    if not isinstance(options, dict):
        raise ValueError("source driver options are invalid")
    value = options.get("capability_ttl_hours", 168)
    if type(value) is not int or not 1 <= value <= 8760:
        raise ValueError("capability TTL is invalid")
    return value


@contextmanager
def _atomic(conn: sqlite3.Connection) -> Iterator[None]:
    if conn.in_transaction:
        savepoint = "switch_store_atomic"
        conn.execute(f"SAVEPOINT {savepoint}")
        try:
            yield
        except BaseException:
            conn.execute(f"ROLLBACK TO SAVEPOINT {savepoint}")
            conn.execute(f"RELEASE SAVEPOINT {savepoint}")
            raise
        else:
            conn.execute(f"RELEASE SAVEPOINT {savepoint}")
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


def _create_run(
    conn: sqlite3.Connection,
    *,
    source_id: int,
    started_at: str,
    profile_id: str,
    sys_uptime_ticks: int | None,
) -> int:
    cursor = conn.execute(
        """
        INSERT INTO switch_collection_runs (
            source_id, started_at, status, profile_id, sys_uptime_ticks
        ) VALUES (?, ?, 'running', ?, ?)
        """,
        (source_id, started_at, profile_id, sys_uptime_ticks),
    )
    return int(cursor.lastrowid)


def _finish_run(
    conn: sqlite3.Connection,
    *,
    run_id: int,
    source_id: int,
    finished_at: str,
    status: str,
    error_class: str,
    error_message: str,
    outcomes: dict[str, str],
    counts: dict[str, int],
) -> None:
    cursor = conn.execute(
        """
        UPDATE switch_collection_runs
        SET finished_at = ?, status = ?, error_class = ?, error_message = ?,
            outcomes_json = ?, counts_json = ?
        WHERE id = ? AND source_id = ? AND status = 'running'
        """,
        (
            finished_at,
            status,
            error_class,
            error_message,
            _json(outcomes),
            _json(counts),
            run_id,
            source_id,
        ),
    )
    if cursor.rowcount != 1:
        raise ValueError("switch collection run cannot be finalized")


def _record_failed_run(
    conn: sqlite3.Connection,
    *,
    source_id: int,
    started_at: str,
    error_class: str,
    error_message: str,
) -> dict[str, Any]:
    counts = dict(_EMPTY_COUNTS)
    try:
        with _atomic(conn):
            counts["fdb_current"] = _current_fdb_count(conn, source_id)
            run_id = _create_run(
                conn,
                source_id=source_id,
                started_at=started_at,
                profile_id="",
                sys_uptime_ticks=None,
            )
            _finish_run(
                conn,
                run_id=run_id,
                source_id=source_id,
                finished_at=started_at,
                status="failed",
                error_class=error_class,
                error_message=error_message,
                outcomes={"fdb": SnmpOutcome.PARSE_ERROR.value},
                counts=counts,
            )
    except Exception:
        raise SwitchPersistenceError("Switch collection persistence failed") from None
    return _result(
        run_id=run_id,
        source_id=source_id,
        status="failed",
        fdb_outcome=SnmpOutcome.PARSE_ERROR.value,
        counts=counts,
        error_class=error_class,
        error_message=error_message,
    )


def _invalid_snapshot_result(
    conn: sqlite3.Connection,
    *,
    source_id: int,
) -> dict[str, Any]:
    try:
        counts = dict(_EMPTY_COUNTS)
        counts["fdb_current"] = _current_fdb_count(conn, source_id)
    except Exception:
        raise SwitchPersistenceError("Switch collection persistence failed") from None
    return _result(
        run_id=None,
        source_id=source_id,
        status="failed",
        fdb_outcome=SnmpOutcome.PARSE_ERROR.value,
        counts=counts,
        error_class="invalid_snapshot",
        error_message="Switch snapshot is invalid",
    )


def _has_newer_or_equal_success(
    conn: sqlite3.Connection,
    *,
    source_id: int,
    started_time: datetime,
    exclude_run_id: int,
) -> bool:
    rows = conn.execute(
        """
        SELECT started_at
        FROM switch_collection_runs
        WHERE source_id = ? AND status = 'success' AND id != ?
        """,
        (source_id, exclude_run_id),
    ).fetchall()
    return any(_parse_started_at(row[0]) >= started_time for row in rows)


def _upsert_device(
    conn: sqlite3.Connection,
    source_id: int,
    snapshot: SwitchSnapshot,
    observed_at: str,
) -> None:
    system = snapshot.system
    conn.execute(
        """
        INSERT INTO switch_devices (
            source_id, profile_id, profile_fingerprint, sys_object_id, sys_descr,
            sys_name, sys_location, sys_uptime_ticks, last_success_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(source_id) DO UPDATE SET
            profile_id = excluded.profile_id,
            profile_fingerprint = excluded.profile_fingerprint,
            sys_object_id = excluded.sys_object_id,
            sys_descr = excluded.sys_descr,
            sys_name = excluded.sys_name,
            sys_location = excluded.sys_location,
            sys_uptime_ticks = excluded.sys_uptime_ticks,
            last_success_at = excluded.last_success_at,
            updated_at = excluded.updated_at
        """,
        (
            source_id,
            snapshot.profile_id,
            snapshot.profile_fingerprint,
            system.sys_object_id,
            system.sys_descr,
            system.sys_name,
            system.sys_location,
            system.sys_uptime_ticks,
            observed_at,
            observed_at,
        ),
    )


def _upsert_ports(
    conn: sqlite3.Connection,
    source_id: int,
    run_id: int,
    ports: tuple[SwitchPort, ...],
    observed_at: str,
) -> None:
    for port in ports:
        conn.execute(
            """
            INSERT INTO switch_ports (
                source_id, port_key, if_index, bridge_port, physical_port, name,
                alias, mac, admin_status, oper_status, speed_bps, last_seen_at,
                collector_run_id
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(source_id, port_key) DO UPDATE SET
                if_index = excluded.if_index,
                bridge_port = excluded.bridge_port,
                physical_port = excluded.physical_port,
                name = excluded.name,
                alias = excluded.alias,
                mac = excluded.mac,
                admin_status = excluded.admin_status,
                oper_status = excluded.oper_status,
                speed_bps = excluded.speed_bps,
                last_seen_at = excluded.last_seen_at,
                collector_run_id = excluded.collector_run_id
            """,
            (
                source_id,
                port.port_key,
                port.if_index,
                port.bridge_port,
                port.physical_port,
                port.name,
                port.alias,
                port.mac,
                port.admin_status,
                port.oper_status,
                port.speed_bps,
                observed_at,
                run_id,
            ),
        )


def _upsert_capabilities(
    conn: sqlite3.Connection,
    source_id: int,
    snapshot: SwitchSnapshot,
    *,
    checked_at: str,
    capability_ttl_hours: int,
) -> None:
    expires_at = (
        _parse_started_at(checked_at) + timedelta(hours=capability_ttl_hours)
    ).isoformat().replace("+00:00", "Z")
    for capability in snapshot.capabilities:
        rows_seen = (
            len(snapshot.fdb)
            if capability.capability == "fdb"
            else len(capability.rows)
        )
        conn.execute(
            """
            INSERT INTO switch_capabilities (
                source_id, capability, outcome, rows_seen, profile_fingerprint,
                checked_at, expires_at, details_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, '{}')
            ON CONFLICT(source_id, capability) DO UPDATE SET
                outcome = excluded.outcome,
                rows_seen = excluded.rows_seen,
                profile_fingerprint = excluded.profile_fingerprint,
                checked_at = excluded.checked_at,
                expires_at = excluded.expires_at,
                details_json = '{}'
            """,
            (
                source_id,
                capability.capability,
                capability.outcome.value,
                rows_seen,
                snapshot.profile_fingerprint,
                checked_at,
                expires_at,
            ),
        )


def _replace_fdb(
    conn: sqlite3.Connection,
    *,
    source_id: int,
    run_id: int,
    entries: tuple[SwitchFdbEntry, ...],
    observed_at: str,
) -> dict[str, int]:
    old_rows = conn.execute(
        "SELECT * FROM current_switch_fdb WHERE source_id = ?",
        (source_id,),
    ).fetchall()
    old_by_key = {
        (str(row["vlan_key"]), str(row["mac"])): row for row in old_rows
    }
    new_by_key = {(entry.vlan_key, entry.mac): entry for entry in entries}
    old_keys = set(old_by_key)
    new_keys = set(new_by_key)
    appeared = new_keys - old_keys
    disappeared = old_keys - new_keys
    common = old_keys & new_keys
    moved = {
        key
        for key in common
        if str(old_by_key[key]["port_key"]) != new_by_key[key].port_key
    }

    for key in sorted(appeared):
        entry = new_by_key[key]
        _insert_fdb_event(
            conn,
            source_id=source_id,
            run_id=run_id,
            entry=entry,
            event_type="appeared",
            old_port_key="",
            new_port_key=entry.port_key,
            observed_at=observed_at,
        )
    for key in sorted(moved):
        entry = new_by_key[key]
        _insert_fdb_event(
            conn,
            source_id=source_id,
            run_id=run_id,
            entry=entry,
            event_type="moved",
            old_port_key=str(old_by_key[key]["port_key"]),
            new_port_key=entry.port_key,
            observed_at=observed_at,
        )
    for key in sorted(disappeared):
        old = old_by_key[key]
        _insert_fdb_event(
            conn,
            source_id=source_id,
            run_id=run_id,
            entry=_entry_from_row(old),
            event_type="disappeared",
            old_port_key=str(old["port_key"]),
            new_port_key="",
            observed_at=observed_at,
        )

    conn.execute("DELETE FROM current_switch_fdb WHERE source_id = ?", (source_id,))
    for key in sorted(new_by_key):
        entry = new_by_key[key]
        first_seen_at = (
            str(old_by_key[key]["first_seen_at"])
            if key in old_by_key
            else observed_at
        )
        conn.execute(
            """
            INSERT INTO current_switch_fdb (
                source_id, fdb_id, vlan_key, vlan_id, mac, port_key, bridge_port,
                if_index, physical_port, port_name, status, first_seen_at,
                last_seen_at, collector_run_id
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                source_id,
                entry.fdb_id,
                entry.vlan_key,
                entry.vlan_id,
                entry.mac,
                entry.port_key,
                entry.bridge_port,
                entry.if_index,
                entry.physical_port,
                entry.port_name,
                entry.status,
                first_seen_at,
                observed_at,
                run_id,
            ),
        )

    return {
        "ports": 0,
        "fdb_current": len(new_by_key),
        "appeared": len(appeared),
        "moved": len(moved),
        "disappeared": len(disappeared),
    }


def _replace_optional_current_state(
    conn: sqlite3.Connection,
    *,
    source_id: int,
    run_id: int,
    snapshot: SwitchSnapshot,
    observed_at: str,
) -> None:
    if _capabilities_confirm_success(
        snapshot, _VLAN_CAPABILITIES
    ) and _valid_vlan_memberships(snapshot.vlan_memberships):
        conn.execute(
            "DELETE FROM current_switch_vlan_memberships WHERE source_id = ?",
            (source_id,),
        )
        for row in snapshot.vlan_memberships:
            conn.execute(
                """
                INSERT INTO current_switch_vlan_memberships (
                    source_id, vlan_id, port_key, if_index, bridge_port,
                    physical_port, port_name, egress, untagged, pvid,
                    observed_at, collector_run_id
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    source_id,
                    row["vlan_id"],
                    row["port_key"],
                    row["if_index"],
                    row["bridge_port"],
                    row["physical_port"],
                    row["port_name"],
                    int(row["egress"]),
                    int(row["untagged"]),
                    int(row["pvid"]),
                    observed_at,
                    run_id,
                ),
            )

    if _capabilities_confirm_success(
        snapshot, _LLDP_CAPABILITIES
    ) and _valid_lldp_neighbors(snapshot.lldp_neighbors):
        conn.execute(
            "DELETE FROM current_switch_lldp_neighbors WHERE source_id = ?",
            (source_id,),
        )
        for row in snapshot.lldp_neighbors:
            conn.execute(
                """
                INSERT INTO current_switch_lldp_neighbors (
                    source_id, local_port_key, chassis_id, port_id, system_name,
                    observed_at, collector_run_id
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    source_id,
                    row["local_port_key"],
                    row["chassis_id"],
                    row["port_id"],
                    row["system_name"],
                    observed_at,
                    run_id,
                ),
            )


def _insert_fdb_event(
    conn: sqlite3.Connection,
    *,
    source_id: int,
    run_id: int,
    entry: SwitchFdbEntry,
    event_type: str,
    old_port_key: str,
    new_port_key: str,
    observed_at: str,
) -> None:
    conn.execute(
        """
        INSERT INTO switch_fdb_events (
            source_id, fdb_id, vlan_key, vlan_id, mac, event_type,
            old_port_key, new_port_key, observed_at, collector_run_id,
            details_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, '{}')
        """,
        (
            source_id,
            entry.fdb_id,
            entry.vlan_key,
            entry.vlan_id,
            entry.mac,
            event_type,
            old_port_key,
            new_port_key,
            observed_at,
            run_id,
        ),
    )


def _entry_from_row(row: sqlite3.Row) -> SwitchFdbEntry:
    return SwitchFdbEntry(
        fdb_id=row["fdb_id"],
        vlan_key=str(row["vlan_key"]),
        vlan_id=row["vlan_id"],
        mac=str(row["mac"]),
        port_key=str(row["port_key"]),
        bridge_port=row["bridge_port"],
        if_index=row["if_index"],
        physical_port=row["physical_port"],
        port_name=str(row["port_name"]),
        status=str(row["status"]),
    )


def _current_fdb_count(conn: sqlite3.Connection, source_id: int) -> int:
    row = conn.execute(
        "SELECT COUNT(*) FROM current_switch_fdb WHERE source_id = ?", (source_id,)
    ).fetchone()
    return int(row[0])


def _json(value: dict[str, Any]) -> str:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))


def _result(
    *,
    run_id: int | None,
    source_id: int,
    status: str,
    fdb_outcome: str,
    counts: dict[str, int],
    error_class: str,
    error_message: str,
) -> dict[str, Any]:
    return {
        "run_id": run_id,
        "source_id": source_id,
        "status": status,
        "fdb_outcome": fdb_outcome,
        "counts": dict(counts),
        "error_class": error_class,
        "error_message": error_message,
    }
