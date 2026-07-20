from __future__ import annotations

import sqlite3
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from netctl.db import connect, ensure_schema, get_source, upsert_source
from netctl.snmp.models import (
    CapabilityResult,
    SwitchFdbEntry,
    SwitchPort,
    SwitchSnapshot,
    SwitchSystem,
)
from netctl.snmp.outcomes import SnmpOutcome


class _FakeDriver:
    def __init__(self, result: object) -> None:
        self.result = result

    def collect(self) -> object:
        if isinstance(self.result, BaseException):
            raise self.result
        return self.result


class _FailCommitConnection(sqlite3.Connection):
    fail_commit = False

    def commit(self) -> None:
        if self.fail_commit:
            raise sqlite3.OperationalError(
                "injected secret-bearing commit failure"
            )
        super().commit()


class _ExplodingStr(str):
    def strip(self, chars: str | None = None) -> str:
        raise RuntimeError("private validation detail")


class _EqualitySpoofStr(str):
    def __eq__(self, other: object) -> bool:
        return other == "legacy:unknown"


class _InequalitySpoofStr(str):
    def __ne__(self, other: object) -> bool:
        return False


class _TupleSubclass(tuple):
    pass


def _source(conn: sqlite3.Connection, name: str) -> dict[str, Any]:
    upsert_source(
        conn,
        {
            "name": name,
            "driver": "snmp_switch",
            "host": "192.0.2.1",
            "port": 161,
            "username": "",
            "secret_ref": f"{name}_secret",
            "tls": False,
            "verify_tls": False,
            "site": "test",
            "role": "switch",
            "enabled": False,
            "driver_options": {},
        },
    )
    source = get_source(conn, name)
    assert source is not None
    return source


@pytest.fixture
def switch_conn(tmp_path: Path) -> sqlite3.Connection:
    conn = connect(f"sqlite:///{tmp_path / 'switch.db'}")
    try:
        yield conn
    finally:
        conn.close()


def _entry(mac: str, port: int, *, vlan: int = 20) -> SwitchFdbEntry:
    return SwitchFdbEntry(
        fdb_id=vlan,
        vlan_key=f"vid:{vlan}",
        vlan_id=vlan,
        mac=mac,
        port_key=f"ifindex:{port}",
        bridge_port=port,
        if_index=port,
        physical_port=port,
        port_name=f"front-{port}",
        status="learned",
    )


def _snapshot(
    entries: tuple[SwitchFdbEntry, ...],
    *,
    outcome: SnmpOutcome | None = None,
) -> SwitchSnapshot:
    if outcome is None:
        outcome = (
            SnmpOutcome.SUCCESS_WITH_ROWS if entries else SnmpOutcome.SUCCESS_EMPTY
        )
    ports = tuple(
        SwitchPort(
            port_key=f"ifindex:{port}",
            if_index=port,
            bridge_port=port,
            physical_port=port,
            name=f"front-{port}",
            alias="",
            mac=None,
            admin_status="up",
            oper_status="up",
            speed_bps=1_000_000_000,
        )
        for port in sorted({entry.if_index for entry in entries if entry.if_index})
    )
    return SwitchSnapshot(
        snapshot_kind="snmp_switch",
        profile_id="test-profile",
        profile_fingerprint="test-profile:v1",
        system=SwitchSystem(
            sys_descr="Synthetic switch",
            sys_object_id="1.3.6.1.4.1.99999.1",
            sys_name="switch-test",
            sys_location="lab",
            sys_uptime_ticks=123,
        ),
        ports=ports,
        fdb=entries,
        vlan_memberships=(),
        stp=None,
        lldp_neighbors=(),
        counter_samples=(),
        capabilities=(
            CapabilityResult(
                capability="fdb",
                outcome=outcome,
                error_code="fixture_code" if outcome not in {
                    SnmpOutcome.SUCCESS_WITH_ROWS,
                    SnmpOutcome.SUCCESS_EMPTY,
                } else "",
                error_message="private backend text must not persist",
                details={"raw": "private detail must not persist"},
            ),
        ),
    )


def _vlan_row(
    vlan_id: int = 20,
    port: int = 1,
    *,
    egress: bool = True,
    untagged: bool = False,
    pvid: bool = False,
) -> dict[str, Any]:
    return {
        "vlan_id": vlan_id,
        "port_key": f"ifindex:{port}",
        "if_index": port,
        "bridge_port": port,
        "physical_port": port,
        "port_name": f"front-{port}",
        "egress": egress,
        "untagged": untagged,
        "pvid": pvid,
    }


def _lldp_row(
    port: int = 1,
    *,
    chassis_id: str = "00:11:22:33:44:55",
    port_id: str = "uplink-1",
    system_name: str = "neighbor-1",
) -> dict[str, Any]:
    return {
        "local_port_key": f"ifindex:{port}",
        "chassis_id": chassis_id,
        "port_id": port_id,
        "system_name": system_name,
    }


def _with_optional_state(
    snapshot: SwitchSnapshot,
    *,
    vlan_memberships: tuple[dict[str, Any], ...] = (),
    vlan_outcomes: tuple[SnmpOutcome, SnmpOutcome, SnmpOutcome] = (
        SnmpOutcome.SUCCESS_EMPTY,
        SnmpOutcome.SUCCESS_EMPTY,
        SnmpOutcome.SUCCESS_EMPTY,
    ),
    lldp_neighbors: tuple[dict[str, Any], ...] = (),
    lldp_outcome: SnmpOutcome = SnmpOutcome.SUCCESS_EMPTY,
) -> SwitchSnapshot:
    optional_capabilities = tuple(
        CapabilityResult(capability, outcome)
        for capability, outcome in zip(
            ("vlan_current_egress", "vlan_current_untagged", "pvid"),
            vlan_outcomes,
            strict=True,
        )
    ) + (CapabilityResult("lldp_remote", lldp_outcome),)
    return replace(
        snapshot,
        vlan_memberships=vlan_memberships,
        lldp_neighbors=lldp_neighbors,
        capabilities=(*snapshot.capabilities, *optional_capabilities),
    )


def _rows(conn: sqlite3.Connection, sql: str, params: tuple[Any, ...] = ()) -> list[dict[str, Any]]:
    return [dict(row) for row in conn.execute(sql, params).fetchall()]


def test_migration_6_creates_typed_vlan_and_lldp_current_tables(
    switch_conn: sqlite3.Connection,
) -> None:
    assert switch_conn.execute(
        "SELECT COUNT(*) FROM schema_migrations WHERE version = 6"
    ).fetchone()[0] == 1

    vlan_columns = {
        row["name"]: (row["type"], row["notnull"], row["pk"])
        for row in switch_conn.execute(
            "PRAGMA table_info(current_switch_vlan_memberships)"
        )
    }
    assert vlan_columns == {
        "source_id": ("INTEGER", 1, 1),
        "vlan_id": ("INTEGER", 1, 2),
        "port_key": ("TEXT", 1, 3),
        "if_index": ("INTEGER", 0, 0),
        "bridge_port": ("INTEGER", 0, 0),
        "physical_port": ("INTEGER", 0, 0),
        "port_name": ("TEXT", 1, 0),
        "egress": ("INTEGER", 1, 0),
        "untagged": ("INTEGER", 1, 0),
        "pvid": ("INTEGER", 1, 0),
        "observed_at": ("TEXT", 1, 0),
        "collector_run_id": ("INTEGER", 1, 0),
    }
    lldp_columns = {
        row["name"]: (row["type"], row["notnull"], row["pk"])
        for row in switch_conn.execute(
            "PRAGMA table_info(current_switch_lldp_neighbors)"
        )
    }
    assert lldp_columns == {
        "source_id": ("INTEGER", 1, 1),
        "local_port_key": ("TEXT", 1, 2),
        "chassis_id": ("TEXT", 1, 3),
        "port_id": ("TEXT", 1, 4),
        "system_name": ("TEXT", 1, 0),
        "observed_at": ("TEXT", 1, 0),
        "collector_run_id": ("INTEGER", 1, 0),
    }
    indexes = {
        row["name"]
        for table in (
            "current_switch_vlan_memberships",
            "current_switch_lldp_neighbors",
        )
        for row in switch_conn.execute(f"PRAGMA index_list({table})")
    }
    assert {
        "current_switch_vlan_memberships_source_observed_idx",
        "current_switch_lldp_neighbors_source_observed_idx",
    } <= indexes


def test_successful_vlan_and_lldp_groups_replace_current_rows(
    switch_conn: sqlite3.Connection,
) -> None:
    from netctl.switch_store import collect_and_save_switch

    source = _source(switch_conn, "switch_a")
    required = _snapshot((_entry("02:00:00:00:00:01", 1),))
    first = _with_optional_state(
        required,
        vlan_memberships=(_vlan_row(),),
        vlan_outcomes=(
            SnmpOutcome.SUCCESS_WITH_ROWS,
            SnmpOutcome.SUCCESS_EMPTY,
            SnmpOutcome.SUCCESS_EMPTY,
        ),
        lldp_neighbors=(_lldp_row(),),
        lldp_outcome=SnmpOutcome.SUCCESS_WITH_ROWS,
    )
    second = _with_optional_state(
        required,
        vlan_memberships=(_vlan_row(30, pvid=True),),
        vlan_outcomes=(
            SnmpOutcome.SUCCESS_EMPTY,
            SnmpOutcome.SUCCESS_EMPTY,
            SnmpOutcome.SUCCESS_WITH_ROWS,
        ),
        lldp_neighbors=(
            _lldp_row(
                chassis_id="66:77:88:99:AA:BB",
                port_id="uplink-2",
                system_name="neighbor-2",
            ),
        ),
        lldp_outcome=SnmpOutcome.SUCCESS_WITH_ROWS,
    )

    collect_and_save_switch(
        switch_conn, source, _FakeDriver(first), "2026-07-19T10:00:00Z"
    )
    result = collect_and_save_switch(
        switch_conn, source, _FakeDriver(second), "2026-07-19T11:00:00Z"
    )

    assert result["status"] == "success"
    assert _rows(
        switch_conn,
        "SELECT vlan_id, port_key, egress, untagged, pvid, observed_at, "
        "collector_run_id FROM current_switch_vlan_memberships",
    ) == [
        {
            "vlan_id": 30,
            "port_key": "ifindex:1",
            "egress": 1,
            "untagged": 0,
            "pvid": 1,
            "observed_at": "2026-07-19T11:00:00Z",
            "collector_run_id": result["run_id"],
        }
    ]
    assert _rows(
        switch_conn,
        "SELECT local_port_key, chassis_id, port_id, system_name, observed_at, "
        "collector_run_id FROM current_switch_lldp_neighbors",
    ) == [
        {
            "local_port_key": "ifindex:1",
            "chassis_id": "66:77:88:99:AA:BB",
            "port_id": "uplink-2",
            "system_name": "neighbor-2",
            "observed_at": "2026-07-19T11:00:00Z",
            "collector_run_id": result["run_id"],
        }
    ]


@pytest.mark.parametrize("group", ["vlan", "lldp"])
def test_confirmed_empty_optional_group_clears_only_that_group(
    switch_conn: sqlite3.Connection, group: str
) -> None:
    from netctl.switch_store import collect_and_save_switch

    source = _source(switch_conn, "switch_a")
    required = _snapshot((_entry("02:00:00:00:00:01", 1),))
    seeded = _with_optional_state(
        required,
        vlan_memberships=(_vlan_row(),),
        vlan_outcomes=(
            SnmpOutcome.SUCCESS_WITH_ROWS,
            SnmpOutcome.SUCCESS_EMPTY,
            SnmpOutcome.SUCCESS_EMPTY,
        ),
        lldp_neighbors=(_lldp_row(),),
        lldp_outcome=SnmpOutcome.SUCCESS_WITH_ROWS,
    )
    collect_and_save_switch(
        switch_conn, source, _FakeDriver(seeded), "2026-07-19T10:00:00Z"
    )
    replacement = _with_optional_state(
        required,
        vlan_memberships=() if group == "vlan" else (_vlan_row(),),
        vlan_outcomes=(
            (SnmpOutcome.SUCCESS_EMPTY,) * 3
            if group == "vlan"
            else (
                SnmpOutcome.SUCCESS_WITH_ROWS,
                SnmpOutcome.SUCCESS_EMPTY,
                SnmpOutcome.SUCCESS_EMPTY,
            )
        ),
        lldp_neighbors=() if group == "lldp" else (_lldp_row(),),
        lldp_outcome=(
            SnmpOutcome.SUCCESS_EMPTY
            if group == "lldp"
            else SnmpOutcome.SUCCESS_WITH_ROWS
        ),
    )

    collect_and_save_switch(
        switch_conn, source, _FakeDriver(replacement), "2026-07-19T11:00:00Z"
    )

    assert switch_conn.execute(
        "SELECT COUNT(*) FROM current_switch_vlan_memberships"
    ).fetchone()[0] == (0 if group == "vlan" else 1)
    assert switch_conn.execute(
        "SELECT COUNT(*) FROM current_switch_lldp_neighbors"
    ).fetchone()[0] == (0 if group == "lldp" else 1)


@pytest.mark.parametrize(
    "failed_outcome",
    [
        SnmpOutcome.UNSUPPORTED_NO_SUCH_OBJECT,
        SnmpOutcome.TIMEOUT,
        SnmpOutcome.PARSE_ERROR,
    ],
)
@pytest.mark.parametrize("group", ["vlan", "lldp"])
def test_optional_error_preserves_current_group_while_required_state_advances(
    switch_conn: sqlite3.Connection,
    group: str,
    failed_outcome: SnmpOutcome,
) -> None:
    from netctl.switch_store import collect_and_save_switch

    source = _source(switch_conn, "switch_a")
    first_required = _snapshot((_entry("02:00:00:00:00:01", 1),))
    seeded = _with_optional_state(
        first_required,
        vlan_memberships=(_vlan_row(),),
        vlan_outcomes=(
            SnmpOutcome.SUCCESS_WITH_ROWS,
            SnmpOutcome.SUCCESS_EMPTY,
            SnmpOutcome.SUCCESS_EMPTY,
        ),
        lldp_neighbors=(_lldp_row(),),
        lldp_outcome=SnmpOutcome.SUCCESS_WITH_ROWS,
    )
    collect_and_save_switch(
        switch_conn, source, _FakeDriver(seeded), "2026-07-19T10:00:00Z"
    )
    second_required = _snapshot((_entry("02:00:00:00:00:02", 2),))
    replacement = _with_optional_state(
        second_required,
        vlan_memberships=() if group == "vlan" else (_vlan_row(30, 2),),
        vlan_outcomes=(
            (failed_outcome, SnmpOutcome.SUCCESS_EMPTY, SnmpOutcome.SUCCESS_EMPTY)
            if group == "vlan"
            else (
                SnmpOutcome.SUCCESS_WITH_ROWS,
                SnmpOutcome.SUCCESS_EMPTY,
                SnmpOutcome.SUCCESS_EMPTY,
            )
        ),
        lldp_neighbors=() if group == "lldp" else (_lldp_row(2),),
        lldp_outcome=(
            failed_outcome
            if group == "lldp"
            else SnmpOutcome.SUCCESS_WITH_ROWS
        ),
    )

    result = collect_and_save_switch(
        switch_conn, source, _FakeDriver(replacement), "2026-07-19T11:00:00Z"
    )

    assert result["status"] == "success"
    assert _rows(
        switch_conn,
        "SELECT mac, port_key FROM current_switch_fdb",
    ) == [{"mac": "02:00:00:00:00:02", "port_key": "ifindex:2"}]
    assert _rows(
        switch_conn,
        "SELECT port_key, collector_run_id FROM switch_ports ORDER BY port_key",
    )[-1] == {"port_key": "ifindex:2", "collector_run_id": result["run_id"]}
    optional_rows = _rows(
        switch_conn,
        (
            "SELECT vlan_id, port_key FROM current_switch_vlan_memberships"
            if group == "vlan"
            else "SELECT local_port_key, chassis_id FROM current_switch_lldp_neighbors"
        ),
    )
    assert optional_rows == (
        [{"vlan_id": 20, "port_key": "ifindex:1"}]
        if group == "vlan"
        else [
            {
                "local_port_key": "ifindex:1",
                "chassis_id": "00:11:22:33:44:55",
            }
        ]
    )


@pytest.mark.parametrize("group", ["vlan", "lldp"])
def test_malformed_optional_mapping_is_not_persisted_or_allowed_to_block_fdb(
    switch_conn: sqlite3.Connection, group: str
) -> None:
    from netctl.switch_store import collect_and_save_switch

    source = _source(switch_conn, "switch_a")
    required = _snapshot((_entry("02:00:00:00:00:01", 1),))
    seeded = _with_optional_state(
        required,
        vlan_memberships=(_vlan_row(),),
        vlan_outcomes=(
            SnmpOutcome.SUCCESS_WITH_ROWS,
            SnmpOutcome.SUCCESS_EMPTY,
            SnmpOutcome.SUCCESS_EMPTY,
        ),
        lldp_neighbors=(_lldp_row(),),
        lldp_outcome=SnmpOutcome.SUCCESS_WITH_ROWS,
    )
    collect_and_save_switch(
        switch_conn, source, _FakeDriver(seeded), "2026-07-19T10:00:00Z"
    )
    malformed = _with_optional_state(
        _snapshot((_entry("02:00:00:00:00:02", 2),)),
        vlan_memberships=(
            {**_vlan_row(30, 2), "pvid": "yes"},
        )
        if group == "vlan"
        else (_vlan_row(30, 2),),
        vlan_outcomes=(
            SnmpOutcome.SUCCESS_WITH_ROWS,
            SnmpOutcome.SUCCESS_EMPTY,
            SnmpOutcome.SUCCESS_EMPTY,
        ),
        lldp_neighbors=(
            {**_lldp_row(2), "chassis_id": ""},
        )
        if group == "lldp"
        else (_lldp_row(2),),
        lldp_outcome=SnmpOutcome.SUCCESS_WITH_ROWS,
    )

    result = collect_and_save_switch(
        switch_conn, source, _FakeDriver(malformed), "2026-07-19T11:00:00Z"
    )

    assert result["status"] == "success"
    assert _rows(switch_conn, "SELECT mac FROM current_switch_fdb") == [
        {"mac": "02:00:00:00:00:02"}
    ]
    optional_rows = _rows(
        switch_conn,
        (
            "SELECT vlan_id FROM current_switch_vlan_memberships"
            if group == "vlan"
            else "SELECT chassis_id FROM current_switch_lldp_neighbors"
        ),
    )
    assert optional_rows == (
        [{"vlan_id": 20}]
        if group == "vlan"
        else [{"chassis_id": "00:11:22:33:44:55"}]
    )


def test_sparse_vlan_mapping_preserves_vlan_without_rolling_back_required_state(
    switch_conn: sqlite3.Connection,
) -> None:
    from netctl.switch_store import collect_and_save_switch

    source = _source(switch_conn, "switch_a")
    seeded = _with_optional_state(
        _snapshot((_entry("02:00:00:00:00:01", 1),)),
        vlan_memberships=(_vlan_row(),),
        vlan_outcomes=(
            SnmpOutcome.SUCCESS_WITH_ROWS,
            SnmpOutcome.SUCCESS_EMPTY,
            SnmpOutcome.SUCCESS_EMPTY,
        ),
    )
    collect_and_save_switch(
        switch_conn, source, _FakeDriver(seeded), "2026-07-19T10:00:00Z"
    )
    sparse_vlan = _vlan_row(30, 2)
    sparse_vlan.pop("if_index")
    malformed = _with_optional_state(
        _snapshot((_entry("02:00:00:00:00:02", 2),)),
        vlan_memberships=(sparse_vlan,),
        vlan_outcomes=(
            SnmpOutcome.SUCCESS_WITH_ROWS,
            SnmpOutcome.SUCCESS_EMPTY,
            SnmpOutcome.SUCCESS_EMPTY,
        ),
    )

    result = collect_and_save_switch(
        switch_conn, source, _FakeDriver(malformed), "2026-07-19T11:00:00Z"
    )

    assert result["status"] == "success"
    assert _rows(
        switch_conn,
        "SELECT mac, port_key FROM current_switch_fdb",
    ) == [{"mac": "02:00:00:00:00:02", "port_key": "ifindex:2"}]
    assert _rows(
        switch_conn,
        "SELECT port_key, collector_run_id FROM switch_ports ORDER BY port_key",
    )[-1] == {"port_key": "ifindex:2", "collector_run_id": result["run_id"]}
    assert _rows(
        switch_conn,
        "SELECT vlan_id, port_key FROM current_switch_vlan_memberships",
    ) == [{"vlan_id": 20, "port_key": "ifindex:1"}]


def test_auth_or_view_failure_preserves_vlan_and_lldp_current_state(
    switch_conn: sqlite3.Connection,
) -> None:
    from netctl.switch_store import collect_and_save_switch

    source = _source(switch_conn, "switch_a")
    seeded = _with_optional_state(
        _snapshot((_entry("02:00:00:00:00:01", 1),)),
        vlan_memberships=(_vlan_row(),),
        vlan_outcomes=(
            SnmpOutcome.SUCCESS_WITH_ROWS,
            SnmpOutcome.SUCCESS_EMPTY,
            SnmpOutcome.SUCCESS_EMPTY,
        ),
        lldp_neighbors=(_lldp_row(),),
        lldp_outcome=SnmpOutcome.SUCCESS_WITH_ROWS,
    )
    collect_and_save_switch(
        switch_conn, source, _FakeDriver(seeded), "2026-07-19T10:00:00Z"
    )
    failed_optional = _with_optional_state(
        _snapshot((_entry("02:00:00:00:00:02", 2),)),
        vlan_outcomes=(
            SnmpOutcome.AUTH_OR_VIEW_FAILURE,
            SnmpOutcome.SUCCESS_EMPTY,
            SnmpOutcome.SUCCESS_EMPTY,
        ),
        lldp_outcome=SnmpOutcome.AUTH_OR_VIEW_FAILURE,
    )

    result = collect_and_save_switch(
        switch_conn,
        source,
        _FakeDriver(failed_optional),
        "2026-07-19T11:00:00Z",
    )

    assert result["status"] == "success"
    assert _rows(switch_conn, "SELECT mac FROM current_switch_fdb") == [
        {"mac": "02:00:00:00:00:02"}
    ]
    assert _rows(
        switch_conn,
        "SELECT vlan_id, port_key FROM current_switch_vlan_memberships",
    ) == [{"vlan_id": 20, "port_key": "ifindex:1"}]
    assert _rows(
        switch_conn,
        "SELECT local_port_key, chassis_id FROM current_switch_lldp_neighbors",
    ) == [
        {
            "local_port_key": "ifindex:1",
            "chassis_id": "00:11:22:33:44:55",
        }
    ]


def test_initial_success_persists_current_rows_and_appeared_events(
    switch_conn: sqlite3.Connection,
) -> None:
    from netctl.switch_store import collect_and_save_switch

    source = _source(switch_conn, "switch_a")
    snapshot = _snapshot(
        (_entry("02:00:00:00:00:01", 1), _entry("02:00:00:00:00:02", 2))
    )

    result = collect_and_save_switch(
        switch_conn, source, _FakeDriver(snapshot), "2026-07-19T10:00:00Z"
    )

    assert result == {
        "run_id": result["run_id"],
        "source_id": source["id"],
        "status": "success",
        "fdb_outcome": "success_with_rows",
        "counts": {
            "ports": 2,
            "fdb_current": 2,
            "appeared": 2,
            "moved": 0,
            "disappeared": 0,
        },
        "error_class": "",
        "error_message": "",
    }
    current = _rows(
        switch_conn,
        "SELECT * FROM current_switch_fdb WHERE source_id = ? ORDER BY mac",
        (source["id"],),
    )
    assert [row["first_seen_at"] for row in current] == [
        "2026-07-19T10:00:00Z",
        "2026-07-19T10:00:00Z",
    ]
    assert {row["collector_run_id"] for row in current} == {result["run_id"]}
    events = _rows(
        switch_conn,
        "SELECT event_type, old_port_key, new_port_key, collector_run_id "
        "FROM switch_fdb_events WHERE source_id = ? ORDER BY mac",
        (source["id"],),
    )
    assert events == [
        {
            "event_type": "appeared",
            "old_port_key": "",
            "new_port_key": "ifindex:1",
            "collector_run_id": result["run_id"],
        },
        {
            "event_type": "appeared",
            "old_port_key": "",
            "new_port_key": "ifindex:2",
            "collector_run_id": result["run_id"],
        },
    ]
    assert switch_conn.execute(
        "SELECT COUNT(*) FROM switch_ports WHERE source_id = ? AND collector_run_id = ?",
        (source["id"], result["run_id"]),
    ).fetchone()[0] == 2
    assert switch_conn.execute(
        "SELECT COUNT(*) FROM switch_capabilities WHERE source_id = ?",
        (source["id"],),
    ).fetchone()[0] == 1
    stored_text = repr(
        _rows(switch_conn, "SELECT * FROM switch_collection_runs")
        + _rows(switch_conn, "SELECT * FROM switch_capabilities")
    )
    assert "private backend text" not in stored_text
    assert "private detail" not in stored_text


def test_capability_expiry_honors_source_ttl_hours(
    switch_conn: sqlite3.Connection,
) -> None:
    from netctl.switch_store import collect_and_save_switch

    source = _source(switch_conn, "switch_ttl")
    source["driver_options"]["capability_ttl_hours"] = 6

    result = collect_and_save_switch(
        switch_conn,
        source,
        _FakeDriver(_snapshot((_entry("02:00:00:00:00:01", 1),))),
        "2026-07-19T10:00:00Z",
    )

    assert result["status"] == "success"
    capability = _rows(
        switch_conn,
        "SELECT checked_at, expires_at FROM switch_capabilities WHERE source_id = ?",
        (source["id"],),
    )[0]
    assert capability == {
        "checked_at": "2026-07-19T10:00:00Z",
        "expires_at": "2026-07-19T16:00:00Z",
    }


def test_identical_success_retains_first_seen_and_emits_no_event(
    switch_conn: sqlite3.Connection,
) -> None:
    from netctl.switch_store import collect_and_save_switch

    source = _source(switch_conn, "switch_a")
    snapshot = _snapshot((_entry("02:00:00:00:00:01", 1),))
    first = collect_and_save_switch(
        switch_conn, source, _FakeDriver(snapshot), "2026-07-19T10:00:00Z"
    )

    second = collect_and_save_switch(
        switch_conn, source, _FakeDriver(snapshot), "2026-07-19T11:00:00Z"
    )

    assert second["counts"] == {
        "ports": 1,
        "fdb_current": 1,
        "appeared": 0,
        "moved": 0,
        "disappeared": 0,
    }
    row = _rows(switch_conn, "SELECT * FROM current_switch_fdb")[0]
    assert (row["first_seen_at"], row["last_seen_at"], row["collector_run_id"]) == (
        "2026-07-19T10:00:00Z",
        "2026-07-19T11:00:00Z",
        second["run_id"],
    )
    assert switch_conn.execute(
        "SELECT COUNT(*) FROM switch_fdb_events"
    ).fetchone()[0] == 1
    assert first["run_id"] != second["run_id"]


def test_port_change_emits_exactly_one_moved_event(
    switch_conn: sqlite3.Connection,
) -> None:
    from netctl.switch_store import collect_and_save_switch

    source = _source(switch_conn, "switch_a")
    collect_and_save_switch(
        switch_conn,
        source,
        _FakeDriver(_snapshot((_entry("02:00:00:00:00:01", 1),))),
        "2026-07-19T10:00:00Z",
    )

    result = collect_and_save_switch(
        switch_conn,
        source,
        _FakeDriver(_snapshot((_entry("02:00:00:00:00:01", 9),))),
        "2026-07-19T11:00:00Z",
    )

    assert result["counts"]["moved"] == 1
    events = _rows(
        switch_conn,
        "SELECT event_type, old_port_key, new_port_key FROM switch_fdb_events "
        "WHERE collector_run_id = ?",
        (result["run_id"],),
    )
    assert events == [
        {
            "event_type": "moved",
            "old_port_key": "ifindex:1",
            "new_port_key": "ifindex:9",
        }
    ]


def test_confirmed_empty_replaces_current_and_emits_disappeared(
    switch_conn: sqlite3.Connection,
) -> None:
    from netctl.switch_store import collect_and_save_switch

    source = _source(switch_conn, "switch_a")
    collect_and_save_switch(
        switch_conn,
        source,
        _FakeDriver(_snapshot((_entry("02:00:00:00:00:01", 1),))),
        "2026-07-19T10:00:00Z",
    )

    result = collect_and_save_switch(
        switch_conn, source, _FakeDriver(_snapshot(())), "2026-07-19T11:00:00Z"
    )

    assert result["fdb_outcome"] == "success_empty"
    assert result["counts"]["disappeared"] == 1
    assert switch_conn.execute(
        "SELECT COUNT(*) FROM current_switch_fdb WHERE source_id = ?", (source["id"],)
    ).fetchone()[0] == 0
    event = _rows(
        switch_conn,
        "SELECT event_type, old_port_key, new_port_key FROM switch_fdb_events "
        "WHERE collector_run_id = ?",
        (result["run_id"],),
    )
    assert event == [
        {
            "event_type": "disappeared",
            "old_port_key": "ifindex:1",
            "new_port_key": "",
        }
    ]


@pytest.mark.parametrize(
    "outcome",
    [
        SnmpOutcome.TIMEOUT,
        SnmpOutcome.AUTH_OR_VIEW_FAILURE,
        SnmpOutcome.UNSUPPORTED_NO_SUCH_OBJECT,
        SnmpOutcome.PARSE_ERROR,
    ],
)
def test_failed_fdb_preserves_all_current_rows_and_emits_no_disappeared(
    switch_conn: sqlite3.Connection, outcome: SnmpOutcome
) -> None:
    from netctl.switch_store import collect_and_save_switch

    source = _source(switch_conn, "switch_a")
    collect_and_save_switch(
        switch_conn,
        source,
        _FakeDriver(_snapshot((_entry("02:00:00:00:00:01", 1),))),
        "2026-07-19T10:00:00Z",
    )
    protected_tables = (
        "switch_devices",
        "switch_ports",
        "switch_capabilities",
        "current_switch_fdb",
        "switch_fdb_events",
    )
    before = {
        table: _rows(switch_conn, f"SELECT * FROM {table}")
        for table in protected_tables
    }

    failed_snapshot = replace(
        _snapshot((_entry("02:00:00:00:00:09", 9),), outcome=outcome),
        system=replace(_snapshot(()).system, sys_name="older-failed-system"),
        fdb=(),
    )
    result = collect_and_save_switch(
        switch_conn,
        source,
        _FakeDriver(failed_snapshot),
        "2026-07-19T11:00:00Z",
    )

    assert (result["status"], result["fdb_outcome"]) == ("failed", outcome.value)
    assert result["error_class"] == "fdb_unavailable"
    assert {
        table: _rows(switch_conn, f"SELECT * FROM {table}")
        for table in protected_tables
    } == before
    run = _rows(
        switch_conn,
        "SELECT status, error_class, outcomes_json FROM switch_collection_runs "
        "WHERE id = ?",
        (result["run_id"],),
    )[0]
    assert (run["status"], run["error_class"]) == ("failed", "fdb_unavailable")
    assert f'"fdb":"{outcome.value}"' in run["outcomes_json"]


def test_optional_capability_failure_does_not_block_confirmed_fdb_replacement(
    switch_conn: sqlite3.Connection,
) -> None:
    from netctl.switch_store import collect_and_save_switch

    source = _source(switch_conn, "switch_a")
    snapshot = _snapshot((_entry("02:00:00:00:00:01", 1),))
    snapshot = replace(
        snapshot,
        capabilities=(
            CapabilityResult("optional_lldp", SnmpOutcome.TIMEOUT),
            *snapshot.capabilities,
        ),
    )

    result = collect_and_save_switch(
        switch_conn, source, _FakeDriver(snapshot), "2026-07-19T10:00:00Z"
    )

    assert (result["status"], result["fdb_outcome"]) == (
        "success",
        "success_with_rows",
    )
    assert result["counts"]["appeared"] == 1
    capabilities = _rows(
        switch_conn,
        "SELECT capability, outcome FROM switch_capabilities "
        "WHERE source_id = ? ORDER BY capability",
        (source["id"],),
    )
    assert capabilities == [
        {"capability": "fdb", "outcome": "success_with_rows"},
        {"capability": "optional_lldp", "outcome": "timeout"},
    ]


@pytest.mark.parametrize(
    "malformed",
    [
        {"snapshot_kind": "snmp_switch"},
        replace(
            _snapshot(()),
            snapshot_kind=_InequalitySpoofStr("malformed-kind"),
        ),
        _snapshot((), outcome=SnmpOutcome.SUCCESS_WITH_ROWS),
        _snapshot((_entry("02:00:00:00:00:02", 2),), outcome=SnmpOutcome.SUCCESS_EMPTY),
        replace(
            _snapshot((_entry("02:00:00:00:00:02", 2),)),
            fdb=(
                _entry("02:00:00:00:00:02", 2),
                _entry("02:00:00:00:00:02", 3),
            ),
        ),
        replace(
            _snapshot((_entry("02:00:00:00:00:02", 2),)),
            fdb=_TupleSubclass((_entry("02:00:00:00:00:02", 2),)),
        ),
        replace(_snapshot(()), lldp_neighbors=_TupleSubclass(())),
    ],
)
def test_malformed_snapshot_fails_closed_without_changing_current(
    switch_conn: sqlite3.Connection, malformed: object
) -> None:
    from netctl.switch_store import collect_and_save_switch

    source = _source(switch_conn, "switch_a")
    collect_and_save_switch(
        switch_conn,
        source,
        _FakeDriver(_snapshot((_entry("02:00:00:00:00:01", 1),))),
        "2026-07-19T10:00:00Z",
    )
    protected_tables = (
        "switch_collection_runs",
        "switch_devices",
        "switch_ports",
        "switch_capabilities",
        "current_switch_fdb",
        "switch_fdb_events",
    )
    before = {
        table: _rows(switch_conn, f"SELECT * FROM {table}")
        for table in protected_tables
    }

    result = collect_and_save_switch(
        switch_conn, source, _FakeDriver(malformed), "2026-07-19T11:00:00Z"
    )

    assert (result["status"], result["fdb_outcome"]) == ("failed", "parse_error")
    assert result["run_id"] is None
    assert result["error_message"] == "Switch snapshot is invalid"
    assert {
        table: _rows(switch_conn, f"SELECT * FROM {table}")
        for table in protected_tables
    } == before


@pytest.mark.parametrize(
    "malformed",
    [
        replace(
            _snapshot(()),
            system=replace(
                _snapshot(()).system,
                sys_uptime_ticks="not-an-integer",  # type: ignore[arg-type]
            ),
        ),
        replace(
            _snapshot(()),
            system=replace(_snapshot(()).system, sys_uptime_ticks=2**63),
        ),
        replace(
            _snapshot((_entry("02:00:00:00:00:02", 2),)),
            ports=(
                replace(
                    _snapshot((_entry("02:00:00:00:00:02", 2),)).ports[0],
                    speed_bps="not-an-integer",  # type: ignore[arg-type]
                ),
            ),
        ),
        replace(
            _snapshot((_entry("02:00:00:00:00:02", 2),)),
            ports=(
                replace(
                    _snapshot((_entry("02:00:00:00:00:02", 2),)).ports[0],
                    speed_bps=2**63,
                ),
            ),
        ),
        replace(
            _snapshot((_entry("02:00:00:00:00:02", 2),)),
            fdb=(
                replace(
                    _entry("02:00:00:00:00:02", 2),
                    vlan_id="not-an-integer",  # type: ignore[arg-type]
                ),
            ),
        ),
        replace(
            _snapshot((_entry("02:00:00:00:00:02", 2),)),
            fdb=(
                replace(
                    _entry("02:00:00:00:00:02", 2),
                    status=[],  # type: ignore[arg-type]
                ),
            ),
        ),
        replace(
            _snapshot((_entry("02:00:00:00:00:02", 2),)),
            fdb=(
                replace(
                    _entry("02:00:00:00:00:02", 2),
                    vlan_key=[],  # type: ignore[arg-type]
                ),
            ),
        ),
        replace(
            _snapshot((_entry("02:00:00:00:00:02", 2),)),
            fdb=(
                replace(
                    _entry("02:00:00:00:00:02", 2),
                    vlan_key="fid:" + "9" * 5000,
                ),
            ),
        ),
        replace(
            _snapshot(()),
            capabilities=(
                replace(
                    _snapshot(()).capabilities[0],
                    rows=("not-a-varbind",),  # type: ignore[arg-type]
                ),
            ),
        ),
        replace(_snapshot(()), profile_id=_ExplodingStr("test-profile")),
        replace(
            _snapshot((_entry("02:00:00:00:00:02", 2),)),
            fdb=(
                replace(
                    _entry("02:00:00:00:00:02", 2),
                    fdb_id=None,
                    vlan_id=None,
                    vlan_key=_EqualitySpoofStr("invalid-vlan-key"),
                ),
            ),
        ),
    ],
)
def test_typed_but_malformed_snapshot_fails_before_any_state_replacement(
    switch_conn: sqlite3.Connection, malformed: SwitchSnapshot
) -> None:
    from netctl.switch_store import collect_and_save_switch

    source = _source(switch_conn, "switch_a")
    collect_and_save_switch(
        switch_conn,
        source,
        _FakeDriver(_snapshot((_entry("02:00:00:00:00:01", 1),))),
        "2026-07-19T10:00:00Z",
    )
    protected_tables = (
        "switch_collection_runs",
        "switch_devices",
        "switch_ports",
        "switch_capabilities",
        "current_switch_fdb",
        "switch_fdb_events",
    )
    before = {
        table: _rows(switch_conn, f"SELECT * FROM {table}")
        for table in protected_tables
    }

    result = collect_and_save_switch(
        switch_conn,
        source,
        _FakeDriver(malformed),
        "2026-07-19T11:00:00Z",
    )

    assert (result["status"], result["error_class"]) == (
        "failed",
        "invalid_snapshot",
    )
    assert result["run_id"] is None
    assert {
        table: _rows(switch_conn, f"SELECT * FROM {table}")
        for table in protected_tables
    } == before


@pytest.mark.parametrize(
    ("first_time", "first_port", "second_time", "second_port", "second_status"),
    [
        (
            "2026-07-19T10:00:00Z",
            1,
            "2026-07-19T11:00:00Z",
            9,
            "success",
        ),
        (
            "2026-07-19T11:00:00Z",
            9,
            "2026-07-19T10:00:00Z",
            1,
            "failed",
        ),
        (
            "2026-07-19T10:00:00Z",
            2,
            "2026-07-19T10:00:00Z",
            3,
            "failed",
        ),
    ],
)
def test_collection_order_never_allows_older_snapshot_to_reverse_current_state(
    switch_conn: sqlite3.Connection,
    first_time: str,
    first_port: int,
    second_time: str,
    second_port: int,
    second_status: str,
) -> None:
    from netctl.switch_store import collect_and_save_switch

    source = _source(switch_conn, "switch_a")
    mac = "02:00:00:00:00:01"
    first = collect_and_save_switch(
        switch_conn,
        source,
        _FakeDriver(_snapshot((_entry(mac, first_port),))),
        first_time,
    )
    second = collect_and_save_switch(
        switch_conn,
        source,
        _FakeDriver(_snapshot((_entry(mac, second_port),))),
        second_time,
    )

    assert second["status"] == second_status
    current = _rows(
        switch_conn,
        "SELECT port_key, last_seen_at, collector_run_id FROM current_switch_fdb",
    )
    if second_status == "success":
        assert current == [
            {
                "port_key": "ifindex:9",
                "last_seen_at": second_time,
                "collector_run_id": second["run_id"],
            }
        ]
        assert second["counts"]["moved"] == 1
    else:
        assert (second["error_class"], second["error_message"]) == (
            "stale_snapshot",
            "Switch snapshot is not newer than current state",
        )
        assert current == [
            {
                "port_key": f"ifindex:{first_port}",
                "last_seen_at": first_time,
                "collector_run_id": first["run_id"],
            }
        ]
        assert second["counts"]["moved"] == 0
        assert _rows(
            switch_conn,
            "SELECT event_type, old_port_key, new_port_key FROM switch_fdb_events "
            "WHERE collector_run_id = ?",
            (second["run_id"],),
        ) == []


def test_sources_have_isolated_current_rows_and_events(
    switch_conn: sqlite3.Connection,
) -> None:
    from netctl.switch_store import collect_and_save_switch

    source_a = _source(switch_conn, "switch_a")
    source_b = _source(switch_conn, "switch_b")
    same_mac = "02:00:00:00:00:01"
    collect_and_save_switch(
        switch_conn,
        source_a,
        _FakeDriver(_snapshot((_entry(same_mac, 1),))),
        "2026-07-19T10:00:00Z",
    )
    collect_and_save_switch(
        switch_conn,
        source_b,
        _FakeDriver(_snapshot((_entry(same_mac, 2),))),
        "2026-07-19T10:00:00Z",
    )

    result = collect_and_save_switch(
        switch_conn, source_a, _FakeDriver(_snapshot(())), "2026-07-19T11:00:00Z"
    )

    remaining = _rows(
        switch_conn,
        "SELECT source_id, port_key FROM current_switch_fdb ORDER BY source_id",
    )
    assert remaining == [{"source_id": source_b["id"], "port_key": "ifindex:2"}]
    assert _rows(
        switch_conn,
        "SELECT source_id, event_type FROM switch_fdb_events WHERE collector_run_id = ?",
        (result["run_id"],),
    ) == [{"source_id": source_a["id"], "event_type": "disappeared"}]


def test_sql_failure_rolls_back_run_device_ports_capabilities_current_and_events(
    switch_conn: sqlite3.Connection,
) -> None:
    from netctl.switch_store import SwitchPersistenceError, collect_and_save_switch

    source = _source(switch_conn, "switch_a")
    collect_and_save_switch(
        switch_conn,
        source,
        _FakeDriver(_snapshot((_entry("02:00:00:00:00:01", 1),))),
        "2026-07-19T10:00:00Z",
    )
    tables = (
        "switch_collection_runs",
        "switch_devices",
        "switch_ports",
        "switch_capabilities",
        "current_switch_fdb",
        "switch_fdb_events",
    )
    before = {table: _rows(switch_conn, f"SELECT * FROM {table}") for table in tables}
    switch_conn.execute(
        """
        CREATE TRIGGER reject_moved_event
        BEFORE INSERT ON switch_fdb_events
        WHEN NEW.event_type = 'moved'
        BEGIN
            SELECT RAISE(ABORT, 'injected secret-bearing database failure');
        END
        """
    )
    switch_conn.commit()

    with pytest.raises(
        SwitchPersistenceError, match="^Switch collection persistence failed$"
    ) as exc_info:
        collect_and_save_switch(
            switch_conn,
            source,
            _FakeDriver(_snapshot((_entry("02:00:00:00:00:01", 9),))),
            "2026-07-19T11:00:00Z",
        )

    assert "secret-bearing" not in repr(exc_info.value)
    assert {
        table: _rows(switch_conn, f"SELECT * FROM {table}") for table in tables
    } == before


def test_commit_failure_rolls_back_live_transaction_and_all_mutations(
    tmp_path: Path,
) -> None:
    from netctl.switch_store import SwitchPersistenceError, collect_and_save_switch

    conn = sqlite3.connect(
        tmp_path / "commit-failure.db",
        factory=_FailCommitConnection,
    )
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    ensure_schema(conn)
    conn.commit()
    try:
        source = _source(conn, "switch_a")
        tables = (
            "switch_collection_runs",
            "switch_devices",
            "switch_ports",
            "switch_capabilities",
            "current_switch_fdb",
            "switch_fdb_events",
        )
        before = {table: _rows(conn, f"SELECT * FROM {table}") for table in tables}
        conn.fail_commit = True

        with pytest.raises(
            SwitchPersistenceError, match="^Switch collection persistence failed$"
        ) as exc_info:
            collect_and_save_switch(
                conn,
                source,
                _FakeDriver(_snapshot((_entry("02:00:00:00:00:01", 1),))),
                "2026-07-19T11:00:00Z",
            )

        assert "secret-bearing" not in repr(exc_info.value)
        assert conn.in_transaction is False
        assert {
            table: _rows(conn, f"SELECT * FROM {table}") for table in tables
        } == before
    finally:
        conn.fail_commit = False
        conn.rollback()
        conn.close()


def test_driver_failure_records_only_fixed_safe_error(
    switch_conn: sqlite3.Connection,
) -> None:
    from netctl.switch_store import collect_and_save_switch

    source = _source(switch_conn, "switch_a")

    result = collect_and_save_switch(
        switch_conn,
        source,
        _FakeDriver(RuntimeError("community private-value at host private-host")),
        "2026-07-19T10:00:00Z",
    )

    assert result["status"] == "failed"
    assert result["error_class"] == "collection_error"
    assert result["error_message"] == "Switch collection failed"
    run = _rows(switch_conn, "SELECT * FROM switch_collection_runs")[0]
    assert (run["status"], run["error_class"], run["error_message"]) == (
        "failed",
        "collection_error",
        "Switch collection failed",
    )
    assert "private-value" not in repr(run)
    assert "private-host" not in repr(run)


def test_source_lookup_database_error_is_fixed_and_safe(tmp_path: Path) -> None:
    from netctl.switch_store import SwitchPersistenceError, collect_and_save_switch

    conn = connect(f"sqlite:///{tmp_path / 'closed.db'}")
    source = _source(conn, "switch_a")
    conn.close()

    with pytest.raises(
        SwitchPersistenceError, match="^Switch collection persistence failed$"
    ) as exc_info:
        collect_and_save_switch(
            conn,
            source,
            _FakeDriver(_snapshot(())),
            "2026-07-19T11:00:00Z",
        )

    assert "closed database" not in repr(exc_info.value).lower()
