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


def _rows(conn: sqlite3.Connection, sql: str, params: tuple[Any, ...] = ()) -> list[dict[str, Any]]:
    return [dict(row) for row in conn.execute(sql, params).fetchall()]


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
