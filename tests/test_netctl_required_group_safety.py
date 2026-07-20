from __future__ import annotations

import asyncio
import sqlite3
from pathlib import Path
from typing import Any

import pytest

from netctl.db import connect, get_source, upsert_source
from netctl.snmp.collector import collect_switch_snapshot
from netctl.snmp.models import (
    CapabilityResult,
    SnmpVarBind,
    SwitchFdbEntry,
    SwitchPort,
    SwitchSnapshot,
    SwitchSystem,
)
from netctl.snmp.oids import (
    DOT1D_BASE_PORT_IFINDEX,
    DOT1Q_FDB_PORT,
    IF_ADMIN_STATUS,
    IF_ALIAS,
    IF_DESCR,
    IF_HIGH_SPEED,
    IF_INDEX,
    IF_NAME,
    IF_OPER_STATUS,
    IF_PHYS_ADDRESS,
    IF_SPEED,
    SYS_DESCR,
    SYS_LOCATION,
    SYS_NAME,
    SYS_OBJECT_ID,
    SYS_UPTIME,
)
from netctl.snmp.outcomes import SnmpOutcome
from netctl.switch_store import collect_and_save_switch


class _FixtureTransport:
    def __init__(self, results: dict[tuple[int, ...], CapabilityResult]) -> None:
        self.results = results

    async def get(
        self, oid: tuple[int, ...], *, capability: str = ""
    ) -> CapabilityResult:
        return self.results.get(
            oid, CapabilityResult(capability, SnmpOutcome.SUCCESS_EMPTY)
        )

    async def walk(
        self, oid: tuple[int, ...], *, capability: str = ""
    ) -> CapabilityResult:
        return self.results.get(
            oid, CapabilityResult(capability, SnmpOutcome.SUCCESS_EMPTY)
        )


class _SnapshotDriver:
    def __init__(self, snapshot: SwitchSnapshot) -> None:
        self.snapshot = snapshot

    def collect(self) -> SwitchSnapshot:
        return self.snapshot


def _row(
    oid: tuple[int, ...], value: int | str | bytes, value_type: str
) -> SnmpVarBind:
    return SnmpVarBind(oid, value_type, value)


def _success(capability: str, row: SnmpVarBind) -> CapabilityResult:
    return CapabilityResult(capability, SnmpOutcome.SUCCESS_WITH_ROWS, rows=(row,))


def _usable_required_results() -> dict[tuple[int, ...], CapabilityResult]:
    index = (1,)
    return {
        SYS_DESCR: _success(
            "sys_descr", _row(SYS_DESCR, b"Fixture switch", "octet_string")
        ),
        SYS_OBJECT_ID: _success(
            "sys_object_id",
            _row(SYS_OBJECT_ID, "1.3.6.1.4.1.99999.1", "object_identifier"),
        ),
        SYS_UPTIME: _success("sys_uptime", _row(SYS_UPTIME, 123, "time_ticks")),
        SYS_NAME: _success("sys_name", _row(SYS_NAME, b"fixture", "octet_string")),
        SYS_LOCATION: _success(
            "sys_location", _row(SYS_LOCATION, b"lab", "octet_string")
        ),
        IF_INDEX: _success("if_index", _row(IF_INDEX + index, 1, "integer")),
        IF_DESCR: _success(
            "if_descr", _row(IF_DESCR + index, b"port1", "octet_string")
        ),
        IF_SPEED: _success(
            "if_speed", _row(IF_SPEED + index, 1_000_000_000, "gauge32")
        ),
        IF_PHYS_ADDRESS: _success(
            "if_phys_address",
            _row(IF_PHYS_ADDRESS + index, b"\x02\x00\x00\x00\x00\x01", "octet_string"),
        ),
        IF_ADMIN_STATUS: _success(
            "if_admin_status", _row(IF_ADMIN_STATUS + index, 1, "integer")
        ),
        IF_OPER_STATUS: _success(
            "if_oper_status", _row(IF_OPER_STATUS + index, 1, "integer")
        ),
        IF_NAME: _success("if_name", _row(IF_NAME + index, b"port1", "octet_string")),
        IF_HIGH_SPEED: _success(
            "if_high_speed", _row(IF_HIGH_SPEED + index, 1_000, "gauge32")
        ),
        IF_ALIAS: _success("if_alias", _row(IF_ALIAS + index, b"", "octet_string")),
        DOT1D_BASE_PORT_IFINDEX: _success(
            "bridge_port_ifindex",
            _row(DOT1D_BASE_PORT_IFINDEX + index, 1, "integer"),
        ),
        DOT1Q_FDB_PORT: CapabilityResult("qbridge_port", SnmpOutcome.SUCCESS_EMPTY),
    }


def _source(conn: sqlite3.Connection) -> dict[str, Any]:
    upsert_source(
        conn,
        {
            "name": "required-safety",
            "driver": "snmp_switch",
            "host": "192.0.2.1",
            "port": 161,
            "username": "",
            "secret_ref": "required_safety_secret",
            "tls": False,
            "verify_tls": False,
            "site": "test",
            "role": "switch",
            "enabled": False,
            "driver_options": {},
        },
    )
    source = get_source(conn, "required-safety")
    assert source is not None
    return source


def _seed_snapshot() -> SwitchSnapshot:
    entry = SwitchFdbEntry(
        fdb_id=20,
        vlan_key="vid:20",
        vlan_id=20,
        mac="02:00:00:00:00:01",
        port_key="ifindex:1",
        bridge_port=1,
        if_index=1,
        physical_port=1,
        port_name="port1",
        status="learned",
    )
    port = SwitchPort(
        port_key="ifindex:1",
        if_index=1,
        bridge_port=1,
        physical_port=1,
        name="port1",
        alias="",
        mac=None,
        admin_status="up",
        oper_status="up",
        speed_bps=1_000_000_000,
    )
    return SwitchSnapshot(
        snapshot_kind="snmp_switch",
        profile_id="fixture",
        profile_fingerprint="fixture:v1",
        system=SwitchSystem(
            "Fixture switch", "1.3.6.1.4.1.99999.1", "fixture", "lab", 123
        ),
        ports=(port,),
        fdb=(entry,),
        vlan_memberships=(),
        stp=None,
        lldp_neighbors=(),
        counter_samples=(),
        capabilities=(CapabilityResult("fdb", SnmpOutcome.SUCCESS_WITH_ROWS),),
    )


@pytest.mark.parametrize(
    ("failed_oid", "failed_capability", "failed_outcome"),
    [
        (
            DOT1D_BASE_PORT_IFINDEX,
            "bridge_port_ifindex",
            SnmpOutcome.TIMEOUT,
        ),
        (SYS_DESCR, "sys_descr", SnmpOutcome.TIMEOUT),
        (IF_INDEX, "if_index", SnmpOutcome.AUTH_OR_VIEW_FAILURE),
    ],
)
def test_required_group_failure_makes_qbridge_empty_non_replacing(
    tmp_path: Path,
    failed_oid: tuple[int, ...],
    failed_capability: str,
    failed_outcome: SnmpOutcome,
) -> None:
    conn = connect(f"sqlite:///{tmp_path / 'required-safety.db'}")
    try:
        source = _source(conn)
        seeded = collect_and_save_switch(
            conn,
            source,
            _SnapshotDriver(_seed_snapshot()),
            "2026-07-20T10:00:00Z",
        )
        assert seeded["status"] == "success"

        results = _usable_required_results()
        results[failed_oid] = CapabilityResult(
            failed_capability,
            failed_outcome,
            error_code="private_backend_code",
            error_message="private backend detail must not escape",
        )
        snapshot = asyncio.run(
            collect_switch_snapshot(source, _FixtureTransport(results))
        )
        final_fdb = next(
            capability
            for capability in snapshot.capabilities
            if capability.capability == "fdb"
        )

        assert final_fdb.outcome is failed_outcome
        assert final_fdb.error_code == "required_capability_failed"
        assert final_fdb.error_message == "Required SNMP collection was not successful"
        assert "private backend" not in repr(final_fdb)

        failed = collect_and_save_switch(
            conn,
            source,
            _SnapshotDriver(snapshot),
            "2026-07-20T11:00:00Z",
        )

        assert (failed["status"], failed["fdb_outcome"]) == (
            "failed",
            failed_outcome.value,
        )
        assert failed["counts"] == {
            "ports": 0,
            "fdb_current": 1,
            "appeared": 0,
            "moved": 0,
            "disappeared": 0,
        }
        assert [
            dict(row)
            for row in conn.execute(
                "SELECT vlan_key, mac, port_key FROM current_switch_fdb"
            )
        ] == [
            {
                "vlan_key": "vid:20",
                "mac": "02:00:00:00:00:01",
                "port_key": "ifindex:1",
            }
        ]
        assert (
            conn.execute(
                "SELECT COUNT(*) FROM switch_fdb_events "
                "WHERE event_type = 'disappeared'"
            ).fetchone()[0]
            == 0
        )
    finally:
        conn.close()
