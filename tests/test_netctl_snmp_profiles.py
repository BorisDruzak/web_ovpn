from __future__ import annotations

import asyncio
from dataclasses import replace
import json
from pathlib import Path

import pytest

from netctl.snmp import CapabilityResult, SnmpOutcome, SnmpVarBind
from netctl.snmp.collector import collect_switch_snapshot
from netctl.snmp.models import SwitchSystem


_DGS_FIXTURE = Path(__file__).parent / "fixtures" / "snmp" / "dgs.json"
_SNR_FIXTURE = Path(__file__).parent / "fixtures" / "snmp" / "snr.json"
_TPLINK_FIXTURE = Path(__file__).parent / "fixtures" / "snmp" / "tplink.json"
_CSS326_FIXTURE = Path(__file__).parent / "fixtures" / "snmp" / "css326.json"


class _PagedFixtureTransport:
    def __init__(self, pages: list[dict[str, object]]) -> None:
        self.results: dict[tuple[int, ...], CapabilityResult] = {}
        for page in pages:
            request_oid = tuple(page["request_oid"])
            prior = self.results.get(request_oid)
            rows = tuple(
                SnmpVarBind(
                    oid=tuple(row["oid"]),
                    value_type=(
                        "octet_string"
                        if row["value_type"] == "octet_string_hex"
                        else row["value_type"]
                    ),
                    value=(
                        bytes.fromhex(row["value"])
                        if row["value_type"] == "octet_string_hex"
                        else row["value"].encode("utf-8")
                        if row["value_type"] == "octet_string"
                        else row["value"]
                    ),
                )
                for row in page["rows"]
            )
            outcome = SnmpOutcome(page["outcome"])
            self.results[request_oid] = CapabilityResult(
                capability=page["capability"],
                outcome=outcome,
                rows=(prior.rows if prior else ()) + rows,
            )

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


def _dgs_fixture_transport() -> _PagedFixtureTransport:
    fixture = json.loads(_DGS_FIXTURE.read_text(encoding="utf-8"))
    return _PagedFixtureTransport(fixture["pages"])


def _tplink_fixture_transport() -> _PagedFixtureTransport:
    fixture = json.loads(_TPLINK_FIXTURE.read_text(encoding="utf-8"))
    return _PagedFixtureTransport(fixture["pages"])


def _css326_fixture_transport() -> _PagedFixtureTransport:
    fixture = json.loads(_CSS326_FIXTURE.read_text(encoding="utf-8"))
    return _PagedFixtureTransport(fixture["pages"])


class _SnapshotDriver:
    def __init__(self, snapshot: object) -> None:
        self.snapshot = snapshot

    def collect(self) -> object:
        return self.snapshot


def _optional_seed(snapshot: object) -> object:
    vlan_row = {
        "vlan_id": 20,
        "port_key": "physical:5",
        "if_index": 5,
        "bridge_port": 5,
        "physical_port": 5,
        "port_name": "ether5",
        "egress": True,
        "untagged": False,
        "pvid": False,
    }
    lldp_row = {
        "local_port_key": "physical:5",
        "chassis_id": "00:11:22:33:44:55",
        "port_id": "uplink-5",
        "system_name": "seeded-neighbor",
    }
    return replace(
        snapshot,
        vlan_memberships=(vlan_row,),
        lldp_neighbors=(lldp_row,),
        capabilities=(
            *(
                row
                for row in snapshot.capabilities
                if row.capability
                not in {
                    "vlan_current_egress",
                    "vlan_current_untagged",
                    "pvid",
                    "lldp_remote",
                }
            ),
            CapabilityResult("vlan_current_egress", SnmpOutcome.SUCCESS_WITH_ROWS),
            CapabilityResult("vlan_current_untagged", SnmpOutcome.SUCCESS_EMPTY),
            CapabilityResult("pvid", SnmpOutcome.SUCCESS_EMPTY),
            CapabilityResult("lldp_remote", SnmpOutcome.SUCCESS_WITH_ROWS),
        ),
    )


def _persist_twice(tmp_path: Path, name: str, seeded: object, replacement: object):
    from netctl.db import connect, get_source, upsert_source
    from netctl.switch_store import collect_and_save_switch

    conn = connect(f"sqlite:///{tmp_path / f'{name}.db'}")
    upsert_source(
        conn,
        {
            "name": name,
            "driver": "snmp_switch",
            "host": "192.0.2.100",
            "port": 161,
            "username": "",
            "secret_ref": "fixture_ref",
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
    first = collect_and_save_switch(
        conn, source, _SnapshotDriver(seeded), "2026-07-20T01:00:00Z"
    )
    second = collect_and_save_switch(
        conn, source, _SnapshotDriver(replacement), "2026-07-20T02:00:00Z"
    )
    assert first["status"] == "success"
    assert second["status"] == "success"
    return conn


def test_tplink_fixture_normalizes_qbridge_fdb_ports() -> None:
    snapshot = asyncio.run(collect_switch_snapshot({}, _tplink_fixture_transport()))

    assert (snapshot.profile_id, snapshot.profile_fingerprint) == (
        "tplink",
        "tplink:v1",
    )
    by_mac = {entry.mac: entry.to_dict() for entry in snapshot.fdb}
    assert by_mac["C0:9B:F4:61:4B:CD"] == {
        "fdb_id": 20,
        "vlan_key": "vid:20",
        "vlan_id": 20,
        "mac": "C0:9B:F4:61:4B:CD",
        "port_key": "physical:48",
        "bridge_port": 48,
        "if_index": 49200,
        "physical_port": 48,
        "port_name": "port48",
        "status": "learned",
    }
    assert {
        mac: (by_mac[mac]["physical_port"], by_mac[mac]["if_index"])
        for mac in (
            "50:D4:F7:85:B5:5A",
            "2C:C8:1B:AB:53:C9",
            "2C:C8:1B:AB:47:23",
        )
    } == {
        "50:D4:F7:85:B5:5A": (31, 49183),
        "2C:C8:1B:AB:53:C9": (22, 49174),
        "2C:C8:1B:AB:47:23": (18, 49170),
    }


def test_tplink_unsupported_optional_groups_preserve_seeded_state(
    tmp_path: Path,
) -> None:
    snapshot = asyncio.run(collect_switch_snapshot({}, _tplink_fixture_transport()))
    outcomes = {
        row.capability: row.outcome
        for row in snapshot.capabilities
        if row.capability in {
            "vlan_current_egress",
            "vlan_current_untagged",
            "pvid",
            "lldp_remote",
        }
    }
    assert outcomes == {
        "vlan_current_egress": SnmpOutcome.UNSUPPORTED_NO_SUCH_OBJECT,
        "vlan_current_untagged": SnmpOutcome.UNSUPPORTED_NO_SUCH_OBJECT,
        "pvid": SnmpOutcome.UNSUPPORTED_NO_SUCH_OBJECT,
        "lldp_remote": SnmpOutcome.UNSUPPORTED_NO_SUCH_OBJECT,
    }
    assert len(snapshot.fdb) == 4

    conn = _persist_twice(
        tmp_path, "tplink-optional", _optional_seed(snapshot), snapshot
    )
    try:
        assert [tuple(row) for row in conn.execute(
            "SELECT vlan_id, port_key FROM current_switch_vlan_memberships"
        ).fetchall()] == [(20, "physical:5")]
        assert [tuple(row) for row in conn.execute(
            "SELECT local_port_key, system_name FROM current_switch_lldp_neighbors"
        ).fetchall()] == [("physical:5", "seeded-neighbor")]
    finally:
        conn.close()


def test_css326_fixture_uses_legacy_fdb_and_one_to_one_physical_ports() -> None:
    snapshot = asyncio.run(collect_switch_snapshot({}, _css326_fixture_transport()))

    assert (snapshot.profile_id, snapshot.profile_fingerprint) == (
        "css326",
        "css326:v1",
    )
    assert [
        (port.port_key, port.bridge_port, port.if_index, port.physical_port)
        for port in snapshot.ports
    ] == [(f"physical:{port}", port, port, port) for port in range(1, 27)]
    by_mac = {entry.mac: entry for entry in snapshot.fdb}
    assert {
        mac: (entry.port_key, entry.physical_port, entry.vlan_key)
        for mac, entry in by_mac.items()
    } == {
        "02:00:00:00:00:24": ("physical:24", 24, "legacy:unknown"),
        "02:00:00:00:00:13": ("physical:13", 13, "legacy:unknown"),
        "02:00:00:00:00:05": ("physical:5", 5, "legacy:unknown"),
    }
    assert next(
        row for row in snapshot.capabilities if row.capability == "qbridge_port"
    ).outcome is SnmpOutcome.UNSUPPORTED_NO_SUCH_OBJECT


def test_css326_empty_lldp_clears_only_lldp_current_state(tmp_path: Path) -> None:
    snapshot = asyncio.run(collect_switch_snapshot({}, _css326_fixture_transport()))
    assert next(
        row for row in snapshot.capabilities if row.capability == "lldp_remote"
    ).outcome is SnmpOutcome.SUCCESS_EMPTY

    conn = _persist_twice(
        tmp_path, "css326-empty-lldp", _optional_seed(snapshot), snapshot
    )
    try:
        assert [tuple(row) for row in conn.execute(
            "SELECT vlan_id, port_key FROM current_switch_vlan_memberships"
        ).fetchall()] == [(20, "physical:5")]
        assert conn.execute(
            "SELECT COUNT(*) FROM current_switch_lldp_neighbors"
        ).fetchone()[0] == 0
        assert conn.execute(
            "SELECT COUNT(*) FROM current_switch_fdb"
        ).fetchone()[0] == 3
    finally:
        conn.close()


def test_css326_fixture_is_sanitized_numeric_oid_data_without_secrets() -> None:
    fixture = json.loads(_CSS326_FIXTURE.read_text(encoding="utf-8"))
    serialized = _CSS326_FIXTURE.read_text(encoding="utf-8").lower()

    assert fixture["fixture_kind"] == "sanitized_numeric_oid_pages"
    assert all(
        all(type(part) is int for part in page["request_oid"])
        for page in fixture["pages"]
    )
    assert all(
        all(type(part) is int for part in row["oid"])
        for page in fixture["pages"]
        for row in page["rows"]
    )
    for forbidden in ("community", "secret", "host", "production", "192.168"):
        assert forbidden not in serialized


def test_tplink_prefers_qbridge_when_legacy_tables_are_also_valid() -> None:
    fixture = json.loads(_TPLINK_FIXTURE.read_text(encoding="utf-8"))
    capabilities = {page["capability"]: page for page in fixture["pages"]}

    assert {"legacy_address", "legacy_port", "legacy_status"} <= capabilities.keys()

    snapshot = asyncio.run(collect_switch_snapshot({}, _tplink_fixture_transport()))

    assert len(snapshot.fdb) == 4
    assert {entry.mac for entry in snapshot.fdb} == {
        "C0:9B:F4:61:4B:CD",
        "50:D4:F7:85:B5:5A",
        "2C:C8:1B:AB:53:C9",
        "2C:C8:1B:AB:47:23",
    }


def test_tplink_fixture_is_sanitized_numeric_oid_data_without_secrets() -> None:
    fixture = json.loads(_TPLINK_FIXTURE.read_text(encoding="utf-8"))
    serialized = _TPLINK_FIXTURE.read_text(encoding="utf-8").lower()

    assert fixture["fixture_kind"] == "sanitized_numeric_oid_pages"
    assert all(
        all(isinstance(part, int) for part in page["request_oid"])
        for page in fixture["pages"]
    )
    assert all(
        all(isinstance(part, int) for part in row["oid"])
        for page in fixture["pages"]
        for row in page["rows"]
    )
    for forbidden in ("community", "secret", "host", "production"):
        assert forbidden not in serialized


def test_tplink_fid_equals_vid_rule_is_bounded_to_valid_vlan_ids() -> None:
    from netctl.snmp.profiles import TplinkProfile

    profile = TplinkProfile()

    assert profile.resolve_fdb_vlan(fdb_id=4094, vids_by_fid={}) == (
        "vid:4094",
        4094,
    )
    assert profile.resolve_fdb_vlan(fdb_id=4095, vids_by_fid={}) == (
        "fid:4095",
        None,
    )


def test_tplink_missing_offset_ifindex_is_a_parse_error() -> None:
    from netctl.snmp.profiles import SnmpParseError, TplinkProfile

    with pytest.raises(
        SnmpParseError,
        match=r"TP-Link physical port 48 has no ifIndex 49200",
    ):
        TplinkProfile().resolve_fdb_port(
            raw_fdb_port=48,
            fdb_mode="qbridge",
            bridge_to_ifindex={},
            ports_by_ifindex={},
        )


def _snr_fixture_transport() -> _PagedFixtureTransport:
    """Expand only synthetic, sanitized FDB rows declared by the fixture."""
    from netctl.snmp.oids import (
        DOT1D_BASE_PORT_IFINDEX,
        DOT1Q_FDB_PORT,
        DOT1Q_FDB_STATUS,
        DOT1Q_PVID,
        IF_INDEX,
        IF_NAME,
    )

    fixture = json.loads(_SNR_FIXTURE.read_text(encoding="utf-8"))
    transport = _PagedFixtureTransport(fixture["pages"])
    synthetic = fixture["synthetic_fdb"]
    assert isinstance(synthetic, dict)
    count = synthetic["count"]
    assert isinstance(count, int)
    fdb_id = synthetic["fdb_id"]
    assert isinstance(fdb_id, int)
    raw_port = synthetic["raw_port"]
    assert isinstance(raw_port, int)
    layout = fixture["snr_port_layout"]
    assert isinstance(layout, dict)
    bridge_port_count = layout["bridge_port_count"]
    assert isinstance(bridge_port_count, int)
    first_ifindex = layout["first_ifindex"]
    assert isinstance(first_ifindex, int)
    lag_ifindex = layout["lag_ifindex"]
    assert isinstance(lag_ifindex, int)
    lag_bridge_port = layout["lag_bridge_port"]
    assert isinstance(lag_bridge_port, int)
    names = layout["names"]
    assert isinstance(names, dict)

    def _result(
        capability: str, rows: tuple[SnmpVarBind, ...]
    ) -> CapabilityResult:
        return CapabilityResult(capability, SnmpOutcome.SUCCESS_WITH_ROWS, rows)

    ifindex_rows = tuple(
        SnmpVarBind(IF_INDEX + (if_index,), "integer", if_index)
        for if_index in range(first_ifindex, first_ifindex + bridge_port_count)
    ) + (SnmpVarBind(IF_INDEX + (lag_ifindex,), "integer", lag_ifindex),)
    bridge_rows = tuple(
        SnmpVarBind(
            DOT1D_BASE_PORT_IFINDEX + (bridge_port,),
            "integer",
            first_ifindex + bridge_port - 1,
        )
        for bridge_port in range(1, bridge_port_count + 1)
    ) + (
        SnmpVarBind(
            DOT1D_BASE_PORT_IFINDEX + (lag_bridge_port,), "integer", lag_ifindex
        ),
    )
    name_rows = tuple(
        SnmpVarBind(IF_NAME + (int(if_index),), "octet_string", str(name).encode())
        for if_index, name in names.items()
    )
    pvid_rows = tuple(
        SnmpVarBind(DOT1Q_PVID + (bridge_port,), "integer", 1)
        for bridge_port in range(1, bridge_port_count + 1)
    ) + (SnmpVarBind(DOT1Q_PVID + (lag_bridge_port,), "integer", 1),)
    transport.results.update(
        {
            IF_INDEX: _result("if_index", ifindex_rows),
            IF_NAME: _result("if_name", name_rows),
            DOT1D_BASE_PORT_IFINDEX: _result("bridge_port_ifindex", bridge_rows),
            DOT1Q_PVID: _result("pvid", pvid_rows),
        }
    )

    port = transport.results[DOT1Q_FDB_PORT]
    status = transport.results[DOT1Q_FDB_STATUS]
    synthetic_port_rows = tuple(
        SnmpVarBind(
            oid=DOT1Q_FDB_PORT + (fdb_id, 2, 0, 0, 1, index // 256, index % 256),
            value_type="integer",
            value=raw_port,
        )
        for index in range(count)
    )
    synthetic_status_rows = tuple(
        SnmpVarBind(
            oid=DOT1Q_FDB_STATUS + (fdb_id, 2, 0, 0, 1, index // 256, index % 256),
            value_type="integer",
            value=3,
        )
        for index in range(count)
    )
    transport.results[DOT1Q_FDB_PORT] = CapabilityResult(
        port.capability, port.outcome, port.rows + synthetic_port_rows
    )
    transport.results[DOT1Q_FDB_STATUS] = CapabilityResult(
        status.capability, status.outcome, status.rows + synthetic_status_rows
    )
    return transport


def test_snr_fixture_collects_fdb_vlan_pvid_and_stp_profile() -> None:
    snapshot = asyncio.run(collect_switch_snapshot({}, _snr_fixture_transport()))

    assert (snapshot.profile_id, snapshot.profile_fingerprint) == ("snr", "snr:v1")
    assert len(snapshot.fdb) == 180
    by_mac = {entry.mac: entry.to_dict() for entry in snapshot.fdb}
    assert by_mac["D4:01:C3:9C:83:5F"] == {
        "fdb_id": 1,
        "vlan_key": "vid:1",
        "vlan_id": 1,
        "mac": "D4:01:C3:9C:83:5F",
        "port_key": "physical:24",
        "bridge_port": 24,
        "if_index": 5024,
        "physical_port": 24,
        "port_name": "ge24",
        "status": "learned",
    }
    assert {
        mac: by_mac[mac]["port_key"]
        for mac in (
            "BC:22:28:0C:EF:E0",
            "2C:C8:1B:AB:55:45",
            "1C:3B:F3:DC:C9:EB",
            "C0:9B:F4:61:4B:CD",
        )
    } == {
        "BC:22:28:0C:EF:E0": "physical:21",
        "2C:C8:1B:AB:55:45": "physical:22",
        "1C:3B:F3:DC:C9:EB": "physical:23",
        "C0:9B:F4:61:4B:CD": "physical:23",
    }
    assert by_mac["C0:9B:F4:61:4B:CD"]["vlan_key"] == "vid:20"
    assert any(
        entry.port_key == "lag:po1" and entry.if_index == 100001
        for entry in snapshot.fdb
    )
    vlan20 = [row for row in snapshot.vlan_memberships if row["vlan_id"] == 20]
    assert [(row["port_key"], row["port_name"], row["egress"]) for row in vlan20] == [
        ("physical:23", "ge23", True),
        ("physical:28", "xe3", True),
    ]
    assert len([row for row in snapshot.vlan_memberships if row["pvid"]]) == 29
    assert all(row["vlan_id"] == 1 for row in snapshot.vlan_memberships if row["pvid"])
    assert snapshot.stp == {
        "protocol": "rstp",
        "root_bridge_mac": "2C:C8:1B:9C:31:EA",
        "root_port_raw": 927,
        "root_port_key": "physical:23",
        "root_path_cost": 20000,
        "topology_changes": 7,
    }
    assert snapshot.lldp_neighbors == ()


def test_snr_vlan_bitmap_rejects_bridge_ports_missing_from_the_map() -> None:
    from netctl.snmp.models import SwitchPort
    from netctl.snmp.oids import DOT1Q_VLAN_CURRENT_EGRESS
    from netctl.snmp.profiles import SnrProfile
    from netctl.snmp.vlan import parse_vlan_memberships

    result = CapabilityResult(
        "vlan_current_egress",
        SnmpOutcome.SUCCESS_WITH_ROWS,
        (
            SnmpVarBind(
                DOT1Q_VLAN_CURRENT_EGRESS + (0, 1), "octet_string", b"\x80"
            ),
        ),
    )
    port = SwitchPort("ifindex:5002", 5002, 2, None, "ge2", "", None, "up", "up", None)

    with pytest.raises(ValueError, match="unknown bridge port"):
        parse_vlan_memberships(
            result,
            CapabilityResult("vlan_current_untagged", SnmpOutcome.SUCCESS_EMPTY),
            CapabilityResult("pvid", SnmpOutcome.SUCCESS_EMPTY),
            profile=SnrProfile(),
            ports=(port,),
            bridge_to_ifindex={2: 5002},
        )


def test_snr_profile_uses_ifindex_qbridge_ports_and_proven_exceptions() -> None:
    from netctl.snmp.models import SwitchPort, SwitchSystem
    from netctl.snmp.profiles import SnrProfile, detect_profile

    system = SwitchSystem("SNR fixture", "1.3.6.1.4.1.57206.1.1", "snr", "", None)
    ge23 = SwitchPort("ifindex:5023", 5023, 23, None, "ge23", "", None, "up", "up", None)
    po1 = SwitchPort("ifindex:100001", 100001, 65, None, "po1", "", None, "up", "up", None)
    profile = detect_profile(system)

    assert isinstance(profile, SnrProfile)
    assert profile.resolve_fdb_port(
        raw_fdb_port=5023,
        fdb_mode="qbridge",
        bridge_to_ifindex={23: 5023, 65: 100001},
        ports_by_ifindex={5023: ge23, 100001: po1},
    ).port_key == "physical:23"
    assert profile.resolve_fdb_port(
        raw_fdb_port=31071,
        fdb_mode="qbridge",
        bridge_to_ifindex={23: 5023, 65: 100001},
        ports_by_ifindex={5023: ge23, 100001: po1},
    ).to_dict() == {
        "port_key": "lag:po1",
        "if_index": 100001,
        "bridge_port": 65,
        "physical_port": None,
        "port_name": "po1",
    }
    assert profile.resolve_fdb_vlan(fdb_id=4094, vids_by_fid={}) == ("vid:4094", 4094)
    assert profile.resolve_fdb_vlan(fdb_id=4095, vids_by_fid={}) == ("fid:4095", None)


def test_snr_malformed_optional_vlan_is_a_sanitized_nonblocking_parse_error() -> None:
    from netctl.snmp.oids import DOT1Q_VLAN_CURRENT_EGRESS

    transport = _snr_fixture_transport()
    transport.results[DOT1Q_VLAN_CURRENT_EGRESS] = CapabilityResult(
        "vlan_current_egress",
        SnmpOutcome.SUCCESS_WITH_ROWS,
        (
            SnmpVarBind(
                DOT1Q_VLAN_CURRENT_EGRESS + (0, 20), "integer", 31071
            ),
        ),
    )

    snapshot = asyncio.run(collect_switch_snapshot({}, transport))
    capability = next(
        row for row in snapshot.capabilities if row.capability == "vlan_current_egress"
    )

    assert len(snapshot.fdb) == 180
    assert snapshot.vlan_memberships == ()
    assert capability.outcome is SnmpOutcome.PARSE_ERROR
    assert capability.error_code == "malformed_vlan"
    assert capability.error_message == "SNMP VLAN rows are malformed"
    assert capability.details == {}
    assert "31071" not in repr(snapshot.to_dict()["capabilities"])


def test_snr_malformed_optional_stp_is_a_sanitized_nonblocking_parse_error() -> None:
    from netctl.snmp.oids import DOT1D_STP_DESIGNATED_ROOT

    transport = _snr_fixture_transport()
    transport.results[DOT1D_STP_DESIGNATED_ROOT] = CapabilityResult(
        "stp_designated_root",
        SnmpOutcome.SUCCESS_WITH_ROWS,
        (
            SnmpVarBind(
                DOT1D_STP_DESIGNATED_ROOT, "octet_string", b"untrusted-payload"
            ),
        ),
    )

    snapshot = asyncio.run(collect_switch_snapshot({}, transport))
    capability = next(
        row for row in snapshot.capabilities if row.capability == "stp_designated_root"
    )

    assert len(snapshot.fdb) == 180
    assert snapshot.stp is None
    assert capability.outcome is SnmpOutcome.PARSE_ERROR
    assert capability.error_code == "malformed_stp"
    assert capability.error_message == "SNMP STP rows are malformed"
    assert capability.details == {}
    assert "untrusted-payload" not in repr(snapshot.to_dict()["capabilities"])


def test_dgs_fixture_selects_profile_and_normalizes_paginated_qbridge_fdb() -> None:
    snapshot = asyncio.run(collect_switch_snapshot({}, _dgs_fixture_transport()))

    assert (snapshot.profile_id, snapshot.profile_fingerprint) == (
        "dgs",
        "dgs:v1",
    )
    assert len(snapshot.fdb) == 3
    assert snapshot.ports[0].to_dict() == {
        "port_key": "ifindex:101",
        "if_index": 101,
        "bridge_port": 11,
        "physical_port": None,
        "name": "front-11",
        "alias": "",
        "mac": None,
        "admin_status": "unknown",
        "oper_status": "unknown",
        "speed_bps": None,
    }
    assert snapshot.fdb[0].to_dict() == {
        "fdb_id": 200,
        "vlan_key": "vid:200",
        "vlan_id": 200,
        "mac": "02:00:00:00:00:01",
        "port_key": "ifindex:101",
        "bridge_port": 11,
        "if_index": 101,
        "physical_port": 11,
        "port_name": "front-11",
        "status": "learned",
    }
    assert snapshot.fdb[-1].to_dict()["vlan_key"] == "vid:30"


def test_dgs_fid_equals_vid_and_port_normalization_cannot_leak_to_generic() -> None:
    from netctl.snmp.models import SwitchPort, SwitchSystem
    from netctl.snmp.profiles import DgsProfile, GenericProfile, detect_profile

    dgs_system = SwitchSystem(
        "WS6-DGS-1210-52/F1 6.20.007",
        "1.3.6.1.4.1.171.10.153.7.1",
        "dgs-synthetic",
        "",
        None,
    )
    non_dgs_system = SwitchSystem(
        "Synthetic switch", "1.3.6.1.4.1.99999.42", "synthetic", "", None
    )
    port = SwitchPort(
        "ifindex:101", 101, 11, None, "front-11", "", None, "up", "up", None
    )

    assert isinstance(detect_profile(dgs_system), DgsProfile)
    assert isinstance(detect_profile(non_dgs_system), GenericProfile)
    assert detect_profile(dgs_system).resolve_fdb_vlan(fdb_id=200, vids_by_fid={}) == (
        "vid:200",
        200,
    )
    assert detect_profile(dgs_system).resolve_fdb_vlan(fdb_id=5000, vids_by_fid={}) == (
        "fid:5000",
        None,
    )
    assert detect_profile(non_dgs_system).resolve_fdb_vlan(
        fdb_id=200, vids_by_fid={}
    ) == ("fid:200", None)
    assert GenericProfile().resolve_fdb_port(
        raw_fdb_port=11,
        fdb_mode="qbridge",
        bridge_to_ifindex={11: 101},
        ports_by_ifindex={101: port},
    ).physical_port is None
    assert detect_profile(dgs_system).resolve_fdb_port(
        raw_fdb_port=11,
        fdb_mode="qbridge",
        bridge_to_ifindex={11: 101},
        ports_by_ifindex={101: port},
    ).physical_port == 11


@pytest.mark.parametrize(
    "description",
    (
        "WS6-DGS-1210-52/F1 6.20.007",
        "WS6-DGS-1210-52/F9 9.99.999",
    ),
)
def test_dgs_selection_accepts_documented_model_with_firmware_suffix(
    description: str,
) -> None:
    from netctl.snmp.profiles import DgsProfile, detect_profile

    system = SwitchSystem(
        description, "1.3.6.1.4.1.171.10.153.7.1", "dgs", "", None
    )

    assert isinstance(detect_profile(system), DgsProfile)


@pytest.mark.parametrize(
    "system",
    (
        SwitchSystem(
            "DGS-SYNTHETIC", "1.3.6.1.4.1.171.10.153.7.1", "false-prefix", "", None
        ),
        SwitchSystem(
            "WS6-DGS-1210-520/F1 6.20.007",
            "1.3.6.1.4.1.171.10.153.7.1",
            "near-prefix",
            "",
            None,
        ),
        SwitchSystem(
            "WS6-DGS-1210-48/F1 6.20.007",
            "1.3.6.1.4.1.171.10.153.7.1",
            "other-model",
            "",
            None,
        ),
        SwitchSystem(
            "WS6-DGS-1210-52/F1 6.20.007",
            "1.3.6.1.4.1.171.10.153.7.2",
            "wrong-oid",
            "",
            None,
        ),
    ),
)
def test_dgs_selection_rejects_prefixes_other_models_and_wrong_oid(
    system: object,
) -> None:
    from netctl.snmp.profiles import GenericProfile, detect_profile

    assert isinstance(detect_profile(system), GenericProfile)


def test_dgs_physical_port_requires_bounded_unique_front_panel_mapping() -> None:
    from netctl.snmp.models import SwitchPort
    from netctl.snmp.profiles import DgsProfile

    front = SwitchPort(
        "ifindex:101", 101, 11, None, "front-11", "", None, "up", "up", None
    )
    cpu = SwitchPort(
        "ifindex:102", 102, 52, None, "cpu", "", None, "up", "up", None
    )
    invalid = SwitchPort(
        "ifindex:103", 103, 65535, None, "front-65535", "", None, "up", "up", None
    )
    duplicate = SwitchPort(
        "ifindex:104", 104, 13, None, "front-11", "", None, "up", "up", None
    )
    aggregate = SwitchPort(
        "ifindex:105", 105, 12, None, "aggregate", "", None, "up", "up", None
    )
    unknown = SwitchPort(
        "ifindex:106", 106, 13, None, "unknown", "", None, "up", "up", None
    )
    ports = {
        101: front,
        102: cpu,
        103: invalid,
        104: duplicate,
        105: aggregate,
        106: unknown,
    }
    bridge_map = {52: 102, 65535: 103, 12: 105, 13: 106}
    profile = DgsProfile()

    known = profile.resolve_fdb_port(
        raw_fdb_port=11,
        fdb_mode="qbridge",
        bridge_to_ifindex={11: 101},
        ports_by_ifindex={101: front},
    )
    cpu_resolution = profile.resolve_fdb_port(
        raw_fdb_port=52,
        fdb_mode="qbridge",
        bridge_to_ifindex=bridge_map,
        ports_by_ifindex=ports,
    )
    invalid_resolution = profile.resolve_fdb_port(
        raw_fdb_port=65535,
        fdb_mode="qbridge",
        bridge_to_ifindex=bridge_map,
        ports_by_ifindex=ports,
    )
    duplicate_resolution = profile.resolve_fdb_port(
        raw_fdb_port=11,
        fdb_mode="qbridge",
        bridge_to_ifindex={11: 104},
        ports_by_ifindex=ports,
    )
    aggregate_resolution = profile.resolve_fdb_port(
        raw_fdb_port=12,
        fdb_mode="qbridge",
        bridge_to_ifindex=bridge_map,
        ports_by_ifindex=ports,
    )
    unknown_resolution = profile.resolve_fdb_port(
        raw_fdb_port=13,
        fdb_mode="qbridge",
        bridge_to_ifindex=bridge_map,
        ports_by_ifindex=ports,
    )

    assert (known.port_key, known.physical_port) == ("ifindex:101", 11)
    assert (cpu_resolution.port_key, cpu_resolution.physical_port) == (
        "ifindex:102",
        None,
    )
    assert (invalid_resolution.port_key, invalid_resolution.physical_port) == (
        "ifindex:103",
        None,
    )
    assert (duplicate_resolution.port_key, duplicate_resolution.physical_port) == (
        "ifindex:104",
        None,
    )
    assert (aggregate_resolution.port_key, aggregate_resolution.physical_port) == (
        "ifindex:105",
        None,
    )
    assert (unknown_resolution.port_key, unknown_resolution.physical_port) == (
        "ifindex:106",
        None,
    )


def test_dgs_fixture_is_synthetic_numeric_oid_data_without_source_or_secrets() -> None:
    fixture = json.loads(_DGS_FIXTURE.read_text(encoding="utf-8"))
    serialized = _DGS_FIXTURE.read_text(encoding="utf-8").lower()

    assert fixture["fixture_kind"] == "sanitized_numeric_oid_pages"
    assert sum(page.get("capability") == "qbridge_port" for page in fixture["pages"]) == 2
    assert all(
        all(isinstance(part, int) for part in page["request_oid"])
        for page in fixture["pages"]
    )
    for forbidden in ("community", "secret", "host", "address", "backup", "production"):
        assert forbidden not in serialized


def test_unknown_identity_selects_generic_profile() -> None:
    from netctl.snmp.models import SwitchSystem
    from netctl.snmp.profiles import GenericProfile, detect_profile

    system = SwitchSystem("fixture", "1.3.6.1.4.1.99999", "sw", "", None)

    assert isinstance(detect_profile(system), GenericProfile)


@pytest.mark.parametrize(
    ("profile_hint", "system"),
    [
        (
            "generic",
            SwitchSystem("fixture", "1.3.6.1.4.1.99999", "sw", "", None),
        ),
        (
            "dgs",
            SwitchSystem(
                "WS6-DGS-1210-52/F1 6.20.007",
                "1.3.6.1.4.1.171.10.153.7.1",
                "dgs-fixture",
                "",
                None,
            ),
        ),
        (
            "snr",
            SwitchSystem(
                "SNR fixture",
                "1.3.6.1.4.1.57206.1.1",
                "snr-fixture",
                "",
                None,
            ),
        ),
        (
            "tplink",
            SwitchSystem(
                "TP-Link T1600G-52TS fixture",
                "1.3.6.1.4.1.11863.1.1",
                "tplink-fixture",
                "",
                None,
            ),
        ),
        (
            "css326",
            SwitchSystem(
                "MikroTik CSS326-24G-2S+ fixture",
                "1.3.6.1.4.1.14988.2",
                "css326-fixture",
                "",
                None,
            ),
        ),
    ],
)
def test_every_supported_explicit_profile_hint_selects_a_matching_profile(
    profile_hint: str,
    system: SwitchSystem,
) -> None:
    from netctl.snmp.profiles import detect_profile

    assert detect_profile(system, profile_hint=profile_hint).profile_id == profile_hint


@pytest.mark.parametrize("profile_hint", ["dgs", "snr", "tplink", "css326"])
def test_explicit_vendor_profile_hint_rejects_a_nonmatching_switch(
    profile_hint: str,
) -> None:
    from netctl.snmp.profiles import detect_profile

    system = SwitchSystem("fixture", "1.3.6.1.4.1.99999", "sw", "", None)

    with pytest.raises(ValueError, match="profile_hint"):
        detect_profile(system, profile_hint=profile_hint)


def test_config_and_runtime_reject_an_invalid_profile_hint() -> None:
    from netctl.config import normalize_source
    from netctl.snmp.profiles import detect_profile

    source = {
        "name": "switch-profile-parity",
        "driver": "snmp_switch",
        "host": "192.0.2.18",
        "secret_ref": "switch_profile_parity_snmp",
        "snmp_profile_hint": "unsupported",
    }
    system = SwitchSystem("fixture", "1.3.6.1.4.1.99999", "sw", "", None)

    with pytest.raises(ValueError, match="profile_hint"):
        normalize_source(source)
    with pytest.raises(ValueError, match="profile_hint"):
        detect_profile(system, profile_hint="unsupported")


@pytest.mark.parametrize("profile_hint", ["generic", "dgs", "snr", "tplink", "css326"])
def test_pr3a_config_accepts_every_runtime_profile_hint(profile_hint: str) -> None:
    from netctl.config import normalize_source
    from netctl.switch_profile_hints import SUPPORTED_SNMP_PROFILE_HINTS

    normalized = normalize_source(
        {
            "name": "switch-profile-parity",
            "driver": "snmp_switch",
            "host": "192.0.2.18",
            "secret_ref": "switch_profile_parity_snmp",
            "snmp_profile_hint": profile_hint,
        }
    )

    assert normalized["driver_options"]["profile_hint"] == profile_hint
    assert SUPPORTED_SNMP_PROFILE_HINTS == frozenset(
        {"generic", "dgs", "snr", "tplink", "css326"}
    )


@pytest.mark.parametrize(
    ("profile_id", "sys_object_id"),
    [
        ("snr", "1.3.6.1.4.1.57206.1.1"),
        ("tplink", "1.3.6.1.4.1.11863.1.1"),
        ("css326", "1.3.6.1.4.1.14988.2"),
    ],
)
def test_normalized_hint_free_source_auto_detects_vendor_fixture_profile(
    profile_id: str,
    sys_object_id: str,
) -> None:
    from netctl.config import normalize_source

    source = normalize_source(
        {
            "name": f"switch-{profile_id}",
            "driver": "snmp_switch",
            "host": "192.0.2.18",
            "secret_ref": f"switch_{profile_id}_snmp",
        }
    )
    transport_factory = {
        "snr": _snr_fixture_transport,
        "tplink": _tplink_fixture_transport,
        "css326": _css326_fixture_transport,
    }[profile_id]

    assert "profile_hint" not in source["driver_options"]
    snapshot = asyncio.run(collect_switch_snapshot(source, transport_factory()))
    assert snapshot.profile_id == profile_id
    assert snapshot.system.sys_object_id == sys_object_id


def test_generic_profile_requires_explicit_fid_mapping() -> None:
    from netctl.snmp.profiles import GenericProfile

    profile = GenericProfile()

    assert profile.resolve_fdb_vlan(fdb_id=777, vids_by_fid={}) == ("fid:777", None)
    assert profile.resolve_fdb_vlan(fdb_id=777, vids_by_fid={777: {12}}) == (
        "vid:12",
        12,
    )
    assert profile.resolve_fdb_vlan(fdb_id=777, vids_by_fid={777: {12, 13}}) == (
        "fid:777",
        None,
    )


def test_generic_profile_rejects_unknown_or_ambiguous_port_mapping() -> None:
    from netctl.snmp.models import SwitchPort
    from netctl.snmp.profiles import GenericProfile

    profile = GenericProfile()
    port = SwitchPort("ifindex:3", 3, 1, None, "p3", "", None, "up", "up", None)

    with pytest.raises(ValueError, match="unknown bridge port"):
        profile.resolve_fdb_port(
            raw_fdb_port=8,
            fdb_mode="qbridge",
            bridge_to_ifindex={1: 3},
            ports_by_ifindex={3: port},
        )

    with pytest.raises(ValueError, match="unknown ifIndex"):
        profile.resolve_fdb_port(
            raw_fdb_port=1,
            fdb_mode="qbridge",
            bridge_to_ifindex={1: 4},
            ports_by_ifindex={3: port},
        )


def test_profile_and_snapshot_serialization_are_explicit() -> None:
    from netctl.snmp import CapabilityResult, SnmpOutcome
    from netctl.snmp.models import SwitchSnapshot, SwitchSystem

    snapshot = SwitchSnapshot(
        snapshot_kind="snmp_switch",
        profile_id="generic",
        profile_fingerprint="generic:v1",
        system=SwitchSystem("fixture", "1.3.6.1.4.1.99999", "sw", "", None),
        ports=(),
        fdb=(),
        vlan_memberships=(),
        stp=None,
        lldp_neighbors=(),
        counter_samples=(),
        capabilities=(
            CapabilityResult(
                capability="qbridge_port",
                outcome=SnmpOutcome.PARSE_ERROR,
                error_code="malformed_value",
                error_message="sanitized",
                details={"raw_topology": "must-not-serialize"},
            ),
        ),
    )

    value = snapshot.to_dict()

    assert value["capabilities"] == [
        {
            "capability": "qbridge_port",
            "outcome": "parse_error",
            "error_code": "malformed_value",
            "error_message": "sanitized",
        }
    ]
    assert "raw_topology" not in repr(value)
