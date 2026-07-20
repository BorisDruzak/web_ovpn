from __future__ import annotations

import asyncio

import pytest

from netctl.snmp import CapabilityResult, SnmpOutcome, SnmpVarBind
from netctl.snmp.oids import (
    DOT1D_BASE_PORT_IFINDEX,
    DOT1D_FDB_ADDRESS,
    DOT1D_FDB_PORT,
    DOT1D_FDB_STATUS,
    DOT1Q_FDB_PORT,
    DOT1Q_FDB_STATUS,
    DOT1Q_VLAN_FDB_ID,
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
    LLDP_REM_CHASSIS_ID,
    LLDP_REM_PORT_ID,
    LLDP_REM_SYS_NAME,
)


def _vb(
    oid: tuple[int, ...], value: int | str | bytes, value_type: str = "integer"
) -> SnmpVarBind:
    return SnmpVarBind(oid=oid, value_type=value_type, value=value)


def _result(
    capability: str,
    *rows: SnmpVarBind,
    outcome: SnmpOutcome | None = None,
) -> CapabilityResult:
    return CapabilityResult(
        capability=capability,
        outcome=outcome
        or (SnmpOutcome.SUCCESS_WITH_ROWS if rows else SnmpOutcome.SUCCESS_EMPTY),
        rows=rows,
    )


def test_system_scalars_are_strictly_typed_and_serialized() -> None:
    from netctl.snmp.system import parse_system

    system = parse_system(
        (
            _vb(SYS_DESCR, b"Fixture switch", "octet_string"),
            _vb(SYS_OBJECT_ID, "1.3.6.1.4.1.99999", "object_identifier"),
            _vb(SYS_NAME, b"switch-fixture", "octet_string"),
            _vb(SYS_LOCATION, b"lab", "octet_string"),
            _vb(SYS_UPTIME, 12345, "time_ticks"),
        )
    )

    assert system.to_dict() == {
        "sys_descr": "Fixture switch",
        "sys_object_id": "1.3.6.1.4.1.99999",
        "sys_name": "switch-fixture",
        "sys_location": "lab",
        "sys_uptime_ticks": 12345,
    }


def test_system_rejects_wrong_scalar_type() -> None:
    from netctl.snmp.system import parse_system

    with pytest.raises(ValueError, match="sysName"):
        parse_system((_vb(SYS_NAME, 7),))


def test_system_uptime_requires_timeticks_not_another_integer_type() -> None:
    from netctl.snmp.system import parse_system

    with pytest.raises(ValueError, match="sysUpTime"):
        parse_system((_vb(SYS_UPTIME, 7, "counter32"),))


def test_interfaces_join_if_table_ifx_table_and_bridge_map() -> None:
    from netctl.snmp.interfaces import parse_bridge_port_map, parse_interfaces

    bridge_map = parse_bridge_port_map(
        (_vb(DOT1D_BASE_PORT_IFINDEX + (7,), 101),)
    )
    ports = parse_interfaces(
        (
            _vb(IF_INDEX + (101,), 101),
            _vb(IF_DESCR + (101,), b"GigabitEthernet1/0/7", "octet_string"),
            _vb(IF_SPEED + (101,), 0, "gauge32"),
            _vb(IF_PHYS_ADDRESS + (101,), b"\x00\x11\x22\xaa\xbb\xcc", "octet_string"),
            _vb(IF_ADMIN_STATUS + (101,), 1),
            _vb(IF_OPER_STATUS + (101,), 2),
        ),
        (
            _vb(IF_NAME + (101,), b"Gi1/0/7", "octet_string"),
            _vb(IF_ALIAS + (101,), b"uplink fixture", "octet_string"),
            _vb(IF_HIGH_SPEED + (101,), 1000, "gauge32"),
        ),
        bridge_map,
    )

    assert len(ports) == 1
    assert ports[0].to_dict() == {
        "port_key": "ifindex:101",
        "if_index": 101,
        "bridge_port": 7,
        "physical_port": None,
        "name": "Gi1/0/7",
        "alias": "uplink fixture",
        "mac": "00:11:22:AA:BB:CC",
        "admin_status": "up",
        "oper_status": "down",
        "speed_bps": 1_000_000_000,
    }


def test_interface_parser_rejects_conflicting_duplicate_and_ambiguous_bridge_map() -> None:
    from netctl.snmp.interfaces import parse_bridge_port_map, parse_interfaces

    with pytest.raises(ValueError, match="conflicting ifIndex"):
        parse_interfaces(
            (_vb(IF_INDEX + (5,), 5), _vb(IF_INDEX + (5,), 6)), (), {}
        )

    with pytest.raises(ValueError, match="ambiguous bridge"):
        parse_bridge_port_map(
            (
                _vb(DOT1D_BASE_PORT_IFINDEX + (1,), 9),
                _vb(DOT1D_BASE_PORT_IFINDEX + (2,), 9),
            )
        )


def test_interface_and_bridge_indices_require_integer_asn1_type() -> None:
    from netctl.snmp.interfaces import parse_bridge_port_map, parse_interfaces

    with pytest.raises(ValueError, match="ifIndex"):
        parse_interfaces((_vb(IF_INDEX + (5,), 5, "time_ticks"),), (), {})

    with pytest.raises(ValueError, match="dot1dBasePortIfIndex"):
        parse_bridge_port_map(
            (_vb(DOT1D_BASE_PORT_IFINDEX + (5,), 5, "time_ticks"),)
        )


def test_interface_status_rejects_values_outside_asn1_domain() -> None:
    from netctl.snmp.interfaces import parse_interfaces

    with pytest.raises(ValueError, match="ifAdminStatus"):
        parse_interfaces(
            (
                _vb(IF_INDEX + (5,), 5),
                _vb(IF_ADMIN_STATUS + (5,), 4),
            ),
            (),
            {},
        )


def test_bridge_map_rejects_ifindex_missing_from_parsed_interfaces() -> None:
    from netctl.snmp.interfaces import parse_interfaces

    with pytest.raises(ValueError, match="unknown ifIndex"):
        parse_interfaces(
            (_vb(IF_INDEX + (5,), 5),),
            (),
            {1: 5, 2: 6},
        )

def _one_port() -> tuple[object, dict[int, int]]:
    from netctl.snmp.interfaces import parse_interfaces

    ports = parse_interfaces(
        (
            _vb(IF_INDEX + (101,), 101),
            _vb(IF_NAME + (101,), b"Gi1/0/7", "octet_string"),
        ),
        (),
        {7: 101},
    )
    return ports, {7: 101}


def test_qbridge_decodes_fid_mac_and_never_assumes_fid_is_vid() -> None:
    from netctl.snmp.fdb import parse_qbridge_fdb
    from netctl.snmp.profiles import GenericProfile

    ports, bridge_map = _one_port()
    index = (4097, 0, 17, 34, 170, 187, 204)
    entries = parse_qbridge_fdb(
        _result("qbridge_port", _vb(DOT1Q_FDB_PORT + index, 7)),
        _result("qbridge_status", _vb(DOT1Q_FDB_STATUS + index, 3)),
        _result("vlan_fdb_id"),
        profile=GenericProfile(),
        ports=ports,
        bridge_to_ifindex=bridge_map,
    )

    assert entries[0].to_dict() == {
        "fdb_id": 4097,
        "vlan_key": "fid:4097",
        "vlan_id": None,
        "mac": "00:11:22:AA:BB:CC",
        "port_key": "ifindex:101",
        "bridge_port": 7,
        "if_index": 101,
        "physical_port": None,
        "port_name": "Gi1/0/7",
        "status": "learned",
    }


def test_qbridge_maps_exactly_one_vid_to_fid_but_not_multiple_vids() -> None:
    from netctl.snmp.fdb import parse_qbridge_fdb
    from netctl.snmp.profiles import GenericProfile

    ports, bridge_map = _one_port()
    index = (55, 2, 0, 0, 0, 0, 1)
    base = (
        _result("qbridge_port", _vb(DOT1Q_FDB_PORT + index, 7)),
        _result("qbridge_status", _vb(DOT1Q_FDB_STATUS + index, 4)),
    )
    single = parse_qbridge_fdb(
        *base,
        _result(
            "vlan_fdb_id",
            _vb(DOT1Q_VLAN_FDB_ID + (0, 20), 55, "unsigned32"),
        ),
        profile=GenericProfile(),
        ports=ports,
        bridge_to_ifindex=bridge_map,
    )
    multiple = parse_qbridge_fdb(
        *base,
        _result(
            "vlan_fdb_id",
            _vb(DOT1Q_VLAN_FDB_ID + (0, 20), 55, "unsigned32"),
            _vb(DOT1Q_VLAN_FDB_ID + (0, 30), 55, "unsigned32"),
        ),
        profile=GenericProfile(),
        ports=ports,
        bridge_to_ifindex=bridge_map,
    )

    assert (single[0].vlan_key, single[0].vlan_id) == ("vid:20", 20)
    assert (multiple[0].vlan_key, multiple[0].vlan_id) == ("fid:55", None)


def test_vlan_fdb_mapping_requires_timemark_and_vlan_index() -> None:
    from netctl.snmp.fdb import parse_qbridge_fdb
    from netctl.snmp.profiles import GenericProfile

    ports, bridge_map = _one_port()
    index = (55, 2, 0, 0, 0, 0, 1)
    with pytest.raises(ValueError, match="VLAN FDB OID index"):
        parse_qbridge_fdb(
            _result("qbridge_port", _vb(DOT1Q_FDB_PORT + index, 7)),
            _result("qbridge_status", _vb(DOT1Q_FDB_STATUS + index, 3)),
            _result(
                "vlan_fdb_id",
                _vb(DOT1Q_VLAN_FDB_ID + (20,), 55, "unsigned32"),
            ),
            profile=GenericProfile(),
            ports=ports,
            bridge_to_ifindex=bridge_map,
        )


def test_fdb_status_requires_integer_not_counter64() -> None:
    from netctl.snmp.fdb import parse_qbridge_fdb
    from netctl.snmp.profiles import GenericProfile

    ports, bridge_map = _one_port()
    index = (55, 2, 0, 0, 0, 0, 1)
    with pytest.raises(ValueError, match="FDB status"):
        parse_qbridge_fdb(
            _result("qbridge_port", _vb(DOT1Q_FDB_PORT + index, 7)),
            _result(
                "qbridge_status",
                _vb(DOT1Q_FDB_STATUS + index, 3, "counter64"),
            ),
            _result("vlan_fdb_id"),
            profile=GenericProfile(),
            ports=ports,
            bridge_to_ifindex=bridge_map,
        )


def test_fdb_status_rejects_values_outside_asn1_domain() -> None:
    from netctl.snmp.fdb import parse_qbridge_fdb
    from netctl.snmp.profiles import GenericProfile

    ports, bridge_map = _one_port()
    index = (55, 2, 0, 0, 0, 0, 1)
    with pytest.raises(ValueError, match="FDB status"):
        parse_qbridge_fdb(
            _result("qbridge_port", _vb(DOT1Q_FDB_PORT + index, 7)),
            _result("qbridge_status", _vb(DOT1Q_FDB_STATUS + index, 6)),
            _result("vlan_fdb_id"),
            profile=GenericProfile(),
            ports=ports,
            bridge_to_ifindex=bridge_map,
        )


@pytest.mark.parametrize("bad_octet", [-1, 256])
def test_qbridge_rejects_malformed_mac_octets(bad_octet: int) -> None:
    from netctl.snmp.fdb import parse_qbridge_fdb
    from netctl.snmp.profiles import GenericProfile

    ports, bridge_map = _one_port()
    index = (55, bad_octet, 0, 0, 0, 0, 1)
    with pytest.raises(ValueError, match="MAC"):
        parse_qbridge_fdb(
            _result("qbridge_port", _vb(DOT1Q_FDB_PORT + index, 7)),
            _result("qbridge_status", _vb(DOT1Q_FDB_STATUS + index, 3)),
            _result("vlan_fdb_id"),
            profile=GenericProfile(),
            ports=ports,
            bridge_to_ifindex=bridge_map,
        )


def test_legacy_fdb_joins_address_port_status_by_mac() -> None:
    from netctl.snmp.fdb import parse_legacy_fdb
    from netctl.snmp.profiles import GenericProfile

    ports, bridge_map = _one_port()
    mac_index = (0, 17, 34, 170, 187, 204)
    entries = parse_legacy_fdb(
        _result(
            "legacy_address",
            _vb(DOT1D_FDB_ADDRESS + mac_index, b"\x00\x11\x22\xaa\xbb\xcc", "octet_string"),
        ),
        _result("legacy_port", _vb(DOT1D_FDB_PORT + mac_index, 7)),
        _result("legacy_status", _vb(DOT1D_FDB_STATUS + mac_index, 3)),
        profile=GenericProfile(),
        ports=ports,
        bridge_to_ifindex=bridge_map,
    )

    assert entries[0].vlan_key == "legacy:unknown"
    assert entries[0].fdb_id is None
    assert entries[0].vlan_id is None
    assert entries[0].mac == "00:11:22:AA:BB:CC"


def test_lldp_joins_remote_columns_and_resolves_local_bridge_port() -> None:
    from netctl.snmp.lldp import parse_lldp_neighbors
    from netctl.snmp.models import SwitchPort

    suffix = (1234, 5, 9)
    port = SwitchPort(
        "physical:5", 5, 5, 5, "ether5", "", None, "up", "up", None
    )

    neighbors = parse_lldp_neighbors(
        _result(
            "lldp_remote_chassis_id",
            _vb(
                LLDP_REM_CHASSIS_ID + suffix,
                b"\x00\x11\x22\x33\x44\x55",
                "octet_string",
            ),
        ),
        _result(
            "lldp_remote_port_id",
            _vb(LLDP_REM_PORT_ID + suffix, b"uplink-5", "octet_string"),
        ),
        _result(
            "lldp_remote_system_name",
            _vb(LLDP_REM_SYS_NAME + suffix, b"edge-fixture", "octet_string"),
        ),
        ports=(port,),
    )

    assert neighbors == (
        {
            "local_port_key": "physical:5",
            "chassis_id": "00:11:22:33:44:55",
            "port_id": "uplink-5",
            "system_name": "edge-fixture",
        },
    )


@pytest.mark.parametrize(
    ("chassis_oid", "chassis_type", "chassis_value"),
    [
        (LLDP_REM_CHASSIS_ID[:-1] + (99, 1, 5, 9), "octet_string", b"chassis"),
        (LLDP_REM_CHASSIS_ID + (1, 5), "octet_string", b"chassis"),
        (LLDP_REM_CHASSIS_ID + (1, 5, 9), "integer", 7),
    ],
)
def test_lldp_rejects_unexpected_oid_suffix_or_value_type(
    chassis_oid: tuple[int, ...], chassis_type: str, chassis_value: int | bytes
) -> None:
    from netctl.snmp.lldp import parse_lldp_neighbors
    from netctl.snmp.models import SwitchPort

    suffix = (1, 5, 9)
    port = SwitchPort("ifindex:5", 5, 5, None, "p5", "", None, "up", "up", None)

    with pytest.raises(ValueError, match="LLDP"):
        parse_lldp_neighbors(
            _result(
                "lldp_remote_chassis_id",
                _vb(chassis_oid, chassis_value, chassis_type),
            ),
            _result(
                "lldp_remote_port_id",
                _vb(LLDP_REM_PORT_ID + suffix, b"p5", "octet_string"),
            ),
            _result(
                "lldp_remote_system_name",
                _vb(LLDP_REM_SYS_NAME + suffix, b"neighbor", "octet_string"),
            ),
            ports=(port,),
        )


def test_malformed_lldp_is_sanitized_and_never_fails_fdb() -> None:
    from netctl.snmp.collector import collect_switch_snapshot

    suffix = (1, 5, 9)
    transport = _FixtureTransport(
        {
            IF_INDEX: _result("if_index", _vb(IF_INDEX + (5,), 5)),
            DOT1D_BASE_PORT_IFINDEX: _result(
                "bridge_port_ifindex", _vb(DOT1D_BASE_PORT_IFINDEX + (5,), 5)
            ),
            DOT1Q_FDB_PORT: _result("qbridge_port"),
            LLDP_REM_CHASSIS_ID: _result(
                "lldp_remote_chassis_id",
                _vb(LLDP_REM_CHASSIS_ID + suffix, 31071, "integer"),
            ),
            LLDP_REM_PORT_ID: _result(
                "lldp_remote_port_id",
                _vb(LLDP_REM_PORT_ID + suffix, b"p5", "octet_string"),
            ),
            LLDP_REM_SYS_NAME: _result(
                "lldp_remote_system_name",
                _vb(LLDP_REM_SYS_NAME + suffix, b"neighbor", "octet_string"),
            ),
        }
    )

    snapshot = asyncio.run(collect_switch_snapshot({}, transport))
    lldp_leaves = [
        row
        for row in snapshot.capabilities
        if row.capability.startswith("lldp_remote_")
    ]

    assert next(row for row in snapshot.capabilities if row.capability == "fdb").outcome is SnmpOutcome.SUCCESS_EMPTY
    assert snapshot.lldp_neighbors == ()
    assert len(lldp_leaves) == 3
    assert {
        (row.outcome, row.error_code, row.error_message) for row in lldp_leaves
    } == {
        (
            SnmpOutcome.PARSE_ERROR,
            "malformed_lldp",
            "SNMP LLDP rows are malformed",
        )
    }
    assert "31071" not in repr(snapshot.to_dict()["capabilities"])


@pytest.mark.parametrize(
    ("local_component", "port_number"),
    [("5", 5), (True, 1)],
)
def test_non_integer_lldp_suffix_is_sanitized_and_never_fails_fdb(
    local_component: object, port_number: int
) -> None:
    from netctl.snmp.collector import collect_switch_snapshot

    suffix = (1, local_component, 9)
    transport = _FixtureTransport(
        {
            IF_INDEX: _result(
                "if_index", _vb(IF_INDEX + (port_number,), port_number)
            ),
            DOT1D_BASE_PORT_IFINDEX: _result(
                "bridge_port_ifindex",
                _vb(
                    DOT1D_BASE_PORT_IFINDEX + (port_number,),
                    port_number,
                ),
            ),
            DOT1Q_FDB_PORT: _result("qbridge_port"),
            LLDP_REM_CHASSIS_ID: _result(
                "lldp_remote_chassis_id",
                _vb(
                    LLDP_REM_CHASSIS_ID + suffix,
                    b"chassis",
                    "octet_string",
                ),
            ),
            LLDP_REM_PORT_ID: _result(
                "lldp_remote_port_id",
                _vb(LLDP_REM_PORT_ID + suffix, b"port", "octet_string"),
            ),
            LLDP_REM_SYS_NAME: _result(
                "lldp_remote_system_name",
                _vb(LLDP_REM_SYS_NAME + suffix, b"neighbor", "octet_string"),
            ),
        }
    )

    snapshot = asyncio.run(collect_switch_snapshot({}, transport))

    assert next(
        row for row in snapshot.capabilities if row.capability == "fdb"
    ).outcome is SnmpOutcome.SUCCESS_EMPTY
    assert snapshot.lldp_neighbors == ()
    assert next(
        row for row in snapshot.capabilities if row.capability == "lldp_remote"
    ).error_code == "malformed_lldp"


class _FixtureTransport:
    def __init__(self, results: dict[tuple[int, ...], CapabilityResult]) -> None:
        self.results = results
        self.walked: list[tuple[int, ...]] = []

    async def get(self, oid: tuple[int, ...], *, capability: str = "") -> CapabilityResult:
        return self.results.get(oid, _result(capability))

    async def walk(self, oid: tuple[int, ...], *, capability: str = "") -> CapabilityResult:
        self.walked.append(oid)
        return self.results.get(oid, _result(capability))


@pytest.mark.parametrize(
    ("qbridge_outcome", "legacy_expected", "fdb_outcome"),
    [
        (SnmpOutcome.SUCCESS_EMPTY, False, SnmpOutcome.SUCCESS_EMPTY),
        (SnmpOutcome.UNSUPPORTED_NO_SUCH_OBJECT, True, SnmpOutcome.SUCCESS_EMPTY),
        (SnmpOutcome.TIMEOUT, False, SnmpOutcome.TIMEOUT),
        (SnmpOutcome.AUTH_OR_VIEW_FAILURE, False, SnmpOutcome.AUTH_OR_VIEW_FAILURE),
        (SnmpOutcome.PARSE_ERROR, False, SnmpOutcome.PARSE_ERROR),
    ],
)
def test_collector_fallback_is_outcome_specific(
    qbridge_outcome: SnmpOutcome,
    legacy_expected: bool,
    fdb_outcome: SnmpOutcome,
) -> None:
    from netctl.snmp.collector import collect_switch_snapshot

    transport = _FixtureTransport(
        {
            DOT1Q_FDB_PORT: _result("qbridge_port", outcome=qbridge_outcome),
            DOT1D_FDB_ADDRESS: _result("legacy_address"),
            DOT1D_FDB_PORT: _result("legacy_port"),
            DOT1D_FDB_STATUS: _result("legacy_status"),
        }
    )
    source = {
        "name": "fixture-source",
        "host": "192.0.2.99",
        "secret_ref": "must_not_serialize",
        "driver_options": {},
    }
    snapshot = asyncio.run(collect_switch_snapshot(source, transport))

    assert (DOT1D_FDB_PORT in transport.walked) is legacy_expected
    assert snapshot.fdb == ()
    assert next(cap for cap in snapshot.capabilities if cap.capability == "fdb").outcome is fdb_outcome
    serialized = repr(snapshot.to_dict())
    assert "192.0.2.99" not in serialized
    assert "must_not_serialize" not in serialized


def test_collector_prefers_qbridge_rows_and_never_queries_legacy() -> None:
    from netctl.snmp.collector import collect_switch_snapshot

    index = (44, 0, 1, 2, 3, 4, 5)
    transport = _FixtureTransport(
        {
            IF_INDEX: _result("if_index", _vb(IF_INDEX + (9,), 9)),
            IF_NAME: _result("if_name", _vb(IF_NAME + (9,), b"port9", "octet_string")),
            DOT1D_BASE_PORT_IFINDEX: _result(
                "bridge_port_ifindex", _vb(DOT1D_BASE_PORT_IFINDEX + (9,), 9)
            ),
            DOT1Q_FDB_PORT: _result("qbridge_port", _vb(DOT1Q_FDB_PORT + index, 9)),
            DOT1Q_FDB_STATUS: _result(
                "qbridge_status", _vb(DOT1Q_FDB_STATUS + index, 3)
            ),
        }
    )

    snapshot = asyncio.run(collect_switch_snapshot({}, transport))

    assert len(snapshot.fdb) == 1
    assert snapshot.fdb[0].vlan_key == "fid:44"
    assert DOT1D_FDB_PORT not in transport.walked
    assert next(cap for cap in snapshot.capabilities if cap.capability == "fdb").outcome is SnmpOutcome.SUCCESS_WITH_ROWS


def test_qbridge_status_unsupported_is_explicit_and_does_not_fall_back() -> None:
    from netctl.snmp.collector import collect_switch_snapshot

    index = (44, 0, 1, 2, 3, 4, 5)
    transport = _FixtureTransport(
        {
            IF_INDEX: _result("if_index", _vb(IF_INDEX + (9,), 9)),
            DOT1D_BASE_PORT_IFINDEX: _result(
                "bridge_port_ifindex", _vb(DOT1D_BASE_PORT_IFINDEX + (9,), 9)
            ),
            DOT1Q_FDB_PORT: _result(
                "qbridge_port", _vb(DOT1Q_FDB_PORT + index, 9)
            ),
            DOT1Q_FDB_STATUS: _result(
                "qbridge_status", outcome=SnmpOutcome.UNSUPPORTED_NO_SUCH_OBJECT
            ),
        }
    )

    snapshot = asyncio.run(collect_switch_snapshot({}, transport))

    final = next(cap for cap in snapshot.capabilities if cap.capability == "fdb")
    assert final.outcome is SnmpOutcome.UNSUPPORTED_NO_SUCH_OBJECT
    assert DOT1D_FDB_ADDRESS not in transport.walked


@pytest.mark.parametrize(
    "legacy_outcome",
    [
        SnmpOutcome.UNSUPPORTED_NO_SUCH_OBJECT,
        SnmpOutcome.TIMEOUT,
        SnmpOutcome.AUTH_OR_VIEW_FAILURE,
        SnmpOutcome.PARSE_ERROR,
    ],
)
def test_legacy_failure_after_explicit_qbridge_unsupported_is_non_replacing(
    legacy_outcome: SnmpOutcome,
) -> None:
    from netctl.snmp.collector import collect_switch_snapshot

    transport = _FixtureTransport(
        {
            DOT1Q_FDB_PORT: _result(
                "qbridge_port", outcome=SnmpOutcome.UNSUPPORTED_NO_SUCH_OBJECT
            ),
            DOT1D_FDB_ADDRESS: _result("legacy_address", outcome=legacy_outcome),
            DOT1D_FDB_PORT: _result("legacy_port"),
            DOT1D_FDB_STATUS: _result("legacy_status"),
        }
    )

    snapshot = asyncio.run(collect_switch_snapshot({}, transport))

    assert snapshot.fdb == ()
    assert next(cap for cap in snapshot.capabilities if cap.capability == "fdb").outcome is legacy_outcome


def test_malformed_qbridge_rows_are_parse_error_without_legacy_fallback() -> None:
    from netctl.snmp.collector import collect_switch_snapshot

    malformed_index = (8, 0, 1, 2, 3, 4, 999)
    transport = _FixtureTransport(
        {
            IF_INDEX: _result("if_index", _vb(IF_INDEX + (1,), 1)),
            DOT1D_BASE_PORT_IFINDEX: _result(
                "bridge_port_ifindex", _vb(DOT1D_BASE_PORT_IFINDEX + (1,), 1)
            ),
            DOT1Q_FDB_PORT: _result(
                "qbridge_port", _vb(DOT1Q_FDB_PORT + malformed_index, 1)
            ),
            DOT1Q_FDB_STATUS: _result(
                "qbridge_status", _vb(DOT1Q_FDB_STATUS + malformed_index, 3)
            ),
        }
    )

    snapshot = asyncio.run(collect_switch_snapshot({}, transport))

    assert snapshot.fdb == ()
    final = next(cap for cap in snapshot.capabilities if cap.capability == "fdb")
    assert (final.outcome, final.error_code) == (
        SnmpOutcome.PARSE_ERROR,
        "malformed_fdb",
    )
    assert DOT1D_FDB_ADDRESS not in transport.walked
