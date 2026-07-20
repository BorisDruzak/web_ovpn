from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

from netctl.snmp import CapabilityResult, SnmpOutcome, SnmpVarBind
from netctl.snmp.collector import collect_switch_snapshot
from netctl.snmp.models import SwitchSystem


_DGS_FIXTURE = Path(__file__).parent / "fixtures" / "snmp" / "dgs.json"
_SNR_FIXTURE = Path(__file__).parent / "fixtures" / "snmp" / "snr.json"


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


def test_only_supported_profile_hint_is_accepted() -> None:
    from netctl.snmp.models import SwitchSystem
    from netctl.snmp.profiles import GenericProfile, detect_profile

    system = SwitchSystem("fixture", "1.3.6.1.4.1.99999", "sw", "", None)

    assert isinstance(detect_profile(system, profile_hint="generic"), GenericProfile)
    with pytest.raises(ValueError, match="profile_hint"):
        detect_profile(system, profile_hint="dgs")


@pytest.mark.parametrize("profile_hint", ["snr", "tplink", "css326"])
def test_pr3a_config_and_runtime_reject_non_dgs_vendor_profiles(
    profile_hint: str,
) -> None:
    from netctl.config import normalize_source
    from netctl.snmp.models import SwitchSystem
    from netctl.snmp.profiles import detect_profile

    source = {
        "name": "switch-profile-parity",
        "driver": "snmp_switch",
        "host": "192.0.2.18",
        "secret_ref": "switch_profile_parity_snmp",
        "snmp_profile_hint": profile_hint,
    }
    system = SwitchSystem("fixture", "1.3.6.1.4.1.99999", "sw", "", None)

    with pytest.raises(ValueError, match="profile_hint"):
        normalize_source(source)
    with pytest.raises(ValueError, match="profile_hint"):
        detect_profile(system, profile_hint=profile_hint)


@pytest.mark.parametrize("profile_hint", ["generic", "dgs"])
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
    assert SUPPORTED_SNMP_PROFILE_HINTS == frozenset({"generic", "dgs"})


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
