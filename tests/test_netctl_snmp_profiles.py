from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

from netctl.snmp import CapabilityResult, SnmpOutcome, SnmpVarBind
from netctl.snmp.collector import collect_switch_snapshot
from netctl.snmp.models import SwitchSystem


_DGS_FIXTURE = Path(__file__).parent / "fixtures" / "snmp" / "dgs.json"


class _PagedFixtureTransport:
    def __init__(self, pages: list[dict[str, object]]) -> None:
        self.results: dict[tuple[int, ...], CapabilityResult] = {}
        for page in pages:
            request_oid = tuple(page["request_oid"])
            prior = self.results.get(request_oid)
            rows = tuple(
                SnmpVarBind(
                    oid=tuple(row["oid"]),
                    value_type=row["value_type"],
                    value=(
                        row["value"].encode("utf-8")
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
