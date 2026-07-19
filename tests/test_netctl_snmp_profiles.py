from __future__ import annotations

import pytest


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
