from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

from .models import CapabilityResult, SnmpVarBind, SwitchPort
from .oids import DOT1Q_PVID, DOT1Q_VLAN_CURRENT_EGRESS, DOT1Q_VLAN_CURRENT_UNTAGGED
from .outcomes import SnmpOutcome
from .profiles import PortProfile


_SUCCESS = {SnmpOutcome.SUCCESS_WITH_ROWS, SnmpOutcome.SUCCESS_EMPTY}
_COMPATIBLE_INTEGRAL_TYPES = {"integer", "unsigned32", "gauge32"}


def _rows(result: CapabilityResult) -> tuple[SnmpVarBind, ...]:
    if result.outcome not in _SUCCESS:
        raise ValueError(f"{result.capability} was not successful")
    return result.rows


def _vlan_index(row: SnmpVarBind, base: tuple[int, ...]) -> int:
    if row.oid[: len(base)] != base or len(row.oid) != len(base) + 2:
        raise ValueError("VLAN row has unexpected numeric OID")
    time_mark, vlan_id = row.oid[-2:]
    if not 0 <= time_mark <= 4_294_967_295 or not 1 <= vlan_id <= 4094:
        raise ValueError("VLAN OID index is invalid")
    if row.value_type != "octet_string" or not isinstance(row.value, bytes):
        raise ValueError("VLAN bitmap has invalid type")
    return vlan_id


def _bitmap_bridge_ports(value: bytes) -> tuple[int, ...]:
    return tuple(
        octet_index * 8 + bit_index + 1
        for octet_index, octet in enumerate(value)
        for bit_index in range(8)
        if octet & (0x80 >> bit_index)
    )


def _pvid(row: SnmpVarBind) -> tuple[int, int]:
    if row.oid[: len(DOT1Q_PVID)] != DOT1Q_PVID or len(row.oid) != len(DOT1Q_PVID) + 1:
        raise ValueError("PVID row has unexpected numeric OID")
    bridge_port = row.oid[-1]
    if not 1 <= bridge_port <= 65_535:
        raise ValueError("PVID OID index is invalid")
    if (
        row.value_type not in _COMPATIBLE_INTEGRAL_TYPES
        or isinstance(row.value, bool)
        or not isinstance(row.value, int)
        or not 1 <= row.value <= 4094
    ):
        raise ValueError("PVID has invalid type")
    return bridge_port, row.value


def parse_vlan_memberships(
    egress_result: CapabilityResult,
    untagged_result: CapabilityResult,
    pvid_result: CapabilityResult,
    *,
    profile: PortProfile,
    ports: Iterable[SwitchPort],
    bridge_to_ifindex: Mapping[int, int],
) -> tuple[dict[str, Any], ...]:
    ports_by_ifindex = {
        port.if_index: port for port in ports if port.if_index is not None
    }
    values: dict[tuple[int, str], dict[str, Any]] = {}

    def add(vlan_id: int, bridge_port: int, field: str) -> None:
        resolution = profile.resolve_bridge_port(
            bridge_port=bridge_port,
            bridge_to_ifindex=bridge_to_ifindex,
            ports_by_ifindex=ports_by_ifindex,
        )
        key = vlan_id, resolution.port_key
        row = values.setdefault(
            key,
            {
                "vlan_id": vlan_id,
                "port_key": resolution.port_key,
                "if_index": resolution.if_index,
                "bridge_port": resolution.bridge_port,
                "physical_port": resolution.physical_port,
                "port_name": resolution.port_name,
                "egress": False,
                "untagged": False,
                "pvid": False,
            },
        )
        row[field] = True

    for result, base, field in (
        (egress_result, DOT1Q_VLAN_CURRENT_EGRESS, "egress"),
        (untagged_result, DOT1Q_VLAN_CURRENT_UNTAGGED, "untagged"),
    ):
        for row in _rows(result):
            vlan_id = _vlan_index(row, base)
            for bridge_port in _bitmap_bridge_ports(row.value):
                add(vlan_id, bridge_port, field)
    for row in _rows(pvid_result):
        bridge_port, vlan_id = _pvid(row)
        add(vlan_id, bridge_port, "pvid")
    return tuple(values[key] for key in sorted(values))
