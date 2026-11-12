from __future__ import annotations

from collections.abc import Iterable, Mapping
import re
from typing import Any

from .models import CapabilityResult, PortResolution, SnmpVarBind, SwitchPort
from .oids import (
    DOT1Q_PVID, DOT1Q_VLAN_CURRENT_EGRESS, DOT1Q_VLAN_CURRENT_UNTAGGED,
    TPLINK_VLAN_PVID, TPLINK_VLAN_TAGGED, TPLINK_VLAN_UNTAGGED,
)
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


def _pvid(row: SnmpVarBind, oid: tuple[int, ...] = DOT1Q_PVID) -> tuple[int, int]:
    if row.oid[:-1] != oid:
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


def _membership(values: dict, vlan_id: int, port: PortResolution) -> dict[str, Any]:
    return values.setdefault((vlan_id, port.port_key), {
        "vlan_id": vlan_id, "port_key": port.port_key, "if_index": port.if_index,
        "bridge_port": port.bridge_port, "physical_port": port.physical_port, "port_name": port.port_name,
        "egress": False, "untagged": False, "pvid": False,
    })


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
        _membership(values, vlan_id, resolution)[field] = True

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


def _tplink_members(result: CapabilityResult, oid: tuple[int, ...]) -> dict[int, set[int]]:
    vlans = {}
    for row in _rows(result):
        if (row.oid[:-1] != oid or not 1 <= row.oid[-1] <= 4094 or row.oid[-1] in vlans
                or row.value_type != "octet_string" or not isinstance(row.value, bytes) or len(row.value) > 1024):
            raise ValueError("TP-Link VLAN row is invalid")
        members = set()
        value = row.value.decode("ascii").strip()
        for part in value.split(",") if value else ():
            match = re.fullmatch(r"(?:1/0/)?([1-9][0-9]?)(?:\s*-\s*(?:1/0/)?([1-9][0-9]?))?", part.strip())
            if not match:
                raise ValueError("TP-Link VLAN port list is invalid")
            start, end = int(match[1]), int(match[2] or match[1])
            if not start <= end <= 52:
                raise ValueError("TP-Link VLAN port range is invalid")
            members.update(range(start, end + 1))
        vlans[row.oid[-1]] = members
    return vlans


def parse_tplink_vlan_memberships(
    tagged_result: CapabilityResult, untagged_result: CapabilityResult, pvid_result: CapabilityResult,
    *, profile: PortProfile, ports: Iterable[SwitchPort], bridge_to_ifindex: Mapping[int, int],
) -> tuple[dict[str, Any], ...]:
    tagged = _tplink_members(tagged_result, TPLINK_VLAN_TAGGED)
    untagged = _tplink_members(untagged_result, TPLINK_VLAN_UNTAGGED)
    if tagged.keys() != untagged.keys():
        raise ValueError("TP-Link VLAN columns are incomplete")
    ports_by_ifindex = {port.if_index: port for port in ports if port.if_index is not None}
    values, resolutions = {}, {}
    for vlan_id, tagged_ports in tagged.items():
        untagged_ports = untagged[vlan_id]
        if tagged_ports & untagged_ports:
            raise ValueError("TP-Link VLAN port has conflicting egress modes")
        for number in tagged_ports | untagged_ports:
            port = profile.resolve_fdb_port(raw_fdb_port=number, fdb_mode="qbridge",
                                            bridge_to_ifindex=bridge_to_ifindex, ports_by_ifindex=ports_by_ifindex)
            resolutions[port.if_index] = port
            _membership(values, vlan_id, port).update(egress=True, untagged=number in untagged_ports)
    seen_pvid = set()
    for row in _rows(pvid_result):
        if_index, vlan_id = _pvid(row, TPLINK_VLAN_PVID)
        if if_index in seen_pvid:
            raise ValueError("TP-Link PVID rows are ambiguous")
        seen_pvid.add(if_index)
        if if_index in resolutions:
            _membership(values, vlan_id, resolutions[if_index])["pvid"] = True
    return tuple(values[key] for key in sorted(values))
