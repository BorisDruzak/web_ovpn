from __future__ import annotations

from collections.abc import Iterable, Mapping

from .models import CapabilityResult, SnmpVarBind, SwitchPort
from .oids import (
    DOT1D_BASE_PORT_IFINDEX,
    IF_ADMIN_STATUS,
    IF_ALIAS,
    IF_DESCR,
    IF_HIGH_SPEED,
    IF_INDEX,
    IF_NAME,
    IF_OPER_STATUS,
    IF_PHYS_ADDRESS,
    IF_SPEED,
)


_INTEGER_TYPES = frozenset(
    {"integer", "counter32", "counter64", "gauge32", "unsigned32", "time_ticks"}
)
_TEXT_TYPES = frozenset({"string", "octet_string"})
_INTERFACE_COLUMNS = (
    IF_INDEX,
    IF_DESCR,
    IF_SPEED,
    IF_PHYS_ADDRESS,
    IF_ADMIN_STATUS,
    IF_OPER_STATUS,
    IF_NAME,
    IF_HIGH_SPEED,
    IF_ALIAS,
)


def _rows(values: Iterable[SnmpVarBind | CapabilityResult]) -> Iterable[SnmpVarBind]:
    for value in values:
        if isinstance(value, CapabilityResult):
            yield from value.rows
        elif isinstance(value, SnmpVarBind):
            yield value
        else:
            raise ValueError("interface row is invalid")


def _integer(row: SnmpVarBind, field: str, *, minimum: int = 0) -> int:
    if (
        row.value_type not in _INTEGER_TYPES
        or isinstance(row.value, bool)
        or not isinstance(row.value, int)
        or row.value < minimum
    ):
        raise ValueError(f"{field} has invalid type")
    return row.value


def _text(row: SnmpVarBind, field: str) -> str:
    if row.value_type not in _TEXT_TYPES:
        raise ValueError(f"{field} has invalid type")
    if row.value_type == "string" and isinstance(row.value, str):
        return row.value
    if row.value_type == "octet_string" and isinstance(row.value, bytes):
        try:
            return row.value.decode("utf-8")
        except UnicodeDecodeError:
            raise ValueError(f"{field} has invalid text") from None
    raise ValueError(f"{field} has invalid type")


def normalize_mac(value: bytes | tuple[int, ...] | list[int]) -> str:
    octets = tuple(value)
    if len(octets) != 6 or any(
        isinstance(octet, bool) or not isinstance(octet, int) or not 0 <= octet <= 255
        for octet in octets
    ):
        raise ValueError("MAC address is invalid")
    return ":".join(f"{octet:02X}" for octet in octets)


def _column(row: SnmpVarBind) -> tuple[tuple[int, ...], int] | None:
    for base in _INTERFACE_COLUMNS:
        if row.oid[: len(base)] == base:
            suffix = row.oid[len(base) :]
            if len(suffix) != 1 or suffix[0] <= 0:
                raise ValueError("interface OID index is invalid")
            return base, suffix[0]
    return None


def _store(
    table: dict[int, dict[tuple[int, ...], object]],
    if_index: int,
    column: tuple[int, ...],
    value: object,
) -> None:
    values = table.setdefault(if_index, {})
    if column in values and values[column] != value:
        field = "ifIndex" if column == IF_INDEX else "interface column"
        raise ValueError(f"conflicting {field}")
    values[column] = value


def parse_bridge_port_map(
    values: Iterable[SnmpVarBind | CapabilityResult],
) -> dict[int, int]:
    result: dict[int, int] = {}
    reverse: dict[int, int] = {}
    for row in _rows(values):
        if row.oid[: len(DOT1D_BASE_PORT_IFINDEX)] != DOT1D_BASE_PORT_IFINDEX:
            continue
        suffix = row.oid[len(DOT1D_BASE_PORT_IFINDEX) :]
        if len(suffix) != 1 or suffix[0] <= 0:
            raise ValueError("bridge port OID index is invalid")
        bridge_port = suffix[0]
        if_index = _integer(row, "dot1dBasePortIfIndex", minimum=1)
        if bridge_port in result and result[bridge_port] != if_index:
            raise ValueError("conflicting bridge port mapping")
        if if_index in reverse and reverse[if_index] != bridge_port:
            raise ValueError("ambiguous bridge port mapping")
        result[bridge_port] = if_index
        reverse[if_index] = bridge_port
    return result


_ADMIN_STATUS = {1: "up", 2: "down", 3: "testing"}
_OPER_STATUS = {
    1: "up",
    2: "down",
    3: "testing",
    4: "unknown",
    5: "dormant",
    6: "not_present",
    7: "lower_layer_down",
}


def parse_interfaces(
    if_table: Iterable[SnmpVarBind | CapabilityResult],
    ifx_table: Iterable[SnmpVarBind | CapabilityResult] = (),
    bridge_to_ifindex: Mapping[int, int] | None = None,
) -> tuple[SwitchPort, ...]:
    table: dict[int, dict[tuple[int, ...], object]] = {}
    for row in (*tuple(_rows(if_table)), *tuple(_rows(ifx_table))):
        located = _column(row)
        if located is None:
            continue
        column, oid_index = located
        if column == IF_INDEX:
            value: object = _integer(row, "ifIndex", minimum=1)
            existing = table.get(oid_index, {}).get(IF_INDEX)
            if existing is not None and existing != value:
                raise ValueError("conflicting ifIndex")
            if value != oid_index:
                raise ValueError("conflicting ifIndex")
        elif column in (IF_DESCR, IF_NAME, IF_ALIAS):
            value = _text(row, "interface text")
        elif column == IF_PHYS_ADDRESS:
            if row.value_type != "octet_string" or not isinstance(row.value, bytes):
                raise ValueError("ifPhysAddress has invalid type")
            value = None if not row.value else normalize_mac(row.value)
        else:
            value = _integer(row, "interface integer")
        _store(table, oid_index, column, value)

    bridge_map = dict(bridge_to_ifindex or {})
    bridge_by_ifindex: dict[int, int] = {}
    for bridge_port, if_index in bridge_map.items():
        if (
            isinstance(bridge_port, bool)
            or not isinstance(bridge_port, int)
            or bridge_port <= 0
            or isinstance(if_index, bool)
            or not isinstance(if_index, int)
            or if_index <= 0
        ):
            raise ValueError("bridge port mapping is invalid")
        if if_index in bridge_by_ifindex and bridge_by_ifindex[if_index] != bridge_port:
            raise ValueError("ambiguous bridge port mapping")
        bridge_by_ifindex[if_index] = bridge_port

    ports: list[SwitchPort] = []
    for if_index in sorted(table):
        values = table[if_index]
        if IF_INDEX not in values:
            continue
        speed = values.get(IF_SPEED)
        high_speed = values.get(IF_HIGH_SPEED)
        speed_bps = int(speed) if isinstance(speed, int) else None
        if (
            isinstance(high_speed, int)
            and (speed_bps is None or speed_bps == 0 or speed_bps >= 4_294_967_295)
        ):
            speed_bps = high_speed * 1_000_000
        admin_value = values.get(IF_ADMIN_STATUS)
        oper_value = values.get(IF_OPER_STATUS)
        name = values.get(IF_NAME) or values.get(IF_DESCR) or f"ifIndex {if_index}"
        ports.append(
            SwitchPort(
                port_key=f"ifindex:{if_index}",
                if_index=if_index,
                bridge_port=bridge_by_ifindex.get(if_index),
                physical_port=None,
                name=str(name),
                alias=str(values.get(IF_ALIAS, "")),
                mac=(
                    values.get(IF_PHYS_ADDRESS)
                    if isinstance(values.get(IF_PHYS_ADDRESS), str)
                    else None
                ),
                admin_status=(
                    _ADMIN_STATUS.get(admin_value, f"unknown:{admin_value}")
                    if isinstance(admin_value, int)
                    else "unknown"
                ),
                oper_status=(
                    _OPER_STATUS.get(oper_value, f"unknown:{oper_value}")
                    if isinstance(oper_value, int)
                    else "unknown"
                ),
                speed_bps=speed_bps,
            )
        )
    return tuple(ports)
