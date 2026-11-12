from __future__ import annotations

import re
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
from .outcomes import SnmpOutcome


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
_SNR_MODULE_ENTRY = (1, 3, 6, 1, 4, 1, 57206, 7, 100, 30, 3, 1)


async def read_snr_transceivers(transport) -> dict[int, dict]:
    """Read the SNR transceiver inventory columns that contain no serial numbers."""
    columns = {}
    for field, number in (("port", 2), ("vendor", 4), ("formFactor", 5), ("media", 6), ("rate", 7)):
        oid = (*_SNR_MODULE_ENTRY, number)
        result = await transport.walk(oid, capability="snr_transceiver_" + field)
        values = {}
        if result.outcome is SnmpOutcome.SUCCESS_WITH_ROWS:
            for row in result.rows:
                if row.oid[:-1] != oid:
                    values.clear()
                    break
                index = row.oid[-1]
                if index in values or not 1 <= index <= 2_147_483_647:
                    values.clear()
                    break
                try:
                    values[index] = _text(row, field).strip()
                except ValueError:
                    values[index] = ""
        columns[field] = values
    modules = {}
    for index, form in columns["formFactor"].items():
        name = columns["port"].get(index, "")
        if not re.fullmatch(r"[A-Za-z0-9_.-]{1,32}", name) or not re.fullmatch(r"(?:SFP|QSFP)[A-Z0-9+ -]{0,8}", form):
            continue
        module = {"port": name, "formFactor": form}
        for field in ("vendor", "media"):
            value = columns[field].get(index, "")
            if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9 ._+/-]{0,31}", value) and value.upper() not in {"NULL", "UNKNOWN", "N/A"}:
                module[field] = value
        rate = re.fullmatch(r"(\d{1,6})\s*Mbit/s", columns["rate"].get(index, ""))
        if rate and int(rate[1]) > 0:
            module["nominalBps"] = int(rate[1]) * 1_000_000
        modules[index] = module
    return modules


async def read_interface_link(transport, if_index: int, expected_name: str) -> dict:
    async def scalar(column):
        oid = (*column, if_index)
        result = await transport.get(oid)
        if (result.outcome is SnmpOutcome.SUCCESS_WITH_ROWS and len(result.rows) == 1
                and result.rows[0].oid == oid):
            return result.rows[0]
        return None

    name = await scalar(IF_NAME)
    if name is None or _text(name, "ifName").strip().casefold() != expected_name.strip().casefold():
        return {}
    admin = await scalar(IF_ADMIN_STATUS)
    if admin is None:
        return {}
    status = _integer(admin, "ifAdminStatus", value_type="integer")
    if status == 2:
        return {"state": "disabled"}
    if status != 1:
        return {}
    oper = await scalar(IF_OPER_STATUS)
    if oper is None:
        return {}
    status = _integer(oper, "ifOperStatus", value_type="integer")
    if status in (2, 7):
        return {"state": "down"}
    if status != 1:
        return {}
    speed = await scalar(IF_HIGH_SPEED)
    mbps = _integer(speed, "ifHighSpeed", value_type="gauge32") if speed else 0
    return {"state": "up", "speedBps": mbps * 1_000_000 if 0 < mbps <= 1_000_000 else None}


def _rows(values: Iterable[SnmpVarBind | CapabilityResult]) -> Iterable[SnmpVarBind]:
    for value in values:
        if isinstance(value, CapabilityResult):
            yield from value.rows
        elif isinstance(value, SnmpVarBind):
            yield value
        else:
            raise ValueError("interface row is invalid")


def _integer(
    row: SnmpVarBind,
    field: str,
    *,
    value_type: str,
    minimum: int = 0,
    maximum: int = 4_294_967_295,
) -> int:
    if (
        row.value_type != value_type
        or isinstance(row.value, bool)
        or not isinstance(row.value, int)
        or row.value < minimum
        or row.value > maximum
    ):
        raise ValueError(f"{field} has invalid type")
    return row.value


def _text(row: SnmpVarBind, field: str) -> str:
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
            if len(suffix) != 1 or not 0 < suffix[0] <= 2_147_483_647:
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
        if len(suffix) != 1 or not 0 < suffix[0] <= 65_535:
            raise ValueError("bridge port OID index is invalid")
        bridge_port = suffix[0]
        if_index = _integer(
            row,
            "dot1dBasePortIfIndex",
            value_type="integer",
            minimum=1,
            maximum=2_147_483_647,
        )
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
            value: object = _integer(
                row,
                "ifIndex",
                value_type="integer",
                minimum=1,
                maximum=2_147_483_647,
            )
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
        elif column in (IF_SPEED, IF_HIGH_SPEED):
            value = _integer(row, "interface speed", value_type="gauge32")
        elif column == IF_ADMIN_STATUS:
            value = _integer(
                row,
                "ifAdminStatus",
                value_type="integer",
                minimum=1,
                maximum=3,
            )
        elif column == IF_OPER_STATUS:
            value = _integer(
                row,
                "ifOperStatus",
                value_type="integer",
                minimum=1,
                maximum=7,
            )
        else:
            raise ValueError("interface column is unsupported")
        _store(table, oid_index, column, value)

    bridge_map = dict(bridge_to_ifindex or {})
    bridge_by_ifindex: dict[int, int] = {}
    for bridge_port, if_index in bridge_map.items():
        if (
            isinstance(bridge_port, bool)
            or not isinstance(bridge_port, int)
            or not 0 < bridge_port <= 65_535
            or isinstance(if_index, bool)
            or not isinstance(if_index, int)
            or not 0 < if_index <= 2_147_483_647
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
        # Some agents cap ifSpeed at the signed 32-bit limit instead of Gauge32's limit.
        if speed_bps in (2_147_483_647, 4_294_967_295):
            speed_bps = None
        if not speed_bps and isinstance(high_speed, int) and high_speed > 0:
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
    known_ifindexes = {port.if_index for port in ports}
    if any(if_index not in known_ifindexes for if_index in bridge_map.values()):
        raise ValueError("bridge port mapping references unknown ifIndex")
    return tuple(ports)
