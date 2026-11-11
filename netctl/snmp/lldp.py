from __future__ import annotations

from collections.abc import Iterable
from ipaddress import IPv4Address
from typing import Callable, TypeVar

from .models import CapabilityResult, SnmpVarBind, SwitchPort
from .oids import (
    LLDP_LOC_PORT_ID,
    LLDP_LOC_PORT_ID_SUBTYPE,
    LLDP_REM_CHASSIS_ID,
    LLDP_REM_CHASSIS_ID_SUBTYPE,
    LLDP_REM_MAN_ADDR_IF_SUBTYPE,
    LLDP_REM_PORT_DESC,
    LLDP_REM_PORT_ID,
    LLDP_REM_PORT_ID_SUBTYPE,
    LLDP_REM_SYS_CAP_ENABLED,
    LLDP_REM_SYS_CAP_SUPPORTED,
    LLDP_REM_SYS_DESC,
    LLDP_REM_SYS_NAME,
)
from .outcomes import SnmpOutcome


_SUCCESS_OUTCOMES = {
    SnmpOutcome.SUCCESS_WITH_ROWS,
    SnmpOutcome.SUCCESS_EMPTY,
}
_T = TypeVar("_T")
_CHASSIS_ID_SUBTYPES = {
    1: "chassis_component",
    2: "interface_alias",
    3: "port_component",
    4: "mac_address",
    5: "network_address",
    6: "interface_name",
    7: "local",
}
_PORT_ID_SUBTYPES = {
    1: "interface_alias",
    2: "port_component",
    3: "mac_address",
    4: "network_address",
    5: "interface_name",
    6: "agent_circuit_id",
    7: "local",
}
_CAPABILITY_BITS = (
    "other",
    "repeater",
    "bridge",
    "wlan_access_point",
    "router",
    "telephone",
    "docsis_cable_device",
    "station_only",
)


def _indexed_rows(
    result: CapabilityResult, base: tuple[int, ...], compact_index: bool = False
) -> dict[tuple[int, int, int], SnmpVarBind]:
    if result.outcome not in _SUCCESS_OUTCOMES:
        raise ValueError("LLDP capability was not successful")
    indexed: dict[tuple[int, int, int], SnmpVarBind] = {}
    for row in result.rows:
        if row.oid[: len(base)] != base:
            raise ValueError("LLDP row has unexpected numeric OID")
        suffix = row.oid[len(base) :]
        if compact_index and len(suffix) == 2:
            suffix = (0, *suffix)
        elif compact_index:
            raise ValueError("LLDP compact OID index is invalid")
        if len(suffix) != 3:
            raise ValueError("LLDP OID index is invalid")
        time_mark, local_port, remote_index = suffix
        if not all(type(component) is int for component in suffix):
            raise ValueError("LLDP OID index has invalid type")
        if not 0 <= time_mark <= 4_294_967_295:
            raise ValueError("LLDP time mark is invalid")
        if not 0 < local_port <= 2_147_483_647:
            raise ValueError("LLDP local port is invalid")
        if not 0 < remote_index <= 4_294_967_295:
            raise ValueError("LLDP remote index is invalid")
        key = (time_mark, local_port, remote_index)
        prior = indexed.get(key)
        if prior is not None and prior != row:
            raise ValueError("conflicting LLDP row")
        indexed[key] = row
    return indexed


def _text(
    row: SnmpVarBind,
    field: str,
    *,
    required: bool,
    binary_identifier: bool = False,
) -> str:
    if row.value_type != "octet_string" or not isinstance(row.value, bytes):
        raise ValueError(f"LLDP {field} has invalid type")
    if required and not row.value:
        raise ValueError(f"LLDP {field} is empty")
    try:
        value = row.value.decode("utf-8").strip()
    except UnicodeDecodeError:
        if binary_identifier:
            return ":".join(f"{octet:02X}" for octet in row.value)
        raise ValueError(f"LLDP {field} has invalid text") from None
    if binary_identifier and any(not character.isprintable() for character in value):
        return ":".join(f"{octet:02X}" for octet in row.value)
    if required and not value:
        raise ValueError(f"LLDP {field} is empty")
    return value


def _optional_rows(
    result: CapabilityResult | None, base: tuple[int, ...], compact_index: bool = False
) -> dict[tuple[int, int, int], SnmpVarBind]:
    if result is None or result.outcome not in _SUCCESS_OUTCOMES:
        return {}
    try:
        return _indexed_rows(result, base, compact_index)
    except ValueError:
        return {}


def _optional_value(
    rows: dict[tuple[int, int, int], SnmpVarBind],
    index: tuple[int, int, int],
    parser: Callable[[SnmpVarBind], _T],
    default: _T,
) -> _T:
    row = rows.get(index)
    if row is None:
        return default
    try:
        return parser(row)
    except ValueError:
        return default


def _subtype(row: SnmpVarBind, names: dict[int, str]) -> str:
    if (
        row.value_type != "integer"
        or type(row.value) is not int
        or row.value not in names
    ):
        raise ValueError("LLDP identifier subtype is invalid")
    return names[row.value]


def _capabilities(row: SnmpVarBind) -> list[str]:
    if (
        row.value_type != "octet_string"
        or not isinstance(row.value, bytes)
        or len(row.value) != 1
    ):
        raise ValueError("LLDP system capabilities are invalid")
    octet = row.value[0]
    return [
        name
        for bit, name in enumerate(_CAPABILITY_BITS)
        if octet & (0x80 >> bit)
    ]


def _management_addresses(
    result: CapabilityResult | None,
    compact_index: bool,
) -> dict[tuple[int, int, int], list[str]]:
    addresses: dict[tuple[int, int, int], set[str]] = {}
    if result is None or result.outcome not in _SUCCESS_OUTCOMES:
        return {}
    for row in result.rows:
        if row.oid[: len(LLDP_REM_MAN_ADDR_IF_SUBTYPE)] != LLDP_REM_MAN_ADDR_IF_SUBTYPE:
            continue
        suffix = row.oid[len(LLDP_REM_MAN_ADDR_IF_SUBTYPE) :]
        if compact_index:
            if len(suffix) != 8:
                continue
            suffix = (0, *suffix)
        if len(suffix) != 9 or not all(type(component) is int for component in suffix):
            continue
        time_mark, local_port, remote_index, address_subtype, length, *octets = suffix
        if (
            not 0 <= time_mark <= 4_294_967_295
            or not 0 < local_port <= 2_147_483_647
            or not 0 < remote_index <= 4_294_967_295
            or address_subtype != 1
            or length != 4
            or len(octets) != 4
            or any(not 0 <= octet <= 255 for octet in octets)
        ):
            continue
        try:
            address = str(IPv4Address(bytes(octets)))
        except ValueError:
            continue
        addresses.setdefault((time_mark, local_port, remote_index), set()).add(address)
    return {index: sorted(values) for index, values in addresses.items()}


def _local_port(ports: tuple[SwitchPort, ...], local_port: int) -> SwitchPort:
    candidates = [
        port
        for port in ports
        if port.bridge_port == local_port or port.if_index == local_port
    ]
    if len(candidates) != 1:
        raise ValueError("LLDP local port mapping is unknown or ambiguous")
    return candidates[0]


def _compact_local_ports(
    ports: tuple[SwitchPort, ...],
    ids: CapabilityResult | None,
    subtypes: CapabilityResult | None,
) -> dict[int, SwitchPort]:
    if ids is None or subtypes is None or ids.outcome not in _SUCCESS_OUTCOMES or subtypes.outcome not in _SUCCESS_OUTCOMES:
        raise ValueError("LLDP local port columns are unavailable")
    by_index = {}
    for row in subtypes.rows:
        suffix = row.oid[len(LLDP_LOC_PORT_ID_SUBTYPE):]
        if row.oid == LLDP_LOC_PORT_ID_SUBTYPE + suffix and len(suffix) == 1:
            if suffix[0] in by_index:
                raise ValueError("Conflicting LLDP local port subtype")
            by_index[suffix[0]] = row
    mapped = {}
    for row in ids.rows:
        suffix = row.oid[len(LLDP_LOC_PORT_ID):]
        if row.oid != LLDP_LOC_PORT_ID + suffix or len(suffix) != 1 or suffix[0] not in by_index:
            continue
        index = suffix[0]
        subtype = _subtype(by_index[index], _PORT_ID_SUBTYPES)
        if subtype not in ("interface_name", "interface_alias"):
            continue
        label = _text(row, "local port ID", required=True).casefold()
        matches = [port for port in ports if (port.name if subtype == "interface_name" else port.alias).casefold() == label]
        if len(matches) == 1:
            if index in mapped:
                raise ValueError("Conflicting LLDP local port ID")
            mapped[index] = matches[0]
    return mapped


def parse_lldp_neighbors(
    chassis_result: CapabilityResult,
    port_result: CapabilityResult,
    system_name_result: CapabilityResult,
    *,
    ports: Iterable[SwitchPort],
    chassis_id_subtype_result: CapabilityResult | None = None,
    port_id_subtype_result: CapabilityResult | None = None,
    port_description_result: CapabilityResult | None = None,
    system_description_result: CapabilityResult | None = None,
    system_capabilities_result: CapabilityResult | None = None,
    enabled_capabilities_result: CapabilityResult | None = None,
    management_address_result: CapabilityResult | None = None,
    compact_index: bool = False,
    local_id_result: CapabilityResult | None = None,
    local_subtype_result: CapabilityResult | None = None,
) -> tuple[dict[str, object], ...]:
    chassis_rows = _indexed_rows(chassis_result, LLDP_REM_CHASSIS_ID, compact_index)
    port_rows = _indexed_rows(port_result, LLDP_REM_PORT_ID, compact_index)
    system_name_rows = _indexed_rows(system_name_result, LLDP_REM_SYS_NAME, compact_index)
    if set(chassis_rows) != set(port_rows) or set(chassis_rows) != set(
        system_name_rows
    ):
        raise ValueError("LLDP remote tables do not join")

    chassis_subtype_rows = _optional_rows(
        chassis_id_subtype_result, LLDP_REM_CHASSIS_ID_SUBTYPE, compact_index
    )
    port_subtype_rows = _optional_rows(
        port_id_subtype_result, LLDP_REM_PORT_ID_SUBTYPE, compact_index
    )
    port_description_rows = _optional_rows(
        port_description_result, LLDP_REM_PORT_DESC, compact_index
    )
    system_description_rows = _optional_rows(
        system_description_result, LLDP_REM_SYS_DESC, compact_index
    )
    system_capability_rows = _optional_rows(
        system_capabilities_result, LLDP_REM_SYS_CAP_SUPPORTED, compact_index
    )
    enabled_capability_rows = _optional_rows(
        enabled_capabilities_result, LLDP_REM_SYS_CAP_ENABLED, compact_index
    )
    management_addresses = _management_addresses(management_address_result, compact_index)

    normalized_ports = tuple(ports)
    local_ports = _compact_local_ports(normalized_ports, local_id_result, local_subtype_result) if compact_index else {}
    neighbors: list[dict[str, object]] = []
    for index in sorted(chassis_rows):
        if compact_index:
            local = local_ports.get(index[1])
            if local is None:
                raise ValueError("LLDP local port identity is unknown or ambiguous")
        else:
            local = _local_port(normalized_ports, index[1])
        neighbors.append(
            {
                "local_port_key": local.port_key,
                "chassis_id": _text(
                    chassis_rows[index],
                    "chassis ID",
                    required=True,
                    binary_identifier=True,
                ),
                "chassis_id_subtype": _optional_value(
                    chassis_subtype_rows,
                    index,
                    lambda row: _subtype(row, _CHASSIS_ID_SUBTYPES),
                    "",
                ),
                "port_id": _text(
                    port_rows[index],
                    "port ID",
                    required=True,
                    binary_identifier=True,
                ),
                "port_id_subtype": _optional_value(
                    port_subtype_rows,
                    index,
                    lambda row: _subtype(row, _PORT_ID_SUBTYPES),
                    "",
                ),
                "port_description": _optional_value(
                    port_description_rows,
                    index,
                    lambda row: _text(row, "port description", required=False),
                    "",
                ),
                "system_name": _text(
                    system_name_rows[index], "system name", required=False
                ),
                "system_description": _optional_value(
                    system_description_rows,
                    index,
                    lambda row: _text(row, "system description", required=False),
                    "",
                ),
                "system_capabilities": _optional_value(
                    system_capability_rows, index, _capabilities, []
                ),
                "enabled_capabilities": _optional_value(
                    enabled_capability_rows, index, _capabilities, []
                ),
                "management_addresses": management_addresses.get(index, []),
            }
        )
    return tuple(neighbors)
