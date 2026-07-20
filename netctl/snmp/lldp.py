from __future__ import annotations

from collections.abc import Iterable

from .models import CapabilityResult, SnmpVarBind, SwitchPort
from .oids import LLDP_REM_CHASSIS_ID, LLDP_REM_PORT_ID, LLDP_REM_SYS_NAME
from .outcomes import SnmpOutcome


_SUCCESS_OUTCOMES = {
    SnmpOutcome.SUCCESS_WITH_ROWS,
    SnmpOutcome.SUCCESS_EMPTY,
}


def _indexed_rows(
    result: CapabilityResult, base: tuple[int, ...]
) -> dict[tuple[int, int, int], SnmpVarBind]:
    if result.outcome not in _SUCCESS_OUTCOMES:
        raise ValueError("LLDP capability was not successful")
    indexed: dict[tuple[int, int, int], SnmpVarBind] = {}
    for row in result.rows:
        if row.oid[: len(base)] != base:
            raise ValueError("LLDP row has unexpected numeric OID")
        suffix = row.oid[len(base) :]
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


def _local_port(ports: tuple[SwitchPort, ...], local_port: int) -> SwitchPort:
    candidates = [
        port
        for port in ports
        if port.bridge_port == local_port or port.if_index == local_port
    ]
    if len(candidates) != 1:
        raise ValueError("LLDP local port mapping is unknown or ambiguous")
    return candidates[0]


def parse_lldp_neighbors(
    chassis_result: CapabilityResult,
    port_result: CapabilityResult,
    system_name_result: CapabilityResult,
    *,
    ports: Iterable[SwitchPort],
) -> tuple[dict[str, object], ...]:
    chassis_rows = _indexed_rows(chassis_result, LLDP_REM_CHASSIS_ID)
    port_rows = _indexed_rows(port_result, LLDP_REM_PORT_ID)
    system_name_rows = _indexed_rows(system_name_result, LLDP_REM_SYS_NAME)
    if set(chassis_rows) != set(port_rows) or set(chassis_rows) != set(
        system_name_rows
    ):
        raise ValueError("LLDP remote tables do not join")

    normalized_ports = tuple(ports)
    neighbors: list[dict[str, object]] = []
    for index in sorted(chassis_rows):
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
                "port_id": _text(
                    port_rows[index],
                    "port ID",
                    required=True,
                    binary_identifier=True,
                ),
                "system_name": _text(
                    system_name_rows[index], "system name", required=False
                ),
            }
        )
    return tuple(neighbors)
