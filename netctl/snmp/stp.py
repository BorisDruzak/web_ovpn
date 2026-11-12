from __future__ import annotations

from collections import Counter
from collections.abc import Mapping
from typing import Any

from .interfaces import normalize_mac
from .models import CapabilityResult, SnmpVarBind, SwitchPort
from .oids import (
    DOT1D_BASE_BRIDGE_ADDRESS,
    DOT1D_STP_DESIGNATED_ROOT,
    DOT1D_STP_PORT_DESIGNATED_BRIDGE,
    DOT1D_STP_PORT_DESIGNATED_PORT,
    DOT1D_STP_PROTOCOL,
    DOT1D_STP_ROOT_COST,
    DOT1D_STP_ROOT_PORT,
    DOT1D_STP_TOPOLOGY_CHANGES,
)
from .outcomes import SnmpOutcome
from .profiles import PortProfile
from .transport import SnmpTransport


_PROTOCOLS = {1: "unknown", 2: "dec_lb100", 3: "ieee8021d", 4: "ieee8021q", 5: "rstp"}


def _scalar(result: CapabilityResult, oid: tuple[int, ...]) -> SnmpVarBind:
    if result.outcome is not SnmpOutcome.SUCCESS_WITH_ROWS or len(result.rows) != 1:
        raise ValueError(f"{result.capability} is not a scalar result")
    row = result.rows[0]
    if row.oid != oid:
        raise ValueError("STP row has unexpected numeric OID")
    return row


def _integer(row: SnmpVarBind, field: str, *, value_type: str) -> int:
    if (
        row.value_type != value_type
        or isinstance(row.value, bool)
        or not isinstance(row.value, int)
        or row.value < 0
        or row.value > 4_294_967_295
    ):
        raise ValueError(f"{field} has invalid type")
    return row.value


async def read_stp_root_path(transport: SnmpTransport) -> dict:
    async def root_port() -> int:
        row = _scalar(await transport.get(DOT1D_STP_ROOT_PORT), DOT1D_STP_ROOT_PORT)
        return _integer(row, "STP root port", value_type="integer")

    port = await root_port()
    if not 1 <= port <= 65535:
        return {}
    bridge_oid = (*DOT1D_STP_PORT_DESIGNATED_BRIDGE, port)
    port_oid = (*DOT1D_STP_PORT_DESIGNATED_PORT, port)
    bridge = _scalar(await transport.get(bridge_oid), bridge_oid)
    designated = _scalar(await transport.get(port_oid), port_oid)
    if (bridge.value_type != "octet_string" or not isinstance(bridge.value, bytes) or len(bridge.value) != 8
            or designated.value_type != "octet_string" or not isinstance(designated.value, bytes)
            or len(designated.value) != 2 or not any(bridge.value[-6:]) or not any(designated.value)
            or await root_port() != port):
        return {}
    return {"rootPortNumber": port, "designatedBridgeMac": bridge.value[-6:].hex(":"),
            "designatedBridgeId": bridge.value.hex(":"), "designatedPortId": designated.value.hex(":")}


async def read_stp_designated_ports(transport: SnmpTransport) -> dict[tuple[str, str], int]:
    """Read own designated ports on the SNR profile, whose STP rows use ifIndex."""
    address = _scalar(await transport.get(DOT1D_BASE_BRIDGE_ADDRESS), DOT1D_BASE_BRIDGE_ADDRESS)
    if (address.value_type != "octet_string" or not isinstance(address.value, bytes)
            or len(address.value) != 6 or not any(address.value)):
        return {}

    async def octets(column, capability, size):
        result = await transport.walk(column, capability=capability)
        if result.outcome is not SnmpOutcome.SUCCESS_WITH_ROWS:
            return {}
        values = {}
        for row in result.rows:
            if (row.oid[:-1] != column or not 1 <= row.oid[-1] <= 2_147_483_647
                    or row.value_type != "octet_string" or not isinstance(row.value, bytes)
                    or len(row.value) != size or row.oid[-1] in values):
                return {}
            values[row.oid[-1]] = row.value
        return values

    bridges = await octets(DOT1D_STP_PORT_DESIGNATED_BRIDGE, "stp_designated_bridges", 8)
    ports = await octets(DOT1D_STP_PORT_DESIGNATED_PORT, "stp_designated_ports", 2)
    pairs = [(index, (bridge.hex(":"), ports[index].hex(":"))) for index, bridge in bridges.items()
             if bridge[-6:] == address.value and index in ports and any(ports[index])]
    counts = Counter(pair for _, pair in pairs)
    return {pair: index for index, pair in pairs if counts[pair] == 1}


def parse_stp(
    protocol_result: CapabilityResult,
    topology_changes_result: CapabilityResult,
    designated_root_result: CapabilityResult,
    root_cost_result: CapabilityResult,
    root_port_result: CapabilityResult,
    *,
    profile: PortProfile,
    ports: tuple[SwitchPort, ...],
    bridge_to_ifindex: Mapping[int, int],
) -> dict[str, Any]:
    protocol = _integer(_scalar(protocol_result, DOT1D_STP_PROTOCOL), "STP protocol", value_type="integer")
    topology_changes = _integer(
        _scalar(topology_changes_result, DOT1D_STP_TOPOLOGY_CHANGES),
        "STP topology changes",
        value_type="counter32",
    )
    root = _scalar(designated_root_result, DOT1D_STP_DESIGNATED_ROOT)
    if root.value_type != "octet_string" or not isinstance(root.value, bytes) or len(root.value) != 8:
        raise ValueError("STP designated root has invalid type")
    root_cost = _integer(
        _scalar(root_cost_result, DOT1D_STP_ROOT_COST), "STP root cost", value_type="integer"
    )
    raw_root_port = _integer(
        _scalar(root_port_result, DOT1D_STP_ROOT_PORT), "STP root port", value_type="integer"
    )
    ports_by_ifindex = {port.if_index: port for port in ports if port.if_index is not None}
    resolution = profile.resolve_stp_root_port(
        raw_root_port=raw_root_port,
        bridge_to_ifindex=bridge_to_ifindex,
        ports_by_ifindex=ports_by_ifindex,
    )
    return {
        "protocol": _PROTOCOLS.get(protocol, f"unknown:{protocol}"),
        "root_bridge_mac": normalize_mac(root.value[-6:]),
        "root_port_raw": raw_root_port,
        "root_port_key": resolution.port_key,
        "root_path_cost": root_cost,
        "topology_changes": topology_changes,
    }
