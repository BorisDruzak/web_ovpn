from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from .interfaces import normalize_mac
from .models import CapabilityResult, SnmpVarBind, SwitchPort
from .oids import (
    DOT1D_STP_DESIGNATED_ROOT,
    DOT1D_STP_PROTOCOL,
    DOT1D_STP_ROOT_COST,
    DOT1D_STP_ROOT_PORT,
    DOT1D_STP_TOPOLOGY_CHANGES,
)
from .outcomes import SnmpOutcome
from .profiles import PortProfile


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
