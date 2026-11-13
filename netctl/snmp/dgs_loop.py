from __future__ import annotations

import re

from .models import CapabilityResult
from .oids import DGS_LBD_ENABLED_VLANS, DGS_LBD_MODE, DGS_LBD_STATE, DGS_LBD_VLAN_PORTS
from .outcomes import SnmpOutcome
from .transport import SnmpTransport

DGS_LOOP_CAPABILITY = "dgs_loopback_detection"
MAX_REPORTED_VLANS = 256


def _scalar(result: CapabilityResult, oid: tuple[int, ...], kind: str) -> int | bytes:
    if len(result.rows) != 1 or result.rows[0].oid != oid or result.rows[0].value_type != kind:
        raise ValueError("Invalid D-Link loop detection scalar")
    value = result.rows[0].value
    if (kind == "integer" and type(value) is int) or (kind == "octet_string" and type(value) is bytes):
        return value
    raise ValueError("Invalid D-Link loop detection value")


def _parse_vlans(raw: int | bytes) -> list[int]:
    if not isinstance(raw, bytes) or len(raw) > 255:
        raise ValueError("Invalid D-Link VLAN list")
    text = raw.decode("ascii").strip()
    vlans = set()
    for item in text.split(",") if text else ():
        if not re.fullmatch(r"[0-9]{1,4}(?:-[0-9]{1,4})?", item.strip()):
            raise ValueError("Invalid D-Link VLAN range")
        first, _, last = item.strip().partition("-")
        start, end = int(first), int(last or first)
        if not 1 <= start <= end <= 4094:
            raise ValueError("Invalid D-Link VLAN bounds")
        vlans.update(range(start, end + 1))
    return sorted(vlans)


async def read_dgs_loop_detection(transport: SnmpTransport) -> CapabilityResult:
    name = DGS_LOOP_CAPABILITY
    try:
        state = await transport.get(DGS_LBD_STATE)
        if state.outcome is not SnmpOutcome.SUCCESS_WITH_ROWS:
            return CapabilityResult(name, state.outcome)
        enabled = _scalar(state, DGS_LBD_STATE, "integer")
        if enabled == 2:
            return CapabilityResult(name, SnmpOutcome.SUCCESS_WITH_ROWS, details={"status": "disabled"})
        if enabled != 1:
            raise ValueError("Unknown D-Link loop detection state")
        mode = await transport.get(DGS_LBD_MODE)
        if mode.outcome is not SnmpOutcome.SUCCESS_WITH_ROWS:
            return CapabilityResult(name, mode.outcome)
        mode_value = _scalar(mode, DGS_LBD_MODE, "integer")
        if mode_value == 1:
            return CapabilityResult(name, SnmpOutcome.SUCCESS_WITH_ROWS, details={"status": "port_mode"})
        if mode_value != 2:
            raise ValueError("Unknown D-Link loop detection mode")
        enabled_vlans = await transport.get(DGS_LBD_ENABLED_VLANS)
        if enabled_vlans.outcome is not SnmpOutcome.SUCCESS_WITH_ROWS:
            return CapabilityResult(name, enabled_vlans.outcome)
        vlans = _parse_vlans(_scalar(enabled_vlans, DGS_LBD_ENABLED_VLANS, "octet_string"))
        current = await transport.walk(DGS_LBD_VLAN_PORTS)
        if current.outcome not in {SnmpOutcome.SUCCESS_EMPTY, SnmpOutcome.SUCCESS_WITH_ROWS}:
            return CapabilityResult(name, current.outcome)
        loops = set()
        configured = set(vlans)
        seen = set()
        for row in current.rows:
            vlan = row.oid[-1]
            if (row.oid[:-1] != DGS_LBD_VLAN_PORTS or vlan not in configured or vlan in seen
                    or row.value_type != "octet_string" or not isinstance(row.value, bytes)
                    or len(row.value) > 32):
                raise ValueError("Invalid D-Link VLAN loop entry")
            seen.add(vlan)
            if any(row.value):
                loops.add(vlan)
        detected = sorted(loops)
        return CapabilityResult(name, SnmpOutcome.SUCCESS_WITH_ROWS, details={
            "status": "vlan_mode",
            "enabled_vlans": vlans[:MAX_REPORTED_VLANS],
            "detected_vlans": detected[:MAX_REPORTED_VLANS],
            "truncated": max(len(vlans), len(detected)) > MAX_REPORTED_VLANS,
        })
    except (ValueError, IndexError):
        return CapabilityResult(name, SnmpOutcome.PARSE_ERROR, error_code="malformed_dgs_loop_detection")
