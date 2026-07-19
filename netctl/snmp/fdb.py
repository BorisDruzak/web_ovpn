from __future__ import annotations

from collections.abc import Iterable, Mapping

from .interfaces import normalize_mac
from .models import CapabilityResult, SnmpVarBind, SwitchFdbEntry, SwitchPort
from .oids import (
    DOT1D_FDB_ADDRESS,
    DOT1D_FDB_PORT,
    DOT1D_FDB_STATUS,
    DOT1Q_FDB_PORT,
    DOT1Q_FDB_STATUS,
    DOT1Q_VLAN_FDB_ID,
)
from .outcomes import SnmpOutcome
from .profiles import PortProfile


_INTEGER_TYPES = frozenset(
    {"integer", "counter32", "counter64", "gauge32", "unsigned32", "time_ticks"}
)
_FDB_STATUS = {1: "other", 2: "invalid", 3: "learned", 4: "self", 5: "mgmt"}


def _successful_rows(result: CapabilityResult) -> tuple[SnmpVarBind, ...]:
    if result.outcome not in {
        SnmpOutcome.SUCCESS_WITH_ROWS,
        SnmpOutcome.SUCCESS_EMPTY,
    }:
        raise ValueError(f"{result.capability} was not successful")
    return result.rows


def _integer(row: SnmpVarBind, field: str, *, minimum: int = 0) -> int:
    if (
        row.value_type not in _INTEGER_TYPES
        or isinstance(row.value, bool)
        or not isinstance(row.value, int)
        or row.value < minimum
    ):
        raise ValueError(f"{field} has invalid type")
    return row.value


def _indexed_rows(
    result: CapabilityResult,
    base: tuple[int, ...],
    *,
    suffix_length: int,
) -> dict[tuple[int, ...], SnmpVarBind]:
    indexed: dict[tuple[int, ...], SnmpVarBind] = {}
    for row in _successful_rows(result):
        if row.oid[: len(base)] != base:
            raise ValueError("FDB row has unexpected numeric OID")
        suffix = row.oid[len(base) :]
        if len(suffix) != suffix_length:
            raise ValueError("FDB OID index is invalid")
        prior = indexed.get(suffix)
        if prior is not None and prior != row:
            raise ValueError("conflicting FDB row")
        indexed[suffix] = row
    return indexed


def _vids_by_fid(result: CapabilityResult) -> dict[int, set[int]]:
    if result.outcome is SnmpOutcome.UNSUPPORTED_NO_SUCH_OBJECT:
        return {}
    rows = _successful_rows(result)
    mapped: dict[int, set[int]] = {}
    seen_vids: dict[int, int] = {}
    for row in rows:
        if row.oid[: len(DOT1Q_VLAN_FDB_ID)] != DOT1Q_VLAN_FDB_ID:
            raise ValueError("VLAN FDB row has unexpected numeric OID")
        suffix = row.oid[len(DOT1Q_VLAN_FDB_ID) :]
        if len(suffix) not in {1, 2}:
            raise ValueError("VLAN FDB OID index is invalid")
        vid = suffix[-1]
        if not 1 <= vid <= 4094:
            raise ValueError("VLAN ID is invalid")
        fdb_id = _integer(row, "dot1qVlanFdbId", minimum=1)
        if vid in seen_vids and seen_vids[vid] != fdb_id:
            raise ValueError("conflicting VLAN FDB mapping")
        seen_vids[vid] = fdb_id
        mapped.setdefault(fdb_id, set()).add(vid)
    return mapped


def _status(row: SnmpVarBind) -> str:
    value = _integer(row, "FDB status", minimum=1)
    return _FDB_STATUS.get(value, f"unknown:{value}")


def parse_qbridge_fdb(
    port_result: CapabilityResult,
    status_result: CapabilityResult,
    vlan_fdb_id_result: CapabilityResult,
    *,
    profile: PortProfile,
    ports: Iterable[SwitchPort],
    bridge_to_ifindex: Mapping[int, int],
) -> tuple[SwitchFdbEntry, ...]:
    port_rows = _indexed_rows(port_result, DOT1Q_FDB_PORT, suffix_length=7)
    status_rows = _indexed_rows(status_result, DOT1Q_FDB_STATUS, suffix_length=7)
    vids_by_fid = _vids_by_fid(vlan_fdb_id_result)
    ports_by_ifindex = {
        port.if_index: port for port in ports if port.if_index is not None
    }
    entries: list[SwitchFdbEntry] = []
    for index in sorted(port_rows):
        fdb_id, *mac_octets = index
        if fdb_id <= 0:
            raise ValueError("FDB ID is invalid")
        mac = normalize_mac(tuple(mac_octets))
        status_row = status_rows.get(index)
        if status_row is None:
            raise ValueError("FDB status row is missing")
        raw_port = _integer(port_rows[index], "Q-BRIDGE FDB port", minimum=1)
        resolution = profile.resolve_fdb_port(
            raw_fdb_port=raw_port,
            fdb_mode="qbridge",
            bridge_to_ifindex=bridge_to_ifindex,
            ports_by_ifindex=ports_by_ifindex,
        )
        vlan_key, vlan_id = profile.resolve_fdb_vlan(
            fdb_id=fdb_id, vids_by_fid=vids_by_fid
        )
        entries.append(
            SwitchFdbEntry(
                fdb_id=fdb_id,
                vlan_key=vlan_key,
                vlan_id=vlan_id,
                mac=mac,
                port_key=resolution.port_key,
                bridge_port=resolution.bridge_port,
                if_index=resolution.if_index,
                physical_port=resolution.physical_port,
                port_name=resolution.port_name,
                status=_status(status_row),
            )
        )
    if set(status_rows) - set(port_rows):
        raise ValueError("FDB status has no matching port row")
    return tuple(entries)


def parse_legacy_fdb(
    address_result: CapabilityResult,
    port_result: CapabilityResult,
    status_result: CapabilityResult,
    *,
    profile: PortProfile,
    ports: Iterable[SwitchPort],
    bridge_to_ifindex: Mapping[int, int],
) -> tuple[SwitchFdbEntry, ...]:
    addresses = _indexed_rows(address_result, DOT1D_FDB_ADDRESS, suffix_length=6)
    port_rows = _indexed_rows(port_result, DOT1D_FDB_PORT, suffix_length=6)
    status_rows = _indexed_rows(status_result, DOT1D_FDB_STATUS, suffix_length=6)
    ports_by_ifindex = {
        port.if_index: port for port in ports if port.if_index is not None
    }
    entries: list[SwitchFdbEntry] = []
    for index in sorted(addresses):
        mac = normalize_mac(index)
        address_row = addresses[index]
        if address_row.value_type != "octet_string" or not isinstance(
            address_row.value, bytes
        ):
            raise ValueError("legacy FDB address has invalid type")
        if normalize_mac(address_row.value) != mac:
            raise ValueError("legacy FDB address conflicts with its index")
        port_row = port_rows.get(index)
        status_row = status_rows.get(index)
        if port_row is None or status_row is None:
            raise ValueError("legacy FDB row is incomplete")
        raw_port = _integer(port_row, "legacy FDB port", minimum=1)
        resolution = profile.resolve_fdb_port(
            raw_fdb_port=raw_port,
            fdb_mode="legacy",
            bridge_to_ifindex=bridge_to_ifindex,
            ports_by_ifindex=ports_by_ifindex,
        )
        entries.append(
            SwitchFdbEntry(
                fdb_id=None,
                vlan_key="legacy:unknown",
                vlan_id=None,
                mac=mac,
                port_key=resolution.port_key,
                bridge_port=resolution.bridge_port,
                if_index=resolution.if_index,
                physical_port=resolution.physical_port,
                port_name=resolution.port_name,
                status=_status(status_row),
            )
        )
    if set(port_rows) != set(addresses) or set(status_rows) != set(addresses):
        raise ValueError("legacy FDB tables do not join")
    return tuple(entries)


def fdb_key(entry: SwitchFdbEntry) -> tuple[str, str]:
    return entry.vlan_key, entry.mac
