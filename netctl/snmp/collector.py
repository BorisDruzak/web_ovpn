from __future__ import annotations

from collections.abc import Mapping
from typing import Protocol

from .fdb import parse_legacy_fdb, parse_qbridge_fdb
from .interfaces import parse_bridge_port_map, parse_interfaces
from .models import CapabilityResult, SnmpVarBind, SwitchFdbEntry, SwitchSnapshot
from .oids import (
    DOT1D_BASE_PORT_IFINDEX,
    DOT1D_FDB_ADDRESS,
    DOT1D_FDB_PORT,
    DOT1D_FDB_STATUS,
    DOT1Q_FDB_PORT,
    DOT1Q_FDB_STATUS,
    DOT1Q_PVID,
    DOT1Q_VLAN_FDB_ID,
    DOT1Q_VLAN_CURRENT_EGRESS,
    DOT1Q_VLAN_CURRENT_UNTAGGED,
    DOT1D_STP_DESIGNATED_ROOT,
    DOT1D_STP_PROTOCOL,
    DOT1D_STP_ROOT_COST,
    DOT1D_STP_ROOT_PORT,
    DOT1D_STP_TOPOLOGY_CHANGES,
    IF_ADMIN_STATUS,
    IF_ALIAS,
    IF_DESCR,
    IF_HIGH_SPEED,
    IF_INDEX,
    IF_NAME,
    IF_OPER_STATUS,
    IF_PHYS_ADDRESS,
    IF_SPEED,
    SYS_DESCR,
    SYS_LOCATION,
    SYS_NAME,
    SYS_OBJECT_ID,
    SYS_UPTIME,
)
from .outcomes import SnmpOutcome
from .profiles import detect_profile
from .stp import parse_stp
from .system import parse_system
from .vlan import parse_vlan_memberships


class CollectorTransport(Protocol):
    async def get(
        self, oid: tuple[int, ...], *, capability: str = ""
    ) -> CapabilityResult: ...

    async def walk(
        self, oid: tuple[int, ...], *, capability: str = ""
    ) -> CapabilityResult: ...


_SYSTEM_CAPABILITIES = (
    (SYS_DESCR, "sys_descr"),
    (SYS_OBJECT_ID, "sys_object_id"),
    (SYS_UPTIME, "sys_uptime"),
    (SYS_NAME, "sys_name"),
    (SYS_LOCATION, "sys_location"),
)
_IF_TABLE_CAPABILITIES = (
    (IF_INDEX, "if_index"),
    (IF_DESCR, "if_descr"),
    (IF_SPEED, "if_speed"),
    (IF_PHYS_ADDRESS, "if_phys_address"),
    (IF_ADMIN_STATUS, "if_admin_status"),
    (IF_OPER_STATUS, "if_oper_status"),
)
_IFX_TABLE_CAPABILITIES = (
    (IF_NAME, "if_name"),
    (IF_HIGH_SPEED, "if_high_speed"),
    (IF_ALIAS, "if_alias"),
)


def _rows(results: tuple[CapabilityResult, ...]) -> tuple[SnmpVarBind, ...]:
    return tuple(row for result in results for row in result.rows)


def _final_fdb_result(
    outcome: SnmpOutcome,
    *,
    rows: tuple[SwitchFdbEntry, ...] = (),
    error_code: str = "",
    error_message: str = "",
) -> CapabilityResult:
    return CapabilityResult(
        capability="fdb",
        outcome=outcome,
        error_code=error_code,
        error_message=error_message,
        details={"normalized_row_count": len(rows)} if rows else {},
    )


def _propagate_fdb_failure(result: CapabilityResult) -> CapabilityResult:
    return _final_fdb_result(
        result.outcome,
        error_code=result.error_code,
        error_message=result.error_message,
    )


async def collect_switch_snapshot(
    source: Mapping[str, object], transport: CollectorTransport
) -> SwitchSnapshot:
    capabilities: list[CapabilityResult] = []

    system_results = tuple(
        [
            await transport.get(oid, capability=capability)
            for oid, capability in _SYSTEM_CAPABILITIES
        ]
    )
    capabilities.extend(system_results)
    system = parse_system(_rows(system_results))

    if_results = tuple(
        [
            await transport.walk(oid, capability=capability)
            for oid, capability in _IF_TABLE_CAPABILITIES
        ]
    )
    ifx_results = tuple(
        [
            await transport.walk(oid, capability=capability)
            for oid, capability in _IFX_TABLE_CAPABILITIES
        ]
    )
    bridge_result = await transport.walk(
        DOT1D_BASE_PORT_IFINDEX, capability="bridge_port_ifindex"
    )
    capabilities.extend((*if_results, *ifx_results, bridge_result))
    bridge_to_ifindex = parse_bridge_port_map(bridge_result.rows)
    ports = parse_interfaces(
        _rows(if_results), _rows(ifx_results), bridge_to_ifindex
    )

    options = source.get("driver_options")
    profile_hint: str | None = None
    if isinstance(options, Mapping):
        hint = options.get("profile_hint")
        if hint is not None and not isinstance(hint, str):
            raise ValueError("SNMP profile_hint is invalid")
        profile_hint = hint
    profile = detect_profile(system, profile_hint=profile_hint)

    qbridge_port = await transport.walk(DOT1Q_FDB_PORT, capability="qbridge_port")
    capabilities.append(qbridge_port)
    fdb: tuple[SwitchFdbEntry, ...] = ()

    if qbridge_port.outcome is SnmpOutcome.SUCCESS_EMPTY:
        final_fdb = _final_fdb_result(SnmpOutcome.SUCCESS_EMPTY)
    elif qbridge_port.outcome is SnmpOutcome.SUCCESS_WITH_ROWS:
        qbridge_status = await transport.walk(
            DOT1Q_FDB_STATUS, capability="qbridge_status"
        )
        capabilities.append(qbridge_status)
        if qbridge_status.outcome not in {
            SnmpOutcome.SUCCESS_WITH_ROWS,
            SnmpOutcome.SUCCESS_EMPTY,
        }:
            final_fdb = _propagate_fdb_failure(qbridge_status)
        else:
            vlan_fdb_id = await transport.walk(
                DOT1Q_VLAN_FDB_ID, capability="vlan_fdb_id"
            )
            capabilities.append(vlan_fdb_id)
            if vlan_fdb_id.outcome not in {
                SnmpOutcome.SUCCESS_WITH_ROWS,
                SnmpOutcome.SUCCESS_EMPTY,
                SnmpOutcome.UNSUPPORTED_NO_SUCH_OBJECT,
            }:
                final_fdb = _propagate_fdb_failure(vlan_fdb_id)
            else:
                try:
                    fdb = parse_qbridge_fdb(
                        qbridge_port,
                        qbridge_status,
                        vlan_fdb_id,
                        profile=profile,
                        ports=ports,
                        bridge_to_ifindex=bridge_to_ifindex,
                    )
                except ValueError:
                    fdb = ()
                    final_fdb = _final_fdb_result(
                        SnmpOutcome.PARSE_ERROR,
                        error_code="malformed_fdb",
                        error_message="SNMP FDB rows are malformed",
                    )
                else:
                    final_fdb = _final_fdb_result(
                        SnmpOutcome.SUCCESS_WITH_ROWS, rows=fdb
                    )
    elif qbridge_port.outcome is SnmpOutcome.UNSUPPORTED_NO_SUCH_OBJECT:
        legacy_address = await transport.walk(
            DOT1D_FDB_ADDRESS, capability="legacy_address"
        )
        legacy_port = await transport.walk(DOT1D_FDB_PORT, capability="legacy_port")
        legacy_status = await transport.walk(
            DOT1D_FDB_STATUS, capability="legacy_status"
        )
        capabilities.extend((legacy_address, legacy_port, legacy_status))
        legacy_results = (legacy_address, legacy_port, legacy_status)
        failure = next(
            (
                result
                for result in legacy_results
                if result.outcome
                not in {SnmpOutcome.SUCCESS_WITH_ROWS, SnmpOutcome.SUCCESS_EMPTY}
            ),
            None,
        )
        if failure is not None:
            final_fdb = _propagate_fdb_failure(failure)
        elif all(
            result.outcome is SnmpOutcome.SUCCESS_EMPTY for result in legacy_results
        ):
            final_fdb = _final_fdb_result(SnmpOutcome.SUCCESS_EMPTY)
        else:
            try:
                fdb = parse_legacy_fdb(
                    legacy_address,
                    legacy_port,
                    legacy_status,
                    profile=profile,
                    ports=ports,
                    bridge_to_ifindex=bridge_to_ifindex,
                )
            except ValueError:
                fdb = ()
                final_fdb = _final_fdb_result(
                    SnmpOutcome.PARSE_ERROR,
                    error_code="malformed_fdb",
                    error_message="SNMP FDB rows are malformed",
                )
            else:
                final_fdb = _final_fdb_result(
                    SnmpOutcome.SUCCESS_WITH_ROWS if fdb else SnmpOutcome.SUCCESS_EMPTY,
                    rows=fdb,
                )
    else:
        final_fdb = _propagate_fdb_failure(qbridge_port)

    capabilities.append(final_fdb)
    vlan_memberships: tuple[dict[str, object], ...] = ()
    stp: dict[str, object] | None = None
    if profile.profile_id == "snr":
        vlan_results = (
            await transport.walk(
                DOT1Q_VLAN_CURRENT_EGRESS, capability="vlan_current_egress"
            ),
            await transport.walk(
                DOT1Q_VLAN_CURRENT_UNTAGGED, capability="vlan_current_untagged"
            ),
            await transport.walk(DOT1Q_PVID, capability="pvid"),
        )
        capabilities.extend(vlan_results)
        if all(
            result.outcome
            in {SnmpOutcome.SUCCESS_WITH_ROWS, SnmpOutcome.SUCCESS_EMPTY}
            for result in vlan_results
        ):
            try:
                vlan_memberships = parse_vlan_memberships(
                    *vlan_results,
                    profile=profile,
                    ports=ports,
                    bridge_to_ifindex=bridge_to_ifindex,
                )
            except ValueError:
                vlan_memberships = ()

        stp_results = (
            await transport.get(DOT1D_STP_PROTOCOL, capability="stp_protocol"),
            await transport.get(
                DOT1D_STP_TOPOLOGY_CHANGES, capability="stp_topology_changes"
            ),
            await transport.get(
                DOT1D_STP_DESIGNATED_ROOT, capability="stp_designated_root"
            ),
            await transport.get(DOT1D_STP_ROOT_COST, capability="stp_root_cost"),
            await transport.get(DOT1D_STP_ROOT_PORT, capability="stp_root_port"),
        )
        capabilities.extend(stp_results)
        if all(result.outcome is SnmpOutcome.SUCCESS_WITH_ROWS for result in stp_results):
            try:
                stp = parse_stp(
                    *stp_results,
                    profile=profile,
                    ports=ports,
                    bridge_to_ifindex=bridge_to_ifindex,
                )
            except ValueError:
                stp = None
    return SwitchSnapshot(
        snapshot_kind="snmp_switch",
        profile_id=profile.profile_id,
        profile_fingerprint=profile.profile_fingerprint,
        system=system,
        ports=ports,
        fdb=fdb,
        vlan_memberships=vlan_memberships,
        stp=stp,
        lldp_neighbors=(),
        counter_samples=(),
        capabilities=tuple(capabilities),
    )
