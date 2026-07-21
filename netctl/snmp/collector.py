from __future__ import annotations

from collections.abc import Mapping
from typing import Protocol

from .fdb import parse_legacy_fdb, parse_qbridge_fdb_with_rejections
from .interfaces import parse_bridge_port_map, parse_interfaces
from .lldp import parse_lldp_neighbors
from .models import (
    CapabilityResult,
    SnmpVarBind,
    SwitchDiscovery,
    SwitchDiscoveryCapability,
    SwitchFdbEntry,
    SwitchPort,
    SwitchSnapshot,
)
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
    LLDP_REM_CHASSIS_ID,
    LLDP_REM_PORT_ID,
    LLDP_REM_SYS_NAME,
    SYS_DESCR,
    SYS_LOCATION,
    SYS_NAME,
    SYS_OBJECT_ID,
    SYS_UPTIME,
)
from .outcomes import SnmpOutcome
from .profiles import PortProfile, detect_profile
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
_USABLE_REQUIRED_OUTCOMES = {
    SnmpOutcome.SUCCESS_WITH_ROWS,
    SnmpOutcome.SUCCESS_EMPTY,
}


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


def _required_group_failure(
    results: tuple[CapabilityResult, ...],
) -> CapabilityResult | None:
    failure = next(
        (
            result
            for result in results
            if result.outcome not in _USABLE_REQUIRED_OUTCOMES
        ),
        None,
    )
    if failure is None:
        return None
    return _final_fdb_result(
        failure.outcome,
        error_code="required_capability_failed",
        error_message="Required SNMP collection was not successful",
    )


def _optional_parse_errors(
    results: tuple[CapabilityResult, ...],
    *,
    error_code: str,
    error_message: str,
) -> tuple[CapabilityResult, ...]:
    return tuple(
        CapabilityResult(
            capability=result.capability,
            outcome=SnmpOutcome.PARSE_ERROR,
            error_code=error_code,
            error_message=error_message,
        )
        for result in results
    )


def _optional_group_result(
    capability: str,
    outcome: SnmpOutcome,
    *,
    rows: tuple[dict[str, object], ...] = (),
    error_code: str = "",
    error_message: str = "",
) -> CapabilityResult:
    return CapabilityResult(
        capability=capability,
        outcome=outcome,
        error_code=error_code,
        error_message=error_message,
        details={"normalized_row_count": len(rows)} if rows else {},
    )


def _parse_optional_ifx(
    if_results: tuple[CapabilityResult, ...],
    ifx_results: tuple[CapabilityResult, ...],
    bridge_to_ifindex: dict[int, int],
    core_ports: tuple[SwitchPort, ...],
) -> tuple[tuple[SwitchPort, ...], tuple[CapabilityResult, ...]]:
    accepted: list[CapabilityResult] = []
    reported: list[CapabilityResult] = []
    ports = core_ports
    for result in ifx_results:
        if result.outcome not in _USABLE_REQUIRED_OUTCOMES:
            reported.append(result)
            continue
        try:
            enriched = parse_interfaces(
                _rows(if_results),
                _rows((*accepted, result)),
                bridge_to_ifindex,
            )
        except ValueError:
            reported.extend(
                _optional_parse_errors(
                    (result,),
                    error_code="malformed_ifx",
                    error_message="SNMP IFX rows are malformed",
                )
            )
        else:
            accepted.append(result)
            reported.append(result)
            ports = enriched
    return ports, tuple(reported)


async def _collect_legacy_fdb(
    transport: CollectorTransport,
    *,
    profile: PortProfile,
    ports: tuple[SwitchPort, ...],
    bridge_to_ifindex: dict[int, int],
    empty_fallback: CapabilityResult | None = None,
) -> tuple[
    tuple[SwitchFdbEntry, ...],
    CapabilityResult,
    tuple[CapabilityResult, ...],
]:
    legacy_address = await transport.walk(
        DOT1D_FDB_ADDRESS, capability="legacy_address"
    )
    legacy_port = await transport.walk(DOT1D_FDB_PORT, capability="legacy_port")
    legacy_status = await transport.walk(
        DOT1D_FDB_STATUS, capability="legacy_status"
    )
    legacy_results = (legacy_address, legacy_port, legacy_status)
    failure = next(
        (
            result
            for result in legacy_results
            if result.outcome not in _USABLE_REQUIRED_OUTCOMES
        ),
        None,
    )
    if failure is not None:
        return (
            (),
            empty_fallback if empty_fallback is not None else _propagate_fdb_failure(failure),
            legacy_results,
        )
    if all(result.outcome is SnmpOutcome.SUCCESS_EMPTY for result in legacy_results):
        return (
            (),
            empty_fallback
            if empty_fallback is not None
            else _final_fdb_result(SnmpOutcome.SUCCESS_EMPTY),
            legacy_results,
        )
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
        legacy_parse = _optional_group_result(
            "legacy_fdb",
            SnmpOutcome.PARSE_ERROR,
            error_code="malformed_fdb",
            error_message="Legacy SNMP FDB rows are malformed",
        )
        return (
            (),
            empty_fallback
            if empty_fallback is not None
            else _final_fdb_result(
                SnmpOutcome.PARSE_ERROR,
                error_code="malformed_fdb",
                error_message="SNMP FDB rows are malformed",
            ),
            (*legacy_results, legacy_parse),
        )
    return (
        fdb,
        _final_fdb_result(SnmpOutcome.SUCCESS_WITH_ROWS, rows=fdb)
        if fdb
        else empty_fallback
        if empty_fallback is not None
        else _final_fdb_result(SnmpOutcome.SUCCESS_EMPTY),
        legacy_results,
    )


async def collect_switch_snapshot(
    source: Mapping[str, object], transport: CollectorTransport
) -> SwitchSnapshot:
    system_results = await _collect_system_results(transport)
    capabilities: list[CapabilityResult] = list(system_results)
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
    required_failure = _required_group_failure(
        (*system_results, *if_results, bridge_result)
    )
    reported_ifx_results = ifx_results
    try:
        bridge_to_ifindex = parse_bridge_port_map(bridge_result.rows)
        ports = parse_interfaces(_rows(if_results), (), bridge_to_ifindex)
    except ValueError:
        if required_failure is None:
            raise
        bridge_to_ifindex = {}
        ports = ()
    else:
        ports, reported_ifx_results = _parse_optional_ifx(
            if_results,
            ifx_results,
            bridge_to_ifindex,
            ports,
        )
    capabilities.extend((*if_results, *reported_ifx_results, bridge_result))

    options = source.get("driver_options")
    profile_hint: str | None = None
    if isinstance(options, Mapping):
        hint = options.get("profile_hint")
        if hint is not None and not isinstance(hint, str):
            raise ValueError("SNMP profile_hint is invalid")
        profile_hint = hint
    profile = detect_profile(system, profile_hint=profile_hint)
    ports = profile.normalize_ports(ports)

    qbridge_port = await transport.walk(DOT1Q_FDB_PORT, capability="qbridge_port")
    capabilities.append(qbridge_port)
    fdb: tuple[SwitchFdbEntry, ...] = ()
    rejected_row_count = 0

    if qbridge_port.outcome is SnmpOutcome.SUCCESS_EMPTY:
        empty_qbridge = _final_fdb_result(SnmpOutcome.SUCCESS_EMPTY)
        fdb, final_fdb, legacy_results = await _collect_legacy_fdb(
            transport,
            profile=profile,
            ports=ports,
            bridge_to_ifindex=bridge_to_ifindex,
            empty_fallback=empty_qbridge,
        )
        capabilities.extend(legacy_results)
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
                    fdb, rejected_row_count = parse_qbridge_fdb_with_rejections(
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
                    final_fdb = (
                        _final_fdb_result(SnmpOutcome.SUCCESS_WITH_ROWS, rows=fdb)
                        if fdb
                        else _final_fdb_result(
                            SnmpOutcome.PARSE_ERROR,
                            error_code="malformed_fdb",
                            error_message="SNMP FDB rows are malformed",
                        )
                    )
    elif qbridge_port.outcome is SnmpOutcome.UNSUPPORTED_NO_SUCH_OBJECT:
        fdb, final_fdb, legacy_results = await _collect_legacy_fdb(
            transport,
            profile=profile,
            ports=ports,
            bridge_to_ifindex=bridge_to_ifindex,
        )
        capabilities.extend(legacy_results)
    else:
        final_fdb = _propagate_fdb_failure(qbridge_port)

    if required_failure is not None:
        fdb = ()
        final_fdb = required_failure
    elif (
        rejected_row_count
        and fdb
        and final_fdb.outcome is SnmpOutcome.SUCCESS_WITH_ROWS
    ):
        capabilities.append(
            CapabilityResult(
                capability="qbridge_fdb_rejected_rows",
                outcome=SnmpOutcome.PARSE_ERROR,
                error_code="invalid_fdb_rows_rejected",
                error_message="Invalid SNMP FDB rows were rejected",
                details={"rejected_row_count": rejected_row_count},
            )
        )
    capabilities.append(final_fdb)
    vlan_memberships: tuple[dict[str, object], ...] = ()
    stp: dict[str, object] | None = None
    if profile.profile_id in {"snr", "tplink", "css326"}:
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
                vlan_results = _optional_parse_errors(
                    vlan_results,
                    error_code="malformed_vlan",
                    error_message="SNMP VLAN rows are malformed",
                )
                capabilities[-len(vlan_results) :] = vlan_results

    if profile.profile_id == "snr":
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
                stp_results = _optional_parse_errors(
                    stp_results,
                    error_code="malformed_stp",
                    error_message="SNMP STP rows are malformed",
                )
                capabilities[-len(stp_results) :] = stp_results

    lldp_results = (
        await transport.walk(
            LLDP_REM_CHASSIS_ID, capability="lldp_remote_chassis_id"
        ),
        await transport.walk(LLDP_REM_PORT_ID, capability="lldp_remote_port_id"),
        await transport.walk(
            LLDP_REM_SYS_NAME, capability="lldp_remote_system_name"
        ),
    )
    capabilities.extend(lldp_results)
    lldp_neighbors: tuple[dict[str, object], ...] = ()
    lldp_failure = next(
        (
            result
            for result in lldp_results
            if result.outcome
            not in {SnmpOutcome.SUCCESS_WITH_ROWS, SnmpOutcome.SUCCESS_EMPTY}
        ),
        None,
    )
    if lldp_failure is not None:
        lldp_group = _optional_group_result(
            "lldp_remote",
            lldp_failure.outcome,
            error_code=lldp_failure.error_code,
            error_message=lldp_failure.error_message,
        )
    else:
        try:
            lldp_neighbors = parse_lldp_neighbors(*lldp_results, ports=ports)
        except ValueError:
            lldp_neighbors = ()
            lldp_results = _optional_parse_errors(
                lldp_results,
                error_code="malformed_lldp",
                error_message="SNMP LLDP rows are malformed",
            )
            capabilities[-len(lldp_results) :] = lldp_results
            lldp_group = _optional_group_result(
                "lldp_remote",
                SnmpOutcome.PARSE_ERROR,
                error_code="malformed_lldp",
                error_message="SNMP LLDP rows are malformed",
            )
        else:
            lldp_group = _optional_group_result(
                "lldp_remote",
                (
                    SnmpOutcome.SUCCESS_WITH_ROWS
                    if lldp_neighbors
                    else SnmpOutcome.SUCCESS_EMPTY
                ),
                rows=lldp_neighbors,
            )
    capabilities.append(lldp_group)
    return SwitchSnapshot(
        snapshot_kind="snmp_switch",
        profile_id=profile.profile_id,
        profile_fingerprint=profile.profile_fingerprint,
        system=system,
        ports=ports,
        fdb=fdb,
        vlan_memberships=vlan_memberships,
        stp=stp,
        lldp_neighbors=lldp_neighbors,
        counter_samples=(),
        capabilities=tuple(capabilities),
    )


async def collect_switch_discovery(
    options: Mapping[str, object], transport: CollectorTransport
) -> SwitchDiscovery:
    """Collect only SNMP system scalars for safe switch fingerprint discovery.

    ``options`` is deliberately accepted for a stable driver interface but is
    not inspected: discovery must not vary into interface, FDB, VLAN, bridge,
    LLDP, STP, or counter collection.
    """
    del options
    system_results = await _collect_system_results(transport)
    return SwitchDiscovery(
        system=parse_system(_rows(system_results)),
        capabilities=tuple(
            SwitchDiscoveryCapability(
                capability=result.capability,
                outcome=result.outcome,
            )
            for result in system_results
        ),
    )


async def _collect_system_results(
    transport: CollectorTransport,
) -> tuple[CapabilityResult, ...]:
    return tuple(
        [
            await transport.get(oid, capability=capability)
            for oid, capability in _SYSTEM_CAPABILITIES
        ]
    )
