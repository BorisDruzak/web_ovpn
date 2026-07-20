from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .outcomes import SnmpOutcome


_TEST_SUMMARY_CAPABILITY_LIMIT = 32


def _bounded_identity_text(value: object, *, limit: int) -> str:
    if type(value) is not str:
        return ""
    normalized = " ".join(value.split())
    return normalized[:limit]


@dataclass(frozen=True)
class SnmpVarBind:
    oid: tuple[int, ...]
    value_type: str
    value: int | str | bytes


@dataclass(frozen=True)
class CapabilityResult:
    capability: str
    outcome: SnmpOutcome
    rows: tuple[SnmpVarBind, ...] = ()
    error_code: str = ""
    error_message: str = ""
    details: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class SwitchSystem:
    sys_descr: str
    sys_object_id: str
    sys_name: str
    sys_location: str
    sys_uptime_ticks: int | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "sys_descr": self.sys_descr,
            "sys_object_id": self.sys_object_id,
            "sys_name": self.sys_name,
            "sys_location": self.sys_location,
            "sys_uptime_ticks": self.sys_uptime_ticks,
        }


@dataclass(frozen=True)
class SwitchPort:
    port_key: str
    if_index: int | None
    bridge_port: int | None
    physical_port: int | None
    name: str
    alias: str
    mac: str | None
    admin_status: str
    oper_status: str
    speed_bps: int | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "port_key": self.port_key,
            "if_index": self.if_index,
            "bridge_port": self.bridge_port,
            "physical_port": self.physical_port,
            "name": self.name,
            "alias": self.alias,
            "mac": self.mac,
            "admin_status": self.admin_status,
            "oper_status": self.oper_status,
            "speed_bps": self.speed_bps,
        }


@dataclass(frozen=True)
class PortResolution:
    port_key: str
    if_index: int | None
    bridge_port: int | None
    physical_port: int | None
    port_name: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "port_key": self.port_key,
            "if_index": self.if_index,
            "bridge_port": self.bridge_port,
            "physical_port": self.physical_port,
            "port_name": self.port_name,
        }


@dataclass(frozen=True)
class SwitchFdbEntry:
    fdb_id: int | None
    vlan_key: str
    vlan_id: int | None
    mac: str
    port_key: str
    bridge_port: int | None
    if_index: int | None
    physical_port: int | None
    port_name: str
    status: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "fdb_id": self.fdb_id,
            "vlan_key": self.vlan_key,
            "vlan_id": self.vlan_id,
            "mac": self.mac,
            "port_key": self.port_key,
            "bridge_port": self.bridge_port,
            "if_index": self.if_index,
            "physical_port": self.physical_port,
            "port_name": self.port_name,
            "status": self.status,
        }


@dataclass(frozen=True)
class SwitchCounterSample:
    port_key: str
    if_index: int | None
    sys_uptime_ticks: int | None
    in_errors: int | None
    in_discards: int | None
    out_errors: int | None
    out_discards: int | None
    in_octets: int | None
    out_octets: int | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "port_key": self.port_key,
            "if_index": self.if_index,
            "sys_uptime_ticks": self.sys_uptime_ticks,
            "in_errors": self.in_errors,
            "in_discards": self.in_discards,
            "out_errors": self.out_errors,
            "out_discards": self.out_discards,
            "in_octets": self.in_octets,
            "out_octets": self.out_octets,
        }


def capability_to_dict(result: CapabilityResult) -> dict[str, str]:
    """Serialize only stable, sanitized capability metadata, never raw rows/details."""
    return {
        "capability": result.capability,
        "outcome": result.outcome.value,
        "error_code": result.error_code,
        "error_message": result.error_message,
    }


@dataclass(frozen=True)
class SwitchSnapshot:
    snapshot_kind: str
    profile_id: str
    profile_fingerprint: str
    system: SwitchSystem
    ports: tuple[SwitchPort, ...]
    fdb: tuple[SwitchFdbEntry, ...]
    vlan_memberships: tuple[dict[str, Any], ...]
    stp: dict[str, Any] | None
    lldp_neighbors: tuple[dict[str, Any], ...]
    counter_samples: tuple[SwitchCounterSample, ...]
    capabilities: tuple[CapabilityResult, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "snapshot_kind": self.snapshot_kind,
            "profile_id": self.profile_id,
            "profile_fingerprint": self.profile_fingerprint,
            "system": self.system.to_dict(),
            "ports": [port.to_dict() for port in self.ports],
            "fdb": [entry.to_dict() for entry in self.fdb],
            "vlan_memberships": [dict(row) for row in self.vlan_memberships],
            "stp": None if self.stp is None else dict(self.stp),
            "lldp_neighbors": [dict(row) for row in self.lldp_neighbors],
            "counter_samples": [sample.to_dict() for sample in self.counter_samples],
            "capabilities": [capability_to_dict(row) for row in self.capabilities],
        }

    def to_test_summary(self) -> dict[str, Any]:
        """Return the bounded public result for ``sources test``.

        Detailed ports and FDB rows are intentionally available only through
        the paginated switch query commands.
        """
        capabilities = []
        for result in self.capabilities[:_TEST_SUMMARY_CAPABILITY_LIMIT]:
            if type(result) is not CapabilityResult or not isinstance(
                result.outcome, SnmpOutcome
            ):
                continue
            capabilities.append(
                {
                    "capability": _bounded_identity_text(
                        result.capability, limit=64
                    ),
                    "outcome": result.outcome.value,
                }
            )
        return {
            "profile": {
                "id": _bounded_identity_text(self.profile_id, limit=64),
                "fingerprint": _bounded_identity_text(
                    self.profile_fingerprint, limit=128
                ),
            },
            "system": {
                "sys_descr": _bounded_identity_text(
                    self.system.sys_descr, limit=256
                ),
                "sys_object_id": _bounded_identity_text(
                    self.system.sys_object_id, limit=128
                ),
                "sys_name": _bounded_identity_text(
                    self.system.sys_name, limit=128
                ),
            },
            "capabilities": capabilities,
            "counts": {"ports": len(self.ports), "fdb": len(self.fdb)},
        }
