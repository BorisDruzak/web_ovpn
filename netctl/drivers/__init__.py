from __future__ import annotations

from typing import Any, TypeAlias

from .base import NetworkDriver
from .mikrotik_api import MikroTikApiDriver
from .mikrotik_ssh import MikroTikSshDriver
from .mock import MockDriver
from .snmp_switch import SnmpSwitchDriver

__all__ = [
    "NetworkDriver",
    "MikroTikApiDriver",
    "MikroTikSshDriver",
    "MockDriver",
    "SnmpSwitchDriver",
    "Driver",
    "driver_for",
    "legacy_driver_for",
    "snmp_driver_for",
]

Driver: TypeAlias = NetworkDriver | SnmpSwitchDriver


def legacy_driver_for(
    source: dict[str, Any], secrets: dict[str, str]
) -> NetworkDriver:
    driver = str(source.get("driver") or "")
    if driver == "mock":
        return MockDriver(source, secrets)
    if driver == "mikrotik_api":
        return MikroTikApiDriver(source, secrets)
    if driver == "mikrotik_ssh":
        return MikroTikSshDriver(source, secrets)
    raise ValueError(f"unsupported legacy driver: {driver}")


def snmp_driver_for(
    source: dict[str, Any], secrets: dict[str, str]
) -> SnmpSwitchDriver:
    driver = str(source.get("driver") or "")
    if driver != "snmp_switch":
        raise ValueError(f"unsupported switch driver: {driver}")
    return SnmpSwitchDriver(source, secrets)


def driver_for(source: dict[str, Any], secrets: dict[str, str]) -> Driver:
    driver = str(source.get("driver") or "")
    if driver == "snmp_switch":
        return snmp_driver_for(source, secrets)
    try:
        return legacy_driver_for(source, secrets)
    except ValueError:
        raise ValueError(f"unsupported driver: {driver}") from None
