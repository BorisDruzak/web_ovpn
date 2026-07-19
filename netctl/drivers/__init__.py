from __future__ import annotations

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
    "driver_for",
]


def driver_for(source: dict, secrets: dict[str, str]) -> NetworkDriver:
    driver = str(source.get("driver") or "")
    if driver == "mock":
        return MockDriver(source, secrets)
    if driver == "mikrotik_api":
        return MikroTikApiDriver(source, secrets)
    if driver == "mikrotik_ssh":
        return MikroTikSshDriver(source, secrets)
    if driver == "snmp_switch":
        return SnmpSwitchDriver(source, secrets)
    raise ValueError(f"unsupported driver: {driver}")
