from __future__ import annotations

from .base import NetworkDriver
from .mikrotik_api import MikroTikApiDriver
from .mock import MockDriver

__all__ = ["NetworkDriver", "MikroTikApiDriver", "MockDriver", "driver_for"]


def driver_for(source: dict, secrets: dict[str, str]) -> NetworkDriver:
    driver = str(source.get("driver") or "")
    if driver == "mock":
        return MockDriver(source, secrets)
    if driver == "mikrotik_api":
        return MikroTikApiDriver(source, secrets)
    raise ValueError(f"unsupported driver: {driver}")
