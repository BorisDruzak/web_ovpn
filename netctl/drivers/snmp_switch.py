from __future__ import annotations

from typing import Any

from ..snmp.collector import collect_switch_snapshot
from ..snmp.models import SwitchSnapshot
from ..snmp.transport import SnmpTransport, collect_on_worker_loop
from .base import NetworkDriver


class SnmpSwitchDriver(NetworkDriver):
    """Thin synchronous adapter around the typed asynchronous SNMP collector."""

    def __init__(self, source: dict[str, Any], secrets: dict[str, str]) -> None:
        super().__init__(source, secrets)

    def collect(self, include_connections: bool = False) -> SwitchSnapshot:
        del include_connections
        async def collect() -> SwitchSnapshot:
            transport = SnmpTransport.from_source(self.source, secrets=self.secrets)
            try:
                return await collect_switch_snapshot(self.source, transport)
            finally:
                await transport.close()

        return collect_on_worker_loop(collect)

    def test(self) -> dict[str, Any]:
        return self.collect().to_dict()
