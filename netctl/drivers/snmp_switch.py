from __future__ import annotations

from typing import Any

from ..snmp.collector import collect_switch_discovery, collect_switch_snapshot
from ..snmp.models import SwitchDiscovery, SwitchSnapshot
from ..snmp.transport import SnmpTransport, collect_on_worker_loop


class SnmpSwitchDriver:
    """Thin synchronous adapter around the typed asynchronous SNMP collector."""

    def __init__(self, source: dict[str, Any], secrets: dict[str, str]) -> None:
        self.source = source
        self.secrets = secrets

    def collect(self) -> SwitchSnapshot:
        async def collect() -> SwitchSnapshot:
            transport = SnmpTransport.from_source(self.source, secrets=self.secrets)
            try:
                return await collect_switch_snapshot(self.source, transport)
            finally:
                await transport.close()

        return collect_on_worker_loop(collect)

    def test(self) -> dict[str, Any]:
        return self.collect().to_test_summary()

    def discover(self) -> SwitchDiscovery:
        async def discover() -> SwitchDiscovery:
            transport = SnmpTransport.from_source(self.source, secrets=self.secrets)
            try:
                return await collect_switch_discovery(self.source, transport)
            finally:
                await transport.close()

        return collect_on_worker_loop(discover)
