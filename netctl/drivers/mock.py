from __future__ import annotations

from typing import Any

from .base import NetworkDriver


class MockDriver(NetworkDriver):
    def test(self) -> dict[str, Any]:
        return {"status": "ok", "identity": "mock-router", "resource": {"version": "mock"}}

    def collect(self, include_connections: bool = False) -> dict[str, Any]:
        return {
            "identity": [{"name": "mock-router"}],
            "system_resource": [{"version": "7.19.4", "board-name": "mock"}],
            "interfaces": [
                {
                    "name": "bridge-lan",
                    "type": "bridge",
                    "running": True,
                    "disabled": False,
                    "mac": "D4:01:C3:9C:83:5F",
                    "comment": "LAN",
                    "rx_bytes": 100,
                    "tx_bytes": 200,
                    "rx_packets": 10,
                    "tx_packets": 20,
                }
            ],
            "routes": [
                {
                    "dst_address": "192.168.50.0/24",
                    "gateway": "192.168.100.30",
                    "distance": "1",
                    "active": True,
                    "disabled": False,
                    "dynamic": False,
                    "comment": "OpenVPN new pool",
                    "routing_table": "main",
                }
            ],
            "arp": [
                {
                    "ip": "192.168.100.55",
                    "mac": "AA:BB:CC:DD:EE:FF",
                    "interface": "bridge-lan",
                    "complete": True,
                    "dynamic": True,
                    "comment": "printer",
                },
                {
                    "ip": "192.168.100.88",
                    "mac": "AA:BB:CC:DD:EE:88",
                    "interface": "bridge-lan",
                    "complete": True,
                    "dynamic": True,
                    "comment": "",
                },
                {
                    "ip": self.source.get("host"),
                    "mac": "D4:01:C3:9C:83:5F",
                    "interface": "bridge-lan",
                    "complete": True,
                    "dynamic": False,
                    "comment": "router",
                },
            ],
            "dhcp_leases": [
                {
                    "ip": "192.168.100.55",
                    "mac": "AA:BB:CC:DD:EE:FF",
                    "hostname": "pc-buh-01",
                    "server": "dhcp-main",
                    "status": "bound",
                    "dynamic": True,
                    "expires_after": "1h",
                    "last_seen": "1m",
                    "comment": "",
                }
            ],
            "neighbors": [
                {
                    "address": "192.168.100.70",
                    "mac": "AA:BB:CC:DD:EE:70",
                    "identity": "switch-core",
                    "interface": "bridge-lan",
                    "platform": "RouterOS",
                    "version": "7.19.4",
                    "uptime": "1d",
                }
            ],
            "bridge_hosts": [
                {
                    "mac": "AA:BB:CC:DD:EE:FF",
                    "bridge": "bridge-lan",
                    "interface": "ether2",
                    "dynamic": True,
                    "local": False,
                    "age": "10s",
                }
            ],
            "firewall_address_lists": [
                {"list": "CORP", "address": "192.168.100.0/23", "comment": "local", "dynamic": False, "disabled": False}
            ],
        }

    def ipsec_status(self) -> dict[str, Any]:
        return {
            "active_peers": [
                {
                    "id": "*1",
                    "local_address": "78.29.35.68",
                    "remote_address": "62.148.235.108",
                    "state": "established",
                    "uptime": "1h",
                    "ph2_total": 1,
                    "side": "responder",
                }
            ],
            "policies": [
                {
                    "id": "*2",
                    "peer": "m-arhiv",
                    "src_address": "192.168.100.0/23",
                    "dst_address": "192.168.99.0/24",
                    "active": True,
                    "disabled": False,
                    "tunnel": True,
                    "ph2_state": "established",
                    "ph2_count": 1,
                    "comment": "central to m-arhiv IPsec",
                    "established": True,
                }
            ],
            "installed_sas": [
                {
                    "id": "*3",
                    "src_address": "78.29.35.68",
                    "dst_address": "62.148.235.108",
                    "state": "mature",
                    "spi": "0x123",
                    "current_bytes": 1024,
                }
            ],
            "errors": [],
        }
