from __future__ import annotations

import shlex
import subprocess
from typing import Any

from .base import NetworkDriver
from .mikrotik_api import MikroTikApiDriver


def parse_routeros_terse(output: str) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    scalar: dict[str, str] = {}
    for line in output.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if "=" not in stripped and ":" in stripped:
            key, value = stripped.split(":", 1)
            scalar[key.strip().replace(" ", "-")] = value.strip()
            continue
        row: dict[str, str] = {}
        for token in shlex.split(stripped):
            if "=" not in token:
                continue
            key, value = token.split("=", 1)
            row[key] = value
        if row:
            rows.append(row)
    if not rows and scalar:
        rows.append(scalar)
    return rows


class MikroTikSshDriver(NetworkDriver):
    COLLECT_PATHS: dict[str, str] = {
        "system_resource": "/system resource",
        "identity": "/system identity",
        "interfaces": "/interface",
        "addresses": "/ip address",
        "routes": "/ip route",
        "arp": "/ip arp",
        "dhcp_leases": "/ip dhcp-server lease",
        "neighbors": "/ip neighbor",
        "bridge_hosts": "/interface bridge host",
        "bridge_ports": "/interface bridge port",
        "firewall_address_lists": "/ip firewall address-list",
        "firewall_filter_rules": "/ip firewall filter",
        "firewall_nat_rules": "/ip firewall nat",
        "firewall_mangle_rules": "/ip firewall mangle",
        "system_package_update": "/system package update",
        "routerboard": "/system routerboard",
    }
    IPSEC_PATHS: dict[str, str] = {
        "active_peers": "/ip ipsec active-peers",
        "policies": "/ip ipsec policy",
    }

    def _ssh_base(self) -> list[str]:
        command = [
            "ssh",
            "-p",
            str(int(self.source.get("port") or 22)),
            "-o",
            "BatchMode=yes",
            "-o",
            f"ConnectTimeout={int(self.source.get('ssh_connect_timeout') or 8)}",
            "-o",
            "StrictHostKeyChecking=accept-new",
            "-o",
            "KexAlgorithms=diffie-hellman-group14-sha1",
            "-o",
            "HostKeyAlgorithms=+ssh-rsa",
            "-o",
            "PubkeyAcceptedAlgorithms=+ssh-rsa",
            "-o",
            "PubkeyAcceptedKeyTypes=+ssh-rsa",
            "-o",
            "MACs=+hmac-sha1,hmac-md5",
        ]
        identity = str(self.source.get("ssh_identity_file") or "")
        if identity:
            command.extend(["-i", identity, "-o", "IdentitiesOnly=yes"])
        proxy_jump = str(self.source.get("ssh_proxy_jump") or "")
        if proxy_jump:
            command.extend(["-J", proxy_jump])
        return command

    def _run_print(self, path: str, *, terse: bool = True) -> list[dict[str, str]]:
        if path not in set(self.COLLECT_PATHS.values()) | set(self.IPSEC_PATHS.values()):
            raise ValueError("RouterOS SSH driver only allows known read-only print paths")
        target = f"{self.source['username']}@{self.source['host']}"
        routeros_command = f"{path} print"
        if terse:
            routeros_command += " terse"
        completed = subprocess.run(
            [*self._ssh_base(), target, routeros_command],
            shell=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=int(self.source.get("ssh_connect_timeout") or 8) + 10,
            check=False,
        )
        if completed.returncode != 0:
            raise RuntimeError((completed.stderr or completed.stdout or "ssh command failed").strip())
        return parse_routeros_terse(completed.stdout)

    def test(self) -> dict[str, Any]:
        identity = self._run_print("/system identity", terse=False)
        resource = self._run_print("/system resource", terse=False)
        return {"status": "ok", "identity": identity[0].get("name") if identity else "", "resource": resource[0] if resource else {}}

    def collect(self, include_connections: bool = False) -> dict[str, Any]:
        raw: dict[str, Any] = {}
        for key, path in self.COLLECT_PATHS.items():
            raw[key] = self._run_print(
                path,
                terse=key not in {"system_resource", "identity", "system_package_update", "routerboard"},
            )
        return {
            "system_resource": raw.get("system_resource", []),
            "identity": raw.get("identity", []),
            "interfaces": MikroTikApiDriver.normalize_interface_rows(raw.get("interfaces", [])),
            "routes": MikroTikApiDriver.normalize_route_rows(raw.get("routes", [])),
            "arp": MikroTikApiDriver.normalize_arp_rows(raw.get("arp", [])),
            "dhcp_leases": MikroTikApiDriver.normalize_dhcp_rows(raw.get("dhcp_leases", [])),
            "neighbors": MikroTikApiDriver.normalize_neighbor_rows(raw.get("neighbors", [])),
            "bridge_hosts": MikroTikApiDriver.normalize_bridge_rows(raw.get("bridge_hosts", [])),
            "bridge_ports": raw.get("bridge_ports", []),
            "firewall_address_lists": MikroTikApiDriver.normalize_address_list_rows(raw.get("firewall_address_lists", [])),
            "firewall_filter_rules": MikroTikApiDriver.normalize_firewall_rule_rows(raw.get("firewall_filter_rules", []), "filter"),
            "firewall_nat_rules": MikroTikApiDriver.normalize_firewall_rule_rows(raw.get("firewall_nat_rules", []), "nat"),
            "firewall_mangle_rules": MikroTikApiDriver.normalize_firewall_rule_rows(raw.get("firewall_mangle_rules", []), "mangle"),
            "update_posture": MikroTikApiDriver.normalize_update_posture(
                raw.get("system_resource", []), raw.get("system_package_update", []), [], raw.get("routerboard", [])
            ),
            "addresses": raw.get("addresses", []),
        }

    def ipsec_status(self) -> dict[str, Any]:
        raw: dict[str, Any] = {}
        errors: list[dict[str, str]] = []
        for key, path in self.IPSEC_PATHS.items():
            try:
                raw[key] = self._run_print(path)
            except Exception as exc:
                raw[key] = []
                errors.append({"section": key, "message": str(exc)})
        return {
            "active_peers": MikroTikApiDriver.normalize_ipsec_active_peers(raw.get("active_peers", [])),
            "policies": MikroTikApiDriver.normalize_ipsec_policy_rows(raw.get("policies", [])),
            "installed_sas": [],
            "errors": errors,
        }
