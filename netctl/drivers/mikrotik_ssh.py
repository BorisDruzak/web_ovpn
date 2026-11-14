from __future__ import annotations

import ipaddress
import re
import shlex
import subprocess
from typing import Any

from .base import NetworkDriver
from .mikrotik_api import MikroTikApiDriver


INTERFACE_COUNTER_KEYS = ("rx-byte", "tx-byte", "rx-packet", "tx-packet")
INTERFACE_COUNTER_COMMAND = (
    ':foreach row in=[/interface print stats as-value] do={:put (($row->"name") . "|" . '
    '($row->"rx-byte") . "|" . ($row->"tx-byte") . "|" . ($row->"rx-packet") . "|" . ($row->"tx-packet"))}'
)
ARP_FLAGS = {"dynamic": "D", "complete": "C"}
BRIDGE_HOST_FLAGS = {"dynamic": "D", "local": "L"}


class RouterOSSshTransportError(RuntimeError):
    """OpenSSH could not complete the remote session."""


def parse_routeros_terse(output: str, *, interface_flags: bool = False,
                         row_flags: dict[str, str] | None = None) -> list[dict[str, str]]:
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
        tokens = shlex.split(stripped)
        for token in tokens:
            if "=" not in token:
                continue
            key, value = token.split("=", 1)
            row[key] = value
        if row:
            if (interface_flags or row_flags) and tokens[0].isdigit():
                flags = ""
                for token in tokens[1:]:
                    if not re.fullmatch(r"[A-Z]+", token):
                        break
                    flags += token
                if interface_flags:
                    row.setdefault("running", "yes" if "R" in flags else "no")
                    row.setdefault("disabled", "yes" if "X" in flags else "no")
                for field, flag in (row_flags or {}).items():
                    row.setdefault(field, "yes" if flag in flags else "no")
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
        "routing_rules": "/routing rule",
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
        "ipsec_policies": "/ip ipsec policy",
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
        routeros_command = f"{path} print"
        if terse:
            routeros_command += " terse"
        output = self._run_read(routeros_command)
        row_flags = {"/ip arp": ARP_FLAGS, "/interface bridge host": BRIDGE_HOST_FLAGS}.get(path) if terse else None
        return parse_routeros_terse(output, interface_flags=terse and path == "/interface", row_flags=row_flags)

    def _run_read(self, routeros_command: str, *, timeout: float | None = None) -> str:
        target = f"{self.source['username']}@{self.source['host']}"
        completed = subprocess.run(
            [*self._ssh_base(), target, routeros_command],
            shell=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout if timeout is not None else int(self.source.get("ssh_connect_timeout") or 8) + 10,
            check=False,
        )
        if completed.returncode != 0:
            failure = RouterOSSshTransportError if completed.returncode == 255 else RuntimeError
            raise failure((completed.stderr or completed.stdout or "ssh command failed").strip())
        return completed.stdout

    def read_ethernet_link_modes(self, names: list[str]) -> dict[str, dict[str, str]]:
        if len(names) > 8 or any(not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,31}", name) for name in names):
            raise ValueError("invalid RouterOS Ethernet interfaces")
        fields = {"name", "status", "rate", "full-duplex", "auto-negotiation"}
        timeout = int(self.source.get("ssh_connect_timeout") or 8) + 3
        readings = {}
        for name in names:
            try:
                output = self._run_read(f"/interface ethernet monitor {name} once", timeout=timeout)
            except (OSError, subprocess.TimeoutExpired, RuntimeError):
                break
            row = {}
            for line in output.splitlines():
                key, sep, value = line.strip().partition(":")
                if not sep or key not in fields:
                    continue
                if key in row:
                    break
                row[key] = value.strip()
            else:
                if row.get("name") == name and row.get("status") == "link-ok":
                    readings[name] = row
        return readings

    def _interface_counters(self) -> dict[str, dict[str, str]]:
        counters = {}
        for line in self._run_read(INTERFACE_COUNTER_COMMAND).splitlines():
            fields = line.rsplit("|", len(INTERFACE_COUNTER_KEYS))
            if len(fields) != len(INTERFACE_COUNTER_KEYS) + 1 or not fields[0]:
                continue
            counters[fields[0]] = {
                key: value for key, value in zip(INTERFACE_COUNTER_KEYS, fields[1:]) if value.isdecimal()
            }
        return counters

    def test(self) -> dict[str, Any]:
        identity = self._run_print("/system identity", terse=False)
        resource = self._run_print("/system resource", terse=False)
        return {"status": "ok", "identity": identity[0].get("name") if identity else "", "resource": resource[0] if resource else {}}

    def ping_ipv4(self, address: str, source_address: str) -> bool:
        destination = ipaddress.IPv4Address(address)
        origin = ipaddress.IPv4Address(source_address)
        target = f"{self.source['username']}@{self.source['host']}"
        result = subprocess.run(
            [*self._ssh_base(), target, f"/ping address={destination} src-address={origin} count=1"],
            capture_output=True, text=True, timeout=int(self.source.get("ssh_connect_timeout") or 8) + 3, check=False,
        )
        return result.returncode == 0 and re.search(r"\bsent=1\s+received=1\b", result.stdout) is not None

    def ping_ipv4_via_interface(self, address: str, interface: str) -> bool | None:
        destination = ipaddress.IPv4Address(address)
        if not destination.is_global or destination.is_multicast or not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,31}", interface):
            raise ValueError("WAN ping requires a public IPv4 address and an interface name")
        target = f"{self.source['username']}@{self.source['host']}"
        result = subprocess.run(
            [*self._ssh_base(), target, f"/ping address={destination} interface={interface} count=1"],
            capture_output=True, text=True, timeout=int(self.source.get("ssh_connect_timeout") or 8) + 3, check=False,
        )
        counts = re.findall(r"^\s*sent=1[ \t]+received=([01])\b", result.stdout, re.MULTILINE)
        return counts[0] == "1" if result.returncode == 0 and len(counts) == 1 else None

    def pppoe_interfaces(self) -> list[dict[str, Any]]:
        # A full PPPoE print on RouterOS 6 can include credentials.
        query = (
            ':foreach i in=[/interface pppoe-client find] do={'
            ':local n [/interface pppoe-client get $i name]; '
            ':local p [/interface pppoe-client get $i interface]; '
            ':put ($n . "|" . $p . "|" . [/interface get $i running] . "|" . [/interface get $i disabled])}'
        )
        target = f"{self.source['username']}@{self.source['host']}"
        result = subprocess.run([*self._ssh_base(), target, query], capture_output=True, text=True,
                                timeout=int(self.source.get("ssh_connect_timeout") or 8) + 3, check=False)
        if result.returncode != 0:
            raise RuntimeError("RouterOS PPPoE observation failed")
        interfaces = []
        for line in result.stdout.splitlines()[:64]:
            parts = line.strip().split("|")
            if len(parts) != 4:
                continue
            name, parent, running, disabled = parts
            if (all(re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,31}", value) for value in (name, parent))
                    and running in ("true", "false", "yes", "no") and disabled in ("true", "false", "yes", "no")):
                interfaces.append({"name": name, "parent": parent, "running": running in ("true", "yes"),
                                   "disabled": disabled in ("true", "yes")})
        return interfaces

    def collect(self, include_connections: bool = False) -> dict[str, Any]:
        raw: dict[str, Any] = {}
        failed_path_fact_keys: set[str] = set()
        for key, path in self.COLLECT_PATHS.items():
            try:
                raw[key] = self._run_print(
                    path,
                    terse=key not in {"system_resource", "identity", "system_package_update", "routerboard"},
                )
            except Exception:
                if key not in MikroTikApiDriver.PATH_FACT_KEYS:
                    raise
                failed_path_fact_keys.add(key)
        interfaces = raw.get("interfaces", [])
        if any("rx-byte" not in row or "tx-byte" not in row for row in interfaces):
            try:
                stats = self._interface_counters()
            except (OSError, subprocess.SubprocessError, RuntimeError, ValueError):
                stats = {}
            for row in interfaces:
                row.update(stats.get(row.get("name"), {}))
        snapshot = {
            "system_resource": raw.get("system_resource", []),
            "identity": raw.get("identity", []),
            "interfaces": MikroTikApiDriver.normalize_interface_rows(interfaces),
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
            "router_routing_rules": MikroTikApiDriver.normalize_routing_rule_rows(raw.get("routing_rules", [])),
            "ipsec_policies": MikroTikApiDriver.normalize_path_ipsec_policy_rows(raw.get("ipsec_policies", [])),
        }
        snapshot["path_fact_outcomes"] = MikroTikApiDriver.path_fact_outcomes(snapshot, failed_keys=failed_path_fact_keys)
        return snapshot

    def read_ipsec_policies(self) -> list[dict[str, Any]]:
        rows = self._run_print(self.IPSEC_PATHS["policies"])
        if not rows or any(
            not row.get("src-address") or not row.get("dst-address")
            or (row.get("template") != "yes" and not row.get("action"))
            or (row.get("action") == "encrypt" and row.get("template") != "yes"
                and (row.get("tunnel") not in {"yes", "no"} or (row["tunnel"] == "yes" and not row.get("peer"))))
            for row in rows
        ):
            raise ValueError("RouterOS IPsec policy table is empty or incomplete")
        return MikroTikApiDriver.normalize_ipsec_policy_rows(rows)

    def ipsec_status(self) -> dict[str, Any]:
        raw: dict[str, Any] = {}
        errors: list[dict[str, str]] = []
        for key, path in self.IPSEC_PATHS.items():
            try:
                raw[key] = self._run_print(path)
            except RouterOSSshTransportError as exc:
                reason = (
                    "ssh_connect_timeout"
                    if re.search(r"(?:connect to host .*: Connection timed out|Connection timed out during banner exchange)",
                                 str(exc), re.IGNORECASE)
                    else "ssh_transport_error"
                )
                errors.append({"section": key, "message": str(exc), "reason": reason})
                break
            except Exception as exc:
                raw[key] = []
                errors.append({"section": key, "message": str(exc)})
        return {
            "active_peers": MikroTikApiDriver.normalize_ipsec_active_peers(raw.get("active_peers", [])),
            "policies": MikroTikApiDriver.normalize_ipsec_policy_rows(raw.get("policies", [])),
            "installed_sas": [],
            "errors": errors,
        }
