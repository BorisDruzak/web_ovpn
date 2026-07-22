from __future__ import annotations

import socket
import ssl
from typing import Any

from netctl.config import secret_env_name
from netctl.util import normalize_mac, parse_bool, parse_int

from .base import NetworkDriver


def _read_len(sock: socket.socket) -> int:
    first = sock.recv(1)
    if not first:
        raise ConnectionError("RouterOS API connection closed")
    c = first[0]
    if (c & 0x80) == 0:
        return c
    if (c & 0xC0) == 0x80:
        return ((c & ~0xC0) << 8) + sock.recv(1)[0]
    if (c & 0xE0) == 0xC0:
        b = sock.recv(2)
        return ((c & ~0xE0) << 16) + (b[0] << 8) + b[1]
    if (c & 0xF0) == 0xE0:
        b = sock.recv(3)
        return ((c & ~0xF0) << 24) + (b[0] << 16) + (b[1] << 8) + b[2]
    b = sock.recv(4)
    return (b[0] << 24) + (b[1] << 16) + (b[2] << 8) + b[3]


def _write_len(length: int) -> bytes:
    if length < 0x80:
        return bytes([length])
    if length < 0x4000:
        return bytes([(length >> 8) | 0x80, length & 0xFF])
    if length < 0x200000:
        return bytes([(length >> 16) | 0xC0, (length >> 8) & 0xFF, length & 0xFF])
    if length < 0x10000000:
        return bytes([(length >> 24) | 0xE0, (length >> 16) & 0xFF, (length >> 8) & 0xFF, length & 0xFF])
    return bytes([0xF0, (length >> 24) & 0xFF, (length >> 16) & 0xFF, (length >> 8) & 0xFF, length & 0xFF])


class RouterOSApiClient:
    def __init__(self, host: str, port: int, username: str, password: str, tls: bool, verify_tls: bool, timeout: int = 8) -> None:
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.tls = tls
        self.verify_tls = verify_tls
        self.timeout = timeout
        self.sock: socket.socket | None = None

    def __enter__(self) -> "RouterOSApiClient":
        raw = socket.create_connection((self.host, self.port), timeout=self.timeout)
        raw.settimeout(self.timeout)
        if self.tls:
            context = ssl.create_default_context()
            if not self.verify_tls:
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
            self.sock = context.wrap_socket(raw, server_hostname=self.host if self.verify_tls else None)
        else:
            self.sock = raw
        self.call(["/login", f"=name={self.username}", f"=password={self.password}"])
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        if self.sock is not None:
            self.sock.close()
            self.sock = None

    def write_word(self, word: str) -> None:
        if self.sock is None:
            raise RuntimeError("not connected")
        data = word.encode("utf-8")
        self.sock.sendall(_write_len(len(data)) + data)

    def read_word(self) -> str:
        if self.sock is None:
            raise RuntimeError("not connected")
        length = _read_len(self.sock)
        if length == 0:
            return ""
        data = b""
        while len(data) < length:
            chunk = self.sock.recv(length - len(data))
            if not chunk:
                raise ConnectionError("RouterOS API connection closed")
            data += chunk
        return data.decode("utf-8", "replace")

    def call(self, words: list[str]) -> list[dict[str, str]]:
        for word in words:
            self.write_word(word)
        self.write_word("")
        rows: list[dict[str, str]] = []
        current: dict[str, str] = {}
        while True:
            word = self.read_word()
            if word == "":
                continue
            if word == "!re":
                current = {}
                while True:
                    item = self.read_word()
                    if item == "":
                        rows.append(current)
                        break
                    if item.startswith("="):
                        _, key, value = item.split("=", 2)
                        current[key] = value
            elif word == "!done":
                while self.read_word() != "":
                    pass
                return rows
            elif word in {"!trap", "!fatal"}:
                message = ""
                while True:
                    item = self.read_word()
                    if item == "":
                        break
                    if item.startswith("=message="):
                        message = item.removeprefix("=message=")
                raise RuntimeError(message or "RouterOS API error")


class MikroTikApiDriver(NetworkDriver):
    COLLECT_PATHS: dict[str, tuple[str, list[str]]] = {
        "system_resource": ("/system/resource/print", ["version", "board-name", "cpu-load", "free-memory", "uptime"]),
        "identity": ("/system/identity/print", ["name"]),
        "interfaces": (
            "/interface/print",
            ["name", "type", "running", "disabled", "mtu", "mac-address", "comment", "actual-mtu", "rx-byte", "tx-byte", "rx-packet", "tx-packet"],
        ),
        "addresses": ("/ip/address/print", ["address", "network", "interface", "disabled", "dynamic", "comment"]),
        "routing_rules": ("/routing/rule/print", [".id", "action", "disabled", "src-address", "dst-address", "routing-mark", "table", "comment", "priority"]),
        "routes": ("/ip/route/print", ["dst-address", "gateway", "distance", "active", "disabled", "dynamic", "comment", "routing-table", "scope", "target-scope", "immediate-gw"]),
        "arp": ("/ip/arp/print", ["address", "mac-address", "interface", "published", "complete", "dynamic", "comment"]),
        "dhcp_leases": (
            "/ip/dhcp-server/lease/print",
            ["address", "mac-address", "host-name", "server", "status", "dynamic", "active-address", "active-mac-address", "expires-after", "last-seen", "comment"],
        ),
        "neighbors": ("/ip/neighbor/print", ["address", "mac-address", "identity", "interface", "platform", "version", "uptime"]),
        "bridge_hosts": ("/interface/bridge/host/print", ["mac-address", "bridge", "interface", "local", "external", "dynamic", "age"]),
        "bridge_ports": ("/interface/bridge/port/print", ["interface", "bridge", "disabled", "dynamic", "comment"]),
        "firewall_address_lists": ("/ip/firewall/address-list/print", ["list", "address", "comment", "dynamic", "disabled", "creation-time"]),
        "firewall_filter_rules": (
            "/ip/firewall/filter/print",
            [".id", "chain", "action", "disabled", "src-address", "dst-address", "src-address-list", "dst-address-list", "protocol", "dst-port", "in-interface", "out-interface", "connection-state", "routing-mark", "comment", "packets", "bytes"],
        ),
        "firewall_nat_rules": (
            "/ip/firewall/nat/print",
            [".id", "chain", "action", "disabled", "src-address", "dst-address", "src-address-list", "dst-address-list", "protocol", "dst-port", "in-interface", "out-interface", "connection-state", "routing-mark", "comment", "packets", "bytes"],
        ),
        "firewall_mangle_rules": (
            "/ip/firewall/mangle/print",
            [".id", "chain", "action", "disabled", "src-address", "dst-address", "src-address-list", "dst-address-list", "protocol", "dst-port", "in-interface", "out-interface", "connection-state", "routing-mark", "comment", "packets", "bytes"],
        ),
        "ipsec_policies": ("/ip/ipsec/policy/print", [".id", "src-address", "dst-address", "protocol", "action", "disabled", "comment"]),
        "system_package_update": ("/system/package/update/print", ["channel", "installed-version", "latest-version"]),
        "system_schedulers": ("/system/scheduler/print", ["name", "disabled", "next-run", "interval", "start-date", "start-time"]),
        "routerboard": ("/system/routerboard/print", ["current-firmware", "upgrade-firmware"]),
    }
    IPSEC_PATHS: dict[str, tuple[str, list[str]]] = {
        "active_peers": (
            "/ip/ipsec/active-peers/print",
            [".id", "local-address", "remote-address", "state", "uptime", "ph2-total", "side", "dynamic"],
        ),
        "policies": (
            "/ip/ipsec/policy/print",
            [
                ".id",
                "peer",
                "tunnel",
                "src-address",
                "dst-address",
                "protocol",
                "action",
                "level",
                "ipsec-protocols",
                "sa-src-address",
                "sa-dst-address",
                "proposal",
                "ph2-count",
                "ph2-state",
                "active",
                "disabled",
                "template",
                "comment",
            ],
        ),
        "installed_sas": (
            "/ip/ipsec/installed-sa/print",
            [
                ".id",
                "src-address",
                "dst-address",
                "state",
                "spi",
                "auth-algorithm",
                "enc-algorithm",
                "current-bytes",
                "add-lifetime",
                "replay",
            ],
        ),
    }

    @staticmethod
    def ensure_read_only(path: str) -> None:
        if not path.endswith("/print"):
            raise ValueError("RouterOS driver is read-only and only print commands are allowed")

    @staticmethod
    def normalize_arp_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
        return [
            {
                "ip": row.get("address"),
                "mac": normalize_mac(row.get("mac-address")),
                "interface": row.get("interface") or "",
                "complete": parse_bool(row.get("complete"), True),
                "dynamic": parse_bool(row.get("dynamic")),
                "comment": row.get("comment") or "",
            }
            for row in rows
            if row.get("address")
        ]

    @staticmethod
    def normalize_dhcp_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
        result = []
        for row in rows:
            ip = row.get("active-address") or row.get("address")
            if not ip:
                continue
            result.append(
                {
                    "ip": ip,
                    "mac": normalize_mac(row.get("active-mac-address") or row.get("mac-address")),
                    "hostname": row.get("host-name") or "",
                    "server": row.get("server") or "",
                    "status": row.get("status") or "",
                    "dynamic": parse_bool(row.get("dynamic")),
                    "expires_after": row.get("expires-after") or "",
                    "last_seen": row.get("last-seen") or "",
                    "comment": row.get("comment") or "",
                }
            )
        return result

    @staticmethod
    def normalize_interface_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
        return [
            {
                "name": row.get("name") or "",
                "type": row.get("type") or "",
                "running": parse_bool(row.get("running")),
                "disabled": parse_bool(row.get("disabled")),
                "mac": normalize_mac(row.get("mac-address")),
                "comment": row.get("comment") or "",
                "rx_bytes": parse_int(row.get("rx-byte")),
                "tx_bytes": parse_int(row.get("tx-byte")),
                "rx_packets": parse_int(row.get("rx-packet")),
                "tx_packets": parse_int(row.get("tx-packet")),
            }
            for row in rows
        ]

    @staticmethod
    def normalize_route_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
        return [
            {
                "dst_address": row.get("dst-address") or "",
                "gateway": row.get("gateway") or "",
                "distance": row.get("distance") or "",
                "active": parse_bool(row.get("active")),
                "disabled": parse_bool(row.get("disabled")),
                "dynamic": parse_bool(row.get("dynamic")),
                "comment": row.get("comment") or "",
                "routing_table": row.get("routing-table") or "main",
                "scope": parse_int(row.get("scope")),
                "target_scope": parse_int(row.get("target-scope")),
                "immediate_gateway": row.get("immediate-gw") or "",
            }
            for row in rows
        ]

    @staticmethod
    def normalize_bridge_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
        return [
            {
                "mac": normalize_mac(row.get("mac-address")),
                "bridge": row.get("bridge") or "",
                "interface": row.get("interface") or "",
                "dynamic": parse_bool(row.get("dynamic")),
                "local": parse_bool(row.get("local")),
                "age": row.get("age") or "",
            }
            for row in rows
            if row.get("mac-address")
        ]

    @staticmethod
    def normalize_neighbor_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
        return [
            {
                "address": row.get("address") or "",
                "mac": normalize_mac(row.get("mac-address")),
                "identity": row.get("identity") or "",
                "interface": row.get("interface") or "",
                "platform": row.get("platform") or "",
                "version": row.get("version") or "",
                "uptime": row.get("uptime") or "",
            }
            for row in rows
        ]

    @staticmethod
    def normalize_address_list_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
        return [
            {
                "list": row.get("list") or "",
                "address": row.get("address") or "",
                "comment": row.get("comment") or "",
                "dynamic": parse_bool(row.get("dynamic")),
                "disabled": parse_bool(row.get("disabled")),
                "creation_time": row.get("creation-time") or "",
            }
            for row in rows
        ]

    @staticmethod
    def normalize_firewall_rule_rows(rows: list[dict[str, Any]], table: str) -> list[dict[str, Any]]:
        return [
            {
                "id": row.get(".id") or row.get("id") or "",
                "table": table,
                "chain": row.get("chain") or "",
                "action": row.get("action") or "",
                "disabled": parse_bool(row.get("disabled")),
                "src_address": row.get("src-address") or "",
                "dst_address": row.get("dst-address") or "",
                "src_address_list": row.get("src-address-list") or "",
                "dst_address_list": row.get("dst-address-list") or "",
                "protocol": row.get("protocol") or "",
                "dst_port": row.get("dst-port") or "",
                "in_interface": row.get("in-interface") or "",
                "out_interface": row.get("out-interface") or "",
                "routing_mark": row.get("routing-mark") or "",
                "connection_state": row.get("connection-state") or "",
                "comment": row.get("comment") or "",
                "packets": parse_int(row.get("packets")),
                "bytes": parse_int(row.get("bytes")),
            }
            for row in rows
        ]

    @staticmethod
    def normalize_routing_rule_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
        return [
            {
                "id": row.get(".id") or row.get("id") or "",
                "position": parse_int(row.get("priority")),
                "disabled": parse_bool(row.get("disabled")),
                "action": row.get("action") or "",
                "src_address": row.get("src-address") or "",
                "dst_address": row.get("dst-address") or "",
                "routing_mark": row.get("routing-mark") or "",
                "table_name": row.get("table") or "",
                "comment": row.get("comment") or "",
            }
            for row in rows
        ]

    @staticmethod
    def normalize_path_ipsec_policy_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
        return [
            {
                "id": row.get(".id") or row.get("id") or "",
                "position": index,
                "disabled": parse_bool(row.get("disabled")),
                "action": row.get("action") or "",
                "src_address": row.get("src-address") or "",
                "dst_address": row.get("dst-address") or "",
                "protocol": row.get("protocol") or "",
                "comment": row.get("comment") or "",
            }
            for index, row in enumerate(rows)
        ]

    @staticmethod
    def path_fact_outcomes(snapshot: dict[str, Any]) -> dict[str, str]:
        return {
            key: "success"
            for key in ("router_routing_rules", "firewall_address_lists", "firewall_filter_rules", "firewall_nat_rules", "firewall_mangle_rules", "ipsec_policies")
            if key in snapshot
        }

    @staticmethod
    def normalize_update_posture(
        resource_rows: list[dict[str, Any]],
        update_rows: list[dict[str, Any]],
        scheduler_rows: list[dict[str, Any]],
        routerboard_rows: list[dict[str, Any]],
    ) -> dict[str, Any]:
        update = update_rows[0] if update_rows else {}
        resource = resource_rows[0] if resource_rows else {}
        routerboard = routerboard_rows[0] if routerboard_rows else {}
        return {
            "channel": update.get("channel") or "",
            "installed_version": update.get("installed-version") or resource.get("version") or "",
            "latest_version": update.get("latest-version") or "",
            "routerboot_current_version": routerboard.get("current-firmware") or "",
            "routerboot_upgrade_version": routerboard.get("upgrade-firmware") or "",
            "schedulers": [
                {
                    "name": row.get("name") or "",
                    "disabled": parse_bool(row.get("disabled")),
                    "next_run": row.get("next-run") or "",
                    "interval": row.get("interval") or "",
                    "start_date": row.get("start-date") or "",
                    "start_time": row.get("start-time") or "",
                }
                for row in scheduler_rows
            ],
        }

    @staticmethod
    def normalize_ipsec_active_peers(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
        return [
            {
                "id": row.get(".id") or row.get("id") or "",
                "local_address": row.get("local-address") or "",
                "remote_address": row.get("remote-address") or row.get("address") or "",
                "state": row.get("state") or "",
                "uptime": row.get("uptime") or "",
                "ph2_total": parse_int(row.get("ph2-total") or row.get("ph2-count")),
                "side": row.get("side") or "",
                "dynamic": parse_bool(row.get("dynamic")),
            }
            for row in rows
        ]

    @staticmethod
    def normalize_ipsec_policy_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
        result = []
        for row in rows:
            if parse_bool(row.get("template")):
                continue
            ph2_count = parse_int(row.get("ph2-count"))
            ph2_state = row.get("ph2-state") or ""
            disabled = parse_bool(row.get("disabled"))
            active = parse_bool(row.get("active")) or ph2_count > 0
            established = not disabled and (ph2_state == "established" or ph2_count > 0)
            result.append(
                {
                    "id": row.get(".id") or row.get("id") or "",
                    "peer": row.get("peer") or "",
                    "src_address": row.get("src-address") or "",
                    "dst_address": row.get("dst-address") or "",
                    "protocol": row.get("protocol") or "",
                    "action": row.get("action") or "",
                    "level": row.get("level") or "",
                    "ipsec_protocols": row.get("ipsec-protocols") or "",
                    "sa_src_address": row.get("sa-src-address") or "",
                    "sa_dst_address": row.get("sa-dst-address") or "",
                    "proposal": row.get("proposal") or "",
                    "ph2_count": ph2_count,
                    "ph2_state": ph2_state,
                    "active": active,
                    "disabled": disabled,
                    "tunnel": parse_bool(row.get("tunnel")),
                    "comment": row.get("comment") or "",
                    "established": established,
                }
            )
        return result

    @staticmethod
    def normalize_ipsec_installed_sa_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
        return [
            {
                "id": row.get(".id") or row.get("id") or "",
                "src_address": row.get("src-address") or "",
                "dst_address": row.get("dst-address") or "",
                "state": row.get("state") or "",
                "spi": row.get("spi") or "",
                "auth_algorithm": row.get("auth-algorithm") or "",
                "enc_algorithm": row.get("enc-algorithm") or "",
                "current_bytes": parse_int(row.get("current-bytes")),
                "add_lifetime": row.get("add-lifetime") or "",
                "replay": row.get("replay") or "",
            }
            for row in rows
        ]

    def _password(self) -> str:
        key = secret_env_name(str(self.source.get("secret_ref") or self.source.get("name")))
        password = self.secrets.get(key)
        if not password:
            raise RuntimeError(f"missing secret {key}")
        return password

    def _client(self) -> RouterOSApiClient:
        return RouterOSApiClient(
            str(self.source["host"]),
            int(self.source.get("port") or 8729),
            str(self.source["username"]),
            self._password(),
            bool(self.source.get("tls")),
            bool(self.source.get("verify_tls")),
        )

    def _query(self, api: RouterOSApiClient, path: str, props: list[str]) -> list[dict[str, str]]:
        self.ensure_read_only(path)
        return api.call([path, f"=.proplist={','.join(props)}"])

    def test(self) -> dict[str, Any]:
        with self._client() as api:
            identity = self._query(api, "/system/identity/print", ["name"])
            resource = self._query(api, "/system/resource/print", ["version", "board-name"])
        return {"status": "ok", "identity": identity[0].get("name") if identity else "", "resource": resource[0] if resource else {}}

    def collect(self, include_connections: bool = False) -> dict[str, Any]:
        raw: dict[str, Any] = {}
        with self._client() as api:
            for key, (path, props) in self.COLLECT_PATHS.items():
                raw[key] = self._query(api, path, props)
        snapshot = {
            "system_resource": raw.get("system_resource", []),
            "identity": raw.get("identity", []),
            "interfaces": self.normalize_interface_rows(raw.get("interfaces", [])),
            "routes": self.normalize_route_rows(raw.get("routes", [])),
            "arp": self.normalize_arp_rows(raw.get("arp", [])),
            "dhcp_leases": self.normalize_dhcp_rows(raw.get("dhcp_leases", [])),
            "neighbors": self.normalize_neighbor_rows(raw.get("neighbors", [])),
            "bridge_hosts": self.normalize_bridge_rows(raw.get("bridge_hosts", [])),
            "bridge_ports": raw.get("bridge_ports", []),
            "firewall_address_lists": self.normalize_address_list_rows(raw.get("firewall_address_lists", [])),
            "firewall_filter_rules": self.normalize_firewall_rule_rows(raw.get("firewall_filter_rules", []), "filter"),
            "firewall_nat_rules": self.normalize_firewall_rule_rows(raw.get("firewall_nat_rules", []), "nat"),
            "firewall_mangle_rules": self.normalize_firewall_rule_rows(raw.get("firewall_mangle_rules", []), "mangle"),
            "update_posture": self.normalize_update_posture(
                raw.get("system_resource", []), raw.get("system_package_update", []), raw.get("system_schedulers", []), raw.get("routerboard", [])
            ),
            "addresses": raw.get("addresses", []),
            "router_routing_rules": self.normalize_routing_rule_rows(raw.get("routing_rules", [])),
            "ipsec_policies": self.normalize_path_ipsec_policy_rows(raw.get("ipsec_policies", [])),
        }
        snapshot["path_fact_outcomes"] = self.path_fact_outcomes(snapshot)
        return snapshot

    def ipsec_status(self) -> dict[str, Any]:
        raw: dict[str, Any] = {}
        errors: list[dict[str, str]] = []
        with self._client() as api:
            for key, (path, props) in self.IPSEC_PATHS.items():
                try:
                    raw[key] = self._query(api, path, props)
                except Exception as exc:
                    raw[key] = []
                    errors.append({"section": key, "message": str(exc)})
        return {
            "active_peers": self.normalize_ipsec_active_peers(raw.get("active_peers", [])),
            "policies": self.normalize_ipsec_policy_rows(raw.get("policies", [])),
            "installed_sas": self.normalize_ipsec_installed_sa_rows(raw.get("installed_sas", [])),
            "errors": errors,
        }
