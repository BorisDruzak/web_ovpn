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
        "routes": ("/ip/route/print", ["dst-address", "gateway", "distance", "active", "disabled", "dynamic", "comment", "routing-table"]),
        "arp": ("/ip/arp/print", ["address", "mac-address", "interface", "published", "complete", "dynamic", "comment"]),
        "dhcp_leases": (
            "/ip/dhcp-server/lease/print",
            ["address", "mac-address", "host-name", "server", "status", "dynamic", "active-address", "active-mac-address", "expires-after", "last-seen", "comment"],
        ),
        "neighbors": ("/ip/neighbor/print", ["address", "mac-address", "identity", "interface", "platform", "version", "uptime"]),
        "bridge_hosts": ("/interface/bridge/host/print", ["mac-address", "bridge", "interface", "local", "external", "dynamic", "age"]),
        "bridge_ports": ("/interface/bridge/port/print", ["interface", "bridge", "disabled", "dynamic", "comment"]),
        "firewall_address_lists": ("/ip/firewall/address-list/print", ["list", "address", "comment", "dynamic", "disabled", "creation-time"]),
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
        return {
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
            "addresses": raw.get("addresses", []),
        }
