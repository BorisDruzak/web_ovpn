import hashlib
import importlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient


def make_executable(path: Path, content: str) -> Path:
    script_path = path.with_suffix(".py") if os.name == "nt" else path
    script_path.write_text(content, encoding="utf-8")
    script_path.chmod(0o755)
    if os.name != "nt":
        return script_path
    wrapper = path.with_suffix(".cmd")
    wrapper.write_text(f'@echo off\r\n"{sys.executable}" "{script_path}" %*\r\n', encoding="utf-8")
    return wrapper


def make_fake_vpnctl(path: Path) -> Path:
    return make_executable(
        path,
        """#!/usr/bin/env python3
import json
import sys
args = sys.argv[1:]
cmd = args[1] if args and args[0] == "--json" else args[0]
if cmd == "connected":
    print(json.dumps({"connected": [{"common_name": "alpha", "virtual_address": "192.168.50.10", "real_address": "1.2.3.4:1000", "profile": "directum"}]}))
elif cmd == "list":
    print(json.dumps({"clients": [{"name": "alpha", "profile": "directum", "status": "active", "vpn_ip": "192.168.50.10"}]}))
elif cmd == "status":
    print(json.dumps({"services": {}}))
elif cmd == "runtime-health":
    print(json.dumps({
        "status": "error", "overall": "error",
        "sections": {
            "openvpn": {"service_active": True, "management_available": True},
            "wireguard": {"service_active": True, "link_present": True, "mtu": 1420, "handshake_age_seconds": 25, "handshake_fresh": True},
            "policy_routing": {"rule_present": True, "table_123_default": True, "mangle_chain_present": True, "nat_chain_present": True, "legacy_51820_rule_present": False},
        },
        "warnings": [], "errors": ["VPN_POLICY_NAT chain or hook is missing"],
    }))
else:
    print(json.dumps({"status": "ok"}))
""",
    )


def make_fake_netctl(path: Path) -> Path:
    return make_executable(
        path,
        """#!/usr/bin/env python3
import json
import sys
args = sys.argv[1:]
cmd = args[1:]
if cmd[:2] == ["hosts", "list"]:
    print(json.dumps({"status": "ok", "hosts": [
        {"ip": "192.168.100.55", "mac": "AA:BB:CC:DD:EE:FF", "hostname": "pc-buh-01", "display_name": "pc-buh-01", "category": "local_device", "device_key": "mac:AA:BB:CC:DD:EE:FF", "device_type": "pc", "device_confidence": 70, "device_evidence": ["text:pc"], "status": "online", "sources": ["mikrotik_dhcp", "mikrotik_arp"], "site": "main", "last_seen_at": "2026-07-03T12:00:00Z"},
        {"ip": "192.168.0.12", "mac": "84:D8:1B:EF:3C:6F", "hostname": "Archer_C24", "display_name": "Archer_C24", "category": "telephony", "device_key": "mac:84:D8:1B:EF:3C:6F", "device_type": "phone", "device_confidence": 85, "device_evidence": ["category:telephony"], "status": "online", "sources": ["mikrotik_dhcp", "mikrotik_arp"], "site": "main", "last_seen_at": "2026-07-03T12:00:00Z"},
        {"ip": "10.83.1.11", "mac": "E0:1C:FC:AE:82:9B", "hostname": "", "display_name": "PVE1 MGMT", "category": "mgmt", "device_key": "mac:E0:1C:FC:AE:82:9B", "device_type": "server", "device_confidence": 80, "device_evidence": ["category:mgmt"], "status": "seen", "sources": ["mikrotik_dhcp"], "site": "main", "last_seen_at": "2026-07-03T12:00:00Z"}
    ]}))
elif cmd[:2] == ["hosts", "inspect"]:
    print(json.dumps({"status": "ok", "host": {"ip": cmd[2], "display_name": "pc-buh-01"}, "observations": []}))
elif cmd[:1] == ["dashboard"]:
    print(json.dumps({"status": "ok", "summary": {"total_hosts": 3, "local_device": 1, "telephony": 1, "mgmt": 1, "vpn_client": 0, "router": 0, "site_device": 0, "unknown": 0, "online": 2, "seen": 1, "offline": 0}, "sources": [{"name": "mikrotik-main", "last_collect_at": "2026-07-03T12:00:00Z", "last_status": "ok"}]}))
elif cmd[:2] == ["sources", "list"]:
    print(json.dumps({"status": "ok", "sources": [{"name": "mikrotik-main", "driver": "mikrotik_api", "host": "192.168.100.250", "site": "main", "role": "core-router", "enabled": True, "last_status": "ok"}]}))
elif cmd[:2] == ["interfaces", "list"]:
    print(json.dumps({"status": "ok", "interfaces": [{"source": "mikrotik-main", "name": "bridge-lan", "type": "bridge", "running": True, "disabled": False, "rx_bytes": 10, "tx_bytes": 20}]}))
elif cmd[:2] == ["routes", "list"]:
    print(json.dumps({"status": "ok", "routes": [{"source": "mikrotik-main", "dst_address": "192.168.50.0/24", "gateway": "192.168.100.30", "active": True, "dynamic": False, "distance": "1"}]}))
elif cmd[:2] == ["ipsec", "status"]:
    print(json.dumps({"status": "ok", "summary": {"sources": 2, "ok": 2, "warn": 0, "error": 0, "site_checks_ok": 1, "site_checks_warn": 0}, "site_checks": [{
        "status": "ok",
        "network_a": "192.168.0.0/24",
        "network_b": "192.168.99.0/24",
        "directions": [
            {"source": "mikrotik-main", "src_address": "192.168.0.0/24", "dst_address": "192.168.99.0/24", "ph2_count": 1},
            {"source": "mikrotik-hex", "src_address": "192.168.99.0/24", "dst_address": "192.168.0.0/24", "ph2_count": 1}
        ]
    }], "sources": [{
        "source": "mikrotik-main",
        "host": "192.168.100.250",
        "site": "main",
        "role": "core-router",
        "status": "ok",
        "summary": {"active_peers": 1, "installed_sas": 2, "policies_total": 1, "policies_established": 1},
        "active_peers": [{"remote_address": "62.148.235.108", "state": "established", "ph2_total": 2}],
        "policies": [{"src_address": "192.168.0.0/24", "dst_address": "192.168.99.0/24", "ph2_state": "established", "ph2_count": 1, "comment": "phone LAN to m-arhiv"}],
        "installed_sas": [{"src_address": "78.29.35.68", "dst_address": "62.148.235.108", "state": "mature"}],
        "errors": []
    }, {
        "source": "mikrotik-hex",
        "host": "192.168.99.1",
        "site": "m-arhiv",
        "role": "edge-router",
        "status": "ok",
        "summary": {"active_peers": 1, "installed_sas": 0, "policies_total": 1, "policies_established": 1},
        "active_peers": [{"remote_address": "78.29.35.68", "state": "established", "ph2_total": 2}],
        "policies": [{"src_address": "192.168.99.0/24", "dst_address": "192.168.0.0/24", "ph2_state": "", "ph2_count": 1, "comment": "m-arhiv to phone LAN"}],
        "installed_sas": [],
        "errors": []
    }]}))
elif cmd[:2] == ["observations", "list"]:
    print(json.dumps({"status": "ok", "observations": []}))
elif cmd[:1] == ["logs"]:
    print(json.dumps({"status": "ok", "events": []}))
elif cmd[:1] == ["collect"]:
    print(json.dumps({"status": "ok", "source": cmd[1], "summary": {"arp": 1}}))
else:
    print(json.dumps({"status": "ok"}))
""",
    )


def make_client(tmp_path, monkeypatch):
    token = "api-token"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{(tmp_path / 'web.sqlite').as_posix()}")
    monkeypatch.setenv("APP_SECRET_KEY", "test-secret")
    monkeypatch.setenv("ADMIN_USERNAME", "admin")
    monkeypatch.setenv("ADMIN_PASSWORD", "admin-pass")
    monkeypatch.setenv("OPENVPN_WEB_API_TOKEN_HASH", hashlib.sha256(token.encode("utf-8")).hexdigest())
    monkeypatch.setenv("VPNCTL_PATH", str(make_fake_vpnctl(tmp_path / "vpnctl")))
    monkeypatch.setenv("VPNCTL_USE_SUDO", "0")
    monkeypatch.setenv("NETCTL_PATH", str(make_fake_netctl(tmp_path / "netctl")))
    monkeypatch.setenv("NETCTL_USE_SUDO", "0")
    monkeypatch.setenv("NETWORK_OBSERVER_ENABLED", "1")
    monkeypatch.setenv("OUT_DIR", str(tmp_path))
    monkeypatch.setenv("SHARE_OUT_DIR", str(tmp_path))
    monkeypatch.setenv("ARCHIVE_DIR", str(tmp_path))

    import app.config
    import app.db
    import app.main

    app.config.reset_settings_cache()
    app.db.reset_engine_cache()
    importlib.reload(app.main)
    app.db.init_db()
    return TestClient(app.main.app), {"Authorization": f"Bearer {token}"}


def login(client: TestClient) -> None:
    page = client.get("/login")
    csrf = page.text.split('name="csrf_token" value="')[1].split('"')[0]
    response = client.post(
        "/login",
        data={"username": "admin", "password": "admin-pass", "csrf_token": csrf},
        follow_redirects=False,
    )
    assert response.status_code == 303


def test_network_runtime_health_requires_session_and_is_read_only(tmp_path, monkeypatch):
    client, _ = make_client(tmp_path, monkeypatch)

    unauthenticated = client.get("/network/runtime-health", follow_redirects=False)
    assert unauthenticated.status_code == 303
    assert unauthenticated.headers["location"] == "/login"
    login(client)
    response = client.get("/network/runtime-health")

    assert response.status_code == 200
    assert response.json()["overall"] == "error"


def test_network_dashboard_contains_runtime_health_card_and_polling(tmp_path, monkeypatch):
    client, _ = make_client(tmp_path, monkeypatch)
    login(client)

    page = client.get("/network/dashboard")

    assert page.status_code == 200
    assert 'id="vpn-runtime-card"' in page.text
    assert "VPN Runtime" in page.text

    script = (Path(__file__).resolve().parents[1] / "app" / "static" / "app.js").read_text(encoding="utf-8")
    assert 'fetch("/network/runtime-health", {credentials: "same-origin"})' in script
    assert "setInterval(loadVpnRuntimeHealth, 30000)" in script
    assert "function runtimeHealthRows" in script
    assert "innerHTML" not in script


def test_runtime_health_messages_redact_peer_identifiers():
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node.js is required to exercise the browser-side redaction helper")

    script = Path(__file__).resolve().parents[1] / "app" / "static" / "app.js"
    key = "A" * 43 + "="
    messages = [
        "Endpoint vpn.example.test:51820 is unavailable",
        "Peer route 192.0.2.8/32 has no handshake",
        "Endpoint [2001:db8::8]:51820 is unavailable",
        "hostname=branch-gateway is unreachable",
        f"WireGuard public key {key} is stale",
    ]
    node_program = """
const fs = require("fs");
const vm = require("vm");
const context = {
  document: {addEventListener() {}},
  HTMLFormElement: function HTMLFormElement() {},
  window: {},
};
vm.createContext(context);
vm.runInContext(fs.readFileSync(process.argv[1], "utf8"), context);
process.stdout.write(JSON.stringify(JSON.parse(process.argv[2]).map(context.runtimeHealthMessage)));
"""
    result = subprocess.run(
        [node, "-e", node_program, str(script), json.dumps(messages)],
        capture_output=True,
        check=True,
        text=True,
    )
    redacted = json.loads(result.stdout)

    assert "vpn.example.test" not in redacted[0]
    assert "vpn.example" not in redacted[0]
    assert "example.test" not in redacted[0]
    assert "51820" not in redacted[0]
    assert "192.0.2.8" not in redacted[1]
    assert "/32" not in redacted[1]
    assert "2001:db8::8" not in redacted[2]
    assert "51820" not in redacted[2]
    assert "branch-gateway" not in redacted[3]
    assert key not in redacted[4]
    assert "unavailable" in redacted[0]


def test_web_network_hosts_page_unifies_netctl_and_openvpn(tmp_path, monkeypatch):
    client, _ = make_client(tmp_path, monkeypatch)
    login(client)

    page = client.get("/network/hosts")

    assert page.status_code == 200
    assert "Все IP и устройства" in page.text
    assert "pc-buh-01" in page.text
    assert "alpha" in page.text
    assert "Обычная сеть" in page.text
    assert "ПК" in page.text
    assert "Телефон" in page.text
    assert "Сервер" in page.text
    assert "Телефония" in page.text
    assert "Управление" in page.text
    assert "192.168.0.12" in page.text
    assert "10.83.1.11" in page.text
    assert "VPN" in page.text
    assert "192.168.50.10" in page.text
    assert "192.168.100.55" in page.text


def test_network_api_hosts_returns_unified_rows(tmp_path, monkeypatch):
    client, headers = make_client(tmp_path, monkeypatch)

    response = client.get("/api/v1/network/hosts", headers=headers)

    assert response.status_code == 200
    rows = response.json()["data"]["hosts"]
    assert {row["ip"] for row in rows} == {"192.168.100.55", "192.168.0.12", "10.83.1.11", "192.168.50.10"}
    vpn = next(row for row in rows if row["ip"] == "192.168.50.10")
    assert vpn["category"] == "vpn_client"
    assert vpn["vpn_client"]["common_name"] == "alpha"
    phone = next(row for row in rows if row["ip"] == "192.168.0.12")
    assert phone["device_type"] == "phone"
    assert phone["device_confidence"] == 85


def test_network_pages_render_sources_interfaces_routes_and_collect(tmp_path, monkeypatch):
    client, _ = make_client(tmp_path, monkeypatch)
    login(client)

    assert client.get("/network/dashboard").status_code == 200
    assert "mikrotik-main" in client.get("/network/sources").text
    assert "bridge-lan" in client.get("/network/interfaces").text
    assert "192.168.50.0/24" in client.get("/network/routes").text
    collect = client.get("/network/collect")
    assert collect.status_code == 200
    assert "Сбор данных" in collect.text


def test_network_ipsec_and_backup_pages_render_status(tmp_path, monkeypatch):
    backup_dir = tmp_path / "routeros_backups"
    backup_dir.mkdir()
    (backup_dir / "sosn-20260706-200358.backup").write_bytes(b"routeros-backup")
    (backup_dir / "sosn-20260706-200358.rsc").write_text("/ip route print\n", encoding="utf-8")
    monkeypatch.setenv("ROUTEROS_BACKUP_DIR", str(backup_dir))
    client, _ = make_client(tmp_path, monkeypatch)
    login(client)

    ipsec = client.get("/network/ipsec")
    backups = client.get("/network/backups")

    assert ipsec.status_code == 200
    assert "IPsec" in ipsec.text
    assert "mikrotik-main" in ipsec.text
    assert "mikrotik-hex" in ipsec.text
    assert "192.168.99.0/24" in ipsec.text
    assert "192.168.0.0/24" in ipsec.text
    assert "192.168.0.0/24 -> 192.168.99.0/24" in ipsec.text
    assert "192.168.99.0/24 -> 192.168.0.0/24" in ipsec.text
    assert backups.status_code == 200
    assert "RouterOS" in backups.text
    assert "sosn-20260706-200358.backup" in backups.text
    assert "sosn-20260706-200358.rsc" in backups.text


def test_network_diagnostic_api_returns_ipsec_backups_and_logs(tmp_path, monkeypatch):
    backup_dir = tmp_path / "routeros_backups"
    backup_dir.mkdir()
    (backup_dir / "sosn-20260706-200358.backup").write_bytes(b"routeros-backup")
    (backup_dir / "m-arhiv-20260706-200358.rsc").write_text("/ip route print\n", encoding="utf-8")
    monkeypatch.setenv("ROUTEROS_BACKUP_DIR", str(backup_dir))
    client, headers = make_client(tmp_path, monkeypatch)

    ipsec = client.get("/api/v1/network/ipsec", headers=headers)
    backups = client.get("/api/v1/network/backups", headers=headers)
    logs = client.get("/api/v1/network/logs", headers=headers)

    assert ipsec.status_code == 200
    assert ipsec.json()["data"]["summary"]["sources"] == 2
    assert ipsec.json()["data"]["site_checks"][0]["network_b"] == "192.168.99.0/24"
    assert backups.status_code == 200
    backup_names = {row["name"] for row in backups.json()["data"]["backups"]}
    assert backup_names == {"sosn-20260706-200358.backup", "m-arhiv-20260706-200358.rsc"}
    assert backups.json()["data"]["error"] is None
    assert logs.status_code == 200
    assert logs.json()["data"]["events"] == []
