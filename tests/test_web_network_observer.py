import hashlib
import importlib
import json
import os
import sys
from pathlib import Path

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
