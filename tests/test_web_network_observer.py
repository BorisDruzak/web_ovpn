import hashlib
import importlib
import json
import os
import shutil
import subprocess
import sys
from datetime import datetime, timezone
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
elif cmd == "server-config":
    print(json.dumps({"status": "ok", "settings": {"server_network": "198.51.100.0/24"}}))
else:
    print(json.dumps({"status": "ok"}))
""",
    )


def make_fake_netctl(path: Path) -> Path:
    return make_executable(
        path,
        """#!/usr/bin/env python3
import json
import os
import sys
from datetime import datetime, timezone
args = sys.argv[1:]
cmd = args[1:]
collected_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
invoked_cli_path = __import__("os").environ.get("NETCTL_INVOKED_CLI_PATH")
if invoked_cli_path:
    with open(invoked_cli_path, "a", encoding="utf-8") as invoked_cli:
        invoked_cli.write(" ".join(cmd) + "\\n")
if cmd[:2] == ["hosts", "list"]:
    print(json.dumps({"status": "ok", "hosts": [
        {"ip": "192.168.100.55", "mac": "AA:BB:CC:DD:EE:01", "hostname": "pc-buh-01", "display_name": "desktop pc-buh-01", "manual_name": "Finance workstation", "category": "local_device", "device_key": "mac:AA:BB:CC:DD:EE:01", "device_type": "pc", "device_confidence": 70, "device_evidence": ["text:pc"], "status": "online", "sources": ["mikrotik_dhcp", "mikrotik_arp"], "site": "main", "last_seen_at": "2026-07-03T12:00:00Z"},
        {"ip": "192.168.0.12", "mac": "84:D8:1B:EF:3C:6F", "hostname": "Archer_C24", "display_name": "Archer_C24", "category": "telephony", "device_key": "legacy-host:desk?old", "device_type": "phone", "device_confidence": 85, "device_evidence": ["category:telephony"], "status": "online", "sources": ["mikrotik_dhcp", "mikrotik_arp"], "site": "main", "last_seen_at": "2026-07-03T12:00:00Z"},
        {"ip": "10.83.1.11", "mac": "E0:1C:FC:AE:82:9B", "hostname": "", "display_name": "PVE1 MGMT", "category": "mgmt", "device_key": "mac:E0:1C:FC:AE:82:9B", "device_type": "server", "device_confidence": 80, "device_evidence": ["category:mgmt"], "status": "seen", "sources": ["mikrotik_dhcp"], "site": "main", "last_seen_at": "2026-07-03T12:00:00Z"}
    ]}))
elif cmd[:2] == ["hosts", "inspect"]:
    print(json.dumps({"status": "ok", "host": {"ip": cmd[2], "display_name": "pc-buh-01"}, "observations": []}))
elif cmd[:2] == ["context-view", "search"]:
    print(json.dumps({"status": "ok", "results": [{"asset_key": "mac:AA:BB:CC:DD:EE:01", "display_name": "desktop pc-buh-01"}]}))
elif cmd[:2] == ["context-view", "asset"]:
    asset_key = cmd[cmd.index("--asset-key") + 1]
    freshness = {"topology_reconciled_at": "2026-07-26T10:05:00Z", "attachment_reconciled_at": "2026-07-26T10:05:00Z", "topology_source_watermark": {}, "attachment_source_watermark": {}}
    if asset_key == "mac:AA:BB:CC:DD:EE:99":
        print(json.dumps({"status": "ok", "context": {}}))
    elif asset_key == "mac:AA:BB:CC:DD:EE:03":
        freshness["topology_reconciled_at"] = ""
        print(json.dumps({"status": "ok", "context": {"asset": {"asset_key": asset_key, "display_name": "stale desktop"}, "attachment": {"status": "unresolved", "alternatives": []}, "freshness": freshness}}))
    elif asset_key == "mac:AA:BB:CC:DD:EE:04":
        print(json.dumps({"status": "ok", "context": {"asset": {"asset_key": asset_key, "display_name": "ambiguous desktop"}, "attachment": {"status": "ambiguous", "alternatives": [{"source": "access-b", "port_key": "physical:12", "vlan_id": 20, "candidate_class": "fdb", "score": 70}], "switch": {"name": "must-not-render"}, "port": {"alias": "must-not-render"}, "port_peers": {"items": [{"asset": {"asset_key": "AA:BB:CC:DD:EE:02", "display_name": "must-not-render"}}]}}, "freshness": freshness}}))
    else:
        print(json.dumps({"status": "ok", "context": {"asset": {"asset_key": asset_key, "display_name": "desktop pc-buh-01", "manual_name": "Finance workstation", "kind": "device", "status": "active", "site": "main", "location": "Office", "identity_method": "mac", "identity_confidence": 100}, "network": {"ip_observations": [{"ip": "192.168.100.55"}], "best_hostname_observation": {"hostname": "pc-buh-01"}}, "attachment": {"status": "confirmed", "confidence": 100, "last_seen_at": "2026-07-26T10:00:00Z", "switch": {"name": "access-a", "site": "main", "host": "must-not-render"}, "port": {"key": "physical:7", "name": "Gi1/0/7", "alias": "Office 12", "oper_status": "up"}, "vlan_membership": {"vlan_id": 20, "egress": True, "untagged": True, "pvid": True}, "port_peers": {"items": [{"asset": {"asset_key": "mac:AA:BB:CC:DD:EE:02", "display_name": "Printer"}, "mac": "AA:BB:CC:DD:EE:02", "vlan_id": 20}], "known_asset_count": 1, "unknown_mac_count": 0, "truncated": False}, "alternatives": []}, "topology_path": {"nodes": [], "hops": [], "complete": True, "reason": ""}, "attachment_events": [{"event_type": "confirmed", "observed_at": "2026-07-25T10:00:00Z", "before": {"status": "unresolved"}, "after": {"status": "confirmed"}}], "freshness": freshness, "evidence": {"secret": "must-not-render"}}}))
elif cmd[:2] == ["assets", "set-name"]:
    marker = os.environ.get("NETCTL_ASSET_NAME_MARKER")
    if marker:
        with open(marker, "w", encoding="utf-8") as handle:
            json.dump(cmd, handle)
    print(json.dumps({"status": "ok", "asset": {"asset_key": cmd[cmd.index("--asset-key") + 1], "manual_name": cmd[cmd.index("--name") + 1]}}))
elif cmd[:1] == ["dashboard"]:
    print(json.dumps({"status": "ok", "summary": {"total_hosts": 3, "local_device": 1, "telephony": 1, "mgmt": 1, "vpn_client": 0, "router": 0, "site_device": 0, "unknown": 0, "online": 2, "seen": 1, "offline": 0}, "sources": [{"name": "mikrotik-main", "last_collect_at": "2026-07-03T12:00:00Z", "last_status": "ok"}]}))
elif cmd[:2] == ["sources", "list"]:
    print(json.dumps({"status": "ok", "sources": [{"name": "mikrotik-main", "driver": "mikrotik_api", "host": "192.168.100.250", "site": "main", "role": "core-router", "enabled": True, "last_status": "ok"}]}))
elif cmd[:2] == ["switches", "unknown-fingerprints"]:
    print(json.dumps({"status": "ok", "fingerprints": [{"source": "switch-unknown", "sys_object_id": "1.3.6.1.4.1.99999.1", "sys_descr": "Synthetic unknown switch", "fingerprint_sha256": "a" * 64, "capabilities": [{"capability": "sys_descr", "outcome": "success_with_rows"}], "status": "requires_profile", "observed_at": "2026-07-20T12:00:00Z"}]}))
elif cmd[:2] == ["interfaces", "list"]:
    print(json.dumps({"status": "ok", "interfaces": [{"source": "mikrotik-main", "name": "bridge-lan", "type": "bridge", "running": True, "disabled": False, "rx_bytes": 10, "tx_bytes": 20}]}))
elif cmd[:2] == ["routes", "list"]:
    print(json.dumps({"status": "ok", "sources": [{"source": "mikrotik-main", "status": "ok", "collected_at": collected_at}], "routes": [{"source": "mikrotik-main", "dst_address": "192.168.50.0/24", "gateway": "192.168.100.30", "active": True, "dynamic": False, "distance": "1", "last_seen_at": collected_at}, {"source": "mikrotik-main", "dst_address": "198.51.100.0/24", "gateway": "198.51.100.1", "active": True, "disabled": False, "last_seen_at": collected_at, "command": "netctl collect all password=not-a-secret /etc/openvpn-web/server-observer.key"}]}))
elif cmd[:2] == ["address-lists", "list"]:
    print(json.dumps({"status": "ok", "sources": [{"source": "mikrotik-main", "status": "ok", "collected_at": collected_at}], "address_lists": [{"source": "mikrotik-main", "list": "vpn-targets", "address": "203.0.113.0/24", "disabled": False, "last_seen_at": collected_at}]}))
elif cmd[:2] == ["firewall-rules", "list"]:
    print(json.dumps({"status": "ok", "sources": [{"source": "mikrotik-main", "status": "ok", "collected_at": collected_at}], "firewall_rules": [{"source": "mikrotik-main", "table": cmd[3], "chain": "forward", "action": "accept", "src_address": "198.51.100.0/24", "dst_address": "203.0.113.0/24", "comment": "vpn target policy", "disabled": False, "packets": 8, "bytes": 800, "last_seen_at": collected_at}]}))
elif cmd[:2] == ["update-posture", "list"]:
    print(json.dumps({"status": "ok", "sources": [{"source": "mikrotik-main", "status": "ok", "collected_at": collected_at}], "update_posture": [{"source": "mikrotik-main", "channel": "stable", "installed_version": "7.19.4", "latest_version": "", "routerboot_current_version": "7.19.4", "routerboot_upgrade_version": "7.20.1", "last_seen_at": collected_at, "host": "router.internal", "credential": "not-a-secret", "raw_output": "private", "schedulers": [{"name": "backup-private", "disabled": False, "next_run": "tomorrow"}, {"name": "secret-job", "disabled": True, "next_run": "later"}]}]}))
elif cmd[:1] == ["collector-status"]:
    print(json.dumps({"status": "ok", "enabled": True, "active": True, "next_run": ""}))
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
    marker = __import__("os").environ.get("NETCTL_COLLECT_MARKER")
    if marker:
        open(marker, "w", encoding="utf-8").write("invoked")
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
    monkeypatch.setenv("NETCTL_INVOKED_CLI_PATH", str(tmp_path / "netctl-invoked-cli.txt"))
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


def login(client: TestClient) -> str:
    page = client.get("/login")
    csrf = page.text.split('name="csrf_token" value="')[1].split('"')[0]
    response = client.post(
        "/login",
        data={"username": "admin", "password": "admin-pass", "csrf_token": csrf},
        follow_redirects=False,
    )
    assert response.status_code == 303
    return csrf


def write_path_evidence(tmp_path: Path, monkeypatch) -> None:
    collected_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    path_config = tmp_path / "network-paths.json"
    path_config.write_text(
        json.dumps(
            {
                "paths": [
                    {
                        "role": "directum",
                        "router_source": "mikrotik-main",
                        "openvpn_pool": "198.51.100.0/24",
                        "target_cidr": "203.0.113.0/24",
                        "return_route": {"dst_address": "198.51.100.0/24", "gateway": "198.51.100.1"},
                        "address_lists": [{"list": "vpn-targets", "address": "203.0.113.0/24"}],
                        "policy_matchers": [
                            {
                                "table": "filter",
                                "chain": "forward",
                                "action": "accept",
                                "src_address": "198.51.100.0/24",
                                "dst_address": "203.0.113.0/24",
                                "comment_contains": "vpn",
                            }
                        ],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    snapshot = tmp_path / "server-health.json"
    snapshot.write_text(
        json.dumps(
            {
                "collected_at": collected_at,
                "overall": "ok",
                "targets": [{"role": "directum", "status": "ok", "checks": []}],
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("NETWORK_PATHS_CONFIG_PATH", str(path_config))
    role_registry = tmp_path / "server-roles.json"
    role_registry.write_text(json.dumps({"roles": ["directum"]}), encoding="utf-8")
    monkeypatch.setenv("SERVER_ROLE_REGISTRY_PATH", str(role_registry))
    monkeypatch.setenv("SERVER_OBSERVER_SNAPSHOT_PATH", str(snapshot))


def test_network_paths_require_login_and_show_existing_server_roles(tmp_path, monkeypatch):
    write_path_evidence(tmp_path, monkeypatch)
    client, headers = make_client(tmp_path, monkeypatch)

    assert client.get("/network/paths", follow_redirects=False).status_code == 303
    login(client)

    page = client.get("/network/paths")
    api = client.get("/api/v1/network/paths", headers=headers)

    assert page.status_code == 200
    assert "directum" in page.text
    assert api.status_code == 200
    assert api.json()["data"]["paths"][0]["role"] == "directum"
    assert client.get("/network/paths/directum").status_code == 200
    assert client.get("/api/v1/network/paths/directum", headers=headers).status_code == 200


def test_network_paths_gets_are_read_only_and_redact_local_evidence(tmp_path, monkeypatch):
    write_path_evidence(tmp_path, monkeypatch)
    marker = tmp_path / "collect-invoked"
    monkeypatch.setenv("NETCTL_COLLECT_MARKER", str(marker))
    client, headers = make_client(tmp_path, monkeypatch)
    login(client)

    browser = client.get("/network/paths/directum")
    api = client.get("/api/v1/network/paths/directum", headers=headers)

    assert browser.status_code == 200
    assert api.status_code == 200
    assert not marker.exists()
    for forbidden in (
        "password=not-a-secret",
        "/etc/openvpn-web/server-observer.key",
        "netctl collect",
        "Traceback",
        "198.51.100.0/24",
        "203.0.113.0/24",
    ):
        assert forbidden not in browser.text
        assert forbidden not in api.text
    assert set(api.json()["data"]["path"]["checks"][0]) == {"name", "status", "message"}


@pytest.mark.parametrize("snapshot_state", ["missing", "invalid"])
def test_registered_paths_survive_missing_or_invalid_health_snapshot(tmp_path, monkeypatch, snapshot_state):
    write_path_evidence(tmp_path, monkeypatch)
    snapshot = tmp_path / "server-health.json"
    if snapshot_state == "missing":
        snapshot.unlink()
    else:
        snapshot.write_text("not-json", encoding="utf-8")
    client, headers = make_client(tmp_path, monkeypatch)

    response = client.get("/api/v1/network/paths", headers=headers)

    assert response.status_code == 200
    assert [row["role"] for row in response.json()["data"]["paths"]] == ["directum"]
    assert response.json()["data"]["paths"][0]["status"] in {"stale", "error", "unknown"}


def test_update_posture_is_redacted_in_authenticated_path_list_and_detail(tmp_path, monkeypatch):
    write_path_evidence(tmp_path, monkeypatch)
    client, headers = make_client(tmp_path, monkeypatch)
    login(client)

    list_api = client.get("/api/v1/network/paths", headers=headers)
    detail_api = client.get("/api/v1/network/paths/directum", headers=headers)
    list_page = client.get("/network/paths")
    detail_page = client.get("/network/paths/directum")
    posture = list_api.json()["data"]["paths"][0]["update_posture"]

    assert list_api.status_code == detail_api.status_code == 200
    assert list_page.status_code == detail_page.status_code == 200
    detail_posture = detail_api.json()["data"]["path"]["update_posture"]
    assert {key: value for key, value in posture.items() if key != "collected_at"} == {
        key: value for key, value in detail_posture.items() if key != "collected_at"
    }
    assert posture["collected_at"].endswith("Z")
    assert detail_posture["collected_at"].endswith("Z")
    assert set(posture) == {
        "installed_version",
        "channel",
        "routerboot_current_version",
        "routerboot_upgrade_version",
        "scheduler_count",
        "collected_at",
        "freshness",
        "status",
    }
    assert posture["installed_version"] == "7.19.4"
    assert posture["channel"] == "stable"
    assert posture["routerboot_current_version"] == "7.19.4"
    assert posture["routerboot_upgrade_version"] == "7.20.1"
    assert posture["scheduler_count"] == 2
    assert posture["freshness"] == "fresh"
    assert posture["status"] == "ok"
    assert "7.19.4" in list_page.text
    assert "7.20.1" in detail_page.text
    for forbidden in (
        "mikrotik-main",
        "router.internal",
        "not-a-secret",
        "private",
        "backup-private",
        "secret-job",
    ):
        assert forbidden not in list_api.text
        assert forbidden not in detail_api.text
        assert forbidden not in list_page.text
        assert forbidden not in detail_page.text


def test_network_path_badges_map_all_evaluator_statuses():
    from app.main import status_class

    assert status_class("warn") == "warn"
    assert status_class("critical") == "bad"
    assert status_class("stale") == "warn"


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
        "hostname=branch-gateway:51820 is unreachable",
        "remote_host: node-01:443 is unreachable",
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
    assert "branch-gateway" not in redacted[4]
    assert "51820" not in redacted[4]
    assert "node-01" not in redacted[5]
    assert "443" not in redacted[5]
    assert key not in redacted[6]
    assert "unavailable" in redacted[0]


def test_web_network_hosts_page_unifies_netctl_and_openvpn(tmp_path, monkeypatch):
    client, _ = make_client(tmp_path, monkeypatch)
    login(client)

    page = client.get("/network/hosts")

    assert page.status_code == 200
    assert "Все IP и устройства" in page.text
    assert "Finance workstation" in page.text
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


def test_network_hosts_links_known_assets_without_changing_ip_fallback(tmp_path, monkeypatch):
    client, _ = make_client(tmp_path, monkeypatch)
    login(client)

    page = client.get("/network/hosts?q=desktop")

    assert page.status_code == 200
    assert 'href="/network/assets/mac%3AAA%3ABB%3ACC%3ADD%3AEE%3A01"' in page.text
    assert 'href="/network/hosts/192.168.100.55"' not in page.text
    all_hosts = client.get("/network/hosts")
    assert 'href="/network/assets/legacy-host%3Adesk%3Fold"' in all_hosts.text
    assert 'href="/network/hosts/192.168.50.10"' in all_hosts.text


def test_network_hosts_url_encodes_reserved_asset_key_and_routes_exact_key(tmp_path, monkeypatch):
    client, _ = make_client(tmp_path, monkeypatch)
    login(client)

    hosts_page = client.get("/network/hosts")

    assert 'href="/network/assets/legacy-host%3Adesk%3Fold"' in hosts_page.text
    asset_page = client.get("/network/assets/legacy-host:desk%3Fold")
    assert asset_page.status_code == 200
    assert "legacy-host:desk?old" in asset_page.text


def test_network_asset_card_requires_login_and_renders_confirmed_attachment(tmp_path, monkeypatch):
    client, _ = make_client(tmp_path, monkeypatch)

    denied = client.get("/network/assets/mac:AA:BB:CC:DD:EE:01", follow_redirects=False)
    assert denied.status_code == 303

    login(client)
    page = client.get("/network/assets/mac:AA:BB:CC:DD:EE:01")

    assert page.status_code == 200
    assert "access-a" in page.text
    assert "Office 12" in page.text
    assert "VLAN 20" in page.text
    assert "Подтверждено" in page.text
    assert "AA:BB:CC:DD:EE:02" in page.text
    assert "must-not-render" not in page.text
    assert "Raw JSON" not in page.text


@pytest.mark.parametrize(
    "query",
    ["FINANCE", "pc-buh-01", "192.168.100.55", "AA:BB:CC:DD:EE:01", "mac:AA:BB:CC:DD:EE:01"],
)
def test_network_hosts_searches_manual_name_and_stable_host_identifiers(tmp_path, monkeypatch, query):
    client, _ = make_client(tmp_path, monkeypatch)
    login(client)

    page = client.get("/network/hosts", params={"q": query})

    assert page.status_code == 200
    assert 'href="/network/assets/mac%3AAA%3ABB%3ACC%3ADD%3AEE%3A01"' in page.text


def test_network_asset_card_keeps_manual_name_ip_and_hostname_in_separate_rows(tmp_path, monkeypatch):
    client, _ = make_client(tmp_path, monkeypatch)
    login(client)

    page = client.get("/network/assets/mac:AA:BB:CC:DD:EE:01")

    assert page.status_code == 200
    assert "\u041d\u0430\u0437\u0432\u0430\u043d\u0438\u0435" in page.text
    assert "Finance workstation" in page.text
    assert "IP-\u0430\u0434\u0440\u0435\u0441" in page.text
    assert "192.168.100.55" in page.text
    assert "\u0418\u043c\u044f \u0445\u043e\u0441\u0442\u0430" in page.text
    assert "pc-buh-01" in page.text
    assert 'action="/network/assets/mac%3AAA%3ABB%3ACC%3ADD%3AEE%3A01/name"' in page.text


def test_network_manual_name_replaces_automatic_list_and_card_title(tmp_path, monkeypatch):
    client, _ = make_client(tmp_path, monkeypatch)
    login(client)

    host_list = client.get("/network/hosts")
    asset_page = client.get("/network/assets/mac:AA:BB:CC:DD:EE:01")

    assert "Finance workstation" in host_list.text
    assert "<title>Finance workstation</title>" in asset_page.text
    assert "pc-buh-01" in asset_page.text
    assert "192.168.100.55" in asset_page.text


def test_network_asset_name_update_requires_login(tmp_path, monkeypatch):
    client, _ = make_client(tmp_path, monkeypatch)

    response = client.post(
        "/network/assets/mac:AA:BB:CC:DD:EE:01/name",
        data={"name": "Finance workstation"},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert response.headers["location"] == "/login"


def test_network_asset_name_update_uses_csrf_netctl_and_audits(tmp_path, monkeypatch):
    marker = tmp_path / "asset-name-command.json"
    monkeypatch.setenv("NETCTL_ASSET_NAME_MARKER", str(marker))
    client, _ = make_client(tmp_path, monkeypatch)
    login(client)
    page = client.get("/network/assets/mac:AA:BB:CC:DD:EE:01")
    csrf = page.text.split('name="csrf_token" value="')[1].split('"')[0]

    response = client.post(
        "/network/assets/mac:AA:BB:CC:DD:EE:01/name",
        data={"name": "Finance workstation", "csrf_token": csrf},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert response.headers["location"] == "/network/assets/mac%3AAA%3ABB%3ACC%3ADD%3AEE%3A01"
    assert json.loads(marker.read_text(encoding="utf-8")) == [
        "assets", "set-name", "--asset-key", "mac:AA:BB:CC:DD:EE:01", "--name", "Finance workstation",
    ]
    from app.db import session_scope
    from app.models import WebAuditLog

    with session_scope() as db:
        audit = db.query(WebAuditLog).filter_by(action="asset-name-update").one()
    assert audit.actor == "admin"
    assert audit.target_client == "mac:AA:BB:CC:DD:EE:01"
    assert audit.result == "ok"


def test_network_asset_name_update_redirects_to_encoded_reserved_asset_key(tmp_path, monkeypatch):
    client, _ = make_client(tmp_path, monkeypatch)
    login(client)
    page = client.get("/network/assets/legacy-host:desk%3Fold")
    csrf = page.text.split('name="csrf_token" value="')[1].split('"')[0]

    response = client.post(
        "/network/assets/legacy-host:desk%3Fold/name",
        data={"name": "Desk phone", "csrf_token": csrf},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert response.headers["location"] == "/network/assets/legacy-host%3Adesk%3Fold"


def test_network_asset_name_update_persists_manual_name_for_authenticated_user(tmp_path, monkeypatch):
    client, _ = make_client(tmp_path, monkeypatch)
    csrf_token = login(client)

    saved = client.post(
        "/network/assets/mac:AA:BB:CC:DD:EE:01/name",
        data={"name": "\u0410\u0440\u0445\u0438\u0432\u043d\u044b\u0439 \u041f\u041a", "csrf_token": csrf_token},
        follow_redirects=False,
    )

    assert saved.status_code == 303
    invoked_cli = (tmp_path / "netctl-invoked-cli.txt").read_text(encoding="utf-8")
    assert "assets set-name --asset-key mac:AA:BB:CC:DD:EE:01 --name \u0410\u0440\u0445\u0438\u0432\u043d\u044b\u0439 \u041f\u041a" in invoked_cli


def test_network_asset_card_has_safe_empty_ambiguous_and_freshness_states(tmp_path, monkeypatch):
    client, _ = make_client(tmp_path, monkeypatch)
    login(client)

    unknown = client.get("/network/assets/mac:AA:BB:CC:DD:EE:99")
    ambiguous = client.get("/network/assets/mac:AA:BB:CC:DD:EE:04")
    stale = client.get("/network/assets/mac:AA:BB:CC:DD:EE:03")

    assert unknown.status_code == 200
    assert "Устройство не найдено" in unknown.text
    assert ambiguous.status_code == 200
    assert "Неоднозначно" in ambiguous.text
    assert "access-b" in ambiguous.text
    assert "must-not-render" not in ambiguous.text
    assert "AA:BB:CC:DD:EE:02" not in ambiguous.text
    assert stale.status_code == 200
    assert "Топология: нужно обновление" in stale.text
    assert "Вложения: восстановлены" in stale.text


def test_network_asset_card_renders_readable_cyrillic_freshness_and_confirmed_copy(tmp_path, monkeypatch):
    client, _ = make_client(tmp_path, monkeypatch)
    login(client)

    page = client.get("/network/assets/mac:AA:BB:CC:DD:EE:01")

    assert "\u0422\u043e\u043f\u043e\u043b\u043e\u0433\u0438\u044f: \u0430\u043a\u0442\u0443\u0430\u043b\u044c\u043d\u043e" in page.text
    assert "\u041f\u043e\u0434\u0442\u0432\u0435\u0440\u0436\u0434\u0435\u043d\u043e" in page.text
    assert "\u0420\u045e\u0420\u0455\u0420\u0457\u0420\u0455\u0420\u00bb\u0420\u0455\u0420\u0456\u0420\u0451\u0421\u040f" not in page.text


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


def test_network_hosts_api_defaults_to_current_and_rejects_unknown_status(tmp_path, monkeypatch):
    client, headers = make_client(tmp_path, monkeypatch)
    import app.api

    hosts = [
        {"ip": "192.168.99.2", "status": "offline", "availability": {"reason": "active_negative_no_passive_evidence"}},
        {"ip": "192.168.99.44", "status": "online", "availability": {"active_method": "icmp", "checked_at": "2026-07-29T10:00:00Z", "reason": "active_probe"}},
        {"ip": "192.168.99.45", "status": "seen", "availability": {"passive_evidence": ["mikrotik_dhcp"], "reason": "passive_evidence"}},
        {"ip": "192.168.99.46", "status": "stale", "availability": {"reason": "run_failed socket timeout"}},
    ]

    netctl_calls = []

    def fake_netctl(args, timeout=None):
        netctl_calls.append(args)
        if args == ["hosts", "list"]:
            return {"hosts": [host for host in hosts if host["status"] in {"online", "seen"}]}
        if args == ["hosts", "list", "--status", "all"]:
            return {"hosts": hosts}
        raise AssertionError(args)

    monkeypatch.setattr(app.api, "call_netctl", fake_netctl)
    monkeypatch.setattr(app.api, "call_vpnctl", lambda args, timeout=None: {"connected": []} if args[0] == "connected" else {"clients": []})

    current = client.get("/api/v1/network/hosts", headers=headers)
    all_hosts = client.get("/api/v1/network/hosts?status=all", headers=headers)
    offline = client.get("/api/v1/network/hosts?status=offline", headers=headers)
    stale = client.get("/api/v1/network/hosts?status=stale", headers=headers)
    invalid = client.get("/api/v1/network/hosts?status=unexpected", headers=headers)

    assert [host["ip"] for host in current.json()["data"]["hosts"]] == ["192.168.99.44", "192.168.99.45"]
    assert [host["ip"] for host in all_hosts.json()["data"]["hosts"]] == [
        "192.168.99.2", "192.168.99.44", "192.168.99.45", "192.168.99.46",
    ]
    assert [host["ip"] for host in offline.json()["data"]["hosts"]] == ["192.168.99.2"]
    assert stale.json()["data"]["hosts"][0]["availability"]["reason"] == "run_failed"
    assert "socket timeout" not in stale.text
    assert invalid.status_code == 422
    assert netctl_calls == [
        ["hosts", "list"],
        ["hosts", "list", "--status", "all"],
        ["hosts", "list", "--status", "all"],
        ["hosts", "list", "--status", "all"],
    ]


def test_network_hosts_page_renders_sanitized_availability_and_not_monitored(tmp_path, monkeypatch):
    client, _ = make_client(tmp_path, monkeypatch)
    import app.main

    hosts = [
        {
            "ip": "192.168.99.46", "display_name": "stale host", "status": "stale",
            "availability": {"active_method": "icmp", "checked_at": "2026-07-29T10:00:00Z", "reason": "run_failed socket timeout"},
        },
        {"ip": "192.168.99.47", "display_name": "unmonitored host", "status": "seen", "availability": None},
    ]

    def fake_netctl(request, args, timeout=None):
        if args == ["hosts", "list"]:
            return {"hosts": [hosts[1]]}, None
        if args == ["hosts", "list", "--status", "all"]:
            return {"hosts": hosts}, None
        if args == ["sources", "list"]:
            return {"sources": []}, None
        if args == ["hosts", "inspect", "192.168.99.46"]:
            return {"host": hosts[0]}, None
        raise AssertionError(args)

    monkeypatch.setattr(app.main, "net_cli_call", fake_netctl)
    monkeypatch.setattr(app.main, "cli_call", lambda request, args, timeout=None: ({"connected": []} if args[0] == "connected" else {"clients": []}, None))
    login(client)

    page = client.get("/network/hosts?status=stale")
    detail = client.get("/network/hosts/192.168.99.46")
    all_hosts = client.get("/network/hosts?status=all")
    invalid = client.get("/network/hosts?status=unexpected")

    assert page.status_code == detail.status_code == all_hosts.status_code == invalid.status_code == 200
    assert "run failed" in page.text
    assert "socket timeout" not in page.text
    assert "run_failed" in detail.text
    assert "socket timeout" not in detail.text
    assert "not monitored" in all_hosts.text
    assert 'value="unexpected"' not in invalid.text
    assert "stale host" not in invalid.text


def test_network_dashboard_renders_availability_counts_and_run_health(tmp_path, monkeypatch):
    client, _ = make_client(tmp_path, monkeypatch)
    import app.main

    login(client)
    monkeypatch.setattr(
        app.main,
        "net_cli_call",
        lambda request, args, timeout=None: (
            {
                "summary": {"online": 1, "seen": 2, "offline": 3, "stale": 4},
                "sources": [],
                "availability": {
                    "failed_or_incomplete_count": 2,
                    "last_successful_runs": [
                        {
                            "cidr": "192.168.99.0/24",
                            "finished_at": "2026-07-29T10:00:00Z",
                            "completed_target_count": 254,
                            "target_count": 254,
                        }
                    ],
                },
            },
            None,
        ),
    )
    monkeypatch.setattr(
        app.main,
        "cli_call",
        lambda request, args, timeout=None: ({"connected": []}, None),
    )

    page = client.get("/network/dashboard")

    assert page.status_code == 200
    assert "Offline</span><strong>3" in page.text
    assert "Stale</span><strong>4" in page.text
    assert "Failed / incomplete runs</span><strong>2" in page.text
    assert "192.168.99.0/24" in page.text
    assert "2026-07-29T10:00:00Z" in page.text


def test_openvpn_merge_copies_availability_without_mutating_netctl_row():
    from app.network_observer import merge_unified_hosts

    source = {
        "ip": "192.168.99.44", "status": "online",
        "availability": {"active_method": "icmp", "checked_at": "2026-07-29T10:00:00Z", "reason": "active_probe"},
    }

    [merged] = merge_unified_hosts([source], [{"common_name": "alpha", "virtual_address": "192.168.99.44"}], [])

    assert merged["status"] == "connected"
    assert merged["availability"] == {
        "active_method": "icmp", "checked_at": "2026-07-29T10:00:00Z", "reason": "openvpn_management",
    }
    assert source["availability"]["reason"] == "active_probe"


def test_host_list_and_details_share_openvpn_availability_view(tmp_path, monkeypatch):
    client, headers = make_client(tmp_path, monkeypatch)
    import app.api
    import app.main

    host = {
        "ip": "192.168.99.44", "display_name": "vpn workstation", "status": "online",
        "availability": {
            "active_method": "icmp", "checked_at": "2026-07-29T10:00:00Z",
            "reason": "active_probe socket timeout",
        },
    }
    connected = [{"common_name": "alpha", "virtual_address": "192.168.99.44"}]

    def api_netctl(args, timeout=None):
        if args == ["hosts", "list"]:
            return {"hosts": [host]}
        if args == ["hosts", "inspect", "192.168.99.44"]:
            return {"host": host, "observations": []}
        raise AssertionError(args)

    def page_netctl(request, args, timeout=None):
        if args == ["hosts", "list"]:
            return {"hosts": [host]}, None
        if args == ["hosts", "inspect", "192.168.99.44"]:
            return {"host": host, "observations": []}, None
        if args == ["sources", "list"]:
            return {"sources": []}, None
        raise AssertionError(args)

    def api_vpnctl(args, timeout=None):
        return {"connected": connected} if args[0] == "connected" else {"clients": []}

    monkeypatch.setattr(app.api, "call_netctl", api_netctl)
    monkeypatch.setattr(app.api, "call_vpnctl", api_vpnctl)
    monkeypatch.setattr(app.main, "net_cli_call", page_netctl)
    monkeypatch.setattr(app.main, "cli_call", lambda request, args, timeout=None: (api_vpnctl(args), None))
    login(client)

    listed = client.get("/api/v1/network/hosts", headers=headers)
    api_detail = client.get("/api/v1/network/hosts/192.168.99.44", headers=headers)
    page_detail = client.get("/network/hosts/192.168.99.44")

    assert listed.status_code == api_detail.status_code == page_detail.status_code == 200
    assert listed.json()["data"]["hosts"][0]["status"] == "connected"
    assert api_detail.json()["data"]["host"]["status"] == "connected"
    assert "connected" in page_detail.text
    assert api_detail.json()["data"]["host"]["availability"]["reason"] == "openvpn_management"
    assert "socket timeout" not in api_detail.text
    assert "socket timeout" not in page_detail.text


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


def test_sources_page_renders_unknown_without_collect_control(tmp_path, monkeypatch):
    client, headers = make_client(tmp_path, monkeypatch)
    login(client)

    page = client.get("/network/sources")
    api = client.get("/api/v1/network/switch-fingerprints", headers=headers)

    assert page.status_code == 200
    assert "Unknown fingerprints" in page.text
    assert "requires_profile" in page.text
    unknown_section = page.text.split("Unknown fingerprints", 1)[1]
    assert "<form" not in unknown_section
    assert "Collect" not in unknown_section
    assert api.status_code == 200
    [row] = api.json()["data"]["fingerprints"]
    assert set(row) == {
        "source",
        "sys_object_id",
        "sys_descr",
        "fingerprint_sha256",
        "capabilities",
        "status",
        "observed_at",
    }


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
