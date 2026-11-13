import hashlib
import importlib
import json
import os
import shutil
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient


class CompletedOperationsClient(TestClient):
    """Legacy domain assertions follow the owned asynchronous result resource.

    Acceptance/barrier/duplicate/reload behavior is tested separately in
    test_panel_operations; these assertions still check the original handler's
    result, target, command budget and audits after durable completion.
    """
    def post(self, url, **kwargs):
        response = super().post(url, **kwargs)
        operation_id = response.headers.get('x-operation-id')
        if not operation_id and '/operations/' in str(response.url):
            operation_id = str(response.url).rsplit('/', 1)[-1]
        if operation_id and not str(url).startswith('/api/'):
            from test_routes_smoke import wait_operation
            wait_operation(self, response)
            return self.get('/operations/'+operation_id+'/result',
                follow_redirects=kwargs.get('follow_redirects', True))
        return response


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


def make_fake_netctl(path: Path, *, include_telemetry: bool = False) -> Path:
    executable = make_executable(
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
    hosts = [
        {"ip": "192.168.100.55", "mac": "AA:BB:CC:DD:EE:01", "hostname": "pc-buh-01", "display_name": "desktop pc-buh-01", "manual_name": "Finance workstation", "category": "local_device", "device_key": "mac:AA:BB:CC:DD:EE:01", "device_type": "pc", "device_confidence": 70, "device_evidence": ["text:pc"], "status": "online", "sources": ["mikrotik_dhcp", "mikrotik_arp"], "site": "main", "last_seen_at": collected_at},
        {"ip": "192.168.0.12", "mac": "84:D8:1B:EF:3C:6F", "hostname": "Archer_C24", "display_name": "Archer_C24", "category": "telephony", "device_key": "legacy-host:desk?old", "device_type": "phone", "device_confidence": 85, "device_evidence": ["category:telephony"], "status": "online", "sources": ["mikrotik_dhcp", "mikrotik_arp"], "site": "main", "last_seen_at": collected_at},
        {"ip": "10.83.1.11", "mac": "E0:1C:FC:AE:82:9B", "hostname": "", "display_name": "PVE1 MGMT", "category": "mgmt", "device_key": "mac:E0:1C:FC:AE:82:9B", "device_type": "server", "device_confidence": 80, "device_evidence": ["category:mgmt"], "status": "seen", "sources": ["mikrotik_dhcp"], "site": "main", "last_seen_at": collected_at}
    ]
    options = {}
    arguments = iter(cmd[2:])
    for argument in arguments:
        name, separator, value = argument.partition('=')
        options[name] = value if separator else next(arguments)
    if options.get('--q'):
        hosts = [host for host in hosts if options['--q'].lower() in ' '.join(str(value) for value in host.values()).lower()]
    selected = options.get('--status', 'current')
    if selected == 'current':
        hosts = [host for host in hosts if host['status'] in ('online', 'seen', 'connected')]
    elif selected != 'all':
        hosts = [host for host in hosts if host['status'] == selected]
    page, limit = int(options.get('--page', 1)), int(options.get('--limit', 100))
    total = len(hosts)
    print(json.dumps({'status': 'ok', 'hosts': hosts[(page - 1) * limit:page * limit], 'sources': [{'name': 'mikrotik-main'}], 'pagination': {'page': page, 'limit': limit, 'total': total, 'pages': (total + limit - 1) // limit}, 'snapshot': {'snapshot_id': 1, 'generated_at': collected_at, 'total_hosts': 3, 'duration_ms': 1}}))
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
        print(json.dumps({"status": "ok", "context": {"asset": {"asset_key": asset_key, "display_name": "ambiguous desktop"}, "attachment": {"status": "ambiguous", "reason": "есть конкурирующая FDB-запись", "alternatives": [{"source": "tplink-ito-15", "port_key": "physical:2", "vlan_id": 20, "candidate_class": "unknown", "score": 50, "reason": "статус порта не получен"}, {"source": "", "port_key": "", "vlan_id": None, "candidate_class": "", "score": None, "reason": ""}], "switch": {"name": "must-not-render"}, "port": {"alias": "must-not-render"}, "port_peers": {"items": [{"asset": {"asset_key": "AA:BB:CC:DD:EE:02", "display_name": "must-not-render"}}]}}, "freshness": freshness}}))
    else:
        print(json.dumps({"status": "ok", "context": {"asset": {"asset_key": asset_key, "display_name": "desktop pc-buh-01", "manual_name": "Finance workstation", "kind": "device", "status": "active", "site": "main", "location": "Office", "identity_method": "mac", "identity_confidence": 100}, "network": {"ip_observations": [{"ip": "192.168.100.55"}], "best_hostname_observation": {"hostname": "pc-buh-01"}}, "attachment": {"status": "confirmed", "confidence": 100, "last_seen_at": "2026-07-26T10:00:00Z", "switch": {"name": "access-a", "site": "main", "host": "must-not-render"}, "port": {"key": "physical:7", "name": "Gi1/0/7", "alias": "Office 12", "oper_status": "up", "role": {"name": "shared_edge", "confidence": 70, "mac_count": 3, "known_asset_count": 2, "unique_vendor_count": 1, "child_source": None, "reason": "Высокая плотность MAC без подтверждённого дочернего коммутатора", "observed_at": "2026-07-26T10:00:00Z"}}, "vlan_membership": {"vlan_id": 20, "egress": True, "untagged": True, "pvid": True}, "port_peers": {"items": [{"asset": {"asset_key": "mac:AA:BB:CC:DD:EE:02", "display_name": "Printer"}, "mac": "AA:BB:CC:DD:EE:02", "vlan_id": 20}], "known_asset_count": 1, "unknown_mac_count": 0, "truncated": False}, "alternatives": []}, "topology_path": {"nodes": [], "hops": [], "complete": True, "reason": ""}, "attachment_events": [{"event_type": "confirmed", "observed_at": "2026-07-25T10:00:00Z", "before": {"status": "unresolved"}, "after": {"status": "confirmed"}}], "freshness": freshness, "evidence": {"secret": "must-not-render"}}}))
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
elif cmd[:2] == ["ipsec", "status"] and "--source" in cmd and "mikrotik-hex" in cmd:
    print(json.dumps({"status": "ok", "summary": {"sources": 1, "ok": 0, "warn": 0, "error": 1},
        "site_checks": [], "sources": [{"source": "mikrotik-hex", "status": "error", "summary": {},
        "errors": [{"section": "active_peers", "message": "SSH connection timed out"}]}]}))
    sys.exit(0 if "--allow-source-errors" in cmd else 1)
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
    if include_telemetry:
        script_path = path.with_suffix(".py") if os.name == "nt" else path
        script = script_path.read_text(encoding="utf-8")
        port = '"port": {"key": "physical:7", "name": "Gi1/0/7", "alias": "Office 12", "oper_status": "up", "role": {"name": "shared_edge", "confidence": 70, "mac_count": 3, "known_asset_count": 2, "unique_vendor_count": 1, "child_source": None, "reason": "Высокая плотность MAC без подтверждённого дочернего коммутатора", "observed_at": "2026-07-26T10:00:00Z"}}'
        telemetry = (
            port[:-1]
            + ', "telemetry": {"speed_bps": 1000000000, "rx_bps": 800.0, '
            '"tx_bps": 1600.0, "rx_utilization_pct": 0.00008, '
            '"tx_utilization_pct": 0.00016, "in_errors_delta": 1, '
            '"out_errors_delta": 2, "in_discards_delta": 3, '
            '"out_discards_delta": 4, "telemetry_state": "ok", '
            '"observed_at": "2026-07-26T10:00:10Z"}}'
        )
        assert port in script
        script_path.write_text(script.replace(port, telemetry), encoding="utf-8")
    return executable


def make_client(tmp_path, monkeypatch, *, include_telemetry: bool = False):
    token = "api-token"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{(tmp_path / 'web.sqlite').as_posix()}")
    monkeypatch.setenv("APP_SECRET_KEY", "test-secret")
    monkeypatch.setenv("ADMIN_USERNAME", "admin")
    monkeypatch.setenv("ADMIN_PASSWORD", "admin-pass")
    monkeypatch.setenv("OPENVPN_WEB_API_TOKEN_HASH", hashlib.sha256(token.encode("utf-8")).hexdigest())
    monkeypatch.setenv("VPNCTL_PATH", str(make_fake_vpnctl(tmp_path / "vpnctl")))
    monkeypatch.setenv("VPNCTL_USE_SUDO", "0")
    monkeypatch.setenv(
        "NETCTL_PATH",
        str(
            make_fake_netctl(
                tmp_path / "netctl", include_telemetry=include_telemetry
            )
        ),
    )
    monkeypatch.setenv("NETCTL_USE_SUDO", "0")
    monkeypatch.setenv("NETCTL_INVOKED_CLI_PATH", str(tmp_path / "netctl-invoked-cli.txt"))
    monkeypatch.setenv("NETWORK_OBSERVER_ENABLED", "1")
    monkeypatch.setenv("OUT_DIR", str(tmp_path))
    monkeypatch.setenv("SHARE_OUT_DIR", str(tmp_path))
    monkeypatch.setenv("ARCHIVE_DIR", str(tmp_path))

    import app.config
    import app.db
    import app.main
    import app.endpoint_agent_network

    app.config.reset_settings_cache()
    app.db.reset_engine_cache()
    importlib.reload(app.main)
    app.db.init_db()
    return CompletedOperationsClient(app.main.app), {"Authorization": f"Bearer {token}"}


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


def write_server_health_snapshot(tmp_path: Path, monkeypatch, *, age_seconds: int = 0, collector=None) -> None:
    collected_at = datetime.now(timezone.utc).timestamp() - age_seconds
    snapshot = tmp_path / "server-health.json"
    snapshot.write_text(
        json.dumps(
            {
                "collected_at": datetime.fromtimestamp(collected_at, timezone.utc).isoformat().replace("+00:00", "Z"),
                "targets": [
                    {
                        "role": "directum",
                        "checks": [
                            {"name": "service_state", "source": "target", "status": "ok", "observed": "active", "expected": "active"},
                        ],
                    },
                    {
                        "role": "nextcloud",
                        "checks": [
                            {"name": "https_healthcheck", "source": "vpn_path", "status": "critical", "error": "timeout"},
                        ],
                    },
                    {
                        "role": "file_server",
                        "checks": [
                            {"name": "disk_capacity", "source": "target", "status": "error", "error": "transport"},
                        ],
                    },
                ],
                **({"collector": collector} if collector is not None else {}),
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("SERVER_OBSERVER_SNAPSHOT_PATH", str(snapshot))


def test_server_health_requires_login_and_api_token_renders_redacted_snapshot(tmp_path, monkeypatch):
    """Breaks if either route bypasses auth or exposes anything beyond the view model."""
    write_server_health_snapshot(tmp_path, monkeypatch)
    marker = tmp_path / "collect-invoked"
    monkeypatch.setenv("NETCTL_COLLECT_MARKER", str(marker))
    client, headers = make_client(tmp_path, monkeypatch)

    assert client.get("/network/server-health", follow_redirects=False).status_code == 303
    assert client.get("/api/v1/network/server-health").status_code == 401

    login(client)
    page = client.get("/network/server-health")
    dashboard = client.get("/network/dashboard")
    response = client.get("/api/v1/network/server-health", headers=headers)

    assert page.status_code == dashboard.status_code == response.status_code == 200
    view = response.json()["data"]["server_health"]
    assert view["freshness"] == "current"
    assert view["summary"] == {"ok": 1, "warn": 0, "critical": 1, "error": 1}
    assert view["targets"][1]["problem_count"] == 1
    assert "<details>" in page.text
    assert "<summary>Checks</summary>" in page.text
    assert 'href="/network/server-health" class="active"' in page.text
    assert 'href="/network/server-health"' in dashboard.text
    assert "2 roles need attention" in dashboard.text
    assert not marker.exists()
    for forbidden in (
        "192.168.",
        "ssh_user",
        "server-observer.key",
        "netctl collect",
        "Traceback",
        "stdout",
        "stderr",
    ):
        assert forbidden not in page.text
        assert forbidden not in response.text


def test_server_health_stale_and_collector_failure_banners_and_navigation(tmp_path, monkeypatch):
    """Breaks if stale/failure snapshot state is hidden or dashboard navigation loses its count."""
    write_server_health_snapshot(
        tmp_path,
        monkeypatch,
        age_seconds=16 * 60,
        collector={"status": "error", "failure_class": "ssh", "message": "SSH connection failed"},
    )
    client, headers = make_client(tmp_path, monkeypatch)
    login(client)

    page = client.get("/network/server-health")
    dashboard = client.get("/network/dashboard")
    response = client.get("/api/v1/network/server-health", headers=headers)

    assert page.status_code == dashboard.status_code == response.status_code == 200
    assert response.json()["data"]["server_health"]["freshness"] == "stale"
    assert "Health data is stale" in page.text
    assert "Collector failed: SSH connection failed" in page.text
    assert 'href="/network/server-health"' in page.text
    assert 'href="/network/server-health"' in dashboard.text
    assert "Health data is stale or unavailable" in dashboard.text


def test_acti_and_backup_roles_render_in_canonical_read_only_server_health(tmp_path, monkeypatch):
    write_server_health_snapshot(tmp_path, monkeypatch)
    path = Path(os.environ["SERVER_OBSERVER_SNAPSHOT_PATH"])
    snapshot = json.loads(path.read_text(encoding="utf-8"))
    snapshot["targets"] = [
        {"role": "acti", "checks": [{"name": "https_live", "source": "gateway", "status": "ok"}]},
        {"role": "acti_backup", "checks": [{"name": "backup_snapshot_fresh", "source": "gateway", "status": "critical"}]},
    ]
    path.write_text(json.dumps(snapshot), encoding="utf-8")
    client, headers = make_client(tmp_path, monkeypatch)
    login(client)
    page = client.get("/network/server-health")
    api = client.get("/api/v1/network/server-health", headers=headers)
    assert page.status_code == api.status_code == 200
    assert "ACTI" in page.text and "ACTI — резервные копии" in page.text
    assert "https_live" in page.text and "backup_snapshot_fresh" in page.text
    assert [target["role"] for target in api.json()["data"]["server_health"]["targets"]] == ["acti", "acti_backup"]


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
    assert 'fetch("/network/runtime-health", {credentials: "same-origin", signal: controller.signal})' in script
    assert "function scheduleVpnRuntimeHealth" in script
    assert "AbortController" in script
    assert "document.hidden" in script
    assert "setInterval(loadVpnRuntimeHealth, 30000)" not in script
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


def test_web_network_hosts_page_renders_persisted_hosts(tmp_path, monkeypatch):
    client, _ = make_client(tmp_path, monkeypatch)
    login(client)

    page = client.get("/network/hosts")

    assert page.status_code == 200
    assert "Все IP и устройства" in page.text
    assert "Finance workstation" in page.text
    assert "alpha" not in page.text
    assert "Обычная сеть" in page.text
    assert "ПК" in page.text
    assert "Телефон" in page.text
    assert "Сервер" in page.text
    assert "Телефония" in page.text
    assert "Управление" in page.text
    assert "192.168.0.12" in page.text
    assert "10.83.1.11" in page.text
    assert "VPN" in page.text
    assert "192.168.50.10" not in page.text
    assert "192.168.100.55" in page.text


def test_network_hosts_get_uses_only_read_only_snapshot_commands(tmp_path, monkeypatch):
    """Rendering the host list must not start collection, probing, or network reconciliation."""
    client, _ = make_client(tmp_path, monkeypatch)
    login(client)
    invoked = tmp_path / "netctl-invoked-cli.txt"
    invoked.write_text("", encoding="utf-8")
    import app.main

    def forbidden(*args, **kwargs):
        pytest.fail("host list must not invoke vpnctl or background refresh")

    monkeypatch.setattr(app.main, "cli_call", forbidden)
    monkeypatch.setattr(app.endpoint_agent_network, "refresh_endpoint_agent_network", forbidden)

    page = client.get("/network/hosts")

    assert page.status_code == 200
    calls = invoked.read_text(encoding="utf-8").splitlines()
    assert len(calls) == 1
    assert calls[0].startswith("hosts list ")
    assert "--status=current" in calls[0]
    assert "--page 1 --limit 100" in calls[0]


def test_hosts_page_progressively_fetches_only_when_snapshot_changes():
    script = (Path(__file__).resolve().parents[1] / "app/static/network-hosts-refresh.js").read_text(encoding="utf-8")
    assert "AbortController" in script
    assert "/api/v1/network/hosts/meta" in script
    assert "window.location.reload" not in script


def test_hosts_refresh_rejects_malformed_rows_and_ignores_stale_metadata():
    script = Path(__file__).resolve().parent / "network_hosts_refresh.test.js"

    subprocess.run(["node", str(script)], check=True)


def test_hosts_page_omits_source_filters_absent_from_snapshot_rows(tmp_path, monkeypatch):
    client, _ = make_client(tmp_path, monkeypatch)
    login(client)

    page = client.get("/network/hosts")

    assert page.status_code == 200
    assert '<option value="openvpn"' not in page.text


def test_hosts_snapshot_api_allows_session_only_for_snapshot_reads(tmp_path, monkeypatch):
    client, headers = make_client(tmp_path, monkeypatch)
    import app.api as api

    assert client.get("/api/v1/network/hosts").status_code == 401
    assert client.get("/api/v1/network/hosts/meta").status_code == 401
    assert client.get("/api/v1/status").status_code == 401

    monkeypatch.setattr(
        api,
        "call_netctl",
        lambda args: {
            "hosts": [], "pagination": {"page": 1, "limit": 100, "total": 0, "pages": 0},
            "snapshot": {"snapshot_id": 0, "generated_at": None, "total_hosts": 0, "duration_ms": 0},
        },
    )
    monkeypatch.setattr(
        api,
        "run_netctl",
        lambda args: {"snapshot": {"snapshot_id": 0, "generated_at": None, "total_hosts": 0, "duration_ms": 0}},
    )
    login(client)

    assert client.get("/api/v1/network/hosts").status_code == 200
    assert client.get("/api/v1/network/hosts/meta").status_code == 200
    assert client.get("/api/v1/status").status_code == 401
    assert client.get("/api/v1/network/hosts", headers=headers).status_code == 200
    assert client.get("/api/v1/network/hosts/meta", headers=headers).status_code == 200


@pytest.mark.parametrize("at, state", [("2026-09-07T10:20:00+00:00", "ready"), ("2026-09-07T10:20:01+00:00", "stale")])
def test_snapshot_freshness_reaches_real_page_and_api_views(tmp_path, monkeypatch, at, state):
    from datetime import datetime
    from test_api_routes import snapshot_netctl
    import app.api as api
    import app.main as main
    import netctl.host_snapshot as snapshot

    client, _ = make_client(tmp_path, monkeypatch)
    login(client)
    snapshot_netctl(tmp_path, monkeypatch, count=1)
    monkeypatch.setattr(snapshot, "_reference_time", lambda now=None: datetime.fromisoformat(at))
    monkeypatch.setattr(main, "net_cli_call", lambda request, args, timeout=None: (api.run_netctl(args), None))
    page = client.get("/network/hosts")
    assert page.status_code == 200
    assert f'data-host-snapshot-state data-state="{state}"' in page.text
    for path in ("/api/v1/network/hosts", "/api/v1/network/hosts/meta"):
        response = client.get(path)
        assert response.status_code == 200
        assert response.json()["data"]["snapshot"]["stale"] is (state == "stale")


@pytest.mark.parametrize("count", [0, 210])
def test_host_page_pagination_uses_real_snapshot_and_pending_state(tmp_path, monkeypatch, count):
    from test_api_routes import snapshot_netctl
    import app.api as api
    import app.main as main

    client, _ = make_client(tmp_path, monkeypatch)
    login(client)
    snapshot_netctl(tmp_path, monkeypatch, count=count)
    monkeypatch.setattr(main, "net_cli_call", lambda request, args, timeout=None: (api.run_netctl(args), None))
    monkeypatch.setattr(main, "cli_call", lambda *a, **kw: pytest.fail("list invoked vpnctl"))
    monkeypatch.setattr(main, "attach_endpoint_agent_statuses", lambda *a, **kw: pytest.fail("list loaded external status"))
    page = client.get("/network/hosts?page=2&limit=100&seen_within=all")
    assert page.status_code == 200
    assert page.context["pagination"] == {"page": 2, "limit": 100, "total": count, "pages": 3 if count else 0}
    assert len(page.context["hosts"]) == (100 if count else 0)
    assert page.context["snapshot"]["snapshot_id"] == (1 if count else 0)
    if count:
        assert page.context["hosts"][0]["endpoint_agent"]["state"] == "disabled"
        assert "No agent" not in page.text


def test_single_host_detail_does_not_depend_on_first_snapshot_page(tmp_path, monkeypatch):
    import app.main as main

    client, _ = make_client(tmp_path, monkeypatch)
    login(client)

    def inspect(request, args, timeout=None):
        assert args == ["hosts", "inspect", "203.0.113.200"]
        return {"host": {"ip": "203.0.113.200", "display_name": "beyond first page", "status": "seen"}}, None

    monkeypatch.setattr(main, "net_cli_call", inspect)
    page = client.get("/network/hosts/203.0.113.200")
    assert page.status_code == 200
    assert "beyond first page" in page.text


def test_hosts_page_accepts_dash_prefixed_query_with_real_snapshot(tmp_path, monkeypatch):
    from test_api_routes import snapshot_netctl
    from netctl.db import connect
    import app.api as api
    import app.main as main

    client, _ = make_client(tmp_path, monkeypatch)
    login(client)
    snapshot_netctl(tmp_path, monkeypatch, count=2)
    conn = connect(f"sqlite:///{(tmp_path / 'hosts.sqlite').as_posix()}")
    conn.execute("UPDATE network_host_current_state SET search_text='office-printer' WHERE ip='203.0.113.2'")
    conn.commit()
    conn.close()
    monkeypatch.setattr(main, "net_cli_call", lambda request, args, timeout=None: (api.run_netctl(args), None))
    monkeypatch.setattr(main, "cli_call", lambda *a, **kw: pytest.fail("list invoked vpnctl"))
    page = client.get("/network/hosts", params={"q": "-printer", "seen_within": "all"})
    assert page.status_code == 200
    assert [row["ip"] for row in page.context["hosts"]] == ["203.0.113.2"]
    assert page.context["pagination"]["total"] == 1


def test_network_hosts_links_known_assets_without_changing_ip_fallback(tmp_path, monkeypatch):
    client, _ = make_client(tmp_path, monkeypatch)
    login(client)

    page = client.get("/network/hosts?q=desktop")

    assert page.status_code == 200
    assert 'href="/network/assets/mac%3AAA%3ABB%3ACC%3ADD%3AEE%3A01?return_url=' in page.text
    assert 'href="/network/hosts/192.168.100.55?return_url=' in page.text
    all_hosts = client.get("/network/hosts")
    assert 'href="/network/assets/legacy-host%3Adesk%3Fold?return_url=' in all_hosts.text
    assert 'href="/network/hosts/192.168.0.12?return_url=' in all_hosts.text


def test_network_hosts_url_encodes_reserved_asset_key_and_routes_exact_key(tmp_path, monkeypatch):
    client, _ = make_client(tmp_path, monkeypatch)
    login(client)

    hosts_page = client.get("/network/hosts")

    assert 'href="/network/assets/legacy-host%3Adesk%3Fold?return_url=' in hosts_page.text
    asset_page = client.get("/network/assets/legacy-host:desk%3Fold")
    assert asset_page.status_code == 200
    assert "legacy-host:desk?old" in asset_page.text


def test_network_asset_card_requires_login_and_renders_confirmed_attachment(tmp_path, monkeypatch):
    client, _ = make_client(tmp_path, monkeypatch, include_telemetry=True)

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
    assert "Port speed" in page.text
    assert "RX utilization" in page.text
    assert "TX utilization" in page.text
    assert "Errors Δ" in page.text
    assert "Discards Δ" in page.text
    assert "Telemetry state" in page.text
    assert "Last sample" in page.text
    assert "2026-07-26T10:00:10Z" in page.text
    assert "Роль порта" in page.text
    assert "shared edge" in page.text
    assert "Уверенность" in page.text
    assert "70%" in page.text
    assert "MAC на порту" in page.text
    assert "Высокая плотность MAC" in page.text
    assert "<canvas" not in page.text
    assert "must-not-render" not in page.text
    assert "Raw JSON" not in page.text


def test_network_asset_fingerprint_ensure_requires_login_and_csrf_before_scheduling(
    tmp_path, monkeypatch
):
    client, _ = make_client(tmp_path, monkeypatch)
    import app.main

    scheduled = []
    monkeypatch.setattr(
        app.main.BackgroundTasks,
        "add_task",
        lambda self, func, *args, **kwargs: scheduled.append((func, args, kwargs)),
    )

    denied = client.post(
        "/network/assets/mac:AA:BB:CC:DD:EE:01/fingerprint/ensure",
        follow_redirects=False,
    )
    assert denied.status_code == 303
    assert denied.headers["location"] == "/login"
    assert scheduled == []

    login(client)
    rejected = client.post(
        "/network/assets/mac:AA:BB:CC:DD:EE:01/fingerprint/ensure",
        data={"csrf_token": "wrong"},
    )
    assert rejected.status_code == 400
    assert scheduled == []


def test_network_asset_card_get_never_ensures_and_post_schedules_asset_key_only(
    tmp_path, monkeypatch
):
    client, _ = make_client(tmp_path, monkeypatch)
    login(client)
    import app.main

    scheduled = []
    monkeypatch.setattr(
        app.main.BackgroundTasks,
        "add_task",
        lambda self, func, *args, **kwargs: scheduled.append((func, args, kwargs)),
    )

    page = client.get("/network/assets/mac:AA:BB:CC:DD:EE:01")
    assert page.status_code == 200
    invoked = (tmp_path / "netctl-invoked-cli.txt").read_text(encoding="utf-8").splitlines()
    assert invoked == [
        "context-view asset --asset-key mac:AA:BB:CC:DD:EE:01"
    ]

    csrf = page.text.split('name="csrf_token" value="')[1].split('"')[0]
    accepted = client.post(
        "/network/assets/mac:AA:BB:CC:DD:EE:01/fingerprint/ensure",
        data={
            "csrf_token": csrf,
            "ip": "203.0.113.77",
            "ports": "1-65535",
            "script": "vuln",
        },
    )

    assert accepted.status_code == 202
    assert accepted.json() == {"status": "scheduled"}
    assert len(scheduled) == 1
    task, args, kwargs = scheduled[0]
    assert task is app.main.run_asset_fingerprint_ensure
    assert args == ("mac:AA:BB:CC:DD:EE:01",)
    assert kwargs == {}
    assert (tmp_path / "netctl-invoked-cli.txt").read_text(encoding="utf-8").splitlines() == invoked

    invalid = client.post(
        f"/network/assets/{'x' * 256}/fingerprint/ensure",
        data={"csrf_token": csrf},
    )
    assert invalid.status_code == 404
    assert len(scheduled) == 1


def test_network_asset_fingerprint_background_task_runs_one_bounded_netctl_ensure(
    tmp_path, monkeypatch
):
    make_client(tmp_path, monkeypatch)
    import app.main

    app.main.run_asset_fingerprint_ensure("mac:AA:BB:CC:DD:EE:01")

    assert (tmp_path / "netctl-invoked-cli.txt").read_text(encoding="utf-8").splitlines() == [
        "fingerprint ensure --asset-key mac:AA:BB:CC:DD:EE:01"
    ]


def test_network_asset_fingerprint_background_failure_isolated_from_card(
    tmp_path, monkeypatch
):
    client, _ = make_client(tmp_path, monkeypatch)
    login(client)
    import app.main

    real_run_netctl = app.main.run_netctl

    def fail_fingerprint_only(args, **kwargs):
        if args[:2] == ["fingerprint", "ensure"]:
            raise app.main.NetctlError(
                "fingerprint failed",
                returncode=1,
                stdout='{"raw_xml":"private"}',
                stderr="private command failure",
            )
        return real_run_netctl(args, **kwargs)

    monkeypatch.setattr(app.main, "run_netctl", fail_fingerprint_only)

    app.main.run_asset_fingerprint_ensure("mac:AA:BB:CC:DD:EE:01")

    page = client.get("/network/assets/mac:AA:BB:CC:DD:EE:01")
    assert page.status_code == 200
    assert "access-a" in page.text


def test_network_asset_fingerprint_status_requires_login_and_returns_only_panel_fields(
    tmp_path, monkeypatch
):
    client, _ = make_client(tmp_path, monkeypatch)
    import app.main

    calls = []

    def cached_context(args, **kwargs):
        calls.append((args, kwargs))
        return {
            "status": "ok",
            "context": {
                "fingerprint": {
                    "device_type": "network",
                    "confidence": 96,
                    "computed_at": "2026-08-09T10:00:01Z",
                    "evidence": [
                        {
                            "provider": "oui",
                            "signal": "mikrotik",
                            "candidate_type": "network",
                            "weight": 50,
                            "summary": "Local OUI vendor suggests network: MikroTik",
                            "raw": "must-not-leak",
                        },
                        {
                            "provider": "nmap_os",
                            "signal": "router",
                            "candidate_type": "network",
                            "weight": 80,
                            "summary": "Nmap OS class suggests network at 98% accuracy",
                        },
                    ],
                    "alternatives": [{"device_type": "server", "score": 10}],
                },
                "nmap_fingerprint": {
                    "id": 17,
                    "status": "success",
                    "fresh": True,
                    "target_ip": "192.168.100.55",
                    "started_at": "2026-08-09T10:00:00Z",
                    "finished_at": "2026-08-09T10:00:01Z",
                    "nmap_version": "7.95",
                    "raw_xml": "<private />",
                    "stderr": "private error",
                    "command": "nmap --script vuln 192.168.100.55",
                    "vulnerabilities": [{"cve": "CVE-2099-0001"}],
                    "ports": [
                        {
                            "port": 22,
                            "protocol": "tcp",
                            "state": "open",
                            "service_name": "ssh",
                            "product": "RouterOS sshd",
                            "version": "7.15",
                            "extra_info": "private",
                            "cpes": ["cpe:/o:mikrotik:routeros"],
                        },
                        {
                            "port": 80,
                            "protocol": "tcp",
                            "state": "closed",
                            "service_name": "http",
                            "product": "must-not-render",
                            "version": "",
                        },
                    ],
                    "os_matches": [
                        {
                            "name": "MikroTik RouterOS 7.15",
                            "accuracy": 98,
                            "classes": [{"vendor": "private"}],
                        }
                    ],
                },
            },
        }

    monkeypatch.setattr(app.main, "run_netctl", cached_context)

    denied = client.get(
        "/network/assets/mac:AA:BB:CC:DD:EE:01/fingerprint/status",
        follow_redirects=False,
    )
    assert denied.status_code == 303
    assert calls == []

    login(client)
    response = client.get(
        "/network/assets/mac:AA:BB:CC:DD:EE:01/fingerprint/status"
    )

    assert response.status_code == 200
    assert response.json() == {
        "status": "success",
        "fresh": True,
        "generation": "17",
        "device_type": "network",
        "confidence": 96,
        "vendor": "MikroTik",
        "os": "MikroTik RouterOS 7.15",
        "nmap_accuracy": 98,
        "last_fingerprint_at": "2026-08-09T10:00:01Z",
        "services": [
            {
                "port": 22,
                "protocol": "tcp",
                "service": "ssh",
                "product": "RouterOS sshd",
                "version": "7.15",
            }
        ],
        "evidence": [
            {
                "source": "OUI",
                "summary": "Local OUI vendor suggests network: MikroTik",
            },
            {
                "source": "Nmap",
                "summary": "Nmap OS class suggests network at 98% accuracy",
            },
        ],
    }
    assert calls[0][0] == [
        "context-view",
        "asset",
        "--asset-key",
        "mac:AA:BB:CC:DD:EE:01",
    ]
    serialized = json.dumps(response.json())
    for forbidden in (
        "target_ip",
        "raw_xml",
        "stderr",
        "command",
        "vulnerabilities",
        "CVE-",
        "cpes",
        "extra_info",
        "must-not-render",
    ):
        assert forbidden not in serialized


def test_network_asset_card_renders_cached_normalized_fingerprint_panels(
    tmp_path, monkeypatch
):
    client, _ = make_client(tmp_path, monkeypatch)
    login(client)
    import app.main

    def cached_card(_request, _args, timeout=None):
        return (
            {
                "context": {
                    "asset": {
                        "asset_key": "mac:AA:BB:CC:DD:EE:01",
                        "display_name": "Router",
                    },
                    "fingerprint": {
                        "device_type": "network",
                        "confidence": 96,
                        "evidence": [
                            {
                                "provider": "oui",
                                "summary": "Local OUI vendor suggests network: MikroTik",
                                "raw": "must-not-leak",
                            },
                            {
                                "provider": "lldp",
                                "summary": "LLDP capabilities identify bridge",
                            },
                        ],
                    },
                    "nmap_fingerprint": {
                        "id": 17,
                        "status": "success",
                        "fresh": True,
                        "finished_at": "2026-08-09T10:00:01Z",
                        "raw_xml": "<must-not-render />",
                        "stderr": "private command error",
                        "command": "nmap --script vuln 192.0.2.1",
                        "ports": [
                            {
                                "port": 22,
                                "protocol": "tcp",
                                "state": "open",
                                "service_name": "ssh",
                                "product": "RouterOS sshd",
                                "version": "7.15",
                            },
                            {
                                "port": 80,
                                "protocol": "tcp",
                                "state": "closed",
                                "service_name": "http",
                                "product": "must-not-render",
                                "version": "",
                            },
                        ],
                        "os_matches": [
                            {"name": "MikroTik RouterOS 7.15", "accuracy": 98}
                        ],
                    },
                }
            },
            None,
        )

    monkeypatch.setattr(app.main, "net_cli_call", cached_card)

    page = client.get("/network/assets/mac:AA:BB:CC:DD:EE:01")

    assert page.status_code == 200
    assert "Device fingerprint" in page.text
    assert "Network services" in page.text
    assert "Evidence" in page.text
    for label in (
        "\u0422\u0438\u043f",
        "\u0423\u0432\u0435\u0440\u0435\u043d\u043d\u043e\u0441\u0442\u044c",
        "OUI/vendor",
        "OS",
        "Nmap accuracy",
        "Last fingerprint time",
    ):
        assert label in page.text
    for value in (
        "network",
        "96%",
        "MikroTik",
        "MikroTik RouterOS 7.15",
        "98%",
        "2026-08-09T10:00:01Z",
        "RouterOS sshd",
        "LLDP capabilities identify bridge",
        "\u0410\u043a\u0442\u0443\u0430\u043b\u044c\u043d\u043e",
    ):
        assert value in page.text
    assert 'data-fingerprint-panel' in page.text
    assert 'data-initial-status="success"' in page.text
    assert 'data-initial-generation="17"' in page.text
    assert 'data-ensure-url="/network/assets/mac%3AAA%3ABB%3ACC%3ADD%3AEE%3A01/fingerprint/ensure"' in page.text
    assert 'data-status-url="/network/assets/mac%3AAA%3ABB%3ACC%3ADD%3AEE%3A01/fingerprint/status"' in page.text
    assert 'network-asset-fingerprint.js' in page.text
    for forbidden in (
        "must-not-render",
        "must-not-leak",
        "raw_xml",
        "stderr",
        "nmap --script",
        "CVE-",
    ):
        assert forbidden not in page.text


@pytest.mark.parametrize(
    "query",
    ["FINANCE", "pc-buh-01", "192.168.100.55", "AA:BB:CC:DD:EE:01", "mac:AA:BB:CC:DD:EE:01"],
)
def test_network_hosts_searches_manual_name_and_stable_host_identifiers(tmp_path, monkeypatch, query):
    client, _ = make_client(tmp_path, monkeypatch)
    login(client)

    page = client.get("/network/hosts", params={"q": query})

    assert page.status_code == 200
    assert 'href="/network/assets/mac%3AAA%3ABB%3ACC%3ADD%3AEE%3A01?return_url=' in page.text


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
    assert "tplink-ito-15" in ambiguous.text
    assert "physical:2" in ambiguous.text
    assert "VLAN: 20" in ambiguous.text
    assert "unknown" in ambiguous.text
    assert "50" in ambiguous.text
    assert "статус порта не получен" in ambiguous.text
    assert "есть конкурирующая FDB-запись" in ambiguous.text
    assert "Источник: —" in ambiguous.text
    assert "Порт: —" in ambiguous.text
    assert "VLAN: —" in ambiguous.text
    assert "класс: —" in ambiguous.text
    assert "оценка: —" in ambiguous.text
    assert "причина: —" in ambiguous.text
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


def test_network_api_hosts_returns_snapshot_rows(tmp_path, monkeypatch):
    client, headers = make_client(tmp_path, monkeypatch)

    response = client.get("/api/v1/network/hosts", headers=headers)

    assert response.status_code == 200
    rows = response.json()["data"]["hosts"]
    assert {row["ip"] for row in rows} == {"192.168.100.55", "192.168.0.12", "10.83.1.11"}
    assert response.json()["data"]["pagination"]["total"] == 3
    assert response.json()["data"]["snapshot"]["snapshot_id"] == 1
    phone = next(row for row in rows if row["ip"] == "192.168.0.12")
    assert phone["device_type"] == "phone"
    assert phone["device_confidence"] == 85


def test_public_availability_keeps_safe_not_monitored_reason_and_check_origin():
    """Dropping safe origin fields would make manual and disabled projections indistinguishable."""
    from app.network_observer import normalize_netctl_host

    host = normalize_netctl_host(
        {
            "ip": "192.0.2.33",
            "status": "stale",
            "availability": {
                "state": "not_monitored",
                "reason": "not_monitored",
                "check_origin": "manual",
            },
        }
    )

    assert host["availability"]["state"] == "not_monitored"
    assert host["availability"]["reason"] == "not_monitored"
    assert host["availability"]["check_origin"] == "manual"


def test_public_availability_drops_unknown_check_origin():
    """Only server-declared manual and scheduled origins belong in the public payload."""
    from app.network_observer import normalize_netctl_host

    host = normalize_netctl_host(
        {
            "ip": "192.0.2.33",
            "status": "stale",
            "availability": {
                "state": "stale",
                "check_origin": "browser-command",
            },
        }
    )

    assert "check_origin" not in host["availability"]


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
        if args[:2] == ["hosts", "list"]:
            from netctl.cli import build_parser

            status = build_parser().parse_args(args).status
            selected = [host for host in hosts if status == "all" or (host["status"] in {"online", "seen", "connected"} if status == "current" else host["status"] == status)]
            return {"hosts": selected, "pagination": {"page": 1, "limit": 100, "total": len(selected), "pages": 1}, "snapshot": {"snapshot_id": 1, "generated_at": "2026-09-07T10:00:00Z", "total_hosts": 4, "duration_ms": 1}}
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
    from netctl.cli import build_parser

    assert [build_parser().parse_args(args).status for args in netctl_calls] == ["current", "all", "offline", "stale"]


def test_network_hosts_page_renders_sanitized_availability_and_not_monitored(tmp_path, monkeypatch):
    client, _ = make_client(tmp_path, monkeypatch)
    import app.main

    hosts = [
        {
            "ip": "192.168.99.46", "display_name": "stale host", "status": "stale",
            "availability": {
                "state": "stale",
                "active_method": "icmp",
                "checked_at": "2026-07-29T10:00:00Z",
                "reason": "run_failed socket timeout",
            },
        },
        {
            "ip": "192.168.99.47",
            "display_name": "unmonitored host",
            "status": "stale",
            "availability": {"state": "not_monitored", "reason": "not_monitored"},
        },
    ]

    def fake_netctl(request, args, timeout=None):
        if args[:2] == ["hosts", "list"]:
            from netctl.cli import build_parser

            status = build_parser().parse_args(args).status or "current"
            return {"hosts": hosts if status in {"all", "stale"} else []}, None
        if args == ["sources", "list"]:
            return {"sources": []}, None
        if args == ["hosts", "inspect", "192.168.99.46"]:
            return {"host": hosts[0]}, None
        raise AssertionError(args)

    monkeypatch.setattr(app.main, "net_cli_call", fake_netctl)
    monkeypatch.setattr(app.main, "cli_call", lambda request, args, timeout=None: ({"connected": []} if args[0] == "connected" else {"clients": []}, None))
    login(client)

    page = client.get("/network/hosts?status=stale&seen_within=all")
    detail = client.get("/network/hosts/192.168.99.46")
    all_hosts = client.get("/network/hosts?status=all&seen_within=all")
    invalid = client.get("/network/hosts?status=unexpected")

    assert page.status_code == detail.status_code == all_hosts.status_code == invalid.status_code == 200
    assert "run failed" in page.text
    assert "socket timeout" not in page.text
    assert "run_failed" in detail.text
    assert "socket timeout" not in detail.text
    assert "данные устарели" in page.text
    assert "не мониторится" in all_hosts.text
    assert "not_monitored" not in all_hosts.text
    assert ">stale<" not in page.text
    assert 'value="unexpected"' not in invalid.text
    assert "stale host" not in invalid.text


def test_host_history_period_defaults_to_24_hours_and_can_include_history():
    """The normal device list must be observation-based, with explicit access to history."""
    from app.network_observer import filter_unified_hosts

    now = datetime.now(timezone.utc)
    fresh = now.isoformat().replace("+00:00", "Z")
    old = (now.replace(microsecond=0) - timedelta(days=8)).isoformat().replace("+00:00", "Z")
    rows = [
        {"ip": "192.0.2.1", "display_name": "fresh device", "category": "unknown", "status": "seen", "last_seen_at": fresh},
        {"ip": "192.0.2.2", "display_name": "old device", "category": "unknown", "status": "stale", "last_seen_at": old},
        {"ip": "192.0.2.3", "display_name": "bad timestamp", "category": "unknown", "status": "stale", "last_seen_at": "not-a-time"},
    ]

    default_rows = filter_unified_hosts(rows, {"status": "all", "seen_within": "24h"})
    weekly_rows = filter_unified_hosts(rows, {"status": "all", "seen_within": "7d"})
    historical_rows = filter_unified_hosts(rows, {"status": "all", "seen_within": "all"})

    assert [row["display_name"] for row in default_rows] == ["fresh device"]
    assert [row["display_name"] for row in weekly_rows] == ["fresh device"]
    assert [row["display_name"] for row in historical_rows] == ["fresh device", "old device", "bad timestamp"]


@pytest.mark.parametrize(
    ("state", "reason", "expected"),
    [
        ("stale", "run_stale", "данные устарели"),
        ("not_monitored", "not_monitored", "не мониторится"),
    ],
)
def test_network_host_detail_sanitizes_summary_and_availability_status(
    tmp_path,
    monkeypatch,
    state,
    reason,
    expected,
):
    """The host summary must not bypass the public availability-state presentation."""
    client, _ = make_client(tmp_path, monkeypatch)
    import app.main

    host = {
        "ip": "192.168.99.48",
        "display_name": "archive host",
        "status": "stale",
        "availability": {"state": state, "reason": reason},
    }

    def fake_netctl(request, args, timeout=None):
        if args == ["hosts", "inspect", "192.168.99.48"]:
            return {"host": host, "observations": []}, None
        if args == ["hosts", "list"]:
            return {"hosts": [host]}, None
        raise AssertionError(args)

    monkeypatch.setattr(app.main, "net_cli_call", fake_netctl)
    monkeypatch.setattr(
        app.main,
        "cli_call",
        lambda request, args, timeout=None: (
            {"connected": []} if args[0] == "connected" else {"clients": []},
            None,
        ),
    )
    login(client)

    detail = client.get("/network/hosts/192.168.99.48")

    assert detail.status_code == 200
    summary_status = detail.text.split("<dt>Статус</dt><dd>", 1)[1].split("</dd>", 1)[0]
    availability_status = detail.text.split("<dt>Состояние</dt><dd>", 1)[1].split("</dd>", 1)[0]
    assert summary_status == expected
    assert availability_status == expected


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
        "availability": {
            "state": "online",
            "active_method": "icmp",
            "checked_at": "2026-07-29T10:00:00Z",
            "reason": "active_probe",
        },
    }

    [merged] = merge_unified_hosts([source], [{"common_name": "alpha", "virtual_address": "192.168.99.44"}], [])

    assert merged["status"] == "connected"
    assert merged["availability"] == {
        "state": "online",
        "active_method": "icmp",
        "checked_at": "2026-07-29T10:00:00Z",
        "reason": "openvpn_management",
    }
    assert source["availability"]["reason"] == "active_probe"


def test_openvpn_only_host_is_connected_but_never_online():
    """A management connection without ICMP/TCP evidence must not claim availability."""
    from app.main import availability_status_label
    from app.network_observer import merge_unified_hosts

    [host] = merge_unified_hosts(
        [],
        [{"common_name": "alpha", "virtual_address": "192.168.50.10"}],
        [],
    )

    assert host["status"] == "connected"
    assert host["availability"] == {"reason": "openvpn_management"}
    assert availability_status_label(host) == "VPN подключён"


def test_host_list_uses_snapshot_while_details_keep_openvpn_view(tmp_path, monkeypatch):
    client, headers = make_client(tmp_path, monkeypatch)
    import app.api
    import app.main

    host = {
        "ip": "192.168.99.44", "display_name": "vpn workstation", "status": "online",
        "availability": {
            "state": "online",
            "active_method": "icmp", "checked_at": "2026-07-29T10:00:00Z",
            "reason": "active_probe socket timeout",
        },
    }
    connected = [
        {"common_name": "unrelated", "virtual_address": "192.168.50.3"},
        {"common_name": "alpha", "virtual_address": "192.168.99.44"},
    ]

    def api_netctl(args, timeout=None):
        if args[:2] == ["hosts", "list"]:
            return {"hosts": [host], "pagination": {"page": 1, "limit": 100, "total": 1, "pages": 1}, "snapshot": {"snapshot_id": 1, "generated_at": "2026-09-07T10:00:00Z", "total_hosts": 1, "duration_ms": 1}}
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
    assert listed.json()["data"]["hosts"][0]["status"] == "online"
    assert listed.json()["data"]["hosts"][0]["availability"]["reason"] == "active_probe"
    assert api_detail.json()["data"]["host"]["ip"] == "192.168.99.44"
    assert api_detail.json()["data"]["host"]["status"] == "connected"
    assert "<dt>Статус</dt><dd>Доступен · ICMP</dd>" in page_detail.text
    assert api_detail.json()["data"]["host"]["availability"]["reason"] == "openvpn_management"
    assert "socket timeout" not in api_detail.text
    assert "socket timeout" not in page_detail.text


def test_monitoring_page_renders_only_canonical_read_only_segment_context(tmp_path, monkeypatch):
    """Making canonical CIDR/context editable would let the browser redefine network intent."""
    client, _ = make_client(tmp_path, monkeypatch)
    import app.main

    login(client)
    monkeypatch.setattr(
        app.main,
        "net_cli_call",
        lambda request, args, timeout=None: (
            {
                "segments": [
                    {
                        "segment_id": "office",
                        "cidr": "192.168.99.0/24",
                        "site": "hq",
                        "category": "local_device",
                        "enabled": True,
                        "tcp_ports": [443],
                        "interval_minutes": 10,
                    }
                ]
            },
            None,
        )
        if args == ["availability", "settings"]
        else pytest.fail(f"unexpected netctl call: {args}"),
    )

    page = client.get("/network/monitoring")

    assert page.status_code == 200
    assert "Настройки доступности" in page.text
    assert "192.168.99.0/24" in page.text
    assert "hq" in page.text
    assert 'action="/network/monitoring/office"' in page.text
    assert 'name="cidr"' not in page.text
    assert 'name="site"' not in page.text
    assert 'name="category"' not in page.text


def test_monitoring_settings_posts_fixed_canonical_segment_and_audits(tmp_path, monkeypatch):
    """A browser field must not be able to replace the canonical segment identity or CIDR."""
    client, _ = make_client(tmp_path, monkeypatch)
    import app.main

    csrf = login(client)
    calls = []

    def fake_netctl(request, args, timeout=None):
        calls.append((args, timeout))
        return {"setting": {"segment_id": "office"}}, None

    monkeypatch.setattr(app.main, "net_cli_call", fake_netctl)

    response = client.post(
        "/network/monitoring/office",
        data={
            "enabled": "true",
            "tcp_ports": "443",
            "interval_minutes": "10",
            "cidr": "203.0.113.0/24",
            "site": "forged",
            "category": "wan",
            "csrf_token": csrf,
        },
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert response.headers["location"] == "/network/monitoring"
    assert calls == [
        (
            [
                "availability",
                "set-segment",
                "--segment-id",
                "office",
                "--enabled",
                "true",
                "--tcp-port",
                "443",
                "--interval-minutes",
                "10",
            ],
            60,
        )
    ]
    from app.db import session_scope
    from app.models import WebAuditLog

    with session_scope() as db:
        audit = db.query(WebAuditLog).filter_by(action="network-availability-settings").one()
    assert audit.actor == "admin"
    assert audit.target_client == "office"
    assert audit.result == "ok"
    assert "203.0.113.0/24" not in audit.message


def test_manual_check_uses_url_ip_audits_and_rate_limits(tmp_path, monkeypatch):
    """A repeated accepted probe could bypass the five-minute public action budget."""
    client, _ = make_client(tmp_path, monkeypatch)
    import app.main

    csrf = login(client)
    calls = []

    def fake_netctl(request, args, timeout=None):
        calls.append((args, timeout))
        if args == ["hosts", "inspect", "192.168.99.44"]:
            return {
                "host": {
                    "ip": "192.168.99.44",
                    "availability": {"state": "stale", "reason": "missing_run"},
                }
            }, None
        return {"result": {"ip": "192.168.99.44"}}, None

    monkeypatch.setattr(app.main, "net_cli_call", fake_netctl)

    first = client.post(
        "/network/hosts/192.168.99.44/availability-check",
        data={"csrf_token": csrf, "ip": "203.0.113.77", "tcp_port": "22"},
        follow_redirects=False,
    )
    second = client.post(
        "/network/hosts/192.168.99.44/availability-check",
        data={"csrf_token": csrf},
        follow_redirects=False,
    )
    flash_page = client.get(second.headers["location"])

    assert first.status_code == second.status_code == 303
    assert first.headers["location"] == second.headers["location"] == "/network/hosts/192.168.99.44"
    assert [call for call in calls if call[0][:2] == ["availability", "probe"]] == [
        (["availability", "probe", "--ip", "192.168.99.44"], 60)
    ]
    assert "через 5 минут" in flash_page.text
    from app.db import session_scope
    from app.models import WebAuditLog

    with session_scope() as db:
        audits = db.query(WebAuditLog).filter_by(action="network-host-availability").all()
    assert [(audit.actor, audit.target_client, audit.result) for audit in audits] == [
        ("admin", "192.168.99.44", "ok"),
        ("admin", "192.168.99.44", "denied"),
    ]


def test_manual_check_rejects_nonexistent_in_cidr_target_and_audits(tmp_path, monkeypatch):
    """CIDR membership alone must not turn an arbitrary URL IP into a probe target."""
    client, _ = make_client(tmp_path, monkeypatch)
    import app.main

    csrf = login(client)
    calls = []

    def fake_netctl(request, args, timeout=None):
        calls.append((args, timeout))
        if args == ["hosts", "inspect", "192.168.99.222"]:
            return {}, "host not found"
        pytest.fail(f"unexpected netctl call: {args}")

    monkeypatch.setattr(app.main, "net_cli_call", fake_netctl)

    response = client.post(
        "/network/hosts/192.168.99.222/availability-check",
        data={"csrf_token": csrf},
        follow_redirects=False,
    )

    assert response.status_code == 404
    assert calls == [(["hosts", "inspect", "192.168.99.222"], None)]
    from app.db import session_scope
    from app.models import WebAuditLog

    with session_scope() as db:
        audit = db.query(WebAuditLog).filter_by(action="network-host-availability").one()
    assert (audit.target_client, audit.result, audit.message) == (
        "192.168.99.222",
        "denied",
        "host target not found",
    )


def test_not_monitored_host_hides_and_rejects_manual_check(tmp_path, monkeypatch):
    """A known passive host outside enabled segments must not expose or accept probing."""
    client, _ = make_client(tmp_path, monkeypatch)
    import app.main

    host = {
        "ip": "192.168.99.47",
        "display_name": "archive host",
        "status": "seen",
        "availability": {"state": "not_monitored", "reason": "not_monitored"},
    }
    calls = []

    def fake_netctl(request, args, timeout=None):
        calls.append((args, timeout))
        if args == ["hosts", "inspect", "192.168.99.47"]:
            return {"host": host, "observations": []}, None
        if args == ["hosts", "list"]:
            return {"hosts": [host]}, None
        pytest.fail(f"unexpected netctl call: {args}")

    monkeypatch.setattr(app.main, "net_cli_call", fake_netctl)
    monkeypatch.setattr(
        app.main,
        "cli_call",
        lambda request, args, timeout=None: (
            {"connected": []} if args[0] == "connected" else {"clients": []},
            None,
        ),
    )
    csrf = login(client)

    page = client.get("/network/hosts/192.168.99.47")
    response = client.post(
        "/network/hosts/192.168.99.47/availability-check",
        data={"csrf_token": csrf},
        follow_redirects=False,
    )

    assert page.status_code == 200
    assert 'action="/network/hosts/192.168.99.47/availability-check"' not in page.text
    assert response.status_code == 403
    assert not any(args[:2] == ["availability", "probe"] for args, _timeout in calls)
    from app.db import session_scope
    from app.models import WebAuditLog

    with session_scope() as db:
        audit = db.query(WebAuditLog).filter_by(action="network-host-availability").one()
    assert (audit.target_client, audit.result, audit.message) == (
        "192.168.99.47",
        "denied",
        "host target is not monitored",
    )


def test_network_action_throttle_accepts_only_one_concurrent_session(tmp_path, monkeypatch):
    """Two simultaneous database sessions must not both acquire the same action budget."""
    from concurrent.futures import ThreadPoolExecutor
    from threading import Barrier

    make_client(tmp_path, monkeypatch)
    from app.db import get_sessionmaker
    from app.models import utcnow
    from app.network_actions import acquire_network_action

    barrier = Barrier(2)
    now = utcnow()

    def attempt() -> bool:
        with get_sessionmaker()() as db:
            barrier.wait(timeout=5)
            return acquire_network_action(
                db,
                "admin",
                "network-host-availability",
                now,
            ).accepted

    with ThreadPoolExecutor(max_workers=2) as pool:
        accepted = list(pool.map(lambda _: attempt(), range(2)))

    assert sorted(accepted) == [False, True]


def test_network_throttle_reports_remaining_time_without_extending_it(tmp_path, monkeypatch):
    make_client(tmp_path, monkeypatch)
    from app.db import get_sessionmaker
    from app.network_actions import acquire_network_action

    now = datetime.now(timezone.utc)
    with get_sessionmaker()() as db:
        assert acquire_network_action(db, "operator", "capture", now).accepted
        denied = acquire_network_action(db, "operator", "capture", now + timedelta(seconds=120.25))
        assert not denied.accepted and denied.retry_after_seconds == 180
        almost_ready = acquire_network_action(db, "operator", "capture", now + timedelta(seconds=299.5))
        assert not almost_ready.accepted and almost_ready.retry_after_seconds == 1
        ready = acquire_network_action(db, "operator", "capture", now + timedelta(seconds=300))
        assert ready.accepted and ready.retry_after_seconds is None


def test_observation_refresh_is_independently_throttled_and_uses_fixed_command(tmp_path, monkeypatch):
    """Observation refresh must not accept a browser-selected source or reuse the probe budget."""
    client, _ = make_client(tmp_path, monkeypatch)
    import app.main

    csrf = login(client)
    calls = []
    def fake_netctl(request, args, timeout=None):
        calls.append((args, timeout))
        if args == ["hosts", "inspect", "192.168.99.44"]:
            return {
                "host": {
                    "ip": "192.168.99.44",
                    "availability": {"state": "stale", "reason": "missing_run"},
                }
            }, None
        return {"status": "ok"}, None

    monkeypatch.setattr(app.main, "net_cli_call", fake_netctl)

    probe = client.post(
        "/network/hosts/192.168.99.44/availability-check",
        data={"csrf_token": csrf},
        follow_redirects=False,
    )
    refresh = client.post(
        "/network/hosts/192.168.99.44/refresh-observations",
        data={"csrf_token": csrf, "source": "forged", "ip": "203.0.113.77"},
        follow_redirects=False,
    )

    assert probe.status_code == refresh.status_code == 303
    assert calls == [
        (["hosts", "inspect", "192.168.99.44"], None),
        (["availability", "probe", "--ip", "192.168.99.44"], 60),
        (["observations", "refresh"], 300),
    ]


def test_network_host_actions_require_login_and_csrf_without_cli_calls(tmp_path, monkeypatch):
    """Authentication or CSRF regressions must never reach a network action."""
    client, _ = make_client(tmp_path, monkeypatch)
    import app.main

    calls = []
    monkeypatch.setattr(
        app.main,
        "net_cli_call",
        lambda request, args, timeout=None: (calls.append(args) or {}, None),
    )

    anonymous = client.post(
        "/network/hosts/192.168.99.44/availability-check",
        follow_redirects=False,
    )
    login(client)
    bad_csrf = client.post(
        "/network/hosts/192.168.99.44/refresh-observations",
        data={"csrf_token": "wrong"},
        follow_redirects=False,
    )

    assert anonymous.status_code == 303
    assert anonymous.headers["location"] == "/login"
    assert bad_csrf.status_code == 400
    assert calls == []


@pytest.mark.parametrize(
    ("route_suffix", "ip", "action"),
    [
        ("availability-check", "not-an-ip", "network-host-availability"),
        ("availability-check", "192.168.099.44", "network-host-availability"),
        ("refresh-observations", "not-an-ip", "network-host-observation-refresh"),
        ("refresh-observations", "192.168.099.44", "network-host-observation-refresh"),
    ],
)
def test_authenticated_host_actions_audit_invalid_ip_without_cli(
    tmp_path,
    monkeypatch,
    route_suffix,
    ip,
    action,
):
    """Invalid URL targets must remain 404s while leaving an authenticated audit trail."""
    client, _ = make_client(tmp_path, monkeypatch)
    import app.main

    csrf = login(client)
    calls = []
    monkeypatch.setattr(
        app.main,
        "net_cli_call",
        lambda request, args, timeout=None: (calls.append(args) or {}, None),
    )

    response = client.post(
        f"/network/hosts/{ip}/{route_suffix}",
        data={"csrf_token": csrf},
        follow_redirects=False,
    )

    assert response.status_code == 404
    assert calls == []
    from app.db import session_scope
    from app.models import WebAuditLog

    with session_scope() as db:
        audit = db.query(WebAuditLog).filter_by(action=action).one()
    assert audit.actor == "admin"
    assert audit.result == "error"
    assert audit.message == "invalid IPv4 host target"
    assert audit.target_client == ip


def test_host_pages_render_russian_availability_evidence_and_csrf_only_actions(tmp_path, monkeypatch):
    """Raw reasons or editable action targets would leak internals or widen device controls."""
    client, _ = make_client(tmp_path, monkeypatch)
    import app.main

    host = {
        "ip": "192.168.99.44",
        "display_name": "Архивный сервер",
        "status": "online",
        "sources": ["mikrotik_arp"],
        "availability": {
            "state": "online",
            "active_method": "tcp:443",
            "checked_at": "2026-07-29T10:00:00Z",
            "check_origin": "manual",
            "cidr": "192.168.99.0/24",
            "passive_evidence": [
                "mikrotik_arp",
                "mikrotik_dhcp",
                "mikrotik_bridge",
                "snmp_fdb",
            ],
            "reason": "active_probe socket timeout must-not-render",
        },
    }

    def fake_netctl(request, args, timeout=None):
        if args[:2] == ["hosts", "list"]:
            return {"hosts": [host]}, None
        if args == ["hosts", "inspect", "192.168.99.44"]:
            return {"host": host, "observations": []}, None
        if args == ["sources", "list"]:
            return {"sources": []}, None
        raise AssertionError(args)

    monkeypatch.setattr(app.main, "net_cli_call", fake_netctl)
    monkeypatch.setattr(
        app.main,
        "cli_call",
        lambda request, args, timeout=None: (
            {"connected": []} if args[0] == "connected" else {"clients": []},
            None,
        ),
    )
    login(client)

    listed = client.get("/network/hosts")
    detail = client.get("/network/hosts/192.168.99.44")

    assert listed.status_code == detail.status_code == 200
    assert 'href="/network/hosts/192.168.99.44?return_url=' in listed.text
    assert "Доступен · TCP:443" in listed.text
    assert "Доступность" in detail.text
    assert "Свежесть наблюдений" in detail.text
    assert "192.168.99.0/24" in detail.text
    assert "TCP:443" in detail.text
    assert "ручная" in detail.text
    assert "ARP, DHCP, bridge, FDB" in detail.text
    evidence_row = detail.text.split("<dt>Пассивные признаки</dt><dd>", 1)[1].split("</dd>", 1)[0]
    assert evidence_row == "ARP, DHCP, bridge, FDB"
    assert "active probe" in detail.text
    assert "socket timeout" not in detail.text
    availability_form = detail.text.split('action="/network/hosts/192.168.99.44/availability-check"', 1)[1].split("</form>", 1)[0]
    refresh_form = detail.text.split('action="/network/hosts/192.168.99.44/refresh-observations"', 1)[1].split("</form>", 1)[0]
    assert 'name="csrf_token"' in availability_form
    assert 'name="csrf_token"' in refresh_form
    assert 'name="ip"' not in availability_form + refresh_form
    assert 'name="cidr"' not in availability_form + refresh_form
    assert 'name="tcp_port"' not in availability_form + refresh_form


def test_force_monitor_route_uses_fixed_persist_probe_and_refresh_commands(tmp_path, monkeypatch):
    """Force monitoring of a known historical host must be explicit and immediately verifiable."""
    client, _ = make_client(tmp_path, monkeypatch)
    import app.main

    calls = []

    def fake_netctl(request, args, timeout=None):
        calls.append((args, timeout))
        if args == ["hosts", "inspect", "192.168.99.44"]:
            return {
                "host": {
                    "ip": "192.168.99.44",
                    "availability": {"state": "stale", "reason": "missing_run"},
                }
            }, None
        return {}, None

    monkeypatch.setattr(app.main, "net_cli_call", fake_netctl)
    csrf = login(client)

    response = client.post(
        "/network/hosts/192.168.99.44/force-monitor",
        data={"csrf_token": csrf, "ip": "192.0.2.77"},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert calls == [
        (["hosts", "inspect", "192.168.99.44"], None),
        (["availability", "force", "--ip", "192.168.99.44", "--enabled", "true"], 30),
        (["availability", "probe", "--ip", "192.168.99.44"], 60),
        (["observations", "refresh"], 300),
    ]


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


def test_network_interfaces_shows_history_for_selected_source(tmp_path, monkeypatch):
    client, headers = make_client(tmp_path, monkeypatch)
    login(client)
    from app import api, main
    from netctl.cli import build_parser, dispatch
    from netctl.db import connect
    from netctl.network_diagnostics import record_router_samples

    db_url = f"sqlite:///{(tmp_path / 'observer.sqlite').as_posix()}"
    original = main.net_cli_call

    def net_cli_call(request, args, **kwargs):
        if args[:2] == ["interfaces", "diagnostics"]:
            rc, result = dispatch(build_parser().parse_args(["--db", db_url, *args]))
            assert rc == 0
            return result, ""
        return original(request, args, **kwargs)

    monkeypatch.setattr(main, "net_cli_call", net_cli_call)
    monkeypatch.setattr(api, "call_netctl", lambda args, **kwargs: net_cli_call(None, args, **kwargs)[0])
    with connect(db_url) as conn:
        conn.execute(
            """INSERT INTO network_sources
               (id, name, driver, host, port, username, secret_ref, site, created_at, updated_at)
               VALUES (1, 'mikrotik-main', 'mikrotik_api', '127.0.0.1', 1, '', '', '', '', '')"""
        )
        conn.execute(
            "INSERT INTO network_interfaces (source_id, name, type, comment) VALUES (1, 'ether1', 'ether', 'WAN')"
        )
        conn.execute("UPDATE network_sources SET last_status='failed' WHERE id=1")
        now = datetime.now(timezone.utc)
        for minutes_ago, tx_errors, tx_drops in [(10, 4, 8), (5, 6, 9)]:
            observed_at = (now - timedelta(minutes=minutes_ago)).strftime("%Y-%m-%dT%H:%M:%SZ")
            record_router_samples(conn, 1, observed_at, [{
                "name": "ether1", "type": "ether", "running": True, "link_downs": 0,
                "in_errors": 0, "out_errors": tx_errors, "in_discards": 0, "out_discards": tx_drops,
            }])
    conn.close()
    page = client.get("/network/interfaces?source=mikrotik-main&interface=ether1")
    assert page.status_code == 200
    assert "История трафика" in page.text
    assert "Недостаточно данных для графика" in page.text
    assert "Ошибка опроса" in page.text
    assert 'value="ether1" selected' in page.text
    assert "Ошибки RX / TX" in page.text
    assert "Отброшено RX / TX" in page.text
    assert "<td>0 / 2</td>" in page.text
    assert "<td>0 / 1</td>" in page.text
    assert "Широковещание RX / TX" not in page.text
    response = client.get(
        "/api/v1/network/diagnostics/interfaces?source=mikrotik-main&interface=ether1", headers=headers,
    )
    assert response.status_code == 200
    assert response.json()["data"]["diagnostics"]["selected"]["key"] == "ether1"


def test_network_diagnostics_api_and_ui_share_route_lookup(tmp_path, monkeypatch):
    client, headers = make_client(tmp_path, monkeypatch)
    from app import network_checks

    monkeypatch.setattr(network_checks, "lookup_linux_route", lambda ip: {
        "status": "route_found", "result": {"dev": "eth0", "prefsrc": "192.0.2.1"},
    })
    endpoint = "/api/v1/network/diagnostics/checks"
    assert client.get(endpoint).status_code == 401
    assert "linux_route" in [entry["check"] for entry in client.get(endpoint, headers=headers).json()["data"]["checks"]]
    result = client.post(endpoint, headers=headers, json={"check": "linux_route", "destination": "192.0.2.20"})
    assert result.status_code == 200
    assert result.json()["data"]["result"]["dev"] == "eth0"
    runs = client.get("/api/v1/network/diagnostics/runs", headers=headers).json()["data"]["runs"]
    assert [(run["check"], run["status"], run["target"]) for run in runs] == [
        ("linux_route", "route_found", "192.0.2.20"),
    ]
    bad = client.post(endpoint, headers=headers, json={"check": "linux_route", "destination": "--help"})
    assert bad.status_code == 422
    assert client.post(endpoint, headers=headers, json={"check": "shell", "command": "id"}).status_code == 422
    csrf = login(client)
    response = client.post("/network/diagnostics/checks", data={
        "csrf_token": csrf, "operation_key": "test-intent", "check": "linux_route", "destination": "192.0.2.20",
    })
    assert response.status_code == 200
    assert "Маршрут найден" in response.text and "eth0" in response.text
    assert "Последние запуски" in response.text


def test_network_checks_read_scope_does_not_grant_execution(tmp_path, monkeypatch):
    client, headers = make_client(tmp_path, monkeypatch)
    from app.config import reset_settings_cache

    monkeypatch.setenv("OPENVPN_WEB_API_PERMISSIONS", "network:read")
    reset_settings_cache()
    endpoint = "/api/v1/network/diagnostics/checks"
    assert client.get(endpoint, headers=headers).status_code == 200
    assert client.post(endpoint, headers=headers, json={
        "check": "linux_route", "destination": "192.0.2.20",
    }).status_code == 403


def test_route_availability_catalog_execution_and_history(tmp_path, monkeypatch):
    client, headers = make_client(tmp_path, monkeypatch)
    from app import network_checks, network_probe_profiles, network_route_matrix

    profile_id = "central-wan"
    profiles = network_probe_profiles.ProbeProfiles.model_validate({"routes": {profile_id: {
        "label": "Central WAN comparison", "scheduled": True, "probes": [
            {"id": "rtk", "expected_path": "RTK", "target": "192.0.2.20", "protocol": "icmp",
             "router_source": "mikrotik-main", "interface": "ether9", "observe_neighbor": True},
        ],
    }}})
    monkeypatch.setattr(network_probe_profiles, "load_probe_profiles", lambda: profiles)
    monkeypatch.setattr(network_checks, "load_probe_profiles", lambda: profiles)
    calls = []

    def probe(args, **kwargs):
        calls.append(args)
        return {"probe": {"status": "reachable", "evidence": {
            "packet_loss_pct": 0, "gateway_arp": {"status": "observed", "state": "reachable", "resolved": True},
            "rtt_variation": {"mean_abs_delta_ms": 0.5, "pairs": 2},
        }}}

    monkeypatch.setattr(network_route_matrix, "run_netctl", probe)
    base = "/api/v1/network/diagnostics"
    endpoint = base + "/checks"
    catalog = client.get(endpoint, headers=headers).json()["data"]
    assert catalog["profiles"]["routes"][0]["id"] == profile_id
    assert catalog["profiles"]["routes"][0]["scheduled"] is True
    payload = {"check": "route_availability", "profile": profile_id}
    assert client.post(endpoint, headers=headers, json={**payload, "target": "192.0.2.30"}).status_code == 422
    data = client.post(endpoint, headers=headers, json=payload).json()["data"]
    assert data["status"] == "reachable"
    assert data["result"]["probes"][0]["path_status"] == "unconfirmed"
    assert data["result"]["probes"][0]["evidence"]["gateway_arp"]["resolved"] is True
    assert client.post(endpoint, headers=headers, json=payload).json()["data"]["status"] == "rate_limited"
    history = client.get(base + "/route-runs", headers=headers, params={"profile": profile_id}).json()["data"]["runs"]
    assert len(history) == 1 and history[0]["result"]["probes"] == data["result"]["probes"]
    from app import main

    scheduled = {**data, "trigger": "scheduled", "result": {**data["result"], "probe_changes": [
        {"probe_id": "rtk", "from": "unreachable", "to": "reachable", "checked_at": data["checked_at"]},
    ]}}
    monkeypatch.setattr(main, "list_route_runs", lambda *args, **kwargs: [scheduled])
    csrf = login(client)
    response = client.post("/network/diagnostics/checks", data={"csrf_token": csrf, **payload})
    assert response.status_code == 200
    assert "Путь не подтверждён" not in response.text and "mikrotik-main" in response.text
    assert "ARP шлюза · reachable" in response.text
    assert "Изменение RTT 0.5 мс · пар 2" in response.text
    assert "Изменились статусы проб" in response.text and "→ Цель ответила" in response.text
    assert [call[:-1] for call in calls] == [["path", "probe", "--profile=central-wan", "--probe=rtk"]] * 2


def test_route_history_filters_by_profile_and_time_in_api_and_ui(tmp_path, monkeypatch):
    from app.db import get_sessionmaker
    from app.network_route_history import persist_route_run

    client, headers = make_client(tmp_path, monkeypatch)
    since = datetime.now(timezone.utc).replace(second=0, microsecond=0) - timedelta(minutes=30)
    until = since + timedelta(minutes=5)
    with get_sessionmaker()() as db:
        for owner, profile, checked, label in [
            ("schedule:", "central-wan", since - timedelta(minutes=1), "before-window"),
            ("schedule:", "central-wan", since, "in-window"),
            ("schedule:", "central-wan", until, "after-window"),
            ("schedule:", "archive-ipsec", since, "different-profile"),
            ("user:another", "central-wan", since, "private-run"),
        ]:
            persist_route_run(db, owner=owner, result={
                "check": "route_availability", "target": profile, "checked_at": checked.isoformat(),
                "status": "unreachable", "result": {"label": label, "probes": []},
            })
        db.commit()

    api = "/api/v1/network/diagnostics/route-runs"
    params = {
        "profile": "central-wan",
        "since": since.astimezone(timezone(timedelta(hours=5))).isoformat(),
        "until": until.isoformat(),
    }
    response = client.get(api, headers=headers, params=params)
    assert response.status_code == 200
    assert [row["result"]["label"] for row in response.json()["data"]["runs"]] == ["in-window"]
    assert client.get(api, headers=headers, params={"since": since.strftime("%Y-%m-%dT%H:%M")}).status_code == 422
    assert client.get(api, headers=headers, params={"since": until.isoformat(), "until": since.isoformat()}).status_code == 422

    login(client)
    ui = "/network/diagnostics"
    params.update(since=since.strftime("%Y-%m-%dT%H:%M"), until=until.strftime("%Y-%m-%dT%H:%M"))
    page = client.get(ui, params=params)
    assert page.status_code == 200
    assert "in-window" in page.text and "Интервал UTC" in page.text
    assert all(label not in page.text for label in ("before-window", "after-window", "different-profile", "private-run"))
    empty = client.get(ui, params={**params, "profile": "missing-profile"})
    assert empty.status_code == 200 and "За выбранный интервал запусков нет" in empty.text
    assert client.get(ui, params={**params, "until": params["since"]}).status_code == 422


def test_route_history_marks_changed_configuration(tmp_path, monkeypatch):
    client, headers = make_client(tmp_path, monkeypatch)
    from app import api, main
    from app.db import get_sessionmaker
    from app.network_route_history import persist_route_run

    catalog = {
        "routes": [{"id": "wan", "label": "WAN", "probes": [{"id": "gateway", "config_digest": "a" * 64}]}],
        "throughput": [], "https_speed": [], "capture": [],
    }
    monkeypatch.setattr(main, "probe_catalog", lambda: catalog)
    monkeypatch.setattr(api, "probe_catalog", lambda: catalog)
    with get_sessionmaker()() as db:
        for i, digest in enumerate(("a" * 64, "b" * 64, None)):
            probe = {
                "id": "gateway", "origin": "router", "target": "192.0.2.1", "protocol": "icmp",
                "status": "reachable", "expected_path": "WAN", "evidence": {},
            }
            if digest:
                probe["config_digest"] = digest
            persist_route_run(db, owner="schedule:", result={
                "check": "route_availability", "target": "wan", "status": "reachable",
                "checked_at": (datetime.now(timezone.utc) - timedelta(minutes=i)).isoformat(),
                "result": {"label": f"Запуск {i}", "probes": [probe]},
            })
        db.commit()
    response = client.get("/api/v1/network/diagnostics/route-runs", headers=headers, params={"profile": "wan"})
    assert response.status_code == 200
    assert [run["configuration_status"] for run in response.json()["data"]["runs"]] == [
        "current", "changed", "unconfirmed",
    ]
    login(client)
    page = client.get("/network/diagnostics", params={"profile": "wan"})
    assert page.status_code == 200
    summaries = {line.strip() for line in page.text.splitlines() if "<summary>Запуск" in line}
    assert any("Запуск 1" in line and "Конфигурация изменилась" in line for line in summaries)
    assert any("Запуск 2" in line and "Конфигурация не подтверждена" in line for line in summaries)
    assert any("Запуск 0" in line and "Конфигурация" not in line for line in summaries)


def test_network_active_check_uses_shared_throttle(tmp_path, monkeypatch):
    client, headers = make_client(tmp_path, monkeypatch)
    from app import network_checks

    targets = []

    def trace(target):
        targets.append(str(target))
        return {"status": "reached", "result": {}}

    monkeypatch.setattr(network_checks, "trace_linux_route", trace)
    endpoint = "/api/v1/network/diagnostics/checks"
    payload = {"check": "trace_route", "destination": "192.0.2.20"}
    assert client.post(endpoint, headers=headers, json=payload).json()["data"]["status"] == "reached"
    limited = client.post(endpoint, headers=headers, json=payload).json()["data"]
    assert limited["status"] == "rate_limited"
    assert 1 <= limited["result"]["retry_after_seconds"] <= 300
    csrf = login(client)
    form = {**payload, "csrf_token": csrf}
    assert client.post("/network/diagnostics/checks", data=form).status_code == 200
    page = client.post("/network/diagnostics/checks", data=form)
    assert "Повтор доступен через" in page.text
    assert targets == ["192.0.2.20", "192.0.2.20"]


@pytest.mark.parametrize("reason,route_status,label,route_label", [
    ("kernel_gateway_mismatch", "route_found", "Ожидаемый шлюз не выбран", "Выбор ядра eth0.20 · 192.0.2.2"),
    ("icmp_no_echo_reply", "route_found", "Цель не ответила на ICMP", "Выбор ядра eth0.20"),
    ("origin_ssh_failed", "not_run", "Не удалось подключиться к пробнику по SSH", "Выбор ядра не проверялся"),
    ("origin_timeout", "not_run", "Истекло время ожидания ответа пробника", "Выбор ядра не проверялся"),
    ("connection_unreachable", "no_route", "Сеть или узел недоступны", "Ядро не нашло маршрут"),
])
def test_route_availability_exposes_linux_neighbor_in_api_and_ui(
    tmp_path, monkeypatch, reason, route_status, label, route_label,
):
    client, headers = make_client(tmp_path, monkeypatch)
    from app import network_checks, network_probe_profiles, network_route_matrix

    profiles = network_probe_profiles.ProbeProfiles.model_validate({
        "routes": {"lan": {"label": "LAN", "probes": [{
            "id": "gateway", "expected_path": "VLAN20", "target": "192.0.2.1",
            "protocol": "icmp",
            **({"expected_kernel_gateway": "192.0.2.1"} if reason == "kernel_gateway_mismatch" else {}),
        }]}},
    })
    neighbor = {"address": "192.0.2.1", "interface": "eth0.20", "state": "failed"}
    monkeypatch.setattr(network_probe_profiles, "load_probe_profiles", lambda: profiles)
    monkeypatch.setattr(network_checks, "load_probe_profiles", lambda: profiles)
    evidence = {"reason": reason}
    if route_status == "route_found":
        evidence["linux_neighbor"] = neighbor
    monkeypatch.setattr(network_route_matrix, "probe_local_route", lambda **kwargs: {
        "status": "unavailable" if reason in {"origin_ssh_failed", "kernel_gateway_mismatch"} else "timeout",
        "evidence": evidence,
        "kernel_route": {"status": route_status, "result": {
            "dev": "eth0.20", "gateway": "192.0.2.2",
        } if route_status == "route_found" else {}},
    })

    payload = {"check": "route_availability", "profile": "lan"}
    endpoint = "/api/v1/network/diagnostics/checks"
    data = client.post(endpoint, headers=headers, json=payload).json()["data"]
    assert data["result"]["probes"][0]["evidence"] == evidence
    csrf = login(client)
    page = client.post("/network/diagnostics/checks", data={"csrf_token": csrf, **payload})
    assert page.status_code == 200
    assert label in page.text and route_label in page.text
    assert "Путь не подтверждён" not in page.text
    assert "Первый переход не подтверждён" not in page.text
    if reason == "kernel_gateway_mismatch":
        assert data["result"]["probes"][0]["expected_kernel_gateway"] == "192.0.2.1"
        assert "Ожидаемый шлюз 192.0.2.1" in page.text
    if route_status == "route_found":
        assert "ARP 192.0.2.1 · разрешение не удалось" in page.text


@pytest.mark.parametrize("central_status, passed_probes", [("unreachable", 0), ("reachable", 1)])
def test_route_ipsec_phase_and_unavailable_reason_in_history_and_ui(
    tmp_path, monkeypatch, central_status, passed_probes,
):
    client, headers = make_client(tmp_path, monkeypatch)
    from app import network_checks, network_probe_profiles, network_route_matrix

    profiles = network_probe_profiles.ProbeProfiles.model_validate({"routes": {
        "archive": {"label": "Archive", "probes": [
            {"id": "central", "expected_path": "IPsec", "target": "192.0.2.1", "protocol": "icmp",
             "router_source": "central-router", "source_address": "198.51.100.1", "ipsec": True},
            {"id": "archive", "expected_path": "IPsec", "target": "198.51.100.1", "protocol": "icmp",
             "router_source": "archive-router", "source_address": "192.0.2.1", "ipsec": True},
        ]},
    }})
    monkeypatch.setattr(network_checks, "load_probe_profiles", lambda: profiles)
    monkeypatch.setattr(network_probe_profiles, "load_probe_profiles", lambda: profiles)

    def netctl(args, **kwargs):
        if args[:2] == ["path", "probe"]:
            return {"probe": {"status": central_status if "--probe=central" in args else "timeout"}}
        if args[-1] == "--source=archive-router":
            return {"sources": [{"source": "archive-router", "status": "error"}]}
        return {"sources": [{"source": "central-router", "status": "warn", "policies": [{
            "src_address": "198.51.100.0/24", "dst_address": "192.0.2.0/24", "action": "encrypt",
            "established": False, "ph2_count": 0, "local_sa_address_status": "missing",
        }]}]}

    monkeypatch.setattr(network_route_matrix, "run_netctl", netctl)
    payload = {"check": "route_availability", "profile": "archive"}
    endpoint = "/api/v1/network/diagnostics"
    run = client.post(f"{endpoint}/checks", headers=headers, json=payload)
    assert run.status_code == 200
    assert run.json()["data"]["status"] == "partial"
    history = client.get(f"{endpoint}/route-runs", headers=headers, params={"profile": "archive"})
    stored_run = history.json()["data"]["runs"][0]
    central, archive = stored_run["result"]["probes"]
    assert central["ipsec"]["phase2_count"] == 0
    assert central["ipsec"]["local_sa_address_status"] == "missing"
    assert archive["ipsec"]["reason"] == "source_error"

    from app import main

    monkeypatch.setattr(main, "list_route_runs", lambda *args, **kwargs: [{**stored_run, "trigger": "scheduled"}])
    csrf = login(client)
    page = client.post("/network/diagnostics/checks", data={"csrf_token": csrf, **payload})
    assert page.status_code == 200
    label = f"Прошли {passed_probes} из 2 проб"
    assert f'id="network-check-result">{label}</h2>' in page.text
    assert f"<summary>Archive · {label} · По расписанию" in page.text
    assert "IPsec не активен" in page.text and "Phase 2: 0" in page.text
    assert "Локальный IPv4 для SA не назначен" in page.text
    assert "источник вернул ошибку опроса" in page.text


@pytest.mark.parametrize("observation, expected_wan, status, wan_label", [
    ({"status": "confirmed", "nat_interface": "wan1"}, "wan1", "measured", "wan1"),
    ({"status": "confirmed", "nat_interface": "wan2"}, "wan1", "wan_mismatch",
     "Ожидался wan1 · наблюдался wan2"),
    ({"status": "unconfirmed", "reason": "no_unique_connection"}, "wan1", "wan_unconfirmed",
     "WAN не подтверждён · соединение не найдено или неоднозначно"),
    ({"status": "unconfirmed", "reason": "no_unique_connection"},
     None, "measured", "WAN не подтверждён · соединение не найдено или неоднозначно"),
    ({"status": "unavailable"}, None, "measured", "Нет данных о WAN"),
])
def test_https_speed_uses_profile_and_records_result_in_api_and_ui(
    tmp_path, monkeypatch, observation, expected_wan, status, wan_label,
):
    client, headers = make_client(tmp_path, monkeypatch)
    from app import network_checks, network_probe_profiles

    peer = "162.159.140.220"
    profiles = network_probe_profiles.ProbeProfiles.model_validate({
        "https_speed": {"internet": {
            "label": "Internet", "peer": peer,
            "download_bytes": 1_000_000, "upload_bytes": 500_000,
            "router_source": "mikrotik-main", "source_address": "192.0.2.10",
            "expected_wan_interface": expected_wan,
        }},
    })
    monkeypatch.setattr(network_probe_profiles, "load_probe_profiles", lambda: profiles)
    monkeypatch.setattr(network_checks, "load_probe_profiles", lambda: profiles)
    monkeypatch.setattr(network_checks, "lookup_linux_route", lambda *args, **kwargs: {
        "status": "route_found", "result": {"dev": "eth0", "gateway": "192.0.2.1"},
    })
    calls = []

    def measure(address, direction, size):
        calls.append((address, direction, size))
        return {"status": "measured", "result": {
            "mbps": 8.0, "duration_seconds": 1.0, "transferred_bytes": size,
            "source_address": "192.0.2.10", "source_port": 42013,
        }}

    monkeypatch.setattr(network_checks, "run_https_speed", measure)
    def observe(args, **kwargs):
        assert args[:4] == ["path", "https-egress", "--profile=internet", "--source-port=42013"]
        assert args[4] == f"--expected-config={profiles.https_speed['internet'].config_digest()}"
        return {"egress": observation}

    monkeypatch.setattr(network_checks, "run_netctl", observe)
    base = "/api/v1/network/diagnostics"
    endpoint = base + "/checks"
    payload = {"check": "https_speed", "profile": "internet", "direction": "receive"}
    catalog = client.get(endpoint, headers=headers).json()["data"]["profiles"]
    assert catalog["https_speed"][0]["id"] == "internet"
    assert client.post(endpoint, headers=headers, json={**payload, "url": "https://example.org"}).status_code == 422
    result = client.post(endpoint, headers=headers, json=payload).json()["data"]
    assert result["status"] == status
    assert result["result"]["kernel_route"]["result"]["dev"] == "eth0"
    assert result["result"]["wan_observation"] == {
        "source": "mikrotik-main", **observation,
        **({"expected_interface": expected_wan} if expected_wan else {}),
    }
    assert client.post(endpoint, headers=headers, json=payload).json()["data"]["status"] == "rate_limited"
    runs = client.get(base + "/runs", headers=headers).json()["data"]["runs"]
    measured = next(row for row in runs if row["status"] == status)
    assert measured["target"] == "internet · receive"
    assert measured["result"]["mbps"] == 8.0
    assert measured["result"]["wan_observation"] == result["result"]["wan_observation"]
    csrf = login(client)
    page = client.post("/network/diagnostics/checks", data={
        "csrf_token": csrf, **payload, "direction": "send",
    })
    assert page.status_code == 200
    assert "Запустить HTTPS-замер" in page.text and "8.00 Мбит/с" in page.text
    assert "Интерфейс по адресу NAT" in page.text and wan_label in page.text
    history_page = client.get("/network/diagnostics")
    assert history_page.status_code == 200 and "8.00 Мбит/с" in history_page.text
    assert wan_label in history_page.text
    assert calls == [(peer, "receive", 1_000_000), (peer, "send", 500_000)]


@pytest.mark.parametrize("gateway_status", ["unreachable", "reachable"])
def test_https_speed_waits_for_configured_wan_gateway(tmp_path, monkeypatch, gateway_status):
    client, headers = make_client(tmp_path, monkeypatch)
    from app import network_checks, network_probe_profiles

    profiles = network_probe_profiles.ProbeProfiles.model_validate({
        "routes": {"wan": {"label": "WAN", "probes": [{
            "id": "gateway", "expected_path": "WAN 2", "protocol": "icmp", "target": "192.0.2.1",
            "router_source": "router", "source_address": "192.0.2.2", "interface": "wan2",
            "observe_neighbor": True,
        }]}},
        "https_speed": {"wan2": {
            "label": "WAN 2", "peer": "162.159.140.220", "download_bytes": 100_000,
            "upload_bytes": 100_000, "router_source": "router", "source_address": "192.0.2.10",
            "expected_wan_interface": "wan2", "gateway_check": {"profile": "wan", "probe": "gateway"},
        }},
    })
    monkeypatch.setattr(network_checks, "load_probe_profiles", lambda: profiles)
    monkeypatch.setattr(network_checks, "lookup_linux_route", lambda *a, **kw: {"status": "route_found", "result": {}})
    calls = []

    def netctl(args, **kwargs):
        if args[1] == "probe":
            assert args[2:4] == ["--profile=wan", "--probe=gateway"]
            return {"probe": {
                "status": gateway_status, "reason": "no_icmp_reply",
                "evidence": {"gateway_source": {"status": "missing", "dhcp": "searching"}},
            }}
        return {"egress": {"status": "confirmed", "nat_interface": "wan1"}}

    def measure(*args):
        calls.append(args)
        return {"status": "measured", "result": {
            "mbps": 8.0, "duration_seconds": 0.1, "transferred_bytes": 100_000,
            "source_address": "192.0.2.10", "source_port": 42013,
        }}

    monkeypatch.setattr(network_checks, "run_netctl", netctl)
    monkeypatch.setattr(network_checks, "run_https_speed", measure)
    payload = {"check": "https_speed", "profile": "wan2", "direction": "receive"}
    base = "/api/v1/network/diagnostics"
    row = client.post(f"{base}/checks", headers=headers, json=payload).json()["data"]
    assert row["status"] == ("wan_mismatch" if gateway_status == "reachable" else "wan_gateway_unavailable")
    assert row["result"]["gateway_check"]["status"] == gateway_status
    assert len(calls) == int(gateway_status == "reachable")
    history = client.get(f"{base}/runs", headers=headers).json()["data"]["runs"][0]
    assert history["result"]["gateway_check"] == row["result"]["gateway_check"]
    if gateway_status == "unreachable":
        assert "mbps" not in history["result"]
        csrf = login(client)
        page = client.post("/network/diagnostics/checks", data={"csrf_token": csrf, **payload})
        assert "Шлюз WAN не подтвердил доступность" in page.text
        assert "DHCP searching" in page.text
        assert calls == []


def test_network_probe_catalog_run_and_download_permissions(tmp_path, monkeypatch):
    client, headers = make_client(tmp_path, monkeypatch)
    from app import network_capture_store, network_checks, network_probe_profiles
    from app.config import reset_settings_cache

    profiles = network_probe_profiles.ProbeProfiles.model_validate({
        "throughput": {"lan": {"label": "LAN test", "peer": "192.0.2.20", "port": 5201,
                              "duration_seconds": 4, "bitrate_mbps": 5}},
        "capture": {"lan": {"label": "LAN PCAP", "peer": "192.0.2.20", "port": 5201, "interface": "ens18",
                           "protocol": "tcp", "duration_seconds": 20, "max_packets": 100, "max_kib": 128}},
    })
    monkeypatch.setattr(network_probe_profiles, "load_probe_profiles", lambda: profiles)
    monkeypatch.setattr(network_checks, "load_probe_profiles", lambda: profiles)
    monkeypatch.setattr(network_checks, "run_throughput", lambda peer, port, direction, **limits: {
        "status": "ok", "result": {"sender_mbps": 5.0, "receiver_mbps": 4.8, "retransmits": 0},
    })
    directory = tmp_path / "captures"
    directory.mkdir(mode=0o700)
    monkeypatch.setattr(network_capture_store, "CAPTURE_DIRECTORY", directory)
    pcap = b"\xd4\xc3\xb2\xa1" + bytes(20)

    def capture(output, **kwargs):
        output.write_bytes(pcap)
        return {"status": "ok", "packets": 0, "size_bytes": len(pcap)}

    monkeypatch.setattr(network_capture_store, "capture_packets", capture)
    base = "/api/v1/network/diagnostics"
    catalog = client.get(base + "/checks", headers=headers).json()["data"]
    assert catalog["profiles"]["throughput"][0]["id"] == "lan"
    bad = client.post(base + "/checks", headers=headers, json={
        "check": "iperf3", "profile": "lan", "peer": "192.0.2.99",
    })
    assert bad.status_code == 422
    measured = client.post(base + "/checks", headers=headers, json={
        "check": "iperf3", "profile": "lan", "direction": "receive",
    }).json()["data"]
    assert measured["status"] == "measured" and measured["result"]["receiver_mbps"] == 4.8
    result = client.post(base + "/checks", headers=headers, json={
        "check": "pcap_capture", "profile": "lan",
    }).json()["data"]
    assert result["status"] == "empty_capture"
    assert result["result"]["filter"] == {
        "interface": "ens18", "peer": "192.0.2.20", "port": 5201, "protocol": "tcp",
    }
    capture_id = result["result"]["capture_id"]
    listed = client.get(base + "/captures", headers=headers).json()["data"]["captures"]
    assert next(row for row in listed if row["capture_id"] == capture_id)["filter"] == result["result"]["filter"]
    service_path = base + "/captures/" + capture_id
    download = client.get(service_path, headers=headers)
    assert download.content == pcap and download.headers["content-type"] == "application/vnd.tcpdump.pcap"
    csrf = login(client)
    assert client.get("/network/diagnostics/captures/" + capture_id).status_code == 404
    panel = client.post("/network/diagnostics/checks", data={
        "csrf_token": csrf, "check": "pcap_capture", "profile": "lan",
    })
    assert "ens18 · 192.0.2.20 · TCP/5201" in panel.text
    assert "ens18 · 192.0.2.20 · TCP/5201" in client.get("/network/diagnostics").text
    monkeypatch.setenv("OPENVPN_WEB_API_PERMISSIONS", "network:read")
    reset_settings_cache()
    assert client.get(service_path, headers=headers).status_code == 403


@pytest.mark.parametrize("wan", [False, True])
def test_iperf_history_keeps_measurement_and_route(tmp_path, monkeypatch, wan):
    client, headers = make_client(tmp_path, monkeypatch)
    from app import network_checks, network_probe_profiles

    profiles = network_probe_profiles.ProbeProfiles.model_validate({
        "throughput": {"lan": {"label": "LAN", "peer": "192.0.2.20", "port": 5201,
                               "duration_seconds": 4, "bitrate_mbps": 5,
                               "source_address": "192.0.2.10", "bind_interface": "ens18",
                               **({"router_source": "central", "expected_wan_interface": "wan1"} if wan else {})}},
    })
    monkeypatch.setattr(network_checks, "load_probe_profiles", lambda: profiles)
    monkeypatch.setattr(network_checks, "lookup_linux_route", lambda *args, **kwargs: {
        "status": "route_found", "result": {"dev": "ens18", "gateway": "192.0.2.1"},
    })
    measurement = {"sender_mbps": 5.0, "receiver_mbps": 4.8, "retransmits": 0}
    connection = {"source_address": "192.0.2.10", "peer_address": "192.0.2.20",
                  "peer_port": 5201, "source_port": 42013}
    observed = {"status": "confirmed", "nat_interface": "wan2"}
    monkeypatch.setattr(network_checks, "run_netctl", lambda *args, **kwargs: {"egress": observed})
    monkeypatch.setattr(network_checks, "run_throughput", lambda *args, **kwargs: {
        "status": "ok", "result": measurement, "connection": connection,
    })
    payload = {"check": "iperf3", "profile": "lan", "direction": "receive"}
    endpoint = "/api/v1/network/diagnostics"
    measured = client.post(endpoint + "/checks", headers=headers, json=payload).json()["data"]
    history = client.get(endpoint + "/runs", headers=headers).json()["data"]["runs"]
    record = next(row for row in history if row["check"] == "iperf3")
    assert measured["status"] == record["status"] == ("wan_mismatch" if wan else "measured")
    assert record["target"] == measured["target"]
    assert record["result"] == {
        **measurement, "bitrate_mbps": 5, "connection": connection,
        "kernel_route": {"dev": "ens18", "gateway": "192.0.2.1"},
        **({"wan_observation": {"source": "central", "expected_interface": "wan1", **observed}} if wan else {}),
    }

    csrf = login(client)
    assert client.post("/network/diagnostics/checks", data={**payload, "csrf_token": csrf}).status_code == 200
    page = client.get("/network/diagnostics")
    assert "Отправитель / получатель 5.00 / 4.80 Мбит/с" in page.text
    assert "Повторные передачи TCP 0" in page.text
    assert "Выбор ядра ens18 · 192.0.2.1" in page.text
    if wan:
        assert "Ожидался wan1 · наблюдался wan2" in page.text


def test_loop_evidence_shared_by_api_and_panel(tmp_path, monkeypatch):
    client, headers = make_client(tmp_path, monkeypatch)
    from app import network_checks

    def netctl(args, **kwargs):
        assert args == ["switches", "loops", "--source=switch-1"]
        return {"loops": {"status": "no_evidence", "since": "start", "until": "end", "sources": []}}

    monkeypatch.setattr(network_checks, "run_netctl", netctl)
    response = client.get("/api/v1/network/diagnostics/loops?source=switch-1", headers=headers)
    assert response.json()["data"]["status"] == "no_evidence"
    csrf = login(client)
    response = client.post("/network/diagnostics/checks", data={
        "csrf_token": csrf, "check": "loop_check", "source": "switch-1",
    })
    assert response.status_code == 200
    assert "Признаки петли не выявлены" in response.text


@pytest.mark.parametrize("reason,label", [
    ("partial_fdb_poll", "часть записей не разобрана"),
    ("failed_fdb_poll", "сбой среди последних опросов"),
])
def test_loop_panel_shows_port_broadcast_as_context(tmp_path, monkeypatch, reason, label):
    client, headers = make_client(tmp_path, monkeypatch)
    from app import network_checks

    interval = {"port_key": "ether2", "if_index": 2, "since": "2026-11-12T19:00:00Z",
                "until": "2026-11-12T19:05:00Z", "interval_seconds": 300,
                "in_pps": 12.5, "out_pps": 4.0}
    movement = {"mac": "00:11:22:33:44:66", "ports": ["ether3", "ether4"],
                "first_observed_at": interval["since"], "last_observed_at": interval["until"]}
    device = {"source": "switch-1", "status": "mac_flapping",
              "coverage": {"fdb": {"status": "insufficient", "reason": reason},
                           "stp": {"status": "insufficient", "reason": "failed_stp_poll"},
                           "broadcast": {"status": "recent", "sampled_ports": 2, "valid_intervals": 1}},
              "unclassified_mac_movements": [movement],
              "evidence": [{"ports": ["ether1", "ether2"], "vlan_id": 20, "mac": "00:11:22:33:44:55",
                            "broadcast_intervals": [interval]}]}
    monkeypatch.setattr(network_checks, "run_netctl", lambda *args, **kwargs: {
        "loops": {"status": "mac_flapping", "since": "start", "until": "end", "sources": [device]},
    })
    api = client.get("/api/v1/network/diagnostics/loops?source=switch-1", headers=headers)
    report = api.json()["data"]["result"]["sources"][0]
    assert report["coverage"]["fdb"]["reason"] == reason
    assert report["coverage"]["stp"]["reason"] == "failed_stp_poll"
    assert report["evidence"][0]["broadcast_intervals"] == [interval]
    assert report["unclassified_mac_movements"] == [movement]
    csrf = login(client)
    panel = client.post("/network/diagnostics/checks", data={
        "csrf_token": csrf, "check": "loop_check", "source": "switch-1",
    })
    assert panel.status_code == 200
    assert "Широковещание" in panel.text and "12.5 / 4.0 пак/с" in " ".join(panel.text.split())
    assert "Обнаружено повторное перемещение MAC" in panel.text
    assert f"FDB · {label}" in panel.text
    assert "STP · новый опрос не подтвердил сохранённое состояние" in panel.text
    assert "Перемещения MAC без VLAN · 1" in panel.text
    assert "ether3 ↔ ether4" in panel.text


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
    assert "Источники" in ipsec.text
    assert "Двусторонняя проверка" in ipsec.text
    assert "Фильтр" in ipsec.text
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


def test_ipsec_keeps_unreachable_source_in_api_and_panel(tmp_path, monkeypatch):
    client, headers = make_client(tmp_path, monkeypatch)
    login(client)
    params = {"source": "mikrotik-hex"}

    response = client.get("/api/v1/network/ipsec", params=params, headers=headers)
    assert response.status_code == 200
    report = response.json()["data"]
    assert report["summary"]["error"] == 1
    assert report["sources"][0]["errors"] == [{"section": "active_peers", "message": "SSH connection timed out"}]

    page = client.get("/network/ipsec", params=params)
    assert page.status_code == 200
    assert "active_peers: SSH connection timed out" in page.text
    assert "failed with code 1" not in page.text
