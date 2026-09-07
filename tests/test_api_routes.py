import hashlib
import importlib
import json
import os
import sys
from pathlib import Path

from fastapi.testclient import TestClient

import pytest


def snapshot_netctl(tmp_path, monkeypatch, *, count=210):
    """Use the real CLI and SQLite; replace only the privileged process boundary."""
    import app.api as api
    import netctl.cli as cli
    import netctl.host_snapshot as snapshot
    from netctl.db import connect

    db_url = f"sqlite:///{(tmp_path / 'hosts.sqlite').as_posix()}"
    conn = connect(db_url)
    conn.executemany(
        "INSERT INTO network_hosts (ip, hostname, category, status, last_seen_at) VALUES (?, 'fixture', 'unknown', 'seen', '2026-09-07T10:00:00Z')",
        [(f"203.0.113.{number}",) for number in range(1, count + 1)],
    )
    conn.commit()
    if count:
        snapshot.refresh_host_snapshot(conn, now="2026-09-07T10:00:00Z")
        # Supply a published current-state fixture independently of probe configuration.
        conn.execute("UPDATE network_host_current_state SET status='seen', payload_json=json_set(payload_json, '$.status', 'seen')")
        conn.commit()
    conn.close()

    calls = []

    def run(args, **kwargs):
        calls.append(args)
        parsed = cli.build_parser().parse_args(["--db", db_url, *args])
        rc, data = cli.dispatch(parsed)
        assert rc == 0, data
        return data

    def forbidden(*args, **kwargs):
        pytest.fail("snapshot GET must not prepare, project, refresh, or call vpnctl")

    monkeypatch.setattr(api, "run_netctl", run)
    monkeypatch.setattr(api, "call_vpnctl", forbidden)
    monkeypatch.setattr(cli, "prepare_conn", forbidden)
    monkeypatch.setattr(cli, "refresh_host_snapshot", forbidden)
    monkeypatch.setattr(snapshot, "bulk_project_host_availability", forbidden)
    return calls


def test_hosts_list_paginates_snapshot_without_live_commands(tmp_path, monkeypatch):
    client, headers = make_api_client(tmp_path, monkeypatch)
    snapshot_netctl(tmp_path, monkeypatch)
    from netctl.db import connect

    conn = connect(f"sqlite:///{(tmp_path / 'hosts.sqlite').as_posix()}")
    conn.execute("UPDATE network_host_current_state SET payload_json='invalid-json' WHERE CAST(substr(ip, 11) AS INTEGER) <= 100 OR CAST(substr(ip, 11) AS INTEGER) > 200")
    conn.commit()
    conn.close()
    response = client.get("/api/v1/network/hosts?status=current&page=2&limit=100", headers=headers)
    assert response.status_code == 200
    data = response.json()["data"]
    assert data["pagination"] == {"page": 2, "limit": 100, "total": 210, "pages": 3}
    assert len(data["hosts"]) == 100
    assert data["hosts"][0]["ip"] == "203.0.113.101"
    assert data["hosts"][-1]["ip"] == "203.0.113.200"
    assert data["snapshot"]["generated_at"] == "2026-09-07T10:00:00Z"


@pytest.mark.parametrize("count", [0, 2])
def test_hosts_meta_does_not_call_projection_or_vpn_list(tmp_path, monkeypatch, count):
    import app.api as api

    client, headers = make_api_client(tmp_path, monkeypatch)
    calls = snapshot_netctl(tmp_path, monkeypatch, count=count)
    monkeypatch.setattr(api, "call_netctl", lambda *a, **kw: pytest.fail("meta used list/projection helper"))
    response = client.get("/api/v1/network/hosts/meta", headers=headers)
    assert response.status_code == 200
    assert response.json()["data"]["snapshot"]["total_hosts"] == count
    assert response.json()["data"]["snapshot"]["snapshot_id"] == (1 if count else 0)
    assert calls == [["hosts", "snapshot-status"]]
    assert client.get("/api/v1/network/hosts/meta").status_code == 401


def test_hosts_pagination_clamps_and_missing_snapshot_is_empty(tmp_path, monkeypatch):
    client, headers = make_api_client(tmp_path, monkeypatch)
    snapshot_netctl(tmp_path, monkeypatch, count=0)
    for query, limit in [("page=-3&limit=999", 250), ("page=0&limit=0", 1)]:
        response = client.get(f"/api/v1/network/hosts?{query}", headers=headers)
        assert response.status_code == 200
        data = response.json()["data"]
        assert data["hosts"] == []
        assert data["pagination"] == {"page": 1, "limit": limit, "total": 0, "pages": 0}
        assert data["snapshot"]["generated_at"] is None


@pytest.mark.parametrize("query", ["network=invalid", "has_hostname=maybe", "has_mac=maybe", "page=abc", "limit=abc"])
def test_hosts_invalid_filters_rejected_before_subprocess(tmp_path, monkeypatch, query):
    import app.api as api

    client, headers = make_api_client(tmp_path, monkeypatch)
    monkeypatch.setattr(api, "run_netctl", lambda *a, **kw: pytest.fail("invalid filter reached subprocess"))
    assert client.get(f"/api/v1/network/hosts?{query}", headers=headers).status_code == 422


def test_host_filter_arguments_preserve_dash_prefixed_values_in_real_parser():
    from app.api import host_snapshot_args
    from netctl.cli import build_parser

    args = host_snapshot_args({
        "q": "--status=offline", "category": "-printer", "status": "current",
        "source": "-source name", "network": "203.0.113.0/24",
        "has_hostname": "yes", "has_mac": "no", "seen_within": "all",
    }, 2, 5)
    parsed = build_parser().parse_args(args)
    assert parsed.q == "--status=offline"
    assert parsed.category == "-printer"
    assert parsed.source == "-source name"
    assert parsed.status == "current"
    assert parsed.network == "203.0.113.0/24"
    assert parsed.has_hostname == "yes"
    assert parsed.has_mac == "no"
    assert parsed.seen_within == "all"
    assert (parsed.page, parsed.limit) == (2, 5)


def test_hosts_api_accepts_dash_prefixed_query_with_real_snapshot(tmp_path, monkeypatch):
    from netctl.db import connect

    client, headers = make_api_client(tmp_path, monkeypatch)
    snapshot_netctl(tmp_path, monkeypatch, count=2)
    conn = connect(f"sqlite:///{(tmp_path / 'hosts.sqlite').as_posix()}")
    conn.execute("UPDATE network_host_current_state SET search_text='office-printer' WHERE ip='203.0.113.2'")
    conn.commit()
    conn.close()
    response = client.get("/api/v1/network/hosts", params={"q": "-printer"}, headers=headers)
    assert response.status_code == 200
    assert [row["ip"] for row in response.json()["data"]["hosts"]] == ["203.0.113.2"]
    assert response.json()["data"]["pagination"]["total"] == 1


def make_fake_vpnctl(path: Path) -> Path:
    script_path = path.with_suffix(".py") if os.name == "nt" else path
    script_path.write_text(
        """#!/usr/bin/env python3
import json
import os
import sys
from pathlib import Path
args = sys.argv[1:]
cmd = args[1] if args and args[0] == "--json" else args[0]
log_path = os.environ.get("FAKE_VPNCTL_LOG")
if log_path:
    with open(log_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(args, ensure_ascii=False) + "\\n")
Path(sys.argv[-1]).write_text(json.dumps(args), encoding="utf-8") if args[-1].endswith(".argv") else None
if cmd == "status":
    print(json.dumps({"services": {"openvpn": {"active": "active"}, "nat": {"active": "active"}}, "connected": []}))
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
    sub = args[2]
    if sub == "inspect":
        print(json.dumps({"status": "ok", "server_conf": "/etc/openvpn/server/server.conf", "settings": {"status_interval": 10, "status_version": 2, "management_enabled": True, "management_socket": "/run/openvpn/server.sock", "management_client_group": "openvpn-web", "management_log_cache": 300}, "warnings": []}))
    elif sub == "apply":
        print(json.dumps({"status": "ok", "changed": True}))
    elif sub == "restart-openvpn":
        print(json.dumps({"status": "ok", "restart": {"active": "active"}}))
elif cmd == "management":
    sub = args[2]
    if sub == "test":
        print(json.dumps({"status": "ok", "socket": "/run/openvpn/server.sock", "available": True}))
    elif sub == "status":
        print(json.dumps({"status": "ok", "source": "management", "clients": []}))
    elif sub == "kill":
        print(json.dumps({"status": "ok", "client": args[3], "killed": True}))
elif cmd == "profiles":
    print(json.dumps({"profiles": [{"name": "directum", "description": "Directum"}]}))
elif cmd == "list":
    print(json.dumps({"clients": [{"name": "alpha", "profile": "directum", "status": "active", "vpn_ip": "192.168.50.10", "connected": False}]}))
elif cmd == "inspect":
    print(json.dumps({"client": args[2], "registry": {"name": args[2], "status": "active"}, "cert_status": "valid", "connected": None, "files": {}, "ccd": {"raw_lines": []}}))
elif cmd == "disable":
    print(json.dumps({"status": "ok", "client": args[2], "reason": args[-1], "kill_active": {"killed": "--kill-active" in args}}))
elif cmd == "sync":
    print(json.dumps({"status": "ok", "imported_or_updated": 1}))
elif cmd == "generate":
    print(json.dumps({"status": "ok", "client": args[2], "profile": args[3]}))
elif cmd == "preview":
    print(json.dumps({"status": "preview", "client": args[2], "profile": args[3], "ccd_preview": [], "server_routes_preview": []}))
elif cmd == "config-view":
    print(json.dumps({"status": "ok", "client": args[2], "ovpn": {"path": "/tmp/alpha.ovpn", "exists": True, "content": "client\\n"}, "ccd": {"path": "/tmp/ccd/alpha", "exists": True, "content": "push route\\n"}}))
elif cmd == "profile-apply":
    print(json.dumps({"status": "ok", "client": args[2], "profile": args[3], "vpn_ip": args[4] if len(args) > 4 and not args[4].startswith("--") else None}))
elif cmd == "ovpn-update":
    print(json.dumps({"status": "ok", "client": args[2], "backup_path": "/tmp/alpha.ovpn.backup"}))
elif cmd == "networks":
    print(json.dumps({"networks": [{"cidr": "192.168.100.10/32", "tag": "directum", "nat": False}, {"cidr": "10.83.1.0/24", "tag": "vipnet", "nat": True}]}))
elif cmd == "network-templates":
    print(json.dumps({"templates": [{"name": "directum", "cidrs": ["192.168.100.10/32"], "dns": False, "builtin": True}]}))
elif cmd == "client-template-apply":
    print(json.dumps({"status": "ok", "client": args[2], "template": args[3]}))
elif cmd == "client-networks-apply":
    print(json.dumps({"status": "ok", "client": args[2], "networks": ["192.168.100.10/32"]}))
elif cmd == "reconnect-client":
    print(json.dumps({"status": "not_configured", "client": args[2]}))
elif cmd == "connected":
    print(json.dumps({"connected": []}))
elif cmd == "nat-status":
    print(json.dumps({"status": "ok", "mode": "disabled_expected", "legacy_nat_service": {"name": "vipnet-openvpn-nat.service", "active": False, "enabled": False}, "legacy_chain": {"name": "VIPNET_OPENVPN_SNAT", "exists": False}, "warnings": []}))
elif cmd == "validate-network-plan":
    print(json.dumps({"status": "ok", "warnings": [], "errors": [], "addressing": {"openvpn_tunnel_cidr": "192.168.50.0/24"}}))
elif cmd == "site-routes":
    print(json.dumps({"status": "ok", "site_routes": [{"cidr": "192.168.51.0/24"}]}))
elif cmd == "vipnet-nets":
    print(json.dumps({"networks": []}))
elif cmd == "logs":
    print(json.dumps({"services": {}, "operations": [], "journal": []}))
else:
    print(json.dumps({"status": "ok"}))
""",
        encoding="utf-8",
    )
    script_path.chmod(0o755)
    if os.name != "nt":
        return script_path
    wrapper = path.with_suffix(".cmd")
    wrapper.write_text(f'@echo off\r\n"{sys.executable}" "{script_path}" %*\r\n', encoding="utf-8")
    return wrapper


def make_api_client(tmp_path, monkeypatch):
    token = "api-token"
    fake = make_fake_vpnctl(tmp_path / "vpnctl")
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{(tmp_path / 'web.sqlite').as_posix()}")
    monkeypatch.setenv("APP_SECRET_KEY", "test-secret")
    monkeypatch.setenv("ADMIN_USERNAME", "admin")
    monkeypatch.setenv("ADMIN_PASSWORD", "admin-pass")
    monkeypatch.setenv("OPENVPN_WEB_API_TOKEN_HASH", hashlib.sha256(token.encode("utf-8")).hexdigest())
    monkeypatch.setenv("VPNCTL_PATH", str(fake))
    monkeypatch.setenv("VPNCTL_USE_SUDO", "0")
    monkeypatch.setenv("OUT_DIR", str(tmp_path))
    monkeypatch.setenv("SHARE_OUT_DIR", str(tmp_path))
    monkeypatch.setenv("ARCHIVE_DIR", str(tmp_path))
    monkeypatch.setenv("FAKE_VPNCTL_LOG", str(tmp_path / "vpnctl-calls.jsonl"))

    import app.db
    import app.main

    app.db.reset_engine_cache()
    importlib.reload(app.main)
    app.db.init_db()
    return TestClient(app.main.app), {"Authorization": f"Bearer {token}"}


def test_api_rejects_missing_bearer_token(tmp_path, monkeypatch):
    client, _ = make_api_client(tmp_path, monkeypatch)

    response = client.get("/api/v1/status")

    assert response.status_code == 401


def test_api_status_and_clients_use_vpnctl(tmp_path, monkeypatch):
    client, headers = make_api_client(tmp_path, monkeypatch)

    status = client.get("/api/v1/status", headers=headers)
    clients = client.get("/api/v1/clients", headers=headers)

    assert status.status_code == 200
    assert status.json()["data"]["services"]["openvpn"]["active"] == "active"
    assert clients.status_code == 200
    assert clients.json()["data"]["clients"][0]["name"] == "alpha"


def test_runtime_health_api_returns_error_shaped_health_as_http_200(tmp_path, monkeypatch):
    client, headers = make_api_client(tmp_path, monkeypatch)

    response = client.get("/api/v1/runtime-health", headers=headers)

    assert response.status_code == 200
    assert response.json()["data"]["overall"] == "error"
    assert response.json()["data"]["errors"] == ["VPN_POLICY_NAT chain or hook is missing"]
    calls = [
        json.loads(line)
        for line in (tmp_path / "vpnctl-calls.jsonl").read_text(encoding="utf-8").splitlines()
        if line
    ]
    assert ["--json", "runtime-health"] in calls
    assert all("--strict" not in call for call in calls)


def test_api_network_add_without_comment_omits_comment_flag(tmp_path, monkeypatch):
    client, headers = make_api_client(tmp_path, monkeypatch)

    empty_comment_response = client.post(
        "/api/v1/networks/add",
        headers=headers,
        json={"cidr": "192.168.100.12", "tag": "default", "comment": "", "nat": False, "restart_nat": False},
    )
    nonempty_comment_response = client.post(
        "/api/v1/networks/add",
        headers=headers,
        json={"cidr": "192.168.100.13", "tag": "default", "comment": "branch office", "nat": False, "restart_nat": False},
    )

    assert empty_comment_response.status_code == 200
    assert nonempty_comment_response.status_code == 200
    calls = [
        json.loads(line)
        for line in (tmp_path / "vpnctl-calls.jsonl").read_text(encoding="utf-8").splitlines()
        if line
    ]
    add_calls = [call for call in calls if call[1:3] == ["networks", "add"]]
    assert "192.168.100.12" in add_calls[0]
    assert "--comment" not in add_calls[0]
    assert add_calls[1][add_calls[1].index("--comment") + 1] == "branch office"


def test_api_disable_requires_confirm_client_and_reason(tmp_path, monkeypatch):
    client, headers = make_api_client(tmp_path, monkeypatch)

    missing_confirm = client.post("/api/v1/clients/alpha/disable", headers=headers, json={"reason": "lost laptop"})
    ok = client.post(
        "/api/v1/clients/alpha/disable",
        headers=headers,
        json={"confirm_client": "alpha", "reason": "lost laptop"},
    )

    assert missing_confirm.status_code == 400
    assert ok.status_code == 200
    assert ok.json()["data"]["status"] == "ok"
    assert ok.json()["data"]["client"] == "alpha"
    calls = [
        json.loads(line)
        for line in (tmp_path / "vpnctl-calls.jsonl").read_text(encoding="utf-8").splitlines()
        if line
    ]
    assert any(call[1:4] == ["disable", "alpha", "--reason"] and "--kill-active" in call for call in calls)


def test_api_client_safe_network_edit_routes_require_confirm_and_reason(tmp_path, monkeypatch):
    client, headers = make_api_client(tmp_path, monkeypatch)

    config = client.get("/api/v1/clients/alpha/config", headers=headers)
    networks = client.get("/api/v1/networks", headers=headers)
    templates = client.get("/api/v1/network-templates", headers=headers)
    manual_ccd = client.post(
        "/api/v1/clients/alpha/ccd",
        headers=headers,
        json={"confirm_client": "wrong", "reason": "route change", "content": "push route"},
    )
    bad_confirm = client.post(
        "/api/v1/clients/alpha/networks",
        headers=headers,
        json={"confirm_client": "wrong", "reason": "route change", "cidrs": ["192.168.100.10/32"]},
    )
    selected = client.post(
        "/api/v1/clients/alpha/networks",
        headers=headers,
        json={"confirm_client": "alpha", "reason": "route change", "cidrs": ["192.168.100.10/32"], "dns": False},
    )
    profile = client.post(
        "/api/v1/clients/alpha/network-template",
        headers=headers,
        json={"confirm_client": "alpha", "reason": "template", "template": "directum", "vpn_ip": "192.168.50.55"},
    )
    ovpn = client.post(
        "/api/v1/clients/alpha/ovpn",
        headers=headers,
        json={"confirm_client": "alpha", "reason": "endpoint", "content": "client\n"},
    )
    reconnect = client.post(
        "/api/v1/clients/alpha/reconnect",
        headers=headers,
        json={"confirm_client": "alpha", "reason": "routes changed"},
    )
    kill = client.post(
        "/api/v1/clients/alpha/kill-session",
        headers=headers,
        json={"confirm_client": "alpha", "reason": "drop active session"},
    )

    assert config.status_code == 200
    assert config.json()["data"]["ovpn"]["content"] == "client\n"
    assert networks.status_code == 200
    assert templates.status_code == 200
    assert manual_ccd.status_code == 404
    assert bad_confirm.status_code == 400
    assert selected.status_code == 200
    assert profile.status_code == 200
    assert profile.json()["data"]["template"] == "directum"
    assert ovpn.status_code == 200
    assert reconnect.status_code == 200
    assert reconnect.json()["data"]["status"] == "not_configured"
    assert kill.status_code == 200
    assert kill.json()["data"]["killed"] is True
    calls = [
        json.loads(line)
        for line in (tmp_path / "vpnctl-calls.jsonl").read_text(encoding="utf-8").splitlines()
        if line
    ]
    reconnect_calls = [call for call in calls if call[1:3] == ["reconnect-client", "alpha"]]
    assert len(reconnect_calls) >= 3


def test_api_preview_and_generate_pass_router_network_fields(tmp_path, monkeypatch):
    client, headers = make_api_client(tmp_path, monkeypatch)

    preview = client.post(
        "/api/v1/clients/router_site_001/preview",
        headers=headers,
        json={
            "profile": "router_vipnet",
            "vpn_ip": "192.168.50.201",
            "client_type": "router_site_to_site",
            "remote_lan_cidr": "192.168.51.0/24",
            "create_server_route": True,
        },
    )
    generated = client.post(
        "/api/v1/clients/router_site_001/generate",
        headers=headers,
        json={
            "profile": "router_vipnet",
            "vpn_ip": "192.168.50.201",
            "client_type": "router_site_to_site",
            "remote_lan_cidr": "192.168.51.0/24",
            "create_server_route": True,
            "comment": "branch router",
        },
    )

    assert preview.status_code == 200
    assert generated.status_code == 200
    calls = [
        json.loads(line)
        for line in (tmp_path / "vpnctl-calls.jsonl").read_text(encoding="utf-8").splitlines()
        if line
    ]
    preview_call = next(call for call in calls if call[1:4] == ["preview", "router_site_001", "router_vipnet"])
    generate_call = next(call for call in calls if call[1:4] == ["generate", "router_site_001", "router_vipnet"])
    for call in (preview_call, generate_call):
        assert "--client-type" in call
        assert "router_site_to_site" in call
        assert "--remote-lan" in call
        assert "192.168.51.0/24" in call
        assert "--create-server-route" in call


def test_api_openvpn_addressing_validation_and_site_routes(tmp_path, monkeypatch):
    client, headers = make_api_client(tmp_path, monkeypatch)

    addressing = client.get("/api/v1/openvpn/addressing", headers=headers)
    validation = client.post("/api/v1/openvpn/validate-network-plan", headers=headers)
    site_routes = client.get("/api/v1/site-routes", headers=headers)
    instructions = client.get("/api/v1/clients/router_site_001/router-instructions", headers=headers)

    assert addressing.status_code == 200
    assert addressing.json()["data"]["openvpn_tunnel_cidr"] == "192.168.50.0/24"
    assert validation.status_code == 200
    assert site_routes.status_code == 200
    assert instructions.status_code == 200


def test_api_has_no_client_delete_route(tmp_path, monkeypatch):
    client, headers = make_api_client(tmp_path, monkeypatch)

    response = client.post(
        "/api/v1/clients/alpha/delete",
        headers=headers,
        json={"confirm_client": "alpha", "reason": "not allowed"},
    )

    assert response.status_code == 404


def test_api_openvpn_management_settings(tmp_path, monkeypatch):
    client, headers = make_api_client(tmp_path, monkeypatch)

    config = client.get("/api/v1/openvpn/server-config", headers=headers)
    interval = client.post(
        "/api/v1/openvpn/status-interval",
        headers=headers,
        json={"status_interval_seconds": 10},
    )
    bad_interval = client.post(
        "/api/v1/openvpn/status-interval",
        headers=headers,
        json={"status_interval_seconds": 4},
    )
    test = client.get("/api/v1/openvpn/management/test", headers=headers)
    status = client.get("/api/v1/openvpn/management/status", headers=headers)

    assert config.status_code == 200
    assert config.json()["data"]["settings"]["management_socket"] == "/run/openvpn/server.sock"
    assert interval.status_code == 200
    assert bad_interval.status_code == 422
    assert test.status_code == 200
    assert test.json()["data"]["available"] is True
    assert status.status_code == 200
