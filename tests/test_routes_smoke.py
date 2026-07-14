import importlib
import json
import os
import sys
from pathlib import Path

from fastapi.testclient import TestClient


def make_fake_vpnctl(path: Path) -> Path:
    script_path = path.with_suffix(".py") if os.name == "nt" else path
    script_path.write_text(
        """#!/usr/bin/env python3
import json
import os
import sys
args = sys.argv[1:]
cmd = args[1] if args and args[0] == "--json" else args[0]
log_path = os.environ.get("FAKE_VPNCTL_LOG")
out_dir = os.environ.get("OUT_DIR") or "/tmp"
if log_path:
    with open(log_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(args, ensure_ascii=False) + "\\n")
if cmd == "status":
    print(json.dumps({"services": {"openvpn": {"active": "active"}, "nat": {"active": "active"}}, "connected": []}))
elif cmd == "list":
    dynamic_vpn_ip = os.environ.get("FAKE_DYNAMIC_VPN_IP", "")
    print(json.dumps({"clients": [{"name": "alpha", "profile": "directum", "status": "active", "vpn_ip": None if dynamic_vpn_ip else "192.168.50.10", "connected": bool(dynamic_vpn_ip), "virtual_address": dynamic_vpn_ip}]}))
elif cmd == "connected":
    print(json.dumps({"connected": [{"common_name": "alpha", "virtual_address": "192.168.50.10", "real_address": "1.2.3.4:1000", "bytes_received": 10, "bytes_sent": 20, "connected_since": "hidden"}]}))
elif cmd == "server-config":
    sub = args[2]
    if sub == "inspect":
        print(json.dumps({"status": "ok", "server_conf": "/etc/openvpn/server/server.conf", "settings": {"server_network": "192.168.50.0/24", "server_tunnel_ip": "192.168.50.1", "status_path": "/var/log/openvpn/status.log", "status_interval": 10, "status_version": 2, "management_enabled": True, "management_socket": "/run/openvpn/server.sock", "management_client_group": "openvpn-web", "management_log_cache": 300}, "warnings": []}))
    elif sub == "apply":
        print(json.dumps({"status": "ok", "changed": True, "settings": {"status_interval": 10, "status_version": 2}}))
    elif sub == "restart-openvpn":
        print(json.dumps({"status": "ok", "restart": {"active": "active"}}))
elif cmd == "management":
    sub = args[2]
    if sub == "test":
        print(json.dumps({"status": "ok", "socket": "/run/openvpn/server.sock", "available": True}))
    elif sub == "kill":
        print(json.dumps({"status": "ok", "client": args[3], "killed": True}))
elif cmd == "profiles":
    print(json.dumps({"profiles": [{"name": "directum", "description": "Directum"}, {"name": "router_vipnet", "description": "Router"}]}))
elif cmd == "inspect":
    client = args[2]
    ovpn_path = os.path.join(out_dir, f"{client}.ovpn")
    dynamic_vpn_ip = os.environ.get("FAKE_DYNAMIC_VPN_IP", "")
    print(json.dumps({"client": client, "registry": {"name": client, "profile": "directum", "status": "active", "vpn_ip": None}, "cert_status": "valid", "connected": {"virtual_address": dynamic_vpn_ip} if dynamic_vpn_ip else None, "files": {"ovpn": {"path": ovpn_path, "exists": os.path.isfile(ovpn_path)}, "bat": {"path": os.path.join(out_dir, f"{client}-install-hosts-as-admin.bat"), "exists": False}}, "ccd": {"raw_lines": []}}))
elif cmd == "sync":
    print(json.dumps({"status": "ok", "imported_or_updated": 1}))
elif cmd == "generate":
    print(json.dumps({"status": "ok", "client": args[2], "profile": args[3], "vpn_ip": None, "ccd_path": "/tmp/ccd", "ovpn_path": "/tmp/alpha.ovpn"}))
elif cmd == "preview":
    print(json.dumps({"status": "preview", "client": args[2], "profile": args[3], "client_type": "router_site_to_site" if "router_site_to_site" in args else "user", "remote_lan_cidr": "192.168.51.0/24" if "192.168.51.0/24" in args else None, "vpn_ip": args[4] if len(args) > 4 and not args[4].startswith("--") else None, "ccd_path": "/tmp/ccd", "ovpn_path": "/tmp/alpha.ovpn", "ccd_preview": ["ifconfig-push 192.168.50.201 255.255.255.0", "iroute 192.168.51.0 255.255.255.0"], "server_routes_preview": ["route 192.168.51.0 255.255.255.0"], "router_instructions": ["Disable NAT/MASQUERADE"]}))
elif cmd == "repair-artifacts":
    client = args[2]
    os.makedirs(out_dir, exist_ok=True)
    ovpn_path = os.path.join(out_dir, f"{client}.ovpn")
    with open(ovpn_path, "w", encoding="utf-8") as f:
        f.write("client\\n")
    print(json.dumps({"status": "ok", "client": client, "ovpn_path": ovpn_path, "actions": ["ovpn_written"]}))
elif cmd == "config-view":
    print(json.dumps({"status": "ok", "client": args[2], "vpn_ip": "192.168.50.10", "detected_profile": "directum", "ovpn": {"path": "/tmp/alpha.ovpn", "exists": True, "content": "client\\n"}, "ccd": {"path": "/tmp/ccd/alpha", "exists": True, "content": "push route\\n"}}))
elif cmd == "networks":
    print(json.dumps({"networks": [{"cidr": "192.168.100.10/32", "tag": "directum", "nat": False}, {"cidr": "10.83.1.0/24", "tag": "vipnet", "nat": True}]}))
elif cmd == "network-templates":
    print(json.dumps({"templates": [{"name": "directum", "description": "Directum", "cidrs": ["192.168.100.10/32"], "dns": False, "builtin": True}], "networks": [{"cidr": "192.168.100.10/32", "tag": "directum", "nat": False}]}))
elif cmd == "client-template-apply":
    print(json.dumps({"status": "ok", "client": args[2], "template": args[3]}))
elif cmd == "client-networks-apply":
    print(json.dumps({"status": "ok", "client": args[2], "networks": ["192.168.100.10/32"]}))
elif cmd == "reconnect-client":
    print(json.dumps({"status": "not_configured", "client": args[2]}))
elif cmd == "disable":
    print(json.dumps({"status": "ok", "client": args[2], "kill_active": {"killed": "--kill-active" in args}}))
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


def test_login_dashboard_and_clients_smoke(tmp_path, monkeypatch):
    fake = make_fake_vpnctl(tmp_path / "vpnctl")
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{(tmp_path / 'web.sqlite').as_posix()}")
    monkeypatch.setenv("APP_SECRET_KEY", "test-secret")
    monkeypatch.setenv("ADMIN_USERNAME", "admin")
    monkeypatch.setenv("ADMIN_PASSWORD", "admin-pass")
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

    with TestClient(app.main.app) as client:
        login = client.get("/login")
        assert login.status_code == 200
        csrf = login.text.split('name="csrf_token" value="')[1].split('"')[0]
        response = client.post(
            "/login",
            data={"username": "admin", "password": "admin-pass", "csrf_token": csrf},
            follow_redirects=False,
        )
        assert response.status_code == 303

        dashboard = client.get("/")
        assert dashboard.status_code == 200
        assert "OpenVPN" in dashboard.text

        clients_page = client.get("/clients")
        assert clients_page.status_code == 200
        assert "alpha" in clients_page.text
        assert "/clients/alpha/edit" in clients_page.text

        networks_page = client.get("/networks")
        assert networks_page.status_code == 200
        assert "192.168.100.10/32" in networks_page.text
        assert "directum" in networks_page.text

        templates_page = client.get("/network-templates")
        assert templates_page.status_code == 200
        assert "directum" in templates_page.text


        edit_page = client.get("/clients/alpha/edit")
        assert edit_page.status_code == 200
        assert "Применить шаблон сетей" in edit_page.text
        assert "Сохранить CCD" not in edit_page.text
        assert "/clients/alpha/edit/ccd" not in edit_page.text

        connections_page = client.get("/connections")
        assert connections_page.status_code == 200
        assert "connected_since" not in connections_page.text

        calls = [
            json.loads(line)
            for line in (tmp_path / "vpnctl-calls.jsonl").read_text(encoding="utf-8").splitlines()
            if line
        ]
        assert any(call[1] == "sync" for call in calls)


def test_clients_page_shows_live_vpn_ip_without_ccd_push(tmp_path, monkeypatch):
    fake = make_fake_vpnctl(tmp_path / "vpnctl")
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{(tmp_path / 'web.sqlite').as_posix()}")
    monkeypatch.setenv("APP_SECRET_KEY", "test-secret")
    monkeypatch.setenv("ADMIN_USERNAME", "admin")
    monkeypatch.setenv("ADMIN_PASSWORD", "admin-pass")
    monkeypatch.setenv("VPNCTL_PATH", str(fake))
    monkeypatch.setenv("VPNCTL_USE_SUDO", "0")
    monkeypatch.setenv("OUT_DIR", str(tmp_path))
    monkeypatch.setenv("SHARE_OUT_DIR", str(tmp_path))
    monkeypatch.setenv("ARCHIVE_DIR", str(tmp_path))
    monkeypatch.setenv("FAKE_DYNAMIC_VPN_IP", "192.168.50.77")

    import app.db
    import app.main

    app.db.reset_engine_cache()
    importlib.reload(app.main)

    with TestClient(app.main.app) as client:
        login = client.get("/login")
        csrf = login.text.split('name="csrf_token" value="')[1].split('"')[0]
        assert client.post(
            "/login",
            data={"username": "admin", "password": "admin-pass", "csrf_token": csrf},
            follow_redirects=False,
        ).status_code == 303
        clients_page = client.get("/clients")
        detail_page = client.get("/clients/alpha")

    assert "192.168.50.77" in clients_page.text
    assert "Действующий VPN IP" in detail_page.text
    assert "192.168.50.77" in detail_page.text


def test_network_add_without_comment_omits_comment_flag(tmp_path, monkeypatch):
    fake = make_fake_vpnctl(tmp_path / "vpnctl")
    log_path = tmp_path / "vpnctl-calls.jsonl"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{(tmp_path / 'web.sqlite').as_posix()}")
    monkeypatch.setenv("APP_SECRET_KEY", "test-secret")
    monkeypatch.setenv("ADMIN_USERNAME", "admin")
    monkeypatch.setenv("ADMIN_PASSWORD", "admin-pass")
    monkeypatch.setenv("VPNCTL_PATH", str(fake))
    monkeypatch.setenv("VPNCTL_USE_SUDO", "0")
    monkeypatch.setenv("OUT_DIR", str(tmp_path))
    monkeypatch.setenv("SHARE_OUT_DIR", str(tmp_path))
    monkeypatch.setenv("ARCHIVE_DIR", str(tmp_path))
    monkeypatch.setenv("FAKE_VPNCTL_LOG", str(log_path))

    import app.db
    import app.main

    app.db.reset_engine_cache()
    importlib.reload(app.main)

    with TestClient(app.main.app) as client:
        login = client.get("/login")
        csrf = login.text.split('name="csrf_token" value="')[1].split('"')[0]
        assert client.post(
            "/login",
            data={"username": "admin", "password": "admin-pass", "csrf_token": csrf},
            follow_redirects=False,
        ).status_code == 303
        response = client.post(
            "/networks/add",
            data={"cidr": "192.168.100.12", "tag": "default", "comment": "", "csrf_token": csrf},
            follow_redirects=False,
        )

    assert response.status_code == 303
    calls = [json.loads(line) for line in log_path.read_text(encoding="utf-8").splitlines() if line]
    add_call = next(call for call in calls if call[1:3] == ["networks", "add"])
    assert "192.168.100.12/32" in add_call
    assert "--comment" not in add_call


def test_generate_profile_runs_sync_after_success(tmp_path, monkeypatch):
    fake = make_fake_vpnctl(tmp_path / "vpnctl")
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{(tmp_path / 'web.sqlite').as_posix()}")
    monkeypatch.setenv("APP_SECRET_KEY", "test-secret")
    monkeypatch.setenv("ADMIN_USERNAME", "admin")
    monkeypatch.setenv("ADMIN_PASSWORD", "admin-pass")
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

    with TestClient(app.main.app) as client:
        login = client.get("/login")
        csrf = login.text.split('name="csrf_token" value="')[1].split('"')[0]
        response = client.post(
            "/login",
            data={"username": "admin", "password": "admin-pass", "csrf_token": csrf},
            follow_redirects=False,
        )
        assert response.status_code == 303

        form = client.get("/clients/new")
        csrf = form.text.split('name="csrf_token" value="')[1].split('"')[0]
        created = client.post(
            "/clients/new",
            data={
                "csrf_token": csrf,
                "action": "generate",
                "client": "alpha",
                "profile": "directum",
                "vpn_ip": "",
                "comment": "test",
            },
        )

        assert created.status_code == 200
        calls = [
            json.loads(line)
            for line in (tmp_path / "vpnctl-calls.jsonl").read_text(encoding="utf-8").splitlines()
            if line
        ]
        commands = [call[1] for call in calls]
        assert "generate" in commands
        assert "sync" in commands[commands.index("generate") + 1 :]


def test_new_client_form_supports_router_site_to_site_preview(tmp_path, monkeypatch):
    fake = make_fake_vpnctl(tmp_path / "vpnctl")
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{(tmp_path / 'web.sqlite').as_posix()}")
    monkeypatch.setenv("APP_SECRET_KEY", "test-secret")
    monkeypatch.setenv("ADMIN_USERNAME", "admin")
    monkeypatch.setenv("ADMIN_PASSWORD", "admin-pass")
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

    with TestClient(app.main.app) as client:
        login = client.get("/login")
        csrf = login.text.split('name="csrf_token" value="')[1].split('"')[0]
        assert client.post(
            "/login",
            data={"username": "admin", "password": "admin-pass", "csrf_token": csrf},
            follow_redirects=False,
        ).status_code == 303

        form = client.get("/clients/new")
        assert 'name="client_type"' in form.text
        assert "router_site_to_site" in form.text
        csrf = form.text.split('name="csrf_token" value="')[1].split('"')[0]
        preview = client.post(
            "/clients/new",
            data={
                "csrf_token": csrf,
                "action": "preview",
                "client": "router_site_001",
                "profile": "router_vipnet",
                "client_type": "router_site_to_site",
                "vpn_ip": "192.168.50.201",
                "remote_lan_cidr": "192.168.51.0/24",
                "create_server_route": "1",
                "comment": "branch router",
            },
        )

        assert preview.status_code == 200
        assert "iroute 192.168.51.0" in preview.text
        assert "route 192.168.51.0" in preview.text
        calls = [
            json.loads(line)
            for line in (tmp_path / "vpnctl-calls.jsonl").read_text(encoding="utf-8").splitlines()
            if line
        ]
        preview_call = next(call for call in calls if call[1:4] == ["preview", "router_site_001", "router_vipnet"])
        assert "--client-type" in preview_call
        assert "--remote-lan" in preview_call
        assert "--create-server-route" in preview_call


def test_download_button_repairs_missing_ovpn_and_returns_file(tmp_path, monkeypatch):
    fake = make_fake_vpnctl(tmp_path / "vpnctl")
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{(tmp_path / 'web.sqlite').as_posix()}")
    monkeypatch.setenv("APP_SECRET_KEY", "test-secret")
    monkeypatch.setenv("ADMIN_USERNAME", "admin")
    monkeypatch.setenv("ADMIN_PASSWORD", "admin-pass")
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

    with TestClient(app.main.app) as client:
        login = client.get("/login")
        csrf = login.text.split('name="csrf_token" value="')[1].split('"')[0]
        assert client.post(
            "/login",
            data={"username": "admin", "password": "admin-pass", "csrf_token": csrf},
            follow_redirects=False,
        ).status_code == 303

        detail = client.get("/clients/alpha")
        csrf = detail.text.split('name="csrf_token" value="')[1].split('"')[0]
        downloaded = client.post(
            "/clients/alpha/download-link",
            data={"csrf_token": csrf, "file_type": "ovpn"},
            follow_redirects=False,
        )

        assert downloaded.status_code == 200
        assert downloaded.content.replace(b"\r\n", b"\n") == b"client\n"
        assert "attachment" in downloaded.headers["content-disposition"]
        assert "alpha.ovpn" in downloaded.headers["content-disposition"]
        assert (tmp_path / "alpha.ovpn").read_text(encoding="utf-8") == "client\n"
        calls = [
            json.loads(line)
            for line in (tmp_path / "vpnctl-calls.jsonl").read_text(encoding="utf-8").splitlines()
            if line
        ]
        assert any(call[1:3] == ["repair-artifacts", "alpha"] for call in calls)
        assert sum(1 for call in calls if call[1:3] == ["inspect", "alpha"]) >= 2


def test_openvpn_settings_page_applies_status_interval(tmp_path, monkeypatch):
    fake = make_fake_vpnctl(tmp_path / "vpnctl")
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{(tmp_path / 'web.sqlite').as_posix()}")
    monkeypatch.setenv("APP_SECRET_KEY", "test-secret")
    monkeypatch.setenv("ADMIN_USERNAME", "admin")
    monkeypatch.setenv("ADMIN_PASSWORD", "admin-pass")
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

    with TestClient(app.main.app) as client:
        login = client.get("/login")
        csrf = login.text.split('name="csrf_token" value="')[1].split('"')[0]
        assert client.post(
            "/login",
            data={"username": "admin", "password": "admin-pass", "csrf_token": csrf},
            follow_redirects=False,
        ).status_code == 303

        page = client.get("/settings/openvpn")
        assert page.status_code == 200
        assert "server.conf" in page.text
        assert "/run/openvpn/server.sock" in page.text
        assert "Адресация" in page.text
        assert "192.168.50.0/24" in page.text
        assert "/settings/openvpn/validate-network-plan" in page.text

        csrf = page.text.split('name="csrf_token" value="')[1].split('"')[0]
        saved = client.post(
            "/settings/openvpn/status-interval",
            data={"csrf_token": csrf, "status_interval_seconds": "10"},
            follow_redirects=False,
        )
        assert saved.status_code == 303

        calls = [
            json.loads(line)
            for line in (tmp_path / "vpnctl-calls.jsonl").read_text(encoding="utf-8").splitlines()
            if line
        ]
        assert any(call[1:6] == ["server-config", "apply", "--status-interval", "10", "--status-version"] for call in calls)
        assert any("--restart" in call for call in calls if call[1:3] == ["server-config", "apply"])


def test_connections_page_uses_auto_source_and_has_kill_button(tmp_path, monkeypatch):
    fake = make_fake_vpnctl(tmp_path / "vpnctl")
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{(tmp_path / 'web.sqlite').as_posix()}")
    monkeypatch.setenv("APP_SECRET_KEY", "test-secret")
    monkeypatch.setenv("ADMIN_USERNAME", "admin")
    monkeypatch.setenv("ADMIN_PASSWORD", "admin-pass")
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

    with TestClient(app.main.app) as client:
        login = client.get("/login")
        csrf = login.text.split('name="csrf_token" value="')[1].split('"')[0]
        assert client.post(
            "/login",
            data={"username": "admin", "password": "admin-pass", "csrf_token": csrf},
            follow_redirects=False,
        ).status_code == 303

        page = client.get("/connections")
        assert page.status_code == 200
        assert "/connections/alpha/kill" in page.text
        assert "connected_since" not in page.text

        csrf = page.text.split('name="csrf_token" value="')[1].split('"')[0]
        killed = client.post(
            "/connections/alpha/kill",
            data={"csrf_token": csrf, "confirm_name": "alpha"},
            follow_redirects=False,
        )
        assert killed.status_code == 303

        calls = [
            json.loads(line)
            for line in (tmp_path / "vpnctl-calls.jsonl").read_text(encoding="utf-8").splitlines()
            if line
        ]
        assert any(call[1:4] == ["connected", "--source", "auto"] for call in calls)
        assert any(call[1:4] == ["management", "kill", "alpha"] for call in calls)


def test_template_apply_reconnects_client_for_route_refresh(tmp_path, monkeypatch):
    fake = make_fake_vpnctl(tmp_path / "vpnctl")
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{(tmp_path / 'web.sqlite').as_posix()}")
    monkeypatch.setenv("APP_SECRET_KEY", "test-secret")
    monkeypatch.setenv("ADMIN_USERNAME", "admin")
    monkeypatch.setenv("ADMIN_PASSWORD", "admin-pass")
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

    with TestClient(app.main.app) as client:
        login = client.get("/login")
        csrf = login.text.split('name="csrf_token" value="')[1].split('"')[0]
        assert client.post(
            "/login",
            data={"username": "admin", "password": "admin-pass", "csrf_token": csrf},
            follow_redirects=False,
        ).status_code == 303

        edit = client.get("/clients/alpha/edit")
        csrf = edit.text.split('name="csrf_token" value="')[1].split('"')[0]
        applied = client.post(
            "/clients/alpha/edit/template",
            data={
                "csrf_token": csrf,
                "template": "directum",
                "vpn_ip": "",
                "reason": "template refresh",
                "confirm_name": "alpha",
            },
            follow_redirects=False,
        )

        assert applied.status_code == 303
        calls = [
            json.loads(line)
            for line in (tmp_path / "vpnctl-calls.jsonl").read_text(encoding="utf-8").splitlines()
            if line
        ]
        assert any(call[1:4] == ["client-template-apply", "alpha", "directum"] for call in calls)
        assert any(call[1:3] == ["sync"] for call in calls)
        assert any(call[1:3] == ["reconnect-client", "alpha"] for call in calls)


def test_client_disable_uses_kill_active(tmp_path, monkeypatch):
    fake = make_fake_vpnctl(tmp_path / "vpnctl")
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{(tmp_path / 'web.sqlite').as_posix()}")
    monkeypatch.setenv("APP_SECRET_KEY", "test-secret")
    monkeypatch.setenv("ADMIN_USERNAME", "admin")
    monkeypatch.setenv("ADMIN_PASSWORD", "admin-pass")
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

    with TestClient(app.main.app) as client:
        login = client.get("/login")
        csrf = login.text.split('name="csrf_token" value="')[1].split('"')[0]
        assert client.post(
            "/login",
            data={"username": "admin", "password": "admin-pass", "csrf_token": csrf},
            follow_redirects=False,
        ).status_code == 303

        detail = client.get("/clients/alpha")
        csrf = detail.text.split('name="csrf_token" value="')[1].split('"')[0]
        disabled = client.post(
            "/clients/alpha/disable",
            data={"csrf_token": csrf, "confirm_name": "alpha", "reason": "test disable"},
            follow_redirects=False,
        )
        assert disabled.status_code == 303

        calls = [
            json.loads(line)
            for line in (tmp_path / "vpnctl-calls.jsonl").read_text(encoding="utf-8").splitlines()
            if line
        ]
        assert any(call[1:4] == ["disable", "alpha", "--reason"] and "--kill-active" in call for call in calls)
