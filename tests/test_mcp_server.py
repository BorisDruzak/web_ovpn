import json


def test_mcp_tools_list_has_no_delete_tool():
    from mcp.openvpn_mcp_server import handle_message

    response = handle_message({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
    names = {tool["name"] for tool in response["result"]["tools"]}

    assert "openvpn_status" in names
    assert "openvpn_server_config" in names
    assert "openvpn_set_status_interval" in names
    assert "openvpn_enable_management" in names
    assert "openvpn_management_test" in names
    assert "openvpn_management_status" in names
    assert "openvpn_addressing" in names
    assert "openvpn_validate_network_plan" in names
    assert "openvpn_site_routes" in names
    assert "openvpn_router_instructions" in names
    assert "openvpn_network_dashboard" in names
    assert "openvpn_network_hosts" in names
    assert "openvpn_network_host_detail" in names
    assert "openvpn_network_sources" in names
    assert "openvpn_network_interfaces" in names
    assert "openvpn_network_routes" in names
    assert "openvpn_network_observations" in names
    assert "openvpn_network_ipsec" in names
    assert "openvpn_routeros_backups" in names
    assert "openvpn_network_logs" in names
    assert "openvpn_diagnostic_snapshot" in names
    assert "openvpn_disable_client" in names
    assert "openvpn_view_config" in names
    assert "openvpn_networks" in names
    assert "openvpn_network_templates" in names
    assert "openvpn_apply_networks" in names
    assert "openvpn_apply_network_template" in names
    assert "openvpn_reconnect_client" in names
    assert "openvpn_kill_client_session" in names
    assert "openvpn_update_ccd" not in names
    assert "openvpn_apply_profile_template" not in names
    assert "openvpn_vipnet_list" not in names
    assert "openvpn_vipnet_add" not in names
    assert "openvpn_vipnet_remove" not in names
    assert "openvpn_update_ovpn" in names
    assert "openvpn_delete_client" not in names


def test_mcp_status_calls_api(monkeypatch):
    import mcp.openvpn_mcp_server as server

    calls = []

    def fake_api_request(method, path, payload=None):
        calls.append((method, path, payload))
        return {"status": "ok", "data": {"services": {"openvpn": {"active": "active"}}}}

    monkeypatch.setattr(server, "api_request", fake_api_request)

    response = server.handle_message(
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {"name": "openvpn_status", "arguments": {}},
        }
    )

    assert calls == [("GET", "/api/v1/status", None)]
    payload = json.loads(response["result"]["content"][0]["text"])
    assert payload["data"]["services"]["openvpn"]["active"] == "active"


def test_mcp_openvpn_management_tools_call_api(monkeypatch):
    import mcp.openvpn_mcp_server as server

    calls = []

    def fake_api_request(method, path, payload=None):
        calls.append((method, path, payload))
        return {"status": "ok", "data": {"ok": True}}

    monkeypatch.setattr(server, "api_request", fake_api_request)

    for idx, (name, arguments) in enumerate(
        [
            ("openvpn_server_config", {}),
            ("openvpn_set_status_interval", {"status_interval_seconds": 10}),
            ("openvpn_enable_management", {}),
            ("openvpn_management_test", {}),
            ("openvpn_management_status", {}),
            ("openvpn_kill_client_session", {"client": "alpha", "confirm_client": "alpha", "reason": "drop"}),
        ],
        start=10,
    ):
        server.handle_message(
            {
                "jsonrpc": "2.0",
                "id": idx,
                "method": "tools/call",
                "params": {"name": name, "arguments": arguments},
            }
        )

    assert calls == [
        ("GET", "/api/v1/openvpn/server-config", None),
        ("POST", "/api/v1/openvpn/status-interval", {"status_interval_seconds": 10}),
        ("POST", "/api/v1/openvpn/management/enable", {}),
        ("GET", "/api/v1/openvpn/management/test", None),
        ("GET", "/api/v1/openvpn/management/status", None),
        ("POST", "/api/v1/clients/alpha/kill-session", {"confirm_client": "alpha", "reason": "drop"}),
    ]


def test_mcp_disable_client_requires_confirmation_and_reason(monkeypatch):
    import mcp.openvpn_mcp_server as server

    calls = []

    def fake_api_request(method, path, payload=None):
        calls.append((method, path, payload))
        return {"status": "ok", "data": {"status": "ok", "client": "alpha"}}

    monkeypatch.setattr(server, "api_request", fake_api_request)

    response = server.handle_message(
        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "openvpn_disable_client",
                "arguments": {
                    "client": "alpha",
                    "confirm_client": "alpha",
                    "reason": "lost laptop",
                },
            },
        }
    )

    assert calls == [
        (
            "POST",
            "/api/v1/clients/alpha/disable",
            {"confirm_client": "alpha", "reason": "lost laptop"},
        )
    ]
    payload = json.loads(response["result"]["content"][0]["text"])
    assert payload["data"]["client"] == "alpha"


def test_mcp_network_template_call_uses_confirm_and_reason(monkeypatch):
    import mcp.openvpn_mcp_server as server

    calls = []

    def fake_api_request(method, path, payload=None):
        calls.append((method, path, payload))
        return {"status": "ok", "data": {"status": "ok", "client": "alpha", "template": "directum17"}}

    monkeypatch.setattr(server, "api_request", fake_api_request)

    response = server.handle_message(
        {
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {
                "name": "openvpn_apply_network_template",
                "arguments": {
                    "client": "alpha",
                    "confirm_client": "alpha",
                    "reason": "change access",
                    "template": "directum17",
                    "vpn_ip": "192.168.50.55",
                },
            },
        }
    )

    assert calls == [
        (
            "POST",
            "/api/v1/clients/alpha/network-template",
            {
                "confirm_client": "alpha",
                "reason": "change access",
                "template": "directum17",
                "vpn_ip": "192.168.50.55",
            },
        )
    ]
    payload = json.loads(response["result"]["content"][0]["text"])
    assert payload["data"]["template"] == "directum17"


def test_mcp_preview_and_generate_pass_router_fields(monkeypatch):
    import mcp.openvpn_mcp_server as server

    calls = []

    def fake_api_request(method, path, payload=None):
        calls.append((method, path, payload))
        return {"status": "ok", "data": {"client": "router_site_001"}}

    monkeypatch.setattr(server, "api_request", fake_api_request)

    for idx, name in enumerate(["openvpn_preview_client", "openvpn_generate_client"], start=20):
        arguments = {
            "client": "router_site_001",
            "profile": "router_vipnet",
            "vpn_ip": "192.168.50.201",
            "client_type": "router_site_to_site",
            "remote_lan_cidr": "192.168.51.0/24",
            "create_server_route": True,
        }
        if name == "openvpn_generate_client":
            arguments["comment"] = "branch router"
        server.handle_message(
            {
                "jsonrpc": "2.0",
                "id": idx,
                "method": "tools/call",
                "params": {"name": name, "arguments": arguments},
            }
        )

    assert calls == [
        (
            "POST",
            "/api/v1/clients/router_site_001/preview",
            {
                "profile": "router_vipnet",
                "vpn_ip": "192.168.50.201",
                "client_type": "router_site_to_site",
                "remote_lan_cidr": "192.168.51.0/24",
                "create_server_route": True,
            },
        ),
        (
            "POST",
            "/api/v1/clients/router_site_001/generate",
            {
                "profile": "router_vipnet",
                "vpn_ip": "192.168.50.201",
                "client_type": "router_site_to_site",
                "remote_lan_cidr": "192.168.51.0/24",
                "create_server_route": True,
                "comment": "branch router",
            },
        ),
    ]


def test_mcp_addressing_tools_call_api(monkeypatch):
    import mcp.openvpn_mcp_server as server

    calls = []

    def fake_api_request(method, path, payload=None):
        calls.append((method, path, payload))
        return {"status": "ok", "data": {"ok": True}}

    monkeypatch.setattr(server, "api_request", fake_api_request)

    for idx, (name, arguments) in enumerate(
        [
            ("openvpn_addressing", {}),
            ("openvpn_validate_network_plan", {}),
            ("openvpn_site_routes", {}),
            ("openvpn_router_instructions", {"client": "router_site_001"}),
        ],
        start=30,
    ):
        server.handle_message(
            {
                "jsonrpc": "2.0",
                "id": idx,
                "method": "tools/call",
                "params": {"name": name, "arguments": arguments},
            }
        )

    assert calls == [
        ("GET", "/api/v1/openvpn/addressing", None),
        ("POST", "/api/v1/openvpn/validate-network-plan", {}),
        ("GET", "/api/v1/site-routes", None),
        ("GET", "/api/v1/clients/router_site_001/router-instructions", None),
    ]


def test_mcp_apply_networks_call_uses_safe_network_list(monkeypatch):
    import mcp.openvpn_mcp_server as server

    calls = []

    def fake_api_request(method, path, payload=None):
        calls.append((method, path, payload))
        return {"status": "ok", "data": {"status": "ok", "client": "alpha", "networks": ["192.168.100.10/32"]}}

    monkeypatch.setattr(server, "api_request", fake_api_request)

    response = server.handle_message(
        {
            "jsonrpc": "2.0",
            "id": 5,
            "method": "tools/call",
            "params": {
                "name": "openvpn_apply_networks",
                "arguments": {
                    "client": "alpha",
                    "confirm_client": "alpha",
                    "reason": "selected access",
                    "cidrs": ["192.168.100.10/32"],
                    "dns": False,
                },
            },
        }
    )

    assert calls == [
        (
            "POST",
            "/api/v1/clients/alpha/networks",
            {
                "confirm_client": "alpha",
                "reason": "selected access",
                "cidrs": ["192.168.100.10/32"],
                "dns": False,
                "vpn_ip": "",
            },
        )
    ]
    payload = json.loads(response["result"]["content"][0]["text"])
    assert payload["data"]["networks"] == ["192.168.100.10/32"]


def test_mcp_network_diagnostic_tools_call_api(monkeypatch):
    import mcp.openvpn_mcp_server as server

    calls = []

    def fake_api_request(method, path, payload=None):
        calls.append((method, path, payload))
        return {"status": "ok", "data": {"ok": True}}

    monkeypatch.setattr(server, "api_request", fake_api_request)

    tool_calls = [
        ("openvpn_network_dashboard", {}),
        (
            "openvpn_network_hosts",
            {"category": "telephony", "status": "online", "source": "mikrotik-main", "network": "telephony", "has_mac": "yes"},
        ),
        ("openvpn_network_host_detail", {"ip": "192.168.100.10"}),
        ("openvpn_network_sources", {}),
        ("openvpn_network_interfaces", {"source": "mikrotik-main"}),
        ("openvpn_network_routes", {"source": "mikrotik-main"}),
        ("openvpn_network_observations", {"host": "192.168.100.10"}),
        ("openvpn_network_ipsec", {"source": "mikrotik-hex"}),
        ("openvpn_routeros_backups", {}),
        ("openvpn_network_logs", {"n": 30}),
    ]
    for idx, (name, arguments) in enumerate(tool_calls, start=40):
        response = server.handle_message(
            {
                "jsonrpc": "2.0",
                "id": idx,
                "method": "tools/call",
                "params": {"name": name, "arguments": arguments},
            }
        )
        assert "result" in response

    assert calls == [
        ("GET", "/api/v1/network/dashboard", None),
        ("GET", "/api/v1/network/hosts?category=telephony&status=online&source=mikrotik-main&network=telephony&has_mac=yes", None),
        ("GET", "/api/v1/network/hosts/192.168.100.10", None),
        ("GET", "/api/v1/network/sources", None),
        ("GET", "/api/v1/network/interfaces?source=mikrotik-main", None),
        ("GET", "/api/v1/network/routes?source=mikrotik-main", None),
        ("GET", "/api/v1/network/observations?host=192.168.100.10", None),
        ("GET", "/api/v1/network/ipsec?source=mikrotik-hex", None),
        ("GET", "/api/v1/network/backups", None),
        ("GET", "/api/v1/network/logs?n=30", None),
    ]


def test_mcp_diagnostic_snapshot_aggregates_read_only_checks(monkeypatch):
    import mcp.openvpn_mcp_server as server

    calls = []

    def fake_api_request(method, path, payload=None):
        calls.append((method, path, payload))
        if path == "/api/v1/network/ipsec":
            return {"status": "ok", "data": {"summary": {"sources": 2, "ok": 2}}}
        return {"status": "ok", "data": {"path": path}}

    monkeypatch.setattr(server, "api_request", fake_api_request)

    response = server.handle_message(
        {
            "jsonrpc": "2.0",
            "id": 50,
            "method": "tools/call",
            "params": {"name": "openvpn_diagnostic_snapshot", "arguments": {}},
        }
    )

    payload = json.loads(response["result"]["content"][0]["text"])
    assert payload["status"] == "ok"
    assert payload["sections"]["ipsec"]["data"]["summary"]["ok"] == 2
    assert calls == [
        ("GET", "/api/v1/status", None),
        ("GET", "/api/v1/openvpn/server-config", None),
        ("GET", "/api/v1/openvpn/management/test", None),
        ("GET", "/api/v1/connections", None),
        ("GET", "/api/v1/nat-status", None),
        ("GET", "/api/v1/network/dashboard", None),
        ("GET", "/api/v1/network/sources", None),
        ("GET", "/api/v1/network/ipsec", None),
        ("GET", "/api/v1/network/backups", None),
        ("GET", "/api/v1/network/logs?n=30", None),
    ]
