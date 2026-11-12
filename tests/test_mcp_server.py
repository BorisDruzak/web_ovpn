import json
import uuid
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest


def test_route_availability_mcp_uses_existing_http_check_and_history(monkeypatch):
    from mcp import openvpn_mcp_server as server

    calls = []
    monkeypatch.setattr(server, "api_request", lambda *args: calls.append(args))
    check = {"check": "route_availability", "profile": "central-wan"}
    server.call_tool("openvpn_network_run_check", check)
    server.call_tool("openvpn_network_route_runs", {"profile": "central-wan", "limit": 3})
    assert calls == [
        ("POST", "/api/v1/network/diagnostics/checks", check),
        ("GET", "/api/v1/network/diagnostics/route-runs?profile=central-wan&limit=3"),
    ]
    schema = server.TOOLS["openvpn_network_run_check"]["inputSchema"]
    assert "route_availability" in schema["properties"]["check"]["enum"]


def test_complete_workflow_reference_and_tool_help_use_original_job():
    import mcp.openvpn_mcp_server as server
    tools=server.TOOLS
    assert 'workstation-full-v1' in tools['openvpn_workstations_plan']['description']
    assert 'read-only' in tools['openvpn_workstations_job_status']['description'].lower()
    skill=(Path(server.__file__).parent/'skills/openvpn-control/SKILL.md').read_text()
    assert 'workstation-full-v1' in skill and 'final_dns' in skill and '5900' in skill
    assert 'choose the returned `office-standard-v1`' not in skill


def workstation_cases():
    identity = str(uuid.UUID(int=1001))
    request = {'request_id': str(uuid.UUID(int=1002))}
    job = 'job-20261015T000000Z-12345678'
    return [
        ('status', {}, 'GET', '/status', None),
        ('devices', {'offset': 0, 'limit': 50}, 'GET', '/devices?offset=0&limit=50', None),
        ('catalog', {}, 'GET', '/catalog', None),
        ('search_users', {'query': 'Synthetic', 'limit': 10}, 'POST', '/directory/search', {'query': 'Synthetic', 'limit': 10}),
        ('link_preview', dict(request, device_key='machine:' + identity, user_guid=identity, computer_guid=None, source_revision='a' * 64),
         'POST', '/links/preview', dict(request, device_key='machine:' + identity, user_guid=identity, computer_guid=None, source_revision='a' * 64)),
        ('link_confirm', dict(request, preview_id=identity, expected_revision=1, reason='Compared'), 'POST', '/links/confirm', dict(request, preview_id=identity, expected_revision=1, reason='Compared')),
        ('link_end', dict(request, link_id=identity, expected_revision=2, reason='Retired'), 'POST', '/links/' + identity + '/end', dict(request, expected_revision=2, reason='Retired')),
        ('plan', dict(request, machine_uuid=identity, user_login='synthetic', user_guid=identity, user_sid='S-1-5-21-1', ou_id='a' * 64, software_profile='office-standard-v1'), 'POST', '/plans', None),
        ('component_plan', dict(request, machine_uuid=identity, component_id='software.onlyoffice'), 'POST', '/component-plans', dict(request, machine_uuid=identity, component_id='software.onlyoffice')),
        ('apply', dict(request, plan_id='setup-' + 'a' * 64, sha256='a' * 64, kind='full_setup'), 'POST', '/plans/setup-' + 'a' * 64 + '/apply', dict(request, sha256='a' * 64, kind='full_setup')),
        ('operation', {'operation_id': identity}, 'GET', '/operations/' + identity, None),
        ('jobs', {'machine_uuid': identity}, 'GET', '/jobs?machine_uuid=' + identity, None),
        ('job_status', {'job_id': job}, 'GET', '/jobs/' + job, None),
        ('job_events', {'job_id': job, 'after': 100, 'limit': 100}, 'GET', '/jobs/' + job + '/events?after=100&limit=100', None),
        ('verify', dict(request, job_id=job), 'POST', '/jobs/' + job + '/verify', request),
        ('cancel', dict(request, job_id=job, sha256='a' * 64), 'POST', '/jobs/' + job + '/cancel', dict(request, sha256='a' * 64)),
        ('reconcile', request, 'POST', '/reconcile', request),
        ('reconcile_status', {'operation_id': identity}, 'GET', '/reconcile/' + identity, None),
        ('findings', {'limit': 50}, 'GET', '/findings?limit=50', None),
        ('sources', {}, 'GET', '/sources', None),
        ('journal', {'job_id': job, 'limit': 100}, 'GET', '/journal?job_id=' + job + '&limit=100', None),
    ]


def test_workstation_tools_have_bounded_schemas_and_no_employee_creation_or_arbitrary_command():
    from mcp.openvpn_mcp_server import TOOLS
    expected = {'openvpn_workstations_' + row[0] for row in workstation_cases()}
    assert {name for name in TOOLS if name.startswith('openvpn_workstations_')} == expected
    assert all(TOOLS[name]['inputSchema']['additionalProperties'] is False for name in expected)
    assert 'request_id' in TOOLS['openvpn_workstations_apply']['inputSchema']['required']
    assert 'sha256' in TOOLS['openvpn_workstations_apply']['inputSchema']['required']
    assert 'expected_revision' in TOOLS['openvpn_workstations_link_confirm']['inputSchema']['required']
    assert not any('users_create' in name or 'command' in TOOLS[name]['inputSchema']['properties'] for name in expected)


@pytest.mark.parametrize('name,arguments,method,path,payload', workstation_cases())
def test_workstation_tools_use_exact_existing_api_contract(monkeypatch, name, arguments, method, path, payload):
    import mcp.openvpn_mcp_server as server
    calls = []
    monkeypatch.setattr(server, 'api_request', lambda method, path, payload=None: calls.append((method, path, payload)) or {'status': 'ok', 'data': {}})
    server.call_tool('openvpn_workstations_' + name, arguments)
    assert calls[0][:2] == (method, '/api/v1/workstations' + path)
    if name == 'plan':
        assert calls[0][2] == arguments
    else:
        assert calls[0][2] == payload


@pytest.mark.parametrize('name,arguments,method,path,payload', workstation_cases())
def test_every_workstation_tool_hides_unexpected_transport_details(monkeypatch, name, arguments, method, path, payload):
    import mcp.openvpn_mcp_server as server
    def fail(*args, **kwargs): raise RuntimeError('private-marker token=synthetic-sensitive-output')
    monkeypatch.setattr(server, 'api_request', fail)
    response = server.handle_message({'jsonrpc': '2.0', 'id': 1, 'method': 'tools/call',
        'params': {'name': 'openvpn_workstations_' + name, 'arguments': arguments}})
    assert 'private-marker' not in json.dumps(response) and 'synthetic-sensitive-output' not in json.dumps(response)
    assert response['error']['message'] == 'workstations_api_unavailable'


@pytest.mark.parametrize('name,arguments', [
    ('devices', {'limit': True}), ('devices', {'limit': 101}), ('job_status', {'job_id': '../private'}),
    ('apply', {'plan_id': 'setup-' + 'a' * 64, 'sha256': 'b' * 64, 'kind': 'full_setup', 'request_id': str(uuid.UUID(int=1))}),
    ('sources', {'command': 'private'}), ('link_confirm', {'preview_id': str(uuid.UUID(int=1)), 'expected_revision': 1, 'reason': 'Compared'}),
])
def test_invalid_workstation_arguments_never_reach_transport(monkeypatch, name, arguments):
    import mcp.openvpn_mcp_server as server
    monkeypatch.setattr(server, 'api_request', lambda *args, **kwargs: pytest.fail('invalid arguments reached transport'))
    with pytest.raises(ValueError): server.call_tool('openvpn_workstations_' + name, arguments)


def test_new_workstation_tools_never_fall_back_to_the_legacy_secret(monkeypatch):
    import mcp.openvpn_mcp_server as server
    monkeypatch.setenv(server.TOKEN_ENV, 'legacy-secret-must-not-be-sent')
    monkeypatch.delenv('OPENVPN_WORKSTATIONS_API_TOKEN_FILE', raising=False)
    with pytest.raises(RuntimeError) as exc:
        server.api_request('GET', '/api/v1/workstations/status')
    assert 'legacy-secret' not in str(exc.value)
    assert str(exc.value) == 'workstations_credentials_unavailable'


def test_workstation_stdio_tools_obey_readonly_credential_and_hide_http_errors(monkeypatch, tmp_path):
    import mcp.openvpn_mcp_server as server
    calls = []
    class API(BaseHTTPRequestHandler):
        def log_message(self, *args): pass
        def do_GET(self): self.reply()
        def do_POST(self): self.reply()
        def reply(self):
            assert self.headers['Authorization'] == 'Bearer synthetic-readonly-token'
            calls.append((self.command, self.path))
            allowed = self.command == 'GET' or self.path.endswith('/directory/search')
            self.send_response(200 if allowed else 403)
            self.send_header('Content-Type', 'application/json'); self.end_headers()
            self.wfile.write(json.dumps({'status': 'ok', 'data': {}} if allowed else {'detail': 'private-marker synthetic-sensitive-output'}).encode())
    api = ThreadingHTTPServer(('127.0.0.1', 0), API)
    thread = threading.Thread(target=api.serve_forever, daemon=True); thread.start()
    token = tmp_path / 'token'; token.write_text('synthetic-readonly-token'); token.chmod(0o600)
    monkeypatch.setenv(server.WORKSTATIONS_TOKEN_FILE_ENV, str(token))
    monkeypatch.setenv(server.BASE_URL_ENV, 'http://127.0.0.1:' + str(api.server_port))
    messages = [{'id': 0, 'method': 'initialize'}, {'id': 1, 'method': 'tools/list'}]
    messages.extend({'id': index + 2, 'method': 'tools/call', 'params': {'name': 'openvpn_workstations_' + case[0], 'arguments': case[1]}} for index, case in enumerate(workstation_cases()))
    try:
        result = subprocess.run([sys.executable, str(Path(server.__file__))], input=''.join(json.dumps(row) + '\n' for row in messages), text=True, capture_output=True, timeout=30, check=True)
    finally:
        api.shutdown(); api.server_close(); thread.join(2)
    assert result.stderr == ''
    responses = [json.loads(line) for line in result.stdout.splitlines()]
    assert len(responses) == 23 and len(calls) == 21
    assert responses[0]['result']['serverInfo']['version'] == '0.2.0'
    assert len([row for row in responses[1]['result']['tools'] if row['name'].startswith(server.WORKSTATIONS_PREFIX)]) == 21
    for case, response in zip(workstation_cases(), responses[2:]):
        if case[2] == 'POST' and case[0] != 'search_users':
            assert response['error']['message'] == 'workstations_permission_denied'
        else:
            assert response['result']['content']
    assert 'private-marker' not in result.stdout and 'synthetic-sensitive-output' not in result.stdout


def test_workstation_transport_refuses_redirect_and_unsafe_token(monkeypatch, tmp_path):
    import mcp.openvpn_mcp_server as server
    received = []
    class API(BaseHTTPRequestHandler):
        def log_message(self, *args): pass
        def do_GET(self):
            received.append(self.path)
            self.send_response(302); self.send_header('Location', '/must-not-follow'); self.end_headers()
    api = ThreadingHTTPServer(('127.0.0.1', 0), API)
    thread = threading.Thread(target=api.serve_forever, daemon=True); thread.start()
    token = tmp_path / 'token'; token.write_text('synthetic-readonly-token'); token.chmod(0o600)
    monkeypatch.setenv(server.WORKSTATIONS_TOKEN_FILE_ENV, str(token))
    monkeypatch.setenv(server.BASE_URL_ENV, 'http://127.0.0.1:' + str(api.server_port))
    try:
        with pytest.raises(RuntimeError, match='^workstations_api_unavailable$'):
            server.api_request('GET', server.WORKSTATIONS_API + '/status')
        assert received == [server.WORKSTATIONS_API + '/status']
        token.write_text('synthetic-token\nAuthorization: bad')
        with pytest.raises(RuntimeError, match='^workstations_credentials_unavailable$'):
            server.api_request('GET', server.WORKSTATIONS_API + '/status')
        assert len(received) == 1
    finally:
        api.shutdown(); api.server_close(); thread.join(2)


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
    assert "openvpn_network_infrastructure" in names
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


def test_mcp_infrastructure_returns_one_node_and_its_linked_peers(monkeypatch):
    import mcp.openvpn_mcp_server as server

    graph = {
        "snapshotAt": "2026-11-11T12:00:00Z", "availability": "ready", "collectionIssues": ["proxmox"],
        "nodes": [{"id": "vm:103", "name": "Directum", "mapStatus": "ok", "checks": []},
                  {"id": "sw", "name": "Switch", "mapStatus": "ok"}, {"id": "other"}],
        "links": [{"a": "sw", "b": "vm:103", "portEvidence": [{"a": "xe3"}]},
                  {"a": "other", "b": "sw"}],
    }

    def api(method, path):
        assert (method, path) == ("GET", "/api/v1/network/infrastructure")
        return {"status": "ok", "infrastructure": graph}

    monkeypatch.setattr(server, "api_request", api)
    assert server.call_tool("openvpn_network_infrastructure", {})["infrastructure"] == graph
    summary = {"availability": "ready", "topologyAudit": {"pendingTotal": 1}}

    def audit_api(method, path):
        assert method == "GET" and path in ("/api/v1/network/infrastructure?view=topology",
                                            "/api/v1/network/infrastructure?view=agents",
                                            "/api/v1/network/infrastructure?view=agents&node_id=vm%3A103",
                                            "/api/v1/network/infrastructure?view=services",
                                            "/api/v1/network/infrastructure?view=attachment",
                                            "/api/v1/network/infrastructure?view=attachment&node_id=role%3Adirectum")
        return {"status": "ok", "infrastructure": summary}

    with monkeypatch.context() as audit:
        audit.setattr(server, "api_request", audit_api)
        assert server.call_tool("openvpn_network_infrastructure", {"view": "topology"})["infrastructure"] == summary
        assert server.call_tool("openvpn_network_infrastructure", {"view": "agents"})["infrastructure"] == summary
        assert server.call_tool("openvpn_network_infrastructure", {
            "view": "agents", "node_id": "vm:103",
        })["infrastructure"] == summary
        assert server.call_tool("openvpn_network_infrastructure", {"view": "services"})["infrastructure"] == summary
        assert server.call_tool("openvpn_network_infrastructure", {
            "view": "attachment", "node_id": "role:directum",
        })["infrastructure"] == summary
        assert server.call_tool("openvpn_network_infrastructure", {"view": "attachment"})["infrastructure"] == summary
        with pytest.raises(ValueError):
            server.call_tool("openvpn_network_infrastructure", {"view": "attachment", "query": "Directum"})
        with pytest.raises(ValueError):
            server.call_tool("openvpn_network_infrastructure", {"view": "topology", "node_id": "vm:103"})
    scoped = server.call_tool("openvpn_network_infrastructure", {"node_id": "vm:103"})["infrastructure"]
    assert scoped["node"] == graph["nodes"][0]
    assert scoped["neighbors"] == [graph["nodes"][1]]
    assert scoped["links"] == graph["links"][:1]
    assert scoped["snapshotAt"] == graph["snapshotAt"]
    assert scoped["collectionIssues"] == ["proxmox"]
    absent = server.call_tool("openvpn_network_infrastructure", {"node_id": "unknown"})["infrastructure"]
    assert absent["node"] is None and absent["links"] == absent["neighbors"] == []


def test_mcp_infrastructure_search_returns_bounded_matches_and_stable_ids(monkeypatch):
    import mcp.openvpn_mcp_server as server

    nodes = [
        {"id": f"node:{index}", "name": f"Directum test {index}", "mapStatus": "unknown"}
        for index in range(15)
    ]
    nodes.append({"id": "directumrx", "name": "Directum", "aliases": ["Документооборот"],
                  "kind": "Виртуальная машина", "vmid": 103, "mapStatus": "ok", "checks": ["details"]})
    graph = {"snapshotAt": "2026-11-11T12:00:00Z", "availability": "ready", "git": "abcdef",
             "nodes": nodes, "links": []}
    requests = []

    def api(method, path):
        requests.append((method, path))
        return {"status": "ok", "infrastructure": graph}

    def search(query):
        return server.call_tool("openvpn_network_infrastructure", {"query": query})["infrastructure"]

    monkeypatch.setattr(server, "api_request", api)
    expected = {"id": "directumrx", "name": "Directum", "kind": "Виртуальная машина", "vmid": 103,
                "mapStatus": "ok"}
    found = search("  DIRECTUM  ")
    assert found["matches"][0] == expected
    assert len(found["matches"]) == 12 and found["total"] == 16
    assert found["snapshotAt"] == graph["snapshotAt"]
    assert "nodes" not in found and "links" not in found
    for query in ("ВМ 103", "VM  103", "103", "ДОКУМЕНТООБОРОТ", "directumrx"):
        assert search(query)["matches"] == [expected]
    assert search("not present")["total"] == 0
    assert set(requests) == {("GET", "/api/v1/network/infrastructure")}
    requests.clear()
    for arguments in ({"query": "  "}, {"query": "x" * 161}, {"query": 103},
                      {"query": "Directum", "node_id": "directumrx"}):
        with pytest.raises(ValueError):
            server.call_tool("openvpn_network_infrastructure", arguments)
    assert requests == []


def test_mcp_infrastructure_port_scope_preserves_evidence_and_guest_observations(monkeypatch):
    import mcp.openvpn_mcp_server as server

    live = {"name": "gigabitEthernet 1/0/22", "state": "up", "stale": False}
    port = {"a": "Gi1/0/22", "b": "port13", "confirmed": True}
    guest_mac = {"id": "sw", "port": live["name"], "vlan": 1, "at": "2026-11-11T12:00:00Z"}
    uplink = {"id": "sw", "port": "Gi1/0/22", "viaMacTable": True, "at": guest_mac["at"]}
    graph = {"nodes": [
        {"id": "sw", "name": "Switch", "ports": [live, {"name": "Gi1/0/2", "state": "down"}]},
        {"id": "other", "name": "Peer"}, {"id": "unrelated"},
        {"id": "host", "ports": [{"name": "eno1", "source": "Proxmox", "stale": False},
                                 {"name": "eno2", "source": "Proxmox", "stale": True}]},
        {"id": "vm", "name": "Guest", "vmid": 103},
    ], "links": [
        {"a": "sw", "b": "other", "confirmed": True, "portEvidence": [
            port, {"a": "Gi1/0/2"}, {"a": "po1 / ge6", "confirmed": True},
        ]},
        {"a": "unrelated", "b": "sw", "portEvidence": [{"a": "Gi1/0/22", "b": "Gi1/0/2"}]},
        {"a": "host", "b": "vm", "confirmed": True, "portEvidence": [
            {"a": "vmbr0", "b": "net0", "confirmed": True, "virtual": {"switchPorts": [guest_mac]}},
            {"a": "vmbr1", "b": "net1", "confirmed": True, "at": guest_mac["at"],
             "virtual": {"switchUplink": uplink, "uplinks": ["eno1", "eno2"],
                         "bridgeActive": True, "linkDisabled": True}},
            {"a": "vmbr2", "b": "net2", "confirmed": False, "virtual": {"switchUplink": uplink}},
        ]},
    ]}
    monkeypatch.setattr(server, "api_request", lambda *_: {"status": "ok", "infrastructure": graph})
    tool = "openvpn_network_infrastructure"
    assert "port_name" in server.TOOLS[tool]["inputSchema"]["properties"]
    result = server.call_tool(tool, {"node_id": "sw", "port_name": " gi 1/0/22 "})["infrastructure"]
    assert result["ports"] == [live]
    assert result["links"] == [{**graph["links"][0], "portEvidence": [port]}]
    assert result["neighbors"] == [{"id": "other", "name": "Peer"}]
    assert "ports" not in result["node"]
    assert [(r["guest"]["id"], r["guestPort"], r["basis"]) for r in result["guestObservations"]] == [
        ("vm", "net0", "guest_mac"), ("vm", "net1", "bridge_uplink"),
    ]
    assert result["guestObservations"][1]["observation"]["viaMacTable"] is True
    host_port = server.call_tool(tool, {"node_id": "host", "port_name": "eno1"})["infrastructure"]
    guest_observation, = host_port["guestObservations"]
    assert (guest_observation["basis"], guest_observation["bridge"], guest_observation["guestPort"]) == (
        "host_bridge_member", "vmbr1", "net1",
    )
    assert guest_observation["observation"] == {
        "id": "host", "port": "eno1", "at": guest_mac["at"], "bridgeActive": True, "linkDisabled": True,
    }
    stale = server.call_tool(tool, {"node_id": "host", "port_name": "eno2"})["infrastructure"]
    assert stale["guestObservations"] == []
    assert len(graph["links"][0]["portEvidence"]) == 3
    assert server.call_tool(tool, {"node_id": "sw", "port_name": "ge6"})["infrastructure"]["links"][0]["confirmed"]
    other_port = server.call_tool(tool, {"node_id": "sw", "port_name": "Gi1/0/2"})["infrastructure"]
    assert not any(edge["confirmed"] for edge in other_port["links"])
    for args in ({"port_name": "ge17"}, {"node_id": "sw", "port_name": " "},
                 {"query": "switch", "port_name": "ge17"}):
        with pytest.raises(ValueError):
            server.call_tool(tool, args)


def test_mcp_infrastructure_port_resolves_physical_alias_and_live_label():
    from mcp.openvpn_mcp_server import _infrastructure_port

    port = {"name": "p5_uplink_IT_TP", "aliases": ["Port5"], "state": "up"}
    switch = {"id": "sw", "ports": [port]}
    graph = {"nodes": [switch, {"id": "core"}], "links": [
        {"a": "core", "b": "sw", "confirmed": False, "portEvidence": [{"a": "Gi1/0/18", "b": "Port5"}]},
        {"a": "core", "b": "sw", "confirmed": True, "portEvidence": [{"a": "Gi1/0/18", "b": port["name"], "confirmed": True}]},
    ]}
    for name in ("Port5", port["name"]):
        result = _infrastructure_port(graph, switch, name)
        assert result["ports"] == [port]
        assert [link["confirmed"] for link in result["links"]] == [False, True]


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
        ("openvpn_network_interface_history", {"source": "mikrotik-main", "interface": "ether1"}),
        ("openvpn_network_diagnostic_checks", {}),
        ("openvpn_network_check_runs", {"limit": 5}),
        ("openvpn_network_loop_diagnostics", {"source": "switch-1"}),
        ("openvpn_network_capture_list", {}),
        ("openvpn_network_run_check", {"check": "linux_route", "destination": "192.0.2.1"}),
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
        ("GET", "/api/v1/network/diagnostics/interfaces?source=mikrotik-main&interface=ether1", None),
        ("GET", "/api/v1/network/diagnostics/checks", None),
        ("GET", "/api/v1/network/diagnostics/runs?limit=5", None),
        ("GET", "/api/v1/network/diagnostics/loops?source=switch-1", None),
        ("GET", "/api/v1/network/diagnostics/captures", None),
        ("POST", "/api/v1/network/diagnostics/checks", {"check": "linux_route", "destination": "192.0.2.1"}),
        ("GET", "/api/v1/network/routes?source=mikrotik-main", None),
        ("GET", "/api/v1/network/observations?host=192.168.100.10", None),
        ("GET", "/api/v1/network/ipsec?source=mikrotik-hex", None),
        ("GET", "/api/v1/network/backups", None),
        ("GET", "/api/v1/network/logs?n=30", None),
    ]


def test_mcp_download_pcap_saves_the_binary_under_codex(tmp_path, monkeypatch):
    from email.message import Message
    from pathlib import Path

    import mcp.openvpn_mcp_server as server

    capture_id = "bb90f6e4-0b96-47c2-a660-2b8cf279275d"
    pcap = b"\xd4\xc3\xb2\xa1" + bytes(20)

    class Response:
        headers = Message()
        headers["Content-Type"] = "application/vnd.tcpdump.pcap"

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self, size):
            return pcap[:size]

    def urlopen(request, **kwargs):
        assert request.full_url.endswith("/api/v1/network/diagnostics/captures/" + capture_id)
        assert request.headers["Accept"] == "application/vnd.tcpdump.pcap"
        return Response()

    monkeypatch.setenv(server.TOKEN_ENV, "test-token")
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    monkeypatch.setattr(server, "_open_capture", urlopen)
    result = server.call_tool("openvpn_network_download_pcap", {"capture_id": capture_id})
    assert Path(result["data"]["path"]).read_bytes() == pcap
    assert Path(result["data"]["path"]).parent == tmp_path / ".codex/network-captures"


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
