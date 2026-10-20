import json
import uuid
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest


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
