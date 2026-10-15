from __future__ import annotations

import json
import os
import re
import stat
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from typing import Any, Callable

BASE_URL_ENV = "OPENVPN_WEB_BASE_URL"
TOKEN_ENV = "OPENVPN_WEB_API_TOKEN"
TOKEN_FILE_ENV = "OPENVPN_WEB_API_TOKEN_FILE"
WORKSTATIONS_TOKEN_FILE_ENV = "OPENVPN_WORKSTATIONS_API_TOKEN_FILE"
WORKSTATIONS_PREFIX = "openvpn_workstations_"
WORKSTATIONS_API = "/api/v1/workstations"


def configure_stdio() -> None:
    for stream_name in ("stdin", "stdout", "stderr"):
        stream = getattr(sys, stream_name, None)
        if stream is not None and hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")


def tool_schema(description: str, properties: dict[str, Any] | None = None, required: list[str] | None = None) -> dict[str, Any]:
    return {
        "description": description,
        "inputSchema": {
            "type": "object",
            "properties": properties or {},
            "required": required or [],
            "additionalProperties": False,
        },
    }


TOOLS: dict[str, dict[str, Any]] = {
    "openvpn_status": tool_schema("Get OpenVPN and NAT service status."),
    "openvpn_server_config": tool_schema("Inspect OpenVPN server.conf management/status settings."),
    "openvpn_set_status_interval": tool_schema(
        "Set OpenVPN status/client refresh interval and restart OpenVPN.",
        {"status_interval_seconds": {"type": "integer", "minimum": 5, "maximum": 300}},
        ["status_interval_seconds"],
    ),
    "openvpn_enable_management": tool_schema("Enable OpenVPN Management Interface through Unix socket and restart OpenVPN."),
    "openvpn_management_test": tool_schema("Test OpenVPN Management Interface Unix socket."),
    "openvpn_management_status": tool_schema("Get current clients from OpenVPN Management Interface."),
    "openvpn_profiles": tool_schema("List available OpenVPN access profiles."),
    "openvpn_list_clients": tool_schema("List registered OpenVPN clients."),
    "openvpn_inspect_client": tool_schema(
        "Inspect one OpenVPN client.",
        {"client": {"type": "string"}},
        ["client"],
    ),
    "openvpn_preview_client": tool_schema(
        "Preview creating or updating a client profile without changing files.",
        {
            "client": {"type": "string"},
            "profile": {"type": "string"},
            "vpn_ip": {"type": "string", "default": ""},
            "client_type": {"type": "string", "enum": ["user", "router_nat", "router_site_to_site"], "default": "user"},
            "remote_lan_cidr": {"type": "string", "default": ""},
            "create_server_route": {"type": "boolean", "default": False},
        },
        ["client", "profile"],
    ),
    "openvpn_generate_client": tool_schema(
        "Generate or update a client profile.",
        {
            "client": {"type": "string"},
            "profile": {"type": "string"},
            "vpn_ip": {"type": "string", "default": ""},
            "client_type": {"type": "string", "enum": ["user", "router_nat", "router_site_to_site"], "default": "user"},
            "remote_lan_cidr": {"type": "string", "default": ""},
            "create_server_route": {"type": "boolean", "default": False},
            "comment": {"type": "string", "default": ""},
        },
        ["client", "profile"],
    ),
    "openvpn_disable_client": tool_schema(
        "Disable client access. Requires exact confirm_client and a reason.",
        {
            "client": {"type": "string"},
            "confirm_client": {"type": "string"},
            "reason": {"type": "string"},
        },
        ["client", "confirm_client", "reason"],
    ),
    "openvpn_view_config": tool_schema(
        "View raw OVPN and CCD content for one OpenVPN client.",
        {"client": {"type": "string"}},
        ["client"],
    ),
    "openvpn_networks": tool_schema("List tagged route networks."),
    "openvpn_network_add": tool_schema(
        "Add or update a tagged route network.",
        {
            "cidr": {"type": "string"},
            "tag": {"type": "string", "default": "default"},
            "nat": {"type": "boolean", "default": False},
            "comment": {"type": "string", "default": ""},
            "restart_nat": {"type": "boolean", "default": False},
        },
        ["cidr"],
    ),
    "openvpn_network_templates": tool_schema("List route network templates."),
    "openvpn_network_template_add": tool_schema(
        "Create a route network template from catalog CIDRs.",
        {
            "name": {"type": "string"},
            "description": {"type": "string", "default": ""},
            "cidrs": {"type": "array", "items": {"type": "string"}},
            "dns": {"type": "boolean", "default": False},
        },
        ["name", "cidrs"],
    ),
    "openvpn_apply_network_template": tool_schema(
        "Rewrite a client's CCD from a route network template. Requires exact confirm_client and a reason.",
        {
            "client": {"type": "string"},
            "confirm_client": {"type": "string"},
            "reason": {"type": "string"},
            "template": {"type": "string"},
            "vpn_ip": {"type": "string", "default": ""},
        },
        ["client", "confirm_client", "reason", "template"],
    ),
    "openvpn_apply_networks": tool_schema(
        "Rewrite a client's CCD from selected catalog CIDRs. Requires exact confirm_client and a reason.",
        {
            "client": {"type": "string"},
            "confirm_client": {"type": "string"},
            "reason": {"type": "string"},
            "cidrs": {"type": "array", "items": {"type": "string"}},
            "dns": {"type": "boolean", "default": False},
            "vpn_ip": {"type": "string", "default": ""},
        },
        ["client", "confirm_client", "reason", "cidrs"],
    ),
    "openvpn_reconnect_client": tool_schema(
        "Disconnect one connected client through OpenVPN management so it reconnects and receives new routes.",
        {
            "client": {"type": "string"},
            "confirm_client": {"type": "string"},
            "reason": {"type": "string"},
        },
        ["client", "confirm_client", "reason"],
    ),
    "openvpn_kill_client_session": tool_schema(
        "Disconnect one active client session without revoking the profile. Requires exact confirm_client and a reason.",
        {
            "client": {"type": "string"},
            "confirm_client": {"type": "string"},
            "reason": {"type": "string"},
        },
        ["client", "confirm_client", "reason"],
    ),
    "openvpn_update_ovpn": tool_schema(
        "Replace a client's OVPN file. Requires exact confirm_client and a reason.",
        {
            "client": {"type": "string"},
            "confirm_client": {"type": "string"},
            "reason": {"type": "string"},
            "content": {"type": "string"},
        },
        ["client", "confirm_client", "reason", "content"],
    ),
    "openvpn_connections": tool_schema("List current OpenVPN connections."),
    "openvpn_nat_status": tool_schema("Show ViPNet NAT counters."),
    "openvpn_network_dashboard": tool_schema("Show network observer dashboard summary and source health."),
    "openvpn_network_hosts": tool_schema(
        "List observed network hosts with optional filters.",
        {
            "q": {"type": "string", "default": ""},
            "category": {"type": "string", "default": ""},
            "status": {"type": "string", "default": ""},
            "source": {"type": "string", "default": ""},
            "network": {"type": "string", "default": ""},
            "has_hostname": {"type": "string", "enum": ["", "yes", "no"], "default": ""},
            "has_mac": {"type": "string", "enum": ["", "yes", "no"], "default": ""},
        },
    ),
    "openvpn_network_host_detail": tool_schema(
        "Inspect one observed network host by IP address.",
        {"ip": {"type": "string"}},
        ["ip"],
    ),
    "openvpn_network_sources": tool_schema("List network observer sources such as MikroTik routers."),
    "openvpn_network_interfaces": tool_schema(
        "List observed router interfaces, optionally filtered by source.",
        {"source": {"type": "string", "default": ""}},
    ),
    "openvpn_network_routes": tool_schema(
        "List observed router routes, optionally filtered by source.",
        {"source": {"type": "string", "default": ""}},
    ),
    "openvpn_network_observations": tool_schema(
        "List raw observations for one host or all hosts.",
        {"host": {"type": "string", "default": ""}},
    ),
    "openvpn_network_ipsec": tool_schema(
        "Show IPsec source health, policies, SAs and bidirectional site checks.",
        {"source": {"type": "string", "default": ""}},
    ),
    "openvpn_routeros_backups": tool_schema("List RouterOS backup and export files known to the web service."),
    "openvpn_network_logs": tool_schema(
        "Read recent network observer collection logs.",
        {"n": {"type": "integer", "enum": [30, 80, 150], "default": 80}},
    ),
    "openvpn_diagnostic_snapshot": tool_schema(
        "Collect a read-only OpenVPN, network, IPsec, RouterOS backup and log diagnostic snapshot."
    ),
    "openvpn_addressing": tool_schema("Show OpenVPN tunnel addressing plan."),
    "openvpn_validate_network_plan": tool_schema("Validate OpenVPN pool, CCDs, site routes and legacy NAT state."),
    "openvpn_site_routes": tool_schema("List managed OpenVPN site-to-site server routes."),
    "openvpn_router_instructions": tool_schema(
        "Get mode-specific router setup instructions for one client.",
        {"client": {"type": "string"}},
        ["client"],
    ),
    "openvpn_logs": tool_schema(
        "Read recent OpenVPN/vpnctl logs.",
        {"n": {"type": "integer", "enum": [30, 80, 150], "default": 80}},
    ),
}


def _string(pattern=None, minimum=1, maximum=192, nullable=False):
    value = {"type": ["string", "null"] if nullable else "string", "minLength": minimum, "maxLength": maximum}
    if pattern:
        value["pattern"] = pattern
    return value


_UUID = _string(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", maximum=36)
_SHA = _string(r"[0-9a-f]{64}", maximum=64)
_JOB = _string(r"job-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}", maximum=40)
_DEVICE = _string(r"(?:(?:machine|inventory|ad):[0-9a-f-]{36}|mac:(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2})", maximum=50)
_CATALOG = _string(r"[a-z][a-z0-9_.-]{0,127}", maximum=128)
_REASON = _string(maximum=2000)
_REVISION = {"type": "integer", "minimum": 1}
_PAGE = {"offset": {"type": "integer", "minimum": 0, "maximum": 10000}, "limit": {"type": "integer", "minimum": 1, "maximum": 100}}


def _workstation_tool(suffix, description, properties=None, required=None, mutation=False):
    fields = dict(properties or {})
    mandatory = list(required or [])
    if mutation:
        fields = {"request_id": _UUID, **fields}
        mandatory.insert(0, "request_id")
    TOOLS[WORKSTATIONS_PREFIX + suffix] = tool_schema(description, fields, mandatory)


_workstation_tool("status", "Read coarse workstation availability and globally sequential queue status.")
_workstation_tool("devices", "List reconciled devices, source revision/freshness, or inspect one device and explicit links.", {"device_key": _DEVICE, **_PAGE})
_workstation_tool("catalog", "Read approved OU IDs, software profiles and component catalog.")
_workstation_tool("search_users", "Read AD employee matches. Explicitly select GUID/SID; homonyms are never auto-selected.", {"query": _string(minimum=2, maximum=160), "limit": {"type": "integer", "minimum": 1, "maximum": 50}}, ["query"])
_workstation_tool("link_preview", "Preview an explicit device/AD relationship using a fresh complete source revision.", {"device_key": _DEVICE, "user_guid": _UUID, "computer_guid": {**_UUID, "type": ["string", "null"]}, "source_revision": _SHA}, ["device_key", "user_guid", "source_revision"], True)
_workstation_tool("link_confirm", "Confirm a reviewed relationship with exact preview revision and reason; preserve inventory ownership.", {"preview_id": _UUID, "expected_revision": _REVISION, "reason": _REASON}, ["preview_id", "expected_revision", "reason"], True)
_workstation_tool("link_end", "End an explicit link with exact revision and reason; retain its audit history.", {"link_id": _UUID, "expected_revision": _REVISION, "reason": _REASON}, ["link_id", "expected_revision", "reason"], True)
_workstation_tool("plan", "Create a protected Setup plan for an explicitly selected existing AD employee. Does not apply it.", {"machine_uuid": _UUID, "user_login": _string(r"[a-zA-Z0-9][a-zA-Z0-9._@-]{0,191}"), "user_guid": _UUID, "user_sid": _string(r"S-1-[0-9]+(?:-[0-9]+)+", maximum=192), "ou_id": _SHA, "software_profile": _CATALOG, "remote_access_profile": {"type": "string", "enum": ["none", "krfb"]}}, ["machine_uuid", "user_login", "user_guid", "user_sid", "ou_id", "software_profile"], True)
_workstation_tool("component_plan", "Plan one approved component using the existing native assignment.", {"machine_uuid": _UUID, "component_id": _CATALOG}, ["machine_uuid", "component_id"], True)
_workstation_tool("apply", "Apply the reviewed exact plan SHA/kind within native TTL. Keep this request ID; UNKNOWN forbids resubmission.", {"plan_id": _string(r"setup-(?:component-)?[0-9a-f]{64}", maximum=80), "sha256": _SHA, "kind": {"type": "string", "enum": ["full_setup", "component"]}}, ["plan_id", "sha256", "kind"], True)
_workstation_tool("operation", "Read the original operation receipt after a lost reply; never create a replacement apply.", {"operation_id": _UUID}, ["operation_id"])
_workstation_tool("jobs", "Read native workstation jobs with bounded pagination.", {"machine_uuid": _UUID, **_PAGE})
_workstation_tool("job_status", "Read native stage history, sequential queue position and technical/functional outcome.", {"job_id": _JOB}, ["job_id"])
_workstation_tool("job_events", "Read sanitized native events after the last sequence. Preserve cursors and report gaps.", {"job_id": _JOB, "after": {"type": "integer", "minimum": 0, "maximum": 10000}, "limit": {"type": "integer", "minimum": 1, "maximum": 1000}}, ["job_id"])
_workstation_tool("verify", "Explicitly verify an existing job; GET status never starts verification.", {"job_id": _JOB}, ["job_id"], True)
_workstation_tool("cancel", "Request native guarded cancellation with its exact SHA; cannot release UNKNOWN.", {"job_id": _JOB, "sha256": _SHA}, ["job_id", "sha256"], True)
_workstation_tool("reconcile", "Collect a fresh read-only AD/DNS/network/inventory comparison; never changes DNS, AD or owners.", mutation=True)
_workstation_tool("reconcile_status", "Read the original reconciliation operation.", {"operation_id": _UUID}, ["operation_id"])
_workstation_tool("findings", "Read comparison conflicts; acknowledgement is not conflict resolution.", _PAGE)
_workstation_tool("sources", "Read attempts, last complete generations and freshness independently.")
_workstation_tool("journal", "Read or export the same authorized sanitized journal with bounded cursor pagination.", {"device_key": _DEVICE, "job_id": _JOB, "component": _CATALOG, "stage": _string(r"[a-z0-9_]+", maximum=64), "severity": {"type": "string", "enum": ["info", "error"]}, "cursor": _string(maximum=1024), "limit": {"type": "integer", "minimum": 1, "maximum": 1000}, "export": {"type": "boolean"}})


class WorkstationsAPIError(RuntimeError):
    """Only fixed public error codes may cross the MCP boundary."""


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _workstations_token():
    try:
        path = os.environ[WORKSTATIONS_TOKEN_FILE_ENV]
        info = os.lstat(path)
        if not stat.S_ISREG(info.st_mode) or info.st_size > 4096 or info.st_size < 16:
            raise ValueError()
        if os.name != "nt" and (info.st_uid not in (0, os.getuid()) or info.st_mode & 0o077):
            raise ValueError()
        with open(path, "r", encoding="utf-8") as stream:
            actual = os.fstat(stream.fileno())
            if (actual.st_ino, actual.st_dev) != (info.st_ino, info.st_dev):
                raise ValueError()
            token = stream.read(4097).strip()
        if not re.fullmatch(r"[A-Za-z0-9_.~-]{16,4096}", token):
            raise ValueError()
        return token
    except (OSError, KeyError, ValueError):
        raise WorkstationsAPIError("workstations_credentials_unavailable") from None


def _workstations_request(method, path, payload):
    token = _workstations_token()
    base_url = os.environ.get(BASE_URL_ENV, "http://192.168.100.30:8088").rstrip("/")
    parsed = urllib.parse.urlsplit(base_url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment or parsed.path:
        raise WorkstationsAPIError("workstations_configuration_invalid")
    headers = {"Authorization": "Bearer " + token, "Accept": "application/json"}
    body = None
    if payload is not None:
        body = json.dumps(payload, allow_nan=False).encode("utf-8")
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(base_url + path, data=body, headers=headers, method=method)
    deadline = time.monotonic() + 60
    try:
        with urllib.request.build_opener(_NoRedirect()).open(request, timeout=60) as response:
            chunks, size = [], 0
            while True:
                if time.monotonic() >= deadline:
                    raise WorkstationsAPIError("workstations_api_timeout")
                chunk = response.read(65536)
                if not chunk:
                    break
                size += len(chunk)
                if size > 20 * 1024 * 1024:
                    raise WorkstationsAPIError("workstations_response_limit")
                chunks.append(chunk)
        value = json.loads(b"".join(chunks))
        if not isinstance(value, dict) or value.get("status") not in ("ok", "error"):
            raise ValueError()
        return value
    except urllib.error.HTTPError as exc:
        exc.close()
        code = {401: "workstations_auth_required", 403: "workstations_permission_denied", 409: "workstations_conflict", 422: "workstations_validation_invalid"}.get(exc.code, "workstations_api_unavailable")
        raise WorkstationsAPIError(code) from None
    except WorkstationsAPIError:
        raise
    except Exception:
        raise WorkstationsAPIError("workstations_api_unavailable") from None


def _workstations_call(name, arguments):
    schema = TOOLS.get(name, {}).get("inputSchema")
    if not schema or not isinstance(arguments, dict) or set(arguments) - set(schema["properties"]) or set(schema["required"]) - set(arguments):
        raise ValueError("workstations_arguments_invalid")
    for key, value in arguments.items():
        rule = schema["properties"][key]
        allowed = rule["type"] if isinstance(rule["type"], list) else [rule["type"]]
        if value is None and "null" in allowed:
            continue
        valid = (("string" in allowed and isinstance(value, str)) or ("integer" in allowed and type(value) is int) or ("boolean" in allowed and type(value) is bool))
        if not valid or ("enum" in rule and value not in rule["enum"]):
            raise ValueError("workstations_arguments_invalid")
        if isinstance(value, str):
            if not rule.get("minLength", 0) <= len(value) <= rule.get("maxLength", 4096) or ("pattern" in rule and not re.fullmatch(rule["pattern"], value)):
                raise ValueError("workstations_arguments_invalid")
            if rule.get("pattern") == _UUID["pattern"] and not uuid.UUID(value).int:
                raise ValueError("workstations_arguments_invalid")
        if type(value) is int and not rule.get("minimum", 0) <= value <= rule.get("maximum", 2**63 - 1):
            raise ValueError("workstations_arguments_invalid")
    suffix = name.removeprefix(WORKSTATIONS_PREFIX)
    values = dict(arguments)
    method, path, body = "GET", "", None
    if suffix == "devices" and "device_key" in values:
        if set(values) != {"device_key"}:
            raise ValueError("workstations_arguments_invalid")
        path = "/devices/" + urllib.parse.quote(values.pop("device_key"), safe="")
    elif suffix in ("operation", "reconcile_status"):
        path = ("/operations/" if suffix == "operation" else "/reconcile/") + values.pop("operation_id")
    elif suffix in ("job_status", "job_events", "verify", "cancel"):
        path = "/jobs/" + values.pop("job_id")
        if suffix != "job_status":
            path += {"job_events": "/events", "verify": "/verify", "cancel": "/cancel"}[suffix]
    elif suffix == "link_end":
        path = "/links/" + values.pop("link_id") + "/end"
    elif suffix == "apply":
        plan_id = values.pop("plan_id")
        if plan_id != ("setup-" if values["kind"] == "full_setup" else "setup-component-") + values["sha256"]:
            raise ValueError("workstations_arguments_invalid")
        path = "/plans/" + plan_id + "/apply"
    elif suffix == "journal":
        path = "/journal/export" if values.pop("export", False) else "/journal"
    else:
        path = {"search_users": "/directory/search", "link_preview": "/links/preview", "link_confirm": "/links/confirm", "plan": "/plans", "component_plan": "/component-plans"}.get(suffix, "/" + suffix)
    if suffix in ("search_users", "link_preview", "link_confirm", "link_end", "plan", "component_plan", "apply", "verify", "cancel", "reconcile"):
        method, body = "POST", values
    else:
        path = _query_path(path, list(values.items()))
    return api_request(method, WORKSTATIONS_API + path, body)


def api_request(method: str, path: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
    if path == WORKSTATIONS_API or path.startswith(WORKSTATIONS_API + "/"):
        return _workstations_request(method, path, payload)
    base_url = os.environ.get(BASE_URL_ENV, "http://192.168.100.30:8088").rstrip("/")
    token = os.environ.get(TOKEN_ENV, "")
    token_file = os.environ.get(TOKEN_FILE_ENV, "")
    if not token and token_file:
        token = open(token_file, "r", encoding="utf-8").read().strip()
    if not token:
        raise RuntimeError(f"{TOKEN_ENV} or {TOKEN_FILE_ENV} is required")
    body = None
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
    if payload is not None:
        body = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(f"{base_url}{path}", data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            data = response.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"API {method} {path} failed: HTTP {exc.code}: {detail}") from exc
    return json.loads(data or "{}")


def _client_path(client: str, suffix: str = "") -> str:
    if not client:
        raise ValueError("client is required")
    return f"/api/v1/clients/{urllib.parse.quote(client, safe='._-')}{suffix}"


def _query_path(path: str, params: list[tuple[str, Any]]) -> str:
    query = [(key, str(value)) for key, value in params if value not in ("", None)]
    if not query:
        return path
    return f"{path}?{urllib.parse.urlencode(query)}"


def _snapshot_section(tool_name: str, arguments: dict[str, Any] | None = None) -> dict[str, Any]:
    try:
        return call_tool(tool_name, arguments or {})
    except Exception as exc:
        return {"status": "error", "message": str(exc)}


def call_tool(name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    if name.startswith(WORKSTATIONS_PREFIX):
        return _workstations_call(name, arguments)
    if name == "openvpn_status":
        return api_request("GET", "/api/v1/status")
    if name == "openvpn_server_config":
        return api_request("GET", "/api/v1/openvpn/server-config")
    if name == "openvpn_set_status_interval":
        return api_request(
            "POST",
            "/api/v1/openvpn/status-interval",
            {"status_interval_seconds": arguments.get("status_interval_seconds")},
        )
    if name == "openvpn_enable_management":
        return api_request("POST", "/api/v1/openvpn/management/enable", {})
    if name == "openvpn_management_test":
        return api_request("GET", "/api/v1/openvpn/management/test")
    if name == "openvpn_management_status":
        return api_request("GET", "/api/v1/openvpn/management/status")
    if name == "openvpn_profiles":
        return api_request("GET", "/api/v1/profiles")
    if name == "openvpn_list_clients":
        return api_request("GET", "/api/v1/clients")
    if name == "openvpn_inspect_client":
        return api_request("GET", _client_path(str(arguments.get("client", ""))))
    if name == "openvpn_preview_client":
        client = str(arguments.get("client", ""))
        payload = {
            "profile": arguments.get("profile", ""),
            "vpn_ip": arguments.get("vpn_ip", ""),
            "client_type": arguments.get("client_type", "user"),
            "remote_lan_cidr": arguments.get("remote_lan_cidr", ""),
            "create_server_route": arguments.get("create_server_route", False),
        }
        return api_request("POST", _client_path(client, "/preview"), payload)
    if name == "openvpn_generate_client":
        client = str(arguments.get("client", ""))
        payload = {
            "profile": arguments.get("profile", ""),
            "vpn_ip": arguments.get("vpn_ip", ""),
            "client_type": arguments.get("client_type", "user"),
            "remote_lan_cidr": arguments.get("remote_lan_cidr", ""),
            "create_server_route": arguments.get("create_server_route", False),
            "comment": arguments.get("comment", ""),
        }
        return api_request("POST", _client_path(client, "/generate"), payload)
    if name == "openvpn_disable_client":
        client = str(arguments.get("client", ""))
        payload = {
            "confirm_client": arguments.get("confirm_client", ""),
            "reason": arguments.get("reason", ""),
        }
        return api_request("POST", _client_path(client, "/disable"), payload)
    if name == "openvpn_view_config":
        return api_request("GET", _client_path(str(arguments.get("client", "")), "/config"))
    if name == "openvpn_networks":
        return api_request("GET", "/api/v1/networks")
    if name == "openvpn_network_add":
        payload = {
            "cidr": arguments.get("cidr", ""),
            "tag": arguments.get("tag", "default"),
            "nat": arguments.get("nat", False),
            "comment": arguments.get("comment", ""),
            "restart_nat": arguments.get("restart_nat", False),
        }
        return api_request("POST", "/api/v1/networks/add", payload)
    if name == "openvpn_network_templates":
        return api_request("GET", "/api/v1/network-templates")
    if name == "openvpn_network_template_add":
        payload = {
            "name": arguments.get("name", ""),
            "description": arguments.get("description", ""),
            "cidrs": arguments.get("cidrs", []),
            "dns": arguments.get("dns", False),
        }
        return api_request("POST", "/api/v1/network-templates/add", payload)
    if name == "openvpn_apply_network_template":
        client = str(arguments.get("client", ""))
        payload = {
            "confirm_client": arguments.get("confirm_client", ""),
            "reason": arguments.get("reason", ""),
            "template": arguments.get("template", ""),
            "vpn_ip": arguments.get("vpn_ip", ""),
        }
        return api_request("POST", _client_path(client, "/network-template"), payload)
    if name == "openvpn_apply_networks":
        client = str(arguments.get("client", ""))
        payload = {
            "confirm_client": arguments.get("confirm_client", ""),
            "reason": arguments.get("reason", ""),
            "cidrs": arguments.get("cidrs", []),
            "dns": arguments.get("dns", False),
            "vpn_ip": arguments.get("vpn_ip", ""),
        }
        return api_request("POST", _client_path(client, "/networks"), payload)
    if name == "openvpn_update_ovpn":
        client = str(arguments.get("client", ""))
        payload = {
            "confirm_client": arguments.get("confirm_client", ""),
            "reason": arguments.get("reason", ""),
            "content": arguments.get("content", ""),
        }
        return api_request("POST", _client_path(client, "/ovpn"), payload)
    if name == "openvpn_reconnect_client":
        client = str(arguments.get("client", ""))
        payload = {
            "confirm_client": arguments.get("confirm_client", ""),
            "reason": arguments.get("reason", ""),
        }
        return api_request("POST", _client_path(client, "/reconnect"), payload)
    if name == "openvpn_kill_client_session":
        client = str(arguments.get("client", ""))
        payload = {
            "confirm_client": arguments.get("confirm_client", ""),
            "reason": arguments.get("reason", ""),
        }
        return api_request("POST", _client_path(client, "/kill-session"), payload)
    if name == "openvpn_connections":
        return api_request("GET", "/api/v1/connections")
    if name == "openvpn_nat_status":
        return api_request("GET", "/api/v1/nat-status")
    if name == "openvpn_network_dashboard":
        return api_request("GET", "/api/v1/network/dashboard")
    if name == "openvpn_network_hosts":
        return api_request(
            "GET",
            _query_path(
                "/api/v1/network/hosts",
                [
                    ("q", arguments.get("q", "")),
                    ("category", arguments.get("category", "")),
                    ("status", arguments.get("status", "")),
                    ("source", arguments.get("source", "")),
                    ("network", arguments.get("network", "")),
                    ("has_hostname", arguments.get("has_hostname", "")),
                    ("has_mac", arguments.get("has_mac", "")),
                ],
            ),
        )
    if name == "openvpn_network_host_detail":
        ip = str(arguments.get("ip", ""))
        if not ip:
            raise ValueError("ip is required")
        return api_request("GET", f"/api/v1/network/hosts/{urllib.parse.quote(ip, safe='.:')}")
    if name == "openvpn_network_sources":
        return api_request("GET", "/api/v1/network/sources")
    if name == "openvpn_network_interfaces":
        return api_request("GET", _query_path("/api/v1/network/interfaces", [("source", arguments.get("source", ""))]))
    if name == "openvpn_network_routes":
        return api_request("GET", _query_path("/api/v1/network/routes", [("source", arguments.get("source", ""))]))
    if name == "openvpn_network_observations":
        return api_request("GET", _query_path("/api/v1/network/observations", [("host", arguments.get("host", ""))]))
    if name == "openvpn_network_ipsec":
        return api_request("GET", _query_path("/api/v1/network/ipsec", [("source", arguments.get("source", ""))]))
    if name == "openvpn_routeros_backups":
        return api_request("GET", "/api/v1/network/backups")
    if name == "openvpn_network_logs":
        n = int(arguments.get("n", 80))
        return api_request("GET", f"/api/v1/network/logs?n={n}")
    if name == "openvpn_diagnostic_snapshot":
        sections = {
            "status": _snapshot_section("openvpn_status"),
            "server_config": _snapshot_section("openvpn_server_config"),
            "management_test": _snapshot_section("openvpn_management_test"),
            "connections": _snapshot_section("openvpn_connections"),
            "nat": _snapshot_section("openvpn_nat_status"),
            "network_dashboard": _snapshot_section("openvpn_network_dashboard"),
            "network_sources": _snapshot_section("openvpn_network_sources"),
            "ipsec": _snapshot_section("openvpn_network_ipsec"),
            "routeros_backups": _snapshot_section("openvpn_routeros_backups"),
            "network_logs": _snapshot_section("openvpn_network_logs", {"n": 30}),
        }
        failed = [key for key, value in sections.items() if value.get("status") == "error"]
        return {"status": "partial" if failed else "ok", "failed_sections": failed, "sections": sections}
    if name == "openvpn_addressing":
        return api_request("GET", "/api/v1/openvpn/addressing")
    if name == "openvpn_validate_network_plan":
        return api_request("POST", "/api/v1/openvpn/validate-network-plan", {})
    if name == "openvpn_site_routes":
        return api_request("GET", "/api/v1/site-routes")
    if name == "openvpn_router_instructions":
        return api_request("GET", _client_path(str(arguments.get("client", "")), "/router-instructions"))
    if name == "openvpn_logs":
        n = int(arguments.get("n", 80))
        return api_request("GET", f"/api/v1/logs?n={n}")
    raise ValueError(f"unknown tool: {name}")


def result_response(message_id: Any, result: dict[str, Any]) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": message_id, "result": result}


def error_response(message_id: Any, code: int, message: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": message_id, "error": {"code": code, "message": message}}


def handle_message(message: dict[str, Any]) -> dict[str, Any] | None:
    method = message.get("method")
    message_id = message.get("id")
    try:
        if method == "initialize":
            return result_response(
                message_id,
                {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": "openvpn-control", "version": "0.2.0"},
                },
            )
        if method == "notifications/initialized":
            return None
        if method == "tools/list":
            tools = [{"name": name, **schema} for name, schema in TOOLS.items()]
            return result_response(message_id, {"tools": tools})
        if method == "tools/call":
            params = message.get("params") or {}
            name = params.get("name")
            arguments = params.get("arguments") or {}
            data = call_tool(str(name), arguments)
            return result_response(
                message_id,
                {"content": [{"type": "text", "text": json.dumps(data, ensure_ascii=False, indent=2)}]},
            )
        return error_response(message_id, -32601, f"method not found: {method}")
    except Exception as exc:
        if method == "tools/call" and str((message.get("params") or {}).get("name", "")).startswith(WORKSTATIONS_PREFIX):
            code = str(exc) if isinstance(exc, WorkstationsAPIError) else ("workstations_arguments_invalid" if isinstance(exc, ValueError) else "workstations_api_unavailable")
            return error_response(message_id, -32000, code)
        return error_response(message_id, -32000, str(exc))


def main() -> int:
    configure_stdio()
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            message = json.loads(line)
            response = handle_message(message)
        except Exception as exc:
            response = error_response(None, -32700, str(exc))
        if response is not None:
            print(json.dumps(response, ensure_ascii=False), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
