from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import re
from typing import Any, Literal

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from .audit import write_audit
from .auth import authorize_network_change
from .auto_sync import force_client_sync
from .config import get_settings
from .db import get_db
from .netctl_client import NetctlError, run_netctl
from .netopsctl_client import NetworkControlError, run_network_control
from .network_observer import filter_unified_hosts, list_from as network_list_from, merge_unified_hosts
from .network_paths_adapter import get_network_path, list_network_paths
from .routeros_backups import list_routeros_backups
from .vpnctl_client import VpnctlError, run_vpnctl

CLIENT_RE = re.compile(r"^[A-Za-z0-9._-]+$")
IDEMPOTENCY_KEY_RE = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")

router = APIRouter(prefix="/api/v1", tags=["api"])


class ClientProfileRequest(BaseModel):
    profile: str
    vpn_ip: str = ""
    comment: str = ""
    client_type: Literal["user", "router_nat", "router_site_to_site"] = "user"
    remote_lan_cidr: str = ""
    create_server_route: bool = False


class DisableClientRequest(BaseModel):
    confirm_client: str = ""
    reason: str = Field(min_length=1)


class ClientContentEditRequest(BaseModel):
    confirm_client: str = ""
    reason: str = Field(min_length=1)
    content: str


class ClientNetworksApplyRequest(BaseModel):
    confirm_client: str = ""
    reason: str = Field(min_length=1)
    cidrs: list[str]
    vpn_ip: str = ""
    dns: bool = False


class ClientNetworkTemplateApplyRequest(BaseModel):
    confirm_client: str = ""
    reason: str = Field(min_length=1)
    template: str
    vpn_ip: str = ""


class ReconnectClientRequest(BaseModel):
    confirm_client: str = ""
    reason: str = Field(min_length=1)


class KillClientSessionRequest(BaseModel):
    confirm_client: str = ""
    reason: str = "session kill requested through API"


class StatusIntervalRequest(BaseModel):
    status_interval_seconds: int = Field(ge=5, le=300)


class NetworkRequest(BaseModel):
    cidr: str
    tag: str = "default"
    nat: bool = False
    comment: str = ""
    restart_nat: bool = False


class NetworkTemplateRequest(BaseModel):
    name: str
    description: str = ""
    cidrs: list[str] = Field(default_factory=list)
    dns: bool = False


class VipnetNetworkRequest(BaseModel):
    cidr: str
    restart_nat: bool = True


class SiteRouteRequest(BaseModel):
    cidr: str
    client: str = ""
    restart: bool = False


class ContextUserCreateRequest(BaseModel):
    user_key: str = Field(min_length=1, max_length=160)
    display_name: str = Field(min_length=1, max_length=240)
    department: str = Field(default="", max_length=160)


class ContextUserAssetBindingRequest(BaseModel):
    asset_key: str = Field(min_length=1, max_length=240)
    relation: Literal["primary_user", "shared_user", "temporary_user", "owner"]
    confidence: int = Field(ge=0, le=100)
    reason: str = Field(min_length=1, max_length=1000)


class ContextBindingRetireRequest(BaseModel):
    reason: str = Field(min_length=1, max_length=1000)


class NetworkSessionCreateRequest(BaseModel):
    user_key: str = Field(min_length=1, max_length=160)
    session_key: str = Field(min_length=1, max_length=255)
    source_type: Literal["captive_portal", "radius", "directory_agent", "manual"]
    started_at: str = Field(min_length=1, max_length=64)
    asset_key: str = Field(default="", max_length=240)
    evidence: dict[str, Any] = Field(default_factory=dict)


class NetworkSessionCloseRequest(BaseModel):
    ended_at: str = Field(min_length=1, max_length=64)


class NetworkChangePlanCreateRequest(BaseModel):
    subject_type: Literal["asset", "user"]
    subject_key: str = Field(min_length=1, max_length=240)
    desired_state: Literal["allow", "deny"]
    reason: str = Field(min_length=1, max_length=1000)


def api_response(data: dict[str, Any]) -> dict[str, Any]:
    return {"status": "ok", "data": data}


def error_detail(exc: VpnctlError) -> str:
    suffix = exc.stderr.strip() or exc.stdout.strip()
    if suffix:
        return f"{exc.message}: {suffix[:500]}"
    return exc.message


def require_client_name(client: str) -> str:
    if not CLIENT_RE.match(client or ""):
        raise HTTPException(status_code=400, detail="invalid client name")
    return client


def require_api_actor(authorization: str | None = Header(default=None)) -> str:
    settings = get_settings()
    if not settings.api_token_hash:
        raise HTTPException(status_code=503, detail="API token is not configured")
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Bearer token required")
    token = authorization.removeprefix("Bearer ").strip()
    digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
    if not hmac.compare_digest(digest, settings.api_token_hash):
        raise HTTPException(status_code=401, detail="Invalid bearer token")
    return settings.api_actor


def call_vpnctl(args: list[str], timeout: int | None = None) -> dict[str, Any]:
    try:
        return run_vpnctl(args, timeout=timeout)
    except VpnctlError as exc:
        raise HTTPException(status_code=502, detail=error_detail(exc)) from exc


def netctl_error_detail(exc: NetctlError) -> str:
    suffix = exc.stderr.strip() or exc.stdout.strip()
    if suffix:
        return f"{exc.message}: {suffix[:500]}"
    return exc.message


def call_netctl(args: list[str], timeout: int | None = None) -> dict[str, Any]:
    try:
        return run_netctl(args, timeout=timeout)
    except NetctlError as exc:
        raise HTTPException(status_code=502, detail=netctl_error_detail(exc)) from exc


def call_network_control(
    action: str,
    payload: dict[str, Any],
    *,
    actor: str,
    session_id: str,
    authorization_id: str,
) -> dict[str, Any]:
    try:
        return run_network_control(
            action, payload, actor=actor, session_id=session_id,
            authorization_id=authorization_id,
        )
    except NetworkControlError as exc:
        raise HTTPException(status_code=502, detail=exc.message) from exc


def _network_change(
    action: str,
    payload: dict[str, Any],
    *,
    required_scope: str,
    request: Request,
    authorization: str | None,
    db: Session,
    idempotency_key: str = "",
) -> dict[str, Any]:
    actor = authorize_network_change(request, authorization, db, required_scope)
    request_id = str(getattr(request.state, "request_id", "")) or "api-request"
    try:
        result = call_network_control(
            action, payload, actor=actor, session_id=request_id,
            authorization_id=f"{idempotency_key or request_id}:{action}",
        )
    except HTTPException as exc:
        write_audit(db, request, actor, f"api-network-change-{action}", "error", str(exc.detail), target_client=str(payload.get("plan_key") or ""))
        raise
    write_audit(db, request, actor, f"api-network-change-{action}", "ok", "broker accepted request", target_client=str(payload.get("plan_key") or result.get("plan_key") or ""))
    return result


def _require_idempotency_key(value: str | None) -> str:
    if not value or not IDEMPOTENCY_KEY_RE.fullmatch(value):
        raise HTTPException(status_code=400, detail="Idempotency-Key is required")
    return value


@router.post("/network-changes/plans")
def api_network_change_plan_create(
    payload: NetworkChangePlanCreateRequest,
    request: Request,
    authorization: str | None = Header(default=None),
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
    db: Session = Depends(get_db),
):
    return api_response(_network_change(
        "plan.create", {"plan": payload.model_dump()}, required_scope="network:plan",
        request=request, authorization=authorization, db=db, idempotency_key=_require_idempotency_key(idempotency_key),
    ))


@router.get("/network-changes/plans/{plan_key}")
def api_network_change_plan_inspect(
    plan_key: str,
    request: Request,
    authorization: str | None = Header(default=None),
    db: Session = Depends(get_db),
):
    return api_response(_network_change(
        "plan.inspect", {"plan_key": plan_key}, required_scope="network:read",
        request=request, authorization=authorization, db=db,
    ))


def _network_change_plan_action(
    action: Literal["plan.approve", "plan.apply", "plan.verify", "plan.rollback"],
    plan_key: str,
    required_scope: str,
    request: Request,
    authorization: str | None,
    db: Session,
    idempotency_key: str | None,
):
    return api_response(_network_change(
        action, {"plan_key": plan_key}, required_scope=required_scope,
        request=request, authorization=authorization, db=db, idempotency_key=_require_idempotency_key(idempotency_key),
    ))


@router.post("/network-changes/plans/{plan_key}/approve")
def api_network_change_plan_approve(plan_key: str, request: Request, authorization: str | None = Header(default=None), idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"), db: Session = Depends(get_db)):
    return _network_change_plan_action("plan.approve", plan_key, "network:plan", request, authorization, db, idempotency_key)


@router.post("/network-changes/plans/{plan_key}/apply")
def api_network_change_plan_apply(plan_key: str, request: Request, authorization: str | None = Header(default=None), idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"), db: Session = Depends(get_db)):
    return _network_change_plan_action("plan.apply", plan_key, "network:apply", request, authorization, db, idempotency_key)


@router.post("/network-changes/plans/{plan_key}/verify")
def api_network_change_plan_verify(plan_key: str, request: Request, authorization: str | None = Header(default=None), idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"), db: Session = Depends(get_db)):
    return _network_change_plan_action("plan.verify", plan_key, "network:apply", request, authorization, db, idempotency_key)


@router.post("/network-changes/plans/{plan_key}/rollback")
def api_network_change_plan_rollback(plan_key: str, request: Request, authorization: str | None = Header(default=None), idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"), db: Session = Depends(get_db)):
    return _network_change_plan_action("plan.rollback", plan_key, "network:rollback", request, authorization, db, idempotency_key)


def profile_command_args(command: str, client: str, payload: ClientProfileRequest) -> list[str]:
    args = [command, client, payload.profile]
    if payload.vpn_ip:
        args.append(payload.vpn_ip)
    args.extend(["--client-type", payload.client_type])
    if payload.remote_lan_cidr:
        args.extend(["--remote-lan", payload.remote_lan_cidr])
    if payload.create_server_route:
        args.append("--create-server-route")
    return args


def require_confirm_client(payload_confirm: str, client: str) -> None:
    if payload_confirm != client:
        raise HTTPException(status_code=400, detail="confirm_client must match client")


def attach_sync_status(
    data: dict[str, Any],
    request: Request,
    db: Session,
    actor: str,
    reason: str,
) -> dict[str, Any]:
    sync_data, sync_error = force_client_sync(db, request, actor, reason, action="api-auto-sync")
    if sync_error:
        data["auto_sync"] = {"status": "error", "message": sync_error}
    else:
        data["auto_sync"] = {"status": "ok", "imported_or_updated": sync_data.get("imported_or_updated", 0)}
    return data


def attach_route_refresh_status(
    data: dict[str, Any],
    request: Request,
    db: Session,
    actor: str,
    client: str,
    reason: str,
) -> dict[str, Any]:
    try:
        reconnect_data = run_vpnctl(["reconnect-client", client, "--reason", reason], timeout=60)
    except VpnctlError as exc:
        detail = error_detail(exc)
        data["route_refresh"] = {"status": "error", "message": detail}
        write_audit(db, request, actor, "api-route-refresh", "error", detail, target_client=client)
        return data
    data["route_refresh"] = reconnect_data
    write_audit(db, request, actor, "api-route-refresh", "ok", reason, target_client=client)
    return data


@router.get("/status")
def api_status(actor: str = Depends(require_api_actor)):
    return api_response(call_vpnctl(["status"]))


@router.get("/runtime-health")
def api_runtime_health(actor: str = Depends(require_api_actor)):
    return api_response(call_vpnctl(["runtime-health"], timeout=15))


@router.get("/openvpn/server-config")
def api_openvpn_server_config(actor: str = Depends(require_api_actor)):
    return api_response(call_vpnctl(["server-config", "inspect"]))


@router.get("/openvpn/addressing")
def api_openvpn_addressing(actor: str = Depends(require_api_actor)):
    data = call_vpnctl(["validate-network-plan"])
    return api_response(data.get("addressing", {}))


@router.post("/openvpn/validate-network-plan")
def api_openvpn_validate_network_plan(actor: str = Depends(require_api_actor)):
    return api_response(call_vpnctl(["validate-network-plan"]))


@router.post("/openvpn/status-interval")
def api_openvpn_status_interval(
    payload: StatusIntervalRequest,
    request: Request,
    actor: str = Depends(require_api_actor),
    db: Session = Depends(get_db),
):
    try:
        data = run_vpnctl(
            [
                "server-config",
                "apply",
                "--status-interval",
                str(payload.status_interval_seconds),
                "--status-version",
                "2",
                "--restart",
            ],
            timeout=180,
        )
    except VpnctlError as exc:
        write_audit(db, request, actor, "api-openvpn-status-interval", "error", error_detail(exc))
        raise HTTPException(status_code=502, detail=error_detail(exc)) from exc
    write_audit(db, request, actor, "api-openvpn-status-interval", "ok", str(payload.status_interval_seconds))
    return api_response(data)


@router.post("/openvpn/management/enable")
def api_openvpn_management_enable(
    request: Request,
    actor: str = Depends(require_api_actor),
    db: Session = Depends(get_db),
):
    try:
        data = run_vpnctl(
            [
                "server-config",
                "apply",
                "--enable-management",
                "--management-socket",
                "/run/openvpn/server.sock",
                "--management-client-group",
                "openvpn-web",
                "--management-log-cache",
                "300",
                "--restart",
            ],
            timeout=180,
        )
    except VpnctlError as exc:
        write_audit(db, request, actor, "api-openvpn-management-enable", "error", error_detail(exc))
        raise HTTPException(status_code=502, detail=error_detail(exc)) from exc
    write_audit(db, request, actor, "api-openvpn-management-enable", "ok", "enable management")
    return api_response(data)


@router.get("/openvpn/management/test")
def api_openvpn_management_test(actor: str = Depends(require_api_actor)):
    return api_response(call_vpnctl(["management", "test"]))


@router.get("/openvpn/management/status")
def api_openvpn_management_status(actor: str = Depends(require_api_actor)):
    return api_response(call_vpnctl(["management", "status"]))


@router.get("/profiles")
def api_profiles(actor: str = Depends(require_api_actor)):
    return api_response(call_vpnctl(["profiles"]))


@router.get("/clients")
def api_clients(actor: str = Depends(require_api_actor)):
    return api_response(call_vpnctl(["list"]))


@router.post("/clients/sync")
def api_clients_sync(
    request: Request,
    actor: str = Depends(require_api_actor),
    db: Session = Depends(get_db),
):
    try:
        data = run_vpnctl(["sync"], timeout=180)
    except VpnctlError as exc:
        write_audit(db, request, actor, "api-sync", "error", error_detail(exc))
        raise HTTPException(status_code=502, detail=error_detail(exc)) from exc
    write_audit(db, request, actor, "api-sync", "ok", f"count={data.get('imported_or_updated', 0)}")
    return api_response(data)


@router.get("/clients/{client}")
def api_client_detail(client: str, actor: str = Depends(require_api_actor)):
    return api_response(call_vpnctl(["inspect", require_client_name(client)]))


@router.post("/clients/{client}/preview")
def api_client_preview(
    client: str,
    payload: ClientProfileRequest,
    actor: str = Depends(require_api_actor),
):
    client = require_client_name(client)
    return api_response(call_vpnctl(profile_command_args("preview", client, payload)))


@router.post("/clients/{client}/generate")
def api_client_generate(
    client: str,
    payload: ClientProfileRequest,
    request: Request,
    actor: str = Depends(require_api_actor),
    db: Session = Depends(get_db),
):
    client = require_client_name(client)
    args = profile_command_args("generate", client, payload)
    args.extend(["--comment", payload.comment])
    try:
        data = run_vpnctl(args, timeout=180)
    except VpnctlError as exc:
        write_audit(db, request, actor, "api-generate", "error", error_detail(exc), target_client=client)
        raise HTTPException(status_code=502, detail=error_detail(exc)) from exc
    write_audit(db, request, actor, "api-generate", "ok", f"profile={payload.profile}", target_client=client)
    attach_sync_status(data, request, db, actor, f"after API generate {client}")
    return api_response(data)


@router.get("/clients/{client}/router-instructions")
def api_client_router_instructions(client: str, actor: str = Depends(require_api_actor)):
    data = call_vpnctl(["inspect", require_client_name(client)])
    return api_response(
        {
            "client": client,
            "client_type": data.get("client_type") or (data.get("registry") or {}).get("client_type") or "user",
            "remote_lan_cidr": data.get("remote_lan_cidr") or (data.get("registry") or {}).get("remote_lan_cidr"),
            "router_instructions": data.get("router_instructions", []),
        }
    )


@router.post("/clients/{client}/disable")
def api_client_disable(
    client: str,
    payload: DisableClientRequest,
    request: Request,
    actor: str = Depends(require_api_actor),
    db: Session = Depends(get_db),
):
    client = require_client_name(client)
    require_confirm_client(payload.confirm_client, client)
    try:
        data = run_vpnctl(["disable", client, "--reason", payload.reason, "--kill-active"], timeout=180)
    except VpnctlError as exc:
        write_audit(db, request, actor, "api-disable", "error", error_detail(exc), target_client=client)
        raise HTTPException(status_code=502, detail=error_detail(exc)) from exc
    write_audit(db, request, actor, "api-disable", "ok", payload.reason, target_client=client)
    attach_sync_status(data, request, db, actor, f"after API disable {client}")
    return api_response(data)


@router.get("/clients/{client}/config")
def api_client_config(client: str, actor: str = Depends(require_api_actor)):
    return api_response(call_vpnctl(["config-view", require_client_name(client)]))


@router.post("/clients/{client}/networks")
def api_client_networks_apply(
    client: str,
    payload: ClientNetworksApplyRequest,
    request: Request,
    actor: str = Depends(require_api_actor),
    db: Session = Depends(get_db),
):
    client = require_client_name(client)
    require_confirm_client(payload.confirm_client, client)
    args = ["client-networks-apply", client]
    for cidr in payload.cidrs:
        args.extend(["--cidr", cidr])
    if payload.vpn_ip:
        args.append(payload.vpn_ip)
    if payload.dns:
        args.append("--dns")
    args.extend(["--reason", payload.reason])
    try:
        data = run_vpnctl(args, timeout=180)
    except VpnctlError as exc:
        write_audit(db, request, actor, "api-networks-apply", "error", error_detail(exc), target_client=client)
        raise HTTPException(status_code=502, detail=error_detail(exc)) from exc
    write_audit(db, request, actor, "api-networks-apply", "ok", payload.reason, target_client=client)
    attach_sync_status(data, request, db, actor, f"after API networks apply {client}")
    attach_route_refresh_status(data, request, db, actor, client, "route refresh after API networks apply")
    return api_response(data)


@router.post("/clients/{client}/network-template")
def api_client_network_template_apply(
    client: str,
    payload: ClientNetworkTemplateApplyRequest,
    request: Request,
    actor: str = Depends(require_api_actor),
    db: Session = Depends(get_db),
):
    client = require_client_name(client)
    require_confirm_client(payload.confirm_client, client)
    args = ["client-template-apply", client, payload.template]
    if payload.vpn_ip:
        args.append(payload.vpn_ip)
    args.extend(["--reason", payload.reason])
    try:
        data = run_vpnctl(args, timeout=180)
    except VpnctlError as exc:
        write_audit(db, request, actor, "api-template-apply", "error", error_detail(exc), target_client=client)
        raise HTTPException(status_code=502, detail=error_detail(exc)) from exc
    write_audit(db, request, actor, "api-template-apply", "ok", payload.reason, target_client=client)
    attach_sync_status(data, request, db, actor, f"after API template apply {client}")
    attach_route_refresh_status(data, request, db, actor, client, "route refresh after API template apply")
    return api_response(data)


@router.post("/clients/{client}/ovpn")
def api_client_ovpn_update(
    client: str,
    payload: ClientContentEditRequest,
    request: Request,
    actor: str = Depends(require_api_actor),
    db: Session = Depends(get_db),
):
    client = require_client_name(client)
    require_confirm_client(payload.confirm_client, client)
    try:
        data = run_vpnctl(["ovpn-update", client, "--content", payload.content, "--reason", payload.reason], timeout=180)
    except VpnctlError as exc:
        write_audit(db, request, actor, "api-ovpn-update", "error", error_detail(exc), target_client=client)
        raise HTTPException(status_code=502, detail=error_detail(exc)) from exc
    write_audit(db, request, actor, "api-ovpn-update", "ok", payload.reason, target_client=client)
    attach_sync_status(data, request, db, actor, f"after API OVPN update {client}")
    return api_response(data)


@router.post("/clients/{client}/reconnect")
def api_client_reconnect(
    client: str,
    payload: ReconnectClientRequest,
    request: Request,
    actor: str = Depends(require_api_actor),
    db: Session = Depends(get_db),
):
    client = require_client_name(client)
    require_confirm_client(payload.confirm_client, client)
    try:
        data = run_vpnctl(["reconnect-client", client, "--reason", payload.reason], timeout=60)
    except VpnctlError as exc:
        write_audit(db, request, actor, "api-reconnect", "error", error_detail(exc), target_client=client)
        raise HTTPException(status_code=502, detail=error_detail(exc)) from exc
    write_audit(db, request, actor, "api-reconnect", "ok", payload.reason, target_client=client)
    return api_response(data)


@router.post("/clients/{client}/kill-session")
def api_client_kill_session(
    client: str,
    payload: KillClientSessionRequest,
    request: Request,
    actor: str = Depends(require_api_actor),
    db: Session = Depends(get_db),
):
    client = require_client_name(client)
    require_confirm_client(payload.confirm_client, client)
    try:
        data = run_vpnctl(["management", "kill", client], timeout=60)
    except VpnctlError as exc:
        write_audit(db, request, actor, "api-management-kill", "error", error_detail(exc), target_client=client)
        raise HTTPException(status_code=502, detail=error_detail(exc)) from exc
    write_audit(db, request, actor, "api-management-kill", "ok", payload.reason, target_client=client)
    return api_response(data)


@router.get("/connections")
def api_connections(actor: str = Depends(require_api_actor)):
    data = call_vpnctl(["connected", "--source", "auto"])
    for row in data.get("connected", []):
        if isinstance(row, dict):
            row.pop("connected_since", None)
    return api_response(data)


@router.get("/networks")
def api_networks(actor: str = Depends(require_api_actor)):
    return api_response(call_vpnctl(["networks", "list"]))


@router.post("/networks/add")
def api_network_add(
    payload: NetworkRequest,
    request: Request,
    actor: str = Depends(require_api_actor),
    db: Session = Depends(get_db),
):
    args = ["networks", "add", payload.cidr, "--tag", payload.tag]
    if payload.comment:
        args.extend(["--comment", payload.comment])
    args.append("--nat" if payload.nat else "--no-nat")
    if payload.restart_nat:
        args.append("--restart-nat")
    try:
        data = run_vpnctl(args, timeout=180)
    except VpnctlError as exc:
        write_audit(db, request, actor, "api-network-add", "error", error_detail(exc))
        raise HTTPException(status_code=502, detail=error_detail(exc)) from exc
    write_audit(db, request, actor, "api-network-add", "ok", payload.cidr)
    return api_response(data)


@router.post("/networks/remove")
def api_network_remove(
    payload: NetworkRequest,
    request: Request,
    actor: str = Depends(require_api_actor),
    db: Session = Depends(get_db),
):
    args = ["networks", "remove", payload.cidr]
    if payload.restart_nat:
        args.append("--restart-nat")
    try:
        data = run_vpnctl(args, timeout=180)
    except VpnctlError as exc:
        write_audit(db, request, actor, "api-network-remove", "error", error_detail(exc))
        raise HTTPException(status_code=502, detail=error_detail(exc)) from exc
    write_audit(db, request, actor, "api-network-remove", "ok", payload.cidr)
    return api_response(data)


@router.get("/network-templates")
def api_network_templates(actor: str = Depends(require_api_actor)):
    return api_response(call_vpnctl(["network-templates", "list"]))


@router.post("/network-templates/add")
def api_network_template_add(
    payload: NetworkTemplateRequest,
    request: Request,
    actor: str = Depends(require_api_actor),
    db: Session = Depends(get_db),
):
    args = ["network-templates", "add", payload.name, "--description", payload.description]
    for cidr in payload.cidrs:
        args.extend(["--cidr", cidr])
    if payload.dns:
        args.append("--dns")
    try:
        data = run_vpnctl(args, timeout=180)
    except VpnctlError as exc:
        write_audit(db, request, actor, "api-network-template-add", "error", error_detail(exc))
        raise HTTPException(status_code=502, detail=error_detail(exc)) from exc
    write_audit(db, request, actor, "api-network-template-add", "ok", payload.name)
    return api_response(data)


@router.post("/network-templates/remove")
def api_network_template_remove(
    payload: NetworkTemplateRequest,
    request: Request,
    actor: str = Depends(require_api_actor),
    db: Session = Depends(get_db),
):
    try:
        data = run_vpnctl(["network-templates", "remove", payload.name], timeout=180)
    except VpnctlError as exc:
        write_audit(db, request, actor, "api-network-template-remove", "error", error_detail(exc))
        raise HTTPException(status_code=502, detail=error_detail(exc)) from exc
    write_audit(db, request, actor, "api-network-template-remove", "ok", payload.name)
    return api_response(data)


@router.get("/vipnet-nets")
def api_vipnet_nets(actor: str = Depends(require_api_actor)):
    return api_response(call_vpnctl(["vipnet-nets", "list"]))


@router.post("/vipnet-nets/add")
def api_vipnet_add(
    payload: VipnetNetworkRequest,
    request: Request,
    actor: str = Depends(require_api_actor),
    db: Session = Depends(get_db),
):
    try:
        cidr = str(ipaddress.ip_network(payload.cidr, strict=False))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=f"invalid CIDR: {exc}") from exc
    args = ["vipnet-nets", "add", cidr]
    if payload.restart_nat:
        args.append("--restart-nat")
    try:
        data = run_vpnctl(args, timeout=180)
    except VpnctlError as exc:
        write_audit(db, request, actor, "api-vipnet-add", "error", error_detail(exc))
        raise HTTPException(status_code=502, detail=error_detail(exc)) from exc
    write_audit(db, request, actor, "api-vipnet-add", "ok", cidr)
    return api_response(data)


@router.post("/vipnet-nets/remove")
def api_vipnet_remove(
    payload: VipnetNetworkRequest,
    request: Request,
    actor: str = Depends(require_api_actor),
    db: Session = Depends(get_db),
):
    try:
        cidr = str(ipaddress.ip_network(payload.cidr, strict=False))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=f"invalid CIDR: {exc}") from exc
    args = ["vipnet-nets", "remove", cidr]
    if payload.restart_nat:
        args.append("--restart-nat")
    try:
        data = run_vpnctl(args, timeout=180)
    except VpnctlError as exc:
        write_audit(db, request, actor, "api-vipnet-remove", "error", error_detail(exc))
        raise HTTPException(status_code=502, detail=error_detail(exc)) from exc
    write_audit(db, request, actor, "api-vipnet-remove", "ok", cidr)
    return api_response(data)


@router.get("/nat-status")
def api_nat_status(actor: str = Depends(require_api_actor)):
    return api_response(call_vpnctl(["nat-status"]))


@router.get("/network/dashboard")
def api_network_dashboard(actor: str = Depends(require_api_actor)):
    dashboard = call_netctl(["dashboard"])
    connected = call_vpnctl(["connected", "--source", "auto"])
    dashboard.setdefault("summary", {})["vpn_connected"] = len(network_list_from(connected, "connected"))
    return api_response(dashboard)


@router.get("/context/search")
def api_context_search(
    q: str = Query(min_length=1),
    limit: int = Query(default=25, ge=1, le=100),
    actor: str = Depends(require_api_actor),
):
    return api_response(call_netctl(["context-view", "search", "--query", q, "--limit", str(limit)]))


@router.get("/context/assets/{asset_key}")
def api_context_asset(asset_key: str, actor: str = Depends(require_api_actor)):
    return api_response(call_netctl(["context-view", "asset", "--asset-key", asset_key]))


@router.get("/context/topology")
def api_context_topology(
    site: str = Query(default="", max_length=128),
    state: str = Query(default=""),
    depth: int = Query(default=4, ge=1, le=32),
    actor: str = Depends(require_api_actor),
):
    if state not in {"", "confirmed", "inferred", "ambiguous", "conflicting"}:
        raise HTTPException(status_code=422, detail="invalid topology state")
    args = ["context-view", "topology"]
    if site:
        args.extend(["--site", site])
    if state:
        args.extend(["--state", state])
    args.extend(["--depth", str(depth)])
    return api_response(call_netctl(args))


@router.get("/context/findings")
def api_context_findings(
    status: str = Query(default="open"),
    actor: str = Depends(require_api_actor),
):
    if status not in {"open", "acknowledged", "resolved"}:
        raise HTTPException(status_code=422, detail="invalid finding status")
    return api_response(call_netctl(["context-view", "findings", "--status", status]))


@router.get("/context/path")
def api_context_path(
    asset_key: str = Query(min_length=1, max_length=255),
    destination: str = Query(min_length=1, max_length=64),
    protocol: str = Query(default="tcp", pattern="^(tcp|udp|icmp)$"),
    port: int | None = Query(default=None, ge=1, le=65535),
    actor: str = Depends(require_api_actor),
):
    args = [
        "path", "explain", "--asset-key", asset_key,
        "--destination", destination, "--protocol", protocol,
    ]
    if port is not None:
        args.extend(["--port", str(port)])
    return api_response(call_netctl(args))


@router.post("/context/users")
def api_context_user_create(
    payload: ContextUserCreateRequest,
    request: Request,
    actor: str = Depends(require_api_actor),
    db: Session = Depends(get_db),
):
    data = call_netctl([
        "users", "add", "--user-key", payload.user_key,
        "--display-name", payload.display_name, "--department", payload.department,
    ])
    write_audit(db, request, actor, "api-context-user-create", "ok", payload.user_key)
    return api_response(data)


@router.post("/context/users/{user_key}/asset-bindings")
def api_context_user_bind_asset(
    user_key: str,
    payload: ContextUserAssetBindingRequest,
    request: Request,
    actor: str = Depends(require_api_actor),
    db: Session = Depends(get_db),
):
    data = call_netctl([
        "users", "bind-asset", "--user-key", user_key,
        "--asset-key", payload.asset_key, "--relation", payload.relation,
        "--confidence", str(payload.confidence), "--reason", payload.reason,
    ])
    write_audit(db, request, actor, "api-context-user-bind-asset", "ok", user_key)
    return api_response(data)


@router.get("/context/users/{user_key}")
def api_context_user_inspect(user_key: str, actor: str = Depends(require_api_actor)):
    return api_response(call_netctl(["users", "inspect", "--user-key", user_key]))


@router.post("/context/network-sessions")
def api_context_network_session_create(
    payload: NetworkSessionCreateRequest,
    request: Request,
    actor: str = Depends(require_api_actor),
    db: Session = Depends(get_db),
):
    data = call_netctl([
        "network-sessions", "open", "--user-key", payload.user_key, "--session-key", payload.session_key,
        "--source-type", payload.source_type, "--started-at", payload.started_at,
        "--asset-key", payload.asset_key, "--evidence", json.dumps(payload.evidence, sort_keys=True),
    ])
    write_audit(db, request, actor, "api-context-network-session-create", "ok", payload.session_key)
    return api_response(data)


@router.post("/context/network-sessions/{session_key}/close")
def api_context_network_session_close(
    session_key: str,
    payload: NetworkSessionCloseRequest,
    request: Request,
    actor: str = Depends(require_api_actor),
    db: Session = Depends(get_db),
):
    data = call_netctl(["network-sessions", "close", "--session-key", session_key, "--ended-at", payload.ended_at])
    write_audit(db, request, actor, "api-context-network-session-close", "ok", session_key)
    return api_response(data)


@router.delete("/context/user-asset-bindings/{binding_id}")
def api_context_user_retire_binding(
    binding_id: int,
    payload: ContextBindingRetireRequest,
    request: Request,
    actor: str = Depends(require_api_actor),
    db: Session = Depends(get_db),
):
    data = call_netctl([
        "users", "retire-binding", "--binding-id", str(binding_id), "--reason", payload.reason,
    ])
    write_audit(db, request, actor, "api-context-user-retire-binding", "ok", str(binding_id))
    return api_response(data)


@router.get("/network/paths")
def api_network_paths(actor: str = Depends(require_api_actor)):
    return api_response({"paths": list_network_paths()})


@router.get("/network/paths/{role}")
def api_network_path_detail(role: str, actor: str = Depends(require_api_actor)):
    path = get_network_path(role)
    if path is None:
        raise HTTPException(status_code=404, detail="network path not found")
    return api_response({"path": path})


@router.get("/network/hosts")
def api_network_hosts(
    actor: str = Depends(require_api_actor),
    q: str = Query(default=""),
    category: str = Query(default="all"),
    status: str = Query(default="all"),
    source: str = Query(default="all"),
    network: str = Query(default="all"),
    has_hostname: str = Query(default=""),
    has_mac: str = Query(default=""),
):
    net_hosts = call_netctl(["hosts", "list"])
    connected = call_vpnctl(["connected", "--source", "auto"])
    clients = call_vpnctl(["list"])
    rows = merge_unified_hosts(
        network_list_from(net_hosts, "hosts"),
        network_list_from(connected, "connected"),
        network_list_from(clients, "clients"),
    )
    rows = filter_unified_hosts(
        rows,
        {
            "q": q,
            "category": category,
            "status": status,
            "source": source,
            "network": network,
            "has_hostname": has_hostname,
            "has_mac": has_mac,
        },
    )
    return api_response({"hosts": rows})


@router.get("/network/hosts/{ip}")
def api_network_host_detail(ip: str, actor: str = Depends(require_api_actor)):
    return api_response(call_netctl(["hosts", "inspect", ip]))


@router.get("/network/sources")
def api_network_sources(actor: str = Depends(require_api_actor)):
    return api_response(call_netctl(["sources", "list"]))


@router.get("/network/switch-fingerprints")
def api_network_switch_fingerprints(actor: str = Depends(require_api_actor)):
    return api_response(call_netctl(["switches", "unknown-fingerprints"]))


@router.post("/network/sources/{source}/test")
def api_network_source_test(source: str, actor: str = Depends(require_api_actor)):
    return api_response(call_netctl(["sources", "test", source], timeout=60))


@router.post("/network/sources/{source}/collect")
def api_network_source_collect(source: str, actor: str = Depends(require_api_actor)):
    return api_response(call_netctl(["collect", source], timeout=180))


@router.get("/network/interfaces")
def api_network_interfaces(actor: str = Depends(require_api_actor), source: str = Query(default="")):
    args = ["interfaces", "list"]
    if source:
        args.extend(["--source", source])
    return api_response(call_netctl(args))


@router.get("/network/routes")
def api_network_routes(actor: str = Depends(require_api_actor), source: str = Query(default="")):
    args = ["routes", "list"]
    if source:
        args.extend(["--source", source])
    return api_response(call_netctl(args))


@router.get("/network/observations")
def api_network_observations(actor: str = Depends(require_api_actor), host: str = Query(default="")):
    args = ["observations", "list"]
    if host:
        args.extend(["--host", host])
    return api_response(call_netctl(args))


@router.get("/network/ipsec")
def api_network_ipsec(actor: str = Depends(require_api_actor), source: str = Query(default="")):
    args = ["ipsec", "status"]
    if source:
        args.extend(["--source", source])
    return api_response(call_netctl(args, timeout=60))


@router.get("/network/backups")
def api_network_backups(actor: str = Depends(require_api_actor)):
    settings = get_settings()
    backups, error = list_routeros_backups(settings.routeros_backup_dir)
    return api_response({"backups": backups, "backup_dir": str(settings.routeros_backup_dir), "error": error})


@router.get("/network/logs")
def api_network_logs(actor: str = Depends(require_api_actor), n: int = Query(default=80)):
    if n not in {30, 80, 150}:
        n = 80
    return api_response(call_netctl(["logs", "-n", str(n)]))


@router.get("/site-routes")
def api_site_routes(actor: str = Depends(require_api_actor)):
    return api_response(call_vpnctl(["site-routes", "list"]))


@router.post("/site-routes")
def api_site_route_add(
    payload: SiteRouteRequest,
    request: Request,
    actor: str = Depends(require_api_actor),
    db: Session = Depends(get_db),
):
    args = ["site-routes", "add", payload.cidr]
    if payload.client:
        args.extend(["--client", payload.client])
    if payload.restart:
        args.append("--restart")
    try:
        data = run_vpnctl(args, timeout=180)
    except VpnctlError as exc:
        write_audit(db, request, actor, "api-site-route-add", "error", error_detail(exc))
        raise HTTPException(status_code=502, detail=error_detail(exc)) from exc
    write_audit(db, request, actor, "api-site-route-add", "ok", payload.cidr)
    return api_response(data)


@router.delete("/site-routes/{cidr:path}")
def api_site_route_remove(
    cidr: str,
    request: Request,
    restart: bool = Query(default=False),
    actor: str = Depends(require_api_actor),
    db: Session = Depends(get_db),
):
    args = ["site-routes", "remove", cidr]
    if restart:
        args.append("--restart")
    try:
        data = run_vpnctl(args, timeout=180)
    except VpnctlError as exc:
        write_audit(db, request, actor, "api-site-route-remove", "error", error_detail(exc))
        raise HTTPException(status_code=502, detail=error_detail(exc)) from exc
    write_audit(db, request, actor, "api-site-route-remove", "ok", cidr)
    return api_response(data)


@router.get("/logs")
def api_logs(
    actor: str = Depends(require_api_actor),
    n: int = Query(default=80),
):
    if n not in {30, 80, 150}:
        n = 80
    return api_response(call_vpnctl(["logs", "-n", str(n)]))
