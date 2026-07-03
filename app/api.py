from __future__ import annotations

import hashlib
import hmac
import ipaddress
import re
from typing import Any

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from .audit import write_audit
from .auto_sync import force_client_sync
from .config import get_settings
from .db import get_db
from .vpnctl_client import VpnctlError, run_vpnctl

CLIENT_RE = re.compile(r"^[A-Za-z0-9._-]+$")

router = APIRouter(prefix="/api/v1", tags=["api"])


class ClientProfileRequest(BaseModel):
    profile: str
    vpn_ip: str = ""
    comment: str = ""


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


@router.get("/openvpn/server-config")
def api_openvpn_server_config(actor: str = Depends(require_api_actor)):
    return api_response(call_vpnctl(["server-config", "inspect"]))


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
    args = ["preview", client, payload.profile]
    if payload.vpn_ip:
        args.append(payload.vpn_ip)
    return api_response(call_vpnctl(args))


@router.post("/clients/{client}/generate")
def api_client_generate(
    client: str,
    payload: ClientProfileRequest,
    request: Request,
    actor: str = Depends(require_api_actor),
    db: Session = Depends(get_db),
):
    client = require_client_name(client)
    args = ["generate", client, payload.profile]
    if payload.vpn_ip:
        args.append(payload.vpn_ip)
    args.extend(["--comment", payload.comment])
    try:
        data = run_vpnctl(args, timeout=180)
    except VpnctlError as exc:
        write_audit(db, request, actor, "api-generate", "error", error_detail(exc), target_client=client)
        raise HTTPException(status_code=502, detail=error_detail(exc)) from exc
    write_audit(db, request, actor, "api-generate", "ok", f"profile={payload.profile}", target_client=client)
    attach_sync_status(data, request, db, actor, f"after API generate {client}")
    return api_response(data)


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
    args = ["networks", "add", payload.cidr, "--tag", payload.tag, "--comment", payload.comment]
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


@router.get("/logs")
def api_logs(
    actor: str = Depends(require_api_actor),
    n: int = Query(default=80),
):
    if n not in {30, 80, 150}:
        n = 80
    return api_response(call_vpnctl(["logs", "-n", str(n)]))
