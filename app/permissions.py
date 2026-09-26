"""Small capability policy shared by browser and legacy service credentials.

Read access remains available to active observers. Writes are explicit; existing
administrators retain administration, and network administrators retain network
operations. Scoped network-control authorization remains an additional gate.
"""
import json

from fastapi import HTTPException

PERMISSIONS = frozenset({"inventory:read", "inventory:write", "inventory:delete", "inventory:export",
    "network:read", "network:diagnose", "network:manage", "network:export",
    "vpn:read", "vpn:manage", "vpn:download", "admin:users"})
LEGACY_SERVICE_PERMISSIONS = "inventory:read,inventory:write,network:read,network:diagnose,vpn:read,vpn:manage,vpn:download"
PERMISSION_LABELS = {
    "inventory:read": "Просмотр инвентаризации", "inventory:write": "Изменение карточек",
    "inventory:delete": "Удаление и восстановление карточек", "inventory:export": "Экспорт инвентаризации",
    "network:read": "Просмотр сети", "network:diagnose": "Диагностика и сбор данных",
    "network:manage": "Управление сетью", "network:export": "Экспорт устройств сети",
    "vpn:read": "Просмотр VPN", "vpn:manage": "Управление VPN", "vpn:download": "Скачивание VPN-файлов",
}


def required_permission(path: str, method: str) -> str | None:
    path = path.removeprefix("/api/v1")
    write = method not in {"GET", "HEAD", "OPTIONS"}
    if path in {"/login", "/logout"} or path.startswith("/static/"):
        return None
    if path.startswith("/operations"):
        return None  # Owner and original capability are checked by each operation route.
    if path.startswith("/admin/users"):
        return "admin:users"
    if path.startswith("/inventory"):
        if path.startswith("/inventory/deleted"):
            return "inventory:delete"
        if "export" in path:
            return "inventory:export"
        if method == "DELETE" and "/assets/" in path or path.endswith(("/delete", "/restore")):
            return "inventory:delete"
        return "inventory:write" if write else "inventory:read"
    if path.startswith("/download/") or path.endswith("/download-link") or "/download" in path or path.endswith("/file"):
        return "vpn:download"
    if path.startswith(("/clients", "/connections", "/openvpn", "/settings/openvpn", "/networks", "/vipnet-nets", "/network-templates", "/site-routes")):
        return "vpn:manage" if write else "vpn:read"
    if path.startswith(("/network", "/context")):
        if "export" in path:
            return "network:export"
        if write:
            diagnostic = path.endswith(("/test", "/collect", "/availability-check", "/refresh-observations", "/fingerprint/ensure"))
            return "network:diagnose" if diagnostic else "network:manage"
        return "network:read"
    if path.startswith("/endpoints"):
        return "inventory:write" if write else "inventory:read"
    # Unknown writes require administration instead of silently allowing observers.
    return "admin:users" if write else "vpn:read"


def user_has_permission(user, permission: str | None) -> bool:
    if user is None or not user.is_active:
        return False
    if permission is None or user.is_admin or permission.endswith(":read"):
        return True
    if user.is_network_admin and permission in {"network:diagnose", "network:manage"}:
        return True
    try:
        grants = json.loads(user.permissions_json or "[]")
    except (ValueError, TypeError):
        return False
    return isinstance(grants, list) and permission in grants


def check_user_permission(user, permission: str | None) -> None:
    if not user_has_permission(user, permission):
        raise HTTPException(status_code=403, detail="Недостаточно прав для этого действия")


def check_service_permission(scopes: str, permission: str | None) -> None:
    if permission and permission not in {part.strip() for part in scopes.split(",")}:
        raise HTTPException(status_code=403, detail="Service credential lacks required permission")
