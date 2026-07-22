from __future__ import annotations

import os
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path


def _bool_env(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _path_env(name: str, default: str) -> Path:
    return Path(os.environ.get(name, default)).expanduser()


@dataclass(frozen=True)
class Settings:
    database_url: str
    app_secret_key: str
    admin_username: str
    admin_password: str
    api_token_hash: str
    api_actor: str
    network_change_trusted_https: bool
    network_change_trust_proxy: bool
    network_change_tokens_json: str
    network_control_socket_path: Path
    vpnctl_path: str
    vpnctl_use_sudo: bool
    netctl_path: str
    netctl_use_sudo: bool
    netctl_sudo_user: str
    network_observer_enabled: bool
    network_paths_config_path: Path
    server_role_registry_path: Path
    server_observer_snapshot_path: Path
    out_dir: Path
    share_out_dir: Path
    archive_dir: Path
    routeros_backup_dir: Path
    server_draft_queue_dir: Path
    server_draft_results_dir: Path
    server_draft_private_dir: Path
    observer_public_key_path: Path
    download_ttl_minutes: int
    session_cookie_name: str

    @property
    def allowed_download_roots(self) -> tuple[Path, ...]:
        return (self.out_dir, self.share_out_dir, self.archive_dir)


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings(
        database_url=os.environ.get("DATABASE_URL", "sqlite:///./openvpn-web.sqlite"),
        app_secret_key=os.environ.get("APP_SECRET_KEY", "dev-only-change-me"),
        admin_username=os.environ.get("ADMIN_USERNAME", "admin"),
        admin_password=os.environ.get("ADMIN_PASSWORD", ""),
        api_token_hash=os.environ.get("OPENVPN_WEB_API_TOKEN_HASH", ""),
        api_actor=os.environ.get("OPENVPN_WEB_API_ACTOR", "api:codex-local"),
        network_change_trusted_https=_bool_env("NETWORK_CHANGE_TRUSTED_HTTPS", False),
        network_change_trust_proxy=_bool_env("NETWORK_CHANGE_TRUST_PROXY", False),
        network_change_tokens_json=os.environ.get("NETWORK_CHANGE_TOKENS_JSON", "[]"),
        network_control_socket_path=_path_env("NETWORK_CONTROL_SOCKET_PATH", "/run/netopsctl/netopsctl.sock"),
        vpnctl_path=os.environ.get("VPNCTL_PATH", "/usr/local/sbin/vpnctl"),
        vpnctl_use_sudo=_bool_env("VPNCTL_USE_SUDO", False),
        netctl_path=os.environ.get("NETCTL_PATH", "/usr/local/sbin/netctl"),
        netctl_use_sudo=_bool_env("NETCTL_USE_SUDO", True),
        netctl_sudo_user=os.environ.get("NETCTL_SUDO_USER", "netctl"),
        network_observer_enabled=_bool_env("NETWORK_OBSERVER_ENABLED", True),
        network_paths_config_path=_path_env("NETWORK_PATHS_CONFIG_PATH", "/etc/openvpn-web/network-paths.json"),
        server_role_registry_path=_path_env(
            "SERVER_ROLE_REGISTRY_PATH", "/etc/openvpn-web/server-roles.json"
        ),
        server_observer_snapshot_path=_path_env(
            "SERVER_OBSERVER_SNAPSHOT_PATH", "/var/lib/openvpn-web/server-observer/latest.json"
        ),
        out_dir=_path_env("OUT_DIR", "/etc/openvpn/client-generator/output"),
        share_out_dir=_path_env("SHARE_OUT_DIR", "/mnt/antares_soft/vpn_config"),
        archive_dir=_path_env("ARCHIVE_DIR", "/etc/openvpn/client-generator/archive"),
        routeros_backup_dir=_path_env("ROUTEROS_BACKUP_DIR", "/var/backups/routeros"),
        server_draft_queue_dir=_path_env(
            "SERVER_DRAFT_QUEUE_DIR", "/var/lib/openvpn-web/server-drafts/queue"
        ),
        server_draft_results_dir=_path_env(
            "SERVER_DRAFT_RESULTS_DIR", "/var/lib/openvpn-web/server-drafts/results"
        ),
        server_draft_private_dir=_path_env(
            "SERVER_DRAFT_PRIVATE_DIR", "/var/lib/openvpn-web/server-drafts/private"
        ),
        observer_public_key_path=_path_env(
            "OBSERVER_PUBLIC_KEY_PATH", "/etc/openvpn-web/server-observer.pub"
        ),
        download_ttl_minutes=int(os.environ.get("DOWNLOAD_TOKEN_TTL_MINUTES", "15")),
        session_cookie_name=os.environ.get("SESSION_COOKIE_NAME", "openvpn_web_session"),
    )


def reset_settings_cache() -> None:
    get_settings.cache_clear()
