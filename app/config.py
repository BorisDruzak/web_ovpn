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
    vpnctl_path: str
    vpnctl_use_sudo: bool
    out_dir: Path
    share_out_dir: Path
    archive_dir: Path
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
        vpnctl_path=os.environ.get("VPNCTL_PATH", "/usr/local/sbin/vpnctl"),
        vpnctl_use_sudo=_bool_env("VPNCTL_USE_SUDO", False),
        out_dir=_path_env("OUT_DIR", "/etc/openvpn/client-generator/output"),
        share_out_dir=_path_env("SHARE_OUT_DIR", "/mnt/antares_soft/vpn_config"),
        archive_dir=_path_env("ARCHIVE_DIR", "/etc/openvpn/client-generator/archive"),
        download_ttl_minutes=int(os.environ.get("DOWNLOAD_TOKEN_TTL_MINUTES", "15")),
        session_cookie_name=os.environ.get("SESSION_COOKIE_NAME", "openvpn_web_session"),
    )


def reset_settings_cache() -> None:
    get_settings.cache_clear()
