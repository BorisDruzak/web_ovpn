from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping

from netctl.drivers.mikrotik_api import RouterOSApiClient


def _enabled(value: str | None) -> bool:
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}


def production_writes_allowed(environment: Mapping[str, str]) -> bool:
    """Fail closed until the independent signed audit checkpoint is healthy."""
    return _enabled(environment.get("NETOPSCTL_PRODUCTION_WRITES_ENABLED")) and _enabled(
        environment.get("NETOPSCTL_AUDIT_CHECKPOINT_HEALTHY")
    )


@dataclass(frozen=True)
class RouterOSConfig:
    host: str
    port: int
    username: str
    password: str
    tls: bool
    verify_tls: bool
    timeout: int


def load_routeros_config(environment: Mapping[str, str] | None = None) -> RouterOSConfig:
    environment = os.environ if environment is None else environment
    host = str(environment.get("NETOPSCTL_ROUTEROS_HOST") or "").strip()
    username = str(environment.get("NETOPSCTL_ROUTEROS_USERNAME") or "").strip()
    password_file = Path(str(environment.get("NETOPSCTL_ROUTEROS_PASSWORD_FILE") or "")).expanduser()
    if not host or not username or not password_file.is_file():
        raise ValueError("dedicated RouterOS secret file and endpoint configuration are required")
    password = password_file.read_text(encoding="utf-8").strip()
    if not password:
        raise ValueError("dedicated RouterOS secret file is empty")
    try:
        port = int(environment.get("NETOPSCTL_ROUTEROS_PORT", "8729"))
        timeout = int(environment.get("NETOPSCTL_ROUTEROS_TIMEOUT", "8"))
    except ValueError as exc:
        raise ValueError("invalid RouterOS connection configuration") from exc
    if not 1 <= port <= 65535 or not 1 <= timeout <= 60:
        raise ValueError("invalid RouterOS connection configuration")
    return RouterOSConfig(
        host=host, port=port, username=username, password=password,
        tls=_enabled(environment.get("NETOPSCTL_ROUTEROS_TLS", "true")),
        verify_tls=_enabled(environment.get("NETOPSCTL_ROUTEROS_VERIFY_TLS", "true")), timeout=timeout,
    )


class PerCallRouterOSClient:
    """Opens one short-lived authenticated RouterOS API session per bounded call."""

    def __init__(self, config: RouterOSConfig) -> None:
        self._config = config

    def call(self, words: list[str]) -> list[dict[str, str]]:
        with RouterOSApiClient(
            self._config.host, self._config.port, self._config.username, self._config.password,
            self._config.tls, self._config.verify_tls, self._config.timeout,
        ) as client:
            return client.call(words)
