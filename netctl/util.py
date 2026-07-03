from __future__ import annotations

import ipaddress
import re
from datetime import UTC, datetime
from typing import Any

SOURCE_NAME_RE = re.compile(r"^[A-Za-z0-9._-]+$")


def utc_now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def parse_bool(value: Any, default: bool = False) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "on", "enabled"}


def parse_int(value: Any, default: int = 0) -> int:
    try:
        return int(str(value or "").strip())
    except (TypeError, ValueError):
        return default


def normalize_mac(value: Any) -> str | None:
    raw = str(value or "").strip().upper()
    if not raw:
        return None
    raw = raw.replace("-", ":")
    return raw


def validate_source_name(name: str) -> str:
    if not SOURCE_NAME_RE.match(name or ""):
        raise ValueError("invalid source name")
    return name


def validate_ip_or_cidr(value: str) -> str:
    try:
        if "/" in value:
            return str(ipaddress.ip_network(value, strict=False))
        return str(ipaddress.ip_address(value))
    except ValueError as exc:
        raise ValueError(f"invalid IP/CIDR: {value}") from exc


def json_list(value: Any) -> list[Any]:
    if isinstance(value, list):
        return value
    return []
