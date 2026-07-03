from __future__ import annotations

import os
import shlex
from pathlib import Path
from typing import Any

from .util import parse_bool, validate_source_name

DEFAULT_CONFIG = Path("/etc/netctl/netctl.yaml")
DEFAULT_DB_URL = "sqlite:////var/lib/netctl/netctl.sqlite"
DEFAULT_SECRETS = Path("/etc/netctl/secrets.env")


def sources_dir(config_path: str | Path) -> Path:
    return Path(config_path).expanduser().resolve().parent / "sources.d"


def _parse_scalar(value: str) -> Any:
    raw = value.strip()
    if raw.lower() in {"true", "false"}:
        return raw.lower() == "true"
    if (raw.startswith("'") and raw.endswith("'")) or (raw.startswith('"') and raw.endswith('"')):
        return raw[1:-1]
    try:
        return int(raw)
    except ValueError:
        return raw


def read_simple_yaml(path: Path) -> dict[str, Any]:
    data: dict[str, Any] = {}
    if not path.exists():
        return data
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or ":" not in stripped:
            continue
        key, value = stripped.split(":", 1)
        data[key.strip()] = _parse_scalar(value)
    return data


def write_source_yaml(config_path: str | Path, source: dict[str, Any]) -> Path:
    validate_source_name(str(source["name"]))
    directory = sources_dir(config_path)
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{source['name']}.yaml"
    ordered = [
        "name",
        "driver",
        "host",
        "port",
        "tls",
        "verify_tls",
        "username",
        "secret_ref",
        "site",
        "role",
        "enabled",
    ]
    lines = []
    for key in ordered:
        if key not in source:
            continue
        value = source[key]
        if isinstance(value, bool):
            rendered = "true" if value else "false"
        else:
            rendered = str(value)
        lines.append(f"{key}: {rendered}")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def load_config_sources(config_path: str | Path) -> list[dict[str, Any]]:
    directory = sources_dir(config_path)
    if not directory.exists():
        return []
    result: list[dict[str, Any]] = []
    for path in sorted(directory.glob("*.yaml")):
        item = read_simple_yaml(path)
        if not item.get("name"):
            item["name"] = path.stem
        result.append(normalize_source(item))
    return result


def normalize_source(source: dict[str, Any]) -> dict[str, Any]:
    name = validate_source_name(str(source.get("name") or ""))
    return {
        "name": name,
        "driver": str(source.get("driver") or "mikrotik_api"),
        "host": str(source.get("host") or ""),
        "port": int(source.get("port") or 8729),
        "username": str(source.get("username") or ""),
        "secret_ref": str(source.get("secret_ref") or name),
        "tls": parse_bool(source.get("tls"), True),
        "verify_tls": parse_bool(source.get("verify_tls"), False),
        "site": str(source.get("site") or "main"),
        "role": str(source.get("role") or ""),
        "enabled": parse_bool(source.get("enabled"), True),
    }


def secret_env_name(secret_ref: str) -> str:
    token = "".join(ch if ch.isalnum() else "_" for ch in secret_ref.upper())
    return f"NETCTL_SECRET_{token}_PASSWORD"


def load_secrets(path: str | Path | None = None) -> dict[str, str]:
    secrets = dict(os.environ)
    secrets_path = Path(path or os.environ.get("NETCTL_SECRETS_PATH") or DEFAULT_SECRETS)
    if not secrets_path.exists():
        return secrets
    try:
        lines = secrets_path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return secrets
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, value = stripped.split("=", 1)
        try:
            parsed = shlex.split(value, posix=True)
            secrets[key.strip()] = parsed[0] if parsed else ""
        except ValueError:
            secrets[key.strip()] = value.strip().strip("'\"")
    return secrets
