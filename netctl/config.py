from __future__ import annotations

import json
import os
import re
import shlex
from pathlib import Path
from typing import Any

from .switch_profile_hints import SUPPORTED_SNMP_PROFILE_HINTS
from .util import parse_bool, validate_source_name

DEFAULT_CONFIG = Path("/etc/netctl/netctl.yaml")
DEFAULT_DB_URL = "sqlite:////var/lib/netctl/netctl.sqlite"
DEFAULT_SECRETS = Path("/etc/netctl/secrets.env")

SNMP_OPTION_YAML_KEYS = {
    "snmp_version": "snmp_version",
    "timeout_seconds": "snmp_timeout_seconds",
    "retries": "snmp_retries",
    "max_repetitions": "snmp_max_repetitions",
    "profile_hint": "snmp_profile_hint",
    "capability_ttl_hours": "snmp_capability_ttl_hours",
    "raw_capture": "snmp_raw_capture",
    "raw_retention_hours": "snmp_raw_retention_hours",
    "counter_retention_days": "snmp_counter_retention_days",
    "event_retention_days": "snmp_event_retention_days",
    "access_port_mac_threshold": "snmp_access_port_mac_threshold",
    "low_speed_threshold_bps": "snmp_low_speed_threshold_bps",
    "runtime_asset_key": "runtime_asset_key",
    "intent_context_id": "intent_context_id",
    "intent_stable_id": "intent_stable_id",
}
SNMP_DRIVER_OPTION_KEYS = frozenset(SNMP_OPTION_YAML_KEYS)
SNMP_SECRET_REF_PATTERN = re.compile(r"[a-z][a-z0-9]*(?:_[a-z0-9]+)*\Z")


def sources_dir(config_path: str | Path) -> Path:
    return Path(config_path).expanduser().resolve().parent / "sources.d"


def _parse_scalar(value: str) -> Any:
    raw = value.strip()
    if raw.startswith('"') and raw.endswith('"'):
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            return raw[1:-1]
        if isinstance(parsed, str):
            return parsed
    if raw.lower() in {"true", "false"}:
        return raw.lower() == "true"
    if raw.startswith("'") and raw.endswith("'"):
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
        "ssh_identity_file",
        "ssh_proxy_jump",
        "ssh_connect_timeout",
        "enabled",
    ]
    values = dict(source)
    if str(source.get("driver") or "") == "snmp_switch":
        options = source.get("driver_options")
        if isinstance(options, dict):
            for option_key, yaml_key in SNMP_OPTION_YAML_KEYS.items():
                if option_key in options:
                    values[yaml_key] = options[option_key]
        ordered.extend(SNMP_OPTION_YAML_KEYS.values())
    rendered_values = {
        key: _render_source_yaml_scalar(values[key])
        for key in ordered
        if key in values
    }
    directory = sources_dir(config_path)
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{source['name']}.yaml"
    lines = []
    for key in ordered:
        if key not in rendered_values:
            continue
        lines.append(f"{key}: {rendered_values[key]}")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def validate_source_yaml_scalars(source: dict[str, Any]) -> None:
    """Reject values that the line-oriented source format cannot preserve."""
    for value in source.values():
        if isinstance(value, dict):
            for nested_value in value.values():
                _render_source_yaml_scalar(nested_value)
        else:
            _render_source_yaml_scalar(value)


def _render_source_yaml_scalar(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    rendered = str(value)
    if rendered and rendered.splitlines() != [rendered]:
        raise ValueError("source YAML values must be a single line")
    if isinstance(value, str):
        return json.dumps(rendered, ensure_ascii=True)
    return rendered


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
    driver = str(source.get("driver") or "mikrotik_api")
    normalized = {
        "name": name,
        "driver": driver,
        "host": str(source.get("host") or ""),
        "port": int(source.get("port") or (161 if driver == "snmp_switch" else 8729)),
        "username": str(source.get("username") or ""),
        "secret_ref": str(source.get("secret_ref") or name),
        "tls": parse_bool(source.get("tls"), True),
        "verify_tls": parse_bool(source.get("verify_tls"), False),
        "site": str(source.get("site") or "main"),
        "role": str(source.get("role") or ""),
        "ssh_identity_file": str(source.get("ssh_identity_file") or ""),
        "ssh_proxy_jump": str(source.get("ssh_proxy_jump") or ""),
        "ssh_connect_timeout": int(source.get("ssh_connect_timeout") or 8),
        "enabled": parse_bool(source.get("enabled"), driver != "snmp_switch"),
    }
    if driver == "snmp_switch":
        snmp_community_env_name(normalized["secret_ref"])
        normalized["driver_options"] = _normalize_snmp_options(source)
    return normalized


def _snmp_option(source: dict[str, Any], option_key: str, default: Any) -> Any:
    yaml_key = SNMP_OPTION_YAML_KEYS[option_key]
    if yaml_key in source:
        return source[yaml_key]
    options = source.get("driver_options")
    if isinstance(options, dict) and option_key in options:
        return options[option_key]
    return default


def _bounded_int(
    value: Any,
    *,
    field: str,
    minimum: int,
    maximum: int,
) -> int:
    if isinstance(value, bool):
        raise ValueError(f"{field} must be an integer")
    if isinstance(value, int):
        normalized = value
    elif isinstance(value, float):
        if not value.is_integer():
            raise ValueError(f"{field} must be an integer")
        normalized = int(value)
    elif isinstance(value, str):
        stripped = value.strip()
        digits = stripped[1:] if stripped.startswith(("+", "-")) else stripped
        if not digits.isdigit():
            raise ValueError(f"{field} must be an integer")
        normalized = int(stripped)
    else:
        raise ValueError(f"{field} must be an integer")
    if not minimum <= normalized <= maximum:
        raise ValueError(f"{field} must be between {minimum} and {maximum}")
    return normalized


def _snmp_bool(value: Any, *, field: str) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"1", "true", "yes", "on", "enabled"}:
            return True
        if normalized in {"0", "false", "no", "off", "disabled"}:
            return False
    raise ValueError(f"{field} must be a boolean")


def _snmp_string(value: Any, *, field: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{field} must be a string")
    return value


def _normalize_snmp_options(source: dict[str, Any]) -> dict[str, Any]:
    nested_options = source.get("driver_options")
    if nested_options is not None and not isinstance(nested_options, dict):
        raise ValueError("SNMP driver_options must be a mapping")
    if "community" in source or (
        isinstance(nested_options, dict) and "community" in nested_options
    ):
        raise ValueError("SNMP community must be configured through secret_ref")
    if isinstance(nested_options, dict) and (
        set(nested_options) - SNMP_DRIVER_OPTION_KEYS
    ):
        raise ValueError("unsupported SNMP driver option")
    if any(
        ("community" in str(key).lower())
        or (
            str(key).startswith("snmp_")
            and str(key) not in SNMP_OPTION_YAML_KEYS.values()
        )
        for key in source
    ):
        raise ValueError("unsupported SNMP source option")

    version = _snmp_string(
        _snmp_option(source, "snmp_version", "2c"), field="snmp_version"
    )
    if version != "2c":
        raise ValueError("snmp_version must be 2c")

    profile_value = _snmp_option(source, "profile_hint", None)
    profile = None
    if profile_value is not None:
        profile = _snmp_string(
            profile_value, field="snmp_profile_hint"
        ).strip().lower()
        if profile not in SUPPORTED_SNMP_PROFILE_HINTS:
            raise ValueError("snmp_profile_hint is unsupported")

    normalized = {
        "snmp_version": version,
        "timeout_seconds": _bounded_int(
            _snmp_option(source, "timeout_seconds", 2),
            field="snmp_timeout_seconds",
            minimum=1,
            maximum=60,
        ),
        "retries": _bounded_int(
            _snmp_option(source, "retries", 1),
            field="snmp_retries",
            minimum=0,
            maximum=10,
        ),
        "max_repetitions": _bounded_int(
            _snmp_option(source, "max_repetitions", 25),
            field="snmp_max_repetitions",
            minimum=1,
            maximum=100,
        ),
        "capability_ttl_hours": _bounded_int(
            _snmp_option(source, "capability_ttl_hours", 168),
            field="snmp_capability_ttl_hours",
            minimum=1,
            maximum=8760,
        ),
        "raw_capture": _snmp_bool(
            _snmp_option(source, "raw_capture", False), field="snmp_raw_capture"
        ),
        "raw_retention_hours": _bounded_int(
            _snmp_option(source, "raw_retention_hours", 24),
            field="snmp_raw_retention_hours",
            minimum=1,
            maximum=24,
        ),
        "counter_retention_days": _bounded_int(
            _snmp_option(source, "counter_retention_days", 14),
            field="snmp_counter_retention_days",
            minimum=1,
            maximum=3650,
        ),
        "event_retention_days": _bounded_int(
            _snmp_option(source, "event_retention_days", 180),
            field="snmp_event_retention_days",
            minimum=1,
            maximum=3650,
        ),
        "access_port_mac_threshold": _bounded_int(
            _snmp_option(source, "access_port_mac_threshold", 10),
            field="snmp_access_port_mac_threshold",
            minimum=1,
            maximum=1_000_000,
        ),
        "low_speed_threshold_bps": _bounded_int(
            _snmp_option(source, "low_speed_threshold_bps", 100_000_000),
            field="snmp_low_speed_threshold_bps",
            minimum=1,
            maximum=10**15,
        ),
        "runtime_asset_key": _snmp_string(
            _snmp_option(source, "runtime_asset_key", ""), field="runtime_asset_key"
        ),
        "intent_context_id": _snmp_string(
            _snmp_option(source, "intent_context_id", ""), field="intent_context_id"
        ),
        "intent_stable_id": _snmp_string(
            _snmp_option(source, "intent_stable_id", ""), field="intent_stable_id"
        ),
    }
    if profile is not None:
        normalized["profile_hint"] = profile
    return normalized


def normalize_snmp_driver_options(options: Any) -> dict[str, Any]:
    if not isinstance(options, dict):
        raise ValueError("SNMP driver_options must be a mapping")
    if set(options) - SNMP_DRIVER_OPTION_KEYS:
        raise ValueError("unsupported SNMP driver option")
    return _normalize_snmp_options({"driver_options": options})


def secret_env_name(secret_ref: str) -> str:
    token = "".join(ch if ch.isalnum() else "_" for ch in secret_ref.upper())
    return f"NETCTL_SECRET_{token}_PASSWORD"


def snmp_community_env_name(secret_ref: str) -> str:
    if not isinstance(secret_ref, str) or not SNMP_SECRET_REF_PATTERN.fullmatch(secret_ref):
        raise ValueError("SNMP secret_ref is invalid")
    return f"NETCTL_SECRET_{secret_ref.upper()}_COMMUNITY"


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
