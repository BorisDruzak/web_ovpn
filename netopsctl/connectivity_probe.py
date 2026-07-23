from __future__ import annotations

import ipaddress
import json
import re
import subprocess
from dataclasses import dataclass
from typing import Any


_ASSET_KEY_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,180}$")
_USER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_-]{0,63}$")
_FIXED_TCP_PROBE = """import socket
import sys
for label, host, port in ((\"internet\", sys.argv[1], int(sys.argv[2])), (\"internal\", sys.argv[3], int(sys.argv[4]))):
    try:
        with socket.create_connection((host, port), timeout=5):
            pass
        print(f\"{label}=reachable\")
    except OSError:
        print(f\"{label}=blocked\")
"""


@dataclass(frozen=True)
class _Endpoint:
    host: str
    port: int


@dataclass(frozen=True)
class _ProbeTarget:
    host: str
    user: str
    internet: _Endpoint
    internal: _Endpoint


class SSHConnectivityProbe:
    def __init__(self, assets: dict[str, _ProbeTarget], identity_file: str) -> None:
        self._assets = assets
        self._identity_file = identity_file

    @classmethod
    def from_json(cls, raw: str, identity_file: str) -> SSHConnectivityProbe:
        try:
            parsed = json.loads(raw)
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise ValueError("invalid active connectivity probe configuration") from exc
        if not isinstance(parsed, dict) or not parsed or not isinstance(identity_file, str) or not identity_file.startswith("/"):
            raise ValueError("invalid active connectivity probe configuration")
        assets: dict[str, _ProbeTarget] = {}
        for asset_key, record in parsed.items():
            if not isinstance(asset_key, str) or not _ASSET_KEY_RE.fullmatch(asset_key) or not isinstance(record, dict):
                raise ValueError("invalid active connectivity probe configuration")
            if set(record) != {"host", "user", "internet", "internal"}:
                raise ValueError("invalid active connectivity probe configuration")
            host = _ipv4(record["host"])
            user = record["user"]
            if not isinstance(user, str) or not _USER_RE.fullmatch(user):
                raise ValueError("invalid active connectivity probe configuration")
            assets[asset_key] = _ProbeTarget(host, user, _endpoint(record["internet"]), _endpoint(record["internal"]))
        return cls(assets, identity_file)

    def _ssh_command(self, target: _ProbeTarget) -> list[str]:
        return [
            "ssh", "-i", self._identity_file,
            "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes", "-o", "ConnectTimeout=8",
            f"{target.user}@{target.host}", "python3", "-",
            target.internet.host, str(target.internet.port), target.internal.host, str(target.internal.port),
        ]

    def verify(self, asset_key: str, expected_internet: bool) -> dict[str, object]:
        target = self._assets.get(asset_key)
        if target is None:
            raise ValueError("active connectivity probe is not configured for this asset")
        completed = subprocess.run(
            self._ssh_command(target), input=_FIXED_TCP_PROBE, text=True,
            capture_output=True, timeout=15, check=False, shell=False,
        )
        if completed.returncode != 0:
            raise ValueError("active connectivity probe transport failed")
        result = _parse_output(completed.stdout)
        expected = "reachable" if expected_internet else "blocked"
        if result["internet"] != expected or result["internal"] != "reachable":
            raise ValueError("active connectivity verification failed")
        return {"asset_key": asset_key, **result}


def _ipv4(value: Any) -> str:
    if not isinstance(value, str):
        raise ValueError("invalid active connectivity probe configuration")
    try:
        parsed = ipaddress.ip_address(value)
    except ValueError as exc:
        raise ValueError("invalid active connectivity probe configuration") from exc
    if parsed.version != 4:
        raise ValueError("invalid active connectivity probe configuration")
    return str(parsed)


def _endpoint(value: Any) -> _Endpoint:
    if not isinstance(value, dict) or set(value) != {"host", "port"}:
        raise ValueError("invalid active connectivity probe configuration")
    port = value["port"]
    if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
        raise ValueError("invalid active connectivity probe configuration")
    return _Endpoint(_ipv4(value["host"]), port)


def _parse_output(value: str) -> dict[str, str]:
    parsed: dict[str, str] = {}
    for line in value.splitlines():
        key, separator, state = line.partition("=")
        if separator and key in {"internet", "internal"} and state in {"reachable", "blocked"}:
            parsed[key] = state
    if set(parsed) != {"internet", "internal"}:
        raise ValueError("active connectivity probe returned invalid result")
    return parsed
