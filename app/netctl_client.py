from __future__ import annotations

import json
import logging
import subprocess
import time
from dataclasses import dataclass
from typing import Any

from .config import get_settings

log = logging.getLogger(__name__)


@dataclass
class NetctlError(Exception):
    message: str
    returncode: int | None = None
    stdout: str = ""
    stderr: str = ""


def _timeout_for(args: list[str], timeout: int | None) -> int:
    if timeout is not None:
        return timeout
    if args and args[0] in {"collect"}:
        return 180
    return 60


def run_netctl(args: list[str], timeout: int | None = None, request_id: str = "") -> dict[str, Any]:
    settings = get_settings()
    clean_args = [str(arg) for arg in args if str(arg) != ""]
    command = [settings.netctl_path, "--json", *clean_args]
    if settings.netctl_use_sudo:
        sudo_prefix = ["sudo", "-n"]
        if settings.netctl_sudo_user:
            sudo_prefix.extend(["-u", settings.netctl_sudo_user])
        command = [*sudo_prefix, *command]

    command_name = clean_args[0] if clean_args else "unknown"
    started = time.monotonic()
    try:
        completed = subprocess.run(
            command,
            shell=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=_timeout_for(clean_args, timeout),
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        log.warning("netctl command=%s outcome=timeout duration_ms=%d request_id=%s", command_name, (time.monotonic() - started) * 1000, request_id or "-")
        raise NetctlError(f"netctl timeout after {exc.timeout}s", stdout=exc.stdout or "", stderr=exc.stderr or "") from exc

    if completed.returncode != 0:
        log.warning("netctl command=%s outcome=error duration_ms=%d request_id=%s", command_name, (time.monotonic() - started) * 1000, request_id or "-")
        message = f"netctl {' '.join(clean_args[:2])} failed with code {completed.returncode}"
        raise NetctlError(message, completed.returncode, completed.stdout, completed.stderr)

    try:
        parsed = json.loads(completed.stdout or "{}")
    except json.JSONDecodeError as exc:
        log.warning("netctl command=%s outcome=invalid_json duration_ms=%d request_id=%s", command_name, (time.monotonic() - started) * 1000, request_id or "-")
        raise NetctlError("netctl returned invalid JSON", completed.returncode, completed.stdout, completed.stderr) from exc
    log.info("netctl command=%s outcome=ok duration_ms=%d request_id=%s", command_name, (time.monotonic() - started) * 1000, request_id or "-")
    if not isinstance(parsed, dict):
        return {"result": parsed}
    return parsed
