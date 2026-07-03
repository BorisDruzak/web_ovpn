from __future__ import annotations

import json
import logging
import subprocess
from dataclasses import dataclass
from typing import Any

from .config import get_settings

log = logging.getLogger(__name__)


@dataclass
class VpnctlError(Exception):
    message: str
    returncode: int | None = None
    stdout: str = ""
    stderr: str = ""


def _timeout_for(args: list[str], timeout: int | None) -> int:
    if timeout is not None:
        return timeout
    if args and args[0] in {"generate", "delete", "disable", "sync"}:
        return 180
    return 60


def run_vpnctl(args: list[str], timeout: int | None = None) -> dict[str, Any]:
    settings = get_settings()
    clean_args = [str(arg) for arg in args if str(arg) != ""]
    command = [settings.vpnctl_path, "--json", *clean_args]
    if settings.vpnctl_use_sudo:
        command = ["sudo", "-n", *command]

    log.info("running vpnctl command: %s", " ".join(command[:3] + clean_args[:2]))
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
        raise VpnctlError(f"vpnctl timeout after {exc.timeout}s", stdout=exc.stdout or "", stderr=exc.stderr or "") from exc

    if completed.returncode != 0:
        message = f"vpnctl {' '.join(clean_args[:2])} failed with code {completed.returncode}"
        raise VpnctlError(message, completed.returncode, completed.stdout, completed.stderr)

    try:
        parsed = json.loads(completed.stdout or "{}")
    except json.JSONDecodeError as exc:
        raise VpnctlError("vpnctl returned invalid JSON", completed.returncode, completed.stdout, completed.stderr) from exc
    if not isinstance(parsed, dict):
        return {"result": parsed}
    return parsed
