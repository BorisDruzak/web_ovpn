from __future__ import annotations

import json
import logging
import subprocess
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


def run_netctl(args: list[str], timeout: int | None = None) -> dict[str, Any]:
    settings = get_settings()
    clean_args = [str(arg) for arg in args if str(arg) != ""]
    command = [settings.netctl_path, "--json", *clean_args]
    if settings.netctl_use_sudo:
        sudo_prefix = ["sudo", "-n"]
        if settings.netctl_sudo_user:
            sudo_prefix.extend(["-u", settings.netctl_sudo_user])
        command = [*sudo_prefix, *command]

    log.info("running netctl command: %s", " ".join(command[:3] + clean_args[:2]))
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
        raise NetctlError(f"netctl timeout after {exc.timeout}s", stdout=exc.stdout or "", stderr=exc.stderr or "") from exc

    if completed.returncode != 0:
        message = f"netctl {' '.join(clean_args[:2])} failed with code {completed.returncode}"
        raise NetctlError(message, completed.returncode, completed.stdout, completed.stderr)

    try:
        parsed = json.loads(completed.stdout or "{}")
    except json.JSONDecodeError as exc:
        raise NetctlError("netctl returned invalid JSON", completed.returncode, completed.stdout, completed.stderr) from exc
    if not isinstance(parsed, dict):
        return {"result": parsed}
    return parsed
