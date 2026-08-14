#!/usr/bin/python3
from __future__ import annotations

import json
import os
import re
import subprocess
from pathlib import Path

from alt_deploy.config import Settings
from alt_deploy.jsonio import atomic_write_json, read_json
from alt_deploy.locks import exclusive_lock


SETTINGS = Settings.from_env()
SAFE_FAILURE_RE = re.compile(
    r"ALT_PREFLIGHT_FAILURE:([a-z][a-z0-9_]{1,79})"
)
WAITING_CODES = frozenset(
    {
        "desktop_shortcuts_user_home_unavailable",
        "remote_access_user_home_unavailable",
        "first_login_profile_retryable",
        "first_login_transport_unavailable",
    }
)


def first_login_root() -> Path:
    return SETTINGS.state_root / "first-login"


def run_user_stage(record: dict[str, object]) -> tuple[bool, str | None]:
    request = record.get("request")
    ip = record.get("ip")
    if not isinstance(request, dict) or not isinstance(ip, str) or not ip:
        return False, "first_login_record_invalid"

    machine_uuid = record.get("machine_uuid")
    if not isinstance(machine_uuid, str) or not machine_uuid:
        return False, "first_login_record_invalid"

    request_path = first_login_root() / f".{machine_uuid}.request"
    atomic_write_json(request_path, request)
    ssh_arguments = (
        f"-o UserKnownHostsFile={SETTINGS.known_hosts_file} "
        "-o StrictHostKeyChecking=yes "
        "-o ProxyCommand=none "
        "-o IdentitiesOnly=yes "
        "-o ConnectTimeout=10"
    )
    command = [
        str(SETTINGS.ansible_playbook_path),
        "-i",
        f"{ip},",
        "-u",
        "ansible",
        f"--private-key={SETTINGS.private_key_file}",
        "-e",
        "ansible_python_interpreter=/usr/bin/python3",
        f"--ssh-common-args={ssh_arguments}",
        "-e",
        f"@{request_path}",
        str(
            SETTINGS.ansible_project_dir
            / "playbooks"
            / "04-configure-domain-user-profile.yml"
        ),
    ]
    environment = os.environ.copy()
    environment["ANSIBLE_CONFIG"] = str(
        SETTINGS.ansible_project_dir / "ansible.cfg"
    )
    try:
        completed = subprocess.run(
            command,
            text=True,
            capture_output=True,
            timeout=900,
            check=False,
            cwd=SETTINGS.ansible_project_dir,
            env=environment,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False, "first_login_transport_unavailable"
    if completed.returncode == 0:
        return True, None
    matched = SAFE_FAILURE_RE.search(completed.stdout + "\n" + completed.stderr)
    if matched:
        return False, matched.group(1)
    return False, "first_login_profile_retryable"


def reconcile() -> None:
    root = first_login_root()
    root.mkdir(parents=True, exist_ok=True)
    os.chmod(root, 0o700)
    for path in sorted(root.glob("*.json")):
        record = read_json(path)
        if record.get("status") != "awaiting_first_domain_login":
            continue
        success, code = run_user_stage(record)
        if success:
            record["status"] = "ready"
            record["profile_finalized"] = True
        elif code in WAITING_CODES:
            continue
        else:
            record["status"] = "failed"
            record["error"] = code
        atomic_write_json(path, record)


def main() -> None:
    with exclusive_lock(SETTINGS.lock_file):
        reconcile()


if __name__ == "__main__":
    main()
