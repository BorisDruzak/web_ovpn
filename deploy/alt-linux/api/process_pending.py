#!/usr/bin/python3

from __future__ import annotations

import ipaddress
import json
import os
import re
import socket
import stat
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

from alt_deploy.config import Settings
from alt_deploy.errors import ControlError
from alt_deploy.locks import exclusive_lock
from alt_deploy.machine_archive_repository import (
    MachineArchiveRepository,
)
from alt_deploy.registration_records import (
    load_registration_candidate,
)

SETTINGS = Settings.from_env()
PENDING_DIR = SETTINGS.registration_root / "pending"
READY_DIR = SETTINGS.registration_root / "ready"
FAILED_DIR = SETTINGS.registration_root / "failed"
CONFIGURE_REQUESTS_DIR = Path(
    os.environ.get(
        "ALT_DEPLOY_CONFIGURE_REQUESTS",
        "/srv/alt-deploy/configure-requests",
    )
)

KNOWN_HOSTS = SETTINGS.known_hosts_file
PRIVATE_KEY = SETTINGS.private_key_file

ANSIBLE = "/usr/bin/ansible"
ANSIBLE_PLAYBOOK = "/usr/bin/ansible-playbook"
SSH_KEYGEN = "/usr/bin/ssh-keygen"
SSH_KEYSCAN = "/usr/bin/ssh-keyscan"
WORKSTATIONCTL = os.environ.get(
    "ALT_DEPLOY_WORKSTATIONCTL",
    "/usr/local/sbin/workstationctl",
)

ALLOWED_NETWORKS = (
    ipaddress.ip_network("192.168.100.0/23"),
)
MACHINE_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-"
    r"[0-9a-f]{4}-[0-9a-f]{12}$"
)
ASSIGNED_DOMAIN_USER_RE = re.compile(
    r"^[a-z0-9][a-z0-9._-]{0,62}@sosnadmin\.local$"
)
PREFLIGHT_FAILURE_RE = re.compile(
    r"ALT_PREFLIGHT_FAILURE:([a-z][a-z0-9_]{1,79})"
)


class PendingConfigurationError(RuntimeError):
    """A secret-free terminal error emitted by the auto-configure handoff."""


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def run_command(
    command: list[str],
    *,
    timeout: int = 60,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        text=True,
        capture_output=True,
        timeout=timeout,
        check=False,
    )


def wait_for_ssh(ip: str) -> bool:
    for _ in range(30):
        try:
            with socket.create_connection(
                (ip, 22),
                timeout=2,
            ):
                return True
        except OSError:
            time.sleep(2)

    return False


def save_record(
    path: Path,
    record: dict[str, object],
    destination_dir: Path,
) -> None:
    machine_key = str(record["machine_key"])
    destination = destination_dir / f"{machine_key}.json"

    path.write_text(
        json.dumps(
            record,
            ensure_ascii=False,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    os.chmod(path, 0o600)

    for other_dir in (READY_DIR, FAILED_DIR):
        other = other_dir / f"{machine_key}.json"
        if other != destination:
            other.unlink(missing_ok=True)

    path.replace(destination)


def finalize_record(
    source_path: Path,
    record: dict[str, object],
    destination_dir: Path,
    captured_generation: str,
) -> bool:
    with exclusive_lock(SETTINGS.lock_file):
        if (
            not source_path.exists()
            and not source_path.is_symlink()
        ):
            return False

        try:
            current = load_registration_candidate(
                source_path,
                "pending",
            )
        except ControlError:
            return False

        if current.generation.value != captured_generation:
            return False

        committed = MachineArchiveRepository(
            SETTINGS
        ).committed_generation_index()
        if captured_generation in committed:
            return False

        save_record(
            source_path,
            record,
            destination_dir,
        )
        return True


def mark_failed(
    path: Path,
    record: dict[str, object],
    message: str,
    captured_generation: str,
) -> bool:
    failed_record = dict(record)
    failed_record["status"] = "failed"
    failed_record["failed_at"] = utc_now()
    failed_record["error"] = message[-10000:]

    return finalize_record(
        path,
        failed_record,
        FAILED_DIR,
        captured_generation,
    )


def _configure_request_path(machine_uuid: str) -> Path | None:
    normalized_uuid = machine_uuid.strip().lower()
    if not MACHINE_UUID_RE.fullmatch(normalized_uuid):
        raise PendingConfigurationError("configure_request_invalid")

    path = CONFIGURE_REQUESTS_DIR / f"{normalized_uuid}.json"
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise PendingConfigurationError(
            "configure_request_unavailable"
        ) from exc

    if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(
        metadata.st_mode
    ):
        raise PendingConfigurationError("configure_request_invalid")

    return path


def _run_configure_command(
    command: list[str],
    *,
    error_code: str,
) -> dict[str, object]:
    try:
        completed = run_command(command, timeout=1900)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise PendingConfigurationError(error_code) from exc

    if completed.returncode != 0:
        raise PendingConfigurationError(error_code)

    try:
        payload = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise PendingConfigurationError(error_code) from exc

    if not isinstance(payload, dict):
        raise PendingConfigurationError(error_code)

    return payload


def validate_assigned_domain_user(record: dict[str, object]) -> None:
    assigned_domain_user = record.get("assigned_domain_user")
    if assigned_domain_user is None:
        return
    if not isinstance(assigned_domain_user, str):
        raise PendingConfigurationError("assigned_domain_user_invalid")

    normalized_user = assigned_domain_user.strip().lower()
    if not ASSIGNED_DOMAIN_USER_RE.fullmatch(normalized_user):
        raise PendingConfigurationError("assigned_domain_user_invalid")

    playbook = (
        SETTINGS.ansible_project_dir
        / "playbooks"
        / "00-validate-assigned-domain-user.yml"
    )
    if not playbook.is_file():
        raise PendingConfigurationError(
            "assigned_domain_user_validation_unavailable"
        )

    completed = run_command(
        [
            ANSIBLE_PLAYBOOK,
            "--extra-vars",
            f"assigned_domain_user={normalized_user}",
            str(playbook),
        ],
        timeout=180,
    )
    if completed.returncode == 0:
        record["assigned_domain_user"] = normalized_user
        record["assigned_domain_user_validation"] = "valid"
        return

    output = completed.stdout + "\n" + completed.stderr
    match = PREFLIGHT_FAILURE_RE.search(output)
    if match and match.group(1) == "assigned_domain_user_not_found":
        raise PendingConfigurationError("assigned_domain_user_not_found")
    raise PendingConfigurationError(
        "assigned_domain_user_validation_unavailable"
    )


def auto_configure(
    record: dict[str, object],
    *,
    ip: str,
) -> tuple[dict[str, object], dict[str, object]] | None:
    machine_uuid = str(record["uuid"]).lower()
    request_path = _configure_request_path(machine_uuid)
    if request_path is None:
        return None

    preview = _run_configure_command(
        [
            WORKSTATIONCTL,
            "--json",
            "configure",
            "preview",
            machine_uuid,
            "--vars-file",
            str(request_path),
        ],
        error_code="configure_preview_failed",
    )
    if (
        preview.get("status") != "ok"
        or preview.get("machine_uuid") != machine_uuid
        or preview.get("target_ip") != ip
    ):
        raise PendingConfigurationError("configure_preview_invalid")

    result = _run_configure_command(
        [
            WORKSTATIONCTL,
            "--json",
            "configure",
            "start",
            machine_uuid,
            "--vars-file",
            str(request_path),
        ],
        error_code="configure_start_failed",
    )
    if (
        result.get("machine_uuid") != machine_uuid
        or not isinstance(result.get("run_id"), str)
        or not result["run_id"]
    ):
        raise PendingConfigurationError("configure_start_invalid")

    return preview, result


def _remove_invalid_pending(path: Path) -> None:
    with exclusive_lock(SETTINGS.lock_file):
        try:
            metadata = path.lstat()
        except OSError:
            return
        if not stat.S_ISREG(metadata.st_mode):
            return
        try:
            path.unlink()
        except OSError:
            return


def process_record(path: Path) -> None:
    try:
        candidate = load_registration_candidate(
            path,
            "pending",
        )
    except ControlError as exc:
        _remove_invalid_pending(path)
        print(f"{path.name}: invalid registration: {exc.code}")
        return

    record: dict[str, object] = dict(candidate.payload)
    captured_generation = candidate.generation.value

    try:
        machine_key = str(record["machine_key"])
        hostname = str(record["hostname"])
        ip = str(record["ip"])

        address = ipaddress.ip_address(ip)
        if not any(
            address in network
            for network in ALLOWED_NETWORKS
        ):
            raise ValueError(
                f"IP outside deployment networks: {ip}"
            )

        if not PRIVATE_KEY.is_file():
            raise RuntimeError(
                f"Private key not found: {PRIVATE_KEY}"
            )

        print(f"{machine_key}: waiting for SSH on {ip}")

        if not wait_for_ssh(ip):
            raise RuntimeError(
                f"SSH port did not become available: {ip}:22"
            )

        # Remove stale keys only from the isolated deployment
        # known_hosts file.
        for target in (ip, hostname):
            run_command(
                [
                    SSH_KEYGEN,
                    "-f",
                    str(KNOWN_HOSTS),
                    "-R",
                    target,
                ],
                timeout=10,
            )

        scan = run_command(
            [
                SSH_KEYSCAN,
                "-T",
                "10",
                "-t",
                "ed25519,ecdsa,rsa",
                ip,
            ],
            timeout=20,
        )

        if scan.returncode != 0 or not scan.stdout.strip():
            raise RuntimeError(
                "ssh-keyscan failed: "
                + scan.stderr.strip()
            )

        with KNOWN_HOSTS.open(
            "a",
            encoding="utf-8",
        ) as known_hosts:
            known_hosts.write(scan.stdout)

        os.chmod(KNOWN_HOSTS, 0o600)

        ssh_arguments = (
            f"-o UserKnownHostsFile={KNOWN_HOSTS} "
            "-o StrictHostKeyChecking=yes "
            "-o ProxyCommand=none "
            "-o IdentitiesOnly=yes "
            "-o ConnectTimeout=10"
        )

        result = run_command(
            [
                ANSIBLE,
                "all",
                "-i",
                f"{ip},",
                "-u",
                "ansible",
                "--private-key",
                str(PRIVATE_KEY),
                "-e",
                "ansible_python_interpreter=/usr/bin/python3",
                f"--ssh-common-args={ssh_arguments}",
                "-m",
                "ansible.builtin.ping",
            ],
            timeout=90,
        )

        if result.returncode != 0:
            raise RuntimeError(
                "Ansible ping failed:\n"
                + result.stdout
                + "\n"
                + result.stderr
            )

        preflight = run_command(
            [
                WORKSTATIONCTL,
                "--json",
                "preflight",
                machine_key,
            ],
            timeout=240,
        )

        if preflight.returncode != 0:
            raise RuntimeError(
                "Automatic preflight failed:\n"
                + preflight.stdout[-10000:]
                + "\n"
                + preflight.stderr[-10000:]
            )

        try:
            preflight_payload = json.loads(
                preflight.stdout
            )
        except json.JSONDecodeError as exc:
            raise RuntimeError(
                "Automatic preflight returned invalid JSON"
            ) from exc

        if not isinstance(preflight_payload, dict):
            raise RuntimeError(
                "Automatic preflight returned invalid payload"
            )

        if preflight_payload.get("status") != "ok":
            raise RuntimeError(
                "Automatic preflight did not return status=ok"
            )

        preflight_result = preflight_payload.get(
            "preflight"
        )

        if not isinstance(preflight_result, dict):
            raise RuntimeError(
                "Automatic preflight result is missing"
            )

        record.pop("failed_at", None)
        record.pop("error", None)

        record["verified_at"] = utc_now()
        record["ansible_output"] = result.stdout[-10000:]
        record["preflight"] = dict(preflight_result)
        record["preflight_verified_at"] = utc_now()

        validate_assigned_domain_user(record)

        configure = auto_configure(record, ip=ip)
        if configure is None:
            record["status"] = "awaiting_assignment"
        else:
            configure_preview, configure_result = configure
            record["status"] = "configured"
            record["configure_preview"] = configure_preview
            record["configure_result"] = configure_result
            record["configured_at"] = utc_now()

        finalized = finalize_record(
            path,
            record,
            READY_DIR,
            captured_generation,
        )

        if finalized:
            print(
                f"{machine_key}: "
                f"{str(record['status']).upper()} at {ip}"
            )
        else:
            print(
                f"{machine_key}: stale generation result discarded"
            )

    except Exception as exc:
        print(f"{path.name}: FAILED: {exc}")
        finalized = mark_failed(
            path,
            record,
            str(exc),
            captured_generation,
        )
        if not finalized:
            print(
                f"{path.name}: stale failure result discarded"
            )


def main() -> None:
    for directory in (
        PENDING_DIR,
        READY_DIR,
        FAILED_DIR,
    ):
        directory.mkdir(parents=True, exist_ok=True)

    for path in sorted(PENDING_DIR.glob("*.json")):
        process_record(path)


if __name__ == "__main__":
    main()
