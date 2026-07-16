#!/usr/bin/python3

from __future__ import annotations

import ipaddress
import json
import os
import socket
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

PENDING_DIR = Path("/srv/alt-deploy/registration/pending")
READY_DIR = Path("/srv/alt-deploy/registration/ready")
FAILED_DIR = Path("/srv/alt-deploy/registration/failed")

KNOWN_HOSTS = Path("/home/altserver/.ssh/known_hosts_autoinstall")
PRIVATE_KEY = Path("/home/altserver/.ssh/id_ed25519")

ANSIBLE = "/usr/bin/ansible"
SSH_KEYGEN = "/usr/bin/ssh-keygen"
SSH_KEYSCAN = "/usr/bin/ssh-keyscan"

ALLOWED_NETWORKS = (
    ipaddress.ip_network("192.168.100.0/23"),
)


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
            with socket.create_connection((ip, 22), timeout=2):
                return True
        except OSError:
            time.sleep(2)

    return False


def save_record(path: Path, record: dict, destination_dir: Path) -> None:
    machine_key = record["machine_key"]
    destination = destination_dir / f"{machine_key}.json"

    path.write_text(
        json.dumps(record, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    os.chmod(path, 0o600)

    for other_dir in (READY_DIR, FAILED_DIR):
        other = other_dir / f"{machine_key}.json"
        if other != destination:
            other.unlink(missing_ok=True)

    path.replace(destination)


def mark_failed(path: Path, record: dict, message: str) -> None:
    record["status"] = "failed"
    record["failed_at"] = utc_now()
    record["error"] = message[-10000:]

    save_record(path, record, FAILED_DIR)


def process_record(path: Path) -> None:
    try:
        record = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        path.unlink(missing_ok=True)
        print(f"{path.name}: invalid JSON: {exc}")
        return

    try:
        machine_key = str(record["machine_key"])
        hostname = str(record["hostname"])
        ip = str(record["ip"])

        address = ipaddress.ip_address(ip)
        if not any(address in network for network in ALLOWED_NETWORKS):
            raise ValueError(f"IP outside deployment networks: {ip}")

        if not PRIVATE_KEY.is_file():
            raise RuntimeError(f"Private key not found: {PRIVATE_KEY}")

        print(f"{machine_key}: waiting for SSH on {ip}")

        if not wait_for_ssh(ip):
            raise RuntimeError(f"SSH port did not become available: {ip}:22")

        # Remove stale keys only from the isolated deployment known_hosts file.
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
            raise RuntimeError("ssh-keyscan failed: " + scan.stderr.strip())

        with KNOWN_HOSTS.open("a", encoding="utf-8") as known_hosts:
            known_hosts.write(scan.stdout)

        os.chmod(KNOWN_HOSTS, 0o600)

        ssh_arguments = (
            f"-o UserKnownHostsFile={KNOWN_HOSTS} "
            "-o StrictHostKeyChecking=yes "
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

        record.pop("failed_at", None)
        record.pop("error", None)
        record["status"] = "ready"
        record["verified_at"] = utc_now()
        record["ansible_output"] = result.stdout[-10000:]

        save_record(path, record, READY_DIR)

        print(f"{machine_key}: READY at {ip}")

    except Exception as exc:
        print(f"{path.name}: FAILED: {exc}")
        mark_failed(path, record, str(exc))


def main() -> None:
    for directory in (PENDING_DIR, READY_DIR, FAILED_DIR):
        directory.mkdir(parents=True, exist_ok=True)

    for path in sorted(PENDING_DIR.glob("*.json")):
        process_record(path)


if __name__ == "__main__":
    main()
