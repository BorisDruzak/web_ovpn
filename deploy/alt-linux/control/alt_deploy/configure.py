from __future__ import annotations

import re
import os
import subprocess
import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from .config import Settings
from .errors import ControlError
from .jsonio import atomic_write_json, read_json

if TYPE_CHECKING:
    from .registry import MachineRepository


REQUEST_FIELDS = frozenset(
    {
        "machine_uuid",
        "final_hostname",
        "profile",
        "domain",
        "realm",
        "workgroup",
        "computer_ou",
        "domain_test_user",
    }
)

HOSTNAME_RE = re.compile(
    r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$"
)
UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-"
    r"[0-9a-f]{4}-[0-9a-f]{12}$"
)
DOMAIN_USER_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,62}$")


def _invalid_request(message: str) -> ControlError:
    return ControlError(
        code="configure_request_invalid",
        message=message,
        exit_code=4,
    )


def _required_string(payload: Mapping[str, object], field: str) -> str:
    value = payload[field]
    if not isinstance(value, str):
        raise _invalid_request(f"Configure request field {field} must be text")

    normalized = value.strip()
    if not normalized:
        raise _invalid_request(f"Configure request field {field} is required")

    return normalized


@dataclass(frozen=True)
class ConfigureRequest:
    machine_uuid: str
    final_hostname: str
    profile: str
    domain: str
    realm: str
    workgroup: str
    computer_ou: str
    domain_test_user: str

    @classmethod
    def from_mapping(
        cls,
        payload: Mapping[str, object],
        *,
        expected_uuid: str,
    ) -> "ConfigureRequest":
        payload_keys = set(payload)
        if payload_keys != REQUEST_FIELDS:
            raise _invalid_request("Configure request fields are not allowed")

        expected = expected_uuid.strip().lower()
        machine_uuid = _required_string(payload, "machine_uuid").lower()
        if not UUID_RE.fullmatch(machine_uuid) or machine_uuid != expected:
            raise _invalid_request("Configure request UUID is invalid")

        final_hostname = _required_string(payload, "final_hostname").lower()
        if not HOSTNAME_RE.fullmatch(final_hostname):
            raise _invalid_request("Configure hostname is invalid")

        profile = _required_string(payload, "profile").lower()
        domain = _required_string(payload, "domain").lower()
        realm = _required_string(payload, "realm").upper()
        workgroup = _required_string(payload, "workgroup").upper()
        computer_ou = _required_string(payload, "computer_ou")
        domain_test_user = _required_string(payload, "domain_test_user").lower()

        if (
            profile != "standard-domain"
            or domain != "sosnadmin.local"
            or realm != "SOSNADMIN.LOCAL"
            or workgroup != "SOSNADM"
        ):
            raise _invalid_request("Configure domain values are unsupported")

        if (
            not computer_ou.startswith("OU=")
            or not computer_ou.endswith("DC=sosnadmin,DC=local")
        ):
            raise _invalid_request("Configure computer OU is invalid")

        if not DOMAIN_USER_RE.fullmatch(domain_test_user):
            raise _invalid_request("Configure domain test user is invalid")

        return cls(
            machine_uuid=machine_uuid,
            final_hostname=final_hostname,
            profile=profile,
            domain=domain,
            realm=realm,
            workgroup=workgroup,
            computer_ou=computer_ou,
            domain_test_user=domain_test_user,
        )

    def to_dict(self) -> dict[str, str]:
        return {
            "machine_uuid": self.machine_uuid,
            "final_hostname": self.final_hostname,
            "profile": self.profile,
            "domain": self.domain,
            "realm": self.realm,
            "workgroup": self.workgroup,
            "computer_ou": self.computer_ou,
            "domain_test_user": self.domain_test_user,
        }


CONFIGURE_ACTIONS = [
    "manual_preflight",
    "set_final_hostname",
    "configure_domain_dns",
    "join_or_verify_domain",
    "install_standard_packages",
    "verify_domain_workstation",
]


class ConfigurePlanner:
    def __init__(
        self,
        settings: Settings,
        *,
        machines: "MachineRepository | None" = None,
    ) -> None:
        self.settings = settings
        if machines is None:
            from .registry import MachineRepository

            machines = MachineRepository(settings)
        self.machines = machines

    def preview(
        self,
        machine_uuid: str,
        request: ConfigureRequest,
    ) -> dict[str, object]:
        machine = self.machines.get(machine_uuid)
        if not machine.ip:
            raise ControlError(
                code="machine_missing_ip",
                message="Registered machine has no IP address",
                exit_code=5,
                details={"machine_uuid": machine.uuid},
            )

        return {
            "status": "ok",
            "machine_uuid": machine.uuid,
            "target_ip": machine.ip,
            "playbook": "03-configure-domain-workstation.yml",
            "request": request.to_dict(),
            "actions": list(CONFIGURE_ACTIONS),
        }

    @property
    def configure_playbook(self) -> Path:
        return self.settings.ansible_project_dir / "playbooks" / "03-configure-domain-workstation.yml"

    def start(self, machine_uuid: str, request: ConfigureRequest) -> dict[str, object]:
        machine = self.machines.get(machine_uuid)
        if not machine.ip:
            raise ControlError(code="machine_missing_ip", message="Registered machine has no IP address", exit_code=5)

        required = {
            "ansible_playbook": self.settings.ansible_playbook_path,
            "private_key": self.settings.private_key_file,
            "known_hosts": self.settings.known_hosts_file,
            "configure_playbook": self.configure_playbook,
        }
        missing = [name for name, path in required.items() if not path.is_file()]
        if missing:
            raise ControlError(code="configure_not_configured", message="Domain configure is not fully configured", exit_code=5, details={"missing": missing})

        run_id = uuid.uuid4().hex
        run_dir = self.settings.state_root / "configure-runs" / run_id
        run_dir.mkdir(parents=True, exist_ok=False)
        os.chmod(run_dir.parent, 0o700)
        os.chmod(run_dir, 0o700)
        request_path = run_dir / "request.json"
        result_path = run_dir / "result.json"
        log_path = run_dir / "ansible.log"
        atomic_write_json(request_path, request.to_dict())

        strict_ssh_arguments = (
            f"-o UserKnownHostsFile={self.settings.known_hosts_file} "
            "-o StrictHostKeyChecking=yes -o ProxyCommand=none "
            "-o IdentitiesOnly=yes -o ConnectTimeout=10"
        )
        command = [
            str(self.settings.ansible_playbook_path), "-i", f"{machine.ip},", "-u", "ansible",
            f"--private-key={self.settings.private_key_file}",
            f"--ssh-common-args={strict_ssh_arguments}",
            "-e", "ansible_python_interpreter=/usr/bin/python3",
            "-e", f"@{request_path}",
            "-e", f"configure_result_file={result_path}",
            str(self.configure_playbook),
        ]
        environment = os.environ.copy()
        environment["ANSIBLE_CONFIG"] = str(
            self.settings.ansible_project_dir / "ansible.cfg"
        )
        with log_path.open("w", encoding="utf-8") as log_stream:
            os.chmod(log_path, 0o600)
            completed = subprocess.run(command, shell=False, text=True, stdout=log_stream, stderr=subprocess.STDOUT, timeout=1800, check=False, cwd=self.settings.ansible_project_dir, env=environment)

        if completed.returncode != 0:
            raise ControlError(code="domain_join_failed", message="Ansible domain configure failed", exit_code=7, details={"run_id": run_id})
        try:
            result = read_json(result_path)
        except (OSError, ValueError) as exc:
            raise ControlError(code="domain_verification_failed", message="Domain configure did not produce a valid result", exit_code=7, details={"run_id": run_id}) from exc
        result["run_id"] = run_id
        return result
