from __future__ import annotations

import json
import os
import re
import subprocess
import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from .config import Settings
from .errors import ControlError
from .jsonio import atomic_write_json, read_json
from .vault import VaultHealthChecker

if TYPE_CHECKING:
    from .registry import MachineRepository


REQUEST_FIELDS = frozenset(
    {
        "machine_uuid",
        "final_hostname",
        "hostname_mode",
        "profile",
        "domain",
        "realm",
        "workgroup",
        "computer_ou",
        "domain_test_user",
    }
)
PROFILE_FIELDS = frozenset(
    {"software_profile", "remote_access_profile", "assigned_domain_user"}
)
SOFTWARE_PROFILES = frozenset({"base", "core-apps"})
REMOTE_ACCESS_PROFILES = frozenset({"none", "krfb"})
KRFB_NETWORK_CONFIRMATION_VARIABLE = (
    "ALT_DEPLOY_KRFB_TCP_5900_RESTRICTED_CONFIRMED"
)
KRFB_ANSIBLE_CONFIRMATION_VARIABLE = (
    "alt_deploy_krfb_tcp_5900_restricted_confirmed"
)
CONFIGURE_RESULT_FIELDS = frozenset(
    {
        "schema_version",
        "machine_uuid",
        "hostname",
        "profile",
        "status",
        "phase",
        "retryable",
        "recovered",
        "reboot_required",
        "error",
        "components",
        "verification",
    }
)
LEGACY_CONFIGURE_RESULT_FIELDS = frozenset(
    {
        "machine_uuid",
        "hostname",
        "profile",
        "domain",
        "already_joined",
        "reboot_required",
        "verification",
    }
)
CONFIGURE_RESULT_STATUSES = frozenset({"successful", "degraded", "failed"})
CONFIGURE_RESULT_PHASES = frozenset(
    {
        "preflight",
        "identity",
        "upgrade",
        "network",
        "domain_join",
        "domain_core_verify",
        "components",
        "finalize",
    }
)
CONFIGURE_ERROR_FIELDS = frozenset({"code", "class", "safe_message"})

HOSTNAME_RE = re.compile(r"^(lin|alt|win|deb)-[a-z][0-9]?-(pc[1-9][0-9]*)$")
HOSTNAME_MODES = frozenset({"verify", "change_confirmed"})
UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-"
    r"[0-9a-f]{4}-[0-9a-f]{12}$"
)
DOMAIN_USER_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,62}$")
DOMAIN_USER_UPN_RE = re.compile(
    r"^[a-z0-9][a-z0-9._-]{0,62}@sosnadmin\.local$"
)
CONFIGURE_ERROR_CODE_RE = re.compile(r"^[a-z][a-z0-9_]{1,79}$")
CONFIGURE_ERROR_CLASS_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_.-]{0,127}$")
CONFIGURE_ERROR_SAFE_MESSAGE_RE = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9 .,;:()/_-]{0,239}$"
)


def _invalid_request(message: str) -> ControlError:
    return ControlError(
        code="configure_request_invalid",
        message=message,
        exit_code=4,
    )


def _hostname_invalid(message: str) -> ControlError:
    return ControlError(code="hostname_invalid", message=message, exit_code=4)


def _required_string(payload: Mapping[str, object], field: str) -> str:
    value = payload[field]
    if not isinstance(value, str):
        raise _invalid_request(f"Configure request field {field} must be text")

    normalized = value.strip()
    if not normalized:
        raise _invalid_request(f"Configure request field {field} is required")

    return normalized


def _krfb_network_restriction_confirmed() -> bool:
    return os.environ.get(KRFB_NETWORK_CONFIRMATION_VARIABLE, "false") == "true"


def _read_configure_result(
    payload: object,
    request: "ConfigureRequest",
) -> dict[str, object]:
    if not isinstance(payload, Mapping):
        raise ValueError("Configure result must be a mapping")

    result = dict(payload)
    fields = set(result)
    if fields == LEGACY_CONFIGURE_RESULT_FIELDS:
        if (
            result["machine_uuid"] != request.machine_uuid
            or result["hostname"] != request.final_hostname
            or result["profile"] != request.profile
            or result["domain"] != request.domain
            or type(result["already_joined"]) is not bool
            or type(result["reboot_required"]) is not bool
            or not isinstance(result["verification"], Mapping)
        ):
            raise ValueError("Legacy configure result is invalid")
        return result

    if fields != CONFIGURE_RESULT_FIELDS:
        raise ValueError("Configure result fields are invalid")
    if (
        type(result["schema_version"]) is not int
        or result["schema_version"] != 1
        or result["machine_uuid"] != request.machine_uuid
        or result["hostname"] != request.final_hostname
        or result["profile"] != request.profile
        or not isinstance(result["status"], str)
        or result["status"] not in CONFIGURE_RESULT_STATUSES
        or not isinstance(result["phase"], str)
        or result["phase"] not in CONFIGURE_RESULT_PHASES
        or any(
            type(result[field]) is not bool
            for field in ("retryable", "recovered", "reboot_required")
        )
        or not isinstance(result["components"], Mapping)
        or not isinstance(result["verification"], Mapping)
    ):
        raise ValueError("Configure result is invalid")

    error = result["error"]
    if result["status"] != "failed":
        if error is not None:
            raise ValueError("Configure result error is invalid")
    elif (
        not isinstance(error, Mapping)
        or set(error) != CONFIGURE_ERROR_FIELDS
        or not isinstance(error["code"], str)
        or not CONFIGURE_ERROR_CODE_RE.fullmatch(error["code"])
        or not isinstance(error["class"], str)
        or not CONFIGURE_ERROR_CLASS_RE.fullmatch(error["class"])
        or not isinstance(error["safe_message"], str)
        or not CONFIGURE_ERROR_SAFE_MESSAGE_RE.fullmatch(error["safe_message"])
    ):
        raise ValueError("Configure result error is invalid")

    return result


@dataclass(frozen=True)
class ConfigureRequest:
    machine_uuid: str
    final_hostname: str
    hostname_mode: str
    profile: str
    domain: str
    realm: str
    workgroup: str
    computer_ou: str
    domain_test_user: str
    software_profile: str = "base"
    remote_access_profile: str = "none"
    assigned_domain_user: str | None = None

    @classmethod
    def from_mapping(
        cls,
        payload: Mapping[str, object],
        *,
        expected_uuid: str,
    ) -> "ConfigureRequest":
        payload_keys = set(payload)
        if payload_keys not in (REQUEST_FIELDS, REQUEST_FIELDS | PROFILE_FIELDS):
            raise _invalid_request("Configure request fields are not allowed")

        expected = expected_uuid.strip().lower()
        machine_uuid = _required_string(payload, "machine_uuid").lower()
        if not UUID_RE.fullmatch(machine_uuid) or machine_uuid != expected:
            raise _invalid_request("Configure request UUID is invalid")

        final_hostname = _required_string(payload, "final_hostname").lower()
        if not HOSTNAME_RE.fullmatch(final_hostname):
            raise _hostname_invalid("Configure hostname is invalid")

        hostname_mode = _required_string(payload, "hostname_mode").lower()
        if hostname_mode not in HOSTNAME_MODES:
            raise _invalid_request("Configure hostname mode is unsupported")

        profile = _required_string(payload, "profile").lower()
        domain = _required_string(payload, "domain").lower()
        realm = _required_string(payload, "realm").upper()
        workgroup = _required_string(payload, "workgroup").upper()
        computer_ou = _required_string(payload, "computer_ou")
        domain_test_user = _required_string(payload, "domain_test_user").lower()
        if payload_keys == REQUEST_FIELDS:
            software_profile = "base"
            remote_access_profile = "none"
            assigned_domain_user = None
        else:
            software_profile = _required_string(payload, "software_profile").lower()
            remote_access_profile = _required_string(
                payload, "remote_access_profile"
            ).lower()
            if (
                software_profile not in SOFTWARE_PROFILES
                or remote_access_profile not in REMOTE_ACCESS_PROFILES
            ):
                raise _invalid_request("Configure profile is unsupported")
            assigned_value = payload["assigned_domain_user"]
            if assigned_value is None:
                assigned_domain_user = None
            elif isinstance(assigned_value, str):
                assigned_domain_user = assigned_value.strip().lower()
                if not assigned_domain_user:
                    raise _invalid_request("Configure assigned domain user is required")
                if not (
                    DOMAIN_USER_RE.fullmatch(assigned_domain_user)
                    or DOMAIN_USER_UPN_RE.fullmatch(assigned_domain_user)
                ):
                    raise _invalid_request("Configure assigned domain user is invalid")
            else:
                raise _invalid_request("Configure assigned domain user must be text or null")

            if (
                (software_profile == "core-apps" or remote_access_profile == "krfb")
                and assigned_domain_user is None
            ):
                raise _invalid_request("Configure assigned domain user is required")

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

        if not (
            DOMAIN_USER_RE.fullmatch(domain_test_user)
            or DOMAIN_USER_UPN_RE.fullmatch(domain_test_user)
        ):
            raise _invalid_request("Configure domain test user is invalid")

        return cls(
            machine_uuid=machine_uuid,
            final_hostname=final_hostname,
            hostname_mode=hostname_mode,
            profile=profile,
            domain=domain,
            realm=realm,
            workgroup=workgroup,
            computer_ou=computer_ou,
            domain_test_user=domain_test_user,
            software_profile=software_profile,
            remote_access_profile=remote_access_profile,
            assigned_domain_user=assigned_domain_user,
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "machine_uuid": self.machine_uuid,
            "final_hostname": self.final_hostname,
            "hostname_mode": self.hostname_mode,
            "profile": self.profile,
            "domain": self.domain,
            "realm": self.realm,
            "workgroup": self.workgroup,
            "computer_ou": self.computer_ou,
            "domain_test_user": self.domain_test_user,
            "software_profile": self.software_profile,
            "remote_access_profile": self.remote_access_profile,
            "assigned_domain_user": self.assigned_domain_user,
        }

    def actions(self) -> list[str]:
        actions = list(CONFIGURE_ACTIONS)
        return actions

    def deferred_actions(self) -> list[str]:
        actions: list[str] = []
        if self.software_profile == "core-apps":
            actions.append("install_core_apps")
        if self.remote_access_profile == "krfb":
            actions.append("configure_krfb")
        return actions


CONFIGURE_ACTIONS = [
    "manual_preflight",
    "verify_or_change_hostname",
    "configure_domain_dns",
    "join_or_verify_domain",
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
            "actions": request.actions(),
            "deferred_actions": request.deferred_actions(),
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

        vault_checker = VaultHealthChecker(self.settings)
        vault_checker.check_ad_join()
        krfb_network_restriction_confirmed = False
        if request.remote_access_profile == "krfb":
            vault_checker.check_krfb()
            krfb_network_restriction_confirmed = (
                _krfb_network_restriction_confirmed()
            )
            if not krfb_network_restriction_confirmed:
                raise ControlError(
                    code="remote_access_network_restriction_unconfirmed",
                    message="Restricted TCP 5900 access is not confirmed",
                    exit_code=7,
                )

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
        ]
        if krfb_network_restriction_confirmed:
            command.extend(
                [
                    "-e",
                    json.dumps(
                        {KRFB_ANSIBLE_CONFIRMATION_VARIABLE: True},
                        separators=(",", ":"),
                    ),
                ]
            )
        command.append(str(self.configure_playbook))
        environment = os.environ.copy()
        environment.pop(KRFB_NETWORK_CONFIRMATION_VARIABLE, None)
        environment["ANSIBLE_CONFIG"] = str(
            self.settings.ansible_project_dir / "ansible.cfg"
        )
        try:
            with log_path.open("w", encoding="utf-8") as log_stream:
                os.chmod(log_path, 0o600)
                completed = subprocess.run(command, shell=False, text=True, stdout=log_stream, stderr=subprocess.STDOUT, timeout=5400, check=False, cwd=self.settings.ansible_project_dir, env=environment)
        except subprocess.TimeoutExpired as exc:
            raise ControlError(
                code="domain_join_timeout",
                message="Ansible domain configure timed out",
                exit_code=7,
                details={"run_id": run_id},
            ) from exc

        if completed.returncode != 0:
            error_code = "domain_join_failed"
            marker_codes = (
                "hostname_mismatch",
                "domain_computer_conflict",
            )
            log_content = log_path.read_text(encoding="utf-8", errors="replace")
            for marker_code in marker_codes:
                if f"ALT_PREFLIGHT_FAILURE:{marker_code}" in log_content:
                    error_code = marker_code
                    break
            raise ControlError(code=error_code, message="Ansible domain configure failed", exit_code=7, details={"run_id": run_id})
        try:
            result = _read_configure_result(read_json(result_path), request)
        except (OSError, ValueError) as exc:
            raise ControlError(code="domain_verification_failed", message="Domain configure did not produce a valid result", exit_code=7, details={"run_id": run_id}) from exc
        result["run_id"] = run_id
        return result
