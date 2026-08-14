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
        "software_profile",
        "remote_access_profile",
        "assigned_domain_user",
    }
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
CONFIGURE_RESULT_STATUSES = frozenset(
    {"successful", "degraded", "failed"}
)
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
SAFE_ERROR_CODE_RE = re.compile(r"^[a-z][a-z0-9_]{1,79}$")
HOSTNAME_RE = re.compile(r"^(lin|alt|win|deb)-[a-z][0-9]?-(pc[1-9][0-9]*)$")
HOSTNAME_MODES = frozenset({"verify", "change_confirmed"})
SOFTWARE_PROFILES = frozenset({"base", "core-apps"})
REMOTE_ACCESS_PROFILES = frozenset({"none", "krfb"})
UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-"
    r"[0-9a-f]{4}-[0-9a-f]{12}$"
)
DOMAIN_USER_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,62}$")
DOMAIN_USER_UPN_RE = re.compile(
    r"^[a-z0-9][a-z0-9._-]{0,62}@sosnadmin\.local$"
)
PREFLIGHT_FAILURE_RE = re.compile(r"ALT_PREFLIGHT_FAILURE:([a-z][a-z0-9_]{1,79})")


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
    software_profile: str
    remote_access_profile: str
    assigned_domain_user: str | None

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
        software_profile = _required_string(payload, "software_profile").lower()
        remote_access_profile = _required_string(
            payload, "remote_access_profile"
        ).lower()
        assigned_domain_user_raw = payload["assigned_domain_user"]

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

        if software_profile not in SOFTWARE_PROFILES:
            raise _invalid_request("Configure software profile is unsupported")
        if remote_access_profile not in REMOTE_ACCESS_PROFILES:
            raise _invalid_request("Configure remote access profile is unsupported")

        if remote_access_profile == "none":
            if assigned_domain_user_raw is not None:
                raise _invalid_request(
                    "Configure assigned domain user must be empty without remote access"
                )
            assigned_domain_user = None
        else:
            if not isinstance(assigned_domain_user_raw, str):
                raise _invalid_request(
                    "Configure assigned domain user is required for KRFB"
                )
            assigned_domain_user = assigned_domain_user_raw.strip().lower()
            if not assigned_domain_user or not (
                DOMAIN_USER_RE.fullmatch(assigned_domain_user)
                or DOMAIN_USER_UPN_RE.fullmatch(assigned_domain_user)
            ):
                raise _invalid_request("Configure assigned domain user is invalid")

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
        actions = [
            "manual_preflight",
            "verify_or_change_hostname",
            "configure_domain_dns",
            "join_or_verify_domain",
            "apply_plasma_baseline",
            "install_standard_packages",
            "verify_domain_workstation",
        ]
        if self.software_profile == "core-apps":
            actions.append("install_core_apps")
        if self.remote_access_profile == "krfb":
            actions.append("configure_krfb")
        return actions


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
        }

    @property
    def configure_playbook(self) -> Path:
        return self.settings.ansible_project_dir / "playbooks" / "03-configure-domain-workstation.yml"

    @staticmethod
    def _synthetic_failure(
        request: ConfigureRequest,
        *,
        code: str,
        error_class: str,
        safe_message: str,
        retryable: bool,
    ) -> dict[str, object]:
        return {
            "schema_version": 1,
            "machine_uuid": request.machine_uuid,
            "hostname": request.final_hostname,
            "profile": request.profile,
            "status": "failed",
            "phase": "finalize",
            "retryable": retryable,
            "recovered": False,
            "reboot_required": False,
            "error": {
                "code": code,
                "class": error_class,
                "safe_message": safe_message,
            },
            "components": {},
            "verification": {},
        }

    @staticmethod
    def _read_structured_result(
        result_path: Path,
        *,
        request: ConfigureRequest,
    ) -> dict[str, object] | None:
        try:
            result = read_json(result_path)
        except (OSError, ValueError):
            return None

        if "schema_version" not in result:
            return None

        if set(result) != CONFIGURE_RESULT_FIELDS:
            raise ControlError(
                code="configure_result_contract_invalid",
                message="Domain configure produced an invalid result",
                exit_code=7,
            )
        if result.get("schema_version") != 1:
            raise ControlError(
                code="configure_result_contract_invalid",
                message="Domain configure produced an invalid result",
                exit_code=7,
            )
        if result.get("machine_uuid") != request.machine_uuid:
            raise ControlError(
                code="configure_result_contract_invalid",
                message="Domain configure produced an invalid result",
                exit_code=7,
            )
        if result.get("hostname") != request.final_hostname:
            raise ControlError(
                code="configure_result_contract_invalid",
                message="Domain configure produced an invalid result",
                exit_code=7,
            )
        if result.get("profile") != request.profile:
            raise ControlError(
                code="configure_result_contract_invalid",
                message="Domain configure produced an invalid result",
                exit_code=7,
            )
        if result.get("status") not in CONFIGURE_RESULT_STATUSES:
            raise ControlError(
                code="configure_result_contract_invalid",
                message="Domain configure produced an invalid result",
                exit_code=7,
            )
        if result.get("phase") not in CONFIGURE_RESULT_PHASES:
            raise ControlError(
                code="configure_result_contract_invalid",
                message="Domain configure produced an invalid result",
                exit_code=7,
            )
        for field in (
            "retryable",
            "recovered",
            "reboot_required",
        ):
            if not isinstance(result.get(field), bool):
                raise ControlError(
                    code="configure_result_contract_invalid",
                    message="Domain configure produced an invalid result",
                    exit_code=7,
                )
        if not isinstance(result.get("components"), dict) or not isinstance(
            result.get("verification"), dict
        ):
            raise ControlError(
                code="configure_result_contract_invalid",
                message="Domain configure produced an invalid result",
                exit_code=7,
            )

        error = result.get("error")
        if not isinstance(error, dict):
            raise ControlError(
                code="configure_result_contract_invalid",
                message="Domain configure produced an invalid result",
                exit_code=7,
            )
        if result["status"] == "failed":
            code = error.get("code")
            error_class = error.get("class")
            safe_message = error.get("safe_message")
            if not (
                isinstance(code, str)
                and SAFE_ERROR_CODE_RE.fullmatch(code)
                and isinstance(error_class, str)
                and error_class
                and isinstance(safe_message, str)
                and safe_message
                and len(safe_message) <= 240
            ):
                raise ControlError(
                    code="configure_result_contract_invalid",
                    message="Domain configure produced an invalid result",
                    exit_code=7,
                )
        elif error:
            raise ControlError(
                code="configure_result_contract_invalid",
                message="Domain configure produced an invalid result",
                exit_code=7,
            )

        return result

    @staticmethod
    def _legacy_result(result_path: Path) -> dict[str, object] | None:
        try:
            result = read_json(result_path)
        except (OSError, ValueError):
            return None

        if "schema_version" in result:
            return None

        return result

    @staticmethod
    def _error_from_result(
        result: dict[str, object],
        *,
        run_id: str,
    ) -> ControlError:
        error = result["error"]
        assert isinstance(error, dict)
        return ControlError(
            code=str(error["code"]),
            message="Ansible domain configure failed",
            exit_code=7,
            details={
                "run_id": run_id,
                "phase": result["phase"],
                "retryable": result["retryable"],
                "recovered": result["recovered"],
            },
        )

    def _persist_synthetic_failure(
        self,
        result_path: Path,
        request: ConfigureRequest,
        *,
        code: str,
        error_class: str,
        safe_message: str,
        retryable: bool,
    ) -> dict[str, object]:
        result = self._synthetic_failure(
            request,
            code=code,
            error_class=error_class,
            safe_message=safe_message,
            retryable=retryable,
        )
        atomic_write_json(result_path, result)
        return result

    @staticmethod
    def _preflight_failure_code(log_path: Path) -> str | None:
        try:
            text = log_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return None
        match = PREFLIGHT_FAILURE_RE.search(text)
        return match.group(1) if match else None

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
        if request.remote_access_profile == "krfb":
            vault_checker.check_krfb()

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
        try:
            with log_path.open("w", encoding="utf-8") as log_stream:
                os.chmod(log_path, 0o600)
                completed = subprocess.run(
                    command,
                    shell=False,
                    text=True,
                    stdout=log_stream,
                    stderr=subprocess.STDOUT,
                    timeout=1800,
                    check=False,
                    cwd=self.settings.ansible_project_dir,
                    env=environment,
                )
        except subprocess.TimeoutExpired:
            result = self._persist_synthetic_failure(
                result_path,
                request,
                code="configure_execution_timeout",
                error_class="retryable_transient",
                safe_message="Ansible domain configure timed out",
                retryable=True,
            )
            raise self._error_from_result(result, run_id=run_id)
        except OSError:
            result = self._persist_synthetic_failure(
                result_path,
                request,
                code="configure_execution_unavailable",
                error_class="retryable_transient",
                safe_message="Ansible domain configure could not start",
                retryable=True,
            )
            raise self._error_from_result(result, run_id=run_id)

        structured_result = self._read_structured_result(
            result_path,
            request=request,
        )
        if structured_result is not None:
            if completed.returncode == 0 and structured_result["status"] in {
                "successful",
                "degraded",
            }:
                structured_result["run_id"] = run_id
                return structured_result
            if (
                completed.returncode != 0
                and structured_result["status"] == "failed"
            ):
                raise self._error_from_result(
                    structured_result,
                    run_id=run_id,
                )

            result = self._persist_synthetic_failure(
                result_path,
                request,
                code="configure_result_contract_invalid",
                error_class="fatal_invariant",
                safe_message="Ansible result and exit status disagree",
                retryable=False,
            )
            raise self._error_from_result(result, run_id=run_id)

        if completed.returncode == 0:
            legacy_result = self._legacy_result(result_path)
            if legacy_result is not None:
                legacy_result["run_id"] = run_id
                return legacy_result

        preflight_failure_code = self._preflight_failure_code(log_path)
        result = self._persist_synthetic_failure(
            result_path,
            request,
            code=preflight_failure_code or "configure_result_missing",
            error_class=(
                "fatal_invariant"
                if preflight_failure_code
                else "retryable_transient"
            ),
            safe_message=(
                "Ansible preflight rejected the workstation"
                if preflight_failure_code
                else "Ansible domain configure produced no valid result"
            ),
            retryable=False if preflight_failure_code else completed.returncode != 0,
        )
        raise self._error_from_result(result, run_id=run_id)
