from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import TYPE_CHECKING

from .config import Settings
from .errors import ControlError

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
