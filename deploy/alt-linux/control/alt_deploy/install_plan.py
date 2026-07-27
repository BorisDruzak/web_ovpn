from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from hashlib import sha256
import json
import re
from types import MappingProxyType
from collections.abc import Mapping

from .install_fingerprint import disk_fingerprint
from .install_inventory import InstallInventoryV1, inventory_sha256
from .install_policy import InstallProfile, PolicyEvaluation


_SESSION_RE = re.compile(r"install-[a-z0-9-]{4,64}")
_HOSTNAME_RE = re.compile(r"alt-install-[a-z0-9-]{1,63}")


class PlanError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        self.code = code
        super().__init__(f"{code}: {message}")


@dataclass(frozen=True)
class OperatorSelection:
    disk_path: str
    disk_fingerprint: str
    interface_name: str
    interface_mac: str


@dataclass(frozen=True)
class PlanRequest:
    session_id: str
    revision: int
    temporary_hostname: str
    approved_at: str
    expires_at: str


@dataclass(frozen=True)
class InstallPlanV1:
    schema_version: int
    session_id: str
    revision: int
    inventory_sha256: str
    profile_id: str
    profile_version: int
    iso_id: str
    iso_sha256: str
    firmware: str
    target_disk: Mapping[str, object]
    network_interface: Mapping[str, str]
    disk_layout: Mapping[str, object]
    package_set: str
    temporary_hostname: str
    approved_at: str
    expires_at: str

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "session_id": self.session_id,
            "revision": self.revision,
            "inventory_sha256": self.inventory_sha256,
            "profile_id": self.profile_id,
            "profile_version": self.profile_version,
            "iso_id": self.iso_id,
            "iso_sha256": self.iso_sha256,
            "firmware": self.firmware,
            "target_disk": dict(self.target_disk),
            "network_interface": dict(self.network_interface),
            "disk_layout": {
                **dict(self.disk_layout),
                "subvolumes": dict(self.disk_layout["subvolumes"]),
            },
            "package_set": self.package_set,
            "temporary_hostname": self.temporary_hostname,
            "approved_at": self.approved_at,
            "expires_at": self.expires_at,
        }


def build_install_plan(
    inventory: InstallInventoryV1,
    profile: InstallProfile,
    evaluation: PolicyEvaluation,
    selection: OperatorSelection,
    request: PlanRequest,
) -> InstallPlanV1:
    if not isinstance(inventory, InstallInventoryV1):
        raise PlanError("inventory_type_invalid", "validated inventory is required")
    if not isinstance(profile, InstallProfile) or not isinstance(evaluation, PolicyEvaluation):
        raise PlanError("policy_type_invalid", "validated policy evaluation is required")
    if not isinstance(selection, OperatorSelection):
        raise PlanError("selection_type_invalid", "operator selection is required")
    if not isinstance(request, PlanRequest):
        raise PlanError("request_type_invalid", "plan request is required")
    _validate_request(request)
    _validate_selection(evaluation, selection)

    disk = evaluation.eligible_disk
    target_disk = MappingProxyType(
        {
            "path": disk.path,
            "size_bytes": disk.size_bytes,
            "model": disk.model,
            "serial": disk.serial,
            "wwn": disk.wwn,
            "fingerprint": disk_fingerprint(disk),
        }
    )
    network_interface = MappingProxyType(
        {"name": evaluation.route_interface.name, "mac": evaluation.route_interface.mac}
    )
    disk_layout = MappingProxyType(
        {
            "wipe_mode": profile.wipe_mode,
            "swap_mib": profile.swap_mib,
            "filesystem": profile.filesystem,
            "btrfs_minimum_mib": profile.btrfs_minimum_mib,
            "grow": profile.grow,
            "subvolumes": MappingProxyType(dict(profile.subvolumes)),
        }
    )
    return InstallPlanV1(
        schema_version=1,
        session_id=request.session_id,
        revision=request.revision,
        inventory_sha256=inventory_sha256(inventory),
        profile_id=profile.profile_id,
        profile_version=profile.profile_version,
        iso_id=profile.iso_id,
        iso_sha256=profile.iso_sha256,
        firmware=profile.firmware,
        target_disk=target_disk,
        network_interface=network_interface,
        disk_layout=disk_layout,
        package_set=profile.package_set,
        temporary_hostname=request.temporary_hostname,
        approved_at=request.approved_at,
        expires_at=request.expires_at,
    )


def canonical_plan_bytes(plan: InstallPlanV1) -> bytes:
    if not isinstance(plan, InstallPlanV1):
        raise PlanError("plan_type_invalid", "validated plan is required")
    return json.dumps(plan.to_dict(), ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("utf-8")


def plan_sha256(plan: InstallPlanV1) -> str:
    return sha256(canonical_plan_bytes(plan)).hexdigest()


def _validate_selection(evaluation: PolicyEvaluation, selection: OperatorSelection) -> None:
    disk = evaluation.eligible_disk
    if selection.disk_path != disk.path or selection.disk_fingerprint != disk_fingerprint(disk):
        raise PlanError("selection_disk_mismatch", "selected disk differs from policy candidate")
    interface = evaluation.route_interface
    if selection.interface_name != interface.name or selection.interface_mac != interface.mac:
        raise PlanError("selection_interface_mismatch", "selected interface differs from policy candidate")


def _validate_request(request: PlanRequest) -> None:
    if not _SESSION_RE.fullmatch(request.session_id):
        raise PlanError("plan_value_invalid", "session identifier is invalid")
    if isinstance(request.revision, bool) or not isinstance(request.revision, int) or request.revision <= 0:
        raise PlanError("plan_value_invalid", "revision must be positive")
    if not _HOSTNAME_RE.fullmatch(request.temporary_hostname):
        raise PlanError("plan_value_invalid", "temporary hostname is invalid")
    approved_at = _timestamp(request.approved_at)
    expires_at = _timestamp(request.expires_at)
    if expires_at <= approved_at:
        raise PlanError("plan_expiry_invalid", "expiry must be later than approval")


def _timestamp(value: str) -> datetime:
    try:
        timestamp = datetime.fromisoformat(value)
    except (TypeError, ValueError) as error:
        raise PlanError("plan_timestamp_invalid", "timestamp must be ISO-8601") from error
    if timestamp.tzinfo is None or timestamp.utcoffset() is None:
        raise PlanError("plan_timestamp_invalid", "timestamp must include timezone")
    return timestamp
