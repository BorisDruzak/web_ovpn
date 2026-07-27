from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
import re
from collections.abc import Mapping

from .install_inventory import DiskInventory, InstallInventoryV1, InterfaceInventory


_SHA256_RE = re.compile(r"[0-9a-f]{64}")


class PolicyError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        self.code = code
        super().__init__(f"{code}: {message}")


@dataclass(frozen=True)
class InstallProfile:
    profile_id: str
    profile_version: int
    target_release: str
    iso_id: str
    iso_sha256: str
    firmware: str
    architecture: str
    network: str
    minimum_disk_bytes: int
    wipe_mode: str
    filesystem: str
    swap_mib: int
    btrfs_minimum_mib: int
    grow: bool
    subvolumes: tuple[tuple[str, str], ...]
    package_set: str


@dataclass(frozen=True)
class PolicyEvaluation:
    profile: InstallProfile
    eligible_disk: DiskInventory
    route_interface: InterfaceInventory


def load_profile(profile_root: Path, profile_id: str, profile_version: int) -> InstallProfile:
    profiles = [_parse_profile(path) for path in sorted(profile_root.glob("*.json"))]
    matching_id = [profile for profile in profiles if profile.profile_id == profile_id]
    if not matching_id:
        raise PolicyError("unknown_profile", "profile identifier is not available")
    for profile in matching_id:
        if profile.profile_version == profile_version:
            return profile
    raise PolicyError("unsupported_profile_version", "profile version is not available")


def evaluate_policy(inventory: InstallInventoryV1, profile: InstallProfile) -> PolicyEvaluation:
    if not isinstance(inventory, InstallInventoryV1):
        raise PolicyError("inventory_type_invalid", "validated inventory is required")
    if not isinstance(profile, InstallProfile):
        raise PolicyError("profile_type_invalid", "validated profile is required")
    if inventory.agent.iso_id != profile.iso_id:
        raise PolicyError("iso_id_mismatch", "inventory ISO identifier differs from policy")
    if inventory.agent.iso_sha256 != profile.iso_sha256:
        raise PolicyError("iso_sha256_mismatch", "inventory ISO hash differs from policy")
    if inventory.machine.firmware != profile.firmware:
        raise PolicyError("unsupported_firmware", "policy requires UEFI firmware")
    if inventory.machine.cpu_arch != profile.architecture:
        raise PolicyError("unsupported_architecture", "policy requires x86_64")

    disk = _eligible_disk(inventory, profile)
    interface = _route_interface(inventory)
    return PolicyEvaluation(profile=profile, eligible_disk=disk, route_interface=interface)


def _eligible_disk(inventory: InstallInventoryV1, profile: InstallProfile) -> DiskInventory:
    physical_disks = [disk for disk in inventory.disks if disk.type == "disk"]
    if not physical_disks:
        raise PolicyError("disk_missing", "no internal disk was reported")
    for disk in physical_disks:
        if disk.path == inventory.boot_media.path:
            raise PolicyError("disk_is_boot_media", "installation medium cannot be selected")
        if disk.removable:
            raise PolicyError("disk_removable", "removable disk cannot be selected")
    sufficiently_large = [
        disk for disk in physical_disks if disk.size_bytes >= profile.minimum_disk_bytes
    ]
    if not sufficiently_large:
        raise PolicyError("disk_too_small", "disk is smaller than policy minimum")
    if len(sufficiently_large) != 1:
        raise PolicyError("disk_ambiguous", "exactly one eligible disk is required")
    return sufficiently_large[0]


def _route_interface(inventory: InstallInventoryV1) -> InterfaceInventory:
    routed = [interface for interface in inventory.interfaces if interface.route_to_controller]
    if not routed:
        raise PolicyError("network_missing", "no route-to-controller interface was reported")
    if len(routed) != 1:
        raise PolicyError("network_ambiguous", "exactly one route-to-controller interface is required")
    return routed[0]


def _parse_profile(path: Path) -> InstallProfile:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise PolicyError("profile_invalid", f"cannot read profile {path.name}") from error
    if not isinstance(raw, Mapping):
        raise PolicyError("profile_invalid", "profile must be an object")
    _require_fields(raw, {"profile_id", "profile_version", "target_release", "iso", "firmware", "architecture", "network", "disk", "layout", "package_set"})
    iso = _object(raw["iso"], "iso")
    disk = _object(raw["disk"], "disk")
    layout = _object(raw["layout"], "layout")
    _require_fields(iso, {"id", "sha256"})
    _require_fields(disk, {"mode", "minimum_bytes", "wipe_mode"})
    _require_fields(layout, {"filesystem", "swap_mib", "btrfs_minimum_mib", "grow", "subvolumes", "encryption", "raid", "lvm"})
    subvolumes = _object(layout["subvolumes"], "subvolumes")
    if dict(subvolumes) != {"@": "/", "@home": "/home"}:
        raise PolicyError("profile_invalid", "profile subvolumes are invalid")
    iso_sha256 = _string(iso["sha256"], "iso.sha256")
    if not _SHA256_RE.fullmatch(iso_sha256):
        raise PolicyError("profile_invalid", "profile ISO hash is invalid")
    profile = InstallProfile(
        profile_id=_string(raw["profile_id"], "profile_id"),
        profile_version=_positive_int(raw["profile_version"], "profile_version"),
        target_release=_string(raw["target_release"], "target_release"),
        iso_id=_string(iso["id"], "iso.id"),
        iso_sha256=iso_sha256,
        firmware=_string(raw["firmware"], "firmware"),
        architecture=_string(raw["architecture"], "architecture"),
        network=_string(raw["network"], "network"),
        minimum_disk_bytes=_positive_int(disk["minimum_bytes"], "disk.minimum_bytes"),
        wipe_mode=_string(disk["wipe_mode"], "disk.wipe_mode"),
        filesystem=_string(layout["filesystem"], "layout.filesystem"),
        swap_mib=_positive_int(layout["swap_mib"], "layout.swap_mib"),
        btrfs_minimum_mib=_positive_int(layout["btrfs_minimum_mib"], "layout.btrfs_minimum_mib"),
        grow=_bool(layout["grow"], "layout.grow"),
        subvolumes=(("@", "/"), ("@home", "/home")),
        package_set=_string(raw["package_set"], "package_set"),
    )
    _validate_standard_office(profile, disk, layout)
    return profile


def _validate_standard_office(profile: InstallProfile, disk: Mapping[str, object], layout: Mapping[str, object]) -> None:
    if (
        profile.profile_id != "standard-office"
        or profile.profile_version != 1
        or profile.target_release != "ALT KWorkstation 11.4"
        or profile.firmware != "uefi"
        or profile.architecture != "x86_64"
        or profile.network != "dhcp"
        or disk["mode"] != "exactly_one_eligible_internal"
        or profile.minimum_disk_bytes != 53_687_091_200
        or profile.wipe_mode != "whole_disk"
        or profile.filesystem != "btrfs"
        or profile.swap_mib != 4096
        or profile.btrfs_minimum_mib != 40960
        or profile.grow is not True
        or layout["encryption"] != "none"
        or layout["raid"] != "none"
        or layout["lvm"] != "none"
        or profile.package_set != "standard-office-v1"
    ):
        raise PolicyError("profile_invalid", "profile differs from standard-office-v1")


def _object(value: object, name: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or any(not isinstance(key, str) for key in value):
        raise PolicyError("profile_invalid", f"{name} must be an object")
    return value


def _require_fields(value: Mapping[str, object], expected: set[str]) -> None:
    if set(value) != expected:
        raise PolicyError("profile_invalid", "profile fields are invalid")


def _string(value: object, name: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 256:
        raise PolicyError("profile_invalid", f"{name} must be a bounded string")
    return value


def _positive_int(value: object, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise PolicyError("profile_invalid", f"{name} must be a positive integer")
    return value


def _bool(value: object, name: str) -> bool:
    if not isinstance(value, bool):
        raise PolicyError("profile_invalid", f"{name} must be boolean")
    return value
