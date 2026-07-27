from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
import re
from collections.abc import Mapping, Sequence
from typing import Any


_MAX_COLLECTION_ITEMS = 16
_MAX_STRING_LENGTH = 256
_SHA256_RE = re.compile(r"[0-9a-f]{64}")
_MAC_RE = re.compile(r"[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}")
_DISK_PATH_RE = re.compile(r"/dev/(?:sd[a-z]+|vd[a-z]+|nvme[0-9]+n[0-9]+|xvd[a-z]+)")
_BOOT_MEDIA_PATH_RE = re.compile(r"/dev/[A-Za-z0-9._-]+")


class InventoryError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        self.code = code
        super().__init__(f"{code}: {message}")


@dataclass(frozen=True)
class AgentInventory:
    version: str
    boot_id: str
    build_id: str
    iso_id: str
    iso_sha256: str

    def to_dict(self) -> dict[str, object]:
        return {
            "version": self.version,
            "boot_id": self.boot_id,
            "build_id": self.build_id,
            "iso_id": self.iso_id,
            "iso_sha256": self.iso_sha256,
        }


@dataclass(frozen=True)
class MachineInventory:
    dmi_uuid: str
    manufacturer: str
    product_name: str
    serial_number: str
    firmware: str
    memory_bytes: int
    cpu_arch: str

    def to_dict(self) -> dict[str, object]:
        return {
            "dmi_uuid": self.dmi_uuid,
            "manufacturer": self.manufacturer,
            "product_name": self.product_name,
            "serial_number": self.serial_number,
            "firmware": self.firmware,
            "memory_bytes": self.memory_bytes,
            "cpu_arch": self.cpu_arch,
        }


@dataclass(frozen=True)
class InterfaceInventory:
    name: str
    mac: str
    addresses: tuple[str, ...]
    route_to_controller: bool

    def to_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "mac": self.mac,
            "addresses": list(self.addresses),
            "route_to_controller": self.route_to_controller,
        }


@dataclass(frozen=True)
class DiskInventory:
    type: str
    path: str
    removable: bool
    size_bytes: int
    model: str
    serial: str | None
    wwn: str | None
    filesystem_signatures: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "type": self.type,
            "path": self.path,
            "removable": self.removable,
            "size_bytes": self.size_bytes,
            "model": self.model,
            "serial": self.serial,
            "wwn": self.wwn,
            "filesystem_signatures": list(self.filesystem_signatures),
        }


@dataclass(frozen=True)
class BootMediaInventory:
    path: str
    model: str
    serial: str | None
    wwn: str | None

    def to_dict(self) -> dict[str, object]:
        return {
            "path": self.path,
            "model": self.model,
            "serial": self.serial,
            "wwn": self.wwn,
        }


@dataclass(frozen=True)
class InstallInventoryV1:
    schema_version: int
    agent: AgentInventory
    machine: MachineInventory
    interfaces: tuple[InterfaceInventory, ...]
    disks: tuple[DiskInventory, ...]
    boot_media: BootMediaInventory

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "agent": self.agent.to_dict(),
            "machine": self.machine.to_dict(),
            "interfaces": [interface.to_dict() for interface in self.interfaces],
            "disks": [disk.to_dict() for disk in self.disks],
            "boot_media": self.boot_media.to_dict(),
        }


def parse_inventory(payload: object) -> InstallInventoryV1:
    root = _mapping(payload, "inventory")
    if "schema_version" not in root:
        raise InventoryError("inventory_missing_field", "schema_version is required")
    version = _positive_int(root["schema_version"], "schema_version")
    if version != 1:
        raise InventoryError("inventory_schema_unsupported", "schema_version must be 1")
    _require_fields(
        root,
        {"schema_version", "agent", "machine", "interfaces", "disks", "boot_media"},
        "inventory",
    )
    return InstallInventoryV1(
        schema_version=version,
        agent=_parse_agent(root["agent"]),
        machine=_parse_machine(root["machine"]),
        interfaces=tuple(_parse_interface(value) for value in _bounded_list(root["interfaces"], "interfaces")),
        disks=tuple(_parse_disk(value) for value in _bounded_list(root["disks"], "disks")),
        boot_media=_parse_boot_media(root["boot_media"]),
    )


def canonical_inventory_bytes(inventory: InstallInventoryV1) -> bytes:
    if not isinstance(inventory, InstallInventoryV1):
        raise InventoryError("inventory_type_invalid", "validated inventory is required")
    return json.dumps(
        inventory.to_dict(), ensure_ascii=True, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def inventory_sha256(inventory: InstallInventoryV1) -> str:
    return sha256(canonical_inventory_bytes(inventory)).hexdigest()


def _parse_agent(value: object) -> AgentInventory:
    raw = _mapping(value, "agent")
    _require_fields(raw, {"version", "boot_id", "build_id", "iso_id", "iso_sha256"}, "agent")
    iso_sha256 = _string(raw["iso_sha256"], "agent.iso_sha256")
    if not _SHA256_RE.fullmatch(iso_sha256):
        raise InventoryError("inventory_value_invalid", "agent.iso_sha256 must be SHA-256")
    return AgentInventory(
        version=_string(raw["version"], "agent.version"),
        boot_id=_string(raw["boot_id"], "agent.boot_id"),
        build_id=_string(raw["build_id"], "agent.build_id"),
        iso_id=_string(raw["iso_id"], "agent.iso_id"),
        iso_sha256=iso_sha256,
    )


def _parse_machine(value: object) -> MachineInventory:
    raw = _mapping(value, "machine")
    _require_fields(
        raw,
        {"dmi_uuid", "manufacturer", "product_name", "serial_number", "firmware", "memory_bytes", "cpu_arch"},
        "machine",
    )
    firmware = _string(raw["firmware"], "machine.firmware")
    if firmware not in {"uefi", "bios"}:
        raise InventoryError("inventory_value_invalid", "machine.firmware is invalid")
    return MachineInventory(
        dmi_uuid=_string(raw["dmi_uuid"], "machine.dmi_uuid"),
        manufacturer=_string(raw["manufacturer"], "machine.manufacturer"),
        product_name=_string(raw["product_name"], "machine.product_name"),
        serial_number=_string(raw["serial_number"], "machine.serial_number"),
        firmware=firmware,
        memory_bytes=_positive_int(raw["memory_bytes"], "machine.memory_bytes"),
        cpu_arch=_string(raw["cpu_arch"], "machine.cpu_arch"),
    )


def _parse_interface(value: object) -> InterfaceInventory:
    raw = _mapping(value, "interface")
    _require_fields(raw, {"name", "mac", "addresses", "route_to_controller"}, "interface")
    mac = _string(raw["mac"], "interface.mac")
    if not _MAC_RE.fullmatch(mac):
        raise InventoryError("inventory_value_invalid", "interface.mac is invalid")
    route_to_controller = raw["route_to_controller"]
    if not isinstance(route_to_controller, bool):
        raise InventoryError("inventory_type_invalid", "interface.route_to_controller must be boolean")
    return InterfaceInventory(
        name=_string(raw["name"], "interface.name"),
        mac=mac.lower(),
        addresses=tuple(
            _string(address, "interface.addresses[]")
            for address in _bounded_list(raw["addresses"], "interface.addresses")
        ),
        route_to_controller=route_to_controller,
    )


def _parse_disk(value: object) -> DiskInventory:
    raw = _mapping(value, "disk")
    _require_fields(
        raw,
        {"type", "path", "removable", "size_bytes", "model", "serial", "wwn", "filesystem_signatures"},
        "disk",
    )
    path = _string(raw["path"], "disk.path")
    if not _DISK_PATH_RE.fullmatch(path):
        raise InventoryError("inventory_value_invalid", "disk.path is unsafe")
    removable = raw["removable"]
    if not isinstance(removable, bool):
        raise InventoryError("inventory_type_invalid", "disk.removable must be boolean")
    return DiskInventory(
        type=_string(raw["type"], "disk.type"),
        path=path,
        removable=removable,
        size_bytes=_positive_int(raw["size_bytes"], "disk.size_bytes"),
        model=_string(raw["model"], "disk.model"),
        serial=_optional_string(raw["serial"], "disk.serial"),
        wwn=_optional_string(raw["wwn"], "disk.wwn"),
        filesystem_signatures=tuple(
            _string(signature, "disk.filesystem_signatures[]")
            for signature in _bounded_list(raw["filesystem_signatures"], "disk.filesystem_signatures")
        ),
    )


def _parse_boot_media(value: object) -> BootMediaInventory:
    raw = _mapping(value, "boot_media")
    _require_fields(raw, {"path", "model", "serial", "wwn"}, "boot_media")
    path = _string(raw["path"], "boot_media.path")
    if not _BOOT_MEDIA_PATH_RE.fullmatch(path):
        raise InventoryError("inventory_value_invalid", "boot_media.path is invalid")
    return BootMediaInventory(
        path=path,
        model=_string(raw["model"], "boot_media.model"),
        serial=_optional_string(raw["serial"], "boot_media.serial"),
        wwn=_optional_string(raw["wwn"], "boot_media.wwn"),
    )


def _mapping(value: object, name: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or any(not isinstance(key, str) for key in value):
        raise InventoryError("inventory_type_invalid", f"{name} must be an object")
    return value


def _require_fields(value: Mapping[str, object], expected: set[str], name: str) -> None:
    unknown = set(value) - expected
    if unknown:
        raise InventoryError("inventory_unknown_field", f"{name} has unknown fields")
    missing = expected - set(value)
    if missing:
        raise InventoryError("inventory_missing_field", f"{name} has missing fields")


def _bounded_list(value: object, name: str) -> Sequence[object]:
    if not isinstance(value, list):
        raise InventoryError("inventory_type_invalid", f"{name} must be an array")
    if len(value) > _MAX_COLLECTION_ITEMS:
        raise InventoryError("inventory_limit_exceeded", f"{name} has too many values")
    return value


def _string(value: object, name: str) -> str:
    if not isinstance(value, str):
        raise InventoryError("inventory_type_invalid", f"{name} must be a string")
    if not value or len(value) > _MAX_STRING_LENGTH:
        raise InventoryError("inventory_value_invalid", f"{name} has invalid length")
    return value


def _optional_string(value: object, name: str) -> str | None:
    if value is None:
        return None
    return _string(value, name)


def _positive_int(value: object, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise InventoryError("inventory_type_invalid", f"{name} must be an integer")
    if value <= 0 or value > (2**63 - 1):
        raise InventoryError("inventory_value_invalid", f"{name} is out of range")
    return value
