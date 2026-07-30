from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from hashlib import sha256
import json
import os
from pathlib import Path
import re
from string import Template
from tempfile import NamedTemporaryFile
from types import MappingProxyType
from collections.abc import Mapping

from .install_plan import InstallPlanV1, canonical_plan_bytes


_ARTIFACT_NAMES = ("autoinstall.scm", "vm-profile.scm", "sha256sums")
_TEMPLATE_NAMES = {
    "autoinstall.scm": "autoinstall.scm.template",
    "vm-profile.scm": "vm-profile.scm.template",
}
_TEMPLATE_FIELDS = {
    "autoinstall.scm": {
        "admin_yescrypt_hash",
        "iso_id",
        "network_name",
        "package_set",
        "root_yescrypt_hash",
        "target_disk_path",
        "temporary_hostname",
    },
    "vm-profile.scm": {
        "btrfs_minimum_mib",
        "filesystem",
        "swap_mib",
        "target_disk_path",
    },
}
_SECRET_RE = re.compile(r"\$y\$[A-Za-z0-9./$=+-]{12,256}")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_FINGERPRINT_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_SESSION_RE = re.compile(r"^install-\d{8}T\d{6}Z-[0-9a-f]{8}$")
_DEVICE_RE = re.compile(r"^/dev/[A-Za-z0-9._+-]{1,63}$")
_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$")
_HOSTNAME_RE = re.compile(r"^alt-install-[a-z0-9-]{1,63}$")
_INTERFACE_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,64}$")
_MAC_RE = re.compile(r"^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$")


class RenderError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        self.code = code
        super().__init__(f"{code}: {message}")


@dataclass(frozen=True)
class RendererSecrets:
    root_yescrypt_hash: str
    admin_yescrypt_hash: str


@dataclass(frozen=True)
class RenderedInstallBundle:
    files: Mapping[str, bytes]


def _strict_object(
    pairs: list[tuple[str, object]],
) -> dict[str, object]:
    result: dict[str, object] = {}
    for name, value in pairs:
        if name in result:
            raise RenderError("plan_invalid", "execution plan is invalid")
        result[name] = value
    return result


def _plan_string(
    value: object,
    *,
    pattern: re.Pattern[str] | None = None,
    maximum: int = 256,
) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= maximum:
        raise RenderError("plan_invalid", "execution plan is invalid")
    if pattern is not None and not pattern.fullmatch(value):
        raise RenderError("plan_invalid", "execution plan is invalid")
    return value


def _plan_timestamp(value: object) -> str:
    text = _plan_string(value, maximum=64)
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise RenderError("plan_invalid", "execution plan is invalid") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise RenderError("plan_invalid", "execution plan is invalid")
    return text


def parse_execution_plan_bytes(raw: bytes) -> InstallPlanV1:
    if not isinstance(raw, bytes) or not 1 <= len(raw) <= 1024 * 1024:
        raise RenderError("plan_invalid", "execution plan is invalid")
    try:
        payload = json.loads(
            raw.decode("utf-8"), object_pairs_hook=_strict_object
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise RenderError("plan_invalid", "execution plan is invalid") from exc
    if not isinstance(payload, Mapping) or set(payload) != {
        "schema_version",
        "session_id",
        "revision",
        "inventory_sha256",
        "profile_id",
        "profile_version",
        "iso_id",
        "iso_sha256",
        "firmware",
        "target_disk",
        "network_interface",
        "disk_layout",
        "package_set",
        "temporary_hostname",
        "approved_at",
        "expires_at",
    }:
        raise RenderError("plan_invalid", "execution plan is invalid")
    target = payload["target_disk"]
    network = payload["network_interface"]
    layout = payload["disk_layout"]
    if (
        not isinstance(target, Mapping)
        or set(target)
        != {"path", "size_bytes", "model", "serial", "wwn", "fingerprint"}
        or not isinstance(network, Mapping)
        or set(network) != {"name", "mac"}
        or not isinstance(layout, Mapping)
        or set(layout)
        != {
            "wipe_mode",
            "swap_mib",
            "filesystem",
            "btrfs_minimum_mib",
            "grow",
            "subvolumes",
        }
    ):
        raise RenderError("plan_invalid", "execution plan is invalid")
    subvolumes = layout["subvolumes"]
    if (
        not isinstance(subvolumes, Mapping)
        or set(subvolumes) != {"@", "@home"}
        or subvolumes.get("@") != "/"
        or subvolumes.get("@home") != "/home"
    ):
        raise RenderError("plan_invalid", "execution plan is invalid")
    revision = payload["revision"]
    profile_version = payload["profile_version"]
    target_size = target["size_bytes"]
    swap_mib = layout["swap_mib"]
    btrfs_minimum_mib = layout["btrfs_minimum_mib"]
    if (
        type(payload["schema_version"]) is not int
        or payload["schema_version"] != 1
        or type(revision) is not int
        or revision != 1
        or type(profile_version) is not int
        or profile_version < 1
        or type(target_size) is not int
        or target_size < 1
        or type(swap_mib) is not int
        or swap_mib < 0
        or type(btrfs_minimum_mib) is not int
        or btrfs_minimum_mib < 1
        or type(layout["grow"]) is not bool
        or layout["wipe_mode"] != "whole_disk"
        or layout["filesystem"] != "btrfs"
        or payload["firmware"] != "uefi"
        or any(
            item is not None
            and (not isinstance(item, str) or len(item) > 128)
            for item in (target["serial"], target["wwn"])
        )
    ):
        raise RenderError("plan_invalid", "execution plan is invalid")
    approved_at = _plan_timestamp(payload["approved_at"])
    expires_at = _plan_timestamp(payload["expires_at"])
    if datetime.fromisoformat(expires_at) <= datetime.fromisoformat(
        approved_at
    ):
        raise RenderError("plan_invalid", "execution plan is invalid")
    plan = InstallPlanV1(
        schema_version=1,
        session_id=_plan_string(payload["session_id"], pattern=_SESSION_RE),
        revision=revision,
        inventory_sha256=_plan_string(
            payload["inventory_sha256"], pattern=_SHA256_RE
        ),
        profile_id=_plan_string(payload["profile_id"], pattern=_IDENTIFIER_RE),
        profile_version=profile_version,
        iso_id=_plan_string(payload["iso_id"], pattern=_IDENTIFIER_RE),
        iso_sha256=_plan_string(payload["iso_sha256"], pattern=_SHA256_RE),
        firmware="uefi",
        target_disk=MappingProxyType(
            {
                "path": _plan_string(target["path"], pattern=_DEVICE_RE),
                "size_bytes": target_size,
                "model": _plan_string(target["model"], maximum=128),
                "serial": target["serial"],
                "wwn": target["wwn"],
                "fingerprint": _plan_string(
                    target["fingerprint"], pattern=_FINGERPRINT_RE
                ),
            }
        ),
        network_interface=MappingProxyType(
            {
                "name": _plan_string(
                    network["name"], pattern=_INTERFACE_RE
                ),
                "mac": _plan_string(network["mac"], pattern=_MAC_RE),
            }
        ),
        disk_layout=MappingProxyType(
            {
                "wipe_mode": "whole_disk",
                "swap_mib": swap_mib,
                "filesystem": "btrfs",
                "btrfs_minimum_mib": btrfs_minimum_mib,
                "grow": layout["grow"],
                "subvolumes": MappingProxyType(dict(subvolumes)),
            }
        ),
        package_set=_plan_string(
            payload["package_set"], pattern=_IDENTIFIER_RE
        ),
        temporary_hostname=_plan_string(
            payload["temporary_hostname"], pattern=_HOSTNAME_RE
        ),
        approved_at=approved_at,
        expires_at=expires_at,
    )
    if canonical_plan_bytes(plan) != raw:
        raise RenderError("plan_invalid", "execution plan is not canonical")
    return plan


def render_install_bundle(
    plan: InstallPlanV1,
    secrets: RendererSecrets,
    template_root: Path,
) -> RenderedInstallBundle:
    if not isinstance(plan, InstallPlanV1):
        raise RenderError("plan_type_invalid", "validated InstallPlanV1 is required")
    if not isinstance(secrets, RendererSecrets):
        raise RenderError("secret_type_invalid", "typed renderer secrets are required")
    _validate_secret(secrets.root_yescrypt_hash)
    _validate_secret(secrets.admin_yescrypt_hash)
    substitutions = _substitutions(plan, secrets)
    rendered = {
        artifact: _render_template(
            template_root / template_name,
            substitutions,
            _TEMPLATE_FIELDS[artifact],
        ).encode("utf-8")
        for artifact, template_name in _TEMPLATE_NAMES.items()
    }
    checksums = b"".join(
        f"{sha256(rendered[name]).hexdigest()}  {name}\n".encode("ascii")
        for name in ("autoinstall.scm", "vm-profile.scm")
    )
    rendered["sha256sums"] = checksums
    return RenderedInstallBundle(files=MappingProxyType(rendered))


def write_install_bundle(bundle: RenderedInstallBundle, destination: Path) -> None:
    if not isinstance(bundle, RenderedInstallBundle):
        raise RenderError("bundle_type_invalid", "rendered bundle is required")
    if not destination.is_dir():
        raise RenderError("destination_invalid", "destination must be an existing directory")
    if tuple(bundle.files) != _ARTIFACT_NAMES:
        raise RenderError("bundle_invalid", "bundle has unexpected artifact names")
    for name in _ARTIFACT_NAMES:
        _atomic_write(destination / name, bundle.files[name])


def _substitutions(plan: InstallPlanV1, secrets: RendererSecrets) -> dict[str, str]:
    return {
        "iso_id": _scheme_string(plan.iso_id),
        "target_disk_path": _scheme_string(str(plan.target_disk["path"])),
        "network_name": _scheme_string(plan.network_interface["name"]),
        "temporary_hostname": _scheme_string(plan.temporary_hostname),
        "package_set": _scheme_string(plan.package_set),
        "root_yescrypt_hash": _scheme_string(secrets.root_yescrypt_hash),
        "admin_yescrypt_hash": _scheme_string(secrets.admin_yescrypt_hash),
        "swap_mib": str(plan.disk_layout["swap_mib"]),
        "filesystem": _scheme_string(str(plan.disk_layout["filesystem"])),
        "btrfs_minimum_mib": str(plan.disk_layout["btrfs_minimum_mib"]),
    }


def _render_template(
    path: Path,
    substitutions: Mapping[str, str],
    expected_identifiers: set[str],
) -> str:
    try:
        source = path.read_text(encoding="utf-8")
    except OSError as error:
        raise RenderError("template_missing", f"template {path.name} is unavailable") from error
    template = Template(source)
    identifiers = set(template.get_identifiers())
    if identifiers != expected_identifiers:
        raise RenderError("template_invalid", f"template {path.name} has unexpected placeholders")
    try:
        rendered = template.substitute(substitutions)
    except ValueError as error:
        raise RenderError("template_invalid", f"template {path.name} is invalid") from error
    return rendered if rendered.endswith("\n") else rendered + "\n"


def _scheme_string(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def _validate_secret(value: str) -> None:
    if not isinstance(value, str) or not _SECRET_RE.fullmatch(value):
        raise RenderError("secret_invalid", "yescrypt secret has invalid format")


def _atomic_write(path: Path, content: bytes) -> None:
    if path.name not in _ARTIFACT_NAMES or path.parent != path.parent.resolve():
        raise RenderError("destination_invalid", "artifact path is unsafe")
    temporary_name: str | None = None
    try:
        with NamedTemporaryFile(dir=path.parent, prefix=f".{path.name}.", delete=False) as temporary:
            temporary.write(content)
            temporary_name = temporary.name
        os.replace(temporary_name, path)
    finally:
        if temporary_name is not None:
            Path(temporary_name).unlink(missing_ok=True)
