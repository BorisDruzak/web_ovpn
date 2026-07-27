from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import os
from pathlib import Path
import re
from string import Template
from tempfile import NamedTemporaryFile
from types import MappingProxyType
from collections.abc import Mapping

from .install_plan import InstallPlanV1


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
