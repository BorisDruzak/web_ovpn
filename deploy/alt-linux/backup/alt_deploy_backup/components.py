from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .settings import BackupSettings
from .systemd import MANAGED_UNITS


@dataclass(frozen=True)
class ComponentSpec:
    name: str
    filename: str
    namespace: str
    paths: tuple[Path, ...]
    excludes: tuple[Path, ...]


COMPONENT_NAMES = (
    "runtime",
    "systemd",
    "ansible",
    "controller_state",
    "registration_state",
    "deployment_assets",
)

COMPONENT_FILENAMES = (
    "runtime.tar.zst",
    "systemd.tar.zst",
    "ansible.tar.zst",
    "controller-state.tar.zst",
    "registration-state.tar.zst",
    "deployment-assets.tar.zst",
)

COMPONENT_NAMESPACES = (
    "runtime",
    "systemd",
    "ansible",
    "controller-state",
    "registration-state",
    "deployment-assets",
)


def component_specs(settings: BackupSettings) -> tuple[ComponentSpec, ...]:
    return (
        ComponentSpec(
            name="runtime",
            filename="runtime.tar.zst",
            namespace="runtime",
            paths=(
                settings.runtime_control_root,
                settings.runtime_api_root,
                settings.workstationctl_path,
                settings.worker_path,
                settings.stage_helper_path,
            ),
            excludes=(),
        ),
        ComponentSpec(
            name="systemd",
            filename="systemd.tar.zst",
            namespace="systemd",
            paths=tuple(
                settings.systemd_root / unit
                for unit in MANAGED_UNITS
            ),
            excludes=(),
        ),
        ComponentSpec(
            name="ansible",
            filename="ansible.tar.zst",
            namespace="ansible",
            paths=(settings.ansible_root,),
            excludes=(settings.vault_file,),
        ),
        ComponentSpec(
            name="controller_state",
            filename="controller-state.tar.zst",
            namespace="controller-state",
            paths=(settings.controller_state_root,),
            excludes=(),
        ),
        ComponentSpec(
            name="registration_state",
            filename="registration-state.tar.zst",
            namespace="registration-state",
            paths=(settings.registration_root,),
            excludes=(),
        ),
        ComponentSpec(
            name="deployment_assets",
            filename="deployment-assets.tar.zst",
            namespace="deployment-assets",
            paths=(
                settings.bootstrap_root,
                settings.metadata_root,
            ),
            excludes=(),
        ),
    )
