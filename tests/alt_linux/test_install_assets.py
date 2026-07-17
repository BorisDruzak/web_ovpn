from __future__ import annotations

from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[2]

INSTALLER = (
    REPO_ROOT
    / "deploy"
    / "alt-linux"
    / "install-control-plane.sh"
)


def test_install_script_exists() -> None:
    assert INSTALLER.is_file(), (
        "Missing deploy/alt-linux/install-control-plane.sh"
    )


@pytest.fixture
def installer_text() -> str:
    if not INSTALLER.is_file():
        pytest.skip("Installer has not been created yet")

    return INSTALLER.read_text(encoding="utf-8")


def test_installer_uses_strict_bash(
    installer_text: str,
) -> None:
    assert installer_text.startswith("#!/bin/bash\n")
    assert "set -Eeuo pipefail" in installer_text


def test_installer_requires_root(
    installer_text: str,
) -> None:
    assert "${EUID}" in installer_text
    assert "Run as root" in installer_text
    assert "exit 1" in installer_text


def test_installer_installs_root_owned_control_files(
    installer_text: str,
) -> None:
    assert (
        "/opt/alt-deploy-control/alt_deploy"
        in installer_text
    )
    assert (
        "/usr/local/sbin/workstationctl"
        in installer_text
    )
    assert (
        "/usr/local/libexec/alt-provision-worker"
        in installer_text
    )

    assert (
        "chown -R root:root /opt/alt-deploy-control"
        in installer_text
    )
    assert (
        "find /opt/alt-deploy-control "
        "-type f -exec chmod 0644"
        in installer_text
    )


def test_installer_creates_private_state_directories(
    installer_text: str,
) -> None:
    assert "install -d -o altserver -g altserver -m 0700" in (
        installer_text
    )

    for path in (
        "/var/lib/alt-deploy",
        "/var/lib/alt-deploy/jobs",
        "/var/lib/alt-deploy/assignments",
    ):
        assert path in installer_text


def test_installer_preserves_existing_ansible_files(
    installer_text: str,
) -> None:
    assert (
        'cp -a "${ALT_ROOT}/ansible/playbooks/." '
        "/home/altserver/ansible/playbooks/"
        in installer_text
    )
    assert (
        'cp -a "${ALT_ROOT}/ansible/roles/." '
        "/home/altserver/ansible/roles/"
        in installer_text
    )

    assert (
        "rm -rf /home/altserver/ansible"
        not in installer_text
    )
    assert (
        "rm -rf /var/lib/alt-deploy"
        not in installer_text
    )


def test_installer_updates_pending_processor(
    installer_text: str,
) -> None:
    assert (
        '"${ALT_ROOT}/api/process_pending.py"'
        in installer_text
    )
    assert (
        "/opt/alt-deploy-api/process_pending.py"
        in installer_text
    )


def test_installer_verifies_before_service_restart(
    installer_text: str,
) -> None:
    verification_markers = (
        "python3 -m py_compile",
        "bash -n",
        "pytest -q tests/alt_linux",
        "ansible-playbook --syntax-check",
    )

    restart_position = installer_text.index(
        "systemctl restart alt-deploy-process.path"
    )

    for marker in verification_markers:
        assert marker in installer_text
        assert installer_text.index(marker) < restart_position


def test_installer_does_not_copy_active_vault_secret(
    installer_text: str,
) -> None:
    assert (
        'cp -a "${ALT_ROOT}/ansible/group_vars/."'
        not in installer_text
    )
    assert (
        '"${ALT_ROOT}/ansible/group_vars/vault.yml"'
        not in installer_text
    )
    assert (
        "vault.yml.example"
        not in installer_text
    )
