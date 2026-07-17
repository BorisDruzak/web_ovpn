from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[2]

INSTALLER = (
    REPO_ROOT
    / "deploy"
    / "alt-linux"
    / "install-control-plane.sh"
)


REQUIRED_CONTROLLER_COMMANDS = (
    "python3",
    "ansible-playbook",
    "ansible-vault",
    "systemd-run",
    "install",
    "cp",
    "ssh",
    "ssh-keyscan",
    "mkpasswd",
)

MUTATING_INSTALLER_COMMANDS = (
    "install",
    "rm",
    "cp",
    "chown",
    "find",
    "chmod",
    "systemctl",
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


def test_missing_dependency_is_reported_before_runtime_mutation(
    tmp_path: Path,
) -> None:
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    mutation_marker = tmp_path / "mutation.log"
    missing_command = "ansible-vault"

    commands = set(REQUIRED_CONTROLLER_COMMANDS)
    commands.update(MUTATING_INSTALLER_COMMANDS)

    for command in sorted(commands - {missing_command}):
        command_path = fake_bin / command

        if command in MUTATING_INSTALLER_COMMANDS:
            command_path.write_text(
                "#!/bin/sh\n"
                'printf "%s\\n" "$0" >> "$INSTALL_MARKER"\n'
                "exit 99\n",
                encoding="utf-8",
            )
            command_path.chmod(0o755)
        else:
            command_path.symlink_to("/bin/true")

    completed = subprocess.run(
        ["/bin/bash", str(INSTALLER)],
        text=True,
        capture_output=True,
        check=False,
        env={
            **os.environ,
            "PATH": str(fake_bin),
            "INSTALL_MARKER": str(mutation_marker),
        },
    )

    assert completed.returncode != 0
    assert (
        f"Missing required command: {missing_command}"
        in completed.stderr
    )
    assert not mutation_marker.exists(), (
        "Installer invoked a mutating command before dependency "
        f"preflight completed:\n{mutation_marker.read_text(encoding='utf-8')}"
    )


def test_reinstall_does_not_mutate_runtime_vault_files(
    installer_text: str,
) -> None:
    runtime_secret_paths = (
        "/home/altserver/ansible/group_vars/vault.yml",
        "/home/altserver/.ansible-vault-pass",
    )

    for path in runtime_secret_paths:
        assert path not in installer_text, (
            "Installer must not read, copy, overwrite, chmod, or chown "
            f"the runtime secret directly: {path}"
        )

    forbidden_recursive_operations = (
        "rm -rf /home/altserver/ansible",
        'cp -a "${ALT_ROOT}/ansible/group_vars/."',
        "chown -R altserver:altserver /home/altserver/ansible\n",
        "find /home/altserver/ansible -type",
    )

    for operation in forbidden_recursive_operations:
        assert operation not in installer_text, (
            "Installer contains a broad operation that could change the "
            f"runtime Vault bytes, owner, or mode: {operation}"
        )
