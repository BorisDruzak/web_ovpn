from __future__ import annotations

from pathlib import Path

import pytest

from support.installer_sandbox import InstallerSandbox


REPO_ROOT = Path(__file__).resolve().parents[2]
ALT_ROOT = REPO_ROOT / "deploy" / "alt-linux"
INSTALLER = ALT_ROOT / "install-control-plane.sh"
INSTALLER_LIBRARY = ALT_ROOT / "install-control-plane-lib.sh"
STAGE_HELPER = ALT_ROOT / "control" / "alt-job-stage"


@pytest.fixture
def installer_text() -> str:
    if not INSTALLER.is_file() or not INSTALLER_LIBRARY.is_file():
        pytest.skip("Installer has not been created yet")
    return (
        INSTALLER.read_text(encoding="utf-8")
        + "\n"
        + INSTALLER_LIBRARY.read_text(encoding="utf-8")
    )


def test_install_scripts_exist() -> None:
    assert INSTALLER.is_file()
    assert INSTALLER_LIBRARY.is_file()


def test_stage_helper_wrapper_exists_and_delegates() -> None:
    assert STAGE_HELPER.is_file()
    wrapper = STAGE_HELPER.read_text(encoding="utf-8")
    assert wrapper.startswith("#!/usr/bin/python3\n")
    assert 'Path("/opt/alt-deploy-control")' in wrapper
    assert "from alt_deploy.job_stage_helper import main" in wrapper
    assert "raise SystemExit(main())" in wrapper


def test_installer_uses_strict_bash(installer_text: str) -> None:
    wrapper = INSTALLER.read_text(encoding="utf-8")
    assert wrapper.startswith("#!/bin/bash\n")
    assert "set -Eeuo pipefail" in wrapper
    assert 'source "${ALT_ROOT}/install-control-plane-lib.sh"' in wrapper


def test_installer_requires_root_before_library_load() -> None:
    wrapper = INSTALLER.read_text(encoding="utf-8")
    root_position = wrapper.index("${EUID}")
    source_position = wrapper.index("source ")
    assert "Run as root" in wrapper
    assert "exit 1" in wrapper
    assert root_position < source_position


def test_installer_installs_root_owned_control_files(
    installer_text: str,
) -> None:
    for path in (
        "/opt/alt-deploy-control",
        "/usr/local/sbin/workstationctl",
        "/usr/local/libexec/alt-provision-worker",
    ):
        assert path in installer_text

    assert (
        'cp -a "${ALT_ROOT}/control/alt_deploy" '
        '"${control_root}/alt_deploy"'
        in installer_text
    )
    assert 'chown -R root:root "${control_root}"' in installer_text
    assert 'find "${control_root}" -type f -exec chmod 0644' in installer_text


def test_installer_installs_and_compiles_stage_helper(
    installer_text: str,
) -> None:
    assert '"${ALT_ROOT}/control/alt-job-stage"' in installer_text
    assert "/usr/local/libexec/alt-job-stage" in installer_text

    compile_start = installer_text.index("python3 -m py_compile")
    compile_end = installer_text.index("bash -n", compile_start)
    compile_block = installer_text[compile_start:compile_end]
    assert '"${ALT_ROOT}/control/alt-job-stage"' in compile_block


def test_installer_creates_private_state_directories(
    installer_text: str,
) -> None:
    assert "install -d -o altserver -g altserver -m 0700" in installer_text
    for path in (
        "/var/lib/alt-deploy",
        "/var/lib/alt-deploy/jobs",
        "/var/lib/alt-deploy/assignments",
        "/srv/alt-deploy/registration/pending",
        "/srv/alt-deploy/registration/ready",
        "/srv/alt-deploy/registration/failed",
    ):
        assert path in installer_text


def test_installer_preserves_existing_ansible_files(
    installer_text: str,
) -> None:
    assert (
        'cp -a "${ALT_ROOT}/ansible/playbooks/." '
        '"${ansible_root}/playbooks/"'
        in installer_text
    )
    assert (
        'cp -a "${ALT_ROOT}/ansible/roles/." '
        '"${ansible_root}/roles/"'
        in installer_text
    )
    assert 'rm -rf "${ansible_root}"' not in installer_text
    assert "rm -rf /var/lib/alt-deploy" not in installer_text


def test_installer_updates_complete_registration_runtime(
    installer_text: str,
) -> None:
    for source, destination in (
        ("register_api.py", "/opt/alt-deploy-api/register_api.py"),
        ("process_pending.py", "/opt/alt-deploy-api/process_pending.py"),
        ("bootstrap/bootstrap.sh", "/srv/alt-deploy/bootstrap"),
    ):
        assert source in installer_text
        assert destination in installer_text

    for unit in (
        "alt-deploy-http.service",
        "alt-deploy-register.service",
        "alt-deploy-process.path",
        "alt-deploy-process.service",
    ):
        assert unit in installer_text


def test_installer_verifies_before_maintenance_and_accepts_last(
    installer_text: str,
) -> None:
    for marker in (
        "python3 -m py_compile",
        "bash -n",
        "pytest -q tests/alt_linux",
    ):
        assert marker in installer_text

    main_start = installer_text.index("install_control_plane_main()")
    main_block = installer_text[main_start:]
    prechecks = main_block.index("install_control_plane_prechecks")
    maintenance = main_block.index("enter_control_plane_maintenance")
    activation = main_block.index("activate_control_plane")
    readiness = main_block.index("run_installed_readiness")
    success = main_block.index("installed successfully")
    assert prechecks < maintenance < activation < readiness < success


def test_installer_does_not_copy_active_vault_secret(
    installer_text: str,
) -> None:
    assert 'cp -a "${ALT_ROOT}/ansible/group_vars/."' not in installer_text
    assert '"${ALT_ROOT}/ansible/group_vars/vault.yml"' not in installer_text
    assert "vault.yml.example" not in installer_text


def test_missing_dependency_is_reported_before_runtime_mutation(
    tmp_path: Path,
) -> None:
    sandbox = InstallerSandbox.create(tmp_path)
    missing_command = sandbox.fake_bin / "ansible-vault"
    missing_command.unlink()
    before = sandbox.protected_snapshot()

    completed = sandbox.run_library(
        PATH=f"{sandbox.fake_bin}:/bin",
    )

    assert completed.returncode != 0
    assert "Missing required command: ansible-vault" in completed.stderr
    assert sandbox.protected_snapshot() == before
    assert InstallerSandbox.mutation_commands(sandbox.commands()) == []


def test_reinstall_does_not_mutate_runtime_vault_files(
    installer_text: str,
) -> None:
    forbidden_operations = (
        'cp -a "${ALT_ROOT}/ansible/group_vars/."',
        '"${ALT_ROOT}/ansible/group_vars/vault.yml"',
        'rm -rf "${ansible_root}"',
        'chown -R altserver:altserver "${ansible_root}"',
    )
    for operation in forbidden_operations:
        assert operation not in installer_text
