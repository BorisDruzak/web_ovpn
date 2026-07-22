from __future__ import annotations

import stat
from pathlib import Path

import pytest

from support.backup_installer_sandbox import BackupInstallerSandbox


def test_public_backup_installer_rejects_arguments_before_mutation(
    tmp_path: Path,
) -> None:
    sandbox = BackupInstallerSandbox.create(tmp_path)

    result = sandbox.run_public("unexpected")

    assert result.returncode != 0
    assert sandbox.mutation_commands() == []


def test_backup_installer_requires_altserver_before_mutation(
    tmp_path: Path,
) -> None:
    sandbox = BackupInstallerSandbox.create(tmp_path)

    result = sandbox.run_library(BACKUP_INSTALLER_ID_RC="1")

    assert result.returncode != 0
    assert "altserver" in result.stderr
    assert sandbox.mutation_commands() == []


def test_backup_installer_library_supports_synthetic_root(
    tmp_path: Path,
) -> None:
    sandbox = BackupInstallerSandbox.create(tmp_path)

    result = sandbox.run_library()

    assert result.returncode == 0, result.stderr
    assert sandbox.destination(
        "/usr/local/sbin/alt-deploy-backup"
    ).is_file()


def test_backup_installer_publishes_only_backup_assets(
    tmp_path: Path,
) -> None:
    sandbox = BackupInstallerSandbox.create(tmp_path)
    before = sandbox.control_plane_snapshot()

    result = sandbox.run_library()

    assert result.returncode == 0, result.stderr
    wrapper = sandbox.destination("/usr/local/sbin/alt-deploy-backup")
    package = sandbox.destination(
        "/opt/alt-deploy-backup/alt_deploy_backup"
    )
    guard = sandbox.destination(
        "/etc/systemd/system/alt-deploy-guard.service"
    )
    assert stat.S_IMODE(wrapper.stat().st_mode) == 0o750
    assert package.is_dir()
    assert stat.S_IMODE(package.stat().st_mode) == 0o750
    assert all(
        stat.S_IMODE(path.stat().st_mode) == 0o640
        for path in package.glob("*.py")
    )
    assert not list(package.rglob("__pycache__"))
    assert stat.S_IMODE(guard.stat().st_mode) == 0o644
    sandbox.assert_private_mode("/var/lib/alt-deploy-backup", 0o700)
    sandbox.assert_private_mode("/var/backups/alt-deploy", 0o700)
    sandbox.assert_private_mode("/var/log/alt-deploy-backup.log", 0o600)
    fingerprint = sandbox.destination(
        "/var/lib/alt-deploy-backup/fingerprint.key"
    )
    assert fingerprint.stat().st_size == 32
    assert stat.S_IMODE(fingerprint.stat().st_mode) == 0o600
    assert sandbox.control_plane_snapshot() == before
    assert any(
        command[:4] == [
            "python3",
            "-m",
            "alt_deploy_backup.cli",
            "install-check",
        ]
        for command in sandbox.commands()
    )
    assert not any(
        command[:2] == ["systemctl", "stop"]
        for command in sandbox.commands()
    )


def test_backup_installer_preserves_bundles_log_and_fingerprint_key(
    tmp_path: Path,
) -> None:
    sandbox = BackupInstallerSandbox.create(tmp_path)
    sentinels = sandbox.seed_existing_backup_state()

    result = sandbox.run_library()

    assert result.returncode == 0, result.stderr
    assert sandbox.read_sentinels(sentinels) == sentinels


def test_backup_installer_preserves_existing_log_parent_mode(
    tmp_path: Path,
) -> None:
    sandbox = BackupInstallerSandbox.create(tmp_path)
    log_parent = sandbox.destination("/var/log")
    before = stat.S_IMODE(log_parent.stat().st_mode)

    result = sandbox.run_library()

    assert result.returncode == 0, result.stderr
    assert stat.S_IMODE(log_parent.stat().st_mode) == before == 0o755


def test_backup_installer_preserves_existing_public_parent_modes(
    tmp_path: Path,
) -> None:
    sandbox = BackupInstallerSandbox.create(tmp_path)
    expected = {
        "/usr/local/sbin": 0o755,
        "/etc/systemd/system": 0o750,
    }
    for absolute_path, mode in expected.items():
        parent = sandbox.destination(absolute_path)
        parent.mkdir(parents=True, exist_ok=True)
        parent.chmod(mode)

    result = sandbox.run_library()

    assert result.returncode == 0, result.stderr
    assert {
        absolute_path: stat.S_IMODE(
            sandbox.destination(absolute_path).stat().st_mode
        )
        for absolute_path in expected
    } == expected


@pytest.mark.parametrize(
    "absolute_path,target_is_directory",
    [
        ("/var/lib/alt-deploy-backup", True),
        ("/var/backups/alt-deploy", True),
        ("/opt/alt-deploy-backup", True),
        ("/usr/local/sbin", True),
        ("/etc/systemd/system", True),
        ("/var/log/alt-deploy-backup.log", False),
    ],
)
def test_backup_installer_rejects_symlink_destinations_before_mutation(
    tmp_path: Path,
    absolute_path: str,
    target_is_directory: bool,
) -> None:
    sandbox = BackupInstallerSandbox.create(tmp_path)
    destination = sandbox.destination(absolute_path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    outside = tmp_path / "outside-target"
    if target_is_directory:
        outside.mkdir()
        sentinel = outside / "sentinel"
        sentinel.write_bytes(b"outside-directory-sentinel")
    else:
        outside.write_bytes(b"outside-file-sentinel")
        sentinel = outside
    before = sentinel.read_bytes()
    destination.symlink_to(
        outside,
        target_is_directory=target_is_directory,
    )

    result = sandbox.run_library()

    assert result.returncode != 0
    assert sentinel.read_bytes() == before
    assert sandbox.mutation_commands() == []
