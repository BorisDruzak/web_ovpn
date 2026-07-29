from __future__ import annotations

import os
from pathlib import Path
import stat

import pytest

from tests.alt_linux.support.installer_sandbox import (
    DEFAULT_ROLLBACK_BACKUP_ID,
    InstallSessionInstallerSandbox,
)


REPO_ROOT = Path(__file__).resolve().parents[2]
ALT_ROOT = REPO_ROOT / "deploy" / "alt-linux"
INSTALLER = ALT_ROOT / "install-install-session-api.sh"
UNIT = ALT_ROOT / "systemd" / "alt-install-session.service"
RUNBOOK = REPO_ROOT / "docs" / "runbooks" / "alt-install-session-api-pr5a.md"
EXISTING_UNIT = "[Service]\nExecStart=/existing\n"


def test_production_unit_is_bound_and_least_privileged() -> None:
    text = UNIT.read_text(encoding="utf-8")
    assert "User=altserver" in text and "Group=altserver" in text
    assert (
        "--listen-address 192.168.100.17 --listen-port 18090"
        in text
    )
    assert (
        "ReadWritePaths=/var/lib/alt-deploy/install-sessions"
        in text
    )
    assert (
        "ReadWritePaths=/var/lib/alt-deploy/install-sessions.lock"
        in text
    )
    assert "/var/lib/alt-deploy-secrets" not in text
    for item in (
        "NoNewPrivileges=true",
        "PrivateTmp=true",
        "PrivateDevices=true",
        "ProtectSystem=strict",
        "ProtectHome=read-only",
        "RestrictAddressFamilies=AF_INET AF_INET6",
        "CapabilityBoundingSet=",
    ):
        assert item in text


def test_pr5a_runbook_prohibits_spike_reuse_and_target_writes() -> None:
    text = RUNBOOK.read_text(encoding="utf-8")

    assert "192.168.100.17:18090" in text
    assert "18089" in text and "must not" in text.lower()
    assert "target-disk write" in text
    assert "systemd-analyze security alt-install-session.service" in text


def test_installer_activates_only_the_isolated_unit(tmp_path: Path) -> None:
    sandbox = InstallSessionInstallerSandbox.create(tmp_path)

    result = sandbox.run_install(
        rollback_backup_id=DEFAULT_ROLLBACK_BACKUP_ID
    )

    assert result.returncode == 0, result.stderr
    assert [
        "systemctl",
        "enable",
        "--now",
        "alt-install-session.service",
    ] in sandbox.commands()
    assert "install-control-plane.sh" not in INSTALLER.read_text(
        encoding="utf-8"
    )
    assert not any(
        command[:2] == ["systemctl", "stop"]
        and "alt-deploy-" in command[-1]
        for command in sandbox.commands()
    )
    assert sandbox.current_target() != str(
        sandbox.destination(
            "/opt/alt-install-session-api/releases/existing-release"
        )
    )


def test_clean_host_storage_is_created_for_service_user(tmp_path: Path) -> None:
    sandbox = InstallSessionInstallerSandbox.create(tmp_path)

    result = sandbox.run_install()

    assert result.returncode == 0, result.stderr
    sessions = sandbox.destination("/var/lib/alt-deploy/install-sessions")
    lock = sandbox.destination(
        "/var/lib/alt-deploy/install-sessions.lock"
    )
    assert sessions.is_dir()
    assert lock.is_file()
    if os.name != "nt":
        assert stat.S_IMODE(sessions.stat().st_mode) == 0o700
        assert stat.S_IMODE(lock.stat().st_mode) == 0o600
    assert [
        "install",
        "-d",
        "-o",
        "altserver",
        "-g",
        "altserver",
        "-m",
        "0700",
        str(sessions).replace("\\", "/").replace("C:/", "/c/"),
    ] in sandbox.commands()
    assert [
        "chmod",
        "0700",
        str(sessions).replace("\\", "/").replace("C:/", "/c/"),
    ] in sandbox.commands()
    assert [
        "chmod",
        "0600",
        str(lock).replace("\\", "/").replace("C:/", "/c/"),
    ] in sandbox.commands()
    assert [
        "stat",
        "-c",
        "%U %G %a",
        str(sessions).replace("\\", "/").replace("C:/", "/c/"),
    ] in sandbox.commands()
    assert [
        "stat",
        "-c",
        "%U %G %a",
        str(lock).replace("\\", "/").replace("C:/", "/c/"),
    ] in sandbox.commands()


@pytest.mark.parametrize(
    "overrides",
    (
        {"INSTALL_SESSION_SS_RC": "2"},
        {"INSTALL_SESSION_AWK_RC": "2"},
    ),
)
def test_socket_inspection_failure_is_not_treated_as_free(
    tmp_path: Path,
    overrides: dict[str, str],
) -> None:
    sandbox = InstallSessionInstallerSandbox.create(tmp_path)
    old_target = sandbox.current_target()

    result = sandbox.run_install(**overrides)

    assert result.returncode != 0
    assert "Install session API socket inspection failed" in result.stderr
    assert sandbox.current_target() == old_target
    assert not any(
        command and command[0] == "ln" for command in sandbox.commands()
    )


@pytest.mark.parametrize(
    "overrides",
    (
        {
            "INSTALL_SESSION_IS_ENABLED_STATUS": "transport-error",
            "INSTALL_SESSION_IS_ENABLED_RC": "5",
        },
        {
            "INSTALL_SESSION_IS_ACTIVE_STATUS": "transport-error",
            "INSTALL_SESSION_IS_ACTIVE_RC": "5",
        },
    ),
)
def test_unknown_systemd_inspection_aborts_before_pointer_activation(
    tmp_path: Path,
    overrides: dict[str, str],
) -> None:
    sandbox = InstallSessionInstallerSandbox.create(tmp_path)
    old_target = sandbox.current_target()

    result = sandbox.run_install(**overrides)

    assert result.returncode != 0
    assert "Install session API service state inspection failed" in result.stderr
    assert sandbox.current_target() == old_target
    assert not any(
        command and command[0] == "ln" for command in sandbox.commands()
    )


def test_symlinked_unit_destination_is_rejected(tmp_path: Path) -> None:
    sandbox = InstallSessionInstallerSandbox.create(tmp_path)
    unit = sandbox.destination(
        "/etc/systemd/system/alt-install-session.service"
    )
    target = tmp_path / "unit-target"
    target.write_text("do-not-overwrite\n", encoding="utf-8")
    unit.unlink()
    unit.symlink_to(target)
    old_target = sandbox.current_target()

    result = sandbox.run_install()

    assert result.returncode != 0
    assert "Service unit destination must not be a symlink" in result.stderr
    assert target.read_text(encoding="utf-8") == "do-not-overwrite\n"
    assert sandbox.current_target() == old_target


def test_unit_replacement_is_same_directory_and_atomic(tmp_path: Path) -> None:
    sandbox = InstallSessionInstallerSandbox.create(tmp_path)

    result = sandbox.run_install()

    assert result.returncode == 0, result.stderr
    unit = sandbox._bash_path(
        sandbox.destination(
            "/etc/systemd/system/alt-install-session.service"
        )
    )
    install_commands = [
        command for command in sandbox.commands()
        if command and command[0] == "install"
        and command[-1].startswith(f"{unit}.new-")
    ]
    assert len(install_commands) == 1
    temporary = install_commands[0][-1]
    assert [
        "mv", "-Tf", "--", temporary, unit
    ] in sandbox.commands()


def test_installer_lock_is_acquired_before_backup_gate(tmp_path: Path) -> None:
    sandbox = InstallSessionInstallerSandbox.create(tmp_path)

    result = sandbox.run_install()

    assert result.returncode == 0, result.stderr
    commands = sandbox.commands()
    flock_index = next(
        index for index, command in enumerate(commands)
        if command and command[0] == "flock"
    )
    backup_index = next(
        index for index, command in enumerate(commands)
        if command[:2] == ["alt-deploy-backup", "rehearse-status"]
    )
    assert flock_index < backup_index
    assert commands[flock_index][:3] == [
        "flock", "--exclusive", "--nonblock"
    ]
    installer_lock = sandbox._bash_path(
        sandbox.destination(
            "/run/lock/alt-install-session-installer.lock"
        )
    )
    assert [
        "chown", "root:root", installer_lock
    ] in commands
    assert [
        "chmod", "0600", installer_lock
    ] in commands
    assert [
        "stat", "-c", "%U %G %a", installer_lock
    ] in commands


def test_busy_installer_lock_aborts_without_preflight(tmp_path: Path) -> None:
    sandbox = InstallSessionInstallerSandbox.create(tmp_path)
    old_target = sandbox.current_target()

    result = sandbox.run_install(INSTALL_SESSION_FLOCK_RC="1")

    assert result.returncode != 0
    assert "Another install session API installer is running" in result.stderr
    assert sandbox.current_target() == old_target
    assert not any(
        command[:2] == ["alt-deploy-backup", "rehearse-status"]
        for command in sandbox.commands()
    )


def test_health_retries_exact_response_and_bypasses_proxy(
    tmp_path: Path,
) -> None:
    sandbox = InstallSessionInstallerSandbox.create(tmp_path)

    result = sandbox.run_install(
        INSTALL_SESSION_HEALTH_FAILS_BEFORE_SUCCESS="2"
    )

    assert result.returncode == 0, result.stderr
    curls = [
        command for command in sandbox.commands()
        if command and command[0] == "curl"
    ]
    assert len(curls) == 3
    assert all(
        ["--noproxy", "*"] == command[
            command.index("--noproxy"):command.index("--noproxy") + 2
        ]
        for command in curls
    )


def test_health_retry_is_bounded(tmp_path: Path) -> None:
    sandbox = InstallSessionInstallerSandbox.create(tmp_path)

    result = sandbox.run_install(
        INSTALL_SESSION_HEALTH_PAYLOAD=(
            '{"schema_version":1,"service":'
            '"alt-install-session","status":"starting"}'
        )
    )

    assert result.returncode != 0
    assert len([
        command for command in sandbox.commands()
        if command and command[0] == "curl"
    ]) == 5


@pytest.mark.parametrize(
    ("overrides", "expected_error"),
    (
        (
            {"INSTALLER_BACKUP_STATUS_PAYLOAD": '{"status":"ok"}'},
            "Invalid rollback rehearsal status",
        ),
        (
            {
                "INSTALL_SESSION_SS_OUTPUT": (
                    "LISTEN 0 128 192.168.100.17:18090 0.0.0.0:*\n"
                )
            },
            "Listener already occupies 192.168.100.17:18090",
        ),
        (
            {"INSTALL_SESSION_KEY_INIT_RC": "1"},
            "Install signing key initialization failed",
        ),
        (
            {
                "INSTALL_SESSION_HEALTH_PAYLOAD": (
                    '{"schema_version":1,"service":'
                    '"alt-install-session","status":"starting"}'
                )
            },
            "Install session API health validation failed",
        ),
        (
            {"INSTALL_SESSION_ACTIVATION_RC": "130"},
            "Install session API activation failed",
        ),
    ),
)
def test_install_failure_preserves_pointer_unit_and_service_state(
    tmp_path: Path,
    overrides: dict[str, str],
    expected_error: str,
) -> None:
    sandbox = InstallSessionInstallerSandbox.create(tmp_path)
    old_target = sandbox.current_target()

    result = sandbox.run_install(**overrides)

    assert result.returncode != 0
    assert expected_error in result.stderr
    assert sandbox.current_target() == old_target
    assert sandbox.unit_text() == EXISTING_UNIT
    assert sandbox.service_status() == ("enabled", "active")
    assert not any(
        "alt-deploy-" in command[-1]
        for command in sandbox.commands()
        if command[:2]
        in (
            ["systemctl", "stop"],
            ["systemctl", "disable"],
            ["systemctl", "restart"],
        )
    )


def test_install_rejects_symlinked_destination_parent(tmp_path: Path) -> None:
    sandbox = InstallSessionInstallerSandbox.create(tmp_path)
    releases = sandbox.destination(
        "/opt/alt-install-session-api/releases"
    )
    elsewhere = tmp_path / "elsewhere"
    releases.rename(elsewhere)
    releases.symlink_to(elsewhere, target_is_directory=True)
    old_target = sandbox.current_target()

    result = sandbox.run_install()

    assert result.returncode != 0
    assert "Symlinked destination parent rejected" in result.stderr
    assert sandbox.current_target() == old_target
    assert sandbox.unit_text() == EXISTING_UNIT
    assert sandbox.service_status() == ("enabled", "active")


def test_preactivation_failure_removes_staging_runtime(tmp_path: Path) -> None:
    sandbox = InstallSessionInstallerSandbox.create(tmp_path)
    releases = sandbox.destination(
        "/opt/alt-install-session-api/releases"
    )

    result = sandbox.run_install(INSTALL_SESSION_KEY_INIT_RC="1")

    assert result.returncode != 0
    assert sorted(path.name for path in releases.iterdir()) == [
        "existing-release"
    ]


def test_rollback_restores_previous_pointer_and_disables_only_owned_unit(
    tmp_path: Path,
) -> None:
    sandbox = InstallSessionInstallerSandbox.create(tmp_path)
    old_target = sandbox.current_target()
    installed = sandbox.run_install()
    assert installed.returncode == 0, installed.stderr
    before = sandbox.protected_snapshot()

    rolled_back = sandbox.run_rollback()

    assert rolled_back.returncode == 0, rolled_back.stderr
    assert sandbox.current_target() == old_target
    assert sandbox.service_status() == ("disabled", "inactive")
    assert [
        "systemctl",
        "disable",
        "--now",
        "alt-install-session.service",
    ] in sandbox.commands()
    assert before == sandbox.protected_snapshot()
    assert not any(
        "alt-deploy-" in command[-1]
        for command in sandbox.commands()
        if command and command[0] == "systemctl"
    )
