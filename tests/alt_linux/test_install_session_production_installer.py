from __future__ import annotations

from pathlib import Path

import pytest

from tests.alt_linux.support.installer_sandbox import (
    DEFAULT_ROLLBACK_BACKUP_ID,
    InstallSessionInstallerSandbox,
)


REPO_ROOT = Path(__file__).resolve().parents[2]
ALT_ROOT = REPO_ROOT / "deploy" / "alt-linux"
INSTALLER = ALT_ROOT / "install-install-session-api.sh"
UNIT = ALT_ROOT / "systemd" / "alt-install-session.service"
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
