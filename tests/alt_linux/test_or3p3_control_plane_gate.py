from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from support.installer_sandbox import (
    ALT_ROOT,
    DEFAULT_ROLLBACK_BACKUP_ID,
    InstallerSandbox,
)


ARGUMENTS_LIBRARY = ALT_ROOT / "install-control-plane-args.sh"


def _parse(*arguments: str) -> subprocess.CompletedProcess[str]:
    quoted = " ".join(subprocess.list2cmdline([item]) for item in arguments)
    return subprocess.run(
        [
            "bash",
            "-c",
            f"source {ARGUMENTS_LIBRARY!s}; parse_control_plane_args {quoted}",
        ],
        text=True,
        capture_output=True,
        check=False,
    )


def test_control_plane_argument_parser_accepts_exact_backup_id() -> None:
    result = _parse(
        "--rollback-backup-id",
        DEFAULT_ROLLBACK_BACKUP_ID,
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == DEFAULT_ROLLBACK_BACKUP_ID


@pytest.mark.parametrize(
    "arguments",
    [
        (),
        ("--rollback-backup-id",),
        ("--rollback-backup-id", "invalid"),
        (
            "--rollback-backup-id",
            DEFAULT_ROLLBACK_BACKUP_ID,
            "--rollback-backup-id",
            DEFAULT_ROLLBACK_BACKUP_ID,
        ),
        ("--unknown", DEFAULT_ROLLBACK_BACKUP_ID),
        (DEFAULT_ROLLBACK_BACKUP_ID,),
    ],
)
def test_control_plane_argument_parser_rejects_unsafe_forms(
    arguments: tuple[str, ...],
) -> None:
    result = _parse(*arguments)

    assert result.returncode != 0


def test_control_plane_installer_requires_explicit_backup_before_mutation(
    tmp_path: Path,
) -> None:
    sandbox = InstallerSandbox.create(tmp_path)
    before = sandbox.protected_snapshot()

    result = sandbox.run_library(rollback_backup_id="")

    assert result.returncode != 0
    assert "rollback backup ID" in result.stderr
    assert sandbox.protected_snapshot() == before
    assert InstallerSandbox.mutation_commands(sandbox.commands()) == []


def test_control_plane_installer_uses_one_read_only_eligibility_call(
    tmp_path: Path,
) -> None:
    sandbox = InstallerSandbox.create(tmp_path)

    result = sandbox.run_prechecks()

    assert result.returncode == 0, result.stderr
    backup_commands = [
        command
        for command in sandbox.commands()
        if command and command[0] == "alt-deploy-backup"
    ]
    assert backup_commands == [
        [
            "alt-deploy-backup",
            "rehearse-status",
            DEFAULT_ROLLBACK_BACKUP_ID,
        ]
    ]
    assert all("verify" not in command for command in backup_commands)


def test_eligibility_response_requires_exact_evidence_hashes(
    tmp_path: Path,
) -> None:
    sandbox = InstallerSandbox.create(tmp_path)
    before = sandbox.protected_snapshot()
    payload = json.dumps(
        {
            "status": "ok",
            "result": "backup_rehearsed",
            "backup_id": DEFAULT_ROLLBACK_BACKUP_ID,
        }
    )

    result = sandbox.run_library(
        INSTALLER_BACKUP_STATUS_PAYLOAD=payload,
    )

    assert result.returncode != 0
    assert "eligibility response is invalid" in result.stderr
    assert sandbox.protected_snapshot() == before
    assert InstallerSandbox.mutation_commands(sandbox.commands()) == []


def test_ineligible_backup_blocks_before_repository_verification(
    tmp_path: Path,
) -> None:
    sandbox = InstallerSandbox.create(tmp_path)
    before = sandbox.protected_snapshot()

    result = sandbox.run_library(INSTALLER_BACKUP_STATUS_RC="4")

    assert result.returncode != 0
    assert sandbox.protected_snapshot() == before
    assert InstallerSandbox.mutation_commands(sandbox.commands()) == []
    assert not any(
        command[:3] == ["python3", "-m", "pytest"]
        for command in sandbox.commands()
    )


def test_unsafe_installed_backup_tool_metadata_blocks_before_mutation(
    tmp_path: Path,
) -> None:
    sandbox = InstallerSandbox.create(tmp_path)
    tool = sandbox.destination("/usr/local/sbin/alt-deploy-backup")
    tool.chmod(0o777)
    before = sandbox.protected_snapshot()

    result = sandbox.run_library()

    assert result.returncode != 0
    assert "backup utility" in result.stderr.lower()
    assert sandbox.protected_snapshot() == before
    assert InstallerSandbox.mutation_commands(sandbox.commands()) == []


def test_missing_installed_guard_unit_blocks_before_mutation(
    tmp_path: Path,
) -> None:
    sandbox = InstallerSandbox.create(tmp_path)
    guard = sandbox.destination(
        "/etc/systemd/system/alt-deploy-guard.service"
    )
    guard.unlink()
    before = sandbox.protected_snapshot()

    result = sandbox.run_library()

    assert result.returncode != 0
    assert "guard" in result.stderr.lower()
    assert sandbox.protected_snapshot() == before
    assert InstallerSandbox.mutation_commands(sandbox.commands()) == []


def test_rollout_guard_commands_wrap_control_plane_mutation(
    tmp_path: Path,
) -> None:
    sandbox = InstallerSandbox.create(tmp_path)

    result = sandbox.run_library()

    assert result.returncode == 0, result.stderr
    commands = sandbox.commands()

    def index(expected: list[str]) -> int:
        return next(
            offset
            for offset, command in enumerate(commands)
            if command == expected
        )

    rehearse = index(
        [
            "alt-deploy-backup",
            "rehearse-status",
            DEFAULT_ROLLBACK_BACKUP_ID,
        ]
    )
    begin = index(
        [
            "alt-deploy-backup",
            "rollout-begin",
            DEFAULT_ROLLBACK_BACKUP_ID,
        ]
    )
    first_stop = next(
        offset
        for offset, command in enumerate(commands)
        if command[:2] == ["systemctl", "stop"]
    )
    authorize = index(
        [
            "alt-deploy-backup",
            "rollout-authorize",
            DEFAULT_ROLLBACK_BACKUP_ID,
        ]
    )
    daemon_reload = index(["systemctl", "daemon-reload"])
    readiness = next(
        offset
        for offset, command in enumerate(commands)
        if command[0] == "sudo"
        and command[-2:] == ["controller", "readiness"]
    )
    complete = index(
        [
            "alt-deploy-backup",
            "rollout-complete",
            DEFAULT_ROLLBACK_BACKUP_ID,
        ]
    )

    assert rehearse < begin < first_stop
    assert first_stop < authorize < daemon_reload < readiness < complete


def test_readiness_failure_revokes_permit_and_leaves_marker(
    tmp_path: Path,
) -> None:
    sandbox = InstallerSandbox.create(tmp_path)

    result = sandbox.run_library(INSTALLER_READINESS_RC="11")

    assert result.returncode != 0
    backup_commands = [
        command
        for command in sandbox.commands()
        if command and command[0] == "alt-deploy-backup"
    ]
    assert [
        "alt-deploy-backup",
        "rollout-begin",
        DEFAULT_ROLLBACK_BACKUP_ID,
    ] in backup_commands
    assert [
        "alt-deploy-backup",
        "rollout-revoke",
        DEFAULT_ROLLBACK_BACKUP_ID,
    ] in backup_commands
    assert [
        "alt-deploy-backup",
        "rollout-complete",
        DEFAULT_ROLLBACK_BACKUP_ID,
    ] not in backup_commands
    assert any(
        command[:3]
        == ["systemctl", "stop", "alt-deploy-http.service"]
        for command in sandbox.commands()
    )


def test_installer_retries_transient_readiness_before_revoking_rollout(
    tmp_path: Path,
) -> None:
    sandbox = InstallerSandbox.create(tmp_path)
    counter = tmp_path / "readiness-attempts"

    result = sandbox.run_library(
        INSTALLER_READINESS_FAILS_BEFORE_SUCCESS="1",
        INSTALLER_READINESS_COUNTER=str(counter),
    )

    assert result.returncode == 0, result.stderr
    readiness_commands = [
        command
        for command in sandbox.commands()
        if command
        and command[0] == "sudo"
        and command[-2:] == ["controller", "readiness"]
    ]
    assert len(readiness_commands) == 2
    assert not any(
        command[:2] == ["alt-deploy-backup", "rollout-revoke"]
        for command in sandbox.commands()
    )


def test_control_plane_installer_never_targets_backup_tool_paths() -> None:
    source = (
        ALT_ROOT / "install-control-plane-lib.sh"
    ).read_text(encoding="utf-8")
    protected = (
        "/usr/local/sbin/alt-deploy-backup",
        "/opt/alt-deploy-backup",
        "/var/lib/alt-deploy-backup",
        "/var/backups/alt-deploy",
        "/var/log/alt-deploy-backup.log",
    )

    mutation_lines = [
        line
        for line in source.splitlines()
        if any(
            token in line
            for token in ("rm ", "cp ", "install ", "chown ", "chmod ")
        )
    ]
    for path in protected:
        assert all(path not in line for line in mutation_lines)
