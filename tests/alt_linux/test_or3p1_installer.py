from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest

from support.installer_sandbox import (
    ALT_ROOT,
    PUBLIC_INSTALLER,
    InstallerSandbox,
)


def assert_pre_mutation_failure(
    sandbox: InstallerSandbox,
    result: subprocess.CompletedProcess[str],
    before: dict[str, bytes],
) -> None:
    assert result.returncode != 0
    assert sandbox.protected_snapshot() == before
    assert InstallerSandbox.mutation_commands(sandbox.commands()) == []


def test_public_installer_requires_root_before_work(
    tmp_path: Path,
) -> None:
    if os.geteuid() == 0:
        pytest.skip("root runner cannot exercise the non-root public boundary")

    sandbox = InstallerSandbox.create(tmp_path)
    before = sandbox.protected_snapshot()

    result = subprocess.run(
        ["bash", str(PUBLIC_INSTALLER)],
        text=True,
        capture_output=True,
        check=False,
        env=sandbox.environment(),
    )

    assert result.returncode != 0
    assert "Run as root" in result.stderr
    assert sandbox.protected_snapshot() == before
    assert InstallerSandbox.mutation_commands(sandbox.commands()) == []


def test_installer_prechecks_succeed_without_mutation(
    tmp_path: Path,
) -> None:
    sandbox = InstallerSandbox.create(tmp_path)
    before = sandbox.protected_snapshot()

    result = sandbox.run_prechecks()

    assert result.returncode == 0, result.stderr
    assert sandbox.protected_snapshot() == before
    assert InstallerSandbox.mutation_commands(sandbox.commands()) == []


def test_active_jobs_block_before_mutation(tmp_path: Path) -> None:
    sandbox = InstallerSandbox.create(tmp_path)
    before = sandbox.protected_snapshot()
    jobs_payload = json.dumps(
        {
            "status": "ok",
            "active_jobs": [
                {
                    "job_id": "job-20260721T120000Z-22222222",
                    "machine_uuid": "fixture-machine",
                    "state": "running",
                    "stage": "employee",
                    "created_at": "2026-07-21T12:00:00+00:00",
                }
            ],
            "count": 1,
        }
    )

    result = sandbox.run_library(INSTALLER_JOBS_JSON=jobs_payload)

    assert_pre_mutation_failure(sandbox, result, before)
    assert "active" in result.stderr.lower()


def test_malformed_active_job_payload_blocks_before_mutation(
    tmp_path: Path,
) -> None:
    sandbox = InstallerSandbox.create(tmp_path)
    before = sandbox.protected_snapshot()

    result = sandbox.run_library(INSTALLER_JOBS_JSON='{"count":"none"}')

    assert_pre_mutation_failure(sandbox, result, before)
    assert "job" in result.stderr.lower()


def test_pending_registration_blocks_before_mutation(
    tmp_path: Path,
) -> None:
    sandbox = InstallerSandbox.create(tmp_path)
    pending = sandbox.seed_pending()
    before = sandbox.protected_snapshot()

    result = sandbox.run_library()

    assert_pre_mutation_failure(sandbox, result, before)
    assert pending.read_bytes() == b"{}\n"
    assert "pending" in result.stderr.lower()
    flattened = "\n".join(
        " ".join(command) for command in sandbox.commands()
    )
    assert "ssh " not in f"{flattened} "
    assert "ansible-playbook -i" not in flattened


@pytest.mark.parametrize(
    ("override", "message_fragment"),
    [
        ({"INSTALLER_JOBS_RC": "4"}, "job"),
        ({"INSTALLER_VAULT_RC": "7"}, "vault"),
        ({"INSTALLER_PERMISSIONS_RC": "8"}, "permission"),
        ({"INSTALLER_STAT_UNSAFE": "1"}, "ssh"),
        ({"INSTALLER_PROCESS_ACTIVE": "1"}, "processor"),
    ],
)
def test_live_state_failures_block_before_mutation(
    tmp_path: Path,
    override: dict[str, str],
    message_fragment: str,
) -> None:
    sandbox = InstallerSandbox.create(tmp_path)
    before = sandbox.protected_snapshot()

    result = sandbox.run_library(**override)

    assert_pre_mutation_failure(sandbox, result, before)
    assert message_fragment in result.stderr.lower()


def test_installer_deploys_complete_runtime_and_preserves_state(
    tmp_path: Path,
) -> None:
    sandbox = InstallerSandbox.create(tmp_path)
    before = sandbox.protected_snapshot()

    result = sandbox.run_library()

    assert result.returncode == 0, result.stderr
    assert "installed successfully" in result.stdout.lower()

    expected_files = {
        "/opt/alt-deploy-api/static_server.py": (
            ALT_ROOT / "api" / "static_server.py"
        ).read_bytes(),
        "/opt/alt-deploy-api/register_api.py": (
            ALT_ROOT / "api" / "register_api.py"
        ).read_bytes(),
        "/opt/alt-deploy-api/process_pending.py": (
            ALT_ROOT / "api" / "process_pending.py"
        ).read_bytes(),
        "/etc/systemd/system/alt-deploy-http.service": (
            ALT_ROOT / "systemd" / "alt-deploy-http.service"
        ).read_bytes(),
        "/etc/systemd/system/alt-deploy-register.service": (
            ALT_ROOT / "systemd" / "alt-deploy-register.service"
        ).read_bytes(),
        "/etc/systemd/system/alt-deploy-process.path": (
            ALT_ROOT / "systemd" / "alt-deploy-process.path"
        ).read_bytes(),
        "/etc/systemd/system/alt-deploy-process.service": (
            ALT_ROOT / "systemd" / "alt-deploy-process.service"
        ).read_bytes(),
        "/srv/alt-deploy/bootstrap/bootstrap.sh": (
            ALT_ROOT / "bootstrap" / "bootstrap.sh"
        ).read_bytes(),
    }
    for absolute_path, expected in expected_files.items():
        assert sandbox.destination(absolute_path).read_bytes() == expected

    for directory in (
        "/var/lib/alt-deploy/jobs",
        "/var/lib/alt-deploy/assignments",
        "/srv/alt-deploy/registration/pending",
        "/srv/alt-deploy/registration/ready",
        "/srv/alt-deploy/registration/failed",
        "/home/altserver/.ssh",
    ):
        assert sandbox.destination(directory).is_dir()

    after = sandbox.protected_snapshot()
    for path, expected in before.items():
        assert after[path] == expected


def test_installer_orders_maintenance_install_and_readiness(
    tmp_path: Path,
) -> None:
    sandbox = InstallerSandbox.create(tmp_path)

    result = sandbox.run_library()

    assert result.returncode == 0, result.stderr
    commands = sandbox.commands()

    def index_of(predicate) -> int:
        return next(
            index
            for index, command in enumerate(commands)
            if predicate(command)
        )

    stop_path = index_of(
        lambda command: command[:3]
        == ["systemctl", "stop", "alt-deploy-process.path"]
    )
    stop_register = index_of(
        lambda command: command[:3]
        == ["systemctl", "stop", "alt-deploy-register.service"]
    )
    stop_http = index_of(
        lambda command: command[:3]
        == ["systemctl", "stop", "alt-deploy-http.service"]
    )
    first_install = index_of(lambda command: command[0] == "install")
    daemon_reload = index_of(
        lambda command: command[:2] == ["systemctl", "daemon-reload"]
    )
    enable_http = index_of(
        lambda command: command[:4]
        == ["systemctl", "enable", "--now", "alt-deploy-http.service"]
    )
    enable_register = index_of(
        lambda command: command[:4]
        == ["systemctl", "enable", "--now", "alt-deploy-register.service"]
    )
    enable_path = index_of(
        lambda command: command[:4]
        == ["systemctl", "enable", "--now", "alt-deploy-process.path"]
    )
    readiness = index_of(
        lambda command: command[0] == "sudo"
        and command[-2:] == ["controller", "readiness"]
    )

    assert stop_path < stop_register < stop_http < first_install
    assert first_install < daemon_reload
    assert daemon_reload < enable_http < enable_register < enable_path
    assert enable_path < readiness


def test_readiness_failure_suppresses_installer_success(
    tmp_path: Path,
) -> None:
    sandbox = InstallerSandbox.create(tmp_path)

    result = sandbox.run_library(INSTALLER_READINESS_RC="11")

    assert result.returncode != 0
    assert "installed successfully" not in result.stdout.lower()
    assert "readiness" in result.stderr.lower()
