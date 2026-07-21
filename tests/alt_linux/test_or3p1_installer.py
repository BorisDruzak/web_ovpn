from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest

from support.installer_sandbox import (
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

    result = sandbox.run_library()

    assert result.returncode == 0, result.stderr
    assert "prechecks passed" in result.stdout.lower()
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
