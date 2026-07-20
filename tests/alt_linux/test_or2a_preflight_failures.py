from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from alt_deploy.ansible import _classify_preflight_failure
from alt_deploy.assignments import AssignmentRepository
from alt_deploy.jobs import JobRepository
from alt_deploy.jsonio import atomic_write_json, read_json
from support.cli import run_json_cli
from support.controller_sandbox import make_controller_sandbox
from support.outcomes import get_outcome
from support.payloads import TEST_MACHINE_UUID

PREFLIGHT_FAILURE_KINDS = {
    "ssh_timeout",
    "ssh_unreachable",
    "ssh_host_key_mismatch",
    "ssh_authentication_failed",
    "sudo_unavailable",
    "ansible_failed",
}

CLI_FAILURE_CASES = (
    (
        "preflight-ssh-unreachable",
        4,
        "",
        (
            "ssh: connect to host 192.0.2.56 port 22: "
            "Connection refused"
        ),
    ),
    (
        "preflight-ssh-host-key-mismatch",
        4,
        "",
        "REMOTE HOST IDENTIFICATION HAS CHANGED!",
    ),
    (
        "preflight-ssh-authentication-failed",
        4,
        "",
        "Permission denied (publickey).",
    ),
    (
        "preflight-sudo-unavailable",
        2,
        "ALT_PREFLIGHT_FAILURE:sudo_unavailable",
        "",
    ),
    (
        "preflight-ansible-failed",
        2,
        "Unsupported operating system",
        "",
    ),
)


@pytest.mark.parametrize(
    ("stdout", "stderr", "expected"),
    [
        (
            "ALT_PREFLIGHT_FAILURE:sudo_unavailable\nPLAY RECAP",
            "Host key verification failed",
            "sudo_unavailable",
        ),
        (
            "",
            "WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!",
            "ssh_host_key_mismatch",
        ),
        (
            "",
            "Host key verification failed.",
            "ssh_host_key_mismatch",
        ),
        (
            "",
            "Permission denied (publickey,password).",
            "ssh_authentication_failed",
        ),
        (
            "Authentication failed for ansible",
            "",
            "ssh_authentication_failed",
        ),
        (
            "",
            (
                "ssh: connect to host 192.0.2.56 port 22: "
                "Connection timed out"
            ),
            "ssh_timeout",
        ),
        (
            "",
            (
                "ssh: connect to host 192.0.2.56 port 22: "
                "Connection refused"
            ),
            "ssh_unreachable",
        ),
        (
            "fatal: [192.0.2.56]: UNREACHABLE!",
            "",
            "ansible_failed",
        ),
        (
            "ALT_PREFLIGHT_FAILURE:unknown_kind",
            "",
            "ansible_failed",
        ),
        (
            None,
            None,
            "ansible_failed",
        ),
    ],
)
def test_classify_preflight_failure(
    stdout: str | None,
    stderr: str | None,
    expected: str,
) -> None:
    result = _classify_preflight_failure(
        stdout=stdout,
        stderr=stderr,
    )

    assert result == expected
    assert result in PREFLIGHT_FAILURE_KINDS


def test_host_key_mismatch_precedes_authentication_text() -> None:
    result = _classify_preflight_failure(
        stdout="",
        stderr=(
            "REMOTE HOST IDENTIFICATION HAS CHANGED!\n"
            "Permission denied (publickey)."
        ),
    )

    assert result == "ssh_host_key_mismatch"


def test_preflight_role_contains_controlled_sudo_marker() -> None:
    role_path = (
        Path(__file__).resolve().parents[2]
        / "deploy"
        / "alt-linux"
        / "ansible"
        / "roles"
        / "preflight"
        / "tasks"
        / "main.yml"
    )
    content = role_path.read_text(encoding="utf-8")

    assert content.count(
        "ALT_PREFLIGHT_FAILURE:sudo_unavailable"
    ) == 1


def test_sandbox_configures_preflight_boundary(tmp_path: Path) -> None:
    sandbox = make_controller_sandbox(tmp_path)
    assets = sandbox.configure_preflight_boundary()

    assert set(assets) == {
        "ansible_playbook",
        "private_key",
        "known_hosts",
        "preflight_playbook",
    }
    for path in assets.values():
        path.relative_to(sandbox.root)
        assert path.is_file()

    assert assets["ansible_playbook"].stat().st_mode & 0o111
    assert assets["private_key"].read_text(encoding="utf-8") == (
        "test-only-private-key-placeholder\n"
    )


@pytest.mark.parametrize(
    ("scenario_id", "returncode", "stdout", "stderr"),
    CLI_FAILURE_CASES,
)
def test_preflight_cli_persists_classified_failure(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    scenario_id: str,
    returncode: int,
    stdout: str,
    stderr: str,
) -> None:
    outcome = get_outcome(scenario_id)
    sandbox = make_controller_sandbox(tmp_path)
    sandbox.configure_preflight_boundary()
    record_path = sandbox.register_machine()
    captured_command: list[str] = []

    def fake_run(command, **kwargs):
        captured_command[:] = command
        return subprocess.CompletedProcess(
            command,
            returncode,
            stdout,
            stderr,
        )

    monkeypatch.setattr(
        "alt_deploy.ansible.subprocess.run",
        fake_run,
    )

    result = run_json_cli(
        ["preflight", TEST_MACHINE_UUID],
        settings=sandbox.settings,
    )

    assert result.exit_code == outcome.command_exit_code
    assert result.payload["error"]["code"] == outcome.error_code
    assert result.payload["error"]["details"]["failure_kind"] == (
        outcome.failure_kind
    )

    record = read_json(record_path)
    assert record["status"] == "preflight_failed"
    assert record["preflight"]["error"]["details"] == (
        result.payload["error"]["details"]
    )
    assert JobRepository(sandbox.settings).list() == []
    assert AssignmentRepository(sandbox.settings).get(
        TEST_MACHINE_UUID
    ) is None

    ssh_args = next(
        value
        for value in captured_command
        if value.startswith("--ssh-common-args=")
    )
    assert "StrictHostKeyChecking=yes" in ssh_args
    assert "ProxyCommand=none" in ssh_args
    assert "IdentitiesOnly=yes" in ssh_args
    assert "ConnectTimeout=10" in ssh_args


def test_preflight_cli_classifies_timeout_exception(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    outcome = get_outcome("preflight-ssh-timeout")
    sandbox = make_controller_sandbox(tmp_path)
    sandbox.configure_preflight_boundary()
    record_path = sandbox.register_machine()

    def fake_run(command, **kwargs):
        raise subprocess.TimeoutExpired(command, kwargs["timeout"])

    monkeypatch.setattr(
        "alt_deploy.ansible.subprocess.run",
        fake_run,
    )

    result = run_json_cli(
        ["preflight", TEST_MACHINE_UUID],
        settings=sandbox.settings,
    )

    assert result.exit_code == outcome.command_exit_code
    assert result.payload["error"]["code"] == outcome.error_code
    assert result.payload["error"]["details"]["failure_kind"] == (
        outcome.failure_kind
    )
    assert result.payload["error"]["details"]["timeout"] == 180
    assert read_json(record_path)["status"] == "preflight_failed"
    assert JobRepository(sandbox.settings).list() == []
    assert AssignmentRepository(sandbox.settings).get(
        TEST_MACHINE_UUID
    ) is None


@pytest.mark.parametrize("malformed", [False, True])
def test_preflight_result_failures_use_ansible_fallback(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    malformed: bool,
) -> None:
    sandbox = make_controller_sandbox(tmp_path)
    sandbox.configure_preflight_boundary()
    record_path = sandbox.register_machine()

    def fake_run(command, **kwargs):
        if malformed:
            result_arg = next(
                value
                for value in command
                if value.startswith("preflight_result_file=")
            )
            result_path = Path(result_arg.split("=", 1)[1])
            result_path.write_text("not-json", encoding="utf-8")
        return subprocess.CompletedProcess(
            command,
            0,
            "PLAY RECAP",
            "",
        )

    monkeypatch.setattr(
        "alt_deploy.ansible.subprocess.run",
        fake_run,
    )

    result = run_json_cli(
        ["preflight", TEST_MACHINE_UUID],
        settings=sandbox.settings,
    )

    assert result.exit_code == 5
    assert result.payload["error"]["code"] == "preflight_failed"
    assert result.payload["error"]["details"]["failure_kind"] == (
        "ansible_failed"
    )
    assert read_json(record_path)["status"] == "preflight_failed"
    assert JobRepository(sandbox.settings).list() == []
    assert AssignmentRepository(sandbox.settings).get(
        TEST_MACHINE_UUID
    ) is None


def test_preflight_is_retryable_after_transport_failure(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    sandbox = make_controller_sandbox(tmp_path)
    sandbox.configure_preflight_boundary()
    record_path = sandbox.register_machine()
    attempts = 0

    def fake_run(command, **kwargs):
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            return subprocess.CompletedProcess(
                command,
                4,
                "",
                "Connection refused",
            )

        result_arg = next(
            value
            for value in command
            if value.startswith("preflight_result_file=")
        )
        result_path = Path(result_arg.split("=", 1)[1])
        atomic_write_json(
            result_path,
            {
                "status": "ok",
                "checks": {
                    "alt_release": True,
                    "uuid": True,
                },
            },
        )
        return subprocess.CompletedProcess(
            command,
            0,
            "PLAY RECAP",
            "",
        )

    monkeypatch.setattr(
        "alt_deploy.ansible.subprocess.run",
        fake_run,
    )

    failed = run_json_cli(
        ["preflight", TEST_MACHINE_UUID],
        settings=sandbox.settings,
    )
    succeeded = run_json_cli(
        ["preflight", TEST_MACHINE_UUID],
        settings=sandbox.settings,
    )

    assert failed.exit_code == 5
    assert failed.payload["error"]["details"]["failure_kind"] == (
        "ssh_unreachable"
    )
    assert succeeded.exit_code == 0

    record = read_json(record_path)
    assert record["status"] == "awaiting_assignment"
    assert record["preflight"]["status"] == "ok"
    assert attempts == 2
    assert JobRepository(sandbox.settings).list() == []
    assert AssignmentRepository(sandbox.settings).get(
        TEST_MACHINE_UUID
    ) is None
