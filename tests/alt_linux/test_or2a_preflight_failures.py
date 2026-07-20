from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from alt_deploy.ansible import _classify_preflight_failure
from support.controller_sandbox import make_controller_sandbox

PREFLIGHT_FAILURE_KINDS = {
    "ssh_timeout",
    "ssh_unreachable",
    "ssh_host_key_mismatch",
    "ssh_authentication_failed",
    "sudo_unavailable",
    "ansible_failed",
}


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
