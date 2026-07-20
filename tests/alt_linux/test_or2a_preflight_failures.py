from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from alt_deploy.ansible import _classify_preflight_failure

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
