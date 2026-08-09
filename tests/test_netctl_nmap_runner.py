from __future__ import annotations

import runpy
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest


ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "deploy" / "netctl-nmap-fingerprint"


def test_runner_calls_only_the_restricted_helper_with_shell_disabled(monkeypatch) -> None:
    """Calling Nmap directly or using a shell would bypass the privilege boundary."""
    import netctl.nmap.runner as runner

    calls: list[tuple[list[str], dict[str, object]]] = []
    xml = b'<nmaprun version="7.95"><host/></nmaprun>'

    def fake_run(command, **kwargs):
        calls.append((command, kwargs))
        return SimpleNamespace(returncode=0, stdout=xml, stderr=b"ignored")

    monkeypatch.setattr(runner.subprocess, "run", fake_run)

    result = runner.run_nmap_fingerprint("192.168.100.55")

    assert result.nmap_version == "7.95"
    assert calls == [
        (
            [
                "/usr/bin/sudo",
                "--non-interactive",
                "/usr/local/libexec/netctl-nmap-fingerprint",
                "192.168.100.55",
            ],
            {
                "capture_output": True,
                "check": False,
                "shell": False,
                "timeout": 30,
            },
        )
    ]


def test_runner_rejects_argument_text_before_starting_a_process(monkeypatch) -> None:
    """An appended Nmap option must never cross the subprocess boundary."""
    import netctl.nmap.runner as runner
    from netctl.nmap.policy import FingerprintPolicyError

    execute = Mock(side_effect=AssertionError("process must not start"))
    monkeypatch.setattr(runner.subprocess, "run", execute)

    with pytest.raises(FingerprintPolicyError):
        runner.run_nmap_fingerprint("192.168.100.55 --script default")

    execute.assert_not_called()


def test_runner_sanitizes_nonzero_exit_without_exposing_stderr(monkeypatch) -> None:
    """Nmap or sudo stderr can contain host and local privilege details."""
    import netctl.nmap.runner as runner

    monkeypatch.setattr(
        runner.subprocess,
        "run",
        lambda *_args, **_kwargs: SimpleNamespace(
            returncode=7,
            stdout=b"partial raw XML",
            stderr=b"sudo secret and raw nmap diagnostics",
        ),
    )

    with pytest.raises(runner.NmapRunnerError) as caught:
        runner.run_nmap_fingerprint("192.168.100.55")

    assert caught.value.error_class == "scan_failed"
    assert str(caught.value) == "fingerprint helper failed"
    assert "secret" not in repr(caught.value)
    assert "diagnostics" not in repr(caught.value)


def test_runner_sanitizes_timeout(monkeypatch) -> None:
    import netctl.nmap.runner as runner

    def timeout(*_args, **_kwargs):
        raise subprocess.TimeoutExpired("private command", 30, stderr=b"private")

    monkeypatch.setattr(runner.subprocess, "run", timeout)

    with pytest.raises(runner.NmapRunnerError) as caught:
        runner.run_nmap_fingerprint("192.168.100.55")

    assert caught.value.error_class == "timeout"
    assert str(caught.value) == "fingerprint helper timed out"


def test_deploy_helper_builds_the_complete_fixed_no_nse_command(monkeypatch) -> None:
    """Removing a fixed bound or adding NSE would widen every privileged scan."""
    expected = [
        "/usr/bin/nmap",
        "-n",
        "-Pn",
        "-sS",
        "-O",
        "--osscan-limit",
        "-sV",
        "--version-light",
        "--top-ports",
        "100",
        "--max-retries",
        "1",
        "--host-timeout",
        "20s",
        "-T3",
        "-oX",
        "-",
        "192.168.100.55",
    ]
    completed = SimpleNamespace(returncode=0, stdout=b"")
    execute = Mock(return_value=completed)
    monkeypatch.setattr(subprocess, "run", execute)
    monkeypatch.setattr(
        sys,
        "argv",
        [str(HELPER), "192.168.100.55"],
    )

    with pytest.raises(SystemExit) as caught:
        runpy.run_path(str(HELPER), run_name="__main__")

    assert caught.value.code == 0
    execute.assert_called_once_with(
        expected,
        capture_output=True,
        check=False,
        env={"LANG": "C", "LC_ALL": "C", "PATH": "/usr/sbin:/usr/bin:/sbin:/bin"},
        shell=False,
        timeout=25,
    )
    assert not any(argument in {"-sC", "--script", "-A"} for argument in expected)


def test_deploy_helper_rejects_extra_arguments_before_nmap() -> None:
    result = subprocess.run(
        [sys.executable, str(HELPER), "192.168.100.55", "--script", "default"],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 2
    assert result.stdout == ""
    assert result.stderr == "invalid fingerprint target\n"


def test_deploy_assets_grant_root_only_for_the_restricted_helper() -> None:
    sudoers = (ROOT / "deploy" / "sudoers-netctl-nmap").read_text(encoding="utf-8")
    installer = (ROOT / "deploy" / "install-openvpn-web.sh").read_text(encoding="utf-8")

    assert sudoers.strip() == (
        "netctl ALL=(root) NOPASSWD: "
        "/usr/local/libexec/netctl-nmap-fingerprint *"
    )
    assert "/usr/bin/nmap" not in sudoers
    assert "NOPASSWD: ALL" not in sudoers
    assert "sudo_cmd test -x /usr/bin/nmap" in installer
    assert "Nmap is required" in installer
    assert 'install -m 0755 -o root -g root "$SRC/deploy/netctl-nmap-fingerprint"' in installer
    assert 'install -m 0440 -o root -g root "$SRC/deploy/sudoers-netctl-nmap"' in installer
    assert "visudo -cf /etc/sudoers.d/netctl-nmap" in installer
