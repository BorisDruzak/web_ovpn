from __future__ import annotations

import json
from pathlib import Path
import runpy
import subprocess
import sys

from test_deploy_netctl import _run_installer


ROOT = Path(__file__).resolve().parents[1]
VERIFIER = ROOT / "deploy" / "verify_netctl_systemd.py"
FIXTURE = ROOT / "tests" / "fixtures" / "systemd" / "netctl-retention.properties"


def test_installer_installs_and_enables_retention_only_after_systemd_verification(tmp_path: Path) -> None:
    result, _bin_dir, calls_path, environment = _run_installer(tmp_path)

    assert result.returncode == 0, result.stderr
    sudo_calls = Path(environment["SUDO_CALLS"]).read_text(encoding="utf-8")
    assert "deploy/netctl-retention.service" in sudo_calls
    assert "deploy/netctl-retention.timer" in sudo_calls

    calls = calls_path.read_text(encoding="utf-8").splitlines()
    verification_index = next(
        index
        for index, call in enumerate(
            Path(environment["SUDO_CALLS"]).read_text(encoding="utf-8").splitlines()
        )
        if call.startswith("/usr/local/sbin/verify-netctl-systemd")
    )
    reload_index = calls.index("daemon-reload")
    retention_index = calls.index("enable --now netctl-retention.timer")
    assert reload_index < retention_index

    sudo_lines = Path(environment["SUDO_CALLS"]).read_text(encoding="utf-8").splitlines()
    retention_enable = "systemctl enable --now netctl-retention.timer"
    assert verification_index < sudo_lines.index(retention_enable)


def test_systemd_verifier_expects_the_retention_command() -> None:
    verifier = runpy.run_path(str(VERIFIER))

    assert verifier["EXPECTED_EXEC_STARTS"]["netctl-retention.service"] == [
        "/usr/local/sbin/netctl",
        "--json",
        "retention",
        "cleanup",
        "--days",
        "30",
        "--apply",
    ]


def test_systemd_show_property_parser_reads_retention_hardening_and_schedule() -> None:
    result = subprocess.run(
        [sys.executable, "-B", str(VERIFIER), "--parse-show-properties"],
        text=True,
        encoding="utf-8",
        input=FIXTURE.read_text(encoding="utf-8"),
        capture_output=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == {
        "Group": "netctl",
        "NoNewPrivileges": "yes",
        "OnCalendar": "*-*-* 03:17:00",
        "Persistent": "yes",
        "PrivateTmp": "yes",
        "ProtectHome": "yes",
        "Unit": "netctl-retention.service",
        "User": "netctl",
    }
