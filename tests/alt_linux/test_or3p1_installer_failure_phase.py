from __future__ import annotations

from pathlib import Path

from support.installer_sandbox import InstallerSandbox


def test_post_maintenance_failure_reports_phase_and_or3p3_recovery(
    tmp_path: Path,
) -> None:
    sandbox = InstallerSandbox.create(tmp_path)

    result = sandbox.run_library(INSTALLER_INSTALL_RC="23")

    assert result.returncode != 0
    assert "installed successfully" not in result.stdout.lower()
    stderr = result.stderr.lower()
    assert "controller_package" in stderr
    assert "or-3p3" in stderr
    assert "restore" in stderr
