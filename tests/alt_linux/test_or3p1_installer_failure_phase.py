from __future__ import annotations

from pathlib import Path

from support.installer_sandbox import InstallerSandbox


def test_post_maintenance_failure_reports_phase_and_or3p3_recovery(
    tmp_path: Path,
) -> None:
    sandbox = InstallerSandbox.create(tmp_path)
    failing_install = sandbox.fake_bin / "install"
    failing_install.write_text(
        "#!/bin/bash\nexit 23\n",
        encoding="utf-8",
    )
    failing_install.chmod(0o755)

    result = sandbox.run_library()

    assert result.returncode != 0
    assert "installed successfully" not in result.stdout.lower()
    stderr = result.stderr.lower()
    assert "controller_package" in stderr
    assert "or-3p3" in stderr
    assert "restore" in stderr
