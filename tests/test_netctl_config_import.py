from __future__ import annotations

import subprocess
import sys


def test_config_module_imports_without_snmp_package_cycle() -> None:
    result = subprocess.run(
        [sys.executable, "-c", "import netctl.config"],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
