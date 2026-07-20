from __future__ import annotations

import os
import stat
import subprocess
import sys
from pathlib import Path

import pytest


VPNCTL = Path(__file__).resolve().parents[1] / "deploy" / "vpnctl"


@pytest.mark.skipif(
    os.name == "nt" or getattr(os, "geteuid", lambda: 0)() == 0,
    reason="Requires non-root POSIX permission enforcement",
)
def test_vpnctl_ignores_unreadable_optional_env_file(
    tmp_path: Path,
) -> None:
    blocked_dir = tmp_path / "blocked-openvpn"
    blocked_dir.mkdir()

    optional_env = blocked_dir / "vpnctl.env"
    optional_env.write_text(
        "REMOTE_HOST=example.invalid\n",
        encoding="utf-8",
    )

    copied_vpnctl = tmp_path / "vpnctl"
    source = VPNCTL.read_text(encoding="utf-8")

    original = 'Path("/etc/openvpn/vpnctl.env")'
    replacement = f"Path({str(optional_env)!r})"

    assert source.count(original) == 1

    copied_vpnctl.write_text(
        source.replace(original, replacement),
        encoding="utf-8",
    )

    blocked_dir.chmod(0)

    try:
        result = subprocess.run(
            [
                sys.executable,
                str(copied_vpnctl),
                "--help",
            ],
            env={
                **os.environ,
                "PYTHONDONTWRITEBYTECODE": "1",
            },
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
    finally:
        blocked_dir.chmod(stat.S_IRWXU)

    assert result.returncode == 0, result.stderr
    assert "PermissionError" not in result.stderr
