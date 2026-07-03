import json
import os
import sys
from pathlib import Path

import pytest


def make_executable(path: Path, content: str) -> Path:
    script_path = path.with_suffix(".py") if os.name == "nt" else path
    script_path.write_text(content, encoding="utf-8")
    script_path.chmod(0o755)
    if os.name != "nt":
        return script_path
    wrapper = path.with_suffix(".cmd")
    wrapper.write_text(f'@echo off\r\n"{sys.executable}" "{script_path}" %*\r\n', encoding="utf-8")
    return wrapper


def test_run_vpnctl_inserts_json_after_binary_and_parses_output(tmp_path, monkeypatch):
    fake = make_executable(
        tmp_path / "vpnctl",
        """#!/usr/bin/env python3
import json
import sys
from pathlib import Path
Path(sys.argv[-1]).write_text(json.dumps(sys.argv[1:]), encoding="utf-8")
print(json.dumps({"status": "ok", "clients": []}))
""",
    )
    argv_file = tmp_path / "argv.json"
    monkeypatch.setenv("VPNCTL_PATH", str(fake))
    monkeypatch.setenv("VPNCTL_USE_SUDO", "0")

    from app.vpnctl_client import run_vpnctl

    result = run_vpnctl(["list", str(argv_file)], timeout=5)

    assert result == {"status": "ok", "clients": []}
    assert json.loads(argv_file.read_text(encoding="utf-8")) == ["--json", "list", str(argv_file)]


def test_run_vpnctl_raises_controlled_error_on_nonzero(tmp_path, monkeypatch):
    fake = make_executable(
        tmp_path / "vpnctl",
        """#!/usr/bin/env python3
import sys
print("not secret stdout")
print("not secret stderr", file=sys.stderr)
raise SystemExit(7)
""",
    )
    monkeypatch.setenv("VPNCTL_PATH", str(fake))
    monkeypatch.setenv("VPNCTL_USE_SUDO", "0")

    from app.vpnctl_client import VpnctlError, run_vpnctl

    with pytest.raises(VpnctlError) as exc:
        run_vpnctl(["status"], timeout=5)

    assert exc.value.returncode == 7
    assert "not secret stdout" in exc.value.stdout
    assert "not secret stderr" in exc.value.stderr
    assert "status" in exc.value.message
