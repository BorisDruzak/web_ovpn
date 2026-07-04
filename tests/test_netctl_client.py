import json
import os
import subprocess
import sys
from pathlib import Path

import pytest


@pytest.fixture(autouse=True)
def reset_settings_cache_between_tests():
    from app.config import reset_settings_cache

    reset_settings_cache()
    yield
    reset_settings_cache()


def make_executable(path: Path, content: str) -> Path:
    script_path = path.with_suffix(".py") if os.name == "nt" else path
    script_path.write_text(content, encoding="utf-8")
    script_path.chmod(0o755)
    if os.name != "nt":
        return script_path
    wrapper = path.with_suffix(".cmd")
    wrapper.write_text(f'@echo off\r\n"{sys.executable}" "{script_path}" %*\r\n', encoding="utf-8")
    return wrapper


def test_run_netctl_uses_shell_false_and_parses_json(tmp_path, monkeypatch):
    fake = make_executable(
        tmp_path / "netctl",
        """#!/usr/bin/env python3
import json
import sys
from pathlib import Path
Path(sys.argv[-1]).write_text(json.dumps(sys.argv[1:]), encoding="utf-8")
print(json.dumps({"status": "ok", "hosts": []}))
""",
    )
    argv_file = tmp_path / "argv.json"
    monkeypatch.setenv("NETCTL_PATH", str(fake))
    monkeypatch.setenv("NETCTL_USE_SUDO", "0")

    from app.netctl_client import run_netctl

    result = run_netctl(["hosts", "list", str(argv_file)], timeout=5)

    assert result == {"status": "ok", "hosts": []}
    assert json.loads(argv_file.read_text(encoding="utf-8")) == ["--json", "hosts", "list", str(argv_file)]


def test_run_netctl_never_uses_shell_true(tmp_path, monkeypatch):
    fake = make_executable(
        tmp_path / "netctl",
        """#!/usr/bin/env python3
import json
print(json.dumps({"status": "ok"}))
""",
    )
    calls = []
    real_run = subprocess.run

    def spy_run(*args, **kwargs):
        calls.append(kwargs)
        return real_run(*args, **kwargs)

    monkeypatch.setenv("NETCTL_PATH", str(fake))
    monkeypatch.setenv("NETCTL_USE_SUDO", "0")
    monkeypatch.setattr(subprocess, "run", spy_run)

    from app.netctl_client import run_netctl

    assert run_netctl(["validate"], timeout=5)["status"] == "ok"
    assert calls
    assert calls[0]["shell"] is False


def test_run_netctl_uses_configured_non_root_sudo_user(monkeypatch):
    import app.config as config
    from app.netctl_client import run_netctl

    calls = []

    def fake_run(command, **kwargs):
        calls.append(command)
        return subprocess.CompletedProcess(command, 0, '{"status": "ok"}', "")

    monkeypatch.setenv("NETCTL_PATH", "/usr/local/sbin/netctl")
    monkeypatch.setenv("NETCTL_USE_SUDO", "1")
    monkeypatch.setenv("NETCTL_SUDO_USER", "netctl")
    config.reset_settings_cache()
    monkeypatch.setattr(subprocess, "run", fake_run)

    assert run_netctl(["dashboard"], timeout=5) == {"status": "ok"}
    assert calls[0][:5] == ["sudo", "-n", "-u", "netctl", "/usr/local/sbin/netctl"]


def test_run_netctl_raises_controlled_error_on_nonzero(tmp_path, monkeypatch):
    fake = make_executable(
        tmp_path / "netctl",
        """#!/usr/bin/env python3
import sys
print("stdout")
print("stderr", file=sys.stderr)
raise SystemExit(7)
""",
    )
    monkeypatch.setenv("NETCTL_PATH", str(fake))
    monkeypatch.setenv("NETCTL_USE_SUDO", "0")

    from app.netctl_client import NetctlError, run_netctl

    with pytest.raises(NetctlError) as exc:
        run_netctl(["dashboard"], timeout=5)

    assert exc.value.returncode == 7
    assert "dashboard" in exc.value.message
    assert "stdout" in exc.value.stdout
    assert "stderr" in exc.value.stderr
