from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess

import pytest


REPO_ROOT = Path(__file__).resolve().parents[2]
INSTALLER = REPO_ROOT / "deploy" / "alt-linux" / "install-install-execution-api.sh"
BASH = shutil.which("bash")


def _fake_command(directory: Path, name: str, body: str) -> None:
    path = directory / name
    path.write_text("#!/bin/bash\nset -Eeuo pipefail\n" + body, encoding="utf-8")
    path.chmod(0o755)


def _environment(tmp_path: Path, *, listener: str = "") -> dict[str, str]:
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    command_log = tmp_path / "commands.log"
    service_state = tmp_path / "service-state"
    service_state.write_text("disabled inactive\n", encoding="utf-8")
    _fake_command(
        fake_bin,
        "systemctl",
        "printf '%s\\n' \"$*\" >> \"${INSTALLER_COMMAND_LOG:?}\"\n"
        "case ${1:-} in\n"
        "  daemon-reload) exit 0 ;;\n"
        "  enable) printf 'enabled active\\n' > \"${INSTALLER_SERVICE_STATE:?}\" ;;\n"
        "  *) exit 90 ;;\n"
        "esac\n",
    )
    _fake_command(fake_bin, "ss", "printf '%s' \"${INSTALLER_SS_OUTPUT:-}\"\n")
    _fake_command(
        fake_bin,
        "curl",
        "printf '%s\\n' '{\"schema_version\":1,\"service\":\"alt-install-execution\",\"status\":\"ok\"}'\n",
    )
    environment = os.environ.copy()
    environment.update(
        {
            "PATH": f"{fake_bin}{os.pathsep}{environment['PATH']}",
            "INSTALLER_COMMAND_LOG": str(command_log),
            "INSTALLER_SERVICE_STATE": str(service_state),
            "INSTALLER_SS_OUTPUT": listener,
        }
    )
    return environment


def _run(tmp_path: Path, *, listener: str = "") -> subprocess.CompletedProcess[str]:
    root = tmp_path / "host-root"
    command = (
        "set -Eeuo pipefail; "
        f"source {INSTALLER.as_posix()!r}; "
        f"install_execution_api_main {root.as_posix()!r}"
    )
    return subprocess.run(
        [BASH, "-c", command],
        text=True,
        capture_output=True,
        cwd=REPO_ROOT,
        env=_environment(tmp_path, listener=listener),
        check=False,
    )


@pytest.mark.skipif(os.name == "nt" or BASH is None, reason="production installer test requires Linux Bash utilities")
def test_installer_stages_only_v2_runtime_generates_tls_and_activates_unit(
    tmp_path: Path,
) -> None:
    result = _run(tmp_path)

    assert result.returncode == 0, result.stderr
    root = tmp_path / "host-root"
    current = root / "opt" / "alt-install-execution-api" / "current"
    release = current.resolve()
    assert current.is_symlink()
    assert (release / "api" / "install_execution_server.py").is_file()
    assert (release / "control" / "alt_deploy" / "install_tls.py").is_file()
    assert not (root / "opt" / "alt-install-session-api").exists()
    assert (root / "etc" / "systemd" / "system" / "alt-install-execution.service").is_file()
    assert (root / "var" / "lib" / "alt-deploy-secrets" / "install-execution-server.pem").is_file()
    assert (root / "etc" / "alt-deploy" / "install-execution-server.pem").is_file()
    if os.name != "nt":
        assert (root / "var" / "lib" / "alt-deploy-secrets" / "install-execution-server.pem").stat().st_mode & 0o777 == 0o600
    assert (tmp_path / "service-state").read_text(encoding="utf-8") == "enabled active\n"
    commands = (tmp_path / "commands.log").read_text(encoding="utf-8")
    assert "daemon-reload" in commands
    assert "enable --now alt-install-execution.service" in commands


@pytest.mark.skipif(os.name == "nt" or BASH is None, reason="production installer test requires Linux Bash utilities")
def test_installer_refuses_the_exact_v2_listener_without_touching_v1(
    tmp_path: Path,
) -> None:
    root = tmp_path / "host-root"
    v1 = root / "opt" / "alt-install-session-api" / "v1-sentinel"
    v1.parent.mkdir(parents=True)
    v1.write_text("unchanged\n", encoding="utf-8")

    result = _run(
        tmp_path,
        listener="LISTEN 0 128 192.168.100.17:18092 0.0.0.0:*\n",
    )

    assert result.returncode != 0
    assert "Listener already occupies 192.168.100.17:18092" in result.stderr
    assert v1.read_text(encoding="utf-8") == "unchanged\n"
    assert not (root / "opt" / "alt-install-execution-api").exists()


@pytest.mark.skipif(os.name == "nt", reason="systemd unit verification requires Linux")
def test_installed_unit_passes_systemd_syntax_verification(tmp_path: Path) -> None:
    if not Path("/usr/bin/systemd-analyze").exists():
        pytest.skip("systemd-analyze is unavailable")
    result = subprocess.run(
        ["/usr/bin/systemd-analyze", "verify", str(REPO_ROOT / "deploy" / "alt-linux" / "systemd" / "alt-install-execution.service")],
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
