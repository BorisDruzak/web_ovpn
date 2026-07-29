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


def _environment(tmp_path: Path, *, listener: str = "", **overrides: str) -> dict[str, str]:
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    command_log = tmp_path / "commands.log"
    service_state = tmp_path / "service-state"
    service_state.write_text(
        overrides.get("INSTALLER_SERVICE_INITIAL_STATE", "disabled inactive") + "\n",
        encoding="utf-8",
    )
    _fake_command(
        fake_bin,
        "systemctl",
        "printf '%s\\n' \"$*\" >> \"${INSTALLER_COMMAND_LOG:?}\"\n"
        "action=${1:-}\n"
        "if [[ ${INSTALLER_SYSTEMCTL_FAIL_ONCE:-} == \"$action\" && ! -e ${INSTALLER_SYSTEMCTL_FAIL_MARKER:?} ]]; then\n"
        "  : > \"${INSTALLER_SYSTEMCTL_FAIL_MARKER}\"\n"
        "  exit 91\n"
        "fi\n"
        "case \"$action\" in\n"
        "  is-enabled) read -r enabled _ < \"${INSTALLER_SERVICE_STATE:?}\"; [[ $enabled == enabled ]] ;;\n"
        "  is-active) read -r _ active < \"${INSTALLER_SERVICE_STATE:?}\"; [[ $active == active ]] ;;\n"
        "  daemon-reload) exit 0 ;;\n"
        "  enable) printf 'enabled active\\n' > \"${INSTALLER_SERVICE_STATE:?}\" ;;\n"
        "  disable) printf 'disabled inactive\\n' > \"${INSTALLER_SERVICE_STATE:?}\" ;;\n"
        "  start) read -r enabled _ < \"${INSTALLER_SERVICE_STATE:?}\"; printf '%s active\\n' \"$enabled\" > \"${INSTALLER_SERVICE_STATE:?}\" ;;\n"
        "  stop) read -r enabled _ < \"${INSTALLER_SERVICE_STATE:?}\"; printf '%s inactive\\n' \"$enabled\" > \"${INSTALLER_SERVICE_STATE:?}\" ;;\n"
        "  *) exit 90 ;;\n"
        "esac\n",
    )
    _fake_command(fake_bin, "ss", "printf '%s' \"${INSTALLER_SS_OUTPUT:-}\"\n")
    _fake_command(
        fake_bin,
        "curl",
        "if [[ ${INSTALLER_HEALTH_FAIL:-0} == 1 ]]; then\n"
        "  printf '%s\\n' '{\"schema_version\":1,\"service\":\"alt-install-execution\",\"status\":\"starting\"}'\n"
        "else\n"
        "  printf '%s\\n' '{\"schema_version\":1,\"service\":\"alt-install-execution\",\"status\":\"ok\"}'\n"
        "fi\n",
    )
    environment = os.environ.copy()
    environment.update(
        {
            "PATH": f"{fake_bin}{os.pathsep}{environment['PATH']}",
            "INSTALLER_COMMAND_LOG": str(command_log),
            "INSTALLER_SERVICE_STATE": str(service_state),
            "INSTALLER_SS_OUTPUT": listener,
            "INSTALLER_SYSTEMCTL_FAIL_MARKER": str(tmp_path / "systemctl-failed"),
        }
    )
    environment.update(overrides)
    return environment


def _run(tmp_path: Path, *, listener: str = "", **overrides: str) -> subprocess.CompletedProcess[str]:
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
        env=_environment(tmp_path, listener=listener, **overrides),
        check=False,
    )


def _run_active_restore(tmp_path: Path) -> subprocess.CompletedProcess[str]:
    root = tmp_path / "restore-root"
    command = (
        "set -Eeuo pipefail; "
        f"source {INSTALLER.as_posix()!r}; "
        f"INSTALL_EXECUTION_CURRENT={str(root / 'current')!r}; "
        f"INSTALL_EXECUTION_UNIT_PATH={str(root / 'unit')!r}; "
        f"INSTALL_EXECUTION_TRANSACTION_DIR={str(root / 'transaction')!r}; "
        f"INSTALL_EXECUTION_RELEASE_PATH={str(root / 'release')!r}; "
        "INSTALL_EXECUTION_OLD_CURRENT_TARGET=; "
        "INSTALL_EXECUTION_HAD_UNIT=0; "
        "INSTALL_EXECUTION_WAS_ENABLED=1; "
        "INSTALL_EXECUTION_WAS_ACTIVE=1; "
        "INSTALL_EXECUTION_TRANSACTION_ACTIVE=1; "
        "install_execution_api_restore_activation"
    )
    return subprocess.run(
        [BASH, "-c", command],
        text=True,
        capture_output=True,
        cwd=REPO_ROOT,
        env=_environment(tmp_path),
        check=False,
    )


@pytest.mark.skipif(BASH is None, reason="rollback command test requires Bash")
def test_active_rollback_stops_new_service_before_starting_restored_unit(
    tmp_path: Path,
) -> None:
    result = _run_active_restore(tmp_path)

    assert result.returncode == 0, result.stderr
    commands = (tmp_path / "commands.log").read_text(encoding="utf-8").splitlines()
    stop = commands.index("stop alt-install-execution.service")
    start = commands.index("start alt-install-execution.service")
    assert stop < start


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


@pytest.mark.skipif(os.name == "nt" or BASH is None, reason="production installer test requires Linux Bash utilities")
@pytest.mark.parametrize("listener", (
    "LISTEN 0 128 0.0.0.0:18092 0.0.0.0:*\\n",
    "LISTEN 0 128 [::]:18092 [::]:*\\n",
))
def test_installer_refuses_wildcard_v2_listener(tmp_path: Path, listener: str) -> None:
    result = _run(tmp_path, listener=listener)

    assert result.returncode != 0
    assert "Listener already occupies 192.168.100.17:18092" in result.stderr
    assert not (tmp_path / "host-root" / "opt" / "alt-install-execution-api").exists()


def _seed_prior_v2_runtime(tmp_path: Path) -> tuple[Path, bytes, str]:
    root = tmp_path / "host-root"
    old_release = root / "opt" / "alt-install-execution-api" / "releases" / "old"
    old_release.mkdir(parents=True)
    (old_release / "marker").write_text("old\\n", encoding="utf-8")
    current = root / "opt" / "alt-install-execution-api" / "current"
    current.symlink_to(old_release)
    unit = root / "etc" / "systemd" / "system" / "alt-install-execution.service"
    unit.parent.mkdir(parents=True)
    unit.write_bytes(b"[Service]\\nExecStart=/old\\n")
    return current, unit.read_bytes(), str(old_release)


@pytest.mark.skipif(os.name == "nt" or BASH is None, reason="production installer test requires Linux Bash utilities")
@pytest.mark.parametrize(
    ("overrides", "expected_error"),
    (
        ({"INSTALLER_SYSTEMCTL_FAIL_ONCE": "daemon-reload"}, "daemon reload"),
        ({"INSTALLER_SYSTEMCTL_FAIL_ONCE": "enable"}, "activation"),
        ({"INSTALLER_HEALTH_FAIL": "1"}, "TLS health"),
    ),
)
def test_activation_failure_restores_preexisting_v2_runtime(
    tmp_path: Path, overrides: dict[str, str], expected_error: str,
) -> None:
    current, old_unit, old_target = _seed_prior_v2_runtime(tmp_path)

    result = _run(
        tmp_path,
        INSTALLER_SERVICE_INITIAL_STATE="enabled active",
        **overrides,
    )

    assert result.returncode != 0
    assert expected_error in result.stderr
    assert str(current.resolve()) == old_target
    assert (tmp_path / "host-root" / "etc" / "systemd" / "system" / "alt-install-execution.service").read_bytes() == old_unit
    assert (tmp_path / "service-state").read_text(encoding="utf-8") == "enabled active\\n"


@pytest.mark.skipif(os.name == "nt" or BASH is None, reason="production installer test requires Linux Bash utilities")
@pytest.mark.parametrize(
    "overrides",
    (
        {"INSTALLER_SYSTEMCTL_FAIL_ONCE": "daemon-reload"},
        {"INSTALLER_SYSTEMCTL_FAIL_ONCE": "enable"},
        {"INSTALLER_HEALTH_FAIL": "1"},
    ),
)
def test_activation_failure_restores_clean_host_absence(
    tmp_path: Path, overrides: dict[str, str],
) -> None:
    result = _run(tmp_path, **overrides)

    assert result.returncode != 0
    root = tmp_path / "host-root"
    assert not (root / "opt" / "alt-install-execution-api" / "current").exists()
    assert not (root / "etc" / "systemd" / "system" / "alt-install-execution.service").exists()
    assert (tmp_path / "service-state").read_text(encoding="utf-8") == "disabled inactive\\n"


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
