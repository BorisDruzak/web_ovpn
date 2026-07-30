from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import sys

import pytest


REPO_ROOT = Path(__file__).resolve().parents[2]
INSTALLER = REPO_ROOT / "deploy" / "alt-linux" / "install-install-execution-api.sh"
BASH = shutil.which("bash")
MANAGED_PROCESS_ARGUMENTS = (
    "/usr/bin/python3",
    "/opt/alt-install-execution-api/current/api/install_execution_server.py",
    "--listen-address",
    "192.168.100.17",
    "--listen-port",
    "18092",
    "--credential-key",
    "/run/credentials/alt-install-execution.service/execution-tls-key",
)


def _fake_command(directory: Path, name: str, body: str) -> None:
    path = directory / name
    path.write_text("#!/bin/bash\nset -Eeuo pipefail\n" + body, encoding="utf-8")
    path.chmod(0o755)


def _seed_process_identity(
    root: Path,
    *,
    main_pid: str,
    arguments: tuple[str, ...] | None = MANAGED_PROCESS_ARGUMENTS,
    executable: bool = True,
) -> None:
    python = root / "usr" / "bin" / "python3"
    python.parent.mkdir(parents=True, exist_ok=True)
    python.write_text("test interpreter\n", encoding="utf-8")
    process = root / "proc" / main_pid
    process.mkdir(parents=True, exist_ok=True)
    if executable:
        (process / "exe").symlink_to(os.path.relpath(python, start=process))
    if arguments is not None:
        (process / "cmdline").write_bytes(
            b"\0".join(item.encode("utf-8") for item in arguments) + b"\0"
        )


def _environment(tmp_path: Path, *, listener: str = "", **overrides: str) -> dict[str, str]:
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir(exist_ok=True)
    command_log = tmp_path / "commands.log"
    service_state = tmp_path / "service-state"
    service_state.write_text(
        overrides.get("INSTALLER_SERVICE_INITIAL_STATE", "disabled inactive") + "\n",
        encoding="utf-8",
        newline="\n",
    )
    _fake_command(
        fake_bin,
        "systemctl",
        "printf '%s\\n' \"$*\" >> \"${INSTALLER_COMMAND_LOG:?}\"\n"
        "action=${1:-}\n"
        "if [[ ${INSTALLER_SYSTEMCTL_FAIL_ALWAYS:-} == \"$action\" ]]; then\n"
        "  exit 92\n"
        "fi\n"
        "if [[ ${INSTALLER_SYSTEMCTL_FAIL_ONCE:-} == \"$action\" && ! -e ${INSTALLER_SYSTEMCTL_FAIL_MARKER:?} ]]; then\n"
        "  : > \"${INSTALLER_SYSTEMCTL_FAIL_MARKER}\"\n"
        "  exit 91\n"
        "fi\n"
        "case \"$action\" in\n"
        "  is-enabled) read -r enabled _ < \"${INSTALLER_SERVICE_STATE:?}\"; [[ $enabled == enabled ]] ;;\n"
        "  is-active) read -r _ active < \"${INSTALLER_SERVICE_STATE:?}\"; [[ $active == active ]] ;;\n"
        "  show)\n"
        "    [[ ${3:-} == --value ]] || exit 90\n"
        "    case \"${2:-}\" in\n"
        "      --property=MainPID) printf '%s\\n' \"${INSTALLER_SERVICE_MAIN_PID:-4242}\" ;;\n"
        "      --property=FragmentPath) printf '%s\\n' \"${INSTALLER_SERVICE_FRAGMENT_PATH:-}\" ;;\n"
        "      --property=DropInPaths) printf '%s\\n' \"${INSTALLER_SERVICE_DROP_IN_PATHS:-}\" ;;\n"
        "      --property=NeedDaemonReload) printf '%s\\n' \"${INSTALLER_SERVICE_NEED_DAEMON_RELOAD:-no}\" ;;\n"
        "      *) exit 90 ;;\n"
        "    esac\n"
        "    ;;\n"
        "  daemon-reload) exit 0 ;;\n"
        "  enable)\n"
        "    read -r _ active < \"${INSTALLER_SERVICE_STATE:?}\"\n"
        "    [[ ${2:-} == --now ]] && active=active\n"
        "    printf 'enabled %s\\n' \"$active\" > \"${INSTALLER_SERVICE_STATE:?}\"\n"
        "    ;;\n"
        "  disable)\n"
        "    read -r _ active < \"${INSTALLER_SERVICE_STATE:?}\"\n"
        "    printf 'disabled %s\\n' \"$active\" > \"${INSTALLER_SERVICE_STATE:?}\"\n"
        "    ;;\n"
        "  start) read -r enabled _ < \"${INSTALLER_SERVICE_STATE:?}\"; printf '%s active\\n' \"$enabled\" > \"${INSTALLER_SERVICE_STATE:?}\" ;;\n"
        "  stop) read -r enabled _ < \"${INSTALLER_SERVICE_STATE:?}\"; printf '%s inactive\\n' \"$enabled\" > \"${INSTALLER_SERVICE_STATE:?}\" ;;\n"
        "  restart) read -r enabled _ < \"${INSTALLER_SERVICE_STATE:?}\"; printf '%s active\\n' \"$enabled\" > \"${INSTALLER_SERVICE_STATE:?}\" ;;\n"
        "  *) exit 90 ;;\n"
        "esac\n",
    )
    _fake_command(fake_bin, "ss", "printf '%s' \"${INSTALLER_SS_OUTPUT:-}\"\n")
    _fake_command(
        fake_bin,
        "curl",
        "attempts=0\n"
        "if [[ -f ${INSTALLER_HEALTH_ATTEMPTS:?} ]]; then\n"
        "  read -r attempts < \"${INSTALLER_HEALTH_ATTEMPTS:?}\"\n"
        "fi\n"
        "attempts=$((attempts + 1))\n"
        "printf '%s\\n' \"$attempts\" > \"${INSTALLER_HEALTH_ATTEMPTS:?}\"\n"
        "if (( attempts <= ${INSTALLER_HEALTH_CONNECT_FAILURES:-0} )); then\n"
        "  exit 7\n"
        "fi\n"
        "if [[ ${INSTALLER_HEALTH_FAIL:-0} == 1 ]]; then\n"
        "  printf '%s\\n' '{\"schema_version\":1,\"service\":\"alt-install-execution\",\"status\":\"starting\"}'\n"
        "else\n"
        "  printf '%s\\n' '{\"schema_version\":1,\"service\":\"alt-install-execution\",\"status\":\"ok\"}'\n"
        "fi\n",
    )
    _fake_command(
        fake_bin,
        "sleep",
        "printf 'sleep %s\\n' \"$*\" >> \"${INSTALLER_COMMAND_LOG:?}\"\n",
    )
    environment = os.environ.copy()
    environment.update(
        {
            "PATH": f"{fake_bin}{os.pathsep}{environment['PATH']}",
            "INSTALLER_COMMAND_LOG": str(command_log),
            "INSTALLER_HEALTH_ATTEMPTS": str(tmp_path / "health-attempts"),
            "INSTALLER_SERVICE_STATE": str(service_state),
            "INSTALLER_SS_OUTPUT": listener,
            "INSTALLER_SYSTEMCTL_FAIL_MARKER": str(tmp_path / "systemctl-failed"),
        }
    )
    environment.update(overrides)
    return environment


def _run(tmp_path: Path, *, listener: str = "", **overrides: str) -> subprocess.CompletedProcess[str]:
    root = tmp_path / "host-root"
    unit = (
        root
        / "etc"
        / "systemd"
        / "system"
        / "alt-install-execution.service"
    )
    if listener:
        _seed_process_identity(
            root,
            main_pid=overrides.get("INSTALLER_SERVICE_MAIN_PID", "4242"),
        )
    command = (
        "set -Eeuo pipefail; "
        f"source {INSTALLER.as_posix()!r}; "
        f"install_execution_api_main {root.as_posix()!r}"
    )
    environment_overrides = {
        "INSTALLER_SERVICE_FRAGMENT_PATH": unit.as_posix(),
        **overrides,
    }
    return subprocess.run(
        [BASH, "-c", command],
        text=True,
        capture_output=True,
        cwd=REPO_ROOT,
        env=_environment(
            tmp_path,
            listener=listener,
            **environment_overrides,
        ),
        check=False,
    )


def _run_active_restore(
    tmp_path: Path, **overrides: str,
) -> subprocess.CompletedProcess[str]:
    root = tmp_path / "restore-root"
    release = root / "releases" / "failed"
    transaction = root / "releases" / ".transaction-test"
    release.mkdir(parents=True)
    (release / "marker").write_text("failed release\n", encoding="utf-8")
    transaction.mkdir()
    command = (
        "set -Eeuo pipefail; "
        f"source {INSTALLER.as_posix()!r}; "
        f"INSTALL_EXECUTION_CURRENT={(root / 'current').as_posix()!r}; "
        f"INSTALL_EXECUTION_UNIT_PATH={(root / 'unit').as_posix()!r}; "
        f"INSTALL_EXECUTION_TRANSACTION_DIR={transaction.as_posix()!r}; "
        f"INSTALL_EXECUTION_RELEASE_PATH={release.as_posix()!r}; "
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
        env=_environment(tmp_path, **overrides),
        check=False,
    )


def _run_restore(
    tmp_path: Path,
    *,
    prior_runtime: bool,
    prior_unit: bool,
    was_enabled: bool,
    was_active: bool,
    fail_pointer: bool = False,
    fail_unit: bool = False,
    **overrides: str,
) -> subprocess.CompletedProcess[str]:
    root = tmp_path / "restore-root"
    old_release = root / "releases" / "old"
    failed_release = root / "releases" / "failed"
    transaction = root / "releases" / ".transaction-test"
    failed_release.mkdir(parents=True)
    transaction.mkdir()
    (failed_release / "marker").write_text("failed release\n", encoding="utf-8")
    (transaction / "marker").write_text("recovery\n", encoding="utf-8")
    current = root / "current"
    current.symlink_to(failed_release, target_is_directory=True)
    old_target = ""
    if prior_runtime:
        old_release.mkdir()
        (old_release / "marker").write_text("old release\n", encoding="utf-8")
        old_target = str(old_release)
    old_target_shell = Path(old_target).as_posix() if old_target else ""
    unit = root / "unit"
    unit.write_text("new unit\n", encoding="utf-8")
    unit_backup = transaction / "unit.backup"
    if prior_unit:
        unit_backup.write_text("old unit\n", encoding="utf-8")
    portable_atomic_overrides = ""
    if os.name == "nt":
        portable_atomic_overrides = (
            "install_execution_api_atomic_pointer() { "
            "python -c 'import os,sys; p=sys.argv[1]; t=sys.argv[2]; "
            "n=p+\".test-new\"; "
            "os.path.lexists(n) and os.unlink(n); "
            "os.symlink(t,n,target_is_directory=True); "
            "os.path.lexists(p) and os.unlink(p); os.replace(n,p)' "
            "\"$1\" \"$2\"; }; "
            "install_execution_api_atomic_regular_file() { "
            "cp -- \"$1\" \"$2\"; }; "
        )
    command = (
        "set -Eeuo pipefail; "
        f"source {INSTALLER.as_posix()!r}; "
        + portable_atomic_overrides
        + (
            "install_execution_api_atomic_pointer() { return 93; }; "
            if fail_pointer
            else ""
        )
        + (
            "install_execution_api_atomic_regular_file() { return 94; }; "
            if fail_unit
            else ""
        )
        + f"INSTALL_EXECUTION_CURRENT={current.as_posix()!r}; "
        + f"INSTALL_EXECUTION_UNIT_PATH={unit.as_posix()!r}; "
        + f"INSTALL_EXECUTION_TRANSACTION_DIR={transaction.as_posix()!r}; "
        + f"INSTALL_EXECUTION_RELEASE_PATH={failed_release.as_posix()!r}; "
        + f"INSTALL_EXECUTION_UNIT_BACKUP={unit_backup.as_posix()!r}; "
        + f"INSTALL_EXECUTION_OLD_CURRENT_TARGET={old_target_shell!r}; "
        + f"INSTALL_EXECUTION_HAD_UNIT={int(prior_unit)}; "
        + f"INSTALL_EXECUTION_WAS_ENABLED={int(was_enabled)}; "
        + f"INSTALL_EXECUTION_WAS_ACTIVE={int(was_active)}; "
        + "INSTALL_EXECUTION_TRANSACTION_ACTIVE=1; "
        + "install_execution_api_restore_activation"
    )
    initial_state = (
        f"{'enabled' if was_enabled else 'disabled'} "
        f"{'active' if was_active else 'inactive'}"
    )
    return subprocess.run(
        [BASH, "-c", command],
        text=True,
        capture_output=True,
        cwd=REPO_ROOT,
        env=_environment(
            tmp_path,
            INSTALLER_SERVICE_INITIAL_STATE=initial_state,
            **overrides,
        ),
        check=False,
    )


def _run_listener_admission(
    tmp_path: Path,
    *,
    listener: str,
    service_state: str = "enabled active",
    main_pid: str = "4242",
    health_fail: str = "0",
    unit_suffix: str = "",
    drop_in_exec_start: str | None = None,
    process_arguments: tuple[str, ...] | None = MANAGED_PROCESS_ARGUMENTS,
    process_executable: bool = True,
    daemon_reload_before_admission: bool = False,
) -> subprocess.CompletedProcess[str]:
    root = tmp_path / "listener-root"
    release = root / "opt" / "alt-install-execution-api" / "releases" / "old"
    release.mkdir(parents=True)
    current = release.parent.parent / "current"
    current.symlink_to(release, target_is_directory=True)
    unit = root / "etc" / "systemd" / "system" / "alt-install-execution.service"
    unit.parent.mkdir(parents=True)
    unit.write_text(
        (
            REPO_ROOT
            / "deploy"
            / "alt-linux"
            / "systemd"
            / "alt-install-execution.service"
        ).read_text(encoding="utf-8").replace("\r\n", "\n")
        + unit_suffix,
        encoding="utf-8",
        newline="\n",
    )
    drop_in_paths = ""
    if drop_in_exec_start is not None:
        drop_in = Path(f"{unit}.d") / "90-foreign-listener.conf"
        drop_in.parent.mkdir()
        drop_in.write_text(
            (
                "[Service]\n"
                "ExecStart=\n"
                f"ExecStart={drop_in_exec_start}\n"
            ),
            encoding="utf-8",
            newline="\n",
        )
        drop_in_paths = str(drop_in)
    ca = root / "etc" / "alt-deploy" / "install-execution-ca.pem"
    ca.parent.mkdir(parents=True)
    ca.write_text("test CA\n", encoding="utf-8")
    _seed_process_identity(
        root,
        main_pid=main_pid,
        arguments=process_arguments,
        executable=process_executable,
    )
    command = (
        "set -Eeuo pipefail; "
        f"source {INSTALLER.as_posix()!r}; "
        "python3() { \"${INSTALLER_TEST_PYTHON:?}\" \"$@\"; }; "
        "curl() { "
        "if [[ ${INSTALLER_HEALTH_FAIL:-0} == 1 ]]; then "
        "printf '%s\\n' "
        "'{\"schema_version\":1,\"service\":\"alt-install-execution\","
        "\"status\":\"starting\"}'; "
        "else printf '%s\\n' "
        "'{\"schema_version\":1,\"service\":\"alt-install-execution\","
        "\"status\":\"ok\"}'; fi; }; "
        + (
            "systemctl daemon-reload; "
            if daemon_reload_before_admission
            else ""
        )
        + f"install_execution_api_listener_allows_install {root.as_posix()!r} "
        f"{current.as_posix()!r} {unit.as_posix()!r}"
    )
    return subprocess.run(
        [BASH, "-c", command],
        text=True,
        capture_output=True,
        cwd=REPO_ROOT,
        env=_environment(
            tmp_path,
            listener=listener,
            INSTALLER_SERVICE_INITIAL_STATE=service_state,
            INSTALLER_SERVICE_MAIN_PID=main_pid,
            INSTALLER_SERVICE_FRAGMENT_PATH=unit.as_posix(),
            INSTALLER_SERVICE_DROP_IN_PATHS=Path(drop_in_paths).as_posix()
            if drop_in_paths
            else "",
            INSTALLER_HEALTH_FAIL=health_fail,
            INSTALLER_TEST_PYTHON=Path(sys.executable).as_posix(),
        ),
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


@pytest.mark.skipif(BASH is None, reason="rollback command test requires Bash")
def test_active_rollback_stop_failure_keeps_failed_release_recoverable(
    tmp_path: Path,
) -> None:
    result = _run_active_restore(
        tmp_path,
        INSTALLER_SYSTEMCTL_FAIL_ONCE="stop",
    )

    assert result.returncode != 0
    assert (
        tmp_path
        / "restore-root"
        / "releases"
        / "failed"
        / "marker"
    ).is_file()
    commands = (tmp_path / "commands.log").read_text(encoding="utf-8").splitlines()
    assert "stop alt-install-execution.service" in commands
    assert "start alt-install-execution.service" not in commands


@pytest.mark.skipif(BASH is None, reason="rollback command test requires Bash")
@pytest.mark.parametrize(
    ("failure", "restore_options", "overrides"),
    (
        (
            "service_stop",
            {"prior_runtime": True, "prior_unit": True, "was_enabled": True, "was_active": True},
            {"INSTALLER_SYSTEMCTL_FAIL_ALWAYS": "stop"},
        ),
        (
            "runtime_pointer_restore",
            {
                "prior_runtime": True,
                "prior_unit": True,
                "was_enabled": True,
                "was_active": True,
                "fail_pointer": True,
            },
            {},
        ),
        (
            "unit_restore",
            {
                "prior_runtime": True,
                "prior_unit": True,
                "was_enabled": True,
                "was_active": True,
                "fail_unit": True,
            },
            {},
        ),
        (
            "daemon_reload",
            {"prior_runtime": True, "prior_unit": True, "was_enabled": True, "was_active": True},
            {"INSTALLER_SYSTEMCTL_FAIL_ALWAYS": "daemon-reload"},
        ),
        (
            "enable_restore",
            {"prior_runtime": True, "prior_unit": True, "was_enabled": True, "was_active": True},
            {"INSTALLER_SYSTEMCTL_FAIL_ALWAYS": "enable"},
        ),
        (
            "disable_restore",
            {"prior_runtime": False, "prior_unit": False, "was_enabled": False, "was_active": False},
            {"INSTALLER_SYSTEMCTL_FAIL_ALWAYS": "disable"},
        ),
    ),
)
def test_rollback_prerequisite_failure_retains_recovery_state_and_never_restarts(
    tmp_path: Path,
    failure: str,
    restore_options: dict[str, bool],
    overrides: dict[str, str],
) -> None:
    result = _run_restore(tmp_path, **restore_options, **overrides)

    assert result.returncode != 0
    assert failure in result.stderr
    root = tmp_path / "restore-root"
    assert (root / "releases" / "failed" / "marker").is_file()
    assert (root / "releases" / ".transaction-test" / "marker").is_file()
    commands = (tmp_path / "commands.log").read_text(encoding="utf-8").splitlines()
    assert "start alt-install-execution.service" not in commands


@pytest.mark.skipif(BASH is None, reason="rollback command test requires Bash")
@pytest.mark.parametrize(
    ("prior_runtime", "prior_unit", "was_enabled", "was_active", "expected_state"),
    (
        (False, False, False, False, "disabled inactive\n"),
        (True, True, True, True, "enabled active\n"),
        (True, True, True, False, "enabled inactive\n"),
    ),
)
def test_rollback_restores_clean_active_and_inactive_host_semantics(
    tmp_path: Path,
    prior_runtime: bool,
    prior_unit: bool,
    was_enabled: bool,
    was_active: bool,
    expected_state: str,
) -> None:
    result = _run_restore(
        tmp_path,
        prior_runtime=prior_runtime,
        prior_unit=prior_unit,
        was_enabled=was_enabled,
        was_active=was_active,
    )

    assert result.returncode == 0, result.stderr
    root = tmp_path / "restore-root"
    assert not (root / "releases" / "failed").exists()
    assert not (root / "releases" / ".transaction-test").exists()
    if prior_runtime:
        assert (root / "current").resolve() == root / "releases" / "old"
    else:
        assert not (root / "current").exists()
    if prior_unit:
        assert (root / "unit").read_text(encoding="utf-8") == "old unit\n"
    else:
        assert not (root / "unit").exists()
    assert (tmp_path / "service-state").read_text(encoding="utf-8") == expected_state
    commands = (tmp_path / "commands.log").read_text(encoding="utf-8").splitlines()
    assert commands[0] == "stop alt-install-execution.service"
    if was_active:
        assert commands[-1] == "start alt-install-execution.service"
    else:
        assert "start alt-install-execution.service" not in commands


@pytest.mark.skipif(BASH is None, reason="listener ownership test requires Bash")
def test_installer_admits_only_healthy_listener_owned_by_managed_v2_service(
    tmp_path: Path,
) -> None:
    result = _run_listener_admission(
        tmp_path,
        listener=(
            'LISTEN 0 128 192.168.100.17:18092 0.0.0.0:* '
            'users:(("python3",pid=4242,fd=3))\n'
        ),
    )

    assert result.returncode == 0, result.stderr


@pytest.mark.skipif(BASH is None, reason="listener ownership test requires Bash")
def test_installer_rejects_foreign_override_process_after_unit_restore_and_reload(
    tmp_path: Path,
) -> None:
    foreign_arguments = (
        "/usr/bin/python3",
        "/opt/foreign/health-compatible.py",
        *MANAGED_PROCESS_ARGUMENTS[2:],
    )

    result = _run_listener_admission(
        tmp_path,
        listener=(
            'LISTEN 0 128 192.168.100.17:18092 0.0.0.0:* '
            'users:(("python3",pid=4242,fd=3))\n'
        ),
        process_arguments=foreign_arguments,
        daemon_reload_before_admission=True,
    )

    assert result.returncode != 0
    assert "process is not the canonical managed invocation" in result.stderr
    commands = (tmp_path / "commands.log").read_text(encoding="utf-8").splitlines()
    assert "daemon-reload" in commands


@pytest.mark.skipif(BASH is None, reason="listener ownership test requires Bash")
@pytest.mark.parametrize(
    ("process_arguments", "process_executable"),
    (
        (None, True),
        (MANAGED_PROCESS_ARGUMENTS, False),
        ((*MANAGED_PROCESS_ARGUMENTS, "--foreign-extra"), True),
    ),
)
def test_installer_rejects_unreadable_or_ambiguous_managed_process_identity(
    tmp_path: Path,
    process_arguments: tuple[str, ...] | None,
    process_executable: bool,
) -> None:
    result = _run_listener_admission(
        tmp_path,
        listener=(
            'LISTEN 0 128 192.168.100.17:18092 0.0.0.0:* '
            'users:(("python3",pid=4242,fd=3))\n'
        ),
        process_arguments=process_arguments,
        process_executable=process_executable,
    )

    assert result.returncode != 0
    assert "process is not the canonical managed invocation" in result.stderr


@pytest.mark.skipif(BASH is None, reason="listener ownership test requires Bash")
def test_installer_rejects_foreign_exec_start_drop_in_on_managed_v2_unit(
    tmp_path: Path,
) -> None:
    result = _run_listener_admission(
        tmp_path,
        listener=(
            'LISTEN 0 128 192.168.100.17:18092 0.0.0.0:* '
            'users:(("python3",pid=4242,fd=3))\n'
        ),
        drop_in_exec_start=(
            "/usr/bin/python3 /opt/foreign/health-compatible.py "
            "--listen-address 192.168.100.17 --listen-port 18092"
        ),
    )

    assert result.returncode != 0
    assert "unit is not the managed V2 unit" in result.stderr


@pytest.mark.skipif(BASH is None, reason="listener ownership test requires Bash")
def test_installer_rejects_duplicate_foreign_exec_start_in_managed_unit_file(
    tmp_path: Path,
) -> None:
    result = _run_listener_admission(
        tmp_path,
        listener=(
            'LISTEN 0 128 192.168.100.17:18092 0.0.0.0:* '
            'users:(("python3",pid=4242,fd=3))\n'
        ),
        unit_suffix=(
            "\n[Service]\n"
            "ExecStart=\n"
            "ExecStart=/usr/bin/python3 "
            "/opt/foreign/health-compatible.py "
            "--listen-address 192.168.100.17 --listen-port 18092\n"
        ),
    )

    assert result.returncode != 0
    assert "unit is not the managed V2 unit" in result.stderr


@pytest.mark.skipif(BASH is None, reason="listener ownership test requires Bash")
@pytest.mark.parametrize(
    ("listener", "service_state", "main_pid", "health_fail"),
    (
        (
            'LISTEN 0 128 192.168.100.17:18092 0.0.0.0:* '
            'users:(("python3",pid=7777,fd=3))\n',
            "enabled active",
            "4242",
            "0",
        ),
        (
            'LISTEN 0 128 192.168.100.17:18092 0.0.0.0:* '
            'users:(("python3",pid=4242,fd=3))\n',
            "enabled inactive",
            "4242",
            "0",
        ),
        (
            'LISTEN 0 128 192.168.100.17:18092 0.0.0.0:* '
            'users:(("python3",pid=4242,fd=3))\n',
            "enabled active",
            "4242",
            "1",
        ),
        (
            'LISTEN 0 128 0.0.0.0:18092 0.0.0.0:* '
            'users:(("python3",pid=4242,fd=3))\n',
            "enabled active",
            "4242",
            "0",
        ),
    ),
)
def test_installer_rejects_unverified_or_foreign_v2_listener(
    tmp_path: Path,
    listener: str,
    service_state: str,
    main_pid: str,
    health_fail: str,
) -> None:
    result = _run_listener_admission(
        tmp_path,
        listener=listener,
        service_state=service_state,
        main_pid=main_pid,
        health_fail=health_fail,
    )

    assert result.returncode != 0


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
    assert "enable alt-install-execution.service" in commands
    assert "restart alt-install-execution.service" in commands


@pytest.mark.skipif(os.name == "nt" or BASH is None, reason="production installer test requires Linux Bash utilities")
def test_installer_waits_for_delayed_v2_tls_readiness(
    tmp_path: Path,
) -> None:
    result = _run(tmp_path, INSTALLER_HEALTH_CONNECT_FAILURES="2")

    assert result.returncode == 0, result.stderr
    assert (tmp_path / "health-attempts").read_text(encoding="utf-8") == "3\n"
    assert (tmp_path / "service-state").read_text(encoding="utf-8") == "enabled active\n"


@pytest.mark.skipif(os.name == "nt" or BASH is None, reason="production installer test requires Linux Bash utilities")
def test_installer_readiness_timeout_restores_preexisting_v2_runtime(
    tmp_path: Path,
) -> None:
    current, old_unit, old_target = _seed_prior_v2_runtime(tmp_path)
    root = tmp_path / "host-root"
    v1 = root / "opt" / "alt-install-session-api" / "v1-sentinel"
    v1.parent.mkdir(parents=True)
    v1.write_text("unchanged\n", encoding="utf-8")

    result = _run(
        tmp_path,
        INSTALLER_HEALTH_CONNECT_FAILURES="100",
        INSTALLER_SERVICE_INITIAL_STATE="enabled active",
    )

    assert result.returncode != 0
    assert "readiness" in result.stderr.lower()
    assert (tmp_path / "health-attempts").read_text(encoding="utf-8") == "10\n"
    assert str(current.resolve()) == old_target
    assert (
        root / "etc" / "systemd" / "system" / "alt-install-execution.service"
    ).read_bytes() == old_unit
    assert {
        path.name
        for path in (
            root / "opt" / "alt-install-execution-api" / "releases"
        ).iterdir()
    } == {"old"}
    assert (tmp_path / "service-state").read_text(encoding="utf-8") == "enabled active\n"
    assert v1.read_text(encoding="utf-8") == "unchanged\n"


@pytest.mark.skipif(os.name == "nt" or BASH is None, reason="production installer test requires Linux Bash utilities")
def test_installer_verified_rerun_restarts_owned_v2_service_on_new_release(
    tmp_path: Path,
) -> None:
    current, _old_unit, old_target = _seed_prior_v2_runtime(tmp_path)
    unit = (
        tmp_path
        / "host-root"
        / "etc"
        / "systemd"
        / "system"
        / "alt-install-execution.service"
    )
    unit.write_bytes(
        (
            REPO_ROOT
            / "deploy"
            / "alt-linux"
            / "systemd"
            / "alt-install-execution.service"
        ).read_bytes()
    )

    result = _run(
        tmp_path,
        listener=(
            'LISTEN 0 128 192.168.100.17:18092 0.0.0.0:* '
            'users:(("python3",pid=4242,fd=3))\n'
        ),
        INSTALLER_SERVICE_INITIAL_STATE="enabled active",
    )

    assert result.returncode == 0, result.stderr
    assert str(current.resolve()) != old_target
    assert Path(old_target).is_dir()
    commands = (tmp_path / "commands.log").read_text(encoding="utf-8").splitlines()
    assert "restart alt-install-execution.service" in commands


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
    assert (tmp_path / "service-state").read_text(encoding="utf-8") == "enabled active\n"


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
    assert (tmp_path / "service-state").read_text(encoding="utf-8") == "disabled inactive\n"


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
