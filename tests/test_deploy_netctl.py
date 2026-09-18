from __future__ import annotations

import json
import os
from pathlib import Path
import runpy
import shutil
import subprocess
import sys

import pytest


ROOT = Path(__file__).resolve().parents[1]
VERIFIER = ROOT / "deploy" / "verify_netctl_systemd.py"
FIXTURES = ROOT / "tests" / "fixtures" / "systemd"


def _write_executable(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")
    path.chmod(0o755)


def _install_systemctl_double(bin_dir: Path) -> None:
    _write_executable(
        bin_dir / "systemctl",
        r'''#!/usr/bin/env bash
set -euo pipefail

printf '%s\n' "$*" >> "$SYSTEMCTL_CALLS"

case "${1:-}" in
  show)
    if [[ "$*" == *ActiveState* ]]; then
      if [[ "$*" == *inventory-endpoint-sync.timer* ]]; then
        [[ "$(cat "$ENDPOINT_TIMER_STATE")" == disabled ]] && printf '%s\n' inactive || printf '%s\n' active
      else
        [[ "$(cat "$ENDPOINT_SERVICE_STATE")" == stopped ]] && printf '%s\n' inactive || printf '%s\n' active
      fi
    else
      printf '%s\n' loaded
    fi
    ;;
  disable)
    if [[ "$*" == *inventory-endpoint-sync.timer* ]]; then
      printf '%s\n' disabled > "$ENDPOINT_TIMER_STATE"
    fi
    ;;
  stop)
    if [[ "$*" == *inventory-endpoint-sync.service* ]]; then
      printf '%s\n' stopped > "$ENDPOINT_SERVICE_STATE"
    fi
    ;;
  daemon-reload)
    touch "$SYSTEMD_RELOADED"
    ;;
  enable)
    shift
    [[ "${1:-}" == "--now" ]] && shift
    [[ -f "$SYSTEMD_RELOADED" ]] || exit 98
    printf '%s\n' "$@" >> "$SYSTEMD_ENABLED"
    ;;
esac
''',
    )


def _install_sudo_double(bin_dir: Path) -> None:
    _write_executable(
        bin_dir / "sudo",
        r'''#!/usr/bin/env bash
set -euo pipefail

while (($#)); do
  case "$1" in
    -S|-n)
      shift
      ;;
    -p|-u)
      shift 2
      ;;
    --)
      shift
      break
      ;;
    -*)
      shift
      ;;
    *)
      break
      ;;
  esac
done

command_name="$1"
shift
printf '%s' "$command_name" >> "$SUDO_CALLS"
printf ' %q' "$@" >> "$SUDO_CALLS"
printf '\n' >> "$SUDO_CALLS"

case "$command_name" in
  test)
    if [[ "$*" == "-x /usr/bin/nmap" ]]; then
      exit 0
    fi
    command test "$@"
    ;;
  /usr/local/sbin/verify-netctl-systemd)
    exit "${NETCTL_VERIFIER_EXIT_CODE:-0}"
    ;;
  rm|cp)
    if [[ "$*" == *app* ]] && [[ "${CHECK_ENDPOINT_QUIESCED:-0}" == 1 ]]; then
      [[ "$(cat "$ENDPOINT_TIMER_STATE")" == disabled ]] || exit 96
      [[ "$(cat "$ENDPOINT_SERVICE_STATE")" == stopped ]] || exit 97
    fi
    ;;
  systemctl)
    command systemctl "$@"
    ;;
esac
''',
    )


def _install_python_double(bin_dir: Path) -> None:
    _write_executable(
        bin_dir / "python3",
        "#!/usr/bin/env bash\nprintf '%s\\n' controlled-installer-value\n",
    )


def _run_installer(
    tmp_path: Path, *, verifier_exit_code: int = 0, endpoint_upgrade: bool = False
) -> tuple[subprocess.CompletedProcess[str], Path, Path, dict[str, str]]:
    bash = shutil.which("bash")
    if bash is None:
        pytest.skip("bash is required to exercise the installer")

    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    _install_systemctl_double(bin_dir)
    _install_sudo_double(bin_dir)
    _install_python_double(bin_dir)

    systemctl_calls = tmp_path / "systemctl-calls"
    enabled = tmp_path / "enabled-timers"
    sudo_calls = tmp_path / "sudo-calls"
    reloaded = tmp_path / "daemon-reloaded"
    timer_state = tmp_path / "endpoint-timer-state"
    service_state = tmp_path / "endpoint-service-state"
    timer_state.write_text("enabled\n")
    service_state.write_text("running\n")
    environment = os.environ | {
        "APP": str(tmp_path / "app"),
        "PATH": f"{bin_dir}:{os.environ['PATH']}",
        "SRC": str(ROOT),
        "SUDO_PASSWORD": "controlled-test-password",
        "SUDO_CALLS": str(sudo_calls),
        "SYSTEMCTL_CALLS": str(systemctl_calls),
        "SYSTEMD_ENABLED": str(enabled),
        "SYSTEMD_RELOADED": str(reloaded),
        "NETCTL_VERIFIER_EXIT_CODE": str(verifier_exit_code),
        "ENDPOINT_TIMER_STATE": str(timer_state),
        "ENDPOINT_SERVICE_STATE": str(service_state),
        "CHECK_ENDPOINT_QUIESCED": "1" if endpoint_upgrade else "0",
    }
    result = subprocess.run(
        [bash, str(ROOT / "deploy" / "install-openvpn-web.sh")],
        text=True,
        encoding="utf-8",
        errors="replace",
        capture_output=True,
        check=False,
        env=environment,
    )
    return result, bin_dir, systemctl_calls, environment


def test_endpoint_upgrade_quiesces_before_replacement_and_stays_off_on_netctl_failure(tmp_path):
    result, _, _, environment = _run_installer(tmp_path, verifier_exit_code=9, endpoint_upgrade=True)
    assert result.returncode == 9, result.stderr
    assert Path(environment["ENDPOINT_TIMER_STATE"]).read_text().strip() == "disabled"
    assert Path(environment["ENDPOINT_SERVICE_STATE"]).read_text().strip() == "stopped"
    assert not Path(environment["SYSTEMD_ENABLED"]).exists()


def _run_exec_start_parser(raw: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-B", str(VERIFIER), "--parse-exec-start"],
        text=True,
        encoding="utf-8",
        errors="replace",
        input=raw,
        capture_output=True,
        check=False,
    )


def _parse_exec_start(raw: str) -> list[str]:
    result = _run_exec_start_parser(raw)

    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


def _run_show_properties_parser(raw: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-B", str(VERIFIER), "--parse-show-properties"],
        text=True,
        encoding="utf-8",
        errors="replace",
        input=raw,
        capture_output=True,
        check=False,
    )


def _parse_show_properties(raw: str) -> dict[str, str]:
    result = _run_show_properties_parser(raw)

    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


def test_installer_enables_the_collection_and_recovery_timers_after_reload(tmp_path: Path) -> None:
    result, _bin_dir, calls_path, _environment = _run_installer(tmp_path)

    assert result.returncode == 0, result.stderr
    calls = calls_path.read_text(encoding="utf-8").splitlines()
    reload_index = calls.index("daemon-reload")
    collection_index = calls.index("enable --now netctl-collect.timer")
    recovery_index = calls.index("enable --now netctl-reconcile.timer")
    assert reload_index < collection_index
    assert reload_index < recovery_index
    assert "restart wg-quick@wg0.service" not in calls
    assert "restart openvpn-server@server.service" not in calls


def test_installer_migrates_netctl_schema_before_restarting_web(tmp_path: Path) -> None:
    """Read-only card requests after an upgrade must not see a pre-v23 schema."""
    result, _bin_dir, _calls_path, environment = _run_installer(tmp_path)

    assert result.returncode == 0, result.stderr
    sudo_calls = Path(environment["SUDO_CALLS"]).read_text(encoding="utf-8")
    assert "netctl.db" in sudo_calls
    installer = (ROOT / "deploy" / "install-openvpn-web.sh").read_text(encoding="utf-8")
    migration_index = installer.index("from netctl.db import connect")
    restart_index = installer.index("systemctl restart openvpn-web.service")
    assert migration_index < restart_index


def test_availability_unit_uses_only_fixed_netctl_argv() -> None:
    """Extra service arguments could turn recovery collection into an unsafe write path."""
    verifier = runpy.run_path(str(VERIFIER))

    assert verifier["EXPECTED_EXEC_STARTS"]["netctl-availability.service"] == [
        "/usr/local/sbin/netctl",
        "--json",
        "availability",
        "collect",
    ]


def test_inventory_sync_unit_uses_only_worker_entrypoint() -> None:
    """The timer must run only the isolated identifier-sync worker."""
    verifier = runpy.run_path(str(VERIFIER))

    assert verifier["EXPECTED_EXEC_STARTS"]["inventory-netctl-sync.service"] == [
        "/opt/openvpn-web/.venv/bin/python",
        "-m",
        "app.inventory.netctl_sync",
    ]


def test_inventory_sync_units_apply_the_worker_hardening_contract() -> None:
    """The worker needs the existing narrow sudo boundary, not a new privilege path."""
    service = (ROOT / "deploy" / "inventory-netctl-sync.service").read_text(encoding="utf-8")
    timer = (ROOT / "deploy" / "inventory-netctl-sync.timer").read_text(encoding="utf-8")

    for property_line in (
        "User=openvpn-web",
        "Group=openvpn-web",
        "WorkingDirectory=/opt/openvpn-web",
        "EnvironmentFile=/etc/openvpn-web/openvpn-web.env",
        "NoNewPrivileges=false",
        "PrivateTmp=true",
        "ProtectHome=true",
        "TimeoutStartSec=2min",
    ):
        assert property_line in service
    assert "NoNewPrivileges=true" not in service
    assert "OnCalendar=*-*-* *:01/5:00" in timer
    assert "Persistent=true" in timer
    assert "Unit=inventory-netctl-sync.service" in timer


def test_inventory_worker_uses_existing_non_root_netctl_sudo_boundary(monkeypatch) -> None:
    """Changing the worker's snapshot read must retain its authorized sudo argv."""
    import app.config as config
    from app.inventory.netctl_sync import read_current_snapshot
    from app.netctl_client import run_netctl

    calls: list[list[str]] = []

    def fake_run(command, **kwargs):
        calls.append(command)
        return subprocess.CompletedProcess(
            command,
            0,
            json.dumps(
                {
                    "snapshot": {"snapshot_id": 1, "generated_at": "2026-09-18T00:00:00+00:00", "stale": False},
                    "pagination": {"page": 1, "total": 0, "limit": 250, "pages": 0},
                    "hosts": [],
                }
            ),
            "",
        )

    monkeypatch.setenv("NETCTL_PATH", "/usr/local/sbin/netctl")
    monkeypatch.setenv("NETCTL_USE_SUDO", "1")
    monkeypatch.setenv("NETCTL_SUDO_USER", "netctl")
    config.reset_settings_cache()
    monkeypatch.setattr("app.netctl_client.subprocess.run", fake_run)

    try:
        snapshot = read_current_snapshot(run_netctl)
    finally:
        config.reset_settings_cache()

    assert snapshot.snapshot_id == 1
    assert calls == [
        [
            "sudo",
            "-n",
            "-u",
            "netctl",
            "/usr/local/sbin/netctl",
            "--json",
            "hosts",
            "list",
            "--status=current",
            "--page",
            "1",
            "--limit",
            "250",
        ]
    ]


def test_installer_enables_inventory_sync_after_verification(tmp_path: Path) -> None:
    """An unverified inventory worker timer must never be scheduled."""
    result, _bin_dir, calls_path, environment = _run_installer(tmp_path)

    assert result.returncode == 0, result.stderr
    calls = calls_path.read_text(encoding="utf-8").splitlines()
    sudo_calls = Path(environment["SUDO_CALLS"]).read_text(encoding="utf-8").splitlines()
    verification_index = next(
        index
        for index, call in enumerate(sudo_calls)
        if call.startswith("/usr/local/sbin/verify-netctl-systemd")
    )
    inventory_enable = "enable --now inventory-netctl-sync.timer"
    assert calls.index("daemon-reload") < calls.index(inventory_enable)
    assert verification_index < sudo_calls.index(f"systemctl {inventory_enable}")


@pytest.mark.parametrize(
    "unit_name",
    ("netctl-collect.service", "netctl-availability.service"),
)
def test_active_probe_units_grant_raw_icmp_without_relaxing_hardening(unit_name: str) -> None:
    unit_text = (ROOT / "deploy" / unit_name).read_text(encoding="utf-8")

    assert "NoNewPrivileges=true" in unit_text
    assert "AmbientCapabilities=CAP_NET_RAW" in unit_text


def test_installer_enables_availability_timer_after_systemd_verification(tmp_path: Path) -> None:
    """Enabling an unverified recovery timer could schedule malformed systemd units."""
    result, _bin_dir, calls_path, environment = _run_installer(tmp_path)

    assert result.returncode == 0, result.stderr
    calls = calls_path.read_text(encoding="utf-8").splitlines()
    sudo_calls = Path(environment["SUDO_CALLS"]).read_text(encoding="utf-8").splitlines()
    verification_index = next(
        index
        for index, call in enumerate(sudo_calls)
        if call.startswith("/usr/local/sbin/verify-netctl-systemd")
    )
    availability_enable = "systemctl enable --now netctl-availability.timer"
    assert "enable --now netctl-availability.timer" in calls
    assert verification_index < sudo_calls.index(availability_enable)


def test_installer_verifies_units_after_reload_before_enabling_timers(tmp_path: Path) -> None:
    result, _bin_dir, _systemctl_calls_path, environment = _run_installer(tmp_path)

    assert result.returncode == 0, result.stderr
    calls = Path(environment["SUDO_CALLS"]).read_text(encoding="utf-8").splitlines()
    verification_index = next(
        index for index, call in enumerate(calls) if call.startswith("/usr/local/sbin/verify-netctl-systemd")
    )
    assert calls.index("systemctl daemon-reload") < verification_index
    assert verification_index < calls.index("systemctl enable --now netctl-collect.timer")
    assert verification_index < calls.index("systemctl enable --now netctl-reconcile.timer")


def test_installer_reports_a_no_systemd_verification_skip_and_enables_timers(tmp_path: Path) -> None:
    result, _bin_dir, _systemctl_calls_path, environment = _run_installer(tmp_path, verifier_exit_code=77)

    assert result.returncode == 0, result.stderr
    assert "netctl systemd verification skipped" in result.stdout
    enabled_timers = Path(environment["SYSTEMD_ENABLED"]).read_text(encoding="utf-8").splitlines()
    assert enabled_timers.index("netctl-collect.timer") < enabled_timers.index("netctl-reconcile.timer")
    assert "inventory-netctl-sync.timer" not in enabled_timers


def test_installer_does_not_enable_timers_after_verification_failure(tmp_path: Path) -> None:
    result, _bin_dir, _systemctl_calls_path, environment = _run_installer(tmp_path, verifier_exit_code=9)

    assert result.returncode == 9
    assert not Path(environment["SYSTEMD_ENABLED"]).exists()


@pytest.mark.parametrize(
    ("fixture_name", "expected"),
    [
        (
            "netctl-collect.execstart",
            ["/usr/local/sbin/netctl", "--json", "collect", "all", "--reconcile"],
        ),
        ("netctl-reconcile.execstart", ["/usr/local/sbin/netctl", "--json", "reconcile"]),
    ],
)
def test_exec_start_parser_reads_captured_systemctl_show_output(
    fixture_name: str, expected: list[str]
) -> None:
    raw = (FIXTURES / fixture_name).read_text(encoding="utf-8")

    assert _parse_exec_start(raw) == expected


def test_exec_start_parser_rejects_multiple_serialized_commands() -> None:
    raw = (FIXTURES / "netctl-reconcile-multiple.execstart").read_text(encoding="utf-8")

    result = _run_exec_start_parser(raw)

    assert result.returncode == 2
    assert "exactly one ExecStart command" in result.stderr


def test_inventory_sync_property_parser_reads_captured_environment_and_timeout() -> None:
    """Loaded systemd output must preserve the worker's environment and timeout boundary."""
    raw = (FIXTURES / "inventory-netctl-sync.properties").read_text(encoding="utf-8")
    verifier = runpy.run_path(str(VERIFIER))

    properties = _parse_show_properties(raw)
    expected = verifier["EXPECTED_PROPERTIES"]["inventory-netctl-sync.service"]
    assert properties["EnvironmentFiles"] == "/etc/openvpn-web/openvpn-web.env (ignore_errors=no)"
    assert properties["TimeoutStartUSec"] == "2min"
    assert verifier["property_matches"]("EnvironmentFiles", properties["EnvironmentFiles"], expected["EnvironmentFiles"])
    assert verifier["property_matches"]("TimeoutStartUSec", properties["TimeoutStartUSec"], expected["TimeoutStartUSec"])
    assert expected["NoNewPrivileges"] == "no"


def test_systemd_verifier_skips_cleanly_without_linux_systemd() -> None:
    if sys.platform == "linux" and Path("/run/systemd/system").is_dir():
        pytest.skip("this host can run the real systemd verifier")

    result = subprocess.run(
        [sys.executable, str(VERIFIER)],
        text=True,
        encoding="utf-8",
        errors="replace",
        capture_output=True,
        check=False,
    )

    assert result.returncode == 77
    assert "Linux host with a running systemd manager" in result.stderr
