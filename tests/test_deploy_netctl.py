from __future__ import annotations

from pathlib import Path
import os
import shutil
import subprocess

import pytest


ROOT = Path(__file__).resolve().parents[1]


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
  daemon-reload)
    touch "$SYSTEMD_RELOADED"
    ;;
  enable)
    shift
    [[ "${1:-}" == "--now" ]] && shift
    for unit in "$@"; do
      [[ -f "$SYSTEMD_UNIT_DIR/$unit" ]] || exit 97
      [[ -f "$SYSTEMD_RELOADED" ]] || exit 98
      printf '%s\n' "$unit" >> "$SYSTEMD_ENABLED"
    done
    ;;
  show)
    shift
    property="${1#--property=}"
    [[ "$1" == --property=* ]] && shift
    [[ "${1:-}" == "--value" ]] && shift
    unit="$1"
    awk -F= -v property="$property" '$1 == property { print substr($0, index($0, "=") + 1) }' "$SYSTEMD_UNIT_DIR/$unit"
    ;;
  is-enabled)
    grep -Fx "$2" "$SYSTEMD_ENABLED"
    ;;
  status)
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
    command test "$@"
    ;;
  install)
    destination="${@: -1}"
    if [[ "$destination" == /etc/systemd/system/* ]]; then
      source="${@: -2:1}"
      cp "$source" "$SYSTEMD_UNIT_DIR/${destination##*/}"
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
    tmp_path: Path,
) -> tuple[subprocess.CompletedProcess[str], Path, Path, dict[str, str]]:
    bash = shutil.which("bash")
    if bash is None:
        pytest.skip("bash is required to exercise the installer")

    bin_dir = tmp_path / "bin"
    unit_dir = tmp_path / "systemd-units"
    bin_dir.mkdir()
    unit_dir.mkdir()
    _install_systemctl_double(bin_dir)
    _install_sudo_double(bin_dir)
    _install_python_double(bin_dir)

    systemctl_calls = tmp_path / "systemctl-calls"
    enabled = tmp_path / "enabled-timers"
    sudo_calls = tmp_path / "sudo-calls"
    reloaded = tmp_path / "daemon-reloaded"
    environment = os.environ | {
        "APP": str(tmp_path / "app"),
        "PATH": f"{bin_dir}:{os.environ['PATH']}",
        "SRC": str(ROOT),
        "SUDO_PASSWORD": "controlled-test-password",
        "SUDO_CALLS": str(sudo_calls),
        "SYSTEMCTL_CALLS": str(systemctl_calls),
        "SYSTEMD_ENABLED": str(enabled),
        "SYSTEMD_RELOADED": str(reloaded),
        "SYSTEMD_UNIT_DIR": str(unit_dir),
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


def _systemctl(bin_dir: Path, environment: dict[str, str], *args: str) -> str:
    bash = shutil.which("bash")
    assert bash is not None
    result = subprocess.run(
        [bash, str(bin_dir / "systemctl"), *args],
        text=True,
        encoding="utf-8",
        errors="replace",
        capture_output=True,
        check=False,
        env=environment,
    )
    assert result.returncode == 0, result.stderr
    return result.stdout.strip()


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


def test_installed_netctl_services_expose_the_composite_commands(tmp_path: Path) -> None:
    result, bin_dir, _calls_path, environment = _run_installer(tmp_path)

    assert result.returncode == 0, result.stderr
    assert _systemctl(
        bin_dir, environment, "show", "--property=ExecStart", "--value", "netctl-collect.service"
    ) == "/usr/local/sbin/netctl --json collect all --reconcile"
    assert _systemctl(
        bin_dir, environment, "show", "--property=ExecStart", "--value", "netctl-reconcile.service"
    ) == "/usr/local/sbin/netctl --json reconcile"
    assert _systemctl(bin_dir, environment, "is-enabled", "netctl-collect.timer") == "netctl-collect.timer"
    assert _systemctl(bin_dir, environment, "is-enabled", "netctl-reconcile.timer") == "netctl-reconcile.timer"
