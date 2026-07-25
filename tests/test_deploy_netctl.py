from __future__ import annotations

import json
import os
from pathlib import Path
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
    command test "$@"
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


def _run_installer(tmp_path: Path) -> tuple[subprocess.CompletedProcess[str], Path, Path, dict[str, str]]:
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
    environment = os.environ | {
        "APP": str(tmp_path / "app"),
        "PATH": f"{bin_dir}:{os.environ['PATH']}",
        "SRC": str(ROOT),
        "SUDO_PASSWORD": "controlled-test-password",
        "SUDO_CALLS": str(sudo_calls),
        "SYSTEMCTL_CALLS": str(systemctl_calls),
        "SYSTEMD_ENABLED": str(enabled),
        "SYSTEMD_RELOADED": str(reloaded),
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


def _parse_exec_start(raw: str) -> list[str]:
    result = subprocess.run(
        [sys.executable, str(VERIFIER), "--parse-exec-start"],
        text=True,
        encoding="utf-8",
        errors="replace",
        input=raw,
        capture_output=True,
        check=False,
    )
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
