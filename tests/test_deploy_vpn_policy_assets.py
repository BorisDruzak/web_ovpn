import os
import re
import shutil
import subprocess
import textwrap
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_policy_unit_follows_wg_lifecycle():
    text = (ROOT / "deploy" / "vpn-policy.service").read_text(encoding="utf-8")

    assert "Wants=wg-quick@wg0.service" in text
    assert "PartOf=wg-quick@wg0.service" in text
    assert "Requires=wg-quick@wg0.service" not in text
    assert "BindsTo=wg-quick@wg0.service" not in text
    assert "ExecStart=/usr/local/sbin/vpn-policy.sh start" in text
    assert "ExecStop=/usr/local/sbin/vpn-policy.sh stop" in text


def test_policy_script_uses_only_managed_objects():
    text = (ROOT / "deploy" / "vpn-policy.sh").read_text(encoding="utf-8")

    assert 'PBR_IN_IF="ens18.50"' in text
    assert 'PBR_TABLE="123"' in text
    assert 'PBR_MARK="0x1"' in text
    assert "ip route replace default dev" in text
    assert "ip rule add fwmark" in text
    assert "VPN_POLICY_MARK" in text
    assert "VPN_POLICY_NAT" in text


def test_policy_stop_keeps_vlan50_fail_closed_when_wg_is_down():
    text = (ROOT / "deploy" / "vpn-policy.sh").read_text(encoding="utf-8")

    assert "ip route replace unreachable default table" in text
    assert "ensure_marking" in text
    assert 'if ! ip link show dev "$WG_IF" >/dev/null; then' in text


def test_policy_script_exposes_reconcile_command():
    text = (ROOT / "deploy" / "vpn-policy.sh").read_text(encoding="utf-8")

    assert "reconcile) reconcile ;;" in text
    assert "usage: $0 {start|stop|reconcile|status}" in text


def _write_mock_commands(tmp_path: Path) -> tuple[Path, Path]:
    mock_bin = tmp_path / "bin"
    mock_bin.mkdir(parents=True)
    log = tmp_path / "commands.log"

    (mock_bin / "ip").write_text(
        textwrap.dedent(
            """\
            #!/usr/bin/env bash
            set -eu
            printf '%s\\n' "$*" >> "${MOCK_LOG:?}"
            case "${1:-}" in
              link)
                [[ "${MODE:?}" != "failclosed_drift" && "${MODE:?}" != "failclosed_healthy" ]]
                ;;
              rule)
                if [[ "${2:-}" == "show" ]]; then
                  printf '1000: from all fwmark 0x1 lookup 123\\n'
                elif [[ "${2:-}" == "del" ]]; then
                  exit 1
                fi
                ;;
              route)
                if [[ "${2:-}" == "show" ]]; then
                  if [[ "${MODE:?}" == "active_healthy" || "${MODE:?}" == "active_drift" ]]; then
                    printf 'default dev wg0 scope link\\n'
                  elif [[ "${MODE:?}" == "failclosed_healthy" ]]; then
                    printf 'unreachable default metric 4278198272\\n'
                  fi
                fi
                ;;
            esac
            """
        ),
        encoding="utf-8",
    )
    (mock_bin / "iptables").write_text(
        textwrap.dedent(
            """\
            #!/usr/bin/env bash
            set -eu
            args=" $* "
            printf '%s\\n' "$*" >> "${MOCK_LOG:?}"
            if [[ "$args" == *" -C "* ]]; then
              if [[ "${MODE:?}" == "active_drift" && "$args" == *"VPN_POLICY_MARK -i ens18.50"* ]]; then
                exit 1
              fi
              if [[ "${MODE:?}" == "failclosed_healthy" || "${MODE:?}" == "failclosed_drift" ]]; then
                [[ "$args" == *" -t nat "* ]] && exit 1
              fi
              exit 0
            fi
            if [[ ( "${MODE:?}" == "failclosed_healthy" || "${MODE:?}" == "failclosed_drift" ) && "$args" == *" -t nat -S VPN_POLICY_NAT "* ]]; then
              exit 1
            fi
            if [[ "$args" == *" -D "* || "$args" == *" -F "* || "$args" == *" -X "* ]]; then
              exit 1
            fi
            exit 0
            """
        ),
        encoding="utf-8",
    )
    for command in ("ip", "iptables"):
        (mock_bin / command).chmod(0o755)
    return mock_bin, log


def _run_reconcile(tmp_path: Path, mode: str) -> list[str]:
    bash = shutil.which("bash")
    assert bash, "bash is required to execute the policy-script behavior tests"
    mock_bin, log = _write_mock_commands(tmp_path)
    env = os.environ | {"PATH": f"{mock_bin}{os.pathsep}{os.environ['PATH']}", "MOCK_LOG": str(log), "MODE": mode}
    result = subprocess.run(
        [bash, str(ROOT / "deploy" / "vpn-policy.sh"), "reconcile"],
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    return log.read_text(encoding="utf-8").splitlines()


def _mutations(commands: list[str]) -> list[str]:
    return [
        command
        for command in commands
        if re.search(r"(?:^|\\s)(?:-A|-D|-F|-X|-N|add|del|replace)(?:\\s|$)", command)
    ]


def test_reconcile_does_not_rebuild_a_healthy_active_policy(tmp_path: Path):
    commands = _run_reconcile(tmp_path, "active_healthy")

    assert _mutations(commands) == []
    assert any(command.startswith("link show dev wg0") for command in commands)
    assert any("-t nat -C POSTROUTING -j VPN_POLICY_NAT" in command for command in commands)


def test_reconcile_does_not_rebuild_a_healthy_fail_closed_policy(tmp_path: Path):
    commands = _run_reconcile(tmp_path, "failclosed_healthy")

    assert _mutations(commands) == []
    assert any(command == "route show table 123" for command in commands)
    assert any("-t nat -S VPN_POLICY_NAT" in command for command in commands)


def test_reconcile_repairs_only_a_drifted_policy_or_fail_closed_state(tmp_path: Path):
    active_commands = _run_reconcile(tmp_path / "active", "active_drift")
    fail_closed_commands = _run_reconcile(tmp_path / "fail-closed", "failclosed_drift")

    assert "route replace default dev wg0 table 123" in active_commands
    assert "route replace unreachable default table 123" in fail_closed_commands
    for command in active_commands + fail_closed_commands:
        assert "wg-quick" not in command
        assert "openvpn" not in command
        assert "systemctl" not in command
