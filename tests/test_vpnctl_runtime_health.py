import importlib.util
import json
import subprocess
import time
from importlib.machinery import SourceFileLoader
from pathlib import Path


VPNCTL = Path(__file__).resolve().parents[1] / "deploy" / "vpnctl"


def load_vpnctl():
    loader = SourceFileLoader("vpnctl_runtime_health", str(VPNCTL))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def healthy_run(calls, *, missing_table_route=False, legacy_51820=False, missing_wg=False, stale_handshake=False):
    def fake_run(cmd, cwd=None, env=None, check=True):
        calls.append(cmd)
        if cmd[:2] == ["systemctl", "is-active"]:
            return subprocess.CompletedProcess(cmd, 0, "active\n", "")
        if cmd[:3] == ["ip", "link", "show"]:
            if missing_wg:
                return subprocess.CompletedProcess(cmd, 1, "", "Device does not exist")
            return subprocess.CompletedProcess(cmd, 0, "7: wg0: <POINTOPOINT,UP> mtu 1420\n", "")
        if cmd[:3] == ["wg", "show", "wg0"]:
            if missing_wg:
                return subprocess.CompletedProcess(cmd, 1, "", "Unable to access interface")
            if cmd[-1] == "latest-handshakes":
                age = 600 if stale_handshake else 10
                return subprocess.CompletedProcess(cmd, 0, f"redacted {int(time.time()) - age}\n", "")
            return subprocess.CompletedProcess(cmd, 0, "redacted 100 200\n", "")
        if cmd[:3] == ["ip", "rule", "show"]:
            rules = "1000: from all fwmark 0x1 lookup 123\n"
            if legacy_51820:
                rules += "32765: from all lookup 51820\n"
            return subprocess.CompletedProcess(cmd, 0, rules, "")
        if cmd[:4] == ["ip", "route", "show", "table"]:
            output = "" if missing_table_route else "default dev wg0 scope link\n"
            return subprocess.CompletedProcess(cmd, 0, output, "")
        if cmd[:4] == ["iptables", "-w", "-t", "mangle"]:
            if cmd[-1] == "PREROUTING":
                output = "-A PREROUTING -j VPN_POLICY_MARK\n"
            else:
                output = "-N VPN_POLICY_MARK\n-A VPN_POLICY_MARK -i ens18.50 -j MARK --set-xmark 0x1/0xffffffff\n"
            return subprocess.CompletedProcess(cmd, 0, output, "")
        if cmd[:4] == ["iptables", "-w", "-t", "nat"]:
            if cmd[-1] == "POSTROUTING":
                output = "-A POSTROUTING -j VPN_POLICY_NAT\n"
            else:
                output = "-N VPN_POLICY_NAT\n-A VPN_POLICY_NAT -o wg0 -m mark --mark 0x1/0xffffffff -j MASQUERADE\n"
            return subprocess.CompletedProcess(cmd, 0, output, "")
        raise AssertionError(f"unexpected command: {cmd}")

    return fake_run


def run_runtime_health(monkeypatch, capsys, **scenario):
    module = load_vpnctl()
    calls = []
    monkeypatch.setattr(module, "run", healthy_run(calls, **scenario))
    monkeypatch.setattr(module, "management_test", lambda **_: {"available": True})

    returncode = module.main(["--json", "runtime-health", "--strict"])
    data = json.loads(capsys.readouterr().out)
    return data, returncode, calls


def test_runtime_health_reports_healthy_state(monkeypatch, capsys):
    data, returncode, calls = run_runtime_health(monkeypatch, capsys)

    assert returncode == 0
    assert data["overall"] == "ok"
    assert data["sections"]["policy_routing"]["table_123_default"] is True
    assert not any("add" in command or "replace" in command for command in calls)


def test_runtime_health_strict_fails_for_missing_route(monkeypatch, capsys):
    data, returncode, _ = run_runtime_health(monkeypatch, capsys, missing_table_route=True)

    assert returncode == 2
    assert "table 123 default route is missing" in data["errors"]


def test_runtime_health_rejects_legacy_51820(monkeypatch, capsys):
    data, _, _ = run_runtime_health(monkeypatch, capsys, legacy_51820=True)

    assert data["overall"] == "error"
    assert any("51820" in message for message in data["errors"])


def test_runtime_health_reports_missing_wg_interface(monkeypatch, capsys):
    data, returncode, _ = run_runtime_health(monkeypatch, capsys, missing_wg=True)

    assert returncode == 2
    assert "WireGuard interface wg0 is missing" in data["errors"]


def test_runtime_health_rejects_stale_handshake(monkeypatch, capsys):
    data, returncode, _ = run_runtime_health(monkeypatch, capsys, stale_handshake=True)

    assert returncode == 2
    assert any("handshake is missing or older" in message for message in data["errors"])
