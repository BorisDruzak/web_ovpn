from __future__ import annotations

import json
from types import SimpleNamespace

import pytest


def _config() -> str:
    return json.dumps({
        "mac:AA": {
            "host": "192.0.2.56",
            "user": "test-user",
            "internet": {"host": "1.1.1.1", "port": 443},
            "internal": {"host": "192.0.2.30", "port": 22},
        },
    })


def test_probe_uses_only_the_configured_asset_and_fixed_tcp_targets(monkeypatch) -> None:
    import netopsctl.connectivity_probe as module
    from netopsctl.connectivity_probe import SSHConnectivityProbe

    calls = []

    def fake_run(args, **kwargs):
        calls.append((args, kwargs))
        return SimpleNamespace(returncode=0, stdout="internet=blocked\ninternal=reachable\n", stderr="")

    probe = SSHConnectivityProbe.from_json(_config(), "/run/credentials/netopsctl-active-probe-ssh-key")
    monkeypatch.setattr(module.subprocess, "run", fake_run)

    assert probe.verify("mac:AA", expected_internet=False) == {
        "asset_key": "mac:AA", "internet": "blocked", "internal": "reachable",
    }
    assert calls[0][0] == [
        "ssh", "-i", "/run/credentials/netopsctl-active-probe-ssh-key",
        "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes", "-o", "ConnectTimeout=8",
        "test-user@192.0.2.56", "python3", "-", "1.1.1.1", "443", "192.0.2.30", "22",
    ]
    assert calls[0][1]["shell"] is False
    with pytest.raises(ValueError, match="not configured"):
        probe.verify("mac:BB", expected_internet=False)


def test_probe_rejects_passwords_commands_and_invalid_endpoints() -> None:
    from netopsctl.connectivity_probe import SSHConnectivityProbe

    for record in (
        {"password": "secret"},
        {"command": "curl example.test"},
        {"host": "example.test", "user": "test-user", "internet": {"host": "1.1.1.1", "port": 443}, "internal": {"host": "192.0.2.30", "port": 22}},
    ):
        with pytest.raises(ValueError, match="invalid active connectivity probe configuration"):
            SSHConnectivityProbe.from_json(json.dumps({"mac:AA": record}), "/credential")
