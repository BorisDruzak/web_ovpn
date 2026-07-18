import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from app import server_observer_cli


SNAPSHOT_DIR = "/var/lib/openvpn-web/server-observer"
RUNTIME_CONFIG = "/etc/openvpn-web/server-observer.json"


def test_server_observer_service_runs_as_gateway_account_with_only_snapshot_write_access():
    service = Path("deploy/server-observer.service").read_text(encoding="utf-8")

    assert "User=openvpm" in service
    assert "Group=openvpn-web" in service
    assert "NoNewPrivileges=true" in service
    assert "PrivateTmp=true" in service
    assert "ProtectHome=read-only" in service
    assert "ProtectSystem=strict" in service
    assert f"ReadWritePaths={SNAPSHOT_DIR}" in service
    assert "CapabilityBoundingSet=" in service
    assert "ExecStart=/usr/local/sbin/server-observer" in service


def test_server_observer_timer_is_persistent_every_five_minutes():
    timer = Path("deploy/server-observer.timer").read_text(encoding="utf-8")

    assert "OnBootSec=2min" in timer
    assert "OnUnitActiveSec=5min" in timer
    assert "Persistent=true" in timer
    assert "WantedBy=timers.target" in timer


def test_wrapper_executes_venv_cli_with_external_config_and_snapshot_paths_only():
    wrapper = Path("deploy/server-observer").read_text(encoding="utf-8")

    assert wrapper.startswith("#!/usr/bin/env bash\nset -euo pipefail\n")
    assert "-m app.server_observer_cli" in wrapper
    assert f"--config {RUNTIME_CONFIG}" in wrapper
    assert f"--snapshot {SNAPSHOT_DIR}/latest.json" in wrapper
    assert "192.168." not in wrapper


def test_role_only_sample_has_no_runtime_topology_or_credentials():
    sample_text = Path("deploy/server-observer.json.sample").read_text(encoding="utf-8")
    sample = json.loads(sample_text)

    assert {target["role"] for target in sample["targets"]} == {
        "file_server",
        "directum",
        "active_directory",
        "nextcloud",
        "onlyoffice",
        "opnsense_dns",
    }
    assert "192.168." not in sample_text
    assert "password" not in sample_text.lower()
    assert "PRIVATE KEY" not in sample_text


def test_install_script_installs_observer_without_creating_runtime_topology():
    installer = Path("deploy/install-openvpn-web.sh").read_text(encoding="utf-8")

    assert "deploy/server-observer\" /usr/local/sbin/server-observer" in installer
    assert "server-observer.service" in installer
    assert "server-observer.timer" in installer
    assert f"-d -m 0750 -o openvpm -g openvpn-web {SNAPSHOT_DIR}" in installer
    assert f'[[ ! -e {RUNTIME_CONFIG} ]]' in installer
    assert "server-observer.json.sample" in installer
    assert "systemctl enable --now server-observer.timer" in installer


def test_cli_writes_snapshot_and_prints_only_role_status_summary(tmp_path, monkeypatch, capsys):
    snapshot_path = tmp_path / "latest.json"
    collected = {
        "collected_at": "2026-07-18T20:00:00Z",
        "overall": "warn",
        "targets": [
            {"role": "directum", "status": "warn", "checks": []},
            {"role": "nextcloud", "status": "ok", "checks": []},
        ],
    }
    calls = {}

    monkeypatch.setattr(server_observer_cli, "load_runtime_config", lambda path: {"safe": True})
    monkeypatch.setattr(
        server_observer_cli,
        "collect",
        lambda config, runner, now: calls.update(config=config, runner=runner, now=now) or collected,
    )
    monkeypatch.setattr(
        server_observer_cli,
        "write_snapshot",
        lambda path, snapshot: calls.update(path=path, snapshot=snapshot),
    )

    assert server_observer_cli.main(["--config", str(tmp_path / "config.json"), "--snapshot", str(snapshot_path)]) == 0

    output = json.loads(capsys.readouterr().out)
    assert output == {
        "overall": "warn",
        "targets": [
            {"role": "directum", "status": "warn"},
            {"role": "nextcloud", "status": "ok"},
        ],
    }
    assert calls["path"] == snapshot_path
    assert calls["snapshot"] == collected
    assert calls["now"].tzinfo == timezone.utc
    assert "config" not in json.dumps(output)
    assert "checks" not in json.dumps(output)


@pytest.mark.parametrize(
    "exception",
    [
        ValueError("host sensitive.example returned raw failure"),
        RuntimeError("ssh user@host command and key path"),
    ],
)
def test_cli_sanitizes_collector_exceptions_and_returns_nonzero(exception, tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(server_observer_cli, "load_runtime_config", lambda path: (_ for _ in ()).throw(exception))

    assert server_observer_cli.main(["--config", str(tmp_path / "config.json"), "--snapshot", str(tmp_path / "latest.json")]) == 1

    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == '{"status": "error", "message": "collector failed"}\n'
    assert "host" not in captured.err
    assert "ssh" not in captured.err
    assert "key" not in captured.err
