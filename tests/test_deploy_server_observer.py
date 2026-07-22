import json
from datetime import datetime, timezone
from pathlib import Path
import shutil
import subprocess

import pytest

from app import server_observer_cli


SNAPSHOT_DIR = "/var/lib/openvpn-web/server-observer"
RUNTIME_CONFIG = "/etc/openvpn-web/server-observer.json"
OBSERVER_KEY = "/etc/openvpn-web/server-observer.key"
OBSERVER_KNOWN_HOSTS = "/etc/openvpn-web/server-observer.known_hosts"
OBSERVER_RUNTIME = "/usr/local/lib/openvpn-web-server-observer"
OBSERVER_INSTALLER = "deploy/install-server-observer.sh"
OBSERVER_BACKUP = "deploy/backup-server-observer.sh"
OBSERVER_ROLLBACK = "deploy/rollback-server-observer.sh"


def test_server_observer_service_runs_as_gateway_account_with_only_snapshot_write_access():
    service = Path("deploy/server-observer.service").read_text(encoding="utf-8")

    assert "User=openvpm" in service
    assert "Group=openvpn-web" in service
    assert "NoNewPrivileges=true" in service
    assert "PrivateTmp=true" in service
    assert "ProtectHome=tmpfs" in service
    assert "ProtectSystem=strict" in service
    assert "WorkingDirectory=/" in service
    assert f"ReadWritePaths={SNAPSHOT_DIR}" in service
    assert "TimeoutStartSec=3min" in service
    assert f"BindReadOnlyPaths={RUNTIME_CONFIG}" in service
    assert f"BindReadOnlyPaths={OBSERVER_KEY}" in service
    assert f"BindReadOnlyPaths={OBSERVER_KNOWN_HOSTS}" in service
    assert "InaccessiblePaths=/etc/openvpn-web/openvpn-web.env" in service
    assert "InaccessiblePaths=/etc/openvpn/client-generator" in service
    assert "InaccessiblePaths=-/mnt/antares_soft/vpn_config" in service
    assert "InaccessiblePaths=-/var/lib/openvpn-web/openvpn-web.sqlite" in service
    assert "InaccessiblePaths=/opt/openvpn-web" in service
    assert "InaccessiblePaths=-/var/lib/openvpn-web/server-drafts" in service
    assert "InaccessiblePaths=/usr/local/lib/openvpn-web-server-draft-worker" in service
    assert f"ReadOnlyPaths={OBSERVER_RUNTIME}" in service
    assert "CapabilityBoundingSet=" in service
    assert "ExecStart=/usr/local/sbin/server-observer" in service


def test_server_observer_timer_is_persistent_every_five_minutes():
    timer = Path("deploy/server-observer.timer").read_text(encoding="utf-8")

    assert "OnBootSec=2min" in timer
    assert "OnUnitActiveSec=5min" in timer
    assert "Persistent=true" in timer
    assert "WantedBy=timers.target" in timer


def test_wrapper_executes_only_the_root_owned_isolated_runtime():
    wrapper = Path("deploy/server-observer").read_text(encoding="utf-8")

    assert wrapper.startswith("#!/bin/bash\nset -euo pipefail\n")
    assert f"exec /usr/bin/python3 -I {OBSERVER_RUNTIME}/observer_main.py" in wrapper
    assert f"--config {RUNTIME_CONFIG}" in wrapper
    assert f"--snapshot {SNAPSHOT_DIR}/latest.json" in wrapper
    assert "192.168." not in wrapper
    assert "/opt/openvpn-web" not in wrapper
    assert ".venv" not in wrapper


def test_isolated_bootstrap_adds_only_the_fixed_runtime_before_running_cli():
    bootstrap = Path("deploy/server-observer-main.py").read_text(encoding="utf-8")

    assert f'RUNTIME_ROOT = Path("{OBSERVER_RUNTIME}")' in bootstrap
    assert "sys.path.insert(0, str(RUNTIME_ROOT))" in bootstrap
    assert 'runpy.run_module("app.server_observer_cli", run_name="__main__", alter_sys=True)' in bootstrap
    assert "/opt/openvpn-web" not in bootstrap


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
    assert sample["ssh_key"] == OBSERVER_KEY


def test_generic_installer_never_mutates_or_enables_observer_assets():
    installer = Path("deploy/install-openvpn-web.sh").read_text(encoding="utf-8")

    for forbidden in (
        "/usr/local/sbin/server-observer",
        "server-observer.service",
        "server-observer.timer",
        SNAPSHOT_DIR,
        RUNTIME_CONFIG,
        OBSERVER_KEY,
        OBSERVER_KNOWN_HOSTS,
        OBSERVER_RUNTIME,
    ):
        assert forbidden not in installer


def test_scoped_installer_uses_a_root_owned_non_web_writable_runtime():
    installer = Path(OBSERVER_INSTALLER).read_text(encoding="utf-8")

    for required in (
        f'OBSERVER_RUNTIME="{OBSERVER_RUNTIME}"',
        "validate_root_component /usr root root 755",
        "validate_root_component /usr/local root root 755",
        "validate_root_component /usr/local/lib root root 755",
        "validate_python_runtime",
        'validate_observer_runtime "$OBSERVER_RUNTIME"',
        '-d -m 0755 -o root -g root "$STAGED_RUNTIME/app"',
        '"$SRC/app/server_observer.py" "$STAGED_RUNTIME/app/server_observer.py"',
        '"$SRC/app/server_observer_cli.py" "$STAGED_RUNTIME/app/server_observer_cli.py"',
        '"$SRC/deploy/server-observer-main.py" "$STAGED_RUNTIME/observer_main.py"',
        '"$SRC/deploy/server-observer" /usr/local/sbin/server-observer',
        "systemctl enable --now server-observer.timer",
    ):
        assert required in installer

    assert 'find "$path" \\( -type l -o ! -user root -o ! -group root -o -perm /022 \\)' in installer
    assert installer.count('validate_observer_runtime "$OBSERVER_RUNTIME"') >= 2
    assert "/opt/openvpn-web" not in installer
    assert ".venv" not in installer
    assert "openvpn-web.service" not in installer
    assert "netctl-collect" not in installer
    assert "openvpn-server" not in installer


def test_scoped_installer_rejects_web_owned_or_mutable_staged_source():
    installer = Path(OBSERVER_INSTALLER).read_text(encoding="utf-8")

    assert "validate_source_tree" in installer
    assert 'find "$SRC/app" "$SRC/deploy" \\( -type l -o -perm /022 -o -user openvpn-web \\)' in installer
    source_validation = installer.rindex("validate_source_tree")
    assert source_validation < installer.index("systemctl stop server-observer.timer")
    assert source_validation < installer.index('mv -- "$STAGED_RUNTIME" "$OBSERVER_RUNTIME"')


def test_scoped_installer_validates_but_never_rewrites_observer_secrets():
    installer = Path(OBSERVER_INSTALLER).read_text(encoding="utf-8")

    for path in (RUNTIME_CONFIG, OBSERVER_KEY, OBSERVER_KNOWN_HOSTS):
        assert f'validate_private_file {path}' in installer
    assert "openvpm:openvpm:600" in installer
    for forbidden in (
        f"chown openvpm:openvpm {OBSERVER_KEY}",
        f"chmod 0600 {OBSERVER_KEY}",
        f"chown openvpm:openvpm {OBSERVER_KNOWN_HOSTS}",
        f"chmod 0600 {OBSERVER_KNOWN_HOSTS}",
        "server-observer.json.sample",
    ):
        assert forbidden not in installer


def test_scoped_installer_safely_migrates_the_legacy_web_owned_snapshot_directory():
    installer = Path(OBSERVER_INSTALLER).read_text(encoding="utf-8")

    legacy_metadata = "openvpn-web:openvpn-web:750"
    legacy_allowance = installer.index(legacy_metadata)
    timer_stop = installer.index("systemctl stop server-observer.timer")
    parent_lock = installer.index("sudo_cmd chmod 1750 \"$STATE_PARENT\"")
    state_hardening = installer.index("sudo_cmd chown openvpm:openvpn-web \"$STATE_DIR\"")
    final_parent_hardening = installer.index("sudo_cmd chmod 1770 \"$STATE_PARENT\"")

    assert legacy_allowance < timer_stop < parent_lock < state_hardening < final_parent_hardening
    assert installer.count("validate_state_dir") >= 3


def test_scoped_observer_backup_and_rollback_cover_every_mutated_asset():
    backup = Path(OBSERVER_BACKUP).read_text(encoding="utf-8")
    rollback = Path(OBSERVER_ROLLBACK).read_text(encoding="utf-8")

    for asset in (
        "server-observer",
        "server-observer-runtime",
        "server-observer.service",
        "server-observer.timer",
        "server-observer-state",
        "server-observer-state-parent",
    ):
        assert asset in backup
        assert asset in rollback
    assert 'rollback_manifest="$BACKUP_ROOT/rollback.assets"' in backup
    assert 'validate_backup_root "$BACKUP_ROOT"' in backup
    assert 'validate_backup_root "$BACKUP_ROOT"' in rollback
    assert 'validate_manifest_asset server-observer-runtime directory' in rollback
    assert 'validate_manifest_asset server-observer-state directory' in rollback
    assert 'validate_manifest_asset server-observer-state-parent metadata' in rollback
    assert 'validate_parent_archive "$BACKUP_ROOT/server-observer-state-parent.tar"' in rollback
    first_mutation = rollback.rindex("stop_observer")
    assert rollback.index('validate_manifest_asset server-observer ') < first_mutation
    assert rollback.index('reject_nested_symlinks "$BACKUP_ROOT/server-observer-runtime"') < first_mutation
    assert f"backup_asset server-observer-key" not in backup
    assert f'cp -a -- "{OBSERVER_KEY}"' not in backup
    assert OBSERVER_KEY not in rollback
    assert RUNTIME_CONFIG not in backup
    assert RUNTIME_CONFIG not in rollback


def test_observer_backup_rejects_mutable_runtime_and_records_parent_metadata():
    backup = Path(OBSERVER_BACKUP).read_text(encoding="utf-8")

    assert 'validate_root_owned_asset server-observer file' in backup
    assert 'validate_root_owned_asset server-observer-runtime directory' in backup
    assert 'validate_root_owned_asset server-observer.service file' in backup
    assert 'validate_root_owned_asset server-observer.timer file' in backup
    assert '! -user root -o ! -group root -o -perm /022' in backup
    assert "--no-recursion" in backup
    assert 'server-observer-state-parent metadata present' in backup
    parent_archive = backup.index('"$BACKUP_ROOT/server-observer-state-parent.tar" --no-recursion')
    parent_lock = backup.index("sudo_cmd chown root:openvpn-web /var/lib/openvpn-web")
    state_copy = backup.index("backup_asset server-observer-state directory")
    assert parent_archive < parent_lock < state_copy
    cleanup = backup.split("restore_timer() {", 1)[1].split("backup_asset()", 1)[0]
    assert 'server-observer-state-parent.tar' in cleanup
    assert "|| true" not in cleanup


def test_rollback_never_reactivates_a_legacy_web_writable_key_boundary():
    backup = Path(OBSERVER_BACKUP).read_text(encoding="utf-8")
    rollback = Path(OBSERVER_ROLLBACK).read_text(encoding="utf-8")

    assert "validate_execution_boundary" in backup
    assert "execution-boundary %s" in backup
    assert "/opt/openvpn-web" in backup
    assert 'boundary_state="$(manifest_value execution-boundary)"' in rollback
    legacy_branch = rollback.rsplit("legacy-unsafe|absent)", 1)[1].split(";;", 1)[0]
    assert "systemctl disable server-observer.timer" in legacy_branch
    assert "rm -f -- /usr/local/sbin/server-observer" in legacy_branch
    assert "rm -rf -- /usr/local/lib/openvpn-web-server-observer" in legacy_branch
    assert "systemctl start server-observer.timer" not in legacy_branch
    cleanup = backup.split("restore_timer() {", 1)[1].split("backup_asset()", 1)[0]
    assert '"$execution_boundary" == isolated' in cleanup


def test_observer_handoff_uses_only_scoped_scripts():
    deployment = Path("docs/DEPLOYMENT.md").read_text(encoding="utf-8")
    handoff = deployment.split("## Server Observer Isolated Runtime Handoff", 1)[1].split(
        "## SSH Server Draft Checks", 1
    )[0]

    assert "bash deploy/backup-server-observer.sh" in handoff
    assert "bash deploy/install-server-observer.sh" in handoff
    assert "bash deploy/rollback-server-observer.sh" in handoff
    assert "bash deploy/install-openvpn-web.sh" not in handoff
    assert "do not back up or modify the observer private key" in handoff


@pytest.mark.parametrize(
    "script",
    [OBSERVER_INSTALLER, OBSERVER_BACKUP, OBSERVER_ROLLBACK, "deploy/server-observer"],
)
def test_observer_deployment_shell_has_valid_bash_syntax(script):
    bash = shutil.which("bash")
    if bash is None:
        pytest.skip("bash is unavailable on this platform")

    result = subprocess.run([bash, "-n", script], text=True, capture_output=True, check=False)

    assert result.returncode == 0, result.stderr


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
