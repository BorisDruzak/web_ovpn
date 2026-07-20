import base64
import json
import os
import shutil
import subprocess
import threading
from pathlib import Path

import pytest

from app import server_observer
from app.server_observer import (
    OBSERVER_KEY_PATH,
    OBSERVER_KNOWN_HOSTS_PATH,
    classify_directum_logs,
    classify_disk,
    collect,
    load_runtime_config,
    load_snapshot,
    parse_utc,
    snapshot_status,
    write_snapshot,
)


def runtime_config():
    """Topology fixture uses documentation-only address space."""
    return {
        "ssh_key": OBSERVER_KEY_PATH,
        "tunnel_source": "198.51.100.50",
        "targets": [
            {
                "role": "file_server",
                "host": "192.0.2.10",
                "user": "observer",
                "checks": [{"name": "file_server_probe", "source": "gateway"}],
            },
            {
                "role": "directum",
                "host": "192.0.2.11",
                "user": "observer",
                "checks": [{"name": "directum_probe", "source": "gateway"}],
            },
            {
                "role": "active_directory",
                "host": "192.0.2.12",
                "user": "observer",
                "checks": [{"name": "active_directory_probe", "source": "gateway"}],
            },
            {
                "role": "nextcloud",
                "host": "192.0.2.13",
                "user": "observer",
                "checks": [{"name": "nextcloud_probe", "source": "vpn_path"}],
            },
            {
                "role": "onlyoffice",
                "host": "192.0.2.14",
                "user": "observer",
                "checks": [{"name": "onlyoffice_probe", "source": "gateway"}],
            },
            {
                "role": "opnsense_dns",
                "host": "192.0.2.15",
                "user": "observer",
                "checks": [{"name": "opnsense_dns_probe", "source": "gateway"}],
            },
        ],
    }


def target(snapshot, role):
    return next(item for item in snapshot["targets"] if item["role"] == role)


def healthy_payload():
    return {
        "free_percent": 34,
        "data_free_percent": 34,
        "log_bytes": 1,
        "services": {
            "sshd": True,
            "directumrx": True,
            "mongo": True,
            "rabbitmq": True,
            "redis": True,
            "iis": True,
            "dns": True,
            "ntds": True,
            "adws": True,
            "nginx": True,
            "php": True,
            "postgresql": True,
            "docker": True,
            "containerd": True,
            "smb": True,
            "unbound": True,
        },
        "internal_dns": True,
        "external_dns": True,
        "installed": True,
        "maintenance": False,
        "needsDbUpgrade": False,
        "https_ok": True,
        "adguard_listener": True,
        "adguard_query": True,
        "raw": "authorized_keys ssh 192.168.100.99",
    }


def healthy_runner(command, **kwargs):
    assert isinstance(command, list)
    assert kwargs == {
        "capture_output": True,
        "text": True,
        "shell": False,
        "timeout": 20,
        "errors": "replace",
    }
    return subprocess.CompletedProcess(command, 0, json.dumps(healthy_payload()), "")


def test_collect_binds_vpn_path_probe_and_continues_after_target_error():
    calls = []

    def runner(command, **kwargs):
        calls.append(command)
        if "nextcloud" in command[-1]:
            raise subprocess.TimeoutExpired(command, 8)
        return healthy_runner(command, **kwargs)

    snapshot = collect(
        runtime_config(), runner=runner, now=parse_utc("2026-07-18T20:00:00Z")
    )

    assert any(
        command[:5] == ["ssh", "-F", "/dev/null", "-b", "198.51.100.50"]
        for command in calls
    )
    assert target(snapshot, "nextcloud")["status"] == "error"
    assert target(snapshot, "directum")["status"] in {"ok", "warn", "critical"}


def test_collect_bounds_each_ssh_probe_and_redacts_timeout_text():
    calls = []

    def runner(command, **kwargs):
        calls.append(kwargs)
        if "nextcloud" in command[-1]:
            raise subprocess.TimeoutExpired(command, kwargs["timeout"], output="raw host response")
        return healthy_runner(command, **kwargs)

    snapshot = collect(
        runtime_config(), runner=runner, now=parse_utc("2026-07-18T20:00:00Z")
    )

    assert calls and {call["timeout"] for call in calls} == {20}
    assert target(snapshot, "nextcloud")["status"] == "error"
    assert {check["error"] for check in target(snapshot, "nextcloud")["checks"]} == {"timeout"}
    assert target(snapshot, "directum")["status"] == "ok"
    assert "raw host response" not in json.dumps(snapshot)


def test_collect_covers_the_allow_listed_role_checks():
    snapshot = collect(
        runtime_config(), runner=healthy_runner, now=parse_utc("2026-07-18T20:00:00Z")
    )

    assert {item["role"] for item in snapshot["targets"]} == {
        "file_server",
        "directum",
        "active_directory",
        "nextcloud",
        "onlyoffice",
        "opnsense_dns",
    }
    assert snapshot["overall"] == "ok"
    assert {check["name"] for check in target(snapshot, "file_server")["checks"]} == {
        "sshd_active", "smb_active", "data_disk_free",
    }
    assert {check["name"] for check in target(snapshot, "directum")["checks"]} == {
        "c_disk_free", "rxdata_log_bytes", "directumrx_active", "mongo_active",
        "rabbitmq_active", "redis_active", "iis_active", "dns_active",
    }
    assert {check["name"] for check in target(snapshot, "active_directory")["checks"]} == {
        "c_disk_free", "dns_active", "ntds_active", "adws_active", "internal_dns",
        "external_dns",
    }
    assert {check["name"] for check in target(snapshot, "nextcloud")["checks"]} == {
        "nextcloud_status", "root_disk_free", "data_disk_free", "nginx_active",
        "php_active", "postgresql_active", "redis_active",
    }
    assert {check["name"] for check in target(snapshot, "onlyoffice")["checks"]} == {
        "https_healthcheck", "docker_active", "containerd_active", "root_disk_free",
    }
    assert {check["name"] for check in target(snapshot, "opnsense_dns")["checks"]} == {
        "adguard_listener", "adguard_query", "unbound_active", "internal_dns",
        "external_dns",
    }


def test_public_collection_never_contains_host_command_or_raw_output():
    snapshot = collect(
        runtime_config(), runner=healthy_runner, now=parse_utc("2026-07-18T20:00:00Z")
    )

    encoded = json.dumps(snapshot)
    assert "192.168." not in encoded
    assert "ssh " not in encoded
    assert "authorized_keys" not in encoded
    assert "observer_key" not in encoded


def test_collect_uses_read_only_argv_probes():
    calls = []

    def runner(command, **kwargs):
        calls.append(command)
        return healthy_runner(command, **kwargs)

    collect(runtime_config(), runner=runner, now=parse_utc("2026-07-18T20:00:00Z"))

    forbidden = {"rm", "mv", "cp", "tee", "chmod", "chown", "sudo", "authorized_keys"}
    assert all(not forbidden.intersection(command[-1].split()) for command in calls)


@pytest.mark.parametrize(
    ("field", "unsafe_value"),
    [
        ("user", "-oProxyCommand=local-command"),
        ("user", "observer name"),
        ("host", "-oProxyCommand=local-command"),
        ("host", "192.0.2.10\nunsafe"),
    ],
)
def test_collect_rejects_ssh_option_injection_before_calling_runner(field, unsafe_value):
    config = runtime_config()
    config["targets"][0][field] = unsafe_value
    calls = []

    def runner(command, **kwargs):
        calls.append(command)
        raise AssertionError("runner must not receive an unsafe SSH destination")

    with pytest.raises(ValueError):
        collect(config, runner=runner, now=parse_utc("2026-07-18T20:00:00Z"))

    assert calls == []


def test_collect_uses_ssh_end_of_options_before_destination():
    calls = []

    def runner(command, **kwargs):
        calls.append(command)
        return healthy_runner(command, **kwargs)

    collect(runtime_config(), runner=runner, now=parse_utc("2026-07-18T20:00:00Z"))

    assert all(command[-3] == "--" for command in calls)
    assert all(command[command.index("ssh") + 1 : command.index("ssh") + 3] == ["-F", "/dev/null"] for command in calls)
    assert all("IdentitiesOnly=yes" in command for command in calls)
    assert all("IdentityAgent=none" in command for command in calls)
    assert all("GlobalKnownHostsFile=/dev/null" in command for command in calls)
    assert all(f"UserKnownHostsFile={OBSERVER_KNOWN_HOSTS_PATH}" in command for command in calls)
    assert all("StrictHostKeyChecking=yes" in command for command in calls)
    assert all(command[-2].startswith("observer@") for command in calls)


def test_collect_rejects_a_noncanonical_observer_key_before_calling_runner():
    config = runtime_config()
    config["ssh_key"] = "/tmp/not-the-observer-key"
    calls = []

    def runner(command, **kwargs):
        calls.append(command)
        raise AssertionError("runner must not receive a noncanonical observer key")

    with pytest.raises(ValueError, match="observer key"):
        collect(config, runner=runner, now=parse_utc("2026-07-18T20:00:00Z"))

    assert calls == []


@pytest.mark.parametrize(
    ("role", "missing_field"),
    [
        ("file_server", "data_free_percent"),
        ("directum", "log_bytes"),
        ("active_directory", "internal_dns"),
        ("nextcloud", "needsDbUpgrade"),
        ("onlyoffice", "https_ok"),
        ("opnsense_dns", "adguard_query"),
    ],
)
def test_collect_rejects_partial_role_payloads(role, missing_field):
    config = runtime_config()
    config["targets"] = [item for item in config["targets"] if item["role"] == role]
    payload = healthy_payload()
    del payload[missing_field]

    def runner(command, **kwargs):
        return subprocess.CompletedProcess(command, 0, json.dumps(payload), "")

    snapshot = collect(config, runner=runner, now=parse_utc("2026-07-18T20:00:00Z"))

    assert snapshot["overall"] == "error"
    assert {check["error"] for check in snapshot["targets"][0]["checks"]} == {
        "unexpected_response"
    }


@pytest.mark.parametrize("invalid_status", [None, "false", 0])
def test_collect_rejects_malformed_nextcloud_status_fields(invalid_status):
    config = runtime_config()
    config["targets"] = [item for item in config["targets"] if item["role"] == "nextcloud"]
    payload = healthy_payload()
    payload["needsDbUpgrade"] = invalid_status

    def runner(command, **kwargs):
        return subprocess.CompletedProcess(command, 0, json.dumps(payload), "")

    snapshot = collect(config, runner=runner, now=parse_utc("2026-07-18T20:00:00Z"))

    assert snapshot["overall"] == "error"
    assert {check["error"] for check in snapshot["targets"][0]["checks"]} == {
        "unexpected_response"
    }


def test_collect_continues_after_unexpected_runner_exception_without_leaking_text():
    calls = []

    def runner(command, **kwargs):
        calls.append(command)
        if command[-1] == server_observer._ROLE_PROBES["file_server"]:
            raise RuntimeError("sensitive remote exception text")
        return healthy_runner(command, **kwargs)

    snapshot = collect(runtime_config(), runner=runner, now=parse_utc("2026-07-18T20:00:00Z"))

    assert target(snapshot, "file_server")["status"] == "error"
    assert target(snapshot, "directum")["status"] == "ok"
    assert "sensitive remote exception text" not in json.dumps(snapshot)
    assert len(calls) == 6


def test_windows_service_probes_require_running_status():
    calls = []

    def runner(command, **kwargs):
        calls.append(command)
        return healthy_runner(command, **kwargs)

    collect(runtime_config(), runner=runner, now=parse_utc("2026-07-18T20:00:00Z"))

    directum = decode_windows_probe(role_probe(calls, "directum"))
    active_directory = decode_windows_probe(role_probe(calls, "active_directory"))
    assert directum.index("$running=") < directum.index("[pscustomobject]@{")
    assert active_directory.index("$running=") < active_directory.index("[pscustomobject]@{")
    assert "Status -eq 'Running'" in directum
    assert "Status -eq 'Running'" in active_directory
    assert all(
        f"& $running '{service}'" in directum
        for service in ("DirectumRX", "MongoDB", "RabbitMQ", "Redis", "W3SVC", "DNS")
    )
    assert all(
        f"& $running '{service}'" in active_directory
        for service in ("DNS", "NTDS", "ADWS")
    )


def test_file_server_probe_checks_windows_e_volume_smb_and_ssh():
    calls = []

    def runner(command, **kwargs):
        calls.append(command)
        return healthy_runner(command, **kwargs)

    collect(runtime_config(), runner=runner, now=parse_utc("2026-07-19T10:00:00Z"))

    probe = decode_windows_probe(role_probe(calls, "file_server"))
    assert "Get-CimInstance Win32_LogicalDisk" in probe
    assert 'DeviceID="E:"' in probe
    assert "& $running 'LanmanServer'" in probe
    assert "& $running 'sshd'" in probe


def test_directum_probe_recursively_sums_rxdata_logs():
    calls = []

    def runner(command, **kwargs):
        calls.append(command)
        return healthy_runner(command, **kwargs)

    collect(runtime_config(), runner=runner, now=parse_utc("2026-07-19T10:00:00Z"))

    probe = decode_windows_probe(role_probe(calls, "directum"))
    assert "Get-ChildItem -LiteralPath 'C:\\rxdata\\logs' -File -Recurse" in probe
    assert "Measure-Object -Property Length -Sum" in probe
    assert "Get-Item 'C:\\rxdata\\log'" not in probe


def test_nextcloud_probe_preserves_raw_status_values_for_strict_parser():
    calls = []

    def runner(command, **kwargs):
        calls.append(command)
        return healthy_runner(command, **kwargs)

    collect(runtime_config(), runner=runner, now=parse_utc("2026-07-18T20:00:00Z"))

    probe = next(command[-1] for command in calls if "server_observer:nextcloud" in command[-1])
    assert '"installed"=>$s["installed"]' in probe
    assert '"maintenance"=>$s["maintenance"]' in probe
    assert '"needsDbUpgrade"=>$s["needsDbUpgrade"]' in probe
    assert "(bool)$s[" not in probe


def test_linux_probes_are_compatible_with_local_https_and_shell_expansion():
    calls = []

    def runner(command, **kwargs):
        calls.append(command)
        return healthy_runner(command, **kwargs)

    collect(runtime_config(), runner=runner, now=parse_utc("2026-07-19T10:00:00Z"))

    nextcloud = next(command[-1] for command in calls if "server_observer:nextcloud" in command[-1])
    onlyoffice = next(command[-1] for command in calls if "server_observer:onlyoffice" in command[-1])
    assert "curl -kfsS https://127.0.0.1/status.php" in nextcloud
    assert "disk_free_space($p)" in nextcloud
    assert '$d("/var/www/nextcloud")' in nextcloud
    assert 'pgrep -f php-fpm' in nextcloud
    assert 'set -- $(df -P / | tail -1)' in onlyoffice
    assert "curl -kfsS https://127.0.0.1/healthcheck" in onlyoffice


def test_opnsense_probe_checks_running_processes_not_rc_service_status():
    calls = []

    def runner(command, **kwargs):
        calls.append(command)
        return healthy_runner(command, **kwargs)

    collect(runtime_config(), runner=runner, now=parse_utc("2026-07-19T10:00:00Z"))

    probe = next(command[-1] for command in calls if "server_observer:opnsense_dns" in command[-1])
    assert "pgrep -x AdGuardHome" in probe
    assert "pgrep -x unbound" in probe
    assert "service unbound onestatus" not in probe


def test_windows_probes_hide_role_markers_inside_encoded_bodies():
    for role in ("file_server", "directum", "active_directory"):
        probe = server_observer._ROLE_PROBES[role]
        assert " # server_observer:" not in probe
        assert decode_windows_probe(probe).endswith(f"# server_observer:{role}")


def test_collect_replaces_non_utf8_probe_stderr():
    config = runtime_config()
    config["targets"] = [item for item in config["targets"] if item["role"] == "directum"]
    kwargs_seen = []

    def runner(command, **kwargs):
        kwargs_seen.append(kwargs)
        return healthy_runner(command, **kwargs)

    snapshot = collect(config, runner=runner, now=parse_utc("2026-07-19T10:00:00Z"))

    assert snapshot["overall"] == "ok"
    assert kwargs_seen == [{"capture_output": True, "text": True, "shell": False, "timeout": 20, "errors": "replace"}]


@pytest.mark.parametrize(
    ("role", "expected_services"),
    [
        ("directum", {"directumrx", "mongo", "rabbitmq", "redis", "iis", "dns"}),
        ("active_directory", {"dns", "ntds", "adws"}),
    ],
)
@pytest.mark.skipif(
    shutil.which("powershell") is None,
    reason="requires PowerShell to execute generated Windows probe bodies",
)
def test_windows_probe_body_with_mocked_commands_emits_json(role, expected_services):
    calls = []

    def runner(command, **kwargs):
        calls.append(command)
        return healthy_runner(command, **kwargs)

    collect(runtime_config(), runner=runner, now=parse_utc("2026-07-18T20:00:00Z"))

    probe = role_probe(calls, role)
    body = decode_windows_probe(probe)
    mocks = """
function Get-CimInstance { [CmdletBinding()] param([Parameter(ValueFromRemainingArguments=$true)]$Rest) [pscustomobject]@{ FreeSpace = 34; Size = 100 } }
function Get-Item { [CmdletBinding()] param([Parameter(ValueFromRemainingArguments=$true)]$Rest) [pscustomobject]@{ Length = 1 } }
function Get-Service { [CmdletBinding()] param([string]$Name) [pscustomobject]@{ Status = 'Running' } }
function Resolve-DnsName { [CmdletBinding()] param([Parameter(ValueFromRemainingArguments=$true)]$Rest) [pscustomobject]@{} }
"""
    completed = subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", mocks + body],
        capture_output=True,
        text=True,
        shell=False,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr
    payload = json.loads(completed.stdout)
    assert set(payload["services"]) == expected_services
    assert all(payload["services"].values())


def decode_windows_probe(probe):
    encoded = probe.split(" -EncodedCommand ", 1)[1].split(" #", 1)[0]
    return base64.b64decode(encoded).decode("utf-16le")


def role_probe(calls, role):
    return next(command[-1] for command in calls if command[-1] == server_observer._ROLE_PROBES[role])


@pytest.mark.parametrize(
    ("result", "category"),
    [
        (subprocess.CompletedProcess([], 255, "remote failure", ""), "transport"),
        (subprocess.CompletedProcess([], 0, "not-json", ""), "parse"),
        (subprocess.CompletedProcess([], 0, "[]", ""), "unexpected_response"),
    ],
)
def test_collect_redacts_non_timeout_probe_failures(result, category):
    config = runtime_config()
    config["targets"] = [config["targets"][0]]

    def runner(command, **kwargs):
        return subprocess.CompletedProcess(command, result.returncode, result.stdout, result.stderr)

    snapshot = collect(config, runner=runner, now=parse_utc("2026-07-18T20:00:00Z"))

    assert snapshot["overall"] == "error"
    assert {check["error"] for check in snapshot["targets"][0]["checks"]} == {category}


def test_capacity_thresholds_and_directum_log_thresholds():
    assert classify_disk(15.0) == "ok"
    assert classify_disk(14.99) == "warn"
    assert classify_disk(9.99) == "critical"
    assert classify_directum_logs(20 * 1024**3) == "warn"
    assert classify_directum_logs(30 * 1024**3) == "critical"


def test_snapshot_write_is_atomic_and_loaded_snapshot_is_redacted(tmp_path):
    path = tmp_path / "latest.json"
    write_snapshot(
        path,
        {
            "collected_at": "2026-07-18T20:00:00Z",
            "targets": [{"role": "directum", "checks": []}],
        },
    )

    loaded = load_snapshot(path, now=parse_utc("2026-07-18T20:01:00Z"))

    assert loaded["overall"] == "ok"
    assert "host" not in loaded["targets"][0]
    assert not list(tmp_path.glob(f".{path.name}.*.tmp"))


def test_snapshot_concurrent_writes_are_atomic_and_leave_no_temporary_files(tmp_path, monkeypatch):
    path = tmp_path / "latest.json"
    barrier = threading.Barrier(2)
    errors = []
    original_write_text = Path.write_text

    def synchronized_write_text(self, *args, **kwargs):
        result = original_write_text(self, *args, **kwargs)
        if self == path.with_suffix(".tmp"):
            barrier.wait(timeout=2)
        return result

    monkeypatch.setattr(Path, "write_text", synchronized_write_text)
    snapshots = [
        {"collected_at": "2026-07-18T20:00:00Z", "targets": [{"role": "directum", "checks": []}]},
        {"collected_at": "2026-07-18T20:00:01Z", "targets": [{"role": "nextcloud", "checks": []}]},
    ]

    def write(snapshot):
        try:
            write_snapshot(path, snapshot)
        except Exception as exc:  # pragma: no cover - asserted below
            errors.append(exc)

    workers = [threading.Thread(target=write, args=(snapshot,)) for snapshot in snapshots]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join(timeout=3)

    assert not any(worker.is_alive() for worker in workers)
    assert errors == []
    assert load_snapshot(path, now=parse_utc("2026-07-18T20:01:00Z"))["overall"] == "ok"
    assert not list(tmp_path.glob(f".{path.name}.*.tmp"))


def test_snapshot_write_preserves_mode_and_cleans_temporary_file_after_replace_error(tmp_path, monkeypatch):
    path = tmp_path / "latest.json"
    path.write_text("{}", encoding="utf-8")
    os.chmod(path, 0o640)
    chmod_calls = []
    original_chmod = server_observer.os.chmod

    def record_chmod(target, mode):
        chmod_calls.append((target, mode))
        original_chmod(target, mode)

    monkeypatch.setattr(server_observer.stat, "S_IMODE", lambda mode: 0o640)
    monkeypatch.setattr(server_observer.os, "chmod", record_chmod)

    write_snapshot(
        path,
        {"collected_at": "2026-07-18T20:00:00Z", "targets": [{"role": "directum", "checks": []}]},
    )
    assert [mode for _, mode in chmod_calls] == [0o640]

    monkeypatch.setattr(server_observer.os, "replace", lambda source, destination: (_ for _ in ()).throw(OSError("replace failed")))
    with pytest.raises(OSError, match="replace failed"):
        write_snapshot(
            path,
            {"collected_at": "2026-07-18T20:00:01Z", "targets": [{"role": "directum", "checks": []}]},
        )
    assert not list(tmp_path.glob(f".{path.name}.*.tmp"))


def test_snapshot_status_is_stale_after_fifteen_minutes():
    snapshot = {"collected_at": "2026-07-18T20:00:00Z", "targets": []}

    assert snapshot_status(snapshot, parse_utc("2026-07-18T20:15:00Z")) == "ok"
    assert snapshot_status(snapshot, parse_utc("2026-07-18T20:15:01Z")) == "stale"


def test_runtime_config_rejects_unknown_target_fields_and_invalid_sources(tmp_path):
    path = tmp_path / "runtime.json"
    path.write_text(
        json.dumps(
            {
                "targets": [
                    {
                        "role": "directum",
                        "host": "runtime-only.example",
                        "user": "observer",
                        "checks": [{"name": "ssh", "source": "outside"}],
                        "password": "must-not-be-accepted",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError):
        load_runtime_config(path)


def test_runtime_config_accepts_only_allowed_roles_and_sources(tmp_path):
    path = tmp_path / "runtime.json"
    config = {
        "ssh_key": OBSERVER_KEY_PATH,
        "tunnel_source": "198.51.100.50",
        "targets": [
            {
                "role": "directum",
                "host": "runtime-only.example",
                "user": "observer",
                "checks": [{"name": "ssh", "source": "gateway"}],
            }
        ]
    }
    path.write_text(json.dumps(config), encoding="utf-8")

    assert load_runtime_config(path) == config


@pytest.mark.parametrize(
    "mutate",
    [
        lambda config: config.update({"unexpected": "value"}),
        lambda config: config["targets"][0]["checks"][0].update({"unexpected": "value"}),
    ],
)
def test_runtime_config_rejects_unknown_fields_at_every_schema_level(tmp_path, mutate):
    config = runtime_config()
    mutate(config)
    path = tmp_path / "runtime.json"
    path.write_text(json.dumps(config), encoding="utf-8")

    with pytest.raises(ValueError, match="fields"):
        load_runtime_config(path)


def test_public_snapshot_rejects_unknown_check_fields(tmp_path):
    path = tmp_path / "latest.json"
    forbidden_values = [
        "192.168.100.30",
        "db.internal.example",
        "ssh -i /home/openvpm/.ssh/observer_key",
        "password=not-a-secret",
        "raw command output",
    ]
    snapshot = {
            "collected_at": "2026-07-18T20:00:00Z",
            "targets": [
                {
                    "role": "directum",
                    "checks": [
                        {
                            "name": "service_state",
                            "source": "target",
                            "status": "error",
                            "observed": forbidden_values[0],
                            "expected": forbidden_values[1],
                            "error": forbidden_values[2],
                            "command": forbidden_values[3],
                            "output": forbidden_values[4],
                        }
                    ],
                }
            ],
        }

    with pytest.raises(ValueError, match="fields"):
        write_snapshot(path, snapshot)

    assert not path.exists()


@pytest.mark.parametrize(
    "target",
    [
        {"role": "unapproved_role", "checks": []},
        {
            "role": "directum",
            "checks": [{"name": "service_state", "source": "unapproved_source"}],
        },
    ],
)
def test_snapshot_write_rejects_unknown_roles_and_sources(tmp_path, target):
    path = tmp_path / "latest.json"
    snapshot = {"collected_at": "2026-07-18T20:00:00Z", "targets": [target]}

    with pytest.raises(ValueError):
        write_snapshot(path, snapshot)

    assert not path.exists()


def test_snapshot_write_rejects_unsafe_overall_and_keeps_valid_status(tmp_path):
    path = tmp_path / "latest.json"
    base_snapshot = {"collected_at": "2026-07-18T20:00:00Z", "targets": []}

    with pytest.raises(ValueError):
        write_snapshot(path, {**base_snapshot, "overall": "ssh -i observer-key"})

    write_snapshot(path, {**base_snapshot, "overall": "warn"})

    assert json.loads(path.read_text(encoding="utf-8"))["overall"] == "warn"


@pytest.mark.parametrize("failure", [OSError("unavailable"), UnicodeDecodeError("utf-8", b"x", 0, 1, "bad")])
def test_snapshot_read_failures_return_only_generic_error(tmp_path, monkeypatch, failure):
    path = tmp_path / "latest.json"
    path.write_text("{}", encoding="utf-8")
    monkeypatch.setattr(Path, "read_text", lambda *_args, **_kwargs: (_ for _ in ()).throw(failure))

    assert load_snapshot(path, now=parse_utc("2026-07-18T20:01:00Z")) == {
        "overall": "error",
        "targets": [],
    }


@pytest.mark.parametrize(
    "snapshot",
    [
        {"collected_at": "2026-07-18T20:00:00Z", "targets": [], "extra": True},
        {
            "collected_at": "2026-07-18T20:00:00Z",
            "targets": [{"role": "directum", "checks": [], "extra": True}],
        },
    ],
)
def test_snapshot_rejects_unknown_fields_at_every_schema_level(tmp_path, snapshot):
    path = tmp_path / "latest.json"
    path.write_text(json.dumps(snapshot), encoding="utf-8")

    assert load_snapshot(path, now=parse_utc("2026-07-18T20:01:00Z")) == {
        "overall": "error",
        "targets": [],
    }
