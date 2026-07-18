import json
import subprocess

import pytest

from app.server_observer import (
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
        "ssh_key": "C:/runtime/observer_key",
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


def healthy_runner(command, **kwargs):
    assert isinstance(command, list)
    assert kwargs == {"capture_output": True, "text": True, "shell": False}
    return subprocess.CompletedProcess(
        command,
        0,
        json.dumps(
            {
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
        ),
        "",
    )


def test_collect_binds_vpn_path_probe_and_continues_after_target_error():
    calls = []

    def runner(command, **kwargs):
        calls.append(command)
        if "nextcloud" in command[-1]:
            raise subprocess.TimeoutExpired(command, 8)
        return subprocess.CompletedProcess(command, 0, '{"free_percent": 34}', "")

    snapshot = collect(
        runtime_config(), runner=runner, now=parse_utc("2026-07-18T20:00:00Z")
    )

    assert any(command[:3] == ["ssh", "-b", "198.51.100.50"] for command in calls)
    assert target(snapshot, "nextcloud")["status"] == "error"
    assert target(snapshot, "directum")["status"] in {"ok", "warn", "critical"}


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
        "sshd_active",
        "data_disk_free",
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
        return subprocess.CompletedProcess(command, 0, '{"free_percent": 34}', "")

    collect(runtime_config(), runner=runner, now=parse_utc("2026-07-18T20:00:00Z"))

    forbidden = {"rm", "mv", "cp", "tee", "chmod", "chown", "sudo", "authorized_keys"}
    assert all(not forbidden.intersection(command[-1].split()) for command in calls)


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
            "targets": [{"role": "directum", "host": "hidden", "checks": []}],
        },
    )

    loaded = load_snapshot(path, now=parse_utc("2026-07-18T20:01:00Z"))

    assert loaded["overall"] == "ok"
    assert "host" not in loaded["targets"][0]
    assert not path.with_suffix(".tmp").exists()


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


def test_public_snapshot_drops_free_form_check_values(tmp_path):
    path = tmp_path / "latest.json"
    forbidden_values = [
        "192.168.100.30",
        "db.internal.example",
        "ssh -i /home/openvpm/.ssh/observer_key",
        "password=not-a-secret",
        "raw command output",
    ]
    write_snapshot(
        path,
        {
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
        },
    )

    encoded = path.read_text(encoding="utf-8")

    assert all(value not in encoded for value in forbidden_values)
    assert json.loads(encoded)["targets"][0]["checks"][0] == {
        "name": "service_state",
        "source": "target",
        "status": "error",
    }


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
