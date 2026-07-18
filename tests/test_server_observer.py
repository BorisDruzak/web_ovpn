import json

import pytest

from app.server_observer import (
    classify_directum_logs,
    classify_disk,
    load_runtime_config,
    load_snapshot,
    parse_utc,
    snapshot_status,
    write_snapshot,
)


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
