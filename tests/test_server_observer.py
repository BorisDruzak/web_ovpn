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
