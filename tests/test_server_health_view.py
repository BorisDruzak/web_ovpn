import json

from app.server_health_view import build_server_health_view
from app.server_observer import parse_utc, write_snapshot


NOW = parse_utc("2026-07-27T12:01:00Z")


def write_current_snapshot(path, targets, **extra):
    write_snapshot(
        path,
        {
            "collected_at": "2026-07-27T12:00:00Z",
            "targets": targets,
            **extra,
        },
    )


def test_view_summarizes_current_role_checks_without_topology(tmp_path):
    snapshot_path = tmp_path / "latest.json"
    write_current_snapshot(
        snapshot_path,
        [
            {
                "role": "directum",
                "checks": [
                    {
                        "name": "service_state",
                        "source": "target",
                        "status": "ok",
                        "observed": "active",
                        "expected": "active",
                        "latency_ms": 12.5,
                    }
                ],
            },
            {
                "role": "nextcloud",
                "checks": [
                    {
                        "name": "https_healthcheck",
                        "source": "vpn_path",
                        "status": "critical",
                        "error": "timeout",
                    }
                ],
            },
        ],
    )

    view = build_server_health_view(snapshot_path, NOW)

    assert set(view) == {"freshness", "collected_at", "age_seconds", "collector", "summary", "targets"}
    assert view["freshness"] == "current"
    assert view["collected_at"] == "2026-07-27T12:00:00Z"
    assert view["age_seconds"] == 60
    assert view["collector"] == {"status": "ok", "failure_class": "", "message": ""}
    assert view["summary"] == {"ok": 1, "warn": 0, "critical": 1, "error": 0}
    assert set(view["targets"][0]) == {"role", "status", "problem_count", "observed_at", "checks"}
    assert view["targets"][0]["checks"] == [
        {
            "name": "service_state",
            "status": "ok",
            "observed": "active",
            "expected": "active",
            "latency_ms": 12.5,
        }
    ]
    assert view["targets"][1]["checks"] == [
        {"name": "https_healthcheck", "status": "critical", "message": "timeout"}
    ]
    assert view["targets"][1]["problem_count"] == 1
    assert "source" not in repr(view)
    assert "error" not in view["targets"][1]["checks"][0]


def test_view_exposes_current_collector_failure_without_raw_snapshot(tmp_path):
    snapshot_path = tmp_path / "latest.json"
    write_current_snapshot(
        snapshot_path,
        [],
        overall="error",
        collector={
            "status": "error",
            "failure_class": "ssh",
            "message": "SSH connection failed",
        },
    )

    view = build_server_health_view(snapshot_path, NOW)

    assert view["freshness"] == "current"
    assert view["collector"] == {
        "status": "error",
        "failure_class": "ssh",
        "message": "SSH connection failed",
    }
    assert view["summary"] == {"ok": 0, "warn": 0, "critical": 0, "error": 0}
    assert view["targets"] == []


def test_view_marks_missing_and_invalid_data_without_timestamps_or_leakage(tmp_path):
    snapshot_path = tmp_path / "latest.json"

    missing = build_server_health_view(snapshot_path, NOW)
    assert missing == {
        "freshness": "missing",
        "collected_at": None,
        "age_seconds": None,
        "collector": {"status": "ok", "failure_class": "", "message": ""},
        "summary": {"ok": 0, "warn": 0, "critical": 0, "error": 0},
        "targets": [],
    }

    snapshot_path.write_text("not json", encoding="utf-8")
    invalid = build_server_health_view(snapshot_path, NOW)
    assert invalid["freshness"] == "invalid"
    assert invalid["collected_at"] is None
    assert invalid["age_seconds"] is None
    assert invalid["targets"] == []


def test_view_reuses_stale_and_future_freshness_with_valid_age(tmp_path):
    snapshot_path = tmp_path / "latest.json"
    write_snapshot(
        snapshot_path,
        {"collected_at": "2026-07-27T11:45:59Z", "targets": []},
    )

    stale = build_server_health_view(snapshot_path, NOW)
    assert stale["freshness"] == "stale"
    assert stale["collected_at"] == "2026-07-27T11:45:59Z"
    assert stale["age_seconds"] == 901

    write_snapshot(
        snapshot_path,
        {"collected_at": "2026-07-27T12:03:01Z", "targets": []},
    )
    future = build_server_health_view(snapshot_path, NOW)
    assert future["freshness"] == "stale"
    assert future["collected_at"] == "2026-07-27T12:03:01Z"
    assert future["age_seconds"] == -121


def test_view_counts_all_target_statuses_and_problem_checks(tmp_path):
    snapshot_path = tmp_path / "latest.json"
    write_current_snapshot(
        snapshot_path,
        [
            {"role": "file_server", "checks": [{"name": "ssh", "source": "gateway", "status": "ok"}]},
            {"role": "directum", "checks": [{"name": "mongo", "source": "target", "status": "warn"}]},
            {"role": "active_directory", "checks": [{"name": "dns", "source": "target", "status": "critical"}]},
            {
                "role": "nextcloud",
                "checks": [
                    {"name": "https_healthcheck", "source": "vpn_path", "status": "error", "error": "transport"},
                    {"name": "php_fpm", "source": "target", "status": "warn"},
                ],
            },
        ],
    )

    view = build_server_health_view(snapshot_path, NOW)

    assert view["summary"] == {"ok": 1, "warn": 1, "critical": 1, "error": 1}
    assert [target["status"] for target in view["targets"]] == ["ok", "warn", "critical", "error"]
    assert [target["problem_count"] for target in view["targets"]] == [0, 1, 1, 2]
    assert all(target["observed_at"] == "2026-07-27T12:00:00Z" for target in view["targets"])


def test_view_rejects_hostile_snapshot_content_without_returning_it(tmp_path):
    snapshot_path = tmp_path / "latest.json"
    forbidden = "192.168.100.30 ssh -i /secret/observer"
    snapshot_path.write_text(
        json.dumps(
            {
                "collected_at": "2026-07-27T12:00:00Z",
                "targets": [
                    {
                        "role": "directum",
                        "checks": [
                            {
                                "name": "service_state",
                                "source": "target",
                                "status": "error",
                                "command": forbidden,
                            }
                        ],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    view = build_server_health_view(snapshot_path, NOW)

    assert view["freshness"] == "invalid"
    assert forbidden not in repr(view)
    assert view["targets"] == []
