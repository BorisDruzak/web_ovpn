from __future__ import annotations

import json

import pytest


OLD = "2026-06-01T00:00:00Z"
NEW = "2026-07-01T00:00:00Z"


@pytest.fixture
def conn(tmp_path):
    from netctl.db import connect

    connection = connect(f"sqlite:///{(tmp_path / 'netctl.sqlite').as_posix()}")
    revision = connection.execute(
        """INSERT INTO context_revisions
           (context_id, schema_version, sha256, source_path, validated_at, git_sha,
            status, error_json, counts_json, validation_order)
           VALUES ('availability-test', '2.2.0', 'availability-sha', 'context.yaml',
                   ?, 'availability-git', 'ok', '[]', '{}', 1)""",
        (OLD,),
    ).lastrowid
    import_run = connection.execute(
        """INSERT INTO context_import_runs
           (context_id, context_revision_id, input_sha256, git_sha, source_path,
            started_at, finished_at, status, errors_json)
           VALUES ('availability-test', ?, 'availability-sha', 'availability-git',
                   'context.yaml', ?, ?, 'success_imported', '[]')""",
        (revision, OLD, OLD),
    ).lastrowid
    for segment_id, cidr in (("availability-a", "192.0.2.0/30"), ("availability-b", "198.51.100.0/30")):
        connection.execute(
            """INSERT INTO intent_segments
               (context_revision_id, stable_id, lifecycle, canonical_json,
                canonical_hash, origin_context_revision_id)
               VALUES (?, ?, 'active', ?, ?, ?)""",
            (
                revision,
                segment_id,
                json.dumps(
                    {"id": segment_id, "cidr": cidr, "availability_monitoring": True},
                    sort_keys=True,
                    separators=(",", ":"),
                ),
                f"hash-{segment_id}",
                revision,
            ),
        )
    connection.execute(
        """INSERT INTO context_heads
           (context_id, context_revision_id, activated_by_import_run_id, activated_at)
           VALUES ('availability-test', ?, ?, ?)""",
        (revision, import_run, OLD),
    )
    connection.commit()
    try:
        yield connection
    finally:
        connection.close()


def test_successful_run_replaces_only_its_cidr_current_results(conn):
    """Replacing all current rows after a failed CIDR run would discard known availability."""
    from netctl.availability import AvailabilityResult, AvailabilityRun, current_availability_results, save_availability_run

    first = AvailabilityRun.success(
        "192.0.2.0/30",
        started=OLD,
        finished=OLD,
        results=[
            AvailabilityResult("192.0.2.1", "reachable", "icmp"),
            AvailabilityResult("192.0.2.2", "unreachable", None),
        ],
    )
    save_availability_run(conn, first)
    save_availability_run(
        conn,
        AvailabilityRun.failed("192.0.2.0/30", started=NEW, error_class="deadline_exceeded"),
    )

    current = current_availability_results(conn, "192.0.2.0/30")
    assert current["192.0.2.1"].method == "icmp"
    assert current["192.0.2.2"].state == "unreachable"
    assert [tuple(row) for row in conn.execute("SELECT status FROM availability_runs ORDER BY id")] == [("success",), ("failed",)]


def test_successful_run_replaces_only_matching_cidr(conn):
    """A successful scan must not replace another CIDR's current result set."""
    from netctl.availability import AvailabilityResult, AvailabilityRun, current_availability_results, save_availability_run

    save_availability_run(
        conn,
        AvailabilityRun.success(
            "192.0.2.0/30", started=OLD, finished=OLD,
            results=[AvailabilityResult("192.0.2.1", "reachable", "icmp"), AvailabilityResult("192.0.2.2", "reachable", "icmp")],
        ),
    )
    save_availability_run(
        conn,
        AvailabilityRun.success(
            "198.51.100.0/30", started=OLD, finished=OLD,
            results=[AvailabilityResult("198.51.100.1", "unreachable", None), AvailabilityResult("198.51.100.2", "reachable", "tcp")],
        ),
    )
    save_availability_run(
        conn,
        AvailabilityRun.success(
            "192.0.2.0/30", started=NEW, finished=NEW,
            results=[AvailabilityResult("192.0.2.1", "unreachable", None), AvailabilityResult("192.0.2.2", "reachable", "icmp")],
        ),
    )

    assert current_availability_results(conn, "192.0.2.0/30")["192.0.2.1"].state == "unreachable"
    assert current_availability_results(conn, "198.51.100.0/30")["198.51.100.1"].state == "unreachable"


def test_incomplete_success_rolls_back_run_results_and_events(conn):
    """Persisting an incomplete success would allow a partial scan to become current state."""
    from netctl.availability import AvailabilityResult, AvailabilityRun, save_availability_run

    complete = AvailabilityRun.success(
        "192.0.2.0/30", started=OLD, finished=OLD,
        results=[AvailabilityResult("192.0.2.1", "reachable", "icmp"), AvailabilityResult("192.0.2.2", "reachable", "icmp")],
    )
    save_availability_run(conn, complete)
    incomplete = AvailabilityRun.success(
        "192.0.2.0/30", started=NEW, finished=NEW,
        results=[AvailabilityResult("192.0.2.1", "unreachable", None)],
        target_count=2,
    )

    with pytest.raises(ValueError, match="completed"):
        save_availability_run(conn, incomplete)

    assert [tuple(row) for row in conn.execute("SELECT id FROM availability_runs")] == [(1,)]
    assert [tuple(row) for row in conn.execute("SELECT ip, active_state FROM availability_results ORDER BY ip")] == [
        ("192.0.2.1", "reachable"),
        ("192.0.2.2", "reachable"),
    ]
    assert conn.execute("SELECT count(*) FROM availability_result_events").fetchone()[0] == 2


def test_unchanged_active_results_do_not_create_duplicate_change_events(conn):
    """Treating a new check timestamp as a state change would grow non-compact event history."""
    from netctl.availability import AvailabilityResult, AvailabilityRun, save_availability_run

    results = [
        AvailabilityResult("192.0.2.1", "reachable", "icmp"),
        AvailabilityResult("192.0.2.2", "unreachable", None),
    ]
    save_availability_run(conn, AvailabilityRun.success("192.0.2.0/30", started=OLD, finished=OLD, results=results))
    save_availability_run(conn, AvailabilityRun.success("192.0.2.0/30", started=NEW, finished=NEW, results=results))

    assert conn.execute("SELECT count(*) FROM availability_result_events").fetchone()[0] == 2


def test_ipv6_cidr_is_rejected_before_active_segment_matching(conn):
    """An IPv6 run must not enter storage even if policy matching later changes."""
    from netctl.availability import AvailabilityRun, save_availability_run

    with pytest.raises(ValueError, match="IPv4"):
        save_availability_run(
            conn,
            AvailabilityRun.failed("2001:db8::/64", started=OLD, error_class="deadline_exceeded"),
        )

    assert conn.execute("SELECT count(*) FROM availability_runs").fetchone()[0] == 0


def test_failure_class_change_without_active_change_does_not_create_event(conn):
    """Failure diagnostics are metadata, not a change in active state or active method."""
    from netctl.availability import AvailabilityResult, AvailabilityRun, save_availability_run

    save_availability_run(
        conn,
        AvailabilityRun.success(
            "192.0.2.0/30", started=OLD, finished=OLD,
            results=[
                AvailabilityResult("192.0.2.1", "reachable", "icmp"),
                AvailabilityResult("192.0.2.2", "unreachable", None, failure_class="timeout"),
            ],
        ),
    )
    save_availability_run(
        conn,
        AvailabilityRun.success(
            "192.0.2.0/30", started=NEW, finished=NEW,
            results=[
                AvailabilityResult("192.0.2.1", "reachable", "icmp"),
                AvailabilityResult("192.0.2.2", "unreachable", None, failure_class="refused"),
            ],
        ),
    )

    assert conn.execute("SELECT count(*) FROM availability_result_events").fetchone()[0] == 2
